//! IO Uring library, based on zig's std.os.linux.IoUring
//! Design around the 3 syscalls provided by the linux kernel, as exposed to
//! rust via rustix.

use core::{assert, assert_eq, assert_ne, cmp, ffi, mem, ops, ptr, slice};
use rustix::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use rustix::io;
use rustix::io::Errno;
use rustix::io_uring::{
    io_cqring_offsets, io_sqring_offsets, io_uring_cqe, io_uring_params,
    io_uring_setup, IoringFeatureFlags, IoringSetupFlags, IORING_OFF_SQES,
    IORING_OFF_SQ_RING,
};
use rustix::mm;
use rustix::mm::{MapFlags, ProtFlags};

struct IoUring {
    fd: OwnedFd,
    sq: SubmissionQueue,
    cq: CompletionQueue,
    flags: u32,
    features: u32,
}

struct SubmissionQueue {
    offsets: io_sqring_offsets,
}

fn size_in_u32<T>() -> u32 {
    u32::try_from(mem::size_of::<T>()).unwrap()
}

// TODO: better name
struct MemMapped {
    len: usize,
    ptr: *mut ffi::c_void,
}

impl MemMapped {
    fn new<Fd: AsFd>(len: usize, fd: Fd) -> io::Result<Self> {
        unsafe {
            let ptr = mm::mmap(
                ptr::null_mut(),
                len,
                ProtFlags::READ | ProtFlags::WRITE,
                MapFlags::SHARED | MapFlags::POPULATE,
                fd,
                IORING_OFF_SQ_RING,
            )?;

            Ok(Self { len, ptr })
        }
    }
}

impl ops::Drop for MemMapped {
    fn drop(&mut self) {
        unsafe { mm::munmap(self.ptr, self.len).unwrap() }
    }
}

impl SubmissionQueue {
    fn new(fd: BorrowedFd, p: io_uring_params) -> io::Result<Self> {
        assert!(fd.as_raw_fd() >= 0); // Extra paranoid sanity check
        assert!(p.features.contains(IoringFeatureFlags::SINGLE_MMAP));

        let size: usize = cmp::max(
            p.sq_off.array + p.sq_entries * size_in_u32::<u32>(),
            p.cq_off.cqes + p.cq_entries * size_in_u32::<io_uring_cqe>(),
        ) as usize;

        let mmap = unsafe {
            mm::mmap(
                ptr::null_mut(),
                size,
                ProtFlags::READ | ProtFlags::WRITE,
                MapFlags::SHARED | MapFlags::POPULATE,
                fd,
                IORING_OFF_SQ_RING,
            )?
        };

        let size_sqes =
            (p.sq_entries as usize) + mem::size_of::<io_uring_cqe>();

        let mmap_sqes = unsafe {
            mm::mmap(
                ptr::null_mut(),
                size_sqes,
                ProtFlags::READ | ProtFlags::WRITE,
                MapFlags::SHARED | MapFlags::POPULATE,
                fd,
                IORING_OFF_SQES,
            )?
        };

        let array = unsafe { slice::from_raw_parts_mut(mmap as *mut u8, size) };

        let sqes =
            unsafe { slice::from_raw_parts_mut(mmap_sqes as *mut u8, size) };

        panic!("construct submission queue");
    }
}

struct CompletionQueue {
    offsets: io_cqring_offsets,
}
enum InitErr {
    EntriesZero,
    EntriesNotPowerOfTwo,
    ParamsOutsideAccessibleAddressSpace,
    ArgumentsInvalid,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    SystemResources,
    PermissionDenied,
    SystemOutdated,
    UnexpectedErrno(Errno),
}

impl IoUring {
    /**
     * A friendly way to setup an io_uring, with default linux.io_uring_params.
     * `entries` must be a power of two between 1 and 32768, although the kernel
     * will make the final call on how many entries the submission and
     * completion queues will ultimately have,
     * see https://github.com/torvalds/linux/blob/v5.8/fs/io_uring.c#L8027-L8050
     * Matches the interface of io_uring_queue_init() in liburing.
     */
    pub fn new(entries: u32, flags: IoringSetupFlags) -> Result<Self, InitErr> {
        let mut params = io_uring_params {
            flags,
            sq_thread_idle: 1000,
            ..Default::default()
        };

        Self::new_with_params(entries, &mut params)
    }

    fn new_with_params(
        entries: u32,
        p: &mut io_uring_params,
    ) -> Result<Self, InitErr> {
        if entries == 0 {
            return Err(InitErr::EntriesZero);
        } else if !entries.is_power_of_two() {
            return Err(InitErr::EntriesNotPowerOfTwo);
        }

        assert_eq!(p.sq_entries, 0);
        assert!(
            p.cq_entries == 0 || p.flags.contains(IoringSetupFlags::CQSIZE)
        );
        assert!(p.features.is_empty());
        assert!(p.wq_fd == 0 || p.flags.contains(IoringSetupFlags::ATTACH_WQ));
        assert_eq!(p.resv, [0, 0, 0]);

        let fd = io_uring_setup(entries, p).map_err(|errno| match errno {
            Errno::FAULT => InitErr::ParamsOutsideAccessibleAddressSpace,
            // The resv array contains non-zero data, p.flags contains an
            // unsupported flag, entries out of bounds, IORING_SETUP_SQ_AFF was
            // specified without IORING_SETUP_SQPOLL, or IORING_SETUP_CQSIZE was
            // specified but linux.io_uring_params.cq_entries was invalid:
            Errno::INVAL => InitErr::ArgumentsInvalid,
            Errno::MFILE => InitErr::ProcessFdQuotaExceeded,
            Errno::NFILE => InitErr::SystemFdQuotaExceeded,
            Errno::NOMEM => InitErr::SystemResources,
            // IORING_SETUP_SQPOLL was specified but effective user ID lacks
            // sufficient privileges, or a container seccomp policy prohibits
            // io_uring syscalls:
            Errno::PERM => InitErr::PermissionDenied,
            Errno::NOSYS => InitErr::SystemOutdated,
            _ => InitErr::UnexpectedErrno(errno),
        })?;

        assert!(fd.as_raw_fd() >= 0); // Extra paranoid sanity check

        // Kernel versions 5.4 and up use only one mmap() for the submission
        // and completion queues. This is not an optional feature for us... if
        // the kernel does it, we have to do it.
        // The thinking on this by the kernel developers was that both the
        // submission and the completion queue rings have sizes just over a
        // power of two, but the submission queue ring is significantly smaller
        // with u32 slots. By bundling both in a single mmap, the kernel gets
        // the submission queue ring for free.
        // See https://patchwork.kernel.org/patch/11115257 for the kernel patch.
        // We do not support the double mmap() done before 5.4, because we want
        // to keep the init/deinit mmap paths simple and because io_uring has
        // had many bug fixes even since 5.4.
        if !p.features.contains(IoringFeatureFlags::SINGLE_MMAP) {
            return Err(InitErr::SystemOutdated);
        }

        // Check that the kernel has actually set params and that "impossible is
        // nothing".
        assert_ne!(p.sq_entries, 0);
        assert_ne!(p.cq_entries, 0);
        assert!(p.cq_entries >= p.sq_entries);

        panic!("TODO implement me")
    }
}

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
