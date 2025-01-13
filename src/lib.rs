//! IO Uring library, based on zig's std.os.linux.IoUring
//! Design around the 3 syscalls provided by the linux kernel, as exposed to
//! rust via rustix.

use core::{assert, assert_eq, assert_ne};
use rustix::fd::AsRawFd;
use rustix::io::Errno;
use rustix::io_uring::{
    io_uring_params, io_uring_setup, IoringFeatureFlags, IoringSetupFlags,
};

struct IoUring {
    fd: rustix::fd::OwnedFd,
    sq: SubmissionQueue,
    cq: CompletionQueue,
    flags: u32,
    features: u32,
}

struct SubmissionQueue {}
struct CompletionQueue {}

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
