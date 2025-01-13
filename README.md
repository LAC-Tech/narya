# High level `io_uring` library

High level `io_uring` library, based around the low-level syscalls as exposed to rust by rustix.

## Why?

I was looking at this [Tigerbeetle blog post](https://tigerbeetle.com/blog/2022-11-23-a-friendly-abstraction-over-iouring-and-kqueue/) and I was jealous of the concise `io_uring` bindings Zig programmers get with their standard library.

Other crates use an op based syntax with fluent APIs, which results in long winded code.
