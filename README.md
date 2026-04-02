# POSIX Conformance Test Suite

A `no_std`, zero-dependency POSIX conformance test suite targeting [IEEE 1003.13-2003](https://standards.ieee.org/ieee/1003.13/3322/) (PSE51/PSE52/PSE53 profiles). The same binary runs on Linux (as a reference) and on any POSIX-compatible RTOS or microkernel.

Developed by [Vinci Consulting](https://vinciconsulting.com) for [µKernel](https://americankernel.com) validation. µKernel is a Rust microkernel with DO-178C certification in progress.

> **Development happens on GitLab.** Issues and merge requests: https://gitlab.com/vinci-consulting/posix-conformance
>
> This GitHub repository is a read-only mirror.

## Why

Existing POSIX test suites (LTP, VSX) are Linux-specific or proprietary. There is no open-source, Rust-native conformance suite that runs on bare-metal RTOS targets. This fills that gap.

The test suite found kernel bugs on its first run — including a panic caused by negative file descriptor validation and missing EINVAL checks in mmap/munmap.

## What it tests

362 tests across 52 x86-64 syscalls (on Linux reference).

| Category | APIs |
|----------|------|
| Memory management | mmap, munmap, mprotect, brk |
| I/O multiplexing | poll, ppoll, select, pselect6, epoll |
| Process/thread info | getpid, gettid, getcwd, chdir, getrandom, prlimit64, sched_getaffinity |
| File descriptors | dup, dup2, dup3, close, fstat, fcntl |
| Sockets | socket, bind, listen, accept, connect, setsockopt, getsockopt |
| Timers/clocks | clock_gettime, clock_getres, nanosleep, timer_create/settime/delete |
| Pipes & vectored I/O | pipe2, read, write, readv, writev |
| Signals | sigprocmask, sigaction, kill, tkill, tgkill |
| Core (TLS, futex, stdio) | arch_prctl, futex, standard fd verification |

Each syscall has positive, negative, and boundary tests. Negative tests verify specific errno values, not just failure.

## Design

- **`#![no_std]`, `#![no_main]`** — no libc, no standard library, no runtime. Direct syscall wrappers via inline assembly.
- **Same binary, two targets** — build once, run on Linux as a reference, run on your RTOS to find gaps. Linux is the oracle.
- **Semantic testing** — tests exercise actual behavior, not just return codes. TLS tests write through `fs:[offset]`. Memory tests write patterns and read them back. Pipe tests verify data integrity end-to-end.
- **Zero dependencies** — the Cargo.toml has no `[dependencies]`. The binary is ~22KB static.

## Build

Requires Rust nightly (for `#![no_main]` and inline asm).

```bash
# Static build — for µKernel or bare-metal POSIX targets
./build.sh static

# Dynamic build — for Linux or container testing
./build.sh dynamic
```

Or manually:

```bash
# Static (position-dependent, no libc)
cargo build --release --target x86_64-unknown-linux-gnu

# Dynamic (standard Linux binary)
cargo build --release
```

The static binary is at `target/x86_64-unknown-linux-gnu/release/posix-conformance`.

## Run

### On Linux

```bash
./target/release/posix-conformance
```

Expected output:

```
=== POSIX Conformance Tests ===

=== Memory Management ===
  [PASS] mmap_basic_anon
  [PASS] mmap_read_write_verify
  ...

SUMMARY: 566 passed, 0 failed
```

### On a POSIX RTOS

Load the static binary as a guest/domain. The binary uses `_start` as its entry point, makes syscalls via the `syscall` instruction, and exits via `exit_group`. Your RTOS needs to handle the syscalls listed above.

The exit code is 0 if all tests pass, 1 if any fail.

### In a container (Docker/Podman)

```bash
# ASLR must be disabled — the binary uses fixed addresses
podman run --rm --security-opt seccomp=unconfined \
  -v ./target/release/posix-conformance:/test:Z \
  alpine /test
```

Or with `setarch`:

```bash
setarch -R ./target/release/posix-conformance
```

## Test structure

Each test module follows the same pattern:

```rust
pub fn run_tests() {
    test_positive_basic();      // Normal usage, expected results
    test_negative_bad_fd();     // Invalid inputs, expected errors
    test_boundary_zero_len();   // Edge cases
    test_stress_many_fds();     // Resource pressure
}
```

Tests report pass/fail individually and accumulate counters. A failing test does not abort — all tests run to completion.

## Adding tests

Add a new test function to the appropriate module (e.g., `memory_tests.rs`), call it from the module's `run_tests()`, and use the `pass!`/`fail!` macros:

```rust
fn test_mmap_example() {
    let addr = mmap_anon(4096, PROT_READ | PROT_WRITE);
    if addr > 0 {
        pass!("mmap_example");
    } else {
        fail!("mmap_example");
    }
    syscall2(nr::MUNMAP, addr as u64, 4096);
}
```

## Standards

This suite targets the POSIX Standard Environment (PSE) profiles for embedded/realtime systems, defined in [IEEE 1003.13-2003](https://standards.ieee.org/ieee/1003.13/3322/):

- **PSE51** (Minimal Realtime) — Single-process, single-threaded: memory, signals, clocks
- **PSE52** (Realtime Controller) — Multi-process, multi-threaded: adds process management, IPC
- **PSE53** (Dedicated Realtime) — Adds networking, I/O multiplexing, filesystem

Coverage is not complete for any profile. The suite is a work in progress — contributions welcome on GitLab.

## License

MIT

## Links

- [µKernel](https://americankernel.com) — Certified Rust microkernel
- [Vinci Consulting](https://vinciconsulting.com) — Systems engineering
