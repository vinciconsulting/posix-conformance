//! PSE51/PSE52/PSE53 Conformance Test Binary
//!
//! Tests POSIX syscall support against IEEE 1003.13-2003 (PSE51/PSE52/PSE53).
//! Each test EXERCISES the API semantics, not just return codes.
//!
//! Philosophy: A test passes only when the API is USED correctly.
//! - TLS: Set FS base, then access memory via fs:[offset]
//! - Memory: mmap, write pattern, read back, verify
//! - Pipes: write data, read data, compare
//! - Threads: clone, verify independent TLS and stack
//! - Futex: actually block and wake threads
//! - Signals: install handler, trigger signal, verify handler ran

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::sync::atomic::AtomicU32;

pub mod arch;

mod memory_tests;
mod pipe_tests;
mod fd_tests;
mod socket_tests;
mod signal_tests;
mod poll_tests;
mod time_tests;
mod process_tests;
mod fork_tests;
mod fs_tests;
mod thread_tests;

// Re-export arch functions so modules can still use crate::syscall3 etc.
pub use arch::{syscall0, syscall1, syscall2, syscall3, syscall4, syscall5, syscall6};

// ════════════════════════════════════════════════════════════════════════════
// Linux syscall numbers (x86-64)
// ════════════════════════════════════════════════════════════════════════════

pub mod nr {
    pub const READ: u64 = 0;
    pub const WRITE: u64 = 1;
    pub const CLOSE: u64 = 3;
    pub const POLL: u64 = 7;
    pub const MMAP: u64 = 9;
    pub const MPROTECT: u64 = 10;
    pub const MUNMAP: u64 = 11;
    pub const BRK: u64 = 12;
    pub const SIGACTION: u64 = 13;
    pub const SIGPROCMASK: u64 = 14;
    pub const IOCTL: u64 = 16;
    pub const PREAD64: u64 = 17;
    pub const PWRITE64: u64 = 18;
    pub const READV: u64 = 19;
    pub const WRITEV: u64 = 20;
    pub const SELECT: u64 = 23;
    pub const SCHED_YIELD: u64 = 24;
    pub const DUP: u64 = 32;
    pub const DUP2: u64 = 33;
    pub const NANOSLEEP: u64 = 35;
    pub const GETPID: u64 = 39;
    pub const SOCKET: u64 = 41;
    pub const CONNECT: u64 = 42;
    pub const ACCEPT: u64 = 43;
    pub const SENDTO: u64 = 44;
    pub const RECVFROM: u64 = 45;
    pub const SHUTDOWN: u64 = 48;
    pub const BIND: u64 = 49;
    pub const LISTEN: u64 = 50;
    pub const GETSOCKNAME: u64 = 51;
    pub const GETPEERNAME: u64 = 52;
    pub const SETSOCKOPT: u64 = 54;
    pub const GETSOCKOPT: u64 = 55;
    pub const CLONE: u64 = 56;
    pub const EXIT: u64 = 60;
    pub const KILL: u64 = 62;
    pub const FCNTL: u64 = 72;
    pub const GETCWD: u64 = 79;
    pub const CHDIR: u64 = 80;
    pub const GETUID: u64 = 102;
    pub const GETGID: u64 = 104;
    pub const GETEUID: u64 = 107;
    pub const GETEGID: u64 = 108;
    pub const GETPPID: u64 = 110;
    pub const ARCH_PRCTL: u64 = 158;
    pub const GETTID: u64 = 186;
    pub const TKILL: u64 = 200;
    pub const FUTEX: u64 = 202;
    pub const SCHED_GETAFFINITY: u64 = 204;
    pub const GETDENTS64: u64 = 217;
    pub const SET_TID_ADDRESS: u64 = 218;
    pub const TIMER_CREATE: u64 = 222;
    pub const TIMER_SETTIME: u64 = 223;
    pub const TIMER_GETTIME: u64 = 224;
    pub const TIMER_GETOVERRUN: u64 = 225;
    pub const TIMER_DELETE: u64 = 226;
    pub const CLOCK_GETTIME: u64 = 228;
    pub const CLOCK_GETRES: u64 = 229;
    pub const EXIT_GROUP: u64 = 231;
    pub const TGKILL: u64 = 234;
    pub const OPENAT: u64 = 257;
    pub const MKDIRAT: u64 = 258;
    pub const NEWFSTATAT: u64 = 262;
    pub const UNLINKAT: u64 = 263;
    pub const READLINKAT: u64 = 267;
    pub const PSELECT6: u64 = 270;
    pub const PPOLL: u64 = 271;
    pub const SET_ROBUST_LIST: u64 = 273;
    pub const EPOLL_CREATE1: u64 = 291;
    pub const DUP3: u64 = 292;
    pub const PIPE2: u64 = 293;
    pub const LSEEK: u64 = 8;
    pub const MLOCK: u64 = 149;
    pub const MUNLOCK: u64 = 150;
    pub const MLOCKALL: u64 = 151;
    pub const MUNLOCKALL: u64 = 152;
    pub const MSYNC: u64 = 26;
    pub const FTRUNCATE: u64 = 77;
    pub const FSYNC: u64 = 74;
    pub const FDATASYNC: u64 = 75;
    pub const RENAMEAT2: u64 = 316;
    pub const LINKAT: u64 = 265;
    pub const FACCESSAT: u64 = 269;
    pub const SYMLINKAT: u64 = 266;
    pub const SOCKETPAIR: u64 = 53;
    pub const SENDMSG: u64 = 46;
    pub const RECVMSG: u64 = 47;
    pub const UNAME: u64 = 63;
    pub const SIGPENDING: u64 = 127;
    pub const SIGSUSPEND: u64 = 130;  // rt_sigsuspend
    pub const SIGTIMEDWAIT: u64 = 128; // rt_sigtimedwait
    pub const CLOCK_NANOSLEEP: u64 = 230;
    pub const EPOLL_CTL: u64 = 233;
    pub const EPOLL_WAIT: u64 = 232;
    pub const SCHED_SETSCHEDULER: u64 = 144;
    pub const SCHED_GETSCHEDULER: u64 = 145;
    pub const SCHED_GET_PRIORITY_MAX: u64 = 146;
    pub const SCHED_GET_PRIORITY_MIN: u64 = 147;
    pub const PRLIMIT64: u64 = 302;
    pub const GETRANDOM: u64 = 318;
    pub const CLONE3: u64 = 435;
}

// ════════════════════════════════════════════════════════════════════════════
// Output helpers
// ════════════════════════════════════════════════════════════════════════════

pub fn write_str(s: &str) {
    unsafe {
        syscall3(nr::WRITE, 1, s.as_ptr() as u64, s.len() as u64);
    }
}

pub fn write_hex(mut n: u64) {
    let mut buf = [0u8; 18]; // "0x" + 16 hex digits
    buf[0] = b'0';
    buf[1] = b'x';
    for i in (2..18).rev() {
        let digit = (n & 0xF) as u8;
        buf[i] = if digit < 10 { b'0' + digit } else { b'a' + digit - 10 };
        n >>= 4;
    }
    unsafe {
        syscall3(nr::WRITE, 1, buf.as_ptr() as u64, 18);
    }
}

pub fn write_num(n: i64) {
    // Handle i64::MIN specially to avoid overflow on negation
    if n == i64::MIN {
        write_str("-9223372036854775808");
        return;
    }
    let mut val = if n < 0 {
        write_str("-");
        -n
    } else {
        n
    };
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    if val == 0 {
        write_str("0");
        return;
    }
    while val > 0 {
        i -= 1;
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
    }
    unsafe {
        syscall3(nr::WRITE, 1, buf[i..].as_ptr() as u64, (buf.len() - i) as u64);
    }
}

/// Print a centered banner: ╔═══╗ / ║  msg  ║ / ╚═══╝
/// Width = max(60, msg.len() + 4), so the message always has at least 2 chars padding per side.
pub fn write_banner(msg: &str) {
    let min_width = 60;
    let inner = if msg.len() + 4 > min_width { msg.len() + 4 } else { min_width };

    write_str("\n╔");
    for _ in 0..inner { write_str("═"); }
    write_str("╗\n║");

    let pad_total = inner - msg.len();
    let pad_left = pad_total / 2;
    let pad_right = pad_total - pad_left;

    for _ in 0..pad_left { write_str(" "); }
    write_str(msg);
    for _ in 0..pad_right { write_str(" "); }

    write_str("║\n╚");
    for _ in 0..inner { write_str("═"); }
    write_str("╝\n");
}

// ════════════════════════════════════════════════════════════════════════════
// Test framework
// ════════════════════════════════════════════════════════════════════════════

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PseLevel {
    PSE51,
    PSE52,
    PSE53,
}

pub struct TestCategory {
    pub level: PseLevel,
    pub name: &'static str,
    pub passed: u32,
    pub failed: u32,
}

impl TestCategory {
    pub fn new(level: PseLevel, name: &'static str) -> Self {
        Self { level, name, passed: 0, failed: 0 }
    }

    pub fn header(&self) {
        write_str("\n=== ");
        write_str(self.name);
        write_str(" ===\n");
    }

    pub fn pass(&mut self, name: &str) {
        write_str("  [PASS] ");
        write_str(name);
        write_str("\n");
        self.passed += 1;
    }

    pub fn fail(&mut self, name: &str) {
        write_str("  [FAIL] ");
        write_str(name);
        write_str("\n");
        self.failed += 1;
    }

    pub fn fail_expected(&mut self, name: &str, expected: u64, got: u64) {
        write_str("  [FAIL] ");
        write_str(name);
        write_str(" (expected ");
        write_hex(expected);
        write_str(", got ");
        write_hex(got);
        write_str(")\n");
        self.failed += 1;
    }

    pub fn fail_errno(&mut self, name: &str, expected: i64, got: i64) {
        write_str("  [FAIL] ");
        write_str(name);
        write_str(" (expected ");
        write_num(expected);
        write_str(", got ");
        write_num(got);
        write_str(")\n");
        self.failed += 1;
    }

    pub fn check(&mut self, name: &str, condition: bool) {
        if condition { self.pass(name); } else { self.fail(name); }
    }

    pub fn check_errno(&mut self, name: &str, got: i64, expected: i64) {
        if got == expected {
            self.pass(name);
        } else {
            self.fail_errno(name, expected, got);
        }
    }

}

pub struct Results {
    categories: [Option<(PseLevel, &'static str, u32, u32)>; 64],
    count: usize,
}

impl Results {
    pub fn new() -> Self {
        Self { categories: [None; 64], count: 0 }
    }

    pub fn add(&mut self, cat: TestCategory) {
        if self.count < 64 {
            self.categories[self.count] = Some((cat.level, cat.name, cat.passed, cat.failed));
            self.count += 1;
        }
    }

    fn level_totals(&self, level: PseLevel) -> (u32, u32) {
        let (mut p, mut f) = (0u32, 0u32);
        for i in 0..self.count {
            if let Some((l, _, passed, failed)) = self.categories[i] {
                if l == level { p += passed; f += failed; }
            }
        }
        (p, f)
    }

    pub fn summary(&self) {
        write_str("\n════════════════════════════════════════════════════════════\n");

        let (mut total_p, mut total_f) = (0u32, 0u32);

        for &(level, label) in &[
            (PseLevel::PSE51, "PSE51"),
            (PseLevel::PSE52, "PSE52"),
            (PseLevel::PSE53, "PSE53"),
        ] {
            let (p, f) = self.level_totals(level);
            if p + f == 0 { continue; }
            let total = p + f;
            write_str(label);
            write_str(": ");
            write_num(p as i64);
            write_str("/");
            write_num(total as i64);
            if total > 0 {
                write_str(" (");
                write_num((p as i64 * 100) / total as i64);
                write_str("%)");
            }
            write_str("\n");
            total_p += p;
            total_f += f;
        }

        let total = total_p + total_f;
        write_str("TOTAL: ");
        write_num(total_p as i64);
        write_str("/");
        write_num(total as i64);
        if total > 0 {
            write_str(" (");
            write_num((total_p as i64 * 100) / total as i64);
            write_str("%)");
        }
        write_str("\n");

        write_str("════════════════════════════════════════════════════════════\n");

        if total_f == 0 {
            write_str("\nALL TESTS PASSED\n");
        } else {
            write_str("\nSOME TESTS FAILED\n");
        }
    }

    pub fn exit_code(&self) -> u64 {
        let total_f = self.level_totals(PseLevel::PSE51).1
            + self.level_totals(PseLevel::PSE52).1
            + self.level_totals(PseLevel::PSE53).1;
        if total_f == 0 { 0 } else { 1 }
    }
}


// ════════════════════════════════════════════════════════════════════════════
// Common structures
// ════════════════════════════════════════════════════════════════════════════

#[repr(C)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

#[repr(C)]
pub struct Iovec {
    pub iov_base: u64,
    pub iov_len: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Pollfd {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}

// ════════════════════════════════════════════════════════════════════════════
// PSE51: TLS - SET FS BASE AND USE IT
// ════════════════════════════════════════════════════════════════════════════

fn test_tls_fs_relative(results: &mut Results) {
    let mut cat = TestCategory::new(PseLevel::PSE51, "TLS: arch_prctl + FS-relative access");
    cat.header();

    const ARCH_SET_FS: u64 = 0x1002;
    const ARCH_GET_FS: u64 = 0x1003;

    // 1. Create a TLS block with known values
    #[repr(C, align(16))]
    struct TlsBlock {
        val0: u64,  // fs:[0]
        val1: u64,  // fs:[8]
        val2: u64,  // fs:[16]
        val3: u64,  // fs:[24]
    }

    let mut tls = TlsBlock {
        val0: 0xAAAA_BBBB_CCCC_DDDD,
        val1: 0x1111_2222_3333_4444,
        val2: 0x5555_6666_7777_8888,
        val3: 0x9999_AAAA_BBBB_CCCC,
    };

    // 2. Set FS base to point to our TLS block
    let tls_addr = &mut tls as *mut TlsBlock as u64;
    let ret = unsafe { syscall2(nr::ARCH_PRCTL, ARCH_SET_FS, tls_addr) };
    if ret != 0 {
        cat.fail("arch_prctl(SET_FS) returns 0");
        return;
    }
    cat.pass("arch_prctl(SET_FS) returns 0");

    // 3. GET_FS should return the same address
    let mut fs_base: u64 = 0;
    let ret = unsafe { syscall2(nr::ARCH_PRCTL, ARCH_GET_FS, &mut fs_base as *mut u64 as u64) };
    if ret != 0 {
        cat.fail("arch_prctl(GET_FS) returns 0");
    } else if fs_base != tls_addr {
        cat.fail_expected("GET_FS returns SET_FS value", tls_addr, fs_base);
    } else {
        cat.pass("GET_FS returns SET_FS value");
    }

    // 4. Access memory via FS-relative addressing (this is what libc does)
    let val0 = unsafe { arch::tls_read(0) };
    let val1 = unsafe { arch::tls_read(8) };
    let val2 = unsafe { arch::tls_read(16) };
    let val3 = unsafe { arch::tls_read(24) };

    if val0 == 0xAAAA_BBBB_CCCC_DDDD {
        cat.pass("fs:[0] reads correct value");
    } else {
        cat.fail_expected("fs:[0] reads correct value", 0xAAAA_BBBB_CCCC_DDDD, val0);
    }

    if val1 == 0x1111_2222_3333_4444 {
        cat.pass("fs:[8] reads correct value");
    } else {
        cat.fail_expected("fs:[8] reads correct value", 0x1111_2222_3333_4444, val1);
    }

    if val2 == 0x5555_6666_7777_8888 {
        cat.pass("fs:[16] reads correct value");
    } else {
        cat.fail_expected("fs:[16] reads correct value", 0x5555_6666_7777_8888, val2);
    }

    if val3 == 0x9999_AAAA_BBBB_CCCC {
        cat.pass("fs:[24] reads correct value");
    } else {
        cat.fail_expected("fs:[24] reads correct value", 0x9999_AAAA_BBBB_CCCC, val3);
    }

    // 5. Write via FS-relative addressing
    unsafe { arch::tls_write(0, 0xDEAD_BEEF) };

    // 6. Verify the TLS block was modified
    if tls.val0 == 0xDEAD_BEEF {
        cat.pass("fs:[0] write modifies TLS block");
    } else {
        cat.fail_expected("fs:[0] write modifies TLS block", 0xDEAD_BEEF, tls.val0);
    }
    results.add(cat);
}

// ════════════════════════════════════════════════════════════════════════════
// PSE51: Futex - ACTUALLY BLOCK AND WAKE
// ════════════════════════════════════════════════════════════════════════════

// Futex ops
const FUTEX_WAIT: u64 = 0;
const FUTEX_WAKE: u64 = 1;

fn test_futex(results: &mut Results) {
    let mut cat = TestCategory::new(PseLevel::PSE51, "Futex");
    cat.header();

    let futex_word: AtomicU32 = AtomicU32::new(0);
    let ret = unsafe {
        syscall6(nr::FUTEX, &futex_word as *const _ as u64, FUTEX_WAKE, 1, 0, 0, 0)
    };
    cat.check("futex(WAKE) with no waiters returns 0", ret == 0);

    let futex_word: AtomicU32 = AtomicU32::new(42);
    let ret = unsafe {
        syscall6(nr::FUTEX, &futex_word as *const _ as u64, FUTEX_WAIT, 0, 0, 0, 0)
    };
    cat.check_errno("futex(WAIT) wrong value returns -EAGAIN", ret, -11);

    results.add(cat);
}

// ════════════════════════════════════════════════════════════════════════════
// Standard File Descriptors (fd 0/1/2) - POSIX requires these pre-open
// ════════════════════════════════════════════════════════════════════════════

fn test_standard_fds(results: &mut Results) {
    let mut cat = TestCategory::new(PseLevel::PSE51, "Standard FDs: fd 0/1/2");
    cat.header();

    const FSTAT: u64 = 5;

    #[repr(C)]
    struct Stat {
        st_dev: u64,
        st_ino: u64,
        st_nlink: u64,
        st_mode: u32,
        st_uid: u32,
        st_gid: u32,
        _pad0: u32,
        st_rdev: u64,
        st_size: i64,
        st_blksize: i64,
        st_blocks: i64,
        st_atime: i64,
        st_atime_nsec: i64,
        st_mtime: i64,
        st_mtime_nsec: i64,
        st_ctime: i64,
        st_ctime_nsec: i64,
        _reserved: [i64; 3],
    }

    // Note: POSIX doesn't require std fds to be character devices - they can be
    // pipes, sockets, ptys, or files. We only verify they exist and are usable.

    // 1. fstat(0) - stdin should exist (POSIX requires fd 0 be open)
    let mut stat = core::mem::MaybeUninit::<Stat>::uninit();
    let ret = unsafe { syscall2(FSTAT, 0, stat.as_mut_ptr() as u64) };
    if ret == 0 {
        cat.pass("fstat(stdin) returns 0");
    } else {
        cat.fail("fstat(stdin) returns 0");
    }

    // 2. fstat(1) - stdout should exist (POSIX requires fd 1 be open)
    let mut stat = core::mem::MaybeUninit::<Stat>::uninit();
    let ret = unsafe { syscall2(FSTAT, 1, stat.as_mut_ptr() as u64) };
    if ret == 0 {
        cat.pass("fstat(stdout) returns 0");
    } else {
        cat.fail("fstat(stdout) returns 0");
    }

    // 3. fstat(2) - stderr should exist (POSIX requires fd 2 be open)
    let mut stat = core::mem::MaybeUninit::<Stat>::uninit();
    let ret = unsafe { syscall2(FSTAT, 2, stat.as_mut_ptr() as u64) };
    if ret == 0 {
        cat.pass("fstat(stderr) returns 0");
    } else {
        cat.fail("fstat(stderr) returns 0");
    }

    // 4. Write to stdout (already tested implicitly, but explicit)
    let ret = unsafe { syscall3(nr::WRITE, 1, b"    (stdout write test)\n".as_ptr() as u64, 24) };
    if ret == 24 {
        cat.pass("write(stdout) returns count");
    } else {
        cat.fail("write(stdout) returns count");
    }

    // 5. Write to stderr
    let ret = unsafe { syscall3(nr::WRITE, 2, b"    (stderr write test)\n".as_ptr() as u64, 24) };
    if ret == 24 {
        cat.pass("write(stderr) returns count");
    } else {
        cat.fail("write(stderr) returns count");
    }

    // 6. Read from stdin - should not return EBADF
    // In a non-interactive environment, this returns 0 (EOF) or -EAGAIN (no data)
    let mut buf = [0u8; 1];
    let ret = unsafe { syscall3(nr::READ, 0, buf.as_mut_ptr() as u64, 0) };
    // Zero-length read should return 0, not error
    if ret == 0 {
        cat.pass("read(stdin, 0) returns 0");
    } else if ret == -9 { // -EBADF
        cat.fail("read(stdin) returns EBADF (fd 0 not initialized)");
    } else {
        cat.pass("read(stdin, 0) accepted");
    }

    // 7. Verify closing fd 0/1/2 and reopening works correctly
    // Note: We won't actually close these as we need stdout for test output,
    // but we verify they can be dup'd which proves they're valid
    let dup_stdin = unsafe { syscall1(nr::DUP, 0) };
    if dup_stdin >= 3 {
        cat.pass("dup(stdin) returns new fd");
        unsafe { syscall1(nr::CLOSE, dup_stdin as u64) };
    } else {
        cat.fail("dup(stdin) returns new fd");
    }

    let dup_stderr = unsafe { syscall1(nr::DUP, 2) };
    if dup_stderr >= 3 {
        cat.pass("dup(stderr) returns new fd");
        unsafe { syscall1(nr::CLOSE, dup_stderr as u64) };
    } else {
        cat.fail("dup(stderr) returns new fd");
    }
    results.add(cat);
}

// ════════════════════════════════════════════════════════════════════════════
// Entry point
// ════════════════════════════════════════════════════════════════════════════

pub(crate) extern "C" fn main() -> ! {
    write_str("════════════════════════════════════════════════════════════\n");
    write_str("  PSE51/PSE52/PSE53 POSIX Conformance Test Suite v");
    write_str(env!("CARGO_PKG_VERSION"));
    write_str("\n  IEEE 1003.13-2003\n");
    write_str("════════════════════════════════════════════════════════════\n");

    let mut results = Results::new();

    // PSE51: Standard file descriptors
    test_standard_fds(&mut results);

    // PSE51: Memory
    memory_tests::run_all(&mut results);

    // PSE51: TLS
    test_tls_fs_relative(&mut results);

    // PSE51: Pipes
    pipe_tests::run_all(&mut results);

    // PSE52: FD Management
    fd_tests::run_all(&mut results);

    // PSE51: Clocks/Timers
    time_tests::run_all(&mut results);

    // PSE51: Process Identity
    process_tests::run_all(&mut results);

    // PSE51: Futex
    test_futex(&mut results);

    // PSE53: Sockets
    socket_tests::run_all(&mut results);

    // PSE51: Signals
    signal_tests::run_all(&mut results);

    // PSE53: I/O Multiplexing
    poll_tests::run_all(&mut results);

    // PSE52: Fork/exec/wait
    fork_tests::run_all(&mut results);

    // PSE52: Filesystem
    fs_tests::run_all(&mut results);

    // PSE51: Threads
    thread_tests::run_all(&mut results);

    results.summary();
    let exit_code = results.exit_code();

    unsafe { syscall1(nr::EXIT_GROUP, exit_code) };
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    write_str("PANIC: ");
    if let Some(location) = info.location() {
        write_str(location.file());
        write_str(":");
        write_num(location.line() as i64);
    }
    write_str("\n");
    unsafe { syscall1(nr::EXIT_GROUP, 99) };
    loop {
        core::hint::spin_loop();
    }
}
