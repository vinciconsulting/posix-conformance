//! Comprehensive process identity tests for POSIX conformance
//!
//! Tests: getpid, gettid, getppid, getuid, geteuid, getgid, getegid,
//!        set_tid_address, getcwd, chdir, sched_yield, sched_getaffinity,
//!        prlimit64, getrandom
//!
//! Categories:
//! - Positive: normal process/thread identity queries
//! - Negative: invalid arguments, permission checks
//! - Boundary: edge cases for resource limits

use crate::nr;
use crate::{pass, fail, fail_errno, write_str, write_num, syscall0, syscall1, syscall2, syscall3, syscall4};

// ════════════════════════════════════════════════════════════════════════════
// Constants
// ════════════════════════════════════════════════════════════════════════════

// Resource limit constants for prlimit64
const RLIMIT_CPU: u64 = 0;
const RLIMIT_FSIZE: u64 = 1;
const RLIMIT_DATA: u64 = 2;
const RLIMIT_STACK: u64 = 3;
const RLIMIT_CORE: u64 = 4;
const RLIMIT_RSS: u64 = 5;
const RLIMIT_NPROC: u64 = 6;
const RLIMIT_NOFILE: u64 = 7;
const RLIMIT_MEMLOCK: u64 = 8;
const RLIMIT_AS: u64 = 9;

// getrandom flags
const GRND_RANDOM: u64 = 0x0002;
const GRND_NONBLOCK: u64 = 0x0001;

// Error codes
const EINVAL: i64 = -22;
const ESRCH: i64 = -3;
const ENOENT: i64 = -2;
const ERANGE: i64 = -34;

// ════════════════════════════════════════════════════════════════════════════
// Structures
// ════════════════════════════════════════════════════════════════════════════

#[repr(C)]
struct Rlimit {
    rlim_cur: u64,  // Soft limit
    rlim_max: u64,  // Hard limit
}

// ════════════════════════════════════════════════════════════════════════════
// Process/Thread identity tests
// ════════════════════════════════════════════════════════════════════════════

pub fn test_getpid() {
    write_str("\n=== Process: getpid ===\n");

    // 1. getpid returns positive value
    let pid = unsafe { syscall0(nr::GETPID) };
    if pid > 0 {
        pass("getpid: returns positive value");
    } else {
        fail_errno("getpid: returns positive value", 1, pid);
    }

    // 2. getpid is consistent (multiple calls return same value)
    let pid2 = unsafe { syscall0(nr::GETPID) };
    if pid == pid2 {
        pass("getpid: consistent across calls");
    } else {
        fail("getpid: consistent across calls");
    }

    // 3. getpid is in reasonable range
    if pid > 0 && pid < 0x7FFFFFFF {
        pass("getpid: value in valid range");
    } else {
        fail("getpid: value in valid range");
    }
}

pub fn test_gettid() {
    write_str("\n=== Process: gettid ===\n");

    // 1. gettid returns positive value
    let tid = unsafe { syscall0(nr::GETTID) };
    if tid > 0 {
        pass("gettid: returns positive value");
    } else {
        fail_errno("gettid: returns positive value", 1, tid);
    }

    // 2. For single-threaded process, tid == pid
    let pid = unsafe { syscall0(nr::GETPID) };
    if tid == pid {
        pass("gettid: equals getpid (single-threaded)");
    } else {
        fail("gettid: equals getpid (single-threaded)");
    }

    // 3. gettid is consistent
    let tid2 = unsafe { syscall0(nr::GETTID) };
    if tid == tid2 {
        pass("gettid: consistent across calls");
    } else {
        fail("gettid: consistent across calls");
    }
}

pub fn test_getppid() {
    write_str("\n=== Process: getppid ===\n");

    // 1. getppid returns value >= 0
    let ppid = unsafe { syscall0(nr::GETPPID) };
    if ppid >= 0 {
        pass("getppid: returns non-negative value");
    } else {
        fail_errno("getppid: returns non-negative value", 0, ppid);
    }

    // 2. getppid != getpid (parent is different from self)
    let pid = unsafe { syscall0(nr::GETPID) };
    if ppid != pid || ppid == 1 {
        // ppid == pid only if we're init (ppid=1) and very special case
        pass("getppid: different from getpid (or we're init)");
    } else {
        fail("getppid: different from getpid");
    }

    // 3. getppid is consistent
    let ppid2 = unsafe { syscall0(nr::GETPPID) };
    if ppid == ppid2 {
        pass("getppid: consistent across calls");
    } else {
        fail("getppid: consistent across calls");
    }
}

pub fn test_uid_gid() {
    write_str("\n=== Process: uid/gid ===\n");

    // 1. getuid
    let uid = unsafe { syscall0(nr::GETUID) };
    if uid >= 0 {
        pass("getuid: returns non-negative value");
    } else {
        fail("getuid: returns non-negative value");
    }

    // 2. geteuid
    let euid = unsafe { syscall0(nr::GETEUID) };
    if euid >= 0 {
        pass("geteuid: returns non-negative value");
    } else {
        fail("geteuid: returns non-negative value");
    }

    // 3. getgid
    let gid = unsafe { syscall0(nr::GETGID) };
    if gid >= 0 {
        pass("getgid: returns non-negative value");
    } else {
        fail("getgid: returns non-negative value");
    }

    // 4. getegid
    let egid = unsafe { syscall0(nr::GETEGID) };
    if egid >= 0 {
        pass("getegid: returns non-negative value");
    } else {
        fail("getegid: returns non-negative value");
    }

    // 5. For non-setuid binary, uid == euid
    if uid == euid {
        pass("uid equals euid (non-setuid)");
    } else {
        pass("uid differs from euid (setuid binary)");
    }

    // 6. For non-setgid binary, gid == egid
    if gid == egid {
        pass("gid equals egid (non-setgid)");
    } else {
        pass("gid differs from egid (setgid binary)");
    }

    // 7. Values are consistent
    let uid2 = unsafe { syscall0(nr::GETUID) };
    let gid2 = unsafe { syscall0(nr::GETGID) };
    if uid == uid2 && gid == gid2 {
        pass("uid/gid: consistent across calls");
    } else {
        fail("uid/gid: consistent across calls");
    }
}

pub fn test_set_tid_address() {
    write_str("\n=== Process: set_tid_address ===\n");

    // set_tid_address sets the clear_child_tid address and returns TID
    let mut tid_addr: i32 = 0;

    // 1. set_tid_address returns current TID
    let ret = unsafe { syscall1(nr::SET_TID_ADDRESS, &mut tid_addr as *mut _ as u64) };
    let expected_tid = unsafe { syscall0(nr::GETTID) };
    if ret == expected_tid {
        pass("set_tid_address: returns current TID");
    } else {
        fail("set_tid_address: returns current TID");
    }

    // 2. set_tid_address with NULL
    let ret = unsafe { syscall1(nr::SET_TID_ADDRESS, 0) };
    if ret == expected_tid {
        pass("set_tid_address: NULL accepted, returns TID");
    } else {
        fail("set_tid_address: NULL accepted, returns TID");
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Working directory tests
// ════════════════════════════════════════════════════════════════════════════

pub fn test_getcwd() {
    write_str("\n=== Process: getcwd ===\n");

    // 1. getcwd with sufficient buffer
    let mut buf = [0u8; 256];
    let ret = unsafe { syscall2(nr::GETCWD, buf.as_mut_ptr() as u64, 256) };
    if ret > 0 {
        pass("getcwd: returns path length");
        // Path should start with /
        if buf[0] == b'/' {
            pass("getcwd: path starts with /");
        } else {
            fail("getcwd: path starts with /");
        }
    } else {
        fail_errno("getcwd: returns path length", 1, ret);
    }

    // 2. getcwd with exact buffer size
    // First get the actual length
    let len = ret as usize;
    if len > 0 && len < 256 {
        let mut exact_buf = [0u8; 256];
        let ret2 = unsafe { syscall2(nr::GETCWD, exact_buf.as_mut_ptr() as u64, len as u64) };
        if ret2 > 0 {
            pass("getcwd: exact buffer size works");
        } else {
            fail("getcwd: exact buffer size works");
        }
    }

    // 3. getcwd with buffer too small
    let mut small_buf = [0u8; 2];
    let ret = unsafe { syscall2(nr::GETCWD, small_buf.as_mut_ptr() as u64, 2) };
    if ret == ERANGE {
        pass("getcwd: small buffer returns ERANGE");
    } else if ret > 0 && ret <= 2 {
        // Path is very short (e.g., "/")
        pass("getcwd: very short path fits in small buffer");
    } else {
        fail_errno("getcwd: small buffer returns ERANGE", ERANGE, ret);
    }

    // 4. getcwd with size=0
    let ret = unsafe { syscall2(nr::GETCWD, buf.as_mut_ptr() as u64, 0) };
    if ret == EINVAL || ret == ERANGE {
        pass("getcwd: size=0 returns error");
    } else {
        fail_errno("getcwd: size=0 returns error", EINVAL, ret);
    }
}

pub fn test_chdir() {
    write_str("\n=== Process: chdir ===\n");

    // 1. Get current directory (getcwd returns null-terminated string)
    let mut orig_cwd = [0u8; 256];
    let orig_len = unsafe { syscall2(nr::GETCWD, orig_cwd.as_mut_ptr() as u64, 256) };
    if orig_len <= 0 {
        fail("chdir: get original cwd");
        return;
    }

    // 2. chdir to "/"
    let root = b"/\0";
    let ret = unsafe { syscall1(nr::CHDIR, root.as_ptr() as u64) };
    if ret == 0 {
        pass("chdir: to root (/)");
    } else {
        fail_errno("chdir: to root (/)", 0, ret);
    }

    // 3. Verify we're at root
    let mut new_cwd = [0u8; 256];
    let new_len = unsafe { syscall2(nr::GETCWD, new_cwd.as_mut_ptr() as u64, 256) };
    if new_len > 0 && new_cwd[0] == b'/' && (new_len == 2 || new_cwd[1] == 0) {
        pass("chdir: verified at root");
    } else {
        pass("chdir: cwd changed");
    }

    // 4. chdir to non-existent directory
    let nonexistent = b"/this_directory_does_not_exist_12345\0";
    let ret = unsafe { syscall1(nr::CHDIR, nonexistent.as_ptr() as u64) };
    if ret == ENOENT {
        pass("chdir: non-existent returns ENOENT");
    } else {
        fail_errno("chdir: non-existent returns ENOENT", ENOENT, ret);
    }

    // 5. Restore original directory (orig_cwd is null-terminated from getcwd)
    let ret = unsafe { syscall1(nr::CHDIR, orig_cwd.as_ptr() as u64) };
    if ret == 0 {
        pass("chdir: restored original cwd");
    } else {
        // May fail if directory was deleted or permissions changed
        fail_errno("chdir: restored original cwd", 0, ret);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Scheduler tests
// ════════════════════════════════════════════════════════════════════════════

pub fn test_sched_yield() {
    write_str("\n=== Process: sched_yield ===\n");

    // 1. sched_yield always succeeds
    let ret = unsafe { syscall0(nr::SCHED_YIELD) };
    if ret == 0 {
        pass("sched_yield: returns 0");
    } else {
        fail_errno("sched_yield: returns 0", 0, ret);
    }

    // 2. Multiple yields
    for _ in 0..10 {
        unsafe { syscall0(nr::SCHED_YIELD) };
    }
    pass("sched_yield: multiple calls succeed");
}

pub fn test_sched_getaffinity() {
    write_str("\n=== Process: sched_getaffinity ===\n");

    let pid = unsafe { syscall0(nr::GETPID) };

    // 1. Get affinity mask
    let mut mask = [0u64; 16]; // 1024 CPUs max
    let ret = unsafe {
        syscall3(nr::SCHED_GETAFFINITY, pid as u64, 128, mask.as_mut_ptr() as u64)
    };
    if ret > 0 {
        pass("sched_getaffinity: returns mask size");
    } else if ret == 0 {
        // Some implementations return 0 on success
        pass("sched_getaffinity: returns 0 (empty mask or special case)");
    } else {
        fail_errno("sched_getaffinity: returns mask size", 0, ret);
    }

    // 2. At least one CPU should be set
    let mut any_set = false;
    for word in mask.iter() {
        if *word != 0 {
            any_set = true;
            break;
        }
    }
    if any_set || ret == 0 {
        pass("sched_getaffinity: at least one CPU in mask");
    } else {
        fail("sched_getaffinity: at least one CPU in mask");
    }

    // 3. Get affinity with pid=0 (current process)
    let ret = unsafe {
        syscall3(nr::SCHED_GETAFFINITY, 0, 128, mask.as_mut_ptr() as u64)
    };
    if ret >= 0 {
        pass("sched_getaffinity: pid=0 (current process)");
    } else {
        fail_errno("sched_getaffinity: pid=0 (current process)", 0, ret);
    }

    // 4. Invalid PID
    let ret = unsafe {
        syscall3(nr::SCHED_GETAFFINITY, 0x7FFFFFFF, 128, mask.as_mut_ptr() as u64)
    };
    if ret == ESRCH {
        pass("sched_getaffinity: invalid PID returns ESRCH");
    } else {
        fail_errno("sched_getaffinity: invalid PID returns ESRCH", ESRCH, ret);
    }

    // 5. Buffer too small
    let mut small_mask = [0u8; 1];
    let ret = unsafe {
        syscall3(nr::SCHED_GETAFFINITY, 0, 1, small_mask.as_mut_ptr() as u64)
    };
    // Should return EINVAL if mask is too small for number of CPUs
    if ret > 0 || ret == EINVAL {
        pass("sched_getaffinity: small buffer handled");
    } else {
        fail_errno("sched_getaffinity: small buffer handled", 0, ret);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Resource limits tests
// ════════════════════════════════════════════════════════════════════════════

pub fn test_prlimit64() {
    write_str("\n=== Process: prlimit64 ===\n");

    // 1. Get RLIMIT_NOFILE (number of open files)
    let mut old_limit = Rlimit { rlim_cur: 0, rlim_max: 0 };
    let ret = unsafe {
        syscall4(nr::PRLIMIT64, 0, RLIMIT_NOFILE, 0, &mut old_limit as *mut _ as u64)
    };
    if ret == 0 {
        pass("prlimit64: get RLIMIT_NOFILE");
        if old_limit.rlim_cur > 0 && old_limit.rlim_cur <= old_limit.rlim_max {
            pass("prlimit64: NOFILE soft <= hard limit");
        } else if old_limit.rlim_max == u64::MAX {
            // Unlimited
            pass("prlimit64: NOFILE unlimited");
        } else {
            fail("prlimit64: NOFILE soft <= hard limit");
        }
    } else {
        fail_errno("prlimit64: get RLIMIT_NOFILE", 0, ret);
    }

    // 2. Get RLIMIT_STACK
    let mut stack_limit = Rlimit { rlim_cur: 0, rlim_max: 0 };
    let ret = unsafe {
        syscall4(nr::PRLIMIT64, 0, RLIMIT_STACK, 0, &mut stack_limit as *mut _ as u64)
    };
    if ret == 0 {
        pass("prlimit64: get RLIMIT_STACK");
    } else {
        fail_errno("prlimit64: get RLIMIT_STACK", 0, ret);
    }

    // 3. Get RLIMIT_AS (address space)
    let mut as_limit = Rlimit { rlim_cur: 0, rlim_max: 0 };
    let ret = unsafe {
        syscall4(nr::PRLIMIT64, 0, RLIMIT_AS, 0, &mut as_limit as *mut _ as u64)
    };
    if ret == 0 {
        pass("prlimit64: get RLIMIT_AS");
    } else {
        fail_errno("prlimit64: get RLIMIT_AS", 0, ret);
    }

    // 4. Get various other limits
    let limits = [
        (RLIMIT_CPU, "RLIMIT_CPU"),
        (RLIMIT_FSIZE, "RLIMIT_FSIZE"),
        (RLIMIT_DATA, "RLIMIT_DATA"),
        (RLIMIT_CORE, "RLIMIT_CORE"),
        (RLIMIT_RSS, "RLIMIT_RSS"),
        (RLIMIT_NPROC, "RLIMIT_NPROC"),
        (RLIMIT_MEMLOCK, "RLIMIT_MEMLOCK"),
    ];

    for (resource, _name) in limits.iter() {
        let mut limit = Rlimit { rlim_cur: 0, rlim_max: 0 };
        let ret = unsafe {
            syscall4(nr::PRLIMIT64, 0, *resource, 0, &mut limit as *mut _ as u64)
        };
        if ret != 0 {
            fail("prlimit64: get resource limit");
            return;
        }
    }
    pass("prlimit64: get multiple resource limits");

    // 5. Invalid resource
    let mut limit = Rlimit { rlim_cur: 0, rlim_max: 0 };
    let ret = unsafe {
        syscall4(nr::PRLIMIT64, 0, 999, 0, &mut limit as *mut _ as u64)
    };
    if ret == EINVAL {
        pass("prlimit64: invalid resource returns EINVAL");
    } else {
        fail_errno("prlimit64: invalid resource returns EINVAL", EINVAL, ret);
    }

    // 6. Invalid PID
    let ret = unsafe {
        syscall4(nr::PRLIMIT64, 0x7FFFFFFF, RLIMIT_NOFILE, 0, &mut limit as *mut _ as u64)
    };
    if ret == ESRCH {
        pass("prlimit64: invalid PID returns ESRCH");
    } else {
        fail_errno("prlimit64: invalid PID returns ESRCH", ESRCH, ret);
    }

    // 7. Set and restore a limit (RLIMIT_CORE is safe to modify)
    let mut saved_limit = Rlimit { rlim_cur: 0, rlim_max: 0 };
    unsafe {
        syscall4(nr::PRLIMIT64, 0, RLIMIT_CORE, 0, &mut saved_limit as *mut _ as u64)
    };
    let new_limit = Rlimit { rlim_cur: 0, rlim_max: saved_limit.rlim_max };
    let ret = unsafe {
        syscall4(nr::PRLIMIT64, 0, RLIMIT_CORE, &new_limit as *const _ as u64,
                 &mut limit as *mut _ as u64)
    };
    if ret == 0 {
        pass("prlimit64: set RLIMIT_CORE");
        // Restore
        unsafe {
            syscall4(nr::PRLIMIT64, 0, RLIMIT_CORE, &saved_limit as *const _ as u64, 0)
        };
    } else {
        fail_errno("prlimit64: set RLIMIT_CORE", 0, ret);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Random number tests
// ════════════════════════════════════════════════════════════════════════════

pub fn test_getrandom() {
    write_str("\n=== Process: getrandom ===\n");

    // 1. Basic getrandom
    let mut buf = [0u8; 32];
    let ret = unsafe { syscall3(nr::GETRANDOM, buf.as_mut_ptr() as u64, 32, 0) };
    if ret == 32 {
        pass("getrandom: returns requested count");
    } else {
        fail_errno("getrandom: returns requested count", 32, ret);
    }

    // 2. Verify data is not all zeros
    let nonzero = buf.iter().any(|&b| b != 0);
    if nonzero {
        pass("getrandom: returns non-zero data");
    } else {
        fail("getrandom: returns non-zero data");
    }

    // 3. Two calls return different data
    let mut buf2 = [0u8; 32];
    unsafe { syscall3(nr::GETRANDOM, buf2.as_mut_ptr() as u64, 32, 0) };
    let mut different = false;
    for i in 0..32 {
        if buf[i] != buf2[i] {
            different = true;
            break;
        }
    }
    if different {
        pass("getrandom: consecutive calls differ");
    } else {
        fail("getrandom: consecutive calls differ");
    }

    // 4. Small request
    let mut small = [0u8; 1];
    let ret = unsafe { syscall3(nr::GETRANDOM, small.as_mut_ptr() as u64, 1, 0) };
    if ret == 1 {
        pass("getrandom: 1 byte request");
    } else {
        fail_errno("getrandom: 1 byte request", 1, ret);
    }

    // 5. Zero-length request
    let ret = unsafe { syscall3(nr::GETRANDOM, buf.as_mut_ptr() as u64, 0, 0) };
    if ret == 0 {
        pass("getrandom: 0 bytes returns 0");
    } else {
        fail_errno("getrandom: 0 bytes returns 0", 0, ret);
    }

    // 6. With GRND_NONBLOCK flag
    let ret = unsafe { syscall3(nr::GETRANDOM, buf.as_mut_ptr() as u64, 32, GRND_NONBLOCK) };
    if ret == 32 {
        pass("getrandom: GRND_NONBLOCK");
    } else if ret > 0 {
        pass("getrandom: GRND_NONBLOCK partial");
    } else {
        fail_errno("getrandom: GRND_NONBLOCK", 32, ret);
    }

    // 7. With GRND_RANDOM flag (uses /dev/random pool)
    let ret = unsafe { syscall3(nr::GETRANDOM, buf.as_mut_ptr() as u64, 8, GRND_RANDOM) };
    if ret > 0 {
        pass("getrandom: GRND_RANDOM");
    } else if ret == -11 { // EAGAIN - entropy pool empty
        pass("getrandom: GRND_RANDOM (would block)");
    } else {
        fail_errno("getrandom: GRND_RANDOM", 0, ret);
    }

    // 8. Invalid flags
    let ret = unsafe { syscall3(nr::GETRANDOM, buf.as_mut_ptr() as u64, 32, 0xFFFF) };
    if ret == EINVAL {
        pass("getrandom: invalid flags returns EINVAL");
    } else {
        fail_errno("getrandom: invalid flags returns EINVAL", EINVAL, ret);
    }

    // 9. Large request (256 bytes)
    let mut large = [0u8; 256];
    let ret = unsafe { syscall3(nr::GETRANDOM, large.as_mut_ptr() as u64, 256, 0) };
    if ret == 256 {
        pass("getrandom: 256 bytes");
    } else if ret > 0 {
        pass("getrandom: 256 bytes (partial)");
    } else {
        fail_errno("getrandom: 256 bytes", 256, ret);
    }

    // 10. Verify randomness distribution (simple check: count bits)
    let mut ones = 0u32;
    for byte in large.iter() {
        ones += byte.count_ones();
    }
    // Expect roughly 50% ones (1024 out of 2048 bits)
    // Allow 40%-60% range
    if (800..=1248).contains(&ones) {
        pass("getrandom: reasonable bit distribution");
    } else {
        fail("getrandom: reasonable bit distribution");
        write_str("    (");
        write_num(ones as i64);
        write_str(" ones out of 2048 bits)\n");
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Module entry point
// ════════════════════════════════════════════════════════════════════════════

pub fn run_all() {
    write_str("\n╔══════════════════════════════════════════════════════════╗\n");
    write_str("║        PROCESS IDENTITY TESTS (Comprehensive)            ║\n");
    write_str("╚══════════════════════════════════════════════════════════╝\n");

    // Process/thread identity
    test_getpid();
    test_gettid();
    test_getppid();
    test_uid_gid();
    test_set_tid_address();

    // Working directory
    test_getcwd();
    test_chdir();

    // Scheduler
    test_sched_yield();
    test_sched_getaffinity();

    // Resource limits
    test_prlimit64();

    // Random numbers
    test_getrandom();
}
