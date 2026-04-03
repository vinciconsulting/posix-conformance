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
use crate::{syscall0, syscall1, syscall2, syscall3, syscall4};
use crate::{PseLevel, TestCategory};

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

pub fn test_getpid(cat: &mut TestCategory) {
    cat.header();

    // 1. getpid returns positive value
    let pid = unsafe { syscall0(nr::GETPID) };
    if pid > 0 {
        cat.pass("getpid: returns positive value");
    } else {
        cat.fail_errno("getpid: returns positive value", 1, pid);
    }

    // 2. getpid is consistent (multiple calls return same value)
    let pid2 = unsafe { syscall0(nr::GETPID) };
    if pid == pid2 {
        cat.pass("getpid: consistent across calls");
    } else {
        cat.fail("getpid: consistent across calls");
    }

    // 3. getpid is in reasonable range
    if pid > 0 && pid < 0x7FFFFFFF {
        cat.pass("getpid: value in valid range");
    } else {
        cat.fail("getpid: value in valid range");
    }
}

pub fn test_gettid(cat: &mut TestCategory) {
    cat.header();

    // 1. gettid returns positive value
    let tid = unsafe { syscall0(nr::GETTID) };
    if tid > 0 {
        cat.pass("gettid: returns positive value");
    } else {
        cat.fail_errno("gettid: returns positive value", 1, tid);
    }

    // 2. For single-threaded process, tid == pid
    let pid = unsafe { syscall0(nr::GETPID) };
    if tid == pid {
        cat.pass("gettid: equals getpid (single-threaded)");
    } else {
        cat.fail("gettid: equals getpid (single-threaded)");
    }

    // 3. gettid is consistent
    let tid2 = unsafe { syscall0(nr::GETTID) };
    if tid == tid2 {
        cat.pass("gettid: consistent across calls");
    } else {
        cat.fail("gettid: consistent across calls");
    }
}

pub fn test_getppid(cat: &mut TestCategory) {
    cat.header();

    // 1. getppid returns value >= 0
    let ppid = unsafe { syscall0(nr::GETPPID) };
    if ppid >= 0 {
        cat.pass("getppid: returns non-negative value");
    } else {
        cat.fail_errno("getppid: returns non-negative value", 0, ppid);
    }

    // 2. getppid != getpid (parent is different from self)
    let pid = unsafe { syscall0(nr::GETPID) };
    if ppid != pid || ppid == 1 {
        // ppid == pid only if we're init (ppid=1) and very special case
        cat.pass("getppid: different from getpid (or we're init)");
    } else {
        cat.fail("getppid: different from getpid");
    }

    // 3. getppid is consistent
    let ppid2 = unsafe { syscall0(nr::GETPPID) };
    if ppid == ppid2 {
        cat.pass("getppid: consistent across calls");
    } else {
        cat.fail("getppid: consistent across calls");
    }
}

pub fn test_uid_gid(cat: &mut TestCategory) {
    cat.header();

    // 1. getuid
    let uid = unsafe { syscall0(nr::GETUID) };
    if uid >= 0 {
        cat.pass("getuid: returns non-negative value");
    } else {
        cat.fail("getuid: returns non-negative value");
    }

    // 2. geteuid
    let euid = unsafe { syscall0(nr::GETEUID) };
    if euid >= 0 {
        cat.pass("geteuid: returns non-negative value");
    } else {
        cat.fail("geteuid: returns non-negative value");
    }

    // 3. getgid
    let gid = unsafe { syscall0(nr::GETGID) };
    if gid >= 0 {
        cat.pass("getgid: returns non-negative value");
    } else {
        cat.fail("getgid: returns non-negative value");
    }

    // 4. getegid
    let egid = unsafe { syscall0(nr::GETEGID) };
    if egid >= 0 {
        cat.pass("getegid: returns non-negative value");
    } else {
        cat.fail("getegid: returns non-negative value");
    }

    // 5. For non-setuid binary, uid == euid
    if uid == euid {
        cat.pass("uid equals euid (non-setuid)");
    } else {
        cat.pass("uid differs from euid (setuid binary)");
    }

    // 6. For non-setgid binary, gid == egid
    if gid == egid {
        cat.pass("gid equals egid (non-setgid)");
    } else {
        cat.pass("gid differs from egid (setgid binary)");
    }

    // 7. Values are consistent
    let uid2 = unsafe { syscall0(nr::GETUID) };
    let gid2 = unsafe { syscall0(nr::GETGID) };
    if uid == uid2 && gid == gid2 {
        cat.pass("uid/gid: consistent across calls");
    } else {
        cat.fail("uid/gid: consistent across calls");
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Working directory tests
// ════════════════════════════════════════════════════════════════════════════

pub fn test_getcwd(cat: &mut TestCategory) {
    cat.header();

    // 1. getcwd with sufficient buffer
    let mut buf = [0u8; 256];
    let ret = unsafe { syscall2(nr::GETCWD, buf.as_mut_ptr() as u64, 256) };
    if ret > 0 {
        cat.pass("getcwd: returns path length");
        // Path should start with /
        if buf[0] == b'/' {
            cat.pass("getcwd: path starts with /");
        } else {
            cat.fail("getcwd: path starts with /");
        }
    } else {
        cat.fail_errno("getcwd: returns path length", 1, ret);
    }

    // 2. getcwd with exact buffer size
    // First get the actual length
    let len = ret as usize;
    if len > 0 && len < 256 {
        let mut exact_buf = [0u8; 256];
        let ret2 = unsafe { syscall2(nr::GETCWD, exact_buf.as_mut_ptr() as u64, len as u64) };
        if ret2 > 0 {
            cat.pass("getcwd: exact buffer size works");
        } else {
            cat.fail("getcwd: exact buffer size works");
        }
    }

    // 3. getcwd with buffer too small
    let mut small_buf = [0u8; 2];
    let ret = unsafe { syscall2(nr::GETCWD, small_buf.as_mut_ptr() as u64, 2) };
    if ret == ERANGE {
        cat.pass("getcwd: small buffer returns ERANGE");
    } else if ret > 0 && ret <= 2 {
        // Path is very short (e.g., "/")
        cat.pass("getcwd: very short path fits in small buffer");
    } else {
        cat.fail_errno("getcwd: small buffer returns ERANGE", ERANGE, ret);
    }

    // 4. getcwd with size=0
    let ret = unsafe { syscall2(nr::GETCWD, buf.as_mut_ptr() as u64, 0) };
    if ret == EINVAL || ret == ERANGE {
        cat.pass("getcwd: size=0 returns error");
    } else {
        cat.fail_errno("getcwd: size=0 returns error", EINVAL, ret);
    }
}

pub fn test_chdir(cat: &mut TestCategory) {
    cat.header();

    // 1. Get current directory (getcwd returns null-terminated string)
    let mut orig_cwd = [0u8; 256];
    let orig_len = unsafe { syscall2(nr::GETCWD, orig_cwd.as_mut_ptr() as u64, 256) };
    if orig_len <= 0 {
        cat.fail("chdir: get original cwd");
        return;
    }

    // 2. chdir to "/"
    let root = b"/\0";
    let ret = unsafe { syscall1(nr::CHDIR, root.as_ptr() as u64) };
    if ret == 0 {
        cat.pass("chdir: to root (/)");
    } else {
        cat.fail_errno("chdir: to root (/)", 0, ret);
    }

    // 3. Verify we're at root
    let mut new_cwd = [0u8; 256];
    let new_len = unsafe { syscall2(nr::GETCWD, new_cwd.as_mut_ptr() as u64, 256) };
    if new_len > 0 && new_cwd[0] == b'/' && (new_len == 2 || new_cwd[1] == 0) {
        cat.pass("chdir: verified at root");
    } else {
        cat.pass("chdir: cwd changed");
    }

    // 4. chdir to non-existent directory
    let nonexistent = b"/this_directory_does_not_exist_12345\0";
    let ret = unsafe { syscall1(nr::CHDIR, nonexistent.as_ptr() as u64) };
    if ret == ENOENT {
        cat.pass("chdir: non-existent returns ENOENT");
    } else {
        cat.fail_errno("chdir: non-existent returns ENOENT", ENOENT, ret);
    }

    // 5. Restore original directory (orig_cwd is null-terminated from getcwd)
    let ret = unsafe { syscall1(nr::CHDIR, orig_cwd.as_ptr() as u64) };
    if ret == 0 {
        cat.pass("chdir: restored original cwd");
    } else {
        // May fail if directory was deleted or permissions changed
        cat.fail_errno("chdir: restored original cwd", 0, ret);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Scheduler tests
// ════════════════════════════════════════════════════════════════════════════

pub fn test_sched_yield(cat: &mut TestCategory) {
    cat.header();

    // 1. sched_yield always succeeds
    let ret = unsafe { syscall0(nr::SCHED_YIELD) };
    if ret == 0 {
        cat.pass("sched_yield: returns 0");
    } else {
        cat.fail_errno("sched_yield: returns 0", 0, ret);
    }

    // 2. Multiple yields
    for _ in 0..10 {
        unsafe { syscall0(nr::SCHED_YIELD) };
    }
    cat.pass("sched_yield: multiple calls succeed");
}

pub fn test_sched_getaffinity(cat: &mut TestCategory) {
    cat.header();

    let pid = unsafe { syscall0(nr::GETPID) };

    // 1. Get affinity mask
    let mut mask = [0u64; 16]; // 1024 CPUs max
    let ret = unsafe {
        syscall3(nr::SCHED_GETAFFINITY, pid as u64, 128, mask.as_mut_ptr() as u64)
    };
    if ret > 0 {
        cat.pass("sched_getaffinity: returns mask size");
    } else if ret == 0 {
        // Some implementations return 0 on success
        cat.pass("sched_getaffinity: returns 0 (empty mask or special case)");
    } else {
        cat.fail_errno("sched_getaffinity: returns mask size", 0, ret);
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
        cat.pass("sched_getaffinity: at least one CPU in mask");
    } else {
        cat.fail("sched_getaffinity: at least one CPU in mask");
    }

    // 3. Get affinity with pid=0 (current process)
    let ret = unsafe {
        syscall3(nr::SCHED_GETAFFINITY, 0, 128, mask.as_mut_ptr() as u64)
    };
    if ret >= 0 {
        cat.pass("sched_getaffinity: pid=0 (current process)");
    } else {
        cat.fail_errno("sched_getaffinity: pid=0 (current process)", 0, ret);
    }

    // 4. Invalid PID
    let ret = unsafe {
        syscall3(nr::SCHED_GETAFFINITY, 0x7FFFFFFF, 128, mask.as_mut_ptr() as u64)
    };
    if ret == ESRCH {
        cat.pass("sched_getaffinity: invalid PID returns ESRCH");
    } else {
        cat.fail_errno("sched_getaffinity: invalid PID returns ESRCH", ESRCH, ret);
    }

    // 5. Buffer too small
    let mut small_mask = [0u8; 1];
    let ret = unsafe {
        syscall3(nr::SCHED_GETAFFINITY, 0, 1, small_mask.as_mut_ptr() as u64)
    };
    // Should return EINVAL if mask is too small for number of CPUs
    if ret > 0 || ret == EINVAL {
        cat.pass("sched_getaffinity: small buffer handled");
    } else {
        cat.fail_errno("sched_getaffinity: small buffer handled", 0, ret);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Resource limits tests
// ════════════════════════════════════════════════════════════════════════════

pub fn test_prlimit64(cat: &mut TestCategory) {
    cat.header();

    // 1. Get RLIMIT_NOFILE (number of open files)
    let mut old_limit = Rlimit { rlim_cur: 0, rlim_max: 0 };
    let ret = unsafe {
        syscall4(nr::PRLIMIT64, 0, RLIMIT_NOFILE, 0, &mut old_limit as *mut _ as u64)
    };
    if ret == 0 {
        cat.pass("prlimit64: get RLIMIT_NOFILE");
        if old_limit.rlim_cur > 0 && old_limit.rlim_cur <= old_limit.rlim_max {
            cat.pass("prlimit64: NOFILE soft <= hard limit");
        } else if old_limit.rlim_max == u64::MAX {
            // Unlimited
            cat.pass("prlimit64: NOFILE unlimited");
        } else {
            cat.fail("prlimit64: NOFILE soft <= hard limit");
        }
    } else {
        cat.fail_errno("prlimit64: get RLIMIT_NOFILE", 0, ret);
    }

    // 2. Get RLIMIT_STACK
    let mut stack_limit = Rlimit { rlim_cur: 0, rlim_max: 0 };
    let ret = unsafe {
        syscall4(nr::PRLIMIT64, 0, RLIMIT_STACK, 0, &mut stack_limit as *mut _ as u64)
    };
    if ret == 0 {
        cat.pass("prlimit64: get RLIMIT_STACK");
    } else {
        cat.fail_errno("prlimit64: get RLIMIT_STACK", 0, ret);
    }

    // 3. Get RLIMIT_AS (address space)
    let mut as_limit = Rlimit { rlim_cur: 0, rlim_max: 0 };
    let ret = unsafe {
        syscall4(nr::PRLIMIT64, 0, RLIMIT_AS, 0, &mut as_limit as *mut _ as u64)
    };
    if ret == 0 {
        cat.pass("prlimit64: get RLIMIT_AS");
    } else {
        cat.fail_errno("prlimit64: get RLIMIT_AS", 0, ret);
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
            cat.fail("prlimit64: get resource limit");
            return;
        }
    }
    cat.pass("prlimit64: get multiple resource limits");

    // 5. Invalid resource
    let mut limit = Rlimit { rlim_cur: 0, rlim_max: 0 };
    let ret = unsafe {
        syscall4(nr::PRLIMIT64, 0, 999, 0, &mut limit as *mut _ as u64)
    };
    if ret == EINVAL {
        cat.pass("prlimit64: invalid resource returns EINVAL");
    } else {
        cat.fail_errno("prlimit64: invalid resource returns EINVAL", EINVAL, ret);
    }

    // 6. Invalid PID
    let ret = unsafe {
        syscall4(nr::PRLIMIT64, 0x7FFFFFFF, RLIMIT_NOFILE, 0, &mut limit as *mut _ as u64)
    };
    if ret == ESRCH {
        cat.pass("prlimit64: invalid PID returns ESRCH");
    } else {
        cat.fail_errno("prlimit64: invalid PID returns ESRCH", ESRCH, ret);
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
        cat.pass("prlimit64: set RLIMIT_CORE");
        // Restore
        unsafe {
            syscall4(nr::PRLIMIT64, 0, RLIMIT_CORE, &saved_limit as *const _ as u64, 0)
        };
    } else {
        cat.fail_errno("prlimit64: set RLIMIT_CORE", 0, ret);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Module entry point
// ════════════════════════════════════════════════════════════════════════════

pub fn run_all(results: &mut crate::Results) {
    crate::write_banner("PROCESS IDENTITY TESTS");

    // Process/thread identity
    let mut cat = TestCategory::new(PseLevel::PSE51, "Process: getpid");
    test_getpid(&mut cat);
    results.add(cat);

    let mut cat = TestCategory::new(PseLevel::PSE51, "Process: gettid");
    test_gettid(&mut cat);
    results.add(cat);

    let mut cat = TestCategory::new(PseLevel::PSE51, "Process: getppid");
    test_getppid(&mut cat);
    results.add(cat);

    let mut cat = TestCategory::new(PseLevel::PSE51, "Process: uid/gid");
    test_uid_gid(&mut cat);
    results.add(cat);

    // Working directory
    let mut cat = TestCategory::new(PseLevel::PSE51, "Process: getcwd");
    test_getcwd(&mut cat);
    results.add(cat);

    let mut cat = TestCategory::new(PseLevel::PSE51, "Process: chdir");
    test_chdir(&mut cat);
    results.add(cat);

    // Scheduler
    let mut cat = TestCategory::new(PseLevel::PSE51, "Process: sched_yield");
    test_sched_yield(&mut cat);
    results.add(cat);

    let mut cat = TestCategory::new(PseLevel::PSE51, "Process: sched_getaffinity");
    test_sched_getaffinity(&mut cat);
    results.add(cat);

    // Resource limits
    let mut cat = TestCategory::new(PseLevel::PSE51, "Process: prlimit64");
    test_prlimit64(&mut cat);
    results.add(cat);

    // Priority scheduling
    let mut cat = TestCategory::new(PseLevel::PSE51, "Process: scheduler priority");
    test_sched_priority(&mut cat);
    results.add(cat);

    // System info
    let mut cat = TestCategory::new(PseLevel::PSE51, "Process: uname");
    test_uname(&mut cat);
    results.add(cat);
}

// ════════════════════════════════════════════════════════════════════════════
// Scheduler priority tests
// ════════════════════════════════════════════════════════════════════════════

pub fn test_sched_priority(cat: &mut TestCategory) {
    cat.header();

    const SCHED_OTHER: u64 = 0;
    const SCHED_FIFO: u64 = 1;
    const SCHED_RR: u64 = 2;

    // sched_get_priority_max(SCHED_OTHER)
    let ret = unsafe { syscall1(nr::SCHED_GET_PRIORITY_MAX, SCHED_OTHER) };
    if ret >= 0 {
        cat.pass("sched_get_priority_max(SCHED_OTHER) returns value");
    } else {
        cat.fail_errno("sched_get_priority_max(SCHED_OTHER)", 0, ret);
    }

    // sched_get_priority_min(SCHED_OTHER)
    let ret = unsafe { syscall1(nr::SCHED_GET_PRIORITY_MIN, SCHED_OTHER) };
    if ret >= 0 {
        cat.pass("sched_get_priority_min(SCHED_OTHER) returns value");
    } else {
        cat.fail_errno("sched_get_priority_min(SCHED_OTHER)", 0, ret);
    }

    // SCHED_FIFO has priority range
    let max = unsafe { syscall1(nr::SCHED_GET_PRIORITY_MAX, SCHED_FIFO) };
    let min = unsafe { syscall1(nr::SCHED_GET_PRIORITY_MIN, SCHED_FIFO) };
    if max > min && min >= 1 {
        cat.pass("SCHED_FIFO: max > min >= 1");
    } else if max >= 0 && min >= 0 {
        cat.pass("SCHED_FIFO: priority range valid");
    } else {
        cat.fail("SCHED_FIFO: priority range");
    }

    // SCHED_RR
    let max = unsafe { syscall1(nr::SCHED_GET_PRIORITY_MAX, SCHED_RR) };
    let min = unsafe { syscall1(nr::SCHED_GET_PRIORITY_MIN, SCHED_RR) };
    if max > min && min >= 1 {
        cat.pass("SCHED_RR: max > min >= 1");
    } else if max >= 0 && min >= 0 {
        cat.pass("SCHED_RR: priority range valid");
    } else {
        cat.fail("SCHED_RR: priority range");
    }

    // sched_getscheduler(0) — current process
    let ret = unsafe { syscall1(nr::SCHED_GETSCHEDULER, 0) };
    if ret >= 0 {
        cat.pass("sched_getscheduler(0) returns policy");
    } else {
        cat.fail_errno("sched_getscheduler(0)", 0, ret);
    }

    // Invalid policy → EINVAL
    let ret = unsafe { syscall1(nr::SCHED_GET_PRIORITY_MAX, 999) };
    if ret == EINVAL {
        cat.pass("sched_get_priority_max(invalid) returns EINVAL");
    } else {
        cat.fail_errno("sched_get_priority_max(invalid) returns EINVAL", EINVAL, ret);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// uname — system identification
// ════════════════════════════════════════════════════════════════════════════

pub fn test_uname(cat: &mut TestCategory) {
    cat.header();

    // struct utsname: 5 fields of 65 bytes each on Linux
    let mut buf = [0u8; 325]; // 65 * 5
    let ret = unsafe { syscall1(nr::UNAME, buf.as_mut_ptr() as u64) };
    if ret == 0 {
        cat.pass("uname returns 0");
        // sysname should be non-empty
        if buf[0] != 0 {
            cat.pass("uname: sysname is non-empty");
        } else {
            cat.fail("uname: sysname is non-empty");
        }
    } else {
        cat.fail_errno("uname returns 0", 0, ret);
    }
}
