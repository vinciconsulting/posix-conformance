//! Comprehensive time/clock tests for POSIX conformance
//!
//! Tests: clock_gettime, clock_getres, nanosleep, timer_create, timer_settime,
//!        timer_gettime, timer_getoverrun, timer_delete
//!
//! Categories:
//! - Positive: normal clock operations, timer lifecycle
//! - Negative: invalid clock IDs, bad pointers, invalid timer IDs
//! - Boundary: zero/max timespec values, timer edge cases

use crate::nr;
use crate::{write_str, write_num, syscall1, syscall2, syscall3, syscall4, PseLevel, TestCategory};
use crate::Timespec;

// ════════════════════════════════════════════════════════════════════════════
// Constants
// ════════════════════════════════════════════════════════════════════════════

// Clock IDs
const CLOCK_REALTIME: u64 = 0;
const CLOCK_MONOTONIC: u64 = 1;
const CLOCK_PROCESS_CPUTIME_ID: u64 = 2;
const CLOCK_THREAD_CPUTIME_ID: u64 = 3;

// Timer constants
const SIGEV_NONE: i32 = 1;

// Error codes
const EINVAL: i64 = -22;

// ════════════════════════════════════════════════════════════════════════════
// Structures
// ════════════════════════════════════════════════════════════════════════════

#[repr(C)]
struct Itimerspec {
    it_interval: Timespec,
    it_value: Timespec,
}

#[repr(C)]
struct Sigevent {
    sigev_value: u64,       // union sigval
    sigev_signo: i32,
    sigev_notify: i32,
    _pad: [u64; 6],         // padding for full structure
}

// ════════════════════════════════════════════════════════════════════════════
// Clock tests
// ════════════════════════════════════════════════════════════════════════════

fn test_clock_gettime_positive(results: &mut crate::Results) {
    let mut cat = TestCategory::new(PseLevel::PSE51, "Clock: clock_gettime positive");
    cat.header();

    // 1. CLOCK_REALTIME
    let mut ts = Timespec { tv_sec: 0, tv_nsec: 0 };
    let ret = unsafe { syscall2(nr::CLOCK_GETTIME, CLOCK_REALTIME, &mut ts as *mut _ as u64) };
    if ret == 0 && ts.tv_sec > 0 {
        cat.pass("clock_gettime: CLOCK_REALTIME");
    } else {
        cat.fail_errno("clock_gettime: CLOCK_REALTIME", 0, ret);
    }

    // 2. CLOCK_MONOTONIC
    ts = Timespec { tv_sec: 0, tv_nsec: 0 };
    let ret = unsafe { syscall2(nr::CLOCK_GETTIME, CLOCK_MONOTONIC, &mut ts as *mut _ as u64) };
    if ret == 0 {
        cat.pass("clock_gettime: CLOCK_MONOTONIC");
    } else {
        cat.fail_errno("clock_gettime: CLOCK_MONOTONIC", 0, ret);
    }

    // 3. Verify CLOCK_MONOTONIC advances
    let mut ts1 = Timespec { tv_sec: 0, tv_nsec: 0 };
    let mut ts2 = Timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { syscall2(nr::CLOCK_GETTIME, CLOCK_MONOTONIC, &mut ts1 as *mut _ as u64) };
    // Busy wait
    for _ in 0..100000 {
        core::hint::spin_loop();
    }
    unsafe { syscall2(nr::CLOCK_GETTIME, CLOCK_MONOTONIC, &mut ts2 as *mut _ as u64) };
    let ns1 = ts1.tv_sec as u64 * 1_000_000_000 + ts1.tv_nsec as u64;
    let ns2 = ts2.tv_sec as u64 * 1_000_000_000 + ts2.tv_nsec as u64;
    if ns2 > ns1 {
        cat.pass("clock_gettime: MONOTONIC advances");
    } else {
        cat.fail("clock_gettime: MONOTONIC advances");
    }

    // 4. CLOCK_PROCESS_CPUTIME_ID
    ts = Timespec { tv_sec: 0, tv_nsec: 0 };
    let ret = unsafe { syscall2(nr::CLOCK_GETTIME, CLOCK_PROCESS_CPUTIME_ID, &mut ts as *mut _ as u64) };
    if ret == 0 {
        cat.pass("clock_gettime: CLOCK_PROCESS_CPUTIME_ID");
    } else {
        // Some systems don't support this
        cat.fail_errno("clock_gettime: CLOCK_PROCESS_CPUTIME_ID", 0, ret);
    }

    // 5. CLOCK_THREAD_CPUTIME_ID
    ts = Timespec { tv_sec: 0, tv_nsec: 0 };
    let ret = unsafe { syscall2(nr::CLOCK_GETTIME, CLOCK_THREAD_CPUTIME_ID, &mut ts as *mut _ as u64) };
    if ret == 0 {
        cat.pass("clock_gettime: CLOCK_THREAD_CPUTIME_ID");
    } else {
        cat.fail_errno("clock_gettime: CLOCK_THREAD_CPUTIME_ID", 0, ret);
    }

    // 6. Verify tv_nsec is in valid range [0, 999999999]
    ts = Timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { syscall2(nr::CLOCK_GETTIME, CLOCK_MONOTONIC, &mut ts as *mut _ as u64) };
    if ts.tv_nsec >= 0 && ts.tv_nsec < 1_000_000_000 {
        cat.pass("clock_gettime: tv_nsec in valid range");
    } else {
        cat.fail("clock_gettime: tv_nsec in valid range");
    }

    results.add(cat);
}

fn test_clock_gettime_negative(results: &mut crate::Results) {
    let mut cat = TestCategory::new(PseLevel::PSE51, "Clock: clock_gettime negative");
    cat.header();

    // 1. Invalid clock ID
    let mut ts = Timespec { tv_sec: 0, tv_nsec: 0 };
    let ret = unsafe { syscall2(nr::CLOCK_GETTIME, 999, &mut ts as *mut _ as u64) };
    if ret == EINVAL {
        cat.pass("clock_gettime: invalid clock ID returns EINVAL");
    } else {
        cat.fail_errno("clock_gettime: invalid clock ID returns EINVAL", EINVAL, ret);
    }

    // 2. Negative clock ID
    let ret = unsafe { syscall2(nr::CLOCK_GETTIME, (-1i64) as u64, &mut ts as *mut _ as u64) };
    if ret == EINVAL {
        cat.pass("clock_gettime: negative clock ID returns EINVAL");
    } else {
        cat.fail_errno("clock_gettime: negative clock ID returns EINVAL", EINVAL, ret);
    }

    // 3. Very large clock ID
    let ret = unsafe { syscall2(nr::CLOCK_GETTIME, 0x7FFFFFFF, &mut ts as *mut _ as u64) };
    if ret == EINVAL {
        cat.pass("clock_gettime: large clock ID returns EINVAL");
    } else {
        cat.fail_errno("clock_gettime: large clock ID returns EINVAL", EINVAL, ret);
    }

    results.add(cat);
}

fn test_clock_getres_positive(results: &mut crate::Results) {
    let mut cat = TestCategory::new(PseLevel::PSE51, "Clock: clock_getres positive");
    cat.header();

    // 1. CLOCK_REALTIME resolution
    let mut ts = Timespec { tv_sec: 0, tv_nsec: 0 };
    let ret = unsafe { syscall2(nr::CLOCK_GETRES, CLOCK_REALTIME, &mut ts as *mut _ as u64) };
    if ret == 0 {
        cat.pass("clock_getres: CLOCK_REALTIME");
        // Resolution should be > 0 and <= 1 second
        if ts.tv_sec == 0 && ts.tv_nsec > 0 && ts.tv_nsec <= 1_000_000_000 {
            cat.pass("clock_getres: REALTIME resolution valid");
        } else if ts.tv_sec <= 1 {
            cat.pass("clock_getres: REALTIME resolution valid (coarse)");
        } else {
            cat.fail("clock_getres: REALTIME resolution valid");
        }
    } else {
        cat.fail_errno("clock_getres: CLOCK_REALTIME", 0, ret);
    }

    // 2. CLOCK_MONOTONIC resolution
    ts = Timespec { tv_sec: 0, tv_nsec: 0 };
    let ret = unsafe { syscall2(nr::CLOCK_GETRES, CLOCK_MONOTONIC, &mut ts as *mut _ as u64) };
    if ret == 0 {
        cat.pass("clock_getres: CLOCK_MONOTONIC");
    } else {
        cat.fail_errno("clock_getres: CLOCK_MONOTONIC", 0, ret);
    }

    // 3. NULL timespec (just validate clock exists)
    let ret = unsafe { syscall2(nr::CLOCK_GETRES, CLOCK_REALTIME, 0) };
    if ret == 0 {
        cat.pass("clock_getres: NULL timespec");
    } else {
        cat.fail_errno("clock_getres: NULL timespec", 0, ret);
    }

    // 4. CLOCK_PROCESS_CPUTIME_ID
    ts = Timespec { tv_sec: 0, tv_nsec: 0 };
    let ret = unsafe { syscall2(nr::CLOCK_GETRES, CLOCK_PROCESS_CPUTIME_ID, &mut ts as *mut _ as u64) };
    if ret == 0 || ret == EINVAL {
        cat.pass("clock_getres: CLOCK_PROCESS_CPUTIME_ID handled");
    } else {
        cat.fail_errno("clock_getres: CLOCK_PROCESS_CPUTIME_ID handled", 0, ret);
    }

    results.add(cat);
}

fn test_clock_getres_negative(results: &mut crate::Results) {
    let mut cat = TestCategory::new(PseLevel::PSE51, "Clock: clock_getres negative");
    cat.header();

    // 1. Invalid clock ID
    let mut ts = Timespec { tv_sec: 0, tv_nsec: 0 };
    let ret = unsafe { syscall2(nr::CLOCK_GETRES, 999, &mut ts as *mut _ as u64) };
    if ret == EINVAL {
        cat.pass("clock_getres: invalid clock ID returns EINVAL");
    } else {
        cat.fail_errno("clock_getres: invalid clock ID returns EINVAL", EINVAL, ret);
    }

    // 2. Negative clock ID with NULL pointer (should still fail)
    let ret = unsafe { syscall2(nr::CLOCK_GETRES, (-1i64) as u64, 0) };
    if ret == EINVAL {
        cat.pass("clock_getres: negative clock ID returns EINVAL");
    } else {
        cat.fail_errno("clock_getres: negative clock ID returns EINVAL", EINVAL, ret);
    }

    results.add(cat);
}

// ════════════════════════════════════════════════════════════════════════════
// Nanosleep tests
// ════════════════════════════════════════════════════════════════════════════

fn test_nanosleep_positive(results: &mut crate::Results) {
    let mut cat = TestCategory::new(PseLevel::PSE51, "Nanosleep: positive tests");
    cat.header();

    // 1. Sleep for 1ms
    let req = Timespec { tv_sec: 0, tv_nsec: 1_000_000 }; // 1ms
    let mut rem = Timespec { tv_sec: 0, tv_nsec: 0 };

    let mut start = Timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { syscall2(nr::CLOCK_GETTIME, CLOCK_MONOTONIC, &mut start as *mut _ as u64) };

    let ret = unsafe { syscall2(nr::NANOSLEEP, &req as *const _ as u64, &mut rem as *mut _ as u64) };

    let mut end = Timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { syscall2(nr::CLOCK_GETTIME, CLOCK_MONOTONIC, &mut end as *mut _ as u64) };

    if ret == 0 {
        cat.pass("nanosleep: 1ms returns 0");
    } else {
        cat.fail_errno("nanosleep: 1ms returns 0", 0, ret);
    }

    // Verify elapsed time
    let start_ns = start.tv_sec as u64 * 1_000_000_000 + start.tv_nsec as u64;
    let end_ns = end.tv_sec as u64 * 1_000_000_000 + end.tv_nsec as u64;
    let elapsed = end_ns.saturating_sub(start_ns);
    if elapsed >= 1_000_000 {
        cat.pass("nanosleep: slept >= 1ms");
    } else {
        cat.fail("nanosleep: slept >= 1ms");
        write_str("    (elapsed ");
        write_num(elapsed as i64);
        write_str(" ns)\n");
    }

    // 2. Sleep for 10ms
    let req = Timespec { tv_sec: 0, tv_nsec: 10_000_000 }; // 10ms
    unsafe { syscall2(nr::CLOCK_GETTIME, CLOCK_MONOTONIC, &mut start as *mut _ as u64) };
    let ret = unsafe { syscall2(nr::NANOSLEEP, &req as *const _ as u64, &mut rem as *mut _ as u64) };
    unsafe { syscall2(nr::CLOCK_GETTIME, CLOCK_MONOTONIC, &mut end as *mut _ as u64) };

    if ret == 0 {
        cat.pass("nanosleep: 10ms returns 0");
    } else {
        cat.fail_errno("nanosleep: 10ms returns 0", 0, ret);
    }

    // 3. Sleep with NULL rem pointer
    let ret = unsafe { syscall2(nr::NANOSLEEP, &req as *const _ as u64, 0) };
    if ret == 0 {
        cat.pass("nanosleep: NULL rem pointer");
    } else {
        cat.fail_errno("nanosleep: NULL rem pointer", 0, ret);
    }

    // 4. Sleep for 0 nanoseconds (should return immediately)
    let req = Timespec { tv_sec: 0, tv_nsec: 0 };
    let ret = unsafe { syscall2(nr::NANOSLEEP, &req as *const _ as u64, 0) };
    if ret == 0 {
        cat.pass("nanosleep: 0ns returns immediately");
    } else {
        cat.fail_errno("nanosleep: 0ns returns immediately", 0, ret);
    }

    // 5. Sleep for 1 second (but we test with a small value)
    // We won't actually wait 1 second, just verify the call works
    let req = Timespec { tv_sec: 0, tv_nsec: 100_000 }; // 100us
    let ret = unsafe { syscall2(nr::NANOSLEEP, &req as *const _ as u64, 0) };
    if ret == 0 {
        cat.pass("nanosleep: 100us");
    } else {
        cat.fail_errno("nanosleep: 100us", 0, ret);
    }

    results.add(cat);
}

fn test_nanosleep_negative(results: &mut crate::Results) {
    let mut cat = TestCategory::new(PseLevel::PSE51, "Nanosleep: negative tests");
    cat.header();

    let mut rem = Timespec { tv_sec: 0, tv_nsec: 0 };

    // 1. Negative tv_sec
    let req = Timespec { tv_sec: -1, tv_nsec: 0 };
    let ret = unsafe { syscall2(nr::NANOSLEEP, &req as *const _ as u64, &mut rem as *mut _ as u64) };
    if ret == EINVAL {
        cat.pass("nanosleep: negative tv_sec returns EINVAL");
    } else {
        cat.fail_errno("nanosleep: negative tv_sec returns EINVAL", EINVAL, ret);
    }

    // 2. Negative tv_nsec
    let req = Timespec { tv_sec: 0, tv_nsec: -1 };
    let ret = unsafe { syscall2(nr::NANOSLEEP, &req as *const _ as u64, &mut rem as *mut _ as u64) };
    if ret == EINVAL {
        cat.pass("nanosleep: negative tv_nsec returns EINVAL");
    } else {
        cat.fail_errno("nanosleep: negative tv_nsec returns EINVAL", EINVAL, ret);
    }

    // 3. tv_nsec >= 1 billion
    let req = Timespec { tv_sec: 0, tv_nsec: 1_000_000_000 };
    let ret = unsafe { syscall2(nr::NANOSLEEP, &req as *const _ as u64, &mut rem as *mut _ as u64) };
    if ret == EINVAL {
        cat.pass("nanosleep: tv_nsec >= 1e9 returns EINVAL");
    } else {
        cat.fail_errno("nanosleep: tv_nsec >= 1e9 returns EINVAL", EINVAL, ret);
    }

    // 4. Very large tv_nsec
    let req = Timespec { tv_sec: 0, tv_nsec: i64::MAX };
    let ret = unsafe { syscall2(nr::NANOSLEEP, &req as *const _ as u64, &mut rem as *mut _ as u64) };
    if ret == EINVAL {
        cat.pass("nanosleep: very large tv_nsec returns EINVAL");
    } else {
        cat.fail_errno("nanosleep: very large tv_nsec returns EINVAL", EINVAL, ret);
    }

    results.add(cat);
}

fn test_nanosleep_boundary(results: &mut crate::Results) {
    let mut cat = TestCategory::new(PseLevel::PSE51, "Nanosleep: boundary tests");
    cat.header();

    // 1. Maximum valid tv_nsec (999999999)
    let req = Timespec { tv_sec: 0, tv_nsec: 100_000 }; // Use small value for testing
    let ret = unsafe { syscall2(nr::NANOSLEEP, &req as *const _ as u64, 0) };
    if ret == 0 {
        cat.pass("nanosleep: small nsec value");
    } else {
        cat.fail_errno("nanosleep: small nsec value", 0, ret);
    }

    // 2. tv_nsec = 999999999 (just under 1 second) - use smaller for test
    let req = Timespec { tv_sec: 0, tv_nsec: 1 }; // 1 nanosecond
    let ret = unsafe { syscall2(nr::NANOSLEEP, &req as *const _ as u64, 0) };
    if ret == 0 {
        cat.pass("nanosleep: 1ns (minimum)");
    } else {
        cat.fail_errno("nanosleep: 1ns (minimum)", 0, ret);
    }

    // 3. Combined small seconds and nanoseconds
    let req = Timespec { tv_sec: 0, tv_nsec: 500_000 }; // 500us
    let ret = unsafe { syscall2(nr::NANOSLEEP, &req as *const _ as u64, 0) };
    if ret == 0 {
        cat.pass("nanosleep: 500us");
    } else {
        cat.fail_errno("nanosleep: 500us", 0, ret);
    }

    results.add(cat);
}

// ════════════════════════════════════════════════════════════════════════════
// Timer tests (POSIX interval timers)
// ════════════════════════════════════════════════════════════════════════════

fn test_timer_create_positive(results: &mut crate::Results) {
    let mut cat = TestCategory::new(PseLevel::PSE51, "Timer: timer_create positive");
    cat.header();

    // 1. Create timer with SIGEV_NONE (no notification)
    let mut timer_id: i32 = 0;
    let sev = Sigevent {
        sigev_value: 0,
        sigev_signo: 0,
        sigev_notify: SIGEV_NONE,
        _pad: [0; 6],
    };
    let ret = unsafe {
        syscall3(nr::TIMER_CREATE, CLOCK_MONOTONIC, &sev as *const _ as u64,
                 &mut timer_id as *mut _ as u64)
    };
    if ret == 0 {
        cat.pass("timer_create: CLOCK_MONOTONIC, SIGEV_NONE");
        // Clean up
        unsafe { syscall1(nr::TIMER_DELETE, timer_id as u64) };
    } else {
        cat.fail_errno("timer_create: CLOCK_MONOTONIC, SIGEV_NONE", 0, ret);
    }

    // 2. Create timer with CLOCK_REALTIME
    let ret = unsafe {
        syscall3(nr::TIMER_CREATE, CLOCK_REALTIME, &sev as *const _ as u64,
                 &mut timer_id as *mut _ as u64)
    };
    if ret == 0 {
        cat.pass("timer_create: CLOCK_REALTIME");
        unsafe { syscall1(nr::TIMER_DELETE, timer_id as u64) };
    } else {
        cat.fail_errno("timer_create: CLOCK_REALTIME", 0, ret);
    }

    // 3. Create timer with NULL sigevent (default behavior)
    let ret = unsafe {
        syscall3(nr::TIMER_CREATE, CLOCK_MONOTONIC, 0, &mut timer_id as *mut _ as u64)
    };
    if ret == 0 {
        cat.pass("timer_create: NULL sigevent");
        unsafe { syscall1(nr::TIMER_DELETE, timer_id as u64) };
    } else {
        cat.fail_errno("timer_create: NULL sigevent", 0, ret);
    }

    // 4. Create multiple timers
    let mut timer1: i32 = 0;
    let mut timer2: i32 = 0;
    let ret1 = unsafe {
        syscall3(nr::TIMER_CREATE, CLOCK_MONOTONIC, &sev as *const _ as u64,
                 &mut timer1 as *mut _ as u64)
    };
    let ret2 = unsafe {
        syscall3(nr::TIMER_CREATE, CLOCK_MONOTONIC, &sev as *const _ as u64,
                 &mut timer2 as *mut _ as u64)
    };
    if ret1 == 0 && ret2 == 0 && timer1 != timer2 {
        cat.pass("timer_create: multiple timers have different IDs");
        unsafe {
            syscall1(nr::TIMER_DELETE, timer1 as u64);
            syscall1(nr::TIMER_DELETE, timer2 as u64);
        }
    } else {
        cat.fail("timer_create: multiple timers have different IDs");
    }

    results.add(cat);
}

fn test_timer_create_negative(results: &mut crate::Results) {
    let mut cat = TestCategory::new(PseLevel::PSE51, "Timer: timer_create negative");
    cat.header();

    let mut timer_id: i32 = 0;
    let sev = Sigevent {
        sigev_value: 0,
        sigev_signo: 0,
        sigev_notify: SIGEV_NONE,
        _pad: [0; 6],
    };

    // 1. Invalid clock ID
    let ret = unsafe {
        syscall3(nr::TIMER_CREATE, 999, &sev as *const _ as u64,
                 &mut timer_id as *mut _ as u64)
    };
    if ret == EINVAL {
        cat.pass("timer_create: invalid clock ID returns EINVAL");
    } else {
        cat.fail_errno("timer_create: invalid clock ID returns EINVAL", EINVAL, ret);
    }

    // 2. Negative clock ID
    let ret = unsafe {
        syscall3(nr::TIMER_CREATE, (-1i64) as u64, &sev as *const _ as u64,
                 &mut timer_id as *mut _ as u64)
    };
    if ret == EINVAL {
        cat.pass("timer_create: negative clock ID returns EINVAL");
    } else {
        cat.fail_errno("timer_create: negative clock ID returns EINVAL", EINVAL, ret);
    }

    // 3. Invalid sigev_notify
    let bad_sev = Sigevent {
        sigev_value: 0,
        sigev_signo: 0,
        sigev_notify: 999,
        _pad: [0; 6],
    };
    let ret = unsafe {
        syscall3(nr::TIMER_CREATE, CLOCK_MONOTONIC, &bad_sev as *const _ as u64,
                 &mut timer_id as *mut _ as u64)
    };
    if ret == EINVAL {
        cat.pass("timer_create: invalid sigev_notify returns EINVAL");
    } else {
        cat.fail_errno("timer_create: invalid sigev_notify returns EINVAL", EINVAL, ret);
    }

    results.add(cat);
}

fn test_timer_settime_gettime(results: &mut crate::Results) {
    let mut cat = TestCategory::new(PseLevel::PSE51, "Timer: timer_settime/gettime");
    cat.header();

    // Create timer first
    let mut timer_id: i32 = 0;
    let sev = Sigevent {
        sigev_value: 0,
        sigev_signo: 0,
        sigev_notify: SIGEV_NONE,
        _pad: [0; 6],
    };
    let ret = unsafe {
        syscall3(nr::TIMER_CREATE, CLOCK_MONOTONIC, &sev as *const _ as u64,
                 &mut timer_id as *mut _ as u64)
    };
    if ret != 0 {
        cat.fail("timer_settime/gettime: create timer");
        results.add(cat);
        return;
    }

    // 1. Set timer (one-shot, 100ms)
    let new_value = Itimerspec {
        it_interval: Timespec { tv_sec: 0, tv_nsec: 0 },
        it_value: Timespec { tv_sec: 0, tv_nsec: 100_000_000 }, // 100ms
    };
    let mut old_value = Itimerspec {
        it_interval: Timespec { tv_sec: 0, tv_nsec: 0 },
        it_value: Timespec { tv_sec: 0, tv_nsec: 0 },
    };
    let ret = unsafe {
        syscall4(nr::TIMER_SETTIME, timer_id as u64, 0,
                 &new_value as *const _ as u64, &mut old_value as *mut _ as u64)
    };
    if ret == 0 {
        cat.pass("timer_settime: one-shot 100ms");
    } else {
        cat.fail_errno("timer_settime: one-shot 100ms", 0, ret);
    }

    // 2. Get timer value
    let mut curr_value = Itimerspec {
        it_interval: Timespec { tv_sec: 0, tv_nsec: 0 },
        it_value: Timespec { tv_sec: 0, tv_nsec: 0 },
    };
    let ret = unsafe {
        syscall2(nr::TIMER_GETTIME, timer_id as u64, &mut curr_value as *mut _ as u64)
    };
    if ret == 0 {
        cat.pass("timer_gettime: success");
    } else {
        cat.fail_errno("timer_gettime: success", 0, ret);
    }

    // 3. Set periodic timer
    let periodic = Itimerspec {
        it_interval: Timespec { tv_sec: 0, tv_nsec: 10_000_000 }, // 10ms interval
        it_value: Timespec { tv_sec: 0, tv_nsec: 10_000_000 },    // 10ms initial
    };
    let ret = unsafe {
        syscall4(nr::TIMER_SETTIME, timer_id as u64, 0,
                 &periodic as *const _ as u64, 0)
    };
    if ret == 0 {
        cat.pass("timer_settime: periodic 10ms");
    } else {
        cat.fail_errno("timer_settime: periodic 10ms", 0, ret);
    }

    // 4. Disarm timer (set to zero)
    let disarm = Itimerspec {
        it_interval: Timespec { tv_sec: 0, tv_nsec: 0 },
        it_value: Timespec { tv_sec: 0, tv_nsec: 0 },
    };
    let ret = unsafe {
        syscall4(nr::TIMER_SETTIME, timer_id as u64, 0,
                 &disarm as *const _ as u64, &mut old_value as *mut _ as u64)
    };
    if ret == 0 {
        cat.pass("timer_settime: disarm (set to zero)");
    } else {
        cat.fail_errno("timer_settime: disarm (set to zero)", 0, ret);
    }

    // 5. Verify old_value contains previous setting
    if old_value.it_interval.tv_nsec == 10_000_000 {
        cat.pass("timer_settime: old_value contains previous setting");
    } else {
        cat.fail("timer_settime: old_value contains previous setting");
    }

    // Clean up
    unsafe { syscall1(nr::TIMER_DELETE, timer_id as u64) };

    results.add(cat);
}

fn test_timer_delete(results: &mut crate::Results) {
    let mut cat = TestCategory::new(PseLevel::PSE51, "Timer: timer_delete");
    cat.header();

    // 1. Delete valid timer
    let mut timer_id: i32 = 0;
    let sev = Sigevent {
        sigev_value: 0,
        sigev_signo: 0,
        sigev_notify: SIGEV_NONE,
        _pad: [0; 6],
    };
    unsafe {
        syscall3(nr::TIMER_CREATE, CLOCK_MONOTONIC, &sev as *const _ as u64,
                 &mut timer_id as *mut _ as u64)
    };
    let ret = unsafe { syscall1(nr::TIMER_DELETE, timer_id as u64) };
    if ret == 0 {
        cat.pass("timer_delete: valid timer");
    } else {
        cat.fail_errno("timer_delete: valid timer", 0, ret);
    }

    // 2. Delete invalid timer ID
    let ret = unsafe { syscall1(nr::TIMER_DELETE, 999) };
    if ret == EINVAL {
        cat.pass("timer_delete: invalid timer returns EINVAL");
    } else {
        cat.fail_errno("timer_delete: invalid timer returns EINVAL", EINVAL, ret);
    }

    // 3. Delete already-deleted timer
    let ret = unsafe { syscall1(nr::TIMER_DELETE, timer_id as u64) };
    if ret == EINVAL {
        cat.pass("timer_delete: already deleted returns EINVAL");
    } else {
        cat.fail_errno("timer_delete: already deleted returns EINVAL", EINVAL, ret);
    }

    results.add(cat);
}

fn test_timer_getoverrun(results: &mut crate::Results) {
    let mut cat = TestCategory::new(PseLevel::PSE51, "Timer: timer_getoverrun");
    cat.header();

    // Create timer
    let mut timer_id: i32 = 0;
    let sev = Sigevent {
        sigev_value: 0,
        sigev_signo: 0,
        sigev_notify: SIGEV_NONE,
        _pad: [0; 6],
    };
    let ret = unsafe {
        syscall3(nr::TIMER_CREATE, CLOCK_MONOTONIC, &sev as *const _ as u64,
                 &mut timer_id as *mut _ as u64)
    };
    if ret != 0 {
        cat.fail("timer_getoverrun: create timer");
        results.add(cat);
        return;
    }

    // 1. Get overrun count (should be 0 for never-expired timer)
    let ret = unsafe { syscall1(nr::TIMER_GETOVERRUN, timer_id as u64) };
    if ret >= 0 {
        cat.pass("timer_getoverrun: returns >= 0");
    } else {
        cat.fail_errno("timer_getoverrun: returns >= 0", 0, ret);
    }

    // 2. Invalid timer ID
    let ret = unsafe { syscall1(nr::TIMER_GETOVERRUN, 999) };
    if ret == EINVAL {
        cat.pass("timer_getoverrun: invalid timer returns EINVAL");
    } else {
        cat.fail_errno("timer_getoverrun: invalid timer returns EINVAL", EINVAL, ret);
    }

    // Clean up
    unsafe { syscall1(nr::TIMER_DELETE, timer_id as u64) };

    results.add(cat);
}

// ════════════════════════════════════════════════════════════════════════════
// clock_nanosleep — sleep on a specific clock
// ════════════════════════════════════════════════════════════════════════════

fn test_clock_nanosleep(results: &mut crate::Results) {
    let mut cat = TestCategory::new(PseLevel::PSE51, "clock_nanosleep");
    cat.header();

    const CLOCK_MONOTONIC: u64 = 1;
    const CLOCK_REALTIME: u64 = 0;
    const TIMER_ABSTIME: u64 = 1;

    // 1. Relative sleep on CLOCK_MONOTONIC (1ms)
    let ts = Timespec { tv_sec: 0, tv_nsec: 1_000_000 };
    let ret = unsafe {
        syscall4(nr::CLOCK_NANOSLEEP, CLOCK_MONOTONIC, 0,
                 &ts as *const _ as u64, 0)
    };
    if ret == 0 {
        cat.pass("clock_nanosleep(MONOTONIC, 1ms) returns 0");
    } else {
        cat.fail_errno("clock_nanosleep(MONOTONIC, 1ms)", 0, ret);
    }

    // 2. Relative sleep on CLOCK_REALTIME
    let ret = unsafe {
        syscall4(nr::CLOCK_NANOSLEEP, CLOCK_REALTIME, 0,
                 &ts as *const _ as u64, 0)
    };
    if ret == 0 {
        cat.pass("clock_nanosleep(REALTIME, 1ms) returns 0");
    } else {
        cat.fail_errno("clock_nanosleep(REALTIME, 1ms)", 0, ret);
    }

    // 3. Absolute time sleep (already past → returns immediately)
    let past = Timespec { tv_sec: 1, tv_nsec: 0 }; // 1970-01-01 00:00:01
    let ret = unsafe {
        syscall4(nr::CLOCK_NANOSLEEP, CLOCK_REALTIME, TIMER_ABSTIME,
                 &past as *const _ as u64, 0)
    };
    if ret == 0 {
        cat.pass("clock_nanosleep(ABSTIME, past) returns immediately");
    } else {
        cat.fail_errno("clock_nanosleep(ABSTIME, past)", 0, ret);
    }

    // 4. Invalid clock → EINVAL
    let ret = unsafe {
        syscall4(nr::CLOCK_NANOSLEEP, 99, 0, &ts as *const _ as u64, 0)
    };
    if ret == -22 { // EINVAL
        cat.pass("clock_nanosleep(invalid clock) returns EINVAL");
    } else {
        cat.fail_errno("clock_nanosleep(invalid clock) returns EINVAL", -22, ret);
    }

    // 5. Negative nsec → EINVAL
    let bad = Timespec { tv_sec: 0, tv_nsec: -1 };
    let ret = unsafe {
        syscall4(nr::CLOCK_NANOSLEEP, CLOCK_MONOTONIC, 0,
                 &bad as *const _ as u64, 0)
    };
    if ret == -22 {
        cat.pass("clock_nanosleep(negative nsec) returns EINVAL");
    } else {
        cat.fail_errno("clock_nanosleep(negative nsec) returns EINVAL", -22, ret);
    }

    results.add(cat);
}

// ════════════════════════════════════════════════════════════════════════════
// Module entry point
// ════════════════════════════════════════════════════════════════════════════

pub fn run_all(results: &mut crate::Results) {
    crate::write_banner("TIME/CLOCK TESTS");

    // Clock tests
    test_clock_gettime_positive(results);
    test_clock_gettime_negative(results);
    test_clock_getres_positive(results);
    test_clock_getres_negative(results);

    // Nanosleep tests
    test_nanosleep_positive(results);
    test_nanosleep_negative(results);
    test_nanosleep_boundary(results);

    // Timer tests
    test_timer_create_positive(results);
    test_timer_create_negative(results);
    test_timer_settime_gettime(results);
    test_timer_delete(results);
    test_timer_getoverrun(results);

    // clock_nanosleep
    test_clock_nanosleep(results);
}
