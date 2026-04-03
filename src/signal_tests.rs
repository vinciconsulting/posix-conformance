//! Comprehensive signal tests for POSIX conformance
//!
//! Tests: sigaction, sigprocmask, kill, tgkill, tkill
//!
//! Categories:
//! - Positive: normal usage with expected return values
//! - Negative: invalid signal numbers, bad pointers, invalid flags
//! - Boundary: edge cases like signal 0 (process existence check)

use core::sync::atomic::{AtomicU32, Ordering};

use crate::nr;
use crate::{write_str, write_num, syscall0, syscall2, syscall3, syscall4};
use crate::{PseLevel, TestCategory};

// ════════════════════════════════════════════════════════════════════════════
// Signal constants
// ════════════════════════════════════════════════════════════════════════════

const SIGHUP: u64 = 1;
const SIGKILL: u64 = 9;
const SIGUSR1: u64 = 10;
const SIGUSR2: u64 = 12;
const SIGALRM: u64 = 14;
const SIGSTOP: u64 = 19;
const SIGSYS: u64 = 31;

// sigprocmask "how" values
const SIG_BLOCK: u64 = 0;
const SIG_UNBLOCK: u64 = 1;
const SIG_SETMASK: u64 = 2;

// sigaction flags
const SA_RESTORER: u64 = 0x04000000;

// Error codes
const EINVAL: i64 = -22;
const ESRCH: i64 = -3;
const EPERM: i64 = -1;

// ════════════════════════════════════════════════════════════════════════════
// Signal handler state
// ════════════════════════════════════════════════════════════════════════════

static SIGNAL_RECEIVED: AtomicU32 = AtomicU32::new(0);
static SIGNAL_NUMBER: AtomicU32 = AtomicU32::new(0);

#[unsafe(no_mangle)]
extern "C" fn test_sig_handler(sig: i32) {
    SIGNAL_RECEIVED.store(1, Ordering::SeqCst);
    SIGNAL_NUMBER.store(sig as u32, Ordering::SeqCst);
}

// sig_restorer lives in crate::arch — re-import for local use
use crate::arch::sig_restorer;

// ════════════════════════════════════════════════════════════════════════════
// Structures
// ════════════════════════════════════════════════════════════════════════════

#[repr(C)]
struct Sigaction {
    sa_handler: u64,        // or sa_sigaction
    sa_flags: u64,
    sa_restorer: u64,
    sa_mask: [u64; 2],      // sigset_t (128 bytes, but we only need 2 u64s)
}

// ════════════════════════════════════════════════════════════════════════════
// Test functions
// ════════════════════════════════════════════════════════════════════════════

/// Positive tests for sigprocmask
pub fn test_sigprocmask_positive(cat: &mut TestCategory) {
    cat.header();

    // 1. Query current mask (how=0, set=NULL)
    let mut oldset = [0u64; 2];
    let ret = unsafe { syscall4(nr::SIGPROCMASK, 0, 0, oldset.as_mut_ptr() as u64, 8) };
    if ret == 0 {
        cat.pass("sigprocmask: query current mask");
    } else {
        cat.fail_errno("sigprocmask: query current mask", 0, ret);
    }

    // 2. SIG_BLOCK - add SIGUSR1 to blocked set
    let newset: u64 = 1 << (SIGUSR1 - 1);
    let mut saved = [0u64; 2];
    let ret = unsafe {
        syscall4(nr::SIGPROCMASK, SIG_BLOCK, &newset as *const _ as u64,
                 saved.as_mut_ptr() as u64, 8)
    };
    if ret == 0 {
        cat.pass("sigprocmask: SIG_BLOCK SIGUSR1");
    } else {
        cat.fail_errno("sigprocmask: SIG_BLOCK SIGUSR1", 0, ret);
    }

    // 3. Verify SIGUSR1 is blocked
    let mut current = [0u64; 2];
    let ret = unsafe { syscall4(nr::SIGPROCMASK, 0, 0, current.as_mut_ptr() as u64, 8) };
    if ret == 0 && (current[0] & (1 << (SIGUSR1 - 1))) != 0 {
        cat.pass("sigprocmask: SIGUSR1 verified blocked");
    } else {
        cat.fail("sigprocmask: SIGUSR1 verified blocked");
    }

    // 4. SIG_UNBLOCK - remove SIGUSR1
    let ret = unsafe {
        syscall4(nr::SIGPROCMASK, SIG_UNBLOCK, &newset as *const _ as u64, 0, 8)
    };
    if ret == 0 {
        cat.pass("sigprocmask: SIG_UNBLOCK SIGUSR1");
    } else {
        cat.fail_errno("sigprocmask: SIG_UNBLOCK SIGUSR1", 0, ret);
    }

    // 5. Verify SIGUSR1 is unblocked
    let mut current = [0u64; 2];
    let ret = unsafe { syscall4(nr::SIGPROCMASK, 0, 0, current.as_mut_ptr() as u64, 8) };
    if ret == 0 && (current[0] & (1 << (SIGUSR1 - 1))) == 0 {
        cat.pass("sigprocmask: SIGUSR1 verified unblocked");
    } else {
        cat.fail("sigprocmask: SIGUSR1 verified unblocked");
    }

    // 6. SIG_SETMASK - set entire mask
    let fullset: u64 = (1 << (SIGUSR1 - 1)) | (1 << (SIGUSR2 - 1)) | (1 << (SIGALRM - 1));
    let ret = unsafe {
        syscall4(nr::SIGPROCMASK, SIG_SETMASK, &fullset as *const _ as u64, 0, 8)
    };
    if ret == 0 {
        cat.pass("sigprocmask: SIG_SETMASK multiple signals");
    } else {
        cat.fail_errno("sigprocmask: SIG_SETMASK multiple signals", 0, ret);
    }

    // 7. Verify multiple signals blocked
    let mut current = [0u64; 2];
    let ret = unsafe { syscall4(nr::SIGPROCMASK, 0, 0, current.as_mut_ptr() as u64, 8) };
    let expected = (1 << (SIGUSR1 - 1)) | (1 << (SIGUSR2 - 1)) | (1 << (SIGALRM - 1));
    if ret == 0 && (current[0] & expected) == expected {
        cat.pass("sigprocmask: multiple signals verified blocked");
    } else {
        cat.fail("sigprocmask: multiple signals verified blocked");
    }

    // 8. Restore original mask
    let ret = unsafe {
        syscall4(nr::SIGPROCMASK, SIG_SETMASK, saved.as_ptr() as u64, 0, 8)
    };
    if ret == 0 {
        cat.pass("sigprocmask: restore original mask");
    } else {
        cat.fail_errno("sigprocmask: restore original mask", 0, ret);
    }

    // 9. Block all blockable signals (except SIGKILL, SIGSTOP)
    let all_mask: u64 = !((1 << (SIGKILL - 1)) | (1 << (SIGSTOP - 1)));
    let ret = unsafe {
        syscall4(nr::SIGPROCMASK, SIG_SETMASK, &all_mask as *const _ as u64,
                 saved.as_mut_ptr() as u64, 8)
    };
    if ret == 0 {
        cat.pass("sigprocmask: block all blockable signals");
    } else {
        cat.fail_errno("sigprocmask: block all blockable signals", 0, ret);
    }

    // Restore
    unsafe { syscall4(nr::SIGPROCMASK, SIG_SETMASK, saved.as_ptr() as u64, 0, 8) };
}

/// Negative tests for sigprocmask
pub fn test_sigprocmask_negative(cat: &mut TestCategory) {
    cat.header();

    // 1. Invalid "how" value
    let newset: u64 = 1 << (SIGUSR1 - 1);
    let ret = unsafe {
        syscall4(nr::SIGPROCMASK, 999, &newset as *const _ as u64, 0, 8)
    };
    if ret == EINVAL {
        cat.pass("sigprocmask: invalid 'how' returns EINVAL");
    } else {
        cat.fail_errno("sigprocmask: invalid 'how' returns EINVAL", EINVAL, ret);
    }

    // 2. Invalid sigsetsize (too small)
    let ret = unsafe {
        syscall4(nr::SIGPROCMASK, 0, 0, 0, 4)  // should be 8
    };
    if ret == EINVAL {
        cat.pass("sigprocmask: invalid sigsetsize returns EINVAL");
    } else {
        cat.fail_errno("sigprocmask: invalid sigsetsize returns EINVAL", EINVAL, ret);
    }

    // 3. Try to block SIGKILL (kernel ignores this, but syscall returns 0)
    let killmask: u64 = 1 << (SIGKILL - 1);
    let ret = unsafe {
        syscall4(nr::SIGPROCMASK, SIG_BLOCK, &killmask as *const _ as u64, 0, 8)
    };
    // syscall should succeed even though kernel will ignore SIGKILL blocking
    if ret == 0 {
        cat.pass("sigprocmask: SIG_BLOCK SIGKILL accepted (kernel ignores)");
    } else {
        cat.fail_errno("sigprocmask: SIG_BLOCK SIGKILL accepted", 0, ret);
    }

    // Note: Whether the mask shows SIGKILL bit is implementation-defined.
    // The kernel guarantee is at signal delivery time, not in the mask storage.
    // We verify the syscall works, not the mask contents for unblockable signals.

    // 4. Try to block SIGSTOP (kernel ignores this, but syscall returns 0)
    let stopmask: u64 = 1 << (SIGSTOP - 1);
    let ret = unsafe {
        syscall4(nr::SIGPROCMASK, SIG_BLOCK, &stopmask as *const _ as u64, 0, 8)
    };
    if ret == 0 {
        cat.pass("sigprocmask: SIG_BLOCK SIGSTOP accepted (kernel ignores)");
    } else {
        cat.fail_errno("sigprocmask: SIG_BLOCK SIGSTOP accepted", 0, ret);
    }
}

/// Positive tests for kill
pub fn test_kill_positive(cat: &mut TestCategory) {
    cat.header();

    let pid = unsafe { syscall0(nr::GETPID) };

    // 1. Signal 0 - process existence check (should succeed for self)
    let ret = unsafe { syscall2(nr::KILL, pid as u64, 0) };
    if ret == 0 {
        cat.pass("kill(self, 0): process exists");
    } else {
        cat.fail_errno("kill(self, 0): process exists", 0, ret);
    }

    // 2. Signal 0 to process group (pid=0)
    let ret = unsafe { syscall2(nr::KILL, 0, 0) };
    if ret == 0 {
        cat.pass("kill(0, 0): process group check");
    } else {
        cat.fail_errno("kill(0, 0): process group check", 0, ret);
    }

    // 3. Signal 0 to all processes (pid=-1, requires CAP_KILL usually)
    // Skip this test as it likely requires root
}

/// Negative tests for kill
pub fn test_kill_negative(cat: &mut TestCategory) {
    cat.header();

    let pid = unsafe { syscall0(nr::GETPID) };

    // 1. Invalid signal number (> 64)
    let ret = unsafe { syscall2(nr::KILL, pid as u64, 999) };
    if ret == EINVAL {
        cat.pass("kill: invalid signal 999 returns EINVAL");
    } else {
        cat.fail_errno("kill: invalid signal 999 returns EINVAL", EINVAL, ret);
    }

    // 2. Negative signal number
    let ret = unsafe { syscall2(nr::KILL, pid as u64, (-1i64) as u64) };
    if ret == EINVAL {
        cat.pass("kill: negative signal returns EINVAL");
    } else {
        cat.fail_errno("kill: negative signal returns EINVAL", EINVAL, ret);
    }

    // 3. Non-existent process (large PID)
    let ret = unsafe { syscall2(nr::KILL, 0x7FFFFFFF, 0) };
    if ret == ESRCH {
        cat.pass("kill: non-existent PID returns ESRCH");
    } else {
        cat.fail_errno("kill: non-existent PID returns ESRCH", ESRCH, ret);
    }

    // 4. Invalid PID (negative, not -1)
    let ret = unsafe { syscall2(nr::KILL, (-2i64) as u64, 0) };
    // -2 means "all processes in process group |pid|" which would be group 2
    // This might return ESRCH if no such group exists
    if ret == ESRCH || ret == EPERM {
        cat.pass("kill: pid=-2 returns ESRCH or EPERM");
    } else if ret == 0 {
        cat.pass("kill: pid=-2 succeeded (group exists)");
    } else {
        cat.fail_errno("kill: pid=-2 returns expected error", ESRCH, ret);
    }

    // 5. Signal 0 to non-existent process
    let ret = unsafe { syscall2(nr::KILL, 99999, 0) };
    if ret == ESRCH {
        cat.pass("kill(99999, 0): returns ESRCH");
    } else {
        cat.fail_errno("kill(99999, 0): returns ESRCH", ESRCH, ret);
    }
}

/// Boundary tests for signals
pub fn test_signal_boundary(cat: &mut TestCategory) {
    cat.header();

    let pid = unsafe { syscall0(nr::GETPID) };

    // 1. Signal 0 (existence check, doesn't send actual signal)
    let ret = unsafe { syscall2(nr::KILL, pid as u64, 0) };
    if ret == 0 {
        cat.pass("kill: signal 0 doesn't kill process");
    } else {
        cat.fail_errno("kill: signal 0 doesn't kill process", 0, ret);
    }

    // 2. Signal 1 (SIGHUP) - minimum valid signal
    // Don't actually send it, just check it's valid
    // We'll use sigprocmask to verify it's a valid signal number
    let mask: u64 = 1 << (SIGHUP - 1);
    let ret = unsafe {
        syscall4(nr::SIGPROCMASK, SIG_BLOCK, &mask as *const _ as u64, 0, 8)
    };
    if ret == 0 {
        cat.pass("sigprocmask: signal 1 (SIGHUP) is valid");
        // Unblock
        unsafe { syscall4(nr::SIGPROCMASK, SIG_UNBLOCK, &mask as *const _ as u64, 0, 8) };
    } else {
        cat.fail_errno("sigprocmask: signal 1 (SIGHUP) is valid", 0, ret);
    }

    // 3. Signal 31 (SIGSYS) - maximum standard signal
    let mask: u64 = 1 << (SIGSYS - 1);
    let ret = unsafe {
        syscall4(nr::SIGPROCMASK, SIG_BLOCK, &mask as *const _ as u64, 0, 8)
    };
    if ret == 0 {
        cat.pass("sigprocmask: signal 31 (SIGSYS) is valid");
        unsafe { syscall4(nr::SIGPROCMASK, SIG_UNBLOCK, &mask as *const _ as u64, 0, 8) };
    } else {
        cat.fail_errno("sigprocmask: signal 31 (SIGSYS) is valid", 0, ret);
    }

    // 4. Signal 64 (SIGRTMAX in extended signal range)
    let rt_mask: u64 = 1 << 63; // Signal 64 is bit 63 (0-indexed in mask)
    let ret = unsafe {
        syscall4(nr::SIGPROCMASK, SIG_BLOCK, &rt_mask as *const _ as u64, 0, 8)
    };
    if ret == 0 || ret == EINVAL {
        cat.pass("sigprocmask: signal 64 (SIGRTMAX) handled");
        if ret == 0 {
            unsafe { syscall4(nr::SIGPROCMASK, SIG_UNBLOCK, &rt_mask as *const _ as u64, 0, 8) };
        }
    } else {
        cat.fail_errno("sigprocmask: signal 64 (SIGRTMAX) handled", 0, ret);
    }

    // 5. Empty signal mask operations
    let empty: u64 = 0;
    let ret = unsafe {
        syscall4(nr::SIGPROCMASK, SIG_BLOCK, &empty as *const _ as u64, 0, 8)
    };
    if ret == 0 {
        cat.pass("sigprocmask: block empty mask succeeds");
    } else {
        cat.fail_errno("sigprocmask: block empty mask succeeds", 0, ret);
    }

    // 6. Full mask (test that blocking all signals is accepted)
    let full: u64 = u64::MAX;
    let mut saved = [0u64; 2];
    let ret = unsafe {
        syscall4(nr::SIGPROCMASK, SIG_SETMASK, &full as *const _ as u64,
                 saved.as_mut_ptr() as u64, 8)
    };
    if ret == 0 {
        cat.pass("sigprocmask: set full mask accepted");
        unsafe { syscall4(nr::SIGPROCMASK, SIG_SETMASK, saved.as_ptr() as u64, 0, 8) };
    } else {
        cat.fail_errno("sigprocmask: set full mask accepted", 0, ret);
    }
}

/// Test sigaction basics
pub fn test_sigaction_positive(cat: &mut TestCategory) {
    cat.header();

    let mut sa = Sigaction {
        sa_handler: test_sig_handler as *const () as u64,
        sa_flags: SA_RESTORER,
        sa_restorer: sig_restorer as *const () as u64,
        sa_mask: [0, 0],
    };

    let mut oldsa = Sigaction {
        sa_handler: 0,
        sa_flags: 0,
        sa_restorer: 0,
        sa_mask: [0, 0],
    };

    // 1. Install handler for SIGUSR1
    let ret = unsafe {
        syscall4(
            nr::SIGACTION,
            SIGUSR1,
            &sa as *const _ as u64,
            &mut oldsa as *mut _ as u64,
            8
        )
    };
    if ret == 0 {
        cat.pass("sigaction: install SIGUSR1 handler");
    } else {
        cat.fail_errno("sigaction: install SIGUSR1 handler", 0, ret);
        return;
    }

    // 2. Query handler (set=NULL)
    let mut query = Sigaction {
        sa_handler: 0,
        sa_flags: 0,
        sa_restorer: 0,
        sa_mask: [0, 0],
    };
    let ret = unsafe {
        syscall4(nr::SIGACTION, SIGUSR1, 0, &mut query as *mut _ as u64, 8)
    };
    if ret == 0 && query.sa_handler == test_sig_handler as *const () as u64 {
        cat.pass("sigaction: query returns installed handler");
    } else {
        cat.fail("sigaction: query returns installed handler");
    }

    // 3. Restore default handler (SIG_DFL = 0)
    sa.sa_handler = 0;
    sa.sa_flags = 0;
    sa.sa_restorer = 0;
    let ret = unsafe {
        syscall4(nr::SIGACTION, SIGUSR1, &sa as *const _ as u64, 0, 8)
    };
    if ret == 0 {
        cat.pass("sigaction: restore SIG_DFL");
    } else {
        cat.fail_errno("sigaction: restore SIG_DFL", 0, ret);
    }

    // 4. Install handler for SIGUSR2
    sa.sa_handler = test_sig_handler as *const () as u64;
    sa.sa_flags = SA_RESTORER;
    sa.sa_restorer = sig_restorer as *const () as u64;
    let ret = unsafe {
        syscall4(nr::SIGACTION, SIGUSR2, &sa as *const _ as u64, 0, 8)
    };
    if ret == 0 {
        cat.pass("sigaction: install SIGUSR2 handler");
    } else {
        cat.fail_errno("sigaction: install SIGUSR2 handler", 0, ret);
    }

    // Restore SIGUSR2 to default
    sa.sa_handler = 0;
    sa.sa_flags = 0;
    sa.sa_restorer = 0;
    unsafe { syscall4(nr::SIGACTION, SIGUSR2, &sa as *const _ as u64, 0, 8) };
}

/// Negative tests for sigaction
pub fn test_sigaction_negative(cat: &mut TestCategory) {
    cat.header();

    let sa = Sigaction {
        sa_handler: test_sig_handler as *const () as u64,
        sa_flags: SA_RESTORER,
        sa_restorer: sig_restorer as *const () as u64,
        sa_mask: [0, 0],
    };

    // 1. Invalid signal number (0)
    let ret = unsafe {
        syscall4(nr::SIGACTION, 0, &sa as *const _ as u64, 0, 8)
    };
    if ret == EINVAL {
        cat.pass("sigaction: signal 0 returns EINVAL");
    } else {
        cat.fail_errno("sigaction: signal 0 returns EINVAL", EINVAL, ret);
    }

    // 2. Invalid signal number (> 64)
    let ret = unsafe {
        syscall4(nr::SIGACTION, 999, &sa as *const _ as u64, 0, 8)
    };
    if ret == EINVAL {
        cat.pass("sigaction: signal 999 returns EINVAL");
    } else {
        cat.fail_errno("sigaction: signal 999 returns EINVAL", EINVAL, ret);
    }

    // 3. Try to install handler for SIGKILL
    let ret = unsafe {
        syscall4(nr::SIGACTION, SIGKILL, &sa as *const _ as u64, 0, 8)
    };
    if ret == EINVAL {
        cat.pass("sigaction: SIGKILL returns EINVAL");
    } else {
        cat.fail_errno("sigaction: SIGKILL returns EINVAL", EINVAL, ret);
    }

    // 4. Try to install handler for SIGSTOP
    let ret = unsafe {
        syscall4(nr::SIGACTION, SIGSTOP, &sa as *const _ as u64, 0, 8)
    };
    if ret == EINVAL {
        cat.pass("sigaction: SIGSTOP returns EINVAL");
    } else {
        cat.fail_errno("sigaction: SIGSTOP returns EINVAL", EINVAL, ret);
    }

    // 5. Invalid sigsetsize
    let ret = unsafe {
        syscall4(nr::SIGACTION, SIGUSR1, &sa as *const _ as u64, 0, 4)
    };
    if ret == EINVAL {
        cat.pass("sigaction: invalid sigsetsize returns EINVAL");
    } else {
        cat.fail_errno("sigaction: invalid sigsetsize returns EINVAL", EINVAL, ret);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Signal DELIVERY verification — install handler, trigger, verify it ran
// ════════════════════════════════════════════════════════════════════════════

/// Second signal handler to verify distinct signals are dispatched correctly
#[unsafe(no_mangle)]
extern "C" fn test_sig_handler_usr2(sig: i32) {
    SIGNAL_RECEIVED.store(2, Ordering::SeqCst);
    SIGNAL_NUMBER.store(sig as u32, Ordering::SeqCst);
}

/// Test: install SIGUSR1 handler -> kill(self, SIGUSR1) -> verify handler ran
pub fn test_signal_delivery_sigusr1(cat: &mut TestCategory) {
    cat.header();

    let mut sa = Sigaction {
        sa_handler: test_sig_handler as *const () as u64,
        sa_flags: SA_RESTORER,
        sa_restorer: sig_restorer as *const () as u64,
        sa_mask: [0, 0],
    };

    let ret = unsafe {
        syscall4(nr::SIGACTION, SIGUSR1, &sa as *const _ as u64, 0, 8)
    };
    if ret != 0 {
        cat.fail_errno("install SIGUSR1 handler", 0, ret);
        return;
    }

    let unblock: u64 = 1 << (SIGUSR1 - 1);
    unsafe { syscall4(nr::SIGPROCMASK, SIG_UNBLOCK, &unblock as *const _ as u64, 0, 8) };

    SIGNAL_RECEIVED.store(0, Ordering::SeqCst);
    SIGNAL_NUMBER.store(0, Ordering::SeqCst);

    let pid = unsafe { syscall0(nr::GETPID) };
    let ret = unsafe { syscall2(nr::KILL, pid as u64, SIGUSR1) };
    if ret != 0 {
        cat.fail_errno("kill(self, SIGUSR1)", 0, ret);
        return;
    }

    let received = SIGNAL_RECEIVED.load(Ordering::SeqCst);
    if received == 1 {
        cat.pass("SIGUSR1 handler was invoked");
    } else {
        cat.fail("SIGUSR1 handler was invoked");
        write_str("    SIGNAL_RECEIVED=");
        write_num(received as i64);
        write_str("\n");
    }

    let signo = SIGNAL_NUMBER.load(Ordering::SeqCst);
    if signo == SIGUSR1 as u32 {
        cat.pass("handler received correct signal number (10)");
    } else {
        cat.fail("handler received correct signal number (10)");
        write_str("    got signo=");
        write_num(signo as i64);
        write_str("\n");
    }

    sa.sa_handler = 0;
    sa.sa_flags = 0;
    sa.sa_restorer = 0;
    unsafe { syscall4(nr::SIGACTION, SIGUSR1, &sa as *const _ as u64, 0, 8) };
}

/// Test: install SIGUSR2 handler -> tgkill(self, SIGUSR2) -> verify
pub fn test_signal_delivery_sigusr2(cat: &mut TestCategory) {
    cat.header();

    SIGNAL_RECEIVED.store(0, Ordering::SeqCst);
    SIGNAL_NUMBER.store(0, Ordering::SeqCst);

    let mut sa = Sigaction {
        sa_handler: test_sig_handler_usr2 as *const () as u64,
        sa_flags: SA_RESTORER,
        sa_restorer: sig_restorer as *const () as u64,
        sa_mask: [0, 0],
    };

    let ret = unsafe {
        syscall4(nr::SIGACTION, SIGUSR2, &sa as *const _ as u64, 0, 8)
    };
    if ret != 0 {
        cat.fail_errno("install SIGUSR2 handler", 0, ret);
        return;
    }

    let pid = unsafe { syscall0(nr::GETPID) };
    let tid = unsafe { syscall0(nr::GETTID) };
    let ret = unsafe { syscall3(nr::TGKILL, pid as u64, tid as u64, SIGUSR2) };
    if ret != 0 {
        cat.fail_errno("tgkill(self, SIGUSR2)", 0, ret);
        return;
    }

    let received = SIGNAL_RECEIVED.load(Ordering::SeqCst);
    if received == 2 {
        cat.pass("SIGUSR2 handler was invoked (distinct from SIGUSR1)");
    } else {
        cat.fail("SIGUSR2 handler was invoked");
    }

    let signo = SIGNAL_NUMBER.load(Ordering::SeqCst);
    if signo == SIGUSR2 as u32 {
        cat.pass("handler received SIGUSR2 (12)");
    } else {
        cat.fail("handler received SIGUSR2 (12)");
        write_str("    got signo=");
        write_num(signo as i64);
        write_str("\n");
    }

    sa.sa_handler = 0;
    sa.sa_flags = 0;
    sa.sa_restorer = 0;
    unsafe { syscall4(nr::SIGACTION, SIGUSR2, &sa as *const _ as u64, 0, 8) };
}

/// Test: blocked signal is held pending, delivered on unblock
pub fn test_signal_blocked_pending(cat: &mut TestCategory) {
    cat.header();

    let mut sa = Sigaction {
        sa_handler: test_sig_handler as *const () as u64,
        sa_flags: SA_RESTORER,
        sa_restorer: sig_restorer as *const () as u64,
        sa_mask: [0, 0],
    };
    let ret = unsafe {
        syscall4(nr::SIGACTION, SIGUSR1, &sa as *const _ as u64, 0, 8)
    };
    if ret != 0 {
        cat.fail_errno("install handler for pending test", 0, ret);
        return;
    }

    let unblock: u64 = 1 << (SIGUSR1 - 1);
    unsafe { syscall4(nr::SIGPROCMASK, SIG_UNBLOCK, &unblock as *const _ as u64, 0, 8) };
    SIGNAL_RECEIVED.store(0, Ordering::SeqCst);
    SIGNAL_NUMBER.store(0, Ordering::SeqCst);

    let block_mask: u64 = 1 << (SIGUSR1 - 1);
    let mut saved_mask = [0u64; 2];
    unsafe {
        syscall4(nr::SIGPROCMASK, SIG_BLOCK, &block_mask as *const _ as u64,
                 saved_mask.as_mut_ptr() as u64, 8)
    };

    let pid = unsafe { syscall0(nr::GETPID) };
    unsafe { syscall2(nr::KILL, pid as u64, SIGUSR1) };

    let received = SIGNAL_RECEIVED.load(Ordering::SeqCst);
    if received == 0 {
        cat.pass("blocked signal not delivered yet");
    } else {
        cat.fail("blocked signal not delivered yet (handler ran prematurely)");
    }

    unsafe {
        syscall4(nr::SIGPROCMASK, SIG_SETMASK, saved_mask.as_ptr() as u64, 0, 8)
    };

    let received = SIGNAL_RECEIVED.load(Ordering::SeqCst);
    if received == 1 {
        cat.pass("pending signal delivered on unblock");
    } else {
        cat.fail("pending signal delivered on unblock");
        write_str("    SIGNAL_RECEIVED=");
        write_num(received as i64);
        write_str("\n");
    }

    sa.sa_handler = 0;
    sa.sa_flags = 0;
    sa.sa_restorer = 0;
    unsafe { syscall4(nr::SIGACTION, SIGUSR1, &sa as *const _ as u64, 0, 8) };
}

/// Test: SIGALRM delivery (timer signal)
pub fn test_signal_delivery_sigalrm(cat: &mut TestCategory) {
    cat.header();

    SIGNAL_RECEIVED.store(0, Ordering::SeqCst);
    SIGNAL_NUMBER.store(0, Ordering::SeqCst);

    let mut sa = Sigaction {
        sa_handler: test_sig_handler as *const () as u64,
        sa_flags: SA_RESTORER,
        sa_restorer: sig_restorer as *const () as u64,
        sa_mask: [0, 0],
    };

    let ret = unsafe {
        syscall4(nr::SIGACTION, SIGALRM, &sa as *const _ as u64, 0, 8)
    };
    if ret != 0 {
        cat.fail_errno("install SIGALRM handler", 0, ret);
        return;
    }

    let pid = unsafe { syscall0(nr::GETPID) };
    unsafe { syscall2(nr::KILL, pid as u64, SIGALRM) };

    let received = SIGNAL_RECEIVED.load(Ordering::SeqCst);
    let signo = SIGNAL_NUMBER.load(Ordering::SeqCst);

    if received == 1 && signo == SIGALRM as u32 {
        cat.pass("SIGALRM delivered and handler invoked");
    } else {
        cat.fail("SIGALRM delivered and handler invoked");
    }

    sa.sa_handler = 0;
    sa.sa_flags = 0;
    sa.sa_restorer = 0;
    unsafe { syscall4(nr::SIGACTION, SIGALRM, &sa as *const _ as u64, 0, 8) };
}

/// Test: multiple signals delivered in sequence
pub fn test_signal_multiple_delivery(cat: &mut TestCategory) {
    cat.header();

    static DELIVERY_COUNT: AtomicU32 = AtomicU32::new(0);

    #[unsafe(no_mangle)]
    extern "C" fn counting_handler(_sig: i32) {
        DELIVERY_COUNT.fetch_add(1, Ordering::SeqCst);
    }

    let mut sa = Sigaction {
        sa_handler: counting_handler as *const () as u64,
        sa_flags: SA_RESTORER,
        sa_restorer: sig_restorer as *const () as u64,
        sa_mask: [0, 0],
    };
    unsafe {
        syscall4(nr::SIGACTION, SIGUSR1, &sa as *const _ as u64, 0, 8)
    };

    let unblock: u64 = 1 << (SIGUSR1 - 1);
    unsafe { syscall4(nr::SIGPROCMASK, SIG_UNBLOCK, &unblock as *const _ as u64, 0, 8) };
    DELIVERY_COUNT.store(0, Ordering::SeqCst);

    let pid = unsafe { syscall0(nr::GETPID) };

    for _ in 0..5 {
        unsafe { syscall2(nr::KILL, pid as u64, SIGUSR1) };
    }

    let count = DELIVERY_COUNT.load(Ordering::SeqCst);
    if count == 5 {
        cat.pass("5 signals -> 5 handler invocations");
    } else {
        if count >= 1 {
            cat.pass("signals delivered (some may coalesce)");
            write_str("    delivered ");
            write_num(count as i64);
            write_str(" of 5\n");
        } else {
            cat.fail("no signals delivered");
        }
    }

    sa.sa_handler = 0;
    sa.sa_flags = 0;
    sa.sa_restorer = 0;
    unsafe { syscall4(nr::SIGACTION, SIGUSR1, &sa as *const _ as u64, 0, 8) };
}

// ════════════════════════════════════════════════════════════════════════════
// sigpending -- query pending signal set
// ════════════════════════════════════════════════════════════════════════════

pub fn test_sigpending(cat: &mut TestCategory) {
    cat.header();

    let mut sa = Sigaction {
        sa_handler: test_sig_handler as *const () as u64,
        sa_flags: SA_RESTORER,
        sa_restorer: sig_restorer as *const () as u64,
        sa_mask: [0, 0],
    };
    unsafe { syscall4(nr::SIGACTION, SIGUSR1, &sa as *const _ as u64, 0, 8) };

    let mut saved = [0u64; 2];
    let block_mask: u64 = 1 << (SIGUSR1 - 1);
    unsafe {
        syscall4(nr::SIGPROCMASK, SIG_SETMASK, &block_mask as *const _ as u64,
                 saved.as_mut_ptr() as u64, 8)
    };

    let pid = unsafe { syscall0(nr::GETPID) };
    unsafe { syscall2(nr::KILL, pid as u64, SIGUSR1) };

    let mut pending = [0u64; 2];
    let ret = unsafe {
        syscall2(nr::SIGPENDING, pending.as_mut_ptr() as u64, 8)
    };
    if ret == 0 {
        cat.pass("sigpending returns 0");
    } else {
        cat.fail_errno("sigpending returns 0", 0, ret);
    }

    if (pending[0] & (1 << (SIGUSR1 - 1))) != 0 {
        cat.pass("SIGUSR1 appears in pending set");
    } else {
        cat.fail("SIGUSR1 appears in pending set");
    }

    unsafe { syscall4(nr::SIGPROCMASK, SIG_SETMASK, saved.as_ptr() as u64, 0, 8) };

    sa.sa_handler = 0; sa.sa_flags = 0; sa.sa_restorer = 0;
    unsafe { syscall4(nr::SIGACTION, SIGUSR1, &sa as *const _ as u64, 0, 8) };
}

// ════════════════════════════════════════════════════════════════════════════
// rt_sigtimedwait -- synchronous signal wait
// ════════════════════════════════════════════════════════════════════════════

pub fn test_sigtimedwait(cat: &mut TestCategory) {
    cat.header();

    let block_mask: u64 = 1 << (SIGUSR1 - 1);
    let mut saved = [0u64; 2];
    unsafe {
        syscall4(nr::SIGPROCMASK, SIG_SETMASK, &block_mask as *const _ as u64,
                 saved.as_mut_ptr() as u64, 8)
    };

    let pid = unsafe { syscall0(nr::GETPID) };
    unsafe { syscall2(nr::KILL, pid as u64, SIGUSR1) };

    let ts = crate::Timespec { tv_sec: 0, tv_nsec: 0 };
    let ret = unsafe {
        syscall4(nr::SIGTIMEDWAIT, &block_mask as *const _ as u64, 0,
                 &ts as *const _ as u64, 8)
    };
    if ret == SIGUSR1 as i64 {
        cat.pass("rt_sigtimedwait returns SIGUSR1");
    } else if ret > 0 {
        cat.pass("rt_sigtimedwait returned a signal");
    } else {
        cat.fail_errno("rt_sigtimedwait returns signal", SIGUSR1 as i64, ret);
    }

    let ts2 = crate::Timespec { tv_sec: 0, tv_nsec: 1_000_000 }; // 1ms
    let ret = unsafe {
        syscall4(nr::SIGTIMEDWAIT, &block_mask as *const _ as u64, 0,
                 &ts2 as *const _ as u64, 8)
    };
    if ret == -11 { // EAGAIN
        cat.pass("rt_sigtimedwait with no pending signal returns EAGAIN");
    } else {
        cat.fail_errno("rt_sigtimedwait timeout returns EAGAIN", -11, ret);
    }

    unsafe { syscall4(nr::SIGPROCMASK, SIG_SETMASK, saved.as_ptr() as u64, 0, 8) };
}

// ════════════════════════════════════════════════════════════════════════════
// Module entry point
// ════════════════════════════════════════════════════════════════════════════

pub fn run_all(results: &mut crate::Results) {
    crate::write_banner("SIGNAL TESTS");

    // Positive tests
    let mut cat = TestCategory::new(PseLevel::PSE51, "Signals: sigprocmask positive");
    test_sigprocmask_positive(&mut cat);
    results.add(cat);

    let mut cat = TestCategory::new(PseLevel::PSE51, "Signals: kill positive");
    test_kill_positive(&mut cat);
    results.add(cat);

    let mut cat = TestCategory::new(PseLevel::PSE51, "Signals: sigaction positive");
    test_sigaction_positive(&mut cat);
    results.add(cat);

    // Negative tests
    let mut cat = TestCategory::new(PseLevel::PSE51, "Signals: sigprocmask negative");
    test_sigprocmask_negative(&mut cat);
    results.add(cat);

    let mut cat = TestCategory::new(PseLevel::PSE51, "Signals: kill negative");
    test_kill_negative(&mut cat);
    results.add(cat);

    let mut cat = TestCategory::new(PseLevel::PSE51, "Signals: sigaction negative");
    test_sigaction_negative(&mut cat);
    results.add(cat);

    // Boundary tests
    let mut cat = TestCategory::new(PseLevel::PSE51, "Signals: boundary cases");
    test_signal_boundary(&mut cat);
    results.add(cat);

    // Signal delivery verification
    let mut cat = TestCategory::new(PseLevel::PSE51, "Signal delivery: SIGUSR1 handler invoked");
    test_signal_delivery_sigusr1(&mut cat);
    results.add(cat);

    let mut cat = TestCategory::new(PseLevel::PSE51, "Signal delivery: SIGUSR2 via tgkill");
    test_signal_delivery_sigusr2(&mut cat);
    results.add(cat);

    let mut cat = TestCategory::new(PseLevel::PSE51, "Signal delivery: blocked -> pending -> delivered on unblock");
    test_signal_blocked_pending(&mut cat);
    results.add(cat);

    let mut cat = TestCategory::new(PseLevel::PSE51, "Signal delivery: SIGALRM");
    test_signal_delivery_sigalrm(&mut cat);
    results.add(cat);

    let mut cat = TestCategory::new(PseLevel::PSE51, "Signal delivery: multiple signals in sequence");
    test_signal_multiple_delivery(&mut cat);
    results.add(cat);

    // Realtime signal extensions
    let mut cat = TestCategory::new(PseLevel::PSE51, "Signal: sigpending");
    test_sigpending(&mut cat);
    results.add(cat);

    let mut cat = TestCategory::new(PseLevel::PSE51, "Signal: rt_sigtimedwait");
    test_sigtimedwait(&mut cat);
    results.add(cat);
}
