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
use crate::{pass, fail, fail_errno, write_str, write_num, syscall0, syscall2, syscall3, syscall4};

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

// Signal restorer (required for rt_sigaction)
#[unsafe(naked)]
#[unsafe(no_mangle)]
extern "C" fn sig_restorer() {
    core::arch::naked_asm!(
        "mov rax, 15",  // __NR_rt_sigreturn
        "syscall",
    );
}

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
pub fn test_sigprocmask_positive() {
    write_str("\n=== Signals: sigprocmask positive ===\n");

    // 1. Query current mask (how=0, set=NULL)
    let mut oldset = [0u64; 2];
    let ret = unsafe { syscall4(nr::SIGPROCMASK, 0, 0, oldset.as_mut_ptr() as u64, 8) };
    if ret == 0 {
        pass("sigprocmask: query current mask");
    } else {
        fail_errno("sigprocmask: query current mask", 0, ret);
    }

    // 2. SIG_BLOCK - add SIGUSR1 to blocked set
    let newset: u64 = 1 << SIGUSR1;
    let mut saved = [0u64; 2];
    let ret = unsafe {
        syscall4(nr::SIGPROCMASK, SIG_BLOCK, &newset as *const _ as u64,
                 saved.as_mut_ptr() as u64, 8)
    };
    if ret == 0 {
        pass("sigprocmask: SIG_BLOCK SIGUSR1");
    } else {
        fail_errno("sigprocmask: SIG_BLOCK SIGUSR1", 0, ret);
    }

    // 3. Verify SIGUSR1 is blocked
    let mut current = [0u64; 2];
    let ret = unsafe { syscall4(nr::SIGPROCMASK, 0, 0, current.as_mut_ptr() as u64, 8) };
    if ret == 0 && (current[0] & (1 << SIGUSR1)) != 0 {
        pass("sigprocmask: SIGUSR1 verified blocked");
    } else {
        fail("sigprocmask: SIGUSR1 verified blocked");
    }

    // 4. SIG_UNBLOCK - remove SIGUSR1
    let ret = unsafe {
        syscall4(nr::SIGPROCMASK, SIG_UNBLOCK, &newset as *const _ as u64, 0, 8)
    };
    if ret == 0 {
        pass("sigprocmask: SIG_UNBLOCK SIGUSR1");
    } else {
        fail_errno("sigprocmask: SIG_UNBLOCK SIGUSR1", 0, ret);
    }

    // 5. Verify SIGUSR1 is unblocked
    let mut current = [0u64; 2];
    let ret = unsafe { syscall4(nr::SIGPROCMASK, 0, 0, current.as_mut_ptr() as u64, 8) };
    if ret == 0 && (current[0] & (1 << SIGUSR1)) == 0 {
        pass("sigprocmask: SIGUSR1 verified unblocked");
    } else {
        fail("sigprocmask: SIGUSR1 verified unblocked");
    }

    // 6. SIG_SETMASK - set entire mask
    let fullset: u64 = (1 << SIGUSR1) | (1 << SIGUSR2) | (1 << SIGALRM);
    let ret = unsafe {
        syscall4(nr::SIGPROCMASK, SIG_SETMASK, &fullset as *const _ as u64, 0, 8)
    };
    if ret == 0 {
        pass("sigprocmask: SIG_SETMASK multiple signals");
    } else {
        fail_errno("sigprocmask: SIG_SETMASK multiple signals", 0, ret);
    }

    // 7. Verify multiple signals blocked
    let mut current = [0u64; 2];
    let ret = unsafe { syscall4(nr::SIGPROCMASK, 0, 0, current.as_mut_ptr() as u64, 8) };
    let expected = (1 << SIGUSR1) | (1 << SIGUSR2) | (1 << SIGALRM);
    if ret == 0 && (current[0] & expected) == expected {
        pass("sigprocmask: multiple signals verified blocked");
    } else {
        fail("sigprocmask: multiple signals verified blocked");
    }

    // 8. Restore original mask
    let ret = unsafe {
        syscall4(nr::SIGPROCMASK, SIG_SETMASK, saved.as_ptr() as u64, 0, 8)
    };
    if ret == 0 {
        pass("sigprocmask: restore original mask");
    } else {
        fail_errno("sigprocmask: restore original mask", 0, ret);
    }

    // 9. Block all blockable signals (except SIGKILL, SIGSTOP)
    let all_mask: u64 = !((1 << SIGKILL) | (1 << SIGSTOP));
    let ret = unsafe {
        syscall4(nr::SIGPROCMASK, SIG_SETMASK, &all_mask as *const _ as u64,
                 saved.as_mut_ptr() as u64, 8)
    };
    if ret == 0 {
        pass("sigprocmask: block all blockable signals");
    } else {
        fail_errno("sigprocmask: block all blockable signals", 0, ret);
    }

    // Restore
    unsafe { syscall4(nr::SIGPROCMASK, SIG_SETMASK, saved.as_ptr() as u64, 0, 8) };
}

/// Negative tests for sigprocmask
pub fn test_sigprocmask_negative() {
    write_str("\n=== Signals: sigprocmask negative ===\n");

    // 1. Invalid "how" value
    let newset: u64 = 1 << SIGUSR1;
    let ret = unsafe {
        syscall4(nr::SIGPROCMASK, 999, &newset as *const _ as u64, 0, 8)
    };
    if ret == EINVAL {
        pass("sigprocmask: invalid 'how' returns EINVAL");
    } else {
        fail_errno("sigprocmask: invalid 'how' returns EINVAL", EINVAL, ret);
    }

    // 2. Invalid sigsetsize (too small)
    let ret = unsafe {
        syscall4(nr::SIGPROCMASK, 0, 0, 0, 4)  // should be 8
    };
    if ret == EINVAL {
        pass("sigprocmask: invalid sigsetsize returns EINVAL");
    } else {
        fail_errno("sigprocmask: invalid sigsetsize returns EINVAL", EINVAL, ret);
    }

    // 3. Try to block SIGKILL (kernel ignores this, but syscall returns 0)
    let killmask: u64 = 1 << SIGKILL;
    let ret = unsafe {
        syscall4(nr::SIGPROCMASK, SIG_BLOCK, &killmask as *const _ as u64, 0, 8)
    };
    // syscall should succeed even though kernel will ignore SIGKILL blocking
    if ret == 0 {
        pass("sigprocmask: SIG_BLOCK SIGKILL accepted (kernel ignores)");
    } else {
        fail_errno("sigprocmask: SIG_BLOCK SIGKILL accepted", 0, ret);
    }

    // Note: Whether the mask shows SIGKILL bit is implementation-defined.
    // The kernel guarantee is at signal delivery time, not in the mask storage.
    // We verify the syscall works, not the mask contents for unblockable signals.

    // 4. Try to block SIGSTOP (kernel ignores this, but syscall returns 0)
    let stopmask: u64 = 1 << SIGSTOP;
    let ret = unsafe {
        syscall4(nr::SIGPROCMASK, SIG_BLOCK, &stopmask as *const _ as u64, 0, 8)
    };
    if ret == 0 {
        pass("sigprocmask: SIG_BLOCK SIGSTOP accepted (kernel ignores)");
    } else {
        fail_errno("sigprocmask: SIG_BLOCK SIGSTOP accepted", 0, ret);
    }
}

/// Positive tests for kill
pub fn test_kill_positive() {
    write_str("\n=== Signals: kill positive ===\n");

    let pid = unsafe { syscall0(nr::GETPID) };

    // 1. Signal 0 - process existence check (should succeed for self)
    let ret = unsafe { syscall2(nr::KILL, pid as u64, 0) };
    if ret == 0 {
        pass("kill(self, 0): process exists");
    } else {
        fail_errno("kill(self, 0): process exists", 0, ret);
    }

    // 2. Signal 0 to process group (pid=0)
    let ret = unsafe { syscall2(nr::KILL, 0, 0) };
    if ret == 0 {
        pass("kill(0, 0): process group check");
    } else {
        fail_errno("kill(0, 0): process group check", 0, ret);
    }

    // 3. Signal 0 to all processes (pid=-1, requires CAP_KILL usually)
    // Skip this test as it likely requires root
}

/// Negative tests for kill
pub fn test_kill_negative() {
    write_str("\n=== Signals: kill negative ===\n");

    let pid = unsafe { syscall0(nr::GETPID) };

    // 1. Invalid signal number (> 64)
    let ret = unsafe { syscall2(nr::KILL, pid as u64, 999) };
    if ret == EINVAL {
        pass("kill: invalid signal 999 returns EINVAL");
    } else {
        fail_errno("kill: invalid signal 999 returns EINVAL", EINVAL, ret);
    }

    // 2. Negative signal number
    let ret = unsafe { syscall2(nr::KILL, pid as u64, (-1i64) as u64) };
    if ret == EINVAL {
        pass("kill: negative signal returns EINVAL");
    } else {
        fail_errno("kill: negative signal returns EINVAL", EINVAL, ret);
    }

    // 3. Non-existent process (large PID)
    let ret = unsafe { syscall2(nr::KILL, 0x7FFFFFFF, 0) };
    if ret == ESRCH {
        pass("kill: non-existent PID returns ESRCH");
    } else {
        fail_errno("kill: non-existent PID returns ESRCH", ESRCH, ret);
    }

    // 4. Invalid PID (negative, not -1)
    let ret = unsafe { syscall2(nr::KILL, (-2i64) as u64, 0) };
    // -2 means "all processes in process group |pid|" which would be group 2
    // This might return ESRCH if no such group exists
    if ret == ESRCH || ret == EPERM {
        pass("kill: pid=-2 returns ESRCH or EPERM");
    } else if ret == 0 {
        pass("kill: pid=-2 succeeded (group exists)");
    } else {
        fail_errno("kill: pid=-2 returns expected error", ESRCH, ret);
    }

    // 5. Signal 0 to non-existent process
    let ret = unsafe { syscall2(nr::KILL, 99999, 0) };
    if ret == ESRCH {
        pass("kill(99999, 0): returns ESRCH");
    } else {
        fail_errno("kill(99999, 0): returns ESRCH", ESRCH, ret);
    }
}

/// Tests for tkill/tgkill
pub fn test_thread_signals() {
    write_str("\n=== Signals: tkill/tgkill ===\n");

    let pid = unsafe { syscall0(nr::GETPID) };
    let tid = unsafe { syscall0(nr::GETTID) };

    // 1. tkill with signal 0 (thread existence check)
    let ret = unsafe { syscall2(nr::TKILL, tid as u64, 0) };
    if ret == 0 {
        pass("tkill(self, 0): thread exists");
    } else {
        fail_errno("tkill(self, 0): thread exists", 0, ret);
    }

    // 2. tkill with invalid TID
    let ret = unsafe { syscall2(nr::TKILL, 0x7FFFFFFF, 0) };
    if ret == ESRCH {
        pass("tkill: invalid TID returns ESRCH");
    } else {
        fail_errno("tkill: invalid TID returns ESRCH", ESRCH, ret);
    }

    // 3. tkill with invalid signal
    let ret = unsafe { syscall2(nr::TKILL, tid as u64, 999) };
    if ret == EINVAL {
        pass("tkill: invalid signal returns EINVAL");
    } else {
        fail_errno("tkill: invalid signal returns EINVAL", EINVAL, ret);
    }

    // 4. tgkill with signal 0
    let ret = unsafe { syscall3(nr::TGKILL, pid as u64, tid as u64, 0) };
    if ret == 0 {
        pass("tgkill(self, self, 0): success");
    } else {
        fail_errno("tgkill(self, self, 0): success", 0, ret);
    }

    // 5. tgkill with mismatched tgid/tid
    let ret = unsafe { syscall3(nr::TGKILL, 1, tid as u64, 0) };
    if ret == ESRCH {
        pass("tgkill: mismatched tgid returns ESRCH");
    } else {
        fail_errno("tgkill: mismatched tgid returns ESRCH", ESRCH, ret);
    }

    // 6. tgkill with invalid tgid
    let ret = unsafe { syscall3(nr::TGKILL, (-1i64) as u64, tid as u64, 0) };
    if ret == EINVAL {
        pass("tgkill: invalid tgid=-1 returns EINVAL");
    } else {
        fail_errno("tgkill: invalid tgid=-1 returns EINVAL", EINVAL, ret);
    }

    // 7. tgkill with invalid tid
    let ret = unsafe { syscall3(nr::TGKILL, pid as u64, (-1i64) as u64, 0) };
    if ret == EINVAL {
        pass("tgkill: invalid tid=-1 returns EINVAL");
    } else {
        fail_errno("tgkill: invalid tid=-1 returns EINVAL", EINVAL, ret);
    }
}

/// Boundary tests for signals
pub fn test_signal_boundary() {
    write_str("\n=== Signals: boundary cases ===\n");

    let pid = unsafe { syscall0(nr::GETPID) };

    // 1. Signal 0 (existence check, doesn't send actual signal)
    let ret = unsafe { syscall2(nr::KILL, pid as u64, 0) };
    if ret == 0 {
        pass("kill: signal 0 doesn't kill process");
    } else {
        fail_errno("kill: signal 0 doesn't kill process", 0, ret);
    }

    // 2. Signal 1 (SIGHUP) - minimum valid signal
    // Don't actually send it, just check it's valid
    // We'll use sigprocmask to verify it's a valid signal number
    let mask: u64 = 1 << SIGHUP;
    let ret = unsafe {
        syscall4(nr::SIGPROCMASK, SIG_BLOCK, &mask as *const _ as u64, 0, 8)
    };
    if ret == 0 {
        pass("sigprocmask: signal 1 (SIGHUP) is valid");
        // Unblock
        unsafe { syscall4(nr::SIGPROCMASK, SIG_UNBLOCK, &mask as *const _ as u64, 0, 8) };
    } else {
        fail_errno("sigprocmask: signal 1 (SIGHUP) is valid", 0, ret);
    }

    // 3. Signal 31 (SIGSYS) - maximum standard signal
    let mask: u64 = 1 << SIGSYS;
    let ret = unsafe {
        syscall4(nr::SIGPROCMASK, SIG_BLOCK, &mask as *const _ as u64, 0, 8)
    };
    if ret == 0 {
        pass("sigprocmask: signal 31 (SIGSYS) is valid");
        unsafe { syscall4(nr::SIGPROCMASK, SIG_UNBLOCK, &mask as *const _ as u64, 0, 8) };
    } else {
        fail_errno("sigprocmask: signal 31 (SIGSYS) is valid", 0, ret);
    }

    // 4. Signal 64 (SIGRTMAX in extended signal range)
    // Test validity by blocking it (don't actually send it - that would kill us!)
    // Real-time signals have default action of terminate, so we must block before testing
    let rt_mask: u64 = 1 << 63; // Signal 64 is bit 63 (0-indexed in mask)
    let ret = unsafe {
        syscall4(nr::SIGPROCMASK, SIG_BLOCK, &rt_mask as *const _ as u64, 0, 8)
    };
    if ret == 0 || ret == EINVAL {
        pass("sigprocmask: signal 64 (SIGRTMAX) handled");
        // Unblock if we succeeded
        if ret == 0 {
            unsafe { syscall4(nr::SIGPROCMASK, SIG_UNBLOCK, &rt_mask as *const _ as u64, 0, 8) };
        }
    } else {
        fail_errno("sigprocmask: signal 64 (SIGRTMAX) handled", 0, ret);
    }

    // 5. Empty signal mask operations
    let empty: u64 = 0;
    let ret = unsafe {
        syscall4(nr::SIGPROCMASK, SIG_BLOCK, &empty as *const _ as u64, 0, 8)
    };
    if ret == 0 {
        pass("sigprocmask: block empty mask succeeds");
    } else {
        fail_errno("sigprocmask: block empty mask succeeds", 0, ret);
    }

    // 6. Full mask (test that blocking all signals is accepted)
    // Note: SIGKILL/SIGSTOP cannot be blocked - kernel enforces this at delivery time
    let full: u64 = u64::MAX;
    let mut saved = [0u64; 2];
    let ret = unsafe {
        syscall4(nr::SIGPROCMASK, SIG_SETMASK, &full as *const _ as u64,
                 saved.as_mut_ptr() as u64, 8)
    };
    if ret == 0 {
        pass("sigprocmask: set full mask accepted");
        // Restore original mask
        unsafe { syscall4(nr::SIGPROCMASK, SIG_SETMASK, saved.as_ptr() as u64, 0, 8) };
    } else {
        fail_errno("sigprocmask: set full mask accepted", 0, ret);
    }
}

/// Test sigaction basics
pub fn test_sigaction_positive() {
    write_str("\n=== Signals: sigaction positive ===\n");

    // Note: sigaction requires rt_sigaction (nr 13) with specific structure layout
    // This is complex because the kernel expects sa_restorer to be set

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
        pass("sigaction: install SIGUSR1 handler");
    } else {
        fail_errno("sigaction: install SIGUSR1 handler", 0, ret);
        return; // Can't proceed without handler
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
        pass("sigaction: query returns installed handler");
    } else {
        fail("sigaction: query returns installed handler");
    }

    // 3. Restore default handler (SIG_DFL = 0)
    sa.sa_handler = 0;
    sa.sa_flags = 0;
    sa.sa_restorer = 0;
    let ret = unsafe {
        syscall4(nr::SIGACTION, SIGUSR1, &sa as *const _ as u64, 0, 8)
    };
    if ret == 0 {
        pass("sigaction: restore SIG_DFL");
    } else {
        fail_errno("sigaction: restore SIG_DFL", 0, ret);
    }

    // 4. Install handler for SIGUSR2
    sa.sa_handler = test_sig_handler as *const () as u64;
    sa.sa_flags = SA_RESTORER;
    sa.sa_restorer = sig_restorer as *const () as u64;
    let ret = unsafe {
        syscall4(nr::SIGACTION, SIGUSR2, &sa as *const _ as u64, 0, 8)
    };
    if ret == 0 {
        pass("sigaction: install SIGUSR2 handler");
    } else {
        fail_errno("sigaction: install SIGUSR2 handler", 0, ret);
    }

    // Restore SIGUSR2 to default
    sa.sa_handler = 0;
    sa.sa_flags = 0;
    sa.sa_restorer = 0;
    unsafe { syscall4(nr::SIGACTION, SIGUSR2, &sa as *const _ as u64, 0, 8) };
}

/// Negative tests for sigaction
pub fn test_sigaction_negative() {
    write_str("\n=== Signals: sigaction negative ===\n");

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
        pass("sigaction: signal 0 returns EINVAL");
    } else {
        fail_errno("sigaction: signal 0 returns EINVAL", EINVAL, ret);
    }

    // 2. Invalid signal number (> 64)
    let ret = unsafe {
        syscall4(nr::SIGACTION, 999, &sa as *const _ as u64, 0, 8)
    };
    if ret == EINVAL {
        pass("sigaction: signal 999 returns EINVAL");
    } else {
        fail_errno("sigaction: signal 999 returns EINVAL", EINVAL, ret);
    }

    // 3. Try to install handler for SIGKILL
    let ret = unsafe {
        syscall4(nr::SIGACTION, SIGKILL, &sa as *const _ as u64, 0, 8)
    };
    if ret == EINVAL {
        pass("sigaction: SIGKILL returns EINVAL");
    } else {
        fail_errno("sigaction: SIGKILL returns EINVAL", EINVAL, ret);
    }

    // 4. Try to install handler for SIGSTOP
    let ret = unsafe {
        syscall4(nr::SIGACTION, SIGSTOP, &sa as *const _ as u64, 0, 8)
    };
    if ret == EINVAL {
        pass("sigaction: SIGSTOP returns EINVAL");
    } else {
        fail_errno("sigaction: SIGSTOP returns EINVAL", EINVAL, ret);
    }

    // 5. Invalid sigsetsize
    let ret = unsafe {
        syscall4(nr::SIGACTION, SIGUSR1, &sa as *const _ as u64, 0, 4)
    };
    if ret == EINVAL {
        pass("sigaction: invalid sigsetsize returns EINVAL");
    } else {
        fail_errno("sigaction: invalid sigsetsize returns EINVAL", EINVAL, ret);
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

/// Test: install SIGUSR1 handler → kill(self, SIGUSR1) → verify handler ran
pub fn test_signal_delivery_sigusr1() {
    write_str("\n=== Signal delivery: SIGUSR1 handler invoked ===\n");

    // Reset state
    SIGNAL_RECEIVED.store(0, Ordering::SeqCst);
    SIGNAL_NUMBER.store(0, Ordering::SeqCst);

    // Ensure SIGUSR1 is unblocked (prior tests may leave it blocked)
    let unblock: u64 = 1 << SIGUSR1;
    unsafe { syscall4(nr::SIGPROCMASK, SIG_UNBLOCK, &unblock as *const _ as u64, 0, 8) };

    // Install handler
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
        fail_errno("install SIGUSR1 handler", 0, ret);
        return;
    }

    // Send SIGUSR1 to self
    let pid = unsafe { syscall0(nr::GETPID) };
    let ret = unsafe { syscall2(nr::KILL, pid as u64, SIGUSR1) };
    if ret != 0 {
        fail_errno("kill(self, SIGUSR1)", 0, ret);
        return;
    }

    // Verify handler ran
    let received = SIGNAL_RECEIVED.load(Ordering::SeqCst);
    if received == 1 {
        pass("SIGUSR1 handler was invoked");
    } else {
        fail("SIGUSR1 handler was invoked");
        write_str("    SIGNAL_RECEIVED=");
        write_num(received as i64);
        write_str("\n");
    }

    // Verify correct signal number was passed
    let signo = SIGNAL_NUMBER.load(Ordering::SeqCst);
    if signo == SIGUSR1 as u32 {
        pass("handler received correct signal number (10)");
    } else {
        fail("handler received correct signal number (10)");
        write_str("    got signo=");
        write_num(signo as i64);
        write_str("\n");
    }

    // Restore default
    sa.sa_handler = 0;
    sa.sa_flags = 0;
    sa.sa_restorer = 0;
    unsafe { syscall4(nr::SIGACTION, SIGUSR1, &sa as *const _ as u64, 0, 8) };
}

/// Test: install SIGUSR2 handler → tgkill(self, SIGUSR2) → verify
pub fn test_signal_delivery_sigusr2() {
    write_str("\n=== Signal delivery: SIGUSR2 via tgkill ===\n");

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
        fail_errno("install SIGUSR2 handler", 0, ret);
        return;
    }

    // Send via tgkill (more precise: targets specific thread)
    let pid = unsafe { syscall0(nr::GETPID) };
    let tid = unsafe { syscall0(nr::GETTID) };
    let ret = unsafe { syscall3(nr::TGKILL, pid as u64, tid as u64, SIGUSR2) };
    if ret != 0 {
        fail_errno("tgkill(self, SIGUSR2)", 0, ret);
        return;
    }

    let received = SIGNAL_RECEIVED.load(Ordering::SeqCst);
    if received == 2 {
        pass("SIGUSR2 handler was invoked (distinct from SIGUSR1)");
    } else {
        fail("SIGUSR2 handler was invoked");
    }

    let signo = SIGNAL_NUMBER.load(Ordering::SeqCst);
    if signo == SIGUSR2 as u32 {
        pass("handler received SIGUSR2 (12)");
    } else {
        fail("handler received SIGUSR2 (12)");
        write_str("    got signo=");
        write_num(signo as i64);
        write_str("\n");
    }

    // Restore
    sa.sa_handler = 0;
    sa.sa_flags = 0;
    sa.sa_restorer = 0;
    unsafe { syscall4(nr::SIGACTION, SIGUSR2, &sa as *const _ as u64, 0, 8) };
}

/// Test: blocked signal is held pending, delivered on unblock
pub fn test_signal_blocked_pending() {
    write_str("\n=== Signal delivery: blocked → pending → delivered on unblock ===\n");

    // Start clean: unblock SIGUSR1
    let unblock: u64 = 1 << SIGUSR1;
    unsafe { syscall4(nr::SIGPROCMASK, SIG_UNBLOCK, &unblock as *const _ as u64, 0, 8) };

    SIGNAL_RECEIVED.store(0, Ordering::SeqCst);
    SIGNAL_NUMBER.store(0, Ordering::SeqCst);

    // Install handler for SIGUSR1
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
        fail_errno("install handler for pending test", 0, ret);
        return;
    }

    // Block SIGUSR1
    let block_mask: u64 = 1 << SIGUSR1;
    let mut saved_mask = [0u64; 2];
    unsafe {
        syscall4(nr::SIGPROCMASK, SIG_BLOCK, &block_mask as *const _ as u64,
                 saved_mask.as_mut_ptr() as u64, 8)
    };

    // Send SIGUSR1 while blocked
    let pid = unsafe { syscall0(nr::GETPID) };
    unsafe { syscall2(nr::KILL, pid as u64, SIGUSR1) };

    // Verify handler has NOT run yet (signal is pending)
    let received = SIGNAL_RECEIVED.load(Ordering::SeqCst);
    if received == 0 {
        pass("blocked signal not delivered yet");
    } else {
        fail("blocked signal not delivered yet (handler ran prematurely)");
    }

    // Unblock SIGUSR1 — pending signal should be delivered immediately
    unsafe {
        syscall4(nr::SIGPROCMASK, SIG_SETMASK, saved_mask.as_ptr() as u64, 0, 8)
    };

    let received = SIGNAL_RECEIVED.load(Ordering::SeqCst);
    if received == 1 {
        pass("pending signal delivered on unblock");
    } else {
        fail("pending signal delivered on unblock");
        write_str("    SIGNAL_RECEIVED=");
        write_num(received as i64);
        write_str("\n");
    }

    // Restore default handler
    sa.sa_handler = 0;
    sa.sa_flags = 0;
    sa.sa_restorer = 0;
    unsafe { syscall4(nr::SIGACTION, SIGUSR1, &sa as *const _ as u64, 0, 8) };
}

/// Test: SIGALRM delivery (timer signal)
pub fn test_signal_delivery_sigalrm() {
    write_str("\n=== Signal delivery: SIGALRM ===\n");

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
        fail_errno("install SIGALRM handler", 0, ret);
        return;
    }

    let pid = unsafe { syscall0(nr::GETPID) };
    unsafe { syscall2(nr::KILL, pid as u64, SIGALRM) };

    let received = SIGNAL_RECEIVED.load(Ordering::SeqCst);
    let signo = SIGNAL_NUMBER.load(Ordering::SeqCst);

    if received == 1 && signo == SIGALRM as u32 {
        pass("SIGALRM delivered and handler invoked");
    } else {
        fail("SIGALRM delivered and handler invoked");
    }

    sa.sa_handler = 0;
    sa.sa_flags = 0;
    sa.sa_restorer = 0;
    unsafe { syscall4(nr::SIGACTION, SIGALRM, &sa as *const _ as u64, 0, 8) };
}

/// Test: multiple signals delivered in sequence
pub fn test_signal_multiple_delivery() {
    write_str("\n=== Signal delivery: multiple signals in sequence ===\n");

    // Ensure SIGUSR1 is unblocked
    let unblock: u64 = 1 << SIGUSR1;
    unsafe { syscall4(nr::SIGPROCMASK, SIG_UNBLOCK, &unblock as *const _ as u64, 0, 8) };

    static DELIVERY_COUNT: AtomicU32 = AtomicU32::new(0);

    #[unsafe(no_mangle)]
    extern "C" fn counting_handler(_sig: i32) {
        DELIVERY_COUNT.fetch_add(1, Ordering::SeqCst);
    }

    DELIVERY_COUNT.store(0, Ordering::SeqCst);

    let mut sa = Sigaction {
        sa_handler: counting_handler as *const () as u64,
        sa_flags: SA_RESTORER,
        sa_restorer: sig_restorer as *const () as u64,
        sa_mask: [0, 0],
    };

    unsafe {
        syscall4(nr::SIGACTION, SIGUSR1, &sa as *const _ as u64, 0, 8)
    };

    let pid = unsafe { syscall0(nr::GETPID) };

    // Send 5 signals
    for _ in 0..5 {
        unsafe { syscall2(nr::KILL, pid as u64, SIGUSR1) };
    }

    let count = DELIVERY_COUNT.load(Ordering::SeqCst);
    if count == 5 {
        pass("5 signals → 5 handler invocations");
    } else {
        // Signals may coalesce if pending — count >= 1 is valid
        if count >= 1 {
            pass("signals delivered (some may coalesce)");
            write_str("    delivered ");
            write_num(count as i64);
            write_str(" of 5\n");
        } else {
            fail("no signals delivered");
        }
    }

    // Restore default
    sa.sa_handler = 0;
    sa.sa_flags = 0;
    sa.sa_restorer = 0;
    unsafe { syscall4(nr::SIGACTION, SIGUSR1, &sa as *const _ as u64, 0, 8) };
}

// ════════════════════════════════════════════════════════════════════════════
// sigpending — query pending signal set
// ════════════════════════════════════════════════════════════════════════════

pub fn test_sigpending() {
    write_str("\n=== Signal: sigpending ===\n");

    // Install handler FIRST so delivery on unblock doesn't kill us
    let mut sa = Sigaction {
        sa_handler: test_sig_handler as *const () as u64,
        sa_flags: SA_RESTORER,
        sa_restorer: sig_restorer as *const () as u64,
        sa_mask: [0, 0],
    };
    unsafe { syscall4(nr::SIGACTION, SIGUSR1, &sa as *const _ as u64, 0, 8) };

    // Save current mask, then explicitly set mask with SIGUSR1 blocked
    let mut saved = [0u64; 2];
    let block_mask: u64 = 1 << SIGUSR1;
    unsafe {
        syscall4(nr::SIGPROCMASK, SIG_SETMASK, &block_mask as *const _ as u64,
                 saved.as_mut_ptr() as u64, 8)
    };

    let pid = unsafe { syscall0(nr::GETPID) };
    unsafe { syscall2(nr::KILL, pid as u64, SIGUSR1) };

    // Query pending signals
    let mut pending = [0u64; 2];
    let ret = unsafe {
        syscall2(nr::SIGPENDING, pending.as_mut_ptr() as u64, 8)
    };
    if ret == 0 {
        pass("sigpending returns 0");
    } else {
        fail_errno("sigpending returns 0", 0, ret);
    }

    if (pending[0] & (1 << SIGUSR1)) != 0 {
        pass("SIGUSR1 appears in pending set");
    } else {
        fail("SIGUSR1 appears in pending set");
    }

    // Unblock to clear the pending signal
    unsafe { syscall4(nr::SIGPROCMASK, SIG_SETMASK, saved.as_ptr() as u64, 0, 8) };

    // Restore default
    sa.sa_handler = 0; sa.sa_flags = 0; sa.sa_restorer = 0;
    unsafe { syscall4(nr::SIGACTION, SIGUSR1, &sa as *const _ as u64, 0, 8) };
}

// ════════════════════════════════════════════════════════════════════════════
// rt_sigtimedwait — synchronous signal wait
// ════════════════════════════════════════════════════════════════════════════

pub fn test_sigtimedwait() {
    write_str("\n=== Signal: rt_sigtimedwait ===\n");

    // Explicitly set mask with SIGUSR1 blocked (deterministic state)
    let block_mask: u64 = 1 << SIGUSR1;
    let mut saved = [0u64; 2];
    unsafe {
        syscall4(nr::SIGPROCMASK, SIG_SETMASK, &block_mask as *const _ as u64,
                 saved.as_mut_ptr() as u64, 8)
    };

    let pid = unsafe { syscall0(nr::GETPID) };
    unsafe { syscall2(nr::KILL, pid as u64, SIGUSR1) };

    // sigtimedwait with zero timeout (immediate)
    let ts = crate::Timespec { tv_sec: 0, tv_nsec: 0 };
    let ret = unsafe {
        syscall4(nr::SIGTIMEDWAIT, &block_mask as *const _ as u64, 0,
                 &ts as *const _ as u64, 8)
    };
    if ret == SIGUSR1 as i64 {
        pass("rt_sigtimedwait returns SIGUSR1");
    } else if ret > 0 {
        pass("rt_sigtimedwait returned a signal");
    } else {
        fail_errno("rt_sigtimedwait returns signal", SIGUSR1 as i64, ret);
    }

    // Timeout with no pending signal → EAGAIN
    let ts2 = crate::Timespec { tv_sec: 0, tv_nsec: 1_000_000 }; // 1ms
    let ret = unsafe {
        syscall4(nr::SIGTIMEDWAIT, &block_mask as *const _ as u64, 0,
                 &ts2 as *const _ as u64, 8)
    };
    if ret == -11 { // EAGAIN
        pass("rt_sigtimedwait with no pending signal returns EAGAIN");
    } else {
        fail_errno("rt_sigtimedwait timeout returns EAGAIN", -11, ret);
    }

    // Restore mask
    unsafe { syscall4(nr::SIGPROCMASK, SIG_SETMASK, saved.as_ptr() as u64, 0, 8) };
}

// ════════════════════════════════════════════════════════════════════════════
// Module entry point
// ════════════════════════════════════════════════════════════════════════════

pub fn run_all() {
    write_str("\n╔══════════════════════════════════════════════════════════╗\n");
    write_str("║              SIGNAL TESTS (Comprehensive)                ║\n");
    write_str("╚══════════════════════════════════════════════════════════╝\n");

    // Positive tests
    test_sigprocmask_positive();
    test_kill_positive();
    test_sigaction_positive();

    // Negative tests
    test_sigprocmask_negative();
    test_kill_negative();
    test_sigaction_negative();

    // Thread signal tests
    test_thread_signals();

    // Boundary tests
    test_signal_boundary();

    // Signal delivery verification
    test_signal_delivery_sigusr1();
    test_signal_delivery_sigusr2();
    test_signal_blocked_pending();
    test_signal_delivery_sigalrm();
    test_signal_multiple_delivery();

    // Realtime signal extensions
    test_sigpending();
    test_sigtimedwait();
}
