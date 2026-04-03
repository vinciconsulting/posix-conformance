//! Fork/exec/waitpid conformance tests — PSE52's defining feature
//!
//! Tests: clone (fork-like), execve, wait4, exit status propagation,
//!        signal-caused death, zombie reaping
//!
//! Categories:
//! - Positive: fork child, child exits, parent reaps with correct status
//! - Negative: waitpid on non-child, execve of non-existent binary
//! - Boundary: double-wait (ECHILD), exit(127) vs signal death encoding

use crate::nr;
use crate::{pass, fail, fail_errno, write_str, write_num, write_hex};
use crate::{syscall0, syscall1, syscall2, syscall3, syscall4, syscall5};

// ════════════════════════════════════════════════════════════════════════════
// Constants
// ════════════════════════════════════════════════════════════════════════════

// clone flags for fork-like behavior
const SIGCHLD: u64 = 17;

// waitpid options
const WNOHANG: u64 = 1;
// Error codes
const ECHILD: i64 = -10;
const ENOENT: i64 = -2;
const EFAULT: i64 = -14;

// Signals
const SIGKILL: u64 = 9;

// wait status macros (Linux encoding)
fn wifexited(status: i32) -> bool {
    (status & 0x7F) == 0
}

fn wexitstatus(status: i32) -> i32 {
    (status >> 8) & 0xFF
}

fn wifsignaled(status: i32) -> bool {
    let sig = status & 0x7F;
    sig != 0 && sig != 0x7F
}

fn wtermsig(status: i32) -> i32 {
    status & 0x7F
}

// ════════════════════════════════════════════════════════════════════════════
// Helper: fork via clone(SIGCHLD, 0, 0, 0, 0)
// ════════════════════════════════════════════════════════════════════════════

/// Fork using clone(SIGCHLD, 0, 0, 0, 0).
/// Returns: > 0 = child pid (in parent), 0 = in child, < 0 = error.
unsafe fn do_fork() -> i64 {
    unsafe { syscall5(nr::CLONE, SIGCHLD, 0, 0, 0, 0) }
}

/// wait4(pid, &status, options, NULL) — wait for child
unsafe fn do_wait4(pid: i64, status: &mut i32, options: u64) -> i64 {
    const WAIT4: u64 = 61;
    unsafe { syscall4(WAIT4, pid as u64, status as *mut i32 as u64, options, 0) }
}

// ════════════════════════════════════════════════════════════════════════════
// Test: Basic fork + exit + wait
// ════════════════════════════════════════════════════════════════════════════

fn test_fork_exit_wait() {
    write_str("\n=== Fork: basic fork + exit(42) + wait ===\n");

    let pid = unsafe { do_fork() };
    if pid < 0 {
        fail_errno("clone(SIGCHLD) fork", 0, pid);
        return;
    }

    if pid == 0 {
        // Child: exit with status 42
        unsafe { syscall1(nr::EXIT, 42) };
        loop { core::hint::spin_loop(); }
    }

    // Parent: pid > 0
    if pid > 0 {
        pass("clone(SIGCHLD) returns child pid");
    } else {
        fail("clone(SIGCHLD) returns child pid");
        return;
    }

    // Wait for child
    let mut status: i32 = 0;
    let waited = unsafe { do_wait4(pid, &mut status, 0) };

    if waited == pid {
        pass("wait4 returns child pid");
    } else {
        fail_errno("wait4 returns child pid", pid, waited);
        return;
    }

    // Verify exit status encoding
    if wifexited(status) {
        pass("WIFEXITED(status) is true");
    } else {
        fail("WIFEXITED(status) is true");
        write_str("    raw status: ");
        write_hex(status as u64);
        write_str("\n");
    }

    if wexitstatus(status) == 42 {
        pass("WEXITSTATUS(status) == 42");
    } else {
        fail("WEXITSTATUS(status) == 42");
        write_str("    got exit status: ");
        write_num(wexitstatus(status) as i64);
        write_str("\n");
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Test: Fork child exits 0
// ════════════════════════════════════════════════════════════════════════════

fn test_fork_exit_zero() {
    write_str("\n=== Fork: child exit(0) ===\n");

    let pid = unsafe { do_fork() };
    if pid < 0 {
        fail_errno("fork for exit(0)", 0, pid);
        return;
    }
    if pid == 0 {
        unsafe { syscall1(nr::EXIT, 0) };
        loop { core::hint::spin_loop(); }
    }

    let mut status: i32 = 0;
    let waited = unsafe { do_wait4(pid, &mut status, 0) };

    if waited == pid && wifexited(status) && wexitstatus(status) == 0 {
        pass("child exit(0): reaped with status 0");
    } else {
        fail("child exit(0): reaped with status 0");
        write_str("    waited=");
        write_num(waited);
        write_str(" status=");
        write_hex(status as u64);
        write_str("\n");
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Test: Fork child exits 127 (convention for exec-not-found)
// ════════════════════════════════════════════════════════════════════════════

fn test_fork_exit_127() {
    write_str("\n=== Fork: child exit(127) — exec-not-found convention ===\n");

    let pid = unsafe { do_fork() };
    if pid < 0 {
        fail_errno("fork for exit(127)", 0, pid);
        return;
    }
    if pid == 0 {
        unsafe { syscall1(nr::EXIT, 127) };
        loop { core::hint::spin_loop(); }
    }

    let mut status: i32 = 0;
    let waited = unsafe { do_wait4(pid, &mut status, 0) };

    if waited == pid && wifexited(status) && wexitstatus(status) == 127 {
        pass("child exit(127): reaped correctly");
    } else {
        fail("child exit(127): reaped correctly");
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Test: Fork child exits 255 (max exit code)
// ════════════════════════════════════════════════════════════════════════════

fn test_fork_exit_max() {
    write_str("\n=== Fork: child exit(255) — max exit code ===\n");

    let pid = unsafe { do_fork() };
    if pid < 0 {
        fail_errno("fork for exit(255)", 0, pid);
        return;
    }
    if pid == 0 {
        unsafe { syscall1(nr::EXIT, 255) };
        loop { core::hint::spin_loop(); }
    }

    let mut status: i32 = 0;
    let waited = unsafe { do_wait4(pid, &mut status, 0) };

    if waited == pid && wifexited(status) && wexitstatus(status) == 255 {
        pass("child exit(255): max code preserved");
    } else {
        fail("child exit(255): max code preserved");
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Test: Child killed by signal → WIFSIGNALED
// ════════════════════════════════════════════════════════════════════════════

fn test_fork_signal_death() {
    write_str("\n=== Fork: child killed by SIGKILL ===\n");

    let pid = unsafe { do_fork() };
    if pid < 0 {
        fail_errno("fork for signal death", 0, pid);
        return;
    }
    if pid == 0 {
        // Child: spin until killed
        loop { unsafe { syscall0(nr::SCHED_YIELD) }; }
    }

    // Parent: kill child with SIGKILL
    let ret = unsafe { syscall2(nr::KILL, pid as u64, SIGKILL) };
    if ret != 0 {
        fail_errno("kill(child, SIGKILL)", 0, ret);
        return;
    }
    pass("kill(child, SIGKILL) returns 0");

    let mut status: i32 = 0;
    let waited = unsafe { do_wait4(pid, &mut status, 0) };

    if waited != pid {
        fail_errno("wait4 after SIGKILL returns child pid", pid, waited);
        return;
    }
    pass("wait4 after SIGKILL returns child pid");

    if wifsignaled(status) {
        pass("WIFSIGNALED(status) is true");
    } else {
        fail("WIFSIGNALED(status) is true");
        write_str("    raw status: ");
        write_hex(status as u64);
        write_str("\n");
    }

    if wtermsig(status) == SIGKILL as i32 {
        pass("WTERMSIG(status) == SIGKILL");
    } else {
        fail("WTERMSIG(status) == SIGKILL");
        write_str("    got signal: ");
        write_num(wtermsig(status) as i64);
        write_str("\n");
    }

    // Verify mutual exclusion: WIFEXITED should be false
    if !wifexited(status) {
        pass("WIFEXITED(status) is false after signal death");
    } else {
        fail("WIFEXITED(status) is false after signal death");
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Test: WNOHANG — non-blocking wait
// ════════════════════════════════════════════════════════════════════════════

fn test_wnohang() {
    write_str("\n=== Fork: WNOHANG (non-blocking wait) ===\n");

    let pid = unsafe { do_fork() };
    if pid < 0 {
        fail_errno("fork for WNOHANG", 0, pid);
        return;
    }
    if pid == 0 {
        // Child: sleep briefly then exit
        let ts = crate::Timespec { tv_sec: 0, tv_nsec: 50_000_000 }; // 50ms
        unsafe { syscall2(nr::NANOSLEEP, &ts as *const _ as u64, 0) };
        unsafe { syscall1(nr::EXIT, 7) };
        loop { core::hint::spin_loop(); }
    }

    // Parent: immediate WNOHANG should return 0 (child still running)
    let mut status: i32 = 0;
    let waited = unsafe { do_wait4(pid, &mut status, WNOHANG) };
    if waited == 0 {
        pass("WNOHANG returns 0 (child still running)");
    } else if waited == pid {
        // Child finished very quickly (possible on fast system)
        pass("WNOHANG returned child (already exited)");
        return;
    } else {
        fail_errno("WNOHANG returns 0 or child pid", 0, waited);
    }

    // Now do blocking wait
    let waited = unsafe { do_wait4(pid, &mut status, 0) };
    if waited == pid && wifexited(status) && wexitstatus(status) == 7 {
        pass("blocking wait after WNOHANG succeeds");
    } else {
        fail("blocking wait after WNOHANG succeeds");
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Test: Double wait → ECHILD
// ════════════════════════════════════════════════════════════════════════════

fn test_double_wait() {
    write_str("\n=== Fork: double wait → ECHILD ===\n");

    let pid = unsafe { do_fork() };
    if pid < 0 {
        fail_errno("fork for double wait", 0, pid);
        return;
    }
    if pid == 0 {
        unsafe { syscall1(nr::EXIT, 0) };
        loop { core::hint::spin_loop(); }
    }

    // First wait: should succeed
    let mut status: i32 = 0;
    let waited = unsafe { do_wait4(pid, &mut status, 0) };
    if waited != pid {
        fail("double wait: first wait failed");
        return;
    }
    pass("first wait succeeds");

    // Second wait: should return ECHILD (zombie already reaped)
    let waited = unsafe { do_wait4(pid, &mut status, 0) };
    if waited == ECHILD {
        pass("second wait returns ECHILD");
    } else {
        fail_errno("second wait returns ECHILD", ECHILD, waited);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Test: waitpid(-1) with no children → ECHILD
// ════════════════════════════════════════════════════════════════════════════

fn test_wait_no_children() {
    write_str("\n=== Fork: wait(-1) with no children ===\n");

    let mut status: i32 = 0;
    let waited = unsafe { do_wait4(-1, &mut status, WNOHANG) };
    if waited == ECHILD {
        pass("wait(-1, WNOHANG) with no children returns ECHILD");
    } else {
        fail_errno("wait(-1, WNOHANG) with no children returns ECHILD", ECHILD, waited);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Test: Multiple children, wait for each
// ════════════════════════════════════════════════════════════════════════════

fn test_multiple_children() {
    write_str("\n=== Fork: multiple children ===\n");

    const NUM_CHILDREN: usize = 3;
    let mut pids = [0i64; NUM_CHILDREN];

    // Fork 3 children with different exit codes
    for i in 0..NUM_CHILDREN {
        let pid = unsafe { do_fork() };
        if pid < 0 {
            fail_errno("fork child", 0, pid);
            return;
        }
        if pid == 0 {
            unsafe { syscall1(nr::EXIT, (10 + i) as u64) };
            loop { core::hint::spin_loop(); }
        }
        pids[i] = pid;
    }
    pass("forked 3 children");

    // Wait for each child specifically
    let mut all_ok = true;
    for i in 0..NUM_CHILDREN {
        let mut status: i32 = 0;
        let waited = unsafe { do_wait4(pids[i], &mut status, 0) };
        if waited != pids[i] || !wifexited(status) || wexitstatus(status) != (10 + i) as i32 {
            all_ok = false;
            write_str("    child ");
            write_num(i as i64);
            write_str(": waited=");
            write_num(waited);
            write_str(" status=");
            write_hex(status as u64);
            write_str("\n");
        }
    }
    if all_ok {
        pass("all 3 children reaped with correct exit codes");
    } else {
        fail("all 3 children reaped with correct exit codes");
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Test: Child getpid/getppid consistency
// ════════════════════════════════════════════════════════════════════════════

fn test_child_pid_consistency() {
    write_str("\n=== Fork: child pid/ppid consistency ===\n");

    let parent_pid = unsafe { syscall0(nr::GETPID) };

    let pid = unsafe { do_fork() };
    if pid < 0 {
        fail_errno("fork for pid check", 0, pid);
        return;
    }
    if pid == 0 {
        // Child: verify our pid differs from parent and ppid matches parent
        let child_pid = unsafe { syscall0(nr::GETPID) };
        let child_ppid = unsafe { syscall0(nr::GETPPID) };

        // Exit with encoded result: bit 0 = pid != parent, bit 1 = ppid == parent
        let mut result: u64 = 0;
        if child_pid != parent_pid { result |= 1; }
        if child_ppid == parent_pid { result |= 2; }
        unsafe { syscall1(nr::EXIT, result) };
        loop { core::hint::spin_loop(); }
    }

    let mut status: i32 = 0;
    let waited = unsafe { do_wait4(pid, &mut status, 0) };
    if waited != pid {
        fail("wait for pid-check child");
        return;
    }

    let code = wexitstatus(status);
    if code & 1 != 0 {
        pass("child getpid() != parent getpid()");
    } else {
        fail("child getpid() != parent getpid()");
    }

    if code & 2 != 0 {
        pass("child getppid() == parent getpid()");
    } else {
        fail("child getppid() == parent getpid()");
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Test: execve with non-existent binary → ENOENT
// ════════════════════════════════════════════════════════════════════════════

fn test_execve_enoent() {
    write_str("\n=== Fork: execve non-existent → ENOENT ===\n");

    const EXECVE: u64 = 59;

    let pid = unsafe { do_fork() };
    if pid < 0 {
        fail_errno("fork for execve test", 0, pid);
        return;
    }
    if pid == 0 {
        // Child: try to execve a non-existent binary
        let path = b"/nonexistent_binary_12345\0";
        let argv: [u64; 1] = [0]; // NULL-terminated argv
        let envp: [u64; 1] = [0]; // NULL-terminated envp

        let ret = unsafe {
            syscall3(EXECVE, path.as_ptr() as u64, argv.as_ptr() as u64, envp.as_ptr() as u64)
        };
        // execve only returns on error — encode errno in exit code
        // ret is negative errno, negate to get positive exit code
        let code = if ret == ENOENT { 1u64 } else { 2u64 };
        unsafe { syscall1(nr::EXIT, code) };
        loop { core::hint::spin_loop(); }
    }

    let mut status: i32 = 0;
    let waited = unsafe { do_wait4(pid, &mut status, 0) };
    if waited != pid {
        fail("wait for execve child");
        return;
    }

    if wifexited(status) && wexitstatus(status) == 1 {
        pass("execve(/nonexistent) returns ENOENT in child");
    } else {
        fail("execve(/nonexistent) returns ENOENT in child");
        write_str("    exit code: ");
        write_num(wexitstatus(status) as i64);
        write_str("\n");
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Test: execve with bad pointer → EFAULT
// ════════════════════════════════════════════════════════════════════════════

fn test_execve_efault() {
    write_str("\n=== Fork: execve bad pointer → EFAULT ===\n");

    const EXECVE: u64 = 59;

    let pid = unsafe { do_fork() };
    if pid < 0 {
        fail_errno("fork for execve EFAULT", 0, pid);
        return;
    }
    if pid == 0 {
        // Child: execve with NULL path
        let ret = unsafe { syscall3(EXECVE, 0, 0, 0) };
        let code = if ret == EFAULT { 1u64 } else { 2u64 };
        unsafe { syscall1(nr::EXIT, code) };
        loop { core::hint::spin_loop(); }
    }

    let mut status: i32 = 0;
    let waited = unsafe { do_wait4(pid, &mut status, 0) };
    if waited == pid && wifexited(status) && wexitstatus(status) == 1 {
        pass("execve(NULL) returns EFAULT");
    } else {
        fail("execve(NULL) returns EFAULT");
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Test: exit_group terminates all threads in child
// ════════════════════════════════════════════════════════════════════════════

fn test_exit_group() {
    write_str("\n=== Fork: exit_group in child ===\n");

    let pid = unsafe { do_fork() };
    if pid < 0 {
        fail_errno("fork for exit_group", 0, pid);
        return;
    }
    if pid == 0 {
        // exit_group(99)
        unsafe { syscall1(nr::EXIT_GROUP, 99) };
        loop { core::hint::spin_loop(); }
    }

    let mut status: i32 = 0;
    let waited = unsafe { do_wait4(pid, &mut status, 0) };
    if waited == pid && wifexited(status) && wexitstatus(status) == 99 {
        pass("exit_group(99) reaped correctly");
    } else {
        fail("exit_group(99) reaped correctly");
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Test: child inherits open file descriptors
// ════════════════════════════════════════════════════════════════════════════

fn test_child_inherits_fds() {
    write_str("\n=== Fork: child inherits open fds ===\n");

    // Create a pipe, fork, child writes to pipe, parent reads
    let mut fds = [0i32; 2];
    let ret = unsafe { syscall2(nr::PIPE2, fds.as_mut_ptr() as u64, 0) };
    if ret != 0 {
        fail_errno("pipe2 for fd inheritance", 0, ret);
        return;
    }

    let pid = unsafe { do_fork() };
    if pid < 0 {
        fail_errno("fork for fd inheritance", 0, pid);
        unsafe {
            syscall1(nr::CLOSE, fds[0] as u64);
            syscall1(nr::CLOSE, fds[1] as u64);
        }
        return;
    }
    if pid == 0 {
        // Child: close read end, write magic bytes to write end
        unsafe { syscall1(nr::CLOSE, fds[0] as u64) };
        let magic = [0xDE_u8, 0xAD, 0xBE, 0xEF];
        let written = unsafe {
            syscall3(nr::WRITE, fds[1] as u64, magic.as_ptr() as u64, 4)
        };
        let code = if written == 4 { 0u64 } else { 1u64 };
        unsafe { syscall1(nr::CLOSE, fds[1] as u64) };
        unsafe { syscall1(nr::EXIT, code) };
        loop { core::hint::spin_loop(); }
    }

    // Parent: close write end, read from pipe
    unsafe { syscall1(nr::CLOSE, fds[1] as u64) };

    let mut buf = [0u8; 4];
    let nread = unsafe {
        syscall3(nr::READ, fds[0] as u64, buf.as_mut_ptr() as u64, 4)
    };
    unsafe { syscall1(nr::CLOSE, fds[0] as u64) };

    let mut status: i32 = 0;
    unsafe { do_wait4(pid, &mut status, 0) };

    if nread == 4 && buf == [0xDE, 0xAD, 0xBE, 0xEF] {
        pass("child wrote to inherited pipe, parent read magic bytes");
    } else {
        fail("child wrote to inherited pipe, parent read magic bytes");
        write_str("    nread=");
        write_num(nread);
        write_str("\n");
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Module entry point
// ════════════════════════════════════════════════════════════════════════════

pub fn run_all() {
    crate::write_banner("FORK/EXEC/WAIT TESTS (PSE52)");

    // Basic fork + exit + wait
    test_fork_exit_wait();
    test_fork_exit_zero();
    test_fork_exit_127();
    test_fork_exit_max();

    // Signal-caused death
    test_fork_signal_death();

    // Wait semantics
    test_wnohang();
    test_double_wait();
    test_wait_no_children();

    // Multiple children
    test_multiple_children();

    // PID consistency across fork
    test_child_pid_consistency();

    // Exec
    test_execve_enoent();
    test_execve_efault();

    // exit_group
    test_exit_group();

    // FD inheritance
    test_child_inherits_fds();
}
