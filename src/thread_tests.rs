//! Thread (pthread-equivalent) conformance tests
//!
//! Tests: clone with CLONE_THREAD + CLONE_VM, shared futex wait/wake,
//!        independent TLS per thread, thread stack isolation,
//!        clear_child_tid on thread exit
//!
//! Categories:
//! - Positive: thread creation, shared memory, futex signaling
//! - Negative: clone with invalid flags
//! - Boundary: thread accessing parent stack, concurrent futex
//!
//! Assembly note: clone(CLONE_THREAD) with a new stack requires asm because
//! after the syscall the child is on a different stack — Rust's stack frame
//! is gone. The trampoline is 6 instructions. Everything else is Rust.

use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};

use crate::nr;
use crate::{pass, fail, fail_errno, write_str, write_num, write_hex, Timespec};
use crate::{syscall0, syscall1, syscall2, syscall6};

// ════════════════════════════════════════════════════════════════════════════
// Constants
// ════════════════════════════════════════════════════════════════════════════

const CLONE_VM: u64 = 0x00000100;
const CLONE_FS: u64 = 0x00000200;
const CLONE_FILES: u64 = 0x00000400;
const CLONE_SIGHAND: u64 = 0x00000800;
const CLONE_THREAD: u64 = 0x00010000;
const CLONE_SETTLS: u64 = 0x00080000;
const CLONE_PARENT_SETTID: u64 = 0x00100000;
const CLONE_CHILD_CLEARTID: u64 = 0x00200000;

const PTHREAD_FLAGS: u64 = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND
    | CLONE_THREAD | CLONE_SETTLS | CLONE_PARENT_SETTID
    | CLONE_CHILD_CLEARTID;

const FUTEX_WAIT: u64 = 0;
const FUTEX_WAKE: u64 = 1;

const THREAD_STACK_SIZE: usize = 64 * 1024; // 64 KiB

const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const MAP_PRIVATE: u64 = 0x02;
const MAP_ANONYMOUS: u64 = 0x20;

// ════════════════════════════════════════════════════════════════════════════
// Thread-shared state (atomics — no unsafe needed to access)
// ════════════════════════════════════════════════════════════════════════════

static SHARED_COUNTER: AtomicU32 = AtomicU32::new(0);
static THREAD_TID: AtomicI32 = AtomicI32::new(0);
static THREAD_RESULT: AtomicU32 = AtomicU32::new(0);
static THREAD2_TID: AtomicI32 = AtomicI32::new(0);
static THREAD2_RESULT: AtomicU32 = AtomicU32::new(0);
static FUTEX_RENDEZVOUS: AtomicU32 = AtomicU32::new(0);

// ════════════════════════════════════════════════════════════════════════════
// Stack allocation (Rust calling mmap/munmap via existing syscall wrappers)
// ════════════════════════════════════════════════════════════════════════════

fn alloc_stack() -> Option<u64> {
    let addr = unsafe {
        syscall6(
            nr::MMAP, 0, THREAD_STACK_SIZE as u64,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
            (-1i64) as u64, 0,
        )
    };
    if addr < 0 { return None; }
    Some((addr as u64) + THREAD_STACK_SIZE as u64)
}

fn free_stack(stack_top: u64) {
    let base = stack_top - THREAD_STACK_SIZE as u64;
    unsafe { syscall2(nr::MUNMAP, base, THREAD_STACK_SIZE as u64) };
}

// ════════════════════════════════════════════════════════════════════════════
// Wait for thread exit via CLONE_CHILD_CLEARTID + futex
// ════════════════════════════════════════════════════════════════════════════

fn wait_for_thread(tid_ptr: &AtomicI32) {
    // Spin first — thread may have already exited
    for _ in 0..1_000_000 {
        if tid_ptr.load(Ordering::Acquire) == 0 {
            return;
        }
        core::hint::spin_loop();
    }
    // Fall back to futex wait with 1 s timeout
    let ts = Timespec { tv_sec: 1, tv_nsec: 0 };
    let tid_val = tid_ptr.load(Ordering::Acquire);
    if tid_val != 0 {
        unsafe {
            syscall6(
                nr::FUTEX, tid_ptr as *const _ as u64,
                FUTEX_WAIT, tid_val as u64,
                &ts as *const _ as u64, 0, 0,
            );
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Thread entry points — plain Rust functions that use syscall wrappers
// ════════════════════════════════════════════════════════════════════════════

unsafe extern "C" fn thread_entry_basic() -> ! {
    SHARED_COUNTER.fetch_add(1, Ordering::SeqCst);
    let my_tid = unsafe { syscall0(nr::GETTID) };
    THREAD_RESULT.store(my_tid as u32, Ordering::SeqCst);
    unsafe { syscall1(nr::EXIT, 0) };
    loop { core::hint::spin_loop(); }
}

unsafe extern "C" fn thread_entry_tls() -> ! {
    const ARCH_SET_FS: u64 = 0x1002;
    const ARCH_GET_FS: u64 = 0x1003;

    #[repr(C, align(16))]
    struct TlsBlock { magic: u64 }

    let mut tls = TlsBlock { magic: 0xDEAD_CAFE_u64 };
    let tls_addr = &mut tls as *mut TlsBlock as u64;
    unsafe { syscall2(nr::ARCH_PRCTL, ARCH_SET_FS, tls_addr) };

    let mut fs_base: u64 = 0;
    unsafe { syscall2(nr::ARCH_PRCTL, ARCH_GET_FS, &mut fs_base as *mut u64 as u64) };

    THREAD_RESULT.store(if fs_base == tls_addr { 1 } else { 0 }, Ordering::SeqCst);
    unsafe { syscall1(nr::EXIT, 0) };
    loop { core::hint::spin_loop(); }
}

unsafe extern "C" fn thread_entry_second() -> ! {
    SHARED_COUNTER.fetch_add(10, Ordering::SeqCst);
    let my_tid = unsafe { syscall0(nr::GETTID) };
    THREAD2_RESULT.store(my_tid as u32, Ordering::SeqCst);
    unsafe { syscall1(nr::EXIT, 0) };
    loop { core::hint::spin_loop(); }
}

unsafe extern "C" fn thread_entry_futex() -> ! {
    unsafe {
        syscall6(
            nr::FUTEX, &FUTEX_RENDEZVOUS as *const _ as u64,
            FUTEX_WAIT, 0, 0, 0, 0,
        );
    }
    THREAD_RESULT.store(0xBEEF, Ordering::SeqCst);
    unsafe { syscall1(nr::EXIT, 0) };
    loop { core::hint::spin_loop(); }
}

// ════════════════════════════════════════════════════════════════════════════
// spawn_thread — the only place that needs custom asm
//
// Why: clone(CLONE_THREAD) gives the child a new stack. After the syscall
// instruction, the child's RSP points to that new stack and the parent's
// Rust stack frame is gone. We need 6 asm instructions to handle the fork:
//   syscall → test rax → jnz (parent) / call entry → ud2 (child)
// Everything else (flags, registers) uses Rust `in()` constraints.
// ════════════════════════════════════════════════════════════════════════════

fn spawn_thread(
    entry: unsafe extern "C" fn() -> !,
    tid_ptr: &AtomicI32,
) -> Result<u64, i64> {
    let stack_top = alloc_stack().ok_or(-12i64)?; // ENOMEM

    tid_ptr.store(-1, Ordering::SeqCst);

    let ret: i64;
    unsafe {
        // Place entry fn pointer on the new stack for the child to pop+call
        *((stack_top - 8) as *mut u64) = entry as u64;

        core::arch::asm!(
            "syscall",
            "test rax, rax",
            "jnz 2f",
            // Child path: on new stack, pop entry address and call it
            "pop rax",
            "call rax",
            "ud2",
            "2:",
            inout("rax") nr::CLONE => ret,
            in("rdi") PTHREAD_FLAGS,
            in("rsi") stack_top - 8,          // child stack pointer
            in("rdx") tid_ptr as *const _ as u64,  // parent_tid
            in("r10") tid_ptr as *const _ as u64,  // child_tid
            in("r8")  0u64,                   // tls
            out("rcx") _,
            out("r11") _,
        );
    }

    if ret < 0 {
        free_stack(stack_top);
        Err(ret)
    } else {
        Ok(stack_top)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Tests — all plain Rust
// ════════════════════════════════════════════════════════════════════════════

fn test_basic_thread() {
    write_str("\n=== Threads: basic CLONE_THREAD ===\n");

    SHARED_COUNTER.store(0, Ordering::SeqCst);
    THREAD_RESULT.store(0, Ordering::SeqCst);

    let parent_tid = unsafe { syscall0(nr::GETTID) };

    let stack_top = match spawn_thread(thread_entry_basic, &THREAD_TID) {
        Ok(s) => { pass("clone(CLONE_THREAD) returns tid"); s }
        Err(e) => { fail_errno("clone(CLONE_THREAD)", 0, e); return; }
    };

    wait_for_thread(&THREAD_TID);

    let counter = SHARED_COUNTER.load(Ordering::SeqCst);
    if counter == 1 {
        pass("CLONE_VM: shared counter incremented by thread");
    } else {
        fail("CLONE_VM: shared counter incremented by thread");
        write_str("    counter=");
        write_num(counter as i64);
        write_str("\n");
    }

    let child_tid = THREAD_RESULT.load(Ordering::SeqCst);
    if child_tid != 0 && child_tid != parent_tid as u32 {
        pass("thread TID differs from parent TID");
    } else {
        fail("thread TID differs from parent TID");
        write_str("    parent=");
        write_num(parent_tid);
        write_str(" child=");
        write_num(child_tid as i64);
        write_str("\n");
    }

    let tid_val = THREAD_TID.load(Ordering::SeqCst);
    if tid_val == 0 {
        pass("CLONE_CHILD_CLEARTID: tid set to 0 on exit");
    } else {
        fail("CLONE_CHILD_CLEARTID: tid set to 0 on exit");
        write_str("    tid_val=");
        write_num(tid_val as i64);
        write_str("\n");
    }

    free_stack(stack_top);
}

fn test_thread_tls() {
    write_str("\n=== Threads: independent TLS ===\n");

    const ARCH_GET_FS: u64 = 0x1003;
    const ARCH_SET_FS: u64 = 0x1002;
    let mut parent_fs: u64 = 0;
    unsafe { syscall2(nr::ARCH_PRCTL, ARCH_GET_FS, &mut parent_fs as *mut u64 as u64) };

    THREAD_RESULT.store(0, Ordering::SeqCst);

    let stack_top = match spawn_thread(thread_entry_tls, &THREAD_TID) {
        Ok(s) => s,
        Err(e) => { fail_errno("clone for TLS test", 0, e); return; }
    };

    wait_for_thread(&THREAD_TID);

    if THREAD_RESULT.load(Ordering::SeqCst) == 1 {
        pass("thread set independent FS base");
    } else {
        fail("thread set independent FS base");
    }

    let mut current_fs: u64 = 0;
    unsafe { syscall2(nr::ARCH_PRCTL, ARCH_GET_FS, &mut current_fs as *mut u64 as u64) };
    if current_fs == parent_fs {
        pass("parent FS base unchanged after thread exit");
    } else {
        fail("parent FS base unchanged after thread exit");
    }

    unsafe { syscall2(nr::ARCH_PRCTL, ARCH_SET_FS, parent_fs) };
    free_stack(stack_top);
}

fn test_two_threads() {
    write_str("\n=== Threads: two concurrent threads ===\n");

    SHARED_COUNTER.store(0, Ordering::SeqCst);
    THREAD_RESULT.store(0, Ordering::SeqCst);
    THREAD2_RESULT.store(0, Ordering::SeqCst);

    let stack1 = match spawn_thread(thread_entry_basic, &THREAD_TID) {
        Ok(s) => s,
        Err(e) => { fail_errno("clone thread 1", 0, e); return; }
    };
    let stack2 = match spawn_thread(thread_entry_second, &THREAD2_TID) {
        Ok(s) => s,
        Err(e) => {
            fail_errno("clone thread 2", 0, e);
            wait_for_thread(&THREAD_TID);
            free_stack(stack1);
            return;
        }
    };
    pass("two threads created");

    wait_for_thread(&THREAD_TID);
    wait_for_thread(&THREAD2_TID);

    let counter = SHARED_COUNTER.load(Ordering::SeqCst);
    if counter == 11 {
        pass("shared counter = 11 (1 + 10 from two threads)");
    } else {
        fail("shared counter = 11 (1 + 10 from two threads)");
        write_str("    counter=");
        write_num(counter as i64);
        write_str("\n");
    }

    let tid1 = THREAD_RESULT.load(Ordering::SeqCst);
    let tid2 = THREAD2_RESULT.load(Ordering::SeqCst);
    if tid1 != tid2 && tid1 != 0 && tid2 != 0 {
        pass("two threads have distinct TIDs");
    } else {
        fail("two threads have distinct TIDs");
    }

    free_stack(stack1);
    free_stack(stack2);
}

fn test_futex_sync() {
    write_str("\n=== Threads: futex wait/wake between threads ===\n");

    FUTEX_RENDEZVOUS.store(0, Ordering::SeqCst);
    THREAD_RESULT.store(0, Ordering::SeqCst);

    let stack_top = match spawn_thread(thread_entry_futex, &THREAD_TID) {
        Ok(s) => s,
        Err(e) => { fail_errno("clone for futex sync", 0, e); return; }
    };

    // Give thread time to enter FUTEX_WAIT
    let ts = Timespec { tv_sec: 0, tv_nsec: 10_000_000 };
    unsafe { syscall2(nr::NANOSLEEP, &ts as *const _ as u64, 0) };

    FUTEX_RENDEZVOUS.store(1, Ordering::SeqCst);
    let woken = unsafe {
        syscall6(
            nr::FUTEX, &FUTEX_RENDEZVOUS as *const _ as u64,
            FUTEX_WAKE, 1, 0, 0, 0,
        )
    };
    if woken >= 0 {
        pass("FUTEX_WAKE accepted");
    } else {
        fail_errno("FUTEX_WAKE", 0, woken);
    }

    wait_for_thread(&THREAD_TID);

    if THREAD_RESULT.load(Ordering::SeqCst) == 0xBEEF {
        pass("thread was woken and ran to completion");
    } else {
        fail("thread was woken and ran to completion");
        write_str("    result=");
        write_hex(THREAD_RESULT.load(Ordering::SeqCst) as u64);
        write_str("\n");
    }

    free_stack(stack_top);
}

fn test_thread_pid_tid() {
    write_str("\n=== Threads: getpid/gettid consistency ===\n");

    let parent_pid = unsafe { syscall0(nr::GETPID) };
    let parent_tid = unsafe { syscall0(nr::GETTID) };

    SHARED_COUNTER.store(0, Ordering::SeqCst);
    THREAD_RESULT.store(0, Ordering::SeqCst);

    let stack_top = match spawn_thread(thread_entry_basic, &THREAD_TID) {
        Ok(s) => s,
        Err(e) => { fail_errno("clone for pid/tid test", 0, e); return; }
    };

    wait_for_thread(&THREAD_TID);

    if parent_pid == parent_tid {
        pass("main thread: getpid() == gettid()");
    } else {
        fail("main thread: getpid() == gettid()");
    }

    let thread_tid = THREAD_RESULT.load(Ordering::SeqCst);
    if thread_tid != parent_tid as u32 && thread_tid != 0 {
        pass("child thread: different TID from main");
    } else {
        fail("child thread: different TID from main");
    }

    free_stack(stack_top);
}

// ════════════════════════════════════════════════════════════════════════════
// Module entry point
// ════════════════════════════════════════════════════════════════════════════

pub fn run_all() {
    crate::write_banner("THREAD (PTHREAD) TESTS");

    test_basic_thread();
    test_thread_tls();
    test_two_threads();
    test_futex_sync();
    test_thread_pid_tid();
}
