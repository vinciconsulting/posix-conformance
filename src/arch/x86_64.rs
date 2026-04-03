//! x86-64 architecture support: syscall wrappers, entry point, signal restorer,
//! clone trampoline, and TLS helpers.

use core::arch::asm;

// ════════════════════════════════════════════════════════════════════════════
// Syscall wrappers (x86-64 syscall convention)
// ════════════════════════════════════════════════════════════════════════════

#[inline(always)]
pub unsafe fn syscall0(nr: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") nr,
            out("rcx") _,
            out("r11") _,
            lateout("rax") ret,
            options(nostack)
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn syscall1(nr: u64, a1: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") nr,
            in("rdi") a1,
            out("rcx") _,
            out("r11") _,
            lateout("rax") ret,
            options(nostack)
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn syscall2(nr: u64, a1: u64, a2: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") nr,
            in("rdi") a1,
            in("rsi") a2,
            out("rcx") _,
            out("r11") _,
            lateout("rax") ret,
            options(nostack)
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn syscall3(nr: u64, a1: u64, a2: u64, a3: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") nr,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            out("rcx") _,
            out("r11") _,
            lateout("rax") ret,
            options(nostack)
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn syscall4(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") nr,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            out("rcx") _,
            out("r11") _,
            lateout("rax") ret,
            options(nostack)
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn syscall5(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") nr,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            in("r8") a5,
            out("rcx") _,
            out("r11") _,
            lateout("rax") ret,
            options(nostack)
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn syscall6(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") nr,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            in("r8") a5,
            in("r9") a6,
            out("rcx") _,
            out("r11") _,
            lateout("rax") ret,
            options(nostack)
        );
    }
    ret
}

// ════════════════════════════════════════════════════════════════════════════
// Entry point
// ════════════════════════════════════════════════════════════════════════════

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        asm!(
            "and rsp, -16",
            "call {main}",
            "ud2",
            main = sym super::super::main,
            options(noreturn)
        );
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Signal restorer (required by rt_sigaction SA_RESTORER on x86-64)
// ════════════════════════════════════════════════════════════════════════════

#[unsafe(naked)]
#[unsafe(no_mangle)]
pub extern "C" fn sig_restorer() {
    core::arch::naked_asm!(
        "mov rax, 15",  // __NR_rt_sigreturn
        "syscall",
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Clone trampoline for CLONE_THREAD
//
// After clone, the child has a new stack and the parent's Rust stack frame
// is gone. These 6 instructions dispatch the child to its entry function.
// ════════════════════════════════════════════════════════════════════════════

/// Spawn a thread via clone(CLONE_THREAD).
///
/// `entry` is called on the new stack. `tid_ptr` is used for both
/// CLONE_PARENT_SETTID and CLONE_CHILD_CLEARTID.
///
/// Returns the child TID on success, or a negative errno.
pub fn clone_thread(
    flags: u64,
    stack_top: u64,
    entry: unsafe extern "C" fn() -> !,
    tid_ptr: *const core::sync::atomic::AtomicI32,
) -> i64 {
    let ret: i64;
    unsafe {
        *((stack_top - 8) as *mut u64) = entry as u64;

        asm!(
            "syscall",
            "test rax, rax",
            "jnz 2f",
            "pop rax",
            "call rax",
            "ud2",
            "2:",
            inout("rax") super::super::nr::CLONE => ret,
            in("rdi") flags,
            in("rsi") stack_top - 8,
            in("rdx") tid_ptr as u64,
            in("r10") tid_ptr as u64,
            in("r8")  0u64,
            out("rcx") _,
            out("r11") _,
        );
    }
    ret
}

// ════════════════════════════════════════════════════════════════════════════
// TLS helpers (FS-segment relative access, x86-64 specific)
// ════════════════════════════════════════════════════════════════════════════

/// Read a u64 from fs:[offset].
#[inline(always)]
pub unsafe fn tls_read(offset: u32) -> u64 {
    let val: u64;
    unsafe {
        match offset {
            0 => asm!("mov {}, fs:[0]", out(reg) val, options(nostack, readonly)),
            8 => asm!("mov {}, fs:[8]", out(reg) val, options(nostack, readonly)),
            16 => asm!("mov {}, fs:[16]", out(reg) val, options(nostack, readonly)),
            24 => asm!("mov {}, fs:[24]", out(reg) val, options(nostack, readonly)),
            _ => { val = 0; }
        }
    }
    val
}

/// Write a u64 to fs:[offset].
#[inline(always)]
pub unsafe fn tls_write(offset: u32, val: u64) {
    unsafe {
        match offset {
            0 => asm!("mov fs:[0], {}", in(reg) val, options(nostack)),
            8 => asm!("mov fs:[8], {}", in(reg) val, options(nostack)),
            16 => asm!("mov fs:[16], {}", in(reg) val, options(nostack)),
            24 => asm!("mov fs:[24], {}", in(reg) val, options(nostack)),
            _ => {}
        }
    }
}
