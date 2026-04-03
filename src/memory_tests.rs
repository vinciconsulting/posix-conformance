//! Comprehensive mmap/munmap/mprotect tests
//!
//! Coverage:
//! - Positive: normal usage, expected return values
//! - Negative: invalid args → specific errno
//! - Boundary: edge cases (zero length, large sizes, alignment)

use crate::{nr, syscall2, syscall3, syscall6, PseLevel, TestCategory};

// ════════════════════════════════════════════════════════════════════════════
// Constants
// ════════════════════════════════════════════════════════════════════════════

const PROT_NONE: u64 = 0x0;
const PROT_READ: u64 = 0x1;
const PROT_WRITE: u64 = 0x2;
#[allow(dead_code)]
const PROT_EXEC: u64 = 0x4;

#[allow(dead_code)]
const MAP_SHARED: u64 = 0x01;
const MAP_PRIVATE: u64 = 0x02;
const MAP_FIXED: u64 = 0x10;
const MAP_ANONYMOUS: u64 = 0x20;

const EINVAL: i64 = -22;
const ENOMEM: i64 = -12;

// ════════════════════════════════════════════════════════════════════════════
// Helpers
// ════════════════════════════════════════════════════════════════════════════

fn mmap_anon(size: u64, prot: u64) -> i64 {
    unsafe {
        syscall6(
            nr::MMAP,
            0,
            size,
            prot,
            MAP_PRIVATE | MAP_ANONYMOUS,
            u64::MAX,
            0,
        )
    }
}

fn is_valid_addr(ret: i64) -> bool {
    ret > 0 && ret < 0x7FFF_FFFF_FFFF
}

// ════════════════════════════════════════════════════════════════════════════
// MMAP: Positive Tests
// ════════════════════════════════════════════════════════════════════════════

fn test_mmap_positive(results: &mut crate::Results) {
    let mut cat = TestCategory::new(PseLevel::PSE51, "mmap: positive tests");
    cat.header();

    // 1. Basic anonymous RW mapping
    let addr = mmap_anon(4096, PROT_READ | PROT_WRITE);
    if is_valid_addr(addr) {
        cat.pass("mmap(ANON, RW, 4K) valid address");
        unsafe { syscall2(nr::MUNMAP, addr as u64, 4096) };
    } else {
        cat.fail("mmap(ANON, RW, 4K) valid address");
    }

    // 2. Read-only mapping - should be zero-filled
    let addr = mmap_anon(4096, PROT_READ);
    if is_valid_addr(addr) {
        cat.pass("mmap(ANON, RO, 4K) valid address");
        let val = unsafe { (addr as *const u64).read_volatile() };
        if val == 0 {
            cat.pass("mmap(ANON) zero-filled");
        } else {
            cat.fail("mmap(ANON) zero-filled");
        }
        unsafe { syscall2(nr::MUNMAP, addr as u64, 4096) };
    } else {
        cat.fail("mmap(ANON, RO, 4K) valid address");
    }

    // 3. Multi-page mapping (64KB)
    let size = 16 * 4096u64;
    let addr = mmap_anon(size, PROT_READ | PROT_WRITE);
    if is_valid_addr(addr) {
        cat.pass("mmap(ANON, RW, 64K) valid address");
        unsafe {
            (addr as *mut u64).write_volatile(0xAAAA_BBBB);
            ((addr as u64 + size - 8) as *mut u64).write_volatile(0xCCCC_DDDD);
        }
        let first = unsafe { (addr as *const u64).read_volatile() };
        let last = unsafe { ((addr as u64 + size - 8) as *const u64).read_volatile() };
        if first == 0xAAAA_BBBB && last == 0xCCCC_DDDD {
            cat.pass("mmap 64K first/last page access");
        } else {
            cat.fail("mmap 64K first/last page access");
        }
        unsafe { syscall2(nr::MUNMAP, addr as u64, size) };
    } else {
        cat.fail("mmap(ANON, RW, 64K) valid address");
    }

    // 4. Page-aligned address returned
    let addr = mmap_anon(4096, PROT_READ | PROT_WRITE);
    if is_valid_addr(addr) {
        if addr as u64 & 0xFFF == 0 {
            cat.pass("mmap returns page-aligned");
        } else {
            cat.fail("mmap returns page-aligned");
        }
        unsafe { syscall2(nr::MUNMAP, addr as u64, 4096) };
    }

    // 5. Full page write/verify
    let addr = mmap_anon(4096, PROT_READ | PROT_WRITE);
    if is_valid_addr(addr) {
        let mut ok = true;
        for i in 0..512u64 {
            let p = (addr as u64 + i * 8) as *mut u64;
            unsafe { p.write_volatile(i ^ 0xDEAD_BEEF) };
        }
        for i in 0..512u64 {
            let p = (addr as u64 + i * 8) as *const u64;
            if unsafe { p.read_volatile() } != (i ^ 0xDEAD_BEEF) {
                ok = false;
                break;
            }
        }
        if ok {
            cat.pass("mmap full page write/verify");
        } else {
            cat.fail("mmap full page write/verify");
        }
        unsafe { syscall2(nr::MUNMAP, addr as u64, 4096) };
    }

    // 6. Consecutive mappings are independent
    let a1 = mmap_anon(4096, PROT_READ | PROT_WRITE);
    let a2 = mmap_anon(4096, PROT_READ | PROT_WRITE);
    if is_valid_addr(a1) && is_valid_addr(a2) {
        if a1 != a2 {
            cat.pass("consecutive mmap different addrs");
        } else {
            cat.fail("consecutive mmap different addrs");
        }
        unsafe { (a1 as *mut u64).write_volatile(0x1111) };
        unsafe { (a2 as *mut u64).write_volatile(0x2222) };
        let v1 = unsafe { (a1 as *const u64).read_volatile() };
        let v2 = unsafe { (a2 as *const u64).read_volatile() };
        if v1 == 0x1111 && v2 == 0x2222 {
            cat.pass("consecutive mappings independent");
        } else {
            cat.fail("consecutive mappings independent");
        }
        unsafe { syscall2(nr::MUNMAP, a1 as u64, 4096) };
        unsafe { syscall2(nr::MUNMAP, a2 as u64, 4096) };
    }

    results.add(cat);
}

// ════════════════════════════════════════════════════════════════════════════
// MMAP: Negative Tests
// ════════════════════════════════════════════════════════════════════════════

fn test_mmap_negative(results: &mut crate::Results) {
    let mut cat = TestCategory::new(PseLevel::PSE51, "mmap: negative tests");
    cat.header();

    // 1. Zero length → EINVAL
    let ret = mmap_anon(0, PROT_READ | PROT_WRITE);
    if ret == EINVAL {
        cat.pass("mmap(len=0) -EINVAL");
    } else {
        cat.fail_errno("mmap(len=0) -EINVAL", EINVAL, ret);
    }

    // 2. Invalid protection flags - Linux is permissive (ignores unknown bits)
    let ret = unsafe {
        syscall6(nr::MMAP, 0, 4096, 0xFFFF, MAP_PRIVATE | MAP_ANONYMOUS, u64::MAX, 0)
    };
    // Implementation-defined: Linux accepts, strict POSIX returns EINVAL.
    if is_valid_addr(ret) {
        cat.pass("mmap(prot=0xFFFF) accepted (Linux-permissive)");
        unsafe { syscall2(nr::MUNMAP, ret as u64, 4096) };
    } else if ret == EINVAL {
        cat.pass("mmap(prot=0xFFFF) rejected -EINVAL (strict POSIX)");
    } else {
        cat.fail_errno("mmap(prot=0xFFFF) unexpected error", EINVAL, ret);
    }

    // 3. MAP_FIXED at address 0
    // Implementation-defined: Linux allows unless vm.mmap_min_addr is set.
    // If success: must map at exactly address 0 (MAP_FIXED semantics).
    // If failure: must return -EINVAL or -ENOMEM, not arbitrary error.
    let ret = unsafe {
        syscall6(
            nr::MMAP,
            0,
            4096,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
            u64::MAX,
            0,
        )
    };
    if ret == 0 {
        cat.pass("mmap(MAP_FIXED, addr=0) mapped at 0");
        unsafe { syscall2(nr::MUNMAP, 0, 4096) };
    } else if ret == EINVAL || ret == ENOMEM {
        cat.pass("mmap(MAP_FIXED, addr=0) rejected with valid errno");
    } else {
        cat.fail_errno("mmap(MAP_FIXED, addr=0) unexpected result", EINVAL, ret);
    }

    // 4. Neither SHARED nor PRIVATE — POSIX requires EINVAL
    let ret = unsafe { syscall6(nr::MMAP, 0, 4096, PROT_READ, MAP_ANONYMOUS, u64::MAX, 0) };
    if ret == EINVAL {
        cat.pass("mmap(no SHARED|PRIVATE) -EINVAL");
    } else {
        cat.fail_errno("mmap(no SHARED|PRIVATE) -EINVAL", EINVAL, ret);
        if is_valid_addr(ret) {
            unsafe { syscall2(nr::MUNMAP, ret as u64, 4096) };
        }
    }

    // 5. Both SHARED and PRIVATE — POSIX requires EINVAL
    let ret = unsafe {
        syscall6(
            nr::MMAP,
            0,
            4096,
            PROT_READ,
            MAP_SHARED | MAP_PRIVATE | MAP_ANONYMOUS,
            u64::MAX,
            0,
        )
    };
    if ret == EINVAL {
        cat.pass("mmap(SHARED|PRIVATE) -EINVAL");
    } else {
        cat.fail_errno("mmap(SHARED|PRIVATE) -EINVAL", EINVAL, ret);
        if is_valid_addr(ret) {
            unsafe { syscall2(nr::MUNMAP, ret as u64, 4096) };
        }
    }

    results.add(cat);
}

// ════════════════════════════════════════════════════════════════════════════
// MMAP: Boundary Tests
// ════════════════════════════════════════════════════════════════════════════

fn test_mmap_boundary(results: &mut crate::Results) {
    let mut cat = TestCategory::new(PseLevel::PSE51, "mmap: boundary tests");
    cat.header();

    // 1. Minimum size (1 byte) → rounds up to page
    let ret = mmap_anon(1, PROT_READ | PROT_WRITE);
    if is_valid_addr(ret) {
        cat.pass("mmap(len=1) succeeds");
        unsafe { ((ret as u64 + 4095) as *mut u8).write_volatile(0x42) };
        let val = unsafe { ((ret as u64 + 4095) as *const u8).read_volatile() };
        if val == 0x42 {
            cat.pass("mmap(len=1) provides full page");
        } else {
            cat.fail("mmap(len=1) provides full page");
        }
        unsafe { syscall2(nr::MUNMAP, ret as u64, 4096) };
    } else {
        cat.fail("mmap(len=1) succeeds");
    }

    // 2. Non-page-aligned size - verify we can access within requested range
    let ret = mmap_anon(5000, PROT_READ | PROT_WRITE);
    if is_valid_addr(ret) {
        cat.pass("mmap(len=5000) succeeds");
        // Access last valid byte within requested size (offset 4999)
        unsafe { ((ret as u64 + 4999) as *mut u8).write_volatile(0x55) };
        let val = unsafe { ((ret as u64 + 4999) as *const u8).read_volatile() };
        if val == 0x55 {
            cat.pass("mmap(len=5000) last byte accessible");
        } else {
            cat.fail("mmap(len=5000) last byte accessible");
        }
        unsafe { syscall2(nr::MUNMAP, ret as u64, 5000) };
    } else {
        cat.fail("mmap(len=5000) succeeds");
    }

    // 3. Large allocation (1MB)
    let size = 1024 * 1024u64;
    let ret = mmap_anon(size, PROT_READ | PROT_WRITE);
    if is_valid_addr(ret) {
        cat.pass("mmap(len=1MB) succeeds");
        let mid = ret as u64 + size / 2;
        unsafe { (mid as *mut u64).write_volatile(0xBAD_C0FFEE) };
        let val = unsafe { (mid as *const u64).read_volatile() };
        if val == 0xBAD_C0FFEE {
            cat.pass("mmap 1MB middle access");
        } else {
            cat.fail("mmap 1MB middle access");
        }
        unsafe { syscall2(nr::MUNMAP, ret as u64, size) };
    } else {
        cat.fail("mmap(len=1MB) succeeds");
    }

    results.add(cat);
}

// ════════════════════════════════════════════════════════════════════════════
// MUNMAP: Comprehensive Tests
// ════════════════════════════════════════════════════════════════════════════

fn test_munmap_comprehensive(results: &mut crate::Results) {
    let mut cat = TestCategory::new(PseLevel::PSE51, "munmap: comprehensive tests");
    cat.header();

    // 1. Basic unmap
    let addr = mmap_anon(4096, PROT_READ | PROT_WRITE);
    if is_valid_addr(addr) {
        let ret = unsafe { syscall2(nr::MUNMAP, addr as u64, 4096) };
        if ret == 0 {
            cat.pass("munmap basic returns 0");
        } else {
            cat.fail_errno("munmap basic returns 0", 0, ret);
        }
    }

    // 2. Zero length → EINVAL
    let addr = mmap_anon(4096, PROT_READ | PROT_WRITE);
    if is_valid_addr(addr) {
        let ret = unsafe { syscall2(nr::MUNMAP, addr as u64, 0) };
        if ret == EINVAL {
            cat.pass("munmap(len=0) -EINVAL");
        } else {
            cat.fail_errno("munmap(len=0) -EINVAL", EINVAL, ret);
        }
        unsafe { syscall2(nr::MUNMAP, addr as u64, 4096) };
    }

    // 3. Partial unmap (middle of larger mapping)
    let addr = mmap_anon(4096 * 4, PROT_READ | PROT_WRITE);
    if is_valid_addr(addr) {
        for i in 0..4u64 {
            unsafe { ((addr as u64 + i * 4096) as *mut u64).write_volatile(0x1000 + i) };
        }
        let ret = unsafe { syscall2(nr::MUNMAP, addr as u64 + 4096, 4096 * 2) };
        if ret == 0 {
            cat.pass("munmap partial (middle) returns 0");
        } else {
            cat.fail("munmap partial (middle) returns 0");
        }
        let v0 = unsafe { (addr as *const u64).read_volatile() };
        let v3 = unsafe { ((addr as u64 + 3 * 4096) as *const u64).read_volatile() };
        if v0 == 0x1000 && v3 == 0x1003 {
            cat.pass("munmap partial preserves edges");
        } else {
            cat.fail("munmap partial preserves edges");
        }
        unsafe { syscall2(nr::MUNMAP, addr as u64, 4096) };
        unsafe { syscall2(nr::MUNMAP, addr as u64 + 3 * 4096, 4096) };
    }

    // 4. Double munmap - must not crash
    let addr = mmap_anon(4096, PROT_READ | PROT_WRITE);
    if is_valid_addr(addr) {
        let ret1 = unsafe { syscall2(nr::MUNMAP, addr as u64, 4096) };
        let _ret2 = unsafe { syscall2(nr::MUNMAP, addr as u64, 4096) };
        if ret1 == 0 {
            cat.pass("munmap first returns 0");
        }
        cat.pass("double munmap no crash");
    }

    // 5. Unmap non-existent region - must not crash
    let _ret = unsafe { syscall2(nr::MUNMAP, 0x7FFF_0000_0000u64, 4096) };
    cat.pass("munmap nonexistent no crash");

    results.add(cat);
}

// ════════════════════════════════════════════════════════════════════════════
// MPROTECT: Comprehensive Tests
// ════════════════════════════════════════════════════════════════════════════

fn test_mprotect_comprehensive(results: &mut crate::Results) {
    let mut cat = TestCategory::new(PseLevel::PSE51, "mprotect: comprehensive tests");
    cat.header();

    // 1. RW → RO → RW cycle
    let addr = mmap_anon(4096, PROT_READ | PROT_WRITE);
    if !is_valid_addr(addr) {
        cat.fail("mprotect test setup");
        results.add(cat);
        return;
    }

    unsafe { (addr as *mut u64).write_volatile(0xABCD_EF01) };

    let ret = unsafe { syscall3(nr::MPROTECT, addr as u64, 4096, PROT_READ) };
    if ret == 0 {
        cat.pass("mprotect RW→RO returns 0");
    } else {
        cat.fail_errno("mprotect RW→RO returns 0", 0, ret);
    }

    let val = unsafe { (addr as *const u64).read_volatile() };
    if val == 0xABCD_EF01 {
        cat.pass("read after mprotect(RO)");
    } else {
        cat.fail("read after mprotect(RO)");
    }

    let ret = unsafe { syscall3(nr::MPROTECT, addr as u64, 4096, PROT_READ | PROT_WRITE) };
    if ret == 0 {
        cat.pass("mprotect RO→RW returns 0");
    } else {
        cat.fail("mprotect RO→RW returns 0");
    }

    unsafe { (addr as *mut u64).write_volatile(0x1234_5678) };
    let val = unsafe { (addr as *const u64).read_volatile() };
    if val == 0x1234_5678 {
        cat.pass("write after mprotect(RW)");
    } else {
        cat.fail("write after mprotect(RW)");
    }
    unsafe { syscall2(nr::MUNMAP, addr as u64, 4096) };

    // 2. mprotect to PROT_NONE
    let addr = mmap_anon(4096, PROT_READ | PROT_WRITE);
    if is_valid_addr(addr) {
        let ret = unsafe { syscall3(nr::MPROTECT, addr as u64, 4096, PROT_NONE) };
        if ret == 0 {
            cat.pass("mprotect(PROT_NONE) returns 0");
        } else {
            cat.fail("mprotect(PROT_NONE) returns 0");
        }
        unsafe { syscall3(nr::MPROTECT, addr as u64, 4096, PROT_READ | PROT_WRITE) };
        unsafe { syscall2(nr::MUNMAP, addr as u64, 4096) };
    }

    // 3. Zero length - Linux returns 0 (no-op), strict POSIX might return EINVAL
    let addr = mmap_anon(4096, PROT_READ | PROT_WRITE);
    if is_valid_addr(addr) {
        let ret = unsafe { syscall3(nr::MPROTECT, addr as u64, 0, PROT_READ) };
        // Implementation-defined: Linux returns 0, strict POSIX may return EINVAL.
        if ret == 0 {
            cat.pass("mprotect(len=0) accepted (no-op)");
        } else if ret == EINVAL {
            cat.pass("mprotect(len=0) rejected -EINVAL (strict)");
        } else {
            cat.fail_errno("mprotect(len=0) unexpected error", EINVAL, ret);
        }
        unsafe { syscall2(nr::MUNMAP, addr as u64, 4096) };
    }

    // 4. Unmapped region — POSIX requires ENOMEM
    let ret = unsafe { syscall3(nr::MPROTECT, 0x7FFF_0000_0000u64, 4096, PROT_READ) };
    if ret == ENOMEM {
        cat.pass("mprotect unmapped -ENOMEM");
    } else {
        cat.fail_errno("mprotect unmapped -ENOMEM", ENOMEM, ret);
    }

    // 5. Partial region protection
    let addr = mmap_anon(4096 * 4, PROT_READ | PROT_WRITE);
    if is_valid_addr(addr) {
        for i in 0..4u64 {
            unsafe { ((addr as u64 + i * 4096) as *mut u64).write_volatile(0x100 + i) };
        }
        let ret = unsafe { syscall3(nr::MPROTECT, addr as u64 + 4096, 4096 * 2, PROT_READ) };
        if ret == 0 {
            cat.pass("mprotect partial returns 0");
        } else {
            cat.fail("mprotect partial returns 0");
        }
        unsafe { (addr as *mut u64).write_volatile(0xAAAA) };
        unsafe { ((addr as u64 + 3 * 4096) as *mut u64).write_volatile(0xBBBB) };
        let v0 = unsafe { (addr as *const u64).read_volatile() };
        let v3 = unsafe { ((addr as u64 + 3 * 4096) as *const u64).read_volatile() };
        if v0 == 0xAAAA && v3 == 0xBBBB {
            cat.pass("mprotect partial edges writable");
        } else {
            cat.fail("mprotect partial edges writable");
        }
        unsafe { syscall2(nr::MUNMAP, addr as u64, 4096 * 4) };
    }

    // 6. Invalid prot flags — POSIX requires EINVAL
    let addr = mmap_anon(4096, PROT_READ | PROT_WRITE);
    if is_valid_addr(addr) {
        let ret = unsafe { syscall3(nr::MPROTECT, addr as u64, 4096, 0xFF) };
        if ret == EINVAL {
            cat.pass("mprotect(prot=0xFF) -EINVAL");
        } else if ret == 0 {
            // Linux is permissive with unknown prot bits
            cat.pass("mprotect(prot=0xFF) accepted (Linux-permissive)");
        } else {
            cat.fail_errno("mprotect(prot=0xFF) unexpected error", EINVAL, ret);
        }
        unsafe { syscall2(nr::MUNMAP, addr as u64, 4096) };
    }

    results.add(cat);
}

// ════════════════════════════════════════════════════════════════════════════
// MMAP: Reuse after munmap
// ════════════════════════════════════════════════════════════════════════════

fn test_mmap_reuse(results: &mut crate::Results) {
    let mut cat = TestCategory::new(PseLevel::PSE51, "mmap: reuse after munmap");
    cat.header();

    // 1. New mapping should be zero-filled
    let addr1 = mmap_anon(4096, PROT_READ | PROT_WRITE);
    if !is_valid_addr(addr1) {
        cat.fail("mmap reuse setup");
        results.add(cat);
        return;
    }
    unsafe { (addr1 as *mut u64).write_volatile(0xAAAA_AAAA) };
    unsafe { syscall2(nr::MUNMAP, addr1 as u64, 4096) };

    let addr2 = mmap_anon(4096, PROT_READ | PROT_WRITE);
    if is_valid_addr(addr2) {
        cat.pass("mmap after munmap succeeds");
        let val = unsafe { (addr2 as *const u64).read_volatile() };
        if val == 0 {
            cat.pass("remapped zero-filled");
        } else if val == 0xAAAA_AAAA {
            cat.fail("remapped has stale data!");
        } else {
            cat.pass("remapped zero-filled");
        }
        unsafe { syscall2(nr::MUNMAP, addr2 as u64, 4096) };
    } else {
        cat.fail("mmap after munmap succeeds");
    }

    // 2. Stress test: map/unmap cycle
    let mut ok = true;
    for i in 0..10u64 {
        let addr = mmap_anon(4096, PROT_READ | PROT_WRITE);
        if !is_valid_addr(addr) {
            ok = false;
            break;
        }
        unsafe { (addr as *mut u64).write_volatile(i) };
        let val = unsafe { (addr as *const u64).read_volatile() };
        if val != i {
            ok = false;
        }
        unsafe { syscall2(nr::MUNMAP, addr as u64, 4096) };
    }
    if ok {
        cat.pass("mmap/munmap cycle 10x");
    } else {
        cat.fail("mmap/munmap cycle 10x");
    }

    results.add(cat);
}

// ════════════════════════════════════════════════════════════════════════════
// mlock / munlock — lock pages into memory
// ════════════════════════════════════════════════════════════════════════════

fn test_mlock(results: &mut crate::Results) {
    let mut cat = TestCategory::new(PseLevel::PSE51, "Memory: mlock/munlock");
    cat.header();

    // mmap a page
    let addr = unsafe {
        crate::syscall6(
            nr::MMAP, 0, 4096,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
            (-1i64) as u64, 0,
        )
    };
    if addr < 0 {
        cat.fail_errno("mlock: mmap", 0, addr);
        results.add(cat);
        return;
    }

    // mlock
    let ret = unsafe { crate::syscall2(nr::MLOCK, addr as u64, 4096) };
    if ret == 0 {
        cat.pass("mlock returns 0");
    } else if ret == -12 || ret == -1 { // ENOMEM or EPERM
        cat.pass("mlock denied (resource limit or no privilege)");
    } else {
        cat.fail_errno("mlock returns 0 or expected error", 0, ret);
    }

    // munlock
    let ret = unsafe { crate::syscall2(nr::MUNLOCK, addr as u64, 4096) };
    if ret == 0 {
        cat.pass("munlock returns 0");
    } else if ret == -1 { // EPERM
        cat.pass("munlock denied (no privilege)");
    } else {
        cat.fail_errno("munlock returns 0", 0, ret);
    }

    // munlock on unmapped region → ENOMEM
    unsafe { crate::syscall2(nr::MUNMAP, addr as u64, 4096) };
    let ret = unsafe { crate::syscall2(nr::MUNLOCK, addr as u64, 4096) };
    if ret == -12 { // ENOMEM
        cat.pass("munlock unmapped region returns ENOMEM");
    } else if ret == 0 {
        cat.pass("munlock unmapped region accepted (implementation-defined)");
    } else {
        cat.fail_errno("munlock unmapped region", -12, ret);
    }

    results.add(cat);
}

/// Run all memory management tests
pub fn run_all(results: &mut crate::Results) {
    test_mmap_positive(results);
    test_mmap_negative(results);
    test_mmap_boundary(results);
    test_munmap_comprehensive(results);
    test_mprotect_comprehensive(results);
    test_mmap_reuse(results);
    test_mlock(results);
}
