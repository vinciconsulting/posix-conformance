//! Comprehensive pipe/read/write tests
//!
//! Coverage:
//! - Positive: normal pipe operations, vectored I/O
//! - Negative: invalid fds, closed pipes, bad buffers
//! - Boundary: zero-length, large transfers, pipe capacity

use crate::{fail, fail_errno, nr, pass, syscall1, syscall2, syscall3, write_str, Iovec};

// Error codes
const EBADF: i64 = -9;

// ════════════════════════════════════════════════════════════════════════════
// PIPE2: Positive Tests
// ════════════════════════════════════════════════════════════════════════════

fn test_pipe_positive() {
    write_str("\n=== pipe2: positive tests ===\n");

    // 1. Basic pipe creation
    let mut fds = [0i32; 2];
    let ret = unsafe { syscall2(nr::PIPE2, fds.as_mut_ptr() as u64, 0) };
    if ret == 0 {
        pass("pipe2() returns 0");
        if fds[0] >= 3 && fds[1] >= 3 && fds[0] != fds[1] {
            pass("pipe2 fds are valid and distinct");
        } else {
            fail("pipe2 fds are valid and distinct");
        }
        unsafe {
            syscall1(nr::CLOSE, fds[0] as u64);
            syscall1(nr::CLOSE, fds[1] as u64);
        }
    } else {
        fail_errno("pipe2() returns 0", 0, ret);
    }

    // 2. O_CLOEXEC flag
    let mut fds = [0i32; 2];
    const O_CLOEXEC: u64 = 0x80000;
    let ret = unsafe { syscall2(nr::PIPE2, fds.as_mut_ptr() as u64, O_CLOEXEC) };
    if ret == 0 {
        pass("pipe2(O_CLOEXEC) returns 0");
        unsafe {
            syscall1(nr::CLOSE, fds[0] as u64);
            syscall1(nr::CLOSE, fds[1] as u64);
        }
    } else {
        fail("pipe2(O_CLOEXEC) returns 0");
    }

    // 3. O_NONBLOCK flag
    let mut fds = [0i32; 2];
    const O_NONBLOCK: u64 = 0x800;
    let ret = unsafe { syscall2(nr::PIPE2, fds.as_mut_ptr() as u64, O_NONBLOCK) };
    if ret == 0 {
        pass("pipe2(O_NONBLOCK) returns 0");
        // Read from empty non-blocking pipe should return -EAGAIN
        let mut buf = [0u8; 1];
        let ret = unsafe { syscall3(nr::READ, fds[0] as u64, buf.as_mut_ptr() as u64, 1) };
        if ret == -11 {
            // -EAGAIN
            pass("read(nonblock empty) -EAGAIN");
        } else {
            fail_errno("read(nonblock empty) -EAGAIN", -11, ret);
        }
        unsafe {
            syscall1(nr::CLOSE, fds[0] as u64);
            syscall1(nr::CLOSE, fds[1] as u64);
        }
    } else {
        fail("pipe2(O_NONBLOCK) returns 0");
    }
}

// ════════════════════════════════════════════════════════════════════════════
// READ/WRITE: Positive Tests
// ════════════════════════════════════════════════════════════════════════════

fn test_rw_positive() {
    write_str("\n=== read/write: positive tests ===\n");

    let mut fds = [0i32; 2];
    if unsafe { syscall2(nr::PIPE2, fds.as_mut_ptr() as u64, 0) } != 0 {
        fail("rw positive: pipe setup");
        return;
    }
    let rd = fds[0];
    let wr = fds[1];

    // 1. Single byte write/read
    let data = [0x42u8];
    let ret = unsafe { syscall3(nr::WRITE, wr as u64, data.as_ptr() as u64, 1) };
    if ret == 1 {
        pass("write(1 byte) returns 1");
    } else {
        fail_errno("write(1 byte) returns 1", 1, ret);
    }

    let mut buf = [0u8; 1];
    let ret = unsafe { syscall3(nr::READ, rd as u64, buf.as_mut_ptr() as u64, 1) };
    if ret == 1 && buf[0] == 0x42 {
        pass("read(1 byte) returns 1, correct data");
    } else {
        fail("read(1 byte) returns 1, correct data");
    }

    // 2. Multi-byte write/read
    let data: [u8; 64] = core::array::from_fn(|i| i as u8);
    let ret = unsafe { syscall3(nr::WRITE, wr as u64, data.as_ptr() as u64, 64) };
    if ret == 64 {
        pass("write(64 bytes) returns 64");
    } else {
        fail_errno("write(64 bytes) returns 64", 64, ret);
    }

    let mut buf = [0u8; 64];
    let ret = unsafe { syscall3(nr::READ, rd as u64, buf.as_mut_ptr() as u64, 64) };
    if ret == 64 {
        pass("read(64 bytes) returns 64");
        let ok = buf.iter().enumerate().all(|(i, &b)| b == i as u8);
        if ok {
            pass("read data matches write");
        } else {
            fail("read data matches write");
        }
    } else {
        fail_errno("read(64 bytes) returns 64", 64, ret);
    }

    // 3. Partial read (request more than available)
    let data = [1u8, 2, 3, 4];
    unsafe { syscall3(nr::WRITE, wr as u64, data.as_ptr() as u64, 4) };
    let mut buf = [0u8; 100];
    let ret = unsafe { syscall3(nr::READ, rd as u64, buf.as_mut_ptr() as u64, 100) };
    if ret == 4 {
        pass("read(partial) returns available");
    } else {
        fail_errno("read(partial) returns available", 4, ret);
    }

    // 4. Multiple writes, single read
    for i in 0..4u8 {
        let b = [i];
        unsafe { syscall3(nr::WRITE, wr as u64, b.as_ptr() as u64, 1) };
    }
    let mut buf = [0u8; 4];
    let ret = unsafe { syscall3(nr::READ, rd as u64, buf.as_mut_ptr() as u64, 4) };
    if ret == 4 && buf == [0, 1, 2, 3] {
        pass("multiple writes, single read");
    } else {
        fail("multiple writes, single read");
    }

    unsafe {
        syscall1(nr::CLOSE, rd as u64);
        syscall1(nr::CLOSE, wr as u64);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// READ/WRITE: Negative Tests
// ════════════════════════════════════════════════════════════════════════════

fn test_rw_negative() {
    write_str("\n=== read/write: negative tests ===\n");

    // 1. Read from invalid fd
    let mut buf = [0u8; 1];
    let ret = unsafe { syscall3(nr::READ, 999, buf.as_mut_ptr() as u64, 1) };
    if ret == EBADF {
        pass("read(bad fd) -EBADF");
    } else {
        fail_errno("read(bad fd) -EBADF", EBADF, ret);
    }

    // 2. Write to invalid fd
    let data = [0u8];
    let ret = unsafe { syscall3(nr::WRITE, 999, data.as_ptr() as u64, 1) };
    if ret == EBADF {
        pass("write(bad fd) -EBADF");
    } else {
        fail_errno("write(bad fd) -EBADF", EBADF, ret);
    }

    // 3. Read from write-only fd (pipe write end)
    let mut fds = [0i32; 2];
    if unsafe { syscall2(nr::PIPE2, fds.as_mut_ptr() as u64, 0) } == 0 {
        let ret = unsafe { syscall3(nr::READ, fds[1] as u64, buf.as_mut_ptr() as u64, 1) };
        if ret == EBADF {
            pass("read(write-end) -EBADF");
        } else {
            fail_errno("read(write-end) -EBADF", EBADF, ret);
        }

        // 4. Write to read-only fd (pipe read end)
        let ret = unsafe { syscall3(nr::WRITE, fds[0] as u64, data.as_ptr() as u64, 1) };
        if ret == EBADF {
            pass("write(read-end) -EBADF");
        } else {
            fail_errno("write(read-end) -EBADF", EBADF, ret);
        }

        unsafe {
            syscall1(nr::CLOSE, fds[0] as u64);
            syscall1(nr::CLOSE, fds[1] as u64);
        }
    }

    // 5. Read from closed pipe
    let mut fds = [0i32; 2];
    if unsafe { syscall2(nr::PIPE2, fds.as_mut_ptr() as u64, 0) } == 0 {
        unsafe { syscall1(nr::CLOSE, fds[1] as u64) }; // Close write end
        let ret = unsafe { syscall3(nr::READ, fds[0] as u64, buf.as_mut_ptr() as u64, 1) };
        // Should return 0 (EOF) since write end closed
        if ret == 0 {
            pass("read(closed write end) EOF");
        } else {
            fail_errno("read(closed write end) EOF", 0, ret);
        }
        unsafe { syscall1(nr::CLOSE, fds[0] as u64) };
    }
}

// ════════════════════════════════════════════════════════════════════════════
// READ/WRITE: Boundary Tests
// ════════════════════════════════════════════════════════════════════════════

fn test_rw_boundary() {
    write_str("\n=== read/write: boundary tests ===\n");

    let mut fds = [0i32; 2];
    if unsafe { syscall2(nr::PIPE2, fds.as_mut_ptr() as u64, 0) } != 0 {
        fail("boundary: pipe setup");
        return;
    }
    let rd = fds[0];
    let wr = fds[1];

    // 1. Zero-length write returns 0
    let data = [0u8];
    let ret = unsafe { syscall3(nr::WRITE, wr as u64, data.as_ptr() as u64, 0) };
    if ret == 0 {
        pass("write(len=0) returns 0");
    } else {
        fail_errno("write(len=0) returns 0", 0, ret);
    }

    // 2. Zero-length read returns 0
    let mut buf = [0u8];
    let ret = unsafe { syscall3(nr::READ, rd as u64, buf.as_mut_ptr() as u64, 0) };
    if ret == 0 {
        pass("read(len=0) returns 0");
    } else {
        fail_errno("read(len=0) returns 0", 0, ret);
    }

    // 3. Large write (4KB)
    let data = [0xABu8; 4096];
    let ret = unsafe { syscall3(nr::WRITE, wr as u64, data.as_ptr() as u64, 4096) };
    if ret == 4096 {
        pass("write(4KB) returns 4096");
    } else if ret > 0 {
        pass("write(4KB) partial");
    } else {
        fail_errno("write(4KB) returns 4096", 4096, ret);
    }

    // 4. Read all written data
    let mut buf = [0u8; 4096];
    let mut total = 0i64;
    while total < ret {
        let n = unsafe {
            syscall3(
                nr::READ,
                rd as u64,
                buf.as_mut_ptr().add(total as usize) as u64,
                (ret - total) as u64,
            )
        };
        if n <= 0 {
            break;
        }
        total += n;
    }
    if total == ret {
        pass("read all written data");
    } else {
        fail("read all written data");
    }

    unsafe {
        syscall1(nr::CLOSE, rd as u64);
        syscall1(nr::CLOSE, wr as u64);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// VECTORED I/O: writev/readv
// ════════════════════════════════════════════════════════════════════════════

fn test_vectored_io() {
    write_str("\n=== writev/readv: comprehensive ===\n");

    let mut fds = [0i32; 2];
    if unsafe { syscall2(nr::PIPE2, fds.as_mut_ptr() as u64, 0) } != 0 {
        fail("vectored: pipe setup");
        return;
    }
    let rd = fds[0];
    let wr = fds[1];

    // 1. writev with multiple segments
    let buf1 = b"AAAA";
    let buf2 = b"BBBB";
    let buf3 = b"CCCC";
    let iov = [
        Iovec {
            iov_base: buf1.as_ptr() as u64,
            iov_len: 4,
        },
        Iovec {
            iov_base: buf2.as_ptr() as u64,
            iov_len: 4,
        },
        Iovec {
            iov_base: buf3.as_ptr() as u64,
            iov_len: 4,
        },
    ];
    let ret = unsafe { syscall3(nr::WRITEV, wr as u64, iov.as_ptr() as u64, 3) };
    if ret == 12 {
        pass("writev(3 segments) returns 12");
    } else {
        fail_errno("writev(3 segments) returns 12", 12, ret);
    }

    // 2. readv with multiple segments
    let mut rbuf1 = [0u8; 4];
    let mut rbuf2 = [0u8; 4];
    let mut rbuf3 = [0u8; 4];
    let iov = [
        Iovec {
            iov_base: rbuf1.as_mut_ptr() as u64,
            iov_len: 4,
        },
        Iovec {
            iov_base: rbuf2.as_mut_ptr() as u64,
            iov_len: 4,
        },
        Iovec {
            iov_base: rbuf3.as_mut_ptr() as u64,
            iov_len: 4,
        },
    ];
    let ret = unsafe { syscall3(nr::READV, rd as u64, iov.as_ptr() as u64, 3) };
    if ret == 12 {
        pass("readv(3 segments) returns 12");
        if &rbuf1 == b"AAAA" && &rbuf2 == b"BBBB" && &rbuf3 == b"CCCC" {
            pass("readv data correct");
        } else {
            fail("readv data correct");
        }
    } else {
        fail_errno("readv(3 segments) returns 12", 12, ret);
    }

    // 3. writev with zero-length segment
    let buf1 = b"XX";
    let buf2: [u8; 0] = [];
    let buf3 = b"YY";
    let iov = [
        Iovec {
            iov_base: buf1.as_ptr() as u64,
            iov_len: 2,
        },
        Iovec {
            iov_base: buf2.as_ptr() as u64,
            iov_len: 0,
        },
        Iovec {
            iov_base: buf3.as_ptr() as u64,
            iov_len: 2,
        },
    ];
    let ret = unsafe { syscall3(nr::WRITEV, wr as u64, iov.as_ptr() as u64, 3) };
    if ret == 4 {
        pass("writev with empty segment");
    } else {
        fail_errno("writev with empty segment", 4, ret);
    }

    // Read the data
    let mut buf = [0u8; 4];
    unsafe { syscall3(nr::READ, rd as u64, buf.as_mut_ptr() as u64, 4) };
    if &buf == b"XXYY" {
        pass("writev empty segment skipped");
    } else {
        fail("writev empty segment skipped");
    }

    // 4. writev/readv with iovcnt=0
    let ret = unsafe { syscall3(nr::WRITEV, wr as u64, 0, 0) };
    if ret == 0 {
        pass("writev(iovcnt=0) returns 0");
    } else {
        fail_errno("writev(iovcnt=0) returns 0", 0, ret);
    }

    let ret = unsafe { syscall3(nr::READV, rd as u64, 0, 0) };
    if ret == 0 {
        pass("readv(iovcnt=0) returns 0");
    } else {
        fail_errno("readv(iovcnt=0) returns 0", 0, ret);
    }

    // 5. writev/readv with bad fd
    let iov = [Iovec {
        iov_base: buf1.as_ptr() as u64,
        iov_len: 2,
    }];
    let ret = unsafe { syscall3(nr::WRITEV, 999, iov.as_ptr() as u64, 1) };
    if ret == EBADF {
        pass("writev(bad fd) -EBADF");
    } else {
        fail_errno("writev(bad fd) -EBADF", EBADF, ret);
    }

    let ret = unsafe { syscall3(nr::READV, 999, iov.as_ptr() as u64, 1) };
    if ret == EBADF {
        pass("readv(bad fd) -EBADF");
    } else {
        fail_errno("readv(bad fd) -EBADF", EBADF, ret);
    }

    unsafe {
        syscall1(nr::CLOSE, rd as u64);
        syscall1(nr::CLOSE, wr as u64);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// PIPE: Stress Tests
// ════════════════════════════════════════════════════════════════════════════

fn test_pipe_stress() {
    write_str("\n=== pipe: stress tests ===\n");

    // 1. Many small writes and reads
    let mut fds = [0i32; 2];
    if unsafe { syscall2(nr::PIPE2, fds.as_mut_ptr() as u64, 0) } != 0 {
        fail("stress: pipe setup");
        return;
    }
    let rd = fds[0];
    let wr = fds[1];

    let mut ok = true;
    for i in 0..100u8 {
        let data = [i];
        let ret = unsafe { syscall3(nr::WRITE, wr as u64, data.as_ptr() as u64, 1) };
        if ret != 1 {
            ok = false;
            break;
        }
    }
    if ok {
        pass("100 writes succeed");
    } else {
        fail("100 writes succeed");
    }

    ok = true;
    for i in 0..100u8 {
        let mut buf = [0u8];
        let ret = unsafe { syscall3(nr::READ, rd as u64, buf.as_mut_ptr() as u64, 1) };
        if ret != 1 || buf[0] != i {
            ok = false;
            break;
        }
    }
    if ok {
        pass("100 reads correct");
    } else {
        fail("100 reads correct");
    }

    unsafe {
        syscall1(nr::CLOSE, rd as u64);
        syscall1(nr::CLOSE, wr as u64);
    }

    // 2. Create many pipes
    ok = true;
    let mut pipes: [[i32; 2]; 10] = [[0; 2]; 10];
    for pipe in &mut pipes {
        let ret = unsafe { syscall2(nr::PIPE2, pipe.as_mut_ptr() as u64, 0) };
        if ret != 0 {
            ok = false;
            break;
        }
    }
    if ok {
        pass("create 10 pipes");
    } else {
        fail("create 10 pipes");
    }

    // Close all
    for pipe in &pipes {
        if pipe[0] != 0 {
            unsafe {
                syscall1(nr::CLOSE, pipe[0] as u64);
                syscall1(nr::CLOSE, pipe[1] as u64);
            }
        }
    }
}

/// Run all pipe tests
pub fn run_all() {
    test_pipe_positive();
    test_rw_positive();
    test_rw_negative();
    test_rw_boundary();
    test_vectored_io();
    test_pipe_stress();
}
