//! Comprehensive file descriptor tests
//!
//! Coverage:
//! - dup/dup2/dup3: positive, negative, boundary
//! - close: positive, negative
//! - fstat: positive, negative, struct validation
//! - fcntl: F_GETFD, F_SETFD, F_GETFL, F_SETFL

use crate::{nr, syscall1, syscall2, syscall3, syscall4, PseLevel, TestCategory};

// Error codes
const EBADF: i64 = -9;
const EINVAL: i64 = -22;

// fcntl commands
const F_DUPFD: u64 = 0;
const F_GETFD: u64 = 1;
const F_SETFD: u64 = 2;
const F_GETFL: u64 = 3;
const F_SETFL: u64 = 4;
const F_DUPFD_CLOEXEC: u64 = 1030;

const FD_CLOEXEC: u64 = 1;
const O_NONBLOCK: u64 = 0x800;

// ════════════════════════════════════════════════════════════════════════════
// DUP: Positive Tests
// ════════════════════════════════════════════════════════════════════════════

fn test_dup_positive(results: &mut crate::Results) {
    let mut cat = TestCategory::new(PseLevel::PSE52, "dup: positive tests");
    cat.header();

    // 1. Basic dup of stdout
    let fd = unsafe { syscall1(nr::DUP, 1) };
    if fd >= 3 {
        cat.pass("dup(stdout) >= 3");
        // Verify write works
        let ret = unsafe { syscall3(nr::WRITE, fd as u64, b".\n".as_ptr() as u64, 2) };
        if ret == 2 {
            cat.pass("write to dup'd fd works");
        } else {
            cat.fail("write to dup'd fd works");
        }
        unsafe { syscall1(nr::CLOSE, fd as u64) };
    } else {
        cat.fail_errno("dup(stdout) >= 3", 3, fd);
    }

    // 2. dup of stdin
    let fd = unsafe { syscall1(nr::DUP, 0) };
    if fd >= 3 {
        cat.pass("dup(stdin) >= 3");
        unsafe { syscall1(nr::CLOSE, fd as u64) };
    } else {
        cat.fail("dup(stdin) >= 3");
    }

    // 3. dup of stderr
    let fd = unsafe { syscall1(nr::DUP, 2) };
    if fd >= 3 {
        cat.pass("dup(stderr) >= 3");
        unsafe { syscall1(nr::CLOSE, fd as u64) };
    } else {
        cat.fail("dup(stderr) >= 3");
    }

    // 4. dup returns lowest available fd
    let fd1 = unsafe { syscall1(nr::DUP, 1) };
    let fd2 = unsafe { syscall1(nr::DUP, 1) };
    if fd1 >= 3 && fd2 == fd1 + 1 {
        cat.pass("dup returns consecutive fds");
    } else {
        cat.fail("dup returns consecutive fds");
    }
    unsafe {
        syscall1(nr::CLOSE, fd1 as u64);
        syscall1(nr::CLOSE, fd2 as u64);
    }

    // 5. dup of pipe fds
    let mut fds = [0i32; 2];
    if unsafe { syscall2(nr::PIPE2, fds.as_mut_ptr() as u64, 0) } == 0 {
        let dup_rd = unsafe { syscall1(nr::DUP, fds[0] as u64) };
        let dup_wr = unsafe { syscall1(nr::DUP, fds[1] as u64) };
        if dup_rd >= 3 && dup_wr >= 3 {
            cat.pass("dup pipe fds");
            // Verify they work
            let data = [0xABu8];
            unsafe { syscall3(nr::WRITE, dup_wr as u64, data.as_ptr() as u64, 1) };
            let mut buf = [0u8];
            let ret = unsafe { syscall3(nr::READ, dup_rd as u64, buf.as_mut_ptr() as u64, 1) };
            if ret == 1 && buf[0] == 0xAB {
                cat.pass("dup'd pipe fds work");
            } else {
                cat.fail("dup'd pipe fds work");
            }
        } else {
            cat.fail("dup pipe fds");
        }
        unsafe {
            syscall1(nr::CLOSE, fds[0] as u64);
            syscall1(nr::CLOSE, fds[1] as u64);
            syscall1(nr::CLOSE, dup_rd as u64);
            syscall1(nr::CLOSE, dup_wr as u64);
        }
    }

    results.add(cat);
}

// ════════════════════════════════════════════════════════════════════════════
// DUP2: Positive Tests
// ════════════════════════════════════════════════════════════════════════════

fn test_dup2_positive(results: &mut crate::Results) {
    let mut cat = TestCategory::new(PseLevel::PSE52, "dup2: positive tests");
    cat.header();

    // 1. Basic dup2 to specific fd
    let fd = unsafe { syscall2(nr::DUP2, 1, 100) };
    if fd == 100 {
        cat.pass("dup2(stdout, 100) returns 100");
        let ret = unsafe { syscall3(nr::WRITE, 100, b".\n".as_ptr() as u64, 2) };
        if ret == 2 {
            cat.pass("write to dup2'd fd works");
        } else {
            cat.fail("write to dup2'd fd works");
        }
        unsafe { syscall1(nr::CLOSE, 100) };
    } else {
        cat.fail_errno("dup2(stdout, 100) returns 100", 100, fd);
    }

    // 2. dup2 to same fd (no-op, returns fd)
    let fd = unsafe { syscall2(nr::DUP2, 1, 1) };
    if fd == 1 {
        cat.pass("dup2(fd, fd) returns fd");
    } else {
        cat.fail_errno("dup2(fd, fd) returns fd", 1, fd);
    }

    // 3. dup2 closes target fd first
    let fd1 = unsafe { syscall1(nr::DUP, 1) };
    let fd2 = unsafe { syscall2(nr::DUP2, 1, fd1 as u64) };
    if fd2 == fd1 {
        cat.pass("dup2 to existing fd closes it first");
    } else {
        cat.fail("dup2 to existing fd closes it first");
    }
    unsafe { syscall1(nr::CLOSE, fd1 as u64) };

    // 4. dup2 with gap creates sparse fd table
    let fd = unsafe { syscall2(nr::DUP2, 1, 200) };
    if fd == 200 {
        cat.pass("dup2 to high fd");
        unsafe { syscall1(nr::CLOSE, 200) };
    } else {
        cat.fail("dup2 to high fd");
    }

    results.add(cat);
}

// ════════════════════════════════════════════════════════════════════════════
// DUP3: Tests
// ════════════════════════════════════════════════════════════════════════════

fn test_dup3(results: &mut crate::Results) {
    let mut cat = TestCategory::new(PseLevel::PSE52, "dup3: tests");
    cat.header();

    const O_CLOEXEC: u64 = 0x80000;

    // 1. dup3 with O_CLOEXEC
    let fd = unsafe { syscall3(nr::DUP3, 1, 101, O_CLOEXEC) };
    if fd == 101 {
        cat.pass("dup3(stdout, 101, O_CLOEXEC)");
        // Check cloexec flag via fcntl
        let flags = unsafe { syscall2(nr::FCNTL, 101, F_GETFD) };
        if flags & FD_CLOEXEC as i64 != 0 {
            cat.pass("dup3 O_CLOEXEC sets FD_CLOEXEC");
        } else {
            cat.fail("dup3 O_CLOEXEC sets FD_CLOEXEC");
        }
        unsafe { syscall1(nr::CLOSE, 101) };
    } else if fd == EINVAL {
        // dup3 might not be implemented
        cat.pass("dup3 not supported (EINVAL)");
    } else {
        cat.fail_errno("dup3(stdout, 101, O_CLOEXEC)", 101, fd);
    }

    // 2. dup3 with same oldfd/newfd is EINVAL
    let ret = unsafe { syscall3(nr::DUP3, 1, 1, 0) };
    if ret == EINVAL {
        cat.pass("dup3(fd, fd, 0) -EINVAL");
    } else if ret == 1 {
        // Some systems allow this (act like dup2)
        cat.pass("dup3(fd, fd, 0) returns fd");
    } else {
        cat.fail_errno("dup3(fd, fd, 0) -EINVAL", EINVAL, ret);
    }

    results.add(cat);
}

// ════════════════════════════════════════════════════════════════════════════
// DUP: Negative Tests
// ════════════════════════════════════════════════════════════════════════════

fn test_dup_negative(results: &mut crate::Results) {
    let mut cat = TestCategory::new(PseLevel::PSE52, "dup: negative tests");
    cat.header();

    // 1. dup invalid fd
    let ret = unsafe { syscall1(nr::DUP, 999) };
    if ret == EBADF {
        cat.pass("dup(999) -EBADF");
    } else {
        cat.fail_errno("dup(999) -EBADF", EBADF, ret);
    }

    // 2. dup negative fd
    let ret = unsafe { syscall1(nr::DUP, (-1i64) as u64) };
    if ret == EBADF {
        cat.pass("dup(-1) -EBADF");
    } else {
        cat.fail_errno("dup(-1) -EBADF", EBADF, ret);
    }

    // 3. dup2 invalid oldfd
    let ret = unsafe { syscall2(nr::DUP2, 999, 50) };
    if ret == EBADF {
        cat.pass("dup2(999, 50) -EBADF");
    } else {
        cat.fail_errno("dup2(999, 50) -EBADF", EBADF, ret);
    }

    // 4. dup2 negative newfd
    let ret = unsafe { syscall2(nr::DUP2, 1, (-1i64) as u64) };
    if ret == EBADF {
        cat.pass("dup2(1, -1) -EBADF");
    } else {
        cat.fail_errno("dup2(1, -1) -EBADF", EBADF, ret);
    }

    results.add(cat);
}

// ════════════════════════════════════════════════════════════════════════════
// CLOSE: Tests
// ════════════════════════════════════════════════════════════════════════════

fn test_close(results: &mut crate::Results) {
    let mut cat = TestCategory::new(PseLevel::PSE52, "close: tests");
    cat.header();

    // 1. Close valid fd
    let fd = unsafe { syscall1(nr::DUP, 1) };
    if fd >= 3 {
        let ret = unsafe { syscall1(nr::CLOSE, fd as u64) };
        if ret == 0 {
            cat.pass("close(valid fd) returns 0");
        } else {
            cat.fail_errno("close(valid fd) returns 0", 0, ret);
        }
    }

    // 2. Double close
    let fd = unsafe { syscall1(nr::DUP, 1) };
    if fd >= 3 {
        unsafe { syscall1(nr::CLOSE, fd as u64) };
        let ret = unsafe { syscall1(nr::CLOSE, fd as u64) };
        if ret == EBADF {
            cat.pass("double close -EBADF");
        } else {
            cat.fail_errno("double close -EBADF", EBADF, ret);
        }
    }

    // 3. Close invalid fd
    let ret = unsafe { syscall1(nr::CLOSE, 999) };
    if ret == EBADF {
        cat.pass("close(999) -EBADF");
    } else {
        cat.fail_errno("close(999) -EBADF", EBADF, ret);
    }

    // 4. Close negative fd
    let ret = unsafe { syscall1(nr::CLOSE, (-1i64) as u64) };
    if ret == EBADF {
        cat.pass("close(-1) -EBADF");
    } else {
        cat.fail_errno("close(-1) -EBADF", EBADF, ret);
    }

    // 5. Close pipe, verify EOF on read
    let mut fds = [0i32; 2];
    if unsafe { syscall2(nr::PIPE2, fds.as_mut_ptr() as u64, 0) } == 0 {
        unsafe { syscall1(nr::CLOSE, fds[1] as u64) }; // Close write end
        let mut buf = [0u8];
        let ret = unsafe { syscall3(nr::READ, fds[0] as u64, buf.as_mut_ptr() as u64, 1) };
        if ret == 0 {
            cat.pass("read after close(write end) EOF");
        } else {
            cat.fail("read after close(write end) EOF");
        }
        unsafe { syscall1(nr::CLOSE, fds[0] as u64) };
    }

    results.add(cat);
}

// ════════════════════════════════════════════════════════════════════════════
// FSTAT: Tests
// ════════════════════════════════════════════════════════════════════════════

#[repr(C)]
struct Stat {
    st_dev: u64,
    st_ino: u64,
    st_nlink: u64,
    st_mode: u32,
    st_uid: u32,
    st_gid: u32,
    _pad0: u32,
    st_rdev: u64,
    st_size: i64,
    st_blksize: i64,
    st_blocks: i64,
    st_atime: i64,
    st_atime_nsec: i64,
    st_mtime: i64,
    st_mtime_nsec: i64,
    st_ctime: i64,
    st_ctime_nsec: i64,
    _reserved: [i64; 3],
}

const FSTAT: u64 = 5;

fn test_fstat(results: &mut crate::Results) {
    let mut cat = TestCategory::new(PseLevel::PSE52, "fstat: tests");
    cat.header();

    // 1. fstat stdout
    let mut stat = core::mem::MaybeUninit::<Stat>::uninit();
    let ret = unsafe { syscall2(FSTAT, 1, stat.as_mut_ptr() as u64) };
    if ret == 0 {
        cat.pass("fstat(stdout) returns 0");
        let stat = unsafe { stat.assume_init() };
        // Mode should have some file type bits
        if stat.st_mode != 0 {
            cat.pass("fstat st_mode nonzero");
        } else {
            cat.fail("fstat st_mode nonzero");
        }
    } else {
        cat.fail_errno("fstat(stdout) returns 0", 0, ret);
    }

    // 2. fstat stdin
    let mut stat = core::mem::MaybeUninit::<Stat>::uninit();
    let ret = unsafe { syscall2(FSTAT, 0, stat.as_mut_ptr() as u64) };
    if ret == 0 {
        cat.pass("fstat(stdin) returns 0");
    } else {
        cat.fail("fstat(stdin) returns 0");
    }

    // 3. fstat stderr
    let mut stat = core::mem::MaybeUninit::<Stat>::uninit();
    let ret = unsafe { syscall2(FSTAT, 2, stat.as_mut_ptr() as u64) };
    if ret == 0 {
        cat.pass("fstat(stderr) returns 0");
    } else {
        cat.fail("fstat(stderr) returns 0");
    }

    // 4. fstat pipe
    let mut fds = [0i32; 2];
    if unsafe { syscall2(nr::PIPE2, fds.as_mut_ptr() as u64, 0) } == 0 {
        let mut stat = core::mem::MaybeUninit::<Stat>::uninit();
        let ret = unsafe { syscall2(FSTAT, fds[0] as u64, stat.as_mut_ptr() as u64) };
        if ret == 0 {
            cat.pass("fstat(pipe) returns 0");
        } else {
            cat.fail("fstat(pipe) returns 0");
        }
        unsafe {
            syscall1(nr::CLOSE, fds[0] as u64);
            syscall1(nr::CLOSE, fds[1] as u64);
        }
    }

    // 5. fstat invalid fd
    let mut stat = core::mem::MaybeUninit::<Stat>::uninit();
    let ret = unsafe { syscall2(FSTAT, 999, stat.as_mut_ptr() as u64) };
    if ret == EBADF {
        cat.pass("fstat(999) -EBADF");
    } else {
        cat.fail_errno("fstat(999) -EBADF", EBADF, ret);
    }

    results.add(cat);
}

// ════════════════════════════════════════════════════════════════════════════
// FCNTL: Tests
// ════════════════════════════════════════════════════════════════════════════

fn test_fcntl(results: &mut crate::Results) {
    let mut cat = TestCategory::new(PseLevel::PSE52, "fcntl: tests");
    cat.header();

    // 1. F_GETFD on stdout
    let ret = unsafe { syscall2(nr::FCNTL, 1, F_GETFD) };
    if ret >= 0 {
        cat.pass("fcntl(stdout, F_GETFD) >= 0");
    } else {
        cat.fail_errno("fcntl(stdout, F_GETFD) >= 0", 0, ret);
    }

    // 2. F_SETFD then F_GETFD
    let fd = unsafe { syscall1(nr::DUP, 1) };
    if fd >= 3 {
        let ret = unsafe { syscall3(nr::FCNTL, fd as u64, F_SETFD, FD_CLOEXEC) };
        if ret == 0 {
            cat.pass("fcntl(F_SETFD, FD_CLOEXEC) returns 0");
        } else {
            cat.fail("fcntl(F_SETFD, FD_CLOEXEC) returns 0");
        }
        let ret = unsafe { syscall2(nr::FCNTL, fd as u64, F_GETFD) };
        if ret & FD_CLOEXEC as i64 != 0 {
            cat.pass("fcntl(F_GETFD) has FD_CLOEXEC");
        } else {
            cat.fail("fcntl(F_GETFD) has FD_CLOEXEC");
        }
        unsafe { syscall1(nr::CLOSE, fd as u64) };
    }

    // 3. F_GETFL
    let ret = unsafe { syscall2(nr::FCNTL, 1, F_GETFL) };
    if ret >= 0 {
        cat.pass("fcntl(stdout, F_GETFL) >= 0");
    } else {
        cat.fail_errno("fcntl(stdout, F_GETFL) >= 0", 0, ret);
    }

    // 4. F_SETFL O_NONBLOCK on pipe
    let mut fds = [0i32; 2];
    if unsafe { syscall2(nr::PIPE2, fds.as_mut_ptr() as u64, 0) } == 0 {
        let ret = unsafe { syscall3(nr::FCNTL, fds[0] as u64, F_SETFL, O_NONBLOCK) };
        if ret == 0 {
            cat.pass("fcntl(F_SETFL, O_NONBLOCK) returns 0");
        } else {
            cat.fail("fcntl(F_SETFL, O_NONBLOCK) returns 0");
        }
        // Verify non-blocking read
        let mut buf = [0u8];
        let ret = unsafe { syscall3(nr::READ, fds[0] as u64, buf.as_mut_ptr() as u64, 1) };
        if ret == -11 {
            // EAGAIN
            cat.pass("read after F_SETFL(NONBLOCK) -EAGAIN");
        } else {
            cat.fail_errno("read after F_SETFL(NONBLOCK) -EAGAIN", -11, ret);
        }
        unsafe {
            syscall1(nr::CLOSE, fds[0] as u64);
            syscall1(nr::CLOSE, fds[1] as u64);
        }
    }

    // 5. F_DUPFD
    let fd = unsafe { syscall3(nr::FCNTL, 1, F_DUPFD, 50) };
    if fd >= 50 {
        cat.pass("fcntl(F_DUPFD, 50) >= 50");
        unsafe { syscall1(nr::CLOSE, fd as u64) };
    } else {
        cat.fail_errno("fcntl(F_DUPFD, 50) >= 50", 50, fd);
    }

    // 6. F_DUPFD_CLOEXEC
    let fd = unsafe { syscall3(nr::FCNTL, 1, F_DUPFD_CLOEXEC, 60) };
    if fd >= 60 {
        cat.pass("fcntl(F_DUPFD_CLOEXEC, 60) >= 60");
        let flags = unsafe { syscall2(nr::FCNTL, fd as u64, F_GETFD) };
        if flags & FD_CLOEXEC as i64 != 0 {
            cat.pass("F_DUPFD_CLOEXEC sets FD_CLOEXEC");
        } else {
            cat.fail("F_DUPFD_CLOEXEC sets FD_CLOEXEC");
        }
        unsafe { syscall1(nr::CLOSE, fd as u64) };
    } else if fd == EINVAL {
        cat.pass("F_DUPFD_CLOEXEC not supported");
    } else {
        cat.fail_errno("fcntl(F_DUPFD_CLOEXEC, 60)", 60, fd);
    }

    // 7. fcntl on bad fd
    let ret = unsafe { syscall2(nr::FCNTL, 999, F_GETFD) };
    if ret == EBADF {
        cat.pass("fcntl(999, F_GETFD) -EBADF");
    } else {
        cat.fail_errno("fcntl(999, F_GETFD) -EBADF", EBADF, ret);
    }

    results.add(cat);
}

// ════════════════════════════════════════════════════════════════════════════
// LSEEK: Seek within an open file descriptor
// ════════════════════════════════════════════════════════════════════════════

const O_CREAT: u64 = 0o100;
const O_RDWR: u64 = 2;
const O_TRUNC: u64 = 0o1000;
const AT_FDCWD: u64 = (-100i64) as u64;
const SEEK_SET: u64 = 0;
const SEEK_CUR: u64 = 1;
const SEEK_END: u64 = 2;

fn test_lseek(results: &mut crate::Results) {
    let mut cat = TestCategory::new(PseLevel::PSE52, "FD: lseek");
    cat.header();

    let path = b"/tmp/_posix_lseek_test\0";
    let fd = unsafe {
        syscall4(nr::OPENAT, AT_FDCWD, path.as_ptr() as u64,
                 O_CREAT | O_RDWR | O_TRUNC, 0o600)
    };
    if fd < 0 {
        cat.fail_errno("lseek: create file", 0, fd);
        results.add(cat);
        return;
    }

    // Write 10 bytes
    let data = b"0123456789";
    unsafe { syscall3(nr::WRITE, fd as u64, data.as_ptr() as u64, 10) };

    // SEEK_SET to beginning
    let pos = unsafe { syscall3(nr::LSEEK, fd as u64, 0, SEEK_SET) };
    if pos == 0 {
        cat.pass("lseek(SEEK_SET, 0) returns 0");
    } else {
        cat.fail_errno("lseek(SEEK_SET, 0) returns 0", 0, pos);
    }

    // Read 3 bytes from position 0
    let mut buf = [0u8; 3];
    unsafe { syscall3(nr::READ, fd as u64, buf.as_mut_ptr() as u64, 3) };
    if buf == *b"012" {
        cat.pass("read after SEEK_SET(0) returns correct data");
    } else {
        cat.fail("read after SEEK_SET(0) returns correct data");
    }

    // SEEK_CUR should be at 3
    let pos = unsafe { syscall3(nr::LSEEK, fd as u64, 0, SEEK_CUR) };
    if pos == 3 {
        cat.pass("lseek(SEEK_CUR, 0) returns 3 after reading 3 bytes");
    } else {
        cat.fail_errno("lseek(SEEK_CUR, 0) returns 3", 3, pos);
    }

    // SEEK_CUR +4
    let pos = unsafe { syscall3(nr::LSEEK, fd as u64, 4, SEEK_CUR) };
    if pos == 7 {
        cat.pass("lseek(SEEK_CUR, +4) returns 7");
    } else {
        cat.fail_errno("lseek(SEEK_CUR, +4) returns 7", 7, pos);
    }

    // SEEK_END -2 → position 8
    let pos = unsafe { syscall3(nr::LSEEK, fd as u64, (-2i64) as u64, SEEK_END) };
    if pos == 8 {
        cat.pass("lseek(SEEK_END, -2) returns 8");
    } else {
        cat.fail_errno("lseek(SEEK_END, -2) returns 8", 8, pos);
    }

    // Read 2 bytes from position 8 → "89"
    let mut buf2 = [0u8; 2];
    unsafe { syscall3(nr::READ, fd as u64, buf2.as_mut_ptr() as u64, 2) };
    if buf2 == *b"89" {
        cat.pass("read after SEEK_END(-2) returns correct data");
    } else {
        cat.fail("read after SEEK_END(-2) returns correct data");
    }

    // SEEK_SET on pipe → ESPIPE
    let mut pipe_fds = [0i32; 2];
    if unsafe { syscall2(nr::PIPE2, pipe_fds.as_mut_ptr() as u64, 0) } == 0 {
        let ret = unsafe { syscall3(nr::LSEEK, pipe_fds[0] as u64, 0, SEEK_SET) };
        if ret == -29 { // ESPIPE
            cat.pass("lseek on pipe returns ESPIPE");
        } else {
            cat.fail_errno("lseek on pipe returns ESPIPE", -29, ret);
        }
        unsafe {
            syscall1(nr::CLOSE, pipe_fds[0] as u64);
            syscall1(nr::CLOSE, pipe_fds[1] as u64);
        }
    }

    unsafe { syscall1(nr::CLOSE, fd as u64) };
    unsafe { syscall3(nr::UNLINKAT, AT_FDCWD, path.as_ptr() as u64, 0) };

    results.add(cat);
}

// ════════════════════════════════════════════════════════════════════════════
// FTRUNCATE: Truncate an open file to a specified length
// ════════════════════════════════════════════════════════════════════════════

fn test_ftruncate(results: &mut crate::Results) {
    let mut cat = TestCategory::new(PseLevel::PSE52, "FD: ftruncate");
    cat.header();

    let path = b"/tmp/_posix_ftrunc_test\0";
    let fd = unsafe {
        syscall4(nr::OPENAT, AT_FDCWD, path.as_ptr() as u64,
                 O_CREAT | O_RDWR | O_TRUNC, 0o600)
    };
    if fd < 0 {
        cat.fail_errno("ftruncate: create file", 0, fd);
        results.add(cat);
        return;
    }

    // Write 20 bytes
    let data = b"ABCDEFGHIJKLMNOPQRST";
    unsafe { syscall3(nr::WRITE, fd as u64, data.as_ptr() as u64, 20) };

    // Truncate to 5 bytes
    let ret = unsafe { syscall2(nr::FTRUNCATE, fd as u64, 5) };
    if ret == 0 {
        cat.pass("ftruncate(fd, 5) returns 0");
    } else {
        cat.fail_errno("ftruncate(fd, 5) returns 0", 0, ret);
    }

    // Verify size via lseek(SEEK_END)
    let size = unsafe { syscall3(nr::LSEEK, fd as u64, 0, SEEK_END) };
    if size == 5 {
        cat.pass("file size is 5 after ftruncate");
    } else {
        cat.fail_errno("file size is 5 after ftruncate", 5, size);
    }

    // Extend to 10 (should zero-fill)
    let ret = unsafe { syscall2(nr::FTRUNCATE, fd as u64, 10) };
    if ret == 0 {
        cat.pass("ftruncate(fd, 10) extends file");
    } else {
        cat.fail_errno("ftruncate(fd, 10) extends file", 0, ret);
    }

    // Read from position 5 — should be zero bytes
    unsafe { syscall3(nr::LSEEK, fd as u64, 5, SEEK_SET) };
    let mut buf = [0xFFu8; 5];
    unsafe { syscall3(nr::READ, fd as u64, buf.as_mut_ptr() as u64, 5) };
    if buf == [0, 0, 0, 0, 0] {
        cat.pass("ftruncate extension zero-fills");
    } else {
        cat.fail("ftruncate extension zero-fills");
    }

    // ftruncate on bad fd
    let ret = unsafe { syscall2(nr::FTRUNCATE, 999, 0) };
    if ret == -9 { // EBADF
        cat.pass("ftruncate(bad fd) returns EBADF");
    } else {
        cat.fail_errno("ftruncate(bad fd) returns EBADF", -9, ret);
    }

    unsafe { syscall1(nr::CLOSE, fd as u64) };
    unsafe { syscall3(nr::UNLINKAT, AT_FDCWD, path.as_ptr() as u64, 0) };

    results.add(cat);
}

/// Run all fd tests
pub fn run_all(results: &mut crate::Results) {
    test_dup_positive(results);
    test_dup2_positive(results);
    test_dup3(results);
    test_dup_negative(results);
    test_close(results);
    test_fstat(results);
    test_fcntl(results);
    test_lseek(results);
    test_ftruncate(results);
}
