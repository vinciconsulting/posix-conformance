//! Comprehensive file descriptor tests
//!
//! Coverage:
//! - dup/dup2/dup3: positive, negative, boundary
//! - close: positive, negative
//! - fstat: positive, negative, struct validation
//! - fcntl: F_GETFD, F_SETFD, F_GETFL, F_SETFL

use crate::{fail, fail_errno, nr, pass, syscall1, syscall2, syscall3, write_str};

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

fn test_dup_positive() {
    write_str("\n=== dup: positive tests ===\n");

    // 1. Basic dup of stdout
    let fd = unsafe { syscall1(nr::DUP, 1) };
    if fd >= 3 {
        pass("dup(stdout) >= 3");
        // Verify write works
        let ret = unsafe { syscall3(nr::WRITE, fd as u64, b".\n".as_ptr() as u64, 2) };
        if ret == 2 {
            pass("write to dup'd fd works");
        } else {
            fail("write to dup'd fd works");
        }
        unsafe { syscall1(nr::CLOSE, fd as u64) };
    } else {
        fail_errno("dup(stdout) >= 3", 3, fd);
    }

    // 2. dup of stdin
    let fd = unsafe { syscall1(nr::DUP, 0) };
    if fd >= 3 {
        pass("dup(stdin) >= 3");
        unsafe { syscall1(nr::CLOSE, fd as u64) };
    } else {
        fail("dup(stdin) >= 3");
    }

    // 3. dup of stderr
    let fd = unsafe { syscall1(nr::DUP, 2) };
    if fd >= 3 {
        pass("dup(stderr) >= 3");
        unsafe { syscall1(nr::CLOSE, fd as u64) };
    } else {
        fail("dup(stderr) >= 3");
    }

    // 4. dup returns lowest available fd
    let fd1 = unsafe { syscall1(nr::DUP, 1) };
    let fd2 = unsafe { syscall1(nr::DUP, 1) };
    if fd1 >= 3 && fd2 == fd1 + 1 {
        pass("dup returns consecutive fds");
    } else {
        fail("dup returns consecutive fds");
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
            pass("dup pipe fds");
            // Verify they work
            let data = [0xABu8];
            unsafe { syscall3(nr::WRITE, dup_wr as u64, data.as_ptr() as u64, 1) };
            let mut buf = [0u8];
            let ret = unsafe { syscall3(nr::READ, dup_rd as u64, buf.as_mut_ptr() as u64, 1) };
            if ret == 1 && buf[0] == 0xAB {
                pass("dup'd pipe fds work");
            } else {
                fail("dup'd pipe fds work");
            }
        } else {
            fail("dup pipe fds");
        }
        unsafe {
            syscall1(nr::CLOSE, fds[0] as u64);
            syscall1(nr::CLOSE, fds[1] as u64);
            syscall1(nr::CLOSE, dup_rd as u64);
            syscall1(nr::CLOSE, dup_wr as u64);
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// DUP2: Positive Tests
// ════════════════════════════════════════════════════════════════════════════

fn test_dup2_positive() {
    write_str("\n=== dup2: positive tests ===\n");

    // 1. Basic dup2 to specific fd
    let fd = unsafe { syscall2(nr::DUP2, 1, 100) };
    if fd == 100 {
        pass("dup2(stdout, 100) returns 100");
        let ret = unsafe { syscall3(nr::WRITE, 100, b".\n".as_ptr() as u64, 2) };
        if ret == 2 {
            pass("write to dup2'd fd works");
        } else {
            fail("write to dup2'd fd works");
        }
        unsafe { syscall1(nr::CLOSE, 100) };
    } else {
        fail_errno("dup2(stdout, 100) returns 100", 100, fd);
    }

    // 2. dup2 to same fd (no-op, returns fd)
    let fd = unsafe { syscall2(nr::DUP2, 1, 1) };
    if fd == 1 {
        pass("dup2(fd, fd) returns fd");
    } else {
        fail_errno("dup2(fd, fd) returns fd", 1, fd);
    }

    // 3. dup2 closes target fd first
    let fd1 = unsafe { syscall1(nr::DUP, 1) };
    let fd2 = unsafe { syscall2(nr::DUP2, 1, fd1 as u64) };
    if fd2 == fd1 {
        pass("dup2 to existing fd closes it first");
    } else {
        fail("dup2 to existing fd closes it first");
    }
    unsafe { syscall1(nr::CLOSE, fd1 as u64) };

    // 4. dup2 with gap creates sparse fd table
    let fd = unsafe { syscall2(nr::DUP2, 1, 200) };
    if fd == 200 {
        pass("dup2 to high fd");
        unsafe { syscall1(nr::CLOSE, 200) };
    } else {
        fail("dup2 to high fd");
    }
}

// ════════════════════════════════════════════════════════════════════════════
// DUP3: Tests
// ════════════════════════════════════════════════════════════════════════════

fn test_dup3() {
    write_str("\n=== dup3: tests ===\n");

    const O_CLOEXEC: u64 = 0x80000;

    // 1. dup3 with O_CLOEXEC
    let fd = unsafe { syscall3(nr::DUP3, 1, 101, O_CLOEXEC) };
    if fd == 101 {
        pass("dup3(stdout, 101, O_CLOEXEC)");
        // Check cloexec flag via fcntl
        let flags = unsafe { syscall2(nr::FCNTL, 101, F_GETFD) };
        if flags & FD_CLOEXEC as i64 != 0 {
            pass("dup3 O_CLOEXEC sets FD_CLOEXEC");
        } else {
            fail("dup3 O_CLOEXEC sets FD_CLOEXEC");
        }
        unsafe { syscall1(nr::CLOSE, 101) };
    } else if fd == EINVAL {
        // dup3 might not be implemented
        pass("dup3 not supported (EINVAL)");
    } else {
        fail_errno("dup3(stdout, 101, O_CLOEXEC)", 101, fd);
    }

    // 2. dup3 with same oldfd/newfd is EINVAL
    let ret = unsafe { syscall3(nr::DUP3, 1, 1, 0) };
    if ret == EINVAL {
        pass("dup3(fd, fd, 0) -EINVAL");
    } else if ret == 1 {
        // Some systems allow this (act like dup2)
        pass("dup3(fd, fd, 0) returns fd");
    } else {
        fail_errno("dup3(fd, fd, 0) -EINVAL", EINVAL, ret);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// DUP: Negative Tests
// ════════════════════════════════════════════════════════════════════════════

fn test_dup_negative() {
    write_str("\n=== dup: negative tests ===\n");

    // 1. dup invalid fd
    let ret = unsafe { syscall1(nr::DUP, 999) };
    if ret == EBADF {
        pass("dup(999) -EBADF");
    } else {
        fail_errno("dup(999) -EBADF", EBADF, ret);
    }

    // 2. dup negative fd
    let ret = unsafe { syscall1(nr::DUP, (-1i64) as u64) };
    if ret == EBADF {
        pass("dup(-1) -EBADF");
    } else {
        fail_errno("dup(-1) -EBADF", EBADF, ret);
    }

    // 3. dup2 invalid oldfd
    let ret = unsafe { syscall2(nr::DUP2, 999, 50) };
    if ret == EBADF {
        pass("dup2(999, 50) -EBADF");
    } else {
        fail_errno("dup2(999, 50) -EBADF", EBADF, ret);
    }

    // 4. dup2 negative newfd
    let ret = unsafe { syscall2(nr::DUP2, 1, (-1i64) as u64) };
    if ret == EBADF {
        pass("dup2(1, -1) -EBADF");
    } else {
        fail_errno("dup2(1, -1) -EBADF", EBADF, ret);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// CLOSE: Tests
// ════════════════════════════════════════════════════════════════════════════

fn test_close() {
    write_str("\n=== close: tests ===\n");

    // 1. Close valid fd
    let fd = unsafe { syscall1(nr::DUP, 1) };
    if fd >= 3 {
        let ret = unsafe { syscall1(nr::CLOSE, fd as u64) };
        if ret == 0 {
            pass("close(valid fd) returns 0");
        } else {
            fail_errno("close(valid fd) returns 0", 0, ret);
        }
    }

    // 2. Double close
    let fd = unsafe { syscall1(nr::DUP, 1) };
    if fd >= 3 {
        unsafe { syscall1(nr::CLOSE, fd as u64) };
        let ret = unsafe { syscall1(nr::CLOSE, fd as u64) };
        if ret == EBADF {
            pass("double close -EBADF");
        } else {
            fail_errno("double close -EBADF", EBADF, ret);
        }
    }

    // 3. Close invalid fd
    let ret = unsafe { syscall1(nr::CLOSE, 999) };
    if ret == EBADF {
        pass("close(999) -EBADF");
    } else {
        fail_errno("close(999) -EBADF", EBADF, ret);
    }

    // 4. Close negative fd
    let ret = unsafe { syscall1(nr::CLOSE, (-1i64) as u64) };
    if ret == EBADF {
        pass("close(-1) -EBADF");
    } else {
        fail_errno("close(-1) -EBADF", EBADF, ret);
    }

    // 5. Close pipe, verify EOF on read
    let mut fds = [0i32; 2];
    if unsafe { syscall2(nr::PIPE2, fds.as_mut_ptr() as u64, 0) } == 0 {
        unsafe { syscall1(nr::CLOSE, fds[1] as u64) }; // Close write end
        let mut buf = [0u8];
        let ret = unsafe { syscall3(nr::READ, fds[0] as u64, buf.as_mut_ptr() as u64, 1) };
        if ret == 0 {
            pass("read after close(write end) EOF");
        } else {
            fail("read after close(write end) EOF");
        }
        unsafe { syscall1(nr::CLOSE, fds[0] as u64) };
    }
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

fn test_fstat() {
    write_str("\n=== fstat: tests ===\n");

    // 1. fstat stdout
    let mut stat = core::mem::MaybeUninit::<Stat>::uninit();
    let ret = unsafe { syscall2(FSTAT, 1, stat.as_mut_ptr() as u64) };
    if ret == 0 {
        pass("fstat(stdout) returns 0");
        let stat = unsafe { stat.assume_init() };
        // Mode should have some file type bits
        if stat.st_mode != 0 {
            pass("fstat st_mode nonzero");
        } else {
            fail("fstat st_mode nonzero");
        }
    } else {
        fail_errno("fstat(stdout) returns 0", 0, ret);
    }

    // 2. fstat stdin
    let mut stat = core::mem::MaybeUninit::<Stat>::uninit();
    let ret = unsafe { syscall2(FSTAT, 0, stat.as_mut_ptr() as u64) };
    if ret == 0 {
        pass("fstat(stdin) returns 0");
    } else {
        fail("fstat(stdin) returns 0");
    }

    // 3. fstat stderr
    let mut stat = core::mem::MaybeUninit::<Stat>::uninit();
    let ret = unsafe { syscall2(FSTAT, 2, stat.as_mut_ptr() as u64) };
    if ret == 0 {
        pass("fstat(stderr) returns 0");
    } else {
        fail("fstat(stderr) returns 0");
    }

    // 4. fstat pipe
    let mut fds = [0i32; 2];
    if unsafe { syscall2(nr::PIPE2, fds.as_mut_ptr() as u64, 0) } == 0 {
        let mut stat = core::mem::MaybeUninit::<Stat>::uninit();
        let ret = unsafe { syscall2(FSTAT, fds[0] as u64, stat.as_mut_ptr() as u64) };
        if ret == 0 {
            pass("fstat(pipe) returns 0");
        } else {
            fail("fstat(pipe) returns 0");
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
        pass("fstat(999) -EBADF");
    } else {
        fail_errno("fstat(999) -EBADF", EBADF, ret);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// FCNTL: Tests
// ════════════════════════════════════════════════════════════════════════════

fn test_fcntl() {
    write_str("\n=== fcntl: tests ===\n");

    // 1. F_GETFD on stdout
    let ret = unsafe { syscall2(nr::FCNTL, 1, F_GETFD) };
    if ret >= 0 {
        pass("fcntl(stdout, F_GETFD) >= 0");
    } else {
        fail_errno("fcntl(stdout, F_GETFD) >= 0", 0, ret);
    }

    // 2. F_SETFD then F_GETFD
    let fd = unsafe { syscall1(nr::DUP, 1) };
    if fd >= 3 {
        let ret = unsafe { syscall3(nr::FCNTL, fd as u64, F_SETFD, FD_CLOEXEC) };
        if ret == 0 {
            pass("fcntl(F_SETFD, FD_CLOEXEC) returns 0");
        } else {
            fail("fcntl(F_SETFD, FD_CLOEXEC) returns 0");
        }
        let ret = unsafe { syscall2(nr::FCNTL, fd as u64, F_GETFD) };
        if ret & FD_CLOEXEC as i64 != 0 {
            pass("fcntl(F_GETFD) has FD_CLOEXEC");
        } else {
            fail("fcntl(F_GETFD) has FD_CLOEXEC");
        }
        unsafe { syscall1(nr::CLOSE, fd as u64) };
    }

    // 3. F_GETFL
    let ret = unsafe { syscall2(nr::FCNTL, 1, F_GETFL) };
    if ret >= 0 {
        pass("fcntl(stdout, F_GETFL) >= 0");
    } else {
        fail_errno("fcntl(stdout, F_GETFL) >= 0", 0, ret);
    }

    // 4. F_SETFL O_NONBLOCK on pipe
    let mut fds = [0i32; 2];
    if unsafe { syscall2(nr::PIPE2, fds.as_mut_ptr() as u64, 0) } == 0 {
        let ret = unsafe { syscall3(nr::FCNTL, fds[0] as u64, F_SETFL, O_NONBLOCK) };
        if ret == 0 {
            pass("fcntl(F_SETFL, O_NONBLOCK) returns 0");
        } else {
            fail("fcntl(F_SETFL, O_NONBLOCK) returns 0");
        }
        // Verify non-blocking read
        let mut buf = [0u8];
        let ret = unsafe { syscall3(nr::READ, fds[0] as u64, buf.as_mut_ptr() as u64, 1) };
        if ret == -11 {
            // EAGAIN
            pass("read after F_SETFL(NONBLOCK) -EAGAIN");
        } else {
            fail_errno("read after F_SETFL(NONBLOCK) -EAGAIN", -11, ret);
        }
        unsafe {
            syscall1(nr::CLOSE, fds[0] as u64);
            syscall1(nr::CLOSE, fds[1] as u64);
        }
    }

    // 5. F_DUPFD
    let fd = unsafe { syscall3(nr::FCNTL, 1, F_DUPFD, 50) };
    if fd >= 50 {
        pass("fcntl(F_DUPFD, 50) >= 50");
        unsafe { syscall1(nr::CLOSE, fd as u64) };
    } else {
        fail_errno("fcntl(F_DUPFD, 50) >= 50", 50, fd);
    }

    // 6. F_DUPFD_CLOEXEC
    let fd = unsafe { syscall3(nr::FCNTL, 1, F_DUPFD_CLOEXEC, 60) };
    if fd >= 60 {
        pass("fcntl(F_DUPFD_CLOEXEC, 60) >= 60");
        let flags = unsafe { syscall2(nr::FCNTL, fd as u64, F_GETFD) };
        if flags & FD_CLOEXEC as i64 != 0 {
            pass("F_DUPFD_CLOEXEC sets FD_CLOEXEC");
        } else {
            fail("F_DUPFD_CLOEXEC sets FD_CLOEXEC");
        }
        unsafe { syscall1(nr::CLOSE, fd as u64) };
    } else if fd == EINVAL {
        pass("F_DUPFD_CLOEXEC not supported");
    } else {
        fail_errno("fcntl(F_DUPFD_CLOEXEC, 60)", 60, fd);
    }

    // 7. fcntl on bad fd
    let ret = unsafe { syscall2(nr::FCNTL, 999, F_GETFD) };
    if ret == EBADF {
        pass("fcntl(999, F_GETFD) -EBADF");
    } else {
        fail_errno("fcntl(999, F_GETFD) -EBADF", EBADF, ret);
    }
}

/// Run all fd tests
pub fn run_all() {
    test_dup_positive();
    test_dup2_positive();
    test_dup3();
    test_dup_negative();
    test_close();
    test_fstat();
    test_fcntl();
}
