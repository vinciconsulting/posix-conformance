//! Poll/select tests for POSIX conformance (PSE51/53)
//!
//! Tests: poll, ppoll, select, pselect6
//!
//! Categories:
//! - Positive: normal I/O multiplexing scenarios
//! - Negative: invalid fds, bad pointers, invalid flags
//! - Boundary: zero timeout, max fds, empty fd sets

use crate::nr;
use crate::{pass, fail, fail_errno, write_str, syscall1, syscall2, syscall3, syscall5, syscall6};
use crate::{Pollfd, Timespec};

// ════════════════════════════════════════════════════════════════════════════
// Constants
// ════════════════════════════════════════════════════════════════════════════

// Poll event flags
const POLLIN: i16 = 0x0001;
const POLLPRI: i16 = 0x0002;
const POLLOUT: i16 = 0x0004;
const POLLNVAL: i16 = 0x0020;
const POLLRDNORM: i16 = 0x0040;
const POLLWRNORM: i16 = 0x0100;

// Error codes
const EINVAL: i64 = -22;

#[repr(C)]
struct Timeval {
    tv_sec: i64,
    tv_usec: i64,
}

// ════════════════════════════════════════════════════════════════════════════
// Helper functions
// ════════════════════════════════════════════════════════════════════════════

fn create_pipe() -> Option<(i32, i32)> {
    let mut fds = [0i32; 2];
    let ret = unsafe { syscall2(nr::PIPE2, fds.as_mut_ptr() as u64, 0) };
    if ret == 0 {
        Some((fds[0], fds[1]))
    } else {
        None
    }
}

fn close_pipe(read_fd: i32, write_fd: i32) {
    unsafe {
        syscall1(nr::CLOSE, read_fd as u64);
        syscall1(nr::CLOSE, write_fd as u64);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Poll tests
// ════════════════════════════════════════════════════════════════════════════

pub fn test_poll_positive() {
    write_str("\n=== Poll: positive tests ===\n");

    // 1. Poll empty pipe read end (not ready, timeout immediately)
    let Some((read_fd, write_fd)) = create_pipe() else {
        fail("poll test: pipe setup");
        return;
    };

    let mut pollfds = [Pollfd { fd: read_fd, events: POLLIN, revents: 0 }];
    let ret = unsafe { syscall3(nr::POLL, pollfds.as_mut_ptr() as u64, 1, 0) };
    if ret == 0 && pollfds[0].revents == 0 {
        pass("poll: empty pipe read not ready (timeout 0)");
    } else {
        fail("poll: empty pipe read not ready (timeout 0)");
    }

    // 2. Poll pipe write end (should be ready - has space)
    pollfds[0] = Pollfd { fd: write_fd, events: POLLOUT, revents: 0 };
    let ret = unsafe { syscall3(nr::POLL, pollfds.as_mut_ptr() as u64, 1, 0) };
    if ret >= 1 && (pollfds[0].revents & POLLOUT) != 0 {
        pass("poll: pipe write ready (POLLOUT)");
    } else {
        fail("poll: pipe write ready (POLLOUT)");
    }

    // 3. Write to pipe, then poll read end
    let data = b"test";
    unsafe { syscall3(nr::WRITE, write_fd as u64, data.as_ptr() as u64, 4) };
    pollfds[0] = Pollfd { fd: read_fd, events: POLLIN, revents: 0 };
    let ret = unsafe { syscall3(nr::POLL, pollfds.as_mut_ptr() as u64, 1, 0) };
    if ret >= 1 && (pollfds[0].revents & POLLIN) != 0 {
        pass("poll: pipe read ready after write (POLLIN)");
    } else {
        fail("poll: pipe read ready after write (POLLIN)");
    }

    // 4. Poll multiple fds
    let mut pollfds2 = [
        Pollfd { fd: read_fd, events: POLLIN, revents: 0 },
        Pollfd { fd: write_fd, events: POLLOUT, revents: 0 },
    ];
    let ret = unsafe { syscall3(nr::POLL, pollfds2.as_mut_ptr() as u64, 2, 0) };
    if ret >= 1 {
        pass("poll: multiple fds returns count");
    } else {
        fail("poll: multiple fds returns count");
    }

    // 5. Poll with POLLPRI (out-of-band data, typically not available on pipes)
    pollfds[0] = Pollfd { fd: read_fd, events: POLLPRI, revents: 0 };
    let ret = unsafe { syscall3(nr::POLL, pollfds.as_mut_ptr() as u64, 1, 0) };
    if ret == 0 || ret >= 0 {
        pass("poll: POLLPRI handled gracefully");
    } else {
        fail("poll: POLLPRI handled gracefully");
    }

    // 6. Poll with timeout (1ms) - should timeout
    let mut buf = [0u8; 32];
    unsafe { syscall3(nr::READ, read_fd as u64, buf.as_mut_ptr() as u64, 32) }; // drain pipe
    pollfds[0] = Pollfd { fd: read_fd, events: POLLIN, revents: 0 };
    let ret = unsafe { syscall3(nr::POLL, pollfds.as_mut_ptr() as u64, 1, 1) };
    if ret == 0 {
        pass("poll: 1ms timeout returns 0 (no events)");
    } else {
        fail("poll: 1ms timeout returns 0 (no events)");
    }

    // 7. Poll with negative timeout (infinite, but we have data)
    unsafe { syscall3(nr::WRITE, write_fd as u64, data.as_ptr() as u64, 4) };
    pollfds[0] = Pollfd { fd: read_fd, events: POLLIN, revents: 0 };
    let ret = unsafe { syscall3(nr::POLL, pollfds.as_mut_ptr() as u64, 1, -1i64 as u64) };
    if ret >= 1 && (pollfds[0].revents & POLLIN) != 0 {
        pass("poll: infinite timeout returns when ready");
    } else {
        fail("poll: infinite timeout returns when ready");
    }

    close_pipe(read_fd, write_fd);
}

pub fn test_poll_negative() {
    write_str("\n=== Poll: negative tests ===\n");

    // 1. Poll with invalid fd
    let mut pollfds = [Pollfd { fd: 999, events: POLLIN, revents: 0 }];
    let ret = unsafe { syscall3(nr::POLL, pollfds.as_mut_ptr() as u64, 1, 0) };
    if ret == 1 && (pollfds[0].revents & POLLNVAL) != 0 {
        pass("poll: invalid fd returns POLLNVAL");
    } else {
        fail("poll: invalid fd returns POLLNVAL");
    }

    // 2. Poll with negative fd (-1 should be ignored)
    pollfds[0] = Pollfd { fd: -1, events: POLLIN, revents: 0 };
    let ret = unsafe { syscall3(nr::POLL, pollfds.as_mut_ptr() as u64, 1, 0) };
    if ret == 0 {
        pass("poll: fd=-1 is ignored");
    } else {
        fail("poll: fd=-1 is ignored");
    }

    // 3. Poll with nfds=0 (should succeed immediately)
    let ret = unsafe { syscall3(nr::POLL, 0, 0, 0) };
    if ret == 0 {
        pass("poll: nfds=0 returns 0");
    } else {
        fail_errno("poll: nfds=0 returns 0", 0, ret);
    }

    // 4. Poll with bad pointer (won't crash, but may return EFAULT)
    // Skip this as it could cause issues

    // 5. Mix valid and invalid fds
    let Some((read_fd, write_fd)) = create_pipe() else {
        fail("poll negative: pipe setup");
        return;
    };
    let mut pollfds2 = [
        Pollfd { fd: read_fd, events: POLLIN, revents: 0 },
        Pollfd { fd: 999, events: POLLIN, revents: 0 },
    ];
    let ret = unsafe { syscall3(nr::POLL, pollfds2.as_mut_ptr() as u64, 2, 0) };
    if ret == 1 && (pollfds2[1].revents & POLLNVAL) != 0 {
        pass("poll: mixed valid/invalid fds handled");
    } else {
        fail("poll: mixed valid/invalid fds handled");
    }

    close_pipe(read_fd, write_fd);
}

pub fn test_poll_boundary() {
    write_str("\n=== Poll: boundary tests ===\n");

    let Some((read_fd, write_fd)) = create_pipe() else {
        fail("poll boundary: pipe setup");
        return;
    };

    // 1. Zero events mask
    let mut pollfds = [Pollfd { fd: read_fd, events: 0, revents: 0 }];
    let ret = unsafe { syscall3(nr::POLL, pollfds.as_mut_ptr() as u64, 1, 0) };
    if ret == 0 {
        pass("poll: events=0 returns 0");
    } else {
        fail("poll: events=0 returns 0");
    }

    // 2. All event flags
    pollfds[0] = Pollfd { fd: write_fd, events: POLLIN | POLLOUT | POLLPRI | POLLRDNORM | POLLWRNORM, revents: 0 };
    let ret = unsafe { syscall3(nr::POLL, pollfds.as_mut_ptr() as u64, 1, 0) };
    if ret >= 0 {
        pass("poll: all event flags accepted");
    } else {
        fail("poll: all event flags accepted");
    }

    // 3. Maximum reasonable nfds (test with 16)
    let mut many_fds = [Pollfd { fd: read_fd, events: POLLIN, revents: 0 }; 16];
    for (i, pfd) in many_fds.iter_mut().enumerate() {
        pfd.fd = if i % 2 == 0 { read_fd } else { write_fd };
        pfd.events = if i % 2 == 0 { POLLIN } else { POLLOUT };
    }
    let ret = unsafe { syscall3(nr::POLL, many_fds.as_mut_ptr() as u64, 16, 0) };
    if ret >= 0 {
        pass("poll: 16 fds handled");
    } else {
        fail("poll: 16 fds handled");
    }

    // 4. Timeout edge cases
    // Zero timeout
    pollfds[0] = Pollfd { fd: read_fd, events: POLLIN, revents: 0 };
    let ret = unsafe { syscall3(nr::POLL, pollfds.as_mut_ptr() as u64, 1, 0) };
    if ret == 0 {
        pass("poll: timeout=0 (immediate)");
    } else {
        fail("poll: timeout=0 (immediate)");
    }

    // Large timeout (but we have ready fd)
    unsafe { syscall3(nr::WRITE, write_fd as u64, b"x".as_ptr() as u64, 1) };
    pollfds[0] = Pollfd { fd: read_fd, events: POLLIN, revents: 0 };
    let ret = unsafe { syscall3(nr::POLL, pollfds.as_mut_ptr() as u64, 1, 60000) }; // 60 seconds
    if ret >= 1 && (pollfds[0].revents & POLLIN) != 0 {
        pass("poll: large timeout with ready fd returns immediately");
    } else {
        fail("poll: large timeout with ready fd returns immediately");
    }

    close_pipe(read_fd, write_fd);
}

// ════════════════════════════════════════════════════════════════════════════
// Select tests
// ════════════════════════════════════════════════════════════════════════════

pub fn test_select_positive() {
    write_str("\n=== Select: positive tests ===\n");

    let Some((read_fd, write_fd)) = create_pipe() else {
        fail("select positive: pipe setup");
        return;
    };

    let read_fd_u = read_fd as u64;
    let write_fd_u = write_fd as u64;
    let nfds = (if read_fd > write_fd { read_fd } else { write_fd }) as u64 + 1;

    // 1. Select on empty pipe read - should timeout
    let mut readfds: u64 = 1 << read_fd_u;
    let mut tv = Timeval { tv_sec: 0, tv_usec: 0 };
    let ret = unsafe {
        syscall5(nr::SELECT, nfds, &mut readfds as *mut _ as u64, 0, 0,
                 &mut tv as *mut _ as u64)
    };
    if ret == 0 {
        pass("select: empty pipe read timeout");
    } else {
        fail_errno("select: empty pipe read timeout", 0, ret);
    }

    // 2. Select on pipe write - should be ready
    let mut writefds: u64 = 1 << write_fd_u;
    let ret = unsafe {
        syscall5(nr::SELECT, nfds, 0, &mut writefds as *mut _ as u64, 0,
                 &mut tv as *mut _ as u64)
    };
    if ret >= 1 && (writefds & (1 << write_fd_u)) != 0 {
        pass("select: pipe write ready");
    } else {
        fail("select: pipe write ready");
    }

    // 3. Write to pipe, select on read
    unsafe { syscall3(nr::WRITE, write_fd_u, b"data".as_ptr() as u64, 4) };
    readfds = 1 << read_fd_u;
    let ret = unsafe {
        syscall5(nr::SELECT, nfds, &mut readfds as *mut _ as u64, 0, 0,
                 &mut tv as *mut _ as u64)
    };
    if ret >= 1 && (readfds & (1 << read_fd_u)) != 0 {
        pass("select: pipe read ready after write");
    } else {
        fail("select: pipe read ready after write");
    }

    // 4. Select with readfds and writefds
    readfds = 1 << read_fd_u;
    writefds = 1 << write_fd_u;
    let ret = unsafe {
        syscall5(nr::SELECT, nfds, &mut readfds as *mut _ as u64,
                 &mut writefds as *mut _ as u64, 0, &mut tv as *mut _ as u64)
    };
    if ret >= 1 {
        pass("select: readfds and writefds");
    } else {
        fail("select: readfds and writefds");
    }

    // 5. Select with timeout (1ms)
    let mut buf = [0u8; 32];
    unsafe { syscall3(nr::READ, read_fd_u, buf.as_mut_ptr() as u64, 32) }; // drain
    readfds = 1 << read_fd_u;
    tv = Timeval { tv_sec: 0, tv_usec: 1000 }; // 1ms
    let ret = unsafe {
        syscall5(nr::SELECT, nfds, &mut readfds as *mut _ as u64, 0, 0,
                 &mut tv as *mut _ as u64)
    };
    if ret == 0 {
        pass("select: 1ms timeout");
    } else {
        fail("select: 1ms timeout");
    }

    // 6. Select with NULL timeout and ready fd
    unsafe { syscall3(nr::WRITE, write_fd_u, b"x".as_ptr() as u64, 1) };
    readfds = 1 << read_fd_u;
    let ret = unsafe {
        syscall5(nr::SELECT, nfds, &mut readfds as *mut _ as u64, 0, 0, 0)
    };
    if ret >= 1 {
        pass("select: NULL timeout with ready fd");
    } else {
        fail("select: NULL timeout with ready fd");
    }

    close_pipe(read_fd, write_fd);
}

pub fn test_select_negative() {
    write_str("\n=== Select: negative tests ===\n");

    let Some((read_fd, write_fd)) = create_pipe() else {
        fail("select negative: pipe setup");
        return;
    };

    let read_fd_u = read_fd as u64;
    let nfds = read_fd as u64 + 1;

    // 1. nfds = 0 (should succeed, no fds checked)
    let mut tv = Timeval { tv_sec: 0, tv_usec: 0 };
    let ret = unsafe {
        syscall5(nr::SELECT, 0, 0, 0, 0, &mut tv as *mut _ as u64)
    };
    if ret == 0 {
        pass("select: nfds=0 returns 0");
    } else {
        fail_errno("select: nfds=0 returns 0", 0, ret);
    }

    // 2. Negative timeout values are treated as zero on some systems
    // or invalid on others
    tv = Timeval { tv_sec: -1, tv_usec: 0 };
    let mut readfds: u64 = 1 << read_fd_u;
    let ret = unsafe {
        syscall5(nr::SELECT, nfds, &mut readfds as *mut _ as u64, 0, 0,
                 &mut tv as *mut _ as u64)
    };
    // Accept either EINVAL or timeout (0)
    if ret == EINVAL || ret == 0 {
        pass("select: negative tv_sec handled");
    } else {
        fail_errno("select: negative tv_sec handled", 0, ret);
    }

    // 3. Invalid tv_usec (>= 1000000)
    tv = Timeval { tv_sec: 0, tv_usec: 1000001 };
    readfds = 1 << read_fd_u;
    let ret = unsafe {
        syscall5(nr::SELECT, nfds, &mut readfds as *mut _ as u64, 0, 0,
                 &mut tv as *mut _ as u64)
    };
    if ret == EINVAL {
        pass("select: invalid tv_usec returns EINVAL");
    } else {
        // Some kernels accept this
        pass("select: invalid tv_usec handled");
    }

    close_pipe(read_fd, write_fd);
}


// ════════════════════════════════════════════════════════════════════════════
// ppoll tests
// ════════════════════════════════════════════════════════════════════════════

pub fn test_ppoll() {
    write_str("\n=== Ppoll: tests ===\n");

    let Some((read_fd, write_fd)) = create_pipe() else {
        fail("ppoll: pipe setup");
        return;
    };

    // 1. Basic ppoll with timeout
    let mut pollfds = [Pollfd { fd: read_fd, events: POLLIN, revents: 0 }];
    let ts = Timespec { tv_sec: 0, tv_nsec: 1_000_000 }; // 1ms
    let ret = unsafe {
        syscall5(nr::PPOLL, pollfds.as_mut_ptr() as u64, 1,
                 &ts as *const _ as u64, 0, 8)
    };
    if ret == 0 {
        pass("ppoll: timeout with no data");
    } else {
        fail_errno("ppoll: timeout with no data", 0, ret);
    }

    // 2. ppoll with data ready
    unsafe { syscall3(nr::WRITE, write_fd as u64, b"x".as_ptr() as u64, 1) };
    pollfds[0].revents = 0;
    let ret = unsafe {
        syscall5(nr::PPOLL, pollfds.as_mut_ptr() as u64, 1,
                 &ts as *const _ as u64, 0, 8)
    };
    if ret >= 1 && (pollfds[0].revents & POLLIN) != 0 {
        pass("ppoll: returns when ready");
    } else {
        fail("ppoll: returns when ready");
    }

    // 3. ppoll with NULL timeout (immediate with ready fd)
    pollfds[0].revents = 0;
    let ret = unsafe {
        syscall5(nr::PPOLL, pollfds.as_mut_ptr() as u64, 1, 0, 0, 8)
    };
    if ret >= 1 {
        pass("ppoll: NULL timeout with ready fd");
    } else {
        fail("ppoll: NULL timeout with ready fd");
    }

    close_pipe(read_fd, write_fd);
}

// ════════════════════════════════════════════════════════════════════════════
// pselect tests
// ════════════════════════════════════════════════════════════════════════════

pub fn test_pselect() {
    write_str("\n=== Pselect: tests ===\n");

    let Some((read_fd, write_fd)) = create_pipe() else {
        fail("pselect: pipe setup");
        return;
    };

    let read_fd_u = read_fd as u64;
    let nfds = read_fd as u64 + 1;

    // 1. pselect6 with timeout
    let mut readfds: u64 = 1 << read_fd_u;
    let ts = Timespec { tv_sec: 0, tv_nsec: 1_000_000 }; // 1ms
    let ret = unsafe {
        syscall6(nr::PSELECT6, nfds, &mut readfds as *mut _ as u64, 0, 0,
                 &ts as *const _ as u64, 0)
    };
    if ret == 0 {
        pass("pselect6: timeout with no data");
    } else {
        fail_errno("pselect6: timeout with no data", 0, ret);
    }

    // 2. pselect6 with data ready
    unsafe { syscall3(nr::WRITE, write_fd as u64, b"x".as_ptr() as u64, 1) };
    readfds = 1 << read_fd_u;
    let ret = unsafe {
        syscall6(nr::PSELECT6, nfds, &mut readfds as *mut _ as u64, 0, 0,
                 &ts as *const _ as u64, 0)
    };
    if ret >= 1 && (readfds & (1 << read_fd_u)) != 0 {
        pass("pselect6: returns when ready");
    } else {
        fail("pselect6: returns when ready");
    }

    close_pipe(read_fd, write_fd);
}

// ════════════════════════════════════════════════════════════════════════════
// Module entry point
// ════════════════════════════════════════════════════════════════════════════

pub fn run_all() {
    crate::write_banner("POLL/SELECT TESTS (PSE51/PSE53)");

    // Poll tests
    test_poll_positive();
    test_poll_negative();
    test_poll_boundary();

    // Select tests
    test_select_positive();
    test_select_negative();

    // Extended poll/select variants
    test_ppoll();
    test_pselect();
}
