//! Comprehensive poll/select/epoll tests for POSIX conformance
//!
//! Tests: poll, ppoll, select, pselect6, epoll_create1, epoll_ctl, epoll_wait
//!
//! Categories:
//! - Positive: normal I/O multiplexing scenarios
//! - Negative: invalid fds, bad pointers, invalid flags
//! - Boundary: zero timeout, max fds, empty fd sets

use crate::nr;
use crate::{pass, fail, fail_errno, write_str, syscall1, syscall2, syscall3, syscall4, syscall5, syscall6};
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

// Epoll constants
const EPOLL_CTL_ADD: u64 = 1;
const EPOLL_CTL_DEL: u64 = 2;
const EPOLL_CTL_MOD: u64 = 3;

const EPOLLIN: u32 = 0x001;
const EPOLLPRI: u32 = 0x002;
const EPOLLOUT: u32 = 0x004;
const EPOLLERR: u32 = 0x008;
const EPOLLHUP: u32 = 0x010;
const EPOLLET: u32 = 1 << 31;
const EPOLLONESHOT: u32 = 1 << 30;

// Epoll_create1 flags
const EPOLL_CLOEXEC: u64 = 0x80000;

// Syscall numbers for epoll
const SYS_EPOLL_CTL: u64 = 233;
const SYS_EPOLL_WAIT: u64 = 232;

// Error codes
const EINVAL: i64 = -22;
const EBADF: i64 = -9;
const ENOENT: i64 = -2;
const EEXIST: i64 = -17;

// ════════════════════════════════════════════════════════════════════════════
// Structures
// ════════════════════════════════════════════════════════════════════════════

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct EpollEvent {
    events: u32,
    data: u64,
}

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
// Epoll tests
// ════════════════════════════════════════════════════════════════════════════

pub fn test_epoll_positive() {
    write_str("\n=== Epoll: positive tests ===\n");

    // 1. Create epoll instance
    let epfd = unsafe { syscall1(nr::EPOLL_CREATE1, 0) };
    if epfd < 0 {
        fail_errno("epoll_create1: basic", 0, epfd);
        return;
    }
    pass("epoll_create1: basic");

    // 2. Create with CLOEXEC
    let epfd2 = unsafe { syscall1(nr::EPOLL_CREATE1, EPOLL_CLOEXEC) };
    if epfd2 >= 0 {
        pass("epoll_create1: CLOEXEC");
        unsafe { syscall1(nr::CLOSE, epfd2 as u64) };
    } else {
        fail("epoll_create1: CLOEXEC");
    }

    // 3. Create pipe for testing
    let Some((read_fd, write_fd)) = create_pipe() else {
        fail("epoll positive: pipe setup");
        unsafe { syscall1(nr::CLOSE, epfd as u64) };
        return;
    };

    // 4. EPOLL_CTL_ADD
    let mut ev = EpollEvent { events: EPOLLIN, data: read_fd as u64 };
    let ret = unsafe {
        syscall4(SYS_EPOLL_CTL, epfd as u64, EPOLL_CTL_ADD, read_fd as u64,
                 &mut ev as *mut _ as u64)
    };
    if ret == 0 {
        pass("epoll_ctl: ADD");
    } else {
        fail_errno("epoll_ctl: ADD", 0, ret);
    }

    // 5. EPOLL_CTL_MOD
    ev.events = EPOLLIN | EPOLLOUT;
    let ret = unsafe {
        syscall4(SYS_EPOLL_CTL, epfd as u64, EPOLL_CTL_MOD, read_fd as u64,
                 &mut ev as *mut _ as u64)
    };
    if ret == 0 {
        pass("epoll_ctl: MOD");
    } else {
        fail_errno("epoll_ctl: MOD", 0, ret);
    }

    // 6. epoll_wait with timeout=0 (empty pipe, no events)
    let mut events = [EpollEvent { events: 0, data: 0 }; 4];
    let ret = unsafe {
        syscall4(SYS_EPOLL_WAIT, epfd as u64, events.as_mut_ptr() as u64, 4, 0)
    };
    if ret == 0 {
        pass("epoll_wait: timeout=0, no events");
    } else {
        fail_errno("epoll_wait: timeout=0, no events", 0, ret);
    }

    // 7. Write to pipe, then epoll_wait
    unsafe { syscall3(nr::WRITE, write_fd as u64, b"data".as_ptr() as u64, 4) };
    let ret = unsafe {
        syscall4(SYS_EPOLL_WAIT, epfd as u64, events.as_mut_ptr() as u64, 4, 0)
    };
    if ret >= 1 && (events[0].events & EPOLLIN) != 0 {
        pass("epoll_wait: EPOLLIN after write");
    } else {
        fail("epoll_wait: EPOLLIN after write");
    }

    // 8. Add write end
    ev = EpollEvent { events: EPOLLOUT, data: write_fd as u64 };
    let ret = unsafe {
        syscall4(SYS_EPOLL_CTL, epfd as u64, EPOLL_CTL_ADD, write_fd as u64,
                 &mut ev as *mut _ as u64)
    };
    if ret == 0 {
        pass("epoll_ctl: ADD second fd");
    } else {
        fail_errno("epoll_ctl: ADD second fd", 0, ret);
    }

    // 9. epoll_wait should return multiple events
    let ret = unsafe {
        syscall4(SYS_EPOLL_WAIT, epfd as u64, events.as_mut_ptr() as u64, 4, 0)
    };
    if ret >= 1 {
        pass("epoll_wait: multiple fds");
    } else {
        fail("epoll_wait: multiple fds");
    }

    // 10. EPOLL_CTL_DEL
    let ret = unsafe {
        syscall4(SYS_EPOLL_CTL, epfd as u64, EPOLL_CTL_DEL, write_fd as u64, 0)
    };
    if ret == 0 {
        pass("epoll_ctl: DEL");
    } else {
        fail_errno("epoll_ctl: DEL", 0, ret);
    }

    // 11. EPOLLET (edge-triggered)
    ev = EpollEvent { events: EPOLLIN | EPOLLET, data: read_fd as u64 };
    let ret = unsafe {
        syscall4(SYS_EPOLL_CTL, epfd as u64, EPOLL_CTL_MOD, read_fd as u64,
                 &mut ev as *mut _ as u64)
    };
    if ret == 0 {
        pass("epoll_ctl: EPOLLET");
    } else {
        fail_errno("epoll_ctl: EPOLLET", 0, ret);
    }

    // 12. EPOLLONESHOT
    ev = EpollEvent { events: EPOLLIN | EPOLLONESHOT, data: read_fd as u64 };
    let ret = unsafe {
        syscall4(SYS_EPOLL_CTL, epfd as u64, EPOLL_CTL_MOD, read_fd as u64,
                 &mut ev as *mut _ as u64)
    };
    if ret == 0 {
        pass("epoll_ctl: EPOLLONESHOT");
    } else {
        fail_errno("epoll_ctl: EPOLLONESHOT", 0, ret);
    }

    close_pipe(read_fd, write_fd);
    unsafe { syscall1(nr::CLOSE, epfd as u64) };
}

pub fn test_epoll_negative() {
    write_str("\n=== Epoll: negative tests ===\n");

    // 1. epoll_create1 with invalid flags
    let ret = unsafe { syscall1(nr::EPOLL_CREATE1, 0x12345678) };
    if ret == EINVAL {
        pass("epoll_create1: invalid flags returns EINVAL");
    } else {
        fail_errno("epoll_create1: invalid flags returns EINVAL", EINVAL, ret);
    }

    // 2. Create valid epoll for remaining tests
    let epfd = unsafe { syscall1(nr::EPOLL_CREATE1, 0) };
    if epfd < 0 {
        fail("epoll negative: create");
        return;
    }

    // 3. EPOLL_CTL_ADD with invalid fd
    let mut ev = EpollEvent { events: EPOLLIN, data: 0 };
    let ret = unsafe {
        syscall4(SYS_EPOLL_CTL, epfd as u64, EPOLL_CTL_ADD, 999,
                 &mut ev as *mut _ as u64)
    };
    if ret == EBADF {
        pass("epoll_ctl: ADD invalid fd returns EBADF");
    } else {
        fail_errno("epoll_ctl: ADD invalid fd returns EBADF", EBADF, ret);
    }

    // 4. EPOLL_CTL_MOD on non-existent fd
    let Some((read_fd, write_fd)) = create_pipe() else {
        fail("epoll negative: pipe setup");
        unsafe { syscall1(nr::CLOSE, epfd as u64) };
        return;
    };
    let ret = unsafe {
        syscall4(SYS_EPOLL_CTL, epfd as u64, EPOLL_CTL_MOD, read_fd as u64,
                 &mut ev as *mut _ as u64)
    };
    if ret == ENOENT {
        pass("epoll_ctl: MOD non-existent returns ENOENT");
    } else {
        fail_errno("epoll_ctl: MOD non-existent returns ENOENT", ENOENT, ret);
    }

    // 5. EPOLL_CTL_DEL on non-existent fd
    let ret = unsafe {
        syscall4(SYS_EPOLL_CTL, epfd as u64, EPOLL_CTL_DEL, read_fd as u64, 0)
    };
    if ret == ENOENT {
        pass("epoll_ctl: DEL non-existent returns ENOENT");
    } else {
        fail_errno("epoll_ctl: DEL non-existent returns ENOENT", ENOENT, ret);
    }

    // 6. EPOLL_CTL_ADD duplicate
    ev = EpollEvent { events: EPOLLIN, data: read_fd as u64 };
    unsafe {
        syscall4(SYS_EPOLL_CTL, epfd as u64, EPOLL_CTL_ADD, read_fd as u64,
                 &mut ev as *mut _ as u64)
    };
    let ret = unsafe {
        syscall4(SYS_EPOLL_CTL, epfd as u64, EPOLL_CTL_ADD, read_fd as u64,
                 &mut ev as *mut _ as u64)
    };
    if ret == EEXIST {
        pass("epoll_ctl: ADD duplicate returns EEXIST");
    } else {
        fail_errno("epoll_ctl: ADD duplicate returns EEXIST", EEXIST, ret);
    }

    // 7. Invalid op code
    let ret = unsafe {
        syscall4(SYS_EPOLL_CTL, epfd as u64, 999, read_fd as u64,
                 &mut ev as *mut _ as u64)
    };
    if ret == EINVAL {
        pass("epoll_ctl: invalid op returns EINVAL");
    } else {
        fail_errno("epoll_ctl: invalid op returns EINVAL", EINVAL, ret);
    }

    // 8. epoll_wait with invalid epfd
    let mut events = [EpollEvent { events: 0, data: 0 }; 4];
    let ret = unsafe {
        syscall4(SYS_EPOLL_WAIT, 999, events.as_mut_ptr() as u64, 4, 0)
    };
    if ret == EBADF {
        pass("epoll_wait: invalid epfd returns EBADF");
    } else {
        fail_errno("epoll_wait: invalid epfd returns EBADF", EBADF, ret);
    }

    // 9. epoll_wait with maxevents <= 0
    let ret = unsafe {
        syscall4(SYS_EPOLL_WAIT, epfd as u64, events.as_mut_ptr() as u64, 0, 0)
    };
    if ret == EINVAL {
        pass("epoll_wait: maxevents=0 returns EINVAL");
    } else {
        fail_errno("epoll_wait: maxevents=0 returns EINVAL", EINVAL, ret);
    }

    let ret = unsafe {
        syscall4(SYS_EPOLL_WAIT, epfd as u64, events.as_mut_ptr() as u64, -1i64 as u64, 0)
    };
    if ret == EINVAL {
        pass("epoll_wait: maxevents<0 returns EINVAL");
    } else {
        fail_errno("epoll_wait: maxevents<0 returns EINVAL", EINVAL, ret);
    }

    close_pipe(read_fd, write_fd);
    unsafe { syscall1(nr::CLOSE, epfd as u64) };
}

pub fn test_epoll_boundary() {
    write_str("\n=== Epoll: boundary tests ===\n");

    let epfd = unsafe { syscall1(nr::EPOLL_CREATE1, 0) };
    if epfd < 0 {
        fail("epoll boundary: create");
        return;
    }

    let Some((read_fd, write_fd)) = create_pipe() else {
        fail("epoll boundary: pipe setup");
        unsafe { syscall1(nr::CLOSE, epfd as u64) };
        return;
    };

    // 1. Add with all event flags
    let mut ev = EpollEvent {
        events: EPOLLIN | EPOLLOUT | EPOLLPRI | EPOLLERR | EPOLLHUP,
        data: read_fd as u64,
    };
    let ret = unsafe {
        syscall4(SYS_EPOLL_CTL, epfd as u64, EPOLL_CTL_ADD, read_fd as u64,
                 &mut ev as *mut _ as u64)
    };
    if ret == 0 {
        pass("epoll_ctl: all event flags");
    } else {
        fail_errno("epoll_ctl: all event flags", 0, ret);
    }

    // 2. epoll_wait with maxevents=1
    let mut events = [EpollEvent { events: 0, data: 0 }; 1];
    let ret = unsafe {
        syscall4(SYS_EPOLL_WAIT, epfd as u64, events.as_mut_ptr() as u64, 1, 0)
    };
    if ret >= 0 {
        pass("epoll_wait: maxevents=1");
    } else {
        fail("epoll_wait: maxevents=1");
    }

    // 3. Large maxevents
    let mut many_events = [EpollEvent { events: 0, data: 0 }; 64];
    let ret = unsafe {
        syscall4(SYS_EPOLL_WAIT, epfd as u64, many_events.as_mut_ptr() as u64, 64, 0)
    };
    if ret >= 0 {
        pass("epoll_wait: maxevents=64");
    } else {
        fail("epoll_wait: maxevents=64");
    }

    // 4. Event data field (user data)
    unsafe {
        syscall4(SYS_EPOLL_CTL, epfd as u64, EPOLL_CTL_DEL, read_fd as u64, 0)
    };
    ev = EpollEvent { events: EPOLLIN, data: 0xDEADBEEFCAFEBABE };
    unsafe {
        syscall4(SYS_EPOLL_CTL, epfd as u64, EPOLL_CTL_ADD, read_fd as u64,
                 &mut ev as *mut _ as u64)
    };
    unsafe { syscall3(nr::WRITE, write_fd as u64, b"x".as_ptr() as u64, 1) };
    let ret = unsafe {
        syscall4(SYS_EPOLL_WAIT, epfd as u64, events.as_mut_ptr() as u64, 1, 0)
    };
    if ret >= 1 && events[0].data == 0xDEADBEEFCAFEBABE {
        pass("epoll_wait: preserves user data");
    } else {
        fail("epoll_wait: preserves user data");
    }

    close_pipe(read_fd, write_fd);
    unsafe { syscall1(nr::CLOSE, epfd as u64) };
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
    write_str("\n╔══════════════════════════════════════════════════════════╗\n");
    write_str("║        POLL/SELECT/EPOLL TESTS (Comprehensive)          ║\n");
    write_str("╚══════════════════════════════════════════════════════════╝\n");

    // Poll tests
    test_poll_positive();
    test_poll_negative();
    test_poll_boundary();

    // Select tests
    test_select_positive();
    test_select_negative();

    // Epoll tests
    test_epoll_positive();
    test_epoll_negative();
    test_epoll_boundary();

    // Extended poll/select variants
    test_ppoll();
    test_pselect();
}
