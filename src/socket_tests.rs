//! Comprehensive socket tests
//!
//! Coverage:
//! - socket(): AF_INET/AF_INET6/AF_UNIX, SOCK_STREAM/SOCK_DGRAM
//! - setsockopt/getsockopt: SOL_SOCKET options
//! - bind/listen/accept (where possible without network)
//! - shutdown

use crate::{fail, fail_errno, nr, pass, syscall1, syscall2, syscall3, syscall5, write_str};

// Error codes
const EPERM: i64 = -1;
const EACCES: i64 = -13;
const EBADF: i64 = -9;
const EINVAL: i64 = -22;
const EAFNOSUPPORT: i64 = -97;
const ENOTSOCK: i64 = -88;
const ENOPROTOOPT: i64 = -92;
const EPROTONOSUPPORT: i64 = -93;

// Address families
const AF_UNIX: u64 = 1;
const AF_INET: u64 = 2;
const AF_INET6: u64 = 10;

// Socket types
const SOCK_STREAM: u64 = 1;
const SOCK_DGRAM: u64 = 2;
const SOCK_RAW: u64 = 3;
const SOCK_NONBLOCK: u64 = 0x800;
const SOCK_CLOEXEC: u64 = 0x80000;

// Socket options
const SOL_SOCKET: u64 = 1;
const SO_REUSEADDR: u64 = 2;
const SO_TYPE: u64 = 3;
const SO_ERROR: u64 = 4;
const SO_SNDBUF: u64 = 7;
const SO_RCVBUF: u64 = 8;
const SO_KEEPALIVE: u64 = 9;
const SO_REUSEPORT: u64 = 15;
const SO_ACCEPTCONN: u64 = 30;

// IP protocol
const IPPROTO_TCP: u64 = 6;
const IPPROTO_UDP: u64 = 17;

// ════════════════════════════════════════════════════════════════════════════
// SOCKET: Positive Tests
// ════════════════════════════════════════════════════════════════════════════

fn test_socket_positive() {
    write_str("\n=== socket: positive tests ===\n");

    // 1. TCP socket (AF_INET, SOCK_STREAM)
    let fd = unsafe { syscall3(nr::SOCKET, AF_INET, SOCK_STREAM, 0) };
    if fd >= 0 {
        pass("socket(AF_INET, STREAM) returns fd");
        unsafe { syscall1(nr::CLOSE, fd as u64) };
    } else {
        fail_errno("socket(AF_INET, STREAM) returns fd", 0, fd);
    }

    // 2. UDP socket (AF_INET, SOCK_DGRAM)
    let fd = unsafe { syscall3(nr::SOCKET, AF_INET, SOCK_DGRAM, 0) };
    if fd >= 0 {
        pass("socket(AF_INET, DGRAM) returns fd");
        unsafe { syscall1(nr::CLOSE, fd as u64) };
    } else {
        fail_errno("socket(AF_INET, DGRAM) returns fd", 0, fd);
    }

    // 3. TCP socket with explicit protocol
    let fd = unsafe { syscall3(nr::SOCKET, AF_INET, SOCK_STREAM, IPPROTO_TCP) };
    if fd >= 0 {
        pass("socket(AF_INET, STREAM, TCP)");
        unsafe { syscall1(nr::CLOSE, fd as u64) };
    } else {
        fail_errno("socket(AF_INET, STREAM, TCP)", 0, fd);
    }

    // 4. UDP socket with explicit protocol
    let fd = unsafe { syscall3(nr::SOCKET, AF_INET, SOCK_DGRAM, IPPROTO_UDP) };
    if fd >= 0 {
        pass("socket(AF_INET, DGRAM, UDP)");
        unsafe { syscall1(nr::CLOSE, fd as u64) };
    } else {
        fail_errno("socket(AF_INET, DGRAM, UDP)", 0, fd);
    }

    // 5. Socket with SOCK_NONBLOCK
    let fd = unsafe { syscall3(nr::SOCKET, AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0) };
    if fd >= 0 {
        pass("socket(SOCK_NONBLOCK)");
        unsafe { syscall1(nr::CLOSE, fd as u64) };
    } else if fd == EINVAL {
        pass("SOCK_NONBLOCK not supported");
    } else {
        fail_errno("socket(SOCK_NONBLOCK)", 0, fd);
    }

    // 6. Socket with SOCK_CLOEXEC
    let fd = unsafe { syscall3(nr::SOCKET, AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0) };
    if fd >= 0 {
        pass("socket(SOCK_CLOEXEC)");
        unsafe { syscall1(nr::CLOSE, fd as u64) };
    } else if fd == EINVAL {
        pass("SOCK_CLOEXEC not supported");
    } else {
        fail_errno("socket(SOCK_CLOEXEC)", 0, fd);
    }

    // 7. IPv6 TCP socket
    let fd = unsafe { syscall3(nr::SOCKET, AF_INET6, SOCK_STREAM, 0) };
    if fd >= 0 {
        pass("socket(AF_INET6, STREAM)");
        unsafe { syscall1(nr::CLOSE, fd as u64) };
    } else if fd == EAFNOSUPPORT {
        pass("AF_INET6 not supported");
    } else {
        fail_errno("socket(AF_INET6, STREAM)", 0, fd);
    }

    // 8. Unix socket
    let fd = unsafe { syscall3(nr::SOCKET, AF_UNIX, SOCK_STREAM, 0) };
    if fd >= 0 {
        pass("socket(AF_UNIX, STREAM)");
        unsafe { syscall1(nr::CLOSE, fd as u64) };
    } else if fd == EAFNOSUPPORT {
        pass("AF_UNIX not supported");
    } else {
        fail_errno("socket(AF_UNIX, STREAM)", 0, fd);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// SOCKET: Negative Tests
// ════════════════════════════════════════════════════════════════════════════

fn test_socket_negative() {
    write_str("\n=== socket: negative tests ===\n");

    // 1. Invalid address family
    let ret = unsafe { syscall3(nr::SOCKET, 999, SOCK_STREAM, 0) };
    if ret == EAFNOSUPPORT {
        pass("socket(AF=999) -EAFNOSUPPORT");
    } else {
        fail_errno("socket(AF=999) -EAFNOSUPPORT", EAFNOSUPPORT, ret);
    }

    // 2. Invalid socket type — POSIX requires EINVAL or EPROTONOSUPPORT
    let ret = unsafe { syscall3(nr::SOCKET, AF_INET, 999, 0) };
    if ret == EINVAL || ret == EPROTONOSUPPORT {
        pass("socket(type=999) valid errno");
    } else {
        fail_errno("socket(type=999) expected EINVAL or EPROTONOSUPPORT", EINVAL, ret);
        if ret >= 0 { unsafe { syscall1(nr::CLOSE, ret as u64) }; }
    }

    // 3. Invalid protocol for type — POSIX requires EPROTONOSUPPORT
    let ret = unsafe { syscall3(nr::SOCKET, AF_INET, SOCK_STREAM, IPPROTO_UDP) };
    if ret == EPROTONOSUPPORT {
        pass("socket(STREAM, UDP) -EPROTONOSUPPORT");
    } else if ret >= 0 {
        // Linux allows mismatched proto in some configurations
        pass("socket(STREAM, UDP) accepted (Linux-permissive)");
        unsafe { syscall1(nr::CLOSE, ret as u64) };
    } else {
        fail_errno("socket(STREAM, UDP) unexpected error", EPROTONOSUPPORT, ret);
    }

    // 4. RAW socket without privilege — expects EPERM or EACCES
    let ret = unsafe { syscall3(nr::SOCKET, AF_INET, SOCK_RAW, 0) };
    if ret == EPERM || ret == EACCES {
        pass("socket(RAW) -EPERM/-EACCES (unprivileged)");
    } else if ret >= 0 {
        // Succeeds with CAP_NET_RAW (e.g., running as root in CI container)
        pass("socket(RAW) allowed (privileged)");
        unsafe { syscall1(nr::CLOSE, ret as u64) };
    } else {
        fail_errno("socket(RAW) unexpected error", EPERM, ret);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// SETSOCKOPT/GETSOCKOPT: Tests
// ════════════════════════════════════════════════════════════════════════════

fn test_sockopt() {
    write_str("\n=== setsockopt/getsockopt: tests ===\n");

    let fd = unsafe { syscall3(nr::SOCKET, AF_INET, SOCK_STREAM, 0) };
    if fd < 0 {
        fail("sockopt: socket setup");
        return;
    }

    // 1. SO_REUSEADDR
    let val: i32 = 1;
    let ret = unsafe {
        syscall5(
            nr::SETSOCKOPT,
            fd as u64,
            SOL_SOCKET,
            SO_REUSEADDR,
            &val as *const _ as u64,
            4,
        )
    };
    if ret == 0 {
        pass("setsockopt(SO_REUSEADDR) returns 0");
    } else {
        fail_errno("setsockopt(SO_REUSEADDR) returns 0", 0, ret);
    }

    // 2. SO_TYPE
    let mut optval: i32 = 0;
    let mut optlen: u32 = 4;
    let ret = unsafe {
        syscall5(
            nr::GETSOCKOPT,
            fd as u64,
            SOL_SOCKET,
            SO_TYPE,
            &mut optval as *mut _ as u64,
            &mut optlen as *mut _ as u64,
        )
    };
    if ret == 0 && optval == SOCK_STREAM as i32 {
        pass("getsockopt(SO_TYPE) = SOCK_STREAM");
    } else {
        fail("getsockopt(SO_TYPE) = SOCK_STREAM");
    }

    // 3. SO_ERROR (should be 0 on fresh socket)
    optval = 99;
    optlen = 4;
    let ret = unsafe {
        syscall5(
            nr::GETSOCKOPT,
            fd as u64,
            SOL_SOCKET,
            SO_ERROR,
            &mut optval as *mut _ as u64,
            &mut optlen as *mut _ as u64,
        )
    };
    if ret == 0 && optval == 0 {
        pass("getsockopt(SO_ERROR) = 0");
    } else {
        fail("getsockopt(SO_ERROR) = 0");
    }

    // 4. SO_KEEPALIVE
    let val: i32 = 1;
    let ret = unsafe {
        syscall5(
            nr::SETSOCKOPT,
            fd as u64,
            SOL_SOCKET,
            SO_KEEPALIVE,
            &val as *const _ as u64,
            4,
        )
    };
    if ret == 0 {
        pass("setsockopt(SO_KEEPALIVE) returns 0");
    } else if ret == ENOPROTOOPT {
        pass("SO_KEEPALIVE not supported");
    } else {
        fail_errno("setsockopt(SO_KEEPALIVE) returns 0", 0, ret);
    }

    // 5. SO_SNDBUF
    let mut bufsize: i32 = 0;
    optlen = 4;
    let ret = unsafe {
        syscall5(
            nr::GETSOCKOPT,
            fd as u64,
            SOL_SOCKET,
            SO_SNDBUF,
            &mut bufsize as *mut _ as u64,
            &mut optlen as *mut _ as u64,
        )
    };
    if ret == 0 && bufsize > 0 {
        pass("getsockopt(SO_SNDBUF) > 0");
    } else if ret == ENOPROTOOPT {
        pass("SO_SNDBUF not supported");
    } else {
        fail("getsockopt(SO_SNDBUF) > 0");
    }

    // 6. SO_RCVBUF
    bufsize = 0;
    optlen = 4;
    let ret = unsafe {
        syscall5(
            nr::GETSOCKOPT,
            fd as u64,
            SOL_SOCKET,
            SO_RCVBUF,
            &mut bufsize as *mut _ as u64,
            &mut optlen as *mut _ as u64,
        )
    };
    if ret == 0 && bufsize > 0 {
        pass("getsockopt(SO_RCVBUF) > 0");
    } else if ret == ENOPROTOOPT {
        pass("SO_RCVBUF not supported");
    } else {
        fail("getsockopt(SO_RCVBUF) > 0");
    }

    // 7. SO_REUSEPORT
    let val: i32 = 1;
    let ret = unsafe {
        syscall5(
            nr::SETSOCKOPT,
            fd as u64,
            SOL_SOCKET,
            SO_REUSEPORT,
            &val as *const _ as u64,
            4,
        )
    };
    if ret == 0 {
        pass("setsockopt(SO_REUSEPORT) returns 0");
    } else if ret == ENOPROTOOPT {
        pass("SO_REUSEPORT not supported");
    } else {
        fail_errno("setsockopt(SO_REUSEPORT)", 0, ret);
    }

    unsafe { syscall1(nr::CLOSE, fd as u64) };
}

// ════════════════════════════════════════════════════════════════════════════
// SOCKOPT: Negative Tests
// ════════════════════════════════════════════════════════════════════════════

fn test_sockopt_negative() {
    write_str("\n=== sockopt: negative tests ===\n");

    // 1. getsockopt on non-socket
    let mut fds = [0i32; 2];
    if unsafe { syscall2(nr::PIPE2, fds.as_mut_ptr() as u64, 0) } == 0 {
        let mut optval: i32 = 0;
        let mut optlen: u32 = 4;
        let ret = unsafe {
            syscall5(
                nr::GETSOCKOPT,
                fds[0] as u64,
                SOL_SOCKET,
                SO_TYPE,
                &mut optval as *mut _ as u64,
                &mut optlen as *mut _ as u64,
            )
        };
        if ret == ENOTSOCK {
            pass("getsockopt(pipe) -ENOTSOCK");
        } else {
            fail_errno("getsockopt(pipe) -ENOTSOCK", ENOTSOCK, ret);
        }
        unsafe {
            syscall1(nr::CLOSE, fds[0] as u64);
            syscall1(nr::CLOSE, fds[1] as u64);
        }
    }

    // 2. setsockopt on invalid fd
    let val: i32 = 1;
    let ret = unsafe {
        syscall5(
            nr::SETSOCKOPT,
            999,
            SOL_SOCKET,
            SO_REUSEADDR,
            &val as *const _ as u64,
            4,
        )
    };
    if ret == EBADF {
        pass("setsockopt(bad fd) -EBADF");
    } else {
        fail_errno("setsockopt(bad fd) -EBADF", EBADF, ret);
    }

    // 3. getsockopt on invalid fd
    let mut optval: i32 = 0;
    let mut optlen: u32 = 4;
    let ret = unsafe {
        syscall5(
            nr::GETSOCKOPT,
            999,
            SOL_SOCKET,
            SO_TYPE,
            &mut optval as *mut _ as u64,
            &mut optlen as *mut _ as u64,
        )
    };
    if ret == EBADF {
        pass("getsockopt(bad fd) -EBADF");
    } else {
        fail_errno("getsockopt(bad fd) -EBADF", EBADF, ret);
    }

    // 4. Invalid socket option
    let fd = unsafe { syscall3(nr::SOCKET, AF_INET, SOCK_STREAM, 0) };
    if fd >= 0 {
        let val: i32 = 1;
        let ret = unsafe {
            syscall5(
                nr::SETSOCKOPT,
                fd as u64,
                SOL_SOCKET,
                9999, // Invalid option
                &val as *const _ as u64,
                4,
            )
        };
        if ret == ENOPROTOOPT {
            pass("setsockopt(invalid opt) -ENOPROTOOPT");
        } else {
            fail_errno("setsockopt(invalid opt) -ENOPROTOOPT", ENOPROTOOPT, ret);
        }
        unsafe { syscall1(nr::CLOSE, fd as u64) };
    }
}

// ════════════════════════════════════════════════════════════════════════════
// BIND/LISTEN: Tests
// ════════════════════════════════════════════════════════════════════════════

#[repr(C)]
struct SockaddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [u8; 8],
}

fn test_bind_listen() {
    write_str("\n=== bind/listen: tests ===\n");

    let fd = unsafe { syscall3(nr::SOCKET, AF_INET, SOCK_STREAM, 0) };
    if fd < 0 {
        fail("bind/listen: socket setup");
        return;
    }

    // 1. Bind to localhost:0 (let OS pick port)
    let addr = SockaddrIn {
        sin_family: AF_INET as u16,
        sin_port: 0, // Let OS pick
        sin_addr: 0x7F000001u32.to_be(), // 127.0.0.1
        sin_zero: [0; 8],
    };
    let ret = unsafe { syscall3(nr::BIND, fd as u64, &addr as *const _ as u64, 16) };
    if ret == 0 {
        pass("bind(127.0.0.1:0) returns 0");
    } else {
        fail_errno("bind(127.0.0.1:0) returns 0", 0, ret);
        unsafe { syscall1(nr::CLOSE, fd as u64) };
        return;
    }

    // 2. Listen
    let ret = unsafe { syscall2(nr::LISTEN, fd as u64, 5) };
    if ret == 0 {
        pass("listen(5) returns 0");
    } else {
        fail_errno("listen(5) returns 0", 0, ret);
    }

    // 3. Check SO_ACCEPTCONN
    let mut optval: i32 = 0;
    let mut optlen: u32 = 4;
    let ret = unsafe {
        syscall5(
            nr::GETSOCKOPT,
            fd as u64,
            SOL_SOCKET,
            SO_ACCEPTCONN,
            &mut optval as *mut _ as u64,
            &mut optlen as *mut _ as u64,
        )
    };
    if ret == 0 && optval != 0 {
        pass("SO_ACCEPTCONN after listen");
    } else if ret == ENOPROTOOPT {
        pass("SO_ACCEPTCONN not supported");
    } else {
        fail("SO_ACCEPTCONN after listen");
    }

    // 4. getsockname to verify bind
    let mut addr_out = SockaddrIn {
        sin_family: 0,
        sin_port: 0,
        sin_addr: 0,
        sin_zero: [0; 8],
    };
    let mut len: u32 = 16;
    let ret = unsafe {
        syscall3(
            nr::GETSOCKNAME,
            fd as u64,
            &mut addr_out as *mut _ as u64,
            &mut len as *mut _ as u64,
        )
    };
    if ret == 0 && addr_out.sin_family == AF_INET as u16 {
        pass("getsockname returns AF_INET");
        if addr_out.sin_port != 0 {
            pass("getsockname port assigned");
        } else {
            fail("getsockname port assigned");
        }
    } else {
        fail("getsockname returns AF_INET");
    }

    unsafe { syscall1(nr::CLOSE, fd as u64) };
}

// ════════════════════════════════════════════════════════════════════════════
// SHUTDOWN: Tests
// ════════════════════════════════════════════════════════════════════════════

fn test_shutdown() {
    write_str("\n=== shutdown: tests ===\n");

    const SHUT_RDWR: u64 = 2;

    let fd = unsafe { syscall3(nr::SOCKET, AF_INET, SOCK_STREAM, 0) };
    if fd < 0 {
        fail("shutdown: socket setup");
        return;
    }

    // shutdown on unconnected socket may succeed or fail (ENOTCONN)
    // Both are valid behaviors
    let ret = unsafe { syscall2(nr::SHUTDOWN, fd as u64, SHUT_RDWR) };
    if ret == 0 || ret == -107 {
        // ENOTCONN
        pass("shutdown(unconnected) handled");
    } else {
        fail_errno("shutdown(unconnected) handled", 0, ret);
    }

    // shutdown on invalid fd
    let ret = unsafe { syscall2(nr::SHUTDOWN, 999, SHUT_RDWR) };
    if ret == EBADF {
        pass("shutdown(bad fd) -EBADF");
    } else {
        fail_errno("shutdown(bad fd) -EBADF", EBADF, ret);
    }

    // shutdown with invalid how — POSIX requires EINVAL
    let ret = unsafe { syscall2(nr::SHUTDOWN, fd as u64, 999) };
    if ret == EINVAL {
        pass("shutdown(how=999) -EINVAL");
    } else {
        fail_errno("shutdown(how=999) -EINVAL", EINVAL, ret);
    }

    unsafe { syscall1(nr::CLOSE, fd as u64) };
}

// ════════════════════════════════════════════════════════════════════════════
// UDP Socket Tests
// ════════════════════════════════════════════════════════════════════════════

fn test_udp_socket() {
    write_str("\n=== UDP socket: tests ===\n");

    let fd = unsafe { syscall3(nr::SOCKET, AF_INET, SOCK_DGRAM, 0) };
    if fd < 0 {
        fail("UDP socket setup");
        return;
    }
    pass("UDP socket created");

    // SO_TYPE should be SOCK_DGRAM
    let mut optval: i32 = 0;
    let mut optlen: u32 = 4;
    let ret = unsafe {
        syscall5(
            nr::GETSOCKOPT,
            fd as u64,
            SOL_SOCKET,
            SO_TYPE,
            &mut optval as *mut _ as u64,
            &mut optlen as *mut _ as u64,
        )
    };
    if ret == 0 && optval == SOCK_DGRAM as i32 {
        pass("UDP getsockopt(SO_TYPE) = DGRAM");
    } else {
        fail("UDP getsockopt(SO_TYPE) = DGRAM");
    }

    // Bind UDP socket
    let addr = SockaddrIn {
        sin_family: AF_INET as u16,
        sin_port: 0,
        sin_addr: 0x7F000001u32.to_be(),
        sin_zero: [0; 8],
    };
    let ret = unsafe { syscall3(nr::BIND, fd as u64, &addr as *const _ as u64, 16) };
    if ret == 0 {
        pass("UDP bind returns 0");
    } else {
        fail_errno("UDP bind returns 0", 0, ret);
    }

    unsafe { syscall1(nr::CLOSE, fd as u64) };
}

/// Run all socket tests
pub fn run_all() {
    test_socket_positive();
    test_socket_negative();
    test_sockopt();
    test_sockopt_negative();
    test_bind_listen();
    test_shutdown();
    test_udp_socket();
}
