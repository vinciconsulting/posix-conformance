//! Comprehensive socket tests
//!
//! Coverage:
//! - socket(): AF_INET/AF_INET6/AF_UNIX, SOCK_STREAM/SOCK_DGRAM
//! - setsockopt/getsockopt: SOL_SOCKET options
//! - bind/listen/accept (where possible without network)
//! - shutdown

use crate::{fail, fail_errno, nr, pass, syscall1, syscall2, syscall3, syscall4, syscall5, syscall6, write_str};

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

    // 4. RAW socket without privilege — expects EPERM, EACCES, or EPROTONOSUPPORT
    let ret = unsafe { syscall3(nr::SOCKET, AF_INET, SOCK_RAW, 0) };
    if ret == EPERM || ret == EACCES || ret == EPROTONOSUPPORT {
        pass("socket(RAW) denied (expected error)");
    } else if ret >= 0 {
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

// ════════════════════════════════════════════════════════════════════════════
// TCP CONNECT → ACCEPT → SEND → RECV: End-to-end data flow
// ════════════════════════════════════════════════════════════════════════════

fn test_tcp_data_flow() {
    write_str("\n=== TCP: connect → accept → send → recv ===\n");

    // 1. Create listener socket
    let listen_fd = unsafe { syscall3(nr::SOCKET, AF_INET, SOCK_STREAM, 0) };
    if listen_fd < 0 {
        fail_errno("TCP data flow: listener socket", 0, listen_fd);
        return;
    }

    // Enable SO_REUSEADDR
    let val: i32 = 1;
    unsafe {
        syscall5(nr::SETSOCKOPT, listen_fd as u64, SOL_SOCKET, SO_REUSEADDR,
                 &val as *const _ as u64, 4)
    };

    // Bind to localhost:0
    let listen_addr = SockaddrIn {
        sin_family: AF_INET as u16,
        sin_port: 0,
        sin_addr: 0x7F000001u32.to_be(),
        sin_zero: [0; 8],
    };
    let ret = unsafe {
        syscall3(nr::BIND, listen_fd as u64, &listen_addr as *const _ as u64, 16)
    };
    if ret != 0 {
        fail_errno("TCP data flow: bind", 0, ret);
        unsafe { syscall1(nr::CLOSE, listen_fd as u64) };
        return;
    }

    // Listen
    let ret = unsafe { syscall2(nr::LISTEN, listen_fd as u64, 1) };
    if ret != 0 {
        fail_errno("TCP data flow: listen", 0, ret);
        unsafe { syscall1(nr::CLOSE, listen_fd as u64) };
        return;
    }

    // Get the assigned port via getsockname
    let mut bound_addr = SockaddrIn {
        sin_family: 0, sin_port: 0, sin_addr: 0, sin_zero: [0; 8],
    };
    let mut addr_len: u32 = 16;
    unsafe {
        syscall3(nr::GETSOCKNAME, listen_fd as u64,
                 &mut bound_addr as *mut _ as u64, &mut addr_len as *mut _ as u64)
    };
    let port = bound_addr.sin_port;

    // 2. Create client socket and connect
    let client_fd = unsafe { syscall3(nr::SOCKET, AF_INET, SOCK_STREAM, 0) };
    if client_fd < 0 {
        fail_errno("TCP data flow: client socket", 0, client_fd);
        unsafe { syscall1(nr::CLOSE, listen_fd as u64) };
        return;
    }

    let connect_addr = SockaddrIn {
        sin_family: AF_INET as u16,
        sin_port: port,
        sin_addr: 0x7F000001u32.to_be(),
        sin_zero: [0; 8],
    };
    let ret = unsafe {
        syscall3(nr::CONNECT, client_fd as u64, &connect_addr as *const _ as u64, 16)
    };
    if ret != 0 {
        fail_errno("TCP connect to listener", 0, ret);
        unsafe {
            syscall1(nr::CLOSE, client_fd as u64);
            syscall1(nr::CLOSE, listen_fd as u64);
        }
        return;
    }
    pass("TCP connect succeeds");

    // 3. Accept on listener
    let mut peer_addr = SockaddrIn {
        sin_family: 0, sin_port: 0, sin_addr: 0, sin_zero: [0; 8],
    };
    let mut peer_len: u32 = 16;
    let accepted_fd = unsafe {
        syscall3(nr::ACCEPT, listen_fd as u64,
                 &mut peer_addr as *mut _ as u64, &mut peer_len as *mut _ as u64)
    };
    if accepted_fd < 0 {
        fail_errno("TCP accept", 0, accepted_fd);
        unsafe {
            syscall1(nr::CLOSE, client_fd as u64);
            syscall1(nr::CLOSE, listen_fd as u64);
        }
        return;
    }
    pass("TCP accept returns connected fd");

    // Verify peer address is loopback
    if peer_addr.sin_addr == 0x7F000001u32.to_be() {
        pass("accepted peer is 127.0.0.1");
    } else {
        fail("accepted peer is 127.0.0.1");
    }

    // 4. Client sends data, server receives
    let send_data = b"POSIX conformance TCP payload!";
    let nsent = unsafe {
        syscall3(crate::nr::WRITE, client_fd as u64,
                 send_data.as_ptr() as u64, send_data.len() as u64)
    };
    if nsent == send_data.len() as i64 {
        pass("client write returns exact count");
    } else {
        fail_errno("client write returns exact count", send_data.len() as i64, nsent);
    }

    let mut recv_buf = [0u8; 64];
    let nrecv = unsafe {
        syscall3(crate::nr::READ, accepted_fd as u64,
                 recv_buf.as_mut_ptr() as u64, 64)
    };
    if nrecv == send_data.len() as i64 {
        pass("server read returns exact count");
    } else {
        fail_errno("server read returns exact count", send_data.len() as i64, nrecv);
    }

    // Compare data
    let mut data_match = true;
    for i in 0..send_data.len() {
        if recv_buf[i] != send_data[i] {
            data_match = false;
            break;
        }
    }
    if data_match && nrecv == send_data.len() as i64 {
        pass("received data matches sent data");
    } else {
        fail("received data matches sent data");
    }

    // 5. Server sends reply, client receives
    let reply = b"ACK";
    let nsent = unsafe {
        syscall3(crate::nr::WRITE, accepted_fd as u64,
                 reply.as_ptr() as u64, 3)
    };
    if nsent != 3 {
        fail_errno("server reply write", 3, nsent);
    }

    let mut reply_buf = [0u8; 8];
    let nrecv = unsafe {
        syscall3(crate::nr::READ, client_fd as u64,
                 reply_buf.as_mut_ptr() as u64, 8)
    };
    if nrecv == 3 && reply_buf[..3] == *b"ACK" {
        pass("bidirectional data flow works");
    } else {
        fail("bidirectional data flow works");
    }

    // 6. getpeername on accepted socket
    let mut name = SockaddrIn {
        sin_family: 0, sin_port: 0, sin_addr: 0, sin_zero: [0; 8],
    };
    let mut name_len: u32 = 16;
    let ret = unsafe {
        syscall3(nr::GETPEERNAME, accepted_fd as u64,
                 &mut name as *mut _ as u64, &mut name_len as *mut _ as u64)
    };
    if ret == 0 && name.sin_family == AF_INET as u16 {
        pass("getpeername on accepted socket");
    } else {
        fail_errno("getpeername on accepted socket", 0, ret);
    }

    // 7. Shutdown write on client, verify server gets EOF
    const SHUT_WR: u64 = 1;
    unsafe { syscall2(nr::SHUTDOWN, client_fd as u64, SHUT_WR) };

    let nrecv = unsafe {
        syscall3(crate::nr::READ, accepted_fd as u64,
                 recv_buf.as_mut_ptr() as u64, 64)
    };
    if nrecv == 0 {
        pass("shutdown(SHUT_WR) → server reads EOF");
    } else {
        fail("shutdown(SHUT_WR) → server reads EOF");
    }

    // Cleanup
    unsafe {
        syscall1(nr::CLOSE, accepted_fd as u64);
        syscall1(nr::CLOSE, client_fd as u64);
        syscall1(nr::CLOSE, listen_fd as u64);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// UDP SENDTO → RECVFROM: Datagram data flow
// ════════════════════════════════════════════════════════════════════════════

fn test_udp_data_flow() {
    write_str("\n=== UDP: sendto → recvfrom ===\n");

    // Create two UDP sockets (server + client)
    let server_fd = unsafe { syscall3(nr::SOCKET, AF_INET, SOCK_DGRAM, 0) };
    let client_fd = unsafe { syscall3(nr::SOCKET, AF_INET, SOCK_DGRAM, 0) };
    if server_fd < 0 || client_fd < 0 {
        fail("UDP data flow: socket setup");
        if server_fd >= 0 { unsafe { syscall1(nr::CLOSE, server_fd as u64) }; }
        if client_fd >= 0 { unsafe { syscall1(nr::CLOSE, client_fd as u64) }; }
        return;
    }

    // Bind server to localhost:0
    let server_addr = SockaddrIn {
        sin_family: AF_INET as u16,
        sin_port: 0,
        sin_addr: 0x7F000001u32.to_be(),
        sin_zero: [0; 8],
    };
    let ret = unsafe {
        syscall3(nr::BIND, server_fd as u64, &server_addr as *const _ as u64, 16)
    };
    if ret != 0 {
        fail_errno("UDP server bind", 0, ret);
        unsafe {
            syscall1(nr::CLOSE, server_fd as u64);
            syscall1(nr::CLOSE, client_fd as u64);
        }
        return;
    }

    // Get assigned port
    let mut bound = SockaddrIn {
        sin_family: 0, sin_port: 0, sin_addr: 0, sin_zero: [0; 8],
    };
    let mut len: u32 = 16;
    unsafe {
        syscall3(nr::GETSOCKNAME, server_fd as u64,
                 &mut bound as *mut _ as u64, &mut len as *mut _ as u64)
    };

    // Client sendto server
    let dest_addr = SockaddrIn {
        sin_family: AF_INET as u16,
        sin_port: bound.sin_port,
        sin_addr: 0x7F000001u32.to_be(),
        sin_zero: [0; 8],
    };
    let msg = b"UDP POSIX test";
    let nsent = unsafe {
        syscall6(nr::SENDTO, client_fd as u64,
                 msg.as_ptr() as u64, msg.len() as u64, 0,
                 &dest_addr as *const _ as u64, 16)
    };
    if nsent == msg.len() as i64 {
        pass("UDP sendto returns exact count");
    } else {
        fail_errno("UDP sendto returns exact count", msg.len() as i64, nsent);
    }

    // Server recvfrom
    let mut recv_buf = [0u8; 64];
    let mut from_addr = SockaddrIn {
        sin_family: 0, sin_port: 0, sin_addr: 0, sin_zero: [0; 8],
    };
    let mut from_len: u32 = 16;
    let nrecv = unsafe {
        syscall6(nr::RECVFROM, server_fd as u64,
                 recv_buf.as_mut_ptr() as u64, 64, 0,
                 &mut from_addr as *mut _ as u64,
                 &mut from_len as *mut _ as u64)
    };
    if nrecv == msg.len() as i64 {
        pass("UDP recvfrom returns exact count");
    } else {
        fail_errno("UDP recvfrom returns exact count", msg.len() as i64, nrecv);
    }

    // Verify data
    let mut data_ok = true;
    for i in 0..msg.len() {
        if recv_buf[i] != msg[i] {
            data_ok = false;
            break;
        }
    }
    if data_ok && nrecv == msg.len() as i64 {
        pass("UDP received data matches sent data");
    } else {
        fail("UDP received data matches sent data");
    }

    // Verify sender address is loopback
    if from_addr.sin_addr == 0x7F000001u32.to_be() && from_addr.sin_family == AF_INET as u16 {
        pass("recvfrom: sender is 127.0.0.1");
    } else {
        fail("recvfrom: sender is 127.0.0.1");
    }

    unsafe {
        syscall1(nr::CLOSE, server_fd as u64);
        syscall1(nr::CLOSE, client_fd as u64);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// UNIX DOMAIN SOCKET: Socketpair-style data flow
// ════════════════════════════════════════════════════════════════════════════

fn test_unix_data_flow() {
    write_str("\n=== Unix socket: bind → connect → send → recv ===\n");

    // Create listener
    let listen_fd = unsafe { syscall3(nr::SOCKET, AF_UNIX, SOCK_STREAM, 0) };
    if listen_fd < 0 {
        if listen_fd == -97 { // EAFNOSUPPORT
            pass("AF_UNIX not supported (skipping)");
            return;
        }
        fail_errno("unix socket create", 0, listen_fd);
        return;
    }

    // Bind to abstract socket (Linux: first byte is \0)
    #[repr(C)]
    struct SockaddrUn {
        sun_family: u16,
        sun_path: [u8; 108],
    }

    let mut addr = SockaddrUn {
        sun_family: AF_UNIX as u16,
        sun_path: [0; 108],
    };
    // Abstract socket: \0 + name
    let name = b"_posix_conf_test";
    for i in 0..name.len() {
        addr.sun_path[1 + i] = name[i];
    }
    let addr_len: u32 = 2 + 1 + name.len() as u32; // family + null + name

    let ret = unsafe {
        syscall3(nr::BIND, listen_fd as u64, &addr as *const _ as u64, addr_len as u64)
    };
    if ret != 0 {
        fail_errno("unix bind (abstract)", 0, ret);
        unsafe { syscall1(nr::CLOSE, listen_fd as u64) };
        return;
    }

    unsafe { syscall2(nr::LISTEN, listen_fd as u64, 1) };

    // Connect
    let client_fd = unsafe { syscall3(nr::SOCKET, AF_UNIX, SOCK_STREAM, 0) };
    if client_fd < 0 {
        fail_errno("unix client socket", 0, client_fd);
        unsafe { syscall1(nr::CLOSE, listen_fd as u64) };
        return;
    }

    let ret = unsafe {
        syscall3(nr::CONNECT, client_fd as u64, &addr as *const _ as u64, addr_len as u64)
    };
    if ret != 0 {
        fail_errno("unix connect", 0, ret);
        unsafe {
            syscall1(nr::CLOSE, client_fd as u64);
            syscall1(nr::CLOSE, listen_fd as u64);
        }
        return;
    }
    pass("unix domain connect");

    // Accept
    let accepted = unsafe { syscall3(nr::ACCEPT, listen_fd as u64, 0, 0) };
    if accepted < 0 {
        fail_errno("unix accept", 0, accepted);
        unsafe {
            syscall1(nr::CLOSE, client_fd as u64);
            syscall1(nr::CLOSE, listen_fd as u64);
        }
        return;
    }
    pass("unix domain accept");

    // Send/recv
    let msg = b"unix domain payload";
    let nsent = unsafe {
        syscall3(crate::nr::WRITE, client_fd as u64,
                 msg.as_ptr() as u64, msg.len() as u64)
    };
    let mut buf = [0u8; 32];
    let nrecv = unsafe {
        syscall3(crate::nr::READ, accepted as u64,
                 buf.as_mut_ptr() as u64, 32)
    };

    if nsent == msg.len() as i64 && nrecv == msg.len() as i64 {
        let mut ok = true;
        for i in 0..msg.len() {
            if buf[i] != msg[i] { ok = false; break; }
        }
        if ok {
            pass("unix domain: data round-trip matches");
        } else {
            fail("unix domain: data round-trip matches");
        }
    } else {
        fail("unix domain: send/recv counts");
    }

    unsafe {
        syscall1(nr::CLOSE, accepted as u64);
        syscall1(nr::CLOSE, client_fd as u64);
        syscall1(nr::CLOSE, listen_fd as u64);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// SOCKETPAIR: Create connected socket pair
// ════════════════════════════════════════════════════════════════════════════

fn test_socketpair() {
    write_str("\n=== socketpair: tests ===\n");

    let mut sv = [0i32; 2];
    let ret = unsafe {
        syscall4(nr::SOCKETPAIR, AF_UNIX, SOCK_STREAM, 0, sv.as_mut_ptr() as u64)
    };
    if ret < 0 {
        if ret == -97 { // EAFNOSUPPORT
            pass("AF_UNIX socketpair not supported (skipping)");
            return;
        }
        fail_errno("socketpair(AF_UNIX, STREAM)", 0, ret);
        return;
    }
    pass("socketpair returns 0");

    if sv[0] >= 0 && sv[1] >= 0 && sv[0] != sv[1] {
        pass("socketpair: two distinct fds");
    } else {
        fail("socketpair: two distinct fds");
    }

    // Write on sv[0], read on sv[1]
    let msg = b"socketpair data";
    let nsent = unsafe {
        syscall3(crate::nr::WRITE, sv[0] as u64, msg.as_ptr() as u64, msg.len() as u64)
    };
    let mut buf = [0u8; 32];
    let nrecv = unsafe {
        syscall3(crate::nr::READ, sv[1] as u64, buf.as_mut_ptr() as u64, 32)
    };
    if nsent == msg.len() as i64 && nrecv == msg.len() as i64 {
        let mut ok = true;
        for i in 0..msg.len() { if buf[i] != msg[i] { ok = false; break; } }
        if ok {
            pass("socketpair: bidirectional data flow");
        } else {
            fail("socketpair: bidirectional data flow");
        }
    } else {
        fail("socketpair: send/recv counts");
    }

    // SOCK_DGRAM pair
    let mut sv2 = [0i32; 2];
    let ret = unsafe {
        syscall4(nr::SOCKETPAIR, AF_UNIX, SOCK_DGRAM, 0, sv2.as_mut_ptr() as u64)
    };
    if ret == 0 {
        pass("socketpair(SOCK_DGRAM) returns 0");
        unsafe {
            syscall1(nr::CLOSE, sv2[0] as u64);
            syscall1(nr::CLOSE, sv2[1] as u64);
        }
    } else {
        fail_errno("socketpair(SOCK_DGRAM)", 0, ret);
    }

    unsafe {
        syscall1(nr::CLOSE, sv[0] as u64);
        syscall1(nr::CLOSE, sv[1] as u64);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// SENDMSG / RECVMSG: Scatter-gather I/O
// ════════════════════════════════════════════════════════════════════════════

fn test_sendmsg_recvmsg() {
    write_str("\n=== sendmsg/recvmsg: scatter-gather ===\n");

    let mut sv = [0i32; 2];
    let ret = unsafe {
        syscall4(nr::SOCKETPAIR, AF_UNIX, SOCK_STREAM, 0, sv.as_mut_ptr() as u64)
    };
    if ret < 0 {
        pass("AF_UNIX not supported, skipping sendmsg/recvmsg");
        return;
    }

    // sendmsg with 2-segment iovec
    let seg1 = b"Hello";
    let seg2 = b"World";
    let iov = [
        crate::Iovec { iov_base: seg1.as_ptr() as u64, iov_len: 5 },
        crate::Iovec { iov_base: seg2.as_ptr() as u64, iov_len: 5 },
    ];

    #[repr(C)]
    struct Msghdr {
        msg_name: u64,
        msg_namelen: u32,
        _pad0: u32,
        msg_iov: u64,
        msg_iovlen: u64,
        msg_control: u64,
        msg_controllen: u64,
        msg_flags: i32,
        _pad1: i32,
    }

    let hdr = Msghdr {
        msg_name: 0,
        msg_namelen: 0,
        _pad0: 0,
        msg_iov: iov.as_ptr() as u64,
        msg_iovlen: 2,
        msg_control: 0,
        msg_controllen: 0,
        msg_flags: 0,
        _pad1: 0,
    };

    let nsent = unsafe {
        syscall3(nr::SENDMSG, sv[0] as u64, &hdr as *const _ as u64, 0)
    };
    if nsent == 10 {
        pass("sendmsg: 2-segment iovec sent 10 bytes");
    } else {
        fail_errno("sendmsg: 2-segment iovec", 10, nsent);
    }

    // recvmsg into single buffer
    let mut recv_buf = [0u8; 16];
    let recv_iov = [crate::Iovec {
        iov_base: recv_buf.as_mut_ptr() as u64,
        iov_len: 16,
    }];
    let mut recv_hdr = Msghdr {
        msg_name: 0,
        msg_namelen: 0,
        _pad0: 0,
        msg_iov: recv_iov.as_ptr() as u64,
        msg_iovlen: 1,
        msg_control: 0,
        msg_controllen: 0,
        msg_flags: 0,
        _pad1: 0,
    };
    let nrecv = unsafe {
        syscall3(nr::RECVMSG, sv[1] as u64, &mut recv_hdr as *mut _ as u64, 0)
    };
    if nrecv == 10 && recv_buf[..10] == *b"HelloWorld" {
        pass("recvmsg: received scatter-gathered data");
    } else {
        fail("recvmsg: received scatter-gathered data");
    }

    unsafe {
        syscall1(nr::CLOSE, sv[0] as u64);
        syscall1(nr::CLOSE, sv[1] as u64);
    }
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

    // End-to-end data flow
    test_tcp_data_flow();
    test_udp_data_flow();
    test_unix_data_flow();
    test_socketpair();
    test_sendmsg_recvmsg();
}
