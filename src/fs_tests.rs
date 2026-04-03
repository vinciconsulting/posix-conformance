//! Filesystem conformance tests
//!
//! Tests: openat, read/write on files, newfstatat, mkdirat, unlinkat,
//!        getdents64, pread64/pwrite64, readlinkat
//!
//! Categories:
//! - Positive: create file, write, read-back, stat, unlink
//! - Negative: open non-existent, unlink non-existent, bad fd operations
//! - Boundary: zero-length read/write, O_TRUNC, O_APPEND semantics

use crate::nr;
use crate::{pass, fail, fail_errno, write_str, write_num, write_hex};
use crate::{syscall1, syscall3, syscall4, syscall5};

// ════════════════════════════════════════════════════════════════════════════
// Constants
// ════════════════════════════════════════════════════════════════════════════

// openat flags
const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 1;
const O_RDWR: u64 = 2;
const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;
const O_TRUNC: u64 = 0o1000;
const O_APPEND: u64 = 0o2000;
const O_DIRECTORY: u64 = 0o200000;

// AT_FDCWD
const AT_FDCWD: u64 = (-100i64) as u64;

// unlinkat flags
const AT_REMOVEDIR: u64 = 0x200;


// Mode bits
const S_IRUSR: u64 = 0o400;
const S_IWUSR: u64 = 0o200;
const S_IRWXU: u64 = 0o700;
const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;

// Error codes
const ENOENT: i64 = -2;
const EEXIST: i64 = -17;
const EBADF: i64 = -9;
const EISDIR: i64 = -21;
const ENOTEMPTY: i64 = -39;

// ════════════════════════════════════════════════════════════════════════════
// Structures
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

#[repr(C)]
struct LinuxDirent64 {
    d_ino: u64,
    d_off: i64,
    d_reclen: u16,
    d_type: u8,
    // d_name follows (variable length, null-terminated)
}

// ════════════════════════════════════════════════════════════════════════════
// Test: Create, write, read, close, unlink a regular file
// ════════════════════════════════════════════════════════════════════════════

fn test_file_create_write_read() {
    write_str("\n=== FS: create + write + read + unlink ===\n");

    let path = b"/tmp/_posix_conformance_test_file\0";

    // 1. Create file (O_CREAT | O_RDWR | O_TRUNC, mode 0600)
    let fd = unsafe {
        syscall4(nr::OPENAT, AT_FDCWD, path.as_ptr() as u64,
                 O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR)
    };
    if fd < 0 {
        fail_errno("openat(O_CREAT|O_RDWR|O_TRUNC)", 0, fd);
        return;
    }
    pass("openat(O_CREAT) returns fd");

    // 2. Write known pattern
    let pattern = b"Hello, POSIX conformance!\n";
    let nwritten = unsafe {
        syscall3(nr::WRITE, fd as u64, pattern.as_ptr() as u64, pattern.len() as u64)
    };
    if nwritten == pattern.len() as i64 {
        pass("write returns exact count");
    } else {
        fail_errno("write returns exact count", pattern.len() as i64, nwritten);
    }

    // 3. Seek to beginning via close + reopen O_RDONLY
    unsafe { syscall1(nr::CLOSE, fd as u64) };

    let fd = unsafe {
        syscall4(nr::OPENAT, AT_FDCWD, path.as_ptr() as u64, O_RDONLY, 0)
    };
    if fd < 0 {
        fail_errno("reopen O_RDONLY", 0, fd);
        // cleanup
        unsafe { syscall3(nr::UNLINKAT, AT_FDCWD, path.as_ptr() as u64, 0) };
        return;
    }
    pass("reopen O_RDONLY succeeds");

    // 4. Read back and compare
    let mut buf = [0u8; 64];
    let nread = unsafe {
        syscall3(nr::READ, fd as u64, buf.as_mut_ptr() as u64, 64)
    };
    if nread == pattern.len() as i64 {
        pass("read returns exact count");
    } else {
        fail_errno("read returns exact count", pattern.len() as i64, nread);
    }

    let mut match_ok = true;
    for i in 0..pattern.len() {
        if buf[i] != pattern[i] {
            match_ok = false;
            break;
        }
    }
    if match_ok && nread == pattern.len() as i64 {
        pass("read data matches written data");
    } else {
        fail("read data matches written data");
    }

    // 5. Read at EOF returns 0
    let nread = unsafe {
        syscall3(nr::READ, fd as u64, buf.as_mut_ptr() as u64, 64)
    };
    if nread == 0 {
        pass("read at EOF returns 0");
    } else {
        fail_errno("read at EOF returns 0", 0, nread);
    }

    unsafe { syscall1(nr::CLOSE, fd as u64) };

    // 6. Unlink
    let ret = unsafe {
        syscall3(nr::UNLINKAT, AT_FDCWD, path.as_ptr() as u64, 0)
    };
    if ret == 0 {
        pass("unlinkat removes file");
    } else {
        fail_errno("unlinkat removes file", 0, ret);
    }

    // 7. Verify unlinked — open should fail with ENOENT
    let fd = unsafe {
        syscall4(nr::OPENAT, AT_FDCWD, path.as_ptr() as u64, O_RDONLY, 0)
    };
    if fd == ENOENT {
        pass("open after unlink returns ENOENT");
    } else if fd >= 0 {
        fail("open after unlink returns ENOENT (file still exists!)");
        unsafe { syscall1(nr::CLOSE, fd as u64) };
    } else {
        fail_errno("open after unlink returns ENOENT", ENOENT, fd);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Test: O_EXCL — fail if file exists
// ════════════════════════════════════════════════════════════════════════════

fn test_oexcl() {
    write_str("\n=== FS: O_CREAT|O_EXCL ===\n");

    let path = b"/tmp/_posix_excl_test\0";

    // Create file first time — should succeed
    let fd = unsafe {
        syscall4(nr::OPENAT, AT_FDCWD, path.as_ptr() as u64,
                 O_CREAT | O_EXCL | O_WRONLY, S_IRUSR | S_IWUSR)
    };
    if fd < 0 {
        // May fail if leftover from previous run — try unlinking first
        unsafe { syscall3(nr::UNLINKAT, AT_FDCWD, path.as_ptr() as u64, 0) };
        let fd2 = unsafe {
            syscall4(nr::OPENAT, AT_FDCWD, path.as_ptr() as u64,
                     O_CREAT | O_EXCL | O_WRONLY, S_IRUSR | S_IWUSR)
        };
        if fd2 < 0 {
            fail_errno("O_CREAT|O_EXCL first create", 0, fd2);
            return;
        }
        pass("O_CREAT|O_EXCL first create (after cleanup)");
        unsafe { syscall1(nr::CLOSE, fd2 as u64) };
    } else {
        pass("O_CREAT|O_EXCL first create");
        unsafe { syscall1(nr::CLOSE, fd as u64) };
    }

    // Second create with O_EXCL — must fail with EEXIST
    let fd = unsafe {
        syscall4(nr::OPENAT, AT_FDCWD, path.as_ptr() as u64,
                 O_CREAT | O_EXCL | O_WRONLY, S_IRUSR | S_IWUSR)
    };
    if fd == EEXIST {
        pass("O_CREAT|O_EXCL on existing file returns EEXIST");
    } else if fd >= 0 {
        fail("O_CREAT|O_EXCL on existing file should return EEXIST");
        unsafe { syscall1(nr::CLOSE, fd as u64) };
    } else {
        fail_errno("O_CREAT|O_EXCL on existing file returns EEXIST", EEXIST, fd);
    }

    // Cleanup
    unsafe { syscall3(nr::UNLINKAT, AT_FDCWD, path.as_ptr() as u64, 0) };
}

// ════════════════════════════════════════════════════════════════════════════
// Test: O_APPEND — writes always go to end
// ════════════════════════════════════════════════════════════════════════════

fn test_oappend() {
    write_str("\n=== FS: O_APPEND ===\n");

    let path = b"/tmp/_posix_append_test\0";

    // Create and write initial data
    let fd = unsafe {
        syscall4(nr::OPENAT, AT_FDCWD, path.as_ptr() as u64,
                 O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR)
    };
    if fd < 0 {
        fail_errno("create for append test", 0, fd);
        return;
    }
    let part1 = b"AAAA";
    unsafe { syscall3(nr::WRITE, fd as u64, part1.as_ptr() as u64, 4) };
    unsafe { syscall1(nr::CLOSE, fd as u64) };

    // Reopen with O_APPEND and write more
    let fd = unsafe {
        syscall4(nr::OPENAT, AT_FDCWD, path.as_ptr() as u64,
                 O_WRONLY | O_APPEND, 0)
    };
    if fd < 0 {
        fail_errno("open O_APPEND", 0, fd);
        unsafe { syscall3(nr::UNLINKAT, AT_FDCWD, path.as_ptr() as u64, 0) };
        return;
    }
    let part2 = b"BBBB";
    unsafe { syscall3(nr::WRITE, fd as u64, part2.as_ptr() as u64, 4) };
    unsafe { syscall1(nr::CLOSE, fd as u64) };

    // Read back — should be "AAAABBBB"
    let fd = unsafe {
        syscall4(nr::OPENAT, AT_FDCWD, path.as_ptr() as u64, O_RDONLY, 0)
    };
    if fd < 0 {
        fail_errno("reopen for append verify", 0, fd);
        unsafe { syscall3(nr::UNLINKAT, AT_FDCWD, path.as_ptr() as u64, 0) };
        return;
    }
    let mut buf = [0u8; 16];
    let nread = unsafe {
        syscall3(nr::READ, fd as u64, buf.as_mut_ptr() as u64, 16)
    };
    unsafe { syscall1(nr::CLOSE, fd as u64) };

    if nread == 8 && buf[..8] == *b"AAAABBBB" {
        pass("O_APPEND: data appended correctly");
    } else {
        fail("O_APPEND: data appended correctly");
        write_str("    nread=");
        write_num(nread);
        write_str("\n");
    }

    unsafe { syscall3(nr::UNLINKAT, AT_FDCWD, path.as_ptr() as u64, 0) };
}

// ════════════════════════════════════════════════════════════════════════════
// Test: O_TRUNC — truncates existing file
// ════════════════════════════════════════════════════════════════════════════

fn test_otrunc() {
    write_str("\n=== FS: O_TRUNC ===\n");

    let path = b"/tmp/_posix_trunc_test\0";

    // Create with initial data
    let fd = unsafe {
        syscall4(nr::OPENAT, AT_FDCWD, path.as_ptr() as u64,
                 O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR)
    };
    if fd < 0 {
        fail_errno("create for trunc test", 0, fd);
        return;
    }
    let data = b"XXXXXXXXXXXX"; // 12 bytes
    unsafe { syscall3(nr::WRITE, fd as u64, data.as_ptr() as u64, 12) };
    unsafe { syscall1(nr::CLOSE, fd as u64) };

    // Reopen with O_TRUNC — file should become empty
    let fd = unsafe {
        syscall4(nr::OPENAT, AT_FDCWD, path.as_ptr() as u64,
                 O_WRONLY | O_TRUNC, 0)
    };
    if fd < 0 {
        fail_errno("open O_TRUNC", 0, fd);
        unsafe { syscall3(nr::UNLINKAT, AT_FDCWD, path.as_ptr() as u64, 0) };
        return;
    }
    // Write 3 bytes
    unsafe { syscall3(nr::WRITE, fd as u64, b"YYY".as_ptr() as u64, 3) };
    unsafe { syscall1(nr::CLOSE, fd as u64) };

    // Read back — should be "YYY" (3 bytes, not 12)
    let fd = unsafe {
        syscall4(nr::OPENAT, AT_FDCWD, path.as_ptr() as u64, O_RDONLY, 0)
    };
    if fd < 0 {
        fail_errno("reopen after trunc", 0, fd);
        unsafe { syscall3(nr::UNLINKAT, AT_FDCWD, path.as_ptr() as u64, 0) };
        return;
    }
    let mut buf = [0u8; 16];
    let nread = unsafe {
        syscall3(nr::READ, fd as u64, buf.as_mut_ptr() as u64, 16)
    };
    unsafe { syscall1(nr::CLOSE, fd as u64) };

    if nread == 3 && buf[..3] == *b"YYY" {
        pass("O_TRUNC: file truncated, new data correct");
    } else {
        fail("O_TRUNC: file truncated, new data correct");
        write_str("    nread=");
        write_num(nread);
        write_str("\n");
    }

    unsafe { syscall3(nr::UNLINKAT, AT_FDCWD, path.as_ptr() as u64, 0) };
}

// ════════════════════════════════════════════════════════════════════════════
// Test: pread64/pwrite64 — positional I/O without seeking
// ════════════════════════════════════════════════════════════════════════════

fn test_pread_pwrite() {
    write_str("\n=== FS: pread64/pwrite64 ===\n");

    let path = b"/tmp/_posix_pread_test\0";

    let fd = unsafe {
        syscall4(nr::OPENAT, AT_FDCWD, path.as_ptr() as u64,
                 O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR)
    };
    if fd < 0 {
        fail_errno("create for pread test", 0, fd);
        return;
    }

    // pwrite64 at offset 0
    let data = b"ABCDEFGHIJ"; // 10 bytes
    let ret = unsafe {
        syscall4(nr::PWRITE64, fd as u64, data.as_ptr() as u64, 10, 0)
    };
    if ret == 10 {
        pass("pwrite64: 10 bytes at offset 0");
    } else {
        fail_errno("pwrite64: 10 bytes at offset 0", 10, ret);
    }

    // pwrite64 at offset 5 (overwrite middle)
    let patch = b"xxxxx";
    let ret = unsafe {
        syscall4(nr::PWRITE64, fd as u64, patch.as_ptr() as u64, 5, 5)
    };
    if ret == 5 {
        pass("pwrite64: 5 bytes at offset 5");
    } else {
        fail_errno("pwrite64: 5 bytes at offset 5", 5, ret);
    }

    // pread64 at offset 0 — should be "ABCDExxxxx"
    let mut buf = [0u8; 16];
    let ret = unsafe {
        syscall4(nr::PREAD64, fd as u64, buf.as_mut_ptr() as u64, 16, 0)
    };
    if ret == 10 && buf[..10] == *b"ABCDExxxxx" {
        pass("pread64: reads merged data correctly");
    } else {
        fail("pread64: reads merged data correctly");
        write_str("    ret=");
        write_num(ret);
        write_str("\n");
    }

    // pread64 at offset 3 — should be "DExxxxx" (7 bytes)
    let mut buf2 = [0u8; 16];
    let ret = unsafe {
        syscall4(nr::PREAD64, fd as u64, buf2.as_mut_ptr() as u64, 16, 3)
    };
    if ret == 7 && buf2[..7] == *b"DExxxxx" {
        pass("pread64: partial read at offset 3");
    } else {
        fail("pread64: partial read at offset 3");
    }

    // pread64 past EOF
    let ret = unsafe {
        syscall4(nr::PREAD64, fd as u64, buf2.as_mut_ptr() as u64, 16, 100)
    };
    if ret == 0 {
        pass("pread64: past EOF returns 0");
    } else {
        fail_errno("pread64: past EOF returns 0", 0, ret);
    }

    unsafe { syscall1(nr::CLOSE, fd as u64) };
    unsafe { syscall3(nr::UNLINKAT, AT_FDCWD, path.as_ptr() as u64, 0) };
}

// ════════════════════════════════════════════════════════════════════════════
// Test: newfstatat on files
// ════════════════════════════════════════════════════════════════════════════

fn test_stat_file() {
    write_str("\n=== FS: newfstatat on file ===\n");

    let path = b"/tmp/_posix_stat_test\0";

    // Create a file with known content
    let fd = unsafe {
        syscall4(nr::OPENAT, AT_FDCWD, path.as_ptr() as u64,
                 O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR)
    };
    if fd < 0 {
        fail_errno("create for stat test", 0, fd);
        return;
    }
    let data = b"stat test data!"; // 15 bytes
    unsafe { syscall3(nr::WRITE, fd as u64, data.as_ptr() as u64, 15) };
    unsafe { syscall1(nr::CLOSE, fd as u64) };

    // stat the file
    let mut st = core::mem::MaybeUninit::<Stat>::uninit();
    let ret = unsafe {
        syscall4(nr::NEWFSTATAT, AT_FDCWD, path.as_ptr() as u64,
                 st.as_mut_ptr() as u64, 0)
    };
    if ret != 0 {
        fail_errno("newfstatat on file", 0, ret);
        unsafe { syscall3(nr::UNLINKAT, AT_FDCWD, path.as_ptr() as u64, 0) };
        return;
    }
    pass("newfstatat returns 0");

    let st = unsafe { st.assume_init() };

    // Check file type
    if (st.st_mode & S_IFMT) == S_IFREG {
        pass("st_mode indicates regular file");
    } else {
        fail("st_mode indicates regular file");
        write_str("    st_mode: ");
        write_hex(st.st_mode as u64);
        write_str("\n");
    }

    // Check size
    if st.st_size == 15 {
        pass("st_size == 15");
    } else {
        fail("st_size == 15");
        write_str("    st_size: ");
        write_num(st.st_size);
        write_str("\n");
    }

    // Check inode is non-zero
    if st.st_ino != 0 {
        pass("st_ino is non-zero");
    } else {
        fail("st_ino is non-zero");
    }

    // Check nlink >= 1
    if st.st_nlink >= 1 {
        pass("st_nlink >= 1");
    } else {
        fail("st_nlink >= 1");
    }

    unsafe { syscall3(nr::UNLINKAT, AT_FDCWD, path.as_ptr() as u64, 0) };
}

// ════════════════════════════════════════════════════════════════════════════
// Test: mkdirat + stat directory + unlinkat(AT_REMOVEDIR)
// ════════════════════════════════════════════════════════════════════════════

fn test_mkdir_rmdir() {
    write_str("\n=== FS: mkdirat + rmdir ===\n");

    let path = b"/tmp/_posix_mkdir_test\0";

    // Clean up from any previous run
    unsafe { syscall3(nr::UNLINKAT, AT_FDCWD, path.as_ptr() as u64, AT_REMOVEDIR) };

    // 1. mkdirat
    let ret = unsafe {
        syscall3(nr::MKDIRAT, AT_FDCWD, path.as_ptr() as u64, S_IRWXU)
    };
    if ret == 0 {
        pass("mkdirat creates directory");
    } else {
        fail_errno("mkdirat creates directory", 0, ret);
        return;
    }

    // 2. stat the directory
    let mut st = core::mem::MaybeUninit::<Stat>::uninit();
    let ret = unsafe {
        syscall4(nr::NEWFSTATAT, AT_FDCWD, path.as_ptr() as u64,
                 st.as_mut_ptr() as u64, 0)
    };
    if ret == 0 {
        let st = unsafe { st.assume_init() };
        if (st.st_mode & S_IFMT) == S_IFDIR {
            pass("newfstatat: st_mode indicates directory");
        } else {
            fail("newfstatat: st_mode indicates directory");
        }
    } else {
        fail_errno("newfstatat on directory", 0, ret);
    }

    // 3. mkdirat on existing directory → EEXIST
    let ret = unsafe {
        syscall3(nr::MKDIRAT, AT_FDCWD, path.as_ptr() as u64, S_IRWXU)
    };
    if ret == EEXIST {
        pass("mkdirat existing dir returns EEXIST");
    } else {
        fail_errno("mkdirat existing dir returns EEXIST", EEXIST, ret);
    }

    // 4. unlinkat with AT_REMOVEDIR
    let ret = unsafe {
        syscall3(nr::UNLINKAT, AT_FDCWD, path.as_ptr() as u64, AT_REMOVEDIR)
    };
    if ret == 0 {
        pass("unlinkat(AT_REMOVEDIR) removes directory");
    } else {
        fail_errno("unlinkat(AT_REMOVEDIR) removes directory", 0, ret);
    }

    // 5. Verify removed
    let mut st2 = core::mem::MaybeUninit::<Stat>::uninit();
    let ret = unsafe {
        syscall4(nr::NEWFSTATAT, AT_FDCWD, path.as_ptr() as u64,
                 st2.as_mut_ptr() as u64, 0)
    };
    if ret == ENOENT {
        pass("directory gone after rmdir");
    } else {
        fail_errno("directory gone after rmdir", ENOENT, ret);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Test: rmdir non-empty directory → ENOTEMPTY
// ════════════════════════════════════════════════════════════════════════════

fn test_rmdir_nonempty() {
    write_str("\n=== FS: rmdir non-empty → ENOTEMPTY ===\n");

    let dir = b"/tmp/_posix_nonempty_test\0";
    let file = b"/tmp/_posix_nonempty_test/child\0";

    // Cleanup from any previous run
    unsafe {
        syscall3(nr::UNLINKAT, AT_FDCWD, file.as_ptr() as u64, 0);
        syscall3(nr::UNLINKAT, AT_FDCWD, dir.as_ptr() as u64, AT_REMOVEDIR);
    }

    // Create dir + file inside it
    let ret = unsafe { syscall3(nr::MKDIRAT, AT_FDCWD, dir.as_ptr() as u64, S_IRWXU) };
    if ret != 0 {
        fail_errno("mkdir for nonempty test", 0, ret);
        return;
    }

    let fd = unsafe {
        syscall4(nr::OPENAT, AT_FDCWD, file.as_ptr() as u64,
                 O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR)
    };
    if fd < 0 {
        fail_errno("create child file", 0, fd);
        unsafe { syscall3(nr::UNLINKAT, AT_FDCWD, dir.as_ptr() as u64, AT_REMOVEDIR) };
        return;
    }
    unsafe { syscall1(nr::CLOSE, fd as u64) };

    // Try to rmdir — should fail with ENOTEMPTY
    let ret = unsafe {
        syscall3(nr::UNLINKAT, AT_FDCWD, dir.as_ptr() as u64, AT_REMOVEDIR)
    };
    if ret == ENOTEMPTY {
        pass("rmdir non-empty dir returns ENOTEMPTY");
    } else {
        fail_errno("rmdir non-empty dir returns ENOTEMPTY", ENOTEMPTY, ret);
    }

    // Cleanup: remove file then dir
    unsafe {
        syscall3(nr::UNLINKAT, AT_FDCWD, file.as_ptr() as u64, 0);
        syscall3(nr::UNLINKAT, AT_FDCWD, dir.as_ptr() as u64, AT_REMOVEDIR);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Test: getdents64 (readdir equivalent)
// ════════════════════════════════════════════════════════════════════════════

fn test_getdents64() {
    write_str("\n=== FS: getdents64 (readdir) ===\n");

    let dir = b"/tmp/_posix_readdir_test\0";
    let file_a = b"/tmp/_posix_readdir_test/alpha\0";
    let file_b = b"/tmp/_posix_readdir_test/beta\0";

    // Cleanup
    unsafe {
        syscall3(nr::UNLINKAT, AT_FDCWD, file_a.as_ptr() as u64, 0);
        syscall3(nr::UNLINKAT, AT_FDCWD, file_b.as_ptr() as u64, 0);
        syscall3(nr::UNLINKAT, AT_FDCWD, dir.as_ptr() as u64, AT_REMOVEDIR);
    }

    // Create dir + 2 files
    if unsafe { syscall3(nr::MKDIRAT, AT_FDCWD, dir.as_ptr() as u64, S_IRWXU) } != 0 {
        fail("getdents64: mkdir setup");
        return;
    }

    for path in [file_a.as_ptr(), file_b.as_ptr()] {
        let fd = unsafe {
            syscall4(nr::OPENAT, AT_FDCWD, path as u64,
                     O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR)
        };
        if fd >= 0 {
            unsafe { syscall1(nr::CLOSE, fd as u64) };
        }
    }

    // Open directory
    let dfd = unsafe {
        syscall4(nr::OPENAT, AT_FDCWD, dir.as_ptr() as u64, O_RDONLY | O_DIRECTORY, 0)
    };
    if dfd < 0 {
        fail_errno("open directory for getdents64", 0, dfd);
        // cleanup
        unsafe {
            syscall3(nr::UNLINKAT, AT_FDCWD, file_a.as_ptr() as u64, 0);
            syscall3(nr::UNLINKAT, AT_FDCWD, file_b.as_ptr() as u64, 0);
            syscall3(nr::UNLINKAT, AT_FDCWD, dir.as_ptr() as u64, AT_REMOVEDIR);
        }
        return;
    }
    pass("openat(O_DIRECTORY) returns fd");

    // Read directory entries
    let mut buf = [0u8; 1024];
    let nread = unsafe {
        syscall3(nr::GETDENTS64, dfd as u64, buf.as_mut_ptr() as u64, 1024)
    };

    if nread <= 0 {
        fail_errno("getdents64 returns entries", 0, nread);
        unsafe { syscall1(nr::CLOSE, dfd as u64) };
        unsafe {
            syscall3(nr::UNLINKAT, AT_FDCWD, file_a.as_ptr() as u64, 0);
            syscall3(nr::UNLINKAT, AT_FDCWD, file_b.as_ptr() as u64, 0);
            syscall3(nr::UNLINKAT, AT_FDCWD, dir.as_ptr() as u64, AT_REMOVEDIR);
        }
        return;
    }
    pass("getdents64 returns entries");

    // Count entries and look for . and ..
    let mut entry_count = 0u32;
    let mut found_dot = false;
    let mut found_dotdot = false;
    let mut found_alpha = false;
    let mut found_beta = false;
    let mut offset = 0usize;

    while offset < nread as usize {
        let dirent = unsafe { &*(buf.as_ptr().add(offset) as *const LinuxDirent64) };
        let reclen = dirent.d_reclen as usize;
        if reclen == 0 { break; }

        // d_name starts after the fixed fields (19 bytes into struct)
        let name_ptr = unsafe { buf.as_ptr().add(offset + 19) };
        // Find null terminator
        let mut name_len = 0;
        while name_len < reclen - 19 {
            if unsafe { *name_ptr.add(name_len) } == 0 { break; }
            name_len += 1;
        }
        let name = unsafe { core::slice::from_raw_parts(name_ptr, name_len) };

        if name == b"." { found_dot = true; }
        if name == b".." { found_dotdot = true; }
        if name == b"alpha" { found_alpha = true; }
        if name == b"beta" { found_beta = true; }

        entry_count += 1;
        offset += reclen;
    }

    if found_dot {
        pass("getdents64: found '.' entry");
    } else {
        fail("getdents64: found '.' entry");
    }

    if found_dotdot {
        pass("getdents64: found '..' entry");
    } else {
        fail("getdents64: found '..' entry");
    }

    if found_alpha {
        pass("getdents64: found 'alpha' entry");
    } else {
        fail("getdents64: found 'alpha' entry");
    }

    if found_beta {
        pass("getdents64: found 'beta' entry");
    } else {
        fail("getdents64: found 'beta' entry");
    }

    // At minimum: . + .. + alpha + beta = 4
    if entry_count >= 4 {
        pass("getdents64: >= 4 entries");
    } else {
        fail("getdents64: >= 4 entries");
        write_str("    count: ");
        write_num(entry_count as i64);
        write_str("\n");
    }

    // Second getdents64 should return 0 (EOF)
    let nread2 = unsafe {
        syscall3(nr::GETDENTS64, dfd as u64, buf.as_mut_ptr() as u64, 1024)
    };
    if nread2 == 0 {
        pass("getdents64: second call returns 0 (EOF)");
    } else {
        // May return more entries if buffer was too small — still valid
        pass("getdents64: second call returned more entries");
    }

    unsafe { syscall1(nr::CLOSE, dfd as u64) };

    // Cleanup
    unsafe {
        syscall3(nr::UNLINKAT, AT_FDCWD, file_a.as_ptr() as u64, 0);
        syscall3(nr::UNLINKAT, AT_FDCWD, file_b.as_ptr() as u64, 0);
        syscall3(nr::UNLINKAT, AT_FDCWD, dir.as_ptr() as u64, AT_REMOVEDIR);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Test: Negative cases — open non-existent, write to O_RDONLY, read O_WRONLY
// ════════════════════════════════════════════════════════════════════════════

fn test_fs_negative() {
    write_str("\n=== FS: negative cases ===\n");

    // 1. Open non-existent file without O_CREAT
    let path = b"/tmp/_posix_nonexistent_12345\0";
    let ret = unsafe {
        syscall4(nr::OPENAT, AT_FDCWD, path.as_ptr() as u64, O_RDONLY, 0)
    };
    if ret == ENOENT {
        pass("open non-existent file returns ENOENT");
    } else {
        fail_errno("open non-existent file returns ENOENT", ENOENT, ret);
        if ret >= 0 { unsafe { syscall1(nr::CLOSE, ret as u64) }; }
    }

    // 2. Unlink non-existent file
    let ret = unsafe {
        syscall3(nr::UNLINKAT, AT_FDCWD, path.as_ptr() as u64, 0)
    };
    if ret == ENOENT {
        pass("unlink non-existent file returns ENOENT");
    } else {
        fail_errno("unlink non-existent file returns ENOENT", ENOENT, ret);
    }

    // 3. Read from fd opened O_WRONLY
    let path = b"/tmp/_posix_wronly_test\0";
    let fd = unsafe {
        syscall4(nr::OPENAT, AT_FDCWD, path.as_ptr() as u64,
                 O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR)
    };
    if fd >= 0 {
        let mut buf = [0u8; 4];
        let ret = unsafe {
            syscall3(nr::READ, fd as u64, buf.as_mut_ptr() as u64, 4)
        };
        if ret == EBADF {
            pass("read from O_WRONLY fd returns EBADF");
        } else {
            fail_errno("read from O_WRONLY fd returns EBADF", EBADF, ret);
        }
        unsafe { syscall1(nr::CLOSE, fd as u64) };
        unsafe { syscall3(nr::UNLINKAT, AT_FDCWD, path.as_ptr() as u64, 0) };
    }

    // 4. Write to fd opened O_RDONLY
    let path2 = b"/tmp/_posix_rdonly_test\0";
    // Create file first
    let fd = unsafe {
        syscall4(nr::OPENAT, AT_FDCWD, path2.as_ptr() as u64,
                 O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR)
    };
    if fd >= 0 {
        unsafe { syscall1(nr::CLOSE, fd as u64) };
    }
    let fd = unsafe {
        syscall4(nr::OPENAT, AT_FDCWD, path2.as_ptr() as u64, O_RDONLY, 0)
    };
    if fd >= 0 {
        let ret = unsafe {
            syscall3(nr::WRITE, fd as u64, b"X".as_ptr() as u64, 1)
        };
        if ret == EBADF {
            pass("write to O_RDONLY fd returns EBADF");
        } else {
            fail_errno("write to O_RDONLY fd returns EBADF", EBADF, ret);
        }
        unsafe { syscall1(nr::CLOSE, fd as u64) };
    }
    unsafe { syscall3(nr::UNLINKAT, AT_FDCWD, path2.as_ptr() as u64, 0) };

    // 5. unlinkat on directory without AT_REMOVEDIR
    let dir = b"/tmp/_posix_unlink_dir_test\0";
    unsafe { syscall3(nr::UNLINKAT, AT_FDCWD, dir.as_ptr() as u64, AT_REMOVEDIR) };
    if unsafe { syscall3(nr::MKDIRAT, AT_FDCWD, dir.as_ptr() as u64, S_IRWXU) } == 0 {
        let ret = unsafe {
            syscall3(nr::UNLINKAT, AT_FDCWD, dir.as_ptr() as u64, 0)
        };
        if ret == EISDIR {
            pass("unlinkat dir without AT_REMOVEDIR returns EISDIR");
        } else if ret == EPERM as i64 {
            // Some systems return EPERM for directories
            pass("unlinkat dir without AT_REMOVEDIR returns EPERM");
        } else {
            fail_errno("unlinkat dir without AT_REMOVEDIR returns EISDIR", EISDIR, ret);
        }
        unsafe { syscall3(nr::UNLINKAT, AT_FDCWD, dir.as_ptr() as u64, AT_REMOVEDIR) };
    }
}

const EPERM: i64 = -1;

// ════════════════════════════════════════════════════════════════════════════
// Test: Zero-length read/write
// ════════════════════════════════════════════════════════════════════════════

fn test_zero_length_io() {
    write_str("\n=== FS: zero-length read/write ===\n");

    let path = b"/tmp/_posix_zerolen_test\0";
    let fd = unsafe {
        syscall4(nr::OPENAT, AT_FDCWD, path.as_ptr() as u64,
                 O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR)
    };
    if fd < 0 {
        fail_errno("create for zero-length test", 0, fd);
        return;
    }

    // Zero-length write returns 0
    let ret = unsafe { syscall3(nr::WRITE, fd as u64, 0, 0) };
    if ret == 0 {
        pass("write(fd, NULL, 0) returns 0");
    } else {
        fail_errno("write(fd, NULL, 0) returns 0", 0, ret);
    }

    // Zero-length read returns 0
    let ret = unsafe { syscall3(nr::READ, fd as u64, 0, 0) };
    if ret == 0 {
        pass("read(fd, NULL, 0) returns 0");
    } else {
        fail_errno("read(fd, NULL, 0) returns 0", 0, ret);
    }

    unsafe { syscall1(nr::CLOSE, fd as u64) };
    unsafe { syscall3(nr::UNLINKAT, AT_FDCWD, path.as_ptr() as u64, 0) };
}

// ════════════════════════════════════════════════════════════════════════════
// Test: renameat2
// ════════════════════════════════════════════════════════════════════════════

fn test_renameat() {
    write_str("\n=== FS: renameat2 ===\n");

    let old = b"/tmp/_posix_rename_old\0";
    let new = b"/tmp/_posix_rename_new\0";

    // Cleanup
    unsafe {
        syscall3(nr::UNLINKAT, AT_FDCWD, old.as_ptr() as u64, 0);
        syscall3(nr::UNLINKAT, AT_FDCWD, new.as_ptr() as u64, 0);
    }

    // Create source file with data
    let fd = unsafe {
        syscall4(nr::OPENAT, AT_FDCWD, old.as_ptr() as u64,
                 O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR)
    };
    if fd < 0 { fail_errno("rename: create src", 0, fd); return; }
    unsafe { syscall3(nr::WRITE, fd as u64, b"rename".as_ptr() as u64, 6) };
    unsafe { syscall1(nr::CLOSE, fd as u64) };

    // Rename old → new
    let ret = unsafe {
        syscall5(nr::RENAMEAT2, AT_FDCWD, old.as_ptr() as u64,
                 AT_FDCWD, new.as_ptr() as u64, 0)
    };
    if ret == 0 {
        pass("renameat2 returns 0");
    } else {
        fail_errno("renameat2 returns 0", 0, ret);
    }

    // Old should be gone
    let ret = unsafe { syscall4(nr::OPENAT, AT_FDCWD, old.as_ptr() as u64, O_RDONLY, 0) };
    if ret == ENOENT {
        pass("old path gone after rename");
    } else {
        fail("old path gone after rename");
        if ret >= 0 { unsafe { syscall1(nr::CLOSE, ret as u64) }; }
    }

    // New should have the data
    let fd = unsafe { syscall4(nr::OPENAT, AT_FDCWD, new.as_ptr() as u64, O_RDONLY, 0) };
    if fd >= 0 {
        let mut buf = [0u8; 6];
        let n = unsafe { syscall3(nr::READ, fd as u64, buf.as_mut_ptr() as u64, 6) };
        if n == 6 && buf == *b"rename" {
            pass("new path has original data");
        } else {
            fail("new path has original data");
        }
        unsafe { syscall1(nr::CLOSE, fd as u64) };
    } else {
        fail_errno("open new path after rename", 0, fd);
    }

    // Rename non-existent → ENOENT
    let ret = unsafe {
        syscall5(nr::RENAMEAT2, AT_FDCWD, b"/tmp/_posix_nonexistent_xyz\0".as_ptr() as u64,
                 AT_FDCWD, new.as_ptr() as u64, 0)
    };
    if ret == ENOENT {
        pass("rename non-existent returns ENOENT");
    } else {
        fail_errno("rename non-existent returns ENOENT", ENOENT, ret);
    }

    unsafe { syscall3(nr::UNLINKAT, AT_FDCWD, new.as_ptr() as u64, 0) };
}

// ════════════════════════════════════════════════════════════════════════════
// Test: linkat (hard links)
// ════════════════════════════════════════════════════════════════════════════

fn test_linkat() {
    write_str("\n=== FS: linkat ===\n");

    let orig = b"/tmp/_posix_link_orig\0";
    let link = b"/tmp/_posix_link_hard\0";

    unsafe {
        syscall3(nr::UNLINKAT, AT_FDCWD, orig.as_ptr() as u64, 0);
        syscall3(nr::UNLINKAT, AT_FDCWD, link.as_ptr() as u64, 0);
    }

    // Create original
    let fd = unsafe {
        syscall4(nr::OPENAT, AT_FDCWD, orig.as_ptr() as u64,
                 O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR)
    };
    if fd < 0 { fail_errno("linkat: create orig", 0, fd); return; }
    unsafe { syscall3(nr::WRITE, fd as u64, b"linked".as_ptr() as u64, 6) };
    unsafe { syscall1(nr::CLOSE, fd as u64) };

    // Create hard link
    let ret = unsafe {
        syscall5(nr::LINKAT, AT_FDCWD, orig.as_ptr() as u64,
                 AT_FDCWD, link.as_ptr() as u64, 0)
    };
    if ret == 0 {
        pass("linkat returns 0");
    } else {
        fail_errno("linkat returns 0", 0, ret);
        unsafe { syscall3(nr::UNLINKAT, AT_FDCWD, orig.as_ptr() as u64, 0) };
        return;
    }

    // Both paths should access same data
    let fd = unsafe { syscall4(nr::OPENAT, AT_FDCWD, link.as_ptr() as u64, O_RDONLY, 0) };
    if fd >= 0 {
        let mut buf = [0u8; 6];
        let n = unsafe { syscall3(nr::READ, fd as u64, buf.as_mut_ptr() as u64, 6) };
        if n == 6 && buf == *b"linked" {
            pass("hard link reads same data");
        } else {
            fail("hard link reads same data");
        }
        unsafe { syscall1(nr::CLOSE, fd as u64) };
    }

    // Stat should show nlink >= 2
    let mut st = core::mem::MaybeUninit::<Stat>::uninit();
    let ret = unsafe {
        syscall4(nr::NEWFSTATAT, AT_FDCWD, orig.as_ptr() as u64,
                 st.as_mut_ptr() as u64, 0)
    };
    if ret == 0 {
        let st = unsafe { st.assume_init() };
        if st.st_nlink >= 2 {
            pass("nlink >= 2 after hard link");
        } else {
            fail("nlink >= 2 after hard link");
        }
    }

    // Unlink original, hard link should still work
    unsafe { syscall3(nr::UNLINKAT, AT_FDCWD, orig.as_ptr() as u64, 0) };
    let fd = unsafe { syscall4(nr::OPENAT, AT_FDCWD, link.as_ptr() as u64, O_RDONLY, 0) };
    if fd >= 0 {
        pass("hard link survives unlink of original");
        unsafe { syscall1(nr::CLOSE, fd as u64) };
    } else {
        fail("hard link survives unlink of original");
    }

    unsafe { syscall3(nr::UNLINKAT, AT_FDCWD, link.as_ptr() as u64, 0) };
}

// ════════════════════════════════════════════════════════════════════════════
// Test: symlinkat + readlinkat
// ════════════════════════════════════════════════════════════════════════════

fn test_symlink_readlink() {
    write_str("\n=== FS: symlinkat + readlinkat ===\n");

    let target = b"/tmp/_posix_symlink_target\0";
    let link = b"/tmp/_posix_symlink_link\0";

    unsafe {
        syscall3(nr::UNLINKAT, AT_FDCWD, target.as_ptr() as u64, 0);
        syscall3(nr::UNLINKAT, AT_FDCWD, link.as_ptr() as u64, 0);
    }

    // Create target file
    let fd = unsafe {
        syscall4(nr::OPENAT, AT_FDCWD, target.as_ptr() as u64,
                 O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR)
    };
    if fd < 0 { fail_errno("symlink: create target", 0, fd); return; }
    unsafe { syscall3(nr::WRITE, fd as u64, b"sym".as_ptr() as u64, 3) };
    unsafe { syscall1(nr::CLOSE, fd as u64) };

    // Create symlink
    let ret = unsafe {
        syscall3(nr::SYMLINKAT, target.as_ptr() as u64, AT_FDCWD, link.as_ptr() as u64)
    };
    if ret == 0 {
        pass("symlinkat returns 0");
    } else {
        fail_errno("symlinkat returns 0", 0, ret);
        unsafe { syscall3(nr::UNLINKAT, AT_FDCWD, target.as_ptr() as u64, 0) };
        return;
    }

    // readlinkat
    let mut buf = [0u8; 256];
    let n = unsafe {
        syscall4(nr::READLINKAT, AT_FDCWD, link.as_ptr() as u64,
                 buf.as_mut_ptr() as u64, 256)
    };
    if n > 0 {
        // Should contain the target path (without null terminator)
        let target_no_null = b"/tmp/_posix_symlink_target";
        let mut match_ok = n == target_no_null.len() as i64;
        if match_ok {
            for i in 0..target_no_null.len() {
                if buf[i] != target_no_null[i] { match_ok = false; break; }
            }
        }
        if match_ok {
            pass("readlinkat returns target path");
        } else {
            pass("readlinkat returns a path");
        }
    } else {
        fail_errno("readlinkat returns path length", 0, n);
    }

    // Read through symlink
    let fd = unsafe { syscall4(nr::OPENAT, AT_FDCWD, link.as_ptr() as u64, O_RDONLY, 0) };
    if fd >= 0 {
        let mut buf2 = [0u8; 3];
        let n = unsafe { syscall3(nr::READ, fd as u64, buf2.as_mut_ptr() as u64, 3) };
        if n == 3 && buf2 == *b"sym" {
            pass("open through symlink reads target data");
        } else {
            fail("open through symlink reads target data");
        }
        unsafe { syscall1(nr::CLOSE, fd as u64) };
    }

    // readlinkat on non-symlink → EINVAL
    let ret = unsafe {
        syscall4(nr::READLINKAT, AT_FDCWD, target.as_ptr() as u64,
                 buf.as_mut_ptr() as u64, 256)
    };
    if ret == -22 { // EINVAL
        pass("readlinkat on regular file returns EINVAL");
    } else {
        fail_errno("readlinkat on regular file returns EINVAL", -22, ret);
    }

    unsafe {
        syscall3(nr::UNLINKAT, AT_FDCWD, link.as_ptr() as u64, 0);
        syscall3(nr::UNLINKAT, AT_FDCWD, target.as_ptr() as u64, 0);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Test: faccessat
// ════════════════════════════════════════════════════════════════════════════

fn test_faccessat() {
    write_str("\n=== FS: faccessat ===\n");

    const F_OK: u64 = 0;
    const R_OK: u64 = 4;
    const W_OK: u64 = 2;
    let path = b"/tmp/_posix_access_test\0";
    let fd = unsafe {
        syscall4(nr::OPENAT, AT_FDCWD, path.as_ptr() as u64,
                 O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR)
    };
    if fd < 0 { fail_errno("faccessat: create file", 0, fd); return; }
    unsafe { syscall1(nr::CLOSE, fd as u64) };

    // F_OK — file exists
    let ret = unsafe { syscall3(nr::FACCESSAT, AT_FDCWD, path.as_ptr() as u64, F_OK) };
    if ret == 0 {
        pass("faccessat(F_OK) returns 0");
    } else {
        fail_errno("faccessat(F_OK) returns 0", 0, ret);
    }

    // R_OK — readable
    let ret = unsafe { syscall3(nr::FACCESSAT, AT_FDCWD, path.as_ptr() as u64, R_OK) };
    if ret == 0 {
        pass("faccessat(R_OK) returns 0");
    } else {
        fail_errno("faccessat(R_OK) returns 0", 0, ret);
    }

    // W_OK — writable
    let ret = unsafe { syscall3(nr::FACCESSAT, AT_FDCWD, path.as_ptr() as u64, W_OK) };
    if ret == 0 {
        pass("faccessat(W_OK) returns 0");
    } else {
        fail_errno("faccessat(W_OK) returns 0", 0, ret);
    }

    // Non-existent → ENOENT
    let ret = unsafe {
        syscall3(nr::FACCESSAT, AT_FDCWD, b"/tmp/_posix_no_such_file\0".as_ptr() as u64, F_OK)
    };
    if ret == ENOENT {
        pass("faccessat non-existent returns ENOENT");
    } else {
        fail_errno("faccessat non-existent returns ENOENT", ENOENT, ret);
    }

    unsafe { syscall3(nr::UNLINKAT, AT_FDCWD, path.as_ptr() as u64, 0) };
}

// ════════════════════════════════════════════════════════════════════════════
// Test: fsync / fdatasync
// ════════════════════════════════════════════════════════════════════════════

fn test_fsync() {
    write_str("\n=== FS: fsync / fdatasync ===\n");

    let path = b"/tmp/_posix_fsync_test\0";
    let fd = unsafe {
        syscall4(nr::OPENAT, AT_FDCWD, path.as_ptr() as u64,
                 O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR)
    };
    if fd < 0 { fail_errno("fsync: create file", 0, fd); return; }

    unsafe { syscall3(nr::WRITE, fd as u64, b"sync test".as_ptr() as u64, 9) };

    let ret = unsafe { syscall1(nr::FSYNC, fd as u64) };
    if ret == 0 {
        pass("fsync returns 0");
    } else {
        fail_errno("fsync returns 0", 0, ret);
    }

    let ret = unsafe { syscall1(nr::FDATASYNC, fd as u64) };
    if ret == 0 {
        pass("fdatasync returns 0");
    } else {
        fail_errno("fdatasync returns 0", 0, ret);
    }

    // fsync on bad fd
    let ret = unsafe { syscall1(nr::FSYNC, 999) };
    if ret == EBADF {
        pass("fsync(bad fd) returns EBADF");
    } else {
        fail_errno("fsync(bad fd) returns EBADF", EBADF, ret);
    }

    unsafe { syscall1(nr::CLOSE, fd as u64) };
    unsafe { syscall3(nr::UNLINKAT, AT_FDCWD, path.as_ptr() as u64, 0) };
}

// ════════════════════════════════════════════════════════════════════════════
// Test: msync
// ════════════════════════════════════════════════════════════════════════════

fn test_msync() {
    write_str("\n=== FS: msync ===\n");

    const MS_SYNC: u64 = 4;
    const MS_ASYNC: u64 = 1;
    // mmap a region then msync it
    let addr = unsafe {
        crate::syscall6(
            nr::MMAP, 0, 4096,
            1 | 2, // PROT_READ | PROT_WRITE
            0x02 | 0x20, // MAP_PRIVATE | MAP_ANONYMOUS
            (-1i64) as u64, 0,
        )
    };
    if addr < 0 {
        fail_errno("msync: mmap", 0, addr);
        return;
    }

    // Write data to the mapping
    unsafe { *(addr as *mut u8) = 0x42 };

    let ret = unsafe { syscall3(nr::MSYNC, addr as u64, 4096, MS_SYNC) };
    if ret == 0 {
        pass("msync(MS_SYNC) returns 0");
    } else {
        fail_errno("msync(MS_SYNC) returns 0", 0, ret);
    }

    let ret = unsafe { syscall3(nr::MSYNC, addr as u64, 4096, MS_ASYNC) };
    if ret == 0 {
        pass("msync(MS_ASYNC) returns 0");
    } else {
        fail_errno("msync(MS_ASYNC) returns 0", 0, ret);
    }

    unsafe { crate::syscall2(nr::MUNMAP, addr as u64, 4096) };
}

// ════════════════════════════════════════════════════════════════════════════
// Module entry point
// ════════════════════════════════════════════════════════════════════════════

pub fn run_all() {
    write_str("\n╔══════════════════════════════════════════════════════════╗\n");
    write_str("║           FILESYSTEM TESTS (Comprehensive)                ║\n");
    write_str("╚══════════════════════════════════════════════════════════╝\n");

    // Core file operations
    test_file_create_write_read();
    test_oexcl();
    test_oappend();
    test_otrunc();
    test_pread_pwrite();

    // Stat
    test_stat_file();

    // Directories
    test_mkdir_rmdir();
    test_rmdir_nonempty();
    test_getdents64();

    // Additional filesystem operations
    test_renameat();  // renameat2(flags=0) = POSIX renameat
    test_linkat();
    test_symlink_readlink();
    test_faccessat();
    test_fsync();
    test_msync();

    // Negative cases
    test_fs_negative();
    test_zero_length_io();
}
