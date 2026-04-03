//! Architecture-specific plumbing.
//!
//! Each arch module exports:
//! - syscall0 through syscall6
//! - _start entry point
//! - sig_restorer (for rt_sigaction SA_RESTORER)
//! - clone_thread (thread creation trampoline)
//! - TLS read/write helpers

#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(target_arch = "x86_64")]
pub use x86_64::*;

#[cfg(target_arch = "aarch64")]
mod aarch64;

#[cfg(target_arch = "aarch64")]
pub use aarch64::*;
