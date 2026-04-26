//! Raw kernel-to-userspace event ABI for Mini-EDR sensor probes.
//!
//! SDD §4.1.1 defines `RawSyscallEvent` as the only C-compatible schema shared
//! by kernel eBPF code and userspace. The layout below intentionally uses fixed
//! width integers and byte arrays only, so it can be copied through
//! `BPF_MAP_TYPE_RINGBUF` without allocation or Rust enum layout assumptions.

use mini_edr_common::SyscallType;

/// Maximum filename bytes copied from user memory by the `openat` probe.
///
/// The kernel verifier allows this buffer on the stack while still leaving
/// enough room for helper-call bookkeeping. Userspace treats the first NUL byte
/// as the logical end of the path.
pub const MAX_FILENAME_LEN: usize = 256;

/// Discriminator values written by the kernel program into `RawSyscallEvent`.
///
/// A primitive `u32` representation keeps the wire format stable across Rust
/// compiler versions and maps directly to `mini_edr_common::SyscallType` after
/// ring-buffer deserialization.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawSyscallType {
    /// Process image replacement through `execve`.
    Execve = 1,
    /// File open operation through `openat`.
    Openat = 2,
    /// Network connection attempt through `connect`.
    Connect = 3,
    /// Process or thread creation through `clone`.
    Clone = 4,
}

impl RawSyscallType {
    /// Convert a raw kernel discriminator into the shared userspace enum.
    ///
    /// # Errors
    ///
    /// Returns `RawEventError::UnknownSyscallType` when the raw value is not one
    /// of the four syscall probes mandated by SRS FR-S01.
    pub const fn to_syscall_type(value: u32) -> Result<SyscallType, RawEventError> {
        match value {
            value if value == Self::Execve as u32 => Ok(SyscallType::Execve),
            value if value == Self::Openat as u32 => Ok(SyscallType::Openat),
            value if value == Self::Connect as u32 => Ok(SyscallType::Connect),
            value if value == Self::Clone as u32 => Ok(SyscallType::Clone),
            value => Err(RawEventError::UnknownSyscallType(value)),
        }
    }
}

/// C-compatible event emitted by the eBPF tracepoint programs.
///
/// Fields are ordered from largest to smallest to keep the alignment at eight
/// bytes without hidden high-alignment members. The total size is asserted in
/// tests because any drift would corrupt the userspace ring-buffer consumer.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawSyscallEvent {
    /// Monotonic kernel timestamp from `bpf_ktime_get_ns`.
    pub timestamp: u64,
    /// Thread-group/process identifier from `bpf_get_current_pid_tgid`.
    pub pid: u32,
    /// Kernel thread identifier from `bpf_get_current_pid_tgid`.
    pub tid: u32,
    /// Parent process identifier read from the current task relationship.
    pub ppid: u32,
    /// One of `RawSyscallType` encoded as a stable `u32`.
    pub syscall_type: u32,
    /// IPv4 destination address in host-order octets for `connect`.
    pub ipv4_addr: [u8; 4],
    /// Destination port in host byte order for `connect`.
    pub port: u16,
    /// Number of bytes copied into `filename`, excluding any trailing NUL.
    pub filename_len: u16,
    /// Child PID for clone-style events when available from the tracepoint.
    pub child_pid: u32,
    /// Reserved bytes keep the ABI aligned and leave room for later flags.
    pub reserved: u32,
    /// NUL-padded filename copied from userspace for `openat`.
    pub filename: [u8; MAX_FILENAME_LEN],
}

impl Default for RawSyscallEvent {
    fn default() -> Self {
        Self {
            timestamp: 0,
            pid: 0,
            tid: 0,
            ppid: 0,
            syscall_type: 0,
            ipv4_addr: [0; 4],
            port: 0,
            filename_len: 0,
            child_pid: 0,
            reserved: 0,
            filename: [0; MAX_FILENAME_LEN],
        }
    }
}

/// Errors returned while interpreting raw kernel event records.
#[derive(Debug, thiserror::Error)]
pub enum RawEventError {
    /// The eBPF program emitted a syscall discriminator outside FR-S01's set.
    #[error("unknown raw syscall type discriminator {0}")]
    UnknownSyscallType(u32),
}

#[cfg(test)]
mod tests {
    use super::{MAX_FILENAME_LEN, RawSyscallEvent};

    #[test]
    fn raw_syscall_event_size_documents_ring_buffer_abi() {
        assert_eq!(core::mem::align_of::<RawSyscallEvent>(), 8);
        assert_eq!(core::mem::size_of::<RawSyscallEvent>(), 296);
        assert_eq!(MAX_FILENAME_LEN, 256);
    }
}
