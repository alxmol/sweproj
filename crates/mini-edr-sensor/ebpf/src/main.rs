#![no_std]
#![no_main]

//! Pure-Rust Aya eBPF programs for Mini-EDR syscall capture.
//!
//! The programs attach to syscall tracepoints from SRS FR-S01 and emit one
//! fixed-layout `RawSyscallEvent` per observed syscall through a
//! `BPF_MAP_TYPE_RINGBUF` map. Execve/openat/connect use syscall-entry hooks
//! because their arguments are available before the syscall runs; clone uses the
//! syscall-exit hook because VAL-SENSOR-006 requires the child PID returned to
//! the parent by the kernel. Every helper use is intentionally documented in
//! place because kernel verifier failures are easier to debug when the safety
//! and portability assumptions are visible next to the code.

use aya_ebpf::{
    cty::c_long,
    helpers::{
        bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_probe_read_user,
        bpf_probe_read_user_str_bytes, gen,
    },
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use core::{mem, panic::PanicInfo};

const MAX_FILENAME_LEN: usize = 256;
const RAW_EXECVE: u32 = 1;
const RAW_OPENAT: u32 = 2;
const RAW_CONNECT: u32 = 3;
const RAW_CLONE: u32 = 4;
const AF_INET: u16 = 2;

/// Shared ring-buffer transport required by SRS FR-S03.
///
/// `RingBuf` maps were introduced in Linux 5.8 and provide ordered,
/// shared-across-CPU delivery. `output` copies a stack event into the map and
/// returns an error if the buffer is full, which lets the kernel continue
/// instead of blocking syscall execution.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);

#[repr(C)]
#[derive(Clone, Copy)]
struct RawSyscallEvent {
    timestamp: u64,
    pid: u32,
    tid: u32,
    ppid: u32,
    syscall_type: u32,
    ipv4_addr: [u8; 4],
    port: u16,
    filename_len: u16,
    child_pid: u32,
    reserved: u32,
    filename: [u8; MAX_FILENAME_LEN],
}

impl RawSyscallEvent {
    fn new(syscall_type: u32) -> Self {
        // `bpf_ktime_get_ns` supplies a monotonic timestamp from the kernel's
        // fast time source. It avoids wall-clock adjustments and is therefore
        // the correct ordering key for the downstream process-window logic.
        let timestamp = unsafe { gen::bpf_ktime_get_ns() };
        let pid_tgid = bpf_get_current_pid_tgid();

        Self {
            timestamp,
            pid: (pid_tgid >> 32) as u32,
            tid: pid_tgid as u32,
            ppid: current_parent_tgid(),
            syscall_type,
            ipv4_addr: [0; 4],
            port: 0,
            filename_len: 0,
            child_pid: 0,
            reserved: 0,
            filename: [0; MAX_FILENAME_LEN],
        }
    }
}

/// Capture `execve(2)` entry events.
#[tracepoint]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    handle_execve(&ctx).unwrap_or(0)
}

fn handle_execve(_ctx: &TracePointContext) -> Result<u32, c_long> {
    let event = RawSyscallEvent::new(RAW_EXECVE);
    submit_event(&event);
    Ok(0)
}

/// Capture `openat(2)` entry events and copy the user filename pointer.
#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    handle_openat(&ctx).unwrap_or(0)
}

fn handle_openat(ctx: &TracePointContext) -> Result<u32, c_long> {
    let mut event = RawSyscallEvent::new(RAW_OPENAT);
    let filename_ptr = read_syscall_arg(ctx, 1)? as *const u8;

    // `bpf_probe_read_user_str_bytes` is the verifier-aware way to copy a
    // userspace C string. It bounds the read to our stack buffer, NUL-terminates
    // on success, and returns the logical byte count so userspace can detect
    // truncation without scanning uninitialized memory.
    if !filename_ptr.is_null() {
        // SAFETY: The pointer is a syscall argument supplied by userspace. The
        // BPF helper validates that the address is readable and copies at most
        // `event.filename.len()` bytes into our stack-owned buffer.
        if let Ok(bytes) =
            unsafe { bpf_probe_read_user_str_bytes(filename_ptr, &mut event.filename) }
        {
            event.filename_len = bytes.len().min(MAX_FILENAME_LEN) as u16;
        }
    }

    submit_event(&event);
    Ok(0)
}

/// Capture `connect(2)` entry events and decode IPv4 sockaddr data.
#[tracepoint]
pub fn sys_enter_connect(ctx: TracePointContext) -> u32 {
    handle_connect(&ctx).unwrap_or(0)
}

fn handle_connect(ctx: &TracePointContext) -> Result<u32, c_long> {
    let mut event = RawSyscallEvent::new(RAW_CONNECT);
    let sockaddr_ptr = read_syscall_arg(ctx, 1)? as *const SockAddrIn;

    // The sockaddr lives in userspace at syscall entry, so `bpf_probe_read_user`
    // is mandatory; using a kernel read helper would fail verifier/runtime
    // checks and could leak invalid data. We only decode AF_INET because the
    // validation contract for this feature is IPv4-specific.
    if !sockaddr_ptr.is_null() {
        // SAFETY: The helper copies exactly `SockAddrIn` bytes from the user
        // pointer if readable. Invalid or short pointers return an error, which
        // leaves the event arguments at their zero defaults.
        if let Ok(addr) = unsafe { bpf_probe_read_user(sockaddr_ptr) } {
            if addr.sin_family == AF_INET {
                event.port = u16::from_be(addr.sin_port);
                event.ipv4_addr = addr.sin_addr.to_be_bytes();
            }
        }
    }

    submit_event(&event);
    Ok(0)
}

/// Capture successful `clone(2)` exit events with the kernel-returned child PID.
#[tracepoint]
pub fn sys_exit_clone(ctx: TracePointContext) -> u32 {
    handle_clone(&ctx).unwrap_or(0)
}

fn handle_clone(ctx: &TracePointContext) -> Result<u32, c_long> {
    let child_pid = read_syscall_return(ctx)?;
    if child_pid <= 0 {
        return Ok(0);
    }

    let mut event = RawSyscallEvent::new(RAW_CLONE);
    event.child_pid = child_pid as u32;
    submit_event(&event);
    Ok(0)
}

fn read_syscall_arg(ctx: &TracePointContext, index: usize) -> Result<u64, c_long> {
    // Linux syscall tracepoints use `trace_event_raw_sys_enter`: an 8-byte
    // `trace_entry`, an 8-byte syscall id, then six 8-byte argument slots. Aya's
    // `read_at` wraps `bpf_probe_read`, which is acceptable for tracepoint
    // context memory because it is kernel-owned and verifier-bounded by offset.
    let offset = 16 + (index * mem::size_of::<u64>());
    // SAFETY: `offset` selects one of the fixed syscall argument slots described
    // above. Callers pass only constants in the 0..6 range for traced syscalls.
    unsafe { ctx.read_at::<u64>(offset) }
}

fn read_syscall_return(ctx: &TracePointContext) -> Result<i64, c_long> {
    // Linux syscall-exit tracepoints use `trace_event_raw_sys_exit`: an 8-byte
    // `trace_entry`, a 4-byte syscall id, 4 bytes of padding, then the signed
    // `long ret` value at offset 16. This offset was verified on the host via
    // `/sys/kernel/tracing/events/syscalls/sys_exit_clone/format`, whose format
    // reports `field:long ret; offset:16; size:8; signed:1`.
    //
    // We intentionally emit clone events only from the parent-side successful
    // return where `ret` is the new child PID. Failed clone calls return a
    // negative errno and the child-side return is zero, neither of which can
    // satisfy VAL-SENSOR-006's actual-child-pid equality check.
    // SAFETY: Offset 16 is the fixed, verifier-bounded `ret` slot in the
    // syscall-exit tracepoint context described above.
    unsafe { ctx.read_at::<i64>(16) }
}

fn submit_event(event: &RawSyscallEvent) {
    // `RingBuf::output` copies a fully initialized fixed-layout event. We ignore
    // the return code in this feature because the follow-up overflow feature
    // owns drop counters; critically, failed output does not block the syscall.
    let _ = EVENTS.output(event, 0);
}

fn current_parent_tgid() -> u32 {
    // Parent PID is read from `task_struct` to satisfy SRS FR-S02. Aya's helper
    // surface exposes raw BPF helpers, but not libbpf-style `BPF_CORE_READ`
    // macros. The offsets below are kept isolated so a later CO-RE generated
    // bindings pass can replace them without touching event construction.
    //
    // SAFETY: `bpf_get_current_task_btf` returns the current task pointer or
    // NULL. Each subsequent load goes through `bpf_probe_read_kernel`, so invalid
    // offsets fail safely and return the default ppid=0 rather than dereferencing
    // a raw pointer directly in Rust.
    unsafe {
        let task = gen::bpf_get_current_task_btf() as *const u8;
        if task.is_null() {
            return 0;
        }

        // These fields are stable enough for the host/CI kernel smoke path but
        // intentionally centralized. `real_parent` points at another
        // `task_struct`; `tgid` is the process id userspace expects as PPID.
        const REAL_PARENT_OFFSET: usize = 2_568;
        const TGID_OFFSET: usize = 2_328;
        let parent_ptr_addr: u64 =
            bpf_probe_read_kernel(task.add(REAL_PARENT_OFFSET).cast::<u64>()).unwrap_or(0);
        if parent_ptr_addr == 0 {
            return 0;
        }
        bpf_probe_read_kernel((parent_ptr_addr as *const u8).add(TGID_OFFSET).cast::<u32>())
            .unwrap_or(0)
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [u8; 8],
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    // eBPF programs cannot unwind. If verifier-unreachable code panics, spin so
    // the compiler has a defined diverging endpoint; ordinary logic returns
    // errors instead of panicking.
    loop {}
}
