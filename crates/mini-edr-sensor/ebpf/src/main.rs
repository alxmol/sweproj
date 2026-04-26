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

#[allow(dead_code, non_camel_case_types, non_snake_case, non_upper_case_globals)]
mod vmlinux;

use aya_ebpf::{
    cty::c_long,
    helpers::{
        bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_probe_read_user,
        bpf_probe_read_user_str_bytes, gen,
    },
    macros::{map, tracepoint},
    maps::{Array, PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use core::{mem, panic::PanicInfo};
use vmlinux::task_struct;

const MAX_FILENAME_LEN: usize = 256;
const RAW_EXECVE: u32 = 1;
const RAW_OPENAT: u32 = 2;
const RAW_CONNECT: u32 = 3;
const RAW_CLONE: u32 = 4;
const AF_INET: u16 = 2;
const RINGBUF_DROP_COUNTER_INDEX: u32 = 0;
const FAULT_MODE_NORMAL: u32 = 0;
const FAULT_MODE_INVALID_RINGBUF_FLAGS: u32 = 1;
const INVALID_RINGBUF_OUTPUT_FLAGS: u64 = 1 << 2;
const EINVAL: i64 = -22;

/// Shared ring-buffer transport required by SRS FR-S03.
///
/// `RingBuf` maps were introduced in Linux 5.8 and provide ordered,
/// shared-across-CPU delivery. `output` copies a stack event into the map and
/// returns an error if the buffer is full, which lets the kernel continue
/// instead of blocking syscall execution.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);

/// Per-CPU counter of ring-buffer submission drops.
///
/// We deliberately use a per-CPU map instead of a shared scalar so tracepoints
/// can update their local slot without atomics or spin locks. Userspace sums
/// the slots when exposing health metrics, which preserves every lost sample
/// count even during a cross-CPU burst.
#[map]
static RINGBUF_DROP_COUNTS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Per-CPU counter of probe runtime helper faults keyed by syscall probe index.
///
/// Runtime faults are distinct from overflow drops: they represent helper
/// failures such as the test hook's deliberate `-EINVAL` path. Keeping them in
/// a separate map lets the daemon report "`connect` is faulting" without
/// suggesting the whole ring buffer is saturated.
#[map]
static PROBE_RUNTIME_ERRORS: PerCpuArray<u64> = PerCpuArray::with_max_entries(4, 0);

/// Test-only control plane for per-probe fault injection.
///
/// Userspace can toggle one syscall probe into `InvalidRingbufFlags` mode so
/// `bpf_ringbuf_output` returns `-EINVAL` repeatedly. The other probes keep
/// using valid flags and therefore continue delivering events at their normal
/// rate, which is the isolation property required by VAL-SENSOR-019.
#[map]
static PROBE_FAULT_MODES: Array<u32> = Array::with_max_entries(4, 0);

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
                // `sockaddr_in.sin_addr.s_addr` already stores the IPv4 octets
                // in network-byte order in memory. The userspace contract wants
                // those raw octets verbatim (127.0.0.1 => [127, 0, 0, 1]), so
                // we use native-endian byte extraction to preserve the in-memory
                // layout instead of swapping it again with `to_be_bytes()`.
                event.ipv4_addr = addr.sin_addr.to_ne_bytes();
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
    // The tracepoint must never block kernel execution when userspace falls
    // behind. `bpf_ringbuf_output` therefore stays best-effort: success copies
    // the event, a full buffer increments the graceful-drop counter, and an
    // explicit fault-injection mode turns the helper's `-EINVAL` into a
    // per-syscall runtime error without destabilizing the other probes.
    let fault_mode = fault_mode_for_syscall(event.syscall_type);
    let flags = match fault_mode {
        FAULT_MODE_INVALID_RINGBUF_FLAGS => INVALID_RINGBUF_OUTPUT_FLAGS,
        _ => 0,
    };
    if let Err(error) = EVENTS.output(event, flags) {
        match classify_submit_failure(fault_mode, error) {
            SubmitFailureClass::DroppedOverflow => increment_drop_counter(),
            SubmitFailureClass::RuntimeFault => increment_runtime_error_counter(event.syscall_type),
        }
    }
}

fn fault_mode_for_syscall(raw_syscall_type: u32) -> u32 {
    let Some(index) = syscall_counter_index(raw_syscall_type) else {
        return FAULT_MODE_NORMAL;
    };

    // SAFETY: `index` is derived from the fixed four-syscall mapping above, so
    // it is always within the array's declared bounds. Missing entries simply
    // fall back to normal mode, which keeps production traffic unaffected by a
    // misconfigured test hook.
    PROBE_FAULT_MODES
        .get(index)
        .copied()
        .unwrap_or(FAULT_MODE_NORMAL)
}

fn increment_drop_counter() {
    // SAFETY: The map has exactly one slot at index zero. Per-CPU arrays hand
    // back a mutable pointer to this CPU's storage, so incrementing it does not
    // contend with other CPUs and cannot corrupt a shared global scalar.
    unsafe {
        if let Some(slot) = RINGBUF_DROP_COUNTS.get_ptr_mut(RINGBUF_DROP_COUNTER_INDEX) {
            *slot = (*slot).wrapping_add(1);
        }
    }
}

fn increment_runtime_error_counter(raw_syscall_type: u32) {
    let Some(index) = syscall_counter_index(raw_syscall_type) else {
        return;
    };

    // SAFETY: `index` is one of the four fixed syscall slots, and the per-CPU
    // map returns a pointer to the current CPU's private counter cell.
    unsafe {
        if let Some(slot) = PROBE_RUNTIME_ERRORS.get_ptr_mut(index) {
            *slot = (*slot).wrapping_add(1);
        }
    }
}

const fn syscall_counter_index(raw_syscall_type: u32) -> Option<u32> {
    match raw_syscall_type {
        RAW_EXECVE => Some(0),
        RAW_OPENAT => Some(1),
        RAW_CONNECT => Some(2),
        RAW_CLONE => Some(3),
        _ => None,
    }
}

#[derive(Clone, Copy)]
enum SubmitFailureClass {
    DroppedOverflow,
    RuntimeFault,
}

const fn classify_submit_failure(fault_mode: u32, error: c_long) -> SubmitFailureClass {
    if error == EINVAL && fault_mode == FAULT_MODE_INVALID_RINGBUF_FLAGS {
        SubmitFailureClass::RuntimeFault
    } else {
        SubmitFailureClass::DroppedOverflow
    }
}

fn current_parent_tgid() -> u32 {
    // Parent PID is read from `task_struct` to satisfy SRS FR-S02. We use an
    // Aya-generated `vmlinux` binding so the field accesses reference BTF type
    // names (`task_struct.real_parent` and `task_struct.tgid`) rather than
    // host-specific byte offsets. That is the CO-RE-safe path requested by the
    // scrutiny fix: the same compiled object can be relocated on 5.8 and 6.x
    // kernels as long as the target kernel provides matching BTF metadata.
    //
    // SAFETY: `bpf_get_current_task_btf` returns a BTF-typed pointer for the
    // current task or NULL. We never dereference the raw pointer directly;
    // instead we pass field addresses through `bpf_probe_read_kernel`, which
    // keeps the verifier-visible memory reads bounded and returns zero on
    // failure rather than faulting the tracepoint.
    unsafe {
        let task = gen::bpf_get_current_task_btf() as *const task_struct;
        if task.is_null() {
            return 0;
        }

        let parent = bpf_probe_read_kernel(core::ptr::addr_of!((*task).real_parent))
            .unwrap_or(core::ptr::null_mut());
        if parent.is_null() {
            return 0;
        }

        bpf_probe_read_kernel(core::ptr::addr_of!((*parent).tgid))
            .map(|tgid| tgid as u32)
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
