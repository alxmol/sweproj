//! Userspace helpers for building and smoke-loading the Aya eBPF probes.
//!
//! This module owns only the kernel-object boundary for feature `f2-bpf-programs`.
//! Higher-level lifecycle APIs (`SensorManager` and dynamic detach/reattach)
//! live in `crate::manager` so this code stays focused on FR-S01..FR-S03 and
//! VAL-SENSOR-001..008.

use crate::raw_event::{RawSyscallEvent, RawSyscallType};
use aya::{Ebpf, maps::RingBuf, programs::TracePoint};
use std::{
    collections::HashSet,
    fs, io,
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::Instant,
};

/// Name of the BPF ring buffer map used as the event transport.
pub const EVENT_RINGBUF_MAP: &str = "EVENTS";

/// Metadata for one generated tracepoint program.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BpfProgramSpec {
    /// Aya program symbol compiled into the eBPF object.
    pub program_name: &'static str,
    /// ELF section name produced by the Aya `#[tracepoint]` macro.
    pub section_name: &'static str,
    /// Kernel tracepoint category passed to `TracePoint::attach`.
    pub category: &'static str,
    /// Kernel tracepoint name passed to `TracePoint::attach`.
    pub tracepoint: &'static str,
    /// Raw event discriminator expected from this program.
    pub raw_type: RawSyscallType,
}

/// The four FR-S01 syscall probes compiled into the eBPF object.
pub const BPF_PROGRAMS: &[BpfProgramSpec] = &[
    BpfProgramSpec {
        program_name: "sys_enter_execve",
        section_name: "tracepoint",
        category: "syscalls",
        tracepoint: "sys_enter_execve",
        raw_type: RawSyscallType::Execve,
    },
    BpfProgramSpec {
        program_name: "sys_enter_openat",
        section_name: "tracepoint",
        category: "syscalls",
        tracepoint: "sys_enter_openat",
        raw_type: RawSyscallType::Openat,
    },
    BpfProgramSpec {
        program_name: "sys_enter_connect",
        section_name: "tracepoint",
        category: "syscalls",
        tracepoint: "sys_enter_connect",
        raw_type: RawSyscallType::Connect,
    },
    BpfProgramSpec {
        program_name: "sys_exit_clone",
        section_name: "tracepoint",
        category: "syscalls",
        tracepoint: "sys_exit_clone",
        raw_type: RawSyscallType::Clone,
    },
];

/// Return the deterministic path where the nested eBPF release build writes
/// the loadable ELF object.
#[must_use]
pub fn ebpf_object_path() -> PathBuf {
    repo_root()
        .join("target")
        .join("mini-edr-sensor-ebpf")
        .join("bpfel-unknown-none")
        .join("release")
        .join("mini-edr-sensor-ebpf")
}

/// Build the kernel-side Rust eBPF package with nightly and return its object.
///
/// # Errors
///
/// Returns `BuildError` if Cargo cannot be spawned, the nightly eBPF build
/// exits non-zero, or the expected ELF object is missing afterward.
pub fn build_ebpf_object() -> Result<PathBuf, BuildError> {
    let root = repo_root();
    let ebpf_dir = root.join("crates").join("mini-edr-sensor").join("ebpf");
    let manifest = ebpf_dir.join("Cargo.toml");
    let target_dir = root.join("target").join("mini-edr-sensor-ebpf");

    // Cargo discovers `.cargo/config.toml` from the child process working
    // directory rather than from `--manifest-path` alone. Running from the
    // nested eBPF crate is what applies the local `bpf-linker --btf` rustflags
    // required for CO-RE metadata while leaving the userspace workspace clean.
    let mut command = Command::new("cargo");
    command
        .current_dir(&ebpf_dir)
        .arg("+nightly")
        .arg("build")
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--release")
        .arg("--target")
        .arg("bpfel-unknown-none")
        .arg("-Z")
        .arg("build-std=core")
        .arg("--target-dir")
        .arg(&target_dir);
    clear_outer_cargo_toolchain_env(&mut command);

    let status = command.status().map_err(BuildError::Spawn)?;

    if !status.success() {
        return Err(BuildError::CargoFailed(status.code()));
    }

    let object = ebpf_object_path();
    if !object.exists() {
        return Err(BuildError::ObjectMissing(object));
    }
    Ok(object)
}

/// Errors produced while compiling the nested eBPF package.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    /// The child Cargo process could not be started.
    #[error("failed to spawn cargo +nightly for eBPF build: {0}")]
    Spawn(io::Error),
    /// The child Cargo process returned a failing status.
    #[error("eBPF cargo build failed with exit code {0:?}")]
    CargoFailed(Option<i32>),
    /// The expected eBPF ELF was not written by Cargo.
    #[error("eBPF object was not produced at {0}")]
    ObjectMissing(PathBuf),
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("sensor crate lives under crates/<name>")
        .to_path_buf()
}

fn clear_outer_cargo_toolchain_env(command: &mut Command) {
    // Unit tests and release build scripts both invoke a nested Cargo build for
    // the kernel-side package. When that happens from inside another Cargo
    // process, environment variables such as `RUSTC` can force the child back to
    // the stable compiler even though the command line says `+nightly`. Clearing
    // them lets rustup select nightly and find the `rust-src` component required
    // for `-Z build-std=core`.
    for var in [
        "RUSTC",
        "RUSTDOC",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_ENCODED_RUSTFLAGS",
    ] {
        command.env_remove(var);
    }
}

/// Privileged harness for verifier loading and basic ring-buffer delivery.
pub mod privileged_harness {
    const MAX_RING_DRAIN_BATCH: usize = 4_096;

    use super::{
        BPF_PROGRAMS, EVENT_RINGBUF_MAP, Ebpf, HashSet, Instant, RawSyscallEvent, RawSyscallType,
        RingBuf, TracePoint, build_ebpf_object, fs, thread,
    };
    use crate::kernel_metrics::{
        KernelCounterSnapshot, PROBE_FAULT_MODES_MAP, PROBE_RUNTIME_ERRORS_MAP, ProbeFaultMode,
        RINGBUF_DROP_COUNTER_INDEX, RINGBUF_DROP_COUNTER_MAP, syscall_array_index,
    };
    use aya::maps::{Array, PerCpuArray};
    use libc::{AF_INET, O_RDONLY, SOCK_STREAM, sockaddr, sockaddr_in};
    use std::{convert::TryFrom, ffi::CString, io, mem, os::fd::RawFd, ptr, time::Duration};

    /// Load every probe, attach it to its syscall tracepoint, trigger one event
    /// per syscall class, and verify the ring buffer delivered all classes.
    ///
    /// # Errors
    ///
    /// Returns an error if the BPF object cannot be built/loaded, a tracepoint
    /// cannot be attached by the kernel verifier, a syscall trigger fails, or
    /// not all four event discriminators arrive before the timeout.
    pub fn load_attach_and_trigger_all() -> Result<(), Box<dyn std::error::Error>> {
        let object = build_ebpf_object()?;
        let mut bpf = Ebpf::load_file(&object)?;

        // Attaching one link per program mirrors what SensorManager will do in
        // a later feature. We retain link IDs in this stack frame so drops at
        // function exit detach probes cleanly and avoid orphaned programs.
        let mut links = Vec::with_capacity(BPF_PROGRAMS.len());
        for spec in BPF_PROGRAMS {
            let program: &mut TracePoint = bpf
                .program_mut(spec.program_name)
                .ok_or_else(|| format!("missing program {}", spec.program_name))?
                .try_into()?;
            program.load()?;
            let link = program.attach(spec.category, spec.tracepoint)?;
            links.push(link);
        }

        let mut ring = RingBuf::try_from(
            bpf.map_mut(EVENT_RINGBUF_MAP)
                .ok_or("missing EVENTS ring buffer map")?,
        )?;

        trigger_execve()?;
        trigger_openat()?;
        trigger_connect();
        trigger_clone()?;

        let mut observed = HashSet::new();
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline && observed.len() < BPF_PROGRAMS.len() {
            while let Some(item) = ring.next() {
                if item.len() == mem::size_of::<RawSyscallEvent>() {
                    let raw = parse_raw_event(&item);
                    observed.insert(raw.syscall_type);
                }
            }
            thread::sleep(Duration::from_millis(10));
        }

        for spec in BPF_PROGRAMS {
            if !observed.contains(&(spec.raw_type as u32)) {
                return Err(format!("did not observe event for {}", spec.program_name).into());
            }
        }

        drop(links);
        Ok(())
    }

    /// Load the clone probe and verify its emitted child PID against `/proc`.
    ///
    /// # Errors
    ///
    /// Returns an error if the BPF object cannot be built/loaded, the clone
    /// tracepoint cannot attach, the child process cannot be spawned, the child
    /// exits before `/proc/<pid>/stat` can be read, or no matching clone event
    /// arrives before the timeout.
    pub fn load_attach_and_trigger_clone_child_pid() -> Result<(), Box<dyn std::error::Error>> {
        let object = build_ebpf_object()?;
        let mut bpf = Ebpf::load_file(&object)?;
        let clone_spec = BPF_PROGRAMS
            .iter()
            .find(|spec| spec.raw_type == RawSyscallType::Clone)
            .ok_or("missing clone probe specification")?;

        // Attach only the clone probe for this assertion-specific harness. The
        // basic delivery test still loads all probes; narrowing this path keeps
        // the ring buffer quiet enough that a child-pid mismatch is easy to
        // diagnose from the observed events.
        let program: &mut TracePoint = bpf
            .program_mut(clone_spec.program_name)
            .ok_or_else(|| format!("missing program {}", clone_spec.program_name))?
            .try_into()?;
        program.load()?;
        let _link = program.attach(clone_spec.category, clone_spec.tracepoint)?;

        let mut ring = RingBuf::try_from(
            bpf.map_mut(EVENT_RINGBUF_MAP)
                .ok_or("missing EVENTS ring buffer map")?,
        )?;

        let mut child = ChildGuard::spawn_sleeping_child()?;
        let child_pid = child.pid();
        let proc_stat_pid = read_proc_stat_pid(child_pid)?;

        if proc_stat_pid != child_pid {
            return Err(format!(
                "/proc stat pid mismatch: expected {child_pid}, saw {proc_stat_pid}"
            )
            .into());
        }

        let deadline = Instant::now() + Duration::from_secs(3);
        let mut observed_clone_children = Vec::new();
        while Instant::now() < deadline {
            while let Some(item) = ring.next() {
                if item.len() == mem::size_of::<RawSyscallEvent>() {
                    let raw = parse_raw_event(&item);
                    if raw.syscall_type == RawSyscallType::Clone as u32 {
                        observed_clone_children.push(raw.child_pid);
                        if raw.child_pid == child_pid {
                            child.finish()?;
                            return Ok(());
                        }
                    }
                }
            }
            thread::sleep(Duration::from_millis(10));
        }

        let _ = child.finish();
        Err(format!(
            "did not observe clone event for child_pid={child_pid}; observed clone child_pids={observed_clone_children:?}"
        )
        .into())
    }

    /// Attach all probes, induce a ring-buffer overflow burst, and confirm the
    /// kernel drop counter increments while event delivery for at least some
    /// records continues.
    ///
    /// # Errors
    ///
    /// Returns an error if the object cannot be built or loaded, the drop
    /// counter fails to increase after the burst, or the ring buffer delivers no
    /// events at all during the run.
    pub fn load_attach_and_force_overflow_burst() -> Result<(), Box<dyn std::error::Error>> {
        let object = build_ebpf_object()?;
        let mut bpf = Ebpf::load_file(&object)?;
        let _links = attach_all_programs(&mut bpf)?;
        let before = read_kernel_counters(&mut bpf)?;
        let mut ring = RingBuf::try_from(
            bpf.map_mut(EVENT_RINGBUF_MAP)
                .ok_or("missing EVENTS ring buffer map")?,
        )?;
        trigger_openat_burst(500_000)?;

        let mut observed = 0_u64;
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            for _ in 0..MAX_RING_DRAIN_BATCH {
                let Some(item) = ring.next() else {
                    break;
                };
                if item.len() == mem::size_of::<RawSyscallEvent>() {
                    let _ = parse_raw_event(&item);
                    observed = observed.saturating_add(1);
                }
            }
            if observed > 0 {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        drop(ring);

        let after = read_kernel_counters(&mut bpf)?;
        if after.ring_events_dropped_total <= before.ring_events_dropped_total {
            return Err(format!(
                "expected ring-buffer overflow drops to increase; before={} after={}",
                before.ring_events_dropped_total, after.ring_events_dropped_total
            )
            .into());
        }
        if observed == 0 {
            return Err(
                "overflow burst delivered zero records; expected mixed delivery/drop behavior"
                    .into(),
            );
        }

        Ok(())
    }

    /// Inject repeated helper faults into the connect probe and prove they stay
    /// isolated to the connect counter while the other probes continue
    /// delivering events.
    ///
    /// # Errors
    ///
    /// Returns an error if the connect runtime-error counter does not increase
    /// or if no exec/open/clone records are observed while the fault injection
    /// is active.
    pub fn load_attach_and_inject_connect_runtime_faults() -> Result<(), Box<dyn std::error::Error>>
    {
        let object = build_ebpf_object()?;
        let mut bpf = Ebpf::load_file(&object)?;
        let _links = attach_all_programs(&mut bpf)?;
        set_probe_fault_mode(
            &mut bpf,
            RawSyscallType::Connect,
            ProbeFaultMode::InvalidRingbufFlags,
        )?;
        let before = read_kernel_counters(&mut bpf)?;
        let mut ring = RingBuf::try_from(
            bpf.map_mut(EVENT_RINGBUF_MAP)
                .ok_or("missing EVENTS ring buffer map")?,
        )?;
        for _ in 0..64 {
            trigger_connect();
            trigger_execve()?;
            trigger_openat()?;
            trigger_clone()?;
        }

        let mut observed = HashSet::new();
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline
            && !(observed.contains(&(RawSyscallType::Execve as u32))
                && observed.contains(&(RawSyscallType::Openat as u32))
                && observed.contains(&(RawSyscallType::Clone as u32)))
        {
            for _ in 0..MAX_RING_DRAIN_BATCH {
                let Some(item) = ring.next() else {
                    break;
                };
                if item.len() == mem::size_of::<RawSyscallEvent>() {
                    let raw = parse_raw_event(&item);
                    observed.insert(raw.syscall_type);
                    if observed.contains(&(RawSyscallType::Execve as u32))
                        && observed.contains(&(RawSyscallType::Openat as u32))
                        && observed.contains(&(RawSyscallType::Clone as u32))
                    {
                        break;
                    }
                }
            }
            thread::sleep(Duration::from_millis(10));
        }
        drop(ring);

        let after = read_kernel_counters(&mut bpf)?;
        if after.runtime_errors_for(mini_edr_common::SyscallType::Connect)
            <= before.runtime_errors_for(mini_edr_common::SyscallType::Connect)
        {
            return Err(format!(
                "expected connect runtime errors to increase; before={} after={}",
                before.runtime_errors_for(mini_edr_common::SyscallType::Connect),
                after.runtime_errors_for(mini_edr_common::SyscallType::Connect)
            )
            .into());
        }

        for syscall_type in [
            RawSyscallType::Execve,
            RawSyscallType::Openat,
            RawSyscallType::Clone,
        ] {
            if !observed.contains(&(syscall_type as u32)) {
                return Err(format!(
                    "expected {syscall_type:?} events to continue while connect faults were injected; observed={observed:?}",
                )
                .into());
            }
        }

        if after.runtime_errors_for(mini_edr_common::SyscallType::Execve) != 0
            || after.runtime_errors_for(mini_edr_common::SyscallType::Openat) != 0
            || after.runtime_errors_for(mini_edr_common::SyscallType::Clone) != 0
        {
            return Err(format!(
                "runtime-fault injection leaked into non-connect probes: {:?}",
                after.probe_runtime_errors_total
            )
            .into());
        }

        Ok(())
    }

    fn attach_all_programs(
        bpf: &mut Ebpf,
    ) -> Result<Vec<aya::programs::trace_point::TracePointLinkId>, Box<dyn std::error::Error>> {
        let mut links = Vec::with_capacity(BPF_PROGRAMS.len());
        for spec in BPF_PROGRAMS {
            let program: &mut TracePoint = bpf
                .program_mut(spec.program_name)
                .ok_or_else(|| format!("missing program {}", spec.program_name))?
                .try_into()?;
            program.load()?;
            let link = program.attach(spec.category, spec.tracepoint)?;
            links.push(link);
        }
        Ok(links)
    }

    fn set_probe_fault_mode(
        bpf: &mut Ebpf,
        raw_syscall_type: RawSyscallType,
        fault_mode: ProbeFaultMode,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut map = Array::<_, u32>::try_from(
            bpf.map_mut(PROBE_FAULT_MODES_MAP)
                .ok_or("missing PROBE_FAULT_MODES control map")?,
        )?;
        let index = match raw_syscall_type {
            RawSyscallType::Execve => syscall_array_index(mini_edr_common::SyscallType::Execve),
            RawSyscallType::Openat => syscall_array_index(mini_edr_common::SyscallType::Openat),
            RawSyscallType::Connect => syscall_array_index(mini_edr_common::SyscallType::Connect),
            RawSyscallType::Clone => syscall_array_index(mini_edr_common::SyscallType::Clone),
        };
        map.set(index, fault_mode.as_raw(), 0)?;
        Ok(())
    }

    fn read_kernel_counters(
        bpf: &mut Ebpf,
    ) -> Result<KernelCounterSnapshot, Box<dyn std::error::Error>> {
        let drop_counts = {
            let map = bpf
                .map_mut(RINGBUF_DROP_COUNTER_MAP)
                .ok_or("missing RINGBUF_DROP_COUNTS map")?;
            let drop_counts = PerCpuArray::<_, u64>::try_from(map)?;
            drop_counts.get(&RINGBUF_DROP_COUNTER_INDEX, 0)?
        };
        let execve_errors = {
            let map = bpf
                .map_mut(PROBE_RUNTIME_ERRORS_MAP)
                .ok_or("missing PROBE_RUNTIME_ERRORS map")?;
            let runtime_errors = PerCpuArray::<_, u64>::try_from(map)?;
            runtime_errors.get(&0, 0)?
        };
        let openat_errors = {
            let map = bpf
                .map_mut(PROBE_RUNTIME_ERRORS_MAP)
                .ok_or("missing PROBE_RUNTIME_ERRORS map")?;
            let runtime_errors = PerCpuArray::<_, u64>::try_from(map)?;
            runtime_errors.get(&1, 0)?
        };
        let connect_errors = {
            let map = bpf
                .map_mut(PROBE_RUNTIME_ERRORS_MAP)
                .ok_or("missing PROBE_RUNTIME_ERRORS map")?;
            let runtime_errors = PerCpuArray::<_, u64>::try_from(map)?;
            runtime_errors.get(&2, 0)?
        };
        let clone_errors = {
            let map = bpf
                .map_mut(PROBE_RUNTIME_ERRORS_MAP)
                .ok_or("missing PROBE_RUNTIME_ERRORS map")?;
            let runtime_errors = PerCpuArray::<_, u64>::try_from(map)?;
            runtime_errors.get(&3, 0)?
        };

        Ok(KernelCounterSnapshot::from_per_cpu_values(
            &drop_counts,
            &[
                (mini_edr_common::SyscallType::Execve, &execve_errors),
                (mini_edr_common::SyscallType::Openat, &openat_errors),
                (mini_edr_common::SyscallType::Connect, &connect_errors),
                (mini_edr_common::SyscallType::Clone, &clone_errors),
            ],
        ))
    }

    fn parse_raw_event(bytes: &[u8]) -> RawSyscallEvent {
        let mut event = RawSyscallEvent::default();
        // SAFETY: The destination is a valid, properly aligned `RawSyscallEvent`
        // and the caller checked that the source slice has exactly that size.
        // `copy_nonoverlapping` is used rather than a reference cast so we do
        // not require the ring-buffer item bytes to be aligned.
        unsafe {
            ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                (&raw mut event).cast::<u8>(),
                mem::size_of::<RawSyscallEvent>(),
            );
        }
        event
    }

    fn trigger_execve() -> io::Result<()> {
        let status = std::process::Command::new("/bin/true").status()?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other("/bin/true exited unsuccessfully"))
        }
    }

    fn trigger_openat() -> io::Result<()> {
        const OPENAT_TRIGGER_PATH: &str = "/tmp/mini-edr-openat-trigger.txt";
        let path = CString::new(OPENAT_TRIGGER_PATH).expect("static path has no NUL");
        fs::write(OPENAT_TRIGGER_PATH, b"mini-edr")?;
        // SAFETY: `path` is a live NUL-terminated C string, and this direct
        // libc call is used only to force an `openat` syscall for the harness.
        let fd = unsafe { libc::openat(libc::AT_FDCWD, path.as_ptr(), O_RDONLY) };
        if fd >= 0 {
            // SAFETY: `fd` was returned by `openat` and has not yet been closed.
            unsafe {
                libc::close(fd);
            }
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn trigger_openat_burst(iterations: usize) -> io::Result<()> {
        const OPENAT_BURST_PATH: &str = "/tmp/mini-edr-burst-openat-trigger.txt";
        let path = CString::new(OPENAT_BURST_PATH).expect("static path has no NUL");
        fs::write(OPENAT_BURST_PATH, b"mini-edr-overflow")?;
        for _ in 0..iterations {
            // SAFETY: The path is a valid NUL-terminated string and the file is
            // created before the loop. Each successful descriptor is closed in
            // the same iteration so the burst stresses tracepoint delivery, not
            // the process fd table.
            let fd = unsafe { libc::openat(libc::AT_FDCWD, path.as_ptr(), O_RDONLY) };
            if fd >= 0 {
                // SAFETY: `fd` came from `openat` in this loop iteration.
                unsafe {
                    libc::close(fd);
                }
            } else {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    fn trigger_connect() {
        // Connecting to an unroutable local port is sufficient: the tracepoint
        // fires on syscall entry before the kernel reports `ECONNREFUSED`.
        // We use `SOCK_NONBLOCK` so the harness cannot stall on TCP retry
        // behavior if the host's port-9 handling differs from the common
        // immediate-refusal path.
        // SAFETY: libc socket/connect receive initialized arguments, and every
        // successful socket descriptor is closed in this function.
        unsafe {
            let fd: RawFd = libc::socket(AF_INET, SOCK_STREAM | libc::SOCK_NONBLOCK, 0);
            if fd < 0 {
                return;
            }
            let addr = sockaddr_in {
                sin_family: 2_u16,
                sin_port: u16::to_be(9),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes([127, 0, 0, 1]).to_be(),
                },
                sin_zero: [0; 8],
            };
            let _ = libc::connect(
                fd,
                (&raw const addr).cast::<sockaddr>(),
                libc::socklen_t::try_from(mem::size_of::<sockaddr_in>()).unwrap_or(16),
            );
            libc::close(fd);
        }
    }

    fn trigger_clone() -> io::Result<()> {
        // `std::process::Command` may use `clone3` or `posix_spawn` depending on
        // libc/kernel details. The sensor probe for VAL-SENSOR-019 specifically
        // targets `sys_exit_clone`, so the harness issues clone(2) directly to
        // guarantee the traced syscall executes.
        // SAFETY: Passing SIGCHLD with a null child stack requests fork-like
        // clone semantics. The child exits immediately via `_exit`, avoiding
        // Rust destructor execution in the cloned child, and the parent reaps
        // the returned PID with `waitpid`.
        let ret = unsafe { libc::syscall(libc::SYS_clone, libc::SIGCHLD, 0) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        if ret == 0 {
            // SAFETY: This is the cloned child. `_exit` is async-signal-safe and
            // avoids running inherited Rust test harness state twice.
            unsafe {
                libc::_exit(0);
            }
        }
        let child_pid = libc::pid_t::try_from(ret).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("clone returned PID outside pid_t range: {error}"),
            )
        })?;
        // SAFETY: `child_pid` was returned by clone in this process; waiting for
        // it prevents a zombie test child.
        unsafe {
            if libc::waitpid(child_pid, ptr::null_mut(), 0) < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    fn read_proc_stat_pid(pid: u32) -> io::Result<u32> {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
        let pid_field = stat.split_whitespace().next().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "proc stat file was unexpectedly empty",
            )
        })?;
        pid_field.parse::<u32>().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("proc stat pid field was not numeric: {error}"),
            )
        })
    }

    struct ChildGuard {
        pid: Option<u32>,
    }

    impl ChildGuard {
        fn spawn_sleeping_child() -> io::Result<Self> {
            // `std::process::Command` may use `posix_spawn`, `vfork`, or
            // `clone3` depending on libc/kernel details. VAL-SENSOR-006 is
            // explicitly about the `clone(2)` return value, so the harness
            // issues that syscall directly with SIGCHLD semantics and keeps the
            // child alive long enough to read `/proc/<child>/stat`.
            // SAFETY: `SYS_clone` is invoked with only the low-byte SIGCHLD
            // termination signal and a null child stack, which is the classic
            // fork-like form where parent and child continue on separate
            // stacks. The child executes only libc `sleep` and `_exit`, and the
            // parent records/reaps the returned PID through `ChildGuard`.
            let ret = unsafe { libc::syscall(libc::SYS_clone, libc::SIGCHLD, 0) };
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
            if ret == 0 {
                // SAFETY: This branch runs in the freshly cloned child. `_exit`
                // avoids running Rust destructors or test-harness cleanup in
                // the child process, which could corrupt the parent's state.
                unsafe {
                    libc::sleep(2);
                    libc::_exit(0);
                }
            }
            Ok(Self {
                pid: Some(u32::try_from(ret).map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("clone returned a pid outside u32: {error}"),
                    )
                })?),
            })
        }

        const fn pid(&self) -> u32 {
            self.pid
                .expect("child guard retains child until finish/drop")
        }

        fn finish(&mut self) -> io::Result<()> {
            if let Some(pid) = self.pid.take() {
                let pid_t = libc::pid_t::try_from(pid).map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("child pid did not fit pid_t: {error}"),
                    )
                })?;
                // SAFETY: `pid` was returned by `clone` in this process. Sending
                // SIGKILL is best-effort cleanup; `waitpid` below is what reaps
                // the child and prevents zombies.
                unsafe {
                    let _ = libc::kill(pid_t, libc::SIGKILL);
                    if libc::waitpid(pid_t, ptr::null_mut(), 0) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
            }
            Ok(())
        }
    }

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.finish();
        }
    }
}
