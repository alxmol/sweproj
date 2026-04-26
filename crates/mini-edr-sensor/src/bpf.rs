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
/// Name of the kernel-resident PID→PPID index maintained by support tracepoints.
pub const PPID_BY_PID_MAP: &str = "PPID_BY_PID";

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

/// Metadata for one support tracepoint that does not emit a `RawSyscallEvent`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuxiliaryBpfProgramSpec {
    /// Aya program symbol compiled into the eBPF object.
    pub program_name: &'static str,
    /// ELF section name produced by the Aya `#[tracepoint]` macro.
    pub section_name: &'static str,
    /// Kernel tracepoint category passed to `TracePoint::attach`.
    pub category: &'static str,
    /// Kernel tracepoint name passed to `TracePoint::attach`.
    pub tracepoint: &'static str,
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

/// Support tracepoints that maintain the CO-RE-free PID→PPID index.
///
/// These programs do not emit user-facing events. They update the `PPID_BY_PID`
/// map using stable tracepoint-format offsets so the four syscall probes can
/// look up `ppid` without walking `task_struct`.
pub const AUXILIARY_BPF_PROGRAMS: &[AuxiliaryBpfProgramSpec] = &[
    AuxiliaryBpfProgramSpec {
        program_name: "sched_process_fork",
        section_name: "tracepoint",
        category: "sched",
        tracepoint: "sched_process_fork",
    },
    AuxiliaryBpfProgramSpec {
        program_name: "sched_process_exit",
        section_name: "tracepoint",
        category: "sched",
        tracepoint: "sched_process_exit",
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
    const CONNECT_TRIGGER_PORT: u16 = 51_234;

    use super::{
        AUXILIARY_BPF_PROGRAMS, BPF_PROGRAMS, EVENT_RINGBUF_MAP, Ebpf, HashSet, Instant,
        RawSyscallEvent, RawSyscallType, RingBuf, TracePoint, build_ebpf_object, fs, thread,
    };
    use crate::kernel_metrics::{
        KernelCounterMaps, PROBE_FAULT_MODES_MAP, ProbeFaultMode, syscall_array_index,
    };
    use aya::maps::Array;
    use libc::{AF_INET, O_RDONLY, SOCK_STREAM, sockaddr, sockaddr_in};
    use mini_edr_common::Config;
    use std::{convert::TryFrom, ffi::CString, io, mem, os::fd::RawFd, ptr, time::Duration};
    use tokio::runtime::Builder;

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
        let mut links = Vec::with_capacity(BPF_PROGRAMS.len() + AUXILIARY_BPF_PROGRAMS.len());
        for spec in AUXILIARY_BPF_PROGRAMS {
            let program: &mut TracePoint = bpf
                .program_mut(spec.program_name)
                .ok_or_else(|| format!("missing program {}", spec.program_name))?
                .try_into()?;
            program.load()?;
            let link = program.attach(spec.category, spec.tracepoint)?;
            links.push(link);
        }
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

    /// Attach the support probes plus `openat`, exec a sentinel child, and
    /// verify the first child-side `Openat` event reports the real parent PID.
    ///
    /// # Errors
    ///
    /// Returns an error if the eBPF object cannot be loaded and attached, the
    /// child cannot be forked/executed, `/proc/<pid>/status` cannot be read
    /// before the child exits, or no matching `Openat` event arrives
    /// before the timeout.
    #[allow(clippy::too_many_lines)]
    pub fn load_attach_and_trigger_openat_ppid_round_trip_after_exec()
    -> Result<(), Box<dyn std::error::Error>> {
        let object = build_ebpf_object()?;
        let mut bpf = Ebpf::load_file(&object)?;
        let openat_spec = BPF_PROGRAMS
            .iter()
            .find(|spec| spec.raw_type == RawSyscallType::Openat)
            .ok_or("missing openat probe specification")?;

        let mut links = Vec::with_capacity(1 + AUXILIARY_BPF_PROGRAMS.len());
        for spec in AUXILIARY_BPF_PROGRAMS {
            let program: &mut TracePoint = bpf
                .program_mut(spec.program_name)
                .ok_or_else(|| format!("missing program {}", spec.program_name))?
                .try_into()?;
            program.load()?;
            let link = program.attach(spec.category, spec.tracepoint)?;
            links.push(link);
        }
        let program: &mut TracePoint = bpf
            .program_mut(openat_spec.program_name)
            .ok_or_else(|| format!("missing program {}", openat_spec.program_name))?
            .try_into()?;
        program.load()?;
        let link = program.attach(openat_spec.category, openat_spec.tracepoint)?;
        links.push(link);

        crate::manager::bootstrap_loaded_bpf_ppid_map(&mut bpf)?;
        let mut ring = RingBuf::try_from(
            bpf.map_mut(EVENT_RINGBUF_MAP)
                .ok_or("missing EVENTS ring buffer map")?,
        )?;

        let scenario_result = (|| -> Result<(), Box<dyn std::error::Error>> {
            // `load_default_object()` shells out to `cargo +nightly build` for
            // the kernel-side crate, and those helper processes can generate a
            // backlog of unrelated exec/open events before this assertion's
            // child is spawned. We therefore drain for a short, bounded window
            // rather than waiting for a perfectly idle host.
            for _ in 0..32 {
                let mut drained_any = false;
                for _ in 0..MAX_RING_DRAIN_BATCH {
                    if ring.next().is_none() {
                        break;
                    }
                    drained_any = true;
                }
                if !drained_any {
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }

            // We use a short-lived exec child here because the new
            // CO-RE-free PPID index is updated by `sched_process_fork`, while
            // the validation target is a deterministic post-exec `openat`
            // emitted from the child. Using Python to read
            // `/proc/self/status` guarantees one `openat` in the child process,
            // and the short sleep keeps the child alive long enough to inspect
            // `/proc/<pid>/status` before cleanup.
            let sentinel_path = format!("/tmp/mini-edr-child-openat-{}.txt", std::process::id());
            let mut child = ChildGuard::spawn_openat_after_exec_child(&sentinel_path)?;
            let child_pid = child.pid();
            let expected_child_ppid = read_proc_status_ppid(child_pid)?;
            let mut observed_openat_ppids = Vec::new();
            let mut observed_events = Vec::new();
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                for _ in 0..MAX_RING_DRAIN_BATCH {
                    let Some(item) = ring.next() else {
                        break;
                    };
                    if item.len() != mem::size_of::<RawSyscallEvent>() {
                        continue;
                    }
                    let raw = parse_raw_event(&item);
                    if observed_events.len() < 64 {
                        observed_events.push((
                            raw.syscall_type,
                            raw.pid,
                            raw.ppid,
                            raw.child_pid,
                            raw.filename_len,
                        ));
                    }
                    if raw.syscall_type == RawSyscallType::Openat as u32
                        && raw_openat_filename(&raw).as_deref() == Some(sentinel_path.as_str())
                    {
                        match read_proc_status_ppid(raw.pid) {
                            Ok(emitter_ppid) => {
                                observed_openat_ppids.push((raw.pid, raw.ppid, emitter_ppid));
                                if raw.ppid == emitter_ppid {
                                    child.finish()?;
                                    let _ = fs::remove_file(&sentinel_path);
                                    return Ok(());
                                }
                            }
                            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                                observed_openat_ppids.push((raw.pid, raw.ppid, 0));
                                if raw.ppid > 0 {
                                    child.finish()?;
                                    let _ = fs::remove_file(&sentinel_path);
                                    return Ok(());
                                }
                            }
                            Err(error) => return Err(Box::new(error)),
                        }
                    }
                }
                thread::sleep(Duration::from_millis(10));
            }

            let _ = child.finish();
            let _ = fs::remove_file(&sentinel_path);
            Err(format!(
                "did not observe openat event for sentinel path {sentinel_path} with a PPID matching /proc for child_pid={child_pid} (expected child PPid {expected_child_ppid}); observed openat tuples=(event_pid,event_ppid,proc_ppid) {observed_openat_ppids:?}; observed events={observed_events:?}"
            )
            .into())
        })();
        drop(ring);
        drop(links);
        scenario_result
    }

    /// Load the connect probe and verify loopback IPv4 octets survive the
    /// kernel-to-userspace round trip without an endian swap regression.
    ///
    /// # Errors
    ///
    /// Returns an error if the connect tracepoint cannot attach or if no
    /// matching `127.0.0.1:51234` raw event arrives before the timeout.
    pub fn load_attach_and_trigger_connect_ipv4_round_trip()
    -> Result<(), Box<dyn std::error::Error>> {
        let object = build_ebpf_object()?;
        let mut bpf = Ebpf::load_file(&object)?;
        let connect_spec = BPF_PROGRAMS
            .iter()
            .find(|spec| spec.raw_type == RawSyscallType::Connect)
            .ok_or("missing connect probe specification")?;

        // This focused harness attaches only the connect tracepoint so the
        // assertion can inspect the first observed connect payload without
        // unrelated background exec/open/clone traffic obscuring the result.
        let program: &mut TracePoint = bpf
            .program_mut(connect_spec.program_name)
            .ok_or_else(|| format!("missing program {}", connect_spec.program_name))?
            .try_into()?;
        program.load()?;
        let _link = program.attach(connect_spec.category, connect_spec.tracepoint)?;

        let mut ring = RingBuf::try_from(
            bpf.map_mut(EVENT_RINGBUF_MAP)
                .ok_or("missing EVENTS ring buffer map")?,
        )?;

        trigger_connect();

        let deadline = Instant::now() + Duration::from_secs(3);
        let mut observed_connects = Vec::new();
        while Instant::now() < deadline {
            while let Some(item) = ring.next() {
                if item.len() == mem::size_of::<RawSyscallEvent>() {
                    let raw = parse_raw_event(&item);
                    if raw.syscall_type == RawSyscallType::Connect as u32 {
                        observed_connects.push((raw.ipv4_addr, raw.port));
                        if raw.ipv4_addr == [127, 0, 0, 1] && raw.port == CONNECT_TRIGGER_PORT {
                            return Ok(());
                        }
                    }
                }
            }
            thread::sleep(Duration::from_millis(10));
        }

        Err(format!(
            "did not observe loopback connect bytes [127, 0, 0, 1]:{CONNECT_TRIGGER_PORT}; observed connect payloads={observed_connects:?}"
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
    pub fn load_attach_with_sensor_manager_and_force_overflow_burst()
    -> Result<(), Box<dyn std::error::Error>> {
        let runtime = Builder::new_current_thread().enable_all().build()?;
        let config = Config {
            ring_buffer_size_pages: 4,
            ..Config::default()
        };
        let manager = crate::manager::SensorManager::load_default_object_with_config(&config)?;
        runtime.block_on(async { manager.attach_probes().await })?;
        let scenario_result = (|| -> Result<(), Box<dyn std::error::Error>> {
            let before = runtime.block_on(async { manager.kernel_counters().await })?;
            trigger_openat_burst(500_000)?;

            let mut observed = 0_u64;
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                observed = observed.saturating_add(
                    u64::try_from(manager.drain_raw_events()?.len()).unwrap_or(u64::MAX),
                );
                if observed > 0 {
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }

            let after = runtime.block_on(async { manager.kernel_counters().await })?;
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
        })();
        let cleanup_result = runtime.block_on(async { manager.detach_probes().await });
        if let Err(error) = cleanup_result {
            return Err(Box::new(error));
        }
        scenario_result
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
        let before = KernelCounterMaps::snapshot_from_bpf(&mut bpf)?;
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

        let after = KernelCounterMaps::snapshot_from_bpf(&mut bpf)?;
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
        let mut links = Vec::with_capacity(BPF_PROGRAMS.len() + AUXILIARY_BPF_PROGRAMS.len());
        for spec in AUXILIARY_BPF_PROGRAMS {
            let program: &mut TracePoint = bpf
                .program_mut(spec.program_name)
                .ok_or_else(|| format!("missing program {}", spec.program_name))?
                .try_into()?;
            program.load()?;
            let link = program.attach(spec.category, spec.tracepoint)?;
            links.push(link);
        }
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

    fn raw_openat_filename(raw: &RawSyscallEvent) -> Option<String> {
        let length = usize::from(raw.filename_len).min(raw.filename.len());
        let bytes = &raw.filename[..length];
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        std::str::from_utf8(&bytes[..end]).ok().map(str::to_owned)
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
        // fires on syscall entry before the kernel reports `ECONNREFUSED`. We
        // choose the validation contract's `127.0.0.1:51234` pair so privileged
        // tests can assert both the IPv4 octets and the port value from a real
        // tracepoint delivery path. `SOCK_NONBLOCK` prevents the harness from
        // stalling on any host-specific TCP retry behavior.
        // SAFETY: libc socket/connect receive initialized arguments, and every
        // successful socket descriptor is closed in this function.
        unsafe {
            let fd: RawFd = libc::socket(AF_INET, SOCK_STREAM | libc::SOCK_NONBLOCK, 0);
            if fd < 0 {
                return;
            }
            let addr = sockaddr_in {
                sin_family: 2_u16,
                sin_port: u16::to_be(CONNECT_TRIGGER_PORT),
                sin_addr: libc::in_addr {
                    // The userspace `sockaddr_in` ABI wants the IPv4 bytes laid
                    // out in network order in memory. `from_ne_bytes` preserves
                    // the literal `[127, 0, 0, 1]` byte sequence on both
                    // little- and big-endian hosts, which is the same layout
                    // the connect probe must report back to userspace.
                    s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
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

    fn read_proc_status_ppid(pid: u32) -> io::Result<u32> {
        let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
        let ppid_field = status
            .lines()
            .find_map(|line| line.strip_prefix("PPid:"))
            .and_then(|value| value.split_whitespace().next())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "proc status file was missing a PPid field",
                )
            })?;
        ppid_field.parse::<u32>().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("proc status PPid field was not numeric: {error}"),
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

        fn spawn_openat_after_exec_child(sentinel_path: &str) -> io::Result<Self> {
            let executable = CString::new("/usr/bin/python3")
                .expect("static executable path has no interior NUL");
            let arg0 = CString::new("python3").expect("static argv[0] has no interior NUL");
            let arg1 = CString::new("-c").expect("static argv[1] has no interior NUL");
            let arg2 = CString::new(format!(
                "import pathlib,time; p=pathlib.Path({sentinel_path:?}); p.write_text('mini-edr'); time.sleep(2)"
            ))
            .expect("python sentinel command has no interior NUL");
            let argv_ptrs = [arg0.as_ptr(), arg1.as_ptr(), arg2.as_ptr(), ptr::null()];
            let envp = [ptr::null()];

            // A direct `fork` + `execve` sequence gives this privileged harness
            // a deterministic child PID to watch while exercising exactly the
            // fork/exec lifecycle that should populate and then consume the
            // `PPID_BY_PID` index. The Python one-liner immediately opens
            // `/proc/self/status`, which yields a child-owned `openat` event
            // for the probe under test.
            // SAFETY: `fork` creates a child with identical memory. The child
            // immediately jumps into `execve`/`_exit`, avoiding interaction
            // with shared Rust state, and the parent retains the returned PID
            // so `finish` can reap the child later.
            let ret = unsafe { libc::fork() };
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
            if ret == 0 {
                // SAFETY: `executable`, `argv`, and `envp` are all NUL-terminated
                // C-compatible arrays that live for the duration of the syscall.
                // `_exit(127)` is the standard fallback when `execve` fails.
                unsafe {
                    libc::execve(executable.as_ptr(), argv_ptrs.as_ptr(), envp.as_ptr());
                    libc::_exit(127);
                }
            }

            Ok(Self {
                pid: Some(u32::try_from(ret).map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("fork returned a pid outside u32: {error}"),
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
