//! Userspace helpers for building and smoke-loading the Aya eBPF probes.
//!
//! This module owns only the kernel-object boundary for feature `f2-bpf-programs`.
//! Higher-level lifecycle APIs (`SensorManager`, dynamic detach, drop counters)
//! are intentionally left to later sensor features so this code stays focused on
//! FR-S01..FR-S03 and VAL-SENSOR-001..008.

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
        program_name: "sys_enter_clone",
        section_name: "tracepoint",
        category: "syscalls",
        tracepoint: "sys_enter_clone",
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
    let manifest = root
        .join("crates")
        .join("mini-edr-sensor")
        .join("ebpf")
        .join("Cargo.toml");
    let target_dir = root.join("target").join("mini-edr-sensor-ebpf");

    // The eBPF crate is deliberately excluded from the workspace because it
    // needs nightly `build-std=core` and a BPF linker. Building it as a child
    // Cargo invocation keeps normal userspace validators on stable Rust while
    // still making the feature's release build produce a real BPF ELF.
    let status = Command::new("cargo")
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
        .arg(&target_dir)
        .status()
        .map_err(BuildError::Spawn)?;

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

/// Privileged harness for verifier loading and basic ring-buffer delivery.
pub mod privileged_harness {
    use super::{
        BPF_PROGRAMS, EVENT_RINGBUF_MAP, Ebpf, HashSet, Instant, RawSyscallEvent, RingBuf,
        TracePoint, build_ebpf_object, fs, thread,
    };
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

    fn trigger_connect() {
        // Connecting to an unroutable local port is sufficient: the tracepoint
        // fires on syscall entry before the kernel reports `ECONNREFUSED`.
        // SAFETY: libc socket/connect receive initialized arguments, and every
        // successful socket descriptor is closed in this function.
        unsafe {
            let fd: RawFd = libc::socket(AF_INET, SOCK_STREAM, 0);
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
        let status = std::process::Command::new("/bin/true").status()?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other(
                "clone trigger child exited unsuccessfully",
            ))
        }
    }
}
