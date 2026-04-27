//! Linux- and host-specific helpers for the Mini-EDR daemon.
//!
//! Mini-EDR's portability strategy follows NFR-PO01/NFR-PO04: the daemon only
//! supports Linux `x86_64`, it refuses to compile elsewhere with a clear cfg
//! gate, and the small amount of host-coupled runtime logic (kernel-version
//! detection, capability checks, `/proc` reads, localhost socket binding, and
//! Unix-socket lifecycle) stays isolated in this module so the rest of the
//! daemon remains portable Rust business logic.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!(
    "mini-edr-daemon requires Linux with eBPF support on x86_64; non-Linux or non-x86_64 builds are intentionally cfg-gated because the daemon depends on Linux tracepoints, /proc, CAP_BPF/CAP_PERFMON, and Unix sockets"
);

use crate::DaemonError;
use mini_edr_common::KernelVersion;
use std::{
    env, fs, io,
    os::unix::{fs::FileTypeExt, net::UnixStream as StdUnixStream},
    path::{Path, PathBuf},
};
use tokio::net::{TcpListener, UnixListener};

/// Operator-visible environment escape hatch for deterministic kernel-gate tests.
const KERNEL_RELEASE_OVERRIDE_ENV: &str = "MINI_EDR_KERNEL_RELEASE_OVERRIDE";

/// Read the current Linux kernel release string for the runtime compatibility gate.
///
/// The override exists so contract harnesses can prove the 5.4 rejection path
/// without needing to mutate the real host kernel during ordinary CI runs.
fn current_kernel_release() -> Result<String, DaemonError> {
    if let Some(release) = env::var_os(KERNEL_RELEASE_OVERRIDE_ENV) {
        return Ok(release.to_string_lossy().trim().to_owned());
    }

    fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|contents| contents.trim().to_owned())
        .map_err(|error| DaemonError::UnsupportedRuntime {
            details: format!(
                "failed to read /proc/sys/kernel/osrelease while checking the Linux >= 5.8 runtime gate: {error}"
            ),
        })
}

/// Normalize Linux release strings so distro suffixes and extra vendor numeric
/// segments (for example WSL's `6.6.87.2-microsoft-standard-WSL2`) can still
/// flow through the shared `KernelVersion` parser, which intentionally reasons
/// about the first three numeric components only.
fn normalize_kernel_release_for_parser(release: &str) -> String {
    let (numeric_prefix, suffix) = match release.split_once('-') {
        Some((numeric_prefix, suffix)) => (numeric_prefix, Some(suffix)),
        None => (release, None),
    };
    let numeric_parts = numeric_prefix.split('.').collect::<Vec<_>>();
    if numeric_parts.len() <= 3 {
        return release.to_owned();
    }

    let trimmed = numeric_parts[..3].join(".");
    match suffix {
        Some(suffix) => format!("{trimmed}-{suffix}"),
        None => trimmed,
    }
}

/// Refuse to start on kernels older than Linux 5.8.
pub fn ensure_supported_runtime_kernel() -> Result<(), DaemonError> {
    let release = current_kernel_release()?;
    let normalized_release = normalize_kernel_release_for_parser(&release);
    let version = KernelVersion::parse(&normalized_release).map_err(|error| {
        DaemonError::UnsupportedRuntime {
            details: format!("failed to parse Linux kernel release `{release}`: {error}"),
        }
    })?;

    if version.supports_mini_edr() {
        Ok(())
    } else {
        Err(DaemonError::UnsupportedRuntime {
            details: format!(
                "mini-edr-daemon requires Linux kernel >= 5.8 because BPF_MAP_TYPE_RINGBUF first shipped there; detected unsupported kernel `{release}`"
            ),
        })
    }
}

/// Refuse to start without the Linux capabilities required to load eBPF programs.
pub fn ensure_required_capabilities() -> Result<(), DaemonError> {
    // Root is allowed to bypass the fine-grained capability bit check because
    // Linux grants the daemon the effective power to load BPF programs even if
    // `/proc/self/status` reflects a containerized or ambient capability set.
    if unsafe { libc::geteuid() } == 0 {
        return Ok(());
    }

    let status = fs::read_to_string("/proc/self/status").map_err(|error| {
        DaemonError::MissingCapabilities {
            details: format!(
                "failed to read /proc/self/status while checking capabilities: {error}"
            ),
        }
    })?;
    let effective_caps = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:\t"))
        .ok_or_else(|| DaemonError::MissingCapabilities {
            details:
                "failed to read CapEff from /proc/self/status while checking CAP_BPF/CAP_PERFMON"
                    .to_owned(),
        })
        .and_then(|raw_caps| {
            u64::from_str_radix(raw_caps.trim(), 16).map_err(|error| {
                DaemonError::MissingCapabilities {
                    details: format!("failed to parse CapEff from /proc/self/status: {error}"),
                }
            })
        })?;
    let missing = crate::REQUIRED_CAPABILITY_BITS
        .iter()
        .filter_map(|(name, bit)| (((effective_caps >> bit) & 1) == 0).then_some(*name))
        .collect::<Vec<_>>();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(DaemonError::MissingCapabilities {
            details: format!(
                "{} are required to start mini-edr-daemon; run `sudo setcap cap_bpf,cap_perfmon,cap_sys_admin+ep <binary>` or start the daemon via sudo",
                missing.join(" and ")
            ),
        })
    }
}

/// Return the daemon's resident set size in bytes from procfs.
pub fn current_rss_bytes() -> u64 {
    let Ok(status) = fs::read_to_string("/proc/self/status") else {
        return 0;
    };
    status
        .lines()
        .find_map(|line| {
            let remainder = line.strip_prefix("VmRSS:")?;
            let kibibytes = remainder.split_whitespace().next()?.parse::<u64>().ok()?;
            Some(kibibytes.saturating_mul(1_024))
        })
        .unwrap_or(0)
}

/// Canonical allowed dashboard origins for localhost-only CSRF enforcement.
pub fn allowed_origins(port: u16) -> [String; 2] {
    [
        format!("http://127.0.0.1:{port}"),
        format!("http://localhost:{port}"),
    ]
}

/// Bind the daemon's TCP surface to loopback only.
pub async fn bind_localhost_listener(requested_port: u16) -> Result<TcpListener, DaemonError> {
    TcpListener::bind(("127.0.0.1", requested_port))
        .await
        .map_err(|error| DaemonError::Bind {
            port: requested_port,
            details: error.to_string(),
        })
}

/// Resolve the Unix-socket path used by the local API.
pub fn configured_api_socket_path() -> PathBuf {
    env::var_os("MINI_EDR_API_SOCKET")
        .map_or_else(|| PathBuf::from("/run/mini-edr/api.sock"), PathBuf::from)
}

/// Prepare and bind the daemon's Unix-socket listener safely.
pub fn bind_unix_listener(socket_path: &Path) -> Result<UnixListener, DaemonError> {
    let parent = socket_path
        .parent()
        .ok_or_else(|| DaemonError::UnixSocketPrepare {
            path: socket_path.to_path_buf(),
            details: "Unix socket path must have a parent directory".to_owned(),
        })?;
    fs::create_dir_all(parent).map_err(|error| DaemonError::UnixSocketPrepare {
        path: socket_path.to_path_buf(),
        details: error.to_string(),
    })?;

    // We always prefer a false-negative "socket_in_use" over unlinking a live
    // peer's path. A stale socket returns `ECONNREFUSED`, which is the safe
    // signal that no listener is still attached and the inode can be replaced.
    match fs::symlink_metadata(socket_path) {
        Ok(metadata) => {
            if !metadata.file_type().is_socket() {
                return Err(DaemonError::UnixSocketPrepare {
                    path: socket_path.to_path_buf(),
                    details: "existing path is not a Unix socket".to_owned(),
                });
            }
            match StdUnixStream::connect(socket_path) {
                Ok(_stream) => {
                    return Err(DaemonError::SocketInUse {
                        path: socket_path.to_path_buf(),
                    });
                }
                Err(error) => match error.raw_os_error() {
                    Some(libc::ECONNREFUSED | libc::ENOENT) => {
                        fs::remove_file(socket_path).map_err(|remove_error| {
                            DaemonError::UnixSocketPrepare {
                                path: socket_path.to_path_buf(),
                                details: remove_error.to_string(),
                            }
                        })?;
                        tracing::info!(
                            event = "stale_socket_removed",
                            path = %socket_path.display(),
                            "Removed stale Unix socket from prior unclean exit before binding"
                        );
                    }
                    _ => {
                        return Err(DaemonError::SocketInUse {
                            path: socket_path.to_path_buf(),
                        });
                    }
                },
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(DaemonError::UnixSocketPrepare {
                path: socket_path.to_path_buf(),
                details: error.to_string(),
            });
        }
    }

    UnixListener::bind(socket_path).map_err(|error| match error.raw_os_error() {
        Some(libc::EADDRINUSE) => DaemonError::SocketInUse {
            path: socket_path.to_path_buf(),
        },
        _ => DaemonError::UnixBind {
            path: socket_path.to_path_buf(),
            details: error.to_string(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::{
        KERNEL_RELEASE_OVERRIDE_ENV, allowed_origins, ensure_supported_runtime_kernel,
        normalize_kernel_release_for_parser,
    };
    use std::sync::Mutex;

    static KERNEL_OVERRIDE_LOCK: Mutex<()> = Mutex::new(());

    fn with_kernel_override<T>(release: &str, test: impl FnOnce() -> T) -> T {
        let _guard = KERNEL_OVERRIDE_LOCK.lock().expect("kernel override lock");
        // SAFETY: the mutex above serializes environment mutation across these
        // tests, so no other test in this process can concurrently read or write
        // the override variable while the closure runs.
        unsafe {
            std::env::set_var(KERNEL_RELEASE_OVERRIDE_ENV, release);
        }
        let result = test();
        // SAFETY: see the `set_var` comment above; the same mutex still guards
        // the process-wide environment mutation during cleanup.
        unsafe {
            std::env::remove_var(KERNEL_RELEASE_OVERRIDE_ENV);
        }
        result
    }

    #[test]
    fn runtime_kernel_gate_accepts_documented_supported_versions() {
        for release in [
            "5.8.0-generic",
            "6.5.0-1018-azure",
            "6.6.87.2-microsoft-standard-WSL2",
        ] {
            with_kernel_override(release, || {
                ensure_supported_runtime_kernel()
                    .unwrap_or_else(|error| panic!("{release} should be accepted: {error}"));
            });
        }
    }

    #[test]
    fn runtime_kernel_gate_rejects_pre_5_8_versions_with_clear_error() {
        with_kernel_override("5.4.0-170-generic", || {
            let error = ensure_supported_runtime_kernel().expect_err("5.4 rejected");
            assert!(
                error.to_string().contains("requires Linux kernel >= 5.8"),
                "unexpected error: {error}"
            );
            assert!(
                error.to_string().contains("5.4.0-170-generic"),
                "unexpected error: {error}"
            );
        });
    }

    #[test]
    fn localhost_only_allowed_origins_match_the_dashboard_contract() {
        assert_eq!(
            allowed_origins(8080),
            [
                "http://127.0.0.1:8080".to_owned(),
                "http://localhost:8080".to_owned(),
            ]
        );
    }

    #[test]
    fn runtime_kernel_parser_normalization_trims_vendor_numeric_segments() {
        assert_eq!(
            normalize_kernel_release_for_parser("6.6.87.2-microsoft-standard-WSL2"),
            "6.6.87-microsoft-standard-WSL2"
        );
    }
}
