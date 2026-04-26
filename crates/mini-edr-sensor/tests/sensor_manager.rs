//! Integration tests for dynamic probe lifecycle management.
//!
//! The non-privileged tests lock the public API and metadata required by
//! FR-S05/TC-05, while ignored tests document the sudo-backed evidence that
//! detaching one live tracepoint does not silence the remaining probes.

use mini_edr_common::SyscallType;
use mini_edr_sensor::manager::{ProbeLifecycleState, SensorManager, SensorManagerError};

#[test]
fn sensor_manager_default_probe_order_covers_all_four_syscalls() {
    assert_eq!(
        SensorManager::default_probe_types(),
        &[
            SyscallType::Execve,
            SyscallType::Openat,
            SyscallType::Connect,
            SyscallType::Clone,
        ],
        "FR-S01/FR-S05 lifecycle APIs should manage exactly the four required probes"
    );
}

#[test]
fn sensor_manager_probe_metadata_matches_compiled_bpf_specs() {
    let connect =
        SensorManager::probe_metadata(SyscallType::Connect).expect("connect metadata is present");
    assert_eq!(connect.program_name, "sys_enter_connect");
    assert_eq!(connect.category, "syscalls");
    assert_eq!(connect.tracepoint, "sys_enter_connect");

    let clone =
        SensorManager::probe_metadata(SyscallType::Clone).expect("clone metadata is present");
    assert_eq!(clone.program_name, "sys_exit_clone");
    assert_eq!(clone.category, "syscalls");
    assert_eq!(clone.tracepoint, "sys_exit_clone");
}

#[test]
fn sensor_manager_constructs_detached_handles_before_kernel_attach() {
    let manager = SensorManager::from_unloaded_specs();
    let handles = manager.probe_handles();

    assert_eq!(handles.len(), 4);
    for handle in handles {
        assert_eq!(handle.lifecycle_state(), ProbeLifecycleState::Detached);
        assert!(SensorManager::default_probe_types().contains(&handle.syscall_type()));
    }
}

#[test]
fn sensor_manager_attach_without_loaded_object_faults_only_requested_probe() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime builds")
        .block_on(async {
            let manager = SensorManager::from_unloaded_specs();

            let Err(error) = manager.attach_probe(SyscallType::Connect).await else {
                panic!("metadata-only manager cannot attach a live probe");
            };

            assert!(
                matches!(error, SensorManagerError::ObjectNotLoaded),
                "attach should report that no Aya Ebpf object is available, got {error:?}"
            );

            for handle in manager.probe_handles() {
                let expected = if handle.syscall_type() == SyscallType::Connect {
                    ProbeLifecycleState::Faulted
                } else {
                    ProbeLifecycleState::Detached
                };
                assert_eq!(
                    handle.lifecycle_state(),
                    expected,
                    "failed per-probe attach must not disturb {:?}",
                    handle.syscall_type()
                );
            }
        });
}

#[test]
fn sensor_manager_bulk_detach_on_unloaded_specs_reports_all_already_detached() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime builds")
        .block_on(async {
            let manager = SensorManager::from_unloaded_specs();
            let report = manager
                .detach_probes()
                .await
                .expect("detaching metadata-only detached handles is idempotent");

            assert_eq!(report.attempted, 4);
            assert_eq!(report.detached, 0);
            assert_eq!(report.already_detached, 4);
            assert!(report.failures.is_empty());
            assert!(
                manager
                    .probe_handles()
                    .iter()
                    .all(|handle| handle.lifecycle_state() == ProbeLifecycleState::Detached),
                "bulk detach should not manufacture attached or faulted states"
            );
        });
}

#[cfg(feature = "e2e")]
mod e2e {
    use super::*;
    use mini_edr_sensor::raw_event::RawSyscallType;
    use std::{
        collections::HashSet,
        io,
        process::Command,
        ptr,
        time::{Duration, Instant},
    };

    #[test]
    #[ignore = "requires CAP_BPF/CAP_PERFMON or sudo to load tracepoints and observe live syscalls"]
    fn privileged_manager_detaches_connect_without_collateral_damage_then_reattaches() {
        let manager = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime builds")
            .block_on(async {
                let manager =
                    SensorManager::load_default_object().expect("BTF-enabled eBPF object loads");
                manager.attach_probes().await.expect("all probes attach");

                let connect = manager
                    .probe_handle(SyscallType::Connect)
                    .expect("connect handle exists");
                connect.detach().await.expect("connect detach succeeds");

                trigger_non_connect_syscalls();
                assert_observed(
                    &manager,
                    &[
                        RawSyscallType::Execve,
                        RawSyscallType::Openat,
                        RawSyscallType::Clone,
                    ],
                );
                assert_eq!(connect.lifecycle_state(), ProbeLifecycleState::Detached);

                let reattach_started = Instant::now();
                connect.attach().await.expect("connect reattach succeeds");
                assert!(
                    reattach_started.elapsed() <= Duration::from_millis(200),
                    "FR-S05 requires probe reattach to complete inside the 200 ms event-flow budget"
                );
                trigger_connect_syscall();
                assert_observed_within(
                    &manager,
                    &[RawSyscallType::Connect],
                    Duration::from_millis(200),
                );

                manager
                    .detach_probes()
                    .await
                    .expect("cleanup detaches all probes");
                manager
            });

        assert!(
            manager
                .probe_handles()
                .iter()
                .all(|handle| handle.lifecycle_state() == ProbeLifecycleState::Detached),
            "test cleanup should leave no manager-owned links attached"
        );
    }

    fn trigger_non_connect_syscalls() {
        let status = Command::new("/bin/true")
            .status()
            .expect("execve trigger runs");
        assert!(status.success());
        std::fs::write("/tmp/mini-edr-manager-openat-trigger.txt", b"mini-edr")
            .expect("openat trigger file is created");
        let _ = std::fs::read("/tmp/mini-edr-manager-openat-trigger.txt")
            .expect("openat trigger file is read");
        let _ = std::fs::remove_file("/tmp/mini-edr-manager-openat-trigger.txt");
        trigger_clone_syscall().expect("clone trigger runs");
    }

    fn trigger_connect_syscall() {
        // Connecting to a closed localhost port still enters `connect(2)`, so
        // the tracepoint fires before the kernel reports ECONNREFUSED.
        let _ = std::net::TcpStream::connect("127.0.0.1:9");
    }

    fn trigger_clone_syscall() -> io::Result<()> {
        // `std::process::Command` may use `clone3`/`posix_spawn` on modern
        // libc/kernel combinations. The sensor's clone probe intentionally
        // targets `sys_exit_clone`, so this harness issues clone(2) directly.
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
        // SAFETY: `ret` is a positive child PID returned by clone in this
        // process; waiting for it prevents a zombie test child.
        unsafe {
            if libc::waitpid(child_pid, ptr::null_mut(), 0) < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    fn assert_observed(manager: &SensorManager, expected: &[RawSyscallType]) {
        assert_observed_within(manager, expected, Duration::from_secs(3));
    }

    fn assert_observed_within(
        manager: &SensorManager,
        expected: &[RawSyscallType],
        timeout: Duration,
    ) {
        let deadline = Instant::now() + timeout;
        let mut observed = HashSet::new();
        while Instant::now() < deadline && observed.len() < expected.len() {
            for raw in manager.drain_raw_events().expect("ring buffer drains") {
                observed.insert(raw.syscall_type);
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        for expected_type in expected {
            assert!(
                observed.contains(&(*expected_type as u32)),
                "expected to observe {expected_type:?} within {timeout:?}; saw raw discriminators {observed:?}"
            );
        }
    }
}
