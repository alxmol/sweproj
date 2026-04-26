//! Tests for the sensor milestone's kernel-side eBPF program contract.
//!
//! These tests are deliberately split between non-privileged object inspection
//! and an ignored privileged harness. The first group gives developers a fast
//! RED/GREEN loop for the generated ELF, while the ignored harness documents
//! the exact sudo-backed event-delivery scenario required by FR-S01..FR-S03.

use aya_obj::Object as AyaObject;
use mini_edr_sensor::bpf::{
    AUXILIARY_BPF_PROGRAMS, BPF_PROGRAMS, EVENT_RINGBUF_MAP, build_ebpf_object, ebpf_object_path,
};
use mini_edr_sensor::raw_event::{MAX_FILENAME_LEN, RawSyscallEvent, RawSyscallType};
use object::{Object, ObjectSection, ObjectSymbol};
use std::path::Path;

#[test]
fn ebpf_ppid_tracking_avoids_generated_task_struct_bindings_and_host_offsets() {
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/ebpf/src/main.rs"))
        .expect("eBPF source should be readable for regression assertions");
    let generated_bindings_path =
        Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/ebpf/src/vmlinux.rs"));

    assert!(
        !generated_bindings_path.exists(),
        "the generated vmlinux.rs bindings should be removed once task_struct walks are gone"
    );
    assert!(
        !source.contains("mod vmlinux;"),
        "the eBPF source should not import generated task_struct bindings anymore"
    );
    assert!(
        !source.contains("bpf_get_current_task_btf"),
        "the eBPF source should not ask the kernel for a BTF task_struct pointer anymore"
    );
    assert!(
        !source.contains("(*task).real_parent"),
        "the eBPF source should not dereference task_struct.real_parent anymore"
    );
    assert!(
        !source.contains("(*parent).tgid"),
        "the eBPF source should not dereference parent->tgid anymore"
    );
    assert!(
        source.contains("PPID_BY_TGID"),
        "the replacement process-TGID→parent-process-TGID index should remain visible in source"
    );
    assert!(
        source.contains("PPID_BY_TGID.get(&current_tgid)"),
        "syscall probes should look up PPID by the current process TGID, not by the current thread TID"
    );
    assert!(
        !source.contains("PPID_BY_TID.get(&tid)"),
        "the eBPF source should no longer look up PPIDs by the current thread TID"
    );
}

#[test]
fn ebpf_object_declares_ppid_by_tgid_hash_with_pid_max_capacity() {
    let object = build_ebpf_object().expect("eBPF object builds with nightly rust-src");
    let bytes = std::fs::read(&object).expect("compiled eBPF object is readable");
    let parsed = AyaObject::parse(&bytes).expect("aya-obj parses the compiled eBPF ELF");
    let ppid_map = parsed
        .maps
        .get("PPID_BY_TGID")
        .expect("compiled object should declare the PPID_BY_TGID support map");

    assert_eq!(
        ppid_map.map_type(),
        1,
        "PPID_BY_TGID should remain a plain hash map keyed by process TGID"
    );
    assert_eq!(
        ppid_map.max_entries(),
        65_536,
        "PPID_BY_TGID should scale to Linux's default pid_max"
    );
}

#[test]
fn raw_syscall_event_layout_is_stable_for_kernel_userspace_boundary() {
    assert_eq!(MAX_FILENAME_LEN, 256);
    assert_eq!(core::mem::align_of::<RawSyscallEvent>(), 8);
    assert_eq!(core::mem::size_of::<RawSyscallEvent>(), 296);
    assert_eq!(RawSyscallType::Execve as u32, 1);
    assert_eq!(RawSyscallType::Openat as u32, 2);
    assert_eq!(RawSyscallType::Connect as u32, 3);
    assert_eq!(RawSyscallType::Clone as u32, 4);
}

#[test]
fn ebpf_object_builds_and_contains_syscall_and_support_tracepoints_plus_ringbuf() {
    let object = build_ebpf_object().expect("eBPF object builds with nightly rust-src");
    assert_eq!(object, ebpf_object_path());
    assert!(object.exists(), "eBPF object path should exist after build");

    let bytes = std::fs::read(&object).expect("compiled eBPF object is readable");
    let file = object::File::parse(bytes.as_slice()).expect("compiled eBPF is an ELF object");
    let section_names = file
        .sections()
        .filter_map(|section| section.name().ok())
        .collect::<Vec<_>>();
    let symbol_names = file
        .symbols()
        .filter_map(|symbol| symbol.name().ok())
        .collect::<Vec<_>>();

    for program in BPF_PROGRAMS {
        assert!(
            section_names.contains(&program.section_name),
            "missing tracepoint section {}",
            program.section_name
        );
        assert!(
            symbol_names.contains(&program.program_name),
            "missing eBPF program symbol {} for {}",
            program.program_name,
            program.tracepoint
        );
    }
    for program in AUXILIARY_BPF_PROGRAMS {
        assert!(
            section_names.contains(&program.section_name),
            "missing support tracepoint section {}",
            program.section_name
        );
        assert!(
            symbol_names.contains(&program.program_name),
            "missing support eBPF program symbol {} for {}",
            program.program_name,
            program.tracepoint
        );
    }
    assert!(
        section_names.contains(&"maps"),
        "compiled object should contain Aya map definitions, including {EVENT_RINGBUF_MAP}"
    );
}

#[test]
fn ebpf_object_contains_btf_sections_for_core_metadata() {
    let object = build_ebpf_object().expect("eBPF object builds with BTF-enabled linker flags");
    let bytes = std::fs::read(&object).expect("compiled eBPF object is readable");
    let file = object::File::parse(bytes.as_slice()).expect("compiled eBPF is an ELF object");
    let section_names = file
        .sections()
        .filter_map(|section| section.name().ok())
        .collect::<Vec<_>>();

    assert!(
        section_names.contains(&".BTF"),
        "compiled eBPF object should include .BTF type metadata for CO-RE/BTF loading"
    );
    assert!(
        section_names.contains(&".BTF.ext"),
        "compiled eBPF object should include .BTF.ext relocation/function metadata for CO-RE"
    );
}

#[test]
fn clone_probe_uses_syscall_exit_tracepoint_for_child_pid_return_value() {
    let clone_program = BPF_PROGRAMS
        .iter()
        .find(|program| program.raw_type == RawSyscallType::Clone)
        .expect("clone probe metadata should be present");

    assert_eq!(clone_program.program_name, "sys_exit_clone");
    assert_eq!(clone_program.category, "syscalls");
    assert_eq!(clone_program.tracepoint, "sys_exit_clone");
}

#[test]
fn ebpf_object_contains_no_host_specific_task_struct_immediates() {
    let object = build_ebpf_object().expect("eBPF object builds with nightly rust-src");
    let bytes = std::fs::read(&object).expect("compiled eBPF object is readable");
    let parsed = AyaObject::parse(&bytes).expect("aya-obj parses the compiled eBPF ELF");
    let forbidden_immediates = [0x974, 0x980, 2420, 2432];

    // We inspect every instruction emitted into every parsed program so this
    // regression test catches the exact host-specific immediates the scrutiny
    // pass observed in the old task_struct walk.
    for (program_name, program) in &parsed.programs {
        let function = parsed
            .functions
            .get(&program.function_key())
            .expect("every parsed program should have a backing function");
        for (index, instruction) in function.instructions.iter().enumerate() {
            assert!(
                !forbidden_immediates.contains(&instruction.imm),
                "program {program_name} instruction #{index} still embeds forbidden immediate {}",
                instruction.imm
            );
        }
    }
}

#[test]
#[ignore = "requires CAP_BPF/CAP_PERFMON or sudo to load tracepoints and observe live syscalls"]
fn privileged_harness_loads_programs_and_observes_basic_event_delivery() {
    mini_edr_sensor::bpf::privileged_harness::load_attach_and_trigger_all()
        .expect("privileged eBPF harness should load programs and receive events");
}

#[test]
#[ignore = "requires CAP_BPF/CAP_PERFMON or sudo to load tracepoints and observe live clone events"]
fn privileged_harness_observes_clone_child_pid() {
    mini_edr_sensor::bpf::privileged_harness::load_attach_and_trigger_clone_child_pid()
        .expect("clone event should carry the actual live child PID");
}

#[test]
#[ignore = "requires CAP_BPF/CAP_PERFMON or sudo to load tracepoints and observe a post-exec openat PPID round trip"]
fn privileged_harness_observes_child_openat_ppid_from_sched_process_fork_index() {
    mini_edr_sensor::bpf::privileged_harness::load_attach_and_trigger_openat_ppid_round_trip_after_exec()
        .expect("post-exec openat event should carry the real parent PID from the sched_process_fork index");
}

#[test]
#[ignore = "requires CAP_BPF/CAP_PERFMON or sudo to load tracepoints and observe threaded openat PPID behavior"]
fn privileged_harness_preserves_process_leader_ppid_after_worker_thread_exit() {
    mini_edr_sensor::bpf::privileged_harness::load_attach_and_trigger_thread_exit_ppid_round_trip()
        .expect("worker-thread and process-leader openat events should share the same parent PID without a post-thread /proc reseed");
}

#[test]
#[ignore = "requires CAP_BPF/CAP_PERFMON or sudo to load tracepoints and observe live connect IPv4 bytes"]
fn privileged_harness_observes_connect_ipv4_octets_without_endian_swap() {
    mini_edr_sensor::bpf::privileged_harness::load_attach_and_trigger_connect_ipv4_round_trip()
        .expect("connect event should preserve 127.0.0.1 as raw octets in userspace");
}

#[test]
#[ignore = "requires CAP_BPF/CAP_PERFMON or sudo to load tracepoints and drive a 500k overflow burst"]
fn privileged_harness_counts_ringbuf_overflow_without_crashing_kernel() {
    mini_edr_sensor::bpf::privileged_harness::load_attach_with_sensor_manager_and_force_overflow_burst()
        .expect("overflow burst should increment drop counters through SensorManager::kernel_counters without crashing");
}

#[test]
#[ignore = "requires CAP_BPF/CAP_PERFMON or sudo to inject connect-only runtime helper faults"]
fn privileged_harness_isolates_connect_runtime_faults() {
    mini_edr_sensor::bpf::privileged_harness::load_attach_and_inject_connect_runtime_faults()
        .expect("connect runtime faults should stay isolated to the connect probe");
}
