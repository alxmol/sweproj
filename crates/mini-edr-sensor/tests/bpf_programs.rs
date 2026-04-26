//! Tests for the sensor milestone's kernel-side eBPF program contract.
//!
//! These tests are deliberately split between non-privileged object inspection
//! and an ignored privileged harness. The first group gives developers a fast
//! RED/GREEN loop for the generated ELF, while the ignored harness documents
//! the exact sudo-backed event-delivery scenario required by FR-S01..FR-S03.

use mini_edr_sensor::bpf::{BPF_PROGRAMS, EVENT_RINGBUF_MAP, build_ebpf_object, ebpf_object_path};
use mini_edr_sensor::raw_event::{MAX_FILENAME_LEN, RawSyscallEvent, RawSyscallType};
use object::{Object, ObjectSection, ObjectSymbol};

#[test]
fn ebpf_parent_tgid_reader_uses_generated_bindings_not_kernel_specific_offsets() {
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/ebpf/src/main.rs"))
        .expect("eBPF source should be readable for regression assertions");

    assert!(
        !source.contains("REAL_PARENT_OFFSET"),
        "CO-RE parent lookup must not hard-code task_struct offsets"
    );
    assert!(
        !source.contains("TGID_OFFSET"),
        "CO-RE parent lookup must not hard-code the tgid field offset"
    );
    assert!(
        source.contains("mod vmlinux;"),
        "the eBPF program should import generated kernel bindings for CO-RE field access"
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
fn ebpf_object_builds_and_contains_four_tracepoint_sections_plus_ringbuf() {
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
#[ignore = "requires CAP_BPF/CAP_PERFMON or sudo to load tracepoints and observe live connect IPv4 bytes"]
fn privileged_harness_observes_connect_ipv4_octets_without_endian_swap() {
    mini_edr_sensor::bpf::privileged_harness::load_attach_and_trigger_connect_ipv4_round_trip()
        .expect("connect event should preserve 127.0.0.1 as raw octets in userspace");
}

#[test]
#[ignore = "requires CAP_BPF/CAP_PERFMON or sudo to load tracepoints and drive a 500k overflow burst"]
fn privileged_harness_counts_ringbuf_overflow_without_crashing_kernel() {
    mini_edr_sensor::bpf::privileged_harness::load_attach_and_force_overflow_burst()
        .expect("overflow burst should increment drop counters without crashing");
}

#[test]
#[ignore = "requires CAP_BPF/CAP_PERFMON or sudo to inject connect-only runtime helper faults"]
fn privileged_harness_isolates_connect_runtime_faults() {
    mini_edr_sensor::bpf::privileged_harness::load_attach_and_inject_connect_runtime_faults()
        .expect("connect runtime faults should stay isolated to the connect probe");
}
