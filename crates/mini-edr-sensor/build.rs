//! Release-build hook for compiling the nested kernel-side Rust eBPF package.
//!
//! Normal stable test, clippy, and documentation builds intentionally skip this
//! hook so developers without BPF privileges still get a fast userspace loop.
//! The feature contract's `cargo +nightly build -p mini-edr-sensor --release`
//! path enters here and builds the pure-Rust Aya eBPF ELF with `rust-src` and
//! `bpf-linker`.

use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=ebpf/Cargo.toml");
    println!("cargo:rerun-if-changed=ebpf/.cargo/config.toml");
    println!("cargo:rerun-if-changed=ebpf/src/main.rs");

    // Release builds are the only routine build mode that should produce a
    // loadable eBPF object. Keeping debug/test builds userspace-only preserves
    // the foundation milestone validators and avoids forcing nightly onto every
    // unit-test edit.
    if env::var("PROFILE").as_deref() != Ok("release") {
        return;
    }

    if env::var_os("MINI_EDR_SKIP_EBPF_BUILD").is_some() {
        return;
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("manifest dir set"));
    let repo_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("sensor crate lives under crates/<name>");
    let ebpf_dir = manifest_dir.join("ebpf");
    let target_dir = repo_root.join("target").join("mini-edr-sensor-ebpf");

    // Cargo discovers `.cargo/config.toml` from the child process working
    // directory. Running from the nested eBPF crate ensures the local
    // `bpf-linker --btf` setting is applied for CO-RE/BTF metadata without
    // leaking BPF-only rustflags into the userspace workspace.
    let status = Command::new("cargo")
        .current_dir(&ebpf_dir)
        .arg("+nightly")
        .arg("build")
        .arg("--manifest-path")
        .arg(ebpf_dir.join("Cargo.toml"))
        .arg("--release")
        .arg("--target")
        .arg("bpfel-unknown-none")
        .arg("-Z")
        .arg("build-std=core")
        .arg("--target-dir")
        .arg(target_dir)
        .status()
        .expect("failed to spawn cargo +nightly for mini-edr-sensor eBPF build");

    assert!(
        status.success(),
        "mini-edr-sensor eBPF release build failed with status {status}"
    );
}
