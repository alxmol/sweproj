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

    // Cross-target portability checks deliberately try to build the workspace
    // for unsupported hosts such as macOS. Those targets should fail at the
    // Rust cfg gate in `src/lib.rs`, not by spawning the nested Linux-only eBPF
    // build. Skipping the eBPF child build here keeps the failure focused.
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux")
        || env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("x86_64")
    {
        return;
    }

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
    let mut command = Command::new("cargo");
    command
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
        .arg(target_dir);
    clear_outer_cargo_toolchain_env(&mut command);

    let status = command
        .status()
        .expect("failed to spawn cargo +nightly for mini-edr-sensor eBPF build");

    assert!(
        status.success(),
        "mini-edr-sensor eBPF release build failed with status {status}"
    );
}

fn clear_outer_cargo_toolchain_env(command: &mut Command) {
    // Cargo sets `RUSTC` and `RUSTDOC` for build scripts so nested invocations
    // normally reuse the outer stable compiler. The eBPF package must run under
    // `cargo +nightly -Z build-std=core`, so these inherited overrides are
    // removed before spawning the child Cargo process. Without this, release
    // builds try to find `rust-src` under the stable toolchain and fail before
    // `bpf-linker --btf` can produce the CO-RE object.
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
