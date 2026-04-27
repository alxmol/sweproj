# Mini-EDR

Mini-EDR is a single-host Linux Endpoint Detection and Response daemon written in Rust.
It uses eBPF tracepoints to capture process and syscall activity, enriches events with
local `/proc` context, aggregates behavior into process windows, scores those windows
with an ML model, and displays alerts in both a terminal UI and a localhost web dashboard.
This README is the foundation-milestone skeleton for NFR-M04 and will be expanded as
later milestones deliver the sensor, pipeline, detection, TUI, web, and full daemon.

The authoritative source documents remain:
- [`Mini_EDR_SRS.docx.md`](Mini_EDR_SRS.docx.md) for functional and non-functional requirements.
- [`Mini-edr_SDD.docx.md`](Mini-edr_SDD.docx.md) for system design and crate topology.
- [`Mini-EDR_Test_Document.docx.md`](Mini-EDR_Test_Document.docx.md) for validation cases.

## Build Instructions

Builds happen from the repository root so Cargo can resolve the seven-crate workspace.
The userspace crates build on stable Rust, while kernel-side eBPF code is planned to build
with nightly Rust, `rust-src`, and `bpf-linker`.
The project requires Linux `x86_64` with kernel `5.8` or newer for the final daemon.
Development on WSL2 is supported for non-privileged unit tests and documentation work.
Privileged eBPF loading requires `CAP_BPF` and `CAP_PERFMON`; older kernels may also need `CAP_SYS_ADMIN`.
The daemon is expected to refuse startup without the required capabilities once lifecycle wiring is complete.
The default web/API port is `127.0.0.1:8080`, and all HTTP/WebSocket surfaces must stay localhost-only.
Build artifacts are written under `target/`, and generated model/log artifacts are written under `artifacts/` and `logs/`.
The BETH dataset used by the ML pipeline is expected at `beth/archive/` and should be treated as read-only.
The commands below are the canonical local path for the current skeleton and will become stricter as milestones land.

- Install or refresh the Rust toolchains:
  `rustup toolchain install stable`
- Add the stable components used by validators:
  `rustup component add rustfmt clippy --toolchain stable`
- Install nightly for eBPF and fuzzing work:
  `rustup toolchain install nightly`
- Add nightly `rust-src` so Aya/BPF builds can use `-Z build-std=core`:
  `rustup component add rust-src --toolchain nightly`
- Install the eBPF linker used by kernel-side Rust programs:
  `cargo install bpf-linker`
- Install the normal mission developer tools:
  `cargo install cargo-nextest --locked cargo-llvm-cov cargo-audit cargo-deny cargo-fuzz`
- Build every crate and target in the workspace:
  `cargo build --workspace --all-targets`
- Run the fast unit test suite:
  `cargo nextest run --workspace --test-threads=8`
- Run formatting checks:
  `cargo fmt --all -- --check`
- Run lint checks:
  `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- Run strict public API documentation checks:
  `RUSTDOCFLAGS='-D missing_docs' cargo doc --workspace --no-deps`
- Run supply-chain checks:
  `cargo audit && cargo deny check`
- Run coverage once the test corpus is mature:
  `cargo llvm-cov nextest --workspace --html --test-threads=8`
- Build a release daemon before applying capabilities:
  `cargo build --workspace --release`
- Apply production-style daemon capabilities after a release build:
  `sudo ./scripts/setcap.sh`
- Verify capabilities when debugging startup failures:
  `getcap target/release/mini-edr-daemon`
- Build the pinned Ubuntu 24.04 dev container that verifies `cargo build --workspace --all-targets` during image creation:
  `docker build --no-cache -f contrib/Dockerfile.dev -t mini-edr-dev .`
- Use the dev container as the reproducible Linux workspace for privileged system tests:
  `docker run --rm -it --privileged --cap-add=BPF --cap-add=PERFMON -v "$PWD":/workspace -w /workspace mini-edr-dev bash`
- Validate the portable Ubuntu 24.04 VM definition before bringing it up:
  `vagrant validate contrib/Vagrantfile`
- Bring up the portable VM fallback and run the release build inside `/vagrant` when Docker is not the right fit:
  `vagrant up && vagrant ssh -c 'cd /vagrant && cargo build --workspace --release'`
- If capabilities are not available, run only non-privileged unit tests or use the future privileged Docker harness.
- Do not run `rustup target add bpfel-unknown-none` as a required step; current nightly may not ship prebuilt `rust-std` for that tier-3 target.
- The expected eBPF path is nightly plus `rust-src` plus `bpf-linker`, driven by Aya build logic.
- The current foundation workspace can be validated without sudo because eBPF probes are introduced in later milestones.
- Future sensor and system-integration tests will document which commands require sudo or Docker privileges.
- Keep generated ONNX model files out of ordinary code commits unless a later feature explicitly requires a checked-in artifact.
- Keep `Cargo.lock` committed because Mini-EDR is an application workspace and reproducible builds matter.
- If a validator reports a missing command, rerun the mission bootstrap script before debugging the code itself:
  `bash /home/alexm/.factory/missions/2072d5be-b8e6-456d-b85d-0508f0a8bc30/init.sh`

## Usage

The current repository is in the foundation stage, so some commands below describe the intended operator flow.
As implementation progresses, placeholders will be replaced by exact command flags, config examples, and screenshots.
All commands are written from the repository root unless noted otherwise.
The final daemon is a single process that owns eBPF probes, the local API, the web dashboard, and the TUI data bus.
For developer runs, logs should stay under `./logs/` rather than `/var/log/mini-edr/` unless sudo setup is intentional.
For production-like runs, apply `setcap` first so the daemon has `CAP_BPF` and `CAP_PERFMON`.
The web dashboard is expected at `http://127.0.0.1:8080/`.
The local API Unix socket is expected at `/tmp/mini-edr.sock`.
The TUI is expected to be launched through the daemon or the `mini-edr-tui` binary once the TUI crate is implemented.
The daemon should be stopped with `SIGTERM` or `Ctrl-C` so probes can be detached and alert logs flushed.
Do not bind the dashboard to `0.0.0.0` during normal development; localhost-only binding is part of the security contract.

- Start by building the workspace:
  `cargo build --workspace --all-targets`
- Run tests before attempting a daemon run:
  `cargo nextest run --workspace --test-threads=8`
- Build the release daemon:
  `cargo build --release -p mini-edr-daemon`
- Grant capabilities to the release daemon:
  `sudo ./scripts/setcap.sh`
- Open a pinned Linux shell for reproducible builds and privileged system-test runs:
  `docker run --rm -it --privileged --cap-add=BPF --cap-add=PERFMON -v "$PWD":/workspace -w /workspace mini-edr-dev bash`
- Use `contrib/Vagrantfile` as the VM fallback when you need a full Ubuntu guest instead of a container:
  `vagrant up && vagrant ssh`
- Start the daemon with the default development config once `config.toml` exists:
  `MINI_EDR_WEB_PORT=8080 MINI_EDR_API_SOCKET=/tmp/mini-edr.sock ./target/release/mini-edr-daemon --config ./config.toml`
- Use a local log directory for development:
  `MINI_EDR_LOG_DIR=./logs`
- Use the trained model artifact when detection is enabled:
  `MINI_EDR_MODEL_PATH=./artifacts/model.onnx`
- Open the web dashboard in a browser:
  `http://127.0.0.1:8080/`
- Check daemon health through HTTP:
  `curl -fsS http://127.0.0.1:8080/api/health`
- Check daemon health through the Unix socket:
  `curl --unix-socket /tmp/mini-edr.sock http://localhost/api/health`
- Launch the terminal UI when the TUI binary is available:
  `./target/release/mini-edr-tui --socket /tmp/mini-edr.sock`
- If the TUI is exposed as a daemon mode in a later milestone, prefer the documented daemon subcommand instead.
- Stream alerts from the local API once alerting is implemented:
  `curl --unix-socket /tmp/mini-edr.sock -N http://localhost/api/alerts/stream`
- Rotate the alert log once signal handling is implemented:
  `kill -USR1 $(pidof mini-edr-daemon)`
- Reload config and model state once hot reload is implemented:
  `kill -HUP $(pidof mini-edr-daemon)`
- Stop the daemon cleanly:
  `kill -TERM $(pidof mini-edr-daemon)`
- If startup reports missing capabilities, re-run `getcap` and the `setcap` command above.
- If startup reports an invalid config, validate `web_port`, `alert_threshold`, `window_duration_secs`, and paths for traversal.
- If the web dashboard is unreachable, confirm the daemon is listening on `127.0.0.1:8080`, not a wildcard address.
- If no alerts appear, confirm the model exists, the daemon is not in degraded mode, and test fixtures are producing syscalls.
- If eBPF probe attachment fails, inspect kernel version, BTF availability at `/sys/kernel/btf/vmlinux`, and daemon capabilities.
- System tests that require Docker or privileged probe loading will be documented in the system-integration milestone.
- Long-running soak and fuzz tests use configurable durations; do not hard-code 24-hour runs into routine local workflows.

## Architecture

Mini-EDR follows the architecture in [`Mini-edr_SDD.docx.md`](Mini-edr_SDD.docx.md), especially SDD §3 and SDD §8.2.
The top-level data flow is strictly downstream: `SyscallEvent` to `EnrichedEvent` to `FeatureVector` to `Alert`.
The workspace contains seven crates so each subsystem can be developed, tested, and reviewed independently.
`mini-edr-common` owns shared domain types, configuration parsing, serialization, and validation utilities.
`mini-edr-sensor` will own the Aya eBPF probes and userspace ring-buffer consumer.
`mini-edr-pipeline` will enrich syscall events with `/proc` metadata and compute process-window feature vectors.
`mini-edr-detection` will load the ONNX/XGBoost model, run inference, and create alerts at or above the configured threshold.
`mini-edr-tui` will render the ratatui terminal interface backed by daemon telemetry and alert broadcasts.
`mini-edr-web` will serve the localhost axum dashboard, static assets, and live alert/telemetry streams.
`mini-edr-daemon` will wire all subsystems together, own the Tokio runtime, manage Unix signals, and enforce lifecycle state.
The crate dependency graph must remain acyclic, with visualization crates consuming shared domain types rather than reaching into lower layers.

- Sensor input comes from Linux tracepoints for `execve`, `openat`, `connect`, and `clone`.
- Kernel-to-userspace transport is planned to use `BPF_MAP_TYPE_RINGBUF`, not `perf_event_array`.
- The sensor converts raw kernel records into `SyscallEvent` values from `mini-edr-common`.
- The pipeline enriches events with process name, binary path, cgroup, UID, and ancestry.
- The window aggregator groups enriched events per PID and emits `FeatureVector` records.
- Feature vectors include syscall counts, n-gram frequencies, path entropy, unique IPs/files, child process counts, timing statistics, and sensitive-directory flags.
- Detection scores each feature vector and emits an `Alert` when `threat_score >= alert_threshold`.
- Alert threshold equality is intentional: boundary scores at exactly the threshold must alert.
- Alert records are single-line JSON and are the primary persisted runtime artifact.
- The daemon state machine is `Initializing`, `Running`, `Degraded`, `Reloading`, and `ShuttingDown`.
- Missing or invalid models should put the daemon into degraded pass-through mode rather than halting capture.
- Missing capabilities or invalid configuration should fail startup with an operator-actionable error.
- Tokio `mpsc` channels are used for single-consumer stage transitions.
- Tokio `broadcast` channels are used for fan-out to the TUI, web dashboard, API, and log writer.
- Backpressure must be explicit and observable through counters rather than silently corrupting data.
- The web dashboard binds to `127.0.0.1` by default for NFR-SE02.
- The alert log must be created with mode `0600` for NFR-SE03.
- Runtime config is represented by a validated `Config` and eventually hot-swapped on `SIGHUP`.
- The ML model artifact is loaded from disk at startup and eventually hot-reloaded atomically.
- The TUI and web dashboard are presentation layers; they should not own sensor, pipeline, or detection state directly.
- Cross-area validation will eventually prove a real syscall can become an alert in JSON logs, TUI, and web UI within the latency budget.
- Portability validation targets Linux `x86_64` kernels from `5.8` through current `6.x` with CO-RE.
- The architecture intentionally avoids outbound network dependencies during daemon runtime.
- The SDD remains the detailed design reference when this README and implementation comments disagree.

## Contribution

Contributions should keep the project aligned with the SRS, SDD, Test Document, and validation contract.
Small, focused changes are preferred because every subsystem has explicit functional and non-functional assertions.
Each change should name the requirement or validation assertion it helps satisfy when that mapping is known.
Use GitHub Issues to track defects, enhancements, and technical debt before opening broad or cross-cutting changes.
Issue labels should include at least one of `bug`, `enhancement`, or `tech-debt` so triage remains searchable.
Do not mix unrelated feature work, dependency updates, and formatting-only changes in a single commit.
Do not introduce runtime outbound network calls unless a future requirement explicitly allows them.
Do not weaken security defaults such as localhost-only web binding, capability checks, or alert-log permissions.
Do not remove comments or rustdoc that explain safety, invariants, or requirement mappings.
If a test is flaky or blocked by environment setup, document the exact command, exit code, and observed output in the issue or handoff.
The preferred workflow mirrors the Test Document §1.4 bug-tracker discipline: file, label, reproduce, fix, verify, and close with evidence.

- Start from a clean working tree on `main` unless the maintainer asks for a feature branch.
- Read the relevant SRS, SDD, and Test Document sections before designing the change.
- For Rust code, add tests before implementation whenever the behavior is not already covered.
- Public Rust items need `///` rustdoc comments that explain purpose, inputs, outputs, and errors.
- Non-trivial algorithms need inline comments explaining why the approach is correct.
- Unsafe code must include a `SAFETY:` comment that justifies the assumptions.
- Prefer `thiserror` in library crates and `anyhow` in the daemon binary.
- Avoid `.unwrap()` outside tests; return structured errors with actionable context.
- Keep crate boundaries intact; shared data types belong in `mini-edr-common`.
- Keep UI crates independent from sensor/pipeline/detection internals.
- Run `cargo fmt --all -- --check` before committing.
- Run `cargo clippy --workspace --all-targets --all-features -- -D warnings` before committing code changes.
- Run `cargo nextest run --workspace --test-threads=8` before committing any behavior change.
- Run `RUSTDOCFLAGS='-D missing_docs' cargo doc --workspace --no-deps` when public APIs change.
- Run `cargo audit` and `cargo deny check` when dependencies change.
- Update fixtures only when the expected behavior changes and the reason is documented.
- Keep generated logs, coverage reports, fuzz corpora, and large model artifacts out of commits unless explicitly requested.
- When reporting a `bug`, include the command, expected result, actual result, environment, and relevant logs.
- When proposing an `enhancement`, include the requirement or user scenario it supports.
- When filing `tech-debt`, include the risk, affected crate, and suggested follow-up milestone.
- Keep commits local unless maintainers explicitly request a push.
- Include co-authorship or automation metadata only when the workflow requires it.
- Future milestone writeups in `docs/milestones/` will summarize accomplishments, bugs, resolutions, and carry-overs.
- This skeleton README may be expanded by later workers, but it should continue to preserve these four major NFR-M04 sections.
