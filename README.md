# Mini-EDR

Mini-EDR is a single-host Linux endpoint detection and response daemon written in Rust.
It uses Aya-based eBPF tracepoints to capture `execve`, `openat`, `connect`, and `clone`,
enriches those events with `/proc` context, aggregates them into per-process windows,
scores the windows with an XGBoost-derived ONNX model, and surfaces alerts through:

- an append-only JSON alert log,
- an embedded ratatui terminal UI,
- a localhost-only axum dashboard, and
- HTTP + Unix-socket operator APIs.

The repository now contains the full seven-crate workspace, the Python training pipeline
under `training/`, the TUI and web harnesses under `tests/`, and reproducible Docker /
Vagrant development environments under `contrib/`.

Authoritative references:

- [`Mini_EDR_SRS.docx.md`](Mini_EDR_SRS.docx.md)
- [`Mini-edr_SDD.docx.md`](Mini-edr_SDD.docx.md)
- [`Mini-EDR_Test_Document.docx.md`](Mini-EDR_Test_Document.docx.md)

## Build Instructions

### Supported host and tooling

| Requirement | Notes |
| --- | --- |
| Linux `x86_64`, kernel `>= 5.8` | Required for live eBPF probe attachment. The daemon refuses to start on older kernels. |
| Rust stable `1.94.1` | Builds the seven-crate userspace workspace. |
| Rust nightly + `rust-src` + `bpf-linker` | Builds the kernel-side Aya eBPF object through `mini-edr-sensor`. |
| Python 3.12 | Runs the training pipeline under `training/`. |
| BETH dataset at `beth/archive/` | Used to produce `training/output/model.onnx`. |
| Docker (optional) | Recommended for reproducible privileged Linux development. |
| Vagrant (optional) | Checked-in fallback when Docker is not the right fit. |

### Bootstrap a local checkout

Install the Rust and Python dependencies the repo expects:

```sh
rustup toolchain install 1.94.1 nightly
rustup default 1.94.1
rustup component add rustfmt clippy --toolchain 1.94.1
rustup component add rust-src --toolchain nightly
cargo install --locked cargo-nextest cargo-llvm-cov cargo-audit cargo-deny cargo-fuzz
cargo install --locked bpf-linker --version 0.10.3

python3 -m venv crates/mini-edr-detection/training/.venv
crates/mini-edr-detection/training/.venv/bin/pip install -r training/requirements.txt
```

### Build the workspace and model

From the repository root:

```sh
cargo build --workspace --all-targets
crates/mini-edr-detection/training/.venv/bin/python -m training.train \
  --beth-dir "$PWD/beth/archive" \
  --output-dir "$PWD/training/output" \
  --seed 1337
cargo build --release -p mini-edr-daemon
sudo ./scripts/setcap.sh target/release/mini-edr-daemon
getcap target/release/mini-edr-daemon
```

Notes:

- `cargo build --workspace --all-targets` builds the seven workspace crates plus tests/examples.
- The portable training command above writes the deployed model to `training/output/model.onnx`.
- `make train` is a convenience wrapper around the same training entrypoint, but the current
  `Makefile` is pinned to the `/home/directory/mini-edr` mission checkout path.
- `scripts/setcap.sh` applies the capability set the current daemon expects for live probe
  startup: `cap_bpf,cap_perfmon,cap_sys_admin+ep`.

The checked-in `config.toml` is also tied to the current `/home/directory/mini-edr` checkout, so
contributors cloning elsewhere should update its absolute `model_path` and `state_dir` values
before launching the daemon.

### Reproducible development environments

#### Docker

Build the pinned Ubuntu 24.04 development image:

```sh
docker build -f contrib/Dockerfile.dev -t mini-edr-dev .
```

Open an interactive shell inside the image against your current checkout:

```sh
docker run --rm -it \
  --privileged \
  --cap-add=BPF \
  --cap-add=PERFMON \
  -v "$PWD":/home/directory/mini-edr \
  -w /home/directory/mini-edr \
  mini-edr-dev bash
```

Use this path when you want a reproducible Linux userspace for builds, tests, or privileged
fixture runs.

#### Vagrant

The repository also ships `contrib/Vagrantfile` as a VM fallback. If you use Vagrant locally,
run it from `contrib/`:

```sh
cd contrib
vagrant validate
vagrant up
vagrant ssh -c 'cd /vagrant && cargo build --workspace --release'
```

The Vagrant path is mainly for contributors who need a portable Ubuntu guest with a supported
kernel but do not want to use the Docker harness.

### Validation commands

The project-level checks used throughout the workspace are:

```sh
cargo nextest run --workspace --test-threads=8
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
RUSTDOCFLAGS='-D missing_docs' cargo doc --workspace --no-deps
cargo audit && cargo deny check
```

Use `cargo +nightly fuzz run ringbuffer_deserialize -- -max_total_time=60` for the short fuzz
smoke, and the shell harnesses under `tests/` for TUI, web, cross-area, availability, and
performance validation.

## Usage

### 1. Prepare a model and config

The daemon expects a model file at the configured `model_path`. From a fresh clone, generate it
first:

```sh
crates/mini-edr-detection/training/.venv/bin/python -m training.train \
  --beth-dir "$PWD/beth/archive" \
  --output-dir "$PWD/training/output" \
  --seed 1337
```

The checked-in `config.toml` is intentionally small:

```toml
alert_threshold = 0.7
web_port = 8080
model_path = "/home/directory/mini-edr/training/output/model.onnx"
log_file_path = "alerts.jsonl"
state_dir = "/home/directory/mini-edr/state"
```

Fields omitted from that file fall back to the defaults implemented in `mini-edr-common::Config`,
including:

- `monitored_syscalls = ["execve", "openat", "connect", "clone"]`
- `window_duration_secs = 30`
- `ring_buffer_size_pages = 64`
- `enable_tui = true`
- `enable_web = true`
- `log_level = "info"`

If your checkout is not `/home/directory/mini-edr`, update `model_path` and `state_dir` before
starting the daemon.

### 2. Run the live daemon

For a real probe-attaching run, build the release binary, apply capabilities, and then start it
from a terminal:

```sh
MINI_EDR_API_SOCKET=/tmp/mini-edr.sock \
  ./target/release/mini-edr-daemon --config ./config.toml
```

Important behavior to know:

- The daemon binds the dashboard and HTTP API to `127.0.0.1:8080` by default.
- The Unix-socket API defaults to `/run/mini-edr/api.sock`, but
  `MINI_EDR_API_SOCKET=/tmp/mini-edr.sock` is a convenient user-writable development override.
- When `enable_tui = true` and stdout is a real terminal, the daemon launches the ratatui
  operator UI in the same terminal after startup.
- When stdout is not a terminal, the daemon logs `tui_skipped_headless` and continues in
  headless mode with the web/API surfaces still enabled.

### 3. TUI, dashboard, and API surfaces

After startup:

- **TUI command**: run the daemon from an interactive terminal with `enable_tui = true`; there is
  no separate operator binary in the workspace today.
- **Dashboard URL**: `http://127.0.0.1:8080/`
- **HTTP health**: `curl -fsS http://127.0.0.1:8080/api/health`
- **Unix-socket health**: `curl --unix-socket /tmp/mini-edr.sock http://localhost/health`

Useful endpoints:

| Surface | Endpoint |
| --- | --- |
| Health | `GET /api/health` |
| Telemetry summary | `GET /api/telemetry/summary` |
| Recent live events | `GET /api/events?pid=<pid>&limit=<n>` |
| Alert stream | `GET /api/alerts/stream` |
| Dashboard alert snapshot | `GET /api/dashboard/alerts` |
| WebSocket alerts | `GET /ws` |
| SSE alerts | `GET /sse` |
| Threshold settings CSRF token | `GET /api/settings/csrf` |
| Threshold update | `POST /api/settings/threshold` |
| Probe lifecycle | `POST /api/probes/<execve|openat|connect|clone>/<attach|detach>` |
| Internal prediction harness | `POST /internal/predict` |

The daemon writes three operator-facing log files beside the configured alert log path:

- `alerts.jsonl` — durable alert records
- `events.jsonl` — structured inference/debug events
- `daemon.log` — operational lifecycle events

### 4. Non-privileged synthetic smoke run

If you want to exercise the dashboard, API, and TUI without Linux capabilities, use the daemon's
synthetic test mode:

```sh
MINI_EDR_TEST_MODE=1 \
MINI_EDR_TEST_SENSOR_RATE=250 \
MINI_EDR_API_SOCKET=/tmp/mini-edr.sock \
cargo run -p mini-edr-daemon -- --config ./config.toml
```

That mode skips live probe attachment, generates deterministic synthetic syscall traffic, and is
the same escape hatch used by several integration and availability harnesses.

### 5. Signals and day-2 operations

From another terminal:

```sh
kill -HUP  "$(pgrep -x mini-edr-daemon)"   # reload config + model
kill -USR1 "$(pgrep -x mini-edr-daemon)"   # reopen logs for rotation
kill -TERM "$(pgrep -x mini-edr-daemon)"   # graceful shutdown
```

The daemon's lifecycle states exposed through `/api/health` are:

- `Initializing`
- `Running`
- `BackPressure`
- `Degraded`
- `Reloading`
- `ShuttingDown`

If the configured model cannot be loaded, the daemon stays up in `Degraded` mode instead of
exiting outright.

### 6. TUI-only smoke harness

The TUI crate also ships a standalone smoke example that the `tuistory` harnesses use:

```sh
cargo run -p mini-edr-tui --example launch_smoke
```

Use that when you want to iterate on TUI rendering without starting the full daemon.

### Troubleshooting

- **`requires Linux kernel >= 5.8`**: you are on an unsupported host kernel for live probe mode.
- **`CAP_BPF` / `CAP_PERFMON` missing**: rerun
  `sudo ./scripts/setcap.sh target/release/mini-edr-daemon` or start the daemon via `sudo`.
- **Dashboard is unreachable**: confirm the daemon is listening on `127.0.0.1:8080` and that
  `web_port` in `config.toml` was not changed.
- **The daemon starts but no TUI appears**: stdout is not a terminal, or `enable_tui = false`.
- **The daemon is running in `Degraded`**: verify that `training/output/model.onnx` exists and
  matches `model_path`.
- **The Unix socket will not bind**: remove or override `MINI_EDR_API_SOCKET`; the daemon already
  cleans up stale socket files, but it refuses to replace a live socket owner.
- **No alerts appear during a synthetic run**: synthetic mode is for surface and lifecycle smoke
  testing, not live malicious-fixture verification.

## Architecture

Mini-EDR follows a strict seven-crate workspace layout so each subsystem can be built and
reviewed independently.

### Workspace map

| Path | Responsibility |
| --- | --- |
| `crates/mini-edr-common` | Shared domain types, config parsing, validation, serde/rustdoc contract |
| `crates/mini-edr-sensor` | Aya eBPF programs, ring-buffer consumer, probe manager, kernel counters |
| `crates/mini-edr-pipeline` | `/proc` enrichment, ancestry reconstruction, window aggregation, feature extraction |
| `crates/mini-edr-detection` | ONNX/XGBoost inference, hot reload, alert generation, alert-ID persistence |
| `crates/mini-edr-tui` | ratatui operator interface and PTY smoke harness example |
| `crates/mini-edr-web` | axum-served localhost SPA assets and web router scaffold |
| `crates/mini-edr-daemon` | runtime wiring, lifecycle state machine, signals, API, logs, dashboard/TUI startup |
| `training/` | Python training and evaluation pipeline |
| `tests/` | shell harnesses for TUI, web, system, performance, availability, and cross-area flows |
| `contrib/` | Docker and Vagrant development environments |
| `scripts/` | operator/dev helpers such as `setcap.sh` |

### Runtime data flow

The live data path is intentionally one-way:

```text
SyscallEvent -> EnrichedEvent -> FeatureVector -> Alert
```

At runtime that means:

1. Aya tracepoints capture `execve`, `openat`, `connect`, and `clone`.
2. The userspace sensor consumes the ring buffer and normalizes raw kernel events.
3. The pipeline enriches events with `/proc` metadata and groups them into per-process windows.
4. The detection engine scores each `FeatureVector` against the ONNX model.
5. Alerts fan out to `alerts.jsonl`, the embedded TUI, the localhost dashboard, the
   WebSocket/SSE feeds, and the Unix-socket/HTTP APIs.

### Main operator surfaces

- **Interactive terminal**: the daemon launches the TUI when run in a real terminal.
- **Browser dashboard**: `mini-edr-web` serves the SPA at `http://127.0.0.1:8080/`.
- **Local API**: health, telemetry, alert streaming, event inspection, threshold updates, and
  probe attach/detach operations are exposed over both HTTP and a Unix socket.
- **Training pipeline**: `training/train.py` and `make train` build the deployed model artifact
  from the BETH dataset.

### Design constraints that show up everywhere

- Linux only, `x86_64` only, kernel `>= 5.8`
- localhost-only web binding by default
- append-only alert log with `0600` permissions
- capability-gated live probe startup
- hot reload via `SIGHUP`
- clean probe detach on shutdown

## Contribution

### Development workflow

1. Read the SRS, SDD, and Test Document before changing behavior.
2. Make focused changes inside the relevant crate instead of crossing boundaries casually.
3. Keep explanatory comments in code, especially around public APIs, invariants, unsafe blocks,
   signal handling, and kernel-facing logic.
4. Prefer the checked-in harnesses under `tests/` over ad-hoc one-off scripts when verifying
   behavior.
5. Use Docker or the live capability flow when touching probe lifecycle or other privileged paths.

### Required checks before opening or sharing a change

Run the normal workspace validators:

```sh
cargo nextest run --workspace --test-threads=8
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
RUSTDOCFLAGS='-D missing_docs' cargo doc --workspace --no-deps
```

Also run these when relevant:

- `cargo audit && cargo deny check` for dependency changes
- `make train` plus the evaluation harness when touching the ML path
- the matching shell harnesses under `tests/` when touching TUI, web, or daemon lifecycle
  surfaces
