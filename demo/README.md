# Mini-EDR Demo Workflow

`demo/run_demo.sh` is an isolated, reviewer-facing walkthrough of Mini-EDR's live daemon.

## What it shows

The script runs a small end-to-end story:

1. Prints the daemon binary's file capabilities and explains why the project uses file caps instead of keeping the process root.
2. Starts the real release daemon, waits for `state=Running`, prints `/api/health`, and confirms that BPF probes are attached.
3. Samples the real live host activity already flowing through `/api/processes` and `/api/events` so reviewers can see the daemon's operator-facing surfaces populate in real time.
4. Waits for the next real alert emitted by the daemon, then shows:
   - the matching alert line from `alerts.jsonl`,
   - the matching process row with feature-vector detail from `/api/processes`,
   - the matching dashboard alert from `/api/dashboard/alerts`.
5. Demonstrates operational hygiene:
   - a successful `SIGHUP` threshold reload,
   - a deliberately bad reload that rolls back cleanly,
   - a final `SIGTERM` clean shutdown with no leftover daemon.
6. Runs a short illustrative performance snapshot and reports the observed generator throughput, daemon-received event rate, CPU share, and RSS peak.

## How to run it

From the repository root:

```bash
bash demo/run_demo.sh
```

The script keeps runtime artifacts under a temp directory named like:

```text
/tmp/mini-edr-demo-XXXXXX
```

That directory contains the generated config, daemon stdout log, alert log, and per-phase JSON evidence.

## Prerequisites

The demo intentionally consumes the existing production artifact instead of modifying the workspace:

- `target/release/mini-edr-daemon` must already exist
- `training/output/model.onnx` must already exist
- the daemon binary must already carry:
  - `cap_bpf`
  - `cap_perfmon`
  - `cap_sys_admin`
  - `cap_dac_read_search`

If file capabilities are missing, the script exits early and prints the exact `setcap` command to run.

## Isolation guarantees

The demo is designed to stay inside the boundaries requested for this feature:

- it adds files only under `demo/`
- at runtime it writes only under `demo/` and `/tmp/mini-edr-demo-*`
- it does not modify `crates/`, `tests/`, `scripts/`, `contrib/`, or any top-level config
- it does not install packages or change the workspace graph
- it starts the daemon without `sudo`; `sudo -n` is used only for read-only `bpftool` inspection when needed

For safety, the script **refuses to start** if another `mini-edr-daemon` is already running. It does not kill pre-existing user processes.

## Hardcoded for demo

These values are intentionally demo-specific and are not referenced anywhere outside `demo/`:

- `alert_threshold = 0.0` at initial startup so the live host activity already present on this machine deterministically surfaces a visible alert
- `alert_threshold = 0.7` for the successful reload phase
- `ring_buffer_size_pages = 1024` to make the short perf snapshot less noisy
- a 10-second, 4-thread loopback `connect(2)` storm for the perf snapshot

Those hardcoded values make the demo reliable, but the reported scores, health state, alert contents, observed PIDs, and perf numbers still come from the real daemon and the real model.

## Expected output samples

See `demo/expected_output/` for small sample artifacts captured from a successful run on this host.

The exact PIDs, timestamps, and perf figures will vary, but the shape should match:

- a `Running` health payload
- a live process-tree row plus a recent event sample from the host
- a correlated live alert with `pid`, `model_hash`, `threat_score`, and `ancestry_chain`
- a matching dashboard alert snapshot
- a short perf summary with non-zero throughput and RSS data
