# Mini-EDR Mission Summary

This file is the consolidated mission roll-up for all eight milestones that produced the Mini-EDR workspace, daemon, operator surfaces, fixture suites, and validation harnesses.
It spans the foundational crate work, sensor/pipeline/detection/alerting implementation, the TUI and web surfaces, and the system-integration convergence work that tied the pieces together.
As of `2026-04-27`, the mission-level validation snapshot in `validation-state.json` is **142/215 passed, 73/215 pending, 0 blocked**.
That means the repository now traces **215/215 contract assertions** and maps each one to an owning feature, but milestone-8-heavy areas still need formal promotion through the missing system-integration scrutiny and user-testing synthesis runs.

## Milestone roll-up

| Milestone | One-line achievement | Primary writeup |
| --- | --- | --- |
| M1 — Foundation | Established the seven-crate workspace, shared schema/config contract, CI gates, and the initial operator/developer README. | `docs/milestones/01-foundation.md` |
| M2 — Sensor | Delivered Aya-based syscall capture, a stable ring-buffer ABI, dynamic probe management, overflow accounting, and fuzz coverage. | `docs/milestones/02-sensor.md` |
| M3 — Pipeline | Added `/proc` enrichment, ancestry reconstruction, sliding windows, feature extraction, deduplication, and race/deep-chain hardening. | `docs/milestones/03-pipeline.md` |
| M4 — Detection | Shipped the BETH → XGBoost → ONNX training path, Rust inference engines, thresholded alert generation, and hot reload. | `docs/milestones/04-detection.md` |
| M5 — Alerting API | Turned alerts into durable localhost-visible artifacts with JSON logs, rotation, Unix-socket/HTTP APIs, and restart-safe alert-id persistence. | `docs/milestones/05-alerting-api.md` |
| M6 — TUI | Delivered the ratatui operator console with score-color parity, drill-down inspection, PTY automation, and latency-oriented harnesses. | `docs/milestones/06-tui.md` |
| M7 — Web | Delivered the axum-served dashboard with process tree, alert timeline, health tab, live WS/SSE updates, and CSRF-protected state changes. | `docs/milestones/07-web.md` |
| M8 — System Integration | Wired the daemon lifecycle, dev/prod environments, perf/availability/portability harnesses, and the cross-area validation story into one converged system. | `docs/milestones/08-system-integration.md` |

## Mission-wide achievements

- The repository now contains the complete seven-crate Rust workspace promised by the SDD.
- The sensor path captures `execve`, `openat`, `connect`, and `clone` into a typed ring-buffer pipeline.
- The pipeline path enriches events through `/proc`, reconstructs ancestry, windows activity per PID, and computes the feature schema the detector expects.
- The detection path trains a real model from the BETH dataset, exports ONNX, serves inference in Rust, and preserves hot-reload semantics.
- The alerting path persists append-only operator artifacts with restart-safe alert-id sequencing and localhost-only APIs.
- The TUI path provides an in-terminal SOC workflow with score-color parity, drill-downs, and keyboard automation coverage.
- The web path provides a browser-native SOC workflow with live updates, filters, drill-downs, and health visibility.
- The system-integration path provides the lifecycle, portability, performance, availability, and cross-area harnesses needed to treat the repo as a single product rather than a set of crates.

## Performance and availability roll-up

| Metric | Contract target | Observed result | Evidence source |
| --- | --- | --- | --- |
| Synthetic throughput replay | `>= 50,000 events/s` | `3,127,542.95 events/s` over `3,600,000` events with `0` dropped events | `tests/perf/throughput_50k.sh`; handoff `f8-performance-benchmarks` |
| End-to-end alert latency | `< 5 s p99` | `p50 0.187659 ms`, `p99 0.831888 ms`, `max 0.831888 ms` over `50` reverse-shell trials | `tests/perf/e2e_latency.sh`; handoff `f8-performance-benchmarks` |
| CPU overhead under steady load | `<= 2%` of total system CPU budget | `mean 0.423729%`, with `max spike 32.0%` during a `5,000 eps` paced run | `tests/perf/cpu_overhead.sh`; handoff `f8-performance-benchmarks` |
| Resident memory peak | `<= 256 MiB` | `30,670,848 bytes` peak (`~29.3 MiB`) during the configurable RSS gate | `tests/perf/rss_4h.sh`; handoff `f8-performance-benchmarks` |
| RSS growth slope (perf proxy) | bounded long-run growth | `0.075 MB/min` (`4.5 MB/h`) during the short-run perf proxy | `tests/perf/rss_4h.sh`; handoff `f8-performance-benchmarks` |
| RSS growth slope (availability soak) | `< 1 MiB/h` after warmup | `0.0 MiB/h` over the `20 s` smoke soak with `4/4` fixture detections | `tests/system/soak.sh`; handoff `f8-availability-tests` |
| Probe reload recovery | reconnect within `1 s` | `attach_gap_seconds ≈ 0.307` with a fresh Connect event after reload | `tests/system/probe_reload.sh`; handoff `f8-availability-tests` |
| BackPressure visibility | daemon survives under memory pressure | `ring_events_dropped_total: 945619`, `windows_evicted_total: 5164`, state `BackPressure`, alert still generated | `tests/system/memory_pressure.sh`; handoff `f8-availability-tests` |
| Inference latency microbenchmark | `< 10 ms p99` | `6.13–6.17 µs` in Criterion | `crates/mini-edr-detection/benches/performance.rs`; handoff `f8-performance-benchmarks` |
| Feature extraction throughput microbenchmark | implementation benchmark required | `2.88–2.89M elements/s` in Criterion | `crates/mini-edr-detection/benches/performance.rs`; handoff `f8-performance-benchmarks` |
| JSON serialization overhead | implementation benchmark required | `630–637 ns` in Criterion | `crates/mini-edr-detection/benches/performance.rs`; handoff `f8-performance-benchmarks` |
| Hot-reload load floor after contract revision | revised floor `>= 3000 req/s` | `3276.86 req/s` with two model hashes, zero late-v1 results after swap, and `Initializing → Running → Reloading → Running` | `validation-state.json` evidence for `VAL-DETECT-018` |
| Portability LoC ratio | `<= 0.10` host-dependent code | `platform_loc=259`, `total_loc=3666`, `ratio=0.0706` | `scripts/measure_platform_loc.sh`; handoff `f8-portability-tests` |
| Portability kernel matrix | same release binary on `5.8` and `6.x`; clear reject on `5.4` | `5.4` rejected with clear error; `5.8` and `6.8` passed with all four probes and ring-buffer deltas `4099` / `3350` | `scripts/test_kernel_matrix.sh`; handoff `f8-portability-tests` |

## Validation coverage roll-up

Every contract assertion now has three stable trace anchors:

1. the definition line in `validation-contract.md`,
2. the unique owner line in `features.json`, and
3. the live status line in `validation-state.json`.

That 3-way join is what allows the 215-row coverage matrix below to stay deterministic even before the final system-integration synthesis files are generated.

| Prefix | Total | Passed | Pending | Notes |
| --- | ---: | ---: | ---: | --- |
| `VAL-SENSOR` | 19 | 15 | 4 | Pending promotion concentrated here |
| `VAL-PIPELINE` | 26 | 26 | 0 | Validator-complete |
| `VAL-DETECT` | 19 | 16 | 3 | Pending promotion concentrated here |
| `VAL-ALERT` | 16 | 16 | 0 | Validator-complete |
| `VAL-TUI` | 17 | 17 | 0 | Validator-complete |
| `VAL-WEB` | 20 | 20 | 0 | Validator-complete |
| `VAL-DAEMON` | 18 | 2 | 16 | Pending promotion concentrated here |
| `VAL-PERF` | 14 | 3 | 11 | Pending promotion concentrated here |
| `VAL-REL` | 12 | 10 | 2 | Pending promotion concentrated here |
| `VAL-AVAIL` | 7 | 1 | 6 | Pending promotion concentrated here |
| `VAL-SEC` | 13 | 4 | 9 | Pending promotion concentrated here |
| `VAL-MAINT` | 11 | 11 | 0 | Validator-complete |
| `VAL-PORT` | 11 | 1 | 10 | Pending promotion concentrated here |
| `VAL-CROSS` | 12 | 0 | 12 | Pending promotion concentrated here |

## Known limitations

- **Linux-only deployment**: the product remains intentionally limited to `x86_64` Linux hosts on kernel `>= 5.8`; the portability work proves reject/pass behavior, not cross-platform support.
- **System-integration validation is not sealed yet**: the mission directory still lacks `validation/system-integration/scrutiny/synthesis.json` and `validation/system-integration/user-testing/synthesis.json`, so milestone 8 should be described as *implemented with pending promotion*, not as fully sealed.
- **Detection quality is bounded by the BETH split**: the held-out gate is the user-approved `F1 >= 0.90`, `TPR >= 0.95`, `FPR <= 0.35` floor, and the runtime-prior investigation follow-up is still pending.
- **Privilege ergonomics still need polish**: `scripts/setcap.sh` has not yet absorbed the `cap_dac_read_search` follow-up required by some WSL2/full-flow drop-privilege scenarios.
- **The final Docker runtime image is still slimmed for reproducibility, not fixture completeness**: some privileged fixture runs still need additional runtime toolchain/runtime support inside `mini-edr-dev`.
- **Cross-area harness cleanup and degraded-start semantics need one more tightening pass**: the misc follow-ups for `VAL-CROSS-012` and EXIT-trap robustness are still open.
- **The web process tree still keys rows by PID alone**: a future follow-up should include a process-instance identifier to eliminate PID-reuse UI-state carry-over.
- **Supply-chain warning hygiene is close but not perfect**: the `crossterm` duplicate-version warning follow-up remains pending even though the hard policy gate is resolved.

## Deferred work explicitly tagged for follow-on missions

| Follow-on feature | Why it remains open |
| --- | --- |
| `f4-misc-runtime-prior-source-investigation` | Non-blocking design follow-up surfaced by f4-ml-training. The BETH archive is strongly process-family shifted across train/val/test splits, so the trainer relies on a static corpus-derived sparse-prior catalogue (under the existing bigrams/trigrams namespaces) to satisfy... |
| `misc-fixture-ergonomics-default-paths` | Surfaced as non-blocking discovered issues during f5-fix-alerts-jsonl-naming-sweep verification. Two related fixture-ergonomics defects make the standalone shell fixtures harder to run outside the cargo nextest harness: 1. **Hot-reload shell fixtures default... |
| `misc-fix-dev-image-runtime-toolchain` | Carry-over from f8-privileged-isolation-tests (session 04f5fe31, non-blocking discovered issue). The final `mini-edr-dev` runtime image cannot run the privileged harnesses end-to-end as-is: the daemon runtime rebuilds the eBPF object on startup but the... |
| `misc-fix-setcap-include-dac-read-search` | Carry-over from f8-fix-cross-flow-harness-completeness (orchestrator override 2026-04-27). The live harness `tests/cross/full_flow.sh` deliberately drops privileges back to the original user via `sudo -u "#${ORIGINAL_UID}"` to mimic production. On WSL2... |
| `misc-fix-cross-flow-val-cross-012-harness-scenario` | Carry-over from f8-fix-cross-flow-harness-completeness (orchestrator review 2026-04-27). The current `tests/cross/full_flow.sh` VAL-CROSS-012 path tries to enter Degraded by SIGHUP-swapping to a bad model and then expects the daemon to transition Running... |
| `misc-fix-cross-flow-cleanup-robustness` | Carry-over from f8-fix-sec-005-second-host-probe (orchestrator review 2026-04-27). The current `tests/cross/full_flow.sh` harness has an EXIT trap, but during runs that record partial blocks (e.g., a non-VAL-SEC assertion fails before the full happy-path completes)... |
| `misc-fix-crossterm-duplicate-version-warning` | Carry-over from f8-fix-supply-chain-policy-bsd3-and-paste-advisory (orchestrator review 2026-04-27). After upgrading `ratatui` to 0.30.0, `cargo deny check` reports a `duplicate-version` warning because `mini-edr-tui` declares `crossterm = 0.28` directly... |

## SOC operator quickstart

### 1. Build the workspace and the model

```sh
cargo build --workspace --all-targets
crates/mini-edr-detection/training/.venv/bin/python -m training.train \
  --beth-dir "$PWD/beth/archive" \
  --output-dir "$PWD/training/output" \
  --seed 1337
cargo build --release -p mini-edr-daemon
```

### 2. Apply the required capabilities

```sh
sudo ./scripts/setcap.sh target/release/mini-edr-daemon
getcap target/release/mini-edr-daemon
```

### 3. Start the daemon

```sh
MINI_EDR_API_SOCKET=/tmp/mini-edr.sock \
  ./target/release/mini-edr-daemon --config ./config.toml
```

### 4. Observe the operator surfaces

- **TUI**: run the daemon in a real interactive terminal with `enable_tui = true`; the TUI launches in-process.
- **Dashboard**: open `http://127.0.0.1:8080/`.
- **HTTP health**: `curl -fsS http://127.0.0.1:8080/api/health`
- **Unix-socket health**: `curl --unix-socket /tmp/mini-edr.sock http://localhost/health`
- **Alert log**: inspect `alerts.jsonl`, `events.jsonl`, and `daemon.log` beside the configured log path.

### 5. Day-2 operator controls

```sh
kill -HUP  "$(pgrep -x mini-edr-daemon)"   # reload config + model
kill -USR1 "$(pgrep -x mini-edr-daemon)"   # reopen logs for rotation
kill -TERM "$(pgrep -x mini-edr-daemon)"   # graceful shutdown
```

### 6. Non-privileged synthetic smoke mode

```sh
MINI_EDR_TEST_MODE=1 \
MINI_EDR_TEST_SENSOR_RATE=250 \
MINI_EDR_API_SOCKET=/tmp/mini-edr.sock \
cargo run -p mini-edr-daemon -- --config ./config.toml
```

That mode is the safest way to exercise the dashboard, API, and TUI surfaces on a host where BPF capabilities or sudo are not available.

### 7. Operator reading notes

- `alerts.jsonl` is the durable alert artifact.
- `events.jsonl` is the structured debug/inference artifact.
- `daemon.log` is the lifecycle and operational artifact.
- `Degraded` means the daemon is up but the detection model or another critical subsystem is unavailable.
- `BackPressure` means the daemon is shedding load but still alive and observable.
- `Reloading` should be transient after `SIGHUP`.
- A lack of TUI startup in a non-interactive environment is expected; use the dashboard and local APIs there.

## Acknowledgments

Mini-EDR leans heavily on upstream open-source building blocks and the wider Linux observability ecosystem:

- **Aya** for Rust-native eBPF and CO-RE program loading.
- **Tokio** for the daemon runtime, channels, and signal/task orchestration.
- **Axum** and **hyper** for localhost HTTP, WebSocket, and SSE surfaces.
- **Ratatui**, **crossterm**, and **tuistory** for the terminal operator experience and PTY validation.
- **serde**, **serde_json**, and **toml** for the schema/config contract.
- **tracing** and **tracing-subscriber** for structured operational logging.
- **Criterion**, **cargo-nextest**, **cargo-deny**, and **cargo-audit** for performance and supply-chain validation.
- **ONNX Runtime (`ort`)**, **XGBoost**, **onnxmltools**, and the Python scientific stack for the detection pipeline.
- **Docker**, **QEMU**, **Vagrant**, and the Linux BTF/tracefs toolchain for the privileged integration and portability work.

## 215-assertion coverage matrix

The matrix below intentionally lists **all 215 validation-contract assertions**, their current status, the milestone that last promoted them (when present), their unique owning feature, and stable file:line references into the contract, feature map, and validation-state snapshot.

### Sensor

| Assertion ID | Status | Validated in | Feature owner | Validation trace refs |
| --- | --- | --- | --- | --- |
| `VAL-SENSOR-001` | `passed` | `sensor` | `f2-bpf-programs` | `validation-contract.md:46` · `features.json:524` · `validation-state.json:3` |
| `VAL-SENSOR-002` | `passed` | `sensor` | `f2-bpf-programs` | `validation-contract.md:57` · `features.json:525` · `validation-state.json:8` |
| `VAL-SENSOR-003` | `passed` | `sensor` | `f2-bpf-programs` | `validation-contract.md:72` · `features.json:526` · `validation-state.json:13` |
| `VAL-SENSOR-004` | `passed` | `sensor` | `f2-bpf-programs` | `validation-contract.md:85` · `features.json:527` · `validation-state.json:18` |
| `VAL-SENSOR-005` | `passed` | `sensor` | `f2-bpf-programs` | `validation-contract.md:97` · `features.json:528` · `validation-state.json:23` |
| `VAL-SENSOR-006` | `passed` | `sensor` | `f2-bpf-programs` | `validation-contract.md:107` · `features.json:474` · `validation-state.json:28` |
| `VAL-SENSOR-007` | `passed` | `sensor` | `f2-ringbuffer-consumer` | `validation-contract.md:118` · `features.json:561` · `validation-state.json:33` |
| `VAL-SENSOR-008` | `passed` | `sensor` | `f2-bpf-programs` | `validation-contract.md:131` · `features.json:530` · `validation-state.json:38` |
| `VAL-SENSOR-009` | `pending` | `—` | `f8-portability-tests` | `validation-contract.md:141` · `features.json:2977` · `validation-state.json:43` |
| `VAL-SENSOR-010` | `pending` | `—` | `f8-daemon-binary` | `validation-contract.md:156` · `features.json:2823` · `validation-state.json:46` |
| `VAL-SENSOR-011` | `pending` | `—` | `f8-daemon-binary` | `validation-contract.md:169` · `features.json:2869` · `validation-state.json:49` |
| `VAL-SENSOR-012` | `pending` | `—` | `f8-daemon-binary` | `validation-contract.md:181` · `features.json:2870` · `validation-state.json:52` |
| `VAL-SENSOR-013` | `passed` | `sensor` | `f2-overflow-and-fault` | `validation-contract.md:191` · `features.json:622` · `validation-state.json:55` |
| `VAL-SENSOR-014` | `passed` | `sensor` | `f2-overflow-and-fault` | `validation-contract.md:204` · `features.json:623` · `validation-state.json:60` |
| `VAL-SENSOR-015` | `passed` | `sensor` | `f2-overflow-and-fault` | `validation-contract.md:215` · `features.json:624` · `validation-state.json:65` |
| `VAL-SENSOR-016` | `passed` | `sensor` | `f2-ringbuffer-consumer` | `validation-contract.md:226` · `features.json:562` · `validation-state.json:70` |
| `VAL-SENSOR-017` | `passed` | `sensor` | `f2-ringbuffer-consumer` | `validation-contract.md:242` · `features.json:563` · `validation-state.json:75` |
| `VAL-SENSOR-018` | `passed` | `sensor` | `f2-fuzz-harness` | `validation-contract.md:253` · `features.json:656` · `validation-state.json:80` |
| `VAL-SENSOR-019` | `passed` | `sensor` | `f2-overflow-and-fault` | `validation-contract.md:282` · `features.json:625` · `validation-state.json:867` |

### Pipeline

| Assertion ID | Status | Validated in | Feature owner | Validation trace refs |
| --- | --- | --- | --- | --- |
| `VAL-PIPELINE-022` | `passed` | `pipeline` | `f3-pipeline-stress` | `validation-contract.md:277` · `features.json:1054` · `validation-state.json:832` |
| `VAL-PIPELINE-001` | `passed` | `sensor` | `f2-ringbuffer-consumer` | `validation-contract.md:289` · `features.json:564` · `validation-state.json:85` |
| `VAL-PIPELINE-002` | `passed` | `pipeline` | `f3-procreader` | `validation-contract.md:302` · `features.json:923` · `validation-state.json:90` |
| `VAL-PIPELINE-003` | `passed` | `pipeline` | `f3-procreader` | `validation-contract.md:318` · `features.json:924` · `validation-state.json:95` |
| `VAL-PIPELINE-004` | `passed` | `pipeline` | `f3-procreader` | `validation-contract.md:337` · `features.json:925` · `validation-state.json:100` |
| `VAL-PIPELINE-005` | `passed` | `pipeline` | `f3-ancestry` | `validation-contract.md:348` · `features.json:958` · `validation-state.json:105` |
| `VAL-PIPELINE-006` | `passed` | `pipeline` | `f3-ancestry` | `validation-contract.md:359` · `features.json:959` · `validation-state.json:110` |
| `VAL-PIPELINE-007` | `passed` | `pipeline` | `f3-ancestry` | `validation-contract.md:369` · `features.json:960` · `validation-state.json:115` |
| `VAL-PIPELINE-008` | `passed` | `pipeline` | `f3-windows-and-features` | `validation-contract.md:381` · `features.json:995` · `validation-state.json:120` |
| `VAL-PIPELINE-009` | `passed` | `pipeline` | `f3-windows-and-features` | `validation-contract.md:394` · `features.json:996` · `validation-state.json:125` |
| `VAL-PIPELINE-010` | `passed` | `pipeline` | `f3-windows-and-features` | `validation-contract.md:407` · `features.json:997` · `validation-state.json:130` |
| `VAL-PIPELINE-011` | `passed` | `pipeline` | `f3-windows-and-features` | `validation-contract.md:417` · `features.json:998` · `validation-state.json:135` |
| `VAL-PIPELINE-012` | `passed` | `pipeline` | `f3-windows-and-features` | `validation-contract.md:431` · `features.json:999` · `validation-state.json:140` |
| `VAL-PIPELINE-013` | `passed` | `pipeline` | `f3-windows-and-features` | `validation-contract.md:443` · `features.json:1000` · `validation-state.json:145` |
| `VAL-PIPELINE-014` | `passed` | `pipeline` | `f3-windows-and-features` | `validation-contract.md:458` · `features.json:1001` · `validation-state.json:150` |
| `VAL-PIPELINE-015` | `passed` | `pipeline` | `f3-windows-and-features` | `validation-contract.md:469` · `features.json:396` · `validation-state.json:155` |
| `VAL-PIPELINE-016` | `passed` | `pipeline` | `f3-dedup` | `validation-contract.md:478` · `features.json:1028` · `validation-state.json:160` |
| `VAL-PIPELINE-017` | `passed` | `pipeline` | `f3-dedup` | `validation-contract.md:490` · `features.json:1029` · `validation-state.json:165` |
| `VAL-PIPELINE-018` | `passed` | `pipeline` | `f3-ancestry` | `validation-contract.md:501` · `features.json:961` · `validation-state.json:170` |
| `VAL-PIPELINE-019` | `passed` | `pipeline` | `f3-ancestry` | `validation-contract.md:514` · `features.json:962` · `validation-state.json:175` |
| `VAL-PIPELINE-020` | `passed` | `pipeline` | `f3-ancestry` | `validation-contract.md:526` · `features.json:963` · `validation-state.json:180` |
| `VAL-PIPELINE-021` | `passed` | `pipeline` | `f3-ancestry` | `validation-contract.md:537` · `features.json:964` · `validation-state.json:185` |
| `VAL-PIPELINE-023` | `passed` | `pipeline` | `f3-procreader` | `validation-contract.md:552` · `features.json:926` · `validation-state.json:872` |
| `VAL-PIPELINE-024` | `passed` | `pipeline` | `f3-procreader` | `validation-contract.md:557` · `features.json:927` · `validation-state.json:877` |
| `VAL-PIPELINE-025` | `passed` | `pipeline` | `f3-procreader` | `validation-contract.md:562` · `features.json:908` · `validation-state.json:882` |
| `VAL-PIPELINE-026` | `passed` | `pipeline` | `f3-windows-and-features` | `validation-contract.md:567` · `features.json:976` · `validation-state.json:910` |

### Detection

| Assertion ID | Status | Validated in | Feature owner | Validation trace refs |
| --- | --- | --- | --- | --- |
| `VAL-DETECT-001` | `pending` | `—` | `f8-daemon-binary` | `validation-contract.md:574` · `features.json:1355` · `validation-state.json:190` |
| `VAL-DETECT-002` | `pending` | `—` | `f8-daemon-binary` | `validation-contract.md:587` · `features.json:2872` · `validation-state.json:193` |
| `VAL-DETECT-003` | `passed` | `detection` | `f4-inference-engine` | `validation-contract.md:602` · `features.json:1355` · `validation-state.json:196` |
| `VAL-DETECT-004` | `passed` | `alerting-api` | `f5-local-api` | `validation-contract.md:616` · `features.json:1697` · `validation-state.json:201` |
| `VAL-DETECT-005` | `passed` | `alerting-api` | `f5-local-api` | `validation-contract.md:628` · `features.json:1788` · `validation-state.json:206` |
| `VAL-DETECT-006` | `passed` | `alerting-api` | `f5-local-api` | `validation-contract.md:640` · `features.json:1788` · `validation-state.json:211` |
| `VAL-DETECT-007` | `passed` | `detection` | `f4-alert-generator` | `validation-contract.md:651` · `features.json:396` · `validation-state.json:216` |
| `VAL-DETECT-008` | `passed` | `detection` | `f4-hot-reload` | `validation-contract.md:678` · `features.json:1444` · `validation-state.json:221` |
| `VAL-DETECT-009` | `passed` | `detection` | `f4-hot-reload` | `validation-contract.md:694` · `features.json:1445` · `validation-state.json:226` |
| `VAL-DETECT-010` | `passed` | `detection` | `f4-hot-reload` | `validation-contract.md:708` · `features.json:1446` · `validation-state.json:231` |
| `VAL-DETECT-011` | `passed` | `alerting-api` | `f5-json-log` | `validation-contract.md:720` · `features.json:1616` · `validation-state.json:236` |
| `VAL-DETECT-012` | `passed` | `alerting-api` | `f5-malicious-fixtures-via-alert-stream` | `validation-contract.md:734` · `features.json:1532` · `validation-state.json:241` |
| `VAL-DETECT-013` | `passed` | `alerting-api` | `f5-malicious-fixtures-via-alert-stream` | `validation-contract.md:749` · `features.json:1829` · `validation-state.json:246` |
| `VAL-DETECT-014` | `pending` | `—` | `f8-daemon-binary` | `validation-contract.md:762` · `features.json:2873` · `validation-state.json:251` |
| `VAL-DETECT-015` | `passed` | `detection` | `f4-ml-training` | `validation-contract.md:777` · `features.json:28` · `validation-state.json:254` |
| `VAL-DETECT-016` | `passed` | `detection` | `f4-alert-generator` | `validation-contract.md:791` · `features.json:1408` · `validation-state.json:259` |
| `VAL-DETECT-017` | `passed` | `alerting-api` | `f5-local-api` | `validation-contract.md:804` · `features.json:1788` · `validation-state.json:264` |
| `VAL-DETECT-018` | `passed` | `system-integration` | `f8-privileged-isolation-tests` | `validation-contract.md:819` · `features.json:1788` · `validation-state.json:847` |
| `VAL-DETECT-019` | `passed` | `detection` | `f4-alert-generator` | `validation-contract.md:825` · `features.json:1385` · `validation-state.json:895` |

### Alerting

| Assertion ID | Status | Validated in | Feature owner | Validation trace refs |
| --- | --- | --- | --- | --- |
| `VAL-ALERT-001` | `passed` | `alerting-api` | `f5-json-log` | `validation-contract.md:832` · `features.json:1739` · `validation-state.json:269` |
| `VAL-ALERT-002` | `passed` | `alerting-api` | `f5-json-log` | `validation-contract.md:844` · `features.json:1740` · `validation-state.json:274` |
| `VAL-ALERT-003` | `passed` | `alerting-api` | `f5-local-api` | `validation-contract.md:855` · `features.json:1807` · `validation-state.json:279` |
| `VAL-ALERT-004` | `passed` | `alerting-api` | `f5-local-api` | `validation-contract.md:869` · `features.json:1808` · `validation-state.json:284` |
| `VAL-ALERT-005` | `passed` | `alerting-api` | `f5-local-api` | `validation-contract.md:883` · `features.json:1809` · `validation-state.json:289` |
| `VAL-ALERT-006` | `passed` | `alerting-api` | `f5-log-rotation` | `validation-contract.md:894` · `features.json:1775` · `validation-state.json:294` |
| `VAL-ALERT-007` | `passed` | `alerting-api` | `f5-log-rotation` | `validation-contract.md:909` · `features.json:1776` · `validation-state.json:299` |
| `VAL-ALERT-008` | `passed` | `alerting-api` | `f5-json-log` | `validation-contract.md:923` · `features.json:1741` · `validation-state.json:304` |
| `VAL-ALERT-009` | `passed` | `alerting-api` | `f5-json-log` | `validation-contract.md:936` · `features.json:1719` · `validation-state.json:309` |
| `VAL-ALERT-010` | `passed` | `alerting-api` | `f5-local-api` | `validation-contract.md:950` · `features.json:1810` · `validation-state.json:314` |
| `VAL-ALERT-011` | `passed` | `alerting-api` | `f5-json-log` | `validation-contract.md:976` · `features.json:1742` · `validation-state.json:319` |
| `VAL-ALERT-012` | `passed` | `alerting-api` | `f5-json-log` | `validation-contract.md:986` · `features.json:1743` · `validation-state.json:324` |
| `VAL-ALERT-013` | `passed` | `alerting-api` | `f5-json-log` | `validation-contract.md:1002` · `features.json:1744` · `validation-state.json:842` |
| `VAL-ALERT-014` | `passed` | `system-integration` | `f8-privileged-isolation-tests` | `validation-contract.md:1007` · `features.json:1866` · `validation-state.json:858` |
| `VAL-ALERT-015` | `passed` | `detection` | `f4-alert-generator` | `validation-contract.md:1012` · `features.json:1410` · `validation-state.json:887` |
| `VAL-ALERT-016` | `passed` | `alerting-api` | `f5-local-api` | `validation-contract.md:1017` · `features.json:1811` · `validation-state.json:930` |

### TUI

| Assertion ID | Status | Validated in | Feature owner | Validation trace refs |
| --- | --- | --- | --- | --- |
| `VAL-TUI-001` | `passed` | `tui` | `f6-tui-app` | `validation-contract.md:1024` · `features.json:2235` · `validation-state.json:329` |
| `VAL-TUI-002` | `passed` | `tui` | `f6-tui-app` | `validation-contract.md:1030` · `features.json:2236` · `validation-state.json:334` |
| `VAL-TUI-003` | `passed` | `tui` | `f6-process-tree-colors` | `validation-contract.md:1036` · `features.json:2269` · `validation-state.json:339` |
| `VAL-TUI-004` | `passed` | `tui` | `f6-process-tree-colors` | `validation-contract.md:1042` · `features.json:2270` · `validation-state.json:344` |
| `VAL-TUI-005` | `passed` | `tui` | `f6-process-tree-colors` | `validation-contract.md:1048` · `features.json:2271` · `validation-state.json:349` |
| `VAL-TUI-006` | `passed` | `tui` | `f6-process-tree-colors` | `validation-contract.md:1054` · `features.json:2272` · `validation-state.json:354` |
| `VAL-TUI-007` | `passed` | `tui` | `f6-process-tree-colors` | `validation-contract.md:1060` · `features.json:2273` · `validation-state.json:359` |
| `VAL-TUI-008` | `passed` | `tui` | `f6-timeline-and-status` | `validation-contract.md:1066` · `features.json:2302` · `validation-state.json:364` |
| `VAL-TUI-009` | `passed` | `tui` | `f6-timeline-and-status` | `validation-contract.md:1072` · `features.json:2303` · `validation-state.json:369` |
| `VAL-TUI-010` | `passed` | `tui` | `f6-tui-app` | `validation-contract.md:1080` · `features.json:2237` · `validation-state.json:374` |
| `VAL-TUI-011` | `passed` | `tui` | `f6-timeline-and-status` | `validation-contract.md:1086` · `features.json:2304` · `validation-state.json:379` |
| `VAL-TUI-012` | `passed` | `tui` | `f6-detail-view-and-keyboard` | `validation-contract.md:1092` · `features.json:2332` · `validation-state.json:384` |
| `VAL-TUI-013` | `passed` | `tui` | `f6-detail-view-and-keyboard` | `validation-contract.md:1098` · `features.json:2333` · `validation-state.json:389` |
| `VAL-TUI-014` | `passed` | `tui` | `f6-detail-view-and-keyboard` | `validation-contract.md:1104` · `features.json:53` · `validation-state.json:394` |
| `VAL-TUI-015` | `passed` | `tui` | `f6-process-tree-colors` | `validation-contract.md:1110` · `features.json:2274` · `validation-state.json:399` |
| `VAL-TUI-016` | `passed` | `tui` | `f6-process-tree-colors` | `validation-contract.md:1116` · `features.json:2275` · `validation-state.json:404` |
| `VAL-TUI-017` | `passed` | `tui` | `f6-tui-app` | `validation-contract.md:1122` · `features.json:2238` · `validation-state.json:409` |

### Web Dashboard

| Assertion ID | Status | Validated in | Feature owner | Validation trace refs |
| --- | --- | --- | --- | --- |
| `VAL-WEB-001` | `passed` | `web` | `f7-web-server` | `validation-contract.md:1131` · `features.json:2515` · `validation-state.json:414` |
| `VAL-WEB-002` | `passed` | `web` | `f7-web-server` | `validation-contract.md:1137` · `features.json:2516` · `validation-state.json:419` |
| `VAL-WEB-003` | `passed` | `web` | `f7-web-server` | `validation-contract.md:1143` · `features.json:2517` · `validation-state.json:424` |
| `VAL-WEB-004` | `passed` | `web` | `f7-web-server` | `validation-contract.md:1149` · `features.json:2518` · `validation-state.json:429` |
| `VAL-WEB-005` | `passed` | `web` | `f7-web-server` | `validation-contract.md:1155` · `features.json:2519` · `validation-state.json:434` |
| `VAL-WEB-006` | `passed` | `web` | `f7-tree-and-detail` | `validation-contract.md:1161` · `features.json:2549` · `validation-state.json:439` |
| `VAL-WEB-007` | `passed` | `web` | `f7-timeline-filters` | `validation-contract.md:1167` · `features.json:2593` · `validation-state.json:444` |
| `VAL-WEB-008` | `passed` | `web` | `f7-timeline-filters` | `validation-contract.md:1173` · `features.json:2594` · `validation-state.json:449` |
| `VAL-WEB-009` | `passed` | `web` | `f7-timeline-filters` | `validation-contract.md:1179` · `features.json:53` · `validation-state.json:454` |
| `VAL-WEB-010` | `passed` | `web` | `f7-timeline-filters` | `validation-contract.md:1185` · `features.json:2596` · `validation-state.json:459` |
| `VAL-WEB-011` | `passed` | `web` | `f7-tree-and-detail` | `validation-contract.md:1191` · `features.json:2550` · `validation-state.json:464` |
| `VAL-WEB-012` | `passed` | `web` | `f7-health-and-degraded` | `validation-contract.md:1197` · `features.json:2628` · `validation-state.json:469` |
| `VAL-WEB-013` | `passed` | `web` | `f7-timeline-filters` | `validation-contract.md:1203` · `features.json:2597` · `validation-state.json:474` |
| `VAL-WEB-014` | `passed` | `web` | `f7-health-and-degraded` | `validation-contract.md:1209` · `features.json:2629` · `validation-state.json:479` |
| `VAL-WEB-015` | `passed` | `web` | `f7-timeline-filters` | `validation-contract.md:1215` · `features.json:2598` · `validation-state.json:484` |
| `VAL-WEB-016` | `passed` | `web` | `f7-tree-and-detail` | `validation-contract.md:1221` · `features.json:2551` · `validation-state.json:489` |
| `VAL-WEB-017` | `passed` | `web` | `f7-tree-and-detail` | `validation-contract.md:1227` · `features.json:2552` · `validation-state.json:494` |
| `VAL-WEB-018` | `passed` | `web` | `f7-timeline-filters` | `validation-contract.md:1234` · `features.json:2599` · `validation-state.json:853` |
| `VAL-WEB-019` | `passed` | `web` | `f7-timeline-filters` | `validation-contract.md:1239` · `features.json:2600` · `validation-state.json:920` |
| `VAL-WEB-020` | `passed` | `web` | `f7-timeline-filters` | `validation-contract.md:1244` · `features.json:2601` · `validation-state.json:925` |

### Daemon Lifecycle

| Assertion ID | Status | Validated in | Feature owner | Validation trace refs |
| --- | --- | --- | --- | --- |
| `VAL-DAEMON-001` | `pending` | `—` | `f8-daemon-binary` | `validation-contract.md:1251` · `features.json:2842` · `validation-state.json:499` |
| `VAL-DAEMON-002` | `pending` | `—` | `f8-daemon-binary` | `validation-contract.md:1263` · `features.json:2843` · `validation-state.json:502` |
| `VAL-DAEMON-003` | `pending` | `—` | `f8-daemon-binary` | `validation-contract.md:1276` · `features.json:2844` · `validation-state.json:505` |
| `VAL-DAEMON-004` | `pending` | `—` | `f8-daemon-binary` | `validation-contract.md:1288` · `features.json:2845` · `validation-state.json:508` |
| `VAL-DAEMON-005` | `pending` | `—` | `f8-daemon-binary` | `validation-contract.md:1302` · `features.json:396` · `validation-state.json:511` |
| `VAL-DAEMON-006` | `pending` | `—` | `f8-daemon-binary` | `validation-contract.md:1319` · `features.json:2846` · `validation-state.json:514` |
| `VAL-DAEMON-007` | `pending` | `—` | `f8-daemon-binary` | `validation-contract.md:1332` · `features.json:2847` · `validation-state.json:517` |
| `VAL-DAEMON-008` | `pending` | `—` | `f8-daemon-binary` | `validation-contract.md:1344` · `features.json:2848` · `validation-state.json:520` |
| `VAL-DAEMON-009` | `pending` | `—` | `f8-daemon-binary` | `validation-contract.md:1356` · `features.json:2823` · `validation-state.json:523` |
| `VAL-DAEMON-010` | `pending` | `—` | `f8-daemon-binary` | `validation-contract.md:1366` · `features.json:2849` · `validation-state.json:526` |
| `VAL-DAEMON-011` | `pending` | `—` | `f8-daemon-binary` | `validation-contract.md:1378` · `features.json:2850` · `validation-state.json:529` |
| `VAL-DAEMON-012` | `pending` | `—` | `f8-daemon-binary` | `validation-contract.md:1390` · `features.json:2851` · `validation-state.json:532` |
| `VAL-DAEMON-013` | `pending` | `—` | `f8-daemon-binary` | `validation-contract.md:1401` · `features.json:2852` · `validation-state.json:535` |
| `VAL-DAEMON-014` | `pending` | `—` | `f8-daemon-binary` | `validation-contract.md:1413` · `features.json:2853` · `validation-state.json:538` |
| `VAL-DAEMON-015` | `pending` | `—` | `f8-daemon-binary` | `validation-contract.md:1427` · `features.json:2854` · `validation-state.json:541` |
| `VAL-DAEMON-016` | `passed` | `detection` | `f4-hot-reload` | `validation-contract.md:1442` · `features.json:1447` · `validation-state.json:837` |
| `VAL-DAEMON-017` | `pending` | `—` | `f8-daemon-binary` | `validation-contract.md:1447` · `features.json:396` · `validation-state.json:892` |
| `VAL-DAEMON-018` | `passed` | `foundation` | `f1-config-and-validation` | `validation-contract.md:1452` · `features.json:294` · `validation-state.json:905` |

### Performance

| Assertion ID | Status | Validated in | Feature owner | Validation trace refs |
| --- | --- | --- | --- | --- |
| `VAL-PERF-001` | `pending` | `—` | `f8-performance-benchmarks` | `validation-contract.md:1459` · `features.json:3039` · `validation-state.json:544` |
| `VAL-PERF-002` | `pending` | `—` | `f8-performance-benchmarks` | `validation-contract.md:1465` · `features.json:3015` · `validation-state.json:547` |
| `VAL-PERF-003` | `pending` | `—` | `f8-performance-benchmarks` | `validation-contract.md:1471` · `features.json:3041` · `validation-state.json:550` |
| `VAL-PERF-004` | `pending` | `—` | `f8-performance-benchmarks` | `validation-contract.md:1477` · `features.json:3042` · `validation-state.json:553` |
| `VAL-PERF-005` | `pending` | `—` | `f8-performance-benchmarks` | `validation-contract.md:1483` · `features.json:3043` · `validation-state.json:556` |
| `VAL-PERF-006` | `pending` | `—` | `f8-performance-benchmarks` | `validation-contract.md:1489` · `features.json:3044` · `validation-state.json:559` |
| `VAL-PERF-007` | `pending` | `—` | `f8-performance-benchmarks` | `validation-contract.md:1495` · `features.json:3045` · `validation-state.json:562` |
| `VAL-PERF-008` | `passed` | `tui` | `f6-tui-app` | `validation-contract.md:1501` · `features.json:2239` · `validation-state.json:565` |
| `VAL-PERF-009` | `passed` | `tui` | `f6-detail-view-and-keyboard` | `validation-contract.md:1507` · `features.json:2335` · `validation-state.json:570` |
| `VAL-PERF-010` | `passed` | `web` | `f7-timeline-filters` | `validation-contract.md:1513` · `features.json:2602` · `validation-state.json:575` |
| `VAL-PERF-011` | `pending` | `—` | `f8-performance-benchmarks` | `validation-contract.md:1519` · `features.json:3046` · `validation-state.json:580` |
| `VAL-PERF-012` | `pending` | `—` | `f8-performance-benchmarks` | `validation-contract.md:1525` · `features.json:3047` · `validation-state.json:583` |
| `VAL-PERF-013` | `pending` | `—` | `f8-performance-benchmarks` | `validation-contract.md:1531` · `features.json:3048` · `validation-state.json:586` |
| `VAL-PERF-014` | `pending` | `—` | `f8-availability-tests` | `validation-contract.md:1538` · `features.json:3083` · `validation-state.json:864` |

### Reliability

| Assertion ID | Status | Validated in | Feature owner | Validation trace refs |
| --- | --- | --- | --- | --- |
| `VAL-REL-001` | `passed` | `sensor` | `f2-overflow-and-fault` | `validation-contract.md:1545` · `features.json:626` · `validation-state.json:589` |
| `VAL-REL-002` | `passed` | `sensor` | `f2-overflow-and-fault` | `validation-contract.md:1551` · `features.json:627` · `validation-state.json:594` |
| `VAL-REL-003` | `passed` | `sensor` | `f2-overflow-and-fault` | `validation-contract.md:1557` · `features.json:628` · `validation-state.json:599` |
| `VAL-REL-004` | `passed` | `pipeline` | `f3-procreader` | `validation-contract.md:1563` · `features.json:929` · `validation-state.json:604` |
| `VAL-REL-005` | `pending` | `—` | `f8-daemon-binary` | `validation-contract.md:1569` · `features.json:1355` · `validation-state.json:609` |
| `VAL-REL-006` | `passed` | `alerting-api` | `f5-malicious-fixtures-via-alert-stream` | `validation-contract.md:1575` · `features.json:1532` · `validation-state.json:612` |
| `VAL-REL-007` | `passed` | `alerting-api` | `f5-malicious-fixtures-via-alert-stream` | `validation-contract.md:1581` · `features.json:1851` · `validation-state.json:617` |
| `VAL-REL-008` | `passed` | `alerting-api` | `f5-malicious-fixtures-via-alert-stream` | `validation-contract.md:1587` · `features.json:1852` · `validation-state.json:622` |
| `VAL-REL-009` | `passed` | `alerting-api` | `f5-malicious-fixtures-via-alert-stream` | `validation-contract.md:1593` · `features.json:1853` · `validation-state.json:627` |
| `VAL-REL-010` | `passed` | `alerting-api` | `f5-malicious-fixtures-via-alert-stream` | `validation-contract.md:1599` · `features.json:1829` · `validation-state.json:632` |
| `VAL-REL-011` | `passed` | `sensor` | `f2-fuzz-harness` | `validation-contract.md:1605` · `features.json:657` · `validation-state.json:637` |
| `VAL-REL-012` | `pending` | `—` | `f8-availability-tests` | `validation-contract.md:1611` · `features.json:3084` · `validation-state.json:642` |

### Availability

| Assertion ID | Status | Validated in | Feature owner | Validation trace refs |
| --- | --- | --- | --- | --- |
| `VAL-AVAIL-001` | `pending` | `—` | `f8-availability-tests` | `validation-contract.md:1620` · `features.json:3079` · `validation-state.json:645` |
| `VAL-AVAIL-002` | `pending` | `—` | `f8-availability-tests` | `validation-contract.md:1626` · `features.json:3080` · `validation-state.json:648` |
| `VAL-AVAIL-003` | `pending` | `—` | `f8-availability-tests` | `validation-contract.md:1632` · `features.json:3081` · `validation-state.json:651` |
| `VAL-AVAIL-004` | `pending` | `—` | `f8-availability-tests` | `validation-contract.md:1638` · `features.json:3082` · `validation-state.json:654` |
| `VAL-AVAIL-005` | `pending` | `—` | `f8-daemon-binary` | `validation-contract.md:1644` · `features.json:2858` · `validation-state.json:657` |
| `VAL-AVAIL-006` | `passed` | `alerting-api` | `f5-json-log` | `validation-contract.md:1650` · `features.json:1745` · `validation-state.json:660` |
| `VAL-AVAIL-007` | `pending` | `—` | `f8-daemon-binary` | `validation-contract.md:1656` · `features.json:2859` · `validation-state.json:665` |

### Security

| Assertion ID | Status | Validated in | Feature owner | Validation trace refs |
| --- | --- | --- | --- | --- |
| `VAL-SEC-001` | `pending` | `—` | `f8-daemon-binary` | `validation-contract.md:1664` · `features.json:2855` · `validation-state.json:668` |
| `VAL-SEC-002` | `pending` | `—` | `f8-daemon-binary` | `validation-contract.md:1674` · `features.json:2856` · `validation-state.json:671` |
| `VAL-SEC-003` | `pending` | `—` | `f8-daemon-binary` | `validation-contract.md:1681` · `features.json:2857` · `validation-state.json:674` |
| `VAL-SEC-004` | `passed` | `alerting-api` | `f5-local-api` | `validation-contract.md:1689` · `features.json:1812` · `validation-state.json:677` |
| `VAL-SEC-005` | `pending` | `—` | `f8-fix-sec-005-second-host-probe` | `validation-contract.md:1700` · `features.json:1796` · `validation-state.json:682` |
| `VAL-SEC-006` | `passed` | `alerting-api` | `f5-json-log` | `validation-contract.md:1712` · `features.json:1746` · `validation-state.json:686` |
| `VAL-SEC-007` | `passed` | `alerting-api` | `f5-json-log` | `validation-contract.md:1721` · `features.json:1747` · `validation-state.json:691` |
| `VAL-SEC-008` | `passed` | `detection` | `f4-alert-generator` | `validation-contract.md:1731` · `features.json:1409` · `validation-state.json:696` |
| `VAL-SEC-009` | `pending` | `—` | `f8-daemon-binary` | `validation-contract.md:1740` · `features.json:2823` · `validation-state.json:701` |
| `VAL-SEC-010` | `pending` | `—` | `f8-daemon-binary` | `validation-contract.md:1749` · `features.json:2823` · `validation-state.json:704` |
| `VAL-SEC-011` | `pending` | `—` | `f8-daemon-binary` | `validation-contract.md:1757` · `features.json:2823` · `validation-state.json:707` |
| `VAL-SEC-012` | `pending` | `—` | `f8-daemon-binary` | `validation-contract.md:1766` · `features.json:2823` · `validation-state.json:710` |
| `VAL-SEC-013` | `pending` | `—` | `f8-daemon-binary` | `validation-contract.md:1774` · `features.json:2823` · `validation-state.json:713` |

### Maintainability

| Assertion ID | Status | Validated in | Feature owner | Validation trace refs |
| --- | --- | --- | --- | --- |
| `VAL-MAINT-001` | `passed` | `foundation` | `f1-workspace-bootstrap` | `validation-contract.md:1789` · `features.json:232` · `validation-state.json:716` |
| `VAL-MAINT-002` | `passed` | `foundation` | `f1-workspace-bootstrap` | `validation-contract.md:1798` · `features.json:233` · `validation-state.json:721` |
| `VAL-MAINT-003` | `passed` | `foundation` | `f1-ci-and-tooling` | `validation-contract.md:1808` · `features.json:326` · `validation-state.json:726` |
| `VAL-MAINT-004` | `passed` | `foundation` | `f1-ci-and-tooling` | `validation-contract.md:1816` · `features.json:327` · `validation-state.json:731` |
| `VAL-MAINT-005` | `passed` | `foundation` | `f1-ci-and-tooling` | `validation-contract.md:1823` · `features.json:328` · `validation-state.json:736` |
| `VAL-MAINT-006` | `passed` | `foundation` | `f1-ci-and-tooling` | `validation-contract.md:1829` · `features.json:329` · `validation-state.json:741` |
| `VAL-MAINT-007` | `passed` | `foundation` | `f1-readme-skeleton` | `validation-contract.md:1835` · `features.json:356` · `validation-state.json:746` |
| `VAL-MAINT-008` | `passed` | `foundation` | `f1-readme-skeleton` | `validation-contract.md:1844` · `features.json:357` · `validation-state.json:751` |
| `VAL-MAINT-009` | `passed` | `foundation` | `f1-readme-skeleton` | `validation-contract.md:1851` · `features.json:358` · `validation-state.json:756` |
| `VAL-MAINT-010` | `passed` | `foundation` | `f1-readme-skeleton` | `validation-contract.md:1859` · `features.json:359` · `validation-state.json:761` |
| `VAL-MAINT-011` | `passed` | `alerting-api` | `f5-json-log` | `validation-contract.md:1870` · `features.json:1748` · `validation-state.json:915` |

### Portability

| Assertion ID | Status | Validated in | Feature owner | Validation trace refs |
| --- | --- | --- | --- | --- |
| `VAL-PORT-001` | `pending` | `—` | `f8-portability-tests` | `validation-contract.md:1877` · `features.json:2995` · `validation-state.json:766` |
| `VAL-PORT-002` | `pending` | `—` | `f8-portability-tests` | `validation-contract.md:1886` · `features.json:2996` · `validation-state.json:769` |
| `VAL-PORT-003` | `pending` | `—` | `f8-portability-tests` | `validation-contract.md:1896` · `features.json:2997` · `validation-state.json:772` |
| `VAL-PORT-004` | `pending` | `—` | `f8-portability-tests` | `validation-contract.md:1905` · `features.json:2998` · `validation-state.json:775` |
| `VAL-PORT-005` | `pending` | `—` | `f8-portability-tests` | `validation-contract.md:1913` · `features.json:2999` · `validation-state.json:778` |
| `VAL-PORT-006` | `pending` | `—` | `f8-dev-environment` | `validation-contract.md:1921` · `features.json:2932` · `validation-state.json:781` |
| `VAL-PORT-007` | `pending` | `—` | `f8-dev-environment` | `validation-contract.md:1929` · `features.json:2933` · `validation-state.json:784` |
| `VAL-PORT-008` | `pending` | `—` | `f8-portability-tests` | `validation-contract.md:1940` · `features.json:2977` · `validation-state.json:787` |
| `VAL-PORT-009` | `pending` | `—` | `f8-portability-tests` | `validation-contract.md:1950` · `features.json:3000` · `validation-state.json:790` |
| `VAL-PORT-010` | `pending` | `—` | `f8-portability-tests` | `validation-contract.md:1958` · `features.json:3001` · `validation-state.json:793` |
| `VAL-PORT-011` | `passed` | `foundation` | `f1-config-and-validation` | `validation-contract.md:1971` · `features.json:295` · `validation-state.json:900` |

### Cross-Area Flows

| Assertion ID | Status | Validated in | Feature owner | Validation trace refs |
| --- | --- | --- | --- | --- |
| `VAL-CROSS-001` | `pending` | `—` | `f8-fix-cross-flow-harness-completeness` | `validation-contract.md:1978` · `features.json:3096` · `validation-state.json:796` |
| `VAL-CROSS-002` | `pending` | `—` | `f8-fix-cross-flow-harness-completeness` | `validation-contract.md:2001` · `features.json:3096` · `validation-state.json:799` |
| `VAL-CROSS-003` | `pending` | `—` | `f8-cross-area-flows` | `validation-contract.md:2014` · `features.json:3096` · `validation-state.json:802` |
| `VAL-CROSS-004` | `pending` | `—` | `f8-fix-cross-flow-harness-completeness` | `validation-contract.md:2031` · `features.json:3096` · `validation-state.json:805` |
| `VAL-CROSS-005` | `pending` | `—` | `f8-cross-area-flows` | `validation-contract.md:2045` · `features.json:3096` · `validation-state.json:808` |
| `VAL-CROSS-006` | `pending` | `—` | `f8-fix-cross-flow-harness-completeness` | `validation-contract.md:2059` · `features.json:3096` · `validation-state.json:811` |
| `VAL-CROSS-007` | `pending` | `—` | `f8-fix-cross-flow-schema-and-shape` | `validation-contract.md:2073` · `features.json:3096` · `validation-state.json:814` |
| `VAL-CROSS-008` | `pending` | `—` | `f8-fix-cross-flow-schema-and-shape` | `validation-contract.md:2087` · `features.json:3096` · `validation-state.json:817` |
| `VAL-CROSS-009` | `pending` | `—` | `f8-cross-area-flows` | `validation-contract.md:2100` · `features.json:3096` · `validation-state.json:820` |
| `VAL-CROSS-010` | `pending` | `—` | `f8-fix-cross-flow-harness-completeness` | `validation-contract.md:2114` · `features.json:3096` · `validation-state.json:823` |
| `VAL-CROSS-011` | `pending` | `—` | `f8-fix-cross-flow-harness-completeness` | `validation-contract.md:2127` · `features.json:3096` · `validation-state.json:826` |
| `VAL-CROSS-012` | `pending` | `—` | `f8-fix-cross-flow-schema-and-shape` | `validation-contract.md:2141` · `features.json:130` · `validation-state.json:829` |
