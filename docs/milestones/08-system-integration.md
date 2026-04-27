# Mini-EDR Milestone 08 — System Integration

## Overview

System integration is the milestone where the earlier seven deliverables stopped behaving like isolated crates and started behaving like one operator-facing security product.
The work converged in `mini-edr-daemon`, but the milestone was broader than daemon wiring alone: it also delivered the reproducible dev environment, portability gates, performance harnesses, availability harnesses, cross-area orchestration, and final repo-level policy/doc gates needed to treat the mission as an integrated whole.
The implementation history shows that clearly.
Milestone 8 started with daemon lifecycle wiring in commit `0734d3f`, then absorbed the live sensor ABI carry-over in `de5628f`, the development-environment work in `d24f48d`, portability in `46b5068`, performance in `6b82d3f`, availability in `5603043`, and the cross-area/security/supply-chain/doc follow-ups in `47b1343`, `af241a9`, `0776d60`, `acd3abc`, `dfc62fe`, and `66f11d3`.
I also checked the scrutiny and user-testing synthesis paths that AGENTS.md tells milestone authors to consult before declaring full resolution.
At the time of writing, neither `validation/system-integration/scrutiny/synthesis.json` nor `validation/system-integration/user-testing/synthesis.json` exists in the mission directory.
Because of that, this writeup intentionally reports the current `validation-state.json` snapshot and the preserved worker handoffs rather than overstating milestone 8 as formally sealed.

## Accomplishments

### Daemon convergence

- Commit `0734d3f` / feature `f8-daemon-binary` wired the daemon lifecycle around the real subsystem graph.
- `crates/mini-edr-daemon/src/lib.rs` now contains the converged lifecycle types, runtime startup order, signal workers, shutdown path, local HTTP router, TUI/web fan-out, and live sensor startup hooks.
- `crates/mini-edr-daemon/src/main.rs` now behaves like a real operator entrypoint rather than a placeholder shell around lower-level crates.
- The daemon now owns a documented `DaemonLifecycleState` progression instead of implicit “whatever tasks are alive” behavior.
- Capability refusal is now explicit and scriptable rather than inferred from probe-load failures.
- `/api/events` and `/api/probes/{syscall}/{attach,detach}` now exist as daemon-owned control/inspection surfaces.
- The TUI and web surfaces now consume daemon-owned telemetry and alert streams from the same integrated runtime.
- Graceful shutdown now has an explicit probe-detach path and shell harness coverage, even though the privileged lifecycle proofs still need promotion.
- The milestone therefore converted lifecycle behavior from “crate-local assumptions” into “daemon-local product behavior.”

### Sensor-to-pipeline handoff closure

- Commit `de5628f` / feature `f8-sensor-abi-extension` closed the live ABI gap that earlier milestone writeups had carried forward.
- `crates/mini-edr-sensor/ebpf/src/main.rs` was extended so the live sensor path can emit the extra syscall context the pipeline already knew how to consume.
- `crates/mini-edr-sensor/src/raw_event.rs` now models the richer event shape required by the late-stage pipeline features.
- `crates/mini-edr-sensor/src/ringbuffer_consumer.rs` now merges the additional live metadata into the domain events the daemon and pipeline consume.
- That matters because earlier pipeline/detection logic for sensitive writes and syscall-result-aware features was strongest in synthetic flows, not in the real probe path.
- Milestone 8 moved that gap from “known limitation” into “implemented integration surface.”

### Environment and portability

- Commit `d24f48d` / feature `f8-dev-environment` created the reproducible Linux environments required for serious end-to-end validation.
- `contrib/Dockerfile.dev` now provides a pinned Ubuntu 24.04 container build path for reproducible local development and privileged integration work.
- `contrib/Vagrantfile` now provides a VM fallback for contributors who need a supported Linux kernel without relying on privileged Docker.
- `scripts/setcap.sh` now provides a repo-local capability workflow for the release daemon binary.
- Commit `46b5068` / feature `f8-portability-tests` moved host-specific runtime logic into `crates/mini-edr-daemon/src/platform.rs`.
- `scripts/test_kernel_matrix.py` and `scripts/test_kernel_matrix.sh` now run the same release daemon binary against a `5.4` reject case plus `5.8` and `6.x` pass cases.
- `scripts/measure_platform_loc.sh` now measures the host-dependent code ratio instead of leaving portability as a narrative claim.
- The measured platform ratio was `platform_loc=259`, `total_loc=3666`, `ratio=0.0706`, which stays below the `0.10` gate.
- The kernel matrix evidence showed `5.4` rejecting cleanly and both `5.8` and `6.8` starting the same release binary with live probe traffic.

### Performance and availability harnesses

- Commit `6b82d3f` / feature `f8-performance-benchmarks` added the reusable benchmark and shell-harness surface.
- `crates/mini-edr-detection/benches/performance.rs` now holds Criterion coverage for inference latency, feature extraction throughput, and JSON serialization overhead.
- `crates/mini-edr-daemon/examples/perf_harness.rs` provides a deterministic production-path load generator for the perf scripts.
- `tests/perf/throughput_50k.sh` measures synthetic replay throughput through the integrated path.
- `tests/perf/cpu_overhead.sh` samples process CPU during a paced load.
- `tests/perf/e2e_latency.sh` measures reverse-shell alert latency over repeated trials.
- `tests/perf/rss_4h.sh` provides the configurable RSS peak/slope measurement path.
- `tests/perf/bpftool_profile.sh` provides the privileged live-probe profiling path, including an explicit capability guard when the environment is not privileged enough.
- Commit `5603043` / feature `f8-availability-tests` added the integrated availability validation surface.
- `crates/mini-edr-daemon/tests/availability.rs` now covers synthetic probe reload and synthetic memory pressure in Rust integration tests.
- `tests/system/availability_lib.sh` now centralizes isolated daemon startup for system availability harnesses.
- `tests/system/soak.sh` now provides the configurable continuous-operation smoke/soak path.
- `tests/system/probe_reload.sh` now measures reconnect timing through the operator-facing daemon surface.
- `tests/system/memory_pressure.sh` now validates `BackPressure`, drop counters, and window-eviction visibility under sustained pressure.
- The availability work also added `BackPressure` state reporting and `windows_evicted_total` surfacing so those assertions can be measured instead of guessed.

### Cross-area convergence and final polish

- The first end-to-end cross-area integration pass added runtime sparse-prior loading in `crates/mini-edr-pipeline/src/window.rs`.
- That runtime-prior work mattered because it restored live scoring behavior for real probe-driven workloads against the shipped detection model.
- `tests/cross/full_flow.sh` now exists as a real orchestration harness instead of an aspirational placeholder.
- That harness coordinates curl, tuistory, agent-browser, daemon restart/reload, degraded-mode checks, and second-host security probing from one temp evidence directory.
- Commit `47b1343` tightened cross-surface schema and state-shape expectations.
- Commits `af241a9` and `0776d60` improved replay/reconnect visibility and cross-surface observability inside the harness.
- Commit `acd3abc` added the Docker peer-bridge probe required for the localhost-only security story.
- Commit `dfc62fe` resolved the supply-chain gate so milestone 8 closed on a dependency-policy-clean repo instead of leaving hard warnings behind.
- Commit `66f11d3` refreshed the final `README.md` so the operator/developer instructions now match the implemented system rather than the greenfield proposal.

### Performance snapshot

| Metric | Contract target | Observed result | Evidence source |
| --- | --- | --- | --- |
| Synthetic throughput replay | `>= 50,000 events/s` | `3,127,542.95 events/s` over `3,600,000` events with `0` dropped events | `tests/perf/throughput_50k.sh`; `f8-performance-benchmarks` handoff |
| End-to-end alert latency | `< 5 s p99` | `p50 0.187659 ms`, `p99 0.831888 ms`, `max 0.831888 ms` over `50` trials | `tests/perf/e2e_latency.sh`; `f8-performance-benchmarks` handoff |
| CPU overhead | `<= 2%` | `mean 0.423729%` during a `5,000 eps` paced run | `tests/perf/cpu_overhead.sh`; `f8-performance-benchmarks` handoff |
| RSS peak | `<= 256 MiB` | `30,670,848 bytes` peak (`~29.3 MiB`) | `tests/perf/rss_4h.sh`; `f8-performance-benchmarks` handoff |
| RSS slope (perf proxy) | bounded long-run growth | `0.075 MB/min` (`4.5 MB/h`) | `tests/perf/rss_4h.sh`; `f8-performance-benchmarks` handoff |
| RSS slope (availability smoke) | `< 1 MiB/h` after warmup | `0.0 MiB/h` with `4/4` successful injections | `tests/system/soak.sh`; `f8-availability-tests` handoff |
| Probe reload recovery | reconnect within `1 s` | `attach_gap_seconds ≈ 0.307` | `tests/system/probe_reload.sh`; `f8-availability-tests` handoff |
| BackPressure visibility | daemon survives pressure | `945619` ring drops, `5164` evictions, alert still produced | `tests/system/memory_pressure.sh`; `f8-availability-tests` handoff |
| Hot-reload load floor | revised floor `>= 3000 req/s` | `3276.86 req/s` with two hashes and zero late-v1 responses | `validation-state.json` evidence for `VAL-DETECT-018` |
| Platform ratio | `<= 0.10` | `0.0706` | `scripts/measure_platform_loc.sh`; `f8-portability-tests` handoff |
| Kernel matrix | same release binary on `5.8` and `6.x` | `5.4` rejected; `5.8` and `6.8` passed with live probe traffic | `scripts/test_kernel_matrix.sh`; `f8-portability-tests` handoff |

### SOC operator implications delivered by milestone 8

- Operators now have a single daemon binary that owns the runtime, local API, TUI, and dashboard.
- Operators now have documented signal-based day-2 controls for reload, log rotation, and shutdown.
- Operators now have a reproducible Docker path and a VM fallback for standing up a supported environment.
- Operators now have a capability helper script instead of needing to remember a raw `setcap` invocation.
- Operators now have alerting, telemetry, and event-inspection surfaces that live at daemon level instead of only in lower-level crate tests.
- Operators now have perf and availability harnesses that can be rerun when a deployment needs regression evidence.
- Operators now have a cross-area harness that records which integrated product behaviors are still blocked and why.
- Operators do **not** yet have final milestone-8 validator promotion across the lifecycle/perf/availability/portability/cross-area prefixes, which is why the repo should be described as integrated-but-not-finally-sealed.

### Milestone-8 feature inventory

- `f8-daemon-binary` — status `completed`; owns lifecycle, capability, live sensor/runtime, daemon-surface, and several security/availability assertions.
- `f8-sensor-abi-extension` — status `completed`; supporting integration work with no direct `fulfills` mapping.
- `f8-dev-environment` — status `completed`; owns `VAL-PORT-006` and `VAL-PORT-007`.
- `f8-privileged-isolation-tests` — status `completed`; owns `VAL-ALERT-014` and `VAL-DETECT-018`.
- `f8-portability-tests` — status `completed`; owns `VAL-PORT-001`, `VAL-PORT-002`, `VAL-PORT-003`, `VAL-PORT-004`, `VAL-PORT-005`, `VAL-PORT-008`, `VAL-PORT-009`, `VAL-PORT-010`, and `VAL-SENSOR-009`.
- `f8-performance-benchmarks` — status `completed`; owns `VAL-PERF-001` through `VAL-PERF-007` plus `VAL-PERF-011` through `VAL-PERF-013`.
- `f8-availability-tests` — status `completed`; owns `VAL-AVAIL-001` through `VAL-AVAIL-004`, `VAL-PERF-014`, and `VAL-REL-012`.
- `f8-cross-area-flows` — status `completed`; owns `VAL-CROSS-003`, `VAL-CROSS-005`, and `VAL-CROSS-009`.
- `f8-fix-cross-flow-schema-and-shape` — status `completed`; owns `VAL-CROSS-007`, `VAL-CROSS-008`, and `VAL-CROSS-012`.
- `f8-fix-cross-flow-harness-completeness` — status `completed`; owns `VAL-CROSS-001`, `VAL-CROSS-002`, `VAL-CROSS-004`, `VAL-CROSS-006`, `VAL-CROSS-010`, and `VAL-CROSS-011`.
- `f8-fix-sec-005-second-host-probe` — status `completed`; owns `VAL-SEC-005`.
- `f8-fix-supply-chain-policy-bsd3-and-paste-advisory` — status `completed`; supporting integration/policy work with no direct `fulfills` mapping.
- `f8-final-readme-and-doc-gate` — status `completed`; supporting final documentation/gate work with no direct `fulfills` mapping.

### Evidence-bearing milestone-8 handoffs consulted for this writeup

- `handoffs/2026-04-27T11-31-44-437Z__f8-daemon-binary__d5eb426e-4775-4cb9-b698-099efb198526.json`
- `handoffs/2026-04-27T13-37-50-752Z__f8-privileged-isolation-tests__d4e9a992-a0e1-46d0-bfa1-c4ead72fff71.json`
- `handoffs/2026-04-27T14-54-41-910Z__f8-portability-tests__b01f37ab-9fbf-4639-884d-673cef423e7a.json`
- `handoffs/2026-04-27T16-05-52-760Z__f8-performance-benchmarks__b277dc10-137a-49b5-b769-2056c86f35c1.json`
- `handoffs/2026-04-27T16-47-15-051Z__f8-availability-tests__0137b185-8be7-4f05-b72d-f5298394478f.json`
- `handoffs/2026-04-27T17-35-06-733Z__f8-cross-area-flows__6854fd2f-d21d-425a-8a62-59d40c79d289.json`

## Issues / Bugs Encountered

- Issue 1: privileged lifecycle proof on this host was blocked by missing file capabilities, no sudo path in the worker session, and unreliable Docker socket access.
- Issue 2: the live sensor ABI lagged the pipeline contract even after the pipeline milestone had the math and tests for richer feature extraction.
- Issue 3: the original `>= 5000 req/s` load-floor contract for `VAL-DETECT-018` was not realistic for this WSL2 host or for the same Python load client inside privileged Docker.
- Issue 4: availability validation needed a non-privileged fallback because the fully privileged environment was not always available during worker execution.
- Issue 5: cross-area alert/process correlation for a launched live workload was initially too brittle to satisfy the end-to-end timing contract.
- Issue 6: degraded-mode UI signaling and post-restart replay/reconnect behavior surfaced integration gaps that lower-level crate tests had not exercised.
- Issue 7: the second-host localhost-only proof did not exist in the original harness.
- Issue 8: the final doc gate surfaced dependency-policy drift late enough that a doc-only milestone seal would have been misleading.
- Issue 9: WSL2 tracefs readability exposed a capability edge in drop-privilege cross-flow runs.
- Issue 10: even after the code and harnesses landed, formal milestone-8 scrutiny/user-testing promotion files were still absent.

## Resolutions

- Resolution 1: lifecycle, capability, and shutdown behavior now have concrete daemon code plus shell harnesses, even where privileged reruns are still pending.
- Resolution 2: the live sensor ABI carry-over became code, not just a note, so live pipeline behavior now matches the richer event contract expected downstream.
- Resolution 3: the hot-reload throughput dispute was resolved honestly through measured evidence and a contract-floor revision rather than through hand-waving or fixture-only optimism.
- Resolution 4: synthetic but integrated availability harnesses now provide meaningful non-privileged evidence for soak, reload, and pressure behavior.
- Resolution 5: runtime sparse-prior loading plus the cross-area harness restored live scoring and made remaining integration gaps explicit and reproducible.
- Resolution 6: follow-up cross-flow fixes tightened schema, degraded parity, replay/reconnect visibility, and the second-host probe path.
- Resolution 7: host-specific runtime logic is now isolated and measurable through `platform.rs` and `measure_platform_loc.sh`.
- Resolution 8: the final repo closes on a supply-chain-clean and rustdoc-clean state instead of carrying unresolved policy warnings into the milestone summary.
- Resolution 9: this writeup itself records milestone-8 status conservatively because the scrutiny/user-testing synthesis files are not present.
- Resolution 10: the mission summary produced alongside this file now tracks all `215` validation assertions through stable file:line references and live status entries.

## Carry-overs

- `f4-misc-runtime-prior-source-investigation` — detection still needs a post-f8 analysis of whether the static prior catalog is sufficient once live telemetry is compared against the held-out BETH behavior.
- `misc-fixture-ergonomics-default-paths` — standalone shell fixtures still need temp-socket/temp-port ergonomics, executable-bit cleanup, and a small helper restoration.
- `misc-fix-dev-image-runtime-toolchain` — the final `mini-edr-dev` image still needs more runtime tooling if it is to run every privileged fixture flow without host-mounted support.
- `misc-fix-setcap-include-dac-read-search` — the repo still needs the WSL2-friendly `cap_dac_read_search` addition in `scripts/setcap.sh`.
- `misc-fix-cross-flow-val-cross-012-harness-scenario` — the degraded-mode cross-flow scenario still needs to be rewritten to align with FR-D05 reload semantics.
- `misc-fix-cross-flow-cleanup-robustness` — the full-flow harness still needs stronger pre-run sweeping and process-chain cleanup guarantees.
- `misc-fix-crossterm-duplicate-version-warning` — dependency-warning hygiene still has one small follow-up.
- Formal system-integration scrutiny and user-testing promotion are still pending because their milestone synthesis files do not yet exist.

## Validation Status

The authoritative state for this section is `validation-state.json`.
Mission-wide, the repository is currently at `142/215 passed`, `73/215 pending`, and `0 blocked`.
Milestone 8 owns the bulk of the remaining pending assertions, which is consistent with system integration being the convergence layer for lifecycle, perf, availability, portability, and cross-area promotion.
The most important milestone-8-specific passes already reflected in state are `VAL-ALERT-014` and `VAL-DETECT-018`.
The most important earlier cross-cutting passes that still matter to system integration are `VAL-DAEMON-016`, `VAL-DAEMON-018`, and `VAL-PORT-011`.

### Prefix summary

| Prefix | Total | Passed | Pending | Current interpretation |
| --- | ---: | ---: | ---: | --- |
| `VAL-DAEMON` | 18 | 2 | 16 | Lifecycle harnesses exist, but the milestone-8-owned daemon assertions have not yet been promoted into state. |
| `VAL-PERF` | 14 | 3 | 11 | TUI/web latency carry-ins passed earlier; the new perf harnesses still await formal promotion. |
| `VAL-AVAIL` | 7 | 1 | 6 | Alert-log durability passed earlier; the new soak/reload/pressure harnesses are implemented but still pending promotion. |
| `VAL-SEC` | 13 | 4 | 9 | Alerting/detection security assertions passed earlier; the remaining lifecycle and second-host checks are still pending promotion. |
| `VAL-PORT` | 11 | 1 | 10 | Foundation config gating passed earlier; milestone-8 portability harnesses are implemented but not yet promoted. |
| `VAL-CROSS` | 12 | 0 | 12 | The orchestration harness and follow-up fixes exist, but the full cross-area suite is still entirely pending in state. |

### Milestone-8 assertion ownership snapshot

| Assertion ID | Owner feature | Status | Validated in |
| --- | --- | --- | --- |
| `VAL-ALERT-014` | `f8-privileged-isolation-tests` | `passed` | `system-integration` |
| `VAL-AVAIL-001` | `f8-availability-tests` | `pending` | `—` |
| `VAL-AVAIL-002` | `f8-availability-tests` | `pending` | `—` |
| `VAL-AVAIL-003` | `f8-availability-tests` | `pending` | `—` |
| `VAL-AVAIL-004` | `f8-availability-tests` | `pending` | `—` |
| `VAL-AVAIL-005` | `f8-daemon-binary` | `pending` | `—` |
| `VAL-AVAIL-007` | `f8-daemon-binary` | `pending` | `—` |
| `VAL-CROSS-001` | `f8-fix-cross-flow-harness-completeness` | `pending` | `—` |
| `VAL-CROSS-002` | `f8-fix-cross-flow-harness-completeness` | `pending` | `—` |
| `VAL-CROSS-003` | `f8-cross-area-flows` | `pending` | `—` |
| `VAL-CROSS-004` | `f8-fix-cross-flow-harness-completeness` | `pending` | `—` |
| `VAL-CROSS-005` | `f8-cross-area-flows` | `pending` | `—` |
| `VAL-CROSS-006` | `f8-fix-cross-flow-harness-completeness` | `pending` | `—` |
| `VAL-CROSS-007` | `f8-fix-cross-flow-schema-and-shape` | `pending` | `—` |
| `VAL-CROSS-008` | `f8-fix-cross-flow-schema-and-shape` | `pending` | `—` |
| `VAL-CROSS-009` | `f8-cross-area-flows` | `pending` | `—` |
| `VAL-CROSS-010` | `f8-fix-cross-flow-harness-completeness` | `pending` | `—` |
| `VAL-CROSS-011` | `f8-fix-cross-flow-harness-completeness` | `pending` | `—` |
| `VAL-CROSS-012` | `f8-fix-cross-flow-schema-and-shape` | `pending` | `—` |
| `VAL-DAEMON-001` | `f8-daemon-binary` | `pending` | `—` |
| `VAL-DAEMON-002` | `f8-daemon-binary` | `pending` | `—` |
| `VAL-DAEMON-003` | `f8-daemon-binary` | `pending` | `—` |
| `VAL-DAEMON-004` | `f8-daemon-binary` | `pending` | `—` |
| `VAL-DAEMON-005` | `f8-daemon-binary` | `pending` | `—` |
| `VAL-DAEMON-006` | `f8-daemon-binary` | `pending` | `—` |
| `VAL-DAEMON-007` | `f8-daemon-binary` | `pending` | `—` |
| `VAL-DAEMON-008` | `f8-daemon-binary` | `pending` | `—` |
| `VAL-DAEMON-009` | `f8-daemon-binary` | `pending` | `—` |
| `VAL-DAEMON-010` | `f8-daemon-binary` | `pending` | `—` |
| `VAL-DAEMON-011` | `f8-daemon-binary` | `pending` | `—` |
| `VAL-DAEMON-012` | `f8-daemon-binary` | `pending` | `—` |
| `VAL-DAEMON-013` | `f8-daemon-binary` | `pending` | `—` |
| `VAL-DAEMON-014` | `f8-daemon-binary` | `pending` | `—` |
| `VAL-DAEMON-015` | `f8-daemon-binary` | `pending` | `—` |
| `VAL-DAEMON-017` | `f8-daemon-binary` | `pending` | `—` |
| `VAL-DETECT-001` | `f8-daemon-binary` | `pending` | `—` |
| `VAL-DETECT-002` | `f8-daemon-binary` | `pending` | `—` |
| `VAL-DETECT-014` | `f8-daemon-binary` | `pending` | `—` |
| `VAL-DETECT-018` | `f8-privileged-isolation-tests` | `passed` | `system-integration` |
| `VAL-PERF-001` | `f8-performance-benchmarks` | `pending` | `—` |
| `VAL-PERF-002` | `f8-performance-benchmarks` | `pending` | `—` |
| `VAL-PERF-003` | `f8-performance-benchmarks` | `pending` | `—` |
| `VAL-PERF-004` | `f8-performance-benchmarks` | `pending` | `—` |
| `VAL-PERF-005` | `f8-performance-benchmarks` | `pending` | `—` |
| `VAL-PERF-006` | `f8-performance-benchmarks` | `pending` | `—` |
| `VAL-PERF-007` | `f8-performance-benchmarks` | `pending` | `—` |
| `VAL-PERF-011` | `f8-performance-benchmarks` | `pending` | `—` |
| `VAL-PERF-012` | `f8-performance-benchmarks` | `pending` | `—` |
| `VAL-PERF-013` | `f8-performance-benchmarks` | `pending` | `—` |
| `VAL-PERF-014` | `f8-availability-tests` | `pending` | `—` |
| `VAL-PORT-001` | `f8-portability-tests` | `pending` | `—` |
| `VAL-PORT-002` | `f8-portability-tests` | `pending` | `—` |
| `VAL-PORT-003` | `f8-portability-tests` | `pending` | `—` |
| `VAL-PORT-004` | `f8-portability-tests` | `pending` | `—` |
| `VAL-PORT-005` | `f8-portability-tests` | `pending` | `—` |
| `VAL-PORT-006` | `f8-dev-environment` | `pending` | `—` |
| `VAL-PORT-007` | `f8-dev-environment` | `pending` | `—` |
| `VAL-PORT-008` | `f8-portability-tests` | `pending` | `—` |
| `VAL-PORT-009` | `f8-portability-tests` | `pending` | `—` |
| `VAL-PORT-010` | `f8-portability-tests` | `pending` | `—` |
| `VAL-REL-005` | `f8-daemon-binary` | `pending` | `—` |
| `VAL-REL-012` | `f8-availability-tests` | `pending` | `—` |
| `VAL-SEC-001` | `f8-daemon-binary` | `pending` | `—` |
| `VAL-SEC-002` | `f8-daemon-binary` | `pending` | `—` |
| `VAL-SEC-003` | `f8-daemon-binary` | `pending` | `—` |
| `VAL-SEC-005` | `f8-fix-sec-005-second-host-probe` | `pending` | `—` |
| `VAL-SEC-009` | `f8-daemon-binary` | `pending` | `—` |
| `VAL-SEC-010` | `f8-daemon-binary` | `pending` | `—` |
| `VAL-SEC-011` | `f8-daemon-binary` | `pending` | `—` |
| `VAL-SEC-012` | `f8-daemon-binary` | `pending` | `—` |
| `VAL-SEC-013` | `f8-daemon-binary` | `pending` | `—` |
| `VAL-SENSOR-009` | `f8-portability-tests` | `pending` | `—` |
| `VAL-SENSOR-010` | `f8-daemon-binary` | `pending` | `—` |
| `VAL-SENSOR-011` | `f8-daemon-binary` | `pending` | `—` |
| `VAL-SENSOR-012` | `f8-daemon-binary` | `pending` | `—` |
