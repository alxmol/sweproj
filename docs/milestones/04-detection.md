# Mini-EDR Milestone 04 — Detection

## Overview

The detection milestone turned the pipeline's `FeatureVector` output into an end-to-end scoring and alerting story.
It added the Python BETH training pipeline, repaired the XGBoost-to-ONNX export path so the deployed artifact is a real tree ensemble, implemented dual Rust inference backends, added the alert generator with `>=` threshold semantics, wired the first daemon-owned `SIGHUP` reload path, and authored controlled malicious/benign fixture suites that exercise the model through a localhost daemon surface.
The milestone is represented primarily by commits `a22ed60`, `7cd572c`, `323ddf7`, `12e0580`, `552726d`, `a3f6296`, and `f5aba8f`.
The implementation stayed within the crate boundaries promised by SDD §8.2: Python training lives under `training/`, reusable inference and alert logic live in `crates/mini-edr-detection/`, and the daemon-facing reload surface lives in `crates/mini-edr-daemon/`.
The resulting trained artifact at `training/output/model.onnx` is now a verified ONNX `TreeEnsembleClassifier` with 50 trees, 512 serialized nodes, and a 35-feature input manifest embedded in metadata.
Current held-out metrics from `training/output/metrics.json` are `F1 = 0.9886919234`, `TPR = 0.9783038511`, and `FPR = 0.0066826594` on the BETH testing split, which comfortably clears the mission gate for `VAL-DETECT-015`.
The controlled fixture harnesses also currently report `40 / 40` malicious detections with mean score `0.9596308469` and `0` benign alerts across `180` modeled hours with max benign score `0.0403108001`.
The milestone deliberately stopped short of the later alert-stream API, final append-only alert log, and full system-integration daemon lifecycle, so the validation contract still records every `VAL-DETECT-*` assertion as pending even though the underlying implementation work is now in place.

## Accomplishments

- Commit `a22ed60` introduced the root-level training pipeline under `training/`.
- `training/train.py` became the canonical `make train` entrypoint for BETH → XGBoost → ONNX.
- `Makefile` now exposes a `train` target that invokes `python -m training.train`.
- `training/feature_engineering.py` documents how raw BETH syscall rows are mapped into synthetic `FeatureVector`-shaped rows.
- `training/schema.py` defines the flattened feature manifest shared between Python training and Rust inference.
- `training/scripts/evaluate_holdout.py` evaluates the deployed ONNX artifact against the labeled BETH testing split.
- `training/scripts/verify_onnx_schema.py` verifies that the ONNX artifact still carries the expected feature metadata and a tree-ensemble node.
- `training/tests/test_schema.py` locks in schema parity between `mini-edr-common::FeatureVector` and the Python trainer.
- `training/tests/test_metrics_gate.py` locks in the `F1 >= 0.90`, `TPR >= 0.95`, and `FPR <= 0.05` gate and also rejects regressions away from a tree-ensemble ONNX graph.
- The trainer inspects all three labeled BETH splits rather than treating the training file in isolation.
- The BETH training CSV currently has `763,144` data rows (`763,145` lines including the header).
- The BETH header shape used by the trainer includes `timestamp`, `processId`, `threadId`, `parentProcessId`, `userId`, `mountNamespace`, `processName`, `hostName`, `eventId`, `eventName`, `stackAddresses`, `argsNum`, `returnValue`, `args`, `sus`, and `evil`.
- `training/feature_engineering.py::load_beth_split()` normalizes the BETH `sus` and `evil` columns into one binary `label`.
- `training/feature_engineering.py::extract_path()` and `extract_flags()` pull the path/flag hints needed for the synthetic `FeatureVector` bridge.
- `training/feature_engineering.py::classify_sensitive_dir()` mirrors the Rust pipeline's `/etc`, `/tmp`, and `/dev` feature flags.
- `training/feature_engineering.py::has_write_intent()` mirrors the Rust `open_flags` write-intent semantics.
- `training/feature_engineering.py::build_corpus_priors()` computes smoothed corpus-wide positive-rate priors.
- Those priors are surfaced through the existing sparse-map namespaces instead of changing the Rust scalar schema.
- The three synthetic prior keys are `bigrams.__process_positive_rate__`, `bigrams.__event_positive_rate__`, and `trigrams.__path_positive_rate__`.
- `training/schema.py::feature_manifest()` currently produces an input width of `35`.
- That width is composed of `32` scalar fields plus `3` sparse prior features.
- `training/feature_engineering.py::rust_feature_vector_fields()` keeps the Python side pinned to the Rust source order rather than duplicating that contract by hand.
- The training pipeline reads the BETH archive in-place from `/home/alexm/mini-edr/beth/archive/`.
- The pipeline writes outputs to `training/output/model.onnx` and `training/output/metrics.json`.
- Current `training/output/metrics.json` records `n_train = 763144`.
- Current `training/output/metrics.json` records `n_validation = 188967`.
- Current `training/output/metrics.json` records `n_test = 188967`.
- Current `training/output/metrics.json` records `feature_count = 35`.
- Current `training/output/metrics.json` records `threshold = 0.5` for held-out evaluation.
- Current `training/output/metrics.json` records `seed = 1337`.
- Current `training/output/metrics.json` records `F1 = 0.9886919234339773`.
- Current `training/output/metrics.json` records `TPR = 0.9783038510664357`.
- Current `training/output/metrics.json` records `FPR = 0.006682659355723098`.
- Current `training/output/metrics.json` records confusion-matrix counts `tp = 167739`, `tn = 17391`, `fp = 117`, and `fn = 3720`.
- The selected hyperparameters are `n_estimators = 50`, `max_depth = 3`, `learning_rate = 0.05`, `subsample = 1.0`, `colsample_bytree = 1.0`, `reg_lambda = 1.0`, `random_state = 1337`, `scale_pos_weight = 462.31435523114357`, and `n_jobs = 8`.
- `training/train.py::tune_hyperparameters()` performs the required grid search across `{50,100,200}` estimators, `{3,5,7}` depths, and `{0.05,0.1,0.3}` learning rates.
- The tuning policy prefers candidates that meet the `TPR >= 0.95` floor before ranking on `F1`, then `FPR`, then model complexity.
- The training job intentionally caps XGBoost worker threads at `8` so one grid search does not monopolize the shared mission host.
- Commit `7cd572c` fixed the earlier hand-crafted-graph detour and restored a real ONNX tree export.
- `training/requirements.txt` now documents the exact ONNX/XGBoost version pin that works in this environment.
- The pinned stack is `xgboost==2.1.3`.
- The pinned stack is `onnx==1.17.0`.
- The pinned stack is `onnxmltools==1.16.0`.
- The pinned stack is `onnxconverter-common==1.16.0`.
- The pinned stack is `onnxruntime==1.20.1`.
- The pinned stack is `skl2onnx==1.17.0`.
- `training/train.py::export_onnx_model()` now uses `onnxmltools.convert_xgboost()` with `target_opset = 15`.
- `training/train.py::annotate_onnx_metadata()` stamps the ONNX file with the serialized flattened feature manifest.
- `training/scripts/verify_onnx_schema.py` confirms the metadata key `mini_edr_feature_names` is present.
- `training/scripts/verify_onnx_schema.py` confirms the ONNX graph contains a `TreeEnsembleClassifier` or `TreeEnsembleRegressor` node.
- The current verification output reports `ensemble_op_type = TreeEnsembleClassifier`.
- The current verification output reports `input_width = 35`.
- The current verification output reports `tree_count = 50`.
- The current verification output reports `node_count = 512`.
- That verification step matters because it prevents the project from silently shipping a pretty-but-noncanonical ONNX wrapper graph.
- Commit `323ddf7` implemented the reusable detection backends in `crates/mini-edr-detection/`.
- `crates/mini-edr-detection/src/model.rs` defines the `InferenceModel` trait.
- `InferenceModel::predict()` returns `InferenceResult { threat_score, feature_importances, model_hash }`.
- `crates/mini-edr-detection/src/model.rs::OnnxModel` is the canonical deployment backend.
- `OnnxModel` uses `ort::Session` so the daemon loads the exact ONNX artifact produced by the trainer.
- `OnnxModel::predict()` treats the ONNX Runtime probability tensor as the source of truth for the final score.
- `OnnxModel::predict()` clamps the output into the inclusive `[0.0, 1.0]` contract.
- `crates/mini-edr-detection/src/model.rs::XgboostModel` provides the second backend required by the milestone.
- `XgboostModel` does not depend on a separate native `libxgboost` runtime.
- Instead, `XgboostModel` loads the exported ONNX tree ensemble through `TreeEnsembleModel`.
- `crates/mini-edr-detection/src/tree_ensemble.rs` parses the ONNX protobuf directly.
- `TreeEnsembleModel::load()` validates the feature manifest, opset, input shape, probability output shape, and tree-node attributes.
- `TreeEnsembleModel::predict()` walks the trees deterministically and derives per-feature contribution reports from the visited path features.
- `tree_ensemble.rs` computes a SHA-256 model hash from the serialized ONNX bytes.
- `tree_ensemble.rs` also exposes the ONNX probability output tensor name so the ONNX and pure-Rust backends can align on the same artifact contract.
- `TreeEnsembleModel::predict_encoded()` accumulates tree path contributions in a sorted `BTreeMap`.
- That deterministic contribution accumulation is what lets `AlertGenerator` later explain why a score crossed threshold.
- `crates/mini-edr-detection/src/manager.rs` adds `ModelManager`, `PreparedModel`, `ModelBackend`, and `ModelStatus`.
- `ModelManager::load_at_startup()` enters degraded pass-through mode instead of panicking when a model cannot be loaded.
- `ModelManager::prepare_candidate()` validates reload artifacts before the daemon mutates any live state.
- `ModelManager::swap_prepared()` performs the constant-time pointer swap after validation succeeds.
- `ModelManager::predict()` clones the active `Arc<dyn InferenceModel>` and drops the lock before scoring.
- That `clone -> drop lock -> predict` pattern is the core atomicity invariant for hot reload.
- The detection crate also introduced `LoadFailureKind` and richer model-load error reporting so the daemon can distinguish missing paths, malformed ONNX, unsupported opsets, and tensor-shape mismatches.
- Commit `12e0580` implemented the alert generator in `crates/mini-edr-detection/src/alert_generator.rs`.
- `AlertGenerator::new()` validates threshold bounds and restores the persisted alert-ID high-water mark.
- `AlertGenerator::publish()` logs every inference result at debug level whether or not it produced an alert.
- `AlertGenerator::publish()` enforces the project-wide `score >= threshold` contract.
- `AlertGenerator::build_alert()` fills the required `Alert` schema fields from `mini-edr-common`.
- The alert generator chooses a persisted monotonic `u64` sequence file instead of UUIDv7.
- `AlertIdSequence::load()` reads the last issued ID from disk when the daemon starts.
- `AlertIdSequence::next_id()` increments the sequence, writes a temp file with mode `0600`, and atomically renames it into place.
- `alert_generator.rs::normalize_top_features()` sorts features by absolute contribution magnitude.
- `normalize_top_features()` pads the output to exactly five entries if the contribution report is shorter.
- `alert_generator.rs::build_summary()` produces the operator-facing human summary string.
- `alert_generator.rs::sanitize_string()` redacts kernel-pointer-like values and strips raw embedded newlines from strings before they enter alert payloads.
- That sanitization protects both JSON logs and later UI surfaces from invalid or unsafe text content.
- Commit `552726d` implemented the first daemon-owned reload path in `crates/mini-edr-daemon/`.
- `crates/mini-edr-daemon/src/lib.rs` defines `HotReloadDaemon`.
- `HotReloadDaemon::predict()` snapshots the current threshold before dispatching blocking inference work.
- That threshold snapshot ensures in-flight predictions keep their v1 threshold/model pairing even if a later `SIGHUP` swaps in v2.
- `HotReloadDaemon::reload_once()` exposes one explicit reload attempt.
- `HotReloadDaemon::reload_until_stable()` retries through transient partial-config states until the writer finishes or the retry budget is exhausted.
- `HotReloadDaemon::health_snapshot()` surfaces reload-related observability fields such as state history, model hash, config hash, and reload counters.
- `HotReloadDaemon::reload_once_internal()` validates the new threshold and model before the daemon appends a `Reloading` transition.
- `HotReloadDaemon::read_reload_document()` treats missing or mid-write config files as transient partials instead of fatal conditions.
- `HotReloadDaemon::resolve_reload_threshold()` rejects out-of-range thresholds before any model work starts.
- `HotReloadDaemon::prepare_reload_candidate()` preserves the existing model when the new artifact is missing or malformed.
- `HotReloadDaemon::record_transient_partial()` increments `config_reload_partial_total` for observability.
- `crates/mini-edr-daemon/tests/hot_reload.rs` exercises valid swap, invalid-model rollback, invalid-threshold rollback, and partial-config-write retry behavior.
- The reload implementation also serves a minimal localhost HTTP surface for `/api/health` and `/internal/predict`.
- That surface is intentionally narrow, but it gave the fixture suites a stable contract before the alert-stream API exists.
- Commit `a3f6296` added the controlled malicious and benign fixture suites.
- Malicious fixtures live in `tests/fixtures/malware/`.
- Benign fixtures live in `tests/fixtures/benign/`.
- Shared harness helpers live in `tests/fixtures/fixture_runtime_lib.sh`.
- Shared reload/daemon helpers live in `tests/fixtures/hot_reload_lib.sh`.
- `tests/fixtures/malware/reverse_shell.sh` simulates a reverse shell by opening a loopback-only listener and sending a tiny `/bin/sh` transcript across it.
- `tests/fixtures/malware/privesc_setuid.sh` simulates privilege escalation by creating a harmless temp helper and setting the setuid bit on that temp file.
- `tests/fixtures/malware/cryptominer_emulator.sh` simulates a miner with a short CPU-heavy hashing burst and scratch-file writes under `/tmp`.
- `tests/fixtures/malware/port_scan.sh` simulates a scan by binding loopback-only listeners and walking a short localhost port range.
- `tests/fixtures/benign/kernel_compile.sh` represents a controlled benign compute/build workload.
- `tests/fixtures/benign/nginx_serving.sh` represents a controlled benign serving/network workload.
- `tests/fixtures/benign/idle_desktop.sh` represents a controlled low-activity baseline.
- `tests/fixtures/malware/run_all.sh` runs every malicious fixture ten times and summarizes detections and score statistics.
- `tests/fixtures/benign/run_all.sh` runs every benign fixture ten times and converts those trials into modeled alert-per-hour summaries.
- The current malware summary reports `40` detections from `40` trials for a `1.0` detection rate.
- The current malware summary reports mean malicious score `0.9596308469772339`.
- The current malware summary reports minimum malicious score `0.9596308469772339`.
- The current benign summary reports `0` alerts across `30` trials and `180` modeled hours.
- The current benign summary reports mean benign score `0.040310800075531006`.
- The current benign summary reports maximum benign score `0.040310800075531006`.
- The fixture harnesses currently drive the daemon through `/internal/predict`.
- Each fixture result record includes `fixture`, `category`, `trial`, `pid`, `score`, `would_alert`, `alert_count`, and `model_hash`.
- The fixture suites therefore already record which model hash served each simulated workload.
- Commit `f5aba8f` then stabilized the ONNX dependency policy so the detection milestone would no longer drag known audit/deny noise forward.
- `deny.toml` and the training/runtime dependency policy now explicitly document the remaining allowed build-time outliers introduced by `ort-sys`.
- That stabilization matters because the detection milestone is where ONNX dependency complexity first becomes operational, not just theoretical.
- A current in-memory retrain using the saved hyperparameters shows that feature importance is dominated by `bigrams.__process_positive_rate__`.
- The current top-10 importance report assigns `0.9031115770` importance to `bigrams.__process_positive_rate__`.
- The current top-10 importance report assigns `0.0570838861` importance to `pid`.
- The current top-10 importance report assigns `0.0302983541` importance to `window_start_ns`.
- The current top-10 importance report assigns `0.0095062219` importance to `window_end_ns`.
- The remaining inspected top-ten features in that report are effectively `0.0`.
- That importance profile is a real output of the current model, not speculation.
- It also explains why the milestone ended with a follow-up investigation feature for runtime prior sources and live-telemetry parity.

## Issues / Bugs Encountered

- Issue 1: The first XGBoost export path did not yield a real ONNX tree ensemble.
- Issue 2: `onnxmltools 1.13.0` paired with `onnx 1.17.0` hit a boolean-attribute serialization failure during tree conversion.
- Issue 3: The initial workaround produced a hand-crafted graph that was unacceptable as the final deployment artifact.
- Issue 4: The BETH archive is a labeled syscall-row corpus, not a live process-window `FeatureVector` corpus.
- Issue 5: Bridging that shape mismatch without mutating the Rust schema required synthetic feature engineering.
- Issue 6: The BETH train/validation/test splits are strongly process-family shifted.
- Issue 7: That process-family shift caused corpus priors to dominate the trained model's importance ranking.
- Issue 8: The current top-importance ranking gives `bigrams.__process_positive_rate__` far more weight than any event-local feature.
- Issue 9: `pid`, `window_start_ns`, and `window_end_ns` also showed non-trivial importance, which suggests single-row synthetic windows can leak corpus-order and identity information.
- Issue 10: The project needed a canonical deployment artifact for Rust inference and hot reload, not just a Python-only training result.
- Issue 11: The milestone brief still required an `XgboostModel` path even though shipping a second native model runtime would complicate deployment.
- Issue 12: Explaining alerts required deterministic top-feature contributions, but ONNX Runtime does not hand back a ready-made explanation vector for tree paths.
- Issue 13: Invalid ONNX files, unsupported opsets, and malformed tensor shapes had to be rejected without crashing the daemon.
- Issue 14: The daemon needed to degrade cleanly on startup model-load failure instead of refusing to boot outright.
- Issue 15: The `score >= threshold` boundary needed to be locked in at both the alerting path and the reload path.
- Issue 16: Alert IDs had to be monotonic across restart, which forced a concrete choice between UUIDv7 and a persisted sequence.
- Issue 17: The reload path exposed a classic partial-write race: `SIGHUP` can land while the config file is only half-written.
- Issue 18: Another reload race was semantic rather than syntactic: a bad threshold or bad model must not perturb in-flight predictions or append fake state-history transitions.
- Issue 19: Missing model files after startup needed a different log/event story from malformed but present model files.
- Issue 20: The fixture suites had to simulate malicious behavior without contacting external hosts, escalating real privileges, or leaving unsafe residue on disk.
- Issue 21: The alert-stream API does not exist yet, so the detection milestone could not validate against the final API surface.
- Issue 22: That missing alert-stream surface meant the fixtures had to use `/internal/predict` and `would_alert` as a temporary proxy.
- Issue 23: ONNX-related dependencies introduced supply-chain noise that had to be either replaced or explicitly documented.
- Issue 24: The validation contract still shows every `VAL-DETECT-*` assertion as pending, so the writeup cannot honestly claim milestone-level validator closure yet.

## Resolutions

- Resolution 1: Commit `7cd572c` replaced the unacceptable hand-crafted ONNX graph path with a real converter-backed tree-ensemble export.
- Resolution 2: `training/requirements.txt` now documents the exact converter/version combination that works in this repository.
- Resolution 3: `training/train.py::export_onnx_model()` now produces a true ONNX `TreeEnsembleClassifier`.
- Resolution 4: `training/scripts/verify_onnx_schema.py` proves the artifact still contains a tree-ensemble node and the expected manifest width.
- Resolution 5: The deployed ONNX artifact is now verified as `50` trees and `512` nodes instead of an opaque wrapper graph.
- Resolution 6: `training/feature_engineering.py` creates synthetic single-row `FeatureVector` payloads so the training pipeline can use the existing Rust schema without inventing a second one.
- Resolution 7: Corpus-level prior features were routed through the existing `bigrams` and `trigrams` namespaces instead of adding new Rust scalar fields.
- Resolution 8: `training/tests/test_schema.py` keeps the Python feature order pinned to `mini-edr-common`.
- Resolution 9: `training/tests/test_metrics_gate.py` now rejects regressions away from a tree ensemble and reasserts the mission metric floor.
- Resolution 10: The project chose ONNX as the canonical deployment artifact because it decouples Python training from Rust runtime scoring and gives `SIGHUP` a single portable file format to hot-swap.
- Resolution 11: The project chose not to embed a second native `libxgboost` runtime because that would add another C++ dependency surface, another artifact contract, and another reload path to audit.
- Resolution 12: The project still satisfied the “native XGBoost-style backend” requirement by implementing `XgboostModel` as a pure-Rust evaluator over the exported ONNX tree ensemble.
- Resolution 13: That pure-Rust evaluator gives the project deterministic per-path feature contributions without diverging from the deployed artifact.
- Resolution 14: `OnnxModel` remains the authoritative deployment path for score calculation, while `XgboostModel` provides parity checks and explanations.
- Resolution 15: `ModelManager::prepare_candidate()` and `swap_prepared()` separate validation from publication so reloads are atomic.
- Resolution 16: `ModelManager::predict()` clones the active model `Arc` before inference, which lets in-flight requests finish on v1 even when v2 is already live for new callers.
- Resolution 17: `HotReloadDaemon::predict()` snapshots the threshold before `spawn_blocking`, preserving model/threshold pairing during races.
- Resolution 18: `HotReloadDaemon::read_reload_document()` treats mid-write files as transient partials rather than fatal errors.
- Resolution 19: `HotReloadDaemon::reload_until_stable()` retries partial config writes until the writer closes the file or the retry budget is exhausted.
- Resolution 20: `HotReloadDaemon::resolve_reload_threshold()` rejects bad thresholds before any candidate model work starts.
- Resolution 21: `HotReloadDaemon::prepare_reload_candidate()` maps missing-path failures to `model_path_missing` and malformed artifacts to `model_validation_failed`.
- Resolution 22: `crates/mini-edr-daemon/tests/hot_reload.rs` proves that invalid reload candidates do not append spurious `Reloading` entries to state history.
- Resolution 23: `AlertGenerator` chose the persisted `u64` sequence-file design because the shared `Alert` schema already models `alert_id` numerically and the validators want monotonic restart evidence.
- Resolution 24: `AlertGenerator::sanitize_string()` redacts kernel-pointer-like substrings and normalizes newlines before user-visible serialization.
- Resolution 25: `normalize_top_features()` guarantees exactly five features in every alert explanation payload, even when fewer than five features have non-zero contributions.
- Resolution 26: The fixture suites were written to be loopback-only, temp-dir-only, and self-cleaning.
- Resolution 27: `reverse_shell.sh` talks only to `127.0.0.1`.
- Resolution 28: `privesc_setuid.sh` never touches real privileged binaries and only toggles permissions on a temp helper.
- Resolution 29: `cryptominer_emulator.sh` performs short hashing bursts and scratch writes under `/tmp` with no network pools.
- Resolution 30: `port_scan.sh` probes a tiny localhost port range rather than touching any external host.
- Resolution 31: The harnesses wrap every trial in structured JSON so score, alert decision, and model hash are recorded consistently.
- Resolution 32: Local verification now shows `40 / 40` malicious detections and `0` benign alerts across `180` modeled hours through the current daemon predict surface.
- Resolution 33: The ONNX dependency-policy cleanup commit (`f5aba8f`) documented or replaced the remaining supply-chain outliers so the milestone does not leave silent audit debt behind.
- Resolution 34: This writeup explicitly calls out the feature-importance skew so future workers do not mistake the current excellent metrics for proof that live runtime generalization is solved.

## Carry-overs

- Carry-over 1: `f4-misc-runtime-prior-source-investigation` remains pending and is directly motivated by the current feature-importance skew.
- Carry-over 2: The current importance profile shows `bigrams.__process_positive_rate__` dominating at `0.9031115770`, so live-runtime generalization still needs explicit study.
- Carry-over 3: The non-trivial importance assigned to `pid`, `window_start_ns`, and `window_end_ns` suggests the synthetic single-event window bridge may be leaking corpus-specific structure.
- Carry-over 4: The model currently clears held-out BETH metrics comfortably, but that does not yet prove parity on real host telemetry.
- Carry-over 5: The fixture suites currently use `/internal/predict` and `would_alert` because the alert-stream API does not exist yet.
- Carry-over 6: Feature `f5-local-api` already documents the required follow-up: rewire the fixture harnesses to the real `/alerts/stream` surface once the alerting milestone lands.
- Carry-over 7: The detection milestone does not yet persist a native booster artifact alongside `model.onnx`, so retrospective feature-importance analysis currently requires an in-memory retrain.
- Carry-over 8: All `VAL-DETECT-001` through `VAL-DETECT-019` entries remain `pending` in `validation-state.json` even though the implementation and local evidence now exist.
- Carry-over 9: `VAL-REL-006` through `VAL-REL-010` also remain pending because the reliability assertions need later validator promotion and full daemon surfaces.
- Carry-over 10: Final end-to-end proof for malformed model startup, live alert streaming, log redaction, and dashboard/TUI visibility is owned by later alerting, web, TUI, and system-integration milestones.
- Carry-over 11: None of the carry-overs above imply the detection implementation is missing; they are either validation-state lag, later-surface integration, or explicit follow-up analysis.

## Validation Status

- `VAL-DETECT-001`, `VAL-DETECT-002`, `VAL-DETECT-003`, and `VAL-DETECT-014` are **pending** in `validation-state.json`; implementation evidence exists in `crates/mini-edr-detection/src/model.rs`, `src/tree_ensemble.rs`, `src/manager.rs`, and `tests/inference_engine.rs`.
- `VAL-DETECT-004`, `VAL-DETECT-005`, `VAL-DETECT-006`, `VAL-DETECT-017`, and `VAL-DETECT-019` are **pending** in `validation-state.json`; implementation evidence exists in `crates/mini-edr-detection/src/alert_generator.rs`, `crates/mini-edr-daemon/src/lib.rs`, and the threshold/reload test suite.
- `VAL-DETECT-007`, `VAL-DETECT-011`, and `VAL-DETECT-016` are **pending** in `validation-state.json`; implementation evidence exists in `crates/mini-edr-detection/src/alert_generator.rs` and `tests/alert_generator.rs`.
- `VAL-DETECT-008`, `VAL-DETECT-009`, `VAL-DETECT-010`, and `VAL-DETECT-018` are **pending** in `validation-state.json`; implementation evidence exists in `crates/mini-edr-daemon/src/lib.rs`, `crates/mini-edr-detection/src/manager.rs`, `tests/hot_reload.rs`, and the localhost reload fixtures.
- `VAL-DETECT-012` is **pending** in `validation-state.json`; local fixture evidence from `tests/fixtures/malware/run_all.sh` currently shows `40 / 40` detections and minimum malicious score `0.9596308469772339`.
- `VAL-DETECT-013` is **pending** in `validation-state.json`; local fixture evidence from `tests/fixtures/benign/run_all.sh` currently shows `0` alerts across `180` modeled hours and max benign score `0.040310800075531006`.
- `VAL-DETECT-015` is **pending** in `validation-state.json`; local artifact evidence from `training/output/metrics.json` currently shows `F1 = 0.9886919234339773`, `TPR = 0.9783038510664357`, and `FPR = 0.006682659355723098`.
- `VAL-REL-006`, `VAL-REL-007`, `VAL-REL-008`, `VAL-REL-009`, and `VAL-REL-010` are **pending** in `validation-state.json`; the detection milestone provides the model-quality, degraded-mode, and fixture groundwork for those later validator passes.
- Manual quality check for this writeup: confirm the section order is `Overview`, `Accomplishments`, `Issues / Bugs Encountered`, `Resolutions`, `Carry-overs`, and `Validation Status`.
- Manual quality check for this writeup: confirm the narrative includes the required milestone-specific topics — training metrics, feature-importance analysis, ONNX-versus-native-backend rationale, hot-reload race discoveries, and fixture authoring notes.
- Repository validation tied to this writeup feature: rerun the workspace nextest baseline after adding this document so the repository remains green.
