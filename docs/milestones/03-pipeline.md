# Mini-EDR Milestone 03 — Pipeline

## Overview

The pipeline milestone converted the repository from “sensor data exists” into “sensor data can become structured behavioral evidence.”
It implemented the userspace `/proc` reader, ancestry reconstruction, window aggregation, feature-vector math, openat deduplication, and synthetic fork-storm stress fixtures described by `FR-P02` through `FR-P07`.
This milestone is represented primarily by commits `417e74c`, `bd185ab`, `07eb2bd`, `840030f`, and `3a4dad8`.
The work stayed inside the crate boundary promised by SDD §8.2: `mini-edr-pipeline` consumes shared types from `mini-edr-common`, but it does not reach upward into daemon, TUI, or web crates.
The result is a pipeline layer that can enrich `SyscallEvent` records with host-visible process context, preserve ancestry correctness across PID reuse and deep chains, emit half-open process windows, compute deterministic feature vectors, and tolerate synthetic reload-era fork storms without panicking.
The current baseline `cargo nextest run --workspace --test-threads=8` run passes 82 tests, including the pipeline ancestry, feature, window, dedup, and stress suites that landed in this milestone.
The milestone deliberately stopped short of final daemon-owned validation surfaces such as live SIGHUP orchestration, alert generation, and browser/TUI rendering, because those belong to later milestones.

## Accomplishments

- Commit `417e74c` introduced the `/proc` reader implementation in `crates/mini-edr-pipeline/src/proc_reader.rs`.
- `proc_reader.rs` starts with a module comment that explains the central race of the pipeline stage: `/proc` is not a snapshot, so missing files are a normal condition rather than a panic-worthy invariant break.
- `ProcStatus` captures the exact subset of `/proc/<pid>/status` needed by enrichment: `name`, `tgid`, `ppid`, and `uid`.
- `ProcStat` captures the exact subset of `/proc/<pid>/stat` needed by ancestry correctness: `pid`, `comm`, `state`, `ppid`, and `start_time_ticks`.
- `ProcHidePidSetting` records the active procfs `hidepid` mount policy so callers can distinguish ordinary process exit races from persistent visibility restrictions.
- `ProcHidePidSetting::is_active()` gives the rest of the pipeline a simple predicate instead of forcing raw mount-option parsing everywhere else.
- `ProcReadError` formalizes the three `/proc` failure families the milestone cares about: `NotFound`, `Permission`, and catch-all `Io`.
- `ProcReadError::NotFound` documents the expected “process exited mid-read” race required by `TC-09`.
- `ProcReadError::Permission` documents the expected hidepid or ownership restriction required by `VAL-PIPELINE-025`.
- `ProcReadError::Io` preserves the underlying `std::io::Error` so callers can log actionable detail instead of losing the original cause.
- `ProcReader::new()` anchors the production reader at the host `/proc` mount.
- `ProcReader::with_root()` gives the test suite a fixture-friendly constructor that can point at temporary fake procfs trees.
- `ProcReader::hidepid_setting()` exposes the parsed procfs visibility policy for later daemon health and degraded-state decisions.
- `ProcReader::read_status()` implements the `FR-P02` requirement to read `/proc/<pid>/status`.
- `ProcReader::read_exe()` implements the `FR-P02` requirement to resolve `/proc/<pid>/exe`.
- `ProcReader::read_cgroup()` implements the `FR-P02` requirement to preserve the host-visible `/proc/<pid>/cgroup` text verbatim.
- `ProcReader::read_stat()` implements the `FR-P02` requirement to read `/proc/<pid>/stat`.
- `ProcReader::detect_hidepid()` parses `/proc/mounts` once at startup rather than rediscovering the policy on every event.
- `ProcReader::parse_hidepid_options()` preserves both the `hidepid` mode and optional `gid` override from procfs mount options.
- `ProcReader::log_hidepid_warning()` emits a single structured warning with `event = "proc_hidepid_detected"` when procfs restrictions are active.
- `ProcReader::classify_io()` centralizes the `ENOENT -> NotFound` and `EACCES -> Permission` mapping so every read path behaves consistently.
- `ProcReader::parse_status()` extracts the specific `Name`, `Tgid`, `PPid`, and `Uid` fields the pipeline needs for enrichment and ancestry.
- `ProcReader::parse_stat()` handles the tricky `/proc/<pid>/stat` grammar where `comm` is parenthesized and may itself contain spaces.
- `parse_stat()` also captures field 22 (`starttime`) so PID reuse can be distinguished from a still-live process with the same numeric ID.
- The `ProcReader` implementation is fully documented with rustdoc and inline “why” comments rather than only “what” comments.
- Commit `bd185ab` introduced ancestry reconstruction in `crates/mini-edr-pipeline/src/event_enricher.rs`.
- `event_enricher.rs` starts with a module comment describing the parent-first ancestry contract and the explicit choice to use an iterative walk instead of recursion.
- `EventEnricher` owns the `ProcReader`, the ancestry depth cap, and a PID-keyed ancestry cache.
- `EventEnricher::DEFAULT_MAX_ANCESTRY_DEPTH` fixes the default truncation ceiling at 1,024 entries.
- `EventEnricher::new()` gives the crate a safe default that matches the documented depth policy.
- `EventEnricher::with_max_ancestry_depth()` clamps zero to one so callers cannot create a degenerate “truncate everything away” configuration.
- `EventEnricher::enrich_event()` is the main pipeline entry point that turns one `SyscallEvent` into one `EnrichedEvent`.
- `enrich_event()` reads cgroup text independently from process identity so partial enrichment can still preserve some context when later reads race with process exit.
- `enrich_event()` emits `tracing::warn!` records with `event = "enrichment_partial"` instead of surfacing `/proc` races as fatal errors.
- `EventEnricher::invalidate_clone_related_cache()` clears ancestry cache entries for the observed parent PID and any returned child PID when clone events arrive.
- That clone-triggered invalidation is the first line of defense against stale ancestry after fork bursts or PID reuse.
- `EventEnricher::resolve_ancestry_chain()` performs the iterative parent walk that satisfies `FR-P03`.
- `resolve_ancestry_chain()` uses a `visited_pids` set as a corruption fuse so synthetic or race-induced loops terminate cleanly instead of repeating forever.
- `resolve_ancestry_chain()` stops at PID 1 and never emits PID 0 as a synthetic ancestor entry.
- `resolve_ancestry_chain()` checks cached ancestry entries against a live `ProcessFingerprint` before trusting them.
- `ProcessFingerprint` combines `parent_pid` and `start_time_ticks`, which lets the pipeline reject reused numeric PIDs that point at a new process incarnation.
- `cache_visited_suffix()` stores validated ancestry suffixes so later events can reuse stable prefixes without re-reading every ancestor on every event.
- `read_process_snapshot()` keeps the `/proc` snapshot logic in one place and chooses `stat.ppid` first because it shares a read boundary with `starttime`.
- `trim_chain_to_depth()` enforces the default 1,024-entry cap without recursion.
- `chain_has_duplicate_pids()` discards corrupted cached chains rather than reusing them.
- The milestone kept ancestry logic inside `mini-edr-pipeline` instead of teaching downstream crates to reconstruct process trees for themselves.
- Commit `07eb2bd` introduced process-window aggregation and feature-vector computation in `crates/mini-edr-pipeline/src/window.rs`.
- `window.rs` starts with a module comment that names the half-open window invariant `[window_start_ns, window_end_ns)` from `FR-P04`.
- `WindowAggregator` owns a `HashMap<u32, ProcessWindow>` keyed by PID, matching the architecture description in SDD §4.1.2.
- `WindowAggregator::DEFAULT_DEDUP_WINDOW_MS` encodes the documented 100 ms dedup tuning default.
- `WindowAggregator::new()` converts configured seconds into nanoseconds once and stores the active dedup window alongside the process map.
- `WindowAggregator::with_dedup_window_ms()` gives tests and later runtime configuration code a direct way to exercise non-default dedup tuning.
- `WindowAggregator::set_window_duration_secs()` applies duration changes only to future windows, not windows already in flight.
- `WindowAggregator::set_dedup_window_ms()` applies dedup tuning changes only to future windows for the same reason.
- `WindowAggregator::push_event()` implements the core half-open state machine for per-process windows.
- `push_event()` emits exactly one full `FeatureVector` when an event lands on or beyond the exclusive end of the active window.
- `WindowAggregator::flush_expired()` lets future daemon code close time-expired windows even when a process goes quiet.
- `WindowAggregator::close_process()` emits a partial vector with `short_lived = true` when a process exits before the configured window boundary.
- `ProcessWindow` stores the PID, start timestamp, duration, dedup window, and buffered events for one process.
- `ProcessWindow::new()` and `new_with_dedup_window_ns()` guarantee that both window duration and dedup duration are at least one nanosecond.
- `ProcessWindow::window_end_ns()` computes the exclusive end boundary for the active window.
- `ProcessWindow::push_event()` either appends a new event or merges it into an eligible dedup record.
- `ProcessWindow::compute_features()` builds the stable `FeatureVector` schema consumed by the future detection crate.
- The feature computation path sorts events by `(timestamp, event_id)` so replayed fixtures and live traffic behave deterministically under equal timestamps.
- `compute_features()` expands deduplicated syscall runs back into the repeated syscall sequence needed by the n-gram math.
- `compute_features()` emits the scalar count features required by `FR-P05`: total syscalls and per-syscall counts.
- `compute_features()` emits ratio features for each syscall family.
- `compute_features()` emits deterministic bigram and trigram distributions as `BTreeMap<String, f64>`.
- `compute_features()` emits Shannon path entropy using the natural-log base.
- `compute_features()` emits unique IP, unique file, child-spawn, timing, and sensitive-directory features.
- `compute_features()` emits `failed_syscall_count` using `syscall_result < 0` when that metadata is available.
- `compute_features()` emits `short_lived`, `window_duration_ns`, and `events_per_second`, which are important for later ML and operator explanations.
- `FeatureCounters` gives the implementation one explicit accumulator for all scalar and set-based features.
- `SensitiveDir` isolates the three policy directories `/etc`, `/tmp`, and `/dev`.
- `accumulate_feature_counters()` performs the single ordered pass over enriched events that feeds the rest of the feature computation path.
- `update_sensitive_file_counters()` separates reads from writes so `/etc` reads do not accidentally set the “wrote to /etc” flag.
- `has_write_intent()` interprets `O_WRONLY`, `O_RDWR`, `O_CREAT`, `O_TRUNC`, and `O_APPEND` as write-capable opens.
- `sensitive_dir_for_path()` recognizes both the directory roots themselves and descendant paths.
- `expand_syscall_sequence()` turns deduplicated runs back into the sequence model needed by n-grams.
- `build_ngram_distribution()` normalizes counts to probabilities, which makes golden-fixture comparisons independent of raw window size.
- `shannon_entropy()` implements the same `-Σ p_i ln(p_i)` formula as SciPy’s default entropy computation.
- `inter_syscall_timing_stats()` computes average, minimum, maximum, and standard-deviation timing summaries from adjacent events.
- The milestone kept numeric conversion helpers explicit and annotated them with the reason the precision-loss lint is safe here.
- Commit `07eb2bd` also updated `crates/mini-edr-common/src/lib.rs` sample helpers so ancestry fixtures end at the observed process, matching the documented chain invariant.
- Commit `07eb2bd` also updated `crates/mini-edr-sensor/src/ringbuffer_consumer.rs` so the pipeline-facing sensor schema carried the metadata needed by the new feature math.
- Commit `840030f` layered openat deduplication on top of the window engine.
- `ProcessWindow::find_dedup_target_index()` searches backward only across the trailing run of openat events.
- That trailing-run restriction preserves syscall order for n-gram and timing features instead of collapsing across unrelated syscalls.
- `is_dedup_candidate()` limits deduplication to openat records that actually have filenames.
- `dedup_equivalent()` compares every feature-relevant and operator-visible field, not just the filename.
- `dedup_equivalent()` explicitly includes `open_flags` and `syscall_result`, which prevents a read from collapsing into a write or a success from collapsing into a failure.
- `dedup_equivalent()` also includes enriched metadata such as `process_name`, `binary_path`, `cgroup`, `uid`, and `ancestry_chain`.
- The dedup work preserved boundary behavior by refusing to merge events exactly on the dedup-window edge.
- The default dedup window stayed at 100 ms, matching the task brief and `TC-14` guidance.
- Commit `3a4dad8` added stress hardening for reload-era fork storms.
- `crates/mini-edr-pipeline/tests/stress.rs` starts with a module comment that names the two pipeline-side failure modes this crate can own today: ancestry cycles and duplicate partial windows.
- `stress_breaks_ancestry_cycles_instead_of_repeating_pids()` proves that a synthetic parent/child loop is truncated before duplicate PIDs appear in the output ancestry chain.
- `stress_reload_reconfiguration_does_not_duplicate_partial_windows_in_50k_process_burst()` simulates repeated reconfiguration during a 50,000-process burst and proves that each PID emits exactly one partial vector.
- `tests/fixtures/fork_storm.rs` provides a configurable Rust burst generator for high-rate process creation.
- `tests/fixtures/fork_storm` is the executable wrapper that makes the fixture easy to invoke from shell scripts and validators.
- `tests/fixtures/fork_storm_sighup.sh` records the intended integrated stress path for later daemon-owned validation of `VAL-PIPELINE-022`.
- `tests/fixtures/deep_chain.sh` gives the project a reproducible deep-ancestry fixture rather than relying only on in-memory fake trees.
- `tests/fixtures/spawn_chain.sh` gives the project a reproducible normal-depth ancestry fixture.
- `crates/mini-edr-pipeline/tests/ancestry.rs` covers parent-first chain reconstruction, PID-0 elision, deep-chain truncation, and PID reuse.
- `ancestry_reconstructs_parent_first_four_level_chain()` locks in the canonical `init -> bash -> python -> leaf` order expected by `VAL-PIPELINE-005` and `VAL-PIPELINE-006`.
- `ancestry_stops_at_pid_one_and_omits_pid_zero_sentinel()` locks in the “PID 1 yes, PID 0 no” boundary rule.
- `ancestry_truncates_deep_chain_at_default_depth_without_recursion()` proves the iterative walk can survive a 10,000-deep chain and cap the output at 1,024 entries.
- `ancestry_reused_pid_never_inherits_stale_cached_chain_after_clone_event()` locks in the fingerprint-and-invalidation protection against stale cached ancestry after PID reuse.
- `ancestry_spawn_chain_fixture_matches_requested_depth()` and `ancestry_deep_chain_stack_safety_fixture_matches_requested_depth()` turn the shell fixtures into deterministic test inputs.
- `crates/mini-edr-pipeline/tests/features.rs` covers both golden-fixture correctness and property-based invariants.
- `features_match_handcrafted_golden_window_within_tolerance()` is the golden window that locks in concrete counts, ratios, bigrams, trigrams, entropy, timing, and directory flags.
- `features_require_write_intent_for_sensitive_directory_flags()` proves that write flags only fire when the open flags actually imply write intent.
- `features_path_entropy_matches_scipy_reference_within_tolerance()` is the explicit entropy-parity test required by the task brief.
- `features_invariants_hold_for_1000_random_sequences()` uses `proptest` with 1,000 cases to stress ratio sums, finite timing values, and normalized n-gram distributions.
- `crates/mini-edr-pipeline/tests/windows.rs` covers boundary emission, duration reconfiguration, and short-lived partial windows.
- `windows_emit_exactly_one_feature_vector_at_boundary_and_carry_boundary_event_forward()` locks in the half-open boundary rule.
- `windows_apply_duration_reconfiguration_to_the_next_window_only()` locks in the “reload affects next window, not current window” invariant.
- `windows_emit_short_lived_process_partial_window_once_at_exit_timestamp()` locks in the `FR-P06` partial-window rule and forbids double emission on a second close.
- `crates/mini-edr-pipeline/src/lib.rs` now re-exports `EventEnricher`, `ProcReader`, `ProcStat`, `ProcStatus`, `ProcessWindow`, and `WindowAggregator` from one stable crate root.
- The milestone added `tempfile` and `proptest` support to `crates/mini-edr-pipeline/Cargo.toml` so the crate can own fixture-heavy and invariant-heavy tests locally.
- The milestone preserved the “no reverse compile-time edges” rule from the workspace architecture.
- The milestone ended with all pipeline tests participating in the workspace-wide nextest baseline rather than requiring ad hoc one-off commands.

## Issues / Bugs Encountered

- Issue 1: `/proc` reads are inherently racy, so a process can disappear between the sensor event and the enrichment read.
- Issue 2: A generic I/O error surface would have blurred “process exited” and “hidepid denied access,” which are operationally different situations.
- Issue 3: `/proc/<pid>/stat` is awkward to parse because `comm` is parenthesized and may contain spaces.
- Issue 4: Hidepid detection needed to happen once and warn once, not per event, or the logs would turn a mount-policy issue into a warning storm.
- Issue 5: Ancestry reconstruction over a 10,000-level chain could have blown the stack if implemented recursively.
- Issue 6: PID reuse could poison a cached ancestry chain if the cache key was only the numeric PID.
- Issue 7: Clone events can change the process tree before `/proc` settles, so cached parentage needed an invalidation strategy.
- Issue 8: Synthetic or race-induced loops in parent links could otherwise create repeated PIDs or long-running ancestry walks.
- Issue 9: The feature brief required the ancestry chain to end at the observed process, but older sample fixtures in `mini-edr-common` did not yet model that invariant.
- Issue 10: Sliding-window boundaries are easy to get subtly wrong; an event exactly at `window_end_ns` must belong to the next window, not the old one.
- Issue 11: Duration reconfiguration during an active window could distort already buffered evidence if it retroactively stretched or shrank the current window.
- Issue 12: Short-lived processes needed one partial vector at exit, not zero vectors and not duplicate vectors.
- Issue 13: Shannon entropy parity is easy to drift if the implementation uses a different logarithm base or forgets to normalize counts to probabilities.
- Issue 14: N-gram feature maps had to be deterministic for tests, which ruled out unordered hash-map output.
- Issue 15: Sensitive-directory flags are semantically about writes, but simple pathname matching would have produced false positives on read-only opens.
- Issue 16: Deduplication is attractive for reducing event volume, but over-aggressive dedup would destroy syscall order and corrupt n-gram/timing features.
- Issue 17: Dedup also had to avoid merging different filenames, different open flags, and different syscall results.
- Issue 18: The live sensor path does not yet fully populate all pipeline-relevant metadata, especially `open_flags` and some syscall-result paths, so some feature flags are stronger in fixture tests than they are end-to-end today.
- Issue 19: Fork storms plus configuration reloads are exactly the kind of load where duplicate partial windows or ancestry loops can slip through if state transitions are not conservative.
- Issue 20: Validation-state coverage for the pipeline milestone lagged the implementation, so the writeup needed to distinguish “implemented” from “validated” honestly.

## Resolutions

- Resolution 1: `ProcReadError` now separates `NotFound`, `Permission`, and `Io`, making the caller’s fallback behavior explicit.
- Resolution 2: `ProcReader::classify_io()` centralized that mapping so every `/proc` read path reports the same error categories.
- Resolution 3: `ProcReader::parse_stat()` now anchors parsing on the outer parentheses around `comm`, which preserves process names containing spaces.
- Resolution 4: `ProcReader::detect_hidepid()` and `log_hidepid_warning()` move procfs policy discovery to startup time and emit exactly one structured warning.
- Resolution 5: `EventEnricher::resolve_ancestry_chain()` is iterative, not recursive, eliminating stack-growth risk on 10,000-level chains.
- Resolution 6: `ProcessFingerprint { parent_pid, start_time_ticks }` gives the ancestry cache a stable identity check that survives PID reuse.
- Resolution 7: `invalidate_clone_related_cache()` drops parent and child cache entries on clone events so stale lineages are not reused optimistically.
- Resolution 8: `visited_pids` in `resolve_ancestry_chain()` acts as a cycle fuse, stopping ancestry output before duplicate PIDs can surface.
- Resolution 9: The sample ancestry helpers in `mini-edr-common` were updated alongside the pipeline feature work so fixture chains end at the observed process.
- Resolution 10: `WindowAggregator::push_event()` now treats windows as half-open intervals and carries a boundary event forward into the next window.
- Resolution 11: `set_window_duration_secs()` and `set_dedup_window_ms()` only affect future windows, keeping buffered evidence stable during reloads.
- Resolution 12: `close_process()` emits exactly one partial vector and then removes the process window, preventing duplicate exit emissions.
- Resolution 13: `shannon_entropy()` explicitly mirrors SciPy’s natural-log formula, and `features_path_entropy_matches_scipy_reference_within_tolerance()` locks that in with a concrete numeric reference.
- Resolution 14: `BTreeMap` is used for bigrams and trigrams so golden tests compare deterministic key ordering and values.
- Resolution 15: `has_write_intent()` interprets access-mode and creation/truncation flags so sensitive-directory booleans represent write-capable opens instead of all opens.
- Resolution 16: `find_dedup_target_index()` searches only the trailing run of openat events, preserving observable syscall order for the feature math.
- Resolution 17: `dedup_equivalent()` compares filename, flags, results, and enriched identity fields so only truly equivalent events merge.
- Resolution 18: The live-sensor ABI limitation on `open_flags` and `syscall_result` was documented as a carry-over for later daemon/system-integration work instead of being silently ignored.
- Resolution 19: `stress_reload_reconfiguration_does_not_duplicate_partial_windows_in_50k_process_burst()` exercises repeated reconfiguration during a large burst and proves one partial vector per PID.
- Resolution 20: This writeup uses `validation-state.json` statuses directly in the final section so it does not overclaim milestone validation.

## Carry-overs

- Carry-over 1: `VAL-PIPELINE-001` is already marked passed in `validation-state.json`, but that replay-ringbuf seam evidence was established during the sensor milestone rather than by this writeup feature.
- Carry-over 2: `VAL-PIPELINE-002`, `VAL-PIPELINE-003`, and `VAL-PIPELINE-004` still need final validator evidence even though `ProcReader` and partial-enrichment logic are implemented.
- Carry-over 3: `VAL-PIPELINE-005`, `VAL-PIPELINE-006`, and `VAL-PIPELINE-007` still need final validator evidence even though the ancestry engine and tests are in place.
- Carry-over 4: `VAL-PIPELINE-008` through `VAL-PIPELINE-015` still need validator promotion from unit/integration evidence to contract evidence.
- Carry-over 5: `VAL-PIPELINE-016` and `VAL-PIPELINE-017` still need validator promotion for the dedup contract, even though same-file collapse and different-file separation are implemented and tested.
- Carry-over 6: `VAL-PIPELINE-018`, `VAL-PIPELINE-019`, `VAL-PIPELINE-020`, and `VAL-PIPELINE-021` still need final contract evidence even though PID reuse and deep-chain behavior are implemented in the crate.
- Carry-over 7: `VAL-PIPELINE-022` depends on a live daemon-level SIGHUP path and probe inventory surface, so the crate-level stress fixture is only a precursor to the final integrated assertion.
- Carry-over 8: `VAL-PIPELINE-023` needs host-versus-container cgroup evidence under a real Docker-launched process; the current crate preserves cgroup text but does not itself start containers.
- Carry-over 9: `VAL-PIPELINE-024` needs end-to-end UTF-8 rendering checks in the TUI and web surfaces; the pipeline currently preserves strings but does not own those renderers.
- Carry-over 10: `VAL-PIPELINE-025` needs daemon-level startup handling and degraded-state policy around hidepid beyond the crate-level single-warning behavior.
- Carry-over 11: `VAL-PIPELINE-026` still needs integrated runtime memory and boundary validation at the daemon level, even though zero and negative configuration values are already rejected in `mini-edr-common`.
- Carry-over 12: The live sensor ABI still needs to populate `open_flags` and complete syscall-result coverage so the pipeline’s sensitive-write and failed-syscall features are fully exercised end to end.
- Carry-over 13: Final cross-area evidence that a real syscall becomes a feature vector and then an alert remains a later detection/daemon/system-integration responsibility.
- Carry-over 14: None of these carry-overs represent missing core pipeline crate work; they are either validation-state lag or intentional later-surface integration.

## Validation Status

- `VAL-PIPELINE-001` — **passed** in `validation-state.json` on the sensor milestone (`2026-04-26T12:46:25.073154+00:00`); this writeup references it because the pipeline milestone inherits that seam.
- `VAL-PIPELINE-002` — **pending** in `validation-state.json`; implemented by `ProcReader::read_status`, `read_exe`, and `read_cgroup`, but awaiting validator evidence.
- `VAL-PIPELINE-003` — **pending** in `validation-state.json`; implemented by partial-enrichment fallback behavior in `EventEnricher::enrich_event`, but awaiting validator evidence.
- `VAL-PIPELINE-004` — **pending** in `validation-state.json`; implemented by structured `enrichment_partial` warnings, but awaiting validator evidence.
- `VAL-PIPELINE-005` — **pending** in `validation-state.json`; implemented by `resolve_ancestry_chain()` and `ancestry_reconstructs_parent_first_four_level_chain()`, but awaiting validator evidence.
- `VAL-PIPELINE-006` — **pending** in `validation-state.json`; implemented by parent-first ancestry ordering and tested in `tests/ancestry.rs`, but awaiting validator evidence.
- `VAL-PIPELINE-007` — **pending** in `validation-state.json`; implemented by the PID-1/PID-0 boundary handling in `resolve_ancestry_chain()`, but awaiting validator evidence.
- `VAL-PIPELINE-008` — **pending** in `validation-state.json`; implemented by `WindowAggregator::push_event()` and `windows_emit_exactly_one_feature_vector_at_boundary_and_carry_boundary_event_forward()`, but awaiting validator evidence.
- `VAL-PIPELINE-009` — **pending** in `validation-state.json`; implemented by the half-open window rule in `push_event()`, but awaiting validator evidence.
- `VAL-PIPELINE-010` — **pending** in `validation-state.json`; implemented by `set_window_duration_secs()` and the corresponding window reconfiguration test, but awaiting validator evidence.
- `VAL-PIPELINE-011` — **pending** in `validation-state.json`; implemented by `compute_features()` producing the required schema fields, but awaiting validator evidence.
- `VAL-PIPELINE-012` — **pending** in `validation-state.json`; implemented by the golden-feature test and SciPy-parity entropy test, but awaiting validator evidence.
- `VAL-PIPELINE-013` — **pending** in `validation-state.json`; implemented by `update_sensitive_file_counters()` and `features_require_write_intent_for_sensitive_directory_flags()`, but awaiting validator evidence.
- `VAL-PIPELINE-014` — **pending** in `validation-state.json`; implemented by `close_process()` and `windows_emit_short_lived_process_partial_window_once_at_exit_timestamp()`, but awaiting validator evidence.
- `VAL-PIPELINE-015` — **pending** in `validation-state.json`; implemented by partial-window end-time handling in `close_process()`, but awaiting validator evidence.
- `VAL-PIPELINE-016` — **pending** in `validation-state.json`; implemented by same-file openat deduplication and tested in `dedup_collapses_same_file_openat_burst_into_one_record_with_repeat_count()`, but awaiting validator evidence.
- `VAL-PIPELINE-017` — **pending** in `validation-state.json`; implemented by filename-aware dedup separation and tested in `dedup_keeps_distinct_filenames_separate_even_when_they_interleave()`, but awaiting validator evidence.
- `VAL-PIPELINE-018` — **pending** in `validation-state.json`; implemented by PID fingerprinting and clone-cache invalidation, but awaiting validator evidence.
- `VAL-PIPELINE-019` — **pending** in `validation-state.json`; implemented by the same PID-reuse protections, but awaiting validator evidence.
- `VAL-PIPELINE-020` — **pending** in `validation-state.json`; implemented by iterative ancestry traversal and deep-chain tests, but awaiting validator evidence.
- `VAL-PIPELINE-021` — **pending** in `validation-state.json`; implemented by depth truncation plus `ancestry_truncated`, but awaiting validator evidence.
- `VAL-PIPELINE-022` — **pending** in `validation-state.json`; the crate-level stress fixture exists, but the final integrated SIGHUP/fork-storm assertion is still daemon-owned.
- `VAL-PIPELINE-023` — **pending** in `validation-state.json`; cgroup preservation is implemented, but the live Docker host-side check is still pending.
- `VAL-PIPELINE-024` — **pending** in `validation-state.json`; string preservation is compatible with UTF-8, but the TUI/web render-path assertion is still pending.
- `VAL-PIPELINE-025` — **pending** in `validation-state.json`; the single startup hidepid warning is implemented in `ProcReader`, but the full degraded-mode/system behavior is still pending.
- `VAL-PIPELINE-026` — **pending** in `validation-state.json`; configuration-side boundary rejection already exists, but the integrated long-window/runtime-memory assertion is still pending.
- Manual quality check for this writeup: confirm the section order is `Overview`, `Accomplishments`, `Issues / Bugs Encountered`, `Resolutions`, `Carry-overs`, `Validation Status`.
- Manual quality check for this writeup: confirm the narrative references the required topics from the feature brief — entropy computation reference, dedup tuning notes, and ancestry-tracking edge cases.
- Repository validation check tied to this writeup feature: rerun the workspace nextest baseline after adding the milestone document so the repository remains green.
