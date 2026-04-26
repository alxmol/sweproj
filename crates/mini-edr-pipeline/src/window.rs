//! Per-process window aggregation and feature-vector computation.
//!
//! Per SDD §4.1.2 and SRS FR-P04/FR-P05/FR-P06, the pipeline groups enriched
//! syscall events into process-local half-open windows and computes the stable
//! `FeatureVector` schema consumed by detection. The aggregator owns a
//! `HashMap<u32, ProcessWindow>` keyed by PID so each process advances
//! independently, and each `ProcessWindow` stores the duration it was created
//! with so a later SIGHUP reconfiguration only affects the *next* window.

use mini_edr_common::{EnrichedEvent, FeatureVector, SyscallType};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ops::Deref;

const NANOS_PER_SECOND: f64 = 1_000_000_000.0;
const NANOS_PER_MILLISECOND: u64 = 1_000_000;
const O_ACCMODE: u32 = 3;
const O_WRONLY: u32 = 1;
const O_RDWR: u32 = 2;
const O_CREAT: u32 = 64;
const O_TRUNC: u32 = 512;
const O_APPEND: u32 = 1_024;

/// Aggregates enriched events into per-process windows.
///
/// The aggregator keeps one active window per PID. Windows are half-open:
/// events with timestamps in `[window_start_ns, window_end_ns)` belong to the
/// current window, while an event exactly at `window_end_ns` starts the next
/// window. Full windows emit exactly one feature vector at their configured
/// boundary, and short-lived processes emit exactly one partial vector when
/// `close_process` observes the exit timestamp before the boundary.
#[derive(Debug)]
pub struct WindowAggregator {
    window_duration_ns: u64,
    dedup_window_ns: u64,
    windows_by_pid: HashMap<u32, ProcessWindow>,
}

impl WindowAggregator {
    /// Default deduplication window from TC-14's tuning guidance.
    pub const DEFAULT_DEDUP_WINDOW_MS: u64 = 100;

    /// Create a new aggregator using the documented `window_duration_secs`.
    #[must_use]
    pub fn new(window_duration_secs: u64) -> Self {
        Self::with_dedup_window_ms(window_duration_secs, Self::DEFAULT_DEDUP_WINDOW_MS)
    }

    /// Create a new aggregator with an explicit deduplication window.
    ///
    /// The dedup window is expressed in milliseconds because TC-14 and the
    /// feature brief describe burst tuning at millisecond granularity. A zero
    /// value is clamped to one nanosecond so callers cannot accidentally
    /// disable the invariant checks by creating an always-equal boundary.
    #[must_use]
    pub fn with_dedup_window_ms(window_duration_secs: u64, dedup_window_ms: u64) -> Self {
        Self {
            window_duration_ns: secs_to_nanos(window_duration_secs),
            dedup_window_ns: millis_to_nanos(dedup_window_ms),
            windows_by_pid: HashMap::new(),
        }
    }

    /// Update the duration used for *future* windows created after this call.
    ///
    /// Existing windows preserve the duration they were born with so SIGHUP
    /// takes effect on the next boundary rather than shortening or stretching
    /// a window that is already mid-flight.
    pub fn set_window_duration_secs(&mut self, window_duration_secs: u64) {
        self.window_duration_ns = secs_to_nanos(window_duration_secs);
    }

    /// Update the deduplication window used for future process windows.
    ///
    /// Existing windows preserve the dedup policy they were born with so a
    /// reload cannot retroactively merge or split records that are already in
    /// flight. This mirrors the window-duration policy and keeps FR-P07
    /// behavior stable for an already-buffered burst.
    pub fn set_dedup_window_ms(&mut self, dedup_window_ms: u64) {
        self.dedup_window_ns = millis_to_nanos(dedup_window_ms);
    }

    /// Push one enriched event through the half-open window state machine.
    ///
    /// When the event crosses a boundary, the closed full window is emitted and
    /// the event starts the next window. The caller receives either zero or one
    /// feature vector because a single event can close at most one active
    /// non-empty window for its PID.
    #[must_use]
    pub fn push_event(&mut self, event: EnrichedEvent) -> Vec<FeatureVector> {
        let pid = event.event.pid;
        let event_timestamp = event.event.timestamp;

        match self.windows_by_pid.remove(&pid) {
            Some(mut window) if event_timestamp < window.window_end_ns() => {
                window.push_event(event);
                self.windows_by_pid.insert(pid, window);
                Vec::new()
            }
            Some(window) => {
                let mut emitted = Vec::new();
                if !window.is_empty() {
                    emitted.push(window.compute_features(window.window_end_ns(), false));
                }

                // Per FR-P04's half-open interval semantics, the next active
                // window stays aligned to the previous boundary even if the
                // process goes idle. When SIGHUP reconfigures the duration, we
                // re-anchor from the expired boundary using the *new* duration
                // so VAL-PIPELINE-010 still observes the documented cadence
                // shift at the next window, not retroactively inside the old
                // one.
                let next_start_ns = aligned_window_start_ns(
                    window.window_end_ns(),
                    self.window_duration_ns,
                    event_timestamp,
                );
                let mut next_window = ProcessWindow::new_with_dedup_window_ns(
                    pid,
                    next_start_ns,
                    self.window_duration_ns,
                    self.dedup_window_ns,
                );
                next_window.push_event(event);
                self.windows_by_pid.insert(pid, next_window);
                emitted
            }
            None => {
                let mut window = ProcessWindow::new_with_dedup_window_ns(
                    pid,
                    event_timestamp,
                    self.window_duration_ns,
                    self.dedup_window_ns,
                );
                window.push_event(event);
                self.windows_by_pid.insert(pid, window);
                Vec::new()
            }
        }
    }

    /// Emit every full window whose boundary is at or before `now_ns`.
    ///
    /// This method lets the daemon drive time-based flushes even when a process
    /// goes quiet between syscalls. Empty windows are never fabricated; a quiet
    /// PID simply has no active state until another event arrives.
    #[must_use]
    pub fn flush_expired(&mut self, now_ns: u64) -> Vec<FeatureVector> {
        let mut emitted = Vec::new();
        let mut still_active = HashMap::with_capacity(self.windows_by_pid.len());

        for (pid, window) in std::mem::take(&mut self.windows_by_pid) {
            if now_ns >= window.window_end_ns() {
                if !window.is_empty() {
                    emitted.push(window.compute_features(window.window_end_ns(), false));
                }

                // Quiet processes still need an aligned anchor so the next
                // post-idle event lands in the correct half-open window. We do
                // not emit silent empty vectors; we simply roll the PID state
                // forward to the next boundary that contains `now_ns`.
                let next_start_ns = aligned_window_start_ns(
                    window.window_end_ns(),
                    self.window_duration_ns,
                    now_ns,
                );
                still_active.insert(
                    pid,
                    ProcessWindow::new_with_dedup_window_ns(
                        pid,
                        next_start_ns,
                        self.window_duration_ns,
                        self.dedup_window_ns,
                    ),
                );
            } else {
                still_active.insert(pid, window);
            }
        }

        self.windows_by_pid = still_active;
        emitted
    }

    /// Emit the active feature window for a process when it exits.
    ///
    /// If the process exits before the configured boundary, the vector is
    /// marked `short_lived = true` and uses the actual exit timestamp as the
    /// half-open `window_end_ns`. If the boundary already passed and no timer
    /// flushed the window yet, the full boundary takes precedence so the caller
    /// still receives the correct FR-P04 vector instead of a late partial one.
    #[must_use]
    pub fn close_process(&mut self, pid: u32, exit_timestamp_ns: u64) -> Option<FeatureVector> {
        self.windows_by_pid.remove(&pid).and_then(|window| {
            if window.is_empty() {
                return None;
            }

            if exit_timestamp_ns >= window.window_end_ns() {
                Some(window.compute_features(window.window_end_ns(), false))
            } else {
                Some(window.compute_features(exit_timestamp_ns.max(window.window_start_ns), true))
            }
        })
    }
}

/// Active event buffer for one process window.
///
/// `ProcessWindow` is public because TC-12 and future replay tests exercise the
/// feature math directly without needing the full daemon wiring. Callers are
/// expected to keep events within the window's half-open interval and to pass
/// the final `window_end_ns` chosen by the aggregator or process-exit logic.
#[derive(Clone, Debug)]
pub struct ProcessWindow {
    pid: u32,
    window_start_ns: u64,
    duration_ns: u64,
    dedup_window_ns: u64,
    events: Vec<DeduplicatedEvent>,
}

impl ProcessWindow {
    /// Create an empty process window.
    #[must_use]
    pub fn new(pid: u32, window_start_ns: u64, duration_ns: u64) -> Self {
        Self::new_with_dedup_window_ns(
            pid,
            window_start_ns,
            duration_ns,
            millis_to_nanos(WindowAggregator::DEFAULT_DEDUP_WINDOW_MS),
        )
    }

    fn new_with_dedup_window_ns(
        pid: u32,
        window_start_ns: u64,
        duration_ns: u64,
        dedup_window_ns: u64,
    ) -> Self {
        Self {
            pid,
            window_start_ns,
            duration_ns: duration_ns.max(1),
            dedup_window_ns: dedup_window_ns.max(1),
            events: Vec::new(),
        }
    }

    /// Return the exclusive end of the configured full window.
    #[must_use]
    pub const fn window_end_ns(&self) -> u64 {
        self.window_start_ns.saturating_add(self.duration_ns)
    }

    /// Returns whether the window currently contains any feature-bearing data.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Append one enriched event to this process window.
    pub fn push_event(&mut self, event: EnrichedEvent) {
        debug_assert_eq!(
            event.event.pid, self.pid,
            "WindowAggregator keys windows by PID, so a mismatched event would corrupt feature accounting"
        );

        if let Some(candidate) = self.find_dedup_target_index(&event) {
            let record = &mut self.events[candidate];
            record.event.repeat_count = record
                .event
                .repeat_count
                .saturating_add(event.repeat_count.max(1));
            record.last_observed_timestamp = event.event.timestamp;
            return;
        }

        self.events.push(DeduplicatedEvent::new(event));
    }

    /// Compute the stable FR-P05 feature vector for the recorded event set.
    ///
    /// The Shannon entropy math intentionally matches `scipy.stats.entropy`
    /// with the natural-log base: `H = -Σ p_i ln(p_i)` over the empirical file
    /// path distribution. Likewise, the n-gram maps are normalized frequency
    /// distributions, not raw counts, so replay fixtures can compare exact
    /// probabilities independent of window size.
    #[must_use]
    pub fn compute_features(&self, window_end_ns: u64, short_lived: bool) -> FeatureVector {
        let mut ordered_events: Vec<&EnrichedEvent> =
            self.events.iter().map(Deref::deref).collect();
        ordered_events.sort_by_key(|event| (event.event.timestamp, event.event.event_id));
        let counters = accumulate_feature_counters(&ordered_events);
        let expanded_sequence = expand_syscall_sequence(&ordered_events);
        let bigrams = build_ngram_distribution(&expanded_sequence, 2);
        let trigrams = build_ngram_distribution(&expanded_sequence, 3);
        let path_entropy = shannon_entropy(&counters.path_counts);
        let (avg_interval, min_interval, max_interval, stddev_interval) =
            inter_syscall_timing_stats(&ordered_events);
        let window_duration_ns = window_end_ns.saturating_sub(self.window_start_ns);
        let duration_seconds = (u64_to_f64(window_duration_ns) / NANOS_PER_SECOND).max(1e-9);

        FeatureVector {
            pid: self.pid,
            window_start_ns: self.window_start_ns,
            window_end_ns,
            total_syscalls: counters.total_syscalls,
            execve_count: counters.execve_count,
            openat_count: counters.openat_count,
            connect_count: counters.connect_count,
            clone_count: counters.clone_count,
            execve_ratio: ratio(counters.execve_count, counters.total_syscalls),
            openat_ratio: ratio(counters.openat_count, counters.total_syscalls),
            connect_ratio: ratio(counters.connect_count, counters.total_syscalls),
            clone_ratio: ratio(counters.clone_count, counters.total_syscalls),
            bigrams,
            trigrams,
            path_entropy,
            unique_ips: counters.unique_ips.len() as u64,
            unique_files: counters.unique_files.len() as u64,
            child_spawn_count: counters.child_spawn_count,
            avg_inter_syscall_time_ns: avg_interval,
            min_inter_syscall_time_ns: min_interval,
            max_inter_syscall_time_ns: max_interval,
            stddev_inter_syscall_time_ns: stddev_interval,
            wrote_etc: counters.wrote_etc,
            wrote_tmp: counters.wrote_tmp,
            wrote_dev: counters.wrote_dev,
            read_sensitive_file_count: counters.read_sensitive_file_count,
            write_sensitive_file_count: counters.write_sensitive_file_count,
            outbound_connection_count: counters.outbound_connection_count,
            loopback_connection_count: counters.loopback_connection_count,
            distinct_ports: counters.unique_ports.len() as u64,
            failed_syscall_count: counters.failed_syscall_count,
            short_lived,
            window_duration_ns,
            events_per_second: if counters.total_syscalls == 0 {
                0.0
            } else {
                u64_to_f64(counters.total_syscalls) / duration_seconds
            },
        }
    }

    fn find_dedup_target_index(&self, event: &EnrichedEvent) -> Option<usize> {
        if !is_dedup_candidate(event) {
            return None;
        }

        // The canonical pipeline stream is monotonic per PID. If a caller
        // hands us a backward timestamp anyway, keeping the event separate is
        // safer than deduplicating across reversed time because FR-P05 timing
        // features and FR-P07's chronological collapse semantics both depend
        // on preserving observable order.
        if self
            .events
            .last()
            .is_some_and(|last| event.event.timestamp < last.last_observed_timestamp)
        {
            return None;
        }

        // Dedup correctness invariant: we only merge inside a trailing run of
        // `openat` records. Crossing over a different syscall would rewrite the
        // observable syscall order that FR-P05 uses for timing and n-gram
        // features, so any non-openat event terminates the search immediately.
        for (index, existing) in self.events.iter().enumerate().rev() {
            if existing.event.event.syscall_type != SyscallType::Openat {
                break;
            }

            let delta_ns = event
                .event
                .timestamp
                .abs_diff(existing.last_observed_timestamp);
            if delta_ns >= self.dedup_window_ns {
                continue;
            }

            if dedup_equivalent(existing, event) {
                return Some(index);
            }
        }

        None
    }
}

#[derive(Clone, Debug)]
struct DeduplicatedEvent {
    event: EnrichedEvent,
    last_observed_timestamp: u64,
}

impl DeduplicatedEvent {
    const fn new(event: EnrichedEvent) -> Self {
        Self {
            last_observed_timestamp: event.event.timestamp,
            event,
        }
    }
}

impl Deref for DeduplicatedEvent {
    type Target = EnrichedEvent;

    fn deref(&self) -> &Self::Target {
        &self.event
    }
}

#[derive(Debug, Default)]
struct FeatureCounters {
    total_syscalls: u64,
    execve_count: u64,
    openat_count: u64,
    connect_count: u64,
    clone_count: u64,
    path_counts: BTreeMap<String, u64>,
    unique_ips: BTreeSet<[u8; 4]>,
    unique_files: BTreeSet<String>,
    unique_ports: BTreeSet<u16>,
    child_spawn_count: u64,
    wrote_etc: bool,
    wrote_tmp: bool,
    wrote_dev: bool,
    read_sensitive_file_count: u64,
    write_sensitive_file_count: u64,
    outbound_connection_count: u64,
    loopback_connection_count: u64,
    failed_syscall_count: u64,
}

#[derive(Clone, Copy, Debug)]
enum SensitiveDir {
    Etc,
    Tmp,
    Dev,
}

fn secs_to_nanos(window_duration_secs: u64) -> u64 {
    window_duration_secs.saturating_mul(1_000_000_000).max(1)
}

fn millis_to_nanos(dedup_window_ms: u64) -> u64 {
    dedup_window_ms.saturating_mul(NANOS_PER_MILLISECOND).max(1)
}

fn aligned_window_start_ns(
    previous_window_end_ns: u64,
    duration_ns: u64,
    timestamp_ns: u64,
) -> u64 {
    let mut next_start_ns = previous_window_end_ns;
    let duration_ns = duration_ns.max(1);

    while next_start_ns.saturating_add(duration_ns) <= timestamp_ns {
        next_start_ns = next_start_ns.saturating_add(duration_ns);
    }

    next_start_ns
}

fn ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        u64_to_f64(numerator) / u64_to_f64(denominator)
    }
}

fn accumulate_feature_counters(events: &[&EnrichedEvent]) -> FeatureCounters {
    let mut counters = FeatureCounters::default();

    // The feature schema mixes scalar counters, timing summaries, and
    // categorical distributions. Performing one ordered pass keeps the
    // implementation obvious for reviewers and minimizes accidental drift
    // between related features such as unique-file counts and entropy.
    for event in events {
        let weight = u64::from(event.repeat_count.max(1));
        counters.total_syscalls = counters.total_syscalls.saturating_add(weight);

        match event.event.syscall_type {
            SyscallType::Execve => {
                counters.execve_count = counters.execve_count.saturating_add(weight);
            }
            SyscallType::Openat => {
                counters.openat_count = counters.openat_count.saturating_add(weight);
            }
            SyscallType::Connect => {
                counters.connect_count = counters.connect_count.saturating_add(weight);
            }
            SyscallType::Clone => {
                counters.clone_count = counters.clone_count.saturating_add(weight);
            }
        }

        if event.event.syscall_result.is_some_and(|result| result < 0) {
            counters.failed_syscall_count = counters.failed_syscall_count.saturating_add(weight);
        }

        if let Some(filename) = event.event.filename.as_deref() {
            counters.unique_files.insert(filename.to_owned());
            *counters.path_counts.entry(filename.to_owned()).or_default() += weight;
            update_sensitive_file_counters(&mut counters, filename, event.event.open_flags, weight);
        }

        if let Some(ip_address) = event.event.ip_address {
            counters.unique_ips.insert(ip_address);
            counters.outbound_connection_count =
                counters.outbound_connection_count.saturating_add(weight);
            if ip_address[0] == 127 {
                counters.loopback_connection_count =
                    counters.loopback_connection_count.saturating_add(weight);
            }
        }

        if let Some(port) = event.event.port {
            counters.unique_ports.insert(port);
        }

        if event.event.syscall_type == SyscallType::Clone && event.event.child_pid.is_some() {
            counters.child_spawn_count = counters.child_spawn_count.saturating_add(weight);
        }
    }

    counters
}

fn update_sensitive_file_counters(
    counters: &mut FeatureCounters,
    filename: &str,
    open_flags: Option<u32>,
    weight: u64,
) {
    let Some(sensitive_dir) = sensitive_dir_for_path(filename) else {
        return;
    };

    if has_write_intent(open_flags) {
        counters.write_sensitive_file_count =
            counters.write_sensitive_file_count.saturating_add(weight);
        match sensitive_dir {
            SensitiveDir::Etc => counters.wrote_etc = true,
            SensitiveDir::Tmp => counters.wrote_tmp = true,
            SensitiveDir::Dev => counters.wrote_dev = true,
        }
    } else {
        counters.read_sensitive_file_count =
            counters.read_sensitive_file_count.saturating_add(weight);
    }
}

fn has_write_intent(open_flags: Option<u32>) -> bool {
    open_flags.is_some_and(|flags| {
        let access_mode = flags & O_ACCMODE;
        access_mode == O_WRONLY
            || access_mode == O_RDWR
            || flags & (O_CREAT | O_TRUNC | O_APPEND) != 0
    })
}

fn sensitive_dir_for_path(path: &str) -> Option<SensitiveDir> {
    if path == "/etc" || path.starts_with("/etc/") {
        Some(SensitiveDir::Etc)
    } else if path == "/tmp" || path.starts_with("/tmp/") {
        Some(SensitiveDir::Tmp)
    } else if path == "/dev" || path.starts_with("/dev/") {
        Some(SensitiveDir::Dev)
    } else {
        None
    }
}

fn is_dedup_candidate(event: &EnrichedEvent) -> bool {
    event.event.syscall_type == SyscallType::Openat && event.event.filename.is_some()
}

fn dedup_equivalent(existing: &EnrichedEvent, incoming: &EnrichedEvent) -> bool {
    // FR-P07 only promises same-file `openat` collapse, but the feature math
    // in FR-P05 also depends on open flags, failure results, and the enriched
    // process identity fields. We therefore merge only when every
    // feature-relevant and operator-visible field other than event_id,
    // timestamp, thread ID, and repeat_count agrees. Different filenames must
    // remain distinct (VAL-PIPELINE-017), and read/write or success/failure
    // transitions must stay separate so sensitive-write and failed-syscall
    // counters do not drift.
    existing.event.pid == incoming.event.pid
        && existing.event.ppid == incoming.event.ppid
        && existing.event.syscall_type == incoming.event.syscall_type
        && existing.event.filename == incoming.event.filename
        && existing.event.ip_address == incoming.event.ip_address
        && existing.event.port == incoming.event.port
        && existing.event.child_pid == incoming.event.child_pid
        && existing.event.open_flags == incoming.event.open_flags
        && existing.event.syscall_result == incoming.event.syscall_result
        && existing.process_name == incoming.process_name
        && existing.binary_path == incoming.binary_path
        && existing.cgroup == incoming.cgroup
        && existing.uid == incoming.uid
        && existing.ancestry_chain == incoming.ancestry_chain
        && existing.ancestry_truncated == incoming.ancestry_truncated
}

fn expand_syscall_sequence(events: &[&EnrichedEvent]) -> Vec<SyscallType> {
    let mut sequence = Vec::new();
    for event in events {
        for _ in 0..event.repeat_count.max(1) {
            sequence.push(event.event.syscall_type);
        }
    }
    sequence
}

fn build_ngram_distribution(sequence: &[SyscallType], width: usize) -> BTreeMap<String, f64> {
    if sequence.len() < width {
        return BTreeMap::new();
    }

    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    for window in sequence.windows(width) {
        let key = window
            .iter()
            .map(|syscall_type| syscall_name(*syscall_type))
            .collect::<Vec<_>>()
            .join("->");
        *counts.entry(key).or_default() += 1;
    }

    let total = u64_to_f64(counts.values().sum::<u64>());
    counts
        .into_iter()
        .map(|(key, count)| (key, u64_to_f64(count) / total))
        .collect()
}

const fn syscall_name(syscall_type: SyscallType) -> &'static str {
    match syscall_type {
        SyscallType::Execve => "Execve",
        SyscallType::Openat => "Openat",
        SyscallType::Connect => "Connect",
        SyscallType::Clone => "Clone",
    }
}

fn shannon_entropy(path_counts: &BTreeMap<String, u64>) -> f64 {
    let total = u64_to_f64(path_counts.values().sum::<u64>());
    if total == 0.0 {
        return 0.0;
    }

    // This mirrors SciPy's default natural-log entropy exactly: probabilities
    // are derived from occurrence counts and accumulated as `-p * ln(p)`.
    path_counts
        .values()
        .map(|count| {
            let probability = u64_to_f64(*count) / total;
            -probability * probability.ln()
        })
        .sum()
}

fn inter_syscall_timing_stats(events: &[&EnrichedEvent]) -> (f64, f64, f64, f64) {
    if events.len() < 2 {
        return (0.0, 0.0, 0.0, 0.0);
    }

    let intervals: Vec<f64> = events
        .windows(2)
        .map(|pair| {
            u64_to_f64(
                pair[1]
                    .event
                    .timestamp
                    .saturating_sub(pair[0].event.timestamp),
            )
        })
        .collect();

    let min_interval = intervals.iter().copied().fold(f64::INFINITY, f64::min);
    let max_interval = intervals.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let average = intervals.iter().sum::<f64>() / usize_to_f64(intervals.len());
    let variance = intervals
        .iter()
        .map(|interval| {
            let delta = *interval - average;
            delta * delta
        })
        .sum::<f64>()
        / usize_to_f64(intervals.len());

    (average, min_interval, max_interval, variance.sqrt())
}

#[allow(
    clippy::cast_precision_loss,
    reason = "FR-P05 exposes floating-point ratios, timings, and entropy; supported window-scoped counts stay far below f64 precision limits."
)]
const fn u64_to_f64(value: u64) -> f64 {
    value as f64
}

#[allow(
    clippy::cast_precision_loss,
    reason = "Window-local n-gram and timing sample counts are tiny compared with the f64 mantissa capacity."
)]
const fn usize_to_f64(value: usize) -> f64 {
    value as f64
}

#[cfg(test)]
mod tests {
    use super::{ProcessWindow, WindowAggregator};
    use mini_edr_common::{EnrichedEvent, ProcessInfo, SyscallEvent, SyscallType};

    const DEFAULT_WINDOW_NS: u64 = 5_000_000_000;
    const DEFAULT_DEDUP_WINDOW_NS: u64 = 100_000_000;

    #[test]
    fn dedup_collapses_same_file_openat_burst_into_one_record_with_repeat_count() {
        let mut window = ProcessWindow::new(4_242, 0, DEFAULT_WINDOW_NS);

        for event_id in 0_u64..100 {
            window.push_event(sample_openat_event(
                4_242,
                event_id.saturating_mul(10_000),
                event_id,
                "/tmp/dedup-target",
            ));
        }

        assert_eq!(
            window.events.len(),
            1,
            "FR-P07/TC-14 require a 100-event same-file burst to collapse before feature computation"
        );
        assert_eq!(window.events[0].repeat_count, 100);

        let features = window.compute_features(DEFAULT_WINDOW_NS, false);
        assert_eq!(features.total_syscalls, 100);
        assert_eq!(features.openat_count, 100);
        assert_eq!(features.unique_files, 1);
    }

    #[test]
    fn dedup_keeps_distinct_filenames_separate_even_when_they_interleave() {
        let mut window = ProcessWindow::new(7, 0, DEFAULT_WINDOW_NS);

        for event_id in 0_u64..100 {
            let filename = if event_id % 2 == 0 {
                "/tmp/a"
            } else {
                "/tmp/b"
            };
            window.push_event(sample_openat_event(
                7,
                event_id.saturating_mul(10_000),
                event_id,
                filename,
            ));
        }

        assert_eq!(
            window.events.len(),
            2,
            "VAL-PIPELINE-017 expects one deduplicated record per filename rather than 100 per-call records"
        );
        assert_eq!(
            window.events[0].event.event.filename.as_deref(),
            Some("/tmp/a")
        );
        assert_eq!(window.events[0].repeat_count, 50);
        assert_eq!(
            window.events[1].event.event.filename.as_deref(),
            Some("/tmp/b")
        );
        assert_eq!(window.events[1].repeat_count, 50);
    }

    #[test]
    fn dedup_treats_events_at_the_window_edge_as_separate_records() {
        let mut window = ProcessWindow::new(11, 0, DEFAULT_WINDOW_NS);

        window.push_event(sample_openat_event(11, 0, 1, "/tmp/edge"));
        window.push_event(sample_openat_event(
            11,
            DEFAULT_DEDUP_WINDOW_NS,
            2,
            "/tmp/edge",
        ));

        assert_eq!(
            window.events.len(),
            2,
            "events exactly at the dedup-window edge must stay separate so boundary jitter is retained"
        );
        assert_eq!(window.events[0].repeat_count, 1);
        assert_eq!(window.events[1].repeat_count, 1);
    }

    #[test]
    fn dedup_window_is_tunable_without_changing_the_default_constructor() {
        let mut aggregator = WindowAggregator::with_dedup_window_ms(5, 1);

        assert!(
            aggregator
                .push_event(sample_openat_event(90, 0, 1, "/tmp/tunable"))
                .is_empty()
        );
        assert!(
            aggregator
                .push_event(sample_openat_event(90, 1_500_000, 2, "/tmp/tunable"))
                .is_empty()
        );

        let partial = aggregator
            .close_process(90, 2_000_000)
            .expect("the active window should still flush on process exit");
        assert_eq!(
            partial.total_syscalls, 2,
            "a 1 ms custom dedup window must keep events 1.5 ms apart as separate records"
        );
    }

    #[test]
    fn dedup_keeps_backward_timestamp_event_separate_from_the_latest_record() {
        let mut window = ProcessWindow::new(13, 0, DEFAULT_WINDOW_NS);

        window.push_event(sample_openat_event(13, 2_000_000, 1, "/tmp/backward"));
        window.push_event(sample_openat_event(13, 1_500_000, 2, "/tmp/backward"));

        assert_eq!(
            window.events.len(),
            2,
            "per-PID canonical streams are expected to be monotonic, so a backward timestamp must not merge into the latest dedup record"
        );

        let features = window.compute_features(DEFAULT_WINDOW_NS, false);
        assert_eq!(features.total_syscalls, 2);
        assert_eq!(features.openat_count, 2);
    }

    fn sample_openat_event(
        pid: u32,
        timestamp: u64,
        event_id: u64,
        filename: &str,
    ) -> EnrichedEvent {
        EnrichedEvent {
            event: SyscallEvent {
                event_id,
                timestamp,
                pid,
                tid: pid,
                ppid: 1,
                syscall_type: SyscallType::Openat,
                filename: Some(filename.to_owned()),
                ip_address: None,
                port: None,
                child_pid: None,
                open_flags: Some(0),
                syscall_result: Some(0),
            },
            process_name: format!("proc-{pid}"),
            binary_path: format!("/usr/bin/proc-{pid}"),
            cgroup: format!("0::/mini-edr/{pid}"),
            uid: 1_000,
            ancestry_chain: vec![
                ProcessInfo {
                    pid: 1,
                    process_name: "init".to_owned(),
                    binary_path: "/sbin/init".to_owned(),
                },
                ProcessInfo {
                    pid,
                    process_name: format!("proc-{pid}"),
                    binary_path: format!("/usr/bin/proc-{pid}"),
                },
            ],
            ancestry_truncated: false,
            repeat_count: 1,
        }
    }
}
