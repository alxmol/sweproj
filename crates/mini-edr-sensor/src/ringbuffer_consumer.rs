//! Userspace ring-buffer consumer for Mini-EDR syscall events.
//!
//! SDD §4.1.1 assigns this module the first userspace boundary after the
//! kernel-side Aya probes. The consumer drains `BPF_MAP_TYPE_RINGBUF` records,
//! validates the fixed `RawSyscallEvent` ABI, converts records into
//! `mini_edr_common::SyscallEvent`, and forwards only successfully decoded
//! events onto the Tokio `mpsc` channel consumed by the pipeline.

use crate::raw_event::{
    DecodedRawSyscallTag, MAX_FILENAME_LEN, RawEventError, RawSyscallEvent, RawSyscallPhase,
    RawSyscallType,
};
use aya::maps::RingBuf;
use mini_edr_common::{SyscallEvent, SyscallType};
use std::{
    collections::HashMap,
    mem, ptr,
    str::Utf8Error,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::mpsc::{Sender, error::TrySendError};

/// Byte size of the fixed kernel/userspace event ABI.
///
/// Tests and fuzz harnesses use this constant to generate exact-size fixture
/// records without duplicating the `mem::size_of` expression in multiple
/// places. Keeping the value derived prevents drift when the ABI evolves.
pub const RAW_SYSCALL_EVENT_SIZE: usize = mem::size_of::<RawSyscallEvent>();

/// Default grace period for matching an exit record to its earlier enter record.
///
/// The live daemon polls the raw ring buffer every 50 ms. A 250 ms timeout
/// gives five poll intervals for the matching exit to arrive, which is enough
/// to cover ordinary scheduler jitter without stalling the pipeline for longer
/// than a fraction of the end-to-end latency budget.
pub const DEFAULT_EXIT_PAIRING_TIMEOUT: Duration = Duration::from_millis(250);

/// Merges syscall-entry and syscall-exit raw records back into one logical event.
///
/// `openat` and `connect` emit an entry record with arguments and a separate
/// exit record with the return code. The pairer buffers whichever side arrives
/// first, joins the two when their `(pid, tid, syscall_type)` key matches, and
/// eventually times out unmatched records so the pipeline never wedges waiting
/// for an exit that was dropped in kernel or userspace.
pub struct SyscallEventPairer {
    pending_enters: HashMap<PairingKey, PendingEnterEvent>,
    pending_exits: HashMap<PairingKey, PendingExitEvent>,
    timeout: Duration,
    next_event_id: u64,
}

impl Default for SyscallEventPairer {
    fn default() -> Self {
        Self::new(DEFAULT_EXIT_PAIRING_TIMEOUT)
    }
}

impl SyscallEventPairer {
    /// Construct a pairer with a caller-specified timeout.
    #[must_use]
    pub fn new(timeout: Duration) -> Self {
        Self {
            pending_enters: HashMap::new(),
            pending_exits: HashMap::new(),
            timeout,
            next_event_id: 1,
        }
    }

    /// Convert one raw kernel record into zero or more ready userspace events.
    ///
    /// The return vector is usually empty (the pairer is still waiting for the
    /// matching side) or contains exactly one `SyscallEvent`. A vector is used
    /// so callers can handle expiry flushes and immediate matches through one
    /// interface without a second allocation path.
    ///
    /// # Errors
    ///
    /// Returns `RingBufferConsumerError` when the raw record carries an invalid
    /// discriminator or malformed filename bytes.
    pub fn process_raw_event(
        &mut self,
        raw: &RawSyscallEvent,
    ) -> Result<Vec<SyscallEvent>, RingBufferConsumerError> {
        self.process_raw_event_at(raw, Instant::now())
    }

    /// Flush timed-out pending records.
    ///
    /// Enter records are forwarded with `syscall_result = None` so the pipeline
    /// still sees the underlying syscall when its exit record went missing.
    /// Exit-only records are dropped after the timeout because they lack the
    /// filename/IP context the downstream stages need.
    #[must_use]
    pub fn flush_expired(&mut self) -> Vec<SyscallEvent> {
        self.flush_expired_at(Instant::now())
    }

    fn process_raw_event_at(
        &mut self,
        raw: &RawSyscallEvent,
        now: Instant,
    ) -> Result<Vec<SyscallEvent>, RingBufferConsumerError> {
        let decoded = decode_raw_event(raw)?;
        let key = PairingKey::new(decoded.pid, decoded.tid, decoded.syscall_type);

        let ready_events = match (decoded.syscall_type, decoded.phase) {
            (SyscallType::Execve, RawSyscallPhase::Enter)
            | (SyscallType::Clone, RawSyscallPhase::Exit) => {
                vec![self.assign_event_id(decoded.into_syscall_event())]
            }
            (SyscallType::Openat | SyscallType::Connect, RawSyscallPhase::Enter) => {
                if let Some(pending_exit) = self.pending_exits.remove(&key) {
                    if now.duration_since(pending_exit.first_seen_at) < self.timeout {
                        let mut event = decoded.into_syscall_event();
                        event.syscall_result = Some(pending_exit.syscall_result);
                        vec![self.assign_event_id(event)]
                    } else {
                        self.pending_enters.insert(
                            key,
                            PendingEnterEvent {
                                first_seen_at: now,
                                event: decoded.into_syscall_event(),
                            },
                        );
                        Vec::new()
                    }
                } else {
                    self.pending_enters.insert(
                        key,
                        PendingEnterEvent {
                            first_seen_at: now,
                            event: decoded.into_syscall_event(),
                        },
                    );
                    Vec::new()
                }
            }
            (SyscallType::Openat | SyscallType::Connect, RawSyscallPhase::Exit) => {
                let syscall_result = decoded
                    .syscall_result
                    .expect("decoded exit records always carry a syscall_result payload");
                if let Some(mut pending_enter) = self.pending_enters.remove(&key) {
                    if now.duration_since(pending_enter.first_seen_at) < self.timeout {
                        pending_enter.event.syscall_result = Some(syscall_result);
                        vec![self.assign_event_id(pending_enter.event)]
                    } else {
                        self.pending_exits.insert(
                            key,
                            PendingExitEvent {
                                first_seen_at: now,
                                syscall_result,
                            },
                        );
                        Vec::new()
                    }
                } else {
                    self.pending_exits.insert(
                        key,
                        PendingExitEvent {
                            first_seen_at: now,
                            syscall_result,
                        },
                    );
                    Vec::new()
                }
            }
            // Mini-EDR intentionally has no syscall-entry clone probe because
            // the validation contract needs the child PID returned by the
            // kernel, which is only available from `sys_exit_clone`.
            (SyscallType::Clone, RawSyscallPhase::Enter)
            // Execve currently has only an entry probe because there is no
            // downstream feature that needs the return code.
            | (SyscallType::Execve, RawSyscallPhase::Exit) => Vec::new(),
        };

        Ok(ready_events)
    }

    fn flush_expired_at(&mut self, now: Instant) -> Vec<SyscallEvent> {
        let expired_enter_keys = self
            .pending_enters
            .iter()
            .filter_map(|(key, pending)| {
                if now.duration_since(pending.first_seen_at) >= self.timeout {
                    Some(*key)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        let expired_exit_keys = self
            .pending_exits
            .iter()
            .filter_map(|(key, pending)| {
                if now.duration_since(pending.first_seen_at) >= self.timeout {
                    Some(*key)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        let mut ready_events = Vec::with_capacity(expired_enter_keys.len());
        for key in expired_enter_keys {
            if let Some(pending) = self.pending_enters.remove(&key) {
                ready_events.push(self.assign_event_id(pending.event));
            }
        }
        for key in expired_exit_keys {
            let _ = self.pending_exits.remove(&key);
        }

        ready_events
    }

    const fn assign_event_id(&mut self, mut event: SyscallEvent) -> SyscallEvent {
        event.event_id = self.next_event_id;
        self.next_event_id = self.next_event_id.saturating_add(1);
        event
    }
}

/// Consumes Mini-EDR ring-buffer records and forwards domain events downstream.
///
/// The generic parameter is the backing ring-buffer handle. Production code uses
/// `RingBufferConsumer<RingBuf<T>>` constructed by `new`, while fixture replay
/// and unit tests use `RingBufferConsumer<()>` through `for_replay` to exercise
/// the same deserializer without requiring kernel privileges.
pub struct RingBufferConsumer<R = ()> {
    ring_buffer: R,
    sender: Sender<SyscallEvent>,
    metrics: RingBufferMetrics,
    pairer: SyscallEventPairer,
}

impl RingBufferConsumer<()> {
    /// Construct a consumer for fixture replay without an Aya ring-buffer map.
    ///
    /// This constructor exists so TC-07/VAL-PIPELINE-001 style pre-recorded
    /// traces can pass bytes through the production deserializer and mpsc
    /// forwarding path on machines that lack `CAP_BPF`/`CAP_PERFMON`.
    #[must_use]
    pub fn for_replay(sender: Sender<SyscallEvent>) -> Self {
        Self::with_parts(
            (),
            sender,
            RingBufferMetrics::default(),
            SyscallEventPairer::default(),
        )
    }

    /// Deserialize one raw ring-buffer record into the shared domain event.
    ///
    /// `event_id` is supplied by the caller because the kernel ABI intentionally
    /// does not include userspace sequencing state. Production polling assigns a
    /// monotonically increasing identifier before each decode attempt.
    ///
    /// # Errors
    ///
    /// Returns `RingBufferConsumerError` for malformed lengths, unknown syscall
    /// discriminators, impossible filename lengths, or non-UTF-8 filenames.
    pub fn deserialize_record(
        bytes: &[u8],
        event_id: u64,
    ) -> Result<SyscallEvent, RingBufferConsumerError> {
        deserialize_record(bytes, event_id)
    }

    /// Convert one already-copied raw kernel event into the shared domain type.
    ///
    /// This helper exists for daemon-owned lifecycle wiring where privileged
    /// probe management has already copied `RawSyscallEvent` records out of the
    /// Aya ring buffer. Reusing the production conversion path keeps the live
    /// daemon and the replay/fuzz harnesses on one ABI interpretation.
    ///
    /// # Errors
    ///
    /// Returns the same deserialization errors as [`Self::deserialize_record`]
    /// when the raw record contains an unknown syscall discriminator or
    /// malformed filename metadata.
    pub fn syscall_event_from_raw_event(
        raw: &RawSyscallEvent,
        event_id: u64,
    ) -> Result<SyscallEvent, RingBufferConsumerError> {
        raw_to_syscall_event(raw, event_id)
    }
}

impl<T> RingBufferConsumer<RingBuf<T>> {
    /// Construct a production consumer around an Aya `RingBuf` map.
    ///
    /// The returned consumer owns the ring-buffer handle and sends decoded
    /// `SyscallEvent` values to the supplied bounded Tokio mpsc channel. The
    /// daemon should retain a clone of `metrics()` for health endpoints.
    #[must_use]
    pub fn new(ring_buffer: RingBuf<T>, sender: Sender<SyscallEvent>) -> Self {
        Self::with_parts(
            ring_buffer,
            sender,
            RingBufferMetrics::default(),
            SyscallEventPairer::default(),
        )
    }

    /// Drain every record currently available from the Aya ring buffer.
    ///
    /// Aya's `RingBuf::next` is non-blocking: it returns `None` when the shared
    /// buffer is empty and expects the caller to wait on the map fd (for example
    /// with epoll/`AsyncFd`) before polling again. This method therefore performs
    /// one drain pass and reports per-record outcomes instead of sleeping.
    #[must_use]
    pub fn poll_available(&mut self) -> RingBufferPollStats {
        let mut stats = RingBufferPollStats::default();

        let expired_before_poll = self.pairer.flush_expired();
        if self.forward_ready_events(expired_before_poll).is_err() {
            stats.send_failures += 1;
        }

        // Only one `RingBufItem` may be outstanding at a time. Copying the item
        // into an owned Vec before processing releases Aya's borrow immediately,
        // allowing `process_record` to update counters and the mpsc sender
        // without fighting a borrow of `self.ring_buffer`.
        loop {
            let Some(bytes) = ({ self.ring_buffer.next().map(|item| item.to_vec()) }) else {
                break;
            };

            stats.records_seen += 1;
            match self.process_record(&bytes) {
                Ok(()) => stats.delivered_records += 1,
                Err(error) if error.is_deserialize_error() => stats.malformed_records += 1,
                Err(RingBufferConsumerError::SenderFull) => stats.dropped_records += 1,
                Err(RingBufferConsumerError::SenderClosed) => stats.send_failures += 1,
                Err(_) => stats.malformed_records += 1,
            }
        }

        let expired_after_poll = self.pairer.flush_expired();
        if self.forward_ready_events(expired_after_poll).is_err() {
            stats.send_failures += 1;
        }

        stats
    }
}

impl<R> RingBufferConsumer<R> {
    const fn with_parts(
        ring_buffer: R,
        sender: Sender<SyscallEvent>,
        metrics: RingBufferMetrics,
        pairer: SyscallEventPairer,
    ) -> Self {
        Self {
            ring_buffer,
            sender,
            metrics,
            pairer,
        }
    }

    /// Return cloneable metrics for daemon health reporting.
    ///
    /// The metrics handle uses atomics so future daemon tasks can expose health
    /// snapshots while the consumer task continues polling the ring buffer.
    #[must_use]
    pub fn metrics(&self) -> RingBufferMetrics {
        self.metrics.clone()
    }

    /// Callback target for lost-sample notifications from the transport layer.
    ///
    /// Linux BPF ring buffers report producer-side drops through failed kernel
    /// submissions rather than the perf-buffer `lost_samples` event stream. The
    /// sensor manager/overflow feature can still route its observed lost-sample
    /// count here, giving all drop sources one health counter as required by
    /// FR-S06 and VAL-SENSOR-013.
    pub fn record_lost_samples(&self, lost_samples: u64) {
        self.metrics.add_dropped(lost_samples);
    }

    /// Flush any timed-out enter/exit pairs through the downstream sender.
    ///
    /// # Errors
    ///
    /// Returns `SenderFull` or `SenderClosed` when forwarding one of the
    /// expired ready events fails.
    pub fn flush_expired_pairs(&mut self) -> Result<(), RingBufferConsumerError> {
        let expired_events = self.pairer.flush_expired();
        self.forward_ready_events(expired_events)
    }

    /// Deserialize and forward one ring-buffer record.
    ///
    /// The method returns an error for the specific record that failed while
    /// leaving the consumer usable for subsequent records. That per-record error
    /// behavior is the TC-68/VAL-SENSOR-016 guardrail against malformed bytes
    /// taking down the daemon.
    ///
    /// # Errors
    ///
    /// Returns a deserialization error for malformed input, `SenderFull` when
    /// the bounded mpsc channel applies backpressure, or `SenderClosed` when the
    /// downstream pipeline has shut down.
    pub fn process_record(&mut self, bytes: &[u8]) -> Result<(), RingBufferConsumerError> {
        let raw = match deserialize_raw_event(bytes) {
            Ok(raw) => raw,
            Err(error) => {
                self.metrics.add_deserialize_error(1);
                return Err(error);
            }
        };

        let ready_events = match self.pairer.process_raw_event(&raw) {
            Ok(ready_events) => ready_events,
            Err(error) => {
                self.metrics.add_deserialize_error(1);
                return Err(error);
            }
        };

        self.forward_ready_events(ready_events)
    }

    fn forward_ready_events(
        &self,
        ready_events: Vec<SyscallEvent>,
    ) -> Result<(), RingBufferConsumerError> {
        let mut first_error = None;
        for event in ready_events {
            // The sensor must never block the kernel-facing poller on downstream
            // work. `try_send` makes backpressure explicit: full queues
            // increment the same drop counter surfaced in health metrics, while
            // a closed queue is reported separately so the daemon can begin
            // shutdown/reload logic.
            match self.sender.try_send(event) {
                Ok(()) => self.metrics.add_received(1),
                Err(TrySendError::Full(_event)) => {
                    self.metrics.add_dropped(1);
                    first_error.get_or_insert(RingBufferConsumerError::SenderFull);
                }
                Err(TrySendError::Closed(_event)) => {
                    self.metrics.add_send_error(1);
                    first_error.get_or_insert(RingBufferConsumerError::SenderClosed);
                }
            }
        }

        first_error.map_or(Ok(()), Err)
    }
}

/// Cloneable atomic counters maintained by `RingBufferConsumer`.
#[derive(Clone, Default)]
pub struct RingBufferMetrics {
    received: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
    deserialize_errors: Arc<AtomicU64>,
    send_errors: Arc<AtomicU64>,
}

impl RingBufferMetrics {
    /// Return a point-in-time copy of all ring-buffer counters.
    #[must_use]
    pub fn snapshot(&self) -> RingBufferMetricsSnapshot {
        RingBufferMetricsSnapshot {
            events_received_total: self.received.load(Ordering::Relaxed),
            events_dropped_total: self.dropped.load(Ordering::Relaxed),
            deserialize_errors_total: self.deserialize_errors.load(Ordering::Relaxed),
            send_errors_total: self.send_errors.load(Ordering::Relaxed),
        }
    }

    fn add_received(&self, count: u64) {
        self.received.fetch_add(count, Ordering::Relaxed);
    }

    fn add_dropped(&self, count: u64) {
        self.dropped.fetch_add(count, Ordering::Relaxed);
    }

    fn add_deserialize_error(&self, count: u64) {
        self.deserialize_errors.fetch_add(count, Ordering::Relaxed);
    }

    fn add_send_error(&self, count: u64) {
        self.send_errors.fetch_add(count, Ordering::Relaxed);
    }
}

/// Immutable snapshot of ring-buffer consumer health counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RingBufferMetricsSnapshot {
    /// Number of decoded events successfully sent to the pipeline channel.
    pub events_received_total: u64,
    /// Number of events dropped due to ring overflow or userspace backpressure.
    pub events_dropped_total: u64,
    /// Number of ring-buffer records rejected by the deserializer.
    pub deserialize_errors_total: u64,
    /// Number of records that could not be sent because the receiver closed.
    pub send_errors_total: u64,
}

/// Outcome counters for a single non-blocking ring-buffer drain pass.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RingBufferPollStats {
    /// Total records removed from the ring buffer during this drain pass.
    pub records_seen: u64,
    /// Records decoded and sent to the pipeline.
    pub delivered_records: u64,
    /// Records rejected as malformed without panicking.
    pub malformed_records: u64,
    /// Records dropped because the mpsc channel was full.
    pub dropped_records: u64,
    /// Records that could not be sent because the receiver was closed.
    pub send_failures: u64,
}

/// Errors returned by `RingBufferConsumer` while handling one record.
#[derive(Debug, thiserror::Error)]
pub enum RingBufferConsumerError {
    /// The record length did not match the fixed `RawSyscallEvent` ABI.
    #[error("malformed ring-buffer record length {actual} bytes; expected {expected}")]
    MalformedRecordLength {
        /// Actual number of bytes received from the ring buffer.
        actual: usize,
        /// Expected `RawSyscallEvent` byte size.
        expected: usize,
    },
    /// The raw filename length exceeded the fixed payload buffer.
    #[error("raw filename length {actual} exceeds max {max}")]
    FilenameLengthOutOfRange {
        /// Length claimed by the raw record.
        actual: usize,
        /// Maximum bytes available in the raw filename buffer.
        max: usize,
    },
    /// The raw filename bytes were not valid UTF-8.
    #[error("filename bytes were not valid UTF-8: {0}")]
    InvalidFilenameUtf8(#[from] Utf8Error),
    /// The raw syscall discriminator failed ABI validation.
    #[error(transparent)]
    RawEvent(#[from] RawEventError),
    /// The pipeline channel was full and the event was dropped.
    #[error("syscall event channel is full")]
    SenderFull,
    /// The pipeline channel receiver was closed.
    #[error("syscall event channel is closed")]
    SenderClosed,
}

impl RingBufferConsumerError {
    const fn is_deserialize_error(&self) -> bool {
        matches!(
            self,
            Self::MalformedRecordLength { .. }
                | Self::FilenameLengthOutOfRange { .. }
                | Self::InvalidFilenameUtf8(_)
                | Self::RawEvent(_)
        )
    }
}

fn deserialize_record(
    bytes: &[u8],
    event_id: u64,
) -> Result<SyscallEvent, RingBufferConsumerError> {
    let raw = deserialize_raw_event(bytes)?;
    raw_to_syscall_event(&raw, event_id)
}

fn deserialize_raw_event(bytes: &[u8]) -> Result<RawSyscallEvent, RingBufferConsumerError> {
    if bytes.len() != RAW_SYSCALL_EVENT_SIZE {
        return Err(RingBufferConsumerError::MalformedRecordLength {
            actual: bytes.len(),
            expected: RAW_SYSCALL_EVENT_SIZE,
        });
    }

    let mut raw = RawSyscallEvent::default();
    // SAFETY: `raw` is a valid, properly aligned destination, and the length
    // check above proves `bytes` contains exactly one `RawSyscallEvent` worth of
    // initialized bytes. Copying into an owned value avoids creating an aligned
    // reference to the possibly unaligned ring-buffer byte slice.
    unsafe {
        ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            (&raw mut raw).cast::<u8>(),
            RAW_SYSCALL_EVENT_SIZE,
        );
    }

    Ok(raw)
}

fn raw_to_syscall_event(
    raw: &RawSyscallEvent,
    event_id: u64,
) -> Result<SyscallEvent, RingBufferConsumerError> {
    let mut event = decode_raw_event(raw)?.into_syscall_event();
    event.event_id = event_id;
    Ok(event)
}

fn decode_raw_event(raw: &RawSyscallEvent) -> Result<DecodedRawEvent, RingBufferConsumerError> {
    let DecodedRawSyscallTag {
        syscall_type,
        phase,
    } = RawSyscallType::decode_wire(raw.syscall_type)?;
    let filename = parse_optional_filename(raw)?;

    Ok(DecodedRawEvent {
        timestamp: raw.timestamp,
        pid: raw.pid,
        tid: raw.tid,
        ppid: raw.ppid,
        syscall_type,
        phase,
        filename: if matches!(syscall_type, SyscallType::Openat)
            && matches!(phase, RawSyscallPhase::Enter)
        {
            filename
        } else {
            None
        },
        ip_address: if matches!(syscall_type, SyscallType::Connect)
            && matches!(phase, RawSyscallPhase::Enter)
        {
            Some(raw.ipv4_addr)
        } else {
            None
        },
        port: if matches!(syscall_type, SyscallType::Connect)
            && matches!(phase, RawSyscallPhase::Enter)
        {
            Some(raw.port)
        } else {
            None
        },
        child_pid: if matches!(syscall_type, SyscallType::Clone)
            && matches!(phase, RawSyscallPhase::Exit)
            && raw.syscall_result > 0
        {
            Some(raw.syscall_result.cast_unsigned())
        } else {
            None
        },
        open_flags: if matches!(syscall_type, SyscallType::Openat)
            && matches!(phase, RawSyscallPhase::Enter)
        {
            Some(raw.open_flags)
        } else {
            None
        },
        syscall_result: if matches!(phase, RawSyscallPhase::Exit) {
            Some(raw.syscall_result)
        } else {
            None
        },
    })
}

fn parse_optional_filename(
    raw: &RawSyscallEvent,
) -> Result<Option<String>, RingBufferConsumerError> {
    let filename_len = usize::from(raw.filename_len);
    if filename_len > MAX_FILENAME_LEN {
        return Err(RingBufferConsumerError::FilenameLengthOutOfRange {
            actual: filename_len,
            max: MAX_FILENAME_LEN,
        });
    }
    if filename_len == 0 {
        return Ok(None);
    }

    // The eBPF probe records the helper-returned string length excluding the
    // trailing NUL, but defensive NUL trimming keeps fixture/replay bytes from
    // leaking padding into the domain string if a future kernel helper changes
    // that convention or a corrupted record includes embedded terminators.
    let raw_bytes = &raw.filename[..filename_len];
    let logical_len = raw_bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(filename_len);
    if logical_len == 0 {
        return Ok(None);
    }

    Ok(Some(
        std::str::from_utf8(&raw_bytes[..logical_len])?.to_owned(),
    ))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DecodedRawEvent {
    timestamp: u64,
    pid: u32,
    tid: u32,
    ppid: u32,
    syscall_type: SyscallType,
    phase: RawSyscallPhase,
    filename: Option<String>,
    ip_address: Option<[u8; 4]>,
    port: Option<u16>,
    child_pid: Option<u32>,
    open_flags: Option<u32>,
    syscall_result: Option<i32>,
}

impl DecodedRawEvent {
    fn into_syscall_event(self) -> SyscallEvent {
        SyscallEvent {
            event_id: 0,
            timestamp: self.timestamp,
            pid: self.pid,
            tid: self.tid,
            ppid: self.ppid,
            syscall_type: self.syscall_type,
            filename: self.filename,
            ip_address: self.ip_address,
            port: self.port,
            child_pid: self.child_pid,
            open_flags: self.open_flags,
            syscall_result: self.syscall_result,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct PairingKey {
    pid: u32,
    tid: u32,
    syscall_type: SyscallType,
}

impl PairingKey {
    const fn new(pid: u32, tid: u32, syscall_type: SyscallType) -> Self {
        Self {
            pid,
            tid,
            syscall_type,
        }
    }
}

struct PendingEnterEvent {
    first_seen_at: Instant,
    event: SyscallEvent,
}

struct PendingExitEvent {
    first_seen_at: Instant,
    syscall_result: i32,
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_EXIT_PAIRING_TIMEOUT, SyscallEventPairer};
    use crate::raw_event::{RawSyscallEvent, RawSyscallPhase, RawSyscallType};
    use mini_edr_common::SyscallType;
    use std::time::{Duration, Instant};

    #[test]
    fn pairer_merges_openat_enter_and_exit_records_into_one_event() {
        let mut pairer = SyscallEventPairer::new(DEFAULT_EXIT_PAIRING_TIMEOUT);
        let now = Instant::now();
        let enter = sample_raw_event(RawSyscallType::Openat, RawSyscallPhase::Enter);
        let exit = sample_raw_event(RawSyscallType::Openat, RawSyscallPhase::Exit);

        assert!(
            pairer
                .process_raw_event_at(&enter, now)
                .expect("enter record decodes")
                .is_empty()
        );
        let ready = pairer
            .process_raw_event_at(&exit, now + Duration::from_millis(10))
            .expect("exit record decodes");

        assert_eq!(ready.len(), 1);
        let event = &ready[0];
        assert_eq!(event.event_id, 1);
        assert_eq!(event.syscall_type, SyscallType::Openat);
        assert_eq!(event.filename.as_deref(), Some("/tmp/paired-openat"));
        assert_eq!(event.open_flags, Some(0x241));
        assert_eq!(event.syscall_result, Some(3));
    }

    #[test]
    fn pairer_drops_unmatched_exit_after_timeout_without_emitting_event() {
        let mut pairer = SyscallEventPairer::new(Duration::from_millis(50));
        let now = Instant::now();
        let exit = sample_raw_event(RawSyscallType::Connect, RawSyscallPhase::Exit);

        assert!(
            pairer
                .process_raw_event_at(&exit, now)
                .expect("exit record decodes")
                .is_empty()
        );
        assert!(
            pairer
                .flush_expired_at(now + Duration::from_millis(60))
                .is_empty(),
            "unmatched exits should age out silently because they lack entry arguments"
        );
    }

    #[test]
    fn pairer_handles_exit_before_enter_race_within_timeout() {
        let mut pairer = SyscallEventPairer::new(Duration::from_millis(75));
        let now = Instant::now();
        let exit = sample_raw_event(RawSyscallType::Openat, RawSyscallPhase::Exit);
        let enter = sample_raw_event(RawSyscallType::Openat, RawSyscallPhase::Enter);

        assert!(
            pairer
                .process_raw_event_at(&exit, now)
                .expect("exit record decodes")
                .is_empty()
        );
        let ready = pairer
            .process_raw_event_at(&enter, now + Duration::from_millis(10))
            .expect("enter record decodes");

        assert_eq!(ready.len(), 1);
        let event = &ready[0];
        assert_eq!(event.syscall_type, SyscallType::Openat);
        assert_eq!(event.filename.as_deref(), Some("/tmp/paired-openat"));
        assert_eq!(event.syscall_result, Some(3));
    }

    #[test]
    fn pairer_flushes_unmatched_enter_after_timeout_with_missing_result() {
        let mut pairer = SyscallEventPairer::new(Duration::from_millis(50));
        let now = Instant::now();
        let enter = sample_raw_event(RawSyscallType::Openat, RawSyscallPhase::Enter);

        assert!(
            pairer
                .process_raw_event_at(&enter, now)
                .expect("enter record decodes")
                .is_empty()
        );
        let ready = pairer.flush_expired_at(now + Duration::from_millis(60));

        assert_eq!(ready.len(), 1);
        let event = &ready[0];
        assert_eq!(event.syscall_type, SyscallType::Openat);
        assert_eq!(event.open_flags, Some(0x241));
        assert_eq!(event.syscall_result, None);
    }

    fn sample_raw_event(syscall_type: RawSyscallType, phase: RawSyscallPhase) -> RawSyscallEvent {
        let mut raw = RawSyscallEvent {
            timestamp: 1_713_000_000_123_456_789,
            pid: 4_242,
            tid: 4_242,
            ppid: 1_001,
            syscall_type: syscall_type.encode_wire(phase),
            ..RawSyscallEvent::default()
        };
        match (syscall_type, phase) {
            (RawSyscallType::Openat, RawSyscallPhase::Enter) => {
                let path = b"/tmp/paired-openat";
                raw.filename[..path.len()].copy_from_slice(path);
                raw.filename_len = u16::try_from(path.len()).expect("path length fits raw ABI");
                raw.open_flags = 0x241;
            }
            (RawSyscallType::Openat, RawSyscallPhase::Exit) => {
                raw.syscall_result = 3;
            }
            (RawSyscallType::Connect, RawSyscallPhase::Enter) => {
                raw.ipv4_addr = [127, 0, 0, 1];
                raw.port = 51_234;
            }
            (RawSyscallType::Connect, RawSyscallPhase::Exit) => {
                raw.syscall_result = -111;
            }
            (RawSyscallType::Clone, RawSyscallPhase::Exit) => {
                raw.syscall_result = 4_201;
            }
            _ => {}
        }
        raw
    }
}
