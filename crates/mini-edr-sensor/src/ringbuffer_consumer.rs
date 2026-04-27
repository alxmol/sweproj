//! Userspace ring-buffer consumer for Mini-EDR syscall events.
//!
//! SDD §4.1.1 assigns this module the first userspace boundary after the
//! kernel-side Aya probes. The consumer drains `BPF_MAP_TYPE_RINGBUF` records,
//! validates the fixed `RawSyscallEvent` ABI, converts records into
//! `mini_edr_common::SyscallEvent`, and forwards only successfully decoded
//! events onto the Tokio `mpsc` channel consumed by the pipeline.

use crate::raw_event::{MAX_FILENAME_LEN, RawEventError, RawSyscallEvent, RawSyscallType};
use aya::maps::RingBuf;
use mini_edr_common::SyscallEvent;
use std::{
    mem, ptr,
    str::Utf8Error,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::sync::mpsc::{Sender, error::TrySendError};

/// Byte size of the fixed kernel/userspace event ABI.
///
/// Tests and fuzz harnesses use this constant to generate exact-size fixture
/// records without duplicating the `mem::size_of` expression in multiple
/// places. Keeping the value derived prevents drift when the ABI evolves.
pub const RAW_SYSCALL_EVENT_SIZE: usize = mem::size_of::<RawSyscallEvent>();

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
    next_event_id: u64,
}

impl RingBufferConsumer<()> {
    /// Construct a consumer for fixture replay without an Aya ring-buffer map.
    ///
    /// This constructor exists so TC-07/VAL-PIPELINE-001 style pre-recorded
    /// traces can pass bytes through the production deserializer and mpsc
    /// forwarding path on machines that lack `CAP_BPF`/`CAP_PERFMON`.
    #[must_use]
    pub fn for_replay(sender: Sender<SyscallEvent>) -> Self {
        Self::with_parts((), sender, RingBufferMetrics::default(), 1)
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
        Self::with_parts(ring_buffer, sender, RingBufferMetrics::default(), 1)
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

        stats
    }
}

impl<R> RingBufferConsumer<R> {
    const fn with_parts(
        ring_buffer: R,
        sender: Sender<SyscallEvent>,
        metrics: RingBufferMetrics,
        next_event_id: u64,
    ) -> Self {
        Self {
            ring_buffer,
            sender,
            metrics,
            next_event_id,
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
        let event_id = self.next_event_id;
        self.next_event_id = self.next_event_id.saturating_add(1);

        let event = match deserialize_record(bytes, event_id) {
            Ok(event) => event,
            Err(error) => {
                self.metrics.add_deserialize_error(1);
                return Err(error);
            }
        };

        // The sensor must never block the kernel-facing poller on downstream
        // work. `try_send` makes backpressure explicit: full queues increment
        // the same drop counter surfaced in health metrics, while a closed queue
        // is reported separately so the daemon can begin shutdown/reload logic.
        match self.sender.try_send(event) {
            Ok(()) => {
                self.metrics.add_received(1);
                Ok(())
            }
            Err(TrySendError::Full(_event)) => {
                self.metrics.add_dropped(1);
                Err(RingBufferConsumerError::SenderFull)
            }
            Err(TrySendError::Closed(_event)) => {
                self.metrics.add_send_error(1);
                Err(RingBufferConsumerError::SenderClosed)
            }
        }
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

    raw_to_syscall_event(&raw, event_id)
}

fn raw_to_syscall_event(
    raw: &RawSyscallEvent,
    event_id: u64,
) -> Result<SyscallEvent, RingBufferConsumerError> {
    let syscall_type = RawSyscallType::to_syscall_type(raw.syscall_type)?;
    let filename = parse_optional_filename(raw)?;

    Ok(SyscallEvent {
        event_id,
        timestamp: raw.timestamp,
        pid: raw.pid,
        tid: raw.tid,
        ppid: raw.ppid,
        syscall_type,
        filename: if matches!(syscall_type, mini_edr_common::SyscallType::Openat) {
            filename
        } else {
            None
        },
        ip_address: if matches!(syscall_type, mini_edr_common::SyscallType::Connect) {
            Some(raw.ipv4_addr)
        } else {
            None
        },
        port: if matches!(syscall_type, mini_edr_common::SyscallType::Connect) {
            Some(raw.port)
        } else {
            None
        },
        child_pid: if matches!(syscall_type, mini_edr_common::SyscallType::Clone)
            && raw.child_pid != 0
        {
            Some(raw.child_pid)
        } else {
            None
        },
        open_flags: None,
        syscall_result: None,
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
