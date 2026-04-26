//! Integration tests for userspace ring-buffer deserialization and forwarding.
//!
//! These tests exercise the fixture/replay path for TC-07 and TC-68 without
//! requiring `CAP_BPF`. Handcrafted byte buffers keep the ABI expectations visible
//! next to the assertions that protect malformed-input robustness.

use mini_edr_common::SyscallType;
use mini_edr_sensor::raw_event::{MAX_FILENAME_LEN, RawSyscallEvent, RawSyscallType};
use mini_edr_sensor::ringbuffer_consumer::{
    RAW_SYSCALL_EVENT_SIZE, RingBufferConsumer, RingBufferConsumerError,
};
use std::{mem, panic, ptr, slice};
use tokio::sync::mpsc;

#[test]
fn ringbuffer_consumer_valid_openat_record_deserializes_to_syscall_event() {
    let mut raw = sample_raw_event(RawSyscallType::Openat);
    write_filename(&mut raw, "/tmp/rb-bench-42");

    let event = RingBufferConsumer::deserialize_record(&raw_event_bytes(&raw), 7)
        .expect("valid openat bytes deserialize");

    assert_eq!(event.event_id, 7);
    assert_eq!(event.timestamp, raw.timestamp);
    assert_eq!(event.pid, raw.pid);
    assert_eq!(event.tid, raw.tid);
    assert_eq!(event.ppid, raw.ppid);
    assert_eq!(event.syscall_type, SyscallType::Openat);
    assert_eq!(event.filename.as_deref(), Some("/tmp/rb-bench-42"));
    assert_eq!(event.ip_address, None);
    assert_eq!(event.port, None);
    assert_eq!(event.child_pid, None);
}

#[test]
fn ringbuffer_consumer_valid_connect_and_clone_records_preserve_typed_arguments() {
    let mut connect = sample_raw_event(RawSyscallType::Connect);
    connect.ipv4_addr = [127, 0, 0, 1];
    connect.port = 51_234;

    let connect_event = RingBufferConsumer::deserialize_record(&raw_event_bytes(&connect), 11)
        .expect("valid connect bytes deserialize");
    assert_eq!(connect_event.syscall_type, SyscallType::Connect);
    assert_eq!(connect_event.ip_address, Some([127, 0, 0, 1]));
    assert_eq!(connect_event.port, Some(51_234));
    assert_eq!(connect_event.filename, None);
    assert_eq!(connect_event.child_pid, None);

    let mut clone = sample_raw_event(RawSyscallType::Clone);
    clone.child_pid = 4_201;

    let clone_event = RingBufferConsumer::deserialize_record(&raw_event_bytes(&clone), 12)
        .expect("valid clone bytes deserialize");
    assert_eq!(clone_event.syscall_type, SyscallType::Clone);
    assert_eq!(clone_event.child_pid, Some(4_201));
}

#[test]
fn ringbuffer_consumer_forwards_valid_records_to_mpsc_sender() {
    let (sender, mut receiver) = mpsc::channel(4);
    let mut consumer = RingBufferConsumer::for_replay(sender);
    let mut raw = sample_raw_event(RawSyscallType::Openat);
    write_filename(&mut raw, "/tmp/forwarded");

    consumer
        .process_record(&raw_event_bytes(&raw))
        .expect("valid record forwards");

    let forwarded = receiver.try_recv().expect("one event forwarded");
    assert_eq!(forwarded.event_id, 1);
    assert_eq!(forwarded.filename.as_deref(), Some("/tmp/forwarded"));
    assert_eq!(consumer.metrics().snapshot().events_received_total, 1);
}

#[test]
fn ringbuffer_consumer_drop_counter_increments_from_lost_samples_callback() {
    let (sender, _receiver) = mpsc::channel(4);
    let consumer = RingBufferConsumer::for_replay(sender);

    consumer.record_lost_samples(37);
    consumer.record_lost_samples(5);

    assert_eq!(consumer.metrics().snapshot().events_dropped_total, 42);
}

#[test]
fn ringbuffer_consumer_backpressure_full_channel_counts_dropped_event() {
    let (sender, _receiver) = mpsc::channel(1);
    let mut consumer = RingBufferConsumer::for_replay(sender);
    let raw = sample_raw_event(RawSyscallType::Execve);
    let bytes = raw_event_bytes(&raw);

    consumer
        .process_record(&bytes)
        .expect("first event occupies the bounded channel");
    let error = consumer
        .process_record(&bytes)
        .expect_err("second event hits channel backpressure");

    assert!(matches!(error, RingBufferConsumerError::SenderFull));
    assert_eq!(consumer.metrics().snapshot().events_received_total, 1);
    assert_eq!(consumer.metrics().snapshot().events_dropped_total, 1);
}

#[test]
fn malformed_bytes_truncated_record_returns_err_without_panic() {
    let truncated = vec![0_u8; RAW_SYSCALL_EVENT_SIZE - 1];

    let result = panic::catch_unwind(|| RingBufferConsumer::deserialize_record(&truncated, 1));

    assert!(result.is_ok(), "malformed input must not panic");
    assert!(matches!(
        result.expect("catch_unwind result present"),
        Err(RingBufferConsumerError::MalformedRecordLength { .. })
    ));
}

#[test]
fn malformed_bytes_garbage_discriminator_returns_err_without_panic() {
    let mut raw = sample_raw_event(RawSyscallType::Execve);
    raw.syscall_type = u32::MAX;

    let result =
        panic::catch_unwind(|| RingBufferConsumer::deserialize_record(&raw_event_bytes(&raw), 1));

    assert!(result.is_ok(), "unknown syscall type must not panic");
    assert!(matches!(
        result.expect("catch_unwind result present"),
        Err(RingBufferConsumerError::RawEvent(_))
    ));
}

#[test]
fn malformed_bytes_invalid_utf8_filename_returns_err_without_panic() {
    let mut raw = sample_raw_event(RawSyscallType::Openat);
    raw.filename_len = 2;
    raw.filename[0] = 0xff;
    raw.filename[1] = 0xfe;

    let result =
        panic::catch_unwind(|| RingBufferConsumer::deserialize_record(&raw_event_bytes(&raw), 1));

    assert!(result.is_ok(), "invalid UTF-8 must not panic");
    assert!(matches!(
        result.expect("catch_unwind result present"),
        Err(RingBufferConsumerError::InvalidFilenameUtf8(_))
    ));
}

#[test]
fn malformed_bytes_oversized_filename_len_returns_err_without_panic() {
    let mut raw = sample_raw_event(RawSyscallType::Openat);
    raw.filename_len = u16::try_from(MAX_FILENAME_LEN + 1).expect("test length fits u16");

    let result =
        panic::catch_unwind(|| RingBufferConsumer::deserialize_record(&raw_event_bytes(&raw), 1));

    assert!(result.is_ok(), "oversized filename length must not panic");
    assert!(matches!(
        result.expect("catch_unwind result present"),
        Err(RingBufferConsumerError::FilenameLengthOutOfRange { .. })
    ));
}

fn sample_raw_event(syscall_type: RawSyscallType) -> RawSyscallEvent {
    RawSyscallEvent {
        timestamp: 1_713_000_000_123_456_789,
        pid: 4_242,
        tid: 4_242,
        ppid: 1_001,
        syscall_type: syscall_type as u32,
        ..RawSyscallEvent::default()
    }
}

fn write_filename(raw: &mut RawSyscallEvent, filename: &str) {
    let bytes = filename.as_bytes();
    assert!(bytes.len() <= MAX_FILENAME_LEN);
    raw.filename[..bytes.len()].copy_from_slice(bytes);
    raw.filename_len = u16::try_from(bytes.len()).expect("filename length fits raw ABI");
}

fn raw_event_bytes(raw: &RawSyscallEvent) -> Vec<u8> {
    assert_eq!(mem::size_of::<RawSyscallEvent>(), RAW_SYSCALL_EVENT_SIZE);
    // SAFETY: `raw` is a properly initialized `RawSyscallEvent` that lives for
    // the duration of this copy, and the byte slice length exactly matches the
    // C-compatible ABI size asserted above.
    unsafe {
        slice::from_raw_parts(
            ptr::from_ref::<RawSyscallEvent>(raw).cast::<u8>(),
            RAW_SYSCALL_EVENT_SIZE,
        )
    }
    .to_vec()
}
