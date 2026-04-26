#![no_main]

//! Coverage-guided fuzz target for `RingBufferConsumer::deserialize_record`.
//!
//! The strategy is intentionally simple and high-volume: every byte slice that
//! libFuzzer generates is treated as a candidate `RawSyscallEvent` record. That
//! means the target exercises all of the parser's boundary checks at once:
//! truncated buffers, oversized filename lengths, invalid UTF-8, unknown syscall
//! discriminators, and any future ABI drift. The target discards both `Ok` and
//! `Err` results because TC-74 cares about robustness (no crash / no panic),
//! not about steering toward only "valid" records.

use libfuzzer_sys::fuzz_target;
use mini_edr_sensor::{
    fuzzing::ringbuffer_deserialize_recorder, ringbuffer_consumer::RingBufferConsumer,
};

fuzz_target!(|data: &[u8]| {
    // The recorder keeps the target self-describing for both local runs and CI:
    // direct `cargo +nightly fuzz run ... -max_total_time=N` invocations emit a
    // summary JSON file with the observed duration and total iteration count.
    let event_id = ringbuffer_deserialize_recorder().record_iteration();

    let _ = RingBufferConsumer::deserialize_record(data, event_id);
});
