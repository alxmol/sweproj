//! Paced `connect(2)` workload generator for the live performance harnesses.
//!
//! The real-daemon performance scripts use this helper instead of the
//! synthetic in-process perf harness so the observed throughput / CPU / RSS
//! metrics reflect the full live sensor path. Each thread repeatedly attempts a
//! localhost TCP connect against an expected-closed sentinel port; the connect
//! may fail with `ECONNREFUSED`, but the syscall still traverses the kernel
//! tracepoint that Mini-EDR monitors.

use std::{
    env,
    fs,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const MIN_TICK_MILLIS: u64 = 1;
const AF_INET: i32 = 2;
const SOCK_STREAM: i32 = 1;

#[repr(C)]
struct SockAddr {
    sa_family: u16,
    sa_data: [u8; 14],
}

#[repr(C)]
struct InAddr {
    s_addr: u32,
}

#[repr(C)]
struct SockAddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: InAddr,
    sin_zero: [u8; 8],
}

unsafe extern "C" {
    fn socket(domain: i32, socket_type: i32, protocol: i32) -> i32;
    fn connect(fd: i32, address: *const SockAddr, address_len: u32) -> i32;
    fn close(fd: i32) -> i32;
}

fn unix_time_ns() -> Result<u64, Box<dyn std::error::Error>> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_nanos()
        .try_into()?)
}

fn paced_worker(
    address: SockAddrIn,
    deadline: Instant,
    tick: Duration,
    ops_per_tick: u64,
) -> u64 {
    let mut next_tick = Instant::now() + tick;
    let mut completed = 0_u64;

    while Instant::now() < deadline {
        for _ in 0..ops_per_tick {
            if Instant::now() >= deadline {
                break;
            }
            // Use a single explicit `connect(2)` FFI call per iteration so the
            // performance harness counts one kernel connect attempt for each
            // scheduled operation instead of whatever extra userspace work a
            // higher-level networking helper might perform internally.
            unsafe {
                let fd = socket(AF_INET, SOCK_STREAM, 0);
                if fd >= 0 {
                    let _ = connect(
                        fd,
                        (&address as *const SockAddrIn).cast::<SockAddr>(),
                        u32::try_from(std::mem::size_of::<SockAddrIn>())
                            .unwrap_or(u32::MAX),
                    );
                    let _ = close(fd);
                }
            }
            completed = completed.saturating_add(1);
        }

        let now = Instant::now();
        if next_tick > now {
            thread::sleep(next_tick - now);
        }
        next_tick += tick;
    }

    completed
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let host = args.next().ok_or("missing connect-host argument")?;
    let port = args
        .next()
        .ok_or("missing connect-port argument")?
        .parse::<u16>()?;
    let duration_seconds = args
        .next()
        .ok_or("missing duration-seconds argument")?
        .parse::<u64>()?;
    let target_events_per_second = args
        .next()
        .ok_or("missing target-events-per-second argument")?
        .parse::<u64>()?;
    let thread_count = args
        .next()
        .ok_or("missing thread-count argument")?
        .parse::<usize>()?;
    let report_path = args.next().ok_or("missing report-path argument")?;
    if args.next().is_some() {
        return Err(
            "expected exactly six arguments: connect-host connect-port duration-seconds target-eps thread-count report-path".into(),
        );
    }
    if thread_count == 0 {
        return Err("thread-count must be greater than zero".into());
    }
    if target_events_per_second == 0 {
        return Err("target-events-per-second must be greater than zero".into());
    }
    if host != "127.0.0.1" {
        return Err("live_connect_load.rs currently supports only the documented 127.0.0.1 sentinel host".into());
    }

    let per_thread_target_eps = target_events_per_second.div_ceil(thread_count as u64);
    let tick_millis = if per_thread_target_eps >= 1_000 {
        MIN_TICK_MILLIS
    } else {
        (1_000 / per_thread_target_eps).max(MIN_TICK_MILLIS)
    };
    let tick = Duration::from_millis(tick_millis);
    let ops_per_thread_per_tick = ((per_thread_target_eps * tick_millis).div_ceil(1_000)).max(1);
    let scheduled_events_per_second = thread_count as u64
        * ops_per_thread_per_tick
        * (1_000 / tick_millis);
    let address = SockAddrIn {
        sin_family: AF_INET as u16,
        sin_port: port.to_be(),
        sin_addr: InAddr {
            s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        },
        sin_zero: [0; 8],
    };
    let start_wall_ns = unix_time_ns()?;
    let started_at = Instant::now();
    let deadline = started_at + Duration::from_secs(duration_seconds);

    let mut workers = Vec::with_capacity(thread_count);
    for _ in 0..thread_count {
        let address = SockAddrIn {
            sin_family: address.sin_family,
            sin_port: address.sin_port,
            sin_addr: InAddr {
                s_addr: address.sin_addr.s_addr,
            },
            sin_zero: address.sin_zero,
        };
        workers.push(thread::spawn(move || {
            paced_worker(address, deadline, tick, ops_per_thread_per_tick)
        }));
    }

    let mut generated_events_total = 0_u64;
    for worker in workers {
        generated_events_total = generated_events_total.saturating_add(
            worker
                .join()
                .map_err(|_| "load worker panicked while issuing the paced connect workload")?,
        );
    }

    let elapsed_seconds = started_at.elapsed().as_secs_f64();
    let observed_events_per_second = if elapsed_seconds == 0.0 {
        0.0
    } else {
        generated_events_total as f64 / elapsed_seconds
    };
    let end_wall_ns = unix_time_ns()?;
    fs::write(
        report_path,
        format!(
            concat!(
                "{{",
                "\"pid\":{},",
                "\"thread_count\":{},",
                "\"tick_millis\":{},",
                "\"ops_per_thread_per_tick\":{},",
                "\"requested_events_per_second\":{},",
                "\"scheduled_events_per_second\":{},",
                "\"generated_events_total\":{},",
                "\"observed_events_per_second\":{},",
                "\"connect_host\":\"{}\",",
                "\"connect_port\":{},",
                "\"start_wall_ns\":{},",
                "\"end_wall_ns\":{},",
                "\"elapsed_seconds\":{}",
                "}}\n"
            ),
            std::process::id(),
            thread_count,
            tick_millis,
            ops_per_thread_per_tick,
            target_events_per_second,
            scheduled_events_per_second,
            generated_events_total,
            observed_events_per_second,
            host,
            port,
            start_wall_ns,
            end_wall_ns,
            elapsed_seconds,
        ),
    )?;
    Ok(())
}
