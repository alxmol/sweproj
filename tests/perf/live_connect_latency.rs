//! Single-syscall helper for the real-daemon end-to-end latency harness.
//!
//! The shell wrapper launches this binary as one fresh PID per latency sample.
//! The helper records its wall-clock timestamp immediately before issuing the
//! sentinel `connect(2)`, writes that metadata to disk, and then exits so the
//! daemon can flush the resulting short-lived partial window into an alert.

use std::{
    env,
    fs,
    net::TcpStream,
    thread,
    time::Duration,
    time::{SystemTime, UNIX_EPOCH},
};

fn unix_time_ns() -> Result<u64, Box<dyn std::error::Error>> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_nanos()
        .try_into()?)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let host = args.next().ok_or("missing connect-host argument")?;
    let port = args
        .next()
        .ok_or("missing connect-port argument")?
        .parse::<u16>()?;
    let linger_ms = args
        .next()
        .ok_or("missing linger-ms argument")?
        .parse::<u64>()?;
    let metadata_path = args.next().ok_or("missing metadata-path argument")?;
    if args.next().is_some() {
        return Err("expected exactly four arguments: host port linger-ms metadata-path".into());
    }

    let pid = std::process::id();
    let start_ns = unix_time_ns()?;
    fs::write(
        &metadata_path,
        format!("{{\"pid\":{pid},\"start_ns\":{start_ns}}}\n"),
    )?;

    let _ = TcpStream::connect((host.as_str(), port));
    thread::sleep(Duration::from_millis(linger_ms));
    Ok(())
}
