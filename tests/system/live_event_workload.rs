//! Helper binary for the live event-to-alert correlation system test.
//!
//! The shell harness launches this helper as a brand-new PID after the daemon
//! is already running. The helper then performs a burst of `openat` activity
//! against a readable canary file, attempts one outbound `connect`, and lingers
//! briefly so the daemon can correlate the resulting alert back to the exact
//! userspace PID the harness recorded.

use std::{
    env,
    fs::{self, File},
    io::Read,
    net::TcpStream,
    thread,
    time::Duration,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let file_path = args
        .next()
        .ok_or("missing file path argument")?;
    let repeat_count = args
        .next()
        .ok_or("missing repeat-count argument")?
        .parse::<u32>()?;
    let host = args
        .next()
        .ok_or("missing connect-host argument")?;
    let port = args
        .next()
        .ok_or("missing connect-port argument")?
        .parse::<u16>()?;
    let linger_ms = args
        .next()
        .ok_or("missing linger-ms argument")?
        .parse::<u64>()?;
    let pid_path = args
        .next()
        .ok_or("missing pid-path argument")?;
    if args.next().is_some() {
        return Err("expected exactly six arguments".into());
    }

    fs::write(&pid_path, std::process::id().to_string())?;

    // Spread the openat burst across a short interval so the live daemon has a
    // realistic chance to drain the ring buffer even on a noisy host.
    let mut single_byte = [0_u8; 1];
    for _ in 0..repeat_count {
        let mut handle = File::open(&file_path)?;
        let _ = handle.read(&mut single_byte)?;
        thread::sleep(Duration::from_millis(5));
    }

    let _ = TcpStream::connect((host.as_str(), port));
    thread::sleep(Duration::from_millis(linger_ms));
    Ok(())
}
