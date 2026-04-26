//! Helper binary for the privileged CLONE_THREAD PPID regression.
//!
//! The parent privileged harness spawns this binary as a direct child process.
//! The helper then creates one worker thread that opens a canary file, joins
//! that thread, opens a second canary file on the process leader, and sleeps
//! briefly so the parent test can drain both `openat` events from the ring
//! buffer before the helper exits.

use std::{env, fs, thread, time::Duration};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let worker_path = args
        .next()
        .ok_or("missing worker canary path argument")?;
    let leader_path = args
        .next()
        .ok_or("missing leader canary path argument")?;
    let pid_path = args
        .next()
        .ok_or("missing pid file path argument")?;
    if args.next().is_some() {
        return Err("expected exactly three arguments: worker path, leader path, pid file path".into());
    }

    fs::write(&pid_path, std::process::id().to_string())?;
    let worker_pid_path = pid_path.clone();
    let worker = thread::Builder::new()
        .name("mini-edr-worker".to_owned())
        .spawn(move || {
            fs::write(&worker_pid_path, std::process::id().to_string())?;
            fs::read(worker_path).map(|_| ())
        })?;
    worker.join().map_err(|_| "worker thread panicked")??;
    fs::write(&pid_path, std::process::id().to_string())?;
    let _ = fs::read(&leader_path)?;
    thread::sleep(Duration::from_secs(5));
    Ok(())
}
