//! Standalone fork-storm generator used by pipeline and daemon stress tests.
//!
//! The binary intentionally has no Cargo dependencies so `tests/fixtures/fork_storm`
//! can compile it on demand with a plain `rustc` invocation. That keeps the
//! fixture fast to bootstrap inside sudo-backed validation shells while still
//! letting future system tests dial the fork rate and race-window width.

use std::{
    env,
    io,
    process::ExitCode,
    thread,
    time::{Duration, Instant},
};

unsafe extern "C" {
    fn fork() -> i32;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    fn _exit(status: i32) -> !;
}

const WNOHANG: i32 = 1;
const DEFAULT_RATE_PER_SEC: u64 = 50_000;
const DEFAULT_DURATION: Duration = Duration::from_secs(10);
const DEFAULT_CHILD_HOLD_MS: u64 = 0;
const PACER_SLEEP_MS: u64 = 10;

#[derive(Clone, Copy, Debug)]
struct Config {
    rate_per_sec: u64,
    duration: Duration,
    child_hold_ms: u64,
}

fn main() -> ExitCode {
    match parse_args(env::args().skip(1)) {
        Ok(config) => match run(config) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("fork_storm failed: {error}");
                ExitCode::from(1)
            }
        },
        Err(ArgumentOutcome::Help) => {
            print_usage();
            ExitCode::SUCCESS
        }
        Err(ArgumentOutcome::Error(message)) => {
            eprintln!("{message}");
            print_usage();
            ExitCode::from(2)
        }
    }
}

fn run(config: Config) -> io::Result<()> {
    let start = Instant::now();
    let mut spawned = 0_u64;
    let mut reaped = 0_u64;
    let mut max_outstanding = 0_u64;

    // The fixture stays single-threaded on purpose: calling `fork()` from a
    // multi-threaded Rust process would constrain us to async-signal-safe code
    // in the child. By keeping the helper minimal and single-threaded, the
    // child can sleep briefly and `_exit` without interacting with shared
    // runtime state or test harness threads.
    while start.elapsed() < config.duration {
        let target_total = target_spawns_by_now(config.rate_per_sec, start.elapsed());
        while spawned < target_total {
            match spawn_one_child(config.child_hold_ms)? {
                SpawnOutcome::Spawned => {
                    spawned = spawned.saturating_add(1);
                }
                SpawnOutcome::WouldBlock => {
                    reaped = reaped.saturating_add(reap_one_child_blocking()?);
                }
            }
        }

        reaped = reaped.saturating_add(reap_available_children()?);
        max_outstanding = max_outstanding.max(spawned.saturating_sub(reaped));

        let remaining = config.duration.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            break;
        }
        thread::sleep(remaining.min(Duration::from_millis(PACER_SLEEP_MS)));
    }

    while reaped < spawned {
        reaped = reaped.saturating_add(reap_one_child_blocking()?);
    }

    println!("target_rate_per_sec={}", config.rate_per_sec);
    println!("requested_duration_ms={}", config.duration.as_millis());
    println!("forks={spawned}");
    println!("reaped={reaped}");
    println!("elapsed_ms={}", start.elapsed().as_millis());
    println!("max_outstanding_children={max_outstanding}");
    Ok(())
}

fn target_spawns_by_now(rate_per_sec: u64, elapsed: Duration) -> u64 {
    let nanos = elapsed.as_nanos();
    let rate = u128::from(rate_per_sec);
    let expected = rate.saturating_mul(nanos).div_ceil(1_000_000_000);
    u64::try_from(expected).unwrap_or(u64::MAX)
}

fn spawn_one_child(child_hold_ms: u64) -> io::Result<SpawnOutcome> {
    // SAFETY: The helper is intentionally single-threaded, and the child path
    // performs only a bounded sleep followed by `_exit(0)`. That keeps the
    // post-fork work within the classic "fork without exec" safety envelope
    // needed for a deterministic stress fixture.
    let pid = unsafe { fork() };
    if pid < 0 {
        let error = io::Error::last_os_error();
        return if matches!(error.raw_os_error(), Some(11 | 12)) {
            Ok(SpawnOutcome::WouldBlock)
        } else {
            Err(error)
        };
    }

    if pid == 0 {
        if child_hold_ms > 0 {
            thread::sleep(Duration::from_millis(child_hold_ms));
        }

        // SAFETY: We are in the freshly forked child process and want to avoid
        // running Rust destructors twice. `_exit` terminates the child
        // immediately after the optional hold period.
        unsafe { _exit(0) };
    }

    Ok(SpawnOutcome::Spawned)
}

fn reap_available_children() -> io::Result<u64> {
    let mut reaped = 0_u64;
    loop {
        let mut status = 0_i32;
        // SAFETY: `waitpid` writes at most one `int` to `status`, whose storage
        // lives for the duration of the call. `-1` means "any child".
        let result = unsafe { waitpid(-1, &mut status, WNOHANG) };
        if result > 0 {
            reaped = reaped.saturating_add(1);
            continue;
        }
        if result == 0 {
            return Ok(reaped);
        }

        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(10) {
            Ok(reaped)
        } else {
            Err(error)
        };
    }
}

fn reap_one_child_blocking() -> io::Result<u64> {
    let mut status = 0_i32;
    // SAFETY: Same reasoning as `reap_available_children`, but with blocking
    // semantics so the parent drains every child before reporting completion.
    let result = unsafe { waitpid(-1, &mut status, 0) };
    if result > 0 {
        Ok(1)
    } else {
        Err(io::Error::last_os_error())
    }
}

#[derive(Debug)]
enum ArgumentOutcome {
    Help,
    Error(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SpawnOutcome {
    Spawned,
    WouldBlock,
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Config, ArgumentOutcome> {
    let mut config = Config {
        rate_per_sec: DEFAULT_RATE_PER_SEC,
        duration: DEFAULT_DURATION,
        child_hold_ms: DEFAULT_CHILD_HOLD_MS,
    };

    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--rate" => {
                let value = args
                    .next()
                    .ok_or_else(|| ArgumentOutcome::Error("--rate requires a value".to_owned()))?;
                config.rate_per_sec = value.parse::<u64>().map_err(|error| {
                    ArgumentOutcome::Error(format!("invalid --rate `{value}`: {error}"))
                })?;
            }
            "--duration" => {
                let value = args.next().ok_or_else(|| {
                    ArgumentOutcome::Error("--duration requires a value".to_owned())
                })?;
                config.duration = parse_duration(&value)?;
            }
            "--child-hold-ms" => {
                let value = args.next().ok_or_else(|| {
                    ArgumentOutcome::Error("--child-hold-ms requires a value".to_owned())
                })?;
                config.child_hold_ms = value.parse::<u64>().map_err(|error| {
                    ArgumentOutcome::Error(format!(
                        "invalid --child-hold-ms `{value}`: {error}"
                    ))
                })?;
            }
            "-h" | "--help" => return Err(ArgumentOutcome::Help),
            other => {
                return Err(ArgumentOutcome::Error(format!(
                    "unknown argument `{other}`"
                )));
            }
        }
    }

    if config.rate_per_sec == 0 {
        return Err(ArgumentOutcome::Error(
            "--rate must be greater than zero".to_owned(),
        ));
    }

    if config.duration.is_zero() {
        return Err(ArgumentOutcome::Error(
            "--duration must be greater than zero".to_owned(),
        ));
    }

    Ok(config)
}

fn parse_duration(value: &str) -> Result<Duration, ArgumentOutcome> {
    let (number, unit) = if let Some(value) = value.strip_suffix("ms") {
        (value, "ms")
    } else if let Some(value) = value.strip_suffix('s') {
        (value, "s")
    } else if let Some(value) = value.strip_suffix('m') {
        (value, "m")
    } else {
        (value, "s")
    };

    let quantity = number.parse::<u64>().map_err(|error| {
        ArgumentOutcome::Error(format!("invalid duration `{value}`: {error}"))
    })?;

    let duration = match unit {
        "ms" => Duration::from_millis(quantity),
        "s" => Duration::from_secs(quantity),
        "m" => Duration::from_secs(quantity.saturating_mul(60)),
        _ => unreachable!("only the documented duration suffixes are reachable"),
    };

    Ok(duration)
}

fn print_usage() {
    eprintln!(
        "Usage: tests/fixtures/fork_storm [--rate N] [--duration 10s|500ms|1m] [--child-hold-ms N]"
    );
}
