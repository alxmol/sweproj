//! Mini-EDR daemon bootstrap binary.
//!
//! The binary is intentionally thin: `mini-edr-daemon`'s library owns the
//! state machine, reload logic, and HTTP surfaces, while `main` only hands
//! control to the Tokio runtime and reports fatal startup/shutdown errors.

/// Tokio entry point for the hot-reload daemon.
#[tokio::main(flavor = "multi_thread")]
async fn main() {
    if let Err(error) = mini_edr_daemon::run_cli().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
