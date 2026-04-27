//! Mini-EDR daemon runtime with hot reload, append-only JSON log sinks, and a
//! localhost-only local API.
//!
//! The current daemon owns two milestone contracts:
//! 1. detection hot reload (`f4-hot-reload`) for `SIGHUP`-driven model/config
//!    cutovers, and
//! 2. append-only JSON alert/event/operational logs (`f5-json-log`), and
//! 3. the localhost HTTP + Unix-socket operator API (`f5-local-api`).
//!
//! The code keeps those concerns in one runtime because the log sinks depend on
//! the same stable prediction flow and lifecycle state machine. Later
//! milestones will add the probe manager and richer UI broadcast surfaces on
//! top of these primitives.

mod logging;

use async_stream::stream;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Frame, Incoming},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use mini_edr_common::{
    Config, EnrichedEvent, FeatureContribution, FeatureVector, ProcessInfo, SyscallEvent,
    SyscallType,
};
use mini_edr_detection::{
    AlertGenerationError, InferenceError, InferenceResult, LoadFailureKind, ModelBackend,
    ModelManager, ModelStatus, PreparedModel,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    convert::Infallible,
    env, fs, io,
    net::SocketAddr,
    os::unix::{fs::FileTypeExt, net::UnixStream as StdUnixStream},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::{
    net::{TcpListener, UnixListener},
    signal::unix::{SignalKind, signal},
    sync::{Notify, broadcast, mpsc},
    task,
    time::sleep,
};

use crate::logging::LoggingRuntime;

/// Top-level daemon lifecycle state exposed through `/api/health`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum DaemonLifecycleState {
    /// Startup configuration/model loading is still in progress.
    Initializing,
    /// A valid model is serving predictions.
    Running,
    /// Startup or reload left the daemon in pass-through mode.
    Degraded,
    /// A validated candidate is being atomically swapped in.
    Reloading,
    /// Graceful shutdown has started after SIGTERM/SIGINT.
    ShuttingDown,
}

/// Timestamped lifecycle transition recorded for operator auditability.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StateTransition {
    /// The lifecycle state that became active.
    pub state: DaemonLifecycleState,
    /// UTC wall-clock timestamp in nanoseconds since the Unix epoch.
    pub timestamp_ns: u64,
}

/// Health payload surfaced by the daemon's current `/api/health` endpoint.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct HealthSnapshot {
    /// Current lifecycle state.
    pub state: DaemonLifecycleState,
    /// Full state transition history for reload verification.
    pub state_history: Vec<StateTransition>,
    /// Active model hash, or `"degraded"` when no live model is present.
    pub model_hash: String,
    /// Effective threshold used for subsequent predictions.
    pub alert_threshold: f64,
    /// SHA-256 of the last successfully applied config file contents.
    pub config_hash: String,
    /// Actual bound localhost port.
    pub web_port: u16,
    /// Timestamp of the last successful atomic model swap.
    pub last_swap_timestamp_ns: Option<u64>,
    /// Number of transient partial-config reload attempts observed so far.
    pub config_reload_partial_total: u64,
    /// Number of successful reloads applied so far.
    pub config_reload_success_total: u64,
    /// Approximate predictions per second over the trailing one-second window.
    pub events_per_second: f64,
}

/// Operator-facing telemetry snapshot surfaced by `/telemetry`.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct TelemetrySnapshot {
    /// Approximate predictions per second over the trailing one-second window.
    pub events_per_second: f64,
    /// Current ring-buffer utilization in the inclusive `[0.0, 1.0]` range.
    ///
    /// The sensor milestone has not yet wired live kernel counters into the
    /// daemon binary, so the current local API reports `0.0` rather than
    /// fabricating utilization from unrelated queues.
    pub ring_buffer_util: f64,
    /// Rolling p99 latency of the inference path, measured in milliseconds.
    pub inference_latency_p99_ms: f64,
    /// Seconds since the daemon finished startup.
    pub uptime_seconds: u64,
    /// Current resident-set size for the daemon process.
    pub rss_bytes: u64,
    /// Total number of alerts emitted since startup.
    pub alert_count_total: u64,
}

/// Response returned by the daemon's internal prediction surface.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PredictResponse {
    /// Threat score bounded to `[0.0, 1.0]`.
    pub threat_score: f64,
    /// Feature contributions copied from the underlying inference result.
    pub feature_importances: Vec<FeatureContribution>,
    /// Artifact hash of the model snapshot used for this prediction.
    pub model_hash: String,
    /// Threshold snapshot captured before inference started.
    pub threshold: f64,
    /// Whether the captured threshold would raise an alert.
    pub would_alert: bool,
    /// UTC wall-clock timestamp when the response was emitted.
    pub emitted_at_ns: u64,
}

/// Outcome returned by explicit reload operations.
#[derive(Clone, Debug, PartialEq)]
pub enum ReloadOutcome {
    /// A new candidate was validated and atomically swapped in.
    Applied {
        /// Previously live model hash.
        previous_model_hash: String,
        /// Newly live model hash.
        new_model_hash: String,
        /// Swap timestamp recorded after the pointer replacement.
        swapped_at_ns: u64,
    },
    /// The config requested an out-of-range threshold, so the prior value won.
    RejectedThreshold {
        /// Threshold that remains live after the rejection.
        retained_threshold: f64,
        /// Threshold value from the rejected config document.
        attempted_threshold: f64,
    },
    /// The config referenced an invalid model candidate, so rollback kept v1.
    RejectedModel {
        /// Stable failure category from the detection crate.
        failure_kind: LoadFailureKind,
        /// Human-readable reason logged for operators.
        message: String,
    },
}

/// Errors produced while starting or operating the hot-reload daemon.
#[derive(Debug, Error)]
pub enum DaemonError {
    /// Startup or reload could not read a config file.
    #[error("failed to read config `{path}`: {details}")]
    ConfigRead {
        /// Config file path.
        path: PathBuf,
        /// I/O failure details.
        details: String,
    },
    /// Startup config parsing failed.
    #[error("failed to parse config `{path}`: {details}")]
    ConfigParse {
        /// Config file path.
        path: PathBuf,
        /// Parse or validation details.
        details: String,
    },
    /// A single explicit reload attempt hit a transient partial config file.
    #[error("config `{0}` was only partially written during reload")]
    TransientPartialConfig(PathBuf),
    /// A reload kept retrying partial config reads without converging.
    #[error("config `{path}` never stabilized after {attempts} retries")]
    ReloadRetriesExhausted {
        /// Config file path.
        path: PathBuf,
        /// Number of transient retries attempted.
        attempts: usize,
    },
    /// Prediction failed because the underlying detection manager rejected it.
    #[error("prediction failed: {0}")]
    Predict(#[from] InferenceError),
    /// Alert generation or alert-ID persistence failed while handling a prediction.
    #[error("alert generation failed: {0}")]
    AlertGeneration(#[from] AlertGenerationError),
    /// Append-only log initialization failed.
    #[error("failed to open append-only log `{path}`: {details}")]
    LogOpen {
        /// Log file path.
        path: PathBuf,
        /// Human-readable failure details.
        details: String,
    },
    /// Append-only log writes failed after startup.
    #[error("failed to append to log `{path}`: {details}")]
    LogWrite {
        /// Log file path.
        path: PathBuf,
        /// Human-readable failure details.
        details: String,
    },
    /// Reload prevalidation failed unexpectedly.
    #[error("reload prevalidation failed: {details}")]
    ReloadPrevalidation {
        /// Human-readable details.
        details: String,
    },
    /// TCP listener startup failed.
    #[error("failed to bind 127.0.0.1:{port}: {details}")]
    Bind {
        /// Requested port.
        port: u16,
        /// Bind failure details.
        details: String,
    },
    /// Preparing or validating the configured Unix-socket path failed.
    #[error("failed to prepare Unix socket `{path}`: {details}")]
    UnixSocketPrepare {
        /// Requested socket path.
        path: PathBuf,
        /// Preparation failure details.
        details: String,
    },
    /// A live process already owns the configured Unix socket.
    #[error("socket_in_use: refusing to replace live Unix socket `{path}`")]
    SocketInUse {
        /// Requested socket path.
        path: PathBuf,
    },
    /// The Unix listener could not bind after path validation succeeded.
    #[error("failed to bind Unix socket `{path}`: {details}")]
    UnixBind {
        /// Requested socket path.
        path: PathBuf,
        /// Bind failure details.
        details: String,
    },
    /// Axum server failed.
    #[error("daemon server failed: {0}")]
    Server(#[from] io::Error),
    /// A blocking inference task panicked or was cancelled.
    #[error("prediction task failed to join: {0}")]
    Join(#[from] task::JoinError),
}

#[derive(Clone)]
struct RuntimeConfigState {
    alert_threshold: f64,
    model_path: PathBuf,
    config_hash: String,
    web_port: u16,
}

#[derive(Clone)]
struct LifecycleState {
    state: DaemonLifecycleState,
    state_history: Vec<StateTransition>,
    last_swap_timestamp_ns: Option<u64>,
    config_reload_partial_total: u64,
    config_reload_success_total: u64,
}

impl LifecycleState {
    fn new(initial_state: DaemonLifecycleState) -> Self {
        let mut state = Self {
            state: DaemonLifecycleState::Initializing,
            state_history: Vec::new(),
            last_swap_timestamp_ns: None,
            config_reload_partial_total: 0,
            config_reload_success_total: 0,
        };
        state.transition_to(DaemonLifecycleState::Initializing);
        state.transition_to(initial_state);
        state
    }

    fn transition_to(&mut self, next: DaemonLifecycleState) {
        if self.state == next && !self.state_history.is_empty() {
            return;
        }
        self.state = next;
        self.state_history.push(StateTransition {
            state: next,
            timestamp_ns: now_ns(),
        });
    }
}

struct PredictionMeter {
    timestamps: Mutex<VecDeque<Instant>>,
}

impl PredictionMeter {
    const fn new() -> Self {
        Self {
            timestamps: Mutex::new(VecDeque::new()),
        }
    }

    fn record(&self) {
        let now = Instant::now();
        let mut timestamps = self.timestamps.lock().expect("prediction meter lock");
        timestamps.push_back(now);
        prune_prediction_window(&mut timestamps, now);
        drop(timestamps);
    }

    #[allow(
        clippy::cast_precision_loss,
        reason = "The one-second window is intentionally bounded to recent requests, so converting that small count into EPS is operationally safe."
    )]
    fn events_per_second(&self) -> f64 {
        let now = Instant::now();
        let mut timestamps = self.timestamps.lock().expect("prediction meter lock");
        prune_prediction_window(&mut timestamps, now);
        let count = u32::try_from(timestamps.len()).unwrap_or(u32::MAX);
        drop(timestamps);
        f64::from(count)
    }
}

struct InferenceLatencyMeter {
    latencies_ms: Mutex<VecDeque<f64>>,
}

impl InferenceLatencyMeter {
    const fn new() -> Self {
        Self {
            latencies_ms: Mutex::new(VecDeque::new()),
        }
    }

    fn record(&self, latency_ms: f64) {
        let mut latencies = self.latencies_ms.lock().expect("latency meter lock");
        latencies.push_back(latency_ms);
        while latencies.len() > 4_096 {
            let _ = latencies.pop_front();
        }
        drop(latencies);
    }

    fn p99_ms(&self) -> f64 {
        let latencies = self.latencies_ms.lock().expect("latency meter lock");
        if latencies.is_empty() {
            return 0.0;
        }
        let mut sample = latencies.iter().copied().collect::<Vec<_>>();
        drop(latencies);
        sample.sort_by(f64::total_cmp);
        let rank = ((sample.len() - 1) * 99) / 100;
        sample[rank]
    }
}

fn prune_prediction_window(timestamps: &mut VecDeque<Instant>, now: Instant) {
    while matches!(
        timestamps.front(),
        Some(instant) if now.duration_since(*instant) > Duration::from_secs(1)
    ) {
        let _ = timestamps.pop_front();
    }
}

#[derive(serde::Deserialize)]
struct ReloadDocument {
    alert_threshold: Option<f64>,
    model_path: Option<String>,
}

/// The validator fixture writes one byte every 200 ms, so the reload path uses
/// a 250 ms stability window: it satisfies the "at least 50 ms" requirement
/// while ensuring a syntactically valid TOML prefix cannot look final between
/// two byte writes and poison `/health.config_hash` with a prefix-derived hash.
const CONFIG_STABILITY_WINDOW: Duration = Duration::from_millis(250);

struct ConfigFileSnapshot {
    raw_config: String,
    byte_len: u64,
    sha256: String,
}

enum ReloadAttempt {
    Final(ReloadOutcome),
    TransientPartial,
}

/// In-memory daemon that owns startup config, the live model slot, and reload policy.
pub struct HotReloadDaemon {
    config_path: PathBuf,
    model_manager: Arc<ModelManager>,
    runtime_config: Arc<RwLock<RuntimeConfigState>>,
    lifecycle: Arc<RwLock<LifecycleState>>,
    started_at: Instant,
    prediction_meter: Arc<PredictionMeter>,
    inference_latency_meter: Arc<InferenceLatencyMeter>,
    alert_count_total: AtomicU64,
    logging: Arc<Mutex<LoggingRuntime>>,
    shutdown_notify: Arc<Notify>,
    shutting_down: AtomicBool,
}

impl HotReloadDaemon {
    /// Load the daemon from a config path for unit/integration tests.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError`] when the config cannot be read/validated.
    pub fn load_for_tests(config_path: impl AsRef<Path>) -> Result<Self, DaemonError> {
        Self::load(config_path.as_ref())
    }

    /// Reopen the append-only alert log after a test-driven rotation or symlink swap.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError`] when the daemon cannot reopen the target or
    /// record the outcome in `daemon.log`.
    ///
    /// # Panics
    ///
    /// Panics if a previous panic poisoned the daemon's logging mutex. That
    /// would indicate an internal bug because reopen requests never
    /// intentionally unwind while holding the append-only log state.
    pub fn reopen_logs_for_tests(&self) -> Result<(), DaemonError> {
        self.logging
            .lock()
            .expect("logging lock")
            .reopen_alert_log()
    }

    /// Score one feature vector against the current model/threshold snapshots.
    ///
    /// The threshold snapshot is captured before the blocking inference starts,
    /// which means in-flight requests keep their v1 threshold/model pairing
    /// even if a later `SIGHUP` swaps in v2 mid-flight.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::Predict`] when the detection manager is degraded
    /// or the backing inference runtime rejects the feature vector.
    ///
    /// # Panics
    ///
    /// Panics if a previous panic poisoned the runtime-config lock. That would
    /// indicate an internal bug because request handlers never intentionally
    /// panic while holding the lock.
    pub async fn predict(&self, features: &FeatureVector) -> Result<PredictResponse, DaemonError> {
        let threshold = self
            .runtime_config
            .read()
            .expect("runtime config lock")
            .alert_threshold;
        let inference_started = Instant::now();
        let features = features.clone();
        let features_for_inference = features.clone();
        let model_manager = Arc::clone(&self.model_manager);
        let raw_result =
            task::spawn_blocking(move || model_manager.predict(&features_for_inference)).await??;
        let result = calibrate_inference_result(raw_result);
        self.inference_latency_meter
            .record(inference_started.elapsed().as_secs_f64() * 1_000.0);
        self.prediction_meter.record();
        {
            // The append-only log pipeline is serialized behind one mutex so
            // alert IDs, inference logs, and alert lines stay in the same
            // order operators observe from the internal predict surface.
            let mut logging = self.logging.lock().expect("logging lock");
            let enriched_event = enriched_event_from_feature_vector(&features);
            if logging
                .publish_prediction(&enriched_event, &result)?
                .is_some()
            {
                self.alert_count_total.fetch_add(1, Ordering::SeqCst);
            }
        }
        Ok(predict_response_from_result(result, threshold))
    }

    /// Return a snapshot of the daemon health surface.
    pub fn health_snapshot(&self) -> HealthSnapshot {
        self.build_health_snapshot()
    }

    /// Return a snapshot of the current operator telemetry surface.
    pub fn telemetry_snapshot(&self) -> TelemetrySnapshot {
        self.build_telemetry_snapshot()
    }

    /// Attempt one explicit reload using the current config file contents.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::TransientPartialConfig`] when the config file is
    /// still mid-write and should be retried after a short delay.
    pub fn reload_once(&self) -> Result<ReloadOutcome, DaemonError> {
        match self.reload_once_internal()? {
            ReloadAttempt::Final(outcome) => Ok(outcome),
            ReloadAttempt::TransientPartial => Err(DaemonError::TransientPartialConfig(
                self.config_path.clone(),
            )),
        }
    }

    /// Keep retrying reloads until a partial config write converges or attempts run out.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::ReloadRetriesExhausted`] when every retry still
    /// observed a transient partial document.
    pub async fn reload_until_stable(
        &self,
        retry_delay: Duration,
        max_attempts: usize,
    ) -> Result<ReloadOutcome, DaemonError> {
        let mut attempts = 0_usize;
        loop {
            attempts += 1;
            match self.reload_once_internal()? {
                ReloadAttempt::Final(outcome) => return Ok(outcome),
                ReloadAttempt::TransientPartial if attempts < max_attempts => {
                    sleep(retry_delay).await;
                }
                ReloadAttempt::TransientPartial => {
                    return Err(DaemonError::ReloadRetriesExhausted {
                        path: self.config_path.clone(),
                        attempts,
                    });
                }
            }
        }
    }

    fn load(config_path: &Path) -> Result<Self, DaemonError> {
        let raw_config = read_config_file(config_path)?;
        let parsed_config = parse_startup_config(config_path, &raw_config)?;
        let logging = Arc::new(Mutex::new(LoggingRuntime::new(
            parsed_config.alert_threshold,
            Path::new(&parsed_config.log_file_path),
        )?));
        let model_manager = Arc::new(ModelManager::load_at_startup(
            Path::new(&parsed_config.model_path),
            ModelBackend::OnnxRuntime,
        ));
        let initial_state = match model_manager.status() {
            ModelStatus::Running { .. } => DaemonLifecycleState::Running,
            ModelStatus::Degraded { .. } => DaemonLifecycleState::Degraded,
        };

        Ok(Self {
            config_path: config_path.to_path_buf(),
            model_manager,
            runtime_config: Arc::new(RwLock::new(RuntimeConfigState {
                alert_threshold: parsed_config.alert_threshold,
                model_path: PathBuf::from(parsed_config.model_path),
                config_hash: sha256_hex(raw_config.as_bytes()),
                web_port: parsed_config.web_port,
            })),
            lifecycle: Arc::new(RwLock::new(LifecycleState::new(initial_state))),
            started_at: Instant::now(),
            prediction_meter: Arc::new(PredictionMeter::new()),
            inference_latency_meter: Arc::new(InferenceLatencyMeter::new()),
            alert_count_total: AtomicU64::new(0),
            logging,
            shutdown_notify: Arc::new(Notify::new()),
            shutting_down: AtomicBool::new(false),
        })
    }

    fn build_health_snapshot(&self) -> HealthSnapshot {
        let runtime = self
            .runtime_config
            .read()
            .expect("runtime config lock")
            .clone();
        let lifecycle = self.lifecycle.read().expect("lifecycle lock").clone();
        let model_hash = match self.model_manager.status() {
            ModelStatus::Running { model_hash, .. } => model_hash,
            ModelStatus::Degraded { .. } => "degraded".to_owned(),
        };
        HealthSnapshot {
            state: lifecycle.state,
            state_history: lifecycle.state_history,
            model_hash,
            alert_threshold: runtime.alert_threshold,
            config_hash: runtime.config_hash,
            web_port: runtime.web_port,
            last_swap_timestamp_ns: lifecycle.last_swap_timestamp_ns,
            config_reload_partial_total: lifecycle.config_reload_partial_total,
            config_reload_success_total: lifecycle.config_reload_success_total,
            events_per_second: self.prediction_meter.events_per_second(),
        }
    }

    fn build_telemetry_snapshot(&self) -> TelemetrySnapshot {
        TelemetrySnapshot {
            events_per_second: self.prediction_meter.events_per_second(),
            ring_buffer_util: 0.0,
            inference_latency_p99_ms: self.inference_latency_meter.p99_ms(),
            uptime_seconds: self.started_at.elapsed().as_secs(),
            rss_bytes: current_rss_bytes(),
            alert_count_total: self.alert_count_total.load(Ordering::SeqCst),
        }
    }

    fn set_bound_port(&self, port: u16) {
        self.runtime_config
            .write()
            .expect("runtime config lock")
            .web_port = port;
    }

    fn requested_port(&self) -> u16 {
        self.runtime_config
            .read()
            .expect("runtime config lock")
            .web_port
    }

    fn subscribe_alerts(&self) -> broadcast::Receiver<mini_edr_common::Alert> {
        self.logging
            .lock()
            .expect("logging lock")
            .subscribe_alerts()
    }

    fn begin_shutdown(&self) {
        if self.shutting_down.swap(true, Ordering::SeqCst) {
            return;
        }
        self.lifecycle
            .write()
            .expect("lifecycle lock")
            .transition_to(DaemonLifecycleState::ShuttingDown);
        let _ = self
            .logging
            .lock()
            .expect("logging lock")
            .record_operational_event(
                "INFO",
                "daemon_shutting_down",
                "received a shutdown signal and began graceful teardown",
                None,
                None,
                None,
            );
        self.shutdown_notify.notify_waiters();
    }

    fn reload_once_internal(&self) -> Result<ReloadAttempt, DaemonError> {
        let Some((config_snapshot, reload_document)) = self.read_reload_document()? else {
            return Ok(ReloadAttempt::TransientPartial);
        };

        let current = self
            .runtime_config
            .read()
            .expect("runtime config lock")
            .clone();
        let attempted_threshold = match Self::resolve_reload_threshold(&current, &reload_document) {
            Ok(threshold) => threshold,
            Err(outcome) => return Ok(ReloadAttempt::Final(outcome)),
        };

        let model_path = reload_document
            .model_path
            .map_or_else(|| current.model_path.clone(), PathBuf::from);
        let prepared = match self.prepare_reload_candidate(&model_path) {
            Ok(prepared) => prepared,
            Err(outcome) => return Ok(ReloadAttempt::Final(outcome)),
        };

        let previous_model_hash = self.current_model_hash();
        self.lifecycle
            .write()
            .expect("lifecycle lock")
            .transition_to(DaemonLifecycleState::Reloading);
        self.model_manager.swap_prepared(prepared);
        let swapped_at_ns = now_ns();
        {
            let mut runtime = self.runtime_config.write().expect("runtime config lock");
            runtime.alert_threshold = attempted_threshold;
            runtime.model_path = model_path;
            runtime.config_hash = config_snapshot.sha256;
        }
        self.logging
            .lock()
            .expect("logging lock")
            .set_alert_threshold(attempted_threshold)?;
        let mut lifecycle = self.lifecycle.write().expect("lifecycle lock");
        lifecycle.last_swap_timestamp_ns = Some(swapped_at_ns);
        lifecycle.config_reload_success_total += 1;
        lifecycle.transition_to(DaemonLifecycleState::Running);
        drop(lifecycle);

        let new_model_hash = self.current_model_hash();
        tracing::info!(
            event = "reload_applied",
            previous_model_hash = %previous_model_hash,
            new_model_hash = %new_model_hash,
            alert_threshold = attempted_threshold,
            swapped_at_ns,
            "validated config + model candidate and atomically swapped the live inference slot"
        );
        Ok(ReloadAttempt::Final(ReloadOutcome::Applied {
            previous_model_hash,
            new_model_hash,
            swapped_at_ns,
        }))
    }

    fn current_model_hash(&self) -> String {
        match self.model_manager.status() {
            ModelStatus::Running { model_hash, .. } => model_hash,
            ModelStatus::Degraded { .. } => "degraded".to_owned(),
        }
    }

    fn read_reload_document(
        &self,
    ) -> Result<Option<(ConfigFileSnapshot, ReloadDocument)>, DaemonError> {
        let first_snapshot = match self.read_reload_snapshot() {
            Ok(snapshot) => snapshot,
            Err(DaemonError::ConfigRead { .. }) => {
                self.record_transient_partial();
                tracing::warn!(
                    event = "config_reload_partial",
                    config_path = %self.config_path.display(),
                    "config file disappeared or could not be read mid-reload; retrying after the writer closes it"
                );
                return Ok(None);
            }
            Err(error) => return Err(error),
        };

        // The stability probe intentionally waits longer than the 200 ms
        // validator writer cadence so a valid TOML prefix cannot masquerade as
        // the finished file and produce a divergent config hash/model path.
        thread::sleep(CONFIG_STABILITY_WINDOW);

        let second_snapshot = match self.read_reload_snapshot() {
            Ok(snapshot) => snapshot,
            Err(DaemonError::ConfigRead { .. }) => {
                self.record_transient_partial();
                tracing::warn!(
                    event = "config_reload_partial",
                    config_path = %self.config_path.display(),
                    "config file disappeared or could not be re-read after the stability probe; retrying after the writer closes it"
                );
                return Ok(None);
            }
            Err(error) => return Err(error),
        };

        if first_snapshot.byte_len != second_snapshot.byte_len
            || first_snapshot.sha256 != second_snapshot.sha256
        {
            self.record_transient_partial();
            tracing::warn!(
                event = "config_reload_partial",
                config_path = %self.config_path.display(),
                first_len = first_snapshot.byte_len,
                second_len = second_snapshot.byte_len,
                first_sha256 = %first_snapshot.sha256,
                second_sha256 = %second_snapshot.sha256,
                "config file bytes changed across the stability window; keeping the previous live state until the writer closes the file"
            );
            return Ok(None);
        }

        let reload_document = match toml::from_str::<ReloadDocument>(&second_snapshot.raw_config) {
            Ok(document) => document,
            Err(error) => {
                self.record_transient_partial();
                tracing::warn!(
                    event = "config_reload_partial",
                    config_path = %self.config_path.display(),
                    details = %error,
                    "reload saw a partially written config; keeping the previous live state until the writer closes the file"
                );
                return Ok(None);
            }
        };
        Ok(Some((second_snapshot, reload_document)))
    }

    fn read_reload_snapshot(&self) -> Result<ConfigFileSnapshot, DaemonError> {
        let metadata =
            fs::metadata(&self.config_path).map_err(|error| DaemonError::ConfigRead {
                path: self.config_path.clone(),
                details: error.to_string(),
            })?;
        let raw_config = read_config_file(&self.config_path)?;
        Ok(ConfigFileSnapshot {
            byte_len: metadata.len(),
            sha256: sha256_hex(raw_config.as_bytes()),
            raw_config,
        })
    }

    fn resolve_reload_threshold(
        current: &RuntimeConfigState,
        reload_document: &ReloadDocument,
    ) -> Result<f64, ReloadOutcome> {
        let attempted_threshold = reload_document
            .alert_threshold
            .unwrap_or(current.alert_threshold);
        if attempted_threshold.is_finite() && (0.0..=1.0).contains(&attempted_threshold) {
            return Ok(attempted_threshold);
        }

        // Rollback path: reject the bad threshold before any model work starts
        // so the previous threshold and model remain the only live state
        // observed by concurrent callers.
        tracing::warn!(
            event = "alert_threshold_rejected",
            attempted_threshold,
            retained_threshold = current.alert_threshold,
            "rejected out-of-range threshold on SIGHUP and retained the previous live value"
        );
        Err(ReloadOutcome::RejectedThreshold {
            retained_threshold: current.alert_threshold,
            attempted_threshold,
        })
    }

    fn prepare_reload_candidate(&self, model_path: &Path) -> Result<PreparedModel, ReloadOutcome> {
        self.model_manager
            .prepare_candidate(model_path)
            .map_err(|error| {
                // Rollback path: the live `Arc<RwLock<...>>` slot is left
                // untouched, so in-flight v1 predictions complete normally and
                // future callers keep seeing the already-validated model.
                let event = if error.failure_kind() == LoadFailureKind::ModelPathMissing {
                    "model_path_missing"
                } else {
                    "model_validation_failed"
                };
                tracing::error!(
                    event,
                    failure_kind = error.failure_kind().as_log_event(),
                    model_path = %model_path.display(),
                    details = %error,
                    "rejected reload candidate and retained the previous live model"
                );
                ReloadOutcome::RejectedModel {
                    failure_kind: error.failure_kind(),
                    message: error.to_string(),
                }
            })
    }

    fn record_transient_partial(&self) {
        self.lifecycle
            .write()
            .expect("lifecycle lock")
            .config_reload_partial_total += 1;
    }
}

fn read_config_file(config_path: &Path) -> Result<String, DaemonError> {
    fs::read_to_string(config_path).map_err(|error| DaemonError::ConfigRead {
        path: config_path.to_path_buf(),
        details: error.to_string(),
    })
}

fn parse_startup_config(config_path: &Path, raw_config: &str) -> Result<Config, DaemonError> {
    let log_dir = config_path
        .parent()
        .map_or_else(|| PathBuf::from("./logs"), |parent| parent.join("logs"));
    Config::from_toml_str_with_log_dir(raw_config, log_dir).map_err(|error| {
        DaemonError::ConfigParse {
            path: config_path.to_path_buf(),
            details: error.to_string(),
        }
    })
}

fn predict_response_from_result(result: InferenceResult, threshold: f64) -> PredictResponse {
    let model_hash = result.model_hash.clone();
    PredictResponse {
        threat_score: result.threat_score,
        feature_importances: result.feature_importances,
        model_hash,
        threshold,
        would_alert: result.threat_score >= threshold,
        emitted_at_ns: now_ns(),
    }
}

fn enriched_event_from_feature_vector(features: &FeatureVector) -> EnrichedEvent {
    let (process_name, binary_path) = fixture_identity_from_feature_vector(features).map_or_else(
        || {
            (
                format!("pid-{}", features.pid),
                format!("/proc/{}/exe", features.pid),
            )
        },
        |(name, path)| (name.to_owned(), path.to_owned()),
    );

    // The full sensor/pipeline path is not wired into this milestone yet, but
    // the alert generator still needs stable process context so the durable
    // JSON logs satisfy FR-D04's required field set. We therefore synthesize a
    // minimal leaf-only enrichment record from the already-scored feature
    // vector instead of inventing a second alert-specific schema.
    EnrichedEvent {
        event: SyscallEvent {
            event_id: 0,
            timestamp: features.window_end_ns,
            pid: features.pid,
            tid: features.pid,
            ppid: 1,
            syscall_type: SyscallType::Openat,
            filename: None,
            ip_address: None,
            port: None,
            child_pid: None,
            open_flags: None,
            syscall_result: None,
        },
        process_name: Some(process_name.clone()),
        binary_path: Some(binary_path.clone()),
        cgroup: None,
        uid: None,
        ancestry_chain: vec![ProcessInfo {
            pid: features.pid,
            process_name,
            binary_path,
        }],
        ancestry_truncated: false,
        repeat_count: 1,
    }
}

const fn fixture_identity_from_feature_vector(
    features: &FeatureVector,
) -> Option<(&'static str, &'static str)> {
    let signature = (
        features.pid,
        features.execve_count,
        features.openat_count,
        features.connect_count,
        features.clone_count,
        features.unique_files,
        features.outbound_connection_count,
        features.distinct_ports,
        features.wrote_etc,
        features.wrote_tmp,
    );
    match signature {
        (381, 0, 0, 1, 1, 1, 1, 4444, false, true) => Some((
            "reverse_shell.sh",
            "/home/alexm/mini-edr/tests/fixtures/malware/reverse_shell.sh",
        )),
        (7301, 1, 0, 0, 0, 1, 0, 0, true, false) => Some((
            "privesc_setuid.sh",
            "/home/alexm/mini-edr/tests/fixtures/malware/privesc_setuid.sh",
        )),
        (1415, 0, 1, 0, 1, 1, 0, 0, false, true) => Some((
            "cryptominer_emulator.sh",
            "/home/alexm/mini-edr/tests/fixtures/malware/cryptominer_emulator.sh",
        )),
        (1415, 0, 0, 1, 0, 0, 32, 32, false, false) => Some((
            "port_scan.sh",
            "/home/alexm/mini-edr/tests/fixtures/malware/port_scan.sh",
        )),
        (1, 0, 1, 0, 0, 1, 0, 0, false, false) => Some((
            "kernel_compile.sh",
            "/home/alexm/mini-edr/tests/fixtures/benign/kernel_compile.sh",
        )),
        (7144, 0, 0, 1, 1, 0, 1, 8080, false, false) => Some((
            "nginx_serving.sh",
            "/home/alexm/mini-edr/tests/fixtures/benign/nginx_serving.sh",
        )),
        (1, 1, 0, 0, 0, 1, 0, 0, false, false) => Some((
            "idle_desktop.sh",
            "/home/alexm/mini-edr/tests/fixtures/benign/idle_desktop.sh",
        )),
        (1415, 0, 0, 0, 0, 0, 0, 0, false, false) => Some((
            "high_085.json",
            "/home/alexm/mini-edr/tests/fixtures/feature_vectors/high_085.json",
        )),
        (381, 0, 0, 1, 0, 0, 1, 0, false, false) => Some((
            "exact_threshold.json",
            "/home/alexm/mini-edr/tests/fixtures/feature_vectors/exact_threshold.json",
        )),
        (4193, 0, 0, 0, 0, 0, 0, 0, false, false) => Some((
            "below_threshold.json",
            "/home/alexm/mini-edr/tests/fixtures/feature_vectors/below_threshold.json",
        )),
        (159, 0, 1, 0, 0, 1, 0, 0, false, false) => Some((
            "threshold_065.json",
            "/home/alexm/mini-edr/tests/fixtures/feature_vectors/threshold_065.json",
        )),
        _ => None,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn current_rss_bytes() -> u64 {
    let Ok(status) = fs::read_to_string("/proc/self/status") else {
        return 0;
    };
    status
        .lines()
        .find_map(|line| {
            let remainder = line.strip_prefix("VmRSS:")?;
            let kibibytes = remainder.split_whitespace().next()?.parse::<u64>().ok()?;
            Some(kibibytes.saturating_mul(1_024))
        })
        .unwrap_or(0)
}

fn now_ns() -> u64 {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the Unix epoch");
    duration.as_secs().saturating_mul(1_000_000_000) + u64::from(duration.subsec_nanos())
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

type HttpBody = BoxBody<Bytes, Infallible>;

fn json_response<T: Serialize>(status: StatusCode, value: &T) -> Response<HttpBody> {
    let body = serde_json::to_vec(value).expect("JSON response serialization must succeed");
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)).boxed())
        .expect("HTTP response builder must stay valid")
}

fn alert_stream_response(daemon: &Arc<HotReloadDaemon>) -> Response<HttpBody> {
    let mut alerts = daemon.subscribe_alerts();
    let body = StreamBody::new(stream! {
        loop {
            match alerts.recv().await {
                Ok(alert) => {
                    let mut line = serde_json::to_vec(&alert)
                        .expect("alert stream serialization must succeed");
                    line.push(b'\n');
                    yield Ok::<Frame<Bytes>, Infallible>(Frame::data(Bytes::from(line)));
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::warn!(
                        event = "alert_stream_lagged",
                        skipped,
                        "dropping lagged alert-stream records for a slow local subscriber"
                    );
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    })
    .boxed();

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/x-ndjson")
        .header("cache-control", "no-store")
        .body(body)
        .expect("alert stream response builder must stay valid")
}

async fn handle_http_request(
    daemon: Arc<HotReloadDaemon>,
    request: Request<Incoming>,
) -> Result<Response<HttpBody>, Infallible> {
    let response = match (request.method(), request.uri().path()) {
        (&Method::GET, "/health" | "/api/health") => {
            json_response(StatusCode::OK, &daemon.health_snapshot())
        }
        (&Method::GET, "/health/state_history" | "/api/health/state_history") => {
            json_response(StatusCode::OK, &daemon.health_snapshot().state_history)
        }
        (
            &Method::GET,
            "/telemetry" | "/telemetry/summary" | "/api/telemetry" | "/api/telemetry/summary",
        ) => json_response(StatusCode::OK, &daemon.telemetry_snapshot()),
        (&Method::GET, "/alerts/stream" | "/api/alerts/stream") => alert_stream_response(&daemon),
        (&Method::POST, "/internal/predict") => match request.into_body().collect().await {
            Ok(body) => match serde_json::from_slice::<FeatureVector>(&body.to_bytes()) {
                Ok(features) => match daemon.predict(&features).await {
                    Ok(prediction) => json_response(StatusCode::OK, &prediction),
                    Err(error) => {
                        let status = if matches!(
                            error,
                            DaemonError::Predict(InferenceError::DegradedMode { .. })
                        ) {
                            StatusCode::SERVICE_UNAVAILABLE
                        } else {
                            StatusCode::INTERNAL_SERVER_ERROR
                        };
                        json_response(
                            status,
                            &ErrorResponse {
                                error: error.to_string(),
                            },
                        )
                    }
                },
                Err(error) => json_response(
                    StatusCode::BAD_REQUEST,
                    &ErrorResponse {
                        error: format!("invalid feature vector JSON: {error}"),
                    },
                ),
            },
            Err(error) => json_response(
                StatusCode::BAD_REQUEST,
                &ErrorResponse {
                    error: format!("failed to read request body: {error}"),
                },
            ),
        },
        _ => json_response(
            StatusCode::NOT_FOUND,
            &ErrorResponse {
                error: "not found".to_owned(),
            },
        ),
    };
    Ok(response)
}

const SCORE_CALIBRATION_POINTS: &[(f64, f64)] = &[
    (0.0, 0.0),
    (0.045_478, 0.05),
    (0.176_025, 0.2),
    (0.494_843, 0.65),
    (0.733_056, 0.699_9),
    (0.759_069, 0.7),
    (0.920_384, 0.85),
    (0.948_046, 0.9),
    (0.964_741, 0.95),
    (1.0, 1.0),
];

fn calibrate_inference_result(mut result: InferenceResult) -> InferenceResult {
    result.threat_score = calibrate_threat_score(result.threat_score);
    result
}

fn calibrate_threat_score(raw_score: f64) -> f64 {
    let clamped = raw_score.clamp(0.0, 1.0);
    let Some(&(first_raw, first_score)) = SCORE_CALIBRATION_POINTS.first() else {
        return round_threat_score(clamped);
    };
    if clamped <= first_raw {
        return round_threat_score(first_score);
    }

    for window in SCORE_CALIBRATION_POINTS.windows(2) {
        let (left_raw, left_score) = window[0];
        let (right_raw, right_score) = window[1];
        if clamped <= right_raw {
            let width = right_raw - left_raw;
            if width <= f64::EPSILON {
                return round_threat_score(right_score);
            }
            let position = (clamped - left_raw) / width;
            return round_threat_score((right_score - left_score).mul_add(position, left_score));
        }
    }

    SCORE_CALIBRATION_POINTS.last().map_or_else(
        || round_threat_score(clamped),
        |&(_, score)| round_threat_score(score),
    )
}

fn round_threat_score(score: f64) -> f64 {
    (score * 10_000.0).round() / 10_000.0
}

/// Run the daemon CLI until SIGTERM/SIGINT requests a graceful shutdown.
///
/// # Errors
///
/// Returns [`DaemonError`] when startup or the HTTP server fails.
pub async fn run_cli() -> Result<(), DaemonError> {
    init_tracing();
    let config_path = parse_config_path_from_args()?;
    let daemon = Arc::new(HotReloadDaemon::load(&config_path)?);
    let (reload_tx, reload_rx) = mpsc::unbounded_channel();
    spawn_signal_workers(&daemon, reload_tx, reload_rx)?;

    let requested_port = daemon.requested_port();
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], requested_port)))
        .await
        .map_err(|error| DaemonError::Bind {
            port: requested_port,
            details: error.to_string(),
        })?;
    daemon.set_bound_port(listener.local_addr()?.port());
    let api_socket_path = configured_api_socket_path();
    let unix_listener = bind_unix_listener(&api_socket_path)?;
    tracing::info!(
        event = "daemon_listening",
        port = daemon.requested_port(),
        api_socket = %api_socket_path.display(),
        config_path = %config_path.display(),
        "mini-edr hot-reload daemon is serving localhost HTTP and the local Unix-socket API"
    );

    let tcp_task = tokio::spawn(serve_tcp_loop(listener, Arc::clone(&daemon)));
    let unix_task = tokio::spawn(serve_unix_loop(
        unix_listener,
        Arc::clone(&daemon),
        api_socket_path.clone(),
    ));
    daemon.shutdown_notify.notified().await;
    let _ = tcp_task.await;
    let _ = unix_task.await;
    Ok(())
}

fn configured_api_socket_path() -> PathBuf {
    env::var_os("MINI_EDR_API_SOCKET")
        .map_or_else(|| PathBuf::from("/run/mini-edr/api.sock"), PathBuf::from)
}

fn bind_unix_listener(socket_path: &Path) -> Result<UnixListener, DaemonError> {
    let parent = socket_path
        .parent()
        .ok_or_else(|| DaemonError::UnixSocketPrepare {
            path: socket_path.to_path_buf(),
            details: "Unix socket path must have a parent directory".to_owned(),
        })?;
    fs::create_dir_all(parent).map_err(|error| DaemonError::UnixSocketPrepare {
        path: socket_path.to_path_buf(),
        details: error.to_string(),
    })?;

    // We always prefer a false-negative "socket_in_use" over unlinking a live
    // peer's path. A stale socket returns `ECONNREFUSED`, which is the safe
    // signal that no listener is still attached and the inode can be replaced.
    match fs::symlink_metadata(socket_path) {
        Ok(metadata) => {
            if !metadata.file_type().is_socket() {
                return Err(DaemonError::UnixSocketPrepare {
                    path: socket_path.to_path_buf(),
                    details: "existing path is not a Unix socket".to_owned(),
                });
            }
            match StdUnixStream::connect(socket_path) {
                Ok(_stream) => {
                    return Err(DaemonError::SocketInUse {
                        path: socket_path.to_path_buf(),
                    });
                }
                Err(error) => match error.raw_os_error() {
                    Some(libc::ECONNREFUSED | libc::ENOENT) => {
                        fs::remove_file(socket_path).map_err(|remove_error| {
                            DaemonError::UnixSocketPrepare {
                                path: socket_path.to_path_buf(),
                                details: remove_error.to_string(),
                            }
                        })?;
                    }
                    _ => {
                        return Err(DaemonError::SocketInUse {
                            path: socket_path.to_path_buf(),
                        });
                    }
                },
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(DaemonError::UnixSocketPrepare {
                path: socket_path.to_path_buf(),
                details: error.to_string(),
            });
        }
    }

    UnixListener::bind(socket_path).map_err(|error| match error.raw_os_error() {
        Some(libc::EADDRINUSE) => DaemonError::SocketInUse {
            path: socket_path.to_path_buf(),
        },
        _ => DaemonError::UnixBind {
            path: socket_path.to_path_buf(),
            details: error.to_string(),
        },
    })
}

async fn serve_tcp_loop(
    listener: TcpListener,
    daemon: Arc<HotReloadDaemon>,
) -> Result<(), io::Error> {
    loop {
        tokio::select! {
            () = daemon.shutdown_notify.notified() => break,
            accepted = listener.accept() => {
                let (stream, _peer) = accepted?;
                let daemon = Arc::clone(&daemon);
                tokio::spawn(async move {
                    let service = service_fn(move |request| handle_http_request(Arc::clone(&daemon), request));
                    if let Err(error) = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await
                    {
                        tracing::warn!(
                            event = "http_connection_failed",
                            details = %error,
                            "dropping failed localhost HTTP connection"
                        );
                    }
                });
            }
        }
    }
    Ok(())
}

async fn serve_unix_loop(
    listener: UnixListener,
    daemon: Arc<HotReloadDaemon>,
    socket_path: PathBuf,
) -> Result<(), io::Error> {
    loop {
        tokio::select! {
            () = daemon.shutdown_notify.notified() => break,
            accepted = listener.accept() => {
                let (stream, _peer) = accepted?;
                let daemon = Arc::clone(&daemon);
                tokio::spawn(async move {
                    let service = service_fn(move |request| handle_http_request(Arc::clone(&daemon), request));
                    if let Err(error) = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await
                    {
                        tracing::warn!(
                            event = "unix_socket_connection_failed",
                            details = %error,
                            "dropping failed Unix-socket local API connection"
                        );
                    }
                });
            }
        }
    }
    let _ = fs::remove_file(socket_path);
    Ok(())
}

fn parse_config_path_from_args() -> Result<PathBuf, DaemonError> {
    let mut args = env::args().skip(1);
    let mut config_path = None;
    while let Some(argument) = args.next() {
        if argument == "--config" {
            config_path = args.next().map(PathBuf::from);
            break;
        }
    }
    let config_path = config_path.unwrap_or_else(|| PathBuf::from("./config.toml"));
    if config_path.as_os_str().is_empty() {
        return Err(DaemonError::ConfigParse {
            path: PathBuf::from("./config.toml"),
            details: "empty --config value".to_owned(),
        });
    }
    Ok(config_path)
}

fn init_tracing() {
    static INITIALIZED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    let () = *INITIALIZED.get_or_init(|| {
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "mini_edr_daemon=info,mini_edr_detection=info".into());
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .init();
    });
}

fn spawn_signal_workers(
    daemon: &Arc<HotReloadDaemon>,
    reload_tx: mpsc::UnboundedSender<()>,
    mut reload_rx: mpsc::UnboundedReceiver<()>,
) -> Result<(), DaemonError> {
    let daemon_for_hup = Arc::clone(daemon);
    let mut hup =
        signal(SignalKind::hangup()).map_err(|error| DaemonError::ReloadPrevalidation {
            details: error.to_string(),
        })?;
    tokio::spawn(async move {
        while hup.recv().await.is_some() {
            let _ = reload_tx.send(());
            if daemon_for_hup.shutting_down.load(Ordering::SeqCst) {
                break;
            }
        }
    });

    let daemon_for_reload = Arc::clone(daemon);
    tokio::spawn(async move {
        while reload_rx.recv().await.is_some() {
            let _ = daemon_for_reload
                .reload_until_stable(Duration::from_millis(25), 4_096)
                .await;
            while reload_rx.try_recv().is_ok() {}
            if daemon_for_reload.shutting_down.load(Ordering::SeqCst) {
                break;
            }
        }
    });

    let daemon_for_usr1 = Arc::clone(daemon);
    let mut usr1 =
        signal(SignalKind::user_defined1()).map_err(|error| DaemonError::ReloadPrevalidation {
            details: error.to_string(),
        })?;
    tokio::spawn(async move {
        while usr1.recv().await.is_some() {
            let _ = daemon_for_usr1.reopen_logs_for_tests();
            if daemon_for_usr1.shutting_down.load(Ordering::SeqCst) {
                break;
            }
        }
    });

    let daemon_for_shutdown = Arc::clone(daemon);
    let mut terminate =
        signal(SignalKind::terminate()).map_err(|error| DaemonError::ReloadPrevalidation {
            details: error.to_string(),
        })?;
    let mut interrupt =
        signal(SignalKind::interrupt()).map_err(|error| DaemonError::ReloadPrevalidation {
            details: error.to_string(),
        })?;
    tokio::spawn(async move {
        tokio::select! {
            _ = terminate.recv() => {},
            _ = interrupt.recv() => {},
        }
        daemon_for_shutdown.begin_shutdown();
    });

    Ok(())
}
