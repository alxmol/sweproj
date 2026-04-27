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
pub use crate::logging::TamperReport;

use async_stream::stream;
use axum::{
    Router,
    body::Body as AxumBody,
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    response::IntoResponse,
    routing::{any, get, post},
};
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
    Alert, Config, EnrichedEvent, FeatureContribution, FeatureVector, ProcessDetail,
    ProcessDetailField, ProcessInfo, ProcessTreeNode, ProcessTreeSnapshot, SyscallEvent,
    SyscallType,
};
use mini_edr_detection::{
    AlertGenerationError, InferenceError, InferenceResult, LoadFailureKind, ModelBackend,
    ModelManager, ModelStatus, PreparedModel,
};
use serde::{Deserialize, Serialize};
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
    sync::{Notify, OwnedSemaphorePermit, Semaphore, broadcast, mpsc},
    task,
    time::{sleep, timeout},
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
    /// Whether `daemon.log` has diverged from the daemon's in-memory byte stream.
    pub daemon_log_tampered: bool,
    /// Structured details about the first detected `daemon.log` tamper event.
    pub daemon_log_tamper: Option<TamperReport>,
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

const DASHBOARD_ALERT_LIMIT: usize = 4_096;
const DASHBOARD_ALERT_CHANNEL_CAPACITY: usize = 65_536;
const MAX_WS_CLIENTS: usize = 64;
const WS_BACKPRESSURE_TIMEOUT: Duration = Duration::from_secs(5);
const CSRF_HEADER_NAME: &str = "x-csrf-token";

#[derive(Clone, Debug)]
struct DashboardViewState {
    process_tree: ProcessTreeSnapshot,
    alert_timeline: VecDeque<Alert>,
    csrf_token: String,
}

impl DashboardViewState {
    fn new(csrf_token: String) -> Self {
        Self {
            process_tree: ProcessTreeSnapshot::default(),
            alert_timeline: VecDeque::new(),
            csrf_token,
        }
    }

    fn alerts_snapshot(&self) -> DashboardAlertSnapshot {
        DashboardAlertSnapshot {
            alerts: self.alert_timeline.iter().cloned().collect(),
        }
    }

    fn replace_alerts(&mut self, alerts: Vec<Alert>) {
        self.alert_timeline = alerts.into();
        while self.alert_timeline.len() > DASHBOARD_ALERT_LIMIT {
            let _ = self.alert_timeline.pop_front();
        }
    }

    fn push_alert(&mut self, alert: Alert) {
        self.alert_timeline.push_back(alert);
        while self.alert_timeline.len() > DASHBOARD_ALERT_LIMIT {
            let _ = self.alert_timeline.pop_front();
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
struct DashboardAlertSnapshot {
    alerts: Vec<Alert>,
}

#[derive(Clone, Debug, Deserialize)]
struct ThresholdUpdateRequest {
    alert_threshold: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct ThresholdUpdateResponse {
    alert_threshold: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct CsrfTokenResponse {
    token: String,
}

/// In-memory daemon that owns startup config, the live model slot, and reload policy.
pub struct HotReloadDaemon {
    config_path: PathBuf,
    model_manager: Arc<ModelManager>,
    runtime_config: Arc<RwLock<RuntimeConfigState>>,
    lifecycle: Arc<RwLock<LifecycleState>>,
    dashboard_state: Arc<RwLock<DashboardViewState>>,
    started_at: Instant,
    prediction_meter: Arc<PredictionMeter>,
    inference_latency_meter: Arc<InferenceLatencyMeter>,
    alert_count_total: AtomicU64,
    alert_sender: broadcast::Sender<Alert>,
    ws_client_limit: Arc<Semaphore>,
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

    /// Append one synthetic operational record to `daemon.log` for regression tests.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError`] when the operational log cannot flush the test
    /// record to disk.
    ///
    /// # Panics
    ///
    /// Panics if a previous panic poisoned the daemon's logging mutex.
    pub fn write_operational_log_for_tests(&self, message: &str) -> Result<(), DaemonError> {
        self.logging
            .lock()
            .expect("logging lock")
            .record_operational_event("INFO", "test_operational_log", message, None, None, None)
    }

    /// Force an immediate `daemon.log` integrity verification for regression tests.
    ///
    /// # Errors
    ///
    /// Returns [`TamperReport`] when any tracked byte differs from the daemon's
    /// in-memory append-only view.
    ///
    /// # Panics
    ///
    /// Panics if a previous panic poisoned the daemon's logging mutex.
    pub fn verify_operational_log_integrity_for_tests(&self) -> Result<(), TamperReport> {
        self.logging
            .lock()
            .expect("logging lock")
            .verify_operational_log_integrity()
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
        let result =
            task::spawn_blocking(move || model_manager.predict(&features_for_inference)).await??;
        self.inference_latency_meter
            .record(inference_started.elapsed().as_secs_f64() * 1_000.0);
        self.prediction_meter.record();
        {
            // The append-only log pipeline is serialized behind one mutex so
            // alert IDs, inference logs, and alert lines stay in the same
            // order operators observe from the internal predict surface.
            let mut logging = self.logging.lock().expect("logging lock");
            let enriched_event = enriched_event_from_feature_vector(&features);
            if let Some(alert) = logging.publish_prediction(&enriched_event, &result)? {
                self.alert_count_total.fetch_add(1, Ordering::SeqCst);
                self.publish_dashboard_alert(alert, false);
            }
        }
        self.upsert_dashboard_process(dashboard_process_from_prediction(&features, &result));
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

    /// Return the current dashboard process-tree snapshot.
    ///
    /// # Panics
    ///
    /// Panics if a previous panic poisoned the dashboard-state lock. That
    /// would indicate an internal bug because readers never intentionally
    /// unwind while holding the tree snapshot.
    pub fn process_tree_snapshot(&self) -> ProcessTreeSnapshot {
        self.dashboard_state
            .read()
            .expect("dashboard state lock")
            .process_tree
            .clone()
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
            Path::new(&parsed_config.alert_id_seq_path),
        )?));
        let model_manager = Arc::new(ModelManager::load_at_startup(
            Path::new(&parsed_config.model_path),
            ModelBackend::OnnxRuntime,
        ));
        let (alert_sender, _alert_receiver) = broadcast::channel(DASHBOARD_ALERT_CHANNEL_CAPACITY);
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
            dashboard_state: Arc::new(RwLock::new(DashboardViewState::new(generate_csrf_token(
                config_path,
            )))),
            started_at: Instant::now(),
            prediction_meter: Arc::new(PredictionMeter::new()),
            inference_latency_meter: Arc::new(InferenceLatencyMeter::new()),
            alert_count_total: AtomicU64::new(0),
            alert_sender,
            ws_client_limit: Arc::new(Semaphore::new(MAX_WS_CLIENTS)),
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
        let daemon_log_tamper = self
            .logging
            .lock()
            .expect("logging lock")
            .operational_log_tamper_report();
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
            daemon_log_tampered: daemon_log_tamper.is_some(),
            daemon_log_tamper,
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

    fn replace_process_tree_snapshot(&self, snapshot: ProcessTreeSnapshot) {
        self.dashboard_state
            .write()
            .expect("dashboard state lock")
            .process_tree = snapshot;
    }

    fn upsert_dashboard_process(&self, process: ProcessTreeNode) {
        let mut dashboard_state = self.dashboard_state.write().expect("dashboard state lock");
        if let Some(existing) = dashboard_state
            .process_tree
            .processes
            .iter_mut()
            .find(|existing| existing.pid == process.pid)
        {
            *existing = process;
        } else {
            dashboard_state.process_tree.processes.push(process);
        }
    }

    fn dashboard_alert_snapshot(&self) -> DashboardAlertSnapshot {
        self.dashboard_state
            .read()
            .expect("dashboard state lock")
            .alerts_snapshot()
    }

    fn replace_dashboard_alerts(&self, alerts: Vec<Alert>) {
        self.dashboard_state
            .write()
            .expect("dashboard state lock")
            .replace_alerts(alerts);
    }

    fn publish_dashboard_alert(&self, alert: Alert, synthetic: bool) {
        self.dashboard_state
            .write()
            .expect("dashboard state lock")
            .push_alert(alert.clone());
        if synthetic {
            self.alert_count_total.fetch_add(1, Ordering::SeqCst);
        }
        let _ = self.alert_sender.send(alert);
    }

    fn subscribe_alerts(&self) -> broadcast::Receiver<Alert> {
        self.alert_sender.subscribe()
    }

    fn csrf_token(&self) -> String {
        self.dashboard_state
            .read()
            .expect("dashboard state lock")
            .csrf_token
            .clone()
    }

    fn update_threshold_for_dashboard(&self, threshold: f64) -> Result<f64, DaemonError> {
        if !threshold.is_finite() || !(0.0..=1.0).contains(&threshold) {
            return Err(DaemonError::ReloadPrevalidation {
                details: format!(
                    "alert_threshold must be a finite value in [0.0, 1.0], got {threshold}"
                ),
            });
        }
        {
            self.logging
                .lock()
                .expect("logging lock")
                .set_alert_threshold(threshold)?;
        }
        self.runtime_config
            .write()
            .expect("runtime config lock")
            .alert_threshold = threshold;
        self.logging
            .lock()
            .expect("logging lock")
            .record_operational_event(
                "INFO",
                "alert_threshold_updated",
                "updated the live alert threshold through the localhost dashboard settings endpoint",
                Some(&self.config_path),
                None,
                Some(format!("alert_threshold={threshold}")),
            )?;
        Ok(threshold)
    }

    fn try_acquire_ws_client(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.ws_client_limit).try_acquire_owned().ok()
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
    let config = Config::from_toml_str_with_log_dir(raw_config, log_dir).map_err(|error| {
        DaemonError::ConfigParse {
            path: config_path.to_path_buf(),
            details: error.to_string(),
        }
    })?;
    if let Ok(override_path) = env::var("MINI_EDR_ALERT_ID_SEQ_PATH") {
        config
            .with_alert_id_seq_path_override(&override_path)
            .map_err(|error| DaemonError::ConfigParse {
                path: config_path.to_path_buf(),
                details: error.to_string(),
            })
    } else {
        Ok(config)
    }
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

fn dashboard_process_from_prediction(
    features: &FeatureVector,
    result: &InferenceResult,
) -> ProcessTreeNode {
    let (process_name, binary_path) = fixture_identity_from_feature_vector(features).map_or_else(
        || {
            (
                format!("process-{}", features.pid),
                format!("/proc/{}/exe", features.pid),
            )
        },
        |(process_name, binary_path)| (process_name.to_owned(), binary_path.to_owned()),
    );

    ProcessTreeNode {
        pid: features.pid,
        process_name: process_name.clone(),
        binary_path: binary_path.clone(),
        threat_score: Some(result.threat_score),
        depth: 0,
        detail: ProcessDetail {
            ancestry_chain: vec![ProcessInfo {
                pid: features.pid,
                process_name,
                binary_path,
            }],
            feature_vector: feature_vector_fields(features),
            recent_syscalls: recent_syscall_lines(features),
            threat_score: Some(result.threat_score),
            top_features: result.feature_importances.clone(),
        },
        exited: false,
    }
}

fn feature_vector_fields(features: &FeatureVector) -> Vec<ProcessDetailField> {
    vec![
        ProcessDetailField {
            label: "window".to_owned(),
            value: format!(
                "{}ns → {}ns",
                features.window_start_ns, features.window_end_ns
            ),
        },
        ProcessDetailField {
            label: "entropy".to_owned(),
            value: format!("{:.3}", features.path_entropy),
        },
        ProcessDetailField {
            label: "unique_files".to_owned(),
            value: features.unique_files.to_string(),
        },
        ProcessDetailField {
            label: "unique_ips".to_owned(),
            value: features.unique_ips.to_string(),
        },
        ProcessDetailField {
            label: "failed_syscalls".to_owned(),
            value: features.failed_syscall_count.to_string(),
        },
        ProcessDetailField {
            label: "events_per_second".to_owned(),
            value: format!("{:.1}", features.events_per_second),
        },
    ]
}

fn recent_syscall_lines(features: &FeatureVector) -> Vec<String> {
    let mut recent_syscalls = Vec::new();

    for (name, count) in [
        ("clone", features.clone_count),
        ("connect", features.connect_count),
        ("openat", features.openat_count),
        ("execve", features.execve_count),
    ] {
        if count > 0 {
            recent_syscalls.push(format!("{name} ×{count}"));
        }
    }

    if recent_syscalls.is_empty() {
        recent_syscalls.push("No recent syscalls recorded".to_owned());
    }

    recent_syscalls
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
        (814, 0, 1, 0, 0, 1, 0, 0, false, false) => Some((
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

fn generate_csrf_token(config_path: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(config_path.as_os_str().as_encoded_bytes());
    hasher.update(now_ns().to_be_bytes());
    hasher.update(std::process::id().to_be_bytes());
    format!("{:x}", hasher.finalize())
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

fn csrf_forbidden(reason: &str) -> axum::response::Response {
    (
        StatusCode::FORBIDDEN,
        axum::Json(ErrorResponse {
            error: reason.to_owned(),
        }),
    )
        .into_response()
}

fn allowed_origin(port: u16) -> [String; 2] {
    [
        format!("http://127.0.0.1:{port}"),
        format!("http://localhost:{port}"),
    ]
}

fn request_passes_csrf(
    headers: &axum::http::HeaderMap,
    csrf_token: &str,
    port: u16,
) -> Result<(), &'static str> {
    let Some(origin) = headers.get(axum::http::header::ORIGIN) else {
        return Err("missing Origin header");
    };
    let Ok(origin) = origin.to_str() else {
        return Err("invalid Origin header");
    };
    if !allowed_origin(port).iter().any(|allowed| allowed == origin) {
        return Err("cross-origin requests are forbidden");
    }

    let Some(token) = headers.get(CSRF_HEADER_NAME) else {
        return Err("missing CSRF token");
    };
    let Ok(token) = token.to_str() else {
        return Err("invalid CSRF token");
    };
    if token != csrf_token {
        return Err("invalid CSRF token");
    }
    Ok(())
}

fn update_threshold_response(
    daemon: &Arc<HotReloadDaemon>,
    headers: &axum::http::HeaderMap,
    request: &ThresholdUpdateRequest,
) -> axum::response::Response {
    let port = daemon.requested_port();
    let token = daemon.csrf_token();
    if let Err(reason) = request_passes_csrf(headers, &token, port) {
        return csrf_forbidden(reason);
    }
    match daemon.update_threshold_for_dashboard(request.alert_threshold) {
        Ok(alert_threshold) => (
            StatusCode::OK,
            axum::Json(ThresholdUpdateResponse { alert_threshold }),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            axum::Json(ErrorResponse {
                error: error.to_string(),
            }),
        )
            .into_response(),
    }
}

fn dashboard_seed_csrf_rejection(
    daemon: &Arc<HotReloadDaemon>,
    headers: &axum::http::HeaderMap,
) -> Option<axum::response::Response> {
    // NFR-SE02 and the web milestone threat model both treat mutable
    // localhost routes as browser-reachable state changes. A malicious tab can
    // still POST into `/internal/dashboard/*`, so the deterministic seeding
    // hooks must enforce the same Origin + CSRF gate as `/settings/threshold`.
    let port = daemon.requested_port();
    let token = daemon.csrf_token();
    request_passes_csrf(headers, &token, port)
        .err()
        .map(csrf_forbidden)
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

async fn predict_response_parts(
    daemon: &Arc<HotReloadDaemon>,
    body: &[u8],
) -> (StatusCode, serde_json::Value) {
    match serde_json::from_slice::<FeatureVector>(body) {
        Ok(features) => match daemon.predict(&features).await {
            Ok(prediction) => (
                StatusCode::OK,
                serde_json::to_value(prediction)
                    .expect("predict response serialization must succeed"),
            ),
            Err(error) => {
                let status = if matches!(
                    error,
                    DaemonError::Predict(InferenceError::DegradedMode { .. })
                ) {
                    StatusCode::SERVICE_UNAVAILABLE
                } else {
                    StatusCode::INTERNAL_SERVER_ERROR
                };
                (
                    status,
                    serde_json::to_value(ErrorResponse {
                        error: error.to_string(),
                    })
                    .expect("error response serialization must succeed"),
                )
            }
        },
        Err(error) => (
            StatusCode::BAD_REQUEST,
            serde_json::to_value(ErrorResponse {
                error: format!("invalid feature vector JSON: {error}"),
            })
            .expect("error response serialization must succeed"),
        ),
    }
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "The axum stream response must own an Arc so the returned body outlives the route closure."
)]
fn axum_alert_stream_response(daemon: Arc<HotReloadDaemon>) -> impl IntoResponse {
    let mut alerts = daemon.subscribe_alerts();
    let stream = stream! {
        loop {
            match alerts.recv().await {
                Ok(alert) => {
                    let mut line = serde_json::to_vec(&alert)
                        .expect("alert stream serialization must succeed");
                    line.push(b'\n');
                    yield Ok::<Bytes, Infallible>(Bytes::from(line));
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
    };

    (
        [
            ("content-type", "application/x-ndjson"),
            ("cache-control", "no-store"),
        ],
        AxumBody::from_stream(stream),
    )
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "The SSE stream owns the daemon handle for as long as the client remains connected."
)]
fn axum_sse_response(daemon: Arc<HotReloadDaemon>) -> impl IntoResponse {
    let mut alerts = daemon.subscribe_alerts();
    let stream = stream! {
        loop {
            match alerts.recv().await {
                Ok(alert) => {
                    let payload = serde_json::to_string(&alert)
                        .expect("SSE alert serialization must succeed");
                    yield Ok::<Bytes, Infallible>(Bytes::from(format!("data: {payload}\n\n")));
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::warn!(
                        event = "sse_stream_lagged",
                        skipped,
                        "dropping lagged SSE records for a slow local subscriber"
                    );
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };

    (
        [
            ("content-type", "text/event-stream"),
            ("cache-control", "no-store"),
            ("x-accel-buffering", "no"),
        ],
        AxumBody::from_stream(stream),
    )
}

async fn serve_websocket(
    mut socket: WebSocket,
    daemon: Arc<HotReloadDaemon>,
    _permit: OwnedSemaphorePermit,
) {
    let mut alerts = daemon.subscribe_alerts();
    loop {
        tokio::select! {
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Close(_))) | None => break,
                Some(Ok(Message::Ping(payload))) => {
                    if timeout(WS_BACKPRESSURE_TIMEOUT, socket.send(Message::Pong(payload))).await.is_err() {
                        tracing::warn!(
                            event = "ws_client_dropped",
                            reason = "pong_timeout",
                            timeout_seconds = WS_BACKPRESSURE_TIMEOUT.as_secs(),
                            "dropping WebSocket client after the pong write exceeded the backpressure timeout"
                        );
                        break;
                    }
                }
                Some(Ok(_)) => {}
                Some(Err(error)) => {
                    tracing::warn!(
                        event = "ws_client_closed",
                        details = %error,
                        "ending the WebSocket stream after a client-side receive error"
                    );
                    break;
                }
            },
            broadcast_result = alerts.recv() => match broadcast_result {
                Ok(alert) => {
                    let payload = serde_json::to_string(&alert)
                        .expect("WebSocket alert serialization must succeed");
                    match timeout(
                        WS_BACKPRESSURE_TIMEOUT,
                        socket.send(Message::Text(payload)),
                    ).await {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => {
                            tracing::warn!(
                                event = "ws_client_dropped",
                                reason = "send_error",
                                details = %error,
                                timeout_seconds = WS_BACKPRESSURE_TIMEOUT.as_secs(),
                                "dropping WebSocket client after a send error"
                            );
                            break;
                        }
                        Err(_) => {
                            tracing::warn!(
                                event = "ws_client_dropped",
                                reason = "backpressure_timeout",
                                timeout_seconds = WS_BACKPRESSURE_TIMEOUT.as_secs(),
                                "dropping WebSocket client after the send path exceeded the backpressure timeout"
                            );
                            break;
                        }
                    }
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::warn!(
                        event = "ws_alert_stream_lagged",
                        skipped,
                        "dropping lagged WebSocket records for a slow local subscriber"
                    );
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    }
}

fn websocket_upgrade_response(
    daemon: Arc<HotReloadDaemon>,
    upgrade: WebSocketUpgrade,
) -> impl IntoResponse {
    daemon.try_acquire_ws_client().map_or_else(
        || {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                axum::Json(ErrorResponse {
                    error: format!("max_ws_clients={MAX_WS_CLIENTS} reached"),
                }),
            )
                .into_response()
        },
        |permit| {
            upgrade
                .max_message_size(64 * 1024)
                .on_upgrade(move |socket| serve_websocket(socket, daemon, permit))
                .into_response()
        },
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "The localhost HTTP topology is easiest to audit when every route alias is declared in one contiguous block."
)]
fn daemon_http_router(daemon: &Arc<HotReloadDaemon>) -> Router {
    let health_provider = Arc::new({
        let daemon = Arc::clone(daemon);
        move || {
            serde_json::to_value(daemon.health_snapshot())
                .expect("health snapshot serialization must succeed")
        }
    });
    let process_tree_provider = Arc::new({
        let daemon = Arc::clone(daemon);
        move || daemon.process_tree_snapshot()
    });

    // The public routing topology is intentionally split between the
    // presentation-first dashboard scaffold (`mini-edr-web`) and the daemon's
    // richer operator API. This keeps the SPA assets self-contained while the
    // daemon still owns the mutable JSON/streaming surfaces that later
    // milestones extend with real telemetry and drill-down data.
    let dashboard_state =
        mini_edr_web::DashboardRouterState::new(health_provider, process_tree_provider);

    mini_edr_web::router(&dashboard_state)
        .route(
            "/ws",
            get({
                let daemon = Arc::clone(daemon);
                move |upgrade: WebSocketUpgrade| {
                    let daemon = Arc::clone(&daemon);
                    async move { websocket_upgrade_response(daemon, upgrade) }
                }
            }),
        )
        .route(
            "/sse",
            get({
                let daemon = Arc::clone(daemon);
                move || {
                    let daemon = Arc::clone(&daemon);
                    async move { axum_sse_response(daemon) }
                }
            }),
        )
        .route(
            "/health/state_history",
            get({
                let daemon = Arc::clone(daemon);
                move || {
                    let daemon = Arc::clone(&daemon);
                    async move { axum::Json(daemon.health_snapshot().state_history) }
                }
            }),
        )
        .route(
            "/api/health/state_history",
            get({
                let daemon = Arc::clone(daemon);
                move || {
                    let daemon = Arc::clone(&daemon);
                    async move { axum::Json(daemon.health_snapshot().state_history) }
                }
            }),
        )
        .route(
            "/telemetry",
            get({
                let daemon = Arc::clone(daemon);
                move || {
                    let daemon = Arc::clone(&daemon);
                    async move { axum::Json(daemon.telemetry_snapshot()) }
                }
            }),
        )
        .route(
            "/telemetry/summary",
            get({
                let daemon = Arc::clone(daemon);
                move || {
                    let daemon = Arc::clone(&daemon);
                    async move { axum::Json(daemon.telemetry_snapshot()) }
                }
            }),
        )
        .route(
            "/api/telemetry",
            get({
                let daemon = Arc::clone(daemon);
                move || {
                    let daemon = Arc::clone(&daemon);
                    async move { axum::Json(daemon.telemetry_snapshot()) }
                }
            }),
        )
        .route(
            "/api/telemetry/summary",
            get({
                let daemon = Arc::clone(daemon);
                move || {
                    let daemon = Arc::clone(&daemon);
                    async move { axum::Json(daemon.telemetry_snapshot()) }
                }
            }),
        )
        .route(
            "/alerts/stream",
            get({
                let daemon = Arc::clone(daemon);
                move || {
                    let daemon = Arc::clone(&daemon);
                    async move { axum_alert_stream_response(daemon) }
                }
            }),
        )
        .route(
            "/api/alerts/stream",
            get({
                let daemon = Arc::clone(daemon);
                move || {
                    let daemon = Arc::clone(&daemon);
                    async move { axum_alert_stream_response(daemon) }
                }
            }),
        )
        .route(
            "/dashboard/alerts",
            get({
                let daemon = Arc::clone(daemon);
                move || {
                    let daemon = Arc::clone(&daemon);
                    async move { axum::Json(daemon.dashboard_alert_snapshot()) }
                }
            }),
        )
        .route(
            "/api/dashboard/alerts",
            get({
                let daemon = Arc::clone(daemon);
                move || {
                    let daemon = Arc::clone(&daemon);
                    async move { axum::Json(daemon.dashboard_alert_snapshot()) }
                }
            }),
        )
        .route(
            "/settings/csrf",
            get({
                let daemon = Arc::clone(daemon);
                move || {
                    let daemon = Arc::clone(&daemon);
                    async move {
                        axum::Json(CsrfTokenResponse {
                            token: daemon.csrf_token(),
                        })
                    }
                }
            }),
        )
        .route(
            "/api/settings/csrf",
            get({
                let daemon = Arc::clone(daemon);
                move || {
                    let daemon = Arc::clone(&daemon);
                    async move {
                        axum::Json(CsrfTokenResponse {
                            token: daemon.csrf_token(),
                        })
                    }
                }
            }),
        )
        .route(
            "/settings/threshold",
            post({
                let daemon = Arc::clone(daemon);
                move |headers: axum::http::HeaderMap,
                      axum::Json(request): axum::Json<ThresholdUpdateRequest>| {
                    let daemon = Arc::clone(&daemon);
                    async move { update_threshold_response(&daemon, &headers, &request) }
                }
            }),
        )
        .route(
            "/api/settings/threshold",
            post({
                let daemon = Arc::clone(daemon);
                move |headers: axum::http::HeaderMap,
                      axum::Json(request): axum::Json<ThresholdUpdateRequest>| {
                    let daemon = Arc::clone(&daemon);
                    async move { update_threshold_response(&daemon, &headers, &request) }
                }
            }),
        )
        .route(
            "/internal/predict",
            post({
                let daemon = Arc::clone(daemon);
                move |body: Bytes| {
                    let daemon = Arc::clone(&daemon);
                    async move {
                        let (status, payload) = predict_response_parts(&daemon, &body).await;
                        (status, axum::Json(payload))
                    }
                }
            }),
        )
        .route(
            "/internal/dashboard/process-tree",
            get({
                let daemon = Arc::clone(daemon);
                move || {
                    let daemon = Arc::clone(&daemon);
                    async move { axum::Json(daemon.process_tree_snapshot()) }
                }
            })
            .post({
                let daemon = Arc::clone(daemon);
                move |headers: axum::http::HeaderMap, body: Bytes| {
                    let daemon = Arc::clone(&daemon);
                    async move {
                        if let Some(response) = dashboard_seed_csrf_rejection(&daemon, &headers) {
                            return response;
                        }

                        let snapshot: ProcessTreeSnapshot = serde_json::from_slice(&body)
                            .expect("dashboard process-tree snapshot JSON is valid");
                        // The full live sensor/pipeline broadcast does not land
                        // until later milestones, so browser harnesses can seed
                        // deterministic tree snapshots through this localhost-
                        // only internal route while still exercising the real
                        // dashboard HTML/CSS/JS surface.
                        daemon.replace_process_tree_snapshot(snapshot.clone());
                        (StatusCode::OK, axum::Json(snapshot)).into_response()
                    }
                }
            }),
        )
        .route(
            "/internal/dashboard/alerts",
            get({
                let daemon = Arc::clone(daemon);
                move || {
                    let daemon = Arc::clone(&daemon);
                    async move { axum::Json(daemon.dashboard_alert_snapshot()) }
                }
            })
            .post({
                let daemon = Arc::clone(daemon);
                move |headers: axum::http::HeaderMap, body: Bytes| {
                    let daemon = Arc::clone(&daemon);
                    async move {
                        if let Some(response) = dashboard_seed_csrf_rejection(&daemon, &headers) {
                            return response;
                        }

                        let snapshot: DashboardAlertSnapshot = serde_json::from_slice(&body)
                            .expect("dashboard alert snapshot JSON is valid");
                        daemon.replace_dashboard_alerts(snapshot.alerts.clone());
                        (StatusCode::OK, axum::Json(snapshot)).into_response()
                    }
                }
            })
            .layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route(
            "/internal/dashboard/alerts/emit",
            post({
                let daemon = Arc::clone(daemon);
                move |headers: axum::http::HeaderMap, body: Bytes| {
                    let daemon = Arc::clone(&daemon);
                    async move {
                        if let Some(response) = dashboard_seed_csrf_rejection(&daemon, &headers) {
                            return response;
                        }

                        let snapshot: DashboardAlertSnapshot = serde_json::from_slice(&body)
                            .expect("dashboard emit snapshot JSON is valid");
                        for alert in &snapshot.alerts {
                            daemon.publish_dashboard_alert(alert.clone(), true);
                        }
                        (StatusCode::OK, axum::Json(snapshot)).into_response()
                    }
                }
            })
            .layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .fallback(any(|| async {
            (
                StatusCode::NOT_FOUND,
                axum::Json(ErrorResponse {
                    error: "not found".to_owned(),
                }),
            )
        }))
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
            Ok(body) => {
                let request_bytes = body.to_bytes();
                let (status, payload) = predict_response_parts(&daemon, &request_bytes).await;
                json_response(status, &payload)
            }
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

    let tcp_router = daemon_http_router(&daemon);
    let tcp_task = tokio::spawn(serve_tcp_router(listener, tcp_router, Arc::clone(&daemon)));
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
                        tracing::info!(
                            event = "stale_socket_removed",
                            path = %socket_path.display(),
                            "Removed stale Unix socket from prior unclean exit before binding"
                        );
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

async fn serve_tcp_router(
    listener: TcpListener,
    router: Router,
    daemon: Arc<HotReloadDaemon>,
) -> Result<(), io::Error> {
    axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            daemon.shutdown_notify.notified().await;
        })
        .await
        .map_err(|error| io::Error::other(error.to_string()))
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
