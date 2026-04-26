//! Minimal daemon runtime for detection hot reload.
//!
//! This library deliberately focuses on the `f4-hot-reload` contract from
//! SDD §4.2.1 / FR-D05: load a startup config, serve inference requests, react
//! to `SIGHUP`, and expose health state that proves atomic cutovers. Later
//! milestones will extend the daemon with probes, the alert log, and the full
//! local API surface, but those features build on the reload/state primitives
//! implemented here.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{
    Method, Request, Response, StatusCode, body::Incoming, server::conn::http1, service::service_fn,
};
use hyper_util::rt::TokioIo;
use mini_edr_common::{Config, FeatureContribution, FeatureVector};
use mini_edr_detection::{
    InferenceError, InferenceResult, LoadFailureKind, ModelBackend, ModelManager, ModelStatus,
    PreparedModel,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    convert::Infallible,
    env, fs, io,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::{
    net::TcpListener,
    signal::unix::{SignalKind, signal},
    sync::{Notify, mpsc},
    task,
    time::sleep,
};

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
    prediction_meter: Arc<PredictionMeter>,
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
        let features = features.clone();
        let model_manager = Arc::clone(&self.model_manager);
        let result = task::spawn_blocking(move || model_manager.predict(&features)).await??;
        self.prediction_meter.record();
        Ok(predict_response_from_result(result, threshold))
    }

    /// Return a snapshot of the daemon health surface.
    pub fn health_snapshot(&self) -> HealthSnapshot {
        self.build_health_snapshot()
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
            prediction_meter: Arc::new(PredictionMeter::new()),
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

    fn begin_shutdown(&self) {
        if self.shutting_down.swap(true, Ordering::SeqCst) {
            return;
        }
        self.lifecycle
            .write()
            .expect("lifecycle lock")
            .transition_to(DaemonLifecycleState::ShuttingDown);
        self.shutdown_notify.notify_waiters();
    }

    fn reload_once_internal(&self) -> Result<ReloadAttempt, DaemonError> {
        let Some((raw_config, reload_document)) = self.read_reload_document()? else {
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
            runtime.config_hash = sha256_hex(raw_config.as_bytes());
        }
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

    fn read_reload_document(&self) -> Result<Option<(String, ReloadDocument)>, DaemonError> {
        let raw_config = match read_config_file(&self.config_path) {
            Ok(raw) => raw,
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
        let reload_document = match toml::from_str::<ReloadDocument>(&raw_config) {
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
        Ok(Some((raw_config, reload_document)))
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

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
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

type HttpResponse = Response<Full<Bytes>>;

fn json_response<T: Serialize>(status: StatusCode, value: &T) -> HttpResponse {
    let body = serde_json::to_vec(value).expect("JSON response serialization must succeed");
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .expect("HTTP response builder must stay valid")
}

async fn handle_http_request(
    daemon: Arc<HotReloadDaemon>,
    request: Request<Incoming>,
) -> Result<HttpResponse, Infallible> {
    let response = match (request.method(), request.uri().path()) {
        (&Method::GET, "/api/health") => json_response(StatusCode::OK, &daemon.health_snapshot()),
        (&Method::GET, "/api/health/state_history") => {
            json_response(StatusCode::OK, &daemon.health_snapshot().state_history)
        }
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
    tracing::info!(
        event = "daemon_listening",
        port = daemon.requested_port(),
        config_path = %config_path.display(),
        "mini-edr hot-reload daemon is serving localhost HTTP"
    );

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
