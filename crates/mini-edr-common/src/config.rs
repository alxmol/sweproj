//! Typed Mini-EDR configuration parsing and host-compatibility validation.
//!
//! Per SDD §8.1 and NFR-SE05, the daemon must reject invalid or malicious TOML
//! configuration before any privileged subsystem starts. This module keeps that
//! validation in `mini-edr-common` so startup, SIGHUP reload, tests, and future
//! UI settings code all share one policy.

use crate::SyscallType;
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    fmt, fs,
    path::{Component, Path, PathBuf},
};

/// Default directory that confines production alert-log paths.
pub const DEFAULT_LOG_DIRECTORY: &str = "/var/log/mini-edr";
/// Default directory that stores daemon-owned mutable state files.
pub const DEFAULT_STATE_DIRECTORY: &str = "/var/lib/mini-edr";
/// Canonical alert-ID sequence filename beneath the configured state directory.
pub const ALERT_ID_SEQUENCE_FILE_NAME: &str = "alert_id.seq";

/// Fully validated Mini-EDR daemon configuration.
///
/// The fields mirror SDD §8.1. Paths are stored as strings because downstream
/// JSON health endpoints and operator-facing errors need to echo the exact
/// effective path without platform-specific `PathBuf` serialization behavior.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Config {
    /// Threat score threshold for alert generation; valid inclusive range is `[0.0, 1.0]`.
    pub alert_threshold: f64,
    /// Monitored syscall probes after stable duplicate removal.
    pub monitored_syscalls: Vec<SyscallType>,
    /// Sliding feature-window duration in seconds; must be strictly positive.
    pub window_duration_secs: u64,
    /// BPF ring-buffer capacity in memory pages.
    pub ring_buffer_size_pages: u32,
    /// Localhost web/API port; `0` delegates port assignment to the kernel.
    pub web_port: u16,
    /// Append-only alert log path confined to the configured log directory.
    pub log_file_path: String,
    /// Directory that owns daemon-managed mutable state files such as alert IDs.
    pub state_dir: String,
    /// Alert-ID persistence file confined to the configured state directory.
    pub alert_id_seq_path: String,
    /// ML model artifact path consumed by the detection engine.
    pub model_path: String,
    /// Whether the daemon should launch the ratatui interface.
    pub enable_tui: bool,
    /// Whether the daemon should serve the localhost web dashboard.
    pub enable_web: bool,
    /// Structured daemon logging level.
    pub log_level: LogLevel,
}

impl Config {
    /// Parse and validate a TOML configuration string using the production log directory.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when TOML decoding fails or any SDD §8.1 /
    /// NFR-SE05 validation rule rejects a field.
    pub fn from_toml_str(input: &str) -> Result<Self, ConfigError> {
        Self::from_toml_str_with_log_dir(input, DEFAULT_LOG_DIRECTORY)
    }

    /// Parse and validate a TOML configuration string with an explicit log directory.
    ///
    /// This variant lets the daemon use a user-owned development directory such
    /// as `./logs` while preserving the same path-traversal policy used for the
    /// production default. Relative `log_file_path` values are interpreted
    /// under `log_directory`; absolute values must already be inside it.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when TOML decoding fails, `log_directory` cannot
    /// be normalized, or any semantic validation rule rejects a field.
    pub fn from_toml_str_with_log_dir(
        input: &str,
        log_directory: impl AsRef<Path>,
    ) -> Result<Self, ConfigError> {
        let raw: RawConfig = toml::from_str(input).map_err(ConfigError::Toml)?;
        raw.into_config(log_directory.as_ref())
    }

    /// Apply an env-style alert-ID sequence-path override to an existing config.
    ///
    /// Relative override values are resolved beneath the already-validated
    /// `state_dir`, which keeps the runtime override independent from the alert
    /// log directory while preserving the same traversal/symlink policy as the
    /// config-file field.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if the override escapes the configured state
    /// directory or otherwise resolves to an invalid path.
    pub fn with_alert_id_seq_path_override(
        mut self,
        override_path: &str,
    ) -> Result<Self, ConfigError> {
        self.alert_id_seq_path =
            validate_alert_id_seq_path(override_path, Path::new(&self.state_dir))?;
        Ok(self)
    }
}

impl Default for Config {
    fn default() -> Self {
        // Defaults are copied from SDD §8.1. Keeping them in one constructor
        // avoids drift between serde's "missing field" behavior and operator
        // documentation as later daemon startup code grows.
        Self {
            alert_threshold: 0.7,
            monitored_syscalls: vec![
                SyscallType::Execve,
                SyscallType::Openat,
                SyscallType::Connect,
                SyscallType::Clone,
            ],
            window_duration_secs: 30,
            ring_buffer_size_pages: 64,
            web_port: 8_080,
            log_file_path: "/var/log/mini-edr/alerts.jsonl".to_owned(),
            state_dir: DEFAULT_STATE_DIRECTORY.to_owned(),
            alert_id_seq_path: format!("{DEFAULT_STATE_DIRECTORY}/{ALERT_ID_SEQUENCE_FILE_NAME}"),
            model_path: "/etc/mini-edr/model.onnx".to_owned(),
            enable_tui: true,
            enable_web: true,
            log_level: LogLevel::Info,
        }
    }
}

/// Daemon log verbosity accepted by SDD §8.1.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum LogLevel {
    /// Trace-level logging for the most verbose diagnostics.
    Trace,
    /// Debug-level logging, including detection inference records.
    Debug,
    /// Informational logging used by default.
    #[default]
    Info,
    /// Warning logging for recoverable issues.
    Warn,
    /// Error logging for failed operations that need operator attention.
    Error,
}

impl LogLevel {
    fn parse(value: &str) -> Result<Self, ConfigError> {
        match value {
            "trace" => Ok(Self::Trace),
            "debug" => Ok(Self::Debug),
            "info" => Ok(Self::Info),
            "warn" => Ok(Self::Warn),
            "error" => Ok(Self::Error),
            other => Err(ConfigError::Validation {
                field: "log_level",
                message: format!(
                    "`{other}` is not supported; expected one of trace, debug, info, warn, error"
                ),
            }),
        }
    }
}

/// Parsed Linux kernel version used for Mini-EDR's kernel `>= 5.8` gate.
///
/// Distro and release-candidate suffixes are preserved for diagnostics but do
/// not affect ordering because NFR-PO01 depends only on the numeric version
/// tuple where `BPF_MAP_TYPE_RINGBUF` first appeared.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelVersion {
    /// Kernel major version, e.g. `5` for `5.8.0-1042-azure`.
    pub major: u32,
    /// Kernel minor version, e.g. `8` for `5.8.0-1042-azure`.
    pub minor: u32,
    /// Kernel patch version, defaulting to `0` when omitted by `uname -r`.
    pub patch: u32,
    /// Optional suffix after the first `-`, such as `rc1` or `1042-azure`.
    pub suffix: Option<String>,
}

impl KernelVersion {
    /// Parse a Linux `uname -r` style kernel release string.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if the release does not begin with a numeric
    /// `major.minor` or `major.minor.patch` tuple.
    pub fn parse(release: &str) -> Result<Self, ConfigError> {
        let (numeric, suffix) = release
            .split_once('-')
            .map_or((release, None), |(head, tail)| (head, Some(tail)));
        let parts = numeric.split('.').collect::<Vec<_>>();

        if !(2..=3).contains(&parts.len()) || parts.iter().any(|part| part.is_empty()) {
            return Err(ConfigError::KernelVersion {
                value: release.to_owned(),
                message: "kernel version must start with major.minor[.patch]".to_owned(),
            });
        }

        // Parsing the numeric tuple explicitly keeps suffix handling simple:
        // `5.10.0-rc1` compares as 5.10.0, while non-numeric strings such as
        // `garbage` fail with an operator-actionable message.
        let major = parse_kernel_component(release, parts[0], "major")?;
        let minor = parse_kernel_component(release, parts[1], "minor")?;
        let patch = parts
            .get(2)
            .map_or(Ok(0), |part| parse_kernel_component(release, part, "patch"))?;

        Ok(Self {
            major,
            minor,
            patch,
            suffix: suffix.map(ToOwned::to_owned),
        })
    }

    /// Return whether this kernel satisfies Mini-EDR's Linux `>= 5.8` contract.
    #[must_use]
    pub const fn supports_mini_edr(&self) -> bool {
        self.major > 5 || (self.major == 5 && self.minor >= 8)
    }
}

/// Error produced while parsing or validating Mini-EDR configuration.
#[derive(Debug)]
pub enum ConfigError {
    /// TOML syntax or decode error from the `toml` crate.
    Toml(toml::de::Error),
    /// A semantically invalid field with a descriptive operator-facing message.
    Validation {
        /// Name of the offending configuration field.
        field: &'static str,
        /// Explanation of the rejected value and accepted policy.
        message: String,
    },
    /// Kernel-version parser error.
    KernelVersion {
        /// Raw kernel release string that failed parsing.
        value: String,
        /// Explanation of the expected kernel-version shape.
        message: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Toml(error) => write!(formatter, "TOML parse error: {error}"),
            Self::Validation { field, message } => write!(formatter, "{field}: {message}"),
            Self::KernelVersion { value, message } => {
                write!(formatter, "kernel version `{value}` is invalid: {message}")
            }
        }
    }
}

impl Error for ConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Toml(error) => Some(error),
            Self::Validation { .. } | Self::KernelVersion { .. } => None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct RawConfig {
    alert_threshold: Option<f64>,
    monitored_syscalls: Option<Vec<String>>,
    window_duration_secs: Option<u64>,
    ring_buffer_size_pages: Option<u32>,
    web_port: Option<u16>,
    log_file_path: Option<String>,
    state_dir: Option<String>,
    alert_id_seq_path: Option<String>,
    model_path: Option<String>,
    enable_tui: Option<bool>,
    enable_web: Option<bool>,
    log_level: Option<String>,
}

impl RawConfig {
    fn into_config(self, log_directory: &Path) -> Result<Config, ConfigError> {
        let defaults = Config::default();
        let alert_threshold = self.alert_threshold.unwrap_or(defaults.alert_threshold);
        validate_alert_threshold(alert_threshold)?;

        let monitored_syscalls = self
            .monitored_syscalls
            .map_or(Ok(defaults.monitored_syscalls), validate_monitored_syscalls)?;

        let window_duration_secs = self
            .window_duration_secs
            .unwrap_or(defaults.window_duration_secs);
        validate_window_duration(window_duration_secs)?;

        let ring_buffer_size_pages = self
            .ring_buffer_size_pages
            .unwrap_or(defaults.ring_buffer_size_pages);
        validate_ring_buffer_size(ring_buffer_size_pages)?;

        let web_port = self.web_port.unwrap_or(defaults.web_port);
        let log_file_path = validate_log_file_path(
            self.log_file_path
                .as_deref()
                .unwrap_or(&defaults.log_file_path),
            log_directory,
        )?;
        let state_dir =
            validate_state_dir(self.state_dir.as_deref().unwrap_or(DEFAULT_STATE_DIRECTORY))?;
        let alert_id_seq_path = validate_alert_id_seq_path(
            self.alert_id_seq_path
                .as_deref()
                .unwrap_or(ALERT_ID_SEQUENCE_FILE_NAME),
            Path::new(&state_dir),
        )?;
        let log_level = self
            .log_level
            .map_or(Ok(defaults.log_level), |value| LogLevel::parse(&value))?;

        Ok(Config {
            alert_threshold,
            monitored_syscalls,
            window_duration_secs,
            ring_buffer_size_pages,
            web_port,
            log_file_path,
            state_dir,
            alert_id_seq_path,
            model_path: self.model_path.unwrap_or(defaults.model_path),
            enable_tui: self.enable_tui.unwrap_or(defaults.enable_tui),
            enable_web: self.enable_web.unwrap_or(defaults.enable_web),
            log_level,
        })
    }
}

fn validate_alert_threshold(value: f64) -> Result<(), ConfigError> {
    if value.is_finite() && (0.0..=1.0).contains(&value) {
        Ok(())
    } else {
        Err(ConfigError::Validation {
            field: "alert_threshold",
            message: format!("value {value} must be finite and in [0.0, 1.0]"),
        })
    }
}

fn validate_monitored_syscalls(values: Vec<String>) -> Result<Vec<SyscallType>, ConfigError> {
    if values.is_empty() {
        return Err(ConfigError::Validation {
            field: "monitored_syscalls",
            message: "list must contain at least one syscall".to_owned(),
        });
    }

    let mut deduplicated = Vec::with_capacity(values.len());
    for value in values {
        let syscall =
            SyscallType::from_config_name(&value).map_err(|unknown| ConfigError::Validation {
                field: "monitored_syscalls",
                message: format!(
                    "`{unknown}` is not supported; expected execve, openat, connect, or clone"
                ),
            })?;

        // VAL-DAEMON-018 allows either rejection or documented duplicate
        // handling. We choose stable deduplication so a repeated entry cannot
        // attach duplicate probes, while preserving operator intent and order.
        if !deduplicated.contains(&syscall) {
            deduplicated.push(syscall);
        }
    }

    Ok(deduplicated)
}

fn validate_window_duration(value: u64) -> Result<(), ConfigError> {
    if value > 0 {
        Ok(())
    } else {
        Err(ConfigError::Validation {
            field: "window_duration_secs",
            message: "value must be greater than 0 seconds".to_owned(),
        })
    }
}

fn validate_ring_buffer_size(value: u32) -> Result<(), ConfigError> {
    if value > 0 {
        Ok(())
    } else {
        Err(ConfigError::Validation {
            field: "ring_buffer_size_pages",
            message: "value must be at least 1 page".to_owned(),
        })
    }
}

fn validate_log_file_path(value: &str, log_directory: &Path) -> Result<String, ConfigError> {
    validate_path_within_directory(value, log_directory, "log_file_path")
}

fn validate_state_dir(value: &str) -> Result<String, ConfigError> {
    let raw_path = Path::new(value);
    let normalized_requested_path =
        normalize_absolute_path(&absolute_path(raw_path).map_err(|message| {
            ConfigError::Validation {
                field: "state_dir",
                message,
            }
        })?)
        .map_err(|message| ConfigError::Validation {
            field: "state_dir",
            message,
        })?;
    let canonical_state_dir = canonicalize_existing_path(&normalized_requested_path, true)
        .map_err(|message| ConfigError::Validation {
            field: "state_dir",
            message,
        })?;
    Ok(canonical_state_dir.to_string_lossy().into_owned())
}

fn validate_alert_id_seq_path(value: &str, state_directory: &Path) -> Result<String, ConfigError> {
    validate_path_within_directory(value, state_directory, "alert_id_seq_path")
}

fn validate_path_within_directory(
    value: &str,
    directory: &Path,
    field: &'static str,
) -> Result<String, ConfigError> {
    let raw_path = Path::new(value);

    let canonical_directory = canonicalize_existing_path(directory, true)
        .map_err(|message| ConfigError::Validation { field, message })?;

    let requested_path = if raw_path.is_absolute() {
        raw_path.to_path_buf()
    } else {
        directory.join(raw_path)
    };
    let normalized_requested_path = normalize_absolute_path(
        &absolute_path(&requested_path)
            .map_err(|message| ConfigError::Validation { field, message })?,
    )
    .map_err(|message| ConfigError::Validation { field, message })?;
    let requested_parent =
        normalized_requested_path
            .parent()
            .ok_or_else(|| ConfigError::Validation {
                field,
                message: format!(
                    "`{value}` must include a filename below the configured directory"
                ),
            })?;
    let canonical_parent =
        canonicalize_existing_path(requested_parent, false).map_err(|message| {
            ConfigError::Validation {
                field,
                message: format!(
                    "`{value}` has invalid parent `{}`: {message}",
                    requested_parent.display()
                ),
            }
        })?;

    if !canonical_parent.starts_with(&canonical_directory) {
        return Err(ConfigError::Validation {
            field,
            message: format!(
                "`{value}` resolves to parent `{}` but must remain within {}",
                canonical_parent.display(),
                canonical_directory.display()
            ),
        });
    }

    let file_name =
        normalized_requested_path
            .file_name()
            .ok_or_else(|| ConfigError::Validation {
                field,
                message: format!(
                    "`{value}` must include a filename below the configured directory"
                ),
            })?;
    let effective_path = canonical_parent.join(file_name);

    Ok(effective_path.to_string_lossy().into_owned())
}

fn absolute_path(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|current_dir| current_dir.join(path))
            .map_err(|error| {
                format!(
                    "could not resolve relative path `{}` against the current directory: {error}",
                    path.display()
                )
            })
    }
}

fn canonicalize_existing_path(
    path: &Path,
    require_final_directory: bool,
) -> Result<PathBuf, String> {
    let normalized = normalize_absolute_path(&absolute_path(path)?)?;
    let mut existing_prefix = PathBuf::from("/");
    let mut missing_components = Vec::new();

    // NFR-SE05/TC-69 require filesystem-aware path confinement, not just
    // lexical `..` cleanup. Walking from the root lets us canonicalize the
    // deepest existing parent with `std::fs::canonicalize`, resolving any
    // symlink component before the final starts-with confinement check.
    for component in normalized.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(segment) if missing_components.is_empty() => {
                let candidate = existing_prefix.join(segment);
                if candidate.exists() {
                    existing_prefix = candidate;
                } else {
                    missing_components.push(segment.to_owned());
                }
            }
            Component::Normal(segment) => missing_components.push(segment.to_owned()),
            Component::ParentDir | Component::Prefix(_) => {
                return Err(format!(
                    "`{}` contains an unsupported path component after normalization",
                    path.display()
                ));
            }
        }
    }

    let mut canonical = fs::canonicalize(&existing_prefix).map_err(|error| {
        format!(
            "could not canonicalize existing path component `{}` for `{}`: {error}",
            existing_prefix.display(),
            path.display()
        )
    })?;

    if !canonical.is_dir() {
        return Err(format!(
            "`{}` resolves through `{}` which is not a directory",
            path.display(),
            canonical.display()
        ));
    }

    if missing_components.is_empty() && require_final_directory && !canonical.is_dir() {
        return Err(format!(
            "`{}` must be an existing or creatable directory",
            path.display()
        ));
    }

    for component in missing_components {
        canonical.push(component);
    }

    Ok(canonical)
}

fn normalize_absolute_path(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err(format!(
            "`{}` must be absolute after log-directory resolution",
            path.display()
        ));
    }

    let mut normalized = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(format!(
                        "`{}` escapes above the filesystem root",
                        path.display()
                    ));
                }
            }
            Component::Normal(segment) => normalized.push(segment),
            Component::Prefix(_) => {
                return Err(format!(
                    "`{}` contains an unsupported path prefix",
                    path.display()
                ));
            }
        }
    }

    Ok(normalized)
}

fn parse_kernel_component(
    release: &str,
    component: &str,
    label: &'static str,
) -> Result<u32, ConfigError> {
    component
        .parse::<u32>()
        .map_err(|error| ConfigError::KernelVersion {
            value: release.to_owned(),
            message: format!("{label} component `{component}` is not numeric: {error}"),
        })
}
