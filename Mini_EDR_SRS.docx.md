# Mini-EDR Software Requirements Specification

## 1. Introduction

This Software Requirements Specification (SRS) document describes the functional and non-functional requirements for Mini-EDR, a lightweight Endpoint Detection and Response system built on eBPF kernel instrumentation and on-device machine learning inference. This document is intended to provide a complete description of the system’s behavior so that designers can build it and testers can verify it.

### 1.1 Purpose

The purpose of this SRS is to define the requirements for the Mini-EDR system at a level sufficient for system design, implementation, and testing. The intended audience includes the development team (sensor engineers, pipeline engineers, ML engineers, frontend engineers, and the DevOps/integration lead), the course instructor and graders for SWE 3313, and any future contributors or maintainers of the system.

### 1.2 Scope

The software product is Mini-EDR, a Linux daemon and accompanying visualization interfaces that provide real-time endpoint threat detection. The system will:

- Monitor a Linux host by attaching eBPF probes to kernel tracepoints for key syscalls (`execve`, `openat`, `connect`, `clone`) and delivering events to userspace via BPF ring buffer.
- Enrich raw kernel events with process metadata from `/proc` (process ancestry, cgroup, binary path, UID) and aggregate them into per-process behavioral timelines using sliding windows.
- Run a locally-deployed machine learning model (XGBoost classifier exported to ONNX or native format) to classify process behavior as benign or malicious, producing a numerical threat score.
- Surface structured JSON alerts with full process context through a terminal user interface (TUI) and a localhost-served web dashboard.

The system will not perform automated remediation (for example, killing processes or isolating hosts), will not support operating systems other than Linux `x86_64`, and will not provide multi-host fleet management or centralized aggregation.

The primary benefit of Mini-EDR is providing lightweight, open, cloud-independent endpoint visibility using modern kernel instrumentation techniques. It serves both as a functional security tool for resource-constrained environments and as an educational reference implementation of eBPF-native security architecture.

### 1.3 Definitions, Acronyms, and Abbreviations

| Term | Definition |
| --- | --- |
| EDR | Endpoint Detection and Response. A category of security software that continuously monitors host machines for threats and provides investigation and response capabilities. |
| eBPF | Extended Berkeley Packet Filter. A Linux kernel technology that allows sandboxed programs to run in kernel space without modifying the kernel or loading kernel modules. Programs are verified by the kernel before execution. |
| BPF Ring Buffer | A kernel-to-userspace data structure (`BPF_MAP_TYPE_RINGBUF`) for efficient event delivery from eBPF programs to userspace consumers. Introduced in Linux kernel 5.8. |
| CO-RE | Compile Once, Run Everywhere. A BPF portability mechanism that allows eBPF programs to run across different kernel versions without recompilation, using BTF (BPF Type Format) metadata. |
| Aya | A pure-Rust library for writing, loading, and managing eBPF programs, eliminating the need for C code in BPF development. |
| Syscall | System call. The interface through which userspace programs request services from the Linux kernel (for example, `execve`, `openat`, `connect`, `clone`). |
| Tracepoint | A static instrumentation point in the Linux kernel that eBPF programs can attach to for observing specific kernel events such as syscall entry and exit. |
| ONNX | Open Neural Network Exchange. An open format for representing machine learning models, enabling interoperability between training frameworks (for example, PyTorch) and inference runtimes (for example, ONNX Runtime). |
| XGBoost | Extreme Gradient Boosting. An optimized gradient-boosted decision tree algorithm widely used for classification and regression on tabular data. |
| TUI | Terminal User Interface. A text-based graphical interface rendered in a terminal emulator, built using libraries such as ratatui in Rust. |
| SOC | Security Operations Center. A centralized team or facility responsible for monitoring and analyzing an organization's security posture. |
| BETH Dataset | BPF-Extended Tracking Honeypot Dataset. A cybersecurity dataset containing over 8 million kernel-level process events collected from 23 honeypot hosts, used for anomaly detection research. |
| Feature Vector | A fixed-size numerical representation of a process's behavior within a time window, derived from raw syscall events through feature engineering. |
| SSE | Server-Sent Events. A server push technology enabling a server to send real-time updates to a client over an HTTP connection. |
| WebSocket | A communication protocol providing full-duplex communication channels over a single TCP connection, used for real-time data streaming between the daemon and web dashboard. |
| Threat Score | A numerical value between 0 and 1 output by the behavior model indicating the estimated probability that a process's behavior is malicious. |
| Process Ancestry Tree | A hierarchical representation of parent-child relationships between processes, reconstructed from `/proc` metadata and clone/fork events. |

### 1.4 References

1. Mini-EDR Project Plan, SWE 3313, Team 4, 2026.
2. Highnam, K., Arulkumaran, K., Hanif, Z., and Jennings, N.R. “BETH Dataset: Real Cybersecurity Data for Anomaly Detection Research.” ICML Workshop on Uncertainty and Robustness in Deep Learning, 2021. Available at: https://www.kaggle.com/datasets/katehighnam/beth-dataset
3. Chen, T. and Guestrin, C. “XGBoost: A Scalable Tree Boosting System.” KDD 2016. Available at: https://arxiv.org/abs/1603.02754
4. Aya eBPF Library Documentation. Available at: https://aya-rs.dev/
5. Linux Kernel BPF Documentation. Available at: https://docs.kernel.org/bpf/
6. ONNX Runtime Documentation. Available at: https://onnxruntime.ai/
7. ratatui Terminal UI Library. Available at: https://ratatui.rs/
8. Cilium Tetragon: eBPF-based Security Observability and Runtime Enforcement. Available at: https://tetragon.io/

## 2. Specific Requirements

### 2.1 External Interfaces

This section describes all inputs into and outputs from the Mini-EDR system.

1. **EI-1: Linux Kernel Tracepoints (Input).** The system receives raw syscall event data from the Linux kernel via eBPF tracepoint attachments. Events are generated by the kernel whenever a monitored syscall (`execve`, `openat`, `connect`, `clone`) is invoked by any process on the host. Data is delivered through the BPF ring buffer shared memory interface.
2. **EI-2: `/proc` Filesystem (Input).** The system reads process metadata from the Linux `/proc` pseudo-filesystem, including `/proc/[pid]/status`, `/proc/[pid]/exe`, `/proc/[pid]/cgroup`, and `/proc/[pid]/stat`. This data is used to enrich raw events with process ancestry, binary path, cgroup context, and user identity.
3. **EI-3: ML Model Artifact (Input).** The system loads a pre-trained machine learning model from a file on disk at daemon startup. The model is stored in ONNX format or XGBoost native JSON format. The file is produced offline by the training pipeline and is not modified at runtime.
4. **EI-4: Configuration File (Input).** The system reads a TOML configuration file at startup specifying parameters such as alert threshold, monitored syscalls, sliding window duration, ring buffer size, and web dashboard port.
5. **EI-5: JSON Alert Log (Output).** The system writes structured JSON alert records to a log file on disk. Each alert contains process ID, process name, binary path, process ancestry chain, threat score, contributing feature values, timestamp, and a human-readable summary.
6. **EI-6: TUI Display (Output).** The system renders a live terminal interface displaying a process tree with color-coded threat scores, a scrollable alert timeline, and a real-time event stream counter. Output is rendered to the terminal via ANSI escape sequences through the ratatui library.
7. **EI-7: Web Dashboard (Output).** The system serves a web-based dashboard on a configurable localhost port. The dashboard receives real-time data from the daemon via WebSocket or Server-Sent Events (SSE) and displays process trees, alert timelines, and telemetry summaries in a browser.

### 2.2 Functional Requirements

The following tables enumerate the functional requirements organized by subsystem. Each requirement is assigned a unique identifier for traceability and a priority level (High, Medium, or Low).

#### 2.2.1 eBPF Sensor Layer

| Req. ID | Description | Priority |
| --- | --- | --- |
| FR-S01 | The system shall attach eBPF tracepoint probes to syscall entry points for `execve`, `openat`, `connect`, and `clone`. | High |
| FR-S02 | The system shall capture the following fields from each syscall event: timestamp, process ID, thread ID, parent process ID, syscall number, and syscall-specific arguments (for example, filename for `openat`, IP address and port for `connect`). | High |
| FR-S03 | The system shall deliver captured events from kernel space to userspace via BPF ring buffer (`BPF_MAP_TYPE_RINGBUF`). | High |
| FR-S04 | The system shall use CO-RE (Compile Once, Run Everywhere) with BTF metadata so that eBPF probes function across kernel versions 5.8 and above without recompilation. | High |
| FR-S05 | The system shall allow eBPF probes to be dynamically attached and detached at runtime without restarting the daemon. | Medium |
| FR-S06 | The system shall drop events gracefully when the ring buffer is full rather than blocking kernel execution. | High |

#### 2.2.2 Telemetry Pipeline

| Req. ID | Description | Priority |
| --- | --- | --- |
| FR-P01 | The system shall consume events from the BPF ring buffer and deserialize them into structured Rust data types. | High |
| FR-P02 | The system shall enrich each event with process metadata by reading `/proc/[pid]/status`, `/proc/[pid]/exe`, `/proc/[pid]/cgroup`, and `/proc/[pid]/stat`. | High |
| FR-P03 | The system shall reconstruct process ancestry trees by tracking parent-child relationships via clone events and `/proc` metadata. | High |
| FR-P04 | The system shall aggregate events into per-process sliding windows of configurable duration (default: 30 seconds). | High |
| FR-P05 | The system shall compute feature vectors from each window, including: syscall frequency counts, syscall bigram/trigram frequency distributions, Shannon entropy of file paths accessed, count of unique IP addresses contacted, count of unique files opened, child process spawn count, average inter-syscall timing, and boolean flags for writes to sensitive directories (`/etc`, `/tmp`, `/dev`). | High |
| FR-P06 | The system shall handle short-lived processes (those that exit before a full window elapses) by computing features over the available partial window. | Medium |
| FR-P07 | The system shall deduplicate redundant events (for example, rapid repeated `openat` calls on the same file) before feature computation. | Low |

#### 2.2.3 Detection Engine

| Req. ID | Description | Priority |
| --- | --- | --- |
| FR-D01 | The system shall load a pre-trained ML model from disk at daemon startup. | High |
| FR-D02 | The system shall run inference on each completed feature vector, producing a threat score between `0.0` (benign) and `1.0` (malicious). | High |
| FR-D03 | The system shall compare each threat score against a configurable alert threshold (default: `0.7`) and generate an alert when the threshold is exceeded. | High |
| FR-D04 | The system shall include in each alert: process ID, process name, binary path, parent process chain, threat score, the top 5 contributing features (by importance), timestamp, and a human-readable summary string. | High |
| FR-D05 | The system shall support hot-reloading of the ML model artifact without restarting the daemon, triggered by a `SIGHUP` signal or API call. | Medium |
| FR-D06 | The system shall log all inference results (not just alerts) at debug log level for offline analysis and model evaluation. | Low |

#### 2.2.4 Alerting and Output

| Req. ID | Description | Priority |
| --- | --- | --- |
| FR-A01 | The system shall write each alert as a single-line JSON record to a configurable log file path. | High |
| FR-A02 | The system shall expose alert and telemetry data over a local API endpoint (Unix socket or HTTP on localhost) for consumption by visualization interfaces. | High |
| FR-A03 | The system shall support log rotation by reopening the log file on receipt of a `SIGUSR1` signal. | Low |

#### 2.2.5 Terminal User Interface (TUI)

| Req. ID | Description | Priority |
| --- | --- | --- |
| FR-T01 | The system shall display a live process tree showing all currently running processes with their threat scores, updated at least once per second. | High |
| FR-T02 | The system shall color-code processes in the tree by threat level: green (score < 0.3), yellow (0.3 <= score < 0.7), red (score >= 0.7). | High |
| FR-T03 | The system shall display a scrollable alert timeline showing the most recent alerts in reverse chronological order. | High |
| FR-T04 | The system shall display a real-time event counter showing events processed per second. | Medium |
| FR-T05 | The system shall allow the user to select a process in the tree and view its detailed event history and feature vector. | Medium |
| FR-T06 | The system shall respond to keyboard input (arrow keys, enter, `q` to quit) with latency under 100ms. | High |

#### 2.2.6 Web Dashboard

| Req. ID | Description | Priority |
| --- | --- | --- |
| FR-W01 | The system shall serve a web dashboard on a configurable localhost port (default: `8080`). | High |
| FR-W02 | The dashboard shall display a live process tree with threat-score coloring matching the TUI color scheme. | High |
| FR-W03 | The dashboard shall display an alert timeline with filtering by severity (low, medium, high) and time range. | Medium |
| FR-W04 | The dashboard shall receive real-time updates from the daemon via WebSocket or SSE without requiring manual page refresh. | High |
| FR-W05 | The dashboard shall allow the user to click on a process to view its detailed behavioral profile including feature values, syscall history, and ancestry chain. | Medium |
| FR-W06 | The dashboard shall display a system health overview including events per second, ring buffer utilization, and inference latency. | Low |

### 2.3 Non-Functional Requirements

#### 2.3.1 Performance

| Req. ID | Description | Priority |
| --- | --- | --- |
| NFR-P01 | The eBPF sensor shall impose no more than 2% CPU overhead on the monitored host under normal workload conditions (defined as fewer than 10,000 syscall events per second). | High |
| NFR-P02 | The telemetry pipeline shall process and enrich events at a sustained throughput of at least 50,000 events per second without dropping events. | High |
| NFR-P03 | ML inference on a single feature vector shall complete in under 10 milliseconds. | High |
| NFR-P04 | End-to-end latency from syscall occurrence to alert generation shall not exceed 5 seconds under normal workload. | High |
| NFR-P05 | The TUI shall render updates at a minimum of 1 frame per second with no visible input lag. | Medium |
| NFR-P06 | The web dashboard shall deliver updates to connected clients within 2 seconds of alert generation. | Medium |
| NFR-P07 | The daemon shall consume no more than 256 MB of resident memory under normal operation. | High |

#### 2.3.2 Reliability

| Req. ID | Description | Priority |
| --- | --- | --- |
| NFR-R01 | The eBPF sensor shall not cause kernel panics, deadlocks, or data corruption under any conditions. All BPF programs shall pass the kernel verifier before loading. | High |
| NFR-R02 | The daemon shall handle malformed or unexpected `/proc` data gracefully (for example, a process exiting between event capture and enrichment) without crashing. | High |
| NFR-R03 | The daemon shall handle ML model loading failures at startup by falling back to a pass-through mode that logs events without scoring, and shall emit a clear warning. | Medium |
| NFR-R04 | The system shall produce no false negatives on the integration test suite of known malicious behaviors (reverse shell, privilege escalation, cryptominer simulation, port scan). | High |

#### 2.3.3 Availability

| Req. ID | Description | Priority |
| --- | --- | --- |
| NFR-AV01 | The daemon shall be designed for continuous 24/7 operation as a system service. | High |
| NFR-AV02 | The daemon shall automatically reconnect to the BPF ring buffer if it is temporarily unavailable due to probe reloading. | Medium |
| NFR-AV03 | Upon unexpected daemon termination, the system shall cleanly detach all eBPF probes so that no orphaned programs remain loaded in the kernel. | High |
| NFR-AV04 | The daemon shall be restartable without data loss; alert logs shall be append-only and survive daemon restarts. | High |

#### 2.3.4 Security

| Req. ID | Description | Priority |
| --- | --- | --- |
| NFR-SE01 | The daemon shall require `CAP_BPF` and `CAP_PERFMON` capabilities (or root privileges) and shall refuse to start without them, displaying a clear error message. | High |
| NFR-SE02 | The web dashboard shall bind only to localhost (`127.0.0.1`) by default and shall not be accessible from external network interfaces unless explicitly reconfigured. | High |
| NFR-SE03 | The alert log file shall be created with permissions `0600` (owner read/write only). | Medium |
| NFR-SE04 | The system shall not expose raw kernel memory addresses or other sensitive kernel internals in alert output or API responses. | High |
| NFR-SE05 | The configuration file shall be validated at startup; invalid or malicious configuration values shall be rejected with descriptive error messages. | Medium |

#### 2.3.5 Maintainability

| Req. ID | Description | Priority |
| --- | --- | --- |
| NFR-M01 | The codebase shall be organized into separate Rust crates or modules for the sensor, pipeline, detection engine, TUI, and web server, allowing independent compilation and testing of each subsystem. | High |
| NFR-M02 | All public functions and module interfaces shall include Rust doc comments describing purpose, parameters, return values, and error conditions. | Medium |
| NFR-M03 | The project shall include unit tests for each module achieving a minimum of 70% code coverage on the userspace daemon. | Medium |
| NFR-M04 | The project shall include a README with build instructions, usage guide, architecture overview, and contribution guidelines. | High |

#### 2.3.6 Portability

| Req. ID | Description | Priority |
| --- | --- | --- |
| NFR-PO01 | The system shall run on Linux `x86_64` systems with kernel version 5.8 or later. No other operating system or architecture is supported. | High |
| NFR-PO02 | The system shall be buildable and runnable within the provided Docker or Vagrant development environment on any host OS capable of running Linux VMs (macOS, Windows, Linux). | High |
| NFR-PO03 | The eBPF probes shall use CO-RE and BTF to ensure portability across kernel versions 5.8 through 6.x without recompilation. | High |
| NFR-PO04 | Host-dependent code (kernel version detection, capability checks, `/proc` parsing) shall be isolated in a dedicated platform abstraction module comprising no more than 10% of total daemon code. | Medium |

### 2.4 Database Requirements

Mini-EDR does not use a traditional relational or NoSQL database. All data is processed as in-memory streams and persisted only as append-only log files. The logical data entities are as follows:

- **SyscallEvent:** The atomic unit of data captured by the sensor. Fields: `event_id (u64)`, `timestamp (u64 nanoseconds)`, `pid (u32)`, `tid (u32)`, `ppid (u32)`, `syscall_type (enum: Execve, Openat, Connect, Clone)`, and syscall-specific argument fields (`filename: String`, `ip_address: [u8;4]`, `port: u16`, `child_pid: u32`).
- **EnrichedEvent:** A `SyscallEvent` augmented with process metadata. Additional fields: `process_name (String)`, `binary_path (String)`, `cgroup (String)`, `uid (u32)`, `ancestry_chain (Vec<ProcessInfo>)`.
- **FeatureVector:** A fixed-size numerical representation of a process window. Fields: `pid (u32)`, `window_start (u64)`, `window_end (u64)`, and approximately `20–40` floating-point feature values (syscall counts, ratios, entropy values, timing statistics, boolean flags).
- **Alert:** A detection result exceeding the alert threshold. Fields: `alert_id (u64)`, `timestamp (u64)`, `pid (u32)`, `process_name (String)`, `binary_path (String)`, `ancestry_chain (Vec<ProcessInfo>)`, `threat_score (f64)`, `top_features (Vec<FeatureContribution>)`, `summary (String)`.
- **ProcessInfo:** A lightweight process descriptor used in ancestry chains. Fields: `pid (u32)`, `process_name (String)`, `binary_path (String)`.

Data flows unidirectionally: `SyscallEvent -> EnrichedEvent -> FeatureVector -> Alert`. No data is written back upstream. Alert records are serialized to JSON and appended to the log file. In-memory state (process trees, active windows) is reconstructed from the live event stream at daemon startup and does not require persistent storage.

### 2.5 Design Constraints

- **Linux kernel 5.8+ required:** The BPF ring buffer (`BPF_MAP_TYPE_RINGBUF`) was introduced in kernel 5.8. Systems running older kernels are not supported.
- **Root or `CAP_BPF`/`CAP_PERFMON` required:** Loading eBPF programs into the kernel requires elevated privileges. The daemon cannot operate without them.
- **Rust stable toolchain:** The daemon must compile with the latest stable Rust toolchain. Nightly features are not permitted to ensure build reproducibility.
- **Aya eBPF library:** eBPF probes are written in Rust using Aya. The project does not use `libbpf-rs` or require a C toolchain for BPF compilation unless Aya proves insufficient for a specific probe type.
- **ONNX Runtime or XGBoost native format:** The ML model must be exportable from the Python training environment and loadable in Rust. Only ONNX (via the `ort` crate) and XGBoost native JSON (via `xgboost-rs` or equivalent) are supported inference formats.
- **No kernel modules:** The system must not load any custom kernel modules. All kernel instrumentation must use the eBPF subsystem exclusively.
- **Single-host deployment:** The system is designed for single-host monitoring only. No distributed communication protocols or multi-host aggregation are required.
- **Localhost-only web interface:** The web dashboard must bind to `127.0.0.1` by default. Exposing it on `0.0.0.0` requires explicit configuration change.

## 3. Use Case Models

### 3.1 Use Case Diagrams

The Mini-EDR system has three primary actors:

- **Security Analyst:** A human user who monitors the system via the TUI or web dashboard, reviews alerts, investigates suspicious processes, and configures detection parameters.
- **System Administrator:** A human user who installs, configures, starts, stops, and maintains the Mini-EDR daemon and its development environment.
- **Linux Kernel:** An external system actor that generates syscall events observed by the eBPF sensor probes.

The following use cases are identified:

- **Security Analyst use cases:** View Live Process Tree (UC-01), Review Alert Timeline (UC-02), Inspect Process Details (UC-03), Filter Alerts by Severity (UC-04), Adjust Alert Threshold (UC-05).
- **System Administrator use cases:** Start Daemon (UC-06), Stop Daemon (UC-07), Reload ML Model (UC-08), Configure Monitored Syscalls (UC-09), View System Health Metrics (UC-10).
- **Linux Kernel use case:** Generate Syscall Event (UC-11).

### 3.2 Use Case Descriptions

#### UC-01: View Live Process Tree

- **Requirements:** The system must allow a Security Analyst to view all currently running processes in a hierarchical tree, with each process annotated by its current threat score and color-coded by severity.
- **Pre-conditions:** The Mini-EDR daemon is running with eBPF probes attached and the ML model loaded. The analyst has opened either the TUI or web dashboard.
- **Post-conditions:** The analyst sees a live-updating process tree reflecting the current state of the host, with threat scores updated at least once per second.
- **Scenario (Normal):**
  1. The analyst launches the TUI (via command-line flag) or opens the web dashboard in a browser.
  2. The system retrieves the current process tree from in-memory state.
  3. The system renders the tree with each process showing PID, name, binary path, and threat score.
  4. Processes are color-coded: green (`< 0.3`), yellow (`0.3–0.7`), red (`>= 0.7`).
  5. The tree updates in real time as new events are processed and scores are recalculated.
- **Scenario (Alternate):** If the sensor has not yet captured events (for example, the daemon just started), the tree displays a loading indicator and populates as events arrive.

#### UC-02: Review Alert Timeline

- **Requirements:** The system must allow a Security Analyst to review a chronological list of all generated alerts, showing the most recent alerts first.
- **Pre-conditions:** The daemon is running and has generated at least one alert.
- **Post-conditions:** The analyst sees a scrollable list of alerts with timestamps, process names, threat scores, and summary descriptions.
- **Scenario (Normal):**
  1. The analyst navigates to the alert timeline panel in the TUI (keyboard shortcut) or clicks the Alerts tab in the web dashboard.
  2. The system displays alerts in reverse chronological order.
  3. Each alert entry shows: timestamp, process name, PID, threat score, and summary.
  4. The analyst scrolls through the list to review historical alerts.
- **Scenario (Alternate):** If no alerts have been generated, the timeline displays a message indicating no threats have been detected.

#### UC-03: Inspect Process Details

- **Requirements:** The system must allow a Security Analyst to select a process and view its detailed behavioral profile, including full event history, feature vector values, and ancestry chain.
- **Pre-conditions:** The process tree or alert timeline is displayed and contains at least one entry.
- **Post-conditions:** The analyst sees a detail view for the selected process with its complete behavioral context.
- **Scenario (Normal):**
  1. The analyst selects a process in the tree (keyboard in TUI, click in web dashboard) or clicks an alert entry.
  2. The system retrieves the process’s enriched event history, current feature vector, and ancestry chain from in-memory state.
  3. The detail view displays: full ancestry chain with PIDs and binary paths, current feature vector with labeled values, recent syscall event log, and threat score with top contributing features highlighted.
  4. The analyst reviews the information to determine whether the behavior is a true threat.
- **Scenario (Exceptional):** If the process has already exited, the system displays the last known state with an indication that the process is no longer running. Data is available as long as it remains in the in-memory window.

#### UC-04: Filter Alerts by Severity

- **Requirements:** The system must allow a Security Analyst to filter the alert timeline by severity level to focus on the most critical detections.
- **Pre-conditions:** The alert timeline is displayed with one or more alerts.
- **Post-conditions:** The alert timeline displays only alerts matching the selected severity filter(s).
- **Scenario (Normal):**
  1. The analyst selects a severity filter in the web dashboard dropdown or uses a keyboard shortcut in the TUI.
  2. The system filters displayed alerts to show only those with threat scores in the selected range: low (`0.7–0.8`), medium (`0.8–0.9`), high (`0.9–1.0`).
  3. The analyst can clear the filter to return to the full timeline.

#### UC-05: Adjust Alert Threshold

- **Requirements:** The system must allow a user to adjust the threat score threshold above which alerts are generated.
- **Pre-conditions:** The daemon is running.
- **Post-conditions:** The new threshold takes effect immediately for subsequent inferences. Previously generated alerts are unaffected.
- **Scenario (Normal):**
  1. The user modifies the threshold value in the configuration file or via the web dashboard settings panel.
  2. If modified via file, the user sends `SIGHUP` to the daemon to trigger a reload.
  3. The daemon validates the new threshold (must be between `0.0` and `1.0`) and applies it.
  4. Subsequent inference results are compared against the new threshold.
- **Scenario (Exceptional):** If the provided threshold is outside the valid range, the system rejects it, logs a warning, and retains the previous threshold.

#### UC-06: Start Daemon

- **Requirements:** The system must allow a System Administrator to start the Mini-EDR daemon, which loads configuration, attaches eBPF probes, loads the ML model, and begins monitoring.
- **Pre-conditions:** Linux kernel 5.8+ on `x86_64`. User has root or `CAP_BPF`/`CAP_PERFMON` privileges. Configuration file and ML model artifact exist on disk.
- **Post-conditions:** The daemon is running, probes are attached, the model is loaded, and the system is actively monitoring.
- **Scenario (Normal):**
  1. The administrator executes the daemon binary with appropriate privileges.
  2. The daemon reads and validates the configuration file.
  3. The daemon loads the ML model artifact into memory.
  4. The daemon compiles and loads eBPF probes into the kernel via Aya.
  5. The daemon begins consuming events from the ring buffer.
  6. The daemon starts the API endpoint, TUI (if enabled), and web server (if enabled).
  7. The daemon logs a startup confirmation message.
- **Scenario (Exceptional — Missing Privileges):** The daemon prints an error specifying required capabilities and exits with a non-zero code.
- **Scenario (Exceptional — Model Load Failure):** The daemon starts in pass-through mode (logging without scoring) and emits a warning.

#### UC-07: Stop Daemon

- **Requirements:** The system must allow graceful daemon shutdown, detaching all probes and flushing buffered alerts to disk.
- **Pre-conditions:** The daemon is running.
- **Post-conditions:** All eBPF probes are detached. All pending alerts are written to log. The daemon has exited cleanly.
- **Scenario (Normal):**
  1. The administrator sends `SIGTERM` or `SIGINT` to the daemon process.
  2. The daemon stops consuming new events.
  3. The daemon flushes pending alerts and telemetry to the log file.
  4. The daemon detaches all eBPF probes from the kernel.
  5. The daemon closes all network connections and exits with code `0`.

#### UC-08: Reload ML Model

- **Requirements:** The system must allow replacing the active ML model without restarting the daemon.
- **Pre-conditions:** The daemon is running. A new model artifact has been placed at the configured path.
- **Post-conditions:** The daemon uses the new model for all subsequent inference. No events were dropped during reload.
- **Scenario (Normal):**
  1. The administrator places the new model file at the configured path.
  2. The administrator sends `SIGHUP` to the daemon.
  3. The daemon loads the new model while continuing to use the old model for in-flight inferences.
  4. Once validated, the daemon atomically swaps in the new model.
  5. The daemon logs a confirmation message.
- **Scenario (Exceptional):** If the new model fails validation, the daemon retains the previous model, logs an error, and continues normally.

#### UC-09: Configure Monitored Syscalls

- **Requirements:** The system must allow specifying which syscalls are monitored via the configuration file.
- **Pre-conditions:** The configuration file exists and is writable.
- **Post-conditions:** The daemon monitors only the specified syscalls after restart or configuration reload.
- **Scenario (Normal):**
  1. The administrator edits the configuration file to add or remove syscalls.
  2. The administrator restarts the daemon or sends `SIGHUP`.
  3. The daemon attaches/detaches probes for the specified syscalls.
  4. Only events from configured syscalls are captured.

#### UC-10: View System Health Metrics

- **Requirements:** The system must allow viewing operational health metrics including events per second, ring buffer utilization, inference latency, and memory usage.
- **Pre-conditions:** The daemon is running. The TUI or web dashboard is open.
- **Post-conditions:** The user sees current health metrics updated in real time.
- **Scenario (Normal):**
  1. The user navigates to the health/status panel.
  2. The system displays: events per second, ring buffer fill percentage, average inference latency, daemon uptime, and memory usage.
  3. Metrics update at least once per second.

#### UC-11: Generate Syscall Event (System Actor)

- **Requirements:** The Linux kernel generates event data whenever a monitored syscall is invoked, which the eBPF probe captures and delivers to userspace.
- **Pre-conditions:** eBPF probes are attached to the relevant tracepoints. A process on the host invokes a monitored syscall.
- **Post-conditions:** The event data is placed in the BPF ring buffer for consumption by the userspace daemon.
- **Scenario (Normal):**
  1. A process invokes a monitored syscall (for example, a shell runs `execve` to launch a binary).
  2. The kernel triggers the attached eBPF tracepoint probe.
  3. The probe extracts relevant fields and writes a structured event to the ring buffer.
  4. The userspace daemon detects and reads the new data from the ring buffer.
- **Scenario (Exceptional — Ring Buffer Full):** The event is dropped. The daemon increments a dropped-event counter exposed in health metrics. Kernel execution is not blocked.
