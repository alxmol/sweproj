/**
 * Mini-EDR dashboard process tree, alert timeline, and live-stream client.
 *
 * The dashboard intentionally renders every user-controlled string through
 * `textContent` instead of `innerHTML`. That preserves UTF-8 glyphs such as
 * `мойбин-🔥` while ensuring `<script>` payloads stay inert text nodes rather
 * than executable DOM.
 */

const PROCESS_REFRESH_MS = 1_000;
const HEALTH_REFRESH_MS = 1_000;
const MAX_VISIBLE_INDENT_LEVELS = 12;
const RENDER_CHUNK_SIZE = 200;
const RENDER_FRAME_BUDGET_MS = 12;
const INITIAL_RECONNECT_MS = 250;
const MAX_RECONNECT_MS = 1_000;
const PROCESS_ROW_REFS = Symbol("processRowRefs");

const state = {
  processes: [],
  selectedPid: null,
  processTree: {
    emptyStateEl: null,
    lastRenderStats: null,
    rowsByKey: new Map(),
  },
  renderGeneration: 0,
  alerts: [],
  csrfToken: "",
  health: {
    activeTab: "overview",
    lastHealthSnapshot: null,
    lastTelemetrySnapshot: null,
  },
  filters: {
    severity: "all",
    timeRange: "all",
  },
  transport: {
    mode: "offline",
    connected: false,
    reconnectAttempts: 0,
    consecutiveFailures: 0,
    openCount: 0,
    closeCount: 0,
    messagesReceived: 0,
    lastMessageAlertId: null,
    reconnectDelayMs: INITIAL_RECONNECT_MS,
    fallbackMode: "websocket",
  },
  streamHandle: null,
  reconnectTimer: null,
};

function threatBand(score) {
  // FR-T02 / VAL-WEB-005 parity with the TUI: scores below 0.3 are green,
  // scores in [0.3, 0.7) are yellow, and scores >= 0.7 are red.
  if (!hasFiniteThreatScore(score)) {
    return "unscored";
  }
  if (score < 0.3) {
    return "low";
  }
  if (score < 0.7) {
    return "medium";
  }
  return "high";
}

function hasFiniteThreatScore(score) {
  // Scrutiny parity fix: a missing score means the process has not been scored
  // yet, not that it is red/high severity. Keep the branch explicit so both the
  // process tree and the drill-down can render a neutral state without calling
  // numeric formatters on null / undefined / NaN values.
  return typeof score === "number" && Number.isFinite(score);
}

function formatThreatScore(score, digits, fallback = "—") {
  return hasFiniteThreatScore(score) ? score.toFixed(digits) : fallback;
}

function processStableKey(process) {
  // VAL-WEB-017 requires stable DOM keys so the 1 Hz refresh path updates rows
  // in place instead of replacing the full tree. The current daemon snapshot
  // exposes PID but not a distinct start_time, so PID is the strongest stable
  // identity available today. If the snapshot later adds start_time, this
  // helper is the single place to extend the key without rewriting the diff.
  return String(process.pid);
}

function alertSeverity(score) {
  // UC-04 / VAL-WEB-007..009 use the documented alert-only partitions:
  // low  = [0.7, 0.8), medium = [0.8, 0.9), high = [0.9, 1.0].
  if (score >= 0.9) {
    return "high";
  }
  if (score >= 0.8) {
    return "medium";
  }
  return "low";
}

function sanitizeProcessText(value) {
  return Array.from(String(value ?? ""), (character) =>
    /[\u0000-\u001f\u007f-\u009f]/u.test(character) ? "�" : character,
  ).join("");
}

function formatPercentage(value) {
  return `${Number(value).toFixed(1)}%`;
}

function formatDuration(totalSeconds) {
  const seconds = Math.max(0, Math.trunc(Number(totalSeconds) || 0));
  const hours = String(Math.floor(seconds / 3_600)).padStart(2, "0");
  const minutes = String(Math.floor((seconds % 3_600) / 60)).padStart(2, "0");
  const remainder = String(seconds % 60).padStart(2, "0");
  return `${hours}:${minutes}:${remainder}`;
}

function formatBytes(bytes) {
  const rawBytes = Math.max(0, Number(bytes) || 0);
  if (rawBytes < 1_024) {
    return `${rawBytes.toFixed(0)} B`;
  }

  const units = ["KiB", "MiB", "GiB", "TiB"];
  let value = rawBytes / 1_024;
  let unitIndex = 0;
  while (value >= 1_024 && unitIndex < units.length - 1) {
    value /= 1_024;
    unitIndex += 1;
  }
  return `${value.toFixed(1)} ${units[unitIndex]}`;
}

function parseAlertTimestampMs(timestamp) {
  const parsed = Date.parse(String(timestamp ?? ""));
  return Number.isFinite(parsed) ? parsed : 0;
}

function fetchJson(path, init = {}) {
  return fetch(path, {
    ...init,
    headers: {
      Accept: "application/json",
      ...(init.headers ?? {}),
    },
  }).then((response) => {
    if (!response.ok) {
      throw new Error(`${path} failed with status ${response.status}`);
    }
    return response.json();
  });
}

function normalizeProcess(process) {
  return {
    ...process,
    process_name: sanitizeProcessText(process.process_name),
    binary_path: sanitizeProcessText(process.binary_path),
    detail: {
      ...process.detail,
      ancestry_chain: Array.isArray(process.detail?.ancestry_chain)
        ? process.detail.ancestry_chain.map((entry) => ({
            ...entry,
            process_name: sanitizeProcessText(entry.process_name),
            binary_path: sanitizeProcessText(entry.binary_path),
          }))
        : [],
      feature_vector: Array.isArray(process.detail?.feature_vector)
        ? process.detail.feature_vector
        : [],
      recent_syscalls: Array.isArray(process.detail?.recent_syscalls)
        ? process.detail.recent_syscalls.map((entry) => sanitizeProcessText(entry))
        : [],
      top_features: Array.isArray(process.detail?.top_features)
        ? process.detail.top_features
        : [],
      threat_score: process.detail?.threat_score ?? process.threat_score ?? null,
    },
  };
}

function normalizeAlert(alert) {
  return {
    ...alert,
    process_name: sanitizeProcessText(alert.process_name),
    binary_path: sanitizeProcessText(alert.binary_path),
    summary: sanitizeProcessText(alert.summary),
    severity: alertSeverity(Number(alert.threat_score ?? 0)),
    timestampMs: parseAlertTimestampMs(alert.timestamp),
  };
}

function selectedProcess() {
  return state.processes.find((process) => process.pid === state.selectedPid) ?? null;
}

function replaceDetailList(targetId, entries, renderEntry) {
  const target = document.getElementById(targetId);
  if (!target) {
    return;
  }

  const fragment = document.createDocumentFragment();
  for (const entry of entries) {
    const listItem = document.createElement("li");
    listItem.className = "detail-list__item";
    listItem.textContent = renderEntry(entry);
    fragment.appendChild(listItem);
  }
  target.replaceChildren(fragment);
}

function renderSelectedProcessDetail() {
  const detailPanel = document.getElementById("process-detail");
  const detailEmpty = document.getElementById("process-detail-empty");
  const detailSummary = document.getElementById("process-detail-summary");
  const process = selectedProcess();

  if (!detailPanel || !detailEmpty || !detailSummary) {
    return;
  }

  if (!process) {
    detailPanel.hidden = true;
    detailEmpty.hidden = false;
    detailSummary.textContent = "Click a process row to populate the drill-down side panel.";
    return;
  }

  detailPanel.hidden = false;
  detailEmpty.hidden = true;
  detailSummary.textContent = `${process.process_name} · PID ${process.pid} · ${process.binary_path}`;
  replaceDetailList(
    "detail-ancestry",
    process.detail.ancestry_chain,
    (entry) => `${entry.process_name} (pid ${entry.pid}) [${entry.binary_path}]`,
  );
  replaceDetailList(
    "detail-feature-vector",
    process.detail.feature_vector,
    (entry) => `${entry.label}: ${entry.value}`,
  );
  replaceDetailList("detail-syscalls", process.detail.recent_syscalls, (entry) => entry);
  replaceDetailList(
    "detail-threat-score",
    [
      `Process: ${process.process_name}`,
      `Score: ${formatThreatScore(process.detail.threat_score, 3)}`,
      process.exited ? "process has exited" : `Band: ${threatBand(process.threat_score)}`,
    ],
    (entry) => entry,
  );
  replaceDetailList(
    "detail-top-features",
    process.detail.top_features,
    (entry) => `${entry.feature_name}: ${Number(entry.contribution_score).toFixed(2)}`,
  );
}

function updateSelectedRowStyles() {
  for (const row of document.querySelectorAll(".process-row")) {
    const isSelected = row.dataset.pid === String(state.selectedPid);
    row.classList.toggle("is-selected", isSelected);
    row.setAttribute("aria-current", isSelected ? "true" : "false");
  }
}

function selectProcess(pid) {
  state.selectedPid = pid;
  updateSelectedRowStyles();
  renderSelectedProcessDetail();
}

function buildProcessRow() {
  const row = document.createElement("button");
  row.type = "button";
  row.className = "process-row";
  row.addEventListener("click", () => selectProcess(Number(row.dataset.pid)));
  row.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      selectProcess(Number(row.dataset.pid));
    }
  });

  const identity = document.createElement("span");
  identity.className = "process-row__identity";

  const depthMarker = document.createElement("span");
  depthMarker.className = "process-row__depth-marker";

  const copy = document.createElement("span");
  copy.className = "process-row__copy";

  const name = document.createElement("span");
  name.className = "process-row__name";

  const meta = document.createElement("span");
  meta.className = "process-row__meta";

  copy.append(name, meta);
  identity.append(depthMarker, copy);

  const score = document.createElement("span");
  score.className = "process-row__score";

  row.append(identity, score);
  row[PROCESS_ROW_REFS] = {
    depthMarker,
    meta,
    name,
    score,
  };
  return row;
}

function updateProcessRow(row, process) {
  const refs = row[PROCESS_ROW_REFS];
  row.dataset.pid = String(process.pid);
  row.dataset.processKey = processStableKey(process);
  row.dataset.threatBand = threatBand(process.threat_score);
  row.dataset.depthTruncated = String(process.depth > MAX_VISIBLE_INDENT_LEVELS);
  row.dataset.exited = String(Boolean(process.exited));
  row.style.paddingInlineStart = `${
    0.9 + Math.min(process.depth, MAX_VISIBLE_INDENT_LEVELS) * 1.15
  }rem`;
  refs.depthMarker.textContent = process.depth > MAX_VISIBLE_INDENT_LEVELS ? "…" : "";
  refs.name.textContent = process.process_name;
  refs.meta.textContent = `PID ${process.pid} · depth ${process.depth}`;
  refs.score.textContent = formatThreatScore(process.threat_score, 2, "unscored");
}

function processTreeEmptyState() {
  if (!state.processTree.emptyStateEl) {
    const emptyState = document.createElement("p");
    emptyState.className = "process-tree__empty";
    state.processTree.emptyStateEl = emptyState;
  }
  return state.processTree.emptyStateEl;
}

function renderProcessTree(processes) {
  const treeRoot = document.getElementById("process-tree");
  if (!treeRoot) {
    return;
  }

  state.renderGeneration += 1;
  const generation = state.renderGeneration;

  if (processes.length === 0) {
    state.processTree.rowsByKey.clear();
    state.processTree.lastRenderStats = {
      chunkDurationsMs: [],
      completed: true,
      generation,
      insertedRows: 0,
      preservedScrollTop: 0,
      processedRows: 0,
      reusedRows: 0,
    };
    const emptyState = processTreeEmptyState();
    emptyState.textContent = "Waiting for process data…";
    treeRoot.replaceChildren(emptyState);
    attachDebugState();
    return;
  }

  if (state.processTree.emptyStateEl?.isConnected) {
    state.processTree.emptyStateEl.remove();
  }

  const preservedScrollTop = treeRoot.scrollTop;
  const nextKeys = new Set(processes.map((process) => processStableKey(process)));
  for (const [key, row] of state.processTree.rowsByKey.entries()) {
    if (!nextKeys.has(key)) {
      row.remove();
      state.processTree.rowsByKey.delete(key);
    }
  }

  const renderStats = {
    chunkDurationsMs: [],
    completed: false,
    finalScrollTop: preservedScrollTop,
    generation,
    insertedRows: 0,
    preservedScrollTop,
    processedRows: 0,
    reusedRows: 0,
  };
  state.processTree.lastRenderStats = renderStats;
  attachDebugState();

  let index = 0;

  // Rendering a 1,500+ node tree in one synchronous DOM batch can stall the
  // main thread and reset the operator's place in the list if the DOM is
  // rebuilt wholesale. This chunked diff keeps existing row elements keyed by
  // PID, reorders them in place, and restores scrollTop after every chunk so
  // scroll, selection, and any future expand/collapse classes survive polling.
  function reconcileChunk() {
    if (generation !== state.renderGeneration) {
      return;
    }

    const chunkStartedAt = performance.now();
    let renderedThisChunk = 0;

    while (index < processes.length) {
      const process = processes[index];
      const key = processStableKey(process);
      let row = state.processTree.rowsByKey.get(key);
      if (row) {
        renderStats.reusedRows += 1;
      } else {
        row = buildProcessRow();
        state.processTree.rowsByKey.set(key, row);
        renderStats.insertedRows += 1;
      }

      updateProcessRow(row, process);

      const rowAtTargetIndex = treeRoot.children[index];
      if (rowAtTargetIndex !== row) {
        treeRoot.insertBefore(row, rowAtTargetIndex ?? null);
      }

      index += 1;
      renderedThisChunk += 1;
      renderStats.processedRows += 1;

      if (renderedThisChunk >= RENDER_CHUNK_SIZE) {
        break;
      }
      if (performance.now() - chunkStartedAt >= RENDER_FRAME_BUDGET_MS) {
        break;
      }
    }

    renderStats.chunkDurationsMs.push(performance.now() - chunkStartedAt);
    renderStats.finalScrollTop = preservedScrollTop;
    treeRoot.scrollTop = preservedScrollTop;
    updateSelectedRowStyles();
    attachDebugState();

    if (index < processes.length) {
      requestAnimationFrame(reconcileChunk);
    } else {
      renderStats.completed = true;
      renderStats.finalScrollTop = treeRoot.scrollTop;
      attachDebugState();
    }
  }

  requestAnimationFrame(reconcileChunk);
}

function timeRangeCutoffMs(timeRange) {
  switch (timeRange) {
    case "last_30m":
      return Date.now() - 30 * 60 * 1_000;
    case "last_1h":
      return Date.now() - 60 * 60 * 1_000;
    case "last_6h":
      return Date.now() - 6 * 60 * 60 * 1_000;
    case "last_24h":
      return Date.now() - 24 * 60 * 60 * 1_000;
    default:
      return 0;
  }
}

function filteredAlerts() {
  const cutoffMs = timeRangeCutoffMs(state.filters.timeRange);
  return state.alerts
    .filter((alert) => {
      if (state.filters.severity === "medium+" && alert.severity === "low") {
        return false;
      }
      if (state.filters.severity === "high" && alert.severity !== "high") {
        return false;
      }
      if (cutoffMs > 0 && alert.timestampMs < cutoffMs) {
        return false;
      }
      return true;
    })
    .sort((left, right) => right.timestampMs - left.timestampMs);
}

function renderAlertTimeline() {
  const timeline = document.getElementById("alert-timeline");
  const emptyState = document.getElementById("alert-timeline-empty");
  if (!timeline || !emptyState) {
    return;
  }

  const visibleAlerts = filteredAlerts();
  timeline.replaceChildren();
  emptyState.hidden = visibleAlerts.length !== 0;
  timeline.hidden = visibleAlerts.length === 0;
  if (visibleAlerts.length === 0) {
    return;
  }

  const fragment = document.createDocumentFragment();
  for (const alert of visibleAlerts) {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "alert-row";
    row.dataset.alertId = String(alert.alert_id);
    row.dataset.severity = alert.severity;
    row.dataset.timestamp = String(alert.timestampMs);
    row.addEventListener("click", () => {
      if (state.processes.some((process) => process.pid === alert.pid)) {
        selectProcess(alert.pid);
      }
    });

    const summary = document.createElement("span");
    summary.className = "alert-row__summary";
    summary.textContent = `${alert.process_name} · ${alert.summary}`;

    const meta = document.createElement("span");
    meta.className = "alert-row__meta";
    meta.textContent = `${alert.severity.toUpperCase()} · ${new Date(alert.timestampMs).toLocaleString()} · score ${formatThreatScore(alert.threat_score, 3)}`;

    row.append(summary, meta);
    fragment.appendChild(row);
  }

  timeline.appendChild(fragment);
}

function setMetric(metricName, rawValue, displayText) {
  const metric = document.querySelector(`[data-metric="${metricName}"]`);
  if (!metric) {
    return;
  }

  metric.dataset.rawValue = String(rawValue);
  metric.textContent = displayText;
}

function mergeAlert(alert) {
  const normalized = normalizeAlert(alert);
  const existingIndex = state.alerts.findIndex(
    (existing) => Number(existing.alert_id) === Number(normalized.alert_id),
  );
  if (existingIndex >= 0) {
    state.alerts.splice(existingIndex, 1, normalized);
  } else {
    state.alerts.push(normalized);
  }
  state.alerts.sort((left, right) => left.timestampMs - right.timestampMs);
  if (state.alerts.length > 4_096) {
    state.alerts.splice(0, state.alerts.length - 4_096);
  }
  renderAlertTimeline();
}

function attachDebugState() {
  // Browser validators need a stable introspection surface for transport
  // events and filtered alert rows without scraping implementation details.
  window.__miniEdrDebug = {
    get alerts() {
      return state.alerts.map((alert) => ({ ...alert }));
    },
    get filteredAlerts() {
      return filteredAlerts().map((alert) => ({ ...alert }));
    },
    get transport() {
      return { ...state.transport };
    },
    get processTree() {
      return {
        lastRender: state.processTree.lastRenderStats
          ? {
              ...state.processTree.lastRenderStats,
              chunkDurationsMs: [...state.processTree.lastRenderStats.chunkDurationsMs],
            }
          : null,
        renderedRowCount: state.processTree.rowsByKey.size,
      };
    },
    get csrfToken() {
      return state.csrfToken;
    },
    get health() {
      return {
        activeTab: state.health.activeTab,
        lastHealthSnapshot: state.health.lastHealthSnapshot
          ? { ...state.health.lastHealthSnapshot }
          : null,
        lastTelemetrySnapshot: state.health.lastTelemetrySnapshot
          ? { ...state.health.lastTelemetrySnapshot }
          : null,
      };
    },
  };
}

function renderActiveTab() {
  const overviewPanel = document.getElementById("overview-tab-panel");
  const healthPanel = document.getElementById("health-tab-panel");

  for (const button of document.querySelectorAll("[data-tab-target]")) {
    const isActive = button.dataset.tabTarget === state.health.activeTab;
    button.classList.toggle("is-active", isActive);
    button.setAttribute("aria-selected", isActive ? "true" : "false");
  }

  if (overviewPanel) {
    overviewPanel.hidden = state.health.activeTab !== "overview";
  }
  if (healthPanel) {
    healthPanel.hidden = state.health.activeTab !== "health";
  }
}

async function refreshProcessTree() {
  try {
    const snapshot = await fetchJson("/processes");
    state.processes = Array.isArray(snapshot.processes)
      ? snapshot.processes.map(normalizeProcess)
      : [];
    if (
      state.selectedPid != null &&
      !state.processes.some((process) => process.pid === state.selectedPid)
    ) {
      state.selectedPid = null;
    }
    renderProcessTree(state.processes);
    renderSelectedProcessDetail();
  } catch (error) {
    console.error("mini-edr web dashboard failed to refresh /processes", error);
  }
}

async function refreshHealth() {
  const badge = document.getElementById("daemon-status-badge");
  const degradedBadge = document.getElementById("degraded-badge");

  try {
    const health = await fetchJson("/health");
    state.health.lastHealthSnapshot = health;
    const daemonState = health.state ?? "Unknown";
    badge.textContent = `Daemon: ${daemonState}`;
    badge.dataset.state = String(daemonState).toLowerCase();
    const degraded = String(daemonState).toLowerCase() === "degraded";
    degradedBadge.hidden = !degraded;
    degradedBadge.textContent = degraded
      ? "Warning: degraded mode — alerts may be unscored"
      : "Warning: degraded mode";
    attachDebugState();
  } catch (error) {
    state.health.lastHealthSnapshot = null;
    badge.textContent = "Daemon: Offline";
    state.transport.connected = false;
    degradedBadge.hidden = true;
    attachDebugState();
    console.info("mini-edr dashboard health refresh observed a temporary outage", error);
  }
}

async function refreshTelemetry() {
  try {
    // FR-W06 / VAL-WEB-012 require the health overview to update at least once
    // per second. Polling the daemon's same-origin telemetry summary keeps the
    // browser-side update cadence explicit and easy to audit in tests.
    const telemetry = await fetchJson("/telemetry/summary");
    state.health.lastTelemetrySnapshot = telemetry;
    setMetric(
      "events-per-second",
      telemetry.events_per_second ?? 0,
      `${Number(telemetry.events_per_second ?? 0).toFixed(1)} eps`,
    );
    setMetric(
      "ring-buffer-utilization",
      telemetry.ring_buffer_util ?? 0,
      formatPercentage(Number(telemetry.ring_buffer_util ?? 0) * 100),
    );
    setMetric(
      "inference-latency",
      telemetry.inference_latency_p99_ms ?? 0,
      `${Number(telemetry.inference_latency_p99_ms ?? 0).toFixed(2)} ms`,
    );
    setMetric(
      "uptime",
      telemetry.uptime_seconds ?? 0,
      formatDuration(telemetry.uptime_seconds ?? 0),
    );
    setMetric("memory", telemetry.rss_bytes ?? 0, formatBytes(telemetry.rss_bytes ?? 0));
    attachDebugState();
  } catch (error) {
    console.info("mini-edr dashboard telemetry refresh failed during polling", error);
  }
}

async function refreshAlertSnapshot() {
  try {
    const snapshot = await fetchJson("/api/dashboard/alerts");
    state.alerts = Array.isArray(snapshot.alerts) ? snapshot.alerts.map(normalizeAlert) : [];
    state.alerts.sort((left, right) => left.timestampMs - right.timestampMs);
    renderAlertTimeline();
  } catch (error) {
    console.info("mini-edr dashboard alert snapshot refresh failed during reconnect", error);
  }
}

async function refreshCsrfToken() {
  try {
    const payload = await fetchJson("/api/settings/csrf");
    state.csrfToken = String(payload.token ?? "");
    attachDebugState();
  } catch (error) {
    console.info("mini-edr dashboard could not refresh the CSRF token yet", error);
  }
}

function closeLiveStream() {
  if (state.streamHandle) {
    state.streamHandle.onclose = null;
    state.streamHandle.onerror = null;
    state.streamHandle.close();
    state.streamHandle = null;
  }
}

function scheduleReconnect() {
  window.clearTimeout(state.reconnectTimer);
  state.transport.connected = false;
  state.transport.reconnectAttempts += 1;
  const delay = state.transport.reconnectDelayMs;
  state.reconnectTimer = window.setTimeout(() => {
    void connectLiveAlerts();
  }, delay);
  state.transport.reconnectDelayMs = Math.min(MAX_RECONNECT_MS, delay * 2);
  attachDebugState();
}

function handleIncomingAlertPayload(payload) {
  state.transport.messagesReceived += 1;
  state.transport.lastMessageAlertId = payload.alert_id ?? null;
  mergeAlert(payload);
  attachDebugState();
}

function connectSseFallback() {
  closeLiveStream();
  const eventSource = new EventSource("/sse");
  state.streamHandle = eventSource;
  state.transport.mode = "sse";
  state.transport.fallbackMode = "sse";

  eventSource.onopen = async () => {
    state.transport.connected = true;
    state.transport.openCount += 1;
    state.transport.consecutiveFailures = 0;
    state.transport.reconnectDelayMs = INITIAL_RECONNECT_MS;
    attachDebugState();
    await refreshAlertSnapshot();
  };

  eventSource.onmessage = (event) => {
    handleIncomingAlertPayload(JSON.parse(event.data));
  };

  eventSource.onerror = () => {
    state.transport.closeCount += 1;
    eventSource.close();
    scheduleReconnect();
  };
}

async function connectLiveAlerts() {
  window.clearTimeout(state.reconnectTimer);
  closeLiveStream();

  if (!("WebSocket" in window) || state.transport.fallbackMode === "sse") {
    connectSseFallback();
    return;
  }

  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  const socket = new WebSocket(`${protocol}://${window.location.host}/ws`);
  state.streamHandle = socket;
  state.transport.mode = "websocket";

  socket.onopen = async () => {
    state.transport.connected = true;
    state.transport.openCount += 1;
    state.transport.consecutiveFailures = 0;
    state.transport.reconnectDelayMs = INITIAL_RECONNECT_MS;
    attachDebugState();
    await refreshAlertSnapshot();
  };

  socket.onmessage = (event) => {
    handleIncomingAlertPayload(JSON.parse(event.data));
  };

  socket.onerror = () => {
    socket.close();
  };

  socket.onclose = () => {
    state.transport.connected = false;
    state.transport.closeCount += 1;
    state.transport.consecutiveFailures += 1;
    if (state.transport.consecutiveFailures >= 3 && state.transport.openCount === 0) {
      state.transport.fallbackMode = "sse";
    }
    attachDebugState();
    scheduleReconnect();
  };
}

function bindFilterControls() {
  const severityFilter = document.getElementById("severity-filter");
  const timeFilter = document.getElementById("time-filter");

  severityFilter.addEventListener("change", () => {
    state.filters.severity = severityFilter.value;
    renderAlertTimeline();
    attachDebugState();
  });
  timeFilter.addEventListener("change", () => {
    state.filters.timeRange = timeFilter.value;
    renderAlertTimeline();
    attachDebugState();
  });
}

function bindTabControls() {
  for (const button of document.querySelectorAll("[data-tab-target]")) {
    button.addEventListener("click", () => {
      state.health.activeTab = button.dataset.tabTarget;
      renderActiveTab();
      attachDebugState();
    });
  }
}

async function bootstrap() {
  attachDebugState();
  bindTabControls();
  bindFilterControls();
  renderActiveTab();
  renderSelectedProcessDetail();
  renderAlertTimeline();
  await Promise.all([
    refreshProcessTree(),
    refreshHealth(),
    refreshTelemetry(),
    refreshAlertSnapshot(),
    refreshCsrfToken(),
  ]);
  await connectLiveAlerts();
  window.setInterval(() => {
    void refreshProcessTree();
  }, PROCESS_REFRESH_MS);
  window.setInterval(() => {
    void refreshHealth();
  }, HEALTH_REFRESH_MS);
  window.setInterval(() => {
    void refreshTelemetry();
  }, HEALTH_REFRESH_MS);
}

void bootstrap();
