/**
 * Mini-EDR dashboard process tree and drill-down renderer.
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

let currentProcesses = [];
let selectedPid = null;
let renderGeneration = 0;

function threatBand(score) {
  // FR-T02 / VAL-WEB-005 parity with the TUI: scores below 0.3 are green,
  // scores in [0.3, 0.7) are yellow, and scores >= 0.7 are red.
  if (score == null) {
    return "unknown";
  }
  if (score < 0.3) {
    return "low";
  }
  if (score < 0.7) {
    return "medium";
  }
  return "high";
}

function sanitizeProcessText(value) {
  return Array.from(String(value ?? ""), (character) =>
    /[\u0000-\u001f\u007f-\u009f]/u.test(character) ? "�" : character,
  ).join("");
}

function fetchJson(path) {
  return fetch(path, { headers: { Accept: "application/json" } }).then((response) => {
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

function selectedProcess() {
  return currentProcesses.find((process) => process.pid === selectedPid) ?? null;
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
      `Score: ${
        process.detail.threat_score == null ? "unscored" : process.detail.threat_score.toFixed(3)
      }`,
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
    const isSelected = row.dataset.pid === String(selectedPid);
    row.classList.toggle("is-selected", isSelected);
    row.setAttribute("aria-current", isSelected ? "true" : "false");
  }
}

function selectProcess(pid) {
  selectedPid = pid;
  updateSelectedRowStyles();
  renderSelectedProcessDetail();
}

function buildProcessRow(process) {
  const row = document.createElement("button");
  row.type = "button";
  row.className = "process-row";
  row.dataset.pid = String(process.pid);
  row.dataset.threatBand = threatBand(process.threat_score);
  row.dataset.depthTruncated = String(process.depth > MAX_VISIBLE_INDENT_LEVELS);
  row.style.paddingInlineStart = `${
    0.9 + Math.min(process.depth, MAX_VISIBLE_INDENT_LEVELS) * 1.15
  }rem`;
  row.addEventListener("click", () => selectProcess(process.pid));
  row.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      selectProcess(process.pid);
    }
  });

  const identity = document.createElement("span");
  identity.className = "process-row__identity";

  const depthMarker = document.createElement("span");
  depthMarker.className = "process-row__depth-marker";
  depthMarker.textContent = process.depth > MAX_VISIBLE_INDENT_LEVELS ? "…" : "";

  const copy = document.createElement("span");
  copy.className = "process-row__copy";

  const name = document.createElement("span");
  name.className = "process-row__name";
  name.textContent = process.process_name;

  const meta = document.createElement("span");
  meta.className = "process-row__meta";
  meta.textContent = `PID ${process.pid} · depth ${process.depth}`;

  copy.append(name, meta);
  identity.append(depthMarker, copy);

  const score = document.createElement("span");
  score.className = "process-row__score";
  score.textContent =
    process.threat_score == null ? "unscored" : Number(process.threat_score).toFixed(2);

  row.append(identity, score);
  return row;
}

function renderProcessTree(processes) {
  const treeRoot = document.getElementById("process-tree");
  if (!treeRoot) {
    return;
  }

  renderGeneration += 1;
  const generation = renderGeneration;
  treeRoot.replaceChildren();

  if (processes.length === 0) {
    const emptyState = document.createElement("p");
    emptyState.className = "process-tree__empty";
    emptyState.textContent = "Waiting for process data…";
    treeRoot.appendChild(emptyState);
    return;
  }

  let index = 0;

  // Rendering a 1,200+ node tree in one synchronous DOM batch can stall the
  // main thread. Chunking work behind requestAnimationFrame keeps scrolling and
  // row clicks responsive while still rendering the full tree without
  // truncating UTF-8 names.
  function appendChunk() {
    if (generation !== renderGeneration) {
      return;
    }

    const fragment = document.createDocumentFragment();
    for (
      let rendered = 0;
      rendered < RENDER_CHUNK_SIZE && index < processes.length;
      rendered += 1, index += 1
    ) {
      fragment.appendChild(buildProcessRow(processes[index]));
    }

    treeRoot.appendChild(fragment);
    updateSelectedRowStyles();

    if (index < processes.length) {
      requestAnimationFrame(appendChunk);
    }
  }

  requestAnimationFrame(appendChunk);
}

async function refreshProcessTree() {
  try {
    const snapshot = await fetchJson("/processes");
    currentProcesses = Array.isArray(snapshot.processes)
      ? snapshot.processes.map(normalizeProcess)
      : [];
    if (
      selectedPid != null &&
      !currentProcesses.some((process) => process.pid === selectedPid)
    ) {
      selectedPid = null;
    }
    renderProcessTree(currentProcesses);
    renderSelectedProcessDetail();
  } catch (error) {
    console.error("mini-edr web dashboard failed to refresh /processes", error);
  }
}

async function refreshHealth() {
  try {
    const health = await fetchJson("/health");
    const state = health.state ?? "Unknown";

    document.getElementById("daemon-status-badge").textContent = `Daemon: ${state}`;
    document.getElementById("daemon-status-badge").dataset.state = String(state).toLowerCase();
  } catch (error) {
    document.getElementById("daemon-status-badge").textContent = "Daemon: Offline";
    console.error("mini-edr web scaffold failed to refresh /health", error);
  }
}

async function bootstrap() {
  renderSelectedProcessDetail();
  await Promise.all([refreshProcessTree(), refreshHealth()]);
  window.setInterval(() => {
    void refreshProcessTree();
  }, PROCESS_REFRESH_MS);
  window.setInterval(() => {
    void refreshHealth();
  }, HEALTH_REFRESH_MS);
}

void bootstrap();
