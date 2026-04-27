const SAMPLE_PROCESS_TREE = [
  { pid: 1, processName: "systemd", threatScore: 0.1, depth: 0 },
  { pid: 2457, processName: "mini-edr-daemon", threatScore: 0.5, depth: 1 },
  { pid: 8120, processName: "suspicious-shell", threatScore: 0.9, depth: 2 },
];

function threatBand(score) {
  // FR-T02 / VAL-WEB-005 parity with the TUI: scores below 0.3 are green,
  // scores in [0.3, 0.7) are yellow, and scores >= 0.7 are red.
  if (score < 0.3) {
    return "low";
  }
  if (score < 0.7) {
    return "medium";
  }
  return "high";
}

function renderProcessTree(processes) {
  const treeRoot = document.getElementById("process-tree");
  if (!treeRoot) {
    return;
  }

  const fragment = document.createDocumentFragment();

  for (const process of processes) {
    const row = document.createElement("article");
    row.className = "process-row";
    row.dataset.pid = String(process.pid);
    row.dataset.threatBand = threatBand(process.threatScore);
    row.style.paddingInlineStart = `${0.9 + process.depth * 1.35}rem`;

    const identity = document.createElement("div");
    identity.className = "process-row__identity";

    const name = document.createElement("span");
    name.className = "process-row__name";
    name.textContent = process.processName;

    const pid = document.createElement("span");
    pid.className = "process-row__pid";
    pid.textContent = `PID ${process.pid}`;

    identity.append(name, pid);

    const score = document.createElement("span");
    score.className = "process-row__score";
    score.textContent = process.threatScore.toFixed(2);

    row.append(identity, score);
    fragment.appendChild(row);
  }

  treeRoot.replaceChildren(fragment);
}

async function refreshHealth() {
  try {
    const response = await fetch("/health", { headers: { Accept: "application/json" } });
    if (!response.ok) {
      throw new Error(`health request failed with status ${response.status}`);
    }

    const health = await response.json();
    const state = health.state ?? "Unknown";

    document.getElementById("daemon-status-badge").textContent = `Daemon: ${state}`;
    document.getElementById("health-state").textContent = state;
    document.getElementById("health-model-hash").textContent =
      health.model_hash ?? "unknown";
    document.getElementById("health-web-port").textContent = String(
      health.web_port ?? "unknown",
    );
  } catch (error) {
    document.getElementById("daemon-status-badge").textContent = "Daemon: Offline";
    document.getElementById("health-state").textContent = "Offline";
    document.getElementById("health-model-hash").textContent = "unreachable";
    document.getElementById("health-web-port").textContent = "unreachable";
    console.error("mini-edr web scaffold failed to refresh /health", error);
  }
}

renderProcessTree(SAMPLE_PROCESS_TREE);
void refreshHealth();
