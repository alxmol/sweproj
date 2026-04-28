# Mini-EDR Demo Presentation Script

## 0:00-0:30 — Setup the story

- "This demo uses the real Mini-EDR daemon, the real ONNX model, and live eBPF probes."
- "The only demo-specific shortcuts live under `demo/`; nothing here changes the production crates."

## 0:30-1:30 — Phase 1: Bring-up

- Run `bash demo/run_demo.sh`.
- Narrate the file-capability line:
  - "We grant the binary the minimum caps it needs for BPF and tracefs access."
  - "That lets us avoid running the whole daemon as root."
- Call out the printed `/api/health` JSON:
  - `state = Running`
  - `model_hash`
  - `active_probes`
- Call out the printed `bpftool` evidence:
  - "These are the live tracepoint programs attached for this daemon PID."

## 1:30-2:45 — Phase 2: Live observation

- "Now we let the live host activity speak for itself."
- Point to the `/api/processes` row:
  - PID
  - binary path
  - recent syscall detail
- Then point to the `/api/events` sample:
  - "This is the raw live event feed the daemon is exposing right now."
  - "The exact filenames and PIDs vary by host, but the data is live and not mocked."

## 2:45-4:45 — Phase 3: Live alert correlation

- "Next we wait for the daemon's next real alert on this host."
- Point to the alert excerpt from `alerts.jsonl`:
  - matching `pid`
  - `threat_score`
  - `model_hash`
  - `ancestry_chain`
- Then point to the `/api/processes` row for the same PID:
  - "This is the live process-tree row associated with that alert PID."
- Then point to `/api/dashboard/alerts`:
  - "The same alert is visible in the dashboard feed."

## 4:45-6:15 — Phase 4: Reload and rollback hygiene

- "The demo starts with a deliberately permissive threshold so the safe workload always produces a visible alert."
- Point to the successful reload:
  - "Here the threshold moves from `0.0` to `0.7` without restarting the daemon."
- Then point to the rejected reload:
  - "This config references a missing model file."
  - "The daemon stays `Running`, keeps the previous `model_hash`, and does not apply the bad config."
- Call out the rollback log snippet.

## 6:15-7:30 — Phase 5: Light performance snapshot

- "This is not the full SRS performance gate; it's an illustrative 10-second sample."
- Point to:
  - generated connect attempts per second
  - daemon-received event rate
  - CPU share
  - RSS peak
- "The key point is that the numbers are observed live, not hardcoded."

## 7:30-8:15 — Phase 6: Clean shutdown

- "We finish with a normal `SIGTERM`."
- Point to the final shutdown lines:
  - no leftover daemon
  - no leftover probe IDs from this run
- "That closes the loop from startup to shutdown."

## 8:15-9:00 — Wrap-up

- "What you saw was a real daemon with real probes, real health surfaces, real alert persistence, live operator APIs, reload semantics, and a short performance sample."
- "The only demo-specific compromises are documented in `demo/README.md` under 'Hardcoded for demo'."
