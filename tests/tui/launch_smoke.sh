#!/usr/bin/env bash
set -euo pipefail

ROOT="/home/alexm/mini-edr"
BINARY="${ROOT}/target/debug/examples/launch_smoke"
TRIALS=20
DEGRADED_BANNER="WARNING: degraded mode — alerts may be unscored"

cleanup_session() {
  local session="$1"
  tuistory close -s "${session}" >/dev/null 2>&1 || true
}

launch_session() {
  local session="$1"
  local scenario="$2"
  local cols="${3:-80}"

  tuistory launch "${BINARY}" \
    -s "${session}" \
    --cwd "${ROOT}" \
    --cols "${cols}" \
    --rows 24 \
    --env "MINI_EDR_TUI_SCENARIO=${scenario}" \
    --env "MINI_EDR_TUI_AUTOQUIT_MS=3000" \
    >/dev/null
}

capture_snapshot() {
  local session="$1"
  tuistory snapshot -s "${session}" --trim
}

assert_contains() {
  local haystack="$1"
  local needle="$2"
  if ! grep -Fq "${needle}" <<<"${haystack}"; then
    printf 'expected snapshot to contain %q\n' "${needle}" >&2
    printf '%s\n' "${haystack}" >&2
    exit 1
  fi
}

assert_not_contains() {
  local haystack="$1"
  local needle="$2"
  if grep -Fq "${needle}" <<<"${haystack}"; then
    printf 'expected snapshot to NOT contain %q\n' "${needle}" >&2
    printf '%s\n' "${haystack}" >&2
    exit 1
  fi
}

wait_for_process_tree() {
  local session="$1"
  local start_ms end_ms snapshot elapsed_ms
  start_ms="$(date +%s%3N)"

  while true; do
    snapshot="$(capture_snapshot "${session}")"
    if grep -Fq "mini-edr-daemon" <<<"${snapshot}"; then
      end_ms="$(date +%s%3N)"
      elapsed_ms="$((end_ms - start_ms))"
      printf '%s\n' "${elapsed_ms}"
      return 0
    fi

    end_ms="$(date +%s%3N)"
    if (( end_ms - start_ms > 1000 )); then
      printf 'process row did not appear within 1000 ms\n%s\n' "${snapshot}" >&2
      exit 1
    fi

    sleep 0.05
  done
}

cd "${ROOT}"
cargo build --quiet -p mini-edr-tui --example launch_smoke

sum_elapsed=0
max_elapsed=0

for trial in $(seq 1 "${TRIALS}"); do
  session="mini-edr-tui-smoke-${trial}-$$"
  trap 'cleanup_session "${session}"' EXIT
  launch_session "${session}" "normal"

  sleep 0.15
  snapshot="$(capture_snapshot "${session}")"
  assert_contains "${snapshot}" "Loading process tree…"

  elapsed_ms="$(wait_for_process_tree "${session}")"
  sum_elapsed=$((sum_elapsed + elapsed_ms))
  if (( elapsed_ms > max_elapsed )); then
    max_elapsed="${elapsed_ms}"
  fi

  if (( trial == 1 )); then
    sleep 1.2
    snapshot="$(capture_snapshot "${session}")"
    assert_contains "${snapshot}" "mini-edr-daemon"
    assert_contains "${snapshot}" "No threats detected"
    assert_not_contains "${snapshot}" "${DEGRADED_BANNER}"
  fi

  cleanup_session "${session}"
  trap - EXIT
done

mean_elapsed=$((sum_elapsed / TRIALS))
if (( mean_elapsed > 750 )); then
  printf 'mean process-tree update latency %s ms exceeded 750 ms\n' "${mean_elapsed}" >&2
  exit 1
fi
if (( max_elapsed > 1000 )); then
  printf 'max process-tree update latency %s ms exceeded 1000 ms\n' "${max_elapsed}" >&2
  exit 1
fi

degraded_session="mini-edr-tui-degraded-$$"
trap 'cleanup_session "${degraded_session}"' EXIT
launch_session "${degraded_session}" "degraded" 130
sleep 1.0
degraded_snapshot="$(capture_snapshot "${degraded_session}")"
assert_contains "${degraded_snapshot}" "mini-edr-daemon"
assert_contains "${degraded_snapshot}" "${DEGRADED_BANNER}"
cleanup_session "${degraded_session}"
trap - EXIT

printf 'launch_smoke.sh passed: mean=%sms max=%sms trials=%s\n' "${mean_elapsed}" "${max_elapsed}" "${TRIALS}"
