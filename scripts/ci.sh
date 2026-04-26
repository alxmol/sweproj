#!/usr/bin/env bash
# Mini-EDR CI/local gate helper.
#
# This script mirrors the GitHub Actions workflow so engineers can reproduce PR
# failures locally without remembering the exact cargo incantations. Each gate is
# intentionally small and explicit: the workflow runs them in parallel jobs for
# fast feedback, while `ci.sh all` keeps the same order for local pre-commit use.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COVERAGE_DIR="${REPO_ROOT}/target/llvm-cov"

usage() {
  cat <<'USAGE'
Usage: scripts/ci.sh <gate>

Gates:
  lint           Run clippy with warnings denied, then rustfmt check.
  supply-chain   Run cargo-audit and cargo-deny.
  test           Run cargo-nextest with threads capped to floor(nproc/2).
  coverage       Run cargo-llvm-cov and enforce line coverage thresholds.
  docs           Run cargo doc with missing_docs promoted to errors.
  fuzz-smoke     Run the 60s cargo-fuzz smoke for ringbuffer deserialization.
  all            Run lint, supply-chain, test, coverage, docs, and fuzz-smoke in order.
USAGE
}

require_tool() {
  local tool="$1"
  if ! command -v "${tool}" >/dev/null 2>&1; then
    printf 'error: required tool `%s` is not on PATH\n' "${tool}" >&2
    exit 127
  fi
}

nextest_threads() {
  local cpus

  # CI and developer laptops can have very different CPU counts. Capping
  # nextest to floor(nproc/2) leaves headroom for rustc, llvm-cov, and future
  # daemon/eBPF fixture processes instead of saturating the runner.
  cpus="$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || printf '2')"
  if ! [[ "${cpus}" =~ ^[0-9]+$ ]] || (( cpus < 2 )); then
    printf '1'
    return
  fi

  printf '%s' "$((cpus / 2))"
}

line_percent() {
  local report="$1"
  jq -r '.data[0].totals.lines.percent' "${report}"
}

assert_minimum_percent() {
  local label="$1"
  local observed="$2"
  local minimum="$3"

  awk -v label="${label}" -v observed="${observed}" -v minimum="${minimum}" '
    BEGIN {
      if (observed + 0 < minimum + 0) {
        printf "coverage gate failed: %s lines %.2f%% < %.2f%%\n", label, observed, minimum > "/dev/stderr";
        exit 1;
      }
      printf "coverage gate passed: %s lines %.2f%% >= %.2f%%\n", label, observed, minimum;
    }
  '
}

run_lint() {
  require_tool cargo
  cargo clippy --workspace --all-targets --all-features -- -D warnings
  cargo fmt --all -- --check
}

run_supply_chain() {
  require_tool cargo
  require_tool cargo-audit
  require_tool cargo-deny
  cargo audit
  cargo deny check
}

run_test() {
  require_tool cargo
  require_tool cargo-nextest

  local threads
  threads="$(nextest_threads)"
  printf 'running cargo-nextest with --test-threads=%s\n' "${threads}"
  cargo nextest run --workspace --test-threads="${threads}"
}

coverage_report() {
  local label="$1"
  local output="$2"
  shift 2

  require_tool cargo
  require_tool cargo-llvm-cov
  mkdir -p "${COVERAGE_DIR}"

  local threads
  threads="$(nextest_threads)"
  printf 'running coverage for %s with --test-threads=%s\n' "${label}" "${threads}"
  cargo llvm-cov nextest "$@" --json --summary-only --output-path "${output}" --test-threads="${threads}"
}

run_coverage() {
  require_tool jq
  require_tool awk

  local workspace_report="${COVERAGE_DIR}/workspace-summary.json"
  local sensor_report="${COVERAGE_DIR}/mini-edr-sensor-summary.json"
  local detection_report="${COVERAGE_DIR}/mini-edr-detection-summary.json"

  # The validation contract has one workspace-wide threshold and two stricter
  # crate-level thresholds. Running separate summaries makes CI failures clear:
  # engineers can tell whether they broke general maintainability coverage or a
  # security-critical sensor/detection target.
  coverage_report "workspace" "${workspace_report}" --workspace
  assert_minimum_percent "workspace" "$(line_percent "${workspace_report}")" "70.0"

  coverage_report "mini-edr-sensor" "${sensor_report}" -p mini-edr-sensor
  assert_minimum_percent "mini-edr-sensor" "$(line_percent "${sensor_report}")" "85.0"

  coverage_report "mini-edr-detection" "${detection_report}" -p mini-edr-detection
  assert_minimum_percent "mini-edr-detection" "$(line_percent "${detection_report}")" "85.0"
}

run_docs() {
  require_tool cargo
  RUSTDOCFLAGS='-D missing_docs' cargo doc --no-deps --workspace
}

run_fuzz_smoke() {
  require_tool cargo
  require_tool cargo-fuzz
  require_tool jq

  # Historical mission artifacts use both MINI_EDR_FUZZ_SECONDS and
  # MINIEDR_FUZZ_DURATION. Supporting both keeps the smoke gate compatible with
  # the feature contract while preserving the repo-level env var naming.
  local duration
  duration="${MINI_EDR_FUZZ_SECONDS:-${MINIEDR_FUZZ_DURATION:-60}}"
  export MINI_EDR_FUZZ_SUMMARY_PATH="${REPO_ROOT}/fuzz/run_summary.json"

  printf 'running cargo-fuzz smoke with -max_total_time=%s\n' "${duration}"
  cargo +nightly fuzz run ringbuffer_deserialize -- -max_total_time="${duration}"
  jq -e '
    .start_ts >= 0 and
    .end_ts >= .start_ts and
    .duration_secs >= 0 and
    .iterations >= 0 and
    .crashes == 0
  ' "${MINI_EDR_FUZZ_SUMMARY_PATH}" >/dev/null
}

main() {
  cd "${REPO_ROOT}"

  case "${1:-}" in
    lint) run_lint ;;
    supply-chain) run_supply_chain ;;
    test) run_test ;;
    coverage) run_coverage ;;
    docs) run_docs ;;
    fuzz-smoke) run_fuzz_smoke ;;
    all)
      run_lint
      run_supply_chain
      run_test
      run_coverage
      run_docs
      run_fuzz_smoke
      ;;
    -h|--help|help) usage ;;
    *)
      usage >&2
      exit 64
      ;;
  esac
}

main "$@"
