#!/usr/bin/env bash
# kernel_compile.sh — controlled benign build-workload simulator.
#
# The fixture creates a tiny local source tree and, when toolchain components
# are available, compiles it via `make`. If the host lacks a C compiler, it
# falls back to compiling a handful of Python modules so the workload still
# performs many safe file reads and child-process execs without touching the
# real kernel tree.

set -euo pipefail

source "/home/directory/mini-edr/tests/fixtures/fixture_runtime_lib.sh"

daemon_port=""
output_path=""
trial_id="0"
window_hours="6"
pid_hint="${BASHPID}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --daemon-port)
      daemon_port="$2"
      shift 2
      ;;
    --output)
      output_path="$2"
      shift 2
      ;;
    --trial)
      trial_id="$2"
      shift 2
      ;;
    --hours)
      window_hours="$2"
      shift 2
      ;;
    --pid)
      pid_hint="$2"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "${daemon_port}" ]]; then
  echo "--daemon-port is required" >&2
  exit 2
fi

temp_dir="$(mktemp -d /tmp/mini-edr-kernel-compile-XXXXXX)"
src_dir="${temp_dir}/src"
mkdir -p "${src_dir}"

cat >"${src_dir}/main.c" <<'EOF'
#include <stdio.h>
int helper(void);
int main(void) { printf("%d\n", helper()); return 0; }
EOF
cat >"${src_dir}/helper.c" <<'EOF'
int helper(void) { return 42; }
EOF
cat >"${src_dir}/Makefile" <<'EOF'
all:
	cc -c main.c -o main.o
	cc -c helper.c -o helper.o
	cc main.o helper.o -o demo
EOF

if command -v make >/dev/null 2>&1 && command -v cc >/dev/null 2>&1; then
  make -C "${src_dir}" >/dev/null
else
  for index in 1 2 3 4 5; do
    cat >"${src_dir}/module_${index}.py" <<EOF
value = ${index}
EOF
  done
  "${FIXTURE_PYTHON_BIN}" -m py_compile "${src_dir}"/module_*.py
fi

response_json="$(fixture_submit_vector "kernel_compile" "${daemon_port}" "${pid_hint}" "${window_hours}")"
score="$(fixture_json_get "${response_json}" "threat_score")"
would_alert="$(fixture_json_get "${response_json}" "would_alert")"

result_json="$("${FIXTURE_PYTHON_BIN}" - "${response_json}" "${trial_id}" "${pid_hint}" "${window_hours}" <<'PY'
import json
import sys

response = json.loads(sys.argv[1])
trial_id = int(sys.argv[2])
pid = int(sys.argv[3])
hours = float(sys.argv[4])
result = {
    "fixture": "kernel_compile",
    "category": "benign",
    "trial": trial_id,
    "pid": pid,
    "expected_binary_path": "/home/directory/mini-edr/tests/fixtures/benign/kernel_compile.sh",
    "window_hours": hours,
    "score": response["threat_score"],
    "would_alert": response["would_alert"],
    "alert_count": 1 if response["would_alert"] else 0,
    "model_hash": response["model_hash"],
}
print(json.dumps(result, separators=(",", ":")))
PY
)"

if [[ -n "${output_path}" ]]; then
  printf '%s\n' "${result_json}" >"${output_path}"
fi

echo "kernel_compile trial=${trial_id} score=${score} would_alert=${would_alert}" >&2
printf '%s\n' "${result_json}"
