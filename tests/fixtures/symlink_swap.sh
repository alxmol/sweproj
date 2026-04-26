#!/usr/bin/env bash
# Verify that SIGUSR1 reopen refuses to follow a symlinked alert target and
# keeps future alerts buffered until the path becomes safe again.

set -euo pipefail

source "/home/alexm/mini-edr/tests/fixtures/json_log_lib.sh"

temp_dir="$(mktemp -d /tmp/mini-edr-symlink-swap-XXXXXX)"
read -r daemon_pid daemon_port _config_path _daemon_stdout < <(json_log_start_daemon "${temp_dir}" 0.0)
trap 'cleanup_daemon "${daemon_pid}"' EXIT

alert_log="${temp_dir}/logs/alerts.jsonl"
daemon_log="${temp_dir}/logs/daemon.log"

json_log_predict_n "${daemon_port}" 1
[[ "$(wc -l < "${alert_log}")" == "1" ]]

rm -f "${alert_log}"
ln -s /dev/null "${alert_log}"
kill -USR1 "${daemon_pid}"
sleep 0.2

json_log_predict_n "${daemon_port}" 2

rm -f "${alert_log}"
kill -USR1 "${daemon_pid}"
sleep 0.2

json_log_predict_n "${daemon_port}" 1

[[ "$(wc -l < "${alert_log}")" == "3" ]]
[[ "$(jq -c . "${alert_log}" | wc -l)" == "3" ]]
grep -q 'log_target_unsafe' "${daemon_log}"
if lsof -nP -a -p "${daemon_pid}" -- /dev/null | awk '$4 ~ /[0-9]+[wu]/ { found = 1 } END { exit found ? 0 : 1 }'; then
  echo "daemon unexpectedly reopened the alert log through /dev/null" >&2
  exit 1
fi

echo "symlink_swap.sh: PASS"
