#!/usr/bin/env bash
# Verify that a SIGUSR1-driven logrotate handoff closes the old alert-log
# descriptor, reopens the configured path with mode 0600, and writes all
# subsequent alerts to the new file only.

set -euo pipefail

source "/home/alexm/mini-edr/tests/fixtures/json_log_lib.sh"

temp_dir="$(mktemp -d /tmp/mini-edr-log-rotation-XXXXXX)"
read -r daemon_pid daemon_port _config_path _daemon_stdout < <(json_log_start_daemon "${temp_dir}" 0.0)
trap 'cleanup_daemon "${daemon_pid}"' EXIT

alert_log="${temp_dir}/logs/alerts.jsonl"
rotated_log="${temp_dir}/logs/alerts.jsonl.1"

json_log_predict_n "${daemon_port}" 1
[[ "$(wc -l < "${alert_log}")" == "1" ]]

old_inode="$(stat -c '%i' "${alert_log}")"
old_size="$(stat -c '%s' "${alert_log}")"
mv "${alert_log}" "${rotated_log}"

kill -USR1 "${daemon_pid}"
for _ in $(seq 1 20); do
  if [[ -f "${alert_log}" ]]; then
    break
  fi
  sleep 0.05
done

[[ -f "${alert_log}" ]]
[[ "$(stat -c '%a' "${alert_log}")" == "600" ]]
[[ "$(stat -c '%i' "${alert_log}")" != "${old_inode}" ]]

json_log_predict_n "${daemon_port}" 2
sleep 0.2

[[ "$(wc -l < "${alert_log}")" == "2" ]]
[[ "$(jq -c . "${alert_log}" | wc -l)" == "2" ]]
[[ "$(wc -l < "${rotated_log}")" == "1" ]]
[[ "$(stat -c '%s' "${rotated_log}")" == "${old_size}" ]]

echo "log_rotation.sh: PASS"
