#!/usr/bin/env bash
# Verify that append-only alert logs survive a clean daemon restart without
# truncating previously written records.

set -euo pipefail

source "/home/alexm/mini-edr/tests/fixtures/json_log_lib.sh"

temp_dir="$(mktemp -d /tmp/mini-edr-log-survival-XXXXXX)"
read -r daemon_pid daemon_port config_path _daemon_stdout < <(json_log_start_daemon "${temp_dir}" 0.0)

alert_log="${temp_dir}/logs/alerts.jsonl"
pre_restart_snapshot="${temp_dir}/pre-restart-head-100.jsonl"

trap 'cleanup_daemon "${daemon_pid}"' EXIT

json_log_predict_n "${daemon_port}" 100
head -n 100 "${alert_log}" > "${pre_restart_snapshot}"
mtime_before="$(stat -c '%Y' "${alert_log}")"
inode_before="$(stat -c '%i' "${alert_log}")"

cleanup_daemon "${daemon_pid}"

read -r daemon_pid daemon_port _config_path _daemon_stdout < <(json_log_start_daemon "${temp_dir}" 0.0 "${daemon_port}")
trap 'cleanup_daemon "${daemon_pid}"' EXIT

json_log_predict_n "${daemon_port}" 100

[[ "$(wc -l < "${alert_log}")" == "200" ]]
[[ "$(jq -c . "${alert_log}" | wc -l)" == "200" ]]
cmp --silent "${pre_restart_snapshot}" <(head -n 100 "${alert_log}")
[[ "$(stat -c '%a' "${alert_log}")" == "600" ]]
[[ "$(stat -c '%Y' "${alert_log}")" -ge "${mtime_before}" ]]
[[ "$(stat -c '%i' "${alert_log}")" == "${inode_before}" ]]

echo "log_survival.sh: PASS"
