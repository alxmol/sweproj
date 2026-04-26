#!/usr/bin/env bash
# Verify that append-only alert, inference, and daemon logs satisfy the
# f5-json-log contract on a normal happy-path daemon run.

set -euo pipefail

source "/home/alexm/mini-edr/tests/fixtures/json_log_lib.sh"

temp_dir="$(mktemp -d /tmp/mini-edr-alert-log-XXXXXX)"
read -r daemon_pid daemon_port _config_path _daemon_stdout < <(json_log_start_daemon "${temp_dir}" 0.0)
trap 'cleanup_daemon "${daemon_pid}"' EXIT

alert_log="${temp_dir}/logs/alerts.jsonl"
event_log="${temp_dir}/logs/events.jsonl"
daemon_log="${temp_dir}/logs/daemon.log"

json_log_predict_n "${daemon_port}" 50

[[ "$(wc -l < "${alert_log}")" == "50" ]]
[[ "$(jq -c . "${alert_log}" | wc -l)" == "50" ]]
[[ "$(stat -c '%a' "${alert_log}")" == "600" ]]

[[ "$(wc -l < "${event_log}")" == "50" ]]
[[ "$(jq -c . "${event_log}" | wc -l)" == "50" ]]
[[ "$(jq -c -e 'select(.event_type == "inference_result" and (.score >= 0 and .score <= 1) and (.top_features | length == 5) and .pid)' "${event_log}" | wc -l)" == "50" ]]

[[ "$(stat -c '%a' "${daemon_log}")" == "640" ]]
lsof_output="$(lsof -nP +fg -a -p "${daemon_pid}" -- "${daemon_log}")"
echo "${lsof_output}" | grep -q "${daemon_log}"
echo "${lsof_output}" | grep -Eq 'AP|O_APPEND|0x[a-f0-9]+'

echo "alert_log_test.sh: PASS"
