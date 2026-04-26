#!/usr/bin/env bash
# Validate the daemon's fork-storm NDJSON contract for VAL-PIPELINE-022.
#
# The parser defines the future daemon-output schema that f8-daemon-binary must
# emit during live validation:
# - Ignore blank lines and unrelated NDJSON records.
# - Lines relevant to this validator MUST use `record_type` set to
#   `fork_storm_enrichment`.
# - Required top-level fields: `pid`, `ancestry_truncated`,
#   `enrichment_partial`, and `ancestry_chain`.
# - `ancestry_chain` MUST be ordered from the observed leaf process toward the
#   root terminator. Complete chains therefore end at PID 1, while the only
#   non-PID-1 terminator this validator accepts is the explicit kthreadd
#   allow-list entry (`pid == 0` with `process_name` of `kthreadd` or
#   `[kthreadd]`).
# - Each ancestry entry MUST include `pid`, `ppid`, `process_name`, and
#   `binary_path` so the live daemon output remains self-describing.
#
# Exit codes:
#   0 = success
#   2 = parse/schema error or no relevant validator records
#   3 = ancestry cycle detected
#   4 = non-truncated chain does not end at PID 1 / kthreadd allow-list
#   5 = mid-chain entry has ppid == 0
#   6 = enrichment_partial ratio exceeded 5%

set -euo pipefail

if [[ $# -ne 1 ]]; then
  printf 'usage: %s <daemon-log.ndjson>\n' "$0" >&2
  exit 64
fi

LOG_PATH="$1"
if [[ ! -f "${LOG_PATH}" ]]; then
  printf 'error: daemon log %s does not exist\n' "${LOG_PATH}" >&2
  exit 64
fi

python3 - "${LOG_PATH}" <<'PY'
import json
import pathlib
import sys

LOG_PATH = pathlib.Path(sys.argv[1])
ROOT_ALLOWLIST = {"kthreadd", "[kthreadd]"}
RECORD_TYPE = "fork_storm_enrichment"


def fail(code: int, message: str) -> "None":
    print(message, file=sys.stderr)
    raise SystemExit(code)


def require(record: dict, key: str, expected_type: type, line_number: int):
    value = record.get(key)
    if not isinstance(value, expected_type):
        fail(
            2,
            f"line {line_number}: record field `{key}` must be {expected_type.__name__}",
        )
    return value


def require_chain_entry(entry: dict, line_number: int, index: int) -> tuple[int, int, str]:
    if not isinstance(entry, dict):
        fail(2, f"line {line_number}: ancestry_chain[{index}] must be an object")

    pid = require(entry, "pid", int, line_number)
    ppid = require(entry, "ppid", int, line_number)
    process_name = require(entry, "process_name", str, line_number)
    require(entry, "binary_path", str, line_number)
    return pid, ppid, process_name


validated_records = 0
partial_records = 0

with LOG_PATH.open("r", encoding="utf-8") as handle:
    for line_number, raw_line in enumerate(handle, start=1):
        line = raw_line.strip()
        if not line:
            continue

        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            fail(2, f"line {line_number}: invalid JSON: {error}")

        if not isinstance(record, dict):
            fail(2, f"line {line_number}: NDJSON lines must decode to objects")

        if record.get("record_type") != RECORD_TYPE:
            continue

        pid = require(record, "pid", int, line_number)
        ancestry_truncated = require(record, "ancestry_truncated", bool, line_number)
        enrichment_partial = require(record, "enrichment_partial", bool, line_number)
        ancestry_chain = require(record, "ancestry_chain", list, line_number)

        if not ancestry_chain:
            fail(2, f"line {line_number}: ancestry_chain must not be empty")

        seen_pids: set[int] = set()
        parsed_chain: list[tuple[int, int, str]] = []
        for index, entry in enumerate(ancestry_chain):
            chain_pid, chain_ppid, process_name = require_chain_entry(
                entry, line_number, index
            )
            if chain_pid in seen_pids:
                fail(
                    3,
                    f"line {line_number}: ancestry cycle detected when pid {chain_pid} repeats",
                )
            seen_pids.add(chain_pid)
            parsed_chain.append((chain_pid, chain_ppid, process_name))

            if index < len(ancestry_chain) - 1 and chain_ppid == 0:
                fail(
                    5,
                    f"line {line_number}: ancestry_chain[{index}] has mid-chain ppid == 0",
                )

        if parsed_chain[0][0] != pid:
            fail(
                2,
                f"line {line_number}: ancestry_chain[0].pid must match record pid {pid}",
            )

        if not ancestry_truncated:
            terminal_pid, _, terminal_name = parsed_chain[-1]
            if terminal_pid != 1 and not (
                terminal_pid == 0 and terminal_name in ROOT_ALLOWLIST
            ):
                fail(
                    4,
                    "line "
                    f"{line_number}: complete ancestry chain must end at pid 1 or the kthreadd allow-list",
                )

        validated_records += 1
        partial_records += int(enrichment_partial)

if validated_records == 0:
    fail(2, "no fork_storm_enrichment records were found in the daemon log")

partial_ratio = partial_records / validated_records
if partial_ratio > 0.05:
    fail(
        6,
        "enrichment_partial ratio exceeded 5%: "
        f"{partial_records}/{validated_records} = {partial_ratio:.6f}",
    )

print(f"validated_records={validated_records}")
print(f"partial_records={partial_records}")
print(f"partial_ratio={partial_ratio:.6f}")
PY
