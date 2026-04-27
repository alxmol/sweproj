#!/usr/bin/env bash
# Apply the Linux capabilities Mini-EDR needs to its release daemon binary.
#
# This helper intentionally refuses to touch arbitrary paths outside the
# repository checkout. That keeps the "production-style" capability workflow
# focused on the built `mini-edr-daemon` artifact instead of accidentally
# changing unrelated host binaries.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(readlink -f "${SCRIPT_DIR}/..")"
readonly DEFAULT_BINARY="${REPO_ROOT}/target/release/mini-edr-daemon"
readonly REQUIRED_CAPS="cap_bpf,cap_perfmon,cap_sys_admin+ep"

binary_input="${1:-${DEFAULT_BINARY}}"

if ! command -v setcap >/dev/null 2>&1; then
  echo "setcap is required but not installed; install libcap2-bin first" >&2
  exit 1
fi

if ! command -v getcap >/dev/null 2>&1; then
  echo "getcap is required but not installed; install libcap2-bin first" >&2
  exit 1
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "setcap.sh must run as root; re-run with sudo ./scripts/setcap.sh" >&2
  exit 1
fi

if [[ ! -e "${binary_input}" ]]; then
  echo "daemon binary not found at ${binary_input}; run cargo build --release first" >&2
  exit 1
fi

if [[ -L "${binary_input}" ]]; then
  echo "refusing to set capabilities on symlink ${binary_input}; use the real binary path" >&2
  exit 1
fi

binary_path="$(readlink -f "${binary_input}")"

case "${binary_path}" in
  "${REPO_ROOT}"/*) ;;
  *)
    echo "refusing to set capabilities outside the repository: ${binary_path}" >&2
    exit 1
    ;;
esac

if [[ ! -f "${binary_path}" ]]; then
  echo "expected a regular file, not ${binary_path}" >&2
  exit 1
fi

if [[ "$(basename "${binary_path}")" != "mini-edr-daemon" ]]; then
  echo "expected a mini-edr-daemon binary, not $(basename "${binary_path}")" >&2
  exit 1
fi

if [[ ! -x "${binary_path}" ]]; then
  echo "binary exists but is not executable: ${binary_path}" >&2
  exit 1
fi

setcap "${REQUIRED_CAPS}" "${binary_path}"

caps_line="$(getcap "${binary_path}" 2>/dev/null || true)"
if [[ -z "${caps_line}" ]] \
  || ! echo "${caps_line}" | grep -q "cap_bpf" \
  || ! echo "${caps_line}" | grep -q "cap_perfmon" \
  || ! echo "${caps_line}" | grep -q "cap_sys_admin"; then
  echo "capability verification failed after setcap: ${caps_line}" >&2
  exit 1
fi

printf 'Applied %s to %s\n' "${REQUIRED_CAPS}" "${binary_path}"
