#!/usr/bin/env bash
# Run the system-integration portability matrix for Mini-EDR.
#
# This wrapper keeps the user-facing entrypoint in `scripts/` while delegating
# the heavier QEMU/KVM orchestration to the adjacent Python helper.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "${REPO_ROOT}/scripts/test_kernel_matrix.py"
