#!/usr/bin/env bash
# Backward-compatible wrapper for the stale-socket recovery fixture.

set -euo pipefail

exec "/home/alexm/mini-edr/tests/fixtures/stale_socket_recovery.sh" "$@"
