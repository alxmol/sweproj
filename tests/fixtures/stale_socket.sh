#!/usr/bin/env bash
# Backward-compatible wrapper for the stale-socket recovery fixture.

set -euo pipefail

exec "/home/directory/mini-edr/tests/fixtures/stale_socket_recovery.sh" "$@"
