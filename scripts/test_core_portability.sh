#!/usr/bin/env bash
# Verify the sensor CO-RE portability prerequisites used by TC-04/FR-S04.
#
# The system-integration milestone will provide the kernel-5.8 guest image that
# can run the full daemon under KVM. Until that artifact exists, this script
# keeps the sensor milestone honest by proving the exact release build emits a
# BTF-enabled eBPF object and that the current host exposes `/sys/kernel/btf`
# for Aya/libbpf-style CO-RE relocation.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SENSOR_OBJECT="${REPO_ROOT}/target/mini-edr-sensor-ebpf/bpfel-unknown-none/release/mini-edr-sensor-ebpf"
BPFTool_DEFAULT="/usr/lib/linux-tools/6.8.0-110-generic/bpftool"
BPFTool="${MINI_EDR_BPFTOOL:-${BPFTool_DEFAULT}}"

if [[ ! -x "${BPFTool}" ]]; then
  if command -v bpftool >/dev/null 2>&1; then
    BPFTool="$(command -v bpftool)"
  else
    echo "error: bpftool not found; install linux-tools-generic or set MINI_EDR_BPFTOOL" >&2
    exit 1
  fi
fi

cd "${REPO_ROOT}"

echo "[core-portability] building release sensor/eBPF object"
cargo build -p mini-edr-sensor --release

echo "[core-portability] checking BTF sections in ${SENSOR_OBJECT}"
if [[ ! -f "${SENSOR_OBJECT}" ]]; then
  echo "error: expected eBPF object missing at ${SENSOR_OBJECT}" >&2
  exit 1
fi

# BTF and BTF.ext are the data that let the same object relocate against both
# kernel 5.8 and newer 6.x layouts. A missing section means the runtime could
# still load on this host by luck but would fail the portability contract.
readelf -S "${SENSOR_OBJECT}" | grep -Eq ' \.BTF[[:space:]]'
readelf -S "${SENSOR_OBJECT}" | grep -Eq ' \.BTF\.ext[[:space:]]'

echo "[core-portability] checking host kernel BTF availability"
"${BPFTool}" btf dump file /sys/kernel/btf/vmlinux format c >/dev/null

if [[ -n "${MINI_EDR_CORE_QEMU_KERNEL:-}" || -n "${MINI_EDR_CORE_QEMU_ROOTFS:-}" ]]; then
  echo "error: QEMU 5.8 boot is not wired in this sensor-stage script yet; system-integration supplies the guest harness" >&2
  exit 1
fi

echo "[core-portability] host CO-RE preflight passed; set MINI_EDR_CORE_QEMU_KERNEL/MINI_EDR_CORE_QEMU_ROOTFS in the system-integration harness for the 5.8 boot matrix"
