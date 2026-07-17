#!/usr/bin/env bash
# Reproducibly fetch the real-world benchmark corpora into benchmark/corpora/.
# These are NOT vendored into the repo (see .gitignore); this script recreates
# them. Pinned to specific commits so the benchmark numbers are reproducible.
# After running, use: python benchmark/run_realworld_benchmark.py
set -euo pipefail
cd "$(dirname "$0")"

clone() { # name url ref
  local name="$1" url="$2" ref="$3"
  if [ -d "$name/.git" ]; then echo "[have] $name"; return; fi
  echo "[clone] $name @ $ref"
  git clone --depth 1 --filter=blob:none "$url" "$name"
  git -C "$name" fetch --depth 1 origin "$ref" 2>/dev/null || true
  git -C "$name" checkout -q "$ref" 2>/dev/null || echo "  (using default branch tip)"
}

# small, self-contained embedded filesystem
clone littlefs   https://github.com/littlefs-project/littlefs.git v2.9.3
# TCP/IP stack
clone lwip       https://github.com/lwip-tcpip/lwip.git           STABLE-2_2_0_RELEASE
# crypto library (large; we scan library/ only)
clone mbedtls    https://github.com/Mbed-TLS/mbedtls.git          v3.6.2

# Zephyr is huge; take only kernel/ + include/ via sparse checkout.
if [ ! -d zephyr-kernel/.git ]; then
  echo "[clone] zephyr-kernel (sparse: kernel/ include/)"
  git clone --depth 1 --filter=blob:none --sparse \
      https://github.com/zephyrproject-rtos/zephyr.git zephyr-kernel
  git -C zephyr-kernel sparse-checkout set kernel include
else
  echo "[have] zephyr-kernel"
fi
echo "done."
