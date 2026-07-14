#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUITE_SCRIPT="${SCRIPT_DIR}/run_public_stun_suite.sh"
BIN_DIR="${1:-/root/code/turbo-p2p/build/linux-gcc-debug/bin}"

[[ -x "${SUITE_SCRIPT}" ]] || {
    echo "[FAIL] public STUN suite script not found: ${SUITE_SCRIPT}" >&2
    exit 1
}

exec "${SUITE_SCRIPT}" --bin-dir "${BIN_DIR}" --scenario matrix
