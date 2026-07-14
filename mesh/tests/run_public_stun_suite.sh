#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BIN_DIR="${BIN_DIR:-}"
SCENARIO="${SCENARIO:-matrix}"
STUN_URL_OVERRIDE="${STUN_URL_OVERRIDE:-}"
ADVERTISE_IP_OVERRIDE="${ADVERTISE_IP_OVERRIDE:-}"
WORKDIR_ROOT="${WORKDIR_ROOT:-/tmp/mesh-public-stun-suite}"
TWO_NODE_SCRIPT="${TWO_NODE_SCRIPT:-${SCRIPT_DIR}/run_eu_public_stun_2node.sh}"
THREE_NODE_SCRIPT="${THREE_NODE_SCRIPT:-${SCRIPT_DIR}/run_eu_public_stun_regression.sh}"

STUN_MATRIX=(
    "self-hosted|stun:161.97.65.129:3479"
    "cloudflare|stun:stun.cloudflare.com:3478"
    "google|stun:stun.l.google.com:19302"
)

fail() {
    echo "[FAIL] $*" >&2
    exit 1
}

usage() {
    cat <<EOF
Usage:
  $(basename "$0") --bin-dir <dir> [--scenario two-node|three-node|matrix]
                   [--stun-url <url>] [--advertise-ip <ip>] [--workdir-root <dir>]

Examples:
  $(basename "$0") --bin-dir /root/code/turbo-p2p/build/linux-gcc-debug/bin
  $(basename "$0") --bin-dir /root/code/turbo-p2p/build/linux-gcc-debug/bin --scenario three-node
  $(basename "$0") --bin-dir /root/code/turbo-p2p/build/linux-gcc-debug/bin --scenario two-node --stun-url stun:161.97.65.129:3479
EOF
}

require_cmd() {
    local cmd="$1"
    command -v "$cmd" >/dev/null 2>&1 || fail "required command not found: ${cmd}"
}

run_case() {
    local label="$1"
    local script_path="$2"
    local stun_url="$3"
    local workdir="$4"

    echo "[INFO] Running ${label} with ${stun_url}"
    STUN_URL="${stun_url}" \
    ADVERTISE_IP="${ADVERTISE_IP_OVERRIDE:-${ADVERTISE_IP:-161.97.65.129}}" \
    WORKDIR="${workdir}" \
    "${script_path}" "${BIN_DIR}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --bin-dir)
            [[ $# -ge 2 ]] || fail "--bin-dir requires a value"
            BIN_DIR="$2"
            shift 2
            ;;
        --scenario)
            [[ $# -ge 2 ]] || fail "--scenario requires a value"
            SCENARIO="$2"
            shift 2
            ;;
        --stun-url)
            [[ $# -ge 2 ]] || fail "--stun-url requires a value"
            STUN_URL_OVERRIDE="$2"
            shift 2
            ;;
        --advertise-ip)
            [[ $# -ge 2 ]] || fail "--advertise-ip requires a value"
            ADVERTISE_IP_OVERRIDE="$2"
            shift 2
            ;;
        --workdir-root)
            [[ $# -ge 2 ]] || fail "--workdir-root requires a value"
            WORKDIR_ROOT="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            fail "unknown argument: $1"
            ;;
    esac
done

[[ -n "${BIN_DIR}" ]] || fail "--bin-dir is required"

require_cmd tmux
[[ -x "${BIN_DIR}/meshctl" ]] || fail "meshctl not found in ${BIN_DIR}"
[[ -x "${TWO_NODE_SCRIPT}" ]] || fail "2-node script not found: ${TWO_NODE_SCRIPT}"
[[ -x "${THREE_NODE_SCRIPT}" ]] || fail "3-node script not found: ${THREE_NODE_SCRIPT}"

mkdir -p "${WORKDIR_ROOT}"

case "${SCENARIO}" in
    two-node)
        run_case "public STUN 2-node regression" "${TWO_NODE_SCRIPT}" \
                 "${STUN_URL_OVERRIDE:-stun:161.97.65.129:3479}" \
                 "${WORKDIR_ROOT}/two-node"
        ;;
    three-node)
        run_case "public STUN 3-node regression" "${THREE_NODE_SCRIPT}" \
                 "${STUN_URL_OVERRIDE:-stun:161.97.65.129:3479}" \
                 "${WORKDIR_ROOT}/three-node"
        ;;
    matrix)
        if [[ -n "${STUN_URL_OVERRIDE}" ]]; then
            fail "--stun-url cannot be combined with --scenario matrix"
        fi

        for entry in "${STUN_MATRIX[@]}"; do
            name="${entry%%|*}"
            url="${entry#*|}"

            run_case "public STUN 2-node regression (${name})" "${TWO_NODE_SCRIPT}" \
                     "${url}" "${WORKDIR_ROOT}/${name}/two-node"
            run_case "public STUN 3-node regression (${name})" "${THREE_NODE_SCRIPT}" \
                     "${url}" "${WORKDIR_ROOT}/${name}/three-node"
        done
        ;;
    *)
        fail "invalid --scenario: ${SCENARIO}"
        ;;
esac

echo "[PASS] public STUN suite passed (${SCENARIO})"
