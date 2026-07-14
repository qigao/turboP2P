#!/usr/bin/env bash
set -euo pipefail

ACTION="run"
REPO_DIR="${REPO_DIR:-/root/code/turbo-p2p}"
MESHD_BIN="${MESHD_BIN:-/root/code/turbo-p2p/build/linux-gcc-release/bin/meshd}"
BOOTSTRAP_CONFIG="${BOOTSTRAP_CONFIG:-/root/code/turbo-p2p/mesh/examples/mesh.eu.yaml}"
JOINER_CONFIG="${JOINER_CONFIG:-/root/code/turbo-p2p/mesh/examples/mesh.local.yaml}"
BOOTSTRAP_STATUS_FILE="${BOOTSTRAP_STATUS_FILE:-/tmp/meshd-bootstrap-status.json}"
JOINER_STATUS_FILE="${JOINER_STATUS_FILE:-/tmp/meshd-joiner-status.json}"
BOOTSTRAP_SESSION_PREFIX="${BOOTSTRAP_SESSION_PREFIX:-turbonet-meshd-bootstrap}"
JOINER_SESSION_PREFIX="${JOINER_SESSION_PREFIX:-turbonet-meshd-joiner}"
STATUS_INTERVAL_MS="${STATUS_INTERVAL_MS:-200}"
START_WAIT_SECS="${START_WAIT_SECS:-3}"
CONNECT_WAIT_SECS="${CONNECT_WAIT_SECS:-20}"
CONNECT_POLL_SECS="${CONNECT_POLL_SECS:-2}"
STATUS_LINES="${STATUS_LINES:-80}"
LD_LIBRARY_PATH_VALUE="${LD_LIBRARY_PATH_VALUE:-/root/code/turbo-p2p/build/linux-gcc-release/bin:/root/code/turbonet/build/linux-gcc-release/bin:/opt/turbonet/lib}"
SINGLE_RUNNER="${SINGLE_RUNNER:-/root/code/turbo-p2p/run_meshd_remote_status_check.sh}"

fail() {
    echo "[FAIL] $*" >&2
    exit 1
}

usage() {
    cat <<EOF
Usage:
  $(basename "$0") [--action run|status|logs|stop]
                   [--repo-dir <dir>]
                   [--meshd-bin <path>]
                   [--bootstrap-config <path>]
                   [--joiner-config <path>]
                   [--connect-wait-secs <n>]
                   [--connect-poll-secs <n>]

Examples:
  $(basename "$0")
  $(basename "$0") --action status
  $(basename "$0") --bootstrap-config /root/code/turbo-p2p/mesh/examples/mesh.eu.yaml --joiner-config /root/code/turbo-p2p/mesh/examples/mesh.local.yaml
EOF
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

run_single() {
    local action="$1"
    local config="$2"
    local status_file="$3"
    local session_prefix="$4"

    env \
        LD_LIBRARY_PATH_VALUE="${LD_LIBRARY_PATH_VALUE}" \
        bash "${SINGLE_RUNNER}" \
        --action "${action}" \
        --repo-dir "${REPO_DIR}" \
        --meshd-bin "${MESHD_BIN}" \
        --config "${config}" \
        --status-file "${status_file}" \
        --session-prefix "${session_prefix}" \
        --status-interval-ms "${STATUS_INTERVAL_MS}" \
        --start-wait-secs "${START_WAIT_SECS}" \
        --status-lines "${STATUS_LINES}"
}

verify_pair_status() {
    python3 - "${BOOTSTRAP_STATUS_FILE}" "${JOINER_STATUS_FILE}" <<'PY'
import json
import sys
import time

bootstrap_path = sys.argv[1]
joiner_path = sys.argv[2]

with open(bootstrap_path, "r", encoding="utf-8") as f:
    bootstrap = json.load(f)
with open(joiner_path, "r", encoding="utf-8") as f:
    joiner = json.load(f)

def require(cond, msg):
    if not cond:
        raise SystemExit(msg)

require(bootstrap.get("snapshot_version") == 1, "bootstrap snapshot_version mismatch")
require(joiner.get("snapshot_version") == 1, "joiner snapshot_version mismatch")
require((bootstrap.get("mesh") or {}).get("direct_peers", 0) >= 1, "bootstrap direct_peers < 1")
require((joiner.get("mesh") or {}).get("direct_peers", 0) >= 1, "joiner direct_peers < 1")

bootstrap_peers = bootstrap.get("direct_peers") or []
joiner_peers = joiner.get("direct_peers") or []
bootstrap_node = bootstrap.get("node") or {}
joiner_node = joiner.get("node") or {}

require(bootstrap_node.get("node_id"), "bootstrap missing node.node_id")
require(joiner_node.get("node_id"), "joiner missing node.node_id")
require(isinstance(bootstrap_node.get("protocol_major"), int), "bootstrap missing node.protocol_major")
require(isinstance(bootstrap_node.get("protocol_minor"), int), "bootstrap missing node.protocol_minor")
require(isinstance(joiner_node.get("protocol_major"), int), "joiner missing node.protocol_major")
require(isinstance(joiner_node.get("protocol_minor"), int), "joiner missing node.protocol_minor")

require(any(peer.get("virtual_ip") == "10.42.0.2" and
            peer.get("is_connected") and
            peer.get("node_id") == joiner_node.get("node_id") and
            peer.get("protocol_major") == joiner_node.get("protocol_major") and
            peer.get("protocol_minor") == joiner_node.get("protocol_minor")
            for peer in bootstrap_peers),
        "bootstrap missing connected joiner peer 10.42.0.2")
require(any(peer.get("virtual_ip") == "10.42.0.1" and
            peer.get("is_connected") and
            peer.get("node_id") == bootstrap_node.get("node_id") and
            peer.get("protocol_major") == bootstrap_node.get("protocol_major") and
            peer.get("protocol_minor") == bootstrap_node.get("protocol_minor")
            for peer in joiner_peers),
        "joiner missing connected bootstrap peer 10.42.0.1")

print(f"BOOTSTRAP_HEALTH={(bootstrap.get('control_plane') or {}).get('health', {}).get('state', '')}")
print(f"JOINER_HEALTH={(joiner.get('control_plane') or {}).get('health', {}).get('state', '')}")
print(f"BOOTSTRAP_NODE_ID={bootstrap_node.get('node_id', '')}")
print(f"JOINER_NODE_ID={joiner_node.get('node_id', '')}")
print(f"BOOTSTRAP_PROTOCOL={bootstrap_node.get('protocol_major', '')}.{bootstrap_node.get('protocol_minor', '')}")
print(f"JOINER_PROTOCOL={joiner_node.get('protocol_major', '')}.{joiner_node.get('protocol_minor', '')}")
print(f"BOOTSTRAP_DIRECT={(bootstrap.get('mesh') or {}).get('direct_peers', '')}")
print(f"JOINER_DIRECT={(joiner.get('mesh') or {}).get('direct_peers', '')}")
PY
}

wait_for_connection() {
    local deadline
    deadline=$(( $(date +%s) + CONNECT_WAIT_SECS ))

    while [[ $(date +%s) -lt ${deadline} ]]; do
        if [[ -f "${BOOTSTRAP_STATUS_FILE}" && -f "${JOINER_STATUS_FILE}" ]]; then
            if verify_pair_status >/tmp/meshd-pair-verify.out 2>/tmp/meshd-pair-verify.err; then
                cat /tmp/meshd-pair-verify.out
                rm -f /tmp/meshd-pair-verify.out /tmp/meshd-pair-verify.err
                return 0
            fi
        fi

        sleep "${CONNECT_POLL_SECS}"
    done

    if [[ -f /tmp/meshd-pair-verify.err ]]; then
        cat /tmp/meshd-pair-verify.err >&2
    fi
    rm -f /tmp/meshd-pair-verify.out /tmp/meshd-pair-verify.err
    fail "pair connectivity did not converge within ${CONNECT_WAIT_SECS}s"
}

print_pair_status() {
    echo "== bootstrap =="
    run_single status "${BOOTSTRAP_CONFIG}" "${BOOTSTRAP_STATUS_FILE}" "${BOOTSTRAP_SESSION_PREFIX}"
    echo "== joiner =="
    run_single status "${JOINER_CONFIG}" "${JOINER_STATUS_FILE}" "${JOINER_SESSION_PREFIX}"
}

print_pair_logs() {
    echo "== bootstrap logs =="
    run_single logs "${BOOTSTRAP_CONFIG}" "${BOOTSTRAP_STATUS_FILE}" "${BOOTSTRAP_SESSION_PREFIX}"
    echo "== joiner logs =="
    run_single logs "${JOINER_CONFIG}" "${JOINER_STATUS_FILE}" "${JOINER_SESSION_PREFIX}"
}

stop_pair() {
    run_single stop "${JOINER_CONFIG}" "${JOINER_STATUS_FILE}" "${JOINER_SESSION_PREFIX}" || true
    run_single stop "${BOOTSTRAP_CONFIG}" "${BOOTSTRAP_STATUS_FILE}" "${BOOTSTRAP_SESSION_PREFIX}" || true
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --action)
            [[ $# -ge 2 ]] || fail "--action requires a value"
            ACTION="$2"
            shift 2
            ;;
        --repo-dir)
            [[ $# -ge 2 ]] || fail "--repo-dir requires a value"
            REPO_DIR="$2"
            shift 2
            ;;
        --meshd-bin)
            [[ $# -ge 2 ]] || fail "--meshd-bin requires a value"
            MESHD_BIN="$2"
            shift 2
            ;;
        --bootstrap-config)
            [[ $# -ge 2 ]] || fail "--bootstrap-config requires a value"
            BOOTSTRAP_CONFIG="$2"
            shift 2
            ;;
        --joiner-config)
            [[ $# -ge 2 ]] || fail "--joiner-config requires a value"
            JOINER_CONFIG="$2"
            shift 2
            ;;
        --connect-wait-secs)
            [[ $# -ge 2 ]] || fail "--connect-wait-secs requires a value"
            CONNECT_WAIT_SECS="$2"
            shift 2
            ;;
        --connect-poll-secs)
            [[ $# -ge 2 ]] || fail "--connect-poll-secs requires a value"
            CONNECT_POLL_SECS="$2"
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

require_cmd python3

case "$ACTION" in
    run)
        stop_pair
        run_single start "${BOOTSTRAP_CONFIG}" "${BOOTSTRAP_STATUS_FILE}" "${BOOTSTRAP_SESSION_PREFIX}"
        run_single start "${JOINER_CONFIG}" "${JOINER_STATUS_FILE}" "${JOINER_SESSION_PREFIX}"
        wait_for_connection
        stop_pair
        ;;
    status)
        print_pair_status
        ;;
    logs)
        print_pair_logs
        ;;
    stop)
        stop_pair
        ;;
    *)
        fail "invalid action: ${ACTION}"
        ;;
esac
