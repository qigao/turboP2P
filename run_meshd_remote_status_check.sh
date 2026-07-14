#!/usr/bin/env bash
set -euo pipefail

ACTION="run"
REPO_DIR="${REPO_DIR:-/root/code/turbo-p2p}"
MESHD_BIN="${MESHD_BIN:-/root/code/turbo-p2p/build/linux-gcc-release/bin/meshd}"
CONFIG_PATH="${CONFIG_PATH:-/root/code/turbo-p2p/mesh/examples/mesh.eu.yaml}"
STATUS_FILE="${STATUS_FILE:-/tmp/meshd-status.json}"
LOG_OUT="${LOG_OUT:-/tmp/meshd-status.out}"
LOG_ERR="${LOG_ERR:-/tmp/meshd-status.err}"
SESSION_PREFIX="${SESSION_PREFIX:-turbonet-meshd}"
STATUS_INTERVAL_MS="${STATUS_INTERVAL_MS:-200}"
START_WAIT_SECS="${START_WAIT_SECS:-3}"
STATUS_LINES="${STATUS_LINES:-80}"
DOCTOR_BEFORE_START="${DOCTOR_BEFORE_START:-1}"
LD_LIBRARY_PATH_VALUE="${LD_LIBRARY_PATH_VALUE:-/root/code/turbo-p2p/build/linux-gcc-release/bin:/root/code/turbonet/build/linux-gcc-release/bin:/opt/turbonet/lib}"

fail() {
    echo "[FAIL] $*" >&2
    exit 1
}

usage() {
    cat <<EOF
Usage:
  $(basename "$0") [--action run|start|status|logs|verify|stop]
                   [--repo-dir <dir>]
                   [--meshd-bin <path>]
                   [--config <path>]
                   [--status-file <path>]
                   [--status-interval-ms <ms>]
                   [--start-wait-secs <n>]
                   [--session-prefix <prefix>]
                   [--status-lines <n>]
                   [--doctor-before-start 0|1]

Examples:
  $(basename "$0")
  $(basename "$0") --action start
  $(basename "$0") --action verify
  $(basename "$0") --config /root/code/turbo-p2p/mesh/examples/mesh.local.yaml
EOF
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

session_name() {
    printf "%s-status" "$SESSION_PREFIX"
}

build_run_command() {
    local cmd=(
        env "LD_LIBRARY_PATH=${LD_LIBRARY_PATH_VALUE}"
        "$MESHD_BIN"
        run
        -c "$CONFIG_PATH"
        --status-file "$STATUS_FILE"
        --status-interval-ms "$STATUS_INTERVAL_MS"
    )

    printf 'cd %q && rm -f %q %q %q && ' "$REPO_DIR" "$STATUS_FILE" "$LOG_OUT" "$LOG_ERR"
    printf '%q ' "${cmd[@]}"
    printf '>%q 2>%q' "$LOG_OUT" "$LOG_ERR"
}

run_doctor() {
    local cmd=(
        env "LD_LIBRARY_PATH=${LD_LIBRARY_PATH_VALUE}"
        "$MESHD_BIN"
        doctor
        -c "$CONFIG_PATH"
    )

    printf '[INFO] doctor: '
    printf '%q ' "${cmd[@]}"
    printf '\n'
    "${cmd[@]}"
}

print_json_summary() {
    python3 - "$STATUS_FILE" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    obj = json.load(f)

print(f"snapshot_version: {obj.get('snapshot_version')}")
print(f"node: {obj.get('node', {}).get('name', '')}")
print(f"node_id: {obj.get('node', {}).get('node_id', '')}")
print(f"protocol: {obj.get('node', {}).get('protocol_major', '')}.{obj.get('node', {}).get('protocol_minor', '')}")
print(f"health: {obj.get('control_plane', {}).get('health', {}).get('state', '')}")
print(f"dht_entries: {obj.get('control_plane', {}).get('summary', {}).get('dht_entries', '')}")
print(f"tunnel_rx_packets: {obj.get('tunnel', {}).get('rx_packets', '')}")
PY
}

verify_status_file() {
    [[ -f "$STATUS_FILE" ]] || fail "status file not found: ${STATUS_FILE}"

    python3 - "$STATUS_FILE" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    obj = json.load(f)

if obj.get("snapshot_version") != 1:
    raise SystemExit("snapshot_version mismatch")

node = obj.get("node") or {}
runtime = obj.get("runtime") or {}
control_plane = obj.get("control_plane") or {}
summary = control_plane.get("summary") or {}
health = control_plane.get("health") or {}
dht = control_plane.get("dht") or {}
diagnostics = control_plane.get("diagnostics") or {}
tunnel = obj.get("tunnel") or {}

if not node.get("name"):
    raise SystemExit("missing node.name")
if not node.get("node_id"):
    raise SystemExit("missing node.node_id")
if not isinstance(node.get("protocol_major"), int):
    raise SystemExit("node.protocol_major is not an int")
if not isinstance(node.get("protocol_minor"), int):
    raise SystemExit("node.protocol_minor is not an int")
if runtime.get("running") is not True:
    raise SystemExit("runtime.running is not true")
if not all(k in control_plane for k in ("summary", "health", "dht", "diagnostics")):
    raise SystemExit("control_plane sections are incomplete")
if not isinstance(summary.get("dht_entries"), int):
    raise SystemExit("control_plane.summary.dht_entries is not an int")
if not health.get("state"):
    raise SystemExit("control_plane.health.state is missing")
if not isinstance(dht.get("entry_count"), int):
    raise SystemExit("control_plane.dht.entry_count is not an int")
if not isinstance(tunnel.get("rx_packets"), int):
    raise SystemExit("tunnel.rx_packets is not an int")
if not isinstance(diagnostics.get("control_plane_refreshes"), int):
    raise SystemExit("control_plane.diagnostics.control_plane_refreshes is not an int")

print(f"VERSION={obj['snapshot_version']}")
print(f"NODE={node['name']}")
print(f"NODE_ID={node['node_id']}")
print(f"NODE_PROTOCOL={node['protocol_major']}.{node['protocol_minor']}")
print(f"CP_HEALTH={health['state']}")
print(f"CP_DHT={summary['dht_entries']}")
print(f"TUNNEL_RX={tunnel['rx_packets']}")
PY
}

print_status() {
    local session
    session="$(session_name)"

    echo "session: ${session}"
    echo "meshd_bin: ${MESHD_BIN}"
    echo "config: ${CONFIG_PATH}"
    echo "status_file: ${STATUS_FILE}"
    echo "log_out: ${LOG_OUT}"
    echo "log_err: ${LOG_ERR}"

    if tmux has-session -t "$session" 2>/dev/null; then
        echo "state: running"
    else
        echo "state: stopped"
    fi

    if [[ -f "$STATUS_FILE" ]]; then
        echo "----- parsed status -----"
        print_json_summary
    fi
}

print_logs() {
    local session
    session="$(session_name)"

    if tmux has-session -t "$session" 2>/dev/null; then
        echo "----- tmux pane -----"
        tmux capture-pane -J -pt "$session" -S "-${STATUS_LINES}" || true
    fi

    if [[ -f "$LOG_OUT" ]]; then
        echo "----- stdout -----"
        tail -n "$STATUS_LINES" "$LOG_OUT"
    fi

    if [[ -f "$LOG_ERR" ]]; then
        echo "----- stderr -----"
        tail -n "$STATUS_LINES" "$LOG_ERR"
    fi
}

start_session() {
    local session
    session="$(session_name)"

    [[ -x "$MESHD_BIN" ]] || fail "meshd binary not found: ${MESHD_BIN}"
    [[ -f "$CONFIG_PATH" ]] || fail "config not found: ${CONFIG_PATH}"

    if [[ "$DOCTOR_BEFORE_START" == "1" ]]; then
        run_doctor
    fi

    tmux kill-session -t "$session" 2>/dev/null || true
    tmux new-session -d -s "$session" "$(build_run_command)"
    tmux set-option -t "$session" remain-on-exit on >/dev/null
}

stop_session() {
    tmux kill-session -t "$(session_name)" 2>/dev/null || true
    echo "[PASS] stopped $(session_name)"
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
        --config)
            [[ $# -ge 2 ]] || fail "--config requires a value"
            CONFIG_PATH="$2"
            shift 2
            ;;
        --status-file)
            [[ $# -ge 2 ]] || fail "--status-file requires a value"
            STATUS_FILE="$2"
            shift 2
            ;;
        --status-interval-ms)
            [[ $# -ge 2 ]] || fail "--status-interval-ms requires a value"
            STATUS_INTERVAL_MS="$2"
            shift 2
            ;;
        --start-wait-secs)
            [[ $# -ge 2 ]] || fail "--start-wait-secs requires a value"
            START_WAIT_SECS="$2"
            shift 2
            ;;
        --session-prefix)
            [[ $# -ge 2 ]] || fail "--session-prefix requires a value"
            SESSION_PREFIX="$2"
            shift 2
            ;;
        --status-lines)
            [[ $# -ge 2 ]] || fail "--status-lines requires a value"
            STATUS_LINES="$2"
            shift 2
            ;;
        --doctor-before-start)
            [[ $# -ge 2 ]] || fail "--doctor-before-start requires a value"
            DOCTOR_BEFORE_START="$2"
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

require_cmd tmux
require_cmd python3

case "$ACTION" in
    run)
        start_session
        sleep "$START_WAIT_SECS"
        verify_status_file
        stop_session
        ;;
    start)
        start_session
        sleep "$START_WAIT_SECS"
        print_status
        ;;
    status)
        print_status
        ;;
    logs)
        print_logs
        ;;
    verify)
        verify_status_file
        ;;
    stop)
        stop_session
        ;;
    *)
        fail "invalid action: ${ACTION}"
        ;;
esac
