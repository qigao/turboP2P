#!/usr/bin/env bash
set -euo pipefail

ACTION="start"
SCENARIO="matrix"
REPO_DIR="${REPO_DIR:-/root/code/turbo-p2p}"
RUNNER="${RUNNER:-/root/code/turbo-p2p/mesh/tests/run_public_stun_suite.sh}"
BIN_DIR="${BIN_DIR:-/root/code/turbo-p2p/build/linux-gcc-release/bin}"
SESSION_PREFIX="${SESSION_PREFIX:-turbop2p-public-stun}"
LOG_DIR="${LOG_DIR:-/tmp}"
WORKDIR_ROOT="${WORKDIR_ROOT:-/tmp/mesh-public-stun-suite}"
STUN_URL="${STUN_URL:-}"
ADVERTISE_IP="${ADVERTISE_IP:-}"
STATUS_LINES="${STATUS_LINES:-120}"
WAIT_POLL_SECS="${WAIT_POLL_SECS:-2}"
WAIT_STALE_POLLS="${WAIT_STALE_POLLS:-3}"

fail() {
    echo "[FAIL] $*" >&2
    exit 1
}

usage() {
    cat <<EOF
Usage:
  $(basename "$0") [--action start|status|logs|wait|stop]
                   [--scenario two-node|three-node|matrix]
                   [--repo-dir <dir>]
                   [--runner <path>]
                   [--bin-dir <dir>]
                   [--session-prefix <prefix>]
                   [--log-dir <dir>]
                   [--workdir-root <dir>]
                   [--stun-url <url>]
                   [--advertise-ip <ip>]
                   [--status-lines <n>]
                   [--wait-poll-secs <n>]

Examples:
  $(basename "$0") --scenario two-node
  $(basename "$0") --action wait --scenario matrix
  $(basename "$0") --scenario three-node --stun-url stun:161.97.65.129:3479
EOF
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

session_name() {
    printf "%s-%s" "$SESSION_PREFIX" "$SCENARIO"
}

log_path() {
    printf "%s/%s-%s.log" "$LOG_DIR" "$SESSION_PREFIX" "$SCENARIO"
}

build_tmux_command() {
    local cmd=(
        bash "$RUNNER"
        --bin-dir "$BIN_DIR"
        --scenario "$SCENARIO"
        --workdir-root "$WORKDIR_ROOT"
    )

    if [[ -n "$STUN_URL" ]]; then
        cmd+=(--stun-url "$STUN_URL")
    fi

    if [[ -n "$ADVERTISE_IP" ]]; then
        cmd+=(--advertise-ip "$ADVERTISE_IP")
    fi

    printf 'cd %q && ' "$REPO_DIR"
    printf '%q ' "${cmd[@]}"
    printf '2>&1 | tee %q' "$(log_path)"
}

capture_session() {
    local session="$1"
    tmux capture-pane -J -pt "$session" -S "-${STATUS_LINES}"
}

print_status() {
    local session="$1"
    local log_file

    log_file="$(log_path)"
    echo "scenario: ${SCENARIO}"
    echo "runner: ${RUNNER}"
    echo "session: ${session}"
    echo "log: ${log_file}"
    echo "workdir_root: ${WORKDIR_ROOT}"

    if tmux has-session -t "$session" 2>/dev/null; then
        echo "state: running"
        echo "----- recent pane -----"
        capture_session "$session" || true
        return 0
    fi

    if [[ -f "$log_file" ]]; then
        echo "state: exited"
        echo "----- recent log -----"
        tail -n "$STATUS_LINES" "$log_file"
        return 0
    fi

    echo "state: not-started"
}

wait_for_finish() {
    local session="$1"
    local log_file
    local last_size=-1
    local stale_polls=0
    local current_size=0

    log_file="$(log_path)"

    while true; do
        if [[ -f "$log_file" ]]; then
            if grep -Fq "[PASS] public STUN suite passed (${SCENARIO})" "$log_file"; then
                tail -n "$STATUS_LINES" "$log_file"
                echo "[PASS] public STUN suite succeeded"
                return 0
            fi

            if grep -Fq "[FAIL]" "$log_file"; then
                tail -n "$STATUS_LINES" "$log_file"
                fail "public STUN suite failed"
            fi
        fi

        if tmux has-session -t "$session" 2>/dev/null; then
            stale_polls=0
            sleep "$WAIT_POLL_SECS"
            continue
        fi

        [[ -f "$log_file" ]] || fail "session exited and log file is missing: ${log_file}"
        current_size=$(wc -c <"$log_file")
        if [[ "$current_size" -eq "$last_size" ]]; then
            stale_polls=$((stale_polls + 1))
        else
            stale_polls=0
            last_size="$current_size"
        fi

        if [[ "$stale_polls" -ge "$WAIT_STALE_POLLS" ]]; then
            tail -n "$STATUS_LINES" "$log_file"
            fail "public STUN suite finished without explicit pass/fail marker"
        fi

        sleep "$WAIT_POLL_SECS"
    done
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --action)
            [[ $# -ge 2 ]] || fail "--action requires a value"
            ACTION="$2"
            shift 2
            ;;
        --scenario)
            [[ $# -ge 2 ]] || fail "--scenario requires a value"
            SCENARIO="$2"
            shift 2
            ;;
        --repo-dir)
            [[ $# -ge 2 ]] || fail "--repo-dir requires a value"
            REPO_DIR="$2"
            shift 2
            ;;
        --runner)
            [[ $# -ge 2 ]] || fail "--runner requires a value"
            RUNNER="$2"
            shift 2
            ;;
        --bin-dir)
            [[ $# -ge 2 ]] || fail "--bin-dir requires a value"
            BIN_DIR="$2"
            shift 2
            ;;
        --session-prefix)
            [[ $# -ge 2 ]] || fail "--session-prefix requires a value"
            SESSION_PREFIX="$2"
            shift 2
            ;;
        --log-dir)
            [[ $# -ge 2 ]] || fail "--log-dir requires a value"
            LOG_DIR="$2"
            shift 2
            ;;
        --workdir-root)
            [[ $# -ge 2 ]] || fail "--workdir-root requires a value"
            WORKDIR_ROOT="$2"
            shift 2
            ;;
        --stun-url)
            [[ $# -ge 2 ]] || fail "--stun-url requires a value"
            STUN_URL="$2"
            shift 2
            ;;
        --advertise-ip)
            [[ $# -ge 2 ]] || fail "--advertise-ip requires a value"
            ADVERTISE_IP="$2"
            shift 2
            ;;
        --status-lines)
            [[ $# -ge 2 ]] || fail "--status-lines requires a value"
            STATUS_LINES="$2"
            shift 2
            ;;
        --wait-poll-secs)
            [[ $# -ge 2 ]] || fail "--wait-poll-secs requires a value"
            WAIT_POLL_SECS="$2"
            shift 2
            ;;
        --wait-stale-polls)
            [[ $# -ge 2 ]] || fail "--wait-stale-polls requires a value"
            WAIT_STALE_POLLS="$2"
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
[[ -x "$RUNNER" ]] || fail "runner not found: ${RUNNER}"
session="$(session_name)"
log_file="$(log_path)"

case "$ACTION" in
    start)
        mkdir -p "$LOG_DIR"
        tmux kill-session -t "$session" 2>/dev/null || true
        tmux new-session -d -s "$session" "$(build_tmux_command)"
        tmux set-option -t "$session" remain-on-exit on >/dev/null
        print_status "$session"
        ;;
    status)
        print_status "$session"
        ;;
    logs)
        if tmux has-session -t "$session" 2>/dev/null; then
            capture_session "$session"
        elif [[ -f "$log_file" ]]; then
            tail -n "$STATUS_LINES" "$log_file"
        else
            fail "no session or log found for ${session}"
        fi
        ;;
    wait)
        wait_for_finish "$session"
        ;;
    stop)
        tmux kill-session -t "$session" 2>/dev/null || true
        echo "[PASS] stopped ${session}"
        ;;
    *)
        fail "invalid action: ${ACTION}"
        ;;
esac
