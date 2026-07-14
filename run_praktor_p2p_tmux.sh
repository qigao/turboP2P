#!/usr/bin/env bash
set -euo pipefail

ACTION="start"
MODE="full"
REPO_DIR="${REPO_DIR:-/root/code/turbo-p2p}"
PRAKTOR_BIN="${PRAKTOR_BIN:-/root/code/praktor/build/linux-gcc-release/bin/praktor}"
LD_LIBRARY_PATH_VALUE="${LD_LIBRARY_PATH_VALUE:-/opt/turbonet/lib}"
SESSION_PREFIX="${SESSION_PREFIX:-turbop2p-praktor}"
LOG_DIR="${LOG_DIR:-/tmp}"
STATUS_LINES="${STATUS_LINES:-120}"
WAIT_POLL_SECS="${WAIT_POLL_SECS:-2}"
WAIT_STALE_POLLS="${WAIT_STALE_POLLS:-3}"
COLOR_ARGS=(--color never)
VAR_OVERRIDES=()

fail() {
    echo "[FAIL] $*" >&2
    exit 1
}

usage() {
    cat <<EOF
Usage:
  $(basename "$0") [--action start|status|logs|wait|stop]
                   [--mode full|smoke]
                   [--repo-dir <dir>]
                   [--praktor-bin <path>]
                   [--log-dir <dir>]
                   [--session-prefix <prefix>]
                   [--status-lines <n>]
                   [--wait-poll-secs <n>]
                   [--var KEY=VALUE]...

Examples:
  $(basename "$0") --mode smoke
  $(basename "$0") --action wait --mode full
  $(basename "$0") --mode full --var CTEST_ARGS='-R ^test_mesh_paths$'
EOF
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

resolve_workflow_path() {
    case "$MODE" in
        full) printf "%s/praktor_p2p_ci.yml" "$REPO_DIR" ;;
        smoke) printf "%s/praktor_p2p_smoke_ci.yml" "$REPO_DIR" ;;
        *) fail "invalid mode: $MODE" ;;
    esac
}

session_name() {
    printf "%s-%s" "$SESSION_PREFIX" "$MODE"
}

log_path() {
    printf "%s/%s-%s.log" "$LOG_DIR" "$SESSION_PREFIX" "$MODE"
}

build_tmux_command() {
    local workflow_path="$1"
    local cmd=(
        env "LD_LIBRARY_PATH=${LD_LIBRARY_PATH_VALUE}"
        "$PRAKTOR_BIN"
        -f "$workflow_path"
        "${COLOR_ARGS[@]}"
    )
    local override

    for override in "${VAR_OVERRIDES[@]}"; do
        cmd+=(-i "$override")
    done

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
    local workflow_path="$2"
    local log_file

    log_file="$(log_path)"
    echo "mode: ${MODE}"
    echo "workflow: ${workflow_path}"
    echo "session: ${session}"
    echo "log: ${log_file}"

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
            if grep -Fq "[workflow] SUCCESS" "$log_file"; then
                tail -n "$STATUS_LINES" "$log_file"
                echo "[PASS] workflow succeeded"
                return 0
            fi

            if grep -Fq "[workflow] FAILED" "$log_file"; then
                tail -n "$STATUS_LINES" "$log_file"
                fail "workflow failed"
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
            fail "workflow finished without explicit success/failure marker"
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
        --mode)
            [[ $# -ge 2 ]] || fail "--mode requires a value"
            MODE="$2"
            shift 2
            ;;
        --repo-dir)
            [[ $# -ge 2 ]] || fail "--repo-dir requires a value"
            REPO_DIR="$2"
            shift 2
            ;;
        --praktor-bin)
            [[ $# -ge 2 ]] || fail "--praktor-bin requires a value"
            PRAKTOR_BIN="$2"
            shift 2
            ;;
        --log-dir)
            [[ $# -ge 2 ]] || fail "--log-dir requires a value"
            LOG_DIR="$2"
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
        --var)
            [[ $# -ge 2 ]] || fail "--var requires KEY=VALUE"
            VAR_OVERRIDES+=("$2")
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
workflow_path="$(resolve_workflow_path)"
session="$(session_name)"
log_file="$(log_path)"

case "$ACTION" in
    start)
        [[ -x "$PRAKTOR_BIN" ]] || fail "praktor binary not found: ${PRAKTOR_BIN}"
        [[ -f "$workflow_path" ]] || fail "workflow not found: ${workflow_path}"
        mkdir -p "$LOG_DIR"
        tmux kill-session -t "$session" 2>/dev/null || true
        tmux new-session -d -s "$session" "$(build_tmux_command "$workflow_path")"
        tmux set-option -t "$session" remain-on-exit on >/dev/null
        print_status "$session" "$workflow_path"
        ;;
    status)
        print_status "$session" "$workflow_path"
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
