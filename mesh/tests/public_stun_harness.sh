#!/usr/bin/env bash

fail() {
    echo "[FAIL] $*" >&2
    dump_logs >&2 || true
    exit 1
}

cleanup_sessions() {
    local session

    for session in "${SESSION_NAMES[@]}"; do
        tmux kill-session -t "$session" 2>/dev/null || true
    done
}

capture_session() {
    local session="$1"

    if tmux has-session -t "$session" 2>/dev/null; then
        tmux capture-pane -J -pt "$session" -S -240
        return 0
    fi

    return 1
}

dump_logs() {
    local session

    for session in "${SESSION_NAMES[@]}"; do
        echo "===== ${session} ====="
        capture_session "$session" 2>/dev/null || true
        echo
    done
}

send_cmd() {
    local session="$1"
    local command="$2"

    tmux send-keys -t "$session" "$command" C-m
}

wait_for_pattern() {
    local session="$1"
    local pattern="$2"
    local retries="${3:-80}"
    local sleep_secs="${4:-1}"

    for ((i = 0; i < retries; i++)); do
        if capture_session "$session" | grep -Fq "$pattern"; then
            return 0
        fi
        sleep "$sleep_secs"
    done

    return 1
}

refresh_state() {
    local session="$1"

    send_cmd "$session" "status json"
    send_cmd "$session" "diag json"
    send_cmd "$session" "peers json"
}

wait_for_fragment_with_refresh() {
    local session="$1"
    local fragment="$2"
    local retries="${3:-30}"
    local sleep_secs="${4:-1}"
    local log

    for ((i = 0; i < retries; i++)); do
        refresh_state "$session"
        sleep "$sleep_secs"
        log="$(capture_session "$session")"
        if grep -Fq "$fragment" <<<"$log"; then
            return 0
        fi
    done

    return 1
}

write_config() {
    local path="$1"
    local vip="$2"
    local port="$3"
    local bootstrap="${4:-}"
    local meshctl_bin="${BIN_DIR}/meshctl"
    local node_name
    local init_args=()

    [[ -x "$meshctl_bin" ]] || fail "meshctl not found in ${BIN_DIR}"

    node_name="$(basename "$path" .yaml)"
    init_args=(-o "$path"
               --node-name "$node_name"
               --virtual-ip "$vip"
               --listen-port "$port"
               --advertise-ip "$ADVERTISE_IP"
               --stun "$STUN_URL")

    if [[ -n "$bootstrap" ]]; then
        init_args+=(--bootstrap "$bootstrap")
    fi

    "$meshctl_bin" init "${init_args[@]}" >/dev/null ||
        fail "failed to generate config ${path} with meshctl init"
}

doctor_config() {
    local path="$1"
    local meshctl_bin="${BIN_DIR}/meshctl"

    [[ -x "$meshctl_bin" ]] || fail "meshctl not found in ${BIN_DIR}"
    "$meshctl_bin" doctor -c "$path" >/dev/null ||
        fail "meshctl doctor failed for ${path}"
}

assert_public_ice_direct_only() {
    local session="$1"
    local peer_vip="$2"
    local expected_endpoint_prefix="$3"
    local log

    refresh_state "$session"
    sleep 1
    log="$(capture_session "$session")"
    grep -F '"path_mode":"direct-only"' <<<"$log" >/dev/null ||
        fail "${session} did not converge to direct-only"
    grep -F '"relay_routes":0' <<<"$log" >/dev/null ||
        fail "${session} still has relay routes"
    grep -F "\"virtual_ip\":\"${peer_vip}\"" <<<"$log" | grep -F '"state":"connected"' >/dev/null ||
        fail "${session} peer ${peer_vip} is not connected"
    grep -F "\"last_selected_local_endpoint\":\"${expected_endpoint_prefix}" <<<"$log" >/dev/null ||
        fail "${session} did not select a public local ICE endpoint"
    grep -F "\"last_selected_remote_endpoint\":\"${expected_endpoint_prefix}" <<<"$log" >/dev/null ||
        fail "${session} did not select a public remote ICE endpoint"
}

assert_public_direct_peer_and_ice_direct_only() {
    local session="$1"
    local peer_vip="$2"
    local expected_endpoint_prefix="$3"
    local log

    refresh_state "$session"
    sleep 1
    log="$(capture_session "$session")"
    grep -F '"path_mode":"direct-only"' <<<"$log" >/dev/null ||
        fail "${session} did not converge to direct-only"
    grep -F '"relay_routes":0' <<<"$log" >/dev/null ||
        fail "${session} still has relay routes"
    grep -F "\"virtual_ip\":\"${peer_vip}\",\"real_endpoint\":\"${expected_endpoint_prefix}" <<<"$log" >/dev/null ||
        fail "${session} missing direct peer ${peer_vip} -> ${expected_endpoint_prefix}"
    grep -F "\"virtual_ip\":\"${peer_vip}\",\"real_endpoint\":\"${expected_endpoint_prefix}" <<<"$log" | grep -F '"state":"connected"' >/dev/null ||
        fail "${session} peer ${peer_vip} is not connected"
    grep -F "\"last_selected_local_endpoint\":\"${expected_endpoint_prefix}" <<<"$log" >/dev/null ||
        fail "${session} did not select a public local ICE endpoint"
    grep -F "\"last_selected_remote_endpoint\":\"${expected_endpoint_prefix}" <<<"$log" >/dev/null ||
        fail "${session} did not select a public remote ICE endpoint"
}
