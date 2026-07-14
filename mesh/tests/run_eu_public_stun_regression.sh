#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/public_stun_harness.sh"

BIN_DIR="${1:-/root/code/turbo-p2p/build/linux-gcc-debug/bin}"
STUN_URL="${STUN_URL:-stun:161.97.65.129:3479}"
ADVERTISE_IP="${ADVERTISE_IP:-161.97.65.129}"
WORKDIR="${WORKDIR:-/tmp/mesh-eu-public-stun-regression}"

LEADER_PORT=11293
NODE2_PORT=11294
NODE3_PORT=11295

LEADER_SESSION="mesh-eu-stun-leader"
NODE2_SESSION="mesh-eu-stun-node2"
NODE3_SESSION="mesh-eu-stun-node3"
SESSION_NAMES=("$LEADER_SESSION" "$NODE2_SESSION" "$NODE3_SESSION")

trap cleanup_sessions EXIT

[[ -x "${BIN_DIR}/meshctl" ]] || fail "meshctl not found in ${BIN_DIR}"

mkdir -p "$WORKDIR"
cleanup_sessions

write_config "${WORKDIR}/leader.yaml" "10.42.22.1" "${LEADER_PORT}"
write_config "${WORKDIR}/node2.yaml" "10.42.22.2" "${NODE2_PORT}" "127.0.0.1:${LEADER_PORT}"
write_config "${WORKDIR}/node3.yaml" "10.42.22.3" "${NODE3_PORT}" "127.0.0.1:${LEADER_PORT}"
doctor_config "${WORKDIR}/leader.yaml"
doctor_config "${WORKDIR}/node2.yaml"
doctor_config "${WORKDIR}/node3.yaml"

tmux new-session -d -s "$LEADER_SESSION" "cd \"${BIN_DIR}\" && ./meshctl up -c \"${WORKDIR}/leader.yaml\""
tmux set-option -t "$LEADER_SESSION" remain-on-exit on >/dev/null
sleep 2
tmux new-session -d -s "$NODE2_SESSION" "cd \"${BIN_DIR}\" && ./meshctl up -c \"${WORKDIR}/node2.yaml\""
tmux set-option -t "$NODE2_SESSION" remain-on-exit on >/dev/null
tmux new-session -d -s "$NODE3_SESSION" "cd \"${BIN_DIR}\" && ./meshctl up -c \"${WORKDIR}/node3.yaml\""
tmux set-option -t "$NODE3_SESSION" remain-on-exit on >/dev/null

wait_for_pattern "$NODE2_SESSION" "Updated peer virtual IP to: 10.42.22.1" 20 1 ||
    fail "node2 never connected to leader"
wait_for_pattern "$NODE3_SESSION" "Updated peer virtual IP to: 10.42.22.1" 20 1 ||
    fail "node3 never connected to leader"

send_cmd "$NODE2_SESSION" "status json"
send_cmd "$NODE3_SESSION" "status json"
sleep 2

send_cmd "$NODE2_SESSION" "ping 10.42.22.3"
wait_for_pattern "$NODE2_SESSION" "[ping] reply seq=1 from 10.42.22.3" 30 1 ||
    fail "node2 never received ping reply from node3"

wait_for_fragment_with_refresh "$NODE2_SESSION" '"path_mode":"direct-only"' 40 1 ||
    fail "node2 did not switch to direct-only"
wait_for_fragment_with_refresh "$NODE3_SESSION" '"path_mode":"direct-only"' 40 1 ||
    fail "node3 did not switch to direct-only"

refresh_state "$NODE2_SESSION"
refresh_state "$NODE3_SESSION"
sleep 2

assert_public_direct_peer_and_ice_direct_only "$NODE2_SESSION" "10.42.22.3" "${ADVERTISE_IP}:"
assert_public_direct_peer_and_ice_direct_only "$NODE3_SESSION" "10.42.22.2" "${ADVERTISE_IP}:"

echo "[PASS] public STUN relay-to-direct regression passed"
