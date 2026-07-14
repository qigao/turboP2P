#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/public_stun_harness.sh"

BIN_DIR="${1:-/root/code/turbo-p2p/build/linux-gcc-debug/bin}"
STUN_URL="${STUN_URL:-stun:161.97.65.129:3479}"
ADVERTISE_IP="${ADVERTISE_IP:-161.97.65.129}"
WORKDIR="${WORKDIR:-/tmp/mesh-eu-public-stun-2node}"

NODE1_PORT=11193
NODE2_PORT=11194

NODE1_SESSION="mesh-eu-stun-a"
NODE2_SESSION="mesh-eu-stun-b"
SESSION_NAMES=("$NODE1_SESSION" "$NODE2_SESSION")

trap cleanup_sessions EXIT

[[ -x "${BIN_DIR}/meshctl" ]] || fail "meshctl not found in ${BIN_DIR}"

mkdir -p "$WORKDIR"
cleanup_sessions

write_config "${WORKDIR}/node1.yaml" "10.42.21.1" "${NODE1_PORT}"
write_config "${WORKDIR}/node2.yaml" "10.42.21.2" "${NODE2_PORT}" "127.0.0.1:${NODE1_PORT}"
doctor_config "${WORKDIR}/node1.yaml"
doctor_config "${WORKDIR}/node2.yaml"

tmux new-session -d -s "$NODE1_SESSION" "cd \"${BIN_DIR}\" && ./meshctl up -c \"${WORKDIR}/node1.yaml\""
tmux set-option -t "$NODE1_SESSION" remain-on-exit on >/dev/null
sleep 2
tmux new-session -d -s "$NODE2_SESSION" "cd \"${BIN_DIR}\" && ./meshctl up -c \"${WORKDIR}/node2.yaml\""
tmux set-option -t "$NODE2_SESSION" remain-on-exit on >/dev/null

wait_for_pattern "$NODE2_SESSION" "Updated peer virtual IP to: 10.42.21.1" 20 1 ||
    fail "node2 never connected to node1"

send_cmd "$NODE2_SESSION" "ping 10.42.21.1"
wait_for_pattern "$NODE2_SESSION" "[ping] reply seq=1 from 10.42.21.1" 30 1 ||
    fail "node2 never received ping reply from node1"

wait_for_fragment_with_refresh "$NODE1_SESSION" '"path_mode":"direct-only"' 40 1 ||
    fail "node1 did not switch to direct-only"
wait_for_fragment_with_refresh "$NODE2_SESSION" '"path_mode":"direct-only"' 40 1 ||
    fail "node2 did not switch to direct-only"
wait_for_fragment_with_refresh "$NODE1_SESSION" "\"last_selected_local_endpoint\":\"${ADVERTISE_IP}:" 40 1 ||
    fail "node1 did not record a public selected local ICE endpoint"
wait_for_fragment_with_refresh "$NODE1_SESSION" "\"last_selected_remote_endpoint\":\"${ADVERTISE_IP}:" 40 1 ||
    fail "node1 did not record a public selected remote ICE endpoint"
wait_for_fragment_with_refresh "$NODE2_SESSION" "\"last_selected_local_endpoint\":\"${ADVERTISE_IP}:" 40 1 ||
    fail "node2 did not record a public selected local ICE endpoint"
wait_for_fragment_with_refresh "$NODE2_SESSION" "\"last_selected_remote_endpoint\":\"${ADVERTISE_IP}:" 40 1 ||
    fail "node2 did not record a public selected remote ICE endpoint"

assert_public_ice_direct_only "$NODE1_SESSION" "10.42.21.2" "${ADVERTISE_IP}:"
assert_public_ice_direct_only "$NODE2_SESSION" "10.42.21.1" "${ADVERTISE_IP}:"

echo "[PASS] public STUN direct 2-node regression passed"
