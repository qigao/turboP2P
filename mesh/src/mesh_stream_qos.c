#include "mesh_stream_qos.h"

#include <string.h>

/* P6: per-peer QoS. Bandwidth is estimated over a sliding window: when the
 * window elapses the collected bytes are converted to an instantaneous
 * bitrate (bytes * 8 * 1000 / window_ms) and folded into an EWMA. Admission
 * delegates to the borrowed mesh_flow_ruleset with a zeroed L3/L4 tuple so
 * rules keyed on peer identity + direction apply. */

static mesh_stream_qos_peer_v1_t *find_or_create(mesh_stream_qos_v1_t *qos,
                                                 const uint8_t *peer_identity) {
  for (size_t i = 0u; i < qos->count; i++) {
    if (memcmp(qos->peers[i].peer_identity, peer_identity,
               MESH_STREAM_QOS_IDENTITY_SIZE) == 0) {
      return &qos->peers[i];
    }
  }
  if (qos->count >= MESH_STREAM_QOS_PEERS_MAX)
    return NULL;
  {
    mesh_stream_qos_peer_v1_t *peer = &qos->peers[qos->count];

    memset(peer, 0, sizeof(*peer));
    memcpy(peer->peer_identity, peer_identity, MESH_STREAM_QOS_IDENTITY_SIZE);
    peer->window_start_ms = UINT64_MAX; /* sentinel: no window started yet */
    qos->count++;
    return peer;
  }
}

mesh_stream_qos_result_t mesh_stream_qos_init_v1(
    mesh_stream_qos_v1_t *qos, uint64_t window_ms,
    mesh_flow_ruleset_v1_t *ruleset) {
  if (!qos || window_ms == 0u)
    return MESH_STREAM_QOS_INVALID_ARG;
  memset(qos, 0, sizeof(*qos));
  qos->window_ms = window_ms;
  qos->ruleset = ruleset;
  return MESH_STREAM_QOS_OK;
}

mesh_stream_qos_result_t mesh_stream_qos_admit_v1(
    mesh_stream_qos_v1_t *qos, const uint8_t peer_identity[32],
    uint32_t peer_virtual_ip, uint32_t direction) {
  if (!qos || !peer_identity)
    return MESH_STREAM_QOS_INVALID_ARG;
  if (qos->ruleset) {
    mesh_flow_query_v1_t query;
    mesh_flow_decision_v1_t decision;

    memset(&query, 0, sizeof(query));
    query.src_ip = peer_virtual_ip; /* flow rules match the peer virtual IP */
    query.direction = direction;
    query.ip_proto = 0u;
    query.has_ports = 0u;
    memcpy(query.peer_identity, peer_identity, sizeof(query.peer_identity));
    if (mesh_flow_ruleset_evaluate_v1(qos->ruleset, &query, &decision) !=
        MESH_FLOW_RULESET_OK) {
      return MESH_STREAM_QOS_INVALID_ARG;
    }
    if (decision.action == MESH_FLOW_ACTION_DENY)
      return MESH_STREAM_QOS_DENIED;
  }
  return MESH_STREAM_QOS_OK;
}

mesh_stream_qos_result_t mesh_stream_qos_account_v1(
    mesh_stream_qos_v1_t *qos, const uint8_t peer_identity[32],
    uint64_t bytes, uint64_t now_ms) {
  mesh_stream_qos_peer_v1_t *peer;
  uint64_t elapsed;

  if (!qos || !peer_identity)
    return MESH_STREAM_QOS_INVALID_ARG;
  peer = find_or_create(qos, peer_identity);
  if (!peer)
    return MESH_STREAM_QOS_RESOURCE_EXHAUSTED;
  if (peer->window_start_ms == UINT64_MAX) {
    peer->window_start_ms = now_ms;
  } else if (now_ms >= peer->window_start_ms) {
    elapsed = now_ms - peer->window_start_ms;
    if (elapsed >= qos->window_ms) {
      uint64_t instant_bps =
          peer->bytes_window * 8000u / qos->window_ms;

      if (peer->rate_bps == 0u) {
        peer->rate_bps = instant_bps;
      } else {
        peer->rate_bps = peer->rate_bps -
                         peer->rate_bps / MESH_STREAM_QOS_RATE_ALPHA +
                         instant_bps / MESH_STREAM_QOS_RATE_ALPHA;
      }
      peer->bytes_window = 0u;
      peer->window_start_ms = now_ms;
    }
  }
  peer->bytes_window += bytes;
  peer->bytes_total += bytes;
  peer->chunks_total++;
  peer->last_activity_ms = now_ms;
  return MESH_STREAM_QOS_OK;
}

mesh_stream_qos_result_t mesh_stream_qos_peer_stats_v1(
    const mesh_stream_qos_v1_t *qos, const uint8_t peer_identity[32],
    mesh_stream_qos_peer_v1_t *out_stats) {
  if (!qos || !peer_identity || !out_stats)
    return MESH_STREAM_QOS_INVALID_ARG;
  for (size_t i = 0u; i < qos->count; i++) {
    if (memcmp(qos->peers[i].peer_identity, peer_identity,
               MESH_STREAM_QOS_IDENTITY_SIZE) == 0) {
      *out_stats = qos->peers[i];
      return MESH_STREAM_QOS_OK;
    }
  }
  return MESH_STREAM_QOS_NOT_FOUND;
}

void mesh_stream_qos_total_v1(const mesh_stream_qos_v1_t *qos,
                              uint64_t *out_bytes, uint64_t *out_chunks) {
  uint64_t bytes = 0u;
  uint64_t chunks = 0u;

  if (!qos)
    return;
  for (size_t i = 0u; i < qos->count; i++) {
    bytes += qos->peers[i].bytes_total;
    chunks += qos->peers[i].chunks_total;
  }
  if (out_bytes)
    *out_bytes = bytes;
  if (out_chunks)
    *out_chunks = chunks;
}