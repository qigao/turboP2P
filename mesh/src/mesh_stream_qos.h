#ifndef TURBO_P2P_MESH_STREAM_QOS_H
#define TURBO_P2P_MESH_STREAM_QOS_H

#include "mesh_flow_ruleset.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* P6: per-peer stream QoS. Tracks chunk/byte statistics with a sliding-window
 * bandwidth estimate (EWMA) and gates transfers through a mesh_flow_ruleset
 * decision: a deny decision rejects the peer with MESH_STREAM_QOS_DENIED. The
 * ruleset is borrowed (NULL = allow all). */

#define MESH_STREAM_QOS_IDENTITY_SIZE MESH_FLOW_RULESET_IDENTITY_SIZE
#define MESH_STREAM_QOS_PEERS_MAX 16u
#define MESH_STREAM_QOS_DEFAULT_WINDOW_MS 1000u
#define MESH_STREAM_QOS_RATE_ALPHA 4u /* EWMA divisor */

typedef enum {
  MESH_STREAM_QOS_OK = 0,
  MESH_STREAM_QOS_INVALID_ARG = -1,
  MESH_STREAM_QOS_RESOURCE_EXHAUSTED = -2,
  MESH_STREAM_QOS_DENIED = -3,
  MESH_STREAM_QOS_NOT_FOUND = -4,
} mesh_stream_qos_result_t;

typedef struct {
  uint8_t peer_identity[MESH_STREAM_QOS_IDENTITY_SIZE];
  uint64_t bytes_total;
  uint64_t chunks_total;
  uint64_t bytes_window;   /* bytes in the current window */
  uint64_t window_start_ms;
  uint64_t rate_bps;       /* EWMA of bytes per second (bits) */
  uint64_t last_activity_ms;
} mesh_stream_qos_peer_v1_t;

typedef struct {
  mesh_stream_qos_peer_v1_t peers[MESH_STREAM_QOS_PEERS_MAX];
  size_t count;
  uint64_t window_ms;
  mesh_flow_ruleset_v1_t *ruleset; /* borrowed; NULL = allow all */
} mesh_stream_qos_v1_t;

/** Zero-initialize qos, set the sliding window length and borrow a ruleset. */
mesh_stream_qos_result_t mesh_stream_qos_init_v1(
    mesh_stream_qos_v1_t *qos, uint64_t window_ms,
    mesh_flow_ruleset_v1_t *ruleset);

/**
 * Gate a stream transfer from a peer in `direction` (a mesh_flow_direction
 * bit). peer_identity is carried for audit; peer_virtual_ip is the peer's
 * virtual address from its service record and is what the flow rules match
 * on. A deny decision returns MESH_STREAM_QOS_DENIED; with no ruleset every
 * peer is admitted.
 */
mesh_stream_qos_result_t mesh_stream_qos_admit_v1(
    mesh_stream_qos_v1_t *qos, const uint8_t peer_identity[32],
    uint32_t peer_virtual_ip, uint32_t direction);

/** Account one transferred chunk of `bytes` with the peer at now_ms. */
mesh_stream_qos_result_t mesh_stream_qos_account_v1(
    mesh_stream_qos_v1_t *qos, const uint8_t peer_identity[32],
    uint64_t bytes, uint64_t now_ms);

/** Copy the peer's statistics (totals + current rate estimate). */
mesh_stream_qos_result_t mesh_stream_qos_peer_stats_v1(
    const mesh_stream_qos_v1_t *qos, const uint8_t peer_identity[32],
    mesh_stream_qos_peer_v1_t *out_stats);

/** Aggregate chunk/byte statistics across all peers. */
void mesh_stream_qos_total_v1(const mesh_stream_qos_v1_t *qos,
                              uint64_t *out_bytes, uint64_t *out_chunks);

#ifdef __cplusplus
}
#endif

#endif