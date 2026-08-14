#ifndef MESH_NODE_IPC_FLOWMQ_H
#define MESH_NODE_IPC_FLOWMQ_H

#include "mesh_node_ipc_channel.h"

#include <flowmq.h>

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#if !defined(FLOWMQ_ROUTER_ENDPOINT_API_VERSION) || \
    FLOWMQ_ROUTER_ENDPOINT_API_VERSION < 4u || \
    !defined(FLOWMQ_CONNECT_ENDPOINT_API_VERSION) || \
    FLOWMQ_CONNECT_ENDPOINT_API_VERSION < 3u || \
    !defined(FLOWMQ_TLS_IDENTITY_MAP_API_VERSION) || \
    FLOWMQ_TLS_IDENTITY_MAP_API_VERSION < 1u || \
    !defined(FLOWMQ_CORONET_API_VERSION) || \
    FLOWMQ_CORONET_API_VERSION < 2u || \
    !defined(FLOWMQ_SEND_ADMISSION_API_VERSION) || \
    FLOWMQ_SEND_ADMISSION_API_VERSION < 1u
#error "MeshNodeIPC requires FlowMQ ROUTER v4, CONNECT v3, CoroNet facade v2, TLS identity map v1, and send-admission v1"
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  MESH_NODE_IPC_FLOWMQ_BIND_V1 = 1,
  MESH_NODE_IPC_FLOWMQ_CONNECT_V1 = 2
} mesh_node_ipc_flowmq_mode_v1_t;

#define MESH_NODE_IPC_FLOWMQ_MAX_FRAME_SIZE_V1 \
  (MESH_NODE_IPC_MAX_FRAME_SIZE_V1 + FLOWMQ_PROTOCOL_MAX_IDENTITY_SIZE)

typedef struct {
  mesh_node_ipc_flowmq_mode_v1_t mode;
  const flowmq_router_endpoint_config_t *bind_endpoint;
  const flowmq_connect_endpoint_config_t *connect_endpoint;
  /** Exact FMQ HELLO identity expected from the sole peer; borrowed until destroy. */
  const char *expected_peer_identity;
  /** Primary canonical peer leaf-certificate SHA-256; copied during init. */
  const char *expected_peer_certificate_sha256;
  /** Optional rotation-overlap certificate SHA-256; copied during init. */
  const char *expected_peer_certificate_sha256_next;
  uint64_t identity_policy_generation;
  mesh_node_ipc_channel_v1_t *inbound;
  mesh_node_ipc_channel_v1_t *outbound;
} mesh_node_ipc_flowmq_config_v1_t;

typedef struct {
  uint8_t started;
  uint8_t stopped;
  uint64_t received;
  uint64_t receive_rejected;
  uint64_t sent;
  uint64_t send_failed;
  size_t send_pending;
  size_t send_pending_bytes;
  size_t send_high_water;
  size_t send_high_water_bytes;
  uint64_t send_rejected_full;
  uint64_t send_completed;
  uint64_t send_admission_failed;
  uint64_t route_generation;
  int last_flow_status;
} mesh_node_ipc_flowmq_stats_v1_t;

typedef struct mesh_node_ipc_flowmq_send_request_v1_s
    mesh_node_ipc_flowmq_send_request_v1_t;

/** Optional adapter built only with TURBOP2P_ENABLE_FLOWMQ_IPC. */
typedef struct {
  flowmq_router_endpoint_t *router;
  flowmq_connect_endpoint_t *connect;
  flowmq_tls_identity_map_t *identity_map;
  mesh_node_ipc_channel_v1_t *inbound;
  mesh_node_ipc_channel_v1_t *outbound;
  char own_identity[FLOWMQ_PROTOCOL_MAX_IDENTITY_SIZE + 1u];
  char expected_peer_identity[FLOWMQ_PROTOCOL_MAX_IDENTITY_SIZE + 1u];
  atomic_uint_fast64_t route_endpoint_id;
  atomic_uint_fast64_t route_session_id;
  atomic_uint_fast64_t route_generation;
  atomic_uint_fast64_t received;
  atomic_uint_fast64_t receive_rejected;
  atomic_uint_fast64_t next_message_id;
  atomic_uint_fast64_t send_completion_id;
  atomic_int send_completion_status;
  atomic_int send_completion_done;
  mesh_node_ipc_flowmq_send_request_v1_t *send_request;
  uint64_t send_timeout_ms;
  uint64_t sent;
  uint64_t send_failed;
  int last_flow_status;
  uint8_t mode;
  uint8_t started;
  uint8_t stopped;
  uint8_t initialized;
} mesh_node_ipc_flowmq_v1_t;

/** Validate the mandatory loopback TLS/mTLS ROUTER/DEALER profile. */
mesh_control_result_t mesh_node_ipc_flowmq_profile_validate_v1(
    const mesh_node_ipc_flowmq_config_v1_t *config);

/** Adapter and both channels must be zero-initialized before init. */
mesh_control_result_t mesh_node_ipc_flowmq_init_v1(
    mesh_node_ipc_flowmq_v1_t *adapter,
    const mesh_node_ipc_flowmq_config_v1_t *config);
mesh_control_result_t mesh_node_ipc_flowmq_start_v1(
    mesh_node_ipc_flowmq_v1_t *adapter);

/**
 * Send at most budget copied frames. Timeout leaves one fenced in-flight send;
 * a later pump resolves it before considering another queue head.
 */
mesh_control_result_t mesh_node_ipc_flowmq_pump_send_v1(
    mesh_node_ipc_flowmq_v1_t *adapter, size_t budget, size_t *out_sent);

/** Requires no queued or in-flight outbound frame. */
mesh_control_result_t mesh_node_ipc_flowmq_stop_v1(
    mesh_node_ipc_flowmq_v1_t *adapter);
mesh_control_result_t mesh_node_ipc_flowmq_get_stats_v1(
    const mesh_node_ipc_flowmq_v1_t *adapter,
    mesh_node_ipc_flowmq_stats_v1_t *out_stats);
void mesh_node_ipc_flowmq_destroy_v1(mesh_node_ipc_flowmq_v1_t *adapter);

#ifdef __cplusplus
}
#endif

#endif
