#ifndef MESH_NODE_CONTROL_CLIENT_RUNTIME_H
#define MESH_NODE_CONTROL_CLIENT_RUNTIME_H

#include "mesh_node_ipc_client.h"
#include "mesh_node_ipc_flowmq.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  const flowmq_connect_endpoint_config_t *connect_endpoint;
  const char *expected_peer_identity;
  const char *expected_peer_certificate_sha256;
  const char *expected_peer_certificate_sha256_next;
  uint64_t identity_policy_generation;
  uint8_t mesh_id[MESH_CONTROL_DIGEST_SIZE];
  uint8_t provider_id[MESH_CONTROL_DIGEST_SIZE];
  uint8_t sender_incarnation[MESH_CONTROL_ID_SIZE];
  size_t operation_capacity;
  size_t channel_capacity;
  size_t channel_max_retained_bytes;
} mesh_node_control_client_runtime_config_v1_t;

typedef struct {
  mesh_node_ipc_client_stats_v1_t client;
  mesh_node_ipc_flowmq_stats_v1_t transport;
  mesh_node_ipc_channel_stats_v1_t inbound;
  mesh_node_ipc_channel_stats_v1_t outbound;
  uint8_t started;
  uint8_t draining;
  uint8_t stopped;
} mesh_node_control_client_runtime_stats_v1_t;

/**
 * Agent-side CONNECT runtime. All APIs are single-owner and non-blocking
 * except FlowMQ endpoint startup/shutdown within their configured deadlines.
 */
typedef struct {
  mesh_node_ipc_channel_v1_t inbound;
  mesh_node_ipc_channel_v1_t outbound;
  mesh_node_ipc_client_v1_t client;
  mesh_node_ipc_flowmq_v1_t transport;
  uint8_t started;
  uint8_t draining;
  uint8_t stopped;
  uint8_t initialized;
} mesh_node_control_client_runtime_v1_t;

mesh_control_result_t mesh_node_control_client_runtime_init_v1(
    mesh_node_control_client_runtime_v1_t *runtime,
    const mesh_node_control_client_runtime_config_v1_t *config);
mesh_control_result_t mesh_node_control_client_runtime_start_v1(
    mesh_node_control_client_runtime_v1_t *runtime);
mesh_control_result_t mesh_node_control_client_runtime_submit_v1(
    mesh_node_control_client_runtime_v1_t *runtime,
    const uint8_t request_id[MESH_CONTROL_ID_SIZE],
    const uint8_t operation_id[MESH_CONTROL_ID_SIZE], uint64_t desired_epoch,
    const mesh_node_ipc_command_v1_t *command);
mesh_control_result_t mesh_node_control_client_runtime_poll_v1(
    mesh_node_control_client_runtime_v1_t *runtime, size_t response_budget,
    size_t send_budget, size_t *out_processed, size_t *out_sent);
mesh_control_result_t mesh_node_control_client_runtime_peek_result_v1(
    const mesh_node_control_client_runtime_v1_t *runtime,
    uint8_t out_operation_id[MESH_CONTROL_ID_SIZE],
    mesh_node_ipc_result_v1_t *out_result);
mesh_control_result_t mesh_node_control_client_runtime_ack_result_v1(
    mesh_node_control_client_runtime_v1_t *runtime,
    const uint8_t operation_id[MESH_CONTROL_ID_SIZE]);
mesh_control_result_t mesh_node_control_client_runtime_begin_drain_v1(
    mesh_node_control_client_runtime_v1_t *runtime);
mesh_control_result_t mesh_node_control_client_runtime_stop_v1(
    mesh_node_control_client_runtime_v1_t *runtime);
mesh_control_result_t mesh_node_control_client_runtime_get_stats_v1(
    const mesh_node_control_client_runtime_v1_t *runtime,
    mesh_node_control_client_runtime_stats_v1_t *out_stats);
void mesh_node_control_client_runtime_destroy_v1(
    mesh_node_control_client_runtime_v1_t *runtime);

#ifdef __cplusplus
}
#endif

#endif
