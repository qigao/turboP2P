#ifndef MESH_NODE_CONTROL_RUNTIME_H
#define MESH_NODE_CONTROL_RUNTIME_H

#include "mesh_node_ipc_flowmq.h"
#include "mesh_node_ipc_owner.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  mesh_node_ipc_flowmq_mode_v1_t mode;
  const flowmq_router_endpoint_config_t *bind_endpoint;
  const flowmq_connect_endpoint_config_t *connect_endpoint;
  const char *expected_peer_identity;
  const char *expected_peer_certificate_sha256;
  const char *expected_peer_certificate_sha256_next;
  uint64_t identity_policy_generation;
  mesh_node_ipc_execute_fn_v1 execute;
  void *execute_context;
  uint8_t mesh_id[MESH_CONTROL_DIGEST_SIZE];
  uint8_t provider_id[MESH_CONTROL_DIGEST_SIZE];
  uint8_t sender_incarnation[MESH_CONTROL_ID_SIZE];
  uint64_t allowed_resource_mask;
  size_t operation_capacity;
  size_t channel_capacity;
  size_t channel_max_retained_bytes;
} mesh_node_control_runtime_config_v1_t;

typedef struct {
  mesh_node_ipc_owner_stats_v1_t owner;
  mesh_node_ipc_flowmq_stats_v1_t transport;
  mesh_node_ipc_channel_stats_v1_t inbound;
  mesh_node_ipc_channel_stats_v1_t outbound;
  uint8_t started;
  uint8_t draining;
  uint8_t stopped;
} mesh_node_control_runtime_stats_v1_t;

/**
 * Single-owner meshd control composition. The runtime owns both bounded
 * channels, the typed operation owner, and the FlowMQ facade. Endpoint,
 * endpoint configuration and execute_context remain caller-owned until destroy.
 */
typedef struct {
  mesh_node_ipc_channel_v1_t inbound;
  mesh_node_ipc_channel_v1_t outbound;
  mesh_node_ipc_owner_v1_t owner;
  mesh_node_ipc_flowmq_v1_t transport;
  uint8_t started;
  uint8_t draining;
  uint8_t stopped;
  uint8_t initialized;
} mesh_node_control_runtime_v1_t;

mesh_control_result_t mesh_node_control_runtime_init_v1(
    mesh_node_control_runtime_v1_t *runtime,
    const mesh_node_control_runtime_config_v1_t *config);
mesh_control_result_t mesh_node_control_runtime_start_v1(
    mesh_node_control_runtime_v1_t *runtime);

/**
 * Nonblocking owner-loop step. Existing results are sent first, then at most
 * command_budget inputs are executed, followed by newly produced results.
 */
mesh_control_result_t mesh_node_control_runtime_poll_v1(
    mesh_node_control_runtime_v1_t *runtime, size_t command_budget,
    size_t send_budget, size_t *out_processed, size_t *out_sent);

mesh_control_result_t mesh_node_control_runtime_begin_drain_v1(
    mesh_node_control_runtime_v1_t *runtime);

/**
 * Stops only after inbound/outbound queues and acknowledged operation state
 * are empty. RESOURCE_EXHAUSTED means the caller must keep polling/draining.
 */
mesh_control_result_t mesh_node_control_runtime_stop_v1(
    mesh_node_control_runtime_v1_t *runtime);
mesh_control_result_t mesh_node_control_runtime_get_stats_v1(
    const mesh_node_control_runtime_v1_t *runtime,
    mesh_node_control_runtime_stats_v1_t *out_stats);

/** Force-closes transport admission and releases bounded volatile state. */
void mesh_node_control_runtime_destroy_v1(
    mesh_node_control_runtime_v1_t *runtime);

#ifdef __cplusplus
}
#endif

#endif
