#ifndef MESH_NODE_NETWORK_CONTROL_SERVICE_H
#define MESH_NODE_NETWORK_CONTROL_SERVICE_H

#include "mesh_node_control_runtime.h"
#include "mesh_node_ipc_network_executor.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  MESH_NODE_NETWORK_CONTROL_UNINITIALIZED_V1 = 0,
  MESH_NODE_NETWORK_CONTROL_READY_V1 = 1,
  MESH_NODE_NETWORK_CONTROL_RUNNING_V1 = 2,
  MESH_NODE_NETWORK_CONTROL_DRAINING_V1 = 3,
  MESH_NODE_NETWORK_CONTROL_STOPPED_V1 = 4,
  MESH_NODE_NETWORK_CONTROL_ABORTING_V1 = 5
} mesh_node_network_control_lifecycle_v1_t;

typedef struct {
  /** Borrowed and required to outlive the service. */
  mesh_fabric_t *fabric;
  /** Borrowed by the FlowMQ endpoint until service destruction. */
  const flowmq_router_endpoint_config_t *bind_endpoint;
  const char *expected_peer_identity;
  const char *expected_peer_certificate_sha256;
  const char *expected_peer_certificate_sha256_next;
  uint64_t identity_policy_generation;
  uint8_t mesh_id[MESH_CONTROL_DIGEST_SIZE];
  uint8_t provider_id[MESH_CONTROL_DIGEST_SIZE];
  uint8_t sender_incarnation[MESH_CONTROL_ID_SIZE];
  size_t network_capacity;
  size_t operation_capacity;
  size_t channel_capacity;
  size_t channel_max_retained_bytes;
  size_t command_budget;
  size_t send_budget;
  uint64_t delete_drain_timeout_ms;
  uint64_t shutdown_drain_timeout_ms;
} mesh_node_network_control_service_config_v1_t;

typedef struct {
  mesh_node_control_runtime_stats_v1_t runtime;
  mesh_fabric_status_v2_t fabric;
  size_t owned_networks;
  size_t network_capacity;
  mesh_node_network_control_lifecycle_v1_t lifecycle;
} mesh_node_network_control_service_stats_v1_t;

/**
 * Single-owner meshd composition for typed Network APPLY/DELETE commands.
 * The service owns the reconciler, executor and FlowMQ server runtime, but it
 * only borrows the shared fabric and endpoint configuration. The service must
 * be zero-initialized before init and all APIs must run on the fabric owner.
 */
typedef struct {
  mesh_network_reconciler_v1_t reconciler;
  mesh_node_ipc_network_executor_v1_t executor;
  mesh_node_control_runtime_v1_t runtime;
  mesh_fabric_t *fabric;
  size_t command_budget;
  size_t send_budget;
  uint64_t shutdown_drain_timeout_ms;
  size_t abandoned_operations;
  mesh_node_network_control_lifecycle_v1_t lifecycle;
} mesh_node_network_control_service_v1_t;

mesh_control_result_t mesh_node_network_control_service_init_v1(
    mesh_node_network_control_service_v1_t *service,
    const mesh_node_network_control_service_config_v1_t *config);
mesh_control_result_t mesh_node_network_control_service_start_v1(
    mesh_node_network_control_service_v1_t *service);
mesh_control_result_t mesh_node_network_control_service_poll_v1(
    mesh_node_network_control_service_v1_t *service,
    size_t *out_processed, size_t *out_sent);
mesh_control_result_t mesh_node_network_control_service_begin_drain_v1(
    mesh_node_network_control_service_v1_t *service);

/**
 * Stop succeeds only after every RESULT has been acknowledged. It then
 * detaches every Network owned by this service while the borrowed fabric is
 * still alive. RESOURCE_EXHAUSTED means the owner must continue polling.
 */
mesh_control_result_t mesh_node_network_control_service_stop_v1(
    mesh_node_network_control_service_v1_t *service);

/**
 * Explicitly abandon volatile unacknowledged results after the caller's drain
 * deadline. The count is returned for audit/exit-status reporting. Attached
 * Networks are still synchronously detached before success is reported.
 */
mesh_control_result_t mesh_node_network_control_service_abort_v1(
    mesh_node_network_control_service_v1_t *service,
    size_t *out_abandoned_operations);
mesh_control_result_t mesh_node_network_control_service_get_stats_v1(
    const mesh_node_network_control_service_v1_t *service,
    mesh_node_network_control_service_stats_v1_t *out_stats);

/**
 * Release owned resources. A running or draining service is rejected so
 * unacknowledged results and attached Networks cannot be silently discarded.
 */
mesh_control_result_t mesh_node_network_control_service_destroy_v1(
    mesh_node_network_control_service_v1_t *service);

#ifdef __cplusplus
}
#endif

#endif
