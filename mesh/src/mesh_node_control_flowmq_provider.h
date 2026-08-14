#ifndef MESH_NODE_CONTROL_FLOWMQ_PROVIDER_H
#define MESH_NODE_CONTROL_FLOWMQ_PROVIDER_H

#include "mesh_control_reconciler.h"
#include "mesh_node_control_client_runtime.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_NODE_CONTROL_FLOWMQ_PROVIDER_OPERATION_CAPACITY_V1 1u

typedef struct {
  mesh_node_control_client_runtime_config_v1_t runtime;
  uint16_t provider_runtime;
  uint64_t initial_applied_epoch;
  size_t response_budget;
  size_t send_budget;
} mesh_node_control_flowmq_provider_config_v1_t;

/**
 * Prestaged function provider backed by MeshNodeIPC/1. It intentionally
 * serializes one mutation so runtime preconditions have a single owner.
 */
typedef struct {
  mesh_node_control_client_runtime_v1_t runtime;
  mesh_control_provider_v1_t descriptor;
  mesh_control_provider_request_v1_t active_request;
  mesh_node_ipc_result_v1_t active_result;
  uint64_t applied_epoch;
  size_t response_budget;
  size_t send_budget;
  mesh_control_result_t last_error;
  uint8_t active;
  uint8_t result_ready;
  uint8_t started;
  uint8_t closed;
  uint8_t stopped;
  uint8_t initialized;
} mesh_node_control_flowmq_provider_v1_t;

mesh_control_result_t mesh_node_control_flowmq_provider_init_v1(
    mesh_node_control_flowmq_provider_v1_t *provider,
    const mesh_node_control_flowmq_provider_config_v1_t *config);
mesh_control_result_t mesh_node_control_flowmq_provider_start_v1(
    mesh_node_control_flowmq_provider_v1_t *provider);

/** Advances transport without blocking the agent owner. */
mesh_control_result_t mesh_node_control_flowmq_provider_poll_v1(
    mesh_node_control_flowmq_provider_v1_t *provider,
    size_t *out_progress);

/** Descriptor remains owned by provider and valid until destroy. */
const mesh_control_provider_v1_t *
mesh_node_control_flowmq_provider_descriptor_v1(
    mesh_node_control_flowmq_provider_v1_t *provider);

void mesh_node_control_flowmq_provider_destroy_v1(
    mesh_node_control_flowmq_provider_v1_t *provider);

#ifdef __cplusplus
}
#endif

#endif
