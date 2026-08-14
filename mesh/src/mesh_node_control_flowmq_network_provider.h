#ifndef MESH_NODE_CONTROL_FLOWMQ_NETWORK_PROVIDER_H
#define MESH_NODE_CONTROL_FLOWMQ_NETWORK_PROVIDER_H

#include "mesh_control_network_provider.h"
#include "mesh_node_control_client_runtime.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_NODE_CONTROL_FLOWMQ_NETWORK_OPERATION_CAPACITY_V1 1u

typedef struct {
  mesh_node_control_client_runtime_config_v1_t runtime;
  size_t response_budget;
  size_t send_budget;
} mesh_node_control_flowmq_network_provider_config_v1_t;

typedef struct {
  mesh_node_control_client_runtime_v1_t runtime;
  mesh_control_network_provider_v1_t descriptor;
  mesh_control_operation_v1_t active_operation;
  mesh_node_ipc_result_v1_t active_result;
  size_t response_budget;
  size_t send_budget;
  mesh_control_result_t last_error;
  uint8_t active;
  uint8_t result_ready;
  uint8_t started;
  uint8_t closed;
  uint8_t stopped;
  uint8_t initialized;
} mesh_node_control_flowmq_network_provider_v1_t;

mesh_control_result_t mesh_node_control_flowmq_network_provider_init_v1(
    mesh_node_control_flowmq_network_provider_v1_t *provider,
    const mesh_node_control_flowmq_network_provider_config_v1_t *config);
mesh_control_result_t mesh_node_control_flowmq_network_provider_start_v1(
    mesh_node_control_flowmq_network_provider_v1_t *provider);
mesh_control_result_t mesh_node_control_flowmq_network_provider_poll_v1(
    mesh_node_control_flowmq_network_provider_v1_t *provider,
    size_t *out_progress);
const mesh_control_network_provider_v1_t *
mesh_node_control_flowmq_network_provider_descriptor_v1(
    mesh_node_control_flowmq_network_provider_v1_t *provider);
void mesh_node_control_flowmq_network_provider_destroy_v1(
    mesh_node_control_flowmq_network_provider_v1_t *provider);

#ifdef __cplusplus
}
#endif

#endif
