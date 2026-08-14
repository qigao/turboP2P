#ifndef MESH_NODE_IPC_NETWORK_EXECUTOR_H
#define MESH_NODE_IPC_NETWORK_EXECUTOR_H

#include "mesh_network_reconciler.h"
#include "mesh_node_ipc_owner.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  mesh_network_reconciler_v1_t *reconciler;
  uint8_t mesh_id[MESH_CONTROL_DIGEST_SIZE];
  uint64_t delete_drain_timeout_ms;
  uint8_t initialized;
} mesh_node_ipc_network_executor_v1_t;

mesh_control_result_t mesh_node_ipc_network_executor_init_v1(
    mesh_node_ipc_network_executor_v1_t *executor,
    mesh_network_reconciler_v1_t *reconciler,
    const uint8_t mesh_id[MESH_CONTROL_DIGEST_SIZE],
    uint64_t delete_drain_timeout_ms);

/** mesh_node_ipc_execute_fn_v1 implementation for Network APPLY/DELETE. */
mesh_control_result_t mesh_node_ipc_network_execute_v1(
    void *context, const mesh_node_ipc_command_v1_t *command,
    uint64_t desired_epoch, mesh_node_ipc_execution_output_v1_t *out_execution);

void mesh_node_ipc_network_executor_destroy_v1(
    mesh_node_ipc_network_executor_v1_t *executor);

#ifdef __cplusplus
}
#endif

#endif
