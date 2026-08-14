#ifndef MESH_NODE_IPC_OWNER_H
#define MESH_NODE_IPC_OWNER_H

#include "mesh_node_ipc_channel.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  uint64_t applied_epoch;
  uint8_t observed_digest[MESH_CONTROL_DIGEST_SIZE];
} mesh_node_ipc_execution_output_v1_t;

/** Synchronous single-owner execution boundary; it must not retain command. */
typedef mesh_control_result_t (*mesh_node_ipc_execute_fn_v1)(
    void *context, const mesh_node_ipc_command_v1_t *command,
    uint64_t desired_epoch, mesh_node_ipc_execution_output_v1_t *out_execution);

typedef struct {
  mesh_node_ipc_channel_v1_t *inbound;
  mesh_node_ipc_channel_v1_t *outbound;
  mesh_node_ipc_execute_fn_v1 execute;
  void *execute_context;
  uint8_t mesh_id[MESH_CONTROL_DIGEST_SIZE];
  uint8_t provider_id[MESH_CONTROL_DIGEST_SIZE];
  uint8_t sender_incarnation[MESH_CONTROL_ID_SIZE];
  uint64_t allowed_resource_mask;
  size_t operation_capacity;
} mesh_node_ipc_owner_config_v1_t;

typedef struct {
  uint8_t operation_id[MESH_CONTROL_ID_SIZE];
  uint8_t request_id[MESH_CONTROL_ID_SIZE];
  uint8_t binding_digest[MESH_CONTROL_DIGEST_SIZE];
  uint64_t desired_epoch;
  mesh_node_ipc_result_v1_t result;
  uint8_t result_sent;
} mesh_node_ipc_operation_v1_t;

typedef struct {
  mesh_node_ipc_channel_v1_t *inbound;
  mesh_node_ipc_channel_v1_t *outbound;
  mesh_node_ipc_execute_fn_v1 execute;
  void *execute_context;
  uint8_t mesh_id[MESH_CONTROL_DIGEST_SIZE];
  uint8_t provider_id[MESH_CONTROL_DIGEST_SIZE];
  uint8_t sender_incarnation[MESH_CONTROL_ID_SIZE];
  uint64_t allowed_resource_mask;
  mesh_node_ipc_operation_v1_t *operations;
  size_t operation_count;
  size_t operation_capacity;
  uint64_t next_sequence;
  uint64_t commands_accepted;
  uint64_t commands_rejected;
  uint64_t duplicate_commands;
  uint64_t operation_collisions;
  uint64_t results_acked;
  uint8_t accepting_commands;
  uint8_t initialized;
} mesh_node_ipc_owner_v1_t;

typedef struct {
  size_t retained_operations;
  size_t operation_capacity;
  uint8_t accepting_commands;
  uint64_t commands_accepted;
  uint64_t commands_rejected;
  uint64_t duplicate_commands;
  uint64_t operation_collisions;
  uint64_t results_acked;
} mesh_node_ipc_owner_stats_v1_t;

/** owner must be zero-initialized and remains single-owner after init. */
mesh_control_result_t mesh_node_ipc_owner_init_v1(
    mesh_node_ipc_owner_v1_t *owner,
    const mesh_node_ipc_owner_config_v1_t *config);

/** Processes at most budget inbound frames and never blocks. */
mesh_control_result_t mesh_node_ipc_owner_poll_v1(
    mesh_node_ipc_owner_v1_t *owner, size_t budget, size_t *out_processed);

/** Rejects later COMMAND frames while continuing ACK_RESULT/DRAIN handling. */
mesh_control_result_t mesh_node_ipc_owner_begin_drain_v1(
    mesh_node_ipc_owner_v1_t *owner);
mesh_control_result_t mesh_node_ipc_owner_get_stats_v1(
    const mesh_node_ipc_owner_v1_t *owner,
    mesh_node_ipc_owner_stats_v1_t *out_stats);

/** Requires both channels to be quiescent; retained results are released. */
void mesh_node_ipc_owner_destroy_v1(mesh_node_ipc_owner_v1_t *owner);

#ifdef __cplusplus
}
#endif

#endif
