#ifndef MESH_NODE_IPC_CLIENT_H
#define MESH_NODE_IPC_CLIENT_H

#include "mesh_node_ipc_channel.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  MESH_NODE_IPC_CLIENT_COMMAND_QUEUED_V1 = 1,
  MESH_NODE_IPC_CLIENT_ACCEPTED_V1 = 2,
  MESH_NODE_IPC_CLIENT_RESULT_READY_V1 = 3
} mesh_node_ipc_client_operation_state_v1_t;

typedef struct {
  mesh_node_ipc_channel_v1_t *inbound;
  mesh_node_ipc_channel_v1_t *outbound;
  uint8_t mesh_id[MESH_CONTROL_DIGEST_SIZE];
  uint8_t provider_id[MESH_CONTROL_DIGEST_SIZE];
  uint8_t sender_incarnation[MESH_CONTROL_ID_SIZE];
  size_t operation_capacity;
} mesh_node_ipc_client_config_v1_t;

typedef struct {
  uint8_t operation_id[MESH_CONTROL_ID_SIZE];
  uint8_t request_id[MESH_CONTROL_ID_SIZE];
  uint8_t resource_id[MESH_CONTROL_DIGEST_SIZE];
  uint8_t document_digest[MESH_CONTROL_DIGEST_SIZE];
  uint8_t peer_incarnation[MESH_CONTROL_ID_SIZE];
  uint64_t desired_epoch;
  uint16_t resource_kind;
  uint16_t action;
  uint8_t state;
  mesh_node_ipc_result_v1_t result;
} mesh_node_ipc_client_operation_v1_t;

typedef struct {
  size_t retained_operations;
  size_t operation_capacity;
  uint8_t accepting_commands;
  uint64_t commands_submitted;
  uint64_t accepted_received;
  uint64_t results_received;
  uint64_t duplicate_frames;
  uint64_t rejected_frames;
  uint64_t results_acked;
} mesh_node_ipc_client_stats_v1_t;

/**
 * Single-owner client state machine. It does not own either channel. A submit
 * copies one canonical frame into outbound before returning and retains no
 * document pointer. The caller must durably record a terminal result before
 * ack_result; ack_result admits an exact ACK frame before releasing state.
 */
typedef struct {
  mesh_node_ipc_channel_v1_t *inbound;
  mesh_node_ipc_channel_v1_t *outbound;
  uint8_t mesh_id[MESH_CONTROL_DIGEST_SIZE];
  uint8_t provider_id[MESH_CONTROL_DIGEST_SIZE];
  uint8_t sender_incarnation[MESH_CONTROL_ID_SIZE];
  mesh_node_ipc_client_operation_v1_t *operations;
  size_t operation_count;
  size_t operation_capacity;
  uint64_t next_sequence;
  uint64_t commands_submitted;
  uint64_t accepted_received;
  uint64_t results_received;
  uint64_t duplicate_frames;
  uint64_t rejected_frames;
  uint64_t results_acked;
  uint8_t accepting_commands;
  uint8_t initialized;
} mesh_node_ipc_client_v1_t;

mesh_control_result_t mesh_node_ipc_client_init_v1(
    mesh_node_ipc_client_v1_t *client,
    const mesh_node_ipc_client_config_v1_t *config);

/** Non-blocking; any non-OK result means the command was not consumed. */
mesh_control_result_t mesh_node_ipc_client_submit_v1(
    mesh_node_ipc_client_v1_t *client,
    const uint8_t request_id[MESH_CONTROL_ID_SIZE],
    const uint8_t operation_id[MESH_CONTROL_ID_SIZE], uint64_t desired_epoch,
    const mesh_node_ipc_command_v1_t *command);

/** Processes at most budget inbound ACCEPTED/RESULT frames. */
mesh_control_result_t mesh_node_ipc_client_poll_v1(
    mesh_node_ipc_client_v1_t *client, size_t budget, size_t *out_processed);

/** Returns the oldest retained terminal result without consuming it. */
mesh_control_result_t mesh_node_ipc_client_peek_result_v1(
    const mesh_node_ipc_client_v1_t *client,
    uint8_t out_operation_id[MESH_CONTROL_ID_SIZE],
    mesh_node_ipc_result_v1_t *out_result);

/** Enqueues exact ACK_RESULT, then releases the matching retained operation. */
mesh_control_result_t mesh_node_ipc_client_ack_result_v1(
    mesh_node_ipc_client_v1_t *client,
    const uint8_t operation_id[MESH_CONTROL_ID_SIZE]);

mesh_control_result_t mesh_node_ipc_client_begin_drain_v1(
    mesh_node_ipc_client_v1_t *client);
int mesh_node_ipc_client_is_drained_v1(
    const mesh_node_ipc_client_v1_t *client);
mesh_control_result_t mesh_node_ipc_client_get_stats_v1(
    const mesh_node_ipc_client_v1_t *client,
    mesh_node_ipc_client_stats_v1_t *out_stats);

/** Caller must first quiesce both channel endpoints. */
void mesh_node_ipc_client_destroy_v1(mesh_node_ipc_client_v1_t *client);

#ifdef __cplusplus
}
#endif

#endif
