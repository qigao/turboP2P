#ifndef MESH_NODE_IPC_H
#define MESH_NODE_IPC_H

#include "mesh_control_primitives.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_NODE_IPC_HEADER_SIZE_V1 128u
#define MESH_NODE_IPC_MAX_FRAME_SIZE_V1 MESH_CONTROL_MAX_FRAME_SIZE_V1
#define MESH_NODE_IPC_COMMAND_HEADER_SIZE_V1 156u
#define MESH_NODE_IPC_RESULT_SIZE_V1 96u

typedef enum {
  MESH_NODE_IPC_HELLO_V1 = 1,
  MESH_NODE_IPC_HELLO_ACK_V1 = 2,
  MESH_NODE_IPC_COMMAND_V1 = 3,
  MESH_NODE_IPC_ACCEPTED_V1 = 4,
  MESH_NODE_IPC_RESULT_V1 = 5,
  MESH_NODE_IPC_QUERY_V1 = 6,
  MESH_NODE_IPC_STATUS_V1 = 7,
  MESH_NODE_IPC_ACK_RESULT_V1 = 8,
  MESH_NODE_IPC_CANCEL_V1 = 9,
  MESH_NODE_IPC_DRAIN_V1 = 10,
  MESH_NODE_IPC_DRAINED_V1 = 11
} mesh_node_ipc_kind_v1_t;

typedef enum {
  MESH_NODE_IPC_OUTCOME_SUCCEEDED_V1 = 1,
  MESH_NODE_IPC_OUTCOME_FAILED_V1 = 2
} mesh_node_ipc_outcome_v1_t;

typedef enum {
  MESH_NODE_IPC_ERROR_NONE_V1 = 0,
  MESH_NODE_IPC_ERROR_INVALID_DOCUMENT_V1 = 1,
  MESH_NODE_IPC_ERROR_PERMISSION_DENIED_V1 = 2,
  MESH_NODE_IPC_ERROR_FENCED_V1 = 3,
  MESH_NODE_IPC_ERROR_CONFLICT_V1 = 4,
  MESH_NODE_IPC_ERROR_RESOURCE_EXHAUSTED_V1 = 5,
  MESH_NODE_IPC_ERROR_PROVIDER_UNAVAILABLE_V1 = 6,
  MESH_NODE_IPC_ERROR_UNKNOWN_COMMIT_V1 = 7,
  MESH_NODE_IPC_ERROR_SHUTTING_DOWN_V1 = 8,
  MESH_NODE_IPC_ERROR_INTERNAL_V1 = 9,
  MESH_NODE_IPC_ERROR_TIMEOUT_V1 = 10
} mesh_node_ipc_error_v1_t;

typedef enum {
  MESH_NODE_IPC_STAGE_NONE_V1 = 0,
  MESH_NODE_IPC_STAGE_ADMISSION_V1 = 1,
  MESH_NODE_IPC_STAGE_QUEUE_V1 = 2,
  MESH_NODE_IPC_STAGE_EXECUTION_V1 = 3,
  MESH_NODE_IPC_STAGE_COMMIT_V1 = 4,
  MESH_NODE_IPC_STAGE_RESULT_V1 = 5
} mesh_node_ipc_failure_stage_v1_t;

/** Decoded body is borrowed from the input and invalid after its owner mutates. */
typedef struct {
  uint16_t minor;
  uint16_t kind;
  uint16_t flags;
  uint8_t request_id[MESH_CONTROL_ID_SIZE];
  uint8_t operation_id[MESH_CONTROL_ID_SIZE];
  uint8_t sender_incarnation[MESH_CONTROL_ID_SIZE];
  uint64_t sequence;
  uint64_t desired_epoch;
  const uint8_t *body;
  size_t body_size;
} mesh_node_ipc_envelope_v1_t;

/** Canonical declarative command. document is borrowed by encode/decode. */
typedef struct {
  uint16_t action;
  uint16_t resource_kind;
  uint64_t precondition_epoch;
  uint8_t mesh_id[MESH_CONTROL_DIGEST_SIZE];
  uint8_t resource_id[MESH_CONTROL_DIGEST_SIZE];
  uint8_t provider_id[MESH_CONTROL_DIGEST_SIZE];
  uint8_t document_digest[MESH_CONTROL_DIGEST_SIZE];
  const uint8_t *document;
  size_t document_size;
} mesh_node_ipc_command_v1_t;

typedef struct {
  uint16_t outcome;
  uint16_t stable_error;
  uint16_t failure_stage;
  uint16_t resource_kind;
  uint16_t action;
  uint64_t applied_epoch;
  uint8_t resource_id[MESH_CONTROL_DIGEST_SIZE];
  uint8_t observed_digest[MESH_CONTROL_DIGEST_SIZE];
} mesh_node_ipc_result_v1_t;

mesh_control_result_t mesh_node_ipc_envelope_encode_v1(
    const mesh_node_ipc_envelope_v1_t *envelope, uint8_t *output,
    size_t output_capacity, size_t *out_size);

mesh_control_result_t mesh_node_ipc_envelope_decode_v1(
    const uint8_t *input, size_t input_size,
    mesh_node_ipc_envelope_v1_t *out_envelope);

mesh_control_result_t mesh_node_ipc_command_encode_v1(
    const mesh_node_ipc_command_v1_t *command, uint8_t *output,
    size_t output_capacity, size_t *out_size);

mesh_control_result_t mesh_node_ipc_command_decode_v1(
    const uint8_t *input, size_t input_size,
    mesh_node_ipc_command_v1_t *out_command);

mesh_control_result_t mesh_node_ipc_result_encode_v1(
    const mesh_node_ipc_result_v1_t *result,
    uint8_t output[MESH_NODE_IPC_RESULT_SIZE_V1]);

mesh_control_result_t mesh_node_ipc_result_decode_v1(
    const uint8_t input[MESH_NODE_IPC_RESULT_SIZE_V1], size_t input_size,
    mesh_node_ipc_result_v1_t *out_result);

#ifdef __cplusplus
}
#endif

#endif
