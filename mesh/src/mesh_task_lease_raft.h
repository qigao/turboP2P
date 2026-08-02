#ifndef MESH_TASK_LEASE_RAFT_H
#define MESH_TASK_LEASE_RAFT_H

#include "mesh_task_lease.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_TASK_LEASE_RAFT_COMMAND_VERSION 1u
#define MESH_TASK_LEASE_RAFT_COMMAND_HEADER_SIZE 8u
#define MESH_TASK_LEASE_RAFT_COMMAND_SIZE                                      \
  (MESH_TASK_LEASE_RAFT_COMMAND_HEADER_SIZE +                                 \
   MESH_MGMT_EXECUTION_ID_SIZE + (2u * MESH_MGMT_EXECUTION_DIGEST_SIZE) +     \
   (4u * sizeof(uint64_t)) + (2u * sizeof(uint32_t)))

typedef enum {
  MESH_TASK_LEASE_RAFT_REGISTER = 1,
  MESH_TASK_LEASE_RAFT_ACQUIRE = 2,
  MESH_TASK_LEASE_RAFT_RENEW = 3,
  MESH_TASK_LEASE_RAFT_EXPIRE = 4,
  MESH_TASK_LEASE_RAFT_COMPLETE = 5,
} mesh_task_lease_raft_operation_v1_t;

/*
 * Commands contain only leader-observed facts. Apply never reads a local clock,
 * so the same committed entry produces the same lease transition on replay.
 */
typedef struct {
  mesh_task_lease_raft_operation_v1_t operation;
  uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE];
  uint8_t request_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint8_t holder_node_id[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint64_t task_deadline_ms;
  uint64_t observed_now_ms;
  uint64_t lease_expires_at_ms;
  uint64_t expected_fencing_token;
  int32_t result_code;
  mesh_task_state_v1_t terminal_state;
} mesh_task_lease_raft_command_v1_t;

mesh_task_lease_result_t mesh_task_lease_raft_encode_v1(
    const mesh_task_lease_raft_command_v1_t *command, uint8_t *output,
    size_t output_capacity, size_t *out_size);

mesh_task_lease_result_t mesh_task_lease_raft_decode_v1(
    const uint8_t *input, size_t input_size,
    mesh_task_lease_raft_command_v1_t *out_command);

mesh_task_lease_result_t mesh_task_lease_raft_apply_v1(
    mesh_task_lease_store_v1_t *store, uint64_t committed_index,
    const uint8_t *command_data, size_t command_size,
    mesh_task_lease_entry_v1_t *out_entry);

#ifdef __cplusplus
}
#endif

#endif
