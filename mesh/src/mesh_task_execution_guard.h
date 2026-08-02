#ifndef MESH_TASK_EXECUTION_GUARD_H
#define MESH_TASK_EXECUTION_GUARD_H

#include "mesh_task_lease.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  MESH_TASK_EXECUTION_GUARD_OK = 0,
  MESH_TASK_EXECUTION_GUARD_INVALID_ARG = -1,
  MESH_TASK_EXECUTION_GUARD_NOT_FOUND = -2,
  MESH_TASK_EXECUTION_GUARD_IDENTITY_CONFLICT = -3,
  MESH_TASK_EXECUTION_GUARD_NOT_LEASED = -4,
  MESH_TASK_EXECUTION_GUARD_FENCED = -5,
  MESH_TASK_EXECUTION_GUARD_STALE_READ = -6,
  MESH_TASK_EXECUTION_GUARD_EXPIRED = -7,
  MESH_TASK_EXECUTION_GUARD_CRYPTO_FAILED = -8,
} mesh_task_execution_guard_result_t;

/* Extracted only after the signed execution request digest is verified. */
typedef struct {
  uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE];
  uint8_t request_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint8_t target_node_id[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint64_t task_deadline_ms;
} mesh_task_execution_claim_v1_t;

typedef struct {
  uint64_t fencing_token;
  uint64_t worker_generation;
  uint64_t quorum_read_index;
  uint64_t local_applied_index;
  uint64_t observed_now_ms;
} mesh_task_execution_proof_v1_t;

mesh_task_execution_guard_result_t mesh_task_worker_identity_v1(
    const uint8_t node_id[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    uint64_t worker_generation,
    uint8_t out_identity[MESH_MGMT_EXECUTION_DIGEST_SIZE]);

/* Pure pre-runner authorization; it never advances lease or journal state. */
mesh_task_execution_guard_result_t mesh_task_execution_guard_v1(
    const mesh_task_lease_store_v1_t *store,
    const uint8_t local_node_id[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    const mesh_task_execution_claim_v1_t *claim,
    const mesh_task_execution_proof_v1_t *proof,
    mesh_task_lease_entry_v1_t *out_lease);

#ifdef __cplusplus
}
#endif

#endif
