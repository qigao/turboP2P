#ifndef MESH_TASK_LEASE_H
#define MESH_TASK_LEASE_H

#include "mesh_mgmt_execution.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_TASK_LEASE_VERSION 1u
#define MESH_TASK_LEASE_MAX_TASKS 1024u

typedef enum {
  MESH_TASK_LEASE_OK = 0,
  MESH_TASK_LEASE_INVALID_ARG = -1,
  MESH_TASK_LEASE_INVALID_STATE = -2,
  MESH_TASK_LEASE_NOT_FOUND = -3,
  MESH_TASK_LEASE_CONFLICT = -4,
  MESH_TASK_LEASE_BUSY = -5,
  MESH_TASK_LEASE_FENCED = -6,
  MESH_TASK_LEASE_OUT_OF_ORDER = -7,
  MESH_TASK_LEASE_RESOURCE_EXHAUSTED = -8,
} mesh_task_lease_result_t;

typedef enum {
  MESH_TASK_STATE_READY = 1,
  MESH_TASK_STATE_LEASED = 2,
  MESH_TASK_STATE_SUCCEEDED = 3,
  MESH_TASK_STATE_FAILED = 4,
  MESH_TASK_STATE_CANCELLED = 5,
  MESH_TASK_STATE_EXPIRED = 6,
} mesh_task_state_v1_t;

typedef struct {
  uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE];
  uint8_t request_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint8_t holder_node_id[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  mesh_task_state_v1_t state;
  int32_t result_code;
  uint64_t task_deadline_ms;
  uint64_t lease_expires_at_ms;
  uint64_t lease_generation;
  uint64_t fencing_token;
  uint64_t registered_index;
  uint64_t mutation_index;
  uint8_t occupied;
} mesh_task_lease_entry_v1_t;

typedef struct {
  mesh_task_lease_entry_v1_t *entries;
  size_t capacity;
  size_t count;
  uint64_t max_lease_duration_ms;
  uint64_t applied_index;
  uint8_t open;
} mesh_task_lease_store_v1_t;

/** The caller must zero-initialize store before first init. */
mesh_task_lease_result_t mesh_task_lease_store_init_v1(
    mesh_task_lease_store_v1_t *store, size_t capacity,
    uint64_t max_lease_duration_ms);
void mesh_task_lease_store_destroy_v1(mesh_task_lease_store_v1_t *store);

/** Exact duplicate registration is idempotent but still advances applied_index. */
mesh_task_lease_result_t mesh_task_lease_register_v1(
    mesh_task_lease_store_v1_t *store, uint64_t committed_index,
    const uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE],
    const uint8_t request_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    uint64_t task_deadline_ms, mesh_task_lease_entry_v1_t *out_entry);

/** Acquire a READY task. committed_index becomes the worker fencing token. */
mesh_task_lease_result_t mesh_task_lease_acquire_v1(
    mesh_task_lease_store_v1_t *store, uint64_t committed_index,
    const uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE],
    const uint8_t request_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    const uint8_t holder_node_id[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    uint64_t observed_now_ms, uint64_t lease_expires_at_ms,
    mesh_task_lease_entry_v1_t *out_entry);

/** Renew only the current holder/token; renewal publishes a new token. */
mesh_task_lease_result_t mesh_task_lease_renew_v1(
    mesh_task_lease_store_v1_t *store, uint64_t committed_index,
    const uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE],
    const uint8_t request_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    const uint8_t holder_node_id[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    uint64_t expected_fencing_token, uint64_t observed_now_ms,
    uint64_t lease_expires_at_ms, mesh_task_lease_entry_v1_t *out_entry);

/** Release an elapsed lease to READY, or terminalize an elapsed task deadline. */
mesh_task_lease_result_t mesh_task_lease_expire_v1(
    mesh_task_lease_store_v1_t *store, uint64_t committed_index,
    const uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE],
    const uint8_t request_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    uint64_t expected_fencing_token, uint64_t observed_now_ms,
    mesh_task_lease_entry_v1_t *out_entry);

/** Commit a terminal result only from the live holder and latest token. */
mesh_task_lease_result_t mesh_task_lease_complete_v1(
    mesh_task_lease_store_v1_t *store, uint64_t committed_index,
    const uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE],
    const uint8_t request_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    const uint8_t holder_node_id[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    uint64_t expected_fencing_token, uint64_t observed_now_ms,
    mesh_task_state_v1_t terminal_state, int32_t result_code,
    mesh_task_lease_entry_v1_t *out_entry);

mesh_task_lease_result_t mesh_task_lease_get_v1(
    const mesh_task_lease_store_v1_t *store,
    const uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE],
    mesh_task_lease_entry_v1_t *out_entry);

#ifdef __cplusplus
}
#endif

#endif
