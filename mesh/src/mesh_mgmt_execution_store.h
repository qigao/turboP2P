#ifndef TURBO_P2P_MESH_MGMT_EXECUTION_STORE_H
#define TURBO_P2P_MESH_MGMT_EXECUTION_STORE_H

#include "mesh_mgmt_execution.h"
#include "mesh_mgmt_execution_result.h"
#include "turbo_fs.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_MGMT_EXECUTION_STORE_VERSION 2u

typedef enum {
  MESH_MGMT_EXECUTION_STORE_OK = 0,
  MESH_MGMT_EXECUTION_STORE_INVALID_ARG = -1,
  MESH_MGMT_EXECUTION_STORE_IO = -2,
  MESH_MGMT_EXECUTION_STORE_LOCKED = -3,
  MESH_MGMT_EXECUTION_STORE_CORRUPT = -4,
  MESH_MGMT_EXECUTION_STORE_RESOURCE_EXHAUSTED = -5,
  MESH_MGMT_EXECUTION_STORE_CONFLICT = -6,
  MESH_MGMT_EXECUTION_STORE_NOT_FOUND = -7,
  MESH_MGMT_EXECUTION_STORE_INVALID_STATE = -8,
} mesh_mgmt_execution_store_result_t;

typedef struct {
  mesh_mgmt_execution_result_v1_t result;
  uint8_t occupied;
} mesh_mgmt_execution_stored_result_v1_t;

/**
 * Single-writer durable command journal. Calls are synchronous and must not be
 * made from the Mesh/MMP event loop. One owner must serialize all access.
 */
typedef struct {
  mesh_mgmt_execution_journal_v1_t journal;
  mesh_mgmt_execution_journal_entry_v1_t *rollback_entries;
  mesh_mgmt_execution_stored_result_v1_t *results;
  mesh_mgmt_execution_stored_result_v1_t *rollback_results;
  char path[TURBO_FS_MAX_PATH];
  char temp_path[TURBO_FS_MAX_PATH + 5u];
  char lock_path[TURBO_FS_MAX_PATH + 6u];
  turbo_file_t lock_file;
  uint8_t open;
} mesh_mgmt_execution_store_v1_t;

mesh_mgmt_execution_store_result_t mesh_mgmt_execution_store_open_v1(
    mesh_mgmt_execution_store_v1_t *store, const char *path,
    size_t capacity, size_t *out_recovered);

void mesh_mgmt_execution_store_close_v1(
    mesh_mgmt_execution_store_v1_t *store);

mesh_mgmt_execution_store_result_t mesh_mgmt_execution_store_submit_v1(
    mesh_mgmt_execution_store_v1_t *store,
    const uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE],
    const uint8_t request_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    mesh_mgmt_execution_journal_entry_v1_t *out_entry);

mesh_mgmt_execution_store_result_t mesh_mgmt_execution_store_get_v1(
    const mesh_mgmt_execution_store_v1_t *store,
    const uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE],
    mesh_mgmt_execution_journal_entry_v1_t *out_entry);

mesh_mgmt_execution_store_result_t mesh_mgmt_execution_store_transition_v1(
    mesh_mgmt_execution_store_v1_t *store,
    const uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE],
    mesh_mgmt_execution_state_t next_state, int32_t result_code,
    mesh_mgmt_execution_journal_entry_v1_t *out_entry);

/**
 * Atomically persist a terminal journal transition and its self-verifying
 * signed rich result. Repeating the exact same result is idempotent.
 */
mesh_mgmt_execution_store_result_t
mesh_mgmt_execution_store_commit_result_v1(
    mesh_mgmt_execution_store_v1_t *store,
    const mesh_mgmt_execution_result_v1_t *result,
    mesh_mgmt_execution_journal_entry_v1_t *out_entry);

mesh_mgmt_execution_store_result_t mesh_mgmt_execution_store_get_result_v1(
    const mesh_mgmt_execution_store_v1_t *store,
    const uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE],
    mesh_mgmt_execution_result_v1_t *out_result);

/**
 * Removes one terminal command after its outcome has been committed to the
 * owning control-plane WAL. Non-terminal commands are never removable.
 */
mesh_mgmt_execution_store_result_t
mesh_mgmt_execution_store_forget_terminal_v1(
    mesh_mgmt_execution_store_v1_t *store,
    const uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE]);

#ifdef __cplusplus
}
#endif

#endif
