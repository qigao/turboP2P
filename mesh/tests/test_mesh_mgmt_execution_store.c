#include "mesh_mgmt_execution_store.h"
#include "mesh_mgmt_crypto.h"
#include "tinytest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void fill_bytes(uint8_t *bytes, size_t size, uint8_t value) {
  memset(bytes, value, size);
}

static void make_signed_result(
    mesh_mgmt_execution_result_v1_t *result,
    const uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE],
    const uint8_t request_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE]) {
  static const uint8_t private_key[32] = {
      1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
      17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};

  memset(result, 0, sizeof(*result));
  result->version = MESH_MGMT_EXECUTION_RESULT_VERSION_V1;
  memcpy(result->command_id, command_id, sizeof(result->command_id));
  memcpy(result->request_digest, request_digest,
         sizeof(result->request_digest));
  fill_bytes(result->target_node_id, sizeof(result->target_node_id), 3u);
  fill_bytes(result->deployment_id, sizeof(result->deployment_id), 4u);
  result->deployment_generation = 5u;
  fill_bytes(result->package_digest, sizeof(result->package_digest), 6u);
  result->policy_epoch = 7u;
  fill_bytes(result->grant_id, sizeof(result->grant_id), 8u);
  result->state = MESH_MGMT_EXECUTION_STATE_SUCCEEDED;
  result->runtime_stage = 7;
  result->usage.invocations = 1u;
  fill_bytes(result->stdout_digest, sizeof(result->stdout_digest), 9u);
  fill_bytes(result->stderr_digest, sizeof(result->stderr_digest), 10u);
  result->started_at_ms = 100u;
  result->finished_at_ms = 110u;
  result->worker_generation = 1u;
  fill_bytes(result->correlation_id, sizeof(result->correlation_id), 11u);
  check_int_eq(mesh_mgmt_execution_result_sign_v1(result, private_key),
               MESH_MGMT_EXECUTION_RESULT_OK);
}

static void cleanup_store_files(const char *path) {
  char lock_path[TURBO_FS_MAX_PATH + 6u];
  char temp_path[TURBO_FS_MAX_PATH + 5u];

  (void)snprintf(lock_path, sizeof(lock_path), "%s.lock", path);
  (void)snprintf(temp_path, sizeof(temp_path), "%s.tmp", path);
  /* Only remove files that exist; unlink/stat of a missing file logs ERROR. */
  if (turbo_fs_access(path, TURBO_FS_ACCESS_EXISTS) == 0) (void)turbo_fs_unlink(path);
  if (turbo_fs_access(lock_path, TURBO_FS_ACCESS_EXISTS) == 0) (void)turbo_fs_unlink(lock_path);
  if (turbo_fs_access(temp_path, TURBO_FS_ACCESS_EXISTS) == 0) (void)turbo_fs_unlink(temp_path);
}

static void test_persists_dedupe_and_recovers_running(void) {
  mesh_mgmt_execution_store_v1_t first;
  mesh_mgmt_execution_store_v1_t second;
  mesh_mgmt_execution_journal_entry_v1_t entry;
  uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE];
  uint8_t request_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  size_t recovered = 0u;
  char *path = tt_make_temp_file("mesh-execution-store", ".bin");

  check_not_null(path);
  if (!path)
    return;
  cleanup_store_files(path);
  fill_bytes(command_id, sizeof(command_id), 1u);
  fill_bytes(request_digest, sizeof(request_digest), 2u);

  check_int_eq(mesh_mgmt_execution_store_open_v1(&first, path, 4u, NULL),
               MESH_MGMT_EXECUTION_STORE_OK);
  check_int_eq(mesh_mgmt_execution_store_submit_v1(
                   &first, command_id, request_digest, &entry),
               MESH_MGMT_EXECUTION_STORE_OK);
  check_int_eq(mesh_mgmt_execution_store_submit_v1(
                   &first, command_id, request_digest, &entry),
               MESH_MGMT_EXECUTION_STORE_OK);
  check_int_eq(mesh_mgmt_execution_store_transition_v1(
                   &first, command_id, MESH_MGMT_EXECUTION_STATE_STAGING,
                   0, &entry),
               MESH_MGMT_EXECUTION_STORE_OK);
  check_int_eq(mesh_mgmt_execution_store_transition_v1(
                   &first, command_id, MESH_MGMT_EXECUTION_STATE_RUNNING,
                   0, &entry),
               MESH_MGMT_EXECUTION_STORE_OK);
  check_int_eq(mesh_mgmt_execution_store_open_v1(&second, path, 4u, NULL),
               MESH_MGMT_EXECUTION_STORE_LOCKED);
  mesh_mgmt_execution_store_close_v1(&first);

  check_int_eq(mesh_mgmt_execution_store_open_v1(
                   &second, path, 4u, &recovered),
               MESH_MGMT_EXECUTION_STORE_OK);
  check_size_eq(recovered, 1u);
  check_int_eq(mesh_mgmt_execution_store_get_v1(
                   &second, command_id, &entry),
               MESH_MGMT_EXECUTION_STORE_OK);
  check_int_eq(entry.state,
               MESH_MGMT_EXECUTION_STATE_FAILED_INDETERMINATE);
  check_int_eq(entry.result_code, MESH_MGMT_EXECUTION_INVALID_STATE);
  mesh_mgmt_execution_store_close_v1(&second);
  cleanup_store_files(path);
  free(path);
}

static void test_rejects_corrupt_snapshot(void) {
  mesh_mgmt_execution_store_v1_t store;
  turbo_fs_buf_t data;
  char *path = tt_make_temp_file("mesh-execution-corrupt", ".bin");

  check_not_null(path);
  if (!path)
    return;
  data.base = "corrupt";
  data.len = 7u;
  check_int_eq(turbo_fs_write_file(path, &data), 0);
  check_int_eq(mesh_mgmt_execution_store_open_v1(&store, path, 2u, NULL),
               MESH_MGMT_EXECUTION_STORE_CORRUPT);
  cleanup_store_files(path);
  free(path);
}

static void test_atomically_persists_terminal_result(void) {
  mesh_mgmt_execution_store_v1_t store;
  mesh_mgmt_execution_journal_entry_v1_t entry;
  mesh_mgmt_execution_result_v1_t result;
  mesh_mgmt_execution_result_v1_t restored;
  uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE];
  uint8_t request_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  char *path = tt_make_temp_file("mesh-execution-result-store", ".bin");

  check_not_null(path);
  if (!path)
    return;
  cleanup_store_files(path);
  fill_bytes(command_id, sizeof(command_id), 12u);
  fill_bytes(request_digest, sizeof(request_digest), 13u);
  make_signed_result(&result, command_id, request_digest);

  check_int_eq(mesh_mgmt_execution_store_open_v1(&store, path, 2u, NULL),
               MESH_MGMT_EXECUTION_STORE_OK);
  check_int_eq(mesh_mgmt_execution_store_submit_v1(
                   &store, command_id, request_digest, &entry),
               MESH_MGMT_EXECUTION_STORE_OK);
  check_int_eq(mesh_mgmt_execution_store_transition_v1(
                   &store, command_id, MESH_MGMT_EXECUTION_STATE_STAGING,
                   0, &entry),
               MESH_MGMT_EXECUTION_STORE_OK);
  check_int_eq(mesh_mgmt_execution_store_transition_v1(
                   &store, command_id, MESH_MGMT_EXECUTION_STATE_RUNNING,
                   0, &entry),
               MESH_MGMT_EXECUTION_STORE_OK);
  check_int_eq(mesh_mgmt_execution_store_transition_v1(
                   &store, command_id, MESH_MGMT_EXECUTION_STATE_SUCCEEDED,
                   0, &entry),
               MESH_MGMT_EXECUTION_STORE_INVALID_STATE);
  check_int_eq(mesh_mgmt_execution_store_commit_result_v1(
                   &store, &result, &entry),
               MESH_MGMT_EXECUTION_STORE_OK);
  check_int_eq(mesh_mgmt_execution_store_commit_result_v1(
                   &store, &result, &entry),
               MESH_MGMT_EXECUTION_STORE_OK);
  mesh_mgmt_execution_store_close_v1(&store);

  check_int_eq(mesh_mgmt_execution_store_open_v1(&store, path, 2u, NULL),
               MESH_MGMT_EXECUTION_STORE_OK);
  check_int_eq(mesh_mgmt_execution_store_get_result_v1(
                   &store, command_id, &restored),
               MESH_MGMT_EXECUTION_STORE_OK);
  check_mem_eq(restored.signature, result.signature,
               sizeof(result.signature));
  check_int_eq(mesh_mgmt_execution_result_verify_v1(
                   &restored, restored.signer_public_key),
               MESH_MGMT_EXECUTION_RESULT_OK);
  result.finished_at_ms++;
  check_int_eq(mesh_mgmt_execution_store_commit_result_v1(
                   &store, &result, &entry),
               MESH_MGMT_EXECUTION_STORE_INVALID_ARG);
  mesh_mgmt_execution_store_close_v1(&store);
  cleanup_store_files(path);
  free(path);
}

spec("mesh management durable execution journal E2") {
  describe("single-writer persistence") {
    it("persists dedupe and makes interrupted work indeterminate") {
      test_persists_dedupe_and_recovers_running();
    }
    it("fails fast on a corrupt snapshot") {
      test_rejects_corrupt_snapshot();
    }
    it("commits terminal state and signed result in one snapshot") {
      test_atomically_persists_terminal_result();
    }
  }
}
