#include "mesh_mgmt_execution_store.h"
#include "mesh_mgmt_crypto.h"
#include <fmt.h>
#include <tinytest.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <sys/wait.h>
#include <unistd.h>
#endif

#ifdef MESH_EXECUTION_SNAPSHOT_TEST_FAULT
/* Only this private symbol is substituted. Injected UNKNOWN always follows
 * a real production filesystem write and durable namespace publication. */
#define mesh_mgmt_execution_snapshot_write mesh_mgmt_execution_snapshot_write_real
#include "mesh_mgmt_execution_snapshot_io.h"
#undef mesh_mgmt_execution_snapshot_write
static int uncertain;
static unsigned publications;
int mesh_mgmt_execution_snapshot_write(
    const char *staging_path, const char *destination, const uint8_t *bytes,
    size_t size, cmeta_fs_replace_state_t *publication) {
  int status = mesh_mgmt_execution_snapshot_write_real(
      staging_path, destination, bytes, size, publication);
  ++publications;
  if (uncertain && status == 0) {
    *publication = SALTS_FS_REPLACE_DURABILITY_UNKNOWN;
    return -EIO;
  }
  return status;
}
#endif

static mesh_mgmt_execution_store_v1_t store, second;
static mesh_mgmt_execution_journal_entry_v1_t entry;
static mesh_mgmt_execution_result_v1_t result, restored;
static uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE];
static uint8_t request_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
static char *path, *contents, *after;
static tstr staging, lock_path;
static int staging_directory;

static void make_signed_result(void) {
  static const uint8_t private_key[32] = {
      1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
      17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
  memset(&result, 0, sizeof(result));
  result.version = MESH_MGMT_EXECUTION_RESULT_VERSION_V1;
  memcpy(result.command_id, command_id, sizeof(command_id));
  memcpy(result.request_digest, request_digest, sizeof(request_digest));
  memset(result.target_node_id, 3, sizeof(result.target_node_id));
  memset(result.deployment_id, 4, sizeof(result.deployment_id));
  result.deployment_generation = 5u;
  memset(result.package_digest, 6, sizeof(result.package_digest));
  result.policy_epoch = 7u;
  memset(result.grant_id, 8, sizeof(result.grant_id));
  result.state = MESH_MGMT_EXECUTION_STATE_SUCCEEDED;
  result.runtime_stage = 7;
  result.usage.invocations = 1u;
  memset(result.stdout_digest, 9, sizeof(result.stdout_digest));
  memset(result.stderr_digest, 10, sizeof(result.stderr_digest));
  result.started_at_ms = 100u;
  result.finished_at_ms = 110u;
  result.worker_generation = 1u;
  memset(result.correlation_id, 11, sizeof(result.correlation_id));
  check_equal(mesh_mgmt_execution_result_sign_v1(&result, private_key),
              MESH_MGMT_EXECUTION_RESULT_OK);
}

static void open_store(void) {
  check_equal(mesh_mgmt_execution_store_open_v1(&store, path, 4u, NULL),
              MESH_MGMT_EXECUTION_STORE_OK);
}
static void expect_writer_lock(void) {
#ifdef _WIN32
    check_equal(mesh_mgmt_execution_store_open_v1(&second, path, 4u, NULL),
                MESH_MGMT_EXECUTION_STORE_LOCKED);
#else
    /* fcntl exclusion is process scoped, so prove it with a real child. */
    pid_t child = fork();
    check_greater_equal(child, 0);
    if (child == 0) {
      mesh_mgmt_execution_store_v1_t other;
      _exit(mesh_mgmt_execution_store_open_v1(&other, path, 4u, NULL) ==
          MESH_MGMT_EXECUTION_STORE_LOCKED ? 0 : 1);
    }
    int status;
    check_equal(waitpid(child, &status, 0), child);
    check_true(WIFEXITED(status));
    check_equal(WEXITSTATUS(status), 0);
#endif
}
static void prepare_running(void) {
  open_store();
  check_equal(mesh_mgmt_execution_store_submit_v1(
      &store, command_id, request_digest, &entry), MESH_MGMT_EXECUTION_STORE_OK);
  check_equal(mesh_mgmt_execution_store_transition_v1(&store, command_id,
      MESH_MGMT_EXECUTION_STATE_STAGING, 0, &entry), MESH_MGMT_EXECUTION_STORE_OK);
  check_equal(mesh_mgmt_execution_store_transition_v1(&store, command_id,
      MESH_MGMT_EXECUTION_STATE_RUNNING, 0, &entry), MESH_MGMT_EXECUTION_STORE_OK);
}
static void expect_signed_result(void) {
  uint8_t canonical[2][MESH_MGMT_EXECUTION_RESULT_CANONICAL_SIZE_V1];
  size_t sizes[2] = {0};
  check_equal(mesh_mgmt_execution_store_get_result_v1(
      &store, command_id, &restored), MESH_MGMT_EXECUTION_STORE_OK);
  check_equal(mesh_mgmt_execution_result_verify_v1(&restored, restored.signer_public_key),
              MESH_MGMT_EXECUTION_RESULT_OK);
  check_equal(mesh_mgmt_execution_result_encode_canonical_v1(
      &result, canonical[0], sizeof(canonical[0]), &sizes[0]), MESH_MGMT_EXECUTION_RESULT_OK);
  check_equal(mesh_mgmt_execution_result_encode_canonical_v1(
      &restored, canonical[1], sizeof(canonical[1]), &sizes[1]), MESH_MGMT_EXECUTION_RESULT_OK);
  check_equal(sizes[0], sizes[1]);
  check_equal(canonical[0], canonical[1], sizes[0]);
  check_equal(restored.signature, result.signature, sizeof(result.signature));
}
static void remove_if_present(const char *file) {
  if (file && cmeta_fs_access(file, SALTS_FS_ACCESS_EXISTS) == 0)
    check_equal(tt_remove_file(file), 0);
}

spec("mesh management durable execution journal E2") {
  before_each() {
    memset(&store, 0, sizeof(store));
    memset(&second, 0, sizeof(second));
    store.lock_file = second.lock_file = SALTS_INVALID_FILE;
    memset(&entry, 0, sizeof(entry));
    memset(&restored, 0, sizeof(restored));
    memset(command_id, 1, sizeof(command_id));
    memset(request_digest, 2, sizeof(request_digest));
    contents = after = NULL;
    staging = lock_path = NULL;
    staging_directory = 0;
#ifdef MESH_EXECUTION_SNAPSHOT_TEST_FAULT
    uncertain = 0;
    publications = 0;
#endif
    path = tt_make_temp_file("mesh-execution-store", ".bin");
    check_not_null(path);
    check_equal(tt_remove_file(path), 0);
    staging = tstr_format("{}.tmp", path);
    lock_path = tstr_format("{}.lock", path);
    check_not_null(staging);
    check_not_null(lock_path);
    make_signed_result();
  }
  after_each() {
    mesh_mgmt_execution_store_close_v1(&second);
    mesh_mgmt_execution_store_close_v1(&store);
    if (staging_directory) check_equal(cmeta_fs_rmdir(staging), 0);
    else remove_if_present(staging);
    remove_if_present(lock_path);
    remove_if_present(path);
    free(contents);
    free(after);
    free(path);
    tstr_freep(&staging);
    tstr_freep(&lock_path);
  }
#ifndef MESH_EXECUTION_SNAPSHOT_TEST_FAULT
  it("persists dedupe and makes interrupted work indeterminate after restart") {
    size_t recovered = 0u;
    prepare_running();
    uint64_t generation = store.journal.generation;
    check_equal(mesh_mgmt_execution_store_submit_v1(
        &store, command_id, request_digest, &entry), MESH_MGMT_EXECUTION_STORE_OK);
    check_equal(store.journal.generation, generation);
    mesh_mgmt_execution_store_close_v1(&store);
    check_equal(mesh_mgmt_execution_store_open_v1(&store, path, 4u, &recovered),
                MESH_MGMT_EXECUTION_STORE_OK);
    check_equal(recovered, 1u);
    check_equal(mesh_mgmt_execution_store_get_v1(&store, command_id, &entry),
                MESH_MGMT_EXECUTION_STORE_OK);
    check_equal(entry.state, MESH_MGMT_EXECUTION_STATE_FAILED_INDETERMINATE);
    check_equal(entry.result_code, MESH_MGMT_EXECUTION_INVALID_STATE);
    check_equal(store.journal.generation, generation + 1u);
    mesh_mgmt_execution_store_close_v1(&store);
    recovered = 99u;
    check_equal(mesh_mgmt_execution_store_open_v1(&store, path, 4u, &recovered),
                MESH_MGMT_EXECUTION_STORE_OK);
    check_equal(recovered, 0u);
    check_equal(store.journal.generation, generation + 1u);
  }
  it("holds the single writer lock until close") {
    open_store();
    expect_writer_lock();
    mesh_mgmt_execution_store_close_v1(&store);
    check_equal(mesh_mgmt_execution_store_open_v1(&second, path, 4u, NULL),
                MESH_MGMT_EXECUTION_STORE_OK);
  }
  it("rejects a corrupt existing snapshot without resetting it") {
    check_equal(tt_write_file(path, "corrupt", 7u), 0);
    check_equal(mesh_mgmt_execution_store_open_v1(&store, path, 4u, NULL),
                MESH_MGMT_EXECUTION_STORE_CORRUPT);
    size_t size = 0;
    contents = tt_read_file(path, &size);
    check_not_null(contents);
    check_equal(size, 7u);
    check_equal(contents, "corrupt", 7u);
    check_equal(store.open, 0u);
    check_equal(store.lock_file, SALTS_INVALID_FILE);
  }
  it("commits terminal state and the identical signed result in one snapshot") {
    prepare_running();
    check_equal(mesh_mgmt_execution_store_transition_v1(&store, command_id,
        MESH_MGMT_EXECUTION_STATE_SUCCEEDED, 0, &entry), MESH_MGMT_EXECUTION_STORE_INVALID_STATE);
    check_equal(mesh_mgmt_execution_store_commit_result_v1(&store, &result, &entry),
                MESH_MGMT_EXECUTION_STORE_OK);
    uint64_t generation = store.journal.generation;
    check_equal(mesh_mgmt_execution_store_commit_result_v1(&store, &result, &entry),
                MESH_MGMT_EXECUTION_STORE_OK);
    check_equal(store.journal.generation, generation);
    mesh_mgmt_execution_store_close_v1(&store);
    open_store();
    expect_signed_result();
    check_equal(store.journal.generation, generation);
    result.finished_at_ms++;
    check_equal(mesh_mgmt_execution_store_commit_result_v1(&store, &result, &entry),
                MESH_MGMT_EXECUTION_STORE_INVALID_ARG);
    check_equal(mesh_mgmt_execution_store_forget_terminal_v1(&store, command_id),
                MESH_MGMT_EXECUTION_STORE_OK);
    uint64_t compacted_generation = store.journal.generation;
    mesh_mgmt_execution_store_close_v1(&store);
    open_store();
    check_equal(mesh_mgmt_execution_store_get_v1(&store, command_id, &entry),
                MESH_MGMT_EXECUTION_STORE_NOT_FOUND);
    check_equal(store.journal.generation, compacted_generation);
  }
  it("rolls back an unpublished submit failure and permits explicit retry") {
    open_store();
    uint64_t generation = store.journal.generation;
    check_equal(cmeta_fs_mkdir(staging, 0700), 0);
    staging_directory = 1;
    check_equal(mesh_mgmt_execution_store_submit_v1(
        &store, command_id, request_digest, &entry), MESH_MGMT_EXECUTION_STORE_IO);
    check_equal(store.open, 1u);
    check_equal(store.journal.count, 0u);
    check_equal(store.journal.generation, generation);
    check_equal(mesh_mgmt_execution_store_get_v1(&store, command_id, &entry),
                MESH_MGMT_EXECUTION_STORE_NOT_FOUND);
    check_equal(cmeta_fs_rmdir(staging), 0);
    staging_directory = 0;
    check_equal(mesh_mgmt_execution_store_submit_v1(
        &store, command_id, request_digest, &entry), MESH_MGMT_EXECUTION_STORE_OK);
  }
  it("keeps the running record and signed result uncommitted on staging failure") {
    prepare_running();
    uint64_t generation = store.journal.generation;
    check_equal(cmeta_fs_mkdir(staging, 0700), 0);
    staging_directory = 1;
    check_equal(mesh_mgmt_execution_store_commit_result_v1(&store, &result, &entry),
                MESH_MGMT_EXECUTION_STORE_IO);
    check_equal(store.journal.generation, generation);
    check_equal(mesh_mgmt_execution_store_get_v1(&store, command_id, &entry),
                MESH_MGMT_EXECUTION_STORE_OK);
    check_equal(entry.state, MESH_MGMT_EXECUTION_STATE_RUNNING);
    check_equal(mesh_mgmt_execution_store_get_result_v1(&store, command_id, &restored),
                MESH_MGMT_EXECUTION_STORE_NOT_FOUND);
    check_equal(cmeta_fs_rmdir(staging), 0);
    staging_directory = 0;
    check_equal(mesh_mgmt_execution_store_commit_result_v1(&store, &result, &entry),
                MESH_MGMT_EXECUTION_STORE_OK);
    expect_signed_result();
  }
  it("rolls back unpublished compaction and retains the signed outcome") {
    prepare_running();
    check_equal(mesh_mgmt_execution_store_commit_result_v1(&store, &result, &entry),
                MESH_MGMT_EXECUTION_STORE_OK);
    uint64_t generation = store.journal.generation;
    check_equal(cmeta_fs_mkdir(staging, 0700), 0);
    staging_directory = 1;
    check_equal(mesh_mgmt_execution_store_forget_terminal_v1(&store, command_id),
                MESH_MGMT_EXECUTION_STORE_IO);
    check_equal(store.journal.generation, generation);
    check_equal(store.journal.count, 1u);
    expect_signed_result();
  }
  it("does not remove nonterminal commands or accept conflicting request identity") {
    prepare_running();
    check_equal(mesh_mgmt_execution_store_forget_terminal_v1(&store, command_id),
                MESH_MGMT_EXECUTION_STORE_INVALID_STATE);
    request_digest[0] ^= 1u;
    check_equal(mesh_mgmt_execution_store_submit_v1(
        &store, command_id, request_digest, &entry), MESH_MGMT_EXECUTION_STORE_CONFLICT);
    check_equal(mesh_mgmt_execution_store_get_result_v1(&store, command_id, &restored),
                MESH_MGMT_EXECUTION_STORE_NOT_FOUND);
  }
  it("retains durable signed results when terminal compaction exhausts generation") {
    prepare_running();
    store.journal.generation = UINT64_MAX - 1u;
    check_equal(mesh_mgmt_execution_store_commit_result_v1(&store, &result, &entry),
                MESH_MGMT_EXECUTION_STORE_OK);
    check_equal(entry.generation, UINT64_MAX);
    check_equal(mesh_mgmt_execution_store_forget_terminal_v1(&store, command_id),
                MESH_MGMT_EXECUTION_STORE_RESOURCE_EXHAUSTED);
    check_equal(store.journal.count, 1u);
    expect_signed_result();
    mesh_mgmt_execution_store_close_v1(&store);
    open_store();
    check_equal(store.journal.generation, UINT64_MAX);
    check_equal(mesh_mgmt_execution_store_commit_result_v1(&store, &result, &entry),
                MESH_MGMT_EXECUTION_STORE_OK);
    check_equal(mesh_mgmt_execution_store_forget_terminal_v1(&store, command_id),
                MESH_MGMT_EXECUTION_STORE_RESOURCE_EXHAUSTED);
    expect_signed_result();
    command_id[0]++;
    check_equal(mesh_mgmt_execution_store_submit_v1(&store, command_id, request_digest, &entry),
                MESH_MGMT_EXECUTION_STORE_RESOURCE_EXHAUSTED);
    check_equal(store.journal.generation, UINT64_MAX);
  }
  it("rejects generation-exhausted restart without rewriting or leaking its lock") {
    prepare_running();
    store.journal.generation = UINT64_MAX - 1u;
    command_id[0]++;
    check_equal(mesh_mgmt_execution_store_submit_v1(&store, command_id, request_digest, &entry),
                MESH_MGMT_EXECUTION_STORE_OK);
    check_equal(entry.generation, UINT64_MAX);
    mesh_mgmt_execution_store_close_v1(&store);
    size_t before_size = 0u, after_size = 0u, recovered = 99u;
    contents = tt_read_file(path, &before_size);
    check_not_null(contents);
    check_equal(mesh_mgmt_execution_store_open_v1(&store, path, 4u, &recovered),
                MESH_MGMT_EXECUTION_STORE_RESOURCE_EXHAUSTED);
    check_equal(recovered, 99u);
    check_equal(store.open, 0u);
    check_equal(store.lock_file, SALTS_INVALID_FILE);
    after = tt_read_file(path, &after_size);
    check_not_null(after);
    check_equal(after_size, before_size);
    check_equal(after, contents, before_size);
    check_equal(mesh_mgmt_execution_store_open_v1(&second, path, 4u, NULL),
                MESH_MGMT_EXECUTION_STORE_RESOURCE_EXHAUSTED);
    check_equal(second.lock_file, SALTS_INVALID_FILE);
  }
  it("durably reopens the legacy v1 format without changing its original bytes") {
    /* Frozen v1 header + ACCEPTED record with SHA-256 integrity. */
    static const uint8_t legacy_snapshot[] = {
        0x54, 0x4d, 0x45, 0x58, 0x4a, 0x4e, 0x4c, 0x31, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x40,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x4a, 0x65, 0xb8, 0xd2, 0x2c, 0xa4, 0x8a, 0x2c, 0xee, 0x26, 0xa8, 0x6d, 0xc9, 0x6a, 0x7a, 0xf5,
        0xa8, 0xae, 0xdb, 0x3d, 0xdc, 0x71, 0xc0, 0x90, 0xf7, 0x48, 0x89, 0x33, 0x95, 0xf0, 0x2a, 0x63,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };
    check_equal(tt_write_file(path, legacy_snapshot, sizeof(legacy_snapshot)), 0);
    open_store();
    check_equal(mesh_mgmt_execution_store_get_v1(&store, command_id, &entry),
                MESH_MGMT_EXECUTION_STORE_OK);
    check_equal(entry.state, MESH_MGMT_EXECUTION_STATE_ACCEPTED);
    check_equal(entry.generation, 1u);
    check_equal(mesh_mgmt_execution_store_submit_v1(&store, command_id, request_digest, &entry),
                MESH_MGMT_EXECUTION_STORE_OK);
    size_t size = 0u;
    contents = tt_read_file(path, &size);
    check_not_null(contents);
    check_equal(size, sizeof(legacy_snapshot));
    check_equal(contents, legacy_snapshot, size);
  }
  it("rejects failed durable reopen without losing the validated disk snapshot") {
    open_store();
    check_equal(mesh_mgmt_execution_store_submit_v1(
        &store, command_id, request_digest, &entry), MESH_MGMT_EXECUTION_STORE_OK);
    mesh_mgmt_execution_store_close_v1(&store);
    size_t before_size = 0u, after_size = 0u;
    contents = tt_read_file(path, &before_size);
    check_not_null(contents);
    check_equal(cmeta_fs_mkdir(staging, 0700), 0);
    staging_directory = 1;
    check_equal(mesh_mgmt_execution_store_open_v1(&store, path, 4u, NULL),
                MESH_MGMT_EXECUTION_STORE_IO);
    check_equal(store.open, 0u);
    check_equal(store.lock_file, SALTS_INVALID_FILE);
    after = tt_read_file(path, &after_size);
    check_not_null(after);
    check_equal(after_size, before_size);
    check_equal(after, contents, before_size);
    check_equal(cmeta_fs_rmdir(staging), 0);
    staging_directory = 0;
    open_store();
    check_equal(mesh_mgmt_execution_store_get_v1(&store, command_id, &entry),
                MESH_MGMT_EXECUTION_STORE_OK);
    check_equal(entry.generation, 1u);
  }

#else
  it("fences all access after uncertain submit and recovers the published disk record") {
    open_store();
    uncertain = 1;
    publications = 0;
    check_equal(mesh_mgmt_execution_store_submit_v1(
        &store, command_id, request_digest, &entry), MESH_MGMT_EXECUTION_STORE_IO);
    check_equal(store.open, 2u);
    check_equal(store.journal.count, 1u);
    check_equal(mesh_mgmt_execution_store_get_v1(&store, command_id, &entry),
                MESH_MGMT_EXECUTION_STORE_IO);
    check_equal(mesh_mgmt_execution_store_get_result_v1(&store, command_id, &restored),
                MESH_MGMT_EXECUTION_STORE_IO);
    check_equal(mesh_mgmt_execution_store_submit_v1(
        &store, command_id, request_digest, &entry), MESH_MGMT_EXECUTION_STORE_IO);
    check_equal(mesh_mgmt_execution_store_transition_v1(&store, command_id,
        MESH_MGMT_EXECUTION_STATE_STAGING, 0, &entry), MESH_MGMT_EXECUTION_STORE_IO);
    check_equal(mesh_mgmt_execution_store_commit_result_v1(&store, &result, &entry),
                MESH_MGMT_EXECUTION_STORE_IO);
    check_equal(mesh_mgmt_execution_store_forget_terminal_v1(&store, command_id),
                MESH_MGMT_EXECUTION_STORE_IO);
    check_equal(publications, 1u);
    expect_writer_lock();
    mesh_mgmt_execution_store_close_v1(&store);
    uncertain = 0;
    open_store();
    check_equal(mesh_mgmt_execution_store_get_v1(&store, command_id, &entry),
                MESH_MGMT_EXECUTION_STORE_OK);
    check_equal(entry.state, MESH_MGMT_EXECUTION_STATE_ACCEPTED);
  }
  it("withholds success after uncertain RESULT publication and reloads its exact signature") {
    prepare_running();
    uncertain = 1;
    publications = 0;
    check_equal(mesh_mgmt_execution_store_commit_result_v1(&store, &result, &entry),
                MESH_MGMT_EXECUTION_STORE_IO);
    check_equal(store.open, 2u);
    check_equal(mesh_mgmt_execution_store_get_result_v1(&store, command_id, &restored),
                MESH_MGMT_EXECUTION_STORE_IO);
    check_equal(mesh_mgmt_execution_store_commit_result_v1(&store, &result, &entry),
                MESH_MGMT_EXECUTION_STORE_IO);
    check_equal(publications, 1u);
    expect_writer_lock();
    mesh_mgmt_execution_store_close_v1(&store);
    uncertain = 0;
    open_store();
    expect_signed_result();
    check_equal(publications, 2u);
    publications = 0;
    check_equal(mesh_mgmt_execution_store_commit_result_v1(&store, &result, &entry),
                MESH_MGMT_EXECUTION_STORE_OK);
    check_equal(publications, 0u);
  }
  it("fences uncertain compaction and reloads the published removal") {
    prepare_running();
    check_equal(mesh_mgmt_execution_store_commit_result_v1(&store, &result, &entry),
                MESH_MGMT_EXECUTION_STORE_OK);
    uint64_t generation = store.journal.generation;
    uncertain = 1;
    publications = 0;
    check_equal(mesh_mgmt_execution_store_forget_terminal_v1(&store, command_id),
                MESH_MGMT_EXECUTION_STORE_IO);
    check_equal(store.open, 2u);
    check_equal(store.journal.count, 0u);
    check_equal(mesh_mgmt_execution_store_get_v1(&store, command_id, &entry),
                MESH_MGMT_EXECUTION_STORE_IO);
    check_equal(mesh_mgmt_execution_store_forget_terminal_v1(&store, command_id),
                MESH_MGMT_EXECUTION_STORE_IO);
    check_equal(publications, 1u);
    expect_writer_lock();
    mesh_mgmt_execution_store_close_v1(&store);
    uncertain = 0;
    open_store();
    check_equal(mesh_mgmt_execution_store_get_v1(&store, command_id, &entry),
                MESH_MGMT_EXECUTION_STORE_NOT_FOUND);
    check_equal(store.journal.generation, generation + 1u);
  }
  it("fails uncertain initialization and releases the writer lock before checked reopen") {
    uncertain = 1;
    check_equal(mesh_mgmt_execution_store_open_v1(&store, path, 4u, NULL),
                MESH_MGMT_EXECUTION_STORE_IO);
    check_equal(store.open, 0u);
    check_equal(store.lock_file, SALTS_INVALID_FILE);
    check_null(store.journal.entries);
    uncertain = 0;
    open_store();
    check_equal(store.journal.count, 0u);
  }
  it("fails uncertain recovery without silently executing an interrupted command again") {
    prepare_running();
    mesh_mgmt_execution_store_close_v1(&store);
    uncertain = 1;
    size_t recovered = 99u;
    check_equal(mesh_mgmt_execution_store_open_v1(&store, path, 4u, &recovered),
                MESH_MGMT_EXECUTION_STORE_IO);
    check_equal(store.open, 0u);
    uncertain = 0;
    recovered = 0u;
    check_equal(mesh_mgmt_execution_store_open_v1(&store, path, 4u, &recovered),
                MESH_MGMT_EXECUTION_STORE_OK);
    check_equal(recovered, 0u);
    check_equal(mesh_mgmt_execution_store_get_v1(&store, command_id, &entry),
                MESH_MGMT_EXECUTION_STORE_OK);
    check_equal(entry.state, MESH_MGMT_EXECUTION_STATE_FAILED_INDETERMINATE);
  }
  it("requires durable admission even when reopen has no interrupted commands") {
    open_store();
    check_equal(mesh_mgmt_execution_store_submit_v1(
        &store, command_id, request_digest, &entry), MESH_MGMT_EXECUTION_STORE_OK);
    mesh_mgmt_execution_store_close_v1(&store);
    uncertain = 1;
    publications = 0;
    size_t recovered = 99u;
    check_equal(mesh_mgmt_execution_store_open_v1(&store, path, 4u, &recovered),
                MESH_MGMT_EXECUTION_STORE_IO);
    check_equal(publications, 1u);
    check_equal(recovered, 99u);
    check_equal(store.open, 0u);
    check_equal(store.lock_file, SALTS_INVALID_FILE);
    uncertain = 0;
    check_equal(mesh_mgmt_execution_store_open_v1(&store, path, 4u, &recovered),
                MESH_MGMT_EXECUTION_STORE_OK);
    check_equal(publications, 2u);
    check_equal(recovered, 0u);
    check_equal(mesh_mgmt_execution_store_get_v1(&store, command_id, &entry),
                MESH_MGMT_EXECUTION_STORE_OK);
    check_equal(entry.state, MESH_MGMT_EXECUTION_STATE_ACCEPTED);
    check_equal(entry.generation, 1u);
  }
#endif
}
