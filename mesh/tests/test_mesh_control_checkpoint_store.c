#include "mesh_control_checkpoint_store.h"
#include "tinytest.h"
#include <fmt.h>
#include <openssl/evp.h>
#ifndef _WIN32
#include <sys/wait.h>
#include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void make_config(mesh_control_owner_config_v1_t *config) {
  memset(config, 0, sizeof(*config));
  config->state.resource_capacity = 2u;
  config->state.operation_capacity = 2u;
  config->state.event_capacity = 4u;
  config->state.terminal_retention_ms = 500u;
  config->state.desired_document_max_bytes = 1024u;
  config->state.desired_document_retained_bytes = 2048u;
  config->replay.capacity = 4u;
  config->replay.ttl_ms = 1000u;
  config->mesh_id[0] = 1u;
  config->node_id[0] = 2u;
  config->replay_binding.principal_key[0] = 3u;
  config->replay_binding.principal_epoch = 4u;
  config->replay_binding.incarnation = 5u;
  config->replay_binding.session_id[0] = 6u;
}

static void make_intent(mesh_control_envelope_v1_t *envelope) {
  memset(envelope, 0, sizeof(*envelope));
  envelope->schema_version = MESH_CONTROL_SCHEMA_V1;
  envelope->kind = MESH_CONTROL_MESSAGE_INTENT;
  envelope->message_id[0] = 1u;
  envelope->request_id[0] = 2u;
  envelope->mesh_id[0] = 1u;
  envelope->origin_principal[0] = 3u;
  envelope->target_node_id[0] = 2u;
  envelope->resource_kind = MESH_CONTROL_RESOURCE_NETWORK;
  envelope->resource_id[0] = 3u;
  envelope->epoch = 1u;
  envelope->sequence = 1u;
  envelope->issued_at_ms = 1000u;
  envelope->expires_at_ms = 2000u;
  envelope->payload_digest[0] = 4u;
  envelope->payload_size = 3u;
}

static mesh_control_checkpoint_store_v1_t store, first, second;
static mesh_control_owner_v1_t source, restored, owner;
static mesh_control_channel_v1_t source_channel, restored_channel, channel;
static cmeta_file_t file;
static char *path;
static tstr lock_path, staging;
static cmeta_fs_buf_t before_bytes, after_bytes;
static uint8_t *checkpoint;
static int staging_directory, path_directory;

static void cleanup_store_files(const char *name) {
  if (cmeta_fs_access(name, SALTS_FS_ACCESS_EXISTS) == 0)
    check_equal(cmeta_fs_unlink(name), 0);
  if (cmeta_fs_access(lock_path, SALTS_FS_ACCESS_EXISTS) == 0)
    check_equal(cmeta_fs_unlink(lock_path), 0);
  if (cmeta_fs_access(staging, SALTS_FS_ACCESS_EXISTS) == 0)
    check_equal(cmeta_fs_unlink(staging), 0);
}

static void set_test_path(const char *prefix) {
  path = tt_make_temp_file(prefix, ".bin");
  check_not_null(path);
  lock_path = tstr_format("{}.lock", path);
  staging = tstr_format("{}.tmp", path);
  check_not_null(lock_path);
  check_not_null(staging);
  cleanup_store_files(path);
}

static void expect_writer_lock(void) {
#ifdef _WIN32
  check_equal(mesh_control_checkpoint_store_open_v1(&second, path),
      MESH_CONTROL_CHECKPOINT_STORE_LOCKED);
#else
  pid_t child = fork();
  check_greater_equal(child, 0);
  if (child == 0) {
    mesh_control_checkpoint_store_v1_t other = {0};
    _exit(mesh_control_checkpoint_store_open_v1(&other, path) ==
        MESH_CONTROL_CHECKPOINT_STORE_LOCKED ? 0 : 1);
  }
  int status;
  check_equal(waitpid(child, &status, 0), child);
  check_true(WIFEXITED(status));
  check_equal(WEXITSTATUS(status), 0);
#endif
}

#ifdef MESH_CONTROL_CHECKPOINT_TEST_FAULT
#define mesh_control_checkpoint_snapshot_write mesh_control_checkpoint_snapshot_write_real
#include "mesh_control_checkpoint_snapshot_io.h"
#undef mesh_control_checkpoint_snapshot_write
#include <errno.h>
static int uncertain;
static unsigned publications;
int mesh_control_checkpoint_snapshot_write(const char *temp, const char *destination,
    const uint8_t *bytes, size_t size, const uint8_t *tag, size_t tag_size,
    cmeta_fs_replace_state_t *publication) {
  publications++;
  int status = mesh_control_checkpoint_snapshot_write_real(
      temp, destination, bytes, size, tag, tag_size, publication);
  if (uncertain && !status) {
    if (uncertain != 3) *publication = SALTS_FS_REPLACE_DURABILITY_UNKNOWN;
    return uncertain == 2 ? 0 : -EIO;
  }
  return status;
}
#endif

static void test_store_persists_and_restores_owner(void) {
  mesh_control_owner_config_v1_t config;
  mesh_control_envelope_v1_t intent;
  mesh_control_operation_v1_t operation;
  mesh_control_resource_status_v1_t status;
  uint8_t found = 0u;
  set_test_path("mesh-control-checkpoint");

  check_not_null(path);
  if (!path)
    return;
  cleanup_store_files(path);
  make_config(&config);
  make_intent(&intent);
  check_equal(mesh_control_channel_init_v1(&source_channel, 2u, 2048u, 1024u), MESH_CONTROL_OK);
  check_equal(mesh_control_channel_init_v1(&restored_channel, 2u, 2048u, 1024u), MESH_CONTROL_OK);
  check_equal(mesh_control_owner_init_v1(&source, &source_channel, &config), MESH_CONTROL_OK);
  check_equal(mesh_control_owner_init_v1(&restored, &restored_channel, &config), MESH_CONTROL_OK);
  check_equal(mesh_control_checkpoint_store_open_v1(&store, path),
               MESH_CONTROL_CHECKPOINT_STORE_OK);
  check_equal(mesh_control_checkpoint_store_load_v1(&store, &restored, 1100u, &found),
               MESH_CONTROL_CHECKPOINT_STORE_OK);
  check_false(found);
  check_equal(mesh_control_state_submit_document_v1(&source.state, &intent,
                                                     MESH_CONTROL_DESIRED_APPLY,
                                                     (const uint8_t *)"abc", 3u, 1100u, &operation),
               MESH_CONTROL_OK);
  check_equal(mesh_control_checkpoint_store_save_v1(&store, &source),
               MESH_CONTROL_CHECKPOINT_STORE_OK);
  mesh_control_checkpoint_store_close_v1(&store);

  check_equal(mesh_control_checkpoint_store_open_v1(&store, path),
               MESH_CONTROL_CHECKPOINT_STORE_OK);
  check_equal(mesh_control_checkpoint_store_load_v1(&store, &restored, 1200u, &found),
               MESH_CONTROL_CHECKPOINT_STORE_OK);
  check_true(found);
  check_equal(mesh_control_state_get_resource_v1(&restored.state, intent.resource_kind,
                                                  intent.resource_id, &status),
               MESH_CONTROL_OK);
  check_equal(status.desired_epoch, 1u);

  mesh_control_checkpoint_store_close_v1(&store);
  mesh_control_owner_destroy_v1(&restored);
  mesh_control_owner_destroy_v1(&source);
  mesh_control_channel_destroy_v1(&restored_channel);
  mesh_control_channel_destroy_v1(&source_channel);
  cleanup_store_files(path);

}

static void test_store_locks_and_rejects_corruption(void) {
  mesh_control_owner_config_v1_t config;
  cmeta_fs_buf_t corrupt;
  uint8_t found = 1u;
  set_test_path("mesh-control-corrupt");

  check_not_null(path);
  if (!path)
    return;
  cleanup_store_files(path);
  make_config(&config);
  check_equal(mesh_control_channel_init_v1(&channel, 2u, 2048u, 1024u), MESH_CONTROL_OK);
  check_equal(mesh_control_owner_init_v1(&owner, &channel, &config), MESH_CONTROL_OK);
  check_equal(mesh_control_checkpoint_store_open_v1(&first, path),
               MESH_CONTROL_CHECKPOINT_STORE_OK);
  expect_writer_lock();
  mesh_control_checkpoint_store_close_v1(&first);

  corrupt.base = "corrupt";
  corrupt.len = 7u;
  check_equal(cmeta_fs_write_file(path, &corrupt), 0);
  check_equal(mesh_control_checkpoint_store_open_v1(&second, path),
               MESH_CONTROL_CHECKPOINT_STORE_OK);
  check_equal(mesh_control_checkpoint_store_load_v1(&second, &owner, 1100u, &found),
               MESH_CONTROL_CHECKPOINT_STORE_CORRUPT);
  check_false(found);

  mesh_control_checkpoint_store_close_v1(&second);
  mesh_control_owner_destroy_v1(&owner);
  mesh_control_channel_destroy_v1(&channel);
  cleanup_store_files(path);

}

static void test_authenticated_store_rejects_wrong_key_and_tamper(void) {
  mesh_control_owner_config_v1_t config;
  mesh_control_envelope_v1_t intent;
  mesh_control_operation_v1_t operation;
  uint8_t key[MESH_CONTROL_CHECKPOINT_STORE_AUTH_KEY_SIZE_V1];
  uint8_t wrong_key[MESH_CONTROL_CHECKPOINT_STORE_AUTH_KEY_SIZE_V1];
  uint8_t byte = 0u;
  uint8_t found = 0u;
  set_test_path("mesh-control-checkpoint-auth");

  check_not_null(path);
  if (!path)
    return;
  cleanup_store_files(path);
  memset(key, 0xa5, sizeof(key));
  memset(wrong_key, 0xb6, sizeof(wrong_key));
  make_config(&config);
  make_intent(&intent);
  check_equal(mesh_control_channel_init_v1(&source_channel, 2u, 2048u, 1024u), MESH_CONTROL_OK);
  check_equal(mesh_control_channel_init_v1(&restored_channel, 2u, 2048u, 1024u), MESH_CONTROL_OK);
  check_equal(mesh_control_owner_init_v1(&source, &source_channel, &config), MESH_CONTROL_OK);
  check_equal(mesh_control_owner_init_v1(&restored, &restored_channel, &config), MESH_CONTROL_OK);
  check_equal(mesh_control_state_submit_document_v1(&source.state, &intent,
                                                     MESH_CONTROL_DESIRED_APPLY,
                                                     (const uint8_t *)"abc", 3u, 1100u, &operation),
               MESH_CONTROL_OK);
  check_equal(mesh_control_checkpoint_store_open_authenticated_v1(&store, path, key),
               MESH_CONTROL_CHECKPOINT_STORE_OK);
  check_equal(mesh_control_checkpoint_store_save_v1(&store, &source),
               MESH_CONTROL_CHECKPOINT_STORE_OK);
  mesh_control_checkpoint_store_close_v1(&store);

  check_equal(mesh_control_checkpoint_store_open_authenticated_v1(&store, path, wrong_key),
               MESH_CONTROL_CHECKPOINT_STORE_OK);
  check_equal(mesh_control_checkpoint_store_load_v1(&store, &restored, 1200u, &found),
               MESH_CONTROL_CHECKPOINT_STORE_AUTH_FAILED);
  check_false(found);
  mesh_control_checkpoint_store_close_v1(&store);

  file = cmeta_fs_open(path, SALTS_FS_O_RDWR, 0);
  check_true(file != SALTS_INVALID_FILE);
  if (file != SALTS_INVALID_FILE) {
    check_equal((int)cmeta_fs_seek(file, 256, SEEK_SET), 256);
    check_equal(cmeta_fs_read(file, (char *)&byte, 1u), 1);
    byte ^= 1u;
    check_equal((int)cmeta_fs_seek(file, 256, SEEK_SET), 256);
    check_equal(cmeta_fs_write(file, (const char *)&byte, 1u), 1);
    check_equal(cmeta_fs_close(file), 0);
    file = SALTS_INVALID_FILE;
  }
  check_equal(mesh_control_checkpoint_store_open_authenticated_v1(&store, path, key),
               MESH_CONTROL_CHECKPOINT_STORE_OK);
  check_equal(mesh_control_checkpoint_store_load_v1(&store, &restored, 1200u, &found),
               MESH_CONTROL_CHECKPOINT_STORE_AUTH_FAILED);
  check_false(found);

  mesh_control_checkpoint_store_close_v1(&store);
  mesh_control_owner_destroy_v1(&restored);
  mesh_control_owner_destroy_v1(&source);
  mesh_control_channel_destroy_v1(&restored_channel);
  mesh_control_channel_destroy_v1(&source_channel);
  cleanup_store_files(path);

}

static void prepare_empty_authenticated_store(void) {
  mesh_control_owner_config_v1_t config;
  uint8_t key[MESH_CONTROL_CHECKPOINT_STORE_AUTH_KEY_SIZE_V1];
  memset(key, 0xa5, sizeof(key));
  make_config(&config);
  set_test_path("mesh-checkpoint-publication");
  check_equal(mesh_control_channel_init_v1(&source_channel, 2u, 2048u, 1024u), MESH_CONTROL_OK);
  check_equal(mesh_control_channel_init_v1(&restored_channel, 2u, 2048u, 1024u), MESH_CONTROL_OK);
  check_equal(mesh_control_owner_init_v1(&source, &source_channel, &config), MESH_CONTROL_OK);
  check_equal(mesh_control_owner_init_v1(&restored, &restored_channel, &config), MESH_CONTROL_OK);
  check_equal(mesh_control_owner_advance_log_index_v1(&source, 1u), MESH_CONTROL_OK);
  check_equal(mesh_control_checkpoint_store_open_authenticated_v1(&store, path, key),
      MESH_CONTROL_CHECKPOINT_STORE_OK);
  check_equal(mesh_control_checkpoint_store_save_v1(&store, &source), MESH_CONTROL_CHECKPOINT_STORE_OK);
  check_equal(cmeta_fs_read_file(path, &before_bytes), 0);
}

static void test_exact_republication(void) {
  uint8_t found = 0u;
  prepare_empty_authenticated_store();
  const mesh_control_checkpoint_store_v1_t *reader = &store;
  check_equal(mesh_control_checkpoint_store_load_v1(reader, &restored, 1100u, &found),
      MESH_CONTROL_CHECKPOINT_STORE_OK);
  check_true(found);
  check_equal(restored.committed_log_index, 1u);
  check_equal(cmeta_fs_read_file(path, &after_bytes), 0);
  check_equal(after_bytes.len, before_bytes.len);
  check_equal(after_bytes.base, before_bytes.base, before_bytes.len);
}

static void test_v1_republication_preserves_format(void) {
  enum { HEADER_SIZE = 256, VERSION_OFFSET = 8, LOG_INDEX_OFFSET = 216, DIGEST_OFFSET = 224 };
  size_t size = 0u;
  unsigned int digest_size = 0u;
  uint8_t digest[32];
  uint8_t found = 0u;
  prepare_empty_authenticated_store();
  check_equal(mesh_control_checkpoint_encode_v1(&source, &checkpoint, &size), MESH_CONTROL_CHECKPOINT_OK);
  check_greater_equal(size, (size_t)HEADER_SIZE);
  memset(checkpoint + VERSION_OFFSET, 0, 4u); checkpoint[VERSION_OFFSET + 3] = 1u;
  memset(checkpoint + LOG_INDEX_OFFSET, 0, 8u); memset(checkpoint + DIGEST_OFFSET, 0, 32u);
  check_equal(EVP_Digest(checkpoint, size, digest, &digest_size, EVP_sha256(), NULL), 1);
  check_equal(digest_size, 32u); memcpy(checkpoint + DIGEST_OFFSET, digest, 32u);
  check_equal(mesh_control_checkpoint_store_save_bytes_v1(&store, checkpoint, size),
      MESH_CONTROL_CHECKPOINT_STORE_OK);
  cmeta_fs_buf_free(&before_bytes);
  check_equal(cmeta_fs_read_file(path, &before_bytes), 0);
  check_equal(mesh_control_checkpoint_store_load_v1(&store, &restored, 1100u, &found),
      MESH_CONTROL_CHECKPOINT_STORE_OK);
  check_true(found); check_equal(restored.committed_log_index, 0u);
  check_equal(cmeta_fs_read_file(path, &after_bytes), 0);
  check_equal(after_bytes.len, before_bytes.len);
  check_equal(after_bytes.base, before_bytes.base, before_bytes.len);
}

static void test_failed_staging_keeps_file_and_owner(void) {
  uint8_t found = 1u;
  mesh_control_state_usage_v1_t usage;
  prepare_empty_authenticated_store();
  check_equal(cmeta_fs_mkdir(staging, 0700), 0); staging_directory = 1;
  check_equal(mesh_control_owner_advance_log_index_v1(&source, 2u), MESH_CONTROL_OK);
  check_equal(mesh_control_checkpoint_store_save_v1(&store, &source), MESH_CONTROL_CHECKPOINT_STORE_IO);
  check_equal(mesh_control_checkpoint_store_load_v1(&store, &restored, 1100u, &found),
      MESH_CONTROL_CHECKPOINT_STORE_IO);
  check_false(found);
  check_equal(restored.committed_log_index, 0u);
  check_equal(mesh_control_state_get_usage_v1(&restored.state, &usage), MESH_CONTROL_OK);
  check_equal(usage.resource_count, 0u);
  check_equal(cmeta_fs_read_file(path, &after_bytes), 0);
  check_equal(after_bytes.len, before_bytes.len);
  check_equal(after_bytes.base, before_bytes.base, before_bytes.len);
  check_equal(cmeta_fs_rmdir(staging), 0); staging_directory = 0;
  check_equal(mesh_control_checkpoint_store_save_v1(&store, &source), MESH_CONTROL_CHECKPOINT_STORE_OK);
  check_equal(mesh_control_checkpoint_store_load_v1(&store, &restored, 1100u, &found),
      MESH_CONTROL_CHECKPOINT_STORE_OK);
  check_true(found);
  check_equal(restored.committed_log_index, 2u);
}

static void test_invalid_owner_binding_never_publishes(void) {
  uint8_t found = 1u;
  prepare_empty_authenticated_store();
  check_equal(cmeta_fs_mkdir(staging, 0700), 0); staging_directory = 1;
  restored.config.mesh_id[0] ^= 1u;
  check_equal(mesh_control_checkpoint_store_load_v1(&store, &restored, 1100u, &found),
      MESH_CONTROL_CHECKPOINT_STORE_BINDING_MISMATCH);
  check_false(found);
  check_equal(restored.committed_log_index, 0u);
  check_equal(cmeta_fs_read_file(path, &after_bytes), 0);
  check_equal(after_bytes.len, before_bytes.len);
  check_equal(after_bytes.base, before_bytes.base, before_bytes.len);
}

static void test_directory_is_not_first_start(void) {
  uint8_t found = 1u;
  prepare_empty_authenticated_store();
  check_equal(cmeta_fs_unlink(path), 0);
  check_equal(cmeta_fs_mkdir(path, 0700), 0); path_directory = 1;
  check_equal(mesh_control_checkpoint_store_load_v1(&store, &restored, 1100u, &found),
      MESH_CONTROL_CHECKPOINT_STORE_CORRUPT);
  check_false(found);
  check_equal(restored.committed_log_index, 0u);
}

#ifdef MESH_CONTROL_CHECKPOINT_TEST_FAULT
static void test_unknown_publication_never_commits_owner(int mode) {
  uint8_t found = 1u;
  prepare_empty_authenticated_store();
  publications = 0u; uncertain = mode;
  check_equal(mesh_control_checkpoint_store_save_v1(&store, &source), MESH_CONTROL_CHECKPOINT_STORE_IO);
  check_equal(publications, 1u);
  expect_writer_lock();
  check_equal(mesh_control_checkpoint_store_load_v1(&store, &restored, 1100u, &found),
      MESH_CONTROL_CHECKPOINT_STORE_IO);
  check_equal(publications, 2u);
  check_false(found);
  check_equal(restored.committed_log_index, 0u);
  uncertain = 0;
  check_equal(mesh_control_checkpoint_store_load_v1(&store, &restored, 1100u, &found),
      MESH_CONTROL_CHECKPOINT_STORE_OK);
  check_true(found);
  check_equal(restored.committed_log_index, 1u);
  check_equal(cmeta_fs_read_file(path, &after_bytes), 0);
  check_equal(after_bytes.len, before_bytes.len);
  check_equal(after_bytes.base, before_bytes.base, before_bytes.len);
}
#endif

spec("mesh control durable checkpoint store") {
  before_each() {
    memset(&store, 0, sizeof(store)); store.lock_file = SALTS_INVALID_FILE;
    memset(&first, 0, sizeof(first)); first.lock_file = SALTS_INVALID_FILE;
    memset(&second, 0, sizeof(second)); second.lock_file = SALTS_INVALID_FILE;
    memset(&source, 0, sizeof(source)); memset(&restored, 0, sizeof(restored));
    memset(&owner, 0, sizeof(owner)); memset(&channel, 0, sizeof(channel));
    memset(&source_channel, 0, sizeof(source_channel));
    memset(&restored_channel, 0, sizeof(restored_channel));
    file = SALTS_INVALID_FILE; path = NULL; lock_path = NULL; staging = NULL;
    checkpoint = NULL; staging_directory = 0; path_directory = 0;
    memset(&before_bytes, 0, sizeof(before_bytes)); memset(&after_bytes, 0, sizeof(after_bytes));
#ifdef MESH_CONTROL_CHECKPOINT_TEST_FAULT
    uncertain = 0; publications = 0u;
#endif
  }
  after_each() {
    if (file != SALTS_INVALID_FILE) (void)cmeta_fs_close(file);
    mesh_control_checkpoint_store_close_v1(&store);
    mesh_control_checkpoint_store_close_v1(&first);
    mesh_control_checkpoint_store_close_v1(&second);
    mesh_control_owner_destroy_v1(&source); mesh_control_owner_destroy_v1(&restored);
    mesh_control_owner_destroy_v1(&owner); mesh_control_channel_destroy_v1(&channel);
    mesh_control_channel_destroy_v1(&source_channel);
    mesh_control_channel_destroy_v1(&restored_channel);
    if (staging_directory) (void)cmeta_fs_rmdir(staging);
    if (path_directory) (void)cmeta_fs_rmdir(path);
    if (path && lock_path && staging) cleanup_store_files(path);
    cmeta_fs_buf_free(&before_bytes); cmeta_fs_buf_free(&after_bytes);
    mesh_control_checkpoint_free_v1(checkpoint);
    free(path); tstr_free(lock_path); tstr_free(staging);
  }
  describe("single-writer crash-safe persistence") {
    it("preserves V1 checkpoint bytes and HMAC without upgrading the format") {
      test_v1_republication_preserves_format();
    }
    it("durably republishes the exact authenticated bytes before owner restore") {
      test_exact_republication();
    }
    it("preserves the snapshot and owner on staging failure and permits an explicit retry") {
      test_failed_staging_keeps_file_and_owner();
    }
    it("validates owner binding before any republication") {
      test_invalid_owner_binding_never_publishes();
    }
    it("rejects a directory checkpoint instead of treating it as first start") {
      test_directory_is_not_first_start();
    }
#ifdef MESH_CONTROL_CHECKPOINT_TEST_FAULT
    it("keeps the owner unchanged when real publication reports unknown durability") {
      test_unknown_publication_never_commits_owner(1);
    }
    it("rejects a successful status with an unknown publication state") {
      test_unknown_publication_never_commits_owner(2);
    }
    it("rejects a failed status even when publication reports durable") {
      test_unknown_publication_never_commits_owner(3);
    }
#endif
    it("persists and restores an owner checkpoint") { test_store_persists_and_restores_owner(); }
    it("locks writers and fails closed on corruption") {
      test_store_locks_and_rejects_corruption();
    }
    it("authenticates production checkpoints and rejects tamper") {
      test_authenticated_store_rejects_wrong_key_and_tamper();
    }
  }
}
