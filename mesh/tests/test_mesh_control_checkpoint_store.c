#include "mesh_control_checkpoint_store.h"
#include "tinytest.h"

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

static void cleanup_store_files(const char *path) {
  char lock_path[TURBO_FS_MAX_PATH + 6u];
  char temp_path[TURBO_FS_MAX_PATH + 5u];
  (void)snprintf(lock_path, sizeof(lock_path), "%s.lock", path);
  (void)snprintf(temp_path, sizeof(temp_path), "%s.tmp", path);
  if (turbo_fs_access(path, TURBO_FS_ACCESS_EXISTS) == 0)
    (void)turbo_fs_unlink(path);
  if (turbo_fs_access(lock_path, TURBO_FS_ACCESS_EXISTS) == 0)
    (void)turbo_fs_unlink(lock_path);
  if (turbo_fs_access(temp_path, TURBO_FS_ACCESS_EXISTS) == 0)
    (void)turbo_fs_unlink(temp_path);
}

static void test_store_persists_and_restores_owner(void) {
  mesh_control_checkpoint_store_v1_t store = {0};
  mesh_control_channel_v1_t source_channel;
  mesh_control_channel_v1_t restored_channel;
  mesh_control_owner_v1_t source = {0};
  mesh_control_owner_v1_t restored = {0};
  mesh_control_owner_config_v1_t config;
  mesh_control_envelope_v1_t intent;
  mesh_control_operation_v1_t operation;
  mesh_control_resource_status_v1_t status;
  uint8_t found = 0u;
  char *path = tt_make_temp_file("mesh-control-checkpoint", ".bin");

  check_not_null(path);
  if (!path)
    return;
  cleanup_store_files(path);
  make_config(&config);
  make_intent(&intent);
  check_int_eq(mesh_control_channel_init_v1(&source_channel, 2u, 2048u, 1024u), MESH_CONTROL_OK);
  check_int_eq(mesh_control_channel_init_v1(&restored_channel, 2u, 2048u, 1024u), MESH_CONTROL_OK);
  check_int_eq(mesh_control_owner_init_v1(&source, &source_channel, &config), MESH_CONTROL_OK);
  check_int_eq(mesh_control_owner_init_v1(&restored, &restored_channel, &config), MESH_CONTROL_OK);
  check_int_eq(mesh_control_checkpoint_store_open_v1(&store, path),
               MESH_CONTROL_CHECKPOINT_STORE_OK);
  check_int_eq(mesh_control_checkpoint_store_load_v1(&store, &restored, 1100u, &found),
               MESH_CONTROL_CHECKPOINT_STORE_OK);
  check_false(found);
  check_int_eq(mesh_control_state_submit_document_v1(&source.state, &intent,
                                                     MESH_CONTROL_DESIRED_APPLY,
                                                     (const uint8_t *)"abc", 3u, 1100u, &operation),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_checkpoint_store_save_v1(&store, &source),
               MESH_CONTROL_CHECKPOINT_STORE_OK);
  mesh_control_checkpoint_store_close_v1(&store);

  check_int_eq(mesh_control_checkpoint_store_open_v1(&store, path),
               MESH_CONTROL_CHECKPOINT_STORE_OK);
  check_int_eq(mesh_control_checkpoint_store_load_v1(&store, &restored, 1200u, &found),
               MESH_CONTROL_CHECKPOINT_STORE_OK);
  check_true(found);
  check_int_eq(mesh_control_state_get_resource_v1(&restored.state, intent.resource_kind,
                                                  intent.resource_id, &status),
               MESH_CONTROL_OK);
  check_int_eq(status.desired_epoch, 1u);

  mesh_control_checkpoint_store_close_v1(&store);
  mesh_control_owner_destroy_v1(&restored);
  mesh_control_owner_destroy_v1(&source);
  mesh_control_channel_destroy_v1(&restored_channel);
  mesh_control_channel_destroy_v1(&source_channel);
  cleanup_store_files(path);
  free(path);
}

static void test_store_locks_and_rejects_corruption(void) {
  mesh_control_checkpoint_store_v1_t first = {0};
  mesh_control_checkpoint_store_v1_t second = {0};
  mesh_control_channel_v1_t channel;
  mesh_control_owner_v1_t owner = {0};
  mesh_control_owner_config_v1_t config;
  turbo_fs_buf_t corrupt;
  uint8_t found = 1u;
  char *path = tt_make_temp_file("mesh-control-corrupt", ".bin");

  check_not_null(path);
  if (!path)
    return;
  cleanup_store_files(path);
  make_config(&config);
  check_int_eq(mesh_control_channel_init_v1(&channel, 2u, 2048u, 1024u), MESH_CONTROL_OK);
  check_int_eq(mesh_control_owner_init_v1(&owner, &channel, &config), MESH_CONTROL_OK);
  check_int_eq(mesh_control_checkpoint_store_open_v1(&first, path),
               MESH_CONTROL_CHECKPOINT_STORE_OK);
  check_int_eq(mesh_control_checkpoint_store_open_v1(&second, path),
               MESH_CONTROL_CHECKPOINT_STORE_LOCKED);
  mesh_control_checkpoint_store_close_v1(&first);

  corrupt.base = "corrupt";
  corrupt.len = 7u;
  check_int_eq(turbo_fs_write_file(path, &corrupt), 0);
  check_int_eq(mesh_control_checkpoint_store_open_v1(&second, path),
               MESH_CONTROL_CHECKPOINT_STORE_OK);
  check_int_eq(mesh_control_checkpoint_store_load_v1(&second, &owner, 1100u, &found),
               MESH_CONTROL_CHECKPOINT_STORE_CORRUPT);
  check_false(found);

  mesh_control_checkpoint_store_close_v1(&second);
  mesh_control_owner_destroy_v1(&owner);
  mesh_control_channel_destroy_v1(&channel);
  cleanup_store_files(path);
  free(path);
}

static void test_authenticated_store_rejects_wrong_key_and_tamper(void) {
  mesh_control_checkpoint_store_v1_t store = {0};
  mesh_control_channel_v1_t source_channel = {0};
  mesh_control_channel_v1_t restored_channel = {0};
  mesh_control_owner_v1_t source = {0};
  mesh_control_owner_v1_t restored = {0};
  mesh_control_owner_config_v1_t config;
  mesh_control_envelope_v1_t intent;
  mesh_control_operation_v1_t operation;
  turbo_file_t file = TURBO_INVALID_FILE;
  uint8_t key[MESH_CONTROL_CHECKPOINT_STORE_AUTH_KEY_SIZE_V1];
  uint8_t wrong_key[MESH_CONTROL_CHECKPOINT_STORE_AUTH_KEY_SIZE_V1];
  uint8_t byte = 0u;
  uint8_t found = 0u;
  char *path = tt_make_temp_file("mesh-control-checkpoint-auth", ".bin");

  check_not_null(path);
  if (!path)
    return;
  cleanup_store_files(path);
  memset(key, 0xa5, sizeof(key));
  memset(wrong_key, 0xb6, sizeof(wrong_key));
  make_config(&config);
  make_intent(&intent);
  check_int_eq(mesh_control_channel_init_v1(&source_channel, 2u, 2048u, 1024u), MESH_CONTROL_OK);
  check_int_eq(mesh_control_channel_init_v1(&restored_channel, 2u, 2048u, 1024u), MESH_CONTROL_OK);
  check_int_eq(mesh_control_owner_init_v1(&source, &source_channel, &config), MESH_CONTROL_OK);
  check_int_eq(mesh_control_owner_init_v1(&restored, &restored_channel, &config), MESH_CONTROL_OK);
  check_int_eq(mesh_control_state_submit_document_v1(&source.state, &intent,
                                                     MESH_CONTROL_DESIRED_APPLY,
                                                     (const uint8_t *)"abc", 3u, 1100u, &operation),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_checkpoint_store_open_authenticated_v1(&store, path, key),
               MESH_CONTROL_CHECKPOINT_STORE_OK);
  check_int_eq(mesh_control_checkpoint_store_save_v1(&store, &source),
               MESH_CONTROL_CHECKPOINT_STORE_OK);
  mesh_control_checkpoint_store_close_v1(&store);

  check_int_eq(mesh_control_checkpoint_store_open_authenticated_v1(&store, path, wrong_key),
               MESH_CONTROL_CHECKPOINT_STORE_OK);
  check_int_eq(mesh_control_checkpoint_store_load_v1(&store, &restored, 1200u, &found),
               MESH_CONTROL_CHECKPOINT_STORE_AUTH_FAILED);
  check_false(found);
  mesh_control_checkpoint_store_close_v1(&store);

  file = turbo_fs_open(path, TURBO_FS_O_RDWR, 0);
  check_true(file != TURBO_INVALID_FILE);
  if (file != TURBO_INVALID_FILE) {
    check_int_eq((int)turbo_fs_seek(file, 256, SEEK_SET), 256);
    check_int_eq(turbo_fs_read(file, (char *)&byte, 1u), 1);
    byte ^= 1u;
    check_int_eq((int)turbo_fs_seek(file, 256, SEEK_SET), 256);
    check_int_eq(turbo_fs_write(file, (const char *)&byte, 1u), 1);
    check_int_eq(turbo_fs_close(file), 0);
    file = TURBO_INVALID_FILE;
  }
  check_int_eq(mesh_control_checkpoint_store_open_authenticated_v1(&store, path, key),
               MESH_CONTROL_CHECKPOINT_STORE_OK);
  check_int_eq(mesh_control_checkpoint_store_load_v1(&store, &restored, 1200u, &found),
               MESH_CONTROL_CHECKPOINT_STORE_AUTH_FAILED);
  check_false(found);

  mesh_control_checkpoint_store_close_v1(&store);
  mesh_control_owner_destroy_v1(&restored);
  mesh_control_owner_destroy_v1(&source);
  mesh_control_channel_destroy_v1(&restored_channel);
  mesh_control_channel_destroy_v1(&source_channel);
  cleanup_store_files(path);
  free(path);
}

spec("mesh control durable checkpoint store") {
  describe("single-writer crash-safe persistence") {
    it("persists and restores an owner checkpoint") { test_store_persists_and_restores_owner(); }
    it("locks writers and fails closed on corruption") {
      test_store_locks_and_rejects_corruption();
    }
    it("authenticates production checkpoints and rejects tamper") {
      test_authenticated_store_rejects_wrong_key_and_tamper();
    }
  }
}
