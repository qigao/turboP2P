#include "mesh_control_mmp.h"
#include "mesh_control_wal_worker.h"
#include "mesh_mgmt_crypto.h"
#include "tinytest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t TEST_PRIVATE_KEY[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};

typedef struct {
  size_t count;
  uint64_t last_index;
} recovery_capture_v1_t;

static void cleanup_wal_files(const char *path) {
  char lock_path[TURBO_FS_MAX_PATH];
  (void)snprintf(lock_path, sizeof(lock_path), "%s.lock", path);
  if (turbo_fs_access(path, TURBO_FS_ACCESS_EXISTS) == 0)
    (void)turbo_fs_unlink(path);
  if (turbo_fs_access(lock_path, TURBO_FS_ACCESS_EXISTS) == 0)
    (void)turbo_fs_unlink(lock_path);
}

static void cleanup_checkpoint_files(const char *path) {
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

static void make_owner_config(mesh_control_owner_config_v1_t *owner_config,
                              const mesh_control_wal_config_v1_t *wal_config) {
  memset(owner_config, 0, sizeof(*owner_config));
  owner_config->state.resource_capacity = 2u;
  owner_config->state.operation_capacity = 2u;
  owner_config->state.event_capacity = 4u;
  owner_config->state.terminal_retention_ms = 500u;
  owner_config->state.desired_document_max_bytes = 1024u;
  owner_config->state.desired_document_retained_bytes = 2048u;
  owner_config->replay.capacity = 4u;
  owner_config->replay.ttl_ms = 1000u;
  memcpy(owner_config->mesh_id, wal_config->mesh_id, sizeof(owner_config->mesh_id));
  memcpy(owner_config->node_id, wal_config->node_id, sizeof(owner_config->node_id));
  memcpy(owner_config->replay_binding.principal_key, wal_config->controller_principal,
         sizeof(owner_config->replay_binding.principal_key));
  owner_config->replay_binding.principal_epoch = wal_config->principal_epoch;
  owner_config->replay_binding.incarnation = wal_config->incarnation;
  memcpy(owner_config->replay_binding.session_id, wal_config->session_id,
         sizeof(owner_config->replay_binding.session_id));
}

static void make_config(mesh_control_wal_worker_config_v1_t *config, const char *path) {
  size_t index;
  memset(config, 0, sizeof(*config));
  config->wal.path = path;
  config->wal.record_capacity = 4u;
  config->wal.byte_capacity = 64u * 1024u;
  config->wal.principal_epoch = 1u;
  config->wal.incarnation = 1u;
  config->wal.certificate_serial = 1u;
  config->wal.session_id[0] = 1u;
  memset(config->wal.authentication_key, 0xa5, sizeof(config->wal.authentication_key));
  for (index = 0u; index < MESH_CONTROL_DIGEST_SIZE; ++index) {
    config->wal.mesh_id[index] = (uint8_t)(0x30u + index);
    config->wal.node_id[index] = (uint8_t)(0x40u + index);
    config->wal.controller_node_id[index] = (uint8_t)(0x40u + index);
  }
  check_int_eq(
      mesh_mgmt_ed25519_public_from_private(TEST_PRIVATE_KEY, config->wal.controller_principal),
      MESH_MGMT_CRYPTO_OK);
}

static size_t make_signed_frame(uint64_t sequence, uint8_t frame[MESH_MGMT_FRAME_MAX]) {
  static const uint8_t body[] = {1u, 2u, 3u};
  mesh_control_envelope_v1_t envelope;
  mesh_mgmt_sign_input_v1_t input;
  uint8_t payload[256];
  size_t payload_size = 0u;
  size_t frame_size = 0u;
  size_t index;

  memset(&envelope, 0, sizeof(envelope));
  envelope.schema_version = MESH_CONTROL_SCHEMA_V1;
  envelope.kind = MESH_CONTROL_MESSAGE_INTENT;
  envelope.resource_kind = MESH_CONTROL_RESOURCE_NETWORK;
  envelope.epoch = sequence;
  envelope.sequence = sequence;
  envelope.issued_at_ms = 1000u;
  envelope.expires_at_ms = 2000u;
  envelope.payload_size = sizeof(body);
  for (index = 0u; index < MESH_CONTROL_ID_SIZE; ++index) {
    envelope.message_id[index] = (uint8_t)(0x10u + sequence + index);
    envelope.request_id[index] = (uint8_t)(0x40u + sequence + index);
  }
  for (index = 0u; index < MESH_CONTROL_DIGEST_SIZE; ++index) {
    envelope.mesh_id[index] = (uint8_t)(0x30u + index);
    envelope.target_node_id[index] = (uint8_t)(0x40u + index);
    envelope.origin_node_id[index] = (uint8_t)(0x40u + index);
    envelope.origin_principal[index] = (uint8_t)(0x60u + index);
    envelope.resource_id[index] = (uint8_t)(0x50u + index);
  }
  check_int_eq(mesh_control_mmp_body_digest_v1(body, sizeof(body), envelope.payload_digest),
               MESH_CONTROL_MMP_OK);
  check_int_eq(mesh_control_mmp_payload_encode_v1(&envelope, body, sizeof(body), payload,
                                                  sizeof(payload), &payload_size),
               MESH_CONTROL_MMP_OK);
  memset(&input, 0, sizeof(input));
  input.minor = MESH_MGMT_MINOR_V1;
  input.kind = MESH_MGMT_KIND_CONTROL_FRAME;
  input.private_key = TEST_PRIVATE_KEY;
  input.payload = payload;
  input.payload_len = payload_size;
  memcpy(input.header.mesh_id_hash, envelope.mesh_id, sizeof(input.header.mesh_id_hash));
  memcpy(input.header.origin_node_id, envelope.origin_node_id, sizeof(input.header.origin_node_id));
  memcpy(input.header.target_node_id, envelope.target_node_id, sizeof(input.header.target_node_id));
  input.header.principal_epoch = 1u;
  input.header.incarnation = 1u;
  input.header.session_id[0] = 1u;
  input.header.origin_sequence = sequence;
  memcpy(input.header.message_id, envelope.message_id, sizeof(input.header.message_id));
  input.header.issued_at_ms = envelope.issued_at_ms;
  input.header.expires_at_ms = envelope.expires_at_ms;
  input.header.certificate_serial = 1u;
  check_int_eq(mesh_mgmt_envelope_sign_v1(&input, frame, MESH_MGMT_FRAME_MAX, &frame_size),
               MESH_MGMT_ENVELOPE_OK);
  return frame_size;
}

static int recover_record(void *context, const mesh_control_wal_record_view_v1_t *record) {
  recovery_capture_v1_t *capture = (recovery_capture_v1_t *)context;
  if (!capture || !record)
    return -1;
  capture->count++;
  capture->last_index = record->log_index;
  return 0;
}

static void test_worker_serializes_append_and_replays_before_accepting(void) {
  mesh_control_wal_worker_v1_t worker = {0};
  mesh_control_wal_worker_config_v1_t config;
  mesh_control_wal_worker_completion_v1_t completion;
  mesh_control_wal_worker_stats_v1_t stats;
  recovery_capture_v1_t recovery = {0};
  uint8_t first[MESH_MGMT_FRAME_MAX];
  uint8_t second[MESH_MGMT_FRAME_MAX];
  size_t first_size;
  size_t second_size;
  char *path = tt_make_temp_file("mesh-control-wal-worker", ".bin");

  check_not_null(path);
  if (!path)
    return;
  cleanup_wal_files(path);
  make_config(&config, path);
  config.recovery = recover_record;
  config.recovery_context = &recovery;
  first_size = make_signed_frame(1u, first);
  second_size = make_signed_frame(2u, second);

  check_int_eq(mesh_control_wal_worker_init_v1(&worker, &config), MESH_CONTROL_WAL_WORKER_OK);
  check_size_eq(recovery.count, 0u);
  check_int_eq(mesh_control_wal_worker_try_submit_v1(&worker, 1u, 1100u, first, first_size),
               MESH_CONTROL_WAL_WORKER_OK);
  check_int_eq(mesh_control_wal_worker_try_submit_v1(&worker, 2u, 1200u, second, second_size),
               MESH_CONTROL_WAL_WORKER_FULL);
  check_int_eq(mesh_control_wal_worker_shutdown_v1(&worker), MESH_CONTROL_WAL_WORKER_OK);
  check_int_eq(mesh_control_wal_worker_try_take_v1(&worker, &completion),
               MESH_CONTROL_WAL_WORKER_OK);
  check_int_eq(completion.wal_result, MESH_CONTROL_WAL_OK);
  check_uint_eq(completion.expected_index, 1u);
  check_uint_eq(completion.log_index, 1u);
  check_uint_eq(completion.accepted_at_ms, 1100u);
  check_int_eq(mesh_control_wal_worker_try_take_v1(&worker, &completion),
               MESH_CONTROL_WAL_WORKER_EMPTY);
  check_int_eq(mesh_control_wal_worker_get_stats_v1(&worker, &stats), MESH_CONTROL_WAL_WORKER_OK);
  check_uint_eq(stats.submitted, 1u);
  check_uint_eq(stats.completed, 1u);
  check_uint_eq(stats.rejected_full, 1u);
  check_uint_eq(stats.persistence_failures, 0u);
  check_false(stats.accepting);
  check_false(stats.busy);
  check_false(stats.completion_ready);
  check_uint_eq(stats.wal.tail_index, 1u);
  mesh_control_wal_worker_destroy_v1(&worker);

  memset(&recovery, 0, sizeof(recovery));
  config.recovery_context = &recovery;
  check_int_eq(mesh_control_wal_worker_init_v1(&worker, &config), MESH_CONTROL_WAL_WORKER_OK);
  check_size_eq(recovery.count, 1u);
  check_uint_eq(recovery.last_index, 1u);
  mesh_control_wal_worker_destroy_v1(&worker);
  cleanup_wal_files(path);
  free(path);
}

static void test_worker_checkpoints_then_compacts_and_recovers(void) {
  mesh_control_wal_worker_v1_t worker = {0};
  mesh_control_wal_worker_config_v1_t config;
  mesh_control_wal_worker_completion_v1_t completion;
  mesh_control_wal_worker_stats_v1_t stats;
  mesh_control_channel_v1_t source_channel = {0};
  mesh_control_channel_v1_t restored_channel = {0};
  mesh_control_owner_v1_t source = {0};
  mesh_control_owner_v1_t restored = {0};
  mesh_control_owner_config_v1_t owner_config;
  recovery_capture_v1_t recovery = {0};
  uint8_t frame[MESH_MGMT_FRAME_MAX];
  uint8_t *checkpoint = NULL;
  size_t frame_size;
  size_t checkpoint_size = 0u;
  size_t attempts;
  char *wal_path = tt_make_temp_file("mesh-control-wal-compact-worker", ".bin");
  char *checkpoint_path = tt_make_temp_file("mesh-control-checkpoint-worker", ".bin");

  check_not_null(wal_path);
  check_not_null(checkpoint_path);
  if (!wal_path || !checkpoint_path)
    goto cleanup;
  cleanup_wal_files(wal_path);
  cleanup_checkpoint_files(checkpoint_path);
  make_config(&config, wal_path);
  make_owner_config(&owner_config, &config.wal);
  check_int_eq(mesh_control_channel_init_v1(&source_channel, 4u, 4096u, 1024u), MESH_CONTROL_OK);
  check_int_eq(mesh_control_owner_init_v1(&source, &source_channel, &owner_config),
               MESH_CONTROL_OK);
  config.checkpoint_path = checkpoint_path;
  config.checkpoint_owner = &source;
  config.recovery_now_ms = 1100u;
  config.recovery = recover_record;
  config.recovery_context = &recovery;
  frame_size = make_signed_frame(1u, frame);

  check_int_eq(mesh_control_wal_worker_init_v1(&worker, &config), MESH_CONTROL_WAL_WORKER_OK);
  check_int_eq(mesh_control_wal_worker_try_submit_v1(&worker, 1u, 1100u, frame, frame_size),
               MESH_CONTROL_WAL_WORKER_OK);
  for (attempts = 0u; attempts < 1000u; ++attempts) {
    if (mesh_control_wal_worker_try_take_v1(&worker, &completion) == MESH_CONTROL_WAL_WORKER_OK)
      break;
    turbo_sleep_ms(1u);
  }
  check_true(attempts < 1000u);
  check_int_eq(completion.wal_result, MESH_CONTROL_WAL_OK);
  check_int_eq(mesh_control_owner_advance_log_index_v1(&source, 1u), MESH_CONTROL_OK);
  check_int_eq(mesh_control_checkpoint_encode_v1(&source, &checkpoint, &checkpoint_size),
               MESH_CONTROL_CHECKPOINT_OK);
  check_int_eq(
      mesh_control_wal_worker_try_submit_checkpoint_v1(&worker, 2u, checkpoint, checkpoint_size),
      MESH_CONTROL_WAL_WORKER_INVALID_ARG);
  check_int_eq(
      mesh_control_wal_worker_try_submit_checkpoint_v1(&worker, 1u, checkpoint, checkpoint_size),
      MESH_CONTROL_WAL_WORKER_OK);
  checkpoint = NULL;
  check_int_eq(mesh_control_wal_worker_shutdown_v1(&worker), MESH_CONTROL_WAL_WORKER_OK);
  check_int_eq(mesh_control_wal_worker_try_take_v1(&worker, &completion),
               MESH_CONTROL_WAL_WORKER_OK);
  check_int_eq(completion.record_type, MESH_CONTROL_WAL_WORKER_CHECKPOINT_RECORD_V1);
  check_int_eq(completion.checkpoint_result, MESH_CONTROL_CHECKPOINT_STORE_OK);
  check_int_eq(completion.wal_result, MESH_CONTROL_WAL_OK);
  check_uint_eq(completion.log_index, 1u);
  check_int_eq(mesh_control_wal_worker_get_stats_v1(&worker, &stats), MESH_CONTROL_WAL_WORKER_OK);
  check_uint_eq(stats.wal.base_index, 1u);
  check_uint_eq(stats.wal.tail_index, 1u);
  check_size_eq(stats.wal.record_count, 0u);
  check_uint_eq(stats.checkpoints_completed, 1u);
  mesh_control_wal_worker_destroy_v1(&worker);

  check_int_eq(mesh_control_channel_init_v1(&restored_channel, 4u, 4096u, 1024u), MESH_CONTROL_OK);
  check_int_eq(mesh_control_owner_init_v1(&restored, &restored_channel, &owner_config),
               MESH_CONTROL_OK);
  memset(&recovery, 0, sizeof(recovery));
  config.checkpoint_owner = &restored;
  config.recovery_context = &recovery;
  check_int_eq(mesh_control_wal_worker_init_v1(&worker, &config), MESH_CONTROL_WAL_WORKER_OK);
  check_uint_eq(restored.committed_log_index, 1u);
  check_size_eq(recovery.count, 0u);
  mesh_control_wal_worker_destroy_v1(&worker);

cleanup:
  mesh_control_checkpoint_free_v1(checkpoint);
  mesh_control_owner_destroy_v1(&restored);
  mesh_control_channel_destroy_v1(&restored_channel);
  mesh_control_owner_destroy_v1(&source);
  mesh_control_channel_destroy_v1(&source_channel);
  if (wal_path) {
    cleanup_wal_files(wal_path);
    free(wal_path);
  }
  if (checkpoint_path) {
    cleanup_checkpoint_files(checkpoint_path);
    free(checkpoint_path);
  }
}

static void test_worker_releases_checkpoint_lock_when_wal_recovery_fails(void) {
  mesh_control_wal_worker_v1_t worker = {0};
  mesh_control_wal_worker_config_v1_t config;
  mesh_control_checkpoint_store_v1_t checkpoint_store = {0};
  mesh_control_channel_v1_t channel = {0};
  mesh_control_owner_v1_t owner = {0};
  mesh_control_owner_config_v1_t owner_config;
  recovery_capture_v1_t recovery = {0};
  turbo_fs_buf_t corrupt = {"corrupt", 7u};
  char *wal_path = tt_make_temp_file("mesh-control-wal-worker-corrupt", ".bin");
  char *checkpoint_path = tt_make_temp_file("mesh-control-worker-lock-release", ".bin");

  check_not_null(wal_path);
  check_not_null(checkpoint_path);
  if (!wal_path || !checkpoint_path)
    goto cleanup;
  cleanup_wal_files(wal_path);
  cleanup_checkpoint_files(checkpoint_path);
  check_int_eq(turbo_fs_write_file(wal_path, &corrupt), 0);
  make_config(&config, wal_path);
  make_owner_config(&owner_config, &config.wal);
  check_int_eq(mesh_control_channel_init_v1(&channel, 4u, 4096u, 1024u), MESH_CONTROL_OK);
  check_int_eq(mesh_control_owner_init_v1(&owner, &channel, &owner_config), MESH_CONTROL_OK);
  config.checkpoint_path = checkpoint_path;
  config.checkpoint_owner = &owner;
  config.recovery_now_ms = 1100u;
  config.recovery = recover_record;
  config.recovery_context = &recovery;
  check_int_eq(mesh_control_wal_worker_init_v1(&worker, &config),
               MESH_CONTROL_WAL_WORKER_RECOVERY_FAILED);
  check_int_eq(mesh_control_checkpoint_store_open_authenticated_v1(
                   &checkpoint_store, checkpoint_path, config.wal.authentication_key),
               MESH_CONTROL_CHECKPOINT_STORE_OK);

cleanup:
  mesh_control_checkpoint_store_close_v1(&checkpoint_store);
  mesh_control_wal_worker_destroy_v1(&worker);
  mesh_control_owner_destroy_v1(&owner);
  mesh_control_channel_destroy_v1(&channel);
  if (wal_path) {
    cleanup_wal_files(wal_path);
    free(wal_path);
  }
  if (checkpoint_path) {
    cleanup_checkpoint_files(checkpoint_path);
    free(checkpoint_path);
  }
}

static void test_worker_preserves_wal_when_checkpoint_replace_fails(void) {
  mesh_control_wal_worker_v1_t worker = {0};
  mesh_control_wal_worker_config_v1_t config;
  mesh_control_wal_worker_completion_v1_t completion;
  mesh_control_wal_worker_stats_v1_t stats;
  mesh_control_channel_v1_t source_channel = {0};
  mesh_control_channel_v1_t restored_channel = {0};
  mesh_control_owner_v1_t source = {0};
  mesh_control_owner_v1_t restored = {0};
  mesh_control_owner_config_v1_t owner_config;
  recovery_capture_v1_t recovery = {0};
  uint8_t frame[MESH_MGMT_FRAME_MAX];
  uint8_t *checkpoint = NULL;
  size_t checkpoint_size = 0u;
  size_t frame_size;
  size_t attempts;
  char *wal_path = tt_make_temp_file("mesh-control-wal-checkpoint-fault", ".bin");
  char *checkpoint_path = tt_make_temp_file("mesh-control-checkpoint-fault", ".bin");

  check_not_null(wal_path);
  check_not_null(checkpoint_path);
  if (!wal_path || !checkpoint_path)
    goto cleanup;
  cleanup_wal_files(wal_path);
  cleanup_checkpoint_files(checkpoint_path);
  make_config(&config, wal_path);
  make_owner_config(&owner_config, &config.wal);
  check_int_eq(mesh_control_channel_init_v1(&source_channel, 4u, 4096u, 1024u), MESH_CONTROL_OK);
  check_int_eq(mesh_control_owner_init_v1(&source, &source_channel, &owner_config),
               MESH_CONTROL_OK);
  config.checkpoint_path = checkpoint_path;
  config.checkpoint_owner = &source;
  config.recovery_now_ms = 1100u;
  config.recovery = recover_record;
  config.recovery_context = &recovery;
  frame_size = make_signed_frame(1u, frame);

  check_int_eq(mesh_control_wal_worker_init_v1(&worker, &config), MESH_CONTROL_WAL_WORKER_OK);
  check_int_eq(mesh_control_wal_worker_try_submit_v1(&worker, 1u, 1100u, frame, frame_size),
               MESH_CONTROL_WAL_WORKER_OK);
  for (attempts = 0u; attempts < 1000u; ++attempts) {
    if (mesh_control_wal_worker_try_take_v1(&worker, &completion) == MESH_CONTROL_WAL_WORKER_OK)
      break;
    turbo_sleep_ms(1u);
  }
  check_true(attempts < 1000u);
  check_int_eq(completion.wal_result, MESH_CONTROL_WAL_OK);
  check_int_eq(mesh_control_owner_advance_log_index_v1(&source, 1u), MESH_CONTROL_OK);
  check_int_eq(mesh_control_checkpoint_encode_v1(&source, &checkpoint, &checkpoint_size),
               MESH_CONTROL_CHECKPOINT_OK);

  check_int_eq(turbo_fs_mkdir(checkpoint_path, 0700), 0);
  check_int_eq(
      mesh_control_wal_worker_try_submit_checkpoint_v1(&worker, 1u, checkpoint, checkpoint_size),
      MESH_CONTROL_WAL_WORKER_OK);
  checkpoint = NULL;
  check_int_eq(mesh_control_wal_worker_shutdown_v1(&worker), MESH_CONTROL_WAL_WORKER_OK);
  for (attempts = 0u; attempts < 1000u; ++attempts) {
    if (mesh_control_wal_worker_try_take_v1(&worker, &completion) == MESH_CONTROL_WAL_WORKER_OK)
      break;
    turbo_sleep_ms(1u);
  }
  check_true(attempts < 1000u);
  check_int_eq(completion.record_type, MESH_CONTROL_WAL_WORKER_CHECKPOINT_RECORD_V1);
  check_int_eq(completion.checkpoint_result, MESH_CONTROL_CHECKPOINT_STORE_IO);
  check_int_eq(completion.wal_result, MESH_CONTROL_WAL_INVALID_STATE);
  check_int_eq(mesh_control_wal_worker_get_stats_v1(&worker, &stats), MESH_CONTROL_WAL_WORKER_OK);
  check_uint_eq(stats.wal.base_index, 0u);
  check_uint_eq(stats.wal.tail_index, 1u);
  check_size_eq(stats.wal.record_count, 1u);
  check_uint_eq(stats.checkpoint_failures, 1u);
  mesh_control_wal_worker_destroy_v1(&worker);

  check_int_eq(turbo_fs_rmdir(checkpoint_path), 0);
  check_int_eq(mesh_control_channel_init_v1(&restored_channel, 4u, 4096u, 1024u), MESH_CONTROL_OK);
  check_int_eq(mesh_control_owner_init_v1(&restored, &restored_channel, &owner_config),
               MESH_CONTROL_OK);
  memset(&recovery, 0, sizeof(recovery));
  config.checkpoint_owner = &restored;
  config.recovery_context = &recovery;
  check_int_eq(mesh_control_wal_worker_init_v1(&worker, &config), MESH_CONTROL_WAL_WORKER_OK);
  check_size_eq(recovery.count, 1u);
  check_uint_eq(recovery.last_index, 1u);

cleanup:
  mesh_control_checkpoint_free_v1(checkpoint);
  mesh_control_wal_worker_destroy_v1(&worker);
  mesh_control_owner_destroy_v1(&restored);
  mesh_control_channel_destroy_v1(&restored_channel);
  mesh_control_owner_destroy_v1(&source);
  mesh_control_channel_destroy_v1(&source_channel);
  if (checkpoint_path && turbo_fs_access(checkpoint_path, TURBO_FS_ACCESS_EXISTS) == 0)
    (void)turbo_fs_rmdir(checkpoint_path);
  if (wal_path) {
    cleanup_wal_files(wal_path);
    free(wal_path);
  }
  if (checkpoint_path) {
    cleanup_checkpoint_files(checkpoint_path);
    free(checkpoint_path);
  }
}

spec("mesh control WAL persistence worker") {
  describe("bounded asynchronous append and startup recovery") {
    it("serializes one owned frame and replays before accepting") {
      test_worker_serializes_append_and_replays_before_accepting();
    }
    it("persists a checkpoint before compact and recovers from its WAL anchor") {
      test_worker_checkpoints_then_compacts_and_recovers();
    }
    it("releases the checkpoint lock when WAL recovery fails") {
      test_worker_releases_checkpoint_lock_when_wal_recovery_fails();
    }
    it("preserves WAL recovery when checkpoint atomic replace fails") {
      test_worker_preserves_wal_when_checkpoint_replace_fails();
    }
  }
}
