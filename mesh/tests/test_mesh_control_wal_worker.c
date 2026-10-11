#include "mesh_control_mmp.h"
#include "mesh_control_wal_worker.h"
#include "mesh_mgmt_crypto.h"
#include "tinytest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static mesh_control_wal_worker_v1_t worker;
static mesh_control_checkpoint_store_v1_t checkpoint_store;
static mesh_control_channel_v1_t source_channel, restored_channel, channel;
static mesh_control_owner_v1_t source, restored, owner;
static uint8_t *checkpoint;
static char *path, *wal_path, *checkpoint_path;
static int checkpoint_directory;

#ifdef MESH_CONTROL_CHECKPOINT_TEST_FAULT
#define mesh_control_checkpoint_snapshot_write mesh_control_checkpoint_snapshot_write_real
#include "mesh_control_checkpoint_snapshot_io.h"
#undef mesh_control_checkpoint_snapshot_write
#include <errno.h>
static int uncertain;
int mesh_control_checkpoint_snapshot_write(const char *temp, const char *destination,
    const uint8_t *bytes, size_t size, const uint8_t *tag, size_t tag_size,
    cmeta_fs_replace_state_t *publication) {
  int status = mesh_control_checkpoint_snapshot_write_real(
      temp, destination, bytes, size, tag, tag_size, publication);
  if (uncertain && !status) {
    *publication = SALTS_FS_REPLACE_DURABILITY_UNKNOWN;
    return -EIO;
  }
  return status;
}
#endif

static const uint8_t TEST_PRIVATE_KEY[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};

typedef struct {
  size_t count;
  uint64_t last_index;
  uint16_t last_type;
  mesh_control_wal_operation_result_v1_t last_operation_result;
} recovery_capture_v1_t;

static void cleanup_wal_files(const char *path) {
  char lock_path[SALTS_FS_MAX_PATH];
  (void)snprintf(lock_path, sizeof(lock_path), "%s.lock", path);
  if (cmeta_fs_access(path, SALTS_FS_ACCESS_EXISTS) == 0)
    (void)cmeta_fs_unlink(path);
  if (cmeta_fs_access(lock_path, SALTS_FS_ACCESS_EXISTS) == 0)
    (void)cmeta_fs_unlink(lock_path);
}

static void cleanup_checkpoint_files(const char *path) {
  char lock_path[SALTS_FS_MAX_PATH + 6u];
  char temp_path[SALTS_FS_MAX_PATH + 5u];
  (void)snprintf(lock_path, sizeof(lock_path), "%s.lock", path);
  (void)snprintf(temp_path, sizeof(temp_path), "%s.tmp", path);
  if (cmeta_fs_access(path, SALTS_FS_ACCESS_EXISTS) == 0)
    (void)cmeta_fs_unlink(path);
  if (cmeta_fs_access(lock_path, SALTS_FS_ACCESS_EXISTS) == 0)
    (void)cmeta_fs_unlink(lock_path);
  if (cmeta_fs_access(temp_path, SALTS_FS_ACCESS_EXISTS) == 0)
    (void)cmeta_fs_unlink(temp_path);
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
  check_equal(
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
  check_equal(mesh_control_mmp_body_digest_v1(body, sizeof(body), envelope.payload_digest),
               MESH_CONTROL_MMP_OK);
  check_equal(mesh_control_mmp_payload_encode_v1(&envelope, body, sizeof(body), payload,
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
  check_equal(mesh_mgmt_envelope_sign_v1(&input, frame, MESH_MGMT_FRAME_MAX, &frame_size),
               MESH_MGMT_ENVELOPE_OK);
  return frame_size;
}

static int recover_record(void *context, const mesh_control_wal_record_view_v1_t *record) {
  recovery_capture_v1_t *capture = (recovery_capture_v1_t *)context;
  if (!capture || !record)
    return -1;
  capture->count++;
  capture->last_index = record->log_index;
  capture->last_type = record->record_type;
  capture->last_operation_result = record->operation_result;
  return 0;
}

static void test_worker_serializes_append_and_replays_before_accepting(void) {
  mesh_control_wal_worker_config_v1_t config;
  mesh_control_wal_worker_completion_v1_t completion;
  mesh_control_wal_worker_stats_v1_t stats;
  recovery_capture_v1_t recovery = {0};
  uint8_t first[MESH_MGMT_FRAME_MAX];
  uint8_t second[MESH_MGMT_FRAME_MAX];
  size_t first_size;
  size_t second_size;
  path = tt_make_temp_file("mesh-control-wal-worker", ".bin");

  check_not_null(path);
  if (!path)
    return;
  cleanup_wal_files(path);
  make_config(&config, path);
  config.recovery = recover_record;
  config.recovery_context = &recovery;
  first_size = make_signed_frame(1u, first);
  second_size = make_signed_frame(2u, second);

  check_equal(mesh_control_wal_worker_init_v1(&worker, &config), MESH_CONTROL_WAL_WORKER_OK);
  check_equal(recovery.count, 0u);
  check_equal(mesh_control_wal_worker_try_submit_v1(&worker, 1u, 1100u, first, first_size),
               MESH_CONTROL_WAL_WORKER_OK);
  check_equal(mesh_control_wal_worker_try_submit_v1(&worker, 2u, 1200u, second, second_size),
               MESH_CONTROL_WAL_WORKER_FULL);
  check_equal(mesh_control_wal_worker_shutdown_v1(&worker), MESH_CONTROL_WAL_WORKER_OK);
  check_equal(mesh_control_wal_worker_try_take_v1(&worker, &completion),
               MESH_CONTROL_WAL_WORKER_OK);
  check_equal(completion.wal_result, MESH_CONTROL_WAL_OK);
  check_equal(completion.expected_index, 1u);
  check_equal(completion.log_index, 1u);
  check_equal(completion.accepted_at_ms, 1100u);
  check_equal(mesh_control_wal_worker_try_take_v1(&worker, &completion),
               MESH_CONTROL_WAL_WORKER_EMPTY);
  check_equal(mesh_control_wal_worker_get_stats_v1(&worker, &stats), MESH_CONTROL_WAL_WORKER_OK);
  check_equal(stats.submitted, 1u);
  check_equal(stats.completed, 1u);
  check_equal(stats.rejected_full, 1u);
  check_equal(stats.persistence_failures, 0u);
  check_false(stats.accepting);
  check_false(stats.busy);
  check_false(stats.completion_ready);
  check_equal(stats.wal.tail_index, 1u);
  mesh_control_wal_worker_destroy_v1(&worker);

  memset(&recovery, 0, sizeof(recovery));
  config.recovery_context = &recovery;
  check_equal(mesh_control_wal_worker_init_v1(&worker, &config), MESH_CONTROL_WAL_WORKER_OK);
  check_equal(recovery.count, 1u);
  check_equal(recovery.last_index, 1u);
  mesh_control_wal_worker_destroy_v1(&worker);
  cleanup_wal_files(path);

}

static void test_worker_checkpoints_then_compacts_and_recovers(void) {
  mesh_control_wal_worker_config_v1_t config;
  mesh_control_wal_worker_completion_v1_t completion;
  mesh_control_wal_worker_stats_v1_t stats;
  mesh_control_owner_config_v1_t owner_config;
  recovery_capture_v1_t recovery = {0};
  uint8_t frame[MESH_MGMT_FRAME_MAX];
  size_t frame_size;
  size_t checkpoint_size = 0u;
  size_t attempts;
  wal_path = tt_make_temp_file("mesh-control-wal-compact-worker", ".bin");
  checkpoint_path = tt_make_temp_file("mesh-control-checkpoint-worker", ".bin");

  check_not_null(wal_path);
  check_not_null(checkpoint_path);
  if (!wal_path || !checkpoint_path)
    goto cleanup;
  cleanup_wal_files(wal_path);
  cleanup_checkpoint_files(checkpoint_path);
  make_config(&config, wal_path);
  make_owner_config(&owner_config, &config.wal);
  check_equal(mesh_control_channel_init_v1(&source_channel, 4u, 4096u, 1024u), MESH_CONTROL_OK);
  check_equal(mesh_control_owner_init_v1(&source, &source_channel, &owner_config),
               MESH_CONTROL_OK);
  config.checkpoint_path = checkpoint_path;
  config.checkpoint_owner = &source;
  config.recovery_now_ms = 1100u;
  config.recovery = recover_record;
  config.recovery_context = &recovery;
  frame_size = make_signed_frame(1u, frame);

  check_equal(mesh_control_wal_worker_init_v1(&worker, &config), MESH_CONTROL_WAL_WORKER_OK);
  check_equal(mesh_control_wal_worker_try_submit_v1(&worker, 1u, 1100u, frame, frame_size),
               MESH_CONTROL_WAL_WORKER_OK);
  for (attempts = 0u; attempts < 1000u; ++attempts) {
    if (mesh_control_wal_worker_try_take_v1(&worker, &completion) == MESH_CONTROL_WAL_WORKER_OK)
      break;
    cmeta_sleep_ms(1u);
  }
  check_true(attempts < 1000u);
  check_equal(completion.wal_result, MESH_CONTROL_WAL_OK);
  check_equal(mesh_control_owner_advance_log_index_v1(&source, 1u), MESH_CONTROL_OK);
  check_equal(mesh_control_checkpoint_encode_v1(&source, &checkpoint, &checkpoint_size),
               MESH_CONTROL_CHECKPOINT_OK);
  check_equal(
      mesh_control_wal_worker_try_submit_checkpoint_v1(&worker, 2u, checkpoint, checkpoint_size),
      MESH_CONTROL_WAL_WORKER_INVALID_ARG);
  check_equal(
      mesh_control_wal_worker_try_submit_checkpoint_v1(&worker, 1u, checkpoint, checkpoint_size),
      MESH_CONTROL_WAL_WORKER_OK);
  checkpoint = NULL;
  check_equal(mesh_control_wal_worker_shutdown_v1(&worker), MESH_CONTROL_WAL_WORKER_OK);
  check_equal(mesh_control_wal_worker_try_take_v1(&worker, &completion),
               MESH_CONTROL_WAL_WORKER_OK);
  check_equal(completion.record_type, MESH_CONTROL_WAL_WORKER_CHECKPOINT_RECORD_V1);
  check_equal(completion.checkpoint_result, MESH_CONTROL_CHECKPOINT_STORE_OK);
  check_equal(completion.wal_result, MESH_CONTROL_WAL_OK);
  check_equal(completion.log_index, 1u);
  check_equal(mesh_control_wal_worker_get_stats_v1(&worker, &stats), MESH_CONTROL_WAL_WORKER_OK);
  check_equal(stats.wal.base_index, 1u);
  check_equal(stats.wal.tail_index, 1u);
  check_equal(stats.wal.record_count, 0u);
  check_equal(stats.checkpoints_completed, 1u);
  mesh_control_wal_worker_destroy_v1(&worker);

  check_equal(mesh_control_channel_init_v1(&restored_channel, 4u, 4096u, 1024u), MESH_CONTROL_OK);
  check_equal(mesh_control_owner_init_v1(&restored, &restored_channel, &owner_config),
               MESH_CONTROL_OK);
  memset(&recovery, 0, sizeof(recovery));
  config.checkpoint_owner = &restored;
  config.recovery_context = &recovery;
  check_equal(mesh_control_wal_worker_init_v1(&worker, &config), MESH_CONTROL_WAL_WORKER_OK);
  check_equal(restored.committed_log_index, 1u);
  check_equal(recovery.count, 0u);
  mesh_control_wal_worker_destroy_v1(&worker);

cleanup:
  return;
}

static void test_worker_releases_checkpoint_lock_when_wal_recovery_fails(void) {
  mesh_control_wal_worker_config_v1_t config;
  mesh_control_owner_config_v1_t owner_config;
  recovery_capture_v1_t recovery = {0};
  cmeta_fs_buf_t corrupt = {"corrupt", 7u};
  wal_path = tt_make_temp_file("mesh-control-wal-worker-corrupt", ".bin");
  checkpoint_path = tt_make_temp_file("mesh-control-worker-lock-release", ".bin");

  check_not_null(wal_path);
  check_not_null(checkpoint_path);
  if (!wal_path || !checkpoint_path)
    goto cleanup;
  cleanup_wal_files(wal_path);
  cleanup_checkpoint_files(checkpoint_path);
  check_equal(cmeta_fs_write_file(wal_path, &corrupt), 0);
  make_config(&config, wal_path);
  make_owner_config(&owner_config, &config.wal);
  check_equal(mesh_control_channel_init_v1(&channel, 4u, 4096u, 1024u), MESH_CONTROL_OK);
  check_equal(mesh_control_owner_init_v1(&owner, &channel, &owner_config), MESH_CONTROL_OK);
  config.checkpoint_path = checkpoint_path;
  config.checkpoint_owner = &owner;
  config.recovery_now_ms = 1100u;
  config.recovery = recover_record;
  config.recovery_context = &recovery;
  check_equal(mesh_control_wal_worker_init_v1(&worker, &config),
               MESH_CONTROL_WAL_WORKER_RECOVERY_FAILED);
  check_equal(mesh_control_checkpoint_store_open_authenticated_v1(
                   &checkpoint_store, checkpoint_path, config.wal.authentication_key),
               MESH_CONTROL_CHECKPOINT_STORE_OK);

cleanup:
  return;
}

static void test_worker_preserves_wal_when_checkpoint_replace_fails(void) {
  mesh_control_wal_worker_config_v1_t config;
  mesh_control_wal_worker_completion_v1_t completion;
  mesh_control_wal_worker_stats_v1_t stats;
  mesh_control_owner_config_v1_t owner_config;
  recovery_capture_v1_t recovery = {0};
  uint8_t frame[MESH_MGMT_FRAME_MAX];
  size_t checkpoint_size = 0u;
  size_t frame_size;
  size_t attempts;
  wal_path = tt_make_temp_file("mesh-control-wal-checkpoint-fault", ".bin");
  checkpoint_path = tt_make_temp_file("mesh-control-checkpoint-fault", ".bin");

  check_not_null(wal_path);
  check_not_null(checkpoint_path);
  if (!wal_path || !checkpoint_path)
    goto cleanup;
  cleanup_wal_files(wal_path);
  cleanup_checkpoint_files(checkpoint_path);
  make_config(&config, wal_path);
  make_owner_config(&owner_config, &config.wal);
  check_equal(mesh_control_channel_init_v1(&source_channel, 4u, 4096u, 1024u), MESH_CONTROL_OK);
  check_equal(mesh_control_owner_init_v1(&source, &source_channel, &owner_config),
               MESH_CONTROL_OK);
  config.checkpoint_path = checkpoint_path;
  config.checkpoint_owner = &source;
  config.recovery_now_ms = 1100u;
  config.recovery = recover_record;
  config.recovery_context = &recovery;
  frame_size = make_signed_frame(1u, frame);

  check_equal(mesh_control_wal_worker_init_v1(&worker, &config), MESH_CONTROL_WAL_WORKER_OK);
  check_equal(mesh_control_wal_worker_try_submit_v1(&worker, 1u, 1100u, frame, frame_size),
               MESH_CONTROL_WAL_WORKER_OK);
  for (attempts = 0u; attempts < 1000u; ++attempts) {
    if (mesh_control_wal_worker_try_take_v1(&worker, &completion) == MESH_CONTROL_WAL_WORKER_OK)
      break;
    cmeta_sleep_ms(1u);
  }
  check_true(attempts < 1000u);
  check_equal(completion.wal_result, MESH_CONTROL_WAL_OK);
  check_equal(mesh_control_owner_advance_log_index_v1(&source, 1u), MESH_CONTROL_OK);
  check_equal(mesh_control_checkpoint_encode_v1(&source, &checkpoint, &checkpoint_size),
               MESH_CONTROL_CHECKPOINT_OK);

#ifdef MESH_CONTROL_CHECKPOINT_TEST_FAULT
  uncertain = 1;
#else
  check_equal(cmeta_fs_mkdir(checkpoint_path, 0700), 0);
  checkpoint_directory = 1;
#endif
  check_equal(
      mesh_control_wal_worker_try_submit_checkpoint_v1(&worker, 1u, checkpoint, checkpoint_size),
      MESH_CONTROL_WAL_WORKER_OK);
  checkpoint = NULL;
  check_equal(cmeta_threadpool_wait_status(worker.pool), SALTS_OK);
  check_equal(mesh_control_wal_worker_get_stats_v1(&worker, &stats), MESH_CONTROL_WAL_WORKER_OK);
  check_true(stats.busy);
  check_true(stats.completion_ready);
  check_false(stats.accepting);

  for (attempts = 0u; attempts < 1000u; ++attempts) {
    if (mesh_control_wal_worker_try_take_v1(&worker, &completion) == MESH_CONTROL_WAL_WORKER_OK)
      break;
    cmeta_sleep_ms(1u);
  }
  check_true(attempts < 1000u);
  check_equal(completion.record_type, MESH_CONTROL_WAL_WORKER_CHECKPOINT_RECORD_V1);
  check_equal(completion.checkpoint_result, MESH_CONTROL_CHECKPOINT_STORE_IO);
  check_equal(completion.wal_result, MESH_CONTROL_WAL_INVALID_STATE);
  check_equal(mesh_control_wal_worker_get_stats_v1(&worker, &stats), MESH_CONTROL_WAL_WORKER_OK);
  check_equal(stats.wal.base_index, 0u);
  check_equal(stats.wal.tail_index, 1u);
  check_equal(stats.wal.record_count, 1u);
  check_equal(mesh_control_wal_worker_try_take_v1(&worker, &completion), MESH_CONTROL_WAL_WORKER_EMPTY);
  check_equal(stats.checkpoint_failures, 1u);
  check_false(stats.accepting);
  check_equal(mesh_control_wal_worker_try_submit_v1(&worker, 2u, 1200u, frame, frame_size),
      MESH_CONTROL_WAL_WORKER_INVALID_STATE);
  check_equal(mesh_control_wal_worker_shutdown_v1(&worker), MESH_CONTROL_WAL_WORKER_OK);
  mesh_control_wal_worker_destroy_v1(&worker);

#ifdef MESH_CONTROL_CHECKPOINT_TEST_FAULT
  uncertain = 0;
#else
  check_equal(cmeta_fs_rmdir(checkpoint_path), 0);
  checkpoint_directory = 0;
#endif
  check_equal(mesh_control_channel_init_v1(&restored_channel, 4u, 4096u, 1024u), MESH_CONTROL_OK);
  check_equal(mesh_control_owner_init_v1(&restored, &restored_channel, &owner_config),
               MESH_CONTROL_OK);
  memset(&recovery, 0, sizeof(recovery));
  config.checkpoint_owner = &restored;
  config.recovery_context = &recovery;
#ifdef MESH_CONTROL_CHECKPOINT_TEST_FAULT
  uncertain = 1;
  check_equal(mesh_control_wal_worker_init_v1(&worker, &config), MESH_CONTROL_WAL_WORKER_RECOVERY_FAILED);
  check_equal(restored.committed_log_index, 0u);
  check_equal(mesh_control_checkpoint_store_open_authenticated_v1(
      &checkpoint_store, checkpoint_path, config.wal.authentication_key), MESH_CONTROL_CHECKPOINT_STORE_OK);
  mesh_control_checkpoint_store_close_v1(&checkpoint_store);
  uncertain = 0;
#endif
  check_equal(mesh_control_wal_worker_init_v1(&worker, &config), MESH_CONTROL_WAL_WORKER_OK);
#ifdef MESH_CONTROL_CHECKPOINT_TEST_FAULT
  check_equal(recovery.count, 0u);
  check_equal(restored.committed_log_index, 1u);
#else
  check_equal(recovery.count, 1u);
  check_equal(recovery.last_index, 1u);
#endif

cleanup:
  return;
}

static void test_worker_copies_operation_result_and_drains(void) {
  mesh_control_wal_worker_config_v1_t config;
  mesh_control_wal_worker_completion_v1_t completion;
  mesh_control_wal_operation_result_v1_t result = {0};
  recovery_capture_v1_t recovery = {0};
  path = tt_make_temp_file("mesh-wal-worker-result", ".bin");
  check_not_null(path); cleanup_wal_files(path);
  make_config(&config, path); config.recovery = recover_record; config.recovery_context = &recovery;
  result.operation_id[0] = 1u; result.resource_kind = MESH_CONTROL_RESOURCE_NETWORK;
  result.action = MESH_CONTROL_DESIRED_APPLY; result.outcome = MESH_CONTROL_WAL_OPERATION_SUCCEEDED;
  result.resource_id[0] = 2u; result.desired_epoch = 3u;
  check_equal(mesh_control_wal_worker_init_v1(&worker, &config), MESH_CONTROL_WAL_WORKER_OK);
  check_equal(mesh_control_wal_worker_try_submit_operation_result_v1(&worker, 1u, 1100u, &result),
      MESH_CONTROL_WAL_WORKER_OK);
  memset(&result, 0, sizeof(result));
  check_equal(mesh_control_wal_worker_try_submit_operation_result_v1(&worker, 2u, 1200u, &result),
      MESH_CONTROL_WAL_WORKER_FULL);
  check_equal(mesh_control_wal_worker_shutdown_v1(&worker), MESH_CONTROL_WAL_WORKER_OK);
  check_equal(mesh_control_wal_worker_try_take_v1(&worker, &completion), MESH_CONTROL_WAL_WORKER_OK);
  check_equal(completion.record_type, MESH_CONTROL_WAL_RECORD_OPERATION_RESULT);
  check_equal(completion.wal_result, MESH_CONTROL_WAL_OK);
  check_equal(completion.log_index, 1u);
  check_equal(completion.accepted_at_ms, 1100u);
  check_equal(mesh_control_wal_worker_try_take_v1(&worker, &completion), MESH_CONTROL_WAL_WORKER_EMPTY);
  mesh_control_wal_worker_destroy_v1(&worker);
  check_equal(mesh_control_wal_worker_init_v1(&worker, &config), MESH_CONTROL_WAL_WORKER_OK);
  check_equal(recovery.count, 1u);
  check_equal(recovery.last_type, MESH_CONTROL_WAL_RECORD_OPERATION_RESULT);
  check_equal(recovery.last_operation_result.operation_id[0], 1u);
  check_equal(recovery.last_operation_result.desired_epoch, 3u);
  check_equal(recovery.last_operation_result.outcome, MESH_CONTROL_WAL_OPERATION_SUCCEEDED);
}

static void test_worker_closes_admission_on_append_failure(void) {
  mesh_control_wal_worker_config_v1_t config;
  mesh_control_wal_worker_completion_v1_t completion;
  mesh_control_wal_worker_stats_v1_t stats;
  recovery_capture_v1_t recovery = {0};
  uint8_t frame[MESH_MGMT_FRAME_MAX];
  size_t frame_size = make_signed_frame(1u, frame);
  path = tt_make_temp_file("mesh-wal-worker-gap", ".bin");
  check_not_null(path); cleanup_wal_files(path);
  make_config(&config, path); config.recovery = recover_record; config.recovery_context = &recovery;
  check_equal(mesh_control_wal_worker_init_v1(&worker, &config), MESH_CONTROL_WAL_WORKER_OK);
  check_equal(mesh_control_wal_worker_try_submit_v1(&worker, 2u, 1100u, frame, frame_size),
      MESH_CONTROL_WAL_WORKER_OK);
  check_equal(cmeta_threadpool_wait_status(worker.pool), SALTS_OK);
  check_equal(mesh_control_wal_worker_get_stats_v1(&worker, &stats), MESH_CONTROL_WAL_WORKER_OK);
  check_false(stats.accepting); check_true(stats.busy); check_true(stats.completion_ready);
  check_equal(stats.persistence_failures, 1u); check_equal(stats.wal.tail_index, 0u);
  check_equal(mesh_control_wal_worker_try_take_v1(&worker, &completion), MESH_CONTROL_WAL_WORKER_OK);
  check_equal(completion.wal_result, MESH_CONTROL_WAL_CONFLICT); check_equal(completion.log_index, 0u);
  check_equal(mesh_control_wal_worker_try_submit_v1(&worker, 1u, 1100u, frame, frame_size),
      MESH_CONTROL_WAL_WORKER_INVALID_STATE);
  check_equal(mesh_control_wal_worker_try_take_v1(&worker, &completion), MESH_CONTROL_WAL_WORKER_EMPTY);
  check_equal(mesh_control_wal_worker_shutdown_v1(&worker), MESH_CONTROL_WAL_WORKER_OK);
  mesh_control_wal_worker_destroy_v1(&worker);
  check_equal(mesh_control_wal_worker_init_v1(&worker, &config), MESH_CONTROL_WAL_WORKER_OK);
  check_equal(recovery.count, 0u);
  check_equal(mesh_control_wal_worker_try_submit_v1(&worker, 1u, 1100u, frame, frame_size),
      MESH_CONTROL_WAL_WORKER_OK);
  check_equal(mesh_control_wal_worker_shutdown_v1(&worker), MESH_CONTROL_WAL_WORKER_OK);
  check_equal(mesh_control_wal_worker_try_take_v1(&worker, &completion), MESH_CONTROL_WAL_WORKER_OK);
  check_equal(completion.wal_result, MESH_CONTROL_WAL_OK); check_equal(completion.log_index, 1u);
}

spec("mesh control WAL persistence worker") {
  before_each() {
    memset(&worker, 0, sizeof(worker));
    memset(&checkpoint_store, 0, sizeof(checkpoint_store)); checkpoint_store.lock_file = SALTS_INVALID_FILE;
    memset(&source_channel, 0, sizeof(source_channel));
    memset(&restored_channel, 0, sizeof(restored_channel)); memset(&channel, 0, sizeof(channel));
    memset(&source, 0, sizeof(source)); memset(&restored, 0, sizeof(restored)); memset(&owner, 0, sizeof(owner));
    checkpoint = NULL; path = NULL; wal_path = NULL; checkpoint_path = NULL; checkpoint_directory = 0;
#ifdef MESH_CONTROL_CHECKPOINT_TEST_FAULT
    uncertain = 0;
#endif
  }
  after_each() {
    mesh_control_wal_worker_destroy_v1(&worker);
    mesh_control_checkpoint_store_close_v1(&checkpoint_store);
    mesh_control_owner_destroy_v1(&source); mesh_control_owner_destroy_v1(&restored);
    mesh_control_owner_destroy_v1(&owner); mesh_control_channel_destroy_v1(&channel);
    mesh_control_channel_destroy_v1(&source_channel); mesh_control_channel_destroy_v1(&restored_channel);
    mesh_control_checkpoint_free_v1(checkpoint);
    if (checkpoint_directory) (void)cmeta_fs_rmdir(checkpoint_path);
    if (path) { cleanup_wal_files(path); free(path); }
    if (wal_path) { cleanup_wal_files(wal_path); free(wal_path); }
    if (checkpoint_path) { cleanup_checkpoint_files(checkpoint_path); free(checkpoint_path); }
  }
  describe("bounded asynchronous append and startup recovery") {
    it("safely destroys a zero worker and repeats destruction") {
      mesh_control_wal_worker_destroy_v1(&worker);
      check_equal(worker.wal.lock_file, SALTS_INVALID_FILE);
      check_equal(worker.checkpoint_store.lock_file, SALTS_INVALID_FILE);
      mesh_control_wal_worker_destroy_v1(&worker);
      check_null(worker.pool);
    }
    it("copies an operation result and retains exactly one drained completion") {
      test_worker_copies_operation_result_and_drains();
    }
    it("closes admission on append failure until checked reinitialization") {
      test_worker_closes_admission_on_append_failure();
    }
    it("serializes one owned frame and replays before accepting") {
      test_worker_serializes_append_and_replays_before_accepting();
    }
    it("persists a checkpoint before compact and recovers from its WAL anchor") {
      test_worker_checkpoints_then_compacts_and_recovers();
    }
    it("releases the checkpoint lock when WAL recovery fails") {
      test_worker_releases_checkpoint_lock_when_wal_recovery_fails();
    }
#ifdef MESH_CONTROL_CHECKPOINT_TEST_FAULT
    it("retains the WAL and completion and closes admission on unknown checkpoint durability") {
#else
    it("preserves WAL recovery when checkpoint durable replace fails") {
#endif
      test_worker_preserves_wal_when_checkpoint_replace_fails();
    }
  }
}
