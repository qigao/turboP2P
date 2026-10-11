#include "mesh_control_mmp.h"
#include "mesh_control_wal.h"
#include "mesh_mgmt_crypto.h"
#include "tinytest.h"
#include <fmt.h>
#include <errno.h>
#ifndef _WIN32
#include <sys/wait.h>
#include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_WAL_HEADER_SIZE 256u
#define TEST_WAL_RECORD_HEADER_SIZE 72u

static const uint8_t TEST_PRIVATE_KEY[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};

static mesh_control_wal_v1_t wal, second, reopened;
static cmeta_file_t file;
static char *path, *contents, *after;
static tstr lock_path, staging;
static int staging_directory;

#ifdef MESH_CONTROL_WAL_TEST_FAULT
#define mesh_control_wal_snapshot_write mesh_control_wal_snapshot_write_real
#define mesh_control_wal_snapshot_republish mesh_control_wal_snapshot_republish_real
#include "mesh_control_wal_snapshot_io.h"
#undef mesh_control_wal_snapshot_write
#undef mesh_control_wal_snapshot_republish
static int uncertain;
static unsigned publications;
static int inject_publication(int status, cmeta_fs_replace_state_t *publication) {
  publications++;
  if (uncertain && !status) {
    *publication = SALTS_FS_REPLACE_DURABILITY_UNKNOWN;
    return -EIO;
  }
  return status;
}
int mesh_control_wal_snapshot_write(const char *staging_path, const char *destination,
    const uint8_t *bytes, size_t size, cmeta_fs_replace_state_t *publication) {
  return inject_publication(mesh_control_wal_snapshot_write_real(
      staging_path, destination, bytes, size, publication), publication);
}
int mesh_control_wal_snapshot_republish(const char *staging_path, const char *destination,
    size_t size, cmeta_fs_replace_state_t *publication) {
  return inject_publication(mesh_control_wal_snapshot_republish_real(
      staging_path, destination, size, publication), publication);
}
#endif

typedef struct {
  size_t count;
  uint64_t indexes[4];
  uint64_t accepted_at_ms[4];
} replay_capture_v1_t;

typedef struct {
  size_t count;
  uint16_t types[2];
  mesh_control_wal_operation_result_v1_t operation_result;
} mixed_replay_capture_v1_t;

static void remove_if_present(const char *name) {
  if (name && cmeta_fs_access(name, SALTS_FS_ACCESS_EXISTS) == 0)
    check_equal(tt_remove_file(name), 0);
}
static void cleanup_wal_files(const char *name) {
  remove_if_present(name);
  remove_if_present(lock_path);
}
static void expect_writer_lock(const mesh_control_wal_config_v1_t *config) {
#ifdef _WIN32
  check_equal(mesh_control_wal_open_v1(&second, config), MESH_CONTROL_WAL_LOCKED);
#else
  pid_t child = fork();
  check_greater_equal(child, 0);
  if (child == 0) {
    mesh_control_wal_v1_t other = {0};
    _exit(mesh_control_wal_open_v1(&other, config) == MESH_CONTROL_WAL_LOCKED ? 0 : 1);
  }
  int status;
  check_equal(waitpid(child, &status, 0), child);
  check_true(WIFEXITED(status));
  check_equal(WEXITSTATUS(status), 0);
#endif
}

static void make_config(mesh_control_wal_config_v1_t *config, const char *path) {
  size_t index;
  memset(config, 0, sizeof(*config));
  config->path = path;
  config->record_capacity = 2u;
  config->byte_capacity = 64u * 1024u;
  config->principal_epoch = 1u;
  config->incarnation = 1u;
  config->certificate_serial = 1u;
  config->session_id[0] = 1u;
  memset(config->authentication_key, 0xa5, sizeof(config->authentication_key));
  for (index = 0u; index < MESH_CONTROL_DIGEST_SIZE; ++index) {
    config->mesh_id[index] = (uint8_t)(0x30u + index);
    config->node_id[index] = (uint8_t)(0x40u + index);
    config->controller_node_id[index] = (uint8_t)(0x40u + index);
  }
  check_equal(
      mesh_mgmt_ed25519_public_from_private(TEST_PRIVATE_KEY, config->controller_principal),
      MESH_MGMT_CRYPTO_OK);
}

static size_t make_signed_frame(uint64_t sequence, uint8_t message_seed,
                                uint8_t frame[MESH_MGMT_FRAME_MAX]) {
  static const uint8_t body[] = {1u, 2u, 3u};
  mesh_control_envelope_v1_t envelope;
  mesh_mgmt_sign_input_v1_t sign_input;
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
    envelope.message_id[index] = (uint8_t)(message_seed + index);
    envelope.request_id[index] = (uint8_t)(message_seed + 0x20u + index);
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

  memset(&sign_input, 0, sizeof(sign_input));
  sign_input.minor = MESH_MGMT_MINOR_V1;
  sign_input.kind = MESH_MGMT_KIND_CONTROL_FRAME;
  sign_input.private_key = TEST_PRIVATE_KEY;
  sign_input.payload = payload;
  sign_input.payload_len = payload_size;
  memcpy(sign_input.header.mesh_id_hash, envelope.mesh_id, sizeof(sign_input.header.mesh_id_hash));
  memcpy(sign_input.header.origin_node_id, envelope.origin_node_id,
         sizeof(sign_input.header.origin_node_id));
  memcpy(sign_input.header.target_node_id, envelope.target_node_id,
         sizeof(sign_input.header.target_node_id));
  sign_input.header.principal_epoch = 1u;
  sign_input.header.incarnation = 1u;
  sign_input.header.session_id[0] = 1u;
  sign_input.header.origin_sequence = sequence;
  memcpy(sign_input.header.message_id, envelope.message_id, sizeof(sign_input.header.message_id));
  sign_input.header.issued_at_ms = envelope.issued_at_ms;
  sign_input.header.expires_at_ms = envelope.expires_at_ms;
  sign_input.header.certificate_serial = 1u;
  check_equal(mesh_mgmt_envelope_sign_v1(&sign_input, frame, MESH_MGMT_FRAME_MAX, &frame_size),
               MESH_MGMT_ENVELOPE_OK);
  return frame_size;
}

static int capture_count(void *context, const mesh_control_wal_record_view_v1_t *record) {
  size_t *count = context;
  mesh_mgmt_verified_envelope_v1_t verified;
  if (!count || !record || record->log_index != *count + 1u ||
      mesh_mgmt_envelope_verify_v1(record->signed_frame, record->signed_frame_size, &verified) !=
          MESH_MGMT_ENVELOPE_OK) return -1;
  (*count)++;
  return 0;
}

static void prepare_result(mesh_control_wal_config_v1_t *config) {
  uint8_t frame[MESH_MGMT_FRAME_MAX];
  uint64_t index = 0u;
  make_config(config, path);
  size_t frame_size = make_signed_frame(1u, 0x10u, frame);
  check_equal(mesh_control_wal_open_v1(&wal, config), MESH_CONTROL_WAL_OK);
  check_equal(mesh_control_wal_append_v1(&wal, 1u, 1100u, frame, frame_size, &index),
              MESH_CONTROL_WAL_OK);
  mesh_control_wal_operation_result_v1_t result = {0};
  result.operation_id[0] = 0x71u;
  result.resource_kind = MESH_CONTROL_RESOURCE_NETWORK;
  result.action = MESH_CONTROL_DESIRED_APPLY;
  result.outcome = MESH_CONTROL_WAL_OPERATION_SUCCEEDED;
  result.resource_id[0] = 0x72u;
  result.desired_epoch = 1u;
  check_equal(mesh_control_wal_append_operation_result_v1(&wal, 2u, 1200u, &result, &index),
              MESH_CONTROL_WAL_OK);
  check_equal(index, 2u);
}

static int capture_record(void *context, const mesh_control_wal_record_view_v1_t *record) {
  replay_capture_v1_t *capture = (replay_capture_v1_t *)context;
  mesh_mgmt_verified_envelope_v1_t verified;

  if (!capture || !record || capture->count >= 4u ||
      mesh_mgmt_envelope_verify_v1(record->signed_frame, record->signed_frame_size, &verified) !=
          MESH_MGMT_ENVELOPE_OK) {
    return -1;
  }
  capture->indexes[capture->count] = record->log_index;
  capture->accepted_at_ms[capture->count] = record->accepted_at_ms;
  capture->count++;
  return 0;
}

static int reject_record(void *context, const mesh_control_wal_record_view_v1_t *record) {
  (void)context;
  (void)record;
  return -1;
}

static int capture_mixed_record(void *context, const mesh_control_wal_record_view_v1_t *record) {
  mixed_replay_capture_v1_t *capture = (mixed_replay_capture_v1_t *)context;
  if (!capture || !record || capture->count >= 2u)
    return -1;
  capture->types[capture->count++] = record->record_type;
  if (record->record_type == MESH_CONTROL_WAL_RECORD_OPERATION_RESULT)
    capture->operation_result = record->operation_result;
  return 0;
}

static void test_wal_appends_reopens_and_replays_signed_frames(void) {
  mesh_control_wal_config_v1_t config;
  mesh_control_wal_stats_v1_t stats;
  replay_capture_v1_t capture = {0};
  uint8_t first[MESH_MGMT_FRAME_MAX];
  uint8_t second_frame[MESH_MGMT_FRAME_MAX];
  uint8_t different[MESH_MGMT_FRAME_MAX];
  size_t first_size;
  size_t second_size;
  size_t different_size;
  size_t replayed = 0u;
  uint64_t log_index = 0u;

  check_not_null(path);
  if (!path)
    return;
  cleanup_wal_files(path);
  make_config(&config, path);
  first_size = make_signed_frame(1u, 0x10u, first);
  second_size = make_signed_frame(2u, 0x20u, second_frame);
  different_size = make_signed_frame(3u, 0x30u, different);

  check_equal(mesh_control_wal_open_v1(&wal, &config), MESH_CONTROL_WAL_OK);
  check_equal(mesh_control_wal_append_v1(&wal, 1u, 1100u, first, first_size, &log_index),
               MESH_CONTROL_WAL_OK);
  check_equal(log_index, 1u);
  check_equal(mesh_control_wal_append_v1(&wal, 1u, 1100u, first, first_size, &log_index),
               MESH_CONTROL_WAL_OK);
  check_equal(wal.record_count, 1u);
  check_equal(mesh_control_wal_append_v1(&wal, 1u, 1100u, different, different_size, &log_index),
               MESH_CONTROL_WAL_CONFLICT);
  check_equal(mesh_control_wal_append_v1(&wal, 2u, 1200u, second_frame, second_size, &log_index),
               MESH_CONTROL_WAL_OK);
  check_equal(log_index, 2u);
  check_equal(mesh_control_wal_append_v1(&wal, 3u, 1300u, different, different_size, &log_index),
               MESH_CONTROL_WAL_RESOURCE_EXHAUSTED);
  expect_writer_lock(&config);
  mesh_control_wal_close_v1(&wal);

  check_equal(mesh_control_wal_open_v1(&second, &config), MESH_CONTROL_WAL_OK);
  check_equal(second.tail_index, 2u);
  check_equal(second.record_count, 2u);
  check_equal(
      mesh_control_wal_append_v1(&second, 2u, 1200u, second_frame, second_size, &log_index),
      MESH_CONTROL_WAL_OK);
  check_equal(second.record_count, 2u);
  check_equal(mesh_control_wal_get_stats_v1(&second, &stats), MESH_CONTROL_WAL_OK);
  check_equal(stats.base_index, 0u);
  check_equal(stats.tail_index, 2u);
  check_equal(stats.record_count, 2u);
  check_equal(stats.record_capacity, 2u);
  check_equal(stats.byte_capacity, config.byte_capacity);
  check_true(stats.file_size > TEST_WAL_HEADER_SIZE);
  check_true(stats.open);
  check_false(stats.faulted);
  check_equal(mesh_control_wal_replay_v1(&second, 0u, capture_record, &capture, &replayed),
               MESH_CONTROL_WAL_OK);
  check_equal(replayed, 2u);
  check_equal(capture.count, 2u);
  check_equal(capture.indexes[0], 1u);
  check_equal(capture.indexes[1], 2u);
  check_equal(capture.accepted_at_ms[0], 1100u);
  check_equal(capture.accepted_at_ms[1], 1200u);

  memset(&capture, 0, sizeof(capture));
  replayed = 0u;
  check_equal(mesh_control_wal_replay_v1(&second, 1u, capture_record, &capture, &replayed),
               MESH_CONTROL_WAL_OK);
  check_equal(replayed, 1u);
  check_equal(capture.count, 1u);
  check_equal(capture.indexes[0], 2u);
  check_equal(mesh_control_wal_replay_v1(&second, 0u, reject_record, NULL, &replayed),
               MESH_CONTROL_WAL_CALLBACK_FAILED);
  check_equal(mesh_control_wal_replay_v1(&second, 3u, capture_record, &capture, &replayed),
               MESH_CONTROL_WAL_CONFLICT);

  mesh_control_wal_close_v1(&second);
  cleanup_wal_files(path);
}

static void test_wal_rejects_wrong_binding_key_and_tampering(void) {
  mesh_control_wal_config_v1_t config;
  mesh_control_wal_config_v1_t wrong;
  uint8_t frame[MESH_MGMT_FRAME_MAX];
  uint8_t byte = 0u;
  size_t frame_size;
  uint64_t log_index = 0u;

  check_not_null(path);
  if (!path)
    return;
  cleanup_wal_files(path);
  make_config(&config, path);
  frame_size = make_signed_frame(1u, 0x10u, frame);
  check_equal(mesh_control_wal_open_v1(&wal, &config), MESH_CONTROL_WAL_OK);
  check_equal(mesh_control_wal_append_v1(&wal, 1u, 1100u, frame, frame_size, &log_index),
               MESH_CONTROL_WAL_OK);
  mesh_control_wal_close_v1(&wal);

  wrong = config;
  wrong.node_id[0] ^= 1u;
  check_equal(mesh_control_wal_open_v1(&reopened, &wrong), MESH_CONTROL_WAL_BINDING_MISMATCH);
  wrong = config;
  wrong.authentication_key[0] ^= 1u;
  check_equal(mesh_control_wal_open_v1(&reopened, &wrong), MESH_CONTROL_WAL_AUTH_FAILED);

  file = cmeta_fs_open(path, SALTS_FS_O_RDWR, 0);
  check_true(file != SALTS_INVALID_FILE);
  check_equal(cmeta_fs_pread(file, (char *)&byte, 1u,
                              TEST_WAL_HEADER_SIZE + TEST_WAL_RECORD_HEADER_SIZE + 10u),
               1);
  byte ^= 1u;
  check_equal(cmeta_fs_pwrite(file, (const char *)&byte, 1u,
                               TEST_WAL_HEADER_SIZE + TEST_WAL_RECORD_HEADER_SIZE + 10u),
               1);
  check_equal(cmeta_fs_fsync(file), 0);
  check_equal(cmeta_fs_close(file), 0);
  file = SALTS_INVALID_FILE;
  check_equal(mesh_control_wal_open_v1(&reopened, &config), MESH_CONTROL_WAL_AUTH_FAILED);

  cleanup_wal_files(path);
}

static void test_wal_rejects_a_partial_tail(void) {
  mesh_control_wal_config_v1_t config;
  cmeta_fs_stat_t stat;
  uint8_t frame[MESH_MGMT_FRAME_MAX];
  size_t frame_size;
  uint64_t log_index = 0u;

  check_not_null(path);
  if (!path)
    return;
  cleanup_wal_files(path);
  make_config(&config, path);
  frame_size = make_signed_frame(1u, 0x10u, frame);
  check_equal(mesh_control_wal_open_v1(&wal, &config), MESH_CONTROL_WAL_OK);
  check_equal(mesh_control_wal_append_v1(&wal, 1u, 1100u, frame, frame_size, &log_index),
               MESH_CONTROL_WAL_OK);
  mesh_control_wal_close_v1(&wal);
  check_equal(cmeta_fs_stat(path, &stat), 0);
  file = cmeta_fs_open(path, SALTS_FS_O_RDWR, 0);
  check_true(file != SALTS_INVALID_FILE);
  check_equal(cmeta_fs_ftruncate(file, (int64_t)stat.size - 1), 0);
  check_equal(cmeta_fs_fsync(file), 0);
  check_equal(cmeta_fs_close(file), 0);
  file = SALTS_INVALID_FILE;
  check_equal(mesh_control_wal_open_v1(&reopened, &config), MESH_CONTROL_WAL_CORRUPT);

  cleanup_wal_files(path);
}

static void test_wal_authenticates_and_replays_operation_results(void) {
  mesh_control_wal_config_v1_t config;
  mesh_control_wal_operation_result_v1_t operation_result;
  mixed_replay_capture_v1_t capture = {0};
  uint8_t frame[MESH_MGMT_FRAME_MAX];
  size_t frame_size;
  size_t replayed = 0u;
  uint64_t log_index = 0u;

  check_not_null(path);
  if (!path)
    return;
  cleanup_wal_files(path);
  make_config(&config, path);
  frame_size = make_signed_frame(1u, 0x10u, frame);
  memset(&operation_result, 0, sizeof(operation_result));
  operation_result.operation_id[0] = 0x71u;
  operation_result.resource_kind = MESH_CONTROL_RESOURCE_NETWORK;
  operation_result.action = MESH_CONTROL_DESIRED_APPLY;
  operation_result.outcome = MESH_CONTROL_WAL_OPERATION_SUCCEEDED;
  operation_result.resource_id[0] = 0x72u;
  operation_result.desired_epoch = 1u;

  check_equal(mesh_control_wal_open_v1(&wal, &config), MESH_CONTROL_WAL_OK);
  check_equal(mesh_control_wal_append_v1(&wal, 1u, 1100u, frame, frame_size, &log_index),
               MESH_CONTROL_WAL_OK);
  check_equal(
      mesh_control_wal_append_operation_result_v1(&wal, 2u, 1200u, &operation_result, &log_index),
      MESH_CONTROL_WAL_OK);
  check_equal(log_index, 2u);
  check_equal(
      mesh_control_wal_append_operation_result_v1(&wal, 2u, 1200u, &operation_result, &log_index),
      MESH_CONTROL_WAL_OK);
  check_equal(mesh_control_wal_replay_v1(&wal, 0u, capture_mixed_record, &capture, &replayed),
               MESH_CONTROL_WAL_OK);
  check_equal(replayed, 2u);
  check_equal(capture.count, 2u);
  check_equal(capture.types[0], MESH_CONTROL_WAL_RECORD_SIGNED_INTENT);
  check_equal(capture.types[1], MESH_CONTROL_WAL_RECORD_OPERATION_RESULT);
  check_equal(capture.operation_result.operation_id, operation_result.operation_id,
               sizeof(operation_result.operation_id));
  check_equal(capture.operation_result.outcome, MESH_CONTROL_WAL_OPERATION_SUCCEEDED);

  mesh_control_wal_close_v1(&wal);
  cleanup_wal_files(path);
}

static void test_wal_compacts_only_at_a_checkpointed_tail(void) {
  mesh_control_wal_config_v1_t config;
  mesh_control_wal_stats_v1_t stats;
  replay_capture_v1_t capture = {0};
  uint8_t first[MESH_MGMT_FRAME_MAX];
  uint8_t second[MESH_MGMT_FRAME_MAX];
  uint8_t third[MESH_MGMT_FRAME_MAX];
  size_t first_size;
  size_t second_size;
  size_t third_size;
  size_t replayed = 0u;
  uint64_t log_index = 0u;

  check_not_null(path);
  if (!path)
    return;
  cleanup_wal_files(path);
  make_config(&config, path);
  first_size = make_signed_frame(1u, 0x10u, first);
  second_size = make_signed_frame(2u, 0x20u, second);
  third_size = make_signed_frame(3u, 0x30u, third);
  check_equal(mesh_control_wal_open_v1(&wal, &config), MESH_CONTROL_WAL_OK);
  check_equal(mesh_control_wal_append_v1(&wal, 1u, 1100u, first, first_size, &log_index),
               MESH_CONTROL_WAL_OK);
  check_equal(mesh_control_wal_append_v1(&wal, 2u, 1200u, second, second_size, &log_index),
               MESH_CONTROL_WAL_OK);
  check_equal(mesh_control_wal_compact_v1(&wal, 1u), MESH_CONTROL_WAL_CONFLICT);
  check_equal(mesh_control_wal_compact_v1(&wal, 2u), MESH_CONTROL_WAL_OK);
  check_equal(mesh_control_wal_get_stats_v1(&wal, &stats), MESH_CONTROL_WAL_OK);
  check_equal(stats.base_index, 2u);
  check_equal(stats.tail_index, 2u);
  check_equal(stats.record_count, 0u);
  check_equal(stats.file_size, TEST_WAL_HEADER_SIZE);
  check_equal(mesh_control_wal_replay_v1(&wal, 2u, capture_record, &capture, &replayed),
               MESH_CONTROL_WAL_OK);
  check_equal(replayed, 0u);
  mesh_control_wal_close_v1(&wal);

  check_equal(mesh_control_wal_open_v1(&wal, &config), MESH_CONTROL_WAL_OK);
  check_equal(wal.base_index, 2u);
  check_equal(wal.tail_index, 2u);
  check_equal(mesh_control_wal_append_v1(&wal, 3u, 1300u, third, third_size, &log_index),
               MESH_CONTROL_WAL_OK);
  check_equal(mesh_control_wal_replay_v1(&wal, 2u, capture_record, &capture, &replayed),
               MESH_CONTROL_WAL_OK);
  check_equal(replayed, 1u);
  check_equal(capture.indexes[0], 3u);
  mesh_control_wal_close_v1(&wal);
  cleanup_wal_files(path);
}

spec("mesh control signed intent WAL") {
  before_each() {
    memset(&wal, 0, sizeof(wal));
    memset(&second, 0, sizeof(second));
    memset(&reopened, 0, sizeof(reopened));
    wal.lock_file = second.lock_file = reopened.lock_file = SALTS_INVALID_FILE;
    file = SALTS_INVALID_FILE;
    contents = after = NULL;
    lock_path = staging = NULL;
    staging_directory = 0;
#ifdef MESH_CONTROL_WAL_TEST_FAULT
    uncertain = 0;
    publications = 0;
#endif
    path = tt_make_temp_file("mesh-control-wal", ".bin");
    check_not_null(path);
    check_equal(tt_remove_file(path), 0);
    lock_path = tstr_format("{}.lock", path);
    staging = tstr_format("{}.compact", path);
    check_not_null(lock_path);
    check_not_null(staging);
  }
  after_each() {
    if (file != SALTS_INVALID_FILE) (void)cmeta_fs_close(file);
    mesh_control_wal_close_v1(&wal);
    mesh_control_wal_close_v1(&second);
    mesh_control_wal_close_v1(&reopened);
    if (staging_directory) check_equal(cmeta_fs_rmdir(staging), 0);
    else remove_if_present(staging);
    cleanup_wal_files(path);
    free(contents);
    free(after);
    free(path);
    tstr_freep(&lock_path);
    tstr_freep(&staging);
  }
#ifndef MESH_CONTROL_WAL_TEST_FAULT
  describe("authenticated bounded append and replay") {
    it("appends idempotently and replays signed frames after reopen") {
      test_wal_appends_reopens_and_replays_signed_frames();
    }
    it("rejects wrong identity, wrong key and modified records") {
      test_wal_rejects_wrong_binding_key_and_tampering();
    }
    it("fails closed instead of discarding a partial tail") { test_wal_rejects_a_partial_tail(); }
    it("authenticates and replays durable operation results") {
      test_wal_authenticates_and_replays_operation_results();
    }
    it("compacts only at a checkpointed tail and preserves the HMAC anchor") {
      test_wal_compacts_only_at_a_checkpointed_tail();
    }
  }
  it("keeps authenticated operation results after an unpublished compaction failure") {
    mesh_control_wal_config_v1_t config;
    prepare_result(&config);
    uint8_t anchor[MESH_CONTROL_DIGEST_SIZE];
    memcpy(anchor, wal.tail_authenticator, sizeof(anchor));
    check_equal(cmeta_fs_mkdir(staging, 0700), 0);
    staging_directory = 1;
    check_equal(mesh_control_wal_compact_v1(&wal, 2u), MESH_CONTROL_WAL_IO);
    check_false(wal.faulted);
    check_equal(wal.base_index, 0u);
    check_equal(wal.tail_index, 2u);
    check_equal(wal.record_count, 2u);
    check_equal(wal.tail_authenticator, anchor, sizeof(anchor));
    mixed_replay_capture_v1_t capture = {0};
    size_t replayed = 0u;
    check_equal(mesh_control_wal_replay_v1(&wal, 0u, capture_mixed_record, &capture, &replayed),
                MESH_CONTROL_WAL_OK);
    check_equal(replayed, 2u);
    check_equal(capture.operation_result.outcome, MESH_CONTROL_WAL_OPERATION_SUCCEEDED);
    check_equal(cmeta_fs_rmdir(staging), 0);
    staging_directory = 0;
    check_equal(mesh_control_wal_compact_v1(&wal, 2u), MESH_CONTROL_WAL_OK);
    check_equal(wal.base_index, 2u);
    check_equal(wal.record_count, 0u);
  }
  it("requires durable reopen while preserving the exact authenticated log bytes") {
    mesh_control_wal_config_v1_t config;
    prepare_result(&config);
    mesh_control_wal_close_v1(&wal);
    size_t before_size = 0u, after_size = 0u;
    contents = tt_read_file(path, &before_size);
    check_not_null(contents);
    check_equal(cmeta_fs_mkdir(staging, 0700), 0);
    staging_directory = 1;
    check_equal(mesh_control_wal_open_v1(&wal, &config), MESH_CONTROL_WAL_IO);
    check_false(wal.open);
    check_equal(wal.lock_file, SALTS_INVALID_FILE);
    check_equal(cmeta_fs_rmdir(staging), 0);
    staging_directory = 0;
    check_equal(mesh_control_wal_open_v1(&wal, &config), MESH_CONTROL_WAL_OK);
    after = tt_read_file(path, &after_size);
    check_not_null(after);
    check_equal(after_size, before_size);
    check_equal(after, contents, before_size);
    check_equal(wal.record_count, 2u);
    mixed_replay_capture_v1_t capture = {0};
    size_t replayed = 0u;
    check_equal(mesh_control_wal_replay_v1(&wal, 0u, capture_mixed_record, &capture, &replayed),
                MESH_CONTROL_WAL_OK);
    check_equal(replayed, 2u);
    check_equal(capture.types[1], MESH_CONTROL_WAL_RECORD_OPERATION_RESULT);
  }
  it("reopens a multi-chunk WAL without dropping or rewriting its signed records") {
    mesh_control_wal_config_v1_t config;
    make_config(&config, path);
    config.record_capacity = 32u;
    uint8_t frame[MESH_MGMT_FRAME_MAX];
    uint64_t index = 0u;
    check_equal(mesh_control_wal_open_v1(&wal, &config), MESH_CONTROL_WAL_OK);
    for (uint64_t i = 1u; i <= config.record_capacity; ++i) {
      size_t size = make_signed_frame(i, (uint8_t)(0x10u + i), frame);
      check_equal(mesh_control_wal_append_v1(&wal, i, 1100u, frame, size, &index), MESH_CONTROL_WAL_OK);
      check_equal(index, i);
    }
    check_greater(wal.file_size, 8192u);
    mesh_control_wal_close_v1(&wal);
    size_t before_size = 0u, after_size = 0u;
    contents = tt_read_file(path, &before_size);
    check_not_null(contents);
    check_equal(mesh_control_wal_open_v1(&wal, &config), MESH_CONTROL_WAL_OK);
    after = tt_read_file(path, &after_size);
    check_not_null(after);
    check_equal(after_size, before_size);
    check_equal(after, contents, before_size);
    size_t count = 0u, replayed = 0u;
    check_equal(mesh_control_wal_replay_v1(&wal, 0u, capture_count, &count, &replayed), MESH_CONTROL_WAL_OK);
    check_equal(count, config.record_capacity);
    check_equal(replayed, config.record_capacity);
    check_equal(wal.tail_index, (uint64_t)config.record_capacity);
  }
#else
  it("fences uncertain compaction and reloads the published HMAC anchor") {
    mesh_control_wal_config_v1_t config;
    prepare_result(&config);
    uint8_t anchor[MESH_CONTROL_DIGEST_SIZE];
    memcpy(anchor, wal.tail_authenticator, sizeof(anchor));
    uncertain = 1;
    publications = 0;
    check_equal(mesh_control_wal_compact_v1(&wal, 2u), MESH_CONTROL_WAL_COMMIT_UNKNOWN);
    check_true(wal.faulted);
    expect_writer_lock(&config);
    uint8_t frame[MESH_MGMT_FRAME_MAX];
    size_t size = make_signed_frame(3u, 0x30u, frame);
    uint64_t index = 99u;
    check_equal(mesh_control_wal_append_v1(&wal, 3u, 1300u, frame, size, &index),
                MESH_CONTROL_WAL_INVALID_STATE);
    check_equal(index, 0u);
    size_t replayed = 99u;
    mixed_replay_capture_v1_t capture = {0};
    check_equal(mesh_control_wal_replay_v1(&wal, 0u, capture_mixed_record, &capture, &replayed),
                MESH_CONTROL_WAL_INVALID_STATE);
    check_equal(replayed, 0u);
    check_equal(mesh_control_wal_compact_v1(&wal, 2u), MESH_CONTROL_WAL_INVALID_STATE);
    check_equal(publications, 1u);
    mesh_control_wal_close_v1(&wal);
    uncertain = 0;
    check_equal(mesh_control_wal_open_v1(&wal, &config), MESH_CONTROL_WAL_OK);
    check_equal(publications, 2u);
    check_equal(wal.base_index, 2u);
    check_equal(wal.tail_index, 2u);
    check_equal(wal.record_count, 0u);
    check_equal(wal.base_authenticator, anchor, sizeof(anchor));
    check_equal(mesh_control_wal_append_v1(&wal, 3u, 1300u, frame, size, &index), MESH_CONTROL_WAL_OK);
    check_equal(index, 3u);
    mesh_control_wal_close_v1(&wal);
    check_equal(mesh_control_wal_open_v1(&wal, &config), MESH_CONTROL_WAL_OK);
    check_equal(wal.base_index, 2u);
    check_equal(wal.tail_index, 3u);
    check_equal(wal.record_count, 1u);
  }
  it("withholds successful initialization after unknown header publication and releases the lock") {
    mesh_control_wal_config_v1_t config;
    make_config(&config, path);
    uncertain = 1;
    check_equal(mesh_control_wal_open_v1(&wal, &config), MESH_CONTROL_WAL_COMMIT_UNKNOWN);
    check_false(wal.open);
    check_equal(wal.lock_file, SALTS_INVALID_FILE);
    uncertain = 0;
    check_equal(mesh_control_wal_open_v1(&second, &config), MESH_CONTROL_WAL_OK);
    check_equal(second.base_index, 0u);
    check_equal(second.record_count, 0u);
  }
  it("rejects uncertain reopen before replay and then durably retains operation results") {
    mesh_control_wal_config_v1_t config;
    prepare_result(&config);
    mesh_control_wal_close_v1(&wal);
    uncertain = 1;
    publications = 0;
    check_equal(mesh_control_wal_open_v1(&wal, &config), MESH_CONTROL_WAL_COMMIT_UNKNOWN);
    check_false(wal.open);
    check_equal(wal.lock_file, SALTS_INVALID_FILE);
    check_equal(publications, 1u);
    size_t replayed = 99u;
    mixed_replay_capture_v1_t capture = {0};
    check_equal(mesh_control_wal_replay_v1(&wal, 0u, capture_mixed_record, &capture, &replayed),
                MESH_CONTROL_WAL_INVALID_STATE);
    check_equal(capture.count, 0u);
    uncertain = 0;
    check_equal(mesh_control_wal_open_v1(&wal, &config), MESH_CONTROL_WAL_OK);
    check_equal(publications, 2u);
    check_equal(mesh_control_wal_replay_v1(&wal, 0u, capture_mixed_record, &capture, &replayed),
                MESH_CONTROL_WAL_OK);
    check_equal(replayed, 2u);
    check_equal(capture.operation_result.outcome, MESH_CONTROL_WAL_OPERATION_SUCCEEDED);
  }

#endif
}
