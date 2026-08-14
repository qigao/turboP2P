#include "mesh_control_wal.h"

#include "mesh_control_mmp.h"
#include "mesh_mgmt_crypto.h"

#include <openssl/hmac.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WAL_FILE_MODE 0600
#define WAL_HEADER_SIZE 256u
#define WAL_HEADER_AUTH_OFFSET 224u
#define WAL_RECORD_HEADER_SIZE 72u
#define WAL_RECORD_AUTH_SIZE 32u
#define WAL_RECORD_FIXED_SIZE (WAL_RECORD_HEADER_SIZE + WAL_RECORD_AUTH_SIZE)
#define WAL_RECORD_TYPE_SIGNED_INTENT 1u
#define WAL_RECORD_TYPE_OPERATION_RESULT 2u
#define WAL_OPERATION_RESULT_SIZE 80u

static const uint8_t WAL_MAGIC[8] = {'T', 'M', 'C', 'W', 'A', 'L', '0', '1'};
static const uint8_t WAL_RECORD_MAGIC[4] = {'T', 'C', 'W', 'R'};

static int bytes_zero(const uint8_t *bytes, size_t size) {
  uint8_t aggregate = 0u;
  size_t index;

  if (!bytes)
    return 1;
  for (index = 0u; index < size; ++index)
    aggregate |= bytes[index];
  return aggregate == 0u;
}

static int operation_result_valid(const mesh_control_wal_operation_result_v1_t *result) {
  return result && !bytes_zero(result->operation_id, sizeof(result->operation_id)) &&
         result->resource_kind >= MESH_CONTROL_RESOURCE_NODE &&
         result->resource_kind <= MESH_CONTROL_RESOURCE_RELEASE &&
         (result->action == MESH_CONTROL_DESIRED_APPLY ||
          result->action == MESH_CONTROL_DESIRED_DELETE) &&
         (result->outcome == MESH_CONTROL_WAL_OPERATION_SUCCEEDED ||
          result->outcome == MESH_CONTROL_WAL_OPERATION_FAILED) &&
         result->reserved == 0u && !bytes_zero(result->resource_id, sizeof(result->resource_id)) &&
         result->desired_epoch != 0u;
}

static void write_u16(uint8_t output[2], uint16_t value) {
  output[0] = (uint8_t)(value >> 8u);
  output[1] = (uint8_t)value;
}

static void write_u32(uint8_t output[4], uint32_t value) {
  output[0] = (uint8_t)(value >> 24u);
  output[1] = (uint8_t)(value >> 16u);
  output[2] = (uint8_t)(value >> 8u);
  output[3] = (uint8_t)value;
}

static void write_u64(uint8_t output[8], uint64_t value) {
  size_t index;
  for (index = 0u; index < 8u; ++index)
    output[index] = (uint8_t)(value >> (56u - index * 8u));
}

static uint16_t read_u16(const uint8_t input[2]) {
  return (uint16_t)(((uint16_t)input[0] << 8u) | input[1]);
}

static uint32_t read_u32(const uint8_t input[4]) {
  return ((uint32_t)input[0] << 24u) | ((uint32_t)input[1] << 16u) | ((uint32_t)input[2] << 8u) |
         input[3];
}

static uint64_t read_u64(const uint8_t input[8]) {
  uint64_t value = 0u;
  size_t index;
  for (index = 0u; index < 8u; ++index)
    value = (value << 8u) | input[index];
  return value;
}

static int encode_operation_result(const mesh_control_wal_operation_result_v1_t *result,
                                   uint8_t output[WAL_OPERATION_RESULT_SIZE]) {
  if (!operation_result_valid(result) || !output)
    return 0;
  memset(output, 0, WAL_OPERATION_RESULT_SIZE);
  memcpy(output, "TCRES001", 8u);
  write_u32(output + 8u, MESH_CONTROL_WAL_VERSION_V1);
  write_u32(output + 12u, WAL_OPERATION_RESULT_SIZE);
  memcpy(output + 16u, result->operation_id, sizeof(result->operation_id));
  write_u16(output + 32u, result->resource_kind);
  write_u16(output + 34u, result->action);
  write_u16(output + 36u, result->outcome);
  memcpy(output + 40u, result->resource_id, sizeof(result->resource_id));
  write_u64(output + 72u, result->desired_epoch);
  return 1;
}

static int decode_operation_result(const uint8_t *bytes, size_t size,
                                   mesh_control_wal_operation_result_v1_t *out_result) {
  if (!bytes || size != WAL_OPERATION_RESULT_SIZE || !out_result ||
      memcmp(bytes, "TCRES001", 8u) != 0 || read_u32(bytes + 8u) != MESH_CONTROL_WAL_VERSION_V1 ||
      read_u32(bytes + 12u) != WAL_OPERATION_RESULT_SIZE || read_u16(bytes + 38u) != 0u) {
    return 0;
  }
  memset(out_result, 0, sizeof(*out_result));
  memcpy(out_result->operation_id, bytes + 16u, sizeof(out_result->operation_id));
  out_result->resource_kind = read_u16(bytes + 32u);
  out_result->action = read_u16(bytes + 34u);
  out_result->outcome = read_u16(bytes + 36u);
  memcpy(out_result->resource_id, bytes + 40u, sizeof(out_result->resource_id));
  out_result->desired_epoch = read_u64(bytes + 72u);
  return operation_result_valid(out_result);
}

static int calculate_hmac(const uint8_t key[MESH_CONTROL_WAL_AUTH_KEY_SIZE_V1],
                          const uint8_t *bytes, size_t size,
                          uint8_t output[MESH_CONTROL_DIGEST_SIZE]) {
  unsigned int output_size = 0u;

  if (!key || !bytes || !output || size > INT_MAX)
    return 0;
  return HMAC(EVP_sha256(), key, MESH_CONTROL_WAL_AUTH_KEY_SIZE_V1, bytes, size, output,
              &output_size) != NULL &&
         output_size == MESH_CONTROL_DIGEST_SIZE;
}

static int config_valid(const mesh_control_wal_config_v1_t *config) {
  size_t minimum_size = WAL_HEADER_SIZE + WAL_RECORD_FIXED_SIZE + 1u;

  return config && config->path && config->path[0] != '\0' &&
         turbo_fs_path_is_absolute(config->path) && strlen(config->path) < TURBO_FS_MAX_PATH - 6u &&
         config->record_capacity != 0u &&
         config->record_capacity <= MESH_CONTROL_WAL_MAX_RECORDS_V1 &&
         config->byte_capacity >= minimum_size &&
         config->byte_capacity <= MESH_CONTROL_WAL_MAX_FILE_SIZE_V1 &&
         !bytes_zero(config->mesh_id, sizeof(config->mesh_id)) &&
         !bytes_zero(config->node_id, sizeof(config->node_id)) &&
         !bytes_zero(config->controller_principal, sizeof(config->controller_principal)) &&
         !bytes_zero(config->controller_node_id, sizeof(config->controller_node_id)) &&
         config->principal_epoch != 0u && config->incarnation != 0u &&
         config->certificate_serial != 0u &&
         !bytes_zero(config->session_id, sizeof(config->session_id)) &&
         !bytes_zero(config->authentication_key, sizeof(config->authentication_key));
}

static mesh_control_wal_result_t write_all(turbo_file_t file, const uint8_t *bytes, size_t size) {
  size_t offset = 0u;
  while (offset < size) {
    int written = turbo_fs_write(file, (const char *)bytes + offset, size - offset);
    if (written <= 0)
      return MESH_CONTROL_WAL_IO;
    offset += (size_t)written;
  }
  return MESH_CONTROL_WAL_OK;
}

static mesh_control_wal_result_t read_exact(turbo_file_t file, uint8_t *bytes, size_t size) {
  size_t offset = 0u;
  while (offset < size) {
    int read_size = turbo_fs_read(file, (char *)bytes + offset, size - offset);
    if (read_size <= 0)
      return MESH_CONTROL_WAL_CORRUPT;
    offset += (size_t)read_size;
  }
  return MESH_CONTROL_WAL_OK;
}

static int encode_header(const mesh_control_wal_v1_t *wal, uint8_t output[WAL_HEADER_SIZE]) {
  uint8_t authenticator[MESH_CONTROL_DIGEST_SIZE];

  memset(output, 0, WAL_HEADER_SIZE);
  memcpy(output, WAL_MAGIC, sizeof(WAL_MAGIC));
  write_u32(output + 8u, MESH_CONTROL_WAL_VERSION_V1);
  write_u32(output + 12u, WAL_HEADER_SIZE);
  write_u64(output + 16u, wal->base_index);
  memcpy(output + 24u, wal->config.mesh_id, MESH_CONTROL_DIGEST_SIZE);
  memcpy(output + 56u, wal->config.node_id, MESH_CONTROL_NODE_ID_SIZE);
  memcpy(output + 88u, wal->config.controller_principal, MESH_CONTROL_DIGEST_SIZE);
  memcpy(output + 120u, wal->config.controller_node_id, MESH_CONTROL_NODE_ID_SIZE);
  write_u64(output + 152u, wal->config.principal_epoch);
  write_u64(output + 160u, wal->config.incarnation);
  write_u64(output + 168u, wal->config.certificate_serial);
  memcpy(output + 176u, wal->config.session_id, MESH_CONTROL_ID_SIZE);
  memcpy(output + 192u, wal->base_authenticator, MESH_CONTROL_DIGEST_SIZE);
  if (!calculate_hmac(wal->config.authentication_key, output, WAL_HEADER_AUTH_OFFSET,
                      authenticator)) {
    memset(output, 0, WAL_HEADER_SIZE);
    return 0;
  }
  memcpy(output + WAL_HEADER_AUTH_OFFSET, authenticator, sizeof(authenticator));
  return 1;
}

static mesh_control_wal_result_t validate_header(mesh_control_wal_v1_t *wal,
                                                 const uint8_t bytes[WAL_HEADER_SIZE]) {
  uint8_t authenticator[MESH_CONTROL_DIGEST_SIZE];

  if (memcmp(bytes, WAL_MAGIC, sizeof(WAL_MAGIC)) != 0 ||
      read_u32(bytes + 8u) != MESH_CONTROL_WAL_VERSION_V1 ||
      read_u32(bytes + 12u) != WAL_HEADER_SIZE) {
    return MESH_CONTROL_WAL_CORRUPT;
  }
  if (!calculate_hmac(wal->config.authentication_key, bytes, WAL_HEADER_AUTH_OFFSET,
                      authenticator)) {
    return MESH_CONTROL_WAL_AUTH_FAILED;
  }
  if (!mesh_mgmt_crypto_equal_32(authenticator, bytes + WAL_HEADER_AUTH_OFFSET)) {
    return MESH_CONTROL_WAL_AUTH_FAILED;
  }
  if (memcmp(bytes + 24u, wal->config.mesh_id, MESH_CONTROL_DIGEST_SIZE) != 0 ||
      memcmp(bytes + 56u, wal->config.node_id, MESH_CONTROL_NODE_ID_SIZE) != 0 ||
      memcmp(bytes + 88u, wal->config.controller_principal, MESH_CONTROL_DIGEST_SIZE) != 0 ||
      memcmp(bytes + 120u, wal->config.controller_node_id, MESH_CONTROL_NODE_ID_SIZE) != 0 ||
      read_u64(bytes + 152u) != wal->config.principal_epoch ||
      read_u64(bytes + 160u) != wal->config.incarnation ||
      read_u64(bytes + 168u) != wal->config.certificate_serial ||
      memcmp(bytes + 176u, wal->config.session_id, MESH_CONTROL_ID_SIZE) != 0) {
    return MESH_CONTROL_WAL_BINDING_MISMATCH;
  }
  wal->base_index = read_u64(bytes + 16u);
  memcpy(wal->base_authenticator, bytes + 192u, sizeof(wal->base_authenticator));
  wal->tail_index = wal->base_index;
  memcpy(wal->tail_previous_authenticator, wal->base_authenticator,
         sizeof(wal->tail_previous_authenticator));
  memcpy(wal->tail_authenticator, wal->base_authenticator, sizeof(wal->tail_authenticator));
  return MESH_CONTROL_WAL_OK;
}

static mesh_control_wal_result_t validate_signed_frame(const mesh_control_wal_v1_t *wal,
                                                       uint64_t accepted_at_ms,
                                                       const uint8_t *frame, size_t frame_size) {
  mesh_mgmt_verified_envelope_v1_t verified;
  mesh_mgmt_envelope_result_t verify_result;
  mesh_control_envelope_v1_t envelope;
  const uint8_t *body = NULL;
  size_t body_size = 0u;

  if (!frame || frame_size == 0u || frame_size > MESH_MGMT_FRAME_MAX)
    return MESH_CONTROL_WAL_CORRUPT;
  verify_result = mesh_mgmt_envelope_verify_v1(frame, frame_size, &verified);
  if (verify_result == MESH_MGMT_ENVELOPE_AUTH_FAILED ||
      verify_result == MESH_MGMT_ENVELOPE_CRYPTO_FAILURE)
    return MESH_CONTROL_WAL_AUTH_FAILED;
  if (verify_result != MESH_MGMT_ENVELOPE_OK ||
      verified.frame.kind != MESH_MGMT_KIND_CONTROL_FRAME ||
      mesh_control_mmp_payload_decode_v1(&verified, &envelope, &body, &body_size) !=
          MESH_CONTROL_MMP_OK) {
    return MESH_CONTROL_WAL_CORRUPT;
  }
  (void)body;
  (void)body_size;
  if (accepted_at_ms < envelope.issued_at_ms || accepted_at_ms >= envelope.expires_at_ms ||
      memcmp(envelope.mesh_id, wal->config.mesh_id, MESH_CONTROL_DIGEST_SIZE) != 0 ||
      memcmp(envelope.target_node_id, wal->config.node_id, MESH_CONTROL_NODE_ID_SIZE) != 0 ||
      memcmp(envelope.origin_principal, wal->config.controller_principal,
             MESH_CONTROL_DIGEST_SIZE) != 0 ||
      memcmp(envelope.origin_node_id, wal->config.controller_node_id, MESH_CONTROL_NODE_ID_SIZE) !=
          0 ||
      envelope.principal_epoch != wal->config.principal_epoch ||
      envelope.incarnation != wal->config.incarnation ||
      envelope.certificate_serial != wal->config.certificate_serial ||
      memcmp(envelope.session_id, wal->config.session_id, MESH_CONTROL_ID_SIZE) != 0) {
    return MESH_CONTROL_WAL_BINDING_MISMATCH;
  }
  return MESH_CONTROL_WAL_OK;
}

static int calculate_record_authenticator(const mesh_control_wal_v1_t *wal,
                                          const uint8_t header[WAL_RECORD_HEADER_SIZE],
                                          const uint8_t *frame, size_t frame_size,
                                          uint8_t output[MESH_CONTROL_DIGEST_SIZE]) {
  uint8_t input[WAL_RECORD_HEADER_SIZE + MESH_MGMT_FRAME_MAX];

  if (frame_size > MESH_MGMT_FRAME_MAX)
    return 0;
  memcpy(input, header, WAL_RECORD_HEADER_SIZE);
  memcpy(input + WAL_RECORD_HEADER_SIZE, frame, frame_size);
  return calculate_hmac(wal->config.authentication_key, input, WAL_RECORD_HEADER_SIZE + frame_size,
                        output);
}

static mesh_control_wal_result_t
validate_record(const mesh_control_wal_v1_t *wal, const uint8_t header[WAL_RECORD_HEADER_SIZE],
                const uint8_t *payload, const uint8_t authenticator[MESH_CONTROL_DIGEST_SIZE],
                uint64_t expected_index, const uint8_t expected_previous[MESH_CONTROL_DIGEST_SIZE],
                uint16_t *out_record_type,
                mesh_control_wal_operation_result_v1_t *out_operation_result) {
  uint8_t actual[MESH_CONTROL_DIGEST_SIZE];
  uint16_t record_type = read_u16(header + 6u);
  uint32_t payload_size = read_u32(header + 12u);
  uint64_t record_size = read_u64(header + 16u);
  uint64_t log_index = read_u64(header + 24u);
  uint64_t accepted_at_ms = read_u64(header + 32u);
  mesh_control_wal_operation_result_v1_t decoded_operation_result;

  if (memcmp(header, WAL_RECORD_MAGIC, sizeof(WAL_RECORD_MAGIC)) != 0 ||
      read_u16(header + 4u) != MESH_CONTROL_WAL_VERSION_V1 ||
      (record_type != WAL_RECORD_TYPE_SIGNED_INTENT &&
       record_type != WAL_RECORD_TYPE_OPERATION_RESULT) ||
      read_u32(header + 8u) != WAL_RECORD_HEADER_SIZE || payload_size == 0u ||
      payload_size > MESH_MGMT_FRAME_MAX ||
      record_size != WAL_RECORD_FIXED_SIZE + (uint64_t)payload_size ||
      log_index != expected_index ||
      memcmp(header + 40u, expected_previous, MESH_CONTROL_DIGEST_SIZE) != 0) {
    return MESH_CONTROL_WAL_CORRUPT;
  }
  if (!calculate_record_authenticator(wal, header, payload, payload_size, actual) ||
      !mesh_mgmt_crypto_equal_32(actual, authenticator))
    return MESH_CONTROL_WAL_AUTH_FAILED;
  if (out_record_type)
    *out_record_type = record_type;
  if (record_type == WAL_RECORD_TYPE_SIGNED_INTENT)
    return validate_signed_frame(wal, accepted_at_ms, payload, payload_size);
  if (accepted_at_ms == 0u || payload_size != WAL_OPERATION_RESULT_SIZE ||
      !decode_operation_result(payload, payload_size,
                               out_operation_result ? out_operation_result
                                                    : &decoded_operation_result)) {
    return MESH_CONTROL_WAL_CORRUPT;
  }
  return MESH_CONTROL_WAL_OK;
}

static mesh_control_wal_result_t create_empty_file(mesh_control_wal_v1_t *wal) {
  uint8_t header[WAL_HEADER_SIZE];
  turbo_file_t file = TURBO_INVALID_FILE;
  mesh_control_wal_result_t result = MESH_CONTROL_WAL_IO;

  if (!encode_header(wal, header))
    return MESH_CONTROL_WAL_AUTH_FAILED;
  file = turbo_fs_open(wal->path, TURBO_FS_O_WRONLY | TURBO_FS_O_CREAT | TURBO_FS_O_TRUNC,
                       WAL_FILE_MODE);
  if (file == TURBO_INVALID_FILE)
    return MESH_CONTROL_WAL_IO;
  result = write_all(file, header, sizeof(header));
  if (result == MESH_CONTROL_WAL_OK && turbo_fs_fsync(file) != 0)
    result = MESH_CONTROL_WAL_COMMIT_UNKNOWN;
  if (turbo_fs_close(file) != 0 && result == MESH_CONTROL_WAL_OK)
    result = MESH_CONTROL_WAL_COMMIT_UNKNOWN;
  if (result == MESH_CONTROL_WAL_OK)
    wal->file_size = WAL_HEADER_SIZE;
  return result;
}

static mesh_control_wal_result_t scan_existing(mesh_control_wal_v1_t *wal, size_t size) {
  uint8_t header[WAL_HEADER_SIZE];
  uint8_t record_header[WAL_RECORD_HEADER_SIZE];
  uint8_t frame[MESH_MGMT_FRAME_MAX];
  uint8_t authenticator[MESH_CONTROL_DIGEST_SIZE];
  uint8_t previous[MESH_CONTROL_DIGEST_SIZE];
  turbo_file_t file = TURBO_INVALID_FILE;
  size_t offset = 0u;
  uint64_t next_index;
  mesh_control_wal_result_t result;

  if (size < WAL_HEADER_SIZE || size > wal->config.byte_capacity)
    return MESH_CONTROL_WAL_CORRUPT;
  file = turbo_fs_open(wal->path, TURBO_FS_O_RDONLY, 0);
  if (file == TURBO_INVALID_FILE)
    return MESH_CONTROL_WAL_IO;
  result = read_exact(file, header, sizeof(header));
  if (result != MESH_CONTROL_WAL_OK)
    goto cleanup;
  result = validate_header(wal, header);
  if (result != MESH_CONTROL_WAL_OK)
    goto cleanup;
  memcpy(previous, wal->base_authenticator, sizeof(previous));
  next_index = wal->base_index;
  offset = WAL_HEADER_SIZE;
  while (offset < size) {
    uint32_t frame_size;
    uint64_t record_size;
    if (wal->record_count >= wal->config.record_capacity || size - offset < WAL_RECORD_FIXED_SIZE ||
        next_index == UINT64_MAX) {
      result = MESH_CONTROL_WAL_CORRUPT;
      goto cleanup;
    }
    result = read_exact(file, record_header, sizeof(record_header));
    if (result != MESH_CONTROL_WAL_OK)
      goto cleanup;
    frame_size = read_u32(record_header + 12u);
    record_size = read_u64(record_header + 16u);
    if (frame_size == 0u || frame_size > MESH_MGMT_FRAME_MAX ||
        record_size != WAL_RECORD_FIXED_SIZE + (uint64_t)frame_size ||
        record_size > size - offset) {
      result = MESH_CONTROL_WAL_CORRUPT;
      goto cleanup;
    }
    result = read_exact(file, frame, frame_size);
    if (result != MESH_CONTROL_WAL_OK)
      goto cleanup;
    result = read_exact(file, authenticator, sizeof(authenticator));
    if (result != MESH_CONTROL_WAL_OK)
      goto cleanup;
    result = validate_record(wal, record_header, frame, authenticator, next_index + 1u, previous,
                             NULL, NULL);
    if (result != MESH_CONTROL_WAL_OK)
      goto cleanup;
    next_index++;
    wal->tail_index = next_index;
    memcpy(wal->tail_previous_authenticator, previous, sizeof(wal->tail_previous_authenticator));
    memcpy(wal->tail_authenticator, authenticator, sizeof(wal->tail_authenticator));
    memcpy(previous, authenticator, sizeof(previous));
    wal->record_count++;
    offset += (size_t)record_size;
  }
  if (offset != size) {
    result = MESH_CONTROL_WAL_CORRUPT;
    goto cleanup;
  }
  wal->file_size = size;
  result = MESH_CONTROL_WAL_OK;

cleanup:
  if (turbo_fs_close(file) != 0 && result == MESH_CONTROL_WAL_OK)
    result = MESH_CONTROL_WAL_IO;
  return result;
}

mesh_control_wal_result_t mesh_control_wal_open_v1(mesh_control_wal_v1_t *wal,
                                                   const mesh_control_wal_config_v1_t *config) {
  turbo_fs_stat_t stat;
  int path_length;
  mesh_control_wal_result_t result = MESH_CONTROL_WAL_INVALID_ARG;

  if (!wal || wal->open || !config_valid(config))
    return result;
  memset(wal, 0, sizeof(*wal));
  wal->lock_file = TURBO_INVALID_FILE;
  wal->config = *config;
  wal->config.path = wal->path;
  memcpy(wal->path, config->path, strlen(config->path) + 1u);
  path_length = snprintf(wal->lock_path, sizeof(wal->lock_path), "%s.lock", wal->path);
  if (path_length < 0 || (size_t)path_length >= sizeof(wal->lock_path))
    goto failed;
  if (turbo_fs_lstat(wal->lock_path, &stat) == 0 && stat.is_symlink) {
    result = MESH_CONTROL_WAL_CORRUPT;
    goto failed;
  }
  wal->lock_file = turbo_fs_open(wal->lock_path, TURBO_FS_O_RDWR | TURBO_FS_O_CREAT, WAL_FILE_MODE);
  if (wal->lock_file == TURBO_INVALID_FILE) {
    result = MESH_CONTROL_WAL_IO;
    goto failed;
  }
  if (turbo_fs_lock(wal->lock_file, TURBO_FS_LOCK_EXCLUSIVE | TURBO_FS_LOCK_NONBLOCK, 0, 1u) != 0) {
    result = MESH_CONTROL_WAL_LOCKED;
    goto failed;
  }
  wal->open = 1u;
  if (turbo_fs_lstat(wal->path, &stat) == 0) {
    if (!stat.is_file || stat.is_symlink || stat.size > SIZE_MAX) {
      result = MESH_CONTROL_WAL_CORRUPT;
      goto failed;
    }
    result = scan_existing(wal, (size_t)stat.size);
  } else {
    result = create_empty_file(wal);
  }
  if (result != MESH_CONTROL_WAL_OK)
    goto failed;
  return MESH_CONTROL_WAL_OK;

failed:
  mesh_control_wal_close_v1(wal);
  return result;
}

static void encode_record_header(const mesh_control_wal_v1_t *wal, uint16_t record_type,
                                 uint64_t log_index, uint64_t recorded_at_ms, size_t payload_size,
                                 uint8_t output[WAL_RECORD_HEADER_SIZE]) {
  memset(output, 0, WAL_RECORD_HEADER_SIZE);
  memcpy(output, WAL_RECORD_MAGIC, sizeof(WAL_RECORD_MAGIC));
  write_u16(output + 4u, MESH_CONTROL_WAL_VERSION_V1);
  write_u16(output + 6u, record_type);
  write_u32(output + 8u, WAL_RECORD_HEADER_SIZE);
  write_u32(output + 12u, (uint32_t)payload_size);
  write_u64(output + 16u, WAL_RECORD_FIXED_SIZE + (uint64_t)payload_size);
  write_u64(output + 24u, log_index);
  write_u64(output + 32u, recorded_at_ms);
  memcpy(output + 40u, wal->tail_authenticator, MESH_CONTROL_DIGEST_SIZE);
}

static mesh_control_wal_result_t
validate_record_payload(const mesh_control_wal_v1_t *wal, uint16_t record_type,
                        uint64_t recorded_at_ms, const uint8_t *payload, size_t payload_size) {
  mesh_control_wal_operation_result_v1_t operation_result;
  if (record_type == WAL_RECORD_TYPE_SIGNED_INTENT)
    return validate_signed_frame(wal, recorded_at_ms, payload, payload_size);
  if (record_type == WAL_RECORD_TYPE_OPERATION_RESULT && recorded_at_ms != 0u &&
      decode_operation_result(payload, payload_size, &operation_result)) {
    return MESH_CONTROL_WAL_OK;
  }
  return MESH_CONTROL_WAL_CORRUPT;
}

static int record_matches_tail(const mesh_control_wal_v1_t *wal, uint16_t record_type,
                               uint64_t log_index, uint64_t recorded_at_ms, const uint8_t *payload,
                               size_t payload_size) {
  uint8_t header[WAL_RECORD_HEADER_SIZE];
  uint8_t actual[MESH_CONTROL_DIGEST_SIZE];

  if (log_index != wal->tail_index || wal->record_count == 0u)
    return 0;
  encode_record_header(wal, record_type, log_index, recorded_at_ms, payload_size, header);
  memcpy(header + 40u, wal->tail_previous_authenticator, MESH_CONTROL_DIGEST_SIZE);
  return validate_record_payload(wal, record_type, recorded_at_ms, payload, payload_size) ==
             MESH_CONTROL_WAL_OK &&
         calculate_record_authenticator(wal, header, payload, payload_size, actual) &&
         mesh_mgmt_crypto_equal_32(actual, wal->tail_authenticator);
}

static mesh_control_wal_result_t append_record(mesh_control_wal_v1_t *wal, uint16_t record_type,
                                               uint64_t expected_index, uint64_t recorded_at_ms,
                                               const uint8_t *payload, size_t payload_size,
                                               uint64_t *out_log_index) {
  uint8_t record_header[WAL_RECORD_HEADER_SIZE];
  uint8_t authenticator[MESH_CONTROL_DIGEST_SIZE];
  turbo_file_t file = TURBO_INVALID_FILE;
  size_t record_size;
  mesh_control_wal_result_t result;

  if (out_log_index)
    *out_log_index = 0u;
  if (!wal || !payload || !out_log_index || expected_index == 0u || payload_size == 0u ||
      payload_size > MESH_MGMT_FRAME_MAX ||
      (record_type != WAL_RECORD_TYPE_SIGNED_INTENT &&
       record_type != WAL_RECORD_TYPE_OPERATION_RESULT)) {
    return MESH_CONTROL_WAL_INVALID_ARG;
  }
  if (!wal->open || wal->faulted)
    return MESH_CONTROL_WAL_INVALID_STATE;
  if (expected_index == wal->tail_index &&
      record_matches_tail(wal, record_type, expected_index, recorded_at_ms, payload,
                          payload_size)) {
    *out_log_index = expected_index;
    return MESH_CONTROL_WAL_OK;
  }
  if (wal->tail_index == UINT64_MAX || expected_index != wal->tail_index + 1u)
    return MESH_CONTROL_WAL_CONFLICT;
  result = validate_record_payload(wal, record_type, recorded_at_ms, payload, payload_size);
  if (result != MESH_CONTROL_WAL_OK)
    return result;
  record_size = WAL_RECORD_FIXED_SIZE + payload_size;
  if (wal->record_count >= wal->config.record_capacity ||
      record_size > wal->config.byte_capacity - wal->file_size) {
    return MESH_CONTROL_WAL_RESOURCE_EXHAUSTED;
  }
  encode_record_header(wal, record_type, expected_index, recorded_at_ms, payload_size,
                       record_header);
  if (!calculate_record_authenticator(wal, record_header, payload, payload_size, authenticator)) {
    return MESH_CONTROL_WAL_AUTH_FAILED;
  }
  file = turbo_fs_open(wal->path, TURBO_FS_O_WRONLY | TURBO_FS_O_APPEND, WAL_FILE_MODE);
  if (file == TURBO_INVALID_FILE)
    return MESH_CONTROL_WAL_IO;
  result = write_all(file, record_header, sizeof(record_header));
  if (result == MESH_CONTROL_WAL_OK)
    result = write_all(file, payload, payload_size);
  if (result == MESH_CONTROL_WAL_OK)
    result = write_all(file, authenticator, sizeof(authenticator));
  if (result != MESH_CONTROL_WAL_OK || turbo_fs_fsync(file) != 0) {
    wal->faulted = 1u;
    result = MESH_CONTROL_WAL_COMMIT_UNKNOWN;
  }
  if (turbo_fs_close(file) != 0 && result == MESH_CONTROL_WAL_OK) {
    wal->faulted = 1u;
    result = MESH_CONTROL_WAL_COMMIT_UNKNOWN;
  }
  if (result != MESH_CONTROL_WAL_OK)
    return result;
  wal->tail_index = expected_index;
  memcpy(wal->tail_previous_authenticator, record_header + 40u,
         sizeof(wal->tail_previous_authenticator));
  memcpy(wal->tail_authenticator, authenticator, sizeof(wal->tail_authenticator));
  wal->record_count++;
  wal->file_size += record_size;
  *out_log_index = expected_index;
  return MESH_CONTROL_WAL_OK;
}

mesh_control_wal_result_t
mesh_control_wal_append_v1(mesh_control_wal_v1_t *wal, uint64_t expected_index,
                           uint64_t accepted_at_ms, const uint8_t *signed_frame,
                           size_t signed_frame_size, uint64_t *out_log_index) {
  return append_record(wal, WAL_RECORD_TYPE_SIGNED_INTENT, expected_index, accepted_at_ms,
                       signed_frame, signed_frame_size, out_log_index);
}

mesh_control_wal_result_t mesh_control_wal_append_operation_result_v1(
    mesh_control_wal_v1_t *wal, uint64_t expected_index, uint64_t recorded_at_ms,
    const mesh_control_wal_operation_result_v1_t *operation_result, uint64_t *out_log_index) {
  uint8_t payload[WAL_OPERATION_RESULT_SIZE];
  if (out_log_index)
    *out_log_index = 0u;
  if (!operation_result || !encode_operation_result(operation_result, payload))
    return MESH_CONTROL_WAL_INVALID_ARG;
  return append_record(wal, WAL_RECORD_TYPE_OPERATION_RESULT, expected_index, recorded_at_ms,
                       payload, sizeof(payload), out_log_index);
}

mesh_control_wal_result_t mesh_control_wal_replay_v1(const mesh_control_wal_v1_t *wal,
                                                     uint64_t after_index,
                                                     mesh_control_wal_replay_fn callback,
                                                     void *context, size_t *out_replayed) {
  uint8_t file_header[WAL_HEADER_SIZE];
  uint8_t record_header[WAL_RECORD_HEADER_SIZE];
  uint8_t frame[MESH_MGMT_FRAME_MAX];
  uint8_t authenticator[MESH_CONTROL_DIGEST_SIZE];
  uint8_t previous[MESH_CONTROL_DIGEST_SIZE];
  turbo_file_t file = TURBO_INVALID_FILE;
  uint64_t next_index;
  size_t replayed = 0u;
  size_t index;
  mesh_control_wal_result_t result;

  if (out_replayed)
    *out_replayed = 0u;
  if (!wal || !callback || !out_replayed) {
    return MESH_CONTROL_WAL_INVALID_ARG;
  }
  if (!wal->open || wal->faulted)
    return MESH_CONTROL_WAL_INVALID_STATE;
  if (after_index < wal->base_index || after_index > wal->tail_index)
    return MESH_CONTROL_WAL_CONFLICT;
  file = turbo_fs_open(wal->path, TURBO_FS_O_RDONLY, 0);
  if (file == TURBO_INVALID_FILE)
    return MESH_CONTROL_WAL_IO;
  result = read_exact(file, file_header, sizeof(file_header));
  if (result != MESH_CONTROL_WAL_OK)
    goto cleanup;
  memcpy(previous, wal->base_authenticator, sizeof(previous));
  next_index = wal->base_index;
  for (index = 0u; index < wal->record_count; ++index) {
    mesh_control_wal_record_view_v1_t view;
    mesh_control_wal_operation_result_v1_t operation_result;
    uint16_t record_type = 0u;
    uint32_t frame_size;
    result = read_exact(file, record_header, sizeof(record_header));
    if (result != MESH_CONTROL_WAL_OK)
      goto cleanup;
    frame_size = read_u32(record_header + 12u);
    if (frame_size == 0u || frame_size > MESH_MGMT_FRAME_MAX) {
      result = MESH_CONTROL_WAL_CORRUPT;
      goto cleanup;
    }
    result = read_exact(file, frame, frame_size);
    if (result != MESH_CONTROL_WAL_OK)
      goto cleanup;
    result = read_exact(file, authenticator, sizeof(authenticator));
    if (result != MESH_CONTROL_WAL_OK)
      goto cleanup;
    memset(&operation_result, 0, sizeof(operation_result));
    result = validate_record(wal, record_header, frame, authenticator, next_index + 1u, previous,
                             &record_type, &operation_result);
    if (result != MESH_CONTROL_WAL_OK)
      goto cleanup;
    next_index++;
    memcpy(previous, authenticator, sizeof(previous));
    if (next_index <= after_index)
      continue;
    memset(&view, 0, sizeof(view));
    view.log_index = next_index;
    view.accepted_at_ms = read_u64(record_header + 32u);
    view.record_type = record_type;
    if (record_type == WAL_RECORD_TYPE_SIGNED_INTENT) {
      view.signed_frame = frame;
      view.signed_frame_size = frame_size;
    } else {
      view.operation_result = operation_result;
    }
    if (callback(context, &view) != 0) {
      result = MESH_CONTROL_WAL_CALLBACK_FAILED;
      goto cleanup;
    }
    replayed++;
  }
  result = MESH_CONTROL_WAL_OK;

cleanup:
  if (turbo_fs_close(file) != 0 && result == MESH_CONTROL_WAL_OK)
    result = MESH_CONTROL_WAL_IO;
  if (result == MESH_CONTROL_WAL_OK)
    *out_replayed = replayed;
  return result;
}

mesh_control_wal_result_t mesh_control_wal_compact_v1(mesh_control_wal_v1_t *wal,
                                                      uint64_t checkpoint_index) {
  mesh_control_wal_v1_t next;
  uint8_t header[WAL_HEADER_SIZE];
  char temp_path[TURBO_FS_MAX_PATH + 9u];
  turbo_file_t file = TURBO_INVALID_FILE;
  mesh_control_wal_result_t result = MESH_CONTROL_WAL_IO;
  int path_length;

  if (!wal)
    return MESH_CONTROL_WAL_INVALID_ARG;
  if (!wal->open || wal->faulted)
    return MESH_CONTROL_WAL_INVALID_STATE;
  if (checkpoint_index != wal->tail_index)
    return MESH_CONTROL_WAL_CONFLICT;
  next = *wal;
  next.base_index = checkpoint_index;
  memcpy(next.base_authenticator, wal->tail_authenticator, sizeof(next.base_authenticator));
  if (!encode_header(&next, header))
    return MESH_CONTROL_WAL_AUTH_FAILED;
  path_length = snprintf(temp_path, sizeof(temp_path), "%s.compact", wal->path);
  if (path_length < 0 || (size_t)path_length >= sizeof(temp_path))
    return MESH_CONTROL_WAL_INVALID_ARG;
  file = turbo_fs_open(temp_path, TURBO_FS_O_WRONLY | TURBO_FS_O_CREAT | TURBO_FS_O_TRUNC,
                       WAL_FILE_MODE);
  if (file == TURBO_INVALID_FILE)
    return MESH_CONTROL_WAL_IO;
  result = write_all(file, header, sizeof(header));
  if (result == MESH_CONTROL_WAL_OK && turbo_fs_fsync(file) != 0)
    result = MESH_CONTROL_WAL_IO;
  if (turbo_fs_close(file) != 0 && result == MESH_CONTROL_WAL_OK)
    result = MESH_CONTROL_WAL_IO;
  file = TURBO_INVALID_FILE;
  if (result == MESH_CONTROL_WAL_OK && turbo_fs_rename(temp_path, wal->path) != 0) {
    result = MESH_CONTROL_WAL_IO;
  }
  if (result != MESH_CONTROL_WAL_OK) {
    if (file != TURBO_INVALID_FILE)
      (void)turbo_fs_close(file);
    if (turbo_fs_access(temp_path, TURBO_FS_ACCESS_EXISTS) == 0)
      (void)turbo_fs_unlink(temp_path);
    return result;
  }
  wal->base_index = checkpoint_index;
  memcpy(wal->base_authenticator, next.base_authenticator, sizeof(wal->base_authenticator));
  memcpy(wal->tail_previous_authenticator, wal->base_authenticator,
         sizeof(wal->tail_previous_authenticator));
  memcpy(wal->tail_authenticator, wal->base_authenticator, sizeof(wal->tail_authenticator));
  wal->record_count = 0u;
  wal->file_size = WAL_HEADER_SIZE;
  return MESH_CONTROL_WAL_OK;
}

mesh_control_wal_result_t mesh_control_wal_get_stats_v1(const mesh_control_wal_v1_t *wal,
                                                        mesh_control_wal_stats_v1_t *out_stats) {
  if (!wal || !out_stats)
    return MESH_CONTROL_WAL_INVALID_ARG;
  memset(out_stats, 0, sizeof(*out_stats));
  out_stats->base_index = wal->base_index;
  out_stats->tail_index = wal->tail_index;
  out_stats->record_count = wal->record_count;
  out_stats->record_capacity = wal->config.record_capacity;
  out_stats->file_size = wal->file_size;
  out_stats->byte_capacity = wal->config.byte_capacity;
  out_stats->open = wal->open;
  out_stats->faulted = wal->faulted;
  return MESH_CONTROL_WAL_OK;
}

void mesh_control_wal_close_v1(mesh_control_wal_v1_t *wal) {
  if (!wal)
    return;
  if (wal->lock_file != TURBO_INVALID_FILE) {
    if (wal->open)
      (void)turbo_fs_unlock(wal->lock_file, 0, 1u);
    (void)turbo_fs_close(wal->lock_file);
  }
  mesh_mgmt_crypto_wipe(wal, sizeof(*wal));
  wal->lock_file = TURBO_INVALID_FILE;
}
