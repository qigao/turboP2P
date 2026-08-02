#include "mesh_mgmt_execution_result.h"

#include "mesh_mgmt_crypto.h"

#include <string.h>

static const uint8_t request_domain[32] = {
    'm', 'e', 's', 'h', '-', 'e', 'x', 'e', 'c', 'u', 't', 'i', 'o', 'n',
    '-', 'r', 'e', 'q', 'u', 'e', 's', 't', '-', 'v', '1', 0,   0,   0,
    0,   0,   0,   0};

static const uint8_t result_domain[32] = {
    'm', 'e', 's', 'h', '-', 'e', 'x', 'e', 'c', 'u', 't', 'i', 'o', 'n',
    '-', 'r', 'e', 's', 'u', 'l', 't', '-', 'v', '1', 0,   0,   0,   0,
    0,   0,   0,   0};

static int bytes_are_zero(const uint8_t *bytes, size_t size) {
  size_t index;

  for (index = 0u; index < size; ++index) {
    if (bytes[index] != 0u)
      return 0;
  }
  return 1;
}

static void write_u16(uint8_t *output, uint16_t value) {
  output[0] = (uint8_t)(value >> 8u);
  output[1] = (uint8_t)value;
}

static void write_u32(uint8_t *output, uint32_t value) {
  output[0] = (uint8_t)(value >> 24u);
  output[1] = (uint8_t)(value >> 16u);
  output[2] = (uint8_t)(value >> 8u);
  output[3] = (uint8_t)value;
}

static void write_u64(uint8_t *output, uint64_t value) {
  write_u32(output, (uint32_t)(value >> 32u));
  write_u32(output + 4u, (uint32_t)value);
}

static uint16_t read_u16(const uint8_t *input) {
  return (uint16_t)(((uint16_t)input[0] << 8u) | (uint16_t)input[1]);
}

static uint32_t read_u32(const uint8_t *input) {
  return ((uint32_t)input[0] << 24u) | ((uint32_t)input[1] << 16u) |
         ((uint32_t)input[2] << 8u) | (uint32_t)input[3];
}

static uint64_t read_u64(const uint8_t *input) {
  return ((uint64_t)read_u32(input) << 32u) |
         (uint64_t)read_u32(input + 4u);
}

static int32_t read_i32(const uint8_t *input) {
  uint32_t encoded = read_u32(input);
  int64_t signed_value = encoded <= INT32_MAX
                             ? (int64_t)encoded
                             : (int64_t)encoded - 4294967296LL;
  return (int32_t)signed_value;
}

static void append_bytes(uint8_t *output, size_t *offset,
                         const uint8_t *bytes, size_t size) {
  memcpy(output + *offset, bytes, size);
  *offset += size;
}

static void append_u16(uint8_t *output, size_t *offset, uint16_t value) {
  write_u16(output + *offset, value);
  *offset += sizeof(uint16_t);
}

static void append_u32(uint8_t *output, size_t *offset, uint32_t value) {
  write_u32(output + *offset, value);
  *offset += sizeof(uint32_t);
}

static void append_u64(uint8_t *output, size_t *offset, uint64_t value) {
  write_u64(output + *offset, value);
  *offset += sizeof(uint64_t);
}

mesh_mgmt_execution_result_codec_result_t
mesh_mgmt_execution_request_encode_canonical_v1(
    const mesh_mgmt_execution_request_v1_t *request, uint8_t *output,
    size_t output_capacity, size_t *out_size) {
  size_t offset = 0u;
  size_t required_size;

  if (!request || !out_size)
    return MESH_MGMT_EXECUTION_RESULT_INVALID_ARG;
  if (request->version != MESH_MGMT_EXECUTION_SCHEMA_V1 ||
      request->inline_input_size > MESH_MGMT_EXECUTION_INLINE_INPUT_MAX)
    return MESH_MGMT_EXECUTION_RESULT_INVALID_SCHEMA;
  required_size = MESH_MGMT_EXECUTION_REQUEST_CANONICAL_BASE_SIZE_V1 +
                  request->inline_input_size;
  *out_size = required_size;
  if (!output || output_capacity < required_size)
    return MESH_MGMT_EXECUTION_RESULT_RESOURCE_EXHAUSTED;

  append_bytes(output, &offset, request_domain, sizeof(request_domain));
  append_u16(output, &offset, request->version);
  append_bytes(output, &offset, request->command_id,
               sizeof(request->command_id));
  append_bytes(output, &offset, request->grant_id,
               sizeof(request->grant_id));
  append_bytes(output, &offset, request->target_node_id,
               sizeof(request->target_node_id));
  append_bytes(output, &offset, request->deployment_id,
               sizeof(request->deployment_id));
  append_u64(output, &offset, request->deployment_generation);
  append_bytes(output, &offset, request->package_digest,
               sizeof(request->package_digest));
  append_u32(output, &offset, (uint32_t)request->input_kind);
  append_bytes(output, &offset, request->input_digest,
               sizeof(request->input_digest));
  append_u64(output, &offset, request->input_length);
  append_u32(output, &offset, (uint32_t)request->inline_input_size);
  append_bytes(output, &offset, request->inline_input,
               request->inline_input_size);
  append_u32(output, &offset, (uint32_t)request->output_mode);
  append_u64(output, &offset, request->deadline_ms);
  append_bytes(output, &offset, request->request_nonce,
               sizeof(request->request_nonce));
  append_bytes(output, &offset, request->correlation_id,
               sizeof(request->correlation_id));
  if (offset != required_size) {
    memset(output, 0, output_capacity);
    return MESH_MGMT_EXECUTION_RESULT_INVALID_SCHEMA;
  }
  return MESH_MGMT_EXECUTION_RESULT_OK;
}

mesh_mgmt_execution_result_codec_result_t
mesh_mgmt_execution_request_decode_canonical_v1(
    const uint8_t *canonical, size_t canonical_size,
    mesh_mgmt_execution_request_v1_t *out_request) {
  size_t offset = 0u;
  uint32_t inline_size;

  if (!canonical || !out_request)
    return MESH_MGMT_EXECUTION_RESULT_INVALID_ARG;
  memset(out_request, 0, sizeof(*out_request));
  if (canonical_size < MESH_MGMT_EXECUTION_REQUEST_CANONICAL_BASE_SIZE_V1 ||
      canonical_size > MESH_MGMT_EXECUTION_REQUEST_CANONICAL_MAX_SIZE_V1 ||
      memcmp(canonical, request_domain, sizeof(request_domain)) != 0)
    return MESH_MGMT_EXECUTION_RESULT_INVALID_SCHEMA;
  offset += sizeof(request_domain);
  out_request->version = read_u16(canonical + offset);
  offset += sizeof(uint16_t);
#define READ_REQUEST_BYTES(field)                                            \
  do {                                                                       \
    memcpy((field), canonical + offset, sizeof(field));                       \
    offset += sizeof(field);                                                  \
  } while (0)
  READ_REQUEST_BYTES(out_request->command_id);
  READ_REQUEST_BYTES(out_request->grant_id);
  READ_REQUEST_BYTES(out_request->target_node_id);
  READ_REQUEST_BYTES(out_request->deployment_id);
  out_request->deployment_generation = read_u64(canonical + offset);
  offset += sizeof(uint64_t);
  READ_REQUEST_BYTES(out_request->package_digest);
  out_request->input_kind =
      (mesh_mgmt_execution_input_kind_t)read_u32(canonical + offset);
  offset += sizeof(uint32_t);
  READ_REQUEST_BYTES(out_request->input_digest);
  out_request->input_length = read_u64(canonical + offset);
  offset += sizeof(uint64_t);
  inline_size = read_u32(canonical + offset);
  offset += sizeof(uint32_t);
  if (inline_size > MESH_MGMT_EXECUTION_INLINE_INPUT_MAX ||
      canonical_size !=
          MESH_MGMT_EXECUTION_REQUEST_CANONICAL_BASE_SIZE_V1 + inline_size) {
    memset(out_request, 0, sizeof(*out_request));
    return MESH_MGMT_EXECUTION_RESULT_INVALID_SCHEMA;
  }
  out_request->inline_input_size = (size_t)inline_size;
  memcpy(out_request->inline_input, canonical + offset, inline_size);
  offset += inline_size;
  out_request->output_mode =
      (mesh_mgmt_execution_output_mode_t)read_u32(canonical + offset);
  offset += sizeof(uint32_t);
  out_request->deadline_ms = read_u64(canonical + offset);
  offset += sizeof(uint64_t);
  READ_REQUEST_BYTES(out_request->request_nonce);
  READ_REQUEST_BYTES(out_request->correlation_id);
#undef READ_REQUEST_BYTES
  if (offset != canonical_size ||
      mesh_mgmt_execution_request_validate_v1(
          out_request,
          out_request->deadline_ms == 0u
              ? 0u
              : out_request->deadline_ms - 1u) != MESH_MGMT_EXECUTION_OK) {
    memset(out_request, 0, sizeof(*out_request));
    return MESH_MGMT_EXECUTION_RESULT_INVALID_SCHEMA;
  }
  return MESH_MGMT_EXECUTION_RESULT_OK;
}

mesh_mgmt_execution_result_codec_result_t
mesh_mgmt_execution_request_digest_v1(
    const mesh_mgmt_execution_request_v1_t *request,
    uint8_t out_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE]) {
  uint8_t canonical[MESH_MGMT_EXECUTION_REQUEST_CANONICAL_MAX_SIZE_V1];
  size_t canonical_size = 0u;
  mesh_mgmt_execution_result_codec_result_t encode_result;

  if (!request || !out_digest)
    return MESH_MGMT_EXECUTION_RESULT_INVALID_ARG;
  encode_result = mesh_mgmt_execution_request_encode_canonical_v1(
      request, canonical, sizeof(canonical), &canonical_size);
  if (encode_result != MESH_MGMT_EXECUTION_RESULT_OK)
    return encode_result;
  if (mesh_mgmt_blake2b_256(canonical, canonical_size, out_digest) !=
      MESH_MGMT_CRYPTO_OK) {
    mesh_mgmt_crypto_wipe(canonical, sizeof(canonical));
    return MESH_MGMT_EXECUTION_RESULT_CRYPTO_FAILED;
  }
  mesh_mgmt_crypto_wipe(canonical, sizeof(canonical));
  return MESH_MGMT_EXECUTION_RESULT_OK;
}

mesh_mgmt_execution_result_codec_result_t
mesh_mgmt_execution_result_validate_v1(
    const mesh_mgmt_execution_result_v1_t *result) {
  if (!result)
    return MESH_MGMT_EXECUTION_RESULT_INVALID_ARG;
  if (result->version != MESH_MGMT_EXECUTION_RESULT_VERSION_V1 ||
      bytes_are_zero(result->command_id, sizeof(result->command_id)) ||
      bytes_are_zero(result->request_digest,
                     sizeof(result->request_digest)) ||
      bytes_are_zero(result->target_node_id,
                     sizeof(result->target_node_id)) ||
      bytes_are_zero(result->deployment_id, sizeof(result->deployment_id)) ||
      result->deployment_generation == 0u ||
      bytes_are_zero(result->package_digest,
                     sizeof(result->package_digest)) ||
      result->policy_epoch == 0u ||
      bytes_are_zero(result->grant_id, sizeof(result->grant_id)) ||
      !mesh_mgmt_execution_state_is_terminal_v1(result->state) ||
      result->runtime_stage < 0 || result->runtime_stage > 8 ||
      bytes_are_zero(result->stdout_digest,
                     sizeof(result->stdout_digest)) ||
      bytes_are_zero(result->stderr_digest,
                     sizeof(result->stderr_digest)) ||
      result->has_output_artifact > 1u ||
      (result->has_output_artifact &&
       bytes_are_zero(result->output_artifact_digest,
                      sizeof(result->output_artifact_digest))) ||
      (!result->has_output_artifact &&
       !bytes_are_zero(result->output_artifact_digest,
                       sizeof(result->output_artifact_digest))) ||
      result->started_at_ms == 0u ||
      result->finished_at_ms < result->started_at_ms ||
      result->worker_generation == 0u ||
      bytes_are_zero(result->correlation_id,
                     sizeof(result->correlation_id)) ||
      bytes_are_zero(result->signer_public_key,
                     sizeof(result->signer_public_key)))
    return MESH_MGMT_EXECUTION_RESULT_INVALID_SCHEMA;
  return MESH_MGMT_EXECUTION_RESULT_OK;
}

mesh_mgmt_execution_result_codec_result_t
mesh_mgmt_execution_result_encode_canonical_v1(
    const mesh_mgmt_execution_result_v1_t *result, uint8_t *output,
    size_t output_capacity, size_t *out_size) {
  size_t offset = 0u;
  mesh_mgmt_execution_result_codec_result_t validation;

  if (!result || !out_size)
    return MESH_MGMT_EXECUTION_RESULT_INVALID_ARG;
  *out_size = MESH_MGMT_EXECUTION_RESULT_CANONICAL_SIZE_V1;
  validation = mesh_mgmt_execution_result_validate_v1(result);
  if (validation != MESH_MGMT_EXECUTION_RESULT_OK)
    return validation;
  if (!output ||
      output_capacity < MESH_MGMT_EXECUTION_RESULT_CANONICAL_SIZE_V1)
    return MESH_MGMT_EXECUTION_RESULT_RESOURCE_EXHAUSTED;

  append_bytes(output, &offset, result_domain, sizeof(result_domain));
  append_u16(output, &offset, result->version);
  append_bytes(output, &offset, result->command_id,
               sizeof(result->command_id));
  append_bytes(output, &offset, result->request_digest,
               sizeof(result->request_digest));
  append_bytes(output, &offset, result->target_node_id,
               sizeof(result->target_node_id));
  append_bytes(output, &offset, result->deployment_id,
               sizeof(result->deployment_id));
  append_u64(output, &offset, result->deployment_generation);
  append_bytes(output, &offset, result->package_digest,
               sizeof(result->package_digest));
  append_u64(output, &offset, result->policy_epoch);
  append_bytes(output, &offset, result->grant_id, sizeof(result->grant_id));
  append_u32(output, &offset, (uint32_t)result->state);
  append_u32(output, &offset, (uint32_t)result->runtime_code);
  append_u32(output, &offset, (uint32_t)result->runtime_stage);
  append_u32(output, &offset, (uint32_t)result->guest_exit_code);
  append_u64(output, &offset, result->usage.invocations);
  append_u64(output, &offset, result->usage.host_calls);
  append_u64(output, &offset, result->usage.copied_guest_bytes);
  append_u64(output, &offset, result->usage.modules_loaded);
  append_u64(output, &offset, result->usage.modules_rejected);
  append_u32(output, &offset, result->usage.open_handles);
  append_u64(output, &offset, result->stdout_bytes);
  append_u64(output, &offset, result->stderr_bytes);
  append_bytes(output, &offset, result->stdout_digest,
               sizeof(result->stdout_digest));
  append_bytes(output, &offset, result->stderr_digest,
               sizeof(result->stderr_digest));
  output[offset++] = result->has_output_artifact;
  append_bytes(output, &offset, result->output_artifact_digest,
               sizeof(result->output_artifact_digest));
  append_u64(output, &offset, result->started_at_ms);
  append_u64(output, &offset, result->finished_at_ms);
  append_u64(output, &offset, result->worker_generation);
  append_bytes(output, &offset, result->correlation_id,
               sizeof(result->correlation_id));
  append_bytes(output, &offset, result->signer_public_key,
               sizeof(result->signer_public_key));
  if (offset != MESH_MGMT_EXECUTION_RESULT_CANONICAL_SIZE_V1) {
    memset(output, 0, output_capacity);
    return MESH_MGMT_EXECUTION_RESULT_INVALID_SCHEMA;
  }
  return MESH_MGMT_EXECUTION_RESULT_OK;
}

mesh_mgmt_execution_result_codec_result_t
mesh_mgmt_execution_result_decode_canonical_v1(
    const uint8_t *canonical, size_t canonical_size,
    mesh_mgmt_execution_result_v1_t *out_result) {
  size_t offset = 0u;

  if (!canonical || !out_result)
    return MESH_MGMT_EXECUTION_RESULT_INVALID_ARG;
  memset(out_result, 0, sizeof(*out_result));
  if (canonical_size != MESH_MGMT_EXECUTION_RESULT_CANONICAL_SIZE_V1 ||
      memcmp(canonical, result_domain, sizeof(result_domain)) != 0)
    return MESH_MGMT_EXECUTION_RESULT_INVALID_SCHEMA;
  offset += sizeof(result_domain);
  out_result->version = read_u16(canonical + offset);
  offset += sizeof(uint16_t);
#define READ_BYTES(field)                                                    \
  do {                                                                       \
    memcpy((field), canonical + offset, sizeof(field));                       \
    offset += sizeof(field);                                                  \
  } while (0)
  READ_BYTES(out_result->command_id);
  READ_BYTES(out_result->request_digest);
  READ_BYTES(out_result->target_node_id);
  READ_BYTES(out_result->deployment_id);
  out_result->deployment_generation = read_u64(canonical + offset);
  offset += sizeof(uint64_t);
  READ_BYTES(out_result->package_digest);
  out_result->policy_epoch = read_u64(canonical + offset);
  offset += sizeof(uint64_t);
  READ_BYTES(out_result->grant_id);
  out_result->state =
      (mesh_mgmt_execution_state_t)read_u32(canonical + offset);
  offset += sizeof(uint32_t);
  out_result->runtime_code = read_i32(canonical + offset);
  offset += sizeof(uint32_t);
  out_result->runtime_stage = read_i32(canonical + offset);
  offset += sizeof(uint32_t);
  out_result->guest_exit_code = read_i32(canonical + offset);
  offset += sizeof(uint32_t);
  out_result->usage.invocations = read_u64(canonical + offset);
  offset += sizeof(uint64_t);
  out_result->usage.host_calls = read_u64(canonical + offset);
  offset += sizeof(uint64_t);
  out_result->usage.copied_guest_bytes = read_u64(canonical + offset);
  offset += sizeof(uint64_t);
  out_result->usage.modules_loaded = read_u64(canonical + offset);
  offset += sizeof(uint64_t);
  out_result->usage.modules_rejected = read_u64(canonical + offset);
  offset += sizeof(uint64_t);
  out_result->usage.open_handles = read_u32(canonical + offset);
  offset += sizeof(uint32_t);
  out_result->stdout_bytes = read_u64(canonical + offset);
  offset += sizeof(uint64_t);
  out_result->stderr_bytes = read_u64(canonical + offset);
  offset += sizeof(uint64_t);
  READ_BYTES(out_result->stdout_digest);
  READ_BYTES(out_result->stderr_digest);
  out_result->has_output_artifact = canonical[offset++];
  READ_BYTES(out_result->output_artifact_digest);
  out_result->started_at_ms = read_u64(canonical + offset);
  offset += sizeof(uint64_t);
  out_result->finished_at_ms = read_u64(canonical + offset);
  offset += sizeof(uint64_t);
  out_result->worker_generation = read_u64(canonical + offset);
  offset += sizeof(uint64_t);
  READ_BYTES(out_result->correlation_id);
  READ_BYTES(out_result->signer_public_key);
#undef READ_BYTES
  if (offset != canonical_size ||
      mesh_mgmt_execution_result_validate_v1(out_result) !=
          MESH_MGMT_EXECUTION_RESULT_OK) {
    memset(out_result, 0, sizeof(*out_result));
    return MESH_MGMT_EXECUTION_RESULT_INVALID_SCHEMA;
  }
  return MESH_MGMT_EXECUTION_RESULT_OK;
}

mesh_mgmt_execution_result_codec_result_t mesh_mgmt_execution_result_sign_v1(
    mesh_mgmt_execution_result_v1_t *result,
    const uint8_t private_key[MESH_MGMT_EXECUTION_DIGEST_SIZE]) {
  uint8_t canonical[MESH_MGMT_EXECUTION_RESULT_CANONICAL_SIZE_V1];
  size_t canonical_size = 0u;
  mesh_mgmt_execution_result_codec_result_t encode_result;

  if (!result || !private_key)
    return MESH_MGMT_EXECUTION_RESULT_INVALID_ARG;
  memset(result->signature, 0, sizeof(result->signature));
  if (mesh_mgmt_ed25519_public_from_private(
          private_key, result->signer_public_key) != MESH_MGMT_CRYPTO_OK)
    return MESH_MGMT_EXECUTION_RESULT_CRYPTO_FAILED;
  encode_result = mesh_mgmt_execution_result_encode_canonical_v1(
      result, canonical, sizeof(canonical), &canonical_size);
  if (encode_result != MESH_MGMT_EXECUTION_RESULT_OK)
    return encode_result;
  if (mesh_mgmt_ed25519_sign(private_key, canonical, canonical_size,
                             result->signature) != MESH_MGMT_CRYPTO_OK) {
    mesh_mgmt_crypto_wipe(canonical, sizeof(canonical));
    return MESH_MGMT_EXECUTION_RESULT_CRYPTO_FAILED;
  }
  mesh_mgmt_crypto_wipe(canonical, sizeof(canonical));
  return MESH_MGMT_EXECUTION_RESULT_OK;
}

mesh_mgmt_execution_result_codec_result_t
mesh_mgmt_execution_result_verify_v1(
    const mesh_mgmt_execution_result_v1_t *result,
    const uint8_t expected_signer_public_key[MESH_MGMT_EXECUTION_DIGEST_SIZE]) {
  uint8_t canonical[MESH_MGMT_EXECUTION_RESULT_CANONICAL_SIZE_V1];
  size_t canonical_size = 0u;
  mesh_mgmt_execution_result_codec_result_t encode_result;

  if (!result || !expected_signer_public_key)
    return MESH_MGMT_EXECUTION_RESULT_INVALID_ARG;
  if (!mesh_mgmt_crypto_equal_32(result->signer_public_key,
                                 expected_signer_public_key) ||
      bytes_are_zero(result->signature, sizeof(result->signature)))
    return MESH_MGMT_EXECUTION_RESULT_AUTH_FAILED;
  encode_result = mesh_mgmt_execution_result_encode_canonical_v1(
      result, canonical, sizeof(canonical), &canonical_size);
  if (encode_result != MESH_MGMT_EXECUTION_RESULT_OK)
    return encode_result;
  if (mesh_mgmt_ed25519_verify(result->signer_public_key, canonical,
                               canonical_size, result->signature) !=
      MESH_MGMT_CRYPTO_OK) {
    mesh_mgmt_crypto_wipe(canonical, sizeof(canonical));
    return MESH_MGMT_EXECUTION_RESULT_AUTH_FAILED;
  }
  mesh_mgmt_crypto_wipe(canonical, sizeof(canonical));
  return MESH_MGMT_EXECUTION_RESULT_OK;
}
