#include "mesh_mgmt_execution_wire.h"

#include "mesh_mgmt_crypto.h"
#include "mesh_mgmt_wire.h"

#include <string.h>

#define EXECUTION_COMMAND_VERSION_V1 1u
#define EXECUTION_COMMAND_REQUEST_V1 1u
#define EXECUTION_COMMAND_RESULT_V1 2u
#define EXECUTION_COMMAND_STATUS_V1 3u
#define EXECUTION_COMMAND_FIELD_DOMAIN 1u
#define EXECUTION_COMMAND_FIELD_VERSION 2u
#define EXECUTION_COMMAND_FIELD_KIND 3u
#define EXECUTION_COMMAND_FIELD_BODY 4u
#define EXECUTION_COMMAND_FIELD_SIGNATURE 5u
#define EXECUTION_COMMAND_FIELD_REQUEST 6u

static const uint8_t grant_domain[32] = {
    'm', 'e', 's', 'h', '-', 'e', 'x', 'e', 'c', 'u', 't', 'i', 'o', 'n',
    '-', 'g', 'r', 'a', 'n', 't', '-', 'v', '1', 0,   0,   0,   0,   0,
    0,   0,   0,   0};
static const uint8_t command_domain[16] = {
    'm', 'e', 's', 'h', '-', 'e', 'x', 'e',
    'c', '-', 'c', 'm', 'd', '-', 'v', '1'};
static const uint8_t status_domain[16] = {
    'm', 'e', 's', 'h', '-', 'e', 'x', 'e',
    'c', '-', 's', 't', '-', 'v', '1', 0};

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
  return (uint16_t)(((uint16_t)input[0] << 8u) | input[1]);
}

static uint32_t read_u32(const uint8_t *input) {
  return ((uint32_t)input[0] << 24u) | ((uint32_t)input[1] << 16u) |
         ((uint32_t)input[2] << 8u) | input[3];
}

static uint64_t read_u64(const uint8_t *input) {
  return ((uint64_t)read_u32(input) << 32u) | read_u32(input + 4u);
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

static int grant_structure_is_valid(
    const mesh_mgmt_execution_grant_v1_t *grant) {
  mesh_mgmt_execution_grant_v1_t validation_copy;
  mesh_mgmt_execution_result_t result;

  if (!grant)
    return 0;
  validation_copy = *grant;
  if (bytes_are_zero(validation_copy.signature,
                     sizeof(validation_copy.signature))) {
    validation_copy.signature[0] = 1u;
  }
  result = mesh_mgmt_execution_grant_validate_v1(
      &validation_copy, validation_copy.not_before_ms);
  memset(&validation_copy, 0, sizeof(validation_copy));
  return result == MESH_MGMT_EXECUTION_OK;
}

static mesh_mgmt_execution_wire_result_t map_result_codec(
    mesh_mgmt_execution_result_codec_result_t result) {
  switch (result) {
    case MESH_MGMT_EXECUTION_RESULT_OK:
      return MESH_MGMT_EXECUTION_WIRE_OK;
    case MESH_MGMT_EXECUTION_RESULT_INVALID_ARG:
      return MESH_MGMT_EXECUTION_WIRE_INVALID_ARG;
    case MESH_MGMT_EXECUTION_RESULT_RESOURCE_EXHAUSTED:
      return MESH_MGMT_EXECUTION_WIRE_RESOURCE_EXHAUSTED;
    case MESH_MGMT_EXECUTION_RESULT_CRYPTO_FAILED:
      return MESH_MGMT_EXECUTION_WIRE_CRYPTO_FAILED;
    case MESH_MGMT_EXECUTION_RESULT_AUTH_FAILED:
      return MESH_MGMT_EXECUTION_WIRE_AUTH_FAILED;
    case MESH_MGMT_EXECUTION_RESULT_INVALID_SCHEMA:
    default:
      return MESH_MGMT_EXECUTION_WIRE_INVALID_SCHEMA;
  }
}

mesh_mgmt_execution_wire_result_t
mesh_mgmt_execution_grant_encode_canonical_v1(
    const mesh_mgmt_execution_grant_v1_t *grant, uint8_t *output,
    size_t output_capacity, size_t *out_size) {
  size_t required_size;
  size_t offset = 0u;
  size_t index;

  if (!grant || !out_size)
    return MESH_MGMT_EXECUTION_WIRE_INVALID_ARG;
  if (!grant_structure_is_valid(grant))
    return MESH_MGMT_EXECUTION_WIRE_INVALID_SCHEMA;
  required_size = MESH_MGMT_EXECUTION_GRANT_CANONICAL_BASE_SIZE_V1 +
                  (grant->mount_count + grant->service_count +
                   grant->provider_count) *
                      MESH_MGMT_EXECUTION_ID_SIZE;
  *out_size = required_size;
  if (!output || output_capacity < required_size)
    return MESH_MGMT_EXECUTION_WIRE_RESOURCE_EXHAUSTED;

  append_bytes(output, &offset, grant_domain, sizeof(grant_domain));
  append_u16(output, &offset, grant->version);
  append_bytes(output, &offset, grant->grant_id, sizeof(grant->grant_id));
  append_bytes(output, &offset, grant->mesh_id, sizeof(grant->mesh_id));
  append_u64(output, &offset, grant->policy_epoch);
  append_bytes(output, &offset, grant->subject_principal,
               sizeof(grant->subject_principal));
  append_bytes(output, &offset, grant->target_node_id,
               sizeof(grant->target_node_id));
  append_bytes(output, &offset, grant->deployment_id,
               sizeof(grant->deployment_id));
  append_u64(output, &offset, grant->deployment_generation);
  append_bytes(output, &offset, grant->package_digest,
               sizeof(grant->package_digest));
  append_u32(output, &offset, (uint32_t)grant->operation);
  append_u32(output, &offset, grant->capabilities);
#define APPEND_REFS(ids, count)                                              \
  do {                                                                       \
    append_u32(output, &offset, (uint32_t)(count));                           \
    for (index = 0u; index < (count); ++index)                               \
      append_bytes(output, &offset, (ids)[index],                            \
                   MESH_MGMT_EXECUTION_ID_SIZE);                             \
  } while (0)
  APPEND_REFS(grant->mount_ids, grant->mount_count);
  APPEND_REFS(grant->service_ids, grant->service_count);
  APPEND_REFS(grant->provider_ids, grant->provider_count);
#undef APPEND_REFS
  append_u32(output, &offset, grant->max_limits.module_bytes);
  append_u32(output, &offset, grant->max_limits.stack_bytes);
  append_u32(output, &offset, grant->max_limits.linear_memory_bytes);
  append_u64(output, &offset, grant->max_limits.timeout_ms);
  append_u64(output, &offset, grant->max_limits.control_flow_steps);
  append_u32(output, &offset, grant->max_limits.host_calls);
  append_u64(output, &offset, grant->max_limits.copied_guest_bytes);
  append_u64(output, &offset, grant->max_limits.input_bytes);
  append_u64(output, &offset, grant->max_limits.stdout_bytes);
  append_u64(output, &offset, grant->max_limits.stderr_bytes);
  append_u64(output, &offset, grant->not_before_ms);
  append_u64(output, &offset, grant->expires_at_ms);
  append_bytes(output, &offset, grant->issuer_key, sizeof(grant->issuer_key));
  if (offset != required_size) {
    memset(output, 0, output_capacity);
    return MESH_MGMT_EXECUTION_WIRE_INVALID_SCHEMA;
  }
  return MESH_MGMT_EXECUTION_WIRE_OK;
}

static int decode_refs(const uint8_t *canonical, size_t canonical_size,
                       size_t *offset,
                       uint8_t refs[MESH_MGMT_EXECUTION_MAX_REFS]
                                   [MESH_MGMT_EXECUTION_ID_SIZE],
                       size_t *out_count) {
  uint32_t count;
  size_t bytes;

  if (*offset > canonical_size ||
      canonical_size - *offset < sizeof(uint32_t))
    return 0;
  count = read_u32(canonical + *offset);
  *offset += sizeof(uint32_t);
  if (count > MESH_MGMT_EXECUTION_MAX_REFS)
    return 0;
  bytes = (size_t)count * MESH_MGMT_EXECUTION_ID_SIZE;
  if (canonical_size - *offset < bytes)
    return 0;
  memcpy(refs, canonical + *offset, bytes);
  *offset += bytes;
  *out_count = count;
  return 1;
}

mesh_mgmt_execution_wire_result_t
mesh_mgmt_execution_grant_decode_canonical_v1(
    const uint8_t *canonical, size_t canonical_size,
    mesh_mgmt_execution_grant_v1_t *out_grant) {
  size_t offset = 0u;

  if (!canonical || !out_grant)
    return MESH_MGMT_EXECUTION_WIRE_INVALID_ARG;
  memset(out_grant, 0, sizeof(*out_grant));
  if (canonical_size < MESH_MGMT_EXECUTION_GRANT_CANONICAL_BASE_SIZE_V1 ||
      canonical_size > MESH_MGMT_EXECUTION_GRANT_CANONICAL_MAX_SIZE_V1 ||
      memcmp(canonical, grant_domain, sizeof(grant_domain)) != 0)
    return MESH_MGMT_EXECUTION_WIRE_INVALID_SCHEMA;
  offset += sizeof(grant_domain);
  out_grant->version = read_u16(canonical + offset);
  offset += sizeof(uint16_t);
#define READ_GRANT_BYTES(field)                                              \
  do {                                                                       \
    memcpy((field), canonical + offset, sizeof(field));                       \
    offset += sizeof(field);                                                  \
  } while (0)
  READ_GRANT_BYTES(out_grant->grant_id);
  READ_GRANT_BYTES(out_grant->mesh_id);
  out_grant->policy_epoch = read_u64(canonical + offset);
  offset += sizeof(uint64_t);
  READ_GRANT_BYTES(out_grant->subject_principal);
  READ_GRANT_BYTES(out_grant->target_node_id);
  READ_GRANT_BYTES(out_grant->deployment_id);
  out_grant->deployment_generation = read_u64(canonical + offset);
  offset += sizeof(uint64_t);
  READ_GRANT_BYTES(out_grant->package_digest);
  out_grant->operation =
      (mesh_mgmt_execution_operation_t)read_u32(canonical + offset);
  offset += sizeof(uint32_t);
  out_grant->capabilities = read_u32(canonical + offset);
  offset += sizeof(uint32_t);
  if (!decode_refs(canonical, canonical_size, &offset, out_grant->mount_ids,
                   &out_grant->mount_count) ||
      !decode_refs(canonical, canonical_size, &offset, out_grant->service_ids,
                   &out_grant->service_count) ||
      !decode_refs(canonical, canonical_size, &offset, out_grant->provider_ids,
                   &out_grant->provider_count) ||
      offset > canonical_size || canonical_size - offset < 112u) {
    memset(out_grant, 0, sizeof(*out_grant));
    return MESH_MGMT_EXECUTION_WIRE_INVALID_SCHEMA;
  }
  out_grant->max_limits.module_bytes = read_u32(canonical + offset);
  offset += sizeof(uint32_t);
  out_grant->max_limits.stack_bytes = read_u32(canonical + offset);
  offset += sizeof(uint32_t);
  out_grant->max_limits.linear_memory_bytes = read_u32(canonical + offset);
  offset += sizeof(uint32_t);
  out_grant->max_limits.timeout_ms = read_u64(canonical + offset);
  offset += sizeof(uint64_t);
  out_grant->max_limits.control_flow_steps = read_u64(canonical + offset);
  offset += sizeof(uint64_t);
  out_grant->max_limits.host_calls = read_u32(canonical + offset);
  offset += sizeof(uint32_t);
  out_grant->max_limits.copied_guest_bytes = read_u64(canonical + offset);
  offset += sizeof(uint64_t);
  out_grant->max_limits.input_bytes = read_u64(canonical + offset);
  offset += sizeof(uint64_t);
  out_grant->max_limits.stdout_bytes = read_u64(canonical + offset);
  offset += sizeof(uint64_t);
  out_grant->max_limits.stderr_bytes = read_u64(canonical + offset);
  offset += sizeof(uint64_t);
  out_grant->not_before_ms = read_u64(canonical + offset);
  offset += sizeof(uint64_t);
  out_grant->expires_at_ms = read_u64(canonical + offset);
  offset += sizeof(uint64_t);
  READ_GRANT_BYTES(out_grant->issuer_key);
#undef READ_GRANT_BYTES
  if (offset != canonical_size || !grant_structure_is_valid(out_grant)) {
    memset(out_grant, 0, sizeof(*out_grant));
    return MESH_MGMT_EXECUTION_WIRE_INVALID_SCHEMA;
  }
  return MESH_MGMT_EXECUTION_WIRE_OK;
}

mesh_mgmt_execution_wire_result_t mesh_mgmt_execution_grant_sign_v1(
    mesh_mgmt_execution_grant_v1_t *grant,
    const uint8_t private_key[MESH_MGMT_EXECUTION_DIGEST_SIZE]) {
  uint8_t canonical[MESH_MGMT_EXECUTION_GRANT_CANONICAL_MAX_SIZE_V1];
  size_t canonical_size = 0u;
  mesh_mgmt_execution_wire_result_t result;

  if (!grant || !private_key)
    return MESH_MGMT_EXECUTION_WIRE_INVALID_ARG;
  memset(grant->signature, 0, sizeof(grant->signature));
  if (mesh_mgmt_ed25519_public_from_private(private_key, grant->issuer_key) !=
      MESH_MGMT_CRYPTO_OK)
    return MESH_MGMT_EXECUTION_WIRE_CRYPTO_FAILED;
  result = mesh_mgmt_execution_grant_encode_canonical_v1(
      grant, canonical, sizeof(canonical), &canonical_size);
  if (result != MESH_MGMT_EXECUTION_WIRE_OK)
    return result;
  if (mesh_mgmt_ed25519_sign(private_key, canonical, canonical_size,
                             grant->signature) != MESH_MGMT_CRYPTO_OK) {
    mesh_mgmt_crypto_wipe(canonical, sizeof(canonical));
    return MESH_MGMT_EXECUTION_WIRE_CRYPTO_FAILED;
  }
  mesh_mgmt_crypto_wipe(canonical, sizeof(canonical));
  return MESH_MGMT_EXECUTION_WIRE_OK;
}

mesh_mgmt_execution_wire_result_t mesh_mgmt_execution_grant_verify_v1(
    const mesh_mgmt_execution_grant_v1_t *grant,
    const uint8_t expected_issuer_key[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    uint64_t now_ms) {
  uint8_t canonical[MESH_MGMT_EXECUTION_GRANT_CANONICAL_MAX_SIZE_V1];
  size_t canonical_size = 0u;
  mesh_mgmt_execution_result_t validation;
  mesh_mgmt_execution_wire_result_t result;

  if (!grant || !expected_issuer_key)
    return MESH_MGMT_EXECUTION_WIRE_INVALID_ARG;
  validation = mesh_mgmt_execution_grant_validate_v1(grant, now_ms);
  if (validation == MESH_MGMT_EXECUTION_EXPIRED)
    return MESH_MGMT_EXECUTION_WIRE_EXPIRED;
  if (validation != MESH_MGMT_EXECUTION_OK)
    return MESH_MGMT_EXECUTION_WIRE_INVALID_SCHEMA;
  if (!mesh_mgmt_crypto_equal_32(grant->issuer_key, expected_issuer_key))
    return MESH_MGMT_EXECUTION_WIRE_AUTH_FAILED;
  result = mesh_mgmt_execution_grant_encode_canonical_v1(
      grant, canonical, sizeof(canonical), &canonical_size);
  if (result != MESH_MGMT_EXECUTION_WIRE_OK)
    return result;
  if (mesh_mgmt_ed25519_verify(grant->issuer_key, canonical, canonical_size,
                               grant->signature) != MESH_MGMT_CRYPTO_OK) {
    mesh_mgmt_crypto_wipe(canonical, sizeof(canonical));
    return MESH_MGMT_EXECUTION_WIRE_AUTH_FAILED;
  }
  mesh_mgmt_crypto_wipe(canonical, sizeof(canonical));
  return MESH_MGMT_EXECUTION_WIRE_OK;
}

static size_t write_command_u16_field(uint8_t *output, uint16_t field_id,
                                      uint16_t value) {
  uint8_t encoded[sizeof(uint16_t)];

  write_u16(encoded, value);
  return mesh_mgmt_wire_write_tlv(output, field_id, encoded, sizeof(encoded));
}

static int read_command_u16_field(mesh_mgmt_tlv_reader_t *reader,
                                  uint16_t field_id, uint16_t expected) {
  mesh_mgmt_tlv_view_t field;

  return mesh_mgmt_wire_read_field(reader, field_id, sizeof(uint16_t),
                                   &field) &&
         read_u16(field.value) == expected;
}

mesh_mgmt_execution_wire_result_t
mesh_mgmt_execution_command_request_encode_v1(
    const mesh_mgmt_execution_grant_v1_t *grant,
    const mesh_mgmt_execution_request_v1_t *request, uint8_t *output,
    size_t output_capacity, size_t *out_size) {
  uint8_t grant_canonical[MESH_MGMT_EXECUTION_GRANT_CANONICAL_MAX_SIZE_V1];
  uint8_t request_canonical[MESH_MGMT_EXECUTION_REQUEST_CANONICAL_MAX_SIZE_V1];
  size_t grant_size = 0u;
  size_t request_size = 0u;
  size_t required_size;
  mesh_mgmt_execution_wire_result_t grant_result;
  mesh_mgmt_execution_result_codec_result_t request_result;

  if (!grant || !request || !out_size)
    return MESH_MGMT_EXECUTION_WIRE_INVALID_ARG;
  if (mesh_mgmt_execution_grant_validate_v1(grant, grant->not_before_ms) !=
          MESH_MGMT_EXECUTION_OK ||
      mesh_mgmt_execution_request_validate_v1(
          request,
          request->deadline_ms == 0u ? 0u : request->deadline_ms - 1u) !=
          MESH_MGMT_EXECUTION_OK ||
      mesh_mgmt_execution_request_bind_v1(grant, request) !=
          MESH_MGMT_EXECUTION_OK) {
    return MESH_MGMT_EXECUTION_WIRE_INVALID_SCHEMA;
  }
  grant_result = mesh_mgmt_execution_grant_encode_canonical_v1(
      grant, grant_canonical, sizeof(grant_canonical), &grant_size);
  if (grant_result != MESH_MGMT_EXECUTION_WIRE_OK)
    return grant_result;
  request_result = mesh_mgmt_execution_request_encode_canonical_v1(
      request, request_canonical, sizeof(request_canonical), &request_size);
  if (request_result != MESH_MGMT_EXECUTION_RESULT_OK)
    return map_result_codec(request_result);
  required_size = MESH_MGMT_EXECUTION_COMMAND_REQUEST_OVERHEAD_SIZE_V1 +
                  grant_size + request_size;
  *out_size = required_size;
  if (!output || output_capacity < required_size)
    return MESH_MGMT_EXECUTION_WIRE_RESOURCE_EXHAUSTED;
  required_size = 0u;
  required_size += mesh_mgmt_wire_write_tlv(
      output + required_size, EXECUTION_COMMAND_FIELD_DOMAIN, command_domain,
      sizeof(command_domain));
  required_size += write_command_u16_field(
      output + required_size, EXECUTION_COMMAND_FIELD_VERSION,
      EXECUTION_COMMAND_VERSION_V1);
  required_size += write_command_u16_field(
      output + required_size, EXECUTION_COMMAND_FIELD_KIND,
      EXECUTION_COMMAND_REQUEST_V1);
  required_size += mesh_mgmt_wire_write_tlv(
      output + required_size, EXECUTION_COMMAND_FIELD_BODY, grant_canonical,
      grant_size);
  required_size += mesh_mgmt_wire_write_tlv(
      output + required_size, EXECUTION_COMMAND_FIELD_SIGNATURE,
      grant->signature, MESH_MGMT_EXECUTION_SIGNATURE_SIZE);
  required_size += mesh_mgmt_wire_write_tlv(
      output + required_size, EXECUTION_COMMAND_FIELD_REQUEST,
      request_canonical, request_size);
  if (required_size != *out_size) {
    memset(output, 0, output_capacity);
    return MESH_MGMT_EXECUTION_WIRE_INVALID_SCHEMA;
  }
  return MESH_MGMT_EXECUTION_WIRE_OK;
}

mesh_mgmt_execution_wire_result_t
mesh_mgmt_execution_command_request_decode_v1(
    const uint8_t *payload, size_t payload_size,
    mesh_mgmt_execution_grant_v1_t *out_grant,
    mesh_mgmt_execution_request_v1_t *out_request) {
  mesh_mgmt_tlv_reader_t reader;
  mesh_mgmt_tlv_view_t field;
  mesh_mgmt_execution_wire_result_t grant_result;
  mesh_mgmt_execution_result_codec_result_t request_result;

  if (!payload || !out_grant || !out_request)
    return MESH_MGMT_EXECUTION_WIRE_INVALID_ARG;
  memset(out_grant, 0, sizeof(*out_grant));
  memset(out_request, 0, sizeof(*out_request));
  mesh_mgmt_tlv_reader_init(&reader, payload, payload_size);
  if (!mesh_mgmt_wire_read_field(
          &reader, EXECUTION_COMMAND_FIELD_DOMAIN, sizeof(command_domain),
          &field) ||
      memcmp(field.value, command_domain, sizeof(command_domain)) != 0 ||
      !read_command_u16_field(&reader, EXECUTION_COMMAND_FIELD_VERSION,
                              EXECUTION_COMMAND_VERSION_V1) ||
      !read_command_u16_field(&reader, EXECUTION_COMMAND_FIELD_KIND,
                              EXECUTION_COMMAND_REQUEST_V1) ||
      mesh_mgmt_tlv_reader_next(&reader, &field) != 1 ||
      field.field_id != EXECUTION_COMMAND_FIELD_BODY ||
      field.value_len < MESH_MGMT_EXECUTION_GRANT_CANONICAL_BASE_SIZE_V1 ||
      field.value_len > MESH_MGMT_EXECUTION_GRANT_CANONICAL_MAX_SIZE_V1) {
    return MESH_MGMT_EXECUTION_WIRE_INVALID_SCHEMA;
  }
  grant_result = mesh_mgmt_execution_grant_decode_canonical_v1(
      field.value, field.value_len, out_grant);
  if (grant_result != MESH_MGMT_EXECUTION_WIRE_OK)
    return grant_result;
  if (!mesh_mgmt_wire_read_field(
          &reader, EXECUTION_COMMAND_FIELD_SIGNATURE,
          MESH_MGMT_EXECUTION_SIGNATURE_SIZE, &field)) {
    memset(out_grant, 0, sizeof(*out_grant));
    return MESH_MGMT_EXECUTION_WIRE_INVALID_SCHEMA;
  }
  memcpy(out_grant->signature, field.value, MESH_MGMT_EXECUTION_SIGNATURE_SIZE);
  if (mesh_mgmt_tlv_reader_next(&reader, &field) != 1 ||
      field.field_id != EXECUTION_COMMAND_FIELD_REQUEST ||
      field.value_len <
          MESH_MGMT_EXECUTION_REQUEST_CANONICAL_BASE_SIZE_V1 ||
      field.value_len >
          MESH_MGMT_EXECUTION_REQUEST_CANONICAL_MAX_SIZE_V1) {
    memset(out_grant, 0, sizeof(*out_grant));
    return MESH_MGMT_EXECUTION_WIRE_INVALID_SCHEMA;
  }
  request_result = mesh_mgmt_execution_request_decode_canonical_v1(
      field.value, field.value_len, out_request);
  if (request_result != MESH_MGMT_EXECUTION_RESULT_OK ||
      mesh_mgmt_tlv_reader_next(&reader, &field) != 0 ||
      mesh_mgmt_execution_request_bind_v1(out_grant, out_request) !=
          MESH_MGMT_EXECUTION_OK) {
    memset(out_grant, 0, sizeof(*out_grant));
    memset(out_request, 0, sizeof(*out_request));
    return request_result == MESH_MGMT_EXECUTION_RESULT_OK
               ? MESH_MGMT_EXECUTION_WIRE_INVALID_SCHEMA
               : map_result_codec(request_result);
  }
  return MESH_MGMT_EXECUTION_WIRE_OK;
}

mesh_mgmt_execution_wire_result_t
mesh_mgmt_execution_command_result_encode_v1(
    const mesh_mgmt_execution_result_v1_t *result, uint8_t *output,
    size_t output_capacity, size_t *out_size) {
  uint8_t canonical[MESH_MGMT_EXECUTION_RESULT_CANONICAL_SIZE_V1];
  size_t canonical_size = 0u;
  mesh_mgmt_execution_result_codec_result_t encode_result;

  if (!result || !out_size)
    return MESH_MGMT_EXECUTION_WIRE_INVALID_ARG;
  if (bytes_are_zero(result->signature, sizeof(result->signature)))
    return MESH_MGMT_EXECUTION_WIRE_INVALID_SCHEMA;
  *out_size = MESH_MGMT_EXECUTION_COMMAND_RESULT_SIZE_V1;
  if (!output ||
      output_capacity < MESH_MGMT_EXECUTION_COMMAND_RESULT_SIZE_V1)
    return MESH_MGMT_EXECUTION_WIRE_RESOURCE_EXHAUSTED;
  encode_result = mesh_mgmt_execution_result_encode_canonical_v1(
      result, canonical, sizeof(canonical), &canonical_size);
  if (encode_result != MESH_MGMT_EXECUTION_RESULT_OK)
    return map_result_codec(encode_result);
  canonical_size = 0u;
  canonical_size += mesh_mgmt_wire_write_tlv(
      output + canonical_size, EXECUTION_COMMAND_FIELD_DOMAIN, command_domain,
      sizeof(command_domain));
  canonical_size += write_command_u16_field(
      output + canonical_size, EXECUTION_COMMAND_FIELD_VERSION,
      EXECUTION_COMMAND_VERSION_V1);
  canonical_size += write_command_u16_field(
      output + canonical_size, EXECUTION_COMMAND_FIELD_KIND,
      EXECUTION_COMMAND_RESULT_V1);
  canonical_size += mesh_mgmt_wire_write_tlv(
      output + canonical_size, EXECUTION_COMMAND_FIELD_BODY, canonical,
      MESH_MGMT_EXECUTION_RESULT_CANONICAL_SIZE_V1);
  canonical_size += mesh_mgmt_wire_write_tlv(
      output + canonical_size, EXECUTION_COMMAND_FIELD_SIGNATURE,
      result->signature, MESH_MGMT_EXECUTION_SIGNATURE_SIZE);
  if (canonical_size != MESH_MGMT_EXECUTION_COMMAND_RESULT_SIZE_V1) {
    memset(output, 0, output_capacity);
    return MESH_MGMT_EXECUTION_WIRE_INVALID_SCHEMA;
  }
  return MESH_MGMT_EXECUTION_WIRE_OK;
}

mesh_mgmt_execution_wire_result_t
mesh_mgmt_execution_command_result_decode_v1(
    const uint8_t *payload, size_t payload_size,
    mesh_mgmt_execution_result_v1_t *out_result) {
  mesh_mgmt_tlv_reader_t reader;
  mesh_mgmt_tlv_view_t field;
  mesh_mgmt_execution_result_codec_result_t decode_result;

  if (!payload || !out_result)
    return MESH_MGMT_EXECUTION_WIRE_INVALID_ARG;
  memset(out_result, 0, sizeof(*out_result));
  mesh_mgmt_tlv_reader_init(&reader, payload, payload_size);
  if (!mesh_mgmt_wire_read_field(
          &reader, EXECUTION_COMMAND_FIELD_DOMAIN, sizeof(command_domain),
          &field) ||
      memcmp(field.value, command_domain, sizeof(command_domain)) != 0 ||
      !read_command_u16_field(&reader, EXECUTION_COMMAND_FIELD_VERSION,
                              EXECUTION_COMMAND_VERSION_V1) ||
      !read_command_u16_field(&reader, EXECUTION_COMMAND_FIELD_KIND,
                              EXECUTION_COMMAND_RESULT_V1) ||
      !mesh_mgmt_wire_read_field(
          &reader, EXECUTION_COMMAND_FIELD_BODY,
          MESH_MGMT_EXECUTION_RESULT_CANONICAL_SIZE_V1, &field)) {
    return MESH_MGMT_EXECUTION_WIRE_INVALID_SCHEMA;
  }
  decode_result = mesh_mgmt_execution_result_decode_canonical_v1(
      field.value, field.value_len, out_result);
  if (decode_result != MESH_MGMT_EXECUTION_RESULT_OK)
    return map_result_codec(decode_result);
  if (!mesh_mgmt_wire_read_field(
          &reader, EXECUTION_COMMAND_FIELD_SIGNATURE,
          MESH_MGMT_EXECUTION_SIGNATURE_SIZE, &field)) {
    memset(out_result, 0, sizeof(*out_result));
    return MESH_MGMT_EXECUTION_WIRE_INVALID_SCHEMA;
  }
  memcpy(out_result->signature, field.value,
         MESH_MGMT_EXECUTION_SIGNATURE_SIZE);
  if (mesh_mgmt_tlv_reader_next(&reader, &field) != 0) {
    memset(out_result, 0, sizeof(*out_result));
    return MESH_MGMT_EXECUTION_WIRE_INVALID_SCHEMA;
  }
  return MESH_MGMT_EXECUTION_WIRE_OK;
}

static int execution_status_code_valid(uint16_t code) {
  return code >= MESH_MGMT_EXECUTION_STATUS_DISABLED &&
         code <= MESH_MGMT_EXECUTION_STATUS_INTERNAL;
}

int mesh_mgmt_execution_status_is_retryable_v1(uint16_t code) {
  return code == MESH_MGMT_EXECUTION_STATUS_BUSY ||
         code == MESH_MGMT_EXECUTION_STATUS_INDETERMINATE ||
         code == MESH_MGMT_EXECUTION_STATUS_STORE_FAILED ||
         code == MESH_MGMT_EXECUTION_STATUS_INTERNAL;
}

mesh_mgmt_execution_wire_result_t
mesh_mgmt_execution_command_status_encode_v1(
    const mesh_mgmt_execution_status_v1_t *status, uint8_t *output,
    size_t output_capacity, size_t *out_size) {
  uint8_t canonical[MESH_MGMT_EXECUTION_STATUS_CANONICAL_SIZE_V1];
  size_t offset = 0u;
  size_t encoded = 0u;

  if (!status || !out_size)
    return MESH_MGMT_EXECUTION_WIRE_INVALID_ARG;
  *out_size = MESH_MGMT_EXECUTION_COMMAND_STATUS_SIZE_V1;
  if (status->version != MESH_MGMT_EXECUTION_SCHEMA_V1 ||
      !execution_status_code_valid(status->code) ||
      bytes_are_zero(status->command_id, sizeof(status->command_id)) ||
      bytes_are_zero(status->correlation_id, sizeof(status->correlation_id)) ||
      bytes_are_zero(status->request_digest, sizeof(status->request_digest)) ||
      bytes_are_zero(status->responder_node_id,
                     sizeof(status->responder_node_id)))
    return MESH_MGMT_EXECUTION_WIRE_INVALID_SCHEMA;
  if (!output ||
      output_capacity < MESH_MGMT_EXECUTION_COMMAND_STATUS_SIZE_V1)
    return MESH_MGMT_EXECUTION_WIRE_RESOURCE_EXHAUSTED;

  memcpy(canonical + offset, status_domain, sizeof(status_domain));
  offset += sizeof(status_domain);
  write_u16(canonical + offset, status->version);
  offset += sizeof(uint16_t);
  write_u16(canonical + offset, status->code);
  offset += sizeof(uint16_t);
  memcpy(canonical + offset, status->command_id, sizeof(status->command_id));
  offset += sizeof(status->command_id);
  memcpy(canonical + offset, status->correlation_id,
         sizeof(status->correlation_id));
  offset += sizeof(status->correlation_id);
  memcpy(canonical + offset, status->request_digest,
         sizeof(status->request_digest));
  offset += sizeof(status->request_digest);
  memcpy(canonical + offset, status->responder_node_id,
         sizeof(status->responder_node_id));
  offset += sizeof(status->responder_node_id);
  if (offset != sizeof(canonical))
    return MESH_MGMT_EXECUTION_WIRE_INVALID_SCHEMA;

  encoded += mesh_mgmt_wire_write_tlv(
      output + encoded, EXECUTION_COMMAND_FIELD_DOMAIN, command_domain,
      sizeof(command_domain));
  encoded += write_command_u16_field(
      output + encoded, EXECUTION_COMMAND_FIELD_VERSION,
      EXECUTION_COMMAND_VERSION_V1);
  encoded += write_command_u16_field(
      output + encoded, EXECUTION_COMMAND_FIELD_KIND,
      EXECUTION_COMMAND_STATUS_V1);
  encoded += mesh_mgmt_wire_write_tlv(
      output + encoded, EXECUTION_COMMAND_FIELD_BODY, canonical,
      sizeof(canonical));
  if (encoded != *out_size) {
    memset(output, 0, output_capacity);
    return MESH_MGMT_EXECUTION_WIRE_INVALID_SCHEMA;
  }
  return MESH_MGMT_EXECUTION_WIRE_OK;
}

mesh_mgmt_execution_wire_result_t
mesh_mgmt_execution_command_status_decode_v1(
    const uint8_t *payload, size_t payload_size,
    mesh_mgmt_execution_status_v1_t *out_status) {
  mesh_mgmt_tlv_reader_t reader;
  mesh_mgmt_tlv_view_t field;
  uint8_t canonical[MESH_MGMT_EXECUTION_STATUS_CANONICAL_SIZE_V1];
  size_t offset = 0u;

  if (!payload || !out_status)
    return MESH_MGMT_EXECUTION_WIRE_INVALID_ARG;
  memset(out_status, 0, sizeof(*out_status));
  mesh_mgmt_tlv_reader_init(&reader, payload, payload_size);
  if (!mesh_mgmt_wire_read_field(
          &reader, EXECUTION_COMMAND_FIELD_DOMAIN, sizeof(command_domain),
          &field) ||
      memcmp(field.value, command_domain, sizeof(command_domain)) != 0 ||
      !read_command_u16_field(&reader, EXECUTION_COMMAND_FIELD_VERSION,
                              EXECUTION_COMMAND_VERSION_V1) ||
      !read_command_u16_field(&reader, EXECUTION_COMMAND_FIELD_KIND,
                              EXECUTION_COMMAND_STATUS_V1) ||
      !mesh_mgmt_wire_read_field(
          &reader, EXECUTION_COMMAND_FIELD_BODY,
          MESH_MGMT_EXECUTION_STATUS_CANONICAL_SIZE_V1, &field))
    return MESH_MGMT_EXECUTION_WIRE_INVALID_SCHEMA;
  memcpy(canonical, field.value, sizeof(canonical));
  if (mesh_mgmt_tlv_reader_next(&reader, &field) != 0)
    return MESH_MGMT_EXECUTION_WIRE_INVALID_SCHEMA;
  if (memcmp(canonical, status_domain, sizeof(status_domain)) != 0)
    return MESH_MGMT_EXECUTION_WIRE_INVALID_SCHEMA;
  offset += sizeof(status_domain);
  out_status->version = read_u16(canonical + offset);
  offset += sizeof(uint16_t);
  out_status->code = read_u16(canonical + offset);
  offset += sizeof(uint16_t);
  memcpy(out_status->command_id, canonical + offset,
         sizeof(out_status->command_id));
  offset += sizeof(out_status->command_id);
  memcpy(out_status->correlation_id, canonical + offset,
         sizeof(out_status->correlation_id));
  offset += sizeof(out_status->correlation_id);
  memcpy(out_status->request_digest, canonical + offset,
         sizeof(out_status->request_digest));
  offset += sizeof(out_status->request_digest);
  memcpy(out_status->responder_node_id, canonical + offset,
         sizeof(out_status->responder_node_id));
  if (out_status->version != MESH_MGMT_EXECUTION_SCHEMA_V1 ||
      !execution_status_code_valid(out_status->code) ||
      bytes_are_zero(out_status->command_id,
                     sizeof(out_status->command_id)) ||
      bytes_are_zero(out_status->correlation_id,
                     sizeof(out_status->correlation_id)) ||
      bytes_are_zero(out_status->request_digest,
                     sizeof(out_status->request_digest)) ||
      bytes_are_zero(out_status->responder_node_id,
                     sizeof(out_status->responder_node_id))) {
    memset(out_status, 0, sizeof(*out_status));
    return MESH_MGMT_EXECUTION_WIRE_INVALID_SCHEMA;
  }
  return MESH_MGMT_EXECUTION_WIRE_OK;
}
