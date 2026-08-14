#include "mesh_control_mmp.h"

#include "mesh_mgmt_crypto.h"
#include "mesh_mgmt_wire.h"

#include <string.h>

static const uint8_t MESH_CONTROL_MMP_MAGIC_V1[4] = {'T', 'C', 'T', 'L'};

enum {
  MESH_CONTROL_FIELD_DOMAIN_V1 = 1,
  MESH_CONTROL_FIELD_SCHEMA_V1 = 2,
  MESH_CONTROL_FIELD_KIND_V1 = 3,
  MESH_CONTROL_FIELD_RESOURCE_KIND_V1 = 4,
  MESH_CONTROL_FIELD_FLAGS_V1 = 5,
  MESH_CONTROL_FIELD_EPOCH_V1 = 6,
  MESH_CONTROL_FIELD_PRECONDITION_EPOCH_V1 = 7,
  MESH_CONTROL_FIELD_REQUEST_ID_V1 = 8,
  MESH_CONTROL_FIELD_RESOURCE_ID_V1 = 9,
  MESH_CONTROL_FIELD_BODY_V1 = 10
};

static size_t write_u16_field(uint8_t *output, uint16_t field_id,
                              uint16_t value) {
  uint8_t bytes[sizeof(value)];
  mesh_mgmt_wire_write_u16(bytes, value);
  return mesh_mgmt_wire_write_tlv(output, field_id, bytes, sizeof(bytes));
}

static size_t write_u32_field(uint8_t *output, uint16_t field_id,
                              uint32_t value) {
  uint8_t bytes[sizeof(value)];
  mesh_mgmt_wire_write_u32(bytes, value);
  return mesh_mgmt_wire_write_tlv(output, field_id, bytes, sizeof(bytes));
}

static size_t write_u64_field(uint8_t *output, uint16_t field_id,
                              uint64_t value) {
  uint8_t bytes[sizeof(value)];
  mesh_mgmt_wire_write_u64(bytes, value);
  return mesh_mgmt_wire_write_tlv(output, field_id, bytes, sizeof(bytes));
}

mesh_control_mmp_result_t mesh_control_mmp_body_digest_v1(
    const uint8_t *body, size_t body_size,
    uint8_t out_digest[MESH_CONTROL_DIGEST_SIZE]) {
  if (out_digest == NULL || (body_size != 0u && body == NULL) ||
      body_size > MESH_CONTROL_MMP_BODY_MAX_V1) {
    return MESH_CONTROL_MMP_INVALID_ARG;
  }
  memset(out_digest, 0, MESH_CONTROL_DIGEST_SIZE);
  if (body_size == 0u) {
    return MESH_CONTROL_MMP_OK;
  }
  if (mesh_mgmt_blake2b_256(body, body_size, out_digest) !=
      MESH_MGMT_CRYPTO_OK) {
    memset(out_digest, 0, MESH_CONTROL_DIGEST_SIZE);
    return MESH_CONTROL_MMP_CRYPTO_FAILED;
  }
  return MESH_CONTROL_MMP_OK;
}

mesh_control_mmp_result_t mesh_control_mmp_payload_encode_v1(
    const mesh_control_envelope_v1_t *envelope, const uint8_t *body,
    size_t body_size, uint8_t *output, size_t output_capacity,
    size_t *out_size) {
  uint8_t digest[MESH_CONTROL_DIGEST_SIZE];
  size_t required_size;
  size_t offset = 0u;

  if (out_size == NULL) {
    return MESH_CONTROL_MMP_INVALID_ARG;
  }
  *out_size = 0u;
  if (envelope == NULL || body_size != envelope->payload_size ||
      (body_size != 0u && body == NULL) ||
      mesh_control_envelope_validate_v1(envelope) != MESH_CONTROL_OK) {
    return MESH_CONTROL_MMP_INVALID_ARG;
  }
  if (body_size > MESH_CONTROL_MMP_BODY_MAX_V1) {
    return MESH_CONTROL_MMP_RESOURCE_EXHAUSTED;
  }
  if (mesh_control_mmp_body_digest_v1(body, body_size, digest) !=
      MESH_CONTROL_MMP_OK) {
    return MESH_CONTROL_MMP_CRYPTO_FAILED;
  }
  if (memcmp(digest, envelope->payload_digest, sizeof(digest)) != 0) {
    return MESH_CONTROL_MMP_DIGEST_MISMATCH;
  }
  required_size = MESH_CONTROL_MMP_PAYLOAD_HEADER_SIZE_V1 + body_size;
  *out_size = required_size;
  if (output == NULL || output_capacity < required_size) {
    return MESH_CONTROL_MMP_RESOURCE_EXHAUSTED;
  }

  offset += mesh_mgmt_wire_write_tlv(
      output + offset, MESH_CONTROL_FIELD_DOMAIN_V1,
      MESH_CONTROL_MMP_MAGIC_V1, sizeof(MESH_CONTROL_MMP_MAGIC_V1));
  offset += write_u16_field(output + offset, MESH_CONTROL_FIELD_SCHEMA_V1,
                            envelope->schema_version);
  offset += write_u16_field(output + offset, MESH_CONTROL_FIELD_KIND_V1,
                            envelope->kind);
  offset += write_u16_field(output + offset,
                            MESH_CONTROL_FIELD_RESOURCE_KIND_V1,
                            envelope->resource_kind);
  offset += write_u32_field(output + offset, MESH_CONTROL_FIELD_FLAGS_V1,
                            envelope->flags);
  offset += write_u64_field(output + offset, MESH_CONTROL_FIELD_EPOCH_V1,
                            envelope->epoch);
  offset += write_u64_field(
      output + offset, MESH_CONTROL_FIELD_PRECONDITION_EPOCH_V1,
      envelope->precondition_epoch);
  offset += mesh_mgmt_wire_write_tlv(
      output + offset, MESH_CONTROL_FIELD_REQUEST_ID_V1,
      envelope->request_id, sizeof(envelope->request_id));
  offset += mesh_mgmt_wire_write_tlv(
      output + offset, MESH_CONTROL_FIELD_RESOURCE_ID_V1,
      envelope->resource_id, sizeof(envelope->resource_id));
  offset += mesh_mgmt_wire_write_tlv(
      output + offset, MESH_CONTROL_FIELD_BODY_V1, body, body_size);
  if (offset != required_size) {
    memset(output, 0, required_size);
    *out_size = 0u;
    return MESH_CONTROL_MMP_INVALID_SCHEMA;
  }
  return MESH_CONTROL_MMP_OK;
}

mesh_control_mmp_result_t mesh_control_mmp_payload_decode_v1(
    const mesh_mgmt_verified_envelope_v1_t *verified,
    mesh_control_envelope_v1_t *out_envelope, const uint8_t **out_body,
    size_t *out_body_size) {
  const uint8_t *payload;
  const uint8_t *body;
  size_t payload_size;
  size_t body_size;
  mesh_mgmt_tlv_reader_t reader;
  mesh_mgmt_tlv_view_t field;

  if (verified == NULL || out_envelope == NULL || out_body == NULL ||
      out_body_size == NULL) {
    return MESH_CONTROL_MMP_INVALID_ARG;
  }
  memset(out_envelope, 0, sizeof(*out_envelope));
  *out_body = NULL;
  *out_body_size = 0u;
  if (verified->frame.kind != MESH_MGMT_KIND_CONTROL_FRAME) {
    return MESH_CONTROL_MMP_INVALID_SCHEMA;
  }
  payload = verified->frame.payload;
  payload_size = verified->frame.payload_len;
  if (payload == NULL ||
      payload_size < MESH_CONTROL_MMP_PAYLOAD_HEADER_SIZE_V1 ||
      payload_size > MESH_CONTROL_MMP_PAYLOAD_HEADER_SIZE_V1 +
                         MESH_CONTROL_MMP_BODY_MAX_V1) {
    return MESH_CONTROL_MMP_INVALID_SCHEMA;
  }
  mesh_mgmt_tlv_reader_init(&reader, payload, payload_size);
#define READ_FIELD(field_id, size)                                        \
  if (!mesh_mgmt_wire_read_field(&reader, (field_id), (size), &field))    \
    return MESH_CONTROL_MMP_INVALID_SCHEMA
  READ_FIELD(MESH_CONTROL_FIELD_DOMAIN_V1,
             sizeof(MESH_CONTROL_MMP_MAGIC_V1));
  if (memcmp(field.value, MESH_CONTROL_MMP_MAGIC_V1,
             sizeof(MESH_CONTROL_MMP_MAGIC_V1)) != 0) {
    return MESH_CONTROL_MMP_INVALID_SCHEMA;
  }
  READ_FIELD(MESH_CONTROL_FIELD_SCHEMA_V1, sizeof(uint16_t));
  out_envelope->schema_version = mesh_mgmt_wire_read_u16(field.value);
  READ_FIELD(MESH_CONTROL_FIELD_KIND_V1, sizeof(uint16_t));
  out_envelope->kind = mesh_mgmt_wire_read_u16(field.value);
  READ_FIELD(MESH_CONTROL_FIELD_RESOURCE_KIND_V1, sizeof(uint16_t));
  out_envelope->resource_kind = mesh_mgmt_wire_read_u16(field.value);
  READ_FIELD(MESH_CONTROL_FIELD_FLAGS_V1, sizeof(uint32_t));
  out_envelope->flags = mesh_mgmt_wire_read_u32(field.value);
  READ_FIELD(MESH_CONTROL_FIELD_EPOCH_V1, sizeof(uint64_t));
  out_envelope->epoch = mesh_mgmt_wire_read_u64(field.value);
  READ_FIELD(MESH_CONTROL_FIELD_PRECONDITION_EPOCH_V1, sizeof(uint64_t));
  out_envelope->precondition_epoch = mesh_mgmt_wire_read_u64(field.value);
  READ_FIELD(MESH_CONTROL_FIELD_REQUEST_ID_V1,
             sizeof(out_envelope->request_id));
  memcpy(out_envelope->request_id, field.value,
         sizeof(out_envelope->request_id));
  READ_FIELD(MESH_CONTROL_FIELD_RESOURCE_ID_V1,
             sizeof(out_envelope->resource_id));
  memcpy(out_envelope->resource_id, field.value,
         sizeof(out_envelope->resource_id));
  if (mesh_mgmt_tlv_reader_next(&reader, &field) != 1 ||
      field.field_id != MESH_CONTROL_FIELD_BODY_V1 ||
      field.value_len > MESH_CONTROL_MMP_BODY_MAX_V1) {
    return MESH_CONTROL_MMP_INVALID_SCHEMA;
  }
  body = field.value;
  body_size = field.value_len;
  if (mesh_mgmt_tlv_reader_next(&reader, &field) != 0) {
    return MESH_CONTROL_MMP_INVALID_SCHEMA;
  }
#undef READ_FIELD

  memcpy(out_envelope->message_id, verified->header.message_id,
         sizeof(out_envelope->message_id));
  memcpy(out_envelope->mesh_id, verified->header.mesh_id_hash,
         sizeof(out_envelope->mesh_id));
  memcpy(out_envelope->origin_principal,
         verified->header.origin_principal_key,
         sizeof(out_envelope->origin_principal));
  memcpy(out_envelope->origin_node_id, verified->header.origin_node_id,
         sizeof(out_envelope->origin_node_id));
  memcpy(out_envelope->session_id, verified->header.session_id,
         sizeof(out_envelope->session_id));
  memcpy(out_envelope->target_node_id, verified->header.target_node_id,
         sizeof(out_envelope->target_node_id));
  out_envelope->sequence = verified->header.origin_sequence;
  out_envelope->issued_at_ms = verified->header.issued_at_ms;
  out_envelope->expires_at_ms = verified->header.expires_at_ms;
  out_envelope->principal_epoch = verified->header.principal_epoch;
  out_envelope->incarnation = verified->header.incarnation;
  out_envelope->certificate_serial =
      verified->header.certificate_serial;
  out_envelope->payload_size = body_size;
  if (mesh_control_mmp_body_digest_v1(
          body_size == 0u ? NULL : body, body_size,
          out_envelope->payload_digest) != MESH_CONTROL_MMP_OK) {
    memset(out_envelope, 0, sizeof(*out_envelope));
    return MESH_CONTROL_MMP_CRYPTO_FAILED;
  }
  if (mesh_control_envelope_validate_v1(out_envelope) != MESH_CONTROL_OK) {
    memset(out_envelope, 0, sizeof(*out_envelope));
    return MESH_CONTROL_MMP_INVALID_SCHEMA;
  }
  *out_body = body_size == 0u ? NULL : body;
  *out_body_size = body_size;
  return MESH_CONTROL_MMP_OK;
}
