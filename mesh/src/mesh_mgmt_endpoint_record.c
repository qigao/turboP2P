#include "mesh_mgmt_endpoint_record.h"

#include "mesh_mgmt_crypto.h"
#include "mesh_mgmt_envelope.h"
#include "mesh_mgmt_wire.h"

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <sys/socket.h>
  #include <arpa/inet.h>
#endif

#include <string.h>

enum {
  ENDPOINT_FIELD_RECORD_KIND = 1,
  ENDPOINT_FIELD_OWNER_NODE_ID = 2,
  ENDPOINT_FIELD_TRANSPORT_PEER_ID = 3,
  ENDPOINT_FIELD_ADDRESS_FAMILY = 4,
  ENDPOINT_FIELD_ADDRESS = 5,
  ENDPOINT_FIELD_PORT = 6,
  ENDPOINT_FIELD_RECORD_EPOCH = 7,
  ENDPOINT_FIELD_EXPIRES_AT_MS = 8,
};

enum { ENDPOINT_RECORD_KIND_V1 = 1 };

static const char ENDPOINT_DHT_PREFIX[] = "mgmt:";
static const char ENDPOINT_DHT_NODE_SEPARATOR[] = ":node:";
static const char HEX_LOWER[] = "0123456789abcdef";

static int bytes_are_zero(const uint8_t *bytes, size_t length) {
  uint8_t aggregate = 0u;
  size_t index;

  for (index = 0u; index < length; index++)
    aggregate |= bytes[index];
  return aggregate == 0u;
}

static void bytes_to_lower_hex(const uint8_t *bytes, size_t length, char *output) {
  size_t index;

  for (index = 0u; index < length; index++) {
    output[index * 2u] = HEX_LOWER[bytes[index] >> 4u];
    output[index * 2u + 1u] = HEX_LOWER[bytes[index] & 0x0fu];
  }
}

static int lower_hex_value(char value, uint8_t *output) {
  if (value >= '0' && value <= '9') {
    *output = (uint8_t)(value - '0');
    return 1;
  }
  if (value >= 'a' && value <= 'f') {
    *output = (uint8_t)(value - 'a' + 10);
    return 1;
  }
  return 0;
}

static int lower_hex_to_bytes(const char *hex, size_t output_length, uint8_t *output) {
  size_t index;

  for (index = 0u; index < output_length; index++) {
    uint8_t high;
    uint8_t low;

    if (!lower_hex_value(hex[index * 2u], &high) || !lower_hex_value(hex[index * 2u + 1u], &low))
      return 0;
    output[index] = (uint8_t)((high << 4u) | low);
  }
  return 1;
}

static size_t address_length(mesh_mgmt_endpoint_address_family_t family) {
  if (family == MESH_MGMT_ENDPOINT_ADDRESS_IPV4)
    return 4u;
  if (family == MESH_MGMT_ENDPOINT_ADDRESS_IPV6)
    return 16u;
  return 0u;
}

static int address_is_valid(const mesh_mgmt_endpoint_announcement_v1_t *announcement) {
  static const uint8_t IPV4_MAPPED_PREFIX[12] = {0u, 0u, 0u, 0u, 0u,    0u,
                                                 0u, 0u, 0u, 0u, 0xffu, 0xffu};
  size_t length;
  size_t index;

  if (!announcement)
    return 0;
  length = address_length(announcement->address_family);
  if (length == 0u || bytes_are_zero(announcement->address, length))
    return 0;
  if (announcement->address_family == MESH_MGMT_ENDPOINT_ADDRESS_IPV4) {
    if (announcement->address[0] == 0u || announcement->address[0] >= 224u ||
        !bytes_are_zero(announcement->address + 4u, sizeof(announcement->address) - 4u))
      return 0;
  } else {
    if (announcement->address[0] == 0xffu ||
        memcmp(announcement->address, IPV4_MAPPED_PREFIX, sizeof(IPV4_MAPPED_PREFIX)) == 0)
      return 0;
  }
  for (index = length; index < sizeof(announcement->address); index++) {
    if (announcement->address[index] != 0u)
      return 0;
  }
  return 1;
}

static int announcement_is_valid(const mesh_mgmt_endpoint_announcement_v1_t *announcement) {
  return announcement && !bytes_are_zero(announcement->owner_node_id, 32u) &&
         !bytes_are_zero(announcement->transport_peer_id, P2P_KEY_SIZE) &&
         address_is_valid(announcement) && announcement->port != 0u &&
         announcement->record_epoch != 0u && announcement->expires_at_ms != 0u;
}

static size_t write_u64_field(uint8_t *output, uint16_t field_id, uint64_t value) {
  uint8_t bytes[sizeof(value)];

  mesh_mgmt_wire_write_u64(bytes, value);
  return mesh_mgmt_wire_write_tlv(output, field_id, bytes, sizeof(bytes));
}

static size_t write_u16_field(uint8_t *output, uint16_t field_id, uint16_t value) {
  uint8_t bytes[sizeof(value)];

  mesh_mgmt_wire_write_u16(bytes, value);
  return mesh_mgmt_wire_write_tlv(output, field_id, bytes, sizeof(bytes));
}

static int read_field(mesh_mgmt_tlv_reader_t *reader, uint16_t field_id, size_t length,
                      mesh_mgmt_tlv_view_t *field) {
  return mesh_mgmt_wire_read_field(reader, field_id, length, field);
}

static mesh_mgmt_endpoint_record_result_t map_envelope_result(mesh_mgmt_envelope_result_t result) {
  switch (result) {
  case MESH_MGMT_ENVELOPE_OK:
    return MESH_MGMT_ENDPOINT_RECORD_OK;
  case MESH_MGMT_ENVELOPE_AUTH_FAILED:
  case MESH_MGMT_ENVELOPE_PAYLOAD_HASH_MISMATCH:
    return MESH_MGMT_ENDPOINT_RECORD_AUTH_FAILED;
  case MESH_MGMT_ENVELOPE_RESOURCE_EXHAUSTED:
    return MESH_MGMT_ENDPOINT_RECORD_RESOURCE_EXHAUSTED;
  case MESH_MGMT_ENVELOPE_CRYPTO_FAILURE:
    return MESH_MGMT_ENDPOINT_RECORD_CRYPTO_FAILURE;
  case MESH_MGMT_ENVELOPE_INVALID_ARG:
    return MESH_MGMT_ENDPOINT_RECORD_INVALID_ARG;
  case MESH_MGMT_ENVELOPE_INVALID_FRAME:
  case MESH_MGMT_ENVELOPE_UNSUPPORTED_VERSION:
  case MESH_MGMT_ENVELOPE_INVALID_SCHEMA:
  default:
    return MESH_MGMT_ENDPOINT_RECORD_INVALID_SCHEMA;
  }
}

static mesh_mgmt_endpoint_record_result_t map_identity_result(mesh_mgmt_identity_result_t result) {
  switch (result) {
  case MESH_MGMT_IDENTITY_OK:
    return MESH_MGMT_ENDPOINT_RECORD_OK;
  case MESH_MGMT_IDENTITY_AUTH_FAILED:
    return MESH_MGMT_ENDPOINT_RECORD_AUTH_FAILED;
  case MESH_MGMT_IDENTITY_EXPIRED:
    return MESH_MGMT_ENDPOINT_RECORD_EXPIRED;
  case MESH_MGMT_IDENTITY_RESOURCE_EXHAUSTED:
    return MESH_MGMT_ENDPOINT_RECORD_RESOURCE_EXHAUSTED;
  case MESH_MGMT_IDENTITY_CRYPTO_FAILURE:
    return MESH_MGMT_ENDPOINT_RECORD_CRYPTO_FAILURE;
  case MESH_MGMT_IDENTITY_INVALID_ARG:
    return MESH_MGMT_ENDPOINT_RECORD_INVALID_ARG;
  case MESH_MGMT_IDENTITY_INVALID_SCHEMA:
  default:
    return MESH_MGMT_ENDPOINT_RECORD_INVALID_SCHEMA;
  }
}

mesh_mgmt_endpoint_record_result_t
mesh_mgmt_endpoint_dht_key_build_v1(const uint8_t mesh_id_hash[32], const uint8_t owner_node_id[32],
                                    char *output, size_t output_capacity, size_t *out_len) {
  char key[MESH_MGMT_ENDPOINT_DHT_KEY_V1_SIZE];
  size_t offset = 0u;

  if (!mesh_id_hash || !owner_node_id || !out_len)
    return MESH_MGMT_ENDPOINT_RECORD_INVALID_ARG;
  *out_len = 0u;
  if (bytes_are_zero(mesh_id_hash, 32u) || bytes_are_zero(owner_node_id, 32u))
    return MESH_MGMT_ENDPOINT_RECORD_INVALID_SCHEMA;
  if (!output || output_capacity < sizeof(key)) {
    *out_len = MESH_MGMT_ENDPOINT_DHT_KEY_V1_LENGTH;
    return MESH_MGMT_ENDPOINT_RECORD_RESOURCE_EXHAUSTED;
  }

  memcpy(key + offset, ENDPOINT_DHT_PREFIX, sizeof(ENDPOINT_DHT_PREFIX) - 1u);
  offset += sizeof(ENDPOINT_DHT_PREFIX) - 1u;
  bytes_to_lower_hex(mesh_id_hash, 32u, key + offset);
  offset += 64u;
  memcpy(key + offset, ENDPOINT_DHT_NODE_SEPARATOR, sizeof(ENDPOINT_DHT_NODE_SEPARATOR) - 1u);
  offset += sizeof(ENDPOINT_DHT_NODE_SEPARATOR) - 1u;
  bytes_to_lower_hex(owner_node_id, 32u, key + offset);
  offset += 64u;
  if (offset != MESH_MGMT_ENDPOINT_DHT_KEY_V1_LENGTH)
    return MESH_MGMT_ENDPOINT_RECORD_INVALID_SCHEMA;
  key[offset] = '\0';
  memcpy(output, key, sizeof(key));
  *out_len = offset;
  return MESH_MGMT_ENDPOINT_RECORD_OK;
}

mesh_mgmt_endpoint_record_result_t
mesh_mgmt_endpoint_dht_key_parse_v1(const char *key, size_t key_len, uint8_t out_mesh_id_hash[32],
                                    uint8_t out_owner_node_id[32]) {
  uint8_t mesh_id_hash[32];
  uint8_t owner_node_id[32];
  size_t offset = 0u;

  if (!out_mesh_id_hash || !out_owner_node_id)
    return MESH_MGMT_ENDPOINT_RECORD_INVALID_ARG;
  memset(out_mesh_id_hash, 0, 32u);
  memset(out_owner_node_id, 0, 32u);
  memset(mesh_id_hash, 0, sizeof(mesh_id_hash));
  memset(owner_node_id, 0, sizeof(owner_node_id));
  if (!key || key_len != MESH_MGMT_ENDPOINT_DHT_KEY_V1_LENGTH)
    goto invalid_schema;
  if (memcmp(key + offset, ENDPOINT_DHT_PREFIX, sizeof(ENDPOINT_DHT_PREFIX) - 1u) != 0)
    goto invalid_schema;
  offset += sizeof(ENDPOINT_DHT_PREFIX) - 1u;
  if (!lower_hex_to_bytes(key + offset, sizeof(mesh_id_hash), mesh_id_hash))
    goto invalid_schema;
  offset += sizeof(mesh_id_hash) * 2u;
  if (memcmp(key + offset, ENDPOINT_DHT_NODE_SEPARATOR, sizeof(ENDPOINT_DHT_NODE_SEPARATOR) - 1u) !=
      0)
    goto invalid_schema;
  offset += sizeof(ENDPOINT_DHT_NODE_SEPARATOR) - 1u;
  if (!lower_hex_to_bytes(key + offset, sizeof(owner_node_id), owner_node_id))
    goto invalid_schema;
  offset += sizeof(owner_node_id) * 2u;
  if (offset != key_len || bytes_are_zero(mesh_id_hash, sizeof(mesh_id_hash)) ||
      bytes_are_zero(owner_node_id, sizeof(owner_node_id)))
    goto invalid_schema;

  memcpy(out_mesh_id_hash, mesh_id_hash, sizeof(mesh_id_hash));
  memcpy(out_owner_node_id, owner_node_id, sizeof(owner_node_id));
  return MESH_MGMT_ENDPOINT_RECORD_OK;

invalid_schema:
  mesh_mgmt_crypto_wipe(mesh_id_hash, sizeof(mesh_id_hash));
  mesh_mgmt_crypto_wipe(owner_node_id, sizeof(owner_node_id));
  return MESH_MGMT_ENDPOINT_RECORD_INVALID_SCHEMA;
}

static int address_to_host(const mesh_mgmt_endpoint_announcement_v1_t *announcement,
                           char output[MESH_MGMT_ENDPOINT_HOST_MAX]) {
  int family = announcement->address_family == MESH_MGMT_ENDPOINT_ADDRESS_IPV4
                   ? AF_INET
                   : AF_INET6;

  if (inet_ntop(family, announcement->address, output, MESH_MGMT_ENDPOINT_HOST_MAX) == NULL) {
    return 0;
  }
  return output[0] != '\\0';
}

mesh_mgmt_endpoint_record_result_t
mesh_mgmt_endpoint_record_encode_v1(const mesh_mgmt_endpoint_announcement_v1_t *announcement,
                                    uint8_t *output, size_t output_capacity, size_t *out_len) {
  uint8_t record_kind = ENDPOINT_RECORD_KIND_V1;
  uint8_t family;
  size_t address_size;
  size_t required_size;
  size_t offset = 0u;

  if (!announcement || !out_len)
    return MESH_MGMT_ENDPOINT_RECORD_INVALID_ARG;
  *out_len = 0u;
  if (!announcement_is_valid(announcement))
    return MESH_MGMT_ENDPOINT_RECORD_INVALID_SCHEMA;
  address_size = address_length(announcement->address_family);
  required_size = announcement->address_family == MESH_MGMT_ENDPOINT_ADDRESS_IPV4
                      ? MESH_MGMT_ENDPOINT_RECORD_IPV4_V1_SIZE
                      : MESH_MGMT_ENDPOINT_RECORD_IPV6_V1_SIZE;
  if (!output || output_capacity < required_size) {
    *out_len = required_size;
    return MESH_MGMT_ENDPOINT_RECORD_RESOURCE_EXHAUSTED;
  }
  family = (uint8_t)announcement->address_family;
  offset += mesh_mgmt_wire_write_tlv(output + offset, ENDPOINT_FIELD_RECORD_KIND, &record_kind, 1u);
  offset +=
      mesh_mgmt_wire_write_tlv(output + offset, ENDPOINT_FIELD_OWNER_NODE_ID,
                               announcement->owner_node_id, sizeof(announcement->owner_node_id));
  offset += mesh_mgmt_wire_write_tlv(output + offset, ENDPOINT_FIELD_TRANSPORT_PEER_ID,
                                     announcement->transport_peer_id,
                                     sizeof(announcement->transport_peer_id));
  offset += mesh_mgmt_wire_write_tlv(output + offset, ENDPOINT_FIELD_ADDRESS_FAMILY, &family, 1u);
  offset += mesh_mgmt_wire_write_tlv(output + offset, ENDPOINT_FIELD_ADDRESS, announcement->address,
                                     address_size);
  offset += write_u16_field(output + offset, ENDPOINT_FIELD_PORT, announcement->port);
  offset +=
      write_u64_field(output + offset, ENDPOINT_FIELD_RECORD_EPOCH, announcement->record_epoch);
  offset +=
      write_u64_field(output + offset, ENDPOINT_FIELD_EXPIRES_AT_MS, announcement->expires_at_ms);
  if (offset != required_size) {
    memset(output, 0, required_size);
    return MESH_MGMT_ENDPOINT_RECORD_INVALID_SCHEMA;
  }
  *out_len = required_size;
  return MESH_MGMT_ENDPOINT_RECORD_OK;
}

mesh_mgmt_endpoint_record_result_t
mesh_mgmt_endpoint_record_decode_v1(const uint8_t *payload, size_t payload_len,
                                    mesh_mgmt_endpoint_announcement_v1_t *out_announcement) {
  mesh_mgmt_tlv_reader_t reader;
  mesh_mgmt_tlv_view_t field;
  size_t expected_address_length;

  if (!out_announcement)
    return MESH_MGMT_ENDPOINT_RECORD_INVALID_ARG;
  memset(out_announcement, 0, sizeof(*out_announcement));
  if (!payload || (payload_len != MESH_MGMT_ENDPOINT_RECORD_IPV4_V1_SIZE &&
                   payload_len != MESH_MGMT_ENDPOINT_RECORD_IPV6_V1_SIZE))
    return MESH_MGMT_ENDPOINT_RECORD_INVALID_SCHEMA;
  mesh_mgmt_tlv_reader_init(&reader, payload, payload_len);
  if (!read_field(&reader, ENDPOINT_FIELD_RECORD_KIND, 1u, &field) ||
      field.value[0] != ENDPOINT_RECORD_KIND_V1)
    goto invalid_schema;
  if (!read_field(&reader, ENDPOINT_FIELD_OWNER_NODE_ID, 32u, &field))
    goto invalid_schema;
  memcpy(out_announcement->owner_node_id, field.value, 32u);
  if (!read_field(&reader, ENDPOINT_FIELD_TRANSPORT_PEER_ID, P2P_KEY_SIZE, &field))
    goto invalid_schema;
  memcpy(out_announcement->transport_peer_id, field.value, P2P_KEY_SIZE);
  if (!read_field(&reader, ENDPOINT_FIELD_ADDRESS_FAMILY, 1u, &field))
    goto invalid_schema;
  out_announcement->address_family = (mesh_mgmt_endpoint_address_family_t)field.value[0];
  expected_address_length = address_length(out_announcement->address_family);
  if (expected_address_length == 0u ||
      !read_field(&reader, ENDPOINT_FIELD_ADDRESS, expected_address_length, &field))
    goto invalid_schema;
  memcpy(out_announcement->address, field.value, expected_address_length);
  if (!read_field(&reader, ENDPOINT_FIELD_PORT, sizeof(uint16_t), &field))
    goto invalid_schema;
  out_announcement->port = mesh_mgmt_wire_read_u16(field.value);
  if (!read_field(&reader, ENDPOINT_FIELD_RECORD_EPOCH, sizeof(uint64_t), &field))
    goto invalid_schema;
  out_announcement->record_epoch = mesh_mgmt_wire_read_u64(field.value);
  if (!read_field(&reader, ENDPOINT_FIELD_EXPIRES_AT_MS, sizeof(uint64_t), &field))
    goto invalid_schema;
  out_announcement->expires_at_ms = mesh_mgmt_wire_read_u64(field.value);
  if (mesh_mgmt_tlv_reader_next(&reader, &field) != 0 || !announcement_is_valid(out_announcement))
    goto invalid_schema;
  return MESH_MGMT_ENDPOINT_RECORD_OK;

invalid_schema:
  memset(out_announcement, 0, sizeof(*out_announcement));
  return MESH_MGMT_ENDPOINT_RECORD_INVALID_SCHEMA;
}

mesh_mgmt_endpoint_record_result_t
mesh_mgmt_endpoint_record_verify_v1(const mesh_mgmt_endpoint_record_verify_input_v1_t *input,
                                    mesh_mgmt_endpoint_record_v1_t *out_record) {
  mesh_mgmt_verified_envelope_v1_t envelope;
  mesh_mgmt_certificate_v1_t certificate;
  mesh_mgmt_endpoint_announcement_v1_t announcement;
  mesh_mgmt_endpoint_record_result_t result;

  if (!out_record)
    return MESH_MGMT_ENDPOINT_RECORD_INVALID_ARG;
  memset(out_record, 0, sizeof(*out_record));
  if (!input || !input->frame || !input->certificate || !input->trusted_issuer_key ||
      !input->expected_mesh_id_hash || !input->expected_owner_node_id || input->now_ms == 0u ||
      input->max_ttl_ms == 0u || input->max_ttl_ms > MESH_MGMT_ENDPOINT_RECORD_MAX_TTL_MS)
    return MESH_MGMT_ENDPOINT_RECORD_INVALID_ARG;

  result =
      map_envelope_result(mesh_mgmt_envelope_verify_v1(input->frame, input->frame_len, &envelope));
  if (result != MESH_MGMT_ENDPOINT_RECORD_OK)
    return result;
  result = map_identity_result(mesh_mgmt_certificate_verify_v1(
      input->certificate, input->certificate_len, input->trusted_issuer_key,
      input->expected_mesh_id_hash, input->now_ms, &certificate));
  if (result != MESH_MGMT_ENDPOINT_RECORD_OK)
    return result;
  if (envelope.frame.kind != MESH_MGMT_KIND_MEMBERSHIP_DELTA || envelope.frame.flags != 0u ||
      envelope.header.forward_budget != 0u ||
      !bytes_are_zero(envelope.header.target_node_id, sizeof(envelope.header.target_node_id)))
    return MESH_MGMT_ENDPOINT_RECORD_INVALID_SCHEMA;
  if (envelope.header.issued_at_ms > input->now_ms ||
      envelope.header.expires_at_ms <= input->now_ms)
    return MESH_MGMT_ENDPOINT_RECORD_EXPIRED;
  if (envelope.header.expires_at_ms - envelope.header.issued_at_ms > input->max_ttl_ms)
    return MESH_MGMT_ENDPOINT_RECORD_EXPIRED;
  if (certificate.principal_type != MESH_MGMT_PRINCIPAL_NODE ||
      certificate.expires_at_ms < envelope.header.expires_at_ms ||
      !mesh_mgmt_crypto_equal_32(envelope.header.mesh_id_hash, input->expected_mesh_id_hash) ||
      !mesh_mgmt_crypto_equal_32(envelope.header.origin_node_id, input->expected_owner_node_id) ||
      !mesh_mgmt_crypto_equal_32(envelope.header.origin_node_id, certificate.managed_node_id) ||
      !mesh_mgmt_crypto_equal_32(envelope.header.origin_principal_key,
                                 certificate.management_key) ||
      envelope.header.certificate_serial != certificate.serial ||
      envelope.header.principal_epoch != certificate.principal_epoch)
    return MESH_MGMT_ENDPOINT_RECORD_AUTH_FAILED;
  result = mesh_mgmt_endpoint_record_decode_v1(envelope.frame.payload, envelope.frame.payload_len,
                                               &announcement);
  if (result != MESH_MGMT_ENDPOINT_RECORD_OK)
    return result;
  if (!mesh_mgmt_crypto_equal_32(announcement.owner_node_id, input->expected_owner_node_id) ||
      !mesh_mgmt_crypto_equal_32(announcement.transport_peer_id, certificate.transport_peer_id) ||
      announcement.expires_at_ms != envelope.header.expires_at_ms)
    return MESH_MGMT_ENDPOINT_RECORD_AUTH_FAILED;

  memcpy(out_record->transport_peer_id, announcement.transport_peer_id, P2P_KEY_SIZE);
  if (!address_to_host(&announcement, out_record->host)) {
    memset(out_record, 0, sizeof(*out_record));
    return MESH_MGMT_ENDPOINT_RECORD_ADDRESS_FAILURE;
  }
  out_record->port = announcement.port;
  out_record->source = MESH_MGMT_ENDPOINT_SOURCE_VERIFIED_RECORD;
  out_record->record_epoch = announcement.record_epoch;
  out_record->expires_at_ms = announcement.expires_at_ms;
  return MESH_MGMT_ENDPOINT_RECORD_OK;
}
