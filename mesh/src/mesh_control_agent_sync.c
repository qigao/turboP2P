#include "mesh_control_agent_sync.h"

#include "mesh_mgmt_wire.h"

#include <limits.h>
#include <string.h>

static const uint8_t MESH_CONTROL_AGENT_SYNC_MAGIC_V1[4] = {'T', 'S', 'Y', 'N'};
static const uint8_t MESH_CONTROL_AGENT_SYNC_HELLO_DOMAIN_V1[16] = {
    'T', 'P', '2', 'P', '-', 'A', 'G', 'E', 'N', 'T', '-', 'H', 'E', 'L', 'L', 'O'};

enum {
  SYNC_OFFSET_MAGIC = 0,
  SYNC_OFFSET_VERSION = 4,
  SYNC_OFFSET_KIND = 6,
  SYNC_OFFSET_FLAGS = 8,
  SYNC_OFFSET_STATUS = 12,
  SYNC_OFFSET_NODE_ID = 16,
  SYNC_OFFSET_SESSION_ID = 48,
  SYNC_OFFSET_SESSION_GENERATION = 64,
  SYNC_OFFSET_REQUEST_TOKEN = 72,
  SYNC_OFFSET_MESSAGE_ID = 80,
  SYNC_OFFSET_LEASE_GENERATION = 96,
  SYNC_OFFSET_SENT_AT = 104,
  SYNC_OFFSET_PAYLOAD_SIZE = 112,
  SYNC_OFFSET_PAYLOAD_DIGEST = 116,
  HELLO_OFFSET_CERTIFICATE_SERIAL = 0,
  HELLO_OFFSET_NOT_BEFORE = 8,
  HELLO_OFFSET_EXPIRES = 16,
  HELLO_OFFSET_NONCE = 24,
  HELLO_OFFSET_TLS_DIGEST = 56,
  HELLO_OFFSET_PUBLIC_KEY = 88,
  HELLO_OFFSET_SIGNATURE = 120,
  HELLO_SIGNED_SIZE = 16 + 2 + MESH_CONTROL_NODE_ID_SIZE +
                      MESH_CONTROL_ID_SIZE + 8 + 8 + 8 + 8 + 8 +
                      MESH_CONTROL_AGENT_SYNC_NONCE_SIZE_V1 +
                      MESH_CONTROL_DIGEST_SIZE +
                      MESH_MGMT_ED25519_PUBLIC_KEY_SIZE
};

static int bytes_zero(const uint8_t *bytes, size_t size) {
  size_t index;
  uint8_t value = 0u;
  if (!bytes) return 1;
  for (index = 0u; index < size; ++index) value |= bytes[index];
  return value == 0u;
}

static int kind_valid(mesh_control_agent_sync_kind_v1_t kind) {
  return kind >= MESH_CONTROL_AGENT_SYNC_HELLO &&
         kind <= MESH_CONTROL_AGENT_SYNC_ERROR;
}

static int message_shape_valid(const mesh_control_agent_sync_message_v1_t *message) {
  int empty_message_id;
  if (!message || !kind_valid(message->kind) ||
      bytes_zero(message->node_id, sizeof(message->node_id)) ||
      bytes_zero(message->session_id, sizeof(message->session_id)) ||
      message->request_token == 0u || message->sent_at_ms == 0u ||
      message->payload_size > MESH_CONTROL_AGENT_SYNC_MAX_PAYLOAD_V1 ||
      (message->payload_size != 0u && !message->payload)) {
    return 0;
  }
  empty_message_id = bytes_zero(message->message_id, sizeof(message->message_id));
  switch (message->kind) {
    case MESH_CONTROL_AGENT_SYNC_HELLO:
      return message->session_generation == 0u &&
             message->lease_generation == 0u && empty_message_id &&
             message->payload_size == MESH_CONTROL_AGENT_SYNC_HELLO_PAYLOAD_SIZE_V1;
    case MESH_CONTROL_AGENT_SYNC_HELLO_ACK:
    case MESH_CONTROL_AGENT_SYNC_CLAIM_REQUEST:
    case MESH_CONTROL_AGENT_SYNC_HEARTBEAT:
    case MESH_CONTROL_AGENT_SYNC_CLOSE:
      return message->session_generation != 0u &&
             message->lease_generation == 0u && empty_message_id &&
             message->payload_size == 0u;
    case MESH_CONTROL_AGENT_SYNC_COMMAND:
    case MESH_CONTROL_AGENT_SYNC_RECEIPT:
      return message->session_generation != 0u &&
             message->lease_generation != 0u && !empty_message_id &&
             message->payload_size != 0u;
    case MESH_CONTROL_AGENT_SYNC_ERROR:
      return message->session_generation != 0u &&
             message->lease_generation == 0u && empty_message_id;
    default:
      return 0;
  }
}

static mesh_control_agent_sync_result_t payload_digest(
    const uint8_t *payload, size_t payload_size,
    uint8_t digest[MESH_CONTROL_DIGEST_SIZE]) {
  memset(digest, 0, MESH_CONTROL_DIGEST_SIZE);
  if (payload_size == 0u) return MESH_CONTROL_AGENT_SYNC_OK;
  return mesh_mgmt_blake2b_256(payload, payload_size, digest) ==
                 MESH_MGMT_CRYPTO_OK
             ? MESH_CONTROL_AGENT_SYNC_OK
             : MESH_CONTROL_AGENT_SYNC_AUTH_FAILED;
}

mesh_control_agent_sync_result_t mesh_control_agent_sync_encode_v1(
    const mesh_control_agent_sync_message_v1_t *message, uint8_t *output,
    size_t output_capacity, size_t *out_size) {
  uint8_t digest[MESH_CONTROL_DIGEST_SIZE];
  size_t required;
  if (!out_size) return MESH_CONTROL_AGENT_SYNC_INVALID_ARG;
  *out_size = 0u;
  if (!message_shape_valid(message)) return MESH_CONTROL_AGENT_SYNC_INVALID_ARG;
  required = MESH_CONTROL_AGENT_SYNC_HEADER_SIZE_V1 + message->payload_size;
  *out_size = required;
  if (!output || output_capacity < required)
    return MESH_CONTROL_AGENT_SYNC_RESOURCE_EXHAUSTED;
  if (payload_digest(message->payload, message->payload_size, digest) !=
      MESH_CONTROL_AGENT_SYNC_OK)
    return MESH_CONTROL_AGENT_SYNC_AUTH_FAILED;
  memset(output, 0, required);
  memcpy(output + SYNC_OFFSET_MAGIC, MESH_CONTROL_AGENT_SYNC_MAGIC_V1,
         sizeof(MESH_CONTROL_AGENT_SYNC_MAGIC_V1));
  mesh_mgmt_wire_write_u16(output + SYNC_OFFSET_VERSION,
                           MESH_CONTROL_AGENT_SYNC_VERSION_V1);
  mesh_mgmt_wire_write_u16(output + SYNC_OFFSET_KIND, (uint16_t)message->kind);
  mesh_mgmt_wire_write_u32(output + SYNC_OFFSET_FLAGS, message->flags);
  mesh_mgmt_wire_write_u32(output + SYNC_OFFSET_STATUS, (uint32_t)message->status);
  memcpy(output + SYNC_OFFSET_NODE_ID, message->node_id, sizeof(message->node_id));
  memcpy(output + SYNC_OFFSET_SESSION_ID, message->session_id,
         sizeof(message->session_id));
  mesh_mgmt_wire_write_u64(output + SYNC_OFFSET_SESSION_GENERATION,
                           message->session_generation);
  mesh_mgmt_wire_write_u64(output + SYNC_OFFSET_REQUEST_TOKEN,
                           message->request_token);
  memcpy(output + SYNC_OFFSET_MESSAGE_ID, message->message_id,
         sizeof(message->message_id));
  mesh_mgmt_wire_write_u64(output + SYNC_OFFSET_LEASE_GENERATION,
                           message->lease_generation);
  mesh_mgmt_wire_write_u64(output + SYNC_OFFSET_SENT_AT, message->sent_at_ms);
  mesh_mgmt_wire_write_u32(output + SYNC_OFFSET_PAYLOAD_SIZE,
                           (uint32_t)message->payload_size);
  memcpy(output + SYNC_OFFSET_PAYLOAD_DIGEST, digest, sizeof(digest));
  if (message->payload_size != 0u)
    memcpy(output + MESH_CONTROL_AGENT_SYNC_HEADER_SIZE_V1, message->payload,
           message->payload_size);
  return MESH_CONTROL_AGENT_SYNC_OK;
}

mesh_control_agent_sync_result_t mesh_control_agent_sync_decode_v1(
    const uint8_t *frame, size_t frame_size,
    mesh_control_agent_sync_message_v1_t *out_message) {
  mesh_control_agent_sync_message_v1_t decoded;
  uint8_t digest[MESH_CONTROL_DIGEST_SIZE];
  uint32_t payload_size;
  if (!frame || !out_message ||
      frame_size < MESH_CONTROL_AGENT_SYNC_HEADER_SIZE_V1 ||
      frame_size > MESH_CONTROL_MAX_FRAME_SIZE_V1)
    return MESH_CONTROL_AGENT_SYNC_INVALID_ARG;
  memset(out_message, 0, sizeof(*out_message));
  if (memcmp(frame + SYNC_OFFSET_MAGIC, MESH_CONTROL_AGENT_SYNC_MAGIC_V1,
             sizeof(MESH_CONTROL_AGENT_SYNC_MAGIC_V1)) != 0 ||
      mesh_mgmt_wire_read_u16(frame + SYNC_OFFSET_VERSION) !=
          MESH_CONTROL_AGENT_SYNC_VERSION_V1)
    return MESH_CONTROL_AGENT_SYNC_INVALID_SCHEMA;
  payload_size = mesh_mgmt_wire_read_u32(frame + SYNC_OFFSET_PAYLOAD_SIZE);
  if ((size_t)payload_size > MESH_CONTROL_AGENT_SYNC_MAX_PAYLOAD_V1 ||
      frame_size != MESH_CONTROL_AGENT_SYNC_HEADER_SIZE_V1 +
                        (size_t)payload_size)
    return MESH_CONTROL_AGENT_SYNC_INVALID_SCHEMA;
  memset(&decoded, 0, sizeof(decoded));
  decoded.kind = (mesh_control_agent_sync_kind_v1_t)mesh_mgmt_wire_read_u16(
      frame + SYNC_OFFSET_KIND);
  decoded.flags = mesh_mgmt_wire_read_u32(frame + SYNC_OFFSET_FLAGS);
  decoded.status = (int32_t)mesh_mgmt_wire_read_u32(frame + SYNC_OFFSET_STATUS);
  memcpy(decoded.node_id, frame + SYNC_OFFSET_NODE_ID, sizeof(decoded.node_id));
  memcpy(decoded.session_id, frame + SYNC_OFFSET_SESSION_ID,
         sizeof(decoded.session_id));
  decoded.session_generation = mesh_mgmt_wire_read_u64(
      frame + SYNC_OFFSET_SESSION_GENERATION);
  decoded.request_token = mesh_mgmt_wire_read_u64(
      frame + SYNC_OFFSET_REQUEST_TOKEN);
  memcpy(decoded.message_id, frame + SYNC_OFFSET_MESSAGE_ID,
         sizeof(decoded.message_id));
  decoded.lease_generation = mesh_mgmt_wire_read_u64(
      frame + SYNC_OFFSET_LEASE_GENERATION);
  decoded.sent_at_ms = mesh_mgmt_wire_read_u64(frame + SYNC_OFFSET_SENT_AT);
  memcpy(decoded.payload_digest, frame + SYNC_OFFSET_PAYLOAD_DIGEST,
         sizeof(decoded.payload_digest));
  decoded.payload = payload_size == 0u
                        ? NULL
                        : frame + MESH_CONTROL_AGENT_SYNC_HEADER_SIZE_V1;
  decoded.payload_size = payload_size;
  if (!message_shape_valid(&decoded))
    return MESH_CONTROL_AGENT_SYNC_INVALID_SCHEMA;
  if (payload_digest(decoded.payload, decoded.payload_size, digest) !=
      MESH_CONTROL_AGENT_SYNC_OK)
    return MESH_CONTROL_AGENT_SYNC_AUTH_FAILED;
  if (!mesh_mgmt_crypto_equal_32(digest, decoded.payload_digest))
    return MESH_CONTROL_AGENT_SYNC_DIGEST_MISMATCH;
  *out_message = decoded;
  return MESH_CONTROL_AGENT_SYNC_OK;
}

static size_t hello_signing_input(
    const mesh_control_agent_sync_message_v1_t *message,
    const mesh_control_agent_sync_hello_v1_t *hello, uint8_t *output) {
  size_t offset = 0u;
  memcpy(output + offset, MESH_CONTROL_AGENT_SYNC_HELLO_DOMAIN_V1,
         sizeof(MESH_CONTROL_AGENT_SYNC_HELLO_DOMAIN_V1));
  offset += sizeof(MESH_CONTROL_AGENT_SYNC_HELLO_DOMAIN_V1);
  mesh_mgmt_wire_write_u16(output + offset, MESH_CONTROL_AGENT_SYNC_VERSION_V1);
  offset += 2u;
  memcpy(output + offset, message->node_id, sizeof(message->node_id));
  offset += sizeof(message->node_id);
  memcpy(output + offset, message->session_id, sizeof(message->session_id));
  offset += sizeof(message->session_id);
  mesh_mgmt_wire_write_u64(output + offset, message->request_token);
  offset += 8u;
  mesh_mgmt_wire_write_u64(output + offset, message->sent_at_ms);
  offset += 8u;
  mesh_mgmt_wire_write_u64(output + offset, hello->certificate_serial);
  offset += 8u;
  mesh_mgmt_wire_write_u64(output + offset, hello->not_before_ms);
  offset += 8u;
  mesh_mgmt_wire_write_u64(output + offset, hello->expires_at_ms);
  offset += 8u;
  memcpy(output + offset, hello->nonce, sizeof(hello->nonce));
  offset += sizeof(hello->nonce);
  memcpy(output + offset, hello->tls_certificate_sha256,
         sizeof(hello->tls_certificate_sha256));
  offset += sizeof(hello->tls_certificate_sha256);
  memcpy(output + offset, hello->management_public_key,
         sizeof(hello->management_public_key));
  offset += sizeof(hello->management_public_key);
  return offset;
}

mesh_control_agent_sync_result_t mesh_control_agent_sync_hello_sign_v1(
    const mesh_control_agent_sync_message_v1_t *hello_message,
    const uint8_t private_key[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE],
    mesh_control_agent_sync_hello_v1_t *hello) {
  uint8_t input[HELLO_SIGNED_SIZE];
  size_t input_size;
  if (!hello_message || !private_key || !hello ||
      hello_message->kind != MESH_CONTROL_AGENT_SYNC_HELLO ||
      hello_message->session_generation != 0u ||
      hello_message->request_token == 0u || hello_message->sent_at_ms == 0u ||
      bytes_zero(hello_message->node_id, sizeof(hello_message->node_id)) ||
      bytes_zero(hello_message->session_id, sizeof(hello_message->session_id)) ||
      hello->certificate_serial == 0u || hello->not_before_ms == 0u ||
      hello->expires_at_ms <= hello->not_before_ms ||
      bytes_zero(hello->nonce, sizeof(hello->nonce)) ||
      bytes_zero(hello->tls_certificate_sha256,
                 sizeof(hello->tls_certificate_sha256)) ||
      bytes_zero(hello->management_public_key,
                 sizeof(hello->management_public_key)))
    return MESH_CONTROL_AGENT_SYNC_INVALID_ARG;
  input_size = hello_signing_input(hello_message, hello, input);
  if (input_size != sizeof(input)) {
    mesh_mgmt_crypto_wipe(input, sizeof(input));
    return MESH_CONTROL_AGENT_SYNC_INVALID_SCHEMA;
  }
  if (mesh_mgmt_ed25519_sign(private_key, input, input_size,
                             hello->signature) != MESH_MGMT_CRYPTO_OK) {
    mesh_mgmt_crypto_wipe(input, sizeof(input));
    memset(hello->signature, 0, sizeof(hello->signature));
    return MESH_CONTROL_AGENT_SYNC_AUTH_FAILED;
  }
  mesh_mgmt_crypto_wipe(input, sizeof(input));
  return MESH_CONTROL_AGENT_SYNC_OK;
}

mesh_control_agent_sync_result_t mesh_control_agent_sync_hello_encode_v1(
    const mesh_control_agent_sync_hello_v1_t *hello, uint8_t *output,
    size_t output_capacity, size_t *out_size) {
  if (!out_size) return MESH_CONTROL_AGENT_SYNC_INVALID_ARG;
  *out_size = MESH_CONTROL_AGENT_SYNC_HELLO_PAYLOAD_SIZE_V1;
  if (!hello) return MESH_CONTROL_AGENT_SYNC_INVALID_ARG;
  if (!output || output_capacity < MESH_CONTROL_AGENT_SYNC_HELLO_PAYLOAD_SIZE_V1)
    return MESH_CONTROL_AGENT_SYNC_RESOURCE_EXHAUSTED;
  mesh_mgmt_wire_write_u64(output + HELLO_OFFSET_CERTIFICATE_SERIAL,
                           hello->certificate_serial);
  mesh_mgmt_wire_write_u64(output + HELLO_OFFSET_NOT_BEFORE,
                           hello->not_before_ms);
  mesh_mgmt_wire_write_u64(output + HELLO_OFFSET_EXPIRES, hello->expires_at_ms);
  memcpy(output + HELLO_OFFSET_NONCE, hello->nonce, sizeof(hello->nonce));
  memcpy(output + HELLO_OFFSET_TLS_DIGEST, hello->tls_certificate_sha256,
         sizeof(hello->tls_certificate_sha256));
  memcpy(output + HELLO_OFFSET_PUBLIC_KEY, hello->management_public_key,
         sizeof(hello->management_public_key));
  memcpy(output + HELLO_OFFSET_SIGNATURE, hello->signature,
         sizeof(hello->signature));
  return MESH_CONTROL_AGENT_SYNC_OK;
}

mesh_control_agent_sync_result_t mesh_control_agent_sync_hello_decode_v1(
    const uint8_t *payload, size_t payload_size,
    mesh_control_agent_sync_hello_v1_t *out_hello) {
  if (!payload || !out_hello ||
      payload_size != MESH_CONTROL_AGENT_SYNC_HELLO_PAYLOAD_SIZE_V1)
    return MESH_CONTROL_AGENT_SYNC_INVALID_ARG;
  memset(out_hello, 0, sizeof(*out_hello));
  out_hello->certificate_serial = mesh_mgmt_wire_read_u64(
      payload + HELLO_OFFSET_CERTIFICATE_SERIAL);
  out_hello->not_before_ms = mesh_mgmt_wire_read_u64(
      payload + HELLO_OFFSET_NOT_BEFORE);
  out_hello->expires_at_ms = mesh_mgmt_wire_read_u64(
      payload + HELLO_OFFSET_EXPIRES);
  memcpy(out_hello->nonce, payload + HELLO_OFFSET_NONCE,
         sizeof(out_hello->nonce));
  memcpy(out_hello->tls_certificate_sha256, payload + HELLO_OFFSET_TLS_DIGEST,
         sizeof(out_hello->tls_certificate_sha256));
  memcpy(out_hello->management_public_key, payload + HELLO_OFFSET_PUBLIC_KEY,
         sizeof(out_hello->management_public_key));
  memcpy(out_hello->signature, payload + HELLO_OFFSET_SIGNATURE,
         sizeof(out_hello->signature));
  return MESH_CONTROL_AGENT_SYNC_OK;
}

mesh_control_agent_sync_result_t mesh_control_agent_sync_hello_verify_v1(
    const mesh_control_agent_sync_message_v1_t *hello_message,
    const mesh_control_agent_sync_hello_v1_t *hello,
    const mesh_control_agent_sync_hello_policy_v1_t *policy) {
  uint8_t input[HELLO_SIGNED_SIZE];
  size_t input_size;
  uint64_t latest_allowed_sent;
  if (!hello_message || !hello || !policy ||
      hello_message->kind != MESH_CONTROL_AGENT_SYNC_HELLO ||
      policy->minimum_certificate_serial == 0u ||
      policy->maximum_certificate_serial < policy->minimum_certificate_serial ||
      policy->identity_policy_generation == 0u ||
      policy->now_ms == 0u || policy->maximum_hello_lifetime_ms == 0u ||
      bytes_zero(policy->expected_node_id, sizeof(policy->expected_node_id)) ||
      bytes_zero(policy->expected_management_public_key,
                 sizeof(policy->expected_management_public_key)) ||
      bytes_zero(policy->actual_tls_certificate_sha256,
                 sizeof(policy->actual_tls_certificate_sha256)))
    return MESH_CONTROL_AGENT_SYNC_INVALID_ARG;
  if (!mesh_mgmt_crypto_equal_32(hello_message->node_id,
                                 policy->expected_node_id) ||
      !mesh_mgmt_crypto_equal_32(hello->management_public_key,
                                 policy->expected_management_public_key) ||
      !mesh_mgmt_crypto_equal_32(hello->tls_certificate_sha256,
                                 policy->actual_tls_certificate_sha256) ||
      hello->certificate_serial < policy->minimum_certificate_serial ||
      hello->certificate_serial > policy->maximum_certificate_serial ||
      bytes_zero(hello->nonce, sizeof(hello->nonce)))
    return MESH_CONTROL_AGENT_SYNC_AUTH_FAILED;
  if (hello->not_before_ms == 0u || hello->expires_at_ms <= hello->not_before_ms ||
      hello->expires_at_ms - hello->not_before_ms >
          policy->maximum_hello_lifetime_ms)
    return MESH_CONTROL_AGENT_SYNC_EXPIRED;
  latest_allowed_sent = policy->now_ms;
  if (UINT64_MAX - latest_allowed_sent < policy->maximum_clock_skew_ms)
    latest_allowed_sent = UINT64_MAX;
  else
    latest_allowed_sent += policy->maximum_clock_skew_ms;
  if (hello_message->sent_at_ms > latest_allowed_sent ||
      policy->now_ms < hello->not_before_ms ||
      policy->now_ms >= hello->expires_at_ms ||
      hello_message->sent_at_ms < hello->not_before_ms ||
      hello_message->sent_at_ms >= hello->expires_at_ms ||
      policy->now_ms - (policy->now_ms > hello_message->sent_at_ms
                            ? hello_message->sent_at_ms
                            : policy->now_ms) > policy->maximum_clock_skew_ms)
    return MESH_CONTROL_AGENT_SYNC_EXPIRED;
  input_size = hello_signing_input(hello_message, hello, input);
  if (input_size != sizeof(input)) {
    mesh_mgmt_crypto_wipe(input, sizeof(input));
    return MESH_CONTROL_AGENT_SYNC_INVALID_SCHEMA;
  }
  if (mesh_mgmt_ed25519_verify(policy->expected_management_public_key, input,
                               input_size, hello->signature) !=
      MESH_MGMT_CRYPTO_OK) {
    mesh_mgmt_crypto_wipe(input, sizeof(input));
    return MESH_CONTROL_AGENT_SYNC_AUTH_FAILED;
  }
  mesh_mgmt_crypto_wipe(input, sizeof(input));
  return MESH_CONTROL_AGENT_SYNC_OK;
}
