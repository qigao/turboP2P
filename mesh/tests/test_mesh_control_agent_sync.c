#include "mesh_control_agent_sync.h"
#include "tinytest.h"

#include <string.h>

static const uint8_t TEST_PRIVATE_KEY[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60};

static void fill_bytes(uint8_t *output, size_t size, uint8_t seed) {
  size_t index;
  for (index = 0u; index < size; ++index)
    output[index] = (uint8_t)(seed + index);
}

static void make_hello(mesh_control_agent_sync_message_v1_t *message,
                       mesh_control_agent_sync_hello_v1_t *hello,
                       uint8_t payload[MESH_CONTROL_AGENT_SYNC_HELLO_PAYLOAD_SIZE_V1]) {
  size_t payload_size = 0u;
  memset(message, 0, sizeof(*message));
  memset(hello, 0, sizeof(*hello));
  message->kind = MESH_CONTROL_AGENT_SYNC_HELLO;
  message->request_token = 9u;
  message->sent_at_ms = 1000u;
  message->payload = payload;
  message->payload_size = MESH_CONTROL_AGENT_SYNC_HELLO_PAYLOAD_SIZE_V1;
  fill_bytes(message->node_id, sizeof(message->node_id), 0x10u);
  fill_bytes(message->session_id, sizeof(message->session_id), 0x40u);
  hello->certificate_serial = 7u;
  hello->not_before_ms = 900u;
  hello->expires_at_ms = 1900u;
  fill_bytes(hello->nonce, sizeof(hello->nonce), 0x50u);
  fill_bytes(hello->tls_certificate_sha256,
             sizeof(hello->tls_certificate_sha256), 0x70u);
  check_int_eq(mesh_mgmt_ed25519_public_from_private(
                   TEST_PRIVATE_KEY, hello->management_public_key),
               MESH_MGMT_CRYPTO_OK);
  check_int_eq(mesh_control_agent_sync_hello_sign_v1(
                   message, TEST_PRIVATE_KEY, hello),
               MESH_CONTROL_AGENT_SYNC_OK);
  check_int_eq(mesh_control_agent_sync_hello_encode_v1(
                   hello, payload,
                   MESH_CONTROL_AGENT_SYNC_HELLO_PAYLOAD_SIZE_V1,
                   &payload_size),
               MESH_CONTROL_AGENT_SYNC_OK);
  check_uint_eq(payload_size, MESH_CONTROL_AGENT_SYNC_HELLO_PAYLOAD_SIZE_V1);
}

static void make_policy(
    mesh_control_agent_sync_hello_policy_v1_t *policy,
    const mesh_control_agent_sync_message_v1_t *message,
    const mesh_control_agent_sync_hello_v1_t *hello) {
  memset(policy, 0, sizeof(*policy));
  memcpy(policy->expected_node_id, message->node_id,
         sizeof(policy->expected_node_id));
  memcpy(policy->expected_management_public_key,
         hello->management_public_key,
         sizeof(policy->expected_management_public_key));
  memcpy(policy->actual_tls_certificate_sha256,
         hello->tls_certificate_sha256,
         sizeof(policy->actual_tls_certificate_sha256));
  policy->minimum_certificate_serial = 7u;
  policy->maximum_certificate_serial = 8u;
  policy->identity_policy_generation = 1u;
  policy->now_ms = 1001u;
  policy->maximum_clock_skew_ms = 100u;
  policy->maximum_hello_lifetime_ms = 2000u;
}

static void test_signed_hello_round_trips_and_verifies(void) {
  mesh_control_agent_sync_message_v1_t message;
  mesh_control_agent_sync_message_v1_t decoded;
  mesh_control_agent_sync_hello_v1_t hello;
  mesh_control_agent_sync_hello_v1_t decoded_hello;
  mesh_control_agent_sync_hello_policy_v1_t policy;
  uint8_t payload[MESH_CONTROL_AGENT_SYNC_HELLO_PAYLOAD_SIZE_V1];
  uint8_t frame[MESH_CONTROL_AGENT_SYNC_HEADER_SIZE_V1 +
                MESH_CONTROL_AGENT_SYNC_HELLO_PAYLOAD_SIZE_V1];
  size_t frame_size = 0u;

  make_hello(&message, &hello, payload);
  check_int_eq(mesh_control_agent_sync_encode_v1(
                   &message, frame, sizeof(frame), &frame_size),
               MESH_CONTROL_AGENT_SYNC_OK);
  check_uint_eq(frame_size, sizeof(frame));
  check_int_eq(mesh_control_agent_sync_decode_v1(frame, frame_size, &decoded),
               MESH_CONTROL_AGENT_SYNC_OK);
  check_mem_eq(decoded.node_id, message.node_id, sizeof(message.node_id));
  check_mem_eq(decoded.session_id, message.session_id,
               sizeof(message.session_id));
  check_int_eq(mesh_control_agent_sync_hello_decode_v1(
                   decoded.payload, decoded.payload_size, &decoded_hello),
               MESH_CONTROL_AGENT_SYNC_OK);
  make_policy(&policy, &decoded, &decoded_hello);
  check_int_eq(mesh_control_agent_sync_hello_verify_v1(
                   &decoded, &decoded_hello, &policy),
               MESH_CONTROL_AGENT_SYNC_OK);
}

static void test_hello_rejects_tls_identity_and_registry_mismatch(void) {
  mesh_control_agent_sync_message_v1_t message;
  mesh_control_agent_sync_hello_v1_t hello;
  mesh_control_agent_sync_hello_policy_v1_t policy;
  uint8_t payload[MESH_CONTROL_AGENT_SYNC_HELLO_PAYLOAD_SIZE_V1];

  make_hello(&message, &hello, payload);
  make_policy(&policy, &message, &hello);
  policy.actual_tls_certificate_sha256[0] ^= 1u;
  check_int_eq(mesh_control_agent_sync_hello_verify_v1(
                   &message, &hello, &policy),
               MESH_CONTROL_AGENT_SYNC_AUTH_FAILED);
  make_policy(&policy, &message, &hello);
  policy.expected_node_id[0] ^= 1u;
  check_int_eq(mesh_control_agent_sync_hello_verify_v1(
                   &message, &hello, &policy),
               MESH_CONTROL_AGENT_SYNC_AUTH_FAILED);
  make_policy(&policy, &message, &hello);
  policy.minimum_certificate_serial = 8u;
  check_int_eq(mesh_control_agent_sync_hello_verify_v1(
                   &message, &hello, &policy),
               MESH_CONTROL_AGENT_SYNC_AUTH_FAILED);
}

static void test_hello_rejects_expiry_and_signature_tampering(void) {
  mesh_control_agent_sync_message_v1_t message;
  mesh_control_agent_sync_hello_v1_t hello;
  mesh_control_agent_sync_hello_policy_v1_t policy;
  uint8_t payload[MESH_CONTROL_AGENT_SYNC_HELLO_PAYLOAD_SIZE_V1];

  make_hello(&message, &hello, payload);
  make_policy(&policy, &message, &hello);
  policy.now_ms = hello.expires_at_ms;
  check_int_eq(mesh_control_agent_sync_hello_verify_v1(
                   &message, &hello, &policy),
               MESH_CONTROL_AGENT_SYNC_EXPIRED);
  make_policy(&policy, &message, &hello);
  hello.signature[0] ^= 1u;
  check_int_eq(mesh_control_agent_sync_hello_verify_v1(
                   &message, &hello, &policy),
               MESH_CONTROL_AGENT_SYNC_AUTH_FAILED);
}

static void test_command_requires_both_fencing_generations(void) {
  static const uint8_t command[] = {1u, 2u, 3u};
  mesh_control_agent_sync_message_v1_t message;
  uint8_t output[256];
  size_t output_size = 0u;

  memset(&message, 0, sizeof(message));
  message.kind = MESH_CONTROL_AGENT_SYNC_COMMAND;
  message.session_generation = 4u;
  message.lease_generation = 5u;
  message.request_token = 6u;
  message.sent_at_ms = 7u;
  message.payload = command;
  message.payload_size = sizeof(command);
  fill_bytes(message.node_id, sizeof(message.node_id), 0x10u);
  fill_bytes(message.session_id, sizeof(message.session_id), 0x40u);
  fill_bytes(message.message_id, sizeof(message.message_id), 0x60u);
  check_int_eq(mesh_control_agent_sync_encode_v1(
                   &message, output, sizeof(output), &output_size),
               MESH_CONTROL_AGENT_SYNC_OK);
  message.session_generation = 0u;
  check_int_eq(mesh_control_agent_sync_encode_v1(
                   &message, output, sizeof(output), &output_size),
               MESH_CONTROL_AGENT_SYNC_INVALID_ARG);
  message.session_generation = 4u;
  message.lease_generation = 0u;
  check_int_eq(mesh_control_agent_sync_encode_v1(
                   &message, output, sizeof(output), &output_size),
               MESH_CONTROL_AGENT_SYNC_INVALID_ARG);
}

static void test_frame_tampering_is_detected(void) {
  mesh_control_agent_sync_message_v1_t message;
  mesh_control_agent_sync_message_v1_t decoded;
  mesh_control_agent_sync_hello_v1_t hello;
  uint8_t payload[MESH_CONTROL_AGENT_SYNC_HELLO_PAYLOAD_SIZE_V1];
  uint8_t frame[MESH_CONTROL_AGENT_SYNC_HEADER_SIZE_V1 +
                MESH_CONTROL_AGENT_SYNC_HELLO_PAYLOAD_SIZE_V1];
  size_t frame_size = 0u;

  make_hello(&message, &hello, payload);
  check_int_eq(mesh_control_agent_sync_encode_v1(
                   &message, frame, sizeof(frame), &frame_size),
               MESH_CONTROL_AGENT_SYNC_OK);
  frame[frame_size - 1u] ^= 1u;
  check_int_eq(mesh_control_agent_sync_decode_v1(frame, frame_size, &decoded),
               MESH_CONTROL_AGENT_SYNC_DIGEST_MISMATCH);
}

spec("mesh agent Controller sync protocol") {
  describe("mTLS identity and online fencing") {
    it("round trips and verifies a certificate-bound signed HELLO") {
      test_signed_hello_round_trips_and_verifies();
    }
    it("rejects TLS, registry and serial mismatches") {
      test_hello_rejects_tls_identity_and_registry_mismatch();
    }
    it("rejects expired or signature-tampered HELLO messages") {
      test_hello_rejects_expiry_and_signature_tampering();
    }
    it("requires session and lease generations for commands") {
      test_command_requires_both_fencing_generations();
    }
    it("detects frame payload tampering") {
      test_frame_tampering_is_detected();
    }
  }
}
