#include <tinytest.h>

#include "mesh_mgmt_peer_signer.h"

#include <string.h>

static const uint8_t ROOT_PRIVATE_KEY[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};

static const uint8_t MANAGEMENT_PRIVATE_KEY[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
};

#define TEST_NOW_MS 1500u
#define TEST_CERT_SERIAL 42u
#define TEST_PRINCIPAL_EPOCH 7u
#define TEST_INCARNATION 3u
#define TEST_FIRST_SEQUENCE 11u
#define TEST_FRAME_TTL_MS 200u

typedef struct {
  uint64_t now_ms;
  int random_result;
  size_t random_calls;
} signer_callbacks_t;

typedef struct {
  signer_callbacks_t callbacks;
  mesh_mgmt_peer_signer_config_v1_t config;
} signer_fixture_t;

static void fill_bytes(uint8_t *bytes, size_t length, uint8_t first) {
  size_t index;
  for (index = 0u; index < length; index++)
    bytes[index] = (uint8_t)(first + index);
}

static uint64_t test_now_ms(void *context) { return ((signer_callbacks_t *)context)->now_ms; }

static int test_random_bytes(void *context, uint8_t *output, size_t output_len) {
  signer_callbacks_t *callbacks = (signer_callbacks_t *)context;
  uint8_t first = (uint8_t)(0x40u + callbacks->random_calls * 0x10u);

  callbacks->random_calls++;
  if (callbacks->random_result != 0)
    return callbacks->random_result;
  fill_bytes(output, output_len, first);
  return 0;
}

static int zero_random_bytes(void *context, uint8_t *output, size_t output_len) {
  (void)context;
  memset(output, 0, output_len);
  return 0;
}

static void prepare_fixture(signer_fixture_t *fixture) {
  mesh_mgmt_certificate_claims_v1_t claims;
  uint8_t management_public_key[32];
  size_t certificate_len = 0u;

  memset(fixture, 0, sizeof(*fixture));
  memset(&claims, 0, sizeof(claims));
  fixture->callbacks.now_ms = TEST_NOW_MS;
  memcpy(fixture->config.private_key, MANAGEMENT_PRIVATE_KEY, sizeof(fixture->config.private_key));
  check_int_eq(
      mesh_mgmt_ed25519_public_from_private(ROOT_PRIVATE_KEY, fixture->config.trusted_issuer_key),
      MESH_MGMT_CRYPTO_OK);
  check_int_eq(mesh_mgmt_ed25519_public_from_private(MANAGEMENT_PRIVATE_KEY, management_public_key),
               MESH_MGMT_CRYPTO_OK);
  fill_bytes(fixture->config.expected_mesh_id_hash, sizeof(fixture->config.expected_mesh_id_hash),
             0x20u);
  fill_bytes(fixture->config.local_transport_peer_id,
             sizeof(fixture->config.local_transport_peer_id), 0x50u);

  claims.principal_type = MESH_MGMT_PRINCIPAL_NODE;
  memcpy(claims.management_key, management_public_key, sizeof(claims.management_key));
  memcpy(claims.transport_peer_id, fixture->config.local_transport_peer_id,
         sizeof(claims.transport_peer_id));
  fill_bytes(claims.managed_node_id, sizeof(claims.managed_node_id), 0x80u);
  memcpy(claims.mesh_id_hash, fixture->config.expected_mesh_id_hash, sizeof(claims.mesh_id_hash));
  claims.roles = MESH_MGMT_ROLE_OBSERVER | MESH_MGMT_ROLE_OPERATOR;
  claims.not_before_ms = 1000u;
  claims.expires_at_ms = 3000u;
  claims.serial = TEST_CERT_SERIAL;
  claims.principal_epoch = TEST_PRINCIPAL_EPOCH;
  check_int_eq(
      mesh_mgmt_certificate_issue_v1(&claims, ROOT_PRIVATE_KEY, fixture->config.hello.certificate,
                                     sizeof(fixture->config.hello.certificate), &certificate_len),
      MESH_MGMT_IDENTITY_OK);
  check_size_eq(certificate_len, MESH_MGMT_CERTIFICATE_V1_SIZE);

  fixture->config.hello.major = MESH_MGMT_MAJOR_V1;
  fixture->config.hello.min_minor = MESH_MGMT_MINOR_V1;
  fixture->config.hello.max_minor = MESH_MGMT_MINOR_V1;
  fixture->config.hello.features = MESH_MGMT_FEATURE_MEMBERSHIP | MESH_MGMT_FEATURE_ANTI_ENTROPY;
  fixture->config.hello.platform = MESH_MGMT_PLATFORM_LINUX;
  memcpy(fixture->config.hello.build_version, "signer-test", 11u);
  fixture->config.hello.build_version_len = 11u;
  check_int_eq(mesh_mgmt_blake2b_256(fixture->config.trusted_issuer_key,
                                     sizeof(fixture->config.trusted_issuer_key),
                                     fixture->config.hello.issuer_chain_hash),
               MESH_MGMT_CRYPTO_OK);
  fixture->config.hello.principal_type = MESH_MGMT_PRINCIPAL_NODE;
  memcpy(fixture->config.hello.management_key, management_public_key,
         sizeof(fixture->config.hello.management_key));
  memcpy(fixture->config.hello.managed_node_id, claims.managed_node_id,
         sizeof(fixture->config.hello.managed_node_id));
  fill_bytes(fixture->config.hello.connection_id, sizeof(fixture->config.hello.connection_id),
             0xb0u);
  fixture->config.hello.max_frame = MESH_MGMT_FRAME_MAX;
  fixture->config.hello.max_digest_entries = 128u;
  fixture->config.hello.max_delta_batch = 64u;
  fill_bytes(fixture->config.session_id, sizeof(fixture->config.session_id), 0x10u);
  fixture->config.incarnation = TEST_INCARNATION;
  fixture->config.first_sequence = TEST_FIRST_SEQUENCE;
  fixture->config.frame_ttl_ms = TEST_FRAME_TTL_MS;
  fixture->config.now_ms = test_now_ms;
  fixture->config.random_bytes = test_random_bytes;
  fixture->config.callback_context = &fixture->callbacks;
  mesh_mgmt_crypto_wipe(management_public_key, sizeof(management_public_key));
}

static void prepare_ack(mesh_mgmt_hello_ack_v1_t *ack, const mesh_mgmt_hello_v1_t *hello) {
  memset(ack, 0, sizeof(*ack));
  ack->selected_major = MESH_MGMT_MAJOR_V1;
  ack->selected_minor = MESH_MGMT_MINOR_V1;
  ack->features = hello->features;
  ack->max_frame = hello->max_frame;
  ack->max_digest_entries = hello->max_digest_entries;
  ack->max_delta_batch = hello->max_delta_batch;
  memcpy(ack->peer_connection_id, hello->connection_id, sizeof(ack->peer_connection_id));
}

static void test_signer_builds_bound_hello_and_ack(void) {
  signer_fixture_t fixture;
  mesh_mgmt_peer_signer_v1_t signer;
  mesh_mgmt_verified_envelope_v1_t hello_envelope;
  mesh_mgmt_verified_envelope_v1_t ack_envelope;
  mesh_mgmt_verified_envelope_v1_t targeted_envelope;
  mesh_mgmt_hello_v1_t decoded_hello;
  mesh_mgmt_hello_ack_v1_t expected_ack;
  mesh_mgmt_hello_ack_v1_t decoded_ack;
  const uint8_t *frame = NULL;
  size_t frame_len = 0u;
  uint8_t expected_message_id[16];
  uint8_t target_node_id[32];
  uint8_t zero_key[32] = {0};

  memset(&signer, 0, sizeof(signer));
  prepare_fixture(&fixture);
  prepare_ack(&expected_ack, &fixture.config.hello);
  check_int_eq(mesh_mgmt_peer_signer_init_v1(&signer, &fixture.config), MESH_MGMT_PEER_SIGNER_OK);
  frame = (const uint8_t *)1;
  frame_len = 1u;
  check_int_eq(mesh_mgmt_peer_signer_build_ack_v1(&signer, &expected_ack, &frame, &frame_len),
               MESH_MGMT_PEER_SIGNER_INVALID_STATE);
  check_null(frame);
  check_size_eq(frame_len, 0u);
  check_int_eq(mesh_mgmt_peer_signer_build_hello_v1(&signer, &frame, &frame_len),
               MESH_MGMT_PEER_SIGNER_OK);
  check_not_null(frame);
  check_size_gt(frame_len, 0u);
  check_int_eq(mesh_mgmt_envelope_verify_v1(frame, frame_len, &hello_envelope),
               MESH_MGMT_ENVELOPE_OK);
  check_int_eq(mesh_mgmt_hello_decode_v1(hello_envelope.frame.payload,
                                         hello_envelope.frame.payload_len, &decoded_hello),
               MESH_MGMT_SESSION_OK);
  check_int_eq(hello_envelope.frame.kind, MESH_MGMT_KIND_HELLO);
  check_hex64_eq(hello_envelope.header.origin_sequence, TEST_FIRST_SEQUENCE);
  check_hex64_eq(hello_envelope.header.issued_at_ms, TEST_NOW_MS);
  check_hex64_eq(hello_envelope.header.expires_at_ms, TEST_NOW_MS + TEST_FRAME_TTL_MS);
  fill_bytes(expected_message_id, sizeof(expected_message_id), 0x40u);
  check_mem_eq(hello_envelope.header.message_id, expected_message_id, sizeof(expected_message_id));
  check_mem_eq(decoded_hello.connection_id, fixture.config.hello.connection_id,
               sizeof(decoded_hello.connection_id));

  check_int_eq(mesh_mgmt_peer_signer_build_ack_v1(&signer, &expected_ack, &frame, &frame_len),
               MESH_MGMT_PEER_SIGNER_OK);
  check_int_eq(mesh_mgmt_envelope_verify_v1(frame, frame_len, &ack_envelope),
               MESH_MGMT_ENVELOPE_OK);
  check_int_eq(mesh_mgmt_hello_ack_decode_v1(ack_envelope.frame.payload,
                                             ack_envelope.frame.payload_len, &decoded_ack),
               MESH_MGMT_SESSION_OK);
  check_int_eq(ack_envelope.frame.kind, MESH_MGMT_KIND_HELLO_ACK);
  check_hex64_eq(ack_envelope.header.origin_sequence, TEST_FIRST_SEQUENCE + 1u);
  fill_bytes(expected_message_id, sizeof(expected_message_id), 0x50u);
  check_mem_eq(ack_envelope.header.message_id, expected_message_id, sizeof(expected_message_id));
  check_mem_eq(ack_envelope.header.session_id, hello_envelope.header.session_id,
               sizeof(ack_envelope.header.session_id));
  check_mem_eq(&decoded_ack, &expected_ack, sizeof(decoded_ack));
  check_hex64_eq(signer.next_sequence, TEST_FIRST_SEQUENCE + 2u);
  check_size_eq(fixture.callbacks.random_calls, 2u);

  fill_bytes(target_node_id, sizeof(target_node_id), 0x70u);
  check_int_eq(mesh_mgmt_peer_signer_build_targeted_v1(
                   &signer, MESH_MGMT_KIND_COMMAND_REQUEST, target_node_id,
                   NULL, 0u, &frame, &frame_len),
               MESH_MGMT_PEER_SIGNER_OK);
  check_int_eq(signer.last_envelope_result, MESH_MGMT_ENVELOPE_OK);
  check_int_eq(mesh_mgmt_envelope_verify_v1(
                   frame, frame_len, &targeted_envelope),
               MESH_MGMT_ENVELOPE_OK);
  check_int_eq(targeted_envelope.frame.kind,
               MESH_MGMT_KIND_COMMAND_REQUEST);
  check_mem_eq(targeted_envelope.header.target_node_id, target_node_id,
               sizeof(target_node_id));
  check_size_eq(targeted_envelope.frame.payload_len, 0u);
  check_hex64_eq(targeted_envelope.header.origin_sequence,
                 TEST_FIRST_SEQUENCE + 2u);
  check_hex64_eq(signer.next_sequence, TEST_FIRST_SEQUENCE + 3u);
  check_size_eq(fixture.callbacks.random_calls, 3u);

  frame = (const uint8_t *)1;
  frame_len = 1u;
  check_int_eq(mesh_mgmt_peer_signer_build_hello_v1(&signer, &frame, &frame_len),
               MESH_MGMT_PEER_SIGNER_INVALID_STATE);
  check_null(frame);
  check_size_eq(frame_len, 0u);
  mesh_mgmt_peer_signer_destroy_v1(&signer);
  check_int_eq(signer.state, MESH_MGMT_PEER_SIGNER_UNINITIALIZED);
  check_mem_eq(signer.private_key, zero_key, sizeof(zero_key));
}

static void test_signer_rejects_identity_mismatch(void) {
  signer_fixture_t fixture;
  mesh_mgmt_peer_signer_v1_t signer;

  memset(&signer, 0, sizeof(signer));
  prepare_fixture(&fixture);
  fixture.config.local_transport_peer_id[0] ^= 1u;
  check_int_eq(mesh_mgmt_peer_signer_init_v1(&signer, &fixture.config),
               MESH_MGMT_PEER_SIGNER_IDENTITY_FAILED);
  check_int_eq(signer.state, MESH_MGMT_PEER_SIGNER_UNINITIALIZED);

  fixture.config.local_transport_peer_id[0] ^= 1u;
  fixture.config.private_key[0] ^= 1u;
  check_int_eq(mesh_mgmt_peer_signer_init_v1(&signer, &fixture.config),
               MESH_MGMT_PEER_SIGNER_IDENTITY_FAILED);
  check_int_eq(signer.state, MESH_MGMT_PEER_SIGNER_UNINITIALIZED);
}

static void test_signer_propagates_random_failure_without_sequence_advance(void) {
  signer_fixture_t fixture;
  mesh_mgmt_peer_signer_v1_t signer;
  const uint8_t *frame = (const uint8_t *)1;
  size_t frame_len = 1u;

  memset(&signer, 0, sizeof(signer));
  prepare_fixture(&fixture);
  fixture.callbacks.random_result = -77;
  check_int_eq(mesh_mgmt_peer_signer_init_v1(&signer, &fixture.config), MESH_MGMT_PEER_SIGNER_OK);
  check_int_eq(mesh_mgmt_peer_signer_build_hello_v1(&signer, &frame, &frame_len),
               MESH_MGMT_PEER_SIGNER_RANDOM_FAILED);
  check_null(frame);
  check_size_eq(frame_len, 0u);
  check_int_eq(signer.last_random_result, -77);
  check_hex64_eq(signer.next_sequence, TEST_FIRST_SEQUENCE);
  check_false(signer.hello_built);

  fixture.callbacks.random_result = 0;
  signer.random_bytes = zero_random_bytes;
  check_int_eq(mesh_mgmt_peer_signer_build_hello_v1(&signer, &frame, &frame_len),
               MESH_MGMT_PEER_SIGNER_RANDOM_FAILED);
  check_hex64_eq(signer.next_sequence, TEST_FIRST_SEQUENCE);
  check_false(signer.hello_built);

  signer.random_bytes = test_random_bytes;
  check_int_eq(mesh_mgmt_peer_signer_build_hello_v1(&signer, &frame, &frame_len),
               MESH_MGMT_PEER_SIGNER_OK);
  check_hex64_eq(signer.next_sequence, TEST_FIRST_SEQUENCE + 1u);
  mesh_mgmt_peer_signer_destroy_v1(&signer);
}

static void test_signer_uses_turboutils_csprng_by_default(void) {
  signer_fixture_t fixture;
  mesh_mgmt_peer_signer_v1_t signer;
  mesh_mgmt_verified_envelope_v1_t envelope;
  const uint8_t *frame = NULL;
  size_t frame_len = 0u;
  uint8_t zero_message_id[16] = {0};

  memset(&signer, 0, sizeof(signer));
  prepare_fixture(&fixture);
  fixture.config.random_bytes = NULL;
  check_int_eq(mesh_mgmt_peer_signer_init_v1(&signer, &fixture.config), MESH_MGMT_PEER_SIGNER_OK);
  check_int_eq(mesh_mgmt_peer_signer_build_hello_v1(&signer, &frame, &frame_len),
               MESH_MGMT_PEER_SIGNER_OK);
  check_int_eq(mesh_mgmt_envelope_verify_v1(frame, frame_len, &envelope), MESH_MGMT_ENVELOPE_OK);
  check_mem_ne(envelope.header.message_id, zero_message_id, sizeof(zero_message_id));
  mesh_mgmt_peer_signer_destroy_v1(&signer);
}

spec("mesh management peer signer") {
  describe("local identity and frame construction") {
    it("builds one signed HELLO and matching ACK") { test_signer_builds_bound_hello_and_ack(); }
    it("rejects private-key and transport identity mismatch") {
      test_signer_rejects_identity_mismatch();
    }
    it("propagates CSPRNG failure without advancing sequence") {
      test_signer_propagates_random_failure_without_sequence_advance();
    }
    it("uses TurboUtils system CSPRNG by default") {
      test_signer_uses_turboutils_csprng_by_default();
    }
  }
}
