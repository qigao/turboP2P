#include <tinytest.h>

#include "mesh_mgmt_peer.h"
#include "mesh_mgmt_peer_signer.h"

#include <stdlib.h>
#include <string.h>

static const uint8_t ROOT_PRIVATE_KEY[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};

static const uint8_t REMOTE_PRIVATE_KEY[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
};

#define TEST_NOW_MS 1500u
#define TEST_CERT_SERIAL 42u
#define TEST_PRINCIPAL_EPOCH 7u

typedef struct {
  uint8_t root_public_key[32];
  uint8_t remote_public_key[32];
  uint8_t mesh_id_hash[32];
  uint8_t transport_peer_id[32];
  uint8_t managed_node_id[32];
  uint8_t remote_connection_id[16];
  uint8_t certificate[MESH_MGMT_CERTIFICATE_V1_SIZE];
  mesh_mgmt_certificate_claims_v1_t claims;
  mesh_mgmt_hello_v1_t hello;
  mesh_mgmt_session_config_v1_t session_config;
} test_context_t;

static void fill_bytes(uint8_t *bytes, size_t length, uint8_t first) {
  size_t index = 0;
  for (index = 0; index < length; index++) {
    bytes[index] = (uint8_t)(first + index);
  }
}

static void prepare_context(test_context_t *context) {
  size_t certificate_len = 0;

  memset(context, 0, sizeof(*context));
  check_int_eq(mesh_mgmt_ed25519_public_from_private(ROOT_PRIVATE_KEY, context->root_public_key),
               MESH_MGMT_CRYPTO_OK);
  check_int_eq(
      mesh_mgmt_ed25519_public_from_private(REMOTE_PRIVATE_KEY, context->remote_public_key),
      MESH_MGMT_CRYPTO_OK);
  fill_bytes(context->mesh_id_hash, 32, 0x20);
  fill_bytes(context->transport_peer_id, 32, 0x50);
  fill_bytes(context->managed_node_id, 32, 0x80);
  fill_bytes(context->remote_connection_id, 16, 0xb0);

  context->claims.principal_type = MESH_MGMT_PRINCIPAL_NODE;
  memcpy(context->claims.management_key, context->remote_public_key, 32);
  memcpy(context->claims.transport_peer_id, context->transport_peer_id, 32);
  memcpy(context->claims.managed_node_id, context->managed_node_id, 32);
  memcpy(context->claims.mesh_id_hash, context->mesh_id_hash, 32);
  context->claims.roles = MESH_MGMT_ROLE_OBSERVER | MESH_MGMT_ROLE_OPERATOR;
  context->claims.not_before_ms = 1000;
  context->claims.expires_at_ms = 3000;
  context->claims.serial = TEST_CERT_SERIAL;
  context->claims.principal_epoch = TEST_PRINCIPAL_EPOCH;
  check_int_eq(mesh_mgmt_certificate_issue_v1(&context->claims, ROOT_PRIVATE_KEY,
                                              context->certificate, sizeof(context->certificate),
                                              &certificate_len),
               MESH_MGMT_IDENTITY_OK);
  check_size_eq(certificate_len, MESH_MGMT_CERTIFICATE_V1_SIZE);

  context->hello.major = MESH_MGMT_MAJOR_V1;
  context->hello.min_minor = 0;
  context->hello.max_minor = 0;
  context->hello.features = MESH_MGMT_FEATURE_MEMBERSHIP | MESH_MGMT_FEATURE_TARGETED_RPC;
  context->hello.platform = MESH_MGMT_PLATFORM_LINUX;
  memcpy(context->hello.build_version, "1.2.3-test", 10);
  context->hello.build_version_len = 10;
  memcpy(context->hello.certificate, context->certificate, sizeof(context->certificate));
  check_int_eq(
      mesh_mgmt_blake2b_256(context->root_public_key, 32, context->hello.issuer_chain_hash),
      MESH_MGMT_CRYPTO_OK);
  context->hello.principal_type = MESH_MGMT_PRINCIPAL_NODE;
  memcpy(context->hello.management_key, context->remote_public_key, 32);
  memcpy(context->hello.managed_node_id, context->managed_node_id, 32);
  memcpy(context->hello.connection_id, context->remote_connection_id, 16);
  context->hello.max_frame = 12000;
  context->hello.max_digest_entries = 64;
  context->hello.max_delta_batch = 32;

  memcpy(context->session_config.expected_mesh_id_hash, context->mesh_id_hash, 32);
  memcpy(context->session_config.trusted_issuer_key, context->root_public_key, 32);
  context->session_config.min_minor = 0;
  context->session_config.max_minor = 0;
  context->session_config.features = MESH_MGMT_FEATURE_MEMBERSHIP | MESH_MGMT_FEATURE_ANTI_ENTROPY;
  fill_bytes(context->session_config.connection_id, 16, 0xd0);
  context->session_config.max_frame = MESH_MGMT_FRAME_MAX;
  context->session_config.max_digest_entries = 128;
  context->session_config.max_delta_batch = 64;
}

static size_t encode_hello_payload(const test_context_t *context,
                                   uint8_t output[MESH_MGMT_HELLO_V1_MAX_SIZE]) {
  size_t output_len = 0;
  check_int_eq(
      mesh_mgmt_hello_encode_v1(&context->hello, output, MESH_MGMT_HELLO_V1_MAX_SIZE, &output_len),
      MESH_MGMT_SESSION_OK);
  check_size_eq(output_len, 557);
  return output_len;
}

static size_t sign_remote_frame_values(const test_context_t *context, uint8_t kind,
                                       const uint8_t *payload, size_t payload_len,
                                       uint64_t certificate_serial, uint64_t incarnation,
                                       uint8_t session_first, uint64_t sequence,
                                       uint8_t message_first, uint8_t output[MESH_MGMT_FRAME_MAX]) {
  mesh_mgmt_sign_input_v1_t input;
  size_t output_len = 0;

  memset(&input, 0, sizeof(input));
  input.minor = MESH_MGMT_MINOR_V1;
  input.kind = kind;
  input.private_key = REMOTE_PRIVATE_KEY;
  input.payload = payload;
  input.payload_len = payload_len;
  memcpy(input.header.mesh_id_hash, context->mesh_id_hash, 32);
  memcpy(input.header.origin_node_id, context->managed_node_id, 32);
  if (kind == MESH_MGMT_KIND_FORWARD || kind == MESH_MGMT_KIND_COMMAND_REQUEST ||
      kind == MESH_MGMT_KIND_COMMAND_ACCEPTED || kind == MESH_MGMT_KIND_COMMAND_RESULT ||
      kind == MESH_MGMT_KIND_COMMAND_STATUS) {
    fill_bytes(input.header.target_node_id, 32, 0xa0);
  }
  input.header.principal_epoch = TEST_PRINCIPAL_EPOCH;
  input.header.incarnation = incarnation;
  fill_bytes(input.header.session_id, 16, session_first);
  input.header.origin_sequence = sequence;
  fill_bytes(input.header.message_id, 16, message_first);
  input.header.issued_at_ms = 1400;
  input.header.expires_at_ms = 1600;
  input.header.certificate_serial = certificate_serial;
  check_int_eq(mesh_mgmt_envelope_sign_v1(&input, output, MESH_MGMT_FRAME_MAX, &output_len),
               MESH_MGMT_ENVELOPE_OK);
  return output_len;
}

static size_t sign_remote_frame(const test_context_t *context, uint8_t kind, const uint8_t *payload,
                                size_t payload_len, uint64_t certificate_serial,
                                uint8_t output[MESH_MGMT_FRAME_MAX]) {
  return sign_remote_frame_values(context, kind, payload, payload_len, certificate_serial, 3u, 0x10,
                                  kind, kind, output);
}

static void verify_frame(const uint8_t *frame, size_t frame_len,
                         mesh_mgmt_verified_envelope_v1_t *verified) {
  check_int_eq(mesh_mgmt_envelope_verify_v1(frame, frame_len, verified), MESH_MGMT_ENVELOPE_OK);
}

static void accept_valid_hello(test_context_t *context, mesh_mgmt_session_v1_t *session,
                               mesh_mgmt_hello_ack_v1_t *ack) {
  uint8_t hello_payload[MESH_MGMT_HELLO_V1_MAX_SIZE];
  uint8_t hello_frame[MESH_MGMT_FRAME_MAX];
  size_t hello_payload_len = encode_hello_payload(context, hello_payload);
  size_t hello_frame_len = sign_remote_frame(context, MESH_MGMT_KIND_HELLO, hello_payload,
                                             hello_payload_len, TEST_CERT_SERIAL, hello_frame);

  check_int_eq(mesh_mgmt_session_accept_hello_v1(session, hello_frame, hello_frame_len,
                                                 context->transport_peer_id, TEST_NOW_MS, ack),
               MESH_MGMT_SESSION_OK);
}

static void test_certificate_verifies_direct_trust_binding(void) {
  test_context_t context;
  mesh_mgmt_certificate_v1_t certificate;
  mesh_mgmt_tlv_reader_t reader;
  mesh_mgmt_tlv_view_t field;
  uint16_t expected_field_id = 1;

  prepare_context(&context);
  check_int_eq(mesh_mgmt_certificate_verify_v1(context.certificate, sizeof(context.certificate),
                                               context.root_public_key, context.mesh_id_hash,
                                               TEST_NOW_MS, &certificate),
               MESH_MGMT_IDENTITY_OK);
  check_uint_eq(certificate.principal_type, MESH_MGMT_PRINCIPAL_NODE);
  check_mem_eq(certificate.management_key, context.remote_public_key, 32);
  check_mem_eq(certificate.transport_peer_id, context.transport_peer_id, 32);
  check_mem_eq(certificate.managed_node_id, context.managed_node_id, 32);
  check_hex64_eq(certificate.serial, TEST_CERT_SERIAL);
  check_hex64_eq(certificate.principal_epoch, TEST_PRINCIPAL_EPOCH);
  mesh_mgmt_tlv_reader_init(&reader, context.certificate, sizeof(context.certificate));
  while (mesh_mgmt_tlv_reader_next(&reader, &field) == 1) {
    check_uint_eq(field.field_id, expected_field_id);
    expected_field_id++;
  }
  check_uint_eq(expected_field_id, 15);
}

static void test_certificate_rejects_tamper_expiry_and_missing_node_binding(void) {
  test_context_t context;
  mesh_mgmt_certificate_v1_t certificate;
  uint8_t tampered[MESH_MGMT_CERTIFICATE_V1_SIZE];
  uint8_t output[MESH_MGMT_CERTIFICATE_V1_SIZE];
  size_t output_len = 0;

  prepare_context(&context);
  memcpy(tampered, context.certificate, sizeof(tampered));
  tampered[sizeof(tampered) - 1u] ^= 1u;
  check_int_eq(mesh_mgmt_certificate_verify_v1(tampered, sizeof(tampered), context.root_public_key,
                                               context.mesh_id_hash, TEST_NOW_MS, &certificate),
               MESH_MGMT_IDENTITY_AUTH_FAILED);
  check_int_eq(mesh_mgmt_certificate_verify_v1(context.certificate, sizeof(context.certificate),
                                               context.root_public_key, context.mesh_id_hash, 3000,
                                               &certificate),
               MESH_MGMT_IDENTITY_EXPIRED);
  check_int_eq(mesh_mgmt_certificate_verify_v1(context.certificate, sizeof(context.certificate),
                                               context.remote_public_key, context.mesh_id_hash,
                                               TEST_NOW_MS, &certificate),
               MESH_MGMT_IDENTITY_AUTH_FAILED);

  memset(context.claims.transport_peer_id, 0, 32);
  check_int_eq(mesh_mgmt_certificate_issue_v1(&context.claims, ROOT_PRIVATE_KEY, output,
                                              sizeof(output), &output_len),
               MESH_MGMT_IDENTITY_INVALID_SCHEMA);
  check_size_eq(output_len, 0);
}

static void test_session_establishes_only_after_mutual_ack(void) {
  test_context_t context;
  mesh_mgmt_session_v1_t session;
  mesh_mgmt_hello_ack_v1_t ack;
  mesh_mgmt_verified_envelope_v1_t verified;
  uint8_t ack_payload[MESH_MGMT_HELLO_ACK_V1_SIZE];
  uint8_t ack_frame[MESH_MGMT_FRAME_MAX];
  size_t ack_payload_len = 0;
  size_t ack_frame_len = 0;

  prepare_context(&context);
  check_int_eq(mesh_mgmt_session_init_v1(&session, &context.session_config), MESH_MGMT_SESSION_OK);
  check_int_eq(mesh_mgmt_session_authorize_kind_v1(&session, MESH_MGMT_KIND_PROBE),
               MESH_MGMT_SESSION_NOT_ESTABLISHED);
  check_int_eq(mesh_mgmt_session_mark_hello_sent_v1(&session), MESH_MGMT_SESSION_OK);
  accept_valid_hello(&context, &session, &ack);
  check_int_eq(session.state, MESH_MGMT_SESSION_NEGOTIATING);
  check_uint_eq(ack.selected_minor, 0);
  check_hex64_eq(ack.features, MESH_MGMT_FEATURE_MEMBERSHIP);
  check_uint_eq(ack.max_frame, 12000);
  check_uint_eq(ack.max_digest_entries, 64);
  check_uint_eq(ack.max_delta_batch, 32);
  check_mem_eq(ack.peer_connection_id, context.remote_connection_id, 16);
  check_int_eq(mesh_mgmt_session_mark_ack_sent_v1(&session), MESH_MGMT_SESSION_OK);
  check_int_eq(session.state, MESH_MGMT_SESSION_NEGOTIATING);

  memcpy(ack.peer_connection_id, context.session_config.connection_id, 16);
  check_int_eq(
      mesh_mgmt_hello_ack_encode_v1(&ack, ack_payload, sizeof(ack_payload), &ack_payload_len),
      MESH_MGMT_SESSION_OK);
  ack_frame_len = sign_remote_frame(&context, MESH_MGMT_KIND_HELLO_ACK, ack_payload,
                                    ack_payload_len, TEST_CERT_SERIAL, ack_frame);
  verify_frame(ack_frame, ack_frame_len, &verified);
  check_int_eq(
      mesh_mgmt_session_accept_hello_ack_v1(&session, ack_frame, ack_frame_len, TEST_NOW_MS),
      MESH_MGMT_SESSION_OK);
  check_int_eq(session.state, MESH_MGMT_SESSION_ESTABLISHED);
  check_int_eq(mesh_mgmt_session_authorize_kind_v1(&session, MESH_MGMT_KIND_PROBE),
               MESH_MGMT_SESSION_OK);
  check_int_eq(mesh_mgmt_session_authorize_kind_v1(&session, MESH_MGMT_KIND_COMMAND_REQUEST),
               MESH_MGMT_SESSION_UNSUPPORTED_FEATURE);
  check_int_eq(mesh_mgmt_session_authorize_kind_v1(&session, MESH_MGMT_KIND_ERROR),
               MESH_MGMT_SESSION_OK);
}

static void test_session_rejects_transport_and_header_binding_mismatch(void) {
  test_context_t context;
  mesh_mgmt_session_v1_t session;
  mesh_mgmt_hello_ack_v1_t ack;
  mesh_mgmt_verified_envelope_v1_t verified;
  uint8_t wrong_transport[32];
  uint8_t payload[MESH_MGMT_HELLO_V1_MAX_SIZE];
  uint8_t frame[MESH_MGMT_FRAME_MAX];
  size_t payload_len = 0;
  size_t frame_len = 0;

  prepare_context(&context);
  check_int_eq(mesh_mgmt_session_init_v1(&session, &context.session_config), MESH_MGMT_SESSION_OK);
  payload_len = encode_hello_payload(&context, payload);
  frame_len = sign_remote_frame(&context, MESH_MGMT_KIND_HELLO, payload, payload_len,
                                TEST_CERT_SERIAL, frame);
  verify_frame(frame, frame_len, &verified);
  fill_bytes(wrong_transport, 32, 0xee);
  check_int_eq(mesh_mgmt_session_accept_hello_v1(&session, frame, frame_len, wrong_transport,
                                                 TEST_NOW_MS, &ack),
               MESH_MGMT_SESSION_AUTH_FAILED);
  check_int_eq(session.state, MESH_MGMT_SESSION_FAILED);
  check_mem_eq(session.remote_certificate.management_key, (uint8_t[32]){0}, 32);

  check_int_eq(mesh_mgmt_session_init_v1(&session, &context.session_config), MESH_MGMT_SESSION_OK);
  frame_len = sign_remote_frame(&context, MESH_MGMT_KIND_HELLO, payload, payload_len,
                                TEST_CERT_SERIAL + 1u, frame);
  verify_frame(frame, frame_len, &verified);
  check_int_eq(mesh_mgmt_session_accept_hello_v1(&session, frame, frame_len,
                                                 context.transport_peer_id, TEST_NOW_MS, &ack),
               MESH_MGMT_SESSION_AUTH_FAILED);
  check_int_eq(session.state, MESH_MGMT_SESSION_FAILED);

  check_int_eq(mesh_mgmt_session_init_v1(&session, &context.session_config), MESH_MGMT_SESSION_OK);
  frame_len = sign_remote_frame_values(&context, MESH_MGMT_KIND_HELLO, payload, payload_len,
                                       TEST_CERT_SERIAL, 0u, 0x10, MESH_MGMT_KIND_HELLO,
                                       MESH_MGMT_KIND_HELLO, frame);
  check_int_eq(mesh_mgmt_session_accept_hello_v1(&session, frame, frame_len,
                                                 context.transport_peer_id, TEST_NOW_MS, &ack),
               MESH_MGMT_SESSION_AUTH_FAILED);
  check_int_eq(session.state, MESH_MGMT_SESSION_FAILED);
}

static void test_session_rejects_raw_frame_without_valid_envelope_signature(void) {
  test_context_t context;
  mesh_mgmt_session_v1_t session;
  mesh_mgmt_hello_ack_v1_t ack;
  uint8_t payload[MESH_MGMT_HELLO_V1_MAX_SIZE];
  uint8_t frame[MESH_MGMT_FRAME_MAX];
  size_t payload_len = 0;
  size_t frame_len = 0;

  prepare_context(&context);
  check_int_eq(mesh_mgmt_session_init_v1(&session, &context.session_config), MESH_MGMT_SESSION_OK);
  payload_len = encode_hello_payload(&context, payload);
  frame_len = sign_remote_frame(&context, MESH_MGMT_KIND_HELLO, payload, payload_len,
                                TEST_CERT_SERIAL, frame);
  frame[frame_len - 1u] ^= 1u;
  check_int_eq(mesh_mgmt_session_accept_hello_v1(&session, frame, frame_len,
                                                 context.transport_peer_id, TEST_NOW_MS, &ack),
               MESH_MGMT_SESSION_AUTH_FAILED);
  check_int_eq(session.state, MESH_MGMT_SESSION_FAILED);
  check_mem_eq(session.remote_certificate.management_key, (uint8_t[32]){0}, 32);
}

static void test_session_rejects_downgraded_ack(void) {
  test_context_t context;
  mesh_mgmt_session_v1_t session;
  mesh_mgmt_hello_ack_v1_t ack;
  mesh_mgmt_verified_envelope_v1_t verified;
  uint8_t payload[MESH_MGMT_HELLO_ACK_V1_SIZE];
  uint8_t frame[MESH_MGMT_FRAME_MAX];
  size_t payload_len = 0;
  size_t frame_len = 0;

  prepare_context(&context);
  check_int_eq(mesh_mgmt_session_init_v1(&session, &context.session_config), MESH_MGMT_SESSION_OK);
  check_int_eq(mesh_mgmt_session_mark_hello_sent_v1(&session), MESH_MGMT_SESSION_OK);
  accept_valid_hello(&context, &session, &ack);
  check_int_eq(mesh_mgmt_session_mark_ack_sent_v1(&session), MESH_MGMT_SESSION_OK);
  memcpy(ack.peer_connection_id, context.session_config.connection_id, 16);
  ack.features = 0;
  check_int_eq(mesh_mgmt_hello_ack_encode_v1(&ack, payload, sizeof(payload), &payload_len),
               MESH_MGMT_SESSION_OK);
  frame_len = sign_remote_frame(&context, MESH_MGMT_KIND_HELLO_ACK, payload, payload_len,
                                TEST_CERT_SERIAL, frame);
  verify_frame(frame, frame_len, &verified);
  check_int_eq(mesh_mgmt_session_accept_hello_ack_v1(&session, frame, frame_len, TEST_NOW_MS),
               MESH_MGMT_SESSION_AUTH_FAILED);
  check_int_eq(session.state, MESH_MGMT_SESSION_FAILED);
}

static void test_session_rejects_ack_from_changed_origin_session(void) {
  test_context_t context;
  mesh_mgmt_session_v1_t session;
  mesh_mgmt_hello_ack_v1_t ack;
  uint8_t payload[MESH_MGMT_HELLO_ACK_V1_SIZE];
  uint8_t frame[MESH_MGMT_FRAME_MAX];
  size_t payload_len = 0;
  size_t frame_len = 0;

  prepare_context(&context);
  check_int_eq(mesh_mgmt_session_init_v1(&session, &context.session_config), MESH_MGMT_SESSION_OK);
  check_int_eq(mesh_mgmt_session_mark_hello_sent_v1(&session), MESH_MGMT_SESSION_OK);
  accept_valid_hello(&context, &session, &ack);
  check_int_eq(mesh_mgmt_session_mark_ack_sent_v1(&session), MESH_MGMT_SESSION_OK);
  memcpy(ack.peer_connection_id, context.session_config.connection_id, 16);
  check_int_eq(mesh_mgmt_hello_ack_encode_v1(&ack, payload, sizeof(payload), &payload_len),
               MESH_MGMT_SESSION_OK);
  frame_len = sign_remote_frame_values(&context, MESH_MGMT_KIND_HELLO_ACK, payload, payload_len,
                                       TEST_CERT_SERIAL, 3u, 0x11, MESH_MGMT_KIND_HELLO_ACK,
                                       MESH_MGMT_KIND_HELLO_ACK, frame);
  check_int_eq(mesh_mgmt_session_accept_hello_ack_v1(&session, frame, frame_len, TEST_NOW_MS),
               MESH_MGMT_SESSION_AUTH_FAILED);
  check_int_eq(session.state, MESH_MGMT_SESSION_FAILED);
}

static void establish_dispatcher(test_context_t *context, mesh_mgmt_dispatcher_v1_t *dispatcher) {
  mesh_mgmt_dispatch_config_v1_t config;
  mesh_mgmt_dispatch_event_v1_t event;
  mesh_mgmt_dispatch_stage_t stage;
  uint8_t hello_payload[MESH_MGMT_HELLO_V1_MAX_SIZE];
  uint8_t ack_payload[MESH_MGMT_HELLO_ACK_V1_SIZE];
  uint8_t frame[MESH_MGMT_FRAME_MAX];
  size_t hello_payload_len = 0;
  size_t ack_payload_len = 0;
  size_t frame_len = 0;

  prepare_context(context);
  context->hello.features |= MESH_MGMT_FEATURE_STREAM_TICKET;
  context->session_config.features |=
      MESH_MGMT_FEATURE_TARGETED_RPC | MESH_MGMT_FEATURE_STREAM_TICKET;
  memset(&config, 0, sizeof(config));
  config.session = context->session_config;
  config.replay.capacity = 4u;
  config.replay.ttl_ms = 100u;
  check_int_eq(mesh_mgmt_dispatcher_init_v1(dispatcher, &config, &stage), MESH_MGMT_DISPATCH_OK);
  check_int_eq(stage, MESH_MGMT_DISPATCH_STAGE_REPLAY);
  check_int_eq(mesh_mgmt_dispatcher_mark_hello_sent_v1(dispatcher, &stage), MESH_MGMT_DISPATCH_OK);

  hello_payload_len = encode_hello_payload(context, hello_payload);
  frame_len = sign_remote_frame(context, MESH_MGMT_KIND_HELLO, hello_payload, hello_payload_len,
                                TEST_CERT_SERIAL, frame);
  check_int_eq(mesh_mgmt_dispatcher_receive_v1(dispatcher, frame, frame_len,
                                               context->transport_peer_id, TEST_NOW_MS, &event,
                                               &stage),
               MESH_MGMT_DISPATCH_OK);
  check_int_eq(event.type, MESH_MGMT_DISPATCH_EVENT_HELLO_ACK_REQUIRED);
  check_int_eq(mesh_mgmt_dispatcher_mark_ack_sent_v1(dispatcher, &stage), MESH_MGMT_DISPATCH_OK);

  memcpy(event.hello_ack.peer_connection_id, context->session_config.connection_id, 16);
  check_int_eq(mesh_mgmt_hello_ack_encode_v1(&event.hello_ack, ack_payload, sizeof(ack_payload),
                                             &ack_payload_len),
               MESH_MGMT_SESSION_OK);
  frame_len = sign_remote_frame(context, MESH_MGMT_KIND_HELLO_ACK, ack_payload, ack_payload_len,
                                TEST_CERT_SERIAL, frame);
  check_int_eq(mesh_mgmt_dispatcher_receive_v1(dispatcher, frame, frame_len,
                                               context->transport_peer_id, TEST_NOW_MS, &event,
                                               &stage),
               MESH_MGMT_DISPATCH_OK);
  check_int_eq(event.type, MESH_MGMT_DISPATCH_EVENT_SESSION_ESTABLISHED);
  check_true(dispatcher->replay.bound);
}

static void test_dispatcher_owns_verify_session_replay_and_typed_order(void) {
  test_context_t context;
  mesh_mgmt_dispatcher_v1_t dispatcher;
  mesh_mgmt_dispatch_event_v1_t event;
  mesh_mgmt_dispatch_stage_t stage;
  uint8_t frame[MESH_MGMT_FRAME_MAX];
  size_t frame_len = 0;

  establish_dispatcher(&context, &dispatcher);
  frame_len = sign_remote_frame_values(&context, MESH_MGMT_KIND_PROBE, NULL, 0u, TEST_CERT_SERIAL,
                                       3u, 0x10, 16u, 0x51, frame);
  check_int_eq(mesh_mgmt_dispatcher_receive_v1(&dispatcher, frame, frame_len,
                                               context.transport_peer_id, TEST_NOW_MS, &event,
                                               &stage),
               MESH_MGMT_DISPATCH_OK);
  check_int_eq(stage, MESH_MGMT_DISPATCH_STAGE_TYPED_DISPATCH);
  check_int_eq(event.type, MESH_MGMT_DISPATCH_EVENT_MEMBERSHIP);
  check_int_eq(event.kind, MESH_MGMT_KIND_PROBE);
  check_size_eq(event.envelope.frame.payload_len, 0u);

  check_int_eq(mesh_mgmt_dispatcher_receive_v1(&dispatcher, frame, frame_len,
                                               context.transport_peer_id, TEST_NOW_MS, &event,
                                               &stage),
               MESH_MGMT_DISPATCH_REPLAYED);
  check_int_eq(stage, MESH_MGMT_DISPATCH_STAGE_REPLAY);
  check_hex64_eq(dispatcher.replay.last_sequence, 16u);

  frame_len = sign_remote_frame_values(&context, MESH_MGMT_KIND_STREAM_TICKET_REQUEST, NULL, 0u,
                                       TEST_CERT_SERIAL, 3u, 0x10, 17u, 0x52, frame);
  check_int_eq(mesh_mgmt_dispatcher_receive_v1(&dispatcher, frame, frame_len,
                                               context.transport_peer_id, TEST_NOW_MS, &event,
                                               &stage),
               MESH_MGMT_DISPATCH_OK);
  check_int_eq(stage, MESH_MGMT_DISPATCH_STAGE_TYPED_DISPATCH);
  check_int_eq(event.type, MESH_MGMT_DISPATCH_EVENT_STREAM_TICKET_REQUEST);
  check_int_eq(event.kind, MESH_MGMT_KIND_STREAM_TICKET_REQUEST);
  check_hex64_eq(dispatcher.replay.last_sequence, 17u);

  frame_len = sign_remote_frame_values(&context, MESH_MGMT_KIND_STREAM_TICKET_ISSUED, NULL, 0u,
                                       TEST_CERT_SERIAL, 3u, 0x10, 18u, 0x53, frame);
  check_int_eq(mesh_mgmt_dispatcher_receive_v1(&dispatcher, frame, frame_len,
                                               context.transport_peer_id, TEST_NOW_MS, &event,
                                               &stage),
               MESH_MGMT_DISPATCH_OK);
  check_int_eq(stage, MESH_MGMT_DISPATCH_STAGE_TYPED_DISPATCH);
  check_int_eq(event.type, MESH_MGMT_DISPATCH_EVENT_STREAM_TICKET_ISSUED);
  check_int_eq(event.kind, MESH_MGMT_KIND_STREAM_TICKET_ISSUED);
  check_hex64_eq(dispatcher.replay.last_sequence, 18u);

  frame_len = sign_remote_frame_values(&context, MESH_MGMT_KIND_PROBE, NULL, 0u, TEST_CERT_SERIAL,
                                       3u, 0x10, 19u, 0x54, frame);
  frame[frame_len - 1u] ^= 1u;
  check_int_eq(mesh_mgmt_dispatcher_receive_v1(&dispatcher, frame, frame_len,
                                               context.transport_peer_id, TEST_NOW_MS, &event,
                                               &stage),
               MESH_MGMT_DISPATCH_AUTH_FAILED);
  check_int_eq(stage, MESH_MGMT_DISPATCH_STAGE_ENVELOPE);
  check_hex64_eq(dispatcher.replay.last_sequence, 18u);
  mesh_mgmt_dispatcher_destroy_v1(&dispatcher);
}

static void test_dispatcher_rejects_unnegotiated_stream_ticket_without_replay(void) {
  test_context_t context;
  mesh_mgmt_dispatcher_v1_t dispatcher;
  mesh_mgmt_dispatch_event_v1_t event;
  mesh_mgmt_dispatch_stage_t stage;
  uint8_t frame[MESH_MGMT_FRAME_MAX];
  size_t frame_len = 0;

  establish_dispatcher(&context, &dispatcher);
  dispatcher.session.negotiated.features &= ~MESH_MGMT_FEATURE_STREAM_TICKET;
  frame_len = sign_remote_frame_values(&context, MESH_MGMT_KIND_STREAM_TICKET_REQUEST, NULL, 0u,
                                       TEST_CERT_SERIAL, 3u, 0x10, 20u, 0x61, frame);
  check_int_eq(mesh_mgmt_dispatcher_receive_v1(&dispatcher, frame, frame_len,
                                               context.transport_peer_id, TEST_NOW_MS, &event,
                                               &stage),
               MESH_MGMT_DISPATCH_UNSUPPORTED_FEATURE);
  check_int_eq(stage, MESH_MGMT_DISPATCH_STAGE_SESSION);
  check_false(dispatcher.replay.has_sequence);

  frame_len = sign_remote_frame_values(&context, MESH_MGMT_KIND_PROBE, NULL, 0u, TEST_CERT_SERIAL,
                                       3u, 0x10, 20u, 0x61, frame);
  check_int_eq(mesh_mgmt_dispatcher_receive_v1(&dispatcher, frame, frame_len,
                                               context.transport_peer_id, TEST_NOW_MS, &event,
                                               &stage),
               MESH_MGMT_DISPATCH_OK);
  check_hex64_eq(dispatcher.replay.last_sequence, 20u);
  mesh_mgmt_dispatcher_destroy_v1(&dispatcher);
}

static void test_dispatcher_rejects_side_effect_without_consuming_replay(void) {
  test_context_t context;
  mesh_mgmt_dispatcher_v1_t dispatcher;
  mesh_mgmt_dispatch_event_v1_t event;
  mesh_mgmt_dispatch_stage_t stage;
  uint8_t frame[MESH_MGMT_FRAME_MAX];
  size_t frame_len = 0;

  establish_dispatcher(&context, &dispatcher);
  frame_len = sign_remote_frame_values(&context, MESH_MGMT_KIND_COMMAND_REQUEST, NULL, 0u,
                                       TEST_CERT_SERIAL, 3u, 0x10, 20u, 0x61, frame);
  check_int_eq(mesh_mgmt_dispatcher_receive_v1(&dispatcher, frame, frame_len,
                                               context.transport_peer_id, TEST_NOW_MS, &event,
                                               &stage),
               MESH_MGMT_DISPATCH_SIDE_EFFECT_DISABLED);
  check_int_eq(stage, MESH_MGMT_DISPATCH_STAGE_SESSION);
  check_false(dispatcher.replay.has_sequence);

  frame_len = sign_remote_frame_values(&context, MESH_MGMT_KIND_PROBE, NULL, 0u, TEST_CERT_SERIAL,
                                       3u, 0x10, 20u, 0x61, frame);
  check_int_eq(mesh_mgmt_dispatcher_receive_v1(&dispatcher, frame, frame_len,
                                               context.transport_peer_id, TEST_NOW_MS, &event,
                                               &stage),
               MESH_MGMT_DISPATCH_OK);
  check_hex64_eq(dispatcher.replay.last_sequence, 20u);
  mesh_mgmt_dispatcher_destroy_v1(&dispatcher);
}

#define CONNECTION_TEST_FRAME_CAPACITY 4u

typedef struct {
  const uint8_t *frames[CONNECTION_TEST_FRAME_CAPACITY];
  size_t frame_lengths[CONNECTION_TEST_FRAME_CAPACITY];
  size_t frame_count;
  size_t recv_count;
  size_t release_count;
  size_t send_count;
  int send_result;
  uint8_t last_sent[MESH_MGMT_FRAME_MAX];
  size_t last_sent_len;
} connection_fake_io_t;

typedef struct {
  mesh_mgmt_dispatch_event_type_t events[CONNECTION_TEST_FRAME_CAPACITY];
  size_t event_count;
  int reject_result;
  mesh_mgmt_hello_ack_v1_t hello_ack;
} connection_event_capture_t;

static int connection_fake_recv(void *context, uint8_t **out_bytes, size_t *out_len) {
  connection_fake_io_t *fake = (connection_fake_io_t *)context;
  uint8_t *copy;

  if (!out_bytes || !out_len || fake->recv_count >= fake->frame_count)
    return -1;
  copy = (uint8_t *)malloc(fake->frame_lengths[fake->recv_count]);
  if (!copy)
    return -1;
  memcpy(copy, fake->frames[fake->recv_count], fake->frame_lengths[fake->recv_count]);
  *out_bytes = copy;
  *out_len = fake->frame_lengths[fake->recv_count];
  fake->recv_count++;
  return 0;
}

static void connection_fake_release(void *context, uint8_t *bytes) {
  connection_fake_io_t *fake = (connection_fake_io_t *)context;
  fake->release_count++;
  free(bytes);
}

static int connection_fake_send(void *context, const uint8_t *bytes, size_t len) {
  connection_fake_io_t *fake = (connection_fake_io_t *)context;
  fake->send_count++;
  if (fake->send_result != 0)
    return fake->send_result;
  if (len > sizeof(fake->last_sent))
    return -1;
  memcpy(fake->last_sent, bytes, len);
  fake->last_sent_len = len;
  return 0;
}

static int connection_capture_event(void *context, const mesh_mgmt_dispatch_event_v1_t *event) {
  connection_event_capture_t *capture = (connection_event_capture_t *)context;

  if (!event || capture->event_count >= CONNECTION_TEST_FRAME_CAPACITY)
    return -1;
  capture->events[capture->event_count++] = event->type;
  if (event->type == MESH_MGMT_DISPATCH_EVENT_HELLO_ACK_REQUIRED)
    capture->hello_ack = event->hello_ack;
  return capture->reject_result;
}

static void prepare_connection_config(test_context_t *context, connection_fake_io_t *fake,
                                      connection_event_capture_t *capture,
                                      mesh_mgmt_connection_config_v1_t *config) {
  prepare_context(context);
  context->hello.features |= MESH_MGMT_FEATURE_STREAM_TICKET;
  context->session_config.features |=
      MESH_MGMT_FEATURE_TARGETED_RPC | MESH_MGMT_FEATURE_STREAM_TICKET;
  memset(config, 0, sizeof(*config));
  config->dispatch.session = context->session_config;
  config->dispatch.replay.capacity = 4u;
  config->dispatch.replay.ttl_ms = 100u;
  config->io.context = fake;
  config->io.recv = connection_fake_recv;
  config->io.release = connection_fake_release;
  config->io.send = connection_fake_send;
  memcpy(config->transport_peer_id, context->transport_peer_id, 32);
  config->on_event = connection_capture_event;
  config->event_context = capture;
}

static void build_connection_handshake(const test_context_t *context,
                                       uint8_t hello_frame[MESH_MGMT_FRAME_MAX],
                                       size_t *hello_frame_len,
                                       uint8_t ack_frame[MESH_MGMT_FRAME_MAX],
                                       size_t *ack_frame_len) {
  mesh_mgmt_hello_ack_v1_t ack;
  uint8_t hello_payload[MESH_MGMT_HELLO_V1_MAX_SIZE];
  uint8_t ack_payload[MESH_MGMT_HELLO_ACK_V1_SIZE];
  size_t hello_payload_len = encode_hello_payload(context, hello_payload);
  size_t ack_payload_len = 0u;

  memset(&ack, 0, sizeof(ack));
  ack.selected_major = MESH_MGMT_MAJOR_V1;
  ack.selected_minor = MESH_MGMT_MINOR_V1;
  ack.features = context->hello.features & context->session_config.features;
  ack.max_frame = context->hello.max_frame < context->session_config.max_frame
                      ? context->hello.max_frame
                      : context->session_config.max_frame;
  ack.max_digest_entries =
      context->hello.max_digest_entries < context->session_config.max_digest_entries
          ? context->hello.max_digest_entries
          : context->session_config.max_digest_entries;
  ack.max_delta_batch = context->hello.max_delta_batch < context->session_config.max_delta_batch
                            ? context->hello.max_delta_batch
                            : context->session_config.max_delta_batch;
  memcpy(ack.peer_connection_id, context->session_config.connection_id, 16);
  check_int_eq(
      mesh_mgmt_hello_ack_encode_v1(&ack, ack_payload, sizeof(ack_payload), &ack_payload_len),
      MESH_MGMT_SESSION_OK);
  *hello_frame_len = sign_remote_frame(context, MESH_MGMT_KIND_HELLO, hello_payload,
                                       hello_payload_len, TEST_CERT_SERIAL, hello_frame);
  *ack_frame_len = sign_remote_frame(context, MESH_MGMT_KIND_HELLO_ACK, ack_payload,
                                     ack_payload_len, TEST_CERT_SERIAL, ack_frame);
}

static void test_connection_owns_handshake_dispatch_and_receipt_commit(void) {
  test_context_t context;
  connection_fake_io_t fake;
  connection_event_capture_t capture;
  mesh_mgmt_connection_config_v1_t config;
  mesh_mgmt_connection_v1_t connection;
  uint8_t hello_frame[MESH_MGMT_FRAME_MAX];
  uint8_t ack_frame[MESH_MGMT_FRAME_MAX];
  uint8_t probe_frame[MESH_MGMT_FRAME_MAX];
  uint8_t command_frame[MESH_MGMT_FRAME_MAX];
  size_t hello_frame_len = 0u;
  size_t ack_frame_len = 0u;
  size_t probe_frame_len = 0u;
  size_t command_frame_len = 0u;

  memset(&fake, 0, sizeof(fake));
  memset(&capture, 0, sizeof(capture));
  memset(&connection, 0, sizeof(connection));
  prepare_connection_config(&context, &fake, &capture, &config);
  build_connection_handshake(&context, hello_frame, &hello_frame_len, ack_frame, &ack_frame_len);
  probe_frame_len = sign_remote_frame_values(&context, MESH_MGMT_KIND_PROBE, NULL, 0u,
                                             TEST_CERT_SERIAL, 3u, 0x10, 16u, 0x51, probe_frame);
  command_frame_len =
      sign_remote_frame_values(&context, MESH_MGMT_KIND_COMMAND_REQUEST, NULL, 0u, TEST_CERT_SERIAL,
                               3u, 0x10, 17u, 0x52, command_frame);
  fake.frames[0] = hello_frame;
  fake.frame_lengths[0] = hello_frame_len;
  fake.frames[1] = ack_frame;
  fake.frame_lengths[1] = ack_frame_len;
  fake.frames[2] = probe_frame;
  fake.frame_lengths[2] = probe_frame_len;
  fake.frame_count = 3u;

  check_int_eq(mesh_mgmt_connection_init_v1(&connection, &config), MESH_MGMT_CONNECTION_OK);
  check_int_eq(mesh_mgmt_connection_send_v1(&connection, probe_frame, probe_frame_len),
               MESH_MGMT_CONNECTION_INVALID_STATE);
  check_size_eq(fake.send_count, 0u);
  check_int_eq(mesh_mgmt_connection_send_hello_v1(&connection, hello_frame, hello_frame_len),
               MESH_MGMT_CONNECTION_OK);
  check_int_eq(mesh_mgmt_connection_pump_once_v1(&connection, TEST_NOW_MS),
               MESH_MGMT_CONNECTION_OK);
  check_int_eq(capture.events[0], MESH_MGMT_DISPATCH_EVENT_HELLO_ACK_REQUIRED);
  check_mem_eq(capture.hello_ack.peer_connection_id, context.remote_connection_id, 16);
  check_int_eq(mesh_mgmt_connection_send_hello_ack_v1(&connection, ack_frame, ack_frame_len),
               MESH_MGMT_CONNECTION_OK);
  check_int_eq(mesh_mgmt_connection_pump_once_v1(&connection, TEST_NOW_MS),
               MESH_MGMT_CONNECTION_OK);
  check_int_eq(capture.events[1], MESH_MGMT_DISPATCH_EVENT_SESSION_ESTABLISHED);
  check_int_eq(mesh_mgmt_connection_pump_once_v1(&connection, TEST_NOW_MS),
               MESH_MGMT_CONNECTION_OK);
  check_int_eq(capture.events[2], MESH_MGMT_DISPATCH_EVENT_MEMBERSHIP);
  check_int_eq(connection.dispatcher.session.state, MESH_MGMT_SESSION_ESTABLISHED);
  check_hex64_eq(connection.dispatcher.replay.last_sequence, 16u);
  check_hex64_eq(connection.transport.generation, 4u);
  check_size_eq(capture.event_count, 3u);
  check_size_eq(fake.release_count, 3u);
  check_int_eq(mesh_mgmt_connection_send_v1(&connection, command_frame, command_frame_len),
               MESH_MGMT_CONNECTION_INVALID_FRAME);
  check_int_eq(connection.last_dispatch_result, MESH_MGMT_DISPATCH_SIDE_EFFECT_DISABLED);
  check_size_eq(fake.send_count, 2u);
  check_int_eq(mesh_mgmt_connection_send_v1(&connection, probe_frame, probe_frame_len),
               MESH_MGMT_CONNECTION_OK);
  check_size_eq(fake.send_count, 3u);
  mesh_mgmt_connection_destroy_v1(&connection);
}

static void test_connection_commits_before_terminal_callback_rejection(void) {
  test_context_t context;
  connection_fake_io_t fake;
  connection_event_capture_t capture;
  mesh_mgmt_connection_config_v1_t config;
  mesh_mgmt_connection_v1_t connection;
  uint8_t hello_frame[MESH_MGMT_FRAME_MAX];
  uint8_t ack_frame[MESH_MGMT_FRAME_MAX];
  size_t hello_frame_len = 0u;
  size_t ack_frame_len = 0u;

  memset(&fake, 0, sizeof(fake));
  memset(&capture, 0, sizeof(capture));
  memset(&connection, 0, sizeof(connection));
  prepare_connection_config(&context, &fake, &capture, &config);
  build_connection_handshake(&context, hello_frame, &hello_frame_len, ack_frame, &ack_frame_len);
  fake.frames[0] = hello_frame;
  fake.frame_lengths[0] = hello_frame_len;
  fake.frame_count = 1u;
  capture.reject_result = 73;

  check_int_eq(mesh_mgmt_connection_init_v1(&connection, &config), MESH_MGMT_CONNECTION_OK);
  check_int_eq(mesh_mgmt_connection_send_hello_v1(&connection, hello_frame, hello_frame_len),
               MESH_MGMT_CONNECTION_OK);
  check_int_eq(mesh_mgmt_connection_pump_once_v1(&connection, TEST_NOW_MS),
               MESH_MGMT_CONNECTION_EVENT_REJECTED);
  check_int_eq(connection.state, MESH_MGMT_CONNECTION_TERMINAL);
  check_int_eq(connection.last_event_result, 73);
  check_hex64_eq(connection.transport.generation, 2u);
  check_false(connection.transport.frame_ready);
  check_true(connection.dispatcher.session.remote_hello_verified);
  check_int_eq(mesh_mgmt_connection_send_v1(&connection, hello_frame, hello_frame_len),
               MESH_MGMT_CONNECTION_EVENT_REJECTED);
  mesh_mgmt_connection_destroy_v1(&connection);
}

static void test_connection_commits_and_closes_on_authentication_failure(void) {
  test_context_t context;
  connection_fake_io_t fake;
  connection_event_capture_t capture;
  mesh_mgmt_connection_config_v1_t config;
  mesh_mgmt_connection_v1_t connection;
  uint8_t hello_frame[MESH_MGMT_FRAME_MAX];
  uint8_t ack_frame[MESH_MGMT_FRAME_MAX];
  uint8_t tampered_frame[MESH_MGMT_FRAME_MAX];
  size_t hello_frame_len = 0u;
  size_t ack_frame_len = 0u;

  memset(&fake, 0, sizeof(fake));
  memset(&capture, 0, sizeof(capture));
  memset(&connection, 0, sizeof(connection));
  prepare_connection_config(&context, &fake, &capture, &config);
  build_connection_handshake(&context, hello_frame, &hello_frame_len, ack_frame, &ack_frame_len);
  memcpy(tampered_frame, hello_frame, hello_frame_len);
  tampered_frame[hello_frame_len - 1u] ^= 1u;
  fake.frames[0] = tampered_frame;
  fake.frame_lengths[0] = hello_frame_len;
  fake.frame_count = 1u;

  check_int_eq(mesh_mgmt_connection_init_v1(&connection, &config), MESH_MGMT_CONNECTION_OK);
  check_int_eq(mesh_mgmt_connection_send_hello_v1(&connection, hello_frame, hello_frame_len),
               MESH_MGMT_CONNECTION_OK);
  check_int_eq(mesh_mgmt_connection_pump_once_v1(&connection, TEST_NOW_MS),
               MESH_MGMT_CONNECTION_DISPATCH_FAILED);
  check_int_eq(connection.state, MESH_MGMT_CONNECTION_TERMINAL);
  check_int_eq(connection.last_dispatch_result, MESH_MGMT_DISPATCH_AUTH_FAILED);
  check_int_eq(connection.last_dispatch_stage, MESH_MGMT_DISPATCH_STAGE_SESSION);
  check_hex64_eq(connection.transport.generation, 2u);
  check_false(connection.transport.frame_ready);
  check_size_eq(capture.event_count, 0u);
  mesh_mgmt_connection_destroy_v1(&connection);
}

typedef struct {
  const uint8_t *hello_frame;
  size_t hello_frame_len;
  const uint8_t *ack_frame;
  size_t ack_frame_len;
  size_t hello_calls;
  size_t ack_calls;
  int hello_result;
  int ack_result;
  mesh_mgmt_hello_ack_v1_t observed_ack;
} peer_builder_t;

typedef struct {
  uint8_t next_message_first;
} peer_signer_callbacks_t;

static uint64_t peer_signer_now_ms(void *context) {
  (void)context;
  return TEST_NOW_MS;
}

static int peer_signer_random_bytes(void *context, uint8_t *output, size_t output_len) {
  peer_signer_callbacks_t *callbacks = (peer_signer_callbacks_t *)context;
  fill_bytes(output, output_len, callbacks->next_message_first);
  callbacks->next_message_first = (uint8_t)(callbacks->next_message_first + 0x10u);
  return 0;
}

static int peer_build_hello(void *context, const uint8_t **out_frame, size_t *out_frame_len) {
  peer_builder_t *builder = (peer_builder_t *)context;
  builder->hello_calls++;
  if (builder->hello_result != 0)
    return builder->hello_result;
  *out_frame = builder->hello_frame;
  *out_frame_len = builder->hello_frame_len;
  return 0;
}

static int peer_build_ack(void *context, const mesh_mgmt_hello_ack_v1_t *ack,
                          const uint8_t **out_frame, size_t *out_frame_len) {
  peer_builder_t *builder = (peer_builder_t *)context;
  builder->ack_calls++;
  builder->observed_ack = *ack;
  if (builder->ack_result != 0)
    return builder->ack_result;
  *out_frame = builder->ack_frame;
  *out_frame_len = builder->ack_frame_len;
  return 0;
}

static void prepare_peer_config(test_context_t *context, connection_fake_io_t *fake,
                                connection_event_capture_t *capture, peer_builder_t *builder,
                                mesh_mgmt_peer_config_v1_t *config) {
  memset(config, 0, sizeof(*config));
  prepare_connection_config(context, fake, capture, &config->connection);
  memcpy(config->local_transport_peer_id, context->transport_peer_id, 32);
  config->build_hello = peer_build_hello;
  config->build_ack = peer_build_ack;
  config->builder_context = builder;
}

static void build_local_peer_handshake(const test_context_t *context,
                                       uint8_t hello_frame[MESH_MGMT_FRAME_MAX],
                                       size_t *hello_frame_len,
                                       uint8_t ack_frame[MESH_MGMT_FRAME_MAX],
                                       size_t *ack_frame_len) {
  mesh_mgmt_hello_v1_t hello = context->hello;
  mesh_mgmt_hello_ack_v1_t ack;
  uint8_t hello_payload[MESH_MGMT_HELLO_V1_MAX_SIZE];
  uint8_t ack_payload[MESH_MGMT_HELLO_ACK_V1_SIZE];
  size_t hello_payload_len = 0u;
  size_t ack_payload_len = 0u;

  hello.min_minor = context->session_config.min_minor;
  hello.max_minor = context->session_config.max_minor;
  hello.features = context->session_config.features;
  memcpy(hello.connection_id, context->session_config.connection_id, 16);
  hello.max_frame = context->session_config.max_frame;
  hello.max_digest_entries = context->session_config.max_digest_entries;
  hello.max_delta_batch = context->session_config.max_delta_batch;
  check_int_eq(
      mesh_mgmt_hello_encode_v1(&hello, hello_payload, sizeof(hello_payload), &hello_payload_len),
      MESH_MGMT_SESSION_OK);

  memset(&ack, 0, sizeof(ack));
  ack.selected_major = MESH_MGMT_MAJOR_V1;
  ack.selected_minor = MESH_MGMT_MINOR_V1;
  ack.features = context->hello.features & context->session_config.features;
  ack.max_frame = context->hello.max_frame < context->session_config.max_frame
                      ? context->hello.max_frame
                      : context->session_config.max_frame;
  ack.max_digest_entries =
      context->hello.max_digest_entries < context->session_config.max_digest_entries
          ? context->hello.max_digest_entries
          : context->session_config.max_digest_entries;
  ack.max_delta_batch = context->hello.max_delta_batch < context->session_config.max_delta_batch
                            ? context->hello.max_delta_batch
                            : context->session_config.max_delta_batch;
  memcpy(ack.peer_connection_id, context->remote_connection_id, 16);
  check_int_eq(
      mesh_mgmt_hello_ack_encode_v1(&ack, ack_payload, sizeof(ack_payload), &ack_payload_len),
      MESH_MGMT_SESSION_OK);
  *hello_frame_len = sign_remote_frame(context, MESH_MGMT_KIND_HELLO, hello_payload,
                                       hello_payload_len, TEST_CERT_SERIAL, hello_frame);
  *ack_frame_len = sign_remote_frame(context, MESH_MGMT_KIND_HELLO_ACK, ack_payload,
                                     ack_payload_len, TEST_CERT_SERIAL, ack_frame);
}

static void prepare_local_peer_signer(const test_context_t *context,
                                      peer_signer_callbacks_t *callbacks,
                                      mesh_mgmt_peer_signer_config_v1_t *config) {
  memset(config, 0, sizeof(*config));
  memcpy(config->private_key, REMOTE_PRIVATE_KEY, sizeof(config->private_key));
  memcpy(config->trusted_issuer_key, context->root_public_key, sizeof(config->trusted_issuer_key));
  memcpy(config->expected_mesh_id_hash, context->mesh_id_hash,
         sizeof(config->expected_mesh_id_hash));
  memcpy(config->local_transport_peer_id, context->transport_peer_id,
         sizeof(config->local_transport_peer_id));
  config->hello = context->hello;
  config->hello.min_minor = context->session_config.min_minor;
  config->hello.max_minor = context->session_config.max_minor;
  config->hello.features = context->session_config.features;
  memcpy(config->hello.connection_id, context->session_config.connection_id,
         sizeof(config->hello.connection_id));
  config->hello.max_frame = context->session_config.max_frame;
  config->hello.max_digest_entries = context->session_config.max_digest_entries;
  config->hello.max_delta_batch = context->session_config.max_delta_batch;
  fill_bytes(config->session_id, sizeof(config->session_id), 0x30u);
  config->incarnation = 9u;
  config->first_sequence = 100u;
  config->frame_ttl_ms = 100u;
  config->now_ms = peer_signer_now_ms;
  config->random_bytes = peer_signer_random_bytes;
  config->callback_context = callbacks;
}

static void test_peer_uses_live_signer_builder_contract(void) {
  test_context_t context;
  connection_fake_io_t fake;
  connection_event_capture_t capture;
  peer_signer_callbacks_t callbacks;
  mesh_mgmt_peer_signer_config_v1_t signer_config;
  mesh_mgmt_peer_signer_v1_t signer;
  mesh_mgmt_peer_config_v1_t config;
  mesh_mgmt_peer_v1_t peer;
  mesh_mgmt_verified_envelope_v1_t sent;
  uint8_t hello_frame[MESH_MGMT_FRAME_MAX];
  uint8_t ack_frame[MESH_MGMT_FRAME_MAX];
  size_t hello_frame_len = 0u;
  size_t ack_frame_len = 0u;

  memset(&fake, 0, sizeof(fake));
  memset(&capture, 0, sizeof(capture));
  memset(&callbacks, 0, sizeof(callbacks));
  memset(&signer, 0, sizeof(signer));
  memset(&config, 0, sizeof(config));
  memset(&peer, 0, sizeof(peer));
  callbacks.next_message_first = 0x60u;
  prepare_connection_config(&context, &fake, &capture, &config.connection);
  prepare_local_peer_signer(&context, &callbacks, &signer_config);
  check_int_eq(mesh_mgmt_peer_signer_init_v1(&signer, &signer_config), MESH_MGMT_PEER_SIGNER_OK);
  memcpy(config.local_transport_peer_id, context.transport_peer_id,
         sizeof(config.local_transport_peer_id));
  config.build_hello = mesh_mgmt_peer_signer_build_hello_v1;
  config.build_ack = mesh_mgmt_peer_signer_build_ack_v1;
  config.builder_context = &signer;
  build_connection_handshake(&context, hello_frame, &hello_frame_len, ack_frame, &ack_frame_len);
  fake.frames[0] = hello_frame;
  fake.frame_lengths[0] = hello_frame_len;
  fake.frames[1] = ack_frame;
  fake.frame_lengths[1] = ack_frame_len;
  fake.frame_count = 2u;

  check_int_eq(mesh_mgmt_peer_init_v1(&peer, &config), MESH_MGMT_PEER_OK);
  check_int_eq(mesh_mgmt_peer_start_v1(&peer, TEST_NOW_MS), MESH_MGMT_PEER_OK);
  check_int_eq(mesh_mgmt_envelope_verify_v1(fake.last_sent, fake.last_sent_len, &sent),
               MESH_MGMT_ENVELOPE_OK);
  check_int_eq(sent.frame.kind, MESH_MGMT_KIND_HELLO);
  check_hex64_eq(sent.header.origin_sequence, 100u);
  check_int_eq(mesh_mgmt_peer_pump_once_v1(&peer, TEST_NOW_MS), MESH_MGMT_PEER_OK);
  check_int_eq(mesh_mgmt_envelope_verify_v1(fake.last_sent, fake.last_sent_len, &sent),
               MESH_MGMT_ENVELOPE_OK);
  check_int_eq(sent.frame.kind, MESH_MGMT_KIND_HELLO_ACK);
  check_hex64_eq(sent.header.origin_sequence, 101u);
  check_int_eq(mesh_mgmt_peer_pump_once_v1(&peer, TEST_NOW_MS), MESH_MGMT_PEER_OK);
  check_int_eq(peer.connection.dispatcher.session.state, MESH_MGMT_SESSION_ESTABLISHED);
  check_true(signer.hello_built);
  check_true(signer.ack_built);
  check_hex64_eq(signer.next_sequence, 102u);
  mesh_mgmt_peer_destroy_v1(&peer);
  mesh_mgmt_peer_signer_destroy_v1(&signer);
}

static void test_peer_automates_hello_and_ack_after_receipt_commit(void) {
  test_context_t context;
  connection_fake_io_t fake;
  connection_event_capture_t capture;
  peer_builder_t builder;
  mesh_mgmt_peer_config_v1_t config;
  mesh_mgmt_peer_v1_t peer;
  uint8_t hello_frame[MESH_MGMT_FRAME_MAX];
  uint8_t ack_frame[MESH_MGMT_FRAME_MAX];
  uint8_t local_hello_frame[MESH_MGMT_FRAME_MAX];
  uint8_t local_ack_frame[MESH_MGMT_FRAME_MAX];
  size_t hello_frame_len = 0u;
  size_t ack_frame_len = 0u;
  size_t local_hello_frame_len = 0u;
  size_t local_ack_frame_len = 0u;

  memset(&fake, 0, sizeof(fake));
  memset(&capture, 0, sizeof(capture));
  memset(&builder, 0, sizeof(builder));
  memset(&peer, 0, sizeof(peer));
  prepare_peer_config(&context, &fake, &capture, &builder, &config);
  build_connection_handshake(&context, hello_frame, &hello_frame_len, ack_frame, &ack_frame_len);
  build_local_peer_handshake(&context, local_hello_frame, &local_hello_frame_len, local_ack_frame,
                             &local_ack_frame_len);
  builder.hello_frame = local_hello_frame;
  builder.hello_frame_len = local_hello_frame_len;
  builder.ack_frame = local_ack_frame;
  builder.ack_frame_len = local_ack_frame_len;
  fake.frames[0] = hello_frame;
  fake.frame_lengths[0] = hello_frame_len;
  fake.frames[1] = ack_frame;
  fake.frame_lengths[1] = ack_frame_len;
  fake.frame_count = 2u;

  check_int_eq(mesh_mgmt_peer_init_v1(&peer, &config), MESH_MGMT_PEER_OK);
  check_int_eq(mesh_mgmt_peer_pump_once_v1(&peer, TEST_NOW_MS), MESH_MGMT_PEER_INVALID_STATE);
  check_int_eq(mesh_mgmt_peer_start_v1(&peer, TEST_NOW_MS), MESH_MGMT_PEER_OK);
  check_size_eq(builder.hello_calls, 1u);
  check_size_eq(fake.send_count, 1u);
  check_int_eq(mesh_mgmt_peer_pump_once_v1(&peer, TEST_NOW_MS), MESH_MGMT_PEER_OK);
  check_size_eq(builder.ack_calls, 1u);
  check_size_eq(fake.send_count, 2u);
  check_hex64_eq(peer.connection.transport.generation, 2u);
  check_mem_eq(builder.observed_ack.peer_connection_id, context.remote_connection_id, 16);
  check_int_eq(mesh_mgmt_peer_pump_once_v1(&peer, TEST_NOW_MS), MESH_MGMT_PEER_OK);
  check_int_eq(peer.connection.dispatcher.session.state, MESH_MGMT_SESSION_ESTABLISHED);
  check_hex64_eq(peer.connection.transport.generation, 3u);
  check_int_eq(capture.events[0], MESH_MGMT_DISPATCH_EVENT_HELLO_ACK_REQUIRED);
  check_int_eq(capture.events[1], MESH_MGMT_DISPATCH_EVENT_SESSION_ESTABLISHED);
  check_int_eq(mesh_mgmt_peer_start_v1(&peer, TEST_NOW_MS), MESH_MGMT_PEER_INVALID_STATE);
  mesh_mgmt_peer_destroy_v1(&peer);
}

static void test_peer_rejects_signed_mismatched_ack_after_commit(void) {
  test_context_t context;
  connection_fake_io_t fake;
  connection_event_capture_t capture;
  peer_builder_t builder;
  mesh_mgmt_peer_config_v1_t config;
  mesh_mgmt_peer_v1_t peer;
  uint8_t hello_frame[MESH_MGMT_FRAME_MAX];
  uint8_t ack_frame[MESH_MGMT_FRAME_MAX];
  uint8_t local_hello_frame[MESH_MGMT_FRAME_MAX];
  uint8_t local_ack_frame[MESH_MGMT_FRAME_MAX];
  size_t hello_frame_len = 0u;
  size_t ack_frame_len = 0u;
  size_t local_hello_frame_len = 0u;
  size_t local_ack_frame_len = 0u;

  memset(&fake, 0, sizeof(fake));
  memset(&capture, 0, sizeof(capture));
  memset(&builder, 0, sizeof(builder));
  memset(&peer, 0, sizeof(peer));
  prepare_peer_config(&context, &fake, &capture, &builder, &config);
  build_connection_handshake(&context, hello_frame, &hello_frame_len, ack_frame, &ack_frame_len);
  build_local_peer_handshake(&context, local_hello_frame, &local_hello_frame_len, local_ack_frame,
                             &local_ack_frame_len);
  builder.hello_frame = local_hello_frame;
  builder.hello_frame_len = local_hello_frame_len;
  builder.ack_frame = ack_frame;
  builder.ack_frame_len = ack_frame_len;
  fake.frames[0] = hello_frame;
  fake.frame_lengths[0] = hello_frame_len;
  fake.frame_count = 1u;

  check_int_eq(mesh_mgmt_peer_init_v1(&peer, &config), MESH_MGMT_PEER_OK);
  check_int_eq(mesh_mgmt_peer_start_v1(&peer, TEST_NOW_MS), MESH_MGMT_PEER_OK);
  check_int_eq(mesh_mgmt_peer_pump_once_v1(&peer, TEST_NOW_MS), MESH_MGMT_PEER_BUILD_FAILED);
  check_int_eq(peer.state, MESH_MGMT_PEER_TERMINAL);
  check_int_eq(peer.last_builder_result, MESH_MGMT_PEER_BUILDER_INVALID_ACK);
  check_int_eq(peer.connection.state, MESH_MGMT_CONNECTION_TERMINAL);
  check_int_eq(peer.connection.last_error, MESH_MGMT_CONNECTION_LOCAL_FAILED);
  check_hex64_eq(peer.connection.transport.generation, 2u);
  check_false(peer.connection.transport.frame_ready);
  check_size_eq(builder.ack_calls, 1u);
  check_size_eq(fake.send_count, 1u);
  check_size_eq(capture.event_count, 1u);
  check_int_eq(mesh_mgmt_peer_pump_once_v1(&peer, TEST_NOW_MS), MESH_MGMT_PEER_BUILD_FAILED);
  mesh_mgmt_peer_destroy_v1(&peer);
}

static void test_peer_consumer_rejection_never_builds_or_sends_ack(void) {
  test_context_t context;
  connection_fake_io_t fake;
  connection_event_capture_t capture;
  peer_builder_t builder;
  mesh_mgmt_peer_config_v1_t config;
  mesh_mgmt_peer_v1_t peer;
  uint8_t hello_frame[MESH_MGMT_FRAME_MAX];
  uint8_t ack_frame[MESH_MGMT_FRAME_MAX];
  uint8_t local_hello_frame[MESH_MGMT_FRAME_MAX];
  uint8_t local_ack_frame[MESH_MGMT_FRAME_MAX];
  size_t hello_frame_len = 0u;
  size_t ack_frame_len = 0u;
  size_t local_hello_frame_len = 0u;
  size_t local_ack_frame_len = 0u;

  memset(&fake, 0, sizeof(fake));
  memset(&capture, 0, sizeof(capture));
  memset(&builder, 0, sizeof(builder));
  memset(&peer, 0, sizeof(peer));
  prepare_peer_config(&context, &fake, &capture, &builder, &config);
  build_connection_handshake(&context, hello_frame, &hello_frame_len, ack_frame, &ack_frame_len);
  build_local_peer_handshake(&context, local_hello_frame, &local_hello_frame_len, local_ack_frame,
                             &local_ack_frame_len);
  builder.hello_frame = local_hello_frame;
  builder.hello_frame_len = local_hello_frame_len;
  builder.ack_frame = local_ack_frame;
  builder.ack_frame_len = local_ack_frame_len;
  capture.reject_result = 73;
  fake.frames[0] = hello_frame;
  fake.frame_lengths[0] = hello_frame_len;
  fake.frame_count = 1u;

  check_int_eq(mesh_mgmt_peer_init_v1(&peer, &config), MESH_MGMT_PEER_OK);
  check_int_eq(mesh_mgmt_peer_start_v1(&peer, TEST_NOW_MS), MESH_MGMT_PEER_OK);
  check_int_eq(mesh_mgmt_peer_pump_once_v1(&peer, TEST_NOW_MS), MESH_MGMT_PEER_CONNECTION_FAILED);
  check_int_eq(peer.state, MESH_MGMT_PEER_TERMINAL);
  check_int_eq(peer.last_connection_result, MESH_MGMT_CONNECTION_EVENT_REJECTED);
  check_int_eq(peer.connection.last_error, MESH_MGMT_CONNECTION_EVENT_REJECTED);
  check_hex64_eq(peer.connection.transport.generation, 2u);
  check_size_eq(builder.ack_calls, 0u);
  check_size_eq(fake.send_count, 1u);
  mesh_mgmt_peer_destroy_v1(&peer);
}

static void test_peer_rejects_invalid_local_hello_before_io(void) {
  test_context_t context;
  connection_fake_io_t fake;
  connection_event_capture_t capture;
  peer_builder_t builder;
  mesh_mgmt_peer_config_v1_t config;
  mesh_mgmt_peer_v1_t peer;
  uint8_t local_hello_frame[MESH_MGMT_FRAME_MAX];
  uint8_t local_ack_frame[MESH_MGMT_FRAME_MAX];
  size_t local_hello_frame_len = 0u;
  size_t local_ack_frame_len = 0u;

  memset(&fake, 0, sizeof(fake));
  memset(&capture, 0, sizeof(capture));
  memset(&builder, 0, sizeof(builder));
  memset(&peer, 0, sizeof(peer));
  prepare_peer_config(&context, &fake, &capture, &builder, &config);
  build_local_peer_handshake(&context, local_hello_frame, &local_hello_frame_len, local_ack_frame,
                             &local_ack_frame_len);
  local_hello_frame[local_hello_frame_len - 1u] ^= 1u;
  builder.hello_frame = local_hello_frame;
  builder.hello_frame_len = local_hello_frame_len;

  check_int_eq(mesh_mgmt_peer_init_v1(&peer, &config), MESH_MGMT_PEER_OK);
  check_int_eq(mesh_mgmt_peer_start_v1(&peer, TEST_NOW_MS), MESH_MGMT_PEER_BUILD_FAILED);
  check_int_eq(peer.last_builder_result, MESH_MGMT_PEER_BUILDER_INVALID_HELLO);
  check_int_eq(peer.connection.last_error, MESH_MGMT_CONNECTION_LOCAL_FAILED);
  check_size_eq(fake.send_count, 0u);
  check_size_eq(builder.hello_calls, 1u);
  mesh_mgmt_peer_destroy_v1(&peer);
}

spec("mesh management identity and HELLO session") {
  describe("direct trust certificate") {
    it("verifies issuer, mesh, node and key claims") {
      test_certificate_verifies_direct_trust_binding();
    }
    it("rejects tampering, expiry and incomplete node binding") {
      test_certificate_rejects_tamper_expiry_and_missing_node_binding();
    }
  }
  describe("fail-closed HELLO negotiation") {
    it("establishes only after both HELLO acknowledgements") {
      test_session_establishes_only_after_mutual_ack();
    }
    it("rejects transport and envelope certificate mismatches") {
      test_session_rejects_transport_and_header_binding_mismatch();
    }
    it("verifies the raw envelope inside the session boundary") {
      test_session_rejects_raw_frame_without_valid_envelope_signature();
    }
    it("rejects a signed capability downgrade in HELLO_ACK") {
      test_session_rejects_downgraded_ack();
    }
    it("binds HELLO_ACK to the HELLO origin session") {
      test_session_rejects_ack_from_changed_origin_session();
    }
  }
  describe("observer-only raw frame dispatcher") {
    it("owns envelope, session, replay and typed dispatch ordering") {
      test_dispatcher_owns_verify_session_replay_and_typed_order();
    }
    it("does not consume replay state for disabled side effects") {
      test_dispatcher_rejects_side_effect_without_consuming_replay();
    }
    it("rejects an unnegotiated stream ticket without consuming replay") {
      test_dispatcher_rejects_unnegotiated_stream_ticket_without_replay();
    }
  }
  describe("single-owner management connection") {
    it("serializes handshake, dispatch and receipt commit") {
      test_connection_owns_handshake_dispatch_and_receipt_commit();
    }
    it("commits a delivered frame before callback rejection is terminal") {
      test_connection_commits_before_terminal_callback_rejection();
    }
    it("commits a rejected frame and closes on authentication failure") {
      test_connection_commits_and_closes_on_authentication_failure();
    }
  }
  describe("automatic adjacent peer handshake") {
    it("rejects an invalid local HELLO before socket IO") {
      test_peer_rejects_invalid_local_hello_before_io();
    }
    it("sends HELLO and ACK only after accepted receipt commit") {
      test_peer_automates_hello_and_ack_after_receipt_commit();
    }
    it("rejects a signed ACK that does not match accepted negotiation") {
      test_peer_rejects_signed_mismatched_ack_after_commit();
    }
    it("does not build or send ACK after consumer rejection") {
      test_peer_consumer_rejection_never_builds_or_sends_ack();
    }
    it("uses the live local signer callback contract") {
      test_peer_uses_live_signer_builder_contract();
    }
  }
}
