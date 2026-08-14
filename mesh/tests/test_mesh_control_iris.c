#include "mesh_control_iris.h"
#include "tinytest.h"

#include <string.h>

static const uint8_t TEST_PRIVATE_KEY[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};

typedef struct {
  mesh_control_result_t admission_result;
  size_t admissions;
} test_auth_context_t;

static mesh_control_result_t allow_transport(
    void *context,
    const char peer_certificate_sha256[CORO_TLS_PEER_CERT_SHA256_CAPACITY]) {
  (void)context;
  (void)peer_certificate_sha256;
  return MESH_CONTROL_OK;
}

static mesh_control_result_t admit_message(
    void *context, const mesh_mgmt_verified_envelope_v1_t *verified,
    const mesh_control_envelope_v1_t *envelope, const uint8_t *body,
    size_t body_size) {
  test_auth_context_t *auth = (test_auth_context_t *)context;

  check_not_null(verified);
  check_not_null(envelope);
  check_not_null(body);
  check_int_eq(body_size, 3u);
  auth->admissions++;
  return auth->admission_result;
}

static size_t make_signed_frame(uint8_t frame[MESH_MGMT_FRAME_MAX]) {
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
  envelope.epoch = 2u;
  envelope.precondition_epoch = 1u;
  envelope.sequence = 3u;
  envelope.issued_at_ms = 1000u;
  envelope.expires_at_ms = 2000u;
  envelope.payload_size = sizeof(body);
  for (index = 0u; index < MESH_CONTROL_ID_SIZE; ++index) {
    envelope.message_id[index] = (uint8_t)(0x10u + index);
    envelope.request_id[index] = (uint8_t)(0x20u + index);
  }
  for (index = 0u; index < MESH_CONTROL_DIGEST_SIZE; ++index) {
    envelope.mesh_id[index] = (uint8_t)(0x30u + index);
    envelope.target_node_id[index] = (uint8_t)(0x40u + index);
    envelope.resource_id[index] = (uint8_t)(0x50u + index);
    envelope.origin_principal[index] = (uint8_t)(0x60u + index);
  }
  check_int_eq(mesh_control_mmp_body_digest_v1(
                   body, sizeof(body), envelope.payload_digest),
               MESH_CONTROL_MMP_OK);
  check_int_eq(mesh_control_mmp_payload_encode_v1(
                   &envelope, body, sizeof(body), payload, sizeof(payload),
                   &payload_size),
               MESH_CONTROL_MMP_OK);

  memset(&sign_input, 0, sizeof(sign_input));
  sign_input.minor = MESH_MGMT_MINOR_V1;
  sign_input.kind = MESH_MGMT_KIND_CONTROL_FRAME;
  sign_input.private_key = TEST_PRIVATE_KEY;
  sign_input.payload = payload;
  sign_input.payload_len = payload_size;
  memcpy(sign_input.header.mesh_id_hash, envelope.mesh_id,
         sizeof(sign_input.header.mesh_id_hash));
  memcpy(sign_input.header.origin_node_id, envelope.target_node_id,
         sizeof(sign_input.header.origin_node_id));
  memcpy(sign_input.header.target_node_id, envelope.target_node_id,
         sizeof(sign_input.header.target_node_id));
  sign_input.header.principal_epoch = 1u;
  sign_input.header.incarnation = 1u;
  sign_input.header.session_id[0] = 1u;
  sign_input.header.origin_sequence = envelope.sequence;
  memcpy(sign_input.header.message_id, envelope.message_id,
         sizeof(sign_input.header.message_id));
  sign_input.header.issued_at_ms = envelope.issued_at_ms;
  sign_input.header.expires_at_ms = envelope.expires_at_ms;
  sign_input.header.certificate_serial = 1u;
  check_int_eq(mesh_mgmt_envelope_sign_v1(
                   &sign_input, frame, MESH_MGMT_FRAME_MAX, &frame_size),
               MESH_MGMT_ENVELOPE_OK);
  return frame_size;
}

static void test_verified_frame_is_admitted_and_copied_to_owner(void) {
  mesh_control_channel_v1_t channel;
  mesh_control_iris_v1_t adapter;
  mesh_control_iris_config_v1_t config;
  mesh_control_iris_stats_v1_t stats;
  mesh_control_message_view_v1_t view;
  test_auth_context_t auth = {MESH_CONTROL_OK, 0u};
  iris_app_t *app = iris_app_create();
  uint8_t frame[MESH_MGMT_FRAME_MAX];
  size_t frame_size;

  check_not_null(app);
  check_int_eq(mesh_control_channel_init_v1(&channel, 2u, 4096u, 1024u),
               MESH_CONTROL_OK);
  memset(&config, 0, sizeof(config));
  config.inbound = &channel;
  config.authorize_transport = allow_transport;
  config.admit = admit_message;
  config.auth_context = &auth;
  check_int_eq(mesh_control_iris_register_v1(&adapter, app, &config),
               MESH_CONTROL_OK);
  frame_size = make_signed_frame(frame);

  check_int_eq(mesh_control_iris_receive_frame_v1(
                   &adapter, frame, frame_size),
               MESH_CONTROL_OK);
  check_int_eq(auth.admissions, 1u);
  check_int_eq(mesh_control_channel_peek_v1(&channel, &view),
               MESH_CONTROL_OK);
  check_int_eq(view.envelope.resource_kind,
               MESH_CONTROL_RESOURCE_NETWORK);
  check_int_eq(view.payload_size, 3u);
  check_int_eq(view.payload[2], 3u);
  check_int_eq(mesh_control_channel_consume_v1(&channel), MESH_CONTROL_OK);
  check_int_eq(mesh_control_iris_get_stats_v1(&adapter, &stats),
               MESH_CONTROL_OK);
  check_int_eq(stats.received, 1u);
  check_int_eq(stats.queued, 1u);

  mesh_control_iris_destroy_v1(&adapter);
  mesh_control_channel_destroy_v1(&channel);
  iris_app_destroy(app);
}

static void test_invalid_signature_admission_and_backpressure_fail_closed(void) {
  mesh_control_channel_v1_t channel;
  mesh_control_iris_v1_t adapter;
  mesh_control_iris_config_v1_t config;
  mesh_control_iris_stats_v1_t stats;
  test_auth_context_t auth = {MESH_CONTROL_OK, 0u};
  iris_app_t *app = iris_app_create();
  uint8_t frame[MESH_MGMT_FRAME_MAX];
  size_t frame_size;

  check_not_null(app);
  check_int_eq(mesh_control_channel_init_v1(&channel, 1u, 4096u, 1024u),
               MESH_CONTROL_OK);
  memset(&config, 0, sizeof(config));
  config.inbound = &channel;
  config.authorize_transport = allow_transport;
  config.admit = admit_message;
  config.auth_context = &auth;
  check_int_eq(mesh_control_iris_register_v1(&adapter, app, &config),
               MESH_CONTROL_OK);
  frame_size = make_signed_frame(frame);

  frame[frame_size - 1u] ^= 1u;
  check_int_eq(mesh_control_iris_receive_frame_v1(
                   &adapter, frame, frame_size),
               MESH_CONTROL_INVALID_ARG);
  frame[frame_size - 1u] ^= 1u;
  auth.admission_result = MESH_CONTROL_CONFLICT;
  check_int_eq(mesh_control_iris_receive_frame_v1(
                   &adapter, frame, frame_size),
               MESH_CONTROL_CONFLICT);
  auth.admission_result = MESH_CONTROL_OK;
  check_int_eq(mesh_control_iris_receive_frame_v1(
                   &adapter, frame, frame_size),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_iris_receive_frame_v1(
                   &adapter, frame, frame_size),
               MESH_CONTROL_RESOURCE_EXHAUSTED);
  check_int_eq(mesh_control_iris_close_v1(&adapter), MESH_CONTROL_OK);
  check_int_eq(mesh_control_iris_receive_frame_v1(
                   &adapter, frame, frame_size),
               MESH_CONTROL_CLOSED);
  check_int_eq(mesh_control_iris_get_stats_v1(&adapter, &stats),
               MESH_CONTROL_OK);
  check_int_eq(stats.rejected_protocol, 1u);
  check_int_eq(stats.rejected_admission, 1u);
  check_int_eq(stats.rejected_backpressure, 1u);

  mesh_control_iris_destroy_v1(&adapter);
  mesh_control_channel_destroy_v1(&channel);
  iris_app_destroy(app);
}

static void test_register_requires_both_authentication_layers(void) {
  mesh_control_channel_v1_t channel;
  mesh_control_iris_v1_t adapter;
  mesh_control_iris_config_v1_t config;
  iris_app_t *app = iris_app_create();

  check_not_null(app);
  check_int_eq(mesh_control_channel_init_v1(&channel, 1u, 4096u, 1024u),
               MESH_CONTROL_OK);
  memset(&config, 0, sizeof(config));
  config.inbound = &channel;
  check_int_eq(mesh_control_iris_register_v1(&adapter, app, &config),
               MESH_CONTROL_INVALID_ARG);
  config.authorize_transport = allow_transport;
  check_int_eq(mesh_control_iris_register_v1(&adapter, app, &config),
               MESH_CONTROL_INVALID_ARG);
  mesh_control_channel_destroy_v1(&channel);
  iris_app_destroy(app);
}

spec("mesh Iris H2 WebSocket control adapter") {
  describe("verified bounded ingress") {
    it("admits signed frames and copies them to the Mesh owner") {
      test_verified_frame_is_admitted_and_copied_to_owner();
    }
    it("fails closed on signature, policy and queue failures") {
      test_invalid_signature_admission_and_backpressure_fail_closed();
    }
    it("requires transport and signed-message authorization") {
      test_register_requires_both_authentication_layers();
    }
  }
}
