#include "mesh_control_mmp.h"
#include "tinytest.h"

#include <string.h>

static const uint8_t TEST_PRIVATE_KEY[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};

static void fill_control_envelope(mesh_control_envelope_v1_t *envelope,
                                  const uint8_t *body, size_t body_size) {
  size_t index;

  memset(envelope, 0, sizeof(*envelope));
  envelope->schema_version = MESH_CONTROL_SCHEMA_V1;
  envelope->kind = MESH_CONTROL_MESSAGE_INTENT;
  envelope->resource_kind = MESH_CONTROL_RESOURCE_FUNCTION;
  envelope->epoch = 9u;
  envelope->precondition_epoch = 8u;
  envelope->sequence = 7u;
  envelope->issued_at_ms = 1000u;
  envelope->expires_at_ms = 2000u;
  envelope->payload_size = body_size;
  for (index = 0u; index < MESH_CONTROL_ID_SIZE; ++index) {
    envelope->message_id[index] = (uint8_t)(0x10u + index);
    envelope->request_id[index] = (uint8_t)(0x20u + index);
  }
  for (index = 0u; index < MESH_CONTROL_DIGEST_SIZE; ++index) {
    envelope->mesh_id[index] = (uint8_t)(0x30u + index);
    envelope->origin_principal[index] = (uint8_t)(0x40u + index);
    envelope->target_node_id[index] = (uint8_t)(0x50u + index);
    envelope->resource_id[index] = (uint8_t)(0x60u + index);
  }
  check_int_eq(mesh_control_mmp_body_digest_v1(
                   body, body_size, envelope->payload_digest),
               MESH_CONTROL_MMP_OK);
}

static void fill_sign_input(mesh_mgmt_sign_input_v1_t *input,
                            const mesh_control_envelope_v1_t *envelope,
                            const uint8_t *payload, size_t payload_size) {
  memset(input, 0, sizeof(*input));
  input->minor = MESH_MGMT_MINOR_V1;
  input->kind = MESH_MGMT_KIND_CONTROL_FRAME;
  input->private_key = TEST_PRIVATE_KEY;
  input->payload = payload;
  input->payload_len = payload_size;
  memcpy(input->header.mesh_id_hash, envelope->mesh_id,
         sizeof(input->header.mesh_id_hash));
  memcpy(input->header.origin_node_id, envelope->target_node_id,
         sizeof(input->header.origin_node_id));
  memcpy(input->header.target_node_id, envelope->target_node_id,
         sizeof(input->header.target_node_id));
  input->header.principal_epoch = 3u;
  input->header.incarnation = 4u;
  input->header.session_id[0] = 1u;
  input->header.origin_sequence = envelope->sequence;
  memcpy(input->header.message_id, envelope->message_id,
         sizeof(input->header.message_id));
  input->header.issued_at_ms = envelope->issued_at_ms;
  input->header.expires_at_ms = envelope->expires_at_ms;
  input->header.certificate_serial = 5u;
}

static void test_signed_control_frame_round_trips(void) {
  static const uint8_t body[] = {0xdeu, 0xadu, 0xbeu, 0xefu};
  mesh_control_envelope_v1_t input_envelope;
  mesh_control_envelope_v1_t decoded_envelope;
  mesh_mgmt_sign_input_v1_t sign_input;
  mesh_mgmt_verified_envelope_v1_t verified;
  const uint8_t *decoded_body = NULL;
  uint8_t control_payload[256];
  uint8_t frame[MESH_MGMT_FRAME_MAX];
  size_t control_payload_size = 0u;
  size_t frame_size = 0u;
  size_t decoded_body_size = 0u;

  fill_control_envelope(&input_envelope, body, sizeof(body));
  check_int_eq(mesh_control_mmp_payload_encode_v1(
                   &input_envelope, body, sizeof(body), control_payload,
                   sizeof(control_payload), &control_payload_size),
               MESH_CONTROL_MMP_OK);
  check_int_eq(control_payload_size,
               MESH_CONTROL_MMP_PAYLOAD_HEADER_SIZE_V1 + sizeof(body));
  fill_sign_input(&sign_input, &input_envelope, control_payload,
                  control_payload_size);
  check_int_eq(mesh_mgmt_envelope_sign_v1(
                   &sign_input, frame, sizeof(frame), &frame_size),
               MESH_MGMT_ENVELOPE_OK);
  check_int_eq(mesh_mgmt_envelope_verify_v1(frame, frame_size, &verified),
               MESH_MGMT_ENVELOPE_OK);
  check_int_eq(mesh_control_mmp_payload_decode_v1(
                   &verified, &decoded_envelope, &decoded_body,
                   &decoded_body_size),
               MESH_CONTROL_MMP_OK);

  check_mem_eq(decoded_envelope.message_id, input_envelope.message_id,
               sizeof(input_envelope.message_id));
  check_mem_eq(decoded_envelope.mesh_id, input_envelope.mesh_id,
               sizeof(input_envelope.mesh_id));
  check_mem_eq(decoded_envelope.target_node_id,
               input_envelope.target_node_id,
               sizeof(input_envelope.target_node_id));
  check_mem_eq(decoded_envelope.request_id, input_envelope.request_id,
               sizeof(input_envelope.request_id));
  check_mem_eq(decoded_envelope.resource_id, input_envelope.resource_id,
               sizeof(input_envelope.resource_id));
  check_int_eq(decoded_envelope.kind, input_envelope.kind);
  check_int_eq(decoded_envelope.resource_kind,
               input_envelope.resource_kind);
  check_int_eq(decoded_envelope.epoch, input_envelope.epoch);
  check_int_eq(decoded_envelope.precondition_epoch,
               input_envelope.precondition_epoch);
  check_int_eq(decoded_body_size, sizeof(body));
  check_mem_eq(decoded_body, body, sizeof(body));
}

static void test_encode_checks_digest_and_capacity(void) {
  static const uint8_t body[] = {1u, 2u, 3u};
  mesh_control_envelope_v1_t envelope;
  uint8_t output[256];
  size_t output_size = 0u;

  fill_control_envelope(&envelope, body, sizeof(body));
  envelope.payload_digest[0] ^= 1u;
  check_int_eq(mesh_control_mmp_payload_encode_v1(
                   &envelope, body, sizeof(body), output, sizeof(output),
                   &output_size),
               MESH_CONTROL_MMP_DIGEST_MISMATCH);
  check_int_eq(output_size, 0u);

  fill_control_envelope(&envelope, body, sizeof(body));
  check_int_eq(mesh_control_mmp_payload_encode_v1(
                   &envelope, body, sizeof(body), output, 1u, &output_size),
               MESH_CONTROL_MMP_RESOURCE_EXHAUSTED);
  check_int_eq(output_size,
               MESH_CONTROL_MMP_PAYLOAD_HEADER_SIZE_V1 + sizeof(body));
}

static void test_decode_rejects_wrong_mmp_kind(void) {
  mesh_mgmt_verified_envelope_v1_t verified;
  mesh_control_envelope_v1_t envelope;
  const uint8_t *body = NULL;
  size_t body_size = 0u;

  memset(&verified, 0, sizeof(verified));
  verified.frame.kind = MESH_MGMT_KIND_COMMAND_REQUEST;
  check_int_eq(mesh_control_mmp_payload_decode_v1(
                   &verified, &envelope, &body, &body_size),
               MESH_CONTROL_MMP_INVALID_SCHEMA);
}

spec("mesh signed control payload over MMP") {
  describe("canonical resource envelope") {
    it("round trips inside a verified Ed25519 MMP frame") {
      test_signed_control_frame_round_trips();
    }
    it("checks body digest and output capacity before writing") {
      test_encode_checks_digest_and_capacity();
    }
    it("rejects non-control MMP frames") {
      test_decode_rejects_wrong_mmp_kind();
    }
  }
}
