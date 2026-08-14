#include <tinytest.h>

#include "mesh_mgmt_envelope.h"

#include <string.h>

static const uint8_t TEST_PRIVATE_KEY[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};

static const uint8_t TEST_PUBLIC_KEY[32] = {
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
    0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
};

static const uint8_t TEST_PAYLOAD[] = {
    0x00, 0x01, 0x00, 0x03, 0xaa, 0xbb, 0xcc,
};

static void fill_test_input(mesh_mgmt_sign_input_v1_t *input) {
    size_t index = 0;

    memset(input, 0, sizeof(*input));
    input->minor = MESH_MGMT_MINOR_V1;
    input->kind = MESH_MGMT_KIND_HELLO;
    input->private_key = TEST_PRIVATE_KEY;
    input->payload = TEST_PAYLOAD;
    input->payload_len = sizeof(TEST_PAYLOAD);
    for (index = 0; index < sizeof(input->header.mesh_id_hash); index++) {
        input->header.mesh_id_hash[index] = (uint8_t)(0x10u + index);
        input->header.origin_node_id[index] = (uint8_t)(0x40u + index);
        input->header.target_node_id[index] = (uint8_t)(0x80u + index);
    }
    for (index = 0; index < sizeof(input->header.session_id); index++) {
        input->header.session_id[index] = (uint8_t)(0xa0u + index);
        input->header.message_id[index] = (uint8_t)(0xc0u + index);
    }
    input->header.principal_epoch = 0x0102030405060708ULL;
    input->header.incarnation = 0x1112131415161718ULL;
    input->header.origin_sequence = 0x2122232425262728ULL;
    input->header.issued_at_ms = 1000;
    input->header.expires_at_ms = 2000;
    input->header.forward_budget = 1;
    input->header.certificate_serial = 0x3132333435363738ULL;
}

static size_t sign_test_frame(mesh_mgmt_sign_input_v1_t *input,
                              uint8_t frame[MESH_MGMT_FRAME_MAX]) {
    size_t frame_len = 0;

    check_int_eq(mesh_mgmt_envelope_sign_v1(
                     input, frame, MESH_MGMT_FRAME_MAX, &frame_len),
                 MESH_MGMT_ENVELOPE_OK);
    return frame_len;
}

static uint8_t *find_header_field_id(uint8_t *frame,
                                     size_t frame_len,
                                     uint16_t wanted_id) {
    mesh_mgmt_frame_view_t view;
    mesh_mgmt_tlv_reader_t reader;
    mesh_mgmt_tlv_view_t field;

    if (mesh_mgmt_frame_decode(frame, frame_len, &view) !=
        MESH_MGMT_CODEC_OK) {
        return NULL;
    }
    mesh_mgmt_tlv_reader_init(&reader, view.header, view.header_len);
    while (mesh_mgmt_tlv_reader_next(&reader, &field) == 1) {
        if (field.field_id == wanted_id) {
            return (uint8_t *)field.value - MESH_MGMT_TLV_PREFIX_SIZE;
        }
    }
    return NULL;
}

static void test_envelope_round_trips_authenticated_common_header(void) {
    mesh_mgmt_sign_input_v1_t input;
    mesh_mgmt_verified_envelope_v1_t verified;
    mesh_mgmt_tlv_reader_t reader;
    mesh_mgmt_tlv_view_t field;
    uint8_t frame[MESH_MGMT_FRAME_MAX] = {0};
    uint8_t payload_hash[32] = {0};
    size_t frame_len = 0;
    uint16_t expected_id = MESH_MGMT_HEADER_FIELD_MESH_ID_HASH;

    fill_test_input(&input);
    frame_len = sign_test_frame(&input, frame);
    check_size_eq(frame_len, MESH_MGMT_PREFIX_SIZE +
                                 MESH_MGMT_HEADER_V1_ENCODED_SIZE +
                                 sizeof(TEST_PAYLOAD) +
                                 MESH_MGMT_SIGNATURE_SIZE);
    check_int_eq(mesh_mgmt_envelope_verify_v1(frame, frame_len, &verified),
                 MESH_MGMT_ENVELOPE_OK);
    check_mem_eq(verified.header.origin_principal_key, TEST_PUBLIC_KEY,
                 sizeof(TEST_PUBLIC_KEY));
    check_mem_eq(verified.header.mesh_id_hash, input.header.mesh_id_hash,
                 sizeof(input.header.mesh_id_hash));
    check_mem_eq(verified.header.origin_node_id, input.header.origin_node_id,
                 sizeof(input.header.origin_node_id));
    check_mem_eq(verified.header.target_node_id, input.header.target_node_id,
                 sizeof(input.header.target_node_id));
    check_hex64_eq(verified.header.principal_epoch,
                   input.header.principal_epoch);
    check_hex64_eq(verified.header.incarnation, input.header.incarnation);
    check_hex64_eq(verified.header.origin_sequence,
                   input.header.origin_sequence);
    check_hex64_eq(verified.header.issued_at_ms, input.header.issued_at_ms);
    check_hex64_eq(verified.header.expires_at_ms, input.header.expires_at_ms);
    check_uint_eq(verified.header.forward_budget,
                  input.header.forward_budget);
    check_hex64_eq(verified.header.certificate_serial,
                   input.header.certificate_serial);
    check_mem_eq(verified.frame.payload, TEST_PAYLOAD, sizeof(TEST_PAYLOAD));
    check_int_eq(mesh_mgmt_blake2b_256(TEST_PAYLOAD, sizeof(TEST_PAYLOAD),
                                       payload_hash),
                 MESH_MGMT_CRYPTO_OK);
    check_mem_eq(verified.header.payload_hash, payload_hash,
                 sizeof(payload_hash));

    mesh_mgmt_tlv_reader_init(&reader, verified.frame.header,
                              verified.frame.header_len);
    while (mesh_mgmt_tlv_reader_next(&reader, &field) == 1) {
        check_uint_eq(field.field_id, expected_id);
        expected_id++;
    }
    check_uint_eq(expected_id,
                  MESH_MGMT_HEADER_FIELD_CERTIFICATE_SERIAL + 1u);
}

static void test_envelope_rejects_payload_tampering_before_signature(void) {
    mesh_mgmt_sign_input_v1_t input;
    mesh_mgmt_verified_envelope_v1_t verified;
    mesh_mgmt_frame_view_t view;
    uint8_t frame[MESH_MGMT_FRAME_MAX] = {0};
    size_t frame_len = 0;

    fill_test_input(&input);
    frame_len = sign_test_frame(&input, frame);
    check_int_eq(mesh_mgmt_frame_decode(frame, frame_len, &view),
                 MESH_MGMT_CODEC_OK);
    ((uint8_t *)view.payload)[view.payload_len - 1u] ^= 0x01u;
    check_int_eq(mesh_mgmt_envelope_verify_v1(frame, frame_len, &verified),
                 MESH_MGMT_ENVELOPE_PAYLOAD_HASH_MISMATCH);
    check_null(verified.frame.header);
}

static void test_envelope_rejects_signature_tampering(void) {
    mesh_mgmt_sign_input_v1_t input;
    mesh_mgmt_verified_envelope_v1_t verified;
    uint8_t frame[MESH_MGMT_FRAME_MAX] = {0};
    size_t frame_len = 0;

    fill_test_input(&input);
    frame_len = sign_test_frame(&input, frame);
    frame[frame_len - 1u] ^= 0x01u;
    check_int_eq(mesh_mgmt_envelope_verify_v1(frame, frame_len, &verified),
                 MESH_MGMT_ENVELOPE_AUTH_FAILED);
    check_null(verified.frame.signature);
}

static void test_envelope_rejects_unknown_v1_header_field(void) {
    mesh_mgmt_sign_input_v1_t input;
    mesh_mgmt_verified_envelope_v1_t verified;
    uint8_t frame[MESH_MGMT_FRAME_MAX] = {0};
    uint8_t *field_id = NULL;
    size_t frame_len = 0;

    fill_test_input(&input);
    frame_len = sign_test_frame(&input, frame);
    field_id = find_header_field_id(
        frame, frame_len, MESH_MGMT_HEADER_FIELD_CERTIFICATE_SERIAL);
    check_not_null(field_id);
    field_id[1] = 0x0f;
    check_int_eq(mesh_mgmt_envelope_verify_v1(frame, frame_len, &verified),
                 MESH_MGMT_ENVELOPE_INVALID_SCHEMA);
}

static void test_envelope_rejects_invalid_cross_field_constraints(void) {
    mesh_mgmt_sign_input_v1_t input;
    uint8_t frame[MESH_MGMT_FRAME_MAX] = {0};
    size_t frame_len = 99;

    fill_test_input(&input);
    input.header.expires_at_ms = input.header.issued_at_ms;
    check_int_eq(mesh_mgmt_envelope_sign_v1(
                     &input, frame, sizeof(frame), &frame_len),
                 MESH_MGMT_ENVELOPE_INVALID_SCHEMA);
    check_size_eq(frame_len, 0);

    fill_test_input(&input);
    input.header.forward_budget = 2;
    check_int_eq(mesh_mgmt_envelope_sign_v1(
                     &input, frame, sizeof(frame), &frame_len),
                 MESH_MGMT_ENVELOPE_INVALID_SCHEMA);
    check_size_eq(frame_len, 0);

    fill_test_input(&input);
    input.kind = MESH_MGMT_KIND_COMMAND_REQUEST;
    memset(input.header.target_node_id, 0,
           sizeof(input.header.target_node_id));
    check_int_eq(mesh_mgmt_envelope_sign_v1(
                     &input, frame, sizeof(frame), &frame_len),
                 MESH_MGMT_ENVELOPE_INVALID_SCHEMA);
    check_size_eq(frame_len, 0);
}

static void test_envelope_rejects_unnegotiated_minor(void) {
    mesh_mgmt_sign_input_v1_t input;
    mesh_mgmt_verified_envelope_v1_t verified;
    uint8_t frame[MESH_MGMT_FRAME_MAX] = {0};
    size_t frame_len = 0;

    fill_test_input(&input);
    input.minor = 0;
    check_int_eq(mesh_mgmt_envelope_sign_v1(
                     &input, frame, sizeof(frame), &frame_len),
                 MESH_MGMT_ENVELOPE_UNSUPPORTED_VERSION);
    check_size_eq(frame_len, 0);

    fill_test_input(&input);
    frame_len = sign_test_frame(&input, frame);
    frame[5] = 0;
    check_int_eq(mesh_mgmt_envelope_verify_v1(frame, frame_len, &verified),
                 MESH_MGMT_ENVELOPE_UNSUPPORTED_VERSION);
}

static void test_envelope_reports_capacity_without_partial_output(void) {
    mesh_mgmt_sign_input_v1_t input;
    uint8_t output[32];
    uint8_t unchanged[sizeof(output)];
    size_t output_len = 0;

    fill_test_input(&input);
    memset(output, 0xa5, sizeof(output));
    memcpy(unchanged, output, sizeof(output));
    check_int_eq(mesh_mgmt_envelope_sign_v1(
                     &input, output, sizeof(output), &output_len),
                 MESH_MGMT_ENVELOPE_RESOURCE_EXHAUSTED);
    check_size_eq(output_len, MESH_MGMT_PREFIX_SIZE +
                                  MESH_MGMT_HEADER_V1_ENCODED_SIZE +
                                  sizeof(TEST_PAYLOAD) +
                                  MESH_MGMT_SIGNATURE_SIZE);
    check_mem_eq(output, unchanged, sizeof(output));

    input.payload = TEST_PAYLOAD;
    input.payload_len = MESH_MGMT_FRAME_MAX;
    output_len = 99;
    check_int_eq(mesh_mgmt_envelope_sign_v1(
                     &input, output, sizeof(output), &output_len),
                 MESH_MGMT_ENVELOPE_RESOURCE_EXHAUSTED);
    check_size_eq(output_len, 0);
    check_mem_eq(output, unchanged, sizeof(output));
}

spec("mesh management signed envelope") {
    describe("MMP/1.1 common header authentication") {
        it("round trips all frozen header fields and derived values") {
            test_envelope_round_trips_authenticated_common_header();
        }
        it("detects payload modification before signature verification") {
            test_envelope_rejects_payload_tampering_before_signature();
        }
        it("rejects a modified domain-separated signature") {
            test_envelope_rejects_signature_tampering();
        }
        it("rejects an unknown required-header field in the current minor") {
            test_envelope_rejects_unknown_v1_header_field();
        }
        it("enforces expiry and command-target constraints") {
            test_envelope_rejects_invalid_cross_field_constraints();
        }
        it("rejects a minor version before HELLO negotiation exists") {
            test_envelope_rejects_unnegotiated_minor();
        }
        it("reports capacity without exposing a partial unsigned frame") {
            test_envelope_reports_capacity_without_partial_output();
        }
    }
}
