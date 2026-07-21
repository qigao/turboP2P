#include <tinytest.h>

#include "mesh_mgmt_codec.h"

#include <string.h>

static const uint8_t VALID_HEADER[] = {
    0x00, 0x01, 0x00, 0x01, 0xaa,
    0x00, 0x03, 0x00, 0x02, 0xbb, 0xcc,
};

static const uint8_t VALID_PAYLOAD[] = {
    0x00, 0x02, 0x00, 0x03, 0x01, 0x02, 0x03,
};

static void mesh_mgmt_test_fill_input(mesh_mgmt_frame_input_t *input,
                                      uint8_t signature[MESH_MGMT_SIGNATURE_SIZE]) {
    memset(input, 0, sizeof(*input));
    memset(signature, 0x5a, MESH_MGMT_SIGNATURE_SIZE);
    input->major = MESH_MGMT_MAJOR_V1;
    input->minor = MESH_MGMT_MINOR_V1;
    input->kind = MESH_MGMT_KIND_HELLO;
    input->header = VALID_HEADER;
    input->header_len = sizeof(VALID_HEADER);
    input->payload = VALID_PAYLOAD;
    input->payload_len = sizeof(VALID_PAYLOAD);
    input->signature = signature;
}

static void test_codec_round_trips_canonical_frame(void) {
    mesh_mgmt_frame_input_t input;
    mesh_mgmt_frame_view_t view;
    mesh_mgmt_tlv_reader_t reader;
    mesh_mgmt_tlv_view_t field;
    uint8_t signature[MESH_MGMT_SIGNATURE_SIZE];
    uint8_t output[128] = {0};
    size_t output_len = 0;

    mesh_mgmt_test_fill_input(&input, signature);
    check_int_eq(mesh_mgmt_frame_encode(&input, output, sizeof(output),
                                        &output_len),
                 MESH_MGMT_CODEC_OK);
    check_size_eq(output_len, MESH_MGMT_PREFIX_SIZE + sizeof(VALID_HEADER) +
                                  sizeof(VALID_PAYLOAD) +
                                  MESH_MGMT_SIGNATURE_SIZE);
    check_mem_eq(output, "TMGM\x01\x00\x01\x00\x00\x0b\x00\x00\x00\x07",
                 MESH_MGMT_PREFIX_SIZE);
    check_mem_eq(output + MESH_MGMT_PREFIX_SIZE, VALID_HEADER,
                 sizeof(VALID_HEADER));
    check_mem_eq(output + MESH_MGMT_PREFIX_SIZE + sizeof(VALID_HEADER),
                 VALID_PAYLOAD, sizeof(VALID_PAYLOAD));

    check_int_eq(mesh_mgmt_frame_decode(output, output_len, &view),
                 MESH_MGMT_CODEC_OK);
    check_uint_eq(view.major, MESH_MGMT_MAJOR_V1);
    check_uint_eq(view.minor, MESH_MGMT_MINOR_V1);
    check_uint_eq(view.kind, MESH_MGMT_KIND_HELLO);
    check_size_eq(view.header_len, sizeof(VALID_HEADER));
    check_size_eq(view.payload_len, sizeof(VALID_PAYLOAD));
    check_mem_eq(view.signature, signature, sizeof(signature));

    mesh_mgmt_tlv_reader_init(&reader, view.header, view.header_len);
    check_int_eq(mesh_mgmt_tlv_reader_next(&reader, &field), 1);
    check_uint_eq(field.field_id, 1);
    check_size_eq(field.value_len, 1);
    check_uint_eq(field.value[0], 0xaa);
    check_int_eq(mesh_mgmt_tlv_reader_next(&reader, &field), 1);
    check_uint_eq(field.field_id, 3);
    check_size_eq(field.value_len, 2);
    check_int_eq(mesh_mgmt_tlv_reader_next(&reader, &field), 0);
}

static void test_codec_rejects_noncanonical_tlv_order(void) {
    static const uint8_t unordered_header[] = {
        0x00, 0x02, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00,
    };
    mesh_mgmt_frame_input_t input;
    uint8_t signature[MESH_MGMT_SIGNATURE_SIZE];
    uint8_t output[128] = {0};
    size_t output_len = 0;

    mesh_mgmt_test_fill_input(&input, signature);
    input.header = unordered_header;
    input.header_len = sizeof(unordered_header);
    check_int_eq(mesh_mgmt_frame_encode(&input, output, sizeof(output),
                                        &output_len),
                 MESH_MGMT_CODEC_INVALID_FRAME);
    check_size_eq(output_len, 0);
}

static void test_codec_rejects_duplicate_and_truncated_tlvs(void) {
    static const uint8_t duplicate_tlv[] = {
        0x00, 0x01, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00,
    };
    static const uint8_t truncated_tlv[] = {
        0x00, 0x01, 0x00, 0x02, 0xaa,
    };
    mesh_mgmt_tlv_reader_t reader;
    mesh_mgmt_tlv_view_t field;

    mesh_mgmt_tlv_reader_init(&reader, duplicate_tlv, sizeof(duplicate_tlv));
    check_int_eq(mesh_mgmt_tlv_reader_next(&reader, &field), 1);
    check_int_eq(mesh_mgmt_tlv_reader_next(&reader, &field), -1);

    mesh_mgmt_tlv_reader_init(&reader, truncated_tlv, sizeof(truncated_tlv));
    check_int_eq(mesh_mgmt_tlv_reader_next(&reader, &field), -1);
}

static void test_codec_rejects_invalid_envelope_fields(void) {
    mesh_mgmt_frame_input_t input;
    mesh_mgmt_frame_view_t view;
    uint8_t signature[MESH_MGMT_SIGNATURE_SIZE];
    uint8_t output[128] = {0};
    size_t output_len = 0;

    mesh_mgmt_test_fill_input(&input, signature);
    check_int_eq(mesh_mgmt_frame_encode(&input, output, sizeof(output),
                                        &output_len),
                 MESH_MGMT_CODEC_OK);

    output[0] = 'X';
    check_int_eq(mesh_mgmt_frame_decode(output, output_len, &view),
                 MESH_MGMT_CODEC_INVALID_FRAME);
    output[0] = 'T';
    output[4] = 2;
    check_int_eq(mesh_mgmt_frame_decode(output, output_len, &view),
                 MESH_MGMT_CODEC_UNSUPPORTED_VERSION);
    output[4] = MESH_MGMT_MAJOR_V1;
    output[6] = 0xff;
    check_int_eq(mesh_mgmt_frame_decode(output, output_len, &view),
                 MESH_MGMT_CODEC_INVALID_FRAME);
    output[6] = MESH_MGMT_KIND_HELLO;
    output[7] = 1;
    check_int_eq(mesh_mgmt_frame_decode(output, output_len, &view),
                 MESH_MGMT_CODEC_INVALID_FRAME);
}

static void test_codec_rejects_length_mismatch(void) {
    mesh_mgmt_frame_input_t input;
    mesh_mgmt_frame_view_t view;
    uint8_t signature[MESH_MGMT_SIGNATURE_SIZE];
    uint8_t output[128] = {0};
    size_t output_len = 0;

    mesh_mgmt_test_fill_input(&input, signature);
    check_int_eq(mesh_mgmt_frame_encode(&input, output, sizeof(output),
                                        &output_len),
                 MESH_MGMT_CODEC_OK);
    for (size_t truncated_len = 0; truncated_len < output_len;
         truncated_len++) {
        check_int_ne(mesh_mgmt_frame_decode(output, truncated_len, &view),
                     MESH_MGMT_CODEC_OK);
    }
    output[output_len] = 0;
    check_int_eq(mesh_mgmt_frame_decode(output, output_len + 1u, &view),
                 MESH_MGMT_CODEC_INVALID_FRAME);

    output[8] = 0x02;
    output[9] = 0x01;
    check_int_eq(mesh_mgmt_frame_decode(output, output_len, &view),
                 MESH_MGMT_CODEC_RESOURCE_EXHAUSTED);
    output[8] = 0x00;
    output[9] = (uint8_t)sizeof(VALID_HEADER);
    output[10] = 0xff;
    output[11] = 0xff;
    output[12] = 0xff;
    output[13] = 0xff;
    check_int_eq(mesh_mgmt_frame_decode(output, output_len, &view),
                 MESH_MGMT_CODEC_RESOURCE_EXHAUSTED);
}

static void test_codec_reports_required_capacity_without_partial_write(void) {
    mesh_mgmt_frame_input_t input;
    mesh_mgmt_frame_view_t view;
    uint8_t signature[MESH_MGMT_SIGNATURE_SIZE];
    uint8_t output[16];
    uint8_t unchanged[sizeof(output)];
    uint8_t oversized[MESH_MGMT_FRAME_MAX + 1u] = {0};
    size_t output_len = 0;

    mesh_mgmt_test_fill_input(&input, signature);
    memset(output, 0xa5, sizeof(output));
    memcpy(unchanged, output, sizeof(output));
    check_int_eq(mesh_mgmt_frame_encode(&input, output, sizeof(output),
                                        &output_len),
                 MESH_MGMT_CODEC_RESOURCE_EXHAUSTED);
    check_size_eq(output_len, MESH_MGMT_PREFIX_SIZE + sizeof(VALID_HEADER) +
                                  sizeof(VALID_PAYLOAD) +
                                  MESH_MGMT_SIGNATURE_SIZE);
    check_mem_eq(output, unchanged, sizeof(output));

    input.payload_len = MESH_MGMT_FRAME_MAX;
    check_int_eq(mesh_mgmt_frame_encode(&input, output, sizeof(output),
                                        &output_len),
                 MESH_MGMT_CODEC_RESOURCE_EXHAUSTED);
    check_int_eq(mesh_mgmt_frame_decode(oversized, sizeof(oversized), &view),
                 MESH_MGMT_CODEC_RESOURCE_EXHAUSTED);
}

spec("mesh management codec") {
    describe("canonical framing") {
        it("round trips one bounded canonical frame") {
            test_codec_round_trips_canonical_frame();
        }
        it("rejects TLVs that are not in strict field order") {
            test_codec_rejects_noncanonical_tlv_order();
        }
        it("rejects duplicate and truncated TLVs") {
            test_codec_rejects_duplicate_and_truncated_tlvs();
        }
        it("rejects unsupported envelope fields before signature work") {
            test_codec_rejects_invalid_envelope_fields();
        }
        it("rejects truncated and trailing frame bytes") {
            test_codec_rejects_length_mismatch();
        }
        it("reports required capacity without partially writing output") {
            test_codec_reports_required_capacity_without_partial_write();
        }
    }
}
