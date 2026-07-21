#include <tinytest.h>

#include "mesh_stream_codec.h"

#include <string.h>

#define TEST_FRAME_MAX 1024u

static const uint8_t VALID_METADATA[] = {
    0x00, 0x01, 0x00, 0x02, 0xaa, 0xbb,
    0x00, 0x03, 0x00, 0x01, 0xcc,
};

static const uint8_t VALID_PAYLOAD[] = {0x10, 0x20, 0x30, 0x40, 0x50};

static void fill_stream_id(uint8_t stream_id[MESH_STREAM_ID_SIZE]) {
    size_t index = 0u;
    for (index = 0u; index < MESH_STREAM_ID_SIZE; index++)
        stream_id[index] = (uint8_t)(0x80u + index);
}

static void prepare_data_input(mesh_stream_frame_input_t *input) {
    memset(input, 0, sizeof(*input));
    input->type = MESH_STREAM_FRAME_DATA;
    fill_stream_id(input->stream_id);
    input->stream_epoch = 7u;
    input->sequence = 9u;
    input->offset = 1024u;
    input->metadata = VALID_METADATA;
    input->metadata_len = sizeof(VALID_METADATA);
    input->payload = VALID_PAYLOAD;
    input->payload_len = sizeof(VALID_PAYLOAD);
}

static size_t encode_valid_data(uint8_t *output, size_t capacity) {
    mesh_stream_frame_input_t input;
    size_t output_len = 0u;

    prepare_data_input(&input);
    check_int_eq(mesh_stream_frame_encode(
                     &input, TEST_FRAME_MAX, output, capacity, &output_len),
                 MESH_STREAM_CODEC_OK);
    return output_len;
}

static void test_round_trips_ltv_frame_with_borrowed_views(void) {
    mesh_stream_frame_view_t view;
    uint8_t output[128] = {0};
    size_t output_len = encode_valid_data(output, sizeof(output));
    size_t consumed = 0u;
    size_t required = 0u;

    check_size_eq(output_len, MESH_STREAM_FIXED_HEADER_SIZE +
                                  sizeof(VALID_METADATA) +
                                  sizeof(VALID_PAYLOAD));
    check_mem_eq(output, "\x00\x00\x00\x3c\x03\x00\x00\x37", 8u);
    check_int_eq(mesh_stream_frame_decode(
                     output, output_len, TEST_FRAME_MAX, &view, &consumed,
                     &required),
                 MESH_STREAM_CODEC_OK);
    check_size_eq(consumed, output_len);
    check_size_eq(required, output_len);
    check_size_eq(view.frame_size, output_len);
    check_int_eq(view.type, MESH_STREAM_FRAME_DATA);
    check_int_eq(view.flags, 0);
    check_hex64_eq(view.stream_epoch, 7u);
    check_hex64_eq(view.sequence, 9u);
    check_hex64_eq(view.offset, 1024u);
    check_ptr_eq(view.metadata, output + MESH_STREAM_FIXED_HEADER_SIZE);
    check_size_eq(view.metadata_len, sizeof(VALID_METADATA));
    check_mem_eq(view.metadata, VALID_METADATA, sizeof(VALID_METADATA));
    check_ptr_eq(view.payload, output + MESH_STREAM_FIXED_HEADER_SIZE +
                                   sizeof(VALID_METADATA));
    check_size_eq(view.payload_len, sizeof(VALID_PAYLOAD));
    check_mem_eq(view.payload, VALID_PAYLOAD, sizeof(VALID_PAYLOAD));
}

static void test_reports_exact_requirement_for_fragmented_input(void) {
    mesh_stream_frame_view_t view;
    uint8_t output[128] = {0};
    size_t output_len = encode_valid_data(output, sizeof(output));
    size_t consumed = 99u;
    size_t required = 99u;
    size_t available = 0u;

    check_int_eq(mesh_stream_frame_decode(
                     NULL, 0u, TEST_FRAME_MAX, &view, &consumed, &required),
                 MESH_STREAM_CODEC_NEED_MORE);
    check_size_eq(consumed, 0u);
    check_size_eq(required, MESH_STREAM_LENGTH_PREFIX_SIZE);
    for (available = 1u; available < output_len; available++) {
        check_int_eq(mesh_stream_frame_decode(
                         output, available, TEST_FRAME_MAX, &view, &consumed,
                         &required),
                     MESH_STREAM_CODEC_NEED_MORE);
        check_size_eq(consumed, 0u);
        check_size_eq(required,
                      available < MESH_STREAM_LENGTH_PREFIX_SIZE
                          ? MESH_STREAM_LENGTH_PREFIX_SIZE
                          : output_len);
    }
}

static void test_consumes_one_frame_from_a_multi_frame_window(void) {
    mesh_stream_frame_input_t input;
    mesh_stream_frame_view_t view;
    uint8_t output[256] = {0};
    size_t first_len = encode_valid_data(output, sizeof(output));
    size_t second_len = 0u;
    size_t consumed = 0u;
    size_t required = 0u;

    prepare_data_input(&input);
    input.flags = MESH_STREAM_FLAG_END_STREAM;
    input.sequence = 10u;
    input.offset += sizeof(VALID_PAYLOAD);
    input.metadata = NULL;
    input.metadata_len = 0u;
    input.payload = NULL;
    input.payload_len = 0u;
    check_int_eq(mesh_stream_frame_encode(
                     &input, TEST_FRAME_MAX, output + first_len,
                     sizeof(output) - first_len, &second_len),
                 MESH_STREAM_CODEC_OK);

    check_int_eq(mesh_stream_frame_decode(
                     output, first_len + second_len, TEST_FRAME_MAX, &view,
                     &consumed, &required),
                 MESH_STREAM_CODEC_OK);
    check_size_eq(consumed, first_len);
    check_int_eq(view.flags, 0);
    check_int_eq(mesh_stream_frame_decode(
                     output + consumed, second_len, TEST_FRAME_MAX, &view,
                     &consumed, &required),
                 MESH_STREAM_CODEC_OK);
    check_size_eq(consumed, second_len);
    check_int_eq(view.flags, MESH_STREAM_FLAG_END_STREAM);
    check_size_eq(view.payload_len, 0u);
}

static void test_control_frame_carries_only_canonical_metadata(void) {
    mesh_stream_frame_input_t input;
    mesh_stream_frame_view_t view;
    uint8_t output[128] = {0};
    size_t output_len = 0u;
    size_t consumed = 0u;
    size_t required = 0u;

    prepare_data_input(&input);
    input.type = MESH_STREAM_FRAME_OPEN;
    input.sequence = 0u;
    input.offset = 0u;
    input.payload = NULL;
    input.payload_len = 0u;
    check_int_eq(mesh_stream_frame_encode(
                     &input, TEST_FRAME_MAX, output, sizeof(output),
                     &output_len),
                 MESH_STREAM_CODEC_OK);
    check_int_eq(mesh_stream_frame_decode(
                     output, output_len, TEST_FRAME_MAX, &view, &consumed,
                     &required),
                 MESH_STREAM_CODEC_OK);
    check_int_eq(view.type, MESH_STREAM_FRAME_OPEN);
    check_size_eq(view.metadata_len, sizeof(VALID_METADATA));
    check_size_eq(view.payload_len, 0u);
}

static void test_rejects_malformed_lengths_before_payload_access(void) {
    mesh_stream_frame_view_t view;
    uint8_t output[128] = {0};
    size_t output_len = encode_valid_data(output, sizeof(output));
    size_t consumed = 0u;
    size_t required = 0u;

    output[0] = 0u;
    output[1] = 0u;
    output[2] = 0u;
    output[3] = MESH_STREAM_HEADER_AFTER_LENGTH_SIZE - 1u;
    check_int_eq(mesh_stream_frame_decode(
                     output, output_len, TEST_FRAME_MAX, &view, &consumed,
                     &required),
                 MESH_STREAM_CODEC_INVALID_FRAME);

    output[0] = 0u;
    output[1] = 0u;
    output[2] = 4u;
    output[3] = 0u;
    check_int_eq(mesh_stream_frame_decode(
                     output, output_len, TEST_FRAME_MAX, &view, &consumed,
                     &required),
                 MESH_STREAM_CODEC_RESOURCE_EXHAUSTED);

    output_len = encode_valid_data(output, sizeof(output));
    output[6] = 0u;
    output[7] = MESH_STREAM_HEADER_AFTER_LENGTH_SIZE - 1u;
    check_int_eq(mesh_stream_frame_decode(
                     output, output_len, TEST_FRAME_MAX, &view, &consumed,
                     &required),
                 MESH_STREAM_CODEC_INVALID_FRAME);
}

static void test_rejects_noncanonical_metadata_and_invalid_type_semantics(void) {
    static const uint8_t unordered_metadata[] = {
        0x00, 0x02, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00,
    };
    mesh_stream_frame_input_t input;
    mesh_stream_frame_view_t view;
    uint8_t output[128] = {0};
    size_t output_len = 0u;
    size_t consumed = 0u;
    size_t required = 0u;

    prepare_data_input(&input);
    input.metadata = unordered_metadata;
    input.metadata_len = sizeof(unordered_metadata);
    check_int_eq(mesh_stream_frame_encode(
                     &input, TEST_FRAME_MAX, output, sizeof(output),
                     &output_len),
                 MESH_STREAM_CODEC_INVALID_FRAME);

    prepare_data_input(&input);
    input.type = MESH_STREAM_FRAME_OPEN;
    check_int_eq(mesh_stream_frame_encode(
                     &input, TEST_FRAME_MAX, output, sizeof(output),
                     &output_len),
                 MESH_STREAM_CODEC_INVALID_FRAME);

    output_len = encode_valid_data(output, sizeof(output));
    output[4] = MESH_STREAM_FRAME_OPEN;
    check_int_eq(mesh_stream_frame_decode(
                     output, MESH_STREAM_FIXED_HEADER_SIZE, TEST_FRAME_MAX,
                     &view, &consumed, &required),
                 MESH_STREAM_CODEC_INVALID_FRAME);
    output[4] = MESH_STREAM_FRAME_DATA;
    output[5] = 0x80u;
    check_int_eq(mesh_stream_frame_decode(
                     output, MESH_STREAM_FIXED_HEADER_SIZE, TEST_FRAME_MAX,
                     &view, &consumed, &required),
                 MESH_STREAM_CODEC_INVALID_FRAME);
}

static void test_reports_capacity_without_partial_output(void) {
    mesh_stream_frame_input_t input;
    uint8_t output[16];
    uint8_t unchanged[sizeof(output)];
    size_t output_len = 0u;

    prepare_data_input(&input);
    memset(output, 0xa5, sizeof(output));
    memcpy(unchanged, output, sizeof(output));
    check_int_eq(mesh_stream_frame_encode(
                     &input, TEST_FRAME_MAX, output, sizeof(output),
                     &output_len),
                 MESH_STREAM_CODEC_RESOURCE_EXHAUSTED);
    check_size_eq(output_len, MESH_STREAM_FIXED_HEADER_SIZE +
                                  sizeof(VALID_METADATA) +
                                  sizeof(VALID_PAYLOAD));
    check_mem_eq(output, unchanged, sizeof(output));

    memset(input.stream_id, 0, sizeof(input.stream_id));
    check_int_eq(mesh_stream_frame_encode(
                     &input, TEST_FRAME_MAX, output, sizeof(output),
                     &output_len),
                 MESH_STREAM_CODEC_INVALID_FRAME);
}

spec("mesh length-first stream codec") {
    describe("zero-allocation LTV framing") {
        it("round trips metadata and raw payload as borrowed views") {
            test_round_trips_ltv_frame_with_borrowed_views();
        }
        it("reports the exact frame requirement for every input split") {
            test_reports_exact_requirement_for_fragmented_input();
        }
        it("consumes exactly one frame from a multi-frame receive window") {
            test_consumes_one_frame_from_a_multi_frame_window();
        }
        it("keeps control metadata separate from raw data payload") {
            test_control_frame_carries_only_canonical_metadata();
        }
        it("rejects impossible or oversized lengths before payload access") {
            test_rejects_malformed_lengths_before_payload_access();
        }
        it("rejects noncanonical metadata and invalid frame semantics") {
            test_rejects_noncanonical_metadata_and_invalid_type_semantics();
        }
        it("reports output capacity without a partial write") {
            test_reports_capacity_without_partial_output();
        }
    }
    bench("bounded codec throughput baseline") {
        static uint8_t payload[64u * 1024u];
        static uint8_t frame[64u * 1024u + MESH_STREAM_FIXED_HEADER_SIZE];
        mesh_stream_frame_input_t input;
        mesh_stream_frame_view_t view;
        mesh_stream_codec_result_t result = MESH_STREAM_CODEC_INVALID_FRAME;
        size_t frame_len = 0u;
        size_t consumed = 0u;
        size_t required = 0u;

        prepare_data_input(&input);
        input.metadata = NULL;
        input.metadata_len = 0u;
        input.payload = payload;
        input.payload_len = sizeof(payload);
        check_int_eq(mesh_stream_frame_encode(
                         &input, MESH_STREAM_FRAME_MAX, frame, sizeof(frame),
                         &frame_len),
                     MESH_STREAM_CODEC_OK);

        benchmark("encode 64 KiB frame", 1000u, 1.0) {
            result = mesh_stream_frame_encode(
                &input, MESH_STREAM_FRAME_MAX, frame, sizeof(frame),
                &frame_len);
        }
        check_int_eq(result, MESH_STREAM_CODEC_OK);
        benchmark("decode 64 KiB borrowed frame", 10000u, 1.0) {
            result = mesh_stream_frame_decode(
                frame, frame_len, MESH_STREAM_FRAME_MAX, &view, &consumed,
                &required);
        }
        check_int_eq(result, MESH_STREAM_CODEC_OK);
        check_size_eq(consumed, frame_len);
    }
}
