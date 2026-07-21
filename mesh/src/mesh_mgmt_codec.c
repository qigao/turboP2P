#include "mesh_mgmt_codec.h"
#include "mesh_mgmt_wire.h"

#include <limits.h>
#include <string.h>

static const uint8_t MESH_MGMT_MAGIC[4] = {'T', 'M', 'G', 'M'};

static int mesh_mgmt_kind_is_known(uint8_t kind) {
    switch (kind) {
        case MESH_MGMT_KIND_HELLO:
        case MESH_MGMT_KIND_HELLO_ACK:
        case MESH_MGMT_KIND_FORWARD:
        case MESH_MGMT_KIND_PROBE:
        case MESH_MGMT_KIND_PROBE_ACK:
        case MESH_MGMT_KIND_INDIRECT_PROBE:
        case MESH_MGMT_KIND_INDIRECT_ACK:
        case MESH_MGMT_KIND_MEMBERSHIP_DELTA:
        case MESH_MGMT_KIND_DIGEST:
        case MESH_MGMT_KIND_DELTA_REQUEST:
        case MESH_MGMT_KIND_DELTA_BATCH:
        case MESH_MGMT_KIND_COMMAND_REQUEST:
        case MESH_MGMT_KIND_COMMAND_ACCEPTED:
        case MESH_MGMT_KIND_COMMAND_RESULT:
        case MESH_MGMT_KIND_COMMAND_STATUS:
        case MESH_MGMT_KIND_AUDIT_ANCHOR:
        case MESH_MGMT_KIND_STREAM_TICKET_REQUEST:
        case MESH_MGMT_KIND_STREAM_TICKET_ISSUED:
        case MESH_MGMT_KIND_ERROR:
            return 1;
        default:
            return 0;
    }
}

void mesh_mgmt_tlv_reader_init(mesh_mgmt_tlv_reader_t *reader,
                               const uint8_t *bytes,
                               size_t length) {
    if (!reader) {
        return;
    }
    memset(reader, 0, sizeof(*reader));
    reader->bytes = bytes;
    reader->length = length;
}

int mesh_mgmt_tlv_reader_next(mesh_mgmt_tlv_reader_t *reader,
                              mesh_mgmt_tlv_view_t *out_field) {
    size_t remaining = 0;
    uint16_t field_id = 0;
    uint16_t field_length = 0;

    if (!reader || !out_field || (!reader->bytes && reader->length != 0u) ||
        reader->offset > reader->length) {
        return -1;
    }
    memset(out_field, 0, sizeof(*out_field));
    if (reader->offset == reader->length) {
        return 0;
    }

    remaining = reader->length - reader->offset;
    if (remaining < MESH_MGMT_TLV_PREFIX_SIZE) {
        return -1;
    }
    field_id = mesh_mgmt_wire_read_u16(reader->bytes + reader->offset);
    field_length = mesh_mgmt_wire_read_u16(
        reader->bytes + reader->offset + sizeof(uint16_t));
    if (reader->has_previous && field_id <= reader->previous_field_id) {
        return -1;
    }
    if ((size_t)field_length > remaining - MESH_MGMT_TLV_PREFIX_SIZE) {
        return -1;
    }

    out_field->field_id = field_id;
    out_field->value = reader->bytes + reader->offset +
                       MESH_MGMT_TLV_PREFIX_SIZE;
    out_field->value_len = field_length;
    reader->offset += MESH_MGMT_TLV_PREFIX_SIZE + (size_t)field_length;
    reader->previous_field_id = field_id;
    reader->has_previous = 1;
    return 1;
}

static int mesh_mgmt_tlv_block_is_canonical(const uint8_t *bytes,
                                             size_t length) {
    mesh_mgmt_tlv_reader_t reader;
    mesh_mgmt_tlv_view_t field;
    int result = 0;

    if (!bytes && length != 0u) {
        return 0;
    }
    mesh_mgmt_tlv_reader_init(&reader, bytes, length);
    while ((result = mesh_mgmt_tlv_reader_next(&reader, &field)) > 0) {
    }
    return result == 0;
}

static mesh_mgmt_codec_result_t mesh_mgmt_frame_layout(
    uint8_t major,
    uint8_t kind,
    uint8_t flags,
    const uint8_t *header,
    size_t header_len,
    const uint8_t *payload,
    size_t payload_len,
    size_t *out_total) {
    size_t total = 0;

    if (!out_total || (!header && header_len != 0u) ||
        (!payload && payload_len != 0u)) {
        return MESH_MGMT_CODEC_INVALID_ARG;
    }
    if (major != MESH_MGMT_MAJOR_V1) {
        return MESH_MGMT_CODEC_UNSUPPORTED_VERSION;
    }
    if (!mesh_mgmt_kind_is_known(kind) || flags != 0u) {
        return MESH_MGMT_CODEC_INVALID_FRAME;
    }
    if (header_len > MESH_MGMT_HEADER_MAX || header_len > UINT16_MAX ||
        payload_len > UINT32_MAX) {
        return MESH_MGMT_CODEC_RESOURCE_EXHAUSTED;
    }
    if (payload_len > MESH_MGMT_FRAME_MAX - MESH_MGMT_PREFIX_SIZE -
                          MESH_MGMT_SIGNATURE_SIZE - header_len) {
        return MESH_MGMT_CODEC_RESOURCE_EXHAUSTED;
    }
    if (!mesh_mgmt_tlv_block_is_canonical(header, header_len) ||
        !mesh_mgmt_tlv_block_is_canonical(payload, payload_len)) {
        return MESH_MGMT_CODEC_INVALID_FRAME;
    }

    total = MESH_MGMT_PREFIX_SIZE + header_len + payload_len +
            MESH_MGMT_SIGNATURE_SIZE;
    *out_total = total;
    return MESH_MGMT_CODEC_OK;
}

mesh_mgmt_codec_result_t mesh_mgmt_frame_decode(
    const uint8_t *frame,
    size_t frame_len,
    mesh_mgmt_frame_view_t *out_view) {
    mesh_mgmt_codec_result_t result = MESH_MGMT_CODEC_OK;
    size_t header_len = 0;
    size_t payload_len = 0;
    size_t expected_len = 0;

    if (!frame || !out_view) {
        return MESH_MGMT_CODEC_INVALID_ARG;
    }
    memset(out_view, 0, sizeof(*out_view));
    if (frame_len < MESH_MGMT_PREFIX_SIZE + MESH_MGMT_SIGNATURE_SIZE) {
        return MESH_MGMT_CODEC_INVALID_FRAME;
    }
    if (frame_len > MESH_MGMT_FRAME_MAX) {
        return MESH_MGMT_CODEC_RESOURCE_EXHAUSTED;
    }
    if (memcmp(frame, MESH_MGMT_MAGIC, sizeof(MESH_MGMT_MAGIC)) != 0) {
        return MESH_MGMT_CODEC_INVALID_FRAME;
    }

    header_len = mesh_mgmt_wire_read_u16(frame + 8u);
    payload_len = mesh_mgmt_wire_read_u32(frame + 10u);
    if (header_len > MESH_MGMT_HEADER_MAX ||
        payload_len > MESH_MGMT_FRAME_MAX - MESH_MGMT_PREFIX_SIZE -
                          MESH_MGMT_SIGNATURE_SIZE - header_len) {
        return MESH_MGMT_CODEC_RESOURCE_EXHAUSTED;
    }
    expected_len = MESH_MGMT_PREFIX_SIZE + header_len + payload_len +
                   MESH_MGMT_SIGNATURE_SIZE;
    if (expected_len != frame_len) {
        return MESH_MGMT_CODEC_INVALID_FRAME;
    }

    result = mesh_mgmt_frame_layout(
        frame[4], frame[6], frame[7], frame + MESH_MGMT_PREFIX_SIZE,
        header_len, frame + MESH_MGMT_PREFIX_SIZE + header_len, payload_len,
        &expected_len);
    if (result != MESH_MGMT_CODEC_OK) {
        return result;
    }

    out_view->major = frame[4];
    out_view->minor = frame[5];
    out_view->kind = frame[6];
    out_view->flags = frame[7];
    out_view->header = frame + MESH_MGMT_PREFIX_SIZE;
    out_view->header_len = header_len;
    out_view->payload = out_view->header + header_len;
    out_view->payload_len = payload_len;
    out_view->signature = out_view->payload + payload_len;
    return MESH_MGMT_CODEC_OK;
}

mesh_mgmt_codec_result_t mesh_mgmt_frame_encode(
    const mesh_mgmt_frame_input_t *input,
    uint8_t *output,
    size_t output_capacity,
    size_t *out_len) {
    mesh_mgmt_codec_result_t result = MESH_MGMT_CODEC_OK;
    size_t total = 0;
    size_t payload_offset = 0;

    if (!input || !out_len || !input->signature) {
        return MESH_MGMT_CODEC_INVALID_ARG;
    }
    *out_len = 0;
    result = mesh_mgmt_frame_layout(
        input->major, input->kind, input->flags, input->header,
        input->header_len, input->payload, input->payload_len, &total);
    if (result != MESH_MGMT_CODEC_OK) {
        return result;
    }
    *out_len = total;
    if (!output || output_capacity < total) {
        return MESH_MGMT_CODEC_RESOURCE_EXHAUSTED;
    }

    memcpy(output, MESH_MGMT_MAGIC, sizeof(MESH_MGMT_MAGIC));
    output[4] = input->major;
    output[5] = input->minor;
    output[6] = input->kind;
    output[7] = input->flags;
    mesh_mgmt_wire_write_u16(output + 8u, (uint16_t)input->header_len);
    mesh_mgmt_wire_write_u32(output + 10u, (uint32_t)input->payload_len);
    if (input->header_len > 0u) {
        memcpy(output + MESH_MGMT_PREFIX_SIZE, input->header,
               input->header_len);
    }
    payload_offset = MESH_MGMT_PREFIX_SIZE + input->header_len;
    if (input->payload_len > 0u) {
        memcpy(output + payload_offset, input->payload, input->payload_len);
    }
    memcpy(output + payload_offset + input->payload_len, input->signature,
           MESH_MGMT_SIGNATURE_SIZE);
    return MESH_MGMT_CODEC_OK;
}
