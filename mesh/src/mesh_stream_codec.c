#include "mesh_stream_codec.h"

#include <limits.h>
#include <string.h>

#define MESH_STREAM_TYPE_OFFSET 4u
#define MESH_STREAM_FLAGS_OFFSET 5u
#define MESH_STREAM_HEADER_LENGTH_OFFSET 6u
#define MESH_STREAM_ID_OFFSET 8u
#define MESH_STREAM_EPOCH_OFFSET 24u
#define MESH_STREAM_SEQUENCE_OFFSET 32u
#define MESH_STREAM_DATA_OFFSET_OFFSET 40u

static uint16_t read_u16(const uint8_t *bytes) {
    return (uint16_t)(((uint16_t)bytes[0] << 8u) | bytes[1]);
}

static uint32_t read_u32(const uint8_t *bytes) {
    return ((uint32_t)bytes[0] << 24u) | ((uint32_t)bytes[1] << 16u) |
           ((uint32_t)bytes[2] << 8u) | bytes[3];
}

static uint64_t read_u64(const uint8_t *bytes) {
    uint64_t value = 0u;
    size_t index = 0u;

    for (index = 0u; index < sizeof(value); index++)
        value = (value << 8u) | bytes[index];
    return value;
}

static void write_u16(uint8_t *bytes, uint16_t value) {
    bytes[0] = (uint8_t)(value >> 8u);
    bytes[1] = (uint8_t)value;
}

static void write_u32(uint8_t *bytes, uint32_t value) {
    bytes[0] = (uint8_t)(value >> 24u);
    bytes[1] = (uint8_t)(value >> 16u);
    bytes[2] = (uint8_t)(value >> 8u);
    bytes[3] = (uint8_t)value;
}

static void write_u64(uint8_t *bytes, uint64_t value) {
    size_t index = 0u;

    for (index = 0u; index < sizeof(value); index++)
        bytes[index] = (uint8_t)(value >> (56u - index * 8u));
}

static int bytes_are_zero(const uint8_t *bytes, size_t length) {
    uint8_t aggregate = 0u;
    size_t index = 0u;

    for (index = 0u; index < length; index++) aggregate |= bytes[index];
    return aggregate == 0u;
}

static int type_is_known(uint8_t type) {
    return type >= MESH_STREAM_FRAME_OPEN &&
           type <= MESH_STREAM_FRAME_CLOSE;
}

static int metadata_is_canonical(const uint8_t *metadata,
                                 size_t metadata_len) {
    size_t cursor = 0u;
    uint16_t previous_type = 0u;
    int has_previous = 0;

    if (!metadata && metadata_len != 0u) return 0;
    while (cursor < metadata_len) {
        uint16_t type = 0u;
        uint16_t length = 0u;
        size_t remaining = metadata_len - cursor;

        if (remaining < MESH_STREAM_TLV_PREFIX_SIZE) return 0;
        type = read_u16(metadata + cursor);
        length = read_u16(metadata + cursor + sizeof(uint16_t));
        if (type == 0u || (has_previous && type <= previous_type)) return 0;
        if ((size_t)length > remaining - MESH_STREAM_TLV_PREFIX_SIZE)
            return 0;
        cursor += MESH_STREAM_TLV_PREFIX_SIZE + (size_t)length;
        previous_type = type;
        has_previous = 1;
    }
    return cursor == metadata_len;
}

static mesh_stream_codec_result_t validate_lengths_and_fields(
    uint8_t type,
    uint8_t flags,
    const uint8_t stream_id[MESH_STREAM_ID_SIZE],
    uint64_t stream_epoch,
    size_t metadata_len,
    size_t payload_len,
    size_t max_frame_size,
    size_t *out_header_length,
    size_t *out_total) {
    size_t header_length = 0u;
    size_t total = 0u;

    if (!stream_id || !out_header_length || !out_total) {
        return MESH_STREAM_CODEC_INVALID_ARG;
    }
    if (max_frame_size < MESH_STREAM_FIXED_HEADER_SIZE ||
        max_frame_size > MESH_STREAM_FRAME_MAX) {
        return MESH_STREAM_CODEC_INVALID_ARG;
    }
    if (!type_is_known(type) ||
        (flags & (uint8_t)~MESH_STREAM_FLAG_KNOWN_MASK) != 0u ||
        bytes_are_zero(stream_id, MESH_STREAM_ID_SIZE) ||
        stream_epoch == 0u) {
        return MESH_STREAM_CODEC_INVALID_FRAME;
    }
    if ((flags & MESH_STREAM_FLAG_END_STREAM) != 0u &&
        type != MESH_STREAM_FRAME_DATA) {
        return MESH_STREAM_CODEC_INVALID_FRAME;
    }
    if ((type != MESH_STREAM_FRAME_DATA && payload_len != 0u) ||
        (type == MESH_STREAM_FRAME_DATA && payload_len == 0u &&
         (flags & MESH_STREAM_FLAG_END_STREAM) == 0u)) {
        return MESH_STREAM_CODEC_INVALID_FRAME;
    }
    if (metadata_len > MESH_STREAM_METADATA_MAX ||
        metadata_len > UINT16_MAX - MESH_STREAM_HEADER_AFTER_LENGTH_SIZE) {
        return MESH_STREAM_CODEC_RESOURCE_EXHAUSTED;
    }
    header_length = MESH_STREAM_HEADER_AFTER_LENGTH_SIZE + metadata_len;
    if (header_length > max_frame_size - MESH_STREAM_LENGTH_PREFIX_SIZE)
        return MESH_STREAM_CODEC_RESOURCE_EXHAUSTED;
    if (payload_len > max_frame_size - MESH_STREAM_LENGTH_PREFIX_SIZE -
                          header_length) {
        return MESH_STREAM_CODEC_RESOURCE_EXHAUSTED;
    }
    total = MESH_STREAM_LENGTH_PREFIX_SIZE + header_length + payload_len;
    *out_header_length = header_length;
    *out_total = total;
    return MESH_STREAM_CODEC_OK;
}

static mesh_stream_codec_result_t validate_layout(
    uint8_t type,
    uint8_t flags,
    const uint8_t stream_id[MESH_STREAM_ID_SIZE],
    uint64_t stream_epoch,
    const uint8_t *metadata,
    size_t metadata_len,
    const uint8_t *payload,
    size_t payload_len,
    size_t max_frame_size,
    size_t *out_header_length,
    size_t *out_total) {
    mesh_stream_codec_result_t result;

    if ((!metadata && metadata_len != 0u) ||
        (!payload && payload_len != 0u)) {
        return MESH_STREAM_CODEC_INVALID_ARG;
    }
    result = validate_lengths_and_fields(
        type, flags, stream_id, stream_epoch, metadata_len, payload_len,
        max_frame_size, out_header_length, out_total);
    if (result != MESH_STREAM_CODEC_OK) return result;
    return metadata_is_canonical(metadata, metadata_len)
               ? MESH_STREAM_CODEC_OK
               : MESH_STREAM_CODEC_INVALID_FRAME;
}

mesh_stream_codec_result_t mesh_stream_frame_encode(
    const mesh_stream_frame_input_t *input,
    size_t max_frame_size,
    uint8_t *output,
    size_t output_capacity,
    size_t *out_len) {
    mesh_stream_codec_result_t result;
    size_t header_length = 0u;
    size_t total = 0u;
    size_t payload_offset = 0u;

    if (!input || !out_len) return MESH_STREAM_CODEC_INVALID_ARG;
    *out_len = 0u;
    result = validate_layout(
        input->type, input->flags, input->stream_id, input->stream_epoch,
        input->metadata, input->metadata_len, input->payload,
        input->payload_len, max_frame_size, &header_length, &total);
    if (result != MESH_STREAM_CODEC_OK) return result;
    *out_len = total;
    if (!output || output_capacity < total)
        return MESH_STREAM_CODEC_RESOURCE_EXHAUSTED;

    write_u32(output, (uint32_t)(total - MESH_STREAM_LENGTH_PREFIX_SIZE));
    output[MESH_STREAM_TYPE_OFFSET] = input->type;
    output[MESH_STREAM_FLAGS_OFFSET] = input->flags;
    write_u16(output + MESH_STREAM_HEADER_LENGTH_OFFSET,
              (uint16_t)header_length);
    memcpy(output + MESH_STREAM_ID_OFFSET, input->stream_id,
           MESH_STREAM_ID_SIZE);
    write_u64(output + MESH_STREAM_EPOCH_OFFSET, input->stream_epoch);
    write_u64(output + MESH_STREAM_SEQUENCE_OFFSET, input->sequence);
    write_u64(output + MESH_STREAM_DATA_OFFSET_OFFSET, input->offset);
    if (input->metadata_len != 0u)
        memcpy(output + MESH_STREAM_FIXED_HEADER_SIZE, input->metadata,
               input->metadata_len);
    payload_offset = MESH_STREAM_LENGTH_PREFIX_SIZE + header_length;
    if (input->payload_len != 0u)
        memcpy(output + payload_offset, input->payload, input->payload_len);
    return MESH_STREAM_CODEC_OK;
}

mesh_stream_codec_result_t mesh_stream_frame_decode(
    const uint8_t *bytes,
    size_t available,
    size_t max_frame_size,
    mesh_stream_frame_view_t *out_view,
    size_t *out_consumed,
    size_t *out_required) {
    mesh_stream_frame_input_t layout;
    mesh_stream_codec_result_t result;
    size_t encoded_header_length = 0u;
    size_t validated_header_length = 0u;
    size_t frame_length = 0u;
    size_t total = 0u;
    size_t validated_total = 0u;

    if ((!bytes && available != 0u) || !out_view || !out_consumed ||
        !out_required || max_frame_size < MESH_STREAM_FIXED_HEADER_SIZE ||
        max_frame_size > MESH_STREAM_FRAME_MAX) {
        return MESH_STREAM_CODEC_INVALID_ARG;
    }
    memset(out_view, 0, sizeof(*out_view));
    *out_consumed = 0u;
    *out_required = MESH_STREAM_LENGTH_PREFIX_SIZE;
    if (available < MESH_STREAM_LENGTH_PREFIX_SIZE)
        return MESH_STREAM_CODEC_NEED_MORE;

    frame_length = read_u32(bytes);
    if (frame_length < MESH_STREAM_HEADER_AFTER_LENGTH_SIZE)
        return MESH_STREAM_CODEC_INVALID_FRAME;
    if (frame_length > max_frame_size - MESH_STREAM_LENGTH_PREFIX_SIZE)
        return MESH_STREAM_CODEC_RESOURCE_EXHAUSTED;
    total = MESH_STREAM_LENGTH_PREFIX_SIZE + frame_length;
    *out_required = total;
    if (available < MESH_STREAM_FIXED_HEADER_SIZE)
        return MESH_STREAM_CODEC_NEED_MORE;

    encoded_header_length = read_u16(
        bytes + MESH_STREAM_HEADER_LENGTH_OFFSET);
    if (encoded_header_length < MESH_STREAM_HEADER_AFTER_LENGTH_SIZE ||
        encoded_header_length > frame_length) {
        return MESH_STREAM_CODEC_INVALID_FRAME;
    }

    memset(&layout, 0, sizeof(layout));
    layout.type = bytes[MESH_STREAM_TYPE_OFFSET];
    layout.flags = bytes[MESH_STREAM_FLAGS_OFFSET];
    memcpy(layout.stream_id, bytes + MESH_STREAM_ID_OFFSET,
           MESH_STREAM_ID_SIZE);
    layout.stream_epoch = read_u64(bytes + MESH_STREAM_EPOCH_OFFSET);
    layout.sequence = read_u64(bytes + MESH_STREAM_SEQUENCE_OFFSET);
    layout.offset = read_u64(bytes + MESH_STREAM_DATA_OFFSET_OFFSET);
    layout.metadata_len = encoded_header_length -
                          MESH_STREAM_HEADER_AFTER_LENGTH_SIZE;
    layout.payload_len = frame_length - encoded_header_length;
    result = validate_lengths_and_fields(
        layout.type, layout.flags, layout.stream_id, layout.stream_epoch,
        layout.metadata_len, layout.payload_len, max_frame_size,
        &validated_header_length, &validated_total);
    if (result != MESH_STREAM_CODEC_OK) return result;
    if (validated_header_length != encoded_header_length ||
        validated_total != total) {
        return MESH_STREAM_CODEC_INVALID_FRAME;
    }
    if (available < MESH_STREAM_LENGTH_PREFIX_SIZE + encoded_header_length)
        return MESH_STREAM_CODEC_NEED_MORE;
    layout.metadata = bytes + MESH_STREAM_FIXED_HEADER_SIZE;
    if (!metadata_is_canonical(layout.metadata, layout.metadata_len))
        return MESH_STREAM_CODEC_INVALID_FRAME;
    if (available < total) return MESH_STREAM_CODEC_NEED_MORE;
    layout.payload = bytes + MESH_STREAM_LENGTH_PREFIX_SIZE +
                     encoded_header_length;

    out_view->frame_size = total;
    out_view->type = layout.type;
    out_view->flags = layout.flags;
    memcpy(out_view->stream_id, layout.stream_id, MESH_STREAM_ID_SIZE);
    out_view->stream_epoch = layout.stream_epoch;
    out_view->sequence = layout.sequence;
    out_view->offset = layout.offset;
    out_view->metadata = layout.metadata;
    out_view->metadata_len = layout.metadata_len;
    out_view->payload = layout.payload;
    out_view->payload_len = layout.payload_len;
    *out_consumed = total;
    return MESH_STREAM_CODEC_OK;
}
