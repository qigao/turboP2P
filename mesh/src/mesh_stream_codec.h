#ifndef TURBO_P2P_MESH_STREAM_CODEC_H
#define TURBO_P2P_MESH_STREAM_CODEC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Total encoded size, including the four-byte length prefix. */
#define MESH_STREAM_FRAME_MAX 262144u
#define MESH_STREAM_LENGTH_PREFIX_SIZE 4u
#define MESH_STREAM_HEADER_AFTER_LENGTH_SIZE 44u
#define MESH_STREAM_FIXED_HEADER_SIZE 48u
#define MESH_STREAM_METADATA_MAX 4096u
#define MESH_STREAM_TLV_PREFIX_SIZE 4u
#define MESH_STREAM_ID_SIZE 16u

typedef enum {
    MESH_STREAM_FRAME_OPEN = 0x01,
    MESH_STREAM_FRAME_ACCEPT = 0x02,
    MESH_STREAM_FRAME_DATA = 0x03,
    MESH_STREAM_FRAME_WINDOW_UPDATE = 0x04,
    MESH_STREAM_FRAME_CANCEL = 0x05,
    MESH_STREAM_FRAME_CLOSE = 0x06,
} mesh_stream_frame_type_t;

typedef enum {
    MESH_STREAM_FLAG_END_STREAM = 1u << 0,
} mesh_stream_frame_flag_t;

#define MESH_STREAM_FLAG_KNOWN_MASK MESH_STREAM_FLAG_END_STREAM

typedef enum {
    MESH_STREAM_CODEC_OK = 0,
    MESH_STREAM_CODEC_NEED_MORE = 1,
    MESH_STREAM_CODEC_INVALID_ARG = -1,
    MESH_STREAM_CODEC_INVALID_FRAME = -2,
    MESH_STREAM_CODEC_RESOURCE_EXHAUSTED = -3,
} mesh_stream_codec_result_t;

typedef struct {
    uint8_t type;
    uint8_t flags;
    uint8_t stream_id[MESH_STREAM_ID_SIZE];
    uint64_t stream_epoch;
    uint64_t sequence;
    uint64_t offset;
    const uint8_t *metadata;
    size_t metadata_len;
    const uint8_t *payload;
    size_t payload_len;
} mesh_stream_frame_input_t;

typedef struct {
    size_t frame_size;
    uint8_t type;
    uint8_t flags;
    uint8_t stream_id[MESH_STREAM_ID_SIZE];
    uint64_t stream_epoch;
    uint64_t sequence;
    uint64_t offset;
    const uint8_t *metadata;
    size_t metadata_len;
    const uint8_t *payload;
    size_t payload_len;
} mesh_stream_frame_view_t;

/**
 * Encode one complete frame without allocating. Metadata must be canonical
 * TLV (strictly increasing u16 type, u16 length, value). On insufficient
 * output capacity, out_len reports the required size and output is unchanged.
 * Input metadata/payload storage must not overlap the output range.
 *
 * Time: O(metadata_len + payload_len). Space: O(1), excluding caller output.
 */
mesh_stream_codec_result_t mesh_stream_frame_encode(
    const mesh_stream_frame_input_t *input,
    size_t max_frame_size,
    uint8_t *output,
    size_t output_capacity,
    size_t *out_len);

/**
 * Decode the first complete frame in a contiguous receive window. Partial
 * input returns NEED_MORE and the total byte count required in out_required.
 * Success consumes exactly one frame; trailing bytes remain for the next call.
 * Returned metadata/payload are borrowed from bytes and must not outlive it.
 *
 * Time: O(metadata_len); raw payload is not scanned or copied. Space: O(1).
 */
mesh_stream_codec_result_t mesh_stream_frame_decode(
    const uint8_t *bytes,
    size_t available,
    size_t max_frame_size,
    mesh_stream_frame_view_t *out_view,
    size_t *out_consumed,
    size_t *out_required);

#ifdef __cplusplus
}
#endif

#endif
