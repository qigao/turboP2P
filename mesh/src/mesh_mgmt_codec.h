#ifndef TURBO_P2P_MESH_MGMT_CODEC_H
#define TURBO_P2P_MESH_MGMT_CODEC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_MGMT_FRAME_MAX 16384u
#define MESH_MGMT_HEADER_MAX 512u
#define MESH_MGMT_PREFIX_SIZE 14u
#define MESH_MGMT_SIGNATURE_SIZE 64u
#define MESH_MGMT_TLV_PREFIX_SIZE 4u
#define MESH_MGMT_MAJOR_V1 1u
#define MESH_MGMT_MINOR_V1 0u

typedef enum {
    MESH_MGMT_KIND_HELLO = 0x01,
    MESH_MGMT_KIND_HELLO_ACK = 0x02,
    MESH_MGMT_KIND_FORWARD = 0x03,
    MESH_MGMT_KIND_PROBE = 0x10,
    MESH_MGMT_KIND_PROBE_ACK = 0x11,
    MESH_MGMT_KIND_INDIRECT_PROBE = 0x12,
    MESH_MGMT_KIND_INDIRECT_ACK = 0x13,
    MESH_MGMT_KIND_MEMBERSHIP_DELTA = 0x14,
    MESH_MGMT_KIND_DIGEST = 0x20,
    MESH_MGMT_KIND_DELTA_REQUEST = 0x21,
    MESH_MGMT_KIND_DELTA_BATCH = 0x22,
    MESH_MGMT_KIND_COMMAND_REQUEST = 0x30,
    MESH_MGMT_KIND_COMMAND_ACCEPTED = 0x31,
    MESH_MGMT_KIND_COMMAND_RESULT = 0x32,
    MESH_MGMT_KIND_COMMAND_STATUS = 0x33,
    MESH_MGMT_KIND_AUDIT_ANCHOR = 0x40,
    MESH_MGMT_KIND_STREAM_TICKET_REQUEST = 0x50,
    MESH_MGMT_KIND_STREAM_TICKET_ISSUED = 0x51,
    MESH_MGMT_KIND_ERROR = 0x7f,
} mesh_mgmt_kind_t;

typedef enum {
    MESH_MGMT_CODEC_OK = 0,
    MESH_MGMT_CODEC_INVALID_ARG = -1,
    MESH_MGMT_CODEC_INVALID_FRAME = -2,
    MESH_MGMT_CODEC_UNSUPPORTED_VERSION = -3,
    MESH_MGMT_CODEC_RESOURCE_EXHAUSTED = -4,
} mesh_mgmt_codec_result_t;

typedef struct {
    uint8_t major;
    uint8_t minor;
    uint8_t kind;
    uint8_t flags;
    const uint8_t *header;
    size_t header_len;
    const uint8_t *payload;
    size_t payload_len;
    const uint8_t *signature;
} mesh_mgmt_frame_view_t;

typedef struct {
    uint8_t major;
    uint8_t minor;
    uint8_t kind;
    uint8_t flags;
    const uint8_t *header;
    size_t header_len;
    const uint8_t *payload;
    size_t payload_len;
    const uint8_t *signature;
} mesh_mgmt_frame_input_t;

typedef struct {
    const uint8_t *bytes;
    size_t length;
    size_t offset;
    uint16_t previous_field_id;
    int has_previous;
} mesh_mgmt_tlv_reader_t;

typedef struct {
    uint16_t field_id;
    const uint8_t *value;
    size_t value_len;
} mesh_mgmt_tlv_view_t;

/**
 * Validate and expose a borrowed view over one complete MMP frame.
 * The input bytes must outlive the returned view. No signature or field-schema
 * validation is performed at this structural codec boundary.
 */
mesh_mgmt_codec_result_t mesh_mgmt_frame_decode(
    const uint8_t *frame,
    size_t frame_len,
    mesh_mgmt_frame_view_t *out_view);

/**
 * Encode one complete frame from already-canonical header and payload TLVs.
 * On insufficient capacity, writes the required size to out_len and leaves
 * output untouched.
 */
mesh_mgmt_codec_result_t mesh_mgmt_frame_encode(
    const mesh_mgmt_frame_input_t *input,
    uint8_t *output,
    size_t output_capacity,
    size_t *out_len);

void mesh_mgmt_tlv_reader_init(mesh_mgmt_tlv_reader_t *reader,
                               const uint8_t *bytes,
                               size_t length);

/**
 * Return 1 for one field, 0 at the exact end, or -1 for malformed/noncanonical
 * input. Returned values borrow storage from the reader input.
 */
int mesh_mgmt_tlv_reader_next(mesh_mgmt_tlv_reader_t *reader,
                              mesh_mgmt_tlv_view_t *out_field);

#ifdef __cplusplus
}
#endif

#endif
