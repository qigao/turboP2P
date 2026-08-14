#ifndef TURBO_P2P_MESH_MGMT_ENVELOPE_H
#define TURBO_P2P_MESH_MGMT_ENVELOPE_H

#include "mesh_mgmt_codec.h"
#include "mesh_mgmt_crypto.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_MGMT_HEADER_V1_ENCODED_SIZE 297u

typedef enum {
    MESH_MGMT_HEADER_FIELD_MESH_ID_HASH = 0x0001,
    MESH_MGMT_HEADER_FIELD_ORIGIN_PRINCIPAL_KEY = 0x0002,
    MESH_MGMT_HEADER_FIELD_ORIGIN_NODE_ID = 0x0003,
    MESH_MGMT_HEADER_FIELD_TARGET_NODE_ID = 0x0004,
    MESH_MGMT_HEADER_FIELD_PRINCIPAL_EPOCH = 0x0005,
    MESH_MGMT_HEADER_FIELD_INCARNATION = 0x0006,
    MESH_MGMT_HEADER_FIELD_SESSION_ID = 0x0007,
    MESH_MGMT_HEADER_FIELD_ORIGIN_SEQUENCE = 0x0008,
    MESH_MGMT_HEADER_FIELD_MESSAGE_ID = 0x0009,
    MESH_MGMT_HEADER_FIELD_ISSUED_AT_MS = 0x000a,
    MESH_MGMT_HEADER_FIELD_EXPIRES_AT_MS = 0x000b,
    MESH_MGMT_HEADER_FIELD_FORWARD_BUDGET = 0x000c,
    MESH_MGMT_HEADER_FIELD_PAYLOAD_HASH = 0x000d,
    MESH_MGMT_HEADER_FIELD_CERTIFICATE_SERIAL = 0x000e,
} mesh_mgmt_header_field_v1_t;

typedef enum {
    MESH_MGMT_ENVELOPE_OK = 0,
    MESH_MGMT_ENVELOPE_INVALID_ARG = -1,
    MESH_MGMT_ENVELOPE_INVALID_FRAME = -2,
    MESH_MGMT_ENVELOPE_UNSUPPORTED_VERSION = -3,
    MESH_MGMT_ENVELOPE_RESOURCE_EXHAUSTED = -4,
    MESH_MGMT_ENVELOPE_INVALID_SCHEMA = -5,
    MESH_MGMT_ENVELOPE_PAYLOAD_HASH_MISMATCH = -6,
    MESH_MGMT_ENVELOPE_AUTH_FAILED = -7,
    MESH_MGMT_ENVELOPE_CRYPTO_FAILURE = -8,
} mesh_mgmt_envelope_result_t;

typedef struct {
    uint8_t mesh_id_hash[32];
    uint8_t origin_principal_key[32];
    uint8_t origin_node_id[32];
    uint8_t target_node_id[32];
    uint64_t principal_epoch;
    uint64_t incarnation;
    uint8_t session_id[16];
    uint64_t origin_sequence;
    uint8_t message_id[16];
    uint64_t issued_at_ms;
    uint64_t expires_at_ms;
    uint8_t forward_budget;
    uint8_t payload_hash[32];
    uint64_t certificate_serial;
} mesh_mgmt_header_v1_t;

/* Fields derived by signing (principal key and payload hash) are excluded. */
typedef struct {
    uint8_t mesh_id_hash[32];
    uint8_t origin_node_id[32];
    uint8_t target_node_id[32];
    uint64_t principal_epoch;
    uint64_t incarnation;
    uint8_t session_id[16];
    uint64_t origin_sequence;
    uint8_t message_id[16];
    uint64_t issued_at_ms;
    uint64_t expires_at_ms;
    uint8_t forward_budget;
    uint64_t certificate_serial;
} mesh_mgmt_unsigned_header_v1_t;

typedef struct {
    uint8_t minor;
    uint8_t kind;
    uint8_t flags;
    mesh_mgmt_unsigned_header_v1_t header;
    const uint8_t *private_key;
    const uint8_t *payload;
    size_t payload_len;
} mesh_mgmt_sign_input_v1_t;

typedef struct {
    mesh_mgmt_frame_view_t frame;
    mesh_mgmt_header_v1_t header;
} mesh_mgmt_verified_envelope_v1_t;

/**
 * Build and sign one MMP/1.1 frame. The caller owns every input and output
 * buffer; input and output ranges must not overlap. On insufficient capacity,
 * out_len receives the required size and output remains untouched. Other
 * failures set out_len to zero; a failure after encoding clears written bytes.
 */
mesh_mgmt_envelope_result_t mesh_mgmt_envelope_sign_v1(
    const mesh_mgmt_sign_input_v1_t *input,
    uint8_t *output,
    size_t output_capacity,
    size_t *out_len);

/**
 * Verify structural framing, the exact MMP/1.1 common-header schema, payload
 * hash, and the domain-separated Ed25519 signature. The returned frame view
 * borrows the input bytes, which must outlive it. Output is zeroed on failure.
 */
mesh_mgmt_envelope_result_t mesh_mgmt_envelope_verify_v1(
    const uint8_t *frame,
    size_t frame_len,
    mesh_mgmt_verified_envelope_v1_t *out_envelope);

#ifdef __cplusplus
}
#endif

#endif
