#include "mesh_mgmt_envelope.h"
#include "mesh_mgmt_wire.h"

#include <string.h>

static const uint8_t MESH_MGMT_SIGNATURE_DOMAIN[] = "TurboMesh-MMP-v1";
static const uint8_t MESH_MGMT_ZERO_SIGNATURE[MESH_MGMT_SIGNATURE_SIZE] = {0};

#define MESH_MGMT_SIGNING_INPUT_MAX                                      \
    (sizeof(MESH_MGMT_SIGNATURE_DOMAIN) + MESH_MGMT_FRAME_MAX -          \
     MESH_MGMT_SIGNATURE_SIZE)
#define MESH_MGMT_PAYLOAD_V1_MAX                                         \
    (MESH_MGMT_FRAME_MAX - MESH_MGMT_PREFIX_SIZE -                       \
     MESH_MGMT_SIGNATURE_SIZE - MESH_MGMT_HEADER_V1_ENCODED_SIZE)

static size_t mesh_mgmt_write_u64_tlv(uint8_t *output,
                                      uint16_t field_id,
                                      uint64_t value) {
    uint8_t bytes[sizeof(value)];

    mesh_mgmt_wire_write_u64(bytes, value);
    return mesh_mgmt_wire_write_tlv(output, field_id, bytes, sizeof(bytes));
}

static size_t mesh_mgmt_header_encode_v1(
    const mesh_mgmt_header_v1_t *header,
    uint8_t output[MESH_MGMT_HEADER_V1_ENCODED_SIZE]) {
    size_t offset = 0;

#define WRITE_FIELD(field_id, field)                                      \
    offset += mesh_mgmt_wire_write_tlv(output + offset, (field_id),        \
                                  header->field, sizeof(header->field))
#define WRITE_U64_FIELD(field_id, field)                                   \
    offset += mesh_mgmt_write_u64_tlv(output + offset, (field_id),          \
                                      header->field)
    WRITE_FIELD(MESH_MGMT_HEADER_FIELD_MESH_ID_HASH, mesh_id_hash);
    WRITE_FIELD(MESH_MGMT_HEADER_FIELD_ORIGIN_PRINCIPAL_KEY,
                origin_principal_key);
    WRITE_FIELD(MESH_MGMT_HEADER_FIELD_ORIGIN_NODE_ID, origin_node_id);
    WRITE_FIELD(MESH_MGMT_HEADER_FIELD_TARGET_NODE_ID, target_node_id);
    WRITE_U64_FIELD(MESH_MGMT_HEADER_FIELD_PRINCIPAL_EPOCH,
                    principal_epoch);
    WRITE_U64_FIELD(MESH_MGMT_HEADER_FIELD_INCARNATION, incarnation);
    WRITE_FIELD(MESH_MGMT_HEADER_FIELD_SESSION_ID, session_id);
    WRITE_U64_FIELD(MESH_MGMT_HEADER_FIELD_ORIGIN_SEQUENCE, origin_sequence);
    WRITE_FIELD(MESH_MGMT_HEADER_FIELD_MESSAGE_ID, message_id);
    WRITE_U64_FIELD(MESH_MGMT_HEADER_FIELD_ISSUED_AT_MS, issued_at_ms);
    WRITE_U64_FIELD(MESH_MGMT_HEADER_FIELD_EXPIRES_AT_MS, expires_at_ms);
    offset += mesh_mgmt_wire_write_tlv(
        output + offset, MESH_MGMT_HEADER_FIELD_FORWARD_BUDGET,
        &header->forward_budget, sizeof(header->forward_budget));
    WRITE_FIELD(MESH_MGMT_HEADER_FIELD_PAYLOAD_HASH, payload_hash);
    WRITE_U64_FIELD(MESH_MGMT_HEADER_FIELD_CERTIFICATE_SERIAL,
                    certificate_serial);
#undef WRITE_U64_FIELD
#undef WRITE_FIELD
    return offset;
}

static int mesh_mgmt_kind_requires_target(uint8_t kind) {
    return kind == MESH_MGMT_KIND_COMMAND_REQUEST ||
           kind == MESH_MGMT_KIND_COMMAND_ACCEPTED ||
           kind == MESH_MGMT_KIND_COMMAND_RESULT ||
           kind == MESH_MGMT_KIND_COMMAND_STATUS ||
           kind == MESH_MGMT_KIND_CONTROL_FRAME;
}

static int mesh_mgmt_bytes_are_zero(const uint8_t *bytes, size_t length) {
    uint8_t aggregate = 0;
    size_t index = 0;

    for (index = 0; index < length; index++) {
        aggregate |= bytes[index];
    }
    return aggregate == 0u;
}

static int mesh_mgmt_header_constraints_are_valid(
    uint8_t kind,
    const mesh_mgmt_header_v1_t *header) {
    if (header->expires_at_ms <= header->issued_at_ms ||
        header->forward_budget > 1u) {
        return 0;
    }
    if (mesh_mgmt_kind_requires_target(kind) &&
        mesh_mgmt_bytes_are_zero(header->target_node_id,
                                 sizeof(header->target_node_id))) {
        return 0;
    }
    return 1;
}

static int mesh_mgmt_header_parse_v1(const uint8_t *bytes,
                                     size_t length,
                                     mesh_mgmt_header_v1_t *out_header) {
    mesh_mgmt_tlv_reader_t reader;
    mesh_mgmt_tlv_view_t field;

    if (length != MESH_MGMT_HEADER_V1_ENCODED_SIZE) {
        return 0;
    }
    memset(out_header, 0, sizeof(*out_header));
    mesh_mgmt_tlv_reader_init(&reader, bytes, length);

#define READ_FIELD(field_id, field_name)                                   \
    do {                                                                    \
        if (!mesh_mgmt_wire_read_field(&reader, (field_id),                 \
                                  sizeof(out_header->field_name), &field)) { \
            return 0;                                                       \
        }                                                                   \
        memcpy(out_header->field_name, field.value, field.value_len);       \
    } while (0)
#define READ_U64_FIELD(field_id, field_name)                               \
    do {                                                                    \
        if (!mesh_mgmt_wire_read_field(&reader, (field_id),                 \
                                       sizeof(uint64_t),                    \
                                  &field)) {                                \
            return 0;                                                       \
        }                                                                   \
        out_header->field_name = mesh_mgmt_wire_read_u64(field.value);      \
    } while (0)
    READ_FIELD(MESH_MGMT_HEADER_FIELD_MESH_ID_HASH, mesh_id_hash);
    READ_FIELD(MESH_MGMT_HEADER_FIELD_ORIGIN_PRINCIPAL_KEY,
               origin_principal_key);
    READ_FIELD(MESH_MGMT_HEADER_FIELD_ORIGIN_NODE_ID, origin_node_id);
    READ_FIELD(MESH_MGMT_HEADER_FIELD_TARGET_NODE_ID, target_node_id);
    READ_U64_FIELD(MESH_MGMT_HEADER_FIELD_PRINCIPAL_EPOCH,
                   principal_epoch);
    READ_U64_FIELD(MESH_MGMT_HEADER_FIELD_INCARNATION, incarnation);
    READ_FIELD(MESH_MGMT_HEADER_FIELD_SESSION_ID, session_id);
    READ_U64_FIELD(MESH_MGMT_HEADER_FIELD_ORIGIN_SEQUENCE, origin_sequence);
    READ_FIELD(MESH_MGMT_HEADER_FIELD_MESSAGE_ID, message_id);
    READ_U64_FIELD(MESH_MGMT_HEADER_FIELD_ISSUED_AT_MS, issued_at_ms);
    READ_U64_FIELD(MESH_MGMT_HEADER_FIELD_EXPIRES_AT_MS, expires_at_ms);
    if (!mesh_mgmt_wire_read_field(
            &reader, MESH_MGMT_HEADER_FIELD_FORWARD_BUDGET,
            sizeof(out_header->forward_budget), &field)) {
        return 0;
    }
    out_header->forward_budget = field.value[0];
    READ_FIELD(MESH_MGMT_HEADER_FIELD_PAYLOAD_HASH, payload_hash);
    READ_U64_FIELD(MESH_MGMT_HEADER_FIELD_CERTIFICATE_SERIAL,
                   certificate_serial);
#undef READ_U64_FIELD
#undef READ_FIELD
    return mesh_mgmt_tlv_reader_next(&reader, &field) == 0;
}

static mesh_mgmt_envelope_result_t mesh_mgmt_map_codec_result(
    mesh_mgmt_codec_result_t result) {
    switch (result) {
        case MESH_MGMT_CODEC_OK:
            return MESH_MGMT_ENVELOPE_OK;
        case MESH_MGMT_CODEC_INVALID_ARG:
            return MESH_MGMT_ENVELOPE_INVALID_ARG;
        case MESH_MGMT_CODEC_UNSUPPORTED_VERSION:
            return MESH_MGMT_ENVELOPE_UNSUPPORTED_VERSION;
        case MESH_MGMT_CODEC_RESOURCE_EXHAUSTED:
            return MESH_MGMT_ENVELOPE_RESOURCE_EXHAUSTED;
        case MESH_MGMT_CODEC_INVALID_FRAME:
        default:
            return MESH_MGMT_ENVELOPE_INVALID_FRAME;
    }
}

static size_t mesh_mgmt_build_signing_input(const uint8_t *frame,
                                            size_t unsigned_frame_len,
                                            uint8_t *output) {
    memcpy(output, MESH_MGMT_SIGNATURE_DOMAIN,
           sizeof(MESH_MGMT_SIGNATURE_DOMAIN));
    memcpy(output + sizeof(MESH_MGMT_SIGNATURE_DOMAIN), frame,
           unsigned_frame_len);
    return sizeof(MESH_MGMT_SIGNATURE_DOMAIN) + unsigned_frame_len;
}

mesh_mgmt_envelope_result_t mesh_mgmt_envelope_sign_v1(
    const mesh_mgmt_sign_input_v1_t *input,
    uint8_t *output,
    size_t output_capacity,
    size_t *out_len) {
    mesh_mgmt_header_v1_t header;
    mesh_mgmt_frame_input_t frame_input;
    mesh_mgmt_codec_result_t codec_result;
    mesh_mgmt_crypto_result_t crypto_result;
    uint8_t encoded_header[MESH_MGMT_HEADER_V1_ENCODED_SIZE];
    uint8_t signing_input[MESH_MGMT_SIGNING_INPUT_MAX];
    uint8_t signature[MESH_MGMT_SIGNATURE_SIZE];
    size_t header_len = 0;
    size_t signing_len = 0;
    size_t encoded_len = 0;

    if (!out_len) {
        return MESH_MGMT_ENVELOPE_INVALID_ARG;
    }
    *out_len = 0;
    if (!input || !input->private_key ||
        (!input->payload && input->payload_len != 0u)) {
        return MESH_MGMT_ENVELOPE_INVALID_ARG;
    }
    if (input->minor != MESH_MGMT_MINOR_V1) {
        return MESH_MGMT_ENVELOPE_UNSUPPORTED_VERSION;
    }
    if (input->payload_len > MESH_MGMT_PAYLOAD_V1_MAX) {
        return MESH_MGMT_ENVELOPE_RESOURCE_EXHAUSTED;
    }

    memset(&header, 0, sizeof(header));
    memcpy(header.mesh_id_hash, input->header.mesh_id_hash,
           sizeof(header.mesh_id_hash));
    memcpy(header.origin_node_id, input->header.origin_node_id,
           sizeof(header.origin_node_id));
    memcpy(header.target_node_id, input->header.target_node_id,
           sizeof(header.target_node_id));
    header.principal_epoch = input->header.principal_epoch;
    header.incarnation = input->header.incarnation;
    memcpy(header.session_id, input->header.session_id,
           sizeof(header.session_id));
    header.origin_sequence = input->header.origin_sequence;
    memcpy(header.message_id, input->header.message_id,
           sizeof(header.message_id));
    header.issued_at_ms = input->header.issued_at_ms;
    header.expires_at_ms = input->header.expires_at_ms;
    header.forward_budget = input->header.forward_budget;
    header.certificate_serial = input->header.certificate_serial;
    if (!mesh_mgmt_header_constraints_are_valid(input->kind, &header)) {
        return MESH_MGMT_ENVELOPE_INVALID_SCHEMA;
    }

    crypto_result = mesh_mgmt_ed25519_public_from_private(
        input->private_key, header.origin_principal_key);
    if (crypto_result != MESH_MGMT_CRYPTO_OK) {
        return MESH_MGMT_ENVELOPE_CRYPTO_FAILURE;
    }
    crypto_result = mesh_mgmt_blake2b_256(input->payload, input->payload_len,
                                          header.payload_hash);
    if (crypto_result != MESH_MGMT_CRYPTO_OK) {
        return MESH_MGMT_ENVELOPE_CRYPTO_FAILURE;
    }
    header_len = mesh_mgmt_header_encode_v1(&header, encoded_header);
    if (header_len != sizeof(encoded_header)) {
        return MESH_MGMT_ENVELOPE_INVALID_SCHEMA;
    }

    memset(&frame_input, 0, sizeof(frame_input));
    frame_input.major = MESH_MGMT_MAJOR_V1;
    frame_input.minor = input->minor;
    frame_input.kind = input->kind;
    frame_input.flags = input->flags;
    frame_input.header = encoded_header;
    frame_input.header_len = header_len;
    frame_input.payload = input->payload;
    frame_input.payload_len = input->payload_len;
    frame_input.signature = MESH_MGMT_ZERO_SIGNATURE;
    codec_result = mesh_mgmt_frame_encode(&frame_input, output,
                                          output_capacity, &encoded_len);
    if (codec_result != MESH_MGMT_CODEC_OK) {
        *out_len = encoded_len;
        return mesh_mgmt_map_codec_result(codec_result);
    }

    signing_len = mesh_mgmt_build_signing_input(
        output, encoded_len - MESH_MGMT_SIGNATURE_SIZE, signing_input);
    crypto_result = mesh_mgmt_ed25519_sign(input->private_key, signing_input,
                                           signing_len, signature);
    if (crypto_result != MESH_MGMT_CRYPTO_OK) {
        memset(output, 0, encoded_len);
        return MESH_MGMT_ENVELOPE_CRYPTO_FAILURE;
    }
    memcpy(output + encoded_len - MESH_MGMT_SIGNATURE_SIZE, signature,
           sizeof(signature));
    *out_len = encoded_len;
    return MESH_MGMT_ENVELOPE_OK;
}

mesh_mgmt_envelope_result_t mesh_mgmt_envelope_verify_v1(
    const uint8_t *frame,
    size_t frame_len,
    mesh_mgmt_verified_envelope_v1_t *out_envelope) {
    mesh_mgmt_verified_envelope_v1_t verified;
    mesh_mgmt_codec_result_t codec_result;
    mesh_mgmt_crypto_result_t crypto_result;
    uint8_t actual_payload_hash[MESH_MGMT_BLAKE2B_256_SIZE];
    uint8_t signing_input[MESH_MGMT_SIGNING_INPUT_MAX];
    size_t signing_len = 0;

    if (!out_envelope) {
        return MESH_MGMT_ENVELOPE_INVALID_ARG;
    }
    memset(out_envelope, 0, sizeof(*out_envelope));
    if (!frame) {
        return MESH_MGMT_ENVELOPE_INVALID_ARG;
    }
    memset(&verified, 0, sizeof(verified));
    codec_result = mesh_mgmt_frame_decode(frame, frame_len, &verified.frame);
    if (codec_result != MESH_MGMT_CODEC_OK) {
        return mesh_mgmt_map_codec_result(codec_result);
    }
    if (verified.frame.minor != MESH_MGMT_MINOR_V1) {
        return MESH_MGMT_ENVELOPE_UNSUPPORTED_VERSION;
    }
    if (!mesh_mgmt_header_parse_v1(verified.frame.header,
                                   verified.frame.header_len,
                                   &verified.header) ||
        !mesh_mgmt_header_constraints_are_valid(verified.frame.kind,
                                                &verified.header)) {
        return MESH_MGMT_ENVELOPE_INVALID_SCHEMA;
    }
    crypto_result = mesh_mgmt_blake2b_256(
        verified.frame.payload, verified.frame.payload_len,
        actual_payload_hash);
    if (crypto_result != MESH_MGMT_CRYPTO_OK) {
        return MESH_MGMT_ENVELOPE_CRYPTO_FAILURE;
    }
    if (!mesh_mgmt_crypto_equal_32(actual_payload_hash,
                                   verified.header.payload_hash)) {
        return MESH_MGMT_ENVELOPE_PAYLOAD_HASH_MISMATCH;
    }

    signing_len = mesh_mgmt_build_signing_input(
        frame, frame_len - MESH_MGMT_SIGNATURE_SIZE, signing_input);
    crypto_result = mesh_mgmt_ed25519_verify(
        verified.header.origin_principal_key, signing_input, signing_len,
        verified.frame.signature);
    if (crypto_result == MESH_MGMT_CRYPTO_AUTH_FAILED) {
        return MESH_MGMT_ENVELOPE_AUTH_FAILED;
    }
    if (crypto_result != MESH_MGMT_CRYPTO_OK) {
        return MESH_MGMT_ENVELOPE_CRYPTO_FAILURE;
    }

    *out_envelope = verified;
    return MESH_MGMT_ENVELOPE_OK;
}
