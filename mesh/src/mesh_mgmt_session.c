#include "mesh_mgmt_session.h"

#include "mesh_mgmt_wire.h"

#include <string.h>

typedef enum {
    HELLO_FIELD_MAJOR = 0x0001,
    HELLO_FIELD_MIN_MINOR = 0x0002,
    HELLO_FIELD_MAX_MINOR = 0x0003,
    HELLO_FIELD_FEATURES = 0x0004,
    HELLO_FIELD_PLATFORM = 0x0005,
    HELLO_FIELD_BUILD_VERSION = 0x0006,
    HELLO_FIELD_CERTIFICATE = 0x0007,
    HELLO_FIELD_ISSUER_CHAIN_HASH = 0x0008,
    HELLO_FIELD_PRINCIPAL_TYPE = 0x0009,
    HELLO_FIELD_MANAGEMENT_KEY = 0x000a,
    HELLO_FIELD_MANAGED_NODE_ID = 0x000b,
    HELLO_FIELD_CONNECTION_ID = 0x000c,
    HELLO_FIELD_MAX_FRAME = 0x000d,
    HELLO_FIELD_MAX_DIGEST_ENTRIES = 0x000e,
    HELLO_FIELD_MAX_DELTA_BATCH = 0x000f,
} mesh_mgmt_hello_field_v1_t;

typedef enum {
    ACK_FIELD_SELECTED_MAJOR = 0x0001,
    ACK_FIELD_SELECTED_MINOR = 0x0002,
    ACK_FIELD_FEATURES = 0x0003,
    ACK_FIELD_MAX_FRAME = 0x0004,
    ACK_FIELD_MAX_DIGEST_ENTRIES = 0x0005,
    ACK_FIELD_MAX_DELTA_BATCH = 0x0006,
    ACK_FIELD_PEER_CONNECTION_ID = 0x0007,
} mesh_mgmt_ack_field_v1_t;

static int visible_ascii(const uint8_t *bytes, size_t length) {
    size_t index = 0;

    if (!bytes || length == 0u || length > MESH_MGMT_BUILD_VERSION_MAX) {
        return 0;
    }
    for (index = 0; index < length; index++) {
        if (bytes[index] < 0x21u || bytes[index] > 0x7eu) return 0;
    }
    return 1;
}

static int bytes_are_zero(const uint8_t *bytes, size_t length) {
    uint8_t aggregate = 0;
    size_t index = 0;

    for (index = 0; index < length; index++) aggregate |= bytes[index];
    return aggregate == 0u;
}

static int hello_limits_are_valid(const mesh_mgmt_hello_v1_t *hello) {
    return hello->major == MESH_MGMT_MAJOR_V1 &&
           hello->min_minor <= hello->max_minor &&
           hello->platform >= MESH_MGMT_PLATFORM_LINUX &&
           hello->platform <= MESH_MGMT_PLATFORM_OTHER &&
           visible_ascii(hello->build_version, hello->build_version_len) &&
           hello->principal_type == MESH_MGMT_PRINCIPAL_NODE &&
           !bytes_are_zero(hello->certificate,
                           sizeof(hello->certificate)) &&
           !bytes_are_zero(hello->issuer_chain_hash, 32) &&
           !bytes_are_zero(hello->management_key, 32) &&
           !bytes_are_zero(hello->managed_node_id, 32) &&
           !bytes_are_zero(hello->connection_id, 16) &&
           hello->max_frame >= MESH_MGMT_SESSION_MIN_FRAME &&
           hello->max_frame <= MESH_MGMT_FRAME_MAX &&
           hello->max_digest_entries > 0u &&
           hello->max_digest_entries <= MESH_MGMT_DIGEST_ENTRIES_MAX &&
           hello->max_delta_batch > 0u &&
           hello->max_delta_batch <= MESH_MGMT_DELTA_BATCH_MAX;
}

static size_t write_u16_tlv(uint8_t *output,
                            uint16_t field_id,
                            uint16_t value) {
    uint8_t bytes[2];
    mesh_mgmt_wire_write_u16(bytes, value);
    return mesh_mgmt_wire_write_tlv(output, field_id, bytes, sizeof(bytes));
}

static size_t write_u32_tlv(uint8_t *output,
                            uint16_t field_id,
                            uint32_t value) {
    uint8_t bytes[4];
    mesh_mgmt_wire_write_u32(bytes, value);
    return mesh_mgmt_wire_write_tlv(output, field_id, bytes, sizeof(bytes));
}

static size_t write_u64_tlv(uint8_t *output,
                            uint16_t field_id,
                            uint64_t value) {
    uint8_t bytes[8];
    mesh_mgmt_wire_write_u64(bytes, value);
    return mesh_mgmt_wire_write_tlv(output, field_id, bytes, sizeof(bytes));
}

mesh_mgmt_session_result_t mesh_mgmt_hello_encode_v1(
    const mesh_mgmt_hello_v1_t *hello,
    uint8_t *output,
    size_t output_capacity,
    size_t *out_len) {
    size_t required = 0;
    size_t offset = 0;

    if (!out_len) return MESH_MGMT_SESSION_INVALID_ARG;
    *out_len = 0;
    if (!hello || !hello_limits_are_valid(hello)) {
        return hello ? MESH_MGMT_SESSION_INVALID_SCHEMA
                     : MESH_MGMT_SESSION_INVALID_ARG;
    }
    required = MESH_MGMT_HELLO_V1_MAX_SIZE - MESH_MGMT_BUILD_VERSION_MAX +
               hello->build_version_len;
    if (!output || output_capacity < required) {
        *out_len = required;
        return MESH_MGMT_SESSION_RESOURCE_EXHAUSTED;
    }
#define WRITE_HELLO_FIELD(id, field)                                     \
    offset += mesh_mgmt_wire_write_tlv(output + offset, (id), hello->field, \
                                       sizeof(hello->field))
    offset += mesh_mgmt_wire_write_tlv(output + offset, HELLO_FIELD_MAJOR,
                                       &hello->major, 1);
    offset += mesh_mgmt_wire_write_tlv(output + offset,
                                       HELLO_FIELD_MIN_MINOR,
                                       &hello->min_minor, 1);
    offset += mesh_mgmt_wire_write_tlv(output + offset,
                                       HELLO_FIELD_MAX_MINOR,
                                       &hello->max_minor, 1);
    offset += write_u64_tlv(output + offset, HELLO_FIELD_FEATURES,
                            hello->features);
    offset += mesh_mgmt_wire_write_tlv(output + offset,
                                       HELLO_FIELD_PLATFORM,
                                       &hello->platform, 1);
    offset += mesh_mgmt_wire_write_tlv(output + offset,
                                       HELLO_FIELD_BUILD_VERSION,
                                       hello->build_version,
                                       hello->build_version_len);
    WRITE_HELLO_FIELD(HELLO_FIELD_CERTIFICATE, certificate);
    WRITE_HELLO_FIELD(HELLO_FIELD_ISSUER_CHAIN_HASH, issuer_chain_hash);
    offset += mesh_mgmt_wire_write_tlv(output + offset,
                                       HELLO_FIELD_PRINCIPAL_TYPE,
                                       &hello->principal_type, 1);
    WRITE_HELLO_FIELD(HELLO_FIELD_MANAGEMENT_KEY, management_key);
    WRITE_HELLO_FIELD(HELLO_FIELD_MANAGED_NODE_ID, managed_node_id);
    WRITE_HELLO_FIELD(HELLO_FIELD_CONNECTION_ID, connection_id);
    offset += write_u32_tlv(output + offset, HELLO_FIELD_MAX_FRAME,
                            hello->max_frame);
    offset += write_u16_tlv(output + offset, HELLO_FIELD_MAX_DIGEST_ENTRIES,
                            hello->max_digest_entries);
    offset += write_u16_tlv(output + offset, HELLO_FIELD_MAX_DELTA_BATCH,
                            hello->max_delta_batch);
#undef WRITE_HELLO_FIELD
    *out_len = offset;
    return offset == required ? MESH_MGMT_SESSION_OK
                              : MESH_MGMT_SESSION_INVALID_SCHEMA;
}

mesh_mgmt_session_result_t mesh_mgmt_hello_decode_v1(
    const uint8_t *payload,
    size_t payload_len,
    mesh_mgmt_hello_v1_t *out_hello) {
    mesh_mgmt_tlv_reader_t reader;
    mesh_mgmt_tlv_view_t field;

    if (!out_hello) return MESH_MGMT_SESSION_INVALID_ARG;
    memset(out_hello, 0, sizeof(*out_hello));
    if (!payload) return MESH_MGMT_SESSION_INVALID_ARG;
    mesh_mgmt_tlv_reader_init(&reader, payload, payload_len);
#define READ_HELLO_FIELD(id, field_name)                                  \
    do {                                                                   \
        if (!mesh_mgmt_wire_read_field(&reader, (id),                      \
                                       sizeof(out_hello->field_name),      \
                                       &field)) return MESH_MGMT_SESSION_INVALID_SCHEMA; \
        memcpy(out_hello->field_name, field.value, field.value_len);       \
    } while (0)
#define READ_HELLO_SCALAR(id, field_name, size, read_fn)                  \
    do {                                                                   \
        if (!mesh_mgmt_wire_read_field(&reader, (id), (size), &field))     \
            return MESH_MGMT_SESSION_INVALID_SCHEMA;                       \
        out_hello->field_name = read_fn(field.value);                      \
    } while (0)
    if (!mesh_mgmt_wire_read_field(&reader, HELLO_FIELD_MAJOR, 1, &field))
        return MESH_MGMT_SESSION_INVALID_SCHEMA;
    out_hello->major = field.value[0];
    if (!mesh_mgmt_wire_read_field(&reader, HELLO_FIELD_MIN_MINOR, 1, &field))
        return MESH_MGMT_SESSION_INVALID_SCHEMA;
    out_hello->min_minor = field.value[0];
    if (!mesh_mgmt_wire_read_field(&reader, HELLO_FIELD_MAX_MINOR, 1, &field))
        return MESH_MGMT_SESSION_INVALID_SCHEMA;
    out_hello->max_minor = field.value[0];
    READ_HELLO_SCALAR(HELLO_FIELD_FEATURES, features, 8,
                      mesh_mgmt_wire_read_u64);
    if (!mesh_mgmt_wire_read_field(&reader, HELLO_FIELD_PLATFORM, 1, &field))
        return MESH_MGMT_SESSION_INVALID_SCHEMA;
    out_hello->platform = field.value[0];
    if (mesh_mgmt_tlv_reader_next(&reader, &field) != 1 ||
        field.field_id != HELLO_FIELD_BUILD_VERSION ||
        !visible_ascii(field.value, field.value_len)) {
        return MESH_MGMT_SESSION_INVALID_SCHEMA;
    }
    memcpy(out_hello->build_version, field.value, field.value_len);
    out_hello->build_version_len = field.value_len;
    READ_HELLO_FIELD(HELLO_FIELD_CERTIFICATE, certificate);
    READ_HELLO_FIELD(HELLO_FIELD_ISSUER_CHAIN_HASH, issuer_chain_hash);
    if (!mesh_mgmt_wire_read_field(&reader, HELLO_FIELD_PRINCIPAL_TYPE, 1,
                                   &field)) return MESH_MGMT_SESSION_INVALID_SCHEMA;
    out_hello->principal_type = field.value[0];
    READ_HELLO_FIELD(HELLO_FIELD_MANAGEMENT_KEY, management_key);
    READ_HELLO_FIELD(HELLO_FIELD_MANAGED_NODE_ID, managed_node_id);
    READ_HELLO_FIELD(HELLO_FIELD_CONNECTION_ID, connection_id);
    READ_HELLO_SCALAR(HELLO_FIELD_MAX_FRAME, max_frame, 4,
                      mesh_mgmt_wire_read_u32);
    READ_HELLO_SCALAR(HELLO_FIELD_MAX_DIGEST_ENTRIES, max_digest_entries, 2,
                      mesh_mgmt_wire_read_u16);
    READ_HELLO_SCALAR(HELLO_FIELD_MAX_DELTA_BATCH, max_delta_batch, 2,
                      mesh_mgmt_wire_read_u16);
#undef READ_HELLO_SCALAR
#undef READ_HELLO_FIELD
    if (mesh_mgmt_tlv_reader_next(&reader, &field) != 0 ||
        !hello_limits_are_valid(out_hello)) {
        memset(out_hello, 0, sizeof(*out_hello));
        return MESH_MGMT_SESSION_INVALID_SCHEMA;
    }
    return MESH_MGMT_SESSION_OK;
}

static int ack_schema_is_valid(const mesh_mgmt_hello_ack_v1_t *ack) {
    return ack->selected_major == MESH_MGMT_MAJOR_V1 &&
           ack->max_frame >= MESH_MGMT_SESSION_MIN_FRAME &&
           ack->max_frame <= MESH_MGMT_FRAME_MAX &&
           ack->max_digest_entries > 0u &&
           ack->max_digest_entries <= MESH_MGMT_DIGEST_ENTRIES_MAX &&
           ack->max_delta_batch > 0u &&
           ack->max_delta_batch <= MESH_MGMT_DELTA_BATCH_MAX &&
           !bytes_are_zero(ack->peer_connection_id, 16);
}

mesh_mgmt_session_result_t mesh_mgmt_hello_ack_encode_v1(
    const mesh_mgmt_hello_ack_v1_t *ack,
    uint8_t *output,
    size_t output_capacity,
    size_t *out_len) {
    size_t offset = 0;

    if (!out_len) return MESH_MGMT_SESSION_INVALID_ARG;
    *out_len = 0;
    if (!ack || !ack_schema_is_valid(ack)) {
        return ack ? MESH_MGMT_SESSION_INVALID_SCHEMA
                   : MESH_MGMT_SESSION_INVALID_ARG;
    }
    if (!output || output_capacity < MESH_MGMT_HELLO_ACK_V1_SIZE) {
        *out_len = MESH_MGMT_HELLO_ACK_V1_SIZE;
        return MESH_MGMT_SESSION_RESOURCE_EXHAUSTED;
    }
    offset += mesh_mgmt_wire_write_tlv(output + offset,
                                       ACK_FIELD_SELECTED_MAJOR,
                                       &ack->selected_major, 1);
    offset += mesh_mgmt_wire_write_tlv(output + offset,
                                       ACK_FIELD_SELECTED_MINOR,
                                       &ack->selected_minor, 1);
    offset += write_u64_tlv(output + offset, ACK_FIELD_FEATURES,
                            ack->features);
    offset += write_u32_tlv(output + offset, ACK_FIELD_MAX_FRAME,
                            ack->max_frame);
    offset += write_u16_tlv(output + offset, ACK_FIELD_MAX_DIGEST_ENTRIES,
                            ack->max_digest_entries);
    offset += write_u16_tlv(output + offset, ACK_FIELD_MAX_DELTA_BATCH,
                            ack->max_delta_batch);
    offset += mesh_mgmt_wire_write_tlv(output + offset,
                                       ACK_FIELD_PEER_CONNECTION_ID,
                                       ack->peer_connection_id, 16);
    *out_len = offset;
    return offset == MESH_MGMT_HELLO_ACK_V1_SIZE
               ? MESH_MGMT_SESSION_OK
               : MESH_MGMT_SESSION_INVALID_SCHEMA;
}

mesh_mgmt_session_result_t mesh_mgmt_hello_ack_decode_v1(
    const uint8_t *payload,
    size_t payload_len,
    mesh_mgmt_hello_ack_v1_t *out_ack) {
    mesh_mgmt_tlv_reader_t reader;
    mesh_mgmt_tlv_view_t field;

    if (!out_ack) return MESH_MGMT_SESSION_INVALID_ARG;
    memset(out_ack, 0, sizeof(*out_ack));
    if (!payload || payload_len != MESH_MGMT_HELLO_ACK_V1_SIZE)
        return MESH_MGMT_SESSION_INVALID_SCHEMA;
    mesh_mgmt_tlv_reader_init(&reader, payload, payload_len);
#define READ_ACK_SCALAR(id, field_name, size, read_fn)                    \
    do {                                                                   \
        if (!mesh_mgmt_wire_read_field(&reader, (id), (size), &field))     \
            return MESH_MGMT_SESSION_INVALID_SCHEMA;                       \
        out_ack->field_name = read_fn(field.value);                        \
    } while (0)
    if (!mesh_mgmt_wire_read_field(&reader, ACK_FIELD_SELECTED_MAJOR, 1,
                                   &field)) return MESH_MGMT_SESSION_INVALID_SCHEMA;
    out_ack->selected_major = field.value[0];
    if (!mesh_mgmt_wire_read_field(&reader, ACK_FIELD_SELECTED_MINOR, 1,
                                   &field)) return MESH_MGMT_SESSION_INVALID_SCHEMA;
    out_ack->selected_minor = field.value[0];
    READ_ACK_SCALAR(ACK_FIELD_FEATURES, features, 8, mesh_mgmt_wire_read_u64);
    READ_ACK_SCALAR(ACK_FIELD_MAX_FRAME, max_frame, 4,
                    mesh_mgmt_wire_read_u32);
    READ_ACK_SCALAR(ACK_FIELD_MAX_DIGEST_ENTRIES, max_digest_entries, 2,
                    mesh_mgmt_wire_read_u16);
    READ_ACK_SCALAR(ACK_FIELD_MAX_DELTA_BATCH, max_delta_batch, 2,
                    mesh_mgmt_wire_read_u16);
#undef READ_ACK_SCALAR
    if (!mesh_mgmt_wire_read_field(&reader, ACK_FIELD_PEER_CONNECTION_ID, 16,
                                   &field)) return MESH_MGMT_SESSION_INVALID_SCHEMA;
    memcpy(out_ack->peer_connection_id, field.value, 16);
    if (mesh_mgmt_tlv_reader_next(&reader, &field) != 0 ||
        !ack_schema_is_valid(out_ack)) {
        memset(out_ack, 0, sizeof(*out_ack));
        return MESH_MGMT_SESSION_INVALID_SCHEMA;
    }
    return MESH_MGMT_SESSION_OK;
}

static int config_is_valid(const mesh_mgmt_session_config_v1_t *config) {
    return !bytes_are_zero(config->expected_mesh_id_hash, 32) &&
           !bytes_are_zero(config->trusted_issuer_key, 32) &&
           !bytes_are_zero(config->connection_id, 16) &&
           config->min_minor <= config->max_minor &&
           config->min_minor <= MESH_MGMT_MINOR_V1 &&
           config->max_minor >= MESH_MGMT_MINOR_V1 &&
           config->max_frame >= MESH_MGMT_SESSION_MIN_FRAME &&
           config->max_frame <= MESH_MGMT_FRAME_MAX &&
           config->max_digest_entries > 0u &&
           config->max_digest_entries <= MESH_MGMT_DIGEST_ENTRIES_MAX &&
           config->max_delta_batch > 0u &&
           config->max_delta_batch <= MESH_MGMT_DELTA_BATCH_MAX;
}

mesh_mgmt_session_result_t mesh_mgmt_session_init_v1(
    mesh_mgmt_session_v1_t *session,
    const mesh_mgmt_session_config_v1_t *config) {
    if (!session || !config) return MESH_MGMT_SESSION_INVALID_ARG;
    memset(session, 0, sizeof(*session));
    session->state = MESH_MGMT_SESSION_FAILED;
    if (!config_is_valid(config)) return MESH_MGMT_SESSION_INVALID_SCHEMA;
    session->state = MESH_MGMT_SESSION_NEGOTIATING;
    session->config = *config;
    session->config.features &= MESH_MGMT_FEATURE_KNOWN_MASK;
    return MESH_MGMT_SESSION_OK;
}

static void session_fail(mesh_mgmt_session_v1_t *session) {
    session->state = MESH_MGMT_SESSION_FAILED;
    memset(&session->negotiated, 0, sizeof(session->negotiated));
    memset(&session->remote_certificate, 0,
           sizeof(session->remote_certificate));
    memset(session->remote_certificate_wire, 0,
           sizeof(session->remote_certificate_wire));
    memset(session->remote_connection_id, 0,
           sizeof(session->remote_connection_id));
    memset(session->remote_session_id, 0,
           sizeof(session->remote_session_id));
    session->remote_incarnation = 0u;
}

static void refresh_session_state(mesh_mgmt_session_v1_t *session) {
    if (session->local_hello_sent && session->remote_hello_verified &&
        session->local_ack_sent && session->remote_ack_received) {
        session->state = MESH_MGMT_SESSION_ESTABLISHED;
    }
}

mesh_mgmt_session_result_t mesh_mgmt_session_mark_hello_sent_v1(
    mesh_mgmt_session_v1_t *session) {
    if (!session) return MESH_MGMT_SESSION_INVALID_ARG;
    if (session->state != MESH_MGMT_SESSION_NEGOTIATING ||
        session->local_hello_sent) return MESH_MGMT_SESSION_INVALID_STATE;
    session->local_hello_sent = 1;
    return MESH_MGMT_SESSION_OK;
}

static mesh_mgmt_session_result_t negotiate(
    const mesh_mgmt_session_config_v1_t *local,
    const mesh_mgmt_hello_v1_t *remote,
    mesh_mgmt_negotiated_v1_t *out) {
    uint8_t minimum = local->min_minor > remote->min_minor
                          ? local->min_minor
                          : remote->min_minor;
    uint8_t maximum = local->max_minor < remote->max_minor
                          ? local->max_minor
                          : remote->max_minor;

    if (remote->major != MESH_MGMT_MAJOR_V1 || minimum > maximum) {
        return MESH_MGMT_SESSION_UNSUPPORTED_VERSION;
    }
    memset(out, 0, sizeof(*out));
    out->major = MESH_MGMT_MAJOR_V1;
    out->minor = maximum;
    out->features = local->features & remote->features &
                    MESH_MGMT_FEATURE_KNOWN_MASK;
    out->max_frame = local->max_frame < remote->max_frame
                         ? local->max_frame
                         : remote->max_frame;
    out->max_digest_entries =
        local->max_digest_entries < remote->max_digest_entries
            ? local->max_digest_entries
            : remote->max_digest_entries;
    out->max_delta_batch = local->max_delta_batch < remote->max_delta_batch
                               ? local->max_delta_batch
                               : remote->max_delta_batch;
    return MESH_MGMT_SESSION_OK;
}

static int envelope_time_is_valid(
    const mesh_mgmt_verified_envelope_v1_t *envelope,
    uint64_t now_ms) {
    return envelope->header.issued_at_ms <= now_ms &&
           now_ms < envelope->header.expires_at_ms;
}

static mesh_mgmt_session_result_t map_envelope_result(
    mesh_mgmt_envelope_result_t result) {
    switch (result) {
        case MESH_MGMT_ENVELOPE_OK:
            return MESH_MGMT_SESSION_OK;
        case MESH_MGMT_ENVELOPE_INVALID_ARG:
            return MESH_MGMT_SESSION_INVALID_ARG;
        case MESH_MGMT_ENVELOPE_UNSUPPORTED_VERSION:
            return MESH_MGMT_SESSION_UNSUPPORTED_VERSION;
        case MESH_MGMT_ENVELOPE_RESOURCE_EXHAUSTED:
            return MESH_MGMT_SESSION_RESOURCE_EXHAUSTED;
        case MESH_MGMT_ENVELOPE_CRYPTO_FAILURE:
            return MESH_MGMT_SESSION_CRYPTO_FAILURE;
        case MESH_MGMT_ENVELOPE_AUTH_FAILED:
        case MESH_MGMT_ENVELOPE_PAYLOAD_HASH_MISMATCH:
            return MESH_MGMT_SESSION_AUTH_FAILED;
        case MESH_MGMT_ENVELOPE_INVALID_FRAME:
        case MESH_MGMT_ENVELOPE_INVALID_SCHEMA:
        default:
            return MESH_MGMT_SESSION_INVALID_SCHEMA;
    }
}

mesh_mgmt_session_result_t mesh_mgmt_session_accept_hello_v1(
    mesh_mgmt_session_v1_t *session,
    const uint8_t *frame,
    size_t frame_len,
    const uint8_t transport_peer_id[32],
    uint64_t now_ms,
    mesh_mgmt_hello_ack_v1_t *out_ack) {
    mesh_mgmt_verified_envelope_v1_t verified;
    const mesh_mgmt_verified_envelope_v1_t *envelope = &verified;
    mesh_mgmt_envelope_result_t envelope_result;
    mesh_mgmt_hello_v1_t hello;
    mesh_mgmt_certificate_v1_t certificate;
    mesh_mgmt_identity_result_t identity_result;
    mesh_mgmt_session_result_t result;
    uint8_t issuer_hash[32];

    if (!session || !frame || !transport_peer_id || !out_ack)
        return MESH_MGMT_SESSION_INVALID_ARG;
    memset(out_ack, 0, sizeof(*out_ack));
    if (session->state != MESH_MGMT_SESSION_NEGOTIATING ||
        session->remote_hello_verified) return MESH_MGMT_SESSION_INVALID_STATE;
    envelope_result = mesh_mgmt_envelope_verify_v1(frame, frame_len, &verified);
    if (envelope_result != MESH_MGMT_ENVELOPE_OK) {
        result = map_envelope_result(envelope_result);
        session_fail(session);
        return result;
    }
    if (envelope->frame.kind != MESH_MGMT_KIND_HELLO ||
        mesh_mgmt_hello_decode_v1(envelope->frame.payload,
                                  envelope->frame.payload_len,
                                  &hello) != MESH_MGMT_SESSION_OK) {
        session_fail(session);
        return MESH_MGMT_SESSION_INVALID_SCHEMA;
    }
    identity_result = mesh_mgmt_certificate_verify_v1(
        hello.certificate, sizeof(hello.certificate),
        session->config.trusted_issuer_key,
        session->config.expected_mesh_id_hash, now_ms, &certificate);
    if (identity_result != MESH_MGMT_IDENTITY_OK) {
        session_fail(session);
        if (identity_result == MESH_MGMT_IDENTITY_EXPIRED)
            return MESH_MGMT_SESSION_EXPIRED;
        if (identity_result == MESH_MGMT_IDENTITY_CRYPTO_FAILURE)
            return MESH_MGMT_SESSION_CRYPTO_FAILURE;
        return MESH_MGMT_SESSION_AUTH_FAILED;
    }
    if (!envelope_time_is_valid(envelope, now_ms)) {
        session_fail(session);
        return MESH_MGMT_SESSION_EXPIRED;
    }
    if (mesh_mgmt_blake2b_256(session->config.trusted_issuer_key, 32,
                              issuer_hash) != MESH_MGMT_CRYPTO_OK) {
        session_fail(session);
        return MESH_MGMT_SESSION_CRYPTO_FAILURE;
    }
    if (!mesh_mgmt_crypto_equal_32(issuer_hash, hello.issuer_chain_hash) ||
        hello.principal_type != certificate.principal_type ||
        !mesh_mgmt_crypto_equal_32(hello.management_key,
                                   certificate.management_key) ||
        !mesh_mgmt_crypto_equal_32(hello.managed_node_id,
                                   certificate.managed_node_id) ||
        !mesh_mgmt_crypto_equal_32(transport_peer_id,
                                   certificate.transport_peer_id) ||
        !mesh_mgmt_crypto_equal_32(envelope->header.mesh_id_hash,
                                   session->config.expected_mesh_id_hash) ||
        !mesh_mgmt_crypto_equal_32(envelope->header.origin_principal_key,
                                   certificate.management_key) ||
        !mesh_mgmt_crypto_equal_32(envelope->header.origin_node_id,
                                   certificate.managed_node_id) ||
        bytes_are_zero(envelope->header.session_id,
                       sizeof(envelope->header.session_id)) ||
        envelope->header.incarnation == 0u ||
        envelope->header.certificate_serial != certificate.serial ||
        envelope->header.principal_epoch != certificate.principal_epoch) {
        session_fail(session);
        return MESH_MGMT_SESSION_AUTH_FAILED;
    }
    result = negotiate(&session->config, &hello, &session->negotiated);
    if (result != MESH_MGMT_SESSION_OK) {
        session_fail(session);
        return result;
    }
    session->remote_certificate = certificate;
    memcpy(session->remote_certificate_wire, hello.certificate,
           sizeof(session->remote_certificate_wire));
    memcpy(session->remote_connection_id, hello.connection_id, 16);
    memcpy(session->remote_session_id, envelope->header.session_id, 16);
    session->remote_incarnation = envelope->header.incarnation;
    session->remote_hello_verified = 1;
    out_ack->selected_major = session->negotiated.major;
    out_ack->selected_minor = session->negotiated.minor;
    out_ack->features = session->negotiated.features;
    out_ack->max_frame = session->negotiated.max_frame;
    out_ack->max_digest_entries = session->negotiated.max_digest_entries;
    out_ack->max_delta_batch = session->negotiated.max_delta_batch;
    memcpy(out_ack->peer_connection_id, hello.connection_id, 16);
    return MESH_MGMT_SESSION_OK;
}

mesh_mgmt_session_result_t mesh_mgmt_session_mark_ack_sent_v1(
    mesh_mgmt_session_v1_t *session) {
    if (!session) return MESH_MGMT_SESSION_INVALID_ARG;
    if (session->state != MESH_MGMT_SESSION_NEGOTIATING ||
        !session->remote_hello_verified || session->local_ack_sent) {
        return MESH_MGMT_SESSION_INVALID_STATE;
    }
    session->local_ack_sent = 1;
    refresh_session_state(session);
    return MESH_MGMT_SESSION_OK;
}

mesh_mgmt_session_result_t mesh_mgmt_session_accept_hello_ack_v1(
    mesh_mgmt_session_v1_t *session,
    const uint8_t *frame,
    size_t frame_len,
    uint64_t now_ms) {
    mesh_mgmt_verified_envelope_v1_t verified;
    const mesh_mgmt_verified_envelope_v1_t *envelope = &verified;
    mesh_mgmt_envelope_result_t envelope_result;
    mesh_mgmt_session_result_t result;
    mesh_mgmt_hello_ack_v1_t ack;

    if (!session || !frame) return MESH_MGMT_SESSION_INVALID_ARG;
    if (session->state != MESH_MGMT_SESSION_NEGOTIATING ||
        !session->local_hello_sent || !session->remote_hello_verified ||
        session->remote_ack_received) return MESH_MGMT_SESSION_INVALID_STATE;
    envelope_result = mesh_mgmt_envelope_verify_v1(frame, frame_len, &verified);
    if (envelope_result != MESH_MGMT_ENVELOPE_OK) {
        result = map_envelope_result(envelope_result);
        session_fail(session);
        return result;
    }
    if (envelope->frame.kind != MESH_MGMT_KIND_HELLO_ACK ||
        mesh_mgmt_hello_ack_decode_v1(envelope->frame.payload,
                                      envelope->frame.payload_len,
                                      &ack) != MESH_MGMT_SESSION_OK) {
        session_fail(session);
        return MESH_MGMT_SESSION_INVALID_SCHEMA;
    }
    if (!mesh_mgmt_crypto_equal_32(envelope->header.origin_principal_key,
                                   session->remote_certificate.management_key) ||
        !mesh_mgmt_crypto_equal_32(envelope->header.origin_node_id,
                                   session->remote_certificate.managed_node_id) ||
        !mesh_mgmt_crypto_equal_32(envelope->header.mesh_id_hash,
                                   session->config.expected_mesh_id_hash) ||
        envelope->header.certificate_serial !=
            session->remote_certificate.serial ||
        envelope->header.principal_epoch !=
            session->remote_certificate.principal_epoch ||
        envelope->header.incarnation != session->remote_incarnation ||
        !mesh_mgmt_crypto_equal_16(envelope->header.session_id,
                                   session->remote_session_id) ||
        !mesh_mgmt_crypto_equal_16(ack.peer_connection_id,
                                   session->config.connection_id) ||
        ack.selected_major != session->negotiated.major ||
        ack.selected_minor != session->negotiated.minor ||
        ack.features != session->negotiated.features ||
        ack.max_frame != session->negotiated.max_frame ||
        ack.max_digest_entries != session->negotiated.max_digest_entries ||
        ack.max_delta_batch != session->negotiated.max_delta_batch) {
        session_fail(session);
        return MESH_MGMT_SESSION_AUTH_FAILED;
    }
    if (!envelope_time_is_valid(envelope, now_ms)) {
        session_fail(session);
        return MESH_MGMT_SESSION_EXPIRED;
    }
    session->remote_ack_received = 1;
    refresh_session_state(session);
    return MESH_MGMT_SESSION_OK;
}

mesh_mgmt_session_result_t mesh_mgmt_session_authorize_kind_v1(
    const mesh_mgmt_session_v1_t *session,
    uint8_t kind) {
    uint64_t required_feature = 0;

    if (!session) return MESH_MGMT_SESSION_INVALID_ARG;
    if (session->state != MESH_MGMT_SESSION_ESTABLISHED)
        return MESH_MGMT_SESSION_NOT_ESTABLISHED;
    switch (kind) {
        case MESH_MGMT_KIND_PROBE:
        case MESH_MGMT_KIND_PROBE_ACK:
        case MESH_MGMT_KIND_INDIRECT_PROBE:
        case MESH_MGMT_KIND_INDIRECT_ACK:
        case MESH_MGMT_KIND_MEMBERSHIP_DELTA:
            required_feature = MESH_MGMT_FEATURE_MEMBERSHIP;
            break;
        case MESH_MGMT_KIND_DIGEST:
        case MESH_MGMT_KIND_DELTA_REQUEST:
        case MESH_MGMT_KIND_DELTA_BATCH:
            required_feature = MESH_MGMT_FEATURE_ANTI_ENTROPY;
            break;
        case MESH_MGMT_KIND_FORWARD:
        case MESH_MGMT_KIND_COMMAND_REQUEST:
        case MESH_MGMT_KIND_COMMAND_ACCEPTED:
        case MESH_MGMT_KIND_COMMAND_RESULT:
        case MESH_MGMT_KIND_COMMAND_STATUS:
            required_feature = MESH_MGMT_FEATURE_TARGETED_RPC;
            break;
        case MESH_MGMT_KIND_AUDIT_ANCHOR:
            required_feature = MESH_MGMT_FEATURE_AUDIT_ANCHOR;
            break;
        case MESH_MGMT_KIND_STREAM_TICKET_REQUEST:
        case MESH_MGMT_KIND_STREAM_TICKET_ISSUED:
            required_feature = MESH_MGMT_FEATURE_STREAM_TICKET;
            break;
        case MESH_MGMT_KIND_ERROR:
            return MESH_MGMT_SESSION_OK;
        case MESH_MGMT_KIND_HELLO:
        case MESH_MGMT_KIND_HELLO_ACK:
        default:
            return MESH_MGMT_SESSION_INVALID_STATE;
    }
    return mesh_mgmt_session_authorize_feature_v1(session, required_feature);
}

mesh_mgmt_session_result_t mesh_mgmt_session_authorize_feature_v1(
    const mesh_mgmt_session_v1_t *session,
    uint64_t required_features) {
    if (!session) return MESH_MGMT_SESSION_INVALID_ARG;
    if (session->state != MESH_MGMT_SESSION_ESTABLISHED)
        return MESH_MGMT_SESSION_NOT_ESTABLISHED;
    if (required_features == 0u ||
        (required_features & ~MESH_MGMT_FEATURE_KNOWN_MASK) != 0u) {
        return MESH_MGMT_SESSION_INVALID_SCHEMA;
    }
    return (session->negotiated.features & required_features) ==
                   required_features
               ? MESH_MGMT_SESSION_OK
               : MESH_MGMT_SESSION_UNSUPPORTED_FEATURE;
}
