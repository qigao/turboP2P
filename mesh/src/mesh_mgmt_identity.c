#include "mesh_mgmt_identity.h"

#include "mesh_mgmt_codec.h"
#include "mesh_mgmt_wire.h"

#include <string.h>

static const uint8_t MESH_MGMT_CERTIFICATE_DOMAIN[] =
    "TurboMesh-MMP-Cert-v1";

typedef enum {
    CERT_FIELD_FORMAT_VERSION = 0x0001,
    CERT_FIELD_PRINCIPAL_TYPE = 0x0002,
    CERT_FIELD_MANAGEMENT_KEY = 0x0003,
    CERT_FIELD_TRANSPORT_PEER_ID = 0x0004,
    CERT_FIELD_MANAGED_NODE_ID = 0x0005,
    CERT_FIELD_MESH_ID_HASH = 0x0006,
    CERT_FIELD_ROLES = 0x0007,
    CERT_FIELD_TARGET_SCOPE_HASH = 0x0008,
    CERT_FIELD_NOT_BEFORE_MS = 0x0009,
    CERT_FIELD_EXPIRES_AT_MS = 0x000a,
    CERT_FIELD_SERIAL = 0x000b,
    CERT_FIELD_PRINCIPAL_EPOCH = 0x000c,
    CERT_FIELD_ISSUER_KEY = 0x000d,
    CERT_FIELD_ISSUER_SIGNATURE = 0x000e,
} mesh_mgmt_certificate_field_v1_t;

static int bytes_are_zero(const uint8_t *bytes, size_t length) {
    uint8_t aggregate = 0;
    size_t index = 0;

    for (index = 0; index < length; index++) {
        aggregate |= bytes[index];
    }
    return aggregate == 0u;
}

static int certificate_schema_is_valid(
    const mesh_mgmt_certificate_v1_t *certificate) {
    int is_node = certificate->principal_type == MESH_MGMT_PRINCIPAL_NODE;

    if (certificate->format_version != 1u ||
        certificate->principal_type < MESH_MGMT_PRINCIPAL_NODE ||
        certificate->principal_type > MESH_MGMT_PRINCIPAL_POLICY_AUTHORITY ||
        bytes_are_zero(certificate->management_key, 32) ||
        bytes_are_zero(certificate->mesh_id_hash, 32) ||
        bytes_are_zero(certificate->issuer_key, 32) ||
        certificate->roles == 0u ||
        (certificate->roles & ~((uint64_t)MESH_MGMT_ROLE_KNOWN_MASK)) != 0u ||
        certificate->serial == 0u ||
        certificate->expires_at_ms <= certificate->not_before_ms) {
        return 0;
    }
    if (is_node &&
        (bytes_are_zero(certificate->transport_peer_id, 32) ||
         bytes_are_zero(certificate->managed_node_id, 32) ||
         certificate->principal_epoch == 0u)) {
        return 0;
    }
    if (!is_node &&
        (!bytes_are_zero(certificate->transport_peer_id, 32) ||
         !bytes_are_zero(certificate->managed_node_id, 32))) {
        return 0;
    }
    return 1;
}

static size_t write_u64_tlv(uint8_t *output,
                            uint16_t field_id,
                            uint64_t value) {
    uint8_t bytes[8];

    mesh_mgmt_wire_write_u64(bytes, value);
    return mesh_mgmt_wire_write_tlv(output, field_id, bytes, sizeof(bytes));
}

static size_t certificate_encode(const mesh_mgmt_certificate_v1_t *cert,
                                 uint8_t *output,
                                 int include_signature) {
    size_t offset = 0;

#define WRITE_CERT_FIELD(id, field)                                      \
    offset += mesh_mgmt_wire_write_tlv(output + offset, (id), cert->field, \
                                       sizeof(cert->field))
    offset += mesh_mgmt_wire_write_tlv(
        output + offset, CERT_FIELD_FORMAT_VERSION, &cert->format_version, 1);
    offset += mesh_mgmt_wire_write_tlv(
        output + offset, CERT_FIELD_PRINCIPAL_TYPE, &cert->principal_type, 1);
    WRITE_CERT_FIELD(CERT_FIELD_MANAGEMENT_KEY, management_key);
    WRITE_CERT_FIELD(CERT_FIELD_TRANSPORT_PEER_ID, transport_peer_id);
    WRITE_CERT_FIELD(CERT_FIELD_MANAGED_NODE_ID, managed_node_id);
    WRITE_CERT_FIELD(CERT_FIELD_MESH_ID_HASH, mesh_id_hash);
    offset += write_u64_tlv(output + offset, CERT_FIELD_ROLES, cert->roles);
    WRITE_CERT_FIELD(CERT_FIELD_TARGET_SCOPE_HASH, target_scope_hash);
    offset += write_u64_tlv(output + offset, CERT_FIELD_NOT_BEFORE_MS,
                            cert->not_before_ms);
    offset += write_u64_tlv(output + offset, CERT_FIELD_EXPIRES_AT_MS,
                            cert->expires_at_ms);
    offset += write_u64_tlv(output + offset, CERT_FIELD_SERIAL, cert->serial);
    offset += write_u64_tlv(output + offset, CERT_FIELD_PRINCIPAL_EPOCH,
                            cert->principal_epoch);
    WRITE_CERT_FIELD(CERT_FIELD_ISSUER_KEY, issuer_key);
    if (include_signature) {
        WRITE_CERT_FIELD(CERT_FIELD_ISSUER_SIGNATURE, issuer_signature);
    }
#undef WRITE_CERT_FIELD
    return offset;
}

static int certificate_decode(const uint8_t *bytes,
                              size_t length,
                              mesh_mgmt_certificate_v1_t *out_cert) {
    mesh_mgmt_tlv_reader_t reader;
    mesh_mgmt_tlv_view_t field;

    if (length != MESH_MGMT_CERTIFICATE_V1_SIZE) {
        return 0;
    }
    memset(out_cert, 0, sizeof(*out_cert));
    mesh_mgmt_tlv_reader_init(&reader, bytes, length);
#define READ_CERT_FIELD(id, field_name)                                   \
    do {                                                                   \
        if (!mesh_mgmt_wire_read_field(&reader, (id),                      \
                                       sizeof(out_cert->field_name),       \
                                       &field)) {                          \
            return 0;                                                      \
        }                                                                  \
        memcpy(out_cert->field_name, field.value, field.value_len);        \
    } while (0)
#define READ_CERT_U64(id, field_name)                                     \
    do {                                                                   \
        if (!mesh_mgmt_wire_read_field(&reader, (id), 8, &field)) {        \
            return 0;                                                      \
        }                                                                  \
        out_cert->field_name = mesh_mgmt_wire_read_u64(field.value);       \
    } while (0)
    if (!mesh_mgmt_wire_read_field(&reader, CERT_FIELD_FORMAT_VERSION, 1,
                                   &field)) return 0;
    out_cert->format_version = field.value[0];
    if (!mesh_mgmt_wire_read_field(&reader, CERT_FIELD_PRINCIPAL_TYPE, 1,
                                   &field)) return 0;
    out_cert->principal_type = field.value[0];
    READ_CERT_FIELD(CERT_FIELD_MANAGEMENT_KEY, management_key);
    READ_CERT_FIELD(CERT_FIELD_TRANSPORT_PEER_ID, transport_peer_id);
    READ_CERT_FIELD(CERT_FIELD_MANAGED_NODE_ID, managed_node_id);
    READ_CERT_FIELD(CERT_FIELD_MESH_ID_HASH, mesh_id_hash);
    READ_CERT_U64(CERT_FIELD_ROLES, roles);
    READ_CERT_FIELD(CERT_FIELD_TARGET_SCOPE_HASH, target_scope_hash);
    READ_CERT_U64(CERT_FIELD_NOT_BEFORE_MS, not_before_ms);
    READ_CERT_U64(CERT_FIELD_EXPIRES_AT_MS, expires_at_ms);
    READ_CERT_U64(CERT_FIELD_SERIAL, serial);
    READ_CERT_U64(CERT_FIELD_PRINCIPAL_EPOCH, principal_epoch);
    READ_CERT_FIELD(CERT_FIELD_ISSUER_KEY, issuer_key);
    READ_CERT_FIELD(CERT_FIELD_ISSUER_SIGNATURE, issuer_signature);
#undef READ_CERT_U64
#undef READ_CERT_FIELD
    return mesh_mgmt_tlv_reader_next(&reader, &field) == 0;
}

mesh_mgmt_identity_result_t mesh_mgmt_certificate_issue_v1(
    const mesh_mgmt_certificate_claims_v1_t *claims,
    const uint8_t issuer_private_key[32],
    uint8_t *output,
    size_t output_capacity,
    size_t *out_len) {
    mesh_mgmt_certificate_v1_t certificate;
    uint8_t body[MESH_MGMT_CERTIFICATE_V1_BODY_SIZE];
    uint8_t signing_input[sizeof(MESH_MGMT_CERTIFICATE_DOMAIN) +
                          MESH_MGMT_CERTIFICATE_V1_BODY_SIZE];
    mesh_mgmt_crypto_result_t crypto_result;
    size_t body_len = 0;

    if (!out_len) return MESH_MGMT_IDENTITY_INVALID_ARG;
    *out_len = 0;
    if (!claims || !issuer_private_key) {
        return MESH_MGMT_IDENTITY_INVALID_ARG;
    }
    memset(&certificate, 0, sizeof(certificate));
    certificate.format_version = 1;
    certificate.principal_type = claims->principal_type;
    memcpy(certificate.management_key, claims->management_key, 32);
    memcpy(certificate.transport_peer_id, claims->transport_peer_id, 32);
    memcpy(certificate.managed_node_id, claims->managed_node_id, 32);
    memcpy(certificate.mesh_id_hash, claims->mesh_id_hash, 32);
    certificate.roles = claims->roles;
    memcpy(certificate.target_scope_hash, claims->target_scope_hash, 32);
    certificate.not_before_ms = claims->not_before_ms;
    certificate.expires_at_ms = claims->expires_at_ms;
    certificate.serial = claims->serial;
    certificate.principal_epoch = claims->principal_epoch;
    crypto_result = mesh_mgmt_ed25519_public_from_private(
        issuer_private_key, certificate.issuer_key);
    if (crypto_result != MESH_MGMT_CRYPTO_OK) {
        return MESH_MGMT_IDENTITY_CRYPTO_FAILURE;
    }
    if (!certificate_schema_is_valid(&certificate)) {
        return MESH_MGMT_IDENTITY_INVALID_SCHEMA;
    }
    if (!output || output_capacity < MESH_MGMT_CERTIFICATE_V1_SIZE) {
        *out_len = MESH_MGMT_CERTIFICATE_V1_SIZE;
        return MESH_MGMT_IDENTITY_RESOURCE_EXHAUSTED;
    }
    body_len = certificate_encode(&certificate, body, 0);
    if (body_len != sizeof(body)) return MESH_MGMT_IDENTITY_INVALID_SCHEMA;
    memcpy(signing_input, MESH_MGMT_CERTIFICATE_DOMAIN,
           sizeof(MESH_MGMT_CERTIFICATE_DOMAIN));
    memcpy(signing_input + sizeof(MESH_MGMT_CERTIFICATE_DOMAIN), body,
           body_len);
    crypto_result = mesh_mgmt_ed25519_sign(
        issuer_private_key, signing_input, sizeof(signing_input),
        certificate.issuer_signature);
    if (crypto_result != MESH_MGMT_CRYPTO_OK) {
        return MESH_MGMT_IDENTITY_CRYPTO_FAILURE;
    }
    if (certificate_encode(&certificate, output, 1) !=
        MESH_MGMT_CERTIFICATE_V1_SIZE) {
        memset(output, 0, MESH_MGMT_CERTIFICATE_V1_SIZE);
        return MESH_MGMT_IDENTITY_INVALID_SCHEMA;
    }
    *out_len = MESH_MGMT_CERTIFICATE_V1_SIZE;
    return MESH_MGMT_IDENTITY_OK;
}

mesh_mgmt_identity_result_t mesh_mgmt_certificate_verify_v1(
    const uint8_t *certificate_bytes,
    size_t certificate_len,
    const uint8_t trusted_issuer_key[32],
    const uint8_t expected_mesh_id_hash[32],
    uint64_t now_ms,
    mesh_mgmt_certificate_v1_t *out_certificate) {
    mesh_mgmt_certificate_v1_t certificate;
    uint8_t signing_input[sizeof(MESH_MGMT_CERTIFICATE_DOMAIN) +
                          MESH_MGMT_CERTIFICATE_V1_BODY_SIZE];
    mesh_mgmt_crypto_result_t crypto_result;

    if (!out_certificate) return MESH_MGMT_IDENTITY_INVALID_ARG;
    memset(out_certificate, 0, sizeof(*out_certificate));
    if (!certificate_bytes || !trusted_issuer_key ||
        !expected_mesh_id_hash) {
        return MESH_MGMT_IDENTITY_INVALID_ARG;
    }
    if (!certificate_decode(certificate_bytes, certificate_len,
                            &certificate) ||
        !certificate_schema_is_valid(&certificate)) {
        return MESH_MGMT_IDENTITY_INVALID_SCHEMA;
    }
    if (!mesh_mgmt_crypto_equal_32(certificate.issuer_key,
                                   trusted_issuer_key) ||
        !mesh_mgmt_crypto_equal_32(certificate.mesh_id_hash,
                                   expected_mesh_id_hash)) {
        return MESH_MGMT_IDENTITY_AUTH_FAILED;
    }
    memcpy(signing_input, MESH_MGMT_CERTIFICATE_DOMAIN,
           sizeof(MESH_MGMT_CERTIFICATE_DOMAIN));
    memcpy(signing_input + sizeof(MESH_MGMT_CERTIFICATE_DOMAIN),
           certificate_bytes, MESH_MGMT_CERTIFICATE_V1_BODY_SIZE);
    crypto_result = mesh_mgmt_ed25519_verify(
        certificate.issuer_key, signing_input, sizeof(signing_input),
        certificate.issuer_signature);
    if (crypto_result == MESH_MGMT_CRYPTO_AUTH_FAILED) {
        return MESH_MGMT_IDENTITY_AUTH_FAILED;
    }
    if (crypto_result != MESH_MGMT_CRYPTO_OK) {
        return MESH_MGMT_IDENTITY_CRYPTO_FAILURE;
    }
    if (now_ms < certificate.not_before_ms ||
        now_ms >= certificate.expires_at_ms) {
        return MESH_MGMT_IDENTITY_EXPIRED;
    }
    *out_certificate = certificate;
    return MESH_MGMT_IDENTITY_OK;
}
