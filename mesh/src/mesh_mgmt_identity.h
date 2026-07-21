#ifndef TURBO_P2P_MESH_MGMT_IDENTITY_H
#define TURBO_P2P_MESH_MGMT_IDENTITY_H

#include "mesh_mgmt_crypto.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_MGMT_CERTIFICATE_V1_SIZE 354u
#define MESH_MGMT_CERTIFICATE_V1_BODY_SIZE 286u

typedef enum {
    MESH_MGMT_PRINCIPAL_NODE = 1,
    MESH_MGMT_PRINCIPAL_OPERATOR = 2,
    MESH_MGMT_PRINCIPAL_CI = 3,
    MESH_MGMT_PRINCIPAL_POLICY_AUTHORITY = 4,
} mesh_mgmt_principal_type_t;

typedef enum {
    MESH_MGMT_ROLE_OBSERVER = 1u << 0,
    MESH_MGMT_ROLE_OPERATOR = 1u << 1,
    MESH_MGMT_ROLE_POLICY_ADMIN = 1u << 2,
    MESH_MGMT_ROLE_TRUST_ADMIN = 1u << 3,
} mesh_mgmt_role_t;

#define MESH_MGMT_ROLE_KNOWN_MASK 0x0fu

typedef enum {
    MESH_MGMT_IDENTITY_OK = 0,
    MESH_MGMT_IDENTITY_INVALID_ARG = -1,
    MESH_MGMT_IDENTITY_INVALID_SCHEMA = -2,
    MESH_MGMT_IDENTITY_RESOURCE_EXHAUSTED = -3,
    MESH_MGMT_IDENTITY_AUTH_FAILED = -4,
    MESH_MGMT_IDENTITY_EXPIRED = -5,
    MESH_MGMT_IDENTITY_CRYPTO_FAILURE = -6,
} mesh_mgmt_identity_result_t;

typedef struct {
    uint8_t format_version;
    uint8_t principal_type;
    uint8_t management_key[32];
    uint8_t transport_peer_id[32];
    uint8_t managed_node_id[32];
    uint8_t mesh_id_hash[32];
    uint64_t roles;
    uint8_t target_scope_hash[32];
    uint64_t not_before_ms;
    uint64_t expires_at_ms;
    uint64_t serial;
    uint64_t principal_epoch;
    uint8_t issuer_key[32];
    uint8_t issuer_signature[64];
} mesh_mgmt_certificate_v1_t;

typedef struct {
    uint8_t principal_type;
    uint8_t management_key[32];
    uint8_t transport_peer_id[32];
    uint8_t managed_node_id[32];
    uint8_t mesh_id_hash[32];
    uint64_t roles;
    uint8_t target_scope_hash[32];
    uint64_t not_before_ms;
    uint64_t expires_at_ms;
    uint64_t serial;
    uint64_t principal_epoch;
} mesh_mgmt_certificate_claims_v1_t;

mesh_mgmt_identity_result_t mesh_mgmt_certificate_issue_v1(
    const mesh_mgmt_certificate_claims_v1_t *claims,
    const uint8_t issuer_private_key[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE],
    uint8_t *output,
    size_t output_capacity,
    size_t *out_len);

/** Verify a certificate issued directly by the configured trust anchor. */
mesh_mgmt_identity_result_t mesh_mgmt_certificate_verify_v1(
    const uint8_t *certificate,
    size_t certificate_len,
    const uint8_t trusted_issuer_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE],
    const uint8_t expected_mesh_id_hash[32],
    uint64_t now_ms,
    mesh_mgmt_certificate_v1_t *out_certificate);

#ifdef __cplusplus
}
#endif

#endif
