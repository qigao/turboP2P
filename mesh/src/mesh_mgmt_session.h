#ifndef TURBO_P2P_MESH_MGMT_SESSION_H
#define TURBO_P2P_MESH_MGMT_SESSION_H

#include "mesh_mgmt_envelope.h"
#include "mesh_mgmt_identity.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_MGMT_BUILD_VERSION_MAX 32u
#define MESH_MGMT_CHANNEL_BINDING_SIZE 32u
#define MESH_MGMT_HELLO_V1_MAX_SIZE 615u
#define MESH_MGMT_HELLO_ACK_V1_SIZE 98u
#define MESH_MGMT_SESSION_MIN_FRAME 1024u
#define MESH_MGMT_DIGEST_ENTRIES_MAX 1024u
#define MESH_MGMT_DELTA_BATCH_MAX 256u

typedef enum {
    MESH_MGMT_FEATURE_MEMBERSHIP = 1u << 0,
    MESH_MGMT_FEATURE_ANTI_ENTROPY = 1u << 1,
    MESH_MGMT_FEATURE_TARGETED_RPC = 1u << 2,
    MESH_MGMT_FEATURE_AUDIT_ANCHOR = 1u << 3,
    MESH_MGMT_FEATURE_STREAM_TICKET = 1u << 4,
    MESH_MGMT_FEATURE_NODE_EXECUTION = 1u << 5,
} mesh_mgmt_feature_t;

#define MESH_MGMT_FEATURE_KNOWN_MASK 0x3fu

typedef enum {
    MESH_MGMT_PLATFORM_LINUX = 1,
    MESH_MGMT_PLATFORM_WINDOWS = 2,
    MESH_MGMT_PLATFORM_MACOS = 3,
    MESH_MGMT_PLATFORM_OTHER = 4,
} mesh_mgmt_platform_t;

typedef enum {
    MESH_MGMT_SESSION_NEGOTIATING = 0,
    MESH_MGMT_SESSION_ESTABLISHED = 1,
    MESH_MGMT_SESSION_FAILED = 2,
} mesh_mgmt_session_state_t;

typedef enum {
    MESH_MGMT_SESSION_OK = 0,
    MESH_MGMT_SESSION_INVALID_ARG = -1,
    MESH_MGMT_SESSION_INVALID_STATE = -2,
    MESH_MGMT_SESSION_INVALID_SCHEMA = -3,
    MESH_MGMT_SESSION_UNSUPPORTED_VERSION = -4,
    MESH_MGMT_SESSION_AUTH_FAILED = -5,
    MESH_MGMT_SESSION_EXPIRED = -6,
    MESH_MGMT_SESSION_NOT_ESTABLISHED = -7,
    MESH_MGMT_SESSION_UNSUPPORTED_FEATURE = -8,
    MESH_MGMT_SESSION_RESOURCE_EXHAUSTED = -9,
    MESH_MGMT_SESSION_CRYPTO_FAILURE = -10,
} mesh_mgmt_session_result_t;

typedef struct {
    uint8_t major;
    uint8_t min_minor;
    uint8_t max_minor;
    uint64_t features;
    uint8_t platform;
    uint8_t build_version[MESH_MGMT_BUILD_VERSION_MAX];
    size_t build_version_len;
    uint8_t certificate[MESH_MGMT_CERTIFICATE_V1_SIZE];
    uint8_t issuer_chain_hash[32];
    uint8_t principal_type;
    uint8_t management_key[32];
    uint8_t managed_node_id[32];
    uint8_t connection_id[16];
    uint8_t channel_binding[MESH_MGMT_CHANNEL_BINDING_SIZE];
    uint32_t max_frame;
    uint16_t max_digest_entries;
    uint16_t max_delta_batch;
} mesh_mgmt_hello_v1_t;

typedef struct {
    uint8_t selected_major;
    uint8_t selected_minor;
    uint64_t features;
    uint32_t max_frame;
    uint16_t max_digest_entries;
    uint16_t max_delta_batch;
    uint8_t peer_connection_id[16];
    uint8_t channel_binding[MESH_MGMT_CHANNEL_BINDING_SIZE];
} mesh_mgmt_hello_ack_v1_t;

typedef struct {
    uint8_t expected_mesh_id_hash[32];
    uint8_t trusted_issuer_key[32];
    uint8_t min_minor;
    uint8_t max_minor;
    uint64_t features;
    uint8_t connection_id[16];
    uint8_t channel_binding[MESH_MGMT_CHANNEL_BINDING_SIZE];
    uint32_t max_frame;
    uint16_t max_digest_entries;
    uint16_t max_delta_batch;
} mesh_mgmt_session_config_v1_t;

typedef struct {
    uint8_t major;
    uint8_t minor;
    uint64_t features;
    uint32_t max_frame;
    uint16_t max_digest_entries;
    uint16_t max_delta_batch;
} mesh_mgmt_negotiated_v1_t;

typedef struct {
    mesh_mgmt_session_state_t state;
    mesh_mgmt_session_config_v1_t config;
    mesh_mgmt_negotiated_v1_t negotiated;
    mesh_mgmt_certificate_v1_t remote_certificate;
    uint8_t remote_certificate_wire[MESH_MGMT_CERTIFICATE_V1_SIZE];
    uint8_t remote_connection_id[16];
    uint8_t remote_session_id[16];
    uint64_t remote_incarnation;
    uint8_t local_hello_sent;
    uint8_t remote_hello_verified;
    uint8_t local_ack_sent;
    uint8_t remote_ack_received;
} mesh_mgmt_session_v1_t;

mesh_mgmt_session_result_t mesh_mgmt_hello_encode_v1(
    const mesh_mgmt_hello_v1_t *hello,
    uint8_t *output,
    size_t output_capacity,
    size_t *out_len);

mesh_mgmt_session_result_t mesh_mgmt_hello_decode_v1(
    const uint8_t *payload,
    size_t payload_len,
    mesh_mgmt_hello_v1_t *out_hello);

mesh_mgmt_session_result_t mesh_mgmt_hello_ack_encode_v1(
    const mesh_mgmt_hello_ack_v1_t *ack,
    uint8_t *output,
    size_t output_capacity,
    size_t *out_len);

mesh_mgmt_session_result_t mesh_mgmt_hello_ack_decode_v1(
    const uint8_t *payload,
    size_t payload_len,
    mesh_mgmt_hello_ack_v1_t *out_ack);

mesh_mgmt_session_result_t mesh_mgmt_session_init_v1(
    mesh_mgmt_session_v1_t *session,
    const mesh_mgmt_session_config_v1_t *config);

mesh_mgmt_session_result_t mesh_mgmt_session_mark_hello_sent_v1(
    mesh_mgmt_session_v1_t *session);

mesh_mgmt_session_result_t mesh_mgmt_session_accept_hello_v1(
    mesh_mgmt_session_v1_t *session,
    const uint8_t *frame,
    size_t frame_len,
    const uint8_t transport_peer_id[32],
    uint64_t now_ms,
    mesh_mgmt_hello_ack_v1_t *out_ack);

mesh_mgmt_session_result_t mesh_mgmt_session_mark_ack_sent_v1(
    mesh_mgmt_session_v1_t *session);

mesh_mgmt_session_result_t mesh_mgmt_session_accept_hello_ack_v1(
    mesh_mgmt_session_v1_t *session,
    const uint8_t *frame,
    size_t frame_len,
    uint64_t now_ms);

mesh_mgmt_session_result_t mesh_mgmt_session_authorize_kind_v1(
    const mesh_mgmt_session_v1_t *session,
    uint8_t kind);

mesh_mgmt_session_result_t mesh_mgmt_session_authorize_feature_v1(
    const mesh_mgmt_session_v1_t *session,
    uint64_t required_features);

#ifdef __cplusplus
}
#endif

#endif
