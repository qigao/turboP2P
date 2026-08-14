/**
 * @file turbo_mesh_multi_network.h
 * @brief Isolated logical Networks over one authenticated Mesh underlay.
 *
 * This API is additive. The legacy turbo_mesh.h API continues to represent
 * one implicit default Network. Multi-network V2 is an owner-loop API: create,
 * attach, send, poll, detach and destroy must be serialized by the caller.
 */
#ifndef TURBO_MESH_MULTI_NETWORK_H
#define TURBO_MESH_MULTI_NETWORK_H

#include "turbo_mesh.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_NETWORK_UID_SIZE 16u
#define MESH_NETWORK_IDENTITY_SIZE 32u
#define MESH_NETWORK_SIGNATURE_SIZE 64u
#define MESH_NETWORK_NAME_MAX 63u
#define MESH_NETWORK_FRAME_MAX (64u * 1024u)
#define MESH_NETWORK_DEFAULT_LIMIT 16u
#define MESH_NETWORK_HARD_LIMIT 64u
#define MESH_NETWORK_BINDING_DEFAULT_LIMIT 1024u
#define MESH_NETWORK_BINDING_HARD_LIMIT 4096u
#define MESH_NETWORK_ISSUER_HARD_LIMIT 64u
#define MESH_NETWORK_PEER_HARD_LIMIT 256u
#define MESH_NETWORK_ROUTE_HARD_LIMIT 256u
#define MESH_NETWORK_PACKET_DEFAULT_MAX 65400u
#define MESH_NETWORK_MTU_MIN 576u
#define MESH_NETWORK_MTU_MAX 9000u

typedef struct mesh_fabric_s mesh_fabric_t;

typedef struct {
    uint8_t bytes[MESH_NETWORK_UID_SIZE];
} mesh_network_uid_t;

typedef enum {
    MESH_NETWORK_ACTIVE = 1,
    MESH_NETWORK_DRAINING = 2,
    MESH_NETWORK_TOMBSTONED = 3,
} mesh_network_lifecycle_v2_t;

typedef enum {
    MESH_NETWORK_ATTACH_USERSPACE = 1,
    MESH_NETWORK_ATTACH_OS_SHARED = 2,
    MESH_NETWORK_ATTACH_OS_ISOLATED = 3,
} mesh_network_attach_mode_v2_t;

typedef enum {
    MESH_NETWORK_PACKET_IN = 1,
    MESH_NETWORK_PACKET_OUT = 2,
} mesh_network_packet_direction_v2_t;

/** Roles are signed into each membership ticket. */
typedef enum {
    MESH_NETWORK_ROLE_MEMBER = 1u << 0,
    MESH_NETWORK_ROLE_SUBNET_ROUTER = 1u << 1,
    MESH_NETWORK_ROLE_EXIT = 1u << 2,
    MESH_NETWORK_ROLE_NETWORK_GATEWAY = 1u << 3,
    MESH_NETWORK_ROLE_KNOWN_MASK =
        MESH_NETWORK_ROLE_MEMBER | MESH_NETWORK_ROLE_SUBNET_ROUTER |
        MESH_NETWORK_ROLE_EXIT | MESH_NETWORK_ROLE_NETWORK_GATEWAY,
} mesh_network_role_v2_t;

typedef enum {
    /** A non-default external prefix terminated by a member router. */
    MESH_NETWORK_ROUTE_SUBNET = 1,
    /** The 0.0.0.0/0 route terminated by a member exit. */
    MESH_NETWORK_ROUTE_EXIT = 2,
} mesh_network_route_kind_v2_t;

/**
 * One controller-compiled route. next_hop_node_id identifies the terminal
 * gateway member, not an unauthenticated virtual IP. destination_network is
 * a canonical masked IPv4 value in the same numeric representation used by
 * membership tickets. Lower metric wins after longest-prefix selection.
 */
typedef struct {
    uint32_t destination_network;
    uint8_t prefix_length;
    uint8_t kind; /* mesh_network_route_kind_v2_t */
    uint16_t metric;
    uint8_t next_hop_node_id[MESH_NETWORK_IDENTITY_SIZE];
} mesh_network_route_v2_t;

/** Controller issuer key copied by mesh_fabric_create_v2(). */
typedef struct {
    uint8_t key_id[MESH_NETWORK_IDENTITY_SIZE];
    uint8_t public_key[MESH_NETWORK_IDENTITY_SIZE];
} mesh_network_issuer_v1_t;

/**
 * Canonical membership assertion. The signature is Ed25519 over the fixed
 * canonical body produced by mesh_network_membership_ticket_encode_v1().
 */
typedef struct {
    uint8_t mesh_id[MESH_NETWORK_IDENTITY_SIZE];
    mesh_network_uid_t network_uid;
    uint8_t membership_id[MESH_NETWORK_UID_SIZE];
    uint8_t managed_node_id[MESH_NETWORK_IDENTITY_SIZE];
    uint8_t node_public_key_digest[MESH_NETWORK_IDENTITY_SIZE];
    uint64_t network_generation;
    uint64_t membership_generation;
    uint64_t node_key_epoch;
    uint64_t policy_epoch;
    uint32_t ipv4_address; /* Network byte order as a numeric value. */
    uint8_t ipv4_prefix;
    uint32_t roles;
    uint64_t issued_at_unix_s;
    uint64_t not_before_unix_s;
    uint64_t not_after_unix_s;
    uint8_t issuer_key_id[MESH_NETWORK_IDENTITY_SIZE];
    uint8_t signature[MESH_NETWORK_SIGNATURE_SIZE];
} mesh_network_membership_ticket_v1_t;

typedef int (*mesh_network_packet_authorizer_v2_fn)(
    mesh_network_t *network,
    mesh_network_packet_direction_v2_t direction,
    const uint8_t remote_node_id[MESH_NETWORK_IDENTITY_SIZE],
    const uint8_t *packet,
    size_t packet_len,
    void *user_data);

typedef void (*mesh_network_packet_received_v2_fn)(
    mesh_network_t *network,
    const uint8_t remote_node_id[MESH_NETWORK_IDENTITY_SIZE],
    const uint8_t *packet,
    size_t packet_len,
    void *user_data);

typedef struct {
    size_t struct_size;
    mesh_config_t underlay;
    const mesh_network_issuer_v1_t *trusted_issuers;
    size_t trusted_issuer_count;
    size_t max_networks;
    size_t max_peer_network_bindings;
    size_t max_packet_size;
    /** Reserved for the future platform adapter; V2 currently rejects OS modes. */
    int allow_os_overlap;
} mesh_fabric_config_v2_t;

typedef struct {
    size_t struct_size;
    mesh_network_uid_t network_uid;
    const char *name;
    uint64_t generation;
    uint64_t policy_epoch;
    uint16_t mtu;
    mesh_network_lifecycle_v2_t lifecycle;
    mesh_network_attach_mode_v2_t attach_mode;
    mesh_network_membership_ticket_v1_t local_membership;
    /** Contiguous authorized_peer_count * 32-byte managed node IDs; copied. */
    const uint8_t *authorized_peer_node_ids;
    size_t authorized_peer_count;
    mesh_network_packet_authorizer_v2_fn authorize_packet;
    mesh_network_packet_received_v2_fn on_packet_received;
    void *user_data;
    /** Route data is borrowed for the call and copied into the snapshot. */
    uint64_t route_epoch;
    const mesh_network_route_v2_t *routes;
    size_t route_count;
} mesh_network_spec_v2_t;

typedef struct {
    size_t struct_size;
    mesh_network_uid_t network_uid;
    uint64_t generation;
    uint64_t policy_epoch;
    mesh_network_lifecycle_v2_t lifecycle;
    uint32_t ipv4_address;
    uint8_t ipv4_prefix;
    uint16_t mtu;
    size_t active_bindings;
    uint64_t packets_tx;
    uint64_t packets_rx;
    uint64_t bytes_tx;
    uint64_t bytes_rx;
    uint64_t rejected_frames;
    uint64_t replay_drops;
    uint64_t route_epoch;
    size_t route_count;
    uint64_t routed_packets_tx;
    uint64_t routed_packets_rx;
    uint64_t route_misses;
} mesh_network_status_v2_t;

typedef struct {
    size_t struct_size;
    size_t attached_networks;
    size_t active_bindings;
    size_t max_networks;
    size_t max_bindings;
    uint64_t rejected_frames;
    uint64_t unauthorized_opens;
    uint64_t capacity_rejections;
} mesh_fabric_status_v2_t;

/** Initialize bounded production defaults. */
CXX_C_API void mesh_fabric_config_init_v2(mesh_fabric_config_v2_t *config);

/** Deterministically derive the compatibility Network UID from network_id. */
CXX_C_API int mesh_network_default_uid_v2(
    const char *network_id, mesh_network_uid_t *out_uid);

/** Derive SHA-256(public_key), used by the ticket's identity binding. */
CXX_C_API int mesh_network_public_key_digest_v1(
    const uint8_t public_key[MESH_NETWORK_IDENTITY_SIZE],
    uint8_t out_digest[MESH_NETWORK_IDENTITY_SIZE]);

/** Encode the fixed canonical ticket, including its current signature. */
CXX_C_API int mesh_network_membership_ticket_encode_v1(
    const mesh_network_membership_ticket_v1_t *ticket,
    uint8_t *out, size_t out_capacity, size_t *out_len);
/** Decode an exact canonical ticket into caller-owned fields. */
CXX_C_API int mesh_network_membership_ticket_decode_v1(
    const uint8_t *input, size_t input_len,
    mesh_network_membership_ticket_v1_t *out_ticket);

/** Sign or verify the canonical ticket body using Ed25519. */
CXX_C_API int mesh_network_membership_ticket_sign_v1(
    mesh_network_membership_ticket_v1_t *ticket,
    const uint8_t private_key[MESH_NETWORK_IDENTITY_SIZE]);
CXX_C_API int mesh_network_membership_ticket_verify_v1(
    const mesh_network_membership_ticket_v1_t *ticket,
    const mesh_network_issuer_v1_t *issuer,
    uint64_t now_unix_s);

/**
 * Create one shared authenticated underlay. Config and nested arrays are
 * borrowed only for the call; issuer keys are copied. The returned fabric is
 * caller-owned and starts in CREATED state.
 */
CXX_C_API int mesh_fabric_create_v2(
    const mesh_fabric_config_v2_t *config, mesh_fabric_t **out_fabric);
CXX_C_API int mesh_fabric_start_v2(mesh_fabric_t *fabric);
CXX_C_API int mesh_fabric_poll_v2(mesh_fabric_t *fabric, int timeout_ms);
CXX_C_API void mesh_fabric_stop_v2(mesh_fabric_t *fabric);
CXX_C_API void mesh_fabric_destroy_v2(mesh_fabric_t *fabric);

/**
 * Attach an isolated logical Network and copy its immutable specification.
 * The current V2 slice accepts USERSPACE only; OS modes fail UNSUPPORTED.
 */
CXX_C_API int mesh_fabric_attach_network_v2(
    mesh_fabric_t *fabric, const mesh_network_spec_v2_t *spec,
    mesh_network_t **out_network);

/**
 * Atomically replace one ACTIVE Network snapshot. expected_generation fences
 * concurrent/stale writers; the new generation must be strictly greater.
 * Existing peer bindings are closed and must reopen under the new epochs.
 */
CXX_C_API int mesh_network_apply_snapshot_v2(
    mesh_network_t *network, uint64_t expected_generation,
    const mesh_network_spec_v2_t *spec, uint64_t *out_generation);

/**
 * Drain and detach a Network. On success the handle is destroyed and must not
 * be reused. V2 has no retained packet queue, so a nonzero timeout is an
 * admission requirement and detach completes synchronously after best-effort
 * CLOSE notification.
 */
CXX_C_API int mesh_fabric_detach_network_v2(
    mesh_fabric_t *fabric, const mesh_network_uid_t *network_uid,
    uint64_t drain_timeout_ms);

/**
 * Direct-member or explicitly routed IPv4 data path. A route terminates at one
 * authorized SUBNET_ROUTER/EXIT member after one authenticated underlay hop;
 * generic member-to-member relay remains unsupported. deadline_after_ms must
 * be nonzero. V2 performs bounded synchronous admission and does not retain
 * the caller's packet after this function returns.
 */
CXX_C_API int mesh_network_send_packet_v2(
    mesh_network_t *network, const uint8_t *packet, size_t packet_len,
    uint64_t deadline_after_ms);

CXX_C_API int mesh_network_get_status_v2(
    mesh_network_t *network, mesh_network_status_v2_t *out_status);
/** Return one canonical route snapshot entry by stable sorted index. */
CXX_C_API int mesh_network_get_route_v2(
    mesh_network_t *network, size_t index, mesh_network_route_v2_t *out_route);
/** Resolve the deterministic configured route without requiring a live peer. */
CXX_C_API int mesh_network_lookup_route_v2(
    mesh_network_t *network, uint32_t destination_ipv4,
    mesh_network_route_v2_t *out_route);
CXX_C_API int mesh_fabric_get_status_v2(
    mesh_fabric_t *fabric, mesh_fabric_status_v2_t *out_status);

#ifdef __cplusplus
}
#endif

#endif
