#ifndef P2P_H
#define P2P_H

#include <stddef.h>
#include "platform.h"
#include "p2p_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct coro_context_s coro_context_t;

/* Opaque handles - forward declarations only */
typedef struct p2p_node_s p2p_node_t;
typedef struct p2p_peer_s p2p_peer_t;

/* Error codes - Simple and clear */
typedef enum {
    P2P_OK = 0,
    P2P_ERR_INVALID_ARG = -1,
    P2P_ERR_NO_MEM = -2,
    P2P_ERR_NETWORK = -3,
    P2P_ERR_TIMEOUT = -4,
    P2P_ERR_NOT_FOUND = -5,
    P2P_ERR_IO = -6,
    P2P_ERR_INVALID_STATE = -7,
    P2P_ERR_CRYPTO = -8,
    P2P_ERR_PROTOCOL = -9,
    P2P_ERR_INVALID = -10,
    P2P_ERR_AUTH_REQUIRED = -11,
    P2P_ERR_UNTRUSTED_IDENTITY = -12,
    P2P_ERR_RESOURCE_EXHAUSTED = -13,
    P2P_ERR_KEY_EXHAUSTED = -14,
} p2p_error_t;

enum {
    P2P_SECURE_WIRE_VERSION_V2 = 2,
    P2P_NOISE_SUITE_XX_25519_CHACHAPOLY_BLAKE2S = 1,
    P2P_SECURITY_ID_SIZE = 32,
    P2P_SECURITY_CREDENTIAL_MAX = 1024,
    P2P_SECURITY_HANDSHAKE_FRAME_MAX = 4096,
    P2P_SECURITY_HANDSHAKE_ROLE_COUNT_V3 = 2,
    P2P_SECURITY_HANDSHAKE_STAGE_COUNT_V3 = 4,
    P2P_SECURITY_LATENCY_BUCKET_COUNT_V3 = 12,
};

typedef enum {
    P2P_SECURITY_HANDSHAKE_ROLE_INITIATOR_V3 = 0,
    P2P_SECURITY_HANDSHAKE_ROLE_RESPONDER_V3 = 1,
} p2p_security_handshake_role_v3_t;

typedef enum {
    P2P_SECURITY_HANDSHAKE_STAGE_COOKIE_V3 = 0,
    P2P_SECURITY_HANDSHAKE_STAGE_PREFACE_V3 = 1,
    P2P_SECURITY_HANDSHAKE_STAGE_NOISE_V3 = 2,
    P2P_SECURITY_HANDSHAKE_STAGE_READY_V3 = 3,
} p2p_security_handshake_stage_v3_t;

typedef enum {
    P2P_SECURITY_REJECTION_PENDING_GLOBAL = 0,
    P2P_SECURITY_REJECTION_PENDING_SOURCE = 1,
    P2P_SECURITY_REJECTION_SOURCE_RATE = 2,
    P2P_SECURITY_REJECTION_SOURCE_BUCKET_CAPACITY = 3,
    P2P_SECURITY_REJECTION_SEND_BUDGET = 4,
    P2P_SECURITY_REJECTION_HANDSHAKE_TIMEOUT = 5,
    P2P_SECURITY_REJECTION_HANDSHAKE_PROTOCOL = 6,
    P2P_SECURITY_REJECTION_HANDSHAKE_CRYPTO = 7,
    P2P_SECURITY_REJECTION_HANDSHAKE_IDENTITY = 8,
    P2P_SECURITY_REJECTION_HANDSHAKE_RESOURCE = 9,
    P2P_SECURITY_REJECTION_SESSION_PROTOCOL = 10,
    P2P_SECURITY_REJECTION_SESSION_CRYPTO = 11,
    P2P_SECURITY_REJECTION_SESSION_KEY_LIMIT = 12,
    P2P_SECURITY_REJECTION_SESSION_RESOURCE = 13,
    P2P_SECURITY_REJECTION_REVALIDATION_REJECTED = 14,
    P2P_SECURITY_REJECTION_REVALIDATION_IDENTITY_CHANGE = 15,
    P2P_SECURITY_REJECTION_REVALIDATION_FAIL_CLOSED = 16,
    P2P_SECURITY_REJECTION_COOKIE_GATE_CAPACITY = 17,
    P2P_SECURITY_REJECTION_COOKIE_PROTOCOL = 18,
    P2P_SECURITY_REJECTION_COOKIE_EXPIRED = 19,
    P2P_SECURITY_REJECTION_COOKIE_AUTH = 20,
    P2P_SECURITY_REJECTION_REASON_COUNT = 21,
} p2p_security_rejection_reason_v2_t;

typedef struct {
    uint8_t principal_id[P2P_SECURITY_ID_SIZE];
    uint8_t routing_id[P2P_SECURITY_ID_SIZE];
    uint8_t credential_digest[P2P_SECURITY_ID_SIZE];
    uint64_t trust_epoch;
    uint64_t expires_at_ms;
    uint32_t flags;
} p2p_authenticated_identity_v2_t;

typedef struct {
    /**
     * Build the bounded credential sent in this node's Noise handshake and
     * return its immutable authenticated identity. Called synchronously while
     * security is configured; all pointer arguments are borrowed.
     */
    int (*build_local_credential)(
        void *context,
        const uint8_t local_noise_static[P2P_KEY_SIZE],
        uint8_t *output,
        size_t output_capacity,
        size_t *out_len,
        p2p_authenticated_identity_v2_t *out_identity);
    /**
     * Authenticate a remote credential against the Noise-authenticated static
     * key and channel binding. The provider is authoritative for expiry,
     * revocation, role and trust-epoch policy at now_ms. It must return a fully
     * populated, nonzero identity or an error and must not retain pointers.
     */
    int (*verify_remote_credential)(
        void *context,
        const uint8_t remote_noise_static[P2P_KEY_SIZE],
        const uint8_t channel_binding[P2P_SECURITY_ID_SIZE],
        const uint8_t *credential,
        size_t credential_len,
        uint64_t now_ms,
        p2p_authenticated_identity_v2_t *out_identity);
    void *context;
} p2p_identity_provider_ops_v2_t;

/**
 * Opaque synchronous X25519 static-key provider.
 *
 * The node copies this structure, but context remains borrowed until
 * p2p_destroy() returns. get_public_key is called while configuring the node.
 * calculate_x25519 is called once during configuration with the standard
 * X25519 basepoint to verify that the provider owns the advertised public key,
 * then synchronously on the CoroNet owner thread during each Noise handshake.
 * It therefore must be non-blocking, bounded-time, and must not call back into
 * the node. Both callbacks receive borrowed buffers and
 * must not retain them. calculate_x25519 must either return P2P_OK with exactly
 * 32 bytes of shared-secret output or return P2P_ERR_CRYPTO, P2P_ERR_IO,
 * P2P_ERR_TIMEOUT, or P2P_ERR_RESOURCE_EXHAUSTED; other errors are normalized
 * to P2P_ERR_CRYPTO.
 *
 * This synchronous contract is suitable for in-process and bounded-latency OS
 * key services. A blocking TPM, network HSM, or user-presence provider must not
 * be installed here because it would block the event loop.
 */
typedef struct {
    size_t struct_size;
    int (*get_public_key)(void *context,
                          uint8_t public_key_out[P2P_KEY_SIZE]);
    int (*calculate_x25519)(
        void *context,
        const uint8_t remote_public_key[P2P_KEY_SIZE],
        uint8_t shared_key_out[P2P_KEY_SIZE]);
    void *context;
} p2p_private_key_provider_v3_t;

/**
 * Read-only cancellation view passed to a blocking private-key operation.
 * The structure and callback context are borrowed for the duration of the
 * calculate_x25519 callback and must not be retained.
 */
typedef struct {
    size_t struct_size;
    int (*is_cancelled)(void *context);
    void *context;
} p2p_private_key_cancel_v4_t;

/**
 * Blocking opaque X25519 provider executed outside the CoroNet owner loop.
 *
 * The node copies this structure. context remains borrowed until p2p_destroy()
 * returns. get_public_key runs synchronously during configuration, before the
 * node starts. calculate_x25519 runs only on the node's bounded private-key
 * executor and receives an absolute monotonic deadline. It must return no
 * later than that deadline and should periodically query cancel. The optional
 * request_cancel callback must be thread-safe, idempotent, non-blocking, and
 * may be used to interrupt the provider SDK during peer or node shutdown.
 *
 * Both key callbacks receive borrowed buffers and must not retain them.
 * calculate_x25519 returns P2P_OK with a 32-byte nonzero X25519 result, or one
 * of P2P_ERR_CRYPTO, P2P_ERR_IO, P2P_ERR_TIMEOUT, and
 * P2P_ERR_RESOURCE_EXHAUSTED. Other errors are normalized to P2P_ERR_CRYPTO.
 * Zero executor fields select the documented bounded defaults (one worker,
 * 64 queued-plus-active operations, and a 2000 ms operation timeout).
 */
typedef struct {
    size_t struct_size;
    int (*get_public_key)(void *context,
                          uint8_t public_key_out[P2P_KEY_SIZE]);
    int (*calculate_x25519)(
        void *context,
        const uint8_t remote_public_key[P2P_KEY_SIZE],
        uint64_t monotonic_deadline_ms,
        const p2p_private_key_cancel_v4_t *cancel,
        uint8_t shared_key_out[P2P_KEY_SIZE]);
    void (*request_cancel)(void *context);
    void *context;
    uint16_t executor_workers;
    uint16_t executor_capacity;
    uint32_t operation_timeout_ms;
} p2p_blocking_private_key_provider_v4_t;

typedef struct {
    size_t struct_size;
    uint8_t network_id_hash[P2P_SECURITY_ID_SIZE];
    p2p_identity_provider_ops_v2_t identity_provider;
    uint32_t handshake_timeout_ms;
    uint32_t ready_timeout_ms;
    uint16_t handshake_frame_limit;
    uint16_t credential_limit;
    /** Per-stream CoroNet queued-send hard limit; zero selects 1 MiB. */
    size_t send_hwm_bytes;
    /** Sum of admitted transport HWM reservations; zero selects 64 MiB. */
    size_t node_send_budget_bytes;
    /** New inbound transports per source-prefix burst; zero selects 16. */
    uint16_t source_admission_burst;
    /** Per-prefix tokens restored each second; zero selects 4. */
    uint16_t source_admission_refill_per_second;
    /** Fixed source-bucket table size; zero selects the bounded maximum. */
    uint16_t source_admission_bucket_limit;
    /** Fixed unauthenticated listener-gate slots; zero selects 128. */
    uint16_t cookie_gate_limit;
    /** Cookie time bucket and maximum previous-bucket grace; zero selects 10 s. */
    uint32_t cookie_lifetime_ms;
    /** Derived cookie-key epoch; must be a lifetime multiple; zero selects 5 min. */
    uint32_t cookie_key_rotation_ms;
    /** Monotonic session lifetime; zero selects the 24-hour maximum. */
    uint64_t session_max_age_ms;
    /** Encrypted wire bytes allowed in each direction; zero selects 1 TiB. */
    uint64_t session_max_bytes_per_direction;
} p2p_security_config_v2_t;

typedef struct {
    size_t struct_size;
    uint16_t secure_wire_version;
    uint16_t noise_suite;
    int authenticated;
    uint8_t remote_noise_static[P2P_KEY_SIZE];
    uint8_t channel_binding[P2P_SECURITY_ID_SIZE];
    p2p_authenticated_identity_v2_t identity;
    uint64_t sent_frames;
    uint64_t received_frames;
    uint64_t session_started_ms;
    uint64_t sent_bytes;
    uint64_t received_bytes;
} p2p_peer_security_info_v2_t;

typedef struct {
    size_t struct_size;
    size_t send_budget_bytes;
    size_t reserved_send_capacity_bytes;
    size_t available_send_capacity_bytes;
    size_t transport_reservations;
    uint64_t send_budget_rejections;
    uint16_t source_admission_burst;
    uint16_t source_admission_refill_per_second;
    uint16_t source_admission_bucket_limit;
    size_t active_source_admission_buckets;
    uint16_t cookie_gate_limit;
    size_t active_cookie_gates;
    uint64_t cookie_challenges_issued;
    uint64_t cookie_verifications_succeeded;
    uint64_t rejection_counts[P2P_SECURITY_REJECTION_REASON_COUNT];
} p2p_node_security_status_v2_t;

typedef struct {
    size_t struct_size;
    uint16_t workers;
    uint16_t operation_capacity;
    uint32_t operation_timeout_ms;
    size_t active_operations;
    size_t queued_operations;
    int accepting;
    uint64_t submitted;
    uint64_t completed;
    uint64_t rejected;
    uint64_t timed_out;
    uint64_t cancelled;
    uint64_t completion_post_failures;
} p2p_private_key_executor_status_v4_t;

/**
 * Bounded aggregate for one handshake role and stage. Bucket values are
 * disjoint range counts for the upper bounds published by the enclosing v3
 * snapshot; each completed stage increments exactly one bucket.
 * This value owns no memory and contains no peer identity or key material.
 */
typedef struct {
    uint64_t completed;
    uint64_t total_ms;
    uint64_t maximum_ms;
    uint64_t buckets[P2P_SECURITY_LATENCY_BUCKET_COUNT_V3];
} p2p_security_handshake_latency_v3_t;

/**
 * Atomic read-only node security snapshot.
 *
 * The caller owns the output value. Set struct_size to sizeof(*status) before
 * calling. The getter copies all fields while holding the node state lock and
 * never returns secret key, credential, peer identity, address, or handshake
 * sample data. The v2 status remains available unchanged for ABI compatibility.
 */
typedef struct {
    size_t struct_size;
    uint16_t secure_wire_version;
    uint16_t noise_suite;
    p2p_node_security_status_v2_t security;
    int private_key_executor_available;
    p2p_private_key_executor_status_v4_t private_key_executor;
    uint64_t latency_bucket_upper_bounds_ms
        [P2P_SECURITY_LATENCY_BUCKET_COUNT_V3];
    p2p_security_handshake_latency_v3_t handshake_latency
        [P2P_SECURITY_HANDSHAKE_ROLE_COUNT_V3]
        [P2P_SECURITY_HANDSHAKE_STAGE_COUNT_V3];
} p2p_node_security_status_v3_t;

typedef struct {
    size_t struct_size;
    size_t examined_sessions;
    size_t retained_sessions;
    size_t disconnected_sessions;
    size_t provider_rejections;
    size_t identity_changes;
} p2p_security_revalidation_result_v2_t;

/* =============================================================================
 * Node Lifecycle
 * ============================================================================= */

/**
 * Create a new P2P node
 * @param ip IP to bind (e.g., "0.0.0.0")
 * @param port Port to bind
 * @return Handle or NULL
 */
CXX_C_API p2p_node_t *p2p_create(const char *ip, int port);

/**
 * Destroy node
 */
CXX_C_API void p2p_destroy(p2p_node_t *node);

/**
 * Start the node (blocking event loop)
 */
CXX_C_API int p2p_start(p2p_node_t *node);

/**
 * Start server and gossip (non-blocking)
 * Use this with p2p_get_loop() + coro_context_run() for custom event loop integration
 */
CXX_C_API int p2p_start_nonblocking(p2p_node_t *node);

/**
 * Get the CoroNet context for integration
 */
CXX_C_API coro_context_t *p2p_get_loop(p2p_node_t *node);

/**
 * Copy this node's stable P2P id.
 * @param node Node
 * @param id_out Output buffer of P2P_HASH_SIZE bytes
 * @return P2P_OK on success
 */
CXX_C_API int p2p_node_get_id(p2p_node_t *node, uint8_t id_out[P2P_HASH_SIZE]);

/**
 * Copy this node's static public key.
 * @param node Node
 * @param public_key_out Output buffer of P2P_KEY_SIZE bytes
 * @return P2P_OK on success
 */
CXX_C_API int p2p_node_get_public_key(p2p_node_t *node,
                                      uint8_t public_key_out[P2P_KEY_SIZE]);

/**
 * Set this node's static identity secret.
 * Must be called before the node is started or connected.
 * @param node Node
 * @param secret_key 32-byte private key material
 * @return P2P_OK on success
 */
CXX_C_API int p2p_node_set_private_key(p2p_node_t *node,
                                       const uint8_t secret_key[P2P_KEY_SIZE]);

/**
 * Replace the node's in-memory static private key with an opaque synchronous
 * X25519 provider. Must be called before security configuration, start, or any
 * connection. The provider's public key becomes the node's Noise static key;
 * no private key bytes are retained by the node or copied into Noise-C.
 *
 * The provider structure is copied. Its borrowed context and the resources
 * behind it must remain valid until p2p_destroy() returns. Failure leaves the
 * previous node identity unchanged.
 *
 * @return P2P_OK, P2P_ERR_INVALID_ARG, P2P_ERR_INVALID_STATE, or a normalized
 *         provider error.
 */
CXX_C_API int p2p_node_set_private_key_provider_v3(
    p2p_node_t *node, const p2p_private_key_provider_v3_t *provider);

/**
 * Replace the node's in-memory static private key with a blocking opaque
 * X25519 provider backed by a bounded worker executor. Must be called before
 * security configuration, start, or any connection. The provider's public key
 * becomes the Noise static key; private key bytes are not retained by P2P or
 * copied into Noise-C.
 *
 * Configuration performs a synchronous ownership self-test. Failure leaves
 * the previous identity and executor unchanged. The provider structure is
 * copied; its context must remain valid until p2p_destroy() returns.
 *
 * @return P2P_OK, P2P_ERR_INVALID_ARG, P2P_ERR_INVALID_STATE,
 *         P2P_ERR_NO_MEM, or a normalized provider error.
 */
CXX_C_API int p2p_node_set_blocking_private_key_provider_v4(
    p2p_node_t *node,
    const p2p_blocking_private_key_provider_v4_t *provider);

/**
 * Install the mandatory secure-wire v2 identity policy.
 * The provider context must remain valid until p2p_destroy() returns. Provider
 * callbacks are synchronous, must not retain borrowed pointers, and must not
 * call back into this node. This call copies the configuration and local
 * credential and may invoke build_local_credential before returning.
 * Zero resource-limit and cookie-policy fields select bounded defaults.
 * Nonzero capacities may lower their defaults but may not exceed documented
 * maxima; cookie lifetime/rotation must satisfy their maxima and exact-multiple
 * invariant. The node budget must hold at least one stream HWM. Invalid bounds
 * fail before provider invocation and leave the node unconfigured.
 *
 * @param node Node that has not started or connected.
 * @param config Exact-size v2 configuration with a nonzero network hash and
 *               both provider callbacks.
 * @return P2P_OK, P2P_ERR_INVALID_ARG, P2P_ERR_INVALID_STATE, a provider
 *         error, or P2P_ERR_UNTRUSTED_IDENTITY for an incomplete identity.
 *
 * Example: use p2p_node_configure_pinned_security_v2() for an explicit static
 * key allowlist; use this function for certificate-backed Mesh identities.
 */
CXX_C_API int p2p_node_configure_security_v2(
    p2p_node_t *node, const p2p_security_config_v2_t *config);

/**
 * Configure the built-in explicit static-key allowlist provider.
 * trusted_public_keys points to trusted_key_count contiguous 32-byte keys and
 * is copied by the node. Empty allowlists are rejected.
 *
 * @param node Node that has not started or connected.
 * @param network_id_hash Nonzero 32-byte logical-network identifier.
 * @param trusted_public_keys Contiguous X25519 public keys, including every
 *                            remote key this node may accept.
 * @param trusted_key_count Number of keys, from 1 through 256.
 * @return P2P_OK, P2P_ERR_INVALID_ARG, P2P_ERR_INVALID_STATE,
 *         P2P_ERR_NO_MEM, or a cryptographic/provider error.
 */
CXX_C_API int p2p_node_configure_pinned_security_v2(
    p2p_node_t *node,
    const uint8_t network_id_hash[P2P_SECURITY_ID_SIZE],
    const uint8_t *trusted_public_keys,
    size_t trusted_key_count);

/**
 * Replace the built-in pinned provider's remote allowlist and immediately
 * revalidate established sessions. This must run on the CoroNet owner thread.
 * The node copies up to 256 contiguous keys before changing the trust
 * snapshot. A zero count with a NULL key pointer revokes every remote key.
 * Allocation or validation failure before the swap leaves the old snapshot
 * unchanged; revalidation failure after the swap disconnects all established
 * security sessions.
 */
CXX_C_API int p2p_node_update_pinned_trust_v2(
    p2p_node_t *node,
    const uint8_t *trusted_public_keys,
    size_t trusted_key_count,
    p2p_security_revalidation_result_v2_t *out_revalidation);

/**
 * Copy the node-wide secure transport and listener-cookie capacity snapshot.
 * Each promoted transport reserves its configured per-stream send HWM, so
 * reserved capacity is a conservative upper bound rather than a sample of
 * currently queued bytes. Pre-cookie gates are reported separately and do not
 * reserve the full transport HWM. Set status->struct_size = sizeof(*status)
 * before calling.
 *
 * @return P2P_OK, P2P_ERR_INVALID_ARG, or P2P_ERR_INVALID_STATE before the
 *         security policy has been configured.
 */
CXX_C_API int p2p_node_get_security_status_v2(
    p2p_node_t *node, p2p_node_security_status_v2_t *status);

/**
 * Copy one node-atomic, bounded security status snapshot.
 * This read may run outside the owner thread but must not race p2p_destroy().
 * @return P2P_OK, P2P_ERR_INVALID_ARG, or P2P_ERR_INVALID_STATE when security
 *         has not been configured.
 */
CXX_C_API int p2p_node_get_security_status_v3(
    p2p_node_t *node, p2p_node_security_status_v3_t *status);

/** Return a point-in-time snapshot of the blocking private-key executor. */
CXX_C_API int p2p_node_get_private_key_executor_status_v4(
    p2p_node_t *node, p2p_private_key_executor_status_v4_t *status);

/**
 * Revalidate every established peer against the identity provider's current
 * trust snapshot. This must run on the node's CoroNet owner thread and must not
 * race p2p_destroy(). Provider callbacks run without the node mutex. A rejected
 * credential or an identity result different from the READY-bound identity
 * disconnects that session; identity changes require a fresh Noise handshake.
 * If the bounded session snapshot cannot be allocated, all established
 * security sessions are disconnected before P2P_ERR_NO_MEM is returned. This
 * fail-closed rule prevents a newly installed trust policy from coexisting
 * with sessions that were not revalidated.
 * Set result->struct_size = sizeof(*result) before calling.
 */
CXX_C_API int p2p_node_revalidate_security_v2(
    p2p_node_t *node, p2p_security_revalidation_result_v2_t *result);

/**
 * Generate a new 32-byte private key for stable node identity.
 * @param secret_key_out Output buffer of P2P_KEY_SIZE bytes
 * @return P2P_OK on success
 */
CXX_C_API int p2p_generate_private_key(uint8_t secret_key_out[P2P_KEY_SIZE]);

/**
 * Derive the static public key for a 32-byte private key.
 * @param secret_key Private key material
 * @param public_key_out Output buffer of P2P_KEY_SIZE bytes
 * @return P2P_OK on success
 */
CXX_C_API int p2p_public_key_from_private_key(
    const uint8_t secret_key[P2P_KEY_SIZE],
    uint8_t public_key_out[P2P_KEY_SIZE]);

/**
 * Connect to bootstrap peer
 */
CXX_C_API int p2p_connect(p2p_node_t *node, const char *ip, int port);

/* =============================================================================
 * Message Callbacks
 * ============================================================================= */

/**
 * Message receive callback
 * @param node The node
 * @param peer The peer (NULL for broadcast)
 * @param data Message data
 * @param len Message length
 * @param user_data User data
 */
typedef void (*p2p_on_message_fn)(p2p_node_t *node, p2p_peer_t *peer,
                                  const void *data, size_t len, void *user_data);

/**
 * Set message handler
 */
CXX_C_API void p2p_set_message_handler(p2p_node_t *node, p2p_on_message_fn fn, void *user_data);

/**
 * Set peer connection callbacks
 * @param node The node
 * @param on_connected Callback when peer connects (can be NULL)
 * @param on_disconnected Callback when peer disconnects (can be NULL)
 * @param user_data User data passed to callbacks
 */
CXX_C_API void p2p_set_peer_callbacks(p2p_node_t *node,
                             void (*on_connected)(p2p_peer_t *peer, void *user_data),
                             void (*on_disconnected)(p2p_peer_t *peer, void *user_data),
                             void *user_data);

/**
 * Get peer address information
 * @param peer The peer
 * @param ip_out Buffer to store IP (must be at least 16 bytes)
 * @param port_out Pointer to store port
 * @return P2P_OK on success
 */
CXX_C_API int p2p_peer_get_address(p2p_peer_t *peer, char *ip_out, int *port_out);

/**
 * Copy a peer's advertised P2P id.
 * @param peer Peer
 * @param id_out Output buffer of P2P_HASH_SIZE bytes
 * @return P2P_OK on success, P2P_ERR_NOT_FOUND if the peer has not announced an id yet
 */
CXX_C_API int p2p_peer_get_id(p2p_peer_t *peer, uint8_t id_out[P2P_HASH_SIZE]);

/**
 * Copy a peer's static public key learned during the handshake.
 * @param peer Peer
 * @param public_key_out Output buffer of P2P_KEY_SIZE bytes
 * @return P2P_OK on success, P2P_ERR_NOT_FOUND if the peer used an old handshake
 */
CXX_C_API int p2p_peer_get_public_key(p2p_peer_t *peer,
                                      uint8_t public_key_out[P2P_KEY_SIZE]);

/**
 * Copy the immutable authentication result, monotonic session start and
 * current frame/byte counters for an established v2 peer. Set
 * info->struct_size = sizeof(*info) before calling.
 * The result contains no internal pointers.
 *
 * @param peer Peer received from a connected callback.
 * @param info Caller-owned exact-size output structure.
 * @return P2P_OK, P2P_ERR_INVALID_ARG, or P2P_ERR_NOT_FOUND before READY.
 */
CXX_C_API int p2p_peer_get_security_info_v2(
    p2p_peer_t *peer, p2p_peer_security_info_v2_t *info);

/**
 * Disconnect a peer transport
 */
CXX_C_API void p2p_disconnect_peer(p2p_peer_t *peer);

/**
 * Send message to peer
 */
CXX_C_API int p2p_send(p2p_node_t *node, p2p_peer_t *peer, const void *data, size_t len);

/**
 * Send typed message
 */
CXX_C_API int p2p_send_message(p2p_node_t *node, p2p_peer_t *peer, p2p_msg_type_t type,
                               const void *payload, size_t len);

/**
 * Broadcast to all peers
 */
CXX_C_API int p2p_broadcast(p2p_node_t *node, const void *data, size_t len);

/* =============================================================================
 * File Sharing
 * ============================================================================= */

/**
 * Put file (returns hash key)
 * @param node Node
 * @param filepath File path
 * @param key_out Buffer for hash key (must be 65 bytes for null terminator)
 * @return P2P_OK on success
 */
CXX_C_API int p2p_put_file(p2p_node_t *node, const char *filepath, char key_out[65]);

/**
 * Start downloading a file by hash key and report verified completion.
 * @param node Node
 * @param key 65-byte hash key (64 hex chars + null terminator)
 * @param output_path Where to save
 * @param complete_cb Called after whole-file digest verification; may be NULL
 * @param user_data Opaque value passed to complete_cb
 * @return P2P_OK when the asynchronous request was started
 *
 * @note A P2P_OK return does not mean the file is complete. output_path may
 *       contain partial data until complete_cb reports success.
 * @note complete_cb runs on the node event loop. It must not block.
 */
CXX_C_API int p2p_get_file_async(
    p2p_node_t *node, const char key[65], const char *output_path,
    p2p_transfer_complete_cb complete_cb, void *user_data);

/**
 * Start downloading a file without a completion callback.
 * @param node Node
 * @param key 65-byte hash key (64 hex chars + null terminator)
 * @param output_path Where to save
 * @return P2P_OK when the asynchronous request was started
 *
 * @note Prefer p2p_get_file_async() when the caller needs to consume the file.
 */
CXX_C_API int p2p_get_file(p2p_node_t *node, const char key[65], const char *output_path);

/* =============================================================================
 * Pub/Sub
 * ============================================================================= */

/**
 * Subscribe to topic
 */
CXX_C_API int p2p_subscribe(p2p_node_t *node, const char *topic);

/**
 * Unsubscribe from topic
 */
CXX_C_API int p2p_unsubscribe(p2p_node_t *node, const char *topic);

/**
 * Publish message to topic
 */
CXX_C_API int p2p_publish(p2p_node_t *node, const char *topic, const void *data, size_t len);

/* =============================================================================
 * DHT (Distributed Hash Table)
 * ============================================================================= */

/**
 * Store value in DHT network
 * @param node Node
 * @param key Key (string)
 * @param data Value data
 * @param len Value length
 * @return P2P_OK on success
 */
CXX_C_API int p2p_dht_put(p2p_node_t *node, const char *key, const void *data, size_t len);

/**
 * Store value locally and replicate only to currently connected peers.
 */
CXX_C_API int p2p_dht_put_cached(p2p_node_t *node, const char *key, const void *data, size_t len);

/**
 * Get value from DHT network
 * @param node Node
 * @param key Key (string)
 * @param buf Buffer for value
 * @param buf_len Buffer length (input/output)
 * @return P2P_OK on success
 */
CXX_C_API int p2p_dht_get(p2p_node_t *node, const char *key, void *buf, size_t *buf_len);

/**
 * Get a value already present in the local DHT cache without network waiting.
 */
CXX_C_API int p2p_dht_get_cached(p2p_node_t *node, const char *key, void *buf, size_t *buf_len);

/**
 * Count locally cached DHT entries currently stored on this node.
 */
CXX_C_API size_t p2p_dht_get_entry_count(p2p_node_t *node);

/* =============================================================================
 * Peer Information
 * ============================================================================= */

/**
 * Peer information structure
 */
typedef struct {
    char ip[16];
    int port;
    int is_connected;
} p2p_peer_info_t;

typedef struct {
    char ip[P2P_MAX_IP];
    int port;
    int is_connected;
} p2p_peer_info_ex_t;

/**
 * Read-only measurements for the authenticated ordered stream to a peer.
 * sample_count == 0 means that no valid RTT sample is available.
 * sample_age_ms is UINT32_MAX when no sample exists; is_fresh is true only
 * while the latest sample is within the implementation's bounded freshness
 * window. These values do not describe ICE or other datagram paths.
 */
typedef struct {
    uint32_t srtt_ms;
    uint32_t rttvar_ms;
    uint32_t sample_age_ms;
    uint32_t sample_count;
    int is_fresh;
} p2p_peer_stream_metrics_t;

/**
 * Snapshot peer address and connection state
 * @param peer The peer
 * @param info Output peer info
 * @return P2P_OK on success
 */
CXX_C_API int p2p_peer_get_info(p2p_peer_t *peer, p2p_peer_info_t *info);

/**
 * Snapshot peer address and connection state without IPv4-sized truncation
 * @param peer The peer
 * @param info Output peer info
 * @return P2P_OK on success
 */
CXX_C_API int p2p_peer_get_info_ex(p2p_peer_t *peer, p2p_peer_info_ex_t *info);

/**
 * Snapshot authenticated ordered-stream RTT measurements for a peer.
 * @param peer The peer
 * @param metrics Output metrics
 * @return P2P_OK on success, P2P_ERR_INVALID_ARG for invalid arguments
 */
CXX_C_API int p2p_peer_get_stream_metrics(
    p2p_peer_t *peer,
    p2p_peer_stream_metrics_t *metrics);

/**
 * Get peer count
 */
CXX_C_API int p2p_get_peer_count(p2p_node_t *node);

/**
 * Get peer info by index
 * @param node Node
 * @param index Peer index (0 to count-1)
 * @param info Output peer info
 * @return P2P_OK on success
 */
CXX_C_API int p2p_get_peer_info(p2p_node_t *node, int index, p2p_peer_info_t *info);

/**
 * Get extended peer info by index without IPv4-sized truncation
 * @param node Node
 * @param index Peer index (0 to count-1)
 * @param info Output peer info
 * @return P2P_OK on success
 */
CXX_C_API int p2p_get_peer_info_ex(p2p_node_t *node, int index, p2p_peer_info_ex_t *info);

/* =============================================================================
 * Utility
 * ============================================================================= */

CXX_C_API const char *p2p_error_str(int error);

#ifdef __cplusplus
}
#endif

#endif /* P2P_H */
