#ifndef TURBO_P2P_MESH_MGMT_AGENT_RUNTIME_H
#define TURBO_P2P_MESH_MGMT_AGENT_RUNTIME_H

#include "mesh_mgmt_agent_router.h"
#include "mesh_mgmt_endpoint_publisher.h"
#include "mesh_mgmt_p2p_security.h"
#include "mesh_mgmt_service_publisher.h"
#include <salts/native_io_sharded.h>

struct p2p_node_cnet_s;

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  MESH_MGMT_AGENT_RUNTIME_OK = 0,
  MESH_MGMT_AGENT_RUNTIME_INVALID_ARG = -1,
  MESH_MGMT_AGENT_RUNTIME_INVALID_STATE = -2,
  MESH_MGMT_AGENT_RUNTIME_RESOURCE_EXHAUSTED = -3,
  MESH_MGMT_AGENT_RUNTIME_P2P_FAILED = -4,
  MESH_MGMT_AGENT_RUNTIME_ROUTER_FAILED = -5,
  MESH_MGMT_AGENT_RUNTIME_ENDPOINT_FAILED = -6,
  MESH_MGMT_AGENT_RUNTIME_ENDPOINT_RECORD_FAILED = -7,
  MESH_MGMT_AGENT_RUNTIME_DISCOVERY_FAILED = -8,
  MESH_MGMT_AGENT_RUNTIME_PUBLISH_FAILED = -9,
  MESH_MGMT_AGENT_RUNTIME_SERVICE_RECORD_FAILED = -10,
  MESH_MGMT_AGENT_RUNTIME_SEND_FAILED = -11,
  MESH_MGMT_AGENT_RUNTIME_POOL_FAILED = -12,
} mesh_mgmt_agent_runtime_result_t;

typedef enum {
  MESH_MGMT_AGENT_RUNTIME_UNINITIALIZED = 0,
  MESH_MGMT_AGENT_RUNTIME_READY = 1,
  MESH_MGMT_AGENT_RUNTIME_RUNNING = 2,
  MESH_MGMT_AGENT_RUNTIME_STOPPED = 3,
  MESH_MGMT_AGENT_RUNTIME_STOPPING = 4,
} mesh_mgmt_agent_runtime_state_t;

typedef struct {
  uint8_t transport_peer_id[P2P_KEY_SIZE];
  const char *host;
  uint16_t port;
} mesh_mgmt_agent_bootstrap_v1_t;

typedef struct {
  const uint8_t *mesh_id_hash;
  const uint8_t *owner_node_id;
  const uint8_t *certificate;
  size_t certificate_len;
  const uint8_t *trusted_issuer_key;
  uint64_t now_ms;
  uint64_t max_ttl_ms;
} mesh_mgmt_agent_cached_endpoint_v1_t;

typedef struct {
  const uint8_t *mesh_id_hash;
  const uint8_t *owner_node_id;
  const uint8_t *certificate;
  size_t certificate_len;
  const uint8_t *trusted_issuer_key;
  uint64_t now_ms;
  uint64_t max_ttl_ms;
} mesh_mgmt_agent_cached_service_v1_t;

/**
 * Called only after a signed MMP session identifies a peer that is absent from
 * the endpoint pool. Return zero to admit it under an external membership
 * policy; any other value rejects and disconnects it. A NULL callback is
 * fail-closed.
 */
typedef int (*mesh_mgmt_agent_admit_peer_fn)(void *context, p2p_peer_t *peer,
                                             const uint8_t remote_transport_peer_id[P2P_KEY_SIZE],
                                             const mesh_mgmt_dispatch_event_v1_t *event);

typedef struct {
  struct mesh_network_s *shared_mesh;
  const char *listen_host;
  uint16_t listen_port;
  const uint8_t *p2p_private_key;
  size_t max_peers;
  const mesh_mgmt_peer_signer_config_v1_t *signer_template;
  const mesh_mgmt_dispatch_config_v1_t *dispatch_template;
  /* Dedicated-mode secure-wire trust policy, copied during init. Shared mode
   * inherits the mesh node policy and requires these fields to remain zero. */
  uint64_t p2p_minimum_principal_epoch;
  uint64_t p2p_required_remote_roles;
  const uint64_t *p2p_revoked_certificate_serials;
  size_t p2p_revoked_certificate_serial_count;
  size_t endpoint_capacity;
  uint64_t retry_base_ms;
  uint64_t retry_max_ms;
  uint64_t connect_timeout_ms;
  uint32_t protocol_failure_limit;
  uint64_t first_endpoint_record_epoch;
  uint64_t first_service_record_epoch;
  mesh_mgmt_record_epoch_allocate_fn allocate_record_epoch;
  void *record_epoch_context;
  const mesh_mgmt_agent_bootstrap_v1_t *bootstraps;
  size_t bootstrap_count;
  mesh_mgmt_agent_router_random_fn random_bytes;
  void *random_context;
  mesh_mgmt_agent_admit_peer_fn admit_peer;
  mesh_mgmt_agent_router_event_fn on_event;
  mesh_mgmt_agent_router_non_mmp_fn on_non_mmp;
  mesh_mgmt_agent_router_failure_fn on_failure;
  mesh_mgmt_agent_router_peer_closed_fn on_peer_closed;
  void *callback_context;
} mesh_mgmt_agent_runtime_config_v1_t;

/* Runtime-owned signed MMP ClientPool association for exactly one physical
 * Manager generation. Lease storage lives upstream in CNet Pool; this
 * record is a bounded local lifecycle index, not a second credit ledger. */
/* Application-visible result is a local full encrypted CNet write terminal,
 * NOT remote execution acceptance. No callback for rejected admission. */
typedef void (*mesh_mgmt_agent_command_terminal_fn_v4)(
    void *context, uint64_t ticket, int p2p_terminal_status);
typedef struct mesh_mgmt_command_terminal_slot_v4_s mesh_mgmt_command_terminal_slot_v4_t;

typedef struct {
  p2p_peer_t *peer; /* borrowed only until router close callback */
  cnet_pool_connection physical;
  cnet_managed_connection managed;
  cnet_pool_key key;
  uint8_t connection_id[16]; /* original signed Router generation */
  uint8_t active;
  uint8_t draining;
} mesh_mgmt_runtime_pool_record_v3_t;

/**
 * Single-event-loop composition root. In dedicated mode it owns the node and
 * listener and derives the mandatory secure-wire v2 provider from the local
 * signer certificate plus dispatch trust anchor. In shared_mesh mode it
 * borrows the already secured mesh node and attaches its router through the
 * mesh callback bridge. signer_template and
 * dispatch_template are immutable borrows and must outlive the runtime. No
 * method is thread-safe.
 */
typedef struct {
  p2p_node_t *node;
  struct mesh_network_s *shared_mesh;
  mesh_mgmt_agent_router_v1_t router;
  mesh_mgmt_endpoint_pool_v1_t endpoint_pool;
  mesh_mgmt_endpoint_publisher_v1_t endpoint_publisher;
  mesh_mgmt_service_publisher_v1_t service_publisher;
  mesh_mgmt_p2p_security_provider_v2_t p2p_security_provider;
  mesh_mgmt_agent_admit_peer_fn admit_peer;
  mesh_mgmt_agent_router_event_fn on_event;
  mesh_mgmt_agent_router_non_mmp_fn on_non_mmp;
  mesh_mgmt_agent_router_failure_fn on_failure;
  mesh_mgmt_agent_router_peer_closed_fn on_peer_closed;
  void *callback_context;
  mesh_mgmt_agent_runtime_state_t state;
  mesh_mgmt_agent_runtime_result_t last_error;
  mesh_mgmt_agent_router_result_t last_router_result;
  mesh_mgmt_endpoint_pool_result_t last_endpoint_result;
  mesh_mgmt_endpoint_record_result_t last_endpoint_record_result;
  mesh_mgmt_service_record_result_t last_service_record_result;
  mesh_mgmt_endpoint_publisher_result_t last_publisher_result;
  mesh_mgmt_service_publisher_result_t last_service_publisher_result;
  int last_p2p_result;
  uint8_t in_api;
  uint8_t owns_node;
  p2p_runtime_config_v2_t p2p_config;
  const struct mesh_mgmt_agent_mesh_ops_s *mesh_ops;
  /* Opt-in, dedicated-CNet-only post-auth MMP Pool: one upstream Pool
   * borrowing the exact inbound P2P CNet Manager. EndpointPool alone owns
   * dial selection, backoff and quarantine. No ManagedDial timer/replay. */
  cnet_client_pool signed_pool;
  cnet_manager *signed_pool_manager; /* borrowed until Pool fully destroyed */
  mesh_mgmt_runtime_pool_record_v3_t *signed_pool_records;
  size_t signed_pool_capacity;
  size_t signed_pool_max_leases;
  uint64_t signed_pool_owner_id;
  int signed_pool_status;
  uint8_t signed_pool_enabled;
  /* Command tickets and leases are owned by the original SG Final Owner
   * until full wire-write or real transport terminal. Bounded at enable. */
  mesh_mgmt_command_terminal_slot_v4_t *command_terminal_slots;
  size_t command_terminal_capacity;
  size_t command_terminal_inflight;
  uint64_t next_command_ticket;
  uint64_t last_command_ticket;
  int last_command_terminal_status;
  /* Borrowed real SG final Node. The SG Host, not Runtime, owns its backend,
   * connection progress and shutdown; lifecycle methods run ONLY on the
   * original shard worker under a live Host lease. */
  struct p2p_node_cnet_s *sg_final_owner;
  const void *sg_owner_thread;
  uint8_t sg_final_mode;
} mesh_mgmt_agent_runtime_v1_t;

/** Compatibility entry point: dedicated mode uses CNet v2 defaults and
 * requires a nonzero port; shared mode uses the real mesh callback bridge. */
mesh_mgmt_agent_runtime_result_t
mesh_mgmt_agent_runtime_init_v1(mesh_mgmt_agent_runtime_v1_t *runtime,
                                const mesh_mgmt_agent_runtime_config_v1_t *config);

/**
 * Dedicated CNet composition without a mesh link dependency. shared_mesh must
 * be NULL. Port zero requests an ephemeral listener, queryable through
 * p2p_node_get_listen_address_v2() after start. Initialize p2p_config with
 * p2p_runtime_config_v2_init(); its contents are copied, and network limits are
 * checked by start. Templates and callback contexts remain borrowed until
 * destroy_v2 succeeds, including failed init/start cleanup in STOPPING state.
 */
mesh_mgmt_agent_runtime_result_t mesh_mgmt_agent_runtime_init_v2(
    mesh_mgmt_agent_runtime_v1_t *runtime,
    const mesh_mgmt_agent_runtime_config_v1_t *config,
    const p2p_runtime_config_v2_t *p2p_config);

/* Opt-in SG Final Owner composition. Called on the selected NativeIO SG
 * worker AFTER P2P node security configuration, external CNet creation and
 * credited SG final-owner binding. Borrows the exact original P2P Node,
 * external CNet Owner and live Host lease; installs only MMP Router callbacks.
 * The caller must leave the Node/Owner/Host alive until checked Runtime
 * Stop/Destroy succeeds. No additional backend, observer or retry clock.
 * Config must not request a listener, P2P key/trust setup or bootstraps:
 * the borrowed P2P final Node already owns security and inbound handoff. */
mesh_mgmt_agent_runtime_result_t mesh_mgmt_agent_runtime_init_sg_final_v3(
    mesh_mgmt_agent_runtime_v1_t *runtime,
    const mesh_mgmt_agent_runtime_config_v1_t *config,
    p2p_node_t *borrowed_node,
    struct p2p_node_cnet_s *borrowed_final_owner,
    native_io_sharded_context *context,
    native_io_sharded_host_lease lease);

/**
 * Dedicated mode installs callbacks and binds its listener. Shared mode
 * attaches to mesh before mesh_start(); the caller starts the mesh afterward.
 * Failure after callback installation is terminal: STOPPED on successful
 * cleanup, STOPPING otherwise. Destroy before initializing again.
 */
mesh_mgmt_agent_runtime_result_t
mesh_mgmt_agent_runtime_start_v1(mesh_mgmt_agent_runtime_v1_t *runtime);

/* Explicitly enable automatic authenticated ClientPool lifecycle for the
 * dedicated CNet runtime while it is READY (before start), using positive
 * bounded max_connections/max_leases and a stable host-assigned Owner ID.
 * Shared-mesh mode and post-start activation are rejected. Allocates only
 * the bounded record index; physical upstream Pool is lazily initialized
 * on the first live inbound signed MMP SESSION_ESTABLISHED.
 *
 * Only inbound P2P streams managed by the SAME CNet Owner's physical
 * Manager become READY. The legitimate unmanaged outbound client does not
 * inherit inbound ClientPool eligibility. The existing endpoint pool
 * remains the sole reconnect/backoff/quarantine authority. */
mesh_mgmt_agent_runtime_result_t mesh_mgmt_agent_runtime_enable_signed_pool_v3(
    mesh_mgmt_agent_runtime_v1_t *runtime,
    uint64_t owner_id, size_t max_connections, size_t max_leases);

/* Obtain one real exclusive CNet Pool lease only for this exact still-live
 * signed MMP peer, after rechecking Router generation and Manager physical
 * connection on the current Owner. Never retries/replays application data.
 * Output is zeroed on error. A successful lease is caller-owned and MUST
 * be returned exactly once even if the peer closes or Runtime enters
 * STOPPING; outstanding leases prevent Pool/Owner destruction. */
mesh_mgmt_agent_runtime_result_t mesh_mgmt_agent_runtime_signed_pool_acquire_v3(
    mesh_mgmt_agent_runtime_v1_t *runtime, p2p_peer_t *peer,
    cnet_pool_lease *out_lease);
mesh_mgmt_agent_runtime_result_t mesh_mgmt_agent_runtime_signed_pool_release_v3(
    mesh_mgmt_agent_runtime_v1_t *runtime, cnet_pool_lease lease);

/* The status is authoritative upstream CNet Pool data, not a second
 * logical connection counter. The Pool can be absent before the first
 * authenticated inbound session. Does not run IO or apply retry policy. */
mesh_mgmt_agent_runtime_result_t mesh_mgmt_agent_runtime_signed_pool_snapshot_v3(
    mesh_mgmt_agent_runtime_v1_t *runtime, cnet_pool_snapshot *out_snapshot);

/* Call only on the FINAL SG Owner worker AFTER the one authoritative
 * p2p_node_cnet_poll_sg_host() observed and routed physical callbacks.
 * In RUNNING/STOPPING, progresses ONLY the upstream Pool terminal association;
 * it never polls NativeIO or the P2P Node. Wrong shard/lease fails closed.
 * When Stop reports INVALID_STATE on outstanding physical records, continue
 * the original SG Host progress and this call before retrying checked Stop. */
mesh_mgmt_agent_runtime_result_t mesh_mgmt_agent_runtime_sg_final_advance_v3(
    mesh_mgmt_agent_runtime_v1_t *runtime,
    native_io_sharded_context *context,
    native_io_sharded_host_lease lease);

/* Send one signed canonical execution request/result/status using the
 * unique authenticated INBOUND MMP Router target. Reserve one upstream CNet
 * ClientPool Lease before encryption, and return it only on the definitive
 * local CNet full-write/terminal callback (including after logical peer
 * detach and while Runtime is STOPPING). A successful return is merely wire
 * admission, never remote application ACK. No retries or application replay.
 * The callback context is borrowed through completion; STOPPING retains
 * Runtime/Pool/Manager/SG Host for outstanding tickets. Outbound/unmanaged
 * peers and wrong SG owner workers fail closed. out_ticket is zero on failure.
 * Callers may pass NULL for callback/out_ticket if they do not need a result. */
mesh_mgmt_agent_runtime_result_t
mesh_mgmt_agent_runtime_send_execution_leased_v4(
    mesh_mgmt_agent_runtime_v1_t *runtime, uint8_t kind,
    const uint8_t target_node_id[32],
    const uint8_t *payload, size_t payload_len,
    mesh_mgmt_agent_command_terminal_fn_v4 complete,
    void *context, uint64_t *out_ticket);

/** Configure an immutable CNet Client destination strategy after init and
 * before start. Supported only by dedicated CNet runtime; no hot reconfiguration
 * or legacy fallback once enabled. All candidates are static or authenticated
 * signed endpoint records, and authentication still governs protocol READY. */
mesh_mgmt_agent_runtime_result_t mesh_mgmt_agent_runtime_set_client_policy_v2(
    mesh_mgmt_agent_runtime_v1_t *runtime,
    const mesh_mgmt_client_destination_policy_v2_t *policy);

/**
 * Dedicated mode advances endpoint dialing and p2p_poll(). A polling failure
 * returns P2P_FAILED and preserves the P2P code in last_p2p_result. Shared mode
 * is a no-op because mesh_poll() owns connection policy and the event loop.
 */
mesh_mgmt_agent_runtime_result_t
mesh_mgmt_agent_runtime_poll_v1(mesh_mgmt_agent_runtime_v1_t *runtime);

/**
 * Atomically install a dedicated runtime's remote trust snapshot and
 * revalidate all established Noise sessions before processing more traffic.
 * This command must run on the runtime's network owner thread. READY and
 * RUNNING states are accepted; shared_mesh mode is rejected because the
 * borrowed Mesh node owns its security policy. If revalidation cannot
 * complete, P2P disconnects every established security session before this
 * function returns MESH_MGMT_AGENT_RUNTIME_P2P_FAILED.
 */
mesh_mgmt_agent_runtime_result_t
mesh_mgmt_agent_runtime_update_remote_trust_v2(
    mesh_mgmt_agent_runtime_v1_t *runtime,
    const mesh_mgmt_p2p_remote_trust_v2_t *trust,
    p2p_security_revalidation_result_v2_t *out_revalidation);

/** Verify one untrusted signed endpoint frame before updating dial state. */
mesh_mgmt_agent_runtime_result_t mesh_mgmt_agent_runtime_apply_endpoint_frame_v1(
    mesh_mgmt_agent_runtime_v1_t *runtime,
    const mesh_mgmt_endpoint_record_verify_input_v1_t *input);

/**
 * Read one exact signed frame from the local P2P DHT cache, verify it against
 * the caller-owned certificate/trust anchor, then update endpoint dial state.
 * This function never starts or waits for a network DHT lookup.
 */
mesh_mgmt_agent_runtime_result_t
mesh_mgmt_agent_runtime_apply_cached_endpoint_v1(mesh_mgmt_agent_runtime_v1_t *runtime,
                                                 const mesh_mgmt_agent_cached_endpoint_v1_t *input);

/**
 * Read one signed RPC service frame from the local DHT cache and verify it
 * against caller-owned direct trust. The output is zeroed on every failure.
 * This function performs no network lookup and never updates endpoint state.
 */
mesh_mgmt_agent_runtime_result_t
mesh_mgmt_agent_runtime_read_cached_service_v1(mesh_mgmt_agent_runtime_v1_t *runtime,
                                               const mesh_mgmt_agent_cached_service_v1_t *input,
                                               mesh_mgmt_service_record_v1_t *out_record);

/**
 * Resolve one cached RPC service using only an established managed node ID.
 * Trust anchor, mesh identity and the remote certificate come from the
 * runtime's authenticated session state.
 */
mesh_mgmt_agent_runtime_result_t
mesh_mgmt_agent_runtime_resolve_cached_service_v1(mesh_mgmt_agent_runtime_v1_t *runtime,
                                                  const uint8_t owner_node_id[32],
                                                  uint64_t now_ms, uint64_t max_ttl_ms,
                                                  mesh_mgmt_service_record_v1_t *out_record);

/**
 * Sign the next local endpoint fact and push it to the local DHT cache plus
 * currently connected peers. No iterative DHT lookup is run or awaited.
 */
mesh_mgmt_agent_runtime_result_t
mesh_mgmt_agent_runtime_publish_cached_endpoint_v1(mesh_mgmt_agent_runtime_v1_t *runtime,
                                                   const mesh_mgmt_endpoint_publish_v1_t *endpoint,
                                                   uint64_t *out_record_epoch);

/**
 * Sign the next local RPC virtual-service fact and push it to the local DHT
 * cache plus connected peers. The record never enters endpoint dial state.
 */
mesh_mgmt_agent_runtime_result_t
mesh_mgmt_agent_runtime_publish_cached_service_v1(mesh_mgmt_agent_runtime_v1_t *runtime,
                                                  const mesh_mgmt_service_publish_v1_t *service,
                                                  uint64_t *out_record_epoch);

/**
 * Sends one canonical execution request to the unique authenticated management
 * session for target_node_id. The runtime resolves no physical address here.
 */
mesh_mgmt_agent_runtime_result_t
mesh_mgmt_agent_runtime_send_execution_request_v1(
    mesh_mgmt_agent_runtime_v1_t *runtime,
    const uint8_t target_node_id[32],
    const uint8_t *payload,
    size_t payload_len);

/**
 * Sends one canonical execution result/status to the unique authenticated
 * management session for target_node_id.
 */
mesh_mgmt_agent_runtime_result_t
mesh_mgmt_agent_runtime_send_execution_response_v1(
    mesh_mgmt_agent_runtime_v1_t *runtime,
    uint8_t kind,
    const uint8_t target_node_id[32],
    const uint8_t *payload,
    size_t payload_len);

/**
 * Revalidates and copies a request supplied to the configured runtime event
 * callback. The copy may be submitted to an out-of-loop worker.
 */
mesh_mgmt_execution_consumer_result_t
mesh_mgmt_agent_runtime_execution_command_from_event_v1(
    mesh_mgmt_agent_runtime_v1_t *runtime,
    p2p_peer_t *peer,
    const mesh_mgmt_dispatch_event_v1_t *event,
    uint64_t now_ms,
    mesh_mgmt_execution_shadow_command_v1_t *out_command);

/**
 * Sends a command-bound execution status from the active runtime callback.
 */
mesh_mgmt_execution_disabled_responder_result_t
mesh_mgmt_agent_runtime_send_execution_status_from_command_v1(
    mesh_mgmt_agent_runtime_v1_t *runtime,
    p2p_peer_t *peer,
    const mesh_mgmt_execution_shadow_command_v1_t *command,
    uint16_t status_code);

/**
 * Consumes a result/status event through the authenticated dispatcher owned
 * by peer. Intended for use from the configured runtime event callback.
 */
mesh_mgmt_execution_response_consumer_result_t
mesh_mgmt_agent_runtime_execution_response_from_event_v1(
    mesh_mgmt_agent_runtime_v1_t *runtime,
    p2p_peer_t *peer,
    const mesh_mgmt_dispatch_event_v1_t *event,
    mesh_mgmt_execution_response_v1_t *out_response);

mesh_mgmt_execution_disabled_responder_result_t
mesh_mgmt_agent_runtime_send_execution_disabled_from_event_v1(
    mesh_mgmt_agent_runtime_v1_t *runtime,
    p2p_peer_t *peer,
    const mesh_mgmt_dispatch_event_v1_t *event,
    uint64_t now_ms);

/**
 * Stop management work. Dedicated mode disconnects peers and destroys its P2P
 * node. Shared mode detaches MMP without disconnecting mesh peers or destroying
 * the borrowed node. READY may be stopped, STOPPED is idempotent, and a stopped
 * runtime cannot be restarted. Failure leaves STOPPING with the node, provider
 * and composition storage intact for retry. last_p2p_result preserves a P2P
 * cleanup error. Lifecycle calls inside runtime/router callbacks are rejected.
 */
mesh_mgmt_agent_runtime_result_t
mesh_mgmt_agent_runtime_stop_v1(mesh_mgmt_agent_runtime_v1_t *runtime);

/** Stop and release; only success permits freeing runtime/templates/contexts.
 * NULL is accepted. Failure preserves storage and may be retried. */
mesh_mgmt_agent_runtime_result_t
mesh_mgmt_agent_runtime_destroy_v2(mesh_mgmt_agent_runtime_v1_t *runtime);

/** @deprecated Use destroy_v2 and check its result. Failure retains storage. */
void mesh_mgmt_agent_runtime_destroy_v1(mesh_mgmt_agent_runtime_v1_t *runtime);

#ifdef __cplusplus
}
#endif

#endif
