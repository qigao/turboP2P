#ifndef TURBO_P2P_MESH_MGMT_AGENT_RUNTIME_H
#define TURBO_P2P_MESH_MGMT_AGENT_RUNTIME_H

#include "mesh_mgmt_agent_router.h"
#include "mesh_mgmt_endpoint_publisher.h"
#include "mesh_mgmt_p2p_security.h"
#include "mesh_mgmt_service_publisher.h"

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
} mesh_mgmt_agent_runtime_result_t;

typedef enum {
  MESH_MGMT_AGENT_RUNTIME_UNINITIALIZED = 0,
  MESH_MGMT_AGENT_RUNTIME_READY = 1,
  MESH_MGMT_AGENT_RUNTIME_RUNNING = 2,
  MESH_MGMT_AGENT_RUNTIME_STOPPED = 3,
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
} mesh_mgmt_agent_runtime_v1_t;

mesh_mgmt_agent_runtime_result_t
mesh_mgmt_agent_runtime_init_v1(mesh_mgmt_agent_runtime_v1_t *runtime,
                                const mesh_mgmt_agent_runtime_config_v1_t *config);

/**
 * Dedicated mode installs callbacks and binds its listener. Shared mode
 * attaches to mesh before mesh_start(); the caller starts the mesh afterward.
 */
mesh_mgmt_agent_runtime_result_t
mesh_mgmt_agent_runtime_start_v1(mesh_mgmt_agent_runtime_v1_t *runtime);

/**
 * Dedicated mode advances endpoint dialing and CoroNet. Shared mode is a
 * no-op because mesh_poll() owns connection policy and the event loop.
 */
mesh_mgmt_agent_runtime_result_t
mesh_mgmt_agent_runtime_poll_v1(mesh_mgmt_agent_runtime_v1_t *runtime);

/**
 * Atomically install a dedicated runtime's remote trust snapshot and
 * revalidate all established Noise sessions before processing more traffic.
 * This command must run on the runtime's CoroNet owner thread. READY and
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
 * the borrowed node. A stopped runtime cannot be restarted.
 */
mesh_mgmt_agent_runtime_result_t
mesh_mgmt_agent_runtime_stop_v1(mesh_mgmt_agent_runtime_v1_t *runtime);

void mesh_mgmt_agent_runtime_destroy_v1(mesh_mgmt_agent_runtime_v1_t *runtime);

#ifdef __cplusplus
}
#endif

#endif
