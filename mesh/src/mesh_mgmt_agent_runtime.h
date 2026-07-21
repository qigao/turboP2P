#ifndef TURBO_P2P_MESH_MGMT_AGENT_RUNTIME_H
#define TURBO_P2P_MESH_MGMT_AGENT_RUNTIME_H

#include "mesh_mgmt_agent_router.h"
#include "mesh_mgmt_endpoint_publisher.h"

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
  const char *listen_host;
  uint16_t listen_port;
  const uint8_t *p2p_private_key;
  size_t max_peers;
  const mesh_mgmt_peer_signer_config_v1_t *signer_template;
  const mesh_mgmt_dispatch_config_v1_t *dispatch_template;
  size_t endpoint_capacity;
  uint64_t retry_base_ms;
  uint64_t retry_max_ms;
  uint64_t connect_timeout_ms;
  uint32_t protocol_failure_limit;
  uint64_t first_endpoint_record_epoch;
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
 * Dedicated single-event-loop composition root. It owns node, listener,
 * router and endpoint pool. signer_template and dispatch_template are
 * immutable borrows and must outlive the runtime. No method is thread-safe.
 */
typedef struct {
  p2p_node_t *node;
  mesh_mgmt_agent_router_v1_t router;
  mesh_mgmt_endpoint_pool_v1_t endpoint_pool;
  mesh_mgmt_endpoint_publisher_v1_t endpoint_publisher;
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
  mesh_mgmt_endpoint_publisher_result_t last_publisher_result;
  int last_p2p_result;
  uint8_t in_api;
} mesh_mgmt_agent_runtime_v1_t;

mesh_mgmt_agent_runtime_result_t
mesh_mgmt_agent_runtime_init_v1(mesh_mgmt_agent_runtime_v1_t *runtime,
                                const mesh_mgmt_agent_runtime_config_v1_t *config);

/** Install callbacks, arm the inert endpoint pool, then bind the listener. */
mesh_mgmt_agent_runtime_result_t
mesh_mgmt_agent_runtime_start_v1(mesh_mgmt_agent_runtime_v1_t *runtime);

/** Run due endpoint transitions and one nonblocking CoroNet loop iteration. */
mesh_mgmt_agent_runtime_result_t
mesh_mgmt_agent_runtime_poll_v1(mesh_mgmt_agent_runtime_v1_t *runtime);

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
 * Sign the next local endpoint fact and push it to the local DHT cache plus
 * currently connected peers. No iterative DHT lookup is run or awaited.
 */
mesh_mgmt_agent_runtime_result_t
mesh_mgmt_agent_runtime_publish_cached_endpoint_v1(mesh_mgmt_agent_runtime_v1_t *runtime,
                                                   const mesh_mgmt_endpoint_publish_v1_t *endpoint,
                                                   uint64_t *out_record_epoch);

/**
 * Stop reconnects, disconnect managed peers and destroy the owned P2P node.
 * A stopped runtime cannot be restarted; destroy and initialize a new one.
 */
mesh_mgmt_agent_runtime_result_t
mesh_mgmt_agent_runtime_stop_v1(mesh_mgmt_agent_runtime_v1_t *runtime);

void mesh_mgmt_agent_runtime_destroy_v1(mesh_mgmt_agent_runtime_v1_t *runtime);

#ifdef __cplusplus
}
#endif

#endif
