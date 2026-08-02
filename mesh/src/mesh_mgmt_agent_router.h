#ifndef TURBO_P2P_MESH_MGMT_AGENT_ROUTER_H
#define TURBO_P2P_MESH_MGMT_AGENT_ROUTER_H

#include "mesh_mgmt_p2p_peer.h"
#include "mesh_mgmt_execution_disabled_responder.h"
#include "mesh_mgmt_execution_consumer.h"
#include "mesh_mgmt_execution_response_consumer.h"

#include <turbo_vec.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_MGMT_AGENT_ROUTER_MAX_PEERS 64u

typedef enum {
  MESH_MGMT_AGENT_ROUTER_NOT_MMP = 1,
  MESH_MGMT_AGENT_ROUTER_OK = 0,
  MESH_MGMT_AGENT_ROUTER_INVALID_ARG = -1,
  MESH_MGMT_AGENT_ROUTER_INVALID_STATE = -2,
  MESH_MGMT_AGENT_ROUTER_CONFIG_INVALID = -3,
  MESH_MGMT_AGENT_ROUTER_IDENTITY_MISMATCH = -4,
  MESH_MGMT_AGENT_ROUTER_RANDOM_FAILED = -5,
  MESH_MGMT_AGENT_ROUTER_RESOURCE_EXHAUSTED = -6,
  MESH_MGMT_AGENT_ROUTER_DUPLICATE_PEER = -7,
  MESH_MGMT_AGENT_ROUTER_PEER_FAILED = -8,
  MESH_MGMT_AGENT_ROUTER_PEER_NOT_FOUND = -9,
} mesh_mgmt_agent_router_result_t;

typedef enum {
  MESH_MGMT_AGENT_ROUTER_UNINITIALIZED = 0,
  MESH_MGMT_AGENT_ROUTER_READY = 1,
  MESH_MGMT_AGENT_ROUTER_INSTALLED = 2,
} mesh_mgmt_agent_router_state_t;

typedef int (*mesh_mgmt_agent_router_random_fn)(void *context, uint8_t *output, size_t output_len);

typedef int (*mesh_mgmt_agent_router_event_fn)(void *context, p2p_peer_t *peer,
                                               const uint8_t remote_transport_peer_id[P2P_KEY_SIZE],
                                               const mesh_mgmt_dispatch_event_v1_t *event);

typedef void (*mesh_mgmt_agent_router_non_mmp_fn)(void *context, p2p_node_t *node, p2p_peer_t *peer,
                                                  const void *bytes, size_t length);

typedef void (*mesh_mgmt_agent_router_failure_fn)(void *context, p2p_peer_t *peer,
                                                  mesh_mgmt_agent_router_result_t router_result,
                                                  mesh_mgmt_p2p_peer_result_t peer_result);

typedef enum {
  MESH_MGMT_AGENT_ROUTER_CLOSE_TRANSPORT = 1,
  MESH_MGMT_AGENT_ROUTER_CLOSE_PROTOCOL = 2,
  MESH_MGMT_AGENT_ROUTER_CLOSE_LOCAL_STOP = 3,
} mesh_mgmt_agent_router_close_reason_t;

typedef void (*mesh_mgmt_agent_router_peer_closed_fn)(
    void *context, p2p_peer_t *peer, const uint8_t remote_transport_peer_id[P2P_KEY_SIZE],
    mesh_mgmt_agent_router_close_reason_t reason);

typedef struct {
  p2p_node_t *node;
  size_t max_peers;
  const mesh_mgmt_peer_signer_config_v1_t *signer_template;
  const mesh_mgmt_dispatch_config_v1_t *dispatch_template;
  mesh_mgmt_agent_router_random_fn random_bytes;
  void *random_context;
  mesh_mgmt_agent_router_event_fn on_event;
  mesh_mgmt_agent_router_non_mmp_fn on_non_mmp;
  mesh_mgmt_agent_router_failure_fn on_failure;
  mesh_mgmt_agent_router_peer_closed_fn on_peer_closed;
  void *callback_context;
} mesh_mgmt_agent_router_config_v1_t;

typedef struct mesh_mgmt_agent_router_v1_s mesh_mgmt_agent_router_v1_t;

typedef struct {
  mesh_mgmt_agent_router_v1_t *router;
  p2p_peer_t *peer;
  mesh_mgmt_p2p_peer_v1_t runtime;
  uint8_t remote_transport_peer_id[P2P_KEY_SIZE];
  uint8_t connection_id[16];
  uint8_t active;
  uint8_t disconnect_pending;
  uint8_t failure_reported;
  uint8_t close_reported;
  mesh_mgmt_agent_router_close_reason_t close_reason;
} mesh_mgmt_agent_router_slot_v1_t;

typedef struct {
  uint8_t remote_transport_peer_id[P2P_KEY_SIZE];
  uint8_t connection_id[16];
  mesh_mgmt_p2p_peer_state_t runtime_state;
  mesh_mgmt_session_state_t session_state;
} mesh_mgmt_agent_router_peer_snapshot_v1_t;

typedef struct {
  uint8_t managed_node_id[32];
  uint8_t certificate[MESH_MGMT_CERTIFICATE_V1_SIZE];
  size_t certificate_len;
} mesh_mgmt_agent_router_identity_snapshot_v1_t;

/**
 * Single-event-loop owner for all MMP runtimes attached to one P2P node.
 * signer_template and dispatch_template are immutable borrows and must outlive
 * the router. The router owns only its bounded slot vector, not the node or
 * peers. P2P callbacks are exclusive while the router is installed.
 */
struct mesh_mgmt_agent_router_v1_s {
  p2p_node_t *node;
  const mesh_mgmt_peer_signer_config_v1_t *signer_template;
  const mesh_mgmt_dispatch_config_v1_t *dispatch_template;
  mesh_mgmt_agent_router_random_fn random_bytes;
  void *random_context;
  mesh_mgmt_agent_router_event_fn on_event;
  mesh_mgmt_agent_router_non_mmp_fn on_non_mmp;
  mesh_mgmt_agent_router_failure_fn on_failure;
  mesh_mgmt_agent_router_peer_closed_fn on_peer_closed;
  void *callback_context;
  turbo_vec_t slots;
  size_t max_peers;
  size_t active_peers;
  uint8_t connection_namespace[16];
  uint64_t next_connection_sequence;
  mesh_mgmt_agent_router_state_t state;
  mesh_mgmt_agent_router_result_t last_error;
  mesh_mgmt_p2p_peer_result_t last_peer_result;
  mesh_mgmt_peer_signer_result_t last_signer_result;
  mesh_mgmt_dispatch_result_t last_dispatch_result;
  uint32_t callback_depth;
  uint8_t owns_callbacks;
};

mesh_mgmt_agent_router_result_t
mesh_mgmt_agent_router_init_v1(mesh_mgmt_agent_router_v1_t *router,
                               const mesh_mgmt_agent_router_config_v1_t *config);

/** Install this router as the node's exclusive peer/message callback owner. */
mesh_mgmt_agent_router_result_t
mesh_mgmt_agent_router_install_v1(mesh_mgmt_agent_router_v1_t *router);

/**
 * Activate the router without replacing P2P callbacks. The caller remains the
 * sole callback owner and must forward peer and message events through the
 * offer functions below.
 */
mesh_mgmt_agent_router_result_t
mesh_mgmt_agent_router_start_embedded_v1(mesh_mgmt_agent_router_v1_t *router);

mesh_mgmt_agent_router_result_t mesh_mgmt_agent_router_offer_peer_connected_v1(
    mesh_mgmt_agent_router_v1_t *router, p2p_peer_t *peer);

mesh_mgmt_agent_router_result_t mesh_mgmt_agent_router_offer_peer_disconnected_v1(
    mesh_mgmt_agent_router_v1_t *router, p2p_peer_t *peer);

/**
 * Route one custom message. NOT_MMP means the caller retains ownership and
 * must continue its normal protocol dispatch. Every other result consumes the
 * message, including malformed or unauthorized MMP input.
 */
mesh_mgmt_agent_router_result_t mesh_mgmt_agent_router_offer_message_v1(
    mesh_mgmt_agent_router_v1_t *router, p2p_node_t *node, p2p_peer_t *peer,
    const void *bytes, size_t length);

/** Disconnect managed peers and unregister callbacks; the P2P node stays alive. */
mesh_mgmt_agent_router_result_t mesh_mgmt_agent_router_stop_v1(mesh_mgmt_agent_router_v1_t *router);

void mesh_mgmt_agent_router_destroy_v1(mesh_mgmt_agent_router_v1_t *router);

size_t mesh_mgmt_agent_router_active_peers_v1(const mesh_mgmt_agent_router_v1_t *router);

mesh_mgmt_agent_router_result_t
mesh_mgmt_agent_router_peer_snapshot_v1(const mesh_mgmt_agent_router_v1_t *router,
                                        const p2p_peer_t *peer,
                                        mesh_mgmt_agent_router_peer_snapshot_v1_t *out_snapshot);

/**
 * Copy the direct enrollment identity of one established managed node.
 * Duplicate active sessions for the same node fail closed.
 */
mesh_mgmt_agent_router_result_t mesh_mgmt_agent_router_identity_snapshot_v1(
    const mesh_mgmt_agent_router_v1_t *router, const uint8_t managed_node_id[32],
    mesh_mgmt_agent_router_identity_snapshot_v1_t *out_snapshot);

/**
 * Sends one canonical COMMAND_REQUEST through the unique established session
 * authenticated for target_node_id. Physical peer addresses never cross this
 * boundary.
 */
mesh_mgmt_agent_router_result_t
mesh_mgmt_agent_router_send_execution_request_v1(
    mesh_mgmt_agent_router_v1_t *router,
    const uint8_t target_node_id[32],
    const uint8_t *payload,
    size_t payload_len);

/**
 * Sends one canonical COMMAND_RESULT or COMMAND_STATUS through the unique
 * established session authenticated for target_node_id.
 */
mesh_mgmt_agent_router_result_t
mesh_mgmt_agent_router_send_execution_response_v1(
    mesh_mgmt_agent_router_v1_t *router,
    uint8_t kind,
    const uint8_t target_node_id[32],
    const uint8_t *payload,
    size_t payload_len);

/**
 * Revalidates and copies an execution request from the dispatcher owned by
 * peer. This is safe only during the router event callback that supplied event.
 */
mesh_mgmt_execution_consumer_result_t
mesh_mgmt_agent_router_execution_command_from_event_v1(
    mesh_mgmt_agent_router_v1_t *router,
    p2p_peer_t *peer,
    const mesh_mgmt_dispatch_event_v1_t *event,
    uint64_t now_ms,
    mesh_mgmt_execution_shadow_command_v1_t *out_command);

/**
 * Sends a command-bound execution status during the router event callback
 * that supplied command. Peer and node identities are revalidated.
 */
mesh_mgmt_execution_disabled_responder_result_t
mesh_mgmt_agent_router_send_execution_status_from_command_v1(
    mesh_mgmt_agent_router_v1_t *router,
    p2p_peer_t *peer,
    const mesh_mgmt_execution_shadow_command_v1_t *command,
    uint16_t status_code);

/**
 * Converts an execution response event through the dispatcher owned by peer.
 * This may be called from the router event callback; the returned response is
 * already bound to the authenticated session and responder identity.
 */
mesh_mgmt_execution_response_consumer_result_t
mesh_mgmt_agent_router_execution_response_from_event_v1(
    mesh_mgmt_agent_router_v1_t *router,
    p2p_peer_t *peer,
    const mesh_mgmt_dispatch_event_v1_t *event,
    mesh_mgmt_execution_response_v1_t *out_response);

mesh_mgmt_execution_disabled_responder_result_t
mesh_mgmt_agent_router_send_execution_disabled_from_event_v1(
    mesh_mgmt_agent_router_v1_t *router,
    p2p_peer_t *peer,
    const mesh_mgmt_dispatch_event_v1_t *event,
    uint64_t now_ms);

#ifdef __cplusplus
}
#endif

#endif
