#ifndef TURBO_P2P_MESH_MGMT_P2P_PEER_H
#define TURBO_P2P_MESH_MGMT_P2P_PEER_H

#include "mesh_mgmt_p2p_adapter.h"
#include "mesh_mgmt_peer_signer.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  MESH_MGMT_P2P_PEER_OK = 0,
  MESH_MGMT_P2P_PEER_INVALID_ARG = -1,
  MESH_MGMT_P2P_PEER_INVALID_STATE = -2,
  MESH_MGMT_P2P_PEER_IDENTITY_MISMATCH = -3,
  MESH_MGMT_P2P_PEER_ADAPTER_FAILED = -4,
  MESH_MGMT_P2P_PEER_SIGNER_FAILED = -5,
  MESH_MGMT_P2P_PEER_PROTOCOL_FAILED = -6,
  MESH_MGMT_P2P_PEER_NOT_MMP = -7,
  MESH_MGMT_P2P_PEER_MESSAGE_LIFETIME_FAILED = -8,
} mesh_mgmt_p2p_peer_result_t;

typedef enum {
  MESH_MGMT_P2P_PEER_UNINITIALIZED = 0,
  MESH_MGMT_P2P_PEER_READY = 1,
  MESH_MGMT_P2P_PEER_TERMINAL = 2,
} mesh_mgmt_p2p_peer_state_t;

typedef struct {
  p2p_node_t *node;
  p2p_peer_t *peer;
  mesh_mgmt_peer_signer_config_v1_t signer;
  mesh_mgmt_dispatch_config_v1_t dispatch;
  mesh_mgmt_connection_event_fn on_event;
  void *event_context;
} mesh_mgmt_p2p_peer_config_v1_t;

/**
 * Per-connected-peer owner for adapter, short-lived signer and MMP handshake.
 * The P2P node/peer remain caller-owned and must outlive this object. No locks,
 * listener registration, reconnect policy or endpoint discovery are included.
 */
typedef struct {
  mesh_mgmt_p2p_adapter_v1_t adapter;
  mesh_mgmt_peer_signer_v1_t signer;
  mesh_mgmt_peer_v1_t protocol_peer;
  mesh_mgmt_p2p_peer_state_t state;
  mesh_mgmt_p2p_peer_result_t last_error;
  mesh_mgmt_p2p_adapter_result_t last_adapter_result;
  mesh_mgmt_peer_signer_result_t last_signer_result;
  mesh_mgmt_peer_result_t last_peer_result;
  uint8_t in_api;
} mesh_mgmt_p2p_peer_v1_t;

mesh_mgmt_p2p_peer_result_t
mesh_mgmt_p2p_peer_init_v1(mesh_mgmt_p2p_peer_v1_t *runtime,
                           const mesh_mgmt_p2p_peer_config_v1_t *config);

void mesh_mgmt_p2p_peer_destroy_v1(mesh_mgmt_p2p_peer_v1_t *runtime);

/** Build and send this connection's signed HELLO exactly once. */
mesh_mgmt_p2p_peer_result_t mesh_mgmt_p2p_peer_start_v1(mesh_mgmt_p2p_peer_v1_t *runtime,
                                                        uint64_t now_ms);

/**
 * Synchronously consume one P2P custom-message callback. Non-MMP payloads are
 * reported without changing protocol state so an outer legacy mux can handle
 * them. Any MMP ambiguity makes this peer runtime terminal.
 */
mesh_mgmt_p2p_peer_result_t mesh_mgmt_p2p_peer_handle_message_v1(mesh_mgmt_p2p_peer_v1_t *runtime,
                                                                 const void *bytes, size_t length,
                                                                 uint64_t now_ms);

#ifdef __cplusplus
}
#endif

#endif
