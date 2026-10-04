#ifndef TURBO_P2P_MESH_MGMT_CNET_PEER_H
#define TURBO_P2P_MESH_MGMT_CNET_PEER_H

#include "mesh_mgmt_peer_signer.h"
#include <cnet/cnet.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  mesh_mgmt_dispatch_config_v1_t dispatch;
  mesh_mgmt_peer_signer_config_v1_t signer;
  uint8_t remote_transport_peer_id[32];
  mesh_mgmt_connection_event_fn on_event;
  void *event_context;
} mesh_mgmt_cnet_peer_config_v1_t;

/**
 * Signed MMP peer on one already connected CNet TLS 1.3 handle. The caller owns
 * the client and observer, and must forward that handle's receive/send/terminal
 * callbacks exclusively here. Do not send directly on this handle. All methods
 * run on the client's poll thread; only connection_send_event_response may be
 * called from the borrowed application event callback. No internal poll occurs.
 *
 * Stable storage is required through CLOSED/FAILED. close is asynchronous;
 * destroy rejects a live handle, including one whose protocol already failed.
 */
typedef struct {
  mesh_mgmt_peer_v1_t peer;
  mesh_mgmt_peer_signer_v1_t signer;
  cnet_client *client;
  cnet_connection connection;
  uint8_t channel_binding[32];
  uint8_t chunk[MESH_MGMT_FRAME_MAX];
  size_t chunk_len;
  uint64_t pending_token;
  size_t pending_bytes;
  int chunk_borrowed;
  int receive_pending;
  int initialized;
  int terminal_observed;
  int close_requested;
  int in_callback;
  int last_cnet_status;
} mesh_mgmt_cnet_peer_v1_t;

/** The actual exporter overrides config bindings in both dispatcher and signer. */
mesh_mgmt_peer_result_t mesh_mgmt_cnet_peer_init_v1(
    mesh_mgmt_cnet_peer_v1_t *owner, cnet_client *client, cnet_connection connection,
    const mesh_mgmt_cnet_peer_config_v1_t *config);
mesh_mgmt_peer_result_t mesh_mgmt_cnet_peer_start_v1(mesh_mgmt_cnet_peer_v1_t *owner, uint64_t now_ms);

/** Copy the CNet callback loan, authenticate complete frames, and maintain demand. */
mesh_mgmt_peer_result_t mesh_mgmt_cnet_peer_on_receive_v1(
    mesh_mgmt_cnet_peer_v1_t *owner, cnet_connection connection,
    const cnet_receive_view *view, uint64_t now_ms);
/** Match one logical write; only then commit HELLO/ACK and resume buffered input. */
mesh_mgmt_peer_result_t mesh_mgmt_cnet_peer_on_send_v1(
    mesh_mgmt_cnet_peer_v1_t *owner, cnet_connection connection, size_t bytes, uint64_t now_ms);
/** Forward CLOSED/FAILED, including after a protocol error requested close. */
mesh_mgmt_peer_result_t mesh_mgmt_cnet_peer_on_state_v1(
    mesh_mgmt_cnet_peer_v1_t *owner, cnet_connection connection, cnet_connection_state state);
/** Build and admit a signed targeted frame after establishment. BUSY admits nothing. */
mesh_mgmt_connection_result_t mesh_mgmt_cnet_peer_send_v1(
    mesh_mgmt_cnet_peer_v1_t *owner, uint8_t kind, const uint8_t *payload, size_t payload_len);
/**
 * Abort protocol and request close (already-closing is accepted). If command
 * admission fails, keep storage and retry close after polling, or stop the
 * client; destroy still requires the matching terminal observation.
 */
mesh_mgmt_peer_result_t mesh_mgmt_cnet_peer_close_v1(mesh_mgmt_cnet_peer_v1_t *owner);
mesh_mgmt_peer_result_t mesh_mgmt_cnet_peer_destroy_v1(mesh_mgmt_cnet_peer_v1_t *owner);

#ifdef __cplusplus
}
#endif
#endif
