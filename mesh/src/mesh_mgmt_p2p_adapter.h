#ifndef TURBO_P2P_MESH_MGMT_P2P_ADAPTER_H
#define TURBO_P2P_MESH_MGMT_P2P_ADAPTER_H

#include "mesh_mgmt_transport.h"

#include <p2p.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  MESH_MGMT_P2P_ADAPTER_OK = 0,
  MESH_MGMT_P2P_ADAPTER_INVALID_ARG = -1,
  MESH_MGMT_P2P_ADAPTER_INVALID_STATE = -2,
  MESH_MGMT_P2P_ADAPTER_TRANSPORT_ID_UNAVAILABLE = -3,
  MESH_MGMT_P2P_ADAPTER_NOT_MMP = -4,
  MESH_MGMT_P2P_ADAPTER_RESOURCE_EXHAUSTED = -5,
  MESH_MGMT_P2P_ADAPTER_P2P_FAILED = -6,
  MESH_MGMT_P2P_ADAPTER_MESSAGE_NOT_CONSUMED = -7,
} mesh_mgmt_p2p_adapter_result_t;

/**
 * Thin, single-event-loop adapter for one key-bearing P2P peer. The node,
 * peer and offered message bytes remain caller-owned. One adapter must only be
 * used from callbacks belonging to the same node/peer pair.
 */
typedef struct {
  p2p_node_t *node;
  p2p_peer_t *peer;
  const uint8_t *message;
  size_t message_len;
  uint8_t remote_transport_peer_id[P2P_KEY_SIZE];
  mesh_mgmt_p2p_adapter_result_t last_error;
  int last_p2p_result;
  uint8_t initialized;
  uint8_t message_offered;
  uint8_t recv_borrowed;
  uint8_t in_io_callback;
} mesh_mgmt_p2p_adapter_v1_t;

/** Return non-zero only when bytes carry the reserved MMP magic prefix. */
int mesh_mgmt_p2p_message_is_mmp_v1(const void *bytes, size_t length);

/**
 * Build transport IO for a key-bearing P2P peer. Initialization fails until
 * p2p_peer_get_public_key() can return the static key learned by the encrypted
 * handshake. Availability alone is not MMP authentication; signed HELLO must
 * still prove the certificate/key/transport binding. The output receives a
 * copy of that transport key.
 */
mesh_mgmt_p2p_adapter_result_t
mesh_mgmt_p2p_adapter_init_v1(mesh_mgmt_p2p_adapter_v1_t *adapter, p2p_node_t *node,
                              p2p_peer_t *peer, mesh_mgmt_transport_io_v1_t *out_io,
                              uint8_t out_remote_transport_peer_id[P2P_KEY_SIZE]);

void mesh_mgmt_p2p_adapter_destroy_v1(mesh_mgmt_p2p_adapter_v1_t *adapter);

/** Offer one complete callback-borrowed P2P custom-message to transport recv. */
mesh_mgmt_p2p_adapter_result_t
mesh_mgmt_p2p_adapter_offer_message_v1(mesh_mgmt_p2p_adapter_v1_t *adapter, const void *bytes,
                                       size_t length);

/**
 * End the synchronous message callback. Success proves transport consumed and
 * released the offered borrow before the P2P callback returns.
 */
mesh_mgmt_p2p_adapter_result_t
mesh_mgmt_p2p_adapter_finish_message_v1(mesh_mgmt_p2p_adapter_v1_t *adapter);

#ifdef __cplusplus
}
#endif

#endif
