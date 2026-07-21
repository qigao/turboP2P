#include "mesh_mgmt_p2p_adapter.h"

#include <string.h>

static const uint8_t MESH_MGMT_P2P_MAGIC[4] = {'T', 'M', 'G', 'M'};

static int bytes_are_zero(const uint8_t *bytes, size_t length) {
  size_t index;

  for (index = 0u; index < length; index++) {
    if (bytes[index] != 0u)
      return 0;
  }
  return 1;
}

static int p2p_adapter_recv(void *context, uint8_t **out_bytes, size_t *out_len) {
  mesh_mgmt_p2p_adapter_v1_t *adapter = (mesh_mgmt_p2p_adapter_v1_t *)context;

  if (!adapter || !out_bytes || !out_len || !adapter->initialized || !adapter->message_offered ||
      adapter->recv_borrowed || adapter->in_io_callback) {
    if (adapter)
      adapter->last_error = MESH_MGMT_P2P_ADAPTER_INVALID_STATE;
    return -1;
  }

  adapter->in_io_callback = 1u;
  *out_bytes = (uint8_t *)adapter->message;
  *out_len = adapter->message_len;
  adapter->recv_borrowed = 1u;
  adapter->in_io_callback = 0u;
  return 0;
}

static void p2p_adapter_release(void *context, uint8_t *bytes) {
  mesh_mgmt_p2p_adapter_v1_t *adapter = (mesh_mgmt_p2p_adapter_v1_t *)context;

  if (!adapter || !adapter->initialized || !adapter->message_offered || !adapter->recv_borrowed ||
      bytes != adapter->message || adapter->in_io_callback) {
    if (adapter)
      adapter->last_error = MESH_MGMT_P2P_ADAPTER_INVALID_STATE;
    return;
  }

  adapter->in_io_callback = 1u;
  adapter->message = NULL;
  adapter->message_len = 0u;
  adapter->message_offered = 0u;
  adapter->recv_borrowed = 0u;
  adapter->in_io_callback = 0u;
}

static int p2p_adapter_send(void *context, const uint8_t *bytes, size_t length) {
  mesh_mgmt_p2p_adapter_v1_t *adapter = (mesh_mgmt_p2p_adapter_v1_t *)context;
  int result;

  if (!adapter || !bytes || !adapter->initialized || adapter->in_io_callback || length == 0u ||
      length > MESH_MGMT_FRAME_MAX || !mesh_mgmt_p2p_message_is_mmp_v1(bytes, length)) {
    if (adapter)
      adapter->last_error = MESH_MGMT_P2P_ADAPTER_INVALID_STATE;
    return -1;
  }

  adapter->in_io_callback = 1u;
  result = p2p_send_message(adapter->node, adapter->peer, P2P_MSG_CUSTOM, bytes, length);
  adapter->last_p2p_result = result;
  adapter->in_io_callback = 0u;
  if (result != P2P_OK) {
    adapter->last_error = MESH_MGMT_P2P_ADAPTER_P2P_FAILED;
    return -1;
  }
  adapter->last_error = MESH_MGMT_P2P_ADAPTER_OK;
  return 0;
}

int mesh_mgmt_p2p_message_is_mmp_v1(const void *bytes, size_t length) {
  return bytes && length >= sizeof(MESH_MGMT_P2P_MAGIC) &&
         memcmp(bytes, MESH_MGMT_P2P_MAGIC, sizeof(MESH_MGMT_P2P_MAGIC)) == 0;
}

mesh_mgmt_p2p_adapter_result_t
mesh_mgmt_p2p_adapter_init_v1(mesh_mgmt_p2p_adapter_v1_t *adapter, p2p_node_t *node,
                              p2p_peer_t *peer, mesh_mgmt_transport_io_v1_t *out_io,
                              uint8_t out_remote_transport_peer_id[P2P_KEY_SIZE]) {
  uint8_t peer_key[P2P_KEY_SIZE];
  int result;

  if (!adapter || !node || !peer || !out_io || !out_remote_transport_peer_id)
    return MESH_MGMT_P2P_ADAPTER_INVALID_ARG;
  if (adapter->initialized || adapter->node || adapter->peer)
    return MESH_MGMT_P2P_ADAPTER_INVALID_STATE;

  memset(out_io, 0, sizeof(*out_io));
  memset(out_remote_transport_peer_id, 0, P2P_KEY_SIZE);
  memset(peer_key, 0, sizeof(peer_key));
  result = p2p_peer_get_public_key(peer, peer_key);
  if (result != P2P_OK || bytes_are_zero(peer_key, sizeof(peer_key))) {
    memset(peer_key, 0, sizeof(peer_key));
    return MESH_MGMT_P2P_ADAPTER_TRANSPORT_ID_UNAVAILABLE;
  }

  memset(adapter, 0, sizeof(*adapter));
  adapter->node = node;
  adapter->peer = peer;
  memcpy(adapter->remote_transport_peer_id, peer_key, sizeof(peer_key));
  adapter->last_error = MESH_MGMT_P2P_ADAPTER_OK;
  adapter->last_p2p_result = P2P_OK;
  adapter->initialized = 1u;

  out_io->context = adapter;
  out_io->recv = p2p_adapter_recv;
  out_io->release = p2p_adapter_release;
  out_io->send = p2p_adapter_send;
  memcpy(out_remote_transport_peer_id, peer_key, sizeof(peer_key));
  memset(peer_key, 0, sizeof(peer_key));
  return MESH_MGMT_P2P_ADAPTER_OK;
}

void mesh_mgmt_p2p_adapter_destroy_v1(mesh_mgmt_p2p_adapter_v1_t *adapter) {
  if (!adapter)
    return;
  memset(adapter, 0, sizeof(*adapter));
}

mesh_mgmt_p2p_adapter_result_t
mesh_mgmt_p2p_adapter_offer_message_v1(mesh_mgmt_p2p_adapter_v1_t *adapter, const void *bytes,
                                       size_t length) {
  if (!adapter || !bytes)
    return MESH_MGMT_P2P_ADAPTER_INVALID_ARG;
  if (!adapter->initialized || adapter->message_offered || adapter->recv_borrowed ||
      adapter->in_io_callback) {
    return MESH_MGMT_P2P_ADAPTER_INVALID_STATE;
  }
  if (!mesh_mgmt_p2p_message_is_mmp_v1(bytes, length))
    return MESH_MGMT_P2P_ADAPTER_NOT_MMP;
  if (length > MESH_MGMT_FRAME_MAX)
    return MESH_MGMT_P2P_ADAPTER_RESOURCE_EXHAUSTED;

  adapter->message = (const uint8_t *)bytes;
  adapter->message_len = length;
  adapter->message_offered = 1u;
  adapter->last_error = MESH_MGMT_P2P_ADAPTER_OK;
  return MESH_MGMT_P2P_ADAPTER_OK;
}

mesh_mgmt_p2p_adapter_result_t
mesh_mgmt_p2p_adapter_finish_message_v1(mesh_mgmt_p2p_adapter_v1_t *adapter) {
  if (!adapter)
    return MESH_MGMT_P2P_ADAPTER_INVALID_ARG;
  if (!adapter->initialized || adapter->in_io_callback)
    return MESH_MGMT_P2P_ADAPTER_INVALID_STATE;
  if (adapter->recv_borrowed) {
    adapter->last_error = MESH_MGMT_P2P_ADAPTER_MESSAGE_NOT_CONSUMED;
    return adapter->last_error;
  }
  if (adapter->message_offered) {
    adapter->message = NULL;
    adapter->message_len = 0u;
    adapter->message_offered = 0u;
    adapter->last_error = MESH_MGMT_P2P_ADAPTER_MESSAGE_NOT_CONSUMED;
    return adapter->last_error;
  }
  adapter->last_error = MESH_MGMT_P2P_ADAPTER_OK;
  return MESH_MGMT_P2P_ADAPTER_OK;
}
