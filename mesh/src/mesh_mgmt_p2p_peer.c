#include "mesh_mgmt_p2p_peer.h"

#include "mesh_mgmt_crypto.h"

#include <string.h>

static mesh_mgmt_p2p_peer_result_t runtime_fail(mesh_mgmt_p2p_peer_v1_t *runtime,
                                                mesh_mgmt_p2p_peer_result_t result) {
  runtime->state = MESH_MGMT_P2P_PEER_TERMINAL;
  runtime->last_error = result;
  return result;
}

mesh_mgmt_p2p_peer_result_t
mesh_mgmt_p2p_peer_init_v1(mesh_mgmt_p2p_peer_v1_t *runtime,
                           const mesh_mgmt_p2p_peer_config_v1_t *config) {
  mesh_mgmt_transport_io_v1_t io;
  mesh_mgmt_peer_config_v1_t peer_config;
  uint8_t local_transport_peer_id[P2P_KEY_SIZE];
  uint8_t remote_transport_peer_id[P2P_KEY_SIZE];
  int p2p_result;

  if (!runtime || !config || !config->node || !config->peer || !config->on_event)
    return MESH_MGMT_P2P_PEER_INVALID_ARG;
  if (runtime->state != MESH_MGMT_P2P_PEER_UNINITIALIZED || runtime->adapter.initialized ||
      runtime->signer.state != MESH_MGMT_PEER_SIGNER_UNINITIALIZED ||
      runtime->protocol_peer.state != MESH_MGMT_PEER_UNINITIALIZED) {
    return MESH_MGMT_P2P_PEER_INVALID_STATE;
  }

  memset(&io, 0, sizeof(io));
  memset(&peer_config, 0, sizeof(peer_config));
  memset(local_transport_peer_id, 0, sizeof(local_transport_peer_id));
  memset(remote_transport_peer_id, 0, sizeof(remote_transport_peer_id));
  p2p_result = p2p_node_get_public_key(config->node, local_transport_peer_id);
  if (p2p_result != P2P_OK ||
      !mesh_mgmt_crypto_equal_32(local_transport_peer_id, config->signer.local_transport_peer_id)) {
    memset(local_transport_peer_id, 0, sizeof(local_transport_peer_id));
    return MESH_MGMT_P2P_PEER_IDENTITY_MISMATCH;
  }

  memset(runtime, 0, sizeof(*runtime));
  runtime->last_adapter_result = mesh_mgmt_p2p_adapter_init_v1(
      &runtime->adapter, config->node, config->peer, &io, remote_transport_peer_id);
  if (runtime->last_adapter_result != MESH_MGMT_P2P_ADAPTER_OK)
    goto adapter_failed;

  runtime->last_signer_result = mesh_mgmt_peer_signer_init_v1(&runtime->signer, &config->signer);
  if (runtime->last_signer_result != MESH_MGMT_PEER_SIGNER_OK)
    goto signer_failed;

  peer_config.connection.dispatch = config->dispatch;
  peer_config.connection.io = io;
  memcpy(peer_config.connection.transport_peer_id, remote_transport_peer_id,
         sizeof(remote_transport_peer_id));
  peer_config.connection.on_event = config->on_event;
  peer_config.connection.event_context = config->event_context;
  memcpy(peer_config.local_transport_peer_id, local_transport_peer_id,
         sizeof(local_transport_peer_id));
  peer_config.build_hello = mesh_mgmt_peer_signer_build_hello_v1;
  peer_config.build_ack = mesh_mgmt_peer_signer_build_ack_v1;
  peer_config.builder_context = &runtime->signer;
  runtime->last_peer_result = mesh_mgmt_peer_init_v1(&runtime->protocol_peer, &peer_config);
  if (runtime->last_peer_result != MESH_MGMT_PEER_OK)
    goto peer_failed;

  runtime->state = MESH_MGMT_P2P_PEER_READY;
  runtime->last_error = MESH_MGMT_P2P_PEER_OK;
  memset(local_transport_peer_id, 0, sizeof(local_transport_peer_id));
  memset(remote_transport_peer_id, 0, sizeof(remote_transport_peer_id));
  return MESH_MGMT_P2P_PEER_OK;

peer_failed:
  mesh_mgmt_peer_signer_destroy_v1(&runtime->signer);
signer_failed:
  mesh_mgmt_p2p_adapter_destroy_v1(&runtime->adapter);
  memset(local_transport_peer_id, 0, sizeof(local_transport_peer_id));
  memset(remote_transport_peer_id, 0, sizeof(remote_transport_peer_id));
  memset(&runtime->protocol_peer, 0, sizeof(runtime->protocol_peer));
  runtime->last_error = runtime->last_signer_result != MESH_MGMT_PEER_SIGNER_OK
                            ? MESH_MGMT_P2P_PEER_SIGNER_FAILED
                            : MESH_MGMT_P2P_PEER_PROTOCOL_FAILED;
  return runtime->last_error;

adapter_failed:
  memset(local_transport_peer_id, 0, sizeof(local_transport_peer_id));
  memset(remote_transport_peer_id, 0, sizeof(remote_transport_peer_id));
  runtime->last_error = MESH_MGMT_P2P_PEER_ADAPTER_FAILED;
  return runtime->last_error;
}

void mesh_mgmt_p2p_peer_destroy_v1(mesh_mgmt_p2p_peer_v1_t *runtime) {
  if (!runtime || runtime->in_api)
    return;
  mesh_mgmt_peer_destroy_v1(&runtime->protocol_peer);
  mesh_mgmt_peer_signer_destroy_v1(&runtime->signer);
  mesh_mgmt_p2p_adapter_destroy_v1(&runtime->adapter);
  memset(runtime, 0, sizeof(*runtime));
}

mesh_mgmt_p2p_peer_result_t mesh_mgmt_p2p_peer_start_v1(mesh_mgmt_p2p_peer_v1_t *runtime,
                                                        uint64_t now_ms) {
  if (!runtime)
    return MESH_MGMT_P2P_PEER_INVALID_ARG;
  if (runtime->state != MESH_MGMT_P2P_PEER_READY || runtime->in_api)
    return MESH_MGMT_P2P_PEER_INVALID_STATE;

  runtime->in_api = 1u;
  runtime->last_peer_result = mesh_mgmt_peer_start_v1(&runtime->protocol_peer, now_ms);
  runtime->in_api = 0u;
  if (runtime->last_peer_result != MESH_MGMT_PEER_OK)
    return runtime_fail(runtime, MESH_MGMT_P2P_PEER_PROTOCOL_FAILED);
  runtime->last_error = MESH_MGMT_P2P_PEER_OK;
  return MESH_MGMT_P2P_PEER_OK;
}

mesh_mgmt_p2p_peer_result_t mesh_mgmt_p2p_peer_handle_message_v1(mesh_mgmt_p2p_peer_v1_t *runtime,
                                                                 const void *bytes, size_t length,
                                                                 uint64_t now_ms) {
  mesh_mgmt_p2p_adapter_result_t finish_result;

  if (!runtime || !bytes)
    return MESH_MGMT_P2P_PEER_INVALID_ARG;
  if (runtime->state != MESH_MGMT_P2P_PEER_READY || runtime->in_api)
    return MESH_MGMT_P2P_PEER_INVALID_STATE;
  if (!mesh_mgmt_p2p_message_is_mmp_v1(bytes, length))
    return MESH_MGMT_P2P_PEER_NOT_MMP;

  runtime->in_api = 1u;
  runtime->last_adapter_result =
      mesh_mgmt_p2p_adapter_offer_message_v1(&runtime->adapter, bytes, length);
  if (runtime->last_adapter_result != MESH_MGMT_P2P_ADAPTER_OK) {
    runtime->in_api = 0u;
    return runtime_fail(runtime, MESH_MGMT_P2P_PEER_ADAPTER_FAILED);
  }

  runtime->last_peer_result = mesh_mgmt_peer_pump_once_v1(&runtime->protocol_peer, now_ms);
  finish_result = mesh_mgmt_p2p_adapter_finish_message_v1(&runtime->adapter);
  runtime->last_adapter_result = finish_result;
  runtime->in_api = 0u;
  if (finish_result != MESH_MGMT_P2P_ADAPTER_OK) {
    mesh_mgmt_peer_destroy_v1(&runtime->protocol_peer);
    return runtime_fail(runtime, MESH_MGMT_P2P_PEER_MESSAGE_LIFETIME_FAILED);
  }
  if (runtime->last_peer_result != MESH_MGMT_PEER_OK)
    return runtime_fail(runtime, MESH_MGMT_P2P_PEER_PROTOCOL_FAILED);

  runtime->last_error = MESH_MGMT_P2P_PEER_OK;
  return MESH_MGMT_P2P_PEER_OK;
}
