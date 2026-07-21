#include "mesh_mgmt_agent_router.h"

#include "mesh_mgmt_crypto.h"

#include <platform.h>

#include <string.h>

static int bytes_are_zero(const uint8_t *bytes, size_t length) {
  size_t index;
  uint8_t combined = 0u;

  for (index = 0u; index < length; index++)
    combined |= bytes[index];
  return combined == 0u;
}

static mesh_mgmt_agent_router_slot_v1_t *slot_at(mesh_mgmt_agent_router_v1_t *router,
                                                 size_t index) {
  return (mesh_mgmt_agent_router_slot_v1_t *)turbo_vec_at(&router->slots, index);
}

static const mesh_mgmt_agent_router_slot_v1_t *
slot_at_const(const mesh_mgmt_agent_router_v1_t *router, size_t index) {
  return (const mesh_mgmt_agent_router_slot_v1_t *)turbo_vec_at_const(&router->slots, index);
}

static mesh_mgmt_agent_router_slot_v1_t *find_slot(mesh_mgmt_agent_router_v1_t *router,
                                                   const p2p_peer_t *peer) {
  size_t index;

  for (index = 0u; index < router->max_peers; index++) {
    mesh_mgmt_agent_router_slot_v1_t *slot = slot_at(router, index);
    if (slot && slot->active && slot->peer == peer)
      return slot;
  }
  return NULL;
}

static mesh_mgmt_agent_router_slot_v1_t *find_free_slot(mesh_mgmt_agent_router_v1_t *router) {
  size_t index;

  for (index = 0u; index < router->max_peers; index++) {
    mesh_mgmt_agent_router_slot_v1_t *slot = slot_at(router, index);
    if (slot && !slot->active)
      return slot;
  }
  return NULL;
}

static uint64_t router_now_ms(const mesh_mgmt_agent_router_v1_t *router) {
  return router->signer_template->now_ms
             ? router->signer_template->now_ms(router->signer_template->callback_context)
             : turbo_realtime_ms();
}

static int router_random(mesh_mgmt_agent_router_v1_t *router, uint8_t *output, size_t output_len) {
  return router->random_bytes ? router->random_bytes(router->random_context, output, output_len)
                              : turbo_secure_random(output, output_len);
}

static mesh_mgmt_agent_router_result_t next_connection_id(mesh_mgmt_agent_router_v1_t *router,
                                                          uint8_t output[16]) {
  uint64_t addend;
  size_t index;

  if (router->next_connection_sequence == 0u)
    return MESH_MGMT_AGENT_ROUTER_RESOURCE_EXHAUSTED;
  memcpy(output, router->connection_namespace, 16u);
  addend = router->next_connection_sequence;
  for (index = 16u; index > 0u && addend != 0u; index--) {
    uint16_t sum = (uint16_t)output[index - 1u] + (uint16_t)(addend & 0xffu);
    output[index - 1u] = (uint8_t)sum;
    addend = (addend >> 8u) + (uint64_t)(sum >> 8u);
  }
  if (addend != 0u || bytes_are_zero(output, 16u)) {
    mesh_mgmt_crypto_wipe(output, 16u);
    return MESH_MGMT_AGENT_ROUTER_RESOURCE_EXHAUSTED;
  }
  router->next_connection_sequence++;
  return MESH_MGMT_AGENT_ROUTER_OK;
}

static void report_failure(mesh_mgmt_agent_router_v1_t *router,
                           mesh_mgmt_agent_router_slot_v1_t *slot, p2p_peer_t *peer,
                           mesh_mgmt_agent_router_result_t router_result,
                           mesh_mgmt_p2p_peer_result_t peer_result) {
  router->last_error = router_result;
  router->last_peer_result = peer_result;
  if (slot) {
    if (slot->failure_reported)
      return;
    slot->failure_reported = 1u;
  }
  if (router->on_failure)
    router->on_failure(router->callback_context, peer, router_result, peer_result);
}

static void retire_slot(mesh_mgmt_agent_router_v1_t *router,
                        mesh_mgmt_agent_router_slot_v1_t *slot) {
  if (!slot || !slot->active || slot->runtime.in_api)
    return;
  mesh_mgmt_p2p_peer_destroy_v1(&slot->runtime);
  mesh_mgmt_crypto_wipe(slot->remote_transport_peer_id, sizeof(slot->remote_transport_peer_id));
  mesh_mgmt_crypto_wipe(slot->connection_id, sizeof(slot->connection_id));
  memset(slot, 0, sizeof(*slot));
  if (router->active_peers > 0u)
    router->active_peers--;
}

static void report_closed(mesh_mgmt_agent_router_v1_t *router,
                          mesh_mgmt_agent_router_slot_v1_t *slot) {
  if (!slot || !slot->active || slot->close_reported)
    return;
  slot->close_reported = 1u;
  if (router->on_peer_closed) {
    router->on_peer_closed(router->callback_context, slot->peer, slot->remote_transport_peer_id,
                           slot->close_reason);
  }
}

static int route_event(void *context, const mesh_mgmt_dispatch_event_v1_t *event) {
  mesh_mgmt_agent_router_slot_v1_t *slot = (mesh_mgmt_agent_router_slot_v1_t *)context;
  mesh_mgmt_agent_router_v1_t *router;

  if (!slot || !event || !slot->active || !slot->router)
    return -1;
  router = slot->router;
  if (router->state != MESH_MGMT_AGENT_ROUTER_INSTALLED || !router->on_event)
    return -1;
  return router->on_event(router->callback_context, slot->peer, slot->remote_transport_peer_id,
                          event);
}

static mesh_mgmt_agent_router_result_t attach_peer(mesh_mgmt_agent_router_v1_t *router,
                                                   p2p_peer_t *peer) {
  mesh_mgmt_agent_router_slot_v1_t *slot;
  mesh_mgmt_p2p_peer_config_v1_t peer_config;
  mesh_mgmt_agent_router_result_t result;

  if (find_slot(router, peer))
    return MESH_MGMT_AGENT_ROUTER_DUPLICATE_PEER;
  slot = find_free_slot(router);
  if (!slot)
    return MESH_MGMT_AGENT_ROUTER_RESOURCE_EXHAUSTED;

  memset(slot, 0, sizeof(*slot));
  slot->router = router;
  slot->peer = peer;
  slot->active = 1u;
  slot->close_reason = MESH_MGMT_AGENT_ROUTER_CLOSE_TRANSPORT;
  router->active_peers++;

  result = next_connection_id(router, slot->connection_id);
  if (result != MESH_MGMT_AGENT_ROUTER_OK) {
    retire_slot(router, slot);
    return result;
  }

  memset(&peer_config, 0, sizeof(peer_config));
  peer_config.node = router->node;
  peer_config.peer = peer;
  peer_config.signer = *router->signer_template;
  peer_config.dispatch = *router->dispatch_template;
  memcpy(peer_config.signer.hello.connection_id, slot->connection_id,
         sizeof(peer_config.signer.hello.connection_id));
  memcpy(peer_config.dispatch.session.connection_id, slot->connection_id,
         sizeof(peer_config.dispatch.session.connection_id));
  peer_config.on_event = route_event;
  peer_config.event_context = slot;

  router->last_peer_result = mesh_mgmt_p2p_peer_init_v1(&slot->runtime, &peer_config);
  mesh_mgmt_crypto_wipe(&peer_config.signer, sizeof(peer_config.signer));
  if (router->last_peer_result != MESH_MGMT_P2P_PEER_OK) {
    retire_slot(router, slot);
    return MESH_MGMT_AGENT_ROUTER_PEER_FAILED;
  }
  memcpy(slot->remote_transport_peer_id, slot->runtime.adapter.remote_transport_peer_id,
         sizeof(slot->remote_transport_peer_id));

  router->last_peer_result = mesh_mgmt_p2p_peer_start_v1(&slot->runtime, router_now_ms(router));
  if (router->last_peer_result != MESH_MGMT_P2P_PEER_OK) {
    retire_slot(router, slot);
    return MESH_MGMT_AGENT_ROUTER_PEER_FAILED;
  }
  router->last_error = MESH_MGMT_AGENT_ROUTER_OK;
  return MESH_MGMT_AGENT_ROUTER_OK;
}

static void router_peer_connected(p2p_peer_t *peer, void *context) {
  mesh_mgmt_agent_router_v1_t *router = (mesh_mgmt_agent_router_v1_t *)context;
  mesh_mgmt_agent_router_result_t result;

  if (!router || !peer || router->state != MESH_MGMT_AGENT_ROUTER_INSTALLED)
    return;
  router->callback_depth++;
  result = attach_peer(router, peer);
  if (result != MESH_MGMT_AGENT_ROUTER_OK) {
    if (result != MESH_MGMT_AGENT_ROUTER_DUPLICATE_PEER)
      p2p_disconnect_peer(peer);
    report_failure(router, NULL, peer, result, router->last_peer_result);
  }
  router->callback_depth--;
}

static void router_peer_disconnected(p2p_peer_t *peer, void *context) {
  mesh_mgmt_agent_router_v1_t *router = (mesh_mgmt_agent_router_v1_t *)context;
  mesh_mgmt_agent_router_slot_v1_t *slot;

  if (!router || !peer || router->state != MESH_MGMT_AGENT_ROUTER_INSTALLED)
    return;
  router->callback_depth++;
  slot = find_slot(router, peer);
  if (slot) {
    report_closed(router, slot);
    if (router->callback_depth > 1u || slot->runtime.in_api)
      slot->disconnect_pending = 1u;
    else
      retire_slot(router, slot);
  }
  router->callback_depth--;
}

static void fail_and_disconnect(mesh_mgmt_agent_router_v1_t *router,
                                mesh_mgmt_agent_router_slot_v1_t *slot,
                                mesh_mgmt_agent_router_result_t result) {
  p2p_peer_t *peer = slot->peer;

  slot->close_reason = MESH_MGMT_AGENT_ROUTER_CLOSE_PROTOCOL;
  report_failure(router, slot, peer, result, slot->runtime.last_error);
  if (!slot->disconnect_pending)
    p2p_disconnect_peer(peer);
  if (slot->active) {
    report_closed(router, slot);
    retire_slot(router, slot);
  }
}

static void router_message(p2p_node_t *node, p2p_peer_t *peer, const void *bytes, size_t length,
                           void *context) {
  mesh_mgmt_agent_router_v1_t *router = (mesh_mgmt_agent_router_v1_t *)context;
  mesh_mgmt_agent_router_slot_v1_t *slot;

  if (!router || !node || !peer || !bytes || router->state != MESH_MGMT_AGENT_ROUTER_INSTALLED)
    return;
  router->callback_depth++;
  slot = find_slot(router, peer);
  if (!mesh_mgmt_p2p_message_is_mmp_v1(bytes, length)) {
    if (router->on_non_mmp)
      router->on_non_mmp(router->callback_context, node, peer, bytes, length);
    if (slot && slot->disconnect_pending)
      retire_slot(router, slot);
    router->callback_depth--;
    return;
  }
  if (!slot) {
    report_failure(router, NULL, peer, MESH_MGMT_AGENT_ROUTER_PEER_NOT_FOUND,
                   MESH_MGMT_P2P_PEER_INVALID_STATE);
    p2p_disconnect_peer(peer);
    router->callback_depth--;
    return;
  }

  router->last_peer_result =
      mesh_mgmt_p2p_peer_handle_message_v1(&slot->runtime, bytes, length, router_now_ms(router));
  if (router->last_peer_result != MESH_MGMT_P2P_PEER_OK) {
    fail_and_disconnect(router, slot, MESH_MGMT_AGENT_ROUTER_PEER_FAILED);
  } else if (slot->disconnect_pending) {
    retire_slot(router, slot);
  } else {
    router->last_error = MESH_MGMT_AGENT_ROUTER_OK;
  }
  router->callback_depth--;
}

static mesh_mgmt_agent_router_result_t validate_template(mesh_mgmt_agent_router_v1_t *router) {
  mesh_mgmt_peer_signer_config_v1_t signer_config = *router->signer_template;
  mesh_mgmt_dispatch_config_v1_t dispatch_config = *router->dispatch_template;
  mesh_mgmt_peer_signer_v1_t signer;
  mesh_mgmt_dispatcher_v1_t dispatcher;
  mesh_mgmt_dispatch_stage_t stage = MESH_MGMT_DISPATCH_STAGE_STRUCTURE;

  memset(&signer, 0, sizeof(signer));
  memset(&dispatcher, 0, sizeof(dispatcher));
  memcpy(signer_config.hello.connection_id, router->connection_namespace,
         sizeof(signer_config.hello.connection_id));
  memcpy(dispatch_config.session.connection_id, router->connection_namespace,
         sizeof(dispatch_config.session.connection_id));

  router->last_signer_result = mesh_mgmt_peer_signer_init_v1(&signer, &signer_config);
  mesh_mgmt_crypto_wipe(&signer_config, sizeof(signer_config));
  if (router->last_signer_result != MESH_MGMT_PEER_SIGNER_OK)
    return MESH_MGMT_AGENT_ROUTER_CONFIG_INVALID;
  mesh_mgmt_peer_signer_destroy_v1(&signer);

  router->last_dispatch_result =
      mesh_mgmt_dispatcher_init_v1(&dispatcher, &dispatch_config, &stage);
  mesh_mgmt_crypto_wipe(&dispatch_config, sizeof(dispatch_config));
  if (router->last_dispatch_result != MESH_MGMT_DISPATCH_OK)
    return MESH_MGMT_AGENT_ROUTER_CONFIG_INVALID;
  mesh_mgmt_dispatcher_destroy_v1(&dispatcher);
  return MESH_MGMT_AGENT_ROUTER_OK;
}

mesh_mgmt_agent_router_result_t
mesh_mgmt_agent_router_init_v1(mesh_mgmt_agent_router_v1_t *router,
                               const mesh_mgmt_agent_router_config_v1_t *config) {
  uint8_t local_transport_peer_id[P2P_KEY_SIZE];
  mesh_mgmt_agent_router_result_t result;

  if (!router || !config || !config->node || !config->signer_template ||
      !config->dispatch_template || !config->on_event || config->max_peers == 0u ||
      config->max_peers > MESH_MGMT_AGENT_ROUTER_MAX_PEERS)
    return MESH_MGMT_AGENT_ROUTER_INVALID_ARG;
  if (router->state != MESH_MGMT_AGENT_ROUTER_UNINITIALIZED || router->slots.data)
    return MESH_MGMT_AGENT_ROUTER_INVALID_STATE;

  memset(local_transport_peer_id, 0, sizeof(local_transport_peer_id));
  if (p2p_node_get_public_key(config->node, local_transport_peer_id) != P2P_OK ||
      !mesh_mgmt_crypto_equal_32(local_transport_peer_id,
                                 config->signer_template->local_transport_peer_id)) {
    mesh_mgmt_crypto_wipe(local_transport_peer_id, sizeof(local_transport_peer_id));
    return MESH_MGMT_AGENT_ROUTER_IDENTITY_MISMATCH;
  }
  mesh_mgmt_crypto_wipe(local_transport_peer_id, sizeof(local_transport_peer_id));

  memset(router, 0, sizeof(*router));
  router->node = config->node;
  router->signer_template = config->signer_template;
  router->dispatch_template = config->dispatch_template;
  router->random_bytes = config->random_bytes;
  router->random_context = config->random_context;
  router->on_event = config->on_event;
  router->on_non_mmp = config->on_non_mmp;
  router->on_failure = config->on_failure;
  router->on_peer_closed = config->on_peer_closed;
  router->callback_context = config->callback_context;
  router->max_peers = config->max_peers;
  router->next_connection_sequence = 1u;
  if (router_random(router, router->connection_namespace, sizeof(router->connection_namespace)) !=
          0 ||
      bytes_are_zero(router->connection_namespace, sizeof(router->connection_namespace))) {
    mesh_mgmt_crypto_wipe(router, sizeof(*router));
    return MESH_MGMT_AGENT_ROUTER_RANDOM_FAILED;
  }

  result = validate_template(router);
  if (result != MESH_MGMT_AGENT_ROUTER_OK) {
    mesh_mgmt_crypto_wipe(router, sizeof(*router));
    return result;
  }
  if (turbo_vec_init(&router->slots, sizeof(mesh_mgmt_agent_router_slot_v1_t)) != TURBO_OK ||
      turbo_vec_reserve(&router->slots, router->max_peers) != TURBO_OK ||
      turbo_vec_resize(&router->slots, router->max_peers) != TURBO_OK) {
    turbo_vec_destroy(&router->slots);
    mesh_mgmt_crypto_wipe(router, sizeof(*router));
    return MESH_MGMT_AGENT_ROUTER_RESOURCE_EXHAUSTED;
  }
  memset(turbo_vec_data(&router->slots), 0,
         router->max_peers * sizeof(mesh_mgmt_agent_router_slot_v1_t));
  router->state = MESH_MGMT_AGENT_ROUTER_READY;
  router->last_error = MESH_MGMT_AGENT_ROUTER_OK;
  router->last_peer_result = MESH_MGMT_P2P_PEER_OK;
  return MESH_MGMT_AGENT_ROUTER_OK;
}

mesh_mgmt_agent_router_result_t
mesh_mgmt_agent_router_install_v1(mesh_mgmt_agent_router_v1_t *router) {
  if (!router)
    return MESH_MGMT_AGENT_ROUTER_INVALID_ARG;
  if (router->state != MESH_MGMT_AGENT_ROUTER_READY || router->callback_depth != 0u)
    return MESH_MGMT_AGENT_ROUTER_INVALID_STATE;
  p2p_set_peer_callbacks(router->node, router_peer_connected, router_peer_disconnected, router);
  p2p_set_message_handler(router->node, router_message, router);
  router->state = MESH_MGMT_AGENT_ROUTER_INSTALLED;
  router->last_error = MESH_MGMT_AGENT_ROUTER_OK;
  return MESH_MGMT_AGENT_ROUTER_OK;
}

mesh_mgmt_agent_router_result_t
mesh_mgmt_agent_router_stop_v1(mesh_mgmt_agent_router_v1_t *router) {
  size_t index;

  if (!router)
    return MESH_MGMT_AGENT_ROUTER_INVALID_ARG;
  if (router->state != MESH_MGMT_AGENT_ROUTER_INSTALLED || router->callback_depth != 0u)
    return MESH_MGMT_AGENT_ROUTER_INVALID_STATE;

  for (index = 0u; index < router->max_peers; index++) {
    mesh_mgmt_agent_router_slot_v1_t *slot = slot_at(router, index);
    if (slot && slot->active) {
      slot->close_reason = MESH_MGMT_AGENT_ROUTER_CLOSE_LOCAL_STOP;
      p2p_disconnect_peer(slot->peer);
      if (slot->active) {
        report_closed(router, slot);
        retire_slot(router, slot);
      }
    }
  }
  p2p_set_message_handler(router->node, NULL, NULL);
  p2p_set_peer_callbacks(router->node, NULL, NULL, NULL);
  router->state = MESH_MGMT_AGENT_ROUTER_READY;
  router->last_error = MESH_MGMT_AGENT_ROUTER_OK;
  return MESH_MGMT_AGENT_ROUTER_OK;
}

void mesh_mgmt_agent_router_destroy_v1(mesh_mgmt_agent_router_v1_t *router) {
  size_t bytes;

  if (!router || router->callback_depth != 0u)
    return;
  if (router->state == MESH_MGMT_AGENT_ROUTER_INSTALLED &&
      mesh_mgmt_agent_router_stop_v1(router) != MESH_MGMT_AGENT_ROUTER_OK)
    return;
  if (router->slots.data) {
    bytes = turbo_vec_size(&router->slots) * sizeof(mesh_mgmt_agent_router_slot_v1_t);
    mesh_mgmt_crypto_wipe(turbo_vec_data(&router->slots), bytes);
    turbo_vec_destroy(&router->slots);
  }
  mesh_mgmt_crypto_wipe(router, sizeof(*router));
}

size_t mesh_mgmt_agent_router_active_peers_v1(const mesh_mgmt_agent_router_v1_t *router) {
  return router && router->state != MESH_MGMT_AGENT_ROUTER_UNINITIALIZED ? router->active_peers
                                                                         : 0u;
}

mesh_mgmt_agent_router_result_t
mesh_mgmt_agent_router_peer_snapshot_v1(const mesh_mgmt_agent_router_v1_t *router,
                                        const p2p_peer_t *peer,
                                        mesh_mgmt_agent_router_peer_snapshot_v1_t *out_snapshot) {
  size_t index;

  if (out_snapshot)
    memset(out_snapshot, 0, sizeof(*out_snapshot));
  if (!router || !peer || !out_snapshot)
    return MESH_MGMT_AGENT_ROUTER_INVALID_ARG;
  if (router->state == MESH_MGMT_AGENT_ROUTER_UNINITIALIZED)
    return MESH_MGMT_AGENT_ROUTER_INVALID_STATE;
  for (index = 0u; index < router->max_peers; index++) {
    const mesh_mgmt_agent_router_slot_v1_t *slot = slot_at_const(router, index);
    if (slot && slot->active && slot->peer == peer) {
      memcpy(out_snapshot->remote_transport_peer_id, slot->remote_transport_peer_id,
             sizeof(out_snapshot->remote_transport_peer_id));
      memcpy(out_snapshot->connection_id, slot->connection_id, sizeof(out_snapshot->connection_id));
      out_snapshot->runtime_state = slot->runtime.state;
      out_snapshot->session_state = slot->runtime.protocol_peer.connection.dispatcher.session.state;
      return MESH_MGMT_AGENT_ROUTER_OK;
    }
  }
  return MESH_MGMT_AGENT_ROUTER_PEER_NOT_FOUND;
}
