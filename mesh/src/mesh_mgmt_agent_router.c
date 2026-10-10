#include "mesh_mgmt_agent_router.h"

#include "mesh_mgmt_crypto.h"
#include "core/peer_cnet.h"

#include <salts/random.h>
#include <salts/clock.h>

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
  return (mesh_mgmt_agent_router_slot_v1_t *)vec_at(&router->slots, index);
}

static const mesh_mgmt_agent_router_slot_v1_t *
slot_at_const(const mesh_mgmt_agent_router_v1_t *router, size_t index) {
  return (const mesh_mgmt_agent_router_slot_v1_t *)vec_at_const(&router->slots, index);
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

static mesh_mgmt_agent_router_result_t find_execution_target(
    mesh_mgmt_agent_router_v1_t *router,
    const uint8_t target_node_id[32],
    mesh_mgmt_agent_router_slot_v1_t **out_slot) {
  mesh_mgmt_agent_router_slot_v1_t *matched_slot = NULL;
  size_t index;

  *out_slot = NULL;
  for (index = 0u; index < router->max_peers; ++index) {
    mesh_mgmt_agent_router_slot_v1_t *slot = slot_at(router, index);
    const mesh_mgmt_session_v1_t *session;

    if (!slot || !slot->active)
      continue;
    session = &slot->runtime.protocol_peer.connection.dispatcher.session;
    if (session->state != MESH_MGMT_SESSION_ESTABLISHED ||
        !session->remote_hello_verified ||
        !mesh_mgmt_crypto_equal_32(
            session->remote_certificate.managed_node_id, target_node_id))
      continue;
    if (matched_slot)
      return MESH_MGMT_AGENT_ROUTER_DUPLICATE_PEER;
    matched_slot = slot;
  }
  if (!matched_slot)
    return MESH_MGMT_AGENT_ROUTER_PEER_NOT_FOUND;
  *out_slot = matched_slot;
  return MESH_MGMT_AGENT_ROUTER_OK;
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
             : cmeta_realtime_ms();
}

static int router_random(mesh_mgmt_agent_router_v1_t *router, uint8_t *output, size_t output_len) {
  return router->random_bytes ? router->random_bytes(router->random_context, output, output_len)
                              : cmeta_platform_secure_random(output, output_len);
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

mesh_mgmt_agent_router_result_t mesh_mgmt_agent_router_offer_peer_connected_v1(
    mesh_mgmt_agent_router_v1_t *router, p2p_peer_t *peer) {
  mesh_mgmt_agent_router_result_t result;

  if (!router || !peer)
    return MESH_MGMT_AGENT_ROUTER_INVALID_ARG;
  if (router->state != MESH_MGMT_AGENT_ROUTER_INSTALLED)
    return MESH_MGMT_AGENT_ROUTER_INVALID_STATE;
  router->callback_depth++;
  result = attach_peer(router, peer);
  if (result != MESH_MGMT_AGENT_ROUTER_OK) {
    if (result != MESH_MGMT_AGENT_ROUTER_DUPLICATE_PEER)
      p2p_disconnect_peer(peer);
    report_failure(router, NULL, peer, result, router->last_peer_result);
  }
  router->callback_depth--;
  return result;
}

static void router_peer_connected(p2p_peer_t *peer, void *context) {
  (void)mesh_mgmt_agent_router_offer_peer_connected_v1(
      (mesh_mgmt_agent_router_v1_t *)context, peer);
}

mesh_mgmt_agent_router_result_t mesh_mgmt_agent_router_offer_peer_disconnected_v1(
    mesh_mgmt_agent_router_v1_t *router, p2p_peer_t *peer) {
  mesh_mgmt_agent_router_slot_v1_t *slot;
  mesh_mgmt_agent_router_result_t result = MESH_MGMT_AGENT_ROUTER_PEER_NOT_FOUND;

  if (!router || !peer)
    return MESH_MGMT_AGENT_ROUTER_INVALID_ARG;
  if (router->state != MESH_MGMT_AGENT_ROUTER_INSTALLED)
    return MESH_MGMT_AGENT_ROUTER_INVALID_STATE;
  router->callback_depth++;
  slot = find_slot(router, peer);
  if (slot) {
    result = MESH_MGMT_AGENT_ROUTER_OK;
    report_closed(router, slot);
    if (router->callback_depth > 1u || slot->runtime.in_api)
      slot->disconnect_pending = 1u;
    else
      retire_slot(router, slot);
  }
  router->callback_depth--;
  return result;
}

static void router_peer_disconnected(p2p_peer_t *peer, void *context) {
  (void)mesh_mgmt_agent_router_offer_peer_disconnected_v1(
      (mesh_mgmt_agent_router_v1_t *)context, peer);
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

mesh_mgmt_agent_router_result_t mesh_mgmt_agent_router_offer_message_v1(
    mesh_mgmt_agent_router_v1_t *router, p2p_node_t *node, p2p_peer_t *peer,
    const void *bytes, size_t length) {
  mesh_mgmt_agent_router_slot_v1_t *slot;

  if (!router || !node || !peer || !bytes || length == 0u || node != router->node)
    return MESH_MGMT_AGENT_ROUTER_INVALID_ARG;
  if (router->state != MESH_MGMT_AGENT_ROUTER_INSTALLED)
    return MESH_MGMT_AGENT_ROUTER_INVALID_STATE;
  if (!mesh_mgmt_p2p_message_is_mmp_v1(bytes, length))
    return MESH_MGMT_AGENT_ROUTER_NOT_MMP;

  router->callback_depth++;
  slot = find_slot(router, peer);
  if (!slot) {
    report_failure(router, NULL, peer, MESH_MGMT_AGENT_ROUTER_PEER_NOT_FOUND,
                   MESH_MGMT_P2P_PEER_INVALID_STATE);
    p2p_disconnect_peer(peer);
    router->callback_depth--;
    return MESH_MGMT_AGENT_ROUTER_PEER_NOT_FOUND;
  }

  router->last_peer_result =
      mesh_mgmt_p2p_peer_handle_message_v1(&slot->runtime, bytes, length, router_now_ms(router));
  if (router->last_peer_result != MESH_MGMT_P2P_PEER_OK) {
    fail_and_disconnect(router, slot, MESH_MGMT_AGENT_ROUTER_PEER_FAILED);
    router->callback_depth--;
    return MESH_MGMT_AGENT_ROUTER_PEER_FAILED;
  } else if (slot->disconnect_pending) {
    retire_slot(router, slot);
  } else {
    router->last_error = MESH_MGMT_AGENT_ROUTER_OK;
  }
  router->callback_depth--;
  return MESH_MGMT_AGENT_ROUTER_OK;
}

static void router_message(p2p_node_t *node, p2p_peer_t *peer, const void *bytes, size_t length,
                           void *context) {
  mesh_mgmt_agent_router_v1_t *router = (mesh_mgmt_agent_router_v1_t *)context;
  mesh_mgmt_agent_router_result_t result =
      mesh_mgmt_agent_router_offer_message_v1(router, node, peer, bytes, length);

  if (result == MESH_MGMT_AGENT_ROUTER_NOT_MMP && router && router->on_non_mmp)
    router->on_non_mmp(router->callback_context, node, peer, bytes, length);
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
  /* A template has no transport session yet. This sentinel validates all
   * remaining fields; mesh_mgmt_p2p_peer_init_v1 replaces it from the one
   * authenticated P2P security snapshot before either session is created. */
  memset(signer_config.hello.channel_binding, 0,
         sizeof(signer_config.hello.channel_binding));
  memset(dispatch_config.session.channel_binding, 0,
         sizeof(dispatch_config.session.channel_binding));
  signer_config.hello.channel_binding[0] = 1u;
  dispatch_config.session.channel_binding[0] = 1u;

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
  if (vec_init_bytes(&router->slots, sizeof(mesh_mgmt_agent_router_slot_v1_t),
                     _Alignof(mesh_mgmt_agent_router_slot_v1_t), router->max_peers) != STL_OK ||
      vec_reserve(&router->slots, router->max_peers) != STL_OK ||
      vec_resize(&router->slots, router->max_peers) != STL_OK) {
    vec_destroy(&router->slots);
    mesh_mgmt_crypto_wipe(router, sizeof(*router));
    return MESH_MGMT_AGENT_ROUTER_RESOURCE_EXHAUSTED;
  }
  memset(vec_data(&router->slots), 0,
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
  router->owns_callbacks = 1u;
  router->state = MESH_MGMT_AGENT_ROUTER_INSTALLED;
  router->last_error = MESH_MGMT_AGENT_ROUTER_OK;
  return MESH_MGMT_AGENT_ROUTER_OK;
}

mesh_mgmt_agent_router_result_t
mesh_mgmt_agent_router_start_embedded_v1(mesh_mgmt_agent_router_v1_t *router) {
  if (!router)
    return MESH_MGMT_AGENT_ROUTER_INVALID_ARG;
  if (router->state != MESH_MGMT_AGENT_ROUTER_READY || router->callback_depth != 0u)
    return MESH_MGMT_AGENT_ROUTER_INVALID_STATE;
  router->owns_callbacks = 0u;
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
      if (router->owns_callbacks)
        p2p_disconnect_peer(slot->peer);
      if (slot->active) {
        report_closed(router, slot);
        retire_slot(router, slot);
      }
    }
  }
  if (router->owns_callbacks) {
    p2p_set_message_handler(router->node, NULL, NULL);
    p2p_set_peer_callbacks(router->node, NULL, NULL, NULL);
  }
  router->owns_callbacks = 0u;
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
    bytes = vec_size(&router->slots) * sizeof(mesh_mgmt_agent_router_slot_v1_t);
    mesh_mgmt_crypto_wipe(vec_data(&router->slots), bytes);
    vec_destroy(&router->slots);
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

mesh_mgmt_agent_router_result_t mesh_mgmt_agent_router_identity_snapshot_v1(
    const mesh_mgmt_agent_router_v1_t *router, const uint8_t managed_node_id[32],
    mesh_mgmt_agent_router_identity_snapshot_v1_t *out_snapshot) {
  const mesh_mgmt_session_v1_t *matched_session = NULL;
  size_t index;

  if (out_snapshot)
    memset(out_snapshot, 0, sizeof(*out_snapshot));
  if (!router || !managed_node_id || !out_snapshot)
    return MESH_MGMT_AGENT_ROUTER_INVALID_ARG;
  if (router->state == MESH_MGMT_AGENT_ROUTER_UNINITIALIZED)
    return MESH_MGMT_AGENT_ROUTER_INVALID_STATE;

  for (index = 0u; index < router->max_peers; index++) {
    const mesh_mgmt_agent_router_slot_v1_t *slot = slot_at_const(router, index);
    const mesh_mgmt_session_v1_t *session;

    if (!slot || !slot->active)
      continue;
    session = &slot->runtime.protocol_peer.connection.dispatcher.session;
    if (session->state != MESH_MGMT_SESSION_ESTABLISHED ||
        !session->remote_hello_verified ||
        !mesh_mgmt_crypto_equal_32(session->remote_certificate.managed_node_id,
                                   managed_node_id))
      continue;
    if (matched_session)
      return MESH_MGMT_AGENT_ROUTER_DUPLICATE_PEER;
    matched_session = session;
  }
  if (!matched_session)
    return MESH_MGMT_AGENT_ROUTER_PEER_NOT_FOUND;

  memcpy(out_snapshot->managed_node_id, matched_session->remote_certificate.managed_node_id,
         sizeof(out_snapshot->managed_node_id));
  memcpy(out_snapshot->certificate, matched_session->remote_certificate_wire,
         sizeof(out_snapshot->certificate));
  out_snapshot->certificate_len = sizeof(out_snapshot->certificate);
  return MESH_MGMT_AGENT_ROUTER_OK;
}


/* Only the canonical, live and signed MMP session can attest READY for its
 * own peer. This has NO mutating side effect, no CNet Manager binding, no
 * ClientPool lease and no separate retry/lifecycle authority.
 * The Router is single-threaded and the caller is its Owner. */
mesh_mgmt_agent_router_result_t mesh_mgmt_agent_router_ready_session_v1(
    const mesh_mgmt_agent_router_v1_t *router, const p2p_peer_t *peer,
    const uint8_t expected_transport_peer_id[P2P_KEY_SIZE],
    const uint8_t expected_managed_node_id[32],
    const uint8_t expected_connection_id[16],
    mesh_mgmt_agent_router_ready_v1_t *out_ready) {
  const mesh_mgmt_agent_router_slot_v1_t *target = NULL;
  const mesh_mgmt_session_v1_t *session;
  size_t matching_identity = 0u;

  if (out_ready) memset(out_ready, 0, sizeof(*out_ready));
  if (!router || !peer || !expected_transport_peer_id ||
      !expected_managed_node_id || !out_ready ||
      bytes_are_zero(expected_transport_peer_id, P2P_KEY_SIZE) ||
      bytes_are_zero(expected_managed_node_id, 32u))
    return MESH_MGMT_AGENT_ROUTER_INVALID_ARG;
  if (router->state != MESH_MGMT_AGENT_ROUTER_INSTALLED)
    return MESH_MGMT_AGENT_ROUTER_INVALID_STATE;

  for (size_t i = 0u; i < router->max_peers; ++i) {
    const mesh_mgmt_agent_router_slot_v1_t *slot = slot_at_const(router, i);
    const mesh_mgmt_session_v1_t *candidate;
    if (!slot || !slot->active) continue;
    if (slot->peer == peer) target = slot;
    candidate = &slot->runtime.protocol_peer.connection.dispatcher.session;
    if (slot->runtime.state != MESH_MGMT_P2P_PEER_READY ||
        slot->disconnect_pending || slot->failure_reported ||
        slot->close_reported ||
        candidate->state != MESH_MGMT_SESSION_ESTABLISHED ||
        !candidate->remote_hello_verified)
      continue;
    if (mesh_mgmt_crypto_equal_32(
            candidate->remote_certificate.managed_node_id,
            expected_managed_node_id))
      ++matching_identity;
  }
  if (!target) return MESH_MGMT_AGENT_ROUTER_PEER_NOT_FOUND;
  if (target->runtime.state != MESH_MGMT_P2P_PEER_READY ||
      target->disconnect_pending || target->failure_reported ||
      target->close_reported)
    return MESH_MGMT_AGENT_ROUTER_INVALID_STATE;

  session = &target->runtime.protocol_peer.connection.dispatcher.session;
  if (session->state != MESH_MGMT_SESSION_ESTABLISHED ||
      !session->remote_hello_verified)
    return MESH_MGMT_AGENT_ROUTER_INVALID_STATE;
  if (matching_identity > 1u)
    return MESH_MGMT_AGENT_ROUTER_DUPLICATE_PEER;
  if (matching_identity != 1u ||
      !mesh_mgmt_crypto_equal_32(target->remote_transport_peer_id,
                                 expected_transport_peer_id) ||
      !mesh_mgmt_crypto_equal_32(
          session->remote_certificate.transport_peer_id,
          expected_transport_peer_id) ||
      !mesh_mgmt_crypto_equal_32(
          session->remote_certificate.managed_node_id,
          expected_managed_node_id) ||
      bytes_are_zero(target->connection_id, sizeof(target->connection_id)) ||
      (expected_connection_id &&
       memcmp(expected_connection_id, target->connection_id,
              sizeof(target->connection_id)) != 0))
    return MESH_MGMT_AGENT_ROUTER_IDENTITY_MISMATCH;

  out_ready->size = sizeof(*out_ready);
  out_ready->version = MESH_MGMT_AGENT_ROUTER_READY_VERSION;
  memcpy(out_ready->remote_transport_peer_id, expected_transport_peer_id,
         sizeof(out_ready->remote_transport_peer_id));
  memcpy(out_ready->remote_managed_node_id, expected_managed_node_id,
         sizeof(out_ready->remote_managed_node_id));
  memcpy(out_ready->connection_id, target->connection_id,
         sizeof(out_ready->connection_id));
  memcpy(out_ready->remote_session_id, session->remote_session_id,
         sizeof(out_ready->remote_session_id));
  out_ready->remote_incarnation = session->remote_incarnation;
  return MESH_MGMT_AGENT_ROUTER_OK;
}

mesh_mgmt_agent_router_result_t mesh_mgmt_agent_router_physical_ready_v1(
    const mesh_mgmt_agent_router_v1_t *router, const p2p_peer_t *peer,
    const uint8_t expected_transport_peer_id[P2P_KEY_SIZE],
    const uint8_t expected_managed_node_id[32],
    const uint8_t expected_connection_id[16],
    cnet_manager *expected_manager,
    mesh_mgmt_agent_router_physical_ready_v1_t *out_ready) {
  mesh_mgmt_agent_router_ready_v1_t signed_session = {0};
  p2p_cnet_managed_binding_v1_t physical = {0};
  mesh_mgmt_agent_router_result_t status;

  if (out_ready) memset(out_ready, 0, sizeof(*out_ready));
  if (!out_ready || !expected_manager)
    return MESH_MGMT_AGENT_ROUTER_INVALID_ARG;
  status = mesh_mgmt_agent_router_ready_session_v1(
      router, peer, expected_transport_peer_id,
      expected_managed_node_id, expected_connection_id, &signed_session);
  if (status != MESH_MGMT_AGENT_ROUTER_OK) return status;
  /* Signed READY is a necessary proof, NOT a physical association.
   * This call traverses only that live peer's actual P2P transport, checks
   * the exact CNet Manager BOUND generation and physical handle, and
   * rejects any independently cohosted client or unmanaged outbound path. */
  if (p2p_peer_cnet_managed_binding_v1(peer, &physical) != P2P_OK ||
      physical.version != P2P_CNET_MANAGED_BINDING_VERSION)
    return MESH_MGMT_AGENT_ROUTER_INVALID_STATE;
  if (physical.manager != expected_manager)
    return MESH_MGMT_AGENT_ROUTER_IDENTITY_MISMATCH;
  out_ready->size = sizeof(*out_ready);
  out_ready->version = MESH_MGMT_AGENT_ROUTER_PHYSICAL_READY_VERSION;
  out_ready->signed_session = signed_session;
  out_ready->manager = physical.manager;
  out_ready->managed = physical.managed;
  out_ready->physical = physical.physical;
  return MESH_MGMT_AGENT_ROUTER_OK;
}


/* Domain-separated 64-bit host key projection from authenticated signed
 * session facts. Hash-to-64 is a compact CNet Pool compatibility key, not a
 * cryptographic signature or an authorization system of its own. Full signed
 * proof and CNet Manager generation are rechecked on each acquisition.
 * Do not use raw pointers, secrets or hostname-only shortcuts as identities. */
static int pool_fact64(uint8_t domain, const uint8_t *data, size_t length,
                       uint64_t *out) {
  uint8_t message[1u + 32u] = {0}, digest[32] = {0};
  uint64_t value = 0u;
  if (!data || !length || length > 32u || !out) return 0;
  message[0] = domain;
  memcpy(message + 1u, data, length);
  if (mesh_mgmt_blake2b_256(message, length + 1u, digest) != MESH_MGMT_CRYPTO_OK)
    return 0;
  for (size_t i = 0u; i < 8u; ++i)
    value = (value << 8u) | (uint64_t)digest[i];
  mesh_mgmt_crypto_wipe(digest, sizeof(digest));
  if (!value) return 0; /* fail fast on impossible-looking identity */
  *out = value;
  return 1;
}

static int pool_key_from_signed_ready(
    const mesh_mgmt_agent_router_v1_t *router,
    const mesh_mgmt_agent_router_physical_ready_v1_t *ready,
    uint64_t owner_id, cnet_pool_key *out_key) {
  uint8_t session_generation[24] = {0};
  cnet_pool_key key = {0};
  if (!router || !router->signer_template || !router->dispatch_template ||
      !ready || ready->version != MESH_MGMT_AGENT_ROUTER_PHYSICAL_READY_VERSION ||
      owner_id == 0u || !out_key)
    return 0;
  key.size = sizeof(key);
  key.version = CNET_CLIENT_POOL_VERSION;
  key.owner_id = owner_id;
  key.protocol_id = UINT64_C(0x4d4d505f76310001); /* MMP_v1 only */
  /* runtime, Owner and endpoint are independent identity domains. */
  if (!pool_fact64('r', router->connection_namespace,
                   sizeof(router->connection_namespace), &key.runtime_id) ||
      !pool_fact64('e', ready->signed_session.remote_managed_node_id,
                   32u, &key.endpoint_id) ||
      !pool_fact64('g', ready->signed_session.connection_id,
                   16u, &key.peer_generation) ||
      !pool_fact64('a',
                   router->dispatch_template->session.trusted_issuer_key,
                   32u, &key.authority_id) ||
      !pool_fact64('t', ready->signed_session.remote_transport_peer_id,
                   32u, &key.transport_id) ||
      !pool_fact64('l',
                   router->signer_template->hello.managed_node_id,
                   32u, &key.client_identity_id))
    return 0;
  memcpy(session_generation, ready->signed_session.remote_session_id, 16u);
  for (size_t i = 0u; i < 8u; ++i)
    session_generation[16u + i] =
        (uint8_t)(ready->signed_session.remote_incarnation >> (56u - 8u * i));
  if (!pool_fact64('s', session_generation, sizeof(session_generation),
                   &key.session_id))
    return 0;
  /* Noise transport is neither TLS nor TLS ALPN/SNI. All three TLS
   * identity fields remain 0 by protocol design, not an omitted check. */
  *out_key = key;
  return 1;
}

static mesh_mgmt_agent_router_result_t pool_admission_error(int error) {
  if (error == SALTS_ENOBUFS || error == SALTS_ENOMEM)
    return MESH_MGMT_AGENT_ROUTER_RESOURCE_EXHAUSTED;
  if (error == SALTS_EINVAL || error == SALTS_ERANGE)
    return MESH_MGMT_AGENT_ROUTER_CONFIG_INVALID;
  return MESH_MGMT_AGENT_ROUTER_INVALID_STATE;
}

static int same_managed_identity(cnet_managed_connection a,
                                 cnet_managed_connection b) {
  return a.manager == b.manager && a.incarnation == b.incarnation &&
         a.generation == b.generation && a.slot == b.slot;
}

mesh_mgmt_agent_router_result_t mesh_mgmt_agent_router_pool_bind_ready_v1(
    const mesh_mgmt_agent_router_v1_t *router, const p2p_peer_t *peer,
    const uint8_t expected_transport_peer_id[P2P_KEY_SIZE],
    const uint8_t expected_managed_node_id[32],
    const uint8_t expected_connection_id[16],
    cnet_manager *manager, cnet_client_pool *pool, uint64_t owner_id,
    cnet_pool_connection *out_physical, cnet_pool_key *out_key) {
  mesh_mgmt_agent_router_physical_ready_v1_t ready = {0}, rechecked = {0};
  cnet_pool_connection physical = {0};
  cnet_pool_key key = {0};
  mesh_mgmt_agent_router_result_t result;
  int status;
  if (out_physical) *out_physical = (cnet_pool_connection){0};
  if (out_key) *out_key = (cnet_pool_key){0};
  if (!pool || !manager || !out_physical || !out_key || owner_id == 0u)
    return MESH_MGMT_AGENT_ROUTER_INVALID_ARG;
  result = mesh_mgmt_agent_router_physical_ready_v1(
      router, peer, expected_transport_peer_id,
      expected_managed_node_id, expected_connection_id, manager, &ready);
  if (result != MESH_MGMT_AGENT_ROUTER_OK) return result;
  if (!pool_key_from_signed_ready(router, &ready, owner_id, &key))
    return MESH_MGMT_AGENT_ROUTER_CONFIG_INVALID;

  /* Incoming address/authority is unknown before signed HELLO; the
   * *physical* P2P Manager bounded it prior to Noise. Allocate this
   * security-partitioned CNet Pool record only after authentication. */
  status = cnet_pool_reserve_connecting(pool, &key, &physical);
  if (status != SALTS_OK) return pool_admission_error(status);
  /* No other Router/Owner callback or physical CNet progression occurs
   * between the two attestation checks, pool reservation and bind. */
  result = mesh_mgmt_agent_router_physical_ready_v1(
      router, peer, expected_transport_peer_id,
      expected_managed_node_id, ready.signed_session.connection_id,
      manager, &rechecked);
  if (result == MESH_MGMT_AGENT_ROUTER_OK &&
      !same_managed_identity(rechecked.managed, ready.managed))
    result = MESH_MGMT_AGENT_ROUTER_IDENTITY_MISMATCH;
  if (result != MESH_MGMT_AGENT_ROUTER_OK) {
    if (cnet_pool_terminal(pool, physical) != SALTS_OK)
      return MESH_MGMT_AGENT_ROUTER_INVALID_STATE;
    return result;
  }
  status = cnet_pool_bind_ready(pool, physical, rechecked.managed, 1u);
  if (status != SALTS_OK) {
    if (cnet_pool_terminal(pool, physical) != SALTS_OK)
      return MESH_MGMT_AGENT_ROUTER_INVALID_STATE;
    return pool_admission_error(status);
  }
  *out_physical = physical;
  *out_key = key;
  return MESH_MGMT_AGENT_ROUTER_OK;
}

mesh_mgmt_agent_router_result_t mesh_mgmt_agent_router_pool_acquire_v1(
    const mesh_mgmt_agent_router_v1_t *router, const p2p_peer_t *peer,
    const uint8_t expected_transport_peer_id[P2P_KEY_SIZE],
    const uint8_t expected_managed_node_id[32],
    const uint8_t expected_connection_id[16],
    cnet_manager *manager, cnet_client_pool *pool, uint64_t owner_id,
    cnet_pool_lease *out_lease) {
  mesh_mgmt_agent_router_physical_ready_v1_t ready = {0};
  cnet_managed_connection leased = {0};
  cnet_pool_lease lease = {0};
  cnet_pool_key key = {0};
  mesh_mgmt_agent_router_result_t result;
  int status;
  if (out_lease) *out_lease = (cnet_pool_lease){0};
  if (!pool || !manager || !out_lease || !owner_id)
    return MESH_MGMT_AGENT_ROUTER_INVALID_ARG;
  result = mesh_mgmt_agent_router_physical_ready_v1(
      router, peer, expected_transport_peer_id,
      expected_managed_node_id, expected_connection_id, manager, &ready);
  if (result != MESH_MGMT_AGENT_ROUTER_OK) return result;
  if (!pool_key_from_signed_ready(router, &ready, owner_id, &key))
    return MESH_MGMT_AGENT_ROUTER_CONFIG_INVALID;
  status = cnet_pool_try_acquire(pool, &key, NULL, &lease, &leased);
  if (status != SALTS_OK) return pool_admission_error(status);
  if (!same_managed_identity(ready.managed, leased)) {
    if (cnet_pool_release(pool, lease) != SALTS_OK)
      return MESH_MGMT_AGENT_ROUTER_INVALID_STATE;
    return MESH_MGMT_AGENT_ROUTER_IDENTITY_MISMATCH;
  }
  *out_lease = lease;
  return MESH_MGMT_AGENT_ROUTER_OK;
}

mesh_mgmt_execution_consumer_result_t
mesh_mgmt_agent_router_execution_command_from_event_v1(
    mesh_mgmt_agent_router_v1_t *router,
    p2p_peer_t *peer,
    const mesh_mgmt_dispatch_event_v1_t *event,
    uint64_t now_ms,
    mesh_mgmt_execution_shadow_command_v1_t *out_command) {
  mesh_mgmt_agent_router_slot_v1_t *slot;

  if (!router || !peer || !event || !out_command || now_ms == 0u)
    return MESH_MGMT_EXECUTION_CONSUMER_INVALID_ARG;
  if (router->state != MESH_MGMT_AGENT_ROUTER_INSTALLED ||
      router->callback_depth == 0u)
    return MESH_MGMT_EXECUTION_CONSUMER_INVALID_STATE;
  slot = find_slot(router, peer);
  if (!slot)
    return MESH_MGMT_EXECUTION_CONSUMER_INVALID_STATE;
  return mesh_mgmt_execution_shadow_command_from_event_v1(
      &slot->runtime.protocol_peer.connection.dispatcher, event, now_ms,
      out_command);
}

mesh_mgmt_execution_disabled_responder_result_t
mesh_mgmt_agent_router_send_execution_status_from_command_v1(
    mesh_mgmt_agent_router_v1_t *router,
    p2p_peer_t *peer,
    const mesh_mgmt_execution_shadow_command_v1_t *command,
    uint16_t status_code) {
  mesh_mgmt_agent_router_slot_v1_t *slot;

  if (!router || !peer || !command)
    return MESH_MGMT_EXECUTION_DISABLED_RESPONDER_INVALID_ARG;
  if (router->state != MESH_MGMT_AGENT_ROUTER_INSTALLED ||
      router->callback_depth == 0u)
    return MESH_MGMT_EXECUTION_DISABLED_RESPONDER_INVALID_STATE;
  slot = find_slot(router, peer);
  if (!slot)
    return MESH_MGMT_EXECUTION_DISABLED_RESPONDER_INVALID_STATE;
  return mesh_mgmt_execution_status_response_from_command_v1(
      command, status_code, &slot->runtime.signer,
      &slot->runtime.protocol_peer.connection);
}

mesh_mgmt_execution_response_consumer_result_t
mesh_mgmt_agent_router_execution_response_from_event_v1(
    mesh_mgmt_agent_router_v1_t *router,
    p2p_peer_t *peer,
    const mesh_mgmt_dispatch_event_v1_t *event,
    mesh_mgmt_execution_response_v1_t *out_response) {
  mesh_mgmt_agent_router_slot_v1_t *slot;

  if (!router || !peer || !event || !out_response)
    return MESH_MGMT_EXECUTION_RESPONSE_CONSUMER_INVALID_ARG;
  if (router->state != MESH_MGMT_AGENT_ROUTER_INSTALLED)
    return MESH_MGMT_EXECUTION_RESPONSE_CONSUMER_INVALID_STATE;
  slot = find_slot(router, peer);
  if (!slot)
    return MESH_MGMT_EXECUTION_RESPONSE_CONSUMER_INVALID_STATE;
  return mesh_mgmt_execution_response_from_event_v1(
      &slot->runtime.protocol_peer.connection.dispatcher, event,
      out_response);
}

mesh_mgmt_execution_disabled_responder_result_t
mesh_mgmt_agent_router_send_execution_disabled_from_event_v1(
    mesh_mgmt_agent_router_v1_t *router,
    p2p_peer_t *peer,
    const mesh_mgmt_dispatch_event_v1_t *event,
    uint64_t now_ms) {
  mesh_mgmt_agent_router_slot_v1_t *slot;

  if (!router || !peer || !event || now_ms == 0u)
    return MESH_MGMT_EXECUTION_DISABLED_RESPONDER_INVALID_ARG;
  if (router->state != MESH_MGMT_AGENT_ROUTER_INSTALLED)
    return MESH_MGMT_EXECUTION_DISABLED_RESPONDER_INVALID_STATE;
  slot = find_slot(router, peer);
  if (!slot)
    return MESH_MGMT_EXECUTION_DISABLED_RESPONDER_INVALID_STATE;
  return mesh_mgmt_execution_disabled_response_from_event_v1(
      &slot->runtime.protocol_peer.connection.dispatcher, event, now_ms,
      &slot->runtime.signer, &slot->runtime.protocol_peer.connection);
}

mesh_mgmt_agent_router_result_t
mesh_mgmt_agent_router_send_execution_request_v1(
    mesh_mgmt_agent_router_v1_t *router,
    const uint8_t target_node_id[32],
    const uint8_t *payload,
    size_t payload_len) {
  mesh_mgmt_agent_router_slot_v1_t *matched_slot = NULL;
  mesh_mgmt_agent_router_result_t find_result;

  if (!router || !target_node_id || !payload || payload_len == 0u)
    return MESH_MGMT_AGENT_ROUTER_INVALID_ARG;
  if (router->state != MESH_MGMT_AGENT_ROUTER_INSTALLED ||
      router->callback_depth != 0u)
    return MESH_MGMT_AGENT_ROUTER_INVALID_STATE;

  find_result = find_execution_target(router, target_node_id, &matched_slot);
  if (find_result != MESH_MGMT_AGENT_ROUTER_OK)
    return find_result;

  router->last_peer_result = mesh_mgmt_p2p_peer_send_execution_request_v1(
      &matched_slot->runtime, target_node_id, payload, payload_len);
  if (router->last_peer_result != MESH_MGMT_P2P_PEER_OK) {
    router->last_error = MESH_MGMT_AGENT_ROUTER_PEER_FAILED;
    return router->last_error;
  }
  router->last_error = MESH_MGMT_AGENT_ROUTER_OK;
  return MESH_MGMT_AGENT_ROUTER_OK;
}

mesh_mgmt_agent_router_result_t
mesh_mgmt_agent_router_send_execution_response_v1(
    mesh_mgmt_agent_router_v1_t *router,
    uint8_t kind,
    const uint8_t target_node_id[32],
    const uint8_t *payload,
    size_t payload_len) {
  mesh_mgmt_agent_router_slot_v1_t *matched_slot = NULL;
  mesh_mgmt_agent_router_result_t find_result;

  if (!router || !target_node_id || !payload || payload_len == 0u ||
      (kind != MESH_MGMT_KIND_COMMAND_RESULT &&
       kind != MESH_MGMT_KIND_COMMAND_STATUS))
    return MESH_MGMT_AGENT_ROUTER_INVALID_ARG;
  if (router->state != MESH_MGMT_AGENT_ROUTER_INSTALLED ||
      router->callback_depth != 0u)
    return MESH_MGMT_AGENT_ROUTER_INVALID_STATE;

  find_result = find_execution_target(router, target_node_id, &matched_slot);
  if (find_result != MESH_MGMT_AGENT_ROUTER_OK)
    return find_result;
  router->last_peer_result = mesh_mgmt_p2p_peer_send_execution_response_v1(
      &matched_slot->runtime, kind, target_node_id, payload, payload_len);
  if (router->last_peer_result != MESH_MGMT_P2P_PEER_OK) {
    router->last_error = MESH_MGMT_AGENT_ROUTER_PEER_FAILED;
    return router->last_error;
  }
  router->last_error = MESH_MGMT_AGENT_ROUTER_OK;
  return MESH_MGMT_AGENT_ROUTER_OK;
}
