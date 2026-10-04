#include "mesh_mgmt_cnet_peer.h"
#include "mesh_mgmt_crypto.h"
#include <string.h>

static int same_connection(cnet_connection a, cnet_connection b) {
  return a.slot == b.slot && a.generation == b.generation;
}

static int export_binding(cnet_client *client, cnet_connection connection, uint8_t output[32]) {
  static const char required[] = "TLSv1.3";
  char version[sizeof(required)] = {0};
  size_t length = 0u;
  int result = cnet_tls_negotiated_version(client, connection, version, sizeof(version), &length);
  if (result != SALTS_OK)
    return result;
  if (length != sizeof(required) - 1u || memcmp(version, required, sizeof(required)) != 0)
    return SALTS_ENOTSUP;
  return cnet_tls_export_channel_binding(client, connection, output);
}

static int validate_binding(mesh_mgmt_cnet_peer_v1_t *owner) {
  uint8_t current[32] = {0};
  int result = export_binding(owner->client, owner->connection, current);
  if (result == SALTS_OK && !mesh_mgmt_crypto_equal_32(current, owner->channel_binding))
    result = SALTS_EINVAL;
  mesh_mgmt_crypto_wipe(current, sizeof(current));
  owner->last_cnet_status = result;
  return result;
}

static mesh_mgmt_peer_result_t fail_owner(mesh_mgmt_cnet_peer_v1_t *owner) {
  if (owner->peer.state == MESH_MGMT_PEER_READY)
    (void)mesh_mgmt_peer_abort_v1(&owner->peer);
  owner->pending_token = 0u;
  owner->pending_bytes = 0u;
  if (!owner->close_requested && !owner->terminal_observed) {
    int result = cnet_close(owner->client, owner->connection);
    if (result == SALTS_OK)
      owner->close_requested = 1;
    else
      owner->last_cnet_status = result;
  }
  return MESH_MGMT_PEER_CONNECTION_FAILED;
}

static int recv_chunk(void *context, uint8_t **bytes, size_t *len) {
  mesh_mgmt_cnet_peer_v1_t *owner = context;
  *bytes = NULL;
  *len = 0u;
  if (!owner->chunk_len)
    return MESH_MGMT_TRANSPORT_PENDING;
  if (owner->chunk_borrowed)
    return MESH_MGMT_TRANSPORT_INVALID_STATE;
  *bytes = owner->chunk;
  *len = owner->chunk_len;
  owner->chunk_borrowed = 1;
  return MESH_MGMT_TRANSPORT_OK;
}

static void release_chunk(void *context, uint8_t *bytes) {
  mesh_mgmt_cnet_peer_v1_t *owner = context;
  if (bytes == owner->chunk) {
    memset(owner->chunk, 0, owner->chunk_len);
    owner->chunk_len = 0u;
    owner->chunk_borrowed = 0;
  }
}

static int admit(void *context, const uint8_t *bytes, size_t len, uint64_t token) {
  mesh_mgmt_cnet_peer_v1_t *owner = context;
  mem_buffer_t *buffer;
  int result;
  if (owner->pending_token || validate_binding(owner) != SALTS_OK)
    return MESH_MGMT_TRANSPORT_IO_FAILED;
  buffer = mem_get_buffer(mem_global(), len);
  if (!buffer) {
    owner->last_cnet_status = SALTS_ENOMEM;
    return MESH_MGMT_TRANSPORT_RESOURCE_EXHAUSTED;
  }
  memcpy(mem_buffer_data(buffer), bytes, len);
  mem_set_used(buffer, len);
  result = cnet_send_buffer(owner->client, owner->connection, buffer);
  mem_buffer_release(buffer);
  owner->last_cnet_status = result;
  if (result != SALTS_OK)
    return MESH_MGMT_TRANSPORT_IO_FAILED;
  owner->pending_token = token;
  owner->pending_bytes = len;
  return MESH_MGMT_TRANSPORT_OK;
}

static mesh_mgmt_peer_result_t drain(mesh_mgmt_cnet_peer_v1_t *owner, uint64_t now_ms) {
  mesh_mgmt_peer_result_t result;
  do {
    result = mesh_mgmt_peer_pump_once_v1(&owner->peer, now_ms);
  } while (result == MESH_MGMT_PEER_OK);
  if (result != MESH_MGMT_PEER_PENDING)
    return fail_owner(owner);
  if (!owner->pending_token && !owner->chunk_len && !owner->receive_pending) {
    owner->last_cnet_status = cnet_receive(owner->client, owner->connection, 1u);
    if (owner->last_cnet_status != SALTS_OK)
      return fail_owner(owner);
    owner->receive_pending = 1;
  }
  return MESH_MGMT_PEER_PENDING;
}

mesh_mgmt_peer_result_t mesh_mgmt_cnet_peer_init_v1(
    mesh_mgmt_cnet_peer_v1_t *owner, cnet_client *client, cnet_connection connection,
    const mesh_mgmt_cnet_peer_config_v1_t *config) {
  mesh_mgmt_peer_config_v1_t peer_config = {0};
  mesh_mgmt_peer_signer_config_v1_t signer_config;
  mesh_mgmt_transport_async_io_v1_t io = {0};
  mesh_mgmt_peer_result_t result;
  if (!owner || !client || !client->impl || !config || !config->on_event)
    return MESH_MGMT_PEER_INVALID_ARG;
  if (owner->initialized || owner->client)
    return MESH_MGMT_PEER_INVALID_STATE;
  owner->last_cnet_status = export_binding(client, connection, owner->channel_binding);
  if (owner->last_cnet_status != SALTS_OK)
    return MESH_MGMT_PEER_CONNECTION_FAILED;
  signer_config = config->signer;
  memcpy(signer_config.hello.channel_binding, owner->channel_binding, sizeof(owner->channel_binding));
  if (mesh_mgmt_peer_signer_init_v1(&owner->signer, &signer_config) != MESH_MGMT_PEER_SIGNER_OK) {
    mesh_mgmt_crypto_wipe(&signer_config, sizeof(signer_config));
    mesh_mgmt_crypto_wipe(owner->channel_binding, sizeof(owner->channel_binding));
    return MESH_MGMT_PEER_BUILD_FAILED;
  }
  mesh_mgmt_crypto_wipe(&signer_config, sizeof(signer_config));
  owner->client = client;
  owner->connection = connection;
  peer_config.connection.dispatch = config->dispatch;
  memcpy(peer_config.connection.dispatch.session.channel_binding, owner->channel_binding,
         sizeof(owner->channel_binding));
  memcpy(peer_config.connection.transport_peer_id, config->remote_transport_peer_id,
         sizeof(peer_config.connection.transport_peer_id));
  peer_config.connection.on_event = config->on_event;
  peer_config.connection.event_context = config->event_context;
  memcpy(peer_config.local_transport_peer_id, config->signer.local_transport_peer_id,
         sizeof(peer_config.local_transport_peer_id));
  peer_config.build_hello = mesh_mgmt_peer_signer_build_hello_v1;
  peer_config.build_ack = mesh_mgmt_peer_signer_build_ack_v1;
  peer_config.builder_context = &owner->signer;
  io.context = owner;
  io.recv = recv_chunk;
  io.release = release_chunk;
  io.send = admit;
  result = mesh_mgmt_peer_init_async_v1(&owner->peer, &peer_config, &io);
  if (result != MESH_MGMT_PEER_OK) {
    mesh_mgmt_peer_signer_destroy_v1(&owner->signer);
    memset(owner, 0, sizeof(*owner));
    return result;
  }
  owner->initialized = 1;
  return MESH_MGMT_PEER_OK;
}

mesh_mgmt_peer_result_t mesh_mgmt_cnet_peer_start_v1(mesh_mgmt_cnet_peer_v1_t *owner, uint64_t now_ms) {
  mesh_mgmt_peer_result_t result;
  if (!owner || !owner->initialized || owner->in_callback || owner->close_requested)
    return MESH_MGMT_PEER_INVALID_STATE;
  if (validate_binding(owner) != SALTS_OK)
    return fail_owner(owner);
  owner->in_callback = 1;
  result = mesh_mgmt_peer_start_v1(&owner->peer, now_ms);
  owner->in_callback = 0;
  return result == MESH_MGMT_PEER_PENDING ? result : fail_owner(owner);
}

mesh_mgmt_peer_result_t mesh_mgmt_cnet_peer_on_receive_v1(
    mesh_mgmt_cnet_peer_v1_t *owner, cnet_connection connection,
    const cnet_receive_view *view, uint64_t now_ms) {
  mesh_mgmt_peer_result_t result;
  if (!owner || !owner->initialized || owner->in_callback ||
      !same_connection(connection, owner->connection))
    return MESH_MGMT_PEER_INVALID_STATE;
  if (owner->close_requested || owner->terminal_observed)
    return MESH_MGMT_PEER_INVALID_STATE;
  if (!view || !view->data || !view->size || view->kind != CNET_MESSAGE_BYTES ||
      view->size > sizeof(owner->chunk) || owner->chunk_len || !owner->receive_pending ||
      validate_binding(owner) != SALTS_OK)
    return fail_owner(owner);
  owner->receive_pending = 0;
  memcpy(owner->chunk, view->data, view->size);
  owner->chunk_len = view->size;
  owner->in_callback = 1;
  result = drain(owner, now_ms);
  owner->in_callback = 0;
  return result;
}

mesh_mgmt_peer_result_t mesh_mgmt_cnet_peer_on_send_v1(
    mesh_mgmt_cnet_peer_v1_t *owner, cnet_connection connection, size_t bytes, uint64_t now_ms) {
  mesh_mgmt_peer_result_t result;
  uint64_t token;
  if (!owner || !owner->initialized || owner->in_callback ||
      !same_connection(connection, owner->connection))
    return MESH_MGMT_PEER_INVALID_STATE;
  if (owner->close_requested || owner->terminal_observed)
    return MESH_MGMT_PEER_INVALID_STATE;
  if (!owner->pending_token || bytes != owner->pending_bytes || validate_binding(owner) != SALTS_OK)
    return fail_owner(owner);
  token = owner->pending_token;
  owner->pending_token = 0u;
  owner->pending_bytes = 0u;
  owner->in_callback = 1;
  result = mesh_mgmt_peer_complete_send_v1(&owner->peer, token, 1, bytes);
  result = result == MESH_MGMT_PEER_OK ? drain(owner, now_ms) : fail_owner(owner);
  owner->in_callback = 0;
  return result;
}

mesh_mgmt_peer_result_t mesh_mgmt_cnet_peer_on_state_v1(
    mesh_mgmt_cnet_peer_v1_t *owner, cnet_connection connection, cnet_connection_state state) {
  if (!owner || !owner->initialized || owner->in_callback ||
      !same_connection(connection, owner->connection))
    return MESH_MGMT_PEER_INVALID_STATE;
  if (state != CNET_CONNECTION_CLOSED && state != CNET_CONNECTION_FAILED)
    return MESH_MGMT_PEER_INVALID_STATE;
  owner->terminal_observed = 1;
  owner->receive_pending = 0;
  (void)fail_owner(owner);
  return MESH_MGMT_PEER_OK;
}

mesh_mgmt_connection_result_t mesh_mgmt_cnet_peer_send_v1(
    mesh_mgmt_cnet_peer_v1_t *owner, uint8_t kind, const uint8_t *payload, size_t payload_len) {
  const uint8_t *frame = NULL;
  size_t frame_len = 0u;
  mesh_mgmt_connection_result_t result;
  if (!owner || !owner->initialized || owner->in_callback || owner->close_requested ||
      owner->terminal_observed ||
      owner->peer.state != MESH_MGMT_PEER_READY ||
      owner->peer.connection.dispatcher.session.state != MESH_MGMT_SESSION_ESTABLISHED)
    return MESH_MGMT_CONNECTION_INVALID_STATE;
  if (owner->pending_token)
    return MESH_MGMT_CONNECTION_BUSY;
  if (validate_binding(owner) != SALTS_OK) {
    (void)fail_owner(owner);
    return MESH_MGMT_CONNECTION_TRANSPORT_FAILED;
  }
  owner->in_callback = 1;
  if (mesh_mgmt_peer_signer_build_targeted_v1(&owner->signer, kind,
        owner->peer.connection.dispatcher.session.remote_certificate.managed_node_id,
        payload, payload_len, &frame, &frame_len) != MESH_MGMT_PEER_SIGNER_OK) {
    owner->in_callback = 0;
    return MESH_MGMT_CONNECTION_INVALID_FRAME;
  }
  result = mesh_mgmt_connection_send_v1(&owner->peer.connection, frame, frame_len);
  owner->in_callback = 0;
  if (result < MESH_MGMT_CONNECTION_OK && owner->peer.connection.state == MESH_MGMT_CONNECTION_TERMINAL)
    (void)fail_owner(owner);
  return result;
}

mesh_mgmt_peer_result_t mesh_mgmt_cnet_peer_close_v1(mesh_mgmt_cnet_peer_v1_t *owner) {
  if (!owner || !owner->initialized || owner->in_callback)
    return MESH_MGMT_PEER_INVALID_STATE;
  (void)fail_owner(owner);
  return owner->close_requested || owner->terminal_observed
      ? MESH_MGMT_PEER_OK : MESH_MGMT_PEER_CONNECTION_FAILED;
}

mesh_mgmt_peer_result_t mesh_mgmt_cnet_peer_destroy_v1(mesh_mgmt_cnet_peer_v1_t *owner) {
  if (!owner || !owner->initialized || owner->in_callback || !owner->terminal_observed)
    return MESH_MGMT_PEER_INVALID_STATE;
  mesh_mgmt_peer_destroy_v1(&owner->peer);
  mesh_mgmt_peer_signer_destroy_v1(&owner->signer);
  memset(owner, 0, sizeof(*owner));
  return MESH_MGMT_PEER_OK;
}
