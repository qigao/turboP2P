#include "mesh_stream_coronet_adapter.h"

#include <string.h>

_Static_assert(CORO_TLS_CHANNEL_BINDING_SIZE == MESH_STREAM_BIND_CHANNEL_BINDING_SIZE,
               "CoroNet and mesh channel-binding sizes must match");

static mesh_stream_bind_result_t
coronet_export_channel_binding(coro_socket_t *socket,
                               uint8_t output[MESH_STREAM_BIND_CHANNEL_BINDING_SIZE]) {
  int result;

  if (output)
    memset(output, 0, MESH_STREAM_BIND_CHANNEL_BINDING_SIZE);
  if (!socket || !output)
    return MESH_STREAM_BIND_INVALID_ARG;
  result = coro_socket_tls_export_channel_binding(socket, output);
  if (result == 0)
    return MESH_STREAM_BIND_OK;
  memset(output, 0, MESH_STREAM_BIND_CHANNEL_BINDING_SIZE);
  return result == TURBO_EIO ? MESH_STREAM_BIND_CHANNEL_EXPORT_FAILED
                            : MESH_STREAM_BIND_TLS_REQUIRED;
}

static void authorization_set(mesh_stream_coronet_authorization_v1_t *authorization,
                              const mesh_stream_bind_ticket_v1_t *ticket,
                              const uint8_t channel_binding[MESH_STREAM_BIND_CHANNEL_BINDING_SIZE],
                              mesh_stream_coronet_role_v1_t local_role) {
  memset(authorization, 0, sizeof(*authorization));
  authorization->ticket = *ticket;
  memcpy(authorization->channel_binding, channel_binding,
         MESH_STREAM_BIND_CHANNEL_BINDING_SIZE);
  authorization->local_role = local_role;
  authorization->authenticated = 1u;
}

static int authorization_matches(
    const mesh_stream_coronet_authorization_v1_t *authorization,
    const mesh_stream_channel_admission_v1_t *admission, uint64_t now_ms,
    coro_socket_t *socket) {
  const mesh_stream_bind_claims_v1_t *claims;
  const uint8_t *remote_node_id;
  uint8_t current_binding[MESH_STREAM_BIND_CHANNEL_BINDING_SIZE];
  int matches = 0;

  if (!authorization || !admission || !socket || !authorization->authenticated || now_ms == 0u ||
      authorization->ticket.issued_at_ms >= authorization->ticket.expires_at_ms ||
      now_ms < authorization->ticket.issued_at_ms ||
      now_ms >= authorization->ticket.expires_at_ms ||
      (authorization->local_role != MESH_STREAM_CORONET_ROLE_INITIATOR &&
       authorization->local_role != MESH_STREAM_CORONET_ROLE_RESPONDER)) {
    return 0;
  }
  if (coronet_export_channel_binding(socket, current_binding) != MESH_STREAM_BIND_OK)
    return 0;
  claims = &authorization->ticket.claims;
  remote_node_id = authorization->local_role == MESH_STREAM_CORONET_ROLE_INITIATOR
                       ? claims->responder_node_id
                       : claims->initiator_node_id;
  matches = mesh_mgmt_crypto_equal_32(authorization->channel_binding, current_binding) &&
            mesh_mgmt_crypto_equal_32(admission->remote_peer_id, remote_node_id) &&
            admission->generation == claims->admission_generation &&
            admission->stream_epoch == claims->stream_epoch &&
            memcmp(admission->stream_id, claims->stream_id, MESH_STREAM_ID_SIZE) == 0;
  memset(current_binding, 0, sizeof(current_binding));
  return matches;
}

void mesh_stream_coronet_authorization_clear_v1(
    mesh_stream_coronet_authorization_v1_t *authorization) {
  if (authorization)
    memset(authorization, 0, sizeof(*authorization));
}

mesh_stream_bind_result_t mesh_stream_bind_initiator_start_coronet_v1(
    mesh_stream_bind_initiator_v1_t *initiator, const mesh_stream_bind_ticket_v1_t *ticket,
    const uint8_t private_key[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE], coro_socket_t *socket,
    uint8_t output[MESH_STREAM_BIND_INIT_SIZE]) {
  uint8_t channel_binding[MESH_STREAM_BIND_CHANNEL_BINDING_SIZE];
  mesh_stream_bind_result_t result;

  if (output)
    memset(output, 0, MESH_STREAM_BIND_INIT_SIZE);
  if (!initiator || !ticket || !private_key || !socket || !output)
    return MESH_STREAM_BIND_INVALID_ARG;
  result = coronet_export_channel_binding(socket, channel_binding);
  if (result == MESH_STREAM_BIND_OK) {
    result = mesh_stream_bind_initiator_start_v1(initiator, ticket, private_key, channel_binding,
                                                 output);
  }
  if (result == MESH_STREAM_BIND_OK &&
      coro_socket_send(socket, (const char *)output, MESH_STREAM_BIND_INIT_SIZE) != 0) {
    memset(initiator, 0, sizeof(*initiator));
    memset(output, 0, MESH_STREAM_BIND_INIT_SIZE);
    result = MESH_STREAM_BIND_IO_FAILED;
  }
  memset(channel_binding, 0, sizeof(channel_binding));
  return result;
}

mesh_stream_bind_result_t mesh_stream_bind_initiator_confirm_coronet_v1(
    mesh_stream_bind_initiator_v1_t *initiator, const uint8_t *input, size_t input_len,
    const uint8_t private_key[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE], coro_socket_t *socket,
    uint8_t output[MESH_STREAM_BIND_CONFIRM_SIZE],
    mesh_stream_coronet_authorization_v1_t *out_authorization) {
  uint8_t channel_binding[MESH_STREAM_BIND_CHANNEL_BINDING_SIZE];
  mesh_stream_bind_result_t result;

  if (out_authorization)
    memset(out_authorization, 0, sizeof(*out_authorization));
  if (output)
    memset(output, 0, MESH_STREAM_BIND_CONFIRM_SIZE);
  if (!initiator || !input || !private_key || !socket || !output || !out_authorization)
    return MESH_STREAM_BIND_INVALID_ARG;
  result = coronet_export_channel_binding(socket, channel_binding);
  if (result == MESH_STREAM_BIND_OK) {
    result = mesh_stream_bind_initiator_confirm_v1(initiator, input, input_len, private_key,
                                                   channel_binding, output);
  }
  if (result == MESH_STREAM_BIND_OK &&
      coro_socket_send(socket, (const char *)output, MESH_STREAM_BIND_CONFIRM_SIZE) != 0) {
    memset(initiator, 0, sizeof(*initiator));
    memset(output, 0, MESH_STREAM_BIND_CONFIRM_SIZE);
    result = MESH_STREAM_BIND_IO_FAILED;
  }
  if (result == MESH_STREAM_BIND_OK) {
    authorization_set(out_authorization, &initiator->ticket, channel_binding,
                      MESH_STREAM_CORONET_ROLE_INITIATOR);
  }
  memset(channel_binding, 0, sizeof(channel_binding));
  return result;
}

mesh_stream_bind_result_t mesh_stream_bind_responder_accept_coronet_v1(
    mesh_stream_bind_store_v1_t *store, const uint8_t *input, size_t input_len,
    const uint8_t private_key[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE], coro_socket_t *socket,
    uint64_t now_ms, uint8_t output[MESH_STREAM_BIND_ACCEPT_SIZE]) {
  uint8_t channel_binding[MESH_STREAM_BIND_CHANNEL_BINDING_SIZE];
  mesh_stream_bind_result_t result;

  if (output)
    memset(output, 0, MESH_STREAM_BIND_ACCEPT_SIZE);
  if (!store || !input || !private_key || !socket || !output)
    return MESH_STREAM_BIND_INVALID_ARG;
  result = coronet_export_channel_binding(socket, channel_binding);
  if (result == MESH_STREAM_BIND_OK) {
    result = mesh_stream_bind_responder_accept_v1(store, input, input_len, private_key,
                                                  channel_binding, now_ms, output);
  }
  if (result == MESH_STREAM_BIND_OK &&
      coro_socket_send(socket, (const char *)output, MESH_STREAM_BIND_ACCEPT_SIZE) != 0) {
    (void)mesh_stream_bind_responder_abort_init_v1(store, input, input_len, now_ms);
    memset(output, 0, MESH_STREAM_BIND_ACCEPT_SIZE);
    result = MESH_STREAM_BIND_IO_FAILED;
  }
  memset(channel_binding, 0, sizeof(channel_binding));
  return result;
}

mesh_stream_bind_result_t mesh_stream_bind_responder_finish_coronet_v1(
    mesh_stream_bind_store_v1_t *store, const uint8_t *input, size_t input_len,
    coro_socket_t *socket, uint64_t now_ms,
    mesh_stream_coronet_authorization_v1_t *out_authorization) {
  mesh_stream_bind_ticket_v1_t ticket;
  uint8_t channel_binding[MESH_STREAM_BIND_CHANNEL_BINDING_SIZE];
  mesh_stream_bind_result_t result;

  memset(&ticket, 0, sizeof(ticket));
  if (out_authorization)
    memset(out_authorization, 0, sizeof(*out_authorization));
  if (!store || !input || !socket || !out_authorization)
    return MESH_STREAM_BIND_INVALID_ARG;
  result = coronet_export_channel_binding(socket, channel_binding);
  if (result == MESH_STREAM_BIND_OK) {
    result = mesh_stream_bind_responder_finish_v1(store, input, input_len, channel_binding, now_ms,
                                                  &ticket);
  }
  if (result == MESH_STREAM_BIND_OK) {
    authorization_set(out_authorization, &ticket, channel_binding,
                      MESH_STREAM_CORONET_ROLE_RESPONDER);
  }
  memset(&ticket, 0, sizeof(ticket));
  memset(channel_binding, 0, sizeof(channel_binding));
  return result;
}

static int coronet_recv(void *context, uint8_t **out_bytes, size_t *out_len) {
  return coro_socket_recv((coro_socket_t *)context, (char **)out_bytes, out_len);
}

static void coronet_release_recv(void *context, uint8_t *bytes) {
  (void)context;
  coro_socket_free_recv(bytes);
}

static int coronet_send(void *context, const uint8_t *bytes, size_t len) {
  return coro_socket_send((coro_socket_t *)context, (const char *)bytes, len);
}

static int coronet_set_send_hwm(void *context, size_t bytes) {
  return coro_socket_set_send_hwm((coro_socket_t *)context, bytes);
}

static int coronet_set_receive_timeout(void *context, uint64_t timeout_ms) {
  coro_socket_set_timeout((coro_socket_t *)context, timeout_ms);
  return 0;
}

mesh_stream_transport_result_t mesh_stream_transport_init_coronet_v1(
    mesh_stream_transport_v1_t *transport, const mesh_stream_transport_config_v1_t *config,
    coro_socket_t *socket, mesh_stream_transport_event_fn on_event, void *event_context) {
  mesh_stream_transport_io_v1_t io;
  uint8_t channel_binding[MESH_STREAM_BIND_CHANNEL_BINDING_SIZE];

  if (!transport || !config || !socket || !on_event)
    return MESH_STREAM_TRANSPORT_INVALID_ARG;
  if (coronet_export_channel_binding(socket, channel_binding) != MESH_STREAM_BIND_OK)
    return MESH_STREAM_TRANSPORT_SECURE_CHANNEL_REQUIRED;
  memset(channel_binding, 0, sizeof(channel_binding));
  io.recv = coronet_recv;
  io.release_recv = coronet_release_recv;
  io.send = coronet_send;
  io.set_send_hwm = coronet_set_send_hwm;
  io.set_receive_timeout = coronet_set_receive_timeout;
  io.context = socket;
  return mesh_stream_transport_init_v1(transport, config, &io, on_event, event_context);
}

mesh_stream_channel_result_t mesh_stream_channel_init_coronet_v1(
    mesh_stream_channel_v1_t *channel, const mesh_stream_channel_admission_v1_t *admission,
    const mesh_stream_transport_config_v1_t *config,
    const mesh_stream_coronet_authorization_v1_t *authorization, uint64_t now_ms,
    coro_socket_t *socket,
    mesh_stream_transport_event_fn on_event, void *event_context) {
  mesh_stream_transport_io_v1_t io;

  if (!channel || !socket || !admission || !config || !on_event)
    return MESH_STREAM_CHANNEL_INVALID_ARG;
  if (!authorization_matches(authorization, admission, now_ms, socket))
    return MESH_STREAM_CHANNEL_AUTH_REQUIRED;
  io.recv = coronet_recv;
  io.release_recv = coronet_release_recv;
  io.send = coronet_send;
  io.set_send_hwm = coronet_set_send_hwm;
  io.set_receive_timeout = coronet_set_receive_timeout;
  io.context = socket;
  return mesh_stream_channel_init_v1(channel, admission, config, &io, on_event, event_context);
}

mesh_stream_registry_result_t mesh_stream_registry_open_coronet_v1(
    mesh_stream_registry_v1_t *registry, const mesh_stream_channel_admission_v1_t *admission,
    const mesh_stream_transport_config_v1_t *config,
    const mesh_stream_coronet_authorization_v1_t *authorization, uint64_t now_ms,
    coro_socket_t *socket,
    mesh_stream_transport_event_fn on_event, void *event_context,
    mesh_stream_channel_handle_v1_t *out_handle) {
  mesh_stream_registry_open_v1_t request;

  if (!registry || !admission || !config || !socket || !on_event || !out_handle)
    return MESH_STREAM_REGISTRY_INVALID_ARG;
  if (!authorization_matches(authorization, admission, now_ms, socket))
    return MESH_STREAM_REGISTRY_AUTH_REQUIRED;
  request.admission = *admission;
  request.transport = *config;
  request.io.recv = coronet_recv;
  request.io.release_recv = coronet_release_recv;
  request.io.send = coronet_send;
  request.io.set_send_hwm = coronet_set_send_hwm;
  request.io.set_receive_timeout = coronet_set_receive_timeout;
  request.io.context = socket;
  request.on_event = on_event;
  request.event_context = event_context;
  return mesh_stream_registry_open_v1(registry, &request, out_handle);
}
