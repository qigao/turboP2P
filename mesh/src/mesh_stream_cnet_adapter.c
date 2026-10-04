#include "mesh_stream_cnet_adapter.h"

#include <string.h>

/* The core v1 frames share an 8-byte length/type/version/reserved prefix. */
#define BIND_TICKET_OFFSET 8u

static int same_connection(cnet_connection a, cnet_connection b) {
  return a.slot == b.slot && a.generation == b.generation;
}

static mesh_stream_bind_result_t export_binding(cnet_client *client, cnet_connection connection,
                                                uint8_t output[32]) {
  static const char required_version[] = "TLSv1.3";
  char version[sizeof(required_version)] = {0};
  size_t length = 0u;
  int status = cnet_tls_negotiated_version(client, connection, version,
                                           sizeof(version), &length);
  if (status != SALTS_OK)
    return status == SALTS_ENOTSUP || status == SALTS_EMSGSIZE
               ? MESH_STREAM_BIND_TLS_REQUIRED : MESH_STREAM_BIND_CHANNEL_EXPORT_FAILED;
  if (length != sizeof(required_version) - 1u ||
      memcmp(version, required_version, sizeof(required_version)) != 0)
    return MESH_STREAM_BIND_TLS_REQUIRED;
  status = cnet_tls_export_channel_binding(client, connection, output);
  if (status == SALTS_OK)
    return MESH_STREAM_BIND_OK;
  return status == SALTS_ENOTSUP ? MESH_STREAM_BIND_TLS_REQUIRED
                                 : MESH_STREAM_BIND_CHANNEL_EXPORT_FAILED;
}

static mesh_stream_bind_result_t fail_bind(mesh_stream_cnet_bind_v1_t *bind,
                                           mesh_stream_bind_result_t result, uint64_t now_ms) {
  if (bind->challenge_live) {
    (void)mesh_stream_bind_responder_abort_init_v1(bind->store, bind->accepted_init,
                                                   sizeof(bind->accepted_init), now_ms);
    bind->challenge_live = 0u;
  }
  mesh_mgmt_crypto_wipe(&bind->initiator, sizeof(bind->initiator));
  mesh_mgmt_crypto_wipe(&bind->ticket, sizeof(bind->ticket));
  mesh_mgmt_crypto_wipe(bind->channel_binding, sizeof(bind->channel_binding));
  mesh_mgmt_crypto_wipe(bind->accepted_init, sizeof(bind->accepted_init));
  bind->pending_bytes = 0u;
  bind->state = MESH_STREAM_CNET_FAILED;
  bind->last_result = result;
  return result;
}

static mesh_stream_bind_result_t validate_binding(mesh_stream_cnet_bind_v1_t *bind,
                                                   uint64_t now_ms) {
  uint8_t current[32] = {0};
  mesh_stream_bind_result_t result;
  if (now_ms == 0u)
    return fail_bind(bind, MESH_STREAM_BIND_INVALID_ARG, now_ms);
  result = export_binding(bind->client, bind->connection, current);
  if (result == MESH_STREAM_BIND_OK &&
      !mesh_mgmt_crypto_equal_32(current, bind->channel_binding))
    result = MESH_STREAM_BIND_CHANNEL_MISMATCH;
  mesh_mgmt_crypto_wipe(current, sizeof(current));
  if (result != MESH_STREAM_BIND_OK)
    return fail_bind(bind, result, now_ms);
  return MESH_STREAM_BIND_OK;
}

static mesh_stream_bind_result_t submit(mesh_stream_cnet_bind_v1_t *bind,
                                         const uint8_t *wire, size_t len,
                                         mesh_stream_cnet_state_v1_t state, uint64_t now_ms) {
  mem_buffer_t *buffer = mem_get_buffer(mem_global(), len);
  int status;
  if (!buffer)
    return fail_bind(bind, MESH_STREAM_BIND_RESOURCE_EXHAUSTED, now_ms);
  memcpy(mem_buffer_data(buffer), wire, len);
  mem_set_used(buffer, len);
  status = cnet_send_buffer(bind->client, bind->connection, buffer);
  mem_buffer_release(buffer);
  if (status != SALTS_OK)
    return fail_bind(bind, MESH_STREAM_BIND_IO_FAILED, now_ms);
  bind->pending_bytes = len;
  bind->state = state;
  bind->last_result = MESH_STREAM_BIND_OK;
  return MESH_STREAM_BIND_OK;
}

mesh_stream_bind_result_t mesh_stream_cnet_bind_init_v1(
    mesh_stream_cnet_bind_v1_t *bind, cnet_client *client, cnet_connection connection,
    mesh_stream_cnet_role_v1_t role, mesh_stream_bind_store_v1_t *responder_store) {
  uint8_t exporter[32] = {0};
  mesh_stream_bind_result_t result;
  if (!bind || !client || !client->impl || bind->state != MESH_STREAM_CNET_UNINITIALIZED ||
      (role != MESH_STREAM_CNET_ROLE_INITIATOR && role != MESH_STREAM_CNET_ROLE_RESPONDER) ||
      (role == MESH_STREAM_CNET_ROLE_RESPONDER && (!responder_store || !responder_store->entries)) ||
      (role == MESH_STREAM_CNET_ROLE_INITIATOR && responder_store))
    return MESH_STREAM_BIND_INVALID_ARG;
  result = export_binding(client, connection, exporter);
  if (result == MESH_STREAM_BIND_OK) {
    bind->client = client;
    bind->connection = connection;
    bind->role = role;
    bind->store = responder_store;
    memcpy(bind->channel_binding, exporter, sizeof(exporter));
    bind->state = MESH_STREAM_CNET_READY;
  }
  mesh_mgmt_crypto_wipe(exporter, sizeof(exporter));
  return result;
}

mesh_stream_bind_result_t mesh_stream_cnet_bind_start_v1(
    mesh_stream_cnet_bind_v1_t *bind, const mesh_stream_bind_ticket_v1_t *ticket,
    const uint8_t private_key[32], uint64_t now_ms) {
  uint8_t wire[MESH_STREAM_BIND_INIT_SIZE] = {0};
  mesh_stream_bind_result_t result;
  if (!bind || !ticket || !private_key)
    return MESH_STREAM_BIND_INVALID_ARG;
  if (bind->state != MESH_STREAM_CNET_READY || bind->role != MESH_STREAM_CNET_ROLE_INITIATOR)
    return MESH_STREAM_BIND_INVALID_STATE;
  result = validate_binding(bind, now_ms);
  if (result == MESH_STREAM_BIND_OK &&
      (now_ms < ticket->issued_at_ms || now_ms >= ticket->expires_at_ms))
    result = MESH_STREAM_BIND_EXPIRED;
  if (result == MESH_STREAM_BIND_OK)
    result = mesh_stream_bind_initiator_start_v1(&bind->initiator, ticket, private_key,
                                                   bind->channel_binding, wire);
  if (result == MESH_STREAM_BIND_OK)
    result = submit(bind, wire, sizeof(wire), MESH_STREAM_CNET_INIT_PENDING, now_ms);
  else
    result = fail_bind(bind, result, now_ms);
  mesh_mgmt_crypto_wipe(wire, sizeof(wire));
  return result;
}

mesh_stream_bind_result_t mesh_stream_cnet_bind_accept_v1(
    mesh_stream_cnet_bind_v1_t *bind, const uint8_t *init, size_t len,
    const uint8_t private_key[32], uint64_t now_ms) {
  uint8_t wire[MESH_STREAM_BIND_ACCEPT_SIZE] = {0};
  mesh_stream_bind_result_t result;
  if (!bind || !init || !private_key)
    return MESH_STREAM_BIND_INVALID_ARG;
  if (bind->state != MESH_STREAM_CNET_READY || bind->role != MESH_STREAM_CNET_ROLE_RESPONDER)
    return MESH_STREAM_BIND_INVALID_STATE;
  result = validate_binding(bind, now_ms);
  if (result == MESH_STREAM_BIND_OK)
    result = mesh_stream_bind_responder_accept_v1(bind->store, init, len, private_key,
                                                   bind->channel_binding, now_ms, wire);
  if (result == MESH_STREAM_BIND_OK) {
    memcpy(bind->accepted_init, init, sizeof(bind->accepted_init));
    bind->challenge_live = 1u;
    result = submit(bind, wire, sizeof(wire), MESH_STREAM_CNET_ACCEPT_PENDING, now_ms);
  } else {
    result = fail_bind(bind, result, now_ms);
  }
  mesh_mgmt_crypto_wipe(wire, sizeof(wire));
  return result;
}

mesh_stream_bind_result_t mesh_stream_cnet_bind_confirm_v1(
    mesh_stream_cnet_bind_v1_t *bind, const uint8_t *accept, size_t len,
    const uint8_t private_key[32], uint64_t now_ms) {
  uint8_t wire[MESH_STREAM_BIND_CONFIRM_SIZE] = {0};
  mesh_stream_bind_result_t result;
  if (!bind || !accept || !private_key)
    return MESH_STREAM_BIND_INVALID_ARG;
  if (bind->state != MESH_STREAM_CNET_WAIT_ACCEPT)
    return MESH_STREAM_BIND_INVALID_STATE;
  result = validate_binding(bind, now_ms);
  if (result == MESH_STREAM_BIND_OK && now_ms >= bind->initiator.ticket.expires_at_ms)
    result = MESH_STREAM_BIND_EXPIRED;
  if (result == MESH_STREAM_BIND_OK)
    result = mesh_stream_bind_initiator_confirm_v1(&bind->initiator, accept, len, private_key,
                                                     bind->channel_binding, wire);
  if (result == MESH_STREAM_BIND_OK)
    result = submit(bind, wire, sizeof(wire), MESH_STREAM_CNET_CONFIRM_PENDING, now_ms);
  else
    result = fail_bind(bind, result, now_ms);
  mesh_mgmt_crypto_wipe(wire, sizeof(wire));
  return result;
}

mesh_stream_bind_result_t mesh_stream_cnet_bind_finish_v1(
    mesh_stream_cnet_bind_v1_t *bind, const uint8_t *confirm, size_t len, uint64_t now_ms) {
  mesh_stream_bind_result_t result;
  if (!bind || !confirm)
    return MESH_STREAM_BIND_INVALID_ARG;
  if (bind->state != MESH_STREAM_CNET_WAIT_CONFIRM)
    return MESH_STREAM_BIND_INVALID_STATE;
  result = validate_binding(bind, now_ms);
  if (result == MESH_STREAM_BIND_OK &&
      (len != MESH_STREAM_BIND_CONFIRM_SIZE ||
       !mesh_mgmt_crypto_equal_32(confirm + BIND_TICKET_OFFSET,
                                   bind->accepted_init + BIND_TICKET_OFFSET)))
    result = MESH_STREAM_BIND_AUTH_FAILED;
  if (result == MESH_STREAM_BIND_OK)
    result = mesh_stream_bind_responder_finish_v1(bind->store, confirm, len,
                                                   bind->channel_binding, now_ms, &bind->ticket);
  if (result != MESH_STREAM_BIND_OK)
    return fail_bind(bind, result, now_ms);
  mesh_mgmt_crypto_wipe(bind->accepted_init, sizeof(bind->accepted_init));
  bind->challenge_live = 0u;
  bind->state = MESH_STREAM_CNET_AUTHENTICATED;
  return MESH_STREAM_BIND_OK;
}

mesh_stream_bind_result_t mesh_stream_cnet_bind_complete_send_v1(
    mesh_stream_cnet_bind_v1_t *bind, cnet_connection connection, int status,
    size_t bytes, uint64_t now_ms) {
  mesh_stream_bind_result_t result;
  if (!bind)
    return MESH_STREAM_BIND_INVALID_ARG;
  if (!same_connection(connection, bind->connection) || bind->pending_bytes == 0u)
    return MESH_STREAM_BIND_INVALID_STATE;
  if (status != SALTS_OK || bytes != bind->pending_bytes)
    return fail_bind(bind, MESH_STREAM_BIND_IO_FAILED, now_ms);
  result = validate_binding(bind, now_ms);
  if (result != MESH_STREAM_BIND_OK)
    return result;
  if (bind->state == MESH_STREAM_CNET_INIT_PENDING) {
    bind->state = MESH_STREAM_CNET_WAIT_ACCEPT;
  } else if (bind->state == MESH_STREAM_CNET_ACCEPT_PENDING) {
    bind->state = MESH_STREAM_CNET_WAIT_CONFIRM;
  } else if (bind->state == MESH_STREAM_CNET_CONFIRM_PENDING) {
    if (now_ms >= bind->initiator.ticket.expires_at_ms)
      return fail_bind(bind, MESH_STREAM_BIND_EXPIRED, now_ms);
    bind->ticket = bind->initiator.ticket;
    mesh_mgmt_crypto_wipe(&bind->initiator, sizeof(bind->initiator));
    bind->state = MESH_STREAM_CNET_AUTHENTICATED;
  } else {
    return fail_bind(bind, MESH_STREAM_BIND_INVALID_STATE, now_ms);
  }
  bind->pending_bytes = 0u;
  return MESH_STREAM_BIND_OK;
}

mesh_stream_bind_result_t mesh_stream_cnet_bind_abort_v1(
    mesh_stream_cnet_bind_v1_t *bind, cnet_connection connection, uint64_t now_ms) {
  if (!bind)
    return MESH_STREAM_BIND_INVALID_ARG;
  if (bind->state == MESH_STREAM_CNET_UNINITIALIZED || !same_connection(connection, bind->connection))
    return MESH_STREAM_BIND_INVALID_STATE;
  return fail_bind(bind, MESH_STREAM_BIND_IO_FAILED, now_ms);
}

int mesh_stream_cnet_bind_authorizes_v1(
    const mesh_stream_cnet_bind_v1_t *bind,
    const mesh_stream_channel_admission_v1_t *admission, uint64_t now_ms) {
  uint8_t exporter[32] = {0};
  const mesh_stream_bind_claims_v1_t *claims;
  const uint8_t *remote;
  int matches;
  if (!bind || !admission || bind->state != MESH_STREAM_CNET_AUTHENTICATED || now_ms == 0u ||
      now_ms < bind->ticket.issued_at_ms || now_ms >= bind->ticket.expires_at_ms)
    return 0;
  claims = &bind->ticket.claims;
  remote = bind->role == MESH_STREAM_CNET_ROLE_INITIATOR ? claims->responder_node_id
                                                        : claims->initiator_node_id;
  matches = export_binding(bind->client, bind->connection, exporter) == MESH_STREAM_BIND_OK &&
            mesh_mgmt_crypto_equal_32(exporter, bind->channel_binding) &&
            mesh_mgmt_crypto_equal_32(remote, admission->remote_peer_id) &&
            mesh_mgmt_crypto_equal_16(claims->stream_id, admission->stream_id) &&
            claims->stream_epoch == admission->stream_epoch &&
            claims->admission_generation == admission->generation;
  mesh_mgmt_crypto_wipe(exporter, sizeof(exporter));
  return matches;
}
