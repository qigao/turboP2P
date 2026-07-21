#include "mesh_mgmt_connection.h"

#include "mesh_mgmt_crypto.h"

#include <string.h>

typedef mesh_mgmt_dispatch_result_t (*mesh_mgmt_connection_mark_fn)(
    mesh_mgmt_dispatcher_v1_t *dispatcher, mesh_mgmt_dispatch_stage_t *out_stage);

static mesh_mgmt_connection_result_t connection_fail(mesh_mgmt_connection_v1_t *connection,
                                                     mesh_mgmt_connection_result_t result) {
  connection->state = MESH_MGMT_CONNECTION_TERMINAL;
  connection->last_error = result;
  return result;
}

static int peer_id_is_present(const uint8_t peer_id[32]) {
  static const uint8_t zero[32] = {0};
  return !mesh_mgmt_crypto_equal_32(peer_id, zero);
}

static mesh_mgmt_connection_result_t require_ready(mesh_mgmt_connection_v1_t *connection) {
  if (!connection)
    return MESH_MGMT_CONNECTION_INVALID_ARG;
  if (connection->state == MESH_MGMT_CONNECTION_TERMINAL)
    return connection->last_error;
  if (connection->state != MESH_MGMT_CONNECTION_READY || connection->in_event_callback)
    return MESH_MGMT_CONNECTION_INVALID_STATE;
  return MESH_MGMT_CONNECTION_OK;
}

static mesh_mgmt_connection_result_t decode_outbound_kind(mesh_mgmt_connection_v1_t *connection,
                                                          const uint8_t *frame, size_t frame_len,
                                                          uint8_t *out_kind) {
  mesh_mgmt_frame_view_t view;
  mesh_mgmt_codec_result_t result;

  if (!frame || !out_kind)
    return MESH_MGMT_CONNECTION_INVALID_ARG;
  result = mesh_mgmt_frame_decode(frame, frame_len, &view);
  if (result != MESH_MGMT_CODEC_OK) {
    connection->last_transport_result = result == MESH_MGMT_CODEC_RESOURCE_EXHAUSTED
                                            ? MESH_MGMT_TRANSPORT_RESOURCE_EXHAUSTED
                                            : MESH_MGMT_TRANSPORT_INVALID_FRAME;
    return MESH_MGMT_CONNECTION_INVALID_FRAME;
  }
  *out_kind = view.kind;
  return MESH_MGMT_CONNECTION_OK;
}

static mesh_mgmt_connection_result_t send_and_mark(mesh_mgmt_connection_v1_t *connection,
                                                   const uint8_t *frame, size_t frame_len,
                                                   uint8_t expected_kind,
                                                   mesh_mgmt_connection_mark_fn mark) {
  mesh_mgmt_connection_result_t result = require_ready(connection);
  mesh_mgmt_transport_result_t transport_result;
  mesh_mgmt_dispatch_result_t dispatch_result;
  uint8_t kind = 0u;

  if (result != MESH_MGMT_CONNECTION_OK)
    return result;
  result = decode_outbound_kind(connection, frame, frame_len, &kind);
  if (result != MESH_MGMT_CONNECTION_OK)
    return result;
  if (kind != expected_kind)
    return MESH_MGMT_CONNECTION_INVALID_FRAME;

  transport_result = mesh_mgmt_transport_send_v1(&connection->transport, frame, frame_len);
  connection->last_transport_result = transport_result;
  if (transport_result != MESH_MGMT_TRANSPORT_OK)
    return connection_fail(connection, MESH_MGMT_CONNECTION_TRANSPORT_FAILED);

  dispatch_result = mark(&connection->dispatcher, &connection->last_dispatch_stage);
  connection->last_dispatch_result = dispatch_result;
  if (dispatch_result != MESH_MGMT_DISPATCH_OK) {
    return connection_fail(connection, MESH_MGMT_CONNECTION_DISPATCH_FAILED);
  }
  connection->last_error = MESH_MGMT_CONNECTION_OK;
  return MESH_MGMT_CONNECTION_OK;
}

mesh_mgmt_connection_result_t
mesh_mgmt_connection_init_v1(mesh_mgmt_connection_v1_t *connection,
                             const mesh_mgmt_connection_config_v1_t *config) {
  mesh_mgmt_dispatch_stage_t stage = MESH_MGMT_DISPATCH_STAGE_SESSION;
  mesh_mgmt_dispatch_result_t dispatch_result;
  mesh_mgmt_transport_result_t transport_result;

  if (!connection || !config || !config->on_event || !peer_id_is_present(config->transport_peer_id))
    return MESH_MGMT_CONNECTION_INVALID_ARG;
  if (connection->state != MESH_MGMT_CONNECTION_UNINITIALIZED ||
      connection->transport.initialized || connection->transport.io.context)
    return MESH_MGMT_CONNECTION_INVALID_STATE;

  memset(connection, 0, sizeof(*connection));
  dispatch_result =
      mesh_mgmt_dispatcher_init_v1(&connection->dispatcher, &config->dispatch, &stage);
  connection->last_dispatch_result = dispatch_result;
  connection->last_dispatch_stage = stage;
  if (dispatch_result != MESH_MGMT_DISPATCH_OK) {
    memset(connection, 0, sizeof(*connection));
    return MESH_MGMT_CONNECTION_DISPATCH_FAILED;
  }
  transport_result = mesh_mgmt_transport_init_v1(&connection->transport, &config->io);
  connection->last_transport_result = transport_result;
  if (transport_result != MESH_MGMT_TRANSPORT_OK) {
    mesh_mgmt_dispatcher_destroy_v1(&connection->dispatcher);
    memset(connection, 0, sizeof(*connection));
    return MESH_MGMT_CONNECTION_TRANSPORT_FAILED;
  }

  memcpy(connection->transport_peer_id, config->transport_peer_id,
         sizeof(connection->transport_peer_id));
  connection->on_event = config->on_event;
  connection->event_context = config->event_context;
  connection->state = MESH_MGMT_CONNECTION_READY;
  connection->last_error = MESH_MGMT_CONNECTION_OK;
  connection->last_transport_result = MESH_MGMT_TRANSPORT_OK;
  connection->last_dispatch_result = MESH_MGMT_DISPATCH_OK;
  return MESH_MGMT_CONNECTION_OK;
}

void mesh_mgmt_connection_destroy_v1(mesh_mgmt_connection_v1_t *connection) {
  if (!connection || connection->in_event_callback)
    return;
  mesh_mgmt_transport_destroy_v1(&connection->transport);
  mesh_mgmt_dispatcher_destroy_v1(&connection->dispatcher);
  memset(connection, 0, sizeof(*connection));
}

mesh_mgmt_connection_result_t mesh_mgmt_connection_abort_v1(mesh_mgmt_connection_v1_t *connection) {
  mesh_mgmt_connection_result_t result = require_ready(connection);

  if (result != MESH_MGMT_CONNECTION_OK)
    return result;
  return connection_fail(connection, MESH_MGMT_CONNECTION_LOCAL_FAILED);
}

mesh_mgmt_connection_result_t
mesh_mgmt_connection_pump_once_v1(mesh_mgmt_connection_v1_t *connection, uint64_t now_ms) {
  mesh_mgmt_transport_receipt_v1_t receipt;
  mesh_mgmt_dispatch_event_v1_t event;
  mesh_mgmt_connection_result_t result = require_ready(connection);
  mesh_mgmt_transport_result_t transport_result;
  mesh_mgmt_dispatch_result_t dispatch_result;
  int event_result;

  if (result != MESH_MGMT_CONNECTION_OK)
    return result;
  transport_result = mesh_mgmt_transport_receive_v1(&connection->transport, &receipt);
  connection->last_transport_result = transport_result;
  if (transport_result != MESH_MGMT_TRANSPORT_OK)
    return connection_fail(connection, MESH_MGMT_CONNECTION_TRANSPORT_FAILED);

  dispatch_result = mesh_mgmt_dispatcher_receive_v1(
      &connection->dispatcher, receipt.frame, receipt.frame_len, connection->transport_peer_id,
      now_ms, &event, &connection->last_dispatch_stage);
  connection->last_dispatch_result = dispatch_result;
  if (dispatch_result != MESH_MGMT_DISPATCH_OK) {
    transport_result = mesh_mgmt_transport_commit_v1(&connection->transport, &receipt);
    connection->last_transport_result = transport_result;
    if (transport_result != MESH_MGMT_TRANSPORT_OK) {
      return connection_fail(connection, MESH_MGMT_CONNECTION_TRANSPORT_FAILED);
    }
    return connection_fail(connection, MESH_MGMT_CONNECTION_DISPATCH_FAILED);
  }

  connection->in_event_callback = 1;
  event_result = connection->on_event(connection->event_context, &event);
  connection->in_event_callback = 0;
  connection->last_event_result = event_result;

  transport_result = mesh_mgmt_transport_commit_v1(&connection->transport, &receipt);
  connection->last_transport_result = transport_result;
  if (transport_result != MESH_MGMT_TRANSPORT_OK)
    return connection_fail(connection, MESH_MGMT_CONNECTION_TRANSPORT_FAILED);
  if (event_result != 0)
    return connection_fail(connection, MESH_MGMT_CONNECTION_EVENT_REJECTED);

  connection->last_error = MESH_MGMT_CONNECTION_OK;
  return MESH_MGMT_CONNECTION_OK;
}

mesh_mgmt_connection_result_t
mesh_mgmt_connection_send_hello_v1(mesh_mgmt_connection_v1_t *connection, const uint8_t *frame,
                                   size_t frame_len) {
  mesh_mgmt_connection_result_t result = require_ready(connection);

  if (result != MESH_MGMT_CONNECTION_OK)
    return result;
  if (connection->dispatcher.session.state != MESH_MGMT_SESSION_NEGOTIATING ||
      connection->dispatcher.session.local_hello_sent)
    return MESH_MGMT_CONNECTION_INVALID_STATE;
  return send_and_mark(connection, frame, frame_len, MESH_MGMT_KIND_HELLO,
                       mesh_mgmt_dispatcher_mark_hello_sent_v1);
}

mesh_mgmt_connection_result_t
mesh_mgmt_connection_send_hello_ack_v1(mesh_mgmt_connection_v1_t *connection, const uint8_t *frame,
                                       size_t frame_len) {
  mesh_mgmt_connection_result_t result = require_ready(connection);

  if (result != MESH_MGMT_CONNECTION_OK)
    return result;
  if (connection->dispatcher.session.state != MESH_MGMT_SESSION_NEGOTIATING ||
      !connection->dispatcher.session.remote_hello_verified ||
      connection->dispatcher.session.local_ack_sent)
    return MESH_MGMT_CONNECTION_INVALID_STATE;
  return send_and_mark(connection, frame, frame_len, MESH_MGMT_KIND_HELLO_ACK,
                       mesh_mgmt_dispatcher_mark_ack_sent_v1);
}

mesh_mgmt_connection_result_t mesh_mgmt_connection_send_v1(mesh_mgmt_connection_v1_t *connection,
                                                           const uint8_t *frame, size_t frame_len) {
  mesh_mgmt_connection_result_t result = require_ready(connection);
  mesh_mgmt_transport_result_t transport_result;
  uint8_t kind = 0u;

  if (result != MESH_MGMT_CONNECTION_OK)
    return result;
  result = decode_outbound_kind(connection, frame, frame_len, &kind);
  if (result != MESH_MGMT_CONNECTION_OK)
    return result;
  if (connection->dispatcher.session.state != MESH_MGMT_SESSION_ESTABLISHED)
    return MESH_MGMT_CONNECTION_INVALID_STATE;
  if (kind == MESH_MGMT_KIND_HELLO || kind == MESH_MGMT_KIND_HELLO_ACK)
    return MESH_MGMT_CONNECTION_INVALID_FRAME;
  if (!mesh_mgmt_dispatch_kind_is_observer_safe_v1(kind)) {
    connection->last_dispatch_result = MESH_MGMT_DISPATCH_SIDE_EFFECT_DISABLED;
    connection->last_dispatch_stage = MESH_MGMT_DISPATCH_STAGE_SESSION;
    return MESH_MGMT_CONNECTION_INVALID_FRAME;
  }
  if (mesh_mgmt_session_authorize_kind_v1(&connection->dispatcher.session, kind) !=
      MESH_MGMT_SESSION_OK) {
    connection->last_dispatch_result = MESH_MGMT_DISPATCH_UNSUPPORTED_FEATURE;
    connection->last_dispatch_stage = MESH_MGMT_DISPATCH_STAGE_SESSION;
    return MESH_MGMT_CONNECTION_INVALID_STATE;
  }

  transport_result = mesh_mgmt_transport_send_v1(&connection->transport, frame, frame_len);
  connection->last_transport_result = transport_result;
  if (transport_result != MESH_MGMT_TRANSPORT_OK)
    return connection_fail(connection, MESH_MGMT_CONNECTION_TRANSPORT_FAILED);
  connection->last_error = MESH_MGMT_CONNECTION_OK;
  return MESH_MGMT_CONNECTION_OK;
}
