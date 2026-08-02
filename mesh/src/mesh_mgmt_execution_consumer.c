#include "mesh_mgmt_execution_consumer.h"

#include "mesh_mgmt_crypto.h"

#include <string.h>

static mesh_mgmt_execution_consumer_result_t map_dispatch_result(
    mesh_mgmt_dispatch_result_t result) {
  switch (result) {
    case MESH_MGMT_DISPATCH_OK:
      return MESH_MGMT_EXECUTION_CONSUMER_OK;
    case MESH_MGMT_DISPATCH_AUTH_FAILED:
      return MESH_MGMT_EXECUTION_CONSUMER_AUTH_FAILED;
    case MESH_MGMT_DISPATCH_EXPIRED:
      return MESH_MGMT_EXECUTION_CONSUMER_EXPIRED;
    case MESH_MGMT_DISPATCH_UNSUPPORTED_FEATURE:
      return MESH_MGMT_EXECUTION_CONSUMER_UNSUPPORTED_FEATURE;
    case MESH_MGMT_DISPATCH_NOT_ESTABLISHED:
    case MESH_MGMT_DISPATCH_SIDE_EFFECT_DISABLED:
    case MESH_MGMT_DISPATCH_INVALID_STATE:
      return MESH_MGMT_EXECUTION_CONSUMER_INVALID_STATE;
    case MESH_MGMT_DISPATCH_CRYPTO_FAILURE:
      return MESH_MGMT_EXECUTION_CONSUMER_CRYPTO_FAILED;
    case MESH_MGMT_DISPATCH_INVALID_ARG:
      return MESH_MGMT_EXECUTION_CONSUMER_INVALID_ARG;
    case MESH_MGMT_DISPATCH_INVALID_FRAME:
    case MESH_MGMT_DISPATCH_UNSUPPORTED_VERSION:
    case MESH_MGMT_DISPATCH_REPLAYED:
    case MESH_MGMT_DISPATCH_RESOURCE_EXHAUSTED:
    default:
      return MESH_MGMT_EXECUTION_CONSUMER_INVALID_SCHEMA;
  }
}

static int event_matches_session(
    const mesh_mgmt_dispatcher_v1_t *dispatcher,
    const mesh_mgmt_dispatch_event_v1_t *event) {
  const mesh_mgmt_session_v1_t *session = &dispatcher->session;

  return event->type ==
             MESH_MGMT_DISPATCH_EVENT_NODE_EXECUTION_REQUEST_SHADOW &&
         event->kind == MESH_MGMT_KIND_COMMAND_REQUEST &&
         event->envelope.frame.kind == MESH_MGMT_KIND_COMMAND_REQUEST &&
         event->envelope.frame.payload != NULL &&
         mesh_mgmt_crypto_equal_32(
             event->envelope.header.mesh_id_hash,
             session->config.expected_mesh_id_hash) &&
         mesh_mgmt_crypto_equal_32(
             event->envelope.header.origin_node_id,
             session->remote_certificate.managed_node_id) &&
         mesh_mgmt_crypto_equal_32(
             event->envelope.header.origin_principal_key,
             session->remote_certificate.management_key) &&
         event->envelope.header.certificate_serial ==
             session->remote_certificate.serial &&
         event->envelope.header.principal_epoch ==
             session->remote_certificate.principal_epoch &&
         event->envelope.header.incarnation == session->remote_incarnation &&
         mesh_mgmt_crypto_equal_16(
             event->envelope.header.session_id,
             session->remote_session_id);
}

mesh_mgmt_execution_consumer_result_t
mesh_mgmt_execution_shadow_command_from_event_v1(
    const mesh_mgmt_dispatcher_v1_t *dispatcher,
    const mesh_mgmt_dispatch_event_v1_t *event,
    uint64_t now_ms,
    mesh_mgmt_execution_shadow_command_v1_t *out_command) {
  mesh_mgmt_dispatch_result_t dispatch_result;
  mesh_mgmt_execution_wire_result_t wire_result;
  mesh_mgmt_execution_result_codec_result_t digest_result;

  if (!dispatcher || !event || !out_command)
    return MESH_MGMT_EXECUTION_CONSUMER_INVALID_ARG;
  memset(out_command, 0, sizeof(*out_command));
  if (dispatcher->session.state != MESH_MGMT_SESSION_ESTABLISHED ||
      !dispatcher->enable_node_execution_shadow)
    return MESH_MGMT_EXECUTION_CONSUMER_INVALID_STATE;
  if (!event_matches_session(dispatcher, event))
    return MESH_MGMT_EXECUTION_CONSUMER_AUTH_FAILED;

  dispatch_result = mesh_mgmt_dispatcher_validate_node_execution_shadow_v1(
      dispatcher, event->envelope.frame.payload,
      event->envelope.frame.payload_len, now_ms);
  if (dispatch_result != MESH_MGMT_DISPATCH_OK)
    return map_dispatch_result(dispatch_result);
  wire_result = mesh_mgmt_execution_command_request_decode_v1(
      event->envelope.frame.payload, event->envelope.frame.payload_len,
      &out_command->grant, &out_command->request);
  if (wire_result != MESH_MGMT_EXECUTION_WIRE_OK) {
    memset(out_command, 0, sizeof(*out_command));
    return MESH_MGMT_EXECUTION_CONSUMER_INVALID_SCHEMA;
  }
  digest_result = mesh_mgmt_execution_request_digest_v1(
      &out_command->request, out_command->request_digest);
  if (digest_result != MESH_MGMT_EXECUTION_RESULT_OK) {
    memset(out_command, 0, sizeof(*out_command));
    return digest_result == MESH_MGMT_EXECUTION_RESULT_CRYPTO_FAILED
               ? MESH_MGMT_EXECUTION_CONSUMER_CRYPTO_FAILED
               : MESH_MGMT_EXECUTION_CONSUMER_INVALID_SCHEMA;
  }
  memcpy(out_command->reply_node_id,
         event->envelope.header.origin_node_id,
         sizeof(out_command->reply_node_id));
  return MESH_MGMT_EXECUTION_CONSUMER_OK;
}
