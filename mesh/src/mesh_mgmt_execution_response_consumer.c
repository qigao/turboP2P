#include "mesh_mgmt_execution_response_consumer.h"

#include "mesh_mgmt_crypto.h"

#include <string.h>

mesh_mgmt_execution_response_consumer_result_t
mesh_mgmt_execution_response_from_event_v1(
    const mesh_mgmt_dispatcher_v1_t *dispatcher,
    const mesh_mgmt_dispatch_event_v1_t *event,
    mesh_mgmt_execution_response_v1_t *out_response) {
  mesh_mgmt_execution_wire_result_t wire_result;

  if (!dispatcher || !event || !out_response)
    return MESH_MGMT_EXECUTION_RESPONSE_CONSUMER_INVALID_ARG;
  memset(out_response, 0, sizeof(*out_response));
  if (dispatcher->session.state != MESH_MGMT_SESSION_ESTABLISHED ||
      !dispatcher->enable_node_execution_shadow)
    return MESH_MGMT_EXECUTION_RESPONSE_CONSUMER_INVALID_STATE;
  if ((event->type !=
           MESH_MGMT_DISPATCH_EVENT_NODE_EXECUTION_RESULT_SHADOW &&
       event->type !=
           MESH_MGMT_DISPATCH_EVENT_NODE_EXECUTION_STATUS_SHADOW) ||
      event->kind != event->envelope.frame.kind ||
      !mesh_mgmt_crypto_equal_32(
          event->envelope.header.origin_node_id,
          dispatcher->session.remote_certificate.managed_node_id) ||
      !mesh_mgmt_crypto_equal_32(
          event->envelope.header.origin_principal_key,
          dispatcher->session.remote_certificate.management_key))
    return MESH_MGMT_EXECUTION_RESPONSE_CONSUMER_AUTH_FAILED;

  out_response->kind = event->kind;
  memcpy(out_response->origin_node_id,
         event->envelope.header.origin_node_id,
         sizeof(out_response->origin_node_id));
  memcpy(out_response->target_node_id,
         event->envelope.header.target_node_id,
         sizeof(out_response->target_node_id));
  if (event->kind == MESH_MGMT_KIND_COMMAND_RESULT) {
    wire_result = mesh_mgmt_execution_command_result_decode_v1(
        event->envelope.frame.payload, event->envelope.frame.payload_len,
        &out_response->result);
    if (wire_result != MESH_MGMT_EXECUTION_WIRE_OK ||
        mesh_mgmt_execution_result_verify_v1(
            &out_response->result,
            out_response->result.signer_public_key) !=
            MESH_MGMT_EXECUTION_RESULT_OK ||
        !mesh_mgmt_crypto_equal_32(
            out_response->result.target_node_id,
            out_response->origin_node_id)) {
      memset(out_response, 0, sizeof(*out_response));
      return MESH_MGMT_EXECUTION_RESPONSE_CONSUMER_AUTH_FAILED;
    }
  } else if (event->kind == MESH_MGMT_KIND_COMMAND_STATUS) {
    wire_result = mesh_mgmt_execution_command_status_decode_v1(
        event->envelope.frame.payload, event->envelope.frame.payload_len,
        &out_response->status);
    if (wire_result != MESH_MGMT_EXECUTION_WIRE_OK) {
      memset(out_response, 0, sizeof(*out_response));
      return MESH_MGMT_EXECUTION_RESPONSE_CONSUMER_INVALID_SCHEMA;
    }
    if (!mesh_mgmt_crypto_equal_32(
            out_response->status.responder_node_id,
            out_response->origin_node_id)) {
      memset(out_response, 0, sizeof(*out_response));
      return MESH_MGMT_EXECUTION_RESPONSE_CONSUMER_AUTH_FAILED;
    }
  } else {
    memset(out_response, 0, sizeof(*out_response));
    return MESH_MGMT_EXECUTION_RESPONSE_CONSUMER_INVALID_SCHEMA;
  }
  return MESH_MGMT_EXECUTION_RESPONSE_CONSUMER_OK;
}
