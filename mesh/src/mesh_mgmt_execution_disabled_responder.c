#include "mesh_mgmt_execution_disabled_responder.h"

#include "mesh_mgmt_crypto.h"

#include <string.h>

mesh_mgmt_execution_disabled_responder_result_t
mesh_mgmt_execution_disabled_status_from_command_v1(
    const mesh_mgmt_execution_shadow_command_v1_t *command,
    mesh_mgmt_execution_status_v1_t *out_status) {
  if (!command || !out_status)
    return MESH_MGMT_EXECUTION_DISABLED_RESPONDER_INVALID_ARG;
  memset(out_status, 0, sizeof(*out_status));
  out_status->version = MESH_MGMT_EXECUTION_SCHEMA_V1;
  out_status->code = MESH_MGMT_EXECUTION_STATUS_DISABLED;
  memcpy(out_status->command_id, command->request.command_id,
         sizeof(out_status->command_id));
  memcpy(out_status->correlation_id, command->request.correlation_id,
         sizeof(out_status->correlation_id));
  memcpy(out_status->request_digest, command->request_digest,
         sizeof(out_status->request_digest));
  memcpy(out_status->responder_node_id, command->request.target_node_id,
         sizeof(out_status->responder_node_id));
  return MESH_MGMT_EXECUTION_DISABLED_RESPONDER_OK;
}

mesh_mgmt_execution_disabled_responder_result_t
mesh_mgmt_execution_status_response_from_command_v1(
    const mesh_mgmt_execution_shadow_command_v1_t *command,
    uint16_t status_code,
    mesh_mgmt_peer_signer_v1_t *signer,
    mesh_mgmt_connection_v1_t *connection) {
  mesh_mgmt_execution_status_v1_t status;
  const uint8_t *frame = NULL;
  size_t frame_size = 0u;
  size_t payload_size = 0u;
  uint8_t payload[MESH_MGMT_EXECUTION_COMMAND_STATUS_SIZE_V1];

  if (!command || !signer || !connection)
    return MESH_MGMT_EXECUTION_DISABLED_RESPONDER_INVALID_ARG;
  if (connection->state != MESH_MGMT_CONNECTION_READY)
    return MESH_MGMT_EXECUTION_DISABLED_RESPONDER_INVALID_STATE;
  if (!mesh_mgmt_crypto_equal_32(
          command->reply_node_id,
          connection->dispatcher.session.remote_certificate.managed_node_id) ||
      !mesh_mgmt_crypto_equal_32(command->request.target_node_id,
                                 signer->origin_node_id))
    return MESH_MGMT_EXECUTION_DISABLED_RESPONDER_TARGET_MISMATCH;

  memset(&status, 0, sizeof(status));
  status.version = MESH_MGMT_EXECUTION_SCHEMA_V1;
  status.code = status_code;
  memcpy(status.command_id, command->request.command_id,
         sizeof(status.command_id));
  memcpy(status.correlation_id, command->request.correlation_id,
         sizeof(status.correlation_id));
  memcpy(status.request_digest, command->request_digest,
         sizeof(status.request_digest));
  memcpy(status.responder_node_id, command->request.target_node_id,
         sizeof(status.responder_node_id));
  if (mesh_mgmt_execution_command_status_encode_v1(
          &status, payload, sizeof(payload), &payload_size) !=
      MESH_MGMT_EXECUTION_WIRE_OK)
    return MESH_MGMT_EXECUTION_DISABLED_RESPONDER_ENCODE_FAILED;
  if (mesh_mgmt_peer_signer_build_targeted_v1(
          signer, MESH_MGMT_KIND_COMMAND_STATUS, command->reply_node_id,
          payload, payload_size, &frame, &frame_size) !=
      MESH_MGMT_PEER_SIGNER_OK)
    return MESH_MGMT_EXECUTION_DISABLED_RESPONDER_SIGN_FAILED;
  if (mesh_mgmt_connection_send_event_response_v1(
          connection, frame, frame_size) != MESH_MGMT_CONNECTION_OK)
    return MESH_MGMT_EXECUTION_DISABLED_RESPONDER_SEND_FAILED;
  return MESH_MGMT_EXECUTION_DISABLED_RESPONDER_OK;
}

mesh_mgmt_execution_disabled_responder_result_t
mesh_mgmt_execution_disabled_response_from_event_v1(
    const mesh_mgmt_dispatcher_v1_t *dispatcher,
    const mesh_mgmt_dispatch_event_v1_t *event,
    uint64_t now_ms,
    mesh_mgmt_peer_signer_v1_t *signer,
    mesh_mgmt_connection_v1_t *connection) {
  mesh_mgmt_execution_shadow_command_v1_t command;
  mesh_mgmt_execution_consumer_result_t consumer_result;

  if (!dispatcher || !event || !signer || !connection || now_ms == 0u)
    return MESH_MGMT_EXECUTION_DISABLED_RESPONDER_INVALID_ARG;
  if (connection->state != MESH_MGMT_CONNECTION_READY ||
      dispatcher != &connection->dispatcher)
    return MESH_MGMT_EXECUTION_DISABLED_RESPONDER_INVALID_STATE;
  memset(&command, 0, sizeof(command));
  consumer_result = mesh_mgmt_execution_shadow_command_from_event_v1(
      dispatcher, event, now_ms, &command);
  if (consumer_result != MESH_MGMT_EXECUTION_CONSUMER_OK)
    return MESH_MGMT_EXECUTION_DISABLED_RESPONDER_CONSUMER_FAILED;
  return mesh_mgmt_execution_status_response_from_command_v1(
      &command, MESH_MGMT_EXECUTION_STATUS_DISABLED, signer, connection);
}
