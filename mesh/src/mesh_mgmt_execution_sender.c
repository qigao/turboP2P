#include "mesh_mgmt_execution_sender.h"

#include "mesh_mgmt_crypto.h"

static uint16_t status_code_from_service(
    mesh_mgmt_execution_service_result_t result) {
  switch (result) {
    case MESH_MGMT_EXECUTION_SERVICE_DISABLED:
      return MESH_MGMT_EXECUTION_STATUS_DISABLED;
    case MESH_MGMT_EXECUTION_SERVICE_INVALID_ARG:
    case MESH_MGMT_EXECUTION_SERVICE_INVALID_COMMAND:
      return MESH_MGMT_EXECUTION_STATUS_INVALID_COMMAND;
    case MESH_MGMT_EXECUTION_SERVICE_AUTH_FAILED:
      return MESH_MGMT_EXECUTION_STATUS_AUTH_FAILED;
    case MESH_MGMT_EXECUTION_SERVICE_CONFLICT:
      return MESH_MGMT_EXECUTION_STATUS_CONFLICT;
    case MESH_MGMT_EXECUTION_SERVICE_RESOURCE_EXHAUSTED:
    case MESH_MGMT_EXECUTION_SERVICE_BUSY:
      return MESH_MGMT_EXECUTION_STATUS_BUSY;
    case MESH_MGMT_EXECUTION_SERVICE_INDETERMINATE:
      return MESH_MGMT_EXECUTION_STATUS_INDETERMINATE;
    case MESH_MGMT_EXECUTION_SERVICE_STORE_FAILED:
      return MESH_MGMT_EXECUTION_STATUS_STORE_FAILED;
    case MESH_MGMT_EXECUTION_SERVICE_SIGN_FAILED:
    case MESH_MGMT_EXECUTION_SERVICE_CLOCK_FAILED:
    case MESH_MGMT_EXECUTION_SERVICE_ENCODE_FAILED:
    default:
      return MESH_MGMT_EXECUTION_STATUS_INTERNAL;
  }
}

static mesh_mgmt_execution_sender_result_t prepare_item(
    const mesh_mgmt_execution_egress_item_v1_t *item,
    mesh_mgmt_execution_status_v1_t *status,
    uint8_t *out_kind,
    const uint8_t **out_payload,
    size_t *out_payload_size) {
  if (item->service_result == MESH_MGMT_EXECUTION_SERVICE_OK) {
    if (item->result_payload_size !=
        MESH_MGMT_EXECUTION_COMMAND_RESULT_SIZE_V1)
      return MESH_MGMT_EXECUTION_SENDER_UNSUPPORTED_RESULT;
    *out_kind = MESH_MGMT_KIND_COMMAND_RESULT;
    *out_payload = item->result_payload;
    *out_payload_size = item->result_payload_size;
    return MESH_MGMT_EXECUTION_SENDER_OK;
  }

  memset(status, 0, sizeof(*status));
  status->version = MESH_MGMT_EXECUTION_SCHEMA_V1;
  status->code = status_code_from_service(item->service_result);
  memcpy(status->command_id, item->command_id, sizeof(status->command_id));
  memcpy(status->correlation_id, item->correlation_id,
         sizeof(status->correlation_id));
  memcpy(status->request_digest, item->request_digest,
         sizeof(status->request_digest));
  memcpy(status->responder_node_id, item->executor_node_id,
         sizeof(status->responder_node_id));
  if (mesh_mgmt_execution_command_status_encode_v1(
          status, (uint8_t *)item->result_payload,
          sizeof(item->result_payload), out_payload_size) !=
      MESH_MGMT_EXECUTION_WIRE_OK)
    return MESH_MGMT_EXECUTION_SENDER_ENCODE_FAILED;
  *out_kind = MESH_MGMT_KIND_COMMAND_STATUS;
  *out_payload = item->result_payload;
  return MESH_MGMT_EXECUTION_SENDER_OK;
}

mesh_mgmt_execution_sender_result_t mesh_mgmt_execution_sender_send_next_v1(
    mesh_mgmt_execution_egress_v1_t *egress,
    mesh_mgmt_peer_signer_v1_t *signer,
    mesh_mgmt_connection_v1_t *connection) {
  mesh_mgmt_execution_egress_item_v1_t item;
  mesh_mgmt_execution_egress_result_t egress_result;
  mesh_mgmt_peer_signer_result_t signer_result;
  mesh_mgmt_connection_result_t connection_result;
  mesh_mgmt_execution_status_v1_t status;
  uint8_t status_payload[MESH_MGMT_EXECUTION_COMMAND_STATUS_SIZE_V1];
  const uint8_t *payload;
  size_t payload_size;
  uint8_t kind;
  const uint8_t *frame = NULL;
  size_t frame_len = 0u;

  if (egress == NULL || signer == NULL || connection == NULL)
    return MESH_MGMT_EXECUTION_SENDER_INVALID_ARG;
  egress_result = mesh_mgmt_execution_egress_peek_v1(egress, &item);
  if (egress_result == MESH_MGMT_EXECUTION_EGRESS_EMPTY)
    return MESH_MGMT_EXECUTION_SENDER_EMPTY;
  if (egress_result != MESH_MGMT_EXECUTION_EGRESS_OK)
    return MESH_MGMT_EXECUTION_SENDER_INVALID_ARG;
  if (!mesh_mgmt_crypto_equal_32(
          item.target_node_id,
          connection->dispatcher.session.remote_certificate.managed_node_id) ||
      !mesh_mgmt_crypto_equal_32(
          item.executor_node_id, signer->origin_node_id))
    return MESH_MGMT_EXECUTION_SENDER_TARGET_MISMATCH;

  if (item.service_result != MESH_MGMT_EXECUTION_SERVICE_OK)
    memset(item.result_payload, 0, sizeof(item.result_payload));
  if (prepare_item(&item, &status, &kind, &payload, &payload_size) !=
      MESH_MGMT_EXECUTION_SENDER_OK)
    return item.service_result == MESH_MGMT_EXECUTION_SERVICE_OK
               ? MESH_MGMT_EXECUTION_SENDER_UNSUPPORTED_RESULT
               : MESH_MGMT_EXECUTION_SENDER_ENCODE_FAILED;

  signer_result = mesh_mgmt_peer_signer_build_targeted_v1(
      signer, kind, item.target_node_id, payload, payload_size,
      &frame, &frame_len);
  if (signer_result != MESH_MGMT_PEER_SIGNER_OK)
    return MESH_MGMT_EXECUTION_SENDER_SIGN_FAILED;
  connection_result =
      mesh_mgmt_connection_send_v1(connection, frame, frame_len);
  if (connection_result != MESH_MGMT_CONNECTION_OK)
    return MESH_MGMT_EXECUTION_SENDER_SEND_FAILED;
  if (mesh_mgmt_execution_egress_consume_v1(egress) !=
      MESH_MGMT_EXECUTION_EGRESS_OK)
    return MESH_MGMT_EXECUTION_SENDER_COMMIT_FAILED;
  return MESH_MGMT_EXECUTION_SENDER_OK;
}

mesh_mgmt_execution_sender_result_t
mesh_mgmt_execution_sender_send_next_runtime_v1(
    mesh_mgmt_execution_egress_v1_t *egress,
    mesh_mgmt_agent_runtime_v1_t *runtime) {
  mesh_mgmt_execution_egress_item_v1_t item;
  mesh_mgmt_execution_egress_result_t egress_result;
  mesh_mgmt_execution_sender_result_t prepare_result;
  mesh_mgmt_execution_status_v1_t status;
  const uint8_t *payload = NULL;
  size_t payload_size = 0u;
  uint8_t kind = 0u;

  if (!egress || !runtime)
    return MESH_MGMT_EXECUTION_SENDER_INVALID_ARG;
  egress_result = mesh_mgmt_execution_egress_peek_v1(egress, &item);
  if (egress_result == MESH_MGMT_EXECUTION_EGRESS_EMPTY)
    return MESH_MGMT_EXECUTION_SENDER_EMPTY;
  if (egress_result != MESH_MGMT_EXECUTION_EGRESS_OK)
    return MESH_MGMT_EXECUTION_SENDER_INVALID_ARG;
  if (!runtime->router.signer_template ||
      !mesh_mgmt_crypto_equal_32(
          item.executor_node_id,
          runtime->router.signer_template->hello.managed_node_id))
    return MESH_MGMT_EXECUTION_SENDER_TARGET_MISMATCH;

  if (item.service_result != MESH_MGMT_EXECUTION_SERVICE_OK)
    memset(item.result_payload, 0, sizeof(item.result_payload));
  prepare_result =
      prepare_item(&item, &status, &kind, &payload, &payload_size);
  if (prepare_result != MESH_MGMT_EXECUTION_SENDER_OK)
    return prepare_result;
  if (mesh_mgmt_agent_runtime_send_execution_response_v1(
          runtime, kind, item.target_node_id, payload, payload_size) !=
      MESH_MGMT_AGENT_RUNTIME_OK)
    return MESH_MGMT_EXECUTION_SENDER_SEND_FAILED;
  if (mesh_mgmt_execution_egress_consume_v1(egress) !=
      MESH_MGMT_EXECUTION_EGRESS_OK)
    return MESH_MGMT_EXECUTION_SENDER_COMMIT_FAILED;
  return MESH_MGMT_EXECUTION_SENDER_OK;
}
