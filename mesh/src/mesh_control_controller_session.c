#include "mesh_control_controller_session.h"

#include "mesh_control_status.h"
#include "mesh_control_mmp.h"
#include "mesh_mgmt_envelope.h"

#include <stdlib.h>
#include <string.h>

enum {
  CONTROLLER_PENDING_NONE = 0,
  CONTROLLER_PENDING_AGENT = 1,
  CONTROLLER_PENDING_SUBMIT = 2
};

struct mesh_control_controller_session_record_v1 {
  uint8_t node_id[MESH_CONTROL_NODE_ID_SIZE];
  uint8_t session_id[MESH_CONTROL_ID_SIZE];
  uint8_t tls_certificate_sha256[MESH_CONTROL_DIGEST_SIZE];
  uint64_t generation;
  uint64_t identity_policy_generation;
  uint64_t connected_at_ms;
  uint8_t active;
};

static int zero_bytes(const uint8_t *bytes, size_t size) {
  size_t index;
  uint8_t value = 0u;
  if (!bytes) return 1;
  for (index = 0u; index < size; ++index) value |= bytes[index];
  return value == 0u;
}

static mesh_control_controller_session_record_v1_t *find_session(
    mesh_control_controller_session_v1_t *controller,
    const uint8_t node_id[MESH_CONTROL_NODE_ID_SIZE]) {
  size_t index;
  for (index = 0u; index < controller->config.session_capacity; ++index) {
    mesh_control_controller_session_record_v1_t *record =
        &controller->sessions[index];
    if (record->active &&
        mesh_mgmt_crypto_equal_32(record->node_id, node_id))
      return record;
  }
  return NULL;
}

static mesh_control_controller_session_record_v1_t *allocate_session(
    mesh_control_controller_session_v1_t *controller,
    const uint8_t node_id[MESH_CONTROL_NODE_ID_SIZE]) {
  size_t index;
  mesh_control_controller_session_record_v1_t *record =
      find_session(controller, node_id);
  if (record) return record;
  for (index = 0u; index < controller->config.session_capacity; ++index) {
    record = &controller->sessions[index];
    if (!record->active) return record;
  }
  return NULL;
}

static int session_matches(
    const mesh_control_controller_session_record_v1_t *record,
    const mesh_control_agent_sync_message_v1_t *message,
    const uint8_t tls_digest[MESH_CONTROL_DIGEST_SIZE]) {
  return record && record->active &&
         mesh_mgmt_crypto_equal_32(record->node_id, message->node_id) &&
         mesh_mgmt_crypto_equal_16(record->session_id, message->session_id) &&
         record->generation == message->session_generation &&
         mesh_mgmt_crypto_equal_32(record->tls_certificate_sha256, tls_digest);
}

static uint64_t next_token(mesh_control_controller_session_v1_t *controller) {
  controller->next_request_token++;
  if (controller->next_request_token == 0u) controller->next_request_token++;
  return controller->next_request_token;
}

static mesh_control_result_t worker_result(
    mesh_control_durable_outbox_worker_result_t result) {
  switch (result) {
    case MESH_CONTROL_DURABLE_OUTBOX_WORKER_OK:
      return MESH_CONTROL_OK;
    case MESH_CONTROL_DURABLE_OUTBOX_WORKER_FULL:
      return MESH_CONTROL_RESOURCE_EXHAUSTED;
    case MESH_CONTROL_DURABLE_OUTBOX_WORKER_EMPTY:
      return MESH_CONTROL_EMPTY;
    case MESH_CONTROL_DURABLE_OUTBOX_WORKER_RESOURCE_EXHAUSTED:
      return MESH_CONTROL_RESOURCE_EXHAUSTED;
    default:
      return MESH_CONTROL_INVALID_STATE;
  }
}

static int time_valid(const mesh_control_controller_session_v1_t *controller,
                      uint64_t sent_at_ms, uint64_t now_ms) {
  uint64_t skew = controller->config.maximum_clock_skew_ms;
  if (sent_at_ms > now_ms)
    return sent_at_ms - now_ms <= skew;
  return now_ms - sent_at_ms <= skew;
}

static void retain_pending(
    mesh_control_controller_session_v1_t *controller,
    const mesh_control_agent_sync_message_v1_t *message,
    const uint8_t tls_digest[MESH_CONTROL_DIGEST_SIZE], uint8_t operation) {
  controller->pending = *message;
  memcpy(controller->pending_tls_digest, tls_digest,
         sizeof(controller->pending_tls_digest));
  if (message->payload_size != 0u) {
    memcpy(controller->pending_payload, message->payload,
           message->payload_size);
    controller->pending.payload = controller->pending_payload;
  } else {
    controller->pending.payload = NULL;
  }
  controller->pending_operation = operation;
  controller->pending_source = CONTROLLER_PENDING_AGENT;
}

mesh_control_result_t mesh_control_controller_session_init_v1(
    mesh_control_controller_session_v1_t *controller,
    const mesh_control_controller_session_config_v1_t *config,
    size_t *out_recovered_claims) {
  mesh_control_durable_outbox_worker_result_t result;
  if (!controller || controller->initialized || !config ||
      !out_recovered_claims || config->session_capacity == 0u ||
      config->session_capacity > config->outbox.session_capacity ||
      config->outbox.max_payload_size == 0u ||
      config->outbox.max_payload_size >
          MESH_CONTROL_AGENT_SYNC_MAX_PAYLOAD_V1 ||
      config->claim_lease_ms == 0u ||
      config->claim_lease_ms > config->outbox.max_claim_lease_ms ||
      config->maximum_clock_skew_ms == 0u ||
      config->maximum_hello_lifetime_ms == 0u ||
      !config->authorize_identity)
    return MESH_CONTROL_INVALID_ARG;
  memset(controller, 0, sizeof(*controller));
  controller->sessions = (mesh_control_controller_session_record_v1_t *)calloc(
      config->session_capacity, sizeof(*controller->sessions));
  if (!controller->sessions) return MESH_CONTROL_RESOURCE_EXHAUSTED;
  controller->worker_payload =
      (uint8_t *)calloc(1u, config->outbox.max_payload_size);
  if (!controller->worker_payload) {
    free(controller->sessions);
    memset(controller, 0, sizeof(*controller));
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  }
  controller->worker_payload_capacity = config->outbox.max_payload_size;
  controller->config = *config;
  result = mesh_control_durable_outbox_worker_init_v1(
      &controller->worker, &config->outbox, out_recovered_claims);
  if (result != MESH_CONTROL_DURABLE_OUTBOX_WORKER_OK) {
    memset(controller->worker_payload, 0,
           controller->worker_payload_capacity);
    free(controller->worker_payload);
    free(controller->sessions);
    memset(controller, 0, sizeof(*controller));
    return MESH_CONTROL_INVALID_STATE;
  }
  controller->next_request_token = 1u;
  controller->accepting = 1u;
  controller->initialized = 1u;
  return MESH_CONTROL_OK;
}

static mesh_control_result_t receive_hello(
    mesh_control_controller_session_v1_t *controller,
    const uint8_t tls_digest[MESH_CONTROL_DIGEST_SIZE],
    const mesh_control_agent_sync_message_v1_t *message, uint64_t now_ms) {
  mesh_control_agent_sync_hello_v1_t hello;
  mesh_control_agent_sync_hello_policy_v1_t policy;
  mesh_control_result_t auth_result;
  mesh_control_durable_outbox_worker_result_t result;
  uint64_t token;
  if (mesh_control_agent_sync_hello_decode_v1(
          message->payload, message->payload_size, &hello) !=
      MESH_CONTROL_AGENT_SYNC_OK)
    return MESH_CONTROL_INVALID_ARG;
  memset(&policy, 0, sizeof(policy));
  auth_result = controller->config.authorize_identity(
      controller->config.identity_context, message->node_id, tls_digest,
      &policy);
  if (auth_result != MESH_CONTROL_OK) return MESH_CONTROL_UNAUTHORIZED;
  memcpy(policy.actual_tls_certificate_sha256, tls_digest,
         sizeof(policy.actual_tls_certificate_sha256));
  policy.now_ms = now_ms;
  policy.maximum_clock_skew_ms = controller->config.maximum_clock_skew_ms;
  policy.maximum_hello_lifetime_ms =
      controller->config.maximum_hello_lifetime_ms;
  if (mesh_control_agent_sync_hello_verify_v1(message, &hello, &policy) !=
      MESH_CONTROL_AGENT_SYNC_OK)
    return MESH_CONTROL_UNAUTHORIZED;
  token = next_token(controller);
  result = mesh_control_durable_outbox_worker_try_activate_session_v1(
      &controller->worker, token, message->node_id, message->session_id,
      now_ms);
  if (result != MESH_CONTROL_DURABLE_OUTBOX_WORKER_OK)
    return worker_result(result);
  retain_pending(controller, message, tls_digest,
                 MESH_CONTROL_DURABLE_OUTBOX_WORKER_ACTIVATE_SESSION);
  controller->pending_worker_token = token;
  controller->pending_identity_policy_generation =
      policy.identity_policy_generation;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_controller_session_receive_v1(
    mesh_control_controller_session_v1_t *controller,
    const uint8_t tls_digest[MESH_CONTROL_DIGEST_SIZE], const uint8_t *frame,
    size_t frame_size, uint64_t now_ms) {
  mesh_control_agent_sync_message_v1_t message;
  mesh_control_controller_session_record_v1_t *record;
  mesh_control_receipt_v1_t receipt;
  mesh_control_agent_sync_hello_policy_v1_t current_policy;
  mesh_control_result_t auth_result;
  mesh_control_durable_outbox_worker_result_t result;
  uint64_t token;
  if (!controller || !controller->initialized || !controller->accepting ||
      controller->faulted || !tls_digest || zero_bytes(tls_digest, 32u) ||
      !frame || now_ms == 0u)
    return MESH_CONTROL_INVALID_ARG;
  controller->counters.received++;
  if (controller->pending_operation || controller->response_ready ||
      controller->submit_completion_ready) {
    controller->counters.rejected_busy++;
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  }
  if (mesh_control_agent_sync_decode_v1(frame, frame_size, &message) !=
      MESH_CONTROL_AGENT_SYNC_OK) {
    controller->counters.rejected_protocol++;
    return MESH_CONTROL_INVALID_ARG;
  }
  if (message.kind == MESH_CONTROL_AGENT_SYNC_HELLO) {
    mesh_control_result_t hello_result = receive_hello(
        controller, tls_digest, &message, now_ms);
    if (hello_result == MESH_CONTROL_UNAUTHORIZED)
      controller->counters.rejected_auth++;
    return hello_result;
  }
  record = find_session(controller, message.node_id);
  if (!session_matches(record, &message, tls_digest)) {
    controller->counters.fenced++;
    return MESH_CONTROL_STALE_EPOCH;
  }
  memset(&current_policy, 0, sizeof(current_policy));
  auth_result = controller->config.authorize_identity(
      controller->config.identity_context, message.node_id, tls_digest,
      &current_policy);
  if (auth_result != MESH_CONTROL_OK ||
      current_policy.identity_policy_generation == 0u) {
    controller->counters.rejected_auth++;
    return MESH_CONTROL_UNAUTHORIZED;
  }
  if (current_policy.identity_policy_generation !=
      record->identity_policy_generation) {
    controller->counters.fenced++;
    return MESH_CONTROL_STALE_EPOCH;
  }
  if (!time_valid(controller, message.sent_at_ms, now_ms)) {
    controller->counters.rejected_protocol++;
    return MESH_CONTROL_TIMEOUT;
  }
  token = next_token(controller);
  switch (message.kind) {
    case MESH_CONTROL_AGENT_SYNC_CLAIM_REQUEST:
      result = mesh_control_durable_outbox_worker_try_claim_v1(
          &controller->worker, token, message.node_id, message.session_id,
          message.session_generation, now_ms, controller->config.claim_lease_ms);
      break;
    case MESH_CONTROL_AGENT_SYNC_RECEIPT:
      if (mesh_control_receipt_decode_v1(message.payload, message.payload_size,
                                         &receipt) != MESH_CONTROL_OK ||
          !mesh_mgmt_crypto_equal_16(receipt.operation.message_id,
                                     message.message_id)) {
        controller->counters.rejected_protocol++;
        return MESH_CONTROL_INVALID_ARG;
      }
      result = mesh_control_durable_outbox_worker_try_ack_v1(
          &controller->worker, token, message.node_id, message.message_id,
          message.session_id, message.session_generation,
          message.lease_generation, now_ms);
      break;
    case MESH_CONTROL_AGENT_SYNC_CLOSE:
      result = mesh_control_durable_outbox_worker_try_deactivate_session_v1(
          &controller->worker, token, message.node_id, message.session_id,
          message.session_generation);
      break;
    default:
      controller->counters.rejected_protocol++;
      return MESH_CONTROL_INVALID_ARG;
  }
  if (result != MESH_CONTROL_DURABLE_OUTBOX_WORKER_OK)
    return worker_result(result);
  retain_pending(controller, &message, tls_digest,
                 message.kind == MESH_CONTROL_AGENT_SYNC_CLAIM_REQUEST
                     ? MESH_CONTROL_DURABLE_OUTBOX_WORKER_CLAIM
                     : message.kind == MESH_CONTROL_AGENT_SYNC_RECEIPT
                           ? MESH_CONTROL_DURABLE_OUTBOX_WORKER_ACK
                           : MESH_CONTROL_DURABLE_OUTBOX_WORKER_DEACTIVATE_SESSION);
  controller->pending_worker_token = token;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_controller_session_try_submit_v1(
    mesh_control_controller_session_v1_t *controller,
    const mesh_control_durable_outbox_message_v1_t *message,
    uint64_t *out_request_token) {
  mesh_mgmt_verified_envelope_v1_t verified;
  mesh_control_envelope_v1_t envelope;
  const uint8_t *body = NULL;
  size_t body_size = 0u;
  mesh_control_durable_outbox_worker_result_t worker_submit;
  uint64_t token;
  if (!controller || !controller->initialized || !controller->accepting ||
      controller->faulted || !message || !out_request_token ||
      !message->payload || message->payload_size == 0u ||
      message->payload_size > controller->config.outbox.max_payload_size ||
      message->created_at_ms == 0u)
    return MESH_CONTROL_INVALID_ARG;
  *out_request_token = 0u;
  if (controller->pending_operation || controller->response_ready ||
      controller->submit_completion_ready) {
    controller->counters.rejected_busy++;
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  }
  if (mesh_mgmt_envelope_verify_v1(message->payload, message->payload_size,
                                   &verified) != MESH_MGMT_ENVELOPE_OK ||
      verified.frame.kind != MESH_MGMT_KIND_CONTROL_FRAME ||
      !mesh_mgmt_crypto_equal_32(verified.header.target_node_id,
                                 message->target_node_id) ||
      !mesh_mgmt_crypto_equal_16(verified.header.message_id,
                                 message->message_id) ||
      mesh_control_mmp_payload_decode_v1(&verified, &envelope, &body,
                                         &body_size) != MESH_CONTROL_MMP_OK ||
      !mesh_mgmt_crypto_equal_16(envelope.message_id, message->message_id) ||
      !mesh_mgmt_crypto_equal_16(envelope.request_id, message->request_id) ||
      !mesh_mgmt_crypto_equal_32(envelope.target_node_id,
                                 message->target_node_id)) {
    controller->counters.rejected_protocol++;
    return MESH_CONTROL_INVALID_ARG;
  }
  token = next_token(controller);
  controller->submit_abandoned = 0u;
  worker_submit = mesh_control_durable_outbox_worker_try_submit_message_v1(
      &controller->worker, token, message);
  if (worker_submit != MESH_CONTROL_DURABLE_OUTBOX_WORKER_OK)
    return worker_result(worker_submit);
  controller->pending_worker_token = token;
  controller->pending_operation = MESH_CONTROL_DURABLE_OUTBOX_WORKER_SUBMIT;
  controller->pending_source = CONTROLLER_PENDING_SUBMIT;
  *out_request_token = token;
  return MESH_CONTROL_OK;
}

static mesh_control_result_t encode_response(
    mesh_control_controller_session_v1_t *controller,
    mesh_control_agent_sync_kind_v1_t kind, int32_t status,
    uint64_t session_generation, uint64_t lease_generation,
    const uint8_t message_id[MESH_CONTROL_ID_SIZE], const uint8_t *payload,
    size_t payload_size) {
  mesh_control_agent_sync_message_v1_t response;
  size_t output_size = 0u;
  memset(&response, 0, sizeof(response));
  response.kind = kind;
  response.status = status;
  memcpy(response.node_id, controller->pending.node_id,
         sizeof(response.node_id));
  memcpy(response.session_id, controller->pending.session_id,
         sizeof(response.session_id));
  response.session_generation = session_generation;
  response.request_token = controller->pending.request_token;
  response.lease_generation = lease_generation;
  response.sent_at_ms = controller->pending.sent_at_ms;
  if (message_id) memcpy(response.message_id, message_id, sizeof(response.message_id));
  response.payload = payload;
  response.payload_size = payload_size;
  if (mesh_control_agent_sync_encode_v1(
          &response, controller->response, sizeof(controller->response),
          &output_size) != MESH_CONTROL_AGENT_SYNC_OK)
    return MESH_CONTROL_INVALID_STATE;
  controller->response_size = output_size;
  controller->response_ready = 1u;
  controller->counters.responses++;
  return MESH_CONTROL_OK;
}

static void discard_agent_response(
    mesh_control_controller_session_v1_t *controller) {
  memset(controller->response, 0, controller->response_size);
  controller->response_size = 0u;
  controller->response_ready = 0u;
  controller->response_abandoned = 0u;
  memset(&controller->pending, 0, sizeof(controller->pending));
  controller->pending_identity_policy_generation = 0u;
  memset(controller->pending_payload, 0, sizeof(controller->pending_payload));
}

mesh_control_result_t mesh_control_controller_session_poll_v1(
    mesh_control_controller_session_v1_t *controller, size_t *out_progress) {
  mesh_control_durable_outbox_worker_completion_v1_t completion;
  mesh_control_durable_outbox_worker_result_t take_result;
  mesh_control_controller_session_record_v1_t *record;
  mesh_mgmt_verified_envelope_v1_t verified;
  size_t payload_size = 0u;
  mesh_control_result_t result = MESH_CONTROL_OK;
  if (!controller || !controller->initialized || !out_progress)
    return MESH_CONTROL_INVALID_ARG;
  *out_progress = 0u;
  if (!controller->pending_operation || controller->response_ready)
    return MESH_CONTROL_OK;
  take_result = mesh_control_durable_outbox_worker_try_take_v1(
      &controller->worker, &completion, controller->worker_payload,
      controller->worker_payload_capacity,
      &payload_size);
  if (take_result == MESH_CONTROL_DURABLE_OUTBOX_WORKER_EMPTY)
    return MESH_CONTROL_OK;
  if (take_result != MESH_CONTROL_DURABLE_OUTBOX_WORKER_OK ||
      completion.request_token != controller->pending_worker_token ||
      completion.operation != controller->pending_operation) {
    controller->faulted = 1u;
    return MESH_CONTROL_INVALID_STATE;
  }
  *out_progress = 1u;
  if (controller->pending_source == CONTROLLER_PENDING_SUBMIT) {
    if (completion.operation != MESH_CONTROL_DURABLE_OUTBOX_WORKER_SUBMIT) {
      controller->faulted = 1u;
      return MESH_CONTROL_INVALID_STATE;
    }
    if (!controller->submit_abandoned) {
      memset(&controller->submit_completion, 0,
             sizeof(controller->submit_completion));
      controller->submit_completion.request_token = completion.request_token;
      controller->submit_completion.store_result = completion.store_result;
      controller->submit_completion.view = completion.view;
      controller->submit_completion.view.payload = NULL;
      controller->submit_completion.view.payload_size = 0u;
      controller->submit_completion_ready = 1u;
    }
    controller->pending_operation = 0u;
    controller->pending_worker_token = 0u;
    controller->pending_source = CONTROLLER_PENDING_NONE;
    controller->submit_abandoned = 0u;
    if (completion.store_result == MESH_CONTROL_DURABLE_OUTBOX_OK)
      controller->counters.outbox_submitted++;
    return MESH_CONTROL_OK;
  }
  switch (completion.operation) {
    case MESH_CONTROL_DURABLE_OUTBOX_WORKER_ACTIVATE_SESSION:
      if (completion.store_result != MESH_CONTROL_DURABLE_OUTBOX_OK ||
          completion.session_generation == 0u) {
        result = completion.store_result == MESH_CONTROL_DURABLE_OUTBOX_FENCED
                     ? MESH_CONTROL_STALE_EPOCH
                     : MESH_CONTROL_INVALID_STATE;
        break;
      }
      record = allocate_session(controller, controller->pending.node_id);
      if (!record) {
        result = MESH_CONTROL_RESOURCE_EXHAUSTED;
        break;
      }
      if (!record->active) controller->session_count++;
      memset(record, 0, sizeof(*record));
      memcpy(record->node_id, controller->pending.node_id,
             sizeof(record->node_id));
      memcpy(record->session_id, controller->pending.session_id,
             sizeof(record->session_id));
      memcpy(record->tls_certificate_sha256, controller->pending_tls_digest,
             sizeof(record->tls_certificate_sha256));
      record->generation = completion.session_generation;
      if (controller->pending_identity_policy_generation == 0u) {
        result = MESH_CONTROL_INVALID_STATE;
        break;
      }
      record->identity_policy_generation =
          controller->pending_identity_policy_generation;
      record->connected_at_ms = controller->pending.sent_at_ms;
      record->active = 1u;
      controller->counters.activated++;
      result = encode_response(controller, MESH_CONTROL_AGENT_SYNC_HELLO_ACK,
                               MESH_CONTROL_OK, record->generation, 0u, NULL,
                               NULL, 0u);
      break;
    case MESH_CONTROL_DURABLE_OUTBOX_WORKER_CLAIM:
      if (completion.store_result == MESH_CONTROL_DURABLE_OUTBOX_NOT_FOUND) {
        result = encode_response(controller, MESH_CONTROL_AGENT_SYNC_ERROR,
                                 MESH_CONTROL_EMPTY,
                                 controller->pending.session_generation, 0u,
                                 NULL, NULL, 0u);
        break;
      }
      if (completion.store_result != MESH_CONTROL_DURABLE_OUTBOX_OK ||
          payload_size == 0u ||
          mesh_mgmt_envelope_verify_v1(controller->worker_payload,
                                       payload_size, &verified) !=
              MESH_MGMT_ENVELOPE_OK ||
          verified.frame.kind != MESH_MGMT_KIND_CONTROL_FRAME ||
          !mesh_mgmt_crypto_equal_32(verified.header.target_node_id,
                                     controller->pending.node_id) ||
          !mesh_mgmt_crypto_equal_16(verified.header.message_id,
                                     completion.view.message_id)) {
        result = MESH_CONTROL_INVALID_STATE;
        break;
      }
      controller->counters.commands++;
      result = encode_response(
          controller, MESH_CONTROL_AGENT_SYNC_COMMAND, MESH_CONTROL_OK,
          controller->pending.session_generation,
          completion.view.lease_generation, completion.view.message_id,
          controller->worker_payload, payload_size);
      break;
    case MESH_CONTROL_DURABLE_OUTBOX_WORKER_ACK:
      if (completion.store_result != MESH_CONTROL_DURABLE_OUTBOX_OK) {
        result = completion.store_result == MESH_CONTROL_DURABLE_OUTBOX_FENCED
                     ? MESH_CONTROL_STALE_EPOCH
                     : MESH_CONTROL_INVALID_STATE;
        break;
      }
      controller->counters.durable_receipts++;
      result = encode_response(controller, MESH_CONTROL_AGENT_SYNC_HEARTBEAT,
                               MESH_CONTROL_OK,
                               controller->pending.session_generation, 0u,
                               NULL, NULL, 0u);
      break;
    case MESH_CONTROL_DURABLE_OUTBOX_WORKER_DEACTIVATE_SESSION:
      if (completion.store_result != MESH_CONTROL_DURABLE_OUTBOX_OK) {
        result = completion.store_result == MESH_CONTROL_DURABLE_OUTBOX_FENCED
                     ? MESH_CONTROL_STALE_EPOCH
                     : MESH_CONTROL_INVALID_STATE;
        break;
      }
      record = find_session(controller, controller->pending.node_id);
      if (record && session_matches(record, &controller->pending,
                                    controller->pending_tls_digest)) {
        memset(record, 0, sizeof(*record));
        controller->session_count--;
      }
      result = encode_response(controller, MESH_CONTROL_AGENT_SYNC_CLOSE,
                               MESH_CONTROL_OK,
                               controller->pending.session_generation, 0u,
                               NULL, NULL, 0u);
      break;
    default:
      result = MESH_CONTROL_INVALID_STATE;
      break;
  }
  if (result != MESH_CONTROL_OK) controller->faulted = 1u;
  if (result != MESH_CONTROL_OK || controller->response_ready)
    controller->pending_operation = 0u;
  if (!controller->pending_operation) controller->pending_worker_token = 0u;
  if (!controller->pending_operation)
    controller->pending_source = CONTROLLER_PENDING_NONE;
  if (controller->response_ready && controller->response_abandoned)
    discard_agent_response(controller);
  return result;
}

mesh_control_result_t mesh_control_controller_session_try_take_submit_v1(
    mesh_control_controller_session_v1_t *controller,
    mesh_control_controller_submit_completion_v1_t *out_completion) {
  if (!controller || !controller->initialized || !out_completion)
    return MESH_CONTROL_INVALID_ARG;
  if (!controller->submit_completion_ready) return MESH_CONTROL_EMPTY;
  *out_completion = controller->submit_completion;
  memset(&controller->submit_completion, 0,
         sizeof(controller->submit_completion));
  controller->submit_completion_ready = 0u;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_controller_session_abandon_submit_v1(
    mesh_control_controller_session_v1_t *controller,
    uint64_t request_token) {
  if (!controller || !controller->initialized || request_token == 0u)
    return MESH_CONTROL_INVALID_ARG;
  if (controller->submit_completion_ready) {
    if (controller->submit_completion.request_token != request_token)
      return MESH_CONTROL_CONFLICT;
    memset(&controller->submit_completion, 0,
           sizeof(controller->submit_completion));
    controller->submit_completion_ready = 0u;
    return MESH_CONTROL_OK;
  }
  if (controller->pending_source != CONTROLLER_PENDING_SUBMIT ||
      controller->pending_worker_token != request_token)
    return MESH_CONTROL_EMPTY;
  controller->submit_abandoned = 1u;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_controller_session_try_take_response_v1(
    mesh_control_controller_session_v1_t *controller, uint8_t *output,
    size_t output_capacity, size_t *out_size) {
  if (!controller || !controller->initialized || !out_size)
    return MESH_CONTROL_INVALID_ARG;
  *out_size = controller->response_size;
  if (!controller->response_ready) return MESH_CONTROL_EMPTY;
  if (!output || output_capacity < controller->response_size)
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  memcpy(output, controller->response, controller->response_size);
  discard_agent_response(controller);
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_controller_session_abandon_response_v1(
    mesh_control_controller_session_v1_t *controller) {
  if (!controller || !controller->initialized)
    return MESH_CONTROL_INVALID_ARG;
  if (controller->pending_source != CONTROLLER_PENDING_AGENT &&
      !controller->response_ready)
    return MESH_CONTROL_EMPTY;
  controller->response_abandoned = 1u;
  if (controller->response_ready) discard_agent_response(controller);
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_controller_session_get_stats_v1(
    mesh_control_controller_session_v1_t *controller,
    mesh_control_controller_session_stats_v1_t *out_stats) {
  mesh_control_durable_outbox_worker_stats_v1_t worker_stats;
  if (!controller || !controller->initialized || !out_stats)
    return MESH_CONTROL_INVALID_ARG;
  if (mesh_control_durable_outbox_worker_get_stats_v1(
          &controller->worker, &worker_stats) !=
      MESH_CONTROL_DURABLE_OUTBOX_WORKER_OK)
    return MESH_CONTROL_INVALID_STATE;
  *out_stats = controller->counters;
  out_stats->active_sessions = controller->session_count;
  out_stats->accepting = controller->accepting;
  out_stats->persistence_busy =
      (uint8_t)(worker_stats.busy || worker_stats.completion_ready);
  out_stats->response_ready = controller->response_ready;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_controller_session_shutdown_v1(
    mesh_control_controller_session_v1_t *controller) {
  if (!controller || !controller->initialized)
    return MESH_CONTROL_INVALID_ARG;
  controller->accepting = 0u;
  if (controller->pending_operation || controller->response_ready ||
      controller->submit_completion_ready)
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  return mesh_control_durable_outbox_worker_shutdown_v1(&controller->worker) ==
                 MESH_CONTROL_DURABLE_OUTBOX_WORKER_OK
             ? MESH_CONTROL_OK
             : MESH_CONTROL_INVALID_STATE;
}

void mesh_control_controller_session_destroy_v1(
    mesh_control_controller_session_v1_t *controller) {
  if (!controller) return;
  mesh_control_durable_outbox_worker_destroy_v1(&controller->worker);
  if (controller->worker_payload) {
    memset(controller->worker_payload, 0,
           controller->worker_payload_capacity);
    free(controller->worker_payload);
  }
  free(controller->sessions);
  memset(controller, 0, sizeof(*controller));
}
