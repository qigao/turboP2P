#include "mesh_node_ipc_client.h"

#include <turbo_crypto.h>

#include <stdlib.h>
#include <string.h>

static int bytes_zero(const uint8_t *bytes, size_t size) {
  uint8_t value = 0u;
  size_t index;
  if (!bytes)
    return 1;
  for (index = 0u; index < size; ++index)
    value |= bytes[index];
  return value == 0u;
}

static int bytes_equal(const uint8_t *left, const uint8_t *right,
                       size_t size) {
  return left && right &&
         turbo_crypto_verify(left, right, size) == TURBO_CRYPTO_OK;
}

static mesh_node_ipc_client_operation_v1_t *find_operation(
    mesh_node_ipc_client_v1_t *client,
    const uint8_t operation_id[MESH_CONTROL_ID_SIZE]) {
  size_t index;
  for (index = 0u; index < client->operation_capacity; ++index) {
    if (client->operations[index].state != 0u &&
        bytes_equal(client->operations[index].operation_id, operation_id,
                    MESH_CONTROL_ID_SIZE))
      return &client->operations[index];
  }
  return NULL;
}

static const mesh_node_ipc_client_operation_v1_t *find_ready_operation(
    const mesh_node_ipc_client_v1_t *client) {
  size_t index;
  for (index = 0u; index < client->operation_capacity; ++index) {
    if (client->operations[index].state ==
        MESH_NODE_IPC_CLIENT_RESULT_READY_V1)
      return &client->operations[index];
  }
  return NULL;
}

static mesh_node_ipc_client_operation_v1_t *free_operation(
    mesh_node_ipc_client_v1_t *client) {
  size_t index;
  for (index = 0u; index < client->operation_capacity; ++index) {
    if (client->operations[index].state == 0u)
      return &client->operations[index];
  }
  return NULL;
}

static int operation_binding_equal(
    const mesh_node_ipc_client_operation_v1_t *operation,
    const uint8_t request_id[MESH_CONTROL_ID_SIZE], uint64_t desired_epoch,
    const mesh_node_ipc_command_v1_t *command) {
  return bytes_equal(operation->request_id, request_id,
                     MESH_CONTROL_ID_SIZE) &&
         operation->desired_epoch == desired_epoch &&
         operation->resource_kind == command->resource_kind &&
         operation->action == command->action &&
         bytes_equal(operation->resource_id, command->resource_id,
                     MESH_CONTROL_DIGEST_SIZE) &&
         bytes_equal(operation->document_digest, command->document_digest,
                     MESH_CONTROL_DIGEST_SIZE);
}

mesh_control_result_t mesh_node_ipc_client_init_v1(
    mesh_node_ipc_client_v1_t *client,
    const mesh_node_ipc_client_config_v1_t *config) {
  if (!client || client->initialized != 0u || !config || !config->inbound ||
      !config->outbound || config->operation_capacity == 0u ||
      config->operation_capacity > MESH_CONTROL_OUTBOX_MAX_ENTRIES_V1 ||
      bytes_zero(config->mesh_id, sizeof(config->mesh_id)) ||
      bytes_zero(config->provider_id, sizeof(config->provider_id)) ||
      bytes_zero(config->sender_incarnation,
                 sizeof(config->sender_incarnation)))
    return MESH_CONTROL_INVALID_ARG;
  memset(client, 0, sizeof(*client));
  client->operations = (mesh_node_ipc_client_operation_v1_t *)calloc(
      config->operation_capacity, sizeof(*client->operations));
  if (!client->operations)
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  client->inbound = config->inbound;
  client->outbound = config->outbound;
  memcpy(client->mesh_id, config->mesh_id, sizeof(client->mesh_id));
  memcpy(client->provider_id, config->provider_id,
         sizeof(client->provider_id));
  memcpy(client->sender_incarnation, config->sender_incarnation,
         sizeof(client->sender_incarnation));
  client->operation_capacity = config->operation_capacity;
  client->next_sequence = 1u;
  client->accepting_commands = 1u;
  client->initialized = 1u;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_node_ipc_client_submit_v1(
    mesh_node_ipc_client_v1_t *client,
    const uint8_t request_id[MESH_CONTROL_ID_SIZE],
    const uint8_t operation_id[MESH_CONTROL_ID_SIZE], uint64_t desired_epoch,
    const mesh_node_ipc_command_v1_t *command) {
  mesh_node_ipc_client_operation_v1_t *operation;
  mesh_node_ipc_envelope_v1_t envelope;
  uint8_t *body = NULL;
  uint8_t *frame = NULL;
  size_t body_capacity;
  size_t body_size = 0u;
  size_t frame_size = 0u;
  mesh_control_result_t result;

  if (!client || client->initialized == 0u || !request_id || !operation_id ||
      !command || desired_epoch == 0u || bytes_zero(request_id,
                                                    MESH_CONTROL_ID_SIZE) ||
      bytes_zero(operation_id, MESH_CONTROL_ID_SIZE))
    return MESH_CONTROL_INVALID_ARG;
  if (!client->accepting_commands)
    return MESH_CONTROL_CLOSED;
  if (!bytes_equal(command->mesh_id, client->mesh_id,
                   sizeof(client->mesh_id)) ||
      !bytes_equal(command->provider_id, client->provider_id,
                   sizeof(client->provider_id)))
    return MESH_CONTROL_UNAUTHORIZED;
  operation = find_operation(client, operation_id);
  if (operation)
    return operation_binding_equal(operation, request_id, desired_epoch,
                                   command)
               ? MESH_CONTROL_OK
               : MESH_CONTROL_CONFLICT;
  if (client->operation_count >= client->operation_capacity ||
      client->next_sequence == UINT64_MAX)
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  operation = free_operation(client);
  if (!operation)
    return MESH_CONTROL_INVALID_STATE;

  body_capacity = MESH_NODE_IPC_COMMAND_HEADER_SIZE_V1 +
                  command->document_size;
  if (body_capacity > MESH_NODE_IPC_MAX_FRAME_SIZE_V1 -
                          MESH_NODE_IPC_HEADER_SIZE_V1)
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  body = (uint8_t *)malloc(body_capacity);
  frame = (uint8_t *)malloc(MESH_NODE_IPC_HEADER_SIZE_V1 + body_capacity);
  if (!body || !frame) {
    result = MESH_CONTROL_RESOURCE_EXHAUSTED;
    goto done;
  }
  result = mesh_node_ipc_command_encode_v1(command, body, body_capacity,
                                            &body_size);
  if (result != MESH_CONTROL_OK)
    goto done;
  memset(&envelope, 0, sizeof(envelope));
  envelope.kind = MESH_NODE_IPC_COMMAND_V1;
  memcpy(envelope.request_id, request_id, sizeof(envelope.request_id));
  memcpy(envelope.operation_id, operation_id, sizeof(envelope.operation_id));
  memcpy(envelope.sender_incarnation, client->sender_incarnation,
         sizeof(envelope.sender_incarnation));
  envelope.sequence = client->next_sequence;
  envelope.desired_epoch = desired_epoch;
  envelope.body = body;
  envelope.body_size = body_size;
  result = mesh_node_ipc_envelope_encode_v1(
      &envelope, frame, MESH_NODE_IPC_HEADER_SIZE_V1 + body_capacity,
      &frame_size);
  if (result != MESH_CONTROL_OK)
    goto done;
  result = mesh_node_ipc_channel_try_push_v1(client->outbound, frame,
                                              frame_size);
  if (result != MESH_CONTROL_OK)
    goto done;

  memset(operation, 0, sizeof(*operation));
  memcpy(operation->operation_id, operation_id,
         sizeof(operation->operation_id));
  memcpy(operation->request_id, request_id, sizeof(operation->request_id));
  memcpy(operation->resource_id, command->resource_id,
         sizeof(operation->resource_id));
  memcpy(operation->document_digest, command->document_digest,
         sizeof(operation->document_digest));
  operation->desired_epoch = desired_epoch;
  operation->resource_kind = command->resource_kind;
  operation->action = command->action;
  operation->state = MESH_NODE_IPC_CLIENT_COMMAND_QUEUED_V1;
  ++client->operation_count;
  ++client->next_sequence;
  ++client->commands_submitted;

done:
  free(frame);
  free(body);
  return result;
}

static mesh_control_result_t bind_peer_incarnation(
    mesh_node_ipc_client_operation_v1_t *operation,
    const uint8_t peer_incarnation[MESH_CONTROL_ID_SIZE]) {
  if (bytes_zero(operation->peer_incarnation,
                 sizeof(operation->peer_incarnation))) {
    memcpy(operation->peer_incarnation, peer_incarnation,
           sizeof(operation->peer_incarnation));
    return MESH_CONTROL_OK;
  }
  return bytes_equal(operation->peer_incarnation, peer_incarnation,
                     sizeof(operation->peer_incarnation))
             ? MESH_CONTROL_OK
             : MESH_CONTROL_STALE_EPOCH;
}

static int result_matches_operation(
    const mesh_node_ipc_client_operation_v1_t *operation,
    const mesh_node_ipc_result_v1_t *result) {
  static const uint8_t zeros[MESH_CONTROL_DIGEST_SIZE] = {0u};
  if (operation->resource_kind != result->resource_kind ||
      operation->action != result->action ||
      !bytes_equal(operation->resource_id, result->resource_id,
                   sizeof(operation->resource_id)))
    return 0;
  if (result->outcome == MESH_NODE_IPC_OUTCOME_FAILED_V1)
    return 1;
  return result->applied_epoch == operation->desired_epoch &&
         bytes_equal(result->observed_digest,
                     operation->action == MESH_CONTROL_DESIRED_APPLY
                         ? operation->document_digest
                         : zeros,
                     sizeof(operation->document_digest));
}

static int results_equal(const mesh_node_ipc_result_v1_t *left,
                         const mesh_node_ipc_result_v1_t *right) {
  return left->outcome == right->outcome &&
         left->stable_error == right->stable_error &&
         left->failure_stage == right->failure_stage &&
         left->resource_kind == right->resource_kind &&
         left->action == right->action &&
         left->applied_epoch == right->applied_epoch &&
         bytes_equal(left->resource_id, right->resource_id,
                     sizeof(left->resource_id)) &&
         bytes_equal(left->observed_digest, right->observed_digest,
                     sizeof(left->observed_digest));
}

mesh_control_result_t mesh_node_ipc_client_poll_v1(
    mesh_node_ipc_client_v1_t *client, size_t budget,
    size_t *out_processed) {
  size_t processed = 0u;
  mesh_control_result_t result = MESH_CONTROL_OK;
  if (!client || client->initialized == 0u || budget == 0u ||
      !out_processed)
    return MESH_CONTROL_INVALID_ARG;
  *out_processed = 0u;
  while (processed < budget) {
    mesh_node_ipc_frame_view_v1_t frame;
    mesh_node_ipc_client_operation_v1_t *operation;
    result = mesh_node_ipc_channel_peek_v1(client->inbound, &frame);
    if (result == MESH_CONTROL_EMPTY) {
      result = MESH_CONTROL_OK;
      break;
    }
    if (result != MESH_CONTROL_OK)
      break;
    operation = find_operation(client, frame.envelope.operation_id);
    if ((frame.envelope.kind != MESH_NODE_IPC_ACCEPTED_V1 &&
         frame.envelope.kind != MESH_NODE_IPC_RESULT_V1) ||
        !operation ||
        !bytes_equal(operation->request_id, frame.envelope.request_id,
                     sizeof(operation->request_id)) ||
        operation->desired_epoch != frame.envelope.desired_epoch ||
        bind_peer_incarnation(operation,
                              frame.envelope.sender_incarnation) !=
            MESH_CONTROL_OK) {
      ++client->rejected_frames;
      result = MESH_CONTROL_CONFLICT;
    } else if (frame.envelope.kind == MESH_NODE_IPC_ACCEPTED_V1) {
      if (operation->state == MESH_NODE_IPC_CLIENT_COMMAND_QUEUED_V1) {
        operation->state = MESH_NODE_IPC_CLIENT_ACCEPTED_V1;
        ++client->accepted_received;
      } else {
        ++client->duplicate_frames;
      }
    } else {
      mesh_node_ipc_result_v1_t decoded;
      if (mesh_node_ipc_result_decode_v1(
              frame.envelope.body, frame.envelope.body_size, &decoded) !=
              MESH_CONTROL_OK ||
          !result_matches_operation(operation, &decoded)) {
        ++client->rejected_frames;
        result = MESH_CONTROL_CONFLICT;
      } else if (operation->state == MESH_NODE_IPC_CLIENT_RESULT_READY_V1) {
        if (!results_equal(&operation->result, &decoded)) {
          ++client->rejected_frames;
          result = MESH_CONTROL_CONFLICT;
        } else {
          ++client->duplicate_frames;
        }
      } else {
        operation->result = decoded;
        operation->state = MESH_NODE_IPC_CLIENT_RESULT_READY_V1;
        ++client->results_received;
      }
    }
    if (mesh_node_ipc_channel_consume_v1(client->inbound) !=
        MESH_CONTROL_OK)
      return MESH_CONTROL_INVALID_STATE;
    ++processed;
    if (result != MESH_CONTROL_OK)
      break;
  }
  *out_processed = processed;
  return result;
}

mesh_control_result_t mesh_node_ipc_client_peek_result_v1(
    const mesh_node_ipc_client_v1_t *client,
    uint8_t out_operation_id[MESH_CONTROL_ID_SIZE],
    mesh_node_ipc_result_v1_t *out_result) {
  const mesh_node_ipc_client_operation_v1_t *operation;
  if (!client || client->initialized == 0u || !out_operation_id ||
      !out_result)
    return MESH_CONTROL_INVALID_ARG;
  operation = find_ready_operation(client);
  if (!operation)
    return MESH_CONTROL_EMPTY;
  memcpy(out_operation_id, operation->operation_id, MESH_CONTROL_ID_SIZE);
  *out_result = operation->result;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_node_ipc_client_ack_result_v1(
    mesh_node_ipc_client_v1_t *client,
    const uint8_t operation_id[MESH_CONTROL_ID_SIZE]) {
  mesh_node_ipc_client_operation_v1_t *operation;
  mesh_node_ipc_envelope_v1_t envelope;
  uint8_t frame[MESH_NODE_IPC_HEADER_SIZE_V1];
  size_t frame_size = 0u;
  mesh_control_result_t result;
  if (!client || client->initialized == 0u || !operation_id)
    return MESH_CONTROL_INVALID_ARG;
  operation = find_operation(client, operation_id);
  if (!operation || operation->state != MESH_NODE_IPC_CLIENT_RESULT_READY_V1)
    return MESH_CONTROL_CONFLICT;
  if (client->next_sequence == UINT64_MAX)
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  memset(&envelope, 0, sizeof(envelope));
  envelope.kind = MESH_NODE_IPC_ACK_RESULT_V1;
  memcpy(envelope.request_id, operation->request_id,
         sizeof(envelope.request_id));
  memcpy(envelope.operation_id, operation->operation_id,
         sizeof(envelope.operation_id));
  memcpy(envelope.sender_incarnation, client->sender_incarnation,
         sizeof(envelope.sender_incarnation));
  envelope.sequence = client->next_sequence;
  result = mesh_node_ipc_envelope_encode_v1(
      &envelope, frame, sizeof(frame), &frame_size);
  if (result != MESH_CONTROL_OK)
    return result;
  result = mesh_node_ipc_channel_try_push_v1(client->outbound, frame,
                                              frame_size);
  if (result != MESH_CONTROL_OK)
    return result;
  memset(operation, 0, sizeof(*operation));
  --client->operation_count;
  ++client->next_sequence;
  ++client->results_acked;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_node_ipc_client_begin_drain_v1(
    mesh_node_ipc_client_v1_t *client) {
  if (!client || client->initialized == 0u)
    return MESH_CONTROL_INVALID_ARG;
  client->accepting_commands = 0u;
  return MESH_CONTROL_OK;
}

int mesh_node_ipc_client_is_drained_v1(
    const mesh_node_ipc_client_v1_t *client) {
  mesh_node_ipc_channel_stats_v1_t inbound;
  mesh_node_ipc_channel_stats_v1_t outbound;
  if (!client || client->initialized == 0u || client->accepting_commands ||
      client->operation_count != 0u)
    return 0;
  if (mesh_node_ipc_channel_get_stats_v1(client->inbound, &inbound) !=
          MESH_CONTROL_OK ||
      mesh_node_ipc_channel_get_stats_v1(client->outbound, &outbound) !=
          MESH_CONTROL_OK)
    return 0;
  return inbound.pending == 0u && outbound.pending == 0u;
}

mesh_control_result_t mesh_node_ipc_client_get_stats_v1(
    const mesh_node_ipc_client_v1_t *client,
    mesh_node_ipc_client_stats_v1_t *out_stats) {
  if (!client || client->initialized == 0u || !out_stats)
    return MESH_CONTROL_INVALID_ARG;
  memset(out_stats, 0, sizeof(*out_stats));
  out_stats->retained_operations = client->operation_count;
  out_stats->operation_capacity = client->operation_capacity;
  out_stats->accepting_commands = client->accepting_commands;
  out_stats->commands_submitted = client->commands_submitted;
  out_stats->accepted_received = client->accepted_received;
  out_stats->results_received = client->results_received;
  out_stats->duplicate_frames = client->duplicate_frames;
  out_stats->rejected_frames = client->rejected_frames;
  out_stats->results_acked = client->results_acked;
  return MESH_CONTROL_OK;
}

void mesh_node_ipc_client_destroy_v1(mesh_node_ipc_client_v1_t *client) {
  if (!client)
    return;
  free(client->operations);
  memset(client, 0, sizeof(*client));
}
