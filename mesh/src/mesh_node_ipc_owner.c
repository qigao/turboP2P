#include "mesh_node_ipc_owner.h"

#include <turbo_crypto.h>

#include <stdlib.h>
#include <string.h>

static int bytes_zero(const uint8_t *bytes, size_t size) {
  uint8_t aggregate = 0u;
  size_t index;
  if (!bytes)
    return 1;
  for (index = 0u; index < size; ++index)
    aggregate |= bytes[index];
  return aggregate == 0u;
}

static int bytes_equal(const uint8_t *left, const uint8_t *right,
                       size_t size) {
  return turbo_crypto_verify(left, right, size) == TURBO_CRYPTO_OK;
}

static size_t find_operation(const mesh_node_ipc_owner_v1_t *owner,
                             const uint8_t operation_id[MESH_CONTROL_ID_SIZE],
                             const uint8_t request_id[MESH_CONTROL_ID_SIZE]) {
  size_t index;
  for (index = 0u; index < owner->operation_count; ++index) {
    if (bytes_equal(owner->operations[index].operation_id, operation_id,
                    MESH_CONTROL_ID_SIZE) &&
        (!request_id ||
         bytes_equal(owner->operations[index].request_id, request_id,
                     MESH_CONTROL_ID_SIZE)))
      return index;
  }
  return SIZE_MAX;
}

static mesh_node_ipc_error_v1_t stable_error(mesh_control_result_t result) {
  switch (result) {
    case MESH_CONTROL_INVALID_ARG:
      return MESH_NODE_IPC_ERROR_INVALID_DOCUMENT_V1;
    case MESH_CONTROL_UNAUTHORIZED:
      return MESH_NODE_IPC_ERROR_PERMISSION_DENIED_V1;
    case MESH_CONTROL_STALE_EPOCH:
      return MESH_NODE_IPC_ERROR_FENCED_V1;
    case MESH_CONTROL_CONFLICT:
      return MESH_NODE_IPC_ERROR_CONFLICT_V1;
    case MESH_CONTROL_RESOURCE_EXHAUSTED:
      return MESH_NODE_IPC_ERROR_RESOURCE_EXHAUSTED_V1;
    case MESH_CONTROL_UNSUPPORTED:
    case MESH_CONTROL_EMPTY:
    case MESH_CONTROL_PROVIDER_UNAVAILABLE:
      return MESH_NODE_IPC_ERROR_PROVIDER_UNAVAILABLE_V1;
    case MESH_CONTROL_TIMEOUT:
      return MESH_NODE_IPC_ERROR_TIMEOUT_V1;
    case MESH_CONTROL_UNKNOWN_COMMIT:
      return MESH_NODE_IPC_ERROR_UNKNOWN_COMMIT_V1;
    case MESH_CONTROL_CLOSED:
      return MESH_NODE_IPC_ERROR_SHUTTING_DOWN_V1;
    default:
      return MESH_NODE_IPC_ERROR_INTERNAL_V1;
  }
}

static mesh_control_result_t publish(
    mesh_node_ipc_owner_v1_t *owner, uint16_t kind,
    const uint8_t request_id[MESH_CONTROL_ID_SIZE],
    const uint8_t operation_id[MESH_CONTROL_ID_SIZE], uint64_t desired_epoch,
    const uint8_t *body, size_t body_size) {
  mesh_node_ipc_envelope_v1_t envelope;
  mesh_control_result_t result;
  uint8_t frame[MESH_NODE_IPC_HEADER_SIZE_V1 + MESH_NODE_IPC_RESULT_SIZE_V1];
  size_t frame_size = 0u;
  if (owner->next_sequence == UINT64_MAX)
    return MESH_CONTROL_INVALID_STATE;
  memset(&envelope, 0, sizeof(envelope));
  envelope.kind = kind;
  memcpy(envelope.request_id, request_id, MESH_CONTROL_ID_SIZE);
  memcpy(envelope.operation_id, operation_id, MESH_CONTROL_ID_SIZE);
  memcpy(envelope.sender_incarnation, owner->sender_incarnation,
         MESH_CONTROL_ID_SIZE);
  envelope.sequence = owner->next_sequence;
  envelope.desired_epoch = desired_epoch;
  envelope.body = body;
  envelope.body_size = body_size;
  if (mesh_node_ipc_envelope_encode_v1(&envelope, frame, sizeof(frame),
                                       &frame_size) != MESH_CONTROL_OK)
    return MESH_CONTROL_INVALID_STATE;
  result = mesh_node_ipc_channel_try_push_v1(owner->outbound, frame, frame_size);
  if (result != MESH_CONTROL_OK)
    return result;
  owner->next_sequence++;
  return MESH_CONTROL_OK;
}

static mesh_control_result_t publish_result(
    mesh_node_ipc_owner_v1_t *owner, mesh_node_ipc_operation_v1_t *operation) {
  uint8_t body[MESH_NODE_IPC_RESULT_SIZE_V1];
  mesh_control_result_t result =
      mesh_node_ipc_result_encode_v1(&operation->result, body);
  if (result != MESH_CONTROL_OK)
    return result;
  result = publish(owner, MESH_NODE_IPC_RESULT_V1, operation->request_id,
                   operation->operation_id, operation->desired_epoch, body,
                   sizeof(body));
  if (result == MESH_CONTROL_OK)
    operation->result_sent = 1u;
  return result;
}

static mesh_node_ipc_operation_v1_t *append_operation(
    mesh_node_ipc_owner_v1_t *owner,
    const mesh_node_ipc_envelope_v1_t *envelope,
    const uint8_t binding_digest[MESH_CONTROL_DIGEST_SIZE],
    const mesh_node_ipc_command_v1_t *command) {
  mesh_node_ipc_operation_v1_t *operation;
  if (owner->operation_count >= owner->operation_capacity)
    return NULL;
  operation = &owner->operations[owner->operation_count++];
  memset(operation, 0, sizeof(*operation));
  memcpy(operation->operation_id, envelope->operation_id,
         MESH_CONTROL_ID_SIZE);
  memcpy(operation->request_id, envelope->request_id, MESH_CONTROL_ID_SIZE);
  memcpy(operation->binding_digest, binding_digest, MESH_CONTROL_DIGEST_SIZE);
  operation->desired_epoch = envelope->desired_epoch;
  operation->result.resource_kind = command->resource_kind;
  operation->result.action = command->action;
  memcpy(operation->result.resource_id, command->resource_id,
         MESH_CONTROL_DIGEST_SIZE);
  return operation;
}

static void complete_failure(mesh_node_ipc_operation_v1_t *operation,
                             mesh_control_result_t error,
                             mesh_node_ipc_failure_stage_v1_t stage) {
  operation->result.outcome = MESH_NODE_IPC_OUTCOME_FAILED_V1;
  operation->result.stable_error = stable_error(error);
  operation->result.failure_stage = stage;
}

static mesh_control_result_t publish_rejection(
    mesh_node_ipc_owner_v1_t *owner,
    const mesh_node_ipc_envelope_v1_t *envelope,
    const mesh_node_ipc_command_v1_t *command, mesh_control_result_t error) {
  mesh_node_ipc_result_v1_t rejection;
  uint8_t body[MESH_NODE_IPC_RESULT_SIZE_V1];
  mesh_control_result_t result;
  memset(&rejection, 0, sizeof(rejection));
  rejection.outcome = MESH_NODE_IPC_OUTCOME_FAILED_V1;
  rejection.stable_error = stable_error(error);
  rejection.failure_stage = MESH_NODE_IPC_STAGE_ADMISSION_V1;
  rejection.resource_kind = command->resource_kind;
  rejection.action = command->action;
  memcpy(rejection.resource_id, command->resource_id,
         sizeof(rejection.resource_id));
  result = mesh_node_ipc_result_encode_v1(&rejection, body);
  if (result != MESH_CONTROL_OK)
    return MESH_CONTROL_INVALID_STATE;
  result = publish(owner, MESH_NODE_IPC_RESULT_V1, envelope->request_id,
                   envelope->operation_id, envelope->desired_epoch, body,
                   sizeof(body));
  if (result != MESH_CONTROL_OK)
    return result;
  return mesh_node_ipc_channel_consume_v1(owner->inbound);
}

static mesh_control_result_t handle_ack(
    mesh_node_ipc_owner_v1_t *owner,
    const mesh_node_ipc_envelope_v1_t *envelope) {
  size_t index =
      find_operation(owner, envelope->operation_id, envelope->request_id);
  if (index == SIZE_MAX)
    return MESH_CONTROL_EMPTY;
  if (index + 1u < owner->operation_count)
    memmove(&owner->operations[index], &owner->operations[index + 1u],
            (owner->operation_count - index - 1u) *
                sizeof(*owner->operations));
  owner->operation_count--;
  memset(&owner->operations[owner->operation_count], 0,
         sizeof(*owner->operations));
  owner->results_acked++;
  return MESH_CONTROL_OK;
}

static mesh_control_result_t handle_command(
    mesh_node_ipc_owner_v1_t *owner,
    const mesh_node_ipc_envelope_v1_t *envelope) {
  mesh_node_ipc_command_v1_t command;
  mesh_node_ipc_execution_output_v1_t execution;
  mesh_node_ipc_operation_v1_t *operation;
  mesh_control_result_t result;
  uint8_t binding_digest[MESH_CONTROL_DIGEST_SIZE];
  size_t existing;

  if (mesh_node_ipc_command_decode_v1(envelope->body, envelope->body_size,
                                      &command) != MESH_CONTROL_OK ||
      turbo_crypto_sha256(envelope->body, envelope->body_size,
                          binding_digest) != TURBO_CRYPTO_OK) {
    (void)mesh_node_ipc_channel_consume_v1(owner->inbound);
    return MESH_CONTROL_INVALID_ARG;
  }

  existing = find_operation(owner, envelope->operation_id, NULL);
  if (existing != SIZE_MAX) {
    operation = &owner->operations[existing];
    if (!bytes_equal(operation->binding_digest, binding_digest,
                     sizeof(binding_digest)) ||
        !bytes_equal(operation->request_id, envelope->request_id,
                     MESH_CONTROL_ID_SIZE)) {
      owner->operation_collisions++;
      owner->commands_rejected++;
      return publish_rejection(owner, envelope, &command,
                               MESH_CONTROL_CONFLICT);
    }
    owner->duplicate_commands++;
    result = publish_result(owner, operation);
    if (result != MESH_CONTROL_OK)
      return result;
    return mesh_node_ipc_channel_consume_v1(owner->inbound);
  }

  if (!owner->accepting_commands) {
    owner->commands_rejected++;
    return publish_rejection(owner, envelope, &command, MESH_CONTROL_CLOSED);
  } else if (!bytes_equal(command.mesh_id, owner->mesh_id,
                          MESH_CONTROL_DIGEST_SIZE) ||
             !bytes_equal(command.provider_id, owner->provider_id,
                          MESH_CONTROL_DIGEST_SIZE) ||
             command.resource_kind >= 64u ||
             (owner->allowed_resource_mask &
              (UINT64_C(1) << command.resource_kind)) == 0u) {
    owner->commands_rejected++;
    return publish_rejection(owner, envelope, &command,
                             MESH_CONTROL_UNAUTHORIZED);
  }
  if (owner->operation_count >= owner->operation_capacity) {
    owner->commands_rejected++;
    return publish_rejection(owner, envelope, &command,
                             MESH_CONTROL_RESOURCE_EXHAUSTED);
  }

  result = publish(owner, MESH_NODE_IPC_ACCEPTED_V1, envelope->request_id,
                   envelope->operation_id, envelope->desired_epoch, NULL,
                   0u);
  if (result != MESH_CONTROL_OK)
    return result;
  operation = append_operation(owner, envelope, binding_digest, &command);
  if (!operation)
    return MESH_CONTROL_INVALID_STATE;
  memset(&execution, 0, sizeof(execution));
  result = owner->execute(owner->execute_context, &command,
                          envelope->desired_epoch, &execution);
  if (result == MESH_CONTROL_OK) {
    int observed_zero = bytes_zero(execution.observed_digest,
                                   sizeof(execution.observed_digest));
    if (execution.applied_epoch == 0u ||
        (command.action == MESH_CONTROL_DESIRED_APPLY && observed_zero) ||
        (command.action == MESH_CONTROL_DESIRED_DELETE && !observed_zero)) {
      complete_failure(operation, MESH_CONTROL_INVALID_STATE,
                       MESH_NODE_IPC_STAGE_RESULT_V1);
      owner->commands_rejected++;
    } else {
      operation->result.outcome = MESH_NODE_IPC_OUTCOME_SUCCEEDED_V1;
      operation->result.applied_epoch = execution.applied_epoch;
      memcpy(operation->result.observed_digest, execution.observed_digest,
             sizeof(operation->result.observed_digest));
      owner->commands_accepted++;
    }
  } else {
    complete_failure(operation, result, MESH_NODE_IPC_STAGE_EXECUTION_V1);
    owner->commands_rejected++;
  }

  result = mesh_node_ipc_channel_consume_v1(owner->inbound);
  if (result != MESH_CONTROL_OK)
    return MESH_CONTROL_INVALID_STATE;
  result = publish_result(owner, operation);
  return result == MESH_CONTROL_RESOURCE_EXHAUSTED ? MESH_CONTROL_OK : result;
}

mesh_control_result_t mesh_node_ipc_owner_init_v1(
    mesh_node_ipc_owner_v1_t *owner,
    const mesh_node_ipc_owner_config_v1_t *config) {
  if (!owner || !config || owner->initialized != 0u || !config->inbound ||
      !config->outbound || !config->execute || config->operation_capacity == 0u ||
      config->operation_capacity > MESH_CONTROL_OUTBOX_MAX_ENTRIES_V1 ||
      bytes_zero(config->mesh_id, sizeof(config->mesh_id)) ||
      bytes_zero(config->provider_id, sizeof(config->provider_id)) ||
      bytes_zero(config->sender_incarnation,
                 sizeof(config->sender_incarnation)) ||
      config->allowed_resource_mask == 0u)
    return MESH_CONTROL_INVALID_ARG;
  memset(owner, 0, sizeof(*owner));
  owner->operations = (mesh_node_ipc_operation_v1_t *)calloc(
      config->operation_capacity, sizeof(*owner->operations));
  if (!owner->operations)
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  owner->inbound = config->inbound;
  owner->outbound = config->outbound;
  owner->execute = config->execute;
  owner->execute_context = config->execute_context;
  memcpy(owner->mesh_id, config->mesh_id, sizeof(owner->mesh_id));
  memcpy(owner->provider_id, config->provider_id, sizeof(owner->provider_id));
  memcpy(owner->sender_incarnation, config->sender_incarnation,
         sizeof(owner->sender_incarnation));
  owner->allowed_resource_mask = config->allowed_resource_mask;
  owner->operation_capacity = config->operation_capacity;
  owner->next_sequence = 1u;
  owner->accepting_commands = 1u;
  owner->initialized = 1u;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_node_ipc_owner_poll_v1(
    mesh_node_ipc_owner_v1_t *owner, size_t budget, size_t *out_processed) {
  mesh_node_ipc_frame_view_v1_t frame;
  mesh_control_result_t result;
  size_t processed = 0u;
  if (!owner || !out_processed || owner->initialized == 0u || budget == 0u)
    return MESH_CONTROL_INVALID_ARG;
  *out_processed = 0u;

  {
    size_t index;
    for (index = 0u; index < owner->operation_count; ++index) {
      if (!owner->operations[index].result_sent) {
        result = publish_result(owner, &owner->operations[index]);
        if (result != MESH_CONTROL_OK)
          return result;
      }
    }
  }

  while (processed < budget) {
    result = mesh_node_ipc_channel_peek_v1(owner->inbound, &frame);
    if (result == MESH_CONTROL_EMPTY)
      break;
    if (result != MESH_CONTROL_OK)
      return result;
    if (frame.envelope.kind == MESH_NODE_IPC_COMMAND_V1) {
      result = handle_command(owner, &frame.envelope);
    } else if (frame.envelope.kind == MESH_NODE_IPC_ACK_RESULT_V1) {
      result = handle_ack(owner, &frame.envelope);
      if (result == MESH_CONTROL_EMPTY)
        result = MESH_CONTROL_OK;
      if (result == MESH_CONTROL_OK)
        result = mesh_node_ipc_channel_consume_v1(owner->inbound);
    } else if (frame.envelope.kind == MESH_NODE_IPC_DRAIN_V1) {
      owner->accepting_commands = 0u;
      result = publish(owner, MESH_NODE_IPC_DRAINED_V1,
                       frame.envelope.request_id, frame.envelope.operation_id,
                       0u, NULL, 0u);
      if (result == MESH_CONTROL_OK)
        result = mesh_node_ipc_channel_consume_v1(owner->inbound);
    } else {
      (void)mesh_node_ipc_channel_consume_v1(owner->inbound);
      result = MESH_CONTROL_UNSUPPORTED;
    }
    if (result != MESH_CONTROL_OK) {
      *out_processed = processed;
      return result;
    }
    processed++;
  }
  *out_processed = processed;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_node_ipc_owner_begin_drain_v1(
    mesh_node_ipc_owner_v1_t *owner) {
  if (!owner || owner->initialized == 0u)
    return MESH_CONTROL_INVALID_ARG;
  owner->accepting_commands = 0u;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_node_ipc_owner_get_stats_v1(
    const mesh_node_ipc_owner_v1_t *owner,
    mesh_node_ipc_owner_stats_v1_t *out_stats) {
  if (!owner || !out_stats || owner->initialized == 0u)
    return MESH_CONTROL_INVALID_ARG;
  memset(out_stats, 0, sizeof(*out_stats));
  out_stats->retained_operations = owner->operation_count;
  out_stats->operation_capacity = owner->operation_capacity;
  out_stats->accepting_commands = owner->accepting_commands;
  out_stats->commands_accepted = owner->commands_accepted;
  out_stats->commands_rejected = owner->commands_rejected;
  out_stats->duplicate_commands = owner->duplicate_commands;
  out_stats->operation_collisions = owner->operation_collisions;
  out_stats->results_acked = owner->results_acked;
  return MESH_CONTROL_OK;
}

void mesh_node_ipc_owner_destroy_v1(mesh_node_ipc_owner_v1_t *owner) {
  if (!owner)
    return;
  free(owner->operations);
  memset(owner, 0, sizeof(*owner));
}
