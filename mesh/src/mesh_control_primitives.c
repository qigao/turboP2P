#include "mesh_control_primitives.h"

static int bytes_are_zero(const uint8_t *bytes, size_t size) {
  size_t index;
  uint8_t combined = 0u;

  if (!bytes)
    return 1;
  for (index = 0u; index < size; ++index)
    combined |= bytes[index];
  return combined == 0u;
}

static int message_kind_valid(uint16_t kind) {
  return kind >= MESH_CONTROL_MESSAGE_HELLO &&
         kind <= MESH_CONTROL_MESSAGE_RECEIPT;
}

static int resource_kind_valid(uint16_t kind) {
  return kind >= MESH_CONTROL_RESOURCE_NODE &&
         kind <= MESH_CONTROL_RESOURCE_RELEASE;
}

static int operation_state_valid(mesh_control_operation_state_v1_t state) {
  return state >= MESH_CONTROL_OPERATION_SUBMITTED &&
         state <= MESH_CONTROL_OPERATION_INTERRUPTED;
}

mesh_control_result_t mesh_control_envelope_validate_v1(
    const mesh_control_envelope_v1_t *envelope) {
  int is_hello;
  int requires_target;

  if (!envelope || envelope->schema_version != MESH_CONTROL_SCHEMA_V1 ||
      !message_kind_valid(envelope->kind) || envelope->reserved != 0u ||
      bytes_are_zero(envelope->message_id, sizeof(envelope->message_id)) ||
      bytes_are_zero(envelope->mesh_id, sizeof(envelope->mesh_id)) ||
      bytes_are_zero(envelope->origin_principal,
                     sizeof(envelope->origin_principal)) ||
      envelope->sequence == 0u || envelope->issued_at_ms == 0u ||
      envelope->expires_at_ms <= envelope->issued_at_ms ||
      envelope->payload_size > MESH_CONTROL_MAX_FRAME_SIZE_V1) {
    return MESH_CONTROL_INVALID_ARG;
  }

  is_hello = envelope->kind == MESH_CONTROL_MESSAGE_HELLO;
  requires_target = envelope->kind == MESH_CONTROL_MESSAGE_INTENT ||
                    envelope->kind == MESH_CONTROL_MESSAGE_OPERATION;
  if (requires_target &&
      bytes_are_zero(envelope->target_node_id,
                     sizeof(envelope->target_node_id))) {
    return MESH_CONTROL_INVALID_ARG;
  }
  if (is_hello) {
    if (envelope->resource_kind != MESH_CONTROL_RESOURCE_NONE ||
        !bytes_are_zero(envelope->resource_id,
                        sizeof(envelope->resource_id)) ||
        envelope->precondition_epoch != 0u) {
      return MESH_CONTROL_INVALID_ARG;
    }
  } else if (!resource_kind_valid(envelope->resource_kind) ||
             bytes_are_zero(envelope->resource_id,
                            sizeof(envelope->resource_id)) ||
             envelope->epoch == 0u) {
    return MESH_CONTROL_INVALID_ARG;
  }
  if ((envelope->payload_size == 0u) !=
      bytes_are_zero(envelope->payload_digest,
                     sizeof(envelope->payload_digest))) {
    return MESH_CONTROL_INVALID_ARG;
  }
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_function_spec_validate_v1(
    const mesh_control_function_spec_v1_t *spec) {
  uint32_t known_flags = MESH_CONTROL_FUNCTION_FLAG_PRESTAGED |
                         MESH_CONTROL_FUNCTION_FLAG_OUT_OF_PROCESS;

  if (!spec || spec->schema_version != MESH_CONTROL_SCHEMA_V1 ||
      spec->runtime < MESH_CONTROL_FUNCTION_BUILTIN ||
      spec->runtime > MESH_CONTROL_FUNCTION_NATIVE ||
      spec->desired_state < MESH_CONTROL_FUNCTION_STAGED ||
      spec->desired_state > MESH_CONTROL_FUNCTION_STOPPED ||
      spec->reserved != 0u || (spec->flags & ~known_flags) != 0u ||
      bytes_are_zero(spec->function_id, sizeof(spec->function_id)) ||
      bytes_are_zero(spec->provider_id, sizeof(spec->provider_id)) ||
      bytes_are_zero(spec->config_digest, sizeof(spec->config_digest)) ||
      bytes_are_zero(spec->network_policy_digest,
                     sizeof(spec->network_policy_digest)) ||
      spec->generation == 0u || spec->limits.memory_bytes == 0u ||
      spec->limits.cpu_time_ms == 0u || spec->limits.input_bytes == 0u ||
      spec->limits.output_bytes == 0u || spec->limits.concurrency == 0u ||
      spec->limits.host_calls == 0u) {
    return MESH_CONTROL_INVALID_ARG;
  }
  if ((spec->runtime == MESH_CONTROL_FUNCTION_WASM ||
       spec->runtime == MESH_CONTROL_FUNCTION_NATIVE) &&
      (bytes_are_zero(spec->artifact_digest,
                      sizeof(spec->artifact_digest)) ||
       (spec->flags & MESH_CONTROL_FUNCTION_FLAG_PRESTAGED) == 0u)) {
    return MESH_CONTROL_INVALID_ARG;
  }
  if (spec->runtime == MESH_CONTROL_FUNCTION_NATIVE &&
      (spec->flags & MESH_CONTROL_FUNCTION_FLAG_OUT_OF_PROCESS) == 0u) {
    return MESH_CONTROL_INVALID_ARG;
  }
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_function_authorize_v1(
    const mesh_control_function_spec_v1_t *spec,
    uint64_t granted_permissions, uint64_t local_permissions,
    uint64_t *out_effective_permissions) {
  uint64_t effective;
  uint64_t required = MESH_CONTROL_PERMISSION_MANAGE;

  if (!out_effective_permissions ||
      mesh_control_function_spec_validate_v1(spec) != MESH_CONTROL_OK ||
      (granted_permissions & ~MESH_CONTROL_PERMISSION_KNOWN_V1) != 0u ||
      (local_permissions & ~MESH_CONTROL_PERMISSION_KNOWN_V1) != 0u) {
    return MESH_CONTROL_INVALID_ARG;
  }
  *out_effective_permissions = 0u;
  effective = granted_permissions & local_permissions;
  if (spec->desired_state == MESH_CONTROL_FUNCTION_RUNNING) {
    switch (spec->runtime) {
    case MESH_CONTROL_FUNCTION_BUILTIN:
      required |= MESH_CONTROL_PERMISSION_RUN_BUILTIN;
      break;
    case MESH_CONTROL_FUNCTION_NATIVE:
      required |= MESH_CONTROL_PERMISSION_RUN_NATIVE;
      break;
    case MESH_CONTROL_FUNCTION_WASM:
      required |= MESH_CONTROL_PERMISSION_RUN_WASM;
      break;
    default:
      return MESH_CONTROL_INVALID_ARG;
    }
  }
  *out_effective_permissions = effective;
  return (effective & required) == required ? MESH_CONTROL_OK
                                             : MESH_CONTROL_CONFLICT;
}

int mesh_control_operation_state_is_terminal_v1(
    mesh_control_operation_state_v1_t state) {
  return state == MESH_CONTROL_OPERATION_SUCCEEDED ||
         state == MESH_CONTROL_OPERATION_FAILED ||
         state == MESH_CONTROL_OPERATION_REJECTED ||
         state == MESH_CONTROL_OPERATION_EXPIRED ||
         state == MESH_CONTROL_OPERATION_INTERRUPTED;
}

int mesh_control_operation_transition_allowed_v1(
    mesh_control_operation_state_v1_t from,
    mesh_control_operation_state_v1_t to) {
  if (!operation_state_valid(from) || !operation_state_valid(to))
    return 0;
  if (from == to)
    return 1;
  if (mesh_control_operation_state_is_terminal_v1(from))
    return 0;
  switch (from) {
  case MESH_CONTROL_OPERATION_SUBMITTED:
    return to == MESH_CONTROL_OPERATION_ACCEPTED ||
           to == MESH_CONTROL_OPERATION_REJECTED ||
           to == MESH_CONTROL_OPERATION_EXPIRED;
  case MESH_CONTROL_OPERATION_ACCEPTED:
    return to == MESH_CONTROL_OPERATION_RUNNING ||
           to == MESH_CONTROL_OPERATION_SUCCEEDED ||
           to == MESH_CONTROL_OPERATION_FAILED ||
           to == MESH_CONTROL_OPERATION_REJECTED ||
           to == MESH_CONTROL_OPERATION_EXPIRED ||
           to == MESH_CONTROL_OPERATION_INTERRUPTED;
  case MESH_CONTROL_OPERATION_RUNNING:
    return mesh_control_operation_state_is_terminal_v1(to);
  default:
    return 0;
  }
}
