#include "mesh_control_policy.h"

#include <string.h>

void mesh_control_node_policy_default_v1(
    mesh_control_node_policy_v1_t *out_policy) {
  if (out_policy == NULL)
    return;
  memset(out_policy, 0, sizeof(*out_policy));
  out_policy->local_permissions =
      MESH_CONTROL_PERMISSION_OBSERVE | MESH_CONTROL_PERMISSION_MANAGE |
      MESH_CONTROL_PERMISSION_RUN_BUILTIN;
  out_policy->available_runtimes = MESH_CONTROL_RUNTIME_AVAILABLE_BUILTIN;
}

mesh_control_result_t mesh_control_node_policy_validate_v1(
    const mesh_control_node_policy_v1_t *policy) {
  if (policy == NULL ||
      (policy->local_permissions & ~MESH_CONTROL_PERMISSION_KNOWN_V1) != 0u ||
      (policy->available_runtimes &
       ~MESH_CONTROL_RUNTIME_AVAILABLE_KNOWN_V1) != 0u ||
      (policy->local_permissions & MESH_CONTROL_PERMISSION_OBSERVE) == 0u ||
      (policy->local_permissions & MESH_CONTROL_PERMISSION_MANAGE) == 0u ||
      ((policy->local_permissions & MESH_CONTROL_PERMISSION_RUN_BUILTIN) !=
           0u &&
       (policy->available_runtimes &
        MESH_CONTROL_RUNTIME_AVAILABLE_BUILTIN) == 0u) ||
      ((policy->local_permissions & MESH_CONTROL_PERMISSION_RUN_NATIVE) != 0u &&
       (policy->available_runtimes &
        MESH_CONTROL_RUNTIME_AVAILABLE_NATIVE) == 0u) ||
      ((policy->local_permissions & MESH_CONTROL_PERMISSION_RUN_WASM) != 0u &&
       (policy->available_runtimes &
        MESH_CONTROL_RUNTIME_AVAILABLE_WASM) == 0u)) {
    return MESH_CONTROL_INVALID_ARG;
  }
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_node_policy_authorize_function_v1(
    const mesh_control_node_policy_v1_t *policy,
    const mesh_control_function_spec_v1_t *spec,
    uint64_t granted_permissions, uint64_t *out_effective_permissions) {
  mesh_control_result_t result;
  uint32_t required_runtime;

  if (mesh_control_node_policy_validate_v1(policy) != MESH_CONTROL_OK ||
      spec == NULL || out_effective_permissions == NULL) {
    return MESH_CONTROL_INVALID_ARG;
  }
  result = mesh_control_function_authorize_v1(
      spec, granted_permissions, policy->local_permissions,
      out_effective_permissions);
  if (result != MESH_CONTROL_OK ||
      spec->desired_state == MESH_CONTROL_FUNCTION_STOPPED) {
    return result;
  }
  switch (spec->runtime) {
  case MESH_CONTROL_FUNCTION_BUILTIN:
    required_runtime = MESH_CONTROL_RUNTIME_AVAILABLE_BUILTIN;
    break;
  case MESH_CONTROL_FUNCTION_NATIVE:
    required_runtime = MESH_CONTROL_RUNTIME_AVAILABLE_NATIVE;
    break;
  case MESH_CONTROL_FUNCTION_WASM:
    required_runtime = MESH_CONTROL_RUNTIME_AVAILABLE_WASM;
    break;
  default:
    return MESH_CONTROL_INVALID_ARG;
  }
  return (policy->available_runtimes & required_runtime) != 0u
             ? MESH_CONTROL_OK
             : MESH_CONTROL_INVALID_STATE;
}

mesh_control_result_t mesh_control_node_policy_authorize_function_intent_v1(
    const mesh_control_node_policy_v1_t *policy,
    const mesh_control_envelope_v1_t *envelope, const uint8_t *payload,
    size_t payload_size, uint64_t granted_permissions,
    uint64_t *out_effective_permissions,
    mesh_control_function_spec_v1_t *out_spec) {
  mesh_control_intent_view_v1_t intent;

  if (out_effective_permissions == NULL || out_spec == NULL)
    return MESH_CONTROL_INVALID_ARG;
  *out_effective_permissions = 0u;
  memset(out_spec, 0, sizeof(*out_spec));
  if (mesh_control_node_policy_validate_v1(policy) != MESH_CONTROL_OK ||
      envelope == NULL || envelope->kind != MESH_CONTROL_MESSAGE_INTENT ||
      envelope->resource_kind != MESH_CONTROL_RESOURCE_FUNCTION ||
      (granted_permissions & ~MESH_CONTROL_PERMISSION_KNOWN_V1) != 0u ||
      mesh_control_intent_decode_v1(payload, payload_size, &intent) !=
          MESH_CONTROL_OK)
    return MESH_CONTROL_INVALID_ARG;
  if (intent.action == MESH_CONTROL_DESIRED_DELETE) {
    uint64_t effective = granted_permissions & policy->local_permissions;
    if (intent.document_size != 0u)
      return MESH_CONTROL_INVALID_ARG;
    *out_effective_permissions = effective;
    return (effective & MESH_CONTROL_PERMISSION_MANAGE) != 0u
               ? MESH_CONTROL_OK
               : MESH_CONTROL_CONFLICT;
  }
  if (mesh_control_function_document_decode_v1(
          intent.document, intent.document_size, out_spec) !=
      MESH_CONTROL_OK)
    return MESH_CONTROL_INVALID_ARG;
  if (memcmp(out_spec->function_id, envelope->resource_id,
             MESH_CONTROL_DIGEST_SIZE) != 0 ||
      out_spec->generation != envelope->epoch) {
    memset(out_spec, 0, sizeof(*out_spec));
    return MESH_CONTROL_CONFLICT;
  }
  return mesh_control_node_policy_authorize_function_v1(
      policy, out_spec, granted_permissions, out_effective_permissions);
}
