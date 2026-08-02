#include "mesh_mgmt_execution_rpc_control.h"

#include <string.h>

static int bytes_are_zero(const uint8_t *bytes, size_t size) {
  size_t index;
  uint8_t combined = 0u;

  if (!bytes)
    return 1;
  for (index = 0u; index < size; ++index)
    combined |= bytes[index];
  return combined == 0u;
}

static mesh_mgmt_execution_rpc_control_result_t map_registry_result(
    mesh_mgmt_execution_rpc_registry_result_t result) {
  switch (result) {
  case MESH_MGMT_EXECUTION_RPC_REGISTRY_OK:
    return MESH_MGMT_EXECUTION_RPC_CONTROL_OK;
  case MESH_MGMT_EXECUTION_RPC_REGISTRY_ALREADY_EXISTS:
    return MESH_MGMT_EXECUTION_RPC_CONTROL_ALREADY_EXISTS;
  case MESH_MGMT_EXECUTION_RPC_REGISTRY_CONFLICT:
    return MESH_MGMT_EXECUTION_RPC_CONTROL_CONFLICT;
  case MESH_MGMT_EXECUTION_RPC_REGISTRY_RESOURCE_EXHAUSTED:
    return MESH_MGMT_EXECUTION_RPC_CONTROL_RESOURCE_EXHAUSTED;
  case MESH_MGMT_EXECUTION_RPC_REGISTRY_NOT_FOUND:
    return MESH_MGMT_EXECUTION_RPC_CONTROL_NOT_FOUND;
  case MESH_MGMT_EXECUTION_RPC_REGISTRY_AUTH_FAILED:
  case MESH_MGMT_EXECUTION_RPC_REGISTRY_EXPIRED:
    return MESH_MGMT_EXECUTION_RPC_CONTROL_AUTH_FAILED;
  case MESH_MGMT_EXECUTION_RPC_REGISTRY_ALREADY_COMPLETE:
    return MESH_MGMT_EXECUTION_RPC_CONTROL_ALREADY_COMPLETE;
  case MESH_MGMT_EXECUTION_RPC_REGISTRY_NOT_READY:
    return MESH_MGMT_EXECUTION_RPC_CONTROL_NOT_READY;
  case MESH_MGMT_EXECUTION_RPC_REGISTRY_INVALID_ARG:
  default:
    return MESH_MGMT_EXECUTION_RPC_CONTROL_STATE_ERROR;
  }
}

mesh_mgmt_execution_rpc_control_result_t
mesh_mgmt_execution_rpc_control_init_v1(
    mesh_mgmt_execution_rpc_control_v1_t *control,
    const mesh_mgmt_execution_rpc_control_config_v1_t *config) {
  if (!control || !config || control->initialized || !config->registry ||
      !config->registry->impl || !config->clock_now_ms || !config->send ||
      bytes_are_zero(config->expected_mesh_id,
                     sizeof(config->expected_mesh_id)) ||
      bytes_are_zero(config->local_principal_key,
                     sizeof(config->local_principal_key)) ||
      bytes_are_zero(config->expected_grant_issuer_key,
                     sizeof(config->expected_grant_issuer_key)))
    return MESH_MGMT_EXECUTION_RPC_CONTROL_INVALID_ARG;
  memset(control, 0, sizeof(*control));
  control->config = *config;
  control->initialized = 1u;
  return MESH_MGMT_EXECUTION_RPC_CONTROL_OK;
}

mesh_mgmt_execution_rpc_control_result_t
mesh_mgmt_execution_rpc_control_submit_v1(
    mesh_mgmt_execution_rpc_control_v1_t *control, const uint8_t *payload,
    size_t payload_size,
    mesh_mgmt_execution_rpc_binding_v1_t *out_binding) {
  mesh_mgmt_execution_grant_v1_t grant;
  mesh_mgmt_execution_request_v1_t request;
  mesh_mgmt_execution_rpc_binding_v1_t binding;
  mesh_mgmt_execution_rpc_registry_result_t registry_result;
  mesh_mgmt_execution_rpc_transport_result_t send_result;
  uint64_t now_ms;

  if (!control || !control->initialized || !payload || payload_size == 0u ||
      !out_binding)
    return MESH_MGMT_EXECUTION_RPC_CONTROL_INVALID_ARG;
  memset(out_binding, 0, sizeof(*out_binding));
  now_ms = control->config.clock_now_ms(control->config.clock_context);
  if (now_ms == 0u)
    return MESH_MGMT_EXECUTION_RPC_CONTROL_CLOCK_FAILED;
  if (mesh_mgmt_execution_command_request_decode_v1(
          payload, payload_size, &grant, &request) !=
      MESH_MGMT_EXECUTION_WIRE_OK)
    return MESH_MGMT_EXECUTION_RPC_CONTROL_INVALID_REQUEST;
  if (mesh_mgmt_execution_grant_verify_v1(
          &grant, control->config.expected_grant_issuer_key, now_ms) !=
      MESH_MGMT_EXECUTION_WIRE_OK)
    return MESH_MGMT_EXECUTION_RPC_CONTROL_AUTH_FAILED;
  if (mesh_mgmt_execution_request_validate_v1(&request, now_ms) !=
          MESH_MGMT_EXECUTION_OK ||
      mesh_mgmt_execution_request_bind_v1(&grant, &request) !=
          MESH_MGMT_EXECUTION_OK)
    return MESH_MGMT_EXECUTION_RPC_CONTROL_INVALID_REQUEST;
  if (memcmp(grant.mesh_id, control->config.expected_mesh_id,
             sizeof(grant.mesh_id)) != 0 ||
      memcmp(grant.subject_principal, control->config.local_principal_key,
             sizeof(grant.subject_principal)) != 0)
    return MESH_MGMT_EXECUTION_RPC_CONTROL_SCOPE_MISMATCH;

  memset(&binding, 0, sizeof(binding));
  memcpy(binding.command_id, request.command_id, sizeof(binding.command_id));
  memcpy(binding.correlation_id, request.correlation_id,
         sizeof(binding.correlation_id));
  memcpy(binding.target_node_id, request.target_node_id,
         sizeof(binding.target_node_id));
  binding.deadline_ms = request.deadline_ms;
  if (mesh_mgmt_execution_request_digest_v1(
          &request, binding.request_digest) !=
      MESH_MGMT_EXECUTION_RESULT_OK)
    return MESH_MGMT_EXECUTION_RPC_CONTROL_INVALID_REQUEST;

  *out_binding = binding;
  registry_result = mesh_mgmt_execution_rpc_registry_register_v1(
      control->config.registry, &binding, now_ms);
  if (registry_result != MESH_MGMT_EXECUTION_RPC_REGISTRY_OK)
    return map_registry_result(registry_result);

  send_result = control->config.send(control->config.send_context,
                                     binding.target_node_id, payload,
                                     payload_size);
  if (send_result == MESH_MGMT_EXECUTION_RPC_TRANSPORT_SENT)
    return MESH_MGMT_EXECUTION_RPC_CONTROL_OK;
  if (send_result == MESH_MGMT_EXECUTION_RPC_TRANSPORT_AMBIGUOUS)
    return MESH_MGMT_EXECUTION_RPC_CONTROL_SEND_AMBIGUOUS;
  if (send_result == MESH_MGMT_EXECUTION_RPC_TRANSPORT_UNAVAILABLE) {
    registry_result = mesh_mgmt_execution_rpc_registry_abandon_v1(
        control->config.registry, &binding);
    if (registry_result != MESH_MGMT_EXECUTION_RPC_REGISTRY_OK)
      return MESH_MGMT_EXECUTION_RPC_CONTROL_STATE_ERROR;
    return MESH_MGMT_EXECUTION_RPC_CONTROL_SEND_UNAVAILABLE;
  }
  return MESH_MGMT_EXECUTION_RPC_CONTROL_STATE_ERROR;
}

mesh_mgmt_execution_rpc_control_result_t
mesh_mgmt_execution_rpc_control_get_v1(
    mesh_mgmt_execution_rpc_control_v1_t *control,
    const uint8_t correlation_id[MESH_MGMT_EXECUTION_ID_SIZE],
    mesh_mgmt_execution_rpc_completion_v1_t *out_completion) {
  uint64_t now_ms;

  if (!control || !control->initialized || !correlation_id ||
      !out_completion)
    return MESH_MGMT_EXECUTION_RPC_CONTROL_INVALID_ARG;
  now_ms = control->config.clock_now_ms(control->config.clock_context);
  if (now_ms == 0u)
    return MESH_MGMT_EXECUTION_RPC_CONTROL_CLOCK_FAILED;
  return map_registry_result(mesh_mgmt_execution_rpc_registry_get_v1(
      control->config.registry, correlation_id, now_ms, out_completion));
}

mesh_mgmt_execution_rpc_control_result_t
mesh_mgmt_execution_rpc_control_complete_v1(
    mesh_mgmt_execution_rpc_control_v1_t *control,
    const mesh_mgmt_execution_response_v1_t *verified_response) {
  uint64_t now_ms;

  if (!control || !control->initialized || !verified_response)
    return MESH_MGMT_EXECUTION_RPC_CONTROL_INVALID_ARG;
  now_ms = control->config.clock_now_ms(control->config.clock_context);
  if (now_ms == 0u)
    return MESH_MGMT_EXECUTION_RPC_CONTROL_CLOCK_FAILED;
  return map_registry_result(mesh_mgmt_execution_rpc_registry_complete_v1(
      control->config.registry, verified_response, now_ms));
}

size_t mesh_mgmt_execution_rpc_control_sweep_v1(
    mesh_mgmt_execution_rpc_control_v1_t *control) {
  uint64_t now_ms;

  if (!control || !control->initialized)
    return 0u;
  now_ms = control->config.clock_now_ms(control->config.clock_context);
  if (now_ms == 0u)
    return 0u;
  return mesh_mgmt_execution_rpc_registry_sweep_v1(
      control->config.registry, now_ms);
}
