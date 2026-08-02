#include "mesh_mgmt_execution_service.h"

#include "mesh_mgmt_execution_result.h"
#include "mesh_mgmt_execution_wire.h"

#include <string.h>

static int mesh_mgmt_execution_service_digest_equal(
    const uint8_t lhs[32], const uint8_t rhs[32]) {
  uint8_t difference = 0u;
  size_t index;

  for (index = 0u; index < 32u; ++index) {
    difference |= (uint8_t)(lhs[index] ^ rhs[index]);
  }
  return difference == 0u;
}

static mesh_mgmt_execution_service_result_t
mesh_mgmt_execution_service_map_orchestrator_result(
    mesh_mgmt_execution_orchestrator_result_t result) {
  switch (result) {
    case MESH_MGMT_EXECUTION_ORCHESTRATOR_OK:
      return MESH_MGMT_EXECUTION_SERVICE_OK;
    case MESH_MGMT_EXECUTION_ORCHESTRATOR_INVALID_ARG:
      return MESH_MGMT_EXECUTION_SERVICE_INVALID_ARG;
    case MESH_MGMT_EXECUTION_ORCHESTRATOR_AUTH_FAILED:
      return MESH_MGMT_EXECUTION_SERVICE_AUTH_FAILED;
    case MESH_MGMT_EXECUTION_ORCHESTRATOR_CONFLICT:
      return MESH_MGMT_EXECUTION_SERVICE_CONFLICT;
    case MESH_MGMT_EXECUTION_ORCHESTRATOR_BUSY:
      return MESH_MGMT_EXECUTION_SERVICE_BUSY;
    case MESH_MGMT_EXECUTION_ORCHESTRATOR_INDETERMINATE:
      return MESH_MGMT_EXECUTION_SERVICE_INDETERMINATE;
    case MESH_MGMT_EXECUTION_ORCHESTRATOR_STORE_FAILED:
      return MESH_MGMT_EXECUTION_SERVICE_STORE_FAILED;
    case MESH_MGMT_EXECUTION_ORCHESTRATOR_SIGN_FAILED:
      return MESH_MGMT_EXECUTION_SERVICE_SIGN_FAILED;
    case MESH_MGMT_EXECUTION_ORCHESTRATOR_CLOCK_FAILED:
      return MESH_MGMT_EXECUTION_SERVICE_CLOCK_FAILED;
    default:
      return MESH_MGMT_EXECUTION_SERVICE_INDETERMINATE;
  }
}

mesh_mgmt_execution_service_result_t mesh_mgmt_execution_service_init_v1(
    mesh_mgmt_execution_service_v1_t *service,
    const mesh_mgmt_execution_service_config_v1_t *config) {
  if (service == NULL || config == NULL || config->orchestrator == NULL) {
    return MESH_MGMT_EXECUTION_SERVICE_INVALID_ARG;
  }

  memset(service, 0, sizeof(*service));
  service->orchestrator = config->orchestrator;
  service->enabled = config->enabled != 0u;
  service->initialized = 1u;
  return MESH_MGMT_EXECUTION_SERVICE_OK;
}

void mesh_mgmt_execution_service_destroy_v1(
    mesh_mgmt_execution_service_v1_t *service) {
  if (service != NULL) {
    memset(service, 0, sizeof(*service));
  }
}

mesh_mgmt_execution_service_result_t mesh_mgmt_execution_service_execute_v1(
    mesh_mgmt_execution_service_v1_t *service,
    const mesh_mgmt_execution_shadow_command_v1_t *command,
    const mesh_mgmt_execution_authorization_input_v1_t *authorization,
    const mesh_mgmt_execution_runner_io_v1_t *io,
    uint8_t *out_payload,
    size_t out_payload_capacity,
    size_t *out_payload_size,
    mesh_mgmt_execution_result_v1_t *out_result) {
  mesh_mgmt_execution_orchestrator_result_t orchestrator_result;
  mesh_mgmt_execution_service_result_t service_result;
  mesh_mgmt_execution_result_v1_t result;
  uint8_t request_digest[32];
  size_t encoded_size = 0u;

  if (out_payload_size != NULL) {
    *out_payload_size = MESH_MGMT_EXECUTION_COMMAND_RESULT_SIZE_V1;
  }
  if (out_result != NULL) {
    memset(out_result, 0, sizeof(*out_result));
  }

  if (service == NULL || command == NULL || authorization == NULL ||
      out_payload_size == NULL || out_result == NULL) {
    return MESH_MGMT_EXECUTION_SERVICE_INVALID_ARG;
  }
  if (service->initialized == 0u || service->orchestrator == NULL) {
    return MESH_MGMT_EXECUTION_SERVICE_INVALID_ARG;
  }
  if (service->enabled == 0u) {
    return MESH_MGMT_EXECUTION_SERVICE_DISABLED;
  }
  if (out_payload == NULL ||
      out_payload_capacity < MESH_MGMT_EXECUTION_COMMAND_RESULT_SIZE_V1) {
    return MESH_MGMT_EXECUTION_SERVICE_RESOURCE_EXHAUSTED;
  }
  if (mesh_mgmt_execution_request_digest_v1(
          &command->request, request_digest) != 0 ||
      !mesh_mgmt_execution_service_digest_equal(
          request_digest, command->request_digest)) {
    return MESH_MGMT_EXECUTION_SERVICE_INVALID_COMMAND;
  }

  memset(&result, 0, sizeof(result));
  orchestrator_result = mesh_mgmt_execution_orchestrator_execute_v1(
      service->orchestrator, &command->grant, &command->request, authorization,
      io, &result);
  service_result =
      mesh_mgmt_execution_service_map_orchestrator_result(orchestrator_result);
  if (service_result != MESH_MGMT_EXECUTION_SERVICE_OK) {
    return service_result;
  }

  if (mesh_mgmt_execution_command_result_encode_v1(
          &result, out_payload, out_payload_capacity, &encoded_size) !=
          MESH_MGMT_EXECUTION_WIRE_OK ||
      encoded_size != MESH_MGMT_EXECUTION_COMMAND_RESULT_SIZE_V1) {
    memset(out_payload, 0, out_payload_capacity);
    return MESH_MGMT_EXECUTION_SERVICE_ENCODE_FAILED;
  }

  *out_payload_size = encoded_size;
  *out_result = result;
  return MESH_MGMT_EXECUTION_SERVICE_OK;
}
