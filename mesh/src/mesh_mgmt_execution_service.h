#ifndef MESH_MGMT_EXECUTION_SERVICE_H
#define MESH_MGMT_EXECUTION_SERVICE_H

#include "mesh_mgmt_execution_consumer.h"
#include "mesh_mgmt_execution_orchestrator.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum mesh_mgmt_execution_service_result {
  MESH_MGMT_EXECUTION_SERVICE_OK = 0,
  MESH_MGMT_EXECUTION_SERVICE_INVALID_ARG = -1,
  MESH_MGMT_EXECUTION_SERVICE_DISABLED = -2,
  MESH_MGMT_EXECUTION_SERVICE_INVALID_COMMAND = -3,
  MESH_MGMT_EXECUTION_SERVICE_RESOURCE_EXHAUSTED = -4,
  MESH_MGMT_EXECUTION_SERVICE_AUTH_FAILED = -5,
  MESH_MGMT_EXECUTION_SERVICE_CONFLICT = -6,
  MESH_MGMT_EXECUTION_SERVICE_BUSY = -7,
  MESH_MGMT_EXECUTION_SERVICE_INDETERMINATE = -8,
  MESH_MGMT_EXECUTION_SERVICE_STORE_FAILED = -9,
  MESH_MGMT_EXECUTION_SERVICE_SIGN_FAILED = -10,
  MESH_MGMT_EXECUTION_SERVICE_CLOCK_FAILED = -11,
  MESH_MGMT_EXECUTION_SERVICE_ENCODE_FAILED = -12
} mesh_mgmt_execution_service_result_t;

typedef struct mesh_mgmt_execution_service_config_v1 {
  mesh_mgmt_execution_orchestrator_v1_t *orchestrator;
  uint8_t enabled;
} mesh_mgmt_execution_service_config_v1_t;

typedef struct mesh_mgmt_execution_service_v1 {
  mesh_mgmt_execution_orchestrator_v1_t *orchestrator;
  uint8_t enabled;
  uint8_t initialized;
} mesh_mgmt_execution_service_v1_t;

mesh_mgmt_execution_service_result_t mesh_mgmt_execution_service_init_v1(
    mesh_mgmt_execution_service_v1_t *service,
    const mesh_mgmt_execution_service_config_v1_t *config);

void mesh_mgmt_execution_service_destroy_v1(
    mesh_mgmt_execution_service_v1_t *service);

/*
 * Executes only owned commands emitted by mesh_mgmt_execution_consumer.
 * The caller serializes orchestrator access and invokes this outside Mesh/MMP
 * event loops. out_payload_size receives the fixed required result size before
 * any execution side effect.
 */
mesh_mgmt_execution_service_result_t mesh_mgmt_execution_service_execute_v1(
    mesh_mgmt_execution_service_v1_t *service,
    const mesh_mgmt_execution_shadow_command_v1_t *command,
    const mesh_mgmt_execution_authorization_input_v1_t *authorization,
    const mesh_mgmt_execution_runner_io_v1_t *io,
    uint8_t *out_payload,
    size_t out_payload_capacity,
    size_t *out_payload_size,
    mesh_mgmt_execution_result_v1_t *out_result);

#ifdef __cplusplus
}
#endif

#endif
