#ifndef MESH_MGMT_EXECUTION_RESPONSE_CONSUMER_H
#define MESH_MGMT_EXECUTION_RESPONSE_CONSUMER_H

#include "mesh_mgmt_dispatch.h"
#include "mesh_mgmt_execution_wire.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  MESH_MGMT_EXECUTION_RESPONSE_CONSUMER_OK = 0,
  MESH_MGMT_EXECUTION_RESPONSE_CONSUMER_INVALID_ARG = -1,
  MESH_MGMT_EXECUTION_RESPONSE_CONSUMER_INVALID_STATE = -2,
  MESH_MGMT_EXECUTION_RESPONSE_CONSUMER_AUTH_FAILED = -3,
  MESH_MGMT_EXECUTION_RESPONSE_CONSUMER_INVALID_SCHEMA = -4
} mesh_mgmt_execution_response_consumer_result_t;

typedef struct {
  uint8_t kind;
  uint8_t origin_node_id[32];
  uint8_t target_node_id[32];
  mesh_mgmt_execution_result_v1_t result;
  mesh_mgmt_execution_status_v1_t status;
} mesh_mgmt_execution_response_v1_t;

mesh_mgmt_execution_response_consumer_result_t
mesh_mgmt_execution_response_from_event_v1(
    const mesh_mgmt_dispatcher_v1_t *dispatcher,
    const mesh_mgmt_dispatch_event_v1_t *event,
    mesh_mgmt_execution_response_v1_t *out_response);

#ifdef __cplusplus
}
#endif

#endif
