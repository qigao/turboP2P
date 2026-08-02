#ifndef MESH_MGMT_EXECUTION_NODE_H
#define MESH_MGMT_EXECUTION_NODE_H

#include "mesh_mgmt_agent_runtime.h"
#include "mesh_mgmt_execution_egress.h"
#include "mesh_mgmt_execution_sender.h"
#include "mesh_mgmt_execution_service.h"
#include "mesh_mgmt_execution_worker.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_MGMT_EXECUTION_NODE_MAX_DEPLOYMENTS \
  MESH_MGMT_EXECUTION_RUNNER_MAX_DEPLOYMENTS
#define MESH_MGMT_EXECUTION_NODE_RAW_CAPABILITIES \
  (MESH_MGMT_EXECUTION_CAP_CORE | MESH_MGMT_EXECUTION_CAP_UTILS | \
   MESH_MGMT_EXECUTION_CAP_APP)

typedef enum {
  MESH_MGMT_EXECUTION_NODE_OK = 0,
  MESH_MGMT_EXECUTION_NODE_INVALID_ARG = -1,
  MESH_MGMT_EXECUTION_NODE_INVALID_CONFIG = -2,
  MESH_MGMT_EXECUTION_NODE_DEPLOYMENT_FAILED = -3,
  MESH_MGMT_EXECUTION_NODE_STORE_FAILED = -4,
  MESH_MGMT_EXECUTION_NODE_ORCHESTRATOR_FAILED = -5,
  MESH_MGMT_EXECUTION_NODE_SERVICE_FAILED = -6,
  MESH_MGMT_EXECUTION_NODE_EGRESS_FAILED = -7,
  MESH_MGMT_EXECUTION_NODE_WORKER_FAILED = -8,
  MESH_MGMT_EXECUTION_NODE_DISABLED = -9,
  MESH_MGMT_EXECUTION_NODE_BUSY = -10,
  MESH_MGMT_EXECUTION_NODE_CLOSED = -11,
  MESH_MGMT_EXECUTION_NODE_SEND_FAILED = -12,
  MESH_MGMT_EXECUTION_NODE_EMPTY = -13
} mesh_mgmt_execution_node_result_t;

typedef struct {
  const char *store_path;
  size_t store_capacity;
  size_t deployment_capacity;
  size_t worker_queue_capacity;
  size_t egress_capacity;
  const mesh_mgmt_execution_deployment_v1_t *deployments;
  size_t deployment_count;
  uint8_t local_node_id[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint8_t result_private_key[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint8_t grant_issuer_key[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint32_t host_capabilities;
  uint32_t hard_capabilities;
  mesh_mgmt_execution_limits_v1_t host_limits;
  mesh_mgmt_execution_limits_v1_t hard_limits;
  uint64_t worker_generation;
  mesh_mgmt_execution_clock_v1_fn clock_now_ms;
  void *clock_context;
} mesh_mgmt_execution_node_config_v1_t;

/**
 * Single-owner composition root for one node's prestaged TurboRuntime
 * execution boundary. Submit is called from the MMP event loop; execution and
 * durable store access are serialized by the one-thread worker.
 */
typedef struct {
  mesh_mgmt_execution_runner_v1_t runner;
  mesh_mgmt_execution_store_v1_t store;
  mesh_mgmt_execution_orchestrator_v1_t orchestrator;
  mesh_mgmt_execution_service_v1_t service;
  mesh_mgmt_execution_egress_v1_t egress;
  mesh_mgmt_execution_worker_v1_t worker;
  mesh_mgmt_execution_authorization_input_v1_t authorization_template;
  uint8_t grant_issuer_key[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint8_t initialized;
  uint8_t accepting;
} mesh_mgmt_execution_node_v1_t;

mesh_mgmt_execution_node_result_t mesh_mgmt_execution_node_init_v1(
    mesh_mgmt_execution_node_v1_t *node,
    const mesh_mgmt_execution_node_config_v1_t *config);

mesh_mgmt_execution_node_result_t mesh_mgmt_execution_node_try_submit_v1(
    mesh_mgmt_execution_node_v1_t *node,
    const mesh_mgmt_execution_shadow_command_v1_t *command);

mesh_mgmt_execution_node_result_t mesh_mgmt_execution_node_send_next_v1(
    mesh_mgmt_execution_node_v1_t *node,
    mesh_mgmt_agent_runtime_v1_t *runtime);

mesh_mgmt_execution_node_result_t mesh_mgmt_execution_node_shutdown_v1(
    mesh_mgmt_execution_node_v1_t *node);

void mesh_mgmt_execution_node_destroy_v1(
    mesh_mgmt_execution_node_v1_t *node);

#ifdef __cplusplus
}
#endif

#endif
