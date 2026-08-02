#include "mesh_mgmt_execution_node.h"

#include "mesh_mgmt_crypto.h"
#include "mesh_mgmt_execution_wire.h"

#include <string.h>

static int bytes_are_zero(const uint8_t *bytes, size_t size) {
  uint8_t combined = 0u;
  size_t index;

  for (index = 0u; index < size; ++index)
    combined |= bytes[index];
  return combined == 0u;
}

static int limits_are_valid(
    const mesh_mgmt_execution_limits_v1_t *limits) {
  return limits->module_bytes != 0u && limits->stack_bytes != 0u &&
         limits->linear_memory_bytes != 0u && limits->timeout_ms != 0u &&
         limits->control_flow_steps != 0u && limits->host_calls != 0u &&
         limits->copied_guest_bytes != 0u && limits->input_bytes != 0u &&
         limits->stdout_bytes != 0u && limits->stderr_bytes != 0u;
}

static int config_is_valid(
    const mesh_mgmt_execution_node_config_v1_t *config) {
  if (!config || !config->store_path || config->store_path[0] == '\0' ||
      !config->deployments || config->deployment_count == 0u ||
      config->deployment_capacity < config->deployment_count ||
      config->deployment_capacity >
          MESH_MGMT_EXECUTION_NODE_MAX_DEPLOYMENTS ||
      config->store_capacity == 0u ||
      config->worker_queue_capacity == 0u ||
      config->worker_queue_capacity >
          MESH_MGMT_EXECUTION_WORKER_MAX_QUEUE_CAPACITY ||
      config->egress_capacity == 0u ||
      config->egress_capacity > MESH_MGMT_EXECUTION_EGRESS_MAX_CAPACITY ||
      bytes_are_zero(config->local_node_id,
                     sizeof(config->local_node_id)) ||
      bytes_are_zero(config->result_private_key,
                     sizeof(config->result_private_key)) ||
      bytes_are_zero(config->grant_issuer_key,
                     sizeof(config->grant_issuer_key)) ||
      config->host_capabilities == 0u ||
      config->hard_capabilities == 0u ||
      (config->host_capabilities &
       ~MESH_MGMT_EXECUTION_NODE_RAW_CAPABILITIES) != 0u ||
      (config->hard_capabilities &
       ~MESH_MGMT_EXECUTION_NODE_RAW_CAPABILITIES) != 0u ||
      !limits_are_valid(&config->host_limits) ||
      !limits_are_valid(&config->hard_limits) ||
      config->worker_generation == 0u || !config->clock_now_ms)
    return 0;
  return 1;
}

static int verify_grant(void *context,
                        const mesh_mgmt_execution_grant_v1_t *grant,
                        uint64_t now_ms) {
  const mesh_mgmt_execution_node_v1_t *node =
      (const mesh_mgmt_execution_node_v1_t *)context;

  return node && mesh_mgmt_execution_grant_verify_v1(
                     grant, node->grant_issuer_key, now_ms) ==
                     MESH_MGMT_EXECUTION_WIRE_OK
             ? 0
             : -1;
}

static mesh_mgmt_execution_node_result_t register_deployments(
    mesh_mgmt_execution_node_v1_t *node,
    const mesh_mgmt_execution_node_config_v1_t *config) {
  uint8_t actual_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  size_t index;

  for (index = 0u; index < config->deployment_count; ++index) {
    const mesh_mgmt_execution_deployment_v1_t *deployment =
        &config->deployments[index];

    memset(actual_digest, 0, sizeof(actual_digest));
    if (!deployment->module_path || deployment->module_path[0] == '\0' ||
        mesh_mgmt_execution_runner_module_digest_v1(
            deployment->module_path, config->hard_limits.module_bytes,
            actual_digest, NULL) != MESH_MGMT_EXECUTION_RUNNER_OK ||
        !mesh_mgmt_crypto_equal_32(actual_digest,
                                   deployment->module_digest) ||
        mesh_mgmt_execution_runner_register_v1(
            &node->runner, deployment) != MESH_MGMT_EXECUTION_RUNNER_OK) {
      mesh_mgmt_crypto_wipe(actual_digest, sizeof(actual_digest));
      return MESH_MGMT_EXECUTION_NODE_DEPLOYMENT_FAILED;
    }
  }
  mesh_mgmt_crypto_wipe(actual_digest, sizeof(actual_digest));
  return MESH_MGMT_EXECUTION_NODE_OK;
}

mesh_mgmt_execution_node_result_t mesh_mgmt_execution_node_init_v1(
    mesh_mgmt_execution_node_v1_t *node,
    const mesh_mgmt_execution_node_config_v1_t *config) {
  mesh_mgmt_execution_orchestrator_config_v1_t orchestrator_config;
  mesh_mgmt_execution_service_config_v1_t service_config;
  mesh_mgmt_execution_worker_config_v1_t worker_config;
  mesh_mgmt_execution_node_result_t result;

  if (!node || !config)
    return MESH_MGMT_EXECUTION_NODE_INVALID_ARG;
  memset(node, 0, sizeof(*node));
  if (!config_is_valid(config))
    return MESH_MGMT_EXECUTION_NODE_INVALID_CONFIG;
  if (mesh_mgmt_execution_runner_init_v1(
          &node->runner, config->deployment_capacity) !=
      MESH_MGMT_EXECUTION_RUNNER_OK)
    return MESH_MGMT_EXECUTION_NODE_DEPLOYMENT_FAILED;
  result = register_deployments(node, config);
  if (result != MESH_MGMT_EXECUTION_NODE_OK)
    goto failed;
  if (mesh_mgmt_execution_store_open_v1(
          &node->store, config->store_path, config->store_capacity, NULL) !=
      MESH_MGMT_EXECUTION_STORE_OK) {
    result = MESH_MGMT_EXECUTION_NODE_STORE_FAILED;
    goto failed;
  }

  memcpy(node->grant_issuer_key, config->grant_issuer_key,
         sizeof(node->grant_issuer_key));
  memset(&orchestrator_config, 0, sizeof(orchestrator_config));
  orchestrator_config.store = &node->store;
  orchestrator_config.runner = &node->runner;
  memcpy(orchestrator_config.local_node_id, config->local_node_id,
         sizeof(orchestrator_config.local_node_id));
  memcpy(orchestrator_config.result_private_key, config->result_private_key,
         sizeof(orchestrator_config.result_private_key));
  orchestrator_config.worker_generation = config->worker_generation;
  orchestrator_config.verify_grant = verify_grant;
  orchestrator_config.verify_grant_context = node;
  orchestrator_config.clock_now_ms = config->clock_now_ms;
  orchestrator_config.clock_context = config->clock_context;
  if (mesh_mgmt_execution_orchestrator_init_v1(
          &node->orchestrator, &orchestrator_config) !=
      MESH_MGMT_EXECUTION_ORCHESTRATOR_OK) {
    result = MESH_MGMT_EXECUTION_NODE_ORCHESTRATOR_FAILED;
    goto failed;
  }

  memset(&service_config, 0, sizeof(service_config));
  service_config.orchestrator = &node->orchestrator;
  service_config.enabled = 1u;
  if (mesh_mgmt_execution_service_init_v1(
          &node->service, &service_config) !=
      MESH_MGMT_EXECUTION_SERVICE_OK) {
    result = MESH_MGMT_EXECUTION_NODE_SERVICE_FAILED;
    goto failed;
  }
  if (mesh_mgmt_execution_egress_init_v1(
          &node->egress, config->egress_capacity) !=
      MESH_MGMT_EXECUTION_EGRESS_OK) {
    result = MESH_MGMT_EXECUTION_NODE_EGRESS_FAILED;
    goto failed;
  }

  memset(&worker_config, 0, sizeof(worker_config));
  worker_config.service = &node->service;
  worker_config.queue_capacity = config->worker_queue_capacity;
  worker_config.completion = mesh_mgmt_execution_egress_completion_v1;
  worker_config.completion_context = &node->egress;
  if (mesh_mgmt_execution_worker_init_v1(
          &node->worker, &worker_config) !=
      MESH_MGMT_EXECUTION_WORKER_OK) {
    result = MESH_MGMT_EXECUTION_NODE_WORKER_FAILED;
    goto failed;
  }

  node->authorization_template.host_capabilities =
      config->host_capabilities;
  node->authorization_template.hard_capabilities =
      config->hard_capabilities;
  node->authorization_template.host_limits = config->host_limits;
  node->authorization_template.hard_limits = config->hard_limits;
  node->initialized = 1u;
  node->accepting = 1u;
  return MESH_MGMT_EXECUTION_NODE_OK;

failed:
  mesh_mgmt_execution_node_destroy_v1(node);
  return result;
}

mesh_mgmt_execution_node_result_t mesh_mgmt_execution_node_try_submit_v1(
    mesh_mgmt_execution_node_v1_t *node,
    const mesh_mgmt_execution_shadow_command_v1_t *command) {
  mesh_mgmt_execution_authorization_input_v1_t authorization;
  mesh_mgmt_execution_worker_result_t worker_result;

  if (!node || !command || !node->initialized)
    return MESH_MGMT_EXECUTION_NODE_INVALID_ARG;
  if (!node->accepting)
    return MESH_MGMT_EXECUTION_NODE_CLOSED;
  authorization = node->authorization_template;
  authorization.requested_capabilities = command->grant.capabilities;
  authorization.requested_limits = command->grant.max_limits;
  worker_result = mesh_mgmt_execution_worker_try_submit_v1(
      &node->worker, command, &authorization);
  switch (worker_result) {
    case MESH_MGMT_EXECUTION_WORKER_OK:
      return MESH_MGMT_EXECUTION_NODE_OK;
    case MESH_MGMT_EXECUTION_WORKER_FULL:
    case MESH_MGMT_EXECUTION_WORKER_RESOURCE_EXHAUSTED:
      return MESH_MGMT_EXECUTION_NODE_BUSY;
    case MESH_MGMT_EXECUTION_WORKER_DISABLED:
      return MESH_MGMT_EXECUTION_NODE_DISABLED;
    case MESH_MGMT_EXECUTION_WORKER_CLOSED:
      return MESH_MGMT_EXECUTION_NODE_CLOSED;
    default:
      return MESH_MGMT_EXECUTION_NODE_WORKER_FAILED;
  }
}

mesh_mgmt_execution_node_result_t mesh_mgmt_execution_node_send_next_v1(
    mesh_mgmt_execution_node_v1_t *node,
    mesh_mgmt_agent_runtime_v1_t *runtime) {
  mesh_mgmt_execution_sender_result_t sender_result;

  if (!node || !runtime || !node->initialized)
    return MESH_MGMT_EXECUTION_NODE_INVALID_ARG;
  sender_result = mesh_mgmt_execution_sender_send_next_runtime_v1(
      &node->egress, runtime);
  if (sender_result == MESH_MGMT_EXECUTION_SENDER_OK)
    return MESH_MGMT_EXECUTION_NODE_OK;
  if (sender_result == MESH_MGMT_EXECUTION_SENDER_EMPTY)
    return MESH_MGMT_EXECUTION_NODE_EMPTY;
  return MESH_MGMT_EXECUTION_NODE_SEND_FAILED;
}

mesh_mgmt_execution_node_result_t mesh_mgmt_execution_node_shutdown_v1(
    mesh_mgmt_execution_node_v1_t *node) {
  if (!node || !node->initialized)
    return MESH_MGMT_EXECUTION_NODE_INVALID_ARG;
  node->accepting = 0u;
  if (mesh_mgmt_execution_worker_shutdown_v1(&node->worker) !=
      MESH_MGMT_EXECUTION_WORKER_OK)
    return MESH_MGMT_EXECUTION_NODE_WORKER_FAILED;
  return MESH_MGMT_EXECUTION_NODE_OK;
}

void mesh_mgmt_execution_node_destroy_v1(
    mesh_mgmt_execution_node_v1_t *node) {
  if (!node)
    return;
  if (bytes_are_zero((const uint8_t *)node, sizeof(*node)))
    return;
  if (node->worker.initialized)
    (void)mesh_mgmt_execution_worker_shutdown_v1(&node->worker);
  mesh_mgmt_execution_worker_destroy_v1(&node->worker);
  if (node->egress.initialized)
    (void)mesh_mgmt_execution_egress_close_v1(&node->egress);
  mesh_mgmt_execution_egress_destroy_v1(&node->egress);
  mesh_mgmt_execution_service_destroy_v1(&node->service);
  mesh_mgmt_execution_orchestrator_destroy_v1(&node->orchestrator);
  mesh_mgmt_execution_store_close_v1(&node->store);
  mesh_mgmt_execution_runner_destroy_v1(&node->runner);
  mesh_mgmt_crypto_wipe(node, sizeof(*node));
}
