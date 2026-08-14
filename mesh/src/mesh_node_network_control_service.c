#include "mesh_node_network_control_service.h"

#include <string.h>

static mesh_control_result_t close_reconciler(
    mesh_node_network_control_service_v1_t *service) {
  return mesh_network_reconciler_close_v1(
      &service->reconciler, service->shutdown_drain_timeout_ms);
}

static void release_owned_state(
    mesh_node_network_control_service_v1_t *service) {
  mesh_node_control_runtime_destroy_v1(&service->runtime);
  mesh_node_ipc_network_executor_destroy_v1(&service->executor);
  mesh_network_reconciler_destroy_v1(&service->reconciler);
  memset(service, 0, sizeof(*service));
}

mesh_control_result_t mesh_node_network_control_service_init_v1(
    mesh_node_network_control_service_v1_t *service,
    const mesh_node_network_control_service_config_v1_t *config) {
  mesh_node_control_runtime_config_v1_t runtime_config;
  mesh_fabric_status_v2_t fabric_status;
  mesh_control_result_t result;
  if (!service || !config ||
      service->lifecycle != MESH_NODE_NETWORK_CONTROL_UNINITIALIZED_V1 ||
      !config->fabric || !config->bind_endpoint ||
      !config->expected_peer_identity ||
      !config->expected_peer_certificate_sha256 ||
      config->identity_policy_generation == 0u ||
      config->network_capacity == 0u ||
      config->operation_capacity == 0u || config->channel_capacity == 0u ||
      config->channel_max_retained_bytes == 0u ||
      config->command_budget == 0u || config->send_budget == 0u ||
      config->delete_drain_timeout_ms == 0u ||
      config->shutdown_drain_timeout_ms == 0u)
    return MESH_CONTROL_INVALID_ARG;

  memset(&fabric_status, 0, sizeof(fabric_status));
  fabric_status.struct_size = sizeof(fabric_status);
  if (mesh_fabric_get_status_v2(config->fabric, &fabric_status) != MESH_OK ||
      config->network_capacity > fabric_status.max_networks)
    return MESH_CONTROL_INVALID_ARG;

  memset(service, 0, sizeof(*service));
  service->fabric = config->fabric;
  service->command_budget = config->command_budget;
  service->send_budget = config->send_budget;
  service->shutdown_drain_timeout_ms = config->shutdown_drain_timeout_ms;

  result = mesh_network_reconciler_init_v1(
      &service->reconciler, config->fabric, config->network_capacity);
  if (result != MESH_CONTROL_OK)
    goto fail;
  result = mesh_node_ipc_network_executor_init_v1(
      &service->executor, &service->reconciler, config->mesh_id,
      config->delete_drain_timeout_ms);
  if (result != MESH_CONTROL_OK)
    goto fail;

  memset(&runtime_config, 0, sizeof(runtime_config));
  runtime_config.mode = MESH_NODE_IPC_FLOWMQ_BIND_V1;
  runtime_config.bind_endpoint = config->bind_endpoint;
  runtime_config.expected_peer_identity = config->expected_peer_identity;
  runtime_config.expected_peer_certificate_sha256 =
      config->expected_peer_certificate_sha256;
  runtime_config.expected_peer_certificate_sha256_next =
      config->expected_peer_certificate_sha256_next;
  runtime_config.identity_policy_generation =
      config->identity_policy_generation;
  runtime_config.execute = mesh_node_ipc_network_execute_v1;
  runtime_config.execute_context = &service->executor;
  memcpy(runtime_config.mesh_id, config->mesh_id,
         sizeof(runtime_config.mesh_id));
  memcpy(runtime_config.provider_id, config->provider_id,
         sizeof(runtime_config.provider_id));
  memcpy(runtime_config.sender_incarnation, config->sender_incarnation,
         sizeof(runtime_config.sender_incarnation));
  runtime_config.allowed_resource_mask =
      UINT64_C(1) << MESH_CONTROL_RESOURCE_NETWORK;
  runtime_config.operation_capacity = config->operation_capacity;
  runtime_config.channel_capacity = config->channel_capacity;
  runtime_config.channel_max_retained_bytes =
      config->channel_max_retained_bytes;
  result = mesh_node_control_runtime_init_v1(&service->runtime,
                                              &runtime_config);
  if (result != MESH_CONTROL_OK)
    goto fail;
  service->lifecycle = MESH_NODE_NETWORK_CONTROL_READY_V1;
  return MESH_CONTROL_OK;

fail:
  mesh_node_control_runtime_destroy_v1(&service->runtime);
  mesh_node_ipc_network_executor_destroy_v1(&service->executor);
  if (service->reconciler.records) {
    mesh_control_result_t close_result = close_reconciler(service);
    if (close_result == MESH_CONTROL_OK)
      mesh_network_reconciler_destroy_v1(&service->reconciler);
  }
  memset(service, 0, sizeof(*service));
  return result;
}

mesh_control_result_t mesh_node_network_control_service_start_v1(
    mesh_node_network_control_service_v1_t *service) {
  mesh_control_result_t result;
  if (!service || service->lifecycle != MESH_NODE_NETWORK_CONTROL_READY_V1)
    return MESH_CONTROL_INVALID_STATE;
  result = mesh_node_control_runtime_start_v1(&service->runtime);
  if (result == MESH_CONTROL_OK)
    service->lifecycle = MESH_NODE_NETWORK_CONTROL_RUNNING_V1;
  return result;
}

mesh_control_result_t mesh_node_network_control_service_poll_v1(
    mesh_node_network_control_service_v1_t *service,
    size_t *out_processed, size_t *out_sent) {
  if (!service || !out_processed || !out_sent)
    return MESH_CONTROL_INVALID_ARG;
  if (service->lifecycle != MESH_NODE_NETWORK_CONTROL_RUNNING_V1 &&
      service->lifecycle != MESH_NODE_NETWORK_CONTROL_DRAINING_V1)
    return MESH_CONTROL_INVALID_STATE;
  return mesh_node_control_runtime_poll_v1(
      &service->runtime, service->command_budget, service->send_budget,
      out_processed, out_sent);
}

mesh_control_result_t mesh_node_network_control_service_begin_drain_v1(
    mesh_node_network_control_service_v1_t *service) {
  mesh_control_result_t result;
  if (!service)
    return MESH_CONTROL_INVALID_ARG;
  if (service->lifecycle == MESH_NODE_NETWORK_CONTROL_DRAINING_V1)
    return MESH_CONTROL_OK;
  if (service->lifecycle != MESH_NODE_NETWORK_CONTROL_RUNNING_V1)
    return MESH_CONTROL_INVALID_STATE;
  result = mesh_node_control_runtime_begin_drain_v1(&service->runtime);
  if (result == MESH_CONTROL_OK)
    service->lifecycle = MESH_NODE_NETWORK_CONTROL_DRAINING_V1;
  return result;
}

mesh_control_result_t mesh_node_network_control_service_stop_v1(
    mesh_node_network_control_service_v1_t *service) {
  mesh_control_result_t result;
  if (!service)
    return MESH_CONTROL_INVALID_ARG;
  if (service->lifecycle == MESH_NODE_NETWORK_CONTROL_STOPPED_V1)
    return MESH_CONTROL_OK;
  if (service->lifecycle != MESH_NODE_NETWORK_CONTROL_DRAINING_V1)
    return MESH_CONTROL_INVALID_STATE;
  result = mesh_node_control_runtime_stop_v1(&service->runtime);
  if (result != MESH_CONTROL_OK)
    return result;
  result = close_reconciler(service);
  if (result == MESH_CONTROL_OK)
    service->lifecycle = MESH_NODE_NETWORK_CONTROL_STOPPED_V1;
  return result;
}

mesh_control_result_t mesh_node_network_control_service_abort_v1(
    mesh_node_network_control_service_v1_t *service,
    size_t *out_abandoned_operations) {
  mesh_node_control_runtime_stats_v1_t stats;
  mesh_control_result_t result;
  if (!service || !out_abandoned_operations)
    return MESH_CONTROL_INVALID_ARG;
  *out_abandoned_operations = service->abandoned_operations;
  if (service->lifecycle != MESH_NODE_NETWORK_CONTROL_DRAINING_V1 &&
      service->lifecycle != MESH_NODE_NETWORK_CONTROL_ABORTING_V1)
    return MESH_CONTROL_INVALID_STATE;
  if (service->lifecycle == MESH_NODE_NETWORK_CONTROL_DRAINING_V1) {
    memset(&stats, 0, sizeof(stats));
    if (mesh_node_control_runtime_get_stats_v1(&service->runtime, &stats) !=
        MESH_CONTROL_OK)
      return MESH_CONTROL_INVALID_STATE;
    service->abandoned_operations = stats.owner.retained_operations;
    *out_abandoned_operations = service->abandoned_operations;
    mesh_node_control_runtime_destroy_v1(&service->runtime);
    service->lifecycle = MESH_NODE_NETWORK_CONTROL_ABORTING_V1;
  }
  result = close_reconciler(service);
  if (result == MESH_CONTROL_OK)
    service->lifecycle = MESH_NODE_NETWORK_CONTROL_STOPPED_V1;
  return result;
}

mesh_control_result_t mesh_node_network_control_service_get_stats_v1(
    const mesh_node_network_control_service_v1_t *service,
    mesh_node_network_control_service_stats_v1_t *out_stats) {
  if (!service || !out_stats ||
      service->lifecycle == MESH_NODE_NETWORK_CONTROL_UNINITIALIZED_V1)
    return MESH_CONTROL_INVALID_ARG;
  memset(out_stats, 0, sizeof(*out_stats));
  if (mesh_node_control_runtime_get_stats_v1(&service->runtime,
                                              &out_stats->runtime) !=
      MESH_CONTROL_OK)
    return MESH_CONTROL_INVALID_STATE;
  out_stats->fabric.struct_size = sizeof(out_stats->fabric);
  if (mesh_fabric_get_status_v2(service->fabric, &out_stats->fabric) !=
      MESH_OK)
    return MESH_CONTROL_INVALID_STATE;
  out_stats->owned_networks = service->reconciler.count;
  out_stats->network_capacity = service->reconciler.capacity;
  out_stats->lifecycle = service->lifecycle;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_node_network_control_service_destroy_v1(
    mesh_node_network_control_service_v1_t *service) {
  mesh_control_result_t result;
  if (!service)
    return MESH_CONTROL_INVALID_ARG;
  if (service->lifecycle == MESH_NODE_NETWORK_CONTROL_UNINITIALIZED_V1)
    return MESH_CONTROL_OK;
  if (service->lifecycle == MESH_NODE_NETWORK_CONTROL_READY_V1) {
    result = close_reconciler(service);
    if (result != MESH_CONTROL_OK)
      return result;
  } else if (service->lifecycle != MESH_NODE_NETWORK_CONTROL_STOPPED_V1) {
    return MESH_CONTROL_INVALID_STATE;
  }
  release_owned_state(service);
  return MESH_CONTROL_OK;
}
