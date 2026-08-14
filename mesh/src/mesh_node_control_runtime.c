#include "mesh_node_control_runtime.h"

#include <string.h>

static mesh_control_result_t runtime_channels_empty(
    mesh_node_control_runtime_v1_t *runtime) {
  mesh_node_ipc_channel_stats_v1_t inbound;
  mesh_node_ipc_channel_stats_v1_t outbound;
  if (mesh_node_ipc_channel_get_stats_v1(&runtime->inbound, &inbound) !=
          MESH_CONTROL_OK ||
      mesh_node_ipc_channel_get_stats_v1(&runtime->outbound, &outbound) !=
          MESH_CONTROL_OK)
    return MESH_CONTROL_INVALID_STATE;
  return inbound.pending == 0u && outbound.pending == 0u
             ? MESH_CONTROL_OK
             : MESH_CONTROL_RESOURCE_EXHAUSTED;
}

mesh_control_result_t mesh_node_control_runtime_init_v1(
    mesh_node_control_runtime_v1_t *runtime,
    const mesh_node_control_runtime_config_v1_t *config) {
  mesh_node_ipc_owner_config_v1_t owner_config;
  mesh_node_ipc_flowmq_config_v1_t transport_config;
  mesh_control_result_t result;
  if (!runtime || runtime->initialized != 0u || !config || !config->execute ||
      config->operation_capacity == 0u ||
      config->channel_capacity == 0u ||
      config->channel_max_retained_bytes == 0u)
    return MESH_CONTROL_INVALID_ARG;
  memset(runtime, 0, sizeof(*runtime));
  result = mesh_node_ipc_channel_init_v1(
      &runtime->inbound, config->channel_capacity,
      config->channel_max_retained_bytes, MESH_NODE_IPC_MAX_FRAME_SIZE_V1);
  if (result != MESH_CONTROL_OK) return result;
  result = mesh_node_ipc_channel_init_v1(
      &runtime->outbound, config->channel_capacity,
      config->channel_max_retained_bytes, MESH_NODE_IPC_MAX_FRAME_SIZE_V1);
  if (result != MESH_CONTROL_OK) goto fail;

  memset(&owner_config, 0, sizeof(owner_config));
  owner_config.inbound = &runtime->inbound;
  owner_config.outbound = &runtime->outbound;
  owner_config.execute = config->execute;
  owner_config.execute_context = config->execute_context;
  memcpy(owner_config.mesh_id, config->mesh_id, sizeof(owner_config.mesh_id));
  memcpy(owner_config.provider_id, config->provider_id,
         sizeof(owner_config.provider_id));
  memcpy(owner_config.sender_incarnation, config->sender_incarnation,
         sizeof(owner_config.sender_incarnation));
  owner_config.allowed_resource_mask = config->allowed_resource_mask;
  owner_config.operation_capacity = config->operation_capacity;
  result = mesh_node_ipc_owner_init_v1(&runtime->owner, &owner_config);
  if (result != MESH_CONTROL_OK) goto fail;

  memset(&transport_config, 0, sizeof(transport_config));
  transport_config.mode = config->mode;
  transport_config.bind_endpoint = config->bind_endpoint;
  transport_config.connect_endpoint = config->connect_endpoint;
  transport_config.expected_peer_identity = config->expected_peer_identity;
  transport_config.expected_peer_certificate_sha256 =
      config->expected_peer_certificate_sha256;
  transport_config.expected_peer_certificate_sha256_next =
      config->expected_peer_certificate_sha256_next;
  transport_config.identity_policy_generation =
      config->identity_policy_generation;
  transport_config.inbound = &runtime->inbound;
  transport_config.outbound = &runtime->outbound;
  result = mesh_node_ipc_flowmq_init_v1(&runtime->transport,
                                        &transport_config);
  if (result != MESH_CONTROL_OK) goto fail;
  runtime->initialized = 1u;
  return MESH_CONTROL_OK;

fail:
  mesh_node_ipc_flowmq_destroy_v1(&runtime->transport);
  mesh_node_ipc_owner_destroy_v1(&runtime->owner);
  mesh_node_ipc_channel_destroy_v1(&runtime->outbound);
  mesh_node_ipc_channel_destroy_v1(&runtime->inbound);
  memset(runtime, 0, sizeof(*runtime));
  return result;
}

mesh_control_result_t mesh_node_control_runtime_start_v1(
    mesh_node_control_runtime_v1_t *runtime) {
  mesh_control_result_t result;
  if (!runtime || runtime->initialized == 0u || runtime->started ||
      runtime->stopped)
    return MESH_CONTROL_INVALID_ARG;
  result = mesh_node_ipc_flowmq_start_v1(&runtime->transport);
  if (result == MESH_CONTROL_OK) runtime->started = 1u;
  return result;
}

mesh_control_result_t mesh_node_control_runtime_poll_v1(
    mesh_node_control_runtime_v1_t *runtime, size_t command_budget,
    size_t send_budget, size_t *out_processed, size_t *out_sent) {
  mesh_control_result_t result;
  size_t sent_before = 0u;
  size_t sent_after = 0u;
  if (!runtime || !out_processed || !out_sent || runtime->initialized == 0u ||
      !runtime->started || runtime->stopped || command_budget == 0u ||
      send_budget == 0u)
    return MESH_CONTROL_INVALID_ARG;
  *out_processed = 0u;
  *out_sent = 0u;
  result = mesh_node_ipc_flowmq_pump_send_v1(&runtime->transport, send_budget,
                                              &sent_before);
  if (result != MESH_CONTROL_OK && result != MESH_CONTROL_PROVIDER_UNAVAILABLE &&
      result != MESH_CONTROL_TIMEOUT &&
      result != MESH_CONTROL_RESOURCE_EXHAUSTED)
    return result;
  result = mesh_node_ipc_owner_poll_v1(&runtime->owner, command_budget,
                                       out_processed);
  if (result != MESH_CONTROL_OK) {
    *out_sent = sent_before;
    return result;
  }
  if (sent_before < send_budget) {
    result = mesh_node_ipc_flowmq_pump_send_v1(
        &runtime->transport, send_budget - sent_before, &sent_after);
    if (result != MESH_CONTROL_OK) {
      *out_sent = sent_before;
      return result;
    }
  }
  *out_sent = sent_before + sent_after;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_node_control_runtime_begin_drain_v1(
    mesh_node_control_runtime_v1_t *runtime) {
  mesh_control_result_t result;
  if (!runtime || runtime->initialized == 0u || !runtime->started ||
      runtime->stopped)
    return MESH_CONTROL_INVALID_ARG;
  if (runtime->draining) return MESH_CONTROL_OK;
  result = mesh_node_ipc_owner_begin_drain_v1(&runtime->owner);
  if (result == MESH_CONTROL_OK) runtime->draining = 1u;
  return result;
}

mesh_control_result_t mesh_node_control_runtime_stop_v1(
    mesh_node_control_runtime_v1_t *runtime) {
  mesh_node_ipc_owner_stats_v1_t owner_stats;
  mesh_control_result_t result;
  if (!runtime || runtime->initialized == 0u || !runtime->started)
    return MESH_CONTROL_INVALID_ARG;
  if (runtime->stopped) return MESH_CONTROL_OK;
  if (!runtime->draining) return MESH_CONTROL_INVALID_STATE;
  result = runtime_channels_empty(runtime);
  if (result != MESH_CONTROL_OK) return result;
  if (mesh_node_ipc_owner_get_stats_v1(&runtime->owner, &owner_stats) !=
      MESH_CONTROL_OK)
    return MESH_CONTROL_INVALID_STATE;
  if (owner_stats.retained_operations != 0u)
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  result = mesh_node_ipc_flowmq_stop_v1(&runtime->transport);
  if (result == MESH_CONTROL_OK) runtime->stopped = 1u;
  return result;
}

mesh_control_result_t mesh_node_control_runtime_get_stats_v1(
    const mesh_node_control_runtime_v1_t *runtime,
    mesh_node_control_runtime_stats_v1_t *out_stats) {
  if (!runtime || !out_stats || runtime->initialized == 0u)
    return MESH_CONTROL_INVALID_ARG;
  memset(out_stats, 0, sizeof(*out_stats));
  if (mesh_node_ipc_owner_get_stats_v1(&runtime->owner, &out_stats->owner) !=
          MESH_CONTROL_OK ||
      mesh_node_ipc_flowmq_get_stats_v1(&runtime->transport,
                                        &out_stats->transport) !=
          MESH_CONTROL_OK ||
      mesh_node_ipc_channel_get_stats_v1(&runtime->inbound,
                                         &out_stats->inbound) !=
          MESH_CONTROL_OK ||
      mesh_node_ipc_channel_get_stats_v1(&runtime->outbound,
                                         &out_stats->outbound) !=
          MESH_CONTROL_OK)
    return MESH_CONTROL_INVALID_STATE;
  out_stats->started = runtime->started;
  out_stats->draining = runtime->draining;
  out_stats->stopped = runtime->stopped;
  return MESH_CONTROL_OK;
}

void mesh_node_control_runtime_destroy_v1(
    mesh_node_control_runtime_v1_t *runtime) {
  if (!runtime) return;
  mesh_node_ipc_flowmq_destroy_v1(&runtime->transport);
  mesh_node_ipc_owner_destroy_v1(&runtime->owner);
  mesh_node_ipc_channel_destroy_v1(&runtime->outbound);
  mesh_node_ipc_channel_destroy_v1(&runtime->inbound);
  memset(runtime, 0, sizeof(*runtime));
}
