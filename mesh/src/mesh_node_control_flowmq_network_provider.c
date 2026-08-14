#include "mesh_node_control_flowmq_network_provider.h"

#include <turbo_crypto.h>

#include <string.h>

static int recoverable_transport_result(mesh_control_result_t result) {
  return result == MESH_CONTROL_PROVIDER_UNAVAILABLE ||
         result == MESH_CONTROL_TIMEOUT ||
         result == MESH_CONTROL_RESOURCE_EXHAUSTED;
}

mesh_control_result_t mesh_node_control_flowmq_network_provider_poll_v1(
    mesh_node_control_flowmq_network_provider_v1_t *provider,
    size_t *out_progress) {
  size_t processed = 0u;
  size_t sent = 0u;
  mesh_control_result_t result;
  if (!provider || provider->initialized == 0u || !provider->started ||
      provider->stopped || !out_progress)
    return MESH_CONTROL_INVALID_ARG;
  *out_progress = 0u;
  result = mesh_node_control_client_runtime_poll_v1(
      &provider->runtime, provider->response_budget, provider->send_budget,
      &processed, &sent);
  *out_progress = processed + sent;
  if (result == MESH_CONTROL_OK || recoverable_transport_result(result)) {
    provider->last_error = result;
    return MESH_CONTROL_OK;
  }
  provider->last_error = result;
  return result;
}

static mesh_control_result_t provider_try_start(
    void *context,
    const mesh_control_network_provider_request_v1_t *request) {
  mesh_node_control_flowmq_network_provider_v1_t *provider =
      (mesh_node_control_flowmq_network_provider_v1_t *)context;
  mesh_node_ipc_command_v1_t command;
  uint8_t digest[MESH_CONTROL_DIGEST_SIZE];
  size_t progress = 0u;
  mesh_control_result_t result;
  if (!provider || provider->initialized == 0u || !request)
    return MESH_CONTROL_INVALID_ARG;
  if (!provider->started || provider->closed || provider->stopped)
    return MESH_CONTROL_PROVIDER_UNAVAILABLE;
  result = mesh_node_control_flowmq_network_provider_poll_v1(provider,
                                                              &progress);
  if (result != MESH_CONTROL_OK)
    return result;
  if (provider->active)
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  if (request->operation.resource_kind != MESH_CONTROL_RESOURCE_NETWORK ||
      request->operation.desired_epoch == 0u ||
      (request->operation.action != MESH_CONTROL_DESIRED_APPLY &&
       request->operation.action != MESH_CONTROL_DESIRED_DELETE))
    return MESH_CONTROL_INVALID_ARG;

  memset(&command, 0, sizeof(command));
  command.action = request->operation.action;
  command.resource_kind = MESH_CONTROL_RESOURCE_NETWORK;
  command.precondition_epoch = request->precondition_epoch;
  memcpy(command.mesh_id, provider->runtime.client.mesh_id,
         sizeof(command.mesh_id));
  memcpy(command.provider_id, provider->runtime.client.provider_id,
         sizeof(command.provider_id));
  memcpy(command.resource_id, request->operation.resource_id,
         sizeof(command.resource_id));
  if (command.action == MESH_CONTROL_DESIRED_APPLY) {
    if (!request->document || request->document_size == 0u ||
        turbo_crypto_sha256(request->document, request->document_size,
                            digest) != TURBO_CRYPTO_OK ||
        turbo_crypto_verify(digest, request->operation.desired_digest,
                            sizeof(digest)) != TURBO_CRYPTO_OK) {
      memset(digest, 0, sizeof(digest));
      return MESH_CONTROL_CONFLICT;
    }
    memcpy(command.document_digest, digest, sizeof(command.document_digest));
    command.document = request->document;
    command.document_size = request->document_size;
    memset(digest, 0, sizeof(digest));
  } else if (request->document || request->document_size != 0u) {
    return MESH_CONTROL_INVALID_ARG;
  }

  result = mesh_node_control_client_runtime_submit_v1(
      &provider->runtime, request->operation.request_id,
      request->operation.operation_id, request->operation.desired_epoch,
      &command);
  if (result != MESH_CONTROL_OK)
    return result;
  provider->active_operation = request->operation;
  provider->active = 1u;
  provider->result_ready = 0u;
  return MESH_CONTROL_OK;
}

static mesh_control_result_t provider_try_peek_completion(
    void *context, mesh_control_network_provider_completion_v1_t *completion) {
  mesh_node_control_flowmq_network_provider_v1_t *provider =
      (mesh_node_control_flowmq_network_provider_v1_t *)context;
  uint8_t operation_id[MESH_CONTROL_ID_SIZE];
  size_t progress = 0u;
  mesh_control_result_t result;
  if (!provider || provider->initialized == 0u || !completion)
    return MESH_CONTROL_INVALID_ARG;
  if (!provider->active)
    return MESH_CONTROL_EMPTY;
  result = mesh_node_control_flowmq_network_provider_poll_v1(provider,
                                                              &progress);
  if (result != MESH_CONTROL_OK)
    return result;
  if (!provider->result_ready) {
    result = mesh_node_control_client_runtime_peek_result_v1(
        &provider->runtime, operation_id, &provider->active_result);
    if (result != MESH_CONTROL_OK)
      return result;
    if (turbo_crypto_verify(operation_id,
                            provider->active_operation.operation_id,
                            sizeof(operation_id)) != TURBO_CRYPTO_OK)
      return MESH_CONTROL_CONFLICT;
    provider->result_ready = 1u;
  }
  memset(completion, 0, sizeof(*completion));
  memcpy(completion->operation_id, provider->active_operation.operation_id,
         sizeof(completion->operation_id));
  completion->state =
      provider->active_result.outcome == MESH_NODE_IPC_OUTCOME_SUCCEEDED_V1
          ? MESH_CONTROL_NETWORK_PROVIDER_COMPLETED
          : MESH_CONTROL_NETWORK_PROVIDER_FAILED;
  return MESH_CONTROL_OK;
}

static mesh_control_result_t provider_ack_completion(
    void *context, const uint8_t operation_id[MESH_CONTROL_ID_SIZE]) {
  mesh_node_control_flowmq_network_provider_v1_t *provider =
      (mesh_node_control_flowmq_network_provider_v1_t *)context;
  mesh_control_result_t result;
  if (!provider || provider->initialized == 0u || !operation_id ||
      !provider->active || !provider->result_ready ||
      turbo_crypto_verify(operation_id,
                          provider->active_operation.operation_id,
                          MESH_CONTROL_ID_SIZE) != TURBO_CRYPTO_OK)
    return MESH_CONTROL_INVALID_ARG;
  result = mesh_node_control_client_runtime_ack_result_v1(
      &provider->runtime, operation_id);
  if (result != MESH_CONTROL_OK)
    return result;
  memset(&provider->active_operation, 0,
         sizeof(provider->active_operation));
  memset(&provider->active_result, 0, sizeof(provider->active_result));
  provider->active = 0u;
  provider->result_ready = 0u;
  return MESH_CONTROL_OK;
}

static void provider_close(void *context) {
  mesh_node_control_flowmq_network_provider_v1_t *provider =
      (mesh_node_control_flowmq_network_provider_v1_t *)context;
  if (!provider || provider->initialized == 0u || provider->closed)
    return;
  provider->closed = 1u;
  if (provider->started && !provider->stopped)
    (void)mesh_node_control_client_runtime_begin_drain_v1(
        &provider->runtime);
}

static int provider_is_drained(void *context) {
  mesh_node_control_flowmq_network_provider_v1_t *provider =
      (mesh_node_control_flowmq_network_provider_v1_t *)context;
  size_t progress = 0u;
  if (!provider || provider->initialized == 0u || !provider->closed)
    return 0;
  if (provider->stopped)
    return 1;
  if (provider->active ||
      mesh_node_control_flowmq_network_provider_poll_v1(provider,
                                                         &progress) !=
          MESH_CONTROL_OK ||
      !mesh_node_ipc_client_is_drained_v1(&provider->runtime.client))
    return 0;
  if (mesh_node_control_client_runtime_stop_v1(&provider->runtime) !=
      MESH_CONTROL_OK)
    return 0;
  provider->stopped = 1u;
  return 1;
}

mesh_control_result_t mesh_node_control_flowmq_network_provider_init_v1(
    mesh_node_control_flowmq_network_provider_v1_t *provider,
    const mesh_node_control_flowmq_network_provider_config_v1_t *config) {
  mesh_control_result_t result;
  if (!provider || provider->initialized != 0u || !config ||
      config->runtime.operation_capacity !=
          MESH_NODE_CONTROL_FLOWMQ_NETWORK_OPERATION_CAPACITY_V1 ||
      config->response_budget == 0u || config->send_budget == 0u)
    return MESH_CONTROL_INVALID_ARG;
  memset(provider, 0, sizeof(*provider));
  result = mesh_node_control_client_runtime_init_v1(&provider->runtime,
                                                     &config->runtime);
  if (result != MESH_CONTROL_OK)
    return result;
  provider->descriptor.ops.try_start = provider_try_start;
  provider->descriptor.ops.try_peek_completion =
      provider_try_peek_completion;
  provider->descriptor.ops.ack_completion = provider_ack_completion;
  provider->descriptor.ops.close = provider_close;
  provider->descriptor.ops.is_drained = provider_is_drained;
  provider->descriptor.context = provider;
  provider->response_budget = config->response_budget;
  provider->send_budget = config->send_budget;
  provider->last_error = MESH_CONTROL_OK;
  provider->initialized = 1u;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_node_control_flowmq_network_provider_start_v1(
    mesh_node_control_flowmq_network_provider_v1_t *provider) {
  mesh_control_result_t result;
  if (!provider || provider->initialized == 0u || provider->started ||
      provider->closed || provider->stopped)
    return MESH_CONTROL_INVALID_ARG;
  result = mesh_node_control_client_runtime_start_v1(&provider->runtime);
  if (result == MESH_CONTROL_OK)
    provider->started = 1u;
  return result;
}

const mesh_control_network_provider_v1_t *
mesh_node_control_flowmq_network_provider_descriptor_v1(
    mesh_node_control_flowmq_network_provider_v1_t *provider) {
  return provider && provider->initialized != 0u ? &provider->descriptor
                                                  : NULL;
}

void mesh_node_control_flowmq_network_provider_destroy_v1(
    mesh_node_control_flowmq_network_provider_v1_t *provider) {
  if (!provider)
    return;
  mesh_node_control_client_runtime_destroy_v1(&provider->runtime);
  memset(provider, 0, sizeof(*provider));
}
