#include "mesh_mgmt_execution_rpc_registry.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  uint8_t occupied;
  mesh_mgmt_execution_rpc_state_t state;
  uint64_t terminal_expires_at_ms;
  mesh_mgmt_execution_rpc_binding_v1_t binding;
  mesh_mgmt_execution_response_v1_t response;
} mesh_mgmt_execution_rpc_slot_v1_t;

struct mesh_mgmt_execution_rpc_registry_impl_v1 {
  size_t capacity;
  uint64_t terminal_retention_ms;
  mesh_mgmt_execution_rpc_slot_v1_t slots[];
};

static int bytes_are_zero(const uint8_t *bytes, size_t size) {
  size_t index;

  for (index = 0u; index < size; ++index) {
    if (bytes[index] != 0u)
      return 0;
  }
  return 1;
}

static int bytes_equal(const uint8_t *left, const uint8_t *right,
                       size_t size) {
  return memcmp(left, right, size) == 0;
}

static uint64_t saturating_add_u64(uint64_t left, uint64_t right) {
  if (UINT64_MAX - left < right)
    return UINT64_MAX;
  return left + right;
}

static int binding_is_valid(
    const mesh_mgmt_execution_rpc_binding_v1_t *binding, uint64_t now_ms) {
  return binding != NULL &&
         !bytes_are_zero(binding->command_id, sizeof(binding->command_id)) &&
         !bytes_are_zero(binding->correlation_id,
                         sizeof(binding->correlation_id)) &&
         !bytes_are_zero(binding->request_digest,
                         sizeof(binding->request_digest)) &&
         !bytes_are_zero(binding->target_node_id,
                         sizeof(binding->target_node_id)) &&
         binding->deadline_ms > now_ms;
}

static int binding_equal(
    const mesh_mgmt_execution_rpc_binding_v1_t *left,
    const mesh_mgmt_execution_rpc_binding_v1_t *right) {
  return bytes_equal(left->command_id, right->command_id,
                     sizeof(left->command_id)) &&
         bytes_equal(left->correlation_id, right->correlation_id,
                     sizeof(left->correlation_id)) &&
         bytes_equal(left->request_digest, right->request_digest,
                     sizeof(left->request_digest)) &&
         bytes_equal(left->target_node_id, right->target_node_id,
                     sizeof(left->target_node_id)) &&
         left->deadline_ms == right->deadline_ms;
}

static void make_timed_out(
    const struct mesh_mgmt_execution_rpc_registry_impl_v1 *impl,
    mesh_mgmt_execution_rpc_slot_v1_t *slot) {
  slot->state = MESH_MGMT_EXECUTION_RPC_TIMED_OUT;
  slot->terminal_expires_at_ms = saturating_add_u64(
      slot->binding.deadline_ms, impl->terminal_retention_ms);
  memset(&slot->response, 0, sizeof(slot->response));
}

static mesh_mgmt_execution_rpc_slot_v1_t *find_correlation(
    struct mesh_mgmt_execution_rpc_registry_impl_v1 *impl,
    const uint8_t correlation_id[MESH_MGMT_EXECUTION_ID_SIZE]) {
  size_t index;

  for (index = 0u; index < impl->capacity; ++index) {
    mesh_mgmt_execution_rpc_slot_v1_t *slot = &impl->slots[index];
    if (slot->occupied &&
        bytes_equal(slot->binding.correlation_id, correlation_id,
                    sizeof(slot->binding.correlation_id)))
      return slot;
  }
  return NULL;
}

mesh_mgmt_execution_rpc_registry_result_t
mesh_mgmt_execution_rpc_registry_init_v1(
    mesh_mgmt_execution_rpc_registry_v1_t *registry, size_t capacity,
    uint64_t terminal_retention_ms) {
  struct mesh_mgmt_execution_rpc_registry_impl_v1 *impl;
  size_t allocation_size;

  if (!registry || registry->impl || capacity == 0u ||
      capacity > MESH_MGMT_EXECUTION_RPC_REGISTRY_MAX_CAPACITY_V1 ||
      terminal_retention_ms == 0u ||
      capacity > (SIZE_MAX - sizeof(*impl)) /
                     sizeof(mesh_mgmt_execution_rpc_slot_v1_t))
    return MESH_MGMT_EXECUTION_RPC_REGISTRY_INVALID_ARG;

  allocation_size =
      sizeof(*impl) + capacity * sizeof(mesh_mgmt_execution_rpc_slot_v1_t);
  impl = (struct mesh_mgmt_execution_rpc_registry_impl_v1 *)calloc(
      1u, allocation_size);
  if (!impl)
    return MESH_MGMT_EXECUTION_RPC_REGISTRY_RESOURCE_EXHAUSTED;
  impl->capacity = capacity;
  impl->terminal_retention_ms = terminal_retention_ms;
  registry->impl = impl;
  return MESH_MGMT_EXECUTION_RPC_REGISTRY_OK;
}

void mesh_mgmt_execution_rpc_registry_destroy_v1(
    mesh_mgmt_execution_rpc_registry_v1_t *registry) {
  size_t allocation_size;

  if (!registry || !registry->impl)
    return;
  allocation_size =
      sizeof(*registry->impl) +
      registry->impl->capacity * sizeof(mesh_mgmt_execution_rpc_slot_v1_t);
  memset(registry->impl, 0, allocation_size);
  free(registry->impl);
  registry->impl = NULL;
}

size_t mesh_mgmt_execution_rpc_registry_sweep_v1(
    mesh_mgmt_execution_rpc_registry_v1_t *registry, uint64_t now_ms) {
  size_t index;
  size_t removed = 0u;

  if (!registry || !registry->impl)
    return 0u;
  for (index = 0u; index < registry->impl->capacity; ++index) {
    mesh_mgmt_execution_rpc_slot_v1_t *slot =
        &registry->impl->slots[index];
    if (!slot->occupied)
      continue;
    if (slot->state == MESH_MGMT_EXECUTION_RPC_PENDING &&
        now_ms >= slot->binding.deadline_ms) {
      make_timed_out(registry->impl, slot);
    }
    if (slot->state != MESH_MGMT_EXECUTION_RPC_PENDING &&
        now_ms >= slot->terminal_expires_at_ms) {
      memset(slot, 0, sizeof(*slot));
      ++removed;
    }
  }
  return removed;
}

mesh_mgmt_execution_rpc_registry_result_t
mesh_mgmt_execution_rpc_registry_register_v1(
    mesh_mgmt_execution_rpc_registry_v1_t *registry,
    const mesh_mgmt_execution_rpc_binding_v1_t *binding, uint64_t now_ms) {
  mesh_mgmt_execution_rpc_slot_v1_t *free_slot = NULL;
  size_t index;

  if (!registry || !registry->impl || !binding_is_valid(binding, now_ms))
    return MESH_MGMT_EXECUTION_RPC_REGISTRY_INVALID_ARG;
  (void)mesh_mgmt_execution_rpc_registry_sweep_v1(registry, now_ms);
  for (index = 0u; index < registry->impl->capacity; ++index) {
    mesh_mgmt_execution_rpc_slot_v1_t *slot =
        &registry->impl->slots[index];
    int same_command;
    int same_correlation;

    if (!slot->occupied) {
      if (!free_slot)
        free_slot = slot;
      continue;
    }
    same_command =
        bytes_equal(slot->binding.command_id, binding->command_id,
                    sizeof(slot->binding.command_id));
    same_correlation =
        bytes_equal(slot->binding.correlation_id, binding->correlation_id,
                    sizeof(slot->binding.correlation_id));
    if (!same_command && !same_correlation)
      continue;
    if (same_command && same_correlation &&
        binding_equal(&slot->binding, binding))
      return MESH_MGMT_EXECUTION_RPC_REGISTRY_ALREADY_EXISTS;
    return MESH_MGMT_EXECUTION_RPC_REGISTRY_CONFLICT;
  }
  if (!free_slot)
    return MESH_MGMT_EXECUTION_RPC_REGISTRY_RESOURCE_EXHAUSTED;
  free_slot->occupied = 1u;
  free_slot->state = MESH_MGMT_EXECUTION_RPC_PENDING;
  free_slot->binding = *binding;
  return MESH_MGMT_EXECUTION_RPC_REGISTRY_OK;
}

static mesh_mgmt_execution_rpc_registry_result_t response_binding(
    const mesh_mgmt_execution_response_v1_t *response,
    const uint8_t **out_command_id, const uint8_t **out_correlation_id,
    const uint8_t **out_request_digest, const uint8_t **out_responder_node_id,
    mesh_mgmt_execution_rpc_state_t *out_state) {
  if (!response || !out_command_id || !out_correlation_id ||
      !out_request_digest || !out_responder_node_id || !out_state)
    return MESH_MGMT_EXECUTION_RPC_REGISTRY_INVALID_ARG;
  if (response->kind == MESH_MGMT_KIND_COMMAND_RESULT) {
    *out_command_id = response->result.command_id;
    *out_correlation_id = response->result.correlation_id;
    *out_request_digest = response->result.request_digest;
    *out_responder_node_id = response->result.target_node_id;
    *out_state = MESH_MGMT_EXECUTION_RPC_RESULT;
    return MESH_MGMT_EXECUTION_RPC_REGISTRY_OK;
  }
  if (response->kind == MESH_MGMT_KIND_COMMAND_STATUS) {
    *out_command_id = response->status.command_id;
    *out_correlation_id = response->status.correlation_id;
    *out_request_digest = response->status.request_digest;
    *out_responder_node_id = response->status.responder_node_id;
    *out_state = MESH_MGMT_EXECUTION_RPC_STATUS;
    return MESH_MGMT_EXECUTION_RPC_REGISTRY_OK;
  }
  return MESH_MGMT_EXECUTION_RPC_REGISTRY_INVALID_ARG;
}

mesh_mgmt_execution_rpc_registry_result_t
mesh_mgmt_execution_rpc_registry_abandon_v1(
    mesh_mgmt_execution_rpc_registry_v1_t *registry,
    const mesh_mgmt_execution_rpc_binding_v1_t *binding) {
  mesh_mgmt_execution_rpc_slot_v1_t *slot;

  if (!registry || !registry->impl || !binding ||
      !binding_is_valid(binding, 0u))
    return MESH_MGMT_EXECUTION_RPC_REGISTRY_INVALID_ARG;
  slot = find_correlation(registry->impl, binding->correlation_id);
  if (!slot)
    return MESH_MGMT_EXECUTION_RPC_REGISTRY_NOT_FOUND;
  if (!binding_equal(&slot->binding, binding))
    return MESH_MGMT_EXECUTION_RPC_REGISTRY_CONFLICT;
  if (slot->state != MESH_MGMT_EXECUTION_RPC_PENDING)
    return MESH_MGMT_EXECUTION_RPC_REGISTRY_ALREADY_COMPLETE;
  memset(slot, 0, sizeof(*slot));
  return MESH_MGMT_EXECUTION_RPC_REGISTRY_OK;
}

mesh_mgmt_execution_rpc_registry_result_t
mesh_mgmt_execution_rpc_registry_complete_v1(
    mesh_mgmt_execution_rpc_registry_v1_t *registry,
    const mesh_mgmt_execution_response_v1_t *response, uint64_t now_ms) {
  const uint8_t *command_id;
  const uint8_t *correlation_id;
  const uint8_t *request_digest;
  const uint8_t *responder_node_id;
  mesh_mgmt_execution_rpc_state_t terminal_state;
  mesh_mgmt_execution_rpc_slot_v1_t *slot;
  mesh_mgmt_execution_rpc_registry_result_t result;

  if (!registry || !registry->impl)
    return MESH_MGMT_EXECUTION_RPC_REGISTRY_INVALID_ARG;
  result = response_binding(response, &command_id, &correlation_id,
                            &request_digest, &responder_node_id,
                            &terminal_state);
  if (result != MESH_MGMT_EXECUTION_RPC_REGISTRY_OK)
    return result;
  (void)mesh_mgmt_execution_rpc_registry_sweep_v1(registry, now_ms);
  slot = find_correlation(registry->impl, correlation_id);
  if (!slot)
    return MESH_MGMT_EXECUTION_RPC_REGISTRY_NOT_FOUND;
  if (slot->state == MESH_MGMT_EXECUTION_RPC_TIMED_OUT)
    return MESH_MGMT_EXECUTION_RPC_REGISTRY_EXPIRED;
  if (slot->state != MESH_MGMT_EXECUTION_RPC_PENDING)
    return MESH_MGMT_EXECUTION_RPC_REGISTRY_ALREADY_COMPLETE;
  if (!bytes_equal(slot->binding.command_id, command_id,
                   sizeof(slot->binding.command_id)) ||
      !bytes_equal(slot->binding.request_digest, request_digest,
                   sizeof(slot->binding.request_digest)) ||
      !bytes_equal(slot->binding.target_node_id, responder_node_id,
                   sizeof(slot->binding.target_node_id)))
    return MESH_MGMT_EXECUTION_RPC_REGISTRY_AUTH_FAILED;

  slot->state = terminal_state;
  slot->terminal_expires_at_ms =
      saturating_add_u64(now_ms, registry->impl->terminal_retention_ms);
  slot->response = *response;
  return MESH_MGMT_EXECUTION_RPC_REGISTRY_OK;
}

mesh_mgmt_execution_rpc_registry_result_t
mesh_mgmt_execution_rpc_registry_get_v1(
    mesh_mgmt_execution_rpc_registry_v1_t *registry,
    const uint8_t correlation_id[MESH_MGMT_EXECUTION_ID_SIZE],
    uint64_t now_ms, mesh_mgmt_execution_rpc_completion_v1_t *out_completion) {
  mesh_mgmt_execution_rpc_slot_v1_t *slot;

  if (!registry || !registry->impl || !correlation_id || !out_completion ||
      bytes_are_zero(correlation_id, MESH_MGMT_EXECUTION_ID_SIZE))
    return MESH_MGMT_EXECUTION_RPC_REGISTRY_INVALID_ARG;
  memset(out_completion, 0, sizeof(*out_completion));
  (void)mesh_mgmt_execution_rpc_registry_sweep_v1(registry, now_ms);
  slot = find_correlation(registry->impl, correlation_id);
  if (!slot)
    return MESH_MGMT_EXECUTION_RPC_REGISTRY_NOT_FOUND;
  out_completion->state = slot->state;
  out_completion->binding = slot->binding;
  if (slot->state == MESH_MGMT_EXECUTION_RPC_RESULT ||
      slot->state == MESH_MGMT_EXECUTION_RPC_STATUS)
    out_completion->response = slot->response;
  return MESH_MGMT_EXECUTION_RPC_REGISTRY_OK;
}

mesh_mgmt_execution_rpc_registry_result_t
mesh_mgmt_execution_rpc_registry_release_v1(
    mesh_mgmt_execution_rpc_registry_v1_t *registry,
    const uint8_t correlation_id[MESH_MGMT_EXECUTION_ID_SIZE]) {
  mesh_mgmt_execution_rpc_slot_v1_t *slot;

  if (!registry || !registry->impl || !correlation_id ||
      bytes_are_zero(correlation_id, MESH_MGMT_EXECUTION_ID_SIZE))
    return MESH_MGMT_EXECUTION_RPC_REGISTRY_INVALID_ARG;
  slot = find_correlation(registry->impl, correlation_id);
  if (!slot)
    return MESH_MGMT_EXECUTION_RPC_REGISTRY_NOT_FOUND;
  if (slot->state == MESH_MGMT_EXECUTION_RPC_PENDING)
    return MESH_MGMT_EXECUTION_RPC_REGISTRY_NOT_READY;
  memset(slot, 0, sizeof(*slot));
  return MESH_MGMT_EXECUTION_RPC_REGISTRY_OK;
}
