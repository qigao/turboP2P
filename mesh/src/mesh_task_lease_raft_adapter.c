#include "mesh_task_lease_raft_adapter.h"

#include <turbo_error.h>

#include <stdlib.h>
#include <string.h>

struct mesh_task_lease_raft_adapter_s {
  mesh_task_lease_store_v1_t *store;
  tr_raft_service_t *service;
  uint8_t open;
};

_Static_assert(MESH_TASK_LEASE_RAFT_COMMAND_SIZE <= TR_RAFT_MAX_ENTRY_BYTES,
               "task lease command must fit one TurboRaft entry");

static int map_lease_result(mesh_task_lease_result_t result) {
  switch (result) {
  case MESH_TASK_LEASE_OK:
    return TURBO_OK;
  case MESH_TASK_LEASE_RESOURCE_EXHAUSTED:
    return TURBO_ENOMEM;
  case MESH_TASK_LEASE_INVALID_ARG:
  case MESH_TASK_LEASE_INVALID_STATE:
  case MESH_TASK_LEASE_NOT_FOUND:
  case MESH_TASK_LEASE_CONFLICT:
  case MESH_TASK_LEASE_BUSY:
  case MESH_TASK_LEASE_FENCED:
  case MESH_TASK_LEASE_OUT_OF_ORDER:
  default:
    return TURBO_EPROTO;
  }
}

static int apply_batch(void *context, const tr_raft_entry_t *entries,
                       size_t entry_count) {
  mesh_task_lease_raft_adapter_v1_t *adapter =
      (mesh_task_lease_raft_adapter_v1_t *)context;
  size_t index;

  if (!adapter || !adapter->open || !adapter->store || !entries ||
      entry_count == 0u) {
    return TURBO_EINVAL;
  }
  for (index = 0u; index < entry_count; ++index) {
    mesh_task_lease_result_t result = mesh_task_lease_raft_apply_v1(
        adapter->store, entries[index].index, entries[index].data,
        entries[index].data_length, NULL);
    if (result != MESH_TASK_LEASE_OK) {
      return map_lease_result(result);
    }
  }
  return TURBO_OK;
}

int mesh_task_lease_raft_adapter_create_v1(
    mesh_task_lease_store_v1_t *store,
    mesh_task_lease_raft_adapter_v1_t **out_adapter) {
  mesh_task_lease_raft_adapter_v1_t *adapter;

  if (!out_adapter) {
    return TURBO_EINVAL;
  }
  *out_adapter = NULL;
  if (!store || !store->open) {
    return TURBO_EINVAL;
  }
  adapter = (mesh_task_lease_raft_adapter_v1_t *)calloc(1u, sizeof(*adapter));
  if (!adapter) {
    return TURBO_ENOMEM;
  }
  adapter->store = store;
  adapter->open = 1u;
  *out_adapter = adapter;
  return TURBO_OK;
}

void mesh_task_lease_raft_adapter_destroy_v1(
    mesh_task_lease_raft_adapter_v1_t *adapter) {
  if (!adapter) {
    return;
  }
  memset(adapter, 0, sizeof(*adapter));
  free(adapter);
}

tr_raft_state_machine_t mesh_task_lease_raft_state_machine_v1(
    mesh_task_lease_raft_adapter_v1_t *adapter) {
  tr_raft_state_machine_t state_machine;

  memset(&state_machine, 0, sizeof(state_machine));
  if (adapter && adapter->open) {
    state_machine.context = adapter;
    state_machine.apply_batch = apply_batch;
  }
  return state_machine;
}

int mesh_task_lease_raft_adapter_bind_service_v1(
    mesh_task_lease_raft_adapter_v1_t *adapter, tr_raft_service_t *service) {
  if (!adapter || !adapter->open || !service ||
      (adapter->service && adapter->service != service)) {
    return TURBO_EINVAL;
  }
  adapter->service = service;
  return TURBO_OK;
}

int mesh_task_lease_raft_propose_v1(
    mesh_task_lease_raft_adapter_v1_t *adapter, uint64_t command_id,
    const mesh_task_lease_raft_command_v1_t *command,
    tr_raft_operation_status_t *out_receipt) {
  uint8_t bytes[MESH_TASK_LEASE_RAFT_COMMAND_SIZE];
  size_t size = 0u;
  tr_raft_proposal_t proposal;
  mesh_task_lease_result_t encode_result;

  if (!adapter || !adapter->open || !adapter->service || command_id == 0u ||
      !command || !out_receipt) {
    return TURBO_EINVAL;
  }
  encode_result = mesh_task_lease_raft_encode_v1(
      command, bytes, sizeof(bytes), &size);
  if (encode_result != MESH_TASK_LEASE_OK) {
    return map_lease_result(encode_result);
  }
  memset(&proposal, 0, sizeof(proposal));
  proposal.command_id = command_id;
  proposal.data = bytes;
  proposal.data_length = size;
  return tr_raft_service_propose_with_receipt(adapter->service, &proposal,
                                              out_receipt);
}
