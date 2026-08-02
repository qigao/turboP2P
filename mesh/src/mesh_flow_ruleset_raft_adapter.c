#include "mesh_flow_ruleset_raft_adapter.h"

#include <turbo_error.h>

#include <stdlib.h>
#include <string.h>

struct mesh_flow_ruleset_raft_adapter_s {
  mesh_flow_ruleset_raft_store_v1_t *store;
  tr_raft_service_t *service;
  mesh_flow_ruleset_raft_require_v1_fn require;
  mesh_flow_ruleset_raft_publish_v1_fn publish;
  void *publisher_context;
  uint64_t published_index;
  uint8_t publish_pending;
  uint8_t open;
};

_Static_assert(MESH_FLOW_RULESET_RAFT_MAX_COMMAND_SIZE <=
                   TR_RAFT_MAX_ENTRY_BYTES,
               "ruleset command must fit one TurboRaft entry");

static int map_ruleset_result(mesh_flow_ruleset_result_t result) {
  switch (result) {
  case MESH_FLOW_RULESET_OK:
    return TURBO_OK;
  case MESH_FLOW_RULESET_RESOURCE_EXHAUSTED:
    return TURBO_ENOMEM;
  case MESH_FLOW_RULESET_INVALID_ARG:
  case MESH_FLOW_RULESET_INVALID_STATE:
  case MESH_FLOW_RULESET_OUT_OF_ORDER:
  default:
    return TURBO_EPROTO;
  }
}

static int apply_batch(void *context, const tr_raft_entry_t *entries,
                       size_t entry_count) {
  mesh_flow_ruleset_raft_adapter_v1_t *adapter =
      (mesh_flow_ruleset_raft_adapter_v1_t *)context;
  size_t index;

  if (!adapter || !adapter->open || !adapter->store || !entries ||
      entry_count == 0u) {
    return TURBO_EINVAL;
  }
  for (index = 0u; index < entry_count; ++index) {
    mesh_flow_ruleset_raft_command_v1_t command;
    int callback_result;
    mesh_flow_ruleset_result_t decode_result = mesh_flow_ruleset_raft_decode_v1(
        entries[index].data, entries[index].data_length, &command);
    if (decode_result != MESH_FLOW_RULESET_OK) {
      return map_ruleset_result(decode_result);
    }
    if (command.operation == MESH_FLOW_RULESET_RAFT_COMMIT &&
        adapter->require) {
      callback_result = adapter->require(adapter->publisher_context,
                                         entries[index].index);
      if (callback_result != TURBO_OK) {
        return callback_result;
      }
    }
    mesh_flow_ruleset_result_t result = mesh_flow_ruleset_raft_apply_v1(
        adapter->store, entries[index].index, entries[index].data,
        entries[index].data_length);
    if (result != MESH_FLOW_RULESET_OK) {
      return map_ruleset_result(result);
    }
    if (command.operation == MESH_FLOW_RULESET_RAFT_COMMIT &&
        adapter->publish) {
      callback_result = adapter->publish(adapter->publisher_context,
                                         adapter->store->active);
      if (callback_result == TURBO_OK) {
        adapter->published_index = adapter->store->active->applied_index;
        adapter->publish_pending = 0u;
      } else {
        adapter->publish_pending = 1u;
      }
    }
  }
  return TURBO_OK;
}

static int propose_command(mesh_flow_ruleset_raft_adapter_v1_t *adapter,
                           uint64_t command_id,
                           const mesh_flow_ruleset_raft_command_v1_t *command,
                           tr_raft_operation_status_t *receipt) {
  uint8_t bytes[MESH_FLOW_RULESET_RAFT_MAX_COMMAND_SIZE];
  size_t size = 0u;
  tr_raft_proposal_t proposal;
  mesh_flow_ruleset_result_t result = mesh_flow_ruleset_raft_encode_v1(
      command, bytes, sizeof(bytes), &size);

  if (result != MESH_FLOW_RULESET_OK) {
    return map_ruleset_result(result);
  }
  memset(&proposal, 0, sizeof(proposal));
  proposal.command_id = command_id;
  proposal.data = bytes;
  proposal.data_length = size;
  return tr_raft_service_propose_with_receipt(adapter->service, &proposal,
                                              receipt);
}

int mesh_flow_ruleset_raft_adapter_create_v1(
    mesh_flow_ruleset_raft_store_v1_t *store,
    mesh_flow_ruleset_raft_adapter_v1_t **out_adapter) {
  mesh_flow_ruleset_raft_adapter_v1_t *adapter;

  if (!out_adapter) {
    return TURBO_EINVAL;
  }
  *out_adapter = NULL;
  if (!store || !store->open) {
    return TURBO_EINVAL;
  }
  adapter = (mesh_flow_ruleset_raft_adapter_v1_t *)calloc(1u,
                                                          sizeof(*adapter));
  if (!adapter) {
    return TURBO_ENOMEM;
  }
  adapter->store = store;
  adapter->open = 1u;
  *out_adapter = adapter;
  return TURBO_OK;
}

void mesh_flow_ruleset_raft_adapter_destroy_v1(
    mesh_flow_ruleset_raft_adapter_v1_t *adapter) {
  if (!adapter) {
    return;
  }
  memset(adapter, 0, sizeof(*adapter));
  free(adapter);
}

tr_raft_state_machine_t mesh_flow_ruleset_raft_state_machine_v1(
    mesh_flow_ruleset_raft_adapter_v1_t *adapter) {
  tr_raft_state_machine_t state_machine;

  memset(&state_machine, 0, sizeof(state_machine));
  if (adapter && adapter->open) {
    state_machine.context = adapter;
    state_machine.apply_batch = apply_batch;
  }
  return state_machine;
}

int mesh_flow_ruleset_raft_adapter_bind_service_v1(
    mesh_flow_ruleset_raft_adapter_v1_t *adapter, tr_raft_service_t *service) {
  if (!adapter || !adapter->open || !service ||
      (adapter->service && adapter->service != service)) {
    return TURBO_EINVAL;
  }
  adapter->service = service;
  return TURBO_OK;
}

int mesh_flow_ruleset_raft_adapter_set_publisher_v1(
    mesh_flow_ruleset_raft_adapter_v1_t *adapter,
    mesh_flow_ruleset_raft_require_v1_fn require,
    mesh_flow_ruleset_raft_publish_v1_fn publish, void *publisher_context) {
  if (!adapter || !adapter->open || !require || !publish ||
      !publisher_context || adapter->require || adapter->publish) {
    return TURBO_EINVAL;
  }
  adapter->require = require;
  adapter->publish = publish;
  adapter->publisher_context = publisher_context;
  return TURBO_OK;
}

int mesh_flow_ruleset_raft_adapter_poll_publish_v1(
    mesh_flow_ruleset_raft_adapter_v1_t *adapter, uint8_t *out_published) {
  int result;

  if (out_published) {
    *out_published = 0u;
  }
  if (!adapter || !adapter->open || !out_published) {
    return TURBO_EINVAL;
  }
  if (!adapter->publish_pending) {
    return TURBO_OK;
  }
  result = adapter->publish(adapter->publisher_context,
                            adapter->store->active);
  if (result != TURBO_OK) {
    return result;
  }
  adapter->published_index = adapter->store->active->applied_index;
  adapter->publish_pending = 0u;
  *out_published = 1u;
  return TURBO_OK;
}

int mesh_flow_ruleset_raft_propose_snapshot_v1(
    mesh_flow_ruleset_raft_adapter_v1_t *adapter, uint64_t first_command_id,
    uint64_t policy_epoch, mesh_flow_action_v1_t default_action,
    const mesh_flow_rule_v1_t *rules, size_t rule_count,
    tr_raft_operation_status_t *receipts, size_t receipt_capacity,
    size_t *out_submitted) {
  mesh_flow_ruleset_raft_command_v1_t command;
  size_t required_receipts;
  size_t submitted = 0u;
  size_t offset = 0u;
  int result;

  if (out_submitted) {
    *out_submitted = 0u;
  }
  required_receipts = 2u +
                      (rule_count + MESH_FLOW_RULESET_RAFT_MAX_CHUNK_RULES -
                       1u) /
                          MESH_FLOW_RULESET_RAFT_MAX_CHUNK_RULES;
  if (!adapter || !adapter->open || !adapter->service ||
      first_command_id == 0u || policy_epoch == 0u ||
      rule_count > MESH_FLOW_RULESET_MAX_RULES ||
      (rule_count != 0u && !rules) || !receipts || !out_submitted ||
      required_receipts > MESH_FLOW_RULESET_RAFT_MAX_TRANSACTION_ENTRIES ||
      receipt_capacity < required_receipts ||
      first_command_id > UINT64_MAX - (required_receipts - 1u)) {
    return TURBO_EINVAL;
  }

  memset(&command, 0, sizeof(command));
  command.operation = MESH_FLOW_RULESET_RAFT_BEGIN;
  command.policy_epoch = policy_epoch;
  command.total_rule_count = (uint16_t)rule_count;
  command.default_action = default_action;
  result = propose_command(adapter, first_command_id, &command,
                           &receipts[submitted]);
  if (result != TURBO_OK) {
    return result;
  }
  ++submitted;

  while (offset < rule_count) {
    size_t chunk_count = rule_count - offset;
    if (chunk_count > MESH_FLOW_RULESET_RAFT_MAX_CHUNK_RULES) {
      chunk_count = MESH_FLOW_RULESET_RAFT_MAX_CHUNK_RULES;
    }
    memset(&command, 0, sizeof(command));
    command.operation = MESH_FLOW_RULESET_RAFT_CHUNK;
    command.policy_epoch = policy_epoch;
    command.total_rule_count = (uint16_t)rule_count;
    command.rule_offset = (uint16_t)offset;
    command.rule_count = chunk_count;
    memcpy(command.rules, rules + offset,
           chunk_count * sizeof(*command.rules));
    result = propose_command(adapter, first_command_id + submitted, &command,
                             &receipts[submitted]);
    if (result != TURBO_OK) {
      *out_submitted = submitted;
      return result;
    }
    ++submitted;
    offset += chunk_count;
  }

  memset(&command, 0, sizeof(command));
  command.operation = MESH_FLOW_RULESET_RAFT_COMMIT;
  command.policy_epoch = policy_epoch;
  command.total_rule_count = (uint16_t)rule_count;
  command.rule_offset = (uint16_t)rule_count;
  result = propose_command(adapter, first_command_id + submitted, &command,
                           &receipts[submitted]);
  if (result != TURBO_OK) {
    *out_submitted = submitted;
    return result;
  }
  *out_submitted = submitted + 1u;
  return TURBO_OK;
}
