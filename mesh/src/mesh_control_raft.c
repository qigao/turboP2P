#include "mesh_control_raft.h"

#include <turbo_error.h>

#include <stdlib.h>
#include <string.h>

static const uint8_t FLOW_MAGIC[4] = {'M', 'F', 'R', '1'};
static const uint8_t TASK_MAGIC[4] = {'M', 'T', 'L', '1'};

#define CONTROL_READ_CONTEXT_PREFIX UINT64_C(0x4d43545200000000)
#define CONTROL_READ_CONTEXT_MASK UINT64_C(0x00000000ffffffff)

typedef struct {
  uint64_t context_id;
  uint64_t safe_index;
  mesh_control_raft_read_complete_v1_fn complete;
  void *user_data;
  uint8_t active;
  uint8_t ready;
} mesh_control_pending_read_v1_t;

struct mesh_control_raft_s {
  mesh_flow_ruleset_raft_adapter_v1_t *flow;
  mesh_task_lease_raft_adapter_v1_t *task;
  tr_raft_service_t *service;
  uint64_t applied_index;
  uint64_t next_read_sequence;
  mesh_control_pending_read_v1_t
      pending_reads[MESH_CONTROL_RAFT_MAX_PENDING_READS];
  size_t pending_read_count;
  uint8_t open;
};

static int apply_batch(void *context, const tr_raft_entry_t *entries,
                       size_t entry_count) {
  mesh_control_raft_v1_t *control = (mesh_control_raft_v1_t *)context;
  tr_raft_state_machine_t flow_machine;
  tr_raft_state_machine_t task_machine;
  size_t index;

  if (!control || !control->open || !entries || entry_count == 0u) {
    return TURBO_EINVAL;
  }
  flow_machine = mesh_flow_ruleset_raft_state_machine_v1(control->flow);
  task_machine = mesh_task_lease_raft_state_machine_v1(control->task);
  if (!flow_machine.apply_batch || !task_machine.apply_batch) {
    return TURBO_EINVAL;
  }

  for (index = 0u; index < entry_count; ++index) {
    int result;
    if (entries[index].data_length >= sizeof(FLOW_MAGIC) &&
        memcmp(entries[index].data, FLOW_MAGIC, sizeof(FLOW_MAGIC)) == 0) {
      result = flow_machine.apply_batch(flow_machine.context, &entries[index],
                                        1u);
    } else if (entries[index].data_length >= sizeof(TASK_MAGIC) &&
               memcmp(entries[index].data, TASK_MAGIC, sizeof(TASK_MAGIC)) ==
                   0) {
      result = task_machine.apply_batch(task_machine.context, &entries[index],
                                        1u);
    } else {
      return TURBO_EPROTO;
    }
    if (result != TURBO_OK) {
      return result;
    }
    control->applied_index = entries[index].index;
  }
  return TURBO_OK;
}

int mesh_control_raft_create_v1(
    mesh_flow_ruleset_raft_store_v1_t *flow_store,
    mesh_task_lease_store_v1_t *task_store,
    mesh_control_raft_v1_t **out_control) {
  mesh_control_raft_v1_t *control;
  int result;

  if (!out_control) {
    return TURBO_EINVAL;
  }
  *out_control = NULL;
  if (!flow_store || !flow_store->open || !task_store || !task_store->open) {
    return TURBO_EINVAL;
  }
  control = (mesh_control_raft_v1_t *)calloc(1u, sizeof(*control));
  if (!control) {
    return TURBO_ENOMEM;
  }
  result = mesh_flow_ruleset_raft_adapter_create_v1(flow_store,
                                                     &control->flow);
  if (result != TURBO_OK) {
    free(control);
    return result;
  }
  result = mesh_task_lease_raft_adapter_create_v1(task_store, &control->task);
  if (result != TURBO_OK) {
    mesh_flow_ruleset_raft_adapter_destroy_v1(control->flow);
    free(control);
    return result;
  }
  control->open = 1u;
  *out_control = control;
  return TURBO_OK;
}

void mesh_control_raft_destroy_v1(mesh_control_raft_v1_t *control) {
  if (!control) {
    return;
  }
  mesh_task_lease_raft_adapter_destroy_v1(control->task);
  mesh_flow_ruleset_raft_adapter_destroy_v1(control->flow);
  memset(control, 0, sizeof(*control));
  free(control);
}

tr_raft_state_machine_t mesh_control_raft_state_machine_v1(
    mesh_control_raft_v1_t *control) {
  tr_raft_state_machine_t state_machine;
  memset(&state_machine, 0, sizeof(state_machine));
  if (control && control->open) {
    state_machine.context = control;
    state_machine.apply_batch = apply_batch;
  }
  return state_machine;
}

int mesh_control_raft_bind_service_v1(mesh_control_raft_v1_t *control,
                                      tr_raft_service_t *service) {
  int result;
  if (!control || !control->open || !service ||
      (control->service && control->service != service)) {
    return TURBO_EINVAL;
  }
  result = mesh_flow_ruleset_raft_adapter_bind_service_v1(control->flow,
                                                           service);
  if (result != TURBO_OK) {
    return result;
  }
  result = mesh_task_lease_raft_adapter_bind_service_v1(control->task,
                                                         service);
  if (result != TURBO_OK) {
    return result;
  }
  control->service = service;
  return TURBO_OK;
}

int mesh_control_raft_set_flow_publisher_v1(
    mesh_control_raft_v1_t *control,
    mesh_flow_ruleset_raft_require_v1_fn require,
    mesh_flow_ruleset_raft_publish_v1_fn publish, void *publisher_context) {
  if (!control || !control->open) {
    return TURBO_EINVAL;
  }
  return mesh_flow_ruleset_raft_adapter_set_publisher_v1(
      control->flow, require, publish, publisher_context);
}

int mesh_control_raft_poll_v1(mesh_control_raft_v1_t *control,
                              uint8_t *out_flow_published) {
  if (!control || !control->open) {
    return TURBO_EINVAL;
  }
  return mesh_flow_ruleset_raft_adapter_poll_publish_v1(
      control->flow, out_flow_published);
}

int mesh_control_raft_applied_index_v1(const mesh_control_raft_v1_t *control,
                                       uint64_t *out_applied_index) {
  if (!control || !control->open || !out_applied_index) {
    return TURBO_EINVAL;
  }
  *out_applied_index = control->applied_index;
  return TURBO_OK;
}

static mesh_control_pending_read_v1_t *find_pending_read(
    mesh_control_raft_v1_t *control, uint64_t context_id) {
  size_t index;
  for (index = 0u; index < MESH_CONTROL_RAFT_MAX_PENDING_READS; ++index) {
    if (control->pending_reads[index].active &&
        control->pending_reads[index].context_id == context_id) {
      return &control->pending_reads[index];
    }
  }
  return NULL;
}

static uint64_t allocate_read_context(mesh_control_raft_v1_t *control) {
  size_t attempt;
  for (attempt = 0u; attempt <= control->pending_read_count; ++attempt) {
    uint64_t context_id;
    control->next_read_sequence =
        (control->next_read_sequence + 1u) & CONTROL_READ_CONTEXT_MASK;
    if (control->next_read_sequence == 0u) {
      control->next_read_sequence = 1u;
    }
    context_id = CONTROL_READ_CONTEXT_PREFIX | control->next_read_sequence;
    if (!find_pending_read(control, context_id)) {
      return context_id;
    }
  }
  return 0u;
}

int mesh_control_raft_read_index_v1(
    mesh_control_raft_v1_t *control,
    mesh_control_raft_read_complete_v1_fn complete, void *user_data,
    uint64_t *out_context_id) {
  mesh_control_pending_read_v1_t *slot = NULL;
  uint64_t context_id;
  size_t index;
  int result;

  if (out_context_id) {
    *out_context_id = 0u;
  }
  if (!control || !control->open || !control->service || !complete ||
      !out_context_id) {
    return TURBO_EINVAL;
  }
  for (index = 0u; index < MESH_CONTROL_RAFT_MAX_PENDING_READS; ++index) {
    if (!control->pending_reads[index].active) {
      slot = &control->pending_reads[index];
      break;
    }
  }
  if (!slot) {
    return TURBO_ENOMEM;
  }
  context_id = allocate_read_context(control);
  if (context_id == 0u) {
    return TURBO_ENOMEM;
  }
  memset(slot, 0, sizeof(*slot));
  slot->context_id = context_id;
  slot->complete = complete;
  slot->user_data = user_data;
  slot->active = 1u;
  ++control->pending_read_count;
  result = tr_raft_service_read_index(control->service, context_id);
  if (result != TURBO_OK) {
    memset(slot, 0, sizeof(*slot));
    --control->pending_read_count;
    return result;
  }
  *out_context_id = context_id;
  return TURBO_OK;
}

int mesh_control_raft_poll_reads_v1(mesh_control_raft_v1_t *control,
                                    size_t *out_completed) {
  size_t completed = 0u;
  size_t index;

  if (out_completed) {
    *out_completed = 0u;
  }
  if (!control || !control->open || !control->service || !out_completed) {
    return TURBO_EINVAL;
  }
  for (;;) {
    tr_raft_read_state_t read_state;
    mesh_control_pending_read_v1_t *pending;
    int result = tr_raft_service_take_read_state(control->service,
                                                  &read_state);
    if (result == TURBO_ENOENT) {
      break;
    }
    if (result != TURBO_OK) {
      return result;
    }
    pending = find_pending_read(control, read_state.context_id);
    if (!pending || pending->ready) {
      return TURBO_EPROTO;
    }
    pending->safe_index = read_state.index;
    pending->ready = 1u;
  }

  for (index = 0u; index < MESH_CONTROL_RAFT_MAX_PENDING_READS; ++index) {
    mesh_control_pending_read_v1_t *pending = &control->pending_reads[index];
    mesh_control_raft_read_complete_v1_fn complete;
    void *user_data;
    uint64_t safe_index;
    if (!pending->active || !pending->ready ||
        pending->safe_index > control->applied_index) {
      continue;
    }
    complete = pending->complete;
    user_data = pending->user_data;
    safe_index = pending->safe_index;
    memset(pending, 0, sizeof(*pending));
    --control->pending_read_count;
    complete(TURBO_OK, safe_index, control->applied_index, user_data);
    ++completed;
  }
  *out_completed = completed;
  return TURBO_OK;
}

int mesh_control_raft_propose_flow_snapshot_v1(
    mesh_control_raft_v1_t *control, uint64_t first_command_id,
    uint64_t policy_epoch, mesh_flow_action_v1_t default_action,
    const mesh_flow_rule_v1_t *rules, size_t rule_count,
    tr_raft_operation_status_t *receipts, size_t receipt_capacity,
    size_t *out_submitted) {
  if (!control || !control->open) {
    return TURBO_EINVAL;
  }
  return mesh_flow_ruleset_raft_propose_snapshot_v1(
      control->flow, first_command_id, policy_epoch, default_action, rules,
      rule_count, receipts, receipt_capacity, out_submitted);
}

int mesh_control_raft_propose_task_v1(
    mesh_control_raft_v1_t *control, uint64_t command_id,
    const mesh_task_lease_raft_command_v1_t *command,
    tr_raft_operation_status_t *out_receipt) {
  if (!control || !control->open) {
    return TURBO_EINVAL;
  }
  return mesh_task_lease_raft_propose_v1(control->task, command_id, command,
                                         out_receipt);
}
