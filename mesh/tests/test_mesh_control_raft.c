#include "mesh_control_raft.h"
#include "tinytest.h"

#include <string.h>
#include <turbo_error.h>

static void encode_flow(tr_raft_entry_t *entry, uint64_t index,
                        const mesh_flow_ruleset_raft_command_v1_t *command) {
  size_t size = 0u;
  memset(entry, 0, sizeof(*entry));
  check_int_eq(mesh_flow_ruleset_raft_encode_v1(
                   command, entry->data, sizeof(entry->data), &size),
               MESH_FLOW_RULESET_OK);
  entry->index = index;
  entry->data_length = size;
}

static void encode_task(tr_raft_entry_t *entry, uint64_t index,
                        const mesh_task_lease_raft_command_v1_t *command) {
  size_t size = 0u;
  memset(entry, 0, sizeof(*entry));
  check_int_eq(mesh_task_lease_raft_encode_v1(
                   command, entry->data, sizeof(entry->data), &size),
               MESH_TASK_LEASE_OK);
  entry->index = index;
  entry->data_length = size;
}

static void test_mixed_control_log_dispatches_to_one_fact_owner(void) {
  mesh_flow_ruleset_v1_t active;
  mesh_flow_ruleset_raft_store_v1_t flow_store;
  mesh_task_lease_store_v1_t task_store;
  mesh_control_raft_v1_t *control = NULL;
  tr_raft_state_machine_t state_machine;
  tr_raft_entry_t entries[4];
  mesh_flow_ruleset_raft_command_v1_t flow;
  mesh_task_lease_raft_command_v1_t task;
  mesh_task_lease_entry_v1_t task_entry;
  uint64_t control_applied_index = 0u;

  memset(&active, 0, sizeof(active));
  memset(&flow_store, 0, sizeof(flow_store));
  memset(&task_store, 0, sizeof(task_store));
  check_int_eq(mesh_flow_ruleset_init_v1(&active, 2u,
                                         MESH_FLOW_ACTION_DENY),
               MESH_FLOW_RULESET_OK);
  check_int_eq(mesh_flow_ruleset_raft_store_init_v1(&flow_store, &active),
               MESH_FLOW_RULESET_OK);
  check_int_eq(mesh_task_lease_store_init_v1(&task_store, 2u, 100u),
               MESH_TASK_LEASE_OK);
  check_int_eq(mesh_control_raft_create_v1(&flow_store, &task_store, &control),
               TURBO_OK);
  state_machine = mesh_control_raft_state_machine_v1(control);

  memset(&flow, 0, sizeof(flow));
  flow.operation = MESH_FLOW_RULESET_RAFT_BEGIN;
  flow.policy_epoch = 1u;
  flow.default_action = MESH_FLOW_ACTION_ALLOW;
  encode_flow(&entries[0], 1u, &flow);

  memset(&task, 0, sizeof(task));
  task.operation = MESH_TASK_LEASE_RAFT_REGISTER;
  memset(task.command_id, 0x11, sizeof(task.command_id));
  memset(task.request_digest, 0x22, sizeof(task.request_digest));
  task.task_deadline_ms = 1000u;
  encode_task(&entries[1], 2u, &task);

  memset(&flow, 0, sizeof(flow));
  flow.operation = MESH_FLOW_RULESET_RAFT_COMMIT;
  flow.policy_epoch = 1u;
  encode_flow(&entries[2], 3u, &flow);

  memset(&task, 0, sizeof(task));
  task.operation = MESH_TASK_LEASE_RAFT_ACQUIRE;
  memset(task.command_id, 0x11, sizeof(task.command_id));
  memset(task.request_digest, 0x22, sizeof(task.request_digest));
  memset(task.holder_node_id, 0x33, sizeof(task.holder_node_id));
  task.observed_now_ms = 100u;
  task.lease_expires_at_ms = 150u;
  encode_task(&entries[3], 4u, &task);

  check_int_eq(state_machine.apply_batch(state_machine.context, entries, 4u),
               TURBO_OK);
  check_uint_eq(active.applied_index, 3u);
  check_int_eq(active.default_action, MESH_FLOW_ACTION_ALLOW);
  check_int_eq(mesh_task_lease_get_v1(&task_store, task.command_id,
                                      &task_entry),
               MESH_TASK_LEASE_OK);
  check_uint_eq(task_entry.fencing_token, 4u);
  check_uint_eq(task_store.applied_index, 4u);
  check_int_eq(mesh_control_raft_applied_index_v1(control,
                                                  &control_applied_index),
               TURBO_OK);
  check_uint_eq(control_applied_index, 4u);

  mesh_control_raft_destroy_v1(control);
  mesh_task_lease_store_destroy_v1(&task_store);
  mesh_flow_ruleset_raft_store_destroy_v1(&flow_store);
  mesh_flow_ruleset_destroy_v1(&active);
}

spec("mesh control TurboRaft group") {
  it("orders ruleset and task lease commands in one state machine") {
    test_mixed_control_log_dispatches_to_one_fact_owner();
  }
}
