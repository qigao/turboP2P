#include "mesh_flow_ruleset_raft_adapter.h"
#include "tinytest.h"

#include <string.h>
#include <turbo_error.h>

static mesh_flow_rule_v1_t make_rule(uint64_t id) {
  mesh_flow_rule_v1_t rule;
  memset(&rule, 0, sizeof(rule));
  rule.rule_id = id;
  rule.directions = MESH_FLOW_DIRECTION_ANY;
  rule.action = MESH_FLOW_ACTION_ALLOW;
  return rule;
}

typedef struct {
  uint64_t required_index;
  uint64_t published_index;
  size_t publish_calls;
  uint8_t fail_first_publish;
} publisher_capture_t;

static int capture_require(void *context, uint64_t required_index) {
  publisher_capture_t *capture = (publisher_capture_t *)context;
  capture->required_index = required_index;
  return TURBO_OK;
}

static int capture_publish(void *context,
                           const mesh_flow_ruleset_v1_t *ruleset) {
  publisher_capture_t *capture = (publisher_capture_t *)context;
  ++capture->publish_calls;
  if (capture->fail_first_publish) {
    capture->fail_first_publish = 0u;
    return TURBO_EPROTO;
  }
  capture->published_index = ruleset->applied_index;
  return TURBO_OK;
}

static void apply_command(tr_raft_state_machine_t *state_machine,
                          uint64_t index,
                          const mesh_flow_ruleset_raft_command_v1_t *command) {
  tr_raft_entry_t entry;
  size_t size = 0u;
  memset(&entry, 0, sizeof(entry));
  check_int_eq(mesh_flow_ruleset_raft_encode_v1(
                   command, entry.data, sizeof(entry.data), &size),
               MESH_FLOW_RULESET_OK);
  entry.index = index;
  entry.data_length = size;
  check_int_eq(state_machine->apply_batch(state_machine->context, &entry, 1u),
               TURBO_OK);
}

static void test_state_machine_commits_only_complete_transaction(void) {
  mesh_flow_ruleset_v1_t active;
  mesh_flow_ruleset_raft_store_v1_t store;
  mesh_flow_ruleset_raft_adapter_v1_t *adapter = NULL;
  mesh_flow_ruleset_raft_command_v1_t command;
  tr_raft_state_machine_t state_machine;
  publisher_capture_t capture;
  uint8_t published = 0u;

  memset(&active, 0, sizeof(active));
  memset(&store, 0, sizeof(store));
  memset(&capture, 0, sizeof(capture));
  capture.fail_first_publish = 1u;
  check_int_eq(mesh_flow_ruleset_init_v1(&active, 2u,
                                         MESH_FLOW_ACTION_DENY),
               MESH_FLOW_RULESET_OK);
  check_int_eq(mesh_flow_ruleset_raft_store_init_v1(&store, &active),
               MESH_FLOW_RULESET_OK);
  check_int_eq(mesh_flow_ruleset_raft_adapter_create_v1(&store, &adapter),
               TURBO_OK);
  check_int_eq(mesh_flow_ruleset_raft_adapter_set_publisher_v1(
                   adapter, capture_require, capture_publish, &capture),
               TURBO_OK);
  state_machine = mesh_flow_ruleset_raft_state_machine_v1(adapter);

  memset(&command, 0, sizeof(command));
  command.operation = MESH_FLOW_RULESET_RAFT_BEGIN;
  command.policy_epoch = 3u;
  command.total_rule_count = 1u;
  command.default_action = MESH_FLOW_ACTION_DENY;
  apply_command(&state_machine, 30u, &command);
  check_uint_eq(active.applied_index, 0u);

  memset(&command, 0, sizeof(command));
  command.operation = MESH_FLOW_RULESET_RAFT_CHUNK;
  command.policy_epoch = 3u;
  command.total_rule_count = 1u;
  command.rule_count = 1u;
  command.rules[0] = make_rule(301u);
  apply_command(&state_machine, 31u, &command);
  check_uint_eq(active.applied_index, 0u);

  memset(&command, 0, sizeof(command));
  command.operation = MESH_FLOW_RULESET_RAFT_COMMIT;
  command.policy_epoch = 3u;
  command.total_rule_count = 1u;
  command.rule_offset = 1u;
  apply_command(&state_machine, 32u, &command);
  check_uint_eq(active.applied_index, 32u);
  check_uint_eq(active.policy_epoch, 3u);
  check_uint_eq(active.rule_count, 1u);
  check_uint_eq(capture.required_index, 32u);
  check_uint_eq(capture.published_index, 0u);
  check_int_eq(mesh_flow_ruleset_raft_adapter_poll_publish_v1(adapter,
                                                              &published),
               TURBO_OK);
  check_uint_eq(published, 1u);
  check_uint_eq(capture.published_index, 32u);
  check_uint_eq(capture.publish_calls, 2u);

  mesh_flow_ruleset_raft_adapter_destroy_v1(adapter);
  mesh_flow_ruleset_raft_store_destroy_v1(&store);
  mesh_flow_ruleset_destroy_v1(&active);
}

spec("mesh flow ruleset TurboRaft adapter") {
  it("publishes only a complete committed transaction") {
    test_state_machine_commits_only_complete_transaction();
  }
}
