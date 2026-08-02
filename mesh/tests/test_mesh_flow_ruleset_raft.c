#include "mesh_flow_ruleset_raft.h"
#include "tinytest.h"

#include <string.h>

static mesh_flow_rule_v1_t make_rule(uint64_t id, uint16_t port) {
  mesh_flow_rule_v1_t rule;
  memset(&rule, 0, sizeof(rule));
  rule.rule_id = id;
  rule.dst_port_start = port;
  rule.dst_port_end = port;
  rule.directions = MESH_FLOW_DIRECTION_OUT;
  rule.ip_proto = 6u;
  rule.action = MESH_FLOW_ACTION_ALLOW;
  return rule;
}

static void encode_apply(mesh_flow_ruleset_raft_store_v1_t *store,
                         uint64_t index,
                         const mesh_flow_ruleset_raft_command_v1_t *command) {
  uint8_t bytes[MESH_FLOW_RULESET_RAFT_MAX_COMMAND_SIZE];
  size_t size = 0u;
  check_int_eq(mesh_flow_ruleset_raft_encode_v1(
                   command, bytes, sizeof(bytes), &size),
               MESH_FLOW_RULESET_OK);
  check_int_eq(mesh_flow_ruleset_raft_apply_v1(store, index, bytes, size),
               MESH_FLOW_RULESET_OK);
}

static void apply_snapshot(mesh_flow_ruleset_raft_store_v1_t *store,
                           uint64_t first_index) {
  mesh_flow_ruleset_raft_command_v1_t command;
  size_t index;

  memset(&command, 0, sizeof(command));
  command.operation = MESH_FLOW_RULESET_RAFT_BEGIN;
  command.policy_epoch = 7u;
  command.total_rule_count = 16u;
  command.default_action = MESH_FLOW_ACTION_DENY;
  encode_apply(store, first_index, &command);

  memset(&command, 0, sizeof(command));
  command.operation = MESH_FLOW_RULESET_RAFT_CHUNK;
  command.policy_epoch = 7u;
  command.total_rule_count = 16u;
  command.rule_count = MESH_FLOW_RULESET_RAFT_MAX_CHUNK_RULES;
  for (index = 0u; index < command.rule_count; ++index) {
    command.rules[index] = make_rule(100u + index, (uint16_t)(8000u + index));
  }
  encode_apply(store, first_index + 1u, &command);

  memset(&command, 0, sizeof(command));
  command.operation = MESH_FLOW_RULESET_RAFT_CHUNK;
  command.policy_epoch = 7u;
  command.total_rule_count = 16u;
  command.rule_offset = MESH_FLOW_RULESET_RAFT_MAX_CHUNK_RULES;
  command.rule_count = 1u;
  command.rules[0] = make_rule(115u, 8015u);
  encode_apply(store, first_index + 2u, &command);

  memset(&command, 0, sizeof(command));
  command.operation = MESH_FLOW_RULESET_RAFT_COMMIT;
  command.policy_epoch = 7u;
  command.total_rule_count = 16u;
  command.rule_offset = 16u;
  encode_apply(store, first_index + 3u, &command);
}

static void test_segmented_snapshot_replays_atomically(void) {
  mesh_flow_ruleset_v1_t first_active;
  mesh_flow_ruleset_v1_t replay_active;
  mesh_flow_ruleset_raft_store_v1_t first;
  mesh_flow_ruleset_raft_store_v1_t replay;
  mesh_flow_query_v1_t query;
  mesh_flow_decision_v1_t first_decision;
  mesh_flow_decision_v1_t replay_decision;

  memset(&first_active, 0, sizeof(first_active));
  memset(&replay_active, 0, sizeof(replay_active));
  memset(&first, 0, sizeof(first));
  memset(&replay, 0, sizeof(replay));
  check_int_eq(mesh_flow_ruleset_init_v1(&first_active, 16u,
                                         MESH_FLOW_ACTION_DENY),
               MESH_FLOW_RULESET_OK);
  check_int_eq(mesh_flow_ruleset_init_v1(&replay_active, 16u,
                                         MESH_FLOW_ACTION_DENY),
               MESH_FLOW_RULESET_OK);
  check_int_eq(mesh_flow_ruleset_raft_store_init_v1(&first, &first_active),
               MESH_FLOW_RULESET_OK);
  check_int_eq(mesh_flow_ruleset_raft_store_init_v1(&replay, &replay_active),
               MESH_FLOW_RULESET_OK);
  apply_snapshot(&first, 20u);
  apply_snapshot(&replay, 20u);

  memset(&query, 0, sizeof(query));
  query.direction = MESH_FLOW_DIRECTION_OUT;
  query.ip_proto = 6u;
  query.has_ports = 1u;
  query.dst_port = 8015u;
  check_int_eq(mesh_flow_ruleset_evaluate_v1(&first_active, &query,
                                             &first_decision),
               MESH_FLOW_RULESET_OK);
  check_int_eq(mesh_flow_ruleset_evaluate_v1(&replay_active, &query,
                                             &replay_decision),
               MESH_FLOW_RULESET_OK);
  check_int_eq(first_decision.action, MESH_FLOW_ACTION_ALLOW);
  check_uint_eq(first_decision.rule_id, 115u);
  check_uint_eq(first_decision.applied_index, 23u);
  check_mem_eq(&first_decision, &replay_decision, sizeof(first_decision));

  mesh_flow_ruleset_raft_store_destroy_v1(&replay);
  mesh_flow_ruleset_raft_store_destroy_v1(&first);
  mesh_flow_ruleset_destroy_v1(&replay_active);
  mesh_flow_ruleset_destroy_v1(&first_active);
}

static void test_out_of_order_chunk_does_not_publish(void) {
  mesh_flow_ruleset_v1_t active;
  mesh_flow_ruleset_raft_store_v1_t store;
  mesh_flow_ruleset_raft_command_v1_t command;
  uint8_t bytes[MESH_FLOW_RULESET_RAFT_MAX_COMMAND_SIZE];
  size_t size = 0u;

  memset(&active, 0, sizeof(active));
  memset(&store, 0, sizeof(store));
  check_int_eq(mesh_flow_ruleset_init_v1(&active, 2u,
                                         MESH_FLOW_ACTION_DENY),
               MESH_FLOW_RULESET_OK);
  check_int_eq(mesh_flow_ruleset_raft_store_init_v1(&store, &active),
               MESH_FLOW_RULESET_OK);
  memset(&command, 0, sizeof(command));
  command.operation = MESH_FLOW_RULESET_RAFT_BEGIN;
  command.policy_epoch = 2u;
  command.total_rule_count = 1u;
  command.default_action = MESH_FLOW_ACTION_DENY;
  encode_apply(&store, 1u, &command);

  memset(&command, 0, sizeof(command));
  command.operation = MESH_FLOW_RULESET_RAFT_CHUNK;
  command.policy_epoch = 2u;
  command.total_rule_count = 1u;
  command.rule_offset = 1u;
  command.rule_count = 1u;
  command.rules[0] = make_rule(9u, 443u);
  check_int_eq(mesh_flow_ruleset_raft_encode_v1(
                   &command, bytes, sizeof(bytes), &size),
               MESH_FLOW_RULESET_INVALID_ARG);
  check_uint_eq(active.applied_index, 0u);
  check_uint_eq(active.rule_count, 0u);

  mesh_flow_ruleset_raft_store_destroy_v1(&store);
  mesh_flow_ruleset_destroy_v1(&active);
}

spec("mesh flow ruleset raft transaction") {
  it("publishes and replays a segmented snapshot atomically") {
    test_segmented_snapshot_replays_atomically();
  }
  it("rejects out-of-order chunks before publication") {
    test_out_of_order_chunk_does_not_publish();
  }
}
