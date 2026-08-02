#include "mesh_flow_ruleset.h"

#include <tinytest.h>

#include <string.h>

#define IPV4(a, b, c, d)                                                   \
  (((uint32_t)(a) << 24u) | ((uint32_t)(b) << 16u) |                      \
   ((uint32_t)(c) << 8u) | (uint32_t)(d))

static mesh_flow_rule_v1_t make_rule(uint64_t id,
                                     mesh_flow_action_v1_t action,
                                     uint16_t destination_port) {
  mesh_flow_rule_v1_t rule;

  memset(&rule, 0, sizeof(rule));
  rule.rule_id = id;
  rule.src_network_ip = IPV4(10, 42, 0, 0);
  rule.src_prefix_len = 16u;
  rule.dst_network_ip = IPV4(192, 168, 1, 0);
  rule.dst_prefix_len = 24u;
  rule.ip_proto = 6u;
  rule.dst_port_start = destination_port;
  rule.dst_port_end = destination_port;
  rule.directions = MESH_FLOW_DIRECTION_LOCAL_EGRESS;
  rule.action = action;
  return rule;
}

static mesh_flow_query_v1_t make_query(uint16_t destination_port) {
  mesh_flow_query_v1_t query;

  memset(&query, 0, sizeof(query));
  query.src_ip = IPV4(10, 42, 7, 9);
  query.dst_ip = IPV4(192, 168, 1, 10);
  query.src_port = 50000u;
  query.dst_port = destination_port;
  query.direction = MESH_FLOW_DIRECTION_LOCAL_EGRESS;
  query.ip_proto = 6u;
  query.has_ports = 1u;
  memset(query.peer_identity, 0x5a, sizeof(query.peer_identity));
  return query;
}

static void test_first_match_and_default_decisions(void) {
  mesh_flow_ruleset_v1_t ruleset;
  mesh_flow_rule_v1_t rules[2];
  mesh_flow_query_v1_t query;
  mesh_flow_decision_v1_t decision;

  memset(&ruleset, 0, sizeof(ruleset));
  rules[0] = make_rule(101u, MESH_FLOW_ACTION_ALLOW, 443u);
  rules[1] = make_rule(102u, MESH_FLOW_ACTION_DENY, 22u);
  check_int_eq(mesh_flow_ruleset_init_v1(&ruleset, 4u,
                                         MESH_FLOW_ACTION_DENY),
               MESH_FLOW_RULESET_OK);
  check_int_eq(mesh_flow_ruleset_apply_replace_v1(
                   &ruleset, 7u, 3u, MESH_FLOW_ACTION_DENY, rules, 2u),
               MESH_FLOW_RULESET_OK);

  query = make_query(443u);
  check_int_eq(mesh_flow_ruleset_evaluate_v1(&ruleset, &query, &decision),
               MESH_FLOW_RULESET_OK);
  check_int_eq(decision.action, MESH_FLOW_ACTION_ALLOW);
  check_int_eq(decision.reason, MESH_FLOW_REASON_RULE);
  check_long_eq(decision.rule_id, 101u);
  check_long_eq(decision.policy_epoch, 3u);
  check_long_eq(decision.applied_index, 7u);
  check_mem_eq(decision.peer_identity, query.peer_identity,
               sizeof(query.peer_identity));

  query.dst_port = 80u;
  check_int_eq(mesh_flow_ruleset_evaluate_v1(&ruleset, &query, &decision),
               MESH_FLOW_RULESET_OK);
  check_int_eq(decision.action, MESH_FLOW_ACTION_DENY);
  check_int_eq(decision.reason, MESH_FLOW_REASON_DEFAULT);
  check_long_eq(decision.rule_id, 0u);
  mesh_flow_ruleset_destroy_v1(&ruleset);
}

static void test_replay_is_deterministic_and_fenced(void) {
  mesh_flow_ruleset_v1_t first;
  mesh_flow_ruleset_v1_t replay;
  mesh_flow_rule_v1_t rule =
      make_rule(201u, MESH_FLOW_ACTION_ALLOW, 8443u);
  mesh_flow_query_v1_t query = make_query(8443u);
  mesh_flow_decision_v1_t first_decision;
  mesh_flow_decision_v1_t replay_decision;

  memset(&first, 0, sizeof(first));
  memset(&replay, 0, sizeof(replay));
  check_int_eq(mesh_flow_ruleset_init_v1(&first, 2u,
                                         MESH_FLOW_ACTION_DENY),
               MESH_FLOW_RULESET_OK);
  check_int_eq(mesh_flow_ruleset_init_v1(&replay, 2u,
                                         MESH_FLOW_ACTION_DENY),
               MESH_FLOW_RULESET_OK);
  check_int_eq(mesh_flow_ruleset_apply_replace_v1(
                   &first, 11u, 5u, MESH_FLOW_ACTION_DENY, &rule, 1u),
               MESH_FLOW_RULESET_OK);
  check_int_eq(mesh_flow_ruleset_apply_replace_v1(
                   &replay, 11u, 5u, MESH_FLOW_ACTION_DENY, &rule, 1u),
               MESH_FLOW_RULESET_OK);
  check_int_eq(mesh_flow_ruleset_apply_replace_v1(
                   &first, 11u, 6u, MESH_FLOW_ACTION_ALLOW, NULL, 0u),
               MESH_FLOW_RULESET_OUT_OF_ORDER);
  check_int_eq(mesh_flow_ruleset_apply_replace_v1(
                   &first, 12u, 5u, MESH_FLOW_ACTION_ALLOW, NULL, 0u),
               MESH_FLOW_RULESET_OUT_OF_ORDER);
  check_int_eq(mesh_flow_ruleset_evaluate_v1(&first, &query, &first_decision),
               MESH_FLOW_RULESET_OK);
  check_int_eq(mesh_flow_ruleset_evaluate_v1(&replay, &query,
                                              &replay_decision),
               MESH_FLOW_RULESET_OK);
  check_mem_eq(&first_decision, &replay_decision, sizeof(first_decision));
  mesh_flow_ruleset_destroy_v1(&first);
  mesh_flow_ruleset_destroy_v1(&replay);
}

static void test_invalid_replace_preserves_snapshot(void) {
  mesh_flow_ruleset_v1_t ruleset;
  mesh_flow_rule_v1_t rules[2];
  mesh_flow_query_v1_t query = make_query(443u);
  mesh_flow_decision_v1_t before;
  mesh_flow_decision_v1_t after;

  memset(&ruleset, 0, sizeof(ruleset));
  rules[0] = make_rule(301u, MESH_FLOW_ACTION_ALLOW, 443u);
  check_int_eq(mesh_flow_ruleset_init_v1(&ruleset, 1u,
                                         MESH_FLOW_ACTION_DENY),
               MESH_FLOW_RULESET_OK);
  check_int_eq(mesh_flow_ruleset_apply_replace_v1(
                   &ruleset, 1u, 1u, MESH_FLOW_ACTION_DENY, rules, 1u),
               MESH_FLOW_RULESET_OK);
  check_int_eq(mesh_flow_ruleset_evaluate_v1(&ruleset, &query, &before),
               MESH_FLOW_RULESET_OK);

  rules[1] = rules[0];
  check_int_eq(mesh_flow_ruleset_apply_replace_v1(
                   &ruleset, 2u, 2u, MESH_FLOW_ACTION_ALLOW, rules, 2u),
               MESH_FLOW_RULESET_RESOURCE_EXHAUSTED);
  rules[0].src_network_ip = IPV4(10, 42, 0, 1);
  check_int_eq(mesh_flow_ruleset_apply_replace_v1(
                   &ruleset, 2u, 2u, MESH_FLOW_ACTION_ALLOW, rules, 1u),
               MESH_FLOW_RULESET_INVALID_ARG);
  check_int_eq(mesh_flow_ruleset_evaluate_v1(&ruleset, &query, &after),
               MESH_FLOW_RULESET_OK);
  check_mem_eq(&before, &after, sizeof(before));
  mesh_flow_ruleset_destroy_v1(&ruleset);
}

spec("mesh flow ruleset state machine") {
  it("returns immutable first-match and explicit default decisions") {
    test_first_match_and_default_decisions();
  }
  it("replays deterministically and fences stale index or epoch") {
    test_replay_is_deterministic_and_fenced();
  }
  it("keeps the prior snapshot when replacement validation fails") {
    test_invalid_replace_preserves_snapshot();
  }
}
