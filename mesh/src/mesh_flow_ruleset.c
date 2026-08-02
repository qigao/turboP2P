#include "mesh_flow_ruleset.h"

#include <stdlib.h>
#include <string.h>

static int action_valid(mesh_flow_action_v1_t action) {
  return action == MESH_FLOW_ACTION_DENY || action == MESH_FLOW_ACTION_ALLOW;
}

static uint32_t prefix_mask(uint8_t prefix_len) {
  return prefix_len == 0u ? 0u : UINT32_MAX << (32u - prefix_len);
}

static int port_range_valid(uint16_t start, uint16_t end) {
  return (start == 0u && end == 0u) || (start != 0u && end >= start);
}

static int rule_valid(const mesh_flow_rule_v1_t *rule) {
  uint32_t src_mask;
  uint32_t dst_mask;

  if (!rule || rule->rule_id == 0u || !action_valid(rule->action) ||
      rule->src_prefix_len > 32u || rule->dst_prefix_len > 32u ||
      rule->directions == 0u ||
      (rule->directions & ~MESH_FLOW_DIRECTION_ANY) != 0u ||
      !port_range_valid(rule->src_port_start, rule->src_port_end) ||
      !port_range_valid(rule->dst_port_start, rule->dst_port_end)) {
    return 0;
  }
  if ((rule->src_port_start != 0u || rule->dst_port_start != 0u) &&
      rule->ip_proto != 0u && rule->ip_proto != 6u &&
      rule->ip_proto != 17u) {
    return 0;
  }
  src_mask = prefix_mask(rule->src_prefix_len);
  dst_mask = prefix_mask(rule->dst_prefix_len);
  return (rule->src_network_ip & src_mask) == rule->src_network_ip &&
         (rule->dst_network_ip & dst_mask) == rule->dst_network_ip;
}

mesh_flow_ruleset_result_t mesh_flow_ruleset_init_v1(
    mesh_flow_ruleset_v1_t *ruleset, size_t capacity,
    mesh_flow_action_v1_t initial_default_action) {
  mesh_flow_rule_v1_t *rules;

  if (!ruleset || ruleset->open || capacity == 0u ||
      capacity > MESH_FLOW_RULESET_MAX_RULES ||
      capacity > SIZE_MAX / sizeof(*rules) ||
      !action_valid(initial_default_action)) {
    return MESH_FLOW_RULESET_INVALID_ARG;
  }
  rules = (mesh_flow_rule_v1_t *)calloc(capacity, sizeof(*rules));
  if (!rules) {
    return MESH_FLOW_RULESET_RESOURCE_EXHAUSTED;
  }
  memset(ruleset, 0, sizeof(*ruleset));
  ruleset->rules = rules;
  ruleset->capacity = capacity;
  ruleset->default_action = initial_default_action;
  ruleset->open = 1u;
  return MESH_FLOW_RULESET_OK;
}

void mesh_flow_ruleset_destroy_v1(mesh_flow_ruleset_v1_t *ruleset) {
  if (!ruleset) {
    return;
  }
  if (ruleset->rules) {
    memset(ruleset->rules, 0,
           ruleset->capacity * sizeof(*ruleset->rules));
    free(ruleset->rules);
  }
  memset(ruleset, 0, sizeof(*ruleset));
}

mesh_flow_ruleset_result_t mesh_flow_ruleset_apply_replace_v1(
    mesh_flow_ruleset_v1_t *ruleset, uint64_t committed_index,
    uint64_t policy_epoch, mesh_flow_action_v1_t default_action,
    const mesh_flow_rule_v1_t *rules, size_t rule_count) {
  mesh_flow_rule_v1_t *candidate;

  if (!ruleset || !ruleset->open) {
    return MESH_FLOW_RULESET_INVALID_STATE;
  }
  if (committed_index == 0u || policy_epoch == 0u ||
      !action_valid(default_action) ||
      (rule_count != 0u && !rules)) {
    return MESH_FLOW_RULESET_INVALID_ARG;
  }
  if (committed_index <= ruleset->applied_index ||
      policy_epoch <= ruleset->policy_epoch) {
    return MESH_FLOW_RULESET_OUT_OF_ORDER;
  }
  if (rule_count > ruleset->capacity) {
    return MESH_FLOW_RULESET_RESOURCE_EXHAUSTED;
  }
  for (size_t i = 0u; i < rule_count; ++i) {
    if (!rule_valid(&rules[i])) {
      return MESH_FLOW_RULESET_INVALID_ARG;
    }
    for (size_t j = 0u; j < i; ++j) {
      if (rules[i].rule_id == rules[j].rule_id) {
        return MESH_FLOW_RULESET_INVALID_ARG;
      }
    }
  }

  candidate = (mesh_flow_rule_v1_t *)calloc(ruleset->capacity,
                                             sizeof(*candidate));
  if (!candidate) {
    return MESH_FLOW_RULESET_RESOURCE_EXHAUSTED;
  }
  if (rule_count != 0u) {
    memcpy(candidate, rules, rule_count * sizeof(*candidate));
  }
  memset(ruleset->rules, 0,
         ruleset->capacity * sizeof(*ruleset->rules));
  free(ruleset->rules);
  ruleset->rules = candidate;
  ruleset->rule_count = rule_count;
  ruleset->default_action = default_action;
  ruleset->policy_epoch = policy_epoch;
  ruleset->applied_index = committed_index;
  return MESH_FLOW_RULESET_OK;
}

static int query_valid(const mesh_flow_query_v1_t *query) {
  return query && query->direction != 0u &&
         (query->direction & (query->direction - 1u)) == 0u &&
         (query->direction & MESH_FLOW_DIRECTION_ANY) != 0u &&
         query->has_ports <= 1u;
}

static int rule_matches(const mesh_flow_rule_v1_t *rule,
                        const mesh_flow_query_v1_t *query) {
  uint32_t src_mask;
  uint32_t dst_mask;

  if ((rule->directions & query->direction) == 0u ||
      (rule->ip_proto != 0u && rule->ip_proto != query->ip_proto)) {
    return 0;
  }
  src_mask = prefix_mask(rule->src_prefix_len);
  dst_mask = prefix_mask(rule->dst_prefix_len);
  if ((query->src_ip & src_mask) != rule->src_network_ip ||
      (query->dst_ip & dst_mask) != rule->dst_network_ip) {
    return 0;
  }
  if (rule->src_port_start != 0u) {
    if (!query->has_ports || query->src_port < rule->src_port_start ||
        query->src_port > rule->src_port_end) {
      return 0;
    }
  }
  if (rule->dst_port_start != 0u) {
    if (!query->has_ports || query->dst_port < rule->dst_port_start ||
        query->dst_port > rule->dst_port_end) {
      return 0;
    }
  }
  return 1;
}

mesh_flow_ruleset_result_t mesh_flow_ruleset_evaluate_v1(
    const mesh_flow_ruleset_v1_t *ruleset,
    const mesh_flow_query_v1_t *query, mesh_flow_decision_v1_t *out_decision) {
  if (!out_decision) {
    return MESH_FLOW_RULESET_INVALID_ARG;
  }
  memset(out_decision, 0, sizeof(*out_decision));
  if (!ruleset || !ruleset->open) {
    return MESH_FLOW_RULESET_INVALID_STATE;
  }
  if (!query_valid(query)) {
    return MESH_FLOW_RULESET_INVALID_ARG;
  }

  out_decision->action = ruleset->default_action;
  out_decision->reason = MESH_FLOW_REASON_DEFAULT;
  out_decision->policy_epoch = ruleset->policy_epoch;
  out_decision->applied_index = ruleset->applied_index;
  out_decision->direction = query->direction;
  memcpy(out_decision->peer_identity, query->peer_identity,
         sizeof(out_decision->peer_identity));
  for (size_t i = 0u; i < ruleset->rule_count; ++i) {
    if (rule_matches(&ruleset->rules[i], query)) {
      out_decision->action = ruleset->rules[i].action;
      out_decision->reason = MESH_FLOW_REASON_RULE;
      out_decision->rule_id = ruleset->rules[i].rule_id;
      break;
    }
  }
  return MESH_FLOW_RULESET_OK;
}
