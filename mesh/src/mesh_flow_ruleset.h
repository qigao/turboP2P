#ifndef MESH_FLOW_RULESET_H
#define MESH_FLOW_RULESET_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_FLOW_RULESET_VERSION 1u
#define MESH_FLOW_RULESET_IDENTITY_SIZE 32u
#define MESH_FLOW_RULESET_MAX_RULES 256u

typedef enum {
  MESH_FLOW_RULESET_OK = 0,
  MESH_FLOW_RULESET_INVALID_ARG = -1,
  MESH_FLOW_RULESET_INVALID_STATE = -2,
  MESH_FLOW_RULESET_OUT_OF_ORDER = -3,
  MESH_FLOW_RULESET_RESOURCE_EXHAUSTED = -4,
} mesh_flow_ruleset_result_t;

typedef enum {
  MESH_FLOW_ACTION_DENY = 0,
  MESH_FLOW_ACTION_ALLOW = 1,
} mesh_flow_action_v1_t;

typedef enum {
  MESH_FLOW_DIRECTION_IN = 1u << 0,
  MESH_FLOW_DIRECTION_OUT = 1u << 1,
  MESH_FLOW_DIRECTION_FORWARD = 1u << 2,
  MESH_FLOW_DIRECTION_LOCAL_EGRESS = 1u << 3,
  MESH_FLOW_DIRECTION_ANY = 0x0fu,
} mesh_flow_direction_v1_t;

typedef enum {
  MESH_FLOW_REASON_RULE = 1,
  MESH_FLOW_REASON_DEFAULT = 2,
} mesh_flow_reason_v1_t;

/** IPv4 addresses use the canonical a.b.c.d numeric form (a in high byte). */
typedef struct {
  uint64_t rule_id;
  uint32_t src_network_ip;
  uint32_t dst_network_ip;
  uint16_t src_port_start;
  uint16_t src_port_end;
  uint16_t dst_port_start;
  uint16_t dst_port_end;
  uint32_t directions;
  uint8_t src_prefix_len;
  uint8_t dst_prefix_len;
  uint8_t ip_proto;
  mesh_flow_action_v1_t action;
} mesh_flow_rule_v1_t;

typedef struct {
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t direction;
  uint8_t ip_proto;
  uint8_t has_ports;
  uint8_t peer_identity[MESH_FLOW_RULESET_IDENTITY_SIZE];
} mesh_flow_query_v1_t;

typedef struct {
  mesh_flow_action_v1_t action;
  mesh_flow_reason_v1_t reason;
  uint64_t rule_id;
  uint64_t policy_epoch;
  uint64_t applied_index;
  uint32_t direction;
  uint8_t peer_identity[MESH_FLOW_RULESET_IDENTITY_SIZE];
} mesh_flow_decision_v1_t;

typedef struct {
  mesh_flow_rule_v1_t *rules;
  size_t rule_count;
  size_t capacity;
  uint64_t policy_epoch;
  uint64_t applied_index;
  mesh_flow_action_v1_t default_action;
  uint8_t open;
} mesh_flow_ruleset_v1_t;

/** The caller must zero-initialize ruleset before first init. */
mesh_flow_ruleset_result_t mesh_flow_ruleset_init_v1(
    mesh_flow_ruleset_v1_t *ruleset, size_t capacity,
    mesh_flow_action_v1_t initial_default_action);
void mesh_flow_ruleset_destroy_v1(mesh_flow_ruleset_v1_t *ruleset);

/**
 * Atomically replace the complete ordered snapshot after validating every rule.
 * policy_epoch and committed_index must both advance. Validation is O(n^2) for
 * duplicate stable IDs; evaluation is O(n), with n bounded by capacity.
 */
mesh_flow_ruleset_result_t mesh_flow_ruleset_apply_replace_v1(
    mesh_flow_ruleset_v1_t *ruleset, uint64_t committed_index,
    uint64_t policy_epoch, mesh_flow_action_v1_t default_action,
    const mesh_flow_rule_v1_t *rules, size_t rule_count);

/** Pure first-match evaluation against the current immutable snapshot. */
mesh_flow_ruleset_result_t mesh_flow_ruleset_evaluate_v1(
    const mesh_flow_ruleset_v1_t *ruleset,
    const mesh_flow_query_v1_t *query, mesh_flow_decision_v1_t *out_decision);

#ifdef __cplusplus
}
#endif

#endif
