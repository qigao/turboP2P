#ifndef MESH_FLOW_RULESET_RAFT_H
#define MESH_FLOW_RULESET_RAFT_H

#include "mesh_flow_ruleset.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_FLOW_RULESET_RAFT_VERSION 1u
#define MESH_FLOW_RULESET_RAFT_HEADER_SIZE 24u
#define MESH_FLOW_RULESET_RAFT_RULE_SIZE 32u
#define MESH_FLOW_RULESET_RAFT_MAX_CHUNK_RULES 15u
#define MESH_FLOW_RULESET_RAFT_MAX_COMMAND_SIZE                                \
  (MESH_FLOW_RULESET_RAFT_HEADER_SIZE +                                       \
   (MESH_FLOW_RULESET_RAFT_RULE_SIZE *                                        \
    MESH_FLOW_RULESET_RAFT_MAX_CHUNK_RULES))

typedef enum {
  MESH_FLOW_RULESET_RAFT_BEGIN = 1,
  MESH_FLOW_RULESET_RAFT_CHUNK = 2,
  MESH_FLOW_RULESET_RAFT_COMMIT = 3,
} mesh_flow_ruleset_raft_operation_v1_t;

typedef struct {
  mesh_flow_ruleset_raft_operation_v1_t operation;
  uint64_t policy_epoch;
  uint16_t total_rule_count;
  uint16_t rule_offset;
  mesh_flow_action_v1_t default_action;
  mesh_flow_rule_v1_t rules[MESH_FLOW_RULESET_RAFT_MAX_CHUNK_RULES];
  size_t rule_count;
} mesh_flow_ruleset_raft_command_v1_t;

typedef struct {
  mesh_flow_ruleset_v1_t *active;
  mesh_flow_rule_v1_t *staging_rules;
  size_t capacity;
  size_t expected_rule_count;
  size_t received_rule_count;
  uint64_t staging_epoch;
  uint64_t last_log_index;
  mesh_flow_action_v1_t staging_default_action;
  uint8_t staging;
  uint8_t open;
} mesh_flow_ruleset_raft_store_v1_t;

mesh_flow_ruleset_result_t mesh_flow_ruleset_raft_store_init_v1(
    mesh_flow_ruleset_raft_store_v1_t *store,
    mesh_flow_ruleset_v1_t *active_ruleset);

void mesh_flow_ruleset_raft_store_destroy_v1(
    mesh_flow_ruleset_raft_store_v1_t *store);

mesh_flow_ruleset_result_t mesh_flow_ruleset_raft_encode_v1(
    const mesh_flow_ruleset_raft_command_v1_t *command, uint8_t *output,
    size_t output_capacity, size_t *out_size);

mesh_flow_ruleset_result_t mesh_flow_ruleset_raft_decode_v1(
    const uint8_t *input, size_t input_size,
    mesh_flow_ruleset_raft_command_v1_t *out_command);

mesh_flow_ruleset_result_t mesh_flow_ruleset_raft_apply_v1(
    mesh_flow_ruleset_raft_store_v1_t *store, uint64_t committed_index,
    const uint8_t *command_data, size_t command_size);

#ifdef __cplusplus
}
#endif

#endif
