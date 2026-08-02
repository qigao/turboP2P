#include "mesh_flow_ruleset_raft.h"

#include <stdlib.h>
#include <string.h>

static const uint8_t RULESET_RAFT_MAGIC[4] = {'M', 'F', 'R', '1'};

static void write_u16_le(uint8_t *output, uint16_t value) {
  output[0] = (uint8_t)value;
  output[1] = (uint8_t)(value >> 8u);
}

static uint16_t read_u16_le(const uint8_t *input) {
  return (uint16_t)((uint16_t)input[0] | ((uint16_t)input[1] << 8u));
}

static void write_u32_le(uint8_t *output, uint32_t value) {
  output[0] = (uint8_t)value;
  output[1] = (uint8_t)(value >> 8u);
  output[2] = (uint8_t)(value >> 16u);
  output[3] = (uint8_t)(value >> 24u);
}

static uint32_t read_u32_le(const uint8_t *input) {
  return (uint32_t)input[0] | ((uint32_t)input[1] << 8u) |
         ((uint32_t)input[2] << 16u) | ((uint32_t)input[3] << 24u);
}

static void write_u64_le(uint8_t *output, uint64_t value) {
  size_t index;
  for (index = 0u; index < sizeof(value); ++index) {
    output[index] = (uint8_t)(value >> (index * 8u));
  }
}

static uint64_t read_u64_le(const uint8_t *input) {
  uint64_t value = 0u;
  size_t index;
  for (index = 0u; index < sizeof(value); ++index) {
    value |= ((uint64_t)input[index]) << (index * 8u);
  }
  return value;
}

static uint32_t prefix_mask(uint8_t prefix_len) {
  if (prefix_len == 0u) {
    return 0u;
  }
  return UINT32_MAX << (32u - prefix_len);
}

static int port_range_valid(uint16_t start, uint16_t end) {
  return (start == 0u && end == 0u) || (start != 0u && end >= start);
}

static int rule_valid(const mesh_flow_rule_v1_t *rule) {
  int has_ports;

  if (!rule || rule->rule_id == 0u || rule->src_prefix_len > 32u ||
      rule->dst_prefix_len > 32u ||
      (rule->src_network_ip & prefix_mask(rule->src_prefix_len)) !=
          rule->src_network_ip ||
      (rule->dst_network_ip & prefix_mask(rule->dst_prefix_len)) !=
          rule->dst_network_ip ||
      rule->directions == 0u ||
      (rule->directions & ~((uint32_t)MESH_FLOW_DIRECTION_ANY)) != 0u ||
      (rule->action != MESH_FLOW_ACTION_DENY &&
       rule->action != MESH_FLOW_ACTION_ALLOW) ||
      !port_range_valid(rule->src_port_start, rule->src_port_end) ||
      !port_range_valid(rule->dst_port_start, rule->dst_port_end)) {
    return 0;
  }
  has_ports = rule->src_port_start != 0u || rule->dst_port_start != 0u;
  return !has_ports || rule->ip_proto == 6u || rule->ip_proto == 17u;
}

static int action_valid(mesh_flow_action_v1_t action) {
  return action == MESH_FLOW_ACTION_DENY || action == MESH_FLOW_ACTION_ALLOW;
}

static int command_valid(const mesh_flow_ruleset_raft_command_v1_t *command) {
  size_t index;

  if (!command || command->policy_epoch == 0u ||
      command->total_rule_count > MESH_FLOW_RULESET_MAX_RULES) {
    return 0;
  }
  switch (command->operation) {
  case MESH_FLOW_RULESET_RAFT_BEGIN:
    return command->rule_offset == 0u && command->rule_count == 0u &&
           action_valid(command->default_action);
  case MESH_FLOW_RULESET_RAFT_CHUNK:
    if (command->rule_count == 0u ||
        command->rule_count > MESH_FLOW_RULESET_RAFT_MAX_CHUNK_RULES ||
        command->default_action != 0 ||
        (size_t)command->rule_offset + command->rule_count >
            command->total_rule_count) {
      return 0;
    }
    for (index = 0u; index < command->rule_count; ++index) {
      if (!rule_valid(&command->rules[index])) {
        return 0;
      }
    }
    return 1;
  case MESH_FLOW_RULESET_RAFT_COMMIT:
    return command->rule_offset == command->total_rule_count &&
           command->rule_count == 0u && command->default_action == 0;
  default:
    return 0;
  }
}

static void encode_rule(const mesh_flow_rule_v1_t *rule, uint8_t *output) {
  write_u64_le(output, rule->rule_id);
  write_u32_le(output + 8u, rule->src_network_ip);
  write_u32_le(output + 12u, rule->dst_network_ip);
  write_u16_le(output + 16u, rule->src_port_start);
  write_u16_le(output + 18u, rule->src_port_end);
  write_u16_le(output + 20u, rule->dst_port_start);
  write_u16_le(output + 22u, rule->dst_port_end);
  write_u32_le(output + 24u, rule->directions);
  output[28] = rule->src_prefix_len;
  output[29] = rule->dst_prefix_len;
  output[30] = rule->ip_proto;
  output[31] = (uint8_t)rule->action;
}

static void decode_rule(const uint8_t *input, mesh_flow_rule_v1_t *rule) {
  memset(rule, 0, sizeof(*rule));
  rule->rule_id = read_u64_le(input);
  rule->src_network_ip = read_u32_le(input + 8u);
  rule->dst_network_ip = read_u32_le(input + 12u);
  rule->src_port_start = read_u16_le(input + 16u);
  rule->src_port_end = read_u16_le(input + 18u);
  rule->dst_port_start = read_u16_le(input + 20u);
  rule->dst_port_end = read_u16_le(input + 22u);
  rule->directions = read_u32_le(input + 24u);
  rule->src_prefix_len = input[28];
  rule->dst_prefix_len = input[29];
  rule->ip_proto = input[30];
  rule->action = (mesh_flow_action_v1_t)input[31];
}

mesh_flow_ruleset_result_t mesh_flow_ruleset_raft_store_init_v1(
    mesh_flow_ruleset_raft_store_v1_t *store,
    mesh_flow_ruleset_v1_t *active_ruleset) {
  if (!store || store->open || !active_ruleset || !active_ruleset->open ||
      active_ruleset->capacity == 0u ||
      active_ruleset->capacity > SIZE_MAX / sizeof(mesh_flow_rule_v1_t)) {
    return MESH_FLOW_RULESET_INVALID_ARG;
  }
  memset(store, 0, sizeof(*store));
  store->staging_rules = (mesh_flow_rule_v1_t *)calloc(
      active_ruleset->capacity, sizeof(*store->staging_rules));
  if (!store->staging_rules) {
    return MESH_FLOW_RULESET_RESOURCE_EXHAUSTED;
  }
  store->active = active_ruleset;
  store->capacity = active_ruleset->capacity;
  store->last_log_index = active_ruleset->applied_index;
  store->open = 1u;
  return MESH_FLOW_RULESET_OK;
}

void mesh_flow_ruleset_raft_store_destroy_v1(
    mesh_flow_ruleset_raft_store_v1_t *store) {
  if (!store || !store->open) {
    return;
  }
  memset(store->staging_rules, 0,
         store->capacity * sizeof(*store->staging_rules));
  free(store->staging_rules);
  memset(store, 0, sizeof(*store));
}

mesh_flow_ruleset_result_t mesh_flow_ruleset_raft_encode_v1(
    const mesh_flow_ruleset_raft_command_v1_t *command, uint8_t *output,
    size_t output_capacity, size_t *out_size) {
  size_t size;
  size_t index;

  if (!command_valid(command) || !output || !out_size ||
      command->rule_count >
          (SIZE_MAX - MESH_FLOW_RULESET_RAFT_HEADER_SIZE) /
              MESH_FLOW_RULESET_RAFT_RULE_SIZE) {
    return MESH_FLOW_RULESET_INVALID_ARG;
  }
  size = MESH_FLOW_RULESET_RAFT_HEADER_SIZE +
         command->rule_count * MESH_FLOW_RULESET_RAFT_RULE_SIZE;
  if (output_capacity < size) {
    return MESH_FLOW_RULESET_RESOURCE_EXHAUSTED;
  }
  memset(output, 0, size);
  memcpy(output, RULESET_RAFT_MAGIC, sizeof(RULESET_RAFT_MAGIC));
  output[4] = MESH_FLOW_RULESET_RAFT_VERSION;
  output[5] = (uint8_t)command->operation;
  write_u64_le(output + 8u, command->policy_epoch);
  write_u16_le(output + 16u, command->total_rule_count);
  write_u16_le(output + 18u, command->rule_offset);
  output[20] = (uint8_t)command->default_action;
  for (index = 0u; index < command->rule_count; ++index) {
    encode_rule(&command->rules[index],
                output + MESH_FLOW_RULESET_RAFT_HEADER_SIZE +
                    index * MESH_FLOW_RULESET_RAFT_RULE_SIZE);
  }
  *out_size = size;
  return MESH_FLOW_RULESET_OK;
}

mesh_flow_ruleset_result_t mesh_flow_ruleset_raft_decode_v1(
    const uint8_t *input, size_t input_size,
    mesh_flow_ruleset_raft_command_v1_t *out_command) {
  mesh_flow_ruleset_raft_command_v1_t command;
  size_t payload_size;
  size_t index;

  if (!input || !out_command ||
      input_size < MESH_FLOW_RULESET_RAFT_HEADER_SIZE ||
      input_size > MESH_FLOW_RULESET_RAFT_MAX_COMMAND_SIZE ||
      memcmp(input, RULESET_RAFT_MAGIC, sizeof(RULESET_RAFT_MAGIC)) != 0 ||
      input[4] != MESH_FLOW_RULESET_RAFT_VERSION || input[6] != 0u ||
      input[7] != 0u || input[21] != 0u || input[22] != 0u ||
      input[23] != 0u) {
    return MESH_FLOW_RULESET_INVALID_ARG;
  }
  payload_size = input_size - MESH_FLOW_RULESET_RAFT_HEADER_SIZE;
  if (payload_size % MESH_FLOW_RULESET_RAFT_RULE_SIZE != 0u) {
    return MESH_FLOW_RULESET_INVALID_ARG;
  }
  memset(&command, 0, sizeof(command));
  command.operation = (mesh_flow_ruleset_raft_operation_v1_t)input[5];
  command.policy_epoch = read_u64_le(input + 8u);
  command.total_rule_count = read_u16_le(input + 16u);
  command.rule_offset = read_u16_le(input + 18u);
  command.default_action = (mesh_flow_action_v1_t)input[20];
  command.rule_count = payload_size / MESH_FLOW_RULESET_RAFT_RULE_SIZE;
  for (index = 0u; index < command.rule_count; ++index) {
    decode_rule(input + MESH_FLOW_RULESET_RAFT_HEADER_SIZE +
                    index * MESH_FLOW_RULESET_RAFT_RULE_SIZE,
                &command.rules[index]);
  }
  if (!command_valid(&command)) {
    return MESH_FLOW_RULESET_INVALID_ARG;
  }
  *out_command = command;
  return MESH_FLOW_RULESET_OK;
}

mesh_flow_ruleset_result_t mesh_flow_ruleset_raft_apply_v1(
    mesh_flow_ruleset_raft_store_v1_t *store, uint64_t committed_index,
    const uint8_t *command_data, size_t command_size) {
  mesh_flow_ruleset_raft_command_v1_t command;
  mesh_flow_ruleset_result_t result;

  if (!store || !store->open || committed_index == 0u ||
      committed_index <= store->last_log_index) {
    return MESH_FLOW_RULESET_OUT_OF_ORDER;
  }
  result = mesh_flow_ruleset_raft_decode_v1(command_data, command_size,
                                            &command);
  if (result != MESH_FLOW_RULESET_OK) {
    return result;
  }

  if (command.operation == MESH_FLOW_RULESET_RAFT_BEGIN) {
    if (command.total_rule_count > store->capacity ||
        command.policy_epoch <= store->active->policy_epoch ||
        (store->staging && command.policy_epoch <= store->staging_epoch)) {
      return MESH_FLOW_RULESET_OUT_OF_ORDER;
    }
    memset(store->staging_rules, 0,
           store->capacity * sizeof(*store->staging_rules));
    store->staging_epoch = command.policy_epoch;
    store->staging_default_action = command.default_action;
    store->expected_rule_count = command.total_rule_count;
    store->received_rule_count = 0u;
    store->staging = 1u;
  } else if (command.operation == MESH_FLOW_RULESET_RAFT_CHUNK) {
    if (!store->staging || command.policy_epoch != store->staging_epoch ||
        command.total_rule_count != store->expected_rule_count ||
        command.rule_offset != store->received_rule_count) {
      return MESH_FLOW_RULESET_OUT_OF_ORDER;
    }
    memcpy(store->staging_rules + store->received_rule_count, command.rules,
           command.rule_count * sizeof(*command.rules));
    store->received_rule_count += command.rule_count;
  } else {
    if (!store->staging || command.policy_epoch != store->staging_epoch ||
        command.total_rule_count != store->expected_rule_count ||
        store->received_rule_count != store->expected_rule_count) {
      return MESH_FLOW_RULESET_OUT_OF_ORDER;
    }
    result = mesh_flow_ruleset_apply_replace_v1(
        store->active, committed_index, store->staging_epoch,
        store->staging_default_action, store->staging_rules,
        store->expected_rule_count);
    if (result != MESH_FLOW_RULESET_OK) {
      return result;
    }
    store->staging = 0u;
    store->expected_rule_count = 0u;
    store->received_rule_count = 0u;
  }
  store->last_log_index = committed_index;
  return MESH_FLOW_RULESET_OK;
}
