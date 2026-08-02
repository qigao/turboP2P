#include "mesh_flow_runtime.h"

#include <string.h>

#define MESH_IPV4_MIN_HEADER_SIZE 20u
#define MESH_IPV4_VERSION 4u
#define MESH_IPV4_TCP_PROTOCOL 6u
#define MESH_IPV4_UDP_PROTOCOL 17u

static mesh_flow_runtime_result_t map_ruleset_result(
    mesh_flow_ruleset_result_t result) {
  switch (result) {
  case MESH_FLOW_RULESET_OK:
    return MESH_FLOW_RUNTIME_OK;
  case MESH_FLOW_RULESET_INVALID_ARG:
    return MESH_FLOW_RUNTIME_INVALID_ARG;
  case MESH_FLOW_RULESET_INVALID_STATE:
    return MESH_FLOW_RUNTIME_INVALID_STATE;
  case MESH_FLOW_RULESET_OUT_OF_ORDER:
    return MESH_FLOW_RUNTIME_OUT_OF_ORDER;
  case MESH_FLOW_RULESET_RESOURCE_EXHAUSTED:
    return MESH_FLOW_RUNTIME_RESOURCE_EXHAUSTED;
  default:
    return MESH_FLOW_RUNTIME_INVALID_STATE;
  }
}

static uint16_t read_u16_be(const uint8_t *input) {
  return (uint16_t)(((uint16_t)input[0] << 8u) | (uint16_t)input[1]);
}

static uint32_t read_u32_be(const uint8_t *input) {
  return ((uint32_t)input[0] << 24u) | ((uint32_t)input[1] << 16u) |
         ((uint32_t)input[2] << 8u) | (uint32_t)input[3];
}

mesh_flow_runtime_result_t mesh_flow_runtime_init_v1(
    mesh_flow_runtime_v1_t *runtime, size_t capacity,
    mesh_flow_action_v1_t initial_default_action) {
  mesh_flow_ruleset_result_t result;

  if (!runtime || runtime->open) {
    return MESH_FLOW_RUNTIME_INVALID_ARG;
  }

  memset(runtime, 0, sizeof(*runtime));
  result = mesh_flow_ruleset_init_v1(&runtime->slots[0], capacity,
                                     initial_default_action);
  if (result != MESH_FLOW_RULESET_OK) {
    return map_ruleset_result(result);
  }
  result = mesh_flow_ruleset_init_v1(&runtime->slots[1], capacity,
                                     initial_default_action);
  if (result != MESH_FLOW_RULESET_OK) {
    mesh_flow_ruleset_destroy_v1(&runtime->slots[0]);
    return map_ruleset_result(result);
  }

  atomic_init(&runtime->active_slot, 0u);
  atomic_init(&runtime->readers[0], 0u);
  atomic_init(&runtime->readers[1], 0u);
  atomic_init(&runtime->published, 0u);
  atomic_init(&runtime->required_index, 0u);
  atomic_flag_clear(&runtime->writer);
  runtime->open = 1u;
  return MESH_FLOW_RUNTIME_OK;
}

mesh_flow_runtime_result_t mesh_flow_runtime_require_index_v1(
    mesh_flow_runtime_v1_t *runtime, uint64_t required_index) {
  uint_fast64_t current;

  if (!runtime || !runtime->open || required_index == 0u) {
    return MESH_FLOW_RUNTIME_INVALID_ARG;
  }
  current = atomic_load_explicit(&runtime->required_index,
                                 memory_order_acquire);
  while (current < required_index &&
         !atomic_compare_exchange_weak_explicit(
             &runtime->required_index, &current, required_index,
             memory_order_release, memory_order_acquire)) {
  }
  return MESH_FLOW_RUNTIME_OK;
}

void mesh_flow_runtime_destroy_v1(mesh_flow_runtime_v1_t *runtime) {
  if (!runtime || !runtime->open) {
    return;
  }

  atomic_store_explicit(&runtime->published, 0u, memory_order_release);
  mesh_flow_ruleset_destroy_v1(&runtime->slots[1]);
  mesh_flow_ruleset_destroy_v1(&runtime->slots[0]);
  memset(runtime, 0, sizeof(*runtime));
}

mesh_flow_runtime_result_t mesh_flow_runtime_publish_v1(
    mesh_flow_runtime_v1_t *runtime, uint64_t committed_index,
    uint64_t policy_epoch, mesh_flow_action_v1_t default_action,
    const mesh_flow_rule_v1_t *rules, size_t rule_count) {
  unsigned int active;
  unsigned int inactive;
  mesh_flow_ruleset_result_t result;

  if (!runtime || !runtime->open) {
    return MESH_FLOW_RUNTIME_INVALID_ARG;
  }
  if (atomic_flag_test_and_set_explicit(&runtime->writer,
                                        memory_order_acquire)) {
    return MESH_FLOW_RUNTIME_BUSY;
  }

  active = atomic_load_explicit(&runtime->active_slot, memory_order_acquire);
  inactive = active ^ 1u;
  if (atomic_load_explicit(&runtime->published, memory_order_acquire) != 0u &&
      (committed_index <= runtime->slots[active].applied_index ||
       policy_epoch <= runtime->slots[active].policy_epoch)) {
    atomic_flag_clear_explicit(&runtime->writer, memory_order_release);
    return MESH_FLOW_RUNTIME_OUT_OF_ORDER;
  }
  if (atomic_load_explicit(&runtime->readers[inactive],
                           memory_order_acquire) != 0u) {
    atomic_flag_clear_explicit(&runtime->writer, memory_order_release);
    return MESH_FLOW_RUNTIME_BUSY;
  }

  result = mesh_flow_ruleset_apply_replace_v1(
      &runtime->slots[inactive], committed_index, policy_epoch, default_action,
      rules, rule_count);
  if (result == MESH_FLOW_RULESET_OK) {
    atomic_store_explicit(&runtime->active_slot, inactive,
                          memory_order_release);
    atomic_store_explicit(&runtime->published, 1u, memory_order_release);
  }
  atomic_flag_clear_explicit(&runtime->writer, memory_order_release);
  return map_ruleset_result(result);
}

mesh_flow_runtime_result_t mesh_flow_runtime_evaluate_ipv4_v1(
    const mesh_flow_runtime_v1_t *runtime, uint32_t direction,
    const uint8_t *packet, size_t packet_size,
    const uint8_t peer_identity[MESH_FLOW_RULESET_IDENTITY_SIZE],
    mesh_flow_decision_v1_t *out_decision) {
  mesh_flow_query_v1_t query;
  mesh_flow_ruleset_result_t result;
  unsigned int active;
  size_t header_size;
  uint16_t total_size;
  uint16_t fragment;

  if (!runtime || !runtime->open || !packet || !out_decision ||
      packet_size < MESH_IPV4_MIN_HEADER_SIZE ||
      (packet[0] >> 4u) != MESH_IPV4_VERSION) {
    return MESH_FLOW_RUNTIME_INVALID_ARG;
  }
  if (atomic_load_explicit(&runtime->published, memory_order_acquire) == 0u) {
    return atomic_load_explicit(&runtime->required_index,
                                memory_order_acquire) == 0u
               ? MESH_FLOW_RUNTIME_DISABLED
               : MESH_FLOW_RUNTIME_INVALID_STATE;
  }

  header_size = (size_t)(packet[0] & 0x0fu) * 4u;
  total_size = read_u16_be(packet + 2u);
  if (header_size < MESH_IPV4_MIN_HEADER_SIZE || header_size > packet_size ||
      total_size < header_size || total_size > packet_size) {
    return MESH_FLOW_RUNTIME_INVALID_ARG;
  }

  memset(&query, 0, sizeof(query));
  query.src_ip = read_u32_be(packet + 12u);
  query.dst_ip = read_u32_be(packet + 16u);
  query.direction = direction;
  query.ip_proto = packet[9];
  fragment = read_u16_be(packet + 6u);
  if ((query.ip_proto == MESH_IPV4_TCP_PROTOCOL ||
       query.ip_proto == MESH_IPV4_UDP_PROTOCOL) &&
      (fragment & 0x1fffu) == 0u && total_size >= header_size + 4u) {
    query.src_port = read_u16_be(packet + header_size);
    query.dst_port = read_u16_be(packet + header_size + 2u);
    query.has_ports = 1u;
  }
  if (peer_identity) {
    memcpy(query.peer_identity, peer_identity, sizeof(query.peer_identity));
  }

  for (;;) {
    active = atomic_load_explicit(&runtime->active_slot, memory_order_acquire);
    atomic_fetch_add_explicit((atomic_uint *)&runtime->readers[active], 1u,
                              memory_order_acquire);
    if (active ==
            atomic_load_explicit(&runtime->active_slot, memory_order_acquire) &&
        atomic_load_explicit(&runtime->published, memory_order_acquire) != 0u) {
      break;
    }
    atomic_fetch_sub_explicit((atomic_uint *)&runtime->readers[active], 1u,
                              memory_order_release);
    if (atomic_load_explicit(&runtime->published, memory_order_acquire) == 0u) {
      return MESH_FLOW_RUNTIME_DISABLED;
    }
  }

  result = mesh_flow_ruleset_evaluate_v1(&runtime->slots[active], &query,
                                         out_decision);
  if (result == MESH_FLOW_RULESET_OK &&
      runtime->slots[active].applied_index <
          atomic_load_explicit(&runtime->required_index,
                               memory_order_acquire)) {
    result = MESH_FLOW_RULESET_INVALID_STATE;
  }
  atomic_fetch_sub_explicit((atomic_uint *)&runtime->readers[active], 1u,
                            memory_order_release);
  return map_ruleset_result(result);
}
