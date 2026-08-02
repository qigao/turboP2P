#ifndef MESH_FLOW_RUNTIME_H
#define MESH_FLOW_RUNTIME_H

#include "mesh_flow_ruleset.h"

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  MESH_FLOW_RUNTIME_OK = 0,
  MESH_FLOW_RUNTIME_DISABLED = 1,
  MESH_FLOW_RUNTIME_INVALID_ARG = -1,
  MESH_FLOW_RUNTIME_INVALID_STATE = -2,
  MESH_FLOW_RUNTIME_OUT_OF_ORDER = -3,
  MESH_FLOW_RUNTIME_RESOURCE_EXHAUSTED = -4,
  MESH_FLOW_RUNTIME_BUSY = -5,
} mesh_flow_runtime_result_t;

/*
 * Two immutable slots keep the packet path allocation-free. A reader pins one
 * slot while a serialized publisher replaces the inactive slot and flips the
 * active index. The owner must quiesce readers before destroy.
 */
typedef struct {
  mesh_flow_ruleset_v1_t slots[2];
  atomic_uint active_slot;
  atomic_uint readers[2];
  atomic_uchar published;
  atomic_uint_fast64_t required_index;
  atomic_flag writer;
  uint8_t open;
} mesh_flow_runtime_v1_t;

mesh_flow_runtime_result_t mesh_flow_runtime_init_v1(
    mesh_flow_runtime_v1_t *runtime, size_t capacity,
    mesh_flow_action_v1_t initial_default_action);

void mesh_flow_runtime_destroy_v1(mesh_flow_runtime_v1_t *runtime);

mesh_flow_runtime_result_t mesh_flow_runtime_publish_v1(
    mesh_flow_runtime_v1_t *runtime, uint64_t committed_index,
    uint64_t policy_epoch, mesh_flow_action_v1_t default_action,
    const mesh_flow_rule_v1_t *rules, size_t rule_count);

mesh_flow_runtime_result_t mesh_flow_runtime_require_index_v1(
    mesh_flow_runtime_v1_t *runtime, uint64_t required_index);

mesh_flow_runtime_result_t mesh_flow_runtime_evaluate_ipv4_v1(
    const mesh_flow_runtime_v1_t *runtime, uint32_t direction,
    const uint8_t *packet, size_t packet_size,
    const uint8_t peer_identity[MESH_FLOW_RULESET_IDENTITY_SIZE],
    mesh_flow_decision_v1_t *out_decision);

#ifdef __cplusplus
}
#endif

#endif
