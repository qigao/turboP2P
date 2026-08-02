#include "mesh_control_raft_mesh_bridge.h"

#include "mesh_internal_flow_policy.h"

#include <turbo_error.h>

static int map_runtime_result(mesh_flow_runtime_result_t result) {
  switch (result) {
  case MESH_FLOW_RUNTIME_OK:
    return TURBO_OK;
  case MESH_FLOW_RUNTIME_RESOURCE_EXHAUSTED:
    return TURBO_ENOMEM;
  case MESH_FLOW_RUNTIME_DISABLED:
  case MESH_FLOW_RUNTIME_INVALID_ARG:
  case MESH_FLOW_RUNTIME_INVALID_STATE:
  case MESH_FLOW_RUNTIME_OUT_OF_ORDER:
  case MESH_FLOW_RUNTIME_BUSY:
  default:
    return TURBO_EPROTO;
  }
}

static int require_index(void *context, uint64_t required_index) {
  return map_runtime_result(mesh_internal_flow_policy_require_v1(
      (mesh_network_t *)context, required_index));
}

static int publish_ruleset(void *context,
                           const mesh_flow_ruleset_v1_t *ruleset) {
  if (!ruleset || !ruleset->open) {
    return TURBO_EINVAL;
  }
  return map_runtime_result(mesh_internal_flow_policy_publish_v1(
      (mesh_network_t *)context, ruleset->applied_index,
      ruleset->policy_epoch, ruleset->default_action, ruleset->rules,
      ruleset->rule_count));
}

int mesh_control_raft_bind_mesh_v1(mesh_control_raft_v1_t *control,
                                   mesh_network_t *mesh) {
  int result;
  if (!control || !mesh) {
    return TURBO_EINVAL;
  }
  result = map_runtime_result(mesh_internal_flow_policy_prepare_v1(mesh));
  if (result != TURBO_OK) {
    return result;
  }
  return mesh_control_raft_set_flow_publisher_v1(
      control, require_index, publish_ruleset, mesh);
}
