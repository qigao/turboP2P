#ifndef MESH_INTERNAL_FLOW_POLICY_H
#define MESH_INTERNAL_FLOW_POLICY_H

#include "mesh_flow_runtime.h"
#include "turbo_mesh.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Internal control-plane publication boundary; not part of the installed ABI. */
CXX_C_API mesh_flow_runtime_result_t mesh_internal_flow_policy_prepare_v1(
    mesh_network_t *mesh);

CXX_C_API mesh_flow_runtime_result_t mesh_internal_flow_policy_publish_v1(
    mesh_network_t *mesh, uint64_t committed_index, uint64_t policy_epoch,
    mesh_flow_action_v1_t default_action, const mesh_flow_rule_v1_t *rules,
    size_t rule_count);

CXX_C_API mesh_flow_runtime_result_t mesh_internal_flow_policy_require_v1(
    mesh_network_t *mesh, uint64_t required_index);

#ifdef __cplusplus
}
#endif

#endif
