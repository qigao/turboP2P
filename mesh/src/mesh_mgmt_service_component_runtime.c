#include "mesh_mgmt_service_component_runtime.h"

mesh_mgmt_agent_runtime_result_t mesh_mgmt_agent_runtime_publish_component_service_v1(
    mesh_mgmt_agent_runtime_v1_t *runtime,
    const mesh_mgmt_service_component_view_v1_t *view, uint64_t *epoch) {
  mesh_mgmt_service_publish_v1_t snapshot;
  if (epoch == NULL) return MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
  *epoch = 0;
  if (runtime == NULL) return MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
  if (runtime->state != MESH_MGMT_AGENT_RUNTIME_RUNNING || runtime->in_api || !runtime->node)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_STATE;
  if (mesh_mgmt_service_component_snapshot_v1(view, &snapshot) != MESH_MGMT_SERVICE_CONFIG_OK)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
  return mesh_mgmt_agent_runtime_publish_cached_service_v1(runtime, &snapshot, epoch);
}
