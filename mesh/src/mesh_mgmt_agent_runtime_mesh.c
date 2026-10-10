#include "mesh_mgmt_agent_runtime_internal.h"
#include "mesh_mgmt_mesh_bridge.h"

/* Keep references to the full mesh out of the dedicated composition object. */
mesh_mgmt_agent_runtime_result_t mesh_mgmt_agent_runtime_init_v1(
    mesh_mgmt_agent_runtime_v1_t *runtime,
    const mesh_mgmt_agent_runtime_config_v1_t *config) {
  static const mesh_mgmt_agent_mesh_ops_t ops = {
      mesh_mgmt_mesh_router_attach_v1, mesh_mgmt_mesh_router_detach_v1};
  mesh_mgmt_agent_mesh_binding_t binding = {0};
  p2p_runtime_config_v2_t p2p_config;
  int result;

  if (!runtime || !config)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
  if (config->shared_mesh) {
    binding.node = mesh_mgmt_mesh_borrow_p2p_node_v1(config->shared_mesh);
    binding.ops = &ops;
    return mesh_mgmt_agent_runtime_init_bound(runtime, config, NULL, &binding);
  }
  if (config->listen_port == 0u)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
  result = p2p_runtime_config_v2_init(&p2p_config);
  if (result != P2P_OK) {
    runtime->last_p2p_result = result;
    return MESH_MGMT_AGENT_RUNTIME_P2P_FAILED;
  }
  return mesh_mgmt_agent_runtime_init_v2(runtime, config, &p2p_config);
}
