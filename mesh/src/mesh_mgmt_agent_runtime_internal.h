#ifndef TURBO_P2P_MESH_MGMT_AGENT_RUNTIME_INTERNAL_H
#define TURBO_P2P_MESH_MGMT_AGENT_RUNTIME_INTERNAL_H

#include "mesh_mgmt_agent_runtime.h"
#include "core/node_cnet.h"

/* The full mesh owns this immutable bridge; the dedicated runtime has none. */
typedef struct mesh_mgmt_agent_mesh_ops_s {
  mesh_mgmt_agent_router_result_t (*attach)(struct mesh_network_s *,
                                          mesh_mgmt_agent_router_v1_t *);
  mesh_mgmt_agent_router_result_t (*detach)(struct mesh_network_s *,
                                          mesh_mgmt_agent_router_v1_t *);
} mesh_mgmt_agent_mesh_ops_t;

typedef struct {
  p2p_node_t *node;
  const mesh_mgmt_agent_mesh_ops_t *ops;
  p2p_node_cnet_t *sg_final_owner; /* borrowed exact final SG Node, else NULL */
} mesh_mgmt_agent_mesh_binding_t;

/* @internal The binding and p2p_config are copied, ops have static lifetime. */
mesh_mgmt_agent_runtime_result_t mesh_mgmt_agent_runtime_init_bound(
    mesh_mgmt_agent_runtime_v1_t *runtime,
    const mesh_mgmt_agent_runtime_config_v1_t *config,
    const p2p_runtime_config_v2_t *p2p_config,
    const mesh_mgmt_agent_mesh_binding_t *binding);

#endif
