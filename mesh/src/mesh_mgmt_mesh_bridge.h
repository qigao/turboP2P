#ifndef TURBO_P2P_MESH_MGMT_MESH_BRIDGE_H
#define TURBO_P2P_MESH_MGMT_MESH_BRIDGE_H

#include "mesh_mgmt_agent_router.h"
#include "turbo_mesh.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Internal bridge between the mesh data plane and an MMP router.
 *
 * The returned P2P node is borrowed and remains owned by mesh. The router is
 * borrowed by mesh after attach and must outlive the attachment.
 */
CXX_C_API p2p_node_t *mesh_mgmt_mesh_borrow_p2p_node_v1(mesh_network_t *mesh);

/**
 * Attach a READY router initialized against mesh's borrowed P2P node.
 * Attachment is allowed only before mesh_start().
 */
CXX_C_API mesh_mgmt_agent_router_result_t
mesh_mgmt_mesh_router_attach_v1(mesh_network_t *mesh,
                               mesh_mgmt_agent_router_v1_t *router);

/**
 * Retire MMP sessions without disconnecting shared data-plane peers.
 */
CXX_C_API mesh_mgmt_agent_router_result_t
mesh_mgmt_mesh_router_detach_v1(mesh_network_t *mesh,
                               mesh_mgmt_agent_router_v1_t *router);

#ifdef __cplusplus
}
#endif

#endif
