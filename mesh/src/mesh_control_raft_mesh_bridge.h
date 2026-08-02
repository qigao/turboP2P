#ifndef MESH_CONTROL_RAFT_MESH_BRIDGE_H
#define MESH_CONTROL_RAFT_MESH_BRIDGE_H

#include "mesh_control_raft.h"
#include "turbo_mesh.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Both objects are borrowed and must outlive the binding. */
int mesh_control_raft_bind_mesh_v1(mesh_control_raft_v1_t *control,
                                   mesh_network_t *mesh);

#ifdef __cplusplus
}
#endif

#endif
