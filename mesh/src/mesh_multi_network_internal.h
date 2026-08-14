#ifndef TURBO_P2P_MESH_MULTI_NETWORK_INTERNAL_H
#define TURBO_P2P_MESH_MULTI_NETWORK_INTERNAL_H

#include "turbo_mesh_multi_network.h"

typedef int (*mesh_internal_peer_visit_v2_fn)(
    const uint8_t node_id[MESH_NETWORK_IDENTITY_SIZE], void *user_data);

int mesh_internal_bind_fabric_v2(mesh_network_t *underlay,
                                 mesh_fabric_t *fabric);
void mesh_internal_unbind_fabric_v2(mesh_network_t *underlay,
                                    mesh_fabric_t *fabric);
mesh_network_t *mesh_internal_network_handle_create_v2(void *state);
void *mesh_internal_network_handle_state_v2(mesh_network_t *network);
void mesh_internal_network_handle_destroy_v2(mesh_network_t *network);
int mesh_internal_send_to_node_v2(
    mesh_network_t *underlay,
    const uint8_t node_id[MESH_NETWORK_IDENTITY_SIZE],
    const uint8_t *frame, size_t frame_len);
int mesh_internal_visit_v2_peers(
    mesh_network_t *underlay, mesh_internal_peer_visit_v2_fn visitor,
    void *user_data);

/** Borrowed compatibility handle; expires when fabric is destroyed. */
CXX_C_API mesh_network_t *mesh_internal_fabric_underlay_v2(
    mesh_fabric_t *fabric);

/* Called by the legacy underlay callback boundary. */
int mesh_multi_network_offer_message_v2(
    mesh_fabric_t *fabric,
    const uint8_t authenticated_node_id[MESH_NETWORK_IDENTITY_SIZE],
    const uint8_t *frame, size_t frame_len);
void mesh_multi_network_peer_ready_v2(
    mesh_fabric_t *fabric,
    const uint8_t authenticated_node_id[MESH_NETWORK_IDENTITY_SIZE]);
void mesh_multi_network_peer_closed_v2(
    mesh_fabric_t *fabric,
    const uint8_t authenticated_node_id[MESH_NETWORK_IDENTITY_SIZE]);

#endif
