#ifndef MESH_EXAMPLES_MESHD_NETWORK_CONTROL_H
#define MESH_EXAMPLES_MESHD_NETWORK_CONTROL_H

#include "mesh_config.h"
#include "mesh_node_network_control_service.h"

typedef struct {
    const mesh_node_config_t *node;
    const mesh_config_t *underlay;
    uint8_t mesh_id[MESH_CONTROL_DIGEST_SIZE];
    uint8_t provider_id[MESH_CONTROL_DIGEST_SIZE];
    uint8_t issuer_id[MESH_NETWORK_IDENTITY_SIZE];
    uint8_t issuer_public_key[MESH_NETWORK_IDENTITY_SIZE];
    uint8_t sender_incarnation[MESH_CONTROL_ID_SIZE];
} meshd_network_control_config_t;

typedef struct {
    mesh_fabric_t *fabric;
    mesh_network_t *underlay;
    mesh_node_network_control_service_v1_t service;
    uint8_t initialized;
    uint8_t started;
} meshd_network_control_t;

int meshd_network_control_init(
    meshd_network_control_t *runtime,
    const meshd_network_control_config_t *config);
mesh_network_t *meshd_network_control_borrow_underlay(
    meshd_network_control_t *runtime);
int meshd_network_control_start(meshd_network_control_t *runtime);
int meshd_network_control_poll(meshd_network_control_t *runtime,
                               int timeout_ms);

/** Returns zero after an exact drain, one if volatile results were abandoned. */
int meshd_network_control_shutdown(meshd_network_control_t *runtime,
                                   size_t *out_abandoned_operations);
void meshd_network_control_destroy(meshd_network_control_t *runtime);

#endif
