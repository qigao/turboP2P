#ifndef MESH_NETWORK_RECONCILER_H
#define MESH_NETWORK_RECONCILER_H

#include "mesh_control_document.h"
#include "turbo_mesh_multi_network.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  uint8_t resource_id[MESH_CONTROL_DIGEST_SIZE];
  mesh_network_uid_t network_uid;
  mesh_network_t *network;
  uint64_t generation;
  uint8_t document_digest[MESH_CONTROL_DIGEST_SIZE];
} mesh_network_reconciler_record_v1_t;

typedef struct {
  mesh_fabric_t *fabric;
  mesh_network_reconciler_record_v1_t *records;
  size_t count;
  size_t capacity;
  uint8_t lifecycle;
} mesh_network_reconciler_v1_t;

/** Derive the canonical resource identifier from mesh_id and Network UID. */
mesh_control_result_t mesh_network_resource_id_v1(
    const uint8_t mesh_id[MESH_CONTROL_DIGEST_SIZE],
    const uint8_t network_uid[MESH_CONTROL_ID_SIZE],
    uint8_t out_resource_id[MESH_CONTROL_DIGEST_SIZE]);

/** Initialize one zero-initialized, single-owner bounded runtime reconciler. */
mesh_control_result_t mesh_network_reconciler_init_v1(
    mesh_network_reconciler_v1_t *reconciler, mesh_fabric_t *fabric,
    size_t capacity);

/**
 * Apply one signature-verified NETWORK intent. APPLY document is canonical
 * mesh_control_network_document_v1 bytes. DELETE carries no document and uses
 * resource_id + precondition_generation to drain the existing Network.
 */
mesh_control_result_t mesh_network_reconciler_submit_v1(
    mesh_network_reconciler_v1_t *reconciler,
    const uint8_t resource_id[MESH_CONTROL_DIGEST_SIZE],
    mesh_control_desired_action_v1_t action,
    uint64_t precondition_generation,
    const uint8_t *document, size_t document_size,
    uint64_t drain_timeout_ms, uint64_t *out_generation);

/**
 * Detach all owned Networks. Fabric remains caller-owned. A failed detach
 * leaves the reconciler in CLOSING state and retains the failed record so the
 * caller can retry close; new submissions are rejected once close begins.
 */
mesh_control_result_t mesh_network_reconciler_close_v1(
    mesh_network_reconciler_v1_t *reconciler, uint64_t drain_timeout_ms);
void mesh_network_reconciler_destroy_v1(
    mesh_network_reconciler_v1_t *reconciler);

#ifdef __cplusplus
}
#endif

#endif
