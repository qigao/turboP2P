#ifndef M3_GATEWAY_DATAPANE_H
#define M3_GATEWAY_DATAPANE_H

#include "m3_chunk_mesh.h"
#include "m3_object_manifest.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define M3_GATEWAY_DATAPANE_MAX_STORES 8u
#define M3_GATEWAY_DATAPANE_MAX_OBJECT_BYTES (UINT64_C(64) * 1024 * 1024 * 1024)
#define M3_GATEWAY_DATAPANE_MAX_CHUNKS 4096u
#define M3_GATEWAY_DATAPANE_MESH_TIMEOUT_MS 30000u

typedef enum {
  M3_GATEWAY_DATAPANE_OK = 0,
  M3_GATEWAY_DATAPANE_INVALID_ARG = -1,
  M3_GATEWAY_DATAPANE_RESOURCE_EXHAUSTED = -2,
  M3_GATEWAY_DATAPANE_NOT_AVAILABLE = -3,
  M3_GATEWAY_DATAPANE_INSUFFICIENT_REPLICAS = -4,
  M3_GATEWAY_DATAPANE_CRYPTO_FAILED = -5,
  M3_GATEWAY_DATAPANE_NOT_FOUND = -6,
  M3_GATEWAY_DATAPANE_CORRUPT = -7,
  M3_GATEWAY_DATAPANE_DIGEST_MISMATCH = -8,
  M3_GATEWAY_DATAPANE_IO = -9,
  M3_GATEWAY_DATAPANE_INTERNAL = -10,
  M3_GATEWAY_DATAPANE_NETWORK_FAILED = -11,
} m3_gateway_datapane_result_t;

/** One registered data-plane store. transport == 0 uses the in-process store
 *  handle (P3); transport == 1 uses the authenticated p2p client (P4). Both
 *  keep the node identity and verification key for receipt checks. */
typedef struct {
  uint8_t node_id[M3_CHUNK_CAPABILITY_NODE_ID_SIZE];
  uint8_t public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE];
  m3_store_node_v1_t *store;
  m3_chunk_mesh_client_v1_t mesh;
  uint8_t transport;
} m3_gateway_datapane_store_v1_t;

/**
 * Data-plane client used by the metadata leader. It issues authorized chunk
 * capabilities to registered stores, collects and verifies durable receipts,
 * and encodes the placement into a V2 manifest. All calls run on one owner
 * loop and are not thread-safe.
 */
typedef struct {
  m3_gateway_datapane_store_v1_t stores[M3_GATEWAY_DATAPANE_MAX_STORES];
  size_t store_count;
  uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE];
  size_t target_replicas;
  size_t min_durable_replicas;
  m3_chunk_capability_policy_v1_t policy;
  uint64_t request_seq;
  p2p_node_t *mesh_node;
  m3_chunk_mesh_router_v1_t mesh_router;
  uint8_t signer_private_key[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE];
  uint8_t signer_public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE];
  uint8_t mesh_attached;
} m3_gateway_datapane_v1_t;

m3_gateway_datapane_result_t m3_gateway_datapane_init_v1(
    m3_gateway_datapane_v1_t *datapane,
    const uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE],
    size_t target_replicas, size_t min_durable_replicas,
    const m3_chunk_capability_policy_v1_t *policy);

void m3_gateway_datapane_destroy_v1(m3_gateway_datapane_v1_t *datapane);

m3_gateway_datapane_result_t m3_gateway_datapane_register_store_v1(
    m3_gateway_datapane_v1_t *datapane,
    const uint8_t store_node_id[M3_CHUNK_CAPABILITY_NODE_ID_SIZE],
    const uint8_t public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE],
    m3_store_node_v1_t *store);

/**
 * Attach the authenticated p2p transport for mesh stores. private_key is the
 * gateway's p2p identity key, used to sign chunk capabilities; the store side
 * verifies with the connected peer's public key. Must be called before
 * m3_gateway_datapane_register_mesh_store_v1(). The p2p node loop must be
 * pumped externally while chunk calls run.
 */
m3_gateway_datapane_result_t m3_gateway_datapane_attach_mesh_v1(
    m3_gateway_datapane_v1_t *datapane, p2p_node_t *node,
    const uint8_t private_key[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE]);

/**
 * Register one store reachable over p2p. The gateway dials host:port and
 * signs chunk capabilities with the attached key; receipts are verified with
 * public_key. Chunk payloads are capped at M3_CHUNK_MESH_MAX_PAYLOAD, so the
 * configured max_chunk_bytes must stay below that cap in mesh deployments.
 */
m3_gateway_datapane_result_t m3_gateway_datapane_register_mesh_store_v1(
    m3_gateway_datapane_v1_t *datapane,
    const uint8_t store_node_id[M3_CHUNK_CAPABILITY_NODE_ID_SIZE],
    const uint8_t public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE],
    const char *host, int port);

/**
 * Publish one chunk to one registered store (used by repair to backfill a
 * missing replica). On success out_receipt is the verified durable receipt
 * for that store.
 */
m3_gateway_datapane_result_t m3_gateway_datapane_put_chunk_v1(
    m3_gateway_datapane_v1_t *datapane, size_t store_index,
    const m3_chunk_cid_v1_t *cid, const uint8_t *bytes, size_t size,
    uint64_t now_ms, m3_chunk_receipt_v1_t *out_receipt);

/**
 * Chunk the body, durably publish every chunk to up to target_replicas stores,
 * verify each receipt (signature + store/cid/request binding), and require at
 * least min_durable_replicas verified receipts per chunk before producing the
 * V2 manifest with the committed placement. On failure no metadata is
 * produced; already-durable chunks become orphans reclaimed by GC (P5). The
 * returned manifest bytes are released with m3_object_manifest_bytes_free_v2().
 */
m3_gateway_datapane_result_t m3_gateway_datapane_put_object_v1(
    m3_gateway_datapane_v1_t *datapane, const uint8_t *body, size_t body_len,
    uint64_t max_chunk_bytes, uint64_t now_ms, uint8_t **out_manifest_bytes,
    size_t *out_manifest_size, uint64_t *out_object_size);

/**
 * Read [chunk_offset, chunk_offset + length) of one chunk through the replicas
 * recorded for chunk_index in the manifest placement, trying each store in
 * order. The store verifies the complete chunk CID before any byte is
 * returned. Returns NOT_AVAILABLE when no registered replica serves the range
 * (the caller may fall back to its local CAS).
 */
m3_gateway_datapane_result_t m3_gateway_datapane_read_chunk_v1(
    m3_gateway_datapane_v1_t *datapane, const m3_object_manifest_v2_t *manifest,
    size_t chunk_index, const m3_chunk_cid_v1_t *cid, uint64_t chunk_offset,
    size_t length, uint64_t now_ms, uint8_t *buffer, size_t *out_read);

#ifdef __cplusplus
}
#endif

#endif
