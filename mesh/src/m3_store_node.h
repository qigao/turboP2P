#ifndef M3_STORE_NODE_H
#define M3_STORE_NODE_H

#include "m3_chunk_read_service.h"
#include "m3_chunk_receipt.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define M3_STORE_NODE_FAILURE_DOMAIN_SIZE 64u
#define M3_STORE_NODE_MAX_TENANTS 64u
#define M3_STORE_NODE_REPLAY_CAPACITY 256u

typedef enum {
  M3_STORE_NODE_OK = 0,
  M3_STORE_NODE_INVALID_ARG = -1,
  M3_STORE_NODE_AUTH_DENIED = -2,
  M3_STORE_NODE_NOT_YET_VALID = -3,
  M3_STORE_NODE_EXPIRED = -4,
  M3_STORE_NODE_RESOURCE_EXHAUSTED = -5,
  M3_STORE_NODE_NOT_FOUND = -6,
  M3_STORE_NODE_CORRUPT = -7,
  M3_STORE_NODE_DIGEST_MISMATCH = -8,
  M3_STORE_NODE_IO = -9,
  M3_STORE_NODE_QUOTA_EXCEEDED = -10,
  M3_STORE_NODE_CRYPTO_FAILED = -11,
  M3_STORE_NODE_LOCKED = -12,
  M3_STORE_NODE_CONFLICT = -13,
  M3_STORE_NODE_IN_PROGRESS = -14,
  M3_STORE_NODE_INTERNAL = -15,
} m3_store_node_result_t;

/**
 * Store-node configuration. The store root must already exist; the node
 * creates and owns its versioned CAS directories and process-exclusive lock.
 */
typedef struct {
  char store_root[TURBO_FS_MAX_PATH];
  uint64_t max_chunk_bytes;
  uint64_t max_tenant_bytes;
  uint8_t node_id[M3_CHUNK_CAPABILITY_NODE_ID_SIZE];
  uint8_t signing_private_key[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE];
  char failure_domain[M3_STORE_NODE_FAILURE_DOMAIN_SIZE];
  m3_chunk_capability_policy_v1_t policy;
} m3_store_node_config_v1_t;

/** In-memory per-tenant byte accounting (V1; GC reclaims later). */
typedef struct {
  uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE];
  uint64_t used_bytes;
} m3_store_node_tenant_usage_v1_t;

/**
 * Data-plane service over one immutable local CAS. All calls run on one
 * owner loop and are not thread-safe. The node owns the CAS, the read replay
 * journal and the read service; it signs durable receipts with its own key.
 */
typedef struct {
  m3_chunk_store_v1_t store;
  m3_chunk_replay_journal_v1_t replay;
  m3_chunk_read_service_v1_t read_service;
  m3_store_node_tenant_usage_v1_t tenants[M3_STORE_NODE_MAX_TENANTS];
  size_t tenant_count;
  m3_store_node_config_v1_t config;
  uint8_t initialized;
} m3_store_node_v1_t;

/** Observation snapshot for leader placement scoring. */
typedef struct {
  char failure_domain[M3_STORE_NODE_FAILURE_DOMAIN_SIZE];
  uint64_t used_bytes;
  uint64_t quota_limit_bytes;
  uint64_t free_capacity_bytes;
  uint64_t min_tenant_headroom_bytes;
  size_t tenant_count;
} m3_store_node_health_v1_t;

/**
 * Open the local CAS, initialize the read path and bind the node identity.
 * request->now_ms is the store-side evaluation time: the transport boundary
 * must populate it from the store's own clock, not the caller's.
 */
m3_store_node_result_t m3_store_node_init_v1(
    m3_store_node_v1_t *node, const m3_store_node_config_v1_t *config);

void m3_store_node_destroy_v1(m3_store_node_v1_t *node);

/**
 * Authorize and durably publish one complete chunk from already
 * signature-verified claims. The audience check binds the claims to this
 * node. On success out_receipt is signed by this store identity; re-publishing
 * an existing CID is idempotent and does not double-count quota. Quota is a
 * strict per-tenant cap enforced before publication.
 */
m3_store_node_result_t m3_store_node_put_chunk_v1(
    m3_store_node_v1_t *node,
    const m3_chunk_capability_claims_v1_t *verified_claims,
    const m3_chunk_access_request_v1_t *request, const uint8_t *bytes,
    size_t size, m3_chunk_receipt_v1_t *out_receipt);

/**
 * Authorize and read the exact range carried by an already verified READ
 * capability. The CAS verifies the complete chunk CID before out_read
 * becomes nonzero.
 */
m3_store_node_result_t m3_store_node_read_chunk_v1(
    m3_store_node_v1_t *node,
    const m3_chunk_capability_claims_v1_t *verified_claims,
    const m3_chunk_access_request_v1_t *request, uint8_t *buffer,
    size_t buffer_size, size_t *out_read);

m3_store_node_result_t m3_store_node_health_v1(
    const m3_store_node_v1_t *node, m3_store_node_health_v1_t *out_health);

/**
 * Garbage-collect this store: delete published chunks that are not in the
 * live-CID set and whose file mtime is older than now_ms - grace_ms. The live
 * set comes from the committed metadata snapshot (GC is never self-timed by
 * the store). Idempotent and interruptible between items; out_reclaimed_bytes
 * reports the released capacity.
 */
m3_store_node_result_t m3_store_node_gc_v1(
    m3_store_node_v1_t *node, const m3_chunk_cid_v1_t *live_cids,
    size_t live_count, uint64_t grace_ms, uint64_t now_ms,
    uint64_t *out_reclaimed_bytes);

#ifdef __cplusplus
}
#endif

#endif
