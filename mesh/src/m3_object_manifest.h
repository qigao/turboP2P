#ifndef M3_OBJECT_MANIFEST_H
#define M3_OBJECT_MANIFEST_H

#include "m3_chunk_store.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define M3_OBJECT_MANIFEST_VERSION 1u
#define M3_OBJECT_MANIFEST_VERSION_2 2u

#define M3_OBJECT_MANIFEST_STORE_NODE_ID_SIZE 32u
#define M3_OBJECT_MANIFEST_RECEIPT_DIGEST_SIZE M3_CHUNK_CID_DIGEST_SIZE

typedef enum {
  M3_OBJECT_MANIFEST_OK = 0,
  M3_OBJECT_MANIFEST_INVALID_ARG = -1,
  M3_OBJECT_MANIFEST_CORRUPT = -2,
  M3_OBJECT_MANIFEST_INTEGRITY = -3,
  M3_OBJECT_MANIFEST_RESOURCE_EXHAUSTED = -4,
  M3_OBJECT_MANIFEST_CRYPTO_FAILED = -5,
} m3_object_manifest_result_t;

/** Immutable manifest view. The caller owns chunks. */
typedef struct {
  uint32_t version;
  m3_chunk_cid_v1_t object_cid;
  const m3_chunk_cid_v1_t *chunks;
  size_t chunk_count;
} m3_object_manifest_v1_t;

/** Owned result produced by the canonical decoder. */
typedef struct {
  m3_object_manifest_v1_t manifest;
  m3_chunk_cid_v1_t *owned_chunks;
} m3_object_manifest_owned_v1_t;

/** One durable-receipt reference for one chunk of a V2 manifest. */
typedef struct {
  uint32_t chunk_index;
  uint8_t store_node_id[M3_OBJECT_MANIFEST_STORE_NODE_ID_SIZE];
  uint8_t receipt_digest[M3_OBJECT_MANIFEST_RECEIPT_DIGEST_SIZE];
} m3_object_manifest_placement_v1_t;

/** Immutable V2 manifest view. The caller owns chunks and placements. */
typedef struct {
  uint32_t version;
  m3_chunk_cid_v1_t object_cid;
  const m3_chunk_cid_v1_t *chunks;
  size_t chunk_count;
  const m3_object_manifest_placement_v1_t *placements;
  size_t placement_count;
} m3_object_manifest_v2_t;

/** Owned result produced by the canonical V2 decoder. */
typedef struct {
  m3_object_manifest_v2_t manifest;
  m3_chunk_cid_v1_t *owned_chunks;
  m3_object_manifest_placement_v1_t *owned_placements;
} m3_object_manifest_owned_v2_t;

/** Repair debt for one under-replicated chunk. */
typedef struct {
  size_t chunk_index;
  size_t receipt_count;
  size_t missing;
} m3_object_manifest_placement_debt_v1_t;

/** Validate identity, bounds and exact sum(chunk sizes) == object size. */
m3_object_manifest_result_t m3_object_manifest_validate_v1(
    const m3_object_manifest_v1_t *manifest, uint64_t max_object_bytes,
    size_t max_chunks);

/**
 * Encode a canonical big-endian V1 manifest with a SHA-256 envelope digest.
 * The returned bytes are owned and released with
 * m3_object_manifest_bytes_free_v1().
 */
m3_object_manifest_result_t m3_object_manifest_encode_v1(
    const m3_object_manifest_v1_t *manifest, uint64_t max_object_bytes,
    size_t max_chunks, uint8_t **out_bytes, size_t *out_size);

/** Decode, validate and own a canonical V1 manifest. */
m3_object_manifest_result_t m3_object_manifest_decode_v1(
    const uint8_t *bytes, size_t size, uint64_t max_object_bytes,
    size_t max_chunks, m3_object_manifest_owned_v1_t *out_manifest);

void m3_object_manifest_owned_destroy_v1(
    m3_object_manifest_owned_v1_t *manifest);
void m3_object_manifest_bytes_free_v1(uint8_t *bytes);

/**
 * Structurally validate a V2 manifest: object identity, chunk bounds, exact
 * sum, placement index range, non-zero store/digest values and no duplicate
 * (chunk_index, store_node_id) pair. Placement ordering is a serialization
 * concern enforced by the encoder/decoder, not by this predicate.
 */
m3_object_manifest_result_t m3_object_manifest_validate_v2(
    const m3_object_manifest_v2_t *manifest, uint64_t max_object_bytes,
    size_t max_chunks, size_t max_placements);

/**
 * Encode a canonical big-endian V2 manifest with a SHA-256 envelope digest
 * that covers the placement segment. Placements are canonically sorted by
 * (chunk_index, store_node_id) before writing. The returned bytes are owned
 * and released with m3_object_manifest_bytes_free_v2().
 */
m3_object_manifest_result_t m3_object_manifest_encode_v2(
    const m3_object_manifest_v2_t *manifest, uint64_t max_object_bytes,
    size_t max_chunks, size_t max_placements, uint8_t **out_bytes,
    size_t *out_size);

/**
 * Decode and own a canonical manifest. V1 bytes decode to a V2 view with an
 * empty placement segment (repair debt), preserving read compatibility.
 */
m3_object_manifest_result_t m3_object_manifest_decode_v2(
    const uint8_t *bytes, size_t size, uint64_t max_object_bytes,
    size_t max_chunks, size_t max_placements,
    m3_object_manifest_owned_v2_t *out_manifest);

void m3_object_manifest_owned_destroy_v2(
    m3_object_manifest_owned_v2_t *manifest);
void m3_object_manifest_bytes_free_v2(uint8_t *bytes);

/**
 * Evaluate per-chunk replica debt against the placement policy. Every chunk
 * with receipt_count < target_replicas emits a debt entry with
 * missing = target_replicas - receipt_count (this includes chunks below
 * min_durable_replicas, which are degraded and repaired to target). A chunk
 * above target_replicas fails with M3_OBJECT_MANIFEST_INVALID_ARG.
 */
m3_object_manifest_result_t m3_object_manifest_placement_policy_v2(
    const m3_object_manifest_v2_t *manifest, size_t min_durable_replicas,
    size_t target_replicas, m3_object_manifest_placement_debt_v1_t *out_debt,
    size_t debt_capacity, size_t *out_debt_count);

#ifdef __cplusplus
}
#endif

#endif
