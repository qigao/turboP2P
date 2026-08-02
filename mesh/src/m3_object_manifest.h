#ifndef M3_OBJECT_MANIFEST_H
#define M3_OBJECT_MANIFEST_H

#include "m3_chunk_store.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define M3_OBJECT_MANIFEST_VERSION 1u

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

#ifdef __cplusplus
}
#endif

#endif
