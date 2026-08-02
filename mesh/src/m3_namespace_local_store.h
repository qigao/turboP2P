#ifndef M3_NAMESPACE_LOCAL_STORE_H
#define M3_NAMESPACE_LOCAL_STORE_H

#include "m3_object_resolver.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  M3_NAMESPACE_LOCAL_OK = 0,
  M3_NAMESPACE_LOCAL_INVALID_ARG = -1,
  M3_NAMESPACE_LOCAL_INVALID_STATE = -2,
  M3_NAMESPACE_LOCAL_OUT_OF_ORDER = -3,
  M3_NAMESPACE_LOCAL_RESOURCE_EXHAUSTED = -4,
  M3_NAMESPACE_LOCAL_CORRUPT = -5,
} m3_namespace_local_result_t;

typedef struct m3_namespace_local_entry_s
    m3_namespace_local_entry_t;

/**
 * Bounded single-owner namespace for local/stage profiles only.
 *
 * This is not a distributed metadata implementation and must not be used as a
 * substitute for the Raft/ReadIndex adapter in a multi-node deployment.
 */
typedef struct {
  m3_namespace_local_entry_t *entries;
  size_t capacity;
  size_t count;
  size_t max_bucket_bytes;
  size_t max_object_key_bytes;
  size_t max_manifest_bytes;
  uint64_t max_object_bytes;
  size_t max_chunks;
  uint64_t applied_index;
  uint8_t open;
} m3_namespace_local_store_v1_t;

/** The caller must zero-initialize store before first init. */
m3_namespace_local_result_t m3_namespace_local_store_init_v1(
    m3_namespace_local_store_v1_t *store, size_t capacity,
    size_t max_bucket_bytes, size_t max_object_key_bytes,
    size_t max_manifest_bytes, uint64_t max_object_bytes,
    size_t max_chunks);

void m3_namespace_local_store_destroy_v1(
    m3_namespace_local_store_v1_t *store);

/**
 * Apply one already-committed object version. committed_index must advance
 * monotonically. Validation and allocation complete before visible mutation.
 */
m3_namespace_local_result_t m3_namespace_local_store_apply_put_v1(
    m3_namespace_local_store_v1_t *store, uint64_t committed_index,
    const uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE],
    const uint8_t *bucket, size_t bucket_size,
    const uint8_t *object_key, size_t object_key_size,
    const uint8_t *manifest_bytes, size_t manifest_size);

/** Return an inline, single-owner linearizable lookup adapter. */
m3_namespace_lookup_adapter_v1_t
m3_namespace_local_store_adapter_v1(m3_namespace_local_store_v1_t *store);

#ifdef __cplusplus
}
#endif

#endif
