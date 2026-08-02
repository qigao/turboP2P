#ifndef M3_OBJECT_RESOLVER_H
#define M3_OBJECT_RESOLVER_H

#include "m3_chunk_capability.h"
#include "m3_object_download_service.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  M3_NAMESPACE_LOOKUP_OK = 0,
  M3_NAMESPACE_LOOKUP_NOT_FOUND = -1,
  M3_NAMESPACE_LOOKUP_DENIED = -2,
  M3_NAMESPACE_LOOKUP_STALE = -3,
  M3_NAMESPACE_LOOKUP_UNAVAILABLE = -4,
  M3_NAMESPACE_LOOKUP_CORRUPT = -5,
  M3_NAMESPACE_LOOKUP_INVALID_ARG = -6,
  M3_NAMESPACE_LOOKUP_RESOURCE_EXHAUSTED = -7,
} m3_namespace_lookup_result_t;

typedef struct {
  uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE];
  const uint8_t *bucket;
  size_t bucket_size;
  const uint8_t *object_key;
  size_t object_key_size;
  uint8_t require_linearizable;
} m3_namespace_lookup_request_v1_t;

/** Bytes are borrowed and valid only during the completion callback. */
typedef struct {
  const uint8_t *manifest_bytes;
  size_t manifest_size;
  uint64_t applied_index;
  uint8_t linearizable;
} m3_namespace_lookup_response_v1_t;

typedef void (*m3_namespace_lookup_complete_cb)(
    m3_namespace_lookup_result_t result,
    const m3_namespace_lookup_response_v1_t *response, void *user_data);

/**
 * Request bytes are borrowed only for start(). Async implementations copy
 * them. OK requires exactly one future or inline completion; failure requires
 * no completion.
 */
typedef m3_namespace_lookup_result_t (*m3_namespace_lookup_start_fn)(
    void *context, const m3_namespace_lookup_request_v1_t *request,
    m3_namespace_lookup_complete_cb complete_cb, void *user_data);

typedef struct {
  void *context;
  m3_namespace_lookup_start_fn start;
} m3_namespace_lookup_adapter_v1_t;

typedef enum {
  M3_OBJECT_RESOLVER_OK = 0,
  M3_OBJECT_RESOLVER_INVALID_ARG = -1,
  M3_OBJECT_RESOLVER_INVALID_STATE = -2,
  M3_OBJECT_RESOLVER_BUSY = -3,
  M3_OBJECT_RESOLVER_NOT_FOUND = -4,
  M3_OBJECT_RESOLVER_DENIED = -5,
  M3_OBJECT_RESOLVER_STALE = -6,
  M3_OBJECT_RESOLVER_UNAVAILABLE = -7,
  M3_OBJECT_RESOLVER_CORRUPT = -8,
  M3_OBJECT_RESOLVER_DOWNLOAD_FAILED = -9,
  M3_OBJECT_RESOLVER_RESOURCE_EXHAUSTED = -10,
} m3_object_resolver_result_t;

typedef void (*m3_object_resolver_complete_cb)(
    m3_object_resolver_result_t result, const uint8_t *bucket,
    size_t bucket_size, const uint8_t *object_key, size_t object_key_size,
    const m3_chunk_cid_v1_t *object_cid, const char *output_path,
    uint64_t applied_index, void *user_data);

struct m3_object_resolver_request_s;

typedef struct {
  m3_namespace_lookup_adapter_v1_t lookup;
  m3_object_download_service_v1_t *download_service;
  uint64_t max_object_bytes;
  size_t max_chunks;
  size_t max_manifest_bytes;
  size_t max_bucket_bytes;
  size_t max_object_key_bytes;
  size_t max_pending;
  size_t pending_count;
  struct m3_object_resolver_request_s *pending;
  uint8_t open;
} m3_object_resolver_v1_t;

/** The caller must zero-initialize resolver before first init. */
m3_object_resolver_result_t m3_object_resolver_init_v1(
    m3_object_resolver_v1_t *resolver,
    const m3_namespace_lookup_adapter_v1_t *lookup,
    m3_object_download_service_v1_t *download_service,
    uint64_t max_object_bytes, size_t max_chunks,
    size_t max_manifest_bytes, size_t max_bucket_bytes,
    size_t max_object_key_bytes, size_t max_pending);

m3_object_resolver_result_t m3_object_resolver_close_v1(
    m3_object_resolver_v1_t *resolver);

/** Resolve one linearizable namespace read and start the object download. */
m3_object_resolver_result_t m3_object_resolver_get_v1(
    m3_object_resolver_v1_t *resolver,
    const uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE],
    const uint8_t *bucket, size_t bucket_size,
    const uint8_t *object_key, size_t object_key_size,
    const char *output_path, m3_object_resolver_complete_cb complete_cb,
    void *user_data);

#ifdef __cplusplus
}
#endif

#endif
