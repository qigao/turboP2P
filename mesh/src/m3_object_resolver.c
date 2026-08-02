#include "m3_object_resolver.h"

#include <stdlib.h>
#include <string.h>

typedef struct m3_object_resolver_request_s {
  m3_object_resolver_v1_t *resolver;
  uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE];
  uint8_t *bucket;
  size_t bucket_size;
  uint8_t *object_key;
  size_t object_key_size;
  char *output_path;
  uint64_t applied_index;
  m3_object_resolver_complete_cb complete_cb;
  void *user_data;
  struct m3_object_resolver_request_s *next;
} m3_object_resolver_request_t;

static int bytes_are_zero(const uint8_t *bytes, size_t size) {
  uint8_t aggregate = 0u;

  if (!bytes)
    return 0;
  for (size_t i = 0; i < size; i++)
    aggregate |= bytes[i];
  return aggregate == 0u;
}

static int key_is_valid(const uint8_t *bytes, size_t size,
                        size_t maximum) {
  return bytes && size > 0u && size <= maximum &&
         memchr(bytes, 0, size) == NULL;
}

static m3_object_resolver_request_t *find_output(
    const m3_object_resolver_v1_t *resolver, const char *output_path) {
  m3_object_resolver_request_t *request = resolver ? resolver->pending : NULL;

  while (request) {
    if (strcmp(request->output_path, output_path) == 0)
      return request;
    request = request->next;
  }
  return NULL;
}

static void unlink_pending(m3_object_resolver_request_t *request) {
  m3_object_resolver_request_t **current;
  m3_object_resolver_v1_t *resolver;

  if (!request || !request->resolver)
    return;
  resolver = request->resolver;
  current = (m3_object_resolver_request_t **)&resolver->pending;
  while (*current) {
    if (*current == request) {
      *current = request->next;
      if (resolver->pending_count > 0u)
        resolver->pending_count--;
      return;
    }
    current = &(*current)->next;
  }
}

static void finish_request(m3_object_resolver_request_t *request,
                           m3_object_resolver_result_t result,
                           const m3_chunk_cid_v1_t *object_cid) {
  m3_object_resolver_complete_cb complete_cb;
  void *user_data;

  if (!request)
    return;
  unlink_pending(request);
  complete_cb = request->complete_cb;
  user_data = request->user_data;
  complete_cb(result, request->bucket, request->bucket_size,
              request->object_key, request->object_key_size, object_cid,
              request->output_path, request->applied_index, user_data);
  free(request->bucket);
  free(request->object_key);
  free(request->output_path);
  free(request);
}

static m3_object_resolver_result_t map_lookup_result(
    m3_namespace_lookup_result_t result) {
  switch (result) {
  case M3_NAMESPACE_LOOKUP_OK:
    return M3_OBJECT_RESOLVER_OK;
  case M3_NAMESPACE_LOOKUP_NOT_FOUND:
    return M3_OBJECT_RESOLVER_NOT_FOUND;
  case M3_NAMESPACE_LOOKUP_DENIED:
    return M3_OBJECT_RESOLVER_DENIED;
  case M3_NAMESPACE_LOOKUP_STALE:
    return M3_OBJECT_RESOLVER_STALE;
  case M3_NAMESPACE_LOOKUP_CORRUPT:
    return M3_OBJECT_RESOLVER_CORRUPT;
  case M3_NAMESPACE_LOOKUP_RESOURCE_EXHAUSTED:
    return M3_OBJECT_RESOLVER_RESOURCE_EXHAUSTED;
  case M3_NAMESPACE_LOOKUP_INVALID_ARG:
  case M3_NAMESPACE_LOOKUP_UNAVAILABLE:
  default:
    return M3_OBJECT_RESOLVER_UNAVAILABLE;
  }
}

static m3_object_resolver_result_t map_download_result(
    m3_object_download_result_t result) {
  switch (result) {
  case M3_OBJECT_DOWNLOAD_OK:
    return M3_OBJECT_RESOLVER_OK;
  case M3_OBJECT_DOWNLOAD_OUTPUT_EXISTS:
  case M3_OBJECT_DOWNLOAD_BUSY:
    return M3_OBJECT_RESOLVER_BUSY;
  case M3_OBJECT_DOWNLOAD_RESOURCE_EXHAUSTED:
    return M3_OBJECT_RESOLVER_RESOURCE_EXHAUSTED;
  case M3_OBJECT_DOWNLOAD_INTEGRITY:
    return M3_OBJECT_RESOLVER_CORRUPT;
  default:
    return M3_OBJECT_RESOLVER_DOWNLOAD_FAILED;
  }
}

static void on_object_downloaded(m3_object_download_result_t result,
                                 const m3_chunk_cid_v1_t *object_cid,
                                 const char *output_path, void *user_data) {
  m3_object_resolver_request_t *request =
      (m3_object_resolver_request_t *)user_data;

  (void)output_path;
  if (request)
    finish_request(request, map_download_result(result), object_cid);
}

static void on_namespace_lookup(
    m3_namespace_lookup_result_t lookup_result,
    const m3_namespace_lookup_response_v1_t *response, void *user_data) {
  m3_object_resolver_request_t *request =
      (m3_object_resolver_request_t *)user_data;
  m3_object_manifest_owned_v1_t manifest = {0};
  m3_object_download_result_t download_result;
  m3_object_resolver_result_t result;

  if (!request)
    return;
  result = map_lookup_result(lookup_result);
  if (result != M3_OBJECT_RESOLVER_OK) {
    finish_request(request, result, NULL);
    return;
  }
  if (!response || !response->linearizable ||
      response->applied_index == 0u || !response->manifest_bytes ||
      response->manifest_size == 0u ||
      response->manifest_size > request->resolver->max_manifest_bytes) {
    finish_request(request, M3_OBJECT_RESOLVER_STALE, NULL);
    return;
  }
  request->applied_index = response->applied_index;
  if (m3_object_manifest_decode_v1(
          response->manifest_bytes, response->manifest_size,
          request->resolver->max_object_bytes,
          request->resolver->max_chunks,
          &manifest) != M3_OBJECT_MANIFEST_OK) {
    finish_request(request, M3_OBJECT_RESOLVER_CORRUPT, NULL);
    return;
  }
  download_result = m3_object_download_service_start_v1(
      request->resolver->download_service, &manifest.manifest,
      request->output_path, on_object_downloaded, request);
  m3_object_manifest_owned_destroy_v1(&manifest);
  if (download_result != M3_OBJECT_DOWNLOAD_OK)
    finish_request(request, map_download_result(download_result), NULL);
}

m3_object_resolver_result_t m3_object_resolver_init_v1(
    m3_object_resolver_v1_t *resolver,
    const m3_namespace_lookup_adapter_v1_t *lookup,
    m3_object_download_service_v1_t *download_service,
    uint64_t max_object_bytes, size_t max_chunks,
    size_t max_manifest_bytes, size_t max_bucket_bytes,
    size_t max_object_key_bytes, size_t max_pending) {
  if (!resolver || resolver->open || !lookup || !lookup->start ||
      !download_service || !download_service->open ||
      max_object_bytes == 0u || max_chunks == 0u ||
      max_manifest_bytes == 0u || max_bucket_bytes == 0u ||
      max_object_key_bytes == 0u || max_pending == 0u) {
    return M3_OBJECT_RESOLVER_INVALID_ARG;
  }
  memset(resolver, 0, sizeof(*resolver));
  resolver->lookup = *lookup;
  resolver->download_service = download_service;
  resolver->max_object_bytes = max_object_bytes;
  resolver->max_chunks = max_chunks;
  resolver->max_manifest_bytes = max_manifest_bytes;
  resolver->max_bucket_bytes = max_bucket_bytes;
  resolver->max_object_key_bytes = max_object_key_bytes;
  resolver->max_pending = max_pending;
  resolver->open = 1u;
  return M3_OBJECT_RESOLVER_OK;
}

m3_object_resolver_result_t m3_object_resolver_close_v1(
    m3_object_resolver_v1_t *resolver) {
  if (!resolver || !resolver->open)
    return M3_OBJECT_RESOLVER_INVALID_STATE;
  if (resolver->pending_count != 0u || resolver->pending)
    return M3_OBJECT_RESOLVER_BUSY;
  memset(resolver, 0, sizeof(*resolver));
  return M3_OBJECT_RESOLVER_OK;
}

m3_object_resolver_result_t m3_object_resolver_get_v1(
    m3_object_resolver_v1_t *resolver,
    const uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE],
    const uint8_t *bucket, size_t bucket_size,
    const uint8_t *object_key, size_t object_key_size,
    const char *output_path, m3_object_resolver_complete_cb complete_cb,
    void *user_data) {
  m3_object_resolver_request_t *request;
  m3_namespace_lookup_request_v1_t lookup_request = {0};
  m3_namespace_lookup_result_t lookup_result;
  size_t output_size;

  if (!resolver || !resolver->open || !tenant_id ||
      bytes_are_zero(tenant_id, M3_CHUNK_CAPABILITY_TENANT_ID_SIZE) ||
      !key_is_valid(bucket, bucket_size, resolver->max_bucket_bytes) ||
      !key_is_valid(object_key, object_key_size,
                    resolver->max_object_key_bytes) ||
      !output_path || output_path[0] == '\0' ||
      strlen(output_path) >= TURBO_FS_MAX_PATH ||
      !turbo_fs_path_is_absolute(output_path) || !complete_cb) {
    return M3_OBJECT_RESOLVER_INVALID_ARG;
  }
  if (find_output(resolver, output_path))
    return M3_OBJECT_RESOLVER_BUSY;
  if (resolver->pending_count >= resolver->max_pending)
    return M3_OBJECT_RESOLVER_RESOURCE_EXHAUSTED;
  output_size = strlen(output_path);
  request = (m3_object_resolver_request_t *)calloc(1, sizeof(*request));
  if (!request)
    return M3_OBJECT_RESOLVER_RESOURCE_EXHAUSTED;
  request->bucket = (uint8_t *)malloc(bucket_size);
  request->object_key = (uint8_t *)malloc(object_key_size);
  request->output_path = (char *)malloc(output_size + 1u);
  if (!request->bucket || !request->object_key || !request->output_path) {
    free(request->bucket);
    free(request->object_key);
    free(request->output_path);
    free(request);
    return M3_OBJECT_RESOLVER_RESOURCE_EXHAUSTED;
  }
  request->resolver = resolver;
  memcpy(request->tenant_id, tenant_id, sizeof(request->tenant_id));
  memcpy(request->bucket, bucket, bucket_size);
  request->bucket_size = bucket_size;
  memcpy(request->object_key, object_key, object_key_size);
  request->object_key_size = object_key_size;
  memcpy(request->output_path, output_path, output_size + 1u);
  request->complete_cb = complete_cb;
  request->user_data = user_data;
  request->next = resolver->pending;
  resolver->pending = request;
  resolver->pending_count++;

  memcpy(lookup_request.tenant_id, request->tenant_id,
         sizeof(lookup_request.tenant_id));
  lookup_request.bucket = request->bucket;
  lookup_request.bucket_size = request->bucket_size;
  lookup_request.object_key = request->object_key;
  lookup_request.object_key_size = request->object_key_size;
  lookup_request.require_linearizable = 1u;
  lookup_result = resolver->lookup.start(
      resolver->lookup.context, &lookup_request, on_namespace_lookup,
      request);
  if (lookup_result != M3_NAMESPACE_LOOKUP_OK) {
    m3_object_resolver_result_t result = map_lookup_result(lookup_result);
    unlink_pending(request);
    free(request->bucket);
    free(request->object_key);
    free(request->output_path);
    free(request);
    return result;
  }
  return M3_OBJECT_RESOLVER_OK;
}
