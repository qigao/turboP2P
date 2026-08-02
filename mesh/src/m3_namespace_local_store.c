#include "m3_namespace_local_store.h"

#include <stdlib.h>
#include <string.h>

struct m3_namespace_local_entry_s {
  uint8_t occupied;
  uint8_t tombstoned;
  uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE];
  uint8_t *bucket;
  size_t bucket_size;
  uint8_t *object_key;
  size_t object_key_size;
  uint8_t *manifest_bytes;
  size_t manifest_size;
  uint64_t committed_index;
};

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

static int entry_matches(
    const m3_namespace_local_entry_t *entry,
    const uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE],
    const uint8_t *bucket, size_t bucket_size,
    const uint8_t *object_key, size_t object_key_size) {
  return entry && entry->occupied &&
         memcmp(entry->tenant_id, tenant_id,
                M3_CHUNK_CAPABILITY_TENANT_ID_SIZE) == 0 &&
         entry->bucket_size == bucket_size &&
         entry->object_key_size == object_key_size &&
         memcmp(entry->bucket, bucket, bucket_size) == 0 &&
         memcmp(entry->object_key, object_key, object_key_size) == 0;
}

static m3_namespace_local_entry_t *find_entry(
    m3_namespace_local_store_v1_t *store,
    const uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE],
    const uint8_t *bucket, size_t bucket_size,
    const uint8_t *object_key, size_t object_key_size) {
  if (!store || !store->entries)
    return NULL;
  for (size_t i = 0; i < store->capacity; i++) {
    if (entry_matches(&store->entries[i], tenant_id, bucket, bucket_size,
                      object_key, object_key_size)) {
      return &store->entries[i];
    }
  }
  return NULL;
}

static m3_namespace_local_entry_t *find_free_entry(
    m3_namespace_local_store_v1_t *store) {
  if (!store || !store->entries)
    return NULL;
  for (size_t i = 0; i < store->capacity; i++) {
    if (!store->entries[i].occupied)
      return &store->entries[i];
  }
  return NULL;
}

m3_namespace_local_result_t m3_namespace_local_store_init_v1(
    m3_namespace_local_store_v1_t *store, size_t capacity,
    size_t max_bucket_bytes, size_t max_object_key_bytes,
    size_t max_manifest_bytes, uint64_t max_object_bytes,
    size_t max_chunks) {
  if (!store || store->open || capacity == 0u ||
      max_bucket_bytes == 0u || max_object_key_bytes == 0u ||
      max_manifest_bytes == 0u || max_object_bytes == 0u ||
      max_chunks == 0u) {
    return M3_NAMESPACE_LOCAL_INVALID_ARG;
  }
  memset(store, 0, sizeof(*store));
  store->entries = (m3_namespace_local_entry_t *)calloc(
      capacity, sizeof(*store->entries));
  if (!store->entries)
    return M3_NAMESPACE_LOCAL_RESOURCE_EXHAUSTED;
  store->capacity = capacity;
  store->max_bucket_bytes = max_bucket_bytes;
  store->max_object_key_bytes = max_object_key_bytes;
  store->max_manifest_bytes = max_manifest_bytes;
  store->max_object_bytes = max_object_bytes;
  store->max_chunks = max_chunks;
  store->open = 1u;
  return M3_NAMESPACE_LOCAL_OK;
}

void m3_namespace_local_store_destroy_v1(
    m3_namespace_local_store_v1_t *store) {
  if (!store)
    return;
  if (store->entries) {
    for (size_t i = 0; i < store->capacity; i++) {
      free(store->entries[i].bucket);
      free(store->entries[i].object_key);
      free(store->entries[i].manifest_bytes);
    }
  }
  free(store->entries);
  memset(store, 0, sizeof(*store));
}

m3_namespace_local_result_t m3_namespace_local_store_apply_put_v1(
    m3_namespace_local_store_v1_t *store, uint64_t committed_index,
    const uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE],
    const uint8_t *bucket, size_t bucket_size,
    const uint8_t *object_key, size_t object_key_size,
    const uint8_t *manifest_bytes, size_t manifest_size) {
  m3_namespace_local_entry_t *entry;
  m3_object_manifest_owned_v1_t manifest = {0};
  uint8_t *bucket_copy = NULL;
  uint8_t *key_copy = NULL;
  uint8_t *manifest_copy = NULL;
  int is_new;

  if (!store || !store->open || !tenant_id ||
      bytes_are_zero(tenant_id, M3_CHUNK_CAPABILITY_TENANT_ID_SIZE) ||
      !key_is_valid(bucket, bucket_size, store->max_bucket_bytes) ||
      !key_is_valid(object_key, object_key_size,
                    store->max_object_key_bytes) ||
      !manifest_bytes || manifest_size == 0u ||
      manifest_size > store->max_manifest_bytes || committed_index == 0u) {
    return M3_NAMESPACE_LOCAL_INVALID_ARG;
  }
  if (committed_index <= store->applied_index)
    return M3_NAMESPACE_LOCAL_OUT_OF_ORDER;
  if (m3_object_manifest_decode_v1(
          manifest_bytes, manifest_size, store->max_object_bytes,
          store->max_chunks, &manifest) != M3_OBJECT_MANIFEST_OK) {
    return M3_NAMESPACE_LOCAL_CORRUPT;
  }
  m3_object_manifest_owned_destroy_v1(&manifest);

  entry = find_entry(store, tenant_id, bucket, bucket_size, object_key,
                     object_key_size);
  is_new = entry == NULL;
  if (is_new) {
    entry = find_free_entry(store);
    if (!entry)
      return M3_NAMESPACE_LOCAL_RESOURCE_EXHAUSTED;
    bucket_copy = (uint8_t *)malloc(bucket_size);
    key_copy = (uint8_t *)malloc(object_key_size);
    if (!bucket_copy || !key_copy)
      goto exhausted;
    memcpy(bucket_copy, bucket, bucket_size);
    memcpy(key_copy, object_key, object_key_size);
  }
  manifest_copy = (uint8_t *)malloc(manifest_size);
  if (!manifest_copy)
    goto exhausted;
  memcpy(manifest_copy, manifest_bytes, manifest_size);

  if (is_new) {
    memcpy(entry->tenant_id, tenant_id, sizeof(entry->tenant_id));
    entry->bucket = bucket_copy;
    entry->bucket_size = bucket_size;
    entry->object_key = key_copy;
    entry->object_key_size = object_key_size;
    entry->occupied = 1u;
    store->count++;
  }
  free(entry->manifest_bytes);
  entry->manifest_bytes = manifest_copy;
  entry->manifest_size = manifest_size;
  entry->committed_index = committed_index;
  entry->tombstoned = 0u;
  store->applied_index = committed_index;
  return M3_NAMESPACE_LOCAL_OK;

exhausted:
  free(bucket_copy);
  free(key_copy);
  free(manifest_copy);
  return M3_NAMESPACE_LOCAL_RESOURCE_EXHAUSTED;
}

m3_namespace_local_result_t m3_namespace_local_store_apply_tombstone_v1(
    m3_namespace_local_store_v1_t *store, uint64_t committed_index,
    const uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE],
    const uint8_t *bucket, size_t bucket_size,
    const uint8_t *object_key, size_t object_key_size) {
  m3_namespace_local_entry_t *entry;

  if (!store || !store->open || !tenant_id ||
      bytes_are_zero(tenant_id, M3_CHUNK_CAPABILITY_TENANT_ID_SIZE) ||
      !key_is_valid(bucket, bucket_size, store->max_bucket_bytes) ||
      !key_is_valid(object_key, object_key_size,
                    store->max_object_key_bytes) ||
      committed_index == 0u) {
    return M3_NAMESPACE_LOCAL_INVALID_ARG;
  }
  if (committed_index <= store->applied_index)
    return M3_NAMESPACE_LOCAL_OUT_OF_ORDER;

  entry = find_entry(store, tenant_id, bucket, bucket_size, object_key,
                     object_key_size);
  if (entry) {
    free(entry->manifest_bytes);
    entry->manifest_bytes = NULL;
    entry->manifest_size = 0u;
    entry->committed_index = committed_index;
    entry->tombstoned = 1u;
  }
  store->applied_index = committed_index;
  return M3_NAMESPACE_LOCAL_OK;
}

static m3_namespace_lookup_result_t local_lookup_start(
    void *context, const m3_namespace_lookup_request_v1_t *request,
    m3_namespace_lookup_complete_cb complete_cb, void *user_data) {
  m3_namespace_local_store_v1_t *store =
      (m3_namespace_local_store_v1_t *)context;
  m3_namespace_local_entry_t *entry;
  m3_namespace_lookup_response_v1_t response = {0};

  if (!store || !store->open || !request || !complete_cb ||
      !request->require_linearizable || store->applied_index == 0u ||
      bytes_are_zero(request->tenant_id,
                     M3_CHUNK_CAPABILITY_TENANT_ID_SIZE) ||
      !key_is_valid(request->bucket, request->bucket_size,
                    store->max_bucket_bytes) ||
      !key_is_valid(request->object_key, request->object_key_size,
                    store->max_object_key_bytes)) {
    return M3_NAMESPACE_LOOKUP_INVALID_ARG;
  }
  entry = find_entry(store, request->tenant_id, request->bucket,
                     request->bucket_size, request->object_key,
                     request->object_key_size);
  if (!entry || entry->tombstoned) {
    complete_cb(M3_NAMESPACE_LOOKUP_NOT_FOUND, NULL, user_data);
    return M3_NAMESPACE_LOOKUP_OK;
  }
  response.manifest_bytes = entry->manifest_bytes;
  response.manifest_size = entry->manifest_size;
  response.applied_index = store->applied_index;
  response.linearizable = 1u;
  complete_cb(M3_NAMESPACE_LOOKUP_OK, &response, user_data);
  return M3_NAMESPACE_LOOKUP_OK;
}

m3_namespace_lookup_adapter_v1_t
m3_namespace_local_store_adapter_v1(m3_namespace_local_store_v1_t *store) {
  m3_namespace_lookup_adapter_v1_t adapter = {0};

  if (store && store->open) {
    adapter.context = store;
    adapter.start = local_lookup_start;
  }
  return adapter;
}
