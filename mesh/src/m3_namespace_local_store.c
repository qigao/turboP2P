#include "m3_namespace_local_store.h"

/* Placement records per chunk are bounded by the data plane replica cap. */
#define M3_NAMESPACE_LOCAL_MAX_PLACEMENTS_PER_CHUNK 8u

#include <turbo_fs.h>

#include <stdio.h>
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

/*
 * On-disk V1 snapshot layout (big-endian). A snapshot is owned by this module;
 * nothing outside the store may read it. The 64-byte header is followed by one
 * variable-length record per applied entry, written in entry-array order so a
 * persist/load round trip preserves list order.
 *
 * Header:
 *   [0..8)    magic "M3NSLOC1"
 *   [8..12)   version (1)
 *   [12..16)  reserved (0)
 *   [16..24)  applied_index
 *   [24..32)  entry_count
 *   [32..40)  max_bucket_bytes
 *   [40..48)  max_object_key_bytes
 *   [48..56)  max_manifest_bytes
 *   [56..64)  checksum (FNV-1a 64 over the header with the checksum field
 *             zeroed plus every record)
 *
 * Record:
 *   [0..32)   tenant_id
 *   [32..36)  bucket_size
 *   [36..40)  object_key_size
 *   [40..44)  manifest_size (0 for tombstoned entries)
 *   [44]      tombstoned (0/1)
 *   [45..48)  reserved (0)
 *   [48..)    bucket bytes, object_key bytes, manifest bytes
 */
enum {
  M3_NAMESPACE_LOCAL_VERSION = 1u,
  M3_NAMESPACE_LOCAL_HEADER_SIZE = 64,
  M3_NAMESPACE_LOCAL_OFFSET_VERSION = 8,
  M3_NAMESPACE_LOCAL_OFFSET_RESERVED = 12,
  M3_NAMESPACE_LOCAL_OFFSET_APPLIED_INDEX = 16,
  M3_NAMESPACE_LOCAL_OFFSET_ENTRY_COUNT = 24,
  M3_NAMESPACE_LOCAL_OFFSET_MAX_BUCKET_BYTES = 32,
  M3_NAMESPACE_LOCAL_OFFSET_MAX_OBJECT_KEY_BYTES = 40,
  M3_NAMESPACE_LOCAL_OFFSET_MAX_MANIFEST_BYTES = 48,
  M3_NAMESPACE_LOCAL_OFFSET_CHECKSUM = 56,
  M3_NAMESPACE_LOCAL_RECORD_OFFSET_BUCKET = 32,
  M3_NAMESPACE_LOCAL_RECORD_OFFSET_OBJECT_KEY = 36,
  M3_NAMESPACE_LOCAL_RECORD_OFFSET_MANIFEST = 40,
  M3_NAMESPACE_LOCAL_RECORD_OFFSET_TOMBSTONED = 44,
  M3_NAMESPACE_LOCAL_RECORD_OFFSET_RESERVED = 45,
  M3_NAMESPACE_LOCAL_RECORD_PAYLOAD_OFFSET = 48,
  M3_NAMESPACE_LOCAL_FILE_MODE = 0600,
};

static const char M3_NAMESPACE_LOCAL_STATE_FILE[] = "namespace.bin";
static const char M3_NAMESPACE_LOCAL_TEMP_FILE[] = "namespace.bin.tmp";
static const uint8_t m3_namespace_local_magic[8] = {'M', '3', 'N', 'S', 'L', 'O', 'C', '1'};

static int bytes_are_zero(const uint8_t *bytes, size_t size) {
  uint8_t aggregate = 0u;

  if (!bytes)
    return 0;
  for (size_t i = 0; i < size; i++)
    aggregate |= bytes[i];
  return aggregate == 0u;
}

static int key_is_valid(const uint8_t *bytes, size_t size, size_t maximum) {
  return bytes && size > 0u && size <= maximum && memchr(bytes, 0, size) == NULL;
}

static int entry_matches(const m3_namespace_local_entry_t *entry,
                         const uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE],
                         const uint8_t *bucket, size_t bucket_size, const uint8_t *object_key,
                         size_t object_key_size) {
  return entry && entry->occupied &&
         memcmp(entry->tenant_id, tenant_id, M3_CHUNK_CAPABILITY_TENANT_ID_SIZE) == 0 &&
         entry->bucket_size == bucket_size && entry->object_key_size == object_key_size &&
         memcmp(entry->bucket, bucket, bucket_size) == 0 &&
         memcmp(entry->object_key, object_key, object_key_size) == 0;
}

static m3_namespace_local_entry_t *
find_entry(m3_namespace_local_store_v1_t *store,
           const uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE], const uint8_t *bucket,
           size_t bucket_size, const uint8_t *object_key, size_t object_key_size) {
  if (!store || !store->entries)
    return NULL;
  for (size_t i = 0; i < store->capacity; i++) {
    if (entry_matches(&store->entries[i], tenant_id, bucket, bucket_size, object_key,
                      object_key_size)) {
      return &store->entries[i];
    }
  }
  return NULL;
}

static m3_namespace_local_entry_t *find_free_entry(m3_namespace_local_store_v1_t *store) {
  if (!store || !store->entries)
    return NULL;
  for (size_t i = 0; i < store->capacity; i++) {
    if (!store->entries[i].occupied)
      return &store->entries[i];
  }
  return NULL;
}

static void write_u32_be(uint8_t *output, uint32_t value) {
  output[0] = (uint8_t)(value >> 24u);
  output[1] = (uint8_t)(value >> 16u);
  output[2] = (uint8_t)(value >> 8u);
  output[3] = (uint8_t)value;
}

static void write_u64_be(uint8_t *output, uint64_t value) {
  write_u32_be(output, (uint32_t)(value >> 32u));
  write_u32_be(output + 4u, (uint32_t)value);
}

static uint32_t read_u32_be(const uint8_t *input) {
  return ((uint32_t)input[0] << 24u) | ((uint32_t)input[1] << 16u) | ((uint32_t)input[2] << 8u) |
         (uint32_t)input[3];
}

static uint64_t read_u64_be(const uint8_t *input) {
  return ((uint64_t)read_u32_be(input) << 32u) | (uint64_t)read_u32_be(input + 4u);
}

static uint64_t fnv1a_bytes(const uint8_t *bytes, size_t size, uint64_t hash) {
  for (size_t i = 0u; i < size; i++) {
    hash ^= (uint64_t)bytes[i];
    hash *= UINT64_C(1099511628211);
  }
  return hash;
}

static int u64_add_checked(uint64_t a, uint64_t b, uint64_t *out) {
  if (a > UINT64_MAX - b)
    return -1;
  *out = a + b;
  return 0;
}

static int u64_mul_add_checked(uint64_t a, uint64_t b, uint64_t add, uint64_t *out) {
  uint64_t product;

  if (a != 0u && b > UINT64_MAX / a)
    return -1;
  product = a * b;
  if (product > UINT64_MAX - add)
    return -1;
  *out = product + add;
  return 0;
}

static int join_path(const char *root, const char *name, char *out, size_t out_size) {
  size_t root_size;
  int needs_separator;
  int written;

  if (!root || !name || root[0] == '\0' || name[0] == '\0')
    return -1;
  root_size = strlen(root);
  needs_separator = root_size > 0u && root[root_size - 1u] != '/' && root[root_size - 1u] != '\\';
  written = snprintf(out, out_size, "%s%s%s", root, needs_separator ? "/" : "", name);
  return written >= 0 && (size_t)written < out_size ? 0 : -1;
}

static int read_exact(turbo_file_t file, uint8_t *bytes, size_t size) {
  size_t offset = 0u;

  while (offset < size) {
    int read_size = turbo_fs_read(file, (char *)bytes + offset, size - offset);
    if (read_size <= 0)
      return -1;
    offset += (size_t)read_size;
  }
  return 0;
}

static m3_namespace_local_result_t write_all(turbo_file_t file, const uint8_t *bytes, size_t size) {
  size_t written = 0u;

  while (written < size) {
    int result = turbo_fs_write(file, (const char *)bytes + written, size - written);
    if (result <= 0)
      return M3_NAMESPACE_LOCAL_INVALID_STATE;
    written += (size_t)result;
  }
  return M3_NAMESPACE_LOCAL_OK;
}

/*
 * The V1 record encodes lengths as u32, so entries whose component sizes
 * exceed UINT32_MAX cannot be persisted. Such sizes cannot be produced through
 * apply_put with realistic limits, but the store bounds are caller-controlled.
 */
static int record_size(const m3_namespace_local_entry_t *entry, uint64_t *out_size) {
  uint64_t size;

  if (entry->bucket_size > UINT32_MAX || entry->object_key_size > UINT32_MAX ||
      entry->manifest_size > UINT32_MAX)
    return -1;
  size = M3_NAMESPACE_LOCAL_RECORD_PAYLOAD_OFFSET;
  size += (uint64_t)entry->bucket_size;
  size += (uint64_t)entry->object_key_size;
  size += (uint64_t)entry->manifest_size;
  *out_size = size;
  return 0;
}

static void clear_loaded_entries(m3_namespace_local_store_v1_t *store, size_t count) {
  for (size_t i = 0u; i < count; i++) {
    m3_namespace_local_entry_t *entry = &store->entries[i];
    free(entry->bucket);
    free(entry->object_key);
    free(entry->manifest_bytes);
    memset(entry, 0, sizeof(*entry));
  }
  store->count = 0u;
}

m3_namespace_local_result_t
m3_namespace_local_store_init_v1(m3_namespace_local_store_v1_t *store, size_t capacity,
                                 size_t max_bucket_bytes, size_t max_object_key_bytes,
                                 size_t max_manifest_bytes, uint64_t max_object_bytes,
                                 size_t max_chunks) {
  if (!store || store->open || capacity == 0u || max_bucket_bytes == 0u ||
      max_object_key_bytes == 0u || max_manifest_bytes == 0u || max_object_bytes == 0u ||
      max_chunks == 0u) {
    return M3_NAMESPACE_LOCAL_INVALID_ARG;
  }
  memset(store, 0, sizeof(*store));
  store->entries = (m3_namespace_local_entry_t *)calloc(capacity, sizeof(*store->entries));
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

void m3_namespace_local_store_destroy_v1(m3_namespace_local_store_v1_t *store) {
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
    const uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE], const uint8_t *bucket,
    size_t bucket_size, const uint8_t *object_key, size_t object_key_size,
    const uint8_t *manifest_bytes, size_t manifest_size) {
  m3_namespace_local_entry_t *entry;
  m3_object_manifest_owned_v2_t manifest = {0};
  uint8_t *bucket_copy = NULL;
  uint8_t *key_copy = NULL;
  uint8_t *manifest_copy = NULL;
  int is_new;

  if (!store || !store->open || !tenant_id ||
      bytes_are_zero(tenant_id, M3_CHUNK_CAPABILITY_TENANT_ID_SIZE) ||
      !key_is_valid(bucket, bucket_size, store->max_bucket_bytes) ||
      !key_is_valid(object_key, object_key_size, store->max_object_key_bytes) || !manifest_bytes ||
      manifest_size == 0u || manifest_size > store->max_manifest_bytes || committed_index == 0u) {
    return M3_NAMESPACE_LOCAL_INVALID_ARG;
  }
  if (committed_index <= store->applied_index)
    return M3_NAMESPACE_LOCAL_OUT_OF_ORDER;
  if (m3_object_manifest_decode_v2(
          manifest_bytes, manifest_size, store->max_object_bytes,
          store->max_chunks,
          store->max_chunks * M3_NAMESPACE_LOCAL_MAX_PLACEMENTS_PER_CHUNK,
          &manifest) != M3_OBJECT_MANIFEST_OK) {
    return M3_NAMESPACE_LOCAL_CORRUPT;
  }
  m3_object_manifest_owned_destroy_v2(&manifest);

  entry = find_entry(store, tenant_id, bucket, bucket_size, object_key, object_key_size);
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

m3_namespace_local_result_t m3_namespace_local_store_apply_update_placement_v1(
    m3_namespace_local_store_v1_t *store, uint64_t committed_index,
    const uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE],
    const uint8_t *bucket, size_t bucket_size, const uint8_t *object_key,
    size_t object_key_size, const uint8_t *manifest_bytes, size_t manifest_size) {
  m3_object_manifest_owned_v2_t incoming = {0};
  m3_object_manifest_owned_v2_t stored = {0};
  m3_namespace_local_entry_t *entry;
  uint8_t *manifest_copy = NULL;

  if (!store || !store->open || !tenant_id ||
      bytes_are_zero(tenant_id, M3_CHUNK_CAPABILITY_TENANT_ID_SIZE) ||
      !key_is_valid(bucket, bucket_size, store->max_bucket_bytes) ||
      !key_is_valid(object_key, object_key_size, store->max_object_key_bytes) ||
      !manifest_bytes || manifest_size == 0u ||
      manifest_size > store->max_manifest_bytes || committed_index == 0u) {
    return M3_NAMESPACE_LOCAL_INVALID_ARG;
  }
  if (committed_index <= store->applied_index)
    return M3_NAMESPACE_LOCAL_OUT_OF_ORDER;
  if (m3_object_manifest_decode_v2(
          manifest_bytes, manifest_size, store->max_object_bytes,
          store->max_chunks,
          store->max_chunks * M3_NAMESPACE_LOCAL_MAX_PLACEMENTS_PER_CHUNK,
          &incoming) != M3_OBJECT_MANIFEST_OK) {
    return M3_NAMESPACE_LOCAL_CORRUPT;
  }
  entry = find_entry(store, tenant_id, bucket, bucket_size, object_key,
                     object_key_size);
  if (!entry || entry->tombstoned) {
    m3_object_manifest_owned_destroy_v2(&incoming);
    return M3_NAMESPACE_LOCAL_NOT_FOUND;
  }
  if (m3_object_manifest_decode_v2(
          entry->manifest_bytes, entry->manifest_size, store->max_object_bytes,
          store->max_chunks,
          store->max_chunks * M3_NAMESPACE_LOCAL_MAX_PLACEMENTS_PER_CHUNK,
          &stored) != M3_OBJECT_MANIFEST_OK) {
    m3_object_manifest_owned_destroy_v2(&incoming);
    return M3_NAMESPACE_LOCAL_CORRUPT;
  }
  if (incoming.manifest.object_cid.size != stored.manifest.object_cid.size ||
      memcmp(incoming.manifest.object_cid.digest, stored.manifest.object_cid.digest,
             sizeof(incoming.manifest.object_cid.digest)) != 0) {
    m3_object_manifest_owned_destroy_v2(&incoming);
    m3_object_manifest_owned_destroy_v2(&stored);
    return M3_NAMESPACE_LOCAL_CONFLICT;
  }
  m3_object_manifest_owned_destroy_v2(&incoming);
  m3_object_manifest_owned_destroy_v2(&stored);

  manifest_copy = (uint8_t *)malloc(manifest_size);
  if (!manifest_copy)
    return M3_NAMESPACE_LOCAL_RESOURCE_EXHAUSTED;
  memcpy(manifest_copy, manifest_bytes, manifest_size);
  free(entry->manifest_bytes);
  entry->manifest_bytes = manifest_copy;
  entry->manifest_size = manifest_size;
  entry->committed_index = committed_index;
  entry->tombstoned = 0u;
  store->applied_index = committed_index;
  return M3_NAMESPACE_LOCAL_OK;
}

m3_namespace_local_result_t m3_namespace_local_store_apply_tombstone_v1(
    m3_namespace_local_store_v1_t *store, uint64_t committed_index,
    const uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE], const uint8_t *bucket,
    size_t bucket_size, const uint8_t *object_key, size_t object_key_size) {
  m3_namespace_local_entry_t *entry;

  if (!store || !store->open || !tenant_id ||
      bytes_are_zero(tenant_id, M3_CHUNK_CAPABILITY_TENANT_ID_SIZE) ||
      !key_is_valid(bucket, bucket_size, store->max_bucket_bytes) ||
      !key_is_valid(object_key, object_key_size, store->max_object_key_bytes) ||
      committed_index == 0u) {
    return M3_NAMESPACE_LOCAL_INVALID_ARG;
  }
  if (committed_index <= store->applied_index)
    return M3_NAMESPACE_LOCAL_OUT_OF_ORDER;

  entry = find_entry(store, tenant_id, bucket, bucket_size, object_key, object_key_size);
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

static m3_namespace_lookup_result_t
local_lookup_start(void *context, const m3_namespace_lookup_request_v1_t *request,
                   m3_namespace_lookup_complete_cb complete_cb, void *user_data) {
  m3_namespace_local_store_v1_t *store = (m3_namespace_local_store_v1_t *)context;
  m3_namespace_local_entry_t *entry;
  m3_namespace_lookup_response_v1_t response = {0};

  if (!store || !store->open || !request || !complete_cb || !request->require_linearizable ||
      store->applied_index == 0u ||
      bytes_are_zero(request->tenant_id, M3_CHUNK_CAPABILITY_TENANT_ID_SIZE) ||
      !key_is_valid(request->bucket, request->bucket_size, store->max_bucket_bytes) ||
      !key_is_valid(request->object_key, request->object_key_size, store->max_object_key_bytes)) {
    return M3_NAMESPACE_LOOKUP_INVALID_ARG;
  }
  entry = find_entry(store, request->tenant_id, request->bucket, request->bucket_size,
                     request->object_key, request->object_key_size);
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

m3_namespace_local_result_t
m3_namespace_local_store_persist_v1(m3_namespace_local_store_v1_t *store, const char *root) {
  char state_path[TURBO_FS_MAX_PATH];
  char temp_path[TURBO_FS_MAX_PATH];
  uint8_t *bytes = NULL;
  uint64_t total_size;
  size_t offset;
  size_t index;
  size_t count = 0u;
  turbo_file_t file = TURBO_INVALID_FILE;
  m3_namespace_local_result_t result;

  if (!store || !store->open || !root || root[0] == '\0')
    return M3_NAMESPACE_LOCAL_INVALID_ARG;
  if (join_path(root, M3_NAMESPACE_LOCAL_STATE_FILE, state_path, sizeof(state_path)) != 0 ||
      join_path(root, M3_NAMESPACE_LOCAL_TEMP_FILE, temp_path, sizeof(temp_path)) != 0)
    return M3_NAMESPACE_LOCAL_INVALID_ARG;

  total_size = M3_NAMESPACE_LOCAL_HEADER_SIZE;
  for (index = 0u; index < store->capacity; index++) {
    const m3_namespace_local_entry_t *entry = &store->entries[index];
    uint64_t record_size_value;

    if (!entry->occupied)
      continue;
    if (record_size(entry, &record_size_value) != 0)
      return M3_NAMESPACE_LOCAL_RESOURCE_EXHAUSTED;
    if (total_size > UINT64_MAX - record_size_value)
      return M3_NAMESPACE_LOCAL_RESOURCE_EXHAUSTED;
    total_size += record_size_value;
    count++;
  }
  if (total_size > SIZE_MAX)
    return M3_NAMESPACE_LOCAL_RESOURCE_EXHAUSTED;

  bytes = (uint8_t *)malloc((size_t)total_size);
  if (!bytes)
    return M3_NAMESPACE_LOCAL_RESOURCE_EXHAUSTED;
  memset(bytes, 0, (size_t)total_size);
  memcpy(bytes, m3_namespace_local_magic, sizeof(m3_namespace_local_magic));
  write_u32_be(bytes + M3_NAMESPACE_LOCAL_OFFSET_VERSION, M3_NAMESPACE_LOCAL_VERSION);
  write_u32_be(bytes + M3_NAMESPACE_LOCAL_OFFSET_RESERVED, 0u);
  write_u64_be(bytes + M3_NAMESPACE_LOCAL_OFFSET_APPLIED_INDEX, store->applied_index);
  write_u64_be(bytes + M3_NAMESPACE_LOCAL_OFFSET_ENTRY_COUNT, (uint64_t)count);
  write_u64_be(bytes + M3_NAMESPACE_LOCAL_OFFSET_MAX_BUCKET_BYTES,
               (uint64_t)store->max_bucket_bytes);
  write_u64_be(bytes + M3_NAMESPACE_LOCAL_OFFSET_MAX_OBJECT_KEY_BYTES,
               (uint64_t)store->max_object_key_bytes);
  write_u64_be(bytes + M3_NAMESPACE_LOCAL_OFFSET_MAX_MANIFEST_BYTES,
               (uint64_t)store->max_manifest_bytes);

  offset = M3_NAMESPACE_LOCAL_HEADER_SIZE;
  for (index = 0u; index < store->capacity; index++) {
    const m3_namespace_local_entry_t *entry = &store->entries[index];
    uint64_t record_size_value;
    uint8_t *record;

    if (!entry->occupied)
      continue;
    if (record_size(entry, &record_size_value) != 0) {
      result = M3_NAMESPACE_LOCAL_RESOURCE_EXHAUSTED;
      goto cleanup;
    }
    record = bytes + offset;
    memcpy(record, entry->tenant_id, M3_CHUNK_CAPABILITY_TENANT_ID_SIZE);
    write_u32_be(record + M3_NAMESPACE_LOCAL_RECORD_OFFSET_BUCKET, (uint32_t)entry->bucket_size);
    write_u32_be(record + M3_NAMESPACE_LOCAL_RECORD_OFFSET_OBJECT_KEY,
                 (uint32_t)entry->object_key_size);
    write_u32_be(record + M3_NAMESPACE_LOCAL_RECORD_OFFSET_MANIFEST,
                 (uint32_t)entry->manifest_size);
    record[M3_NAMESPACE_LOCAL_RECORD_OFFSET_TOMBSTONED] = entry->tombstoned ? 1u : 0u;
    memcpy(record + M3_NAMESPACE_LOCAL_RECORD_PAYLOAD_OFFSET, entry->bucket, entry->bucket_size);
    memcpy(record + M3_NAMESPACE_LOCAL_RECORD_PAYLOAD_OFFSET + entry->bucket_size,
           entry->object_key, entry->object_key_size);
    if (entry->manifest_size > 0u) {
      memcpy(record + M3_NAMESPACE_LOCAL_RECORD_PAYLOAD_OFFSET + entry->bucket_size +
                 entry->object_key_size,
             entry->manifest_bytes, entry->manifest_size);
    }
    offset += (size_t)record_size_value;
  }
  {
    uint64_t checksum =
        fnv1a_bytes(bytes, M3_NAMESPACE_LOCAL_OFFSET_CHECKSUM, UINT64_C(1469598103934665603));
    checksum = fnv1a_bytes(bytes + M3_NAMESPACE_LOCAL_HEADER_SIZE,
                           (size_t)total_size - M3_NAMESPACE_LOCAL_HEADER_SIZE, checksum);
    write_u64_be(bytes + M3_NAMESPACE_LOCAL_OFFSET_CHECKSUM, checksum);
  }

  file = turbo_fs_open(temp_path, TURBO_FS_O_WRONLY | TURBO_FS_O_CREAT | TURBO_FS_O_TRUNC,
                       M3_NAMESPACE_LOCAL_FILE_MODE);
  if (file == TURBO_INVALID_FILE) {
    result = M3_NAMESPACE_LOCAL_INVALID_STATE;
    goto cleanup;
  }
  result = write_all(file, bytes, (size_t)total_size);
  if (result != M3_NAMESPACE_LOCAL_OK)
    goto cleanup;
  if (turbo_fs_fsync(file) != 0 || turbo_fs_close(file) != 0) {
    file = TURBO_INVALID_FILE;
    result = M3_NAMESPACE_LOCAL_INVALID_STATE;
    goto cleanup;
  }
  file = TURBO_INVALID_FILE;
  if (turbo_fs_rename(temp_path, state_path) != 0) {
    result = M3_NAMESPACE_LOCAL_INVALID_STATE;
    goto cleanup;
  }
  result = M3_NAMESPACE_LOCAL_OK;

cleanup:
  if (file != TURBO_INVALID_FILE)
    (void)turbo_fs_close(file);
  if (result != M3_NAMESPACE_LOCAL_OK)
    (void)turbo_fs_unlink(temp_path);
  free(bytes);
  return result;
}

static int manifest_decodes(const m3_namespace_local_store_v1_t *store,
                            const uint8_t *manifest_bytes, size_t manifest_size) {
  m3_object_manifest_owned_v2_t owned = {0};
  int ok;

  ok = m3_object_manifest_decode_v2(
           manifest_bytes, manifest_size, store->max_object_bytes,
           store->max_chunks,
           store->max_chunks * M3_NAMESPACE_LOCAL_MAX_PLACEMENTS_PER_CHUNK,
           &owned) == M3_OBJECT_MANIFEST_OK;
  m3_object_manifest_owned_destroy_v2(&owned);
  return ok;
}

m3_namespace_local_result_t m3_namespace_local_store_load_v1(m3_namespace_local_store_v1_t *store,
                                                             const char *root, size_t capacity) {
  char state_path[TURBO_FS_MAX_PATH];
  turbo_fs_stat_t stat;
  turbo_file_t file = TURBO_INVALID_FILE;
  uint8_t *bytes = NULL;
  uint64_t applied_index;
  uint64_t entry_count;
  size_t file_size;
  size_t offset;
  size_t index;
  m3_namespace_local_result_t result;

  if (!store || !store->open || !root || root[0] == '\0' || capacity == 0u ||
      capacity != store->capacity)
    return M3_NAMESPACE_LOCAL_INVALID_ARG;
  if (store->count != 0u || store->applied_index != 0u)
    return M3_NAMESPACE_LOCAL_INVALID_STATE;
  if (join_path(root, M3_NAMESPACE_LOCAL_STATE_FILE, state_path, sizeof(state_path)) != 0)
    return M3_NAMESPACE_LOCAL_INVALID_ARG;

  /*
   * A missing state file (or root) is a normal first run, not an error.
   * Probe with access() so the expected absence does not surface as an
   * ERROR log from stat().
   */
  if (turbo_fs_access(state_path, TURBO_FS_ACCESS_EXISTS) != 0)
    return M3_NAMESPACE_LOCAL_OK;
  if (turbo_fs_stat(state_path, &stat) != 0)
    return M3_NAMESPACE_LOCAL_CORRUPT;
  if (!stat.is_file || stat.size < M3_NAMESPACE_LOCAL_HEADER_SIZE || stat.size > SIZE_MAX)
    return M3_NAMESPACE_LOCAL_CORRUPT;

  /*
   * Bound the allocation before reading: a valid file holds at most capacity
   * records, each bounded by the store's configured limits.
   */
  {
    uint64_t max_record = M3_NAMESPACE_LOCAL_RECORD_PAYLOAD_OFFSET;
    uint64_t worst_total;

    if (u64_add_checked(max_record, (uint64_t)store->max_bucket_bytes, &max_record) != 0 ||
        u64_add_checked(max_record, (uint64_t)store->max_object_key_bytes, &max_record) != 0 ||
        u64_add_checked(max_record, (uint64_t)store->max_manifest_bytes, &max_record) != 0 ||
        u64_mul_add_checked((uint64_t)store->capacity, max_record, M3_NAMESPACE_LOCAL_HEADER_SIZE,
                            &worst_total) != 0)
      return M3_NAMESPACE_LOCAL_CORRUPT;
    if ((uint64_t)stat.size > worst_total)
      return M3_NAMESPACE_LOCAL_CORRUPT;
  }

  file = turbo_fs_open(state_path, TURBO_FS_O_RDONLY, 0);
  if (file == TURBO_INVALID_FILE)
    return M3_NAMESPACE_LOCAL_CORRUPT;
  bytes = (uint8_t *)malloc((size_t)stat.size);
  if (!bytes) {
    result = M3_NAMESPACE_LOCAL_RESOURCE_EXHAUSTED;
    goto cleanup;
  }
  if (read_exact(file, bytes, (size_t)stat.size) != 0) {
    result = M3_NAMESPACE_LOCAL_CORRUPT;
    goto cleanup;
  }
  if (turbo_fs_close(file) != 0) {
    file = TURBO_INVALID_FILE;
    result = M3_NAMESPACE_LOCAL_CORRUPT;
    goto cleanup;
  }
  file = TURBO_INVALID_FILE;
  file_size = (size_t)stat.size;

  if (memcmp(bytes, m3_namespace_local_magic, sizeof(m3_namespace_local_magic)) != 0 ||
      read_u32_be(bytes + M3_NAMESPACE_LOCAL_OFFSET_VERSION) != M3_NAMESPACE_LOCAL_VERSION ||
      read_u32_be(bytes + M3_NAMESPACE_LOCAL_OFFSET_RESERVED) != 0u) {
    result = M3_NAMESPACE_LOCAL_CORRUPT;
    goto cleanup;
  }
  applied_index = read_u64_be(bytes + M3_NAMESPACE_LOCAL_OFFSET_APPLIED_INDEX);
  entry_count = read_u64_be(bytes + M3_NAMESPACE_LOCAL_OFFSET_ENTRY_COUNT);
  if (entry_count > capacity || (applied_index == 0u && entry_count != 0u) ||
      read_u64_be(bytes + M3_NAMESPACE_LOCAL_OFFSET_MAX_BUCKET_BYTES) !=
          (uint64_t)store->max_bucket_bytes ||
      read_u64_be(bytes + M3_NAMESPACE_LOCAL_OFFSET_MAX_OBJECT_KEY_BYTES) !=
          (uint64_t)store->max_object_key_bytes ||
      read_u64_be(bytes + M3_NAMESPACE_LOCAL_OFFSET_MAX_MANIFEST_BYTES) !=
          (uint64_t)store->max_manifest_bytes) {
    result = M3_NAMESPACE_LOCAL_CORRUPT;
    goto cleanup;
  }

  /* Validate every record's fields and the exact file shape before mutating. */
  offset = M3_NAMESPACE_LOCAL_HEADER_SIZE;
  for (index = 0u; index < (size_t)entry_count; index++) {
    const uint8_t *record;
    uint32_t bucket_size;
    uint32_t object_key_size;
    uint32_t manifest_size;
    uint8_t tombstoned;
    uint64_t record_size_value;

    if ((uint64_t)file_size - (uint64_t)offset < M3_NAMESPACE_LOCAL_RECORD_PAYLOAD_OFFSET) {
      result = M3_NAMESPACE_LOCAL_CORRUPT;
      goto cleanup;
    }
    record = bytes + offset;
    bucket_size = read_u32_be(record + M3_NAMESPACE_LOCAL_RECORD_OFFSET_BUCKET);
    object_key_size = read_u32_be(record + M3_NAMESPACE_LOCAL_RECORD_OFFSET_OBJECT_KEY);
    manifest_size = read_u32_be(record + M3_NAMESPACE_LOCAL_RECORD_OFFSET_MANIFEST);
    tombstoned = record[M3_NAMESPACE_LOCAL_RECORD_OFFSET_TOMBSTONED];
    if (tombstoned > 1u || record[M3_NAMESPACE_LOCAL_RECORD_OFFSET_RESERVED] != 0u ||
        record[M3_NAMESPACE_LOCAL_RECORD_OFFSET_RESERVED + 1u] != 0u ||
        record[M3_NAMESPACE_LOCAL_RECORD_OFFSET_RESERVED + 2u] != 0u || bucket_size == 0u ||
        bucket_size > store->max_bucket_bytes || object_key_size == 0u ||
        object_key_size > store->max_object_key_bytes ||
        manifest_size > store->max_manifest_bytes ||
        (tombstoned != 0u ? manifest_size != 0u : manifest_size == 0u) ||
        bytes_are_zero(record, M3_CHUNK_CAPABILITY_TENANT_ID_SIZE)) {
      result = M3_NAMESPACE_LOCAL_CORRUPT;
      goto cleanup;
    }
    record_size_value = M3_NAMESPACE_LOCAL_RECORD_PAYLOAD_OFFSET;
    record_size_value += (uint64_t)bucket_size;
    record_size_value += (uint64_t)object_key_size;
    record_size_value += (uint64_t)manifest_size;
    if (record_size_value > (uint64_t)file_size - (uint64_t)offset) {
      result = M3_NAMESPACE_LOCAL_CORRUPT;
      goto cleanup;
    }
    if (tombstoned == 0u) {
      const uint8_t *manifest_bytes =
          record + M3_NAMESPACE_LOCAL_RECORD_PAYLOAD_OFFSET + bucket_size + object_key_size;
      if (!manifest_decodes(store, manifest_bytes, manifest_size)) {
        result = M3_NAMESPACE_LOCAL_CORRUPT;
        goto cleanup;
      }
    }
    offset += (size_t)record_size_value;
  }
  if (offset != file_size) {
    result = M3_NAMESPACE_LOCAL_CORRUPT;
    goto cleanup;
  }
  {
    uint64_t checksum =
        fnv1a_bytes(bytes, M3_NAMESPACE_LOCAL_OFFSET_CHECKSUM, UINT64_C(1469598103934665603));
    checksum = fnv1a_bytes(bytes + M3_NAMESPACE_LOCAL_HEADER_SIZE,
                           file_size - M3_NAMESPACE_LOCAL_HEADER_SIZE, checksum);
    if (checksum != read_u64_be(bytes + M3_NAMESPACE_LOCAL_OFFSET_CHECKSUM)) {
      result = M3_NAMESPACE_LOCAL_CORRUPT;
      goto cleanup;
    }
  }

  /* Second pass: commit the validated records into the empty store. */
  offset = M3_NAMESPACE_LOCAL_HEADER_SIZE;
  for (index = 0u; index < (size_t)entry_count; index++) {
    const uint8_t *record = bytes + offset;
    uint32_t bucket_size = read_u32_be(record + M3_NAMESPACE_LOCAL_RECORD_OFFSET_BUCKET);
    uint32_t object_key_size = read_u32_be(record + M3_NAMESPACE_LOCAL_RECORD_OFFSET_OBJECT_KEY);
    uint32_t manifest_size = read_u32_be(record + M3_NAMESPACE_LOCAL_RECORD_OFFSET_MANIFEST);
    uint8_t tombstoned = record[M3_NAMESPACE_LOCAL_RECORD_OFFSET_TOMBSTONED];
    const uint8_t *bucket_bytes = record + M3_NAMESPACE_LOCAL_RECORD_PAYLOAD_OFFSET;
    const uint8_t *key_bytes = bucket_bytes + bucket_size;
    const uint8_t *manifest_bytes = key_bytes + object_key_size;
    m3_namespace_local_entry_t *entry = &store->entries[index];
    uint8_t *bucket_copy = (uint8_t *)malloc(bucket_size);
    uint8_t *key_copy = (uint8_t *)malloc(object_key_size);
    uint8_t *manifest_copy = tombstoned ? NULL : (uint8_t *)malloc(manifest_size);

    if (!bucket_copy || !key_copy || (!tombstoned && !manifest_copy)) {
      free(bucket_copy);
      free(key_copy);
      free(manifest_copy);
      clear_loaded_entries(store, index);
      result = M3_NAMESPACE_LOCAL_RESOURCE_EXHAUSTED;
      goto cleanup;
    }
    memcpy(bucket_copy, bucket_bytes, bucket_size);
    memcpy(key_copy, key_bytes, object_key_size);
    memcpy(entry->tenant_id, record, M3_CHUNK_CAPABILITY_TENANT_ID_SIZE);
    entry->bucket = bucket_copy;
    entry->bucket_size = bucket_size;
    entry->object_key = key_copy;
    entry->object_key_size = object_key_size;
    entry->manifest_bytes = manifest_copy;
    entry->manifest_size = manifest_size;
    entry->tombstoned = tombstoned;
    entry->committed_index = applied_index;
    entry->occupied = 1u;
    store->count++;
    if (manifest_copy) {
      memcpy(manifest_copy, manifest_bytes, manifest_size);
    }
    offset += M3_NAMESPACE_LOCAL_RECORD_PAYLOAD_OFFSET + (size_t)bucket_size +
              (size_t)object_key_size + (size_t)manifest_size;
  }
  store->applied_index = applied_index;
  result = M3_NAMESPACE_LOCAL_OK;

cleanup:
  if (file != TURBO_INVALID_FILE)
    (void)turbo_fs_close(file);
  free(bytes);
  return result;
}

m3_namespace_local_result_t
m3_namespace_local_store_list_v1(const m3_namespace_local_store_v1_t *store,
                                 const uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE],
                                 const uint8_t *bucket, size_t bucket_size, const uint8_t *prefix,
                                 size_t prefix_size, m3_namespace_list_cb callback,
                                 void *user_data) {
  if (!store || !store->open || !tenant_id ||
      bytes_are_zero(tenant_id, M3_CHUNK_CAPABILITY_TENANT_ID_SIZE) || !callback)
    return M3_NAMESPACE_LOCAL_INVALID_ARG;
  if (bucket && !key_is_valid(bucket, bucket_size, store->max_bucket_bytes))
    return M3_NAMESPACE_LOCAL_INVALID_ARG;
  if (prefix && prefix_size > store->max_object_key_bytes)
    return M3_NAMESPACE_LOCAL_INVALID_ARG;

  /*
   * Deterministic insertion order: the entry array is filled in index order by
   * apply_put and rebuilt in the same order by load, so a persist/load round
   * trip does not reorder enumeration.
   */
  for (size_t i = 0u; i < store->capacity; i++) {
    const m3_namespace_local_entry_t *entry = &store->entries[i];

    if (!entry->occupied || entry->tombstoned ||
        memcmp(entry->tenant_id, tenant_id, M3_CHUNK_CAPABILITY_TENANT_ID_SIZE) != 0)
      continue;
    if (bucket &&
        (entry->bucket_size != bucket_size || memcmp(entry->bucket, bucket, bucket_size) != 0))
      continue;
    if (prefix && (entry->object_key_size < prefix_size ||
                   memcmp(entry->object_key, prefix, prefix_size) != 0))
      continue;
    callback(entry->bucket, entry->bucket_size, entry->object_key, entry->object_key_size,
             entry->manifest_bytes, entry->manifest_size, user_data);
  }
  return M3_NAMESPACE_LOCAL_OK;
}
