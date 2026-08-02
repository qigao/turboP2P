#include "m3_namespace_local_store.h"

#include "tinytest.h"

#include <stdlib.h>
#include <string.h>

enum {
  TEST_NAMESPACE_CAPACITY = 2,
  TEST_MAX_BUCKET_BYTES = 32,
  TEST_MAX_OBJECT_KEY_BYTES = 64,
  TEST_MAX_MANIFEST_BYTES = 512,
  TEST_MAX_OBJECT_BYTES = 1024,
  TEST_MAX_CHUNKS = 4
};

typedef struct {
  size_t calls;
  m3_namespace_lookup_result_t result;
  uint8_t manifest[TEST_MAX_MANIFEST_BYTES];
  size_t manifest_size;
  uint64_t applied_index;
  uint8_t linearizable;
} namespace_lookup_capture_t;

static void fill_bytes(uint8_t *bytes, size_t size, uint8_t value) {
  memset(bytes, value, size);
}

static uint8_t *make_manifest(uint8_t seed, size_t *out_size) {
  m3_chunk_cid_v1_t chunk;
  m3_object_manifest_v1_t manifest;
  uint8_t *bytes = NULL;

  memset(&chunk, 0, sizeof(chunk));
  chunk.hash_algorithm = M3_CHUNK_STORE_HASH_ALGORITHM_SHA256;
  chunk.size = 4u;
  fill_bytes(chunk.digest, sizeof(chunk.digest), seed);
  memset(&manifest, 0, sizeof(manifest));
  manifest.version = M3_OBJECT_MANIFEST_VERSION;
  manifest.object_cid.hash_algorithm =
      M3_CHUNK_STORE_HASH_ALGORITHM_SHA256;
  manifest.object_cid.size = chunk.size;
  fill_bytes(manifest.object_cid.digest,
             sizeof(manifest.object_cid.digest), (uint8_t)(seed + 1u));
  manifest.chunks = &chunk;
  manifest.chunk_count = 1u;
  check_int_eq(m3_object_manifest_encode_v1(
                   &manifest, TEST_MAX_OBJECT_BYTES, TEST_MAX_CHUNKS,
                   &bytes, out_size),
               M3_OBJECT_MANIFEST_OK);
  check_not_null(bytes);
  return bytes;
}

static void init_store(m3_namespace_local_store_v1_t *store,
                       size_t capacity) {
  memset(store, 0, sizeof(*store));
  check_int_eq(m3_namespace_local_store_init_v1(
                   store, capacity, TEST_MAX_BUCKET_BYTES,
                   TEST_MAX_OBJECT_KEY_BYTES, TEST_MAX_MANIFEST_BYTES,
                   TEST_MAX_OBJECT_BYTES, TEST_MAX_CHUNKS),
               M3_NAMESPACE_LOCAL_OK);
}

static void capture_lookup(
    m3_namespace_lookup_result_t result,
    const m3_namespace_lookup_response_v1_t *response, void *user_data) {
  namespace_lookup_capture_t *capture =
      (namespace_lookup_capture_t *)user_data;

  capture->calls++;
  capture->result = result;
  if (response) {
    check_size_le(response->manifest_size, sizeof(capture->manifest));
    memcpy(capture->manifest, response->manifest_bytes,
           response->manifest_size);
    capture->manifest_size = response->manifest_size;
    capture->applied_index = response->applied_index;
    capture->linearizable = response->linearizable;
  }
}

static namespace_lookup_capture_t lookup(
    m3_namespace_local_store_v1_t *store,
    const uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE],
    const char *bucket, const char *object_key) {
  m3_namespace_lookup_adapter_v1_t adapter =
      m3_namespace_local_store_adapter_v1(store);
  m3_namespace_lookup_request_v1_t request;
  namespace_lookup_capture_t capture;

  memset(&request, 0, sizeof(request));
  memset(&capture, 0, sizeof(capture));
  memcpy(request.tenant_id, tenant_id, sizeof(request.tenant_id));
  request.bucket = (const uint8_t *)bucket;
  request.bucket_size = strlen(bucket);
  request.object_key = (const uint8_t *)object_key;
  request.object_key_size = strlen(object_key);
  request.require_linearizable = 1u;
  check_not_null(adapter.start);
  check_int_eq(adapter.start(adapter.context, &request, capture_lookup,
                             &capture),
               M3_NAMESPACE_LOOKUP_OK);
  return capture;
}

static void apply_replay_sequence(
    m3_namespace_local_store_v1_t *store,
    const uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE],
    const uint8_t *first_manifest, size_t first_manifest_size,
    const uint8_t *second_manifest, size_t second_manifest_size) {
  static const uint8_t bucket[] = "bucket";
  static const uint8_t object_key[] = "object";

  check_int_eq(m3_namespace_local_store_apply_put_v1(
                   store, 1u, tenant_id, bucket, sizeof(bucket) - 1u,
                   object_key, sizeof(object_key) - 1u, first_manifest,
                   first_manifest_size),
               M3_NAMESPACE_LOCAL_OK);
  check_int_eq(m3_namespace_local_store_apply_put_v1(
                   store, 2u, tenant_id, bucket, sizeof(bucket) - 1u,
                   object_key, sizeof(object_key) - 1u, second_manifest,
                   second_manifest_size),
               M3_NAMESPACE_LOCAL_OK);
  check_int_eq(m3_namespace_local_store_apply_tombstone_v1(
                   store, 3u, tenant_id, bucket, sizeof(bucket) - 1u,
                   object_key, sizeof(object_key) - 1u),
               M3_NAMESPACE_LOCAL_OK);
  check_int_eq(m3_namespace_local_store_apply_put_v1(
                   store, 4u, tenant_id, bucket, sizeof(bucket) - 1u,
                   object_key, sizeof(object_key) - 1u, first_manifest,
                   first_manifest_size),
               M3_NAMESPACE_LOCAL_OK);
}

static void test_replay_is_deterministic_and_fenced(void) {
  m3_namespace_local_store_v1_t first;
  m3_namespace_local_store_v1_t replay;
  namespace_lookup_capture_t first_lookup;
  namespace_lookup_capture_t replay_lookup;
  uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE];
  uint8_t *manifest_one;
  uint8_t *manifest_two;
  size_t manifest_one_size = 0u;
  size_t manifest_two_size = 0u;

  fill_bytes(tenant_id, sizeof(tenant_id), 7u);
  manifest_one = make_manifest(11u, &manifest_one_size);
  manifest_two = make_manifest(21u, &manifest_two_size);
  init_store(&first, TEST_NAMESPACE_CAPACITY);
  init_store(&replay, TEST_NAMESPACE_CAPACITY);

  apply_replay_sequence(&first, tenant_id, manifest_one,
                        manifest_one_size, manifest_two,
                        manifest_two_size);
  apply_replay_sequence(&replay, tenant_id, manifest_one,
                        manifest_one_size, manifest_two,
                        manifest_two_size);
  check_int_eq(m3_namespace_local_store_apply_tombstone_v1(
                   &first, 4u, tenant_id, (const uint8_t *)"bucket", 6u,
                   (const uint8_t *)"object", 6u),
               M3_NAMESPACE_LOCAL_OUT_OF_ORDER);

  first_lookup = lookup(&first, tenant_id, "bucket", "object");
  replay_lookup = lookup(&replay, tenant_id, "bucket", "object");
  check_size_eq(first_lookup.calls, 1u);
  check_int_eq(first_lookup.result, M3_NAMESPACE_LOOKUP_OK);
  check_true(first_lookup.linearizable);
  check_long_eq(first_lookup.applied_index, 4u);
  check_size_eq(first_lookup.manifest_size, replay_lookup.manifest_size);
  check_mem_eq(first_lookup.manifest, replay_lookup.manifest,
               first_lookup.manifest_size);
  check_mem_eq(first_lookup.manifest, manifest_one, manifest_one_size);
  check_size_eq(first.count, replay.count);
  check_long_eq(first.applied_index, replay.applied_index);

  m3_namespace_local_store_destroy_v1(&replay);
  m3_namespace_local_store_destroy_v1(&first);
  m3_object_manifest_bytes_free_v1(manifest_two);
  m3_object_manifest_bytes_free_v1(manifest_one);
}

static void test_tombstones_are_idempotent_and_capacity_is_bounded(void) {
  m3_namespace_local_store_v1_t store;
  namespace_lookup_capture_t capture;
  uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE];
  uint8_t *manifest;
  size_t manifest_size = 0u;

  fill_bytes(tenant_id, sizeof(tenant_id), 9u);
  manifest = make_manifest(31u, &manifest_size);
  init_store(&store, 1u);
  check_int_eq(m3_namespace_local_store_apply_put_v1(
                   &store, 1u, tenant_id, (const uint8_t *)"bucket", 6u,
                   (const uint8_t *)"one", 3u, manifest, manifest_size),
               M3_NAMESPACE_LOCAL_OK);
  check_int_eq(m3_namespace_local_store_apply_tombstone_v1(
                   &store, 2u, tenant_id, (const uint8_t *)"bucket", 6u,
                   (const uint8_t *)"one", 3u),
               M3_NAMESPACE_LOCAL_OK);
  capture = lookup(&store, tenant_id, "bucket", "one");
  check_size_eq(capture.calls, 1u);
  check_int_eq(capture.result, M3_NAMESPACE_LOOKUP_NOT_FOUND);
  check_int_eq(m3_namespace_local_store_apply_tombstone_v1(
                   &store, 3u, tenant_id, (const uint8_t *)"bucket", 6u,
                   (const uint8_t *)"missing", 7u),
               M3_NAMESPACE_LOCAL_OK);
  check_long_eq(store.applied_index, 3u);
  check_int_eq(m3_namespace_local_store_apply_put_v1(
                   &store, 4u, tenant_id, (const uint8_t *)"bucket", 6u,
                   (const uint8_t *)"two", 3u, manifest, manifest_size),
               M3_NAMESPACE_LOCAL_RESOURCE_EXHAUSTED);
  check_long_eq(store.applied_index, 3u);
  check_int_eq(m3_namespace_local_store_apply_put_v1(
                   &store, 4u, tenant_id, (const uint8_t *)"bucket", 6u,
                   (const uint8_t *)"one", 3u,
                   (const uint8_t *)"corrupt", 7u),
               M3_NAMESPACE_LOCAL_CORRUPT);
  check_long_eq(store.applied_index, 3u);

  m3_namespace_local_store_destroy_v1(&store);
  m3_object_manifest_bytes_free_v1(manifest);
}

spec("M3 local namespace committed state machine") {
  it("replays PUT and tombstone deterministically with index fencing") {
    test_replay_is_deterministic_and_fenced();
  }
  it("keeps tombstones idempotent and preserves bounded capacity") {
    test_tombstones_are_idempotent_and_capacity_is_bounded();
  }
}
