#include "m3_namespace_local_store.h"

#include "tinytest.h"

#include <stdio.h>
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

static void fill_bytes(uint8_t *bytes, size_t size, uint8_t value) { memset(bytes, value, size); }

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
  manifest.object_cid.hash_algorithm = M3_CHUNK_STORE_HASH_ALGORITHM_SHA256;
  manifest.object_cid.size = chunk.size;
  fill_bytes(manifest.object_cid.digest, sizeof(manifest.object_cid.digest), (uint8_t)(seed + 1u));
  manifest.chunks = &chunk;
  manifest.chunk_count = 1u;
  check_int_eq(m3_object_manifest_encode_v1(&manifest, TEST_MAX_OBJECT_BYTES, TEST_MAX_CHUNKS,
                                            &bytes, out_size),
               M3_OBJECT_MANIFEST_OK);
  check_not_null(bytes);
  return bytes;
}

static void init_store(m3_namespace_local_store_v1_t *store, size_t capacity) {
  memset(store, 0, sizeof(*store));
  check_int_eq(m3_namespace_local_store_init_v1(store, capacity, TEST_MAX_BUCKET_BYTES,
                                                TEST_MAX_OBJECT_KEY_BYTES, TEST_MAX_MANIFEST_BYTES,
                                                TEST_MAX_OBJECT_BYTES, TEST_MAX_CHUNKS),
               M3_NAMESPACE_LOCAL_OK);
}

static void capture_lookup(m3_namespace_lookup_result_t result,
                           const m3_namespace_lookup_response_v1_t *response, void *user_data) {
  namespace_lookup_capture_t *capture = (namespace_lookup_capture_t *)user_data;

  capture->calls++;
  capture->result = result;
  if (response) {
    check_size_le(response->manifest_size, sizeof(capture->manifest));
    memcpy(capture->manifest, response->manifest_bytes, response->manifest_size);
    capture->manifest_size = response->manifest_size;
    capture->applied_index = response->applied_index;
    capture->linearizable = response->linearizable;
  }
}

static namespace_lookup_capture_t
lookup(m3_namespace_local_store_v1_t *store,
       const uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE], const char *bucket,
       const char *object_key) {
  m3_namespace_lookup_adapter_v1_t adapter = m3_namespace_local_store_adapter_v1(store);
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
  check_int_eq(adapter.start(adapter.context, &request, capture_lookup, &capture),
               M3_NAMESPACE_LOOKUP_OK);
  return capture;
}

static void apply_replay_sequence(m3_namespace_local_store_v1_t *store,
                                  const uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE],
                                  const uint8_t *first_manifest, size_t first_manifest_size,
                                  const uint8_t *second_manifest, size_t second_manifest_size) {
  static const uint8_t bucket[] = "bucket";
  static const uint8_t object_key[] = "object";

  check_int_eq(m3_namespace_local_store_apply_put_v1(
                   store, 1u, tenant_id, bucket, sizeof(bucket) - 1u, object_key,
                   sizeof(object_key) - 1u, first_manifest, first_manifest_size),
               M3_NAMESPACE_LOCAL_OK);
  check_int_eq(m3_namespace_local_store_apply_put_v1(
                   store, 2u, tenant_id, bucket, sizeof(bucket) - 1u, object_key,
                   sizeof(object_key) - 1u, second_manifest, second_manifest_size),
               M3_NAMESPACE_LOCAL_OK);
  check_int_eq(m3_namespace_local_store_apply_tombstone_v1(store, 3u, tenant_id, bucket,
                                                           sizeof(bucket) - 1u, object_key,
                                                           sizeof(object_key) - 1u),
               M3_NAMESPACE_LOCAL_OK);
  check_int_eq(m3_namespace_local_store_apply_put_v1(
                   store, 4u, tenant_id, bucket, sizeof(bucket) - 1u, object_key,
                   sizeof(object_key) - 1u, first_manifest, first_manifest_size),
               M3_NAMESPACE_LOCAL_OK);
}

enum { TEST_LIST_MAX_ITEMS = 8 };

typedef struct {
  size_t calls;
  size_t bucket_size[TEST_LIST_MAX_ITEMS];
  size_t object_key_size[TEST_LIST_MAX_ITEMS];
  size_t manifest_size[TEST_LIST_MAX_ITEMS];
  uint8_t bucket[TEST_LIST_MAX_ITEMS][TEST_MAX_BUCKET_BYTES];
  uint8_t object_key[TEST_LIST_MAX_ITEMS][TEST_MAX_OBJECT_KEY_BYTES];
  uint8_t manifest[TEST_LIST_MAX_ITEMS][TEST_MAX_MANIFEST_BYTES];
} namespace_list_capture_t;

static void capture_list(const uint8_t *bucket, size_t bucket_size, const uint8_t *object_key,
                         size_t object_key_size, const uint8_t *manifest_bytes,
                         size_t manifest_size, void *user_data) {
  namespace_list_capture_t *capture = (namespace_list_capture_t *)user_data;

  check_true(capture->calls < TEST_LIST_MAX_ITEMS);
  if (capture->calls >= TEST_LIST_MAX_ITEMS)
    return;
  check_size_le(bucket_size, sizeof(capture->bucket[capture->calls]));
  check_size_le(object_key_size, sizeof(capture->object_key[capture->calls]));
  check_size_le(manifest_size, sizeof(capture->manifest[capture->calls]));
  memcpy(capture->bucket[capture->calls], bucket, bucket_size);
  capture->bucket_size[capture->calls] = bucket_size;
  memcpy(capture->object_key[capture->calls], object_key, object_key_size);
  capture->object_key_size[capture->calls] = object_key_size;
  memcpy(capture->manifest[capture->calls], manifest_bytes, manifest_size);
  capture->manifest_size[capture->calls] = manifest_size;
  capture->calls++;
}

static void run_list(const m3_namespace_local_store_v1_t *store,
                     const uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE],
                     const char *bucket, const char *prefix, namespace_list_capture_t *capture) {
  memset(capture, 0, sizeof(*capture));
  check_int_eq(m3_namespace_local_store_list_v1(
                   store, tenant_id, bucket ? (const uint8_t *)bucket : NULL,
                   bucket ? strlen(bucket) : 0u, prefix ? (const uint8_t *)prefix : NULL,
                   prefix ? strlen(prefix) : 0u, capture_list, capture),
               M3_NAMESPACE_LOCAL_OK);
}

static void test_persist_load_round_trip(void) {
  m3_namespace_local_store_v1_t store;
  m3_namespace_local_store_v1_t loaded;
  namespace_list_capture_t capture;
  uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE];
  char *root = tt_make_temp_dir("m3ns");
  uint8_t *manifest_one;
  uint8_t *manifest_two;
  uint8_t *manifest_three;
  size_t manifest_one_size = 0u;
  size_t manifest_two_size = 0u;
  size_t manifest_three_size = 0u;

  check_not_null(root);
  fill_bytes(tenant_id, sizeof(tenant_id), 5u);
  manifest_one = make_manifest(41u, &manifest_one_size);
  manifest_two = make_manifest(42u, &manifest_two_size);
  manifest_three = make_manifest(43u, &manifest_three_size);

  init_store(&store, 3u);
  check_int_eq(m3_namespace_local_store_apply_put_v1(
                   &store, 1u, tenant_id, (const uint8_t *)"bucket-a", 8u, (const uint8_t *)"alpha",
                   5u, manifest_one, manifest_one_size),
               M3_NAMESPACE_LOCAL_OK);
  check_int_eq(m3_namespace_local_store_apply_put_v1(
                   &store, 2u, tenant_id, (const uint8_t *)"bucket-a", 8u, (const uint8_t *)"beta",
                   4u, manifest_two, manifest_two_size),
               M3_NAMESPACE_LOCAL_OK);
  check_int_eq(m3_namespace_local_store_apply_put_v1(
                   &store, 3u, tenant_id, (const uint8_t *)"bucket-b", 8u, (const uint8_t *)"gamma",
                   5u, manifest_three, manifest_three_size),
               M3_NAMESPACE_LOCAL_OK);
  check_int_eq(m3_namespace_local_store_apply_tombstone_v1(&store, 4u, tenant_id,
                                                           (const uint8_t *)"bucket-a", 8u,
                                                           (const uint8_t *)"alpha", 5u),
               M3_NAMESPACE_LOCAL_OK);
  check_long_eq(store.applied_index, 4u);
  check_size_eq(store.count, 3u);

  /* persist is idempotent: a second call must produce the same state */
  check_int_eq(m3_namespace_local_store_persist_v1(&store, root), M3_NAMESPACE_LOCAL_OK);
  check_int_eq(m3_namespace_local_store_persist_v1(&store, root), M3_NAMESPACE_LOCAL_OK);
  m3_namespace_local_store_destroy_v1(&store);

  init_store(&loaded, 3u);
  check_int_eq(m3_namespace_local_store_load_v1(&loaded, root, 3u), M3_NAMESPACE_LOCAL_OK);
  check_long_eq(loaded.applied_index, 4u);
  check_size_eq(loaded.count, 3u);

  /* tombstone survives the round trip and live objects resolve */
  run_list(&loaded, tenant_id, NULL, NULL, &capture);
  check_size_eq(capture.calls, 2u);
  check_mem_eq(capture.bucket[0], "bucket-a", 8u);
  check_mem_eq(capture.object_key[0], "beta", 4u);
  check_size_eq(capture.manifest_size[0], manifest_two_size);
  check_mem_eq(capture.manifest[0], manifest_two, manifest_two_size);
  check_mem_eq(capture.bucket[1], "bucket-b", 8u);
  check_mem_eq(capture.object_key[1], "gamma", 5u);
  check_size_eq(capture.manifest_size[1], manifest_three_size);
  check_mem_eq(capture.manifest[1], manifest_three, manifest_three_size);

  run_list(&loaded, tenant_id, "bucket-a", "b", &capture);
  check_size_eq(capture.calls, 1u);
  check_mem_eq(capture.object_key[0], "beta", 4u);

  run_list(&loaded, tenant_id, "bucket-a", "z", &capture);
  check_size_eq(capture.calls, 0u);

  run_list(&loaded, tenant_id, "bucket-missing", NULL, &capture);
  check_size_eq(capture.calls, 0u);

  {
    namespace_lookup_capture_t lookup_capture = lookup(&loaded, tenant_id, "bucket-b", "gamma");
    check_size_eq(lookup_capture.calls, 1u);
    check_int_eq(lookup_capture.result, M3_NAMESPACE_LOOKUP_OK);
    check_long_eq(lookup_capture.applied_index, 4u);
    check_size_eq(lookup_capture.manifest_size, manifest_three_size);
    check_mem_eq(lookup_capture.manifest, manifest_three, manifest_three_size);
  }

  m3_namespace_local_store_destroy_v1(&loaded);
  check_int_eq(tt_remove_tree(root), 0);
  free(root);
  m3_object_manifest_bytes_free_v1(manifest_three);
  m3_object_manifest_bytes_free_v1(manifest_two);
  m3_object_manifest_bytes_free_v1(manifest_one);
}

static void test_load_first_run_returns_empty(void) {
  m3_namespace_local_store_v1_t store;
  char *root = tt_make_temp_dir("m3ns");
  char missing_root[512];

  check_not_null(root);

  /* no state file in an existing root: first run */
  init_store(&store, TEST_NAMESPACE_CAPACITY);
  check_int_eq(m3_namespace_local_store_load_v1(&store, root, TEST_NAMESPACE_CAPACITY),
               M3_NAMESPACE_LOCAL_OK);
  check_size_eq(store.count, 0u);
  check_long_eq(store.applied_index, 0u);

  /* loading into a non-empty store is rejected */
  {
    uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE];
    fill_bytes(tenant_id, sizeof(tenant_id), 3u);
    check_int_eq(m3_namespace_local_store_apply_tombstone_v1(&store, 1u, tenant_id,
                                                             (const uint8_t *)"bucket", 6u,
                                                             (const uint8_t *)"missing", 7u),
                 M3_NAMESPACE_LOCAL_OK);
    check_int_eq(m3_namespace_local_store_load_v1(&store, root, TEST_NAMESPACE_CAPACITY),
                 M3_NAMESPACE_LOCAL_INVALID_STATE);
  }
  m3_namespace_local_store_destroy_v1(&store);

  /* a capacity mismatch is rejected */
  init_store(&store, TEST_NAMESPACE_CAPACITY);
  check_int_eq(m3_namespace_local_store_load_v1(&store, root, TEST_NAMESPACE_CAPACITY + 1u),
               M3_NAMESPACE_LOCAL_INVALID_ARG);
  m3_namespace_local_store_destroy_v1(&store);

  /* a missing root directory is also a first run */
  snprintf(missing_root, sizeof(missing_root), "%s%cno-such-dir", root, '/');
  init_store(&store, TEST_NAMESPACE_CAPACITY);
  check_int_eq(m3_namespace_local_store_load_v1(&store, missing_root, TEST_NAMESPACE_CAPACITY),
               M3_NAMESPACE_LOCAL_OK);
  check_size_eq(store.count, 0u);
  check_long_eq(store.applied_index, 0u);
  m3_namespace_local_store_destroy_v1(&store);

  check_int_eq(tt_remove_tree(root), 0);
  free(root);
}

static void test_load_corrupt_file_fails(void) {
  m3_namespace_local_store_v1_t store;
  char *root = tt_make_temp_dir("m3ns");
  char state_path[512];
  static const uint8_t garbage[] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                    0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

  check_not_null(root);
  /* the module-owned state file name; load reads exactly this path */
  snprintf(state_path, sizeof(state_path), "%s%cnamespace.bin", root, '/');

  /* garbage bytes are rejected as corrupt */
  check_int_eq(tt_write_file(state_path, garbage, sizeof(garbage)), 0);
  init_store(&store, TEST_NAMESPACE_CAPACITY);
  check_int_eq(m3_namespace_local_store_load_v1(&store, root, TEST_NAMESPACE_CAPACITY),
               M3_NAMESPACE_LOCAL_CORRUPT);
  check_size_eq(store.count, 0u);
  check_long_eq(store.applied_index, 0u);
  m3_namespace_local_store_destroy_v1(&store);

  /* a truncated header is rejected as corrupt */
  check_int_eq(tt_write_file(state_path, "M3NSLOC1", 8), 0);
  init_store(&store, TEST_NAMESPACE_CAPACITY);
  check_int_eq(m3_namespace_local_store_load_v1(&store, root, TEST_NAMESPACE_CAPACITY),
               M3_NAMESPACE_LOCAL_CORRUPT);
  m3_namespace_local_store_destroy_v1(&store);

  check_int_eq(tt_remove_tree(root), 0);
  free(root);
}

static void test_list_enumerates_deterministically(void) {
  m3_namespace_local_store_v1_t store;
  namespace_list_capture_t capture;
  uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE];
  uint8_t other_tenant[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE];
  uint8_t zero_tenant[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE] = {0};
  static const uint8_t bad_bucket[] = {'b', 0x00, 'x'};
  uint8_t *manifest;
  uint8_t *manifest_two;
  size_t manifest_size = 0u;
  size_t manifest_two_size = 0u;

  fill_bytes(tenant_id, sizeof(tenant_id), 6u);
  fill_bytes(other_tenant, sizeof(other_tenant), 8u);
  manifest = make_manifest(51u, &manifest_size);
  manifest_two = make_manifest(52u, &manifest_two_size);
  init_store(&store, 4u);
  check_int_eq(
      m3_namespace_local_store_apply_put_v1(&store, 1u, tenant_id, (const uint8_t *)"bucket-a", 8u,
                                            (const uint8_t *)"alpha", 5u, manifest, manifest_size),
      M3_NAMESPACE_LOCAL_OK);
  check_int_eq(m3_namespace_local_store_apply_put_v1(
                   &store, 2u, tenant_id, (const uint8_t *)"bucket-a", 8u, (const uint8_t *)"beta",
                   4u, manifest_two, manifest_two_size),
               M3_NAMESPACE_LOCAL_OK);
  check_int_eq(
      m3_namespace_local_store_apply_put_v1(&store, 3u, tenant_id, (const uint8_t *)"bucket-b", 8u,
                                            (const uint8_t *)"gamma", 5u, manifest, manifest_size),
      M3_NAMESPACE_LOCAL_OK);
  check_int_eq(m3_namespace_local_store_apply_tombstone_v1(&store, 4u, tenant_id,
                                                           (const uint8_t *)"bucket-a", 8u,
                                                           (const uint8_t *)"alpha", 5u),
               M3_NAMESPACE_LOCAL_OK);
  check_int_eq(m3_namespace_local_store_apply_put_v1(
                   &store, 5u, other_tenant, (const uint8_t *)"bucket-a", 8u,
                   (const uint8_t *)"zeta", 4u, manifest_two, manifest_two_size),
               M3_NAMESPACE_LOCAL_OK);

  /* all buckets, insertion order, tombstone skipped, tenant filtered */
  run_list(&store, tenant_id, NULL, NULL, &capture);
  check_size_eq(capture.calls, 2u);
  check_mem_eq(capture.bucket[0], "bucket-a", 8u);
  check_mem_eq(capture.object_key[0], "beta", 4u);
  check_mem_eq(capture.bucket[1], "bucket-b", 8u);
  check_mem_eq(capture.object_key[1], "gamma", 5u);
  check_mem_eq(capture.manifest[0], manifest_two, manifest_two_size);
  check_mem_eq(capture.manifest[1], manifest, manifest_size);

  /* single bucket with prefix filter */
  run_list(&store, tenant_id, "bucket-a", "b", &capture);
  check_size_eq(capture.calls, 1u);
  check_mem_eq(capture.object_key[0], "beta", 4u);

  /* tombstoned alpha never matches even under its own prefix */
  run_list(&store, tenant_id, "bucket-a", "al", &capture);
  check_size_eq(capture.calls, 0u);

  run_list(&store, tenant_id, "bucket-b", NULL, &capture);
  check_size_eq(capture.calls, 1u);
  check_mem_eq(capture.object_key[0], "gamma", 5u);

  /* empty prefix matches every key in the bucket */
  run_list(&store, tenant_id, "bucket-b", "", &capture);
  check_size_eq(capture.calls, 1u);

  /* the other tenant only sees its own object */
  run_list(&store, other_tenant, NULL, NULL, &capture);
  check_size_eq(capture.calls, 1u);
  check_mem_eq(capture.bucket[0], "bucket-a", 8u);
  check_mem_eq(capture.object_key[0], "zeta", 4u);

  /* invalid arguments are rejected */
  check_int_eq(m3_namespace_local_store_list_v1(&store, tenant_id, NULL, 0u, NULL, 0u, NULL, NULL),
               M3_NAMESPACE_LOCAL_INVALID_ARG);
  check_int_eq(
      m3_namespace_local_store_list_v1(&store, NULL, NULL, 0u, NULL, 0u, capture_list, &capture),
      M3_NAMESPACE_LOCAL_INVALID_ARG);
  check_int_eq(m3_namespace_local_store_list_v1(&store, zero_tenant, NULL, 0u, NULL, 0u,
                                                capture_list, &capture),
               M3_NAMESPACE_LOCAL_INVALID_ARG);
  check_int_eq(m3_namespace_local_store_list_v1(&store, tenant_id, bad_bucket, sizeof(bad_bucket),
                                                NULL, 0u, capture_list, &capture),
               M3_NAMESPACE_LOCAL_INVALID_ARG);

  m3_namespace_local_store_destroy_v1(&store);
  m3_object_manifest_bytes_free_v1(manifest_two);
  m3_object_manifest_bytes_free_v1(manifest);
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

  apply_replay_sequence(&first, tenant_id, manifest_one, manifest_one_size, manifest_two,
                        manifest_two_size);
  apply_replay_sequence(&replay, tenant_id, manifest_one, manifest_one_size, manifest_two,
                        manifest_two_size);
  check_int_eq(m3_namespace_local_store_apply_tombstone_v1(&first, 4u, tenant_id,
                                                           (const uint8_t *)"bucket", 6u,
                                                           (const uint8_t *)"object", 6u),
               M3_NAMESPACE_LOCAL_OUT_OF_ORDER);

  first_lookup = lookup(&first, tenant_id, "bucket", "object");
  replay_lookup = lookup(&replay, tenant_id, "bucket", "object");
  check_size_eq(first_lookup.calls, 1u);
  check_int_eq(first_lookup.result, M3_NAMESPACE_LOOKUP_OK);
  check_true(first_lookup.linearizable);
  check_long_eq(first_lookup.applied_index, 4u);
  check_size_eq(first_lookup.manifest_size, replay_lookup.manifest_size);
  check_mem_eq(first_lookup.manifest, replay_lookup.manifest, first_lookup.manifest_size);
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
  check_int_eq(
      m3_namespace_local_store_apply_put_v1(&store, 1u, tenant_id, (const uint8_t *)"bucket", 6u,
                                            (const uint8_t *)"one", 3u, manifest, manifest_size),
      M3_NAMESPACE_LOCAL_OK);
  check_int_eq(m3_namespace_local_store_apply_tombstone_v1(&store, 2u, tenant_id,
                                                           (const uint8_t *)"bucket", 6u,
                                                           (const uint8_t *)"one", 3u),
               M3_NAMESPACE_LOCAL_OK);
  capture = lookup(&store, tenant_id, "bucket", "one");
  check_size_eq(capture.calls, 1u);
  check_int_eq(capture.result, M3_NAMESPACE_LOOKUP_NOT_FOUND);
  check_int_eq(m3_namespace_local_store_apply_tombstone_v1(&store, 3u, tenant_id,
                                                           (const uint8_t *)"bucket", 6u,
                                                           (const uint8_t *)"missing", 7u),
               M3_NAMESPACE_LOCAL_OK);
  check_long_eq(store.applied_index, 3u);
  check_int_eq(
      m3_namespace_local_store_apply_put_v1(&store, 4u, tenant_id, (const uint8_t *)"bucket", 6u,
                                            (const uint8_t *)"two", 3u, manifest, manifest_size),
      M3_NAMESPACE_LOCAL_RESOURCE_EXHAUSTED);
  check_long_eq(store.applied_index, 3u);
  check_int_eq(m3_namespace_local_store_apply_put_v1(
                   &store, 4u, tenant_id, (const uint8_t *)"bucket", 6u, (const uint8_t *)"one", 3u,
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
  it("round-trips a persisted namespace through load") { test_persist_load_round_trip(); }
  it("treats a missing state file as a first run") { test_load_first_run_returns_empty(); }
  it("rejects corrupt persisted state") { test_load_corrupt_file_fails(); }
  it("lists buckets and prefixes deterministically") { test_list_enumerates_deterministically(); }
}
