#include <tinytest.h>

#include "m3_gateway_raft.h"
#include "m3_object_manifest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t TENANT_ID[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};

static int make_manifest(uint8_t **out_bytes, size_t *out_size) {
  m3_object_manifest_v1_t manifest;

  memset(&manifest, 0, sizeof(manifest));
  manifest.version = M3_OBJECT_MANIFEST_VERSION;
  manifest.object_cid.hash_algorithm = M3_CHUNK_STORE_HASH_ALGORITHM_SHA256;
  manifest.object_cid.size = 0u;
  memset(manifest.object_cid.digest, 1u, sizeof(manifest.object_cid.digest));
  manifest.chunks = NULL;
  manifest.chunk_count = 0u;
  return m3_object_manifest_encode_v1(&manifest, UINT64_C(1) << 30, 4096u, out_bytes, out_size) ==
                 M3_OBJECT_MANIFEST_OK
             ? 0
             : -1;
}

static int init_store(m3_namespace_local_store_v1_t *store) {
  memset(store, 0, sizeof(*store)); /* init_v1 requires a zeroed store */
  return m3_namespace_local_store_init_v1(store, 64u, 128u, 1024u, 65536u, UINT64_C(1) << 30,
                                          4096u) == M3_NAMESPACE_LOCAL_OK
             ? 0
             : -1;
}

static void fill_raft_config(m3_gateway_raft_config_v1_t *config, const char *db_path) {
  static const tr_raft_node_id_t voters[] = {1u};

  memset(config, 0, sizeof(*config));
  config->sqlite_path = db_path;
  config->self_id = 1u;
  config->voters = voters;
  config->voter_count = 1u;
  config->max_snapshot_bytes = 4u * 1024 * 1024;
  config->max_pending_reads = 64u;
}

typedef struct {
  int completed;
  int found;
} lookup_capture_t;

static void capture_lookup(m3_namespace_lookup_result_t result,
                           const m3_namespace_lookup_response_v1_t *response, void *user_data) {
  lookup_capture_t *capture = (lookup_capture_t *)user_data;

  capture->completed = 1;
  capture->found = result == M3_NAMESPACE_LOOKUP_OK && response != NULL;
}

static void make_lookup_request(m3_namespace_lookup_request_v1_t *request, const char *bucket,
                                const char *object) {
  memset(request, 0, sizeof(*request));
  memcpy(request->tenant_id, TENANT_ID, sizeof(request->tenant_id));
  request->bucket = (const uint8_t *)bucket;
  request->bucket_size = strlen(bucket);
  request->object_key = (const uint8_t *)object;
  request->object_key_size = strlen(object);
  request->require_linearizable = 1u;
}

static int drive_lookup(m3_gateway_raft_v1_t *raft, m3_namespace_lookup_adapter_v1_t lookup,
                        lookup_capture_t *capture,
                        const m3_namespace_lookup_request_v1_t *request) {
  int result = lookup.start(lookup.context, request, capture_lookup, capture);
  if (result == M3_NAMESPACE_LOOKUP_OK) {
    for (size_t i = 0u; i < 10000u && !capture->completed; i++) {
      size_t completed = 0u;
      (void)m3_gateway_raft_poll_v1(raft, &completed);
    }
  }
  return result;
}

static void test_raft_put_tombstone_roundtrip(void) {
  char *temp_dir = tt_make_temp_dir("m3-gateway-raft-");
  char db_path[512];
  m3_namespace_local_store_v1_t store;
  m3_gateway_raft_config_v1_t config;
  m3_gateway_raft_v1_t *raft = NULL;
  uint8_t *manifest = NULL;
  size_t manifest_size = 0u;
  lookup_capture_t capture = {0};
  m3_namespace_lookup_adapter_v1_t lookup;
  m3_namespace_lookup_request_v1_t request;

  check_not_null(temp_dir);
  check_true(snprintf(db_path, sizeof(db_path), "%s/meta.db", temp_dir) > 0);
  check_int_eq(0, make_manifest(&manifest, &manifest_size));
  check_int_eq(0, init_store(&store));
  fill_raft_config(&config, db_path);
  check_int_eq(TURBO_OK, m3_gateway_raft_open_v1(&config, &store, &raft));
  check_not_null(raft);

  check_int_eq(TURBO_OK,
               m3_gateway_raft_put_v1(raft, TENANT_ID, "demo", "key1", manifest, manifest_size));

  make_lookup_request(&request, "demo", "key1");
  lookup = m3_gateway_raft_lookup_v1(raft);
  check_int_eq(M3_NAMESPACE_LOOKUP_OK, drive_lookup(raft, lookup, &capture, &request));
  check_int_eq(1, capture.completed);
  check_int_eq(1, capture.found);

  memset(&capture, 0, sizeof(capture));
  check_int_eq(TURBO_OK, m3_gateway_raft_tombstone_v1(raft, TENANT_ID, "demo", "key1"));
  lookup = m3_gateway_raft_lookup_v1(raft);
  check_int_eq(M3_NAMESPACE_LOOKUP_OK, drive_lookup(raft, lookup, &capture, &request));
  check_int_eq(1, capture.completed);
  check_int_eq(0, capture.found);

  m3_gateway_raft_close_v1(raft);
  m3_namespace_local_store_destroy_v1(&store);
  m3_object_manifest_bytes_free_v1(manifest);
  check_int_eq(0, tt_remove_tree(temp_dir));
}

static void test_raft_reopen_recovers(void) {
  char *temp_dir = tt_make_temp_dir("m3-gateway-raft-");
  char db_path[512];
  m3_namespace_local_store_v1_t store;
  m3_namespace_local_store_v1_t store2;
  m3_gateway_raft_config_v1_t config;
  m3_gateway_raft_v1_t *raft = NULL;
  m3_gateway_raft_v1_t *raft2 = NULL;
  uint8_t *manifest = NULL;
  size_t manifest_size = 0u;
  lookup_capture_t capture = {0};
  m3_namespace_lookup_adapter_v1_t lookup;
  m3_namespace_lookup_request_v1_t request;

  check_not_null(temp_dir);
  check_true(snprintf(db_path, sizeof(db_path), "%s/meta.db", temp_dir) > 0);
  check_int_eq(0, make_manifest(&manifest, &manifest_size));
  check_int_eq(0, init_store(&store));
  fill_raft_config(&config, db_path);
  check_int_eq(TURBO_OK, m3_gateway_raft_open_v1(&config, &store, &raft));
  check_int_eq(TURBO_OK, m3_gateway_raft_put_v1(raft, TENANT_ID, "demo", "persisted", manifest,
                                                manifest_size));
  m3_gateway_raft_close_v1(raft);
  m3_namespace_local_store_destroy_v1(&store);

  /* Reopen against the same SQLite file: the raft log replays into a fresh
   * state machine target. */
  check_int_eq(0, init_store(&store2));
  check_int_eq(TURBO_OK, m3_gateway_raft_open_v1(&config, &store2, &raft2));
  /* read-index requires a committed entry in the current term; a leader that
   * just replayed an old-term log must first commit a write. */
  check_int_eq(TURBO_OK, m3_gateway_raft_put_v1(raft2, TENANT_ID, "demo", "after-restart", manifest,
                                                manifest_size));
  make_lookup_request(&request, "demo", "persisted");
  lookup = m3_gateway_raft_lookup_v1(raft2);
  check_int_eq(M3_NAMESPACE_LOOKUP_OK, drive_lookup(raft2, lookup, &capture, &request));
  check_int_eq(1, capture.completed);
  check_int_eq(1, capture.found);

  memset(&capture, 0, sizeof(capture));
  make_lookup_request(&request, "demo", "after-restart");
  lookup = m3_gateway_raft_lookup_v1(raft2);
  check_int_eq(M3_NAMESPACE_LOOKUP_OK, drive_lookup(raft2, lookup, &capture, &request));
  check_int_eq(1, capture.completed);
  check_int_eq(1, capture.found);

  m3_gateway_raft_close_v1(raft2);
  m3_namespace_local_store_destroy_v1(&store2);
  m3_object_manifest_bytes_free_v1(manifest);
  check_int_eq(0, tt_remove_tree(temp_dir));
}

spec("m3 gateway raft backend") {
  describe("single-voter raft metadata") {
    it("commits PUT and tombstone with linearizable reads") { test_raft_put_tombstone_roundtrip(); }
    it("recovers committed metadata after reopen") { test_raft_reopen_recovers(); }
  }
}
