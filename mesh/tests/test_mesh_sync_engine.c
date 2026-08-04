#include <tinytest.h>

#include "mesh_sync_engine.h"

#include <turbo_crypto.h>

#include <stdlib.h>
#include <string.h>

/* P3: file sync engine. A source manifest (M3 V2) drives the sync; chunks are
 * fetched through the io, verified, written progressively to a temp file and
 * atomically renamed. The resume state records the version, present bitmap
 * and the previous version's chunks so later syncs copy reused chunks locally
 * (manifest diff) and only fetch what is missing. */

#define TEST_BLOCK 1024u
#define TEST_DATA_LEN (5u * TEST_BLOCK + 100u) /* 5 full blocks + tail */

static uint8_t g_data_a[TEST_DATA_LEN];
static uint8_t g_data_b[TEST_DATA_LEN];
static uint8_t g_data_c[TEST_DATA_LEN];

static void fill_bytes(uint8_t *out, size_t len, uint64_t seed) {
  for (size_t i = 0u; i < len; i++)
    out[i] = (uint8_t)(seed * 31u + i * 7u + (i >> 4u));
}

/* Chunk `bytes` into TEST_BLOCK blocks and encode a V2 manifest. */
static int build_manifest(const uint8_t *bytes, size_t len, uint8_t **out_bytes,
                          size_t *out_size) {
  size_t chunk_count = (len + TEST_BLOCK - 1u) / TEST_BLOCK;
  m3_chunk_cid_v1_t *chunks;
  m3_object_manifest_v2_t manifest;
  turbo_crypto_sha256_ctx_t object_ctx;
  uint8_t object_digest[M3_CHUNK_CID_DIGEST_SIZE];
  int result = -1;

  chunks = (m3_chunk_cid_v1_t *)calloc(chunk_count, sizeof(*chunks));
  if (!chunks)
    return -1;
  if (turbo_crypto_sha256_init(&object_ctx) != TURBO_CRYPTO_OK)
    goto cleanup;
  for (size_t i = 0u; i < chunk_count; i++) {
    size_t offset = i * TEST_BLOCK;
    size_t take = len - offset;

    if (take > TEST_BLOCK)
      take = TEST_BLOCK;
    if (turbo_crypto_sha256(bytes + offset, take, chunks[i].digest) !=
            TURBO_CRYPTO_OK ||
        turbo_crypto_sha256_update(&object_ctx, chunks[i].digest,
                                   sizeof(chunks[i].digest)) != TURBO_CRYPTO_OK) {
      goto cleanup;
    }
    chunks[i].hash_algorithm = M3_CHUNK_STORE_HASH_ALGORITHM_SHA256;
    chunks[i].size = take;
  }
  if (turbo_crypto_sha256_final(&object_ctx, object_digest) != TURBO_CRYPTO_OK)
    goto cleanup;

  memset(&manifest, 0, sizeof(manifest));
  manifest.version = M3_OBJECT_MANIFEST_VERSION_2;
  manifest.object_cid.hash_algorithm = M3_CHUNK_STORE_HASH_ALGORITHM_SHA256;
  manifest.object_cid.size = len;
  memcpy(manifest.object_cid.digest, object_digest, sizeof(object_digest));
  manifest.chunks = chunks;
  manifest.chunk_count = chunk_count;
  if (m3_object_manifest_encode_v2(&manifest, UINT64_C(1) << 30, 64u, 512u,
                                   out_bytes, out_size) !=
      M3_OBJECT_MANIFEST_OK) {
    goto cleanup;
  }
  result = 0;

cleanup:
  free(chunks);
  return result;
}

typedef struct {
  const uint8_t *data;
  size_t data_len;
  uint64_t block_size;
  size_t fetched_count;
  size_t fetched_indices[128];
  int fail_after; /* >=0: fail once fetched_count reaches this */
} sync_peer_t;

static int peer_fetch(void *context, size_t chunk_index, uint8_t *out,
                      size_t cap, size_t *out_len) {
  sync_peer_t *peer = (sync_peer_t *)context;
  size_t offset;
  size_t len;

  *out_len = 0u;
  if (peer->fail_after >= 0 && (int)peer->fetched_count >= peer->fail_after)
    return -1;
  offset = chunk_index * (size_t)peer->block_size;
  if (offset >= peer->data_len)
    return -1;
  len = peer->data_len - offset;
  if (len > (size_t)peer->block_size)
    len = (size_t)peer->block_size;
  if (cap < len)
    return -1;
  memcpy(out, peer->data + offset, len);
  *out_len = len;
  if (peer->fetched_count < 128u)
    peer->fetched_indices[peer->fetched_count] = chunk_index;
  peer->fetched_count++;
  return 0;
}

static int read_file(const char *path, uint8_t *out, size_t cap,
                     size_t *out_len) {
  turbo_fs_buf_t buf = {0};

  *out_len = 0u;
  if (turbo_fs_read_file(path, &buf) != 0)
    return -1;
  if (buf.len > cap) {
    turbo_fs_buf_free(&buf);
    return -1;
  }
  memcpy(out, buf.base, buf.len);
  *out_len = buf.len;
  turbo_fs_buf_free(&buf);
  return 0;
}

static void make_config(mesh_sync_config_v1_t *config, const char *state_path,
                        const char *output_path, sync_peer_t *peer) {
  memset(config, 0, sizeof(*config));
  config->io.fetch_chunk = peer_fetch;
  config->io.context = peer;
  config->conflict_policy = MESH_SYNC_CONFLICT_LAST_WRITER_WINS;
  snprintf(config->state_path, sizeof(config->state_path), "%s", state_path);
  snprintf(config->output_path, sizeof(config->output_path), "%s", output_path);
  config->max_object_bytes = UINT64_C(1) << 30;
  config->max_chunks = 64u;
  config->max_chunk_bytes = 4096u;
}

static mesh_sync_result_t run_to_complete(mesh_sync_engine_v1_t *engine) {
  for (int i = 0; i < 1000 && !mesh_sync_engine_complete(engine); i++) {
    mesh_sync_result_t rc = mesh_sync_engine_pump_v1(engine);

    if (rc == MESH_SYNC_IO || rc == MESH_SYNC_INTEGRITY ||
        rc == MESH_SYNC_RESOURCE_EXHAUSTED) {
      return rc;
    }
  }
  return mesh_sync_engine_complete(engine) ? MESH_SYNC_END : MESH_SYNC_AGAIN;
}

static void test_full_sync(void) {
  mesh_sync_config_v1_t config;
  mesh_sync_engine_v1_t engine;
  sync_peer_t peer;
  uint8_t *manifest = NULL;
  size_t manifest_size = 0u;
  uint8_t out[TEST_DATA_LEN];
  size_t out_len = 0u;
  char *dir = tt_make_temp_dir("m3-sync-full");
  char state_path[512];
  char output_path[512];

  check_not_null(dir);
  snprintf(state_path, sizeof(state_path), "%s/state.bin", dir);
  snprintf(output_path, sizeof(output_path), "%s/file.bin", dir);
  fill_bytes(g_data_a, sizeof(g_data_a), 1u);
  check_int_eq(0, build_manifest(g_data_a, sizeof(g_data_a), &manifest,
                                 &manifest_size));
  memset(&peer, 0, sizeof(peer));
  peer.data = g_data_a;
  peer.data_len = sizeof(g_data_a);
  peer.block_size = TEST_BLOCK;
  peer.fail_after = -1;
  make_config(&config, state_path, output_path, &peer);

  memset(&engine, 0, sizeof(engine));
  check_int_eq(MESH_SYNC_OK,
               mesh_sync_engine_init_v1(&engine, &config, manifest,
                                        manifest_size));
  check_int_eq(MESH_SYNC_END, run_to_complete(&engine));
  check_true(mesh_sync_engine_complete(&engine));
  check_int_eq(0, read_file(output_path, out, sizeof(out), &out_len));
  check_size_eq(out_len, sizeof(g_data_a));
  check_mem_eq(out, g_data_a, sizeof(g_data_a));
  check_size_eq(peer.fetched_count, 6u); /* 5 full blocks + tail */
  mesh_sync_engine_destroy_v1(&engine);
  m3_object_manifest_bytes_free_v2(manifest);
  check_int_eq(tt_remove_tree(dir), 0);
  free(dir);
}

static void test_incremental_noop_and_diff(void) {
  mesh_sync_config_v1_t config;
  mesh_sync_engine_v1_t engine;
  sync_peer_t peer;
  uint8_t *manifest = NULL;
  size_t manifest_size = 0u;
  uint8_t out[TEST_DATA_LEN];
  size_t out_len = 0u;
  char *dir = tt_make_temp_dir("m3-sync-incr");
  char state_path[512];
  char output_path[512];

  check_not_null(dir);
  snprintf(state_path, sizeof(state_path), "%s/state.bin", dir);
  snprintf(output_path, sizeof(output_path), "%s/file.bin", dir);
  fill_bytes(g_data_a, sizeof(g_data_a), 1u);
  fill_bytes(g_data_b, sizeof(g_data_b), 2u);
  memcpy(g_data_b + TEST_BLOCK, g_data_a + TEST_BLOCK,
         sizeof(g_data_b) - TEST_BLOCK); /* only chunk 0 differs */

  /* First: full sync of A. */
  check_int_eq(0, build_manifest(g_data_a, sizeof(g_data_a), &manifest,
                                 &manifest_size));
  memset(&peer, 0, sizeof(peer));
  peer.data = g_data_a;
  peer.data_len = sizeof(g_data_a);
  peer.block_size = TEST_BLOCK;
  peer.fail_after = -1;
  make_config(&config, state_path, output_path, &peer);
  memset(&engine, 0, sizeof(engine));
  check_int_eq(MESH_SYNC_OK,
               mesh_sync_engine_init_v1(&engine, &config, manifest,
                                        manifest_size));
  check_int_eq(MESH_SYNC_END, run_to_complete(&engine));
  mesh_sync_engine_destroy_v1(&engine);

  /* No-op: same manifest again -> nothing fetched, output untouched. */
  memset(&peer, 0, sizeof(peer));
  peer.data = g_data_a;
  peer.data_len = sizeof(g_data_a);
  peer.block_size = TEST_BLOCK;
  peer.fail_after = -1;
  make_config(&config, state_path, output_path, &peer);
  memset(&engine, 0, sizeof(engine));
  check_int_eq(MESH_SYNC_OK,
               mesh_sync_engine_init_v1(&engine, &config, manifest,
                                        manifest_size));
  check_true(mesh_sync_engine_complete(&engine)); /* already committed */
  check_int_eq(MESH_SYNC_END, run_to_complete(&engine));
  check_size_eq(peer.fetched_count, 0u);
  check_int_eq(0, read_file(output_path, out, sizeof(out), &out_len));
  check_mem_eq(out, g_data_a, sizeof(g_data_a));
  mesh_sync_engine_destroy_v1(&engine);
  m3_object_manifest_bytes_free_v2(manifest);

  /* Incremental: B differs only in chunk 0 -> fetch only chunk 0; chunks 1..4
   * are copied from the previous committed output (manifest diff). */
  check_int_eq(0, build_manifest(g_data_b, sizeof(g_data_b), &manifest,
                                 &manifest_size));
  memset(&peer, 0, sizeof(peer));
  peer.data = g_data_b;
  peer.data_len = sizeof(g_data_b);
  peer.block_size = TEST_BLOCK;
  peer.fail_after = -1;
  make_config(&config, state_path, output_path, &peer);
  memset(&engine, 0, sizeof(engine));
  check_int_eq(MESH_SYNC_OK,
               mesh_sync_engine_init_v1(&engine, &config, manifest,
                                        manifest_size));
  check_int_eq(MESH_SYNC_END, run_to_complete(&engine));
  check_true(mesh_sync_engine_complete(&engine));
  check_int_eq(0, read_file(output_path, out, sizeof(out), &out_len));
  check_size_eq(out_len, sizeof(g_data_b));
  check_mem_eq(out, g_data_b, sizeof(g_data_b));
  check_size_eq(peer.fetched_count, 1u);
  check_size_eq(peer.fetched_indices[0], 0u); /* only the differing chunk */
  mesh_sync_engine_destroy_v1(&engine);
  m3_object_manifest_bytes_free_v2(manifest);

  check_int_eq(tt_remove_tree(dir), 0);
  free(dir);
}

static void test_resume(void) {
  mesh_sync_config_v1_t config;
  mesh_sync_engine_v1_t engine;
  sync_peer_t peer;
  uint8_t *manifest = NULL;
  size_t manifest_size = 0u;
  uint8_t out[TEST_DATA_LEN];
  size_t out_len = 0u;
  char *dir = tt_make_temp_dir("m3-sync-resume");
  char state_path[512];
  char output_path[512];

  check_not_null(dir);
  snprintf(state_path, sizeof(state_path), "%s/state.bin", dir);
  snprintf(output_path, sizeof(output_path), "%s/file.bin", dir);
  fill_bytes(g_data_a, sizeof(g_data_a), 3u);
  check_int_eq(0, build_manifest(g_data_a, sizeof(g_data_a), &manifest,
                                 &manifest_size));

  /* Interrupted after two chunks (the peer refuses the third fetch). */
  memset(&peer, 0, sizeof(peer));
  peer.data = g_data_a;
  peer.data_len = sizeof(g_data_a);
  peer.block_size = TEST_BLOCK;
  peer.fail_after = 2;
  make_config(&config, state_path, output_path, &peer);
  memset(&engine, 0, sizeof(engine));
  check_int_eq(MESH_SYNC_OK,
               mesh_sync_engine_init_v1(&engine, &config, manifest,
                                        manifest_size));
  check_int_eq(MESH_SYNC_IO, run_to_complete(&engine));
  check_true(!mesh_sync_engine_complete(&engine));
  mesh_sync_engine_destroy_v1(&engine);

  /* Resume: the peer serves again; only the missing chunks are fetched. */
  memset(&peer, 0, sizeof(peer));
  peer.data = g_data_a;
  peer.data_len = sizeof(g_data_a);
  peer.block_size = TEST_BLOCK;
  peer.fail_after = -1;
  make_config(&config, state_path, output_path, &peer);
  memset(&engine, 0, sizeof(engine));
  check_int_eq(MESH_SYNC_OK,
               mesh_sync_engine_init_v1(&engine, &config, manifest,
                                        manifest_size));
  check_int_eq(MESH_SYNC_END, run_to_complete(&engine));
  check_true(mesh_sync_engine_complete(&engine));
  check_int_eq(0, read_file(output_path, out, sizeof(out), &out_len));
  check_size_eq(out_len, sizeof(g_data_a));
  check_mem_eq(out, g_data_a, sizeof(g_data_a));
  check_size_eq(peer.fetched_count, 4u); /* chunks 2..5 resumed */
  mesh_sync_engine_destroy_v1(&engine);
  m3_object_manifest_bytes_free_v2(manifest);

  check_int_eq(tt_remove_tree(dir), 0);
  free(dir);
}

static void test_conflict_policies(void) {
  mesh_sync_config_v1_t config;
  mesh_sync_engine_v1_t engine;
  sync_peer_t peer;
  uint8_t *manifest = NULL;
  size_t manifest_size = 0u;
  uint8_t out[TEST_DATA_LEN];
  size_t out_len = 0u;
  char *dir = tt_make_temp_dir("m3-sync-conflict");
  char state_path[512];
  char output_path[512];

  check_not_null(dir);
  snprintf(state_path, sizeof(state_path), "%s/state.bin", dir);
  snprintf(output_path, sizeof(output_path), "%s/file.bin", dir);
  fill_bytes(g_data_a, sizeof(g_data_a), 4u);
  fill_bytes(g_data_b, sizeof(g_data_b), 5u);
  check_int_eq(0, build_manifest(g_data_a, sizeof(g_data_a), &manifest,
                                 &manifest_size));
  memset(&peer, 0, sizeof(peer));
  peer.data = g_data_a;
  peer.data_len = sizeof(g_data_a);
  peer.block_size = TEST_BLOCK;
  peer.fail_after = -1;
  make_config(&config, state_path, output_path, &peer);
  memset(&engine, 0, sizeof(engine));
  check_int_eq(MESH_SYNC_OK,
               mesh_sync_engine_init_v1(&engine, &config, manifest,
                                        manifest_size));
  check_int_eq(MESH_SYNC_END, run_to_complete(&engine));
  mesh_sync_engine_destroy_v1(&engine);
  m3_object_manifest_bytes_free_v2(manifest);

  /* KEEP_BOTH: syncing B renames the committed A to a conflict copy. */
  check_int_eq(0, build_manifest(g_data_b, sizeof(g_data_b), &manifest,
                                 &manifest_size));
  memset(&peer, 0, sizeof(peer));
  peer.data = g_data_b;
  peer.data_len = sizeof(g_data_b);
  peer.block_size = TEST_BLOCK;
  peer.fail_after = -1;
  make_config(&config, state_path, output_path, &peer);
  config.conflict_policy = MESH_SYNC_CONFLICT_KEEP_BOTH;
  memset(&engine, 0, sizeof(engine));
  check_int_eq(MESH_SYNC_OK,
               mesh_sync_engine_init_v1(&engine, &config, manifest,
                                        manifest_size));
  check_uint_eq(mesh_sync_engine_conflict(&engine), 1u);
  check_not_null(mesh_sync_engine_conflict_path(&engine));
  check_int_eq(MESH_SYNC_END, run_to_complete(&engine));
  check_int_eq(0, read_file(output_path, out, sizeof(out), &out_len));
  check_mem_eq(out, g_data_b, sizeof(g_data_b));
  check_int_eq(0, read_file(mesh_sync_engine_conflict_path(&engine), out,
                            sizeof(out), &out_len));
  check_mem_eq(out, g_data_a, sizeof(g_data_a));
  mesh_sync_engine_destroy_v1(&engine);
  m3_object_manifest_bytes_free_v2(manifest);

  /* LAST_WRITER_WINS: syncing an even newer C simply overwrites the current
   * output; no conflict copy is kept. */
  fill_bytes(g_data_c, sizeof(g_data_c), 6u);
  check_int_eq(0, build_manifest(g_data_c, sizeof(g_data_c), &manifest,
                                 &manifest_size));
  memset(&peer, 0, sizeof(peer));
  peer.data = g_data_c;
  peer.data_len = sizeof(g_data_c);
  peer.block_size = TEST_BLOCK;
  peer.fail_after = -1;
  make_config(&config, state_path, output_path, &peer);
  config.conflict_policy = MESH_SYNC_CONFLICT_LAST_WRITER_WINS;
  memset(&engine, 0, sizeof(engine));
  check_int_eq(MESH_SYNC_OK,
               mesh_sync_engine_init_v1(&engine, &config, manifest,
                                        manifest_size));
  check_uint_eq(mesh_sync_engine_conflict(&engine), 1u); /* replaced */
  check_null(mesh_sync_engine_conflict_path(&engine));
  check_int_eq(MESH_SYNC_END, run_to_complete(&engine));
  check_int_eq(0, read_file(output_path, out, sizeof(out), &out_len));
  check_mem_eq(out, g_data_c, sizeof(g_data_c));
  mesh_sync_engine_destroy_v1(&engine);
  m3_object_manifest_bytes_free_v2(manifest);

  check_int_eq(tt_remove_tree(dir), 0);
  free(dir);
}

static void test_invalid_args(void) {
  mesh_sync_engine_v1_t engine;
  mesh_sync_config_v1_t config;
  sync_peer_t peer;
  uint8_t manifest[128] = {0};

  memset(&engine, 0, sizeof(engine));
  memset(&peer, 0, sizeof(peer));
  peer.data = g_data_a;
  peer.data_len = sizeof(g_data_a);
  peer.block_size = TEST_BLOCK;
  make_config(&config, "state", "out", &peer);
  check_int_eq(MESH_SYNC_INVALID_ARG,
               mesh_sync_engine_init_v1(NULL, &config, manifest, sizeof(manifest)));
  check_int_eq(MESH_SYNC_INVALID_ARG,
               mesh_sync_engine_init_v1(&engine, NULL, manifest, sizeof(manifest)));
  config.io.fetch_chunk = NULL;
  check_int_eq(MESH_SYNC_INVALID_ARG,
               mesh_sync_engine_init_v1(&engine, &config, manifest, sizeof(manifest)));
  check_int_eq(MESH_SYNC_INVALID_ARG, mesh_sync_engine_pump_v1(NULL));
}

spec("mesh sync engine") {
    describe("file sync") {
        it("syncs a full file with per-chunk verification") {
            test_full_sync();
        }
        it("skips a no-op sync and fetches only the diff for incremental changes") {
            test_incremental_noop_and_diff();
        }
        it("resumes from the committed offset after an interruption") {
            test_resume();
        }
        it("applies keep-both and last-writer-wins conflict policies") {
            test_conflict_policies();
        }
        it("rejects invalid arguments") {
            test_invalid_args();
        }
    }
}
