#include <tinytest.h>

#include "mesh_stream_media_pull.h"

#include <turbo_crypto.h>

#include <stdlib.h>
#include <string.h>

/* P8: on-demand media range pull. A byte range (HTTP Range/206 or segment
 * seek) resolves to the covering chunk span through the media index; the pull
 * fetches exactly those chunks through an in-memory peer, verifies each
 * SHA-256 and assembles the requested window. */

#define TEST_BLOCK 1024u
#define TEST_BLOCKS 8u
#define TEST_OBJECT_SIZE (TEST_BLOCK * TEST_BLOCKS)

static uint8_t g_data[TEST_OBJECT_SIZE];

static void fill_data(void) {
  for (size_t i = 0u; i < TEST_OBJECT_SIZE; i++)
    g_data[i] = (uint8_t)(i * 7u + (i >> 4u) + 1u);
}

static void build_manifest(m3_object_manifest_v2_t *manifest,
                           m3_chunk_cid_v1_t *chunks) {
  turbo_crypto_sha256_ctx_t ctx;
  uint8_t digest[M3_CHUNK_CID_DIGEST_SIZE];

  (void)turbo_crypto_sha256_init(&ctx);
  memset(manifest, 0, sizeof(*manifest));
  memset(chunks, 0, TEST_BLOCKS * sizeof(*chunks));
  for (size_t i = 0u; i < TEST_BLOCKS; i++) {
    (void)turbo_crypto_sha256(g_data + i * TEST_BLOCK, TEST_BLOCK, chunks[i].digest);
    (void)turbo_crypto_sha256_update(&ctx, chunks[i].digest,
                                     sizeof(chunks[i].digest));
    chunks[i].hash_algorithm = M3_CHUNK_STORE_HASH_ALGORITHM_SHA256;
    chunks[i].size = TEST_BLOCK;
  }
  (void)turbo_crypto_sha256_final(&ctx, digest);
  manifest->version = M3_OBJECT_MANIFEST_VERSION_2;
  manifest->object_cid.hash_algorithm = M3_CHUNK_STORE_HASH_ALGORITHM_SHA256;
  manifest->object_cid.size = TEST_OBJECT_SIZE;
  memcpy(manifest->object_cid.digest, digest, sizeof(digest));
  manifest->chunks = chunks;
  manifest->chunk_count = TEST_BLOCKS;
}

typedef struct {
  size_t fetched_count;
  size_t fetched_indices[64];
  size_t corrupt_index;  /* SIZE_MAX = none */
  size_t pending_index;  /* first call for this chunk returns pending */
  int pending_done;
} media_peer_t;

static int peer_fetch(void *context, size_t chunk_index, uint8_t *out,
                      size_t cap, size_t *out_len) {
  media_peer_t *peer = (media_peer_t *)context;
  size_t offset = chunk_index * TEST_BLOCK;
  size_t len;

  *out_len = 0u;
  if (offset >= TEST_OBJECT_SIZE)
    return -1;
  len = TEST_OBJECT_SIZE - offset;
  if (len > TEST_BLOCK)
    len = TEST_BLOCK;
  if (cap < len)
    return -1;
  if (peer->pending_index == chunk_index && !peer->pending_done) {
    peer->pending_done = 1;
    return 1; /* pending; retry */
  }
  memcpy(out, g_data + offset, len);
  if (peer->corrupt_index == chunk_index)
    out[0] ^= 0xffu;
  *out_len = len;
  if (peer->fetched_count < 64u)
    peer->fetched_indices[peer->fetched_count] = chunk_index;
  peer->fetched_count++;
  return 0;
}

static void make_config(mesh_stream_media_pull_config_v1_t *config,
                        media_peer_t *peer) {
  memset(config, 0, sizeof(*config));
  config->io.fetch_chunk = peer_fetch;
  config->io.context = peer;
  config->max_chunk_bytes = TEST_BLOCK;
  config->target_segment_bytes = 3u * TEST_BLOCK;
}

static void run_pull(mesh_stream_media_pull_v1_t *pull, uint8_t *out,
                     size_t cap, size_t *out_len) {
  mesh_stream_media_pull_result_t rc;

  do {
    rc = mesh_stream_media_pull_pump_v1(pull, out, cap, out_len);
    check_int_eq(MESH_STREAM_MEDIA_PULL_OK, rc);
  } while (!mesh_stream_media_pull_complete(pull));
}

static void test_full_object_pull(void) {
  mesh_stream_media_pull_v1_t pull;
  mesh_stream_media_pull_config_v1_t config;
  m3_object_manifest_v2_t manifest;
  m3_chunk_cid_v1_t chunks[TEST_BLOCKS];
  media_peer_t peer;
  uint8_t out[TEST_OBJECT_SIZE];
  size_t out_len = 0u;

  fill_data();
  build_manifest(&manifest, chunks);
  memset(&peer, 0, sizeof(peer));
  peer.corrupt_index = SIZE_MAX;
  peer.pending_index = SIZE_MAX;
  make_config(&config, &peer);

  memset(&pull, 0, sizeof(pull));
  check_int_eq(MESH_STREAM_MEDIA_PULL_OK,
               mesh_stream_media_pull_init_v1(&pull, &manifest, &config));
  check_uint_eq(mesh_stream_media_pull_window_len(&pull), 0u);
  check_int_eq(MESH_STREAM_MEDIA_PULL_OK,
               mesh_stream_media_pull_start_v1(&pull, 0u, TEST_OBJECT_SIZE));
  check_uint_eq(mesh_stream_media_pull_window_len(&pull), TEST_OBJECT_SIZE);
  run_pull(&pull, out, sizeof(out), &out_len);
  check_size_eq(out_len, TEST_OBJECT_SIZE);
  check_mem_eq(out, g_data, TEST_OBJECT_SIZE);
  check_size_eq(peer.fetched_count, TEST_BLOCKS);
  check_true(mesh_stream_media_pull_complete(&pull));
  /* Idempotent pump after completion. */
  out_len = 0u;
  check_int_eq(MESH_STREAM_MEDIA_PULL_OK,
               mesh_stream_media_pull_pump_v1(&pull, out, sizeof(out), &out_len));
  check_size_eq(out_len, TEST_OBJECT_SIZE);

  mesh_stream_media_pull_destroy_v1(&pull);
}

static void test_segment_aligned_range(void) {
  mesh_stream_media_pull_v1_t pull;
  mesh_stream_media_pull_config_v1_t config;
  m3_object_manifest_v2_t manifest;
  m3_chunk_cid_v1_t chunks[TEST_BLOCKS];
  media_peer_t peer;
  uint8_t out[TEST_OBJECT_SIZE];
  size_t out_len = 0u;
  size_t first = SIZE_MAX;
  size_t count = 0u;
  uint64_t win_off = 0u;
  uint64_t win_len = 0u;

  build_manifest(&manifest, chunks);
  memset(&peer, 0, sizeof(peer));
  peer.corrupt_index = SIZE_MAX;
  peer.pending_index = SIZE_MAX;
  make_config(&config, &peer);

  memset(&pull, 0, sizeof(pull));
  check_int_eq(MESH_STREAM_MEDIA_PULL_OK,
               mesh_stream_media_pull_init_v1(&pull, &manifest, &config));
  /* Segment 1: object bytes [3072, 6144). */
  check_int_eq(MESH_STREAM_MEDIA_PULL_OK,
               mesh_stream_media_pull_resolve_v1(&pull, 3u * TEST_BLOCK,
                                                 3u * TEST_BLOCK, &first,
                                                 &count, &win_off, &win_len));
  check_size_eq(first, 3u);
  check_size_eq(count, 3u);
  check_uint_eq(win_off, 0u);
  check_uint_eq(win_len, 3u * TEST_BLOCK);

  check_int_eq(MESH_STREAM_MEDIA_PULL_OK,
               mesh_stream_media_pull_start_v1(&pull, 3u * TEST_BLOCK,
                                               3u * TEST_BLOCK));
  run_pull(&pull, out, sizeof(out), &out_len);
  check_size_eq(out_len, 3u * TEST_BLOCK);
  check_mem_eq(out, g_data + 3u * TEST_BLOCK, 3u * TEST_BLOCK);
  check_size_eq(peer.fetched_count, 3u); /* only the segment's chunks */
  check_size_eq(peer.fetched_indices[0], 3u);
  check_size_eq(peer.fetched_indices[2], 5u);

  mesh_stream_media_pull_destroy_v1(&pull);
}

static void test_mid_chunk_range(void) {
  mesh_stream_media_pull_v1_t pull;
  mesh_stream_media_pull_config_v1_t config;
  m3_object_manifest_v2_t manifest;
  m3_chunk_cid_v1_t chunks[TEST_BLOCKS];
  media_peer_t peer;
  uint8_t out[4096];
  size_t out_len = 0u;

  build_manifest(&manifest, chunks);
  memset(&peer, 0, sizeof(peer));
  peer.corrupt_index = SIZE_MAX;
  peer.pending_index = SIZE_MAX;
  make_config(&config, &peer);

  memset(&pull, 0, sizeof(pull));
  check_int_eq(MESH_STREAM_MEDIA_PULL_OK,
               mesh_stream_media_pull_init_v1(&pull, &manifest, &config));
  /* Mid-chunk start: [100, 2100) spans chunks 0..2 with a 100-byte offset. */
  check_int_eq(MESH_STREAM_MEDIA_PULL_OK,
               mesh_stream_media_pull_start_v1(&pull, 100u, 2000u));
  check_uint_eq(mesh_stream_media_pull_window_len(&pull), 2000u);
  run_pull(&pull, out, sizeof(out), &out_len);
  check_size_eq(out_len, 2000u);
  check_mem_eq(out, g_data + 100u, 2000u);
  check_size_eq(peer.fetched_count, 3u); /* chunks 0,1,2 */

  mesh_stream_media_pull_destroy_v1(&pull);
}

static void test_clamped_and_out_of_range(void) {
  mesh_stream_media_pull_v1_t pull;
  mesh_stream_media_pull_config_v1_t config;
  m3_object_manifest_v2_t manifest;
  m3_chunk_cid_v1_t chunks[TEST_BLOCKS];
  media_peer_t peer;
  uint8_t out[TEST_OBJECT_SIZE];
  size_t out_len = 0u;

  build_manifest(&manifest, chunks);
  memset(&peer, 0, sizeof(peer));
  peer.corrupt_index = SIZE_MAX;
  peer.pending_index = SIZE_MAX;
  make_config(&config, &peer);

  memset(&pull, 0, sizeof(pull));
  check_int_eq(MESH_STREAM_MEDIA_PULL_OK,
               mesh_stream_media_pull_init_v1(&pull, &manifest, &config));

  /* Past-the-end length clamps to the object tail. */
  check_int_eq(MESH_STREAM_MEDIA_PULL_OK,
               mesh_stream_media_pull_start_v1(&pull, 7000u, 100000u));
  check_uint_eq(mesh_stream_media_pull_window_len(&pull), 1192u);
  run_pull(&pull, out, sizeof(out), &out_len);
  check_size_eq(out_len, 1192u);
  check_mem_eq(out, g_data + 7000u, 1192u);
  check_size_eq(peer.fetched_count, 2u); /* chunks 6,7 */

  /* Start at/after the object end -> HTTP 416. */
  check_int_eq(MESH_STREAM_MEDIA_PULL_OUT_OF_RANGE,
               mesh_stream_media_pull_start_v1(&pull, TEST_OBJECT_SIZE, 100u));
  check_int_eq(MESH_STREAM_MEDIA_PULL_OUT_OF_RANGE,
               mesh_stream_media_pull_start_v1(&pull, TEST_OBJECT_SIZE + 100u, 10u));

  mesh_stream_media_pull_destroy_v1(&pull);
}

static void test_integrity_and_pending(void) {
  mesh_stream_media_pull_v1_t pull;
  mesh_stream_media_pull_config_v1_t config;
  m3_object_manifest_v2_t manifest;
  m3_chunk_cid_v1_t chunks[TEST_BLOCKS];
  media_peer_t peer;
  uint8_t out[TEST_OBJECT_SIZE];
  size_t out_len = 0u;

  build_manifest(&manifest, chunks);

  /* A corrupt chunk is rejected before it reaches the window. */
  memset(&peer, 0, sizeof(peer));
  peer.corrupt_index = 2u;
  peer.pending_index = SIZE_MAX;
  make_config(&config, &peer);
  memset(&pull, 0, sizeof(pull));
  check_int_eq(MESH_STREAM_MEDIA_PULL_OK,
               mesh_stream_media_pull_init_v1(&pull, &manifest, &config));
  check_int_eq(MESH_STREAM_MEDIA_PULL_OK,
               mesh_stream_media_pull_start_v1(&pull, 0u, TEST_OBJECT_SIZE));
  check_int_eq(MESH_STREAM_MEDIA_PULL_INTEGRITY,
               mesh_stream_media_pull_pump_v1(&pull, out, sizeof(out), &out_len));
  check_true(!mesh_stream_media_pull_complete(&pull));
  mesh_stream_media_pull_destroy_v1(&pull);

  /* A pending fetch returns AGAIN and succeeds on retry. */
  memset(&peer, 0, sizeof(peer));
  peer.corrupt_index = SIZE_MAX;
  peer.pending_index = 1u;
  make_config(&config, &peer);
  memset(&pull, 0, sizeof(pull));
  check_int_eq(MESH_STREAM_MEDIA_PULL_OK,
               mesh_stream_media_pull_init_v1(&pull, &manifest, &config));
  check_int_eq(MESH_STREAM_MEDIA_PULL_OK,
               mesh_stream_media_pull_start_v1(&pull, 0u, TEST_OBJECT_SIZE));
  out_len = 0u;
  check_int_eq(MESH_STREAM_MEDIA_PULL_AGAIN,
               mesh_stream_media_pull_pump_v1(&pull, out, sizeof(out), &out_len));
  run_pull(&pull, out, sizeof(out), &out_len);
  check_size_eq(out_len, TEST_OBJECT_SIZE);
  check_mem_eq(out, g_data, TEST_OBJECT_SIZE);

  mesh_stream_media_pull_destroy_v1(&pull);
}

static void test_invalid_args(void) {
  mesh_stream_media_pull_v1_t pull;
  mesh_stream_media_pull_config_v1_t config;
  m3_object_manifest_v2_t manifest;
  m3_chunk_cid_v1_t chunks[TEST_BLOCKS];
  media_peer_t peer;
  uint8_t out[TEST_OBJECT_SIZE];
  size_t out_len = 0u;

  build_manifest(&manifest, chunks);
  memset(&peer, 0, sizeof(peer));
  peer.corrupt_index = SIZE_MAX;
  peer.pending_index = SIZE_MAX;
  make_config(&config, &peer);

  memset(&pull, 0, sizeof(pull));
  check_int_eq(MESH_STREAM_MEDIA_PULL_INVALID_ARG,
               mesh_stream_media_pull_init_v1(NULL, &manifest, &config));
  check_int_eq(MESH_STREAM_MEDIA_PULL_INVALID_ARG,
               mesh_stream_media_pull_init_v1(&pull, NULL, &config));
  check_int_eq(MESH_STREAM_MEDIA_PULL_INVALID_ARG,
               mesh_stream_media_pull_init_v1(&pull, &manifest, NULL));
  config.max_chunk_bytes = 0u;
  check_int_eq(MESH_STREAM_MEDIA_PULL_INVALID_ARG,
               mesh_stream_media_pull_init_v1(&pull, &manifest, &config));
  make_config(&config, &peer);
  config.max_chunk_bytes = TEST_BLOCK / 2u; /* smaller than a chunk */
  check_int_eq(MESH_STREAM_MEDIA_PULL_INVALID_ARG,
               mesh_stream_media_pull_init_v1(&pull, &manifest, &config));
  make_config(&config, &peer);

  /* Start without init. */
  memset(&pull, 0, sizeof(pull));
  check_int_eq(MESH_STREAM_MEDIA_PULL_INVALID_ARG,
               mesh_stream_media_pull_start_v1(&pull, 0u, 100u));
  check_int_eq(MESH_STREAM_MEDIA_PULL_INVALID_ARG,
               mesh_stream_media_pull_pump_v1(&pull, out, sizeof(out), &out_len));
  check_uint_eq(mesh_stream_media_pull_window_len(&pull), 0u);
  check_true(!mesh_stream_media_pull_complete(&pull));

  check_int_eq(MESH_STREAM_MEDIA_PULL_OK,
               mesh_stream_media_pull_init_v1(&pull, &manifest, &config));
  check_int_eq(MESH_STREAM_MEDIA_PULL_INVALID_ARG,
               mesh_stream_media_pull_start_v1(&pull, 0u, 0u));
  check_int_eq(MESH_STREAM_MEDIA_PULL_OK,
               mesh_stream_media_pull_start_v1(&pull, 0u, 100u));
  check_int_eq(MESH_STREAM_MEDIA_PULL_INVALID_ARG,
               mesh_stream_media_pull_pump_v1(&pull, NULL, sizeof(out), &out_len));
  check_int_eq(MESH_STREAM_MEDIA_PULL_INVALID_ARG,
               mesh_stream_media_pull_pump_v1(&pull, out, sizeof(out), NULL));
  check_int_eq(MESH_STREAM_MEDIA_PULL_INVALID_ARG,
               mesh_stream_media_pull_pump_v1(&pull, out, 50u, &out_len));
  mesh_stream_media_pull_destroy_v1(&pull);
  mesh_stream_media_pull_destroy_v1(NULL);
}

spec("mesh stream media pull") {
    describe("media range sync") {
        it("pulls a full object through its manifest") {
            test_full_object_pull();
        }
        it("pulls a segment-aligned range (only its chunks)") {
            test_segment_aligned_range();
        }
        it("pulls a mid-chunk byte range (HTTP Range/206)") {
            test_mid_chunk_range();
        }
        it("clamps past-the-end ranges and rejects 416 starts") {
            test_clamped_and_out_of_range();
        }
        it("rejects corrupt chunks and retries pending fetches") {
            test_integrity_and_pending();
        }
        it("rejects invalid arguments") {
            test_invalid_args();
        }
    }
}