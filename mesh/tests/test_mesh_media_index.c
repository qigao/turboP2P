#include <tinytest.h>

#include "mesh_media_index.h"

#include <turbo_crypto.h>

#include <stdlib.h>
#include <string.h>

/* P4: media segment index + ABR. The index derives chunk-aligned segments
 * from an M3 V2 manifest so a client can seek (segment lookup), serve HTTP
 * Range/206 (byte range -> chunk span) and pick the best rendition for the
 * measured bandwidth. The manifest is the fact source; the index is rebuilt
 * from it and never mutates it. */

#define TEST_BLOCK 1024u
#define TEST_BLOCKS 8u
#define TEST_OBJECT_SIZE (TEST_BLOCK * TEST_BLOCKS)

static uint8_t g_block_data[TEST_BLOCKS][TEST_BLOCK];

static void fill_blocks(void) {
  for (size_t b = 0u; b < TEST_BLOCKS; b++) {
    for (size_t i = 0u; i < TEST_BLOCK; i++)
      g_block_data[b][i] = (uint8_t)(b * 31u + i * 7u + (i >> 4u));
  }
}

static void build_manifest(m3_object_manifest_v2_t *manifest,
                           m3_chunk_cid_v1_t *chunks) {
  turbo_crypto_sha256_ctx_t ctx;
  uint8_t digest[M3_CHUNK_CID_DIGEST_SIZE];

  (void)turbo_crypto_sha256_init(&ctx);
  memset(manifest, 0, sizeof(*manifest));
  memset(chunks, 0, TEST_BLOCKS * sizeof(*chunks));
  for (size_t i = 0u; i < TEST_BLOCKS; i++) {
    (void)turbo_crypto_sha256(g_block_data[i], TEST_BLOCK, chunks[i].digest);
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

static void test_segment_build(void) {
  mesh_media_index_v1_t index;
  m3_object_manifest_v2_t manifest;
  m3_chunk_cid_v1_t chunks[TEST_BLOCKS];
  uint64_t sum = 0u;

  fill_blocks();
  build_manifest(&manifest, chunks);

  /* Target 3 KiB -> segments of 3, 3 and 2 chunks. */
  memset(&index, 0, sizeof(index));
  check_int_eq(MESH_MEDIA_INDEX_OK,
               mesh_media_index_build_v1(&index, &manifest, 3u * TEST_BLOCK));
  check_size_eq(index.segment_count, 3u);
  check_uint_eq(index.object_size, TEST_OBJECT_SIZE);
  check_uint_eq(index.segments[0].byte_offset, 0u);
  check_uint_eq(index.segments[0].byte_len, 3u * TEST_BLOCK);
  check_size_eq(index.segments[0].first_chunk, 0u);
  check_size_eq(index.segments[0].chunk_count, 3u);
  check_uint_eq(index.segments[1].byte_offset, 3u * TEST_BLOCK);
  check_uint_eq(index.segments[1].byte_len, 3u * TEST_BLOCK);
  check_size_eq(index.segments[1].first_chunk, 3u);
  check_size_eq(index.segments[1].chunk_count, 3u);
  check_uint_eq(index.segments[2].byte_offset, 6u * TEST_BLOCK);
  check_uint_eq(index.segments[2].byte_len, 2u * TEST_BLOCK);
  check_size_eq(index.segments[2].first_chunk, 6u);
  check_size_eq(index.segments[2].chunk_count, 2u);
  for (size_t s = 0u; s < index.segment_count; s++)
    sum += index.segments[s].byte_len;
  check_uint_eq(sum, TEST_OBJECT_SIZE); /* contiguous, no gaps */
  mesh_media_index_destroy_v1(&index);

  /* Default target larger than the object -> a single segment. */
  memset(&index, 0, sizeof(index));
  check_int_eq(MESH_MEDIA_INDEX_OK,
               mesh_media_index_build_v1(&index, &manifest,
                                         MESH_MEDIA_INDEX_DEFAULT_SEGMENT_BYTES));
  check_size_eq(index.segment_count, 1u);
  check_size_eq(index.segments[0].chunk_count, TEST_BLOCKS);
  mesh_media_index_destroy_v1(&index);

  /* Target smaller than a chunk -> one segment per chunk. */
  memset(&index, 0, sizeof(index));
  check_int_eq(MESH_MEDIA_INDEX_OK,
               mesh_media_index_build_v1(&index, &manifest, TEST_BLOCK / 2u));
  check_size_eq(index.segment_count, TEST_BLOCKS);
  for (size_t s = 0u; s < index.segment_count; s++) {
    check_size_eq(index.segments[s].chunk_count, 1u);
    check_uint_eq(index.segments[s].byte_len, TEST_BLOCK);
  }
  mesh_media_index_destroy_v1(&index);
}

static void test_seek_segments(void) {
  mesh_media_index_v1_t index;
  m3_object_manifest_v2_t manifest;
  m3_chunk_cid_v1_t chunks[TEST_BLOCKS];
  size_t seg = SIZE_MAX;

  build_manifest(&manifest, chunks);
  memset(&index, 0, sizeof(index));
  check_int_eq(MESH_MEDIA_INDEX_OK,
               mesh_media_index_build_v1(&index, &manifest, 3u * TEST_BLOCK));

  check_int_eq(MESH_MEDIA_INDEX_OK,
               mesh_media_index_segment_at_v1(&index, 0u, &seg));
  check_size_eq(seg, 0u);
  check_int_eq(MESH_MEDIA_INDEX_OK,
               mesh_media_index_segment_at_v1(&index, TEST_BLOCK, &seg));
  check_size_eq(seg, 0u);
  check_int_eq(MESH_MEDIA_INDEX_OK,
               mesh_media_index_segment_at_v1(&index, 3u * TEST_BLOCK - 1u, &seg));
  check_size_eq(seg, 0u);
  check_int_eq(MESH_MEDIA_INDEX_OK,
               mesh_media_index_segment_at_v1(&index, 3u * TEST_BLOCK, &seg));
  check_size_eq(seg, 1u);
  check_int_eq(MESH_MEDIA_INDEX_OK,
               mesh_media_index_segment_at_v1(&index, 6u * TEST_BLOCK, &seg));
  check_size_eq(seg, 2u);
  check_int_eq(MESH_MEDIA_INDEX_OK,
               mesh_media_index_segment_at_v1(&index, TEST_OBJECT_SIZE - 1u, &seg));
  check_size_eq(seg, 2u);
  check_int_eq(MESH_MEDIA_INDEX_OUT_OF_RANGE,
               mesh_media_index_segment_at_v1(&index, TEST_OBJECT_SIZE, &seg));
  check_int_eq(MESH_MEDIA_INDEX_OUT_OF_RANGE,
               mesh_media_index_segment_at_v1(&index, TEST_OBJECT_SIZE + 100u, &seg));
  check_int_eq(MESH_MEDIA_INDEX_INVALID_ARG,
               mesh_media_index_segment_at_v1(NULL, 0u, &seg));
  check_int_eq(MESH_MEDIA_INDEX_INVALID_ARG,
               mesh_media_index_segment_at_v1(&index, 0u, NULL));

  mesh_media_index_destroy_v1(&index);
}

static void test_resolve_range(void) {
  mesh_media_index_v1_t index;
  m3_object_manifest_v2_t manifest;
  m3_chunk_cid_v1_t chunks[TEST_BLOCKS];
  size_t first = SIZE_MAX;
  size_t count = 0u;
  uint64_t window_offset = 0u;
  uint64_t window_len = 0u;

  build_manifest(&manifest, chunks);
  memset(&index, 0, sizeof(index));
  check_int_eq(MESH_MEDIA_INDEX_OK,
               mesh_media_index_build_v1(&index, &manifest, 3u * TEST_BLOCK));

  /* Whole object -> all chunks, no window offset. */
  check_int_eq(MESH_MEDIA_INDEX_OK,
               mesh_media_index_resolve_range_v1(&index, &manifest, 0u,
                                                 TEST_OBJECT_SIZE, &first,
                                                 &count, &window_offset,
                                                 &window_len));
  check_size_eq(first, 0u);
  check_size_eq(count, TEST_BLOCKS);
  check_uint_eq(window_offset, 0u);
  check_uint_eq(window_len, TEST_OBJECT_SIZE);

  /* Mid-chunk start: [100, 2100) spans chunks 0..2. */
  check_int_eq(MESH_MEDIA_INDEX_OK,
               mesh_media_index_resolve_range_v1(&index, &manifest, 100u,
                                                 2000u, &first, &count,
                                                 &window_offset, &window_len));
  check_size_eq(first, 0u);
  check_size_eq(count, 3u);
  check_uint_eq(window_offset, 100u);
  check_uint_eq(window_len, 2000u);

  /* Spanning a segment boundary: [2548, 4548) covers chunks 2..4. */
  check_int_eq(MESH_MEDIA_INDEX_OK,
               mesh_media_index_resolve_range_v1(&index, &manifest, 2548u,
                                                 2000u, &first, &count,
                                                 &window_offset, &window_len));
  check_size_eq(first, 2u);
  check_size_eq(count, 3u);
  check_uint_eq(window_offset, 500u);
  check_uint_eq(window_len, 2000u);

  /* Chunk-boundary-aligned single chunk: [1024, 2048). */
  check_int_eq(MESH_MEDIA_INDEX_OK,
               mesh_media_index_resolve_range_v1(&index, &manifest, TEST_BLOCK,
                                                 TEST_BLOCK, &first, &count,
                                                 &window_offset, &window_len));
  check_size_eq(first, 1u);
  check_size_eq(count, 1u);
  check_uint_eq(window_offset, 0u);
  check_uint_eq(window_len, TEST_BLOCK);

  /* Range past the end is clamped (HTTP 206 with a truncated window). */
  check_int_eq(MESH_MEDIA_INDEX_OK,
               mesh_media_index_resolve_range_v1(&index, &manifest, 7000u,
                                                 100000u, &first, &count,
                                                 &window_offset, &window_len));
  check_size_eq(first, 6u);
  check_size_eq(count, 2u);
  check_uint_eq(window_offset, 856u);
  check_uint_eq(window_len, 1192u);

  /* Start at/after the object end -> HTTP 416 semantics. */
  check_int_eq(MESH_MEDIA_INDEX_OUT_OF_RANGE,
               mesh_media_index_resolve_range_v1(&index, &manifest,
                                                 TEST_OBJECT_SIZE, 100u, &first,
                                                 &count, &window_offset,
                                                 &window_len));
  check_int_eq(MESH_MEDIA_INDEX_OUT_OF_RANGE,
               mesh_media_index_resolve_range_v1(&index, &manifest,
                                                 TEST_OBJECT_SIZE + 100u, 10u,
                                                 &first, &count, &window_offset,
                                                 &window_len));

  check_int_eq(MESH_MEDIA_INDEX_INVALID_ARG,
               mesh_media_index_resolve_range_v1(&index, &manifest, 0u, 0u,
                                                 &first, &count, &window_offset,
                                                 &window_len));
  check_int_eq(MESH_MEDIA_INDEX_INVALID_ARG,
               mesh_media_index_resolve_range_v1(NULL, &manifest, 0u, 100u,
                                                 &first, &count, &window_offset,
                                                 &window_len));
  check_int_eq(MESH_MEDIA_INDEX_INVALID_ARG,
               mesh_media_index_resolve_range_v1(&index, NULL, 0u, 100u,
                                                 &first, &count, &window_offset,
                                                 &window_len));

  mesh_media_index_destroy_v1(&index);
}

static void test_abr_select(void) {
  mesh_media_abr_rendition_v1_t ladder[MESH_MEDIA_ABR_MAX_RENDITIONS];
  size_t picked = SIZE_MAX;

  memset(ladder, 0, sizeof(ladder));
  snprintf(ladder[0].id, sizeof(ladder[0].id), "p240");
  ladder[0].bandwidth_bps = 300000u;
  snprintf(ladder[1].id, sizeof(ladder[1].id), "p480");
  ladder[1].bandwidth_bps = 1000000u;
  snprintf(ladder[2].id, sizeof(ladder[2].id), "p720");
  ladder[2].bandwidth_bps = 2500000u;
  snprintf(ladder[3].id, sizeof(ladder[3].id), "p1080");
  ladder[3].bandwidth_bps = 5000000u;

  check_int_eq(MESH_MEDIA_INDEX_OK,
               mesh_media_abr_select_v1(ladder, 4u, 800000u, &picked));
  check_size_eq(picked, 0u); /* only 240p fits */
  check_int_eq(MESH_MEDIA_INDEX_OK,
               mesh_media_abr_select_v1(ladder, 4u, 1000000u, &picked));
  check_size_eq(picked, 1u); /* 480p fits at exactly its bitrate */
  check_int_eq(MESH_MEDIA_INDEX_OK,
               mesh_media_abr_select_v1(ladder, 4u, 3000000u, &picked));
  check_size_eq(picked, 2u);
  check_int_eq(MESH_MEDIA_INDEX_OK,
               mesh_media_abr_select_v1(ladder, 4u, 6000000u, &picked));
  check_size_eq(picked, 3u);
  /* Below every bitrate: degrade to the lowest instead of failing. */
  check_int_eq(MESH_MEDIA_INDEX_OK,
               mesh_media_abr_select_v1(ladder, 4u, 200000u, &picked));
  check_size_eq(picked, 0u);

  /* Duplicate bitrate: ties keep the lowest index. */
  snprintf(ladder[4].id, sizeof(ladder[4].id), "p480b");
  ladder[4].bandwidth_bps = 1000000u;
  check_int_eq(MESH_MEDIA_INDEX_OK,
               mesh_media_abr_select_v1(ladder, 5u, 1000000u, &picked));
  check_size_eq(picked, 1u);

  /* Selection does not assume a sorted ladder. */
  {
    mesh_media_abr_rendition_v1_t shuffled[3];

    memset(shuffled, 0, sizeof(shuffled));
    shuffled[0].bandwidth_bps = 2500000u;
    shuffled[1].bandwidth_bps = 300000u;
    shuffled[2].bandwidth_bps = 5000000u;
    check_int_eq(MESH_MEDIA_INDEX_OK,
                 mesh_media_abr_select_v1(shuffled, 3u, 2000000u, &picked));
    check_size_eq(picked, 1u); /* only 300k fits */
  }

  check_int_eq(MESH_MEDIA_INDEX_INVALID_ARG,
               mesh_media_abr_select_v1(NULL, 4u, 1000000u, &picked));
  check_int_eq(MESH_MEDIA_INDEX_INVALID_ARG,
               mesh_media_abr_select_v1(ladder, 0u, 1000000u, &picked));
  check_int_eq(MESH_MEDIA_INDEX_INVALID_ARG,
               mesh_media_abr_select_v1(ladder, MESH_MEDIA_ABR_MAX_RENDITIONS + 1u,
                                        1000000u, &picked));
  check_int_eq(MESH_MEDIA_INDEX_INVALID_ARG,
               mesh_media_abr_select_v1(ladder, 4u, 1000000u, NULL));
}

static void test_abr_session_dynamic(void) {
  mesh_media_abr_rendition_v1_t ladder[4];
  mesh_media_abr_session_v1_t session;
  mesh_media_abr_session_config_v1_t config;
  size_t idx = SIZE_MAX;

  memset(ladder, 0, sizeof(ladder));
  ladder[0].bandwidth_bps = 300000u;
  ladder[1].bandwidth_bps = 1000000u;
  ladder[2].bandwidth_bps = 2500000u;
  ladder[3].bandwidth_bps = 5000000u;

  /* Immediate drop when the current tier is no longer sustainable. */
  config.stable_observations = 3u;
  config.min_interval_ms = 0u;
  check_int_eq(MESH_MEDIA_INDEX_OK,
               mesh_media_abr_session_init_v1(&session, &config, 3u));
  check_int_eq(MESH_MEDIA_INDEX_OK,
               mesh_media_abr_session_observe_v1(&session, ladder, 4u, 800000u,
                                                 100u, &idx));
  check_size_eq(idx, 0u); /* 5 Mbps -> 300 kbps (highest fit) */
  check_uint_eq(session.switches_down, 1u);
  check_uint_eq(session.switches_total, 1u);

  /* Conservative climb one tier at a time: 3 stable samples per tier. */
  for (size_t t = 200u; t <= 400u; t += 100u) {
    check_int_eq(MESH_MEDIA_INDEX_OK,
                 mesh_media_abr_session_observe_v1(&session, ladder, 4u, 6000000u,
                                                   t, &idx));
  }
  check_size_eq(idx, 1u); /* 300k -> 1000k */
  check_uint_eq(session.switches_up, 1u);
  for (size_t t = 500u; t <= 700u; t += 100u) {
    check_int_eq(MESH_MEDIA_INDEX_OK,
                 mesh_media_abr_session_observe_v1(&session, ladder, 4u, 6000000u,
                                                   t, &idx));
  }
  check_size_eq(idx, 2u); /* 1000k -> 2500k */
  for (size_t t = 800u; t <= 1000u; t += 100u) {
    check_int_eq(MESH_MEDIA_INDEX_OK,
                 mesh_media_abr_session_observe_v1(&session, ladder, 4u, 6000000u,
                                                   t, &idx));
  }
  check_size_eq(idx, 3u); /* 2500k -> 5000k */
  check_uint_eq(session.switches_up, 3u);

  /* Jitter never triggers a climb (up-candidates keep resetting). */
  check_int_eq(MESH_MEDIA_INDEX_OK,
               mesh_media_abr_session_init_v1(&session, &config, 2u));
  check_int_eq(MESH_MEDIA_INDEX_OK,
               mesh_media_abr_session_observe_v1(&session, ladder, 4u, 2400000u,
                                                 0u, &idx));
  check_size_eq(idx, 1u); /* 2500k -> 1000k */
  for (size_t i = 0u; i < 6u; i++) {
    uint64_t bps = (i % 2u == 0u) ? 2600000u : 2400000u;

    check_int_eq(MESH_MEDIA_INDEX_OK,
                 mesh_media_abr_session_observe_v1(&session, ladder, 4u, bps,
                                                   10u * (i + 1u), &idx));
  }
  check_size_eq(idx, 1u); /* stuck at 1000k, no oscillation */
  check_uint_eq(session.switches_total, 1u);

  /* The min interval gates up-switches even when the signal is stable. */
  config.stable_observations = 2u;
  config.min_interval_ms = 1000u;
  check_int_eq(MESH_MEDIA_INDEX_OK,
               mesh_media_abr_session_init_v1(&session, &config, 0u));
  check_int_eq(MESH_MEDIA_INDEX_OK,
               mesh_media_abr_session_observe_v1(&session, ladder, 4u, 6000000u,
                                                 100u, &idx));
  check_int_eq(MESH_MEDIA_INDEX_OK,
               mesh_media_abr_session_observe_v1(&session, ladder, 4u, 6000000u,
                                                 200u, &idx));
  check_size_eq(idx, 0u); /* stable count reached but interval not elapsed */
  check_int_eq(MESH_MEDIA_INDEX_OK,
               mesh_media_abr_session_observe_v1(&session, ladder, 4u, 6000000u,
                                                 1500u, &idx));
  check_size_eq(idx, 1u); /* interval elapsed -> 300k -> 1000k */

  /* Already at the top: nothing to climb to. */
  check_int_eq(MESH_MEDIA_INDEX_OK,
               mesh_media_abr_session_init_v1(&session, &config, 3u));
  check_int_eq(MESH_MEDIA_INDEX_OK,
               mesh_media_abr_session_observe_v1(&session, ladder, 4u, 6000000u,
                                                 0u, &idx));
  check_size_eq(idx, 3u);
  check_uint_eq(session.switches_total, 0u);

  /* Invalid arguments. */
  check_int_eq(MESH_MEDIA_INDEX_INVALID_ARG,
               mesh_media_abr_session_init_v1(NULL, &config, 0u));
  config.stable_observations = 0u;
  check_int_eq(MESH_MEDIA_INDEX_INVALID_ARG,
               mesh_media_abr_session_init_v1(&session, &config, 0u));
  config.stable_observations = 3u;
  check_int_eq(MESH_MEDIA_INDEX_INVALID_ARG,
               mesh_media_abr_session_observe_v1(NULL, ladder, 4u, 1000000u, 0u,
                                                 &idx));
  check_int_eq(MESH_MEDIA_INDEX_INVALID_ARG,
               mesh_media_abr_session_observe_v1(&session, NULL, 4u, 1000000u, 0u,
                                                 &idx));
  check_int_eq(MESH_MEDIA_INDEX_INVALID_ARG,
               mesh_media_abr_session_observe_v1(&session, ladder, 0u, 1000000u, 0u,
                                                 &idx));
  check_int_eq(MESH_MEDIA_INDEX_INVALID_ARG,
               mesh_media_abr_session_observe_v1(&session, ladder, 4u, 1000000u, 0u,
                                                 NULL));
  /* init stores the index; observe rejects one out of range for the ladder. */
  check_int_eq(MESH_MEDIA_INDEX_OK,
               mesh_media_abr_session_init_v1(&session, &config, 99u));
  check_int_eq(MESH_MEDIA_INDEX_INVALID_ARG,
               mesh_media_abr_session_observe_v1(&session, ladder, 4u, 1000000u, 0u,
                                                 &idx));
}

static void test_invalid_args(void) {
  mesh_media_index_v1_t index;
  m3_object_manifest_v2_t manifest;
  m3_chunk_cid_v1_t chunks[TEST_BLOCKS];

  build_manifest(&manifest, chunks);

  memset(&index, 0, sizeof(index));
  check_int_eq(MESH_MEDIA_INDEX_INVALID_ARG,
               mesh_media_index_build_v1(NULL, &manifest, 1024u));
  check_int_eq(MESH_MEDIA_INDEX_INVALID_ARG,
               mesh_media_index_build_v1(&index, NULL, 1024u));
  check_int_eq(MESH_MEDIA_INDEX_INVALID_ARG,
               mesh_media_index_build_v1(&index, &manifest, 0u));
  {
    m3_object_manifest_v2_t empty = {0};

    check_int_eq(MESH_MEDIA_INDEX_INVALID_ARG,
                 mesh_media_index_build_v1(&index, &empty, 1024u));
  }
  /* Chunk sizes must sum exactly to the object size. */
  {
    m3_chunk_cid_v1_t bad[TEST_BLOCKS];

    memcpy(bad, chunks, sizeof(bad));
    manifest.chunks = bad;
    bad[0].size = TEST_BLOCK / 2u;
    check_int_eq(MESH_MEDIA_INDEX_INVALID_ARG,
                 mesh_media_index_build_v1(&index, &manifest, 1024u));
    bad[0].size = 0u;
    check_int_eq(MESH_MEDIA_INDEX_INVALID_ARG,
                 mesh_media_index_build_v1(&index, &manifest, 1024u));
    manifest.chunks = chunks; /* restore the valid view */
  }
  /* Rebuilding without destroying first is rejected. */
  check_int_eq(MESH_MEDIA_INDEX_OK,
               mesh_media_index_build_v1(&index, &manifest, 1024u));
  check_int_eq(MESH_MEDIA_INDEX_INVALID_ARG,
               mesh_media_index_build_v1(&index, &manifest, 1024u));
  mesh_media_index_destroy_v1(&index);
  /* Rebuild after destroy works. */
  check_int_eq(MESH_MEDIA_INDEX_OK,
               mesh_media_index_build_v1(&index, &manifest, 1024u));
  check_size_eq(index.segment_count, TEST_BLOCKS);
  mesh_media_index_destroy_v1(&index);

  mesh_media_index_destroy_v1(NULL); /* no-op */
}

spec("mesh media index") {
    describe("segment index + ABR ladder") {
        it("builds chunk-aligned segments under a target size") {
            test_segment_build();
        }
        it("maps seek offsets to segments") {
            test_seek_segments();
        }
        it("resolves byte ranges to chunk spans (HTTP Range/206)") {
            test_resolve_range();
        }
        it("selects the ABR rendition that fits the bandwidth") {
            test_abr_select();
        }
        it("switches ABR renditions dynamically with hysteresis") {
            test_abr_session_dynamic();
        }
        it("rejects invalid arguments") {
            test_invalid_args();
        }
    }
}