#include <tinytest.h>

#include "mesh_stream_media_pull.h"
#include "mesh_stream_media_pull_multisource.h"
#include "mesh_stream_multisource.h"

#include <turbo_crypto.h>

#include <stdlib.h>
#include <string.h>

/* P10: the multi-source block puller (P2) drives the media range pull (P8).
 * The multisource fetches the covering chunks across 3 in-memory sources,
 * verifies each digest and eliminates corrupt sources; the media pull then
 * re-verifies and assembles the requested window. */

#define TEST_BLOCK 1024u
#define TEST_BLOCKS 8u
#define TEST_SOURCES 3u
#define TEST_OBJECT_SIZE (TEST_BLOCK * TEST_BLOCKS)

static uint8_t g_data[TEST_OBJECT_SIZE];
static uint8_t g_digests[TEST_BLOCKS][MESH_STREAM_DATA_HASH_SIZE];

static void fill_data(void) {
  for (size_t i = 0u; i < TEST_OBJECT_SIZE; i++)
    g_data[i] = (uint8_t)(i * 7u + (i >> 4u) + 1u);
  for (size_t b = 0u; b < TEST_BLOCKS; b++)
    (void)turbo_crypto_sha256(g_data + b * TEST_BLOCK, TEST_BLOCK, g_digests[b]);
}

static void build_manifest(m3_object_manifest_v2_t *manifest,
                           m3_chunk_cid_v1_t *chunks) {
  turbo_crypto_sha256_ctx_t ctx;
  uint8_t digest[M3_CHUNK_CID_DIGEST_SIZE];

  (void)turbo_crypto_sha256_init(&ctx);
  memset(manifest, 0, sizeof(*manifest));
  memset(chunks, 0, TEST_BLOCKS * sizeof(*chunks));
  for (size_t i = 0u; i < TEST_BLOCKS; i++) {
    memcpy(chunks[i].digest, g_digests[i], MESH_STREAM_DATA_HASH_SIZE);
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

/* ---- fake async multi-source io over the in-memory object ---- */

typedef struct {
  uint64_t seq;
  size_t source_index;
  uint64_t started_at_ms;
  uint8_t *out;
  size_t cap;
} fake_fetch_t;

typedef struct {
  uint64_t delay_ms;
  uint8_t corrupt[TEST_BLOCKS];
  uint64_t served;
  uint64_t corrupted_served;
} fake_source_t;

typedef struct {
  fake_source_t sources[TEST_SOURCES];
  size_t first_chunk; /* absolute object chunk of the puller's relative 0 */
  uint64_t *now_ms;
} fake_io_t;

static int fake_start(void *context, size_t source_index, uint64_t seq,
                      uint8_t *out, size_t cap, void **out_handle) {
  fake_io_t *io = (fake_io_t *)context;
  fake_fetch_t *fetch;

  if (source_index >= TEST_SOURCES || seq >= TEST_BLOCKS)
    return -1;
  fetch = (fake_fetch_t *)calloc(1, sizeof(*fetch));
  if (!fetch)
    return -1;
  fetch->seq = seq;
  fetch->source_index = source_index;
  fetch->started_at_ms = *io->now_ms;
  fetch->out = out;
  fetch->cap = cap;
  *out_handle = fetch;
  return 0;
}

static int fake_poll(void *context, void *handle, size_t *out_len) {
  fake_io_t *io = (fake_io_t *)context;
  fake_fetch_t *fetch = (fake_fetch_t *)handle;
  fake_source_t *source;

  *out_len = 0u;
  if (!fetch)
    return -1;
  source = &io->sources[fetch->source_index];
  if (*io->now_ms - fetch->started_at_ms < source->delay_ms)
    return 1; /* still pending */
  if (fetch->cap < TEST_BLOCK)
    return -1;
  if (source->corrupt[fetch->seq]) {
    memset(fetch->out, 0x5a, TEST_BLOCK);
    source->corrupted_served++;
  } else {
    memcpy(fetch->out, g_data + (io->first_chunk + fetch->seq) * TEST_BLOCK,
           TEST_BLOCK);
    source->served++;
  }
  *out_len = TEST_BLOCK;
  free(fetch);
  return 0;
}

static void fake_cancel(void *context, void *handle) {
  (void)context;
  free(handle);
}

static void make_ids(uint8_t ids[TEST_SOURCES][MESH_STREAM_SOURCE_ID_SIZE]) {
  for (size_t s = 0u; s < TEST_SOURCES; s++) {
    for (size_t i = 0u; i < MESH_STREAM_SOURCE_ID_SIZE; i++)
      ids[s][i] = (uint8_t)(0x50u + s * 16u + i);
  }
}

static void init_fake_io(fake_io_t *io, uint64_t *now_ms) {
  memset(io, 0, sizeof(*io));
  io->now_ms = now_ms;
}

static void run_pull(mesh_stream_media_pull_v1_t *pull, uint8_t *out,
                     size_t cap, size_t *out_len) {
  size_t guard = 0u;

  while (!mesh_stream_media_pull_complete(pull)) {
    mesh_stream_media_pull_result_t rc =
        mesh_stream_media_pull_pump_v1(pull, out, cap, out_len);

    if (rc == MESH_STREAM_MEDIA_PULL_AGAIN) {
      check_true(++guard < 100000u);
      continue;
    }
    check_int_eq(MESH_STREAM_MEDIA_PULL_OK, rc);
  }
}

static void test_multisource_drives_range_pull(void) {
  m3_object_manifest_v2_t manifest;
  m3_chunk_cid_v1_t chunks[TEST_BLOCKS];
  uint8_t ids[TEST_SOURCES][MESH_STREAM_SOURCE_ID_SIZE];
  mesh_stream_source_selector_v1_t selector;
  mesh_stream_multisource_io_v1_t ms_io = {fake_start, fake_poll, fake_cancel, NULL};
  fake_io_t fake;
  mesh_stream_multisource_t *ms;
  uint64_t now_ms = 1000u;
  mesh_stream_media_pull_multisource_ctx_v1_t ctx;
  mesh_stream_media_pull_io_v1_t pull_io;
  mesh_stream_media_pull_config_v1_t config;
  mesh_stream_media_pull_v1_t pull;
  uint8_t range_digests[3][MESH_STREAM_DATA_HASH_SIZE];
  uint8_t out[TEST_OBJECT_SIZE];
  size_t out_len = 0u;

  fill_data();
  build_manifest(&manifest, chunks);

  make_ids(ids);
  memset(&selector, 0, sizeof(selector));
  check_int_eq(MESH_STREAM_SOURCE_SELECTOR_OK,
               mesh_stream_source_selector_init(&selector, 3u, 4u));
  for (size_t s = 0u; s < TEST_SOURCES; s++)
    check_int_eq(MESH_STREAM_SOURCE_SELECTOR_OK,
                 mesh_stream_source_selector_register(&selector, ids[s]));

  init_fake_io(&fake, &now_ms);
  fake.first_chunk = 3u;
  ms_io.context = &fake;
  for (size_t i = 0u; i < 3u; i++)
    memcpy(range_digests[i], chunks[3u + i].digest, MESH_STREAM_DATA_HASH_SIZE);
  ms = mesh_stream_multisource_create(&selector, &ms_io, &range_digests[0][0], 3u,
                                      TEST_BLOCK, 3u, 50u, 3u);
  check_not_null(ms);

  memset(&ctx, 0, sizeof(ctx));
  ctx.ms = ms;
  ctx.first_chunk = 3u;
  ctx.now_ms = &now_ms;
  check_int_eq(MESH_STREAM_MEDIA_PULL_OK,
               mesh_stream_media_pull_multisource_io_v1(&ctx, &pull_io));

  memset(&config, 0, sizeof(config));
  config.io = pull_io;
  config.max_chunk_bytes = TEST_BLOCK;
  config.target_segment_bytes = 3u * TEST_BLOCK;
  memset(&pull, 0, sizeof(pull));
  check_int_eq(MESH_STREAM_MEDIA_PULL_OK,
               mesh_stream_media_pull_init_v1(&pull, &manifest, &config));
  check_int_eq(MESH_STREAM_MEDIA_PULL_OK,
               mesh_stream_media_pull_start_v1(&pull, 3u * TEST_BLOCK,
                                               3u * TEST_BLOCK));
  run_pull(&pull, out, sizeof(out), &out_len);
  check_size_eq(out_len, 3u * TEST_BLOCK);
  check_mem_eq(out, g_data + 3u * TEST_BLOCK, 3u * TEST_BLOCK);
  check_true(mesh_stream_media_pull_complete(&pull));
  check_true(mesh_stream_multisource_complete(ms));

  /* The puller spread the three blocks across the three sources. */
  {
    uint64_t total_served = 0u;

    for (size_t s = 0u; s < TEST_SOURCES; s++)
      total_served += fake.sources[s].served;
    check_uint_eq(total_served, 3u);
  }

  mesh_stream_media_pull_destroy_v1(&pull);
  mesh_stream_multisource_destroy(ms);
}

static void test_corrupt_source_eliminated(void) {
  m3_object_manifest_v2_t manifest;
  m3_chunk_cid_v1_t chunks[TEST_BLOCKS];
  uint8_t ids[TEST_SOURCES][MESH_STREAM_SOURCE_ID_SIZE];
  mesh_stream_source_selector_v1_t selector;
  mesh_stream_multisource_io_v1_t ms_io = {fake_start, fake_poll, fake_cancel, NULL};
  fake_io_t fake;
  mesh_stream_multisource_t *ms;
  uint64_t now_ms = 1000u;
  mesh_stream_media_pull_multisource_ctx_v1_t ctx;
  mesh_stream_media_pull_io_v1_t pull_io;
  mesh_stream_media_pull_config_v1_t config;
  mesh_stream_media_pull_v1_t pull;
  uint8_t range_digests[3][MESH_STREAM_DATA_HASH_SIZE];
  uint8_t out[TEST_OBJECT_SIZE];
  size_t out_len = 0u;

  build_manifest(&manifest, chunks);
  make_ids(ids);
  memset(&selector, 0, sizeof(selector));
  check_int_eq(MESH_STREAM_SOURCE_SELECTOR_OK,
               mesh_stream_source_selector_init(&selector, 3u, 4u));
  for (size_t s = 0u; s < TEST_SOURCES; s++)
    check_int_eq(MESH_STREAM_SOURCE_SELECTOR_OK,
                 mesh_stream_source_selector_register(&selector, ids[s]));

  init_fake_io(&fake, &now_ms);
  fake.first_chunk = 3u;
  fake.sources[0].corrupt[0] = 1u; /* source 0 corrupts the first range chunk */
  ms_io.context = &fake;
  for (size_t i = 0u; i < 3u; i++)
    memcpy(range_digests[i], chunks[3u + i].digest, MESH_STREAM_DATA_HASH_SIZE);
  ms = mesh_stream_multisource_create(&selector, &ms_io, &range_digests[0][0], 3u,
                                      TEST_BLOCK, 3u, 50u, 3u);
  check_not_null(ms);

  memset(&ctx, 0, sizeof(ctx));
  ctx.ms = ms;
  ctx.first_chunk = 3u;
  ctx.now_ms = &now_ms;
  check_int_eq(MESH_STREAM_MEDIA_PULL_OK,
               mesh_stream_media_pull_multisource_io_v1(&ctx, &pull_io));
  memset(&config, 0, sizeof(config));
  config.io = pull_io;
  config.max_chunk_bytes = TEST_BLOCK;
  config.target_segment_bytes = 3u * TEST_BLOCK;
  memset(&pull, 0, sizeof(pull));
  check_int_eq(MESH_STREAM_MEDIA_PULL_OK,
               mesh_stream_media_pull_init_v1(&pull, &manifest, &config));
  check_int_eq(MESH_STREAM_MEDIA_PULL_OK,
               mesh_stream_media_pull_start_v1(&pull, 3u * TEST_BLOCK,
                                               3u * TEST_BLOCK));
  run_pull(&pull, out, sizeof(out), &out_len);
  check_size_eq(out_len, 3u * TEST_BLOCK);
  check_mem_eq(out, g_data + 3u * TEST_BLOCK, 3u * TEST_BLOCK);
  check_true(mesh_stream_media_pull_complete(&pull));
  /* The corrupt source was served but its block was replaced by a good one. */
  check_uint_eq(fake.sources[0].corrupted_served, 1u);

  mesh_stream_media_pull_destroy_v1(&pull);
  mesh_stream_multisource_destroy(ms);
}

static void test_invalid_args(void) {
  mesh_stream_media_pull_io_v1_t io;
  mesh_stream_media_pull_multisource_ctx_v1_t ctx;
  uint64_t now_ms = 0u;

  memset(&ctx, 0, sizeof(ctx));
  ctx.ms = (mesh_stream_multisource_t *)&io;
  ctx.first_chunk = 0u;
  ctx.now_ms = &now_ms;
  check_int_eq(MESH_STREAM_MEDIA_PULL_INVALID_ARG,
               mesh_stream_media_pull_multisource_io_v1(NULL, &io));
  check_int_eq(MESH_STREAM_MEDIA_PULL_INVALID_ARG,
               mesh_stream_media_pull_multisource_io_v1(&ctx, NULL));
  ctx.ms = NULL;
  check_int_eq(MESH_STREAM_MEDIA_PULL_INVALID_ARG,
               mesh_stream_media_pull_multisource_io_v1(&ctx, &io));
  ctx.ms = (mesh_stream_multisource_t *)&io;
  ctx.now_ms = NULL;
  check_int_eq(MESH_STREAM_MEDIA_PULL_INVALID_ARG,
               mesh_stream_media_pull_multisource_io_v1(&ctx, &io));
}

spec("mesh stream media pull multisource") {
    describe("multi-source media range pull") {
        it("pulls a segment range through the multisource puller") {
            test_multisource_drives_range_pull();
        }
        it("recovers from a corrupt source via the multisource retry") {
            test_corrupt_source_eliminated();
        }
        it("rejects invalid arguments") {
            test_invalid_args();
        }
    }
}