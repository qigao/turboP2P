#include <tinytest.h>

#include "mesh_stream_multisource.h"
#include "mesh_stream_source_selector.h"

#include <turbo_crypto.h>

#include <stdlib.h>
#include <string.h>

/* P2: multi-source block pulling. The selector tracks per-source health and
 * disables bad sources; the puller fetches blocks across the best sources in
 * parallel, verifies each SHA-256, retries failures/timeouts and delivers in
 * order. Fake in-memory sources inject corruption, drops and delay. */

#define TEST_BLOCK 1024u
#define TEST_BLOCKS 8u
#define TEST_SOURCES 3u
#define TEST_MAX_PENDING 3u
#define TEST_TIMEOUT_MS 50u

static uint8_t g_block_data[TEST_BLOCKS][TEST_BLOCK];
static uint8_t g_block_digests[TEST_BLOCKS][MESH_STREAM_DATA_HASH_SIZE];

static void fill_block_data(void) {
  for (size_t b = 0u; b < TEST_BLOCKS; b++) {
    for (size_t i = 0u; i < TEST_BLOCK; i++)
      g_block_data[b][i] = (uint8_t)(b * 31u + i * 7u + (i >> 4u));
    (void)turbo_crypto_sha256(g_block_data[b], TEST_BLOCK, g_block_digests[b]);
  }
}

static void make_ids(uint8_t ids[TEST_SOURCES][MESH_STREAM_SOURCE_ID_SIZE]) {
  for (size_t s = 0u; s < TEST_SOURCES; s++)
    for (size_t i = 0u; i < MESH_STREAM_SOURCE_ID_SIZE; i++)
      ids[s][i] = (uint8_t)(0x60u + s * 16u + i);
}

/* ---- selector unit tests ---- */

static void test_selector_health_and_pick(void) {
  mesh_stream_source_selector_v1_t selector;
  uint8_t ids[TEST_SOURCES][MESH_STREAM_SOURCE_ID_SIZE];
  size_t picked = SIZE_MAX;
  size_t in_flight[TEST_SOURCES] = {0u, 0u, 0u};

  make_ids(ids);
  check_int_eq(MESH_STREAM_SOURCE_SELECTOR_OK,
               mesh_stream_source_selector_init(&selector, 3u, 4u));
  for (size_t s = 0u; s < TEST_SOURCES; s++) {
    check_int_eq(MESH_STREAM_SOURCE_SELECTOR_OK,
                 mesh_stream_source_selector_register(&selector, ids[s]));
  }
  check_size_eq(selector.count, TEST_SOURCES);

  /* Equal health: prefer_spread picks the first (least in-flight). */
  check_int_eq(MESH_STREAM_SOURCE_SELECTOR_OK,
               mesh_stream_source_selector_pick(&selector, 1, in_flight,
                                                TEST_SOURCES, &picked));
  check_size_eq(picked, 0u);

  /* A lower smoothed RTT wins when in-flight counts tie. */
  check_int_eq(MESH_STREAM_SOURCE_SELECTOR_OK,
               mesh_stream_source_selector_report_success(&selector, 1u, 10u, 100u));
  check_int_eq(MESH_STREAM_SOURCE_SELECTOR_OK,
               mesh_stream_source_selector_report_success(&selector, 2u, 40u, 100u));
  check_int_eq(MESH_STREAM_SOURCE_SELECTOR_OK,
               mesh_stream_source_selector_pick(&selector, 1, in_flight,
                                                TEST_SOURCES, &picked));
  check_size_eq(picked, 1u); /* source 1 has lower RTT */

  /* prefer_spread favors the source with fewer in-flight requests. */
  in_flight[1] = 5u;
  check_int_eq(MESH_STREAM_SOURCE_SELECTOR_OK,
               mesh_stream_source_selector_pick(&selector, 1, in_flight,
                                                TEST_SOURCES, &picked));
  check_size_eq(picked, 2u); /* source 2 has 0 in flight, source 0 has 0 too but RTT */

  /* Failure threshold disables a source. */
  for (int i = 0; i < 3; i++) {
    check_int_eq(MESH_STREAM_SOURCE_SELECTOR_OK,
                 mesh_stream_source_selector_report_failure(&selector, 2u, 200u));
  }
  check_uint_eq(selector.sources[2].enabled, 0u);
  in_flight[1] = 0u;
  check_int_eq(MESH_STREAM_SOURCE_SELECTOR_OK,
               mesh_stream_source_selector_pick(&selector, 1, in_flight,
                                                TEST_SOURCES, &picked));
  check_true(picked != SIZE_MAX && picked != 2u);

  /* Success re-enables and resets failures. */
  check_int_eq(MESH_STREAM_SOURCE_SELECTOR_OK,
               mesh_stream_source_selector_report_success(&selector, 2u, 5u, 300u));
  check_uint_eq(selector.sources[2].enabled, 1u);
  check_uint_eq(selector.sources[2].consecutive_failures, 0u);
  check_int_eq(MESH_STREAM_SOURCE_SELECTOR_OK,
               mesh_stream_source_selector_enable(&selector, 0u));

  check_int_eq(MESH_STREAM_SOURCE_SELECTOR_INVALID_ARG,
               mesh_stream_source_selector_pick(&selector, 1, NULL, 0u, &picked));
  check_int_eq(MESH_STREAM_SOURCE_SELECTOR_INVALID_ARG,
               mesh_stream_source_selector_report_failure(&selector, 99u, 1u));
  check_int_eq(MESH_STREAM_SOURCE_SELECTOR_INVALID_ARG,
               mesh_stream_source_selector_register(NULL, ids[0]));
}

/* ---- fake multi-source io ---- */

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
  uint8_t drop[TEST_BLOCKS];
  uint64_t served;
  uint64_t corrupted_served;
} fake_source_t;

typedef struct {
  fake_source_t sources[TEST_SOURCES];
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
  fake_source_t *source = &io->sources[fetch->source_index];

  *out_len = 0u;
  if (!fetch)
    return -1;
  if (source->drop[fetch->seq])
    return 1; /* never completes; the puller times it out */
  if (*io->now_ms - fetch->started_at_ms < source->delay_ms)
    return 1; /* still pending */
  if (fetch->cap < TEST_BLOCK)
    return -1;
  if (source->corrupt[fetch->seq]) {
    uint8_t bad[TEST_BLOCK];

    memset(bad, 0x5a, sizeof(bad));
    memcpy(fetch->out, bad, sizeof(bad));
    source->corrupted_served++;
  } else {
    memcpy(fetch->out, g_block_data[fetch->seq], TEST_BLOCK);
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

static void init_fake_io(fake_io_t *io, uint64_t *now_ms) {
  memset(io, 0, sizeof(*io));
  io->now_ms = now_ms;
}

static void run_pull(mesh_stream_multisource_t *ms, uint64_t *now_ms,
                     uint8_t *out, size_t out_cap, size_t *out_len,
                     int expect_fail) {
  size_t got = 0u;
  uint64_t deadline = *now_ms + 10000u;

  *out_len = 0u;
  while (*now_ms < deadline && !mesh_stream_multisource_complete(ms)) {
    size_t n = 0u;

    *now_ms += 2u;
    if (mesh_stream_multisource_tick(ms, *now_ms) == MESH_STREAM_MULTISOURCE_FAILED) {
      if (expect_fail) {
        *out_len = got;
        return;
      }
      check_true(0); /* unexpected failure */
    }
    if (mesh_stream_multisource_recv(ms, out + got, out_cap - got, &n) ==
        MESH_STREAM_MULTISOURCE_OK) {
      got += n;
    }
  }
  *out_len = got;
}

static void test_multisource_spreads_and_verifies(void) {
  mesh_stream_source_selector_v1_t selector;
  mesh_stream_multisource_io_v1_t io;
  mesh_stream_multisource_t *ms;
  fake_io_t fake;
  uint8_t ids[TEST_SOURCES][MESH_STREAM_SOURCE_ID_SIZE];
  uint8_t out[TEST_BLOCKS * TEST_BLOCK];
  size_t out_len = 0u;
  uint64_t now_ms = 1000000u;

  fill_block_data();
  make_ids(ids);
  check_int_eq(MESH_STREAM_SOURCE_SELECTOR_OK,
               mesh_stream_source_selector_init(&selector, 3u, 4u));
  for (size_t s = 0u; s < TEST_SOURCES; s++)
    check_int_eq(MESH_STREAM_SOURCE_SELECTOR_OK,
                 mesh_stream_source_selector_register(&selector, ids[s]));
  init_fake_io(&fake, &now_ms);
  memset(&io, 0, sizeof(io));
  io.start = fake_start;
  io.poll = fake_poll;
  io.cancel = fake_cancel;
  io.context = &fake;

  ms = mesh_stream_multisource_create(&selector, &io, &g_block_digests[0][0],
                                      TEST_BLOCKS, TEST_BLOCK, TEST_MAX_PENDING,
                                      TEST_TIMEOUT_MS, 8u);
  check_not_null(ms);
  run_pull(ms, &now_ms, out, sizeof(out), &out_len, 0);
  check_true(mesh_stream_multisource_complete(ms));
  check_size_eq(out_len, sizeof(out));
  check_mem_eq(out, g_block_data, sizeof(out));
  /* With equal health and prefer_spread, more than one source served blocks. */
  {
    size_t served_sources = 0u;

    for (size_t s = 0u; s < TEST_SOURCES; s++) {
      if (fake.sources[s].served > 0u)
        served_sources++;
    }
    check_true(served_sources >= 2u);
  }
  mesh_stream_multisource_destroy(ms);
}

static void test_multisource_bad_source_eliminated(void) {
  mesh_stream_source_selector_v1_t selector;
  mesh_stream_multisource_io_v1_t io;
  mesh_stream_multisource_t *ms;
  fake_io_t fake;
  uint8_t ids[TEST_SOURCES][MESH_STREAM_SOURCE_ID_SIZE];
  uint8_t out[TEST_BLOCKS * TEST_BLOCK];
  size_t out_len = 0u;
  uint64_t now_ms = 1000000u;

  fill_block_data();
  make_ids(ids);
  check_int_eq(MESH_STREAM_SOURCE_SELECTOR_OK,
               mesh_stream_source_selector_init(&selector, 1u, 4u));
  for (size_t s = 0u; s < 2u; s++)
    check_int_eq(MESH_STREAM_SOURCE_SELECTOR_OK,
                 mesh_stream_source_selector_register(&selector, ids[s]));
  init_fake_io(&fake, &now_ms);
  memset(&fake.sources[1].corrupt, 1, sizeof(fake.sources[1].corrupt));
  memset(&io, 0, sizeof(io));
  io.start = fake_start;
  io.poll = fake_poll;
  io.cancel = fake_cancel;
  io.context = &fake;

  ms = mesh_stream_multisource_create(&selector, &io, &g_block_digests[0][0],
                                      TEST_BLOCKS, TEST_BLOCK, TEST_MAX_PENDING,
                                      TEST_TIMEOUT_MS, 8u);
  check_not_null(ms);
  run_pull(ms, &now_ms, out, sizeof(out), &out_len, 0);
  check_true(mesh_stream_multisource_complete(ms));
  check_size_eq(out_len, sizeof(out));
  check_mem_eq(out, g_block_data, sizeof(out));
  check_uint_eq(selector.sources[1].enabled, 0u); /* bad source disabled */
  check_true(selector.sources[1].total_failures >= 1u);
  check_true(fake.sources[0].served > 0u);
  mesh_stream_multisource_destroy(ms);
}

static void test_multisource_timeout_retries(void) {
  mesh_stream_source_selector_v1_t selector;
  mesh_stream_multisource_io_v1_t io;
  mesh_stream_multisource_t *ms;
  fake_io_t fake;
  uint8_t ids[TEST_SOURCES][MESH_STREAM_SOURCE_ID_SIZE];
  uint8_t out[TEST_BLOCKS * TEST_BLOCK];
  size_t out_len = 0u;
  uint64_t now_ms = 1000000u;

  fill_block_data();
  make_ids(ids);
  check_int_eq(MESH_STREAM_SOURCE_SELECTOR_OK,
               mesh_stream_source_selector_init(&selector, 1u, 4u));
  for (size_t s = 0u; s < 2u; s++)
    check_int_eq(MESH_STREAM_SOURCE_SELECTOR_OK,
                 mesh_stream_source_selector_register(&selector, ids[s]));
  init_fake_io(&fake, &now_ms);
  /* Source 1 drops every block: it never completes, so timeouts disable it. */
  memset(&fake.sources[1].drop, 1, sizeof(fake.sources[1].drop));
  memset(&io, 0, sizeof(io));
  io.start = fake_start;
  io.poll = fake_poll;
  io.cancel = fake_cancel;
  io.context = &fake;

  ms = mesh_stream_multisource_create(&selector, &io, &g_block_digests[0][0],
                                      TEST_BLOCKS, TEST_BLOCK, TEST_MAX_PENDING,
                                      TEST_TIMEOUT_MS, 8u);
  check_not_null(ms);
  run_pull(ms, &now_ms, out, sizeof(out), &out_len, 0);
  check_true(mesh_stream_multisource_complete(ms));
  check_size_eq(out_len, sizeof(out));
  check_mem_eq(out, g_block_data, sizeof(out));
  check_uint_eq(selector.sources[1].enabled, 0u); /* dropped source disabled */
  check_true(selector.sources[1].total_failures >= 1u);
  check_true(fake.sources[0].served > 0u);
  mesh_stream_multisource_destroy(ms);
}

static void test_multisource_all_bad_fails(void) {
  mesh_stream_source_selector_v1_t selector;
  mesh_stream_multisource_io_v1_t io;
  mesh_stream_multisource_t *ms;
  fake_io_t fake;
  uint8_t ids[TEST_SOURCES][MESH_STREAM_SOURCE_ID_SIZE];
  uint8_t out[TEST_BLOCKS * TEST_BLOCK];
  size_t out_len = 0u;
  uint64_t now_ms = 1000000u;

  fill_block_data();
  make_ids(ids);
  check_int_eq(MESH_STREAM_SOURCE_SELECTOR_OK,
               mesh_stream_source_selector_init(&selector, 2u, 4u));
  check_int_eq(MESH_STREAM_SOURCE_SELECTOR_OK,
               mesh_stream_source_selector_register(&selector, ids[0]));
  init_fake_io(&fake, &now_ms);
  memset(&fake.sources[0].corrupt, 1, sizeof(fake.sources[0].corrupt));
  memset(&io, 0, sizeof(io));
  io.start = fake_start;
  io.poll = fake_poll;
  io.cancel = fake_cancel;
  io.context = &fake;

  ms = mesh_stream_multisource_create(&selector, &io, &g_block_digests[0][0],
                                      TEST_BLOCKS, TEST_BLOCK, TEST_MAX_PENDING,
                                      TEST_TIMEOUT_MS, 3u);
  check_not_null(ms);
  run_pull(ms, &now_ms, out, sizeof(out), &out_len, 1);
  check_true(!mesh_stream_multisource_complete(ms)); /* never completes */
  mesh_stream_multisource_destroy(ms);
}

static void test_multisource_invalid_args(void) {
  mesh_stream_source_selector_v1_t selector;
  mesh_stream_multisource_io_v1_t io;

  check_null(mesh_stream_multisource_create(NULL, &io, &g_block_digests[0][0],
                                            TEST_BLOCKS, TEST_BLOCK, 1u, 1u, 1u));
  check_null(mesh_stream_multisource_create(&selector, NULL, &g_block_digests[0][0],
                                            TEST_BLOCKS, TEST_BLOCK, 1u, 1u, 1u));
  check_null(mesh_stream_multisource_create(&selector, &io, NULL, TEST_BLOCKS,
                                            TEST_BLOCK, 1u, 1u, 1u));
  check_int_eq(MESH_STREAM_MULTISOURCE_INVALID_ARG,
               mesh_stream_multisource_recv(NULL, NULL, 0u, NULL));
}

spec("mesh stream source selector") {
    describe("multi-source pulling") {
        it("scores sources and disables bad ones") {
            test_selector_health_and_pick();
        }
        it("spreads block fetches across sources and verifies each block") {
            test_multisource_spreads_and_verifies();
        }
        it("eliminates a source that returns corrupt blocks") {
            test_multisource_bad_source_eliminated();
        }
        it("retries on another source after a timeout") {
            test_multisource_timeout_retries();
        }
        it("fails when every source is bad") {
            test_multisource_all_bad_fails();
        }
        it("rejects invalid arguments") {
            test_multisource_invalid_args();
        }
    }
}
