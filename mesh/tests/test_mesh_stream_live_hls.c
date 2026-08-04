#include <tinytest.h>

#include "mesh_stream_live.h"
#include "mesh_stream_live_hls.h"

#include <stdlib.h>
#include <string.h>

/* P18: live-over-HTTP core. Unit tests for the sliding-window HLS playlist,
 * plus an integration: a live session (P5) delivers blocks that are pushed as
 * segments and served through the live playlist. */

#define TEST_WINDOW 3u
#define TEST_MAX_SEGMENT 4096u
#define TEST_DURATION_MS 2000u

static void fill_block(uint8_t *out, size_t len, uint64_t id) {
  for (size_t i = 0u; i < len; i++)
    out[i] = (uint8_t)(id * 29u + i * 11u + (i >> 3u));
}

static void test_window_and_playlist(void) {
  mesh_stream_live_hls_config_v1_t config;
  mesh_stream_live_hls_v1_t hls;
  uint8_t block[TEST_MAX_SEGMENT];
  char playlist[4096];
  size_t playlist_len = 0u;
  uint8_t out[TEST_MAX_SEGMENT];
  size_t out_len = 0u;
  uint64_t index = 0u;

  memset(&config, 0, sizeof(config));
  config.window = TEST_WINDOW;
  config.segment_duration_ms = TEST_DURATION_MS;
  config.max_segment_bytes = TEST_MAX_SEGMENT;
  memset(&hls, 0, sizeof(hls));
  check_int_eq(MESH_STREAM_LIVE_HLS_OK,
               mesh_stream_live_hls_init_v1(&hls, &config));

  /* Empty live playlist is OK with no content. */
  check_int_eq(MESH_STREAM_LIVE_HLS_OK,
               mesh_stream_live_hls_playlist_v1(&hls, playlist, sizeof(playlist),
                                                &playlist_len));
  check_size_eq(playlist_len, 0u);
  check_true(mesh_stream_live_hls_live_edge(&hls) == UINT64_MAX);

  for (uint64_t i = 0u; i < 5u; i++) {
    fill_block(block, 64u + (size_t)i * 4u, i);
    check_int_eq(MESH_STREAM_LIVE_HLS_OK,
                 mesh_stream_live_hls_push_v1(&hls, block, 64u + (size_t)i * 4u,
                                              &index));
    check_uint_eq(index, i);
  }
  check_uint_eq(mesh_stream_live_hls_live_edge(&hls), 4u);
  check_uint_eq(mesh_stream_live_hls_first_index(&hls), 2u); /* window 3 */

  check_int_eq(MESH_STREAM_LIVE_HLS_OK,
               mesh_stream_live_hls_playlist_v1(&hls, playlist, sizeof(playlist),
                                                &playlist_len));
  check_str_eq(playlist,
               "#EXTM3U\n"
               "#EXT-X-VERSION:3\n"
               "#EXT-X-MEDIA-SEQUENCE:2\n"
               "#EXT-X-TARGETDURATION:2\n"
               "#EXTINF:2.000,\n"
               "seg-2\n"
               "#EXTINF:2.000,\n"
               "seg-3\n"
               "#EXTINF:2.000,\n"
               "seg-4\n");
  check_true(strstr(playlist, "#EXT-X-ENDLIST") == NULL); /* live */

  /* In-window segments are served; evicted ones are NOT_FOUND (LIVE_SKIP). */
  for (uint64_t i = 2u; i <= 4u; i++) {
    fill_block(block, 64u + (size_t)i * 4u, i);
    check_int_eq(MESH_STREAM_LIVE_HLS_OK,
                 mesh_stream_live_hls_segment_v1(&hls, i, out, sizeof(out),
                                                 &out_len));
    check_size_eq(out_len, 64u + (size_t)i * 4u);
    check_mem_eq(out, block, out_len);
  }
  check_int_eq(MESH_STREAM_LIVE_HLS_NOT_FOUND,
               mesh_stream_live_hls_segment_v1(&hls, 1u, out, sizeof(out), &out_len));
  check_int_eq(MESH_STREAM_LIVE_HLS_NOT_FOUND,
               mesh_stream_live_hls_segment_v1(&hls, 5u, out, sizeof(out), &out_len));

  /* Oversized segments are rejected. */
  {
    uint8_t big[TEST_MAX_SEGMENT + 1u];

    check_int_eq(MESH_STREAM_LIVE_HLS_RESOURCE_EXHAUSTED,
                 mesh_stream_live_hls_push_v1(&hls, big, sizeof(big), &index));
  }

  mesh_stream_live_hls_destroy_v1(&hls);
}

static void test_invalid_args(void) {
  mesh_stream_live_hls_config_v1_t config;
  mesh_stream_live_hls_v1_t hls;
  uint8_t block[16] = {0};
  char playlist[64];
  uint8_t out[16];
  size_t len = 0u;
  uint64_t index = 0u;

  memset(&config, 0, sizeof(config));
  config.window = TEST_WINDOW;
  config.segment_duration_ms = TEST_DURATION_MS;
  config.max_segment_bytes = TEST_MAX_SEGMENT;

  check_int_eq(MESH_STREAM_LIVE_HLS_INVALID_ARG,
               mesh_stream_live_hls_init_v1(NULL, &config));
  check_int_eq(MESH_STREAM_LIVE_HLS_INVALID_ARG,
               mesh_stream_live_hls_init_v1(&hls, NULL));
  config.window = 0u;
  check_int_eq(MESH_STREAM_LIVE_HLS_INVALID_ARG,
               mesh_stream_live_hls_init_v1(&hls, &config));
  config.window = TEST_WINDOW;
  config.max_segment_bytes = 0u;
  check_int_eq(MESH_STREAM_LIVE_HLS_INVALID_ARG,
               mesh_stream_live_hls_init_v1(&hls, &config));
  config.max_segment_bytes = TEST_MAX_SEGMENT;

  check_int_eq(MESH_STREAM_LIVE_HLS_OK,
               mesh_stream_live_hls_init_v1(&hls, &config));
  check_int_eq(MESH_STREAM_LIVE_HLS_INVALID_ARG,
               mesh_stream_live_hls_push_v1(&hls, NULL, 4u, &index));
  check_int_eq(MESH_STREAM_LIVE_HLS_INVALID_ARG,
               mesh_stream_live_hls_push_v1(&hls, block, 0u, &index));
  check_int_eq(MESH_STREAM_LIVE_HLS_INVALID_ARG,
               mesh_stream_live_hls_push_v1(&hls, block, 4u, NULL));
  check_int_eq(MESH_STREAM_LIVE_HLS_INVALID_ARG,
               mesh_stream_live_hls_playlist_v1(&hls, NULL, sizeof(playlist), &len));
  check_int_eq(MESH_STREAM_LIVE_HLS_INVALID_ARG,
               mesh_stream_live_hls_segment_v1(&hls, 0u, NULL, sizeof(out), &len));
  check_int_eq(MESH_STREAM_LIVE_HLS_NOT_FOUND,
               mesh_stream_live_hls_segment_v1(&hls, 0u, out, sizeof(out), &len));
  check_true(mesh_stream_live_hls_live_edge(NULL) == UINT64_MAX);
  mesh_stream_live_hls_destroy_v1(&hls);
  mesh_stream_live_hls_destroy_v1(NULL);
}

/* ---- integration: live session -> HLS ---- */

#define PIPE_CAP 64u
typedef struct {
  uint8_t *frames[PIPE_CAP];
  size_t lens[PIPE_CAP];
  size_t count;
  size_t head;
} live_pipe_t;

static int pipe_send(void *context, const uint8_t *bytes, size_t len) {
  live_pipe_t *pipe = (live_pipe_t *)context;
  uint8_t *copy;

  if (pipe->count >= PIPE_CAP)
    return -1;
  copy = (uint8_t *)malloc(len);
  if (!copy)
    return -1;
  memcpy(copy, bytes, len);
  pipe->frames[pipe->count] = copy;
  pipe->lens[pipe->count] = len;
  pipe->count++;
  return 0;
}

static int pipe_recv(void *context, uint8_t *bytes, size_t cap, size_t *out_len) {
  live_pipe_t *pipe = (live_pipe_t *)context;

  *out_len = 0u;
  if (pipe->head >= pipe->count)
    return 0;
  if (pipe->lens[pipe->head] > cap)
    return -1;
  memcpy(bytes, pipe->frames[pipe->head], pipe->lens[pipe->head]);
  free(pipe->frames[pipe->head]);
  pipe->head++;
  *out_len = pipe->lens[pipe->head - 1u];
  return 0;
}

static void test_live_session_to_hls(void) {
  mesh_stream_live_config_v1_t live_config;
  mesh_stream_live_io_v1_t io = {pipe_send, pipe_recv, NULL};
  live_pipe_t pipe;
  mesh_stream_live_t *tx;
  mesh_stream_live_t *rx;
  mesh_stream_live_hls_config_v1_t hls_config;
  mesh_stream_live_hls_v1_t hls;
  uint8_t block[1024];
  char playlist[4096];
  size_t playlist_len = 0u;
  uint8_t out[1024];
  size_t out_len = 0u;
  uint64_t seq = 0u;
  uint64_t pushed = 0u;
  size_t delivered = 0u;

  memset(&pipe, 0, sizeof(pipe));
  io.context = &pipe;
  memset(&live_config, 0, sizeof(live_config));
  live_config.window_groups = 8u;
  live_config.skip_gap_groups = 2u;
  live_config.max_block_bytes = 1024u;
  live_config.fec_data_shards = 0u; /* simple ordered delivery */
  tx = mesh_stream_live_create(MESH_STREAM_LIVE_ROLE_SENDER, &live_config, &io);
  rx = mesh_stream_live_create(MESH_STREAM_LIVE_ROLE_RECEIVER, &live_config, &io);
  check_not_null(tx);
  check_not_null(rx);

  memset(&hls_config, 0, sizeof(hls_config));
  hls_config.window = 6u;
  hls_config.segment_duration_ms = 2000u;
  hls_config.max_segment_bytes = 1024u;
  memset(&hls, 0, sizeof(hls));
  check_int_eq(MESH_STREAM_LIVE_HLS_OK,
               mesh_stream_live_hls_init_v1(&hls, &hls_config));

  for (uint64_t i = 0u; i < 6u; i++) {
    fill_block(block, 256u, i);
    check_int_eq(MESH_STREAM_LIVE_OK,
                 mesh_stream_live_sender_produce(tx, block, 256u, &seq));
  }
  check_int_eq(MESH_STREAM_LIVE_OK, mesh_stream_live_sender_finish(tx));

  /* Drain the receiver into the HLS adapter. */
  for (;;) {
    size_t len = 0u;
    mesh_stream_live_result_t rc =
        mesh_stream_live_receiver_pump(rx, block, sizeof(block), &len, &seq);

    if (rc == MESH_STREAM_LIVE_END)
      break;
    check_int_eq(MESH_STREAM_LIVE_OK, rc);
    check_int_eq(MESH_STREAM_LIVE_HLS_OK,
                 mesh_stream_live_hls_push_v1(&hls, block, len, &pushed));
    delivered++;
  }
  check_size_eq(delivered, 6u);
  check_uint_eq(mesh_stream_live_hls_live_edge(&hls), 5u);

  check_int_eq(MESH_STREAM_LIVE_HLS_OK,
               mesh_stream_live_hls_playlist_v1(&hls, playlist, sizeof(playlist),
                                                &playlist_len));
  check_true(strstr(playlist, "#EXT-X-MEDIA-SEQUENCE:0") != NULL);
  check_true(strstr(playlist, "seg-5\n") != NULL);
  check_true(strstr(playlist, "#EXT-X-ENDLIST") == NULL);

  /* Each live segment is served through the HLS window. */
  for (uint64_t i = 0u; i < 6u; i++) {
    fill_block(block, 256u, i);
    check_int_eq(MESH_STREAM_LIVE_HLS_OK,
                 mesh_stream_live_hls_segment_v1(&hls, i, out, sizeof(out),
                                                 &out_len));
    check_size_eq(out_len, 256u);
    check_mem_eq(out, block, 256u);
  }

  mesh_stream_live_hls_destroy_v1(&hls);
  mesh_stream_live_destroy(rx);
  mesh_stream_live_destroy(tx);
  for (size_t i = pipe.head; i < pipe.count; i++)
    free(pipe.frames[i]);
}

spec("mesh stream live hls") {
    describe("live HLS sliding window") {
        it("builds a sliding-window live playlist and evicts segments") {
            test_window_and_playlist();
        }
        it("rejects invalid arguments") {
            test_invalid_args();
        }
        it("serves live session blocks as HLS segments") {
            test_live_session_to_hls();
        }
    }
}