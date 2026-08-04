#include <tinytest.h>

#include "mesh_stream_live.h"

#include <stdlib.h>
#include <string.h>

/* P5: live edge streaming. An in-memory datagram pipe carries whole frames
 * between sender and receiver; fault injection drops frames by seq (or all
 * parity frames) to exercise LIVE_SKIP and FEC recovery. Frame layout mirrors
 * the implementation: magic4 + type u8 + seq u32 BE + len u32 BE + payload. */

#define TEST_MAX_BLOCK 4096u
#define TEST_PIPE_CAP 64u
#define TEST_FRAME_HEADER 13u

static const uint8_t TEST_MAGIC[4] = {'M', 'S', 'L', '1'};

typedef struct {
  uint8_t *frames[TEST_PIPE_CAP];
  size_t lens[TEST_PIPE_CAP];
  size_t count;
  size_t head;
} live_pipe_t;

typedef struct {
  live_pipe_t *pipe;
  uint64_t drop_seqs[16];
  size_t drop_count;
  int drop_parity;
} live_io_t;

static void pipe_reset(live_pipe_t *pipe) {
  for (size_t i = pipe->head; i < pipe->count; i++)
    free(pipe->frames[i]);
  memset(pipe, 0, sizeof(*pipe));
}

static void pipe_push_raw(live_pipe_t *pipe, const uint8_t *frame, size_t len) {
  uint8_t *copy;

  check_true(pipe->count < TEST_PIPE_CAP);
  copy = (uint8_t *)malloc(len);
  check_not_null(copy);
  memcpy(copy, frame, len);
  pipe->frames[pipe->count] = copy;
  pipe->lens[pipe->count] = len;
  pipe->count++;
}

static void pipe_swap(live_pipe_t *pipe, size_t a, size_t b) {
  uint8_t *f = pipe->frames[a];
  size_t l = pipe->lens[a];

  pipe->frames[a] = pipe->frames[b];
  pipe->lens[a] = pipe->lens[b];
  pipe->frames[b] = f;
  pipe->lens[b] = l;
}

static uint64_t frame_seq(const uint8_t *frame) {
  return ((uint64_t)frame[5] << 24u) | ((uint64_t)frame[6] << 16u) |
         ((uint64_t)frame[7] << 8u) | frame[8];
}

static int live_io_send(void *context, const uint8_t *bytes, size_t len) {
  live_io_t *io = (live_io_t *)context;
  uint64_t seq = frame_seq(bytes);

  if (bytes[4] == 2u && io->drop_parity)
    return 0; /* drop parity frame */
  for (size_t i = 0u; i < io->drop_count; i++) {
    if (io->drop_seqs[i] == seq)
      return 0; /* drop this data/parity frame */
  }
  if (io->pipe->count >= TEST_PIPE_CAP)
    return -1;
  {
    uint8_t *copy = (uint8_t *)malloc(len);

    if (!copy)
      return -1;
    memcpy(copy, bytes, len);
    io->pipe->frames[io->pipe->count] = copy;
    io->pipe->lens[io->pipe->count] = len;
    io->pipe->count++;
  }
  return 0;
}

static int live_io_recv(void *context, uint8_t *bytes, size_t cap, size_t *out_len) {
  live_io_t *io = (live_io_t *)context;

  *out_len = 0u;
  if (io->pipe->head >= io->pipe->count)
    return 0;
  {
    size_t len = io->pipe->lens[io->pipe->head];

    if (len > cap)
      return -1;
    memcpy(bytes, io->pipe->frames[io->pipe->head], len);
    free(io->pipe->frames[io->pipe->head]);
    io->pipe->head++;
    *out_len = len;
  }
  return 0;
}

static void make_io(live_io_t *io, live_pipe_t *pipe) {
  memset(io, 0, sizeof(*io));
  io->pipe = pipe;
}

static void make_config(mesh_stream_live_config_v1_t *config, uint64_t fec_data,
                        uint64_t fec_parity, uint64_t join_seq) {
  memset(config, 0, sizeof(*config));
  for (size_t i = 0u; i < MESH_STREAM_LIVE_STREAM_ID_SIZE; i++)
    config->stream_id[i] = (uint8_t)(0x40u + i);
  config->window_groups = 8u;
  config->skip_gap_groups = 2u;
  config->max_block_bytes = TEST_MAX_BLOCK;
  config->fec_data_shards = fec_data;
  config->fec_parity_shards = fec_parity;
  config->join_seq = join_seq;
}

static void fill_block(uint8_t *out, size_t len, uint64_t id) {
  for (size_t i = 0u; i < len; i++)
    out[i] = (uint8_t)(id * 29u + i * 11u + (i >> 3u));
}

static size_t fec_block_index(uint64_t data_seq) {
  /* 2 data + 1 parity per group: data seqs are 0,1,3,4,6,7,... */
  return (size_t)(data_seq / 3u) * 2u + (size_t)(data_seq % 3u);
}

static mesh_stream_live_result_t pump_once(mesh_stream_live_t *rx, uint8_t *out,
                                           size_t cap, size_t *out_len,
                                           uint64_t *out_seq) {
  return mesh_stream_live_receiver_pump(rx, out, cap, out_len, out_seq);
}

/* ---- FEC codec ---- */

static void test_fec_codec(void) {
  uint8_t a[5] = {1, 2, 3, 4, 5};
  uint8_t b[5] = {5, 4, 3, 2, 1};
  uint8_t c[5] = {9, 8, 7, 6, 0};
  const uint8_t *ptrs[3] = {a, b, c};
  size_t lens[3] = {5, 5, 5};
  uint8_t parity[8];
  size_t parity_len = 0u;

  check_int_eq(MESH_STREAM_LIVE_OK,
               mesh_stream_live_fec_xor_encode(ptrs, lens, 3u, parity,
                                               sizeof(parity), &parity_len));
  check_size_eq(parity_len, 5u);
  for (size_t j = 0u; j < 5u; j++)
    check_uint_eq(parity[j], (uint8_t)(a[j] ^ b[j] ^ c[j]));

  /* Recover the missing middle shard. */
  {
    uint8_t rec[5] = {0};
    uint8_t *shards[3] = {a, rec, c};
    uint8_t present[3] = {1u, 0u, 1u};

    check_int_eq(MESH_STREAM_LIVE_OK,
                 mesh_stream_live_fec_xor_recover(shards, lens, 3u, present,
                                                  parity_len, parity));
    check_mem_eq(rec, b, 5u);
  }

  /* Variable shard lengths: parity is max length, shorter shards zero-pad. */
  {
    uint8_t short_b[3] = {5, 4, 3};
    const uint8_t *ptrs2[2] = {a, short_b};
    size_t lens2[2] = {5, 3};
    uint8_t p2[8];
    size_t p2_len = 0u;

    check_int_eq(MESH_STREAM_LIVE_OK,
                 mesh_stream_live_fec_xor_encode(ptrs2, lens2, 2u, p2,
                                                 sizeof(p2), &p2_len));
    check_size_eq(p2_len, 5u);
    check_uint_eq(p2[0], (uint8_t)(a[0] ^ short_b[0]));
    check_uint_eq(p2[2], (uint8_t)(a[2] ^ short_b[2]));
    check_uint_eq(p2[3], a[3]); /* beyond short_b: zero-padded */
    check_uint_eq(p2[4], a[4]);
  }

  /* Zero or two missing shards exceed the XOR capability. */
  {
    uint8_t rec[5] = {0};
    uint8_t *shards0[3] = {a, b, c};
    uint8_t present_all[3] = {1u, 1u, 1u};
    uint8_t *shards2[3] = {a, rec, NULL};
    uint8_t present_one[3] = {1u, 0u, 0u};

    check_int_eq(MESH_STREAM_LIVE_INTEGRITY,
                 mesh_stream_live_fec_xor_recover(shards0, lens, 3u, present_all,
                                                  parity_len, parity));
    check_int_eq(MESH_STREAM_LIVE_INTEGRITY,
                 mesh_stream_live_fec_xor_recover(shards2, lens, 3u, present_one,
                                                  parity_len, parity));
  }

  check_int_eq(MESH_STREAM_LIVE_INVALID_ARG,
               mesh_stream_live_fec_xor_encode(NULL, lens, 3u, parity, 8u, &parity_len));
  check_int_eq(MESH_STREAM_LIVE_INVALID_ARG,
               mesh_stream_live_fec_xor_encode(ptrs, NULL, 3u, parity, 8u, &parity_len));
  check_int_eq(MESH_STREAM_LIVE_INVALID_ARG,
               mesh_stream_live_fec_xor_encode(ptrs, lens, 0u, parity, 8u, &parity_len));
  check_int_eq(MESH_STREAM_LIVE_INVALID_ARG,
               mesh_stream_live_fec_xor_encode(ptrs, lens, 3u, parity, 2u, &parity_len));
}

/* ---- session: ordered delivery ---- */

static void test_ordered_delivery(void) {
  mesh_stream_live_config_v1_t config;
  mesh_stream_live_io_v1_t io = {live_io_send, live_io_recv, NULL};
  live_pipe_t pipe;
  live_io_t send_io;
  mesh_stream_live_t *tx;
  mesh_stream_live_t *rx;
  uint8_t block[TEST_MAX_BLOCK];
  uint8_t out[TEST_MAX_BLOCK];
  uint8_t got[8][TEST_MAX_BLOCK];
  size_t lens[8] = {100, 200, 300, 400, 500, 600, 700, 800};
  uint64_t seqs[8];
  uint64_t seq = 0u;
  size_t len = 0u;
  size_t delivered = 0u;

  memset(&pipe, 0, sizeof(pipe));
  make_io(&send_io, &pipe);
  send_io.drop_count = 0u;
  io.context = &send_io;
  make_config(&config, 0u, 0u, 0u);
  tx = mesh_stream_live_create(MESH_STREAM_LIVE_ROLE_SENDER, &config, &io);
  rx = mesh_stream_live_create(MESH_STREAM_LIVE_ROLE_RECEIVER, &config, &io);
  check_not_null(tx);
  check_not_null(rx);

  for (size_t i = 0u; i < 8u; i++) {
    fill_block(block, lens[i], i);
    check_int_eq(MESH_STREAM_LIVE_OK,
                 mesh_stream_live_sender_produce(tx, block, lens[i], &seq));
    check_uint_eq(seq, i);
  }
  check_int_eq(MESH_STREAM_LIVE_OK, mesh_stream_live_sender_finish(tx));
  check_uint_eq(mesh_stream_live_live_edge(tx), 7u);
  check_true(mesh_stream_live_complete(tx));

  /* Deliver until END (CLOSE was already drained, so no AGAIN). */
  for (;;) {
    mesh_stream_live_result_t rc =
        pump_once(rx, out, sizeof(out), &len, &seq);

    if (rc == MESH_STREAM_LIVE_END || delivered >= 8u)
      break;
    check_int_eq(MESH_STREAM_LIVE_OK, rc);
    memcpy(got[delivered], out, len);
    seqs[delivered] = seq;
    check_size_eq(len, lens[delivered]);
    delivered++;
  }
  check_size_eq(delivered, 8u);
  for (size_t i = 0u; i < 8u; i++) {
    check_uint_eq(seqs[i], i);
    fill_block(block, lens[i], i);
    check_mem_eq(got[i], block, lens[i]);
  }
  check_uint_eq(mesh_stream_live_delivered(rx), 8u);
  check_uint_eq(mesh_stream_live_skipped(rx), 0u);
  check_uint_eq(mesh_stream_live_recovered(rx), 0u);
  check_uint_eq(mesh_stream_live_live_edge(rx), 7u);
  check_true(mesh_stream_live_complete(rx));

  mesh_stream_live_destroy(tx);
  mesh_stream_live_destroy(rx);
  pipe_reset(&pipe);
}

/* ---- reordering within the window ---- */

static void test_reorder(void) {
  mesh_stream_live_config_v1_t config;
  mesh_stream_live_io_v1_t io = {live_io_send, live_io_recv, NULL};
  live_pipe_t pipe;
  live_io_t send_io;
  mesh_stream_live_t *tx;
  mesh_stream_live_t *rx;
  uint8_t block[TEST_MAX_BLOCK];
  uint8_t got[5][TEST_MAX_BLOCK];
  uint64_t seqs[5];
  uint64_t seq = 0u;
  size_t len = 0u;
  size_t delivered = 0u;

  memset(&pipe, 0, sizeof(pipe));
  make_io(&send_io, &pipe);
  io.context = &send_io;
  make_config(&config, 0u, 0u, 0u);
  tx = mesh_stream_live_create(MESH_STREAM_LIVE_ROLE_SENDER, &config, &io);
  rx = mesh_stream_live_create(MESH_STREAM_LIVE_ROLE_RECEIVER, &config, &io);
  check_not_null(tx);
  check_not_null(rx);

  for (size_t i = 0u; i < 5u; i++) {
    fill_block(block, 128u, i);
    check_int_eq(MESH_STREAM_LIVE_OK,
                 mesh_stream_live_sender_produce(tx, block, 128u, &seq));
  }
  check_int_eq(MESH_STREAM_LIVE_OK, mesh_stream_live_sender_finish(tx));
  /* Frames 1 and 2 arrive out of order; the receiver buffers group 2 while
   * waiting for group 1. */
  pipe_swap(&pipe, 1u, 2u);
  for (size_t i = 0u; i < 5u; i++) {
    mesh_stream_live_result_t rc =
        pump_once(rx, got[i], sizeof(got[i]), &len, &seq);

    check_int_eq(MESH_STREAM_LIVE_OK, rc);
    seqs[i] = seq;
    check_size_eq(len, 128u);
    delivered++;
  }
  check_size_eq(delivered, 5u);
  for (size_t i = 0u; i < 5u; i++) {
    check_uint_eq(seqs[i], i);
    fill_block(block, 128u, i);
    check_mem_eq(got[i], block, 128u);
  }
  {
    mesh_stream_live_result_t rc =
        pump_once(rx, block, sizeof(block), &len, &seq);

    check_int_eq(MESH_STREAM_LIVE_END, rc);
  }
  mesh_stream_live_destroy(tx);
  mesh_stream_live_destroy(rx);
  pipe_reset(&pipe);
}

/* ---- LIVE_SKIP on a lost block ---- */

static void test_live_skip_on_loss(void) {
  mesh_stream_live_config_v1_t config;
  mesh_stream_live_io_v1_t io = {live_io_send, live_io_recv, NULL};
  live_pipe_t pipe;
  live_io_t send_io;
  mesh_stream_live_t *tx;
  mesh_stream_live_t *rx;
  uint8_t block[TEST_MAX_BLOCK];
  uint8_t got[8][TEST_MAX_BLOCK];
  uint64_t seqs[8];
  uint64_t seq = 0u;
  size_t len = 0u;
  size_t delivered = 0u;

  memset(&pipe, 0, sizeof(pipe));
  make_io(&send_io, &pipe);
  send_io.drop_seqs[0] = 3u;
  send_io.drop_count = 1u;
  io.context = &send_io;
  make_config(&config, 0u, 0u, 0u);
  tx = mesh_stream_live_create(MESH_STREAM_LIVE_ROLE_SENDER, &config, &io);
  rx = mesh_stream_live_create(MESH_STREAM_LIVE_ROLE_RECEIVER, &config, &io);
  check_not_null(tx);
  check_not_null(rx);

  for (size_t i = 0u; i < 8u; i++) {
    fill_block(block, 128u, i);
    check_int_eq(MESH_STREAM_LIVE_OK,
                 mesh_stream_live_sender_produce(tx, block, 128u, &seq));
  }
  check_int_eq(MESH_STREAM_LIVE_OK, mesh_stream_live_sender_finish(tx));

  while (delivered < 8u) {
    mesh_stream_live_result_t rc =
        pump_once(rx, got[delivered], sizeof(got[delivered]), &len, &seq);

    if (rc == MESH_STREAM_LIVE_END)
      break;
    check_int_eq(MESH_STREAM_LIVE_OK, rc);
    seqs[delivered] = seq;
    delivered++;
  }
  check_size_eq(delivered, 7u); /* block 3 skipped */
  check_uint_eq(mesh_stream_live_skipped(rx), 1u);
  check_uint_eq(mesh_stream_live_delivered(rx), 7u);
  /* seqs 0,1,2 then 4..7 */
  check_uint_eq(seqs[0], 0u);
  check_uint_eq(seqs[1], 1u);
  check_uint_eq(seqs[2], 2u);
  check_uint_eq(seqs[3], 4u);
  check_uint_eq(seqs[6], 7u);
  check_true(mesh_stream_live_complete(rx));

  mesh_stream_live_destroy(tx);
  mesh_stream_live_destroy(rx);
  pipe_reset(&pipe);
}

/* ---- time-shift join at a live edge ---- */

static void test_join_at_live_edge(void) {
  mesh_stream_live_config_v1_t config;
  mesh_stream_live_io_v1_t io = {live_io_send, live_io_recv, NULL};
  live_pipe_t pipe;
  live_io_t send_io;
  mesh_stream_live_t *tx;
  mesh_stream_live_t *rx;
  uint8_t block[TEST_MAX_BLOCK];
  uint8_t got[8][TEST_MAX_BLOCK];
  uint64_t seqs[8];
  uint64_t seq = 0u;
  size_t len = 0u;
  size_t delivered = 0u;

  memset(&pipe, 0, sizeof(pipe));
  make_io(&send_io, &pipe);
  io.context = &send_io;
  make_config(&config, 0u, 0u, 3u); /* join at seq 3 */
  tx = mesh_stream_live_create(MESH_STREAM_LIVE_ROLE_SENDER, &config, &io);
  rx = mesh_stream_live_create(MESH_STREAM_LIVE_ROLE_RECEIVER, &config, &io);
  check_not_null(tx);
  check_not_null(rx);

  for (size_t i = 0u; i < 8u; i++) {
    fill_block(block, 128u, i);
    check_int_eq(MESH_STREAM_LIVE_OK,
                 mesh_stream_live_sender_produce(tx, block, 128u, &seq));
  }
  check_int_eq(MESH_STREAM_LIVE_OK, mesh_stream_live_sender_finish(tx));

  while (delivered < 8u) {
    mesh_stream_live_result_t rc =
        pump_once(rx, got[delivered], sizeof(got[delivered]), &len, &seq);

    if (rc == MESH_STREAM_LIVE_END)
      break;
    check_int_eq(MESH_STREAM_LIVE_OK, rc);
    seqs[delivered] = seq;
    delivered++;
  }
  check_size_eq(delivered, 5u); /* seqs 3..7 */
  for (size_t i = 0u; i < 5u; i++) {
    check_uint_eq(seqs[i], i + 3u);
    fill_block(block, 128u, i + 3u);
    check_mem_eq(got[i], block, 128u);
  }
  check_uint_eq(mesh_stream_live_skipped(rx), 0u); /* ignored, not skipped */
  check_true(mesh_stream_live_complete(rx));

  mesh_stream_live_destroy(tx);
  mesh_stream_live_destroy(rx);
  pipe_reset(&pipe);
}

/* ---- FEC recovery of one lost data shard ---- */

static void test_fec_recovery(void) {
  mesh_stream_live_config_v1_t config;
  mesh_stream_live_io_v1_t io = {live_io_send, live_io_recv, NULL};
  live_pipe_t pipe;
  live_io_t send_io;
  mesh_stream_live_t *tx;
  mesh_stream_live_t *rx;
  uint8_t block[TEST_MAX_BLOCK];
  uint8_t got[6][TEST_MAX_BLOCK];
  uint64_t seqs[6];
  uint64_t seq = 0u;
  size_t len = 0u;
  size_t delivered = 0u;

  memset(&pipe, 0, sizeof(pipe));
  make_io(&send_io, &pipe);
  send_io.drop_seqs[0] = 1u; /* data shard of group 0 */
  send_io.drop_count = 1u;
  io.context = &send_io;
  make_config(&config, 2u, 1u, 0u); /* 2 data + 1 parity */
  tx = mesh_stream_live_create(MESH_STREAM_LIVE_ROLE_SENDER, &config, &io);
  rx = mesh_stream_live_create(MESH_STREAM_LIVE_ROLE_RECEIVER, &config, &io);
  check_not_null(tx);
  check_not_null(rx);

  for (size_t i = 0u; i < 6u; i++) {
    fill_block(block, 64u, i);
    check_int_eq(MESH_STREAM_LIVE_OK,
                 mesh_stream_live_sender_produce(tx, block, 64u, &seq));
  }
  check_int_eq(MESH_STREAM_LIVE_OK, mesh_stream_live_sender_finish(tx));

  for (;;) {
    mesh_stream_live_result_t rc =
        pump_once(rx, got[delivered], sizeof(got[delivered]), &len, &seq);

    if (rc == MESH_STREAM_LIVE_END || delivered >= 6u)
      break;
    check_int_eq(MESH_STREAM_LIVE_OK, rc);
    seqs[delivered] = seq;
    delivered++;
  }
  check_size_eq(delivered, 6u);
  {
    static const uint64_t exp_seqs[6] = {0u, 1u, 3u, 4u, 6u, 7u};

    for (size_t i = 0u; i < 6u; i++) {
      check_uint_eq(seqs[i], exp_seqs[i]);
      fill_block(block, 64u, fec_block_index(seqs[i]));
      check_mem_eq(got[i], block, 64u); /* seq 1 reconstructed via parity */
    }
  }
  check_uint_eq(mesh_stream_live_recovered(rx), 1u);
  check_uint_eq(mesh_stream_live_skipped(rx), 0u);
  check_uint_eq(mesh_stream_live_delivered(rx), 6u);
  check_true(mesh_stream_live_complete(rx));

  mesh_stream_live_destroy(tx);
  mesh_stream_live_destroy(rx);
  pipe_reset(&pipe);
}

/* ---- FEC group with both data shards lost -> skipped ---- */

static void test_fec_skip_unrecoverable(void) {
  mesh_stream_live_config_v1_t config;
  mesh_stream_live_io_v1_t io = {live_io_send, live_io_recv, NULL};
  live_pipe_t pipe;
  live_io_t send_io;
  mesh_stream_live_t *tx;
  mesh_stream_live_t *rx;
  uint8_t block[TEST_MAX_BLOCK];
  uint8_t got[6][TEST_MAX_BLOCK];
  uint64_t seqs[6];
  uint64_t seq = 0u;
  size_t len = 0u;
  size_t delivered = 0u;

  memset(&pipe, 0, sizeof(pipe));
  make_io(&send_io, &pipe);
  send_io.drop_seqs[0] = 0u; /* both data shards of group 0 lost */
  send_io.drop_seqs[1] = 1u;
  send_io.drop_count = 2u;
  io.context = &send_io;
  make_config(&config, 2u, 1u, 0u);
  tx = mesh_stream_live_create(MESH_STREAM_LIVE_ROLE_SENDER, &config, &io);
  rx = mesh_stream_live_create(MESH_STREAM_LIVE_ROLE_RECEIVER, &config, &io);
  check_not_null(tx);
  check_not_null(rx);

  for (size_t i = 0u; i < 6u; i++) {
    fill_block(block, 64u, i);
    check_int_eq(MESH_STREAM_LIVE_OK,
                 mesh_stream_live_sender_produce(tx, block, 64u, &seq));
  }
  check_int_eq(MESH_STREAM_LIVE_OK, mesh_stream_live_sender_finish(tx));

  for (;;) {
    mesh_stream_live_result_t rc =
        pump_once(rx, got[delivered], sizeof(got[delivered]), &len, &seq);

    if (rc == MESH_STREAM_LIVE_END || delivered >= 6u)
      break;
    check_int_eq(MESH_STREAM_LIVE_OK, rc);
    seqs[delivered] = seq;
    delivered++;
  }
  check_size_eq(delivered, 4u); /* groups 1..2 (data seqs 3,4,6,7) */
  check_uint_eq(mesh_stream_live_skipped(rx), 2u);
  check_uint_eq(mesh_stream_live_recovered(rx), 0u);
  {
    static const uint64_t exp_seqs[4] = {3u, 4u, 6u, 7u};

    for (size_t i = 0u; i < 4u; i++)
      check_uint_eq(seqs[i], exp_seqs[i]);
  }
  check_true(mesh_stream_live_complete(rx));

  mesh_stream_live_destroy(tx);
  mesh_stream_live_destroy(rx);
  pipe_reset(&pipe);
}

/* ---- corrupt frame and out-of-window frame ---- */

static void test_corrupt_and_out_of_window(void) {
  mesh_stream_live_config_v1_t config;
  mesh_stream_live_io_v1_t io = {live_io_send, live_io_recv, NULL};
  live_pipe_t pipe;
  live_io_t rx_io;
  mesh_stream_live_t *rx;
  uint8_t frame[TEST_FRAME_HEADER + 4];
  uint8_t out[TEST_MAX_BLOCK];
  size_t len = 0u;
  uint64_t seq = 0u;

  memset(&pipe, 0, sizeof(pipe));
  make_io(&rx_io, &pipe);
  io.context = &rx_io;
  make_config(&config, 0u, 0u, 0u);
  rx = mesh_stream_live_create(MESH_STREAM_LIVE_ROLE_RECEIVER, &config, &io);
  check_not_null(rx);

  /* Out-of-window DATA frame (group 100 with a window of 8) is ignored. */
  memcpy(frame, TEST_MAGIC, 4);
  frame[4] = 1u;
  frame[5] = 0u;
  frame[6] = 0u;
  frame[7] = 0u;
  frame[8] = 100u;
  frame[9] = 0u;
  frame[10] = 0u;
  frame[11] = 0u;
  frame[12] = 4u;
  memset(frame + TEST_FRAME_HEADER, 0xAB, 4u);
  pipe_push_raw(&pipe, frame, sizeof(frame));
  check_int_eq(MESH_STREAM_LIVE_AGAIN,
               pump_once(rx, out, sizeof(out), &len, &seq));
  check_size_eq(len, 0u);
  check_uint_eq(mesh_stream_live_delivered(rx), 0u);

  /* A frame with a bad magic is a hard corruption error. */
  pipe_reset(&pipe);
  frame[0] = 'X';
  pipe_push_raw(&pipe, frame, sizeof(frame));
  check_int_eq(MESH_STREAM_LIVE_CORRUPT,
               pump_once(rx, out, sizeof(out), &len, &seq));

  mesh_stream_live_destroy(rx);
  pipe_reset(&pipe);
}

/* ---- invalid arguments ---- */

static void test_invalid_args(void) {
  mesh_stream_live_config_v1_t config;
  mesh_stream_live_io_v1_t io = {live_io_send, live_io_recv, NULL};
  live_pipe_t pipe;
  live_io_t send_io;
  mesh_stream_live_t *tx;
  mesh_stream_live_t *rx;
  uint8_t block[TEST_MAX_BLOCK];
  uint64_t seq = 0u;
  size_t len = 0u;

  memset(&pipe, 0, sizeof(pipe));
  make_io(&send_io, &pipe);
  io.context = &send_io;
  make_config(&config, 0u, 0u, 0u);

  check_null(mesh_stream_live_create(MESH_STREAM_LIVE_ROLE_SENDER, NULL, &io));
  check_null(mesh_stream_live_create(MESH_STREAM_LIVE_ROLE_SENDER, &config, NULL));
  check_null(mesh_stream_live_create((mesh_stream_live_role_t)99, &config, &io));
  config.window_groups = 0u;
  check_null(mesh_stream_live_create(MESH_STREAM_LIVE_ROLE_SENDER, &config, &io));
  make_config(&config, 0u, 0u, 0u);
  config.max_block_bytes = 0u;
  check_null(mesh_stream_live_create(MESH_STREAM_LIVE_ROLE_SENDER, &config, &io));
  make_config(&config, 0u, 0u, 0u);
  config.fec_parity_shards = 1u; /* parity without data shards */
  check_null(mesh_stream_live_create(MESH_STREAM_LIVE_ROLE_SENDER, &config, &io));
  make_config(&config, 0u, 0u, 0u);

  tx = mesh_stream_live_create(MESH_STREAM_LIVE_ROLE_SENDER, &config, &io);
  rx = mesh_stream_live_create(MESH_STREAM_LIVE_ROLE_RECEIVER, &config, &io);
  check_not_null(tx);
  check_not_null(rx);

  fill_block(block, 64u, 0u);
  check_int_eq(MESH_STREAM_LIVE_INVALID_ARG,
               mesh_stream_live_sender_produce(NULL, block, 64u, &seq));
  check_int_eq(MESH_STREAM_LIVE_INVALID_ARG,
               mesh_stream_live_sender_produce(rx, block, 64u, &seq));
  check_int_eq(MESH_STREAM_LIVE_INVALID_ARG,
               mesh_stream_live_sender_produce(tx, NULL, 64u, &seq));
  check_int_eq(MESH_STREAM_LIVE_INVALID_ARG,
               mesh_stream_live_sender_produce(tx, block, 0u, &seq));
  check_int_eq(MESH_STREAM_LIVE_INVALID_ARG,
               mesh_stream_live_sender_produce(tx, block, TEST_MAX_BLOCK + 1u, &seq));
  check_int_eq(MESH_STREAM_LIVE_INVALID_ARG,
               mesh_stream_live_sender_produce(tx, block, 64u, NULL));
  check_int_eq(MESH_STREAM_LIVE_OK,
               mesh_stream_live_sender_produce(tx, block, 64u, &seq));
  check_int_eq(MESH_STREAM_LIVE_OK, mesh_stream_live_sender_finish(tx));
  check_int_eq(MESH_STREAM_LIVE_INVALID_ARG,
               mesh_stream_live_sender_produce(tx, block, 64u, &seq));
  check_int_eq(MESH_STREAM_LIVE_OK, mesh_stream_live_sender_finish(tx));

  check_int_eq(MESH_STREAM_LIVE_INVALID_ARG,
               mesh_stream_live_receiver_pump(NULL, block, sizeof(block), &len, &seq));
  check_int_eq(MESH_STREAM_LIVE_INVALID_ARG,
               mesh_stream_live_receiver_pump(tx, block, sizeof(block), &len, &seq));
  check_int_eq(MESH_STREAM_LIVE_INVALID_ARG,
               mesh_stream_live_receiver_pump(rx, block, sizeof(block), NULL, &seq));

  check_uint_eq(mesh_stream_live_delivered(NULL), 0u);
  check_uint_eq(mesh_stream_live_skipped(NULL), 0u);
  check_uint_eq(mesh_stream_live_recovered(NULL), 0u);
  check_uint_eq(mesh_stream_live_live_edge(NULL), 0u);
  check_true(!mesh_stream_live_complete(NULL));

  mesh_stream_live_destroy(tx);
  mesh_stream_live_destroy(rx);
  mesh_stream_live_destroy(NULL);
  pipe_reset(&pipe);
}

spec("mesh stream live") {
    describe("live edge + LIVE_SKIP + FEC") {
        it("encodes and recovers with the XOR erasure codec") {
            test_fec_codec();
        }
        it("delivers an ordered live stream") {
            test_ordered_delivery();
        }
        it("buffers out-of-order blocks and delivers in order") {
            test_reorder();
        }
        it("skips a lost block instead of retransmitting (LIVE_SKIP)") {
            test_live_skip_on_loss();
        }
        it("joins at a time-shift live edge offset") {
            test_join_at_live_edge();
        }
        it("recovers one lost data shard per FEC group") {
            test_fec_recovery();
        }
        it("skips an unrecoverable FEC group") {
            test_fec_skip_unrecoverable();
        }
        it("rejects corrupt frames and ignores out-of-window frames") {
            test_corrupt_and_out_of_window();
        }
        it("rejects invalid arguments") {
            test_invalid_args();
        }
    }
}