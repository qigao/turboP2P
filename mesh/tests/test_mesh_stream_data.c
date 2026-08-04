#include <tinytest.h>

#include "mesh_stream_data.h"

#include <turbo_thread.h>

#include <stdlib.h>
#include <string.h>

/* P1: reliable ordered block-stream session over a pluggable byte transport.
 * The test drives a sender and a receiver over an in-memory frame pipe that
 * can drop / reorder / hold DATA frames, covering loss recovery (NACK + timer
 * resend), reordering, backpressure and reconnect resume. */

#define FRAME_PREFIX 4u
#define HEADER_TYPE_OFFSET (FRAME_PREFIX + 5u)
#define HEADER_SEQ_OFFSET (FRAME_PREFIX + 8u)
#define HEADER_PAYLOAD_LEN_OFFSET (FRAME_PREFIX + 24u)

#define TEST_BLOCK 1024u
#define TEST_WINDOW 8u
#define TEST_TOTAL 4196u /* 4 full blocks + 100 tail */
#define TEST_BLOCKS 5u

static const uint8_t TEST_STREAM_ID[MESH_STREAM_DATA_STREAM_ID_SIZE] = {
    0x50u, 0x51u, 0x52u, 0x53u, 0x54u, 0x55u, 0x56u, 0x57u,
    0x58u, 0x59u, 0x5au, 0x5bu, 0x5cu, 0x5du, 0x5eu, 0x5fu,
};

static uint32_t read_u32(const uint8_t in[4]) {
  return ((uint32_t)in[0] << 24u) | ((uint32_t)in[1] << 16u) |
         ((uint32_t)in[2] << 8u) | (uint32_t)in[3];
}

typedef struct {
  uint8_t *buf;
  size_t cap;
  size_t head;
  size_t len;
  uint8_t drop_seqs[16];
  size_t drop_count;
  uint8_t drop_nack;
  uint8_t hold_seq;
  uint8_t hold_on;
  uint8_t hold_release_next;
  uint8_t *held;
  size_t held_len;
  size_t held_cap;
  size_t dropped;
  uint8_t drop_all;
} frame_pipe_t;

static int pipe_push(frame_pipe_t *p, const uint8_t *bytes, size_t len) {
  if (p->head + p->len + len > p->cap)
    return -1;
  memcpy(p->buf + p->head + p->len, bytes, len);
  p->len += len;
  return 0;
}

static int frame_is_data_dropped(frame_pipe_t *p, const uint8_t *frame) {
  uint32_t seq = read_u32(frame + HEADER_SEQ_OFFSET);

  for (size_t i = 0u; i < p->drop_count; i++) {
    if (p->drop_seqs[i] == (uint8_t)seq) {
      /* Drop once: retransmits of the same block must pass through. */
      p->drop_seqs[i] = p->drop_seqs[p->drop_count - 1u];
      p->drop_count--;
      return 1;
    }
  }
  return 0;
}

static int pipe_pop(frame_pipe_t *p, uint8_t *out, size_t cap, size_t *out_len) {
  *out_len = 0u;
  if (p->drop_all)
    return 0;
  if (p->hold_on && p->hold_release_next) {
    /* Release the held frame on the next call so a later frame went first. */
    if (cap < p->held_len)
      return 0;
    memcpy(out, p->held, p->held_len);
    *out_len = p->held_len;
    p->hold_on = 0;
    p->hold_release_next = 0;
    return 0;
  }
  if (p->len < FRAME_PREFIX)
    return 0;
  {
    uint32_t frame_len = read_u32(p->buf + p->head);
    size_t total = FRAME_PREFIX + (size_t)frame_len;

    if (p->len < total)
      return 0;
    {
      const uint8_t *frame = p->buf + p->head;
      uint8_t type = frame[HEADER_TYPE_OFFSET];
      uint32_t seq = read_u32(frame + HEADER_SEQ_OFFSET);


      if (type == MESH_STREAM_DATA_FRAME_DATA &&
          frame_is_data_dropped(p, frame)) {
        memmove(p->buf + p->head, p->buf + p->head + total, p->len - total);
        p->len -= total;
        p->dropped++;
        return 0;
      }
      if (type == MESH_STREAM_DATA_FRAME_NACK && p->drop_nack) {
        memmove(p->buf + p->head, p->buf + p->head + total, p->len - total);
        p->len -= total;
        p->dropped++;
        return 0;
      }
      if (type == MESH_STREAM_DATA_FRAME_DATA && !p->hold_on &&
          (uint8_t)seq == p->hold_seq) {
        /* Hold this frame; deliver later ones first (reorder). */
        memcpy(p->held, frame, total);
        p->held_len = total;
        p->hold_on = 1;
        memmove(p->buf + p->head, p->buf + p->head + total, p->len - total);
        p->len -= total;
        return 0;
      }
      if (type == MESH_STREAM_DATA_FRAME_DATA && p->hold_on &&
          (uint8_t)seq != p->hold_seq) {
        /* Deliver the later frame now; the held one follows next call. */
        p->hold_release_next = 1;
      }
      if (cap >= total) {
        memcpy(out, frame, total);
        *out_len = total;
        memmove(p->buf + p->head, p->buf + p->head + total, p->len - total);
        p->len -= total;
        return 0;
      }
    }
  }
  return 0;
}

typedef struct {
  frame_pipe_t to_receiver;
  frame_pipe_t to_sender;
  size_t data_frames;
} link_t;

static int link_send_r(void *ctx, const uint8_t *bytes, size_t len) {
  link_t *link = (link_t *)ctx;
  return pipe_push(&link->to_sender, bytes, len) == 0 ? 0 : -1;
}

static int link_recv_r(void *ctx, uint8_t *bytes, size_t cap, size_t *out_len) {
  link_t *link = (link_t *)ctx;
  return pipe_pop(&link->to_receiver, bytes, cap, out_len) == 0 ? 0 : -1;
}

static int link_send_s(void *ctx, const uint8_t *bytes, size_t len) {
  link_t *link = (link_t *)ctx;

  if (len > (size_t)HEADER_TYPE_OFFSET &&
      bytes[HEADER_TYPE_OFFSET] == MESH_STREAM_DATA_FRAME_DATA) {
    link->data_frames++;
  }
  return pipe_push(&link->to_receiver, bytes, len) == 0 ? 0 : -1;
}

static int link_recv_s(void *ctx, uint8_t *bytes, size_t cap, size_t *out_len) {
  link_t *link = (link_t *)ctx;
  return pipe_pop(&link->to_sender, bytes, cap, out_len) == 0 ? 0 : -1;
}

static void link_init(link_t *link) {
  memset(link, 0, sizeof(*link));
  link->to_receiver.hold_seq = 0xffu; /* disabled unless a test sets it */
  link->to_receiver.cap = 256u * 1024u;
  link->to_receiver.buf = (uint8_t *)malloc(link->to_receiver.cap);
  link->to_receiver.held_cap = 8u * 1024u;
  link->to_receiver.held = (uint8_t *)malloc(link->to_receiver.held_cap);
  link->to_sender.cap = 64u * 1024u;
  link->to_sender.buf = (uint8_t *)malloc(link->to_sender.cap);
  check_not_null(link->to_receiver.buf);
  check_not_null(link->to_receiver.held);
  check_not_null(link->to_sender.buf);
}

static void link_destroy(link_t *link) {
  free(link->to_receiver.buf);
  free(link->to_receiver.held);
  free(link->to_sender.buf);
  memset(link, 0, sizeof(*link));
}

static void make_config(mesh_stream_data_config_v1_t *config) {
  memset(config, 0, sizeof(*config));
  memcpy(config->stream_id, TEST_STREAM_ID, sizeof(config->stream_id));
  config->total_size = TEST_TOTAL;
  config->block_size = TEST_BLOCK;
  config->window_blocks = TEST_WINDOW;
  config->max_retransmits = 8u;
  config->resend_timeout_ms = 20u;
}

static void fill_data(uint8_t *data, size_t len) {
  for (size_t i = 0u; i < len; i++)
    data[i] = (uint8_t)(i * 7u + (i >> 8u));
}

/* Drive both sides until the receiver is complete. A real-time deadline bounds
 * the run; sleeping on no progress lets the timer-based resend actually fire. */
static void run_stream(mesh_stream_data_t *sender, mesh_stream_data_t *receiver,
                       const uint8_t *data, size_t data_len, uint8_t *out, size_t out_cap,
                       size_t *out_len, uint64_t *now_ms) {
  size_t fed = 0u;
  size_t got = 0u;
  int finish_sent_flag = 0;
  uint64_t deadline = turbo_monotonic_ms() + 10000u;

  (void)now_ms;
  *out_len = 0u;
  check_int_eq(MESH_STREAM_DATA_OK, mesh_stream_data_sender_start(sender));
  while (turbo_monotonic_ms() < deadline && !mesh_stream_data_complete(receiver)) {
    size_t consumed = 0u;
    size_t n = 0u;

    (void)mesh_stream_data_tick(sender, 0u);
    (void)mesh_stream_data_sender_pump(sender);
    if (fed < data_len) {
      (void)mesh_stream_data_sender_feed(sender, data + fed, data_len - fed, &consumed);
      fed += consumed;
    } else if (!finish_sent_flag) {
      (void)mesh_stream_data_sender_finish(sender);
      finish_sent_flag = 1;
    }
    (void)mesh_stream_data_receiver_pump(receiver, out + got, out_cap - got, &n);
    got += n;
    if (n == 0u)
      turbo_sleep_ms(1);
  }
  if (!finish_sent_flag)
    (void)mesh_stream_data_sender_finish(sender);
  while (turbo_monotonic_ms() < deadline && !mesh_stream_data_complete(receiver)) {
    size_t n = 0u;

    (void)mesh_stream_data_tick(sender, 0u);
    (void)mesh_stream_data_sender_pump(sender);
    (void)mesh_stream_data_receiver_pump(receiver, out + got, out_cap - got, &n);
    got += n;
    if (n == 0u)
      turbo_sleep_ms(1);
  }
  *out_len = got;
}

static void test_roundtrip(void) {
  link_t link;
  mesh_stream_data_config_v1_t config;
  mesh_stream_data_io_v1_t sender_io;
  mesh_stream_data_io_v1_t receiver_io;
  mesh_stream_data_t *sender;
  mesh_stream_data_t *receiver;
  uint8_t data[TEST_TOTAL];
  uint8_t out[TEST_TOTAL + 64];
  size_t out_len = 0u;
  uint64_t now_ms;

  fill_data(data, sizeof(data));
  link_init(&link);
  make_config(&config);
  memset(&sender_io, 0, sizeof(sender_io));
  sender_io.send = link_send_s;
  sender_io.recv = link_recv_s;
  sender_io.context = &link;
  memset(&receiver_io, 0, sizeof(receiver_io));
  receiver_io.send = link_send_r;
  receiver_io.recv = link_recv_r;
  receiver_io.context = &link;

  sender = mesh_stream_data_create(MESH_STREAM_DATA_ROLE_SENDER, &config, &sender_io);
  receiver = mesh_stream_data_create(MESH_STREAM_DATA_ROLE_RECEIVER, &config, &receiver_io);
  check_not_null(sender);
  check_not_null(receiver);
  run_stream(sender, receiver, data, sizeof(data), out, sizeof(out), &out_len, &now_ms);
  check_true(mesh_stream_data_complete(receiver));
  check_size_eq(out_len, sizeof(data));
  check_mem_eq(out, data, sizeof(data));

  mesh_stream_data_destroy(receiver);
  mesh_stream_data_destroy(sender);
  link_destroy(&link);
}

static void test_loss_recovery(void) {
  link_t link;
  mesh_stream_data_config_v1_t config;
  mesh_stream_data_io_v1_t sender_io;
  mesh_stream_data_io_v1_t receiver_io;
  mesh_stream_data_t *sender;
  mesh_stream_data_t *receiver;
  uint8_t data[TEST_TOTAL];
  uint8_t out[TEST_TOTAL + 64];
  size_t out_len = 0u;
  uint64_t now_ms = 1000000u;

  fill_data(data, sizeof(data));
  link_init(&link);
  make_config(&config);
  link.to_receiver.drop_seqs[0] = 2u;
  link.to_receiver.drop_count = 1u;
  memset(&sender_io, 0, sizeof(sender_io));
  sender_io.send = link_send_s;
  sender_io.recv = link_recv_s;
  sender_io.context = &link;
  memset(&receiver_io, 0, sizeof(receiver_io));
  receiver_io.send = link_send_r;
  receiver_io.recv = link_recv_r;
  receiver_io.context = &link;

  sender = mesh_stream_data_create(MESH_STREAM_DATA_ROLE_SENDER, &config, &sender_io);
  receiver = mesh_stream_data_create(MESH_STREAM_DATA_ROLE_RECEIVER, &config, &receiver_io);
  check_not_null(sender);
  check_not_null(receiver);
  run_stream(sender, receiver, data, sizeof(data), out, sizeof(out), &out_len, &now_ms);
  check_true(link.to_receiver.dropped >= 1u);
  check_true(mesh_stream_data_complete(receiver));
  check_size_eq(out_len, sizeof(data));
  check_mem_eq(out, data, sizeof(data));

  mesh_stream_data_destroy(receiver);
  mesh_stream_data_destroy(sender);
  link_destroy(&link);
}

static void test_timer_resend_when_nack_lost(void) {
  link_t link;
  mesh_stream_data_config_v1_t config;
  mesh_stream_data_io_v1_t sender_io;
  mesh_stream_data_io_v1_t receiver_io;
  mesh_stream_data_t *sender;
  mesh_stream_data_t *receiver;
  uint8_t data[TEST_TOTAL];
  uint8_t out[TEST_TOTAL + 64];
  size_t out_len = 0u;
  uint64_t now_ms = 1000000u;

  fill_data(data, sizeof(data));
  link_init(&link);
  make_config(&config);
  config.resend_timeout_ms = 15u;
  link.to_receiver.drop_seqs[0] = 1u;
  link.to_receiver.drop_count = 1u;
  link.to_sender.drop_nack = 1u;
  memset(&sender_io, 0, sizeof(sender_io));
  sender_io.send = link_send_s;
  sender_io.recv = link_recv_s;
  sender_io.context = &link;
  memset(&receiver_io, 0, sizeof(receiver_io));
  receiver_io.send = link_send_r;
  receiver_io.recv = link_recv_r;
  receiver_io.context = &link;

  sender = mesh_stream_data_create(MESH_STREAM_DATA_ROLE_SENDER, &config, &sender_io);
  receiver = mesh_stream_data_create(MESH_STREAM_DATA_ROLE_RECEIVER, &config, &receiver_io);
  check_not_null(sender);
  check_not_null(receiver);
  run_stream(sender, receiver, data, sizeof(data), out, sizeof(out), &out_len, &now_ms);
  check_true(link.to_receiver.dropped >= 1u);
  check_true(link.to_sender.dropped >= 1u);
  check_true(mesh_stream_data_complete(receiver));
  check_size_eq(out_len, sizeof(data));
  check_mem_eq(out, data, sizeof(data));

  mesh_stream_data_destroy(receiver);
  mesh_stream_data_destroy(sender);
  link_destroy(&link);
}

static void test_reorder_recovery(void) {
  link_t link;
  mesh_stream_data_config_v1_t config;
  mesh_stream_data_io_v1_t sender_io;
  mesh_stream_data_io_v1_t receiver_io;
  mesh_stream_data_t *sender;
  mesh_stream_data_t *receiver;
  uint8_t data[TEST_TOTAL];
  uint8_t out[TEST_TOTAL + 64];
  size_t out_len = 0u;
  uint64_t now_ms = 1000000u;

  fill_data(data, sizeof(data));
  link_init(&link);
  make_config(&config);
  link.to_receiver.hold_seq = 1u;
  memset(&sender_io, 0, sizeof(sender_io));
  sender_io.send = link_send_s;
  sender_io.recv = link_recv_s;
  sender_io.context = &link;
  memset(&receiver_io, 0, sizeof(receiver_io));
  receiver_io.send = link_send_r;
  receiver_io.recv = link_recv_r;
  receiver_io.context = &link;

  sender = mesh_stream_data_create(MESH_STREAM_DATA_ROLE_SENDER, &config, &sender_io);
  receiver = mesh_stream_data_create(MESH_STREAM_DATA_ROLE_RECEIVER, &config, &receiver_io);
  check_not_null(sender);
  check_not_null(receiver);
  run_stream(sender, receiver, data, sizeof(data), out, sizeof(out), &out_len, &now_ms);
  check_true(mesh_stream_data_complete(receiver));
  check_size_eq(out_len, sizeof(data));
  check_mem_eq(out, data, sizeof(data));

  mesh_stream_data_destroy(receiver);
  mesh_stream_data_destroy(sender);
  link_destroy(&link);
}

static void test_backpressure(void) {
  link_t link;
  mesh_stream_data_config_v1_t config;
  mesh_stream_data_io_v1_t sender_io;
  mesh_stream_data_io_v1_t receiver_io;
  mesh_stream_data_t *sender;
  mesh_stream_data_t *receiver;
  uint8_t data[TEST_TOTAL];
  uint64_t now_ms = 1000000u;

  fill_data(data, sizeof(data));
  link_init(&link);
  make_config(&config);
  config.window_blocks = 2u; /* 5 blocks exceed the window: backpressure */
  memset(&sender_io, 0, sizeof(sender_io));
  sender_io.send = link_send_s;
  sender_io.recv = link_recv_s;
  sender_io.context = &link;
  memset(&receiver_io, 0, sizeof(receiver_io));
  receiver_io.send = link_send_r;
  receiver_io.recv = link_recv_r;
  receiver_io.context = &link;

  sender = mesh_stream_data_create(MESH_STREAM_DATA_ROLE_SENDER, &config, &sender_io);
  receiver = mesh_stream_data_create(MESH_STREAM_DATA_ROLE_RECEIVER, &config, &receiver_io);
  check_not_null(sender);
  check_not_null(receiver);
  check_int_eq(MESH_STREAM_DATA_OK, mesh_stream_data_sender_start(sender));

  /* Feed more than the whole window without pumping the receiver: the sender
   * must stop accepting (AGAIN) once the window is full. */
  {
    size_t total_consumed = 0u;
    size_t partial = 0u;
    uint64_t iter;

    for (iter = 0u; iter < 100u; iter++) {
      size_t c = 0u;
      mesh_stream_data_result_t rc = mesh_stream_data_sender_feed(
          sender, data + total_consumed, sizeof(data) - total_consumed, &c);

      total_consumed += c;
      partial += c;
      if (rc == MESH_STREAM_DATA_AGAIN && c == 0u)
        break;
      if (total_consumed >= sizeof(data))
        break;
    }
    /* The 2-block window cannot absorb all 5 blocks without ACKs. */
    check_true(total_consumed < sizeof(data));
    check_true(partial > 0u);
  }

  mesh_stream_data_destroy(receiver);
  mesh_stream_data_destroy(sender);
  link_destroy(&link);

  /* Once the receiver drains the window, the full payload transfers. */
  link_init(&link);
  memset(&sender_io, 0, sizeof(sender_io));
  sender_io.send = link_send_s;
  sender_io.recv = link_recv_s;
  sender_io.context = &link;
  memset(&receiver_io, 0, sizeof(receiver_io));
  receiver_io.send = link_send_r;
  receiver_io.recv = link_recv_r;
  receiver_io.context = &link;
  sender = mesh_stream_data_create(MESH_STREAM_DATA_ROLE_SENDER, &config, &sender_io);
  receiver = mesh_stream_data_create(MESH_STREAM_DATA_ROLE_RECEIVER, &config, &receiver_io);
  check_not_null(sender);
  check_not_null(receiver);
  {
    uint8_t out[TEST_TOTAL + 64];
    size_t out_len = 0u;

    run_stream(sender, receiver, data, sizeof(data), out, sizeof(out), &out_len, &now_ms);
    check_true(mesh_stream_data_complete(receiver));
    check_size_eq(out_len, sizeof(data));
    check_mem_eq(out, data, sizeof(data));
  }

  mesh_stream_data_destroy(receiver);
  mesh_stream_data_destroy(sender);
  link_destroy(&link);
}

static void test_resume_after_disconnect(void) {
  link_t link;
  mesh_stream_data_config_v1_t config;
  mesh_stream_data_io_v1_t sender_io;
  mesh_stream_data_io_v1_t receiver_io;
  mesh_stream_data_t *sender;
  mesh_stream_data_t *receiver;
  uint8_t data[TEST_TOTAL];
  uint8_t out[TEST_TOTAL + 64];
  size_t out_len = 0u;
  uint64_t now_ms = 1000000u;

  fill_data(data, sizeof(data));
  link_init(&link);
  make_config(&config);
  memset(&sender_io, 0, sizeof(sender_io));
  sender_io.send = link_send_s;
  sender_io.recv = link_recv_s;
  sender_io.context = &link;
  memset(&receiver_io, 0, sizeof(receiver_io));
  receiver_io.send = link_send_r;
  receiver_io.recv = link_recv_r;
  receiver_io.context = &link;

  sender = mesh_stream_data_create(MESH_STREAM_DATA_ROLE_SENDER, &config, &sender_io);
  receiver = mesh_stream_data_create(MESH_STREAM_DATA_ROLE_RECEIVER, &config, &receiver_io);
  check_not_null(sender);
  check_not_null(receiver);
  check_int_eq(MESH_STREAM_DATA_OK, mesh_stream_data_sender_start(sender));

  /* Deliver the first two blocks, then "disconnect" (drop the pipe). */
  {
    size_t fed = 0u;
    uint64_t iter;
    uint64_t target = 2u * TEST_BLOCK;

    for (iter = 0u; iter < 200000u && fed < target; iter++) {
      size_t c = 0u;
      size_t n = 0u;
      uint8_t sink[4096];

      now_ms += 5u;
      (void)mesh_stream_data_tick(sender, now_ms);
      (void)mesh_stream_data_sender_pump(sender);
      (void)mesh_stream_data_sender_feed(sender, data + fed, target - fed, &c);
      fed += c;
      (void)mesh_stream_data_receiver_pump(receiver, sink, sizeof(sink), &n);
    }
    check_true(mesh_stream_data_receiver_committed(receiver) >= target);
  }
  mesh_stream_data_destroy(receiver);
  mesh_stream_data_destroy(sender);
  link_destroy(&link);

  /* Reconnect: fresh endpoints over a new pipe; the receiver advertises the
   * commit point and the sender must skip the already-delivered blocks. */
  link_init(&link);
  memset(&sender_io, 0, sizeof(sender_io));
  sender_io.send = link_send_s;
  sender_io.recv = link_recv_s;
  sender_io.context = &link;
  memset(&receiver_io, 0, sizeof(receiver_io));
  receiver_io.send = link_send_r;
  receiver_io.recv = link_recv_r;
  receiver_io.context = &link;
  sender = mesh_stream_data_create(MESH_STREAM_DATA_ROLE_SENDER, &config, &sender_io);
  receiver = mesh_stream_data_create(MESH_STREAM_DATA_ROLE_RECEIVER, &config, &receiver_io);
  check_not_null(sender);
  check_not_null(receiver);
  check_int_eq(MESH_STREAM_DATA_OK,
               mesh_stream_data_receiver_send_resume(receiver, 2u * TEST_BLOCK, 2u));
  run_stream(sender, receiver, data, sizeof(data), out, sizeof(out), &out_len, &now_ms);
  check_true(mesh_stream_data_complete(receiver));
  /* Blocks 0..1 were already delivered before the disconnect; the resumed
   * connection delivers only blocks 2..4 (2148 bytes). */
  check_size_eq(out_len, sizeof(data) - 2u * TEST_BLOCK);
  check_mem_eq(out, data + 2u * TEST_BLOCK, sizeof(data) - 2u * TEST_BLOCK);
  /* Only blocks 2..4 (3 DATA frames) cross the wire on the new connection. */
  check_size_eq(link.data_frames, TEST_BLOCKS - 2u);

  mesh_stream_data_destroy(receiver);
  mesh_stream_data_destroy(sender);
  link_destroy(&link);
}

static void test_integrity_and_invalid_args(void) {
  link_t link;
  mesh_stream_data_config_v1_t config;
  mesh_stream_data_io_v1_t sender_io;
  mesh_stream_data_io_v1_t receiver_io;
  mesh_stream_data_t *sender;
  mesh_stream_data_t *receiver;
  uint8_t data[TEST_TOTAL];
  uint8_t out[TEST_TOTAL + 64];
  size_t out_len = 0u;

  fill_data(data, sizeof(data));
  link_init(&link);
  make_config(&config);
  memset(&sender_io, 0, sizeof(sender_io));
  sender_io.send = link_send_s;
  sender_io.recv = link_recv_s;
  sender_io.context = &link;
  memset(&receiver_io, 0, sizeof(receiver_io));
  receiver_io.send = link_send_r;
  receiver_io.recv = link_recv_r;
  receiver_io.context = &link;

  sender = mesh_stream_data_create(MESH_STREAM_DATA_ROLE_SENDER, &config, &sender_io);
  receiver = mesh_stream_data_create(MESH_STREAM_DATA_ROLE_RECEIVER, &config, &receiver_io);
  check_not_null(sender);
  check_not_null(receiver);

  check_null(mesh_stream_data_create(MESH_STREAM_DATA_ROLE_SENDER, NULL, &sender_io));
  check_null(mesh_stream_data_create(MESH_STREAM_DATA_ROLE_SENDER, &config, NULL));
  {
    mesh_stream_data_config_v1_t bad = config;
    bad.block_size = 0u;
    check_null(mesh_stream_data_create(MESH_STREAM_DATA_ROLE_SENDER, &bad, &sender_io));
  }
  check_int_eq(MESH_STREAM_DATA_INVALID_ARG,
               mesh_stream_data_sender_pump(receiver));
  check_int_eq(MESH_STREAM_DATA_INVALID_ARG,
               mesh_stream_data_receiver_pump(sender, out, sizeof(out), &out_len));
  check_int_eq(MESH_STREAM_DATA_INVALID_ARG,
               mesh_stream_data_tick(NULL, 1u));

  mesh_stream_data_destroy(receiver);
  mesh_stream_data_destroy(sender);
  link_destroy(&link);
}

spec("mesh stream data") {
    describe("reliable ordered block stream") {
        it("streams a whole payload in order with verification") {
            test_roundtrip();
        }
        it("recovers from a dropped DATA frame via NACK retransmit") {
            test_loss_recovery();
        }
        it("recovers when the NACK itself is lost via timer resend") {
            test_timer_resend_when_nack_lost();
        }
        it("reorders out-of-order blocks back into sequence") {
            test_reorder_recovery();
        }
        it("applies backpressure when the send window is full") {
            test_backpressure();
        }
        it("resumes after a disconnect from the commit point") {
            test_resume_after_disconnect();
        }
        it("rejects invalid arguments") {
            test_integrity_and_invalid_args();
        }
    }
}
