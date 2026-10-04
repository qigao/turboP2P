#include <tinytest.h>

#include "mesh_mgmt_transport.h"

#include <stdlib.h>
#include <string.h>

#define TEST_CHUNK_CAPACITY 4u

typedef struct {
  const uint8_t *chunks[TEST_CHUNK_CAPACITY];
  size_t chunk_lengths[TEST_CHUNK_CAPACITY];
  size_t chunk_count;
  size_t recv_count;
  size_t release_count;
  size_t send_count;
  int send_result;
  uint64_t token;
  uint8_t sent[MESH_MGMT_FRAME_MAX];
  size_t sent_len;
} fake_io_t;

static size_t encode_test_frame(uint8_t kind, uint8_t signature_byte, uint8_t *output,
                                size_t capacity) {
  mesh_mgmt_frame_input_t input;
  uint8_t signature[MESH_MGMT_SIGNATURE_SIZE];
  size_t output_len = 0u;

  memset(&input, 0, sizeof(input));
  memset(signature, signature_byte, sizeof(signature));
  input.major = MESH_MGMT_MAJOR_V1;
  input.minor = MESH_MGMT_MINOR_V1;
  input.kind = kind;
  input.signature = signature;
  if (mesh_mgmt_frame_encode(&input, output, capacity, &output_len) != MESH_MGMT_CODEC_OK)
    return 0u;
  return output_len;
}

static int fake_recv(void *context, uint8_t **out_bytes, size_t *out_len) {
  fake_io_t *io = (fake_io_t *)context;
  uint8_t *copy;

  if (!out_bytes || !out_len || io->recv_count >= io->chunk_count)
    return -1;
  copy = (uint8_t *)malloc(io->chunk_lengths[io->recv_count]);
  if (!copy)
    return -1;
  memcpy(copy, io->chunks[io->recv_count], io->chunk_lengths[io->recv_count]);
  *out_bytes = copy;
  *out_len = io->chunk_lengths[io->recv_count];
  io->recv_count++;
  return 0;
}

static void fake_release(void *context, uint8_t *bytes) {
  fake_io_t *io = (fake_io_t *)context;

  io->release_count++;
  free(bytes);
}

static int fake_send(void *context, const uint8_t *bytes, size_t len) {
  fake_io_t *io = (fake_io_t *)context;

  io->send_count++;
  if (io->send_result != 0)
    return io->send_result;
  memcpy(io->sent, bytes, len);
  io->sent_len = len;
  return 0;
}

static mesh_mgmt_transport_io_v1_t fake_transport_io(fake_io_t *fake) {
  mesh_mgmt_transport_io_v1_t io;

  memset(&io, 0, sizeof(io));
  io.context = fake;
  io.recv = fake_recv;
  io.release = fake_release;
  io.send = fake_send;
  return io;
}

static void test_receive_preserves_fragmented_and_coalesced_frames(void) {
  fake_io_t fake;
  mesh_mgmt_transport_io_v1_t io;
  mesh_mgmt_transport_v1_t transport;
  mesh_mgmt_transport_receipt_v1_t receipt;
  uint8_t first[128];
  uint8_t second[128];
  uint8_t combined[256];
  size_t first_len;
  size_t second_len;

  memset(&fake, 0, sizeof(fake));
  memset(&transport, 0, sizeof(transport));
  first_len = encode_test_frame(MESH_MGMT_KIND_HELLO, 0x11u, first, sizeof(first));
  second_len = encode_test_frame(MESH_MGMT_KIND_ERROR, 0x22u, second, sizeof(second));
  check_greater(first_len, 3u);
  check_greater(second_len, 0u);
  memcpy(combined, first + 3u, first_len - 3u);
  memcpy(combined + first_len - 3u, second, second_len);
  fake.chunks[0] = first;
  fake.chunk_lengths[0] = 3u;
  fake.chunks[1] = combined;
  fake.chunk_lengths[1] = first_len - 3u + second_len;
  fake.chunk_count = 2u;
  io = fake_transport_io(&fake);

  check_equal(mesh_mgmt_transport_init_v1(&transport, &io), MESH_MGMT_TRANSPORT_OK);
  check_equal(mesh_mgmt_transport_receive_v1(&transport, &receipt), MESH_MGMT_TRANSPORT_OK);
  check_equal(receipt.frame_len, first_len);
  check_equal(receipt.frame, first, first_len);
  check_equal(mesh_mgmt_transport_commit_v1(&transport, &receipt), MESH_MGMT_TRANSPORT_OK);
  check_equal(mesh_mgmt_transport_receive_v1(&transport, &receipt), MESH_MGMT_TRANSPORT_OK);
  check_equal(receipt.frame_len, second_len);
  check_equal(receipt.frame, second, second_len);
  check_equal(mesh_mgmt_transport_commit_v1(&transport, &receipt), MESH_MGMT_TRANSPORT_OK);
  check_equal(fake.recv_count, 2u);
  check_equal(fake.release_count, 2u);
  mesh_mgmt_transport_destroy_v1(&transport);
}

static void test_stale_receipt_cannot_consume_new_frame(void) {
  fake_io_t fake;
  mesh_mgmt_transport_io_v1_t io;
  mesh_mgmt_transport_v1_t transport;
  mesh_mgmt_transport_receipt_v1_t first_receipt;
  mesh_mgmt_transport_receipt_v1_t second_receipt;
  uint8_t first[128];
  uint8_t second[128];
  size_t first_len;
  size_t second_len;

  memset(&fake, 0, sizeof(fake));
  memset(&transport, 0, sizeof(transport));
  first_len = encode_test_frame(MESH_MGMT_KIND_HELLO, 0x31u, first, sizeof(first));
  second_len = encode_test_frame(MESH_MGMT_KIND_ERROR, 0x32u, second, sizeof(second));
  fake.chunks[0] = first;
  fake.chunk_lengths[0] = first_len;
  fake.chunks[1] = second;
  fake.chunk_lengths[1] = second_len;
  fake.chunk_count = 2u;
  io = fake_transport_io(&fake);

  check_equal(mesh_mgmt_transport_init_v1(&transport, &io), MESH_MGMT_TRANSPORT_OK);
  check_equal(mesh_mgmt_transport_receive_v1(&transport, &first_receipt), MESH_MGMT_TRANSPORT_OK);
  check_equal(mesh_mgmt_transport_commit_v1(&transport, &first_receipt), MESH_MGMT_TRANSPORT_OK);
  check_equal(mesh_mgmt_transport_receive_v1(&transport, &second_receipt), MESH_MGMT_TRANSPORT_OK);
  check_equal(mesh_mgmt_transport_commit_v1(&transport, &first_receipt),
               MESH_MGMT_TRANSPORT_INVALID_STATE);
  check_equal(second_receipt.frame, second, second_len);
  check_equal(mesh_mgmt_transport_commit_v1(&transport, &second_receipt), MESH_MGMT_TRANSPORT_OK);
  mesh_mgmt_transport_destroy_v1(&transport);
}

static void test_oversized_prefix_is_terminal_and_released(void) {
  fake_io_t fake;
  mesh_mgmt_transport_io_v1_t io;
  mesh_mgmt_transport_v1_t transport;
  mesh_mgmt_transport_receipt_v1_t receipt;
  uint8_t prefix[MESH_MGMT_PREFIX_SIZE] = {'T', 'M',   'G',   'M', 1u, 0u, 1u,
                                           0u,  0x02u, 0x01u, 0u,  0u, 0u, 0u};

  memset(&fake, 0, sizeof(fake));
  memset(&transport, 0, sizeof(transport));
  fake.chunks[0] = prefix;
  fake.chunk_lengths[0] = sizeof(prefix);
  fake.chunk_count = 1u;
  io = fake_transport_io(&fake);

  check_equal(mesh_mgmt_transport_init_v1(&transport, &io), MESH_MGMT_TRANSPORT_OK);
  check_equal(mesh_mgmt_transport_receive_v1(&transport, &receipt),
               MESH_MGMT_TRANSPORT_RESOURCE_EXHAUSTED);
  check_true(transport.terminal);
  check_equal(fake.release_count, 1u);
  check_equal(mesh_mgmt_transport_receive_v1(&transport, &receipt),
               MESH_MGMT_TRANSPORT_RESOURCE_EXHAUSTED);
  check_equal(fake.recv_count, 1u);
  mesh_mgmt_transport_destroy_v1(&transport);
}

static void test_oversized_recv_chunk_is_terminal_and_released(void) {
  fake_io_t fake;
  mesh_mgmt_transport_io_v1_t io;
  mesh_mgmt_transport_v1_t transport;
  mesh_mgmt_transport_receipt_v1_t receipt;
  uint8_t chunk[MESH_MGMT_FRAME_MAX + 1u];

  memset(&fake, 0, sizeof(fake));
  memset(&transport, 0, sizeof(transport));
  memset(chunk, 0, sizeof(chunk));
  fake.chunks[0] = chunk;
  fake.chunk_lengths[0] = sizeof(chunk);
  fake.chunk_count = 1u;
  io = fake_transport_io(&fake);

  check_equal(mesh_mgmt_transport_init_v1(&transport, &io), MESH_MGMT_TRANSPORT_OK);
  check_equal(mesh_mgmt_transport_receive_v1(&transport, &receipt),
               MESH_MGMT_TRANSPORT_RESOURCE_EXHAUSTED);
  check_true(transport.terminal);
  check_equal(fake.recv_count, 1u);
  check_equal(fake.release_count, 1u);
  mesh_mgmt_transport_destroy_v1(&transport);
}

static void test_send_validates_before_io_and_io_failure_is_terminal(void) {
  fake_io_t fake;
  mesh_mgmt_transport_io_v1_t io;
  mesh_mgmt_transport_v1_t transport;
  uint8_t frame[128];
  size_t frame_len;

  memset(&fake, 0, sizeof(fake));
  memset(&transport, 0, sizeof(transport));
  frame_len = encode_test_frame(MESH_MGMT_KIND_ERROR, 0x41u, frame, sizeof(frame));
  io = fake_transport_io(&fake);

  check_equal(mesh_mgmt_transport_init_v1(&transport, &io), MESH_MGMT_TRANSPORT_OK);
  check_equal(mesh_mgmt_transport_send_v1(&transport, frame, frame_len), MESH_MGMT_TRANSPORT_OK);
  check_equal(fake.send_count, 1u);
  check_equal(fake.sent_len, frame_len);
  check_equal(fake.sent, frame, frame_len);
  frame[0] = 'X';
  check_equal(mesh_mgmt_transport_send_v1(&transport, frame, frame_len),
               MESH_MGMT_TRANSPORT_INVALID_FRAME);
  check_equal(fake.send_count, 1u);
  frame[0] = 'T';
  fake.send_result = -1;
  check_equal(mesh_mgmt_transport_send_v1(&transport, frame, frame_len),
               MESH_MGMT_TRANSPORT_IO_FAILED);
  check_true(transport.terminal);
  mesh_mgmt_transport_destroy_v1(&transport);
}

static int async_recv(void *context, uint8_t **bytes, size_t *len) {
  fake_io_t *fake = context;
  if (fake->recv_count == fake->chunk_count) {
    *bytes = NULL;
    *len = 0u;
    return MESH_MGMT_TRANSPORT_PENDING;
  }
  return fake_recv(context, bytes, len);
}

static int async_send(void *context, const uint8_t *bytes, size_t len, uint64_t token) {
  fake_io_t *fake = context;
  fake->token = token;
  return fake_send(context, bytes, len);
}

static mesh_mgmt_transport_async_io_v1_t async_io(fake_io_t *fake) {
  mesh_mgmt_transport_async_io_v1_t io = {fake, async_recv, fake_release, async_send};
  return io;
}

static void test_async_receive(void) {
  fake_io_t fake = {0};
  mesh_mgmt_transport_v1_t transport = {0};
  mesh_mgmt_transport_async_io_v1_t io = async_io(&fake);
  mesh_mgmt_transport_receipt_v1_t receipt;
  uint8_t frame[128], combined[256];
  size_t len = encode_test_frame(MESH_MGMT_KIND_ERROR, 0x11u, frame, sizeof(frame));
  check_equal(mesh_mgmt_transport_init_async_v1(&transport, &io), MESH_MGMT_TRANSPORT_OK);
  check_equal(mesh_mgmt_transport_receive_v1(&transport, &receipt), MESH_MGMT_TRANSPORT_PENDING);
  check_null(receipt.frame);
  fake.chunks[0] = frame;
  fake.chunk_lengths[0] = 3u;
  fake.chunk_count = 1u;
  check_equal(mesh_mgmt_transport_receive_v1(&transport, &receipt), MESH_MGMT_TRANSPORT_PENDING);
  check_equal(transport.used, 3u);
  check_equal(fake.release_count, 1u);
  check_false(transport.terminal);
  memcpy(combined, frame + 3u, len - 3u);
  memcpy(combined + len - 3u, frame, len);
  fake.chunks[1] = combined;
  fake.chunk_lengths[1] = len * 2u - 3u;
  fake.chunk_count = 2u;
  check_equal(mesh_mgmt_transport_receive_v1(&transport, &receipt), MESH_MGMT_TRANSPORT_OK);
  check_equal(receipt.frame, frame, len);
  check_equal(mesh_mgmt_transport_commit_v1(&transport, &receipt), MESH_MGMT_TRANSPORT_OK);
  check_equal(mesh_mgmt_transport_receive_v1(&transport, &receipt), MESH_MGMT_TRANSPORT_OK);
  check_equal(receipt.frame, frame, len);
  check_equal(mesh_mgmt_transport_commit_v1(&transport, &receipt), MESH_MGMT_TRANSPORT_OK);
  check_equal(mesh_mgmt_transport_receive_v1(&transport, &receipt), MESH_MGMT_TRANSPORT_PENDING);
  check_equal(fake.release_count, 2u);
  mesh_mgmt_transport_destroy_v1(&transport);
}

static void test_async_tokens(int failure) {
  fake_io_t fake = {0};
  mesh_mgmt_transport_v1_t transport = {0};
  mesh_mgmt_transport_async_io_v1_t io = async_io(&fake);
  uint8_t frame[128];
  size_t len = encode_test_frame(MESH_MGMT_KIND_ERROR, 0x11u, frame, sizeof(frame));
  uint64_t first;
  check_equal(mesh_mgmt_transport_init_async_v1(&transport, &io), MESH_MGMT_TRANSPORT_OK);
  check_equal(mesh_mgmt_transport_send_v1(&transport, frame, len), MESH_MGMT_TRANSPORT_PENDING);
  first = fake.token;
  check_equal(mesh_mgmt_transport_send_v1(&transport, frame, len), MESH_MGMT_TRANSPORT_BUSY);
  check_equal(fake.send_count, 1u);
  check_equal(mesh_mgmt_transport_complete_send_v1(&transport, first + 1u, 1, len), MESH_MGMT_TRANSPORT_INVALID_STATE);
  check_equal(transport.pending_send_token, first);
  check_equal(mesh_mgmt_transport_complete_send_v1(&transport, first, 1, len), MESH_MGMT_TRANSPORT_OK);
  check_equal(mesh_mgmt_transport_complete_send_v1(&transport, first, 1, len), MESH_MGMT_TRANSPORT_INVALID_STATE);
  check_equal(mesh_mgmt_transport_send_v1(&transport, frame, len), MESH_MGMT_TRANSPORT_PENDING);
  check_greater(fake.token, first);
  check_equal(mesh_mgmt_transport_complete_send_v1(&transport, first, 1, len), MESH_MGMT_TRANSPORT_INVALID_STATE);
  check_equal(transport.pending_send_token, fake.token);
  if (failure) {
    check_equal(mesh_mgmt_transport_complete_send_v1(&transport, fake.token, failure == 1, failure == 1 ? len - 1u : 0u), MESH_MGMT_TRANSPORT_IO_FAILED);
    check_true(transport.terminal);
    check_equal(transport.pending_send_token, 0u);
    check_equal(mesh_mgmt_transport_send_v1(&transport, frame, len), MESH_MGMT_TRANSPORT_IO_FAILED);
  } else {
    check_equal(mesh_mgmt_transport_complete_send_v1(&transport, fake.token, 1, len), MESH_MGMT_TRANSPORT_OK);
    transport.next_send_token = UINT64_MAX;
    check_equal(mesh_mgmt_transport_send_v1(&transport, frame, len), MESH_MGMT_TRANSPORT_RESOURCE_EXHAUSTED);
    check_equal(fake.send_count, 2u);
  }
  mesh_mgmt_transport_destroy_v1(&transport);
}

spec("mesh management framed transport") {
  describe("explicit asynchronous IO") {
    it("preserves partial input and drains coalesced receipts across pending reads") { test_async_receive(); }
    it("rejects stale/duplicate tokens and token exhaustion without new IO") { test_async_tokens(0); }
    it("makes a matching short completion terminal") { test_async_tokens(1); }
    it("settles a matching failed write terminally") { test_async_tokens(2); }
  }
  describe("bounded receive lifecycle") {
    it("preserves fragmented and coalesced frames") {
      test_receive_preserves_fragmented_and_coalesced_frames();
    }
    it("rejects a stale receipt without consuming the current frame") {
      test_stale_receipt_cannot_consume_new_frame();
    }
    it("makes an oversized prefix terminal and releases its chunk") {
      test_oversized_prefix_is_terminal_and_released();
    }
    it("makes an oversized recv chunk terminal and releases it") {
      test_oversized_recv_chunk_is_terminal_and_released();
    }
  }
  describe("outgoing frame boundary") {
    it("validates before IO and makes send ambiguity terminal") {
      test_send_validates_before_io_and_io_failure_is_terminal();
    }
  }
}
