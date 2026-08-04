#include <tinytest.h>

#include <turbo_error.h>
#include <turboraft/raft_coronet_transport.h>

#include <string.h>

/* Phase 2b-ii groundwork: verify the CoroNet raft transport session layer
 * (length-prefixed frames + wire codec + message callback) in deterministic
 * socket-less mode, without TLS or an event loop. Frames are directional:
 * a packet encoded by session A (local=1/peer=2) must be fed into session B
 * (local=2/peer=1), matching the transport's from/to validation. */

typedef struct {
  int received;
  tr_raft_message_t message;
} session_capture_t;

static int capture_message(void *context, const tr_raft_message_t *message) {
  session_capture_t *capture = (session_capture_t *)context;

  capture->received = 1;
  capture->message = *message; /* self-contained (inline entry data) */
  return TURBO_OK;
}

static void make_message(tr_raft_message_t *message, tr_raft_node_id_t from,
                         tr_raft_node_id_t to, uint64_t term, uint64_t index,
                         const uint8_t *payload, size_t payload_size) {
  memset(message, 0, sizeof(*message));
  message->type = TR_RAFT_MSG_APPEND_REQUEST;
  message->from = from;
  message->to = to;
  message->term = term;
  message->previous_log_index = index - 1u;
  message->entry_count = 1u;
  message->entries[0].index = index;
  message->entries[0].term = term;
  message->entries[0].command_id = 42u;
  message->entries[0].data_length = payload_size;
  if (payload_size > 0u) {
    memcpy(message->entries[0].data, payload, payload_size);
  }
}

static void fill_cluster_id(tr_raft_cluster_id_t *cluster_id) {
  memset(cluster_id, 0x4d, sizeof(*cluster_id));
}

static void configure_session(tr_raft_coronet_session_config_t *config,
                              tr_raft_node_id_t local, tr_raft_node_id_t peer,
                              session_capture_t *capture) {
  memset(config, 0, sizeof(*config));
  config->socket = NULL;
  config->owns_socket = 0;
  fill_cluster_id(&config->cluster_id);
  config->local_node_id = local;
  config->peer_node_id = peer;
  config->first_outbound_message_id = 1u;
  config->on_message = capture_message;
  config->message_context = capture;
}

static void test_session_encode_feed_roundtrip(void) {
  tr_raft_coronet_session_config_t config_a;
  tr_raft_coronet_session_config_t config_b;
  tr_raft_coronet_session_t *session_a = NULL;
  tr_raft_coronet_session_t *session_b = NULL;
  session_capture_t capture_a;
  session_capture_t capture_b;
  tr_raft_message_t original;
  tr_raft_message_t message;
  uint8_t payload[8] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80};
  uint8_t packet[TR_RAFT_CORONET_MAX_PACKET_SIZE];
  size_t packet_size = 0u;

  memset(&capture_a, 0, sizeof(capture_a));
  memset(&capture_b, 0, sizeof(capture_b));
  make_message(&original, 1u, 2u, 7u, 3u, payload, sizeof(payload));
  configure_session(&config_a, 1u, 2u, &capture_a);
  configure_session(&config_b, 2u, 1u, &capture_b);

  check_int_eq(TURBO_OK, tr_raft_coronet_session_create(&config_a, &session_a));
  check_int_eq(TURBO_OK, tr_raft_coronet_session_create(&config_b, &session_b));
  check_not_null(session_a);
  check_not_null(session_b);
  check_int_eq(TURBO_OK, tr_raft_coronet_encode_packet(session_a, &original, packet,
                                                       sizeof(packet), &packet_size));
  check_true(packet_size > 0u);

  /* Feed the frame into the peer session and verify the callback. */
  check_int_eq(TURBO_OK, tr_raft_coronet_feed(session_b, packet, packet_size));
  check_int_eq(1, capture_b.received);
  check_int_eq(0, capture_a.received);
  message = capture_b.message;
  check_int_eq(original.type, message.type);
  check_int_eq((int)original.from, (int)message.from);
  check_int_eq((int)original.to, (int)message.to);
  check_int_eq((int)original.term, (int)message.term);
  check_int_eq((int)original.entry.index, (int)message.entry.index);
  check_int_eq((int)original.entry.command_id, (int)message.entry.command_id);
  check_int_eq((int)original.entry.data_length, (int)message.entry.data_length);
  check_mem_eq(original.entry.data, message.entry.data, sizeof(payload));

  check_int_eq(TURBO_OK, tr_raft_coronet_session_destroy(session_b));
  check_int_eq(TURBO_OK, tr_raft_coronet_session_destroy(session_a));
}

static void test_session_split_stream_decodes_frame(void) {
  tr_raft_coronet_session_config_t config_a;
  tr_raft_coronet_session_config_t config_b;
  tr_raft_coronet_session_t *session_a = NULL;
  tr_raft_coronet_session_t *session_b = NULL;
  session_capture_t capture_b;
  tr_raft_message_t original;
  uint8_t payload[4] = {0xaa, 0xbb, 0xcc, 0xdd};
  uint8_t packet[TR_RAFT_CORONET_MAX_PACKET_SIZE];
  size_t packet_size = 0u;

  memset(&capture_b, 0, sizeof(capture_b));
  make_message(&original, 2u, 1u, 5u, 1u, payload, sizeof(payload));
  configure_session(&config_a, 1u, 2u, &capture_b);
  configure_session(&config_b, 2u, 1u, &capture_b);

  check_int_eq(TURBO_OK, tr_raft_coronet_session_create(&config_a, &session_a));
  check_int_eq(TURBO_OK, tr_raft_coronet_session_create(&config_b, &session_b));
  check_int_eq(TURBO_OK, tr_raft_coronet_encode_packet(session_b, &original, packet,
                                                       sizeof(packet), &packet_size));
  /* Feed byte-by-byte; the frame decoder must reassemble. */
  for (size_t i = 0u; i < packet_size; i++) {
    check_int_eq(TURBO_OK, tr_raft_coronet_feed(session_a, packet + i, 1u));
  }
  check_int_eq(1, capture_b.received);
  check_int_eq((int)original.entry.command_id, (int)capture_b.message.entry.command_id);
  check_mem_eq(original.entry.data, capture_b.message.entry.data, sizeof(payload));
  check_int_eq(TURBO_OK, tr_raft_coronet_session_destroy(session_a));
  check_int_eq(TURBO_OK, tr_raft_coronet_session_destroy(session_b));
}

static void test_cross_session_delivery(void) {
  tr_raft_coronet_session_config_t config_a;
  tr_raft_coronet_session_config_t config_b;
  tr_raft_coronet_session_t *session_a = NULL;
  tr_raft_coronet_session_t *session_b = NULL;
  session_capture_t capture_a;
  session_capture_t capture_b;
  tr_raft_message_t original;
  tr_raft_message_t reply;
  uint8_t payload[3] = {0xde, 0xad, 0xbe};
  uint8_t packet[TR_RAFT_CORONET_MAX_PACKET_SIZE];
  size_t packet_size = 0u;

  memset(&capture_a, 0, sizeof(capture_a));
  memset(&capture_b, 0, sizeof(capture_b));
  make_message(&original, 1u, 2u, 11u, 4u, payload, sizeof(payload));
  configure_session(&config_a, 1u, 2u, &capture_a);
  configure_session(&config_b, 2u, 1u, &capture_b);

  check_int_eq(TURBO_OK, tr_raft_coronet_session_create(&config_a, &session_a));
  check_int_eq(TURBO_OK, tr_raft_coronet_session_create(&config_b, &session_b));
  check_int_eq(TURBO_OK, tr_raft_coronet_encode_packet(session_a, &original, packet,
                                                       sizeof(packet), &packet_size));
  check_int_eq(TURBO_OK, tr_raft_coronet_feed(session_b, packet, packet_size));
  check_int_eq(1, capture_b.received);
  check_int_eq(1u, capture_b.message.from);
  check_int_eq(2u, capture_b.message.to);
  check_int_eq((int)original.entry.data_length, (int)capture_b.message.entry.data_length);

  /* Reply in the reverse direction through session B. */
  make_message(&reply, 2u, 1u, 11u, 5u, payload, sizeof(payload));
  check_int_eq(TURBO_OK, tr_raft_coronet_encode_packet(session_b, &reply, packet,
                                                       sizeof(packet), &packet_size));
  check_int_eq(TURBO_OK, tr_raft_coronet_feed(session_a, packet, packet_size));
  check_int_eq(1, capture_a.received);
  check_int_eq(2u, capture_a.message.from);
  check_int_eq(1u, capture_a.message.to);

  check_int_eq(TURBO_OK, tr_raft_coronet_session_destroy(session_b));
  check_int_eq(TURBO_OK, tr_raft_coronet_session_destroy(session_a));
}

spec("m3 raft coronet session") {
  describe("CoroNet raft transport session frame protocol") {
    it("encodes and decodes a length-prefixed frame") { test_session_encode_feed_roundtrip(); }
    it("reassembles a frame from a byte-split stream") {
      test_session_split_stream_decodes_frame();
    }
    it("delivers a message across two peer sessions") { test_cross_session_delivery(); }
  }
}
