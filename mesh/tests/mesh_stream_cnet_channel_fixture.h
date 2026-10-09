#ifndef MESH_STREAM_CNET_CHANNEL_TEST_FIXTURE_H
#define MESH_STREAM_CNET_CHANNEL_TEST_FIXTURE_H

#include "mesh_stream_cnet_fixture.h"

#define CHANNEL_FRAME_MAX 128u
#define CHANNEL_INITIAL_WINDOW 8u
#define CHANNEL_TOTAL_SIZE 12u
#define CHANNEL_DATA_BYTES 4u

static mesh_stream_channel_v1_t *receiver_channel(test_pair_t *pair) {
  mesh_stream_channel_v1_t *channel = owner_channel(&pair->receiver);
  check_not_null(channel);
  return channel;
}

static int verify_hwm(void *context, size_t bytes) {
  test_owner_t *owner = context;
  return bytes == owner->policy_config.max_send_bytes ? SALTS_OK : SALTS_EINVAL;
}

static int verify_timeout(void *context, uint64_t timeout_ms) {
  test_owner_t *owner = context;
  return timeout_ms == owner->policy_config.read_timeout_ms ? SALTS_OK : SALTS_EINVAL;
}

static int consume_stream(void *context, const mesh_stream_receive_event_v1_t *event) {
  test_owner_t *owner = context;
  if (event->frame.type == MESH_STREAM_FRAME_OPEN)
    owner->open_events++;
  else if (event->frame.type == MESH_STREAM_FRAME_DATA)
    owner->data_bytes += event->frame.payload_len;
  else
    return SALTS_EINVAL;
  return SALTS_OK;
}

static mesh_stream_transport_config_v1_t channel_config(test_pair_t *pair) {
  mesh_stream_transport_config_v1_t config = {0};
  memcpy(config.receiver.stream_id, pair->ticket.claims.stream_id, MESH_STREAM_ID_SIZE);
  config.receiver.stream_epoch = pair->ticket.claims.stream_epoch;
  config.receiver.max_frame_size = CHANNEL_FRAME_MAX;
  config.receiver.initial_receive_window = CHANNEL_INITIAL_WINDOW;
  config.receiver.max_receive_window = CHANNEL_INITIAL_WINDOW * 2u;
  config.receiver.max_total_size = CHANNEL_TOTAL_SIZE;
  config.receiver.allowed_class_mask = MESH_STREAM_CLASS_MEDIA_MASK;
  config.window_update_threshold = CHANNEL_DATA_BYTES;
  config.receive_timeout_ms = pair->receiver.policy_config.read_timeout_ms;
  config.send_high_watermark = pair->receiver.policy_config.max_send_bytes;
  return config;
}

static mesh_stream_channel_result_t open_channel(test_pair_t *pair,
    const mesh_stream_channel_admission_v1_t *proof,
    const mesh_stream_transport_config_v1_t *config) {
  mesh_stream_transport_io_v1_t policy = {0};
  policy.set_send_hwm = verify_hwm;
  policy.set_receive_timeout = verify_timeout;
  policy.context = &pair->receiver;
  return mesh_stream_cnet_channel_init_v1(&pair->receiver.channel, &pair->receiver.bind,
      proof, config, &policy, pair->now, consume_stream, &pair->receiver);
}

static void finish_bind(test_pair_t *pair) {
  send_init(pair); send_accept(pair); queue_confirm(pair);
  await_message(pair, &pair->sender, &pair->receiver);
  check_equal(mesh_stream_cnet_bind_finish_v1(&pair->receiver.bind, pair->receiver.received,
                  pair->receiver.received_size, pair->now), MESH_STREAM_BIND_OK);
  pair->sender.application_sender = 1;
}

static size_t encode_stream(test_pair_t *pair, uint8_t type, uint64_t sequence,
                            uint64_t offset, uint8_t wire[CHANNEL_FRAME_MAX]) {
  static const uint8_t metadata[] = {0u, 1u, 0u, 1u, MESH_STREAM_CLASS_MEDIA,
      0u, 2u, 0u, 8u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, CHANNEL_TOTAL_SIZE};
  static const uint8_t payload[CHANNEL_DATA_BYTES] = {1u, 2u, 3u, 4u};
  mesh_stream_frame_input_t input = {0};
  size_t length = 0u;
  memcpy(input.stream_id, pair->ticket.claims.stream_id, MESH_STREAM_ID_SIZE);
  input.stream_epoch = pair->ticket.claims.stream_epoch;
  input.type = type;
  input.sequence = sequence;
  input.offset = offset;
  if (type == MESH_STREAM_FRAME_OPEN) {
    input.metadata = metadata;
    input.metadata_len = sizeof(metadata);
  } else if (type == MESH_STREAM_FRAME_DATA) {
    input.payload = payload;
    input.payload_len = sizeof(payload);
  }
  check_equal(mesh_stream_frame_encode(&input, CHANNEL_FRAME_MAX, wire, CHANNEL_FRAME_MAX,
                                        &length), MESH_STREAM_CODEC_OK);
  return length;
}

static void send_wire(test_pair_t *pair, const uint8_t *wire, size_t length) {
  mem_buffer_t *buffer = mem_get_buffer(mem_global(), length);
  check_not_null(buffer);
  memcpy(mem_buffer_data(buffer), wire, length);
  mem_set_used(buffer, length);
  check_equal(cnet_send_buffer(&pair->sender.client, pair->sender.connection, buffer), SALTS_OK);
  mem_buffer_release(buffer);
}

static void send_stream(test_pair_t *pair, uint8_t type, uint64_t sequence, uint64_t offset) {
  uint8_t wire[CHANNEL_FRAME_MAX];
  size_t length = encode_stream(pair, type, sequence, offset, wire);
  send_wire(pair, wire, length);
}

static void await_held(test_pair_t *pair, size_t peer_bytes) {
  uint64_t deadline = cmeta_monotonic_ms() + TEST_RUN_TIMEOUT_MS;
  while ((!pair->receiver.held_count || pair->sender.received_size < peer_bytes) &&
         cmeta_monotonic_ms() < deadline)
    drive_pair(pair);
  check_equal(pair->receiver.held_count, 1u);
  check_equal(pair->sender.received_size, peer_bytes);
}

static mesh_stream_channel_result_t settle_held(test_pair_t *pair, int status,
                                               size_t bytes, uint64_t now_ms) {
  size_t frames = 0u;
  uint64_t token = pair->receiver.held_token;
  pair->receiver.held_count = 0u;
  mesh_stream_channel_result_t result = mesh_stream_cnet_channel_complete_send_v1(
      &pair->receiver.channel, pair->receiver.connection,
      receiver_channel(pair)->admission.generation, token, status, bytes, now_ms, &frames);
  if (result == MESH_STREAM_CHANNEL_OK)
    request_channel_receive(&pair->receiver);
  return result;
}

static void start_stream(test_pair_t *pair) {
  mesh_stream_channel_admission_v1_t proof = admission(pair, 1);
  mesh_stream_transport_config_v1_t config = channel_config(pair);
  finish_bind(pair);
  check_equal(open_channel(pair, &proof, &config), MESH_STREAM_CHANNEL_OK);
  pair->receiver.hold_terminal = 1;
  expect_message(&pair->sender, MESH_STREAM_FIXED_HEADER_SIZE * 2u);
  request_channel_receive(&pair->receiver);
  send_stream(pair, MESH_STREAM_FRAME_OPEN, 0u, 0u);
  await_held(pair, MESH_STREAM_FIXED_HEADER_SIZE);
}

static void close_stream(test_pair_t *pair) {
  check_equal(mesh_stream_cnet_channel_close_v1(&pair->receiver.channel, pair->receiver.connection,
                  receiver_channel(pair)->admission.generation, pair->now),
              MESH_STREAM_CHANNEL_OK);
  await_closed(pair, &pair->receiver);
}

static void reconnect_pair(test_pair_t *pair) {
  uint64_t deadline = cmeta_monotonic_ms() + TEST_RUN_TIMEOUT_MS;
  cnet_tls_client_config tls_config = {0};
  cnet_connect_options options = {0};
  uint16_t port = 0u;
  char uri[64];
  while ((!pair->sender.terminal || !pair->receiver.terminal) && cmeta_monotonic_ms() < deadline)
    drive_pair(pair);
  check_true(pair->sender.terminal);
  check_true(pair->receiver.terminal);
  test_owner_t *owners[] = {&pair->sender, &pair->receiver};
  for (size_t i = 0u; i < sizeof(owners) / sizeof(owners[0]); ++i) {
    test_owner_t fresh = {0};
    mesh_stream_cnet_channel_destroy_v1(&owners[i]->channel);
    fresh.client = owners[i]->client;
    fresh.policy_config = owners[i]->policy_config;
    *owners[i] = fresh;
  }
  mesh_stream_bind_store_destroy_v1(&pair->store);
  pair->accepted = 0;
  tls_config.size = sizeof(tls_config);
  tls_config.ca_file = MESH_TEST_TLS_CA_FILE;
  tls_config.server_name = "localhost";
  check_equal(cnet_listener_port(&pair->listener, &port), SALTS_OK);
  check_true(snprintf(uri, sizeof(uri), "tls://127.0.0.1:%u", (unsigned int)port) > 0);
  options.uri = uri;
  options.tls = &tls_config;
  options.observer = observer(&pair->sender);
  check_equal(cnet_connect(&pair->sender.client, &options, &pair->sender.connection), SALTS_OK);
  deadline = cmeta_monotonic_ms() + TEST_RUN_TIMEOUT_MS;
  while ((!pair->sender.connected || !pair->receiver.connected) && cmeta_monotonic_ms() < deadline)
    drive_pair(pair);
  check_true(pair->sender.connected);
  check_true(pair->receiver.connected);
  init_bind_generation(pair, 2u);
}


#endif
