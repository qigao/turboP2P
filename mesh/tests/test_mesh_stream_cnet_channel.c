#include "mesh_stream_cnet_fixture.h"

#define CHANNEL_FRAME_MAX 128u
#define CHANNEL_INITIAL_WINDOW 8u
#define CHANNEL_TOTAL_SIZE 12u
#define CHANNEL_DATA_BYTES 4u

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
  uint64_t deadline = salts_monotonic_ms() + TEST_RUN_TIMEOUT_MS;
  while ((!pair->receiver.held_count || pair->sender.received_size < peer_bytes) &&
         salts_monotonic_ms() < deadline)
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
      pair->receiver.channel.channel.admission.generation, token, status, bytes, now_ms, &frames);
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
                  pair->receiver.channel.channel.admission.generation, pair->now),
              MESH_STREAM_CHANNEL_OK);
  await_closed(pair, &pair->receiver);
}

static void reconnect_pair(test_pair_t *pair) {
  uint64_t deadline = salts_monotonic_ms() + TEST_RUN_TIMEOUT_MS;
  cnet_tls_client_config tls_config = {0};
  cnet_connect_options options = {0};
  uint16_t port = 0u;
  char uri[64];
  while ((!pair->sender.terminal || !pair->receiver.terminal) && salts_monotonic_ms() < deadline)
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
  deadline = salts_monotonic_ms() + TEST_RUN_TIMEOUT_MS;
  while ((!pair->sender.connected || !pair->receiver.connected) && salts_monotonic_ms() < deadline)
    drive_pair(pair);
  check_true(pair->sender.connected);
  check_true(pair->receiver.connected);
  init_bind_generation(pair, 2u);
}

spec("authenticated CNet receiver channel") {
  static test_pair_t pair;
  before_each() { init_pair(&pair, TEST_CNET_TLS); init_bind(&pair); }
  after_each() { destroy_pair(&pair); }

  it("requires completed identity binding, matching claims, and actual client policy") {
    mesh_stream_channel_admission_v1_t proof = admission(&pair, 1);
    mesh_stream_transport_config_v1_t config = channel_config(&pair);
    check_equal(open_channel(&pair, &proof, &config), MESH_STREAM_CHANNEL_AUTH_REQUIRED);
    check_null(pair.receiver.channel.channel.transport.buffer);
    finish_bind(&pair);
    proof.generation++;
    check_equal(open_channel(&pair, &proof, &config), MESH_STREAM_CHANNEL_AUTH_REQUIRED);
    proof = admission(&pair, 1);
    config.send_high_watermark++;
    check_equal(open_channel(&pair, &proof, &config), MESH_STREAM_CHANNEL_TRANSPORT_ERROR);
    check_equal(pair.receiver.channel.channel.last_io_result, SALTS_EINVAL);
    check_null(pair.receiver.channel.binding);
    config = channel_config(&pair);
    config.receive_timeout_ms++;
    check_equal(open_channel(&pair, &proof, &config), MESH_STREAM_CHANNEL_TRANSPORT_ERROR);
    check_null(pair.receiver.channel.channel.transport.buffer);
    config = channel_config(&pair);
    check_equal(open_channel(&pair, &proof, &config), MESH_STREAM_CHANNEL_OK);
    close_stream(&pair);
  }

  it("delivers real TLS OPEN/DATA and commits ACCEPT/window credit only at their terminals") {
    mesh_stream_channel_v1_t *channel = &pair.receiver.channel.channel;
    mesh_stream_frame_view_t response;
    size_t consumed = 0u, required = 0u;
    uint64_t accept_token;
    size_t frames = 99u;
    start_stream(&pair);
    check_true(pair.receiver.accept_pending_seen);
    check_equal(channel->transport.session.state, MESH_STREAM_SESSION_AWAIT_ACCEPT_SEND);
    check_equal(channel->transport.sent_control_frames, 0u);
    check_equal(pair.receiver.open_events, 1u);
    check_false(pair.receiver.receive_pending);
    accept_token = pair.receiver.held_token;
    check_equal(settle_held(&pair, SALTS_OK, pair.receiver.held_bytes, pair.now), MESH_STREAM_CHANNEL_OK);
    check_equal(channel->transport.session.state, MESH_STREAM_SESSION_ACTIVE);
    check_true(pair.receiver.receive_pending);
    send_stream(&pair, MESH_STREAM_FRAME_DATA, 1u, 0u);
    await_held(&pair, MESH_STREAM_FIXED_HEADER_SIZE * 2u);
    check_equal(pair.receiver.data_bytes, CHANNEL_DATA_BYTES);
    check_equal(pair.receiver.credit_while_pending, CHANNEL_INITIAL_WINDOW);
    check_equal(channel->transport.session.receive_limit, CHANNEL_INITIAL_WINDOW);
    check_equal(mesh_stream_cnet_channel_complete_send_v1(&pair.receiver.channel,
                    pair.receiver.connection, channel->admission.generation, accept_token,
                    SALTS_OK, MESH_STREAM_FIXED_HEADER_SIZE, pair.now, &frames),
                MESH_STREAM_CHANNEL_INVALID_STATE);
    check_equal(frames, 0u);
    check_true(channel->transport.send_pending);
    check_equal(settle_held(&pair, SALTS_OK, pair.receiver.held_bytes, pair.now), MESH_STREAM_CHANNEL_OK);
    check_equal(channel->transport.session.receive_limit, CHANNEL_TOTAL_SIZE);
    check_equal(channel->transport.sent_control_frames, 2u);
    check_equal(mesh_stream_frame_decode(pair.sender.received, pair.sender.received_size,
                    CHANNEL_FRAME_MAX, &response, &consumed, &required), MESH_STREAM_CODEC_OK);
    check_equal(response.type, MESH_STREAM_FRAME_ACCEPT);
    check_equal(response.offset, CHANNEL_INITIAL_WINDOW);
    check_equal(mesh_stream_frame_decode(pair.sender.received + consumed,
                    pair.sender.received_size - consumed, CHANNEL_FRAME_MAX,
                    &response, &consumed, &required), MESH_STREAM_CODEC_OK);
    check_equal(response.type, MESH_STREAM_FRAME_WINDOW_UPDATE);
    check_equal(response.offset, CHANNEL_TOTAL_SIZE);
    close_stream(&pair);
  }

  it("buffers a real OPEN/DATA burst and rejects the old ACCEPT token while WINDOW_UPDATE is pending") {
    mesh_stream_channel_admission_v1_t proof = admission(&pair, 1);
    mesh_stream_transport_config_v1_t config = channel_config(&pair);
    mesh_stream_channel_v1_t *channel = &pair.receiver.channel.channel;
    uint8_t burst[CHANNEL_FRAME_MAX * 2u];
    uint8_t data[CHANNEL_FRAME_MAX];
    size_t open_size, data_size, frames = 99u;
    uint64_t old_token;
    finish_bind(&pair);
    check_equal(open_channel(&pair, &proof, &config), MESH_STREAM_CHANNEL_OK);
    pair.receiver.hold_terminal = 1;
    expect_message(&pair.sender, MESH_STREAM_FIXED_HEADER_SIZE * 2u);
    request_channel_receive(&pair.receiver);
    open_size = encode_stream(&pair, MESH_STREAM_FRAME_OPEN, 0u, 0u, burst);
    data_size = encode_stream(&pair, MESH_STREAM_FRAME_DATA, 1u, 0u, data);
    memcpy(burst + open_size, data, data_size);
    send_wire(&pair, burst, open_size + data_size);
    await_held(&pair, MESH_STREAM_FIXED_HEADER_SIZE);
    check_equal(pair.receiver.data_bytes, 0u);
    check_equal(channel->transport.buffer_end - channel->transport.buffer_begin, data_size);
    old_token = pair.receiver.held_token;
    check_equal(settle_held(&pair, SALTS_OK, pair.receiver.held_bytes, pair.now), MESH_STREAM_CHANNEL_OK);
    check_equal(pair.receiver.data_bytes, CHANNEL_DATA_BYTES);
    check_true(channel->transport.send_pending);
    check_equal(channel->transport.session.receive_limit, CHANNEL_INITIAL_WINDOW);
    check_equal(mesh_stream_cnet_channel_complete_send_v1(&pair.receiver.channel,
                    pair.receiver.connection, proof.generation, old_token, SALTS_OK,
                    MESH_STREAM_FIXED_HEADER_SIZE, pair.now, &frames), MESH_STREAM_CHANNEL_INVALID_STATE);
    check_true(channel->transport.send_pending);
    await_held(&pair, MESH_STREAM_FIXED_HEADER_SIZE * 2u);
    close_stream(&pair);
    check_equal(channel->sent_control_frames, 1u);
    check_equal(channel->received_frames, 2u);
    check_equal(channel->state, MESH_STREAM_CHANNEL_CLOSED);
  }

  it("revokes before delivering DATA when live identity authorization is lost") {
    uint64_t deadline = salts_monotonic_ms() + TEST_RUN_TIMEOUT_MS;
    start_stream(&pair);
    check_equal(settle_held(&pair, SALTS_OK, pair.receiver.held_bytes, pair.now), MESH_STREAM_CHANNEL_OK);
    check_equal(mesh_stream_cnet_bind_abort_v1(&pair.receiver.bind, pair.receiver.connection, pair.now),
                MESH_STREAM_BIND_IO_FAILED);
    pair.receiver.expected_channel_result = MESH_STREAM_CHANNEL_AUTH_REQUIRED;
    send_stream(&pair, MESH_STREAM_FRAME_DATA, 1u, 0u);
    while (pair.receiver.channel.channel.state == MESH_STREAM_CHANNEL_READY &&
           salts_monotonic_ms() < deadline)
      drive_pair(&pair);
    check_equal(pair.receiver.channel.channel.state, MESH_STREAM_CHANNEL_REVOKED);
    check_equal(pair.receiver.data_bytes, 0u);
    check_null(pair.receiver.channel.channel.transport.buffer);
    close_stream(&pair);
  }

  it("cancels pending ACCEPT, clears identity proof, and rejects its late success") {
    mesh_stream_channel_v1_t *channel = &pair.receiver.channel.channel;
    mesh_stream_channel_admission_v1_t proof = admission(&pair, 1);
    uint64_t token;
    size_t frames = 99u;
    start_stream(&pair);
    token = pair.receiver.held_token;
    close_stream(&pair);
    check_equal(channel->state, MESH_STREAM_CHANNEL_CLOSED);
    check_null(channel->transport.buffer);
    check_equal(channel->sent_control_frames, 0u);
    check_false(mesh_stream_cnet_bind_authorizes_v1(&pair.receiver.bind, &proof, pair.now));
    check_equal(mesh_stream_cnet_channel_complete_send_v1(&pair.receiver.channel,
                    pair.receiver.connection, proof.generation, token, SALTS_OK,
                    MESH_STREAM_FIXED_HEADER_SIZE, pair.now, &frames), MESH_STREAM_CHANNEL_INVALID_STATE);
    check_equal(frames, 0u);
  }

  it("rejects stale connection/admission terminals without cancelling the live pending control") {
    mesh_stream_channel_v1_t *channel = &pair.receiver.channel.channel;
    cnet_connection stale;
    size_t frames = 99u;
    start_stream(&pair);
    stale = pair.receiver.connection;
    stale.generation++;
    check_equal(mesh_stream_cnet_channel_complete_send_v1(&pair.receiver.channel, stale,
                    channel->admission.generation, pair.receiver.held_token, SALTS_OK,
                    pair.receiver.held_bytes, pair.now, &frames), MESH_STREAM_CHANNEL_INVALID_STATE);
    check_equal(mesh_stream_cnet_channel_close_v1(&pair.receiver.channel, pair.receiver.connection,
                    channel->admission.generation + 1u, pair.now), MESH_STREAM_CHANNEL_STALE_ADMISSION);
    check_true(channel->transport.send_pending);
    check_equal(settle_held(&pair, SALTS_OK, pair.receiver.held_bytes, pair.now), MESH_STREAM_CHANNEL_OK);
    close_stream(&pair);
  }

  it("rebinds on the same CNet clients and rejects callbacks from the old connection lifetime") {
    cnet_connection old_connection;
    uint64_t old_generation;
    uint64_t old_token;
    size_t frames = 99u;
    start_stream(&pair);
    old_connection = pair.receiver.connection;
    old_generation = pair.receiver.channel.channel.admission.generation;
    old_token = pair.receiver.held_token;
    close_stream(&pair);
    reconnect_pair(&pair);
    check_false(same_connection(old_connection, pair.receiver.connection));
    start_stream(&pair);
    mesh_stream_channel_v1_t *channel = &pair.receiver.channel.channel;
    check_true(channel->admission.generation != old_generation);
    check_equal(mesh_stream_cnet_channel_close_v1(&pair.receiver.channel, old_connection,
                    old_generation, pair.now), MESH_STREAM_CHANNEL_INVALID_STATE);
    check_equal(mesh_stream_cnet_channel_complete_send_v1(&pair.receiver.channel, old_connection,
                    old_generation, old_token, SALTS_OK, MESH_STREAM_FIXED_HEADER_SIZE,
                    pair.now, &frames), MESH_STREAM_CHANNEL_INVALID_STATE);
    check_equal(mesh_stream_cnet_channel_complete_send_v1(&pair.receiver.channel,
                    pair.receiver.connection, old_generation, old_token, SALTS_OK,
                    MESH_STREAM_FIXED_HEADER_SIZE, pair.now, &frames), MESH_STREAM_CHANNEL_STALE_ADMISSION);
    check_equal(mesh_stream_cnet_channel_feed_v1(&pair.receiver.channel, old_connection,
                    old_generation, NULL, 0u, pair.now, &frames), MESH_STREAM_CHANNEL_INVALID_STATE);
    check_equal(frames, 0u);
    check_true(channel->transport.send_pending);
    check_equal(settle_held(&pair, SALTS_OK, pair.receiver.held_bytes, pair.now), MESH_STREAM_CHANNEL_OK);
    close_stream(&pair);
  }

  it("expires authorization at ACCEPT completion without publishing ACTIVE") {
    mesh_stream_channel_v1_t *channel = &pair.receiver.channel.channel;
    start_stream(&pair);
    check_equal(settle_held(&pair, SALTS_OK, pair.receiver.held_bytes, pair.ticket.expires_at_ms),
                MESH_STREAM_CHANNEL_AUTH_REQUIRED);
    check_equal(channel->state, MESH_STREAM_CHANNEL_REVOKED);
    check_null(channel->transport.buffer);
    check_equal(channel->sent_control_frames, 0u);
    check_equal(pair.receiver.bind.state, MESH_STREAM_CNET_FAILED);
    close_stream(&pair);
  }

  it("rejects a matching short terminal, preserves diagnostics, and does not commit ACCEPT") {
    mesh_stream_channel_v1_t *channel = &pair.receiver.channel.channel;
    start_stream(&pair);
    check_equal(settle_held(&pair, SALTS_OK, pair.receiver.held_bytes - 1u, pair.now),
                MESH_STREAM_CHANNEL_TRANSPORT_ERROR);
    check_equal(channel->state, MESH_STREAM_CHANNEL_FAILED);
    check_equal(channel->last_transport_result, MESH_STREAM_TRANSPORT_IO_ERROR);
    check_equal(channel->last_io_result, -1);
    check_equal(channel->sent_control_frames, 0u);
    check_null(channel->transport.buffer);
    close_stream(&pair);
  }

  it("fails at the receive-window bound while ACCEPT is pending and revokes the binding") {
    mesh_stream_channel_v1_t *channel = &pair.receiver.channel.channel;
    uint8_t overflow[CHANNEL_FRAME_MAX + 1u] = {0};
    size_t frames = 99u;
    start_stream(&pair);
    check_equal(mesh_stream_cnet_channel_feed_v1(&pair.receiver.channel,
                    pair.receiver.connection, channel->admission.generation, overflow,
                    sizeof(overflow), pair.now, &frames), MESH_STREAM_CHANNEL_TRANSPORT_ERROR);
    check_equal(channel->last_transport_result, MESH_STREAM_TRANSPORT_RESOURCE_EXHAUSTED);
    check_equal(channel->state, MESH_STREAM_CHANNEL_FAILED);
    check_equal(frames, 0u);
    check_equal(pair.receiver.data_bytes, 0u);
    check_equal(pair.receiver.bind.state, MESH_STREAM_CNET_FAILED);
    check_null(channel->transport.buffer);
    close_stream(&pair);
  }
}
