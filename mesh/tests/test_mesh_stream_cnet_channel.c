#include "mesh_stream_cnet_channel_fixture.h"

spec("authenticated CNet receiver channel") {
  static test_pair_t pair;
  before_each() { init_pair(&pair, TEST_CNET_TLS); init_bind(&pair); }
  after_each() { destroy_pair(&pair); }

  it("requires completed identity binding, matching claims, and actual client policy") {
    mesh_stream_channel_admission_v1_t proof = admission(&pair, 1);
    mesh_stream_transport_config_v1_t config = channel_config(&pair);
    check_equal(open_channel(&pair, &proof, &config), MESH_STREAM_CHANNEL_AUTH_REQUIRED);
    check_null(receiver_channel(&pair)->transport.buffer);
    finish_bind(&pair);
    proof.generation++;
    check_equal(open_channel(&pair, &proof, &config), MESH_STREAM_CHANNEL_AUTH_REQUIRED);
    proof = admission(&pair, 1);
    config.send_high_watermark++;
    check_equal(open_channel(&pair, &proof, &config), MESH_STREAM_CHANNEL_TRANSPORT_ERROR);
    check_equal(receiver_channel(&pair)->last_io_result, SALTS_EINVAL);
    check_null(pair.receiver.channel.binding);
    config = channel_config(&pair);
    config.receive_timeout_ms++;
    check_equal(open_channel(&pair, &proof, &config), MESH_STREAM_CHANNEL_TRANSPORT_ERROR);
    check_null(receiver_channel(&pair)->transport.buffer);
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
    uint64_t deadline = cmeta_monotonic_ms() + TEST_RUN_TIMEOUT_MS;
    start_stream(&pair);
    check_equal(settle_held(&pair, SALTS_OK, pair.receiver.held_bytes, pair.now), MESH_STREAM_CHANNEL_OK);
    check_equal(mesh_stream_cnet_bind_abort_v1(&pair.receiver.bind, pair.receiver.connection, pair.now),
                MESH_STREAM_BIND_IO_FAILED);
    pair.receiver.expected_channel_result = MESH_STREAM_CHANNEL_AUTH_REQUIRED;
    send_stream(&pair, MESH_STREAM_FRAME_DATA, 1u, 0u);
    while (receiver_channel(&pair)->state == MESH_STREAM_CHANNEL_READY &&
           cmeta_monotonic_ms() < deadline)
      drive_pair(&pair);
    check_equal(receiver_channel(&pair)->state, MESH_STREAM_CHANNEL_REVOKED);
    check_equal(pair.receiver.data_bytes, 0u);
    check_null(receiver_channel(&pair)->transport.buffer);
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
    old_generation = receiver_channel(&pair)->admission.generation;
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
