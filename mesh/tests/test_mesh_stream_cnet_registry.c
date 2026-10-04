#include "mesh_stream_cnet_channel_fixture.h"

#define REGISTRY_OWNER_GENERATION 71u

static mesh_stream_registry_result_t register_receiver(test_pair_t *pair,
    mesh_stream_cnet_channel_v1_t *route, const mesh_stream_channel_admission_v1_t *proof,
    const mesh_stream_transport_config_v1_t *config, mesh_stream_channel_handle_v1_t *handle) {
  mesh_stream_transport_io_v1_t policy = {0};
  policy.set_send_hwm = verify_hwm;
  policy.set_receive_timeout = verify_timeout;
  policy.context = &pair->receiver;
  return mesh_stream_cnet_channel_register_v1(route, &pair->registry, &pair->receiver.bind,
      proof, config, &policy, pair->now, consume_stream, &pair->receiver, handle);
}

static mesh_stream_channel_handle_v1_t start_registered_stream(test_pair_t *pair) {
  mesh_stream_channel_handle_v1_t handle;
  mesh_stream_channel_admission_v1_t proof = admission(pair, 1);
  mesh_stream_transport_config_v1_t config = channel_config(pair);
  finish_bind(pair);
  check_equal(register_receiver(pair, &pair->receiver.channel, &proof, &config, &handle),
              MESH_STREAM_REGISTRY_OK);
  check_equal(pair->receiver.channel.channel.state, MESH_STREAM_CHANNEL_UNINITIALIZED);
  check_null(pair->receiver.channel.channel.transport.buffer);
  pair->receiver.hold_terminal = 1;
  expect_message(&pair->sender, MESH_STREAM_FIXED_HEADER_SIZE * 2u);
  request_channel_receive(&pair->receiver);
  send_stream(pair, MESH_STREAM_FRAME_OPEN, 0u, 0u);
  await_held(pair, MESH_STREAM_FIXED_HEADER_SIZE);
  return handle;
}

static mesh_stream_registry_channel_info_v1_t query(test_pair_t *pair,
                                                   mesh_stream_channel_handle_v1_t handle) {
  mesh_stream_registry_channel_info_v1_t info;
  check_equal(mesh_stream_registry_query_channel_v1(&pair->registry, handle, &info),
              MESH_STREAM_REGISTRY_OK);
  return info;
}

/* Reserve quota through the generic core; its transport rejects any send.
 * This tests registration policy without inventing a second authenticated peer. */
static int reject_reservation_send(void *context, const uint8_t *bytes, size_t len, uint64_t token) {
  (void)context; (void)bytes; (void)len; (void)token;
  return SALTS_EPERM;
}

static mesh_stream_channel_handle_v1_t reserve_slot(test_pair_t *pair, int same_peer) {
  mesh_stream_registry_async_open_v1_t request = {0};
  mesh_stream_channel_handle_v1_t handle;
  request.channel.admission = admission(pair, 1);
  request.channel.admission.stream_id[0]++;
  if (!same_peer)
    request.channel.admission.remote_peer_id[0]++;
  request.channel.transport = channel_config(pair);
  memcpy(request.channel.transport.receiver.stream_id, request.channel.admission.stream_id,
         MESH_STREAM_ID_SIZE);
  request.channel.io.context = &pair->receiver;
  request.channel.io.set_send_hwm = verify_hwm;
  request.channel.io.set_receive_timeout = verify_timeout;
  request.channel.on_event = consume_stream;
  request.channel.event_context = &pair->receiver;
  request.send_async = reject_reservation_send;
  check_equal(mesh_stream_registry_open_async_v1(&pair->registry, &request, &handle),
              MESH_STREAM_REGISTRY_OK);
  return handle;
}

static void assert_obsolete_route(test_pair_t *pair, mesh_stream_cnet_channel_v1_t *old,
                                  cnet_connection old_connection, uint64_t old_generation,
                                  uint64_t old_token) {
  size_t frames = 99u;
  check_null(mesh_stream_cnet_channel_borrow_v1(old));
  check_equal(mesh_stream_cnet_channel_complete_send_v1(old, old_connection, old_generation,
      old_token, SALTS_OK, MESH_STREAM_FIXED_HEADER_SIZE, pair->now, &frames),
      MESH_STREAM_CHANNEL_INVALID_STATE);
  check_equal(frames, 0u);
  check_equal(mesh_stream_cnet_channel_feed_v1(old, old_connection, old_generation,
      NULL, 0u, pair->now, &frames), MESH_STREAM_CHANNEL_INVALID_STATE);
  check_equal(mesh_stream_cnet_channel_close_v1(old, old_connection, old_generation, pair->now),
              MESH_STREAM_CHANNEL_INVALID_STATE);
  mesh_stream_cnet_channel_destroy_v1(old);
  check_true(mesh_stream_cnet_bind_authorizes_v1(&pair->receiver.bind,
      &receiver_channel(pair)->admission, pair->now));
  check_true(receiver_channel(pair)->transport.send_pending);
}

spec("authenticated CNet registry routes") {
  static test_pair_t pair;
  before_each() {
    mesh_stream_registry_config_v1_t config = {1u, 1u, REGISTRY_OWNER_GENERATION};
    init_pair(&pair, TEST_CNET_TLS);
    init_bind(&pair);
    check_equal(mesh_stream_registry_init_v1(&pair.registry, &config), MESH_STREAM_REGISTRY_OK);
  }
  after_each() { destroy_pair(&pair); }

  it("rejects unauthenticated and invalid policy registration without consuming storage") {
    mesh_stream_channel_admission_v1_t proof = admission(&pair, 1);
    mesh_stream_transport_config_v1_t config = channel_config(&pair);
    mesh_stream_channel_handle_v1_t handle;
    check_equal(register_receiver(&pair, &pair.receiver.channel, &proof, &config, &handle),
                MESH_STREAM_REGISTRY_AUTH_REQUIRED);
    check_equal(handle.generation, 0u);
    finish_bind(&pair);
    config.send_high_watermark++;
    check_equal(register_receiver(&pair, &pair.receiver.channel, &proof, &config, &handle),
                MESH_STREAM_REGISTRY_CHANNEL_ERROR);
    check_equal(pair.registry.occupied_channels, 0u);
    check_equal(pair.registry.slots[0].generation, 0u);
    check_null(pair.receiver.channel.registry);
    check_true(mesh_stream_cnet_bind_authorizes_v1(&pair.receiver.bind, &proof, pair.now));
    config = channel_config(&pair);
    check_equal(register_receiver(&pair, &pair.receiver.channel, &proof, &config, &handle),
                MESH_STREAM_REGISTRY_OK);
    mesh_stream_cnet_channel_v1_t duplicate = {0};
    mesh_stream_channel_handle_v1_t rejected;
    check_equal(register_receiver(&pair, &duplicate, &proof, &config, &rejected),
                MESH_STREAM_REGISTRY_DUPLICATE);
    check_equal(rejected.generation, 0u);
    check_null(duplicate.binding);
    mesh_stream_cnet_channel_destroy_v1(&duplicate);
    check_true(mesh_stream_cnet_bind_authorizes_v1(&pair.receiver.bind, &proof, pair.now));
    check_equal(pair.registry.occupied_channels, 1u);
    close_stream(&pair);
  }

  it("preserves the live identity when capacity or per-peer quota refuses admission") {
    finish_bind(&pair);
    mesh_stream_channel_admission_v1_t proof = admission(&pair, 1);
    mesh_stream_transport_config_v1_t config = channel_config(&pair);
    mesh_stream_channel_handle_v1_t reserved = reserve_slot(&pair, 0);
    mesh_stream_channel_handle_v1_t handle;
    check_equal(register_receiver(&pair, &pair.receiver.channel, &proof, &config, &handle),
                MESH_STREAM_REGISTRY_CAPACITY_EXHAUSTED);
    check_equal(handle.generation, 0u);
    check_null(pair.receiver.channel.binding);
    check_true(mesh_stream_cnet_bind_authorizes_v1(&pair.receiver.bind, &proof, pair.now));
    check_equal(mesh_stream_registry_close_v1(&pair.registry, reserved), MESH_STREAM_REGISTRY_OK);
    check_equal(mesh_stream_registry_release_v1(&pair.registry, reserved), MESH_STREAM_REGISTRY_OK);
    reserved = reserve_slot(&pair, 1);
    check_equal(register_receiver(&pair, &pair.receiver.channel, &proof, &config, &handle),
                MESH_STREAM_REGISTRY_PEER_LIMIT);
    check_true(mesh_stream_cnet_bind_authorizes_v1(&pair.receiver.bind, &proof, pair.now));
    check_equal(mesh_stream_registry_close_v1(&pair.registry, reserved), MESH_STREAM_REGISTRY_OK);
    check_equal(mesh_stream_registry_release_v1(&pair.registry, reserved), MESH_STREAM_REGISTRY_OK);
    check_equal(register_receiver(&pair, &pair.receiver.channel, &proof, &config, &handle),
                MESH_STREAM_REGISTRY_OK);
    close_stream(&pair);
  }

  it("uses one registry-owned channel for real TLS OPEN/DATA and ordered control terminals") {
    mesh_stream_channel_handle_v1_t handle = start_registered_stream(&pair);
    mesh_stream_channel_v1_t *channel = NULL;
    check_equal(mesh_stream_registry_borrow_channel_v1(&pair.registry, handle, &channel),
                MESH_STREAM_REGISTRY_OK);
    check_true(channel == receiver_channel(&pair));
    check_equal(mesh_stream_registry_release_v1(&pair.registry, handle),
                MESH_STREAM_REGISTRY_INVALID_STATE);
    mesh_stream_registry_channel_info_v1_t info = query(&pair, handle);
    check_equal(info.received_frames, 1u);
    check_equal(info.sent_control_frames, 0u);
    check_equal(channel->transport.session.state, MESH_STREAM_SESSION_AWAIT_ACCEPT_SEND);
    uint64_t accept_token = pair.receiver.held_token;
    check_equal(settle_held(&pair, SALTS_OK, pair.receiver.held_bytes, pair.now),
                MESH_STREAM_CHANNEL_OK);
    send_stream(&pair, MESH_STREAM_FRAME_DATA, 1u, 0u);
    await_held(&pair, MESH_STREAM_FIXED_HEADER_SIZE * 2u);
    info = query(&pair, handle);
    check_equal(info.received_frames, 2u);
    check_equal(info.sent_control_frames, 1u);
    check_equal(pair.receiver.data_bytes, CHANNEL_DATA_BYTES);
    check_equal(channel->transport.session.receive_limit, CHANNEL_INITIAL_WINDOW);
    size_t frames = 0u;
    check_equal(mesh_stream_cnet_channel_complete_send_v1(&pair.receiver.channel,
        pair.receiver.connection, channel->admission.generation, accept_token,
        SALTS_OK, MESH_STREAM_FIXED_HEADER_SIZE, pair.now, &frames),
        MESH_STREAM_CHANNEL_INVALID_STATE);
    check_true(channel->transport.send_pending);
    check_equal(settle_held(&pair, SALTS_OK, pair.receiver.held_bytes, pair.now),
                MESH_STREAM_CHANNEL_OK);
    info = query(&pair, handle);
    check_equal(info.sent_control_frames, 2u);
    check_equal(channel->transport.session.receive_limit, CHANNEL_TOTAL_SIZE);
    mesh_stream_frame_view_t control;
    size_t consumed = 0u, required = 0u;
    check_equal(mesh_stream_frame_decode(pair.sender.received, MESH_STREAM_FIXED_HEADER_SIZE,
        CHANNEL_FRAME_MAX, &control, &consumed, &required), MESH_STREAM_CODEC_OK);
    check_equal(control.type, MESH_STREAM_FRAME_ACCEPT);
    check_equal(control.offset, CHANNEL_INITIAL_WINDOW);
    check_equal(mesh_stream_frame_decode(pair.sender.received + MESH_STREAM_FIXED_HEADER_SIZE,
        MESH_STREAM_FIXED_HEADER_SIZE, CHANNEL_FRAME_MAX, &control, &consumed, &required), MESH_STREAM_CODEC_OK);
    check_equal(control.type, MESH_STREAM_FRAME_WINDOW_UPDATE);
    check_equal(control.offset, CHANNEL_TOTAL_SIZE);
    close_stream(&pair);
    info = query(&pair, handle);
    check_equal(info.state, MESH_STREAM_CHANNEL_CLOSED);
    check_equal(info.received_frames, 2u);
    check_equal(info.sent_control_frames, 2u);
  }

  it("retires binding immediately on registry close before a held ACCEPT terminal") {
    mesh_stream_channel_handle_v1_t handle = start_registered_stream(&pair);
    check_equal(mesh_stream_registry_close_v1(&pair.registry, handle), MESH_STREAM_REGISTRY_OK);
    check_equal(pair.receiver.bind.state, MESH_STREAM_CNET_FAILED);
    check_equal(query(&pair, handle).state, MESH_STREAM_CHANNEL_CLOSED);
    check_equal(settle_held(&pair, SALTS_OK, pair.receiver.held_bytes, pair.now),
                MESH_STREAM_CHANNEL_INVALID_STATE);
    check_equal(query(&pair, handle).sent_control_frames, 0u);
    check_null(receiver_channel(&pair)->transport.buffer);
    check_equal(mesh_stream_registry_close_v1(&pair.registry, handle), MESH_STREAM_REGISTRY_OK);
    await_closed(&pair, &pair.receiver);
  }

  it("revokes only the matching peer generation and keeps terminal quota until release") {
    mesh_stream_channel_handle_v1_t handle = start_registered_stream(&pair);
    mesh_stream_channel_admission_v1_t proof = admission(&pair, 1);
    size_t revoked = 99u;
    check_equal(mesh_stream_registry_revoke_peer_v1(&pair.registry, proof.remote_peer_id,
        proof.generation + 1u, &revoked), MESH_STREAM_REGISTRY_OK);
    check_equal(revoked, 0u);
    check_equal(pair.receiver.bind.state, MESH_STREAM_CNET_AUTHENTICATED);
    check_equal(mesh_stream_registry_revoke_peer_v1(&pair.registry, proof.remote_peer_id,
        proof.generation, &revoked), MESH_STREAM_REGISTRY_OK);
    check_equal(revoked, 1u);
    check_equal(pair.receiver.bind.state, MESH_STREAM_CNET_FAILED);
    check_equal(query(&pair, handle).state, MESH_STREAM_CHANNEL_REVOKED);
    check_equal(pair.registry.occupied_channels, 1u);
    check_equal(settle_held(&pair, SALTS_OK, pair.receiver.held_bytes, pair.now),
                MESH_STREAM_CHANNEL_INVALID_STATE);
    await_closed(&pair, &pair.receiver);
    check_equal(mesh_stream_registry_release_v1(&pair.registry, handle), MESH_STREAM_REGISTRY_OK);
    check_equal(pair.registry.occupied_channels, 0u);
    check_null(mesh_stream_cnet_channel_borrow_v1(&pair.receiver.channel));
  }

  it("preserves failure diagnostics and retires binding on a matching short terminal") {
    mesh_stream_channel_handle_v1_t handle = start_registered_stream(&pair);
    check_equal(settle_held(&pair, SALTS_OK, pair.receiver.held_bytes - 1u, pair.now),
                MESH_STREAM_CHANNEL_TRANSPORT_ERROR);
    mesh_stream_registry_channel_info_v1_t info = query(&pair, handle);
    check_equal(info.state, MESH_STREAM_CHANNEL_FAILED);
    check_equal(info.last_io_result, -1);
    check_equal(info.sent_control_frames, 0u);
    check_equal(info.received_frames, 1u);
    check_equal(pair.receiver.bind.state, MESH_STREAM_CNET_FAILED);
    await_closed(&pair, &pair.receiver);
  }

  it("rejects an expired grant at terminal") {
    mesh_stream_channel_handle_v1_t handle = start_registered_stream(&pair);
    check_equal(settle_held(&pair, SALTS_OK, pair.receiver.held_bytes,
                           pair.ticket.expires_at_ms), MESH_STREAM_CHANNEL_AUTH_REQUIRED);
    check_equal(query(&pair, handle).state, MESH_STREAM_CHANNEL_REVOKED);
    check_equal(pair.receiver.bind.state, MESH_STREAM_CNET_FAILED);
    check_null(receiver_channel(&pair)->transport.buffer);
    await_closed(&pair, &pair.receiver);
  }

  it("rejects real TLS DATA when binding authorization is aborted") {
    mesh_stream_channel_handle_v1_t handle = start_registered_stream(&pair);
    check_equal(settle_held(&pair, SALTS_OK, pair.receiver.held_bytes, pair.now),
                MESH_STREAM_CHANNEL_OK);
    check_equal(mesh_stream_cnet_bind_abort_v1(&pair.receiver.bind,
        pair.receiver.connection, pair.now), MESH_STREAM_BIND_IO_FAILED);
    pair.receiver.expected_channel_result = MESH_STREAM_CHANNEL_AUTH_REQUIRED;
    send_stream(&pair, MESH_STREAM_FRAME_DATA, 1u, 0u);
    uint64_t deadline = salts_monotonic_ms() + TEST_RUN_TIMEOUT_MS;
    while (receiver_channel(&pair)->state == MESH_STREAM_CHANNEL_READY &&
           salts_monotonic_ms() < deadline)
      drive_pair(&pair);
    check_equal(query(&pair, handle).state, MESH_STREAM_CHANNEL_REVOKED);
    check_equal(pair.receiver.data_bytes, 0u);
    check_equal(query(&pair, handle).received_frames, 1u);
    await_closed(&pair, &pair.receiver);
  }

  it("retires binding when the quiescent registry is destroyed") {
    finish_bind(&pair);
    mesh_stream_channel_admission_v1_t proof = admission(&pair, 1);
    mesh_stream_transport_config_v1_t config = channel_config(&pair);
    mesh_stream_channel_handle_v1_t handle;
    check_equal(register_receiver(&pair, &pair.receiver.channel, &proof, &config, &handle),
                MESH_STREAM_REGISTRY_OK);
    /* No application demand or write has been submitted after binding. */
    mesh_stream_registry_destroy_v1(&pair.registry);
    check_equal(pair.receiver.bind.state, MESH_STREAM_CNET_FAILED);
    check_null(mesh_stream_cnet_channel_borrow_v1(&pair.receiver.channel));
    mesh_stream_cnet_channel_destroy_v1(&pair.receiver.channel);
    await_closed(&pair, &pair.receiver);
  }

  it("protects reused slots after the same CNet clients reconnect and rebind") {
    mesh_stream_channel_handle_v1_t old_handle = start_registered_stream(&pair);
    cnet_connection old_connection = pair.receiver.connection;
    uint64_t old_token = pair.receiver.held_token;
    close_stream(&pair);
    check_equal(mesh_stream_registry_release_v1(&pair.registry, old_handle), MESH_STREAM_REGISTRY_OK);
    /* A retired route snapshot has no pending IO or callback registration. */
    mesh_stream_cnet_channel_v1_t old = pair.receiver.channel;
    reconnect_pair(&pair);
    mesh_stream_channel_handle_v1_t fresh = start_registered_stream(&pair);
    check_equal(fresh.slot, old_handle.slot);
    check_equal(fresh.generation, old_handle.generation + 1u);
    assert_obsolete_route(&pair, &old, old_connection, 1u, old_token);
    check_equal(mesh_stream_registry_close_v1(&pair.registry, old_handle),
                MESH_STREAM_REGISTRY_STALE_HANDLE);
    check_equal(query(&pair, fresh).state, MESH_STREAM_CHANNEL_READY);
    check_equal(settle_held(&pair, SALTS_OK, pair.receiver.held_bytes, pair.now),
                MESH_STREAM_CHANNEL_OK);
    close_stream(&pair);
  }

  it("protects a reincarnated registry even when its slot generation and token are reused") {
    mesh_stream_channel_handle_v1_t old_handle = start_registered_stream(&pair);
    cnet_connection old_connection = pair.receiver.connection;
    uint64_t old_token = pair.receiver.held_token;
    close_stream(&pair);
    mesh_stream_registry_destroy_v1(&pair.registry);
    mesh_stream_cnet_channel_v1_t old = pair.receiver.channel;
    mesh_stream_registry_config_v1_t config = {1u, 1u, REGISTRY_OWNER_GENERATION + 1u};
    check_equal(mesh_stream_registry_init_v1(&pair.registry, &config), MESH_STREAM_REGISTRY_OK);
    reconnect_pair(&pair);
    mesh_stream_channel_handle_v1_t fresh = start_registered_stream(&pair);
    check_equal(fresh.slot, old_handle.slot);
    check_equal(fresh.generation, old_handle.generation);
    check_equal(pair.receiver.held_token, old_token);
    assert_obsolete_route(&pair, &old, old_connection, 1u, old_token);
    size_t frames = 99u;
    check_equal(mesh_stream_registry_complete_send_v1(&pair.registry, old_handle, 1u,
        old_token, SALTS_OK, MESH_STREAM_FIXED_HEADER_SIZE, &frames),
        MESH_STREAM_REGISTRY_STALE_HANDLE);
    check_equal(frames, 0u);
    check_equal(settle_held(&pair, SALTS_OK, pair.receiver.held_bytes, pair.now),
                MESH_STREAM_CHANNEL_OK);
    close_stream(&pair);
  }
}
