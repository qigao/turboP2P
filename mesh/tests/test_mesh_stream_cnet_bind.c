#include "mesh_stream_cnet_fixture.h"

spec("mesh stream CNet identity bind") {
  static test_pair_t pair;
  before_each() { init_pair(&pair, TEST_CNET_TLS); init_bind(&pair); }
  after_each() { destroy_pair(&pair); }

  it("uses real TLS writes and authorizes only after CONFIRM terminal; consumes once") {
    mesh_stream_channel_admission_v1_t sender = admission(&pair, 0);
    mesh_stream_channel_admission_v1_t receiver = admission(&pair, 1);
    cnet_connection stale = pair.sender.connection;
    send_init(&pair);
    send_accept(&pair);
    queue_confirm(&pair);
    check_false(mesh_stream_cnet_bind_authorizes_v1(&pair.sender.bind, &sender, pair.now));
    stale.generation++;
    check_equal(mesh_stream_cnet_bind_complete_send_v1(&pair.sender.bind, stale,
                    SALTS_OK, MESH_STREAM_BIND_CONFIRM_SIZE, pair.now), MESH_STREAM_BIND_INVALID_STATE);
    check_equal(pair.sender.bind.state, MESH_STREAM_CNET_CONFIRM_PENDING);
    await_message(&pair, &pair.sender, &pair.receiver);
    check_equal(pair.sender.bind.state, MESH_STREAM_CNET_AUTHENTICATED);
    check_true(mesh_stream_cnet_bind_authorizes_v1(&pair.sender.bind, &sender, pair.now));
    check_false(mesh_stream_cnet_bind_authorizes_v1(&pair.receiver.bind, &receiver, pair.now));
    check_equal(mesh_stream_cnet_bind_finish_v1(&pair.receiver.bind, pair.receiver.received,
                    pair.receiver.received_size, pair.now), MESH_STREAM_BIND_OK);
    check_true(mesh_stream_cnet_bind_authorizes_v1(&pair.receiver.bind, &receiver, pair.now));
    check_equal(pair.store.entries[0].state, MESH_STREAM_BIND_TICKET_CONSUMED);
    check_equal(mesh_stream_cnet_bind_complete_send_v1(&pair.sender.bind, pair.sender.connection,
                    SALTS_OK, MESH_STREAM_BIND_CONFIRM_SIZE, pair.now), MESH_STREAM_BIND_INVALID_STATE);
    check_true(mesh_stream_cnet_bind_authorizes_v1(&pair.sender.bind, &sender, pair.now));
    sender.generation++;
    check_false(mesh_stream_cnet_bind_authorizes_v1(&pair.sender.bind, &sender, pair.now));
    sender = admission(&pair, 0); sender.stream_epoch++;
    check_false(mesh_stream_cnet_bind_authorizes_v1(&pair.sender.bind, &sender, pair.now));
    sender = admission(&pair, 0); sender.remote_peer_id[0] ^= 1u;
    check_false(mesh_stream_cnet_bind_authorizes_v1(&pair.sender.bind, &sender, pair.now));
    sender = admission(&pair, 0); sender.stream_id[0] ^= 1u;
    check_false(mesh_stream_cnet_bind_authorizes_v1(&pair.sender.bind, &sender, pair.now));
    sender = admission(&pair, 0);
    check_false(mesh_stream_cnet_bind_authorizes_v1(&pair.sender.bind, &sender, pair.ticket.expires_at_ms));
    {
      mesh_stream_bind_ticket_v1_t replay = {0};
      check_equal(mesh_stream_bind_responder_finish_v1(&pair.store, pair.receiver.received,
                      pair.receiver.received_size, pair.receiver.bind.channel_binding, pair.now,
                      &replay), MESH_STREAM_BIND_REPLAY);
    }
    await_closed(&pair, &pair.sender);
    check_false(mesh_stream_cnet_bind_authorizes_v1(&pair.sender.bind, &sender, pair.now));
  }

  it("tombstones queued ACCEPT on cancellation even if its write subsequently succeeds") {
    send_init(&pair);
    queue_accept(&pair);
    await_closed(&pair, &pair.receiver);
    check_equal(pair.receiver.published, 0u);
    check_equal(pair.store.entries[0].state, MESH_STREAM_BIND_TICKET_CONSUMED);
    check_false(pair.receiver.bind.challenge_live);
  }

  it("tombstones the challenge on close after ACCEPT but before CONFIRM") {
    send_init(&pair); send_accept(&pair);
    await_closed(&pair, &pair.receiver);
    check_equal(pair.store.entries[0].state, MESH_STREAM_BIND_TICKET_CONSUMED);
  }

  it("never publishes initiator authorization when CONFIRM is cancelled") {
    mesh_stream_channel_admission_v1_t sender = admission(&pair, 0);
    send_init(&pair); send_accept(&pair); queue_confirm(&pair);
    await_closed(&pair, &pair.sender);
    check_equal(pair.sender.published, 0u);
    check_false(mesh_stream_cnet_bind_authorizes_v1(&pair.sender.bind, &sender, pair.now));
  }

  it("rejects a short write terminal and prevents a later success from resurrecting bind") {
    send_init(&pair); queue_accept(&pair);
    check_equal(mesh_stream_cnet_bind_complete_send_v1(&pair.receiver.bind, pair.receiver.connection,
                    SALTS_OK, MESH_STREAM_BIND_ACCEPT_SIZE - 1u, pair.now), MESH_STREAM_BIND_IO_FAILED);
    check_equal(pair.store.entries[0].state, MESH_STREAM_BIND_TICKET_CONSUMED);
    check_equal(mesh_stream_cnet_bind_complete_send_v1(&pair.receiver.bind, pair.receiver.connection,
                    SALTS_OK, MESH_STREAM_BIND_ACCEPT_SIZE, pair.now), MESH_STREAM_BIND_INVALID_STATE);
    await_closed(&pair, &pair.receiver);
  }

  it("expires CONFIRM at send completion without publishing authorization") {
    send_init(&pair); send_accept(&pair); queue_confirm(&pair);
    check_equal(mesh_stream_cnet_bind_complete_send_v1(&pair.sender.bind, pair.sender.connection,
                    SALTS_OK, MESH_STREAM_BIND_CONFIRM_SIZE, pair.ticket.expires_at_ms),
                MESH_STREAM_BIND_EXPIRED);
    check_equal(pair.sender.bind.state, MESH_STREAM_CNET_FAILED);
    check_equal(&pair.sender.bind.initiator, &(mesh_stream_bind_initiator_v1_t){0},
                sizeof(pair.sender.bind.initiator));
    await_closed(&pair, &pair.sender);
  }

  it("rejects tampered ACCEPT and wipes the initiator transcript") {
    send_init(&pair); send_accept(&pair);
    pair.sender.received[pair.sender.received_size - 1u] ^= 1u;
    check_equal(mesh_stream_cnet_bind_confirm_v1(&pair.sender.bind, pair.sender.received,
                    pair.sender.received_size, INITIATOR_KEY, pair.now), MESH_STREAM_BIND_AUTH_FAILED);
    check_equal(pair.sender.bind.state, MESH_STREAM_CNET_FAILED);
    check_equal(&pair.sender.bind.initiator, &(mesh_stream_bind_initiator_v1_t){0},
                sizeof(pair.sender.bind.initiator));
  }

  it("rejects a changed exporter at CONFIRM completion and clears authorization") {
    mesh_stream_channel_admission_v1_t sender = admission(&pair, 0);
    send_init(&pair); send_accept(&pair); queue_confirm(&pair);
    pair.sender.bind.channel_binding[0] ^= 1u;
    pair.sender.expected_send_result = MESH_STREAM_BIND_CHANNEL_MISMATCH;
    await_message(&pair, &pair.sender, &pair.receiver);
    check_equal(pair.sender.bind.state, MESH_STREAM_CNET_FAILED);
    check_equal(pair.sender.settle_result, MESH_STREAM_BIND_CHANNEL_MISMATCH);
    check_false(mesh_stream_cnet_bind_authorizes_v1(&pair.sender.bind, &sender, pair.now));
    check_equal(&pair.sender.bind.initiator, &(mesh_stream_bind_initiator_v1_t){0},
                sizeof(pair.sender.bind.initiator));
  }
}

spec("mesh stream CNet TLS gate") {
  static test_pair_t pair;
  before_each() { memset(&pair, 0, sizeof(pair)); }
  after_each() { destroy_pair(&pair); }

  it("rejects a real negotiated TLS 1.2 connection before admitting INIT") {
    char version[16] = {0};
    size_t length = 0u;
    init_pair(&pair, TEST_OPENSSL_TLS12);
    check_equal(cnet_tls_negotiated_version(&pair.receiver.client, pair.receiver.connection,
                    version, sizeof(version), &length), SALTS_OK);
    check_equal(version, "TLSv1.2", sizeof("TLSv1.2"));
    check_equal(length, sizeof("TLSv1.2") - 1u);
    check_equal(SSL_version(pair.sender.tls12_peer), TLS1_2_VERSION);
    check_equal(mesh_stream_cnet_bind_init_v1(&pair.receiver.bind, &pair.receiver.client,
                    pair.receiver.connection, MESH_STREAM_CNET_ROLE_INITIATOR, NULL),
                MESH_STREAM_BIND_TLS_REQUIRED);
    check_equal(pair.receiver.bind.state, MESH_STREAM_CNET_UNINITIALIZED);
    check_equal(pair.receiver.sent, 0u);
    check_equal(pair.receiver.bind.pending_bytes, 0u);
  }

  it("rejects plaintext, stale handles, and closed connections without retaining credentials") {
    cnet_connection stale;
    uint64_t deadline;
    init_pair(&pair, TEST_PLAINTEXT);
    check_equal(mesh_stream_cnet_bind_init_v1(&pair.sender.bind, &pair.sender.client,
                    pair.sender.connection, MESH_STREAM_CNET_ROLE_INITIATOR, NULL),
                MESH_STREAM_BIND_TLS_REQUIRED);
    stale = pair.sender.connection;
    stale.generation++;
    check_equal(mesh_stream_cnet_bind_init_v1(&pair.sender.bind, &pair.sender.client,
                    stale, MESH_STREAM_CNET_ROLE_INITIATOR, NULL),
                MESH_STREAM_BIND_CHANNEL_EXPORT_FAILED);
    check_equal(cnet_close(&pair.sender.client, pair.sender.connection), SALTS_OK);
    deadline = cmeta_monotonic_ms() + TEST_RUN_TIMEOUT_MS;
    while (!pair.sender.terminal && cmeta_monotonic_ms() < deadline)
      drive_pair(&pair);
    check_true(pair.sender.terminal);
    check_equal(mesh_stream_cnet_bind_init_v1(&pair.sender.bind, &pair.sender.client,
                    pair.sender.connection, MESH_STREAM_CNET_ROLE_INITIATOR, NULL),
                MESH_STREAM_BIND_CHANNEL_EXPORT_FAILED);
    check_equal(&pair.sender.bind, &(mesh_stream_cnet_bind_v1_t){0}, sizeof(pair.sender.bind));
  }
}
