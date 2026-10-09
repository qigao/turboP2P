#ifndef MESH_STREAM_CNET_TEST_FIXTURE_H
#define MESH_STREAM_CNET_TEST_FIXTURE_H

#include <tinytest.h>
#include <cnet/cnet.h>
#include <salts/clock.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "mesh_stream_cnet_adapter.h"

#include <stdio.h>
#include <string.h>

#define TEST_FRAME_MAX 1024u
#define TEST_SEND_HWM 1024u
#define TEST_TIMEOUT_MS 3000u
#define TEST_RUN_TIMEOUT_MS 5000u
#define TEST_EPOCH 31u

typedef enum { TEST_CNET_TLS, TEST_OPENSSL_TLS12, TEST_PLAINTEXT } test_peer_kind_t;

typedef struct {
  cnet_client client;
  cnet_connection connection;
  mesh_stream_cnet_bind_v1_t bind;
  mesh_stream_cnet_channel_v1_t channel;
  cnet_client_config policy_config;
  int application_sender;
  int receive_pending;
  int hold_terminal;
  uint64_t held_token;
  size_t held_bytes;
  size_t held_count;
  size_t open_events;
  size_t data_bytes;
  int accept_pending_seen;
  uint64_t credit_while_pending;
  int expected_channel_result;
  int connected;
  int terminal;
  int failed;
  int settle_result;
  int expected_send_result;
  size_t sent;
  size_t published;
  size_t received_size;
  uint8_t received[MESH_STREAM_BIND_INIT_SIZE];
  size_t expected;
  SSL *tls12_peer;
  int cipher_pending;
} test_owner_t;

typedef struct {
  test_owner_t sender;
  test_owner_t receiver;
  cnet_listener listener;
  cnet_tls_server tls;
  int accepted;
  mesh_stream_bind_store_v1_t store;
  mesh_stream_bind_ticket_v1_t ticket;
  mesh_stream_registry_v1_t registry;
  uint64_t now;
  test_peer_kind_t peer_kind;
} test_pair_t;

/* A test-only TLS 1.2 client over public plaintext CNet. OpenSSL owns the TLS
 * engine; one retained ciphertext write at a time keeps the fixture bounded. */
static void flush_tls12_cipher(test_owner_t *owner) {
  uint8_t cipher[TEST_SEND_HWM];
  int size;
  int status;
  mem_buffer_t *buffer;
  if (owner->cipher_pending || BIO_ctrl_pending(SSL_get_wbio(owner->tls12_peer)) == 0u)
    return;
  size = BIO_read(SSL_get_wbio(owner->tls12_peer), cipher, sizeof(cipher));
  if (size <= 0) { owner->failed = 1; return; }
  buffer = mem_get_buffer(mem_global(), (size_t)size);
  if (!buffer) { owner->failed = 1; return; }
  memcpy(mem_buffer_data(buffer), cipher, (size_t)size);
  mem_set_used(buffer, (size_t)size);
  status = cnet_send_buffer(&owner->client, owner->connection, buffer);
  mem_buffer_release(buffer);
  if (status != SALTS_OK) { owner->failed = 1; return; }
  owner->cipher_pending = 1;
}

static void receive_tls12(test_owner_t *owner, const cnet_receive_view *view) {
  int result;
  int error;
  if (!view || view->kind != CNET_MESSAGE_BYTES || !view->data ||
      view->size > TEST_FRAME_MAX ||
      BIO_write(SSL_get_rbio(owner->tls12_peer), view->data, (int)view->size) != (int)view->size) {
    owner->failed = 1;
    return;
  }
  result = SSL_do_handshake(owner->tls12_peer);
  if (result == 1) {
    owner->connected = 1;
  } else {
    error = SSL_get_error(owner->tls12_peer, result);
    if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
      ERR_print_errors_fp(stderr);
      owner->failed = 1;
      return;
    }
  }
  flush_tls12_cipher(owner);
  if (!owner->connected && cnet_receive(&owner->client, owner->connection, 1u) != SALTS_OK)
    owner->failed = 1;
}

static mesh_stream_channel_v1_t *owner_channel(test_owner_t *owner) {
  return mesh_stream_cnet_channel_borrow_v1(&owner->channel);
}

static void request_channel_receive(test_owner_t *owner) {
  if (!owner_channel(owner) || owner->receive_pending || owner_channel(owner)->state != MESH_STREAM_CHANNEL_READY ||
      owner_channel(owner)->transport.send_pending)
    return;
  if (cnet_receive(&owner->client, owner->connection, 1u) != SALTS_OK) {
    owner->failed = 1;
    return;
  }
  owner->receive_pending = 1;
}

static int same_connection(cnet_connection a, cnet_connection b) {
  return a.slot == b.slot && a.generation == b.generation;
}

static void on_state(void *user, cnet_connection connection, cnet_connection_state state,
                     const cnet_error *error) {
  test_owner_t *owner = user;
  if (!same_connection(connection, owner->connection)) {
    owner->failed = 1;
    return;
  }
  if (state == CNET_CONNECTION_CONNECTED) {
    if (owner->tls12_peer) {
      int result = SSL_do_handshake(owner->tls12_peer);
      if (result != 1 && SSL_get_error(owner->tls12_peer, result) != SSL_ERROR_WANT_READ)
        owner->failed = 1;
      flush_tls12_cipher(owner);
      if (cnet_receive(&owner->client, connection, 1u) != SALTS_OK)
        owner->failed = 1;
    } else {
      owner->connected = 1;
    }
  } else if (state == CNET_CONNECTION_CLOSED || state == CNET_CONNECTION_FAILED) {
    owner->terminal = 1;
    if (owner_channel(owner) && owner_channel(owner)->state != MESH_STREAM_CHANNEL_UNINITIALIZED)
      (void)mesh_stream_cnet_channel_close_v1(&owner->channel, connection,
          owner_channel(owner)->admission.generation, cmeta_monotonic_ms());
    if (owner->bind.state != MESH_STREAM_CNET_UNINITIALIZED)
      owner->settle_result = mesh_stream_cnet_bind_abort_v1(
          &owner->bind, connection, cmeta_monotonic_ms());
  }
}

static void on_send(void *user, cnet_connection connection, size_t bytes) {
  test_owner_t *owner = user;
  if (!same_connection(connection, owner->connection)) {
    owner->failed = 1;
    return;
  }
  owner->sent++;
  if (owner->tls12_peer) {
    owner->cipher_pending = 0;
    flush_tls12_cipher(owner);
    return;
  }
  if (owner->application_sender)
    return;
  if (!owner_channel(owner)) { owner->failed = 1; return; }
  if (owner_channel(owner)->state != MESH_STREAM_CHANNEL_UNINITIALIZED) {
    mesh_stream_transport_v1_t *transport = &owner_channel(owner)->transport;
    size_t frames = 0u;
    uint64_t token = transport->pending_send_token;
    if (owner->hold_terminal && transport->send_pending) {
      if (owner->held_count) { owner->failed = 1; return; }
      owner->held_token = token;
      owner->held_bytes = bytes;
      owner->held_count = 1u;
      return;
    }
    owner->settle_result = mesh_stream_cnet_channel_complete_send_v1(&owner->channel,
        connection, owner_channel(owner)->admission.generation, token, SALTS_OK,
        bytes, cmeta_monotonic_ms(), &frames);
    if (owner->settle_result != owner->expected_channel_result &&
        !(owner_channel(owner)->state != MESH_STREAM_CHANNEL_READY &&
          owner->settle_result == MESH_STREAM_CHANNEL_INVALID_STATE))
      owner->failed = 1;
    if (owner->settle_result == MESH_STREAM_CHANNEL_OK)
      request_channel_receive(owner);
    return;
  }
  owner->settle_result = mesh_stream_cnet_bind_complete_send_v1(
      &owner->bind, connection, SALTS_OK, bytes, cmeta_monotonic_ms());
  if (owner->bind.state == MESH_STREAM_CNET_AUTHENTICATED)
    owner->published++;
  if (owner->settle_result != owner->expected_send_result &&
      !(owner->bind.state == MESH_STREAM_CNET_FAILED &&
        owner->settle_result == MESH_STREAM_BIND_INVALID_STATE))
    owner->failed = 1;
}

static void on_receive(void *user, cnet_connection connection, const cnet_receive_view *view) {
  test_owner_t *owner = user;
  if (owner->tls12_peer && same_connection(connection, owner->connection)) {
    receive_tls12(owner, view);
    return;
  }
  if (!owner_channel(owner) || !same_connection(connection, owner->connection) || !view ||
      view->kind != CNET_MESSAGE_BYTES || !view->data ||
      (owner_channel(owner)->state == MESH_STREAM_CHANNEL_UNINITIALIZED &&
       view->size > sizeof(owner->received) - owner->received_size)) {
    owner->failed = 1;
    return;
  }
  if (view->size == 0u)
    return;
  if (owner_channel(owner)->state != MESH_STREAM_CHANNEL_UNINITIALIZED) {
    size_t frames = 0u;
    owner->receive_pending = 0;
    owner->settle_result = mesh_stream_cnet_channel_feed_v1(&owner->channel, connection,
        owner_channel(owner)->admission.generation, view->data, view->size,
        cmeta_monotonic_ms(), &frames);
    if (owner->settle_result != owner->expected_channel_result) {
      owner->failed = 1;
      return;
    }
    if (owner_channel(owner)->transport.send_pending) {
      if (owner_channel(owner)->transport.session.state == MESH_STREAM_SESSION_AWAIT_ACCEPT_SEND)
        owner->accept_pending_seen = 1;
      owner->credit_while_pending = owner_channel(owner)->transport.session.receive_limit;
    }
    request_channel_receive(owner);
    return;
  }
  memcpy(owner->received + owner->received_size, view->data, view->size);
  owner->received_size += view->size;
  if (owner->received_size < owner->expected &&
      cnet_receive(&owner->client, connection, 1u) != SALTS_OK)
    owner->failed = 1;
}

static cnet_client_config client_config(void) {
  cnet_client_config config = {0};
#ifdef _WIN32
  config.backend = NATIVE_IO_BACKEND_IOCP;
#elif defined(__linux__)
  config.backend = NATIVE_IO_BACKEND_EPOLL;
#else
  config.backend = NATIVE_IO_BACKEND_KQUEUE;
#endif
  config.connection_capacity = 2u;
  config.command_capacity = 16u;
  config.request_capacity = 8u;
  config.completion_batch_capacity = 8u;
  config.event_capacity = 16u;
  config.max_send_bytes = TEST_SEND_HWM;
  config.receive_buffer_bytes = TEST_FRAME_MAX;
  config.connect_timeout_ms = TEST_TIMEOUT_MS;
  config.read_timeout_ms = TEST_TIMEOUT_MS;
  config.write_timeout_ms = TEST_TIMEOUT_MS;
  config.tls_io_buffer_bytes = CNET_TLS_MIN_IO_BUFFER_BYTES;
  config.tls_handshake_timeout_ms = TEST_TIMEOUT_MS;
  return config;
}

static cnet_observer observer(test_owner_t *owner) {
  cnet_observer value = {0};
  value.on_state = on_state;
  value.on_receive = on_receive;
  value.user = owner;
  value.on_send = on_send;
  return value;
}

static void drive_pair(test_pair_t *pair) {
  size_t events = 0u;
  int ready = 0;
  check_equal(cnet_client_poll(&pair->sender.client, 1u, &events), SALTS_OK);
  if (!pair->accepted) {
    check_equal(cnet_listener_wait(&pair->listener, 0u, &ready), SALTS_OK);
    if (ready) {
      cnet_observer callbacks = observer(&pair->receiver);
      if (pair->peer_kind != TEST_PLAINTEXT)
        check_equal(cnet_listener_accept_tls(&pair->listener, &pair->receiver.client, &pair->tls,
                                             &callbacks, &pair->receiver.connection), SALTS_OK);
      else
        check_equal(cnet_listener_accept(&pair->listener, &pair->receiver.client,
                                         &callbacks, &pair->receiver.connection), SALTS_OK);
      pair->accepted = 1;
    }
  }
  check_equal(cnet_client_poll(&pair->receiver.client, 1u, &events), SALTS_OK);
  check_false(pair->sender.failed);
  check_false(pair->receiver.failed);
}

static void init_pair(test_pair_t *pair, test_peer_kind_t peer_kind) {
  cnet_client_config config = client_config();
  cnet_listener_config listener_config = {config.backend, "127.0.0.1", 0u, 2u};
  cnet_tls_server_config server_config = {0};
  cnet_tls_client_config tls_config = {0};
  cnet_connect_options options = {0};
  uint64_t deadline = cmeta_monotonic_ms() + TEST_RUN_TIMEOUT_MS;
  uint16_t port = 0u;
  char uri[64];

  memset(pair, 0, sizeof(*pair));
  pair->peer_kind = peer_kind;
  server_config.size = sizeof(server_config);
  server_config.cert_file = MESH_TEST_TLS_CERT_FILE;
  server_config.key_file = MESH_TEST_TLS_KEY_FILE;
  server_config.client_auth = CNET_TLS_CLIENT_AUTH_NONE;
  tls_config.size = sizeof(tls_config);
  tls_config.ca_file = MESH_TEST_TLS_CA_FILE;
  tls_config.server_name = "localhost";
  if (peer_kind != TEST_PLAINTEXT)
    check_equal(cnet_tls_server_init(&pair->tls, &server_config), SALTS_OK);
  if (peer_kind == TEST_OPENSSL_TLS12) {
    SSL_CTX *context = SSL_CTX_new(TLS_client_method());
    BIO *input = BIO_new(BIO_s_mem());
    BIO *output = BIO_new(BIO_s_mem());
    check_not_null(context);
    check_not_null(input);
    check_not_null(output);
    check_equal(SSL_CTX_set_min_proto_version(context, TLS1_2_VERSION), 1);
    check_equal(SSL_CTX_set_max_proto_version(context, TLS1_2_VERSION), 1);
    check_equal(SSL_CTX_set1_groups_list(context, "P-256"), 1);
    check_equal(SSL_CTX_set_cipher_list(context, "ECDHE-RSA-AES128-GCM-SHA256"), 1);
    check_equal(SSL_CTX_load_verify_locations(context, MESH_TEST_TLS_CA_FILE, NULL), 1);
    SSL_CTX_set_verify(context, SSL_VERIFY_PEER, NULL);
    /* GmSSL TLS 1.2 omits RFC 5746. This negative-test peer permits only
     * the initial legacy handshake; production binding still requires 1.3. */
    SSL_CTX_set_options(context, SSL_OP_LEGACY_SERVER_CONNECT | SSL_OP_NO_RENEGOTIATION);
    pair->sender.tls12_peer = SSL_new(context);
    SSL_CTX_free(context);
    check_not_null(pair->sender.tls12_peer);
    check_equal(SSL_set1_host(pair->sender.tls12_peer, "localhost"), 1);
    check_equal(SSL_set_tlsext_host_name(pair->sender.tls12_peer, "localhost"), 1);
    SSL_set_bio(pair->sender.tls12_peer, input, output);
    SSL_set_connect_state(pair->sender.tls12_peer);
  }
  pair->sender.policy_config = config;
  pair->receiver.policy_config = config;
  check_equal(cnet_client_init(&pair->sender.client, &config), SALTS_OK);
  check_equal(cnet_client_init(&pair->receiver.client, &config), SALTS_OK);
  check_equal(cnet_listener_init(&pair->listener, &listener_config), SALTS_OK);
  check_equal(cnet_listener_port(&pair->listener, &port), SALTS_OK);
  check_true(snprintf(uri, sizeof(uri), "%s://127.0.0.1:%u",
                     peer_kind == TEST_CNET_TLS ? "tls" : "tcp", (unsigned int)port) > 0);
  options.uri = uri;
  options.observer = observer(&pair->sender);
  options.tls = peer_kind == TEST_CNET_TLS ? &tls_config : NULL;
  check_equal(cnet_connect(&pair->sender.client, &options, &pair->sender.connection), SALTS_OK);
  while ((!pair->sender.connected || !pair->receiver.connected) &&
         cmeta_monotonic_ms() < deadline)
    drive_pair(pair);
  check_true(pair->sender.connected);
  check_true(pair->receiver.connected);
}

static void destroy_pair(test_pair_t *pair) {
  test_owner_t *owners[] = {&pair->sender, &pair->receiver};
  for (size_t i = 0u; i < sizeof(owners) / sizeof(owners[0]); ++i) {
    mesh_stream_cnet_channel_destroy_v1(&owners[i]->channel);
    if (owners[i]->client.impl) {
      check_equal(cnet_client_stop(&owners[i]->client, TEST_RUN_TIMEOUT_MS), SALTS_OK);
      check_equal(cnet_client_destroy(&owners[i]->client), SALTS_OK);
    }
    SSL_free(owners[i]->tls12_peer);
    owners[i]->tls12_peer = NULL;
  }
  mesh_stream_registry_destroy_v1(&pair->registry);
  mesh_stream_bind_store_destroy_v1(&pair->store);
  if (pair->listener.impl) {
    check_equal(cnet_listener_close(&pair->listener), SALTS_OK);
    check_equal(cnet_listener_destroy(&pair->listener), SALTS_OK);
  }
  if (pair->tls.impl)
    check_equal(cnet_tls_server_destroy(&pair->tls), SALTS_OK);
}

static const uint8_t INITIATOR_KEY[32] = {1u};
static const uint8_t RESPONDER_KEY[32] = {2u};
#define TEST_TICKET_TTL_MS 30000u

static void init_bind_generation(test_pair_t *pair, uint64_t generation) {
  mesh_stream_bind_store_config_v1_t config = {2u, TEST_TICKET_TTL_MS};
  mesh_stream_bind_claims_v1_t claims = {0};
  pair->now = cmeta_monotonic_ms();
  claims.mesh_id_hash[0] = 1u;
  claims.initiator_node_id[0] = 2u;
  claims.responder_node_id[0] = 3u;
  claims.stream_id[0] = 4u;
  claims.stream_epoch = TEST_EPOCH;
  claims.admission_generation = generation;
  check_equal(mesh_mgmt_ed25519_public_from_private(INITIATOR_KEY, claims.initiator_principal_key),
              MESH_MGMT_CRYPTO_OK);
  check_equal(mesh_mgmt_ed25519_public_from_private(RESPONDER_KEY, claims.responder_principal_key),
              MESH_MGMT_CRYPTO_OK);
  check_equal(mesh_stream_bind_store_init_v1(&pair->store, &config), MESH_STREAM_BIND_OK);
  check_equal(mesh_stream_bind_ticket_issue_v1(&pair->store, &claims, pair->now,
                  TEST_TICKET_TTL_MS, &pair->ticket), MESH_STREAM_BIND_OK);
  check_equal(mesh_stream_cnet_bind_init_v1(&pair->sender.bind, &pair->sender.client,
                  pair->sender.connection, MESH_STREAM_CNET_ROLE_INITIATOR, NULL), MESH_STREAM_BIND_OK);
  check_equal(mesh_stream_cnet_bind_init_v1(&pair->receiver.bind, &pair->receiver.client,
                  pair->receiver.connection, MESH_STREAM_CNET_ROLE_RESPONDER, &pair->store), MESH_STREAM_BIND_OK);
}

static void init_bind(test_pair_t *pair) { init_bind_generation(pair, 1u); }

static void expect_message(test_owner_t *owner, size_t len) {
  owner->received_size = 0u;
  owner->expected = len;
  memset(owner->received, 0, sizeof(owner->received));
  check_equal(cnet_receive(&owner->client, owner->connection, 1u), SALTS_OK);
}

static void await_message(test_pair_t *pair, test_owner_t *writer, test_owner_t *reader) {
  uint64_t deadline = cmeta_monotonic_ms() + TEST_RUN_TIMEOUT_MS;
  while ((writer->bind.pending_bytes || reader->received_size < reader->expected) &&
         cmeta_monotonic_ms() < deadline)
    drive_pair(pair);
  check_equal(writer->bind.pending_bytes, 0u);
  check_equal(reader->received_size, reader->expected);
}

static void send_init(test_pair_t *pair) {
  expect_message(&pair->receiver, MESH_STREAM_BIND_INIT_SIZE);
  check_equal(mesh_stream_cnet_bind_start_v1(&pair->sender.bind, &pair->ticket,
                  INITIATOR_KEY, pair->now), MESH_STREAM_BIND_OK);
  check_equal(pair->sender.bind.state, MESH_STREAM_CNET_INIT_PENDING);
  await_message(pair, &pair->sender, &pair->receiver);
  check_equal(pair->sender.bind.state, MESH_STREAM_CNET_WAIT_ACCEPT);
}

static void queue_accept(test_pair_t *pair) {
  expect_message(&pair->sender, MESH_STREAM_BIND_ACCEPT_SIZE);
  check_equal(mesh_stream_cnet_bind_accept_v1(&pair->receiver.bind, pair->receiver.received,
                  pair->receiver.received_size, RESPONDER_KEY, pair->now), MESH_STREAM_BIND_OK);
  check_equal(pair->receiver.bind.state, MESH_STREAM_CNET_ACCEPT_PENDING);
  check_equal(pair->store.entries[0].state, MESH_STREAM_BIND_TICKET_CHALLENGE);
}

static void send_accept(test_pair_t *pair) {
  queue_accept(pair);
  await_message(pair, &pair->receiver, &pair->sender);
  check_equal(pair->receiver.bind.state, MESH_STREAM_CNET_WAIT_CONFIRM);
}

static void queue_confirm(test_pair_t *pair) {
  expect_message(&pair->receiver, MESH_STREAM_BIND_CONFIRM_SIZE);
  check_equal(mesh_stream_cnet_bind_confirm_v1(&pair->sender.bind, pair->sender.received,
                  pair->sender.received_size, INITIATOR_KEY, pair->now), MESH_STREAM_BIND_OK);
  check_equal(pair->sender.bind.state, MESH_STREAM_CNET_CONFIRM_PENDING);
  check_equal(pair->sender.bind.ticket.expires_at_ms, 0u);
}

static mesh_stream_channel_admission_v1_t admission(test_pair_t *pair, int responder) {
  mesh_stream_channel_admission_v1_t value = {0};
  const mesh_stream_bind_claims_v1_t *claims = &pair->ticket.claims;
  memcpy(value.remote_peer_id, responder ? claims->initiator_node_id : claims->responder_node_id, 32u);
  memcpy(value.stream_id, claims->stream_id, sizeof(value.stream_id));
  value.generation = claims->admission_generation;
  value.stream_epoch = claims->stream_epoch;
  return value;
}

static void await_closed(test_pair_t *pair, test_owner_t *owner) {
  uint64_t deadline = cmeta_monotonic_ms() + TEST_RUN_TIMEOUT_MS;
  /* Cancel authorization before submitting the asynchronous close command;
   * a queued logical write can still succeed while close is being processed. */
  check_equal(mesh_stream_cnet_bind_abort_v1(&owner->bind, owner->connection,
                  cmeta_monotonic_ms()), MESH_STREAM_BIND_IO_FAILED);
  check_equal(cnet_close(&owner->client, owner->connection), SALTS_OK);
  while (!owner->terminal && cmeta_monotonic_ms() < deadline)
    drive_pair(pair);
  check_true(owner->terminal);
  check_equal(owner->bind.state, MESH_STREAM_CNET_FAILED);
  check_equal(&owner->bind.ticket, &(mesh_stream_bind_ticket_v1_t){0}, sizeof(owner->bind.ticket));
}


#endif
