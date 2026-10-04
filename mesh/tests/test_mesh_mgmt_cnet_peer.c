#include <tinytest.h>
#include <salts/clock.h>
#include "mesh_mgmt_cnet_peer.h"
#include "mesh_mgmt_crypto.h"
#include <stdio.h>
#include <string.h>

#define TEST_TIMEOUT_MS 3000u
#define TEST_RUN_TIMEOUT_MS 5000u
static const uint8_t ROOT_PRIVATE_KEY[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};

static const uint8_t MANAGEMENT_PRIVATE_KEY[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
};

#define TEST_NOW_MS 1500u
#define TEST_CERT_SERIAL 42u
#define TEST_PRINCIPAL_EPOCH 7u
#define TEST_INCARNATION 3u
#define TEST_FIRST_SEQUENCE 11u
#define TEST_FRAME_TTL_MS 200u

typedef struct {
  uint64_t now_ms;
  int random_result;
  size_t random_calls;
} signer_callbacks_t;

typedef struct {
  signer_callbacks_t callbacks;
  mesh_mgmt_peer_signer_config_v1_t config;
} signer_fixture_t;

static void fill_bytes(uint8_t *bytes, size_t length, uint8_t first) {
  size_t index;
  for (index = 0u; index < length; index++)
    bytes[index] = (uint8_t)(first + index);
}

static uint64_t test_now_ms(void *context) { return ((signer_callbacks_t *)context)->now_ms; }

static int test_random_bytes(void *context, uint8_t *output, size_t output_len) {
  signer_callbacks_t *callbacks = (signer_callbacks_t *)context;
  uint8_t first = (uint8_t)(0x40u + callbacks->random_calls * 0x10u);

  callbacks->random_calls++;
  if (callbacks->random_result != 0)
    return callbacks->random_result;
  fill_bytes(output, output_len, first);
  return 0;
}

static void prepare_fixture(signer_fixture_t *fixture, unsigned side) {
  mesh_mgmt_certificate_claims_v1_t claims;
  uint8_t management_public_key[32];
  size_t certificate_len = 0u;

  memset(fixture, 0, sizeof(*fixture));
  memset(&claims, 0, sizeof(claims));
  fixture->callbacks.now_ms = TEST_NOW_MS;
  memcpy(fixture->config.private_key, MANAGEMENT_PRIVATE_KEY, sizeof(fixture->config.private_key));
  fixture->config.private_key[0] ^= (uint8_t)side;
  check_equal(
      mesh_mgmt_ed25519_public_from_private(ROOT_PRIVATE_KEY, fixture->config.trusted_issuer_key),
      MESH_MGMT_CRYPTO_OK);
  check_equal(mesh_mgmt_ed25519_public_from_private(fixture->config.private_key, management_public_key),
               MESH_MGMT_CRYPTO_OK);
  fill_bytes(fixture->config.expected_mesh_id_hash, sizeof(fixture->config.expected_mesh_id_hash),
             0x20u);
  fill_bytes(fixture->config.local_transport_peer_id,
             sizeof(fixture->config.local_transport_peer_id), (uint8_t)(0x50u + side));

  claims.principal_type = MESH_MGMT_PRINCIPAL_NODE;
  memcpy(claims.management_key, management_public_key, sizeof(claims.management_key));
  memcpy(claims.transport_peer_id, fixture->config.local_transport_peer_id,
         sizeof(claims.transport_peer_id));
  fill_bytes(claims.managed_node_id, sizeof(claims.managed_node_id), (uint8_t)(0x80u + side));
  memcpy(claims.mesh_id_hash, fixture->config.expected_mesh_id_hash, sizeof(claims.mesh_id_hash));
  claims.roles = MESH_MGMT_ROLE_OBSERVER | MESH_MGMT_ROLE_OPERATOR;
  claims.not_before_ms = 1000u;
  claims.expires_at_ms = 3000u;
  claims.serial = TEST_CERT_SERIAL + side;
  claims.principal_epoch = TEST_PRINCIPAL_EPOCH;
  check_equal(
      mesh_mgmt_certificate_issue_v1(&claims, ROOT_PRIVATE_KEY, fixture->config.hello.certificate,
                                     sizeof(fixture->config.hello.certificate), &certificate_len),
      MESH_MGMT_IDENTITY_OK);
  check_equal(certificate_len, MESH_MGMT_CERTIFICATE_V1_SIZE);

  fixture->config.hello.major = MESH_MGMT_MAJOR_V1;
  fixture->config.hello.min_minor = MESH_MGMT_MINOR_V1;
  fixture->config.hello.max_minor = MESH_MGMT_MINOR_V1;
  fixture->config.hello.features = MESH_MGMT_FEATURE_MEMBERSHIP | MESH_MGMT_FEATURE_ANTI_ENTROPY;
  fixture->config.hello.platform = MESH_MGMT_PLATFORM_LINUX;
  memcpy(fixture->config.hello.build_version, "signer-test", 11u);
  fixture->config.hello.build_version_len = 11u;
  check_equal(mesh_mgmt_blake2b_256(fixture->config.trusted_issuer_key,
                                     sizeof(fixture->config.trusted_issuer_key),
                                     fixture->config.hello.issuer_chain_hash),
               MESH_MGMT_CRYPTO_OK);
  fixture->config.hello.principal_type = MESH_MGMT_PRINCIPAL_NODE;
  memcpy(fixture->config.hello.management_key, management_public_key,
         sizeof(fixture->config.hello.management_key));
  memcpy(fixture->config.hello.managed_node_id, claims.managed_node_id,
         sizeof(fixture->config.hello.managed_node_id));
  fill_bytes(fixture->config.hello.connection_id, sizeof(fixture->config.hello.connection_id),
             (uint8_t)(0xb0u + side));
  fill_bytes(fixture->config.hello.channel_binding,
             sizeof(fixture->config.hello.channel_binding), 0xc0u);
  fixture->config.hello.max_frame = MESH_MGMT_FRAME_MAX;
  fixture->config.hello.max_digest_entries = 128u;
  fixture->config.hello.max_delta_batch = 64u;
  fill_bytes(fixture->config.session_id, sizeof(fixture->config.session_id), (uint8_t)(0x10u + side));
  fixture->config.incarnation = TEST_INCARNATION;
  fixture->config.first_sequence = TEST_FIRST_SEQUENCE;
  fixture->config.frame_ttl_ms = TEST_FRAME_TTL_MS;
  fixture->config.now_ms = test_now_ms;
  fixture->config.random_bytes = test_random_bytes;
  fixture->config.callback_context = &fixture->callbacks;
  mesh_mgmt_crypto_wipe(management_public_key, sizeof(management_public_key));
}


typedef struct {
  cnet_client client;
  cnet_connection connection;
  mesh_mgmt_cnet_peer_v1_t mgmt;
  signer_fixture_t identity;
  int connected;
  int terminal;
  int failed;
  int tamper;
  int reject_event;
  int hold_send;
  size_t held_bytes;
  size_t events;
  size_t application_events;
  size_t send_completions;
  int last_result;
} test_owner_t;

typedef struct {
  test_owner_t sender;
  test_owner_t receiver;
  cnet_listener listener;
  cnet_tls_server tls;
  int accepted;
  int plaintext;
} test_pair_t;

static int accept_event(void *context, const mesh_mgmt_dispatch_event_v1_t *event) {
  test_owner_t *owner = context;
  owner->events++;
  if (event->type == MESH_MGMT_DISPATCH_EVENT_MEMBERSHIP) {
    owner->application_events++;
    check_equal(event->envelope.frame.payload_len, 5u);
    check_equal(event->envelope.frame.payload[4], 0x42u);
  }
  return owner->reject_event ? -1 : 0;
}

static void on_state(void *user, cnet_connection connection, cnet_connection_state state,
                     const cnet_error *error) {
  test_owner_t *owner = user;
  (void)error;
  if (state == CNET_CONNECTION_CONNECTED)
    owner->connected = 1;
  else if (state == CNET_CONNECTION_CLOSED || state == CNET_CONNECTION_FAILED) {
    owner->terminal = 1;
    if (owner->mgmt.initialized)
      owner->last_result = mesh_mgmt_cnet_peer_on_state_v1(&owner->mgmt, connection, state);
  }
}

static void on_send(void *user, cnet_connection connection, size_t bytes) {
  test_owner_t *owner = user;
  owner->send_completions++;
  if (owner->hold_send) {
    owner->held_bytes = bytes;
    return;
  }
  if (!owner->mgmt.close_requested)
    owner->last_result = mesh_mgmt_cnet_peer_on_send_v1(&owner->mgmt, connection, bytes, TEST_NOW_MS);
}

static void on_receive(void *user, cnet_connection connection, const cnet_receive_view *view) {
  test_owner_t *owner = user;
  if (owner->tamper) {
    uint8_t copy[MESH_MGMT_FRAME_MAX];
    cnet_receive_view changed = *view;
    check_less_equal(view->size, sizeof(copy));
    memcpy(copy, view->data, view->size);
    copy[view->size - 1u] ^= 1u;
    changed.data = copy;
    owner->last_result = mesh_mgmt_cnet_peer_on_receive_v1(&owner->mgmt, connection, &changed, TEST_NOW_MS);
  } else {
    owner->last_result = mesh_mgmt_cnet_peer_on_receive_v1(&owner->mgmt, connection, view, TEST_NOW_MS);
  }
}

static cnet_observer observer(test_owner_t *owner) {
  cnet_observer value = {0};
  value.on_state = on_state;
  value.on_send = on_send;
  value.on_receive = on_receive;
  value.user = owner;
  return value;
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
  config.max_send_bytes = MESH_MGMT_FRAME_MAX * 2u;
  config.receive_buffer_bytes = MESH_MGMT_FRAME_MAX;
  config.connect_timeout_ms = TEST_TIMEOUT_MS;
  config.read_timeout_ms = TEST_TIMEOUT_MS;
  config.write_timeout_ms = TEST_TIMEOUT_MS;
  config.tls_io_buffer_bytes = CNET_TLS_MIN_IO_BUFFER_BYTES;
  config.tls_handshake_timeout_ms = TEST_TIMEOUT_MS;
  return config;
}


static void drive_pair(test_pair_t *pair) {
  size_t events = 0u;
  int ready = 0;
  check_equal(cnet_client_poll(&pair->sender.client, 1u, &events), SALTS_OK);
  if (!pair->accepted) {
    check_equal(cnet_listener_wait(&pair->listener, 0u, &ready), SALTS_OK);
    if (ready) {
      cnet_observer callbacks = observer(&pair->receiver);
      int result = pair->plaintext
          ? cnet_listener_accept(&pair->listener, &pair->receiver.client, &callbacks, &pair->receiver.connection)
          : cnet_listener_accept_tls(&pair->listener, &pair->receiver.client, &pair->tls, &callbacks, &pair->receiver.connection);
      check_equal(result, SALTS_OK);
      pair->accepted = 1;
    }
  }
  check_equal(cnet_client_poll(&pair->receiver.client, 1u, &events), SALTS_OK);
}

static void init_pair(test_pair_t *pair, size_t receive_bytes, int plaintext) {
  cnet_client_config config = client_config();
  cnet_listener_config listener_config = {config.backend, "127.0.0.1", 0u, 2u};
  cnet_tls_server_config server_config = {0};
  cnet_tls_client_config tls_config = {0};
  cnet_connect_options options = {0};
  uint64_t deadline = salts_monotonic_ms() + TEST_RUN_TIMEOUT_MS;
  uint16_t port = 0u;
  char uri[64];
  memset(pair, 0, sizeof(*pair));
  pair->plaintext = plaintext;
  config.receive_buffer_bytes = receive_bytes;
  server_config.size = sizeof(server_config);
  server_config.cert_file = MESH_TEST_TLS_CERT_FILE;
  server_config.key_file = MESH_TEST_TLS_KEY_FILE;
  server_config.client_auth = CNET_TLS_CLIENT_AUTH_NONE;
  tls_config.size = sizeof(tls_config);
  tls_config.ca_file = MESH_TEST_TLS_CA_FILE;
  tls_config.server_name = "localhost";
  if (!plaintext)
    check_equal(cnet_tls_server_init(&pair->tls, &server_config), SALTS_OK);
  check_equal(cnet_client_init(&pair->sender.client, &config), SALTS_OK);
  check_equal(cnet_client_init(&pair->receiver.client, &config), SALTS_OK);
  check_equal(cnet_listener_init(&pair->listener, &listener_config), SALTS_OK);
  check_equal(cnet_listener_port(&pair->listener, &port), SALTS_OK);
  check_true(snprintf(uri, sizeof(uri), "%s://127.0.0.1:%u", plaintext ? "tcp" : "tls", (unsigned)port) > 0);
  options.uri = uri;
  options.observer = observer(&pair->sender);
  if (!plaintext)
    options.tls = &tls_config;
  check_equal(cnet_connect(&pair->sender.client, &options, &pair->sender.connection), SALTS_OK);
  while ((!pair->sender.connected || !pair->receiver.connected) && salts_monotonic_ms() < deadline)
    drive_pair(pair);
  check_true(pair->sender.connected);
  check_true(pair->receiver.connected);
}

static mesh_mgmt_cnet_peer_config_v1_t peer_config(test_owner_t *owner, test_owner_t *remote, unsigned side) {
  mesh_mgmt_cnet_peer_config_v1_t config = {0};
  prepare_fixture(&owner->identity, side);
  config.signer = owner->identity.config;
  memcpy(config.remote_transport_peer_id, remote->identity.config.local_transport_peer_id, 32u);
  memcpy(config.dispatch.session.expected_mesh_id_hash, config.signer.expected_mesh_id_hash, 32u);
  memcpy(config.dispatch.session.trusted_issuer_key, config.signer.trusted_issuer_key, 32u);
  memcpy(config.dispatch.session.connection_id, config.signer.hello.connection_id, 16u);
  config.dispatch.session.min_minor = MESH_MGMT_MINOR_V1;
  config.dispatch.session.max_minor = MESH_MGMT_MINOR_V1;
  config.dispatch.session.features = config.signer.hello.features;
  config.dispatch.session.max_frame = config.signer.hello.max_frame;
  config.dispatch.session.max_digest_entries = config.signer.hello.max_digest_entries;
  config.dispatch.session.max_delta_batch = config.signer.hello.max_delta_batch;
  config.dispatch.replay.capacity = 16u;
  config.dispatch.replay.ttl_ms = 100u;
  config.on_event = accept_event;
  config.event_context = owner;
  return config;
}

static void init_protocol(test_pair_t *pair) {
  mesh_mgmt_cnet_peer_config_v1_t left, right;
  prepare_fixture(&pair->receiver.identity, 1u);
  left = peer_config(&pair->sender, &pair->receiver, 0u);
  right = peer_config(&pair->receiver, &pair->sender, 1u);
  check_equal(mesh_mgmt_cnet_peer_init_v1(&pair->sender.mgmt, &pair->sender.client, pair->sender.connection, &left), MESH_MGMT_PEER_OK);
  check_equal(mesh_mgmt_cnet_peer_init_v1(&pair->receiver.mgmt, &pair->receiver.client, pair->receiver.connection, &right), MESH_MGMT_PEER_OK);
  check_equal(pair->sender.mgmt.channel_binding, pair->receiver.mgmt.channel_binding, 32u);
  check_equal(pair->sender.mgmt.signer.hello.channel_binding, pair->sender.mgmt.channel_binding, 32u);
  check_equal(pair->sender.mgmt.peer.connection.dispatcher.session.config.channel_binding, pair->sender.mgmt.channel_binding, 32u);
}

static int established(test_pair_t *pair) {
  return pair->sender.mgmt.peer.connection.dispatcher.session.state == MESH_MGMT_SESSION_ESTABLISHED &&
         pair->receiver.mgmt.peer.connection.dispatcher.session.state == MESH_MGMT_SESSION_ESTABLISHED;
}

static void start_protocol(test_pair_t *pair) {
  check_equal(mesh_mgmt_cnet_peer_start_v1(&pair->sender.mgmt, TEST_NOW_MS), MESH_MGMT_PEER_PENDING);
  check_equal(mesh_mgmt_cnet_peer_start_v1(&pair->receiver.mgmt, TEST_NOW_MS), MESH_MGMT_PEER_PENDING);
  check_false(pair->sender.mgmt.peer.connection.dispatcher.session.local_hello_sent);
  check_false(pair->receiver.mgmt.peer.connection.dispatcher.session.local_hello_sent);
}

static void await_established(test_pair_t *pair) {
  uint64_t deadline = salts_monotonic_ms() + TEST_RUN_TIMEOUT_MS;
  while (!established(pair) && salts_monotonic_ms() < deadline) {
    drive_pair(pair);
    if (pair->sender.mgmt.peer.state == MESH_MGMT_PEER_TERMINAL || pair->receiver.mgmt.peer.state == MESH_MGMT_PEER_TERMINAL)
      break;
  }
  check_true(established(pair));
  check_true(pair->sender.mgmt.peer.connection.dispatcher.replay.bound);
  check_true(pair->receiver.mgmt.peer.connection.dispatcher.replay.bound);
}

static void destroy_pair(test_pair_t *pair) {
  test_owner_t *owners[] = {&pair->sender, &pair->receiver};
  for (size_t i = 0u; i < 2u; ++i) {
    if (owners[i]->client.impl) {
      check_equal(cnet_client_stop(&owners[i]->client, TEST_RUN_TIMEOUT_MS), SALTS_OK);
      if (owners[i]->mgmt.initialized) {
        check_true(owners[i]->mgmt.terminal_observed);
        check_equal(mesh_mgmt_cnet_peer_destroy_v1(&owners[i]->mgmt), MESH_MGMT_PEER_OK);
      }
      check_equal(cnet_client_destroy(&owners[i]->client), SALTS_OK);
    }
  }
  check_equal(cnet_listener_close(&pair->listener), SALTS_OK);
  check_equal(cnet_listener_destroy(&pair->listener), SALTS_OK);
  if (pair->tls.impl)
    check_equal(cnet_tls_server_destroy(&pair->tls), SALTS_OK);
}

static void test_signed_loopback(size_t receive_bytes) {
  test_pair_t pair;
  static const uint8_t payload[] = {0u, 1u, 0u, 1u, 0x42u};
  uint64_t deadline;
  init_pair(&pair, receive_bytes, 0);
  init_protocol(&pair);
  start_protocol(&pair);
  /* The builder's loan ends on admission; subsequent reuse must be harmless. */
  memset(pair.sender.mgmt.signer.frame, 0x99, sizeof(pair.sender.mgmt.signer.frame));
  await_established(&pair);
  check_equal(mesh_mgmt_cnet_peer_send_v1(&pair.sender.mgmt, MESH_MGMT_KIND_PROBE, payload, sizeof(payload)), MESH_MGMT_CONNECTION_PENDING);
  check_equal(mesh_mgmt_cnet_peer_send_v1(&pair.sender.mgmt, MESH_MGMT_KIND_PROBE, payload, sizeof(payload)), MESH_MGMT_CONNECTION_BUSY);
  check_equal(mesh_mgmt_cnet_peer_send_v1(&pair.receiver.mgmt, MESH_MGMT_KIND_PROBE, payload, sizeof(payload)), MESH_MGMT_CONNECTION_PENDING);
  deadline = salts_monotonic_ms() + TEST_RUN_TIMEOUT_MS;
  while ((!pair.sender.application_events || !pair.receiver.application_events) && salts_monotonic_ms() < deadline)
    drive_pair(&pair);
  check_equal(pair.sender.application_events, 1u);
  check_equal(pair.receiver.application_events, 1u);
  destroy_pair(&pair);
}

static void test_delayed_completion(void) {
  test_pair_t pair;
  uint64_t deadline;
  cnet_connection stale;
  init_pair(&pair, MESH_MGMT_FRAME_MAX, 0);
  init_protocol(&pair);
  pair.sender.hold_send = 1;
  start_protocol(&pair);
  deadline = salts_monotonic_ms() + TEST_RUN_TIMEOUT_MS;
  while (!pair.sender.held_bytes && salts_monotonic_ms() < deadline)
    drive_pair(&pair);
  check_greater(pair.sender.held_bytes, 0u);
  check_false(pair.sender.mgmt.peer.connection.dispatcher.session.local_hello_sent);
  check_equal(pair.sender.events, 0u);
  stale = pair.sender.connection;
  stale.generation++;
  check_equal(mesh_mgmt_cnet_peer_on_send_v1(&pair.sender.mgmt, stale, pair.sender.held_bytes, TEST_NOW_MS), MESH_MGMT_PEER_INVALID_STATE);
  check_false(pair.sender.mgmt.peer.connection.dispatcher.session.local_hello_sent);
  pair.sender.hold_send = 0;
  check_equal(mesh_mgmt_cnet_peer_on_send_v1(&pair.sender.mgmt, pair.sender.connection, pair.sender.held_bytes, TEST_NOW_MS), MESH_MGMT_PEER_PENDING);
  check_true(pair.sender.mgmt.peer.connection.dispatcher.session.local_hello_sent);
  await_established(&pair);
  destroy_pair(&pair);
}

static void test_close_pending(void) {
  test_pair_t pair;
  init_pair(&pair, MESH_MGMT_FRAME_MAX, 0);
  init_protocol(&pair);
  start_protocol(&pair);
  check_equal(mesh_mgmt_cnet_peer_destroy_v1(&pair.sender.mgmt), MESH_MGMT_PEER_INVALID_STATE);
  check_equal(mesh_mgmt_cnet_peer_close_v1(&pair.sender.mgmt), MESH_MGMT_PEER_OK);
  check_false(pair.sender.mgmt.peer.connection.dispatcher.session.local_hello_sent);
  check_equal(pair.sender.mgmt.peer.state, MESH_MGMT_PEER_TERMINAL);
  check_equal(pair.sender.mgmt.peer.connection.transport.pending_send_token, 0u);
  check_equal(mesh_mgmt_cnet_peer_destroy_v1(&pair.sender.mgmt), MESH_MGMT_PEER_INVALID_STATE);
  destroy_pair(&pair);
}

static void test_already_closing(void) {
  test_pair_t pair;
  init_pair(&pair, MESH_MGMT_FRAME_MAX, 0);
  init_protocol(&pair);
  start_protocol(&pair);
  check_equal(cnet_close(&pair.sender.client, pair.sender.connection), SALTS_OK);
  check_equal(mesh_mgmt_cnet_peer_close_v1(&pair.sender.mgmt), MESH_MGMT_PEER_OK);
  check_true(pair.sender.mgmt.close_requested);
  check_false(pair.sender.mgmt.peer.connection.dispatcher.session.local_hello_sent);
  destroy_pair(&pair);
}

static void test_short_completion(void) {
  test_pair_t pair;
  init_pair(&pair, MESH_MGMT_FRAME_MAX, 0);
  init_protocol(&pair);
  start_protocol(&pair);
  check_equal(mesh_mgmt_cnet_peer_on_send_v1(&pair.sender.mgmt, pair.sender.connection, pair.sender.mgmt.pending_bytes - 1u, TEST_NOW_MS), MESH_MGMT_PEER_CONNECTION_FAILED);
  check_false(pair.sender.mgmt.peer.connection.dispatcher.session.local_hello_sent);
  check_equal(pair.sender.mgmt.peer.state, MESH_MGMT_PEER_TERMINAL);
  destroy_pair(&pair);
}

static void test_rejected_frame(int tamper) {
  test_pair_t pair;
  uint64_t deadline;
  init_pair(&pair, MESH_MGMT_FRAME_MAX, 0);
  init_protocol(&pair);
  pair.receiver.tamper = tamper;
  pair.receiver.reject_event = !tamper;
  start_protocol(&pair);
  deadline = salts_monotonic_ms() + TEST_RUN_TIMEOUT_MS;
  while (pair.receiver.mgmt.peer.state != MESH_MGMT_PEER_TERMINAL && salts_monotonic_ms() < deadline)
    drive_pair(&pair);
  check_equal(pair.receiver.mgmt.peer.state, MESH_MGMT_PEER_TERMINAL);
  check_false(pair.receiver.mgmt.peer.connection.dispatcher.session.local_ack_sent);
  check_equal(pair.receiver.events, tamper ? 0u : 1u);
  check_equal(pair.receiver.mgmt.peer.connection.last_error, tamper ? MESH_MGMT_CONNECTION_DISPATCH_FAILED : MESH_MGMT_CONNECTION_EVENT_REJECTED);
  destroy_pair(&pair);
}

static void test_plaintext_rejected(void) {
  test_pair_t pair;
  mesh_mgmt_cnet_peer_config_v1_t config;
  init_pair(&pair, MESH_MGMT_FRAME_MAX, 1);
  prepare_fixture(&pair.receiver.identity, 1u);
  config = peer_config(&pair.sender, &pair.receiver, 0u);
  check_equal(mesh_mgmt_cnet_peer_init_v1(&pair.sender.mgmt, &pair.sender.client, pair.sender.connection, &config), MESH_MGMT_PEER_CONNECTION_FAILED);
  check_false(pair.sender.mgmt.initialized);
  check_equal(pair.sender.send_completions, 0u);
  destroy_pair(&pair);
}

static void test_inactive_handle_rejected(void) {
  test_pair_t pair;
  mesh_mgmt_cnet_peer_config_v1_t config;
  cnet_connection stale;
  uint64_t deadline;
  init_pair(&pair, MESH_MGMT_FRAME_MAX, 0);
  prepare_fixture(&pair.receiver.identity, 1u);
  config = peer_config(&pair.sender, &pair.receiver, 0u);
  stale = pair.sender.connection;
  stale.generation++;
  check_equal(mesh_mgmt_cnet_peer_init_v1(&pair.sender.mgmt, &pair.sender.client, stale, &config), MESH_MGMT_PEER_CONNECTION_FAILED);
  check_false(pair.sender.mgmt.initialized);
  check_equal(cnet_close(&pair.sender.client, pair.sender.connection), SALTS_OK);
  deadline = salts_monotonic_ms() + TEST_RUN_TIMEOUT_MS;
  while (!pair.sender.terminal && salts_monotonic_ms() < deadline)
    drive_pair(&pair);
  check_true(pair.sender.terminal);
  check_equal(mesh_mgmt_cnet_peer_init_v1(&pair.sender.mgmt, &pair.sender.client, pair.sender.connection, &config), MESH_MGMT_PEER_CONNECTION_FAILED);
  check_equal(pair.sender.mgmt.signer.state, MESH_MGMT_PEER_SIGNER_UNINITIALIZED);
  check_equal(pair.sender.send_completions, 0u);
  destroy_pair(&pair);
}

static void test_binding_mismatch(void) {
  test_pair_t pair;
  init_pair(&pair, MESH_MGMT_FRAME_MAX, 0);
  init_protocol(&pair);
  pair.sender.mgmt.channel_binding[0] ^= 1u;
  check_equal(mesh_mgmt_cnet_peer_start_v1(&pair.sender.mgmt, TEST_NOW_MS), MESH_MGMT_PEER_CONNECTION_FAILED);
  check_equal(pair.sender.mgmt.peer.state, MESH_MGMT_PEER_TERMINAL);
  check_false(pair.sender.mgmt.peer.connection.dispatcher.session.local_hello_sent);
  check_false(pair.sender.mgmt.signer.hello_built);
  check_equal(pair.sender.send_completions, 0u);
  destroy_pair(&pair);
}

spec("signed management peer over CNet") {
  it("authenticates HELLO/ACK and bidirectional targeted events with owned writes") { test_signed_loopback(MESH_MGMT_FRAME_MAX); }
  it("preserves handshake and events across small real TLS read fragments") { test_signed_loopback(7u); }
  it("waits for the matching handle's send completion before accepting input") { test_delayed_completion(); }
  it("settles pending HELLO on close and retains storage until terminal observation") { test_close_pending(); }
  it("accepts an already admitted caller close while settling the pending write") { test_already_closing(); }
  it("fails a short logical write without committing HELLO") { test_short_completion(); }
  it("rejects an altered signed HELLO before its observer or ACK") { test_rejected_frame(1); }
  it("terminates when the application rejects an authenticated HELLO") { test_rejected_frame(0); }
  it("rejects stale and closed handles before initialization or signing") { test_inactive_handle_rejected(); }
  it("rejects exporter mismatch before HELLO admission") { test_binding_mismatch(); }
  it("rejects plaintext before any management write") { test_plaintext_rejected(); }
}
