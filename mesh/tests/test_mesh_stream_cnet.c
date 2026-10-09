#include <tinytest.h>
#include <cnet/cnet.h>
#include <salts/clock.h>

#include "mesh_stream_transport.h"

#include <stdio.h>
#include <string.h>

#define TEST_FRAME_MAX 128u
#define TEST_SEND_HWM 256u
#define TEST_TIMEOUT_MS 3000u
#define TEST_RUN_TIMEOUT_MS 5000u
#define TEST_EPOCH 31u
#define TEST_INITIAL_WINDOW 8u
#define TEST_TOTAL_SIZE 12u

typedef struct {
  cnet_client client;
  cnet_connection connection;
  mesh_stream_transport_v1_t transport;
  uint64_t token;
  int connected;
  int terminal;
  int failed;
  int settle_result;
  size_t sent;
  size_t received_size;
  uint8_t received[MESH_STREAM_FIXED_HEADER_SIZE];
} test_owner_t;

typedef struct {
  test_owner_t sender;
  test_owner_t receiver;
  cnet_listener listener;
  cnet_tls_server tls;
  int accepted;
} test_pair_t;

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
    owner->connected = 1;
  } else if (state == CNET_CONNECTION_CLOSED || state == CNET_CONNECTION_FAILED) {
    size_t frames = 0u;
    owner->terminal = 1;
    if (state == CNET_CONNECTION_FAILED)
      owner->failed = 1;
    if (owner->transport.send_pending)
      owner->settle_result = mesh_stream_transport_complete_send_v1(
          &owner->transport, owner->token,
          error && error->status != SALTS_OK ? error->status : SALTS_ESHUTDOWN, 0u, &frames);
  }
}

static void on_send(void *user, cnet_connection connection, size_t bytes) {
  test_owner_t *owner = user;
  size_t frames = 0u;
  if (!same_connection(connection, owner->connection)) {
    owner->failed = 1;
    return;
  }
  owner->sent++;
  owner->settle_result = mesh_stream_transport_complete_send_v1(
      &owner->transport, owner->token, SALTS_OK, bytes, &frames);
  if (owner->settle_result != MESH_STREAM_TRANSPORT_OK)
    owner->failed = 1;
}

static void on_receive(void *user, cnet_connection connection, const cnet_receive_view *view) {
  test_owner_t *owner = user;
  if (!same_connection(connection, owner->connection) || !view ||
      view->kind != CNET_MESSAGE_BYTES || !view->data ||
      view->size > sizeof(owner->received) - owner->received_size) {
    owner->failed = 1;
    return;
  }
  memcpy(owner->received + owner->received_size, view->data, view->size);
  owner->received_size += view->size;
  if (owner->received_size < sizeof(owner->received) &&
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
      check_equal(cnet_listener_accept_tls(&pair->listener, &pair->receiver.client, &pair->tls,
                                           &callbacks, &pair->receiver.connection), SALTS_OK);
      pair->accepted = 1;
    }
  }
  check_equal(cnet_client_poll(&pair->receiver.client, 1u, &events), SALTS_OK);
  check_false(pair->sender.failed);
  check_false(pair->receiver.failed);
}

static void init_pair(test_pair_t *pair) {
  cnet_client_config config = client_config();
  cnet_listener_config listener_config = {config.backend, "127.0.0.1", 0u, 2u};
  cnet_tls_server_config server_config = {0};
  cnet_tls_client_config tls_config = {0};
  cnet_connect_options options = {0};
  uint64_t deadline = cmeta_monotonic_ms() + TEST_RUN_TIMEOUT_MS;
  uint16_t port = 0u;
  char uri[64];

  memset(pair, 0, sizeof(*pair));
  server_config.size = sizeof(server_config);
  server_config.cert_file = MESH_TEST_TLS_CERT_FILE;
  server_config.key_file = MESH_TEST_TLS_KEY_FILE;
  server_config.client_auth = CNET_TLS_CLIENT_AUTH_NONE;
  tls_config.size = sizeof(tls_config);
  tls_config.ca_file = MESH_TEST_TLS_CA_FILE;
  tls_config.server_name = "localhost";
  check_equal(cnet_tls_server_init(&pair->tls, &server_config), SALTS_OK);
  check_equal(cnet_client_init(&pair->sender.client, &config), SALTS_OK);
  check_equal(cnet_client_init(&pair->receiver.client, &config), SALTS_OK);
  check_equal(cnet_listener_init(&pair->listener, &listener_config), SALTS_OK);
  check_equal(cnet_listener_port(&pair->listener, &port), SALTS_OK);
  check_true(snprintf(uri, sizeof(uri), "tls://127.0.0.1:%u", (unsigned int)port) > 0);
  options.uri = uri;
  options.observer = observer(&pair->sender);
  options.tls = &tls_config;
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
    if (owners[i]->client.impl) {
      check_equal(cnet_client_stop(&owners[i]->client, TEST_RUN_TIMEOUT_MS), SALTS_OK);
      check_equal(cnet_client_destroy(&owners[i]->client), SALTS_OK);
    }
    mesh_stream_transport_destroy_v1(&owners[i]->transport);
  }
  if (pair->listener.impl) {
    check_equal(cnet_listener_close(&pair->listener), SALTS_OK);
    check_equal(cnet_listener_destroy(&pair->listener), SALTS_OK);
  }
  if (pair->tls.impl)
    check_equal(cnet_tls_server_destroy(&pair->tls), SALTS_OK);
}

static int submit_control(void *context, const uint8_t *bytes, size_t len, uint64_t token) {
  test_owner_t *owner = context;
  mem_buffer_t *buffer = mem_get_buffer(mem_global(), len);
  int status;
  if (!buffer)
    return SALTS_ENOMEM;
  memcpy(mem_buffer_data(buffer), bytes, len);
  mem_set_used(buffer, len);
  owner->token = token;
  status = cnet_send_buffer(&owner->client, owner->connection, buffer);
  mem_buffer_release(buffer);
  return status;
}

static int check_hwm(void *context, size_t bytes) {
  (void)context;
  return bytes == TEST_SEND_HWM ? SALTS_OK : SALTS_EINVAL;
}

static int check_timeout(void *context, uint64_t timeout) {
  (void)context;
  return timeout == TEST_TIMEOUT_MS ? SALTS_OK : SALTS_EINVAL;
}

static int accept_open(void *context, const mesh_stream_receive_event_v1_t *event) {
  (void)context;
  return event->frame.type == MESH_STREAM_FRAME_OPEN ? SALTS_OK : SALTS_EINVAL;
}

static void admit_accept(test_owner_t *owner) {
  mesh_stream_transport_config_v1_t config = {0};
  mesh_stream_transport_io_v1_t io = {0};
  mesh_stream_frame_input_t open = {0};
  const uint8_t metadata[] = {0u, 1u, 0u, 1u, MESH_STREAM_CLASS_MEDIA,
                            0u, 2u, 0u, 8u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, TEST_TOTAL_SIZE};
  uint8_t wire[TEST_FRAME_MAX];
  size_t len = 0u;
  size_t frames = 0u;
  config.receiver.stream_id[0] = 1u;
  config.receiver.stream_epoch = TEST_EPOCH;
  config.receiver.max_frame_size = TEST_FRAME_MAX;
  config.receiver.initial_receive_window = TEST_INITIAL_WINDOW;
  config.receiver.max_receive_window = TEST_INITIAL_WINDOW * 2u;
  config.receiver.max_total_size = TEST_TOTAL_SIZE;
  config.receiver.allowed_class_mask = MESH_STREAM_CLASS_MEDIA_MASK;
  config.window_update_threshold = TEST_INITIAL_WINDOW / 2u;
  config.receive_timeout_ms = TEST_TIMEOUT_MS;
  config.send_high_watermark = TEST_SEND_HWM;
  io.context = owner;
  io.set_send_hwm = check_hwm;
  io.set_receive_timeout = check_timeout;
  check_equal(mesh_stream_transport_init_async_v1(&owner->transport, &config, &io,
                  submit_control, accept_open, NULL), MESH_STREAM_TRANSPORT_OK);
  open.type = MESH_STREAM_FRAME_OPEN;
  memcpy(open.stream_id, config.receiver.stream_id, sizeof(open.stream_id));
  open.stream_epoch = config.receiver.stream_epoch;
  open.metadata = metadata;
  open.metadata_len = sizeof(metadata);
  check_equal(mesh_stream_frame_encode(&open, TEST_FRAME_MAX, wire, sizeof(wire), &len),
              MESH_STREAM_CODEC_OK);
  check_equal(mesh_stream_transport_feed_v1(&owner->transport, wire, len, &frames),
              MESH_STREAM_TRANSPORT_OK);
  check_equal(frames, 1u);
  check_true(owner->transport.send_pending);
  check_equal(owner->transport.session.state, MESH_STREAM_SESSION_AWAIT_ACCEPT_SEND);
  check_equal(owner->transport.sent_control_frames, 0u);
  check_equal(owner->sent, 0u);
}

spec("mesh stream CNet TLS send settlement") {
  static test_pair_t pair;
  before_each() { init_pair(&pair); }
  after_each() { destroy_pair(&pair); }

  it("commits ACCEPT only after the retained TLS write terminal and delivers its exact bytes") {
    uint8_t sender_binding[CNET_TLS_CHANNEL_BINDING_BYTES];
    uint8_t receiver_binding[CNET_TLS_CHANNEL_BINDING_BYTES];
    mesh_stream_frame_view_t frame;
    size_t consumed = 0u;
    size_t required = 0u;
    uint64_t deadline = cmeta_monotonic_ms() + TEST_RUN_TIMEOUT_MS;
    check_equal(cnet_tls_export_channel_binding(&pair.sender.client, pair.sender.connection,
                                                 sender_binding), SALTS_OK);
    check_equal(cnet_tls_export_channel_binding(&pair.receiver.client, pair.receiver.connection,
                                                 receiver_binding), SALTS_OK);
    check_equal(sender_binding, receiver_binding, sizeof(sender_binding));
    check_equal(cnet_receive(&pair.receiver.client, pair.receiver.connection, 1u), SALTS_OK);
    admit_accept(&pair.sender);
    while ((pair.sender.sent == 0u || pair.receiver.received_size < MESH_STREAM_FIXED_HEADER_SIZE) &&
           cmeta_monotonic_ms() < deadline)
      drive_pair(&pair);
    check_equal(pair.sender.sent, 1u);
    check_equal(pair.sender.settle_result, MESH_STREAM_TRANSPORT_OK);
    check_equal(pair.sender.transport.session.state, MESH_STREAM_SESSION_ACTIVE);
    check_equal(pair.sender.transport.sent_control_frames, 1u);
    check_false(pair.sender.transport.send_pending);
    check_equal(mesh_stream_frame_decode(pair.receiver.received, pair.receiver.received_size,
                  TEST_FRAME_MAX, &frame, &consumed, &required), MESH_STREAM_CODEC_OK);
    check_equal(frame.type, MESH_STREAM_FRAME_ACCEPT);
    check_equal(frame.offset, (uint64_t)TEST_INITIAL_WINDOW);
    check_equal(consumed, (size_t)MESH_STREAM_FIXED_HEADER_SIZE);
  }

  it("settles close-before-progress as failure without activating ACCEPT") {
    uint64_t deadline = cmeta_monotonic_ms() + TEST_RUN_TIMEOUT_MS;
    admit_accept(&pair.sender);
    check_equal(cnet_close(&pair.sender.client, pair.sender.connection), SALTS_OK);
    while (!pair.sender.terminal && cmeta_monotonic_ms() < deadline)
      drive_pair(&pair);
    check_true(pair.sender.terminal);
    check_equal(pair.sender.sent, 0u);
    check_equal(pair.sender.settle_result, MESH_STREAM_TRANSPORT_IO_ERROR);
    check_equal(pair.sender.transport.state, MESH_STREAM_TRANSPORT_FAILED);
    check_equal(pair.sender.transport.session.state, MESH_STREAM_SESSION_AWAIT_ACCEPT_SEND);
    check_equal(pair.sender.transport.sent_control_frames, 0u);
  }
}
