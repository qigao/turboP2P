#include <tinytest.h>

#include "mesh_mgmt_coronet_adapter.h"

#include <CoroNet.h>

#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <sys/socket.h>
  #include <unistd.h>
#endif

#define TEST_IO_TIMEOUT_MS 3000u
#define TEST_RUN_TIMEOUT_MS 5000u
#define TEST_PENDING_RESULT -1000

typedef struct {
  coro_context_t *context;
  coro_socket_t *server;
  unsigned short port;
  uint8_t frame[128];
  size_t frame_len;
  int server_result;
  int client_result;
  int server_done;
  int client_done;
} mgmt_coronet_test_state_t;

static size_t encode_test_frame(uint8_t *output, size_t capacity) {
  mesh_mgmt_frame_input_t input;
  uint8_t signature[MESH_MGMT_SIGNATURE_SIZE];
  size_t output_len = 0u;

  memset(&input, 0, sizeof(input));
  memset(signature, 0x5au, sizeof(signature));
  input.major = MESH_MGMT_MAJOR_V1;
  input.minor = MESH_MGMT_MINOR_V1;
  input.kind = MESH_MGMT_KIND_ERROR;
  input.signature = signature;
  if (mesh_mgmt_frame_encode(&input, output, capacity, &output_len) != MESH_MGMT_CODEC_OK)
    return 0u;
  return output_len;
}

static int set_tls_test_environment(void) {
#ifdef _WIN32
  if (_putenv_s("TURBONET_TLS_CA_FILE", MESH_TEST_TLS_CERT_FILE) != 0)
    return -1;
  if (_putenv_s("TURBONET_TLS_CA_PATH", "") != 0)
    return -1;
  if (_putenv_s("TURBONET_TLS_CERT_FILE", MESH_TEST_TLS_CERT_FILE) != 0)
    return -1;
  return _putenv_s("TURBONET_TLS_KEY_FILE", MESH_TEST_TLS_KEY_FILE) == 0 ? 0 : -1;
#else
  if (setenv("TURBONET_TLS_CA_FILE", MESH_TEST_TLS_CERT_FILE, 1) != 0)
    return -1;
  if (unsetenv("TURBONET_TLS_CA_PATH") != 0)
    return -1;
  if (setenv("TURBONET_TLS_CERT_FILE", MESH_TEST_TLS_CERT_FILE, 1) != 0)
    return -1;
  return setenv("TURBONET_TLS_KEY_FILE", MESH_TEST_TLS_KEY_FILE, 1) == 0 ? 0 : -1;
#endif
}

static void clear_tls_test_environment(void) {
#ifdef _WIN32
  (void)_putenv_s("TURBONET_TLS_CA_FILE", "");
  (void)_putenv_s("TURBONET_TLS_CA_PATH", "");
  (void)_putenv_s("TURBONET_TLS_CERT_FILE", "");
  (void)_putenv_s("TURBONET_TLS_KEY_FILE", "");
#else
  (void)unsetenv("TURBONET_TLS_CA_FILE");
  (void)unsetenv("TURBONET_TLS_CA_PATH");
  (void)unsetenv("TURBONET_TLS_CERT_FILE");
  (void)unsetenv("TURBONET_TLS_KEY_FILE");
#endif
}

static unsigned short pick_loopback_port(void) {
  unsigned short port = 0u;
  struct sockaddr_in address;
#ifdef _WIN32
  int address_len = (int)sizeof(address);
  SOCKET socket_handle = INVALID_SOCKET;
#else
  socklen_t address_len = (socklen_t)sizeof(address);
  int socket_handle = -1;
#endif

  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = htons(0u);
  socket_handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#ifdef _WIN32
  if (socket_handle == INVALID_SOCKET)
    return 0u;
#else
  if (socket_handle < 0)
    return 0u;
#endif
  if (bind(socket_handle, (struct sockaddr *)&address, sizeof(address)) == 0 &&
      getsockname(socket_handle, (struct sockaddr *)&address, &address_len) == 0) {
    port = ntohs(address.sin_port);
  }
#ifdef _WIN32
  closesocket(socket_handle);
#else
  close(socket_handle);
#endif
  return port;
}

static void server_handler(coro_socket_t *client, void *argument) {
  mgmt_coronet_test_state_t *state = (mgmt_coronet_test_state_t *)argument;
  mesh_mgmt_transport_v1_t transport;
  mesh_mgmt_transport_receipt_v1_t receipt;
  mesh_mgmt_transport_result_t result;

  memset(&transport, 0, sizeof(transport));
  memset(&receipt, 0, sizeof(receipt));
  coro_socket_set_timeout(client, TEST_IO_TIMEOUT_MS);
  result = mesh_mgmt_transport_init_coronet_v1(&transport, client);
  if (result == MESH_MGMT_TRANSPORT_OK)
    result = mesh_mgmt_transport_receive_v1(&transport, &receipt);
  if (result == MESH_MGMT_TRANSPORT_OK &&
      (receipt.frame_len != state->frame_len ||
       memcmp(receipt.frame, state->frame, state->frame_len) != 0)) {
    result = MESH_MGMT_TRANSPORT_INVALID_FRAME;
  }
  if (result == MESH_MGMT_TRANSPORT_OK)
    result = mesh_mgmt_transport_send_v1(&transport, receipt.frame, receipt.frame_len);
  if (result == MESH_MGMT_TRANSPORT_OK)
    result = mesh_mgmt_transport_commit_v1(&transport, &receipt);
  mesh_mgmt_transport_destroy_v1(&transport);
  state->server_result = result;
  state->server_done = 1;
}

static void client_task(coro_t *coroutine, void *argument) {
  mgmt_coronet_test_state_t *state = (mgmt_coronet_test_state_t *)argument;
  mesh_mgmt_transport_v1_t transport;
  mesh_mgmt_transport_receipt_v1_t receipt;
  coro_socket_t *client = NULL;
  mesh_mgmt_transport_result_t result = MESH_MGMT_TRANSPORT_OK;

  (void)coroutine;
  memset(&transport, 0, sizeof(transport));
  memset(&receipt, 0, sizeof(receipt));
  client = coro_socket_create(state->context, CORO_SOCKET_TLS);
  if (!client) {
    result = MESH_MGMT_TRANSPORT_IO_FAILED;
    goto cleanup;
  }
  coro_socket_set_timeout(client, TEST_IO_TIMEOUT_MS);
  if (coro_socket_connect(client, "localhost", state->port) != 0) {
    result = MESH_MGMT_TRANSPORT_IO_FAILED;
    goto cleanup;
  }
  result = mesh_mgmt_transport_init_coronet_v1(&transport, client);
  if (result == MESH_MGMT_TRANSPORT_OK)
    result = mesh_mgmt_transport_send_v1(&transport, state->frame, state->frame_len);
  if (result == MESH_MGMT_TRANSPORT_OK)
    result = mesh_mgmt_transport_receive_v1(&transport, &receipt);
  if (result == MESH_MGMT_TRANSPORT_OK &&
      (receipt.frame_len != state->frame_len ||
       memcmp(receipt.frame, state->frame, state->frame_len) != 0)) {
    result = MESH_MGMT_TRANSPORT_INVALID_FRAME;
  }
  if (result == MESH_MGMT_TRANSPORT_OK)
    result = mesh_mgmt_transport_commit_v1(&transport, &receipt);

cleanup:
  mesh_mgmt_transport_destroy_v1(&transport);
  if (client)
    coro_socket_destroy(client);
  state->client_result = result;
  state->client_done = 1;
}

static int run_until_tasks_done(mgmt_coronet_test_state_t *state) {
  uint64_t deadline = turbo_monotonic_ms() + TEST_RUN_TIMEOUT_MS;

  while ((!state->server_done || !state->client_done) && turbo_monotonic_ms() < deadline)
    coro_context_run(state->context, TURBO_RUN_ONCE);
  return state->server_done && state->client_done ? 0 : -1;
}

static int close_context(mgmt_coronet_test_state_t *state) {
  uint64_t deadline = turbo_monotonic_ms() + TEST_RUN_TIMEOUT_MS;
  int remaining;

  if (state->server) {
    coro_socket_destroy(state->server);
    state->server = NULL;
  }
  while (coro_context_alive(state->context) && turbo_monotonic_ms() < deadline)
    coro_context_run(state->context, TURBO_RUN_NOWAIT);
  remaining = coro_context_alive(state->context);
  coro_context_destroy(state->context);
  state->context = NULL;
  return remaining == 0 ? 0 : -1;
}

static void test_tls13_loopback_carries_one_framed_mmp_exchange(void) {
  mgmt_coronet_test_state_t state;

  memset(&state, 0, sizeof(state));
  state.server_result = TEST_PENDING_RESULT;
  state.client_result = TEST_PENDING_RESULT;
  state.frame_len = encode_test_frame(state.frame, sizeof(state.frame));
  check_size_gt(state.frame_len, 0u);
  check_int_eq(set_tls_test_environment(), 0);
  check_int_eq(turbo_stream_tls_set_protocol_mode(TURBO_TLS_PROTOCOL_TLS13_ONLY), 0);
  state.context = coro_context_create(NULL);
  check_not_null(state.context);
  state.port = pick_loopback_port();
  check_int_gt(state.port, 0);
  state.server = coro_socket_create(state.context, CORO_SOCKET_TLS);
  check_not_null(state.server);
  coro_socket_set_timeout(state.server, TEST_IO_TIMEOUT_MS);
  check_int_eq(coro_socket_listen_on(state.server, "127.0.0.1", state.port, server_handler, &state),
               0);
  check_int_eq(coro_context_spawn(state.context, client_task, &state), 0);

  check_int_eq(run_until_tasks_done(&state), 0);
  check_int_eq(state.server_result, MESH_MGMT_TRANSPORT_OK);
  check_int_eq(state.client_result, MESH_MGMT_TRANSPORT_OK);
  check_int_eq(close_context(&state), 0);

  (void)turbo_stream_tls_set_protocol_mode(TURBO_TLS_PROTOCOL_DEFAULT);
  turbo_stream_tls_reset_client_session_cache();
  turbo_stream_tls_global_cleanup();
  turbo_stream_tls_thread_cleanup();
  clear_tls_test_environment();
}

static void test_raw_tcp_socket_is_rejected_before_transport_state(void) {
  coro_context_t *context = coro_context_create(NULL);
  coro_socket_t *socket;
  mesh_mgmt_transport_v1_t transport;

  check_not_null(context);
  socket = coro_socket_create_tcpv4(context);
  check_not_null(socket);
  memset(&transport, 0, sizeof(transport));
  check_int_eq(mesh_mgmt_transport_init_coronet_v1(&transport, socket),
               MESH_MGMT_TRANSPORT_SECURE_CHANNEL_REQUIRED);
  check_false(transport.initialized);
  coro_socket_destroy(socket);
  coro_context_destroy(context);
}

spec("mesh management CoroNet transport") {
  describe("secure socket boundary") {
    it("exchanges a framed MMP message over a real TLS 1.3 loopback") {
      test_tls13_loopback_carries_one_framed_mmp_exchange();
    }
    it("rejects raw TCP before allocating transport state") {
      test_raw_tcp_socket_is_rejected_before_transport_state();
    }
  }
}
