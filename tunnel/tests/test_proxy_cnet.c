#include <tinytest.h>
#include "../src/proxy/tunnel_proxy.h"
#include "../src/session/tunnel_session.h"
#include "../src/nat/tunnel_nat.h"
#include "../src/stack/tunnel_ip_stack.h"
#include <salts/clock.h>
#include <string.h>

#define TEST_TIMEOUT_MS 5000u
#define TEST_BUFFER_SIZE 8192u

typedef struct {
  tunnel_t *tunnel;
  tunnel_proxy_conn_t *conn;
  cnet_client server;
  cnet_listener listener;
  cnet_tls_server tls;
  cnet_connection peer;
  int accepted, peer_connected, peer_terminal;
  int connect_events, connect_status, close_events, data_events;
  int destroy_on_connect, destroy_on_data, destroy_tunnel_on_connect, stop_on_connect;
  uint8_t received[TEST_BUFFER_SIZE], requests[TEST_BUFFER_SIZE];
  size_t received_size, requests_size, sends;
  int use_tls;
  uint16_t port;
} fixture_t;
static fixture_t f;

static void client_connect(tunnel_proxy_conn_t *conn, int status, void *user) {
  fixture_t *p = user;
  ++p->connect_events;
  p->connect_status = status;
  if (p->stop_on_connect) { tunnel_stop(p->tunnel); p->conn = NULL; }
  else if (p->destroy_tunnel_on_connect) {
    tunnel_destroy(p->tunnel);
    p->tunnel = NULL;
    p->conn = NULL;
  } else if (p->destroy_on_connect) {
    tunnel_proxy_conn_destroy(conn);
    p->conn = NULL;
  }
}
static void client_data(tunnel_proxy_conn_t *conn, const uint8_t *data, size_t size, void *user) {
  fixture_t *p = user;
  check_true(size <= sizeof(p->received) - p->received_size);
  memcpy(p->received + p->received_size, data, size);
  p->received_size += size;
  ++p->data_events;
  if (p->destroy_on_data) { tunnel_proxy_conn_destroy(conn); p->conn = NULL; }
}
static void client_close(tunnel_proxy_conn_t *conn, void *user) {
  fixture_t *p = user;
  ++p->close_events;
  tunnel_proxy_conn_destroy(conn);
  p->conn = NULL;
}
static void server_state(void *user, cnet_connection handle, cnet_connection_state state,
                         const cnet_error *error) {
  fixture_t *p = user;
  (void)error;
  if (state == CNET_CONNECTION_CONNECTED) {
    p->peer_connected = 1;
    check_equal(cnet_receive(&p->server, handle, 1u), SALTS_OK);
  }
  if (state == CNET_CONNECTION_FAILED || state == CNET_CONNECTION_CLOSED) p->peer_terminal = 1;
}
static void server_receive(void *user, cnet_connection handle, const cnet_receive_view *view) {
  fixture_t *p = user;
  check_true(view->size <= sizeof(p->requests) - p->requests_size);
  memcpy(p->requests + p->requests_size, view->data, view->size);
  p->requests_size += view->size;
  check_equal(cnet_receive(&p->server, handle, 1u), SALTS_OK);
}
static void server_send_done(void *user, cnet_connection handle, size_t size) {
  fixture_t *p = user;
  (void)handle;
  p->sends += size;
}
static void drive(void) {
  size_t events;
  int ready = 0;
  if (f.tunnel) {
    int result = tunnel_poll(f.tunnel, 0);
    check_true(result >= 0 || result == TUNNEL_ERR_CLOSED);
  }
  if (!f.accepted) {
    check_equal(cnet_listener_wait(&f.listener, 0u, &ready), SALTS_OK);
    if (ready) {
      cnet_observer observer = {server_state, server_receive, &f, server_send_done};
      int result = f.use_tls
        ? cnet_listener_accept_tls(&f.listener, &f.server, &f.tls, &observer, &f.peer)
        : cnet_listener_accept(&f.listener, &f.server, &observer, &f.peer);
      check_equal(result, SALTS_OK);
      f.accepted = 1;
    }
  }
  check_equal(cnet_client_poll(&f.server, 1u, &events), SALTS_OK);
}
static void wait_connect(void) {
  uint64_t deadline = cmeta_monotonic_ms() + TEST_TIMEOUT_MS;
  while (!f.connect_events && cmeta_monotonic_ms() < deadline) drive();
  check_equal(f.connect_events, 1);
}
static void wait_requests(size_t size) {
  uint64_t deadline = cmeta_monotonic_ms() + TEST_TIMEOUT_MS;
  while (f.requests_size < size && cmeta_monotonic_ms() < deadline) drive();
  check_equal(f.requests_size, size);
}
static void wait_received(size_t size) {
  uint64_t deadline = cmeta_monotonic_ms() + TEST_TIMEOUT_MS;
  while (f.received_size < size && cmeta_monotonic_ms() < deadline) drive();
  check_equal(f.received_size, size);
}
static void wait_retired(void) {
  uint64_t deadline = cmeta_monotonic_ms() + TEST_TIMEOUT_MS;
  while (f.tunnel->proxy->connection_count && cmeta_monotonic_ms() < deadline) drive();
  check_equal(f.tunnel->proxy->connection_count, 0u);
}
static void send_server(const void *data, size_t size) {
  mem_buffer_t *buffer = mem_get_buffer(mem_global(), size);
  check_not_null(buffer);
  memcpy(mem_buffer_data(buffer), data, size);
  mem_set_used(buffer, size);
  check_equal(cnet_send_buffer(&f.server, f.peer, buffer), SALTS_OK);
  mem_buffer_release(buffer);
}
static void init_fixture_owner(tunnel_proxy_type_t type, int use_tls, const char *name, int connect) {
  cnet_client_config policy = {0};
  cnet_tls_server_config tls = {0};
  tunnel_config_t config;
  memset(&f, 0, sizeof(f));
  f.use_tls = use_tls;
#ifdef _WIN32
  policy.backend = NATIVE_IO_BACKEND_IOCP;
#elif defined(__linux__)
  policy.backend = NATIVE_IO_BACKEND_EPOLL;
#else
  policy.backend = NATIVE_IO_BACKEND_KQUEUE;
#endif
  policy.connection_capacity = 2u;
  policy.command_capacity = 32u;
  policy.request_capacity = 16u;
  policy.completion_batch_capacity = 16u;
  policy.event_capacity = 32u;
  policy.max_send_bytes = TUNNEL_SEND_BUF_SIZE;
  policy.receive_buffer_bytes = TUNNEL_RECV_BUF_SIZE;
  policy.connect_timeout_ms = TEST_TIMEOUT_MS;
  policy.write_timeout_ms = TEST_TIMEOUT_MS;
  policy.tls_io_buffer_bytes = CNET_TLS_MIN_IO_BUFFER_BYTES;
  policy.tls_handshake_timeout_ms = TEST_TIMEOUT_MS;
  check_equal(cnet_client_init(&f.server, &policy), SALTS_OK);
  cnet_listener_config listener = {policy.backend, "127.0.0.1", 0u, 2u};
  check_equal(cnet_listener_init(&f.listener, &listener), SALTS_OK);
  check_equal(cnet_listener_port(&f.listener, &f.port), SALTS_OK);
  if (use_tls) {
    tls.size = sizeof(tls);
    tls.cert_file = TUNNEL_TEST_TLS_CERT_FILE;
    tls.key_file = TUNNEL_TEST_TLS_KEY_FILE;
    check_equal(cnet_tls_server_init(&f.tls, &tls), SALTS_OK);
  }
  tunnel_config_init(&config);
  config.proxy.type = type;
  config.proxy.host = "127.0.0.1";
  config.proxy.port = f.port;
  config.proxy.username = "user";
  config.proxy.password = "secret";
  config.proxy.use_tls = use_tls;
  config.proxy.tls_sni = name;
  config.proxy.tls_ca_file = TUNNEL_TEST_TLS_CA_FILE;
  f.tunnel = tunnel_create(&config);
  check_not_null(f.tunnel);
  /* Exercise production tunnel_poll without requiring a privileged TUN device. */
  f.tunnel->running = 1;
  if (!connect) return;
  f.conn = tunnel_proxy_connect_tcp(f.tunnel->proxy, "127.0.0.1",
      type == TUNNEL_PROXY_NONE ? f.port : 443,
      client_connect, client_data, client_close, &f);
  check_not_null(f.conn);
}
static void init_fixture(tunnel_proxy_type_t type, int use_tls, const char *name) {
  init_fixture_owner(type, use_tls, name, 1);
}
static void destroy_fixture(void) {
  if (f.tunnel) { tunnel_destroy(f.tunnel); f.tunnel = NULL; }
  if (f.server.impl) {
    check_equal(cnet_client_stop(&f.server, TEST_TIMEOUT_MS), SALTS_OK);
    check_equal(cnet_client_destroy(&f.server), SALTS_OK);
  }
  if (f.listener.impl) {
    check_equal(cnet_listener_close(&f.listener), SALTS_OK);
    check_equal(cnet_listener_destroy(&f.listener), SALTS_OK);
  }
  if (f.tls.impl) check_equal(cnet_tls_server_destroy(&f.tls), SALTS_OK);
}
static void wait_request_started(void) {
  uint64_t deadline = cmeta_monotonic_ms() + TEST_TIMEOUT_MS;
  while (!f.requests_size && cmeta_monotonic_ms() < deadline) drive();
  check_true(f.requests_size > 0u);
}
static void http_handshake(void) {
  uint64_t deadline = cmeta_monotonic_ms() + TEST_TIMEOUT_MS;
  while (!f.requests_size && cmeta_monotonic_ms() < deadline) drive();
  check_true(f.requests_size > 0u);
  check_true(strstr((const char *)f.requests, "CONNECT 127.0.0.1:443 HTTP/1.1") != NULL);
  check_true(strstr((const char *)f.requests, "Proxy-Authorization: Basic dXNlcjpzZWNyZXQ=") != NULL);
  /* A short fragment must remain pending instead of being reported as invalid. */
  send_server("HT", 2u);
  for (int i = 0; i < 10; ++i) drive();
  check_equal(f.connect_events, 0);
  static const char tail[] = "TP/1.1 200 Connection Established\r\nX-Test: yes\r\n\r\npayload";
  send_server(tail, sizeof(tail) - 1u);
  wait_connect();
  check_equal(f.connect_status, TUNNEL_OK);
}

spec("CNet tunnel product transport") {
  after_each() { destroy_fixture(); }
  it("direct TCP owns admitted bytes and delivers both directions") {
    init_fixture(TUNNEL_PROXY_NONE, 0, NULL);
    wait_connect();
    check_equal(f.connect_status, TUNNEL_OK);
    uint8_t data[] = "hello";
    check_equal(tunnel_proxy_send(f.conn, data, 5u), TUNNEL_OK);
    memset(data, 'x', 5u);
    wait_requests(5u);
    check_equal(f.requests, "hello", 5u);
    send_server("world", 5u);
    wait_received(5u);
    check_equal(f.received, "world", 5u);
    check_equal(cnet_close(&f.server, f.peer), SALTS_OK);
    wait_retired();
    check_equal(f.close_events, 1);
  }
  it("HTTP fragments retain payload coalesced with the handshake") {
    init_fixture(TUNNEL_PROXY_HTTP, 0, NULL);
    http_handshake();
    wait_received(7u);
    check_equal(f.received, "payload", 7u);
  }
  it("verified TLS HTTP uses private CA and SNI and exposes negotiated queries") {
    init_fixture(TUNNEL_PROXY_HTTP, 1, "localhost");
    http_handshake();
    wait_received(7u);
    char version[32], cipher[128];
    size_t size;
    check_equal(cnet_tls_negotiated_version(&f.tunnel->proxy->client, f.conn->connection,
                                           version, sizeof(version), &size), SALTS_OK);
    check_true(!strcmp(version, "TLSv1.3") || !strcmp(version, "TLSv1.2"));
    check_equal(cnet_tls_negotiated_cipher(&f.tunnel->proxy->client, f.conn->connection,
                                          cipher, sizeof(cipher), &size), SALTS_OK);
    check_true(size > 0u);
    check_equal(tunnel_proxy_send(f.conn, (const uint8_t *)"secure", 6u), TUNNEL_OK);
    size_t prior = f.requests_size;
    wait_requests(prior + 6u);
    check_equal(f.requests + prior, "secure", 6u);
  }
  it("TLS identity mismatch never establishes the proxy") {
    init_fixture(TUNNEL_PROXY_HTTP, 1, "wrong.invalid");
    wait_connect();
    check_equal(f.connect_status, TUNNEL_ERR_NETWORK);
    check_equal(f.requests_size, 0u);
    check_equal(f.received_size, 0u);
  }
  it("SOCKS5 auth fragments and short domain replies preserve payload") {
    init_fixture(TUNNEL_PROXY_SOCKS5, 0, NULL);
    wait_requests(4u);
    const uint8_t greeting[] = {5u, 2u};
    send_server(greeting, 1u);
    for (int i = 0; i < 10; ++i) drive();
    check_equal(f.requests_size, 4u);
    send_server(greeting + 1u, 1u);
    wait_requests(17u);
    check_equal(f.requests + 4u, "\1\4user\6secret", 13u);
    const uint8_t auth[] = {1u, 0u};
    send_server(auth, sizeof(auth));
    wait_requests(27u);
    check_equal(f.requests[17], 5u);
    check_equal(f.requests[18], 1u);
    /* One-character domain yields an eight-byte reply, smaller than IPv4. */
    const uint8_t response[] = {5u, 0u, 0u, 3u, 1u, 'x', 0u, 1u, 'o', 'k'};
    send_server(response, 4u);
    for (int i = 0; i < 10; ++i) drive();
    check_equal(f.connect_events, 0);
    send_server(response + 4u, sizeof(response) - 4u);
    wait_connect();
    wait_received(2u);
    check_equal(f.connect_status, TUNNEL_OK);
    check_equal(f.received, "ok", 2u);
  }
  it("unsupported SOCKS authentication is rejected once") {
    init_fixture(TUNNEL_PROXY_SOCKS5, 0, NULL);
    wait_requests(4u);
    const uint8_t response[] = {5u, 1u};
    send_server(response, sizeof(response));
    wait_connect();
    check_equal(f.connect_status, TUNNEL_ERR_PROXY_AUTH);
    for (int i = 0; i < 10; ++i) drive();
    check_equal(f.connect_events, 1);
    check_equal(f.requests_size, 4u);
  }
  it("CONNECT refusal cannot publish coalesced data") {
    init_fixture(TUNNEL_PROXY_HTTP, 0, NULL);
    wait_request_started();
    static const char response[] = "HTTP/1.1 407 Auth Required\r\n\r\nforbidden";
    send_server(response, sizeof(response) - 1u);
    wait_connect();
    check_equal(f.connect_status, TUNNEL_ERR_PROXY_AUTH);
    check_equal(f.received_size, 0u);
  }
  it("oversized HTTP headers fail within the handshake bound") {
    init_fixture(TUNNEL_PROXY_HTTP, 0, NULL);
    wait_request_started();
    uint8_t response[4097];
    memset(response, 'a', sizeof(response));
    send_server(response, sizeof(response));
    wait_connect();
    check_equal(f.connect_status, TUNNEL_ERR_PROXY_CONNECT);
  }
  it("destroy from the connect callback suppresses following data and close callbacks") {
    init_fixture(TUNNEL_PROXY_HTTP, 0, NULL);
    f.destroy_on_connect = 1;
    http_handshake();
    wait_retired();
    check_equal(f.received_size, 0u);
    check_equal(f.close_events, 0);
  }
  it("destroy from receive keeps the observer alive until CNet terminal") {
    init_fixture(TUNNEL_PROXY_NONE, 0, NULL);
    wait_connect();
    f.destroy_on_data = 1;
    send_server("end", 3u);
    wait_received(3u);
    wait_retired();
    check_equal(f.data_events, 1);
    check_equal(f.close_events, 0);
  }
  it("destroy before progress cancels connection without stale user callbacks") {
    init_fixture(TUNNEL_PROXY_NONE, 0, NULL);
    tunnel_proxy_conn_destroy(f.conn);
    f.conn = NULL;
    wait_retired();
    check_equal(f.connect_events, 0);
    check_equal(f.close_events, 0);
  }
  it("tunnel destruction requested by a CNet callback completes after poll") {
    init_fixture(TUNNEL_PROXY_NONE, 0, NULL);
    f.destroy_tunnel_on_connect = 1;
    wait_connect();
    check_null(f.tunnel);
    check_equal(f.close_events, 0);
  }
  it("config replacement retires active handshakes before credentials change") {
    init_fixture(TUNNEL_PROXY_HTTP, 0, NULL);
    wait_request_started();
    tunnel_proxy_config_t config = {0};
    check_equal(tunnel_set_proxy(f.tunnel, &config), TUNNEL_OK);
    wait_connect();
    check_equal(f.connect_status, TUNNEL_ERR_NETWORK);
    check_equal(f.received_size, 0u);
    tunnel_proxy_conn_destroy(f.conn);
    f.conn = NULL;
    wait_retired();
  }
  it("invalid configuration leaves the active proxy intact") {
    init_fixture(TUNNEL_PROXY_NONE, 0, NULL);
    wait_connect();
    tunnel_proxy_config_t config = {0};
    config.type = TUNNEL_PROXY_HTTP;
    config.host = "127.0.0.1";
    config.port = f.port;
    config.use_tls = 1;
    check_equal(tunnel_set_proxy(f.tunnel, &config), TUNNEL_ERR_NOT_SUPPORTED);
    check_equal(tunnel_proxy_conn_get_state(f.conn), TUNNEL_PROXY_STATE_ESTABLISHED);
    config.type = TUNNEL_PROXY_VMESS;
    check_equal(tunnel_set_proxy(f.tunnel, &config), TUNNEL_ERR_NOT_SUPPORTED);
    check_null(tunnel_proxy_connect_udp(f.tunnel->proxy, client_connect, client_data, client_close, &f));
    uint8_t byte = 1u;
    check_equal(tunnel_proxy_send(f.conn, &byte, TUNNEL_SEND_BUF_SIZE + 1u), TUNNEL_ERR_INVALID_ARG);
    check_equal(tunnel_proxy_send(f.conn, &byte, 1u), TUNNEL_OK);
    wait_requests(1u);
  }
  it("stop requested by a callback drains the owner and permits restart") {
    init_fixture(TUNNEL_PROXY_NONE, 0, NULL);
    f.stop_on_connect = 1;
    wait_connect();
    check_false(f.tunnel->running);
    check_null(f.tunnel->proxy->client.impl);
    check_equal(f.tunnel->proxy->connection_count, 0u);
    check_equal(f.close_events, 0);
    check_equal(tunnel_proxy_start(f.tunnel->proxy), TUNNEL_OK);
    check_not_null(f.tunnel->proxy->client.impl);
  }
  it("command pressure preserves cancelled observers until owner quiescence") {
    init_fixture(TUNNEL_PROXY_NONE, 0, NULL);
    size_t admitted = 1u;
    while (admitted < 512u) {
      tunnel_proxy_conn_t *conn = tunnel_proxy_connect_tcp(f.tunnel->proxy,
          "127.0.0.1", f.port, client_connect, client_data, client_close, &f);
      if (!conn) break;
      ++admitted;
    }
    check_true(admitted < 512u);
    check_true(admitted > 1u);
    check_equal(f.tunnel->proxy->connection_count, admitted);
    for (tunnel_proxy_conn_t *conn = f.tunnel->proxy->connections; conn; conn = conn->next)
      tunnel_proxy_conn_destroy(conn);
    check_equal(f.tunnel->proxy->connection_count, admitted);
    check_equal(tunnel_proxy_stop(f.tunnel->proxy), TUNNEL_OK);
    f.conn = NULL;
    check_equal(f.tunnel->proxy->connection_count, 0u);
    check_equal(f.connect_events, 0);
    check_equal(f.close_events, 0);
  }
  it("invalid trust and unsafe authority do not retire a working connection") {
    init_fixture(TUNNEL_PROXY_NONE, 0, NULL);
    wait_connect();
    tunnel_proxy_config_t config = {0};
    config.type = TUNNEL_PROXY_HTTP;
    config.host = "127.0.0.1";
    config.port = f.port;
    config.use_tls = 1;
    config.tls_verify = 1;
    config.tls_ca_file = "missing-tunnel-ca.pem";
    check_equal(tunnel_set_proxy(f.tunnel, &config), TUNNEL_ERR_PROXY_AUTH);
    check_equal(tunnel_proxy_conn_get_state(f.conn), TUNNEL_PROXY_STATE_ESTABLISHED);
    config.use_tls = 0;
    config.host = "127.0.0.1/evil";
    check_equal(tunnel_set_proxy(f.tunnel, &config), TUNNEL_ERR_INVALID_ARG);
    check_null(tunnel_proxy_connect_tcp(f.tunnel->proxy, "bad\r\nhost", 443,
                                       client_connect, client_data, client_close, &f));
  }
  it("UDP proxy transport returns an explicit unsupported error") {
    init_fixture(TUNNEL_PROXY_NONE, 0, NULL);
    tunnel_endpoint_t source = {.family = AF_INET, .port = 1234};
    tunnel_endpoint_t destination = {.family = AF_INET, .port = 443};
    const uint8_t data[] = "udp";
    check_equal(tunnel_session_udp_datagram(f.tunnel, &source, &destination,
                                           data, sizeof(data)), TUNNEL_ERR_NOT_SUPPORTED);
    check_equal(tunnel_nat_session_count(f.tunnel->nat), 0u);
  }
  it("real NAT session buffers before connect and commits only admitted TCP bytes") {
    init_fixture_owner(TUNNEL_PROXY_NONE, 0, NULL, 0);
    tunnel_endpoint_t source = {.family = AF_INET, .port = 1234};
    tunnel_endpoint_t destination = {.family = AF_INET, .port = f.port};
    source.addr.v4 = htonl(0x7f000002u);
    destination.addr.v4 = htonl(0x7f000001u);
    uint8_t packet[64];
    int size = tunnel_ip_build_tcp(packet, sizeof(packet), &source, &destination,
                                   1u, 0u, TUNNEL_TCP_SYN, 65535u, NULL, 0u);
    check_true(size > 0);
    check_equal(tunnel_handle_tun_packet(f.tunnel, packet, (size_t)size), TUNNEL_OK);
    tunnel_session_key_t key = {.src = source, .dst = destination, .protocol = TUNNEL_IPPROTO_TCP};
    tunnel_session_t *session = tunnel_session_find(f.tunnel, &key);
    check_not_null(session);
    f.conn = session->proxy_conn;
    check_equal(tunnel_session_tcp_data(session, 2u, (const uint8_t *)"buffer", 6u), TUNNEL_OK);
    check_equal(session->send_len, 6u);
    wait_requests(6u);
    check_equal(session->state, TUNNEL_SESSION_ESTABLISHED);
    check_equal(session->send_len, 0u);
    check_equal(f.requests, "buffer", 6u);
    uint64_t bytes = session->bytes_tx;
    uint32_t ack = session->tcp.ack_local;
    uint8_t byte = 1u;
    check_equal(tunnel_session_tcp_data(session, 8u, &byte, TUNNEL_SEND_BUF_SIZE + 1u),
                TUNNEL_ERR_INVALID_ARG);
    check_equal(session->bytes_tx, bytes);
    check_equal(session->tcp.ack_local, ack);
    session->send_buf[0] = 'z';
    session->send_len = 1u;
    tunnel_proxy_conn_close(f.conn);
    check_equal(tunnel_session_flush(session), 0u);
    check_equal(session->send_len, 1u);
    tunnel_session_destroy(session);
    f.conn = NULL;
    wait_retired();
    check_equal(tunnel_nat_session_count(f.tunnel->nat), 0u);
  }
  it("IPv6 CONNECT uses a numeric SOCKS address and bracketed HTTP authority") {
    uint8_t request[512];
    size_t size;
    check_equal(tunnel_socks5_build_connect_request("::1", 443, 1, request, &size), TUNNEL_OK);
    check_equal(size, 22u);
    check_equal(request[3], 4u);
    check_equal(request[19], 1u);
    check_equal(tunnel_http_build_connect_request("::1", 443, NULL, NULL,
                                                 request, &size, sizeof(request)), TUNNEL_OK);
    check_true(strstr((const char *)request, "CONNECT [::1]:443 HTTP/1.1") != NULL);
  }
  it("timeout bounds reject invalid input and avoid signed millisecond overflow") {
    tunnel_config_t config;
    tunnel_config_init(&config);
    config.session_timeout = -1;
    check_null(tunnel_create(&config));
    config.session_timeout = (int)(UINT32_MAX / 1000u) + 1;
    check_null(tunnel_create(&config));
    init_fixture(TUNNEL_PROXY_NONE, 0, NULL);
    f.tunnel->config.session_timeout = (int)(UINT32_MAX / 1000u);
    f.tunnel->last_session_maintenance_ms = 0;
    wait_connect();
    check_equal(f.connect_status, TUNNEL_OK);
  }
  it("HTTP bounded parsing handles non-NUL input and rejects malformed status") {
    const uint8_t bytes[] = {'H','T','T','P','/','1','.','1',' ','2','0','0','\r','\n','\r','\n'};
    size_t consumed;
    check_equal(tunnel_http_parse_response_frame(bytes, sizeof(bytes), &consumed), TUNNEL_OK);
    check_equal(consumed, sizeof(bytes));
    check_equal(tunnel_http_parse_response_frame(bytes, 2u, &consumed), TUNNEL_ERR_TIMEOUT);
    static const uint8_t invalid[] = "HTTP/1.1 200x\r\n\r\n";
    check_equal(tunnel_http_parse_response_frame(invalid, sizeof(invalid) - 1u, &consumed), TUNNEL_ERR_PROXY_CONNECT);
  }
}
