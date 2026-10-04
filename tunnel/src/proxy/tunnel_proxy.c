/**
 * @file tunnel_proxy.c
 * @brief Single-owner TCP/TLS proxy transport over public CNet.
 */
#include "tunnel_proxy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PROXY_QUEUE_CAPACITY 256u
#define PROXY_IO_TIMEOUT_MS 30000u
#define PROXY_STOP_TIMEOUT_MS 1000u
#define SOCKS_REPLY_PREFIX_SIZE 4u
#define SOCKS_IPV4_REPLY_SIZE 10u
#define SOCKS_IPV6_REPLY_SIZE 22u
#define SOCKS_DOMAIN_REPLY_OVERHEAD 7u
#define PROXY_REQUEST_SIZE 2048u

static void proxy_conn_send_connect(tunnel_proxy_conn_t *conn);
static void proxy_conn_receive(tunnel_proxy_conn_t *conn);

static int same_connection(cnet_connection a, cnet_connection b) {
  return a.slot == b.slot && a.generation == b.generation;
}

static int proxy_conn_active(const tunnel_proxy_conn_t *conn) {
  return !conn->proxy->tunnel->stopping && !conn->proxy->tunnel->destroy_requested &&
         !conn->destroy_requested && !conn->close_requested && !conn->terminal &&
         conn->state != TUNNEL_PROXY_STATE_ERROR;
}

static void proxy_conn_notify_connect(tunnel_proxy_conn_t *conn, int status) {
  if (conn->destroy_requested || conn->connect_notified) return;
  conn->connect_notified = 1;
  if (conn->connect_cb) conn->connect_cb(conn, status, conn->user_data);
}

static void proxy_conn_notify_close(tunnel_proxy_conn_t *conn) {
  if (conn->destroy_requested || conn->close_notified) return;
  conn->close_notified = 1;
  if (conn->close_cb) conn->close_cb(conn, conn->user_data);
}

static void proxy_conn_try_close(tunnel_proxy_conn_t *conn) {
  int status;
  if (!conn->close_requested || conn->close_admitted || conn->terminal) return;
  status = cnet_close(&conn->proxy->client, conn->connection);
  if (status == SALTS_OK || status == SALTS_EALREADY) conn->close_admitted = 1;
  /* Queue pressure does not revoke the observer. Retry on the owner's next pass. */
}

void tunnel_proxy_conn_close(tunnel_proxy_conn_t *conn) {
  if (!conn) return;
  conn->close_requested = 1;
  if (conn->state != TUNNEL_PROXY_STATE_ERROR) conn->state = TUNNEL_PROXY_STATE_CLOSED;
  proxy_conn_try_close(conn);
}

void tunnel_proxy_conn_destroy(tunnel_proxy_conn_t *conn) {
  if (!conn) return;
  /* Session storage can be freed now; CNet still owns this observer until terminal. */
  conn->destroy_requested = 1;
  conn->connect_cb = NULL;
  conn->data_cb = NULL;
  conn->close_cb = NULL;
  conn->user_data = NULL;
  conn->session = NULL;
  tunnel_proxy_conn_close(conn);
}

static void proxy_conn_fail(tunnel_proxy_conn_t *conn, int status) {
  if (!proxy_conn_active(conn)) return;
  conn->state = TUNNEL_PROXY_STATE_ERROR;
  tunnel_proxy_conn_close(conn);
  if (!conn->connect_notified) proxy_conn_notify_connect(conn, status);
  else proxy_conn_notify_close(conn);
}

static int proxy_conn_send(tunnel_proxy_conn_t *conn, const uint8_t *data, size_t len) {
  mem_buffer_t *buffer;
  int status;
  if (!conn || !data || !len || len > TUNNEL_SEND_BUF_SIZE) return TUNNEL_ERR_INVALID_ARG;
  if (!proxy_conn_active(conn)) return TUNNEL_ERR_CLOSED;
  buffer = mem_get_buffer(mem_global(), len);
  if (!buffer) return TUNNEL_ERR_NO_MEMORY;
  memcpy(mem_buffer_data(buffer), data, len);
  mem_set_used(buffer, len);
  status = cnet_send_buffer(&conn->proxy->client, conn->connection, buffer);
  mem_buffer_release(buffer);
  return status == SALTS_OK ? TUNNEL_OK : TUNNEL_ERR_NETWORK;
}

static void proxy_conn_handshake_write(tunnel_proxy_conn_t *conn, const uint8_t *data,
                                       size_t size, proxy_handshake_state_t next) {
  int result = proxy_conn_send(conn, data, size);
  if (result != TUNNEL_OK) { proxy_conn_fail(conn, result); return; }
  conn->handshake_write_bytes = size;
  conn->next_handshake_state = next;
  /* Only on_send commits the phase and admits its response read. */
}

static void proxy_conn_send_greeting(tunnel_proxy_conn_t *conn) {
  uint8_t data[4];
  size_t size;
  int result = tunnel_socks5_build_greeting(conn, data, &size);
  if (result != TUNNEL_OK) { proxy_conn_fail(conn, result); return; }
  proxy_conn_handshake_write(conn, data, size, PROXY_HANDSHAKE_GREETING_SENT);
}

static void proxy_conn_send_auth(tunnel_proxy_conn_t *conn) {
  uint8_t data[515];
  size_t size;
  int result = tunnel_socks5_build_auth_request(conn->proxy, data, &size);
  if (result != TUNNEL_OK) { proxy_conn_fail(conn, result); return; }
  proxy_conn_handshake_write(conn, data, size, PROXY_HANDSHAKE_AUTH_SENT);
}

static void proxy_conn_send_connect(tunnel_proxy_conn_t *conn) {
  uint8_t data[PROXY_REQUEST_SIZE];
  size_t size;
  int result;
  if (conn->proxy->type == TUNNEL_PROXY_SOCKS5) {
    struct in_addr address;
    int domain = inet_pton(AF_INET, conn->target_host, &address) != 1;
    result = tunnel_socks5_build_connect_request(conn->target_host, conn->target_port,
                                                domain, data, &size);
  } else {
    result = tunnel_http_build_connect_request(conn->target_host, conn->target_port,
        conn->proxy->username, conn->proxy->password, data, &size, sizeof(data));
  }
  if (result != TUNNEL_OK) { proxy_conn_fail(conn, result); return; }
  proxy_conn_handshake_write(conn, data, size, PROXY_HANDSHAKE_CONNECT_SENT);
}

static void proxy_conn_established(tunnel_proxy_conn_t *conn) {
  conn->handshake_state = PROXY_HANDSHAKE_COMPLETE;
  conn->state = TUNNEL_PROXY_STATE_ESTABLISHED;
  conn->recv_len = 0;
  proxy_conn_notify_connect(conn, TUNNEL_OK);
}

/* Returns TIMEOUT only while a bounded handshake frame is incomplete. */
static int proxy_conn_handshake_frame(tunnel_proxy_conn_t *conn) {
  size_t consumed = 0;
  uint8_t *data = conn->recv_buf;
  size_t size = conn->recv_len;
  if (conn->proxy->type == TUNNEL_PROXY_HTTP) {
    int result;
    if (size < 4u || memcmp(data + size - 4u, "\r\n\r\n", 4u)) return TUNNEL_ERR_TIMEOUT;
    result = tunnel_http_parse_response_frame(data, size, &consumed);
    if (result == TUNNEL_OK) proxy_conn_established(conn);
    return result;
  }
  if (conn->handshake_state == PROXY_HANDSHAKE_GREETING_SENT) {
    uint8_t method;
    if (size < 2u) return TUNNEL_ERR_TIMEOUT;
    if (tunnel_socks5_parse_greeting_response(data, size, &method) != TUNNEL_OK)
      return TUNNEL_ERR_PROXY_CONNECT;
    if (method != 0u && (method != 2u || !conn->proxy->username[0]))
      return TUNNEL_ERR_PROXY_AUTH;
    conn->recv_len = 0;
    if (method == 2u) proxy_conn_send_auth(conn);
    else proxy_conn_send_connect(conn);
    return TUNNEL_OK;
  }
  if (conn->handshake_state == PROXY_HANDSHAKE_AUTH_SENT) {
    int result;
    if (size < 2u) return TUNNEL_ERR_TIMEOUT;
    result = tunnel_socks5_parse_auth_response(data, size);
    if (result != TUNNEL_OK) return result;
    conn->recv_len = 0;
    proxy_conn_send_connect(conn);
    return TUNNEL_OK;
  }
  if (conn->handshake_state == PROXY_HANDSHAKE_CONNECT_SENT) {
    uint8_t reply;
    size_t required;
    tunnel_endpoint_t bound;
    if (size < SOCKS_REPLY_PREFIX_SIZE) return TUNNEL_ERR_TIMEOUT;
    if (data[0] != 5u || data[2] != 0u) return TUNNEL_ERR_PROXY_CONNECT;
    if (data[1] != 0u) return TUNNEL_ERR_PROXY_REFUSED;
    if (data[3] == 1u) required = SOCKS_IPV4_REPLY_SIZE;
    else if (data[3] == 4u) required = SOCKS_IPV6_REPLY_SIZE;
    else if (data[3] == 3u) {
      if (size < 5u) return TUNNEL_ERR_TIMEOUT;
      if (!data[4]) return TUNNEL_ERR_PROXY_CONNECT;
      required = SOCKS_DOMAIN_REPLY_OVERHEAD + data[4];
    } else return TUNNEL_ERR_PROXY_CONNECT;
    if (size < required) return TUNNEL_ERR_TIMEOUT;
    if (tunnel_socks5_parse_connect_response(data, size, &reply, &bound) != TUNNEL_OK)
      return TUNNEL_ERR_PROXY_REFUSED;
    proxy_conn_established(conn);
    return TUNNEL_OK;
  }
  return TUNNEL_ERR_PROXY_CONNECT;
}

static void proxy_conn_on_receive(void *user, cnet_connection handle,
                                   const cnet_receive_view *view) {
  tunnel_proxy_conn_t *conn = user;
  const uint8_t *data;
  size_t offset = 0;
  if (!same_connection(handle, conn->connection)) return;
  conn->receive_pending = 0;
  if (!proxy_conn_active(conn)) return;
  if (!view || view->kind != CNET_MESSAGE_BYTES || !view->data || !view->size) {
    proxy_conn_fail(conn, TUNNEL_ERR_NETWORK);
    return;
  }
  data = view->data;
  /* Materialize only the handshake, then forward the coalesced tail as a borrow. */
  while (offset < view->size && conn->state != TUNNEL_PROXY_STATE_ESTABLISHED) {
    int result;
    if (conn->recv_len == sizeof(conn->recv_buf)) {
      proxy_conn_fail(conn, TUNNEL_ERR_PROXY_CONNECT); return;
    }
    conn->recv_buf[conn->recv_len++] = data[offset++];
    result = proxy_conn_handshake_frame(conn);
    if (result == TUNNEL_ERR_TIMEOUT) continue;
    if (result != TUNNEL_OK) { proxy_conn_fail(conn, result); return; }
    if (!proxy_conn_active(conn)) return;
    if (conn->handshake_write_bytes) {
      if (offset != view->size) proxy_conn_fail(conn, TUNNEL_ERR_PROXY_CONNECT);
      return;
    }
  }
  if (proxy_conn_active(conn) && offset < view->size && conn->data_cb)
    conn->data_cb(conn, data + offset, view->size - offset, conn->user_data);
  proxy_conn_receive(conn);
}

static void proxy_conn_receive(tunnel_proxy_conn_t *conn) {
  if (!proxy_conn_active(conn) || conn->receive_pending || conn->handshake_write_bytes) return;
  if (cnet_receive(&conn->proxy->client, conn->connection, 1u) != SALTS_OK) {
    proxy_conn_fail(conn, TUNNEL_ERR_NETWORK); return;
  }
  conn->receive_pending = 1;
}

static void proxy_conn_on_send(void *user, cnet_connection handle, size_t size) {
  tunnel_proxy_conn_t *conn = user;
  if (!same_connection(handle, conn->connection) || !proxy_conn_active(conn)) return;
  if (!conn->handshake_write_bytes) return;
  if (size != conn->handshake_write_bytes) { proxy_conn_fail(conn, TUNNEL_ERR_NETWORK); return; }
  conn->handshake_write_bytes = 0;
  conn->handshake_state = conn->next_handshake_state;
  proxy_conn_receive(conn);
}

static void proxy_conn_on_state(void *user, cnet_connection handle,
                                cnet_connection_state state, const cnet_error *error) {
  tunnel_proxy_conn_t *conn = user;
  (void)error;
  if (!same_connection(handle, conn->connection)) return;
  if (state == CNET_CONNECTION_CLOSED || state == CNET_CONNECTION_FAILED) {
    conn->terminal = 1;
    conn->receive_pending = 0;
    conn->handshake_write_bytes = 0;
    if (conn->destroy_requested) return;
    if (!conn->connect_notified) {
      conn->state = TUNNEL_PROXY_STATE_ERROR;
      proxy_conn_notify_connect(conn, TUNNEL_ERR_NETWORK);
    } else {
      if (conn->state != TUNNEL_PROXY_STATE_ERROR) conn->state = TUNNEL_PROXY_STATE_CLOSED;
      proxy_conn_notify_close(conn);
    }
    return;
  }
  if (state != CNET_CONNECTION_CONNECTED || !proxy_conn_active(conn)) return;
  conn->state = TUNNEL_PROXY_STATE_HANDSHAKING;
  if (conn->proxy->type == TUNNEL_PROXY_SOCKS5) proxy_conn_send_greeting(conn);
  else if (conn->proxy->type == TUNNEL_PROXY_HTTP) proxy_conn_send_connect(conn);
  else {
    proxy_conn_established(conn);
    proxy_conn_receive(conn);
  }
}

static void proxy_collect(tunnel_proxy_t *proxy) {
  tunnel_proxy_conn_t **link = &proxy->connections;
  /* O(n) sweep, bounded by TUNNEL_MAX_SESSIONS. Never free from a CNet callback. */
  while (*link) {
    tunnel_proxy_conn_t *conn = *link;
    if (conn->destroy_requested && conn->terminal) {
      *link = conn->next;
      free(conn);
      --proxy->connection_count;
    } else link = &conn->next;
  }
}

int tunnel_proxy_poll(tunnel_proxy_t *proxy) {
  size_t events = 0;
  int status;
  if (!proxy || !proxy->client.impl) return 0;
  if (proxy->polling) return TUNNEL_ERR_INVALID_ARG;
  for (tunnel_proxy_conn_t *conn = proxy->connections; conn; conn = conn->next)
    proxy_conn_try_close(conn);
  proxy->polling = 1;
  status = cnet_client_poll(&proxy->client, 0u, &events);
  proxy->polling = 0;
  proxy_collect(proxy);
  if (proxy->stop_requested && tunnel_proxy_stop(proxy) != TUNNEL_OK) return TUNNEL_ERR_NETWORK;
  return status == SALTS_OK ? (int)events : TUNNEL_ERR_NETWORK;
}

static int valid_text(const char *text, size_t capacity) {
  if (!text) return 1;
  if (strlen(text) >= capacity) return 0;
  return !strchr(text, '\r') && !strchr(text, '\n');
}

static int valid_host(const char *host) {
  if (!host || !*host) return 0;
  for (const unsigned char *p = (const unsigned char *)host; *p; ++p)
    if (*p <= ' ' || *p == 127u || strchr("/@?#[]", *p)) return 0;
  return 1;
}

int tunnel_proxy_set_config(tunnel_proxy_t *proxy, const tunnel_proxy_config_t *config) {
  cnet_tls_client profile = {0};
  cnet_tls_client_config tls = {0};
  if (!proxy || !config) return TUNNEL_ERR_INVALID_ARG;
  if (config->type != TUNNEL_PROXY_NONE && config->type != TUNNEL_PROXY_HTTP &&
      config->type != TUNNEL_PROXY_SOCKS5) return TUNNEL_ERR_NOT_SUPPORTED;
  if (!valid_text(config->host, sizeof(proxy->host)) ||
      !valid_text(config->username, sizeof(proxy->username)) ||
      !valid_text(config->password, sizeof(proxy->password)) ||
      !valid_text(config->tls_sni, sizeof(proxy->tls_sni))) return TUNNEL_ERR_INVALID_ARG;
  if (config->type != TUNNEL_PROXY_NONE &&
      (!valid_host(config->host) || config->port < 1 || config->port > UINT16_MAX))
    return TUNNEL_ERR_INVALID_ARG;
  if (config->use_tls && (!config->tls_verify || config->type == TUNNEL_PROXY_NONE))
    return TUNNEL_ERR_NOT_SUPPORTED;
  if (config->use_tls) {
    tls.size = sizeof(tls);
    tls.ca_file = config->tls_ca_file;
    tls.server_name = config->tls_sni && config->tls_sni[0] ? config->tls_sni : NULL;
    if (cnet_tls_client_init(&profile, &tls) != SALTS_OK) return TUNNEL_ERR_PROXY_AUTH;
  }
  /* Validate a replacement trust policy before retiring active connections. */
  for (tunnel_proxy_conn_t *conn = proxy->connections; conn; conn = conn->next)
    tunnel_proxy_conn_close(conn);
  if (cnet_tls_client_destroy(&proxy->tls_client) != SALTS_OK) {
    cnet_tls_client_destroy(&profile);
    return TUNNEL_ERR_NETWORK;
  }
  proxy->tls_client = profile;
  proxy->type = config->type;
  proxy->port = config->port;
  proxy->use_tls = config->use_tls;
  proxy->tls_verify = config->tls_verify;
  snprintf(proxy->host, sizeof(proxy->host), "%s", config->host ? config->host : "");
  snprintf(proxy->username, sizeof(proxy->username), "%s", config->username ? config->username : "");
  snprintf(proxy->password, sizeof(proxy->password), "%s", config->password ? config->password : "");
  snprintf(proxy->tls_sni, sizeof(proxy->tls_sni), "%s", config->tls_sni ? config->tls_sni : "");
  return TUNNEL_OK;
}

int tunnel_proxy_start(tunnel_proxy_t *proxy) {
  cnet_client_config policy = {0};
  if (!proxy || !proxy->tunnel) return TUNNEL_ERR_INVALID_ARG;
  if (proxy->client.impl || proxy->tunnel->config.mode == TUNNEL_MODE_PACKET) return TUNNEL_OK;
  proxy->stop_requested = 0;
#ifdef _WIN32
  policy.backend = NATIVE_IO_BACKEND_IOCP;
#elif defined(__linux__)
  policy.backend = NATIVE_IO_BACKEND_EPOLL;
#else
  policy.backend = NATIVE_IO_BACKEND_KQUEUE;
#endif
  policy.connection_capacity = TUNNEL_MAX_SESSIONS;
  policy.command_capacity = PROXY_QUEUE_CAPACITY;
  policy.request_capacity = TUNNEL_MAX_SESSIONS * 4u;
  policy.completion_batch_capacity = PROXY_QUEUE_CAPACITY;
  policy.event_capacity = PROXY_QUEUE_CAPACITY;
  policy.max_send_bytes = TUNNEL_SEND_BUF_SIZE;
  policy.receive_buffer_bytes = TUNNEL_RECV_BUF_SIZE;
  policy.connect_timeout_ms = PROXY_IO_TIMEOUT_MS;
  policy.write_timeout_ms = PROXY_IO_TIMEOUT_MS;
  policy.tls_io_buffer_bytes = CNET_TLS_MIN_IO_BUFFER_BYTES;
  policy.tls_handshake_timeout_ms = PROXY_IO_TIMEOUT_MS;
  policy.read_timeout_ms = TUNNEL_SESSION_TIMEOUT_MS;
  if (proxy->tunnel->config.session_timeout > 0 &&
      (unsigned)proxy->tunnel->config.session_timeout <= UINT32_MAX / 1000u)
    policy.read_timeout_ms = (uint32_t)proxy->tunnel->config.session_timeout * 1000u;
  return cnet_client_init(&proxy->client, &policy) == SALTS_OK ? TUNNEL_OK : TUNNEL_ERR_NETWORK;
}

tunnel_proxy_t *tunnel_proxy_create(tunnel_t *tunnel, const tunnel_proxy_config_t *config) {
  tunnel_proxy_t *proxy;
  if (!tunnel || !config) return NULL;
  proxy = calloc(1, sizeof(*proxy));
  if (!proxy) return NULL;
  proxy->tunnel = tunnel;
  if (tunnel_proxy_set_config(proxy, config) != TUNNEL_OK ||
      tunnel_proxy_start(proxy) != TUNNEL_OK) {
    cnet_tls_client_destroy(&proxy->tls_client);
    free(proxy);
    return NULL;
  }
  return proxy;
}

int tunnel_proxy_stop(tunnel_proxy_t *proxy) {
  int status;
  if (!proxy) return TUNNEL_OK;
  proxy->stop_requested = 1;
  for (tunnel_proxy_conn_t *conn = proxy->connections; conn; conn = conn->next)
    tunnel_proxy_conn_destroy(conn);
  if (proxy->polling) return TUNNEL_OK;
  if (proxy->client.impl) {
    do { status = cnet_client_stop(&proxy->client, PROXY_STOP_TIMEOUT_MS); }
    while (status == SALTS_ETIMEDOUT);
    /* Non-timeout errors can be reported after quiescence; always attempt destroy. */
    if (cnet_client_destroy(&proxy->client) != SALTS_OK) return TUNNEL_ERR_NETWORK;
  }
  while (proxy->connections) {
    tunnel_proxy_conn_t *conn = proxy->connections;
    proxy->connections = conn->next;
    free(conn);
  }
  proxy->connection_count = 0;
  return TUNNEL_OK;
}

int tunnel_proxy_destroy(tunnel_proxy_t *proxy) {
  if (!proxy) return TUNNEL_OK;
  if (proxy->polling) return TUNNEL_ERR_INVALID_ARG;
  if (tunnel_proxy_stop(proxy) != TUNNEL_OK) return TUNNEL_ERR_NETWORK;
  if (cnet_tls_client_destroy(&proxy->tls_client) != SALTS_OK) return TUNNEL_ERR_NETWORK;
  free(proxy);
  return TUNNEL_OK;
}

tunnel_proxy_conn_t *tunnel_proxy_connect_tcp(tunnel_proxy_t *proxy, const char *target_host,
    int target_port, tunnel_proxy_connect_cb connect_cb, tunnel_proxy_data_cb data_cb,
    tunnel_proxy_close_cb close_cb, void *user_data) {
  tunnel_proxy_conn_t *conn;
  const char *host;
  int port, result;
  char uri[512];
  cnet_connect_options options = {0};
  if (!proxy || !proxy->client.impl || proxy->stop_requested || !valid_host(target_host) ||
      !valid_text(target_host, sizeof(conn->target_host)) ||
      target_port < 1 || target_port > UINT16_MAX ||
      proxy->connection_count >= TUNNEL_MAX_SESSIONS) return NULL;
  conn = calloc(1, sizeof(*conn));
  if (!conn) return NULL;
  conn->proxy = proxy;
  conn->state = TUNNEL_PROXY_STATE_CONNECTING;
  snprintf(conn->target_host, sizeof(conn->target_host), "%s", target_host);
  conn->target_port = target_port;
  conn->connect_cb = connect_cb;
  conn->data_cb = data_cb;
  conn->close_cb = close_cb;
  conn->user_data = user_data;
  host = proxy->type == TUNNEL_PROXY_NONE ? target_host : proxy->host;
  port = proxy->type == TUNNEL_PROXY_NONE ? target_port : proxy->port;
  result = snprintf(uri, sizeof(uri), strchr(host, ':') ? "%s://[%s]:%d" : "%s://%s:%d",
                    proxy->use_tls ? "tls" : "tcp", host, port);
  if (result < 0 || (size_t)result >= sizeof(uri)) { free(conn); return NULL; }
  options.uri = uri;
  options.observer = (cnet_observer){proxy_conn_on_state, proxy_conn_on_receive, conn, proxy_conn_on_send};
  if (proxy->use_tls) options.tls_client = &proxy->tls_client;
  if (cnet_connect(&proxy->client, &options, &conn->connection) != SALTS_OK) { free(conn); return NULL; }
  conn->next = proxy->connections;
  proxy->connections = conn;
  ++proxy->connection_count;
  return conn;
}

tunnel_proxy_conn_t *tunnel_proxy_connect_udp(tunnel_proxy_t *proxy,
    tunnel_proxy_connect_cb connect_cb, tunnel_proxy_data_cb data_cb,
    tunnel_proxy_close_cb close_cb, void *user_data) {
  /* UDP requires a real datagram relay; a TCP CONNECT is not UDP ASSOCIATE. */
  (void)proxy; (void)connect_cb; (void)data_cb; (void)close_cb; (void)user_data;
  return NULL;
}

int tunnel_proxy_send(tunnel_proxy_conn_t *conn, const uint8_t *data, size_t len) {
  if (!conn || conn->state != TUNNEL_PROXY_STATE_ESTABLISHED) return TUNNEL_ERR_INVALID_ARG;
  return proxy_conn_send(conn, data, len);
}

int tunnel_proxy_send_udp(tunnel_proxy_conn_t *conn, const tunnel_endpoint_t *dst,
                           const uint8_t *data, size_t len) {
  if (!conn || !dst || !data || !len) return TUNNEL_ERR_INVALID_ARG;
  return TUNNEL_ERR_NOT_SUPPORTED;
}

tunnel_proxy_state_t tunnel_proxy_conn_get_state(tunnel_proxy_conn_t *conn) {
  return conn ? conn->state : TUNNEL_PROXY_STATE_CLOSED;
}
void *tunnel_proxy_conn_get_user_data(tunnel_proxy_conn_t *conn) { return conn ? conn->user_data : NULL; }
void tunnel_proxy_conn_set_user_data(tunnel_proxy_conn_t *conn, void *user_data) {
  if (conn && !conn->destroy_requested) conn->user_data = user_data;
}
void tunnel_proxy_conn_set_session(tunnel_proxy_conn_t *conn, void *session) {
  if (conn && !conn->destroy_requested) conn->session = session;
}
void *tunnel_proxy_conn_get_session(tunnel_proxy_conn_t *conn) { return conn ? conn->session : NULL; }
