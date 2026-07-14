/**
 * @file tunnel_proxy.c
 * @brief Proxy client implementation using CoroNet streams.
 */
#if defined(_MSC_VER) && !defined(__clang__)
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#endif

#include "tunnel_proxy.h"
#include "../core/tunnel_types.h"
#include <CoroNet/turbo_stream.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* =============================================================================
 * Forward Declarations
 * ============================================================================= */

static void proxy_conn_on_connect(void *handle, int status, void *peer);
static int proxy_conn_on_recv(void *handle, const mem_slice_t *slice, void *peer);
static void proxy_conn_on_close(void *handle);
static void proxy_conn_process_handshake(tunnel_proxy_conn_t *conn, const uint8_t *data,
                                         size_t len);
static void proxy_conn_send_greeting(tunnel_proxy_conn_t *conn);
static void proxy_conn_send_auth(tunnel_proxy_conn_t *conn);
static void proxy_conn_send_connect(tunnel_proxy_conn_t *conn);

/* =============================================================================
 * Helpers
 * ============================================================================= */

static turbo_stream_kind_t proxy_stream_kind_for_host(const char *host, int use_tls) {
  if (use_tls) {
    return TURBO_STREAM_TLS;
  }
  if (host && strchr(host, ':')) {
    return TURBO_STREAM_TCP6;
  }
  return TURBO_STREAM_TCP4;
}

static void proxy_conn_notify_connect(tunnel_proxy_conn_t *conn, int status) {
  if (!conn || conn->connect_notified || !conn->connect_cb) {
    return;
  }
  conn->connect_notified = 1;
  conn->connect_cb(conn, status, conn->user_data);
}

static void proxy_conn_notify_close(tunnel_proxy_conn_t *conn) {
  if (!conn || conn->close_notified || !conn->close_cb) {
    return;
  }
  conn->close_notified = 1;
  conn->close_cb(conn, conn->user_data);
}

static int proxy_conn_stream_send(tunnel_proxy_conn_t *conn, const uint8_t *data, size_t len) {
  if (!conn || !conn->stream) {
    return TUNNEL_ERR_NETWORK;
  }
  return turbo_stream_send(conn->stream, (const char *)data, len) == 0 ? TUNNEL_OK
                                                                        : TUNNEL_ERR_NETWORK;
}

/* =============================================================================
 * Proxy Client Lifecycle
 * ============================================================================= */

tunnel_proxy_t *tunnel_proxy_create(tunnel_t *tunnel, const tunnel_proxy_config_t *config) {
  if (!tunnel || !config) {
    return NULL;
  }

  tunnel_proxy_t *proxy = calloc(1, sizeof(tunnel_proxy_t));
  if (!proxy) {
    return NULL;
  }

  proxy->tunnel = tunnel;
  proxy->type = config->type;

  if (config->host) {
    strncpy(proxy->host, config->host, sizeof(proxy->host) - 1);
  }
  proxy->port = config->port;

  if (config->username) {
    strncpy(proxy->username, config->username, sizeof(proxy->username) - 1);
  }
  if (config->password) {
    strncpy(proxy->password, config->password, sizeof(proxy->password) - 1);
  }

  proxy->use_tls = config->use_tls;
  if (config->tls_sni) {
    strncpy(proxy->tls_sni, config->tls_sni, sizeof(proxy->tls_sni) - 1);
  }
  proxy->tls_verify = config->tls_verify;

  switch (config->type) {
  case TUNNEL_PROXY_SHADOWSOCKS:
    if (config->shadowsocks.method) {
      strncpy(proxy->shadowsocks.method, config->shadowsocks.method,
              sizeof(proxy->shadowsocks.method) - 1);
    }
    break;

  case TUNNEL_PROXY_VMESS:
    if (config->vmess.uuid) {
      strncpy(proxy->vmess.uuid, config->vmess.uuid, sizeof(proxy->vmess.uuid) - 1);
    }
    proxy->vmess.alter_id = config->vmess.alter_id;
    if (config->vmess.security) {
      strncpy(proxy->vmess.security, config->vmess.security, sizeof(proxy->vmess.security) - 1);
    }
    break;

  case TUNNEL_PROXY_TROJAN:
    if (config->trojan.password) {
      /* TODO: Hash password with SHA224 */
    }
    break;

  default:
    break;
  }

  return proxy;
}

void tunnel_proxy_destroy(tunnel_proxy_t *proxy) {
  if (!proxy) {
    return;
  }

  for (int i = 0; i < proxy->pool_count; i++) {
    if (proxy->pool[i]) {
      turbo_stream_close(proxy->pool[i]);
      turbo_stream_destroy(proxy->pool[i]);
      proxy->pool[i] = NULL;
    }
  }

  free(proxy);
}

int tunnel_proxy_set_config(tunnel_proxy_t *proxy, const tunnel_proxy_config_t *config) {
  if (!proxy || !config) {
    return TUNNEL_ERR_INVALID_ARG;
  }

  for (int i = 0; i < proxy->pool_count; i++) {
    if (proxy->pool[i]) {
      turbo_stream_close(proxy->pool[i]);
      turbo_stream_destroy(proxy->pool[i]);
      proxy->pool[i] = NULL;
    }
  }
  proxy->pool_count = 0;

  proxy->type = config->type;

  if (config->host) {
    strncpy(proxy->host, config->host, sizeof(proxy->host) - 1);
  }
  proxy->port = config->port;

  if (config->username) {
    strncpy(proxy->username, config->username, sizeof(proxy->username) - 1);
  } else {
    proxy->username[0] = '\0';
  }

  if (config->password) {
    strncpy(proxy->password, config->password, sizeof(proxy->password) - 1);
  } else {
    proxy->password[0] = '\0';
  }

  proxy->use_tls = config->use_tls;
  proxy->tls_verify = config->tls_verify;
  if (config->tls_sni) {
    strncpy(proxy->tls_sni, config->tls_sni, sizeof(proxy->tls_sni) - 1);
  } else {
    proxy->tls_sni[0] = '\0';
  }

  return TUNNEL_OK;
}

/* =============================================================================
 * Proxy Connection Lifecycle
 * ============================================================================= */

static tunnel_proxy_conn_t *proxy_conn_create(tunnel_proxy_t *proxy) {
  tunnel_proxy_conn_t *conn = calloc(1, sizeof(tunnel_proxy_conn_t));
  if (!conn) {
    return NULL;
  }

  conn->proxy = proxy;
  conn->state = TUNNEL_PROXY_STATE_INIT;
  conn->handshake_state = PROXY_HANDSHAKE_INIT;
  return conn;
}

static void proxy_conn_destroy(tunnel_proxy_conn_t *conn) {
  if (!conn) {
    return;
  }

  if (conn->stream) {
    turbo_stream_set_user_data(conn->stream, NULL);
    turbo_stream_destroy(conn->stream);
    conn->stream = NULL;
  }

  free(conn);
}

/* =============================================================================
 * CoroNet Callbacks
 * ============================================================================= */

static void proxy_conn_on_connect(void *handle, int status, void *peer) {
  turbo_stream_t *stream = (turbo_stream_t *)handle;
  tunnel_proxy_conn_t *conn = (tunnel_proxy_conn_t *)turbo_stream_get_user_data(stream);
  (void)peer;

  if (!conn) {
    return;
  }

  if (status != 0) {
    conn->state = TUNNEL_PROXY_STATE_ERROR;
    proxy_conn_notify_connect(conn, TUNNEL_ERR_NETWORK);
    return;
  }

  if (turbo_stream_recv_start(stream, proxy_conn_on_recv) != 0) {
    conn->state = TUNNEL_PROXY_STATE_ERROR;
    proxy_conn_notify_connect(conn, TUNNEL_ERR_NETWORK);
    turbo_stream_close(stream);
    return;
  }

  conn->state = TUNNEL_PROXY_STATE_HANDSHAKING;

  switch (conn->proxy->type) {
  case TUNNEL_PROXY_SOCKS5:
    proxy_conn_send_greeting(conn);
    break;

  case TUNNEL_PROXY_HTTP:
    proxy_conn_send_connect(conn);
    break;

  case TUNNEL_PROXY_NONE:
    conn->state = TUNNEL_PROXY_STATE_ESTABLISHED;
    conn->handshake_state = PROXY_HANDSHAKE_COMPLETE;
    proxy_conn_notify_connect(conn, TUNNEL_OK);
    break;

  default:
    conn->state = TUNNEL_PROXY_STATE_ERROR;
    proxy_conn_notify_connect(conn, TUNNEL_ERR_NOT_SUPPORTED);
    break;
  }
}

static int proxy_conn_on_recv(void *handle, const mem_slice_t *slice, void *peer) {
  tunnel_proxy_conn_t *conn =
      (tunnel_proxy_conn_t *)turbo_stream_get_user_data((turbo_stream_t *)handle);
  (void)peer;

  if (!conn || !slice) {
    return 0;
  }

  if (conn->state == TUNNEL_PROXY_STATE_ESTABLISHED) {
    if (conn->data_cb) {
      conn->data_cb(conn, (const uint8_t *)slice->data, slice->length, conn->user_data);
    }
  } else {
    proxy_conn_process_handshake(conn, (const uint8_t *)slice->data, slice->length);
  }

  return 0;
}

static void proxy_conn_on_close(void *handle) {
  tunnel_proxy_conn_t *conn =
      (tunnel_proxy_conn_t *)turbo_stream_get_user_data((turbo_stream_t *)handle);

  if (!conn) {
    return;
  }

  conn->stream = NULL;

  if (!conn->connect_notified &&
      (conn->state == TUNNEL_PROXY_STATE_CONNECTING ||
       conn->state == TUNNEL_PROXY_STATE_HANDSHAKING ||
       conn->state == TUNNEL_PROXY_STATE_AUTHENTICATING ||
       conn->state == TUNNEL_PROXY_STATE_REQUESTING)) {
    conn->state = TUNNEL_PROXY_STATE_ERROR;
    proxy_conn_notify_connect(conn, TUNNEL_ERR_NETWORK);
    return;
  }

  conn->state = TUNNEL_PROXY_STATE_CLOSED;
  proxy_conn_notify_close(conn);
}

/* =============================================================================
 * SOCKS5 Handshake
 * ============================================================================= */

static void proxy_conn_send_greeting(tunnel_proxy_conn_t *conn) {
  uint8_t buf[4];
  size_t len;

  if (tunnel_socks5_build_greeting(conn, buf, &len) != TUNNEL_OK) {
    conn->state = TUNNEL_PROXY_STATE_ERROR;
    proxy_conn_notify_connect(conn, TUNNEL_ERR_PROXY_CONNECT);
    return;
  }

  if (proxy_conn_stream_send(conn, buf, len) != TUNNEL_OK) {
    conn->state = TUNNEL_PROXY_STATE_ERROR;
    proxy_conn_notify_connect(conn, TUNNEL_ERR_NETWORK);
    return;
  }

  conn->handshake_state = PROXY_HANDSHAKE_GREETING_SENT;
}

static void proxy_conn_send_auth(tunnel_proxy_conn_t *conn) {
  uint8_t buf[515];
  size_t len;

  if (tunnel_socks5_build_auth_request(conn->proxy, buf, &len) != TUNNEL_OK) {
    conn->state = TUNNEL_PROXY_STATE_ERROR;
    proxy_conn_notify_connect(conn, TUNNEL_ERR_PROXY_AUTH);
    return;
  }

  if (proxy_conn_stream_send(conn, buf, len) != TUNNEL_OK) {
    conn->state = TUNNEL_PROXY_STATE_ERROR;
    proxy_conn_notify_connect(conn, TUNNEL_ERR_NETWORK);
    return;
  }

  conn->handshake_state = PROXY_HANDSHAKE_AUTH_SENT;
}

static void proxy_conn_send_connect(tunnel_proxy_conn_t *conn) {
  if (conn->proxy->type == TUNNEL_PROXY_SOCKS5) {
    uint8_t buf[263];
    size_t len;
    int is_ip = 0;
    unsigned int a, b, c, d;

    if (sscanf(conn->target_host, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
      is_ip = 1;
    }

    if (tunnel_socks5_build_connect_request(conn->target_host, conn->target_port, !is_ip, buf,
                                            &len) != TUNNEL_OK) {
      conn->state = TUNNEL_PROXY_STATE_ERROR;
      proxy_conn_notify_connect(conn, TUNNEL_ERR_PROXY_CONNECT);
      return;
    }

    if (proxy_conn_stream_send(conn, buf, len) != TUNNEL_OK) {
      conn->state = TUNNEL_PROXY_STATE_ERROR;
      proxy_conn_notify_connect(conn, TUNNEL_ERR_NETWORK);
      return;
    }

    conn->handshake_state = PROXY_HANDSHAKE_CONNECT_SENT;
  } else if (conn->proxy->type == TUNNEL_PROXY_HTTP) {
    uint8_t buf[2048];
    size_t len;

    if (tunnel_http_build_connect_request(conn->target_host, conn->target_port,
                                          conn->proxy->username, conn->proxy->password, buf, &len,
                                          sizeof(buf)) != TUNNEL_OK) {
      conn->state = TUNNEL_PROXY_STATE_ERROR;
      proxy_conn_notify_connect(conn, TUNNEL_ERR_PROXY_CONNECT);
      return;
    }

    if (proxy_conn_stream_send(conn, buf, len) != TUNNEL_OK) {
      conn->state = TUNNEL_PROXY_STATE_ERROR;
      proxy_conn_notify_connect(conn, TUNNEL_ERR_NETWORK);
      return;
    }

    conn->handshake_state = PROXY_HANDSHAKE_CONNECT_SENT;
  }
}

/* =============================================================================
 * Handshake Response Processing
 * ============================================================================= */

static void proxy_conn_process_handshake(tunnel_proxy_conn_t *conn, const uint8_t *data,
                                         size_t len) {
  if (conn->recv_len + len > sizeof(conn->recv_buf)) {
    conn->state = TUNNEL_PROXY_STATE_ERROR;
    proxy_conn_notify_connect(conn, TUNNEL_ERR_PROXY_CONNECT);
    return;
  }

  memcpy(conn->recv_buf + conn->recv_len, data, len);
  conn->recv_len += len;

  if (conn->proxy->type == TUNNEL_PROXY_SOCKS5) {
    switch (conn->handshake_state) {
    case PROXY_HANDSHAKE_GREETING_SENT: {
      uint8_t method;

      if (conn->recv_len < 2) {
        return;
      }

      if (tunnel_socks5_parse_greeting_response(conn->recv_buf, conn->recv_len, &method) !=
          TUNNEL_OK) {
        conn->state = TUNNEL_PROXY_STATE_ERROR;
        proxy_conn_notify_connect(conn, TUNNEL_ERR_PROXY_CONNECT);
        return;
      }

      conn->recv_len = 0;

      if (method == 0xFF) {
        conn->state = TUNNEL_PROXY_STATE_ERROR;
        proxy_conn_notify_connect(conn, TUNNEL_ERR_PROXY_AUTH);
        return;
      }

      if (method == 0x02) {
        proxy_conn_send_auth(conn);
      } else {
        proxy_conn_send_connect(conn);
      }
      break;
    }

    case PROXY_HANDSHAKE_AUTH_SENT:
      if (conn->recv_len < 2) {
        return;
      }

      if (tunnel_socks5_parse_auth_response(conn->recv_buf, conn->recv_len) != TUNNEL_OK) {
        conn->state = TUNNEL_PROXY_STATE_ERROR;
        proxy_conn_notify_connect(conn, TUNNEL_ERR_PROXY_AUTH);
        return;
      }

      conn->recv_len = 0;
      proxy_conn_send_connect(conn);
      break;

    case PROXY_HANDSHAKE_CONNECT_SENT: {
      uint8_t rep;
      tunnel_endpoint_t bind_addr;

      if (conn->recv_len < 10) {
        return;
      }

      if (tunnel_socks5_parse_connect_response(conn->recv_buf, conn->recv_len, &rep, &bind_addr) !=
          TUNNEL_OK) {
        conn->state = TUNNEL_PROXY_STATE_ERROR;
        proxy_conn_notify_connect(conn, TUNNEL_ERR_PROXY_REFUSED);
        return;
      }

      conn->recv_len = 0;
      conn->state = TUNNEL_PROXY_STATE_ESTABLISHED;
      conn->handshake_state = PROXY_HANDSHAKE_COMPLETE;
      proxy_conn_notify_connect(conn, TUNNEL_OK);
      break;
    }

    default:
      break;
    }
  } else if (conn->proxy->type == TUNNEL_PROXY_HTTP) {
    int ret = tunnel_http_parse_response(conn, conn->recv_buf, conn->recv_len);

    if (ret == TUNNEL_ERR_TIMEOUT) {
      return;
    }

    conn->recv_len = 0;

    if (ret != TUNNEL_OK) {
      conn->state = TUNNEL_PROXY_STATE_ERROR;
      proxy_conn_notify_connect(conn, ret);
      return;
    }

    conn->state = TUNNEL_PROXY_STATE_ESTABLISHED;
    conn->handshake_state = PROXY_HANDSHAKE_COMPLETE;
    proxy_conn_notify_connect(conn, TUNNEL_OK);
  }
}

/* =============================================================================
 * TCP Connection API
 * ============================================================================= */

tunnel_proxy_conn_t *tunnel_proxy_connect_tcp(tunnel_proxy_t *proxy, const char *target_host,
                                              int target_port, tunnel_proxy_connect_cb connect_cb,
                                              tunnel_proxy_data_cb data_cb,
                                              tunnel_proxy_close_cb close_cb, void *user_data) {
  const char *connect_host;
  int connect_port;
  turbo_stream_kind_t kind;

  if (!proxy || !target_host || !proxy->tunnel || !proxy->tunnel->ctx) {
    return NULL;
  }

  tunnel_proxy_conn_t *conn = proxy_conn_create(proxy);
  if (!conn) {
    return NULL;
  }

  strncpy(conn->target_host, target_host, sizeof(conn->target_host) - 1);
  conn->target_port = target_port;
  conn->is_udp = 0;
  conn->connect_cb = connect_cb;
  conn->data_cb = data_cb;
  conn->close_cb = close_cb;
  conn->user_data = user_data;

  if (proxy->type == TUNNEL_PROXY_NONE) {
    connect_host = target_host;
    connect_port = target_port;
    kind = proxy_stream_kind_for_host(target_host, 0);
  } else {
    connect_host = proxy->host;
    connect_port = proxy->port;
    kind = proxy_stream_kind_for_host(proxy->host, proxy->use_tls);
  }

  conn->stream = turbo_stream_create(proxy->tunnel->ctx, kind);
  if (!conn->stream) {
    proxy_conn_destroy(conn);
    return NULL;
  }

  turbo_stream_set_user_data(conn->stream, conn);
  if (kind == TURBO_STREAM_TLS) {
    const char *sni = proxy->tls_sni[0] ? proxy->tls_sni : connect_host;
    turbo_stream_tls_set_sni(conn->stream, sni);
  }

  conn->state = TUNNEL_PROXY_STATE_CONNECTING;
  if (turbo_stream_connect(conn->stream, connect_host, (unsigned short)connect_port,
                           proxy_conn_on_connect, proxy_conn_on_close) != 0) {
    proxy_conn_destroy(conn);
    return NULL;
  }

  return conn;
}

/* =============================================================================
 * UDP Connection API
 * ============================================================================= */

tunnel_proxy_conn_t *tunnel_proxy_connect_udp(tunnel_proxy_t *proxy,
                                              tunnel_proxy_connect_cb connect_cb,
                                              tunnel_proxy_data_cb data_cb,
                                              tunnel_proxy_close_cb close_cb, void *user_data) {
  turbo_stream_kind_t kind;

  if (!proxy || !proxy->tunnel || !proxy->tunnel->ctx) {
    return NULL;
  }

  tunnel_proxy_conn_t *conn = proxy_conn_create(proxy);
  if (!conn) {
    return NULL;
  }

  conn->is_udp = 1;
  conn->connect_cb = connect_cb;
  conn->data_cb = data_cb;
  conn->close_cb = close_cb;
  conn->user_data = user_data;

  if (proxy->type != TUNNEL_PROXY_SOCKS5) {
    conn->state = TUNNEL_PROXY_STATE_CONNECTING;
    return conn;
  }

  kind = proxy_stream_kind_for_host(proxy->host, proxy->use_tls);
  conn->stream = turbo_stream_create(proxy->tunnel->ctx, kind);
  if (!conn->stream) {
    proxy_conn_destroy(conn);
    return NULL;
  }

  turbo_stream_set_user_data(conn->stream, conn);
  if (kind == TURBO_STREAM_TLS) {
    const char *sni = proxy->tls_sni[0] ? proxy->tls_sni : proxy->host;
    turbo_stream_tls_set_sni(conn->stream, sni);
  }

  conn->state = TUNNEL_PROXY_STATE_CONNECTING;
  if (turbo_stream_connect(conn->stream, proxy->host, (unsigned short)proxy->port,
                           proxy_conn_on_connect, proxy_conn_on_close) != 0) {
    proxy_conn_destroy(conn);
    return NULL;
  }

  return conn;
}

/* =============================================================================
 * Data Transfer API
 * ============================================================================= */

int tunnel_proxy_send(tunnel_proxy_conn_t *conn, const uint8_t *data, size_t len) {
  if (!conn || !data || conn->state != TUNNEL_PROXY_STATE_ESTABLISHED) {
    return TUNNEL_ERR_INVALID_ARG;
  }

  return proxy_conn_stream_send(conn, data, len);
}

int tunnel_proxy_send_udp(tunnel_proxy_conn_t *conn, const tunnel_endpoint_t *dst,
                          const uint8_t *data, size_t len) {
  if (!conn || !dst || !data) {
    return TUNNEL_ERR_INVALID_ARG;
  }

  if (conn->proxy->type == TUNNEL_PROXY_SOCKS5) {
    uint8_t buf[65536];
    size_t out_len;
    int ret = tunnel_socks5_wrap_udp(conn, dst, data, len, buf, &out_len);

    if (ret != TUNNEL_OK) {
      return ret;
    }

    return tunnel_proxy_send(conn, buf, out_len);
  }

  return tunnel_proxy_send(conn, data, len);
}

/* =============================================================================
 * Connection Control
 * ============================================================================= */

void tunnel_proxy_conn_close(tunnel_proxy_conn_t *conn) {
  if (!conn) {
    return;
  }

  conn->state = TUNNEL_PROXY_STATE_CLOSED;
  if (conn->stream) {
    turbo_stream_close(conn->stream);
  }
}

void tunnel_proxy_conn_destroy(tunnel_proxy_conn_t *conn) { proxy_conn_destroy(conn); }

tunnel_proxy_state_t tunnel_proxy_conn_get_state(tunnel_proxy_conn_t *conn) {
  return conn ? conn->state : TUNNEL_PROXY_STATE_CLOSED;
}

void *tunnel_proxy_conn_get_user_data(tunnel_proxy_conn_t *conn) {
  return conn ? conn->user_data : NULL;
}

void tunnel_proxy_conn_set_user_data(tunnel_proxy_conn_t *conn, void *user_data) {
  if (conn) {
    conn->user_data = user_data;
  }
}

void tunnel_proxy_conn_set_session(tunnel_proxy_conn_t *conn, void *session) {
  if (conn) {
    conn->session = session;
  }
}

void *tunnel_proxy_conn_get_session(tunnel_proxy_conn_t *conn) {
  return conn ? conn->session : NULL;
}

/* =============================================================================
 * Shadowsocks (Stub)
 * ============================================================================= */

int tunnel_shadowsocks_init_cipher(tunnel_proxy_t *proxy) {
  (void)proxy;
  return TUNNEL_ERR_NOT_SUPPORTED;
}

int tunnel_shadowsocks_encrypt(tunnel_proxy_conn_t *conn, const uint8_t *plain, size_t plain_len,
                               uint8_t *cipher, size_t *cipher_len) {
  (void)conn;
  (void)plain;
  (void)plain_len;
  (void)cipher;
  (void)cipher_len;
  return TUNNEL_ERR_NOT_SUPPORTED;
}

int tunnel_shadowsocks_decrypt(tunnel_proxy_conn_t *conn, const uint8_t *cipher, size_t cipher_len,
                               uint8_t *plain, size_t *plain_len) {
  (void)conn;
  (void)cipher;
  (void)cipher_len;
  (void)plain;
  (void)plain_len;
  return TUNNEL_ERR_NOT_SUPPORTED;
}

int tunnel_shadowsocks_write_header(tunnel_proxy_conn_t *conn, const char *host, int port,
                                    uint8_t *out, size_t *out_len) {
  (void)conn;
  (void)host;
  (void)port;
  (void)out;
  (void)out_len;
  return TUNNEL_ERR_NOT_SUPPORTED;
}

/* =============================================================================
 * VMess (Stub)
 * ============================================================================= */

int tunnel_vmess_handshake(tunnel_proxy_conn_t *conn, const char *host, int port) {
  (void)conn;
  (void)host;
  (void)port;
  return TUNNEL_ERR_NOT_SUPPORTED;
}

int tunnel_vmess_encrypt(tunnel_proxy_conn_t *conn, const uint8_t *plain, size_t plain_len,
                         uint8_t *cipher, size_t *cipher_len) {
  (void)conn;
  (void)plain;
  (void)plain_len;
  (void)cipher;
  (void)cipher_len;
  return TUNNEL_ERR_NOT_SUPPORTED;
}

int tunnel_vmess_decrypt(tunnel_proxy_conn_t *conn, const uint8_t *cipher, size_t cipher_len,
                         uint8_t *plain, size_t *plain_len) {
  (void)conn;
  (void)cipher;
  (void)cipher_len;
  (void)plain;
  (void)plain_len;
  return TUNNEL_ERR_NOT_SUPPORTED;
}

/* =============================================================================
 * Trojan (Stub)
 * ============================================================================= */

int tunnel_trojan_handshake(tunnel_proxy_conn_t *conn, const char *host, int port) {
  (void)conn;
  (void)host;
  (void)port;
  return TUNNEL_ERR_NOT_SUPPORTED;
}
