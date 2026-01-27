/**
 * @file tunnel_proxy.c
 * @brief Proxy client implementation using netcore
 *
 * Uses netcore's async_client for proxy connections (SOCKS5, HTTP CONNECT, etc.)
 */
#if defined(_MSC_VER) && !defined(__clang__)
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#endif
#include "tunnel_proxy.h"
#include "../core/tunnel_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <turbo_async_client.h>


/* =============================================================================
 * Forward Declarations
 * ============================================================================= */

static void proxy_conn_on_event(async_client_t *client, const async_client_event_t *event,
                                void *user_data);
static void proxy_conn_process_handshake(tunnel_proxy_conn_t *conn, const uint8_t *data,
                                         size_t len);
static void proxy_conn_send_greeting(tunnel_proxy_conn_t *conn);
static void proxy_conn_send_auth(tunnel_proxy_conn_t *conn);
static void proxy_conn_send_connect(tunnel_proxy_conn_t *conn);

/* =============================================================================
 * Proxy Client Lifecycle
 * ============================================================================= */

tunnel_proxy_t *tunnel_proxy_create(tunnel_t *tunnel, const tunnel_proxy_config_t *config) {
  if (!tunnel || !config)
    return NULL;

  tunnel_proxy_t *proxy = calloc(1, sizeof(tunnel_proxy_t));
  if (!proxy)
    return NULL;

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

  /* Copy protocol-specific settings */
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
  if (!proxy)
    return;

  /* Close any pooled connections */
  for (int i = 0; i < proxy->pool_count; i++) {
    if (proxy->pool[i]) {
      async_client_close(proxy->pool[i]);
      async_client_destroy(proxy->pool[i]);
      proxy->pool[i] = NULL;
    }
  }

  free(proxy);
}

int tunnel_proxy_set_config(tunnel_proxy_t *proxy, const tunnel_proxy_config_t *config) {
  if (!proxy || !config)
    return TUNNEL_ERR_INVALID_ARG;

  /* Close existing connections */
  for (int i = 0; i < proxy->pool_count; i++) {
    if (proxy->pool[i]) {
      async_client_close(proxy->pool[i]);
      async_client_destroy(proxy->pool[i]);
      proxy->pool[i] = NULL;
    }
  }
  proxy->pool_count = 0;

  /* Update configuration */
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

  return TUNNEL_OK;
}

/* =============================================================================
 * Proxy Connection Lifecycle
 * ============================================================================= */

static tunnel_proxy_conn_t *proxy_conn_create(tunnel_proxy_t *proxy) {
  tunnel_proxy_conn_t *conn = calloc(1, sizeof(tunnel_proxy_conn_t));
  if (!conn)
    return NULL;

  conn->proxy = proxy;
  conn->state = TUNNEL_PROXY_STATE_INIT;
  conn->handshake_state = PROXY_HANDSHAKE_INIT;

  return conn;
}

static void proxy_conn_destroy(tunnel_proxy_conn_t *conn) {
  if (!conn)
    return;

  if (conn->client) {
    async_client_close(conn->client);
    async_client_destroy(conn->client);
    conn->client = NULL;
  }

  free(conn);
}

/* =============================================================================
 * Netcore Event Callback
 * ============================================================================= */

static void proxy_conn_on_event(async_client_t *client, const async_client_event_t *event,
                                void *user_data) {
  tunnel_proxy_conn_t *conn = (tunnel_proxy_conn_t *)user_data;
  (void)client;

  switch (event->type) {
  case ASYNC_CLIENT_EVENT_CONNECTED:
    conn->state = TUNNEL_PROXY_STATE_HANDSHAKING;

    /* Start protocol handshake */
    switch (conn->proxy->type) {
    case TUNNEL_PROXY_SOCKS5:
      proxy_conn_send_greeting(conn);
      break;

    case TUNNEL_PROXY_HTTP:
      proxy_conn_send_connect(conn);
      break;

    case TUNNEL_PROXY_NONE:
      /* Direct connection, already done */
      conn->state = TUNNEL_PROXY_STATE_ESTABLISHED;
      conn->handshake_state = PROXY_HANDSHAKE_COMPLETE;
      if (conn->connect_cb) {
        conn->connect_cb(conn, TUNNEL_OK, conn->user_data);
      }
      break;

    default:
      conn->state = TUNNEL_PROXY_STATE_ERROR;
      if (conn->connect_cb) {
        conn->connect_cb(conn, TUNNEL_ERR_NOT_SUPPORTED, conn->user_data);
      }
      break;
    }
    break;

  case ASYNC_CLIENT_EVENT_DATA:
    if (conn->state == TUNNEL_PROXY_STATE_ESTABLISHED) {
      /* Tunnel established, forward data to application */
      if (conn->data_cb) {
        const uint8_t *data =
            event->slice ? (const uint8_t *)event->slice->data : (const uint8_t *)event->data;
        size_t len = event->slice ? event->slice->length : event->length;
        conn->data_cb(conn, data, len, conn->user_data);
      }
    } else {
      /* Still handshaking, process protocol response */
      const uint8_t *data =
          event->slice ? (const uint8_t *)event->slice->data : (const uint8_t *)event->data;
      size_t len = event->slice ? event->slice->length : event->length;
      proxy_conn_process_handshake(conn, data, len);
    }
    break;

  case ASYNC_CLIENT_EVENT_CLOSED:
    conn->state = TUNNEL_PROXY_STATE_CLOSED;
    if (conn->close_cb) {
      conn->close_cb(conn, conn->user_data);
    }
    break;

  case ASYNC_CLIENT_EVENT_ERROR:
    conn->state = TUNNEL_PROXY_STATE_ERROR;
    if (conn->state == TUNNEL_PROXY_STATE_CONNECTING ||
        conn->state == TUNNEL_PROXY_STATE_HANDSHAKING) {
      if (conn->connect_cb) {
        conn->connect_cb(conn, TUNNEL_ERR_NETWORK, conn->user_data);
      }
    } else {
      if (conn->close_cb) {
        conn->close_cb(conn, conn->user_data);
      }
    }
    break;
  }
}

/* =============================================================================
 * SOCKS5 Handshake
 * ============================================================================= */

static void proxy_conn_send_greeting(tunnel_proxy_conn_t *conn) {
  uint8_t buf[4];
  size_t len;

  if (tunnel_socks5_build_greeting(conn, buf, &len) != TUNNEL_OK) {
    conn->state = TUNNEL_PROXY_STATE_ERROR;
    if (conn->connect_cb) {
      conn->connect_cb(conn, TUNNEL_ERR_PROXY_CONNECT, conn->user_data);
    }
    return;
  }

  async_client_send(conn->client, (const char *)buf, len);
  conn->handshake_state = PROXY_HANDSHAKE_GREETING_SENT;
}

static void proxy_conn_send_auth(tunnel_proxy_conn_t *conn) {
  uint8_t buf[515];
  size_t len;

  if (tunnel_socks5_build_auth_request(conn->proxy, buf, &len) != TUNNEL_OK) {
    conn->state = TUNNEL_PROXY_STATE_ERROR;
    if (conn->connect_cb) {
      conn->connect_cb(conn, TUNNEL_ERR_PROXY_AUTH, conn->user_data);
    }
    return;
  }

  async_client_send(conn->client, (const char *)buf, len);
  conn->handshake_state = PROXY_HANDSHAKE_AUTH_SENT;
}

static void proxy_conn_send_connect(tunnel_proxy_conn_t *conn) {
  if (conn->proxy->type == TUNNEL_PROXY_SOCKS5) {
    /* SOCKS5 connect request */
    uint8_t buf[263];
    size_t len;

    /* Determine if host is IP or domain */
    int is_ip = 0;
    unsigned int a, b, c, d;
    if (sscanf(conn->target_host, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
      is_ip = 1;
    }

    if (tunnel_socks5_build_connect_request(conn->target_host, conn->target_port, !is_ip, buf,
                                            &len) != TUNNEL_OK) {
      conn->state = TUNNEL_PROXY_STATE_ERROR;
      if (conn->connect_cb) {
        conn->connect_cb(conn, TUNNEL_ERR_PROXY_CONNECT, conn->user_data);
      }
      return;
    }

    async_client_send(conn->client, (const char *)buf, len);
    conn->handshake_state = PROXY_HANDSHAKE_CONNECT_SENT;

  } else if (conn->proxy->type == TUNNEL_PROXY_HTTP) {
    /* HTTP CONNECT request */
    uint8_t buf[2048];
    size_t len;

    if (tunnel_http_build_connect_request(conn->target_host, conn->target_port,
                                          conn->proxy->username, conn->proxy->password, buf, &len,
                                          sizeof(buf)) != TUNNEL_OK) {
      conn->state = TUNNEL_PROXY_STATE_ERROR;
      if (conn->connect_cb) {
        conn->connect_cb(conn, TUNNEL_ERR_PROXY_CONNECT, conn->user_data);
      }
      return;
    }

    async_client_send(conn->client, (const char *)buf, len);
    conn->handshake_state = PROXY_HANDSHAKE_CONNECT_SENT;
  }
}

/* =============================================================================
 * Handshake Response Processing
 * ============================================================================= */

static void proxy_conn_process_handshake(tunnel_proxy_conn_t *conn, const uint8_t *data,
                                         size_t len) {
  /* Buffer incoming data */
  if (conn->recv_len + len <= sizeof(conn->recv_buf)) {
    memcpy(conn->recv_buf + conn->recv_len, data, len);
    conn->recv_len += len;
  } else {
    /* Buffer overflow */
    conn->state = TUNNEL_PROXY_STATE_ERROR;
    if (conn->connect_cb) {
      conn->connect_cb(conn, TUNNEL_ERR_PROXY_CONNECT, conn->user_data);
    }
    return;
  }

  if (conn->proxy->type == TUNNEL_PROXY_SOCKS5) {
    switch (conn->handshake_state) {
    case PROXY_HANDSHAKE_GREETING_SENT: {
      /* Expecting method selection response (2 bytes) */
      if (conn->recv_len < 2)
        return; /* Need more data */

      uint8_t method;
      int ret = tunnel_socks5_parse_greeting_response(conn->recv_buf, conn->recv_len, &method);
      if (ret != TUNNEL_OK) {
        conn->state = TUNNEL_PROXY_STATE_ERROR;
        if (conn->connect_cb) {
          conn->connect_cb(conn, TUNNEL_ERR_PROXY_CONNECT, conn->user_data);
        }
        return;
      }

      conn->recv_len = 0; /* Clear buffer */

      if (method == 0xFF) {
        /* No acceptable method */
        conn->state = TUNNEL_PROXY_STATE_ERROR;
        if (conn->connect_cb) {
          conn->connect_cb(conn, TUNNEL_ERR_PROXY_AUTH, conn->user_data);
        }
        return;
      }

      if (method == 0x02) {
        /* Username/password auth required */
        proxy_conn_send_auth(conn);
      } else {
        /* No auth, proceed to connect */
        proxy_conn_send_connect(conn);
      }
      break;
    }

    case PROXY_HANDSHAKE_AUTH_SENT: {
      /* Expecting auth response (2 bytes) */
      if (conn->recv_len < 2)
        return;

      int ret = tunnel_socks5_parse_auth_response(conn->recv_buf, conn->recv_len);
      if (ret != TUNNEL_OK) {
        conn->state = TUNNEL_PROXY_STATE_ERROR;
        if (conn->connect_cb) {
          conn->connect_cb(conn, TUNNEL_ERR_PROXY_AUTH, conn->user_data);
        }
        return;
      }

      conn->recv_len = 0;
      proxy_conn_send_connect(conn);
      break;
    }

    case PROXY_HANDSHAKE_CONNECT_SENT: {
      /* Expecting connect response (at least 10 bytes) */
      if (conn->recv_len < 10)
        return;

      uint8_t rep;
      tunnel_endpoint_t bind_addr;
      int ret =
          tunnel_socks5_parse_connect_response(conn->recv_buf, conn->recv_len, &rep, &bind_addr);
      if (ret != TUNNEL_OK) {
        conn->state = TUNNEL_PROXY_STATE_ERROR;
        if (conn->connect_cb) {
          conn->connect_cb(conn, TUNNEL_ERR_PROXY_REFUSED, conn->user_data);
        }
        return;
      }

      conn->recv_len = 0;
      conn->state = TUNNEL_PROXY_STATE_ESTABLISHED;
      conn->handshake_state = PROXY_HANDSHAKE_COMPLETE;

      if (conn->connect_cb) {
        conn->connect_cb(conn, TUNNEL_OK, conn->user_data);
      }
      break;
    }

    default:
      break;
    }

  } else if (conn->proxy->type == TUNNEL_PROXY_HTTP) {
    /* HTTP: Look for end of headers */
    int ret = tunnel_http_parse_response(conn, conn->recv_buf, conn->recv_len);

    if (ret == TUNNEL_ERR_TIMEOUT) {
      /* Incomplete, need more data */
      return;
    }

    conn->recv_len = 0;

    if (ret != TUNNEL_OK) {
      conn->state = TUNNEL_PROXY_STATE_ERROR;
      if (conn->connect_cb) {
        conn->connect_cb(conn, ret, conn->user_data);
      }
      return;
    }

    conn->state = TUNNEL_PROXY_STATE_ESTABLISHED;
    conn->handshake_state = PROXY_HANDSHAKE_COMPLETE;

    if (conn->connect_cb) {
      conn->connect_cb(conn, TUNNEL_OK, conn->user_data);
    }
  }
}

/* =============================================================================
 * TCP Connection API
 * ============================================================================= */

tunnel_proxy_conn_t *tunnel_proxy_connect_tcp(tunnel_proxy_t *proxy, const char *target_host,
                                              int target_port, tunnel_proxy_connect_cb connect_cb,
                                              tunnel_proxy_data_cb data_cb,
                                              tunnel_proxy_close_cb close_cb, void *user_data) {
  if (!proxy || !target_host)
    return NULL;

  tunnel_proxy_conn_t *conn = proxy_conn_create(proxy);
  if (!conn)
    return NULL;

  /* Store target */
  strncpy(conn->target_host, target_host, sizeof(conn->target_host) - 1);
  conn->target_port = target_port;
  conn->is_udp = 0;

  /* Store callbacks */
  conn->connect_cb = connect_cb;
  conn->data_cb = data_cb;
  conn->close_cb = close_cb;
  conn->user_data = user_data;

  /* Determine connection target and transport */
  const char *connect_host;
  int connect_port;

  if (proxy->type == TUNNEL_PROXY_NONE) {
    /* Direct connection */
    connect_host = target_host;
    connect_port = target_port;
  } else {
    /* Connect to proxy server */
    connect_host = proxy->host;
    connect_port = proxy->port;
  }
  /* Create netcore async client */
  conn->client = async_client_create(proxy_conn_on_event, conn);
  if (!conn->client) {
    proxy_conn_destroy(conn);
    return NULL;
  }

  /* Set connection timeout */
  async_client_set_connect_timeout(conn->client, 30000); /* 30 seconds */

  /* Start connection */
  conn->state = TUNNEL_PROXY_STATE_CONNECTING;
  
  char connect_url[256];
  const char *scheme = proxy->use_tls ? "tls" : "tcp";
  snprintf(connect_url, sizeof(connect_url), "%s://%s:%d", scheme, connect_host, connect_port);

  async_client_status_t status = async_client_connect(conn->client, connect_url);

  if (status != ASYNC_CLIENT_STATUS_OK) {
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
  if (!proxy)
    return NULL;

  tunnel_proxy_conn_t *conn = proxy_conn_create(proxy);
  if (!conn)
    return NULL;

  conn->is_udp = 1;

  /* Store callbacks */
  conn->connect_cb = connect_cb;
  conn->data_cb = data_cb;
  conn->close_cb = close_cb;
  conn->user_data = user_data;

  /* For SOCKS5, establish TCP connection for UDP ASSOCIATE */
  /* For SOCKS5, establish TCP connection for UDP ASSOCIATE */
  if (proxy->type == TUNNEL_PROXY_SOCKS5) {
    conn->client = async_client_create(proxy_conn_on_event, conn);
    if (!conn->client) {
      proxy_conn_destroy(conn);
      return NULL;
    }

    conn->state = TUNNEL_PROXY_STATE_CONNECTING;
    
    char connect_url[256];
    const char *scheme = proxy->use_tls ? "tls" : "tcp";
    snprintf(connect_url, sizeof(connect_url), "%s://%s:%d", scheme, proxy->host, proxy->port);
    
    async_client_status_t status = async_client_connect(conn->client, connect_url);

    if (status != ASYNC_CLIENT_STATUS_OK) {
      proxy_conn_destroy(conn);
      return NULL;
    }
  } else {
    /* For other protocols, UDP is typically encapsulated in TCP */
    conn->state = TUNNEL_PROXY_STATE_CONNECTING;
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

  async_client_status_t status = async_client_send(conn->client, (const char *)data, len);
  return (status == ASYNC_CLIENT_STATUS_OK) ? TUNNEL_OK : TUNNEL_ERR_NETWORK;
}

int tunnel_proxy_send_udp(tunnel_proxy_conn_t *conn, const tunnel_endpoint_t *dst,
                          const uint8_t *data, size_t len) {
  if (!conn || !dst || !data)
    return TUNNEL_ERR_INVALID_ARG;

  if (conn->proxy->type == TUNNEL_PROXY_SOCKS5) {
    /* Wrap in SOCKS5 UDP header */
    uint8_t buf[65536];
    size_t out_len;

    int ret = tunnel_socks5_wrap_udp(conn, dst, data, len, buf, &out_len);
    if (ret != TUNNEL_OK) {
      return ret;
    }

    /* Send via UDP socket to relay address */
    /* TODO: Create UDP socket to relay address */
    return TUNNEL_ERR_NOT_SUPPORTED;
  } else {
    /* Other protocols: send as-is or encapsulate */
    return tunnel_proxy_send(conn, data, len);
  }
}

/* =============================================================================
 * Connection Control
 * ============================================================================= */

void tunnel_proxy_conn_close(tunnel_proxy_conn_t *conn) {
  if (!conn)
    return;

  conn->state = TUNNEL_PROXY_STATE_CLOSED;

  if (conn->client) {
    async_client_close(conn->client);
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
