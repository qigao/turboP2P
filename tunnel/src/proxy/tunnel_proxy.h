/**
 * @file tunnel_proxy.h
 * @brief Proxy client abstraction layer
 *
 * Unified interface for multiple proxy protocols:
 * - SOCKS5 (RFC 1928)
 * - HTTP CONNECT (RFC 7231)
 * - Shadowsocks
 * - VMess (V2Ray)
 * - Trojan
 */

#ifndef TUNNEL_PROXY_H
#define TUNNEL_PROXY_H

#include "core/tunnel_types.h"

/* =============================================================================
 * Proxy Connection State
 * ============================================================================= */

typedef enum {
    TUNNEL_PROXY_STATE_INIT = 0,
    TUNNEL_PROXY_STATE_CONNECTING,      /* TCP connecting */
    TUNNEL_PROXY_STATE_HANDSHAKING,     /* Protocol handshake */
    TUNNEL_PROXY_STATE_AUTHENTICATING,  /* Authentication */
    TUNNEL_PROXY_STATE_REQUESTING,      /* CONNECT request sent */
    TUNNEL_PROXY_STATE_ESTABLISHED,     /* Ready for data */
    TUNNEL_PROXY_STATE_ERROR,
    TUNNEL_PROXY_STATE_CLOSED,
} tunnel_proxy_state_t;

/* =============================================================================
 * Proxy Handshake State Machine
 * ============================================================================= */

typedef enum {
    PROXY_HANDSHAKE_INIT = 0,
    PROXY_HANDSHAKE_GREETING_SENT,      /* SOCKS5: greeting sent */
    PROXY_HANDSHAKE_AUTH_SENT,          /* SOCKS5: auth sent */
    PROXY_HANDSHAKE_CONNECT_SENT,       /* SOCKS5/HTTP: connect request sent */
    PROXY_HANDSHAKE_COMPLETE,           /* Handshake done, tunnel ready */
} proxy_handshake_state_t;

/* =============================================================================
 * Forward Declarations
 * ============================================================================= */

/* Forward declaration for callbacks */
typedef struct tunnel_proxy_conn_s tunnel_proxy_conn_t;

/* =============================================================================
 * Callbacks
 * ============================================================================= */

/**
 * Connection established callback
 * Called when proxy connection is fully established.
 */
typedef void (*tunnel_proxy_connect_cb)(
    tunnel_proxy_conn_t *conn,
    int status,                     /* TUNNEL_OK or error code */
    void *user_data
);

/**
 * Data received callback
 * Called when data is received from the proxy.
 */
typedef void (*tunnel_proxy_data_cb)(
    tunnel_proxy_conn_t *conn,
    const uint8_t *data,
    size_t len,
    void *user_data
);

/**
 * Connection closed callback
 */
typedef void (*tunnel_proxy_close_cb)(
    tunnel_proxy_conn_t *conn,
    void *user_data
);

/* =============================================================================
 * Proxy Connection Structure
 * ============================================================================= */

struct tunnel_proxy_conn_s {
    tunnel_proxy_t *proxy;
    tunnel_proxy_state_t state;
    proxy_handshake_state_t handshake_state;

    /* Target endpoint */
    char target_host[256];
    int target_port;
    int is_udp;

    /* Underlying CoroNet stream */
    turbo_stream_t *stream;

    /* Callbacks */
    tunnel_proxy_connect_cb connect_cb;
    tunnel_proxy_data_cb data_cb;
    tunnel_proxy_close_cb close_cb;
    void *user_data;

    /* Receive buffer for handshake */
    uint8_t recv_buf[4096];
    size_t recv_len;

    /* UDP association info */
    tunnel_endpoint_t udp_relay;

    /* Back-reference to session (if any) */
    void *session;

    /* Callback guards */
    int connect_notified;
    int close_notified;
};

/* =============================================================================
 * Proxy Client API
 * ============================================================================= */

/**
 * Create proxy client
 * @param tunnel Parent tunnel handle
 * @param config Proxy configuration
 * @return Proxy handle or NULL on error
 */
TUNNEL_INTERNAL tunnel_proxy_t* tunnel_proxy_create(
    tunnel_t *tunnel,
    const tunnel_proxy_config_t *config
);

/**
 * Destroy proxy client
 * Closes all connections.
 * @param proxy Proxy handle
 */
TUNNEL_INTERNAL void tunnel_proxy_destroy(tunnel_proxy_t *proxy);

/**
 * Update proxy configuration
 * @param proxy Proxy handle
 * @param config New configuration
 * @return TUNNEL_OK on success
 */
TUNNEL_INTERNAL int tunnel_proxy_set_config(
    tunnel_proxy_t *proxy,
    const tunnel_proxy_config_t *config
);

/* =============================================================================
 * Proxy Connection API
 * ============================================================================= */

/**
 * Create TCP connection through proxy
 *
 * This initiates a full proxy handshake:
 * 1. TCP connect to proxy server
 * 2. Protocol handshake (SOCKS5/HTTP/etc.)
 * 3. Authentication if required
 * 4. CONNECT request to target
 * 5. Call connect_cb when established
 *
 * @param proxy Proxy handle
 * @param target_host Target hostname or IP
 * @param target_port Target port
 * @param connect_cb Connection established callback
 * @param data_cb Data received callback
 * @param close_cb Connection closed callback
 * @param user_data User context for callbacks
 * @return Connection handle or NULL on error
 */
TUNNEL_INTERNAL tunnel_proxy_conn_t* tunnel_proxy_connect_tcp(
    tunnel_proxy_t *proxy,
    const char *target_host,
    int target_port,
    tunnel_proxy_connect_cb connect_cb,
    tunnel_proxy_data_cb data_cb,
    tunnel_proxy_close_cb close_cb,
    void *user_data
);

/**
 * Create UDP association through proxy
 *
 * For SOCKS5: Uses UDP ASSOCIATE
 * For others: Encapsulates UDP in TCP
 *
 * @param proxy Proxy handle
 * @param connect_cb Connection established callback
 * @param data_cb Data received callback
 * @param close_cb Connection closed callback
 * @param user_data User context for callbacks
 * @return Connection handle or NULL on error
 */
TUNNEL_INTERNAL tunnel_proxy_conn_t* tunnel_proxy_connect_udp(
    tunnel_proxy_t *proxy,
    tunnel_proxy_connect_cb connect_cb,
    tunnel_proxy_data_cb data_cb,
    tunnel_proxy_close_cb close_cb,
    void *user_data
);

/**
 * Send data through proxy connection
 * @param conn Connection handle
 * @param data Data to send
 * @param len Data length
 * @return TUNNEL_OK on success
 */
TUNNEL_INTERNAL int tunnel_proxy_send(
    tunnel_proxy_conn_t *conn,
    const uint8_t *data,
    size_t len
);

/**
 * Send UDP datagram through proxy
 * For UDP connections, includes destination address.
 * @param conn Connection handle
 * @param dst Destination endpoint
 * @param data Datagram data
 * @param len Datagram length
 * @return TUNNEL_OK on success
 */
TUNNEL_INTERNAL int tunnel_proxy_send_udp(
    tunnel_proxy_conn_t *conn,
    const tunnel_endpoint_t *dst,
    const uint8_t *data,
    size_t len
);

/**
 * Close proxy connection
 * @param conn Connection handle
 */
TUNNEL_INTERNAL void tunnel_proxy_conn_close(tunnel_proxy_conn_t *conn);

/**
 * Get connection state
 * @param conn Connection handle
 * @return Current state
 */
TUNNEL_INTERNAL tunnel_proxy_state_t tunnel_proxy_conn_get_state(
    tunnel_proxy_conn_t *conn
);

/**
 * Get connection's user data
 * @param conn Connection handle
 * @return User data pointer
 */
TUNNEL_INTERNAL void* tunnel_proxy_conn_get_user_data(tunnel_proxy_conn_t *conn);

/**
 * Set connection's user data
 * @param conn Connection handle
 * @param user_data User data pointer
 */
TUNNEL_INTERNAL void tunnel_proxy_conn_set_user_data(
    tunnel_proxy_conn_t *conn,
    void *user_data
);

/**
 * Destroy proxy connection
 * Frees all resources associated with the connection.
 * @param conn Connection handle
 */
TUNNEL_INTERNAL void tunnel_proxy_conn_destroy(tunnel_proxy_conn_t *conn);

/**
 * Set session reference for proxy connection
 * Used to link proxy connection back to its owning session.
 * @param conn Connection handle
 * @param session Session pointer
 */
TUNNEL_INTERNAL void tunnel_proxy_conn_set_session(
    tunnel_proxy_conn_t *conn,
    void *session
);

/**
 * Get session reference from proxy connection
 * @param conn Connection handle
 * @return Session pointer or NULL
 */
TUNNEL_INTERNAL void* tunnel_proxy_conn_get_session(tunnel_proxy_conn_t *conn);

/* =============================================================================
 * Protocol-Specific Implementations
 * ============================================================================= */

/* SOCKS5 handshake building */
TUNNEL_INTERNAL int tunnel_socks5_build_greeting(tunnel_proxy_conn_t *conn,
                                                   uint8_t *buf, size_t *len);
TUNNEL_INTERNAL int tunnel_socks5_build_auth_request(tunnel_proxy_t *proxy,
                                                       uint8_t *buf, size_t *len);
TUNNEL_INTERNAL int tunnel_socks5_build_connect_request(const char *host, int port,
                                                          int is_domain,
                                                          uint8_t *buf, size_t *len);

/* SOCKS5 response parsing */
TUNNEL_INTERNAL int tunnel_socks5_parse_greeting_response(const uint8_t *data, size_t len,
                                                            uint8_t *method);
TUNNEL_INTERNAL int tunnel_socks5_parse_auth_response(const uint8_t *data, size_t len);
TUNNEL_INTERNAL int tunnel_socks5_parse_connect_response(const uint8_t *data, size_t len,
                                                           uint8_t *rep,
                                                           tunnel_endpoint_t *bind_addr);

/* SOCKS5 */
TUNNEL_INTERNAL int tunnel_socks5_handshake(tunnel_proxy_conn_t *conn);
TUNNEL_INTERNAL int tunnel_socks5_authenticate(tunnel_proxy_conn_t *conn);
TUNNEL_INTERNAL int tunnel_socks5_connect(tunnel_proxy_conn_t *conn,
                                           const char *host, int port);
TUNNEL_INTERNAL int tunnel_socks5_udp_associate(tunnel_proxy_conn_t *conn);
TUNNEL_INTERNAL int tunnel_socks5_wrap_udp(tunnel_proxy_conn_t *conn,
                                            const tunnel_endpoint_t *dst,
                                            const uint8_t *data, size_t len,
                                            uint8_t *out, size_t *out_len);

/* HTTP CONNECT */
TUNNEL_INTERNAL int tunnel_http_build_connect_request(const char *host, int port,
                                                        const char *username,
                                                        const char *password,
                                                        uint8_t *buf, size_t *len,
                                                        size_t buf_size);
TUNNEL_INTERNAL int tunnel_http_connect(tunnel_proxy_conn_t *conn,
                                         const char *host, int port);
TUNNEL_INTERNAL int tunnel_http_parse_response(tunnel_proxy_conn_t *conn,
                                                const uint8_t *data, size_t len);

/* Shadowsocks */
TUNNEL_INTERNAL int tunnel_shadowsocks_init_cipher(tunnel_proxy_t *proxy);
TUNNEL_INTERNAL int tunnel_shadowsocks_encrypt(tunnel_proxy_conn_t *conn,
                                                const uint8_t *plain, size_t plain_len,
                                                uint8_t *cipher, size_t *cipher_len);
TUNNEL_INTERNAL int tunnel_shadowsocks_decrypt(tunnel_proxy_conn_t *conn,
                                                const uint8_t *cipher, size_t cipher_len,
                                                uint8_t *plain, size_t *plain_len);
TUNNEL_INTERNAL int tunnel_shadowsocks_write_header(tunnel_proxy_conn_t *conn,
                                                     const char *host, int port,
                                                     uint8_t *out, size_t *out_len);

/* VMess */
TUNNEL_INTERNAL int tunnel_vmess_handshake(tunnel_proxy_conn_t *conn,
                                            const char *host, int port);
TUNNEL_INTERNAL int tunnel_vmess_encrypt(tunnel_proxy_conn_t *conn,
                                          const uint8_t *plain, size_t plain_len,
                                          uint8_t *cipher, size_t *cipher_len);
TUNNEL_INTERNAL int tunnel_vmess_decrypt(tunnel_proxy_conn_t *conn,
                                          const uint8_t *cipher, size_t cipher_len,
                                          uint8_t *plain, size_t *plain_len);

/* Trojan */
TUNNEL_INTERNAL int tunnel_trojan_handshake(tunnel_proxy_conn_t *conn,
                                             const char *host, int port);

#endif /* TUNNEL_PROXY_H */
