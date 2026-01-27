/**
 * @file tunnel_session.c
 * @brief Session lifecycle management implementation
 *
 * Manages session lifecycle and integrates with proxy connections
 * using netcore's async_client via the tunnel_proxy abstraction.
 */

#include "tunnel_session.h"
#include "../nat/tunnel_nat.h"
#include "../proxy/tunnel_proxy.h"
#include "../tun/tunnel_tun.h"
#include "../stack/tunnel_ip_stack.h"
#include "../dns/tunnel_fake_dns.h"
#include "../core/tunnel_types.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <tlog.h>

/* =============================================================================
 * Time Utilities
 * ============================================================================= */

static uint64_t get_time_ms(void)
{
#ifdef _WIN32
    return GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}

/* =============================================================================
 * Forward Declarations
 * ============================================================================= */

static void on_proxy_connect(tunnel_proxy_conn_t *conn, int status, void *user_data);
static void on_proxy_data(tunnel_proxy_conn_t *conn, const uint8_t *data, size_t len, void *user_data);
static void on_proxy_close(tunnel_proxy_conn_t *conn, void *user_data);

/* =============================================================================
 * Session Manager (using NAT table)
 * ============================================================================= */

tunnel_nat_t* tunnel_session_manager_create(tunnel_t *tunnel)
{
    return tunnel_nat_create(tunnel);
}

void tunnel_session_manager_destroy(tunnel_nat_t *nat)
{
    tunnel_nat_destroy(nat);
}

/* =============================================================================
 * Session Lifecycle
 * ============================================================================= */

tunnel_session_t* tunnel_session_create(tunnel_t *tunnel, const tunnel_session_key_t *key)
{
    if (!tunnel || !key) return NULL;

    tunnel_session_t *session = calloc(1, sizeof(tunnel_session_t));
    if (!session) return NULL;

    /* Copy key */
    tunnel_session_key_copy(&session->key, key);

    /* Initialize state */
    session->state = TUNNEL_SESSION_INIT;
    session->tunnel = tunnel;

    /* Initialize timing */
    session->create_time = get_time_ms();
    session->last_active = session->create_time;

    /* Initialize TCP state */
    session->tcp.state = TUNNEL_TCP_CLOSED;
    session->tcp.window = 65535;

    /* Allocate buffers */
    session->send_cap = TUNNEL_SESSION_SEND_BUF;
    session->send_buf = malloc(session->send_cap);
    session->recv_cap = TUNNEL_SESSION_RECV_BUF;
    session->recv_buf = malloc(session->recv_cap);

    if (!session->send_buf || !session->recv_buf) {
        free(session->send_buf);
        free(session->recv_buf);
        free(session);
        return NULL;
    }

    session->send_len = 0;
    session->recv_len = 0;

    /* Insert into NAT table */
    if (tunnel->nat) {
        tunnel_nat_insert(tunnel->nat, session);
    }

    return session;
}

tunnel_session_t* tunnel_session_find(tunnel_t *tunnel, const tunnel_session_key_t *key)
{
    if (!tunnel || !tunnel->nat || !key) return NULL;
    return tunnel_nat_lookup(tunnel->nat, key);
}

tunnel_session_t* tunnel_session_find_or_create(tunnel_t *tunnel,
                                                  const tunnel_session_key_t *key,
                                                  int *created)
{
    if (created) *created = 0;

    tunnel_session_t *session = tunnel_session_find(tunnel, key);
    if (session) return session;

    session = tunnel_session_create(tunnel, key);
    if (session && created) {
        *created = 1;
    }

    return session;
}

void tunnel_session_destroy(tunnel_session_t *session)
{
    if (!session) return;

    /* Close and destroy proxy connection */
    if (session->proxy_conn) {
        tunnel_proxy_conn_close(session->proxy_conn);
        tunnel_proxy_conn_destroy(session->proxy_conn);
        session->proxy_conn = NULL;
    }

    /* Remove from NAT table */
    if (session->tunnel && session->tunnel->nat) {
        tunnel_nat_remove(session->tunnel->nat, session);
    }

    /* Free UDP port if allocated */
    if (session->key.protocol == TUNNEL_IPPROTO_UDP && session->udp.local_port) {
        if (session->tunnel && session->tunnel->nat) {
            tunnel_nat_free_udp_port(session->tunnel->nat, session->udp.local_port);
        }
    }

    /* Free buffers */
    free(session->send_buf);
    free(session->recv_buf);

    free(session);
}

void tunnel_session_touch(tunnel_session_t *session)
{
    if (!session) return;
    session->last_active = get_time_ms();

    if (session->tunnel && session->tunnel->nat) {
        tunnel_nat_touch(session->tunnel->nat, session);
    }
}

/* =============================================================================
 * Session State Management
 * ============================================================================= */

void tunnel_session_set_state(tunnel_session_t *session, tunnel_session_state_t state)
{
    if (session) {
        session->state = state;
    }
}

int tunnel_session_is_established(tunnel_session_t *session)
{
    return session && session->state == TUNNEL_SESSION_ESTABLISHED;
}

/* =============================================================================
 * Proxy Callbacks
 * ============================================================================= */

static void on_proxy_connect(tunnel_proxy_conn_t *conn, int status, void *user_data)
{
    tunnel_session_t *session = (tunnel_session_t *)user_data;
    if (!session || !session->tunnel) return;

    tunnel_t *tunnel = session->tunnel;

    if (status != TUNNEL_OK) {
        TLOG_ERROR("Proxy connect failed for session, status={}", status);
        session->state = TUNNEL_SESSION_ERROR;
        session->tcp.state = TUNNEL_TCP_CLOSED;

        /* Send RST to client */
        tunnel_session_send_rst(session);
        return;
    }
    
    TLOG_DEBUG("Proxy connection established for session");
    
    /* Proxy connected - send SYN-ACK to client */
    session->state = TUNNEL_SESSION_ESTABLISHED;
    session->tcp.state = TUNNEL_TCP_ESTABLISHED;

    /* Build and send SYN-ACK */
    tunnel_session_send_synack(session);

    /* Flush any buffered data */
    if (session->send_len > 0) {
        tunnel_proxy_send(session->proxy_conn, session->send_buf, session->send_len);
        session->send_len = 0;
    }
}

static void on_proxy_data(tunnel_proxy_conn_t *conn, const uint8_t *data, size_t len, void *user_data)
{
    tunnel_session_t *session = (tunnel_session_t *)user_data;
    if (!session || !session->tunnel) return;

    (void)conn;

    tunnel_session_touch(session);
    session->bytes_rx += len;

    /* Forward data to TUN as TCP packet */
    tunnel_session_send_to_tun(session, data, len);
}

static void on_proxy_close(tunnel_proxy_conn_t *conn, void *user_data)
{
    tunnel_session_t *session = (tunnel_session_t *)user_data;
    if (!session || !session->tunnel) return;

    (void)conn;

    TLOG_DEBUG("Proxy connection closed");

    /* Send FIN to client */
    if (session->tcp.state == TUNNEL_TCP_ESTABLISHED) {
        session->tcp.state = TUNNEL_TCP_FIN_WAIT_1;
        tunnel_session_send_fin(session);
    }

    session->state = TUNNEL_SESSION_CLOSING;
}

/* =============================================================================
 * TCP Packet Building Helpers
 * ============================================================================= */

int tunnel_session_send_synack(tunnel_session_t *session)
{
    if (!session || !session->tunnel || !session->tunnel->tun) {
        return TUNNEL_ERR_INVALID_ARG;
    }

    uint8_t buf[64];
    int len = tunnel_ip_build_tcp_synack(buf, sizeof(buf),
                                          &session->key.dst, &session->key.src,
                                          session->tcp.seq_local,
                                          session->tcp.seq_remote + 1,
                                          session->tcp.window);
    if (len < 0) return len;

    session->tcp.seq_local++;
    session->tcp.ack_local = session->tcp.seq_remote + 1;

    return tunnel_tun_write(session->tunnel->tun, buf, len);
}

int tunnel_session_send_rst(tunnel_session_t *session)
{
    if (!session || !session->tunnel || !session->tunnel->tun) {
        return TUNNEL_ERR_INVALID_ARG;
    }

    uint8_t buf[64];
    int len = tunnel_ip_build_tcp_rst(buf, sizeof(buf),
                                       &session->key.dst, &session->key.src,
                                       session->tcp.ack_local);
    if (len < 0) return len;

    return tunnel_tun_write(session->tunnel->tun, buf, len);
}

int tunnel_session_send_fin(tunnel_session_t *session)
{
    if (!session || !session->tunnel || !session->tunnel->tun) {
        return TUNNEL_ERR_INVALID_ARG;
    }

    uint8_t buf[64];
    int len = tunnel_ip_build_tcp_fin(buf, sizeof(buf),
                                       &session->key.dst, &session->key.src,
                                       session->tcp.seq_local,
                                       session->tcp.ack_local);
    if (len < 0) return len;

    return tunnel_tun_write(session->tunnel->tun, buf, len);
}

int tunnel_session_send_ack(tunnel_session_t *session)
{
    if (!session || !session->tunnel || !session->tunnel->tun) {
        return TUNNEL_ERR_INVALID_ARG;
    }

    uint8_t buf[64];
    int len = tunnel_ip_build_tcp_ack(buf, sizeof(buf),
                                       &session->key.dst, &session->key.src,
                                       session->tcp.seq_local,
                                       session->tcp.ack_local,
                                       session->tcp.window);
    if (len < 0) return len;

    return tunnel_tun_write(session->tunnel->tun, buf, len);
}

/* =============================================================================
 * TCP State Machine
 * ============================================================================= */

tunnel_session_t* tunnel_session_tcp_syn(tunnel_t *tunnel,
                                          const tunnel_endpoint_t *src,
                                          const tunnel_endpoint_t *dst,
                                          uint32_t seq)
{
    if (!tunnel || !tunnel->proxy) return NULL;

    tunnel_session_key_t key;
    memset(&key, 0, sizeof(key));
    tunnel_endpoint_copy(&key.src, src);
    tunnel_endpoint_copy(&key.dst, dst);
    key.protocol = TUNNEL_IPPROTO_TCP;

    tunnel_session_t *session = tunnel_session_create(tunnel, &key);
    if (!session) return NULL;

    session->state = TUNNEL_SESSION_CONNECTING;
    session->tcp.state = TUNNEL_TCP_SYN_RECEIVED;
    session->tcp.seq_remote = seq;
    session->tcp.seq_local = (uint32_t)rand();  /* Random ISN */

    /* Resolve target host */
    char target_host[256];
    int target_port = dst->port;

    /* Check if destination IP is in fake DNS range */
    if (tunnel->fake_dns && dst->family == AF_INET) {
        const char *domain = tunnel_fake_dns_get_domain(tunnel->fake_dns, dst->addr.v4);
        if (domain) {
            strncpy(target_host, domain, sizeof(target_host) - 1);
            target_host[sizeof(target_host) - 1] = '\0';
            tunnel_session_set_domain(session, domain);
        } else {
            /* Use IP address directly */
            tunnel_endpoint_to_string(dst, target_host, sizeof(target_host));
        }
    } else {
        tunnel_endpoint_to_string(dst, target_host, sizeof(target_host));
    }

    TLOG_DEBUG("TCP SYN: connecting to {}:{} via proxy", target_host, target_port);

    /* Create proxy connection */
    session->proxy_conn = tunnel_proxy_connect_tcp(
        tunnel->proxy,
        target_host,
        target_port,
        on_proxy_connect,
        on_proxy_data,
        on_proxy_close,
        session
    );

    if (!session->proxy_conn) {
        TLOG_ERROR("Failed to create proxy connection");
        tunnel_session_destroy(session);
        return NULL;
    }

    /* Link session to proxy connection */
    tunnel_proxy_conn_set_session(session->proxy_conn, session);

    return session;
}

int tunnel_session_tcp_data(tunnel_session_t *session, uint32_t seq,
                             const uint8_t *data, size_t len)
{
    if (!session || !data) return TUNNEL_ERR_INVALID_ARG;

    /* Update activity */
    tunnel_session_touch(session);

    /* Update traffic counters */
    session->bytes_tx += len;
    session->packets_tx++;

    /* Update TCP sequence tracking */
    session->tcp.seq_remote = seq + (uint32_t)len;
    session->tcp.ack_local = session->tcp.seq_remote;

    /* Forward to proxy if established */
    if (session->state == TUNNEL_SESSION_ESTABLISHED && session->proxy_conn) {
        int ret = tunnel_proxy_send(session->proxy_conn, data, len);

        /* Send ACK to client */
        tunnel_session_send_ack(session);

        return ret;
    }

    /* Buffer data if still connecting */
    if (session->state == TUNNEL_SESSION_CONNECTING) {
        if (session->send_len + len <= session->send_cap) {
            memcpy(session->send_buf + session->send_len, data, len);
            session->send_len += len;
        }
        return TUNNEL_OK;
    }

    return TUNNEL_ERR_INVALID_ARG;
}

int tunnel_session_tcp_ack(tunnel_session_t *session, uint32_t ack, uint16_t window)
{
    if (!session) return TUNNEL_ERR_INVALID_ARG;

    tunnel_session_touch(session);
    session->tcp.ack_remote = ack;
    session->tcp.window = window;

    return TUNNEL_OK;
}

int tunnel_session_tcp_fin(tunnel_session_t *session, uint32_t seq)
{
    if (!session) return TUNNEL_ERR_INVALID_ARG;

    tunnel_session_touch(session);
    (void)seq;

    switch (session->tcp.state) {
        case TUNNEL_TCP_ESTABLISHED:
            session->tcp.state = TUNNEL_TCP_CLOSE_WAIT;
            /* Close proxy connection */
            if (session->proxy_conn) {
                tunnel_proxy_conn_close(session->proxy_conn);
            }
            /* Send ACK for FIN */
            session->tcp.ack_local++;
            tunnel_session_send_ack(session);
            /* Send our FIN */
            session->tcp.state = TUNNEL_TCP_LAST_ACK;
            tunnel_session_send_fin(session);
            break;

        case TUNNEL_TCP_FIN_WAIT_1:
            session->tcp.state = TUNNEL_TCP_CLOSING;
            session->tcp.ack_local++;
            tunnel_session_send_ack(session);
            break;

        case TUNNEL_TCP_FIN_WAIT_2:
            session->tcp.state = TUNNEL_TCP_TIME_WAIT;
            session->tcp.ack_local++;
            tunnel_session_send_ack(session);
            break;

        default:
            break;
    }

    return TUNNEL_OK;
}

int tunnel_session_tcp_rst(tunnel_session_t *session)
{
    if (!session) return TUNNEL_ERR_INVALID_ARG;

    session->tcp.state = TUNNEL_TCP_CLOSED;
    session->state = TUNNEL_SESSION_CLOSED;

    /* Close proxy connection */
    if (session->proxy_conn) {
        tunnel_proxy_conn_close(session->proxy_conn);
    }

    return TUNNEL_OK;
}

tunnel_tcp_state_t tunnel_session_tcp_get_state(tunnel_session_t *session)
{
    return session ? session->tcp.state : TUNNEL_TCP_CLOSED;
}

/* =============================================================================
 * UDP Session Management
 * ============================================================================= */

int tunnel_session_udp_datagram(tunnel_t *tunnel,
                                 const tunnel_endpoint_t *src,
                                 const tunnel_endpoint_t *dst,
                                 const uint8_t *data, size_t len)
{
    if (!tunnel || !src || !dst || !data) return TUNNEL_ERR_INVALID_ARG;

    tunnel_session_key_t key;
    memset(&key, 0, sizeof(key));
    tunnel_endpoint_copy(&key.src, src);
    tunnel_endpoint_copy(&key.dst, dst);
    key.protocol = TUNNEL_IPPROTO_UDP;

    int created = 0;
    tunnel_session_t *session = tunnel_session_find_or_create(tunnel, &key, &created);
    if (!session) return TUNNEL_ERR_NO_MEMORY;

    if (created) {
        /* Allocate local NAT port */
        if (tunnel->nat) {
            session->udp.local_port = tunnel_nat_alloc_udp_port(tunnel->nat);
        }
        session->state = TUNNEL_SESSION_ESTABLISHED;

        /* Create UDP proxy connection if proxy supports it */
        if (tunnel->proxy && tunnel->config.udp_mode != TUNNEL_UDP_DISABLED) {
            session->proxy_conn = tunnel_proxy_connect_udp(
                tunnel->proxy,
                on_proxy_connect,
                on_proxy_data,
                on_proxy_close,
                session
            );
            if (session->proxy_conn) {
                tunnel_proxy_conn_set_session(session->proxy_conn, session);
            }
        }
    }

    tunnel_session_touch(session);
    session->bytes_tx += len;
    session->packets_tx++;

    /* Forward to proxy */
    if (session->proxy_conn) {
        tunnel_endpoint_t target;
        tunnel_endpoint_copy(&target, dst);
        return tunnel_proxy_send_udp(session->proxy_conn, &target, data, len);
    }

    return TUNNEL_OK;
}

/* =============================================================================
 * Session Data Transfer
 * ============================================================================= */

int tunnel_session_send_to_proxy(tunnel_session_t *session,
                                  const uint8_t *data, size_t len)
{
    if (!session || !data) return TUNNEL_ERR_INVALID_ARG;

    /* If proxy connection is established, send directly */
    if (session->state == TUNNEL_SESSION_ESTABLISHED && session->proxy_conn) {
        session->bytes_tx += len;
        session->packets_tx++;
        return tunnel_proxy_send(session->proxy_conn, data, len);
    }

    /* Buffer data for sending later */
    if (session->send_len + len > session->send_cap) {
        return TUNNEL_ERR_NO_MEMORY;
    }

    memcpy(session->send_buf + session->send_len, data, len);
    session->send_len += len;

    return TUNNEL_OK;
}

int tunnel_session_send_to_tun(tunnel_session_t *session,
                                const uint8_t *data, size_t len)
{
    if (!session || !data || !session->tunnel || !session->tunnel->tun) {
        return TUNNEL_ERR_INVALID_ARG;
    }

    uint8_t buf[TUNNEL_SEND_BUF_SIZE];
    int pkt_len;

    if (session->key.protocol == TUNNEL_IPPROTO_TCP) {
        /* Build TCP data packet */
        pkt_len = tunnel_ip_build_tcp_data(buf, sizeof(buf),
                                            &session->key.dst, &session->key.src,
                                            session->tcp.seq_local,
                                            session->tcp.ack_local,
                                            session->tcp.window,
                                            data, len);
        if (pkt_len < 0) return pkt_len;

        /* Update sequence number */
        session->tcp.seq_local += (uint32_t)len;

    } else if (session->key.protocol == TUNNEL_IPPROTO_UDP) {
        /* Build UDP packet */
        pkt_len = tunnel_ip_build_udp(buf, sizeof(buf),
                                       &session->key.dst, &session->key.src,
                                       data, len);
        if (pkt_len < 0) return pkt_len;

    } else {
        return TUNNEL_ERR_NOT_SUPPORTED;
    }

    session->bytes_rx += len;
    session->packets_rx++;

    return tunnel_tun_write(session->tunnel->tun, buf, pkt_len);
}

size_t tunnel_session_flush(tunnel_session_t *session)
{
    if (!session) return 0;

    /* Send buffered data to proxy */
    if (session->send_len > 0 && session->proxy_conn &&
        session->state == TUNNEL_SESSION_ESTABLISHED) {
        tunnel_proxy_send(session->proxy_conn, session->send_buf, session->send_len);
    }

    size_t flushed = session->send_len;
    session->send_len = 0;

    return flushed;
}

/* =============================================================================
 * Session Timeout Management
 * ============================================================================= */

int tunnel_session_expire_check(tunnel_t *tunnel)
{
    if (!tunnel || !tunnel->nat) return 0;

    uint32_t tcp_timeout = tunnel->config.session_timeout * 1000;
    uint32_t udp_timeout = TUNNEL_UDP_TIMEOUT_MS;

    return tunnel_nat_evict_expired(tunnel->nat, tcp_timeout, udp_timeout);
}

void tunnel_session_set_timeout(tunnel_session_t *session, uint32_t timeout_ms)
{
    (void)session;
    (void)timeout_ms;
    /* Session-specific timeouts could be stored in session struct */
}

uint64_t tunnel_session_get_age(tunnel_session_t *session)
{
    if (!session) return 0;
    return get_time_ms() - session->create_time;
}

uint64_t tunnel_session_get_idle(tunnel_session_t *session)
{
    if (!session) return 0;
    return get_time_ms() - session->last_active;
}

/* =============================================================================
 * Session Iteration
 * ============================================================================= */

void tunnel_session_foreach(tunnel_t *tunnel,
                             int (*callback)(tunnel_session_t*, void*),
                             void *user_data)
{
    if (!tunnel || !tunnel->nat || !callback) return;

    tunnel_session_t *session = tunnel->nat->lru_head;
    while (session) {
        tunnel_session_t *next = session->lru_next;
        if (callback(session, user_data) != 0) {
            break;
        }
        session = next;
    }
}

size_t tunnel_session_count(tunnel_t *tunnel)
{
    return (tunnel && tunnel->nat) ? tunnel_nat_session_count(tunnel->nat) : 0;
}

static int count_tcp(tunnel_session_t *session, void *user_data)
{
    if (session->key.protocol == TUNNEL_IPPROTO_TCP) {
        (*(size_t *)user_data)++;
    }
    return 0;
}

static int count_udp(tunnel_session_t *session, void *user_data)
{
    if (session->key.protocol == TUNNEL_IPPROTO_UDP) {
        (*(size_t *)user_data)++;
    }
    return 0;
}

size_t tunnel_session_tcp_count(tunnel_t *tunnel)
{
    size_t count = 0;
    tunnel_session_foreach(tunnel, count_tcp, &count);
    return count;
}

size_t tunnel_session_udp_count(tunnel_t *tunnel)
{
    size_t count = 0;
    tunnel_session_foreach(tunnel, count_udp, &count);
    return count;
}

/* =============================================================================
 * Domain Resolution
 * ============================================================================= */

void tunnel_session_set_domain(tunnel_session_t *session, const char *domain)
{
    if (!session) return;

    if (domain) {
        strncpy(session->domain, domain, TUNNEL_MAX_DOMAIN - 1);
        session->domain[TUNNEL_MAX_DOMAIN - 1] = '\0';
    } else {
        session->domain[0] = '\0';
    }
}

const char* tunnel_session_get_domain(tunnel_session_t *session)
{
    if (!session || session->domain[0] == '\0') return NULL;
    return session->domain;
}
