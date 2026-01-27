/**
 * @file tunnel.c
 * @brief Core tunnel implementation
 */

#include "turbo_tunnel.h"
#include "tunnel_types.h"
#include "../tun/tunnel_tun.h"
#include "../proxy/tunnel_proxy.h"
#include "../session/tunnel_session.h"
#include "../nat/tunnel_nat.h"
#include "../stack/tunnel_ip_stack.h"
#include "../dns/tunnel_fake_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stb_sprintf.h>
#include <tlog.h>

/* =============================================================================
 * Version
 * ============================================================================= */

#define TUNNEL_VERSION_MAJOR 1
#define TUNNEL_VERSION_MINOR 0
#define TUNNEL_VERSION_PATCH 0

static const char TUNNEL_VERSION_STRING[] = "1.0.0";

/* =============================================================================
 * Global State
 * ============================================================================= */

static int g_initialized = 0;

/* =============================================================================
 * Library Lifecycle
 * ============================================================================= */

int tunnel_init(void)
{
    if (g_initialized) {
        return TUNNEL_OK;
    }

    g_initialized = 1;
    return TUNNEL_OK;
}

void tunnel_shutdown(void)
{
    g_initialized = 0;
}

/* =============================================================================
 * Tunnel Lifecycle
 * ============================================================================= */

tunnel_t* tunnel_create(const tunnel_config_t *config)
{
    if (!config) return NULL;

    tunnel_t *tunnel = calloc(1, sizeof(tunnel_t));
    if (!tunnel) return NULL;

    /* Copy configuration */
    memcpy(&tunnel->config, config, sizeof(tunnel_config_t));

    /* Create event loop */
    tunnel->loop = calloc(1, sizeof(uv_loop_t));
    if (!tunnel->loop) {
        free(tunnel);
        return NULL;
    }

    if (uv_loop_init(tunnel->loop) != 0) {
        free(tunnel->loop);
        free(tunnel);
        return NULL;
    }
    tunnel->owns_loop = 1;

    /* Initialize mutex */
    if (uv_mutex_init(&tunnel->mutex) != 0) {
        uv_loop_close(tunnel->loop);
        free(tunnel->loop);
        free(tunnel);
        return NULL;
    }

    /* Create TUN device */
    tunnel->tun = tunnel_tun_create(tunnel, &config->tun);
    if (!tunnel->tun) {
        uv_mutex_destroy(&tunnel->mutex);
        uv_loop_close(tunnel->loop);
        free(tunnel->loop);
        free(tunnel);
        return NULL;
    }

    /* Create NAT table */
    tunnel->nat = tunnel_nat_create(tunnel);
    if (!tunnel->nat) {
        tunnel_tun_destroy(tunnel->tun);
        uv_mutex_destroy(&tunnel->mutex);
        uv_loop_close(tunnel->loop);
        free(tunnel->loop);
        free(tunnel);
        return NULL;
    }

    /* Create proxy client */
    tunnel->proxy = tunnel_proxy_create(tunnel, &config->proxy);
    if (!tunnel->proxy) {
        tunnel_nat_destroy(tunnel->nat);
        tunnel_tun_destroy(tunnel->tun);
        uv_mutex_destroy(&tunnel->mutex);
        uv_loop_close(tunnel->loop);
        free(tunnel->loop);
        free(tunnel);
        return NULL;
    }

    /* Create Fake DNS if enabled */
    if (config->dns.fake_dns) {
        uint32_t base_ip = htonl(0xC6120000);  /* 198.18.0.0 */
        uint32_t mask = htonl(0xFFFE0000);     /* /15 */
        tunnel->fake_dns = tunnel_fake_dns_create(tunnel, base_ip, mask, 600);
    }

    /* Set default log level */
    if (tunnel->config.log_level == 0) {
        tunnel->config.log_level = 2;  /* INFO */
    }

    return tunnel;
}

tunnel_t* tunnel_create_from_file(const char *config_path)
{
    (void)config_path;
    /* TODO: Implement YAML parsing */
    return NULL;
}

tunnel_t* tunnel_create_from_yaml(const char *config_yaml)
{
    (void)config_yaml;
    /* TODO: Implement YAML parsing */
    return NULL;
}

void tunnel_destroy(tunnel_t *tunnel)
{
    if (!tunnel) return;

    tunnel_stop(tunnel);

    /* Destroy components */
    tunnel_fake_dns_destroy(tunnel->fake_dns);
    tunnel_proxy_destroy(tunnel->proxy);
    tunnel_nat_destroy(tunnel->nat);
    tunnel_tun_destroy(tunnel->tun);

    /* Free routing rules */
    tunnel_route_rule_t *rule = tunnel->include_rules;
    while (rule) {
        tunnel_route_rule_t *next = rule->next;
        free(rule);
        rule = next;
    }

    rule = tunnel->exclude_rules;
    while (rule) {
        tunnel_route_rule_t *next = rule->next;
        free(rule);
        rule = next;
    }

    /* Destroy event loop */
    if (tunnel->owns_loop && tunnel->loop) {
        uv_loop_close(tunnel->loop);
        free(tunnel->loop);
    }

    uv_mutex_destroy(&tunnel->mutex);
    free(tunnel);
}

/* =============================================================================
 * Packet Processing
 * ============================================================================= */

static void tunnel_process_tcp_packet(tunnel_t *tunnel, tunnel_packet_t *pkt)
{
    /* Look up or create session */
    tunnel_session_key_t key;
    memset(&key, 0, sizeof(key));
    tunnel_endpoint_copy(&key.src, &pkt->ip.src);
    tunnel_endpoint_copy(&key.dst, &pkt->ip.dst);
    key.protocol = TUNNEL_IPPROTO_TCP;

    tunnel_session_t *session = tunnel_nat_lookup(tunnel->nat, &key);

    if (!session) {
        /* New connection - check for SYN */
        if (!(pkt->tcp.flags & TUNNEL_TCP_SYN)) {
            /* Not SYN, ignore (would send RST but no session to send from) */
            return;
        }

        /* Create new TCP session - this initiates proxy connection */
        session = tunnel_session_tcp_syn(tunnel, &pkt->ip.src, &pkt->ip.dst, pkt->tcp.seq);
        if (!session) {
            tunnel->stats.connect_errors++;
            return;
        }

        TLOG_DEBUG("New TCP session {}:{} -> {}:{}",
                         tunnel_session_get_src_addr(session),
                         tunnel_session_get_src_port(session),
                         tunnel_session_get_dst_addr(session),
                         tunnel_session_get_dst_port(session));
        return;  /* SYN-ACK will be sent when proxy connects */
    }

    /* Update session activity */
    tunnel_session_touch(session);

    /* Process packet based on TCP flags */
    if (pkt->tcp.flags & TUNNEL_TCP_RST) {
        tunnel_session_tcp_rst(session);
        return;
    }

    if (pkt->tcp.flags & TUNNEL_TCP_FIN) {
        tunnel_session_tcp_fin(session, pkt->tcp.seq);
        return;
    }

    if (pkt->tcp.flags & TUNNEL_TCP_ACK) {
        tunnel_session_tcp_ack(session, pkt->tcp.ack, pkt->tcp.window);
    }

    /* Handle data if present */
    if (pkt->payload && pkt->payload_len > 0) {
        int ret = tunnel_session_tcp_data(session, pkt->tcp.seq,
                                           pkt->payload, pkt->payload_len);
        if (ret != TUNNEL_OK) {
            TLOG_DEBUG("TCP data error: {}", ret);
        }
    }
}

static void tunnel_process_udp_packet(tunnel_t *tunnel, tunnel_packet_t *pkt)
{
    /* Forward UDP datagram via session manager */
    int ret = tunnel_session_udp_datagram(tunnel,
                                           &pkt->ip.src, &pkt->ip.dst,
                                           pkt->payload, pkt->payload_len);
    if (ret != TUNNEL_OK) {
        tunnel->stats.connect_errors++;
        TLOG_DEBUG("UDP datagram error: {}", ret);
    }
}

static void tunnel_process_dns_packet(tunnel_t *tunnel, tunnel_packet_t *pkt)
{
    if (!tunnel->fake_dns) {
        /* Forward as regular UDP */
        tunnel_process_udp_packet(tunnel, pkt);
        return;
    }

    /* Process DNS query with Fake DNS */
    uint8_t response[512];
    size_t response_len;

    if (tunnel_fake_dns_process_query(tunnel->fake_dns,
                                       pkt->payload, pkt->payload_len,
                                       response, &response_len, sizeof(response))) {
        /* Send DNS response back through TUN */
        uint8_t packet[1500];
        int len = tunnel_ip_build_udp(packet, sizeof(packet),
                                       &pkt->ip.dst, &pkt->ip.src,
                                       response, response_len);
        if (len > 0) {
            tunnel_tun_write(tunnel->tun, packet, len);
            tunnel->stats.packets_tx++;
            tunnel->stats.bytes_tx += len;
        }
    } else {
        /* Fake DNS couldn't handle, forward to upstream */
        tunnel_process_udp_packet(tunnel, pkt);
    }
}

static int tunnel_should_tunnel(tunnel_t *tunnel, tunnel_packet_t *pkt)
{
    /* Check exclude rules first */
    tunnel_route_rule_t *rule = tunnel->exclude_rules;
    while (rule) {
        if (rule->type == TUNNEL_ROUTE_IP) {
            uint32_t dst_masked = pkt->ip.dst.addr.v4 & rule->ip.mask.v4;
            uint32_t rule_masked = rule->ip.addr.v4 & rule->ip.mask.v4;
            if (dst_masked == rule_masked) {
                return 0;  /* Excluded */
            }
        }
        rule = rule->next;
    }

    /* Check include rules */
    rule = tunnel->include_rules;
    if (!rule) {
        return 1;  /* No include rules = tunnel all */
    }

    while (rule) {
        if (rule->type == TUNNEL_ROUTE_IP) {
            uint32_t dst_masked = pkt->ip.dst.addr.v4 & rule->ip.mask.v4;
            uint32_t rule_masked = rule->ip.addr.v4 & rule->ip.mask.v4;
            if (dst_masked == rule_masked) {
                return 1;  /* Included */
            }
        }
        rule = rule->next;
    }

    return 0;  /* Not matched = bypass */
}

static void tunnel_on_tun_packet(tunnel_t *tunnel, const uint8_t *data, size_t len)
{
    /* Traffic callback */
    if (tunnel->traffic_cb) {
        tunnel->traffic_cb(tunnel, 0, data, len, tunnel->traffic_user_data);
    }

    /* Update statistics */
    tunnel->stats.packets_rx++;
    tunnel->stats.bytes_rx += len;

    /* Parse IP packet */
    tunnel_packet_t pkt;
    int ret = tunnel_ip_parse(data, len, &pkt);
    if (ret != TUNNEL_OK) {
        tunnel->stats.protocol_errors++;
        return;
    }

    /* Check routing rules */
    if (!tunnel_should_tunnel(tunnel, &pkt)) {
        /* Bypass - write directly to TUN (loopback) */
        return;
    }

    /* Check for Fake DNS IP and resolve domain */
    if (tunnel->fake_dns && tunnel_fake_dns_is_fake_ip(tunnel->fake_dns, pkt.ip.dst.addr.v4)) {
        const char *domain = tunnel_fake_dns_get_domain(tunnel->fake_dns, pkt.ip.dst.addr.v4);
        if (domain) {
            /* Store domain for session */
            TLOG_DEBUG("Resolved fake IP to domain: {}", domain);
        }
    }

    /* Process by protocol */
    switch (pkt.ip.protocol) {
        case TUNNEL_IPPROTO_TCP:
            tunnel_process_tcp_packet(tunnel, &pkt);
            break;

        case TUNNEL_IPPROTO_UDP:
            /* Check for DNS (port 53) */
            if (pkt.ip.dst.port == 53 && tunnel->config.dns.hijack_dns) {
                tunnel_process_dns_packet(tunnel, &pkt);
            } else {
                tunnel_process_udp_packet(tunnel, &pkt);
            }
            break;

        case TUNNEL_IPPROTO_ICMP:
        case TUNNEL_IPPROTO_ICMPV6:
            /* TODO: Handle ICMP */
            break;

        default:
            tunnel->stats.protocol_errors++;
            break;
    }
}

/* =============================================================================
 * Timer Callbacks
 * ============================================================================= */

static void tunnel_session_timeout_cb(uv_timer_t *handle)
{
    tunnel_t *tunnel = (tunnel_t *)handle->data;

    uint32_t tcp_timeout = tunnel->config.session_timeout * 1000;
    uint32_t udp_timeout = TUNNEL_UDP_TIMEOUT_MS;

    if (tcp_timeout == 0) {
        tcp_timeout = TUNNEL_SESSION_TIMEOUT_MS;
    }

    /* Expire old sessions via NAT */
    int expired = tunnel_nat_evict_expired(tunnel->nat, tcp_timeout, udp_timeout);
    if (expired > 0) {
        TLOG_DEBUG("Expired {} sessions", expired);
        tunnel->stats.timeout_errors += expired;
    }
}

static void tunnel_stats_timer_cb(uv_timer_t *handle)
{
    tunnel_t *tunnel = (tunnel_t *)handle->data;

    /* Update uptime */
    tunnel->stats.uptime_ms = uv_now(tunnel->loop) - tunnel->start_time;

    /* Update session counts */
    tunnel->stats.tcp_sessions = (uint32_t)tunnel_session_tcp_count(tunnel);
    tunnel->stats.udp_sessions = (uint32_t)tunnel_session_udp_count(tunnel);
}

/* =============================================================================
 * TUN Callback
 * ============================================================================= */

static void on_tun_read(tunnel_tun_t *tun, const uint8_t *data, size_t len)
{
    tunnel_t *tunnel = tun->tunnel;
    tunnel_on_tun_packet(tunnel, data, len);
}

/* =============================================================================
 * Control API
 * ============================================================================= */

int tunnel_start(tunnel_t *tunnel)
{
    if (!tunnel) return TUNNEL_ERR_INVALID_ARG;
    if (tunnel->running) return TUNNEL_OK;

    /* Open TUN device */
    int ret = tunnel_tun_open(tunnel->tun);
    if (ret != TUNNEL_OK) {
        TLOG_ERROR("Failed to open TUN device: {}", ret);
        return ret;
    }

    /* Configure TUN device */
    ret = tunnel_tun_configure(tunnel->tun);
    if (ret != TUNNEL_OK) {
        TLOG_ERROR("Failed to configure TUN device: {}", ret);
        tunnel_tun_close(tunnel->tun);
        return ret;
    }

    TLOG_INFO("TUN device {} opened", tunnel_tun_get_name(tunnel->tun));

    /* Start TUN polling */
    ret = tunnel_tun_start(tunnel->tun, tunnel->loop);
    if (ret != TUNNEL_OK) {
        TLOG_ERROR("Failed to start TUN polling: {}", ret);
        tunnel_tun_close(tunnel->tun);
        return ret;
    }

    /* Set TUN read callback */
    tunnel_tun_set_read_cb(tunnel->tun, on_tun_read);

    /* Start session timeout timer */
    uv_timer_init(tunnel->loop, &tunnel->session_timer);
    tunnel->session_timer.data = tunnel;
    uv_timer_start(&tunnel->session_timer, tunnel_session_timeout_cb, 1000, 1000);

    /* Start stats timer */
    uv_timer_init(tunnel->loop, &tunnel->stats_timer);
    tunnel->stats_timer.data = tunnel;
    uv_timer_start(&tunnel->stats_timer, tunnel_stats_timer_cb, 5000, 5000);

    tunnel->start_time = uv_now(tunnel->loop);
    tunnel->running = 1;

    TLOG_INFO("Tunnel started");

    return TUNNEL_OK;
}

void tunnel_stop(tunnel_t *tunnel)
{
    if (!tunnel || !tunnel->running) return;

    tunnel->stopping = 1;

    /* Stop timers */
    uv_timer_stop(&tunnel->session_timer);
    uv_timer_stop(&tunnel->stats_timer);

    /* Stop TUN */
    tunnel_tun_stop(tunnel->tun);
    tunnel_tun_close(tunnel->tun);

    /* Close all sessions */
    tunnel_nat_clear(tunnel->nat);

    tunnel->running = 0;
    tunnel->stopping = 0;

    TLOG_INFO("Tunnel stopped");
}

int tunnel_run(tunnel_t *tunnel)
{
    if (!tunnel) return TUNNEL_ERR_INVALID_ARG;

    if (!tunnel->running) {
        int ret = tunnel_start(tunnel);
        if (ret != TUNNEL_OK) {
            return ret;
        }
    }

    /* Run event loop */
    while (tunnel->running && !tunnel->stopping) {
        uv_run(tunnel->loop, UV_RUN_ONCE);
    }

    return TUNNEL_OK;
}

int tunnel_poll(tunnel_t *tunnel, int timeout_ms)
{
    if (!tunnel || !tunnel->running) return 0;

    (void)timeout_ms;
    return uv_run(tunnel->loop, UV_RUN_NOWAIT);
}

int tunnel_write_packet(tunnel_t *tunnel, const uint8_t *data, size_t len)
{
    if (!tunnel || !data || len == 0) return TUNNEL_ERR_INVALID_ARG;
    if (!tunnel->tun) return TUNNEL_ERR_TUN_OPEN;

    /* Write packet directly to TUN device */
    int ret = tunnel_tun_write(tunnel->tun, data, len);
    if (ret < 0) {
        return TUNNEL_ERR_NETWORK;
    }

    /* Update statistics */
    tunnel->stats.packets_tx++;
    tunnel->stats.bytes_tx += len;

    /* Traffic callback for monitoring */
    if (tunnel->traffic_cb) {
        tunnel->traffic_cb(tunnel, 1, data, len, tunnel->traffic_user_data);
    }

    return TUNNEL_OK;
}

/* =============================================================================
 * Configuration API
 * ============================================================================= */

void tunnel_set_log_callback(tunnel_t *tunnel, tunnel_log_cb callback, void *user_data)
{
    if (!tunnel) return;
    tunnel->log_cb = callback;
    tunnel->log_user_data = user_data;
}

void tunnel_set_session_callback(tunnel_t *tunnel, tunnel_session_cb callback, void *user_data)
{
    if (!tunnel) return;
    tunnel->session_cb = callback;
    tunnel->session_user_data = user_data;
}

void tunnel_set_traffic_callback(tunnel_t *tunnel, tunnel_traffic_cb callback, void *user_data)
{
    if (!tunnel) return;
    tunnel->traffic_cb = callback;
    tunnel->traffic_user_data = user_data;
}

int tunnel_set_proxy(tunnel_t *tunnel, const tunnel_proxy_config_t *proxy)
{
    if (!tunnel || !proxy) return TUNNEL_ERR_INVALID_ARG;

    /* Update proxy configuration */
    return tunnel_proxy_set_config(tunnel->proxy, proxy);
}

int tunnel_set_routes(tunnel_t *tunnel, const tunnel_route_config_t *route)
{
    if (!tunnel || !route) return TUNNEL_ERR_INVALID_ARG;

    /* Free existing rules */
    tunnel_route_rule_t *rule = tunnel->include_rules;
    while (rule) {
        tunnel_route_rule_t *next = rule->next;
        free(rule);
        rule = next;
    }
    tunnel->include_rules = NULL;

    rule = tunnel->exclude_rules;
    while (rule) {
        tunnel_route_rule_t *next = rule->next;
        free(rule);
        rule = next;
    }
    tunnel->exclude_rules = NULL;

    /* Parse and add new rules */
    /* TODO: Implement CIDR parsing */

    return TUNNEL_OK;
}

/* =============================================================================
 * Statistics API
 * ============================================================================= */

int tunnel_get_stats(tunnel_t *tunnel, tunnel_stats_t *stats)
{
    if (!tunnel || !stats) return TUNNEL_ERR_INVALID_ARG;

    uv_mutex_lock(&tunnel->mutex);
    memcpy(stats, &tunnel->stats, sizeof(tunnel_stats_t));
    uv_mutex_unlock(&tunnel->mutex);

    return TUNNEL_OK;
}

void tunnel_reset_stats(tunnel_t *tunnel)
{
    if (!tunnel) return;

    uv_mutex_lock(&tunnel->mutex);
    memset(&tunnel->stats, 0, sizeof(tunnel_stats_t));
    tunnel->start_time = uv_now(tunnel->loop);
    uv_mutex_unlock(&tunnel->mutex);
}

/* =============================================================================
 * Session API
 * ============================================================================= */

int tunnel_get_session_count(tunnel_t *tunnel)
{
    if (!tunnel || !tunnel->nat) return 0;
    return (int)tunnel_nat_session_count(tunnel->nat);
}

void tunnel_foreach_session(tunnel_t *tunnel,
                             int (*callback)(tunnel_session_t*, void*),
                             void *user_data)
{
    if (!tunnel || !tunnel->nat || !callback) return;
    tunnel_session_foreach(tunnel, callback, user_data);
}

static char g_addr_buf[64];

const char* tunnel_session_get_src_addr(tunnel_session_t *session)
{
    if (!session) return NULL;

    if (session->key.src.family == AF_INET) {
        uint32_t ip = ntohl(session->key.src.addr.v4);
        stbsp_snprintf(g_addr_buf, sizeof(g_addr_buf), "%u.%u.%u.%u",
                 (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                 (ip >> 8) & 0xFF, ip & 0xFF);
    } else {
        /* TODO: Format IPv6 */
        return "::";
    }

    return g_addr_buf;
}

int tunnel_session_get_src_port(tunnel_session_t *session)
{
    return session ? session->key.src.port : 0;
}

const char* tunnel_session_get_dst_addr(tunnel_session_t *session)
{
    if (!session) return NULL;

    /* Check if domain is available */
    if (session->domain[0]) {
        return session->domain;
    }

    if (session->key.dst.family == AF_INET) {
        uint32_t ip = ntohl(session->key.dst.addr.v4);
        stbsp_snprintf(g_addr_buf, sizeof(g_addr_buf), "%u.%u.%u.%u",
                 (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                 (ip >> 8) & 0xFF, ip & 0xFF);
    } else {
        /* TODO: Format IPv6 */
        return "::";
    }

    return g_addr_buf;
}

int tunnel_session_get_dst_port(tunnel_session_t *session)
{
    return session ? session->key.dst.port : 0;
}

tunnel_session_state_t tunnel_session_get_state(tunnel_session_t *session)
{
    return session ? session->state : TUNNEL_SESSION_CLOSED;
}

uint64_t tunnel_session_get_bytes_rx(tunnel_session_t *session)
{
    return session ? session->bytes_rx : 0;
}

uint64_t tunnel_session_get_bytes_tx(tunnel_session_t *session)
{
    return session ? session->bytes_tx : 0;
}

void tunnel_session_close(tunnel_session_t *session)
{
    if (!session || !session->tunnel) return;
    tunnel_session_destroy(session);
}

/* =============================================================================
 * Utility API
 * ============================================================================= */

const char* tunnel_error_string(tunnel_error_t error)
{
    switch (error) {
        case TUNNEL_OK:               return "Success";
        case TUNNEL_ERR_INVALID_ARG:  return "Invalid argument";
        case TUNNEL_ERR_NO_MEMORY:    return "Out of memory";
        case TUNNEL_ERR_TUN_OPEN:     return "Failed to open TUN device";
        case TUNNEL_ERR_TUN_CONFIG:   return "Failed to configure TUN device";
        case TUNNEL_ERR_PROXY_CONNECT: return "Proxy connection failed";
        case TUNNEL_ERR_PROXY_AUTH:   return "Proxy authentication failed";
        case TUNNEL_ERR_PROXY_REFUSED: return "Proxy refused connection";
        case TUNNEL_ERR_NETWORK:      return "Network error";
        case TUNNEL_ERR_TIMEOUT:      return "Operation timed out";
        case TUNNEL_ERR_CLOSED:       return "Connection closed";
        case TUNNEL_ERR_NOT_SUPPORTED: return "Operation not supported";
        default:                      return "Unknown error";
    }
}

const char* tunnel_version(void)
{
    return TUNNEL_VERSION_STRING;
}

void tunnel_config_init(tunnel_config_t *config)
{
    if (!config) return;

    memset(config, 0, sizeof(tunnel_config_t));

    /* Set defaults */
    config->tun.mtu = 1500;
    config->udp_mode = TUNNEL_UDP_OVER_TCP;
    config->tcp_keep_alive = 60;
    config->session_timeout = 300;
    config->log_level = 2;  /* INFO */
}
