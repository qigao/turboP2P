/**
 * @file tunnel_types.h
 * @brief Internal type definitions for tunnel module
 */

#ifndef TUNNEL_TYPES_H
#define TUNNEL_TYPES_H

#include "turbo_tunnel.h"
#include <CoroNet/turbo_coro_context.h>
#include <CoroNet/turbo_stream.h>
#include <turbo_thread.h>
#include <fmt.h>

/* =============================================================================
 * Internal Markers
 * ============================================================================= */

#define TUNNEL_INTERNAL

/* =============================================================================
 * Constants
 * ============================================================================= */

#define TUNNEL_RECV_BUF_SIZE    65536
#define TUNNEL_SEND_BUF_SIZE    65536
#define TUNNEL_MAX_DOMAIN       256
#define TUNNEL_NAT_TABLE_SIZE   65536
#define TUNNEL_FAKE_DNS_SIZE    65536

/* =============================================================================
 * IP Protocol Numbers
 * ============================================================================= */

#define TUNNEL_IPPROTO_ICMP     1
#define TUNNEL_IPPROTO_TCP      6
#define TUNNEL_IPPROTO_UDP      17
#define TUNNEL_IPPROTO_ICMPV6   58

/* =============================================================================
 * Forward Declarations
 * ============================================================================= */

typedef struct tunnel_tun_s tunnel_tun_t;
typedef struct tunnel_proxy_s tunnel_proxy_t;
typedef struct tunnel_proxy_conn_s tunnel_proxy_conn_t;
typedef struct tunnel_nat_s tunnel_nat_t;
typedef struct tunnel_ip_stack_s tunnel_ip_stack_t;
typedef struct tunnel_fake_dns_s tunnel_fake_dns_t;

/* =============================================================================
 * IP Address Union
 * ============================================================================= */

typedef union {
    uint32_t v4;                    /* IPv4 in network byte order */
    uint8_t v6[16];                 /* IPv6 address */
} tunnel_ip_addr_t;

typedef struct {
    int family;                     /* AF_INET or AF_INET6 */
    tunnel_ip_addr_t addr;
    uint16_t port;                  /* In host byte order */
} tunnel_endpoint_t;

/* =============================================================================
 * Session Key (for NAT lookup)
 * ============================================================================= */

typedef struct {
    tunnel_endpoint_t src;
    tunnel_endpoint_t dst;
    uint8_t protocol;               /* TCP=6, UDP=17 */
} tunnel_session_key_t;

/* =============================================================================
 * Session Structure
 * ============================================================================= */

struct tunnel_session_s {
    tunnel_session_key_t key;
    tunnel_session_state_t state;

    /* Proxy connection */
    tunnel_proxy_conn_t *proxy_conn;

    /* Traffic counters */
    uint64_t bytes_rx;
    uint64_t bytes_tx;
    uint64_t packets_rx;
    uint64_t packets_tx;

    /* Timing */
    uint64_t create_time;
    uint64_t last_active;

    /* TCP state */
    struct {
        uint32_t seq_local;         /* Local sequence number */
        uint32_t seq_remote;        /* Remote sequence number */
        uint32_t ack_local;
        uint32_t ack_remote;
        uint16_t window;
        uint8_t state;              /* TCP FSM state */
    } tcp;

    /* UDP state */
    struct {
        uint16_t local_port;        /* NAT-assigned local port */
        tunnel_endpoint_t assoc;    /* UDP ASSOCIATE address */
    } udp;

    /* Send/receive buffers */
    uint8_t *send_buf;
    size_t send_len;
    size_t send_cap;

    uint8_t *recv_buf;
    size_t recv_len;
    size_t recv_cap;

    /* Domain name (if resolved via Fake DNS) */
    char domain[TUNNEL_MAX_DOMAIN];

    /* Back-reference */
    tunnel_t *tunnel;

    /* Hash table linkage */
    tunnel_session_t *hash_next;
    tunnel_session_t *hash_prev;

    /* LRU linkage */
    tunnel_session_t *lru_next;
    tunnel_session_t *lru_prev;
};

/* =============================================================================
 * TUN Device Structure
 * ============================================================================= */

/* Forward declaration for read callback */
typedef void (*tunnel_tun_read_cb_t)(struct tunnel_tun_s *tun, const uint8_t *data, size_t len);

struct tunnel_tun_s {
    char name[32];                  /* Device name */
    int fd;                         /* File descriptor (Unix) */
    void *handle;                   /* Platform handle (Windows) */

    /* Configuration */
    char ipv4_addr[16];
    char ipv4_netmask[16];
    char ipv6_addr[46];
    int ipv6_prefix;
    int mtu;

    /* Receive buffer */
    uint8_t recv_buf[TUNNEL_RECV_BUF_SIZE];

    /* Read callback */
    tunnel_tun_read_cb_t read_cb;

    /* Back-reference */
    tunnel_t *tunnel;

    /* Statistics */
    uint64_t packets_read;
    uint64_t packets_written;
    uint64_t bytes_read;
    uint64_t bytes_written;
};

TUNNEL_INTERNAL int tunnel_handle_tun_packet(tunnel_t *tunnel, const uint8_t *data, size_t len);
TUNNEL_INTERNAL int tunnel_config_parse_file(const char *path, tunnel_config_t *config);
TUNNEL_INTERNAL int tunnel_config_parse_cidr(const char *cidr, tunnel_ip_addr_t *addr,
                                             tunnel_ip_addr_t *mask, int *family);
TUNNEL_INTERNAL int tunnel_config_parse_fake_dns_range(const char *range,
                                                       uint32_t *base_ip,
                                                       uint32_t *mask);
TUNNEL_INTERNAL void tunnel_config_clear_parsed_refs(tunnel_config_t *config);
TUNNEL_INTERNAL void tunnel_config_free_parsed_strings(tunnel_config_t *config);

/* =============================================================================
 * Proxy Client Structure
 * ============================================================================= */

struct tunnel_proxy_s {
    tunnel_proxy_type_t type;
    char host[256];
    int port;
    char username[64];
    char password[64];

    /* TLS settings */
    int use_tls;
    char tls_sni[256];
    int tls_verify;

    /* Protocol-specific */
    union {
        struct {
            char method[32];
            uint8_t key[32];
            size_t key_len;
        } shadowsocks;

        struct {
            char uuid[64];
            int alter_id;
            char security[32];
        } vmess;

        struct {
            uint8_t password_hash[56];
        } trojan;
    };

    /* Connection pool */
    turbo_stream_t *pool[8];
    int pool_count;

    /* Back-reference */
    tunnel_t *tunnel;
};

/* =============================================================================
 * NAT Table Structure
 * ============================================================================= */

struct tunnel_nat_s {
    /* Hash table for session lookup */
    tunnel_session_t **table;
    size_t table_size;
    size_t session_count;

    /* LRU list for session expiry */
    tunnel_session_t *lru_head;
    tunnel_session_t *lru_tail;

    /* Port allocation for UDP */
    uint16_t next_udp_port;
    uint8_t udp_port_bitmap[8192];  /* 65536 bits */

    /* Statistics */
    uint64_t lookups;
    uint64_t hits;
    uint64_t misses;
    uint64_t evictions;
};

/* =============================================================================
 * Fake DNS Structure (opaque - defined in tunnel_fake_dns.c)
 * ============================================================================= */

/* Forward declaration only - definition in tunnel_fake_dns.c */

/* =============================================================================
 * Lightweight IP Stack
 * ============================================================================= */

struct tunnel_ip_stack_s {
    /* TCP reassembly */
    struct {
        uint8_t *buffer;
        size_t len;
        size_t cap;
        uint32_t seq_start;
    } tcp_reassembly[256];          /* Indexed by session hash */

    /* IP fragment reassembly */
    struct {
        uint16_t id;
        uint8_t *buffer;
        size_t len;
        uint64_t expire;
    } fragments[64];
    int fragment_count;

    /* Back-reference */
    tunnel_t *tunnel;
};

/* =============================================================================
 * Route Rule
 * ============================================================================= */

typedef struct tunnel_route_rule_s {
    enum {
        TUNNEL_ROUTE_IP,
        TUNNEL_ROUTE_DOMAIN,
    } type;

    union {
        struct {
            tunnel_ip_addr_t addr;
            tunnel_ip_addr_t mask;
            int family;
        } ip;

        struct {
            char pattern[TUNNEL_MAX_DOMAIN];
            int wildcard;           /* 1 if pattern is *.domain */
        } domain;
    };

    int action;                     /* 1=include, 0=exclude */
    struct tunnel_route_rule_s *next;
} tunnel_route_rule_t;

/* =============================================================================
 * Main Tunnel Structure
 * ============================================================================= */

struct tunnel_s {
    /* Configuration */
    tunnel_config_t config;

    /* Core components */
    tunnel_tun_t *tun;              /* TUN device */
    tunnel_proxy_t *proxy;          /* Proxy client */
    tunnel_nat_t *nat;              /* NAT/session table */
    tunnel_ip_stack_t *ip_stack;    /* Lightweight TCP/IP stack */
    tunnel_fake_dns_t *fake_dns;    /* Fake DNS resolver */

    /* Routing rules */
    tunnel_route_rule_t *include_rules;
    tunnel_route_rule_t *exclude_rules;

    coro_context_t *ctx;

    /* Callbacks */
    tunnel_log_cb log_cb;
    void *log_user_data;
    tunnel_session_cb session_cb;
    void *session_user_data;
    tunnel_traffic_cb traffic_cb;
    void *traffic_user_data;

    /* Statistics */
    tunnel_stats_t stats;
    uint64_t start_time;
    uint64_t last_session_maintenance_ms;
    uint64_t last_stats_update_ms;

    /* State */
    int running;
    int stopping;

    /* Thread safety */
    turbo_mutex_t mutex;
};

/* =============================================================================
 * Endpoint Helper Functions
 * ============================================================================= */

/**
 * Copy endpoint
 */
static inline void tunnel_endpoint_copy(tunnel_endpoint_t *dst, const tunnel_endpoint_t *src)
{
    if (dst && src) {
        *dst = *src;
    }
}

/**
 * Copy session key
 */
static inline void tunnel_session_key_copy(tunnel_session_key_t *dst, const tunnel_session_key_t *src)
{
    if (dst && src) {
        *dst = *src;
    }
}

/**
 * Convert endpoint to string (IP only, no port)
 */
static inline int tunnel_endpoint_to_string(const tunnel_endpoint_t *ep, char *buf, size_t len)
{
    if (!ep || !buf || len < 16) return -1;

    if (ep->family == AF_INET) {
        uint32_t ip = ntohl(ep->addr.v4);
        fmt(buf, len, "{}.{}.{}.{}",
            (ip >> 24) & 0xFF,
            (ip >> 16) & 0xFF,
            (ip >> 8) & 0xFF,
            ip & 0xFF);
    } else if (ep->family == AF_INET6) {
        int written;

        /* Eight groups require 39 bytes plus the terminator. */
        if (len < 40) return -1;
        written = fmt(buf, len, "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                      ep->addr.v6[0], ep->addr.v6[1], ep->addr.v6[2], ep->addr.v6[3],
                      ep->addr.v6[4], ep->addr.v6[5], ep->addr.v6[6], ep->addr.v6[7]);
        if (written <= 0 || (size_t)written >= len) return -1;
        if (fmt(buf + written, len - (size_t)written,
                ":{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                ep->addr.v6[8], ep->addr.v6[9], ep->addr.v6[10], ep->addr.v6[11],
                ep->addr.v6[12], ep->addr.v6[13], ep->addr.v6[14], ep->addr.v6[15]) <= 0) {
            return -1;
        }
    } else {
        buf[0] = '\0';
    }
    return 0;
}

#endif /* TUNNEL_TYPES_H */
