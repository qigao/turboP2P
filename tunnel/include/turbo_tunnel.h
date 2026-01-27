/**
 * @file turbo_tunnel.h
 * @brief TurboNet Tunnel - High-performance tun2proxy implementation
 *
 * A lightweight tunnel that captures packets from TUN device and routes them
 * through various proxy protocols (SOCKS5, HTTP, Shadowsocks, etc.)
 *
 * Features:
 * - TUN device packet capture (IPv4/IPv6)
 * - Multiple proxy protocols (SOCKS5, HTTP CONNECT, Shadowsocks)
 * - TCP and UDP support (with multiple UDP relay modes)
 * - NAT session management with connection tracking
 * - Zero-copy packet processing via netcore
 * - Cross-platform (Linux, macOS, Windows, Android, iOS)
 *
 * Architecture:
 * ┌─────────────────────────────────────────────────────────────────┐
 * │                        Application                              │
 * │                            │                                    │
 * │                      ┌─────▼─────┐                              │
 * │                      │    TUN    │  (Virtual Network Device)    │
 * │                      └─────┬─────┘                              │
 * │                            │ IP Packets                         │
 * │                      ┌─────▼─────┐                              │
 * │                      │  IP Stack │  (Lightweight TCP/UDP)       │
 * │                      └─────┬─────┘                              │
 * │                            │ Sessions                           │
 * │                      ┌─────▼─────┐                              │
 * │                      │    NAT    │  (Connection Tracking)       │
 * │                      └─────┬─────┘                              │
 * │                            │                                    │
 * │         ┌──────────────────┼──────────────────┐                 │
 * │         ▼                  ▼                  ▼                 │
 * │   ┌──────────┐      ┌──────────┐       ┌──────────┐            │
 * │   │  SOCKS5  │      │   HTTP   │       │Shadowsocks│           │
 * │   │  Client  │      │  CONNECT │       │  Client   │           │
 * │   └────┬─────┘      └────┬─────┘       └────┬─────┘            │
 * │        └─────────────────┼─────────────────┘                   │
 * │                          │                                      │
 * │                    ┌─────▼─────┐                                │
 * │                    │  netcore  │  (TCP/UDP/KCP/TLS)             │
 * │                    └─────┬─────┘                                │
 * │                          │                                      │
 * └──────────────────────────┼──────────────────────────────────────┘
 *                            │
 *                      ┌─────▼─────┐
 *                      │  Network  │
 *                      └───────────┘
 */

#ifndef TURBO_TUNNEL_H
#define TURBO_TUNNEL_H

#include <stdint.h>
#include <stddef.h>
#include <platform.h>
#ifdef __cplusplus
extern "C" {
#endif

/* =============================================================================
 * Constants
 * ============================================================================= */

#define TUNNEL_MAX_MTU              1500
#define TUNNEL_MAX_SESSIONS         65536
#define TUNNEL_SESSION_TIMEOUT_MS   300000  /* 5 minutes */
#define TUNNEL_UDP_TIMEOUT_MS       60000   /* 1 minute for UDP */

/* =============================================================================
 * Error Codes
 * ============================================================================= */

typedef enum {
    TUNNEL_OK = 0,
    TUNNEL_ERR_INVALID_ARG = -1,
    TUNNEL_ERR_NO_MEMORY = -2,
    TUNNEL_ERR_TUN_OPEN = -3,
    TUNNEL_ERR_TUN_CONFIG = -4,
    TUNNEL_ERR_PROXY_CONNECT = -5,
    TUNNEL_ERR_PROXY_AUTH = -6,
    TUNNEL_ERR_PROXY_REFUSED = -7,
    TUNNEL_ERR_NETWORK = -8,
    TUNNEL_ERR_TIMEOUT = -9,
    TUNNEL_ERR_CLOSED = -10,
    TUNNEL_ERR_NOT_SUPPORTED = -11,
    TUNNEL_ERR_NOT_FOUND = -12,
} tunnel_error_t;

/* =============================================================================
 * Proxy Types
 * ============================================================================= */

typedef enum {
    TUNNEL_PROXY_NONE = 0,          /* Direct connection (no proxy) */
    TUNNEL_PROXY_SOCKS5,            /* SOCKS5 proxy (RFC 1928) */
    TUNNEL_PROXY_HTTP,              /* HTTP CONNECT proxy */
    TUNNEL_PROXY_SHADOWSOCKS,       /* Shadowsocks proxy */
    TUNNEL_PROXY_VMESS,             /* VMess proxy (V2Ray) */
    TUNNEL_PROXY_TROJAN,            /* Trojan proxy */
} tunnel_proxy_type_t;

/* =============================================================================
 * UDP Relay Modes
 * ============================================================================= */

typedef enum {
    TUNNEL_UDP_DISABLED = 0,        /* UDP not tunneled */
    TUNNEL_UDP_OVER_TCP,            /* UDP encapsulated in TCP */
    TUNNEL_UDP_NATIVE,              /* Native UDP (SOCKS5 UDP ASSOCIATE) */
    TUNNEL_UDP_FULLCONE,            /* Full cone NAT mode */
} tunnel_udp_mode_t;

/* =============================================================================
 * Session State
 * ============================================================================= */

typedef enum {
    TUNNEL_SESSION_INIT = 0,
    TUNNEL_SESSION_CONNECTING,
    TUNNEL_SESSION_ESTABLISHED,
    TUNNEL_SESSION_CLOSING,
    TUNNEL_SESSION_CLOSED,
    TUNNEL_SESSION_ERROR,
} tunnel_session_state_t;

/* =============================================================================
 * Opaque Handles
 * ============================================================================= */

typedef struct tunnel_s tunnel_t;
typedef struct tunnel_session_s tunnel_session_t;

/* =============================================================================
 * Configuration Structures
 * ============================================================================= */

/**
 * TUN device configuration
 */
typedef struct {
    const char *name;               /* Device name (e.g., "tun0", NULL for auto) */
    const char *ipv4_addr;          /* IPv4 address (e.g., "10.0.0.1") */
    const char *ipv4_netmask;       /* IPv4 netmask (e.g., "255.255.255.0") */
    const char *ipv6_addr;          /* IPv6 address (NULL to disable) */
    int ipv6_prefix;                /* IPv6 prefix length (e.g., 64) */
    int mtu;                        /* MTU (0 for default 1500) */
    int multi_queue;                /* Enable multi-queue (Linux only) */
} tunnel_tun_config_t;

/**
 * Proxy server configuration
 */
typedef struct {
    tunnel_proxy_type_t type;       /* Proxy protocol type */
    const char *host;               /* Proxy server host */
    int port;                       /* Proxy server port */
    const char *username;           /* Authentication username (NULL if none) */
    const char *password;           /* Authentication password (NULL if none) */

    /* TLS settings (for secure proxies) */
    int use_tls;                    /* Enable TLS */
    const char *tls_sni;            /* TLS SNI hostname (NULL for auto) */
    int tls_verify;                 /* Verify server certificate */
    const char *tls_ca_file;        /* Custom CA file (NULL for system) */

    /* Protocol-specific settings */
    union {
        struct {
            /* Shadowsocks */
            const char *method;     /* Encryption method (e.g., "aes-256-gcm") */
        } shadowsocks;

        struct {
            /* VMess */
            const char *uuid;       /* User UUID */
            int alter_id;           /* Alter ID */
            const char *security;   /* Security method */
        } vmess;

        struct {
            /* Trojan */
            const char *password;   /* Trojan password */
        } trojan;
    };
} tunnel_proxy_config_t;

/**
 * DNS configuration
 */
typedef struct {
    const char *ipv4_server;        /* IPv4 DNS server (e.g., "8.8.8.8") */
    const char *ipv6_server;        /* IPv6 DNS server (NULL to disable) */
    int hijack_dns;                 /* Hijack DNS queries through tunnel */
    int fake_dns;                   /* Enable Fake DNS for domain tracking */
    const char *fake_dns_range;     /* Fake DNS IP range (e.g., "198.18.0.0/15") */
} tunnel_dns_config_t;

/**
 * Routing configuration
 */
typedef struct {
    const char **include_ranges;    /* IP ranges to tunnel (NULL = all) */
    int include_count;
    const char **exclude_ranges;    /* IP ranges to bypass */
    int exclude_count;
    const char **include_domains;   /* Domains to tunnel */
    int include_domain_count;
    const char **exclude_domains;   /* Domains to bypass */
    int exclude_domain_count;
} tunnel_route_config_t;

/**
 * Main tunnel configuration
 */
typedef struct {
    tunnel_tun_config_t tun;        /* TUN device config */
    tunnel_proxy_config_t proxy;    /* Proxy server config */
    tunnel_dns_config_t dns;        /* DNS config */
    tunnel_route_config_t route;    /* Routing config */
    tunnel_udp_mode_t udp_mode;     /* UDP relay mode */
    int tcp_keep_alive;             /* TCP keep-alive interval (seconds) */
    int session_timeout;            /* Session timeout (seconds) */
    int log_level;                  /* Log verbosity (0-4) */
} tunnel_config_t;

/* =============================================================================
 * Statistics
 * ============================================================================= */

typedef struct {
    /* Traffic counters */
    uint64_t bytes_rx;              /* Bytes received from TUN */
    uint64_t bytes_tx;              /* Bytes sent to TUN */
    uint64_t packets_rx;            /* Packets received from TUN */
    uint64_t packets_tx;            /* Packets sent to TUN */

    /* Session counters */
    uint32_t tcp_sessions;          /* Active TCP sessions */
    uint32_t udp_sessions;          /* Active UDP sessions */
    uint32_t total_sessions;        /* Total sessions created */

    /* Error counters */
    uint32_t connect_errors;        /* Proxy connection errors */
    uint32_t timeout_errors;        /* Session timeout errors */
    uint32_t protocol_errors;       /* Protocol errors */

    /* Performance metrics */
    uint64_t uptime_ms;             /* Tunnel uptime in milliseconds */
    double avg_latency_ms;          /* Average proxy latency */
} tunnel_stats_t;

/* =============================================================================
 * Callbacks
 * ============================================================================= */

/**
 * Log callback
 * @param level Log level (0=error, 1=warn, 2=info, 3=debug, 4=trace)
 * @param message Log message
 * @param user_data User context
 */
typedef void (*tunnel_log_cb)(int level, const char *message, void *user_data);

/**
 * Session event callback
 * @param tunnel Tunnel handle
 * @param session Session handle
 * @param event Event type string ("connected", "closed", "error")
 * @param user_data User context
 */
typedef void (*tunnel_session_cb)(tunnel_t *tunnel, tunnel_session_t *session,
                                   const char *event, void *user_data);

/**
 * Traffic callback (for monitoring)
 * @param tunnel Tunnel handle
 * @param direction 0=rx, 1=tx
 * @param data Packet data
 * @param len Packet length
 * @param user_data User context
 */
typedef void (*tunnel_traffic_cb)(tunnel_t *tunnel, int direction,
                                   const uint8_t *data, size_t len,
                                   void *user_data);

/* =============================================================================
 * Lifecycle API
 * ============================================================================= */

/**
 * Initialize tunnel library
 * Call once at application startup.
 */
CXX_C_API int tunnel_init(void);

/**
 * Shutdown tunnel library
 * Call once at application exit.
 */
CXX_C_API void tunnel_shutdown(void);

/**
 * Create a tunnel instance
 * @param config Tunnel configuration
 * @return Tunnel handle or NULL on error
 */
CXX_C_API tunnel_t* tunnel_create(const tunnel_config_t *config);

/**
 * Create tunnel from YAML config file
 * @param config_path Path to YAML config file
 * @return Tunnel handle or NULL on error
 */
CXX_C_API tunnel_t* tunnel_create_from_file(const char *config_path);

/**
 * Create tunnel from YAML config string
 * @param config_yaml YAML config string
 * @return Tunnel handle or NULL on error
 */
CXX_C_API tunnel_t* tunnel_create_from_yaml(const char *config_yaml);

/**
 * Destroy tunnel instance
 * Closes TUN device and all sessions.
 * @param tunnel Tunnel handle
 */
CXX_C_API void tunnel_destroy(tunnel_t *tunnel);

/* =============================================================================
 * Control API
 * ============================================================================= */

/**
 * Start the tunnel
 * Opens TUN device and begins packet processing.
 * @param tunnel Tunnel handle
 * @return TUNNEL_OK on success
 */
CXX_C_API int tunnel_start(tunnel_t *tunnel);

/**
 * Stop the tunnel
 * Closes all sessions but keeps TUN device open.
 * @param tunnel Tunnel handle
 */
CXX_C_API void tunnel_stop(tunnel_t *tunnel);

/**
 * Run tunnel event loop (blocking)
 * Returns when tunnel is stopped.
 * @param tunnel Tunnel handle
 * @return TUNNEL_OK on clean exit
 */
CXX_C_API int tunnel_run(tunnel_t *tunnel);

/**
 * Run single iteration of event loop (non-blocking)
 * @param tunnel Tunnel handle
 * @param timeout_ms Maximum wait time (-1 for blocking)
 * @return Number of events processed
 */
CXX_C_API int tunnel_poll(tunnel_t *tunnel, int timeout_ms);

/**
 * Write packet to TUN device (inject into network stack)
 * Used to inject packets from external sources (e.g., mesh VPN) into the TUN device.
 * The packet will be delivered to the OS network stack as if it arrived from the network.
 * @param tunnel Tunnel handle
 * @param data Packet data (raw IP packet)
 * @param len Packet length
 * @return TUNNEL_OK on success
 */
CXX_C_API int tunnel_write_packet(tunnel_t *tunnel, const uint8_t *data, size_t len);

/* =============================================================================
 * Configuration API
 * ============================================================================= */

/**
 * Set log callback
 * @param tunnel Tunnel handle
 * @param callback Log callback function
 * @param user_data User context passed to callback
 */
CXX_C_API void tunnel_set_log_callback(tunnel_t *tunnel,
                                         tunnel_log_cb callback,
                                         void *user_data);

/**
 * Set session event callback
 * @param tunnel Tunnel handle
 * @param callback Session callback function
 * @param user_data User context passed to callback
 */
CXX_C_API void tunnel_set_session_callback(tunnel_t *tunnel,
                                             tunnel_session_cb callback,
                                             void *user_data);

/**
 * Set traffic monitoring callback
 * @param tunnel Tunnel handle
 * @param callback Traffic callback function
 * @param user_data User context passed to callback
 */
CXX_C_API void tunnel_set_traffic_callback(tunnel_t *tunnel,
                                             tunnel_traffic_cb callback,
                                             void *user_data);

/**
 * Update proxy configuration (hot reload)
 * @param tunnel Tunnel handle
 * @param proxy New proxy configuration
 * @return TUNNEL_OK on success
 */
CXX_C_API int tunnel_set_proxy(tunnel_t *tunnel, const tunnel_proxy_config_t *proxy);

/**
 * Update routing rules (hot reload)
 * @param tunnel Tunnel handle
 * @param route New routing configuration
 * @return TUNNEL_OK on success
 */
CXX_C_API int tunnel_set_routes(tunnel_t *tunnel, const tunnel_route_config_t *route);

/* =============================================================================
 * Statistics API
 * ============================================================================= */

/**
 * Get tunnel statistics
 * @param tunnel Tunnel handle
 * @param stats Output statistics structure
 * @return TUNNEL_OK on success
 */
CXX_C_API int tunnel_get_stats(tunnel_t *tunnel, tunnel_stats_t *stats);

/**
 * Reset statistics counters
 * @param tunnel Tunnel handle
 */
CXX_C_API void tunnel_reset_stats(tunnel_t *tunnel);

/* =============================================================================
 * Session API
 * ============================================================================= */

/**
 * Get number of active sessions
 * @param tunnel Tunnel handle
 * @return Number of active sessions
 */
CXX_C_API int tunnel_get_session_count(tunnel_t *tunnel);

/**
 * Iterate over active sessions
 * @param tunnel Tunnel handle
 * @param callback Called for each session (return 0 to continue, non-zero to stop)
 * @param user_data User context
 */
CXX_C_API void tunnel_foreach_session(tunnel_t *tunnel,
                                        int (*callback)(tunnel_session_t*, void*),
                                        void *user_data);

/**
 * Get session information
 */
CXX_C_API const char* tunnel_session_get_src_addr(tunnel_session_t *session);
CXX_C_API int tunnel_session_get_src_port(tunnel_session_t *session);
CXX_C_API const char* tunnel_session_get_dst_addr(tunnel_session_t *session);
CXX_C_API int tunnel_session_get_dst_port(tunnel_session_t *session);
CXX_C_API tunnel_session_state_t tunnel_session_get_state(tunnel_session_t *session);
CXX_C_API uint64_t tunnel_session_get_bytes_rx(tunnel_session_t *session);
CXX_C_API uint64_t tunnel_session_get_bytes_tx(tunnel_session_t *session);

/**
 * Close a specific session
 * @param session Session handle
 */
CXX_C_API void tunnel_session_close(tunnel_session_t *session);

/* =============================================================================
 * Utility API
 * ============================================================================= */

/**
 * Get error string
 * @param error Error code
 * @return Human-readable error string
 */
CXX_C_API const char* tunnel_error_string(tunnel_error_t error);

/**
 * Get library version
 * @return Version string (e.g., "1.0.0")
 */
CXX_C_API const char* tunnel_version(void);

/**
 * Initialize default configuration
 * @param config Configuration structure to initialize
 */
CXX_C_API void tunnel_config_init(tunnel_config_t *config);

#ifdef __cplusplus
}
#endif

#endif /* TURBO_TUNNEL_H */
