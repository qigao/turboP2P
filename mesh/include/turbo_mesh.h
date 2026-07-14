/**
 * @file turbo_mesh.h
 * @brief P2P Mesh VPN - Decentralized ZeroTier-like network
 *
 * Features:
 * - Decentralized peer discovery via DHT
 * - Virtual IP addressing (10.x.x.x/8 or custom)
 * - Direct peer links plus routed mesh forwarding
 * - Zero-config mesh routing
 *
 * Architecture:
 * ┌─────────────────────────────────────────────────────────────┐
 * │                    Application Layer                        │
 * │                  (ping, ssh, curl, etc.)                    │
 * └──────────────────────┬──────────────────────────────────────┘
 *                        │ IP packets
 * ┌──────────────────────▼──────────────────────────────────────┐
 * │                   TUN Device (turbo_tun)                    │
 * │                   Virtual IP: 10.42.x.x/16                  │
 * └──────────────────────┬──────────────────────────────────────┘
 *                        │
 * ┌──────────────────────▼──────────────────────────────────────┐
 * │              Mesh Routing Layer (this module)               │
 * │  - Virtual IP → Peer lookup (DHT)                           │
 * │  - Session management                                       │
 * │  - Packet forwarding                                        │
 * └──────────────────────┬──────────────────────────────────────┘
 *                        │
 * ┌──────────────────────▼──────────────────────────────────────┐
 * │                  P2P Network Layer                          │
 * │  - Peer discovery (p2p + DHT)                               │
 * │  - Stream transport (TurboNet::CoroNet)                        │
 * └─────────────────────────────────────────────────────────────┘
 */

#ifndef TURBO_MESH_H
#define TURBO_MESH_H

#include <stdint.h>
#include <stddef.h>
#include <platform.h>
#ifdef __cplusplus
extern "C" {
#endif


/* =============================================================================
 * Constants
 * ============================================================================= */

#define MESH_DEFAULT_PORT           9993
#define MESH_MAX_PEERS              256
#define MESH_PEER_TIMEOUT_MS        30000    /* 30 seconds */
#define MESH_DHT_REFRESH_MS         60000    /* 1 minute */
#define MESH_PROTOCOL_MAJOR         1
#define MESH_PROTOCOL_MINOR         0
#define MESH_CAP_ROUTED_CONTROL     (1u << 0) /* Reserved until routed origin auth exists */
#define MESH_CAP_SELECTED_PAIR_IP   (1u << 1)
#define MESH_CAP_SIGNED_ROUTES      (1u << 2) /* Reserved */
#define MESH_CAP_POLICY_EPOCH       (1u << 3) /* Reserved */
#define MESH_CAP_LOCAL_DEFAULT      (0u)

/* =============================================================================
 * Error Codes
 * ============================================================================= */

typedef enum {
    MESH_OK = 0,
    MESH_ERR_INVALID_ARG = -1,
    MESH_ERR_NO_MEMORY = -2,
    MESH_ERR_NOT_FOUND = -3,
    MESH_ERR_NETWORK = -4,
    MESH_ERR_TIMEOUT = -5,
    MESH_ERR_ALREADY_EXISTS = -6,
    MESH_ERR_BUSY = -7,
} mesh_error_t;

/* =============================================================================
 * Opaque Handles
 * ============================================================================= */

typedef struct mesh_network_s mesh_network_t;
typedef struct mesh_peer_s mesh_peer_t;

typedef enum {
    MESH_ROUTE_RULE_PINNED = 1u << 0,
} mesh_route_rule_flags_t;

typedef struct {
    const char *dest_cidr;          /* Destination CIDR, e.g. "10.42.5.0/24" */
    const char *next_hop_virtual_ip;/* Direct neighbor virtual IP used as next hop */
    uint32_t flags;                 /* mesh_route_rule_flags_t */
} mesh_route_rule_t;

typedef struct {
    const char *name;               /* Node name or FQDN, e.g. "laptop" */
    const char *virtual_ip;         /* Mesh virtual IP for this name */
} mesh_magic_dns_record_t;

typedef enum {
    MESH_PACKET_POLICY_IN           = 1u << 0, /* packet delivered to this node */
    MESH_PACKET_POLICY_OUT          = 1u << 1, /* packet sent by this node */
    MESH_PACKET_POLICY_FORWARD      = 1u << 2, /* relay forwarding */
    MESH_PACKET_POLICY_LOCAL_EGRESS = 1u << 3, /* subnet/exit local egress */
    MESH_PACKET_POLICY_ANY          = 0x0fu,
} mesh_packet_policy_direction_t;

typedef struct {
    const char *src_cidr;           /* NULL or empty means any source */
    const char *dst_cidr;           /* NULL or empty means any destination */
    uint8_t ip_proto;               /* 0 means any, 1 ICMP, 6 TCP, 17 UDP */
    uint16_t src_port_start;        /* 0 means any source port */
    uint16_t src_port_end;
    uint16_t dst_port_start;        /* 0 means any destination port */
    uint16_t dst_port_end;
    uint32_t directions;            /* mesh_packet_policy_direction_t */
    int allow;                      /* non-zero allow, zero deny */
} mesh_packet_policy_rule_t;

/* =============================================================================
 * Configuration
 * ============================================================================= */

/**
 * Mesh network configuration
 */
typedef struct {
    const char *virtual_ip;         /* Our virtual IP (e.g., "10.42.0.5") */
    uint8_t virtual_prefix;         /* Network prefix (e.g., 16 for /16) */
    int listen_port;                /* P2P listen port (0 for auto) */
    const char *advertise_ip;       /* Real routable IP to publish in DHT */

    /* Bootstrap peers for initial connection */
    const char **bootstrap_peers;   /* Array of "host:port" strings */
    int bootstrap_count;

    /* Network ID (optional) - for isolated networks */
    const char *network_id;         /* NULL for public mesh */
    const char *identity_secret_hex;/* Optional 32-byte node private key as 64 hex chars */

    /* Direct-path discovery */
    int enable_ice;                 /* Enable ICE candidate signaling */
    const char **ice_stun_servers;  /* Array of stun:host:port strings */
    int ice_stun_count;
    int ice_allow_loopback;         /* Useful for local validation */

    /* Route policy */
    const mesh_route_rule_t *route_rules;
    int route_rule_count;
    const char **local_egress_cidrs; /* Router-side local egress CIDRs */
    int local_egress_count;
    const char **local_egress_allow_cidrs; /* Authenticated direct-peer source CIDRs */
    int local_egress_allow_count;

    /* Local MagicDNS static name table */
    const char *magic_dns_domain;   /* Optional suffix, e.g. "mesh.local" */
    const mesh_magic_dns_record_t *magic_dns_records;
    int magic_dns_record_count;

    /* Admission control */
    const char **peer_allow_cidrs;
    int peer_allow_count;
    const char **peer_allow_node_ids;
    int peer_allow_node_id_count;
    unsigned int peer_protocol_major; /* 0 disables protocol-major admission */
    const mesh_packet_policy_rule_t *packet_policy_rules;
    int packet_policy_rule_count;

    /* Callbacks */
    void (*on_peer_connected)(mesh_peer_t *peer, void *user_data);
    void (*on_peer_disconnected)(mesh_peer_t *peer, void *user_data);
    void (*on_packet_received)(const uint8_t *data, size_t len, void *user_data);
    void *user_data;
} mesh_config_t;

/**
 * Runtime ICE configuration.
 *
 * The server strings are copied by mesh_ice_setup(); the caller retains
 * ownership of the array and strings.
 */
typedef struct {
    const char **stun_servers;      /* Array of stun:host:port strings */
    int stun_server_count;          /* Zero disables server-reflexive gathering */
    int allow_loopback;             /* Non-zero permits loopback candidates */
} mesh_ice_config_t;

/* =============================================================================
 * Peer Information
 * ============================================================================= */

typedef struct {
    char virtual_ip[16];            /* Peer's virtual IP */
    char real_ip[64];               /* Peer's real IP:port */
    char node_id[65];               /* Peer's stable node identity/public key */
    uint16_t protocol_major;        /* Peer's advertised mesh protocol major */
    uint16_t protocol_minor;        /* Peer's advertised mesh protocol minor */
    uint32_t capabilities;          /* Peer's advertised mesh capability bits */
    uint32_t negotiated_capabilities; /* Local and peer capability intersection */
    int is_connected;
    uint64_t bytes_tx;
    uint64_t bytes_rx;
    uint64_t last_seen_ms;
} mesh_peer_info_t;

typedef struct {
    char dest_ip[16];               /* Destination virtual IP */
    char dest_real_ip[64];          /* Destination real IP:port if known */
    char next_hop_virtual_ip[16];   /* Direct neighbor used as next hop */
    char next_hop_real_ip[64];      /* Next hop real IP:port */
    uint8_t hop_count;              /* Routed hop count */
    int is_connected;               /* Next hop transport state */
    uint64_t last_update_ms;        /* Route freshness */
} mesh_route_info_t;

typedef struct {
    char dest_cidr[32];
    char next_hop_virtual_ip[16];
    uint32_t flags;
} mesh_route_rule_info_t;

typedef struct {
    char cidr[32];
} mesh_local_egress_info_t;

typedef struct {
    char cidr[32];
} mesh_local_egress_allow_info_t;

typedef struct {
    char cidr[32];
} mesh_peer_allow_info_t;

typedef struct {
    char node_id[65];
} mesh_peer_allow_node_info_t;

typedef struct {
    char name[64];
    char virtual_ip[16];
} mesh_magic_dns_info_t;

typedef struct {
    char src_cidr[32];
    char dst_cidr[32];
    uint8_t ip_proto;
    uint16_t src_port_start;
    uint16_t src_port_end;
    uint16_t dst_port_start;
    uint16_t dst_port_end;
    uint32_t directions;
    int allow;
} mesh_packet_policy_info_t;

/* =============================================================================
 * Statistics
 * ============================================================================= */

typedef struct {
    uint32_t peer_count;            /* Active peers */
    uint64_t bytes_tx;              /* Total bytes sent */
    uint64_t bytes_rx;              /* Total bytes received */
    uint64_t packets_tx;            /* Total packets sent */
    uint64_t packets_rx;            /* Total packets received */
    uint32_t dht_entries;           /* DHT table size */
} mesh_stats_t;

typedef enum {
    MESH_PATH_MODE_ISOLATED = 0,
    MESH_PATH_MODE_DIRECT_ONLY,
    MESH_PATH_MODE_RELAY_ONLY,
    MESH_PATH_MODE_HYBRID,
} mesh_path_mode_t;

typedef struct {
    uint32_t direct_peer_count;
    uint32_t relay_route_count;
    uint32_t connected_relay_route_count;
    uint32_t bootstrap_connect_attempts;
    uint32_t bootstrap_retry_rounds;
    uint32_t bootstrap_reconnect_scheduled;
    uint32_t direct_connect_attempts;
    uint32_t direct_connect_started;
    uint32_t peer_connect_events;
    uint32_t peer_disconnect_events;
    uint32_t control_plane_refreshes;
    uint32_t reconnect_poll_count;
    int bootstrap_reconnect_pending;
    mesh_path_mode_t path_mode;
    char last_reconnect_reason[64];
    char last_direct_attempt_endpoint[64];
    char last_active_relay_next_hop_virtual_ip[16];
    char last_active_relay_next_hop_real_ip[64];
    int ice_enabled;
    uint32_t ice_peer_count;
    uint32_t ice_connected_peer_count;
    uint32_t ice_auth_messages_tx;
    uint32_t ice_auth_messages_rx;
    uint32_t ice_candidate_messages_tx;
    uint32_t ice_candidate_messages_rx;
    uint32_t ice_end_of_candidates_tx;
    uint32_t ice_end_of_candidates_rx;
    uint32_t ice_checks_started;
    uint32_t ice_last_check_local_candidate_count;
    uint32_t ice_last_check_remote_candidate_count;
    char last_ice_state[32];
    char last_ice_selected_local_endpoint[64];
    char last_ice_selected_remote_endpoint[64];
} mesh_diag_info_t;

/* =============================================================================
 * Lifecycle API
 * ============================================================================= */

/**
 * Initialize mesh network
 * @param config Network configuration
 * @return Mesh handle or NULL on error
 */
CXX_C_API mesh_network_t *mesh_create(const mesh_config_t *config);

/**
 * Destroy mesh network
 * @param mesh Mesh handle
 */
CXX_C_API void mesh_destroy(mesh_network_t *mesh);

/**
 * Start mesh network
 * Connects to bootstrap peers and begins routing.
 * @param mesh Mesh handle
 * @return MESH_OK on success
 */
CXX_C_API int mesh_start(mesh_network_t *mesh);

/**
 * Stop mesh network
 * Disconnects all peers.
 * @param mesh Mesh handle
 */
CXX_C_API void mesh_stop(mesh_network_t *mesh);

/* =============================================================================
 * ICE Runtime API
 * ============================================================================= */

/**
 * Replace the ICE configuration while ICE is disabled.
 *
 * Call this from the mesh event-loop thread, not concurrently with mesh_poll().
 * Existing configuration is preserved if validation or allocation fails.
 *
 * Example:
 * @code
 * const char *servers[] = {"stun:stun.cloudflare.com:3478"};
 * mesh_ice_config_t ice = {servers, 1, 0};
 * if (mesh_ice_setup(mesh, &ice) == MESH_OK) {
 *     mesh_ice_enable(mesh);
 * }
 * @endcode
 *
 * @param mesh Mesh handle
 * @param config ICE configuration copied by this call
 * @return MESH_OK, MESH_ERR_INVALID_ARG, MESH_ERR_NO_MEMORY, or MESH_ERR_BUSY
 */
CXX_C_API int mesh_ice_setup(mesh_network_t *mesh, const mesh_ice_config_t *config);

/**
 * Enable ICE and create its runtime resources.
 *
 * The operation is idempotent. Existing connected peers are initialized for
 * ICE immediately. Call from the mesh event-loop thread.
 *
 * @param mesh Mesh handle
 * @return MESH_OK, MESH_ERR_INVALID_ARG, MESH_ERR_NO_MEMORY, or MESH_ERR_BUSY
 */
CXX_C_API int mesh_ice_enable(mesh_network_t *mesh);

/**
 * Disable ICE and release all ICE agents and coroutine resources.
 *
 * The operation is idempotent and does not disconnect the underlying P2P
 * peers. Call from the mesh event-loop thread.
 *
 * @param mesh Mesh handle
 * @return MESH_OK or MESH_ERR_INVALID_ARG
 */
CXX_C_API int mesh_ice_disable(mesh_network_t *mesh);

/* =============================================================================
 * Packet Routing API
 * ============================================================================= */

/**
 * Send IP packet through mesh
 * Called by TUN device when packet is captured.
 * @param mesh Mesh handle
 * @param data IP packet data
 * @param len Packet length
 * @return MESH_OK on success
 */
CXX_C_API int mesh_send_packet(mesh_network_t *mesh, const uint8_t *data, size_t len);

/**
 * Process events (non-blocking)
 * @param mesh Mesh handle
 * @param timeout_ms Timeout in milliseconds
 * @return Number of events processed
 */
CXX_C_API int mesh_poll(mesh_network_t *mesh, int timeout_ms);

/* =============================================================================
 * Peer Management API
 * ============================================================================= */

/**
 * Get number of active peers
 * @param mesh Mesh handle
 * @return Peer count
 */
CXX_C_API int mesh_get_peer_count(mesh_network_t *mesh);

/**
 * Get peer information by index
 * @param mesh Mesh handle
 * @param index Peer index (0 to count-1)
 * @param info Output peer info
 * @return MESH_OK on success
 */
CXX_C_API int mesh_get_peer_info(mesh_network_t *mesh, int index, mesh_peer_info_t *info);

/**
 * Get number of learned routes
 * @param mesh Mesh handle
 * @return Route count
 */
CXX_C_API int mesh_get_route_count(mesh_network_t *mesh);

/**
 * Get route information by index
 * @param mesh Mesh handle
 * @param index Route index (0 to count-1)
 * @param info Output route info
 * @return MESH_OK on success
 */
CXX_C_API int mesh_get_route_info(mesh_network_t *mesh, int index, mesh_route_info_t *info);

/**
 * Get number of configured route rules
 * @param mesh Mesh handle
 * @return Route rule count
 */
CXX_C_API int mesh_get_route_rule_count(mesh_network_t *mesh);

/**
 * Get configured route rule information by index
 * @param mesh Mesh handle
 * @param index Route rule index (0 to count-1)
 * @param info Output route rule info
 * @return MESH_OK on success
 */
CXX_C_API int mesh_get_route_rule_info(mesh_network_t *mesh, int index, mesh_route_rule_info_t *info);

/**
 * Get number of configured local egress CIDRs
 */
CXX_C_API int mesh_get_local_egress_count(mesh_network_t *mesh);

/**
 * Get configured local egress CIDR information by index
 */
CXX_C_API int mesh_get_local_egress_info(mesh_network_t *mesh, int index, mesh_local_egress_info_t *info);

/**
 * Get number of source virtual CIDRs allowed to use local egress
 */
CXX_C_API int mesh_get_local_egress_allow_count(mesh_network_t *mesh);

/**
 * Get configured local egress source allowlist entry by index
 */
CXX_C_API int mesh_get_local_egress_allow_info(mesh_network_t *mesh, int index,
                                               mesh_local_egress_allow_info_t *info);

/**
 * Get configured peer admission allowlist size
 * @param mesh Mesh handle
 * @return Number of allowlist entries
 */
CXX_C_API int mesh_get_peer_allow_count(mesh_network_t *mesh);

/**
 * Get peer admission allowlist entry by index
 * @param mesh Mesh handle
 * @param index Entry index
 * @param info Output allowlist information
 * @return MESH_OK on success
 */
CXX_C_API int mesh_get_peer_allow_info(mesh_network_t *mesh, int index, mesh_peer_allow_info_t *info);

/**
 * Get configured peer admission node-id allowlist size
 * @param mesh Mesh handle
 * @return Number of configured node-id allowlist entries
 */
CXX_C_API int mesh_get_peer_allow_node_id_count(mesh_network_t *mesh);

/**
 * Get peer admission node-id allowlist entry by index
 * @param mesh Mesh handle
 * @param index Zero-based allowlist index
 * @param info Output allowlist information
 * @return MESH_OK on success
 */
CXX_C_API int mesh_get_peer_allow_node_info(mesh_network_t *mesh, int index,
                                            mesh_peer_allow_node_info_t *info);

/**
 * Get configured peer protocol-major admission policy
 * @param mesh Mesh handle
 * @return Required peer protocol major, or 0 when disabled
 */
CXX_C_API unsigned int mesh_get_peer_protocol_major(mesh_network_t *mesh);

/**
 * Get configured packet policy rule count
 */
CXX_C_API int mesh_get_packet_policy_count(mesh_network_t *mesh);

/**
 * Get configured packet policy rule by index
 */
CXX_C_API int mesh_get_packet_policy_info(mesh_network_t *mesh, int index,
                                          mesh_packet_policy_info_t *info);

/**
 * Get number of configured local MagicDNS static records
 */
CXX_C_API int mesh_get_magic_dns_count(mesh_network_t *mesh);

/**
 * Get configured MagicDNS static record by index
 */
CXX_C_API int mesh_get_magic_dns_info(mesh_network_t *mesh, int index,
                                      mesh_magic_dns_info_t *info);

/**
 * Resolve a local MagicDNS name into a mesh virtual IP.
 * Accepts short names and names under magic_dns_domain.
 */
CXX_C_API int mesh_resolve_magic_dns(mesh_network_t *mesh,
                                     const char *name,
                                     char *virtual_ip,
                                     size_t virtual_ip_len);

/**
 * Reverse resolve a mesh virtual IP into a MagicDNS FQDN when configured.
 */
CXX_C_API int mesh_reverse_magic_dns(mesh_network_t *mesh,
                                     const char *virtual_ip,
                                     char *name,
                                     size_t name_len);

/**
 * Copy local node identity/public-key hex into the caller buffer
 * @param mesh Mesh handle
 * @param buf Output buffer
 * @param buf_len Output buffer length; must be at least 65
 * @return MESH_OK on success
 */
CXX_C_API int mesh_get_node_id(mesh_network_t *mesh, char *buf, size_t buf_len);

/**
 * Get peer information from a peer handle
 * @param peer Peer handle
 * @param info Output peer info
 * @return MESH_OK on success
 */
CXX_C_API int mesh_get_peer_handle_info(mesh_peer_t *peer, mesh_peer_info_t *info);

/**
 * Find peer by virtual IP
 * @param mesh Mesh handle
 * @param virtual_ip Virtual IP address
 * @return Peer handle or NULL if not found
 */
CXX_C_API mesh_peer_t *mesh_find_peer(mesh_network_t *mesh, const char *virtual_ip);

/**
 * Connect to peer by virtual IP
 * Initiates connection if not already connected.
 * @param mesh Mesh handle
 * @param virtual_ip Target virtual IP
 * @return MESH_OK on success
 */
CXX_C_API int mesh_connect_peer(mesh_network_t *mesh, const char *virtual_ip);

/**
 * Disconnect peer
 * @param mesh Mesh handle
 * @param peer Peer handle
 */
CXX_C_API void mesh_disconnect_peer(mesh_network_t *mesh, mesh_peer_t *peer);

/* =============================================================================
 * Statistics API
 * ============================================================================= */

/**
 * Get mesh statistics
 * @param mesh Mesh handle
 * @param stats Output statistics
 * @return MESH_OK on success
 */
CXX_C_API int mesh_get_stats(mesh_network_t *mesh, mesh_stats_t *stats);

/**
 * Get mesh diagnostics and reconnect/path-state counters
 * @param mesh Mesh handle
 * @param info Output diagnostics
 * @return MESH_OK on success
 */
CXX_C_API int mesh_get_diag_info(mesh_network_t *mesh, mesh_diag_info_t *info);

/**
 * Read a value already present in the local mesh DHT cache.
 * This is a non-blocking cached read intended for diagnostics.
 */
CXX_C_API int mesh_get_cached_dht_value(mesh_network_t *mesh,
                                        const char *key,
                                        void *buf,
                                        size_t *buf_len);

/**
 * Reset statistics
 * @param mesh Mesh handle
 */
CXX_C_API void mesh_reset_stats(mesh_network_t *mesh);

/* =============================================================================
 * Utility API
 * ============================================================================= */

/**
 * Get error string
 * @param error Error code
 * @return Human-readable error string
 */
CXX_C_API const char *mesh_error_string(mesh_error_t error);

/**
 * Get mesh version
 * @return Version string
 */
CXX_C_API const char *mesh_version(void);

/**
 * Convert path mode to a stable string
 * @param mode Path mode value
 * @return Stable string representation
 */
CXX_C_API const char *mesh_path_mode_string(mesh_path_mode_t mode);

/**
 * Initialize default configuration
 * @param config Configuration to initialize
 */
CXX_C_API void mesh_config_init(mesh_config_t *config);

#ifdef __cplusplus
}
#endif

#endif /* TURBO_MESH_H */
