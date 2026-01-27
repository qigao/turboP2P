/**
 * @file turbo_mesh.h
 * @brief P2P Mesh VPN - Decentralized ZeroTier-like network
 *
 * Features:
 * - Decentralized peer discovery via DHT
 * - NAT traversal via ICE (STUN/TURN)
 * - Encrypted tunnels via WebRTC DataChannel (DTLS)
 * - Virtual IP addressing (10.x.x.x/8 or custom)
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
 * │  - NAT traversal (ice)                                      │
 * │  - Encrypted tunnel (webrtc DataChannel)                    │
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
} mesh_error_t;

/* =============================================================================
 * Opaque Handles
 * ============================================================================= */

typedef struct mesh_network_s mesh_network_t;
typedef struct mesh_peer_s mesh_peer_t;

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

    /* Bootstrap peers for initial connection */
    const char **bootstrap_peers;   /* Array of "host:port" strings */
    int bootstrap_count;

    /* Network ID (optional) - for isolated networks */
    const char *network_id;         /* NULL for public mesh */

    /* Callbacks */
    void (*on_peer_connected)(mesh_peer_t *peer, void *user_data);
    void (*on_peer_disconnected)(mesh_peer_t *peer, void *user_data);
    void (*on_packet_received)(const uint8_t *data, size_t len, void *user_data);
    void *user_data;
} mesh_config_t;

/* =============================================================================
 * Peer Information
 * ============================================================================= */

typedef struct {
    char virtual_ip[16];            /* Peer's virtual IP */
    char real_ip[64];               /* Peer's real IP:port */
    int is_connected;
    uint64_t bytes_tx;
    uint64_t bytes_rx;
    uint64_t last_seen_ms;
} mesh_peer_info_t;

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
 * Initialize default configuration
 * @param config Configuration to initialize
 */
CXX_C_API void mesh_config_init(mesh_config_t *config);

#ifdef __cplusplus
}
#endif

#endif /* TURBO_MESH_H */
