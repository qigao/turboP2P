/**
 * @file tunnel_session.h
 * @brief Session lifecycle management
 *
 * Manages individual tunnel sessions representing connections
 * between local applications and remote servers through the proxy.
 */

#ifndef TUNNEL_SESSION_H
#define TUNNEL_SESSION_H

#include "core/tunnel_types.h"

/* =============================================================================
 * Session Pool Configuration
 * ============================================================================= */

#define TUNNEL_SESSION_POOL_SIZE    4096    /* Pre-allocated sessions */
#define TUNNEL_SESSION_RECV_BUF     32768   /* Per-session receive buffer */
#define TUNNEL_SESSION_SEND_BUF     32768   /* Per-session send buffer */

/* =============================================================================
 * TCP FSM States (simplified)
 * ============================================================================= */

typedef enum {
    TUNNEL_TCP_CLOSED = 0,
    TUNNEL_TCP_SYN_RECEIVED,
    TUNNEL_TCP_SYN_SENT,
    TUNNEL_TCP_ESTABLISHED,
    TUNNEL_TCP_FIN_WAIT_1,
    TUNNEL_TCP_FIN_WAIT_2,
    TUNNEL_TCP_CLOSING,
    TUNNEL_TCP_TIME_WAIT,
    TUNNEL_TCP_CLOSE_WAIT,
    TUNNEL_TCP_LAST_ACK,
} tunnel_tcp_state_t;

/* =============================================================================
 * Session Manager API
 * ============================================================================= */

/**
 * Create session manager
 * @param tunnel Parent tunnel handle
 * @return Session manager or NULL on error
 */
TUNNEL_INTERNAL tunnel_nat_t* tunnel_session_manager_create(tunnel_t *tunnel);

/**
 * Destroy session manager
 * Frees all sessions and resources.
 * @param nat Session manager handle
 */
TUNNEL_INTERNAL void tunnel_session_manager_destroy(tunnel_nat_t *nat);

/* =============================================================================
 * Session Lifecycle
 * ============================================================================= */

/**
 * Create new session
 * Allocates and initializes a session for a new connection.
 * @param tunnel Tunnel handle
 * @param key Session key (src/dst/protocol)
 * @return Session handle or NULL if table full
 */
TUNNEL_INTERNAL tunnel_session_t* tunnel_session_create(
    tunnel_t *tunnel,
    const tunnel_session_key_t *key
);

/**
 * Find existing session
 * @param tunnel Tunnel handle
 * @param key Session key
 * @return Session handle or NULL if not found
 */
TUNNEL_INTERNAL tunnel_session_t* tunnel_session_find(
    tunnel_t *tunnel,
    const tunnel_session_key_t *key
);

/**
 * Find or create session
 * @param tunnel Tunnel handle
 * @param key Session key
 * @param created Output: set to 1 if newly created
 * @return Session handle or NULL on error
 */
TUNNEL_INTERNAL tunnel_session_t* tunnel_session_find_or_create(
    tunnel_t *tunnel,
    const tunnel_session_key_t *key,
    int *created
);

/**
 * Destroy session
 * Closes proxy connection and frees resources.
 * @param session Session handle
 */
TUNNEL_INTERNAL void tunnel_session_destroy(tunnel_session_t *session);

/**
 * Update session activity timestamp
 * Moves session to front of LRU list.
 * @param session Session handle
 */
TUNNEL_INTERNAL void tunnel_session_touch(tunnel_session_t *session);

/* =============================================================================
 * Session State Management
 * ============================================================================= */

/**
 * Set session state
 * @param session Session handle
 * @param state New state
 */
TUNNEL_INTERNAL void tunnel_session_set_state(
    tunnel_session_t *session,
    tunnel_session_state_t state
);

/**
 * Check if session is established
 * @param session Session handle
 * @return 1 if established, 0 otherwise
 */
TUNNEL_INTERNAL int tunnel_session_is_established(tunnel_session_t *session);

/* =============================================================================
 * TCP State Machine
 * ============================================================================= */

/**
 * Handle incoming TCP SYN
 * Creates session and initiates proxy connection.
 * @param tunnel Tunnel handle
 * @param src Source endpoint
 * @param dst Destination endpoint
 * @param seq Initial sequence number
 * @return Session handle or NULL on error
 */
TUNNEL_INTERNAL tunnel_session_t* tunnel_session_tcp_syn(
    tunnel_t *tunnel,
    const tunnel_endpoint_t *src,
    const tunnel_endpoint_t *dst,
    uint32_t seq
);

/**
 * Handle TCP data
 * @param session Session handle
 * @param seq Sequence number
 * @param data Payload data
 * @param len Payload length
 * @return TUNNEL_OK on success
 */
TUNNEL_INTERNAL int tunnel_session_tcp_data(
    tunnel_session_t *session,
    uint32_t seq,
    const uint8_t *data,
    size_t len
);

/**
 * Handle TCP ACK
 * @param session Session handle
 * @param ack Acknowledgment number
 * @param window Window size
 * @return TUNNEL_OK on success
 */
TUNNEL_INTERNAL int tunnel_session_tcp_ack(
    tunnel_session_t *session,
    uint32_t ack,
    uint16_t window
);

/**
 * Handle TCP FIN
 * @param session Session handle
 * @param seq Sequence number
 * @return TUNNEL_OK on success
 */
TUNNEL_INTERNAL int tunnel_session_tcp_fin(
    tunnel_session_t *session,
    uint32_t seq
);

/**
 * Handle TCP RST
 * @param session Session handle
 * @return TUNNEL_OK on success
 */
TUNNEL_INTERNAL int tunnel_session_tcp_rst(tunnel_session_t *session);

/**
 * Get TCP state
 * @param session Session handle
 * @return TCP FSM state
 */
TUNNEL_INTERNAL tunnel_tcp_state_t tunnel_session_tcp_get_state(
    tunnel_session_t *session
);

/* =============================================================================
 * TCP Packet Helpers
 * ============================================================================= */

/**
 * Send SYN-ACK to client
 * @param session Session handle
 * @return TUNNEL_OK on success
 */
TUNNEL_INTERNAL int tunnel_session_send_synack(tunnel_session_t *session);

/**
 * Send RST to client
 * @param session Session handle
 * @return TUNNEL_OK on success
 */
TUNNEL_INTERNAL int tunnel_session_send_rst(tunnel_session_t *session);

/**
 * Send FIN to client
 * @param session Session handle
 * @return TUNNEL_OK on success
 */
TUNNEL_INTERNAL int tunnel_session_send_fin(tunnel_session_t *session);

/**
 * Send ACK to client
 * @param session Session handle
 * @return TUNNEL_OK on success
 */
TUNNEL_INTERNAL int tunnel_session_send_ack(tunnel_session_t *session);

/* =============================================================================
 * UDP Session Management
 * ============================================================================= */

/**
 * Handle incoming UDP datagram
 * Creates or finds session and forwards to proxy.
 * @param tunnel Tunnel handle
 * @param src Source endpoint
 * @param dst Destination endpoint
 * @param data Datagram payload
 * @param len Payload length
 * @return TUNNEL_OK on success
 */
TUNNEL_INTERNAL int tunnel_session_udp_datagram(
    tunnel_t *tunnel,
    const tunnel_endpoint_t *src,
    const tunnel_endpoint_t *dst,
    const uint8_t *data,
    size_t len
);

/* =============================================================================
 * Session Data Transfer
 * ============================================================================= */

/**
 * Send data to proxy (from TUN)
 * @param session Session handle
 * @param data Data to send
 * @param len Data length
 * @return TUNNEL_OK on success
 */
TUNNEL_INTERNAL int tunnel_session_send_to_proxy(
    tunnel_session_t *session,
    const uint8_t *data,
    size_t len
);

/**
 * Send data to TUN (from proxy)
 * @param session Session handle
 * @param data Data to send
 * @param len Data length
 * @return TUNNEL_OK on success
 */
TUNNEL_INTERNAL int tunnel_session_send_to_tun(
    tunnel_session_t *session,
    const uint8_t *data,
    size_t len
);

/**
 * Flush pending send buffer
 * @param session Session handle
 * @return Number of bytes flushed
 */
TUNNEL_INTERNAL size_t tunnel_session_flush(tunnel_session_t *session);

/* =============================================================================
 * Session Timeout Management
 * ============================================================================= */

/**
 * Check and expire old sessions
 * Called periodically by tunnel timer.
 * @param tunnel Tunnel handle
 * @return Number of sessions expired
 */
TUNNEL_INTERNAL int tunnel_session_expire_check(tunnel_t *tunnel);

/**
 * Set session timeout
 * @param session Session handle
 * @param timeout_ms Timeout in milliseconds (0 for default)
 */
TUNNEL_INTERNAL void tunnel_session_set_timeout(
    tunnel_session_t *session,
    uint32_t timeout_ms
);

/**
 * Get session age
 * @param session Session handle
 * @return Milliseconds since creation
 */
TUNNEL_INTERNAL uint64_t tunnel_session_get_age(tunnel_session_t *session);

/**
 * Get session idle time
 * @param session Session handle
 * @return Milliseconds since last activity
 */
TUNNEL_INTERNAL uint64_t tunnel_session_get_idle(tunnel_session_t *session);

/* =============================================================================
 * Session Iteration
 * ============================================================================= */

/**
 * Iterate over all sessions
 * @param tunnel Tunnel handle
 * @param callback Called for each session (return 0 to continue)
 * @param user_data User context
 */
TUNNEL_INTERNAL void tunnel_session_foreach(
    tunnel_t *tunnel,
    int (*callback)(tunnel_session_t *session, void *user_data),
    void *user_data
);

/**
 * Get session count
 * @param tunnel Tunnel handle
 * @return Number of active sessions
 */
TUNNEL_INTERNAL size_t tunnel_session_count(tunnel_t *tunnel);

/**
 * Get TCP session count
 * @param tunnel Tunnel handle
 * @return Number of active TCP sessions
 */
TUNNEL_INTERNAL size_t tunnel_session_tcp_count(tunnel_t *tunnel);

/**
 * Get UDP session count
 * @param tunnel Tunnel handle
 * @return Number of active UDP sessions
 */
TUNNEL_INTERNAL size_t tunnel_session_udp_count(tunnel_t *tunnel);

/* =============================================================================
 * Domain Resolution
 * ============================================================================= */

/**
 * Set session domain name
 * Called when domain is resolved via Fake DNS.
 * @param session Session handle
 * @param domain Domain name
 */
TUNNEL_INTERNAL void tunnel_session_set_domain(
    tunnel_session_t *session,
    const char *domain
);

/**
 * Get session domain name
 * @param session Session handle
 * @return Domain name or NULL if IP-based
 */
TUNNEL_INTERNAL const char* tunnel_session_get_domain(
    tunnel_session_t *session
);

#endif /* TUNNEL_SESSION_H */
