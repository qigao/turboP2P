/**
 * @file tunnel_nat.h
 * @brief NAT table and connection tracking
 *
 * Provides:
 * - Hash table for O(1) session lookup by 5-tuple
 * - LRU list for session expiry
 * - UDP port allocation for NAT
 * - Reverse NAT for incoming packets
 */

#ifndef TUNNEL_NAT_H
#define TUNNEL_NAT_H

#include "core/tunnel_types.h"

/* =============================================================================
 * NAT Configuration
 * ============================================================================= */

#define TUNNEL_NAT_HASH_BITS        16      /* 65536 buckets */
#define TUNNEL_NAT_HASH_SIZE        (1 << TUNNEL_NAT_HASH_BITS)
#define TUNNEL_NAT_MAX_SESSIONS     65536
#define TUNNEL_NAT_UDP_PORT_MIN     10000   /* Dynamic port range */
#define TUNNEL_NAT_UDP_PORT_MAX     60000

/* =============================================================================
 * NAT Table API
 * ============================================================================= */

/**
 * Create NAT table
 * @param tunnel Parent tunnel handle
 * @return NAT handle or NULL on error
 */
TUNNEL_INTERNAL tunnel_nat_t* tunnel_nat_create(tunnel_t *tunnel);

/**
 * Destroy NAT table
 * @param nat NAT handle
 */
TUNNEL_INTERNAL void tunnel_nat_destroy(tunnel_nat_t *nat);

/**
 * Clear all NAT entries
 * @param nat NAT handle
 */
TUNNEL_INTERNAL void tunnel_nat_clear(tunnel_nat_t *nat);

/* =============================================================================
 * Session Hash Table Operations
 * ============================================================================= */

/**
 * Compute hash for session key
 * Uses fast hash combining src/dst/port/protocol.
 * @param key Session key
 * @return Hash value
 */
TUNNEL_INTERNAL uint32_t tunnel_nat_hash(const tunnel_session_key_t *key);

/**
 * Insert session into NAT table
 * @param nat NAT handle
 * @param session Session to insert
 * @return TUNNEL_OK on success, error if table full
 */
TUNNEL_INTERNAL int tunnel_nat_insert(
    tunnel_nat_t *nat,
    tunnel_session_t *session
);

/**
 * Remove session from NAT table
 * @param nat NAT handle
 * @param session Session to remove
 */
TUNNEL_INTERNAL void tunnel_nat_remove(
    tunnel_nat_t *nat,
    tunnel_session_t *session
);

/**
 * Lookup session by key
 * @param nat NAT handle
 * @param key Session key (5-tuple)
 * @return Session or NULL if not found
 */
TUNNEL_INTERNAL tunnel_session_t* tunnel_nat_lookup(
    tunnel_nat_t *nat,
    const tunnel_session_key_t *key
);

/**
 * Lookup session by source endpoint only (for UDP replies)
 * Used when proxy sends data back.
 * @param nat NAT handle
 * @param src Source endpoint (proxy-side)
 * @param protocol Protocol number
 * @return Session or NULL if not found
 */
TUNNEL_INTERNAL tunnel_session_t* tunnel_nat_lookup_by_src(
    tunnel_nat_t *nat,
    const tunnel_endpoint_t *src,
    uint8_t protocol
);

/* =============================================================================
 * LRU Management
 * ============================================================================= */

/**
 * Move session to front of LRU list
 * Call when session has activity.
 * @param nat NAT handle
 * @param session Session to touch
 */
TUNNEL_INTERNAL void tunnel_nat_touch(
    tunnel_nat_t *nat,
    tunnel_session_t *session
);

/**
 * Get oldest session (LRU tail)
 * @param nat NAT handle
 * @return Oldest session or NULL if empty
 */
TUNNEL_INTERNAL tunnel_session_t* tunnel_nat_get_oldest(tunnel_nat_t *nat);

/**
 * Evict oldest sessions if over limit
 * @param nat NAT handle
 * @param max_sessions Maximum allowed sessions
 * @return Number of sessions evicted
 */
TUNNEL_INTERNAL int tunnel_nat_evict_oldest(
    tunnel_nat_t *nat,
    size_t max_sessions
);

/**
 * Evict expired sessions
 * @param nat NAT handle
 * @param tcp_timeout_ms TCP session timeout
 * @param udp_timeout_ms UDP session timeout
 * @return Number of sessions evicted
 */
TUNNEL_INTERNAL int tunnel_nat_evict_expired(
    tunnel_nat_t *nat,
    uint32_t tcp_timeout_ms,
    uint32_t udp_timeout_ms
);

/* =============================================================================
 * UDP Port Allocation
 * ============================================================================= */

/**
 * Allocate a UDP port for NAT
 * @param nat NAT handle
 * @return Port number or 0 if exhausted
 */
TUNNEL_INTERNAL uint16_t tunnel_nat_alloc_udp_port(tunnel_nat_t *nat);

/**
 * Free a UDP port
 * @param nat NAT handle
 * @param port Port to free
 */
TUNNEL_INTERNAL void tunnel_nat_free_udp_port(tunnel_nat_t *nat, uint16_t port);

/**
 * Check if UDP port is in use
 * @param nat NAT handle
 * @param port Port to check
 * @return 1 if in use, 0 if free
 */
TUNNEL_INTERNAL int tunnel_nat_udp_port_in_use(tunnel_nat_t *nat, uint16_t port);

/* =============================================================================
 * Reverse NAT (for incoming packets)
 * ============================================================================= */

/**
 * Create reverse NAT key
 * Swaps src/dst for lookup.
 * @param key Original key
 * @param reverse Output reverse key
 */
TUNNEL_INTERNAL void tunnel_nat_reverse_key(
    const tunnel_session_key_t *key,
    tunnel_session_key_t *reverse
);

/**
 * Lookup by reverse key
 * Used for packets coming from proxy to TUN.
 * @param nat NAT handle
 * @param dst Destination (was original source)
 * @param src Source (was original destination)
 * @param protocol Protocol number
 * @return Session or NULL if not found
 */
TUNNEL_INTERNAL tunnel_session_t* tunnel_nat_lookup_reverse(
    tunnel_nat_t *nat,
    const tunnel_endpoint_t *dst,
    const tunnel_endpoint_t *src,
    uint8_t protocol
);

/* =============================================================================
 * Statistics
 * ============================================================================= */

/**
 * Get NAT statistics
 * @param nat NAT handle
 * @param lookups Output: total lookups
 * @param hits Output: successful lookups
 * @param misses Output: failed lookups
 * @param evictions Output: LRU evictions
 */
TUNNEL_INTERNAL void tunnel_nat_get_stats(
    tunnel_nat_t *nat,
    uint64_t *lookups,
    uint64_t *hits,
    uint64_t *misses,
    uint64_t *evictions
);

/**
 * Reset NAT statistics
 * @param nat NAT handle
 */
TUNNEL_INTERNAL void tunnel_nat_reset_stats(tunnel_nat_t *nat);

/**
 * Get session count
 * @param nat NAT handle
 * @return Number of sessions in table
 */
TUNNEL_INTERNAL size_t tunnel_nat_session_count(tunnel_nat_t *nat);

/**
 * Get hash table load factor
 * @param nat NAT handle
 * @return Load factor (0.0 - 1.0)
 */
TUNNEL_INTERNAL double tunnel_nat_load_factor(tunnel_nat_t *nat);

/* =============================================================================
 * Session Key Utilities
 * ============================================================================= */

/**
 * Compare two session keys
 * @param a First key
 * @param b Second key
 * @return 0 if equal, non-zero if different
 */
TUNNEL_INTERNAL int tunnel_session_key_compare(
    const tunnel_session_key_t *a,
    const tunnel_session_key_t *b
);

/* tunnel_session_key_copy is provided as static inline in tunnel_types.h */

/**
 * Format session key as string (for logging)
 * @param key Session key
 * @param buf Output buffer
 * @param len Buffer length
 * @return buf pointer
 */
TUNNEL_INTERNAL char* tunnel_session_key_format(
    const tunnel_session_key_t *key,
    char *buf,
    size_t len
);

/* =============================================================================
 * Endpoint Utilities
 * ============================================================================= */

/**
 * Compare two endpoints
 * @param a First endpoint
 * @param b Second endpoint
 * @return 0 if equal, non-zero if different
 */
TUNNEL_INTERNAL int tunnel_endpoint_compare(
    const tunnel_endpoint_t *a,
    const tunnel_endpoint_t *b
);

/* tunnel_endpoint_copy is provided as static inline in tunnel_types.h */

/**
 * Format endpoint as string
 * @param ep Endpoint
 * @param buf Output buffer
 * @param len Buffer length
 * @return buf pointer
 */
TUNNEL_INTERNAL char* tunnel_endpoint_format(
    const tunnel_endpoint_t *ep,
    char *buf,
    size_t len
);

/**
 * Parse endpoint from string
 * Formats: "1.2.3.4:80" or "[::1]:80"
 * @param str String to parse
 * @param ep Output endpoint
 * @return TUNNEL_OK on success
 */
TUNNEL_INTERNAL int tunnel_endpoint_parse(
    const char *str,
    tunnel_endpoint_t *ep
);

#endif /* TUNNEL_NAT_H */
