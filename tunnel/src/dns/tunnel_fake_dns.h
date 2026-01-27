/**
 * @file tunnel_fake_dns.h
 * @brief Fake DNS for domain tracking
 *
 * Assigns fake IP addresses to domain names, enabling:
 * - Domain-based routing rules
 * - Logging of actual hostnames instead of IPs
 * - TLS SNI extraction bypass
 *
 * Works by hijacking DNS queries and returning fake IPs
 * from a reserved range (e.g., 198.18.0.0/15).
 */

#ifndef TUNNEL_FAKE_DNS_H
#define TUNNEL_FAKE_DNS_H

#include "core/tunnel_types.h"

/* =============================================================================
 * Fake DNS Configuration
 * ============================================================================= */

#define TUNNEL_FAKE_DNS_DEFAULT_BASE    0xC6120000  /* 198.18.0.0 */
#define TUNNEL_FAKE_DNS_DEFAULT_MASK    0xFFFE0000  /* /15 (131072 IPs) */
#define TUNNEL_FAKE_DNS_DEFAULT_TTL     300         /* 5 minutes */
#define TUNNEL_FAKE_DNS_TABLE_SIZE      65536       /* Hash table size */

/* =============================================================================
 * Fake DNS API
 * ============================================================================= */

/**
 * Create Fake DNS resolver
 * @param tunnel Parent tunnel handle
 * @param base_ip Base IP in network byte order (e.g., 198.18.0.0)
 * @param mask Network mask in network byte order
 * @param ttl TTL in seconds
 * @return Fake DNS handle or NULL on error
 */
TUNNEL_INTERNAL tunnel_fake_dns_t* tunnel_fake_dns_create(
    tunnel_t *tunnel,
    uint32_t base_ip,
    uint32_t mask,
    int ttl
);

/**
 * Destroy Fake DNS resolver
 * @param dns Fake DNS handle
 */
TUNNEL_INTERNAL void tunnel_fake_dns_destroy(tunnel_fake_dns_t *dns);

/* =============================================================================
 * Domain to IP Mapping
 * ============================================================================= */

/**
 * Get or allocate fake IP for domain
 * If domain already mapped, returns existing IP.
 * Otherwise allocates a new fake IP.
 * @param dns Fake DNS handle
 * @param domain Domain name
 * @return Fake IP in network byte order, or 0 on error
 */
TUNNEL_INTERNAL uint32_t tunnel_fake_dns_get_ip(
    tunnel_fake_dns_t *dns,
    const char *domain
);

/**
 * Lookup domain by fake IP
 * @param dns Fake DNS handle
 * @param fake_ip Fake IP in network byte order
 * @return Domain name or NULL if not found
 */
TUNNEL_INTERNAL const char* tunnel_fake_dns_get_domain(
    tunnel_fake_dns_t *dns,
    uint32_t fake_ip
);

/**
 * Check if IP is in fake DNS range
 * @param dns Fake DNS handle
 * @param ip IP address in network byte order
 * @return 1 if fake IP, 0 otherwise
 */
TUNNEL_INTERNAL int tunnel_fake_dns_is_fake_ip(
    tunnel_fake_dns_t *dns,
    uint32_t ip
);

/* =============================================================================
 * DNS Query Processing
 * ============================================================================= */

/**
 * Process DNS query packet
 * If it's an A/AAAA query, returns fake response.
 * @param dns Fake DNS handle
 * @param query DNS query packet
 * @param query_len Query length
 * @param response Output buffer for response
 * @param response_len Output: response length
 * @param max_len Maximum response buffer size
 * @return 1 if handled (response generated), 0 if should forward
 */
TUNNEL_INTERNAL int tunnel_fake_dns_process_query(
    tunnel_fake_dns_t *dns,
    const uint8_t *query,
    size_t query_len,
    uint8_t *response,
    size_t *response_len,
    size_t max_len
);

/**
 * Extract domain name from DNS query
 * @param query DNS query packet
 * @param query_len Query length
 * @param domain Output buffer
 * @param domain_len Buffer size
 * @return TUNNEL_OK on success
 */
TUNNEL_INTERNAL int tunnel_fake_dns_extract_domain(
    const uint8_t *query,
    size_t query_len,
    char *domain,
    size_t domain_len
);

/* =============================================================================
 * Cache Management
 * ============================================================================= */

/**
 * Expire old mappings
 * @param dns Fake DNS handle
 * @return Number of entries expired
 */
TUNNEL_INTERNAL int tunnel_fake_dns_expire(tunnel_fake_dns_t *dns);

/**
 * Clear all mappings
 * @param dns Fake DNS handle
 */
TUNNEL_INTERNAL void tunnel_fake_dns_clear(tunnel_fake_dns_t *dns);

/**
 * Get number of active mappings
 * @param dns Fake DNS handle
 * @return Number of domain-to-IP mappings
 */
TUNNEL_INTERNAL size_t tunnel_fake_dns_count(tunnel_fake_dns_t *dns);

/* =============================================================================
 * Statistics
 * ============================================================================= */

/**
 * Get Fake DNS statistics
 * @param dns Fake DNS handle
 * @param queries Output: total queries processed
 * @param hits Output: cache hits
 * @param allocations Output: new IP allocations
 */
TUNNEL_INTERNAL void tunnel_fake_dns_get_stats(
    tunnel_fake_dns_t *dns,
    uint64_t *queries,
    uint64_t *hits,
    uint64_t *allocations
);

#endif /* TUNNEL_FAKE_DNS_H */
