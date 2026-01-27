/**
 * @file tunnel_fake_dns.c
 * @brief Fake DNS for domain tracking implementation
 */

#include "tunnel_fake_dns.h"
#include "../core/tunnel_types.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

/* =============================================================================
 * Domain Hash Entry
 * ============================================================================= */

typedef struct domain_entry_s {
    char domain[TUNNEL_MAX_DOMAIN];
    uint32_t fake_ip;
    uint64_t expire_time;
    struct domain_entry_s *next;
} domain_entry_t;

/* =============================================================================
 * Internal Structure
 * ============================================================================= */

struct tunnel_fake_dns_s {
    /* IP to domain (direct index by last 16 bits) */
    char **ip_to_domain;
    size_t ip_capacity;

    /* Domain to IP (hash table) */
    domain_entry_t **domain_table;
    size_t domain_table_size;
    size_t domain_count;

    /* Configuration */
    uint32_t base_ip;
    uint32_t mask;
    uint32_t next_ip;
    int ttl;

    /* Statistics */
    uint64_t queries;
    uint64_t hits;
    uint64_t allocations;

    tunnel_t *tunnel;
};

/* =============================================================================
 * Hash Function for Domains
 * ============================================================================= */

static uint32_t domain_hash(const char *domain)
{
    uint32_t hash = 5381;
    int c;

    while ((c = (unsigned char)*domain++)) {
        /* Case-insensitive hash */
        hash = ((hash << 5) + hash) + tolower(c);
    }

    return hash;
}

/* =============================================================================
 * Domain Normalization (lowercase)
 * ============================================================================= */

static void normalize_domain(const char *src, char *dst, size_t dst_len)
{
    size_t i;
    for (i = 0; i < dst_len - 1 && src[i]; i++) {
        dst[i] = tolower((unsigned char)src[i]);
    }
    dst[i] = '\0';
}

/* =============================================================================
 * Fake DNS Lifecycle
 * ============================================================================= */

tunnel_fake_dns_t* tunnel_fake_dns_create(tunnel_t *tunnel,
                                           uint32_t base_ip,
                                           uint32_t mask,
                                           int ttl)
{
    tunnel_fake_dns_t *dns = calloc(1, sizeof(tunnel_fake_dns_t));
    if (!dns) return NULL;

    dns->tunnel = tunnel;
    dns->base_ip = ntohl(base_ip);
    dns->mask = ntohl(mask);
    dns->next_ip = dns->base_ip;
    dns->ttl = ttl;

    /* Calculate IP range capacity */
    dns->ip_capacity = (~dns->mask) + 1;
    if (dns->ip_capacity > TUNNEL_FAKE_DNS_SIZE) {
        dns->ip_capacity = TUNNEL_FAKE_DNS_SIZE;
    }

    /* Allocate IP to domain array */
    dns->ip_to_domain = calloc(dns->ip_capacity, sizeof(char *));
    if (!dns->ip_to_domain) {
        free(dns);
        return NULL;
    }

    /* Allocate domain hash table */
    dns->domain_table_size = TUNNEL_FAKE_DNS_TABLE_SIZE;
    dns->domain_table = calloc(dns->domain_table_size, sizeof(domain_entry_t *));
    if (!dns->domain_table) {
        free(dns->ip_to_domain);
        free(dns);
        return NULL;
    }

    return dns;
}

void tunnel_fake_dns_destroy(tunnel_fake_dns_t *dns)
{
    if (!dns) return;

    /* Free domain strings */
    for (size_t i = 0; i < dns->ip_capacity; i++) {
        free(dns->ip_to_domain[i]);
    }
    free(dns->ip_to_domain);

    /* Free domain hash table */
    for (size_t i = 0; i < dns->domain_table_size; i++) {
        domain_entry_t *entry = dns->domain_table[i];
        while (entry) {
            domain_entry_t *next = entry->next;
            free(entry);
            entry = next;
        }
    }
    free(dns->domain_table);

    free(dns);
}

/* =============================================================================
 * Domain to IP Mapping
 * ============================================================================= */

uint32_t tunnel_fake_dns_get_ip(tunnel_fake_dns_t *dns, const char *domain)
{
    if (!dns || !domain || domain[0] == '\0') return 0;

    dns->queries++;

    /* Normalize domain */
    char normalized[TUNNEL_MAX_DOMAIN];
    normalize_domain(domain, normalized, sizeof(normalized));

    /* Look up in hash table */
    uint32_t hash = domain_hash(normalized);
    uint32_t index = hash % dns->domain_table_size;

    domain_entry_t *entry = dns->domain_table[index];
    while (entry) {
        if (strcmp(entry->domain, normalized) == 0) {
            dns->hits++;
            return entry->fake_ip;
        }
        entry = entry->next;
    }

    /* Not found, allocate new IP */
    dns->allocations++;

    /* Find next available IP */
    uint32_t start_ip = dns->next_ip;
    uint32_t ip = start_ip;

    do {
        uint32_t ip_index = ip - dns->base_ip;
        if (ip_index < dns->ip_capacity && dns->ip_to_domain[ip_index] == NULL) {
            /* Found free slot */
            break;
        }

        ip++;
        if ((ip & ~dns->mask) == 0) {
            ip = dns->base_ip;  /* Wrap around */
        }
    } while (ip != start_ip);

    uint32_t ip_index = ip - dns->base_ip;
    if (ip_index >= dns->ip_capacity || dns->ip_to_domain[ip_index] != NULL) {
        /* IP space exhausted */
        return 0;
    }

    /* Store mapping */
    dns->ip_to_domain[ip_index] = strdup(normalized);
    if (!dns->ip_to_domain[ip_index]) {
        return 0;
    }

    /* Add to hash table */
    entry = calloc(1, sizeof(domain_entry_t));
    if (!entry) {
        free(dns->ip_to_domain[ip_index]);
        dns->ip_to_domain[ip_index] = NULL;
        return 0;
    }

    strncpy(entry->domain, normalized, sizeof(entry->domain) - 1);
    entry->fake_ip = htonl(ip);
    entry->expire_time = time(NULL) + dns->ttl;
    entry->next = dns->domain_table[index];
    dns->domain_table[index] = entry;
    dns->domain_count++;

    /* Update next IP */
    dns->next_ip = ip + 1;
    if ((dns->next_ip & ~dns->mask) == 0) {
        dns->next_ip = dns->base_ip;
    }

    return entry->fake_ip;
}

const char* tunnel_fake_dns_get_domain(tunnel_fake_dns_t *dns, uint32_t fake_ip)
{
    if (!dns) return NULL;

    uint32_t ip = ntohl(fake_ip);

    /* Check if in range */
    if ((ip & dns->mask) != (dns->base_ip & dns->mask)) {
        return NULL;
    }

    uint32_t index = ip - dns->base_ip;
    if (index >= dns->ip_capacity) {
        return NULL;
    }

    return dns->ip_to_domain[index];
}

int tunnel_fake_dns_is_fake_ip(tunnel_fake_dns_t *dns, uint32_t ip)
{
    if (!dns) return 0;

    uint32_t ip_host = ntohl(ip);
    return (ip_host & dns->mask) == (dns->base_ip & dns->mask);
}

/* =============================================================================
 * DNS Query Processing
 * ============================================================================= */

int tunnel_fake_dns_extract_domain(const uint8_t *query, size_t query_len,
                                    char *domain, size_t domain_len)
{
    if (!query || !domain || query_len < 12 || domain_len < 1) {
        return TUNNEL_ERR_INVALID_ARG;
    }

    /* Skip DNS header (12 bytes) */
    const uint8_t *ptr = query + 12;
    size_t remaining = query_len - 12;
    size_t domain_pos = 0;

    while (remaining > 0) {
        uint8_t label_len = *ptr++;
        remaining--;

        if (label_len == 0) {
            /* End of domain name */
            break;
        }

        if (label_len > 63 || label_len > remaining) {
            return TUNNEL_ERR_INVALID_ARG;
        }

        /* Add dot separator */
        if (domain_pos > 0) {
            if (domain_pos >= domain_len - 1) break;
            domain[domain_pos++] = '.';
        }

        /* Copy label */
        for (uint8_t i = 0; i < label_len && domain_pos < domain_len - 1; i++) {
            domain[domain_pos++] = *ptr++;
            remaining--;
        }
    }

    domain[domain_pos] = '\0';
    return TUNNEL_OK;
}

int tunnel_fake_dns_process_query(tunnel_fake_dns_t *dns,
                                   const uint8_t *query, size_t query_len,
                                   uint8_t *response, size_t *response_len,
                                   size_t max_len)
{
    if (!dns || !query || !response || !response_len) return 0;

    /* Extract domain from query */
    char domain[TUNNEL_MAX_DOMAIN];
    if (tunnel_fake_dns_extract_domain(query, query_len, domain, sizeof(domain)) != TUNNEL_OK) {
        return 0;
    }

    /* Check query type (must be A record, type 1) */
    if (query_len < 16) return 0;

    /* Find the end of the question section to check type */
    const uint8_t *ptr = query + 12;
    while (ptr < query + query_len && *ptr != 0) {
        ptr += *ptr + 1;
    }
    ptr++;  /* Skip null terminator */

    if (ptr + 4 > query + query_len) return 0;

    uint16_t qtype = (ptr[0] << 8) | ptr[1];
    uint16_t qclass = (ptr[2] << 8) | ptr[3];

    /* Only handle A record queries (type 1, class IN) */
    if (qtype != 1 || qclass != 1) {
        return 0;
    }

    /* Get or allocate fake IP */
    uint32_t fake_ip = tunnel_fake_dns_get_ip(dns, domain);
    if (fake_ip == 0) {
        return 0;
    }

    /* Build response */
    if (max_len < query_len + 16) {
        return 0;
    }

    /* Copy query as base */
    memcpy(response, query, query_len);

    /* Set response flags */
    response[2] = 0x81;  /* QR=1, Opcode=0, AA=0, TC=0, RD=1 */
    response[3] = 0x80;  /* RA=1, Z=0, RCODE=0 */

    /* Set answer count to 1 */
    response[6] = 0x00;
    response[7] = 0x01;

    /* Append answer */
    size_t answer_offset = query_len;

    /* Name pointer to question */
    response[answer_offset++] = 0xC0;
    response[answer_offset++] = 0x0C;

    /* Type A */
    response[answer_offset++] = 0x00;
    response[answer_offset++] = 0x01;

    /* Class IN */
    response[answer_offset++] = 0x00;
    response[answer_offset++] = 0x01;

    /* TTL */
    response[answer_offset++] = (dns->ttl >> 24) & 0xFF;
    response[answer_offset++] = (dns->ttl >> 16) & 0xFF;
    response[answer_offset++] = (dns->ttl >> 8) & 0xFF;
    response[answer_offset++] = dns->ttl & 0xFF;

    /* RDLENGTH */
    response[answer_offset++] = 0x00;
    response[answer_offset++] = 0x04;

    /* RDATA (IP address) */
    memcpy(&response[answer_offset], &fake_ip, 4);
    answer_offset += 4;

    *response_len = answer_offset;
    return 1;
}

/* =============================================================================
 * Cache Management
 * ============================================================================= */

int tunnel_fake_dns_expire(tunnel_fake_dns_t *dns)
{
    if (!dns) return 0;

    time_t now = time(NULL);
    int expired = 0;

    for (size_t i = 0; i < dns->domain_table_size; i++) {
        domain_entry_t **pp = &dns->domain_table[i];
        while (*pp) {
            domain_entry_t *entry = *pp;
            if ((time_t)entry->expire_time < now) {
                /* Remove from hash table */
                *pp = entry->next;

                /* Free IP mapping */
                uint32_t ip = ntohl(entry->fake_ip);
                uint32_t ip_index = ip - dns->base_ip;
                if (ip_index < dns->ip_capacity) {
                    free(dns->ip_to_domain[ip_index]);
                    dns->ip_to_domain[ip_index] = NULL;
                }

                free(entry);
                dns->domain_count--;
                expired++;
            } else {
                pp = &entry->next;
            }
        }
    }

    return expired;
}

void tunnel_fake_dns_clear(tunnel_fake_dns_t *dns)
{
    if (!dns) return;

    /* Clear IP to domain */
    for (size_t i = 0; i < dns->ip_capacity; i++) {
        free(dns->ip_to_domain[i]);
        dns->ip_to_domain[i] = NULL;
    }

    /* Clear domain hash table */
    for (size_t i = 0; i < dns->domain_table_size; i++) {
        domain_entry_t *entry = dns->domain_table[i];
        while (entry) {
            domain_entry_t *next = entry->next;
            free(entry);
            entry = next;
        }
        dns->domain_table[i] = NULL;
    }

    dns->domain_count = 0;
    dns->next_ip = dns->base_ip;
}

size_t tunnel_fake_dns_count(tunnel_fake_dns_t *dns)
{
    return dns ? dns->domain_count : 0;
}

/* =============================================================================
 * Statistics
 * ============================================================================= */

void tunnel_fake_dns_get_stats(tunnel_fake_dns_t *dns,
                                uint64_t *queries,
                                uint64_t *hits,
                                uint64_t *allocations)
{
    if (!dns) return;
    if (queries) *queries = dns->queries;
    if (hits) *hits = dns->hits;
    if (allocations) *allocations = dns->allocations;
}
