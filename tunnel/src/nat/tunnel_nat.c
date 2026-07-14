/**
 * @file tunnel_nat.c
 * @brief NAT table and connection tracking implementation
 */

#include "tunnel_nat.h"
#include "../core/tunnel_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fmt.h>


/* =============================================================================
 * Hash Function (FNV-1a)
 * ============================================================================= */

uint32_t tunnel_nat_hash(const tunnel_session_key_t *key) {
  uint32_t hash = 2166136261u;
  const uint8_t *data;
  size_t len;

  /* Hash source address */
  if (key->src.family == AF_INET) {
    data = (const uint8_t *)&key->src.addr.v4;
    len = 4;
  } else {
    data = key->src.addr.v6;
    len = 16;
  }
  for (size_t i = 0; i < len; i++) {
    hash ^= data[i];
    hash *= 16777619u;
  }

  /* Hash source port */
  hash ^= (key->src.port >> 8);
  hash *= 16777619u;
  hash ^= (key->src.port & 0xFF);
  hash *= 16777619u;

  /* Hash destination address */
  if (key->dst.family == AF_INET) {
    data = (const uint8_t *)&key->dst.addr.v4;
    len = 4;
  } else {
    data = key->dst.addr.v6;
    len = 16;
  }
  for (size_t i = 0; i < len; i++) {
    hash ^= data[i];
    hash *= 16777619u;
  }

  /* Hash destination port */
  hash ^= (key->dst.port >> 8);
  hash *= 16777619u;
  hash ^= (key->dst.port & 0xFF);
  hash *= 16777619u;

  /* Hash protocol */
  hash ^= key->protocol;
  hash *= 16777619u;

  return hash;
}

/* =============================================================================
 * NAT Table Lifecycle
 * ============================================================================= */

tunnel_nat_t *tunnel_nat_create(tunnel_t *tunnel) {
  tunnel_nat_t *nat = calloc(1, sizeof(tunnel_nat_t));
  if (!nat)
    return NULL;

  nat->table_size = TUNNEL_NAT_HASH_SIZE;
  nat->table = calloc(nat->table_size, sizeof(tunnel_session_t *));
  if (!nat->table) {
    free(nat);
    return NULL;
  }

  nat->session_count = 0;
  nat->lru_head = NULL;
  nat->lru_tail = NULL;
  nat->next_udp_port = TUNNEL_NAT_UDP_PORT_MIN;

  /* Clear UDP port bitmap */
  memset(nat->udp_port_bitmap, 0, sizeof(nat->udp_port_bitmap));

  (void)tunnel;
  return nat;
}

void tunnel_nat_destroy(tunnel_nat_t *nat) {
  if (!nat)
    return;

  /* Sessions are managed externally, just free the table */
  free(nat->table);
  free(nat);
}

void tunnel_nat_clear(tunnel_nat_t *nat) {
  if (!nat)
    return;

  /* Clear hash table */
  memset(nat->table, 0, nat->table_size * sizeof(tunnel_session_t *));

  /* Clear LRU list */
  nat->lru_head = NULL;
  nat->lru_tail = NULL;
  nat->session_count = 0;

  /* Reset stats */
  nat->lookups = 0;
  nat->hits = 0;
  nat->misses = 0;
  nat->evictions = 0;

  /* Reset UDP port allocation */
  nat->next_udp_port = TUNNEL_NAT_UDP_PORT_MIN;
  memset(nat->udp_port_bitmap, 0, sizeof(nat->udp_port_bitmap));
}

/* =============================================================================
 * Session Key Utilities
 * ============================================================================= */

int tunnel_session_key_compare(const tunnel_session_key_t *a, const tunnel_session_key_t *b) {
  if (a->protocol != b->protocol)
    return 1;
  if (a->src.family != b->src.family)
    return 1;
  if (a->src.port != b->src.port)
    return 1;
  if (a->dst.port != b->dst.port)
    return 1;

  if (a->src.family == AF_INET) {
    if (a->src.addr.v4 != b->src.addr.v4)
      return 1;
    if (a->dst.addr.v4 != b->dst.addr.v4)
      return 1;
  } else {
    if (memcmp(a->src.addr.v6, b->src.addr.v6, 16) != 0)
      return 1;
    if (memcmp(a->dst.addr.v6, b->dst.addr.v6, 16) != 0)
      return 1;
  }

  return 0;
}

char *tunnel_session_key_format(const tunnel_session_key_t *key, char *buf, size_t len) {
  char src_ip[64], dst_ip[64];

  if (key->src.family == AF_INET) {
    uint32_t ip = ntohl(key->src.addr.v4);
    fmt(src_ip, sizeof(src_ip), "{}.{}.{}.{}", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
        (ip >> 8) & 0xFF, ip & 0xFF);
    ip = ntohl(key->dst.addr.v4);
    fmt(dst_ip, sizeof(dst_ip), "{}.{}.{}.{}", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
        (ip >> 8) & 0xFF, ip & 0xFF);
  } else {
    fmt(src_ip, sizeof(src_ip), "[IPv6]");
    fmt(dst_ip, sizeof(dst_ip), "[IPv6]");
  }

  fmt(buf, len, "{}:{} -> {}:{} [{}]", src_ip, key->src.port, dst_ip, key->dst.port,
      key->protocol == TUNNEL_IPPROTO_TCP ? "TCP" : "UDP");

  return buf;
}

/* =============================================================================
 * Endpoint Utilities
 * ============================================================================= */

int tunnel_endpoint_compare(const tunnel_endpoint_t *a, const tunnel_endpoint_t *b) {
  if (a->family != b->family)
    return 1;
  if (a->port != b->port)
    return 1;

  if (a->family == AF_INET) {
    return a->addr.v4 != b->addr.v4;
  } else {
    return memcmp(a->addr.v6, b->addr.v6, 16);
  }
}

char *tunnel_endpoint_format(const tunnel_endpoint_t *ep, char *buf, size_t len) {
  if (ep->family == AF_INET) {
    uint32_t ip = ntohl(ep->addr.v4);
    fmt(buf, len, "{}.{}.{}.{}:{}", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
        (ip >> 8) & 0xFF, ip & 0xFF, ep->port);
  } else {
    fmt(buf, len, "[::%{}]:{}", ep->family, ep->port);
  }
  return buf;
}

int tunnel_endpoint_parse(const char *str, tunnel_endpoint_t *ep) {
  char ip_buf[64];
  int port;
  unsigned int a, b, c, d;

  if (sscanf(str, "%u.%u.%u.%u:%d", &a, &b, &c, &d, &port) == 5) {
    ep->family = AF_INET;
    ep->addr.v4 = htonl((a << 24) | (b << 16) | (c << 8) | d);
    ep->port = (uint16_t)port;
    return TUNNEL_OK;
  }

  /* TODO: Parse IPv6 addresses */
  (void)ip_buf;
  return TUNNEL_ERR_INVALID_ARG;
}

/* =============================================================================
 * Hash Table Operations
 * ============================================================================= */

int tunnel_nat_insert(tunnel_nat_t *nat, tunnel_session_t *session) {
  if (!nat || !session)
    return TUNNEL_ERR_INVALID_ARG;

  uint32_t hash = tunnel_nat_hash(&session->key);
  uint32_t index = hash & (nat->table_size - 1);

  /* Insert at head of bucket chain */
  session->hash_next = nat->table[index];
  session->hash_prev = NULL;
  if (nat->table[index]) {
    nat->table[index]->hash_prev = session;
  }
  nat->table[index] = session;

  /* Add to LRU head (newest) */
  session->lru_prev = NULL;
  session->lru_next = nat->lru_head;
  if (nat->lru_head) {
    nat->lru_head->lru_prev = session;
  }
  nat->lru_head = session;
  if (!nat->lru_tail) {
    nat->lru_tail = session;
  }

  nat->session_count++;
  return TUNNEL_OK;
}

void tunnel_nat_remove(tunnel_nat_t *nat, tunnel_session_t *session) {
  if (!nat || !session)
    return;

  uint32_t hash = tunnel_nat_hash(&session->key);
  uint32_t index = hash & (nat->table_size - 1);

  /* Remove from hash chain */
  if (session->hash_prev) {
    session->hash_prev->hash_next = session->hash_next;
  } else {
    nat->table[index] = session->hash_next;
  }
  if (session->hash_next) {
    session->hash_next->hash_prev = session->hash_prev;
  }

  /* Remove from LRU list */
  if (session->lru_prev) {
    session->lru_prev->lru_next = session->lru_next;
  } else {
    nat->lru_head = session->lru_next;
  }
  if (session->lru_next) {
    session->lru_next->lru_prev = session->lru_prev;
  } else {
    nat->lru_tail = session->lru_prev;
  }

  session->hash_next = session->hash_prev = NULL;
  session->lru_next = session->lru_prev = NULL;

  if (nat->session_count > 0) {
    nat->session_count--;
  }
}

tunnel_session_t *tunnel_nat_lookup(tunnel_nat_t *nat, const tunnel_session_key_t *key) {
  if (!nat || !key)
    return NULL;

  nat->lookups++;

  uint32_t hash = tunnel_nat_hash(key);
  uint32_t index = hash & (nat->table_size - 1);

  tunnel_session_t *session = nat->table[index];
  while (session) {
    if (tunnel_session_key_compare(&session->key, key) == 0) {
      nat->hits++;
      return session;
    }
    session = session->hash_next;
  }

  nat->misses++;
  return NULL;
}

tunnel_session_t *tunnel_nat_lookup_by_src(tunnel_nat_t *nat, const tunnel_endpoint_t *src,
                                           uint8_t protocol) {
  if (!nat || !src)
    return NULL;

  /* Linear scan - not efficient but works for moderate session counts */
  tunnel_session_t *session = nat->lru_head;
  while (session) {
    if (session->key.protocol == protocol && tunnel_endpoint_compare(&session->key.src, src) == 0) {
      return session;
    }
    session = session->lru_next;
  }

  return NULL;
}

/* =============================================================================
 * Reverse NAT
 * ============================================================================= */

void tunnel_nat_reverse_key(const tunnel_session_key_t *key, tunnel_session_key_t *reverse) {
  reverse->protocol = key->protocol;
  tunnel_endpoint_copy(&reverse->src, &key->dst);
  tunnel_endpoint_copy(&reverse->dst, &key->src);
}

tunnel_session_t *tunnel_nat_lookup_reverse(tunnel_nat_t *nat, const tunnel_endpoint_t *dst,
                                            const tunnel_endpoint_t *src, uint8_t protocol) {
  tunnel_session_key_t key;
  key.protocol = protocol;
  tunnel_endpoint_copy(&key.src, dst);
  tunnel_endpoint_copy(&key.dst, src);
  return tunnel_nat_lookup(nat, &key);
}

/* =============================================================================
 * LRU Management
 * ============================================================================= */

void tunnel_nat_touch(tunnel_nat_t *nat, tunnel_session_t *session) {
  if (!nat || !session)
    return;

  /* Already at head */
  if (session == nat->lru_head)
    return;

  /* Remove from current position */
  if (session->lru_prev) {
    session->lru_prev->lru_next = session->lru_next;
  }
  if (session->lru_next) {
    session->lru_next->lru_prev = session->lru_prev;
  } else {
    nat->lru_tail = session->lru_prev;
  }

  /* Move to head */
  session->lru_prev = NULL;
  session->lru_next = nat->lru_head;
  if (nat->lru_head) {
    nat->lru_head->lru_prev = session;
  }
  nat->lru_head = session;
}

tunnel_session_t *tunnel_nat_get_oldest(tunnel_nat_t *nat) { return nat ? nat->lru_tail : NULL; }

int tunnel_nat_evict_oldest(tunnel_nat_t *nat, size_t max_sessions) {
  if (!nat)
    return 0;

  int evicted = 0;
  while (nat->session_count > max_sessions && nat->lru_tail) {
    tunnel_session_t *oldest = nat->lru_tail;
    tunnel_nat_remove(nat, oldest);
    nat->evictions++;
    evicted++;
  }

  return evicted;
}

int tunnel_nat_evict_expired(tunnel_nat_t *nat, uint32_t tcp_timeout_ms, uint32_t udp_timeout_ms) {
  if (!nat)
    return 0;

  uint64_t now = (uint64_t)time(NULL) * 1000;
  int evicted = 0;

  tunnel_session_t *session = nat->lru_tail;
  while (session) {
    tunnel_session_t *prev = session->lru_prev;
    uint32_t timeout =
        (session->key.protocol == TUNNEL_IPPROTO_TCP) ? tcp_timeout_ms : udp_timeout_ms;

    if (now - session->last_active > timeout) {
      tunnel_nat_remove(nat, session);
      nat->evictions++;
      evicted++;
    }

    session = prev;
  }

  return evicted;
}

/* =============================================================================
 * UDP Port Allocation
 * ============================================================================= */

static int port_bitmap_get(tunnel_nat_t *nat, uint16_t port) {
  if (port < TUNNEL_NAT_UDP_PORT_MIN || port > TUNNEL_NAT_UDP_PORT_MAX) {
    return 0;
  }
  uint16_t index = port - TUNNEL_NAT_UDP_PORT_MIN;
  return (nat->udp_port_bitmap[index / 8] >> (index % 8)) & 1;
}

static void port_bitmap_set(tunnel_nat_t *nat, uint16_t port, int value) {
  if (port < TUNNEL_NAT_UDP_PORT_MIN || port > TUNNEL_NAT_UDP_PORT_MAX) {
    return;
  }
  uint16_t index = port - TUNNEL_NAT_UDP_PORT_MIN;
  if (value) {
    nat->udp_port_bitmap[index / 8] |= (1 << (index % 8));
  } else {
    nat->udp_port_bitmap[index / 8] &= ~(1 << (index % 8));
  }
}

uint16_t tunnel_nat_alloc_udp_port(tunnel_nat_t *nat) {
  if (!nat)
    return 0;

  uint16_t start = nat->next_udp_port;
  uint16_t port = start;

  do {
    if (!port_bitmap_get(nat, port)) {
      port_bitmap_set(nat, port, 1);
      nat->next_udp_port = port + 1;
      if (nat->next_udp_port > TUNNEL_NAT_UDP_PORT_MAX) {
        nat->next_udp_port = TUNNEL_NAT_UDP_PORT_MIN;
      }
      return port;
    }

    port++;
    if (port > TUNNEL_NAT_UDP_PORT_MAX) {
      port = TUNNEL_NAT_UDP_PORT_MIN;
    }
  } while (port != start);

  return 0; /* All ports exhausted */
}

void tunnel_nat_free_udp_port(tunnel_nat_t *nat, uint16_t port) {
  if (!nat)
    return;
  port_bitmap_set(nat, port, 0);
}

int tunnel_nat_udp_port_in_use(tunnel_nat_t *nat, uint16_t port) {
  if (!nat)
    return 0;
  return port_bitmap_get(nat, port);
}

/* =============================================================================
 * Statistics
 * ============================================================================= */

void tunnel_nat_get_stats(tunnel_nat_t *nat, uint64_t *lookups, uint64_t *hits, uint64_t *misses,
                          uint64_t *evictions) {
  if (!nat)
    return;
  if (lookups)
    *lookups = nat->lookups;
  if (hits)
    *hits = nat->hits;
  if (misses)
    *misses = nat->misses;
  if (evictions)
    *evictions = nat->evictions;
}

void tunnel_nat_reset_stats(tunnel_nat_t *nat) {
  if (!nat)
    return;
  nat->lookups = 0;
  nat->hits = 0;
  nat->misses = 0;
  nat->evictions = 0;
}

size_t tunnel_nat_session_count(tunnel_nat_t *nat) { return nat ? nat->session_count : 0; }

double tunnel_nat_load_factor(tunnel_nat_t *nat) {
  if (!nat || nat->table_size == 0)
    return 0.0;
  return (double)nat->session_count / (double)nat->table_size;
}
