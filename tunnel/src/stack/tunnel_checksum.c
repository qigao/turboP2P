/**
 * @file tunnel_checksum.c
 * @brief IP/TCP/UDP checksum calculation
 */

#include "tunnel_ip_stack.h"
#include <string.h>

/* =============================================================================
 * Internet Checksum (RFC 1071)
 * ============================================================================= */

uint16_t tunnel_ip_checksum(const uint8_t *data, size_t len) {
  uint32_t sum = 0;
  const uint16_t *ptr = (const uint16_t *)data;

  /* Sum 16-bit words */
  while (len > 1) {
    sum += *ptr++;
    len -= 2;
  }

  /* Add remaining byte if any */
  if (len > 0) {
    sum += *(const uint8_t *)ptr;
  }

  /* Fold 32-bit sum to 16 bits */
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  return (uint16_t)~sum;
}

/* =============================================================================
 * TCP/UDP Pseudo-Header Checksum
 * ============================================================================= */

uint16_t tunnel_ip_pseudo_checksum(const tunnel_endpoint_t *src, const tunnel_endpoint_t *dst,
                                   int protocol, const uint8_t *data, size_t len) {
  uint32_t sum = 0;

  if (src->family == AF_INET) {
    /* IPv4 pseudo-header */
    const uint8_t *s = (const uint8_t *)&src->addr.v4;
    const uint8_t *d = (const uint8_t *)&dst->addr.v4;

    /* Source address */
    sum += (s[0] << 8) | s[1];
    sum += (s[2] << 8) | s[3];

    /* Destination address */
    sum += (d[0] << 8) | d[1];
    sum += (d[2] << 8) | d[3];

    /* Zero + Protocol */
    sum += protocol;

    /* Length */
    sum += (uint32_t)len;
  } else {
    /* IPv6 pseudo-header */
    const uint16_t *s = (const uint16_t *)src->addr.v6;
    const uint16_t *d = (const uint16_t *)dst->addr.v6;

    /* Source address (8 x 16-bit words) */
    for (int i = 0; i < 8; i++) {
      sum += ntohs(s[i]);
    }

    /* Destination address */
    for (int i = 0; i < 8; i++) {
      sum += ntohs(d[i]);
    }

    /* Upper-layer packet length (32-bit) */
    sum += (len >> 16) & 0xFFFF;
    sum += len & 0xFFFF;

    /* Zero + Next header */
    sum += protocol;
  }

  /* Add data checksum */
  const uint16_t *ptr = (const uint16_t *)data;
  size_t remaining = len;

  while (remaining > 1) {
    sum += ntohs(*ptr++);
    remaining -= 2;
  }

  if (remaining > 0) {
    sum += (*(const uint8_t *)ptr) << 8;
  }

  /* Fold and complement */
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  return htons((uint16_t)~sum);
}

/* =============================================================================
 * Incremental Checksum Update (RFC 1624)
 * ============================================================================= */

uint16_t tunnel_checksum_update(uint16_t old_csum, uint16_t old_val, uint16_t new_val) {
  uint32_t sum;

  /* HC' = ~(~HC + ~m + m') */
  sum = (uint16_t)~old_csum;
  sum += (uint16_t)~old_val;
  sum += new_val;

  /* Fold */
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  return (uint16_t)~sum;
}

/* Update checksum when changing 32-bit value (e.g., IP address) */
uint16_t tunnel_checksum_update32(uint16_t old_csum, uint32_t old_val, uint32_t new_val) {
  uint16_t csum = old_csum;

  /* Update high 16 bits */
  csum = tunnel_checksum_update(csum, (uint16_t)(old_val >> 16), (uint16_t)(new_val >> 16));

  /* Update low 16 bits */
  csum = tunnel_checksum_update(csum, (uint16_t)(old_val & 0xFFFF), (uint16_t)(new_val & 0xFFFF));

  return csum;
}
