/**
 * @file tunnel_ip_stack.c
 * @brief IP packet parsing and building
 */

#include "tunnel_ip_stack.h"
#include "../core/tunnel_types.h"
#include <stdlib.h>
#include <string.h>

/* =============================================================================
 * IP Stack Lifecycle
 * ============================================================================= */

tunnel_ip_stack_t *tunnel_ip_stack_create(tunnel_t *tunnel) {
  tunnel_ip_stack_t *stack = calloc(1, sizeof(tunnel_ip_stack_t));
  if (!stack)
    return NULL;

  stack->tunnel = tunnel;

  /* Initialize TCP reassembly buffers */
  for (int i = 0; i < 256; i++) {
    stack->tcp_reassembly[i].buffer = NULL;
    stack->tcp_reassembly[i].len = 0;
    stack->tcp_reassembly[i].cap = 0;
  }

  return stack;
}

void tunnel_ip_stack_destroy(tunnel_ip_stack_t *stack) {
  if (!stack)
    return;

  /* Free TCP reassembly buffers */
  for (int i = 0; i < 256; i++) {
    free(stack->tcp_reassembly[i].buffer);
  }

  /* Free fragment buffers */
  for (int i = 0; i < stack->fragment_count; i++) {
    free(stack->fragments[i].buffer);
  }

  free(stack);
}

/* =============================================================================
 * IPv4 Header Parsing
 * ============================================================================= */

int tunnel_ipv4_parse_header(const uint8_t *data, size_t len, tunnel_ip_header_t *hdr) {
  if (len < TUNNEL_IPV4_HEADER_MIN) {
    return TUNNEL_ERR_INVALID_ARG;
  }

  /* Check version */
  uint8_t version = (data[0] >> 4) & 0x0F;
  if (version != 4) {
    return TUNNEL_ERR_INVALID_ARG;
  }

  /* Header length */
  int ihl = (data[0] & 0x0F) * 4;
  if (ihl < TUNNEL_IPV4_HEADER_MIN || (size_t)ihl > len) {
    return TUNNEL_ERR_INVALID_ARG;
  }

  memset(hdr, 0, sizeof(*hdr));

  hdr->version = 4;
  hdr->header_len = ihl;
  hdr->total_len = (data[2] << 8) | data[3];
  hdr->id = (data[4] << 8) | data[5];

  /* Flags and fragment offset */
  uint16_t flags_frag = (data[6] << 8) | data[7];
  hdr->dont_fragment = (flags_frag >> 14) & 0x01;
  hdr->more_fragments = (flags_frag >> 13) & 0x01;
  hdr->frag_offset = (flags_frag & 0x1FFF) * 8;

  hdr->ttl = data[8];
  hdr->protocol = data[9];

  /* Source address */
  hdr->src.family = AF_INET;
  memcpy(&hdr->src.addr.v4, &data[12], 4);
  hdr->src.port = 0;

  /* Destination address */
  hdr->dst.family = AF_INET;
  memcpy(&hdr->dst.addr.v4, &data[16], 4);
  hdr->dst.port = 0;

  return ihl;
}

/* =============================================================================
 * IPv6 Header Parsing
 * ============================================================================= */

int tunnel_ipv6_parse_header(const uint8_t *data, size_t len, tunnel_ip_header_t *hdr) {
  if (len < TUNNEL_IPV6_HEADER_LEN) {
    return TUNNEL_ERR_INVALID_ARG;
  }

  /* Check version */
  uint8_t version = (data[0] >> 4) & 0x0F;
  if (version != 6) {
    return TUNNEL_ERR_INVALID_ARG;
  }

  memset(hdr, 0, sizeof(*hdr));

  hdr->version = 6;
  hdr->header_len = TUNNEL_IPV6_HEADER_LEN;

  /* Payload length */
  uint16_t payload_len = (data[4] << 8) | data[5];
  hdr->total_len = TUNNEL_IPV6_HEADER_LEN + payload_len;

  hdr->protocol = data[6]; /* Next header */
  hdr->ttl = data[7];      /* Hop limit */

  /* Source address */
  hdr->src.family = AF_INET6;
  memcpy(hdr->src.addr.v6, &data[8], 16);
  hdr->src.port = 0;

  /* Destination address */
  hdr->dst.family = AF_INET6;
  memcpy(hdr->dst.addr.v6, &data[24], 16);
  hdr->dst.port = 0;

  /* IPv6 doesn't have fragment info in base header */
  hdr->id = 0;
  hdr->frag_offset = 0;
  hdr->more_fragments = 0;
  hdr->dont_fragment = 0;

  return TUNNEL_IPV6_HEADER_LEN;
}

/* =============================================================================
 * TCP Header Parsing
 * ============================================================================= */

int tunnel_tcp_parse_header(const uint8_t *data, size_t len, tunnel_tcp_header_t *hdr) {
  if (len < TUNNEL_TCP_HEADER_MIN) {
    return TUNNEL_ERR_INVALID_ARG;
  }

  memset(hdr, 0, sizeof(*hdr));

  hdr->src_port = (data[0] << 8) | data[1];
  hdr->dst_port = (data[2] << 8) | data[3];
  hdr->seq =
      ((uint32_t)data[4] << 24) | ((uint32_t)data[5] << 16) | ((uint32_t)data[6] << 8) | data[7];
  hdr->ack =
      ((uint32_t)data[8] << 24) | ((uint32_t)data[9] << 16) | ((uint32_t)data[10] << 8) | data[11];

  /* Data offset (header length) */
  int data_offset = ((data[12] >> 4) & 0x0F) * 4;
  if (data_offset < TUNNEL_TCP_HEADER_MIN || (size_t)data_offset > len) {
    return TUNNEL_ERR_INVALID_ARG;
  }

  hdr->header_len = data_offset;
  hdr->flags = data[13] & 0x3F;
  hdr->window = (data[14] << 8) | data[15];
  hdr->urgent = (data[18] << 8) | data[19];

  /* Options */
  hdr->options_len = data_offset - TUNNEL_TCP_HEADER_MIN;
  if (hdr->options_len > 0) {
    hdr->options = &data[TUNNEL_TCP_HEADER_MIN];
  } else {
    hdr->options = NULL;
  }

  return data_offset;
}

/* =============================================================================
 * UDP Header Parsing
 * ============================================================================= */

int tunnel_udp_parse_header(const uint8_t *data, size_t len, tunnel_udp_header_t *hdr) {
  if (len < TUNNEL_UDP_HEADER_LEN) {
    return TUNNEL_ERR_INVALID_ARG;
  }

  memset(hdr, 0, sizeof(*hdr));

  hdr->src_port = (data[0] << 8) | data[1];
  hdr->dst_port = (data[2] << 8) | data[3];
  hdr->length = (data[4] << 8) | data[5];
  hdr->checksum = (data[6] << 8) | data[7];

  return TUNNEL_UDP_HEADER_LEN;
}

/* =============================================================================
 * Full Packet Parsing
 * ============================================================================= */

int tunnel_ip_parse(const uint8_t *data, size_t len, tunnel_packet_t *pkt) {
  if (!data || !pkt || len < 1) {
    return TUNNEL_ERR_INVALID_ARG;
  }

  memset(pkt, 0, sizeof(*pkt));

  /* Determine IP version */
  uint8_t version = (data[0] >> 4) & 0x0F;
  int ip_hdr_len;

  if (version == 4) {
    ip_hdr_len = tunnel_ipv4_parse_header(data, len, &pkt->ip);
  } else if (version == 6) {
    ip_hdr_len = tunnel_ipv6_parse_header(data, len, &pkt->ip);
  } else {
    return TUNNEL_ERR_INVALID_ARG;
  }

  if (ip_hdr_len < 0) {
    return ip_hdr_len;
  }

  /* Parse transport layer */
  const uint8_t *transport_data = data + ip_hdr_len;
  size_t transport_len = len - ip_hdr_len;
  int transport_hdr_len = 0;

  if (pkt->ip.protocol == TUNNEL_IPPROTO_TCP) {
    transport_hdr_len = tunnel_tcp_parse_header(transport_data, transport_len, &pkt->tcp);
    if (transport_hdr_len < 0) {
      return transport_hdr_len;
    }

    /* Copy ports to IP header for convenience */
    pkt->ip.src.port = pkt->tcp.src_port;
    pkt->ip.dst.port = pkt->tcp.dst_port;

  } else if (pkt->ip.protocol == TUNNEL_IPPROTO_UDP) {
    transport_hdr_len = tunnel_udp_parse_header(transport_data, transport_len, &pkt->udp);
    if (transport_hdr_len < 0) {
      return transport_hdr_len;
    }

    pkt->ip.src.port = pkt->udp.src_port;
    pkt->ip.dst.port = pkt->udp.dst_port;
  }

  /* Set payload pointer */
  if (transport_hdr_len > 0 && (size_t)transport_hdr_len < transport_len) {
    pkt->payload = transport_data + transport_hdr_len;
    pkt->payload_len = transport_len - transport_hdr_len;
  } else {
    pkt->payload = NULL;
    pkt->payload_len = 0;
  }

  return TUNNEL_OK;
}

/* =============================================================================
 * Fragment Detection
 * ============================================================================= */

int tunnel_ip_is_fragment(const tunnel_packet_t *pkt) {
  if (!pkt)
    return 0;

  /* IPv4: Check MF flag or non-zero fragment offset */
  if (pkt->ip.version == 4) {
    return pkt->ip.more_fragments || pkt->ip.frag_offset > 0;
  }

  /* IPv6: Would need to check Fragment extension header */
  return 0;
}

/* =============================================================================
 * IPv4 Header Building
 * ============================================================================= */

static int build_ipv4_header(uint8_t *buf, size_t buf_len, const tunnel_endpoint_t *src,
                             const tunnel_endpoint_t *dst, int protocol, size_t payload_len) {
  if (buf_len < TUNNEL_IPV4_HEADER_MIN) {
    return TUNNEL_ERR_INVALID_ARG;
  }

  size_t total_len = TUNNEL_IPV4_HEADER_MIN + payload_len;
  if (total_len > 65535) {
    return TUNNEL_ERR_INVALID_ARG;
  }

  memset(buf, 0, TUNNEL_IPV4_HEADER_MIN);

  /* Version (4) and IHL (5 = 20 bytes) */
  buf[0] = 0x45;

  /* Total length */
  buf[2] = (total_len >> 8) & 0xFF;
  buf[3] = total_len & 0xFF;

  /* Identification (random-ish) */
  static uint16_t ip_id = 1;
  buf[4] = (ip_id >> 8) & 0xFF;
  buf[5] = ip_id++ & 0xFF;

  /* Flags: Don't Fragment */
  buf[6] = 0x40;

  /* TTL */
  buf[8] = 64;

  /* Protocol */
  buf[9] = protocol;

  /* Source address */
  memcpy(&buf[12], &src->addr.v4, 4);

  /* Destination address */
  memcpy(&buf[16], &dst->addr.v4, 4);

  /* Header checksum */
  uint16_t csum = tunnel_ip_checksum(buf, TUNNEL_IPV4_HEADER_MIN);
  buf[10] = (csum >> 8) & 0xFF;
  buf[11] = csum & 0xFF;

  return TUNNEL_IPV4_HEADER_MIN;
}

/* =============================================================================
 * TCP Packet Building
 * ============================================================================= */

int tunnel_ip_build_tcp(uint8_t *buf, size_t buf_len, const tunnel_endpoint_t *src,
                        const tunnel_endpoint_t *dst, uint32_t seq, uint32_t ack, uint8_t flags,
                        uint16_t window, const uint8_t *payload, size_t payload_len) {
  size_t tcp_len = TUNNEL_TCP_HEADER_MIN + payload_len;
  size_t total_len = TUNNEL_IPV4_HEADER_MIN + tcp_len;

  if (buf_len < total_len) {
    return TUNNEL_ERR_INVALID_ARG;
  }

  /* Build IP header */
  int ip_len = build_ipv4_header(buf, buf_len, src, dst, TUNNEL_IPPROTO_TCP, tcp_len);
  if (ip_len < 0) {
    return ip_len;
  }

  /* Build TCP header */
  uint8_t *tcp = buf + ip_len;
  memset(tcp, 0, TUNNEL_TCP_HEADER_MIN);

  /* Source port */
  tcp[0] = (src->port >> 8) & 0xFF;
  tcp[1] = src->port & 0xFF;

  /* Destination port */
  tcp[2] = (dst->port >> 8) & 0xFF;
  tcp[3] = dst->port & 0xFF;

  /* Sequence number */
  tcp[4] = (seq >> 24) & 0xFF;
  tcp[5] = (seq >> 16) & 0xFF;
  tcp[6] = (seq >> 8) & 0xFF;
  tcp[7] = seq & 0xFF;

  /* Acknowledgment number */
  tcp[8] = (ack >> 24) & 0xFF;
  tcp[9] = (ack >> 16) & 0xFF;
  tcp[10] = (ack >> 8) & 0xFF;
  tcp[11] = ack & 0xFF;

  /* Data offset (5 = 20 bytes) and flags */
  tcp[12] = 0x50;
  tcp[13] = flags;

  /* Window */
  tcp[14] = (window >> 8) & 0xFF;
  tcp[15] = window & 0xFF;

  /* Copy payload */
  if (payload && payload_len > 0) {
    memcpy(tcp + TUNNEL_TCP_HEADER_MIN, payload, payload_len);
  }

  /* TCP checksum */
  uint16_t csum = tunnel_ip_pseudo_checksum(src, dst, TUNNEL_IPPROTO_TCP, tcp, tcp_len);
  tcp[16] = (csum >> 8) & 0xFF;
  tcp[17] = csum & 0xFF;

  return (int)total_len;
}

/* =============================================================================
 * UDP Packet Building
 * ============================================================================= */

int tunnel_ip_build_udp(uint8_t *buf, size_t buf_len, const tunnel_endpoint_t *src,
                        const tunnel_endpoint_t *dst, const uint8_t *payload, size_t payload_len) {
  size_t udp_len = TUNNEL_UDP_HEADER_LEN + payload_len;
  size_t total_len = TUNNEL_IPV4_HEADER_MIN + udp_len;

  if (buf_len < total_len) {
    return TUNNEL_ERR_INVALID_ARG;
  }

  /* Build IP header */
  int ip_len = build_ipv4_header(buf, buf_len, src, dst, TUNNEL_IPPROTO_UDP, udp_len);
  if (ip_len < 0) {
    return ip_len;
  }

  /* Build UDP header */
  uint8_t *udp = buf + ip_len;

  /* Source port */
  udp[0] = (src->port >> 8) & 0xFF;
  udp[1] = src->port & 0xFF;

  /* Destination port */
  udp[2] = (dst->port >> 8) & 0xFF;
  udp[3] = dst->port & 0xFF;

  /* Length */
  udp[4] = (udp_len >> 8) & 0xFF;
  udp[5] = udp_len & 0xFF;

  /* Checksum (0 for now) */
  udp[6] = 0;
  udp[7] = 0;

  /* Copy payload */
  if (payload && payload_len > 0) {
    memcpy(udp + TUNNEL_UDP_HEADER_LEN, payload, payload_len);
  }

  /* UDP checksum */
  uint16_t csum = tunnel_ip_pseudo_checksum(src, dst, TUNNEL_IPPROTO_UDP, udp, udp_len);
  if (csum == 0)
    csum = 0xFFFF; /* 0 means no checksum in UDP */
  udp[6] = (csum >> 8) & 0xFF;
  udp[7] = csum & 0xFF;

  return (int)total_len;
}

/* =============================================================================
 * TCP RST Packet
 * ============================================================================= */

int tunnel_ip_build_tcp_rst(uint8_t *buf, size_t buf_len, const tunnel_endpoint_t *src,
                            const tunnel_endpoint_t *dst, uint32_t seq) {
  return tunnel_ip_build_tcp(buf, buf_len, src, dst, seq, 0, TUNNEL_TCP_RST, 0, NULL, 0);
}

/* =============================================================================
 * TCP SYN-ACK Packet
 * ============================================================================= */

int tunnel_ip_build_tcp_synack(uint8_t *buf, size_t buf_len, const tunnel_endpoint_t *src,
                               const tunnel_endpoint_t *dst, uint32_t seq, uint32_t ack,
                               uint16_t window) {
  return tunnel_ip_build_tcp(buf, buf_len, src, dst, seq, ack, TUNNEL_TCP_SYN | TUNNEL_TCP_ACK,
                             window, NULL, 0);
}

/* =============================================================================
 * TCP FIN Packet
 * ============================================================================= */

int tunnel_ip_build_tcp_fin(uint8_t *buf, size_t buf_len, const tunnel_endpoint_t *src,
                            const tunnel_endpoint_t *dst, uint32_t seq, uint32_t ack) {
  return tunnel_ip_build_tcp(buf, buf_len, src, dst, seq, ack, TUNNEL_TCP_FIN | TUNNEL_TCP_ACK, 0,
                             NULL, 0);
}

/* =============================================================================
 * TCP ACK Packet
 * ============================================================================= */

int tunnel_ip_build_tcp_ack(uint8_t *buf, size_t buf_len, const tunnel_endpoint_t *src,
                            const tunnel_endpoint_t *dst, uint32_t seq, uint32_t ack,
                            uint16_t window) {
  return tunnel_ip_build_tcp(buf, buf_len, src, dst, seq, ack, TUNNEL_TCP_ACK, window, NULL, 0);
}

/* =============================================================================
 * TCP Data Packet
 * ============================================================================= */

int tunnel_ip_build_tcp_data(uint8_t *buf, size_t buf_len, const tunnel_endpoint_t *src,
                             const tunnel_endpoint_t *dst, uint32_t seq, uint32_t ack,
                             uint16_t window, const uint8_t *payload, size_t payload_len) {
  return tunnel_ip_build_tcp(buf, buf_len, src, dst, seq, ack, TUNNEL_TCP_PSH | TUNNEL_TCP_ACK,
                             window, payload, payload_len);
}

/* =============================================================================
 * ICMP Unreachable
 * ============================================================================= */

int tunnel_ip_build_icmp_unreachable(uint8_t *buf, size_t buf_len, const uint8_t *original,
                                     size_t original_len, int code) {
  /* ICMP header (8) + original IP header + 8 bytes of original data */
  size_t orig_copy = (original_len > 28) ? 28 : original_len;
  size_t icmp_len = 8 + orig_copy;
  size_t total_len = TUNNEL_IPV4_HEADER_MIN + icmp_len;

  if (buf_len < total_len || original_len < TUNNEL_IPV4_HEADER_MIN) {
    return TUNNEL_ERR_INVALID_ARG;
  }

  /* Parse original packet to get addresses */
  tunnel_ip_header_t orig_hdr;
  if (tunnel_ipv4_parse_header(original, original_len, &orig_hdr) < 0) {
    return TUNNEL_ERR_INVALID_ARG;
  }

  /* Swap src/dst for ICMP reply */
  tunnel_endpoint_t src = orig_hdr.dst;
  tunnel_endpoint_t dst = orig_hdr.src;

  /* Build IP header */
  int ip_len = build_ipv4_header(buf, buf_len, &src, &dst, TUNNEL_IPPROTO_ICMP, icmp_len);
  if (ip_len < 0) {
    return ip_len;
  }

  /* Build ICMP header */
  uint8_t *icmp = buf + ip_len;
  icmp[0] = 3;    /* Type: Destination Unreachable */
  icmp[1] = code; /* Code */
  icmp[2] = 0;    /* Checksum (placeholder) */
  icmp[3] = 0;
  icmp[4] = 0; /* Unused */
  icmp[5] = 0;
  icmp[6] = 0;
  icmp[7] = 0;

  /* Copy original packet header */
  memcpy(icmp + 8, original, orig_copy);

  /* ICMP checksum */
  uint16_t csum = tunnel_ip_checksum(icmp, icmp_len);
  icmp[2] = (csum >> 8) & 0xFF;
  icmp[3] = csum & 0xFF;

  return (int)total_len;
}

/* =============================================================================
 * Fragment Reassembly (stub)
 * ============================================================================= */

int tunnel_ip_fragment_add(tunnel_ip_stack_t *stack, const tunnel_packet_t *pkt,
                           const uint8_t *data, size_t len) {
  (void)stack;
  (void)pkt;
  (void)data;
  (void)len;
  /* TODO: Implement fragment reassembly */
  return TUNNEL_ERR_NOT_SUPPORTED;
}

int tunnel_ip_fragment_get(tunnel_ip_stack_t *stack, uint16_t id, uint8_t *buf, size_t buf_len,
                           size_t *out_len) {
  (void)stack;
  (void)id;
  (void)buf;
  (void)buf_len;
  (void)out_len;
  return TUNNEL_ERR_NOT_FOUND;
}

int tunnel_ip_fragment_expire(tunnel_ip_stack_t *stack, uint32_t timeout_ms) {
  (void)stack;
  (void)timeout_ms;
  return 0;
}

/* =============================================================================
 * TCP Reassembly (stub)
 * ============================================================================= */

int tunnel_tcp_reassemble_add(tunnel_ip_stack_t *stack, tunnel_session_t *session, uint32_t seq,
                              const uint8_t *data, size_t len) {
  (void)stack;
  (void)session;
  (void)seq;
  (void)data;
  (void)len;
  return TUNNEL_OK;
}

int tunnel_tcp_reassemble_get(tunnel_ip_stack_t *stack, tunnel_session_t *session, uint8_t *buf,
                              size_t buf_len, size_t *out_len) {
  (void)stack;
  (void)session;
  (void)buf;
  (void)buf_len;
  if (out_len)
    *out_len = 0;
  return TUNNEL_ERR_NOT_FOUND;
}

void tunnel_tcp_reassemble_clear(tunnel_ip_stack_t *stack, tunnel_session_t *session) {
  (void)stack;
  (void)session;
}
