/**
 * @file tunnel_ip_stack.h
 * @brief Lightweight IP stack for packet processing
 *
 * Provides:
 * - IPv4/IPv6 header parsing and building
 * - TCP/UDP header parsing and building
 * - Checksum calculation
 * - IP fragment reassembly
 * - TCP segment reassembly
 */

#ifndef TUNNEL_IP_STACK_H
#define TUNNEL_IP_STACK_H

#include "core/tunnel_types.h"

/* =============================================================================
 * IP Protocol Constants
 * ============================================================================= */

/* IP versions */
#define TUNNEL_IP_VERSION_4     4
#define TUNNEL_IP_VERSION_6     6

/* IP header lengths */
#define TUNNEL_IPV4_HEADER_MIN  20
#define TUNNEL_IPV4_HEADER_MAX  60
#define TUNNEL_IPV6_HEADER_LEN  40

/* TCP header */
#define TUNNEL_TCP_HEADER_MIN   20
#define TUNNEL_TCP_HEADER_MAX   60

/* UDP header */
#define TUNNEL_UDP_HEADER_LEN   8

/* TCP flags */
#define TUNNEL_TCP_FIN          0x01
#define TUNNEL_TCP_SYN          0x02
#define TUNNEL_TCP_RST          0x04
#define TUNNEL_TCP_PSH          0x08
#define TUNNEL_TCP_ACK          0x10
#define TUNNEL_TCP_URG          0x20

/* =============================================================================
 * Parsed Packet Structures
 * ============================================================================= */

typedef struct {
    int version;                /* 4 or 6 */
    int header_len;             /* IP header length */
    int total_len;              /* Total packet length */
    int protocol;               /* Next protocol (TCP/UDP/ICMP) */
    int ttl;                    /* Time to live */
    uint16_t id;                /* Identification (IPv4) */
    uint16_t frag_offset;       /* Fragment offset */
    int more_fragments;         /* MF flag */
    int dont_fragment;          /* DF flag */
    tunnel_endpoint_t src;      /* Source address */
    tunnel_endpoint_t dst;      /* Destination address */
} tunnel_ip_header_t;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;               /* Sequence number */
    uint32_t ack;               /* Acknowledgment number */
    int header_len;             /* TCP header length */
    uint8_t flags;              /* TCP flags */
    uint16_t window;            /* Window size */
    uint16_t urgent;            /* Urgent pointer */
    const uint8_t *options;     /* TCP options (may be NULL) */
    int options_len;
} tunnel_tcp_header_t;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;            /* UDP length including header */
    uint16_t checksum;
} tunnel_udp_header_t;

typedef struct {
    tunnel_ip_header_t ip;
    union {
        tunnel_tcp_header_t tcp;
        tunnel_udp_header_t udp;
    };
    const uint8_t *payload;     /* Pointer to payload */
    size_t payload_len;
} tunnel_packet_t;

/* =============================================================================
 * IP Stack API
 * ============================================================================= */

/**
 * Create IP stack
 * @param tunnel Parent tunnel handle
 * @return IP stack handle or NULL
 */
TUNNEL_INTERNAL tunnel_ip_stack_t* tunnel_ip_stack_create(tunnel_t *tunnel);

/**
 * Destroy IP stack
 * @param stack IP stack handle
 */
TUNNEL_INTERNAL void tunnel_ip_stack_destroy(tunnel_ip_stack_t *stack);

/* =============================================================================
 * Packet Parsing
 * ============================================================================= */

/**
 * Parse IP packet
 * @param data Raw packet data
 * @param len Packet length
 * @param pkt Output parsed packet
 * @return TUNNEL_OK on success
 */
TUNNEL_INTERNAL int tunnel_ip_parse(
    const uint8_t *data,
    size_t len,
    tunnel_packet_t *pkt
);

/**
 * Parse IPv4 header
 * @param data Packet data
 * @param len Data length
 * @param hdr Output header
 * @return Header length or negative on error
 */
TUNNEL_INTERNAL int tunnel_ipv4_parse_header(
    const uint8_t *data,
    size_t len,
    tunnel_ip_header_t *hdr
);

/**
 * Parse IPv6 header
 * @param data Packet data
 * @param len Data length
 * @param hdr Output header
 * @return Header length or negative on error
 */
TUNNEL_INTERNAL int tunnel_ipv6_parse_header(
    const uint8_t *data,
    size_t len,
    tunnel_ip_header_t *hdr
);

/**
 * Parse TCP header
 * @param data TCP segment data
 * @param len Data length
 * @param hdr Output header
 * @return Header length or negative on error
 */
TUNNEL_INTERNAL int tunnel_tcp_parse_header(
    const uint8_t *data,
    size_t len,
    tunnel_tcp_header_t *hdr
);

/**
 * Parse UDP header
 * @param data UDP datagram data
 * @param len Data length
 * @param hdr Output header
 * @return Header length or negative on error
 */
TUNNEL_INTERNAL int tunnel_udp_parse_header(
    const uint8_t *data,
    size_t len,
    tunnel_udp_header_t *hdr
);

/* =============================================================================
 * Packet Building
 * ============================================================================= */

/**
 * Build TCP packet
 * @param buf Output buffer
 * @param buf_len Buffer size
 * @param src Source endpoint
 * @param dst Destination endpoint
 * @param seq Sequence number
 * @param ack Acknowledgment number
 * @param flags TCP flags
 * @param window Window size
 * @param payload Payload data (may be NULL)
 * @param payload_len Payload length
 * @return Packet length or negative on error
 */
TUNNEL_INTERNAL int tunnel_ip_build_tcp(
    uint8_t *buf,
    size_t buf_len,
    const tunnel_endpoint_t *src,
    const tunnel_endpoint_t *dst,
    uint32_t seq,
    uint32_t ack,
    uint8_t flags,
    uint16_t window,
    const uint8_t *payload,
    size_t payload_len
);

/**
 * Build UDP packet
 * @param buf Output buffer
 * @param buf_len Buffer size
 * @param src Source endpoint
 * @param dst Destination endpoint
 * @param payload Payload data
 * @param payload_len Payload length
 * @return Packet length or negative on error
 */
TUNNEL_INTERNAL int tunnel_ip_build_udp(
    uint8_t *buf,
    size_t buf_len,
    const tunnel_endpoint_t *src,
    const tunnel_endpoint_t *dst,
    const uint8_t *payload,
    size_t payload_len
);

/**
 * Build ICMP unreachable packet
 * @param buf Output buffer
 * @param buf_len Buffer size
 * @param original Original packet that triggered error
 * @param original_len Original packet length
 * @param code ICMP code
 * @return Packet length or negative on error
 */
TUNNEL_INTERNAL int tunnel_ip_build_icmp_unreachable(
    uint8_t *buf,
    size_t buf_len,
    const uint8_t *original,
    size_t original_len,
    int code
);

/**
 * Build TCP RST packet
 * @param buf Output buffer
 * @param buf_len Buffer size
 * @param src Source endpoint
 * @param dst Destination endpoint
 * @param seq Sequence number
 * @return Packet length or negative on error
 */
TUNNEL_INTERNAL int tunnel_ip_build_tcp_rst(
    uint8_t *buf,
    size_t buf_len,
    const tunnel_endpoint_t *src,
    const tunnel_endpoint_t *dst,
    uint32_t seq
);

/**
 * Build TCP SYN-ACK packet
 * @param buf Output buffer
 * @param buf_len Buffer size
 * @param src Source endpoint
 * @param dst Destination endpoint
 * @param seq Sequence number
 * @param ack Acknowledgment number
 * @param window Window size
 * @return Packet length or negative on error
 */
TUNNEL_INTERNAL int tunnel_ip_build_tcp_synack(
    uint8_t *buf,
    size_t buf_len,
    const tunnel_endpoint_t *src,
    const tunnel_endpoint_t *dst,
    uint32_t seq,
    uint32_t ack,
    uint16_t window
);

/**
 * Build TCP FIN packet
 * @param buf Output buffer
 * @param buf_len Buffer size
 * @param src Source endpoint
 * @param dst Destination endpoint
 * @param seq Sequence number
 * @param ack Acknowledgment number
 * @return Packet length or negative on error
 */
TUNNEL_INTERNAL int tunnel_ip_build_tcp_fin(
    uint8_t *buf,
    size_t buf_len,
    const tunnel_endpoint_t *src,
    const tunnel_endpoint_t *dst,
    uint32_t seq,
    uint32_t ack
);

/**
 * Build TCP ACK packet (no payload)
 * @param buf Output buffer
 * @param buf_len Buffer size
 * @param src Source endpoint
 * @param dst Destination endpoint
 * @param seq Sequence number
 * @param ack Acknowledgment number
 * @param window Window size
 * @return Packet length or negative on error
 */
TUNNEL_INTERNAL int tunnel_ip_build_tcp_ack(
    uint8_t *buf,
    size_t buf_len,
    const tunnel_endpoint_t *src,
    const tunnel_endpoint_t *dst,
    uint32_t seq,
    uint32_t ack,
    uint16_t window
);

/**
 * Build TCP data packet (PSH+ACK)
 * @param buf Output buffer
 * @param buf_len Buffer size
 * @param src Source endpoint
 * @param dst Destination endpoint
 * @param seq Sequence number
 * @param ack Acknowledgment number
 * @param window Window size
 * @param payload Payload data
 * @param payload_len Payload length
 * @return Packet length or negative on error
 */
TUNNEL_INTERNAL int tunnel_ip_build_tcp_data(
    uint8_t *buf,
    size_t buf_len,
    const tunnel_endpoint_t *src,
    const tunnel_endpoint_t *dst,
    uint32_t seq,
    uint32_t ack,
    uint16_t window,
    const uint8_t *payload,
    size_t payload_len
);

/* =============================================================================
 * Checksum Calculation
 * ============================================================================= */

/**
 * Calculate IP checksum
 * @param data Header data
 * @param len Header length
 * @return Checksum in network byte order
 */
TUNNEL_INTERNAL uint16_t tunnel_ip_checksum(const uint8_t *data, size_t len);

/**
 * Calculate TCP/UDP checksum with pseudo-header
 * @param src Source address
 * @param dst Destination address
 * @param protocol Protocol number
 * @param data Segment/datagram data
 * @param len Data length
 * @return Checksum in network byte order
 */
TUNNEL_INTERNAL uint16_t tunnel_ip_pseudo_checksum(
    const tunnel_endpoint_t *src,
    const tunnel_endpoint_t *dst,
    int protocol,
    const uint8_t *data,
    size_t len
);

/* =============================================================================
 * Fragment Reassembly
 * ============================================================================= */

/**
 * Check if packet is fragmented
 * @param pkt Parsed packet
 * @return 1 if fragment, 0 if complete
 */
TUNNEL_INTERNAL int tunnel_ip_is_fragment(const tunnel_packet_t *pkt);

/**
 * Add fragment to reassembly buffer
 * @param stack IP stack handle
 * @param pkt Parsed fragment
 * @param data Raw fragment data
 * @param len Fragment length
 * @return TUNNEL_OK or error
 */
TUNNEL_INTERNAL int tunnel_ip_fragment_add(
    tunnel_ip_stack_t *stack,
    const tunnel_packet_t *pkt,
    const uint8_t *data,
    size_t len
);

/**
 * Get reassembled packet if complete
 * @param stack IP stack handle
 * @param id Fragment ID
 * @param buf Output buffer
 * @param buf_len Buffer size
 * @param out_len Output: reassembled length
 * @return TUNNEL_OK if complete, TUNNEL_ERR_NOT_FOUND if incomplete
 */
TUNNEL_INTERNAL int tunnel_ip_fragment_get(
    tunnel_ip_stack_t *stack,
    uint16_t id,
    uint8_t *buf,
    size_t buf_len,
    size_t *out_len
);

/**
 * Expire old fragments
 * @param stack IP stack handle
 * @param timeout_ms Timeout in milliseconds
 * @return Number of fragment groups expired
 */
TUNNEL_INTERNAL int tunnel_ip_fragment_expire(
    tunnel_ip_stack_t *stack,
    uint32_t timeout_ms
);

/* =============================================================================
 * TCP Segment Reassembly
 * ============================================================================= */

/**
 * Add TCP segment to reassembly buffer
 * Handles out-of-order segments.
 * @param stack IP stack handle
 * @param session Session handle
 * @param seq Sequence number
 * @param data Segment payload
 * @param len Payload length
 * @return TUNNEL_OK or error
 */
TUNNEL_INTERNAL int tunnel_tcp_reassemble_add(
    tunnel_ip_stack_t *stack,
    tunnel_session_t *session,
    uint32_t seq,
    const uint8_t *data,
    size_t len
);

/**
 * Get in-order data from reassembly buffer
 * @param stack IP stack handle
 * @param session Session handle
 * @param buf Output buffer
 * @param buf_len Buffer size
 * @param out_len Output: data length
 * @return TUNNEL_OK if data available
 */
TUNNEL_INTERNAL int tunnel_tcp_reassemble_get(
    tunnel_ip_stack_t *stack,
    tunnel_session_t *session,
    uint8_t *buf,
    size_t buf_len,
    size_t *out_len
);

/**
 * Clear reassembly buffer for session
 * @param stack IP stack handle
 * @param session Session handle
 */
TUNNEL_INTERNAL void tunnel_tcp_reassemble_clear(
    tunnel_ip_stack_t *stack,
    tunnel_session_t *session
);

#endif /* TUNNEL_IP_STACK_H */
