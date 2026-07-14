/**
 * @file test_ip_stack.c
 * @brief Tests for tunnel IP stack (packet parsing and building)
 */

#include <tinytest.h>
#include "../src/stack/tunnel_ip_stack.h"
#include <string.h> 
void setUp(void) {}
void tearDown(void) {}

/* =============================================================================
 * Test Data - Real Packet Captures
 * ============================================================================= */

/* IPv4 TCP SYN packet (60 bytes) */
static const uint8_t ipv4_tcp_syn[] = {
    /* IPv4 header (20 bytes) */
    0x45, 0x00, 0x00, 0x3c,  /* ver=4, ihl=5, tos=0, len=60 */
    0x1c, 0x46, 0x40, 0x00,  /* id=0x1c46, flags=DF, frag=0 */
    0x40, 0x06, 0x00, 0x00,  /* ttl=64, proto=TCP, checksum (zeroed) */
    0xc0, 0xa8, 0x01, 0x64,  /* src=192.168.1.100 */
    0x5d, 0xb8, 0xd8, 0x22,  /* dst=93.184.216.34 (example.com) */
    /* TCP header (40 bytes with options) */
    0xc0, 0x08, 0x00, 0x50,  /* src_port=49160, dst_port=80 */
    0x00, 0x00, 0x00, 0x01,  /* seq=1 */
    0x00, 0x00, 0x00, 0x00,  /* ack=0 */
    0xa0, 0x02, 0xff, 0xff,  /* data_off=10(40 bytes), flags=SYN, window=65535 */
    0x00, 0x00, 0x00, 0x00,  /* checksum (zeroed), urgent=0 */
    /* TCP options (20 bytes) */
    0x02, 0x04, 0x05, 0xb4,  /* MSS=1460 */
    0x04, 0x02,              /* SACK permitted */
    0x08, 0x0a, 0x00, 0x00,  /* Timestamps */
    0x00, 0x01, 0x00, 0x00,
    0x00, 0x00,
    0x01,                    /* NOP */
    0x03, 0x03, 0x07,        /* Window scale=7 */
};

/* IPv4 UDP packet (28 bytes header + 13 bytes data) */
static const uint8_t ipv4_udp_dns[] = {
    /* IPv4 header (20 bytes) */
    0x45, 0x00, 0x00, 0x29,  /* ver=4, ihl=5, tos=0, len=41 */
    0xab, 0xcd, 0x00, 0x00,  /* id=0xabcd, flags=0, frag=0 */
    0x40, 0x11, 0x00, 0x00,  /* ttl=64, proto=UDP, checksum (zeroed) */
    0x0a, 0x00, 0x00, 0x01,  /* src=10.0.0.1 */
    0x08, 0x08, 0x08, 0x08,  /* dst=8.8.8.8 */
    /* UDP header (8 bytes) */
    0xc0, 0x00, 0x00, 0x35,  /* src_port=49152, dst_port=53 */
    0x00, 0x15, 0x00, 0x00,  /* length=21, checksum (zeroed) */
    /* DNS query payload (13 bytes) */
    0x00, 0x01, 0x01, 0x00,
    0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00,
};

/* IPv6 TCP packet */
static const uint8_t ipv6_tcp[] = {
    /* IPv6 header (40 bytes) */
    0x60, 0x00, 0x00, 0x00,  /* ver=6, traffic class=0, flow label=0 */
    0x00, 0x14, 0x06, 0x40,  /* payload_len=20, next=TCP, hop=64 */
    /* src: 2001:db8::1 */
    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    /* dst: 2001:db8::2 */
    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    /* TCP header (20 bytes, no options) */
    0x1f, 0x90, 0x00, 0x50,  /* src_port=8080, dst_port=80 */
    0x00, 0x00, 0x00, 0x0a,  /* seq=10 */
    0x00, 0x00, 0x00, 0x14,  /* ack=20 */
    0x50, 0x18, 0x10, 0x00,  /* data_off=5(20 bytes), flags=ACK|PSH, window=4096 */
    0x00, 0x00, 0x00, 0x00,  /* checksum (zeroed), urgent=0 */
};

/* =============================================================================
 * IPv4 Header Parsing Tests
 * ============================================================================= */

void test_ipv4_parse_header_tcp(void)
{
    tunnel_ip_header_t hdr;
    int ret = tunnel_ipv4_parse_header(ipv4_tcp_syn, sizeof(ipv4_tcp_syn), &hdr);

    check_int_eq(20, ret);
    check_int_eq(4, hdr.version);
    check_int_eq(20, hdr.header_len);
    check_int_eq(60, hdr.total_len);
    check_int_eq(TUNNEL_IPPROTO_TCP, hdr.protocol);
    check_int_eq(64, hdr.ttl);
    check_int_eq(0x1c46, hdr.id);
    check_int_eq(1, hdr.dont_fragment);
    check_int_eq(0, hdr.more_fragments);
    check_int_eq(0, hdr.frag_offset);

    check_int_eq(AF_INET, hdr.src.family);
    check_int_eq(0xc0a80164, ntohl(hdr.src.addr.v4));  /* 192.168.1.100 */

    check_int_eq(AF_INET, hdr.dst.family);
    check_int_eq(0x5db8d822, ntohl(hdr.dst.addr.v4));  /* 93.184.216.34 */
}

void test_ipv4_parse_header_udp(void)
{
    tunnel_ip_header_t hdr;
    int ret = tunnel_ipv4_parse_header(ipv4_udp_dns, sizeof(ipv4_udp_dns), &hdr);

    check_int_eq(20, ret);
    check_int_eq(4, hdr.version);
    check_int_eq(41, hdr.total_len);
    check_int_eq(TUNNEL_IPPROTO_UDP, hdr.protocol);
    check_int_eq(0xabcd, hdr.id);
}

void test_ipv4_parse_header_too_short(void)
{
    tunnel_ip_header_t hdr;
    uint8_t short_pkt[10] = {0x45, 0x00};

    int ret = tunnel_ipv4_parse_header(short_pkt, sizeof(short_pkt), &hdr);
    check(ret < 0);
}

void test_ipv4_parse_header_wrong_version(void)
{
    tunnel_ip_header_t hdr;
    uint8_t pkt[20] = {0x60};  /* IPv6 version */

    int ret = tunnel_ipv4_parse_header(pkt, sizeof(pkt), &hdr);
    check(ret < 0);
}

/* =============================================================================
 * IPv6 Header Parsing Tests
 * ============================================================================= */

void test_ipv6_parse_header_tcp(void)
{
    tunnel_ip_header_t hdr;
    int ret = tunnel_ipv6_parse_header(ipv6_tcp, sizeof(ipv6_tcp), &hdr);

    check_int_eq(40, ret);
    check_int_eq(6, hdr.version);
    check_int_eq(40, hdr.header_len);
    check_int_eq(60, hdr.total_len);  /* 40 + 20 payload */
    check_int_eq(TUNNEL_IPPROTO_TCP, hdr.protocol);
    check_int_eq(64, hdr.ttl);

    check_int_eq(AF_INET6, hdr.src.family);
    check_int_eq(AF_INET6, hdr.dst.family);

    /* Check src: 2001:db8::1 */
    check_uint_eq(0x20, hdr.src.addr.v6[0]);
    check_uint_eq(0x01, hdr.src.addr.v6[1]);
    check_uint_eq(0x01, hdr.src.addr.v6[15]);

    /* Check dst: 2001:db8::2 */
    check_uint_eq(0x02, hdr.dst.addr.v6[15]);
}

/* =============================================================================
 * TCP Header Parsing Tests
 * ============================================================================= */

void test_tcp_parse_header_syn(void)
{
    tunnel_tcp_header_t hdr;
    const uint8_t *tcp_data = ipv4_tcp_syn + 20;  /* Skip IP header */
    size_t tcp_len = sizeof(ipv4_tcp_syn) - 20;

    int ret = tunnel_tcp_parse_header(tcp_data, tcp_len, &hdr);

    check_int_eq(40, ret);  /* Header with options */
    check_int_eq(49160, hdr.src_port);
    check_int_eq(80, hdr.dst_port);
    check_int_eq(1, hdr.seq);
    check_int_eq(0, hdr.ack);
    check_int_eq(40, hdr.header_len);
    check_int_eq(TUNNEL_TCP_SYN, hdr.flags);
    check_int_eq(65535, hdr.window);
    check_int_eq(20, hdr.options_len);
}

void test_tcp_parse_header_ack(void)
{
    tunnel_tcp_header_t hdr;
    const uint8_t *tcp_data = ipv6_tcp + 40;  /* Skip IPv6 header */
    size_t tcp_len = sizeof(ipv6_tcp) - 40;

    int ret = tunnel_tcp_parse_header(tcp_data, tcp_len, &hdr);

    check_int_eq(20, ret);
    check_int_eq(8080, hdr.src_port);
    check_int_eq(80, hdr.dst_port);
    check_int_eq(10, hdr.seq);
    check_int_eq(20, hdr.ack);
    check_int_eq(TUNNEL_TCP_ACK | TUNNEL_TCP_PSH, hdr.flags);
    check_int_eq(4096, hdr.window);
    check_int_eq(0, hdr.options_len);
}

/* =============================================================================
 * UDP Header Parsing Tests
 * ============================================================================= */

void test_udp_parse_header(void)
{
    tunnel_udp_header_t hdr;
    const uint8_t *udp_data = ipv4_udp_dns + 20;  /* Skip IP header */
    size_t udp_len = sizeof(ipv4_udp_dns) - 20;

    int ret = tunnel_udp_parse_header(udp_data, udp_len, &hdr);

    check_int_eq(8, ret);
    check_int_eq(49152, hdr.src_port);
    check_int_eq(53, hdr.dst_port);
    check_int_eq(21, hdr.length);
}

/* =============================================================================
 * Full Packet Parsing Tests
 * ============================================================================= */

void test_ip_parse_full_tcp(void)
{
    tunnel_packet_t pkt;
    int ret = tunnel_ip_parse(ipv4_tcp_syn, sizeof(ipv4_tcp_syn), &pkt);

    check_int_eq(TUNNEL_OK, ret);
    check_int_eq(4, pkt.ip.version);
    check_int_eq(TUNNEL_IPPROTO_TCP, pkt.ip.protocol);
    check_int_eq(49160, pkt.tcp.src_port);
    check_int_eq(80, pkt.tcp.dst_port);
    check_int_eq(TUNNEL_TCP_SYN, pkt.tcp.flags);
    check_int_eq(0, pkt.payload_len);  /* SYN has no payload */
}

void test_ip_parse_full_udp(void)
{
    tunnel_packet_t pkt;
    int ret = tunnel_ip_parse(ipv4_udp_dns, sizeof(ipv4_udp_dns), &pkt);

    check_int_eq(TUNNEL_OK, ret);
    check_int_eq(4, pkt.ip.version);
    check_int_eq(TUNNEL_IPPROTO_UDP, pkt.ip.protocol);
    check_int_eq(49152, pkt.udp.src_port);
    check_int_eq(53, pkt.udp.dst_port);
    check_int_eq(13, pkt.payload_len);
    check_not_null(pkt.payload);
}

/* =============================================================================
 * Checksum Tests
 * ============================================================================= */

void test_ip_checksum_zero(void)
{
    uint8_t data[] = {0x00, 0x00};
    uint16_t csum = tunnel_ip_checksum(data, sizeof(data));
    check_uint_eq(0xFFFF, csum);
}

void test_ip_checksum_simple(void)
{
    /* IPv4 header with zeroed checksum */
    uint8_t header[20] = {
        0x45, 0x00, 0x00, 0x3c,
        0x1c, 0x46, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,  /* Checksum = 0 */
        0xc0, 0xa8, 0x01, 0x64,
        0x5d, 0xb8, 0xd8, 0x22,
    };

    uint16_t csum = tunnel_ip_checksum(header, sizeof(header));
    check(csum != 0);
}

/* =============================================================================
 * Packet Building Tests
 * ============================================================================= */

void test_ip_build_tcp_syn(void)
{
    uint8_t buf[100];
    tunnel_endpoint_t src = {
        .family = AF_INET,
        .addr.v4 = htonl(0xc0a80101),  /* 192.168.1.1 */
        .port = 12345,
    };
    tunnel_endpoint_t dst = {
        .family = AF_INET,
        .addr.v4 = htonl(0x08080808),  /* 8.8.8.8 */
        .port = 80,
    };

    int len = tunnel_ip_build_tcp(buf, sizeof(buf),
                                   &src, &dst,
                                   1000,           /* seq */
                                   0,              /* ack */
                                   TUNNEL_TCP_SYN, /* flags */
                                   65535,          /* window */
                                   NULL, 0);       /* no payload */

    check(len > 0);
    check_int_eq(40, len);  /* 20 IP + 20 TCP */

    /* Verify we can parse what we built */
    tunnel_packet_t pkt;
    int ret = tunnel_ip_parse(buf, len, &pkt);
    check_int_eq(TUNNEL_OK, ret);
    check_int_eq(12345, pkt.tcp.src_port);
    check_int_eq(80, pkt.tcp.dst_port);
    check_int_eq(1000, pkt.tcp.seq);
    check_int_eq(TUNNEL_TCP_SYN, pkt.tcp.flags);
}

void test_ip_build_tcp_data(void)
{
    uint8_t buf[200];
    const char *payload = "GET / HTTP/1.1\r\n\r\n";
    size_t payload_len = strlen(payload);

    tunnel_endpoint_t src = {
        .family = AF_INET,
        .addr.v4 = htonl(0x0a000001),
        .port = 8080,
    };
    tunnel_endpoint_t dst = {
        .family = AF_INET,
        .addr.v4 = htonl(0x0a000002),
        .port = 80,
    };

    int len = tunnel_ip_build_tcp(buf, sizeof(buf),
                                   &src, &dst,
                                   100, 200,
                                   TUNNEL_TCP_ACK | TUNNEL_TCP_PSH,
                                   32768,
                                   (const uint8_t *)payload, payload_len);

    check_int_eq(40 + (int)payload_len, len);

    tunnel_packet_t pkt;
    int ret = tunnel_ip_parse(buf, len, &pkt);
    check_int_eq(TUNNEL_OK, ret);
    check_int_eq(payload_len, pkt.payload_len);
    check_mem_eq(payload, pkt.payload, payload_len);
}

void test_ip_build_udp(void)
{
    uint8_t buf[100];
    const uint8_t payload[] = {0xde, 0xad, 0xbe, 0xef};

    tunnel_endpoint_t src = {
        .family = AF_INET,
        .addr.v4 = htonl(0x0a000001),
        .port = 5000,
    };
    tunnel_endpoint_t dst = {
        .family = AF_INET,
        .addr.v4 = htonl(0x08080808),
        .port = 53,
    };

    int len = tunnel_ip_build_udp(buf, sizeof(buf),
                                   &src, &dst,
                                   payload, sizeof(payload));

    check_int_eq(28 + 4, len);  /* 20 IP + 8 UDP + 4 payload */

    tunnel_packet_t pkt;
    int ret = tunnel_ip_parse(buf, len, &pkt);
    check_int_eq(TUNNEL_OK, ret);
    check_int_eq(TUNNEL_IPPROTO_UDP, pkt.ip.protocol);
    check_int_eq(5000, pkt.udp.src_port);
    check_int_eq(53, pkt.udp.dst_port);
    check_int_eq(4, pkt.payload_len);
}

void test_ip_build_tcp_rst(void)
{
    uint8_t buf[100];
    tunnel_endpoint_t src = {
        .family = AF_INET,
        .addr.v4 = htonl(0x0a000001),
        .port = 80,
    };
    tunnel_endpoint_t dst = {
        .family = AF_INET,
        .addr.v4 = htonl(0x0a000002),
        .port = 12345,
    };

    int len = tunnel_ip_build_tcp_rst(buf, sizeof(buf), &src, &dst, 999);
    check(len > 0);

    tunnel_packet_t pkt;
    int ret = tunnel_ip_parse(buf, len, &pkt);
    check_int_eq(TUNNEL_OK, ret);
    check_int_eq(TUNNEL_TCP_RST, pkt.tcp.flags);
    check_int_eq(999, pkt.tcp.seq);
}

/* =============================================================================
 * Fragment Detection Tests
 * ============================================================================= */

void test_ip_is_fragment_no(void)
{
    tunnel_packet_t pkt;
    tunnel_ip_parse(ipv4_tcp_syn, sizeof(ipv4_tcp_syn), &pkt);
    check_int_eq(0, tunnel_ip_is_fragment(&pkt));
}

void test_ip_is_fragment_yes(void)
{
    /* Fragmented packet (MF=1, offset=0) */
    uint8_t frag_pkt[40] = {
        0x45, 0x00, 0x00, 0x28,
        0x00, 0x01, 0x20, 0x00,  /* MF=1, offset=0 */
        0x40, 0x06, 0x00, 0x00,
        0x0a, 0x00, 0x00, 0x01,
        0x0a, 0x00, 0x00, 0x02,
    };

    tunnel_packet_t pkt;
    tunnel_ip_parse(frag_pkt, 20, &pkt);
    check_int_eq(1, tunnel_ip_is_fragment(&pkt));
}

spec("tunnel ip stack") {
    before_each() {
        setUp();
    }

    after_each() {
        tearDown();
    }

    describe("ipv4 parsing") {
        it("parses a tcp header") { test_ipv4_parse_header_tcp(); }
        it("parses a udp header") { test_ipv4_parse_header_udp(); }
        it("rejects short packets") { test_ipv4_parse_header_too_short(); }
        it("rejects the wrong version") { test_ipv4_parse_header_wrong_version(); }
    }

    describe("ipv6 parsing") {
        it("parses an ipv6 tcp header") { test_ipv6_parse_header_tcp(); }
    }

    describe("transport parsing") {
        it("parses a syn packet") { test_tcp_parse_header_syn(); }
        it("parses an ack packet") { test_tcp_parse_header_ack(); }
        it("parses a udp header") { test_udp_parse_header(); }
    }

    describe("full packet parsing") {
        it("parses a full tcp packet") { test_ip_parse_full_tcp(); }
        it("parses a full udp packet") { test_ip_parse_full_udp(); }
    }

    describe("checksums") {
        it("computes checksum for zero data") { test_ip_checksum_zero(); }
        it("computes checksum for a simple header") { test_ip_checksum_simple(); }
    }

    describe("packet building") {
        it("builds a tcp syn") { test_ip_build_tcp_syn(); }
        it("builds tcp data") { test_ip_build_tcp_data(); }
        it("builds udp data") { test_ip_build_udp(); }
        it("builds a tcp rst") { test_ip_build_tcp_rst(); }
    }

    describe("fragment detection") {
        it("detects non-fragments") { test_ip_is_fragment_no(); }
        it("detects fragments") { test_ip_is_fragment_yes(); }
    }
}

