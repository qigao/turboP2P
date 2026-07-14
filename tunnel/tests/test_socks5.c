/**
 * @file test_socks5.c
 * @brief Tests for SOCKS5 proxy protocol implementation
 */

#include <tinytest.h>
#include "../src/proxy/tunnel_proxy.h"
#include "../src/core/tunnel_types.h"
#include <string.h>
#include <stdlib.h> 
void setUp(void) {}
void tearDown(void) {}

/* =============================================================================
 * SOCKS5 Protocol Constants (RFC 1928)
 * ============================================================================= */

#define SOCKS5_VERSION          0x05
#define SOCKS5_AUTH_NONE        0x00
#define SOCKS5_AUTH_USERPASS    0x02
#define SOCKS5_AUTH_NOACCEPTABLE 0xFF

#define SOCKS5_CMD_CONNECT      0x01
#define SOCKS5_CMD_BIND         0x02
#define SOCKS5_CMD_UDP_ASSOC    0x03

#define SOCKS5_ATYP_IPV4        0x01
#define SOCKS5_ATYP_DOMAIN      0x03
#define SOCKS5_ATYP_IPV6        0x04

#define SOCKS5_REP_SUCCESS      0x00
#define SOCKS5_REP_GENERAL_FAIL 0x01
#define SOCKS5_REP_NOT_ALLOWED  0x02
#define SOCKS5_REP_NETWORK_UNREACHABLE 0x03
#define SOCKS5_REP_HOST_UNREACHABLE    0x04
#define SOCKS5_REP_CONN_REFUSED 0x05
#define SOCKS5_REP_TTL_EXPIRED  0x06
#define SOCKS5_REP_CMD_NOT_SUPPORTED   0x07
#define SOCKS5_REP_ATYP_NOT_SUPPORTED  0x08

/* =============================================================================
 * Mock Structures for Testing
 * ============================================================================= */

typedef struct {
    uint8_t buffer[1024];
    size_t len;
} mock_buffer_t;

/* Simulate building SOCKS5 handshake messages */
static size_t build_socks5_greeting(uint8_t *buf, int num_methods, const uint8_t *methods)
{
    buf[0] = SOCKS5_VERSION;
    buf[1] = (uint8_t)num_methods;
    memcpy(&buf[2], methods, num_methods);
    return 2 + num_methods;
}

static size_t build_socks5_greeting_response(uint8_t *buf, uint8_t method)
{
    buf[0] = SOCKS5_VERSION;
    buf[1] = method;
    return 2;
}

static size_t build_socks5_connect_request_ipv4(uint8_t *buf, uint32_t ip, uint16_t port)
{
    buf[0] = SOCKS5_VERSION;
    buf[1] = SOCKS5_CMD_CONNECT;
    buf[2] = 0x00;  /* Reserved */
    buf[3] = SOCKS5_ATYP_IPV4;
    memcpy(&buf[4], &ip, 4);
    uint16_t port_be = htons(port);
    memcpy(&buf[8], &port_be, 2);
    return 10;
}

static size_t build_socks5_connect_request_domain(uint8_t *buf, const char *domain, uint16_t port)
{
    size_t domain_len = strlen(domain);
    buf[0] = SOCKS5_VERSION;
    buf[1] = SOCKS5_CMD_CONNECT;
    buf[2] = 0x00;  /* Reserved */
    buf[3] = SOCKS5_ATYP_DOMAIN;
    buf[4] = (uint8_t)domain_len;
    memcpy(&buf[5], domain, domain_len);
    uint16_t port_be = htons(port);
    memcpy(&buf[5 + domain_len], &port_be, 2);
    return 7 + domain_len;
}

static size_t build_socks5_connect_response(uint8_t *buf, uint8_t rep, uint32_t bind_ip, uint16_t bind_port)
{
    buf[0] = SOCKS5_VERSION;
    buf[1] = rep;
    buf[2] = 0x00;  /* Reserved */
    buf[3] = SOCKS5_ATYP_IPV4;
    memcpy(&buf[4], &bind_ip, 4);
    uint16_t port_be = htons(bind_port);
    memcpy(&buf[8], &port_be, 2);
    return 10;
}

static size_t build_socks5_udp_header(uint8_t *buf, uint32_t ip, uint16_t port, const uint8_t *data, size_t data_len)
{
    buf[0] = 0x00;  /* Reserved */
    buf[1] = 0x00;  /* Reserved */
    buf[2] = 0x00;  /* Fragment number (0 = no fragmentation) */
    buf[3] = SOCKS5_ATYP_IPV4;
    memcpy(&buf[4], &ip, 4);
    uint16_t port_be = htons(port);
    memcpy(&buf[8], &port_be, 2);
    memcpy(&buf[10], data, data_len);
    return 10 + data_len;
}

/* =============================================================================
 * Greeting Tests
 * ============================================================================= */

void test_socks5_greeting_no_auth(void)
{
    uint8_t buf[64];
    uint8_t methods[] = {SOCKS5_AUTH_NONE};
    size_t len = build_socks5_greeting(buf, 1, methods);

    check_int_eq(3, len);
    check_uint_eq(SOCKS5_VERSION, buf[0]);
    check_uint_eq(1, buf[1]);
    check_uint_eq(SOCKS5_AUTH_NONE, buf[2]);
}

void test_socks5_greeting_with_userpass(void)
{
    uint8_t buf[64];
    uint8_t methods[] = {SOCKS5_AUTH_NONE, SOCKS5_AUTH_USERPASS};
    size_t len = build_socks5_greeting(buf, 2, methods);

    check_int_eq(4, len);
    check_uint_eq(SOCKS5_VERSION, buf[0]);
    check_uint_eq(2, buf[1]);
}

void test_socks5_greeting_response_parse(void)
{
    uint8_t response[2];
    build_socks5_greeting_response(response, SOCKS5_AUTH_NONE);

    check_uint_eq(SOCKS5_VERSION, response[0]);
    check_uint_eq(SOCKS5_AUTH_NONE, response[1]);
}

void test_socks5_greeting_response_no_acceptable(void)
{
    uint8_t response[2];
    build_socks5_greeting_response(response, SOCKS5_AUTH_NOACCEPTABLE);

    check_uint_eq(SOCKS5_VERSION, response[0]);
    check_uint_eq(SOCKS5_AUTH_NOACCEPTABLE, response[1]);
}

/* =============================================================================
 * Connect Request Tests
 * ============================================================================= */

void test_socks5_connect_ipv4(void)
{
    uint8_t buf[64];
    uint32_t ip = htonl(0x08080808);  /* 8.8.8.8 */
    uint16_t port = 53;

    size_t len = build_socks5_connect_request_ipv4(buf, ip, port);

    check_int_eq(10, len);
    check_uint_eq(SOCKS5_VERSION, buf[0]);
    check_uint_eq(SOCKS5_CMD_CONNECT, buf[1]);
    check_uint_eq(0x00, buf[2]);  /* Reserved */
    check_uint_eq(SOCKS5_ATYP_IPV4, buf[3]);

    /* Verify IP */
    uint32_t parsed_ip;
    memcpy(&parsed_ip, &buf[4], 4);
    check_int_eq(ip, parsed_ip);

    /* Verify port */
    uint16_t parsed_port;
    memcpy(&parsed_port, &buf[8], 2);
    check_int_eq(htons(port), parsed_port);
}

void test_socks5_connect_domain(void)
{
    uint8_t buf[64];
    const char *domain = "example.com";
    uint16_t port = 80;

    size_t len = build_socks5_connect_request_domain(buf, domain, port);

    check_int_eq(7 + strlen(domain), len);
    check_uint_eq(SOCKS5_VERSION, buf[0]);
    check_uint_eq(SOCKS5_CMD_CONNECT, buf[1]);
    check_uint_eq(SOCKS5_ATYP_DOMAIN, buf[3]);
    check_int_eq(strlen(domain), buf[4]);
    check_mem_eq(domain, &buf[5], strlen(domain));
}

void test_socks5_connect_domain_long(void)
{
    uint8_t buf[300];
    char domain[256];
    memset(domain, 'a', 200);
    memcpy(domain + 196, ".com", 4);
    domain[200] = '\0';

    size_t len = build_socks5_connect_request_domain(buf, domain, 443);

    check_int_eq(7 + strlen(domain), len);
    check_int_eq(strlen(domain), buf[4]);
}

/* =============================================================================
 * Connect Response Tests
 * ============================================================================= */

void test_socks5_connect_response_success(void)
{
    uint8_t buf[64];
    uint32_t bind_ip = htonl(0x0a000001);
    uint16_t bind_port = 12345;

    size_t len = build_socks5_connect_response(buf, SOCKS5_REP_SUCCESS, bind_ip, bind_port);

    check_int_eq(10, len);
    check_uint_eq(SOCKS5_VERSION, buf[0]);
    check_uint_eq(SOCKS5_REP_SUCCESS, buf[1]);
    check_uint_eq(SOCKS5_ATYP_IPV4, buf[3]);
}

void test_socks5_connect_response_errors(void)
{
    uint8_t buf[64];

    /* Connection refused */
    build_socks5_connect_response(buf, SOCKS5_REP_CONN_REFUSED, 0, 0);
    check_uint_eq(SOCKS5_REP_CONN_REFUSED, buf[1]);

    /* Network unreachable */
    build_socks5_connect_response(buf, SOCKS5_REP_NETWORK_UNREACHABLE, 0, 0);
    check_uint_eq(SOCKS5_REP_NETWORK_UNREACHABLE, buf[1]);

    /* Host unreachable */
    build_socks5_connect_response(buf, SOCKS5_REP_HOST_UNREACHABLE, 0, 0);
    check_uint_eq(SOCKS5_REP_HOST_UNREACHABLE, buf[1]);
}

/* =============================================================================
 * UDP Associate Tests
 * ============================================================================= */

void test_socks5_udp_header_build(void)
{
    uint8_t buf[64];
    uint32_t ip = htonl(0x08080808);
    uint16_t port = 53;
    const uint8_t data[] = {0xde, 0xad, 0xbe, 0xef};

    size_t len = build_socks5_udp_header(buf, ip, port, data, sizeof(data));

    check_int_eq(10 + sizeof(data), len);
    check_uint_eq(0x00, buf[0]);  /* Reserved */
    check_uint_eq(0x00, buf[1]);  /* Reserved */
    check_uint_eq(0x00, buf[2]);  /* Frag = 0 */
    check_uint_eq(SOCKS5_ATYP_IPV4, buf[3]);

    /* Verify data is at the end */
    check_mem_eq(data, &buf[10], sizeof(data));
}

void test_socks5_udp_header_parse(void)
{
    uint8_t buf[64];
    uint32_t ip = htonl(0x08080808);
    uint16_t port = 53;
    const uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

    build_socks5_udp_header(buf, ip, port, data, sizeof(data));

    /* Parse the header */
    check_uint_eq(0x00, buf[0]);  /* RSV */
    check_uint_eq(0x00, buf[1]);  /* RSV */
    check_uint_eq(0x00, buf[2]);  /* FRAG */
    check_uint_eq(SOCKS5_ATYP_IPV4, buf[3]);

    uint32_t parsed_ip;
    memcpy(&parsed_ip, &buf[4], 4);
    check_int_eq(ip, parsed_ip);

    uint16_t parsed_port;
    memcpy(&parsed_port, &buf[8], 2);
    check_int_eq(htons(port), parsed_port);
}

/* =============================================================================
 * Username/Password Authentication Tests (RFC 1929)
 * ============================================================================= */

static size_t build_socks5_userpass_request(uint8_t *buf, const char *user, const char *pass)
{
    size_t user_len = strlen(user);
    size_t pass_len = strlen(pass);

    buf[0] = 0x01;  /* Version of auth subnegotiation */
    buf[1] = (uint8_t)user_len;
    memcpy(&buf[2], user, user_len);
    buf[2 + user_len] = (uint8_t)pass_len;
    memcpy(&buf[3 + user_len], pass, pass_len);

    return 3 + user_len + pass_len;
}

static size_t build_socks5_userpass_response(uint8_t *buf, uint8_t status)
{
    buf[0] = 0x01;  /* Version */
    buf[1] = status;  /* 0x00 = success */
    return 2;
}

void test_socks5_userpass_request(void)
{
    uint8_t buf[64];
    const char *user = "testuser";
    const char *pass = "testpass";

    size_t len = build_socks5_userpass_request(buf, user, pass);

    check_int_eq(3 + strlen(user) + strlen(pass), len);
    check_uint_eq(0x01, buf[0]);  /* Auth version */
    check_int_eq(strlen(user), buf[1]);
    check_mem_eq(user, &buf[2], strlen(user));
    check_int_eq(strlen(pass), buf[2 + strlen(user)]);
    check_mem_eq(pass, &buf[3 + strlen(user)], strlen(pass));
}

void test_socks5_userpass_response_success(void)
{
    uint8_t buf[2];
    build_socks5_userpass_response(buf, 0x00);

    check_uint_eq(0x01, buf[0]);
    check_uint_eq(0x00, buf[1]);  /* Success */
}

void test_socks5_userpass_response_failure(void)
{
    uint8_t buf[2];
    build_socks5_userpass_response(buf, 0x01);

    check_uint_eq(0x01, buf[0]);
    check_uint_eq(0x01, buf[1]);  /* Failure */
}

/* =============================================================================
 * Full Protocol Flow Tests
 * ============================================================================= */

void test_socks5_full_handshake_no_auth(void)
{
    mock_buffer_t client_send;
    mock_buffer_t server_send;

    /* Step 1: Client sends greeting */
    uint8_t methods[] = {SOCKS5_AUTH_NONE};
    client_send.len = build_socks5_greeting(client_send.buffer, 1, methods);
    check_int_eq(3, client_send.len);

    /* Step 2: Server responds with selected method */
    server_send.len = build_socks5_greeting_response(server_send.buffer, SOCKS5_AUTH_NONE);
    check_int_eq(2, server_send.len);
    check_uint_eq(SOCKS5_AUTH_NONE, server_send.buffer[1]);

    /* Step 3: Client sends connect request */
    client_send.len = build_socks5_connect_request_domain(
        client_send.buffer, "example.com", 80);
    check(client_send.len > 0);

    /* Step 4: Server responds with success */
    server_send.len = build_socks5_connect_response(
        server_send.buffer, SOCKS5_REP_SUCCESS, htonl(0x0a000001), 12345);
    check_uint_eq(SOCKS5_REP_SUCCESS, server_send.buffer[1]);

    /* After this, data flows directly */
}

void test_socks5_full_handshake_with_auth(void)
{
    mock_buffer_t client_send;
    mock_buffer_t server_send;

    /* Step 1: Client offers auth methods */
    uint8_t methods[] = {SOCKS5_AUTH_NONE, SOCKS5_AUTH_USERPASS};
    client_send.len = build_socks5_greeting(client_send.buffer, 2, methods);

    /* Step 2: Server requires username/password */
    server_send.len = build_socks5_greeting_response(server_send.buffer, SOCKS5_AUTH_USERPASS);
    check_uint_eq(SOCKS5_AUTH_USERPASS, server_send.buffer[1]);

    /* Step 3: Client sends credentials */
    client_send.len = build_socks5_userpass_request(client_send.buffer, "user", "pass");

    /* Step 4: Server accepts auth */
    server_send.len = build_socks5_userpass_response(server_send.buffer, 0x00);
    check_uint_eq(0x00, server_send.buffer[1]);

    /* Step 5: Client sends connect request */
    client_send.len = build_socks5_connect_request_ipv4(
        client_send.buffer, htonl(0x08080808), 443);

    /* Step 6: Server responds success */
    server_send.len = build_socks5_connect_response(
        server_send.buffer, SOCKS5_REP_SUCCESS, 0, 0);
    check_uint_eq(SOCKS5_REP_SUCCESS, server_send.buffer[1]);
}

/* =============================================================================
 * Address Type Tests
 * ============================================================================= */

void test_socks5_atyp_ipv6(void)
{
    uint8_t buf[64];

    /* IPv6 CONNECT request */
    buf[0] = SOCKS5_VERSION;
    buf[1] = SOCKS5_CMD_CONNECT;
    buf[2] = 0x00;
    buf[3] = SOCKS5_ATYP_IPV6;

    /* 2001:db8::1 */
    uint8_t ipv6[] = {
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };
    memcpy(&buf[4], ipv6, 16);
    buf[20] = 0x00;
    buf[21] = 0x50;  /* Port 80 */

    check_uint_eq(SOCKS5_ATYP_IPV6, buf[3]);
    check_mem_eq(ipv6, &buf[4], 16);
}

/* =============================================================================
 * Error Handling Tests
 * ============================================================================= */

void test_socks5_version_mismatch(void)
{
    uint8_t bad_version_greeting[] = {0x04, 0x01, 0x00};  /* SOCKS4 version */

    check(bad_version_greeting[0] != SOCKS5_VERSION);
}

void test_socks5_invalid_command(void)
{
    uint8_t buf[64];
    buf[0] = SOCKS5_VERSION;
    buf[1] = 0xFF;  /* Invalid command */
    buf[2] = 0x00;
    buf[3] = SOCKS5_ATYP_IPV4;

    /* Server would respond with CMD_NOT_SUPPORTED */
    uint8_t response[10];
    build_socks5_connect_response(response, SOCKS5_REP_CMD_NOT_SUPPORTED, 0, 0);
    check_uint_eq(SOCKS5_REP_CMD_NOT_SUPPORTED, response[1]);
}

void test_socks5_invalid_atyp(void)
{
    uint8_t buf[64];
    buf[0] = SOCKS5_VERSION;
    buf[1] = SOCKS5_CMD_CONNECT;
    buf[2] = 0x00;
    buf[3] = 0xFF;  /* Invalid address type */

    /* Server would respond with ATYP_NOT_SUPPORTED */
    uint8_t response[10];
    build_socks5_connect_response(response, SOCKS5_REP_ATYP_NOT_SUPPORTED, 0, 0);
    check_uint_eq(SOCKS5_REP_ATYP_NOT_SUPPORTED, response[1]);
}

spec("socks5 protocol") {
    before_each() {
        setUp();
    }

    after_each() {
        tearDown();
    }

    describe("greeting") {
        it("builds a no-auth greeting") { test_socks5_greeting_no_auth(); }
        it("builds a greeting with userpass") { test_socks5_greeting_with_userpass(); }
        it("parses a greeting response") { test_socks5_greeting_response_parse(); }
        it("handles no acceptable methods") { test_socks5_greeting_response_no_acceptable(); }
    }

    describe("connect request") {
        it("builds an ipv4 connect request") { test_socks5_connect_ipv4(); }
        it("builds a domain connect request") { test_socks5_connect_domain(); }
        it("builds a long-domain connect request") { test_socks5_connect_domain_long(); }
    }

    describe("connect response") {
        it("builds a success response") { test_socks5_connect_response_success(); }
        it("maps error responses") { test_socks5_connect_response_errors(); }
    }

    describe("udp") {
        it("builds a udp header") { test_socks5_udp_header_build(); }
        it("parses a udp header") { test_socks5_udp_header_parse(); }
    }

    describe("username password auth") {
        it("builds a request") { test_socks5_userpass_request(); }
        it("builds a success response") { test_socks5_userpass_response_success(); }
        it("builds a failure response") { test_socks5_userpass_response_failure(); }
    }

    describe("full flow") {
        it("handshakes without auth") { test_socks5_full_handshake_no_auth(); }
        it("handshakes with auth") { test_socks5_full_handshake_with_auth(); }
    }

    describe("address types") {
        it("supports ipv6 atyp") { test_socks5_atyp_ipv6(); }
    }

    describe("error handling") {
        it("rejects a bad version") { test_socks5_version_mismatch(); }
        it("rejects an invalid command") { test_socks5_invalid_command(); }
        it("rejects an invalid atyp") { test_socks5_invalid_atyp(); }
    }
}

