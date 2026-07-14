/**
 * @file test_fake_dns.c
 * @brief Tests for Fake DNS domain tracking
 */

#include <tinytest.h>
#include "../src/dns/tunnel_fake_dns.h"
#include "../src/core/tunnel_types.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h> 
#include <fmt.h>

/* Default Fake DNS configuration */
#define TEST_BASE_IP    0xC6120000  /* 198.18.0.0 */
#define TEST_MASK       0xFFFE0000  /* /15 */
#define TEST_TTL        300

static tunnel_t *mock_tunnel = NULL;
static tunnel_fake_dns_t *dns = NULL;

void setUp(void)
{
    mock_tunnel = (tunnel_t *)calloc(1, sizeof(tunnel_t));
    dns = tunnel_fake_dns_create(mock_tunnel, htonl(TEST_BASE_IP), htonl(TEST_MASK), TEST_TTL);
}

void tearDown(void)
{
    if (dns) {
        tunnel_fake_dns_destroy(dns);
        dns = NULL;
    }
    if (mock_tunnel) {
        free(mock_tunnel);
        mock_tunnel = NULL;
    }
}
/* =============================================================================
 * IP Allocation Tests
 * ============================================================================= */

void test_fake_dns_get_ip_basic(void)
{
    uint32_t ip = tunnel_fake_dns_get_ip(dns, "example.com");

    check(ip != 0);
    check_int_eq(1, tunnel_fake_dns_is_fake_ip(dns, ip));
}

void test_fake_dns_get_ip_deterministic(void)
{
    /* Same domain should return same IP */
    uint32_t ip1 = tunnel_fake_dns_get_ip(dns, "example.com");
    uint32_t ip2 = tunnel_fake_dns_get_ip(dns, "example.com");

    check_int_eq(ip1, ip2);
}

void test_fake_dns_get_ip_different_domains(void)
{
    uint32_t ip1 = tunnel_fake_dns_get_ip(dns, "example.com");
    uint32_t ip2 = tunnel_fake_dns_get_ip(dns, "google.com");

    check(ip1 != ip2);
}

void test_fake_dns_get_ip_in_range(void)
{
    uint32_t ip = tunnel_fake_dns_get_ip(dns, "test.example.com");

    /* IP should be in the fake DNS range */
    uint32_t ip_host = ntohl(ip);
    uint32_t base = TEST_BASE_IP;
    uint32_t mask = TEST_MASK;

    check_int_eq(base & mask, ip_host & mask);
}

void test_fake_dns_allocate_many(void)
{
    /* Allocate many fake IPs */
    char domain[64];
    uint32_t ips[100];

    for (int i = 0; i < 100; i++) {
        fmt(domain, sizeof(domain), "domain{}.example.com", i);
        ips[i] = tunnel_fake_dns_get_ip(dns, domain);
        check(ips[i] != 0);
    }

    /* All IPs should be unique */
    for (int i = 0; i < 100; i++) {
        for (int j = i + 1; j < 100; j++) {
            check(ips[i] != ips[j]);
        }
    }
}

/* =============================================================================
 * Domain Lookup Tests
 * ============================================================================= */

void test_fake_dns_get_domain(void)
{
    uint32_t ip = tunnel_fake_dns_get_ip(dns, "example.com");

    const char *domain = tunnel_fake_dns_get_domain(dns, ip);
    check_not_null(domain);
    check_str_eq("example.com", domain);
}

void test_fake_dns_get_domain_not_found(void)
{
    /* Non-fake IP should return NULL */
    uint32_t fake_ip = htonl(0x08080808);  /* 8.8.8.8 - not in range */

    const char *domain = tunnel_fake_dns_get_domain(dns, fake_ip);
    check_null(domain);
}

void test_fake_dns_get_domain_unallocated(void)
{
    /* IP in range but not allocated */
    uint32_t fake_ip = htonl(TEST_BASE_IP + 12345);

    const char *domain = tunnel_fake_dns_get_domain(dns, fake_ip);
    check_null(domain);
}

/* =============================================================================
 * Fake IP Detection Tests
 * ============================================================================= */

void test_fake_dns_is_fake_ip_yes(void)
{
    uint32_t ip = tunnel_fake_dns_get_ip(dns, "test.com");
    check_int_eq(1, tunnel_fake_dns_is_fake_ip(dns, ip));
}

void test_fake_dns_is_fake_ip_no(void)
{
    /* 8.8.8.8 should not be fake */
    check_int_eq(0, tunnel_fake_dns_is_fake_ip(dns, htonl(0x08080808)));

    /* 192.168.1.1 should not be fake */
    check_int_eq(0, tunnel_fake_dns_is_fake_ip(dns, htonl(0xc0a80101)));

    /* 10.0.0.1 should not be fake */
    check_int_eq(0, tunnel_fake_dns_is_fake_ip(dns, htonl(0x0a000001)));
}

void test_fake_dns_is_fake_ip_boundary(void)
{
    /* Test boundary of fake DNS range */
    uint32_t base = TEST_BASE_IP;
    uint32_t end = base + ~TEST_MASK;

    /* Just inside range */
    check_int_eq(1, tunnel_fake_dns_is_fake_ip(dns, htonl(base)));
    check_int_eq(1, tunnel_fake_dns_is_fake_ip(dns, htonl(end)));

    /* Just outside range */
    check_int_eq(0, tunnel_fake_dns_is_fake_ip(dns, htonl(base - 1)));
    check_int_eq(0, tunnel_fake_dns_is_fake_ip(dns, htonl(end + 1)));
}

void test_fake_dns_parse_config_range(void)
{
    uint32_t base_ip = 0;
    uint32_t mask = 0;

    check_int_eq(TUNNEL_OK,
                 tunnel_config_parse_fake_dns_range("203.0.113.0/24", &base_ip, &mask));
    check_int_eq(0xcb007100, ntohl(base_ip));
    check_int_eq(0xffffff00, ntohl(mask));
}

void test_fake_dns_parse_config_range_canonicalizes_base(void)
{
    uint32_t base_ip = 0;
    uint32_t mask = 0;
    tunnel_fake_dns_t *custom_dns = NULL;
    uint32_t ip = 0;

    check_int_eq(TUNNEL_OK,
                 tunnel_config_parse_fake_dns_range("203.0.113.17/30", &base_ip, &mask));
    check_int_eq(0xcb007110, ntohl(base_ip));
    check_int_eq(0xfffffffc, ntohl(mask));

    custom_dns = tunnel_fake_dns_create(mock_tunnel, base_ip, mask, TEST_TTL);
    check_not_null(custom_dns);
    ip = tunnel_fake_dns_get_ip(custom_dns, "canonical.example");
    check_int_eq(0xcb007110, ntohl(ip));
    check_int_eq(1, tunnel_fake_dns_is_fake_ip(custom_dns, htonl(0xcb007110)));
    check_int_eq(1, tunnel_fake_dns_is_fake_ip(custom_dns, htonl(0xcb007113)));
    check_int_eq(0, tunnel_fake_dns_is_fake_ip(custom_dns, htonl(0xcb007114)));
    tunnel_fake_dns_destroy(custom_dns);
}

void test_fake_dns_parse_config_range_rejects_invalid(void)
{
    uint32_t base_ip = 0;
    uint32_t mask = 0;

    check_int_eq(TUNNEL_ERR_INVALID_ARG,
                 tunnel_config_parse_fake_dns_range("not-a-cidr", &base_ip, &mask));
}

void test_fake_dns_parse_config_range_rejects_zero_prefix(void)
{
    uint32_t base_ip = 0;
    uint32_t mask = 0;

    check_int_eq(TUNNEL_ERR_INVALID_ARG,
                 tunnel_config_parse_fake_dns_range("0.0.0.0/0", &base_ip, &mask));
}

void test_fake_dns_file_config_persists_range_key(void)
{
    const char *path = "test_fake_dns_config.tmp";
    tunnel_config_t config;
    FILE *fp = fopen(path, "w");

    check_not_null(fp);
    if (!fp) {
        return;
    }

    fprintf(fp, "proxy.type = none\n");
    fprintf(fp, "dns.hijack = true\n");
    fprintf(fp, "dns.fake = true\n");
    fprintf(fp, "dns.fake_dns_range = 203.0.113.0/24\n");
    fclose(fp);

    check_int_eq(TUNNEL_OK, tunnel_config_parse_file(path, &config));
    remove(path);

    check_int_eq(1, config.dns.hijack_dns);
    check_int_eq(1, config.dns.fake_dns);
    check_not_null(config.dns.fake_dns_range);
    check_str_eq("203.0.113.0/24", config.dns.fake_dns_range);

    tunnel_config_free_parsed_strings(&config);
}

/* =============================================================================
 * DNS Query Processing Tests
 * ============================================================================= */

/* Standard DNS query for example.com A record */
static const uint8_t dns_query_example_com[] = {
    /* Header */
    0x00, 0x01,                         /* Transaction ID */
    0x01, 0x00,                         /* Flags: Standard query */
    0x00, 0x01,                         /* Questions: 1 */
    0x00, 0x00,                         /* Answers: 0 */
    0x00, 0x00,                         /* Authority: 0 */
    0x00, 0x00,                         /* Additional: 0 */
    /* Query */
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,                               /* Root label */
    0x00, 0x01,                         /* Type: A */
    0x00, 0x01,                         /* Class: IN */
};

void test_fake_dns_extract_domain(void)
{
    char domain[256];
    int ret = tunnel_fake_dns_extract_domain(
        dns_query_example_com, sizeof(dns_query_example_com),
        domain, sizeof(domain)
    );

    check_int_eq(TUNNEL_OK, ret);
    check_str_eq("example.com", domain);
}

void test_fake_dns_process_query_a_record(void)
{
    uint8_t response[512];
    size_t response_len = 0;

    int handled = tunnel_fake_dns_process_query(
        dns,
        dns_query_example_com, sizeof(dns_query_example_com),
        response, &response_len, sizeof(response)
    );

    check_int_eq(1, handled);
    check(response_len > sizeof(dns_query_example_com));

    /* Response should contain the fake IP */
    uint32_t expected_ip = tunnel_fake_dns_get_ip(dns, "example.com");

    /* Find IP in response (should be in answer section) */
    int found_ip = 0;
    for (size_t i = 0; i < response_len - 3; i++) {
        uint32_t *ptr = (uint32_t *)&response[i];
        if (*ptr == expected_ip) {
            found_ip = 1;
            break;
        }
    }
    check_int_eq(1, found_ip);
}

void test_fake_dns_extract_domain_subdomain(void)
{
    /* Query for www.example.com */
    static const uint8_t query[] = {
        0x00, 0x02, 0x01, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 'w', 'w', 'w',
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,
        0x00, 0x01, 0x00, 0x01,
    };

    char domain[256];
    int ret = tunnel_fake_dns_extract_domain(query, sizeof(query), domain, sizeof(domain));

    check_int_eq(TUNNEL_OK, ret);
    check_str_eq("www.example.com", domain);
}

void test_fake_dns_extract_domain_long(void)
{
    /* Very long domain name */
    uint8_t query[512];
    memcpy(query, dns_query_example_com, 12);  /* Header */

    /* Build long domain: aaaa...aaaa.bbbb...bbbb.example.com */
    int pos = 12;
    query[pos++] = 63;  /* 63 'a's */
    for (int i = 0; i < 63; i++) query[pos++] = 'a';
    query[pos++] = 63;  /* 63 'b's */
    for (int i = 0; i < 63; i++) query[pos++] = 'b';
    query[pos++] = 7;
    memcpy(&query[pos], "example", 7);
    pos += 7;
    query[pos++] = 3;
    memcpy(&query[pos], "com", 3);
    pos += 3;
    query[pos++] = 0;  /* Root */
    query[pos++] = 0x00;
    query[pos++] = 0x01;  /* Type A */
    query[pos++] = 0x00;
    query[pos++] = 0x01;  /* Class IN */

    char domain[256];
    int ret = tunnel_fake_dns_extract_domain(query, pos, domain, sizeof(domain));

    check_int_eq(TUNNEL_OK, ret);
    check(strlen(domain) > 100);
}

/* =============================================================================
 * Cache Management Tests
 * ============================================================================= */

void test_fake_dns_count(void)
{
    check_int_eq(0, tunnel_fake_dns_count(dns));

    tunnel_fake_dns_get_ip(dns, "a.com");
    check_int_eq(1, tunnel_fake_dns_count(dns));

    tunnel_fake_dns_get_ip(dns, "b.com");
    check_int_eq(2, tunnel_fake_dns_count(dns));

    /* Same domain doesn't increase count */
    tunnel_fake_dns_get_ip(dns, "a.com");
    check_int_eq(2, tunnel_fake_dns_count(dns));
}

void test_fake_dns_clear(void)
{
    tunnel_fake_dns_get_ip(dns, "example.com");
    tunnel_fake_dns_get_ip(dns, "google.com");

    check_int_eq(2, tunnel_fake_dns_count(dns));

    tunnel_fake_dns_clear(dns);

    check_int_eq(0, tunnel_fake_dns_count(dns));

    /* After clear, same domain can be allocated again */
    tunnel_fake_dns_get_ip(dns, "example.com");
    tunnel_fake_dns_clear(dns);
    uint32_t new_ip = tunnel_fake_dns_get_ip(dns, "example.com");

    /* IPs might be same or different depending on implementation */
    /* Just verify we can still allocate */
    check(new_ip != 0);
}

/* =============================================================================
 * Statistics Tests
 * ============================================================================= */

void test_fake_dns_stats(void)
{
    uint64_t queries, hits, allocations;

    /* Initial stats should be zero */
    tunnel_fake_dns_get_stats(dns, &queries, &hits, &allocations);
    check_int_eq(0, queries);
    check_int_eq(0, hits);
    check_int_eq(0, allocations);

    /* First query for domain - allocation */
    tunnel_fake_dns_get_ip(dns, "example.com");
    tunnel_fake_dns_get_stats(dns, &queries, &hits, &allocations);
    check_int_eq(1, queries);
    check_int_eq(0, hits);
    check_int_eq(1, allocations);

    /* Second query for same domain - hit */
    tunnel_fake_dns_get_ip(dns, "example.com");
    tunnel_fake_dns_get_stats(dns, &queries, &hits, &allocations);
    check_int_eq(2, queries);
    check_int_eq(1, hits);
    check_int_eq(1, allocations);

    /* Query for new domain - allocation */
    tunnel_fake_dns_get_ip(dns, "google.com");
    tunnel_fake_dns_get_stats(dns, &queries, &hits, &allocations);
    check_int_eq(3, queries);
    check_int_eq(1, hits);
    check_int_eq(2, allocations);
}

/* =============================================================================
 * Edge Cases
 * ============================================================================= */

void test_fake_dns_empty_domain(void)
{
    uint32_t ip = tunnel_fake_dns_get_ip(dns, "");
    /* Should either return 0 or allocate (implementation dependent) */
    /* Just verify no crash */
    (void)ip;
}

void test_fake_dns_null_domain(void)
{
    /* Should handle NULL gracefully */
    uint32_t ip = tunnel_fake_dns_get_ip(dns, NULL);
    check_int_eq(0, ip);
}

void test_fake_dns_case_sensitivity(void)
{
    uint32_t ip1 = tunnel_fake_dns_get_ip(dns, "Example.COM");
    uint32_t ip2 = tunnel_fake_dns_get_ip(dns, "example.com");

    /* DNS is case-insensitive, so these should be the same */
    check_int_eq(ip1, ip2);
}

void test_fake_dns_special_characters(void)
{
    /* Domains with hyphens and numbers */
    uint32_t ip1 = tunnel_fake_dns_get_ip(dns, "my-domain-123.example.com");
    check(ip1 != 0);

    const char *domain = tunnel_fake_dns_get_domain(dns, ip1);
    check_str_eq("my-domain-123.example.com", domain);
}

void test_fake_dns_very_long_domain(void)
{
    /* Max domain length is 253 characters */
    char long_domain[260];
    memset(long_domain, 'a', 250);
    memcpy(long_domain + 246, ".com", 4);
    long_domain[250] = '\0';

    uint32_t ip = tunnel_fake_dns_get_ip(dns, long_domain);
    /* Should either allocate or gracefully fail */
    /* Just verify no crash */
    (void)ip;
}

spec("fake dns") {
    before_each() {
        setUp();
    }

    after_each() {
        tearDown();
    }

    describe("ip allocation") {
        it("allocates a basic fake ip") { test_fake_dns_get_ip_basic(); }
        it("returns deterministic ips") { test_fake_dns_get_ip_deterministic(); }
        it("separates different domains") { test_fake_dns_get_ip_different_domains(); }
        it("keeps ips inside the configured range") { test_fake_dns_get_ip_in_range(); }
        it("allocates many unique ips") { test_fake_dns_allocate_many(); }
    }

    describe("domain lookup") {
        it("maps fake ip back to domain") { test_fake_dns_get_domain(); }
        it("returns null for non-fake ips") { test_fake_dns_get_domain_not_found(); }
        it("returns null for unallocated fake ips") { test_fake_dns_get_domain_unallocated(); }
    }

    describe("fake ip detection") {
        it("detects fake ips") { test_fake_dns_is_fake_ip_yes(); }
        it("rejects real ips") { test_fake_dns_is_fake_ip_no(); }
        it("handles range boundaries") { test_fake_dns_is_fake_ip_boundary(); }
        it("parses configured ranges") { test_fake_dns_parse_config_range(); }
        it("canonicalizes configured range bases") { test_fake_dns_parse_config_range_canonicalizes_base(); }
        it("rejects invalid configured ranges") { test_fake_dns_parse_config_range_rejects_invalid(); }
        it("rejects zero-prefix configured ranges") { test_fake_dns_parse_config_range_rejects_zero_prefix(); }
        it("persists fake dns range through file config") { test_fake_dns_file_config_persists_range_key(); }
    }

    describe("dns query processing") {
        it("extracts the queried domain") { test_fake_dns_extract_domain(); }
        it("processes an a-record query") { test_fake_dns_process_query_a_record(); }
        it("extracts subdomains") { test_fake_dns_extract_domain_subdomain(); }
        it("extracts long domains") { test_fake_dns_extract_domain_long(); }
    }

    describe("cache management") {
        it("counts allocations") { test_fake_dns_count(); }
        it("clears the cache") { test_fake_dns_clear(); }
    }

    describe("statistics") {
        it("tracks query stats") { test_fake_dns_stats(); }
    }

    describe("edge cases") {
        it("handles empty domains") { test_fake_dns_empty_domain(); }
        it("handles null domains") { test_fake_dns_null_domain(); }
        it("normalizes case") { test_fake_dns_case_sensitivity(); }
        it("supports special characters") { test_fake_dns_special_characters(); }
        it("handles very long domains") { test_fake_dns_very_long_domain(); }
    }
}
