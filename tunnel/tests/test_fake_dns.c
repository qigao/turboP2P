/**
 * @file test_fake_dns.c
 * @brief Tests for Fake DNS domain tracking
 */

#include "unity.h"
#include "../src/dns/tunnel_fake_dns.h"
#include "../src/core/tunnel_types.h"
#include <string.h>
#include <stdlib.h> 
#include <stb_sprintf.h>

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

    TEST_ASSERT_NOT_EQUAL(0, ip);
    TEST_ASSERT_EQUAL(1, tunnel_fake_dns_is_fake_ip(dns, ip));
}

void test_fake_dns_get_ip_deterministic(void)
{
    /* Same domain should return same IP */
    uint32_t ip1 = tunnel_fake_dns_get_ip(dns, "example.com");
    uint32_t ip2 = tunnel_fake_dns_get_ip(dns, "example.com");

    TEST_ASSERT_EQUAL(ip1, ip2);
}

void test_fake_dns_get_ip_different_domains(void)
{
    uint32_t ip1 = tunnel_fake_dns_get_ip(dns, "example.com");
    uint32_t ip2 = tunnel_fake_dns_get_ip(dns, "google.com");

    TEST_ASSERT_NOT_EQUAL(ip1, ip2);
}

void test_fake_dns_get_ip_in_range(void)
{
    uint32_t ip = tunnel_fake_dns_get_ip(dns, "test.example.com");

    /* IP should be in the fake DNS range */
    uint32_t ip_host = ntohl(ip);
    uint32_t base = TEST_BASE_IP;
    uint32_t mask = TEST_MASK;

    TEST_ASSERT_EQUAL(base & mask, ip_host & mask);
}

void test_fake_dns_allocate_many(void)
{
    /* Allocate many fake IPs */
    char domain[64];
    uint32_t ips[100];

    for (int i = 0; i < 100; i++) {
        stbsp_snprintf(domain, sizeof(domain), "domain%d.example.com", i);
        ips[i] = tunnel_fake_dns_get_ip(dns, domain);
        TEST_ASSERT_NOT_EQUAL(0, ips[i]);
    }

    /* All IPs should be unique */
    for (int i = 0; i < 100; i++) {
        for (int j = i + 1; j < 100; j++) {
            TEST_ASSERT_NOT_EQUAL(ips[i], ips[j]);
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
    TEST_ASSERT_NOT_NULL(domain);
    TEST_ASSERT_EQUAL_STRING("example.com", domain);
}

void test_fake_dns_get_domain_not_found(void)
{
    /* Non-fake IP should return NULL */
    uint32_t fake_ip = htonl(0x08080808);  /* 8.8.8.8 - not in range */

    const char *domain = tunnel_fake_dns_get_domain(dns, fake_ip);
    TEST_ASSERT_NULL(domain);
}

void test_fake_dns_get_domain_unallocated(void)
{
    /* IP in range but not allocated */
    uint32_t fake_ip = htonl(TEST_BASE_IP + 12345);

    const char *domain = tunnel_fake_dns_get_domain(dns, fake_ip);
    TEST_ASSERT_NULL(domain);
}

/* =============================================================================
 * Fake IP Detection Tests
 * ============================================================================= */

void test_fake_dns_is_fake_ip_yes(void)
{
    uint32_t ip = tunnel_fake_dns_get_ip(dns, "test.com");
    TEST_ASSERT_EQUAL(1, tunnel_fake_dns_is_fake_ip(dns, ip));
}

void test_fake_dns_is_fake_ip_no(void)
{
    /* 8.8.8.8 should not be fake */
    TEST_ASSERT_EQUAL(0, tunnel_fake_dns_is_fake_ip(dns, htonl(0x08080808)));

    /* 192.168.1.1 should not be fake */
    TEST_ASSERT_EQUAL(0, tunnel_fake_dns_is_fake_ip(dns, htonl(0xc0a80101)));

    /* 10.0.0.1 should not be fake */
    TEST_ASSERT_EQUAL(0, tunnel_fake_dns_is_fake_ip(dns, htonl(0x0a000001)));
}

void test_fake_dns_is_fake_ip_boundary(void)
{
    /* Test boundary of fake DNS range */
    uint32_t base = TEST_BASE_IP;
    uint32_t end = base + ~TEST_MASK;

    /* Just inside range */
    TEST_ASSERT_EQUAL(1, tunnel_fake_dns_is_fake_ip(dns, htonl(base)));
    TEST_ASSERT_EQUAL(1, tunnel_fake_dns_is_fake_ip(dns, htonl(end)));

    /* Just outside range */
    TEST_ASSERT_EQUAL(0, tunnel_fake_dns_is_fake_ip(dns, htonl(base - 1)));
    TEST_ASSERT_EQUAL(0, tunnel_fake_dns_is_fake_ip(dns, htonl(end + 1)));
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

    TEST_ASSERT_EQUAL(TUNNEL_OK, ret);
    TEST_ASSERT_EQUAL_STRING("example.com", domain);
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

    TEST_ASSERT_EQUAL(1, handled);
    TEST_ASSERT_GREATER_THAN(sizeof(dns_query_example_com), response_len);

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
    TEST_ASSERT_EQUAL(1, found_ip);
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

    TEST_ASSERT_EQUAL(TUNNEL_OK, ret);
    TEST_ASSERT_EQUAL_STRING("www.example.com", domain);
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

    TEST_ASSERT_EQUAL(TUNNEL_OK, ret);
    TEST_ASSERT_GREATER_THAN(100, strlen(domain));
}

/* =============================================================================
 * Cache Management Tests
 * ============================================================================= */

void test_fake_dns_count(void)
{
    TEST_ASSERT_EQUAL(0, tunnel_fake_dns_count(dns));

    tunnel_fake_dns_get_ip(dns, "a.com");
    TEST_ASSERT_EQUAL(1, tunnel_fake_dns_count(dns));

    tunnel_fake_dns_get_ip(dns, "b.com");
    TEST_ASSERT_EQUAL(2, tunnel_fake_dns_count(dns));

    /* Same domain doesn't increase count */
    tunnel_fake_dns_get_ip(dns, "a.com");
    TEST_ASSERT_EQUAL(2, tunnel_fake_dns_count(dns));
}

void test_fake_dns_clear(void)
{
    tunnel_fake_dns_get_ip(dns, "example.com");
    tunnel_fake_dns_get_ip(dns, "google.com");

    TEST_ASSERT_EQUAL(2, tunnel_fake_dns_count(dns));

    tunnel_fake_dns_clear(dns);

    TEST_ASSERT_EQUAL(0, tunnel_fake_dns_count(dns));

    /* After clear, same domain gets new IP */
    uint32_t old_ip = tunnel_fake_dns_get_ip(dns, "example.com");
    tunnel_fake_dns_clear(dns);
    uint32_t new_ip = tunnel_fake_dns_get_ip(dns, "example.com");

    /* IPs might be same or different depending on implementation */
    /* Just verify we can still allocate */
    TEST_ASSERT_NOT_EQUAL(0, new_ip);
}

/* =============================================================================
 * Statistics Tests
 * ============================================================================= */

void test_fake_dns_stats(void)
{
    uint64_t queries, hits, allocations;

    /* Initial stats should be zero */
    tunnel_fake_dns_get_stats(dns, &queries, &hits, &allocations);
    TEST_ASSERT_EQUAL(0, queries);
    TEST_ASSERT_EQUAL(0, hits);
    TEST_ASSERT_EQUAL(0, allocations);

    /* First query for domain - allocation */
    tunnel_fake_dns_get_ip(dns, "example.com");
    tunnel_fake_dns_get_stats(dns, &queries, &hits, &allocations);
    TEST_ASSERT_EQUAL(1, queries);
    TEST_ASSERT_EQUAL(0, hits);
    TEST_ASSERT_EQUAL(1, allocations);

    /* Second query for same domain - hit */
    tunnel_fake_dns_get_ip(dns, "example.com");
    tunnel_fake_dns_get_stats(dns, &queries, &hits, &allocations);
    TEST_ASSERT_EQUAL(2, queries);
    TEST_ASSERT_EQUAL(1, hits);
    TEST_ASSERT_EQUAL(1, allocations);

    /* Query for new domain - allocation */
    tunnel_fake_dns_get_ip(dns, "google.com");
    tunnel_fake_dns_get_stats(dns, &queries, &hits, &allocations);
    TEST_ASSERT_EQUAL(3, queries);
    TEST_ASSERT_EQUAL(1, hits);
    TEST_ASSERT_EQUAL(2, allocations);
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
    TEST_ASSERT_EQUAL(0, ip);
}

void test_fake_dns_case_sensitivity(void)
{
    uint32_t ip1 = tunnel_fake_dns_get_ip(dns, "Example.COM");
    uint32_t ip2 = tunnel_fake_dns_get_ip(dns, "example.com");

    /* DNS is case-insensitive, so these should be the same */
    TEST_ASSERT_EQUAL(ip1, ip2);
}

void test_fake_dns_special_characters(void)
{
    /* Domains with hyphens and numbers */
    uint32_t ip1 = tunnel_fake_dns_get_ip(dns, "my-domain-123.example.com");
    TEST_ASSERT_NOT_EQUAL(0, ip1);

    const char *domain = tunnel_fake_dns_get_domain(dns, ip1);
    TEST_ASSERT_EQUAL_STRING("my-domain-123.example.com", domain);
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

/* =============================================================================
 * Main
 * ============================================================================= */

int main(void)
{
    UNITY_BEGIN();

    /* IP allocation */
    RUN_TEST(test_fake_dns_get_ip_basic);
    RUN_TEST(test_fake_dns_get_ip_deterministic);
    RUN_TEST(test_fake_dns_get_ip_different_domains);
    RUN_TEST(test_fake_dns_get_ip_in_range);
    RUN_TEST(test_fake_dns_allocate_many);

    /* Domain lookup */
    RUN_TEST(test_fake_dns_get_domain);
    RUN_TEST(test_fake_dns_get_domain_not_found);
    RUN_TEST(test_fake_dns_get_domain_unallocated);

    /* Fake IP detection */
    RUN_TEST(test_fake_dns_is_fake_ip_yes);
    RUN_TEST(test_fake_dns_is_fake_ip_no);
    RUN_TEST(test_fake_dns_is_fake_ip_boundary);

    /* DNS query processing */
    RUN_TEST(test_fake_dns_extract_domain);
    RUN_TEST(test_fake_dns_process_query_a_record);
    RUN_TEST(test_fake_dns_extract_domain_subdomain);
    RUN_TEST(test_fake_dns_extract_domain_long);

    /* Cache management */
    RUN_TEST(test_fake_dns_count);
    RUN_TEST(test_fake_dns_clear);

    /* Statistics */
    RUN_TEST(test_fake_dns_stats);

    /* Edge cases */
    RUN_TEST(test_fake_dns_empty_domain);
    RUN_TEST(test_fake_dns_null_domain);
    RUN_TEST(test_fake_dns_case_sensitivity);
    RUN_TEST(test_fake_dns_special_characters);
    RUN_TEST(test_fake_dns_very_long_domain);

    return UNITY_END();
}
