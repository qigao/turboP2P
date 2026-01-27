/**
 * @file test_nat.c
 * @brief Tests for tunnel NAT table and session lookup
 */

#include "unity.h"
#include "../src/nat/tunnel_nat.h"
#include "../src/core/tunnel_types.h"
#include <string.h>
#include <stdlib.h>

/* Mock tunnel for tests */
static tunnel_t *mock_tunnel = NULL;
static tunnel_nat_t *nat = NULL;

void setUp(void)
{
    /* Create minimal mock tunnel */
    mock_tunnel = (tunnel_t *)calloc(1, sizeof(tunnel_t));
    nat = tunnel_nat_create(mock_tunnel);
}

void tearDown(void)
{
    if (nat) {
        tunnel_nat_destroy(nat);
        nat = NULL;
    }
    if (mock_tunnel) {
        free(mock_tunnel);
        mock_tunnel = NULL;
    }
}

/* =============================================================================
 * Helper Functions
 * ============================================================================= */

static void make_key(tunnel_session_key_t *key,
                     uint32_t src_ip, uint16_t src_port,
                     uint32_t dst_ip, uint16_t dst_port,
                     uint8_t protocol)
{
    memset(key, 0, sizeof(*key));
    key->src.family = AF_INET;
    key->src.addr.v4 = htonl(src_ip);
    key->src.port = src_port;
    key->dst.family = AF_INET;
    key->dst.addr.v4 = htonl(dst_ip);
    key->dst.port = dst_port;
    key->protocol = protocol;
}

static tunnel_session_t* create_mock_session(const tunnel_session_key_t *key)
{
    tunnel_session_t *session = (tunnel_session_t *)calloc(1, sizeof(tunnel_session_t));
    tunnel_session_key_copy(&session->key, key);
    session->tunnel = mock_tunnel;
    session->state = TUNNEL_SESSION_ESTABLISHED;
    session->create_time = 1000;
    session->last_active = 1000;
    return session;
}

/* =============================================================================
 * Hash Function Tests
 * ============================================================================= */

void test_nat_hash_deterministic(void)
{
    tunnel_session_key_t key;
    make_key(&key, 0x0a000001, 12345, 0x08080808, 80, TUNNEL_IPPROTO_TCP);

    uint32_t hash1 = tunnel_nat_hash(&key);
    uint32_t hash2 = tunnel_nat_hash(&key);

    TEST_ASSERT_EQUAL(hash1, hash2);
}

void test_nat_hash_different_keys(void)
{
    tunnel_session_key_t key1, key2;
    make_key(&key1, 0x0a000001, 12345, 0x08080808, 80, TUNNEL_IPPROTO_TCP);
    make_key(&key2, 0x0a000001, 12346, 0x08080808, 80, TUNNEL_IPPROTO_TCP);

    uint32_t hash1 = tunnel_nat_hash(&key1);
    uint32_t hash2 = tunnel_nat_hash(&key2);

    /* Different keys should (usually) have different hashes */
    /* Note: collisions are possible, so this isn't strictly required */
    TEST_ASSERT_NOT_EQUAL(hash1, hash2);
}

void test_nat_hash_protocol_matters(void)
{
    tunnel_session_key_t key_tcp, key_udp;
    make_key(&key_tcp, 0x0a000001, 12345, 0x08080808, 80, TUNNEL_IPPROTO_TCP);
    make_key(&key_udp, 0x0a000001, 12345, 0x08080808, 80, TUNNEL_IPPROTO_UDP);

    uint32_t hash_tcp = tunnel_nat_hash(&key_tcp);
    uint32_t hash_udp = tunnel_nat_hash(&key_udp);

    TEST_ASSERT_NOT_EQUAL(hash_tcp, hash_udp);
}

/* =============================================================================
 * Insert and Lookup Tests
 * ============================================================================= */

void test_nat_insert_and_lookup(void)
{
    tunnel_session_key_t key;
    make_key(&key, 0x0a000001, 12345, 0x08080808, 80, TUNNEL_IPPROTO_TCP);

    tunnel_session_t *session = create_mock_session(&key);
    int ret = tunnel_nat_insert(nat, session);
    TEST_ASSERT_EQUAL(TUNNEL_OK, ret);

    tunnel_session_t *found = tunnel_nat_lookup(nat, &key);
    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL_PTR(session, found);

    /* Cleanup */
    tunnel_nat_remove(nat, session);
    free(session);
}

void test_nat_lookup_not_found(void)
{
    tunnel_session_key_t key;
    make_key(&key, 0x0a000001, 12345, 0x08080808, 80, TUNNEL_IPPROTO_TCP);

    tunnel_session_t *found = tunnel_nat_lookup(nat, &key);
    TEST_ASSERT_NULL(found);
}

void test_nat_insert_multiple(void)
{
    tunnel_session_key_t keys[10];
    tunnel_session_t *sessions[10];

    /* Insert 10 sessions */
    for (int i = 0; i < 10; i++) {
        make_key(&keys[i], 0x0a000001, 10000 + i, 0x08080808, 80, TUNNEL_IPPROTO_TCP);
        sessions[i] = create_mock_session(&keys[i]);
        int ret = tunnel_nat_insert(nat, sessions[i]);
        TEST_ASSERT_EQUAL(TUNNEL_OK, ret);
    }

    /* Verify all can be found */
    for (int i = 0; i < 10; i++) {
        tunnel_session_t *found = tunnel_nat_lookup(nat, &keys[i]);
        TEST_ASSERT_NOT_NULL(found);
        TEST_ASSERT_EQUAL_PTR(sessions[i], found);
    }

    TEST_ASSERT_EQUAL(10, tunnel_nat_session_count(nat));

    /* Cleanup */
    for (int i = 0; i < 10; i++) {
        tunnel_nat_remove(nat, sessions[i]);
        free(sessions[i]);
    }
}

void test_nat_remove(void)
{
    tunnel_session_key_t key;
    make_key(&key, 0x0a000001, 12345, 0x08080808, 80, TUNNEL_IPPROTO_TCP);

    tunnel_session_t *session = create_mock_session(&key);
    tunnel_nat_insert(nat, session);

    TEST_ASSERT_EQUAL(1, tunnel_nat_session_count(nat));

    tunnel_nat_remove(nat, session);
    TEST_ASSERT_EQUAL(0, tunnel_nat_session_count(nat));

    tunnel_session_t *found = tunnel_nat_lookup(nat, &key);
    TEST_ASSERT_NULL(found);

    free(session);
}

/* =============================================================================
 * Session Key Tests
 * ============================================================================= */

void test_session_key_compare_equal(void)
{
    tunnel_session_key_t key1, key2;
    make_key(&key1, 0x0a000001, 12345, 0x08080808, 80, TUNNEL_IPPROTO_TCP);
    make_key(&key2, 0x0a000001, 12345, 0x08080808, 80, TUNNEL_IPPROTO_TCP);

    TEST_ASSERT_EQUAL(0, tunnel_session_key_compare(&key1, &key2));
}

void test_session_key_compare_different_port(void)
{
    tunnel_session_key_t key1, key2;
    make_key(&key1, 0x0a000001, 12345, 0x08080808, 80, TUNNEL_IPPROTO_TCP);
    make_key(&key2, 0x0a000001, 12346, 0x08080808, 80, TUNNEL_IPPROTO_TCP);

    TEST_ASSERT_NOT_EQUAL(0, tunnel_session_key_compare(&key1, &key2));
}

void test_session_key_compare_different_ip(void)
{
    tunnel_session_key_t key1, key2;
    make_key(&key1, 0x0a000001, 12345, 0x08080808, 80, TUNNEL_IPPROTO_TCP);
    make_key(&key2, 0x0a000002, 12345, 0x08080808, 80, TUNNEL_IPPROTO_TCP);

    TEST_ASSERT_NOT_EQUAL(0, tunnel_session_key_compare(&key1, &key2));
}

void test_session_key_copy(void)
{
    tunnel_session_key_t src, dst;
    make_key(&src, 0x0a000001, 12345, 0x08080808, 80, TUNNEL_IPPROTO_TCP);

    tunnel_session_key_copy(&dst, &src);

    TEST_ASSERT_EQUAL(0, tunnel_session_key_compare(&src, &dst));
}

/* =============================================================================
 * Reverse NAT Tests
 * ============================================================================= */

void test_nat_reverse_key(void)
{
    tunnel_session_key_t key, reverse;
    make_key(&key, 0x0a000001, 12345, 0x08080808, 80, TUNNEL_IPPROTO_TCP);

    tunnel_nat_reverse_key(&key, &reverse);

    /* Reverse should have src/dst swapped */
    TEST_ASSERT_EQUAL(key.src.addr.v4, reverse.dst.addr.v4);
    TEST_ASSERT_EQUAL(key.src.port, reverse.dst.port);
    TEST_ASSERT_EQUAL(key.dst.addr.v4, reverse.src.addr.v4);
    TEST_ASSERT_EQUAL(key.dst.port, reverse.src.port);
    TEST_ASSERT_EQUAL(key.protocol, reverse.protocol);
}

void test_nat_lookup_reverse(void)
{
    tunnel_session_key_t key;
    make_key(&key, 0x0a000001, 12345, 0x08080808, 80, TUNNEL_IPPROTO_TCP);

    tunnel_session_t *session = create_mock_session(&key);
    tunnel_nat_insert(nat, session);

    /* Lookup by reverse key (as if packet coming back from server) */
    tunnel_endpoint_t dst = key.src;
    tunnel_endpoint_t src = key.dst;

    tunnel_session_t *found = tunnel_nat_lookup_reverse(nat, &dst, &src, TUNNEL_IPPROTO_TCP);
    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL_PTR(session, found);

    tunnel_nat_remove(nat, session);
    free(session);
}

/* =============================================================================
 * UDP Port Allocation Tests
 * ============================================================================= */

void test_nat_alloc_udp_port(void)
{
    uint16_t port1 = tunnel_nat_alloc_udp_port(nat);
    uint16_t port2 = tunnel_nat_alloc_udp_port(nat);

    TEST_ASSERT_NOT_EQUAL(0, port1);
    TEST_ASSERT_NOT_EQUAL(0, port2);
    TEST_ASSERT_NOT_EQUAL(port1, port2);

    /* Ports should be in valid range */
    TEST_ASSERT_GREATER_OR_EQUAL(TUNNEL_NAT_UDP_PORT_MIN, port1);
    TEST_ASSERT_LESS_OR_EQUAL(TUNNEL_NAT_UDP_PORT_MAX, port1);
}

void test_nat_free_udp_port(void)
{
    uint16_t port = tunnel_nat_alloc_udp_port(nat);
    TEST_ASSERT_EQUAL(1, tunnel_nat_udp_port_in_use(nat, port));

    tunnel_nat_free_udp_port(nat, port);
    TEST_ASSERT_EQUAL(0, tunnel_nat_udp_port_in_use(nat, port));
}

void test_nat_udp_port_reuse(void)
{
    uint16_t port1 = tunnel_nat_alloc_udp_port(nat);
    tunnel_nat_free_udp_port(nat, port1);

    /* Freed port can be reused */
    uint16_t port2 = tunnel_nat_alloc_udp_port(nat);
    /* Note: may or may not be same port depending on implementation */
    TEST_ASSERT_NOT_EQUAL(0, port2);
}

/* =============================================================================
 * LRU Tests
 * ============================================================================= */

void test_nat_touch_moves_to_front(void)
{
    tunnel_session_key_t key1, key2;
    make_key(&key1, 0x0a000001, 1000, 0x08080808, 80, TUNNEL_IPPROTO_TCP);
    make_key(&key2, 0x0a000001, 2000, 0x08080808, 80, TUNNEL_IPPROTO_TCP);

    tunnel_session_t *s1 = create_mock_session(&key1);
    tunnel_session_t *s2 = create_mock_session(&key2);

    tunnel_nat_insert(nat, s1);
    tunnel_nat_insert(nat, s2);

    /* s2 should be newest (front of LRU), s1 should be oldest */
    TEST_ASSERT_EQUAL_PTR(s1, tunnel_nat_get_oldest(nat));

    /* Touch s1 to move it to front */
    tunnel_nat_touch(nat, s1);

    /* Now s2 should be oldest */
    TEST_ASSERT_EQUAL_PTR(s2, tunnel_nat_get_oldest(nat));

    tunnel_nat_remove(nat, s1);
    tunnel_nat_remove(nat, s2);
    free(s1);
    free(s2);
}

void test_nat_evict_oldest(void)
{
    tunnel_session_t *sessions[5];

    for (int i = 0; i < 5; i++) {
        tunnel_session_key_t key;
        make_key(&key, 0x0a000001, 1000 + i, 0x08080808, 80, TUNNEL_IPPROTO_TCP);
        sessions[i] = create_mock_session(&key);
        sessions[i]->last_active = 1000 + i;  /* Increasing activity time */
        tunnel_nat_insert(nat, sessions[i]);
    }

    TEST_ASSERT_EQUAL(5, tunnel_nat_session_count(nat));

    /* Evict to keep only 3 sessions */
    int evicted = tunnel_nat_evict_oldest(nat, 3);
    TEST_ASSERT_EQUAL(2, evicted);
    TEST_ASSERT_EQUAL(3, tunnel_nat_session_count(nat));

    /* Oldest sessions (0, 1) should be gone */
    tunnel_session_key_t key0;
    make_key(&key0, 0x0a000001, 1000, 0x08080808, 80, TUNNEL_IPPROTO_TCP);
    TEST_ASSERT_NULL(tunnel_nat_lookup(nat, &key0));

    /* Newest sessions (2, 3, 4) should remain */
    tunnel_session_key_t key4;
    make_key(&key4, 0x0a000001, 1004, 0x08080808, 80, TUNNEL_IPPROTO_TCP);
    TEST_ASSERT_NOT_NULL(tunnel_nat_lookup(nat, &key4));

    /* Cleanup remaining */
    for (int i = 2; i < 5; i++) {
        tunnel_nat_remove(nat, sessions[i]);
        free(sessions[i]);
    }
    /* sessions[0] and [1] were evicted, need to free them */
    free(sessions[0]);
    free(sessions[1]);
}

/* =============================================================================
 * Statistics Tests
 * ============================================================================= */

void test_nat_stats(void)
{
    tunnel_session_key_t key;
    make_key(&key, 0x0a000001, 12345, 0x08080808, 80, TUNNEL_IPPROTO_TCP);

    /* Generate some lookups */
    tunnel_nat_lookup(nat, &key);  /* Miss */
    tunnel_nat_lookup(nat, &key);  /* Miss */

    tunnel_session_t *session = create_mock_session(&key);
    tunnel_nat_insert(nat, session);

    tunnel_nat_lookup(nat, &key);  /* Hit */

    uint64_t lookups, hits, misses, evictions;
    tunnel_nat_get_stats(nat, &lookups, &hits, &misses, &evictions);

    TEST_ASSERT_EQUAL(3, lookups);
    TEST_ASSERT_EQUAL(1, hits);
    TEST_ASSERT_EQUAL(2, misses);

    tunnel_nat_remove(nat, session);
    free(session);
}

void test_nat_load_factor(void)
{
    TEST_ASSERT_FLOAT_WITHIN(0.001, 0.0, tunnel_nat_load_factor(nat));

    /* Insert some sessions */
    for (int i = 0; i < 100; i++) {
        tunnel_session_key_t key;
        make_key(&key, 0x0a000001, 1000 + i, 0x08080808, 80, TUNNEL_IPPROTO_TCP);
        tunnel_session_t *session = create_mock_session(&key);
        tunnel_nat_insert(nat, session);
    }

    double load = tunnel_nat_load_factor(nat);
    TEST_ASSERT_TRUE(load > 0.0);
    TEST_ASSERT_TRUE(load < 1.0);

    /* Cleanup */
    tunnel_nat_clear(nat);
}

/* =============================================================================
 * Endpoint Utilities Tests
 * ============================================================================= */

void test_endpoint_format_ipv4(void)
{
    tunnel_endpoint_t ep = {
        .family = AF_INET,
        .addr.v4 = htonl(0xc0a80101),  /* 192.168.1.1 */
        .port = 8080,
    };

    char buf[64];
    tunnel_endpoint_format(&ep, buf, sizeof(buf));

    TEST_ASSERT_EQUAL_STRING("192.168.1.1:8080", buf);
}

void test_endpoint_parse_ipv4(void)
{
    tunnel_endpoint_t ep;
    int ret = tunnel_endpoint_parse("10.0.0.1:443", &ep);

    TEST_ASSERT_EQUAL(TUNNEL_OK, ret);
    TEST_ASSERT_EQUAL(AF_INET, ep.family);
    TEST_ASSERT_EQUAL(htonl(0x0a000001), ep.addr.v4);
    TEST_ASSERT_EQUAL(443, ep.port);
}

void test_endpoint_compare_equal(void)
{
    tunnel_endpoint_t a = {
        .family = AF_INET,
        .addr.v4 = htonl(0x0a000001),
        .port = 80,
    };
    tunnel_endpoint_t b = a;

    TEST_ASSERT_EQUAL(0, tunnel_endpoint_compare(&a, &b));
}

void test_endpoint_compare_different(void)
{
    tunnel_endpoint_t a = {
        .family = AF_INET,
        .addr.v4 = htonl(0x0a000001),
        .port = 80,
    };
    tunnel_endpoint_t b = {
        .family = AF_INET,
        .addr.v4 = htonl(0x0a000001),
        .port = 81,
    };

    TEST_ASSERT_NOT_EQUAL(0, tunnel_endpoint_compare(&a, &b));
}

/* =============================================================================
 * Main
 * ============================================================================= */

int main(void)
{
    UNITY_BEGIN();

    /* Hash function */
    RUN_TEST(test_nat_hash_deterministic);
    RUN_TEST(test_nat_hash_different_keys);
    RUN_TEST(test_nat_hash_protocol_matters);

    /* Insert and lookup */
    RUN_TEST(test_nat_insert_and_lookup);
    RUN_TEST(test_nat_lookup_not_found);
    RUN_TEST(test_nat_insert_multiple);
    RUN_TEST(test_nat_remove);

    /* Session key */
    RUN_TEST(test_session_key_compare_equal);
    RUN_TEST(test_session_key_compare_different_port);
    RUN_TEST(test_session_key_compare_different_ip);
    RUN_TEST(test_session_key_copy);

    /* Reverse NAT */
    RUN_TEST(test_nat_reverse_key);
    RUN_TEST(test_nat_lookup_reverse);

    /* UDP port allocation */
    RUN_TEST(test_nat_alloc_udp_port);
    RUN_TEST(test_nat_free_udp_port);
    RUN_TEST(test_nat_udp_port_reuse);

    /* LRU */
    RUN_TEST(test_nat_touch_moves_to_front);
    RUN_TEST(test_nat_evict_oldest);

    /* Statistics */
    RUN_TEST(test_nat_stats);
    RUN_TEST(test_nat_load_factor);

    /* Endpoint utilities */
    RUN_TEST(test_endpoint_format_ipv4);
    RUN_TEST(test_endpoint_parse_ipv4);
    RUN_TEST(test_endpoint_compare_equal);
    RUN_TEST(test_endpoint_compare_different);

    return UNITY_END();
}
