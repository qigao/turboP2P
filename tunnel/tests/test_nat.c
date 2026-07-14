/**
 * @file test_nat.c
 * @brief Tests for tunnel NAT table and session lookup
 */

#include <tinytest.h>
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

    check_int_eq(hash1, hash2);
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
    check(hash1 != hash2);
}

void test_nat_hash_protocol_matters(void)
{
    tunnel_session_key_t key_tcp, key_udp;
    make_key(&key_tcp, 0x0a000001, 12345, 0x08080808, 80, TUNNEL_IPPROTO_TCP);
    make_key(&key_udp, 0x0a000001, 12345, 0x08080808, 80, TUNNEL_IPPROTO_UDP);

    uint32_t hash_tcp = tunnel_nat_hash(&key_tcp);
    uint32_t hash_udp = tunnel_nat_hash(&key_udp);

    check(hash_tcp != hash_udp);
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
    check_int_eq(TUNNEL_OK, ret);

    tunnel_session_t *found = tunnel_nat_lookup(nat, &key);
    check_not_null(found);
    check_ptr_eq(session, found);

    /* Cleanup */
    tunnel_nat_remove(nat, session);
    free(session);
}

void test_nat_lookup_not_found(void)
{
    tunnel_session_key_t key;
    make_key(&key, 0x0a000001, 12345, 0x08080808, 80, TUNNEL_IPPROTO_TCP);

    tunnel_session_t *found = tunnel_nat_lookup(nat, &key);
    check_null(found);
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
        check_int_eq(TUNNEL_OK, ret);
    }

    /* Verify all can be found */
    for (int i = 0; i < 10; i++) {
        tunnel_session_t *found = tunnel_nat_lookup(nat, &keys[i]);
        check_not_null(found);
        check_ptr_eq(sessions[i], found);
    }

    check_int_eq(10, tunnel_nat_session_count(nat));

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

    check_int_eq(1, tunnel_nat_session_count(nat));

    tunnel_nat_remove(nat, session);
    check_int_eq(0, tunnel_nat_session_count(nat));

    tunnel_session_t *found = tunnel_nat_lookup(nat, &key);
    check_null(found);

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

    check_int_eq(0, tunnel_session_key_compare(&key1, &key2));
}

void test_session_key_compare_different_port(void)
{
    tunnel_session_key_t key1, key2;
    make_key(&key1, 0x0a000001, 12345, 0x08080808, 80, TUNNEL_IPPROTO_TCP);
    make_key(&key2, 0x0a000001, 12346, 0x08080808, 80, TUNNEL_IPPROTO_TCP);

    check(tunnel_session_key_compare(&key1, &key2) != 0);
}

void test_session_key_compare_different_ip(void)
{
    tunnel_session_key_t key1, key2;
    make_key(&key1, 0x0a000001, 12345, 0x08080808, 80, TUNNEL_IPPROTO_TCP);
    make_key(&key2, 0x0a000002, 12345, 0x08080808, 80, TUNNEL_IPPROTO_TCP);

    check(tunnel_session_key_compare(&key1, &key2) != 0);
}

void test_session_key_copy(void)
{
    tunnel_session_key_t src, dst;
    make_key(&src, 0x0a000001, 12345, 0x08080808, 80, TUNNEL_IPPROTO_TCP);

    tunnel_session_key_copy(&dst, &src);

    check_int_eq(0, tunnel_session_key_compare(&src, &dst));
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
    check_int_eq(key.src.addr.v4, reverse.dst.addr.v4);
    check_int_eq(key.src.port, reverse.dst.port);
    check_int_eq(key.dst.addr.v4, reverse.src.addr.v4);
    check_int_eq(key.dst.port, reverse.src.port);
    check_int_eq(key.protocol, reverse.protocol);
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
    check_not_null(found);
    check_ptr_eq(session, found);

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

    check(port1 != 0);
    check(port2 != 0);
    check(port1 != port2);

    /* Ports should be in valid range */
    check(port1 >= TUNNEL_NAT_UDP_PORT_MIN);
    check(port1 <= TUNNEL_NAT_UDP_PORT_MAX);
}

void test_nat_free_udp_port(void)
{
    uint16_t port = tunnel_nat_alloc_udp_port(nat);
    check_int_eq(1, tunnel_nat_udp_port_in_use(nat, port));

    tunnel_nat_free_udp_port(nat, port);
    check_int_eq(0, tunnel_nat_udp_port_in_use(nat, port));
}

void test_nat_udp_port_reuse(void)
{
    uint16_t port1 = tunnel_nat_alloc_udp_port(nat);
    tunnel_nat_free_udp_port(nat, port1);

    /* Freed port can be reused */
    uint16_t port2 = tunnel_nat_alloc_udp_port(nat);
    /* Note: may or may not be same port depending on implementation */
    check(port2 != 0);
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
    check_ptr_eq(s1, tunnel_nat_get_oldest(nat));

    /* Touch s1 to move it to front */
    tunnel_nat_touch(nat, s1);

    /* Now s2 should be oldest */
    check_ptr_eq(s2, tunnel_nat_get_oldest(nat));

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

    check_int_eq(5, tunnel_nat_session_count(nat));

    /* Evict to keep only 3 sessions */
    int evicted = tunnel_nat_evict_oldest(nat, 3);
    check_int_eq(2, evicted);
    check_int_eq(3, tunnel_nat_session_count(nat));

    /* Oldest sessions (0, 1) should be gone */
    tunnel_session_key_t key0;
    make_key(&key0, 0x0a000001, 1000, 0x08080808, 80, TUNNEL_IPPROTO_TCP);
    check_null(tunnel_nat_lookup(nat, &key0));

    /* Newest sessions (2, 3, 4) should remain */
    tunnel_session_key_t key4;
    make_key(&key4, 0x0a000001, 1004, 0x08080808, 80, TUNNEL_IPPROTO_TCP);
    check_not_null(tunnel_nat_lookup(nat, &key4));

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

    check_int_eq(3, lookups);
    check_int_eq(1, hits);
    check_int_eq(2, misses);

    tunnel_nat_remove(nat, session);
    free(session);
}

void test_nat_load_factor(void)
{
    check_double_eq(tunnel_nat_load_factor(nat), 0.0, 0.001);

    /* Insert some sessions */
    for (int i = 0; i < 100; i++) {
        tunnel_session_key_t key;
        make_key(&key, 0x0a000001, 1000 + i, 0x08080808, 80, TUNNEL_IPPROTO_TCP);
        tunnel_session_t *session = create_mock_session(&key);
        tunnel_nat_insert(nat, session);
    }

    double load = tunnel_nat_load_factor(nat);
    check_true(load > 0.0);
    check_true(load < 1.0);

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

    check_str_eq("192.168.1.1:8080", buf);
}

void test_endpoint_parse_ipv4(void)
{
    tunnel_endpoint_t ep;
    int ret = tunnel_endpoint_parse("10.0.0.1:443", &ep);

    check_int_eq(TUNNEL_OK, ret);
    check_int_eq(AF_INET, ep.family);
    check_int_eq(htonl(0x0a000001), ep.addr.v4);
    check_int_eq(443, ep.port);
}

void test_endpoint_compare_equal(void)
{
    tunnel_endpoint_t a = {
        .family = AF_INET,
        .addr.v4 = htonl(0x0a000001),
        .port = 80,
    };
    tunnel_endpoint_t b = a;

    check_int_eq(0, tunnel_endpoint_compare(&a, &b));
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

    check(tunnel_endpoint_compare(&a, &b) != 0);
}

spec("tunnel nat") {
    before_each() {
        setUp();
    }

    after_each() {
        tearDown();
    }

    describe("hashing") {
        it("is deterministic") { test_nat_hash_deterministic(); }
        it("changes for different keys") { test_nat_hash_different_keys(); }
        it("includes protocol in the hash") { test_nat_hash_protocol_matters(); }
    }

    describe("insert and lookup") {
        it("inserts and finds sessions") { test_nat_insert_and_lookup(); }
        it("returns null on miss") { test_nat_lookup_not_found(); }
        it("handles multiple sessions") { test_nat_insert_multiple(); }
        it("removes a session") { test_nat_remove(); }
    }

    describe("session keys") {
        it("compares equal keys") { test_session_key_compare_equal(); }
        it("detects different ports") { test_session_key_compare_different_port(); }
        it("detects different ips") { test_session_key_compare_different_ip(); }
        it("copies keys") { test_session_key_copy(); }
    }

    describe("reverse nat") {
        it("reverses keys") { test_nat_reverse_key(); }
        it("looks up reverse flows") { test_nat_lookup_reverse(); }
    }

    describe("udp ports") {
        it("allocates udp ports") { test_nat_alloc_udp_port(); }
        it("frees udp ports") { test_nat_free_udp_port(); }
        it("reuses freed udp ports") { test_nat_udp_port_reuse(); }
    }

    describe("lru") {
        it("touch moves entries to the front") { test_nat_touch_moves_to_front(); }
        it("evicts the oldest entries") { test_nat_evict_oldest(); }
    }

    describe("statistics") {
        it("tracks nat stats") { test_nat_stats(); }
        it("reports load factor") { test_nat_load_factor(); }
    }

    describe("endpoint utilities") {
        it("formats ipv4 endpoints") { test_endpoint_format_ipv4(); }
        it("parses ipv4 endpoints") { test_endpoint_parse_ipv4(); }
        it("compares equal endpoints") { test_endpoint_compare_equal(); }
        it("compares different endpoints") { test_endpoint_compare_different(); }
    }
}

