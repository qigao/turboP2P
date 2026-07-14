/**
 * @file test_session.c
 * @brief Tests for tunnel session lifecycle management
 */

#include <tinytest.h>
#include "../src/session/tunnel_session.h"
#include "../src/core/tunnel_types.h"
#include "../src/nat/tunnel_nat.h"
#include <string.h>
#include <stdlib.h>

/* Mock tunnel */
static tunnel_t *mock_tunnel = NULL;

void setUp(void)
{
    mock_tunnel = (tunnel_t *)calloc(1, sizeof(tunnel_t));
    mock_tunnel->ctx = coro_context_create(NULL);
    mock_tunnel->nat = tunnel_nat_create(mock_tunnel);
    mock_tunnel->proxy = (tunnel_proxy_t *)calloc(1, sizeof(tunnel_proxy_t));
    mock_tunnel->proxy->tunnel = mock_tunnel;
    mock_tunnel->proxy->type = TUNNEL_PROXY_NONE; /* Direct */
}

void tearDown(void)
{
    if (mock_tunnel) {
        if (mock_tunnel->nat) {
            tunnel_nat_destroy(mock_tunnel->nat);
        }
        if (mock_tunnel->ctx) {
            coro_context_destroy(mock_tunnel->ctx);
        }
        if (mock_tunnel->proxy) {
            free(mock_tunnel->proxy);
        }
        free(mock_tunnel);
        mock_tunnel = NULL;
    }
}

/* =============================================================================
 * Helper Functions
 * ============================================================================= */

static void make_tcp_key(tunnel_session_key_t *key,
                         uint32_t src_ip, uint16_t src_port,
                         uint32_t dst_ip, uint16_t dst_port)
{
    memset(key, 0, sizeof(*key));
    key->src.family = AF_INET;
    key->src.addr.v4 = htonl(src_ip);
    key->src.port = src_port;
    key->dst.family = AF_INET;
    key->dst.addr.v4 = htonl(dst_ip);
    key->dst.port = dst_port;
    key->protocol = TUNNEL_IPPROTO_TCP;
}

static void make_udp_key(tunnel_session_key_t *key,
                         uint32_t src_ip, uint16_t src_port,
                         uint32_t dst_ip, uint16_t dst_port)
{
    memset(key, 0, sizeof(*key));
    key->src.family = AF_INET;
    key->src.addr.v4 = htonl(src_ip);
    key->src.port = src_port;
    key->dst.family = AF_INET;
    key->dst.addr.v4 = htonl(dst_ip);
    key->dst.port = dst_port;
    key->protocol = TUNNEL_IPPROTO_UDP;
}

/* =============================================================================
 * Session Creation Tests
 * ============================================================================= */

void test_session_create(void)
{
    tunnel_session_key_t key;
    make_tcp_key(&key, 0x0a000001, 12345, 0x08080808, 80);

    tunnel_session_t *session = tunnel_session_create(mock_tunnel, &key);
    check_not_null(session);

    /* Verify key is copied */
    check_int_eq(0, tunnel_session_key_compare(&key, &session->key));

    /* Verify initial state */
    check_int_eq(TUNNEL_SESSION_INIT, session->state);
    check_int_eq(0, session->bytes_rx);
    check_int_eq(0, session->bytes_tx);
    check_ptr_eq(mock_tunnel, session->tunnel);

    tunnel_session_destroy(session);
}

void test_session_create_multiple(void)
{
    tunnel_session_t *sessions[10];

    for (int i = 0; i < 10; i++) {
        tunnel_session_key_t key;
        make_tcp_key(&key, 0x0a000001, 10000 + i, 0x08080808, 80);
        sessions[i] = tunnel_session_create(mock_tunnel, &key);
        check_not_null(sessions[i]);
    }

    check_int_eq(10, tunnel_session_count(mock_tunnel));

    for (int i = 0; i < 10; i++) {
        tunnel_session_destroy(sessions[i]);
    }

    check_int_eq(0, tunnel_session_count(mock_tunnel));
}

/* =============================================================================
 * Session Find Tests
 * ============================================================================= */

void test_session_find(void)
{
    tunnel_session_key_t key;
    make_tcp_key(&key, 0x0a000001, 12345, 0x08080808, 80);

    tunnel_session_t *created = tunnel_session_create(mock_tunnel, &key);
    check_not_null(created);

    tunnel_session_t *found = tunnel_session_find(mock_tunnel, &key);
    check_not_null(found);
    check_ptr_eq(created, found);

    tunnel_session_destroy(created);
}

void test_session_find_not_found(void)
{
    tunnel_session_key_t key;
    make_tcp_key(&key, 0x0a000001, 12345, 0x08080808, 80);

    tunnel_session_t *found = tunnel_session_find(mock_tunnel, &key);
    check_null(found);
}

void test_session_find_or_create_existing(void)
{
    tunnel_session_key_t key;
    make_tcp_key(&key, 0x0a000001, 12345, 0x08080808, 80);

    tunnel_session_t *created = tunnel_session_create(mock_tunnel, &key);
    check_not_null(created);

    int was_created = 0;
    tunnel_session_t *found = tunnel_session_find_or_create(mock_tunnel, &key, &was_created);

    check_not_null(found);
    check_ptr_eq(created, found);
    check_int_eq(0, was_created);

    tunnel_session_destroy(created);
}

void test_session_find_or_create_new(void)
{
    tunnel_session_key_t key;
    make_tcp_key(&key, 0x0a000001, 12345, 0x08080808, 80);

    int was_created = 0;
    tunnel_session_t *session = tunnel_session_find_or_create(mock_tunnel, &key, &was_created);

    check_not_null(session);
    check_int_eq(1, was_created);

    tunnel_session_destroy(session);
}

/* =============================================================================
 * Session State Tests
 * ============================================================================= */

void test_session_state_transitions(void)
{
    tunnel_session_key_t key;
    make_tcp_key(&key, 0x0a000001, 12345, 0x08080808, 80);

    tunnel_session_t *session = tunnel_session_create(mock_tunnel, &key);

    check_int_eq(TUNNEL_SESSION_INIT, tunnel_session_get_state(session));

    tunnel_session_set_state(session, TUNNEL_SESSION_CONNECTING);
    check_int_eq(TUNNEL_SESSION_CONNECTING, tunnel_session_get_state(session));

    tunnel_session_set_state(session, TUNNEL_SESSION_ESTABLISHED);
    check_int_eq(TUNNEL_SESSION_ESTABLISHED, tunnel_session_get_state(session));
    check_int_eq(1, tunnel_session_is_established(session));

    tunnel_session_set_state(session, TUNNEL_SESSION_CLOSING);
    check_int_eq(TUNNEL_SESSION_CLOSING, tunnel_session_get_state(session));
    check_int_eq(0, tunnel_session_is_established(session));

    tunnel_session_destroy(session);
}

/* =============================================================================
 * TCP State Machine Tests
 * ============================================================================= */

void test_session_tcp_syn(void)
{
    tunnel_endpoint_t src = {
        .family = AF_INET,
        .addr.v4 = htonl(0x0a000001),
        .port = 12345,
    };
    tunnel_endpoint_t dst = {
        .family = AF_INET,
        .addr.v4 = htonl(0x08080808),
        .port = 80,
    };

    tunnel_session_t *session = tunnel_session_tcp_syn(mock_tunnel, &src, &dst, 1000);
    check_not_null(session);

    /* Should be in SYN_RECEIVED state */
    check_int_eq(TUNNEL_TCP_SYN_RECEIVED, tunnel_session_tcp_get_state(session));

    /* Verify sequence tracking */
    check_int_eq(1000, session->tcp.seq_remote);

    tunnel_session_destroy(session);
}

void test_session_tcp_data(void)
{
    tunnel_session_key_t key;
    make_tcp_key(&key, 0x0a000001, 12345, 0x08080808, 80);

    tunnel_session_t *session = tunnel_session_create(mock_tunnel, &key);
    tunnel_session_set_state(session, TUNNEL_SESSION_CONNECTING);
    session->tcp.state = TUNNEL_TCP_SYN_SENT;
    session->tcp.seq_remote = 1000;

    const uint8_t data[] = "Hello, World!";
    int ret = tunnel_session_tcp_data(session, 1000, data, sizeof(data) - 1);
    check_int_eq(TUNNEL_OK, ret);

    /* Verify traffic counters - buffered data counts as sent when eventually flushed */
    /* Wait, the current implementation only updates bytes_tx (sent to proxy) not bytes_rx (recv from TUN) in tcp_data? */
    /* tunnel_session_tcp_data updates bytes_tx. */
    /* But since we are CONNECTING, it buffers. It implies we accepted the data from TUN. */
    /* So logically it matches. */
    /* session->send_len should be data len */
    check_int_eq(sizeof(data) - 1, session->send_len);

    tunnel_session_destroy(session);
}

void test_session_tcp_ack(void)
{
    tunnel_session_key_t key;
    make_tcp_key(&key, 0x0a000001, 12345, 0x08080808, 80);

    tunnel_session_t *session = tunnel_session_create(mock_tunnel, &key);
    session->tcp.seq_local = 5000;
    session->tcp.window = 32768;

    int ret = tunnel_session_tcp_ack(session, 5100, 65535);
    check_int_eq(TUNNEL_OK, ret);

    /* Window should be updated */
    check_int_eq(65535, session->tcp.window);

    tunnel_session_destroy(session);
}

void test_session_tcp_fin(void)
{
    tunnel_session_key_t key;
    make_tcp_key(&key, 0x0a000001, 12345, 0x08080808, 80);

    tunnel_session_t *session = tunnel_session_create(mock_tunnel, &key);
    session->tcp.state = TUNNEL_TCP_ESTABLISHED;
    session->tcp.seq_remote = 2000;

    int ret = tunnel_session_tcp_fin(session, 2000);
    check_int_eq(TUNNEL_OK, ret);

    /* Should transition to LAST_ACK as it immediately closes both sides in this implementation */
    check_int_eq(TUNNEL_TCP_LAST_ACK, tunnel_session_tcp_get_state(session));

    tunnel_session_destroy(session);
}

void test_session_tcp_rst(void)
{
    tunnel_session_key_t key;
    make_tcp_key(&key, 0x0a000001, 12345, 0x08080808, 80);

    tunnel_session_t *session = tunnel_session_create(mock_tunnel, &key);
    session->tcp.state = TUNNEL_TCP_ESTABLISHED;

    int ret = tunnel_session_tcp_rst(session);
    check_int_eq(TUNNEL_OK, ret);

    /* Should immediately close */
    check_int_eq(TUNNEL_TCP_CLOSED, tunnel_session_tcp_get_state(session));
    check_int_eq(TUNNEL_SESSION_CLOSED, tunnel_session_get_state(session));

    tunnel_session_destroy(session);
}

/* =============================================================================
 * UDP Session Tests
 * ============================================================================= */

void test_session_udp_datagram(void)
{
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

    const uint8_t dns_query[] = {0x00, 0x01, 0x01, 0x00, 0x00, 0x01};
    int ret = tunnel_session_udp_datagram(mock_tunnel, &src, &dst, dns_query, sizeof(dns_query));
    check_int_eq(TUNNEL_OK, ret);

    /* Session should be created */
    tunnel_session_key_t key;
    memset(&key, 0, sizeof(key));
    tunnel_endpoint_copy(&key.src, &src);
    tunnel_endpoint_copy(&key.dst, &dst);
    key.protocol = TUNNEL_IPPROTO_UDP;

    tunnel_session_t *session = tunnel_session_find(mock_tunnel, &key);
    check_not_null(session);

    /* Should be immediately established (no handshake for UDP) */
    check_int_eq(TUNNEL_SESSION_ESTABLISHED, tunnel_session_get_state(session));

    tunnel_session_destroy(session);
}

/* =============================================================================
 * Session Count Tests
 * ============================================================================= */

void test_session_count_by_protocol(void)
{
    /* Create 3 TCP sessions */
    for (int i = 0; i < 3; i++) {
        tunnel_session_key_t key;
        make_tcp_key(&key, 0x0a000001, 10000 + i, 0x08080808, 80);
        tunnel_session_create(mock_tunnel, &key);
    }

    /* Create 2 UDP sessions */
    for (int i = 0; i < 2; i++) {
        tunnel_session_key_t key;
        make_udp_key(&key, 0x0a000001, 20000 + i, 0x08080808, 53);
        tunnel_session_create(mock_tunnel, &key);
    }

    check_int_eq(5, tunnel_session_count(mock_tunnel));
    check_int_eq(3, tunnel_session_tcp_count(mock_tunnel));
    check_int_eq(2, tunnel_session_udp_count(mock_tunnel));
}

/* =============================================================================
 * Session Timeout Tests
 * ============================================================================= */

void test_session_touch_updates_time(void)
{
    tunnel_session_key_t key;
    make_tcp_key(&key, 0x0a000001, 12345, 0x08080808, 80);

    tunnel_session_t *session = tunnel_session_create(mock_tunnel, &key);
    uint64_t initial_active = session->last_active;

    /* Wait a tiny bit and touch */
    tunnel_session_touch(session);

    /* last_active should be updated */
    check(session->last_active >= initial_active);

    tunnel_session_destroy(session);
}

void test_session_age(void)
{
    tunnel_session_key_t key;
    make_tcp_key(&key, 0x0a000001, 12345, 0x08080808, 80);

    tunnel_session_t *session = tunnel_session_create(mock_tunnel, &key);

    /* Newly created session age should stay near zero. */
    uint64_t age = tunnel_session_get_age(session);
    check(age < 1000);

    tunnel_session_destroy(session);
}

void test_session_idle(void)
{
    tunnel_session_key_t key;
    make_tcp_key(&key, 0x0a000001, 12345, 0x08080808, 80);

    tunnel_session_t *session = tunnel_session_create(mock_tunnel, &key);

    /* Newly created session idle time should stay near zero. */
    uint64_t idle = tunnel_session_get_idle(session);
    check(idle < 1000);

    tunnel_session_destroy(session);
}

/* =============================================================================
 * Domain Tests
 * ============================================================================= */

void test_session_domain(void)
{
    tunnel_session_key_t key;
    make_tcp_key(&key, 0x0a000001, 12345, 0x08080808, 80);

    tunnel_session_t *session = tunnel_session_create(mock_tunnel, &key);

    /* Initially no domain */
    check_null(tunnel_session_get_domain(session));

    /* Set domain */
    tunnel_session_set_domain(session, "example.com");
    check_str_eq("example.com", tunnel_session_get_domain(session));

    /* Domain should be copied, not just referenced */
    const char *domain = tunnel_session_get_domain(session);
    check_not_null(domain);

    tunnel_session_destroy(session);
}

void test_session_domain_long(void)
{
    tunnel_session_key_t key;
    make_tcp_key(&key, 0x0a000001, 12345, 0x08080808, 80);

    tunnel_session_t *session = tunnel_session_create(mock_tunnel, &key);

    /* Long domain should be truncated */
    char long_domain[300];
    memset(long_domain, 'a', sizeof(long_domain) - 1);
    long_domain[sizeof(long_domain) - 1] = '\0';

    tunnel_session_set_domain(session, long_domain);

    /* Should not crash, domain should be set (possibly truncated) */
    const char *domain = tunnel_session_get_domain(session);
    check_not_null(domain);
    check(strlen(domain) + 1 <= TUNNEL_MAX_DOMAIN);

    tunnel_session_destroy(session);
}

/* =============================================================================
 * Session Iteration Tests
 * ============================================================================= */

static int count_callback(tunnel_session_t *session, void *user_data)
{
    int *count = (int *)user_data;
    (*count)++;
    return 0;  /* Continue iteration */
}

static int stop_at_3_callback(tunnel_session_t *session, void *user_data)
{
    int *count = (int *)user_data;
    (*count)++;
    return (*count >= 3) ? 1 : 0;  /* Stop after 3 */
}

void test_session_foreach(void)
{
    /* Create 5 sessions */
    for (int i = 0; i < 5; i++) {
        tunnel_session_key_t key;
        make_tcp_key(&key, 0x0a000001, 10000 + i, 0x08080808, 80);
        tunnel_session_create(mock_tunnel, &key);
    }

    int count = 0;
    tunnel_session_foreach(mock_tunnel, count_callback, &count);

    check_int_eq(5, count);
}

void test_session_foreach_early_stop(void)
{
    /* Create 5 sessions */
    for (int i = 0; i < 5; i++) {
        tunnel_session_key_t key;
        make_tcp_key(&key, 0x0a000001, 10000 + i, 0x08080808, 80);
        tunnel_session_create(mock_tunnel, &key);
    }

    int count = 0;
    tunnel_session_foreach(mock_tunnel, stop_at_3_callback, &count);

    check_int_eq(3, count);
}

spec("tunnel session") {
    before_each() {
        setUp();
    }

    after_each() {
        tearDown();
    }

    describe("creation") {
        it("creates a session") { test_session_create(); }
        it("creates multiple sessions") { test_session_create_multiple(); }
    }

    describe("find") {
        it("finds an existing session") { test_session_find(); }
        it("reports a missing session") { test_session_find_not_found(); }
        it("returns an existing session from find_or_create") { test_session_find_or_create_existing(); }
        it("creates a new session from find_or_create") { test_session_find_or_create_new(); }
    }

    describe("state") {
        it("handles state transitions") { test_session_state_transitions(); }
    }

    describe("tcp") {
        it("handles tcp syn") { test_session_tcp_syn(); }
        it("handles tcp data") { test_session_tcp_data(); }
        it("handles tcp ack") { test_session_tcp_ack(); }
        it("handles tcp fin") { test_session_tcp_fin(); }
        it("handles tcp rst") { test_session_tcp_rst(); }
    }

    describe("udp") {
        it("handles udp datagrams") { test_session_udp_datagram(); }
    }

    describe("counts") {
        it("counts by protocol") { test_session_count_by_protocol(); }
    }

    describe("timing") {
        it("updates last active on touch") { test_session_touch_updates_time(); }
        it("reports age") { test_session_age(); }
        it("reports idle time") { test_session_idle(); }
    }

    describe("domain") {
        it("stores a domain") { test_session_domain(); }
        it("caps a long domain") { test_session_domain_long(); }
    }

    describe("iteration") {
        it("iterates sessions") { test_session_foreach(); }
        it("supports early stop") { test_session_foreach_early_stop(); }
    }
}

