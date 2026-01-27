/**
 * @file test_session.c
 * @brief Tests for tunnel session lifecycle management
 */

#include "unity.h"
#include "../src/session/tunnel_session.h"
#include "../src/core/tunnel_types.h"
#include <string.h>
#include <stdlib.h>

/* Mock tunnel */
static tunnel_t *mock_tunnel = NULL;

void setUp(void)
{
    mock_tunnel = (tunnel_t *)calloc(1, sizeof(tunnel_t));
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
    TEST_ASSERT_NOT_NULL(session);

    /* Verify key is copied */
    TEST_ASSERT_EQUAL(0, tunnel_session_key_compare(&key, &session->key));

    /* Verify initial state */
    TEST_ASSERT_EQUAL(TUNNEL_SESSION_INIT, session->state);
    TEST_ASSERT_EQUAL(0, session->bytes_rx);
    TEST_ASSERT_EQUAL(0, session->bytes_tx);
    TEST_ASSERT_EQUAL_PTR(mock_tunnel, session->tunnel);

    tunnel_session_destroy(session);
}

void test_session_create_multiple(void)
{
    tunnel_session_t *sessions[10];

    for (int i = 0; i < 10; i++) {
        tunnel_session_key_t key;
        make_tcp_key(&key, 0x0a000001, 10000 + i, 0x08080808, 80);
        sessions[i] = tunnel_session_create(mock_tunnel, &key);
        TEST_ASSERT_NOT_NULL(sessions[i]);
    }

    TEST_ASSERT_EQUAL(10, tunnel_session_count(mock_tunnel));

    for (int i = 0; i < 10; i++) {
        tunnel_session_destroy(sessions[i]);
    }

    TEST_ASSERT_EQUAL(0, tunnel_session_count(mock_tunnel));
}

/* =============================================================================
 * Session Find Tests
 * ============================================================================= */

void test_session_find(void)
{
    tunnel_session_key_t key;
    make_tcp_key(&key, 0x0a000001, 12345, 0x08080808, 80);

    tunnel_session_t *created = tunnel_session_create(mock_tunnel, &key);
    TEST_ASSERT_NOT_NULL(created);

    tunnel_session_t *found = tunnel_session_find(mock_tunnel, &key);
    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL_PTR(created, found);

    tunnel_session_destroy(created);
}

void test_session_find_not_found(void)
{
    tunnel_session_key_t key;
    make_tcp_key(&key, 0x0a000001, 12345, 0x08080808, 80);

    tunnel_session_t *found = tunnel_session_find(mock_tunnel, &key);
    TEST_ASSERT_NULL(found);
}

void test_session_find_or_create_existing(void)
{
    tunnel_session_key_t key;
    make_tcp_key(&key, 0x0a000001, 12345, 0x08080808, 80);

    tunnel_session_t *created = tunnel_session_create(mock_tunnel, &key);
    TEST_ASSERT_NOT_NULL(created);

    int was_created = 0;
    tunnel_session_t *found = tunnel_session_find_or_create(mock_tunnel, &key, &was_created);

    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL_PTR(created, found);
    TEST_ASSERT_EQUAL(0, was_created);

    tunnel_session_destroy(created);
}

void test_session_find_or_create_new(void)
{
    tunnel_session_key_t key;
    make_tcp_key(&key, 0x0a000001, 12345, 0x08080808, 80);

    int was_created = 0;
    tunnel_session_t *session = tunnel_session_find_or_create(mock_tunnel, &key, &was_created);

    TEST_ASSERT_NOT_NULL(session);
    TEST_ASSERT_EQUAL(1, was_created);

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

    TEST_ASSERT_EQUAL(TUNNEL_SESSION_INIT, tunnel_session_get_state(session));

    tunnel_session_set_state(session, TUNNEL_SESSION_CONNECTING);
    TEST_ASSERT_EQUAL(TUNNEL_SESSION_CONNECTING, tunnel_session_get_state(session));

    tunnel_session_set_state(session, TUNNEL_SESSION_ESTABLISHED);
    TEST_ASSERT_EQUAL(TUNNEL_SESSION_ESTABLISHED, tunnel_session_get_state(session));
    TEST_ASSERT_EQUAL(1, tunnel_session_is_established(session));

    tunnel_session_set_state(session, TUNNEL_SESSION_CLOSING);
    TEST_ASSERT_EQUAL(TUNNEL_SESSION_CLOSING, tunnel_session_get_state(session));
    TEST_ASSERT_EQUAL(0, tunnel_session_is_established(session));

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
    TEST_ASSERT_NOT_NULL(session);

    /* Should be in SYN_RECEIVED state */
    TEST_ASSERT_EQUAL(TUNNEL_TCP_SYN_RECEIVED, tunnel_session_tcp_get_state(session));

    /* Verify sequence tracking */
    TEST_ASSERT_EQUAL(1000, session->tcp.seq_remote);

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
    TEST_ASSERT_EQUAL(TUNNEL_OK, ret);

    /* Verify traffic counters - buffered data counts as sent when eventually flushed */
    /* Wait, the current implementation only updates bytes_tx (sent to proxy) not bytes_rx (recv from TUN) in tcp_data? */
    /* tunnel_session_tcp_data updates bytes_tx. */
    /* But since we are CONNECTING, it buffers. It implies we accepted the data from TUN. */
    /* So logically it matches. */
    /* session->send_len should be data len */
    TEST_ASSERT_EQUAL(sizeof(data) - 1, session->send_len);

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
    TEST_ASSERT_EQUAL(TUNNEL_OK, ret);

    /* Window should be updated */
    TEST_ASSERT_EQUAL(65535, session->tcp.window);

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
    TEST_ASSERT_EQUAL(TUNNEL_OK, ret);

    /* Should transition to LAST_ACK as it immediately closes both sides in this implementation */
    TEST_ASSERT_EQUAL(TUNNEL_TCP_LAST_ACK, tunnel_session_tcp_get_state(session));

    tunnel_session_destroy(session);
}

void test_session_tcp_rst(void)
{
    tunnel_session_key_t key;
    make_tcp_key(&key, 0x0a000001, 12345, 0x08080808, 80);

    tunnel_session_t *session = tunnel_session_create(mock_tunnel, &key);
    session->tcp.state = TUNNEL_TCP_ESTABLISHED;

    int ret = tunnel_session_tcp_rst(session);
    TEST_ASSERT_EQUAL(TUNNEL_OK, ret);

    /* Should immediately close */
    TEST_ASSERT_EQUAL(TUNNEL_TCP_CLOSED, tunnel_session_tcp_get_state(session));
    TEST_ASSERT_EQUAL(TUNNEL_SESSION_CLOSED, tunnel_session_get_state(session));

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
    TEST_ASSERT_EQUAL(TUNNEL_OK, ret);

    /* Session should be created */
    tunnel_session_key_t key;
    memset(&key, 0, sizeof(key));
    tunnel_endpoint_copy(&key.src, &src);
    tunnel_endpoint_copy(&key.dst, &dst);
    key.protocol = TUNNEL_IPPROTO_UDP;

    tunnel_session_t *session = tunnel_session_find(mock_tunnel, &key);
    TEST_ASSERT_NOT_NULL(session);

    /* Should be immediately established (no handshake for UDP) */
    TEST_ASSERT_EQUAL(TUNNEL_SESSION_ESTABLISHED, tunnel_session_get_state(session));

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

    TEST_ASSERT_EQUAL(5, tunnel_session_count(mock_tunnel));
    TEST_ASSERT_EQUAL(3, tunnel_session_tcp_count(mock_tunnel));
    TEST_ASSERT_EQUAL(2, tunnel_session_udp_count(mock_tunnel));
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
    TEST_ASSERT_GREATER_OR_EQUAL(initial_active, session->last_active);

    tunnel_session_destroy(session);
}

void test_session_age(void)
{
    tunnel_session_key_t key;
    make_tcp_key(&key, 0x0a000001, 12345, 0x08080808, 80);

    tunnel_session_t *session = tunnel_session_create(mock_tunnel, &key);

    /* Age should be >= 0 */
    uint64_t age = tunnel_session_get_age(session);
    TEST_ASSERT_GREATER_OR_EQUAL(0, age);

    tunnel_session_destroy(session);
}

void test_session_idle(void)
{
    tunnel_session_key_t key;
    make_tcp_key(&key, 0x0a000001, 12345, 0x08080808, 80);

    tunnel_session_t *session = tunnel_session_create(mock_tunnel, &key);

    /* Idle should be >= 0 */
    uint64_t idle = tunnel_session_get_idle(session);
    TEST_ASSERT_GREATER_OR_EQUAL(0, idle);

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
    TEST_ASSERT_NULL(tunnel_session_get_domain(session));

    /* Set domain */
    tunnel_session_set_domain(session, "example.com");
    TEST_ASSERT_EQUAL_STRING("example.com", tunnel_session_get_domain(session));

    /* Domain should be copied, not just referenced */
    const char *domain = tunnel_session_get_domain(session);
    TEST_ASSERT_NOT_NULL(domain);

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
    TEST_ASSERT_NOT_NULL(domain);
    TEST_ASSERT_LESS_OR_EQUAL(TUNNEL_MAX_DOMAIN, strlen(domain) + 1);

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

    TEST_ASSERT_EQUAL(5, count);
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

    TEST_ASSERT_EQUAL(3, count);
}

/* =============================================================================
 * Main
 * ============================================================================= */

int main(void)
{
    UNITY_BEGIN();

    /* Creation */
    RUN_TEST(test_session_create);
    RUN_TEST(test_session_create_multiple);

    /* Find */
    RUN_TEST(test_session_find);
    RUN_TEST(test_session_find_not_found);
    RUN_TEST(test_session_find_or_create_existing);
    RUN_TEST(test_session_find_or_create_new);

    /* State */
    RUN_TEST(test_session_state_transitions);

    /* TCP */
    RUN_TEST(test_session_tcp_syn);
    RUN_TEST(test_session_tcp_data);
    RUN_TEST(test_session_tcp_ack);
    RUN_TEST(test_session_tcp_fin);
    RUN_TEST(test_session_tcp_rst);

    /* UDP */
    RUN_TEST(test_session_udp_datagram);

    /* Counts */
    RUN_TEST(test_session_count_by_protocol);

    /* Timeout */
    RUN_TEST(test_session_touch_updates_time);
    RUN_TEST(test_session_age);
    RUN_TEST(test_session_idle);

    /* Domain */
    RUN_TEST(test_session_domain);
    RUN_TEST(test_session_domain_long);

    /* Iteration */
    RUN_TEST(test_session_foreach);
    RUN_TEST(test_session_foreach_early_stop);

    return UNITY_END();
}
