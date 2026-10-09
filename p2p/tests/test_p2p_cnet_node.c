#include "p2p_cnet_node_fixture.h"

static void test_poll_lifecycle(void) {
    endpoint_t endpoint = {0};
    p2p_node_cnet_t *duplicate = NULL;
    p2p_cnet_config_t transport = config(TEST_SEND_BYTES);
    check_equal(P2P_ERR_INVALID_ARG, p2p_poll(NULL));
    init_node(&endpoint, 17, 0);
    check_equal(P2P_ERR_INVALID_STATE, p2p_poll(endpoint.node));
    transport.accept_budget = 0;
    check_equal(P2P_ERR_INVALID_ARG,
        p2p_node_cnet_create(endpoint.node, &transport, &endpoint.owner));
    check_true(endpoint.owner == NULL);
    check_true(endpoint.node->network_context == NULL);
    check_equal(P2P_ERR_INVALID_STATE, p2p_poll(endpoint.node));
    transport = config(TEST_SEND_BYTES);
    start_endpoint(&endpoint, TEST_SEND_BYTES);
    check_equal(P2P_ERR_INVALID_STATE, p2p_node_state_destroy(endpoint.node));
    check_equal(P2P_ERR_INVALID_STATE,
        p2p_node_cnet_create(endpoint.node, &transport, &duplicate));
    check_true(duplicate == NULL);
    check_true(endpoint.node->network_context == endpoint.owner);
    check_equal(P2P_OK, p2p_poll(endpoint.node));
    check_equal(P2P_OK, p2p_node_cnet_stop(endpoint.owner));
    check_equal(P2P_ERR_INVALID_STATE, p2p_poll(endpoint.node));
    check_equal(P2P_OK, p2p_node_cnet_stop(endpoint.owner));
    check_equal(P2P_OK, p2p_node_cnet_destroy(endpoint.owner));
    check_equal(P2P_ERR_INVALID_STATE, p2p_poll(endpoint.node));
    check_true(endpoint.node->network_context == NULL);
    check_equal(P2P_OK, p2p_node_state_destroy(endpoint.node));
}

static int has_route(endpoint_t *endpoint, endpoint_t *remote) {
    kad_id_t id;
    int found = 0;
    memcpy(id.bytes, remote->node->id, sizeof(id.bytes));
    kad_node_t **nodes = kademlia_find_node(endpoint->node->kad_dht, &id, KADEMLIA_K);
    if (!nodes) return 0;
    for (int i = 0; i < KADEMLIA_K && nodes[i]; ++i)
        if (!memcmp(nodes[i]->id.bytes, id.bytes, sizeof(id.bytes)) &&
            nodes[i]->port == remote->node->port && !strcmp(nodes[i]->ip, remote->node->ip)) found = 1;
    free(nodes);
    return found;
}
static void lookup_done(void *result, void *context) {
    endpoint_t *endpoint = context;
    check_not_null(result);
    endpoint->lookup_done++;
}
static void lookup_cleaned(void *context) {
    endpoint_t *endpoint = context;
    endpoint->lookup_cleaned++;
    if (!endpoint->node->network_ops)
        check_true(p2p_dht_lookup_start(endpoint->node, endpoint->node->id,
            P2P_MSG_DHT_FIND_NODE) == NULL);
}
static void test_roundtrip(size_t receive_bytes, int blocking) {
    pair_t pair = {0};
    p2p_cnet_admission_stats_t stats;
    uint64_t deadline;
    setup(&pair, receive_bytes, blocking);
    connect_pair(&pair);
    wait_ready(&pair);
    deadline = cmeta_monotonic_ms() + TEST_WAIT_MS;
    while ((!has_route(&pair.client, &pair.server) || !has_route(&pair.server, &pair.client)) &&
        cmeta_monotonic_ms() < deadline) pump(&pair);
    check_true(has_route(&pair.client, &pair.server));
    check_true(has_route(&pair.server, &pair.client));
    check_equal(1, pair.client.node->peer_count);
    check_equal(1, pair.server.node->peer_count);
    check_equal(P2P_OK, p2p_node_cnet_admission_stats(pair.server.owner, &stats));
    check_equal((size_t)0, stats.active);
    check_equal((uint64_t)1, stats.promoted);
    check_equal((uint64_t)1, stats.challenges_completed);
    check_equal(P2P_OK, p2p_send_message(pair.client.node, pair.client.peer, P2P_MSG_CUSTOM, "client", 6));
    check_equal(P2P_OK, p2p_send_message(pair.server.node, pair.server.peer, P2P_MSG_CUSTOM, "server", 6));
    while ((!pair.client.messages || !pair.server.messages) && cmeta_monotonic_ms() < deadline) pump(&pair);
    check_equal(1, pair.client.messages);
    check_equal(1, pair.server.messages);
    check_equal(pair.client.received, "server", 6);
    check_equal(pair.server.received, "client", 6);
    p2p_dht_lookup_t *lookup = p2p_dht_lookup_start(pair.client.node, pair.server.node->id, P2P_MSG_DHT_FIND_NODE);
    check_not_null(lookup);
    lookup->callback = lookup_done;
    lookup->cleanup = lookup_cleaned;
    lookup->user_data = &pair.client;
    while (!pair.client.lookup_done && cmeta_monotonic_ms() < deadline) pump(&pair);
    check_equal(1, pair.client.lookup_done);
    check_equal(1, pair.client.lookup_cleaned);
    teardown(&pair);
}
static void test_stop_callback(void) {
    pair_t pair = {0};
    uint64_t deadline;
    setup(&pair, 7, 0);
    pair.server.stop_on_auth = 1;
    connect_pair(&pair);
    deadline = cmeta_monotonic_ms() + TEST_WAIT_MS;
    while (!pair.server.stopped && cmeta_monotonic_ms() < deadline) pump(&pair);
    check_true(pair.server.stopped);
    check_equal(0, pair.server.node->peer_count);
    check_true(pair.server.node->peers_table == NULL);
    check_equal(P2P_ERR_INVALID_STATE, p2p_poll(pair.server.node));
    check_equal(P2P_ERR_INVALID_STATE, p2p_connect(pair.server.node, "127.0.0.1", pair.client.node->port));
    teardown(&pair);
}
static void test_stop_worker(void) {
    pair_t pair = {0};
    uint64_t deadline;
    setup(&pair, 7, 1);
    atomic_store(&pair.server.released, 0);
    connect_pair(&pair);
    deadline = cmeta_monotonic_ms() + TEST_WAIT_MS;
    while (!atomic_load(&pair.server.calls) && cmeta_monotonic_ms() < deadline) pump(&pair);
    check_true(atomic_load(&pair.server.calls) > 0);
    check_equal(P2P_OK, p2p_node_cnet_stop(pair.server.owner));
    pair.server.stopped = 1;
    check_equal(0, pair.server.authenticated);
    check_equal((size_t)0, pair.server.node->reserved_send_capacity_bytes);
    check_true(pair.server.node->peers_table == NULL);
    teardown(&pair);
}
static void test_stale_peer(void) {
    pair_t pair = {0};
    setup(&pair, TEST_SEND_BYTES, 0);
    connect_pair(&pair);
    wait_ready(&pair);
    pair.client.peer->last_seen = (cmeta_monotonic_ms() - P2P_PEER_TIMEOUT_MS - 1) * 1000000U;
    p2p_node_maintain_peers(pair.client.node, cmeta_monotonic_ms());
    check_equal(P2P_OK, p2p_poll(pair.client.node));
    check_equal(1, pair.client.disconnected);
    check_equal(0, pair.client.node->peer_count);
    check_equal((size_t)0, pair.client.node->reserved_send_capacity_bytes);
    check_equal(P2P_OK, p2p_poll(pair.client.node));
    check_equal(1, pair.client.disconnected);
    teardown(&pair);
}
static void test_handshake_expiry(void) {
    pair_t pair = {0};
    p2p_peer_t *peer;
    setup(&pair, 7, 0);
    connect_pair(&pair);
    peer = p2p_peer_find(pair.client.node, pair.server.node->ip, pair.server.node->port);
    check_not_null(peer);
    peer->security_deadline_ms = cmeta_monotonic_ms();
    check_equal(P2P_OK, p2p_poll(pair.client.node));
    check_true(pair.client.node->peers_table == NULL);
    check_equal((uint64_t)1, pair.client.node->security_rejection_counts[P2P_SECURITY_REJECTION_HANDSHAKE_TIMEOUT]);
    check_equal((size_t)0, pair.client.node->reserved_send_capacity_bytes);
    teardown(&pair);
}
static void test_budget(void) {
    pair_t pair = {0};
    setup(&pair, TEST_SEND_BYTES, 0);
    pair.client.node->security_config.node_send_budget_bytes = TEST_SEND_BYTES;
    connect_pair(&pair);
    check_equal(P2P_ERR_RESOURCE_EXHAUSTED, p2p_connect(pair.client.node, "127.0.0.1", pair.client.node->port));
    check_equal(1, peer_table_count(pair.client.node->peers_table));
    check_equal((uint64_t)1, pair.client.node->send_budget_rejections);
    check_equal((size_t)TEST_SEND_BYTES, pair.client.node->reserved_send_capacity_bytes);
    teardown(&pair);
}
static void test_pending_source(void) {
    pair_t pair = {0};
    uint64_t deadline;
    p2p_cnet_admission_stats_t stats;
    setup(&pair, 7, 0);
    for (int i = 0; i < P2P_PENDING_PEER_SOURCE_LIMIT; ++i) {
        p2p_peer_t *peer = p2p_peer_create(pair.server.node, "127.0.0.1", 20000 + i);
        check_not_null(peer);
        peer->state = P2P_PEER_STATE_HANDSHAKING;
        p2p_node_add_peer_locked(pair.server.node, peer);
    }
    connect_pair(&pair);
    deadline = cmeta_monotonic_ms() + TEST_WAIT_MS;
    do {
        pump(&pair);
        check_equal(P2P_OK, p2p_node_cnet_admission_stats(pair.server.owner, &stats));
    } while (!stats.rejected && cmeta_monotonic_ms() < deadline);
    check_equal((uint64_t)1, stats.rejected);
    check_equal((uint64_t)0, stats.accepted);
    check_equal((uint64_t)1, pair.server.node->security_rejection_counts[P2P_SECURITY_REJECTION_PENDING_SOURCE]);
    check_equal(0, pair.server.authenticated);
    teardown(&pair);
}
static void test_cancel_lookup(void) {
    pair_t pair = {0};
    setup(&pair, TEST_SEND_BYTES, 0);
    connect_pair(&pair);
    wait_ready(&pair);
    p2p_dht_lookup_t *lookup = p2p_dht_lookup_start(pair.client.node, pair.server.node->id, P2P_MSG_DHT_FIND_NODE);
    check_not_null(lookup);
    lookup->callback = lookup_done;
    lookup->cleanup = lookup_cleaned;
    lookup->user_data = &pair.client;
    check_equal(P2P_OK, p2p_node_cnet_stop(pair.client.owner));
    pair.client.stopped = 1;
    check_equal(0, pair.client.lookup_done);
    check_equal(1, pair.client.lookup_cleaned);
    check_true(pair.client.node->dht_lookups == NULL);
    teardown(&pair);
}
static void test_gate_and_peer_quota(void) {
    pair_t pair = {0};
    p2p_cnet_admission_stats_t stats;
    size_t total, source;
    uint64_t deadline;
    setup(&pair, 7, 0);
    connect_pair(&pair);
    deadline = cmeta_monotonic_ms() + TEST_WAIT_MS;
    do {
        pump(&pair);
        check_equal(P2P_OK, p2p_node_cnet_admission_stats(pair.server.owner, &stats));
    } while (!stats.active && cmeta_monotonic_ms() < deadline);
    check_equal((size_t)1, stats.active);
    for (int i = 0; i < P2P_PENDING_PEER_SOURCE_LIMIT - 1; ++i) {
        p2p_peer_t *peer = p2p_peer_create(pair.server.node, "127.0.0.1", 20000 + i);
        check_not_null(peer);
        peer->state = P2P_PEER_STATE_HANDSHAKING;
        p2p_node_add_peer_locked(pair.server.node, peer);
    }
    cmeta_mutex_lock(&pair.server.node->mutex);
    check_equal(P2P_OK, pair.server.node->network_ops->pending_gates(pair.server.node,
        "127.0.0.1", &total, &source, pair.server.node->network_context));
    check_equal((size_t)1, total);
    check_equal((size_t)1, source);
    check_true(!p2p_node_pending_peer_source_capacity_available_locked(pair.server.node, "127.0.0.1"));
    check_true(p2p_node_pending_peer_source_capacity_available_locked(pair.server.node, "127.0.0.2"));
    cmeta_mutex_unlock(&pair.server.node->mutex);
    check_equal(P2P_ERR_RESOURCE_EXHAUSTED, p2p_connect(pair.server.node, "127.0.0.1", pair.client.node->port));
    teardown(&pair);
}
static void test_reject_identity(void) {
    pair_t pair = {0};
    uint64_t deadline;
    setup(&pair, 7, 1);
    pair.server.reject_credential = 1;
    connect_pair(&pair);
    deadline = cmeta_monotonic_ms() + TEST_WAIT_MS;
    while (!pair.server.disconnected && cmeta_monotonic_ms() < deadline) pump(&pair);
    check_equal(0, pair.server.authenticated);
    check_equal(1, pair.server.disconnected);
    check_equal(0, pair.server.node->peer_count);
    check_true(pair.server.node->peers_table == NULL);
    check_equal((size_t)0, pair.server.node->reserved_send_capacity_bytes);
    check_true(pair.server.node->security_rejection_counts[P2P_SECURITY_REJECTION_HANDSHAKE_IDENTITY] > 0);
    teardown(&pair);
}
static void test_retained_peer_limit(void) {
    pair_t pair = {0};
    p2p_cnet_config_t transport = config(7);
    setup(&pair, 7, 0);
    for (size_t i = 0; i < transport.client.connection_capacity; ++i) {
        p2p_peer_t *peer = p2p_peer_create(pair.client.node, "127.0.0.1", 20000 + (int)i);
        check_not_null(peer);
        peer->keep_entry = 1;
        p2p_node_add_peer_locked(pair.client.node, peer);
    }
    check_equal(P2P_ERR_RESOURCE_EXHAUSTED,
        p2p_connect(pair.client.node, pair.server.node->ip, pair.server.node->port));
    check_equal(transport.client.connection_capacity, (size_t)peer_table_count(pair.client.node->peers_table));
    check_equal((size_t)0, pair.client.node->reserved_send_capacity_bytes);
    check_equal((uint64_t)1, pair.client.node->security_rejection_counts[P2P_SECURITY_REJECTION_HANDSHAKE_RESOURCE]);
    teardown(&pair);
}
static void test_cross_connect(void) {
    pair_t pair = {0};
    uint64_t deadline;
    setup(&pair, 7, 0);
    connect_pair(&pair);
    check_equal(P2P_OK, p2p_connect(pair.server.node, pair.client.node->ip, pair.client.node->port));
    deadline = cmeta_monotonic_ms() + TEST_WAIT_MS;
    while ((!pair.client.authenticated || !pair.server.authenticated ||
            pair.client.node->transport_send_reservations != 1 ||
            pair.server.node->transport_send_reservations != 1) &&
        cmeta_monotonic_ms() < deadline) pump(&pair);
    check_equal(1, pair.client.node->peer_count);
    check_equal(1, pair.server.node->peer_count);
    check_equal((size_t)1, pair.client.node->transport_send_reservations);
    check_equal((size_t)1, pair.server.node->transport_send_reservations);
    check_equal(P2P_CONN_OUTBOUND, pair.client.peer->conn->type);
    check_equal(P2P_CONN_INBOUND, pair.server.peer->conn->type);
    check_equal(P2P_OK, p2p_send_message(pair.server.node, pair.server.peer, P2P_MSG_CUSTOM, "winner", 6));
    while (!pair.client.messages && cmeta_monotonic_ms() < deadline) pump(&pair);
    check_equal(1, pair.client.messages);
    teardown(&pair);
}
static void test_direct_disconnect(void) {
    pair_t pair = {0};
    setup(&pair, TEST_SEND_BYTES, 0);
    connect_pair(&pair);
    wait_ready(&pair);
    p2p_peer_disconnect(pair.server.peer);
    check_equal(P2P_OK, p2p_poll(pair.server.node));
    check_equal(1, pair.server.disconnected);
    check_equal(0, pair.server.node->peer_count);
    check_true(pair.server.node->peers_table == NULL);
    check_equal(P2P_OK, p2p_poll(pair.server.node));
    check_equal(1, pair.server.disconnected);
    teardown(&pair);
}
#ifdef P2P_NODE_TEST_WRAP
static int timeout_stop;
static int timeout_poll;
int __real_cnet_client_stop(cnet_client *, uint32_t);
int __real_cnet_client_poll(cnet_client *, uint32_t, size_t *);
int __wrap_cnet_client_stop(cnet_client *client, uint32_t timeout_ms) {
    if (timeout_stop) { timeout_stop = 0; return SALTS_ETIMEDOUT; }
    return __real_cnet_client_stop(client, timeout_ms);
}
int __wrap_cnet_client_poll(cnet_client *client, uint32_t timeout_ms, size_t *events) {
    if (timeout_poll) { timeout_poll = 0; *events = 0; return SALTS_ETIMEDOUT; }
    return __real_cnet_client_poll(client, timeout_ms, events);
}
static void test_poll_error(void) {
    pair_t pair = {0};
    setup(&pair, TEST_SEND_BYTES, 0);
    connect_pair(&pair);
    wait_ready(&pair);
    timeout_poll = 1;
    check_equal(P2P_ERR_TIMEOUT, p2p_poll(pair.client.node));
    check_true(pair.client.node->network_context == pair.client.owner);
    check_equal(P2P_ERR_INVALID_STATE, p2p_poll(pair.client.node));
    teardown(&pair);
}
static void test_callback_stop_error(void) {
    pair_t pair = {0};
    int result = P2P_OK;
    uint64_t deadline;
    setup(&pair, 7, 0);
    pair.server.stop_on_auth = 1;
    connect_pair(&pair);
    timeout_stop = 1;
    deadline = cmeta_monotonic_ms() + TEST_WAIT_MS;
    while (!pair.server.stopped && cmeta_monotonic_ms() < deadline) {
        check_equal(P2P_OK, p2p_poll(pair.client.node));
        result = p2p_poll(pair.server.node);
        if (result != P2P_OK) break;
        cmeta_sleep_ms(1);
    }
    check_true(pair.server.stopped);
    check_equal(P2P_ERR_TIMEOUT, result);
    check_true(pair.server.node->network_context == pair.server.owner);
    check_equal(P2P_ERR_INVALID_STATE, p2p_poll(pair.server.node));
    check_equal(0, timeout_stop);
    teardown(&pair);
}
static void test_stop_timeout(void) {
    pair_t pair = {0};
    setup(&pair, TEST_SEND_BYTES, 0);
    connect_pair(&pair);
    wait_ready(&pair);
    timeout_stop = 1;
    check_equal(P2P_ERR_TIMEOUT, p2p_node_cnet_destroy(pair.client.owner));
    check_true(pair.client.node->network_context == pair.client.owner);
    check_true(pair.client.node->peers_table == NULL);
    check_equal((size_t)0, pair.client.node->reserved_send_capacity_bytes);
    check_equal(P2P_ERR_INVALID_STATE, p2p_poll(pair.client.node));
    teardown(&pair);
}
#endif
spec("P2P production node network over CNet") {
    it("polls only a bound live owner and preserves state after failed or duplicate attachment") { test_poll_lifecycle(); }
    it("authenticates, learns listening endpoints, exchanges messages and completes DHT lookup") { test_roundtrip(TEST_SEND_BYTES, 0); }
    it("preserves routing and DHT under fragmentation with both key workers") { test_roundtrip(7, 1); }
    it("defers callback stop and rejects callback destruction") { test_stop_callback(); }
    it("cancels private-key work before releasing node storage") { test_stop_worker(); }
    it("prunes stale peers and updates node accounting once") { test_stale_peer(); }
    it("expires an idle outbound handshake at its deadline") { test_handshake_expiry(); }
    it("rolls back a second connection rejected by the real node send budget") { test_budget(); }
    it("counts pending peers in source admission before allocating a cookie gate") { test_pending_source(); }
    it("shares a single source quota across pending gates, inbound peers and outbound connects") { test_gate_and_peer_quota(); }
    it("removes a rejected identity without publishing or reserving a peer") { test_reject_identity(); }
    it("bounds retained disconnected endpoints and rolls back rejected insertions") { test_retained_peer_limit(); }
    it("cancels DHT lookups with cleanup exactly once during stop") { test_cancel_lookup(); }
    it("converges crossed connections to one authenticated identity and one reservation") { test_cross_connect(); }
    it("reaps direct protocol disconnects exactly once") { test_direct_disconnect(); }
#ifdef P2P_NODE_TEST_WRAP
    it("propagates a native poll timeout and retains the owner for cleanup") { test_poll_error(); }
    it("propagates callback-deferred stop timeout and allows cleanup retry") { test_callback_stop_error(); }
    it("retains node and owner after a drain timeout until retry succeeds") { test_stop_timeout(); }
#endif
}
