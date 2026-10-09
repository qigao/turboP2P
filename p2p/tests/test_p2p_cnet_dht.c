#define TEST_SEND_BYTES (2 * 1024 * 1024)
#include "p2p_cnet_node_fixture.h"

static const char cache_key[] = "dht:shared:key";
static const char cache_value[] = "authenticated CNet DHT value";

static void check_cached(p2p_node_t *node, const char *key, const void *value, size_t size) {
    uint8_t output[128] = {0};
    size_t length = sizeof(output);
    check_equal(P2P_OK, p2p_dht_get_cached(node, key, output, &length));
    check_equal(size, length);
    check_equal(value, output, size);
}
static void test_cache(void) {
    p2p_node_t *node = p2p_node_state_create("127.0.0.1", 0);
    uint8_t output[sizeof(cache_value)] = {0};
    size_t length = sizeof(output);
    check_not_null(node);
    check_equal(P2P_OK, p2p_dht_put_cached(node, cache_key, cache_value, sizeof(cache_value)));
    check_equal((size_t)1, p2p_dht_get_entry_count(node));
    check_equal(P2P_OK, p2p_dht_get(node, cache_key, output, &length));
    check_equal(cache_value, output, sizeof(output));
    for (int cached = 0; cached < 2; ++cached) {
        uint8_t small[4] = {1, 2, 3, 4};
        const uint8_t expected[4] = {1, 2, 3, 4};
        length = sizeof(small);
        int result = cached ? p2p_dht_get_cached(node, cache_key, small, &length)
                            : p2p_dht_get(node, cache_key, small, &length);
        check_equal(P2P_ERR_RESOURCE_EXHAUSTED, result);
        check_equal(sizeof(cache_value), length);
        check_equal(expected, small, sizeof(small));
        check_true(node->dht_lookups == NULL);
    }
    length = sizeof(output);
    check_equal(P2P_ERR_INVALID_STATE, p2p_dht_get(node, "absent", output, &length));
    check_equal(P2P_ERR_NOT_FOUND, p2p_dht_get_cached(node, "absent", output, &length));
    check_equal(P2P_ERR_INVALID_ARG, p2p_dht_put_cached(node, cache_key, cache_value, 0));
    check_equal(P2P_OK, p2p_node_state_destroy(node));
}
static void test_replication(int cached) {
    pair_t pair = {0};
    uint8_t output[sizeof(cache_value)] = {0};
    size_t length = sizeof(output);
    setup(&pair, 7, 0);
    connect_pair(&pair);
    wait_ready(&pair);
    int result = cached ? p2p_dht_put_cached(pair.client.node, cache_key, cache_value, sizeof(cache_value))
                        : p2p_dht_put(pair.client.node, cache_key, cache_value, sizeof(cache_value));
    check_equal(P2P_OK, result);
    uint64_t deadline = salts_monotonic_ms() + TEST_WAIT_MS;
    while ((p2p_dht_get_cached(pair.server.node, cache_key, output, &length) != P2P_OK ||
            pair.client.node->dht_lookups) && salts_monotonic_ms() < deadline) pump(&pair);
    check_cached(pair.server.node, cache_key, cache_value, sizeof(cache_value));
    check_true(pair.client.node->dht_lookups == NULL);
    teardown(&pair);
}

typedef struct {
    endpoint_t *endpoint;
    atomic_int ready, stop;
    int result;
} remote_loop_t;
static void remote_loop(void *context) {
    remote_loop_t *loop = context;
    endpoint_t *endpoint = loop->endpoint;
    p2p_cnet_config_t transport = config(7);
    loop->result = p2p_node_cnet_create(endpoint->node, &transport, &endpoint->owner);
    if (loop->result == P2P_OK) loop->result = p2p_node_cnet_listen(endpoint->owner);
    atomic_store(&loop->ready, loop->result == P2P_OK ? 1 : -1);
    while (loop->result == P2P_OK && !atomic_load(&loop->stop)) {
        loop->result = p2p_poll(endpoint->node);
        cmeta_sleep_ms(1);
    }
    int result = p2p_node_cnet_destroy(endpoint->owner);
    if (loop->result == P2P_OK) loop->result = result;
    endpoint->owner = NULL;
}
static void test_remote_get(int short_buffer, int missing) {
    pair_t pair = {0};
    remote_loop_t loop = {0};
    cmeta_thread_t thread = NULL;
    uint8_t network[P2P_SECURITY_ID_SIZE] = {9};
    uint8_t output[sizeof(cache_value)] = {0};
    size_t length = short_buffer ? 1 : sizeof(output);
    init_key_node(&pair.client, 17, 0);
    init_key_node(&pair.server, 33, 0);
    check_equal(P2P_OK, p2p_node_configure_pinned_security_v2(pair.client.node, network, pair.server.public_key, 1));
    check_equal(P2P_OK, p2p_node_configure_pinned_security_v2(pair.server.node, network, pair.client.public_key, 1));
    check_equal(P2P_OK, p2p_dht_put_cached(pair.server.node, cache_key, cache_value, sizeof(cache_value)));
    start_endpoint(&pair.client, 7);
    loop.endpoint = &pair.server;
    atomic_init(&loop.ready, 0);
    atomic_init(&loop.stop, 0);
    check_equal(0, cmeta_thread_create(&thread, remote_loop, &loop));
    uint64_t deadline = salts_monotonic_ms() + TEST_WAIT_MS;
    while (!atomic_load(&loop.ready) && salts_monotonic_ms() < deadline) cmeta_sleep_ms(1);
    int ready = atomic_load(&loop.ready);
    int result = P2P_ERR_INVALID_STATE;
    if (ready == 1) {
        result = p2p_connect(pair.client.node, "127.0.0.1", pair.server.node->port);
        while (result == P2P_OK && !pair.client.authenticated && salts_monotonic_ms() < deadline)
            result = p2p_poll(pair.client.node);
        if (result == P2P_OK && pair.client.authenticated)
            result = p2p_dht_get(pair.client.node, missing ? "absent" : cache_key, output, &length);
        else result = P2P_ERR_TIMEOUT;
    }
    atomic_store(&loop.stop, 1);
    check_equal(0, cmeta_thread_join(&thread));
    cmeta_thread_destroy(&thread);
    check_equal(1, ready);
    check_equal(P2P_OK, loop.result);
    check_equal(missing ? P2P_ERR_NOT_FOUND : short_buffer ? P2P_ERR_RESOURCE_EXHAUSTED : P2P_OK, result);
    check_true(pair.client.node->dht_lookups == NULL);
    if (!missing) {
        check_equal(sizeof(cache_value), length);
        if (!short_buffer) check_equal(cache_value, output, sizeof(output));
        else {
            uint8_t expected[sizeof(output)] = {0};
            check_equal(expected, output, sizeof(output));
        }
        check_cached(pair.client.node, cache_key, cache_value, sizeof(cache_value));
    }
    check_equal(P2P_OK, p2p_node_cnet_destroy(pair.client.owner));
    check_equal(P2P_OK, p2p_node_state_destroy(pair.client.node));
    check_equal(P2P_OK, p2p_node_state_destroy(pair.server.node));
}

static void lookup_cleanup(void *context) {
    endpoint_t *endpoint = context;
    endpoint->lookup_cleaned++;
    (void)p2p_dht_get_entry_count(endpoint->node); /* Cleanup must run outside the mutex. */
}
static void lookup_complete(void *result, void *context) {
    (void)result;
    ((endpoint_t *)context)->lookup_done++;
}
static void test_timeout(void) {
    pair_t pair = {0};
    char output[32] = {0};
    size_t length = sizeof(output);
    setup(&pair, TEST_SEND_BYTES, 0);
    connect_pair(&pair);
    wait_ready(&pair);
    p2p_dht_lookup_t *other = p2p_dht_lookup_start(pair.client.node, pair.server.node->id, P2P_MSG_DHT_FIND_NODE);
    check_not_null(other);
    uint32_t other_id = other->request_id;
    other->cleanup = lookup_cleanup;
    other->callback = lookup_complete;
    other->user_data = &pair.client;
    /* Keep the authenticated remote idle so this call reaches its own deadline. */
    check_equal(P2P_ERR_NOT_FOUND, p2p_dht_get(pair.client.node, "unanswered", output, &length));
    check_equal((unsigned)1, HASH_COUNT(pair.client.node->dht_lookups));
    check_true(p2p_dht_lookup_find(pair.client.node, other_id) == other);
    p2p_dht_lookup_cancel(pair.client.node, other_id);
    p2p_dht_lookup_cancel(pair.client.node, other_id);
    check_equal(1, pair.client.lookup_cleaned);
    check_equal(0, pair.client.lookup_done);
    check_true(pair.client.node->dht_lookups == NULL);
    /* Late ordinary responses for cancelled requests remain harmless. */
    for (int i = 0; i < 10; ++i) pump(&pair);
    check_equal(1, pair.client.lookup_cleaned);
    check_equal(0, pair.client.lookup_done);
    teardown(&pair);
}
static void query_callback(p2p_node_t *node, p2p_peer_t *peer,
    const void *bytes, size_t length, void *context) {
    endpoint_t *endpoint = context;
    char output[sizeof(cache_value)] = {0};
    size_t size = sizeof(output);
    (void)peer; (void)bytes; (void)length;
    check_equal(P2P_OK, p2p_dht_get(node, cache_key, output, &size));
    size = sizeof(output);
    check_equal(P2P_ERR_INVALID_STATE, p2p_dht_get(node, "callback-miss", output, &size));
    check_true(node->dht_lookups == NULL);
    endpoint->messages++;
    if (endpoint->stop_on_auth) {
        check_equal(P2P_OK, p2p_node_cnet_stop(endpoint->owner));
        endpoint->stopped = 1;
    }
}
static void test_callback(int stop) {
    pair_t pair = {0};
    char output[32];
    size_t length = sizeof(output);
    setup(&pair, TEST_SEND_BYTES, 0);
    check_equal(P2P_OK, p2p_dht_put_cached(pair.client.node, cache_key, cache_value, sizeof(cache_value)));
    connect_pair(&pair);
    wait_ready(&pair);
    pair.client.stop_on_auth = stop;
    p2p_set_message_handler(pair.client.node, query_callback, &pair.client);
    check_equal(P2P_OK, p2p_send(pair.server.node, pair.server.peer, "query", 5));
    uint64_t deadline = salts_monotonic_ms() + TEST_WAIT_MS;
    while (!pair.client.messages && salts_monotonic_ms() < deadline) pump(&pair);
    check_equal(1, pair.client.messages);
    if (stop) {
        check_equal(P2P_ERR_INVALID_STATE, p2p_dht_get(pair.client.node, "stopped", output, &length));
        check_cached(pair.client.node, cache_key, cache_value, sizeof(cache_value));
    }
    teardown(&pair);
}

static const p2p_node_network_ops_t *original_ops;
static int poll_turn, stop_during_query;
static int interrupted_poll(p2p_node_t *node, void *context) {
    if (++poll_turn == 2) {
        if (stop_during_query) return p2p_node_cnet_stop(context);
        return P2P_ERR_IO;
    }
    return original_ops->poll(node, context);
}
static void test_interrupted_query(int stop) {
    pair_t pair = {0};
    char output[32];
    size_t length = sizeof(output);
    setup(&pair, TEST_SEND_BYTES, 0);
    connect_pair(&pair);
    wait_ready(&pair);
    original_ops = pair.client.node->network_ops;
    p2p_node_network_ops_t ops = *original_ops;
    ops.poll = interrupted_poll;
    pair.client.node->network_ops = &ops;
    poll_turn = 0;
    stop_during_query = stop;
    check_equal(stop ? P2P_ERR_INVALID_STATE : P2P_ERR_IO,
        p2p_dht_get(pair.client.node, "interrupted", output, &length));
    check_equal(2, poll_turn);
    check_true(pair.client.node->dht_lookups == NULL);
    if (!stop) pair.client.node->network_ops = original_ops;
    teardown(&pair);
}

#ifdef P2P_DHT_TEST_WRAP
static size_t reject_allocation_size;
void *__real_malloc(size_t size);
void *__wrap_malloc(size_t size) {
    if (reject_allocation_size && size == reject_allocation_size) {
        reject_allocation_size = 0;
        return NULL;
    }
    return __real_malloc(size);
}
static void test_store_failure(void) {
    p2p_node_t *node = p2p_node_state_create("127.0.0.1", 0);
    const uint8_t replacement[113] = {7};
    check_not_null(node);
    check_equal(P2P_OK, p2p_dht_put_cached(node, cache_key, cache_value, sizeof(cache_value)));
    for (int cached = 0; cached < 2; ++cached) {
        reject_allocation_size = sizeof(replacement);
        int result = cached ? p2p_dht_put_cached(node, cache_key, replacement, sizeof(replacement))
                            : p2p_dht_put(node, cache_key, replacement, sizeof(replacement));
        check_equal((size_t)0, reject_allocation_size);
        check_equal(P2P_ERR_NO_MEM, result);
        check_cached(node, cache_key, cache_value, sizeof(cache_value));
        check_equal((size_t)1, p2p_dht_get_entry_count(node));
    }
    check_equal(P2P_OK, p2p_node_state_destroy(node));
}
#endif

spec("Shared DHT API over real CNet nodes") {
    it("reads local values and preserves caller capacity on short buffers") { test_cache(); }
    it("replicates cached puts over fragmented authenticated connections") { test_replication(1); }
    it("completes iterative put replication and releases pending data") { test_replication(0); }
    it("fetches a value while the remote runs on its own owner thread") { test_remote_get(0, 0); }
    it("reports required capacity after a remote fetch without partial copying") { test_remote_get(1, 0); }
    it("returns not found after the remote exhausts candidates") { test_remote_get(0, 1); }
    it("cancels only the synchronous lookup on timeout and runs cleanup once") { test_timeout(); }
    it("allows cached reads but rejects callback network progress") { test_callback(0); }
    it("rejects stopped-owner progress while retaining cached reads") { test_callback(1); }
    it("cleans its lookup when owner progress returns an error") { test_interrupted_query(0); }
    it("handles owner stop after starting the synchronous lookup") { test_interrupted_query(1); }
#ifdef P2P_DHT_TEST_WRAP
    it("preserves the old cached value when replacement allocation fails") { test_store_failure(); }
#endif
}
