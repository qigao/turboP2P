#include <tinytest.h>
#include "core/peer_cnet.h"
#include "core/node_cnet.h"
#include "security/p2p_cnet_admission.h"
#include "security/p2p_private_key_executor.h"
#include <monocypher.h>
#include <salts/clock.h>
#include <salts/thread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

enum { TEST_WAIT_MS = 3000, TEST_SEND_BYTES = 8192 };
typedef struct endpoint_s endpoint_t;
struct endpoint_s {
    p2p_node_t *node;
    p2p_peer_t *peer;
    p2p_node_cnet_t *owner;
    endpoint_t *remote;
    p2p_authenticated_identity_v2_t expected_identity;
    uint8_t secret[32], public_key[32];
    atomic_int calls, released;
    int blocking, delay_ms, reject_credential, authenticated, disconnected;
    int failures, last_error, messages, stop_on_auth, stopped, lookup_done, lookup_cleaned;
    uint8_t received[64];
    size_t received_len;
};
typedef struct { endpoint_t client, server; } pair_t;

/* Node construction/credentials are fixtures; all node policy/events, tables,
 * routing, peer protocol, admission, executor and CNet code are production. */
static int verify(void *context, const uint8_t remote_key[32], const uint8_t binding[32],
    const uint8_t *credential, size_t length, uint64_t now_ms,
    p2p_authenticated_identity_v2_t *identity) {
    endpoint_t *endpoint = context;
    uint8_t zero[32] = {0};
    check_true(now_ms != 0);
    check_true(memcmp(binding, zero, sizeof(zero)) != 0);
    if (endpoint->reject_credential || length != 32 ||
        memcmp(remote_key, endpoint->remote->public_key, 32) ||
        memcmp(credential, remote_key, 32)) return P2P_ERR_UNTRUSTED_IDENTITY;
    *identity = endpoint->remote->expected_identity;
    return P2P_OK;
}
static int public_key(void *context, uint8_t output[32]) {
    endpoint_t *endpoint = context;
    memcpy(output, endpoint->public_key, 32);
    return P2P_OK;
}
static int calculate(void *context, const uint8_t remote[32], uint64_t deadline,
    const p2p_private_key_cancel_v4_t *cancel, uint8_t output[32]) {
    endpoint_t *endpoint = context;
    uint64_t started = salts_monotonic_ms();
    uint8_t zero[32] = {0};
    atomic_fetch_add(&endpoint->calls, 1);
    while (!atomic_load(&endpoint->released) ||
           salts_monotonic_ms() - started < (uint64_t)endpoint->delay_ms) {
        if (cancel->is_cancelled(cancel->context)) return P2P_ERR_INVALID_STATE;
        if (salts_monotonic_ms() >= deadline) return P2P_ERR_TIMEOUT;
        salts_sleep_ms(1);
    }
    crypto_x25519(output, endpoint->secret, remote);
    return crypto_verify32(output, zero) ? P2P_OK : P2P_ERR_CRYPTO;
}
static void init_node(endpoint_t *endpoint, int number, int blocking) {
    p2p_node_t *node = endpoint->node = calloc(1, sizeof(*node));
    p2p_blocking_private_key_provider_v4_t provider = {0};
    check_not_null(node);
    salts_mutex_init(&node->mutex);
    node->user_data = endpoint;
    endpoint->blocking = blocking;
    atomic_init(&endpoint->calls, 0);
    atomic_init(&endpoint->released, 1);
    endpoint->secret[0] = (uint8_t)number;
    crypto_x25519_public_key(endpoint->public_key, endpoint->secret);
    if (blocking) {
        provider.struct_size = sizeof(provider);
        provider.get_public_key = public_key;
        provider.calculate_x25519 = calculate;
        provider.context = endpoint;
        provider.executor_workers = 1;
        provider.executor_capacity = 4;
        provider.operation_timeout_ms = TEST_WAIT_MS;
        check_equal(P2P_OK, p2p_crypto_identity_from_blocking_provider(
            &node->crypto.identity, &provider, endpoint->public_key));
        node->private_key_executor = p2p_private_key_executor_create_with_notify(node, &provider, NULL);
        check_not_null(node->private_key_executor);
    } else check_equal(P2P_OK, p2p_crypto_identity_from_secret(&node->crypto.identity, endpoint->secret));
    memcpy(node->local_credential, endpoint->public_key, 32);
    node->local_credential_len = 32;
    memset(&node->local_authenticated_identity, number, sizeof(node->local_authenticated_identity));
    endpoint->expected_identity = node->local_authenticated_identity;
    node->security_configured = 1;
    node->security_config.handshake_timeout_ms = TEST_WAIT_MS;
    node->security_config.ready_timeout_ms = TEST_WAIT_MS;
    node->security_config.handshake_frame_limit = P2P_SECURITY_HANDSHAKE_FRAME_MAX;
    node->security_config.credential_limit = P2P_SECURITY_CREDENTIAL_MAX;
    node->security_config.send_hwm_bytes = TEST_SEND_BYTES;
    node->security_config.node_send_budget_bytes = TEST_SEND_BYTES * 4;
    node->security_config.session_max_age_ms = 60000;
    node->security_config.session_max_bytes_per_direction = TEST_SEND_BYTES;
    node->security_config.identity_provider.verify_remote_credential = verify;
    node->security_config.identity_provider.context = endpoint;
    memset(node->security_config.network_id_hash, 9, 32);
    strcpy(node->ip, "127.0.0.1");
    node->security_config.cookie_gate_limit = 16;
    node->security_config.cookie_lifetime_ms = TEST_WAIT_MS;
    node->security_config.cookie_key_rotation_ms = TEST_WAIT_MS * 2;
    node->security_config.source_admission_burst = 16;
    node->security_config.source_admission_refill_per_second = 1;
    node->security_config.source_admission_bucket_limit = 16;
    memset(node->cookie_master_secret, number, 32);
    memcpy(node->id, node->local_authenticated_identity.routing_id, sizeof(node->id));
    vivaldi_init(&node->coord);
    node->kad_dht = kademlia_create(node->ip, 0);
    check_not_null(node->kad_dht);
    memcpy(node->kad_dht->routing->local_id.bytes, node->id, sizeof(node->id));
}
static p2p_cnet_config_t config(size_t receive_bytes) {
    p2p_cnet_config_t value = {0};
#ifdef _WIN32
    value.client.backend = NATIVE_IO_BACKEND_IOCP;
#elif defined(__linux__)
    value.client.backend = NATIVE_IO_BACKEND_EPOLL;
#else
    value.client.backend = NATIVE_IO_BACKEND_KQUEUE;
#endif
    value.client.connection_capacity = 16;
    value.client.command_capacity = 32;
    value.client.request_capacity = 32;
    value.client.completion_batch_capacity = 8;
    value.client.event_capacity = 32;
    value.client.max_send_bytes = TEST_SEND_BYTES;
    value.client.receive_buffer_bytes = receive_bytes;
    value.client.connect_timeout_ms = TEST_WAIT_MS;
    value.client.write_timeout_ms = TEST_WAIT_MS;
    value.send_hwm_bytes = TEST_SEND_BYTES;
    value.pending_write_limit = 8;
    value.accept_budget = 2;
    value.stop_timeout_ms = TEST_WAIT_MS;
    return value;
}

static void on_connected(p2p_peer_t *peer, void *context) {
    endpoint_t *endpoint = context;
    endpoint->authenticated++;
    endpoint->peer = peer;
    check_true(peer->counted);
    check_true(peer->is_connected);
    if (endpoint->stop_on_auth) {
        check_equal(P2P_ERR_INVALID_STATE, p2p_node_cnet_destroy(endpoint->owner));
        check_equal(P2P_OK, p2p_node_cnet_stop(endpoint->owner));
        endpoint->stopped = 1;
    }
}
static void on_disconnected(p2p_peer_t *peer, void *context) {
    endpoint_t *endpoint = context;
    endpoint->disconnected++;
    if (endpoint->peer == peer) endpoint->peer = NULL;
    check_true(!peer->counted);
}
static void on_message(p2p_node_t *node, p2p_peer_t *peer,
    const void *bytes, size_t length, void *context) {
    endpoint_t *endpoint = context;
    check_true(node == endpoint->node);
    check_true(peer->counted && peer->is_connected);
    check_true(length <= sizeof(endpoint->received));
    memcpy(endpoint->received, bytes, length);
    endpoint->received_len = length;
    endpoint->messages++;
}
static void init_endpoint(endpoint_t *endpoint, int number, size_t receive_bytes, int blocking) {
    p2p_cnet_config_t transport = config(receive_bytes);
    init_node(endpoint, number, blocking);
    endpoint->node->on_peer_connected = on_connected;
    endpoint->node->on_peer_disconnected = on_disconnected;
    endpoint->node->peer_user_data = endpoint;
    endpoint->node->on_message = on_message;
    check_equal(P2P_OK, p2p_node_cnet_create(endpoint->node, &transport, &endpoint->owner));
    check_equal(P2P_OK, p2p_node_cnet_listen(endpoint->owner));
    check_true(endpoint->node->port > 0);
}
static void setup(pair_t *pair, size_t receive_bytes, int blocking) {
    pair->client.remote = &pair->server;
    pair->server.remote = &pair->client;
    init_endpoint(&pair->client, 17, receive_bytes, blocking);
    init_endpoint(&pair->server, 33, receive_bytes, blocking);
}
static void connect_pair(pair_t *pair) {
    check_equal(P2P_OK, p2p_connect(pair->client.node, pair->server.node->ip, pair->server.node->port));
}
static void pump(pair_t *pair) {
    if (!pair->client.stopped) check_equal(P2P_OK, p2p_node_cnet_poll(pair->client.owner));
    if (!pair->server.stopped) check_equal(P2P_OK, p2p_node_cnet_poll(pair->server.owner));
    salts_sleep_ms(1);
}
static void wait_ready(pair_t *pair) {
    uint64_t deadline = salts_monotonic_ms() + TEST_WAIT_MS;
    while ((!pair->client.authenticated || !pair->server.authenticated) &&
        salts_monotonic_ms() < deadline) pump(pair);
    check_equal(1, pair->client.authenticated);
    check_equal(1, pair->server.authenticated);
}
static void teardown(pair_t *pair) {
    for (int i = 0; i < 2; ++i) {
        endpoint_t *endpoint = i ? &pair->server : &pair->client;
        check_equal(P2P_OK, p2p_node_cnet_destroy(endpoint->owner));
        check_true(endpoint->node->network_ops == NULL);
        check_true(endpoint->node->peers_table == NULL);
        check_true(endpoint->node->dht_lookups == NULL);
        check_equal(0, endpoint->node->peer_count);
        check_equal((size_t)0, endpoint->node->reserved_send_capacity_bytes);
        check_equal((size_t)0, endpoint->node->transport_send_reservations);
        p2p_private_key_executor_destroy(endpoint->node->private_key_executor);
        kademlia_destroy(endpoint->node->kad_dht);
        salts_mutex_destroy(&endpoint->node->mutex);
        p2p_crypto_wipe(endpoint->node, sizeof(*endpoint->node));
        free(endpoint->node);
    }
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
    deadline = salts_monotonic_ms() + TEST_WAIT_MS;
    while ((!has_route(&pair.client, &pair.server) || !has_route(&pair.server, &pair.client)) &&
        salts_monotonic_ms() < deadline) pump(&pair);
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
    while ((!pair.client.messages || !pair.server.messages) && salts_monotonic_ms() < deadline) pump(&pair);
    check_equal(1, pair.client.messages);
    check_equal(1, pair.server.messages);
    check_equal(pair.client.received, "server", 6);
    check_equal(pair.server.received, "client", 6);
    p2p_dht_lookup_t *lookup = p2p_dht_lookup_start(pair.client.node, pair.server.node->id, P2P_MSG_DHT_FIND_NODE);
    check_not_null(lookup);
    lookup->callback = lookup_done;
    lookup->cleanup = lookup_cleaned;
    lookup->user_data = &pair.client;
    while (!pair.client.lookup_done && salts_monotonic_ms() < deadline) pump(&pair);
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
    deadline = salts_monotonic_ms() + TEST_WAIT_MS;
    while (!pair.server.stopped && salts_monotonic_ms() < deadline) pump(&pair);
    check_true(pair.server.stopped);
    check_equal(0, pair.server.node->peer_count);
    check_true(pair.server.node->peers_table == NULL);
    check_equal(P2P_ERR_INVALID_STATE, p2p_connect(pair.server.node, "127.0.0.1", pair.client.node->port));
    teardown(&pair);
}
static void test_stop_worker(void) {
    pair_t pair = {0};
    uint64_t deadline;
    setup(&pair, 7, 1);
    atomic_store(&pair.server.released, 0);
    connect_pair(&pair);
    deadline = salts_monotonic_ms() + TEST_WAIT_MS;
    while (!atomic_load(&pair.server.calls) && salts_monotonic_ms() < deadline) pump(&pair);
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
    pair.client.peer->last_seen = (salts_monotonic_ms() - P2P_PEER_TIMEOUT_MS - 1) * 1000000U;
    p2p_node_maintain_peers(pair.client.node, salts_monotonic_ms());
    check_equal(P2P_OK, p2p_node_cnet_poll(pair.client.owner));
    check_equal(1, pair.client.disconnected);
    check_equal(0, pair.client.node->peer_count);
    check_equal((size_t)0, pair.client.node->reserved_send_capacity_bytes);
    check_equal(P2P_OK, p2p_node_cnet_poll(pair.client.owner));
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
    peer->security_deadline_ms = salts_monotonic_ms();
    check_equal(P2P_OK, p2p_node_cnet_poll(pair.client.owner));
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
    deadline = salts_monotonic_ms() + TEST_WAIT_MS;
    do {
        pump(&pair);
        check_equal(P2P_OK, p2p_node_cnet_admission_stats(pair.server.owner, &stats));
    } while (!stats.rejected && salts_monotonic_ms() < deadline);
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
    deadline = salts_monotonic_ms() + TEST_WAIT_MS;
    do {
        pump(&pair);
        check_equal(P2P_OK, p2p_node_cnet_admission_stats(pair.server.owner, &stats));
    } while (!stats.active && salts_monotonic_ms() < deadline);
    check_equal((size_t)1, stats.active);
    for (int i = 0; i < P2P_PENDING_PEER_SOURCE_LIMIT - 1; ++i) {
        p2p_peer_t *peer = p2p_peer_create(pair.server.node, "127.0.0.1", 20000 + i);
        check_not_null(peer);
        peer->state = P2P_PEER_STATE_HANDSHAKING;
        p2p_node_add_peer_locked(pair.server.node, peer);
    }
    salts_mutex_lock(&pair.server.node->mutex);
    check_equal(P2P_OK, pair.server.node->network_ops->pending_gates(pair.server.node,
        "127.0.0.1", &total, &source, pair.server.node->network_context));
    check_equal((size_t)1, total);
    check_equal((size_t)1, source);
    check_true(!p2p_node_pending_peer_source_capacity_available_locked(pair.server.node, "127.0.0.1"));
    check_true(p2p_node_pending_peer_source_capacity_available_locked(pair.server.node, "127.0.0.2"));
    salts_mutex_unlock(&pair.server.node->mutex);
    check_equal(P2P_ERR_RESOURCE_EXHAUSTED, p2p_connect(pair.server.node, "127.0.0.1", pair.client.node->port));
    teardown(&pair);
}
static void test_reject_identity(void) {
    pair_t pair = {0};
    uint64_t deadline;
    setup(&pair, 7, 1);
    pair.server.reject_credential = 1;
    connect_pair(&pair);
    deadline = salts_monotonic_ms() + TEST_WAIT_MS;
    while (!pair.server.disconnected && salts_monotonic_ms() < deadline) pump(&pair);
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
    deadline = salts_monotonic_ms() + TEST_WAIT_MS;
    while ((!pair.client.authenticated || !pair.server.authenticated ||
            pair.client.node->transport_send_reservations != 1 ||
            pair.server.node->transport_send_reservations != 1) &&
        salts_monotonic_ms() < deadline) pump(&pair);
    check_equal(1, pair.client.node->peer_count);
    check_equal(1, pair.server.node->peer_count);
    check_equal((size_t)1, pair.client.node->transport_send_reservations);
    check_equal((size_t)1, pair.server.node->transport_send_reservations);
    check_equal(P2P_CONN_OUTBOUND, pair.client.peer->conn->type);
    check_equal(P2P_CONN_INBOUND, pair.server.peer->conn->type);
    check_equal(P2P_OK, p2p_send_message(pair.server.node, pair.server.peer, P2P_MSG_CUSTOM, "winner", 6));
    while (!pair.client.messages && salts_monotonic_ms() < deadline) pump(&pair);
    check_equal(1, pair.client.messages);
    teardown(&pair);
}
static void test_direct_disconnect(void) {
    pair_t pair = {0};
    setup(&pair, TEST_SEND_BYTES, 0);
    connect_pair(&pair);
    wait_ready(&pair);
    p2p_peer_disconnect(pair.server.peer);
    check_equal(P2P_OK, p2p_node_cnet_poll(pair.server.owner));
    check_equal(1, pair.server.disconnected);
    check_equal(0, pair.server.node->peer_count);
    check_true(pair.server.node->peers_table == NULL);
    check_equal(P2P_OK, p2p_node_cnet_poll(pair.server.owner));
    check_equal(1, pair.server.disconnected);
    teardown(&pair);
}
#ifdef P2P_NODE_TEST_WRAP
static int timeout_stop;
int __real_cnet_client_stop(cnet_client *, uint32_t);
int __wrap_cnet_client_stop(cnet_client *client, uint32_t timeout_ms) {
    if (timeout_stop) { timeout_stop = 0; return SALTS_ETIMEDOUT; }
    return __real_cnet_client_stop(client, timeout_ms);
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
    check_equal(P2P_ERR_INVALID_STATE, p2p_node_cnet_poll(pair.client.owner));
    teardown(&pair);
}
#endif
spec("P2P production node network over CNet") {
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
    it("retains node and owner after a drain timeout until retry succeeds") { test_stop_timeout(); }
#endif
}
