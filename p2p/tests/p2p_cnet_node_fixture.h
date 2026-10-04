#ifndef P2P_CNET_NODE_FIXTURE_H
#define P2P_CNET_NODE_FIXTURE_H
#include <tinytest.h>
#include "core/peer_cnet.h"
#include "core/node_cnet.h"
#include "core/node_state.h"
#include "transfer/transfer.h"
#include "security/p2p_cnet_admission.h"
#include "security/p2p_private_key_executor.h"
#include <monocypher.h>
#include <salts/clock.h>
#include <salts/thread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

enum { TEST_WAIT_MS = 3000 };
#ifndef TEST_SEND_BYTES
#define TEST_SEND_BYTES (128 * 1024)
#endif
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

/* Only credential/key provider callbacks are fixtures. State construction,
 * security configuration, transfer and network handlers are production. */
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
static int build_credential(void *context, const uint8_t local_key[32],
    uint8_t *output, size_t capacity, size_t *length,
    p2p_authenticated_identity_v2_t *identity) {
    endpoint_t *endpoint = context;
    if (capacity < 32) return P2P_ERR_RESOURCE_EXHAUSTED;
    memcpy(output, local_key, 32);
    *length = 32;
    *identity = endpoint->expected_identity;
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
static void init_key_node(endpoint_t *endpoint, int number, int blocking) {
    p2p_node_t *node = endpoint->node = p2p_node_state_create("127.0.0.1", 0);
    p2p_blocking_private_key_provider_v4_t provider = {0};
    check_not_null(node);
    node->user_data = endpoint;
    endpoint->blocking = blocking;
    atomic_init(&endpoint->calls, 0);
    atomic_init(&endpoint->released, 1);
    endpoint->secret[0] = (uint8_t)number;
    crypto_x25519_public_key(endpoint->public_key, endpoint->secret);
    memset(&endpoint->expected_identity, number, sizeof(endpoint->expected_identity));
    if (blocking) {
        provider.struct_size = sizeof(provider);
        provider.get_public_key = public_key;
        provider.calculate_x25519 = calculate;
        provider.context = endpoint;
        provider.executor_workers = 1;
        provider.executor_capacity = 4;
        provider.operation_timeout_ms = TEST_WAIT_MS;
        check_equal(P2P_OK, p2p_node_set_blocking_private_key_provider_v4(node, &provider));
        /* Configuration's synchronous ownership self-test is not handshake work. */
        check_equal(1, atomic_load(&endpoint->calls));
        atomic_store(&endpoint->calls, 0);
    } else check_equal(P2P_OK, p2p_node_set_private_key(node, endpoint->secret));

}
static void init_node(endpoint_t *endpoint, int number, int blocking) {
    p2p_security_config_v2_t security = {0};
    init_key_node(endpoint, number, blocking);
    p2p_node_t *node = endpoint->node;
    security.struct_size = sizeof(security);
    security.handshake_timeout_ms = TEST_WAIT_MS;
    security.ready_timeout_ms = TEST_WAIT_MS;
    security.send_hwm_bytes = TEST_SEND_BYTES;
    security.node_send_budget_bytes = TEST_SEND_BYTES * 4;
    security.session_max_age_ms = 60000;
    security.session_max_bytes_per_direction = TEST_SEND_BYTES;
    security.identity_provider.build_local_credential = build_credential;
    security.identity_provider.verify_remote_credential = verify;
    security.identity_provider.context = endpoint;
    memset(security.network_id_hash, 9, 32);
    security.cookie_gate_limit = 16;
    security.cookie_lifetime_ms = TEST_WAIT_MS;
    security.cookie_key_rotation_ms = TEST_WAIT_MS * 2;
    security.source_admission_burst = 16;
    security.source_admission_refill_per_second = 1;
    security.source_admission_bucket_limit = 16;
    check_equal(P2P_OK, p2p_node_configure_security_v2(node, &security));
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
    check_equal(P2P_ERR_INVALID_STATE, p2p_poll(endpoint->node));
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
static void start_endpoint(endpoint_t *endpoint, size_t receive_bytes) {
    p2p_cnet_config_t transport = config(receive_bytes);
    p2p_set_peer_callbacks(endpoint->node, on_connected, on_disconnected, endpoint);
    p2p_set_message_handler(endpoint->node, on_message, endpoint);
    check_equal(P2P_OK, p2p_node_cnet_create(endpoint->node, &transport, &endpoint->owner));
    check_equal(P2P_OK, p2p_node_cnet_listen(endpoint->owner));
    check_true(endpoint->node->port > 0);
}
static void init_endpoint(endpoint_t *endpoint, int number, size_t receive_bytes, int blocking) {
    init_node(endpoint, number, blocking);
    start_endpoint(endpoint, receive_bytes);
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
    if (!pair->client.stopped) check_equal(P2P_OK, p2p_poll(pair->client.node));
    if (!pair->server.stopped) check_equal(P2P_OK, p2p_poll(pair->server.node));
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
        check_equal(P2P_ERR_INVALID_STATE, p2p_poll(endpoint->node));
        check_true(endpoint->node->network_ops == NULL);
        check_true(endpoint->node->peers_table == NULL);
        check_true(endpoint->node->dht_lookups == NULL);
        check_equal(0, endpoint->node->peer_count);
        check_equal((size_t)0, endpoint->node->reserved_send_capacity_bytes);
        check_equal((size_t)0, endpoint->node->transport_send_reservations);
        check_equal(P2P_OK, p2p_node_state_destroy(endpoint->node));
    }
}

#endif
