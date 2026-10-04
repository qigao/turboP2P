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
#define TEST_SEND_BYTES 8192
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

/* Only credential configuration/provider callbacks are fixtures. Node state,
 * transfer manager, networking and all protocol handlers are production. */
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
    p2p_node_t *node = endpoint->node = p2p_node_state_create("127.0.0.1", 0);
    p2p_blocking_private_key_provider_v4_t provider = {0};
    check_not_null(node);
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
        check_equal(P2P_OK, p2p_node_state_destroy(endpoint->node));
    }
}

#endif
