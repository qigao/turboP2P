#include <tinytest.h>
#include "core/peer_cnet.h"
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
    p2p_cnet_owner_t *owner;
    p2p_cnet_admission_t *admission;
    endpoint_t *remote;
    p2p_authenticated_identity_v2_t expected_identity;
    uint8_t secret[32], public_key[32];
    atomic_int calls, released;
    int blocking, delay_ms, reject_credential, authenticated, disconnected;
    int failures, last_error, messages, destroy_on_auth;
    uint8_t received[64];
    size_t received_len;
};
typedef struct { endpoint_t client, server; } pair_t;

/* Node policy and event doubles only. The actual peer, codec, executor,
 * cookie gate, Noise implementation and CNet owner are linked unmodified. */
void p2p_endpoint_to_key(char *out, size_t capacity, const char *ip, int port) {
    snprintf(out, capacity, "%s:%d", ip, port);
}
int p2p_node_reserve_transport_send_capacity(p2p_node_t *node, p2p_peer_t *peer) {
    if (!node->security_configured) return P2P_ERR_AUTH_REQUIRED;
    if (!peer->reserved_send_capacity_bytes) {
        peer->reserved_send_capacity_bytes = node->security_config.send_hwm_bytes;
        node->reserved_send_capacity_bytes += peer->reserved_send_capacity_bytes;
        node->transport_send_reservations++;
    }
    return P2P_OK;
}
void p2p_node_release_transport_send_capacity(p2p_node_t *node, p2p_peer_t *peer) {
    if (!peer->reserved_send_capacity_bytes) return;
    check_true(node->reserved_send_capacity_bytes >= peer->reserved_send_capacity_bytes);
    check_true(node->transport_send_reservations > 0);
    node->reserved_send_capacity_bytes -= peer->reserved_send_capacity_bytes;
    node->transport_send_reservations--;
    peer->reserved_send_capacity_bytes = 0;
}
void p2p_node_record_security_failure(p2p_node_t *node, uint8_t stage, int status) {
    endpoint_t *endpoint = node->user_data;
    (void)stage;
    endpoint->failures++;
    endpoint->last_error = status;
}
void p2p_node_record_handshake_latency(p2p_node_t *node, p2p_security_role_t role,
    p2p_security_latency_stage_t stage, uint64_t started, uint64_t completed) {
    (void)node; (void)role; (void)stage;
    check_true(completed >= started);
}
void p2p_node_on_peer_connected(p2p_node_t *node, p2p_peer_t *peer) {
    int result = p2p_peer_start_handshake(peer);
    if (result != P2P_OK) {
        p2p_node_record_security_failure(node, peer->security_stage, result);
        p2p_peer_disconnect(peer);
    }
}
void p2p_node_on_peer_disconnected(p2p_node_t *node, p2p_peer_t *peer) {
    endpoint_t *endpoint = node->user_data;
    check_true(peer == endpoint->peer);
    endpoint->disconnected++;
}
void p2p_node_on_peer_authenticated(p2p_node_t *node, p2p_peer_t *peer) {
    endpoint_t *endpoint = node->user_data;
    check_true(peer->ready_sent && peer->ready_received);
    check_equal(P2P_SECURITY_STAGE_ESTABLISHED, peer->security_stage);
    endpoint->authenticated++;
    peer->state = P2P_PEER_STATE_CONNECTED;
    peer->is_connected = 1;
    if (endpoint->destroy_on_auth) {
        p2p_peer_destroy(peer);
        endpoint->peer = NULL;
    }
}
void p2p_node_dispatch_message(p2p_node_t *node, p2p_peer_t *peer, p2p_message_t *message) {
    endpoint_t *endpoint = node->user_data;
    check_true(peer == endpoint->peer);
    check_equal(P2P_MSG_CUSTOM, message->header.type);
    check_true(message->header.payload_len <= sizeof(endpoint->received));
    endpoint->messages++;
    endpoint->received_len = message->header.payload_len;
    memcpy(endpoint->received, message->payload.raw, endpoint->received_len);
}

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
        cmeta_sleep_ms(1);
    }
    crypto_x25519(output, endpoint->secret, remote);
    return crypto_verify32(output, zero) ? P2P_OK : P2P_ERR_CRYPTO;
}
static void init_node(endpoint_t *endpoint, int number, int blocking) {
    p2p_node_t *node = endpoint->node = calloc(1, sizeof(*node));
    p2p_blocking_private_key_provider_v4_t provider = {0};
    check_not_null(node);
    cmeta_mutex_init(&node->mutex);
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
    node->security_config.node_send_budget_bytes = TEST_SEND_BYTES;
    node->security_config.session_max_age_ms = 60000;
    node->security_config.session_max_bytes_per_direction = TEST_SEND_BYTES;
    node->security_config.identity_provider.verify_remote_credential = verify;
    node->security_config.identity_provider.context = endpoint;
    memset(node->security_config.network_id_hash, 9, 32);
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
    value.client.connection_capacity = 4;
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
static int admit(const cnet_stream_peer *source, void *context) {
    endpoint_t *endpoint = context;
    check_true(source->port != 0);
    return endpoint->peer ? P2P_ERR_RESOURCE_EXHAUSTED : P2P_OK;
}
static int promote(const cnet_stream_peer *source, const uint8_t preface[44],
    const uint8_t binding[40], p2p_cnet_callbacks_t *output, void *context) {
    endpoint_t *endpoint = context;
    check_true(endpoint->peer == NULL);
    endpoint->peer = p2p_peer_create(endpoint->node, "127.0.0.1", source->port);
    check_not_null(endpoint->peer);
    endpoint->peer->keep_entry = 1;
    return p2p_peer_prepare_cnet_inbound(endpoint->peer, preface, binding, output);
}
static void setup(pair_t *pair, size_t receive_bytes, int blocking) {
    p2p_cnet_config_t transport = config(receive_bytes);
    p2p_cnet_admission_config_t policy = {0};
    p2p_cnet_admission_callbacks_t events = {admit, promote, NULL, &pair->server, NULL};
    cnet_stream_peer remote;
    pair->client.remote = &pair->server;
    pair->server.remote = &pair->client;
    init_node(&pair->client, 17, blocking);
    init_node(&pair->server, 33, blocking);
    check_equal(P2P_OK, p2p_cnet_owner_create(&transport, &pair->client.owner));
    check_equal(P2P_OK, p2p_cnet_owner_create(&transport, &pair->server.owner));
    policy.gate_limit = policy.source_limit = 2;
    policy.peer_send_hwm_bytes = TEST_SEND_BYTES;
    policy.handshake_timeout_ms = TEST_WAIT_MS;
    policy.cookie_lifetime_ms = TEST_WAIT_MS;
    policy.cookie_key_rotation_ms = TEST_WAIT_MS * 2;
    memset(policy.network_id_hash, 9, 32);
    memset(policy.cookie_master_secret, 7, 32);
    check_equal(P2P_OK, p2p_cnet_admission_create(pair->server.owner, &policy, &events, &pair->server.admission));
    check_equal(P2P_OK, p2p_cnet_owner_listen(pair->server.owner, "127.0.0.1", 0, 4,
        p2p_cnet_admission_accept, pair->server.admission, &remote));
    pair->client.peer = p2p_peer_create(pair->client.node, "127.0.0.1", remote.port);
    check_not_null(pair->client.peer);
    pair->client.peer->keep_entry = 1;
    check_equal(P2P_OK, p2p_peer_connect_cnet(pair->client.peer, pair->client.owner));
}
static void pump(pair_t *pair) {
    p2p_private_key_executor_pump(pair->client.node);
    p2p_private_key_executor_pump(pair->server.node);
    check_equal(P2P_OK, p2p_cnet_owner_poll(pair->client.owner));
    check_equal(P2P_OK, p2p_cnet_owner_poll(pair->server.owner));
    check_equal(P2P_OK, p2p_cnet_admission_expire(pair->server.admission, salts_monotonic_ms()));
    cmeta_sleep_ms(1);
}
static void wait_ready(pair_t *pair) {
    uint64_t deadline = salts_monotonic_ms() + TEST_WAIT_MS;
    while ((!pair->client.authenticated || !pair->server.authenticated) &&
           !pair->client.failures && !pair->server.failures && salts_monotonic_ms() < deadline) pump(pair);
    check_equal(1, pair->client.authenticated);
    check_equal(1, pair->server.authenticated);
    check_equal(0, pair->client.failures);
    check_equal(0, pair->server.failures);
}
static void teardown(pair_t *pair) {
    check_equal(P2P_OK, p2p_cnet_admission_stop(pair->server.admission));
    for (int i = 0; i < 2; ++i) {
        endpoint_t *endpoint = i ? &pair->server : &pair->client;
        if (endpoint->peer) p2p_peer_destroy(endpoint->peer);
        endpoint->peer = NULL;
        p2p_private_key_executor_destroy(endpoint->node->private_key_executor);
        endpoint->node->private_key_executor = NULL;
        check_equal(P2P_OK, p2p_cnet_owner_destroy(endpoint->owner));
        check_equal((size_t)0, endpoint->node->transport_send_reservations);
        check_equal((size_t)0, endpoint->node->reserved_send_capacity_bytes);
        cmeta_mutex_destroy(&endpoint->node->mutex);
        p2p_crypto_wipe(&endpoint->node->crypto, sizeof(endpoint->node->crypto));
        free(endpoint->node);
    }
    check_equal(P2P_OK, p2p_cnet_admission_destroy(pair->server.admission));
}
static void send_message(endpoint_t *endpoint) {
    p2p_message_t *message = calloc(1, sizeof(*message));
    check_not_null(message);
    p2p_message_init(message, P2P_MSG_CUSTOM);
    memcpy(message->payload.raw, "authenticated payload", 21);
    message->header.payload_len = 21;
    check_equal(P2P_OK, p2p_peer_send(endpoint->peer, message));
    free(message);
}
static void test_roundtrip(size_t receive_bytes, int blocking) {
    pair_t pair = {0};
    uint64_t deadline;
    setup(&pair, receive_bytes, blocking);
    pair.client.delay_ms = pair.server.delay_ms = 20;
    wait_ready(&pair);
    check_equal(pair.client.peer->channel_binding, pair.server.peer->channel_binding, 32);
    check_equal(pair.client.expected_identity.principal_id, pair.server.peer->authenticated_identity.principal_id, 32);
    if (blocking) {
        p2p_private_key_executor_status_v4_t status;
        check_true(atomic_load(&pair.client.calls) > 0 && atomic_load(&pair.server.calls) > 0);
        check_equal(P2P_OK, p2p_key_worker_status(pair.client.node->private_key_executor->worker, &status));
        check_equal((uint64_t)1, status.completed);
        check_equal((size_t)0, status.active_operations);
    }
    send_message(&pair.client);
    send_message(&pair.server);
    deadline = salts_monotonic_ms() + TEST_WAIT_MS;
    while ((!pair.client.messages || !pair.server.messages) && salts_monotonic_ms() < deadline) pump(&pair);
    check_equal(1, pair.client.messages);
    check_equal(1, pair.server.messages);
    check_equal("authenticated payload", pair.client.received, 21);
    check_equal("authenticated payload", pair.server.received, 21);
    teardown(&pair);
}
static void test_reject(int ready_mismatch) {
    pair_t pair = {0};
    uint64_t deadline;
    setup(&pair, TEST_SEND_BYTES, 0);
    if (ready_mismatch) pair.server.node->local_authenticated_identity.principal_id[0] ^= 1;
    else pair.client.reject_credential = 1;
    deadline = salts_monotonic_ms() + TEST_WAIT_MS;
    while (!pair.client.failures && salts_monotonic_ms() < deadline) pump(&pair);
    check_true(pair.client.failures > 0);
    check_equal(P2P_ERR_UNTRUSTED_IDENTITY, pair.client.last_error);
    check_equal(0, pair.client.authenticated);
    check_equal(0, pair.client.messages);
    teardown(&pair);
}
static void test_destroy_with_worker(void) {
    pair_t pair = {0};
    uint64_t deadline;
    setup(&pair, 7, 1);
    atomic_store(&pair.server.released, 0);
    deadline = salts_monotonic_ms() + TEST_WAIT_MS;
    while (!atomic_load(&pair.server.calls) && salts_monotonic_ms() < deadline) pump(&pair);
    check_true(pair.server.peer && pair.server.peer->private_key_operation);
    p2p_peer_destroy(pair.server.peer);
    pair.server.peer = NULL;
    p2p_private_key_executor_shutdown(pair.server.node->private_key_executor);
    check_equal(0, pair.server.authenticated);
    check_equal((size_t)0, pair.server.node->transport_send_reservations);
    teardown(&pair);
}
static void test_destroy_pending_preface(void) {
    pair_t pair = {0};
    uint64_t deadline;
    setup(&pair, 7, 0);
    deadline = salts_monotonic_ms() + TEST_WAIT_MS;
    while (!pair.client.peer->security_send_action && salts_monotonic_ms() < deadline) {
        check_equal(P2P_OK, p2p_cnet_owner_poll(pair.client.owner));
    }
    check_true(pair.client.peer->security_send_action != 0);
    p2p_peer_destroy(pair.client.peer);
    pair.client.peer = NULL;
    for (int i = 0; i < 4; ++i) pump(&pair);
    check_equal(0, pair.client.authenticated);
    teardown(&pair);
}
static void test_destroy_on_auth(void) {
    pair_t pair = {0};
    uint64_t deadline;
    setup(&pair, TEST_SEND_BYTES, 0);
    pair.client.destroy_on_auth = 1;
    deadline = salts_monotonic_ms() + TEST_WAIT_MS;
    while (!pair.client.authenticated && salts_monotonic_ms() < deadline) pump(&pair);
    check_equal(1, pair.client.authenticated);
    check_true(pair.client.peer == NULL);
    teardown(&pair);
}
/* Delay just the peer continuation after a real native READY send. The pause
 * injection models already-in-flight input so the actual peer buffer, not a
 * test protocol driver, must retain and drain the coalesced tail. */
static struct {
    p2p_peer_t *peer;
    p2p_conn_ops_t original;
    p2p_send_complete_fn complete;
    void *context;
    int native_done, native_status, inflight, reject;
} terminal;

static void captured_terminal(void *context, int status) {
    (void)context;
    terminal.native_done++;
    terminal.native_status = status;
}
static int delayed_send(void *handle, const void *data, size_t length,
    p2p_send_complete_fn complete, void *context) {
    if (terminal.reject) return P2P_ERR_RESOURCE_EXHAUSTED;
    if (terminal.peer->security_stage == P2P_SECURITY_STAGE_READY) {
        check_true(terminal.complete == NULL);
        terminal.complete = complete;
        terminal.context = context;
        return terminal.original.send_completed(handle, data, length, captured_terminal, NULL);
    }
    return terminal.original.send_completed(handle, data, length, complete, context);
}
static int inflight_pause(void *handle, int paused) {
    if (terminal.inflight && terminal.peer->security_stage == P2P_SECURITY_STAGE_READY)
        return terminal.original.pause(handle, 0);
    return terminal.original.pause(handle, paused);
}
static void intercept(endpoint_t *endpoint, int inflight) {
    memset(&terminal, 0, sizeof(terminal));
    terminal.peer = endpoint->peer;
    terminal.original = endpoint->peer->conn->ops;
    terminal.inflight = inflight;
    endpoint->peer->conn->ops.send_completed = delayed_send;
    endpoint->peer->conn->ops.pause = inflight_pause;
}
static void test_delayed_ready(int late, int inflight) {
    pair_t pair = {0};
    uint64_t deadline;
    setup(&pair, TEST_SEND_BYTES, 0);
    intercept(&pair.client, inflight);
    deadline = salts_monotonic_ms() + TEST_WAIT_MS;
    while ((!terminal.native_done || !pair.server.authenticated) &&
           salts_monotonic_ms() < deadline) pump(&pair);
    check_equal(1, terminal.native_done);
    check_equal(P2P_OK, terminal.native_status);
    check_equal(1, pair.server.authenticated);
    check_equal(0, pair.client.authenticated);
    check_equal(0, pair.client.peer->ready_sent);
    send_message(&pair.server);
    for (int i = 0; i < 4; ++i) pump(&pair);
    check_equal(0, pair.client.messages);
    if (inflight) check_true(pair.client.peer->recv_len > 0);
    if (late) pair.client.peer->security_deadline_ms = salts_monotonic_ms();
    terminal.complete(terminal.context, P2P_OK);
    terminal.complete = NULL;
    if (late) {
        check_equal(P2P_ERR_TIMEOUT, pair.client.last_error);
        check_equal(1, pair.client.disconnected);
        check_equal(0, pair.client.authenticated);
        check_equal(0, pair.client.messages);
    } else {
        if (inflight) {
            /* No further receive event is needed to consume the buffered tail. */
            check_equal(1, pair.client.authenticated);
            check_equal(1, pair.client.messages);
        }
        deadline = salts_monotonic_ms() + TEST_WAIT_MS;
        while (!pair.client.messages && salts_monotonic_ms() < deadline) pump(&pair);
        check_equal(1, pair.client.authenticated);
        check_equal(1, pair.client.messages);
        check_equal("authenticated payload", pair.client.received, 21);
    }
    teardown(&pair);
}
static void test_preface_rejection(void) {
    pair_t pair = {0};
    uint64_t deadline;
    setup(&pair, 7, 0);
    intercept(&pair.client, 0);
    terminal.reject = 1;
    deadline = salts_monotonic_ms() + TEST_WAIT_MS;
    while (!pair.client.failures && salts_monotonic_ms() < deadline) pump(&pair);
    check_equal(P2P_ERR_RESOURCE_EXHAUSTED, pair.client.last_error);
    check_equal(0, terminal.native_done);
    check_equal(0, pair.client.peer->security_send_action);
    check_true(pair.client.peer->conn == NULL);
    check_equal(0, pair.client.authenticated);
    teardown(&pair);
}
static void test_close_pending_preface(void) {
    pair_t pair = {0};
    uint64_t deadline;
    setup(&pair, 7, 0);
    deadline = salts_monotonic_ms() + TEST_WAIT_MS;
    while (!pair.client.peer->security_send_action && salts_monotonic_ms() < deadline)
        check_equal(P2P_OK, p2p_cnet_owner_poll(pair.client.owner));
    check_true(pair.client.peer->security_send_action != 0);
    p2p_connection_close(pair.client.peer->conn);
    while (!pair.client.disconnected && salts_monotonic_ms() < deadline) pump(&pair);
    check_equal(1, pair.client.disconnected);
    check_equal(0, pair.client.authenticated);
    check_true(pair.client.peer->conn == NULL);
    teardown(&pair);
}

spec("P2P production peer over CNet") {
    it("authenticates actual peers and exchanges canonical encrypted messages") { test_roundtrip(TEST_SEND_BYTES, 0); }
    it("preserves the wire under seven-byte receive fragmentation") { test_roundtrip(7, 0); }
    it("runs both actual node executors and reaches READY after send completion") { test_roundtrip(7, 1); }
    it("rejects a credential through the actual peer verifier") { test_reject(0); }
    it("rejects READY identity mismatches before publishing authentication") { test_reject(1); }
    it("retains a destroyed peer until its private-key work is cancelled") { test_destroy_with_worker(); }
    it("detaches an admitted preface completion before freeing its peer") { test_destroy_pending_preface(); }
    it("waits for READY continuation before consuming retained CNet input") { test_delayed_ready(0, 0); }
    it("drains coalesced peer-buffered READY and application data without a new receive") { test_delayed_ready(0, 1); }
    it("rejects a successful READY terminal consumed after the handshake deadline") { test_delayed_ready(1, 1); }
    it("rolls back rejected preface admission without a completion") { test_preface_rejection(); }
    it("delivers one failure when close races an admitted preface") { test_close_pending_preface(); }
    it("permits destruction from the authentication callback") { test_destroy_on_auth(); }
}
