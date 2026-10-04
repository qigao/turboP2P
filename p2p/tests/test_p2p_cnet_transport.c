#include <tinytest.h>
#include "core/cnet_transport.h"
#include "crypto/p2p_crypto.h"
#include "security/p2p_cookie.h"
#include <salts/clock.h>
#include <salts/thread.h>
#include <stdlib.h>
#include <string.h>

enum { TEST_BUFFER_SIZE = 8192, TEST_DEADLINE_MS = 3000 };

typedef struct endpoint_s {
    p2p_cnet_owner_t *owner;
    p2p_connection_t *connection;
    unsigned connected, closed, sends, receives;
    size_t sent_bytes, received_bytes;
    uint8_t bytes[TEST_BUFFER_SIZE];
    int close_status;
    int pause_on_receive;
    int destroy_on_receive;
    int stop_on_receive;
    int reject_receive;
    int zero_consume;
    int recursive_poll;
    int recursive_destroy;
    size_t consume_limit;
    int reject_accept;
    int accepted;
} endpoint_t;

typedef struct {
    endpoint_t client, server;
    cnet_stream_peer remote;
} pair_t;

static p2p_cnet_config_t config(size_t receive_bytes) {
    p2p_cnet_config_t value = {0};
#ifdef _WIN32
    value.client.backend = NATIVE_IO_BACKEND_IOCP;
#elif defined(__linux__)
    value.client.backend = NATIVE_IO_BACKEND_EPOLL;
#else
    value.client.backend = NATIVE_IO_BACKEND_KQUEUE;
#endif
    value.client.connection_capacity = 8;
    value.client.command_capacity = 64;
    value.client.request_capacity = 64;
    value.client.completion_batch_capacity = 16;
    value.client.event_capacity = 64;
    value.client.max_send_bytes = TEST_BUFFER_SIZE;
    value.client.receive_buffer_bytes = receive_bytes;
    value.client.connect_timeout_ms = TEST_DEADLINE_MS;
    value.client.write_timeout_ms = TEST_DEADLINE_MS;
    value.send_hwm_bytes = TEST_BUFFER_SIZE;
    value.pending_write_limit = 16;
    value.accept_budget = 4;
    value.stop_timeout_ms = TEST_DEADLINE_MS;
    return value;
}

static int connected(p2p_connection_t *connection, void *context) {
    endpoint_t *endpoint = context;
    endpoint->connection = connection;
    endpoint->connected++;
    return P2P_OK;
}

static void closed(p2p_connection_t *connection, int status, void *context) {
    endpoint_t *endpoint = context;
    (void)connection;
    endpoint->closed++;
    endpoint->close_status = status;
}

static void sent(p2p_connection_t *connection, size_t length, void *context) {
    endpoint_t *endpoint = context;
    (void)connection;
    endpoint->sends++;
    endpoint->sent_bytes += length;
}

static int receive(p2p_connection_t *connection, const uint8_t *bytes,
                     size_t length, size_t *consumed, void *context) {
    endpoint_t *endpoint = context;
    size_t count = length;
    endpoint->receives++;
    if (endpoint->reject_receive) return P2P_ERR_CRYPTO;
    if (endpoint->zero_consume) return P2P_OK;
    if (endpoint->consume_limit && count > endpoint->consume_limit)
        count = endpoint->consume_limit;
    if (count > sizeof(endpoint->bytes) - endpoint->received_bytes)
        return P2P_ERR_RESOURCE_EXHAUSTED;
    memcpy(endpoint->bytes + endpoint->received_bytes, bytes, count);
    endpoint->received_bytes += count;
    *consumed = count;
    if (endpoint->pause_on_receive) {
        endpoint->pause_on_receive = 0;
        check_equal(P2P_OK, p2p_cnet_connection_pause(connection, 1));
    }
    if (endpoint->destroy_on_receive) {
        p2p_connection_destroy(connection);
        endpoint->connection = NULL;
    }
    if (endpoint->stop_on_receive) {
        endpoint->recursive_poll = p2p_cnet_owner_poll(endpoint->owner);
        endpoint->recursive_destroy = p2p_cnet_owner_destroy(endpoint->owner);
        check_equal(P2P_OK, p2p_cnet_owner_stop(endpoint->owner));
    }
    return P2P_OK;
}

static p2p_cnet_callbacks_t callbacks(endpoint_t *endpoint) {
    p2p_cnet_callbacks_t value = {connected, receive, sent, closed, endpoint};
    return value;
}

static int accept_connection(p2p_cnet_owner_t *owner, p2p_connection_t *connection,
                               const cnet_stream_peer *peer, void *context) {
    endpoint_t *endpoint = context;
    p2p_cnet_callbacks_t events = callbacks(endpoint);
    (void)owner;
    check_true(peer->port != 0);
    endpoint->accepted++;
    if (endpoint->reject_accept) return P2P_ERR_UNTRUSTED_IDENTITY;
    endpoint->connection = connection;
    return p2p_cnet_connection_handoff(connection, &events);
}

static int setup_pair(pair_t *pair, const p2p_cnet_config_t *policy) {
    p2p_cnet_callbacks_t events = callbacks(&pair->client);
    int result = p2p_cnet_owner_create(policy, &pair->server.owner);
    if (result != P2P_OK) return result;
    result = p2p_cnet_owner_create(policy, &pair->client.owner);
    if (result != P2P_OK) return result;
    result = p2p_cnet_owner_listen(pair->server.owner, "127.0.0.1", 0, 8,
        accept_connection, &pair->server, &pair->remote);
    if (result != P2P_OK) return result;
    return p2p_cnet_owner_connect(pair->client.owner, &pair->remote,
                                  &events, &pair->client.connection);
}

static void pump(pair_t *pair) {
    check_equal(P2P_OK, p2p_cnet_owner_poll(pair->client.owner));
    check_equal(P2P_OK, p2p_cnet_owner_poll(pair->server.owner));
    salts_sleep_ms(1);
}

static void wait_connected(pair_t *pair) {
    uint64_t deadline = salts_monotonic_ms() + TEST_DEADLINE_MS;
    while ((!pair->client.connected || !pair->server.connected) &&
           salts_monotonic_ms() < deadline) pump(pair);
    check_equal(1U, pair->client.connected);
    check_equal(1U, pair->server.connected);
}

static void destroy_pair(pair_t *pair) {
    check_equal(P2P_OK, p2p_cnet_owner_destroy(pair->client.owner));
    check_equal(P2P_OK, p2p_cnet_owner_destroy(pair->server.owner));
}

static void test_fifo_copy_and_hwm(void) {
    pair_t pair = {0};
    p2p_cnet_config_t policy = config(7);
    uint8_t bytes[20];
    uint8_t expected[60];
    uint64_t deadline;
    check_equal(P2P_OK, setup_pair(&pair, &policy));
    wait_connected(&pair);
    check_equal(P2P_OK, p2p_cnet_connection_set_send_hwm(pair.client.connection, 60));
    for (unsigned index = 0; index < 3; ++index) {
        memset(bytes, (int)index + 1, sizeof(bytes));
        memcpy(expected + index * sizeof(bytes), bytes, sizeof(bytes));
        check_equal(P2P_OK, p2p_connection_send(pair.client.connection, bytes, sizeof(bytes)));
        memset(bytes, 0xa5, sizeof(bytes));
    }
    check_equal((size_t)60, p2p_cnet_connection_pending_bytes(pair.client.connection));
    check_equal(P2P_ERR_RESOURCE_EXHAUSTED, p2p_connection_send(pair.client.connection, bytes, 1));
    check_equal(P2P_ERR_INVALID_STATE, p2p_cnet_connection_set_send_hwm(pair.client.connection, 59));
    check_equal(0U, pair.client.sends);
    deadline = salts_monotonic_ms() + TEST_DEADLINE_MS;
    while ((pair.server.received_bytes < sizeof(expected) || pair.client.sends != 3) &&
           salts_monotonic_ms() < deadline) pump(&pair);
    check_equal(sizeof(expected), pair.server.received_bytes);
    check_equal(expected, pair.server.bytes, sizeof(expected));
    check_equal(3U, pair.client.sends);
    check_equal((size_t)0, p2p_cnet_connection_pending_bytes(pair.client.connection));
    destroy_pair(&pair);
}

static void test_pause_preserves_tail(void) {
    pair_t pair = {0};
    p2p_cnet_config_t policy = config(4096);
    const uint8_t payload[] = "pause must preserve every byte";
    uint64_t deadline;
    check_equal(P2P_OK, setup_pair(&pair, &policy));
    wait_connected(&pair);
    pair.server.pause_on_receive = 1;
    pair.server.consume_limit = 3;
    check_equal(P2P_OK, p2p_connection_send(pair.client.connection, payload, sizeof(payload)));
    deadline = salts_monotonic_ms() + TEST_DEADLINE_MS;
    while (!pair.server.receives && salts_monotonic_ms() < deadline) pump(&pair);
    for (unsigned index = 0; index < 5; ++index) pump(&pair);
    check_equal((size_t)3, pair.server.received_bytes);
    pair.server.consume_limit = 0;
    check_equal(P2P_OK, p2p_cnet_connection_pause(pair.server.connection, 0));
    check_equal((size_t)3, pair.server.received_bytes);
    deadline = salts_monotonic_ms() + TEST_DEADLINE_MS;
    while (pair.server.received_bytes < sizeof(payload) && salts_monotonic_ms() < deadline) pump(&pair);
    check_equal(sizeof(payload), pair.server.received_bytes);
    check_equal(payload, pair.server.bytes, sizeof(payload));
    destroy_pair(&pair);
}

static void test_pause_with_admitted_receive(void) {
    pair_t pair = {0};
    p2p_cnet_config_t policy = config(4096);
    uint64_t deadline;
    const uint8_t payload[] = "already admitted";
    check_equal(P2P_OK, setup_pair(&pair, &policy));
    wait_connected(&pair);
    check_equal(P2P_OK, p2p_cnet_connection_pause(pair.server.connection, 1));
    check_equal(P2P_OK, p2p_connection_send(pair.client.connection, payload, sizeof(payload)));
    for (unsigned index = 0; index < 10; ++index) pump(&pair);
    check_equal(0U, pair.server.receives);
    check_equal(P2P_OK, p2p_cnet_connection_pause(pair.server.connection, 0));
    deadline = salts_monotonic_ms() + TEST_DEADLINE_MS;
    while (pair.server.received_bytes < sizeof(payload) && salts_monotonic_ms() < deadline) pump(&pair);
    check_equal(sizeof(payload), pair.server.received_bytes);
    check_equal(payload, pair.server.bytes, sizeof(payload));
    destroy_pair(&pair);
}

static void test_destroy_during_receive(void) {
    pair_t pair = {0};
    p2p_cnet_config_t policy = config(7);
    const uint8_t payload[80] = {1};
    uint64_t deadline;
    check_equal(P2P_OK, setup_pair(&pair, &policy));
    wait_connected(&pair);
    pair.server.destroy_on_receive = 1;
    check_equal(P2P_OK, p2p_connection_send(pair.client.connection, payload, sizeof(payload)));
    deadline = salts_monotonic_ms() + TEST_DEADLINE_MS;
    while (p2p_cnet_owner_connection_count(pair.server.owner) && salts_monotonic_ms() < deadline) pump(&pair);
    check_equal(1U, pair.server.receives);
    check_equal(0U, pair.server.closed);
    check_true(pair.server.connection == NULL);
    check_equal((size_t)0, p2p_cnet_owner_connection_count(pair.server.owner));
    destroy_pair(&pair);
}

static void test_stop_during_receive(void) {
    pair_t pair = {0};
    p2p_cnet_config_t policy = config(4096);
    uint64_t deadline;
    check_equal(P2P_OK, setup_pair(&pair, &policy));
    wait_connected(&pair);
    pair.server.stop_on_receive = 1;
    check_equal(P2P_OK, p2p_connection_send(pair.client.connection, "stop", 4));
    deadline = salts_monotonic_ms() + TEST_DEADLINE_MS;
    while (!pair.server.receives && salts_monotonic_ms() < deadline) pump(&pair);
    check_equal(1U, pair.server.receives);
    check_equal(1U, pair.server.closed);
    check_equal(P2P_ERR_INVALID_STATE, pair.server.recursive_poll);
    check_equal(P2P_ERR_INVALID_STATE, pair.server.recursive_destroy);
    check_equal(P2P_ERR_INVALID_STATE, p2p_cnet_owner_poll(pair.server.owner));
    destroy_pair(&pair);
}

static void test_rejected_receive(int zero_consume) {
    pair_t pair = {0};
    p2p_cnet_config_t policy = config(4096);
    uint64_t deadline;
    check_equal(P2P_OK, setup_pair(&pair, &policy));
    wait_connected(&pair);
    pair.server.zero_consume = zero_consume;
    pair.server.reject_receive = !zero_consume;
    check_equal(P2P_OK, p2p_connection_send(pair.client.connection, "reject", 6));
    deadline = salts_monotonic_ms() + TEST_DEADLINE_MS;
    while (!pair.server.closed && salts_monotonic_ms() < deadline) pump(&pair);
    check_equal(1U, pair.server.closed);
    check_equal(zero_consume ? P2P_ERR_PROTOCOL : P2P_ERR_CRYPTO, pair.server.close_status);
    check_equal(P2P_ERR_NETWORK, p2p_connection_send(pair.server.connection, "x", 1));
    p2p_connection_destroy(pair.server.connection);
    pair.server.connection = NULL;
    pump(&pair);
    check_equal((size_t)0, p2p_cnet_owner_connection_count(pair.server.owner));
    destroy_pair(&pair);
}

static void test_close_pending_and_reuse(void) {
    pair_t pair = {0};
    p2p_cnet_config_t policy = config(4096);
    p2p_cnet_callbacks_t events;
    uint8_t payload[TEST_BUFFER_SIZE] = {1};
    uint64_t deadline;
    check_equal(P2P_OK, setup_pair(&pair, &policy));
    wait_connected(&pair);
    check_equal(P2P_OK, p2p_connection_send(pair.client.connection, payload, sizeof(payload)));
    p2p_connection_destroy(pair.client.connection);
    pair.client.connection = NULL;
    check_equal((size_t)1, p2p_cnet_owner_connection_count(pair.client.owner));
    deadline = salts_monotonic_ms() + TEST_DEADLINE_MS;
    while (p2p_cnet_owner_connection_count(pair.client.owner) && salts_monotonic_ms() < deadline) pump(&pair);
    check_equal((size_t)0, p2p_cnet_owner_connection_count(pair.client.owner));
    check_equal(0U, pair.client.sends);
    check_equal(0U, pair.client.closed);
    events = callbacks(&pair.client);
    check_equal(P2P_OK, p2p_cnet_owner_connect(pair.client.owner, &pair.remote, &events, &pair.client.connection));
    deadline = salts_monotonic_ms() + TEST_DEADLINE_MS;
    while (pair.client.connected < 2 && salts_monotonic_ms() < deadline) pump(&pair);
    check_equal(2U, pair.client.connected);
    check_equal((size_t)1, p2p_cnet_owner_connection_count(pair.client.owner));
    destroy_pair(&pair);
}

static void test_cancel_connect_and_reject_accept(void) {
    pair_t pair = {0};
    p2p_cnet_config_t policy = config(4096);
    uint64_t deadline;
    check_equal(P2P_OK, setup_pair(&pair, &policy));
    pair.server.reject_accept = 1;
    p2p_connection_destroy(pair.client.connection);
    pair.client.connection = NULL;
    deadline = salts_monotonic_ms() + TEST_DEADLINE_MS;
    while (p2p_cnet_owner_connection_count(pair.client.owner) && salts_monotonic_ms() < deadline) pump(&pair);
    check_equal(0U, pair.client.connected);
    check_equal(0U, pair.client.closed);
    check_equal((size_t)0, p2p_cnet_owner_connection_count(pair.client.owner));
    destroy_pair(&pair);
}

static void test_write_count_and_connection_bounds(void) {
    pair_t pair = {0};
    p2p_cnet_config_t policy = config(4096);
    p2p_connection_t *extra = NULL;
    p2p_cnet_callbacks_t events;
    policy.pending_write_limit = 1;
    policy.client.connection_capacity = 1;
    check_equal(P2P_OK, setup_pair(&pair, &policy));
    wait_connected(&pair);
    check_equal(P2P_OK, p2p_connection_send(pair.client.connection, "x", 1));
    check_equal(P2P_ERR_RESOURCE_EXHAUSTED, p2p_connection_send(pair.client.connection, "y", 1));
    check_equal((size_t)1, p2p_cnet_connection_pending_bytes(pair.client.connection));
    events = callbacks(&pair.client);
    check_equal(P2P_ERR_RESOURCE_EXHAUSTED,
        p2p_cnet_owner_connect(pair.client.owner, &pair.remote, &events, &extra));
    check_true(extra == NULL);
    destroy_pair(&pair);
}
typedef struct secure_pair_s secure_pair_t;
typedef struct {
    endpoint_t transport;
    secure_pair_t *pair;
    p2p_identity_t identity;
    p2p_noise_handshake_t handshake;
    p2p_crypto_session_t session;
    uint8_t frame[4096];
    size_t used;
    size_t pending_handshake_bytes;
    int initiator;
    int delivered;
} secure_endpoint_t;

typedef struct {
    secure_pair_t *pair;
    uint8_t preface[P2P_SECURE_PREFACE_SIZE];
    uint8_t packet[P2P_COOKIE_PACKET_SIZE];
    size_t used;
    int phase;
} gate_t;

struct secure_pair_s {
    secure_endpoint_t client, server;
    gate_t *gate;
    uint8_t cookie_secret[32];
    uint8_t network[32];
    unsigned peer_creations;
    int corrupt_cookie;
    int pause_handoff;
};

static int secure_receive(p2p_connection_t *, const uint8_t *, size_t, size_t *, void *);
static p2p_cnet_callbacks_t secure_callbacks(secure_endpoint_t *endpoint);

static int send_crypto_payload(secure_endpoint_t *endpoint) {
    static const uint8_t payload[] = "cookie and Noise over real CNet";
    uint8_t frame[256];
    size_t length = 0;
    int result = p2p_crypto_encrypt(&endpoint->session, payload, sizeof(payload), frame + 2, &length);
    if (result != P2P_OK) return result;
    frame[0] = (uint8_t)(length >> 8);
    frame[1] = (uint8_t)length;
    result = p2p_connection_send(endpoint->transport.connection, frame, length + 2);
    memset(frame, 0xa5, sizeof(frame));
    return result;
}

static int split_secure(secure_endpoint_t *endpoint) {
    const secure_endpoint_t *remote = endpoint->initiator ?
        &endpoint->pair->server : &endpoint->pair->client;
    int result = p2p_noise_split(&endpoint->handshake, &endpoint->session);
    if (result != P2P_OK) return result;
    check_equal(remote->identity.public_key, endpoint->handshake.remote_static_public, 32);
    return P2P_OK;
}

static void secure_sent(p2p_connection_t *connection, size_t length, void *context) {
    secure_endpoint_t *endpoint = context;
    sent(connection, length, &endpoint->transport);
    if (length != endpoint->pending_handshake_bytes) return;
    endpoint->pending_handshake_bytes = 0;
    if (endpoint->initiator && p2p_noise_is_complete(&endpoint->handshake)) {
        check_equal(P2P_OK, split_secure(endpoint));
        check_equal(P2P_OK, send_crypto_payload(endpoint));
    }
    check_equal(P2P_OK, p2p_cnet_connection_pause(connection, 0));
}

static int send_noise(secure_endpoint_t *endpoint) {
    uint8_t frame[4096];
    size_t length = 0;
    int result = p2p_noise_write_message(&endpoint->handshake, frame + 2, &length, sizeof(frame) - 2);
    if (result != P2P_OK) return result;
    frame[0] = (uint8_t)(length >> 8);
    frame[1] = (uint8_t)length;
    result = p2p_connection_send(endpoint->transport.connection, frame, length + 2);
    if (result == P2P_OK) {
        endpoint->pending_handshake_bytes = length + 2;
        result = p2p_cnet_connection_pause(endpoint->transport.connection, 1);
    }
    memset(frame, 0xa5, sizeof(frame));
    return result;
}

static int secure_receive(p2p_connection_t *connection, const uint8_t *bytes,
                            size_t length, size_t *consumed, void *context) {
    secure_endpoint_t *endpoint = context;
    size_t needed = endpoint->used < 2 ? 2 :
        2 + ((size_t)endpoint->frame[0] << 8) + endpoint->frame[1];
    size_t take;
    int result;
    (void)connection;
    if (needed > sizeof(endpoint->frame) || needed <= endpoint->used) return P2P_ERR_PROTOCOL;
    take = needed - endpoint->used;
    if (take > length) take = length;
    memcpy(endpoint->frame + endpoint->used, bytes, take);
    endpoint->used += take;
    *consumed = take;
    if (endpoint->used < 2 || needed == 2 || endpoint->used != needed) return P2P_OK;
    endpoint->used = 0;
    if (endpoint->session.ready) {
        static const uint8_t expected[] = "cookie and Noise over real CNet";
        uint8_t plaintext[4096];
        size_t plaintext_length = 0;
        result = p2p_crypto_decrypt(&endpoint->session, endpoint->frame + 2, needed - 2,
            plaintext, sizeof(plaintext), &plaintext_length);
        if (result != P2P_OK) return result;
        check_equal(sizeof(expected), plaintext_length);
        check_equal(expected, plaintext, plaintext_length);
        endpoint->delivered++;
        return endpoint->initiator ? P2P_OK : send_crypto_payload(endpoint);
    }
    result = p2p_noise_read_message(&endpoint->handshake, endpoint->frame + 2, needed - 2);
    if (result != P2P_OK) return result;
    if (p2p_noise_is_complete(&endpoint->handshake)) return split_secure(endpoint);
    return send_noise(endpoint);
}

static p2p_cnet_callbacks_t secure_callbacks(secure_endpoint_t *endpoint) {
    p2p_cnet_callbacks_t events = callbacks(&endpoint->transport);
    events.context = endpoint;
    events.receive = secure_receive;
    events.sent = secure_sent;
    /* transport is the first member, so the common lifecycle callbacks share
     * its address while receive/send use the complete fixture. */
    return events;
}

static int client_cookie_receive(p2p_connection_t *connection, const uint8_t *bytes,
                                  size_t length, size_t *consumed, void *context) {
    secure_endpoint_t *endpoint = context;
    uint8_t combined[256], binding[P2P_COOKIE_BINDING_SIZE];
    size_t take = P2P_COOKIE_PACKET_SIZE - endpoint->used;
    size_t noise_length = 0;
    int result;
    p2p_cnet_callbacks_t events;
    if (take > length) take = length;
    memcpy(endpoint->frame + endpoint->used, bytes, take);
    endpoint->used += take;
    *consumed = take;
    if (endpoint->used < P2P_COOKIE_PACKET_SIZE) return P2P_OK;
    result = p2p_cookie_build_response(endpoint->frame, combined, binding);
    if (result != P2P_OK) return result;
    result = p2p_noise_init_initiator(&endpoint->handshake, &endpoint->identity, NULL);
    if (result != P2P_OK) return result;
    result = p2p_noise_write_message(&endpoint->handshake, combined + P2P_COOKIE_PACKET_SIZE + 2,
        &noise_length, sizeof(combined) - P2P_COOKIE_PACKET_SIZE - 2);
    if (result != P2P_OK) return result;
    combined[P2P_COOKIE_PACKET_SIZE] = (uint8_t)(noise_length >> 8);
    combined[P2P_COOKIE_PACKET_SIZE + 1] = (uint8_t)noise_length;
    if (endpoint->pair->corrupt_cookie) combined[P2P_COOKIE_PACKET_SIZE - 1] ^= 1;
    events = secure_callbacks(endpoint);
    result = p2p_cnet_connection_handoff(connection, &events);
    if (result != P2P_OK) return result;
    endpoint->used = 0;
    result = p2p_connection_send(connection, combined, P2P_COOKIE_PACKET_SIZE + 2 + noise_length);
    memset(combined, 0xa5, sizeof(combined));
    return result;
}

static int client_cookie_connected(p2p_connection_t *connection, void *context) {
    secure_endpoint_t *endpoint = context;
    uint8_t preface[P2P_SECURE_PREFACE_SIZE];
    connected(connection, &endpoint->transport);
    p2p_secure_preface_build(endpoint->pair->network, preface);
    return p2p_connection_send(connection, preface, sizeof(preface));
}

static int gate_connected(p2p_connection_t *connection, void *context) {
    gate_t *gate = context;
    return connected(connection, &gate->pair->server.transport);
}

static void gate_closed(p2p_connection_t *connection, int status, void *context) {
    gate_t *gate = context;
    closed(connection, status, &gate->pair->server.transport);
    gate->pair->gate = NULL;
    free(gate);
}

static int gate_receive(p2p_connection_t *connection, const uint8_t *bytes,
                         size_t length, size_t *consumed, void *context) {
    gate_t *gate = context;
    secure_pair_t *pair = gate->pair;
    size_t required = gate->phase ? P2P_COOKIE_PACKET_SIZE : P2P_SECURE_PREFACE_SIZE;
    uint8_t *buffer = gate->phase ? gate->packet : gate->preface;
    size_t take = required - gate->used;
    uint8_t packet[P2P_COOKIE_PACKET_SIZE], binding[P2P_COOKIE_BINDING_SIZE];
    p2p_cnet_callbacks_t events;
    int result;
    if (take > length) take = length;
    memcpy(buffer + gate->used, bytes, take);
    gate->used += take;
    *consumed = take;
    if (gate->used != required) return P2P_OK;
    if (!gate->phase) {
        result = p2p_secure_preface_validate(pair->network, gate->preface);
        if (result != P2P_OK) return result;
        result = p2p_cookie_build_challenge(pair->cookie_secret, "127.0.0.1", gate->preface,
            salts_monotonic_ms(), 10000, 300000, packet);
        if (result != P2P_OK) return result;
        gate->used = 0;
        gate->phase = 1;
        return p2p_connection_send(connection, packet, sizeof(packet));
    }
    result = p2p_cookie_verify_response(pair->cookie_secret, "127.0.0.1", gate->preface,
        salts_monotonic_ms(), 10000, 300000, gate->packet, binding);
    if (result != P2P_OK) return result;
    result = p2p_noise_init_responder(&pair->server.handshake, &pair->server.identity);
    if (result != P2P_OK) return result;
    pair->peer_creations++;
    events = secure_callbacks(&pair->server);
    result = p2p_cnet_connection_handoff(connection, &events);
    if (result != P2P_OK) return result;
    check_equal(P2P_OK, p2p_cnet_connection_set_send_hwm(connection, TEST_BUFFER_SIZE));
    if (pair->pause_handoff) check_equal(P2P_OK, p2p_cnet_connection_pause(connection, 1));
    pair->gate = NULL;
    free(gate);
    return P2P_OK;
}

static int secure_accept(p2p_cnet_owner_t *owner, p2p_connection_t *connection,
                           const cnet_stream_peer *peer, void *context) {
    secure_pair_t *pair = context;
    p2p_cnet_callbacks_t events = {0};
    const uint8_t loopback[4] = {127, 0, 0, 1};
    (void)owner;
    check_equal(loopback, peer->address, sizeof(loopback));
    pair->gate = calloc(1, sizeof(*pair->gate));
    if (!pair->gate) return P2P_ERR_NO_MEM;
    pair->gate->pair = pair;
    pair->server.transport.connection = connection;
    events.connected = gate_connected;
    events.receive = gate_receive;
    events.closed = gate_closed;
    events.context = pair->gate;
    check_equal(P2P_OK, p2p_cnet_connection_set_send_hwm(connection, P2P_COOKIE_PACKET_SIZE));
    return p2p_cnet_connection_handoff(connection, &events);
}

static void test_cookie_noise_handoff(size_t receive_size, int pause, int corrupt) {
    secure_pair_t pair = {0};
    p2p_cnet_config_t policy = config(receive_size);
    p2p_cnet_callbacks_t events;
    cnet_stream_peer remote;
    uint64_t deadline;
    pair.client.pair = pair.server.pair = &pair;
    pair.client.initiator = 1;
    pair.cookie_secret[0] = 7;
    pair.network[0] = 9;
    pair.pause_handoff = pause;
    pair.corrupt_cookie = corrupt;
    check_equal(P2P_OK, p2p_crypto_generate_identity(&pair.client.identity));
    check_equal(P2P_OK, p2p_crypto_generate_identity(&pair.server.identity));
    check_equal(P2P_OK, p2p_cnet_owner_create(&policy, &pair.client.transport.owner));
    check_equal(P2P_OK, p2p_cnet_owner_create(&policy, &pair.server.transport.owner));
    check_equal(P2P_OK, p2p_cnet_owner_listen(pair.server.transport.owner, "127.0.0.1", 0, 8,
        secure_accept, &pair, &remote));
    events = secure_callbacks(&pair.client);
    events.connected = client_cookie_connected;
    events.receive = client_cookie_receive;
    check_equal(P2P_OK, p2p_cnet_owner_connect(pair.client.transport.owner, &remote, &events,
        &pair.client.transport.connection));
    deadline = salts_monotonic_ms() + TEST_DEADLINE_MS;
    while (!pair.client.delivered && !pair.server.transport.closed && salts_monotonic_ms() < deadline) {
        check_equal(P2P_OK, p2p_cnet_owner_poll(pair.client.transport.owner));
        check_equal(P2P_OK, p2p_cnet_owner_poll(pair.server.transport.owner));
        if (pair.peer_creations && pair.pause_handoff) {
            check_true(pair.server.handshake.state != NULL);
            check_equal((size_t)0, pair.server.used);
            check_equal(0, pair.server.session.ready);
            check_equal(P2P_OK, p2p_cnet_connection_pause(pair.server.transport.connection, 0));
            pair.pause_handoff = 0;
        }
        salts_sleep_ms(1);
    }
    if (corrupt) {
        check_equal(0U, pair.peer_creations);
        check_equal(P2P_ERR_CRYPTO, pair.server.transport.close_status);
        check_equal(1U, pair.server.transport.closed);
        check_equal(0, pair.server.session.ready);
    } else {
        check_equal(1U, pair.peer_creations);
        check_equal(1, pair.client.delivered);
        check_equal(1, pair.server.delivered);
        check_equal(pair.client.handshake.handshake_hash, pair.server.handshake.handshake_hash, 32);
    }
    check_equal(P2P_OK, p2p_cnet_owner_destroy(pair.client.transport.owner));
    check_equal(P2P_OK, p2p_cnet_owner_destroy(pair.server.transport.owner));
    free(pair.gate);
    p2p_crypto_session_destroy(&pair.client.session);
    p2p_crypto_session_destroy(&pair.server.session);
    p2p_noise_handshake_destroy(&pair.client.handshake);
    p2p_noise_handshake_destroy(&pair.server.handshake);
    p2p_crypto_wipe(&pair, sizeof(pair));
}

static void test_rejected_accept(void) {
    pair_t pair = {0};
    p2p_cnet_config_t policy = config(4096);
    uint64_t deadline;
    check_equal(P2P_OK, setup_pair(&pair, &policy));
    pair.server.reject_accept = 1;
    deadline = salts_monotonic_ms() + TEST_DEADLINE_MS;
    while ((!pair.server.accepted || p2p_cnet_owner_connection_count(pair.server.owner)) &&
           salts_monotonic_ms() < deadline) pump(&pair);
    check_equal(1, pair.server.accepted);
    check_equal(0U, pair.server.connected);
    check_equal(0U, pair.server.closed);
    check_equal((size_t)0, p2p_cnet_owner_connection_count(pair.server.owner));
    destroy_pair(&pair);
}

#ifdef P2P_CNET_TEST_WRAP
static cnet_observer captured_observer;
static cnet_connection captured_handle;
static unsigned reject_close, rejected_closes;
static int reject_send, timeout_stop, close_error;

int __real_cnet_connect_peer(cnet_client *, const cnet_stream_peer *,
    const cnet_stream_peer *, const cnet_observer *, cnet_connection *);
int __wrap_cnet_connect_peer(cnet_client *client, const cnet_stream_peer *remote,
    const cnet_stream_peer *local, const cnet_observer *observer, cnet_connection *handle) {
    int result = __real_cnet_connect_peer(client, remote, local, observer, handle);
    if (result == SALTS_OK) {
        captured_observer = *observer;
        captured_handle = *handle;
    }
    return result;
}

int __real_cnet_close(cnet_client *, cnet_connection);
int __wrap_cnet_close(cnet_client *client, cnet_connection handle) {
    if (close_error) {
        int status = close_error;
        close_error = 0;
        return status;
    }
    if (reject_close) {
        reject_close--;
        rejected_closes++;
        return SALTS_ENOBUFS;
    }
    return __real_cnet_close(client, handle);
}

int __real_cnet_send_buffer(cnet_client *, cnet_connection, mem_buffer_t *);
int __wrap_cnet_send_buffer(cnet_client *client, cnet_connection handle, mem_buffer_t *buffer) {
    if (reject_send) { reject_send = 0; return SALTS_ENOBUFS; }
    return __real_cnet_send_buffer(client, handle, buffer);
}

int __real_cnet_client_stop(cnet_client *, uint32_t);
int __wrap_cnet_client_stop(cnet_client *client, uint32_t timeout_ms) {
    if (timeout_stop) { timeout_stop = 0; return SALTS_ETIMEDOUT; }
    return __real_cnet_client_stop(client, timeout_ms);
}

static void test_close_admission_retry(void) {
    pair_t pair = {0};
    p2p_cnet_config_t policy = config(4096);
    uint64_t deadline;
    check_equal(P2P_OK, setup_pair(&pair, &policy));
    wait_connected(&pair);
    rejected_closes = 0;
    reject_close = 4;
    p2p_connection_destroy(pair.client.connection);
    pair.client.connection = NULL;
    check_equal((size_t)1, p2p_cnet_owner_connection_count(pair.client.owner));
    check_equal(1U, rejected_closes);
    deadline = salts_monotonic_ms() + TEST_DEADLINE_MS;
    while (p2p_cnet_owner_connection_count(pair.client.owner) && salts_monotonic_ms() < deadline) pump(&pair);
    check_equal(4U, rejected_closes);
    check_equal((size_t)0, p2p_cnet_owner_connection_count(pair.client.owner));
    check_equal(0U, pair.client.closed);
    reject_close = 0;
    destroy_pair(&pair);
}

static void test_close_error_stops_owner(void) {
    pair_t pair = {0};
    p2p_cnet_config_t policy = config(4096);
    check_equal(P2P_OK, setup_pair(&pair, &policy));
    wait_connected(&pair);
    close_error = SALTS_EINVAL;
    p2p_connection_close(pair.client.connection);
    check_equal(P2P_OK, p2p_cnet_owner_poll(pair.client.owner));
    check_equal(P2P_ERR_INVALID_STATE, p2p_cnet_owner_poll(pair.client.owner));
    check_equal(1U, pair.client.closed);
    check_equal(P2P_ERR_INVALID_ARG, pair.client.close_status);
    destroy_pair(&pair);
}

static void test_send_admission_rejection(void) {
    pair_t pair = {0};
    p2p_cnet_config_t policy = config(4096);
    check_equal(P2P_OK, setup_pair(&pair, &policy));
    wait_connected(&pair);
    reject_send = 1;
    check_equal(P2P_ERR_RESOURCE_EXHAUSTED, p2p_connection_send(pair.client.connection, "reject", 6));
    check_equal((size_t)0, p2p_cnet_connection_pending_bytes(pair.client.connection));
    for (unsigned index = 0; index < 3; ++index) pump(&pair);
    check_equal(0U, pair.client.sends);
    check_equal((size_t)0, pair.server.received_bytes);
    check_equal(P2P_OK, p2p_connection_send(pair.client.connection, "admit", 5));
    destroy_pair(&pair);
}

static void test_stale_events_and_bad_completion(void) {
    pair_t pair = {0};
    p2p_cnet_config_t policy = config(4096);
    cnet_connection stale;
    cnet_receive_view view = {"stale", 5, CNET_MESSAGE_BYTES};
    uint64_t deadline;
    check_equal(P2P_OK, setup_pair(&pair, &policy));
    wait_connected(&pair);
    stale = captured_handle;
    stale.generation++;
    captured_observer.on_state(captured_observer.user, stale, CNET_CONNECTION_FAILED, NULL);
    captured_observer.on_receive(captured_observer.user, stale, &view);
    captured_observer.on_send(captured_observer.user, stale, 1);
    check_equal(0U, pair.client.closed);
    check_equal(0U, pair.client.receives);
    check_true(pair.client.connection->is_connected);
    check_equal(P2P_OK, p2p_connection_send(pair.client.connection, "12345678", 8));
    captured_observer.on_send(captured_observer.user, captured_handle, 7);
    check_false(pair.client.connection->is_connected);
    deadline = salts_monotonic_ms() + TEST_DEADLINE_MS;
    while (!pair.client.closed && salts_monotonic_ms() < deadline) pump(&pair);
    check_equal(P2P_ERR_PROTOCOL, pair.client.close_status);
    check_equal(1U, pair.client.closed);
    check_equal(0U, pair.client.sends);
    destroy_pair(&pair);
}

static void test_stop_timeout_retains_owner(void) {
    pair_t pair = {0};
    p2p_cnet_config_t policy = config(4096);
    check_equal(P2P_OK, setup_pair(&pair, &policy));
    wait_connected(&pair);
    timeout_stop = 1;
    check_equal(P2P_ERR_TIMEOUT, p2p_cnet_owner_destroy(pair.client.owner));
    check_equal((size_t)1, p2p_cnet_owner_connection_count(pair.client.owner));
    check_equal(P2P_ERR_NETWORK, p2p_connection_send(pair.client.connection, "x", 1));
    check_equal(P2P_OK, p2p_cnet_owner_destroy(pair.client.owner));
    pair.client.owner = NULL;
    check_equal(1U, pair.client.closed);
    destroy_pair(&pair);
}
#endif

spec("P2P CNet connection ownership") {
    it("rejects an accepted stream without publishing a peer callback") { test_rejected_accept(); }
#ifdef P2P_CNET_TEST_WRAP
    it("stops the owner on a non-capacity close error") { test_close_error_stops_owner(); }
    it("retains observers when close admission must be retried") { test_close_admission_retry(); }
    it("does not advance pending state after rejected send admission") { test_send_admission_rejection(); }
    it("ignores stale generations and closes a short logical completion") { test_stale_events_and_bad_completion(); }
    it("retains a timed-out owner until a later completed stop") { test_stop_timeout_retains_owner(); }
#endif
    it("retains builder bytes and completes bounded writes in FIFO order") { test_fifo_copy_and_hwm(); }
    it("preserves the unconsumed tail across receive pause") { test_pause_preserves_tail(); }
    it("retains one already-admitted receive while paused") { test_pause_with_admitted_receive(); }
    it("detaches callbacks before deferred observer destruction") { test_destroy_during_receive(); }
    it("defers callback stop and rejects recursive poll/destroy") { test_stop_during_receive(); }
    it("propagates consumer rejection to one close") { test_rejected_receive(0); }
    it("rejects a consumer that makes no progress") { test_rejected_receive(1); }
    it("closes pending sends and reuses CNet slots without old callbacks") { test_close_pending_and_reuse(); }
    it("cancels an admitted connect before progress") { test_cancel_connect_and_reject_accept(); }
    it("bounds outstanding write count and retained connections") { test_write_count_and_connection_bounds(); }
    it("hands a cookie gate to Noise with a coalesced first frame") { test_cookie_noise_handoff(4096, 0, 0); }
    it("preserves a paused gate-to-Noise tail") { test_cookie_noise_handoff(4096, 1, 0); }
    it("handles seven-byte cookie and Noise receive fragments") { test_cookie_noise_handoff(7, 0, 0); }
    it("rejects a corrupted cookie before creating a Noise peer") { test_cookie_noise_handoff(4096, 0, 1); }
}
