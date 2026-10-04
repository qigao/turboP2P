#include <tinytest.h>
#include "security/p2p_cnet_admission.h"
#include <salts/clock.h>
#include <salts/thread.h>
#include <string.h>

enum { TEST_TIMEOUT_MS = 3000, TEST_BUFFER_BYTES = 4096, TEST_CLIENTS = 4 };
static const uint8_t noise_tail[] = {0, 3, 0x51, 0x52, 0x53};

typedef struct fixture_s fixture_t;
typedef struct {
    fixture_t *fixture;
    p2p_connection_t *connection;
    unsigned connected, closed;
    uint8_t challenge[P2P_COOKIE_PACKET_SIZE];
    size_t used;
    int respond;
    int corrupt;
} client_t;

struct fixture_s {
    p2p_cnet_owner_t *server, *client_owner;
    p2p_cnet_admission_t *admission;
    p2p_cnet_admission_config_t policy;
    cnet_stream_peer remote;
    client_t clients[TEST_CLIENTS];
    p2p_connection_t *promoted_connection;
    uint8_t bytes[TEST_BUFFER_BYTES];
    size_t received;
    unsigned policies, promotions, rejections, peer_closes;
    int last_error, peer_error, deny, fail_promotion, fail_connected, stop_owner;
    int recursive_stop, recursive_destroy, recursive_expire;
    int override_source;
    cnet_stream_peer source;
};

static p2p_cnet_config_t transport_config(void) {
    p2p_cnet_config_t config = {0};
#ifdef _WIN32
    config.client.backend = NATIVE_IO_BACKEND_IOCP;
#elif defined(__linux__)
    config.client.backend = NATIVE_IO_BACKEND_EPOLL;
#else
    config.client.backend = NATIVE_IO_BACKEND_KQUEUE;
#endif
    config.client.connection_capacity = 8;
    config.client.command_capacity = 64;
    config.client.request_capacity = 64;
    config.client.completion_batch_capacity = 16;
    config.client.event_capacity = 64;
    config.client.max_send_bytes = TEST_BUFFER_BYTES;
    config.client.receive_buffer_bytes = TEST_BUFFER_BYTES;
    config.client.connect_timeout_ms = TEST_TIMEOUT_MS;
    config.client.write_timeout_ms = TEST_TIMEOUT_MS;
    config.send_hwm_bytes = TEST_BUFFER_BYTES;
    config.pending_write_limit = 8;
    config.accept_budget = 4;
    config.stop_timeout_ms = TEST_TIMEOUT_MS;
    return config;
}

static int admit(const cnet_stream_peer *source, void *context) {
    fixture_t *fixture = context;
    check_true(source->port != 0);
    fixture->policies++;
    fixture->recursive_stop = p2p_cnet_admission_stop(fixture->admission);
    fixture->recursive_destroy = p2p_cnet_admission_destroy(fixture->admission);
    fixture->recursive_expire = p2p_cnet_admission_expire(fixture->admission, salts_monotonic_ms());
    return fixture->deny ? P2P_ERR_UNTRUSTED_IDENTITY : P2P_OK;
}

static int peer_connected(p2p_connection_t *connection, void *context) {
    fixture_t *fixture = context;
    fixture->promoted_connection = connection;
    return fixture->fail_connected ? P2P_ERR_CRYPTO : P2P_OK;
}

static int peer_receive(p2p_connection_t *connection, const uint8_t *bytes,
                         size_t length, size_t *consumed, void *context) {
    fixture_t *fixture = context;
    (void)connection;
    if (length > sizeof(fixture->bytes) - fixture->received) return P2P_ERR_RESOURCE_EXHAUSTED;
    memcpy(fixture->bytes + fixture->received, bytes, length);
    fixture->received += length;
    *consumed = length;
    return P2P_OK;
}

static void peer_closed(p2p_connection_t *connection, int status, void *context) {
    fixture_t *fixture = context;
    fixture->peer_closes++;
    fixture->peer_error = status;
    fixture->promoted_connection = NULL;
    p2p_connection_destroy(connection);
}

static int promote_peer(const cnet_stream_peer *source,
    const uint8_t preface[P2P_SECURE_PREFACE_SIZE],
    const uint8_t binding[P2P_COOKIE_BINDING_SIZE],
    p2p_cnet_callbacks_t *output, void *context) {
    fixture_t *fixture = context;
    uint8_t response[P2P_COOKIE_PACKET_SIZE], expected[P2P_COOKIE_BINDING_SIZE];
    p2p_cnet_admission_stats_t pending;
    check_true(source->port != 0);
    fixture->promotions++;
    check_equal(P2P_OK, p2p_cnet_admission_stats(fixture->admission, &pending));
    /* A node with one pending-peer slot must be able to replace its own gate. */
    check_equal((size_t)0, pending.active);
    check_equal(P2P_OK, p2p_secure_preface_validate(fixture->policy.network_id_hash, preface));
    check_equal(P2P_OK, p2p_cookie_build_response(fixture->clients[0].challenge, response, expected));
    check_equal(expected, binding, sizeof(expected));
    if (fixture->fail_promotion) return P2P_ERR_RESOURCE_EXHAUSTED;
    output->connected = peer_connected;
    output->receive = peer_receive;
    output->closed = peer_closed;
    output->context = fixture;
    if (fixture->stop_owner) check_equal(P2P_OK, p2p_cnet_owner_stop(fixture->server));
    return P2P_OK;
}

static void rejected(const cnet_stream_peer *source, int status,
    p2p_cnet_rejection_origin_t origin, void *context) {
    fixture_t *fixture = context;
    check_true(origin >= P2P_CNET_REJECT_GATE_CAPACITY && origin <= P2P_CNET_REJECT_TRANSPORT);
    check_true(source->port != 0);
    fixture->rejections++;
    fixture->last_error = status;
}

static int accept_peer(p2p_cnet_owner_t *owner, p2p_connection_t *connection,
                        const cnet_stream_peer *source, void *context) {
    fixture_t *fixture = context;
    cnet_stream_peer actual = *source;
    if (fixture->override_source) {
        actual = fixture->source;
        actual.port = source->port;
    }
    return p2p_cnet_admission_accept(owner, connection, &actual, fixture->admission);
}

static void setup(fixture_t *fixture, size_t gates, size_t sources) {
    p2p_cnet_config_t config = transport_config();
    p2p_cnet_admission_callbacks_t events = {admit, promote_peer, rejected, fixture, NULL};
    fixture->policy.gate_limit = gates;
    fixture->policy.source_limit = sources;
    fixture->policy.peer_send_hwm_bytes = TEST_BUFFER_BYTES;
    fixture->policy.handshake_timeout_ms = TEST_TIMEOUT_MS;
    fixture->policy.cookie_lifetime_ms = 10000;
    fixture->policy.cookie_key_rotation_ms = 300000;
    fixture->policy.network_id_hash[0] = 19;
    fixture->policy.cookie_master_secret[0] = 53;
    check_equal(P2P_OK, p2p_cnet_owner_create(&config, &fixture->server));
    check_equal(P2P_OK, p2p_cnet_owner_create(&config, &fixture->client_owner));
    check_equal(P2P_OK, p2p_cnet_admission_create(fixture->server, &fixture->policy,
        &events, &fixture->admission));
    check_equal(P2P_OK, p2p_cnet_owner_listen(fixture->server, "127.0.0.1", 0, 8,
        accept_peer, fixture, &fixture->remote));
}

static int client_connected(p2p_connection_t *connection, void *context) {
    client_t *client = context;
    client->connection = connection;
    client->connected++;
    return P2P_OK;
}

static void client_closed(p2p_connection_t *connection, int status, void *context) {
    client_t *client = context;
    (void)status;
    client->closed++;
    client->connection = NULL;
    p2p_connection_destroy(connection);
}

static int client_receive(p2p_connection_t *connection, const uint8_t *bytes,
                           size_t length, size_t *consumed, void *context) {
    client_t *client = context;
    uint8_t response[P2P_COOKIE_PACKET_SIZE + sizeof(noise_tail)];
    uint8_t binding[P2P_COOKIE_BINDING_SIZE];
    size_t take = sizeof(client->challenge) - client->used;
    if (take > length) take = length;
    memcpy(client->challenge + client->used, bytes, take);
    client->used += take;
    *consumed = take;
    if (client->used == sizeof(client->challenge) && client->respond) {
        int result = p2p_cookie_build_response(client->challenge, response, binding);
        if (result != P2P_OK) return result;
        if (client->corrupt) response[sizeof(client->challenge) - 1] ^= 1;
        memcpy(response + sizeof(client->challenge), noise_tail, sizeof(noise_tail));
        client->respond = 0;
        return p2p_connection_send(connection, response, sizeof(response));
    }
    return take ? P2P_OK : P2P_ERR_PROTOCOL;
}

static void pump(fixture_t *fixture) {
    check_equal(P2P_OK, p2p_cnet_admission_expire(fixture->admission, salts_monotonic_ms()));
    check_equal(P2P_OK, p2p_cnet_owner_poll(fixture->client_owner));
    check_equal(P2P_OK, p2p_cnet_owner_poll(fixture->server));
    salts_sleep_ms(1);
}

static p2p_cnet_admission_stats_t stats(fixture_t *fixture) {
    p2p_cnet_admission_stats_t result;
    check_equal(P2P_OK, p2p_cnet_admission_stats(fixture->admission, &result));
    return result;
}

static void connect_client(fixture_t *fixture, size_t index) {
    client_t *client = &fixture->clients[index];
    p2p_cnet_callbacks_t events = {client_connected, client_receive, NULL, client_closed, client};
    uint64_t target = stats(fixture).accepted + fixture->rejections + 1;
    uint64_t deadline = salts_monotonic_ms() + TEST_TIMEOUT_MS;
    client->fixture = fixture;
    check_equal(P2P_OK, p2p_cnet_owner_connect(fixture->client_owner, &fixture->remote,
        &events, &client->connection));
    while ((!client->connected || stats(fixture).accepted + fixture->rejections < target) &&
           salts_monotonic_ms() < deadline) pump(fixture);
    check_equal(target, stats(fixture).accepted + fixture->rejections);
}

static void preface(fixture_t *fixture, int corrupt) {
    uint8_t bytes[P2P_SECURE_PREFACE_SIZE];
    p2p_secure_preface_build(fixture->policy.network_id_hash, bytes);
    if (corrupt) bytes[sizeof(bytes) - 1] ^= 1;
    check_equal(P2P_OK, p2p_connection_send(fixture->clients[0].connection, bytes, sizeof(bytes)));
}

static void wait_result(fixture_t *fixture) {
    uint64_t deadline = salts_monotonic_ms() + TEST_TIMEOUT_MS;
    while (!fixture->rejections && !fixture->peer_closes && fixture->received < sizeof(noise_tail) &&
           salts_monotonic_ms() < deadline) pump(fixture);
}

static void cleanup(fixture_t *fixture) {
    check_equal(P2P_OK, p2p_cnet_admission_stop(fixture->admission));
    check_equal((size_t)0, stats(fixture).active);
    check_equal(P2P_OK, p2p_cnet_owner_destroy(fixture->client_owner));
    check_equal(P2P_OK, p2p_cnet_owner_destroy(fixture->server));
    check_equal(P2P_OK, p2p_cnet_admission_destroy(fixture->admission));
}

static void test_config_and_reentrancy(void) {
    fixture_t fixture = {0};
    p2p_cnet_admission_t *invalid = NULL;
    p2p_cnet_admission_callbacks_t events = {0};
    setup(&fixture, 2, 1);
    check_equal(P2P_ERR_INVALID_ARG, p2p_cnet_admission_create(fixture.server,
        &fixture.policy, &events, &invalid));
    check_true(invalid == NULL);
    events.admit = admit;
    events.promote = promote_peer;
    fixture.policy.cookie_key_rotation_ms++;
    check_equal(P2P_ERR_INVALID_ARG, p2p_cnet_admission_create(fixture.server,
        &fixture.policy, &events, &invalid));
    check_equal(P2P_ERR_INVALID_STATE, p2p_cnet_admission_destroy(fixture.admission));
    connect_client(&fixture, 0);
    check_equal(P2P_ERR_INVALID_STATE, fixture.recursive_stop);
    check_equal(P2P_ERR_INVALID_STATE, fixture.recursive_destroy);
    check_equal(P2P_ERR_INVALID_STATE, fixture.recursive_expire);
    cleanup(&fixture);
}

static void test_rejection(int reason) {
    fixture_t fixture = {0};
    setup(&fixture, 2, 1);
    fixture.deny = reason == 0;
    fixture.fail_promotion = reason == 3;
    fixture.fail_connected = reason == 4;
    fixture.stop_owner = reason == 5;
    fixture.clients[0].respond = 1;
    fixture.clients[0].corrupt = reason == 2;
    connect_client(&fixture, 0);
    if (!fixture.deny) preface(&fixture, reason == 1);
    wait_result(&fixture);
    check_equal((size_t)0, stats(&fixture).active);
    if (reason >= 4) {
        check_equal(1U, fixture.peer_closes);
        check_equal(reason == 4 ? P2P_ERR_CRYPTO : P2P_ERR_INVALID_STATE, fixture.peer_error);
        check_equal(reason == 4 ? 0U : 1U, fixture.rejections);
    } else {
        check_equal(1U, fixture.rejections);
        check_equal(reason == 0 ? P2P_ERR_UNTRUSTED_IDENTITY : reason == 1 ? P2P_ERR_PROTOCOL :
            reason == 2 ? P2P_ERR_CRYPTO : P2P_ERR_RESOURCE_EXHAUSTED, fixture.last_error);
    }
    check_equal(reason >= 3 ? 1U : 0U, fixture.promotions);
    check_equal((size_t)0, fixture.received);
    cleanup(&fixture);
}

static void test_capacity(size_t gates, size_t sources) {
    fixture_t fixture = {0};
    uint64_t deadline;
    setup(&fixture, gates, sources);
    connect_client(&fixture, 0);
    connect_client(&fixture, 1);
    check_equal(1U, fixture.rejections);
    check_equal(P2P_ERR_RESOURCE_EXHAUSTED, fixture.last_error);
    check_equal((size_t)1, stats(&fixture).active);
    p2p_connection_destroy(fixture.clients[0].connection);
    fixture.clients[0].connection = NULL;
    deadline = salts_monotonic_ms() + TEST_TIMEOUT_MS;
    while (stats(&fixture).active && salts_monotonic_ms() < deadline) pump(&fixture);
    check_equal((size_t)0, stats(&fixture).active);
    connect_client(&fixture, 2);
    check_equal((size_t)1, stats(&fixture).active);
    check_equal((uint64_t)2, stats(&fixture).accepted);
    check_equal(0U, fixture.promotions);
    cleanup(&fixture);
}

static void test_ipv6_prefix_capacity(void) {
    fixture_t fixture = {0};
    setup(&fixture, 3, 1);
    fixture.override_source = 1;
    fixture.source.family = CNET_DATAGRAM_ADDRESS_IPV6;
    fixture.source.address[0] = 0x20;
    fixture.source.address[1] = 0x01;
    fixture.source.address[15] = 1;
    connect_client(&fixture, 0);
    fixture.source.address[15] = 2;
    connect_client(&fixture, 1);
    check_equal(1U, fixture.rejections);
    fixture.source.address[7] = 1;
    connect_client(&fixture, 2);
    check_equal((size_t)2, stats(&fixture).active);
    check_equal((uint64_t)2, stats(&fixture).accepted);
    cleanup(&fixture);
}

static void test_timeout(int after_challenge) {
    fixture_t fixture = {0};
    uint64_t deadline;
    setup(&fixture, 2, 1);
    connect_client(&fixture, 0);
    if (after_challenge) {
        preface(&fixture, 0);
        deadline = salts_monotonic_ms() + TEST_TIMEOUT_MS;
        while (fixture.clients[0].used < P2P_COOKIE_PACKET_SIZE && salts_monotonic_ms() < deadline)
            pump(&fixture);
        check_equal((size_t)P2P_COOKIE_PACKET_SIZE, fixture.clients[0].used);
    }
    check_equal(P2P_OK, p2p_cnet_admission_expire(fixture.admission,
        salts_monotonic_ms() + TEST_TIMEOUT_MS));
    check_equal(P2P_OK, p2p_cnet_admission_expire(fixture.admission,
        salts_monotonic_ms() + TEST_TIMEOUT_MS));
    check_equal(1U, fixture.rejections);
    check_equal(P2P_ERR_TIMEOUT, fixture.last_error);
    check_equal((size_t)0, stats(&fixture).active);
    check_equal(0U, fixture.promotions);
    cleanup(&fixture);
}

#ifdef P2P_ADMISSION_TEST_WRAP
static cnet_observer held_observer;
static cnet_connection held_handle;
static size_t held_length;
static int hold_send, fail_send;
int __real_cnet_client_adopt_accepted(cnet_client *, cnet_accepted_stream *,
                                      const cnet_observer *, cnet_connection *);
int __real_cnet_send_buffer(cnet_client *, cnet_connection, mem_buffer_t *);
static void delayed_send(void *context, cnet_connection handle, size_t length) {
    check_true(context == held_observer.user);
    held_handle = handle;
    held_length = length;
}
int __wrap_cnet_client_adopt_accepted(cnet_client *client, cnet_accepted_stream *accepted,
                                      const cnet_observer *observer, cnet_connection *output) {
    cnet_observer events = *observer;
    if (hold_send) {
        held_observer = events;
        events.on_send = delayed_send;
    }
    return __real_cnet_client_adopt_accepted(client, accepted, &events, output);
}
int __wrap_cnet_send_buffer(cnet_client *client, cnet_connection connection, mem_buffer_t *buffer) {
    if (fail_send) { fail_send = 0; return SALTS_ENOBUFS; }
    return __real_cnet_send_buffer(client, connection, buffer);
}

static void test_delayed_completion(int terminal) {
    fixture_t fixture = {0};
    uint64_t deadline;
    hold_send = 1;
    held_length = 0;
    setup(&fixture, 2, 1);
    fixture.clients[0].respond = 1;
    connect_client(&fixture, 0);
    preface(&fixture, 0);
    deadline = salts_monotonic_ms() + TEST_TIMEOUT_MS;
    while ((!held_length || fixture.clients[0].respond) && salts_monotonic_ms() < deadline) pump(&fixture);
    check_equal((size_t)P2P_COOKIE_PACKET_SIZE, held_length);
    /* Drive the response into the paused gate while its logical send terminal
     * is withheld, even though the real socket has delivered the challenge. */
    for (unsigned i = 0; i < 20; ++i) pump(&fixture);
    check_equal(0U, fixture.promotions);
    check_equal((size_t)0, fixture.received);
    check_equal((size_t)1, stats(&fixture).active);
    if (terminal == 2) {
        check_equal(P2P_OK, p2p_cnet_admission_stop(fixture.admission));
    } else if (terminal == 1) {
        check_equal(P2P_OK, p2p_cnet_admission_expire(fixture.admission,
            salts_monotonic_ms() + TEST_TIMEOUT_MS));
    }
    held_observer.on_send(held_observer.user, held_handle, held_length);
    hold_send = 0;
    if (terminal) {
        check_equal(0U, fixture.promotions);
        check_equal(terminal == 1 ? 1U : 0U, fixture.rejections);
        if (terminal == 1) check_equal(P2P_ERR_TIMEOUT, fixture.last_error);
    } else {
        wait_result(&fixture);
        check_equal(1U, fixture.promotions);
        check_equal(noise_tail, fixture.bytes, sizeof(noise_tail));
        check_equal(sizeof(noise_tail), fixture.received);
        check_equal((uint64_t)1, stats(&fixture).challenges_completed);
    }
    cleanup(&fixture);
}

static void test_rejected_challenge_send(void) {
    fixture_t fixture = {0};
    setup(&fixture, 2, 1);
    connect_client(&fixture, 0);
    preface(&fixture, 0);
    fail_send = 1;
    wait_result(&fixture);
    check_equal(0, fail_send);
    check_equal(1U, fixture.rejections);
    check_equal(P2P_ERR_RESOURCE_EXHAUSTED, fixture.last_error);
    check_equal((uint64_t)0, stats(&fixture).challenges_completed);
    check_equal(0U, fixture.promotions);
    cleanup(&fixture);
}
#endif

spec("P2P CNet cookie admission") {
    it("requires bounded policy and rejects recursive lifecycle mutation") { test_config_and_reentrancy(); }
    it("enforces node policy before allocating a gate") { test_rejection(0); }
    it("rejects a preface for a different network before challenge") { test_rejection(1); }
    it("rejects invalid proof without creating a peer") { test_rejection(2); }
    it("releases a verified gate when the peer quota refuses promotion") { test_rejection(3); }
    it("reports peer initialization failure once with its original error") { test_rejection(4); }
    it("releases prepared peer context when owner stop prevents handoff") { test_rejection(5); }
    it("bounds global gates and reuses a disconnected slot") { test_capacity(1, 1); }
    it("bounds pending gates from one IPv4 source") { test_capacity(2, 1); }
    it("groups IPv6 sources by /64 while isolating different prefixes") { test_ipv6_prefix_capacity(); }
    it("expires a silent preface without waiting for receive") { test_timeout(0); }
    it("keeps the original deadline while waiting for cookie proof") { test_timeout(1); }
#ifdef P2P_ADMISSION_TEST_WRAP
    it("waits for challenge completion before handing off a coalesced tail") { test_delayed_completion(0); }
    it("ignores delayed send completion after gate timeout and detach") { test_delayed_completion(1); }
    it("detaches pending challenge callbacks before admission stop") { test_delayed_completion(2); }
    it("fails admission when challenge send cannot enter the queue") { test_rejected_challenge_send(); }
#endif
}
