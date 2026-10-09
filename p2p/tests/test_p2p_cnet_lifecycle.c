#include <tinytest.h>
#include "p2p.h"
#include "core/node_state.h"
#include "transfer/transfer.h"
#include <cnet/cnet.h>
#include <salts/clock.h>
#include <salts/thread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

enum { WAIT_MS = 3000, FILE_BYTES = 128 * 1024 + 37 };
static const uint8_t network_id[P2P_SECURITY_ID_SIZE] = {31};
static const char value[] = "public CNet lifecycle";
#ifdef P2P_LIFECYCLE_TEST_WRAP
static int timeout_stop;
#endif
typedef struct {
    p2p_node_t *node;
    p2p_peer_t *peer;
    uint8_t key[P2P_KEY_SIZE];
    char ip[P2P_MAX_IP];
    int port, connected, messages, stop_on_connect, stopped;
} endpoint_t;
typedef struct { endpoint_t client, server; } pair_t;

static void connected(p2p_peer_t *peer, void *context) {
    endpoint_t *endpoint = context;
    endpoint->connected++;
    endpoint->peer = peer;
    check_equal(P2P_ERR_INVALID_STATE, p2p_poll(endpoint->node));
    check_equal(P2P_ERR_INVALID_STATE, p2p_destroy_v2(endpoint->node));
    if (endpoint->stop_on_connect) {
        check_equal(P2P_OK, p2p_stop_v2(endpoint->node));
        endpoint->stopped = 1;
    }
}
static void disconnected(p2p_peer_t *peer, void *context) {
    endpoint_t *endpoint = context;
    if (endpoint->peer == peer) endpoint->peer = NULL;
}
static void message(p2p_node_t *node, p2p_peer_t *peer,
    const void *data, size_t length, void *context) {
    endpoint_t *endpoint = context;
    check_true(node == endpoint->node && peer == endpoint->peer);
    check_equal(sizeof(value), length);
    check_equal(value, data, sizeof(value));
    endpoint->messages++;
}
static void init_endpoint(endpoint_t *endpoint, uint8_t seed, int port) {
    uint8_t secret[P2P_KEY_SIZE] = {0};
    secret[0] = seed;
    check_equal(P2P_OK, p2p_create_v2("127.0.0.1", port, &endpoint->node));
    check_equal(P2P_OK, p2p_node_set_private_key(endpoint->node, secret));
    check_equal(P2P_OK, p2p_node_get_public_key(endpoint->node, endpoint->key));
    p2p_set_peer_callbacks(endpoint->node, connected, disconnected, endpoint);
    p2p_set_message_handler(endpoint->node, message, endpoint);
}
static void init_pair(pair_t *pair) {
    init_endpoint(&pair->client, 17, 0);
    init_endpoint(&pair->server, 33, 0);
    check_equal(P2P_OK, p2p_node_configure_pinned_security_v2(
        pair->client.node, network_id, pair->server.key, 1));
    check_equal(P2P_OK, p2p_node_configure_pinned_security_v2(
        pair->server.node, network_id, pair->client.key, 1));
}
static void start_endpoint(endpoint_t *endpoint, size_t receive_bytes) {
    p2p_runtime_config_v2_t config;
    check_equal(P2P_OK, p2p_runtime_config_v2_init(&config));
    config.receive_buffer_bytes = receive_bytes;
    check_equal(P2P_OK, p2p_start_nonblocking_v2(endpoint->node, &config));
    check_equal(P2P_ERR_INVALID_STATE, p2p_start_nonblocking_v2(endpoint->node, &config));
    memset(&config, 0, sizeof(config)); /* Startup does not borrow options. */
    check_equal(P2P_OK, p2p_node_get_listen_address_v2(endpoint->node,
        endpoint->ip, sizeof(endpoint->ip), &endpoint->port));
    check_true(endpoint->port > 0);
}
static void start_pair(pair_t *pair, size_t receive_bytes) {
    init_pair(pair);
    start_endpoint(&pair->server, receive_bytes);
    start_endpoint(&pair->client, receive_bytes);
    check_equal(P2P_OK, p2p_connect(pair->client.node, pair->server.ip, pair->server.port));
}
static void pump(pair_t *pair) {
    if (!pair->client.stopped) check_equal(P2P_OK, p2p_poll(pair->client.node));
    if (!pair->server.stopped) check_equal(P2P_OK, p2p_poll(pair->server.node));
    cmeta_sleep_ms(1);
}
static void wait_ready(pair_t *pair) {
    uint64_t deadline = salts_monotonic_ms() + WAIT_MS;
    while ((!pair->client.connected || !pair->server.connected) &&
        salts_monotonic_ms() < deadline) pump(pair);
    check_equal(1, pair->client.connected);
    check_equal(1, pair->server.connected);
}
static void destroy_pair(pair_t *pair) {
    check_equal(P2P_OK, p2p_destroy_v2(pair->client.node));
    pair->client.node = NULL;
    check_equal(P2P_OK, p2p_destroy_v2(pair->server.node));
    pair->server.node = NULL;
}
static void test_unstarted(void) {
    p2p_runtime_config_v2_t config;
    p2p_node_t *node = NULL;
    char ip[P2P_MAX_IP] = "untouched";
    int port = -1;
    check_equal(P2P_ERR_INVALID_ARG, p2p_runtime_config_v2_init(NULL));
    check_equal(P2P_OK, p2p_runtime_config_v2_init(&config));
    check_equal(P2P_ERR_INVALID_ARG, p2p_create_v2(NULL, 0, &node));
    check_true(node == NULL);
    check_equal(P2P_ERR_INVALID_ARG, p2p_create_v2("", 0, &node));
    check_equal(P2P_ERR_INVALID_ARG, p2p_create_v2("127.0.0.1", -1, &node));
    check_equal(P2P_ERR_INVALID_ARG, p2p_create_v2("127.0.0.1", 65536, &node));
    check_equal(P2P_ERR_INVALID_ARG, p2p_create_v2("127.0.0.1", 0, NULL));
    check_equal(P2P_OK, p2p_create_v2("127.0.0.1", 0, &node));
    check_equal(P2P_ERR_INVALID_STATE, p2p_poll(node));
    check_equal(P2P_ERR_INVALID_STATE, p2p_node_get_listen_address_v2(node, ip, sizeof(ip), &port));
    check_equal(0, strcmp(ip, "untouched"));
    check_equal(-1, port);
    check_equal(P2P_ERR_AUTH_REQUIRED, p2p_start_nonblocking_v2(node, &config));
    check_equal(P2P_ERR_INVALID_STATE, p2p_node_state_destroy(node));
    check_equal(P2P_OK, p2p_dht_put_cached(node, "before-start", value, sizeof(value)));
    check_equal(P2P_OK, p2p_stop_v2(node));
    check_equal(P2P_OK, p2p_stop_v2(node));
    check_equal(P2P_ERR_INVALID_STATE, p2p_start_nonblocking_v2(node, &config));
    check_equal(P2P_OK, p2p_destroy_v2(node));
    check_equal(P2P_OK, p2p_destroy_v2(NULL));
    node = p2p_node_state_create("127.0.0.1", 0);
    check_not_null(node);
    check_equal(P2P_ERR_INVALID_STATE, p2p_start_nonblocking_v2(node, &config));
    check_equal(P2P_ERR_INVALID_STATE, p2p_stop_v2(node));
    check_equal(P2P_ERR_INVALID_STATE, p2p_destroy_v2(node));
    check_equal(P2P_OK, p2p_node_state_destroy(node));
}
static void test_start_correction(void) {
    pair_t pair = {0};
    p2p_runtime_config_v2_t config;
    check_equal(P2P_OK, p2p_runtime_config_v2_init(&config));
    init_endpoint(&pair.client, 17, 0);
    check_equal(P2P_ERR_AUTH_REQUIRED, p2p_start_nonblocking_v2(pair.client.node, &config));
    init_endpoint(&pair.server, 33, 0);
    check_equal(P2P_OK, p2p_node_configure_pinned_security_v2(pair.client.node, network_id, pair.server.key, 1));
    check_equal(P2P_OK, p2p_node_configure_pinned_security_v2(pair.server.node, network_id, pair.client.key, 1));
    config.struct_size--;
    check_equal(P2P_ERR_INVALID_ARG, p2p_start_nonblocking_v2(pair.client.node, &config));
    config.struct_size = sizeof(config);
    config.command_capacity = 3;
    check_equal(P2P_ERR_INVALID_ARG, p2p_start_nonblocking_v2(pair.client.node, &config));
    check_equal(P2P_ERR_INVALID_STATE, p2p_poll(pair.client.node));
    config.command_capacity = 256;
    config.send_hwm_bytes = 1;
    check_equal(P2P_ERR_INVALID_ARG, p2p_start_nonblocking_v2(pair.client.node, &config));
    start_endpoint(&pair.client, 7);
    start_endpoint(&pair.server, 7);
    check_equal(P2P_OK, p2p_connect(pair.client.node, pair.server.ip, pair.server.port));
    wait_ready(&pair);
    char short_ip[2] = {'x', 'y'};
    int port = -1;
    check_equal(P2P_ERR_RESOURCE_EXHAUSTED,
        p2p_node_get_listen_address_v2(pair.server.node, short_ip, sizeof(short_ip), &port));
    check_equal('x', short_ip[0]); check_equal('y', short_ip[1]); check_equal(-1, port);
    destroy_pair(&pair);
}
static void test_listener_failure(int expected_error) {
    pair_t pair = {0};
    p2p_runtime_config_v2_t config;
    init_pair(&pair);
    start_endpoint(&pair.server, 7);
    check_equal(P2P_OK, p2p_destroy_v2(pair.client.node));
    init_endpoint(&pair.client, 17, pair.server.port);
    check_equal(P2P_OK, p2p_node_configure_pinned_security_v2(pair.client.node, network_id, pair.server.key, 1));
    check_equal(P2P_OK, p2p_runtime_config_v2_init(&config));
#ifdef P2P_LIFECYCLE_TEST_WRAP
    if (expected_error == P2P_ERR_TIMEOUT) timeout_stop = 1;
#endif
    check_equal(expected_error, p2p_start_nonblocking_v2(pair.client.node, &config));
    check_equal(P2P_ERR_INVALID_STATE, p2p_poll(pair.client.node));
    check_equal(P2P_ERR_INVALID_STATE, p2p_start_nonblocking_v2(pair.client.node, &config));
    check_equal(P2P_OK, p2p_stop_v2(pair.client.node));
    check_equal(P2P_OK, p2p_poll(pair.server.node));
    destroy_pair(&pair);
}
static void test_roundtrip(void) {
    pair_t pair = {0};
    char output[sizeof(value)] = {0};
    size_t length = sizeof(output);
    start_pair(&pair, 7);
    wait_ready(&pair);
    check_equal(P2P_OK, p2p_send_message(pair.client.node, pair.client.peer, P2P_MSG_CUSTOM, value, sizeof(value)));
    check_equal(P2P_OK, p2p_send_message(pair.server.node, pair.server.peer, P2P_MSG_CUSTOM, value, sizeof(value)));
    check_equal(P2P_OK, p2p_dht_put_cached(pair.client.node, "public:key", value, sizeof(value)));
    uint64_t deadline = salts_monotonic_ms() + WAIT_MS;
    while ((!pair.client.messages || !pair.server.messages ||
        p2p_dht_get_cached(pair.server.node, "public:key", output, &length) != P2P_OK) &&
        salts_monotonic_ms() < deadline) pump(&pair);
    check_equal(1, pair.client.messages); check_equal(1, pair.server.messages);
    check_equal(P2P_OK, p2p_dht_get_cached(pair.server.node, "public:key", output, &length));
    check_equal(value, output, sizeof(value));
    check_equal(P2P_OK, p2p_stop_v2(pair.server.node));
    check_equal(P2P_OK, p2p_stop_v2(pair.server.node));
    check_equal(P2P_ERR_INVALID_STATE, p2p_poll(pair.server.node));
    check_equal(P2P_OK, p2p_node_get_listen_address_v2(pair.server.node,
        pair.server.ip, sizeof(pair.server.ip), &pair.server.port));
    check_equal(P2P_OK, p2p_dht_get_cached(pair.server.node, "public:key", output, &length));
    destroy_pair(&pair);
}
static void test_callback_stop(void) {
    pair_t pair = {0};
    start_pair(&pair, 7);
    pair.server.stop_on_connect = 1;
    uint64_t deadline = salts_monotonic_ms() + WAIT_MS;
    while (!pair.server.stopped && salts_monotonic_ms() < deadline) pump(&pair);
    check_true(pair.server.stopped);
    check_equal(P2P_ERR_INVALID_STATE, p2p_poll(pair.server.node));
    destroy_pair(&pair);
}

typedef struct { pair_t pair; int completed, success, stop_on_complete; } file_case_t;
static void file_done(p2p_transfer_t *transfer, int success, const char *error, void *context) {
    file_case_t *file = context;
    (void)transfer;
    check_true(success ? error == NULL : error != NULL);
    file->completed++;
    file->success = success;
    if (file->stop_on_complete) {
        check_equal(P2P_ERR_INVALID_STATE, p2p_destroy_v2(file->pair.client.node));
        check_equal(P2P_OK, p2p_stop_v2(file->pair.client.node));
        file->pair.client.stopped = 1;
    }
}
static void test_file(int stop_on_complete, int retain_lease) {
    file_case_t file = {0};
    char source[128], output[128], key[65];
    unsigned long long stamp = (unsigned long long)salts_hrtime();
    snprintf(source, sizeof(source), "public-cnet-%llu-source.tmp", stamp);
    snprintf(output, sizeof(output), "public-cnet-%llu-output.tmp", stamp);
    FILE *stream = fopen(source, "wbx");
    check_not_null(stream);
    for (size_t i = 0; i < FILE_BYTES; ++i) check_true(fputc((int)(i % 251), stream) != EOF);
    check_equal(0, fclose(stream));
    stream = fopen(output, "wbx"); check_not_null(stream); check_equal(0, fclose(stream));
    start_pair(&file.pair, 4093);
    wait_ready(&file.pair);
    file.stop_on_complete = stop_on_complete;
    check_equal(P2P_OK, p2p_put_file(file.pair.server.node, source, key));
    check_equal(P2P_OK, p2p_get_file_async(file.pair.client.node, key, output, file_done, &file));
    if (retain_lease) {
        p2p_transfer_manager_t *manager = file.pair.client.node->transfers;
        p2p_transfer_t *lease = p2p_transfer_find_by_id(manager, manager->active->id);
        check_not_null(lease);
        p2p_transfer_destroy(manager, lease);
        check_equal(P2P_ERR_INVALID_STATE, p2p_stop_v2(file.pair.client.node));
        check_equal(P2P_ERR_INVALID_STATE, p2p_destroy_v2(file.pair.client.node));
        check_equal(P2P_ERR_INVALID_STATE, p2p_poll(file.pair.client.node));
        check_true(file.pair.client.node->transfers == manager);
        check_not_null(file.pair.client.node->runtime_v2);
        check_equal((size_t)1, manager->outstanding_refs);
        p2p_transfer_release(lease);
        check_equal(0, file.completed);
    } else {
        uint64_t deadline = salts_monotonic_ms() + WAIT_MS;
        while (!file.completed && salts_monotonic_ms() < deadline) pump(&file.pair);
        check_equal(1, file.completed); check_equal(1, file.success);
        stream = fopen(output, "rb"); check_not_null(stream);
        for (size_t i = 0; i < FILE_BYTES; ++i) check_equal((int)(i % 251), fgetc(stream));
        check_equal(EOF, fgetc(stream)); check_equal(0, fclose(stream));
    }
    destroy_pair(&file.pair);
    check_equal(0, remove(source)); check_equal(0, remove(output));
}
static void test_unstarted_lease(void) {
    p2p_node_t *node = NULL;
    check_equal(P2P_OK, p2p_create_v2("127.0.0.1", 0, &node));
    p2p_transfer_t *transfer = p2p_transfer_create(node->transfers, P2P_TRANSFER_DIR_DOWNLOAD);
    check_not_null(transfer);
    p2p_transfer_t *lease = p2p_transfer_find_by_id(node->transfers, transfer->id);
    check_not_null(lease);
    check_equal(P2P_ERR_INVALID_STATE, p2p_destroy_v2(node));
    check_not_null(node->runtime_v2);
    p2p_transfer_release(lease);
    check_equal(P2P_OK, p2p_destroy_v2(node));
}
#ifdef P2P_LIFECYCLE_TEST_WRAP
static int fail_identity;
static unsigned fail_alloc_at, allocations;
int __real_cnet_client_stop(cnet_client *, uint32_t);
int __wrap_cnet_client_stop(cnet_client *client, uint32_t timeout_ms) {
    if (timeout_stop) { timeout_stop = 0; return SALTS_ETIMEDOUT; }
    return __real_cnet_client_stop(client, timeout_ms);
}
int __real_p2p_crypto_generate_identity(p2p_identity_t *);
int __wrap_p2p_crypto_generate_identity(p2p_identity_t *identity) {
    if (fail_identity) { fail_identity = 0; return P2P_ERR_CRYPTO; }
    return __real_p2p_crypto_generate_identity(identity);
}
void *__real_calloc(size_t, size_t);
void *__wrap_calloc(size_t count, size_t size) {
    if (fail_alloc_at && ++allocations == fail_alloc_at) return NULL;
    return __real_calloc(count, size);
}
static void test_create_errors(void) {
    p2p_node_t *node = NULL;
    for (unsigned fail = 1; fail <= 2; ++fail) {
        allocations = 0; fail_alloc_at = fail;
        check_equal(P2P_ERR_NO_MEM, p2p_create_v2("127.0.0.1", 0, &node));
        check_true(node == NULL);
        fail_alloc_at = 0;
    }
    fail_identity = 1;
    check_equal(P2P_ERR_CRYPTO, p2p_create_v2("127.0.0.1", 0, &node));
    check_true(node == NULL);
    check_equal(P2P_OK, p2p_create_v2("127.0.0.1", 0, &node));
    check_equal(P2P_OK, p2p_destroy_v2(node));
}
static void test_destroy_timeout(void) {
    pair_t pair = {0};
    start_pair(&pair, 7);
    wait_ready(&pair);
    timeout_stop = 1;
    check_equal(P2P_ERR_TIMEOUT, p2p_destroy_v2(pair.client.node));
    check_not_null(pair.client.node->runtime_v2);
    check_equal(P2P_ERR_INVALID_STATE, p2p_poll(pair.client.node));
    destroy_pair(&pair);
}
#endif
spec("Public CNet node lifecycle") {
    it("owns unstarted state, makes stop terminal, and rejects mixed lifecycle handles") { test_unstarted(); }
    it("preserves identity and state for corrected security or pre-attachment config") { test_start_correction(); }
    it("makes listener failure terminal without disturbing the existing listener") { test_listener_failure(P2P_ERR_NETWORK); }
    it("authenticates, exchanges fragmented messages and replicates DHT through public APIs") { test_roundtrip(); }
    it("defers public callback stop and rejects callback destruction") { test_callback_stop(); }
    it("transfers a real multichunk file with public construction and destruction") { test_file(0, 0); }
    it("defers public stop from file completion until the handler releases its lease") { test_file(1, 0); }
    it("retains the running node after a detached transfer lease blocks destruction") { test_file(0, 1); }
    it("retains unstarted state and lifecycle until the last transfer lease is released") { test_unstarted_lease(); }
#ifdef P2P_LIFECYCLE_TEST_WRAP
    it("reports cleanup timeout after listener failure and retains storage for retry") { test_listener_failure(P2P_ERR_TIMEOUT); }
    it("returns allocation and identity errors without publishing a partial node") { test_create_errors(); }
    it("retains the public node after a drain timeout and completes destruction on retry") { test_destroy_timeout(); }
#endif
}
