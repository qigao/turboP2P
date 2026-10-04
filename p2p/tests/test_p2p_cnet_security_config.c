#define TEST_SEND_BYTES (2 * 1024 * 1024)
#include "p2p_cnet_node_fixture.h"

static int synchronous_x25519(void *context, const uint8_t remote[32], uint8_t output[32]) {
    endpoint_t *endpoint = context;
    atomic_fetch_add(&endpoint->calls, 1);
    crypto_x25519(output, endpoint->secret, remote);
    return P2P_OK;
}
static int reject_build(void *context, const uint8_t key[32], uint8_t *output,
    size_t capacity, size_t *length, p2p_authenticated_identity_v2_t *identity) {
    (void)key; (void)output; (void)capacity; (void)length; (void)identity;
    endpoint_t *endpoint = context;
    atomic_fetch_add(&endpoint->calls, 1);
    return P2P_ERR_IO;
}
static p2p_node_security_status_v3_t status_of(p2p_node_t *node) {
    p2p_node_security_status_v3_t status = {0};
    status.struct_size = sizeof(status);
    check_equal(P2P_OK, p2p_node_get_security_status_v3(node, &status));
    return status;
}
static void test_configuration_transaction(void) {
    endpoint_t endpoint = {0};
    p2p_node_security_status_v3_t status = {0};
    p2p_security_config_v2_t security = {0};
    p2p_private_key_provider_v3_t provider = {0};
    uint8_t key[32], id[P2P_HASH_SIZE];
    init_key_node(&endpoint, 17, 0);
    status.struct_size = sizeof(status);
    check_equal(P2P_ERR_INVALID_STATE, p2p_node_get_security_status_v3(endpoint.node, &status));
    check_equal(P2P_OK, p2p_node_get_id(endpoint.node, id));
    provider.struct_size = sizeof(provider);
    provider.get_public_key = public_key;
    provider.calculate_x25519 = synchronous_x25519;
    provider.context = &endpoint;
    endpoint.public_key[0] ^= 1;
    check_equal(P2P_ERR_CRYPTO, p2p_node_set_private_key_provider_v3(endpoint.node, &provider));
    endpoint.public_key[0] ^= 1;
    check_equal(P2P_OK, p2p_node_get_public_key(endpoint.node, key));
    check_equal(key, endpoint.public_key, sizeof(key));
    security.struct_size = sizeof(security);
    memset(security.network_id_hash, 9, sizeof(security.network_id_hash));
    security.identity_provider.build_local_credential = reject_build;
    security.identity_provider.verify_remote_credential = verify;
    security.identity_provider.context = &endpoint;
    security.send_hwm_bytes = 1;
    atomic_store(&endpoint.calls, 0);
    check_equal(P2P_ERR_INVALID_ARG, p2p_node_configure_security_v2(endpoint.node, &security));
    check_equal(0, atomic_load(&endpoint.calls));
    security.send_hwm_bytes = 0;
    check_equal(P2P_ERR_IO, p2p_node_configure_security_v2(endpoint.node, &security));
    check_equal(1, atomic_load(&endpoint.calls));
    check_true(!endpoint.node->security_configured);
    check_equal(id, endpoint.node->id, sizeof(id));
    security.identity_provider.build_local_credential = build_credential;
    check_equal(P2P_OK, p2p_node_configure_security_v2(endpoint.node, &security));
    status = status_of(endpoint.node);
    check_equal((size_t)P2P_SECURITY_NODE_SEND_BUDGET_DEFAULT_BYTES, status.security.send_budget_bytes);
    check_equal(P2P_ERR_INVALID_STATE, p2p_node_set_private_key(endpoint.node, endpoint.secret));
    check_equal(P2P_ERR_INVALID_STATE, p2p_node_configure_security_v2(endpoint.node, &security));
    check_equal(P2P_OK, p2p_node_state_destroy(endpoint.node));
}
static void test_provider_replacement(void) {
    endpoint_t endpoint = {0};
    p2p_private_key_executor_status_v4_t status = {0};
    uint8_t key[32];
    init_key_node(&endpoint, 17, 1);
    status.struct_size = sizeof(status);
    check_equal(P2P_OK, p2p_node_get_private_key_executor_status_v4(endpoint.node, &status));
    check_equal(1, status.accepting);
    check_equal((uint16_t)1, status.workers);
    check_equal((uint16_t)4, status.operation_capacity);
    p2p_private_key_executor_t *previous = endpoint.node->private_key_executor;
    p2p_blocking_private_key_provider_v4_t replacement = previous->provider;
    endpoint.public_key[0] ^= 1;
    check_equal(P2P_ERR_CRYPTO, p2p_node_set_blocking_private_key_provider_v4(endpoint.node, &replacement));
    endpoint.public_key[0] ^= 1;
    check_true(endpoint.node->private_key_executor == previous);
    check_equal(P2P_OK, p2p_node_set_private_key(endpoint.node, endpoint.secret));
    check_true(endpoint.node->private_key_executor == NULL);
    check_equal(P2P_ERR_INVALID_STATE, p2p_node_get_private_key_executor_status_v4(endpoint.node, &status));
    check_equal(P2P_OK, p2p_node_get_public_key(endpoint.node, key));
    check_equal(key, endpoint.public_key, sizeof(key));
    check_equal(P2P_OK, p2p_node_state_destroy(endpoint.node));
}
static void setup_pinned(pair_t *pair, int synchronous_provider) {
    uint8_t network[32] = {9};
    pair->client.remote = &pair->server;
    pair->server.remote = &pair->client;
    init_key_node(&pair->client, 17, 0);
    init_key_node(&pair->server, 33, 0);
    if (synchronous_provider) {
        p2p_private_key_provider_v3_t provider = {0};
        provider.struct_size = sizeof(provider);
        provider.get_public_key = public_key;
        provider.calculate_x25519 = synchronous_x25519;
        provider.context = &pair->client;
        check_equal(P2P_OK, p2p_node_set_private_key_provider_v3(pair->client.node, &provider));
        check_equal(1, atomic_load(&pair->client.calls));
    }
    check_equal(P2P_OK, p2p_node_configure_pinned_security_v2(pair->client.node, network,
        pair->server.public_key, 1));
    check_equal(P2P_OK, p2p_node_configure_pinned_security_v2(pair->server.node, network,
        pair->client.public_key, 1));
    start_endpoint(&pair->client, TEST_SEND_BYTES);
    start_endpoint(&pair->server, TEST_SEND_BYTES);
    connect_pair(pair);
    wait_ready(pair);
}
static void test_pinned_trust(int synchronous_provider) {
    pair_t pair = {0};
    p2p_security_revalidation_result_v2_t result = {0};
    p2p_peer_security_info_v2_t peer = {0};
    setup_pinned(&pair, synchronous_provider);
    peer.struct_size = sizeof(peer);
    check_equal(P2P_OK, p2p_peer_get_security_info_v2(pair.client.peer, &peer));
    check_equal(peer.remote_noise_static, pair.server.public_key, sizeof(peer.remote_noise_static));
    check_equal(&peer.identity, &pair.server.node->local_authenticated_identity, sizeof(peer.identity));
    if (synchronous_provider) check_true(atomic_load(&pair.client.calls) > 1);
    result.struct_size = sizeof(result);
    check_equal(P2P_OK, p2p_node_update_pinned_trust_v2(pair.server.node,
        pair.client.public_key, 1, &result));
    check_equal((size_t)1, result.retained_sessions);
    check_equal((size_t)0, result.disconnected_sessions);
    check_equal(P2P_OK, p2p_node_update_pinned_trust_v2(pair.server.node, NULL, 0, &result));
    check_equal((size_t)1, result.provider_rejections);
    check_equal((size_t)1, result.disconnected_sessions);
    check_equal(0, p2p_get_peer_count(pair.server.node));
    check_equal(1, pair.server.disconnected);
    p2p_node_security_status_v3_t status = status_of(pair.server.node);
    check_equal((uint64_t)1, status.security.rejection_counts[P2P_SECURITY_REJECTION_REVALIDATION_REJECTED]);
    teardown(&pair);
}
static void test_blocking_configuration(void) {
    pair_t pair = {0};
    setup(&pair, 7, 1);
    connect_pair(&pair);
    wait_ready(&pair);
    p2p_node_security_status_v3_t status = status_of(pair.server.node);
    check_true(status.private_key_executor_available);
    check_true(status.private_key_executor.submitted > 0);
    check_equal(status.private_key_executor.submitted, status.private_key_executor.completed);
    check_equal((size_t)0, status.private_key_executor.active_operations);
    check_equal(P2P_OK, p2p_send(pair.client.node, pair.client.peer, "opaque", 6));
    uint64_t deadline = salts_monotonic_ms() + TEST_WAIT_MS;
    while (!pair.server.messages && salts_monotonic_ms() < deadline) pump(&pair);
    check_equal(1, pair.server.messages);
    p2p_peer_info_t peer_info;
    check_equal(P2P_OK, p2p_get_peer_info(pair.client.node, 0, &peer_info));
    check_true(peer_info.is_connected);
    teardown(&pair);
}
typedef struct {
    p2p_node_t *node;
    atomic_int stop, reads, errors;
} status_reader_t;
static void read_status(void *context) {
    status_reader_t *reader = context;
    uint64_t previous_challenges = 0, previous_verified = 0;
    while (!atomic_load(&reader->stop)) {
        p2p_node_security_status_v3_t status = {0};
        status.struct_size = sizeof(status);
        int invalid = p2p_node_get_security_status_v3(reader->node, &status) != P2P_OK;
        invalid |= status.security.active_cookie_gates > status.security.cookie_gate_limit;
        invalid |= status.security.reserved_send_capacity_bytes > status.security.send_budget_bytes;
        invalid |= status.security.cookie_challenges_issued < previous_challenges;
        invalid |= status.security.cookie_verifications_succeeded < previous_verified;
        previous_challenges = status.security.cookie_challenges_issued;
        previous_verified = status.security.cookie_verifications_succeeded;
        for (size_t role = 0; role < P2P_SECURITY_HANDSHAKE_ROLE_COUNT_V3; ++role)
            for (size_t stage = 0; stage < P2P_SECURITY_HANDSHAKE_STAGE_COUNT_V3; ++stage) {
                uint64_t sum = 0;
                for (size_t bucket = 0; bucket < P2P_SECURITY_LATENCY_BUCKET_COUNT_V3; ++bucket)
                    sum += status.handshake_latency[role][stage].buckets[bucket];
                invalid |= sum != status.handshake_latency[role][stage].completed;
            }
        if (invalid) atomic_fetch_add(&reader->errors, 1);
        atomic_fetch_add(&reader->reads, 1);
        salts_thread_yield();
    }
}
static void test_status_handoff(void) {
    pair_t pair = {0};
    status_reader_t reader = {0};
    salts_thread_t thread;
    setup(&pair, 7, 0);
    reader.node = pair.server.node;
    atomic_init(&reader.stop, 0); atomic_init(&reader.reads, 0); atomic_init(&reader.errors, 0);
    check_equal(0, salts_thread_create(&thread, read_status, &reader));
    connect_pair(&pair);
    p2p_node_security_status_v3_t status;
    uint64_t deadline = salts_monotonic_ms() + TEST_WAIT_MS;
    do {
        pump(&pair);
        status = status_of(pair.server.node);
    } while (!status.security.active_cookie_gates && salts_monotonic_ms() < deadline);
    check_equal((size_t)1, status.security.active_cookie_gates);
    wait_ready(&pair);
    status = status_of(pair.server.node);
    check_equal((uint64_t)1, status.security.cookie_challenges_issued);
    check_equal((uint64_t)1, status.security.cookie_verifications_succeeded);
    check_equal((size_t)0, status.security.active_cookie_gates);
    check_equal((uint64_t)0, pair.server.node->cookie_verifications_succeeded);
    for (size_t stage = 0; stage < P2P_SECURITY_HANDSHAKE_STAGE_COUNT_V3; ++stage)
        check_equal((uint64_t)1, status.handshake_latency[P2P_SECURITY_HANDSHAKE_ROLE_RESPONDER_V3][stage].completed);
    check_equal(P2P_OK, p2p_node_cnet_destroy(pair.server.owner));
    pair.server.owner = NULL;
    pair.server.stopped = 1;
    status = status_of(pair.server.node);
    check_equal((uint64_t)1, status.security.cookie_verifications_succeeded);
    check_equal((uint64_t)1, pair.server.node->cookie_verifications_succeeded);
    check_equal((size_t)0, status.security.reserved_send_capacity_bytes);
    atomic_store(&reader.stop, 1);
    check_equal(0, salts_thread_join(&thread));
    salts_thread_destroy(&thread);
    check_true(atomic_load(&reader.reads) > 0);
    check_equal(0, atomic_load(&reader.errors));
    p2p_cnet_config_t transport = config(TEST_SEND_BYTES);
    check_equal(P2P_ERR_INVALID_STATE, p2p_node_cnet_create(pair.server.node, &transport, &pair.server.owner));
    check_true(pair.server.owner == NULL);
    teardown(&pair);
}
static void test_identity_revalidation(void) {
    pair_t pair = {0};
    p2p_security_revalidation_result_v2_t result = {0};
    setup(&pair, TEST_SEND_BYTES, 0);
    connect_pair(&pair);
    wait_ready(&pair);
    pair.server.expected_identity.trust_epoch++;
    result.struct_size = sizeof(result);
    check_equal(P2P_OK, p2p_node_revalidate_security_v2(pair.client.node, &result));
    check_equal((size_t)1, result.identity_changes);
    check_equal((size_t)1, result.disconnected_sessions);
    check_equal(0, p2p_get_peer_count(pair.client.node));
    p2p_node_security_status_v3_t status = status_of(pair.client.node);
    check_equal((uint64_t)1, status.security.rejection_counts[P2P_SECURITY_REJECTION_REVALIDATION_IDENTITY_CHANGE]);
    teardown(&pair);
}

static void test_transport_capacity(void) {
    endpoint_t endpoint = {0};
    p2p_cnet_config_t transport = config(7);
    init_node(&endpoint, 17, 0);
    transport.send_hwm_bytes = endpoint.node->security_config.send_hwm_bytes - 1;
    check_equal(P2P_ERR_INVALID_ARG, p2p_node_cnet_create(endpoint.node, &transport, &endpoint.owner));
    check_true(endpoint.owner == NULL);
    check_true(endpoint.node->network_context == NULL);
    check_equal(P2P_OK, p2p_node_state_destroy(endpoint.node));
}

spec("P2P security configuration and status over CNet") {
    it("leaves identity and policy unchanged after provider or configuration failure") { test_configuration_transaction(); }
    it("replaces a polled blocking executor before security configuration") { test_provider_replacement(); }
    it("authenticates pinned keys and revalidates retained and revoked trust") { test_pinned_trust(0); }
    it("uses a synchronous opaque provider through the real pinned handshake") { test_pinned_trust(1); }
    it("uses public blocking-provider configuration and reports actual worker completion") { test_blocking_configuration(); }
    it("reports live gates and stage timing atomically across owner destruction") { test_status_handoff(); }
    it("disconnects an established session when its verified identity changes") { test_identity_revalidation(); }
    it("rejects a transport that cannot honor the configured per-peer send capacity") { test_transport_capacity(); }
}
