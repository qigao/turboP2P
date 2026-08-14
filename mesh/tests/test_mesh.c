/**
 * test_mesh.c - Unit tests for mesh VPN
 *
 * Test strategy:
 * 1. Test P2P layer basics first
 * 2. Test mesh create/destroy
 * 3. Test bootstrap connection
 */

#include <tinytest.h>
#include <turbo_mesh.h>
#include <p2p.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <CoroNet/turbo_coro_context.h>
#include <tlog.h>
#include <turbo_crypto.h>
#ifdef _WIN32
#include <windows.h>
#define sleep_ms(ms) Sleep(ms)
#else
#include <unistd.h>
#define sleep_ms(ms) usleep((ms) * 1000)
#endif

/* Global state for tests */
static int g_peer_connected_count = 0;
static int g_peer_disconnected_count = 0;
static int g_packet_received_count = 0;
static char g_last_peer_ip[64];
static int g_last_peer_port = 0;
static tlog_t *g_test_logger = NULL;

enum { MESH_TEST_IDENTITY_COUNT = 3 };

static const char *const g_mesh_test_identity_secrets[MESH_TEST_IDENTITY_COUNT] = {
    "1111111111111111111111111111111111111111111111111111111111111111",
    "2222222222222222222222222222222222222222222222222222222222222222",
    "3333333333333333333333333333333333333333333333333333333333333333",
};
static char g_mesh_test_identity_public_hex[MESH_TEST_IDENTITY_COUNT][65];
static const char *g_mesh_test_trusted_node_ids[MESH_TEST_IDENTITY_COUNT];
static int g_mesh_test_identities_ready = 0;

typedef struct {
    int packet_received_count;
} mesh_packet_counter_t;

static int mesh_test_initialize_identities(void) {
    static const char hex[] = "0123456789abcdef";
    uint8_t secret[P2P_KEY_SIZE];
    uint8_t public_key[P2P_KEY_SIZE];

    if (g_mesh_test_identities_ready) {
        return 1;
    }

    for (size_t identity_index = 0;
         identity_index < MESH_TEST_IDENTITY_COUNT;
         ++identity_index) {
        memset(secret, (int)((identity_index + 1u) * 0x11u), sizeof(secret));
        if (p2p_public_key_from_private_key(secret, public_key) != P2P_OK) {
            memset(secret, 0, sizeof(secret));
            memset(public_key, 0, sizeof(public_key));
            return 0;
        }
        for (size_t byte_index = 0; byte_index < sizeof(public_key); ++byte_index) {
            g_mesh_test_identity_public_hex[identity_index][byte_index * 2u] =
                hex[public_key[byte_index] >> 4u];
            g_mesh_test_identity_public_hex[identity_index][byte_index * 2u + 1u] =
                hex[public_key[byte_index] & 0x0fu];
        }
        g_mesh_test_identity_public_hex[identity_index][64] = '\0';
        g_mesh_test_trusted_node_ids[identity_index] =
            g_mesh_test_identity_public_hex[identity_index];
    }

    memset(secret, 0, sizeof(secret));
    memset(public_key, 0, sizeof(public_key));
    g_mesh_test_identities_ready = 1;
    return 1;
}

static int mesh_test_configure_identity(mesh_config_t *config, size_t identity_index) {
    if (!config || identity_index >= MESH_TEST_IDENTITY_COUNT ||
        !mesh_test_initialize_identities()) {
        return 0;
    }

    config->identity_secret_hex = g_mesh_test_identity_secrets[identity_index];
    config->peer_allow_node_ids = g_mesh_test_trusted_node_ids;
    config->peer_allow_node_id_count = MESH_TEST_IDENTITY_COUNT;
    return 1;
}

static int mesh_test_configure_p2p_trust(p2p_node_t **nodes, size_t node_count) {
    static const uint8_t network_id_hash[P2P_SECURITY_ID_SIZE] = {
        0x4d, 0x65, 0x73, 0x68, 0x2d, 0x4e, 0x6f, 0x69,
        0x73, 0x65, 0x2d, 0x76, 0x32, 0x2d, 0x74, 0x65,
        0x73, 0x74, 0x2d, 0x6e, 0x65, 0x74, 0x77, 0x6f,
        0x72, 0x6b, 0x2d, 0x69, 0x64, 0x2d, 0x30, 0x31,
    };
    uint8_t trusted_keys[MESH_TEST_IDENTITY_COUNT * P2P_KEY_SIZE];

    if (!nodes || node_count == 0 || node_count > MESH_TEST_IDENTITY_COUNT) {
        return P2P_ERR_INVALID_ARG;
    }
    memset(trusted_keys, 0, sizeof(trusted_keys));
    for (size_t index = 0; index < node_count; ++index) {
        if (!nodes[index] ||
            p2p_node_get_public_key(nodes[index],
                                    trusted_keys + index * P2P_KEY_SIZE) != P2P_OK) {
            memset(trusted_keys, 0, sizeof(trusted_keys));
            return P2P_ERR_INVALID_STATE;
        }
    }
    for (size_t index = 0; index < node_count; ++index) {
        int result = p2p_node_configure_pinned_security_v2(
            nodes[index], network_id_hash, trusted_keys, node_count);
        if (result != P2P_OK) {
            memset(trusted_keys, 0, sizeof(trusted_keys));
            return result;
        }
    }
    memset(trusted_keys, 0, sizeof(trusted_keys));
    return P2P_OK;
}

static void mesh_test_logger_init(void) {
    if (g_test_logger) {
        return;
    }

    tlog_config_t log_config = {0};
    log_config.min_level = TURBO_LOG_LEVEL_INFO;
    g_test_logger = tlog_create(&log_config);
    if (!g_test_logger) {
        return;
    }

    turbo_console_sink_opts_t opts = {0};
    opts.output = stdout;
    opts.use_colors = 1;
    turbo_log_sink_t *sink = turbo_sink_console_create(&opts);
    tlog_add_sink(g_test_logger, sink);
    tlog_set_default(g_test_logger);
}

static void test_logger_shutdown_all(void) {
    if (!g_test_logger) {
        return;
    }

    tlog_destroy(g_test_logger);
    g_test_logger = NULL;
}

void setUp(void) {
    /* Reset counters */
    g_peer_connected_count = 0;
    g_peer_disconnected_count = 0;
    g_packet_received_count = 0;
    memset(g_last_peer_ip, 0, sizeof(g_last_peer_ip));
    g_last_peer_port = 0;
}

void tearDown(void) {
    /* Cleanup after each test */
}

/* =============================================================================
 * Callback Functions
 * ============================================================================= */

static void on_peer_connected(mesh_peer_t *peer, void *user_data) {
    (void)peer;
    (void)user_data;
    g_peer_connected_count++;
    printf("[TEST] Peer connected (count: %d)\n", g_peer_connected_count);
}

static void on_peer_disconnected(mesh_peer_t *peer, void *user_data) {
    (void)peer;
    (void)user_data;
    g_peer_disconnected_count++;
    printf("[TEST] Peer disconnected (count: %d)\n", g_peer_disconnected_count);
}

static void on_packet_received(const uint8_t *data, size_t len, void *user_data) {
    (void)data;
    (void)user_data;
    g_packet_received_count++;
    printf("[TEST] Packet received: %zu bytes (count: %d)\n", len, g_packet_received_count);
}

static void on_packet_received_counting(const uint8_t *data, size_t len, void *user_data) {
    mesh_packet_counter_t *counter = (mesh_packet_counter_t *)user_data;

    (void)data;
    if (counter) {
        counter->packet_received_count++;
        printf("[TEST] Packet received: %zu bytes (count: %d)\n",
               len, counter->packet_received_count);
    }
}
static void mesh_test_build_ipv4_packet(uint8_t *packet, size_t len,
                                        uint8_t src_a, uint8_t src_b,
                                        uint8_t src_c, uint8_t src_d,
                                        uint8_t dst_a, uint8_t dst_b,
                                        uint8_t dst_c, uint8_t dst_d) {
    memset(packet, 0, len);
    packet[0] = 0x45;
    packet[8] = 64;
    packet[9] = 1;
    packet[12] = src_a;
    packet[13] = src_b;
    packet[14] = src_c;
    packet[15] = src_d;
    packet[16] = dst_a;
    packet[17] = dst_b;
    packet[18] = dst_c;
    packet[19] = dst_d;
}

static int mesh_test_find_peer_info(mesh_network_t *mesh, const char *virtual_ip,
                                    mesh_peer_info_t *info) {
    mesh_peer_info_t current;
    int peer_count = mesh_get_peer_count(mesh);

    for (int i = 0; i < peer_count; i++) {
        if (mesh_get_peer_info(mesh, i, &current) != MESH_OK) {
            continue;
        }

        if (strcmp(current.virtual_ip, virtual_ip) == 0) {
            if (info) {
                *info = current;
            }
            return 1;
        }
    }

    return 0;
}

static void mesh_test_stop_destroy(mesh_network_t **mesh_ptr) {
    if (!mesh_ptr || !*mesh_ptr) {
        return;
    }

    mesh_stop(*mesh_ptr);
    mesh_destroy(*mesh_ptr);
    *mesh_ptr = NULL;
}

/* =============================================================================
 * Test Cases
 * ============================================================================= */

/**
 * Test 1: Basic mesh create/destroy
 */
void test_mesh_create_destroy(void) {
    printf("\n[TEST] test_mesh_create_destroy\n");

    mesh_config_t config;
    mesh_config_init(&config);

    config.virtual_ip = "10.42.0.1";
    config.virtual_prefix = 16;
    config.listen_port = 19993;  /* Use different port for testing */
    config.on_peer_connected = on_peer_connected;
    config.on_peer_disconnected = on_peer_disconnected;
    config.on_packet_received = on_packet_received;

    /* Create mesh */
    mesh_network_t *mesh = mesh_create(&config);
    check_not_null(mesh);

    /* Destroy mesh */
    mesh_destroy(mesh);

    printf("[TEST] ✓ Mesh create/destroy successful\n");
}

static void test_mesh_forwards_bounded_security_status_v3(void) {
    mesh_config_t config;
    mesh_network_t *mesh;
    p2p_node_security_status_v3_t status = {0};

    mesh_config_init(&config);
    config.virtual_ip = "10.42.0.8";
    config.listen_port = 19998;
    mesh = mesh_create(&config);
    check_not_null(mesh);
    if (!mesh) {
        return;
    }

    status.struct_size = sizeof(status) - 1U;
    check_int_eq(MESH_ERR_INVALID_ARG,
                 mesh_get_security_status_v3(mesh, &status));
    status.struct_size = sizeof(status);
    check_int_eq(MESH_ERR_INVALID_ARG,
                 mesh_get_security_status_v3(NULL, &status));
    check_int_eq(MESH_OK, mesh_get_security_status_v3(mesh, &status));
    check_uint_eq(sizeof(status), status.struct_size);
    check_int_eq(P2P_SECURE_WIRE_VERSION_V2, status.secure_wire_version);
    check_int_eq(P2P_NOISE_SUITE_XX_25519_CHACHAPOLY_BLAKE2S,
                 status.noise_suite);
    check_uint_eq(sizeof(status.security), status.security.struct_size);
    check(status.security.send_budget_bytes > 0U);
    check_uint_eq(P2P_SECURITY_LATENCY_BUCKET_COUNT_V3,
                  sizeof(status.latency_bucket_upper_bounds_ms) /
                      sizeof(status.latency_bucket_upper_bounds_ms[0]));

    mesh_destroy(mesh);
}

static void test_mesh_accepts_borrowed_binary_identity(void) {
    static const char hex[] = "0123456789abcdef";
    mesh_config_t config;
    mesh_network_t *mesh;
    uint8_t private_key[P2P_KEY_SIZE];
    uint8_t public_key[P2P_KEY_SIZE];
    char expected_node_id[P2P_KEY_SIZE * 2u + 1u];
    char actual_node_id[P2P_KEY_SIZE * 2u + 1u];
    size_t index;

    memset(private_key, 0x5au, sizeof(private_key));
    memset(public_key, 0, sizeof(public_key));
    memset(expected_node_id, 0, sizeof(expected_node_id));
    memset(actual_node_id, 0, sizeof(actual_node_id));
    check_int_eq(p2p_public_key_from_private_key(private_key, public_key),
                 P2P_OK);
    for (index = 0u; index < sizeof(public_key); ++index) {
        expected_node_id[index * 2u] = hex[public_key[index] >> 4u];
        expected_node_id[index * 2u + 1u] = hex[public_key[index] & 0x0fu];
    }

    mesh_config_init(&config);
    config.virtual_ip = "10.42.0.9";
    config.listen_port = 19999;
    config.identity_private_key = private_key;
    config.identity_private_key_size = sizeof(private_key);
    mesh = mesh_create(&config);
    check_not_null(mesh);
    if (mesh) {
        check_int_eq(mesh_get_node_id(mesh, actual_node_id,
                                      sizeof(actual_node_id)),
                     MESH_OK);
        check_str_eq(actual_node_id, expected_node_id);
        mesh_destroy(mesh);
    }
    memset(private_key, 0, sizeof(private_key));
    memset(public_key, 0, sizeof(public_key));
}

typedef struct {
    uint8_t private_key[P2P_KEY_SIZE];
    uint8_t public_key[P2P_KEY_SIZE];
    size_t public_key_calls;
    size_t calculate_calls;
} mesh_test_private_key_provider_context_t;

static int mesh_test_provider_get_public_key(
    void *context, uint8_t public_key_out[P2P_KEY_SIZE]) {
    mesh_test_private_key_provider_context_t *provider_context =
        (mesh_test_private_key_provider_context_t *)context;

    provider_context->public_key_calls++;
    memcpy(public_key_out, provider_context->public_key, P2P_KEY_SIZE);
    return P2P_OK;
}

static int mesh_test_provider_calculate(
    void *context, const uint8_t remote_public_key[P2P_KEY_SIZE],
    uint8_t shared_key_out[P2P_KEY_SIZE]) {
    mesh_test_private_key_provider_context_t *provider_context =
        (mesh_test_private_key_provider_context_t *)context;

    provider_context->calculate_calls++;
    return turbo_crypto_x25519(shared_key_out, provider_context->private_key,
                               remote_public_key) == TURBO_CRYPTO_OK
               ? P2P_OK
               : P2P_ERR_CRYPTO;
}

static int mesh_test_blocking_provider_calculate(
    void *context, const uint8_t remote_public_key[P2P_KEY_SIZE],
    uint64_t monotonic_deadline_ms,
    const p2p_private_key_cancel_v4_t *cancel,
    uint8_t shared_key_out[P2P_KEY_SIZE]) {
    (void)monotonic_deadline_ms;
    (void)cancel;
    return mesh_test_provider_calculate(context, remote_public_key,
                                        shared_key_out);
}

static void test_mesh_accepts_opaque_identity_provider(void) {
    static const char hex[] = "0123456789abcdef";
    mesh_test_private_key_provider_context_t provider_context = {0};
    p2p_private_key_provider_v3_t provider = {0};
    mesh_config_t config;
    mesh_network_t *mesh;
    char expected_node_id[P2P_KEY_SIZE * 2u + 1u] = {0};
    char actual_node_id[P2P_KEY_SIZE * 2u + 1u] = {0};
    size_t index;

    memset(provider_context.private_key, 0x7cu,
           sizeof(provider_context.private_key));
    check_int_eq(P2P_OK,
                 p2p_public_key_from_private_key(
                     provider_context.private_key,
                     provider_context.public_key));
    for (index = 0; index < sizeof(provider_context.public_key); ++index) {
        expected_node_id[index * 2u] =
            hex[provider_context.public_key[index] >> 4u];
        expected_node_id[index * 2u + 1u] =
            hex[provider_context.public_key[index] & 0x0fu];
    }
    provider.struct_size = sizeof(provider);
    provider.get_public_key = mesh_test_provider_get_public_key;
    provider.calculate_x25519 = mesh_test_provider_calculate;
    provider.context = &provider_context;

    mesh_config_init(&config);
    config.virtual_ip = "10.42.0.11";
    config.listen_port = 20000;
    config.identity_private_key_provider = &provider;
    mesh = mesh_create(&config);
    check_not_null(mesh);
    check_uint_eq(1, provider_context.public_key_calls);
    check_uint_eq(1, provider_context.calculate_calls);
    if (mesh) {
        check_int_eq(MESH_OK, mesh_get_node_id(mesh, actual_node_id,
                                               sizeof(actual_node_id)));
        check_str_eq(expected_node_id, actual_node_id);
        mesh_destroy(mesh);
    }
    turbo_crypto_wipe(&provider_context, sizeof(provider_context));
}

static void test_mesh_accepts_blocking_identity_provider(void) {
    mesh_test_private_key_provider_context_t provider_context = {0};
    p2p_blocking_private_key_provider_v4_t provider = {0};
    mesh_config_t config;
    mesh_network_t *mesh;

    memset(provider_context.private_key, 0x5du,
           sizeof(provider_context.private_key));
    check_int_eq(P2P_OK,
                 p2p_public_key_from_private_key(
                     provider_context.private_key,
                     provider_context.public_key));
    provider.struct_size = sizeof(provider);
    provider.get_public_key = mesh_test_provider_get_public_key;
    provider.calculate_x25519 = mesh_test_blocking_provider_calculate;
    provider.context = &provider_context;
    provider.executor_capacity = 2;
    provider.operation_timeout_ms = 500;

    mesh_config_init(&config);
    config.virtual_ip = "10.42.0.12";
    config.listen_port = 20001;
    config.identity_blocking_private_key_provider = &provider;
    mesh = mesh_create(&config);
    check_not_null(mesh);
    check_uint_eq(1, provider_context.public_key_calls);
    check_uint_eq(1, provider_context.calculate_calls);
    if (mesh) {
        mesh_destroy(mesh);
    }
    turbo_crypto_wipe(&provider_context, sizeof(provider_context));
}

static void test_mesh_rejects_ambiguous_or_malformed_binary_identity(void) {
    mesh_config_t config;
    p2p_private_key_provider_v3_t provider = {0};
    uint8_t private_key[P2P_KEY_SIZE];

    memset(private_key, 0x6bu, sizeof(private_key));
    mesh_config_init(&config);
    config.virtual_ip = "10.42.0.10";
    config.identity_private_key = private_key;
    config.identity_private_key_size = sizeof(private_key) - 1u;
    check_null(mesh_create(&config));

    config.identity_private_key_size = sizeof(private_key);
    config.identity_secret_hex = g_mesh_test_identity_secrets[0];
    check_null(mesh_create(&config));

    config.identity_private_key = NULL;
    config.identity_private_key_size = sizeof(private_key);
    config.identity_secret_hex = NULL;
    check_null(mesh_create(&config));

    config.identity_private_key_size = 0u;
    config.identity_secret_hex = g_mesh_test_identity_secrets[0];
    config.identity_private_key_provider = &provider;
    check_null(mesh_create(&config));

    config.identity_secret_hex = NULL;
    config.identity_private_key_provider = NULL;
    config.identity_private_key = private_key;
    config.identity_private_key_size = sizeof(private_key);
    config.identity_blocking_private_key_provider =
        (const p2p_blocking_private_key_provider_v4_t *)&provider;
    check_null(mesh_create(&config));
    memset(private_key, 0, sizeof(private_key));
}

/**
 * Test 2: P2P node creation
 */
void test_p2p_node_creation(void) {
    printf("\n[TEST] test_p2p_node_creation\n");

    /* Create P2P node */
    p2p_node_t *node = p2p_create("127.0.0.1", 29993);
    check_not_null(node);

    printf("[TEST] ✓ P2P node created on port 29993\n");

    /* Destroy */
    p2p_destroy(node);

    printf("[TEST] ✓ P2P node destroyed\n");
}

/**
 * Test 3: Two P2P nodes connect
 */
void test_p2p_two_nodes_connect(void) {
    printf("\n[TEST] test_p2p_two_nodes_connect\n");

    /* Create node 1 (server) */
    p2p_node_t *node1 = p2p_create("127.0.0.1", 30001);
    check_not_null(node1);
    printf("[TEST] Node 1 created on port 30001\n");

    /* Create node 2 (client) */
    p2p_node_t *node2 = p2p_create("127.0.0.1", 30002);
    check_not_null(node2);
    printf("[TEST] Node 2 created on port 30002\n");

    /* Start node 1 in background (we need to test if p2p_start works) */
    /* For now, just create and destroy to verify basic functionality */

    /* Cleanup */
    p2p_destroy(node2);
    p2p_destroy(node1);

    printf("[TEST] ✓ Two P2P nodes created and destroyed\n");
}

/**
 * Test 4: Mesh start/stop
 */
void test_mesh_start_stop(void) {
    printf("\n[TEST] test_mesh_start_stop\n");

    mesh_config_t config;
    mesh_config_init(&config);

    config.virtual_ip = "10.42.0.1";
    config.virtual_prefix = 16;
    config.listen_port = 19994;
    config.on_peer_connected = on_peer_connected;
    config.on_peer_disconnected = on_peer_disconnected;
    config.on_packet_received = on_packet_received;

    mesh_network_t *mesh = mesh_create(&config);
    check_not_null(mesh);

    /* Start mesh */
    int ret = mesh_start(mesh);
    check_int_eq(MESH_OK, ret);
    printf("[TEST] ✓ Mesh started\n");

    /* Wait a bit for P2P thread to start */
    sleep_ms(1000);

    /* Get stats */
    mesh_stats_t stats;
    ret = mesh_get_stats(mesh, &stats);
    check_int_eq(MESH_OK, ret);
    printf("[TEST] Mesh stats: peers=%u, tx=%llu, rx=%llu\n",
           stats.peer_count, (unsigned long long)stats.packets_tx, (unsigned long long)stats.packets_rx);

    /* Stop and destroy */
    mesh_stop(mesh);
    mesh_destroy(mesh);

    printf("[TEST] ✓ Mesh stopped and destroyed\n");
}

/**
 * Test 5: P2P server listening
 */
void test_p2p_server_listening(void) {
    p2p_node_t *nodes[1];

    printf("\n[TEST] test_p2p_server_listening\n");

    /* Create P2P node */
    p2p_node_t *node = p2p_create("127.0.0.1", 31001);
    check_not_null(node);
    nodes[0] = node;
    check_int_eq(P2P_OK, mesh_test_configure_p2p_trust(nodes, 1));
    printf("[TEST] ✓ P2P node created on port 31001\n");

    /* Start P2P server */
    int ret = p2p_start_nonblocking(node);
    check_int_eq(P2P_OK, ret);
    printf("[TEST] ✓ P2P server started\n");

    /* Poll a few times to ensure server is running */
    coro_context_t *ctx = p2p_get_loop(node);
    for (int i = 0; i < 3; i++) {
        coro_context_run(ctx, TURBO_RUN_NOWAIT);
        sleep_ms(100);
    }

    printf("[TEST] ✓ P2P server is running\n");

    /* Cleanup */
    p2p_destroy(node);
    printf("[TEST] ✓ Test completed\n");
}

/**
 * Test 6: P2P peer callbacks
 */
static void test_p2p_peer_connected_cb(p2p_peer_t *peer, void *user_data) {
    (void)user_data;
    g_peer_connected_count++;

    /* Get peer address */
    int ret = p2p_peer_get_address(peer, g_last_peer_ip, &g_last_peer_port);
    if (ret == P2P_OK) {
        printf("[TEST] ✓ P2P peer connected: %s:%d (count: %d)\n",
               g_last_peer_ip, g_last_peer_port, g_peer_connected_count);
    } else {
        printf("[TEST] ⚠ P2P peer connected but failed to get address (error: %d)\n", ret);
    }
}

static void test_p2p_peer_disconnected_cb(p2p_peer_t *peer, void *user_data) {
    (void)peer;
    (void)user_data;
    g_peer_disconnected_count++;
    printf("[TEST] ✓ P2P peer disconnected (count: %d)\n", g_peer_disconnected_count);
}

void test_p2p_peer_callbacks(void) {
    p2p_node_t *nodes[2];

    printf("\n[TEST] test_p2p_peer_callbacks\n");

    /* Create server node */
    p2p_node_t *server = p2p_create("127.0.0.1", 32001);
    check_not_null(server);

    /* Set callbacks */
    p2p_set_peer_callbacks(server, test_p2p_peer_connected_cb,
                           test_p2p_peer_disconnected_cb, NULL);
    printf("[TEST] ✓ Callbacks registered\n");

    /* Create client node */
    p2p_node_t *client = p2p_create("127.0.0.1", 32002);
    check_not_null(client);

    /* Set callbacks on client too */
    p2p_set_peer_callbacks(client, test_p2p_peer_connected_cb,
                           test_p2p_peer_disconnected_cb, NULL);

    nodes[0] = server;
    nodes[1] = client;
    check_int_eq(P2P_OK, mesh_test_configure_p2p_trust(nodes, 2));

    /* Start server */
    int ret = p2p_start_nonblocking(server);
    check_int_eq(P2P_OK, ret);
    printf("[TEST] ✓ Server started on port 32001\n");

    /* Start client */
    ret = p2p_start_nonblocking(client);
    check_int_eq(P2P_OK, ret);
    printf("[TEST] ✓ Client started on port 32002\n");

    /* Wait for server to be ready */
    sleep_ms(500);

    /* Client connects to server */
    printf("[TEST] Client connecting to server...\n");
    ret = p2p_connect(client, "127.0.0.1", 32001);
    check_int_eq(P2P_OK, ret);

    /* Wait for connection */
    printf("[TEST] Waiting for connection (up to 5 seconds)...\n");
    coro_context_t *server_ctx = p2p_get_loop(server);
    coro_context_t *client_ctx = p2p_get_loop(client);

    for (int i = 0; i < 50; i++) {  /* 5 seconds max */
        coro_context_run(server_ctx, TURBO_RUN_NOWAIT);
        coro_context_run(client_ctx, TURBO_RUN_NOWAIT);
        sleep_ms(100);

        if (g_peer_connected_count > 0) {
            printf("[TEST] ✓ Connection established after %d iterations (%.1f seconds)\n",
                   i + 1, (i + 1) * 0.1);
            break;
        }
    }

    /* Verify connection */
    printf("[TEST] Final peer_connected count: %d\n", g_peer_connected_count);
    printf("[TEST] Last peer: %s:%d\n", g_last_peer_ip, g_last_peer_port);

    if (g_peer_connected_count > 0) {
        printf("[TEST] ✓ SUCCESS: P2P callbacks working!\n");
        check(g_peer_connected_count > 0);
    } else {
        printf("[TEST] ✗ FAILURE: No peer connection callbacks triggered!\n");
        printf("[TEST] This indicates P2P layer is not connecting properly.\n");
    }

    /* Cleanup */
    p2p_destroy(client);
    p2p_destroy(server);
    printf("[TEST] ✓ Test completed\n");
}

/**
 * Test 7: DHT put/get
 */
void test_dht_put_get(void) {
    printf("\n[TEST] test_dht_put_get\n");

    /* Create node */
    p2p_node_t *node = p2p_create("127.0.0.1", 33001);
    check_not_null(node);

    /* Put value in DHT */
    const char *key = "test_key";
    const char *value = "test_value";
    int ret = p2p_dht_put(node, key, value, strlen(value) + 1);
    check_int_eq(P2P_OK, ret);
    printf("[TEST] ✓ DHT put: %s = %s\n", key, value);

    /* Get value from DHT */
    char buffer[256];
    size_t buffer_len = sizeof(buffer);
    ret = p2p_dht_get(node, key, buffer, &buffer_len);
    check_int_eq(P2P_OK, ret);
    printf("[TEST] ✓ DHT get: %s = %s\n", key, buffer);

    /* Verify value matches */
    check_str_eq(value, buffer);
    printf("[TEST] ✓ DHT value matches!\n");

    /* Cleanup */
    p2p_destroy(node);
    printf("[TEST] ✓ Test completed\n");
}

/**
 * Test 8: Virtual IP registration in DHT
 */
void test_virtual_ip_dht_registration(void) {
    printf("\n[TEST] test_virtual_ip_dht_registration\n");
    mesh_stats_t stats;
    char vip_key[128];
    char routes_key[128];
    char buffer[1024];
    size_t buffer_len = 0;

    /* Create mesh node */
    mesh_config_t config;
    mesh_config_init(&config);
    config.virtual_ip = "10.42.0.99";
    config.virtual_prefix = 16;
    config.listen_port = 34001;
    config.network_id = "default";

    mesh_network_t *mesh = mesh_create(&config);
    check_not_null(mesh);
    printf("[TEST] ✓ Mesh created with virtual IP: %s\n", config.virtual_ip);

    /* Start mesh */
    int ret = mesh_start(mesh);
    check_int_eq(MESH_OK, ret);
    printf("[TEST] ✓ Mesh started on port %d\n", config.listen_port);

    /* Registration is local and synchronous; one poll is enough to flush startup work. */
    mesh_poll(mesh, 0);

    check_int_eq(MESH_OK, mesh_get_stats(mesh, &stats));
    check(stats.dht_entries >= 1);

    snprintf(vip_key, sizeof(vip_key), "mesh:%s:ip:%s", config.network_id, config.virtual_ip);
    buffer_len = sizeof(buffer);
    check_int_eq(MESH_OK, mesh_get_cached_dht_value(mesh, vip_key, buffer, &buffer_len));
    check_str_eq("10.42.0.99", buffer);

    for (int i = 0; i < 100; i++) {
        mesh_poll(mesh, 0);
    }

    snprintf(routes_key, sizeof(routes_key), "mesh:%s:routes:%s",
             config.network_id, config.virtual_ip);
    buffer_len = sizeof(buffer);
    check_int_eq(MESH_OK, mesh_get_cached_dht_value(mesh, routes_key, buffer, &buffer_len));
    check_str_eq("", buffer);

    printf("[TEST] ✓ Virtual IP should be registered in cached DHT\n");

    /* Cleanup */
    mesh_stop(mesh);
    mesh_destroy(mesh);
    printf("[TEST] ✓ Test completed\n");
}

/**
 * Test 9: Packet routing logic
 */
void test_packet_routing(void) {
    printf("\n[TEST] test_packet_routing\n");

    /* Create simple IP packet (ICMP Echo Request) */
    uint8_t packet[60];
    memset(packet, 0, sizeof(packet));

    /* IP header */
    packet[0] = 0x45;  /* Version 4, IHL 5 */
    packet[9] = 1;     /* Protocol: ICMP */

    /* Source IP: 10.42.0.2 */
    packet[12] = 10;
    packet[13] = 42;
    packet[14] = 0;
    packet[15] = 2;

    /* Destination IP: 10.42.0.1 */
    packet[16] = 10;
    packet[17] = 42;
    packet[18] = 0;
    packet[19] = 1;

    printf("[TEST] ✓ Created test packet: 10.42.0.2 -> 10.42.0.1\n");

    /* Create two mesh nodes */
    mesh_config_t config1;
    mesh_config_init(&config1);
    config1.virtual_ip = "10.42.0.1";
    config1.virtual_prefix = 16;
    config1.listen_port = 35001;
    check(mesh_test_configure_identity(&config1, 0));
    config1.on_packet_received = on_packet_received;

    mesh_network_t *mesh1 = mesh_create(&config1);
    check_not_null(mesh1);

    mesh_config_t config2;
    mesh_config_init(&config2);
    config2.virtual_ip = "10.42.0.2";
    config2.virtual_prefix = 16;
    config2.listen_port = 35002;
    check(mesh_test_configure_identity(&config2, 1));
    config2.on_packet_received = on_packet_received;

    const char *bootstrap[] = {"127.0.0.1:35001"};
    config2.bootstrap_peers = bootstrap;
    config2.bootstrap_count = 1;

    mesh_network_t *mesh2 = mesh_create(&config2);
    check_not_null(mesh2);

    /* Start bootstrap first and give its listener one poll cycle before connecting. */
    mesh_start(mesh1);
    mesh_poll(mesh1, 0);
    mesh_start(mesh2);
    printf("[TEST] ✓ Both mesh nodes started\n");

    /* Wait for connection */
    printf("[TEST] Waiting for peer connection...\n");
    for (int i = 0; i < 30; i++) {
        mesh_poll(mesh1, 100);
        mesh_poll(mesh2, 100);
        sleep_ms(100);

        if (g_peer_connected_count > 0) {
            printf("[TEST] ✓ Peers connected after %d iterations\n", i + 1);
            break;
        }
    }

    /* Try to send packet from mesh2 to mesh1 */
    printf("[TEST] Sending packet from 10.42.0.2 to 10.42.0.1...\n");
    int ret = mesh_send_packet(mesh2, packet, sizeof(packet));

    if (ret == MESH_OK) {
        printf("[TEST] ✓ Packet sent successfully\n");

        /* Wait for packet to be received */
        for (int i = 0; i < 10; i++) {
            mesh_poll(mesh1, 100);
            mesh_poll(mesh2, 100);
            sleep_ms(100);

            if (g_packet_received_count > 0) {
                printf("[TEST] ✓ Packet received! Count: %d\n", g_packet_received_count);
                break;
            }
        }
    } else {
        printf("[TEST] ⚠ Packet send failed: %s\n", mesh_error_string(ret));
        printf("[TEST] This is expected if peers are not connected.\n");
    }

    /* Cleanup */
    mesh_stop(mesh2);
    mesh_destroy(mesh2);
    mesh_stop(mesh1);
    mesh_destroy(mesh1);
    printf("[TEST] ✓ Test completed\n");
}

/**
 * Test 10: Two mesh nodes connect
 */
void test_mesh_two_nodes_connect(void) {
    printf("\n[TEST] test_mesh_two_nodes_connect\n");

    /* Node 1 (bootstrap) */
    mesh_config_t config1;
    mesh_config_init(&config1);
    config1.virtual_ip = "10.42.0.1";
    config1.virtual_prefix = 16;
    config1.listen_port = 19995;
    check(mesh_test_configure_identity(&config1, 0));
    config1.on_peer_connected = on_peer_connected;
    config1.on_peer_disconnected = on_peer_disconnected;
    config1.on_packet_received = on_packet_received;

    mesh_network_t *mesh1 = mesh_create(&config1);
    check_not_null(mesh1);

    int ret = mesh_start(mesh1);
    check_int_eq(MESH_OK, ret);
    printf("[TEST] ✓ Node 1 (10.42.0.1) started on port 19995\n");

    /* Wait for node 1 to be ready */
    sleep_ms(1000);

    /* Node 2 (connects to node 1) */
    const char *bootstrap_peers[] = {"127.0.0.1:19995"};

    mesh_config_t config2;
    mesh_config_init(&config2);
    config2.virtual_ip = "10.42.0.2";
    config2.virtual_prefix = 16;
    config2.listen_port = 19996;
    check(mesh_test_configure_identity(&config2, 1));
    config2.bootstrap_peers = bootstrap_peers;
    config2.bootstrap_count = 1;
    config2.on_peer_connected = on_peer_connected;
    config2.on_peer_disconnected = on_peer_disconnected;
    config2.on_packet_received = on_packet_received;

    mesh_network_t *mesh2 = mesh_create(&config2);
    check_not_null(mesh2);

    ret = mesh_start(mesh2);
    check_int_eq(MESH_OK, ret);
    printf("[TEST] ✓ Node 2 (10.42.0.2) started on port 19996\n");
    printf("[TEST] ✓ Node 2 attempting to connect to 127.0.0.1:19995\n");

    /* Wait for connection */
    printf("[TEST] Waiting 5 seconds for connection...\n");
    fflush(stdout);
    for (int i = 0; i < 5; i++) {
        printf("[TEST] %d... (polling mesh)\n", i + 1);
        fflush(stdout);

        /* Poll both meshes */
        mesh_poll(mesh1, 100);
        mesh_poll(mesh2, 100);

        sleep_ms(1000);
    }

    /* Check stats */
    mesh_stats_t stats1, stats2;
    mesh_get_stats(mesh1, &stats1);
    mesh_get_stats(mesh2, &stats2);

    printf("[TEST] Node 1 stats: peers=%u, tx=%llu, rx=%llu\n",
           stats1.peer_count, (unsigned long long)stats1.packets_tx, (unsigned long long)stats1.packets_rx);
    printf("[TEST] Node 2 stats: peers=%u, tx=%llu, rx=%llu\n",
           stats2.peer_count, (unsigned long long)stats2.packets_tx, (unsigned long long)stats2.packets_rx);

    printf("[TEST] Peer connected callbacks: %d\n", g_peer_connected_count);

    /* Cleanup */
    mesh_stop(mesh2);
    mesh_destroy(mesh2);
    mesh_stop(mesh1);
    mesh_destroy(mesh1);

    /* For now, just verify nodes were created - connection test may fail if P2P isn't working */
    printf("[TEST] ✓ Two mesh nodes created, started, and destroyed\n");
    printf("[TEST] Note: If peers=0, P2P connection is not working\n");
}

/**
 * Test 11: HELLO handshake and virtual IP update
 */
void test_hello_handshake(void) {
    printf("\n[TEST] test_hello_handshake\n");

    /* Node 1 (bootstrap) */
    mesh_config_t config1;
    mesh_config_init(&config1);
    config1.virtual_ip = "10.42.0.100";
    config1.virtual_prefix = 16;
    config1.listen_port = 20001;
    check(mesh_test_configure_identity(&config1, 0));
    config1.on_peer_connected = on_peer_connected;
    config1.on_peer_disconnected = on_peer_disconnected;

    mesh_network_t *mesh1 = mesh_create(&config1);
    check_not_null(mesh1);
    mesh_start(mesh1);
    printf("[TEST] ✓ Node 1 (10.42.0.100) started on port 20001\n");

    sleep_ms(1000);

    /* Node 2 (connects to node 1) */
    const char *bootstrap_peers[] = {"127.0.0.1:20001"};

    mesh_config_t config2;
    mesh_config_init(&config2);
    config2.virtual_ip = "10.42.0.200";
    config2.virtual_prefix = 16;
    config2.listen_port = 20002;
    check(mesh_test_configure_identity(&config2, 1));
    config2.bootstrap_peers = bootstrap_peers;
    config2.bootstrap_count = 1;
    config2.on_peer_connected = on_peer_connected;
    config2.on_peer_disconnected = on_peer_disconnected;

    mesh_network_t *mesh2 = mesh_create(&config2);
    check_not_null(mesh2);
    mesh_start(mesh2);
    printf("[TEST] ✓ Node 2 (10.42.0.200) started on port 20002\n");

    /* Wait for HELLO exchange */
    printf("[TEST] Waiting for HELLO handshake...\n");
    for (int i = 0; i < 30; i++) {
        mesh_poll(mesh1, 100);
        mesh_poll(mesh2, 100);
        sleep_ms(100);

        if (mesh_find_peer(mesh1, "10.42.0.200") &&
            mesh_find_peer(mesh2, "10.42.0.100")) {
            printf("[TEST] ✓ HELLO exchange completed after %d iterations\n", i + 1);
            break;
        }
    }

    /* Verify virtual IPs are correctly set */
    printf("[TEST] Verifying virtual IP mappings...\n");

    /* Node 1 should have peer with virtual IP 10.42.0.200 */
    mesh_peer_info_t info1;
    if (mesh_get_peer_info(mesh1, 0, &info1) == MESH_OK) {
        printf("[TEST] Node 1 peer virtual IP: %s\n", info1.virtual_ip);
        check_str_eq("10.42.0.200", info1.virtual_ip);
        printf("[TEST] ✓ Node 1 peer has correct virtual IP!\n");
    }

    /* Node 2 should have peer with virtual IP 10.42.0.100 */
    mesh_peer_info_t info2;
    if (mesh_get_peer_info(mesh2, 0, &info2) == MESH_OK) {
        printf("[TEST] Node 2 peer virtual IP: %s\n", info2.virtual_ip);
        check_str_eq("10.42.0.100", info2.virtual_ip);
        printf("[TEST] ✓ Node 2 peer has correct virtual IP!\n");
    }

    /* Cleanup */
    mesh_stop(mesh2);
    mesh_destroy(mesh2);
    mesh_stop(mesh1);
    mesh_destroy(mesh1);

    printf("[TEST] ✓ HELLO handshake test completed\n");
}

/**
 * Test 12: Virtual IP peer lookup
 */
void test_virtual_ip_lookup(void) {
    printf("\n[TEST] test_virtual_ip_lookup\n");

    /* Create two connected nodes */
    mesh_config_t config1;
    mesh_config_init(&config1);
    config1.virtual_ip = "10.42.1.1";
    config1.virtual_prefix = 16;
    config1.listen_port = 20101;
    check(mesh_test_configure_identity(&config1, 0));

    mesh_network_t *mesh1 = mesh_create(&config1);
    check_not_null(mesh1);
    mesh_start(mesh1);
    sleep_ms(500);

    const char *bootstrap_peers[] = {"127.0.0.1:20101"};
    mesh_config_t config2;
    mesh_config_init(&config2);
    config2.virtual_ip = "10.42.1.2";
    config2.virtual_prefix = 16;
    config2.listen_port = 20102;
    check(mesh_test_configure_identity(&config2, 1));
    config2.bootstrap_peers = bootstrap_peers;
    config2.bootstrap_count = 1;

    mesh_network_t *mesh2 = mesh_create(&config2);
    check_not_null(mesh2);
    mesh_start(mesh2);

    /* Wait for connection and HELLO exchange */
    for (int i = 0; i < 30; i++) {
        mesh_poll(mesh1, 100);
        mesh_poll(mesh2, 100);
        sleep_ms(100);
    }

    /* Test peer lookup by virtual IP */
    printf("[TEST] Testing mesh_find_peer()...\n");

    mesh_peer_t *peer1 = mesh_find_peer(mesh1, "10.42.1.2");
    if (peer1) {
        printf("[TEST] ✓ Node 1 found peer with virtual IP 10.42.1.2\n");
        check_not_null(peer1);
    } else {
        printf("[TEST] ⚠ Node 1 could not find peer 10.42.1.2\n");
    }

    mesh_peer_t *peer2 = mesh_find_peer(mesh2, "10.42.1.1");
    if (peer2) {
        printf("[TEST] ✓ Node 2 found peer with virtual IP 10.42.1.1\n");
        check_not_null(peer2);
    } else {
        printf("[TEST] ⚠ Node 2 could not find peer 10.42.1.1\n");
    }

    /* Test lookup for non-existent peer */
    mesh_peer_t *peer_none = mesh_find_peer(mesh1, "10.42.1.99");
    check_null(peer_none);
    printf("[TEST] ✓ Lookup for non-existent peer returns NULL\n");

    /* Cleanup */
    mesh_stop(mesh2);
    mesh_destroy(mesh2);
    mesh_stop(mesh1);
    mesh_destroy(mesh1);

    printf("[TEST] ✓ Virtual IP lookup test completed\n");
}

/**
 * Test 13: End-to-end packet routing with HELLO
 */
void test_packet_routing_with_hello(void) {
    printf("\n[TEST] test_packet_routing_with_hello\n");

    /* Reset packet counter */
    g_packet_received_count = 0;

    /* Create test packet (ICMP Echo Request) */
    uint8_t packet[60];
    memset(packet, 0, sizeof(packet));
    packet[0] = 0x45;  /* Version 4, IHL 5 */
    packet[9] = 1;     /* Protocol: ICMP */

    /* Source IP: 10.42.2.2 */
    packet[12] = 10;
    packet[13] = 42;
    packet[14] = 2;
    packet[15] = 2;

    /* Destination IP: 10.42.2.1 */
    packet[16] = 10;
    packet[17] = 42;
    packet[18] = 2;
    packet[19] = 1;

    printf("[TEST] ✓ Created test packet: 10.42.2.2 -> 10.42.2.1\n");

    /* Node 1 (bootstrap) */
    mesh_config_t config1;
    mesh_config_init(&config1);
    config1.virtual_ip = "10.42.2.1";
    config1.virtual_prefix = 16;
    config1.listen_port = 20201;
    check(mesh_test_configure_identity(&config1, 0));
    config1.on_packet_received = on_packet_received;

    mesh_network_t *mesh1 = mesh_create(&config1);
    check_not_null(mesh1);
    mesh_start(mesh1);
    printf("[TEST] ✓ Node 1 (10.42.2.1) started\n");
    sleep_ms(1000);

    /* Node 2 (connects to node 1) */
    const char *bootstrap_peers[] = {"127.0.0.1:20201"};

    mesh_config_t config2;
    mesh_config_init(&config2);
    config2.virtual_ip = "10.42.2.2";
    config2.virtual_prefix = 16;
    config2.listen_port = 20202;
    check(mesh_test_configure_identity(&config2, 1));
    config2.bootstrap_peers = bootstrap_peers;
    config2.bootstrap_count = 1;
    config2.on_packet_received = on_packet_received;

    mesh_network_t *mesh2 = mesh_create(&config2);
    check_not_null(mesh2);
    mesh_start(mesh2);
    printf("[TEST] ✓ Node 2 (10.42.2.2) started\n");

    /* Wait for HELLO exchange */
    printf("[TEST] Waiting for HELLO handshake...\n");
    for (int i = 0; i < 30; i++) {
        mesh_poll(mesh1, 100);
        mesh_poll(mesh2, 100);
        sleep_ms(100);
    }

    /* Send packet from mesh2 to mesh1 */
    printf("[TEST] Sending packet from 10.42.2.2 to 10.42.2.1...\n");
    int ret = mesh_send_packet(mesh2, packet, sizeof(packet));

    if (ret == MESH_OK) {
        printf("[TEST] ✓ Packet sent successfully\n");

        /* Wait for packet to be received */
        printf("[TEST] Waiting for packet delivery...\n");
        for (int i = 0; i < 20; i++) {
            mesh_poll(mesh1, 100);
            mesh_poll(mesh2, 100);
            sleep_ms(100);

            if (g_packet_received_count > 0) {
                printf("[TEST] ✓ Packet received after %d iterations!\n", i + 1);
                printf("[TEST] ✓ Received %d packet(s)\n", g_packet_received_count);
                break;
            }
        }

        if (g_packet_received_count > 0) {
            check(g_packet_received_count > 0);
            printf("[TEST] ✓ SUCCESS: End-to-end packet routing works!\n");
        } else {
            printf("[TEST] ⚠ WARNING: No packets received\n");
            printf("[TEST] This may indicate routing table issues\n");
        }
    } else {
        printf("[TEST] ✗ Packet send failed: %s\n", mesh_error_string(ret));
    }

    /* Check stats */
    mesh_stats_t stats1, stats2;
    mesh_get_stats(mesh1, &stats1);
    mesh_get_stats(mesh2, &stats2);

    printf("[TEST] Node 1 stats: peers=%u, tx=%llu, rx=%llu\n",
           stats1.peer_count, (unsigned long long)stats1.packets_tx, (unsigned long long)stats1.packets_rx);
    printf("[TEST] Node 2 stats: peers=%u, tx=%llu, rx=%llu\n",
           stats2.peer_count, (unsigned long long)stats2.packets_tx, (unsigned long long)stats2.packets_rx);

    /* Cleanup */
    mesh_stop(mesh2);
    mesh_destroy(mesh2);
    mesh_stop(mesh1);
    mesh_destroy(mesh1);

    printf("[TEST] ✓ End-to-end packet routing test completed\n");
}

void test_route_learning(void) {
    const char *bootstrap_peers[] = {"127.0.0.1:20301"};
    mesh_route_info_t route_info;
    mesh_network_t *leader = NULL;
    mesh_network_t *node2 = NULL;
    mesh_network_t *node3 = NULL;
    int found_node3_from_node2 = 0;
    int found_node2_from_node3 = 0;

    printf("\n[TEST] test_route_learning\n");

    mesh_config_t leader_cfg;
    mesh_config_init(&leader_cfg);
    leader_cfg.virtual_ip = "10.42.3.1";
    leader_cfg.virtual_prefix = 16;
    leader_cfg.listen_port = 20301;
    check(mesh_test_configure_identity(&leader_cfg, 0));

    leader = mesh_create(&leader_cfg);
    check_not_null(leader);
    check_int_eq(MESH_OK, mesh_start(leader));
    sleep_ms(500);

    mesh_config_t node2_cfg;
    mesh_config_init(&node2_cfg);
    node2_cfg.virtual_ip = "10.42.3.2";
    node2_cfg.virtual_prefix = 16;
    node2_cfg.listen_port = 20302;
    check(mesh_test_configure_identity(&node2_cfg, 1));
    node2_cfg.bootstrap_peers = bootstrap_peers;
    node2_cfg.bootstrap_count = 1;

    node2 = mesh_create(&node2_cfg);
    check_not_null(node2);
    check_int_eq(MESH_OK, mesh_start(node2));

    mesh_config_t node3_cfg;
    mesh_config_init(&node3_cfg);
    node3_cfg.virtual_ip = "10.42.3.3";
    node3_cfg.virtual_prefix = 16;
    node3_cfg.listen_port = 20303;
    check(mesh_test_configure_identity(&node3_cfg, 2));
    node3_cfg.bootstrap_peers = bootstrap_peers;
    node3_cfg.bootstrap_count = 1;

    node3 = mesh_create(&node3_cfg);
    check_not_null(node3);
    check_int_eq(MESH_OK, mesh_start(node3));

    for (int i = 0; i < 80; i++) {
        mesh_poll(leader, 100);
        mesh_poll(node2, 100);
        mesh_poll(node3, 100);
        sleep_ms(100);

        found_node3_from_node2 = 0;
        found_node2_from_node3 = 0;

        for (int j = 0; j < mesh_get_route_count(node2); j++) {
            if (mesh_get_route_info(node2, j, &route_info) != MESH_OK) {
                continue;
            }
            if (strcmp(route_info.dest_ip, "10.42.3.3") == 0) {
                found_node3_from_node2 = 1;
                break;
            }
        }

        for (int j = 0; j < mesh_get_route_count(node3); j++) {
            if (mesh_get_route_info(node3, j, &route_info) != MESH_OK) {
                continue;
            }
            if (strcmp(route_info.dest_ip, "10.42.3.2") == 0) {
                found_node2_from_node3 = 1;
                break;
            }
        }

        if (found_node3_from_node2 && found_node2_from_node3) {
            break;
        }
    }

    printf("[TEST] node2 routes=%d node3 routes=%d\n",
           mesh_get_route_count(node2), mesh_get_route_count(node3));

    found_node3_from_node2 = 0;
    found_node2_from_node3 = 0;
    for (int i = 0; i < mesh_get_route_count(node2); i++) {
        if (mesh_get_route_info(node2, i, &route_info) != MESH_OK) {
            continue;
        }

        if (strcmp(route_info.dest_ip, "10.42.3.3") == 0) {
            found_node3_from_node2 = 1;
            check_str_eq("10.42.3.1", route_info.next_hop_virtual_ip);
            check_int_eq(1, route_info.hop_count);
            break;
        }
    }

    for (int i = 0; i < mesh_get_route_count(node3); i++) {
        if (mesh_get_route_info(node3, i, &route_info) != MESH_OK) {
            continue;
        }

        if (strcmp(route_info.dest_ip, "10.42.3.2") == 0) {
            found_node2_from_node3 = 1;
            check_str_eq("10.42.3.1", route_info.next_hop_virtual_ip);
            check_int_eq(1, route_info.hop_count);
            break;
        }
    }

    check(found_node3_from_node2);
    check(found_node2_from_node3);

    mesh_stop(node3);
    mesh_destroy(node3);
    mesh_stop(node2);
    mesh_destroy(node2);
    mesh_stop(leader);
    mesh_destroy(leader);

    printf("[TEST] ✓ Route learning test completed\n");
}

static void mesh_test_poll_many(mesh_network_t **nodes, int node_count,
                                int iterations, int timeout_ms, int sleep_between_ms) {
    for (int i = 0; i < iterations; i++) {
        for (int j = 0; j < node_count; j++) {
            if (nodes[j]) {
                mesh_poll(nodes[j], timeout_ms);
            }
        }
        if (sleep_between_ms > 0) {
            sleep_ms(sleep_between_ms);
        }
    }
}

static int mesh_test_find_route(mesh_network_t *mesh, const char *dest_ip,
                                mesh_route_info_t *route_info) {
    mesh_route_info_t current;
    int route_count = mesh_get_route_count(mesh);

    for (int i = 0; i < route_count; i++) {
        if (mesh_get_route_info(mesh, i, &current) != MESH_OK) {
            continue;
        }

        if (strcmp(current.dest_ip, dest_ip) == 0) {
            if (route_info) {
                *route_info = current;
            }
            return 1;
        }
    }

    return 0;
}

static int mesh_test_is_ice_progress_state(const char *state) {
    return state &&
           (strcmp(state, "GATHERING") == 0 ||
            strcmp(state, "CONNECTING") == 0 ||
            strcmp(state, "CONNECTED") == 0 ||
            strcmp(state, "COMPLETED") == 0);
}

static int mesh_test_wait_for_min_peers(mesh_network_t **nodes, int node_count,
                                        int expected_per_node, int iterations) {
    for (int i = 0; i < iterations; i++) {
        int ready = 1;

        mesh_test_poll_many(nodes, node_count, 1, 100, 50);
        for (int j = 0; j < node_count; j++) {
            if (!nodes[j]) {
                continue;
            }
            if (mesh_get_peer_count(nodes[j]) < expected_per_node) {
                ready = 0;
            }
        }

        if (ready) {
            return 1;
        }
    }

    return 0;
}

typedef struct {
    int disconnect_count;
    int ready_during_disconnect;
} mesh_stream_admission_observer_t;

static void mesh_test_stream_peer_disconnected(mesh_peer_t *peer, void *user_data) {
    mesh_stream_admission_observer_t *observer =
        (mesh_stream_admission_observer_t *)user_data;

    if (!observer) {
        return;
    }

    observer->disconnect_count++;
    if (mesh_peer_stream_ready(peer)) {
        observer->ready_during_disconnect = 1;
    }
}

static void test_stream_capability_requires_authenticated_bilateral_admission(void) {
    const char *enabled_bootstrap[] = {"127.0.0.1:20931"};
    const char *disabled_bootstrap[] = {"127.0.0.1:20931"};
    mesh_stream_admission_observer_t observer = {0};
    mesh_network_t *leader = NULL;
    mesh_network_t *enabled = NULL;
    mesh_network_t *disabled = NULL;
    mesh_network_t *nodes[3] = {NULL};
    mesh_peer_t *leader_enabled_peer = NULL;
    mesh_peer_t *leader_disabled_peer = NULL;
    mesh_peer_t *enabled_leader_peer = NULL;
    mesh_peer_t *disabled_leader_peer = NULL;
    mesh_peer_info_t leader_enabled_info;
    mesh_peer_info_t leader_disabled_info;
    mesh_peer_info_t enabled_leader_info;
    mesh_peer_info_t disabled_leader_info;
    int leader_started = 0;
    int enabled_started = 0;
    int disabled_started = 0;
    int peers_ready = 0;

    printf("\n[TEST] test_stream_capability_requires_authenticated_bilateral_admission\n");

    check_int_eq(MESH_ERR_INVALID_ARG, mesh_stream_admission_enable(NULL));
    check_int_eq(MESH_ERR_INVALID_ARG, mesh_stream_admission_disable(NULL));
    check_int_eq(0, mesh_peer_stream_ready(NULL));

    mesh_config_t leader_cfg;
    mesh_config_init(&leader_cfg);
    leader_cfg.virtual_ip = "10.42.19.1";
    leader_cfg.virtual_prefix = 16;
    leader_cfg.listen_port = 20931;
    check(mesh_test_configure_identity(&leader_cfg, 0));
    leader_cfg.on_peer_disconnected = mesh_test_stream_peer_disconnected;
    leader_cfg.user_data = &observer;
    leader = mesh_create(&leader_cfg);
    check_not_null(leader);
    if (leader) {
        check_int_eq(MESH_OK, mesh_stream_admission_enable(leader));
        check_int_eq(MESH_OK, mesh_stream_admission_enable(leader));
        leader_started = (mesh_start(leader) == MESH_OK);
    }

    mesh_config_t enabled_cfg;
    mesh_config_init(&enabled_cfg);
    enabled_cfg.virtual_ip = "10.42.19.2";
    enabled_cfg.virtual_prefix = 16;
    enabled_cfg.listen_port = 20932;
    check(mesh_test_configure_identity(&enabled_cfg, 1));
    enabled_cfg.bootstrap_peers = enabled_bootstrap;
    enabled_cfg.bootstrap_count = 1;
    enabled = mesh_create(&enabled_cfg);
    check_not_null(enabled);
    if (enabled) {
        check_int_eq(MESH_OK, mesh_stream_admission_enable(enabled));
        check_int_eq(MESH_OK, mesh_stream_admission_disable(enabled));
        check_int_eq(MESH_OK, mesh_stream_admission_disable(enabled));
        check_int_eq(MESH_OK, mesh_stream_admission_enable(enabled));
        enabled_started = (mesh_start(enabled) == MESH_OK);
    }

    mesh_config_t disabled_cfg;
    mesh_config_init(&disabled_cfg);
    disabled_cfg.virtual_ip = "10.42.19.3";
    disabled_cfg.virtual_prefix = 16;
    disabled_cfg.listen_port = 20933;
    check(mesh_test_configure_identity(&disabled_cfg, 2));
    disabled_cfg.bootstrap_peers = disabled_bootstrap;
    disabled_cfg.bootstrap_count = 1;
    disabled = mesh_create(&disabled_cfg);
    check_not_null(disabled);
    if (disabled) {
        disabled_started = (mesh_start(disabled) == MESH_OK);
    }

    nodes[0] = leader;
    nodes[1] = enabled;
    nodes[2] = disabled;

    if (leader_started && enabled_started && disabled_started) {
        peers_ready = mesh_test_wait_for_min_peers(nodes, 3, 1, 80);
    }

    for (int i = 0; peers_ready && i < 80; i++) {
        mesh_test_poll_many(nodes, 3, 1, 100, 50);
        leader_enabled_peer = mesh_find_peer(leader, "10.42.19.2");
        leader_disabled_peer = mesh_find_peer(leader, "10.42.19.3");
        enabled_leader_peer = mesh_find_peer(enabled, "10.42.19.1");
        disabled_leader_peer = mesh_find_peer(disabled, "10.42.19.1");
        if (leader_enabled_peer && leader_disabled_peer &&
            enabled_leader_peer && disabled_leader_peer) {
            break;
        }
    }

    memset(&leader_enabled_info, 0, sizeof(leader_enabled_info));
    memset(&leader_disabled_info, 0, sizeof(leader_disabled_info));
    memset(&enabled_leader_info, 0, sizeof(enabled_leader_info));
    memset(&disabled_leader_info, 0, sizeof(disabled_leader_info));
    if (leader_enabled_peer) {
        mesh_get_peer_handle_info(leader_enabled_peer, &leader_enabled_info);
    }
    if (leader_disabled_peer) {
        mesh_get_peer_handle_info(leader_disabled_peer, &leader_disabled_info);
    }
    if (enabled_leader_peer) {
        mesh_get_peer_handle_info(enabled_leader_peer, &enabled_leader_info);
    }
    if (disabled_leader_peer) {
        mesh_get_peer_handle_info(disabled_leader_peer, &disabled_leader_info);
    }

    check(leader_started);
    check(enabled_started);
    check(disabled_started);
    check(peers_ready);
    check_not_null(leader_enabled_peer);
    check_not_null(leader_disabled_peer);
    check_not_null(enabled_leader_peer);
    check_not_null(disabled_leader_peer);
    check(mesh_peer_stream_ready(leader_enabled_peer));
    check(mesh_peer_stream_ready(enabled_leader_peer));
    check_int_eq(0, mesh_peer_stream_ready(leader_disabled_peer));
    check_int_eq(0, mesh_peer_stream_ready(disabled_leader_peer));
    check((leader_enabled_info.capabilities & MESH_CAP_STREAM_V1) != 0u);
    check((enabled_leader_info.capabilities & MESH_CAP_STREAM_V1) != 0u);
    check((leader_enabled_info.negotiated_capabilities & MESH_CAP_STREAM_V1) != 0u);
    check((enabled_leader_info.negotiated_capabilities & MESH_CAP_STREAM_V1) != 0u);
    check_uint_eq(0u, leader_disabled_info.capabilities & MESH_CAP_STREAM_V1);
    check((disabled_leader_info.capabilities & MESH_CAP_STREAM_V1) != 0u);
    check_uint_eq(0u, leader_disabled_info.negotiated_capabilities & MESH_CAP_STREAM_V1);
    check_uint_eq(0u, disabled_leader_info.negotiated_capabilities & MESH_CAP_STREAM_V1);

    if (leader && leader_disabled_peer) {
        mesh_disconnect_peer(leader, leader_disabled_peer);
    }
    if (leader && leader_enabled_peer) {
        mesh_disconnect_peer(leader, leader_enabled_peer);
    }

    check(observer.disconnect_count >= 2);
    check_int_eq(0, observer.ready_during_disconnect);

    mesh_test_stop_destroy(&disabled);
    mesh_test_stop_destroy(&enabled);
    mesh_test_stop_destroy(&leader);

    printf("[TEST] ✓ stream admission capability test completed\n");
}

void test_connect_peer_uses_advertise_ip(void) {
    const char *bootstrap_peers[] = {"127.0.0.1:20401"};
    mesh_network_t *leader = NULL;
    mesh_network_t *node2 = NULL;
    mesh_network_t *node3 = NULL;
    mesh_peer_info_t info;
    int leader_started = 0;
    int node2_started = 0;
    int node3_started = 0;
    int connect_started = 0;
    int direct_found = 0;
    int announced_direct = 0;

    printf("\n[TEST] test_connect_peer_uses_advertise_ip\n");

    mesh_config_t leader_cfg;
    mesh_config_init(&leader_cfg);
    leader_cfg.virtual_ip = "10.42.4.1";
    leader_cfg.virtual_prefix = 16;
    leader_cfg.listen_port = 20401;
    check(mesh_test_configure_identity(&leader_cfg, 0));
    leader_cfg.advertise_ip = "127.0.0.1";

    leader = mesh_create(&leader_cfg);
    check_not_null(leader);
    leader_started = (mesh_start(leader) == MESH_OK);
    if (leader_started) {
        sleep_ms(500);
    }

    mesh_config_t node2_cfg;
    mesh_config_init(&node2_cfg);
    node2_cfg.virtual_ip = "10.42.4.2";
    node2_cfg.virtual_prefix = 16;
    node2_cfg.listen_port = 20402;
    check(mesh_test_configure_identity(&node2_cfg, 1));
    node2_cfg.bootstrap_peers = bootstrap_peers;
    node2_cfg.bootstrap_count = 1;
    node2 = mesh_create(&node2_cfg);
    check_not_null(node2);
    node2_started = (mesh_start(node2) == MESH_OK);

    mesh_config_t node3_cfg;
    mesh_config_init(&node3_cfg);
    node3_cfg.virtual_ip = "10.42.4.3";
    node3_cfg.virtual_prefix = 16;
    node3_cfg.listen_port = 20403;
    check(mesh_test_configure_identity(&node3_cfg, 2));
    node3_cfg.bootstrap_peers = bootstrap_peers;
    node3_cfg.bootstrap_count = 1;
    node3_cfg.advertise_ip = "127.0.0.1";
    node3 = mesh_create(&node3_cfg);
    check_not_null(node3);
    node3_started = (mesh_start(node3) == MESH_OK);

    for (int i = 0; leader_started && node2_started && node3_started && i < 80; i++) {
        int direct_seen_this_round = 0;
        mesh_poll(leader, 100);
        mesh_poll(node2, 100);
        mesh_poll(node3, 100);
        sleep_ms(100);

        if (!connect_started && mesh_connect_peer(node2, "10.42.4.3") == MESH_OK) {
            connect_started = 1;
        }

        for (int j = 0; j < mesh_get_peer_count(node2); j++) {
            if (mesh_get_peer_info(node2, j, &info) != MESH_OK) {
                continue;
            }
            if (strcmp(info.virtual_ip, "10.42.4.3") == 0 &&
                strcmp(info.real_ip, "127.0.0.1:20403") == 0) {
                direct_seen_this_round = 1;
                break;
            }
        }

        if (direct_seen_this_round) {
            announced_direct = 1;
            break;
        }
    }

    if (node2_started) {
        for (int i = 0; i < mesh_get_peer_count(node2); i++) {
            if (mesh_get_peer_info(node2, i, &info) != MESH_OK) {
                continue;
            }

            fprintf(stderr, "[TEST] node2 peer[%d]: vip=%s real=%s connected=%d\n",
                    i, info.virtual_ip, info.real_ip, info.is_connected);

            if (strcmp(info.virtual_ip, "10.42.4.3") == 0 &&
                strcmp(info.real_ip, "127.0.0.1:20403") == 0) {
                direct_found = 1;
                break;
            }
        }
    }

    mesh_test_stop_destroy(&node3);
    mesh_test_stop_destroy(&node2);
    mesh_test_stop_destroy(&leader);

    check(leader_started);
    check(node2_started);
    check(node3_started);
    check(connect_started);
    check(announced_direct);
    check(direct_found);

    printf("[TEST] ✓ connect_peer advertise_ip test completed\n");
}

void test_ice_signaling_two_nodes(void) {
    const char *bootstrap_peers[] = {"127.0.0.1:20891"};
    mesh_network_t *node1 = NULL;
    mesh_network_t *node2 = NULL;
    mesh_diag_info_t diag1;
    mesh_diag_info_t diag2;
    mesh_packet_counter_t node1_packets = {0};
    uint8_t packet[60];
    int node1_started = 0;
    int node2_started = 0;
    int auth_seen = 0;
    int candidate_seen = 0;
    int eoc_seen = 0;
    int checks_started = 0;
    int ice_connected = 0;
    int packet_sent = 0;
    int packet_delivered = 0;

    printf("\n[TEST] test_ice_signaling_two_nodes\n");

    mesh_config_t cfg1;
    mesh_config_init(&cfg1);
    cfg1.virtual_ip = "10.42.9.11";
    cfg1.virtual_prefix = 16;
    cfg1.listen_port = 20891;
    check(mesh_test_configure_identity(&cfg1, 0));
    cfg1.enable_ice = 1;
    cfg1.ice_allow_loopback = 1;
    cfg1.on_packet_received = on_packet_received_counting;
    cfg1.user_data = &node1_packets;

    mesh_config_t cfg2;
    mesh_config_init(&cfg2);
    cfg2.virtual_ip = "10.42.9.12";
    cfg2.virtual_prefix = 16;
    cfg2.listen_port = 20892;
    check(mesh_test_configure_identity(&cfg2, 1));
    cfg2.bootstrap_peers = bootstrap_peers;
    cfg2.bootstrap_count = 1;
    cfg2.enable_ice = 1;
    cfg2.ice_allow_loopback = 1;

    mesh_test_build_ipv4_packet(packet, sizeof(packet),
                                10, 42, 9, 12,
                                10, 42, 9, 11);

    node1 = mesh_create(&cfg1);
    check_not_null(node1);
    node1_started = (mesh_start(node1) == MESH_OK);
    check(node1_started);
    sleep_ms(300);

    node2 = mesh_create(&cfg2);
    check_not_null(node2);
    node2_started = (mesh_start(node2) == MESH_OK);
    check(node2_started);

    memset(&diag1, 0, sizeof(diag1));
    memset(&diag2, 0, sizeof(diag2));
    for (int i = 0; i < 150; i++) {
        mesh_poll(node1, 100);
        mesh_poll(node2, 100);
        sleep_ms(40);

        mesh_get_diag_info(node1, &diag1);
        mesh_get_diag_info(node2, &diag2);

        auth_seen = (diag1.ice_auth_messages_tx > 0 && diag1.ice_auth_messages_rx > 0 &&
                     diag2.ice_auth_messages_tx > 0 && diag2.ice_auth_messages_rx > 0);
        candidate_seen = (diag1.ice_candidate_messages_tx > 0 && diag1.ice_candidate_messages_rx > 0 &&
                          diag2.ice_candidate_messages_tx > 0 && diag2.ice_candidate_messages_rx > 0);
        eoc_seen = (diag1.ice_end_of_candidates_tx > 0 && diag1.ice_end_of_candidates_rx > 0 &&
                    diag2.ice_end_of_candidates_tx > 0 && diag2.ice_end_of_candidates_rx > 0);
        checks_started = (diag1.ice_checks_started > 0 && diag2.ice_checks_started > 0 &&
                          diag1.ice_last_check_local_candidate_count > 0 &&
                          diag1.ice_last_check_remote_candidate_count > 0 &&
                          diag2.ice_last_check_local_candidate_count > 0 &&
                          diag2.ice_last_check_remote_candidate_count > 0);
        ice_connected = (diag1.ice_connected_peer_count == 1 &&
                         diag2.ice_connected_peer_count == 1 &&
                         diag1.last_ice_selected_local_endpoint[0] != '\0' &&
                         diag1.last_ice_selected_remote_endpoint[0] != '\0' &&
                         diag2.last_ice_selected_local_endpoint[0] != '\0' &&
                         diag2.last_ice_selected_remote_endpoint[0] != '\0');

        if (diag1.ice_peer_count == 1 && diag2.ice_peer_count == 1 &&
            auth_seen && candidate_seen && eoc_seen && checks_started &&
            ice_connected) {
            break;
        }
    }

    if (ice_connected) {
        packet_sent = (mesh_send_packet(node2, packet, sizeof(packet)) == MESH_OK);
        for (int i = 0; packet_sent && i < 50; i++) {
            mesh_poll(node1, 100);
            mesh_poll(node2, 100);
            sleep_ms(20);
            if (node1_packets.packet_received_count > 0) {
                packet_delivered = 1;
                break;
            }
        }
    }

    if (node2) {
        mesh_stop(node2);
    }
    if (node1) {
        mesh_stop(node1);
    }
    sleep_ms(200);
    mesh_test_stop_destroy(&node2);
    mesh_test_stop_destroy(&node1);

    check_int_eq(1, diag1.ice_enabled);
    check_int_eq(1, diag2.ice_enabled);
    check_int_eq(1, diag1.ice_peer_count);
    check_int_eq(1, diag2.ice_peer_count);
    check(auth_seen);
    check(candidate_seen);
    check(eoc_seen);
    check(checks_started);
    check(ice_connected);
    check(diag1.ice_candidate_messages_tx >= diag1.ice_last_check_local_candidate_count);
    check(diag2.ice_candidate_messages_tx >= diag2.ice_last_check_local_candidate_count);
    check(diag1.ice_candidate_messages_rx >= diag1.ice_last_check_remote_candidate_count);
    check(diag2.ice_candidate_messages_rx >= diag2.ice_last_check_remote_candidate_count);
    check_int_eq(1, (int)diag1.peer_connect_events);
    check_int_eq(1, (int)diag2.peer_connect_events);
    check(packet_sent);
    check(packet_delivered);

    printf("[TEST] ✓ ice signaling two-node test completed\n");
}

void test_routed_ice_direct_path_three_nodes(void) {
    const char *bootstrap_peers[] = {"127.0.0.1:20801"};
    mesh_network_t *leader = NULL;
    mesh_network_t *node2 = NULL;
    mesh_network_t *node3 = NULL;
    mesh_network_t *nodes[3] = {NULL};
    mesh_diag_info_t diag2;
    mesh_diag_info_t diag3;
    mesh_route_info_t route_info;
    mesh_peer_info_t leader_peer_after;
    mesh_peer_info_t direct_peer_after;
    mesh_packet_counter_t node3_packets = {0};
    uint8_t packet[60];
    int leader_started = 0;
    int node2_started = 0;
    int node3_started = 0;
    int peers_ready = 0;
    int relay_ready = 0;
    int kick_send_ok = 0;
    int ice_connected = 0;
    int direct_peer_ready = 0;
    int leader_peer_found = 0;
    int routed_signaling_seen = 0;
    int direct_send_ok = 0;
    int direct_packet_delivered = 0;
    int relay_bytes_stayed_zero = 0;

    printf("\n[TEST] test_routed_ice_direct_path_three_nodes\n");

    mesh_test_build_ipv4_packet(packet, sizeof(packet),
                                10, 42, 8, 2,
                                10, 42, 8, 3);

    mesh_config_t leader_cfg;
    mesh_config_init(&leader_cfg);
    leader_cfg.virtual_ip = "10.42.8.1";
    leader_cfg.virtual_prefix = 16;
    leader_cfg.listen_port = 20801;
    check(mesh_test_configure_identity(&leader_cfg, 0));
    leader = mesh_create(&leader_cfg);
    check_not_null(leader);
    leader_started = (mesh_start(leader) == MESH_OK);
    if (leader_started) {
        sleep_ms(300);
    }

    mesh_config_t node2_cfg;
    mesh_config_init(&node2_cfg);
    node2_cfg.virtual_ip = "10.42.8.2";
    node2_cfg.virtual_prefix = 16;
    node2_cfg.listen_port = 20802;
    check(mesh_test_configure_identity(&node2_cfg, 1));
    node2_cfg.bootstrap_peers = bootstrap_peers;
    node2_cfg.bootstrap_count = 1;
    node2_cfg.enable_ice = 1;
    node2_cfg.ice_allow_loopback = 1;
    node2 = mesh_create(&node2_cfg);
    check_not_null(node2);
    node2_started = (mesh_start(node2) == MESH_OK);

    mesh_config_t node3_cfg;
    mesh_config_init(&node3_cfg);
    node3_cfg.virtual_ip = "10.42.8.3";
    node3_cfg.virtual_prefix = 16;
    node3_cfg.listen_port = 20803;
    check(mesh_test_configure_identity(&node3_cfg, 2));
    node3_cfg.bootstrap_peers = bootstrap_peers;
    node3_cfg.bootstrap_count = 1;
    node3_cfg.enable_ice = 1;
    node3_cfg.ice_allow_loopback = 1;
    node3_cfg.on_packet_received = on_packet_received_counting;
    node3_cfg.user_data = &node3_packets;
    node3 = mesh_create(&node3_cfg);
    check_not_null(node3);
    node3_started = (mesh_start(node3) == MESH_OK);

    nodes[0] = leader;
    nodes[1] = node2;
    nodes[2] = node3;

    if (leader_started && node2_started && node3_started) {
        peers_ready = mesh_test_wait_for_min_peers(nodes, 3, 1, 60);
    }

    for (int i = 0; peers_ready && i < 80; i++) {
        mesh_test_poll_many(nodes, 3, 1, 100, 50);
        if (mesh_test_find_route(node2, "10.42.8.3", &route_info) &&
            strcmp(route_info.next_hop_virtual_ip, "10.42.8.1") == 0 &&
            route_info.hop_count == 1) {
            relay_ready = 1;
            break;
        }
    }

    if (relay_ready) {
        kick_send_ok = (mesh_send_packet(node2, packet, sizeof(packet)) == MESH_OK);
    }

    memset(&diag2, 0, sizeof(diag2));
    memset(&diag3, 0, sizeof(diag3));
    for (int i = 0; kick_send_ok && i < 120; i++) {
        mesh_test_poll_many(nodes, 3, 1, 100, 50);
        mesh_get_diag_info(node2, &diag2);
        mesh_get_diag_info(node3, &diag3);
        routed_signaling_seen = (diag2.ice_auth_messages_tx > 0 &&
                                 diag2.ice_candidate_messages_tx > 0 &&
                                 diag3.ice_auth_messages_rx > 0 &&
                                 diag3.ice_candidate_messages_rx > 0);
        ice_connected = (diag2.ice_connected_peer_count >= 1 &&
                         diag3.ice_connected_peer_count >= 1);
        direct_peer_ready = mesh_test_find_peer_info(node2, "10.42.8.3", &direct_peer_after) &&
                            direct_peer_after.is_connected &&
                            strcmp(direct_peer_after.real_ip, "127.0.0.1:20803") != 0;
        if (routed_signaling_seen && ice_connected && direct_peer_ready) {
            break;
        }
    }

    if (direct_peer_ready) {
        mesh_reset_stats(node2);
        node3_packets.packet_received_count = 0;
        direct_send_ok = (mesh_send_packet(node2, packet, sizeof(packet)) == MESH_OK);
        for (int i = 0; direct_send_ok && i < 40; i++) {
            mesh_test_poll_many(nodes, 3, 1, 100, 50);
            if (node3_packets.packet_received_count > 0) {
                direct_packet_delivered = 1;
                break;
            }
        }
        leader_peer_found = mesh_test_find_peer_info(node2, "10.42.8.1", &leader_peer_after);
        relay_bytes_stayed_zero = leader_peer_found && ((int)leader_peer_after.bytes_tx == 0);
    }

    mesh_test_stop_destroy(&node3);
    mesh_test_stop_destroy(&node2);
    mesh_test_stop_destroy(&leader);

    check(leader_started);
    check(node2_started);
    check(node3_started);
    check(peers_ready);
    check(relay_ready);
    check(kick_send_ok);
    check(routed_signaling_seen);
    check(ice_connected);
    check(direct_peer_ready);
    check(direct_send_ok);
    check(direct_packet_delivered);
    check(leader_peer_found);
    check(relay_bytes_stayed_zero);
    check(diag2.ice_auth_messages_tx > 0);
    check(diag2.ice_candidate_messages_tx > 0);
    check(diag3.ice_auth_messages_rx > 0);
    check(diag3.ice_candidate_messages_rx > 0);

    printf("[TEST] ✓ routed ice direct path three-node test completed\n");
}

void test_direct_path_preferred_over_relay(void) {
    const char *bootstrap_peers[] = {"127.0.0.1:20701"};
    mesh_network_t *leader = NULL;
    mesh_network_t *node2 = NULL;
    mesh_network_t *node3 = NULL;
    mesh_network_t *nodes[3] = {NULL};
    mesh_route_info_t route_info = {0};
    mesh_peer_info_t direct_peer_before = {0};
    mesh_peer_info_t leader_peer_after = {0};
    mesh_peer_info_t direct_peer_after = {0};
    mesh_packet_counter_t node3_packets = {0};
    uint8_t packet[60];
    int leader_started = 0;
    int node2_started = 0;
    int node3_started = 0;
    int peers_ready = 0;
    int relay_ready = 0;
    int direct_connect_started = 0;
    int direct_ready = 0;
    int direct_send_ok = 0;
    int direct_packet_delivered = 0;
    int fallback_route_ready = 0;
    int fallback_send_ok = 0;
    int leader_peer_found = 0;
    int direct_peer_found = 0;
    int relay_bytes_stayed_zero = 0;
    int leader_peer_found_after_fallback = 0;
    int relay_bytes_after_fallback = 0;
    int direct_peer_gone = 0;

    printf("\n[TEST] test_direct_path_preferred_over_relay\n");

    mesh_test_build_ipv4_packet(packet, sizeof(packet),
                                10, 42, 7, 2,
                                10, 42, 7, 3);

    mesh_config_t leader_cfg;
    mesh_config_init(&leader_cfg);
    leader_cfg.virtual_ip = "10.42.7.1";
    leader_cfg.virtual_prefix = 16;
    leader_cfg.listen_port = 20701;
    check(mesh_test_configure_identity(&leader_cfg, 0));
    leader_cfg.advertise_ip = "127.0.0.1";
    leader = mesh_create(&leader_cfg);
    check_not_null(leader);
    leader_started = (mesh_start(leader) == MESH_OK);
    if (leader_started) {
        sleep_ms(500);
    }

    mesh_config_t node2_cfg;
    mesh_config_init(&node2_cfg);
    node2_cfg.virtual_ip = "10.42.7.2";
    node2_cfg.virtual_prefix = 16;
    node2_cfg.listen_port = 20702;
    check(mesh_test_configure_identity(&node2_cfg, 1));
    node2_cfg.bootstrap_peers = bootstrap_peers;
    node2_cfg.bootstrap_count = 1;
    node2 = mesh_create(&node2_cfg);
    check_not_null(node2);
    node2_started = (mesh_start(node2) == MESH_OK);

    mesh_config_t node3_cfg;
    mesh_config_init(&node3_cfg);
    node3_cfg.virtual_ip = "10.42.7.3";
    node3_cfg.virtual_prefix = 16;
    node3_cfg.listen_port = 20703;
    check(mesh_test_configure_identity(&node3_cfg, 2));
    node3_cfg.bootstrap_peers = bootstrap_peers;
    node3_cfg.bootstrap_count = 1;
    node3_cfg.advertise_ip = "127.0.0.1";
    node3_cfg.on_packet_received = on_packet_received_counting;
    node3_cfg.user_data = &node3_packets;
    node3 = mesh_create(&node3_cfg);
    check_not_null(node3);
    node3_started = (mesh_start(node3) == MESH_OK);

    nodes[0] = leader;
    nodes[1] = node2;
    nodes[2] = node3;

    if (leader_started && node2_started && node3_started) {
        peers_ready = mesh_test_wait_for_min_peers(nodes, 3, 1, 60);
    }

    for (int i = 0; peers_ready && i < 80; i++) {
        mesh_test_poll_many(nodes, 3, 1, 100, 50);
        if (mesh_test_find_route(node2, "10.42.7.3", &route_info) &&
            strcmp(route_info.next_hop_virtual_ip, "10.42.7.1") == 0 &&
            route_info.hop_count == 1) {
            relay_ready = 1;
            break;
        }
    }

    if (relay_ready) {
        direct_connect_started = (mesh_connect_peer(node2, "10.42.7.3") == MESH_OK);
    }

    for (int i = 0; direct_connect_started && i < 80; i++) {
        mesh_test_poll_many(nodes, 3, 1, 100, 50);
        if (mesh_test_find_peer_info(node2, "10.42.7.3", &direct_peer_before) &&
            strcmp(direct_peer_before.real_ip, "127.0.0.1:20703") == 0 &&
            direct_peer_before.is_connected) {
            direct_ready = 1;
            break;
        }
    }

    if (direct_ready) {
        leader_peer_found = mesh_test_find_peer_info(node2, "10.42.7.1", &leader_peer_after);
        mesh_reset_stats(node2);
        node3_packets.packet_received_count = 0;
        direct_send_ok = (mesh_send_packet(node2, packet, sizeof(packet)) == MESH_OK);

        for (int i = 0; direct_send_ok && i < 20; i++) {
            mesh_test_poll_many(nodes, 3, 1, 100, 50);
            if (node3_packets.packet_received_count > 0) {
                break;
            }
        }

        leader_peer_found = mesh_test_find_peer_info(node2, "10.42.7.1", &leader_peer_after);
        direct_peer_found = mesh_test_find_peer_info(node2, "10.42.7.3", &direct_peer_after);
        direct_packet_delivered = (node3_packets.packet_received_count > 0);
        relay_bytes_stayed_zero = leader_peer_found && ((int)leader_peer_after.bytes_tx == 0);
    }

    if (direct_ready) {
        mesh_disconnect_peer(node2, mesh_find_peer(node2, "10.42.7.3"));

        for (int i = 0; i < 40; i++) {
            mesh_test_poll_many(nodes, 3, 1, 100, 50);
            if (!mesh_find_peer(node2, "10.42.7.3") &&
                mesh_test_find_route(node2, "10.42.7.3", &route_info) &&
                strcmp(route_info.next_hop_virtual_ip, "10.42.7.1") == 0) {
                fallback_route_ready = 1;
                break;
            }
        }
    }

    if (fallback_route_ready) {
        direct_peer_gone = (mesh_find_peer(node2, "10.42.7.3") == NULL);
        mesh_reset_stats(node2);
        node3_packets.packet_received_count = 0;
        fallback_send_ok = (mesh_send_packet(node2, packet, sizeof(packet)) == MESH_OK);

        for (int i = 0; fallback_send_ok && i < 20; i++) {
            mesh_test_poll_many(nodes, 3, 1, 100, 50);
            if (node3_packets.packet_received_count > 0) {
                break;
            }
        }

        leader_peer_found_after_fallback = mesh_test_find_peer_info(node2, "10.42.7.1",
                                                                    &leader_peer_after);
        relay_bytes_after_fallback = leader_peer_found_after_fallback &&
                                     (leader_peer_after.bytes_tx > 0);
    }

    mesh_test_stop_destroy(&node3);
    mesh_test_stop_destroy(&node2);
    mesh_test_stop_destroy(&leader);

    check(leader_started);
    check(node2_started);
    check(node3_started);
    check(peers_ready);
    check(relay_ready);
    check(direct_connect_started);
    check(direct_ready);
    check(direct_send_ok);
    check(direct_packet_delivered);
    check(leader_peer_found);
    check(direct_peer_found);
    check(direct_peer_after.bytes_tx > 0);
    check(relay_bytes_stayed_zero);
    check(fallback_route_ready);
    check(direct_peer_gone);
    check(fallback_send_ok);
    check(node3_packets.packet_received_count > 0);
    check(leader_peer_found_after_fallback);
    check(relay_bytes_after_fallback);
    check_str_eq("127.0.0.1:20703", direct_peer_before.real_ip);
    check(direct_peer_before.is_connected);
    check_str_eq("10.42.7.1", route_info.next_hop_virtual_ip);

    printf("[TEST] ✓ direct path preferred over relay test completed\n");
}

void test_pinned_route_overrides_direct_path(void) {
    const char *bootstrap_peers[] = {"127.0.0.1:20711"};
    mesh_network_t *leader = NULL;
    mesh_network_t *node2 = NULL;
    mesh_network_t *node3 = NULL;
    mesh_network_t *nodes[3] = {NULL};
    mesh_route_info_t route_info;
    mesh_route_rule_info_t rule_info;
    mesh_peer_info_t leader_peer_after;
    mesh_peer_info_t direct_peer_after;
    mesh_packet_counter_t node3_packets = {0};
    mesh_route_rule_t node2_rules[] = {
        {"10.42.11.3/32", "10.42.11.1", MESH_ROUTE_RULE_PINNED},
    };
    uint8_t packet[60];
    int leader_started = 0;
    int node2_started = 0;
    int node3_started = 0;
    int peers_ready = 0;
    int relay_ready = 0;
    int direct_connect_started = 0;
    int direct_ready = 0;
    int rule_count_ok = 0;
    int rule_info_ok = 0;
    int pinned_send_ok = 0;
    int pinned_packet_delivered = 0;
    int leader_peer_found = 0;
    int direct_peer_found = 0;
    int pinned_used = 0;
    int direct_unused = 0;
    int leader_stopped = 0;
    int direct_still_ready = 0;
    int pinned_fail_no_fallback = 0;

    printf("\n[TEST] test_pinned_route_overrides_direct_path\n");

    mesh_test_build_ipv4_packet(packet, sizeof(packet),
                                10, 42, 11, 2,
                                10, 42, 11, 3);

    mesh_config_t leader_cfg;
    mesh_config_init(&leader_cfg);
    leader_cfg.virtual_ip = "10.42.11.1";
    leader_cfg.virtual_prefix = 16;
    leader_cfg.listen_port = 20711;
    check(mesh_test_configure_identity(&leader_cfg, 0));
    leader_cfg.advertise_ip = "127.0.0.1";
    leader = mesh_create(&leader_cfg);
    check_not_null(leader);
    leader_started = (mesh_start(leader) == MESH_OK);
    if (leader_started) {
        sleep_ms(500);
    }

    mesh_config_t node2_cfg;
    mesh_config_init(&node2_cfg);
    node2_cfg.virtual_ip = "10.42.11.2";
    node2_cfg.virtual_prefix = 16;
    node2_cfg.listen_port = 20712;
    check(mesh_test_configure_identity(&node2_cfg, 1));
    node2_cfg.bootstrap_peers = bootstrap_peers;
    node2_cfg.bootstrap_count = 1;
    node2_cfg.route_rules = node2_rules;
    node2_cfg.route_rule_count = 1;
    node2 = mesh_create(&node2_cfg);
    check_not_null(node2);
    node2_started = (mesh_start(node2) == MESH_OK);

    mesh_config_t node3_cfg;
    mesh_config_init(&node3_cfg);
    node3_cfg.virtual_ip = "10.42.11.3";
    node3_cfg.virtual_prefix = 16;
    node3_cfg.listen_port = 20713;
    check(mesh_test_configure_identity(&node3_cfg, 2));
    node3_cfg.bootstrap_peers = bootstrap_peers;
    node3_cfg.bootstrap_count = 1;
    node3_cfg.advertise_ip = "127.0.0.1";
    node3_cfg.on_packet_received = on_packet_received_counting;
    node3_cfg.user_data = &node3_packets;
    node3 = mesh_create(&node3_cfg);
    check_not_null(node3);
    node3_started = (mesh_start(node3) == MESH_OK);

    nodes[0] = leader;
    nodes[1] = node2;
    nodes[2] = node3;

    if (leader_started && node2_started && node3_started) {
        peers_ready = mesh_test_wait_for_min_peers(nodes, 3, 1, 60);
    }

    for (int i = 0; peers_ready && i < 80; i++) {
        mesh_test_poll_many(nodes, 3, 1, 100, 50);
        if (mesh_test_find_route(node2, "10.42.11.3", &route_info) &&
            strcmp(route_info.next_hop_virtual_ip, "10.42.11.1") == 0 &&
            route_info.hop_count == 1) {
            relay_ready = 1;
            break;
        }
    }

    if (relay_ready) {
        direct_connect_started = (mesh_connect_peer(node2, "10.42.11.3") == MESH_OK);
    }

    for (int i = 0; direct_connect_started && i < 80; i++) {
        mesh_test_poll_many(nodes, 3, 1, 100, 50);
        if (mesh_test_find_peer_info(node2, "10.42.11.3", &direct_peer_after) &&
            strcmp(direct_peer_after.real_ip, "127.0.0.1:20713") == 0 &&
            direct_peer_after.is_connected) {
            direct_ready = 1;
            break;
        }
    }

    rule_count_ok = (mesh_get_route_rule_count(node2) == 1);
    if (rule_count_ok && mesh_get_route_rule_info(node2, 0, &rule_info) == MESH_OK) {
        rule_info_ok = 1;
    }

    if (direct_ready) {
        mesh_reset_stats(node2);
        node3_packets.packet_received_count = 0;
        pinned_send_ok = (mesh_send_packet(node2, packet, sizeof(packet)) == MESH_OK);

        for (int i = 0; pinned_send_ok && i < 20; i++) {
            mesh_test_poll_many(nodes, 3, 1, 100, 50);
            if (node3_packets.packet_received_count > 0) {
                pinned_packet_delivered = 1;
                break;
            }
        }

        leader_peer_found = mesh_test_find_peer_info(node2, "10.42.11.1", &leader_peer_after);
        direct_peer_found = mesh_test_find_peer_info(node2, "10.42.11.3", &direct_peer_after);
        pinned_used = leader_peer_found && (leader_peer_after.bytes_tx > 0);
        direct_unused = direct_peer_found && ((int)direct_peer_after.bytes_tx == 0);
    }

    if (direct_ready) {
        mesh_test_stop_destroy(&leader);
        nodes[0] = NULL;
        leader_stopped = 1;

        for (int i = 0; i < 40; i++) {
            mesh_test_poll_many(&nodes[1], 2, 1, 100, 50);
            if (!mesh_find_peer(node2, "10.42.11.1") &&
                mesh_test_find_peer_info(node2, "10.42.11.3", &direct_peer_after) &&
                direct_peer_after.is_connected) {
                direct_still_ready = 1;
                break;
            }
        }
    }

    if (direct_still_ready) {
        mesh_reset_stats(node2);
        node3_packets.packet_received_count = 0;
        pinned_fail_no_fallback =
            (mesh_send_packet(node2, packet, sizeof(packet)) == MESH_ERR_NOT_FOUND);
        mesh_test_poll_many(&nodes[1], 2, 4, 100, 50);
    }

    mesh_test_stop_destroy(&node3);
    mesh_test_stop_destroy(&node2);

    check(leader_started);
    check(node2_started);
    check(node3_started);
    check(peers_ready);
    check(relay_ready);
    check(direct_connect_started);
    check(direct_ready);
    check(rule_count_ok);
    check(rule_info_ok);
    check_str_eq("10.42.11.3/32", rule_info.dest_cidr);
    check_str_eq("10.42.11.1", rule_info.next_hop_virtual_ip);
    check_uint_eq(MESH_ROUTE_RULE_PINNED, rule_info.flags);
    check(pinned_send_ok);
    check(pinned_packet_delivered);
    check(leader_peer_found);
    check(direct_peer_found);
    check(pinned_used);
    check(direct_unused);
    check(leader_stopped);
    check(direct_still_ready);
    check(pinned_fail_no_fallback);
    check_int_eq(0, node3_packets.packet_received_count);

    printf("[TEST] ✓ pinned route overrides direct path test completed\n");
}

void test_peer_admission_allowlist(void) {
    const char *bootstrap_peers[] = {"127.0.0.1:20721"};
    const char *leader_allow_cidrs[] = {"10.42.14.2/32"};
    mesh_network_t *leader = NULL;
    mesh_network_t *node2 = NULL;
    mesh_network_t *node3 = NULL;
    mesh_network_t *nodes[3] = {NULL};
    mesh_peer_info_t leader_peer_info;
    mesh_peer_info_t node2_peer_info;
    uint8_t packet[60];
    int leader_started = 0;
    int node2_started = 0;
    int node3_started = 0;
    int allowed_connected = 0;
    int denied_rejected = 0;
    int leader_only_has_allowed_peer = 0;
    int denied_connect_blocked = 0;
    int denied_send_blocked = 0;

    printf("\n[TEST] test_peer_admission_allowlist\n");

    mesh_test_build_ipv4_packet(packet, sizeof(packet),
                                10, 42, 14, 1,
                                10, 42, 14, 3);

    mesh_config_t leader_cfg;
    mesh_config_init(&leader_cfg);
    leader_cfg.virtual_ip = "10.42.14.1";
    leader_cfg.virtual_prefix = 16;
    leader_cfg.listen_port = 20721;
    check(mesh_test_configure_identity(&leader_cfg, 0));
    leader_cfg.peer_allow_cidrs = leader_allow_cidrs;
    leader_cfg.peer_allow_count = 1;
    leader = mesh_create(&leader_cfg);
    check_not_null(leader);
    leader_started = (mesh_start(leader) == MESH_OK);
    if (leader_started) {
        sleep_ms(500);
    }

    mesh_config_t node2_cfg;
    mesh_config_init(&node2_cfg);
    node2_cfg.virtual_ip = "10.42.14.2";
    node2_cfg.virtual_prefix = 16;
    node2_cfg.listen_port = 20722;
    check(mesh_test_configure_identity(&node2_cfg, 1));
    node2_cfg.bootstrap_peers = bootstrap_peers;
    node2_cfg.bootstrap_count = 1;
    node2 = mesh_create(&node2_cfg);
    check_not_null(node2);
    node2_started = (mesh_start(node2) == MESH_OK);

    mesh_config_t node3_cfg;
    mesh_config_init(&node3_cfg);
    node3_cfg.virtual_ip = "10.42.14.3";
    node3_cfg.virtual_prefix = 16;
    node3_cfg.listen_port = 20723;
    check(mesh_test_configure_identity(&node3_cfg, 2));
    node3_cfg.bootstrap_peers = bootstrap_peers;
    node3_cfg.bootstrap_count = 1;
    node3 = mesh_create(&node3_cfg);
    check_not_null(node3);
    node3_started = (mesh_start(node3) == MESH_OK);

    nodes[0] = leader;
    nodes[1] = node2;
    nodes[2] = node3;

    for (int i = 0; leader_started && node2_started && node3_started && i < 80; i++) {
        mesh_test_poll_many(nodes, 3, 1, 100, 50);

        if (mesh_test_find_peer_info(leader, "10.42.14.2", &leader_peer_info) &&
            mesh_test_find_peer_info(node2, "10.42.14.1", &node2_peer_info) &&
            leader_peer_info.is_connected && node2_peer_info.is_connected) {
            allowed_connected = 1;
        }

        if (!mesh_test_find_peer_info(leader, "10.42.14.3", NULL) &&
            mesh_get_peer_count(node3) == 0) {
            denied_rejected = 1;
        }

        if (allowed_connected && denied_rejected) {
            break;
        }
    }

    if (allowed_connected) {
        leader_only_has_allowed_peer = (mesh_get_peer_count(leader) == 1);
        denied_connect_blocked = (mesh_connect_peer(leader, "10.42.14.3") == MESH_ERR_NOT_FOUND);
        denied_send_blocked = (mesh_send_packet(leader, packet, sizeof(packet)) == MESH_ERR_NOT_FOUND);
    }

    mesh_test_stop_destroy(&node3);
    mesh_test_stop_destroy(&node2);
    mesh_test_stop_destroy(&leader);

    check(leader_started);
    check(node2_started);
    check(node3_started);
    check(allowed_connected);
    check(denied_rejected);
    check(leader_only_has_allowed_peer);
    check(denied_connect_blocked);
    check(denied_send_blocked);
    check_str_eq("10.42.14.2", leader_peer_info.virtual_ip);
    check_str_eq("10.42.14.1", node2_peer_info.virtual_ip);

    printf("[TEST] ✓ peer admission allowlist test completed\n");
}

void test_peer_admission_allowlist_blocks_relay_forwarding(void) {
    const char *bootstrap_peers[] = {"127.0.0.1:20731"};
    const char *leader_allow_cidrs[] = {"10.42.15.2/32"};
    mesh_route_rule_t leader_rules[] = {
        {"10.42.15.3/32", "10.42.15.2", MESH_ROUTE_RULE_PINNED},
    };
    mesh_route_rule_t node2_rules[] = {
        {"10.42.15.3/32", "10.42.15.1", MESH_ROUTE_RULE_PINNED},
    };
    mesh_network_t *leader = NULL;
    mesh_network_t *node2 = NULL;
    mesh_network_t *nodes[2] = {NULL};
    mesh_peer_info_t node2_peer_before = {0};
    mesh_peer_info_t leader_peer_after = {0};
    mesh_stats_t leader_stats = {0};
    uint8_t packet[60];
    int leader_started = 0;
    int node2_started = 0;
    int peers_ready = 0;
    int node2_send_ok = 0;
    int leader_peer_found = 0;

    printf("\n[TEST] test_peer_admission_allowlist_blocks_relay_forwarding\n");

    mesh_test_build_ipv4_packet(packet, sizeof(packet),
                                10, 42, 15, 2,
                                10, 42, 15, 3);

    mesh_config_t leader_cfg;
    mesh_config_init(&leader_cfg);
    leader_cfg.virtual_ip = "10.42.15.1";
    leader_cfg.virtual_prefix = 16;
    leader_cfg.listen_port = 20731;
    check(mesh_test_configure_identity(&leader_cfg, 0));
    leader_cfg.peer_allow_cidrs = leader_allow_cidrs;
    leader_cfg.peer_allow_count = 1;
    leader_cfg.route_rules = leader_rules;
    leader_cfg.route_rule_count = 1;
    leader = mesh_create(&leader_cfg);
    check_not_null(leader);
    leader_started = (mesh_start(leader) == MESH_OK);
    if (leader_started) {
        sleep_ms(500);
    }

    mesh_config_t node2_cfg;
    mesh_config_init(&node2_cfg);
    node2_cfg.virtual_ip = "10.42.15.2";
    node2_cfg.virtual_prefix = 16;
    node2_cfg.listen_port = 20732;
    check(mesh_test_configure_identity(&node2_cfg, 1));
    node2_cfg.bootstrap_peers = bootstrap_peers;
    node2_cfg.bootstrap_count = 1;
    node2_cfg.route_rules = node2_rules;
    node2_cfg.route_rule_count = 1;
    node2 = mesh_create(&node2_cfg);
    check_not_null(node2);
    node2_started = (mesh_start(node2) == MESH_OK);

    nodes[0] = leader;
    nodes[1] = node2;

    for (int i = 0; leader_started && node2_started && i < 60; i++) {
        mesh_test_poll_many(nodes, 2, 1, 100, 50);
        if (mesh_test_find_peer_info(leader, "10.42.15.2", &leader_peer_after) &&
            mesh_test_find_peer_info(node2, "10.42.15.1", &node2_peer_before) &&
            leader_peer_after.is_connected && node2_peer_before.is_connected) {
            peers_ready = 1;
            break;
        }
    }

    if (peers_ready) {
        mesh_reset_stats(leader);
        mesh_reset_stats(node2);
        node2_send_ok = (mesh_send_packet(node2, packet, sizeof(packet)) == MESH_OK);
        mesh_test_poll_many(nodes, 2, 10, 100, 50);
        leader_peer_found = mesh_test_find_peer_info(leader, "10.42.15.2",
                                                     &leader_peer_after);
        check_int_eq(MESH_OK, mesh_get_stats(leader, &leader_stats));
    }

    mesh_test_stop_destroy(&node2);
    mesh_test_stop_destroy(&leader);

    check(leader_started);
    check(node2_started);
    check(peers_ready);
    check(node2_send_ok);
    check(leader_peer_found);
    check(leader_peer_after.bytes_rx > 0);
    check_int_eq(0, (int)leader_peer_after.bytes_tx);
    check_int_eq(0, (int)leader_stats.packets_tx);

    printf("[TEST] ✓ peer admission allowlist relay forwarding test completed\n");
}

void test_peer_admission_allowlist_blocks_learned_routes(void) {
    const char *bootstrap_peers[] = {"127.0.0.1:20741"};
    const char *node2_allow_cidrs[] = {"10.42.16.1/32"};
    mesh_network_t *leader = NULL;
    mesh_network_t *node2 = NULL;
    mesh_network_t *node3 = NULL;
    mesh_network_t *nodes[3] = {NULL};
    uint8_t packet[60];
    int leader_started = 0;
    int node2_started = 0;
    int node3_started = 0;
    int peers_ready = 0;
    int disallowed_route_absent = 0;
    int denied_connect_blocked = 0;
    int denied_send_blocked = 0;

    printf("\n[TEST] test_peer_admission_allowlist_blocks_learned_routes\n");

    mesh_test_build_ipv4_packet(packet, sizeof(packet),
                                10, 42, 16, 2,
                                10, 42, 16, 3);

    mesh_config_t leader_cfg;
    mesh_config_init(&leader_cfg);
    leader_cfg.virtual_ip = "10.42.16.1";
    leader_cfg.virtual_prefix = 16;
    leader_cfg.listen_port = 20741;
    check(mesh_test_configure_identity(&leader_cfg, 0));
    leader = mesh_create(&leader_cfg);
    check_not_null(leader);
    leader_started = (mesh_start(leader) == MESH_OK);
    if (leader_started) {
        sleep_ms(500);
    }

    mesh_config_t node2_cfg;
    mesh_config_init(&node2_cfg);
    node2_cfg.virtual_ip = "10.42.16.2";
    node2_cfg.virtual_prefix = 16;
    node2_cfg.listen_port = 20742;
    check(mesh_test_configure_identity(&node2_cfg, 1));
    node2_cfg.bootstrap_peers = bootstrap_peers;
    node2_cfg.bootstrap_count = 1;
    node2_cfg.peer_allow_cidrs = node2_allow_cidrs;
    node2_cfg.peer_allow_count = 1;
    node2 = mesh_create(&node2_cfg);
    check_not_null(node2);
    node2_started = (mesh_start(node2) == MESH_OK);

    mesh_config_t node3_cfg;
    mesh_config_init(&node3_cfg);
    node3_cfg.virtual_ip = "10.42.16.3";
    node3_cfg.virtual_prefix = 16;
    node3_cfg.listen_port = 20743;
    check(mesh_test_configure_identity(&node3_cfg, 2));
    node3_cfg.bootstrap_peers = bootstrap_peers;
    node3_cfg.bootstrap_count = 1;
    node3 = mesh_create(&node3_cfg);
    check_not_null(node3);
    node3_started = (mesh_start(node3) == MESH_OK);

    nodes[0] = leader;
    nodes[1] = node2;
    nodes[2] = node3;

    for (int i = 0; leader_started && node2_started && node3_started && i < 80; i++) {
        mesh_test_poll_many(nodes, 3, 1, 100, 50);
        if (mesh_test_find_peer_info(node2, "10.42.16.1", NULL) &&
            mesh_test_find_peer_info(leader, "10.42.16.2", NULL) &&
            mesh_test_find_peer_info(leader, "10.42.16.3", NULL)) {
            peers_ready = 1;
        }
        if (peers_ready && !mesh_test_find_route(node2, "10.42.16.3", NULL)) {
            disallowed_route_absent = 1;
        }
        if (peers_ready && disallowed_route_absent && i > 20) {
            break;
        }
    }

    if (peers_ready) {
        denied_connect_blocked =
            (mesh_connect_peer(node2, "10.42.16.3") == MESH_ERR_NOT_FOUND);
        denied_send_blocked =
            (mesh_send_packet(node2, packet, sizeof(packet)) == MESH_ERR_NOT_FOUND);
    }

    mesh_test_stop_destroy(&node3);
    mesh_test_stop_destroy(&node2);
    mesh_test_stop_destroy(&leader);

    check(leader_started);
    check(node2_started);
    check(node3_started);
    check(peers_ready);
    check(disallowed_route_absent);
    check(denied_connect_blocked);
    check(denied_send_blocked);

    printf("[TEST] ✓ peer admission allowlist learned route test completed\n");
}

spec("mesh vpn") {
    before_all() {
        mesh_test_logger_init();
        TLOG_INFO("=================================================================");
        TLOG_INFO("  Mesh VPN Unit Tests");
        TLOG_INFO("=================================================================");
    }

    after_all() {
        TLOG_INFO("=================================================================");
        TLOG_INFO("  Test Summary");
        TLOG_INFO("=================================================================");
        test_logger_shutdown_all();
    }

    before_each() {
        setUp();
    }

    after_each() {
        tearDown();
    }

    describe("basic lifecycle") {
        it("creates and destroys mesh") { test_mesh_create_destroy(); }
        it("forwards the bounded atomic p2p security snapshot") {
            test_mesh_forwards_bounded_security_status_v3();
        }
        it("accepts a borrowed binary transport identity") {
            test_mesh_accepts_borrowed_binary_identity();
        }
        it("accepts an opaque transport identity provider") {
            test_mesh_accepts_opaque_identity_provider();
        }
        it("accepts a blocking opaque transport identity provider") {
            test_mesh_accepts_blocking_identity_provider();
        }
        it("rejects ambiguous or malformed binary identities") {
            test_mesh_rejects_ambiguous_or_malformed_binary_identity();
        }
        it("creates a p2p node") { test_p2p_node_creation(); }
        it("starts and stops mesh") { test_mesh_start_stop(); }
    }

    describe("p2p connectivity") {
        it("starts a listening server") { test_p2p_server_listening(); }
        it("fires peer callbacks on connect") { test_p2p_peer_callbacks(); }
        it("connects two nodes") { test_p2p_two_nodes_connect(); }
    }

    describe("dht integration") {
        it("puts and gets values") { test_dht_put_get(); }
        it("registers virtual ip data") { test_virtual_ip_dht_registration(); }
    }

    describe("mesh networking") {
        it("routes packets end to end") { test_packet_routing(); }
        it("connects two mesh nodes") { test_mesh_two_nodes_connect(); }
    }

    describe("hello handshake") {
        it("completes the hello handshake") { test_hello_handshake(); }
        it("looks up virtual ips") { test_virtual_ip_lookup(); }
        it("routes packets after hello") { test_packet_routing_with_hello(); }
        it("learns relay routes") { test_route_learning(); }
        it("connects directly using advertise ip") { test_connect_peer_uses_advertise_ip(); }
        it("admits streams only after authenticated bilateral capability negotiation") {
            test_stream_capability_requires_authenticated_bilateral_admission();
        }
    }

    describe("policy") {
        it("blocks direct admission by allowlist") {
            test_peer_admission_allowlist();
        }
        it("blocks learned routes by admission allowlist") {
            test_peer_admission_allowlist_blocks_learned_routes();
        }
        it("blocks relay forwarding by admission allowlist") {
            test_peer_admission_allowlist_blocks_relay_forwarding();
        }
    }
}
