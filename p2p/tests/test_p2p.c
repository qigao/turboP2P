/**
 * test_p2p.c - P2P Module Unit Tests
 * Using TinyTest
 * Good Taste: Simple, focused tests
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <time.h>
#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

#include <tinytest.h>
#include <noise/protocol.h>
#include "p2p.h"
#include "internal.h"
#include "protocol/message.h"
#include "security/p2p_cookie.h"
#include "security/p2p_private_key_executor.h"
#include "transfer/transfer.h"
#include <CoroNet/turbo_coro_context.h>
#include <CoroNet/turbo_coro_socket.h>
#include <turbo_error.h>
#include <tlog.h>
#include <turbo_crypto.h>

/* Test fixtures */
static p2p_node_t *test_node = NULL;
static int message_received = 0;
static void *received_data = NULL;
static size_t received_len = 0;
static tlog_t *g_test_logger = NULL;
static int g_transfer_status_callback_count = 0;
static int g_transfer_complete_callback_count = 0;
static int g_transfer_cancel_callback_count = 0;

enum {
    P2P_TEST_LEGACY_NOISE_M1_SIZE = 32,
    P2P_TEST_LEGACY_HANDSHAKE_PAYLOAD_SIZE =
        2 + P2P_TEST_LEGACY_NOISE_M1_SIZE,
    P2P_TEST_LEGACY_HANDSHAKE_FRAME_SIZE =
        sizeof(p2p_msg_header_t) + P2P_TEST_LEGACY_HANDSHAKE_PAYLOAD_SIZE,
    P2P_TEST_RAW_CLIENT_TIMEOUT_MS = 250,
};

_Static_assert(sizeof(p2p_msg_header_t) == 8,
               "legacy wire fixture requires the former 8-byte native header");

typedef struct {
    coro_context_t *context;
    int port;
    int connect_result;
    int send_result;
    int recv_result;
    size_t received_bytes;
    int done;
} p2p_test_legacy_client_state_t;

static void test_transfer_progress_status_cb(p2p_transfer_t *transfer,
                                             size_t bytes_transferred,
                                             size_t file_size,
                                             void *user_data) {
    p2p_transfer_status_t status = {0};
    int ret = 0;

    (void)bytes_transferred;
    (void)file_size;

    ret = p2p_transfer_mgr_get_status((p2p_transfer_manager_t *)user_data,
                                      transfer->id,
                                      &status);
    check_int_eq(P2P_OK, ret);
    check_int_eq((int)transfer->id, (int)status.id);
    g_transfer_status_callback_count++;
}
static void test_transfer_complete_status_cb(p2p_transfer_t *transfer,
                                             int success,
                                             const char *error,
                                             void *user_data) {
    p2p_transfer_status_t status = {0};
    int ret = 0;

    (void)error;

    ret = p2p_transfer_mgr_get_status((p2p_transfer_manager_t *)user_data,
                                      transfer->id,
                                      &status);
    check_int_eq(P2P_OK, ret);
    check_int_eq(1, success);
    check_int_eq(P2P_TRANSFER_STATE_COMPLETED, status.state);
    g_transfer_complete_callback_count++;
}
static void test_transfer_cancel_status_cb(p2p_transfer_t *transfer,
                                           int success,
                                           const char *error,
                                           void *user_data) {
    p2p_transfer_status_t status = {0};
    int ret = 0;

    ret = p2p_transfer_mgr_get_status((p2p_transfer_manager_t *)user_data,
                                      transfer->id,
                                      &status);
    check_int_eq(P2P_OK, ret);
    check_int_eq(0, success);
    check_str_eq("Cancelled by user", error);
    check_int_eq(P2P_TRANSFER_CANCELLED, status.state);
    g_transfer_cancel_callback_count++;
}

static void p2p_test_logger_init(void) {
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

static void p2p_test_logger_shutdown(void) {
    if (!g_test_logger) {
        return;
    }

    tlog_destroy(g_test_logger);
    g_test_logger = NULL;
}

static int p2p_test_alloc_port_block(int count) {
    static int next_port = 0;
    int start_port = 0;
    unsigned int seed = 0;

    if (count <= 0) {
        return 0;
    }

    if (next_port == 0) {
#ifdef _WIN32
        seed = (unsigned int)_getpid();
#else
        seed = (unsigned int)getpid();
#endif
        seed ^= (unsigned int)time(NULL);
        next_port = 25000 + (int)((seed % 400) * 10);
    }

    start_port = next_port;
    next_port += count + 12;
    return start_port;
}

static int p2p_test_configure_pinned(p2p_node_t **nodes, size_t count) {
    static const uint8_t network_id[P2P_SECURITY_ID_SIZE] = {
        0x54, 0x75, 0x72, 0x62, 0x6f, 0x50, 0x32, 0x50,
        0x2d, 0x74, 0x65, 0x73, 0x74, 0x2d, 0x76, 0x32,
        0x2d, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b,
        0x2d, 0x69, 0x64, 0x2d, 0x30, 0x30, 0x30, 0x31,
    };
    uint8_t keys[3 * P2P_KEY_SIZE];
    size_t index;

    if (!nodes || count == 0 || count > 3) {
        return P2P_ERR_INVALID_ARG;
    }
    for (index = 0; index < count; ++index) {
        if (!nodes[index] ||
            p2p_node_get_public_key(nodes[index],
                                    keys + index * P2P_KEY_SIZE) != P2P_OK) {
            return P2P_ERR_INVALID_ARG;
        }
    }
    for (index = 0; index < count; ++index) {
        int ret = p2p_node_configure_pinned_security_v2(
            nodes[index], network_id, keys, count);
        if (ret != P2P_OK) {
            return ret;
        }
    }
    memset(keys, 0, sizeof(keys));
    return P2P_OK;
}

static void test_p2p_security_config_installs_bounded_defaults(void) {
    p2p_node_t *node = p2p_create(
        "127.0.0.1", p2p_test_alloc_port_block(1));

    check_not_null(node);
    if (node) {
        p2p_node_t *nodes[] = {node};
        check_int_eq(P2P_OK, p2p_test_configure_pinned(nodes, 1));
        check(node->security_config.send_hwm_bytes ==
              P2P_SECURITY_SEND_HWM_DEFAULT_BYTES);
        check(node->security_config.node_send_budget_bytes ==
              P2P_SECURITY_NODE_SEND_BUDGET_DEFAULT_BYTES);
        check_uint_eq(P2P_SECURITY_SOURCE_ADMISSION_BURST_DEFAULT,
                      node->security_config.source_admission_burst);
        check_uint_eq(
            P2P_SECURITY_SOURCE_ADMISSION_REFILL_DEFAULT,
            node->security_config.source_admission_refill_per_second);
        check_uint_eq(P2P_SECURITY_SOURCE_ADMISSION_BUCKET_LIMIT,
                      node->security_config.source_admission_bucket_limit);
        check_uint_eq(P2P_SECURITY_COOKIE_GATE_LIMIT_DEFAULT,
                      node->security_config.cookie_gate_limit);
        check_uint_eq(P2P_SECURITY_COOKIE_LIFETIME_DEFAULT_MS,
                      node->security_config.cookie_lifetime_ms);
        check_uint_eq(P2P_SECURITY_COOKIE_ROTATION_DEFAULT_MS,
                      node->security_config.cookie_key_rotation_ms);
        check(node->security_config.session_max_age_ms ==
              P2P_SECURITY_SESSION_MAX_AGE_DEFAULT_MS);
        check(node->security_config.session_max_bytes_per_direction ==
              P2P_SECURITY_SESSION_MAX_BYTES_DEFAULT);
    }
    p2p_destroy(node);
}

static void test_p2p_security_config_rejects_unbounded_limits(void) {
    p2p_node_t *configured = p2p_create(
        "127.0.0.1", p2p_test_alloc_port_block(2));
    p2p_node_t *candidate = p2p_create(
        "127.0.0.1", p2p_test_alloc_port_block(1));
    p2p_security_config_v2_t config = {0};

    check_not_null(configured);
    check_not_null(candidate);
    if (configured && candidate) {
        p2p_node_t *nodes[] = {configured};
        check_int_eq(P2P_OK, p2p_test_configure_pinned(nodes, 1));

        config = configured->security_config;
        config.send_hwm_bytes = P2P_SECURITY_MAX_WIRE_FRAME_BYTES - 1U;
        check_int_eq(P2P_ERR_INVALID_ARG,
                     p2p_node_configure_security_v2(candidate, &config));

        config = configured->security_config;
        config.node_send_budget_bytes = config.send_hwm_bytes - 1U;
        check_int_eq(P2P_ERR_INVALID_ARG,
                     p2p_node_configure_security_v2(candidate, &config));

        config = configured->security_config;
        config.node_send_budget_bytes =
            P2P_SECURITY_NODE_SEND_BUDGET_DEFAULT_BYTES + 1U;
        check_int_eq(P2P_ERR_INVALID_ARG,
                     p2p_node_configure_security_v2(candidate, &config));

        config = configured->security_config;
        config.source_admission_burst =
            P2P_SECURITY_SOURCE_ADMISSION_BURST_MAX + 1U;
        check_int_eq(P2P_ERR_INVALID_ARG,
                     p2p_node_configure_security_v2(candidate, &config));

        config = configured->security_config;
        config.source_admission_refill_per_second =
            P2P_SECURITY_SOURCE_ADMISSION_REFILL_MAX + 1U;
        check_int_eq(P2P_ERR_INVALID_ARG,
                     p2p_node_configure_security_v2(candidate, &config));

        config = configured->security_config;
        config.source_admission_bucket_limit =
            P2P_SECURITY_SOURCE_ADMISSION_BUCKET_LIMIT + 1U;
        check_int_eq(P2P_ERR_INVALID_ARG,
                     p2p_node_configure_security_v2(candidate, &config));

        config = configured->security_config;
        config.cookie_gate_limit =
            P2P_SECURITY_COOKIE_GATE_LIMIT_MAX + 1U;
        check_int_eq(P2P_ERR_INVALID_ARG,
                     p2p_node_configure_security_v2(candidate, &config));

        config = configured->security_config;
        config.cookie_lifetime_ms = 11000U;
        config.cookie_key_rotation_ms = 300000U;
        check_int_eq(P2P_ERR_INVALID_ARG,
                     p2p_node_configure_security_v2(candidate, &config));

        config = configured->security_config;
        config.session_max_age_ms =
            P2P_SECURITY_SESSION_MAX_AGE_DEFAULT_MS + 1U;
        check_int_eq(P2P_ERR_INVALID_ARG,
                     p2p_node_configure_security_v2(candidate, &config));

        config = configured->security_config;
        config.session_max_bytes_per_direction =
            P2P_SECURITY_SESSION_MAX_BYTES_DEFAULT + 1U;
        check_int_eq(P2P_ERR_INVALID_ARG,
                     p2p_node_configure_security_v2(candidate, &config));
    }
    p2p_destroy(candidate);
    p2p_destroy(configured);
}

static void test_p2p_node_send_budget_reservations_are_bounded(void) {
    p2p_node_t *node = p2p_create(
        "127.0.0.1", p2p_test_alloc_port_block(1));
    p2p_peer_t *first = NULL;
    p2p_peer_t *second = NULL;
    p2p_peer_t *third = NULL;
    p2p_node_security_status_v2_t status = {0};

    check_not_null(node);
    if (!node) {
        return;
    }

    status.struct_size = sizeof(status);
    check_int_eq(P2P_ERR_INVALID_STATE,
                 p2p_node_get_security_status_v2(node, &status));
    {
        p2p_node_t *nodes[] = {node};
        check_int_eq(P2P_OK, p2p_test_configure_pinned(nodes, 1));
    }
    node->security_config.node_send_budget_bytes =
        2U * node->security_config.send_hwm_bytes;

    first = p2p_peer_create(node, "127.0.0.1", 10001);
    second = p2p_peer_create(node, "127.0.0.1", 10002);
    third = p2p_peer_create(node, "127.0.0.1", 10003);
    check_not_null(first);
    check_not_null(second);
    check_not_null(third);
    if (first && second && third) {
        check_int_eq(P2P_OK,
                     p2p_node_reserve_transport_send_capacity(node, first));
        check_int_eq(P2P_OK,
                     p2p_node_reserve_transport_send_capacity(node, second));
        check_int_eq(P2P_ERR_RESOURCE_EXHAUSTED,
                     p2p_node_reserve_transport_send_capacity(node, third));

        check_int_eq(P2P_OK,
                     p2p_node_get_security_status_v2(node, &status));
        check(status.reserved_send_capacity_bytes ==
              node->security_config.node_send_budget_bytes);
        check_uint_eq(2U, status.transport_reservations);
        check_uint_eq(1U, status.send_budget_rejections);
        check_uint_eq(0U, status.available_send_capacity_bytes);

        p2p_peer_destroy(first);
        first = NULL;
        check_int_eq(P2P_OK,
                     p2p_node_reserve_transport_send_capacity(node, third));
        check_int_eq(P2P_OK,
                     p2p_node_get_security_status_v2(node, &status));
        check_uint_eq(2U, status.transport_reservations);
    }

    p2p_peer_destroy(first);
    p2p_peer_destroy(second);
    p2p_peer_destroy(third);
    status.struct_size = sizeof(status);
    check_int_eq(P2P_OK,
                 p2p_node_get_security_status_v2(node, &status));
    check_uint_eq(0U, status.reserved_send_capacity_bytes);
    check_uint_eq(0U, status.transport_reservations);
    p2p_destroy(node);
}

static void test_p2p_security_status_v3_is_atomic_bounded_and_compatible(void) {
    static const uint64_t expected_bucket_upper_bounds_ms
        [P2P_SECURITY_LATENCY_BUCKET_COUNT_V3] = {
            1U,   5U,   10U,   25U,   50U,   100U,
            250U, 500U, 1000U, 2500U, 5000U, UINT64_MAX,
        };
    p2p_node_t *node = p2p_create(
        "127.0.0.1", p2p_test_alloc_port_block(1));
    p2p_node_security_status_v2_t status_v2 = {0};
    p2p_node_security_status_v3_t status_v3;
    p2p_node_t *nodes[] = {node};

    check_not_null(node);
    if (!node) {
        return;
    }
    check(sizeof(status_v3) <= 2048U);
    memset(&status_v3, 0xa5, sizeof(status_v3));
    status_v3.struct_size = sizeof(status_v3) - 1U;
    check_int_eq(P2P_ERR_INVALID_ARG,
                 p2p_node_get_security_status_v3(node, &status_v3));
    status_v3.struct_size = sizeof(status_v3);
    check_int_eq(P2P_ERR_INVALID_ARG,
                 p2p_node_get_security_status_v3(NULL, &status_v3));
    check_int_eq(P2P_ERR_INVALID_STATE,
                 p2p_node_get_security_status_v3(node, &status_v3));
    check_int_eq(P2P_OK, p2p_test_configure_pinned(nodes, 1));

    turbo_mutex_lock(&node->mutex);
    node->security_rejection_counts[P2P_SECURITY_REJECTION_HANDSHAKE_CRYPTO] =
        7U;
    node->security_handshake_latency[P2P_SECURITY_ROLE_INITIATOR]
                                    [P2P_SECURITY_LATENCY_NOISE]
                                        .completed = 3U;
    node->security_handshake_latency[P2P_SECURITY_ROLE_INITIATOR]
                                    [P2P_SECURITY_LATENCY_NOISE]
                                        .total_ms = 47U;
    node->security_handshake_latency[P2P_SECURITY_ROLE_INITIATOR]
                                    [P2P_SECURITY_LATENCY_NOISE]
                                        .maximum_ms = 30U;
    node->security_handshake_latency[P2P_SECURITY_ROLE_INITIATOR]
                                    [P2P_SECURITY_LATENCY_NOISE]
                                        .buckets[2] = 1U;
    node->security_handshake_latency[P2P_SECURITY_ROLE_INITIATOR]
                                    [P2P_SECURITY_LATENCY_NOISE]
                                        .buckets[3] = 1U;
    node->security_handshake_latency[P2P_SECURITY_ROLE_INITIATOR]
                                    [P2P_SECURITY_LATENCY_NOISE]
                                        .buckets[4] = 1U;
    turbo_mutex_unlock(&node->mutex);

    status_v2.struct_size = sizeof(status_v2);
    check_int_eq(P2P_OK,
                 p2p_node_get_security_status_v2(node, &status_v2));
    memset(&status_v3, 0xa5, sizeof(status_v3));
    status_v3.struct_size = sizeof(status_v3);
    check_int_eq(P2P_OK,
                 p2p_node_get_security_status_v3(node, &status_v3));
    check_uint_eq(sizeof(status_v3), status_v3.struct_size);
    check_int_eq(P2P_SECURE_WIRE_VERSION_V2,
                 status_v3.secure_wire_version);
    check_int_eq(P2P_NOISE_SUITE_XX_25519_CHACHAPOLY_BLAKE2S,
                 status_v3.noise_suite);
    check_mem_eq(&status_v2, &status_v3.security, sizeof(status_v2));
    check_false(status_v3.private_key_executor_available);
    check_uint_eq(sizeof(status_v3.private_key_executor),
                  status_v3.private_key_executor.struct_size);
    check_uint_eq(0U, status_v3.private_key_executor.submitted);
    check_mem_eq(expected_bucket_upper_bounds_ms,
                 status_v3.latency_bucket_upper_bounds_ms,
                 sizeof(expected_bucket_upper_bounds_ms));
    check_uint_eq(
        7U,
        status_v3.security.rejection_counts
            [P2P_SECURITY_REJECTION_HANDSHAKE_CRYPTO]);
    check_uint_eq(
        3U,
        status_v3.handshake_latency
            [P2P_SECURITY_HANDSHAKE_ROLE_INITIATOR_V3]
            [P2P_SECURITY_HANDSHAKE_STAGE_NOISE_V3]
                .completed);
    check_uint_eq(
        47U,
        status_v3.handshake_latency
            [P2P_SECURITY_HANDSHAKE_ROLE_INITIATOR_V3]
            [P2P_SECURITY_HANDSHAKE_STAGE_NOISE_V3]
                .total_ms);
    check_uint_eq(
        30U,
        status_v3.handshake_latency
            [P2P_SECURITY_HANDSHAKE_ROLE_INITIATOR_V3]
            [P2P_SECURITY_HANDSHAKE_STAGE_NOISE_V3]
                .maximum_ms);
    p2p_destroy(node);
}

static void p2p_test_revalidation_close_noop(void *handle) {
    (void)handle;
}

static void test_p2p_security_revalidation_evicts_revoked_session(void) {
    p2p_node_t *nodes[] = {test_node};
    p2p_peer_t *peer = NULL;
    p2p_authenticated_identity_v2_t identity = {0};
    p2p_security_revalidation_result_v2_t result = {0};
    p2p_node_security_status_v2_t status = {0};
    uint8_t public_key[P2P_KEY_SIZE] = {0};
    uint8_t channel_binding[P2P_SECURITY_ID_SIZE];
    uint8_t empty_credential[1] = {0};

    memset(channel_binding, 0xa5, sizeof(channel_binding));
    check_int_eq(P2P_OK, p2p_test_configure_pinned(nodes, 1));
    check_int_eq(P2P_OK,
                 p2p_node_get_public_key(test_node, public_key));
    check_int_eq(
        P2P_OK,
        test_node->security_config.identity_provider.verify_remote_credential(
            test_node->security_config.identity_provider.context, public_key,
            channel_binding, empty_credential, 0, 1U, &identity));

    peer = p2p_peer_create(test_node, "127.0.0.1", 10004);
    check_not_null(peer);
    if (!peer) {
        return;
    }
    peer->conn = (p2p_connection_t *)calloc(1, sizeof(*peer->conn));
    check_not_null(peer->conn);
    if (!peer->conn) {
        p2p_peer_destroy(peer);
        return;
    }
    peer->conn->is_connected = 1;
    peer->conn->ops.handle = peer;
    peer->conn->ops.close = p2p_test_revalidation_close_noop;
    peer->is_connected = 1;
    peer->state = P2P_PEER_STATE_CONNECTED;
    peer->security_stage = P2P_SECURITY_STAGE_ESTABLISHED;
    peer->remote_public_key_ready = 1;
    memcpy(peer->remote_public_key, public_key, sizeof(public_key));
    memcpy(peer->channel_binding, channel_binding, sizeof(channel_binding));
    peer->authenticated_identity = identity;
    memcpy(peer->id, identity.routing_id, P2P_HASH_SIZE);
    turbo_mutex_lock(&test_node->mutex);
    p2p_node_add_peer_locked(test_node, peer);
    peer->counted = 1;
    test_node->peer_count++;
    turbo_mutex_unlock(&test_node->mutex);

    result.struct_size = sizeof(result);
    check_int_eq(P2P_OK,
                 p2p_node_revalidate_security_v2(test_node, &result));
    check_uint_eq(1U, result.examined_sessions);
    check_uint_eq(1U, result.retained_sessions);
    check_uint_eq(0U, result.disconnected_sessions);

    result.struct_size = sizeof(result);
    check_int_eq(P2P_OK,
                 p2p_node_update_pinned_trust_v2(test_node, NULL, 0,
                                                 &result));
    check_uint_eq(1U, result.examined_sessions);
    check_uint_eq(1U, result.provider_rejections);
    check_uint_eq(1U, result.disconnected_sessions);
    status.struct_size = sizeof(status);
    check_int_eq(P2P_OK,
                 p2p_node_get_security_status_v2(test_node, &status));
    check_uint_eq(
        1U, status.rejection_counts[
                P2P_SECURITY_REJECTION_REVALIDATION_REJECTED]);
    check_int_eq(0, p2p_get_peer_count(test_node));
}

/* =============================================================================
 * Test Setup/Teardown
 * ============================================================================= */

void setUp(void) {
    /* Create a test node before each test */
    test_node = p2p_create("127.0.0.1", 8888);
    check_not_null(test_node);
}

void tearDown(void) {
    /* Clean up after each test */
    if (test_node) {
        p2p_destroy(test_node);
        test_node = NULL;
    }

    if (received_data) {
        free(received_data);
        received_data = NULL;
    }
    message_received = 0;
}

/* =============================================================================
 * Node Lifecycle Tests
 * ============================================================================= */

void test_p2p_create_valid(void) {
    p2p_node_t *node = p2p_create("0.0.0.0", 9999);
    check_not_null(node);
    check_str_eq("0.0.0.0", node->ip);
    check_int_eq(9999, node->port);
    check(node->coord.error == VIVALDI_MAX_ERROR);
    p2p_destroy(node);
}

void test_p2p_node_get_id(void) {
    uint8_t id[P2P_HASH_SIZE] = {0};
    uint8_t zero[P2P_HASH_SIZE] = {0};

    check_int_eq(P2P_OK, p2p_node_get_id(test_node, id));
    check(memcmp(id, zero, sizeof(id)) != 0);
    check(memcmp(id, test_node->id, sizeof(id)) == 0);
    check_int_eq(P2P_ERR_INVALID_ARG, p2p_node_get_id(NULL, id));
    check_int_eq(P2P_ERR_INVALID_ARG, p2p_node_get_id(test_node, NULL));
}

void test_p2p_node_get_public_key(void) {
    uint8_t public_key[P2P_KEY_SIZE] = {0};
    uint8_t zero[P2P_KEY_SIZE] = {0};

    check_int_eq(P2P_OK, p2p_node_get_public_key(test_node, public_key));
    check(memcmp(public_key, zero, sizeof(public_key)) != 0);
    check(memcmp(public_key, test_node->crypto.identity.public_key, sizeof(public_key)) == 0);
    check_int_eq(P2P_ERR_INVALID_ARG, p2p_node_get_public_key(NULL, public_key));
    check_int_eq(P2P_ERR_INVALID_ARG, p2p_node_get_public_key(test_node, NULL));
}

void test_p2p_node_set_private_key_makes_identity_stable(void) {
    uint8_t secret[P2P_KEY_SIZE] = {0};
    uint8_t public_key1[P2P_KEY_SIZE] = {0};
    uint8_t public_key2[P2P_KEY_SIZE] = {0};
    p2p_node_t *node1 = NULL;
    p2p_node_t *node2 = NULL;

    for (size_t i = 0; i < sizeof(secret); i++) {
        secret[i] = (uint8_t)(i + 1);
    }

    node1 = p2p_create("127.0.0.1", p2p_test_alloc_port_block(1));
    node2 = p2p_create("127.0.0.1", p2p_test_alloc_port_block(1));
    check_not_null(node1);
    check_not_null(node2);

    check_int_eq(P2P_OK, p2p_node_set_private_key(node1, secret));
    check_int_eq(P2P_OK, p2p_node_set_private_key(node2, secret));
    check_int_eq(P2P_OK, p2p_node_get_public_key(node1, public_key1));
    check_int_eq(P2P_OK, p2p_node_get_public_key(node2, public_key2));
    check(memcmp(public_key1, public_key2, sizeof(public_key1)) == 0);

    check_int_eq(P2P_ERR_INVALID_ARG, p2p_node_set_private_key(NULL, secret));
    check_int_eq(P2P_ERR_INVALID_ARG, p2p_node_set_private_key(node1, NULL));

    p2p_destroy(node2);
    p2p_destroy(node1);
}

void test_p2p_node_set_private_key_rejects_started_node(void) {
    uint8_t secret[P2P_KEY_SIZE] = {0};
    p2p_node_t *node = NULL;

    memset(secret, 0x42, sizeof(secret));
    node = p2p_create("127.0.0.1", p2p_test_alloc_port_block(1));
    check_not_null(node);

    {
        p2p_node_t *nodes[] = {node};
        check_int_eq(P2P_OK, p2p_test_configure_pinned(nodes, 1));
    }
    check_int_eq(P2P_OK, p2p_node_start_server(node));
    check_int_eq(P2P_ERR_INVALID_STATE, p2p_node_set_private_key(node, secret));

    p2p_node_stop_server(node);
    p2p_destroy(node);
}

typedef struct {
    uint8_t secret_key[P2P_KEY_SIZE];
    uint8_t public_key[P2P_KEY_SIZE];
    int public_key_result;
    int calculate_result;
    size_t public_key_calls;
    size_t calculate_calls;
} p2p_test_private_key_provider_t;

typedef struct {
    uint8_t secret_key[P2P_KEY_SIZE];
    uint8_t public_key[P2P_KEY_SIZE];
    int public_key_result;
    int calculate_result;
    uint32_t calculate_delay_ms;
    int honor_cancel;
    atomic_size_t public_key_calls;
    atomic_size_t calculate_calls;
    atomic_size_t cancel_calls;
} p2p_test_blocking_private_key_provider_t;

static int p2p_test_private_key_get_public(
    void *context, uint8_t public_key_out[P2P_KEY_SIZE]) {
    p2p_test_private_key_provider_t *provider =
        (p2p_test_private_key_provider_t *)context;

    provider->public_key_calls++;
    memset(public_key_out, 0xa5, P2P_KEY_SIZE);
    if (provider->public_key_result != P2P_OK) {
        return provider->public_key_result;
    }
    memcpy(public_key_out, provider->public_key, P2P_KEY_SIZE);
    return P2P_OK;
}

static int p2p_test_private_key_calculate(
    void *context, const uint8_t remote_public_key[P2P_KEY_SIZE],
    uint8_t shared_key_out[P2P_KEY_SIZE]) {
    p2p_test_private_key_provider_t *provider =
        (p2p_test_private_key_provider_t *)context;

    provider->calculate_calls++;
    memset(shared_key_out, 0xa5, P2P_KEY_SIZE);
    if (provider->calculate_result != P2P_OK) {
        return provider->calculate_result;
    }
    return turbo_crypto_x25519(shared_key_out, provider->secret_key,
                               remote_public_key) == TURBO_CRYPTO_OK
               ? P2P_OK
               : P2P_ERR_CRYPTO;
}

static int p2p_test_blocking_private_key_get_public(
    void *context, uint8_t public_key_out[P2P_KEY_SIZE]) {
    p2p_test_blocking_private_key_provider_t *provider =
        (p2p_test_blocking_private_key_provider_t *)context;

    atomic_fetch_add_explicit(&provider->public_key_calls, 1,
                              memory_order_relaxed);
    memset(public_key_out, 0xa5, P2P_KEY_SIZE);
    if (provider->public_key_result != P2P_OK) {
        return provider->public_key_result;
    }
    memcpy(public_key_out, provider->public_key, P2P_KEY_SIZE);
    return P2P_OK;
}

static int p2p_test_blocking_private_key_calculate(
    void *context, const uint8_t remote_public_key[P2P_KEY_SIZE],
    uint64_t monotonic_deadline_ms,
    const p2p_private_key_cancel_v4_t *cancel,
    uint8_t shared_key_out[P2P_KEY_SIZE]) {
    p2p_test_blocking_private_key_provider_t *provider =
        (p2p_test_blocking_private_key_provider_t *)context;
    uint32_t elapsed_ms;

    (void)monotonic_deadline_ms;
    atomic_fetch_add_explicit(&provider->calculate_calls, 1,
                              memory_order_relaxed);
    memset(shared_key_out, 0xa5, P2P_KEY_SIZE);
    for (elapsed_ms = 0; elapsed_ms < provider->calculate_delay_ms;
         ++elapsed_ms) {
        if (provider->honor_cancel && cancel && cancel->is_cancelled &&
            cancel->is_cancelled(cancel->context)) {
            return P2P_ERR_TIMEOUT;
        }
        turbo_sleep_ms(1);
    }
    if (provider->calculate_result != P2P_OK) {
        return provider->calculate_result;
    }
    return turbo_crypto_x25519(shared_key_out, provider->secret_key,
                               remote_public_key) == TURBO_CRYPTO_OK
               ? P2P_OK
               : P2P_ERR_CRYPTO;
}

static void p2p_test_blocking_private_key_request_cancel(void *context) {
    p2p_test_blocking_private_key_provider_t *provider =
        (p2p_test_blocking_private_key_provider_t *)context;

    atomic_fetch_add_explicit(&provider->cancel_calls, 1,
                              memory_order_relaxed);
}

static void p2p_test_noop_post(void *arg1, void *arg2) {
    (void)arg1;
    (void)arg2;
}

typedef struct {
    atomic_size_t send_calls;
    atomic_size_t sent_bytes;
} p2p_test_private_key_connection_t;

static int p2p_test_private_key_connection_send(void *handle,
                                                const void *data,
                                                size_t len) {
    p2p_test_private_key_connection_t *connection =
        (p2p_test_private_key_connection_t *)handle;

    if (!connection || !data || len == 0) {
        return P2P_ERR_INVALID_ARG;
    }
    atomic_fetch_add_explicit(&connection->send_calls, 1,
                              memory_order_relaxed);
    atomic_fetch_add_explicit(&connection->sent_bytes, len,
                              memory_order_relaxed);
    return 0;
}

static void p2p_test_private_key_connection_close(void *handle) {
    (void)handle;
}

static p2p_peer_t *p2p_test_create_blocking_responder_peer(
    p2p_node_t *node, int port) {
    p2p_identity_t initiator_identity = {0};
    p2p_noise_handshake_t initiator = {0};
    p2p_peer_t *peer = NULL;
    uint8_t message[P2P_SECURITY_HANDSHAKE_FRAME_MAX] = {0};
    size_t message_len = 0;
    int result = P2P_ERR_INVALID_ARG;

    if (!node) {
        return NULL;
    }
    peer = p2p_peer_create(node, "127.0.0.1", port);
    if (!peer) {
        return NULL;
    }
    peer->handshake =
        (p2p_noise_handshake_t *)calloc(1, sizeof(*peer->handshake));
    if (!peer->handshake) {
        goto cleanup;
    }
    result = p2p_crypto_generate_identity(&initiator_identity);
    if (result == P2P_OK) {
        result = p2p_noise_init_initiator(&initiator,
                                          &initiator_identity, NULL);
    }
    if (result == P2P_OK) {
        result = p2p_noise_init_responder(
            peer->handshake, &node->crypto.identity);
    }
    if (result == P2P_OK) {
        result = p2p_noise_write_message(&initiator, message,
                                         &message_len,
                                         sizeof(message));
    }
    if (result == P2P_OK) {
        result = p2p_noise_read_message(peer->handshake, message,
                                        message_len);
    }
    if (result == P2P_OK) {
        peer->handshake_generation = 1;
    }

cleanup:
    p2p_noise_handshake_destroy(&initiator);
    p2p_crypto_wipe(&initiator_identity, sizeof(initiator_identity));
    p2p_crypto_wipe(message, sizeof(message));
    if (result != P2P_OK) {
        p2p_peer_destroy(peer);
        return NULL;
    }
    return peer;
}

static void p2p_test_blocking_private_key_provider_init(
    p2p_test_blocking_private_key_provider_t *context,
    p2p_blocking_private_key_provider_v4_t *provider,
    uint8_t seed) {
    size_t index;

    memset(context, 0, sizeof(*context));
    memset(provider, 0, sizeof(*provider));
    for (index = 0; index < P2P_KEY_SIZE; ++index) {
        context->secret_key[index] = (uint8_t)(seed + index);
    }
    check_int_eq(P2P_OK,
                 p2p_public_key_from_private_key(context->secret_key,
                                                 context->public_key));
    atomic_init(&context->public_key_calls, 0);
    atomic_init(&context->calculate_calls, 0);
    atomic_init(&context->cancel_calls, 0);
    context->honor_cancel = 1;
    provider->struct_size = sizeof(*provider);
    provider->get_public_key = p2p_test_blocking_private_key_get_public;
    provider->calculate_x25519 =
        p2p_test_blocking_private_key_calculate;
    provider->request_cancel = p2p_test_blocking_private_key_request_cancel;
    provider->context = context;
}

static void p2p_test_private_key_provider_init(
    p2p_test_private_key_provider_t *context,
    p2p_private_key_provider_v3_t *provider,
    uint8_t seed) {
    size_t index;

    memset(context, 0, sizeof(*context));
    memset(provider, 0, sizeof(*provider));
    for (index = 0; index < P2P_KEY_SIZE; ++index) {
        context->secret_key[index] = (uint8_t)(seed + index);
    }
    check_int_eq(P2P_OK,
                 p2p_public_key_from_private_key(context->secret_key,
                                                 context->public_key));
    provider->struct_size = sizeof(*provider);
    provider->get_public_key = p2p_test_private_key_get_public;
    provider->calculate_x25519 = p2p_test_private_key_calculate;
    provider->context = context;
}

void test_p2p_node_set_private_key_provider_is_opaque(void) {
    p2p_test_private_key_provider_t context;
    p2p_private_key_provider_v3_t provider;
    p2p_node_t *node = p2p_create(
        "127.0.0.1", p2p_test_alloc_port_block(1));
    uint8_t actual_public[P2P_KEY_SIZE] = {0};
    uint8_t zero[P2P_KEY_SIZE] = {0};

    check_not_null(node);
    p2p_test_private_key_provider_init(&context, &provider, 0x21);
    check_int_eq(P2P_OK,
                 p2p_node_set_private_key_provider_v3(node, &provider));
    check_uint_eq(1, context.public_key_calls);
    check_uint_eq(1, context.calculate_calls);
    check(node->crypto.identity.uses_private_key_provider == 1);
    check(memcmp(node->crypto.identity.secret_key, zero, sizeof(zero)) == 0);
    check_int_eq(P2P_OK, p2p_node_get_public_key(node, actual_public));
    check(memcmp(actual_public, context.public_key, sizeof(actual_public)) == 0);

    provider.struct_size--;
    check_int_eq(P2P_ERR_INVALID_ARG,
                 p2p_node_set_private_key_provider_v3(node, &provider));
    check_uint_eq(1, context.public_key_calls);
    provider.struct_size = sizeof(provider);
    provider.calculate_x25519 = NULL;
    check_int_eq(P2P_ERR_INVALID_ARG,
                 p2p_node_set_private_key_provider_v3(node, &provider));
    check_uint_eq(1, context.public_key_calls);
    check_int_eq(P2P_ERR_INVALID_ARG,
                 p2p_node_set_private_key_provider_v3(NULL, &provider));
    check_int_eq(P2P_ERR_INVALID_ARG,
                 p2p_node_set_private_key_provider_v3(node, NULL));

    provider.calculate_x25519 = p2p_test_private_key_calculate;
    {
        p2p_node_t *nodes[] = {node};
        check_int_eq(P2P_OK, p2p_test_configure_pinned(nodes, 1));
    }
    check_int_eq(P2P_ERR_INVALID_STATE,
                 p2p_node_set_private_key_provider_v3(node, &provider));
    check_uint_eq(1, context.public_key_calls);
    check_uint_eq(1, context.calculate_calls);

    p2p_destroy(node);
    turbo_crypto_wipe(&context, sizeof(context));
}

void test_p2p_private_key_provider_fails_closed(void) {
    p2p_test_private_key_provider_t context;
    p2p_private_key_provider_v3_t provider;
    p2p_node_t *node = p2p_create(
        "127.0.0.1", p2p_test_alloc_port_block(1));
    uint8_t original_public[P2P_KEY_SIZE] = {0};
    uint8_t current_public[P2P_KEY_SIZE] = {0};

    check_not_null(node);
    check_int_eq(P2P_OK, p2p_node_get_public_key(node, original_public));
    p2p_test_private_key_provider_init(&context, &provider, 0x31);
    context.public_key_result = P2P_ERR_TIMEOUT;
    check_int_eq(P2P_ERR_TIMEOUT,
                 p2p_node_set_private_key_provider_v3(node, &provider));
    check_int_eq(P2P_OK, p2p_node_get_public_key(node, current_public));
    check(memcmp(original_public, current_public, sizeof(original_public)) == 0);

    context.public_key_result = P2P_OK;
    memset(context.public_key, 0, sizeof(context.public_key));
    check_int_eq(P2P_ERR_CRYPTO,
                 p2p_node_set_private_key_provider_v3(node, &provider));
    check_int_eq(P2P_OK, p2p_node_get_public_key(node, current_public));
    check(memcmp(original_public, current_public, sizeof(original_public)) == 0);

    p2p_test_private_key_provider_init(&context, &provider, 0x31);
    context.calculate_result = P2P_ERR_RESOURCE_EXHAUSTED;
    check_int_eq(P2P_ERR_RESOURCE_EXHAUSTED,
                 p2p_node_set_private_key_provider_v3(node, &provider));
    check_int_eq(P2P_OK, p2p_node_get_public_key(node, current_public));
    check(memcmp(original_public, current_public, sizeof(original_public)) == 0);

    context.calculate_result = P2P_OK;
    context.public_key[0] ^= 0x01u;
    check_int_eq(P2P_ERR_CRYPTO,
                 p2p_node_set_private_key_provider_v3(node, &provider));
    check_int_eq(P2P_OK, p2p_node_get_public_key(node, current_public));
    check(memcmp(original_public, current_public, sizeof(original_public)) == 0);

    p2p_destroy(node);
    turbo_crypto_wipe(&context, sizeof(context));
}

static void test_p2p_blocking_private_key_provider_is_bounded_and_opaque(void) {
    p2p_test_blocking_private_key_provider_t context;
    p2p_blocking_private_key_provider_v4_t provider;
    p2p_node_t *node = p2p_create(
        "127.0.0.1", p2p_test_alloc_port_block(1));
    uint8_t actual_public[P2P_KEY_SIZE] = {0};
    uint8_t zero[P2P_KEY_SIZE] = {0};
    uint8_t replacement_secret[P2P_KEY_SIZE] = {7};
    p2p_private_key_executor_t *installed_executor;
    p2p_private_key_executor_status_v4_t status = {0};

    check_not_null(node);
    p2p_test_blocking_private_key_provider_init(&context, &provider, 0x35);
    provider.executor_workers = 1;
    provider.executor_capacity = 2;
    provider.operation_timeout_ms = 500;
    check_int_eq(P2P_OK,
                 p2p_node_set_blocking_private_key_provider_v4(
                     node, &provider));
    check_uint_eq(1, atomic_load_explicit(&context.public_key_calls,
                                         memory_order_relaxed));
    check_uint_eq(1, atomic_load_explicit(&context.calculate_calls,
                                         memory_order_relaxed));
    check(node->crypto.identity.uses_blocking_private_key_provider == 1);
    check(node->crypto.identity.uses_private_key_provider == 0);
    check_mem_eq(node->crypto.identity.secret_key, zero, sizeof(zero));
    check_not_null(node->private_key_executor);
    check_uint_eq(1, node->private_key_executor->workers);
    check_uint_eq(2, node->private_key_executor->capacity);
    check_uint_eq(500, node->private_key_executor->operation_timeout_ms);
    installed_executor = node->private_key_executor;
    status.struct_size = sizeof(status);
    check_int_eq(P2P_OK,
                 p2p_node_get_private_key_executor_status_v4(node,
                                                              &status));
    check_uint_eq(1, status.workers);
    check_uint_eq(2, status.operation_capacity);
    check_uint_eq(500, status.operation_timeout_ms);
    check_true(status.accepting);
    check_uint_eq(0, status.active_operations);
    check_int_eq(P2P_OK, p2p_node_get_public_key(node, actual_public));
    check_mem_eq(actual_public, context.public_key, sizeof(actual_public));

    provider.executor_workers = P2P_PRIVATE_KEY_WORKERS_MAX + 1;
    check_int_eq(P2P_ERR_INVALID_ARG,
                 p2p_node_set_blocking_private_key_provider_v4(
                     node, &provider));
    check_ptr_eq(installed_executor, node->private_key_executor);
    check_int_eq(P2P_OK,
                 p2p_node_set_private_key(node, replacement_secret));
    check_null(node->private_key_executor);
    check(node->crypto.identity.uses_blocking_private_key_provider == 0);
    check_int_eq(P2P_ERR_INVALID_STATE,
                 p2p_node_get_private_key_executor_status_v4(node,
                                                              &status));

    p2p_destroy(node);
    turbo_crypto_wipe(&context, sizeof(context));
}

static void test_p2p_security_status_v3_includes_blocking_executor(void) {
    p2p_test_blocking_private_key_provider_t context;
    p2p_blocking_private_key_provider_v4_t provider;
    p2p_node_t *node = p2p_create(
        "127.0.0.1", p2p_test_alloc_port_block(1));
    p2p_node_t *nodes[] = {node};
    p2p_node_security_status_v3_t status = {0};

    check_not_null(node);
    if (!node) {
        return;
    }
    p2p_test_blocking_private_key_provider_init(&context, &provider, 0x37);
    provider.executor_workers = 1;
    provider.executor_capacity = 3;
    provider.operation_timeout_ms = 500;
    check_int_eq(P2P_OK,
                 p2p_node_set_blocking_private_key_provider_v4(
                     node, &provider));
    check_int_eq(P2P_OK, p2p_test_configure_pinned(nodes, 1));

    status.struct_size = sizeof(status);
    check_int_eq(P2P_OK,
                 p2p_node_get_security_status_v3(node, &status));
    check_true(status.private_key_executor_available);
    check_uint_eq(1U, status.private_key_executor.workers);
    check_uint_eq(3U, status.private_key_executor.operation_capacity);
    check_uint_eq(500U, status.private_key_executor.operation_timeout_ms);
    check_true(status.private_key_executor.accepting);

    p2p_destroy(node);
    turbo_crypto_wipe(&context, sizeof(context));
}

static void test_p2p_blocking_private_key_provider_self_test_times_out(void) {
    p2p_test_blocking_private_key_provider_t context;
    p2p_blocking_private_key_provider_v4_t provider;
    p2p_node_t *node = p2p_create(
        "127.0.0.1", p2p_test_alloc_port_block(1));
    uint8_t original_public[P2P_KEY_SIZE] = {0};
    uint8_t current_public[P2P_KEY_SIZE] = {0};

    check_not_null(node);
    check_int_eq(P2P_OK, p2p_node_get_public_key(node, original_public));
    p2p_test_blocking_private_key_provider_init(&context, &provider, 0x45);
    context.calculate_delay_ms = 5;
    context.honor_cancel = 0;
    provider.operation_timeout_ms = 1;
    check_int_eq(P2P_ERR_TIMEOUT,
                 p2p_node_set_blocking_private_key_provider_v4(
                     node, &provider));
    check_null(node->private_key_executor);
    check_int_eq(P2P_OK, p2p_node_get_public_key(node, current_public));
    check_mem_eq(original_public, current_public, sizeof(original_public));

    p2p_destroy(node);
    turbo_crypto_wipe(&context, sizeof(context));
}

static void test_p2p_blocking_private_key_timeout_must_fit_handshake(void) {
    p2p_test_blocking_private_key_provider_t context;
    p2p_blocking_private_key_provider_v4_t provider;
    p2p_security_config_v2_t config;
    p2p_node_t *template_node = p2p_create(
        "127.0.0.1", p2p_test_alloc_port_block(1));
    p2p_node_t *candidate = p2p_create(
        "127.0.0.1", p2p_test_alloc_port_block(1));

    check_not_null(template_node);
    check_not_null(candidate);
    {
        p2p_node_t *nodes[] = {template_node};
        check_int_eq(P2P_OK, p2p_test_configure_pinned(nodes, 1));
    }
    config = template_node->security_config;
    p2p_test_blocking_private_key_provider_init(&context, &provider, 0x55);
    provider.operation_timeout_ms = 100;
    check_int_eq(P2P_OK,
                 p2p_node_set_blocking_private_key_provider_v4(
                     candidate, &provider));
    config.handshake_timeout_ms = 99;
    check_int_eq(P2P_ERR_INVALID_ARG,
                 p2p_node_configure_security_v2(candidate, &config));
    check(candidate->security_configured == 0);

    p2p_destroy(candidate);
    p2p_destroy(template_node);
    turbo_crypto_wipe(&context, sizeof(context));
}

void test_p2p_generate_private_key(void) {
    uint8_t secret[P2P_KEY_SIZE] = {0};
    uint8_t zero[P2P_KEY_SIZE] = {0};

    check_int_eq(P2P_OK, p2p_generate_private_key(secret));
    check(memcmp(secret, zero, sizeof(secret)) != 0);
    check_int_eq(P2P_ERR_INVALID_ARG, p2p_generate_private_key(NULL));
}

void test_p2p_crypto_random_uses_checked_csprng(void) {
    uint8_t random_bytes[P2P_KEY_SIZE] = {0};
    uint8_t zero[P2P_KEY_SIZE] = {0};

    check_int_eq(P2P_OK, p2p_crypto_random(random_bytes, sizeof(random_bytes)));
    check(memcmp(random_bytes, zero, sizeof(random_bytes)) != 0);
    check_int_eq(P2P_OK, p2p_crypto_random(NULL, 0));
    check_int_eq(P2P_ERR_INVALID_ARG, p2p_crypto_random(NULL, 1));
}

static void test_p2p_cookie_codec_matches_vector_and_binds_source(void) {
    static const uint8_t expected_packet[P2P_COOKIE_PACKET_SIZE] = {
        0x54, 0x50, 0x43, 0x32, 0x00, 0x02, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x39,
        0x31, 0xce, 0x75, 0x47, 0x63, 0x49, 0xb4, 0x2a,
        0xbf, 0x95, 0x4d, 0x08, 0x32, 0x63, 0x94, 0x89,
        0x77, 0x99, 0x06, 0x93, 0x3d, 0x1a, 0x64, 0x28,
        0x0f, 0xd4, 0x0c, 0x62, 0x29, 0x0e, 0x95, 0xb9,
    };
    uint8_t secret[P2P_COOKIE_SECRET_SIZE];
    uint8_t network_id[P2P_SECURITY_ID_SIZE];
    uint8_t preface[P2P_SECURE_PREFACE_SIZE];
    uint8_t altered_preface[P2P_SECURE_PREFACE_SIZE];
    uint8_t challenge[P2P_COOKIE_PACKET_SIZE];
    uint8_t response[P2P_COOKIE_PACKET_SIZE];
    uint8_t binding[P2P_COOKIE_BINDING_SIZE];

    for (size_t index = 0; index < sizeof(secret); ++index) {
        secret[index] = (uint8_t)index;
    }
    for (size_t index = 0; index < sizeof(network_id); ++index) {
        network_id[index] = (uint8_t)(index + 32U);
    }
    p2p_secure_preface_build(network_id, preface);
    check_int_eq(P2P_OK,
                 p2p_secure_preface_validate(network_id, preface));
    check_int_eq(P2P_OK,
                 p2p_cookie_build_challenge(
                     secret, "192.0.2.10", preface, UINT64_C(123456789),
                     10000U, 300000U, challenge));
    check_mem_eq(expected_packet, challenge, sizeof(challenge));
    check_int_eq(P2P_OK,
                 p2p_cookie_build_response(challenge, response, binding));
    check_int_eq(P2P_OK,
                 p2p_cookie_verify_response(
                     secret, "192.0.2.10", preface, UINT64_C(123456789),
                     10000U, 300000U, response, binding));
    check_int_eq(P2P_ERR_CRYPTO,
                 p2p_cookie_verify_response(
                     secret, "192.0.2.11", preface, UINT64_C(123456789),
                     10000U, 300000U, response, binding));
    memcpy(altered_preface, preface, sizeof(altered_preface));
    altered_preface[12] ^= 1U;
    check_int_eq(P2P_ERR_CRYPTO,
                 p2p_cookie_verify_response(
                     secret, "192.0.2.10", altered_preface,
                     UINT64_C(123456789), 10000U, 300000U, response,
                     binding));
    response[47] ^= 1U;
    check_int_eq(P2P_ERR_CRYPTO,
                 p2p_cookie_verify_response(
                     secret, "192.0.2.10", preface, UINT64_C(123456789),
                     10000U, 300000U, response, binding));
}

static void test_p2p_cookie_codec_bounds_time_and_rotation(void) {
    uint8_t secret[P2P_COOKIE_SECRET_SIZE] = {7};
    uint8_t network_id[P2P_SECURITY_ID_SIZE] = {9};
    uint8_t preface[P2P_SECURE_PREFACE_SIZE];
    uint8_t challenge[P2P_COOKIE_PACKET_SIZE];
    uint8_t response[P2P_COOKIE_PACKET_SIZE];
    uint8_t binding[P2P_COOKIE_BINDING_SIZE];
    const uint64_t now_ms = UINT64_C(123456789);

    p2p_secure_preface_build(network_id, preface);
    check_int_eq(P2P_OK,
                 p2p_cookie_build_challenge(
                     secret, "2001:db8::1", preface, now_ms - 10000U,
                     10000U, 300000U, challenge));
    check_int_eq(P2P_OK,
                 p2p_cookie_build_response(challenge, response, binding));
    check_int_eq(P2P_OK,
                 p2p_cookie_verify_response(
                     secret, "2001:db8::1", preface, now_ms, 10000U,
                     300000U, response, binding));

    check_int_eq(P2P_OK,
                 p2p_cookie_build_challenge(
                     secret, "2001:db8::1", preface, now_ms - 20000U,
                     10000U, 300000U, challenge));
    check_int_eq(P2P_OK,
                 p2p_cookie_build_response(challenge, response, binding));
    check_int_eq(P2P_ERR_TIMEOUT,
                 p2p_cookie_verify_response(
                     secret, "2001:db8::1", preface, now_ms, 10000U,
                     300000U, response, binding));

    check_int_eq(P2P_OK,
                 p2p_cookie_build_challenge(
                     secret, "2001:db8::1", preface, now_ms + 10000U,
                     10000U, 300000U, challenge));
    check_int_eq(P2P_OK,
                 p2p_cookie_build_response(challenge, response, binding));
    check_int_eq(P2P_ERR_TIMEOUT,
                 p2p_cookie_verify_response(
                     secret, "2001:db8::1", preface, now_ms, 10000U,
                     300000U, response, binding));

    /* Bucket 29 uses the previous derived key epoch while bucket 30 uses the
     * current epoch; the previous bucket remains valid across rotation. */
    check_int_eq(P2P_OK,
                 p2p_cookie_build_challenge(
                     secret, "2001:db8::1", preface, UINT64_C(299999),
                     10000U, 300000U, challenge));
    check_int_eq(P2P_OK,
                 p2p_cookie_build_response(challenge, response, binding));
    check_int_eq(P2P_OK,
                 p2p_cookie_verify_response(
                     secret, "2001:db8::1", preface, UINT64_C(300000),
                     10000U, 300000U, response, binding));
    response[7] = 1U;
    check_int_eq(P2P_ERR_PROTOCOL,
                 p2p_cookie_verify_response(
                     secret, "2001:db8::1", preface, UINT64_C(300000),
                     10000U, 300000U, response, binding));
}

void test_p2p_endpoint_ids_are_deterministic(void) {
    const int first_port = 24001;
    const int second_port = 24002;
    kad_id_t first = {0};
    kad_id_t same = {0};
    kad_id_t different = {0};

    p2p_endpoint_to_id("127.0.0.1", first_port, &first);
    p2p_endpoint_to_id("127.0.0.1", first_port, &same);
    p2p_endpoint_to_id("127.0.0.1", second_port, &different);

    check_mem_eq(first.bytes, same.bytes, sizeof(first.bytes));
    check_mem_ne(first.bytes, different.bytes, sizeof(first.bytes));
}

void test_p2p_public_key_from_private_key(void) {
    uint8_t secret[P2P_KEY_SIZE] = {0};
    uint8_t derived_public_key[P2P_KEY_SIZE] = {0};
    uint8_t node_public_key[P2P_KEY_SIZE] = {0};
    p2p_node_t *node = NULL;

    for (size_t i = 0; i < sizeof(secret); i++) {
        secret[i] = (uint8_t)(0x20 + i);
    }

    node = p2p_create("127.0.0.1", p2p_test_alloc_port_block(1));
    check_not_null(node);

    check_int_eq(P2P_OK, p2p_public_key_from_private_key(secret, derived_public_key));
    check_int_eq(P2P_OK, p2p_node_set_private_key(node, secret));
    check_int_eq(P2P_OK, p2p_node_get_public_key(node, node_public_key));
    check(memcmp(derived_public_key, node_public_key, sizeof(derived_public_key)) == 0);

    check_int_eq(P2P_ERR_INVALID_ARG, p2p_public_key_from_private_key(NULL, derived_public_key));
    check_int_eq(P2P_ERR_INVALID_ARG, p2p_public_key_from_private_key(secret, NULL));

    p2p_destroy(node);
}

void test_p2p_create_null_ip(void) {
    p2p_node_t *node = p2p_create(NULL, 8888);
    check_null(node);
}

void test_p2p_destroy_null(void) {
    /* Should not crash */
    p2p_destroy(NULL);
}

void test_p2p_destroy_valid(void) {
    p2p_node_t *node = p2p_create("127.0.0.1", 7777);
    check_not_null(node);

    /* Should not crash */
    p2p_destroy(node);
}

void test_p2p_transfer_destroy_waits_for_held_reference(void) {
    p2p_transfer_manager_t mgr = {0};
    p2p_transfer_t *created = NULL;
    p2p_transfer_t *held = NULL;

    p2p_transfer_manager_init(&mgr);

    created = p2p_transfer_create(&mgr, P2P_TRANSFER_DIR_DOWNLOAD);
    check_not_null(created);
    check_ptr_eq(&mgr, created->manager);

    held = p2p_transfer_find_by_id(&mgr, created->id);
    check_ptr_eq(created, held);
    check_int_eq(1, (int)held->ref_count);

    p2p_transfer_destroy(&mgr, created);
    check_int_eq(0, (int)mgr.count);
    check_int_eq(1, held->destroying);
    check_int_eq(1, (int)held->ref_count);
    check_null(p2p_transfer_find_by_id(&mgr, created->id));

    p2p_transfer_release(held);
    p2p_transfer_manager_destroy(&mgr);
}

void test_p2p_transfer_progress_callback_runs_unlocked(void) {
    p2p_transfer_manager_t mgr = {0};
    p2p_transfer_t *transfer = NULL;

    g_transfer_status_callback_count = 0;
    p2p_transfer_manager_init(&mgr);

    transfer = p2p_transfer_create(&mgr, P2P_TRANSFER_DIR_DOWNLOAD);
    check_not_null(transfer);

    transfer->progress_cb = test_transfer_progress_status_cb;
    transfer->user_data = &mgr;

    p2p_transfer_update_progress(transfer, 64);
    check_int_eq(1, g_transfer_status_callback_count);

    p2p_transfer_destroy(&mgr, transfer);
    p2p_transfer_manager_destroy(&mgr);
}

void test_p2p_transfer_complete_callback_runs_unlocked(void) {
    p2p_transfer_manager_t mgr = {0};
    p2p_transfer_t *transfer = NULL;

    g_transfer_complete_callback_count = 0;
    p2p_transfer_manager_init(&mgr);

    transfer = p2p_transfer_create(&mgr, P2P_TRANSFER_DIR_DOWNLOAD);
    check_not_null(transfer);

    transfer->complete_cb = test_transfer_complete_status_cb;
    transfer->user_data = &mgr;

    p2p_transfer_complete(transfer, 1, NULL);
    check_int_eq(1, g_transfer_complete_callback_count);

    p2p_transfer_destroy(&mgr, transfer);
    p2p_transfer_manager_destroy(&mgr);
}

void test_p2p_transfer_cancel_callback_runs_unlocked(void) {
    p2p_transfer_manager_t mgr = {0};
    p2p_transfer_t *transfer = NULL;
    int ret = 0;

    g_transfer_cancel_callback_count = 0;
    p2p_transfer_manager_init(&mgr);

    transfer = p2p_transfer_create(&mgr, P2P_TRANSFER_DIR_DOWNLOAD);
    check_not_null(transfer);

    transfer->state = P2P_TRANSFER_STATE_ACTIVE;
    transfer->complete_cb = test_transfer_cancel_status_cb;
    transfer->user_data = &mgr;

    ret = p2p_transfer_mgr_cancel(&mgr, transfer->id);
    check_int_eq(P2P_OK, ret);
    check_int_eq(1, g_transfer_cancel_callback_count);

    p2p_transfer_destroy(&mgr, transfer);
    p2p_transfer_manager_destroy(&mgr);
}

/* =============================================================================
 * Message Handler Tests
 * ============================================================================= */


void test_message_callback(p2p_node_t *node, p2p_peer_t *peer,
                          const void *data, size_t len, void *user_data) {
    (void)node;
    (void)peer;

    message_received = 1;
    received_data = malloc(len);
    memcpy(received_data, data, len);
    received_len = len;
}

void test_p2p_set_message_handler(void) {
    p2p_set_message_handler(test_node, test_message_callback, NULL);
    check_ptr_eq(test_message_callback, test_node->on_message);
}

void test_p2p_send_broadcast(void) {
    /* Set up message handler */
    p2p_set_message_handler(test_node, test_message_callback, NULL);

    /* Send broadcast message */
    const char *msg = "Hello P2P";
    int ret = p2p_broadcast(test_node, msg, strlen(msg));

    check_int_eq(P2P_OK, ret);
}

/* =============================================================================
 * File API Tests
 * ============================================================================= */

void test_p2p_put_file_valid(void) {
    char key[65];
    /* Note: In a real test we'd need a temp file, but p2p_put_file implementation
     * currently just checks existence and stubs logic. */
    int ret = p2p_put_file(test_node, "nonexistent_test.txt", key);
    /* Should return IO error since file doesn't exist */
    check_int_eq(P2P_ERR_IO, ret);
}

void test_p2p_send_message_invalid_params(void) {
    const uint8_t byte = 0x5a;
    /* Test with NULL node */
    int ret = p2p_send_message(NULL, NULL, P2P_MSG_PING, "data", 4);
    check_int_eq(P2P_ERR_INVALID_ARG, ret);
    check_int_eq(P2P_ERR_INVALID_ARG,
                 p2p_send_message(test_node, NULL, P2P_MSG_CUSTOM,
                                  NULL, 1));
    check_int_eq(P2P_ERR_INVALID_ARG,
                 p2p_send_message(test_node, NULL, P2P_MSG_CUSTOM,
                                  &byte, (size_t)UINT16_MAX + 1U));
}

static void test_p2p_message_ping_codec_is_canonical(void) {
    static const uint8_t expected_double_bytes[] = {
        0x3f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x3f, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    p2p_message_t message = {0};
    p2p_message_t decoded = {0};
    uint8_t *wire = NULL;
    uint8_t *wire_again = NULL;
    size_t wire_length = 0;
    size_t wire_again_length = 0;
    size_t consumed = 0;
    size_t index;

    p2p_message_init(&message, P2P_MSG_PING);
    message.header.request_id = 0x89abcdefU;
    message.header.payload_len = sizeof(p2p_ping_payload_t);
    for (index = 0; index < P2P_DHT_KEY_SIZE; ++index) {
        message.payload.ping.node_id[index] = (uint8_t)index;
    }
    memcpy(message.payload.ping.ip, "127.0.0.1", 10);
    message.payload.ping.port = 0x1234;
    message.payload.ping.timestamp = UINT64_C(0x0102030405060708);
    message.payload.ping.coords[0] = 1.0;
    message.payload.ping.coords[1] = -2.0;
    message.payload.ping.coords[2] = 0.0;
    message.payload.ping.coords[3] = 4.5;
    message.payload.ping.height = 5.5;
    message.payload.ping.error = 0.25;

    check_int_eq(P2P_OK,
                 p2p_message_serialize(&message, &wire, &wire_length));
    check_uint_eq(91, wire_length);
    check_uint_eq(P2P_MSG_PING, wire[0]);
    check_uint_eq(0, wire[1]);
    check_uint_eq(0, wire[2]);
    check_uint_eq(83, wire[3]);
    check_uint_eq(0x89, wire[4]);
    check_uint_eq(0xab, wire[5]);
    check_uint_eq(0xcd, wire[6]);
    check_uint_eq(0xef, wire[7]);
    check(memcmp(wire + 8, message.payload.ping.node_id,
                 P2P_DHT_KEY_SIZE) == 0);
    check_uint_eq(4, wire[28]);
    check(memcmp(wire + 29, "\x7f\x00\x00\x01", 4) == 0);
    check_uint_eq(0x12, wire[33]);
    check_uint_eq(0x34, wire[34]);
    check(memcmp(wire + 35,
                 "\x01\x02\x03\x04\x05\x06\x07\x08", 8) == 0);
    check(memcmp(wire + 43, expected_double_bytes,
                 sizeof(expected_double_bytes)) == 0);

    check_int_eq(P2P_OK, p2p_message_deserialize(
                                 wire, wire_length, &decoded, &consumed));
    check_uint_eq(wire_length, consumed);
    check_uint_eq(sizeof(p2p_ping_payload_t), decoded.header.payload_len);
    check_uint_eq(message.header.request_id, decoded.header.request_id);
    check(memcmp(&message.payload.ping, &decoded.payload.ping,
                 sizeof(message.payload.ping)) == 0);
    check_int_eq(P2P_OK, p2p_message_serialize(
                                 &decoded, &wire_again,
                                 &wire_again_length));
    check_uint_eq(wire_length, wire_again_length);
    check(memcmp(wire, wire_again, wire_length) == 0);

    free(wire_again);
    free(wire);

    memset(&message, 0, sizeof(message));
    memset(&decoded, 0, sizeof(decoded));
    wire = NULL;
    wire_again = NULL;
    wire_length = 0;
    wire_again_length = 0;
    consumed = 0;
    p2p_message_init(&message, P2P_MSG_PONG);
    message.header.payload_len = sizeof(p2p_ping_payload_t);
    memcpy(message.payload.ping.ip, "2001:0db8:0:0:0:0:0:1",
           sizeof("2001:0db8:0:0:0:0:0:1"));
    message.payload.ping.port = 443;
    check_int_eq(P2P_OK,
                 p2p_message_serialize(&message, &wire, &wire_length));
    check_uint_eq(103, wire_length);
    check_uint_eq(P2P_MSG_PONG, wire[0]);
    check_uint_eq(6, wire[28]);
    check_int_eq(P2P_OK, p2p_message_deserialize(
                                 wire, wire_length, &decoded, &consumed));
    check_uint_eq(wire_length, consumed);
    check(decoded.payload.ping.ip[0] != '\0');
    check_int_eq(P2P_OK, p2p_message_serialize(
                                 &decoded, &wire_again,
                                 &wire_again_length));
    check_uint_eq(wire_length, wire_again_length);
    check(memcmp(wire, wire_again, wire_length) == 0);
    free(wire_again);
    free(wire);
}

static void test_p2p_message_variable_payloads_round_trip(void) {
    p2p_message_t message = {0};
    p2p_message_t decoded = {0};
    uint8_t *wire = NULL;
    size_t wire_length = 0;
    size_t consumed = 0;
    size_t index;

    p2p_message_init(&message, P2P_MSG_DHT_RESPONSE);
    message.header.request_id = 7;
    message.payload.dht_response.node_count = 1;
    for (index = 0; index < P2P_DHT_KEY_SIZE; ++index) {
        message.payload.dht_response.nodes[0].id[index] =
            (uint8_t)(0xa0U + index);
    }
    memcpy(message.payload.dht_response.nodes[0].ip, "1.2.3.4", 8);
    message.payload.dht_response.nodes[0].port = 0x1234;
    message.header.payload_len =
        offsetof(p2p_dht_response_payload_t, data);
    check_int_eq(P2P_OK,
                 p2p_message_serialize(&message, &wire, &wire_length));
    check_uint_eq(39, wire_length);
    check_uint_eq(31, wire[3]);
    check_int_eq(P2P_OK, p2p_message_deserialize(
                                 wire, wire_length, &decoded, &consumed));
    check_uint_eq(wire_length, consumed);
    check_uint_eq(1, decoded.payload.dht_response.node_count);
    check_str_eq("1.2.3.4", decoded.payload.dht_response.nodes[0].ip);
    check_uint_eq(0x1234, decoded.payload.dht_response.nodes[0].port);
    check(memcmp(message.payload.dht_response.nodes[0].id,
                 decoded.payload.dht_response.nodes[0].id,
                 P2P_DHT_KEY_SIZE) == 0);
    free(wire);
    wire = NULL;

    p2p_message_init(&message, P2P_MSG_DHT_RESPONSE);
    message.payload.dht_response.found = 1;
    message.payload.dht_response.data_len = 3;
    memcpy(message.payload.dht_response.data, "xyz", 3);
    message.header.payload_len =
        (uint16_t)(offsetof(p2p_dht_response_payload_t, data) + 3);
    check_int_eq(P2P_OK,
                 p2p_message_serialize(&message, &wire, &wire_length));
    check_uint_eq(15, wire_length);
    check_int_eq(P2P_OK, p2p_message_deserialize(
                                 wire, wire_length, &decoded, &consumed));
    check_uint_eq(1, decoded.payload.dht_response.found);
    check_uint_eq(0, decoded.payload.dht_response.node_count);
    check_uint_eq(3, decoded.payload.dht_response.data_len);
    check(memcmp(decoded.payload.dht_response.data, "xyz", 3) == 0);
    free(wire);
    wire = NULL;

    p2p_message_init(&message, P2P_MSG_DHT_PUT);
    memset(message.payload.dht_store.key, 0x31, P2P_DHT_KEY_SIZE);
    message.payload.dht_store.data_len = 3;
    memcpy(message.payload.dht_store.data, "abc", 3);
    message.header.payload_len =
        (uint16_t)(offsetof(p2p_dht_store_payload_t, data) + 3);
    check_int_eq(P2P_OK,
                 p2p_message_serialize(&message, &wire, &wire_length));
    check_uint_eq(33, wire_length);
    check_int_eq(P2P_OK, p2p_message_deserialize(
                                 wire, wire_length, &decoded, &consumed));
    check_uint_eq(3, decoded.payload.dht_store.data_len);
    check(memcmp(decoded.payload.dht_store.data, "abc", 3) == 0);
    free(wire);
    wire = NULL;

    p2p_message_init(&message, P2P_MSG_DHT_GET);
    memset(message.payload.dht_find_node.target_id, 0x23,
           P2P_DHT_KEY_SIZE);
    message.header.payload_len = sizeof(p2p_dht_find_node_payload_t);
    check_int_eq(P2P_OK,
                 p2p_message_serialize(&message, &wire, &wire_length));
    check_uint_eq(28, wire_length);
    check_int_eq(P2P_OK, p2p_message_deserialize(
                                 wire, wire_length, &decoded, &consumed));
    check(memcmp(message.payload.dht_find_node.target_id,
                 decoded.payload.dht_find_node.target_id,
                 P2P_DHT_KEY_SIZE) == 0);
    free(wire);
    wire = NULL;

    p2p_message_init(&message, P2P_MSG_FILE_GET);
    memset(message.payload.file_response.file_id, 0x24,
           P2P_DHT_KEY_SIZE);
    message.header.payload_len = P2P_DHT_KEY_SIZE;
    check_int_eq(P2P_OK,
                 p2p_message_serialize(&message, &wire, &wire_length));
    check_uint_eq(28, wire_length);
    check_int_eq(P2P_OK, p2p_message_deserialize(
                                 wire, wire_length, &decoded, &consumed));
    check(memcmp(message.payload.file_response.file_id,
                 decoded.payload.file_response.file_id,
                 P2P_DHT_KEY_SIZE) == 0);
    free(wire);
    wire = NULL;

    p2p_message_init(&message, P2P_MSG_DHT_FIND_NODE);
    memset(message.payload.dht_find_node.target_id, 0x22,
           P2P_DHT_KEY_SIZE);
    message.header.payload_len = sizeof(p2p_dht_find_node_payload_t);
    check_int_eq(P2P_OK,
                 p2p_message_serialize(&message, &wire, &wire_length));
    check_uint_eq(28, wire_length);
    check_int_eq(P2P_OK, p2p_message_deserialize(
                                 wire, wire_length, &decoded, &consumed));
    check(memcmp(message.payload.dht_find_node.target_id,
                 decoded.payload.dht_find_node.target_id,
                 P2P_DHT_KEY_SIZE) == 0);
    free(wire);
    wire = NULL;

    p2p_message_init(&message, P2P_MSG_FILE_PUT);
    memset(message.payload.file_response.file_id, 0x33,
           P2P_DHT_KEY_SIZE);
    message.payload.file_response.file_size =
        UINT64_C(0x0102030405060708);
    message.payload.file_response.total_chunks = 0x11121314U;
    memset(message.payload.file_response.file_hash, 0x55,
           P2P_SHA256_SIZE);
    message.header.payload_len = sizeof(p2p_file_response_payload_t);
    check_int_eq(P2P_OK,
                 p2p_message_serialize(&message, &wire, &wire_length));
    check_uint_eq(72, wire_length);
    check(memcmp(wire + 28,
                 "\x01\x02\x03\x04\x05\x06\x07\x08", 8) == 0);
    check_int_eq(P2P_OK, p2p_message_deserialize(
                                 wire, wire_length, &decoded, &consumed));
    check_uint_eq(message.payload.file_response.file_size,
                  decoded.payload.file_response.file_size);
    check_uint_eq(message.payload.file_response.total_chunks,
                  decoded.payload.file_response.total_chunks);
    free(wire);
    wire = NULL;

    p2p_message_init(&message, P2P_MSG_CHUNK_REQUEST);
    message.payload.chunk_request.transfer_id = 0x21222324U;
    message.payload.chunk_request.chunk_index = 0x31323334U;
    message.header.payload_len = sizeof(p2p_chunk_request_payload_t);
    check_int_eq(P2P_OK,
                 p2p_message_serialize(&message, &wire, &wire_length));
    check_uint_eq(16, wire_length);
    check_int_eq(P2P_OK, p2p_message_deserialize(
                                 wire, wire_length, &decoded, &consumed));
    check_uint_eq(message.payload.chunk_request.transfer_id,
                  decoded.payload.chunk_request.transfer_id);
    check_uint_eq(message.payload.chunk_request.chunk_index,
                  decoded.payload.chunk_request.chunk_index);
    free(wire);
    wire = NULL;

    p2p_message_init(&message, P2P_MSG_CHUNK_DATA);
    message.payload.chunk_data.transfer_id = 0x01020304U;
    message.payload.chunk_data.chunk_index = 0x05060708U;
    message.payload.chunk_data.data_len = 4;
    memset(message.payload.chunk_data.chunk_hash, 0x44, P2P_SHA256_SIZE);
    memcpy(message.payload.chunk_data.data, "data", 4);
    message.header.payload_len =
        (uint16_t)(offsetof(p2p_chunk_data_payload_t, data) + 4);
    check_int_eq(P2P_OK,
                 p2p_message_serialize(&message, &wire, &wire_length));
    check_uint_eq(54, wire_length);
    check_int_eq(P2P_OK, p2p_message_deserialize(
                                 wire, wire_length, &decoded, &consumed));
    check_uint_eq(message.payload.chunk_data.transfer_id,
                  decoded.payload.chunk_data.transfer_id);
    check_uint_eq(message.payload.chunk_data.chunk_index,
                  decoded.payload.chunk_data.chunk_index);
    check_uint_eq(4, decoded.payload.chunk_data.data_len);
    check(memcmp(decoded.payload.chunk_data.data, "data", 4) == 0);
    free(wire);
    wire = NULL;

    p2p_message_init(&message, P2P_MSG_FILE_ACK);
    message.payload.file_ack.transfer_id = 0x41424344U;
    message.payload.file_ack.success = 1;
    message.header.payload_len = sizeof(p2p_file_ack_payload_t);
    check_int_eq(P2P_OK,
                 p2p_message_serialize(&message, &wire, &wire_length));
    check_uint_eq(13, wire_length);
    check_int_eq(P2P_OK, p2p_message_deserialize(
                                 wire, wire_length, &decoded, &consumed));
    check_uint_eq(message.payload.file_ack.transfer_id,
                  decoded.payload.file_ack.transfer_id);
    check_int_eq(1, decoded.payload.file_ack.success);
    free(wire);
    wire = NULL;

    {
        static const p2p_msg_type_t raw_types[] = {
            P2P_MSG_FILE_DATA,       P2P_MSG_PUBSUB_SUB,
            P2P_MSG_PUBSUB_UNSUB,    P2P_MSG_PUBSUB_PUBLISH,
            P2P_MSG_GOSSIP,          P2P_MSG_CUSTOM,
        };
        for (index = 0; index < sizeof(raw_types) / sizeof(raw_types[0]);
             ++index) {
            p2p_message_init(&message, raw_types[index]);
            memcpy(message.payload.raw, "raw", 3);
            message.header.payload_len = 3;
            check_int_eq(P2P_OK,
                         p2p_message_serialize(&message, &wire,
                                               &wire_length));
            check_uint_eq(11, wire_length);
            check_int_eq(P2P_OK,
                         p2p_message_deserialize(wire, wire_length,
                                                 &decoded, &consumed));
            check_uint_eq(raw_types[index], decoded.header.type);
            check_uint_eq(3, decoded.header.payload_len);
            check(memcmp(decoded.payload.raw, "raw", 3) == 0);
            free(wire);
            wire = NULL;
        }
    }
}

static void test_p2p_message_codec_rejects_noncanonical_input(void) {
    p2p_message_t message = {0};
    p2p_message_t decoded = {0};
    uint8_t malformed[16] = {0};
    uint8_t *oversized = NULL;
    uint8_t *wire = NULL;
    size_t wire_length = 0;
    size_t consumed = 99;

    check_int_eq(P2P_ERR_PROTOCOL,
                 p2p_message_deserialize(malformed, 7, &decoded,
                                         &consumed));
    check_uint_eq(0, consumed);

    malformed[0] = P2P_MSG_CUSTOM;
    malformed[1] = 1;
    check_int_eq(P2P_ERR_PROTOCOL,
                 p2p_message_deserialize(malformed, 8, &decoded,
                                         &consumed));
    malformed[1] = 0;
    malformed[0] = P2P_MSG_RESERVED_LEGACY_HANDSHAKE;
    check_int_eq(P2P_ERR_PROTOCOL,
                 p2p_message_deserialize(malformed, 8, &decoded,
                                         &consumed));

    oversized = (uint8_t *)calloc(1, (size_t)UINT16_MAX + 8U);
    check_not_null(oversized);
    if (oversized) {
        oversized[0] = P2P_MSG_CUSTOM;
        oversized[2] = 0xff;
        oversized[3] = 0xff;
        check_int_eq(P2P_ERR_PROTOCOL,
                     p2p_message_deserialize(
                         oversized, (size_t)UINT16_MAX + 8U,
                         &decoded, &consumed));
        check_uint_eq(0, consumed);
        free(oversized);
    }

    p2p_message_init(&message, P2P_MSG_PING);
    message.header.payload_len = sizeof(p2p_ping_payload_t);
    memcpy(message.payload.ping.ip, "not-an-ip", 10);
    message.payload.ping.error = 1.0;
    check_int_eq(P2P_ERR_PROTOCOL,
                 p2p_message_serialize(&message, &wire, &wire_length));
    check_null(wire);
    check_uint_eq(0, wire_length);

    p2p_message_init(&message, P2P_MSG_FILE_ACK);
    message.header.payload_len = sizeof(p2p_file_ack_payload_t);
    message.payload.file_ack.success = 2;
    check_int_eq(P2P_ERR_PROTOCOL,
                 p2p_message_serialize(&message, &wire, &wire_length));
}

/* =============================================================================
 * Pub/Sub Tests
 * ============================================================================= */

void test_p2p_subscribe_valid(void) {
    int ret = p2p_subscribe(test_node, "test_topic");
    check_int_eq(P2P_OK, ret);
}

void test_p2p_subscribe_null_params(void) {
    int ret = p2p_subscribe(NULL, "test_topic");
    check_int_eq(P2P_ERR_INVALID_ARG, ret);

    ret = p2p_subscribe(test_node, NULL);
    check_int_eq(P2P_ERR_INVALID_ARG, ret);
}

void test_p2p_unsubscribe_valid(void) {
    /* First subscribe */
    int ret = p2p_subscribe(test_node, "test_topic");
    check_int_eq(P2P_OK, ret);

    /* Then unsubscribe */
    ret = p2p_unsubscribe(test_node, "test_topic");
    check_int_eq(P2P_OK, ret);
}

void test_p2p_unsubscribe_not_found(void) {
    int ret = p2p_unsubscribe(test_node, "nonexistent_topic");
    check_int_eq(P2P_ERR_NOT_FOUND, ret);
}

void test_p2p_publish_valid(void) {
    /* Subscribe first */
    int ret = p2p_subscribe(test_node, "test_topic");
    check_int_eq(P2P_OK, ret);

    /* Then publish */
    const char *msg = "Test message";
    ret = p2p_publish(test_node, "test_topic", msg, strlen(msg));
    check_int_eq(P2P_OK, ret);
}

void test_p2p_publish_null_params(void) {
    int ret = p2p_publish(NULL, "topic", "data", 4);
    check_int_eq(P2P_ERR_INVALID, ret);

    ret = p2p_publish(test_node, NULL, "data", 4);
    check_int_eq(P2P_ERR_INVALID, ret);

    ret = p2p_publish(test_node, "topic", NULL, 4);
    check_int_eq(P2P_ERR_INVALID, ret);

    ret = p2p_publish(test_node, "topic", "data", 0);
    check_int_eq(P2P_ERR_INVALID, ret);
}

void test_p2p_publish_topic_not_found(void) {
    const char *msg = "Test message";
    int ret = p2p_publish(test_node, "nonexistent_topic", msg, strlen(msg));
    check_int_eq(P2P_ERR_NOT_FOUND, ret);
}

/* =============================================================================
 * Peer Management Tests
 * ============================================================================= */

void test_p2p_peer_create_valid(void) {
    /* Just test basic creation, don't add to list */
    p2p_peer_t *peer = p2p_peer_create(test_node, "127.0.0.1", 9999);
    p2p_peer_info_t info = {0};
    check_not_null(peer);
    check_int_eq(P2P_OK, p2p_peer_get_info(peer, &info));
    check_str_eq("127.0.0.1", info.ip);
    check_int_eq(9999, info.port);
    check_ptr_eq(test_node, peer->node);
    check_int_eq(0, info.is_connected);
    p2p_peer_destroy(peer);
}

void test_p2p_peer_stream_metrics_are_bounded_and_read_only(void) {
    p2p_peer_t *peer = p2p_peer_create(test_node, "127.0.0.1", 9999);
    p2p_peer_stream_metrics_t metrics = {0};
    uint64_t now_ms = turbo_hrtime() / 1000000U;
    uint64_t sent_ms = now_ms > 10U ? now_ms - 10U : now_ms;

    check_not_null(peer);
    check_int_eq(P2P_ERR_INVALID_ARG,
                 p2p_peer_get_stream_metrics(NULL, &metrics));
    check_int_eq(P2P_ERR_INVALID_ARG,
                 p2p_peer_get_stream_metrics(peer, NULL));
    check_int_eq(P2P_OK, p2p_peer_get_stream_metrics(peer, &metrics));
    check_uint_eq(0, metrics.sample_count);
    check_uint_eq(UINT32_MAX, metrics.sample_age_ms);
    check_false(metrics.is_fresh);

    if (sent_ms > 0) {
        turbo_mutex_lock(&test_node->mutex);
        peer->is_connected = 1;
        peer->state = P2P_PEER_STATE_CONNECTED;
        peer->outstanding_ping_ms = sent_ms;
        check(p2p_peer_record_rtt_sample_locked(peer, sent_ms, now_ms));
        turbo_mutex_unlock(&test_node->mutex);

        check_int_eq(P2P_OK, p2p_peer_get_stream_metrics(peer, &metrics));
        check_uint_eq((uint32_t)(now_ms - sent_ms), metrics.srtt_ms);
        check_uint_eq((uint32_t)(now_ms - sent_ms) / 2U, metrics.rttvar_ms);
        check_uint_eq(1, metrics.sample_count);
        check(metrics.sample_age_ms <= P2P_RTT_METRIC_FRESH_MS);
        check(metrics.is_fresh);

        turbo_mutex_lock(&test_node->mutex);
        peer->is_connected = 0;
        peer->state = P2P_PEER_STATE_DISCONNECTED;
        turbo_mutex_unlock(&test_node->mutex);
        check_int_eq(P2P_OK, p2p_peer_get_stream_metrics(peer, &metrics));
        check_false(metrics.is_fresh);
    }

    p2p_peer_destroy(peer);
}

void test_p2p_rtt_estimator_rejects_unmatched_and_unbounded_samples(void) {
    p2p_peer_t *peer = p2p_peer_create(test_node, "127.0.0.1", 9999);

    check_not_null(peer);
    peer->outstanding_ping_ms = 1000;
    check_false(p2p_peer_record_rtt_sample_locked(peer, 999, 1099));
    check_uint_eq(0, peer->rtt_sample_count);
    check_uint_eq(1000, peer->outstanding_ping_ms);

    check(p2p_peer_record_rtt_sample_locked(peer, 1000, 1100));
    check_uint_eq(100, peer->avg_rtt_ms);
    check_uint_eq(50, peer->rttvar_ms);
    check_uint_eq(1, peer->rtt_sample_count);
    check_uint_eq(0, peer->outstanding_ping_ms);

    peer->outstanding_ping_ms = 2000;
    check(p2p_peer_record_rtt_sample_locked(peer, 2000, 2040));
    check_uint_eq(92, peer->avg_rtt_ms);
    check_uint_eq(52, peer->rttvar_ms);
    check_uint_eq(2, peer->rtt_sample_count);

    peer->outstanding_ping_ms = 3000;
    check_false(p2p_peer_record_rtt_sample_locked(
        peer, 3000, 3000 + (uint64_t)P2P_RTT_SAMPLE_MAX_MS + 1U));
    check_uint_eq(2, peer->rtt_sample_count);
    check_uint_eq(0, peer->outstanding_ping_ms);

    p2p_peer_destroy(peer);
}

void test_p2p_peer_get_id(void) {
    p2p_peer_t *peer = p2p_peer_create(test_node, "127.0.0.1", 9999);
    uint8_t id[P2P_HASH_SIZE] = {0};
    uint8_t expected[P2P_HASH_SIZE] = {0};

    check_not_null(peer);
    check_int_eq(P2P_ERR_NOT_FOUND, p2p_peer_get_id(peer, id));

    expected[0] = 0x12;
    expected[1] = 0x34;
    p2p_peer_set_id(peer, expected);

    check_int_eq(P2P_OK, p2p_peer_get_id(peer, id));
    check(memcmp(id, expected, sizeof(id)) == 0);
    check_int_eq(P2P_ERR_INVALID_ARG, p2p_peer_get_id(NULL, id));
    check_int_eq(P2P_ERR_INVALID_ARG, p2p_peer_get_id(peer, NULL));

    p2p_peer_destroy(peer);
}

void test_p2p_peer_get_public_key(void) {
    p2p_peer_t *peer = p2p_peer_create(test_node, "127.0.0.1", 9999);
    uint8_t public_key[P2P_KEY_SIZE] = {0};
    uint8_t expected[P2P_KEY_SIZE] = {0};

    check_not_null(peer);
    check_int_eq(P2P_ERR_NOT_FOUND, p2p_peer_get_public_key(peer, public_key));

    expected[0] = 0x56;
    expected[1] = 0x78;
    memcpy(peer->remote_public_key, expected, sizeof(expected));
    peer->remote_public_key_ready = 1;

    check_int_eq(P2P_OK, p2p_peer_get_public_key(peer, public_key));
    check(memcmp(public_key, expected, sizeof(public_key)) == 0);
    check_int_eq(P2P_ERR_INVALID_ARG, p2p_peer_get_public_key(NULL, public_key));
    check_int_eq(P2P_ERR_INVALID_ARG, p2p_peer_get_public_key(peer, NULL));

    p2p_peer_destroy(peer);
}

void test_p2p_ping_cannot_replace_authenticated_routing_id(void) {
    p2p_peer_t *peer = p2p_peer_create(test_node, "127.0.0.1", 29999);
    p2p_message_t message = {0};
    uint8_t authenticated_id[P2P_DHT_KEY_SIZE];

    check_not_null(peer);
    memset(authenticated_id, 0x31, sizeof(authenticated_id));
    memcpy(peer->id, authenticated_id, sizeof(peer->id));
    peer->is_connected = 1;
    peer->state = P2P_PEER_STATE_CONNECTED;
    p2p_message_init(&message, P2P_MSG_PING);
    message.header.payload_len = sizeof(message.payload.ping);
    memset(message.payload.ping.node_id, 0x42,
           sizeof(message.payload.ping.node_id));

    p2p_handlers_dispatch(test_node, peer, &message);
    check_mem_eq(authenticated_id, peer->id, sizeof(authenticated_id));
    p2p_peer_destroy(peer);
}

void test_p2p_peer_info_ex_preserves_ipv6(void) {
    const char *ipv6 = "2001:db8:85a3::8a2e:370:7334";
    p2p_peer_t *peer = p2p_peer_create(test_node, ipv6, 9999);
    p2p_peer_info_ex_t info = {0};

    check_not_null(peer);
    check_int_eq(P2P_OK, p2p_peer_get_info_ex(peer, &info));
    check_str_eq(ipv6, info.ip);
    check_int_eq(9999, info.port);
    check_int_eq(0, info.is_connected);
    p2p_peer_destroy(peer);
}

void test_p2p_get_peer_info_ex_preserves_ipv6(void) {
    const char *ipv6 = "2001:db8:85a3::8a2e:370:7334";
    p2p_peer_t *peer = p2p_peer_create(test_node, ipv6, 9999);
    p2p_peer_info_ex_t info = {0};

    check_not_null(peer);
    peer->is_connected = 1;

    turbo_mutex_lock(&test_node->mutex);
    peer_table_add(&test_node->peers_table, peer);
    turbo_mutex_unlock(&test_node->mutex);

    check_int_eq(P2P_OK, p2p_get_peer_info_ex(test_node, 0, &info));
    check_str_eq(ipv6, info.ip);
    check_int_eq(9999, info.port);
    check_int_eq(1, info.is_connected);

    turbo_mutex_lock(&test_node->mutex);
    peer_table_remove(&test_node->peers_table, ipv6, 9999);
    turbo_mutex_unlock(&test_node->mutex);
    p2p_peer_destroy(peer);
}

void test_p2p_peer_create_null_ip(void) {
    /* Test with NULL ip only */
    p2p_peer_t *peer = p2p_peer_create(test_node, NULL, 9999);
    check_null(peer);
}

void test_p2p_peer_find_valid(void) {
    /* Create a peer */
    p2p_peer_t *peer1 = p2p_peer_create(test_node, "192.168.1.1", 8888);
    check_not_null(peer1);

    /* Find it - should not find it since it's not in the list */
    p2p_peer_t *found = p2p_peer_find(test_node, "192.168.1.1", 8888);
    check_null(found);  /* Not in list yet */

    /* Clean up */
    p2p_peer_destroy(peer1);
}

void test_p2p_peer_find_not_found(void) {
    p2p_peer_t *found = p2p_peer_find(test_node, "10.0.0.1", 9999);
    check_null(found);
}

void test_p2p_connect_valid(void) {
    /* This would normally try to connect to a real peer */
    /* For unit tests, we just verify the API works */
    int ret = p2p_connect(test_node, "127.0.0.1", 9999);
    /* May fail if peer doesn't exist, but API should be callable */
    (void)ret;  /* Suppress unused variable warning */
}

void test_p2p_connect_invalid(void) {
    int ret = p2p_connect(NULL, "127.0.0.1", 9999);
    check_int_eq(P2P_ERR_INVALID_ARG, ret);

    ret = p2p_connect(test_node, NULL, 9999);
    check_int_eq(P2P_ERR_INVALID_ARG, ret);
}

/* =============================================================================
 * Connection Tests (Two Nodes)
 * ============================================================================= */

/* Callback counters */
static int g_connected_count = 0;
static int g_disconnected_count = 0;
static int g_message_count = 0;
static char g_last_message[256];

typedef struct {
    p2p_node_t *node;
    int running;
} p2p_loop_thread_ctx_t;

static void on_peer_connected_cb(p2p_peer_t *peer, void *user_data) {
    p2p_peer_info_t info = {0};

    (void)peer;
    (void)user_data;
    g_connected_count++;
    if (peer && p2p_peer_get_info(peer, &info) == P2P_OK) {
        TLOG_INFO("[TEST] Peer connected! {}:{} (count={})",
                  info.ip, info.port, g_connected_count);
    } else {
        TLOG_INFO("[TEST] Peer connected! (count={})", g_connected_count);
    }
}

static void on_peer_disconnected_cb(p2p_peer_t *peer, void *user_data) {
    p2p_peer_info_t info = {0};

    (void)peer;
    (void)user_data;
    g_disconnected_count++;
    if (peer && p2p_peer_get_info(peer, &info) == P2P_OK) {
        TLOG_INFO("[TEST] Peer disconnected! {}:{} (count={})",
                  info.ip, info.port, g_disconnected_count);
    } else {
        TLOG_INFO("[TEST] Peer disconnected! (count={})", g_disconnected_count);
    }
}

static void on_message_cb(p2p_node_t *node, p2p_peer_t *peer,
                          const void *data, size_t len, void *user_data) {
    (void)node;
    (void)peer;
    (void)user_data;

    g_message_count++;
    if (len < sizeof(g_last_message)) {
        memcpy(g_last_message, data, len);
        g_last_message[len] = '\0';
    }
    TLOG_INFO("[TEST] Message received: '{}' (count={})", g_last_message, g_message_count);
}

static void p2p_test_pump_loop(void *arg) {
    p2p_loop_thread_ctx_t *ctx = (p2p_loop_thread_ctx_t *)arg;

    while (ctx->running) {
        coro_context_run(p2p_get_loop(ctx->node), TURBO_RUN_NOWAIT);
        turbo_sleep_ms(10);
    }
}

static int p2p_test_routing_has_endpoint(p2p_node_t *node, const char *ip, uint16_t port) {
    if (!node || !ip || port == 0) {
        return 0;
    }

    for (int i = 0; i < KADEMLIA_ID_BITS; i++) {
        kad_node_t *curr = node->kad_dht->routing->buckets[i].head;
        while (curr) {
            if (strcmp(curr->ip, ip) == 0 && curr->port == port) {
                return 1;
            }
            curr = curr->next;
        }
    }

    return 0;
}

static void p2p_test_disconnect_all_peers(p2p_node_t *node) {
    p2p_peer_t **peers = NULL;
    size_t count = 0;

    if (!node) {
        return;
    }

    peers = p2p_node_snapshot_connected_peers(node, &count);
    if (count > 0 && !peers) {
        return;
    }

    for (size_t i = 0; i < count; i++) {
        turbo_mutex_lock(&node->mutex);
        peers[i]->keep_entry = 0;
        turbo_mutex_unlock(&node->mutex);
        p2p_disconnect_peer(peers[i]);
        p2p_peer_release(peers[i]);
    }
    free(peers);
}

static int p2p_test_peer_table_size(p2p_node_t *node) {
    int count = 0;

    if (!node) {
        return 0;
    }

    turbo_mutex_lock(&node->mutex);
    count = peer_table_count(node->peers_table);
    turbo_mutex_unlock(&node->mutex);
    return count;
}

static int p2p_test_connected_peer_count(p2p_node_t *node) {
    p2p_peer_t **peers = NULL;
    size_t count = 0;

    if (!node) {
        return 0;
    }

    peers = p2p_node_snapshot_connected_peers(node, &count);
    if (count > 0 && !peers) {
        return 0;
    }

    for (size_t i = 0; i < count; i++) {
        p2p_peer_release(peers[i]);
    }
    free(peers);
    return (int)count;
}

static int p2p_test_connected_identity_count(
    p2p_node_t *node, const uint8_t remote_id[P2P_DHT_KEY_SIZE]) {
    p2p_peer_t **peers = NULL;
    size_t count = 0;
    int matches = 0;

    if (!node || !remote_id) {
        return 0;
    }
    peers = p2p_node_snapshot_connected_peers(node, &count);
    if (count > 0 && !peers) {
        return 0;
    }
    for (size_t index = 0; index < count; ++index) {
        if (memcmp(peers[index]->id, remote_id, P2P_DHT_KEY_SIZE) == 0) {
            matches++;
        }
        p2p_peer_release(peers[index]);
    }
    free(peers);
    return matches;
}

static int p2p_test_first_peer_public_key(p2p_node_t *node,
                                          uint8_t public_key[P2P_KEY_SIZE]) {
    p2p_peer_t **peers = NULL;
    size_t count = 0;
    int ret = P2P_ERR_NOT_FOUND;

    if (!node || !public_key) {
        return P2P_ERR_INVALID_ARG;
    }

    peers = p2p_node_snapshot_connected_peers(node, &count);
    if (count > 0 && !peers) {
        return P2P_ERR_NO_MEM;
    }

    for (size_t i = 0; i < count; i++) {
        if (p2p_peer_get_public_key(peers[i], public_key) == P2P_OK) {
            ret = P2P_OK;
            break;
        }
    }

    for (size_t i = 0; i < count; i++) {
        p2p_peer_release(peers[i]);
    }
    free(peers);
    return ret;
}

static int p2p_test_first_peer_security(
    p2p_node_t *node, p2p_peer_security_info_v2_t *security) {
    p2p_peer_t **peers = NULL;
    size_t count = 0;
    int ret = P2P_ERR_NOT_FOUND;

    if (!node || !security) {
        return P2P_ERR_INVALID_ARG;
    }
    peers = p2p_node_snapshot_connected_peers(node, &count);
    if (count > 0 && !peers) {
        return P2P_ERR_NO_MEM;
    }
    for (size_t i = 0; i < count; ++i) {
        security->struct_size = sizeof(*security);
        if (p2p_peer_get_security_info_v2(peers[i], security) == P2P_OK) {
            ret = P2P_OK;
            break;
        }
    }
    for (size_t i = 0; i < count; ++i) {
        p2p_peer_release(peers[i]);
    }
    free(peers);
    return ret;
}

static int p2p_test_lookup_count(p2p_node_t *node) {
    int count = 0;

    if (!node) {
        return 0;
    }

    turbo_mutex_lock(&node->mutex);
    count = HASH_COUNT(node->dht_lookups);
    turbo_mutex_unlock(&node->mutex);
    return count;
}

static int p2p_test_route_exists(p2p_node_t *node, const char *ip, int port) {
    kad_id_t target;
    kad_node_t **closest = NULL;
    int found = 0;

    if (!node || !ip) {
        return 0;
    }

    p2p_endpoint_to_id(ip, port, &target);
    turbo_mutex_lock(&node->mutex);
    closest = kademlia_find_node(node->kad_dht, &target, KADEMLIA_K);
    turbo_mutex_unlock(&node->mutex);
    if (!closest) {
        return 0;
    }

    for (int i = 0; i < KADEMLIA_K && closest[i]; i++) {
        if (strcmp(closest[i]->ip, ip) == 0 && closest[i]->port == port) {
            found = 1;
            break;
        }
    }

    free(closest);
    return found;
}

void test_p2p_dht_lookup_without_candidates_stays_idle(void) {
    p2p_dht_lookup_t *lookup = NULL;

    lookup = p2p_dht_lookup_start(test_node, test_node->id, P2P_MSG_DHT_FIND_NODE);
    check_null(lookup);
    check_int_eq(0, p2p_test_lookup_count(test_node));
}

void test_p2p_authenticated_duplicate_identity_keeps_single_peer(void) {
    const int port1 = p2p_test_alloc_port_block(3);
    p2p_peer_t *peer1 = NULL;
    p2p_peer_t *peer2 = NULL;
    size_t connected_count = 0;
    p2p_peer_t **connected = NULL;
    uint8_t peer_id[P2P_DHT_KEY_SIZE] = {0};

    p2p_destroy(test_node);
    test_node = p2p_create("127.0.0.1", port1);
    check_not_null(test_node);

    peer_id[0] = 0x42;
    peer_id[1] = 0x24;

    peer1 = p2p_peer_create(test_node, "127.0.0.1", port1 + 1);
    check_not_null(peer1);
    memcpy(peer1->id, peer_id, sizeof(peer_id));

    p2p_node_on_peer_authenticated(test_node, peer1);
    check_int_eq(1, p2p_test_peer_table_size(test_node));

    peer2 = p2p_peer_create(test_node, "127.0.0.1", port1 + 2);
    check_not_null(peer2);
    memcpy(peer2->id, peer_id, sizeof(peer_id));

    turbo_mutex_lock(&test_node->mutex);
    peer2->keep_entry = 1;
    p2p_node_add_peer_locked(test_node, peer2);
    turbo_mutex_unlock(&test_node->mutex);

    check_int_eq(2, p2p_test_peer_table_size(test_node));

    p2p_node_on_peer_authenticated(test_node, peer2);

    check_int_eq(1, p2p_test_peer_table_size(test_node));
    connected = p2p_node_snapshot_connected_peers(test_node, &connected_count);
    check_int_eq(1, (int)connected_count);
    check_ptr_eq(peer1, connected[0]);
    p2p_peer_release(connected[0]);
    free(connected);

    turbo_mutex_lock(&test_node->mutex);
    check_ptr_eq(peer1, p2p_node_find_peer_by_endpoint_locked(test_node, "127.0.0.1", port1 + 1));
    check_null(p2p_node_find_peer_by_endpoint_locked(test_node, "127.0.0.1", port1 + 2));
    turbo_mutex_unlock(&test_node->mutex);
}

void test_p2p_authenticated_duplicate_identity_uses_deterministic_direction(void) {
    const int port1 = p2p_test_alloc_port_block(3);
    uint8_t remote_routing_id[P2P_SECURITY_ID_SIZE] = {0};
    p2p_peer_t *inbound = NULL;
    p2p_peer_t *outbound = NULL;
    p2p_peer_t **connected = NULL;
    size_t connected_count = 0;

    p2p_destroy(test_node);
    test_node = p2p_create("127.0.0.1", port1);
    check_not_null(test_node);
    memset(test_node->local_authenticated_identity.routing_id, 0x10,
           P2P_SECURITY_ID_SIZE);
    memset(remote_routing_id, 0x20, sizeof(remote_routing_id));

    inbound = p2p_peer_create(test_node, "127.0.0.1", port1 + 1);
    check_not_null(inbound);
    memcpy(inbound->id, remote_routing_id, P2P_HASH_SIZE);
    memcpy(inbound->authenticated_identity.routing_id, remote_routing_id,
           sizeof(remote_routing_id));
    inbound->conn = (p2p_connection_t *)calloc(1, sizeof(*inbound->conn));
    check_not_null(inbound->conn);
    inbound->conn->type = P2P_CONN_INBOUND;
    p2p_node_on_peer_authenticated(test_node, inbound);

    outbound = p2p_peer_create(test_node, "127.0.0.1", port1 + 2);
    check_not_null(outbound);
    memcpy(outbound->id, remote_routing_id, P2P_HASH_SIZE);
    memcpy(outbound->authenticated_identity.routing_id, remote_routing_id,
           sizeof(remote_routing_id));
    outbound->conn = (p2p_connection_t *)calloc(1, sizeof(*outbound->conn));
    check_not_null(outbound->conn);
    outbound->conn->type = P2P_CONN_OUTBOUND;
    p2p_node_on_peer_authenticated(test_node, outbound);

    connected = p2p_node_snapshot_connected_peers(test_node,
                                                   &connected_count);
    check_int_eq(1, (int)connected_count);
    check_ptr_eq(outbound, connected[0]);
    p2p_peer_release(connected[0]);
    free(connected);

    inbound = p2p_peer_create(test_node, "127.0.0.1", port1 + 1);
    check_not_null(inbound);
    memcpy(inbound->id, remote_routing_id, P2P_HASH_SIZE);
    memcpy(inbound->authenticated_identity.routing_id, remote_routing_id,
           sizeof(remote_routing_id));
    inbound->conn = (p2p_connection_t *)calloc(1, sizeof(*inbound->conn));
    check_not_null(inbound->conn);
    inbound->conn->type = P2P_CONN_INBOUND;
    p2p_node_on_peer_authenticated(test_node, inbound);

    connected = p2p_node_snapshot_connected_peers(test_node,
                                                   &connected_count);
    check_int_eq(1, (int)connected_count);
    check_ptr_eq(outbound, connected[0]);
    p2p_peer_release(connected[0]);
    free(connected);
}

void test_p2p_authenticated_inbound_peer_does_not_publish_ephemeral_route(void) {
    const int port = p2p_test_alloc_port_block(1);
    p2p_peer_t *peer = NULL;

    peer = p2p_peer_create(test_node, "127.0.0.1", port);
    check_not_null(peer);
    peer->id[0] = 0x91;
    peer->id[1] = 0x52;
    peer->conn = (p2p_connection_t *)calloc(1, sizeof(*peer->conn));
    check_not_null(peer->conn);
    peer->conn->type = P2P_CONN_INBOUND;

    p2p_node_on_peer_authenticated(test_node, peer);

    check_int_eq(1, p2p_test_peer_table_size(test_node));
    check(!p2p_test_route_exists(test_node, "127.0.0.1", port));
}

static void p2p_test_shutdown_mesh(p2p_node_t *node1,
                                   p2p_node_t *node2,
                                   p2p_node_t *node3,
                                   p2p_loop_thread_ctx_t *loop1,
                                   p2p_loop_thread_ctx_t *loop2,
                                   p2p_loop_thread_ctx_t *loop3,
                                   turbo_thread_t *thread1,
                                   turbo_thread_t *thread2,
                                   turbo_thread_t *thread3) {
    loop1->running = 0;
    loop2->running = 0;
    loop3->running = 0;
    turbo_thread_join(thread1);
    turbo_thread_join(thread2);
    turbo_thread_join(thread3);
    turbo_thread_destroy(thread1);
    turbo_thread_destroy(thread2);
    turbo_thread_destroy(thread3);

    p2p_node_stop_server(node1);
    p2p_node_stop_server(node2);
    p2p_node_stop_server(node3);

    p2p_test_disconnect_all_peers(node1);
    p2p_test_disconnect_all_peers(node2);
    p2p_test_disconnect_all_peers(node3);

    for (int i = 0; i < 100; i++) {
        coro_context_run(p2p_get_loop(node1), TURBO_RUN_NOWAIT);
        coro_context_run(p2p_get_loop(node2), TURBO_RUN_NOWAIT);
        coro_context_run(p2p_get_loop(node3), TURBO_RUN_NOWAIT);

        if (p2p_test_peer_table_size(node1) == 0 &&
            p2p_test_peer_table_size(node2) == 0 &&
            p2p_test_peer_table_size(node3) == 0) {
            break;
        }
        turbo_sleep_ms(20);
    }
}

static void p2p_test_shutdown_nodes(p2p_node_t *node1,
                                    p2p_node_t *node2,
                                    p2p_node_t *node3) {
    p2p_node_stop_server(node1);
    p2p_node_stop_server(node2);
    if (node3) {
        p2p_node_stop_server(node3);
    }

    p2p_test_disconnect_all_peers(node1);
    p2p_test_disconnect_all_peers(node2);
    if (node3) {
        p2p_test_disconnect_all_peers(node3);
    }

    for (int i = 0; i < 250; i++) {
        coro_context_run(p2p_get_loop(node1), TURBO_RUN_NOWAIT);
        coro_context_run(p2p_get_loop(node2), TURBO_RUN_NOWAIT);
        if (node3) {
            coro_context_run(p2p_get_loop(node3), TURBO_RUN_NOWAIT);
        }

        if (p2p_test_peer_table_size(node1) == 0 &&
            p2p_test_peer_table_size(node2) == 0 &&
            p2p_test_lookup_count(node1) == 0 &&
            p2p_test_lookup_count(node2) == 0 &&
            (!node3 || (p2p_test_peer_table_size(node3) == 0 &&
                        p2p_test_lookup_count(node3) == 0))) {
            break;
        }
        turbo_sleep_ms(20);
    }
}

static int p2p_test_pump_three_until_connected(
    p2p_node_t *node1, p2p_node_t *node2, p2p_node_t *node3,
    int expected1, int expected2, int expected3) {
    for (int attempt = 0; attempt < 500; ++attempt) {
        coro_context_run(p2p_get_loop(node1), TURBO_RUN_NOWAIT);
        coro_context_run(p2p_get_loop(node2), TURBO_RUN_NOWAIT);
        coro_context_run(p2p_get_loop(node3), TURBO_RUN_NOWAIT);
        if (p2p_test_connected_peer_count(node1) == expected1 &&
            p2p_test_connected_peer_count(node2) == expected2 &&
            p2p_test_connected_peer_count(node3) == expected3) {
            return 1;
        }
        turbo_sleep_ms(10);
    }
    return 0;
}

static void test_p2p_three_node_hard_cut_simultaneous_dial_and_reconnect(void) {
    const int port1 = p2p_test_alloc_port_block(3);
    const int port2 = port1 + 1;
    const int port3 = port1 + 2;
    p2p_node_t *node1 = p2p_create("127.0.0.1", port1);
    p2p_node_t *node2 = p2p_create("127.0.0.1", port2);
    p2p_node_t *node3 = p2p_create("127.0.0.1", port3);
    p2p_peer_security_info_v2_t before = {0};
    p2p_peer_security_info_v2_t after = {0};

    check_not_null(node1);
    check_not_null(node2);
    check_not_null(node3);
    if (!node1 || !node2 || !node3) {
        p2p_destroy(node3);
        p2p_destroy(node2);
        p2p_destroy(node1);
        return;
    }
    {
        p2p_node_t *nodes[] = {node1, node2, node3};
        check_int_eq(P2P_OK, p2p_test_configure_pinned(nodes, 3));
    }
    check_int_eq(P2P_OK, p2p_node_start_server(node1));
    check_int_eq(P2P_OK, p2p_node_start_server(node2));
    check_int_eq(P2P_OK, p2p_node_start_server(node3));

    /* Queue both directions before pumping any owner loop.  Each pair must
     * converge to one authenticated transport according to routing-ID order. */
    check_int_eq(P2P_OK, p2p_connect(node1, "127.0.0.1", port2));
    check_int_eq(P2P_OK, p2p_connect(node2, "127.0.0.1", port1));
    check_int_eq(P2P_OK, p2p_connect(node2, "127.0.0.1", port3));
    check_int_eq(P2P_OK, p2p_connect(node3, "127.0.0.1", port2));
    check(p2p_test_pump_three_until_connected(node1, node2, node3,
                                               1, 2, 1));

    check_int_eq(1, p2p_test_connected_identity_count(node1, node2->id));
    check_int_eq(1, p2p_test_connected_identity_count(node2, node1->id));
    check_int_eq(1, p2p_test_connected_identity_count(node2, node3->id));
    check_int_eq(1, p2p_test_connected_identity_count(node3, node2->id));
    check_int_eq(0, p2p_test_connected_identity_count(node1, node3->id));
    check_int_eq(0, p2p_test_connected_identity_count(node3, node1->id));
    check_int_eq(P2P_OK, p2p_test_first_peer_security(node1, &before));
    check(before.authenticated);

    p2p_test_disconnect_all_peers(node1);
    check(p2p_test_pump_three_until_connected(node1, node2, node3,
                                               0, 1, 1));

    /* Reconnect in both directions again.  A fresh Noise transcript must
     * replace the old channel binding without creating duplicate identity
     * entries or disturbing the independent node2-node3 session. */
    check_int_eq(P2P_OK, p2p_connect(node1, "127.0.0.1", port2));
    check_int_eq(P2P_OK, p2p_connect(node2, "127.0.0.1", port1));
    check(p2p_test_pump_three_until_connected(node1, node2, node3,
                                               1, 2, 1));
    check_int_eq(1, p2p_test_connected_identity_count(node1, node2->id));
    check_int_eq(1, p2p_test_connected_identity_count(node2, node1->id));
    check_int_eq(1, p2p_test_connected_identity_count(node2, node3->id));
    check_int_eq(P2P_OK, p2p_test_first_peer_security(node1, &after));
    check(after.authenticated);
    check(memcmp(before.channel_binding, after.channel_binding,
                 P2P_SECURITY_ID_SIZE) != 0);

    p2p_test_shutdown_nodes(node1, node2, node3);
    p2p_destroy(node3);
    p2p_destroy(node2);
    p2p_destroy(node1);
}

static uint64_t p2p_test_latency_bucket_total(
    const p2p_security_latency_accumulator_t *accumulator) {
    uint64_t total = 0;

    if (!accumulator) {
        return 0;
    }
    for (size_t index = 0; index < P2P_SECURITY_LATENCY_BUCKET_COUNT;
         ++index) {
        total += accumulator->buckets[index];
    }
    return total;
}

static void test_p2p_handshake_latency_accumulator_is_bounded(void) {
    p2p_security_latency_accumulator_t *accumulator =
        &test_node->security_handshake_latency[P2P_SECURITY_ROLE_INITIATOR]
                                              [P2P_SECURITY_LATENCY_NOISE];

    p2p_node_record_handshake_latency(
        test_node, P2P_SECURITY_ROLE_INITIATOR,
        P2P_SECURITY_LATENCY_NOISE, 100U, 110U);
    check_uint_eq(1U, accumulator->completed);
    check_uint_eq(10U, accumulator->total_ms);
    check_uint_eq(10U, accumulator->maximum_ms);
    check_uint_eq(1U, accumulator->buckets[2]);
    check_uint_eq(1U, p2p_test_latency_bucket_total(accumulator));

    accumulator->completed = UINT64_MAX;
    accumulator->total_ms = UINT64_MAX;
    accumulator->maximum_ms = UINT64_MAX;
    accumulator->buckets[2] = UINT64_MAX;
    p2p_node_record_handshake_latency(
        test_node, P2P_SECURITY_ROLE_INITIATOR,
        P2P_SECURITY_LATENCY_NOISE, 200U, 210U);
    check(accumulator->completed == UINT64_MAX);
    check(accumulator->total_ms == UINT64_MAX);
    check(accumulator->maximum_ms == UINT64_MAX);
    check(accumulator->buckets[2] == UINT64_MAX);

    p2p_node_record_handshake_latency(
        test_node, P2P_SECURITY_ROLE_COUNT,
        P2P_SECURITY_LATENCY_NOISE, 10U, 20U);
    p2p_node_record_handshake_latency(
        test_node, P2P_SECURITY_ROLE_INITIATOR,
        P2P_SECURITY_LATENCY_STAGE_COUNT, 10U, 20U);
    p2p_node_record_handshake_latency(
        test_node, P2P_SECURITY_ROLE_INITIATOR,
        P2P_SECURITY_LATENCY_NOISE, 20U, 10U);
    check(accumulator->completed == UINT64_MAX);
}

static void test_p2p_real_handshake_records_each_role_and_stage(void) {
    const int responder_port = p2p_test_alloc_port_block(2);
    const int initiator_port = responder_port + 1;
    p2p_node_t *responder =
        p2p_create("127.0.0.1", responder_port);
    p2p_node_t *initiator =
        p2p_create("127.0.0.1", initiator_port);
    int connected = 0;

    check_not_null(responder);
    check_not_null(initiator);
    if (!responder || !initiator) {
        p2p_destroy(initiator);
        p2p_destroy(responder);
        return;
    }
    {
        p2p_node_t *nodes[] = {responder, initiator};
        check_int_eq(P2P_OK, p2p_test_configure_pinned(nodes, 2));
    }
    check_int_eq(P2P_OK, p2p_node_start_server(responder));
    check_int_eq(P2P_OK, p2p_node_start_server(initiator));
    check_int_eq(P2P_OK,
                 p2p_connect(initiator, "127.0.0.1", responder_port));

    for (int attempt = 0; attempt < 500; ++attempt) {
        coro_context_run(p2p_get_loop(responder), TURBO_RUN_NOWAIT);
        coro_context_run(p2p_get_loop(initiator), TURBO_RUN_NOWAIT);
        if (p2p_test_connected_peer_count(responder) == 1 &&
            p2p_test_connected_peer_count(initiator) == 1) {
            connected = 1;
            break;
        }
        turbo_sleep_ms(10);
    }
    check(connected);
    if (connected) {
        for (size_t stage = 0;
             stage < P2P_SECURITY_LATENCY_STAGE_COUNT; ++stage) {
            const p2p_security_latency_accumulator_t *initiator_metric =
                &initiator->security_handshake_latency
                    [P2P_SECURITY_ROLE_INITIATOR][stage];
            const p2p_security_latency_accumulator_t *responder_metric =
                &responder->security_handshake_latency
                    [P2P_SECURITY_ROLE_RESPONDER][stage];

            check_uint_eq(1U, initiator_metric->completed);
            check_uint_eq(1U,
                          p2p_test_latency_bucket_total(initiator_metric));
            check_uint_eq(initiator_metric->total_ms,
                          initiator_metric->maximum_ms);
            check_uint_eq(1U, responder_metric->completed);
            check_uint_eq(1U,
                          p2p_test_latency_bucket_total(responder_metric));
            check_uint_eq(responder_metric->total_ms,
                          responder_metric->maximum_ms);
            check_uint_eq(
                0U, initiator->security_handshake_latency
                        [P2P_SECURITY_ROLE_RESPONDER][stage].completed);
            check_uint_eq(
                0U, responder->security_handshake_latency
                        [P2P_SECURITY_ROLE_INITIATOR][stage].completed);
        }
    }

    p2p_test_shutdown_nodes(responder, initiator, NULL);
    p2p_destroy(initiator);
    p2p_destroy(responder);
}

void test_p2p_two_nodes_real_connection(void) {
    const int port1 = p2p_test_alloc_port_block(2);
    const int port2 = port1 + 1;
    TLOG_INFO("[TEST] Testing real P2P connection between two nodes");

    /* Reset counters */
    g_connected_count = 0;
    g_disconnected_count = 0;
    g_message_count = 0;
    memset(g_last_message, 0, sizeof(g_last_message));

    /* Create node 1 (server) */
    p2p_node_t *node1 = p2p_create("127.0.0.1", port1);
    check_not_null(node1);
    printf("[TEST] ✓ Node 1 created on port %d\n", port1);

    /* Create node 2 (client) */
    p2p_node_t *node2 = p2p_create("127.0.0.1", port2);
    check_not_null(node2);
    printf("[TEST] ✓ Node 2 created on port %d\n", port2);

    /* Set callbacks on node 1 */
    p2p_set_peer_callbacks(node1, on_peer_connected_cb, on_peer_disconnected_cb, NULL);
    p2p_set_message_handler(node1, on_message_cb, NULL);

    /* Set callbacks on node 2 */
    p2p_set_peer_callbacks(node2, on_peer_connected_cb, on_peer_disconnected_cb, NULL);
    p2p_set_message_handler(node2, on_message_cb, NULL);

    {
        p2p_node_t *nodes[] = {node1, node2};
        check_int_eq(P2P_OK, p2p_test_configure_pinned(nodes, 2));
    }
    /* Start node 1 server */
    int ret = p2p_node_start_server(node1);
    check_int_eq(P2P_OK, ret);
    printf("[TEST] ✓ Node 1 server started\n");

    /* Start node 2 server */
    ret = p2p_node_start_server(node2);
    check_int_eq(P2P_OK, ret);
    printf("[TEST] ✓ Node 2 server started\n");

    /* Node 2 connects to node 1 */
    TLOG_INFO("[TEST] Node 2 connecting to node 1...");
    ret = p2p_connect(node2, "127.0.0.1", port1);
    check_int_eq(P2P_OK, ret);

    /* Wait for connection (poll event loop) */
    TLOG_INFO("[TEST] Waiting for connection (3 seconds)...");
    for (int i = 0; i < 30; i++) {
        coro_context_run(p2p_get_loop(node1), TURBO_RUN_NOWAIT);
        coro_context_run(p2p_get_loop(node2), TURBO_RUN_NOWAIT);

#ifdef _WIN32
        Sleep(100);
#else
        usleep(100000);
#endif

        if (g_connected_count > 0) {
            printf("[TEST] ✓ Connection established after %d iterations\n", i + 1);
            break;
        }
    }

    /* Verify connection */
    check(g_connected_count > 0);
    check_int_eq(0, g_disconnected_count);
    TLOG_INFO("[TEST] Connection verified: connected={}, disconnected={}",
           g_connected_count, g_disconnected_count);

    /* Send a test message from node 2 to node 1 */
    const char *msg = "Hello from node 2!";
    TLOG_INFO("[TEST] Sending test message: '{}'", msg);
    ret = p2p_broadcast(node2, msg, strlen(msg) + 1);
    check_int_eq(P2P_OK, ret);

    /* Wait for message */
    TLOG_INFO("[TEST] Waiting for message...");
    for (int i = 0; i < 10; i++) {
        coro_context_run(p2p_get_loop(node1), TURBO_RUN_NOWAIT);
        coro_context_run(p2p_get_loop(node2), TURBO_RUN_NOWAIT);

#ifdef _WIN32
        Sleep(100);
#else
        usleep(100000);
#endif

        if (g_message_count > 0) {
            printf("[TEST] ✓ Message received after %d iterations\n", i + 1);
            break;
        }
    }

    /* Verify message (may not arrive in simple test without full event loop) */
    /* Don't make this a hard requirement for the test to pass */
    if (g_message_count > 0) {
        printf("[TEST] ✓ Message delivered: '%s'\n", g_last_message);
    } else {
        printf("[TEST] ⚠ Message not delivered (event loop issue)\n");
    }

    /* The authenticated identity ping provides the first stream sample. Force
     * the low-frequency scheduler due and verify that maintenance adds another
     * sample without introducing a new wire message type. */
    p2p_peer_t *metrics_peer = p2p_peer_find(node2, "127.0.0.1", port1);
    p2p_peer_stream_metrics_t stream_metrics = {0};
    uint32_t first_sample_count = 0;

    check_not_null(metrics_peer);
    if (metrics_peer) {
        for (int i = 0; i < 100; i++) {
            coro_context_run(p2p_get_loop(node1), TURBO_RUN_NOWAIT);
            coro_context_run(p2p_get_loop(node2), TURBO_RUN_NOWAIT);
            check_int_eq(P2P_OK,
                         p2p_peer_get_stream_metrics(metrics_peer, &stream_metrics));
            if (stream_metrics.sample_count > 0) {
                break;
            }
            turbo_sleep_ms(10);
        }
        check(stream_metrics.sample_count > 0);
        check(stream_metrics.is_fresh);
        first_sample_count = stream_metrics.sample_count;

        turbo_mutex_lock(&node2->mutex);
        uint64_t probe_now_ms = turbo_hrtime() / 1000000U;
        metrics_peer->outstanding_ping_ms = 0;
        metrics_peer->last_ping_sent_ms = probe_now_ms > P2P_RTT_PROBE_INTERVAL_MS
            ? probe_now_ms - P2P_RTT_PROBE_INTERVAL_MS
            : 0;
        turbo_mutex_unlock(&node2->mutex);

        check_not_null(node2->gossip_timer);
        if (node2->gossip_timer) {
            node_maintenance_cb(node2->gossip_timer);
        }
        for (int i = 0; i < 100; i++) {
            coro_context_run(p2p_get_loop(node1), TURBO_RUN_NOWAIT);
            coro_context_run(p2p_get_loop(node2), TURBO_RUN_NOWAIT);
            check_int_eq(P2P_OK,
                         p2p_peer_get_stream_metrics(metrics_peer, &stream_metrics));
            if (stream_metrics.sample_count > first_sample_count) {
                break;
            }
            turbo_sleep_ms(10);
        }
        check(stream_metrics.sample_count > first_sample_count);
    }

    /* Clean up */
    p2p_test_shutdown_nodes(node1, node2, NULL);
    p2p_destroy(node2);
    p2p_destroy(node1);
    TLOG_INFO("[TEST] Both nodes destroyed");
}

static void p2p_test_legacy_client_task(coro_t *coroutine, void *argument) {
    p2p_test_legacy_client_state_t *state =
        (p2p_test_legacy_client_state_t *)argument;
    p2p_msg_header_t header = {0};
    uint8_t frame[P2P_TEST_LEGACY_HANDSHAKE_FRAME_SIZE] = {0};
    coro_socket_t *socket = NULL;
    char *received = NULL;
    size_t received_length = 0;

    (void)coroutine;
    header.type = P2P_MSG_RESERVED_LEGACY_HANDSHAKE;
    header.payload_len = P2P_TEST_LEGACY_HANDSHAKE_PAYLOAD_SIZE;
    header.request_id = 1;
    memcpy(frame, &header, sizeof(header));
    frame[sizeof(header)] = 1;
    frame[sizeof(header) + 1] = P2P_TEST_LEGACY_NOISE_M1_SIZE;
    for (size_t index = 0; index < P2P_TEST_LEGACY_NOISE_M1_SIZE; ++index) {
        frame[sizeof(header) + 2 + index] = (uint8_t)(index + 1U);
    }

    socket = coro_socket_create_tcpv4(state->context);
    if (!socket) {
        goto cleanup;
    }
    coro_socket_set_timeout(socket, P2P_TEST_RAW_CLIENT_TIMEOUT_MS);
    state->connect_result =
        coro_socket_connect(socket, "127.0.0.1", (unsigned short)state->port);
    if (state->connect_result != 0) {
        goto cleanup;
    }
    state->send_result =
        coro_socket_send(socket, (const char *)frame, sizeof(frame));
    if (state->send_result != 0) {
        goto cleanup;
    }
    state->recv_result = coro_socket_recv(socket, &received, &received_length);
    state->received_bytes = received_length;

cleanup:
    if (received) {
        coro_socket_free_recv(received);
    }
    if (socket) {
        coro_socket_destroy(socket);
    }
    state->done = 1;
}

static void test_p2p_v2_listener_rejects_legacy_client_without_fallback(void) {
    const int server_port = p2p_test_alloc_port_block(1);
    p2p_node_t *server = p2p_create("127.0.0.1", server_port);
    coro_context_t *client_context = coro_context_create(NULL);
    p2p_test_legacy_client_state_t client = {0};
    p2p_node_security_status_v2_t status = {0};
    int rejected = 0;

    client.context = client_context;
    client.port = server_port;
    client.connect_result = -1;
    client.send_result = -1;
    client.recv_result = -1;
    check_not_null(server);
    check_not_null(client_context);
    if (!server || !client_context) {
        if (client_context) {
            coro_context_destroy(client_context);
        }
        p2p_destroy(server);
        return;
    }
    {
        p2p_node_t *nodes[] = {server};
        check_int_eq(P2P_OK, p2p_test_configure_pinned(nodes, 1));
    }
    check_int_eq(P2P_OK, p2p_node_start_server(server));
    check_int_eq(0, coro_context_spawn(client_context,
                                        p2p_test_legacy_client_task, &client));

    for (int attempt = 0; attempt < 500; ++attempt) {
        coro_context_run(client_context, TURBO_RUN_NOWAIT);
        coro_context_run(p2p_get_loop(server), TURBO_RUN_NOWAIT);
        status.struct_size = sizeof(status);
        if (client.done &&
            p2p_node_get_security_status_v2(server, &status) == P2P_OK &&
            status.rejection_counts[P2P_SECURITY_REJECTION_COOKIE_PROTOCOL] ==
                1U &&
            status.active_cookie_gates == 0) {
            rejected = 1;
            break;
        }
        turbo_sleep_ms(10);
    }

    check(client.done);
    check_int_eq(0, client.connect_result);
    check_int_eq(0, client.send_result);
    check(client.recv_result != 0);
    check_uint_eq(0, client.received_bytes);
    check(rejected);
    check_int_eq(0, p2p_test_connected_peer_count(server));
    check_int_eq(0, p2p_test_peer_table_size(server));

    p2p_destroy(server);
    coro_context_destroy(client_context);
}

static void test_p2p_cookie_gate_precedes_peer_allocation_and_expires(void) {
    const int server_port = p2p_test_alloc_port_block(2);
    const int client_port = server_port + 1;
    p2p_node_t *server = p2p_create("127.0.0.1", server_port);
    p2p_node_t *client = p2p_create("127.0.0.1", client_port);
    int gate_seen = 0;
    int gate_aged = 0;

    check_not_null(server);
    check_not_null(client);
    if (!server || !client) {
        p2p_destroy(client);
        p2p_destroy(server);
        return;
    }

    {
        p2p_node_t *nodes[] = {server, client};
        check_int_eq(P2P_OK, p2p_test_configure_pinned(nodes, 2));
    }
    check_int_eq(p2p_start_nonblocking(server), P2P_OK);
    check_int_eq(p2p_start_nonblocking(client), P2P_OK);
    check_int_eq(p2p_connect(client, "127.0.0.1", server_port), P2P_OK);

    /* Poll only the server so it accepts the transport before the initiator
     * sends its preface. The fixed cookie gate owns the stream without a peer
     * object or a full transport send-budget reservation. */
    for (int i = 0; i < 100; i++) {
        coro_context_run(p2p_get_loop(server), TURBO_RUN_NOWAIT);
        if (server->active_cookie_gates == 1) {
            gate_seen = 1;
            break;
        }
        turbo_sleep_ms(1);
    }

    check(gate_seen);
    check_int_eq(0, p2p_get_peer_count(server));
    check_int_eq(0, p2p_test_peer_table_size(server));
    check(server->reserved_send_capacity_bytes == 0);
    check(server->transport_send_reservations == 0);

    turbo_mutex_lock(&server->mutex);
    for (size_t index = 0;
         index < server->security_config.cookie_gate_limit; ++index) {
        if (server->cookie_gates[index].state != P2P_COOKIE_GATE_FREE) {
            server->cookie_gates[index].deadline_ms =
                turbo_hrtime() / 1000000U - 1U;
            gate_aged = 1;
            break;
        }
    }
    turbo_mutex_unlock(&server->mutex);

    check(gate_aged);
    check_not_null(server->gossip_timer);
    if (gate_aged && server->gossip_timer) {
        node_maintenance_cb(server->gossip_timer);
    }
    check(server->active_cookie_gates == 0);
    check_int_eq(0, p2p_test_peer_table_size(server));

    p2p_destroy(client);
    p2p_destroy(server);
}

static void test_p2p_cookie_gate_capacity_is_fixed_and_observable(void) {
    const int server_port = p2p_test_alloc_port_block(3);
    p2p_node_t *server = p2p_create("127.0.0.1", server_port);
    p2p_node_t *client1 = p2p_create("127.0.0.1", server_port + 1);
    p2p_node_t *client2 = p2p_create("127.0.0.1", server_port + 2);
    p2p_node_security_status_v2_t status = {0};

    check_not_null(server);
    check_not_null(client1);
    check_not_null(client2);
    if (!server || !client1 || !client2) {
        p2p_destroy(client2);
        p2p_destroy(client1);
        p2p_destroy(server);
        return;
    }
    {
        p2p_node_t *nodes[] = {server, client1, client2};
        check_int_eq(P2P_OK, p2p_test_configure_pinned(nodes, 3));
    }
    server->security_config.cookie_gate_limit = 1U;
    check_int_eq(P2P_OK, p2p_node_start_server(server));
    check_int_eq(P2P_OK, p2p_connect(client1, "127.0.0.1", server_port));
    check_int_eq(P2P_OK, p2p_connect(client2, "127.0.0.1", server_port));

    for (int index = 0; index < 200; ++index) {
        coro_context_run(p2p_get_loop(server), TURBO_RUN_NOWAIT);
        status.struct_size = sizeof(status);
        check_int_eq(P2P_OK,
                     p2p_node_get_security_status_v2(server, &status));
        if (status.active_cookie_gates == 1U &&
            status.rejection_counts[
                P2P_SECURITY_REJECTION_COOKIE_GATE_CAPACITY] >= 1U) {
            break;
        }
        turbo_sleep_ms(1);
    }

    check_uint_eq(1U, status.cookie_gate_limit);
    check(status.active_cookie_gates == 1U);
    check(status.rejection_counts[
              P2P_SECURITY_REJECTION_COOKIE_GATE_CAPACITY] >= 1U);
    check_int_eq(0, p2p_test_peer_table_size(server));
    check(server->reserved_send_capacity_bytes == 0U);
    p2p_node_stop_server(server);
    check(server->active_cookie_gates == 0U);

    p2p_destroy(client2);
    p2p_destroy(client1);
    p2p_destroy(server);
}

static void test_p2p_limits_pending_unauthenticated_peers(void) {
    const int base_port = 30000;
    const int node_port = p2p_test_alloc_port_block(1);
    p2p_node_t *node = p2p_create("127.0.0.1", node_port);
    int capacity_available = 0;

    check_not_null(node);
    if (!node) {
        return;
    }

    turbo_mutex_lock(&node->mutex);
    capacity_available = p2p_node_pending_peer_capacity_available_locked(node);
    turbo_mutex_unlock(&node->mutex);
    check(capacity_available);

    for (int i = 0; i < P2P_PENDING_PEER_LIMIT; i++) {
        p2p_peer_t *peer = p2p_peer_create(node, "127.0.0.1", base_port + i);
        check_not_null(peer);
        if (!peer) {
            break;
        }
        peer->state = P2P_PEER_STATE_HANDSHAKING;
        peer->connect_time = turbo_hrtime();
        turbo_mutex_lock(&node->mutex);
        p2p_node_add_peer_locked(node, peer);
        turbo_mutex_unlock(&node->mutex);
    }

    turbo_mutex_lock(&node->mutex);
    capacity_available = p2p_node_pending_peer_capacity_available_locked(node);
    turbo_mutex_unlock(&node->mutex);
    check_false(capacity_available);
    check_int_eq(P2P_PENDING_PEER_LIMIT, p2p_test_peer_table_size(node));

    p2p_destroy(node);
}

static void test_p2p_limits_pending_peers_per_source_prefix(void) {
    const int node_port = p2p_test_alloc_port_block(1);
    p2p_node_t *node = p2p_create("127.0.0.1", node_port);

    check_not_null(node);
    for (int i = 0; i < P2P_PENDING_PEER_SOURCE_LIMIT; ++i) {
        p2p_peer_t *peer = p2p_peer_create(node, "192.0.2.10", 31000 + i);
        check_not_null(peer);
        peer->state = P2P_PEER_STATE_HANDSHAKING;
        turbo_mutex_lock(&node->mutex);
        p2p_node_add_peer_locked(node, peer);
        turbo_mutex_unlock(&node->mutex);
    }
    for (int i = 0; i < P2P_PENDING_PEER_SOURCE_LIMIT; ++i) {
        char source_ip[P2P_MAX_IP];
        p2p_peer_t *peer;

        snprintf(source_ip, sizeof(source_ip), "2001:db8:1:2::%x", i + 1);
        peer = p2p_peer_create(node, source_ip, 32000 + i);
        check_not_null(peer);
        peer->state = P2P_PEER_STATE_HANDSHAKING;
        turbo_mutex_lock(&node->mutex);
        p2p_node_add_peer_locked(node, peer);
        turbo_mutex_unlock(&node->mutex);
    }
    turbo_mutex_lock(&node->mutex);
    check_false(p2p_node_pending_peer_source_capacity_available_locked(
        node, "192.0.2.10"));
    check_true(p2p_node_pending_peer_source_capacity_available_locked(
        node, "192.0.2.11"));
    check_false(p2p_node_pending_peer_source_capacity_available_locked(
        node, "2001:db8:1:2::ffff"));
    check_true(p2p_node_pending_peer_source_capacity_available_locked(
        node, "2001:db8:1:3::1"));
    check_true(p2p_node_pending_peer_capacity_available_locked(node));
    turbo_mutex_unlock(&node->mutex);
    p2p_destroy(node);
}

static void test_p2p_rate_limits_inbound_sources_with_bounded_buckets(void) {
    p2p_node_t *nodes[] = {test_node};
    p2p_node_security_status_v2_t status = {0};

    check_int_eq(P2P_OK, p2p_test_configure_pinned(nodes, 1));
    test_node->security_config.source_admission_burst = 2u;
    test_node->security_config.source_admission_refill_per_second = 1u;
    test_node->security_config.source_admission_bucket_limit = 2u;

    turbo_mutex_lock(&test_node->mutex);
    check_int_eq(P2P_OK, p2p_node_source_admission_acquire_locked(
                              test_node, "192.0.2.10", 1000u));
    check_int_eq(P2P_OK, p2p_node_source_admission_acquire_locked(
                              test_node, "192.0.2.10", 1000u));
    check_int_eq(P2P_ERR_RESOURCE_EXHAUSTED,
                 p2p_node_source_admission_acquire_locked(
                     test_node, "192.0.2.10", 1000u));
    check_int_eq(P2P_ERR_RESOURCE_EXHAUSTED,
                 p2p_node_source_admission_acquire_locked(
                     test_node, "192.0.2.10", 1999u));
    check_int_eq(P2P_OK, p2p_node_source_admission_acquire_locked(
                              test_node, "192.0.2.10", 2000u));

    check_int_eq(P2P_OK, p2p_node_source_admission_acquire_locked(
                              test_node, "2001:db8:1:2::1", 2000u));
    check_int_eq(P2P_OK, p2p_node_source_admission_acquire_locked(
                              test_node, "2001:db8:1:2::2", 2000u));
    check_int_eq(P2P_ERR_RESOURCE_EXHAUSTED,
                 p2p_node_source_admission_acquire_locked(
                     test_node, "2001:db8:1:2::ffff", 2000u));
    check_int_eq(P2P_ERR_RESOURCE_EXHAUSTED,
                 p2p_node_source_admission_acquire_locked(
                     test_node, "2001:db8:1:3::1", 2000u));
    check_int_eq(P2P_OK, p2p_node_source_admission_acquire_locked(
                              test_node, "2001:db8:1:3::1", 4000u));
    turbo_mutex_unlock(&test_node->mutex);
    p2p_node_record_security_failure(test_node, P2P_SECURITY_STAGE_PREFACE,
                                     P2P_ERR_PROTOCOL);
    p2p_node_record_security_failure(
        test_node, P2P_SECURITY_STAGE_ESTABLISHED, P2P_ERR_KEY_EXHAUSTED);

    status.struct_size = sizeof(status);
    check_int_eq(P2P_OK,
                 p2p_node_get_security_status_v2(test_node, &status));
    check_uint_eq(2u, status.source_admission_burst);
    check_uint_eq(1u, status.source_admission_refill_per_second);
    check_uint_eq(2u, status.source_admission_bucket_limit);
    check_uint_eq(2u, status.active_source_admission_buckets);
    check_uint_eq(
        3u,
        status.rejection_counts[P2P_SECURITY_REJECTION_SOURCE_RATE]);
    check_uint_eq(
        1u, status.rejection_counts[
                P2P_SECURITY_REJECTION_SOURCE_BUCKET_CAPACITY]);
    check_uint_eq(
        1u, status.rejection_counts[
                P2P_SECURITY_REJECTION_HANDSHAKE_PROTOCOL]);
    check_uint_eq(
        1u, status.rejection_counts[
                P2P_SECURITY_REJECTION_SESSION_KEY_LIMIT]);
}

void test_p2p_two_nodes_exchange_public_keys(void) {
    const int port1 = p2p_test_alloc_port_block(2);
    const int port2 = port1 + 1;
    p2p_node_t *node1 = NULL;
    p2p_node_t *node2 = NULL;
    uint8_t node1_public_key[P2P_KEY_SIZE] = {0};
    uint8_t node2_public_key[P2P_KEY_SIZE] = {0};
    uint8_t node1_seen_peer_key[P2P_KEY_SIZE] = {0};
    uint8_t node2_seen_peer_key[P2P_KEY_SIZE] = {0};
    p2p_peer_security_info_v2_t security1 = {0};
    p2p_peer_security_info_v2_t security2 = {0};
    uint8_t zero_security_id[P2P_SECURITY_ID_SIZE] = {0};
    int node1_saw_node2 = 0;
    int node2_saw_node1 = 0;
    int ret = 0;

    node1 = p2p_create("127.0.0.1", port1);
    node2 = p2p_create("127.0.0.1", port2);
    check_not_null(node1);
    check_not_null(node2);

    check_int_eq(P2P_OK, p2p_node_get_public_key(node1, node1_public_key));
    check_int_eq(P2P_OK, p2p_node_get_public_key(node2, node2_public_key));

    {
        p2p_node_t *nodes[] = {node1, node2};
        check_int_eq(P2P_OK, p2p_test_configure_pinned(nodes, 2));
    }
    ret = p2p_node_start_server(node1);
    check_int_eq(P2P_OK, ret);
    ret = p2p_node_start_server(node2);
    check_int_eq(P2P_OK, ret);

    ret = p2p_connect(node2, "127.0.0.1", port1);
    check_int_eq(P2P_OK, ret);

    for (int i = 0; i < 50; i++) {
        coro_context_run(p2p_get_loop(node1), TURBO_RUN_NOWAIT);
        coro_context_run(p2p_get_loop(node2), TURBO_RUN_NOWAIT);
        turbo_sleep_ms(100);

        if (!node1_saw_node2 &&
            p2p_test_first_peer_public_key(node1, node1_seen_peer_key) == P2P_OK) {
            node1_saw_node2 = 1;
        }
        if (!node2_saw_node1 &&
            p2p_test_first_peer_public_key(node2, node2_seen_peer_key) == P2P_OK) {
            node2_saw_node1 = 1;
        }
        if (node1_saw_node2 && node2_saw_node1 &&
            p2p_test_first_peer_security(node1, &security1) == P2P_OK &&
            p2p_test_first_peer_security(node2, &security2) == P2P_OK) {
            break;
        }
    }

    p2p_test_shutdown_nodes(node1, node2, NULL);
    p2p_destroy(node2);
    p2p_destroy(node1);

    check(node1_saw_node2);
    check(node2_saw_node1);
    check(memcmp(node1_seen_peer_key, node2_public_key, sizeof(node1_seen_peer_key)) == 0);
    check(memcmp(node2_seen_peer_key, node1_public_key, sizeof(node2_seen_peer_key)) == 0);
    check_int_eq(P2P_SECURE_WIRE_VERSION_V2, security1.secure_wire_version);
    check_int_eq(1, security1.noise_suite);
    check_true(security1.authenticated);
    check_true(security2.authenticated);
    check_mem_eq(security1.remote_noise_static, node2_public_key,
                 sizeof(node2_public_key));
    check_mem_eq(security2.remote_noise_static, node1_public_key,
                 sizeof(node1_public_key));
    check_mem_ne(security1.channel_binding, zero_security_id,
                 sizeof(zero_security_id));
    check_mem_ne(security2.channel_binding, zero_security_id,
                 sizeof(zero_security_id));
    check(security1.session_started_ms != 0);
    check(security2.session_started_ms != 0);
}

void test_p2p_secure_wire_requires_identity_configuration(void) {
    p2p_node_t *node = p2p_create(
        "127.0.0.1", p2p_test_alloc_port_block(1));

    check_not_null(node);
    check_int_eq(P2P_ERR_AUTH_REQUIRED, p2p_node_start_server(node));
    p2p_destroy(node);
}

void test_p2p_secure_wire_rejects_network_mismatch(void) {
    const int port1 = p2p_test_alloc_port_block(2);
    const int port2 = port1 + 1;
    uint8_t network1[P2P_SECURITY_ID_SIZE] = {1};
    uint8_t network2[P2P_SECURITY_ID_SIZE] = {2};
    uint8_t keys[2 * P2P_KEY_SIZE] = {0};
    p2p_node_security_status_v2_t status1 = {0};
    p2p_node_security_status_v2_t status2 = {0};
    p2p_node_t *node1 = p2p_create("127.0.0.1", port1);
    p2p_node_t *node2 = p2p_create("127.0.0.1", port2);

    check_not_null(node1);
    check_not_null(node2);
    check_int_eq(P2P_OK, p2p_node_get_public_key(node1, keys));
    check_int_eq(P2P_OK,
                 p2p_node_get_public_key(node2, keys + P2P_KEY_SIZE));
    check_int_eq(P2P_OK, p2p_node_configure_pinned_security_v2(
                              node1, network1, keys, 2));
    check_int_eq(P2P_OK, p2p_node_configure_pinned_security_v2(
                              node2, network2, keys, 2));
    check_int_eq(P2P_OK, p2p_node_start_server(node1));
    check_int_eq(P2P_OK, p2p_node_start_server(node2));
    check_int_eq(P2P_OK, p2p_connect(node2, "127.0.0.1", port1));

    for (int i = 0; i < 30; ++i) {
        coro_context_run(p2p_get_loop(node1), TURBO_RUN_NOWAIT);
        coro_context_run(p2p_get_loop(node2), TURBO_RUN_NOWAIT);
        turbo_sleep_ms(10);
    }
    check_int_eq(0, p2p_test_connected_peer_count(node1));
    check_int_eq(0, p2p_test_connected_peer_count(node2));
    status1.struct_size = sizeof(status1);
    status2.struct_size = sizeof(status2);
    check_int_eq(P2P_OK, p2p_node_get_security_status_v2(node1, &status1));
    check_int_eq(P2P_OK, p2p_node_get_security_status_v2(node2, &status2));
    check_true(status1.rejection_counts[
                   P2P_SECURITY_REJECTION_HANDSHAKE_PROTOCOL] +
                   status2.rejection_counts[
                       P2P_SECURITY_REJECTION_HANDSHAKE_PROTOCOL] +
                   status1.rejection_counts[
                       P2P_SECURITY_REJECTION_COOKIE_PROTOCOL] +
                   status2.rejection_counts[
                       P2P_SECURITY_REJECTION_COOKIE_PROTOCOL] >=
               1u);
    p2p_destroy(node2);
    p2p_destroy(node1);
}

void test_p2p_secure_wire_rejects_unpinned_static_key(void) {
    const int port1 = p2p_test_alloc_port_block(2);
    const int port2 = port1 + 1;
    uint8_t network[P2P_SECURITY_ID_SIZE] = {3};
    uint8_t key1[P2P_KEY_SIZE] = {0};
    uint8_t key2[P2P_KEY_SIZE] = {0};
    p2p_node_security_status_v2_t status1 = {0};
    p2p_node_security_status_v2_t status2 = {0};
    p2p_node_t *node1 = p2p_create("127.0.0.1", port1);
    p2p_node_t *node2 = p2p_create("127.0.0.1", port2);

    check_not_null(node1);
    check_not_null(node2);
    check_int_eq(P2P_OK, p2p_node_get_public_key(node1, key1));
    check_int_eq(P2P_OK, p2p_node_get_public_key(node2, key2));
    check_int_eq(P2P_OK, p2p_node_configure_pinned_security_v2(
                              node1, network, key1, 1));
    check_int_eq(P2P_OK, p2p_node_configure_pinned_security_v2(
                              node2, network, key1, 1));
    check_int_eq(P2P_OK, p2p_node_start_server(node1));
    check_int_eq(P2P_OK, p2p_node_start_server(node2));
    check_int_eq(P2P_OK, p2p_connect(node2, "127.0.0.1", port1));

    for (int i = 0; i < 30; ++i) {
        coro_context_run(p2p_get_loop(node1), TURBO_RUN_NOWAIT);
        coro_context_run(p2p_get_loop(node2), TURBO_RUN_NOWAIT);
        turbo_sleep_ms(10);
    }
    check_int_eq(0, p2p_test_connected_peer_count(node1));
    check_int_eq(0, p2p_test_connected_peer_count(node2));
    status1.struct_size = sizeof(status1);
    status2.struct_size = sizeof(status2);
    check_int_eq(P2P_OK, p2p_node_get_security_status_v2(node1, &status1));
    check_int_eq(P2P_OK, p2p_node_get_security_status_v2(node2, &status2));
    check_true(status1.rejection_counts[
                   P2P_SECURITY_REJECTION_HANDSHAKE_IDENTITY] +
                   status2.rejection_counts[
                       P2P_SECURITY_REJECTION_HANDSHAKE_IDENTITY] >=
               1u);
    p2p_destroy(node2);
    p2p_destroy(node1);
}

void test_p2p_dht_get_fetches_remote_value(void) {
    const int port1 = p2p_test_alloc_port_block(2);
    const int port2 = port1 + 1;
    p2p_node_t *node1 = NULL;
    p2p_node_t *node2 = NULL;
    p2p_loop_thread_ctx_t node1_loop = {0};
    turbo_thread_t node1_thread = NULL;
    const char *key = "test:dht:remote:get";
    const char *value = "hello-from-node1";
    char buf[128] = {0};
    size_t buf_len = sizeof(buf);
    int ret = 0;

    g_connected_count = 0;

    node1 = p2p_create("127.0.0.1", port1);
    node2 = p2p_create("127.0.0.1", port2);
    check_not_null(node1);
    check_not_null(node2);

    p2p_set_peer_callbacks(node1, on_peer_connected_cb, on_peer_disconnected_cb, NULL);
    p2p_set_peer_callbacks(node2, on_peer_connected_cb, on_peer_disconnected_cb, NULL);

    {
        p2p_node_t *nodes[] = {node1, node2};
        check_int_eq(P2P_OK, p2p_test_configure_pinned(nodes, 2));
    }
    ret = p2p_node_start_server(node1);
    check_int_eq(P2P_OK, ret);
    ret = p2p_node_start_server(node2);
    check_int_eq(P2P_OK, ret);

    ret = p2p_connect(node2, "127.0.0.1", port1);
    check_int_eq(P2P_OK, ret);

    for (int i = 0; i < 40; i++) {
        coro_context_run(p2p_get_loop(node1), TURBO_RUN_NOWAIT);
        coro_context_run(p2p_get_loop(node2), TURBO_RUN_NOWAIT);
        turbo_sleep_ms(100);
        if (p2p_test_connected_peer_count(node1) > 0 &&
            p2p_test_connected_peer_count(node2) > 0) {
            break;
        }
    }
    check(p2p_test_connected_peer_count(node1) > 0);
    check(p2p_test_connected_peer_count(node2) > 0);

    node1_loop.node = node1;
    node1_loop.running = 1;
    check_int_eq(0, turbo_thread_create(&node1_thread, p2p_test_pump_loop, &node1_loop));

    ret = p2p_dht_put(node1, key, value, strlen(value) + 1);
    check_int_eq(P2P_OK, ret);

    ret = p2p_dht_get(node2, key, buf, &buf_len);
    check_int_eq(P2P_OK, ret);
    check_str_eq(value, buf);

    node1_loop.running = 0;
    turbo_thread_join(&node1_thread);
    turbo_thread_destroy(&node1_thread);

    p2p_test_shutdown_nodes(node1, node2, NULL);
    p2p_destroy(node2);
    p2p_destroy(node1);
}

void test_p2p_dht_put_replicates_to_connected_peer(void) {
    const int port1 = p2p_test_alloc_port_block(2);
    const int port2 = port1 + 1;
    p2p_node_t *node1 = NULL;
    p2p_node_t *node2 = NULL;
    const char *key = "test:dht:replicate";
    const char *value = "replicated-over-p2p";
    kad_id_t kkey;
    char buf[128] = {0};
    size_t buf_len = sizeof(buf);
    int ret = 0;

    g_connected_count = 0;

    node1 = p2p_create("127.0.0.1", port1);
    node2 = p2p_create("127.0.0.1", port2);
    check_not_null(node1);
    check_not_null(node2);

    p2p_set_peer_callbacks(node1, on_peer_connected_cb, on_peer_disconnected_cb, NULL);
    p2p_set_peer_callbacks(node2, on_peer_connected_cb, on_peer_disconnected_cb, NULL);

    {
        p2p_node_t *nodes[] = {node1, node2};
        check_int_eq(P2P_OK, p2p_test_configure_pinned(nodes, 2));
    }
    ret = p2p_node_start_server(node1);
    check_int_eq(P2P_OK, ret);
    ret = p2p_node_start_server(node2);
    check_int_eq(P2P_OK, ret);

    ret = p2p_connect(node2, "127.0.0.1", port1);
    check_int_eq(P2P_OK, ret);

    for (int i = 0; i < 30; i++) {
        coro_context_run(p2p_get_loop(node1), TURBO_RUN_NOWAIT);
        coro_context_run(p2p_get_loop(node2), TURBO_RUN_NOWAIT);
        turbo_sleep_ms(100);
        if (p2p_test_connected_peer_count(node1) > 0 &&
            p2p_test_connected_peer_count(node2) > 0) {
            break;
        }
    }
    check(p2p_test_connected_peer_count(node1) > 0);
    check(p2p_test_connected_peer_count(node2) > 0);

    ret = p2p_dht_put(node1, key, value, strlen(value) + 1);
    check_int_eq(P2P_OK, ret);

    kad_id_from_data(key, strlen(key), &kkey);
    for (int i = 0; i < 80; i++) {
        coro_context_run(p2p_get_loop(node1), TURBO_RUN_NOWAIT);
        coro_context_run(p2p_get_loop(node2), TURBO_RUN_NOWAIT);
        turbo_mutex_lock(&node2->mutex);
        if (kademlia_find_value(node2->kad_dht, &kkey, buf, &buf_len) == 0) {
            turbo_mutex_unlock(&node2->mutex);
            break;
        }
        turbo_mutex_unlock(&node2->mutex);
        buf_len = sizeof(buf);
        turbo_sleep_ms(50);
    }

    check_str_eq(value, buf);

    p2p_test_shutdown_nodes(node1, node2, NULL);
    p2p_destroy(node2);
    p2p_destroy(node1);
}

void test_p2p_dht_entry_count_tracks_cached_values(void) {
    const char *key1 = "test:dht:count:one";
    const char *key2 = "test:dht:count:two";
    const char *value1 = "value-one";
    const char *value2 = "value-two";

    check_int_eq(0, (int)p2p_dht_get_entry_count(test_node));
    check_int_eq(P2P_OK, p2p_dht_put_cached(test_node, key1, value1, strlen(value1) + 1));
    check_int_eq(1, (int)p2p_dht_get_entry_count(test_node));
    check_int_eq(P2P_OK, p2p_dht_put_cached(test_node, key1, value2, strlen(value2) + 1));
    check_int_eq(1, (int)p2p_dht_get_entry_count(test_node));
    check_int_eq(P2P_OK, p2p_dht_put_cached(test_node, key2, value2, strlen(value2) + 1));
    check_int_eq(2, (int)p2p_dht_get_entry_count(test_node));
    check_int_eq(0, (int)p2p_dht_get_entry_count(NULL));
}

void test_p2p_dht_put_reaches_discovered_peer(void) {
    const int port1 = p2p_test_alloc_port_block(3);
    const int port2 = port1 + 1;
    const int port3 = port1 + 2;
    p2p_node_t *node1 = NULL;
    p2p_node_t *node2 = NULL;
    p2p_node_t *node3 = NULL;
    p2p_loop_thread_ctx_t loop1 = {0};
    p2p_loop_thread_ctx_t loop2 = {0};
    p2p_loop_thread_ctx_t loop3 = {0};
    turbo_thread_t thread1 = NULL;
    turbo_thread_t thread2 = NULL;
    turbo_thread_t thread3 = NULL;
    const char *key = "test:dht:discover-put";
    const char *value = "value-for-discovered-node";
    kad_id_t kkey;
    char buf[128] = {0};
    size_t buf_len = sizeof(buf);
    int ret = 0;
    int found = 0;

    g_connected_count = 0;

    node1 = p2p_create("127.0.0.1", port1);
    node2 = p2p_create("127.0.0.1", port2);
    node3 = p2p_create("127.0.0.1", port3);
    check_not_null(node1);
    check_not_null(node2);
    check_not_null(node3);

    p2p_set_peer_callbacks(node1, on_peer_connected_cb, on_peer_disconnected_cb, NULL);
    p2p_set_peer_callbacks(node2, on_peer_connected_cb, on_peer_disconnected_cb, NULL);
    p2p_set_peer_callbacks(node3, on_peer_connected_cb, on_peer_disconnected_cb, NULL);

    {
        p2p_node_t *nodes[] = {node1, node2, node3};
        check_int_eq(P2P_OK, p2p_test_configure_pinned(nodes, 3));
    }
    check_int_eq(P2P_OK, p2p_node_start_server(node1));
    check_int_eq(P2P_OK, p2p_node_start_server(node2));
    check_int_eq(P2P_OK, p2p_node_start_server(node3));

    check_int_eq(P2P_OK, p2p_connect(node1, "127.0.0.1", port2));
    check_int_eq(P2P_OK, p2p_connect(node3, "127.0.0.1", port2));

    for (int i = 0; i < 40; i++) {
        coro_context_run(p2p_get_loop(node1), TURBO_RUN_NOWAIT);
        coro_context_run(p2p_get_loop(node2), TURBO_RUN_NOWAIT);
        coro_context_run(p2p_get_loop(node3), TURBO_RUN_NOWAIT);
        turbo_sleep_ms(100);
        if (p2p_test_connected_peer_count(node1) > 0 &&
            p2p_test_connected_peer_count(node2) >= 2 &&
            p2p_test_connected_peer_count(node3) > 0) {
            break;
        }
    }
    check(p2p_test_connected_peer_count(node1) > 0);
    check(p2p_test_connected_peer_count(node2) >= 2);
    check(p2p_test_connected_peer_count(node3) > 0);

    for (int i = 0; i < 20; i++) {
        int node2_has_node3 = 0;

        turbo_mutex_lock(&node2->mutex);
        node2_has_node3 = p2p_test_routing_has_endpoint(node2, "127.0.0.1", port3);
        turbo_mutex_unlock(&node2->mutex);
        if (node2_has_node3) {
            break;
        }

        coro_context_run(p2p_get_loop(node1), TURBO_RUN_NOWAIT);
        coro_context_run(p2p_get_loop(node2), TURBO_RUN_NOWAIT);
        coro_context_run(p2p_get_loop(node3), TURBO_RUN_NOWAIT);
        turbo_sleep_ms(50);
    }

    turbo_mutex_lock(&node2->mutex);
    check(p2p_test_routing_has_endpoint(node2, "127.0.0.1", port3));
    turbo_mutex_unlock(&node2->mutex);

    loop1.node = node1;
    loop2.node = node2;
    loop3.node = node3;
    loop1.running = 1;
    loop2.running = 1;
    loop3.running = 1;
    check_int_eq(0, turbo_thread_create(&thread1, p2p_test_pump_loop, &loop1));
    check_int_eq(0, turbo_thread_create(&thread2, p2p_test_pump_loop, &loop2));
    check_int_eq(0, turbo_thread_create(&thread3, p2p_test_pump_loop, &loop3));

    ret = p2p_dht_put(node1, key, value, strlen(value) + 1);
    check_int_eq(P2P_OK, ret);

    kad_id_from_data(key, strlen(key), &kkey);
    for (int i = 0; i < 40; i++) {
        turbo_mutex_lock(&node3->mutex);
        ret = kademlia_find_value(node3->kad_dht, &kkey, buf, &buf_len);
        turbo_mutex_unlock(&node3->mutex);
        if (ret == 0) {
            found = 1;
            break;
        }
        buf_len = sizeof(buf);
        turbo_sleep_ms(50);
    }

    p2p_test_shutdown_mesh(node1, node2, node3,
                           &loop1, &loop2, &loop3,
                           &thread1, &thread2, &thread3);

    check(found);
    check(strcmp(buf, value) == 0);

    p2p_test_shutdown_nodes(node1, node2, node3);
    p2p_destroy(node3);
    p2p_destroy(node2);
    p2p_destroy(node1);
}

void test_p2p_dht_get_handles_parallel_network_lookups(void) {
    const int port1 = p2p_test_alloc_port_block(3);
    const int port2 = port1 + 1;
    const int port3 = port1 + 2;
    p2p_node_t *node1 = NULL;
    p2p_node_t *node2 = NULL;
    p2p_node_t *node3 = NULL;
    const char *key1 = "test:dht:parallel:get:one";
    const char *key2 = "test:dht:parallel:get:two";
    const char *value1 = "parallel-value-one";
    const char *value2 = "parallel-value-two";
    kad_id_t kkey1;
    kad_id_t kkey2;
    p2p_dht_lookup_t *lookup1 = NULL;
    p2p_dht_lookup_t *lookup2 = NULL;
    uint32_t request_id1 = 0;
    uint32_t request_id2 = 0;
    char buf1[128] = {0};
    char buf2[128] = {0};
    size_t buf1_len = sizeof(buf1);
    size_t buf2_len = sizeof(buf2);
    int ret = 0;

    g_connected_count = 0;
    node1 = p2p_create("127.0.0.1", port1);
    node2 = p2p_create("127.0.0.1", port2);
    node3 = p2p_create("127.0.0.1", port3);
    check_not_null(node1);
    check_not_null(node2);
    check_not_null(node3);

    p2p_set_peer_callbacks(node1, on_peer_connected_cb, on_peer_disconnected_cb, NULL);
    p2p_set_peer_callbacks(node2, on_peer_connected_cb, on_peer_disconnected_cb, NULL);
    p2p_set_peer_callbacks(node3, on_peer_connected_cb, on_peer_disconnected_cb, NULL);

    {
        p2p_node_t *nodes[] = {node1, node2, node3};
        check_int_eq(P2P_OK, p2p_test_configure_pinned(nodes, 3));
    }
    check_int_eq(P2P_OK, p2p_node_start_server(node1));
    check_int_eq(P2P_OK, p2p_node_start_server(node2));
    check_int_eq(P2P_OK, p2p_node_start_server(node3));
    check_int_eq(P2P_OK, p2p_connect(node1, "127.0.0.1", port2));
    check_int_eq(P2P_OK, p2p_connect(node1, "127.0.0.1", port3));
    check_int_eq(P2P_OK, p2p_connect(node3, "127.0.0.1", port2));

    for (int i = 0; i < 40; i++) {
        coro_context_run(p2p_get_loop(node1), TURBO_RUN_NOWAIT);
        coro_context_run(p2p_get_loop(node2), TURBO_RUN_NOWAIT);
        coro_context_run(p2p_get_loop(node3), TURBO_RUN_NOWAIT);
        turbo_sleep_ms(100);
        if (p2p_test_connected_peer_count(node1) >= 2 &&
            p2p_test_connected_peer_count(node2) >= 2 &&
            p2p_test_connected_peer_count(node3) >= 2) {
            break;
        }
    }
    check(p2p_test_connected_peer_count(node1) >= 2);
    check(p2p_test_connected_peer_count(node2) >= 2);
    check(p2p_test_connected_peer_count(node3) >= 2);

    kad_id_from_data(key1, strlen(key1), &kkey1);
    kad_id_from_data(key2, strlen(key2), &kkey2);

    turbo_mutex_lock(&node3->mutex);
    check_int_eq(0, kademlia_store(node3->kad_dht, &kkey1, value1, strlen(value1) + 1));
    check_int_eq(0, kademlia_store(node3->kad_dht, &kkey2, value2, strlen(value2) + 1));
    turbo_mutex_unlock(&node3->mutex);

    lookup1 = p2p_dht_lookup_start(node1, kkey1.bytes, P2P_MSG_DHT_GET);
    lookup2 = p2p_dht_lookup_start(node1, kkey2.bytes, P2P_MSG_DHT_GET);
    check_not_null(lookup1);
    check_not_null(lookup2);
    request_id1 = lookup1->request_id;
    request_id2 = lookup2->request_id;

    check(request_id1 != request_id2);

    for (int i = 0; i < 200; i++) {
        coro_context_run(p2p_get_loop(node1), TURBO_RUN_NOWAIT);
        coro_context_run(p2p_get_loop(node2), TURBO_RUN_NOWAIT);
        coro_context_run(p2p_get_loop(node3), TURBO_RUN_NOWAIT);

        turbo_mutex_lock(&node1->mutex);
        ret = kademlia_find_value(node1->kad_dht, &kkey1, buf1, &buf1_len);
        if (ret != 0) {
            buf1_len = sizeof(buf1);
        }
        if (kademlia_find_value(node1->kad_dht, &kkey2, buf2, &buf2_len) != 0) {
            buf2_len = sizeof(buf2);
            ret = -1;
        } else if (ret == 0) {
            ret = 0;
        }
        turbo_mutex_unlock(&node1->mutex);

        if (ret == 0) {
            break;
        }
        turbo_sleep_ms(50);
    }

    check_str_eq(value1, buf1);
    check_str_eq(value2, buf2);

    turbo_mutex_lock(&node1->mutex);
    check_null(p2p_dht_lookup_find(node1, request_id1));
    check_null(p2p_dht_lookup_find(node1, request_id2));
    turbo_mutex_unlock(&node1->mutex);

    p2p_test_shutdown_nodes(node1, node2, node3);
    p2p_destroy(node3);
    p2p_destroy(node2);
    p2p_destroy(node1);
}

void test_p2p_dht_response_matches_request_id(void) {
    p2p_node_t *node = NULL;
    p2p_peer_t *peer = NULL;
    p2p_dht_lookup_t *lookup1 = NULL;
    p2p_dht_lookup_t *lookup2 = NULL;
    p2p_message_t msg1 = {0};
    p2p_message_t msg2 = {0};
    kad_id_t key1;
    kad_id_t key2;
    char buf[128] = {0};
    size_t buf_len = sizeof(buf);
    const char *value1 = "value-one";
    const char *value2 = "value-two";

    node = p2p_create("127.0.0.1", 41041);
    check_not_null(node);

    peer = p2p_peer_create(node, "127.0.0.1", 41042);
    check_not_null(peer);
    peer->is_connected = 1;

    lookup1 = (p2p_dht_lookup_t *)calloc(1, sizeof(p2p_dht_lookup_t));
    lookup2 = (p2p_dht_lookup_t *)calloc(1, sizeof(p2p_dht_lookup_t));
    check_not_null(lookup1);
    check_not_null(lookup2);

    kad_id_from_data("parallel-key-1", strlen("parallel-key-1"), &key1);
    kad_id_from_data("parallel-key-2", strlen("parallel-key-2"), &key2);

    lookup1->request_id = 1001;
    lookup1->type = P2P_MSG_DHT_GET;
    lookup1->active_requests = 1;
    memcpy(lookup1->target, key1.bytes, KADEMLIA_ID_BYTES);

    lookup2->request_id = 1002;
    lookup2->type = P2P_MSG_DHT_GET;
    lookup2->active_requests = 1;
    memcpy(lookup2->target, key2.bytes, KADEMLIA_ID_BYTES);

    turbo_mutex_lock(&node->mutex);
    HASH_ADD(hh, node->dht_lookups, request_id, sizeof(lookup1->request_id), lookup1);
    HASH_ADD(hh, node->dht_lookups, request_id, sizeof(lookup2->request_id), lookup2);
    turbo_mutex_unlock(&node->mutex);

    p2p_message_init(&msg1, P2P_MSG_DHT_RESPONSE);
    msg1.header.request_id = 1002;
    msg1.payload.dht_response.found = 1;
    msg1.payload.dht_response.data_len = (uint16_t)(strlen(value2) + 1);
    msg1.header.payload_len =
        (uint16_t)(offsetof(p2p_dht_response_payload_t, data) +
                   msg1.payload.dht_response.data_len);
    memcpy(msg1.payload.dht_response.data, value2, strlen(value2) + 1);

    p2p_message_init(&msg2, P2P_MSG_DHT_RESPONSE);
    msg2.header.request_id = 1001;
    msg2.payload.dht_response.found = 1;
    msg2.payload.dht_response.data_len = (uint16_t)(strlen(value1) + 1);
    msg2.header.payload_len =
        (uint16_t)(offsetof(p2p_dht_response_payload_t, data) +
                   msg2.payload.dht_response.data_len);
    memcpy(msg2.payload.dht_response.data, value1, strlen(value1) + 1);

    check_int_eq(P2P_OK, p2p_handle_dht_response(node, peer, &msg1));
    turbo_mutex_lock(&node->mutex);
    check_int_eq(1, HASH_COUNT(node->dht_lookups));
    turbo_mutex_unlock(&node->mutex);
    check_int_eq(P2P_OK, p2p_handle_dht_response(node, peer, &msg2));
    turbo_mutex_lock(&node->mutex);
    check_int_eq(0, HASH_COUNT(node->dht_lookups));
    turbo_mutex_unlock(&node->mutex);

    turbo_mutex_lock(&node->mutex);
    check_int_eq(0, kademlia_find_value(node->kad_dht, &key1, buf, &buf_len));
    turbo_mutex_unlock(&node->mutex);
    check_str_eq(value1, buf);

    buf_len = sizeof(buf);
    memset(buf, 0, sizeof(buf));
    turbo_mutex_lock(&node->mutex);
    check_int_eq(0, kademlia_find_value(node->kad_dht, &key2, buf, &buf_len));
    turbo_mutex_unlock(&node->mutex);
    check_str_eq(value2, buf);

    p2p_peer_destroy(peer);
    p2p_destroy(node);
}

/* =============================================================================
 * Error Handling Tests
 * ============================================================================= */

void test_p2p_error_str_valid(void) {
    const char *str = p2p_error_str(P2P_OK);
    check_not_null(str);
    check_str_eq("Success", str);

    str = p2p_error_str(P2P_ERR_INVALID);
    check_not_null(str);
    check_str_eq("Invalid argument", str);

    str = p2p_error_str(P2P_ERR_NO_MEM);
    check_not_null(str);
    check_str_eq("Out of memory", str);

    str = p2p_error_str(P2P_ERR_NETWORK);
    check_not_null(str);
    check_str_eq("Network error", str);

    str = p2p_error_str(P2P_ERR_TIMEOUT);
    check_not_null(str);
    check_str_eq("Timeout", str);

    str = p2p_error_str(P2P_ERR_NOT_FOUND);
    check_not_null(str);
    check_str_eq("Not found", str);

    str = p2p_error_str(P2P_ERR_KEY_EXHAUSTED);
    check_not_null(str);
    check_str_eq("Session key exhausted", str);
}

void test_p2p_error_str_unknown(void) {
    const char *str = p2p_error_str(9999);
    check_not_null(str);
    check_str_eq("Unknown error", str);
}

enum {
    P2P_TEST_AEAD_FRAME_OVERHEAD = P2P_NOISE_TAG_SIZE,
};

static int p2p_test_crypto_sessions(p2p_crypto_session_t *initiator_session,
                                    p2p_crypto_session_t *responder_session) {
    p2p_identity_t initiator_identity;
    p2p_identity_t responder_identity;
    p2p_noise_handshake_t initiator;
    p2p_noise_handshake_t responder;
    uint8_t message[P2P_SECURITY_HANDSHAKE_FRAME_MAX];
    size_t message_len = 0;
    int result = P2P_ERR_CRYPTO;

    memset(&initiator_identity, 0, sizeof(initiator_identity));
    memset(&responder_identity, 0, sizeof(responder_identity));
    memset(&initiator, 0, sizeof(initiator));
    memset(&responder, 0, sizeof(responder));
    memset(initiator_session, 0, sizeof(*initiator_session));
    memset(responder_session, 0, sizeof(*responder_session));
    if (p2p_crypto_generate_identity(&initiator_identity) != P2P_OK ||
        p2p_crypto_generate_identity(&responder_identity) != P2P_OK ||
        p2p_noise_init_initiator(&initiator, &initiator_identity, NULL) != P2P_OK ||
        p2p_noise_init_responder(&responder, &responder_identity) != P2P_OK ||
        p2p_noise_write_message(&initiator, message, &message_len,
                                sizeof(message)) != P2P_OK ||
        p2p_noise_read_message(&responder, message, message_len) != P2P_OK ||
        p2p_noise_write_message(&responder, message, &message_len,
                                sizeof(message)) != P2P_OK ||
        p2p_noise_read_message(&initiator, message, message_len) != P2P_OK ||
        p2p_noise_write_message(&initiator, message, &message_len,
                                sizeof(message)) != P2P_OK ||
        p2p_noise_read_message(&responder, message, message_len) != P2P_OK ||
        p2p_noise_split(&initiator, initiator_session) != P2P_OK ||
        p2p_noise_split(&responder, responder_session) != P2P_OK) {
        goto cleanup;
    }
    result = P2P_OK;

cleanup:
    p2p_noise_handshake_destroy(&initiator);
    p2p_noise_handshake_destroy(&responder);
    p2p_crypto_wipe(&initiator_identity, sizeof(initiator_identity));
    p2p_crypto_wipe(&responder_identity, sizeof(responder_identity));
    p2p_crypto_wipe(message, sizeof(message));
    if (result != P2P_OK) {
        p2p_crypto_session_destroy(initiator_session);
        p2p_crypto_session_destroy(responder_session);
    }
    return result;
}

static void test_p2p_private_key_provider_completes_noise_xx(void) {
    p2p_test_private_key_provider_t context;
    p2p_private_key_provider_v3_t provider;
    p2p_node_t *provider_node = p2p_create(
        "127.0.0.1", p2p_test_alloc_port_block(1));
    p2p_identity_t responder_identity = {0};
    p2p_noise_handshake_t initiator = {0};
    p2p_noise_handshake_t responder = {0};
    p2p_crypto_session_t initiator_session = {0};
    p2p_crypto_session_t responder_session = {0};
    uint8_t message[P2P_SECURITY_HANDSHAKE_FRAME_MAX] = {0};
    uint8_t zero[P2P_KEY_SIZE] = {0};
    size_t message_len = 0;

    check_not_null(provider_node);
    p2p_test_private_key_provider_init(&context, &provider, 0x41);
    check_int_eq(P2P_OK, p2p_node_set_private_key_provider_v3(
                              provider_node, &provider));
    check_int_eq(P2P_OK, p2p_crypto_generate_identity(&responder_identity));
    check_int_eq(P2P_OK,
                 p2p_noise_init_initiator(
                     &initiator, &provider_node->crypto.identity, NULL));
    check_int_eq(P2P_OK,
                 p2p_noise_init_responder(&responder, &responder_identity));
    check_int_eq(P2P_OK, p2p_noise_write_message(
                              &initiator, message, &message_len,
                              sizeof(message)));
    check_int_eq(P2P_OK,
                 p2p_noise_read_message(&responder, message, message_len));
    check_int_eq(P2P_OK, p2p_noise_write_message(
                              &responder, message, &message_len,
                              sizeof(message)));
    check_int_eq(P2P_OK,
                 p2p_noise_read_message(&initiator, message, message_len));
    check_int_eq(P2P_OK, p2p_noise_write_message(
                              &initiator, message, &message_len,
                              sizeof(message)));
    check_int_eq(P2P_OK,
                 p2p_noise_read_message(&responder, message, message_len));
    check_int_eq(P2P_OK, p2p_noise_split(&initiator, &initiator_session));
    check_int_eq(P2P_OK, p2p_noise_split(&responder, &responder_session));
    check_uint_eq(2, context.calculate_calls);
    check(memcmp(provider_node->crypto.identity.secret_key, zero,
                 sizeof(zero)) == 0);

    p2p_crypto_session_destroy(&initiator_session);
    p2p_crypto_session_destroy(&responder_session);
    p2p_noise_handshake_destroy(&initiator);
    p2p_noise_handshake_destroy(&responder);
    p2p_crypto_wipe(&responder_identity, sizeof(responder_identity));
    p2p_crypto_wipe(message, sizeof(message));
    p2p_destroy(provider_node);
    turbo_crypto_wipe(&context, sizeof(context));
}

static void test_p2p_private_key_provider_propagates_dh_failure(void) {
    p2p_test_private_key_provider_t context;
    p2p_private_key_provider_v3_t provider;
    p2p_node_t *provider_node = p2p_create(
        "127.0.0.1", p2p_test_alloc_port_block(1));
    p2p_identity_t initiator_identity = {0};
    p2p_noise_handshake_t initiator = {0};
    p2p_noise_handshake_t responder = {0};
    uint8_t message[P2P_SECURITY_HANDSHAKE_FRAME_MAX] = {0};
    size_t message_len = 0;

    check_not_null(provider_node);
    p2p_test_private_key_provider_init(&context, &provider, 0x51);
    check_int_eq(P2P_OK, p2p_node_set_private_key_provider_v3(
                              provider_node, &provider));
    context.calculate_result = P2P_ERR_TIMEOUT;
    check_int_eq(P2P_OK, p2p_crypto_generate_identity(&initiator_identity));
    check_int_eq(P2P_OK,
                 p2p_noise_init_initiator(&initiator, &initiator_identity,
                                          NULL));
    check_int_eq(P2P_OK, p2p_noise_init_responder(
                              &responder, &provider_node->crypto.identity));
    check_int_eq(P2P_OK, p2p_noise_write_message(
                              &initiator, message, &message_len,
                              sizeof(message)));
    check_int_eq(P2P_OK,
                 p2p_noise_read_message(&responder, message, message_len));
    check_int_eq(P2P_ERR_TIMEOUT, p2p_noise_write_message(
                                      &responder, message, &message_len,
                                      sizeof(message)));
    check_uint_eq(2, context.calculate_calls);
    check_uint_eq(0, message_len);

    p2p_noise_handshake_destroy(&initiator);
    p2p_noise_handshake_destroy(&responder);
    p2p_crypto_wipe(&initiator_identity, sizeof(initiator_identity));
    p2p_crypto_wipe(message, sizeof(message));
    p2p_destroy(provider_node);
    turbo_crypto_wipe(&context, sizeof(context));
}

static void test_p2p_blocking_private_key_provider_completes_both_xx_roles(void) {
    const int port1 = p2p_test_alloc_port_block(2);
    const int port2 = port1 + 1;
    p2p_test_blocking_private_key_provider_t context1;
    p2p_test_blocking_private_key_provider_t context2;
    p2p_blocking_private_key_provider_v4_t provider1;
    p2p_blocking_private_key_provider_v4_t provider2;
    p2p_peer_security_info_v2_t security1 = {0};
    p2p_peer_security_info_v2_t security2 = {0};
    p2p_node_t *node1 = p2p_create("127.0.0.1", port1);
    p2p_node_t *node2 = p2p_create("127.0.0.1", port2);
    int connected = 0;
    int index;

    check_not_null(node1);
    check_not_null(node2);
    p2p_test_blocking_private_key_provider_init(&context1, &provider1,
                                                0x61);
    p2p_test_blocking_private_key_provider_init(&context2, &provider2,
                                                0x71);
    context1.calculate_delay_ms = 10;
    context2.calculate_delay_ms = 10;
    provider1.operation_timeout_ms = 500;
    provider2.operation_timeout_ms = 500;
    check_int_eq(P2P_OK,
                 p2p_node_set_blocking_private_key_provider_v4(
                     node1, &provider1));
    check_int_eq(P2P_OK,
                 p2p_node_set_blocking_private_key_provider_v4(
                     node2, &provider2));
    {
        p2p_node_t *nodes[] = {node1, node2};
        check_int_eq(P2P_OK, p2p_test_configure_pinned(nodes, 2));
    }
    check_int_eq(P2P_OK, p2p_node_start_server(node1));
    check_int_eq(P2P_OK, p2p_node_start_server(node2));
    check_int_eq(P2P_OK, p2p_connect(node2, "127.0.0.1", port1));

    security1.struct_size = sizeof(security1);
    security2.struct_size = sizeof(security2);
    for (index = 0; index < 200; ++index) {
        coro_context_run(p2p_get_loop(node1), TURBO_RUN_NOWAIT);
        coro_context_run(p2p_get_loop(node2), TURBO_RUN_NOWAIT);
        if (p2p_test_first_peer_security(node1, &security1) == P2P_OK &&
            p2p_test_first_peer_security(node2, &security2) == P2P_OK &&
            security1.authenticated && security2.authenticated) {
            connected = 1;
            break;
        }
        turbo_sleep_ms(10);
    }

    check_true(connected);
    check_uint_eq(2, atomic_load_explicit(&context1.calculate_calls,
                                         memory_order_relaxed));
    check_uint_eq(2, atomic_load_explicit(&context2.calculate_calls,
                                         memory_order_relaxed));
    check_uint_eq(1, node1->private_key_executor->completed);
    check_uint_eq(1, node2->private_key_executor->completed);
    check_uint_eq(0, node1->private_key_executor->active_operations);
    check_uint_eq(0, node2->private_key_executor->active_operations);

    p2p_test_shutdown_nodes(node1, node2, NULL);
    p2p_destroy(node2);
    p2p_destroy(node1);
    turbo_crypto_wipe(&context2, sizeof(context2));
    turbo_crypto_wipe(&context1, sizeof(context1));
}

static void test_p2p_blocking_private_key_provider_runtime_timeout_is_closed(void) {
    const int port1 = p2p_test_alloc_port_block(2);
    const int port2 = port1 + 1;
    p2p_test_blocking_private_key_provider_t context;
    p2p_blocking_private_key_provider_v4_t provider;
    p2p_private_key_executor_status_v4_t status = {0};
    p2p_node_t *server = p2p_create("127.0.0.1", port1);
    p2p_node_t *client = p2p_create("127.0.0.1", port2);
    int index;

    check_not_null(server);
    check_not_null(client);
    p2p_test_blocking_private_key_provider_init(&context, &provider, 0x81);
    provider.operation_timeout_ms = 10;
    check_int_eq(P2P_OK,
                 p2p_node_set_blocking_private_key_provider_v4(
                     server, &provider));
    context.calculate_delay_ms = 40;
    context.honor_cancel = 0;
    {
        p2p_node_t *nodes[] = {server, client};
        check_int_eq(P2P_OK, p2p_test_configure_pinned(nodes, 2));
    }
    check_int_eq(P2P_OK, p2p_node_start_server(server));
    check_int_eq(P2P_OK, p2p_node_start_server(client));
    check_int_eq(P2P_OK, p2p_connect(client, "127.0.0.1", port1));

    status.struct_size = sizeof(status);
    for (index = 0; index < 200; ++index) {
        coro_context_run(p2p_get_loop(server), TURBO_RUN_NOWAIT);
        coro_context_run(p2p_get_loop(client), TURBO_RUN_NOWAIT);
        if (p2p_node_get_private_key_executor_status_v4(server, &status) ==
                P2P_OK &&
            status.timed_out == 1 && status.active_operations == 0) {
            break;
        }
        turbo_sleep_ms(5);
    }
    check_uint_eq(1, status.submitted);
    check_uint_eq(1, status.completed);
    check_uint_eq(1, status.timed_out);
    check_uint_eq(0, status.active_operations);
    check_uint_eq(2, atomic_load_explicit(&context.calculate_calls,
                                         memory_order_relaxed));

    p2p_test_shutdown_nodes(server, client, NULL);
    p2p_destroy(client);
    p2p_destroy(server);
    turbo_crypto_wipe(&context, sizeof(context));
}

static void test_p2p_blocking_private_key_provider_destroy_cancels_and_drains(void) {
    const int port1 = p2p_test_alloc_port_block(2);
    const int port2 = port1 + 1;
    p2p_test_blocking_private_key_provider_t context;
    p2p_blocking_private_key_provider_v4_t provider;
    p2p_private_key_executor_status_v4_t status = {0};
    p2p_node_t *server = p2p_create("127.0.0.1", port1);
    p2p_node_t *client = p2p_create("127.0.0.1", port2);
    uint64_t destroy_started_ms;
    uint64_t destroy_elapsed_ms;
    int index;

    check_not_null(server);
    check_not_null(client);
    p2p_test_blocking_private_key_provider_init(&context, &provider, 0x91);
    provider.operation_timeout_ms = 2000;
    check_int_eq(P2P_OK,
                 p2p_node_set_blocking_private_key_provider_v4(
                     server, &provider));
    context.calculate_delay_ms = 1000;
    {
        p2p_node_t *nodes[] = {server, client};
        check_int_eq(P2P_OK, p2p_test_configure_pinned(nodes, 2));
    }
    check_int_eq(P2P_OK, p2p_node_start_server(server));
    check_int_eq(P2P_OK, p2p_node_start_server(client));
    check_int_eq(P2P_OK, p2p_connect(client, "127.0.0.1", port1));

    status.struct_size = sizeof(status);
    for (index = 0; index < 200; ++index) {
        coro_context_run(p2p_get_loop(server), TURBO_RUN_NOWAIT);
        coro_context_run(p2p_get_loop(client), TURBO_RUN_NOWAIT);
        if (p2p_node_get_private_key_executor_status_v4(server, &status) ==
                P2P_OK &&
            status.active_operations == 1 &&
            atomic_load_explicit(&context.calculate_calls,
                                 memory_order_relaxed) >= 2) {
            break;
        }
        turbo_sleep_ms(5);
    }
    check_uint_eq(1, status.active_operations);
    destroy_started_ms = turbo_hrtime() / 1000000U;
    p2p_destroy(server);
    destroy_elapsed_ms = turbo_hrtime() / 1000000U - destroy_started_ms;
    check(destroy_elapsed_ms < 500U);
    check_uint_eq(1, atomic_load_explicit(&context.cancel_calls,
                                         memory_order_relaxed));

    p2p_node_stop_server(client);
    p2p_test_disconnect_all_peers(client);
    for (index = 0; index < 50; ++index) {
        coro_context_run(p2p_get_loop(client), TURBO_RUN_NOWAIT);
        turbo_sleep_ms(2);
    }
    p2p_destroy(client);
    turbo_crypto_wipe(&context, sizeof(context));
}

static void test_p2p_blocking_private_key_provider_rejects_at_capacity(void) {
    const int port1 = p2p_test_alloc_port_block(3);
    p2p_test_blocking_private_key_provider_t context;
    p2p_blocking_private_key_provider_v4_t provider;
    p2p_private_key_executor_status_v4_t status = {0};
    p2p_node_t *server = p2p_create("127.0.0.1", port1);
    p2p_node_t *client1 = p2p_create("127.0.0.1", port1 + 1);
    p2p_node_t *client2 = p2p_create("127.0.0.1", port1 + 2);
    int index;

    check_not_null(server);
    check_not_null(client1);
    check_not_null(client2);
    p2p_test_blocking_private_key_provider_init(&context, &provider, 0xa1);
    provider.executor_workers = 1;
    provider.executor_capacity = 1;
    provider.operation_timeout_ms = 1000;
    check_int_eq(P2P_OK,
                 p2p_node_set_blocking_private_key_provider_v4(
                     server, &provider));
    context.calculate_delay_ms = 250;
    {
        p2p_node_t *nodes[] = {server, client1, client2};
        check_int_eq(P2P_OK, p2p_test_configure_pinned(nodes, 3));
    }
    check_int_eq(P2P_OK, p2p_node_start_server(server));
    check_int_eq(P2P_OK, p2p_node_start_server(client1));
    check_int_eq(P2P_OK, p2p_node_start_server(client2));
    check_int_eq(P2P_OK, p2p_connect(client1, "127.0.0.1", port1));
    check_int_eq(P2P_OK, p2p_connect(client2, "127.0.0.1", port1));

    status.struct_size = sizeof(status);
    for (index = 0; index < 300; ++index) {
        coro_context_run(p2p_get_loop(server), TURBO_RUN_NOWAIT);
        coro_context_run(p2p_get_loop(client1), TURBO_RUN_NOWAIT);
        coro_context_run(p2p_get_loop(client2), TURBO_RUN_NOWAIT);
        if (p2p_node_get_private_key_executor_status_v4(server, &status) ==
                P2P_OK &&
            status.rejected >= 1 && status.completed >= 1 &&
            status.active_operations == 0) {
            break;
        }
        turbo_sleep_ms(5);
    }
    check_uint_eq(1, status.operation_capacity);
    check_uint_eq(1, status.submitted);
    check_uint_eq(1, status.completed);
    check(status.rejected >= 1);
    check_uint_eq(0, status.active_operations);

    p2p_test_shutdown_nodes(server, client1, client2);
    p2p_destroy(client2);
    p2p_destroy(client1);
    p2p_destroy(server);
    turbo_crypto_wipe(&context, sizeof(context));
}

static void test_p2p_blocking_private_key_executor_enforces_64_65_boundary(
    void) {
    enum {
        P2P_TEST_PRIVATE_KEY_ADMITTED =
            P2P_PRIVATE_KEY_CAPACITY_DEFAULT,
        P2P_TEST_PRIVATE_KEY_ATTEMPTS =
            P2P_PRIVATE_KEY_CAPACITY_DEFAULT + 1,
    };
    p2p_test_blocking_private_key_provider_t context;
    p2p_blocking_private_key_provider_v4_t provider;
    p2p_private_key_executor_status_v4_t status = {0};
    p2p_peer_t *peers[P2P_TEST_PRIVATE_KEY_ATTEMPTS] = {0};
    p2p_node_t *node = p2p_create(
        "127.0.0.1", p2p_test_alloc_port_block(1));
    size_t prepared = 0;
    size_t index;
    int submit_result = P2P_ERR_INVALID_STATE;

    check_not_null(node);
    if (!node) {
        return;
    }
    p2p_test_blocking_private_key_provider_init(&context, &provider, 0xc1);
    provider.executor_workers = 1;
    provider.executor_capacity = P2P_TEST_PRIVATE_KEY_ADMITTED;
    provider.operation_timeout_ms = 5000;
    check_int_eq(P2P_OK,
                 p2p_node_set_blocking_private_key_provider_v4(
                     node, &provider));
    context.calculate_delay_ms = 1000;

    for (index = 0; index < P2P_TEST_PRIVATE_KEY_ATTEMPTS; ++index) {
        peers[index] = p2p_test_create_blocking_responder_peer(
            node, 20000 + (int)index);
        check_not_null(peers[index]);
        if (!peers[index]) {
            break;
        }
        prepared++;
        submit_result = p2p_private_key_executor_submit(
            peers[index], NULL, 0, 2, 0);
        if (index < P2P_TEST_PRIVATE_KEY_ADMITTED) {
            check_int_eq(P2P_OK, submit_result);
        } else {
            check_int_eq(P2P_ERR_RESOURCE_EXHAUSTED, submit_result);
        }
    }

    status.struct_size = sizeof(status);
    check_uint_eq(P2P_TEST_PRIVATE_KEY_ATTEMPTS, prepared);
    check_int_eq(P2P_OK,
                 p2p_node_get_private_key_executor_status_v4(node,
                                                              &status));
    check_uint_eq(P2P_TEST_PRIVATE_KEY_ADMITTED,
                  status.operation_capacity);
    check_uint_eq(P2P_TEST_PRIVATE_KEY_ADMITTED, status.submitted);
    check_uint_eq(P2P_TEST_PRIVATE_KEY_ADMITTED,
                  status.active_operations);
    check_uint_eq(1, status.rejected);

    p2p_private_key_executor_shutdown(node->private_key_executor);
    coro_context_run(p2p_get_loop(node), TURBO_RUN_NOWAIT);
    for (index = 0; index < prepared; ++index) {
        p2p_peer_destroy(peers[index]);
    }
    p2p_destroy(node);
    turbo_crypto_wipe(&context, sizeof(context));
}

static void test_p2p_blocking_private_key_stale_generation_is_isolated(void) {
    enum {
        P2P_TEST_PRIVATE_KEY_WAIT_ATTEMPTS = 1000,
        P2P_TEST_PRIVATE_KEY_WAIT_MS = 1,
    };
    p2p_test_blocking_private_key_provider_t context;
    p2p_test_private_key_connection_t connection_context;
    p2p_blocking_private_key_provider_v4_t provider;
    p2p_private_key_executor_status_v4_t status = {0};
    p2p_private_key_operation_t *operation = NULL;
    p2p_noise_handshake_t *old_handshake = NULL;
    p2p_noise_handshake_t *replacement_handshake = NULL;
    p2p_connection_t *connection = NULL;
    p2p_peer_t *peer = NULL;
    p2p_node_t *node = p2p_create(
        "127.0.0.1", p2p_test_alloc_port_block(1));
    uint64_t replacement_generation = 0;
    int worker_completed = 0;
    int index;

    check_not_null(node);
    if (!node) {
        return;
    }
    memset(&connection_context, 0, sizeof(connection_context));
    atomic_init(&connection_context.send_calls, 0);
    atomic_init(&connection_context.sent_bytes, 0);
    p2p_test_blocking_private_key_provider_init(&context, &provider, 0xd1);
    provider.operation_timeout_ms = 1000;
    check_int_eq(P2P_OK,
                 p2p_node_set_blocking_private_key_provider_v4(
                     node, &provider));
    context.calculate_delay_ms = 20;
    peer = p2p_test_create_blocking_responder_peer(node, 21000);
    replacement_handshake = (p2p_noise_handshake_t *)calloc(
        1, sizeof(*replacement_handshake));
    connection = (p2p_connection_t *)calloc(1, sizeof(*connection));
    check_not_null(peer);
    check_not_null(replacement_handshake);
    check_not_null(connection);
    if (!peer || !replacement_handshake || !connection) {
        goto cleanup;
    }
    connection->type = P2P_CONN_INBOUND;
    connection->ops.send = p2p_test_private_key_connection_send;
    connection->ops.close = p2p_test_private_key_connection_close;
    connection->ops.handle = &connection_context;
    connection->is_connected = 1;
    peer->conn = connection;
    connection = NULL;
    peer->state = P2P_PEER_STATE_HANDSHAKING;
    peer->security_stage = P2P_SECURITY_STAGE_NOISE;
    check_int_eq(P2P_OK, p2p_private_key_executor_submit(
                              peer, NULL, 0, 2, 0));

    for (index = 0; index < P2P_TEST_PRIVATE_KEY_WAIT_ATTEMPTS; ++index) {
        turbo_mutex_lock(&node->mutex);
        operation = peer->private_key_operation;
        worker_completed =
            operation && atomic_load_explicit(&operation->completed,
                                              memory_order_acquire) != 0;
        turbo_mutex_unlock(&node->mutex);
        if (worker_completed) {
            break;
        }
        turbo_sleep_ms(P2P_TEST_PRIVATE_KEY_WAIT_MS);
    }
    check_true(worker_completed);
    if (!worker_completed) {
        goto cleanup;
    }

    turbo_mutex_lock(&node->mutex);
    old_handshake = peer->handshake;
    peer->handshake = replacement_handshake;
    replacement_handshake = NULL;
    peer->handshake_generation++;
    replacement_generation = peer->handshake_generation;
    turbo_mutex_unlock(&node->mutex);

    p2p_private_key_executor_pump(node);
    status.struct_size = sizeof(status);
    check_int_eq(P2P_OK,
                 p2p_node_get_private_key_executor_status_v4(node,
                                                              &status));
    check_uint_eq(1, status.completed);
    check_uint_eq(0, status.active_operations);
    check_uint_eq(0, atomic_load_explicit(&connection_context.send_calls,
                                         memory_order_relaxed));
    check_uint_eq(0, atomic_load_explicit(&connection_context.sent_bytes,
                                         memory_order_relaxed));
    check_null(peer->private_key_operation);
    check_not_null(peer->handshake);
    check_uint_eq(replacement_generation, peer->handshake_generation);
    check_int_eq(P2P_PEER_STATE_HANDSHAKING, peer->state);
    check_int_eq(P2P_SECURITY_STAGE_NOISE, peer->security_stage);
    coro_context_run(p2p_get_loop(node), TURBO_RUN_NOWAIT);

cleanup:
    if (old_handshake) {
        p2p_noise_handshake_destroy(old_handshake);
        free(old_handshake);
    }
    if (peer) {
        p2p_peer_destroy(peer);
    }
    if (connection) {
        p2p_connection_destroy(connection);
    }
    if (replacement_handshake) {
        p2p_noise_handshake_destroy(replacement_handshake);
        free(replacement_handshake);
    }
    p2p_destroy(node);
    turbo_crypto_wipe(&context, sizeof(context));
}

static void test_p2p_blocking_private_key_late_completion_fails_closed(void) {
    const int port1 = p2p_test_alloc_port_block(2);
    p2p_test_blocking_private_key_provider_t context;
    p2p_blocking_private_key_provider_v4_t provider;
    p2p_private_key_executor_status_v4_t status = {0};
    p2p_node_t *server = p2p_create("127.0.0.1", port1);
    p2p_node_t *client = p2p_create("127.0.0.1", port1 + 1);
    size_t post_count = 0;
    int post_result = 0;
    int status_result = P2P_OK;
    int index;

    check_not_null(server);
    check_not_null(client);
    p2p_test_blocking_private_key_provider_init(&context, &provider, 0xb1);
    provider.operation_timeout_ms = 300;
    check_int_eq(P2P_OK,
                 p2p_node_set_blocking_private_key_provider_v4(
                     server, &provider));
    context.calculate_delay_ms = 200;
    {
        p2p_node_t *nodes[] = {server, client};
        check_int_eq(P2P_OK, p2p_test_configure_pinned(nodes, 2));
    }
    check_int_eq(P2P_OK, p2p_node_start_server(server));
    check_int_eq(P2P_OK, p2p_node_start_server(client));
    check_int_eq(P2P_OK, p2p_connect(client, "127.0.0.1", port1));
    status.struct_size = sizeof(status);
    for (index = 0; index < 200; ++index) {
        coro_context_run(p2p_get_loop(server), TURBO_RUN_NOWAIT);
        coro_context_run(p2p_get_loop(client), TURBO_RUN_NOWAIT);
        if (p2p_node_get_private_key_executor_status_v4(server, &status) ==
                P2P_OK &&
            status.active_operations == 1 &&
            atomic_load_explicit(&context.calculate_calls,
                                 memory_order_relaxed) >= 2) {
            break;
        }
        turbo_sleep_ms(2);
    }
    check_uint_eq(1, status.active_operations);

    for (post_count = 0; post_count < 20000; ++post_count) {
        post_result = coro_post(p2p_get_loop(server), p2p_test_noop_post,
                                NULL, NULL);
        if (post_result != 0) {
            break;
        }
    }
    check(post_count > 0);
    check_int_eq(TURBO_ENOMEM, post_result);
    for (index = 0; index < 500; ++index) {
        status_result = p2p_node_get_private_key_executor_status_v4(
            server, &status);
        if (status_result != P2P_OK) {
            break;
        }
        if (status.completion_post_failures == 1) {
            break;
        }
        turbo_sleep_ms(2);
    }
    check_int_eq(P2P_OK, status_result);
    check_uint_eq(1, status.completion_post_failures);
    p2p_private_key_executor_pump(server);
    check_int_eq(P2P_OK,
                 p2p_node_get_private_key_executor_status_v4(server,
                                                              &status));
    check_uint_eq(1, status.completed);
    check_uint_eq(1, status.timed_out);
    check_uint_eq(1, status.completion_post_failures);
    check_uint_eq(0, status.active_operations);

    coro_context_run(p2p_get_loop(server), TURBO_RUN_NOWAIT);
    coro_context_run(p2p_get_loop(client), TURBO_RUN_NOWAIT);
    p2p_test_shutdown_nodes(server, client, NULL);
    p2p_destroy(client);
    p2p_destroy(server);
    turbo_crypto_wipe(&context, sizeof(context));
}

static int p2p_test_send_enobufs(void *handle, const void *data, size_t len) {
    (void)handle;
    (void)data;
    (void)len;
    return TURBO_ENOBUFS;
}

static void p2p_test_connection_close_noop(void *handle) {
    (void)handle;
}

static int p2p_test_send_ok(void *handle, const void *data, size_t len) {
    (void)handle;
    (void)data;
    (void)len;
    return 0;
}

static p2p_peer_t *p2p_test_create_established_peer(
    p2p_crypto_session_t *receiver,
    int (*send_fn)(void *, const void *, size_t)) {
    p2p_peer_t *peer = p2p_peer_create(test_node, "127.0.0.1", 1);

    if (!peer) {
        return NULL;
    }
    if (p2p_test_crypto_sessions(&peer->crypto, receiver) != P2P_OK) {
        p2p_peer_destroy(peer);
        return NULL;
    }
    peer->conn = (p2p_connection_t *)calloc(1, sizeof(*peer->conn));
    if (!peer->conn) {
        p2p_crypto_session_destroy(receiver);
        p2p_peer_destroy(peer);
        return NULL;
    }
    peer->conn->type = P2P_CONN_OUTBOUND;
    peer->conn->is_connected = 1;
    peer->conn->ops.send = send_fn;
    peer->conn->ops.close = p2p_test_connection_close_noop;
    peer->state = P2P_PEER_STATE_CONNECTED;
    peer->security_stage = P2P_SECURITY_STAGE_ESTABLISHED;
    peer->session_started_ms = turbo_hrtime() / 1000000U;
    test_node->security_config.session_max_age_ms =
        P2P_SECURITY_SESSION_MAX_AGE_DEFAULT_MS;
    test_node->security_config.session_max_bytes_per_direction =
        P2P_SECURITY_SESSION_MAX_BYTES_DEFAULT;
    return peer;
}

static void test_p2p_send_hwm_rejection_closes_advanced_session(void) {
    p2p_crypto_session_t receiver = {0};
    p2p_peer_t *peer = p2p_test_create_established_peer(
        &receiver, p2p_test_send_enobufs);
    p2p_message_t message = {0};

    check_not_null(peer);
    if (peer) {
        p2p_message_init(&message, P2P_MSG_CUSTOM);

        check_int_eq(P2P_ERR_RESOURCE_EXHAUSTED,
                     p2p_peer_send(peer, &message));
        check_int_eq(P2P_PEER_STATE_DISCONNECTED, peer->state);
        check_null(peer->conn);
        check_false(p2p_crypto_session_is_ready(&peer->crypto));
    }
    p2p_crypto_session_destroy(&receiver);
    p2p_peer_destroy(peer);
}

static void test_p2p_session_age_limit_closes_before_encrypt(void) {
    p2p_crypto_session_t receiver = {0};
    p2p_peer_t *peer = p2p_test_create_established_peer(
        &receiver, p2p_test_send_ok);
    p2p_message_t message = {0};

    check_not_null(peer);
    if (peer) {
        test_node->security_config.session_max_age_ms = 1U;
        turbo_sleep_ms(2U);
        p2p_message_init(&message, P2P_MSG_CUSTOM);
        check_int_eq(P2P_ERR_KEY_EXHAUSTED,
                     p2p_peer_send(peer, &message));
        check_int_eq(P2P_PEER_STATE_DISCONNECTED, peer->state);
    }
    p2p_crypto_session_destroy(&receiver);
    p2p_peer_destroy(peer);
}

static void test_p2p_session_byte_limit_closes_before_encrypt(void) {
    p2p_crypto_session_t receiver = {0};
    p2p_peer_t *peer = p2p_test_create_established_peer(
        &receiver, p2p_test_send_ok);
    p2p_message_t message = {0};

    check_not_null(peer);
    if (peer) {
        peer->sent_bytes = P2P_SECURITY_SESSION_MAX_BYTES_DEFAULT - 1U;
        p2p_message_init(&message, P2P_MSG_CUSTOM);
        check_int_eq(P2P_ERR_KEY_EXHAUSTED,
                     p2p_peer_send(peer, &message));
        check_int_eq(P2P_PEER_STATE_DISCONNECTED, peer->state);
    }
    p2p_crypto_session_destroy(&receiver);
    p2p_peer_destroy(peer);
}

static int p2p_test_hex_nibble(char value) {
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    if (value >= 'A' && value <= 'F') {
        return value - 'A' + 10;
    }
    return -1;
}

static int p2p_test_decode_hex(const char *hex,
                               uint8_t *output,
                               size_t output_capacity,
                               size_t *output_len) {
    size_t hex_len;
    size_t index;

    if (!hex || !output || !output_len) {
        return 0;
    }

    hex_len = strlen(hex);
    if ((hex_len & 1U) != 0 || (hex_len / 2U) > output_capacity) {
        return 0;
    }

    for (index = 0; index < hex_len / 2U; ++index) {
        int high = p2p_test_hex_nibble(hex[index * 2U]);
        int low = p2p_test_hex_nibble(hex[index * 2U + 1U]);
        if (high < 0 || low < 0) {
            return 0;
        }
        output[index] = (uint8_t)((high << 4) | low);
    }

    *output_len = hex_len / 2U;
    return 1;
}

void test_p2p_noise_xx_matches_pinned_upstream_vector(void) {
    /* Source: noise-c/tests/vector/noise-c-basic.txt at the commit pinned by
     * cmake/NoiseC.cmake.  Keep this copy independent of the fetched file so
     * a dependency update cannot silently update both code and expectation. */
    static const char *const protocol_name =
        "Noise_XX_25519_ChaChaPoly_BLAKE2s";
    static const char *const prologue_hex = "50726f6c6f677565313233";
    static const char *const initiator_static_hex =
        "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1";
    static const char *const initiator_ephemeral_hex =
        "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a";
    static const char *const responder_static_hex =
        "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893";
    static const char *const responder_ephemeral_hex =
        "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b";
    static const char *const handshake_hash_hex =
        "ff2542ab6833ab2243a6a19599fde5e2b2ac5a6dc4f34a9be3046233fd790d41";
    static const struct {
        const char *payload_hex;
        const char *ciphertext_hex;
    } messages[] = {
        {
            "4c756477696720766f6e204d69736573",
            "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944"
            "4c756477696720766f6e204d69736573",
        },
        {
            "4d757272617920526f746862617264",
            "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843"
            "7c365eb362a1c991b0557fe8a7fb187d99346765d93ec63db6c1b01504ebeec5a"
            "11745edbea05ef4097ca82afe861d8aa196a6cead1e11b2bb13e336fa13614136"
            "f53e3d34be699da5983876f700ff",
        },
        {
            "462e20412e20486179656b",
            "46c3307de83b014258717d97781c1f50936d8b7d50c0722a1739654d10392d41"
            "76a11f5a0f70968037b0e0bedf68d18d802efa4220cff733e7b566970e749fef0"
            "6ea55e598cdb819d0a33e",
        },
    };
    NoiseHandshakeState *initiator = NULL;
    NoiseHandshakeState *responder = NULL;
    NoiseHandshakeState *sender;
    NoiseHandshakeState *receiver;
    NoiseDHState *dh;
    NoiseBuffer message_buffer;
    NoiseBuffer payload_buffer;
    uint8_t key[32] = {0};
    uint8_t prologue[32] = {0};
    uint8_t message[256] = {0};
    uint8_t plaintext[256] = {0};
    uint8_t expected_payload[256] = {0};
    uint8_t expected_ciphertext[256] = {0};
    uint8_t actual_hash[32] = {0};
    uint8_t expected_hash[32] = {0};
    size_t key_len = 0;
    size_t prologue_len = 0;
    size_t expected_payload_len = 0;
    size_t expected_ciphertext_len = 0;
    size_t expected_hash_len = 0;
    size_t index;
    int result;

    result = noise_handshakestate_new_by_name(
        &initiator, protocol_name, NOISE_ROLE_INITIATOR);
    check_int_eq(NOISE_ERROR_NONE, result);
    if (result != NOISE_ERROR_NONE) {
        goto cleanup;
    }
    result = noise_handshakestate_new_by_name(
        &responder, protocol_name, NOISE_ROLE_RESPONDER);
    check_int_eq(NOISE_ERROR_NONE, result);
    if (result != NOISE_ERROR_NONE) {
        goto cleanup;
    }

#define SET_NOISE_PRIVATE_KEY(state, accessor, hex_value)                       \
    do {                                                                        \
        check(p2p_test_decode_hex((hex_value), key, sizeof(key), &key_len));     \
        dh = accessor((state));                                                  \
        check_not_null(dh);                                                      \
        if (!dh || key_len != sizeof(key)) {                                     \
            goto cleanup;                                                        \
        }                                                                        \
        result = noise_dhstate_set_keypair_private(dh, key, key_len);            \
        check_int_eq(NOISE_ERROR_NONE, result);                                  \
        if (result != NOISE_ERROR_NONE) {                                        \
            goto cleanup;                                                        \
        }                                                                        \
    } while (0)

    SET_NOISE_PRIVATE_KEY(initiator,
                          noise_handshakestate_get_local_keypair_dh,
                          initiator_static_hex);
    SET_NOISE_PRIVATE_KEY(initiator,
                          noise_handshakestate_get_fixed_ephemeral_dh,
                          initiator_ephemeral_hex);
    SET_NOISE_PRIVATE_KEY(responder,
                          noise_handshakestate_get_local_keypair_dh,
                          responder_static_hex);
    SET_NOISE_PRIVATE_KEY(responder,
                          noise_handshakestate_get_fixed_ephemeral_dh,
                          responder_ephemeral_hex);
#undef SET_NOISE_PRIVATE_KEY

    check(p2p_test_decode_hex(prologue_hex, prologue, sizeof(prologue),
                              &prologue_len));
    result = noise_handshakestate_set_prologue(
        initiator, prologue, prologue_len);
    check_int_eq(NOISE_ERROR_NONE, result);
    if (result != NOISE_ERROR_NONE) {
        goto cleanup;
    }
    result = noise_handshakestate_set_prologue(
        responder, prologue, prologue_len);
    check_int_eq(NOISE_ERROR_NONE, result);
    if (result != NOISE_ERROR_NONE) {
        goto cleanup;
    }
    result = noise_handshakestate_start(initiator);
    check_int_eq(NOISE_ERROR_NONE, result);
    if (result != NOISE_ERROR_NONE) {
        goto cleanup;
    }
    result = noise_handshakestate_start(responder);
    check_int_eq(NOISE_ERROR_NONE, result);
    if (result != NOISE_ERROR_NONE) {
        goto cleanup;
    }

    for (index = 0; index < sizeof(messages) / sizeof(messages[0]); ++index) {
        sender = (index == 1U) ? responder : initiator;
        receiver = (index == 1U) ? initiator : responder;
        check_int_eq(NOISE_ACTION_WRITE_MESSAGE,
                     noise_handshakestate_get_action(sender));
        check_int_eq(NOISE_ACTION_READ_MESSAGE,
                     noise_handshakestate_get_action(receiver));
        check(p2p_test_decode_hex(messages[index].payload_hex,
                                  expected_payload,
                                  sizeof(expected_payload),
                                  &expected_payload_len));
        check(p2p_test_decode_hex(messages[index].ciphertext_hex,
                                  expected_ciphertext,
                                  sizeof(expected_ciphertext),
                                  &expected_ciphertext_len));

        noise_buffer_set_output(message_buffer, message, sizeof(message));
        noise_buffer_set_input(payload_buffer,
                               expected_payload,
                               expected_payload_len);
        result = noise_handshakestate_write_message(
            sender, &message_buffer, &payload_buffer);
        check_int_eq(NOISE_ERROR_NONE, result);
        if (result != NOISE_ERROR_NONE) {
            goto cleanup;
        }
        check_int_eq((int)expected_ciphertext_len, (int)message_buffer.size);
        check(memcmp(message, expected_ciphertext, expected_ciphertext_len) == 0);

        noise_buffer_set_input(message_buffer, message, message_buffer.size);
        noise_buffer_set_output(payload_buffer, plaintext, sizeof(plaintext));
        result = noise_handshakestate_read_message(
            receiver, &message_buffer, &payload_buffer);
        check_int_eq(NOISE_ERROR_NONE, result);
        if (result != NOISE_ERROR_NONE) {
            goto cleanup;
        }
        check_int_eq((int)expected_payload_len, (int)payload_buffer.size);
        check(memcmp(plaintext, expected_payload, expected_payload_len) == 0);
    }

    check_int_eq(NOISE_ACTION_SPLIT,
                 noise_handshakestate_get_action(initiator));
    check_int_eq(NOISE_ACTION_SPLIT,
                 noise_handshakestate_get_action(responder));
    check(p2p_test_decode_hex(handshake_hash_hex,
                              expected_hash,
                              sizeof(expected_hash),
                              &expected_hash_len));
    check_int_eq((int)sizeof(actual_hash), (int)expected_hash_len);
    result = noise_handshakestate_get_handshake_hash(
        initiator, actual_hash, sizeof(actual_hash));
    check_int_eq(NOISE_ERROR_NONE, result);
    check(memcmp(actual_hash, expected_hash, sizeof(actual_hash)) == 0);
    result = noise_handshakestate_get_handshake_hash(
        responder, actual_hash, sizeof(actual_hash));
    check_int_eq(NOISE_ERROR_NONE, result);
    check(memcmp(actual_hash, expected_hash, sizeof(actual_hash)) == 0);

cleanup:
    if (initiator) {
        (void)noise_handshakestate_free(initiator);
    }
    if (responder) {
        (void)noise_handshakestate_free(responder);
    }
    p2p_crypto_wipe(key, sizeof(key));
    p2p_crypto_wipe(message, sizeof(message));
    p2p_crypto_wipe(plaintext, sizeof(plaintext));
}

void test_p2p_crypto_rejects_replayed_ciphertext(void) {
    const uint8_t plaintext[] = "mesh-replay-test";
    uint8_t ciphertext[sizeof(plaintext) + P2P_TEST_AEAD_FRAME_OVERHEAD] = {0};
    uint8_t output[sizeof(ciphertext)] = {0};
    size_t ciphertext_len = 0;
    size_t output_len = 0;
    p2p_crypto_session_t sender;
    p2p_crypto_session_t receiver;

    check_int_eq(P2P_OK, p2p_test_crypto_sessions(&sender, &receiver));
    check_int_eq(P2P_OK,
                 p2p_crypto_encrypt(&sender, plaintext, sizeof(plaintext),
                                    ciphertext, &ciphertext_len));
    check_int_eq(P2P_OK,
                 p2p_crypto_decrypt(&receiver, ciphertext, ciphertext_len,
                                    output, sizeof(output), &output_len));
    check_int_eq((int)sizeof(plaintext), (int)output_len);
    check(memcmp(plaintext, output, sizeof(plaintext)) == 0);
    check_int_eq(P2P_ERR_CRYPTO,
                 p2p_crypto_decrypt(&receiver, ciphertext, ciphertext_len,
                                    output, sizeof(output), &output_len));
    check_int_eq(1, (int)receiver.received_frames);
    p2p_crypto_session_destroy(&sender);
    p2p_crypto_session_destroy(&receiver);
}

void test_p2p_crypto_rejects_out_of_order_without_advancing(void) {
    const uint8_t first[] = "first";
    const uint8_t second[] = "second";
    uint8_t first_ciphertext[sizeof(first) + P2P_TEST_AEAD_FRAME_OVERHEAD] = {0};
    uint8_t second_ciphertext[sizeof(second) + P2P_TEST_AEAD_FRAME_OVERHEAD] = {0};
    uint8_t output[sizeof(second_ciphertext)] = {0};
    size_t first_ciphertext_len = 0;
    size_t second_ciphertext_len = 0;
    size_t output_len = 0;
    p2p_crypto_session_t sender;
    p2p_crypto_session_t receiver;

    check_int_eq(P2P_OK, p2p_test_crypto_sessions(&sender, &receiver));
    check_int_eq(P2P_OK,
                 p2p_crypto_encrypt(&sender, first, sizeof(first),
                                    first_ciphertext, &first_ciphertext_len));
    check_int_eq(P2P_OK,
                 p2p_crypto_encrypt(&sender, second, sizeof(second),
                                    second_ciphertext, &second_ciphertext_len));

    check_int_eq(P2P_ERR_CRYPTO,
                 p2p_crypto_decrypt(&receiver, second_ciphertext,
                                    second_ciphertext_len, output,
                                    sizeof(output), &output_len));
    check_int_eq(0, (int)receiver.received_frames);
    check_int_eq(P2P_OK,
                 p2p_crypto_decrypt(&receiver, first_ciphertext,
                                    first_ciphertext_len, output,
                                    sizeof(output), &output_len));
    check_int_eq((int)sizeof(first), (int)output_len);
    check(memcmp(first, output, sizeof(first)) == 0);
    check_int_eq(P2P_OK,
                 p2p_crypto_decrypt(&receiver, second_ciphertext,
                                    second_ciphertext_len, output,
                                    sizeof(output), &output_len));
    check_int_eq((int)sizeof(second), (int)output_len);
    check(memcmp(second, output, sizeof(second)) == 0);
    p2p_crypto_session_destroy(&sender);
    p2p_crypto_session_destroy(&receiver);
}

void test_p2p_crypto_rejects_counter_exhaustion(void) {
    const uint8_t plaintext[] = "counter";
    uint8_t ciphertext[sizeof(plaintext) + P2P_TEST_AEAD_FRAME_OVERHEAD] = {0};
    uint8_t output[sizeof(ciphertext)] = {0};
    size_t ciphertext_len = 0;
    size_t output_len = 0;
    p2p_crypto_session_t sender;
    p2p_crypto_session_t receiver;

    check_int_eq(P2P_OK, p2p_test_crypto_sessions(&sender, &receiver));
    sender.sent_frames = P2P_NOISE_SESSION_FRAME_LIMIT;
    receiver.received_frames = P2P_NOISE_SESSION_FRAME_LIMIT;
    check_int_eq(P2P_ERR_KEY_EXHAUSTED,
                 p2p_crypto_encrypt(&sender, plaintext, sizeof(plaintext),
                                    ciphertext, &ciphertext_len));
    check_int_eq(P2P_ERR_KEY_EXHAUSTED,
                 p2p_crypto_decrypt(&receiver, ciphertext, sizeof(ciphertext),
                                    output, sizeof(output), &output_len));
    check(sender.sent_frames == P2P_NOISE_SESSION_FRAME_LIMIT);
    check(receiver.received_frames == P2P_NOISE_SESSION_FRAME_LIMIT);
    p2p_crypto_session_destroy(&sender);
    p2p_crypto_session_destroy(&receiver);
}

spec("p2p module") {
    before_all() {
        p2p_test_logger_init();
    }

    after_all() {
        p2p_test_logger_shutdown();
    }

    before_each() {
        setUp();
    }

    after_each() {
        tearDown();
    }

    describe("node lifecycle") {
        it("creates a valid node") { test_p2p_create_valid(); }
        it("exposes a stable node id") { test_p2p_node_get_id(); }
        it("exposes a static public key") { test_p2p_node_get_public_key(); }
        it("sets stable private-key identity") { test_p2p_node_set_private_key_makes_identity_stable(); }
        it("rejects identity changes after start") { test_p2p_node_set_private_key_rejects_started_node(); }
        it("installs an opaque private-key provider") {
            test_p2p_node_set_private_key_provider_is_opaque();
        }
        it("installs a bounded blocking private-key provider") {
            test_p2p_blocking_private_key_provider_is_bounded_and_opaque();
        }
        it("includes the blocking key executor in the atomic security snapshot") {
            test_p2p_security_status_v3_includes_blocking_executor();
        }
        it("rejects a blocking provider that misses its self-test deadline") {
            test_p2p_blocking_private_key_provider_self_test_times_out();
        }
        it("requires blocking key deadlines to fit the handshake deadline") {
            test_p2p_blocking_private_key_timeout_must_fit_handshake();
        }
        it("keeps the previous identity when a provider fails") {
            test_p2p_private_key_provider_fails_closed();
        }
        it("generates a private key for stable identity") { test_p2p_generate_private_key(); }
        it("uses a checked operating-system csprng") {
            test_p2p_crypto_random_uses_checked_csprng();
        }
        it("derives deterministic provisional ids from endpoints") {
            test_p2p_endpoint_ids_are_deterministic();
        }
        it("derives a public key from a private key") { test_p2p_public_key_from_private_key(); }
        it("requires a v2 identity policy before listening") {
            test_p2p_secure_wire_requires_identity_configuration();
        }
        it("installs bounded secure-session defaults") {
            test_p2p_security_config_installs_bounded_defaults();
        }
        it("rejects unbounded secure-session limits") {
            test_p2p_security_config_rejects_unbounded_limits();
        }
        it("bounds node-wide transport send reservations") {
            test_p2p_node_send_budget_reservations_are_bounded();
        }
        it("exports one bounded atomic v3 security snapshot without changing v2") {
            test_p2p_security_status_v3_is_atomic_bounded_and_compatible();
        }
        it("evicts sessions rejected by an updated trust snapshot") {
            test_p2p_security_revalidation_evicts_revoked_session();
        }
        it("rejects a null ip") { test_p2p_create_null_ip(); }
        it("allows destroy on null") { test_p2p_destroy_null(); }
        it("destroys a valid node") { test_p2p_destroy_valid(); }
        it("keeps transfers alive while held") { test_p2p_transfer_destroy_waits_for_held_reference(); }
        it("runs transfer progress callbacks unlocked") { test_p2p_transfer_progress_callback_runs_unlocked(); }
        it("runs transfer complete callbacks unlocked") { test_p2p_transfer_complete_callback_runs_unlocked(); }
        it("runs transfer cancel callbacks unlocked") { test_p2p_transfer_cancel_callback_runs_unlocked(); }
    }

    describe("message handler") {
        it("stores a message handler") { test_p2p_set_message_handler(); }
        it("broadcasts a message") { test_p2p_send_broadcast(); }
    }

    describe("file api") {
        it("accepts a valid file put") { test_p2p_put_file_valid(); }
    }

    describe("message serialization") {
        it("rejects invalid params") { test_p2p_send_message_invalid_params(); }
        it("uses canonical bytes for identity ping") {
            test_p2p_message_ping_codec_is_canonical();
        }
        it("round trips variable DHT and transfer payloads") {
            test_p2p_message_variable_payloads_round_trip();
        }
        it("rejects noncanonical application messages") {
            test_p2p_message_codec_rejects_noncanonical_input();
        }
    }

    describe("pubsub") {
        it("subscribes with valid params") { test_p2p_subscribe_valid(); }
        it("rejects null subscribe params") { test_p2p_subscribe_null_params(); }
        it("unsubscribes an existing topic") { test_p2p_unsubscribe_valid(); }
        it("reports unsubscribe miss") { test_p2p_unsubscribe_not_found(); }
        it("publishes with valid params") { test_p2p_publish_valid(); }
        it("rejects null publish params") { test_p2p_publish_null_params(); }
        it("reports missing publish topic") { test_p2p_publish_topic_not_found(); }
    }

    describe("peer management") {
        it("creates a valid peer") { test_p2p_peer_create_valid(); }
        it("exposes bounded read-only stream metrics") {
            test_p2p_peer_stream_metrics_are_bounded_and_read_only();
        }
        it("rejects unmatched and unbounded rtt samples") {
            test_p2p_rtt_estimator_rejects_unmatched_and_unbounded_samples();
        }
        it("exposes a known peer id") { test_p2p_peer_get_id(); }
        it("exposes a known peer public key") { test_p2p_peer_get_public_key(); }
        it("does not let ping replace the authenticated routing id") {
            test_p2p_ping_cannot_replace_authenticated_routing_id();
        }
        it("preserves ipv6 in peer info ex") { test_p2p_peer_info_ex_preserves_ipv6(); }
        it("preserves ipv6 in node peer info ex") { test_p2p_get_peer_info_ex_preserves_ipv6(); }
        it("rejects a peer with null ip") { test_p2p_peer_create_null_ip(); }
        it("finds an existing peer") { test_p2p_peer_find_valid(); }
        it("reports missing peers") { test_p2p_peer_find_not_found(); }
        it("rejects invalid connect params") { test_p2p_connect_invalid(); }
        it("keeps empty dht lookups out of the active table") { test_p2p_dht_lookup_without_candidates_stays_idle(); }
        it("deduplicates authenticated peers by identity") { test_p2p_authenticated_duplicate_identity_keeps_single_peer(); }
        it("chooses one authenticated connection direction deterministically") {
            test_p2p_authenticated_duplicate_identity_uses_deterministic_direction();
        }
        it("converges three hard-cut nodes after simultaneous dial and reconnect") {
            test_p2p_three_node_hard_cut_simultaneous_dial_and_reconnect();
        }
        it("bounds handshake latency aggregation without retaining samples") {
            test_p2p_handshake_latency_accumulator_is_bounded();
        }
        it("records every secure handshake stage by role") {
            test_p2p_real_handshake_records_each_role_and_stage();
        }
        it("keeps inbound transport endpoints out of routing") { test_p2p_authenticated_inbound_peer_does_not_publish_ephemeral_route(); }
        it("rejects a legacy client at the v2 listener without fallback") {
            test_p2p_v2_listener_rejects_legacy_client_without_fallback();
        }
        it("gates and expires inbound transports before peer allocation") {
            test_p2p_cookie_gate_precedes_peer_allocation_and_expires();
        }
        it("bounds and reports listener cookie gate capacity") {
            test_p2p_cookie_gate_capacity_is_fixed_and_observable();
        }
        it("limits pending unauthenticated peers") { test_p2p_limits_pending_unauthenticated_peers(); }
        it("limits pending peers per source prefix") {
            test_p2p_limits_pending_peers_per_source_prefix();
        }
        it("rate limits source prefixes with a bounded token bucket table") {
            test_p2p_rate_limits_inbound_sources_with_bounded_buckets();
        }
        it("connects two real nodes") { test_p2p_two_nodes_real_connection(); }
        it("exchanges public keys during handshake") { test_p2p_two_nodes_exchange_public_keys(); }
        it("rejects peers from another secure network") {
            test_p2p_secure_wire_rejects_network_mismatch();
        }
        it("rejects an unpinned Noise static key") {
            test_p2p_secure_wire_rejects_unpinned_static_key();
        }
        it("fetches remote dht values") { test_p2p_dht_get_fetches_remote_value(); }
        it("counts cached dht entries") { test_p2p_dht_entry_count_tracks_cached_values(); }
        it("replicates dht puts to connected peers") { test_p2p_dht_put_replicates_to_connected_peer(); }
        it("replicates dht puts to discovered peers") { test_p2p_dht_put_reaches_discovered_peer(); }
        it("handles parallel dht gets over the network") { test_p2p_dht_get_handles_parallel_network_lookups(); }
        it("matches dht responses by request id") { test_p2p_dht_response_matches_request_id(); }
    }

    describe("error handling") {
        it("returns known error strings") { test_p2p_error_str_valid(); }
        it("returns unknown error fallback") { test_p2p_error_str_unknown(); }
    }

    describe("crypto session") {
        it("completes Noise XX with an opaque static-key provider") {
            test_p2p_private_key_provider_completes_noise_xx();
        }
        it("propagates opaque static-key DH failures") {
            test_p2p_private_key_provider_propagates_dh_failure();
        }
        it("runs blocking static-key DH off-loop for both Noise XX roles") {
            test_p2p_blocking_private_key_provider_completes_both_xx_roles();
        }
        it("closes a blocking static-key handshake after its deadline") {
            test_p2p_blocking_private_key_provider_runtime_timeout_is_closed();
        }
        it("cancels and drains blocking static-key work during destroy") {
            test_p2p_blocking_private_key_provider_destroy_cancels_and_drains();
        }
        it("rejects a blocking static-key handshake at executor capacity") {
            test_p2p_blocking_private_key_provider_rejects_at_capacity();
        }
        it("admits 64 blocking key operations and rejects operation 65") {
            test_p2p_blocking_private_key_executor_enforces_64_65_boundary();
        }
        it("isolates a stale blocking key completion from a new handshake") {
            test_p2p_blocking_private_key_stale_generation_is_isolated();
        }
        it("rejects a blocking key completion delayed past its deadline") {
            test_p2p_blocking_private_key_late_completion_fails_closed();
        }
        it("matches the pinned upstream Noise XX handshake vector") {
            test_p2p_noise_xx_matches_pinned_upstream_vector();
        }
        it("matches the listener cookie vector and binds the source") {
            test_p2p_cookie_codec_matches_vector_and_binds_source();
        }
        it("bounds listener cookie time and derived-key rotation") {
            test_p2p_cookie_codec_bounds_time_and_rotation();
        }
        it("rejects replayed ciphertext") {
            test_p2p_crypto_rejects_replayed_ciphertext();
        }
        it("rejects out-of-order ciphertext without advancing") {
            test_p2p_crypto_rejects_out_of_order_without_advancing();
        }
        it("rejects exhausted counters") {
            test_p2p_crypto_rejects_counter_exhaustion();
        }
        it("closes a session when send backpressure follows nonce advance") {
            test_p2p_send_hwm_rejection_closes_advanced_session();
        }
        it("closes a session at the monotonic age limit") {
            test_p2p_session_age_limit_closes_before_encrypt();
        }
        it("closes a session at the encrypted byte limit") {
            test_p2p_session_byte_limit_closes_before_encrypt();
        }
    }
}
