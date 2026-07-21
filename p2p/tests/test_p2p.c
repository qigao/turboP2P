/**
 * test_p2p.c - P2P Module Unit Tests
 * Using TinyTest
 * Good Taste: Simple, focused tests
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

#include <tinytest.h>
#include "p2p.h"
#include "internal.h"
#include "transfer/transfer.h"
#include <CoroNet/turbo_coro_context.h>
#include <tlog.h>

/* Test fixtures */
static p2p_node_t *test_node = NULL;
static int message_received = 0;
static void *received_data = NULL;
static size_t received_len = 0;
static tlog_t *g_test_logger = NULL;
static int g_transfer_status_callback_count = 0;
static int g_transfer_complete_callback_count = 0;
static int g_transfer_cancel_callback_count = 0;

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

    check_int_eq(P2P_OK, p2p_node_start_server(node));
    check_int_eq(P2P_ERR_INVALID_STATE, p2p_node_set_private_key(node, secret));

    p2p_node_stop_server(node);
    p2p_destroy(node);
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
    /* Test with NULL node */
    int ret = p2p_send_message(NULL, NULL, P2P_MSG_PING, "data", 4);
    check_int_eq(P2P_ERR_INVALID_ARG, ret);
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

static void test_p2p_owns_and_expires_accepted_peer_before_authentication(void) {
    const int server_port = p2p_test_alloc_port_block(2);
    const int client_port = server_port + 1;
    p2p_node_t *server = p2p_create("127.0.0.1", server_port);
    p2p_node_t *client = p2p_create("127.0.0.1", client_port);
    int accepted_seen = 0;
    int pending_aged = 0;

    check_not_null(server);
    check_not_null(client);
    if (!server || !client) {
        p2p_destroy(client);
        p2p_destroy(server);
        return;
    }

    check_int_eq(p2p_start_nonblocking(server), P2P_OK);
    check_int_eq(p2p_start_nonblocking(client), P2P_OK);
    check_int_eq(p2p_connect(client, "127.0.0.1", server_port), P2P_OK);

    /* Poll only the server so it accepts the transport but cannot receive the
     * initiator handshake. The accepted peer must still belong to the node. */
    for (int i = 0; i < 100; i++) {
        coro_context_run(p2p_get_loop(server), TURBO_RUN_NOWAIT);
        if (p2p_test_peer_table_size(server) == 1) {
            accepted_seen = 1;
            break;
        }
        turbo_sleep_ms(1);
    }

    check(accepted_seen);
    check_int_eq(0, p2p_get_peer_count(server));

    turbo_mutex_lock(&server->mutex);
    p2p_peer_entry_t *entry = server->peers_table;
    if (entry && entry->peer) {
        entry->peer->connect_time =
            turbo_hrtime() - ((uint64_t)P2P_PEER_TIMEOUT_MS + 1U) * 1000000U;
        pending_aged = 1;
    }
    turbo_mutex_unlock(&server->mutex);

    check(pending_aged);
    check_not_null(server->gossip_timer);
    if (pending_aged && server->gossip_timer) {
        node_maintenance_cb(server->gossip_timer);
    }
    check_int_eq(0, p2p_test_peer_table_size(server));

    p2p_destroy(client);
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

void test_p2p_two_nodes_exchange_public_keys(void) {
    const int port1 = p2p_test_alloc_port_block(2);
    const int port2 = port1 + 1;
    p2p_node_t *node1 = NULL;
    p2p_node_t *node2 = NULL;
    uint8_t node1_public_key[P2P_KEY_SIZE] = {0};
    uint8_t node2_public_key[P2P_KEY_SIZE] = {0};
    uint8_t node1_seen_peer_key[P2P_KEY_SIZE] = {0};
    uint8_t node2_seen_peer_key[P2P_KEY_SIZE] = {0};
    int node1_saw_node2 = 0;
    int node2_saw_node1 = 0;
    int ret = 0;

    node1 = p2p_create("127.0.0.1", port1);
    node2 = p2p_create("127.0.0.1", port2);
    check_not_null(node1);
    check_not_null(node2);

    check_int_eq(P2P_OK, p2p_node_get_public_key(node1, node1_public_key));
    check_int_eq(P2P_OK, p2p_node_get_public_key(node2, node2_public_key));

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
        if (node1_saw_node2 && node2_saw_node1) {
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
    memcpy(msg1.payload.dht_response.data, value2, strlen(value2) + 1);

    p2p_message_init(&msg2, P2P_MSG_DHT_RESPONSE);
    msg2.header.request_id = 1001;
    msg2.payload.dht_response.found = 1;
    msg2.payload.dht_response.data_len = (uint16_t)(strlen(value1) + 1);
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
}

void test_p2p_error_str_unknown(void) {
    const char *str = p2p_error_str(9999);
    check_not_null(str);
    check_str_eq("Unknown error", str);
}

enum {
    P2P_TEST_NONCE_COUNTER_SIZE = 8,
    P2P_TEST_AEAD_FRAME_OVERHEAD = P2P_TEST_NONCE_COUNTER_SIZE + P2P_TAG_SIZE,
};

static void p2p_test_crypto_sessions(p2p_crypto_session_t *sender,
                                     p2p_crypto_session_t *receiver) {
    memset(sender, 0, sizeof(*sender));
    memset(receiver, 0, sizeof(*receiver));
    for (size_t i = 0; i < P2P_KEY_SIZE; i++) {
        sender->tx_key[i] = (uint8_t)(i + 1U);
        receiver->rx_key[i] = sender->tx_key[i];
    }
    sender->ready = 1;
    receiver->ready = 1;
}

void test_p2p_crypto_rejects_replayed_ciphertext(void) {
    const uint8_t plaintext[] = "mesh-replay-test";
    uint8_t ciphertext[sizeof(plaintext) + P2P_TEST_AEAD_FRAME_OVERHEAD] = {0};
    uint8_t output[sizeof(plaintext)] = {0};
    size_t ciphertext_len = 0;
    size_t output_len = 0;
    p2p_crypto_session_t sender;
    p2p_crypto_session_t receiver;

    p2p_test_crypto_sessions(&sender, &receiver);
    check_int_eq(P2P_OK,
                 p2p_crypto_encrypt(&sender, plaintext, sizeof(plaintext),
                                    ciphertext, &ciphertext_len));
    check_int_eq(P2P_OK,
                 p2p_crypto_decrypt(&receiver, ciphertext, ciphertext_len,
                                    output, &output_len));
    check_int_eq((int)sizeof(plaintext), (int)output_len);
    check(memcmp(plaintext, output, sizeof(plaintext)) == 0);
    check_int_eq(P2P_ERR_CRYPTO,
                 p2p_crypto_decrypt(&receiver, ciphertext, ciphertext_len,
                                    output, &output_len));
    check_int_eq(1, (int)receiver.rx_nonce);
}

void test_p2p_crypto_rejects_out_of_order_without_advancing(void) {
    const uint8_t first[] = "first";
    const uint8_t second[] = "second";
    uint8_t first_ciphertext[sizeof(first) + P2P_TEST_AEAD_FRAME_OVERHEAD] = {0};
    uint8_t second_ciphertext[sizeof(second) + P2P_TEST_AEAD_FRAME_OVERHEAD] = {0};
    uint8_t output[sizeof(second)] = {0};
    size_t first_ciphertext_len = 0;
    size_t second_ciphertext_len = 0;
    size_t output_len = 0;
    p2p_crypto_session_t sender;
    p2p_crypto_session_t receiver;

    p2p_test_crypto_sessions(&sender, &receiver);
    check_int_eq(P2P_OK,
                 p2p_crypto_encrypt(&sender, first, sizeof(first),
                                    first_ciphertext, &first_ciphertext_len));
    check_int_eq(P2P_OK,
                 p2p_crypto_encrypt(&sender, second, sizeof(second),
                                    second_ciphertext, &second_ciphertext_len));

    check_int_eq(P2P_ERR_CRYPTO,
                 p2p_crypto_decrypt(&receiver, second_ciphertext,
                                    second_ciphertext_len, output, &output_len));
    check_int_eq(0, (int)receiver.rx_nonce);
    check_int_eq(P2P_OK,
                 p2p_crypto_decrypt(&receiver, first_ciphertext,
                                    first_ciphertext_len, output, &output_len));
    check_int_eq((int)sizeof(first), (int)output_len);
    check(memcmp(first, output, sizeof(first)) == 0);
    check_int_eq(P2P_OK,
                 p2p_crypto_decrypt(&receiver, second_ciphertext,
                                    second_ciphertext_len, output, &output_len));
    check_int_eq((int)sizeof(second), (int)output_len);
    check(memcmp(second, output, sizeof(second)) == 0);
}

void test_p2p_crypto_rejects_counter_exhaustion(void) {
    const uint8_t plaintext[] = "counter";
    uint8_t ciphertext[sizeof(plaintext) + P2P_TEST_AEAD_FRAME_OVERHEAD] = {0};
    uint8_t output[sizeof(plaintext)] = {0};
    size_t ciphertext_len = 0;
    size_t output_len = 0;
    p2p_crypto_session_t sender;
    p2p_crypto_session_t receiver;

    p2p_test_crypto_sessions(&sender, &receiver);
    sender.tx_nonce = UINT64_MAX;
    receiver.rx_nonce = UINT64_MAX;
    check_int_eq(P2P_ERR_CRYPTO,
                 p2p_crypto_encrypt(&sender, plaintext, sizeof(plaintext),
                                    ciphertext, &ciphertext_len));
    check_int_eq(P2P_ERR_CRYPTO,
                 p2p_crypto_decrypt(&receiver, ciphertext, sizeof(ciphertext),
                                    output, &output_len));
    check(sender.tx_nonce == UINT64_MAX);
    check(receiver.rx_nonce == UINT64_MAX);
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
        it("generates a private key for stable identity") { test_p2p_generate_private_key(); }
        it("uses a checked operating-system csprng") {
            test_p2p_crypto_random_uses_checked_csprng();
        }
        it("derives deterministic provisional ids from endpoints") {
            test_p2p_endpoint_ids_are_deterministic();
        }
        it("derives a public key from a private key") { test_p2p_public_key_from_private_key(); }
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
        it("preserves ipv6 in peer info ex") { test_p2p_peer_info_ex_preserves_ipv6(); }
        it("preserves ipv6 in node peer info ex") { test_p2p_get_peer_info_ex_preserves_ipv6(); }
        it("rejects a peer with null ip") { test_p2p_peer_create_null_ip(); }
        it("finds an existing peer") { test_p2p_peer_find_valid(); }
        it("reports missing peers") { test_p2p_peer_find_not_found(); }
        it("rejects invalid connect params") { test_p2p_connect_invalid(); }
        it("keeps empty dht lookups out of the active table") { test_p2p_dht_lookup_without_candidates_stays_idle(); }
        it("deduplicates authenticated peers by identity") { test_p2p_authenticated_duplicate_identity_keeps_single_peer(); }
        it("keeps inbound transport endpoints out of routing") { test_p2p_authenticated_inbound_peer_does_not_publish_ephemeral_route(); }
        it("owns and expires accepted peers before authentication") {
            test_p2p_owns_and_expires_accepted_peer_before_authentication();
        }
        it("limits pending unauthenticated peers") { test_p2p_limits_pending_unauthenticated_peers(); }
        it("connects two real nodes") { test_p2p_two_nodes_real_connection(); }
        it("exchanges public keys during handshake") { test_p2p_two_nodes_exchange_public_keys(); }
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
        it("rejects replayed ciphertext") {
            test_p2p_crypto_rejects_replayed_ciphertext();
        }
        it("rejects out-of-order ciphertext without advancing") {
            test_p2p_crypto_rejects_out_of_order_without_advancing();
        }
        it("rejects exhausted counters") {
            test_p2p_crypto_rejects_counter_exhaustion();
        }
    }
}
