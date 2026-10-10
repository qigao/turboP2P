#include "p2p_cnet_node_fixture.h"
#include <cnet/sg_host.h>
#include "security/p2p_cookie.h"
#include <salts/native_io_sharded.h>
#include <stdio.h>

enum { HOST_SHARDS = 2u, HOST_BATCH = 16u, HOST_TIMEOUT = 10000u };

typedef struct sg_case sg_case;
typedef struct sg_lane {
    sg_case *test;
    size_t shard;
    native_io_sharded_host_lease lease;
    native_io_backend *backend;
    p2p_cnet_owner_t *acceptor;
    p2p_cnet_owner_t *transport;
    cnet_stream_peer listener;
    const void *worker_token;
    size_t observe_calls, observed, settled;
    unsigned cancelled, accepted;
    bool released;
    bool stopped;
    size_t stop_retries;
    cnet_client cohost_client;
    cnet_connection cohost_connection;
    size_t cohost_connected, cohost_sent, cohost_cookies, cohost_terminal;
    size_t cohost_cookie_bytes;
    uint8_t cohost_cookie[P2P_COOKIE_PACKET_SIZE];
    bool cohost_destroyed;
    int error;
    const char *error_site;
} sg_lane;

struct sg_case {
    native_io_sharded *runtime;
    p2p_cnet_sg_t *handoff;
    sg_lane lanes[HOST_SHARDS];
    endpoint_t client, server;
    bool with_cohost;
};

static native_io_backend_kind sg_backend(void) {
#if defined(_WIN32)
    return NATIVE_IO_BACKEND_IOCP;
#elif defined(__APPLE__)
    return NATIVE_IO_BACKEND_KQUEUE;
#else
    return NATIVE_IO_BACKEND_EPOLL;
#endif
}

static void mark_failed(sg_lane *lane, int rc) {
    if (lane->error == 0) lane->error = rc;
}
#define SG_GO(lane, statement) do { \
    int sg_rc_ = (statement); \
    if (sg_rc_ != 0) { \
        (lane)->error_site = #statement; \
        mark_failed((lane), sg_rc_); \
        return; \
    } \
} while (0)

static bool worker_quiescent(void *arg) {
    sg_lane *lane = (sg_lane *)arg;
    return lane->released && lane->acceptor == NULL &&
           lane->transport == NULL && !lane->cohost_client.impl;
}

static int accept_must_handoff(p2p_cnet_owner_t *owner,
                               p2p_connection_t *connection,
                               const cnet_stream_peer *source,
                               void *context) {
    sg_lane *lane = (sg_lane *)context;
    (void)owner; (void)connection; (void)source;
    ++lane->cancelled;
    return P2P_ERR_INVALID_STATE; /* This should never be selected. */
}

/* Distinct CNet consumer on the acceptor's SAME NativeIO SG shard.
 * Its own connection speaks only the real P2P cookie prefix to the separate
 * standalone P2P listener. Noise is deliberately not promoted; the main
 * cross-shard P2P session still authenticates independently. */
static void cohost_on_state(void *arg, cnet_connection handle,
                             cnet_connection_state state, const cnet_error *error) {
    sg_lane *lane = (sg_lane *)arg;
    (void)error;
    if (cmeta_thread_current_token() != lane->worker_token ||
        handle.slot != lane->cohost_connection.slot ||
        handle.generation != lane->cohost_connection.generation) {
        mark_failed(lane, SALTS_EPERM); return;
    }
    if (state == CNET_CONNECTION_CONNECTED) {
        uint8_t network[32];
        uint8_t preface[P2P_SECURE_PREFACE_SIZE];
        mem_buffer_t *buffer;
        memset(network, 9, sizeof(network));
        p2p_secure_preface_build(network, preface);
        buffer = mem_get_buffer(mem_global(), sizeof(preface));
        if (!buffer) { mark_failed(lane, SALTS_ENOMEM); return; }
        memcpy(mem_buffer_data(buffer), preface, sizeof(preface));
        mem_set_used(buffer, sizeof(preface));
        int rc = cnet_send_buffer(&lane->cohost_client, handle, buffer);
        mem_buffer_release(buffer);
        if (rc == SALTS_OK) rc = cnet_receive(&lane->cohost_client, handle, 1u);
        if (rc != SALTS_OK) mark_failed(lane, rc);
        ++lane->cohost_connected;
    } else if (state == CNET_CONNECTION_CLOSED ||
               state == CNET_CONNECTION_FAILED) {
        if (state == CNET_CONNECTION_FAILED) mark_failed(lane, SALTS_ECONNRESET);
        ++lane->cohost_terminal;
    }
}
static void cohost_on_receive(void *arg, cnet_connection handle,
                               const cnet_receive_view *view) {
    sg_lane *lane = (sg_lane *)arg;
    if (cmeta_thread_current_token() != lane->worker_token ||
        view == NULL || view->kind != CNET_MESSAGE_BYTES ||
        !view->data || !view->size ||
        view->size > sizeof(lane->cohost_cookie) - lane->cohost_cookie_bytes) {
        mark_failed(lane, SALTS_EPROTO); return;
    }
    memcpy(lane->cohost_cookie + lane->cohost_cookie_bytes,
           view->data, view->size);
    lane->cohost_cookie_bytes += view->size;
    if (lane->cohost_cookie_bytes == P2P_COOKIE_PACKET_SIZE) {
        uint8_t response[P2P_COOKIE_PACKET_SIZE];
        uint8_t binding[P2P_COOKIE_BINDING_SIZE];
        if (p2p_cookie_build_response(lane->cohost_cookie, response, binding) != P2P_OK) {
            mark_failed(lane, SALTS_EPROTO); return;
        }
        ++lane->cohost_cookies;
        int rc = cnet_close(&lane->cohost_client, handle);
        if (rc != SALTS_OK) mark_failed(lane, rc);
    } else {
        int rc = cnet_receive(&lane->cohost_client, handle, 1u);
        if (rc != SALTS_OK) mark_failed(lane, rc);
    }
}
static void cohost_on_send(void *arg, cnet_connection handle, size_t bytes) {
    sg_lane *lane = (sg_lane *)arg;
    if (cmeta_thread_current_token() != lane->worker_token ||
        handle.slot != lane->cohost_connection.slot ||
        bytes != P2P_SECURE_PREFACE_SIZE) {
        mark_failed(lane, SALTS_EPROTO); return;
    }
    lane->cohost_sent += bytes;
}
static cnet_observer cohost_observer(sg_lane *lane) {
    cnet_observer cb = {0};
    cb.on_state = cohost_on_state;
    cb.on_receive = cohost_on_receive;
    cb.on_send = cohost_on_send;
    cb.user = lane;
    return cb;
}

static void host_initialize(native_io_sharded_context *context, void *arg) {
    sg_lane *lane = (sg_lane *)arg;
    sg_case *test = lane->test;
    p2p_cnet_config_t cfg = config(7u);
    if (native_io_sharded_context_shard(context) != lane->shard) {
        mark_failed(lane, SALTS_EPERM); return;
    }
    lane->worker_token = cmeta_thread_current_token();
    SG_GO(lane, native_io_sharded_context_acquire_host(
        context, worker_quiescent, lane, &lane->lease, &lane->backend));
    if (lane->shard == 0u) {
        SG_GO(lane, p2p_cnet_owner_create_external(
            &cfg, lane->backend, lane->lease, &lane->acceptor));
        if (p2p_cnet_owner_poll(lane->acceptor) != P2P_ERR_INVALID_STATE) {
            mark_failed(lane, P2P_ERR_INVALID_STATE);
            return;
        }
        SG_GO(lane, p2p_cnet_owner_listen(lane->acceptor, "127.0.0.1",
            0u, 8u, accept_must_handoff, lane, &lane->listener));
        if (test->with_cohost) {
            cnet_stream_peer remote = {0};
            cnet_observer cb = cohost_observer(lane);
            remote.family = CNET_DATAGRAM_ADDRESS_IPV4;
            remote.address[0] = 127u;
            remote.address[3] = 1u;
            remote.port = (uint16_t)test->client.node->port;
            SG_GO(lane, cnet_client_init_external(&lane->cohost_client,
                                                  &cfg.client, lane->backend));
            SG_GO(lane, cnet_connect_peer(&lane->cohost_client, &remote,
                                          NULL, &cb, &lane->cohost_connection));
        }
    } else {
        endpoint_t *server = &test->server;
        init_node(server, 33, 0);
        p2p_set_peer_callbacks(server->node, on_connected,
                                on_disconnected, server);
        p2p_set_message_handler(server->node, on_message, server);
        SG_GO(lane, p2p_node_cnet_create_external(
            server->node, &cfg, lane->backend, lane->lease,
            &server->owner));
        SG_GO(lane, p2p_node_cnet_bind_handoff_accept(server->owner));
        if (p2p_poll(server->node) != P2P_ERR_INVALID_STATE) {
            mark_failed(lane, P2P_ERR_INVALID_STATE);
            return;
        }
        lane->transport = p2p_node_cnet_transport_owner(server->owner);
        if (!lane->transport) mark_failed(lane, P2P_ERR_INVALID_STATE);
    }
}

static void host_progress(native_io_sharded_context *context, void *arg) {
    sg_lane *lane = (sg_lane *)arg;
    sg_case *test = lane->test;
    size_t observed = 0u, settled = 0u;
    int status;
    if (lane->error || lane->stopped) return;
    if (native_io_sharded_context_shard(context) != lane->shard ||
        cmeta_thread_current_token() != lane->worker_token) {
        mark_failed(lane, SALTS_EPERM);
        return;
    }
    /* Must reject even a valid lease from the WRONG owner before executing
     * an external CNet progression or stealing any SG completion. */
    if (lane->shard == 0u && !lane->accepted && test->lanes[1].transport) {
        status = p2p_cnet_owner_poll_sg_host(test->lanes[1].transport,
            context, lane->lease, &observed, &settled);
        if (status != P2P_ERR_INVALID_STATE) {
            mark_failed(lane, P2P_ERR_INVALID_STATE);
            return;
        }
        ++lane->accepted;
    }
    if (lane->shard == 0u) {
        if (test->with_cohost && !lane->cohost_destroyed) {
            cnet_client *other[1] = {&lane->cohost_client};
            SG_GO(lane, p2p_cnet_owner_poll_sg_host_cohosts(
                lane->acceptor, context, lane->lease,
                other, 1u, &observed, &settled));
        } else {
            SG_GO(lane, p2p_cnet_owner_poll_sg_host(
                lane->acceptor, context, lane->lease, &observed, &settled));
        }
    } else if (lane->stop_retries) {
        /* P2P node stop has detached application callbacks. SG Host must
         * still drive the borrowed CNet terminal before destroy/retry. */
        SG_GO(lane, p2p_cnet_owner_poll_sg_host(
            lane->transport, context, lane->lease, &observed, &settled));
    } else {
        SG_GO(lane, p2p_node_cnet_poll_sg_host(
            test->server.owner, context, lane->lease, &observed, &settled));
    }
    ++lane->observe_calls;
    lane->observed += observed;
    lane->settled += settled;
}

static void host_stop(native_io_sharded_context *context, void *arg) {
    sg_lane *lane = (sg_lane *)arg;
    int result;
    if (native_io_sharded_context_shard(context) != lane->shard) {
        mark_failed(lane, SALTS_EPERM); return;
    }
    if (lane->stopped) return;
    if (lane->shard == 0u && lane->test->with_cohost &&
        !lane->cohost_destroyed) {
        if (lane->cohost_terminal == 0u) {
            ++lane->stop_retries;
            return; /* Other client still owns CNet callbacks. */
        }
        SG_GO(lane, cnet_client_stop_external(&lane->cohost_client));
        SG_GO(lane, cnet_client_destroy(&lane->cohost_client));
        lane->cohost_destroyed = true;
    }
    result = lane->shard == 0u
        ? p2p_cnet_owner_stop(lane->acceptor)
        : p2p_node_cnet_stop(lane->test->server.owner);
    if (result == P2P_ERR_INVALID_STATE) {
        /* A canceled external NativeIO accept/connection may still hold a
         * host-owned terminal. This is a REQUIRED observe/retry condition,
         * not permission to free the CNet client/SG host lease early. */
        ++lane->stop_retries;
        return;
    }
    if (result != P2P_OK) {
        lane->error_site = "SG Host owner stop";
        mark_failed(lane, result);
        return;
    }
    lane->stopped = true;
}

static void host_destroy(native_io_sharded_context *context, void *arg) {
    sg_lane *lane = (sg_lane *)arg;
    if (native_io_sharded_context_shard(context) != lane->shard) {
        mark_failed(lane, SALTS_EPERM); return;
    }
    if (lane->shard == 0u) {
        SG_GO(lane, p2p_cnet_owner_destroy(lane->acceptor));
        lane->acceptor = NULL;
    } else {
        SG_GO(lane, p2p_node_cnet_destroy(lane->test->server.owner));
        lane->transport = NULL;
        lane->test->server.owner = NULL;
        SG_GO(lane, p2p_node_state_destroy(lane->test->server.node));
        lane->test->server.node = NULL;
    }
    lane->released = true;
    SG_GO(lane, native_io_sharded_context_release_host(
        context, lane->lease));
    lane->backend = NULL;
}

static void submit_lane(sg_case *test, size_t shard,
                        native_io_sharded_task_fn task) {
    native_io_sharded_task command = {task, NULL, NULL, &test->lanes[shard]};
    check_equal(SALTS_OK, native_io_sharded_submit_to(
        test->runtime, shard, &command));
}
static void barrier(sg_case *test) {
    check_equal(SALTS_OK, native_io_sharded_wait(test->runtime));
    for (size_t i = 0u; i < HOST_SHARDS; ++i) {
        if (test->lanes[i].error)
            fprintf(stderr,
                "SG Host shard=%zu rc=%d at %s observed=%zu progress=%zu\\n",
                i, test->lanes[i].error,
                test->lanes[i].error_site ? test->lanes[i].error_site : "(direct)",
                test->lanes[i].observed, test->lanes[i].observe_calls);
        check_equal(0, test->lanes[i].error);
    }
}
static void progress_once(sg_case *test) {
    check_equal(P2P_OK, p2p_poll(test->client.node));
    for (size_t i = 0u; i < HOST_SHARDS; ++i)
        submit_lane(test, i, host_progress);
    barrier(test);
    cmeta_sleep_ms(1u);
}

static void host_send(native_io_sharded_context *context, void *arg);

static void test_real_sg_host_handoff_authenticated_p2p(bool with_cohost) {
    sg_case fixture = {0};
    sg_case *test = &fixture;
    native_io_sharded_config cfg = {HOST_SHARDS, 8u,
        {sg_backend(), 64u, 128u, HOST_BATCH}};
    const uint64_t deadline = cmeta_monotonic_ms() + HOST_TIMEOUT;
    p2p_cnet_sg_config_v1_t topology = {0};
    p2p_cnet_sg_snapshot_v1_t before = {0}, after = {0};

    test->client.remote = &test->server;
    test->server.remote = &test->client;
    test->with_cohost = with_cohost;
    /* The extra CNet cohost connects to the already-live standalone P2P
     * listener; no second backend is created on the SG acceptor shard. */
    init_endpoint(&test->client, 17, 7u, 0);
    check_equal(SALTS_OK, native_io_sharded_create(&cfg, &test->runtime));
    check_not_null(test->runtime);
    for (size_t i = 0u; i < HOST_SHARDS; ++i) {
        test->lanes[i].test = test;
        test->lanes[i].shard = i;
        submit_lane(test, i, host_initialize);
    }
    barrier(test);
    check_true(test->lanes[0].worker_token != NULL);
    check_true(test->lanes[1].worker_token != NULL);
    check_true(test->lanes[0].worker_token != test->lanes[1].worker_token);
    check_true(test->lanes[0].backend != test->lanes[1].backend);
    check_true(test->lanes[0].lease.owner_identity ==
               test->lanes[1].lease.owner_identity);
    check_equal((uint32_t)0u, test->lanes[0].lease.owner_shard);
    check_equal((uint32_t)1u, test->lanes[1].lease.owner_shard);
    check_true(test->lanes[0].listener.port != 0u);

    topology.size = sizeof(topology);
    topology.version = P2P_CNET_SG_VERSION;
    topology.acceptor = test->lanes[0].acceptor;
    topology.final_owners[0] = test->lanes[1].transport;
    topology.final_owner_count = 1u;
    topology.placement = CNET_OWNER_PLACE_EXPLICIT;
    topology.queue_capacity = 2u;
    topology.connection_capacity = 4u;
    check_equal(P2P_OK, p2p_cnet_sg_create_v1(&topology, &test->handoff));
    check_not_null(test->handoff);
    check_equal(P2P_OK, p2p_connect(
        test->client.node, "127.0.0.1", test->lanes[0].listener.port));

    while ((!test->client.authenticated || !test->server.authenticated) &&
           cmeta_monotonic_ms() < deadline)
        progress_once(test);
    check_equal(1, test->client.authenticated);
    check_equal(1, test->server.authenticated);
    check_equal(0, test->client.failures);
    check_equal(0, test->server.failures);
    check_true(test->lanes[0].observe_calls > 0u);
    check_true(test->lanes[1].observe_calls > 0u);
    check_true(test->lanes[0].observed > 0u);
    check_true(test->lanes[1].observed > 0u);
    check_equal((unsigned)0u, test->lanes[0].cancelled);
    check_equal((unsigned)1u, test->lanes[0].accepted);
    check_equal(P2P_OK, p2p_cnet_sg_snapshot_v1(
        test->handoff, 0u, &before));
    check_equal((uint64_t)1u, before.routed);
    check_equal((uint64_t)0u, before.denied);
    check_equal((size_t)1u, before.handoff.taken);
    check_equal((size_t)0u, before.handoff.queued);

    if (with_cohost) {
        const uint64_t cohost_deadline = cmeta_monotonic_ms() + HOST_TIMEOUT;
        while ((test->lanes[0].cohost_cookies == 0u ||
                test->lanes[0].cohost_terminal == 0u) &&
               cmeta_monotonic_ms() < cohost_deadline)
            progress_once(test);
        check_equal((size_t)1u, test->lanes[0].cohost_connected);
        check_equal((size_t)P2P_SECURE_PREFACE_SIZE,
                    test->lanes[0].cohost_sent);
        check_equal((size_t)P2P_COOKIE_PACKET_SIZE,
                    test->lanes[0].cohost_cookie_bytes);
        check_equal((size_t)1u, test->lanes[0].cohost_cookies);
        check_equal((size_t)1u, test->lanes[0].cohost_terminal);
        check_true(test->lanes[0].observed > 0u);
        check_equal((unsigned)0u, test->lanes[0].cancelled);
    }

    check_equal(P2P_OK, p2p_send_message(test->client.node,
        test->client.peer, P2P_MSG_CUSTOM, "client", 7u));
    submit_lane(test, 1u, host_send);
    barrier(test);
    const uint64_t exchange_deadline = cmeta_monotonic_ms() + HOST_TIMEOUT;
    while ((!test->client.messages || !test->server.messages) &&
           cmeta_monotonic_ms() < exchange_deadline)
        progress_once(test);
    check_equal(1, test->client.messages);
    check_equal(1, test->server.messages);
    check_equal((size_t)7u, test->client.received_len);
    check_equal((size_t)7u, test->server.received_len);
    check_equal(test->server.received, "client", 7u);
    check_equal(test->client.received, "server", 7u);

    p2p_peer_disconnect(test->client.peer);
    const uint64_t drain_deadline = cmeta_monotonic_ms() + HOST_TIMEOUT;
    do {
        progress_once(test);
        check_equal(P2P_OK, p2p_cnet_sg_snapshot_v1(
            test->handoff, 0u, &after));
        if (after.handoff.taken == 0u && test->server.disconnected) break;
    } while (cmeta_monotonic_ms() < drain_deadline);
    check_equal((size_t)0u, after.handoff.taken);
    check_equal((size_t)0u, after.handoff.queued);
    check_true(test->server.disconnected > 0);
    check_equal((size_t)0u, p2p_cnet_owner_connection_count(
        test->lanes[1].transport));

    check_equal(P2P_OK, p2p_cnet_sg_seal_v1(test->handoff));
    for (size_t i = 0u; i < HOST_SHARDS; ++i)
        submit_lane(test, i, host_stop);
    barrier(test);
    const uint64_t stop_deadline = cmeta_monotonic_ms() + HOST_TIMEOUT;
    while ((!test->lanes[0].stopped || !test->lanes[1].stopped) &&
           cmeta_monotonic_ms() < stop_deadline) {
        for (size_t i = 0u; i < HOST_SHARDS; ++i)
            if (!test->lanes[i].stopped)
                submit_lane(test, i, host_progress);
        barrier(test);
        for (size_t i = 0u; i < HOST_SHARDS; ++i)
            if (!test->lanes[i].stopped)
                submit_lane(test, i, host_stop);
        barrier(test);
        cmeta_sleep_ms(1u);
    }
    check_true(test->lanes[0].stopped);
    check_true(test->lanes[1].stopped);
    /* Some backends settle the canceled accept synchronously and need zero
     * retries; asynchronous backends must continue the SAME Host observe. */
    check_equal(P2P_ERR_INVALID_STATE,
                p2p_cnet_owner_destroy(test->lanes[0].acceptor));
    check_equal(P2P_OK, p2p_cnet_sg_destroy_v1(test->handoff));
    test->handoff = NULL;
    for (size_t i = 0u; i < HOST_SHARDS; ++i)
        submit_lane(test, i, host_destroy);
    barrier(test);
    for (size_t i = 0u; i < HOST_SHARDS; ++i) {
        check_true(test->lanes[i].released);
        check_true(test->lanes[i].backend == NULL);
    }
    check_equal(SALTS_OK, native_io_sharded_shutdown(test->runtime));
    check_equal(SALTS_OK, native_io_sharded_destroy(test->runtime));
    test->runtime = NULL;

    check_equal(P2P_OK, p2p_node_cnet_destroy(test->client.owner));
    check_equal(P2P_OK, p2p_node_state_destroy(test->client.node));
}

static void host_send(native_io_sharded_context *context, void *arg) {
    sg_lane *lane = (sg_lane *)arg;
    if (native_io_sharded_context_shard(context) != 1u ||
        cmeta_thread_current_token() != lane->worker_token ||
        !lane->test->server.peer) {
        mark_failed(lane, SALTS_EPERM);
        return;
    }
    SG_GO(lane, p2p_send_message(lane->test->server.node,
        lane->test->server.peer, P2P_MSG_CUSTOM, "server", 7u));
}

spec("P2P SG NativeIO hosted Owner with real credited P2P authentication") {
    it("routes one SG-observed batch per shard and exchanges authenticated data after credit handoff") {
        test_real_sg_host_handoff_authenticated_p2p(false);
    }
    it("cohosts an independent CNet Client on the acceptor shard without stealing P2P completions") {
        test_real_sg_host_handoff_authenticated_p2p(true);
    }
}
