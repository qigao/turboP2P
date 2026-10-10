/* Experimental only: real SG Host P2P Noise echo; results are not
 * equal-load scaling claims (1/2/4 shards host 1/1/3 sessions). */
#define _POSIX_C_SOURCE 200809L
#include "p2p_cnet_node_fixture.h"
#include <time.h>
#include <errno.h>
#include <inttypes.h>

#include <cnet/sg_host.h>
#include <salts/native_io_sharded.h>

#include <stdio.h>

/* Unlike the 4-Owner direct-polling fixture, every P2P final Owner below is
 * constructed, progressed and retired ON its NativeIO SG backend worker. A
 * single acceptor on shard 0 transfers real TCP descriptors by credited CNet
 * handoff. Clients are deliberately independent standalone P2P nodes. */
#if !defined(BENCH_SG_SHARDS) || \
    (BENCH_SG_SHARDS != 1 && BENCH_SG_SHARDS != 2 && BENCH_SG_SHARDS != 4)
#error "BENCH_SG_SHARDS must be 1, 2 or 4"
#endif
enum {
    SG4_SHARDS = BENCH_SG_SHARDS,
    SG4_FINALS = BENCH_SG_SHARDS == 1 ? 1u : BENCH_SG_SHARDS - 1u,
    SG4_BATCH = 16u,
    SG4_TIMEOUT_MS = 12000u
};
static size_t sg4_final_shard(size_t index) {
    return SG4_SHARDS == 1 ? 0u : index + 1u;
}
static size_t sg4_server_index(size_t shard) {
    return SG4_SHARDS == 1 ? 0u : shard - 1u;
}

typedef struct sg4_case sg4_case;
typedef struct sg4_lane {
    sg4_case *scenario;
    size_t shard;
    native_io_sharded_host_lease lease;
    native_io_backend *backend;
    p2p_cnet_owner_t *acceptor;
    p2p_cnet_owner_t *final_transport;
    cnet_stream_peer listener;
    const void *worker_token;
    size_t turns;
    size_t observed;
    size_t settled;
    unsigned wrong_owner_rejections;
    unsigned unwanted_local_accepts;
    size_t stop_retries;
    int stopped;
    int released;
    int error;
    const char *failed_at;
} sg4_lane;

typedef struct sg4_server {
    endpoint_t endpoint; /* Fixture identity and callback context, first. */
    sg4_lane *lane;
    unsigned owner_connected, owner_messages, owner_disconnected;
} sg4_server;

struct sg4_case {
    native_io_sharded *runtime;
    p2p_cnet_sg_t *handoff;
    sg4_lane lanes[SG4_SHARDS];
    sg4_server servers[SG4_FINALS];
    endpoint_t clients[SG4_FINALS];
};

static native_io_backend_kind sg4_backend(void) {
#if defined(_WIN32)
    return NATIVE_IO_BACKEND_IOCP;
#elif defined(__APPLE__)
    return NATIVE_IO_BACKEND_KQUEUE;
#else
    return NATIVE_IO_BACKEND_EPOLL;
#endif
}

static void sg4_error(sg4_lane *lane, int error, const char *site) {
    if (lane->error == 0) {
        lane->error = error;
        lane->failed_at = site;
    }
}

#define SG4_CALL(lane, expression) do {                                \
    int sg4_status_ = (expression);                                    \
    if (sg4_status_ != 0) {                                            \
        sg4_error((lane), sg4_status_, #expression);                   \
        return;                                                        \
    }                                                                 \
} while (0)

static int sg4_affinity(sg4_server *server) {
    return cmeta_thread_current_token() == server->lane->worker_token;
}

static void sg4_connected(p2p_peer_t *peer, void *context) {
    sg4_server *server = (sg4_server *)context;
    check_true(sg4_affinity(server));
    ++server->owner_connected;
    on_connected(peer, &server->endpoint);
}

static void sg4_disconnected(p2p_peer_t *peer, void *context) {
    sg4_server *server = (sg4_server *)context;
    check_true(sg4_affinity(server));
    ++server->owner_disconnected;
    on_disconnected(peer, &server->endpoint);
}

static void sg4_message(p2p_node_t *node, p2p_peer_t *peer,
                        const void *data, size_t length, void *context) {
    sg4_server *server = (sg4_server *)context;
    check_true(sg4_affinity(server));
    ++server->owner_messages;
    on_message(node, peer, data, length, &server->endpoint);
}

static bool sg4_quiescent(void *context) {
    sg4_lane *lane = (sg4_lane *)context;
    return lane->released && lane->acceptor == NULL &&
           lane->final_transport == NULL;
}

static int sg4_unselected_accept(p2p_cnet_owner_t *owner,
                                  p2p_connection_t *connection,
                                  const cnet_stream_peer *remote,
                                  void *context) {
    sg4_lane *lane = (sg4_lane *)context;
    (void)owner;
    (void)connection;
    (void)remote;
    ++lane->unwanted_local_accepts;
    return P2P_ERR_INVALID_STATE;
}

static void sg4_init(native_io_sharded_context *context, void *arg) {
    sg4_lane *lane = (sg4_lane *)arg;
    sg4_case *scenario = lane->scenario;
    p2p_cnet_config_t settings = config(7u);
    if (native_io_sharded_context_shard(context) != lane->shard) {
        sg4_error(lane, SALTS_EPERM, "init owner shard");
        return;
    }
    lane->worker_token = cmeta_thread_current_token();
    SG4_CALL(lane, native_io_sharded_context_acquire_host(
        context, sg4_quiescent, lane, &lane->lease, &lane->backend));
    if (SG4_SHARDS != 1 && lane->shard == 0u) {
        SG4_CALL(lane, p2p_cnet_owner_create_external(
            &settings, lane->backend, lane->lease, &lane->acceptor));
        SG4_CALL(lane, p2p_cnet_owner_listen(
            lane->acceptor, "127.0.0.1", 0u, 8u,
            sg4_unselected_accept, lane, &lane->listener));
    } else {
        sg4_server *server = &scenario->servers[sg4_server_index(lane->shard)];
        server->lane = lane;
        init_node(&server->endpoint, 41 + (int)lane->shard * 2, 0);
        p2p_set_peer_callbacks(server->endpoint.node,
                               sg4_connected, sg4_disconnected, server);
        p2p_set_message_handler(server->endpoint.node, sg4_message, server);
        SG4_CALL(lane, p2p_node_cnet_create_external(
            server->endpoint.node, &settings, lane->backend, lane->lease,
            &server->endpoint.owner));
        if (SG4_SHARDS == 1) {
            SG4_CALL(lane, p2p_node_cnet_listen(server->endpoint.owner));
            lane->listener.port = (uint16_t)server->endpoint.node->port;
        } else {
            SG4_CALL(lane,
                p2p_node_cnet_bind_handoff_accept(server->endpoint.owner));
        }
        lane->final_transport =
            p2p_node_cnet_transport_owner(server->endpoint.owner);
        if (lane->final_transport == NULL)
            sg4_error(lane, P2P_ERR_INVALID_STATE, "final owner");
    }
}

static void sg4_progress(native_io_sharded_context *context, void *arg) {
    sg4_lane *lane = (sg4_lane *)arg;
    size_t observed = 0u, settled = 0u;
    int status;
    if (lane->error || lane->stopped) return;
    if (native_io_sharded_context_shard(context) != lane->shard ||
        cmeta_thread_current_token() != lane->worker_token) {
        sg4_error(lane, SALTS_EPERM, "wrong SG worker affinity");
        return;
    }
    if (lane->wrong_owner_rejections == 0u) {
        /* Incorrect host-lease generation or shard must be rejected BEFORE
         * any observe/completion, not treated as an empty progress turn. */
        native_io_sharded_host_lease bad = lane->lease;
        bad.generation++;
        status = p2p_cnet_owner_poll_sg_host(
            lane->acceptor ? lane->acceptor : lane->final_transport,
            context, bad, &observed, &settled);
        if (status != P2P_ERR_INVALID_STATE || observed || settled) {
            sg4_error(lane, P2P_ERR_INVALID_STATE, "foreign host lease");
            return;
        }
        ++lane->wrong_owner_rejections;
    }
    if (lane->acceptor) {
        SG4_CALL(lane, p2p_cnet_owner_poll_sg_host(
            lane->acceptor, context, lane->lease, &observed, &settled));
    } else if (lane->stop_retries != 0u) {
        SG4_CALL(lane, p2p_cnet_owner_poll_sg_host(
            lane->final_transport, context, lane->lease, &observed, &settled));
    } else {
        sg4_server *server = &lane->scenario->servers[sg4_server_index(lane->shard)];
        SG4_CALL(lane, p2p_node_cnet_poll_sg_host(
            server->endpoint.owner, context, lane->lease, &observed, &settled));
    }
    ++lane->turns;
    lane->observed += observed;
    lane->settled += settled;
}

static void sg4_send(native_io_sharded_context *context, void *arg) {
    sg4_lane *lane = (sg4_lane *)arg;
    sg4_server *server = &lane->scenario->servers[sg4_server_index(lane->shard)];
    char reply[8] = {'r','e','p','l','y','-',(char)('0' + lane->shard),'\0'};
    if (native_io_sharded_context_shard(context) != lane->shard ||
        cmeta_thread_current_token() != lane->worker_token ||
        !server->endpoint.peer) {
        sg4_error(lane, P2P_ERR_INVALID_STATE, "server outbound affinity");
        return;
    }
    SG4_CALL(lane, p2p_send_message(
        server->endpoint.node, server->endpoint.peer,
        P2P_MSG_CUSTOM, reply, sizeof(reply)));
}

static void sg4_stop(native_io_sharded_context *context, void *arg) {
    sg4_lane *lane = (sg4_lane *)arg;
    int status;
    if (native_io_sharded_context_shard(context) != lane->shard) {
        sg4_error(lane, SALTS_EPERM, "stop shard");
        return;
    }
    if (lane->stopped) return;
    status = lane->acceptor
        ? p2p_cnet_owner_stop(lane->acceptor)
        : p2p_node_cnet_stop(
            lane->scenario->servers[sg4_server_index(lane->shard)].endpoint.owner);
    if (status == P2P_ERR_INVALID_STATE) {
        /* Canceled external accepts/CNet requests must be observed by this
         * SG worker, then stop retried. No forced context/lease release. */
        ++lane->stop_retries;
        return;
    }
    if (status != P2P_OK) {
        sg4_error(lane, status, "stop");
        return;
    }
    lane->stopped = 1;
}

static void sg4_destroy(native_io_sharded_context *context, void *arg) {
    sg4_lane *lane = (sg4_lane *)arg;
    if (native_io_sharded_context_shard(context) != lane->shard ||
        cmeta_thread_current_token() != lane->worker_token) {
        sg4_error(lane, SALTS_EPERM, "destroy affinity");
        return;
    }
    if (lane->acceptor) {
        SG4_CALL(lane, p2p_cnet_owner_destroy(lane->acceptor));
        lane->acceptor = NULL;
    } else {
        sg4_server *server = &lane->scenario->servers[sg4_server_index(lane->shard)];
        SG4_CALL(lane, p2p_node_cnet_destroy(server->endpoint.owner));
        server->endpoint.owner = NULL;
        lane->final_transport = NULL;
        SG4_CALL(lane, p2p_node_state_destroy(server->endpoint.node));
        server->endpoint.node = NULL;
    }
    lane->released = 1;
    SG4_CALL(lane, native_io_sharded_context_release_host(context, lane->lease));
    lane->backend = NULL;
}

static void sg4_submit(sg4_case *scenario, size_t shard,
                       native_io_sharded_task_fn fn) {
    native_io_sharded_task task = {fn, NULL, NULL, &scenario->lanes[shard]};
    check_equal(SALTS_OK,
        native_io_sharded_submit_to(scenario->runtime, shard, &task));
}

static void sg4_barrier(sg4_case *scenario) {
    check_equal(SALTS_OK, native_io_sharded_wait(scenario->runtime));
    for (size_t i = 0u; i < SG4_SHARDS; ++i) {
        const sg4_lane *lane = &scenario->lanes[i];
        if (lane->error) fprintf(stderr,
            "P2P SG4 shard %zu: %d at %s (turns %zu, raw completions %zu)\n",
            i, lane->error, lane->failed_at ? lane->failed_at : "?",
            lane->turns, lane->observed);
        check_equal(0, lane->error);
    }
}

static void sg4_pump(sg4_case *scenario) {
    for (size_t i = 0u; i < SG4_FINALS; ++i)
        check_equal(P2P_OK, p2p_poll(scenario->clients[i].node));
    for (size_t i = 0u; i < SG4_SHARDS; ++i)
        sg4_submit(scenario, i, sg4_progress);
    sg4_barrier(scenario);
    /* Saturated bounded SG turns: no fixed artificial 1ms sleep. */
}

static p2p_cnet_sg_snapshot_v1_t sg4_snapshot(sg4_case *scenario, size_t i) {
    p2p_cnet_sg_snapshot_v1_t snap = {0};
    check_equal(P2P_OK, p2p_cnet_sg_snapshot_v1(
        scenario->handoff, i, &snap));
    return snap;
}

static void test_four_sg_native_p2p_owners(void) {
    sg4_case fixture = {0};
    sg4_case *scenario = &fixture;
    const native_io_sharded_config settings = {
        SG4_SHARDS, 8u, {sg4_backend(), 64u, 128u, SG4_BATCH}};
    p2p_cnet_sg_config_v1_t policy = {0};
    check_equal(SALTS_OK,
        native_io_sharded_create(&settings, &scenario->runtime));
    check_not_null(scenario->runtime);

    for (size_t i = 0u; i < SG4_SHARDS; ++i) {
        scenario->lanes[i].scenario = scenario;
        scenario->lanes[i].shard = i;
        sg4_submit(scenario, i, sg4_init);
    }
    sg4_barrier(scenario);
    for (size_t i = 0u; i < SG4_SHARDS; ++i) {
        check_not_null(scenario->lanes[i].worker_token);
        check_not_null(scenario->lanes[i].backend);
        check_equal((uint32_t)i, scenario->lanes[i].lease.owner_shard);
        for (size_t j = 0u; j < i; ++j) {
            check_true(scenario->lanes[i].worker_token !=
                       scenario->lanes[j].worker_token);
            check_true(scenario->lanes[i].backend !=
                       scenario->lanes[j].backend);
            check_equal(scenario->lanes[i].lease.owner_identity,
                        scenario->lanes[j].lease.owner_identity);
        }
    }
    check_true(scenario->lanes[0].listener.port != 0u);

    for (size_t i = 0u; i < SG4_FINALS; ++i) {
        endpoint_t *client = &scenario->clients[i];
        sg4_server *server = &scenario->servers[i];
        client->remote = &server->endpoint;
        server->endpoint.remote = client;
        init_endpoint(client, 17 + (int)i * 2, 7u, 0);
    }

    policy.size = sizeof(policy);
    policy.version = P2P_CNET_SG_VERSION;
    policy.acceptor = scenario->lanes[0].acceptor;
    for (size_t i = 0u; i < SG4_FINALS; ++i)
        policy.final_owners[i] = scenario->lanes[i+1u].final_transport;
    policy.final_owner_count = SG4_FINALS;
    policy.placement = CNET_OWNER_PLACE_ROUND_ROBIN;
    policy.queue_capacity = 2u;
    policy.connection_capacity = 4u;
    check_equal(P2P_OK,
        p2p_cnet_sg_create_v1(&policy, &scenario->handoff));

    /* Sequential accept admission ensures stable, signed identity/owner
     * correspondence. Once established, all sessions advance concurrently. */
    for (size_t i = 0u; i < SG4_FINALS; ++i) {
        endpoint_t *client = &scenario->clients[i];
        sg4_server *server = &scenario->servers[i];
        check_equal(P2P_OK, p2p_connect(client->node,
            "127.0.0.1", (int)scenario->lanes[0].listener.port));
        const uint64_t deadline = cmeta_monotonic_ms() + SG4_TIMEOUT_MS;
        while ((!client->authenticated || !server->endpoint.authenticated) &&
               cmeta_monotonic_ms() < deadline)
            sg4_pump(scenario);
        check_equal(1, client->authenticated);
        check_equal(1, server->endpoint.authenticated);
        check_equal(1u, server->owner_connected);
        p2p_cnet_sg_snapshot_v1_t snap = sg4_snapshot(scenario, i);
        check_equal((uint64_t)(i + 1u), snap.routed);
        check_equal((uint64_t)0u, snap.denied);
        check_equal((size_t)1u, snap.handoff.taken);
        check_equal((size_t)0u, snap.handoff.queued);
    }

    for (size_t i = 0u; i < SG4_FINALS; ++i) {
        char request[8] = {'h','e','l','l','o','-',(char)('1' + i),'\0'};
        check_equal(P2P_OK, p2p_send_message(
            scenario->clients[i].node, scenario->clients[i].peer,
            P2P_MSG_CUSTOM, request, sizeof(request)));
        sg4_submit(scenario, i+1u, sg4_send);
    }
    sg4_barrier(scenario);
    const uint64_t exchange_deadline = cmeta_monotonic_ms() + SG4_TIMEOUT_MS;
    for (;;) {
        bool all_done = true;
        for (size_t i = 0u; i < SG4_FINALS; ++i)
            if (!scenario->servers[i].endpoint.messages ||
                !scenario->clients[i].messages) all_done = false;
        if (all_done || cmeta_monotonic_ms() >= exchange_deadline) break;
        sg4_pump(scenario);
    }
    for (size_t i = 0u; i < SG4_FINALS; ++i) {
        const char request[8] = {'h','e','l','l','o','-',(char)('1' + i),'\0'};
        const char reply[8] = {'r','e','p','l','y','-',(char)('1' + i),'\0'};
        check_equal(1, scenario->clients[i].messages);
        check_equal(1, scenario->servers[i].endpoint.messages);
        check_equal(1u, scenario->servers[i].owner_messages);
        check_equal(request, scenario->servers[i].endpoint.received, 8u);
        check_equal(reply, scenario->clients[i].received, 8u);
        check_equal((size_t)8u,
                    scenario->servers[i].endpoint.received_len);
        check_equal((size_t)8u, scenario->clients[i].received_len);
    }

    for (size_t i = 0u; i < SG4_FINALS; ++i)
        p2p_peer_disconnect(scenario->clients[i].peer);
    const uint64_t drain_deadline = cmeta_monotonic_ms() + SG4_TIMEOUT_MS;
    for (;;) {
        bool drained = true;
        sg4_pump(scenario);
        for (size_t i = 0u; i < SG4_FINALS; ++i) {
            p2p_cnet_sg_snapshot_v1_t snap = sg4_snapshot(scenario, i);
            if (snap.handoff.taken != 0u ||
                !scenario->servers[i].endpoint.disconnected)
                drained = false;
        }
        if (drained || cmeta_monotonic_ms() >= drain_deadline) break;
    }
    for (size_t i = 0u; i < SG4_FINALS; ++i) {
        p2p_cnet_sg_snapshot_v1_t snap = sg4_snapshot(scenario, i);
        check_equal((size_t)0u, snap.handoff.taken);
        check_equal((size_t)0u, snap.handoff.queued);
        check_equal(1u, scenario->servers[i].owner_disconnected);
        check_equal((size_t)0u, p2p_cnet_owner_connection_count(
            scenario->lanes[i+1u].final_transport));
    }
    check_equal((unsigned)0u,
                scenario->lanes[0].unwanted_local_accepts);
    for (size_t i = 0u; i < SG4_SHARDS; ++i) {
        check_true(scenario->lanes[i].turns > 0u);
        check_true(scenario->lanes[i].observed > 0u);
        check_equal(1u, scenario->lanes[i].wrong_owner_rejections);
    }

    check_equal(P2P_OK, p2p_cnet_sg_seal_v1(scenario->handoff));
    for (size_t i = 0u; i < SG4_SHARDS; ++i)
        sg4_submit(scenario, i, sg4_stop);
    sg4_barrier(scenario);
    const uint64_t stop_deadline = cmeta_monotonic_ms() + SG4_TIMEOUT_MS;
    for (;;) {
        bool all_stopped = true;
        for (size_t i = 0u; i < SG4_SHARDS; ++i) {
            if (scenario->lanes[i].stopped) continue;
            all_stopped = false;
            sg4_submit(scenario, i, sg4_progress);
        }
        if (all_stopped || cmeta_monotonic_ms() >= stop_deadline) break;
        sg4_barrier(scenario);
        for (size_t i = 0u; i < SG4_SHARDS; ++i)
            if (!scenario->lanes[i].stopped)
                sg4_submit(scenario, i, sg4_stop);
        sg4_barrier(scenario);
        cmeta_sleep_ms(1u);
    }
    for (size_t i = 0u; i < SG4_SHARDS; ++i)
        check_true(scenario->lanes[i].stopped);

    check_equal(P2P_OK, p2p_cnet_sg_destroy_v1(scenario->handoff));
    scenario->handoff = NULL;
    for (size_t i = 0u; i < SG4_SHARDS; ++i)
        sg4_submit(scenario, i, sg4_destroy);
    sg4_barrier(scenario);
    for (size_t i = 0u; i < SG4_SHARDS; ++i) {
        check_true(scenario->lanes[i].released);
        check_null(scenario->lanes[i].backend);
    }
    check_equal(SALTS_OK, native_io_sharded_shutdown(scenario->runtime));
    check_equal(SALTS_OK, native_io_sharded_destroy(scenario->runtime));

    for (size_t i = 0u; i < SG4_FINALS; ++i) {
        check_equal(P2P_OK,
            p2p_node_cnet_destroy(scenario->clients[i].owner));
        check_equal(P2P_OK,
            p2p_node_state_destroy(scenario->clients[i].node));
    }
}

spec("P2P 4-shard NativeIO SG Host, credited P2P final Owner identities") {
    it("hosts three distinct authenticated final P2P Owners on four actual SG shards") {
        test_four_sg_native_p2p_owners();
    }
}
