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
#ifndef BENCH_ASYNC_PROGRESS
#define BENCH_ASYNC_PROGRESS 0
#endif
#if BENCH_ASYNC_PROGRESS != 0 && BENCH_ASYNC_PROGRESS != 1
#error "BENCH_ASYNC_PROGRESS must be 0 or 1"
#endif
#define BENCH_PROGRESS_LABEL (BENCH_ASYNC_PROGRESS ? "owner-independent" : "global-barrier")
#ifndef BENCH_ACTIVE_SESSIONS
#define BENCH_ACTIVE_SESSIONS (BENCH_SG_SHARDS - (BENCH_SG_SHARDS != 1))
#endif
#if BENCH_ACTIVE_SESSIONS < 1 || BENCH_ACTIVE_SESSIONS > \
    (BENCH_SG_SHARDS - (BENCH_SG_SHARDS != 1))
#error "BENCH_ACTIVE_SESSIONS must fit the real final Owner count"
#endif
enum {
    SG4_SHARDS = BENCH_SG_SHARDS,
    SG4_FINALS = BENCH_SG_SHARDS == 1 ? 1u : BENCH_SG_SHARDS - 1u,
    SG4_ACTIVE_SESSIONS = BENCH_ACTIVE_SESSIONS,
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
#if BENCH_ASYNC_PROGRESS
    atomic_bool progress_ready; /* finalize acknowledges one short Owner task */
    atomic_int cancel_status;  /* no silent cancellation */
#endif
} sg4_lane;

typedef struct sg4_server {
    endpoint_t endpoint; /* Fixture identity and callback context, first. */
    sg4_lane *lane;
    unsigned owner_connected, owner_messages, owner_disconnected;
#if BENCH_ASYNC_PROGRESS
    atomic_int published_messages; /* release/acquire Owner → coordinator */
#endif
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
#if BENCH_ASYNC_PROGRESS
    atomic_store_explicit(&server->published_messages,
                          server->endpoint.messages, memory_order_release);
#endif
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
#if BENCH_ASYNC_PROGRESS
        atomic_init(&server->published_messages, 0);
#endif
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
    char reply[8] = {'r','e','p','l','y','-',
        (char)('1' + sg4_server_index(lane->shard)),'\0'};
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
    for (size_t i = 0u; i < SG4_ACTIVE_SESSIONS; ++i)
        check_equal(P2P_OK, p2p_poll(scenario->clients[i].node));
    for (size_t i = 0u; i < SG4_SHARDS; ++i)
        sg4_submit(scenario, i, sg4_progress);
    sg4_barrier(scenario);
    /* Saturated bounded SG turns: no fixed artificial 1ms sleep. */
}


#if BENCH_ASYNC_PROGRESS
/* Coordinator drives each shard with at most one outstanding finite task.
 * The SG Owner alone observes the backend. The task finalize, not the main
 * thread, grants permission to enqueue the next turn. */
static void sg4_progress_cancel(void *arg, int status) {
    sg4_lane *lane = (sg4_lane *)arg;
    atomic_store_explicit(&lane->cancel_status, status, memory_order_relaxed);
}
static void sg4_progress_finalize(void *arg) {
    sg4_lane *lane = (sg4_lane *)arg;
    atomic_store_explicit(&lane->progress_ready, true, memory_order_release);
}
static void sg4_pump_independent(sg4_case *scenario) {
    for (size_t i = 0u; i < SG4_ACTIVE_SESSIONS; ++i)
        check_equal(P2P_OK, p2p_poll(scenario->clients[i].node));
    for (size_t shard = 0u; shard < SG4_SHARDS; ++shard) {
        sg4_lane *lane = &scenario->lanes[shard];
        if (!atomic_exchange_explicit(&lane->progress_ready, false,
                                      memory_order_acq_rel))
            continue;
        native_io_sharded_task task = {
            sg4_progress, sg4_progress_cancel, sg4_progress_finalize, lane
        };
        int status = native_io_sharded_try_submit_to(
            scenario->runtime, shard, &task);
        if (status != SALTS_OK) {
            /* A rejected route borrows nothing: release the token and retry
             * later. A full bounded queue must never trigger fallback I/O. */
            atomic_store_explicit(&lane->progress_ready, true,
                                  memory_order_release);
            if (status != SALTS_ENOBUFS) check_equal(SALTS_OK, status);
        }
    }
}
static void sg4_independent_drain(sg4_case *scenario) {
    /* The only runtime-wide synchronization boundary after measured rounds. */
    sg4_barrier(scenario);
    for (size_t shard = 0u; shard < SG4_SHARDS; ++shard) {
        sg4_lane *lane = &scenario->lanes[shard];
        check_true(atomic_load_explicit(&lane->progress_ready,
                                        memory_order_acquire));
        check_equal(0, atomic_load_explicit(&lane->cancel_status,
                                            memory_order_relaxed));
    }
}
#define SG4_WORKER_MESSAGES(s, i) \
    atomic_load_explicit(&(s)->servers[(i)].published_messages, memory_order_acquire)
#define SG4_BENCH_PUMP(s) sg4_pump_independent(s)
#define SG4_BENCH_REPLY_BARRIER(s) ((void)0)
#define SG4_BENCH_FINISH(s) sg4_independent_drain(s)
#else
#define SG4_WORKER_MESSAGES(s, i) ((s)->servers[(i)].endpoint.messages)
#define SG4_BENCH_PUMP(s) sg4_pump(s)
#define SG4_BENCH_REPLY_BARRIER(s) sg4_barrier(s)
#define SG4_BENCH_FINISH(s) ((void)0)
#endif

static p2p_cnet_sg_snapshot_v1_t sg4_snapshot(sg4_case *scenario, size_t i) {
    p2p_cnet_sg_snapshot_v1_t snap = {0};
    check_equal(P2P_OK, p2p_cnet_sg_snapshot_v1(
        scenario->handoff, i, &snap));
    return snap;
}


/* Process CPU includes all SG Owner and standalone client threads. A sample
 * measures one complete parallel request/reply application batch, not TCP
 * one-way latency; compare session counts before inferring any core scaling. */
static uint64_t sg4_clock_ns(clockid_t kind) {
    struct timespec value = {0};
    check_equal(0, clock_gettime(kind, &value));
    return (uint64_t)value.tv_sec * 1000000000ull + (uint64_t)value.tv_nsec;
}
static int sg4_sort_u64(const void *a, const void *b) {
    uint64_t lhs = *(const uint64_t *)a, rhs = *(const uint64_t *)b;
    return (lhs > rhs) - (lhs < rhs);
}
static size_t sg4_count_env(const char *name, size_t default_value,
                             size_t maximum) {
    const char *input = getenv(name);
    char *end = NULL;
    unsigned long value;
    if (!input || !*input) return default_value;
    errno = 0;
    value = strtoul(input, &end, 10);
    if (errno || end == input || !end || *end || value == 0u ||
        value > maximum) {
        fprintf(stderr, "Invalid %s=%s (expect 1..%zu)\n",
                name, input, maximum);
        exit(2);
    }
    return (size_t)value;
}
static uint64_t sg4_percentile(const uint64_t *values, size_t count,
                               size_t percentile) {
    size_t rank = (count * percentile + 99u) / 100u;
    if (rank == 0u) rank = 1u;
    if (rank > count) rank = count;
    return values[rank - 1u];
}
static void sg4_run_benchmark(sg4_case *scenario) {
    size_t warmup = sg4_count_env("P2P_SG_BENCH_WARMUP", 16u, 512u);
    size_t count = sg4_count_env("P2P_SG_BENCH_ROUNDS", 128u, 4096u);
    uint64_t *samples = calloc(count, sizeof(*samples));
    uint64_t wall0 = 0u, cpu0 = 0u;
    check_not_null(samples);
    for (size_t round = 0u; round < warmup + count; ++round) {
        int expected = 2 + (int)round; /* preceding one-message proof */
        uint64_t started = 0u;
        if (round == warmup) {
            wall0 = sg4_clock_ns(CLOCK_MONOTONIC);
            cpu0 = sg4_clock_ns(CLOCK_PROCESS_CPUTIME_ID);
        }
        if (round >= warmup) started = sg4_clock_ns(CLOCK_MONOTONIC);
        for (size_t i = 0u; i < SG4_ACTIVE_SESSIONS; ++i) {
            const char request[8] = {'h','e','l','l','o','-',(char)('1' + i),'\0'};
            check_equal(P2P_OK, p2p_send_message(
                scenario->clients[i].node, scenario->clients[i].peer,
                P2P_MSG_CUSTOM, request, sizeof(request)));
        }
        uint64_t deadline = cmeta_monotonic_ms() + SG4_TIMEOUT_MS;
        for (;;) {
            bool done = true;
            for (size_t i = 0u; i < SG4_ACTIVE_SESSIONS; ++i)
                if (SG4_WORKER_MESSAGES(scenario, i) < expected)
                    done = false;
            if (done || cmeta_monotonic_ms() >= deadline) break;
            SG4_BENCH_PUMP(scenario);
        }
        for (size_t i = 0u; i < SG4_ACTIVE_SESSIONS; ++i)
            check_equal(expected, SG4_WORKER_MESSAGES(scenario, i));
        for (size_t i = 0u; i < SG4_ACTIVE_SESSIONS; ++i)
            sg4_submit(scenario, sg4_final_shard(i), sg4_send);
        SG4_BENCH_REPLY_BARRIER(scenario);
        deadline = cmeta_monotonic_ms() + SG4_TIMEOUT_MS;
        for (;;) {
            bool done = true;
            for (size_t i = 0u; i < SG4_ACTIVE_SESSIONS; ++i)
                if (scenario->clients[i].messages < expected) done = false;
            if (done || cmeta_monotonic_ms() >= deadline) break;
            SG4_BENCH_PUMP(scenario);
        }
        for (size_t i = 0u; i < SG4_ACTIVE_SESSIONS; ++i)
            check_equal(expected, scenario->clients[i].messages);
        if (round >= warmup)
            samples[round - warmup] =
                sg4_clock_ns(CLOCK_MONOTONIC) - started;
    }
    uint64_t wall1 = sg4_clock_ns(CLOCK_MONOTONIC);
    uint64_t cpu1 = sg4_clock_ns(CLOCK_PROCESS_CPUTIME_ID);
    SG4_BENCH_FINISH(scenario);
    qsort(samples, count, sizeof(*samples), sg4_sort_u64);
    double wall_s = (double)(wall1 - wall0) / 1e9;
    double cpu_s = (double)(cpu1 - cpu0) / 1e9;
    double messages = (double)count * (double)SG4_ACTIVE_SESSIONS * 2.0;
    check_true(wall_s > 0.0);
    printf("P2P_SG_BENCH,%s,%u,%u,%zu,%zu,8,%.3f,%.3f,%.2f,%.2f,%.4f,%.3f,%.3f,%.3f\n",
           BENCH_PROGRESS_LABEL,
           (unsigned)SG4_SHARDS, (unsigned)SG4_ACTIVE_SESSIONS, count, warmup,
           wall_s * 1e3, cpu_s * 1e3, cpu_s * 100.0 / wall_s,
           messages / wall_s, messages * 8.0 / (1048576.0 * wall_s),
           (double)sg4_percentile(samples, count, 50u) / 1000.0,
           (double)sg4_percentile(samples, count, 95u) / 1000.0,
           (double)sg4_percentile(samples, count, 99u) / 1000.0);
    fflush(stdout);
    free(samples);
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
#if BENCH_ASYNC_PROGRESS
        atomic_init(&scenario->lanes[i].progress_ready, true);
        atomic_init(&scenario->lanes[i].cancel_status, 0);
#endif
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

    for (size_t i = 0u; i < SG4_ACTIVE_SESSIONS; ++i) {
        endpoint_t *client = &scenario->clients[i];
        sg4_server *server = &scenario->servers[i];
        client->remote = &server->endpoint;
        server->endpoint.remote = client;
        init_endpoint(client, 17 + (int)i * 2, 7u, 0);
    }

    if (SG4_SHARDS > 1) {
        policy.size = sizeof(policy);
        policy.version = P2P_CNET_SG_VERSION;
        policy.acceptor = scenario->lanes[0].acceptor;
        for (size_t i = 0u; i < SG4_FINALS; ++i)
            policy.final_owners[i] =
                scenario->lanes[sg4_final_shard(i)].final_transport;
        policy.final_owner_count = SG4_FINALS;
        policy.placement = CNET_OWNER_PLACE_ROUND_ROBIN;
        policy.queue_capacity = 2u;
        policy.connection_capacity = 4u;
        check_equal(P2P_OK,
            p2p_cnet_sg_create_v1(&policy, &scenario->handoff));
    }

    /* Sequential accept admission ensures stable, signed identity/owner
     * correspondence. Once established, all sessions advance concurrently. */
    for (size_t i = 0u; i < SG4_ACTIVE_SESSIONS; ++i) {
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
        if (scenario->handoff) {
            p2p_cnet_sg_snapshot_v1_t snap = sg4_snapshot(scenario, i);
            check_equal((uint64_t)(i + 1u), snap.routed);
            check_equal((uint64_t)0u, snap.denied);
            check_equal((size_t)1u, snap.handoff.taken);
            check_equal((size_t)0u, snap.handoff.queued);
        }
    }

    for (size_t i = 0u; i < SG4_ACTIVE_SESSIONS; ++i) {
        char request[8] = {'h','e','l','l','o','-',(char)('1' + i),'\0'};
        check_equal(P2P_OK, p2p_send_message(
            scenario->clients[i].node, scenario->clients[i].peer,
            P2P_MSG_CUSTOM, request, sizeof(request)));
        sg4_submit(scenario, sg4_final_shard(i), sg4_send);
    }
    sg4_barrier(scenario);
    const uint64_t exchange_deadline = cmeta_monotonic_ms() + SG4_TIMEOUT_MS;
    for (;;) {
        bool all_done = true;
        for (size_t i = 0u; i < SG4_ACTIVE_SESSIONS; ++i)
            if (!scenario->servers[i].endpoint.messages ||
                !scenario->clients[i].messages) all_done = false;
        if (all_done || cmeta_monotonic_ms() >= exchange_deadline) break;
        sg4_pump(scenario);
    }
    for (size_t i = 0u; i < SG4_ACTIVE_SESSIONS; ++i) {
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

    sg4_run_benchmark(scenario);

    for (size_t i = 0u; i < SG4_ACTIVE_SESSIONS; ++i)
        p2p_peer_disconnect(scenario->clients[i].peer);
    const uint64_t drain_deadline = cmeta_monotonic_ms() + SG4_TIMEOUT_MS;
    for (;;) {
        bool drained = true;
        sg4_pump(scenario);
        for (size_t i = 0u; i < SG4_ACTIVE_SESSIONS; ++i) {
            if (scenario->handoff) {
                p2p_cnet_sg_snapshot_v1_t snap = sg4_snapshot(scenario, i);
                if (snap.handoff.taken != 0u) drained = false;
            }
            if (!scenario->servers[i].endpoint.disconnected)
                drained = false;
        }
        if (drained || cmeta_monotonic_ms() >= drain_deadline) break;
    }
    for (size_t i = 0u; i < SG4_ACTIVE_SESSIONS; ++i) {
        if (scenario->handoff) {
            p2p_cnet_sg_snapshot_v1_t snap = sg4_snapshot(scenario, i);
            check_equal((size_t)0u, snap.handoff.taken);
            check_equal((size_t)0u, snap.handoff.queued);
        }
        check_equal(1u, scenario->servers[i].owner_disconnected);
        check_equal((size_t)0u, p2p_cnet_owner_connection_count(
            scenario->lanes[sg4_final_shard(i)].final_transport));
    }
    check_equal((unsigned)0u,
                scenario->lanes[0].unwanted_local_accepts);
    for (size_t i = 0u; i < SG4_SHARDS; ++i) {
        check_true(scenario->lanes[i].turns > 0u);
        /* Non-selected 4-shard final Owners are live but may have zero I/O. */
        if (i == 0u || i <= (size_t)SG4_ACTIVE_SESSIONS)
            check_true(scenario->lanes[i].observed > 0u);
        check_equal(1u, scenario->lanes[i].wrong_owner_rejections);
    }

    if (scenario->handoff)
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

    if (scenario->handoff) {
        check_equal(P2P_OK, p2p_cnet_sg_destroy_v1(scenario->handoff));
        scenario->handoff = NULL;
    }
    for (size_t i = 0u; i < SG4_SHARDS; ++i)
        sg4_submit(scenario, i, sg4_destroy);
    sg4_barrier(scenario);
    for (size_t i = 0u; i < SG4_SHARDS; ++i) {
        check_true(scenario->lanes[i].released);
        check_null(scenario->lanes[i].backend);
    }
    check_equal(SALTS_OK, native_io_sharded_shutdown(scenario->runtime));
    check_equal(SALTS_OK, native_io_sharded_destroy(scenario->runtime));

    for (size_t i = 0u; i < SG4_ACTIVE_SESSIONS; ++i) {
        check_equal(P2P_OK,
            p2p_node_cnet_destroy(scenario->clients[i].owner));
        check_equal(P2P_OK,
            p2p_node_state_destroy(scenario->clients[i].node));
    }
}

spec("P2P SG Host real Noise benchmark: 1/2/4 SG worker topology") {
    it("runs authenticated echo batches and safely retires SG hosts") {
        test_four_sg_native_p2p_owners();
    }
}
