#include <tinytest.h>
#include <turbo_mesh.h>
#include <stdint.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
static void sleep_ms(int ms) {
    Sleep(ms);
}

static uint64_t now_ms(void) {
    return GetTickCount64();
}
#else
#include <time.h>
#include <unistd.h>
static void sleep_ms(int ms) {
    usleep((useconds_t)ms * 1000);
}

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}
#endif

typedef int (*mesh_predicate_fn)(void *ctx);

typedef struct {
    mesh_network_t *mesh;
    const char *dest_ip;
    const char *next_hop_ip;
} route_wait_ctx_t;

typedef struct {
    mesh_network_t *leader;
    mesh_network_t *node2;
    mesh_network_t *node3;
    const char *leader_ip;
} relay_wait_ctx_t;

typedef struct {
    mesh_network_t *mesh_a;
    mesh_network_t *mesh_b;
    int mesh_a_peers;
    int mesh_b_peers;
} peer_wait_ctx_t;

static mesh_network_t *mesh_create_started(const char *virtual_ip,
                                           int listen_port,
                                           const char *advertise_ip,
                                           const char **bootstrap_peers,
                                           int bootstrap_count) {
    mesh_config_t config;
    mesh_config_init(&config);
    config.virtual_ip = virtual_ip;
    config.virtual_prefix = 16;
    config.listen_port = listen_port;
    config.advertise_ip = advertise_ip;
    config.bootstrap_peers = bootstrap_peers;
    config.bootstrap_count = bootstrap_count;

    mesh_network_t *mesh = mesh_create(&config);
    check_not_null(mesh);
    check_int_eq(MESH_OK, mesh_start(mesh));
    return mesh;
}

static void mesh_destroy_stopped(mesh_network_t **mesh) {
    if (!mesh || !*mesh) {
        return;
    }

    mesh_stop(*mesh);
    mesh_destroy(*mesh);
    *mesh = NULL;
}

static void mesh_poll_many(mesh_network_t **meshes, size_t mesh_count) {
    size_t i;

    for (i = 0; i < mesh_count; i++) {
        if (meshes[i]) {
            mesh_poll(meshes[i], 50);
        }
    }

    sleep_ms(50);
}

static int wait_until(mesh_network_t **meshes,
                      size_t mesh_count,
                      int timeout_ms,
                      mesh_predicate_fn predicate,
                      void *ctx) {
    uint64_t deadline = now_ms() + (uint64_t)timeout_ms;

    while (now_ms() < deadline) {
        mesh_poll_many(meshes, mesh_count);
        if (predicate(ctx)) {
            return 1;
        }
    }

    return predicate(ctx);
}

static int mesh_has_connected_route(mesh_network_t *mesh,
                                    const char *dest_ip,
                                    const char *next_hop_ip) {
    int route_count;
    int i;

    route_count = mesh_get_route_count(mesh);
    for (i = 0; i < route_count; i++) {
        mesh_route_info_t route;
        if (mesh_get_route_info(mesh, i, &route) != MESH_OK) {
            continue;
        }

        if (strcmp(route.dest_ip, dest_ip) != 0) {
            continue;
        }

        if (!route.is_connected) {
            continue;
        }

        if (next_hop_ip && strcmp(route.next_hop_virtual_ip, next_hop_ip) != 0) {
            continue;
        }

        return 1;
    }

    return 0;
}

static int mesh_peer_count_is(mesh_network_t *mesh, int expected) {
    return mesh_get_peer_count(mesh) == expected;
}

static int wait_for_route(void *ctx) {
    route_wait_ctx_t *route_ctx = (route_wait_ctx_t *)ctx;
    return mesh_has_connected_route(route_ctx->mesh, route_ctx->dest_ip, route_ctx->next_hop_ip);
}

static int wait_for_relay_mesh(void *ctx) {
    relay_wait_ctx_t *relay_ctx = (relay_wait_ctx_t *)ctx;

    if (!relay_ctx->leader || !mesh_peer_count_is(relay_ctx->leader, 2)) {
        return 0;
    }

    if (!mesh_peer_count_is(relay_ctx->node2, 1) || !mesh_peer_count_is(relay_ctx->node3, 1)) {
        return 0;
    }

    if (!mesh_has_connected_route(relay_ctx->node2, "10.42.5.3", relay_ctx->leader_ip)) {
        return 0;
    }

    if (!mesh_has_connected_route(relay_ctx->node3, "10.42.5.2", relay_ctx->leader_ip)) {
        return 0;
    }

    return 1;
}

static int wait_for_followers_disconnected(void *ctx) {
    relay_wait_ctx_t *relay_ctx = (relay_wait_ctx_t *)ctx;
    return mesh_peer_count_is(relay_ctx->node2, 0) && mesh_peer_count_is(relay_ctx->node3, 0);
}

static int wait_for_peer_counts(void *ctx) {
    peer_wait_ctx_t *peer_ctx = (peer_wait_ctx_t *)ctx;

    if (!mesh_peer_count_is(peer_ctx->mesh_a, peer_ctx->mesh_a_peers)) {
        return 0;
    }

    if (!mesh_peer_count_is(peer_ctx->mesh_b, peer_ctx->mesh_b_peers)) {
        return 0;
    }

    return 1;
}

static void test_mesh_leader_restart_recovers_peers(void) {
    const char *bootstrap_peers[] = {"127.0.0.1:20501"};
    mesh_network_t *leader = NULL;
    mesh_network_t *node2 = NULL;
    mesh_network_t *meshes[2];
    peer_wait_ctx_t peer_ctx;
    uint64_t restart_started_ms;
    uint64_t recovered_ms;
    leader = mesh_create_started("10.42.5.1", 20501, NULL, NULL, 0);
    sleep_ms(200);
    node2 = mesh_create_started("10.42.5.2", 20502, NULL, bootstrap_peers, 1);

    meshes[0] = leader;
    meshes[1] = node2;

    peer_ctx.mesh_a = leader;
    peer_ctx.mesh_b = node2;
    peer_ctx.mesh_a_peers = 1;
    peer_ctx.mesh_b_peers = 1;

    check(wait_until(meshes, 2, 10000, wait_for_peer_counts, &peer_ctx));

    mesh_destroy_stopped(&leader);
    meshes[0] = NULL;
    peer_ctx.mesh_a = node2;
    peer_ctx.mesh_b = node2;
    peer_ctx.mesh_a_peers = 0;
    peer_ctx.mesh_b_peers = 0;

    check(wait_until(&meshes[1], 1, 4000, wait_for_peer_counts, &peer_ctx));

    restart_started_ms = now_ms();
    leader = mesh_create_started("10.42.5.1", 20501, NULL, NULL, 0);
    meshes[0] = leader;
    peer_ctx.mesh_a = leader;
    peer_ctx.mesh_b = node2;
    peer_ctx.mesh_a_peers = 1;
    peer_ctx.mesh_b_peers = 1;

    check(wait_until(meshes, 2, 8000, wait_for_peer_counts, &peer_ctx));
    recovered_ms = now_ms() - restart_started_ms;

    printf("[TEST] leader restart peer recovery: %llu ms\n",
           (unsigned long long)recovered_ms);
    check(recovered_ms <= 8000);

    mesh_destroy_stopped(&node2);
    mesh_destroy_stopped(&leader);
}

static int wait_for_staggered_routes(void *ctx) {
    relay_wait_ctx_t *relay_ctx = (relay_wait_ctx_t *)ctx;

    if (!relay_ctx->leader || !mesh_peer_count_is(relay_ctx->leader, 2)) {
        return 0;
    }

    if (!mesh_has_connected_route(relay_ctx->node2, "10.42.6.3", relay_ctx->leader_ip)) {
        return 0;
    }

    if (!mesh_has_connected_route(relay_ctx->node3, "10.42.6.2", relay_ctx->leader_ip)) {
        return 0;
    }

    return 1;
}

static void test_mesh_followers_boot_before_leader(void) {
    const char *bootstrap_peers[] = {"127.0.0.1:20601"};
    mesh_network_t *leader = NULL;
    mesh_network_t *node2 = NULL;
    mesh_network_t *node3 = NULL;
    mesh_network_t *meshes[3];
    relay_wait_ctx_t relay_ctx;
    route_wait_ctx_t direct_ctx;
    uint64_t leader_started_ms;
    uint64_t converged_ms;

    node3 = mesh_create_started("10.42.6.3", 20603, NULL, bootstrap_peers, 1);
    node2 = mesh_create_started("10.42.6.2", 20602, NULL, bootstrap_peers, 1);

    meshes[0] = NULL;
    meshes[1] = node2;
    meshes[2] = node3;

    direct_ctx.mesh = node2;
    direct_ctx.dest_ip = "10.42.6.3";
    direct_ctx.next_hop_ip = "10.42.6.1";
    check_false(wait_until(&meshes[1], 2, 2000, wait_for_route, &direct_ctx));

    leader_started_ms = now_ms();
    leader = mesh_create_started("10.42.6.1", 20601, NULL, NULL, 0);
    meshes[0] = leader;

    relay_ctx.leader = leader;
    relay_ctx.node2 = node2;
    relay_ctx.node3 = node3;
    relay_ctx.leader_ip = "10.42.6.1";

    check(wait_until(meshes, 3, 18000, wait_for_staggered_routes, &relay_ctx));
    converged_ms = now_ms() - leader_started_ms;

    printf("[TEST] staggered startup route convergence: %llu ms\n",
           (unsigned long long)converged_ms);
    check(converged_ms <= 15000);

    mesh_destroy_stopped(&node3);
    mesh_destroy_stopped(&node2);
    mesh_destroy_stopped(&leader);
}

spec("mesh fault harness") {
    describe("leader flap") {
        it("reconnects to the leader after restart within budget") {
            test_mesh_leader_restart_recovers_peers();
        }
    }

    describe("startup perturbation") {
        it("learns relay routes when followers boot before leader") {
            test_mesh_followers_boot_before_leader();
        }
    }
}
