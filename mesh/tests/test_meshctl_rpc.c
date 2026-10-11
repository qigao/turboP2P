#include <tinytest.h>

#define MESHCTL_NO_MAIN
#include "../examples/meshctl.c"

#include "meshctl_http_fixture.h"
#include <fmt.h>
#include <stdatomic.h>

static void test_rpc_node_adds_the_default_service_port(void) {
    char endpoint[160] = {0};

    check_equal(meshctl_build_rpc_node_addr("node-a.mesh",
                                             endpoint,
                                             sizeof(endpoint)),
                 0);
    check_equal(endpoint, "node-a.mesh:7878");

    check_equal(meshctl_build_rpc_node_addr("10.42.0.9",
                                             endpoint,
                                             sizeof(endpoint)),
                 0);
    check_equal(endpoint, "10.42.0.9:7878");
}

static void test_rpc_node_preserves_an_explicit_service_port(void) {
    char endpoint[160] = {0};

    check_equal(meshctl_build_rpc_node_addr("node-a.mesh:29090",
                                             endpoint,
                                             sizeof(endpoint)),
                 0);
    check_equal(endpoint, "node-a.mesh:29090");
}

static void test_rpc_node_rejects_ambiguous_endpoints(void) {
    char endpoint[160] = "stale";

    check_equal(meshctl_build_rpc_node_addr("node-a.mesh:7878junk",
                                             endpoint,
                                             sizeof(endpoint)),
                 -1);
    check_equal(endpoint, "");
    check_equal(meshctl_build_rpc_node_addr("",
                                             endpoint,
                                             sizeof(endpoint)),
                 -1);
    check_equal(meshctl_build_rpc_node_addr(":7878",
                                             endpoint,
                                             sizeof(endpoint)),
                 -1);
}

static void test_rpc_resolve_builds_only_canonical_node_paths(void) {
    static const char NODE_ID[] =
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";
    char path[128] = {0};

    check_equal(meshctl_build_rpc_resolve_path(NODE_ID,
                                                path,
                                                sizeof(path)),
                 0);
    check_equal(
        path,
        "/v1/node/resolve/"
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f");
    check_equal(meshctl_build_rpc_resolve_path(
                     "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8F",
                     path,
                     sizeof(path)),
                 -1);
    check_equal(path, "");
}

static void test_rpc_token_rejects_header_injection_and_oversize(void) {
    char oversized[MESHD_CTL_RPC_TOKEN_HEADER_MAX + 1u];

    memset(oversized, 'a', sizeof(oversized));
    oversized[sizeof(oversized) - 1u] = '\0';
    check_true(meshctl_rpc_token_is_valid(NULL));
    check_true(meshctl_rpc_token_is_valid(""));
    check_true(meshctl_rpc_token_is_valid("valid-token"));
    check_false(meshctl_rpc_token_is_valid("valid\r\nInjected: true"));
    check_false(meshctl_rpc_token_is_valid(oversized));
}

/* ---- meshctl cluster (turbo_cmd) ---- */

typedef struct {
    chttp_server owner;
    uint16_t port;
    atomic_int requests;
} cluster_http_server_t;

static cluster_http_server_t server_a, server_b;
static tstr node_a_and_closed, node_a_and_b;

static int cluster_http_reply(void *user, const chttp_server_request_view *request,
                               chttp_server_response *response) {
    cluster_http_server_t *server = user;
    static const char BODY[] = "{\"status\":\"up\"}";
    (void)request;
    atomic_fetch_add(&server->requests, 1);
    return chttp_server_reply(response, 200u, "application/json", BODY, sizeof(BODY) - 1u);
}

static void cluster_http_start(cluster_http_server_t *server) {
    chttp_server_config config = meshctl_test_http_server_config();
    check_equal(chttp_server_init(&server->owner, &config), SALTS_OK);
    check_equal(chttp_server_get(&server->owner, "/v1/status", cluster_http_reply, server), SALTS_OK);
    check_equal(chttp_server_start(&server->owner), SALTS_OK);
    check_equal(chttp_server_port(&server->owner, &server->port), SALTS_OK);
    check_not_equal(server->port, (uint16_t)0);
}

static void cluster_http_close(cluster_http_server_t *server) {
    if (server->owner.impl) {
        check_equal(chttp_server_stop(&server->owner, 0u), SALTS_OK);
        check_equal(chttp_server_destroy(&server->owner), SALTS_OK);
    }
}

static void test_cluster_parse_status(void) {
    meshctl_cluster_opts_t opts;
    char *argv[] = {"cluster", "status", "--node",
                    "10.42.0.1:7878, 10.42.0.2:7878",
                    "--token", "sekret", "--raw"};

    check_equal(meshctl_cluster_parse(7, argv, &opts), 0);
    check_equal(opts.subcommand, 0);
    check_equal(opts.node_count, 2u);
    check_equal(opts.nodes[0], "10.42.0.1:7878");
    check_equal(opts.nodes[1], "10.42.0.2:7878");
    check_equal(opts.token, "sekret");
    check_true(opts.raw);
}

static void test_cluster_parse_list(void) {
    meshctl_cluster_opts_t opts;
    char *argv[] = {"cluster", "list", "--node", "a:1,b:2"};

    check_equal(meshctl_cluster_parse(4, argv, &opts), 0);
    check_equal(opts.subcommand, 1);
    check_equal(opts.node_count, 2u);
    check_equal(opts.nodes[0], "a:1");
    check_equal(opts.nodes[1], "b:2");
}


static void test_cluster_status_aggregates(void) {
    cluster_http_start(&server_a);
    cluster_http_start(&server_b);
    node_a_and_closed = tstr_format("127.0.0.1:{},127.0.0.1:1", (unsigned int)server_a.port);
    node_a_and_b = tstr_format("127.0.0.1:{},127.0.0.1:{}",
                                (unsigned int)server_a.port, (unsigned int)server_b.port);
    check_not_null(node_a_and_closed);
    check_not_null(node_a_and_b);
    char *argv_down[] = {"cluster", "status", "--node", node_a_and_closed};
    char *argv_up[] = {"cluster", "status", "--node", node_a_and_b};
    check_equal(meshctl_run_cluster(4, argv_down), 1);
    check_equal(atomic_load(&server_a.requests), 1);
    check_equal(meshctl_run_cluster(4, argv_up), 0);
    check_equal(atomic_load(&server_a.requests), 2);
    check_equal(atomic_load(&server_b.requests), 1);
}
spec("meshctl RPC") {
    before_each() {
        memset(&server_a, 0, sizeof(server_a));
        memset(&server_b, 0, sizeof(server_b));
        atomic_init(&server_a.requests, 0);
        atomic_init(&server_b.requests, 0);
        node_a_and_closed = NULL;
        node_a_and_b = NULL;
    }
    after_each() {
        cluster_http_close(&server_a);
        cluster_http_close(&server_b);
        tstr_freep(&node_a_and_closed);
        tstr_freep(&node_a_and_b);
    }
    describe("virtual node endpoint") {
        it("adds the default RPC service port") {
            test_rpc_node_adds_the_default_service_port();
        }

        it("preserves an explicit RPC service port") {
            test_rpc_node_preserves_an_explicit_service_port();
        }

        it("rejects ambiguous endpoints") {
            test_rpc_node_rejects_ambiguous_endpoints();
        }

        it("builds only canonical verified-service resolve paths") {
            test_rpc_resolve_builds_only_canonical_node_paths();
        }

        it("rejects token header injection and oversized tokens") {
            test_rpc_token_rejects_header_injection_and_oversize();
        }
    }

    describe("cluster (turbo_cmd)") {
        it("parses the status subcommand with a node list") {
            test_cluster_parse_status();
        }

        it("parses the list subcommand") {
            test_cluster_parse_list();
        }


        it("aggregates node status over real HTTP endpoints") {
            test_cluster_status_aggregates();
        }
    }
}
