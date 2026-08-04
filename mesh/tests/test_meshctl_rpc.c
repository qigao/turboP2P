#include <tinytest.h>

#define MESHCTL_NO_MAIN
#include "../examples/meshctl.c"

static void test_rpc_node_adds_the_default_service_port(void) {
    char endpoint[160] = {0};

    check_int_eq(meshctl_build_rpc_node_addr("node-a.mesh",
                                             endpoint,
                                             sizeof(endpoint)),
                 0);
    check_str_eq(endpoint, "node-a.mesh:7878");

    check_int_eq(meshctl_build_rpc_node_addr("10.42.0.9",
                                             endpoint,
                                             sizeof(endpoint)),
                 0);
    check_str_eq(endpoint, "10.42.0.9:7878");
}

static void test_rpc_node_preserves_an_explicit_service_port(void) {
    char endpoint[160] = {0};

    check_int_eq(meshctl_build_rpc_node_addr("node-a.mesh:29090",
                                             endpoint,
                                             sizeof(endpoint)),
                 0);
    check_str_eq(endpoint, "node-a.mesh:29090");
}

static void test_rpc_node_rejects_ambiguous_endpoints(void) {
    char endpoint[160] = "stale";

    check_int_eq(meshctl_build_rpc_node_addr("node-a.mesh:7878junk",
                                             endpoint,
                                             sizeof(endpoint)),
                 -1);
    check_str_eq(endpoint, "");
    check_int_eq(meshctl_build_rpc_node_addr("",
                                             endpoint,
                                             sizeof(endpoint)),
                 -1);
    check_int_eq(meshctl_build_rpc_node_addr(":7878",
                                             endpoint,
                                             sizeof(endpoint)),
                 -1);
}

static void test_rpc_resolve_builds_only_canonical_node_paths(void) {
    static const char NODE_ID[] =
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";
    char path[128] = {0};

    check_int_eq(meshctl_build_rpc_resolve_path(NODE_ID,
                                                path,
                                                sizeof(path)),
                 0);
    check_str_eq(
        path,
        "/v1/node/resolve/"
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f");
    check_int_eq(meshctl_build_rpc_resolve_path(
                     "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8F",
                     path,
                     sizeof(path)),
                 -1);
    check_str_eq(path, "");
}

/* ---- meshctl cluster (turbo_cmd) ---- */

typedef struct {
    unsigned short port;
    int accept_target;
    volatile int requests;
    volatile int done;
} cluster_http_server_t;

static void cluster_http_server_thread(void *arg) {
    cluster_http_server_t *srv = (cluster_http_server_t *)arg;
    meshctl_socket_t listener = meshctl_invalid_socket();
    struct sockaddr_in addr;
    int accepted = 0;
#ifdef _WIN32
    int addr_len = (int)sizeof(addr);
    WSADATA wsa;
    (void)WSAStartup(MAKEWORD(2, 2), &wsa);
#else
    socklen_t addr_len = (socklen_t)sizeof(addr);
#endif

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0);
    listener = (meshctl_socket_t)socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == meshctl_invalid_socket()) {
        srv->done = 1;
        return;
    }
    if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        getsockname(listener, (struct sockaddr *)&addr, &addr_len) != 0 ||
        listen(listener, 4) != 0) {
        meshctl_close_socket(listener);
        srv->done = 1;
        return;
    }
    srv->port = ntohs(addr.sin_port);
    while (accepted < srv->accept_target) {
        static const char RESP[] = "HTTP/1.1 200 OK\r\n"
                                   "Content-Length: 15\r\n"
                                   "Connection: close\r\n"
                                   "\r\n"
                                   "{\"status\":\"up\"}";
        meshctl_socket_t client =
            (meshctl_socket_t)accept(listener, NULL, NULL);
        char buf[256];

        if (client == meshctl_invalid_socket())
            break;
        if (recv(client, buf, (int)sizeof(buf) - 1, 0) > 0)
            (void)send(client, RESP, (int)strlen(RESP), 0);
        meshctl_close_socket(client);
        accepted++;
        srv->requests++;
    }
    /* The listener is intentionally not closed here: closing it from this
     * thread after rpc_send's WSAStartup/WSACleanup churn hangs on Windows.
     * Process exit reclaims it. */
    srv->done = 1;
}

static void wait_for_port(cluster_http_server_t *srv) {
    int guard = 5000;

    while (srv->port == 0 && !srv->done && guard-- > 0)
        turbo_sleep_ms(1);
}

static void test_cluster_parse_status(void) {
    meshctl_cluster_opts_t opts;
    char *argv[] = {"cluster", "status", "--node",
                    "10.42.0.1:7878, 10.42.0.2:7878",
                    "--token", "sekret", "--raw"};

    check_int_eq(meshctl_cluster_parse(7, argv, &opts), 0);
    check_int_eq(opts.subcommand, 0);
    check_uint_eq(opts.node_count, 2u);
    check_str_eq(opts.nodes[0], "10.42.0.1:7878");
    check_str_eq(opts.nodes[1], "10.42.0.2:7878");
    check_str_eq(opts.token, "sekret");
    check_true(opts.raw);
}

static void test_cluster_parse_list(void) {
    meshctl_cluster_opts_t opts;
    char *argv[] = {"cluster", "list", "--node", "a:1,b:2"};

    check_int_eq(meshctl_cluster_parse(4, argv, &opts), 0);
    check_int_eq(opts.subcommand, 1);
    check_uint_eq(opts.node_count, 2u);
    check_str_eq(opts.nodes[0], "a:1");
    check_str_eq(opts.nodes[1], "b:2");
}


static void test_cluster_status_aggregates(void) {
    cluster_http_server_t server_a;
    cluster_http_server_t server_b;
    turbo_thread_t thread_a = NULL;
    turbo_thread_t thread_b = NULL;
    char node_a_and_closed[96];
    char node_a_and_b[96];
    char *argv_down[] = {"cluster", "status", "--node", node_a_and_closed};
    char *argv_up[] = {"cluster", "status", "--node", node_a_and_b};
    memset(&server_a, 0, sizeof(server_a));
    server_a.accept_target = 2;
    memset(&server_b, 0, sizeof(server_b));
    server_b.accept_target = 1;
    check_int_eq(turbo_thread_create(&thread_a, cluster_http_server_thread, &server_a), 0);
    check_int_eq(turbo_thread_create(&thread_b, cluster_http_server_thread, &server_b), 0);
    wait_for_port(&server_a);
    wait_for_port(&server_b);
    check_true(server_a.port != 0u);
    check_true(server_b.port != 0u);

    /* One live node + one refused loopback port -> one down. */
    snprintf(node_a_and_closed, sizeof(node_a_and_closed), "127.0.0.1:%u,127.0.0.1:1",
             server_a.port);
    check_int_eq(meshctl_run_cluster(4, argv_down), 1);
    check_int_eq(server_a.requests, 1);

    /* Both live -> all up. */
    snprintf(node_a_and_b, sizeof(node_a_and_b), "127.0.0.1:%u,127.0.0.1:%u",
             server_a.port, server_b.port);
    check_int_eq(meshctl_run_cluster(4, argv_up), 0);
    check_int_eq(server_a.requests, 2);
    check_int_eq(server_b.requests, 1);

    /* Wait for the server threads to finish serving. */
    {
        int guard = 5000;

        while ((!server_a.done || !server_b.done) && guard-- > 0)
            turbo_sleep_ms(1);
        check_true(server_a.done);
        check_true(server_b.done);
    }
}
spec("meshctl RPC") {
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
