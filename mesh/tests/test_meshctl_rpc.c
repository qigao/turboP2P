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
}
