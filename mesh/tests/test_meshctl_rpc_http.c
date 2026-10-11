#include "meshctl_rpc_http.h"
#include "meshctl_http_fixture.h"
#include <fmt.h>
#include <stdatomic.h>
#include <string.h>
#include <tinytest.h>

static chttp_server server;
static chttp_client client;
static chttp_response response;
static chttp_error error;
static tstr addr, payload;
static chttp_server_deferred deferred;
static atomic_int calls, token_ok, method_ok, deferred_ready;
static atomic_uint reply_status;
static atomic_size_t reply_size;


static int reply(void *user, const chttp_server_request_view *request,
                 chttp_server_response *out) {
    const char *token = chttp_server_request_header(request, "X-Meshd-Token");
    (void)user;
    atomic_fetch_add(&calls, 1);
    atomic_store(&token_ok, token && strcmp(token, "sekret") == 0);
    atomic_store(&method_ok, request->method == CHTTP_METHOD_POST && request->body_size == 0u);
    if (strcmp(request->path, "/wait") == 0) {
        int status = chttp_server_response_defer(out, &deferred);
        atomic_store_explicit(&deferred_ready, status == SALTS_OK, memory_order_release);
        return status;
    }
    if (strcmp(request->path, "/redirect") == 0) {
        int status = chttp_server_response_set_header(out, "Location", "/status");
        if (status != SALTS_OK) return status;
    }
    if (strcmp(request->path, "/header") == 0) {
        int status = chttp_server_response_set_header(out, "X-Large", payload);
        if (status != SALTS_OK) return status;
    }
    return chttp_server_reply(out, reply_status, "application/octet-stream", payload, reply_size);
}

static void start_server(void) {
    uint16_t port = 0;
    chttp_server_config config = meshctl_test_http_server_config();
    check_equal(chttp_server_init(&server, &config), SALTS_OK);
    check_equal(chttp_server_get(&server, "/status", reply, NULL), SALTS_OK);
    check_equal(chttp_server_post(&server, "/shutdown", reply, NULL), SALTS_OK);
    check_equal(chttp_server_get(&server, "/redirect", reply, NULL), SALTS_OK);
    check_equal(chttp_server_get(&server, "/header", reply, NULL), SALTS_OK);
    check_equal(chttp_server_post(&server, "/wait", reply, NULL), SALTS_OK);
    check_equal(chttp_server_start(&server), SALTS_OK);
    check_equal(chttp_server_port(&server, &port), SALTS_OK);
    addr = tstr_format("127.0.0.1:{}", (unsigned int)port);
    check_not_null(addr);
}

static int request(const char *path, const char *method, const char *token) {
    return meshctl_rpc_http_request(&client, addr, path, method, token, &response, &error);
}

static void release_client(void) {
    chttp_response_destroy(&response);
    check_equal(chttp_client_destroy(&client, MESHD_CTL_RPC_TIMEOUT_MS), SALTS_OK);
    check_null(client.impl);
}

spec("meshctl CHttp RPC") {
    before_each() {
        memset(&server, 0, sizeof(server));
        memset(&client, 0, sizeof(client));
        memset(&response, 0, sizeof(response));
        memset(&deferred, 0, sizeof(deferred));
        memset(&error, 0, sizeof(error));
        atomic_init(&calls, 0);
        atomic_init(&token_ok, 0);
        atomic_init(&method_ok, 0);
        atomic_init(&deferred_ready, 0);
        addr = NULL;
        payload = tstr_dup("{\"status\":\"up\"}");
        check_not_null(payload);
        atomic_init(&reply_size, tstr_len(payload));
        atomic_init(&reply_status, 200u);
    }
    after_each() {
        chttp_response_destroy(&response);
        check_equal(chttp_client_destroy(&client, MESHD_CTL_RPC_TIMEOUT_MS), SALTS_OK);
        if (atomic_load_explicit(&deferred_ready, memory_order_acquire)) {
            /* Peer close may already have retired this generation. */
            int status = chttp_server_deferred_cancel(&deferred);
            check_true(status == SALTS_OK || status == SALTS_ENOENT);
        }
        if (server.impl) {
            check_equal(chttp_server_stop(&server, 0u), SALTS_OK);
            check_equal(chttp_server_destroy(&server), SALTS_OK);
        }
        tstr_freep(&addr);
        tstr_freep(&payload);
    }
    it("preserves node port normalization and canonical resolve paths") {
        char out[160];
        check_equal(meshctl_build_rpc_node_addr("node-a.mesh", out, sizeof(out)), 0);
        check_equal(out, "node-a.mesh:7878");
        check_equal(meshctl_build_rpc_node_addr("10.42.0.9:29090", out, sizeof(out)), 0);
        check_equal(out, "10.42.0.9:29090");
        check_equal(meshctl_build_rpc_node_addr("node-a.mesh:7878junk", out, sizeof(out)), -1);
        check_equal(out, "");
        check_equal(meshctl_build_rpc_node_addr(":7878", out, sizeof(out)), -1);
        check_equal(meshctl_build_rpc_node_addr("node.mesh:999999999999999", out, sizeof(out)), -1);
        check_equal(meshctl_build_rpc_node_addr("node.mesh", out, 1u), -1);
        check_equal(out, "");
        const char *id = "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";
        check_equal(meshctl_build_rpc_resolve_path(id, out, sizeof(out)), 0);
        check_equal(out, "/v1/node/resolve/707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f");
        check_equal(meshctl_build_rpc_resolve_path("ABC", out, sizeof(out)), -1);
        check_equal(out, "");
    }
    it("performs authenticated H1 GET with an independently owned byte response") {
        start_server();
        check_equal(request("/status", "GET", "sekret"), SALTS_OK);
        check_equal(response.http_major, 1u);
        check_equal(response.http_minor, 1u);
        check_equal(response.status_code, 200u);
        check_equal(response.body_size, atomic_load(&reply_size));
        check_equal(response.body, payload, atomic_load(&reply_size));
        check_equal(atomic_load(&calls), 1);
        check_equal(atomic_load(&token_ok), 1);
        void *owner = client.impl;
        int status = chttp_client_destroy(&client, 0u);
        check_true(status == SALTS_OK || status == SALTS_ETIMEDOUT);
        if (status == SALTS_ETIMEDOUT) {
            check_true(client.impl == owner);
            check_equal(chttp_client_destroy(&client, MESHD_CTL_RPC_TIMEOUT_MS), SALTS_OK);
        }
        check_null(client.impl);
        check_equal(atomic_load(&calls), 1);
        check_equal(response.body, payload, atomic_load(&reply_size));
    }
    it("sends one bodyless POST and preserves HTTP error status without retry") {
        start_server();
        reply_status = 503u;
        check_equal(request("/shutdown", "POST", "sekret"), SALTS_OK);
        check_equal(response.status_code, 503u);
        check_equal(atomic_load(&method_ok), 1);
        check_equal(atomic_load(&calls), 1);
        check_equal(meshctl_rpc_http_request(&client, addr, "/shutdown", "POST", "sekret",
                                             &response, &error), SALTS_EALREADY);
        check_equal(atomic_load(&calls), 1);
    }
    it("renders CLI requests and keeps HTTP errors as completed transport calls") {
        start_server();
        atomic_store(&reply_status, 404u);
        check_equal(meshctl_rpc_send(addr, "/status", "GET", "sekret", 1), 0);
        check_equal(atomic_load(&calls), 1);
        check_equal(meshctl_rpc_send(addr, "/shutdown", "POST", NULL, 0), 0);
        check_equal(atomic_load(&calls), 2);
        check_equal(atomic_load(&method_ok), 1);
        check_equal(meshctl_rpc_send(addr, "/status", "GET", "bad\r\nheader", 0), 1);
        check_equal(atomic_load(&calls), 2);
    }
    it("returns redirects without following them") {
        reply_status = 302u;
        start_server();
        check_equal(request("/redirect", "GET", NULL), SALTS_OK);
        check_equal(response.status_code, 302u);
        check_equal(chttp_response_header(&response, "Location"), "/status");
        check_equal(atomic_load(&calls), 1);
    }
    it("rejects invalid options and token injection before creating a network owner") {
        char large[MESHD_CTL_RPC_TOKEN_HEADER_MAX + 1u];
        memset(large, 'x', sizeof(large) - 1u);
        large[sizeof(large) - 1u] = '\0';
        check_true(meshctl_rpc_token_is_valid(NULL));
        check_true(meshctl_rpc_token_is_valid(""));
        check_false(meshctl_rpc_token_is_valid(large));
        check_false(meshctl_rpc_token_is_valid("x\r\nInjected: yes"));
        start_server();
        check_equal(request("/status", "GET", large), SALTS_EINVAL);
        check_equal(request("/status", "GET", "x\r\nInjected: yes"), SALTS_EINVAL);
        check_equal(request("relative", "GET", NULL), SALTS_EINVAL);
        check_equal(request("/status", "DELETE", NULL), SALTS_EINVAL);
        char target[MESHD_CTL_RPC_URL_MAX + 1u];
        memset(target, 'a', sizeof(target) - 1u);
        target[0] = '/';
        target[sizeof(target) - 1u] = '\0';
        check_equal(request(target, "GET", NULL), SALTS_EMSGSIZE);
        check_equal(error.status, SALTS_EMSGSIZE);
        large[MESHD_CTL_RPC_TOKEN_HEADER_MAX - sizeof("X-Meshd-Token: ")] = '\0';
        check_true(meshctl_rpc_token_is_valid(large));
        check_null(client.impl);
        check_equal(atomic_load(&calls), 0);
    }
    it("accepts exactly the body bound and rejects one extra byte") {
        tstr_free(payload);
        payload = tstr_new_len(NULL, MESHD_CTL_RPC_MAX_RESPONSE_SIZE + 1u);
        check_not_null(payload);
        memset(payload, 'a', tstr_len(payload));
        reply_size = MESHD_CTL_RPC_MAX_RESPONSE_SIZE;
        start_server();
        check_equal(request("/status", "GET", NULL), SALTS_OK);
        check_equal(response.body_size, atomic_load(&reply_size));
        check_equal(response.body, payload, atomic_load(&reply_size));
        release_client();
        reply_size++;
        check_not_equal(request("/status", "GET", NULL), SALTS_OK);
        check_equal(atomic_load(&calls), 2);
        check_null(response.body);
    }
    it("rejects headers exceeding the existing hard byte bound") {
        tstr_free(payload);
        payload = tstr_new_len(NULL, MESHD_CTL_RPC_MAX_HEADER_SIZE + 1u);
        check_not_null(payload);
        memset(payload, 'x', tstr_len(payload));
        reply_size = 0u;
        start_server();
        check_not_equal(request("/header", "GET", NULL), SALTS_OK);
        check_equal(atomic_load(&calls), 1);
    }
    it("times out a deferred POST without resubmitting and drains its owner") {
        start_server();
        check_equal(request("/wait", "POST", NULL), SALTS_ETIMEDOUT);
        check_equal(atomic_load_explicit(&deferred_ready, memory_order_acquire), 1);
        check_equal(atomic_load(&calls), 1);
        release_client();
    }
    it("renders a bodyless response and retains its parsed headers") {
        reply_size = 0u;
        reply_status = 204u;
        start_server();
        check_equal(request("/status", "GET", NULL), SALTS_OK);
        check_equal(response.status_code, 204u);
        check_equal(response.body_size, (size_t)0u);
        release_client();
        check_equal(meshctl_rpc_send(addr, "/status", "GET", NULL, 0), 0);
        check_equal(atomic_load(&calls), 2);
    }
    it("fails a stopped endpoint and permits a fresh owner on the next call") {
        start_server();
        check_equal(chttp_server_stop(&server, 0u), SALTS_OK);
        check_not_equal(request("/status", "GET", NULL), SALTS_OK);
        release_client();
        tstr_freep(&addr);
        check_equal(chttp_server_destroy(&server), SALTS_OK);
        start_server();
        check_equal(request("/status", "GET", NULL), SALTS_OK);
        check_equal(atomic_load(&calls), 1);
    }
}
