#include "meshctl_controller_http.h"
#include "meshctl_controller_validation.h"
#include "meshctl_http_fixture.h"
#include <cmeta_fs.h>
#include <fmt.h>
#include <stdatomic.h>
#include <string.h>
#include <tinytest.h>
#ifndef _WIN32
#include <sys/stat.h>
#endif

#define MEDIA_TYPE MESHCTL_PRODUCT_MEDIA_TYPE
#define ROUTE "/v1/meshes/demo/nodes"

enum { SERVER_CA, SERVER_CERT, SERVER_KEY, CLIENT_CA, CLIENT_CERT, CLIENT_KEY,
       ROGUE_CERT, ROGUE_KEY, WRONG_CERT, WRONG_KEY, FILE_COUNT };
static const char *const files[FILE_COUNT] = {
    "server-ca.pem", "server.pem", "server.key.pem", "client-ca.pem",
    "client.pem", "client.key.pem", "rogue-client.pem", "rogue-client.key.pem",
    "wrong-host.pem", "wrong-host.key.pem"};
static char *paths[FILE_COUNT];
static chttp_server server;
static chttp_server_deferred deferred;
static meshctl_product_common_options_t options;
static meshctl_controller_response_t response;
static tstr payload, header_value;
static atomic_int calls, authenticated_h2, accept_ok, post_ok, deferred_ready;
static atomic_uint reply_status;

static int reply(void *user, const chttp_server_request_view *request,
                 chttp_server_response *out) {
    (void)user;
    const char *accept = chttp_server_request_header(request, "Accept");
    const char *content_type = chttp_server_request_header(request, "Content-Type");
    atomic_fetch_add(&calls, 1);
    atomic_store(&authenticated_h2, request->http_major == 2u &&
        request->peer_certificate_sha256 && strlen(request->peer_certificate_sha256) == 64u);
    atomic_store(&accept_ok, accept && strcmp(accept, MEDIA_TYPE) == 0);
    atomic_store(&post_ok, request->method == CHTTP_METHOD_POST && content_type &&
        strcmp(content_type, MEDIA_TYPE) == 0 && request->body_size == 2u &&
        memcmp(request->body, "{}", 2u) == 0);
    if (strcmp(request->path, "/v1/meshes/demo/wait") == 0) {
        int status = chttp_server_response_defer(out, &deferred);
        atomic_store_explicit(&deferred_ready, status == SALTS_OK, memory_order_release);
        return status;
    }
    if (strcmp(request->path, "/v1/meshes/demo/redirect") == 0) {
        int status = chttp_server_response_set_header(out, "Location", ROUTE);
        if (status != SALTS_OK) return status;
    }
    if (strcmp(request->path, "/v1/meshes/demo/header") == 0) {
        int status = chttp_server_response_set_header(out, "X-Large", header_value);
        if (status != SALTS_OK) return status;
    }
    return chttp_server_reply(out, atomic_load(&reply_status), MEDIA_TYPE,
                              payload, tstr_len(payload));
}

static void copy_credentials(void) {
    for (size_t i = 0; i < FILE_COUNT; ++i) {
        cmeta_fs_buf_t bytes = {0};
        tstr source = tstr_format("{}/{}", MESHCTL_CONTROLLER_TLS_DIR, files[i]);
        check_not_null(source);
        int status = cmeta_fs_read_file(source, &bytes);
        tstr_free(source);
        check_equal(status, SALTS_OK);
        paths[i] = tt_make_temp_file("mesh-controller", ".pem");
        if (!paths[i]) { cmeta_fs_buf_free(&bytes); check_not_null(paths[i]); }
        status = tt_write_file(paths[i], bytes.base, bytes.len);
        cmeta_fs_buf_free(&bytes);
        check_equal(status, 0);
#ifndef _WIN32
        check_equal(chmod(paths[i], S_IRUSR | S_IWUSR), 0);
#endif
    }
    check_less(strlen(paths[SERVER_CA]), sizeof(options.ca_file));
    check_less(strlen(paths[CLIENT_CERT]), sizeof(options.cert_file));
    check_less(strlen(paths[CLIENT_KEY]), sizeof(options.key_file));
    strcpy(options.ca_file, paths[SERVER_CA]);
    strcpy(options.cert_file, paths[CLIENT_CERT]);
    strcpy(options.key_file, paths[CLIENT_KEY]);
}

static void start_server(int h2, int wrong_host) {
    static const char *const h2_alpn[] = {"h2"};
    static const char *const h1_alpn[] = {"http/1.1"};
    uint16_t port = 0;
    cnet_tls_server_config tls = {0};
    chttp_server_config config = meshctl_test_http_server_config();
    config.network.tls_io_buffer_bytes = CNET_TLS_MIN_IO_BUFFER_BYTES;
    config.network.tls_handshake_timeout_ms = 2000u;
    config.network.max_send_bytes = MESHCTL_PRODUCT_MAX_RESPONSE_SIZE + 65536u;
    config.max_request_body_bytes = MESHCTL_PRODUCT_MAX_REQUEST_SIZE;
    config.max_response_body_bytes = MESHCTL_PRODUCT_MAX_RESPONSE_SIZE + 1u;
    config.max_response_header_bytes = MESHCTL_PRODUCT_MAX_RESPONSE_HEADER_SIZE + 1024u;
    config.enable_http2 = h2;
    if (h2) {
        config.h2_stream_capacity = 1u;
        config.h2_input_buffer_bytes = 128u * 1024u;
        config.h2_output_buffer_bytes = config.network.max_send_bytes;
        config.h2_hpack_dynamic_table_bytes = 4096u;
        config.h2_max_settings_count = 32u;
    }
    tls.size = sizeof(tls);
    tls.cert_file = paths[wrong_host ? WRONG_CERT : SERVER_CERT];
    tls.key_file = paths[wrong_host ? WRONG_KEY : SERVER_KEY];
    tls.ca_file = paths[CLIENT_CA];
    tls.client_auth = CNET_TLS_CLIENT_AUTH_REQUIRED;
    tls.alpn_protocols = h2 ? h2_alpn : h1_alpn;
    tls.alpn_protocol_count = 1u;
    config.tls = &tls;
    check_equal(chttp_server_init(&server, &config), SALTS_OK);
    check_equal(chttp_server_get(&server, ROUTE, reply, NULL), SALTS_OK);
    check_equal(chttp_server_get(&server, "/v1/meshes/demo/redirect", reply, NULL), SALTS_OK);
    check_equal(chttp_server_get(&server, "/v1/meshes/demo/wait", reply, NULL), SALTS_OK);
    check_equal(chttp_server_get(&server, "/v1/meshes/demo/header", reply, NULL), SALTS_OK);
    check_equal(chttp_server_post(&server, "/v1/meshes/demo/apply", reply, NULL), SALTS_OK);
    check_equal(chttp_server_start(&server), SALTS_OK);
    check_equal(chttp_server_port(&server, &port), SALTS_OK);
    tstr endpoint = tstr_format("https://127.0.0.1:{}", (unsigned int)port);
    check_not_null(endpoint);
    memcpy(options.endpoint, endpoint, tstr_len(endpoint) + 1u);
    tstr_free(endpoint);
}

static meshctl_controller_result_t get(const char *route, uint32_t timeout_ms) {
    return meshctl_controller_query_http2(NULL, &options, route, timeout_ms, &response);
}

spec("meshctl Controller CHttp H2 and mTLS") {
    before_each() {
        memset(&server, 0, sizeof(server));
        memset(&deferred, 0, sizeof(deferred));
        memset(&options, 0, sizeof(options));
        memset(&response, 0, sizeof(response));
        memset(paths, 0, sizeof(paths));
        atomic_init(&calls, 0);
        atomic_init(&authenticated_h2, 0);
        atomic_init(&accept_ok, 0);
        atomic_init(&post_ok, 0);
        atomic_init(&deferred_ready, 0);
        atomic_init(&reply_status, 200u);
        header_value = NULL;
        payload = tstr_dup("{\"nodes\":[]}");
        check_not_null(payload);
        copy_credentials();
    }
    after_each() {
        meshctl_controller_response_destroy(&response);
        if (atomic_load_explicit(&deferred_ready, memory_order_acquire)) {
            int status = chttp_server_deferred_cancel(&deferred);
            check_true(status == SALTS_OK || status == SALTS_ENOENT);
        }
        if (server.impl) {
            check_equal(chttp_server_stop(&server, 0u), SALTS_OK);
            check_equal(chttp_server_destroy(&server), SALTS_OK);
        }
        tstr_freep(&payload);
        tstr_freep(&header_value);
        for (size_t i = 0; i < FILE_COUNT; ++i) {
            if (paths[i]) { check_equal(tt_remove_file(paths[i]), 0); free(paths[i]); }
        }
    }
    it("returns an owned terminated JSON body after H2 mTLS transport drain") {
        start_server(1, 0);
        strcat(options.endpoint, "/");
        check_equal(get(ROUTE "?limit=25", 2000u), MESHCTL_CONTROLLER_OK);
        check_equal(response.status_code, 200);
        check_equal(response.body_size, tstr_len(payload));
        check_equal(response.body, payload);
        check_equal(atomic_load(&calls), 1);
        check_equal(atomic_load(&authenticated_h2), 1);
        check_equal(atomic_load(&accept_ok), 1);
        meshctl_controller_response_destroy(&response);
        check_null(response.body);
        check_equal(response.body_size, 0u);
        meshctl_controller_response_destroy(&response);
    }
    it("sends one typed POST and preserves an HTTP failure without replay") {
        meshctl_controller_request_t request = {
            MESHCTL_CONTROLLER_METHOD_POST, "/v1/meshes/demo/apply", MEDIA_TYPE, "{}", 2u};
        start_server(1, 0);
        atomic_store(&reply_status, 503u);
        check_equal(meshctl_controller_request_http2(NULL, &options, &request, 2000u,
                                                     &response), MESHCTL_CONTROLLER_OK);
        check_equal(response.status_code, 503);
        check_equal(atomic_load(&post_ok), 1);
        check_equal(atomic_load(&authenticated_h2), 1);
        check_equal(atomic_load(&calls), 1);
    }
    it("returns a redirect without following Location") {
        start_server(1, 0);
        atomic_store(&reply_status, 302u);
        check_equal(get("/v1/meshes/demo/redirect", 2000u), MESHCTL_CONTROLLER_OK);
        check_equal(response.status_code, 302);
        check_equal(atomic_load(&calls), 1);
    }
    it("rejects unrelated server trust before HTTP dispatch") {
        start_server(1, 0);
        strcpy(options.ca_file, paths[CLIENT_CA]);
        check_equal(get(ROUTE, 2000u), MESHCTL_CONTROLLER_TRANSPORT_ERROR);
        check_equal(atomic_load(&calls), 0);
        check_null(response.body);
    }
    it("rejects a trusted certificate with the wrong server identity") {
        start_server(1, 1);
        check_equal(get(ROUTE, 2000u), MESHCTL_CONTROLLER_TRANSPORT_ERROR);
        check_equal(atomic_load(&calls), 0);
        check_null(response.body);
    }
    it("rejects an untrusted operator certificate before dispatch") {
        start_server(1, 0);
        strcpy(options.cert_file, paths[ROGUE_CERT]);
        strcpy(options.key_file, paths[ROGUE_KEY]);
        check_equal(get(ROUTE, 2000u), MESHCTL_CONTROLLER_TRANSPORT_ERROR);
        check_equal(atomic_load(&calls), 0);
        check_null(response.body);
    }
    it("never falls back to an H1 only authenticated listener") {
        start_server(0, 0);
        check_equal(get(ROUTE, 2000u), MESHCTL_CONTROLLER_TRANSPORT_ERROR);
        check_equal(atomic_load(&calls), 0);
        check_null(response.body);
    }
    it("rejects an invalid JSON response and remains usable on a fresh call") {
        start_server(1, 0);
        tstr_freep(&payload);
        payload = tstr_dup("invalid");
        check_not_null(payload);
        check_equal(get(ROUTE, 2000u), MESHCTL_CONTROLLER_PROTOCOL_ERROR);
        check_null(response.body);
        /* Change reply storage only after the previous request and owner drained. */
        tstr_freep(&payload);
        payload = tstr_dup("{}");
        check_not_null(payload);
        check_equal(get(ROUTE, 2000u), MESHCTL_CONTROLLER_OK);
        check_equal(atomic_load(&calls), 2);
    }
    it("rejects empty responses as a protocol failure") {
        start_server(1, 0);
        tstr_freep(&payload);
        payload = tstr_new();
        check_not_null(payload);
        check_equal(get(ROUTE, 2000u), MESHCTL_CONTROLLER_PROTOCOL_ERROR);
        check_null(response.body);
    }
    it("enforces the response body bound over real H2 DATA frames") {
        tstr_freep(&payload);
        payload = tstr_repeat(" ", MESHCTL_PRODUCT_MAX_RESPONSE_SIZE + 1u);
        check_not_null(payload);
        memcpy(payload, "{}", 2u);
        start_server(1, 0);
        check_equal(get(ROUTE, 5000u), MESHCTL_CONTROLLER_TRANSPORT_ERROR);
        check_equal(atomic_load(&calls), 1);
        check_null(response.body);
    }
    it("accepts a valid JSON body exactly at the response capacity") {
        tstr_freep(&payload);
        payload = tstr_repeat(" ", MESHCTL_PRODUCT_MAX_RESPONSE_SIZE);
        check_not_null(payload);
        memcpy(payload, "{}", 2u);
        start_server(1, 0);
        check_equal(get(ROUTE, 5000u), MESHCTL_CONTROLLER_OK);
        check_equal(response.body_size, (size_t)MESHCTL_PRODUCT_MAX_RESPONSE_SIZE);
        check_equal(response.body, payload, response.body_size);
        check_equal(atomic_load(&calls), 1);
    }
    it("enforces the decoded H2 header bound") {
        header_value = tstr_repeat("x", MESHCTL_PRODUCT_MAX_RESPONSE_HEADER_SIZE + 1u);
        check_not_null(header_value);
        start_server(1, 0);
        check_equal(get("/v1/meshes/demo/header", 2000u), MESHCTL_CONTROLLER_TRANSPORT_ERROR);
        check_equal(atomic_load(&calls), 1);
        check_null(response.body);
    }
    it("times out and drains one admitted request without replay") {
        start_server(1, 0);
        check_equal(get("/v1/meshes/demo/wait", 1000u), MESHCTL_CONTROLLER_TIMEOUT);
        check_equal(atomic_load(&calls), 1);
        check_equal(atomic_load_explicit(&deferred_ready, memory_order_acquire), 1);
        check_null(response.body);
    }
    it("rejects invalid admission before any HTTP request") {
        start_server(1, 0);
        check_equal(get(ROUTE, 0u), MESHCTL_CONTROLLER_INVALID_ARGUMENT);
        check_equal(get(ROUTE, MESHCTL_PRODUCT_MAX_TIMEOUT_MS + 1u), MESHCTL_CONTROLLER_INVALID_ARGUMENT);
        check_equal(get(ROUTE "\r\nInjected: x", 2000u), MESHCTL_CONTROLLER_INVALID_ARGUMENT);
        meshctl_controller_request_t request = {
            MESHCTL_CONTROLLER_METHOD_GET, ROUTE, NULL, "{}", 2u};
        check_equal(meshctl_controller_request_http2(NULL, &options, &request, 2000u,
                                                     &response), MESHCTL_CONTROLLER_INVALID_ARGUMENT);
        request.method = MESHCTL_CONTROLLER_METHOD_POST;
        request.content_type = "application/json";
        check_equal(meshctl_controller_request_http2(NULL, &options, &request, 2000u,
                                                     &response), MESHCTL_CONTROLLER_INVALID_ARGUMENT);
        request.content_type = MEDIA_TYPE;
        request.body_size = MESHCTL_PRODUCT_MAX_REQUEST_SIZE + 1u;
        check_equal(meshctl_controller_request_http2(NULL, &options, &request, 2000u,
                                                     &response), MESHCTL_CONTROLLER_INVALID_ARGUMENT);
        strcpy(options.endpoint, "http://127.0.0.1:1");
        check_equal(get(ROUTE, 2000u), MESHCTL_CONTROLLER_INVALID_ARGUMENT);
        check_equal(atomic_load(&calls), 0);
    }
    it("shares bounded HTTPS origin validation with the product parser") {
        check_true(meshctl_controller_endpoint_valid("https://controller.example"));
        check_true(meshctl_controller_endpoint_valid("https://controller.example/"));
        check_true(meshctl_controller_endpoint_valid("https://[::1]:8443/"));
        check_false(meshctl_controller_endpoint_valid(NULL));
        check_false(meshctl_controller_endpoint_valid("https:controller.example"));
        check_false(meshctl_controller_endpoint_valid("http://controller.example"));
        check_false(meshctl_controller_endpoint_valid("https://user:secret@controller.example"));
        check_false(meshctl_controller_endpoint_valid("https://controller.example/v1"));
        check_false(meshctl_controller_endpoint_valid("https://controller.example/?query=x"));
        check_false(meshctl_controller_endpoint_valid("https://controller.example/#fragment"));
        check_false(meshctl_controller_endpoint_valid("https://controller.example:0"));
        check_false(meshctl_controller_endpoint_valid("https://controller.example:65536"));
        check_false(meshctl_controller_endpoint_valid("https://controller.example:9999999999999999999999"));
    }
    it("rejects absent operator credentials and can admit a subsequent valid call") {
        start_server(1, 0);
        options.key_file[0] = '\0';
        response.status_code = 17;
        check_equal(get(ROUTE, 2000u), MESHCTL_CONTROLLER_INVALID_ARGUMENT);
        check_equal(response.status_code, 17); /* invalid admission leaves output unchanged */
        check_equal(atomic_load(&calls), 0);
        strcpy(options.key_file, paths[CLIENT_KEY]);
        check_equal(get(ROUTE, 2000u), MESHCTL_CONTROLLER_OK);
        check_equal(response.status_code, 200);
        check_equal(atomic_load(&calls), 1);
    }
}
