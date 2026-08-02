#include <tinytest.h>

#define MESHD_NO_MAIN
#include "../examples/meshd.c"

static void meshd_test_reset_signal_state(void) {
    g_running = 1;
#ifndef _WIN32
    g_status_flush_requested = 0;
#endif
}

static void test_task_model_separates_data_plane_and_node_control(void) {
    meshd_task_model_t task = {0};

    meshd_classify_mgmt_task("GET", "/v1/status", &task);
    check_str_eq(task.type, "mesh.status.snapshot");
    check_str_eq(task.layer, "mesh_data_plane");
    check_str_eq(task.impact, "read");
    check_false(task.requires_token);
    check_true(task.safe_to_retry);

    meshd_classify_mgmt_task("POST", "/v1/shutdown", &task);
    check_str_eq(task.type, "node.shutdown");
    check_str_eq(task.layer, "node_control");
    check_str_eq(task.impact, "mutating");
    check_true(task.requires_token);
    check_false(task.safe_to_retry);

    meshd_classify_mgmt_task("POST", "/v1/executions", &task);
    check_str_eq(task.type, "node.execution.submit");
    check_str_eq(task.layer, "node_execution");
    check_str_eq(task.impact, "mutating");
    check_true(task.requires_token);
    check_true(task.safe_to_retry);

    meshd_classify_mgmt_task(
        "GET",
        "/v1/executions/"
        "7171717171717171717171717171717171717171717171717171717171717171",
        &task);
    check_str_eq(task.type, "node.execution.query");
    check_str_eq(task.layer, "node_execution");
    check_str_eq(task.impact, "read");
    check_true(task.requires_token);
    check_true(task.safe_to_retry);
}

static void test_unknown_task_fails_closed(void) {
    meshd_task_model_t task = {0};

    meshd_classify_mgmt_task("POST", "/v1/unknown", &task);

    check_str_eq(task.type, "unknown");
    check_str_eq(task.layer, "unknown");
    check_str_eq(task.impact, "unknown");
    check_true(task.requires_token);
}

static void test_task_response_preserves_the_control_contract(void) {
    meshd_task_model_t task = {
        "node.shutdown",
        "node_control",
        "mutating",
        1,
        0,
    };
    char response[512] = {0};

    check_int_eq(meshd_build_task_response_json(response,
                                                sizeof(response),
                                                "task-42",
                                                &task,
                                                1,
                                                "{\"action\":\"shutdown\"}",
                                                NULL,
                                                NULL),
                 0);
    check_str_contains(response, "\"ok\":true");
    check_str_contains(response, "\"id\":\"task-42\"");
    check_str_contains(response, "\"target_layer\":\"node_control\"");
    check_str_contains(response, "\"safe_to_retry\":false");
    check_str_contains(response, "\"result\":{\"action\":\"shutdown\"}");
}

static void test_task_response_rejects_truncated_json(void) {
    meshd_task_model_t task = {
        "mesh.status.snapshot",
        "mesh_data_plane",
        "read",
        0,
        1,
    };
    char response[32] = "stale";

    check_int_eq(meshd_build_task_response_json(response,
                                                sizeof(response),
                                                "task-oversized",
                                                &task,
                                                1,
                                                "{\"payload\":\"too-large\"}",
                                                NULL,
                                                NULL),
                 -1);
    check_str_eq(response, "");
}

static void test_rpc_listen_parser_accepts_unambiguous_ipv4_endpoints(void) {
    char host[64] = {0};
    uint16_t port = 0;

    check_int_eq(meshd_parse_host_port("127.0.0.1:29090",
                                       host,
                                       sizeof(host),
                                       &port),
                 0);
    check_str_eq(host, "127.0.0.1");
    check_uint_eq(port, 29090);

    check_int_eq(meshd_parse_host_port(":29091",
                                       host,
                                       sizeof(host),
                                       &port),
                 0);
    check_str_eq(host, "127.0.0.1");
    check_uint_eq(port, 29091);
}

static void test_rpc_listen_parser_rejects_ambiguous_endpoints(void) {
    char host[64] = "stale";
    char small_host[4] = "old";
    uint16_t port = 42;

    check_int_eq(meshd_parse_host_port("127.0.0.1:29090junk",
                                       host,
                                       sizeof(host),
                                       &port),
                 -1);
    check_str_eq(host, "");
    check_uint_eq(port, 0);

    check_int_eq(meshd_parse_host_port("127.0.0.1:",
                                       host,
                                       sizeof(host),
                                       &port),
                 -1);
    check_int_eq(meshd_parse_host_port("127.0.0.1:65536",
                                       host,
                                       sizeof(host),
                                       &port),
                 -1);
    check_int_eq(meshd_parse_host_port("127.0.0.1:29090",
                                       small_host,
                                       sizeof(small_host),
                                       &port),
                 -1);
    check_str_eq(small_host, "");
    check_uint_eq(port, 0);
}

static void test_rpc_service_endpoint_uses_only_the_virtual_address(void) {
    meshd_mgmt_server_t server = {0};

    snprintf(server.bind_host, sizeof(server.bind_host), "%s", "192.168.10.20");
    server.bind_port = 29090;

    check_int_eq(meshd_mgmt_configure_service_endpoint(&server,
                                                       NULL,
                                                       "10.42.0.9",
                                                       29090),
                 0);
    check_str_eq(server.virtual_host, "10.42.0.9");
    check_uint_eq(server.service_port, 29090);
    check_str_eq(server.service_endpoint, "http://10.42.0.9:29090");
    check_null(strstr(server.service_endpoint, server.bind_host));
}

static meshd_service_resolve_result_t test_verified_service_resolver(
    void *context,
    const char node_id_hex[MESHD_NODE_ID_HEX_LENGTH + 1],
    meshd_verified_service_snapshot_t *out_snapshot) {
    const char *expected_node_id = (const char *)context;

    if (!expected_node_id || !out_snapshot ||
        strcmp(node_id_hex, expected_node_id) != 0) {
        return MESHD_SERVICE_RESOLVE_NOT_FOUND;
    }
    snprintf(out_snapshot->virtual_host,
             sizeof(out_snapshot->virtual_host),
             "%s",
             "node-b.mesh");
    snprintf(out_snapshot->virtual_ip,
             sizeof(out_snapshot->virtual_ip),
             "%s",
             "10.42.0.10");
    out_snapshot->port = 7878;
    out_snapshot->record_epoch = 7;
    out_snapshot->expires_at_ms = 9000;
    return MESHD_SERVICE_RESOLVE_OK;
}

static void test_node_resolve_exposes_only_verified_virtual_service(void) {
    static const char NODE_ID[] =
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";
    char path[96] = {0};
    char result[1024] = {0};
    meshd_mgmt_server_t server = {0};
    meshd_task_model_t task = {0};

    snprintf(path, sizeof(path), "/v1/node/resolve/%s", NODE_ID);
    server.resolve_service = test_verified_service_resolver;
    server.resolve_service_context = (void *)NODE_ID;

    meshd_classify_mgmt_task("GET", path, &task);
    check_str_eq(task.type, "node.resolve");
    check_str_eq(task.layer, "mesh_data_plane");
    check_true(task.requires_token);
    check_true(task.safe_to_retry);
    check_int_eq(meshd_resolve_node_service_json(&server,
                                                 path,
                                                 result,
                                                 sizeof(result)),
                 MESHD_SERVICE_RESOLVE_OK);
    check_str_contains(result, "\"virtual_host\":\"node-b.mesh\"");
    check_str_contains(result, "\"virtual_ip\":\"10.42.0.10\"");
    check_str_contains(result, "\"port\":7878");
    check_str_contains(result, "\"source\":\"verified_service_record\"");
    check_null(strstr(result, "bind"));
    check_null(strstr(result, "advertise"));
    check_null(strstr(result, "transport"));
}

static void test_node_resolve_fails_closed_without_verified_resolver(void) {
    static const char PATH[] =
        "/v1/node/resolve/"
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";
    char result[1024] = "stale";
    meshd_mgmt_server_t server = {0};

    check_int_eq(meshd_resolve_node_service_json(&server,
                                                 PATH,
                                                 result,
                                                 sizeof(result)),
                 MESHD_SERVICE_RESOLVE_UNAVAILABLE);
    check_str_eq(result, "");
    check_int_eq(meshd_parse_node_resolve_path(
                     "/v1/node/resolve/"
                     "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8F",
                     NULL),
                 -1);
}

static void test_status_publishes_rpc_service_not_internal_bind(void) {
    char status[MESHD_MGMT_RESPONSE_BUF_SIZE] = {0};

    memset(&g_config, 0, sizeof(g_config));
    memset(&g_mgmt_server, 0, sizeof(g_mgmt_server));
    g_mesh = NULL;
    g_started_ms = meshd_now_ms();
    snprintf(g_config.node_name, sizeof(g_config.node_name), "%s", "node-a");
    snprintf(g_config.network_id, sizeof(g_config.network_id), "%s", "mesh-a");
    snprintf(g_config.virtual_ip, sizeof(g_config.virtual_ip), "%s", "10.42.0.9");
    g_config.listen_port = 9000;
    snprintf(g_mgmt_server.bind_host,
             sizeof(g_mgmt_server.bind_host),
             "%s",
             "192.168.10.20");
    g_mgmt_server.bind_port = 29090;
    check_int_eq(meshd_mgmt_configure_service_endpoint(&g_mgmt_server,
                                                       NULL,
                                                       g_config.virtual_ip,
                                                       29090),
                 0);

    check_int_eq(meshd_build_status_json(status, sizeof(status)), 0);
    check_str_contains(status, "\"endpoint\":\"http://10.42.0.9:29090\"");
    check_str_contains(status, "\"virtual_host\":\"10.42.0.9\"");
    check_null(strstr(status, g_mgmt_server.bind_host));
}

static void test_rpc_token_accepts_only_an_exact_header(void) {
    meshd_mgmt_server_t server = {0};

    snprintf(server.token, sizeof(server.token), "%s", "control-secret");

    check_true(meshd_check_token(
        &server,
        "POST /v1/shutdown HTTP/1.1\r\n"
        "x-meshd-token:\tcontrol-secret \r\n"
        "\r\n"));
    check_false(meshd_check_token(
        &server,
        "POST /v1/shutdown HTTP/1.1\r\n"
        "X-Fake-X-Meshd-Token: control-secret\r\n"
        "\r\n"));
    check_false(meshd_check_token(
        &server,
        "POST /v1/shutdown HTTP/1.1\r\n"
        "Content-Length: 29\r\n"
        "\r\n"
        "X-Meshd-Token: control-secret"));
    check_false(meshd_check_token(
        &server,
        "POST /v1/shutdown HTTP/1.1\r\n"
        "X-Meshd-Token: control-secret\r\n"
        "X-Meshd-Token: control-secret\r\n"
        "\r\n"));
}

static void test_rpc_token_is_optional_only_when_unconfigured(void) {
    meshd_mgmt_server_t server = {0};

    check_true(meshd_check_token(
        &server,
        "GET /v1/status HTTP/1.1\r\n"
        "\r\n"));

    snprintf(server.token, sizeof(server.token), "%s", "control-secret");
    check_false(meshd_check_token(
        &server,
        "POST /v1/shutdown HTTP/1.1\r\n"
        "\r\n"));
}

static void test_management_config_requires_complete_enrollment_material(void) {
    mesh_node_config_t config;

    mesh_node_config_init(&config);
    snprintf(config.mgmt_private_key_file,
             sizeof(config.mgmt_private_key_file),
             "%s",
             "management.key");
    check_false(mesh_node_config_management_enabled(&config));
    check_int_eq(mesh_node_config_validate(&config), -1);

    snprintf(config.identity_secret_hex,
             sizeof(config.identity_secret_hex),
             "%064x",
             1);
    snprintf(config.mgmt_certificate_file,
             sizeof(config.mgmt_certificate_file),
             "%s",
             "management.cert");
    snprintf(config.mgmt_trusted_issuer_key_file,
             sizeof(config.mgmt_trusted_issuer_key_file),
             "%s",
             "management.issuer");
    snprintf(config.mgmt_mesh_id_hex,
             sizeof(config.mgmt_mesh_id_hex),
             "%064x",
             2);
    config.mgmt_first_record_epoch = 7u;
    check_false(mesh_node_config_management_enabled(&config));
    check_int_eq(mesh_node_config_validate(&config), -1);
    snprintf(config.mgmt_record_epoch_file,
             sizeof(config.mgmt_record_epoch_file),
             "%s",
             "management.epoch");
    check_true(mesh_node_config_management_enabled(&config));
    check_int_eq(mesh_node_config_validate(&config), 0);

    snprintf(config.mgmt_execution_grant_issuer_key_file,
             sizeof(config.mgmt_execution_grant_issuer_key_file),
             "%s",
             "execution-grant.issuer");
    check_true(mesh_node_config_management_enabled(&config));
    check_int_eq(mesh_node_config_validate(&config), 0);
}

static void test_execution_issuer_requires_management_enrollment(void) {
    mesh_node_config_t config;

    mesh_node_config_init(&config);
    snprintf(config.mgmt_execution_grant_issuer_key_file,
             sizeof(config.mgmt_execution_grant_issuer_key_file),
             "%s",
             "execution-grant.issuer");
    check_false(mesh_node_config_management_enabled(&config));
    check_int_eq(mesh_node_config_validate(&config), -1);
}

static void test_management_epoch_state_rejects_corrupt_data(void) {
    meshd_management_epoch_state_t state;
    char lock_path[TURBO_FS_MAX_PATH + 6];
    char *epoch_path = tt_make_temp_file("meshd-mgmt-epoch-corrupt", ".txt");

    check_not_null(epoch_path);
    if (!epoch_path) {
        return;
    }
    check_int_eq(tt_write_file(epoch_path, "not-an-epoch\n", 13u), 0);
    memset(&state, 0, sizeof(state));
    check_int_eq(meshd_management_epoch_open(&state, epoch_path, 1u), -1);
    check_false(state.initialized);
    snprintf(lock_path, sizeof(lock_path), "%s.lock", epoch_path);
    (void)tt_remove_file(epoch_path);
    (void)tt_remove_file(lock_path);
    free(epoch_path);
}

static void test_management_epoch_state_excludes_a_second_process(void) {
    meshd_management_epoch_state_t first;
    meshd_management_epoch_state_t second;
    char lock_path[TURBO_FS_MAX_PATH + 6];
    char *epoch_path = tt_make_temp_file("meshd-mgmt-epoch-lock", ".txt");

    check_not_null(epoch_path);
    if (!epoch_path) {
        return;
    }
    check_int_eq(tt_remove_file(epoch_path), 0);
    memset(&first, 0, sizeof(first));
    memset(&second, 0, sizeof(second));
    check_int_eq(meshd_management_epoch_open(&first, epoch_path, 10u), 0);
    check_int_eq(meshd_management_epoch_open(&second, epoch_path, 10u), -1);
    check_false(second.initialized);
    meshd_management_epoch_close(&first);
    check_int_eq(meshd_management_epoch_open(&second, epoch_path, 10u), 0);
    check_hex64_eq(second.next_epoch, 10u);
    meshd_management_epoch_close(&second);

    snprintf(lock_path, sizeof(lock_path), "%s.lock", epoch_path);
    (void)tt_remove_file(epoch_path);
    (void)tt_remove_file(lock_path);
    free(epoch_path);
}

static void test_management_hex_decoder_is_exact(void) {
    uint8_t bytes[2] = {0};

    check_int_eq(meshd_decode_hex_exact("0aFf", bytes, sizeof(bytes)), 0);
    check_uint_eq(bytes[0], 0x0a);
    check_uint_eq(bytes[1], 0xff);
    check_int_eq(meshd_decode_hex_exact("0af", bytes, sizeof(bytes)), -1);
    check_int_eq(meshd_decode_hex_exact("0axf", bytes, sizeof(bytes)), -1);
}

static int meshd_test_pick_loopback_ports(unsigned short *out_port1,
                                          unsigned short *out_port2) {
    struct sockaddr_in address1;
    struct sockaddr_in address2;
#ifdef _WIN32
    int address1_len = (int)sizeof(address1);
    int address2_len = (int)sizeof(address2);
    SOCKET socket1 = INVALID_SOCKET;
    SOCKET socket2 = INVALID_SOCKET;
    WSADATA winsock_data;
#else
    socklen_t address1_len = (socklen_t)sizeof(address1);
    socklen_t address2_len = (socklen_t)sizeof(address2);
    int socket1 = -1;
    int socket2 = -1;
#endif

    if (!out_port1 || !out_port2) {
        return -1;
    }
    *out_port1 = 0u;
    *out_port2 = 0u;
    memset(&address1, 0, sizeof(address1));
    memset(&address2, 0, sizeof(address2));
    address1.sin_family = AF_INET;
    address1.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address2.sin_family = AF_INET;
    address2.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#ifdef _WIN32
    if (WSAStartup(MAKEWORD(2, 2), &winsock_data) != 0) {
        return -1;
    }
#endif
    socket1 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    socket2 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#ifdef _WIN32
    if (socket1 == INVALID_SOCKET || socket2 == INVALID_SOCKET) {
        goto cleanup;
    }
#else
    if (socket1 < 0 || socket2 < 0) {
        goto cleanup;
    }
#endif
    if (bind(socket1, (struct sockaddr *)&address1, sizeof(address1)) != 0 ||
        getsockname(socket1, (struct sockaddr *)&address1, &address1_len) != 0 ||
        bind(socket2, (struct sockaddr *)&address2, sizeof(address2)) != 0 ||
        getsockname(socket2, (struct sockaddr *)&address2, &address2_len) != 0) {
        goto cleanup;
    }
    *out_port1 = ntohs(address1.sin_port);
    *out_port2 = ntohs(address2.sin_port);

cleanup:
#ifdef _WIN32
    if (socket2 != INVALID_SOCKET) {
        closesocket(socket2);
    }
    if (socket1 != INVALID_SOCKET) {
        closesocket(socket1);
    }
    WSACleanup();
#else
    if (socket2 >= 0) {
        close(socket2);
    }
    if (socket1 >= 0) {
        close(socket1);
    }
#endif
    return *out_port1 != 0u && *out_port2 != 0u ? 0 : -1;
}

static void meshd_test_hex_encode(const uint8_t *bytes,
                                  size_t bytes_len,
                                  char *output) {
    static const char HEX[] = "0123456789abcdef";
    size_t index;

    for (index = 0u; index < bytes_len; index++) {
        output[index * 2u] = HEX[bytes[index] >> 4u];
        output[index * 2u + 1u] = HEX[bytes[index] & 0x0fu];
    }
    output[bytes_len * 2u] = '\0';
}

static int meshd_test_write_hex_file(const char *path,
                                     const uint8_t *bytes,
                                     size_t bytes_len) {
    char *encoded;
    int result;

    encoded = (char *)malloc(bytes_len * 2u + 1u);
    if (!encoded) {
        return -1;
    }
    meshd_test_hex_encode(bytes, bytes_len, encoded);
    result = tt_write_file(path, encoded, bytes_len * 2u);
    free(encoded);
    return result;
}

static int meshd_test_issue_node_certificate(
    const uint8_t issuer_private_key[32],
    const uint8_t management_private_key[32],
    const uint8_t transport_peer_id[32],
    const uint8_t managed_node_id[32],
    const uint8_t mesh_id_hash[32],
    uint64_t serial,
    uint8_t certificate[MESH_MGMT_CERTIFICATE_V1_SIZE]) {
    mesh_mgmt_certificate_claims_v1_t claims;
    size_t certificate_len = 0u;
    uint64_t now_ms = turbo_realtime_ms();

    memset(&claims, 0, sizeof(claims));
    claims.principal_type = MESH_MGMT_PRINCIPAL_NODE;
    if (mesh_mgmt_ed25519_public_from_private(
            management_private_key, claims.management_key) !=
        MESH_MGMT_CRYPTO_OK) {
        return -1;
    }
    memcpy(claims.transport_peer_id, transport_peer_id,
           sizeof(claims.transport_peer_id));
    memcpy(claims.managed_node_id, managed_node_id,
           sizeof(claims.managed_node_id));
    memcpy(claims.mesh_id_hash, mesh_id_hash, sizeof(claims.mesh_id_hash));
    claims.roles = MESH_MGMT_ROLE_OPERATOR;
    claims.not_before_ms = now_ms - 1000u;
    claims.expires_at_ms = now_ms + 600000u;
    claims.serial = serial;
    claims.principal_epoch = 1u;
    return mesh_mgmt_certificate_issue_v1(
               &claims, issuer_private_key, certificate,
               MESH_MGMT_CERTIFICATE_V1_SIZE, &certificate_len) ==
                   MESH_MGMT_IDENTITY_OK &&
               certificate_len == MESH_MGMT_CERTIFICATE_V1_SIZE
           ? 0
           : -1;
}

typedef struct {
    mesh_mgmt_agent_runtime_v1_t *runtime;
    size_t disabled_response_count;
    size_t failure_count;
} meshd_test_disabled_runtime_context_t;

static void meshd_test_disabled_runtime_failure(
    void *context,
    p2p_peer_t *peer,
    mesh_mgmt_agent_router_result_t router_result,
    mesh_mgmt_p2p_peer_result_t peer_result) {
    meshd_test_disabled_runtime_context_t *runtime_context =
        (meshd_test_disabled_runtime_context_t *)context;

    (void)peer;
    (void)router_result;
    (void)peer_result;
    if (!runtime_context) {
        return;
    }
    runtime_context->failure_count++;
}

static int meshd_test_disabled_runtime_event(
    void *context,
    p2p_peer_t *peer,
    const uint8_t remote_transport_peer_id[P2P_KEY_SIZE],
    const mesh_mgmt_dispatch_event_v1_t *event) {
    meshd_test_disabled_runtime_context_t *runtime_context =
        (meshd_test_disabled_runtime_context_t *)context;

    (void)remote_transport_peer_id;
    if (!runtime_context || !runtime_context->runtime || !peer || !event) {
        return -1;
    }
    if (event->type !=
        MESH_MGMT_DISPATCH_EVENT_NODE_EXECUTION_REQUEST_SHADOW) {
        return 0;
    }
    if (mesh_mgmt_agent_runtime_send_execution_disabled_from_event_v1(
            runtime_context->runtime, peer, event, turbo_realtime_ms()) !=
        MESH_MGMT_EXECUTION_DISABLED_RESPONDER_OK) {
        return -1;
    }
    runtime_context->disabled_response_count++;
    return 0;
}

static size_t meshd_test_make_execution_request(
    const uint8_t issuer_private_key[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    const uint8_t mesh_id[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    const uint8_t subject_key[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    const uint8_t target_node_id[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    uint64_t now_ms,
    uint8_t output[MESH_MGMT_EXECUTION_COMMAND_REQUEST_MAX_SIZE_V1]) {
    mesh_mgmt_execution_grant_v1_t grant;
    mesh_mgmt_execution_request_v1_t request;
    size_t output_size = 0u;

    memset(&grant, 0, sizeof(grant));
    memset(&request, 0, sizeof(request));
    grant.version = MESH_MGMT_EXECUTION_SCHEMA_V1;
    memset(grant.grant_id, 0x11, sizeof(grant.grant_id));
    memcpy(grant.mesh_id, mesh_id, sizeof(grant.mesh_id));
    grant.policy_epoch = 1u;
    memcpy(grant.subject_principal, subject_key,
           sizeof(grant.subject_principal));
    memcpy(grant.target_node_id, target_node_id,
           sizeof(grant.target_node_id));
    memset(grant.deployment_id, 0x21, sizeof(grant.deployment_id));
    grant.deployment_generation = 1u;
    memset(grant.package_digest, 0x31, sizeof(grant.package_digest));
    grant.operation = MESH_MGMT_EXECUTION_OPERATION_RUN_PRESTAGED_WASM;
    grant.capabilities = MESH_MGMT_EXECUTION_CAP_CORE;
    grant.max_limits.module_bytes = 1024u;
    grant.max_limits.stack_bytes = 1024u;
    grant.max_limits.linear_memory_bytes = 4096u;
    grant.max_limits.timeout_ms = 100u;
    grant.max_limits.control_flow_steps = 1000u;
    grant.max_limits.host_calls = 4u;
    grant.max_limits.copied_guest_bytes = 1024u;
    grant.max_limits.input_bytes = 64u;
    grant.max_limits.stdout_bytes = 64u;
    grant.max_limits.stderr_bytes = 64u;
    grant.not_before_ms = now_ms - 1000u;
    grant.expires_at_ms = now_ms + 90000u;
    if (mesh_mgmt_execution_grant_sign_v1(&grant, issuer_private_key) !=
        MESH_MGMT_EXECUTION_WIRE_OK) {
        return 0u;
    }

    request.version = MESH_MGMT_EXECUTION_SCHEMA_V1;
    memset(request.command_id, 0x41, sizeof(request.command_id));
    memcpy(request.grant_id, grant.grant_id, sizeof(request.grant_id));
    memcpy(request.target_node_id, grant.target_node_id,
           sizeof(request.target_node_id));
    memcpy(request.deployment_id, grant.deployment_id,
           sizeof(request.deployment_id));
    request.deployment_generation = grant.deployment_generation;
    memcpy(request.package_digest, grant.package_digest,
           sizeof(request.package_digest));
    request.input_kind = MESH_MGMT_EXECUTION_INPUT_INLINE;
    memset(request.input_digest, 0x51, sizeof(request.input_digest));
    memcpy(request.inline_input, "input", 5u);
    request.inline_input_size = 5u;
    request.input_length = 5u;
    request.output_mode = MESH_MGMT_EXECUTION_OUTPUT_DIGEST;
    request.deadline_ms = now_ms + 60000u;
    memset(request.request_nonce, 0x61, sizeof(request.request_nonce));
    memset(request.correlation_id, 0x71, sizeof(request.correlation_id));
    if (mesh_mgmt_execution_command_request_encode_v1(
            &grant, &request, output,
            MESH_MGMT_EXECUTION_COMMAND_REQUEST_MAX_SIZE_V1,
            &output_size) != MESH_MGMT_EXECUTION_WIRE_OK) {
        return 0u;
    }
    return output_size;
}

static int meshd_test_prepare_management_templates(
    mesh_mgmt_peer_signer_config_v1_t *signer,
    mesh_mgmt_dispatch_config_v1_t *dispatch,
    const uint8_t management_private_key[32],
    const uint8_t trusted_issuer_key[32],
    const uint8_t execution_grant_issuer_key[32],
    const uint8_t mesh_id_hash[32],
    const uint8_t transport_peer_id[32],
    const uint8_t managed_node_id[32],
    const uint8_t certificate[MESH_MGMT_CERTIFICATE_V1_SIZE]) {
    uint8_t management_public_key[32];

    memset(signer, 0, sizeof(*signer));
    memset(dispatch, 0, sizeof(*dispatch));
    if (mesh_mgmt_ed25519_public_from_private(
            management_private_key, management_public_key) !=
            MESH_MGMT_CRYPTO_OK ||
        mesh_mgmt_blake2b_256(trusted_issuer_key, 32u,
                              signer->hello.issuer_chain_hash) !=
            MESH_MGMT_CRYPTO_OK) {
        return -1;
    }
    memcpy(signer->private_key, management_private_key,
           sizeof(signer->private_key));
    memcpy(signer->trusted_issuer_key, trusted_issuer_key,
           sizeof(signer->trusted_issuer_key));
    memcpy(signer->expected_mesh_id_hash, mesh_id_hash,
           sizeof(signer->expected_mesh_id_hash));
    memcpy(signer->local_transport_peer_id, transport_peer_id,
           sizeof(signer->local_transport_peer_id));
    signer->hello.major = MESH_MGMT_MAJOR_V1;
    signer->hello.min_minor = MESH_MGMT_MINOR_V1;
    signer->hello.max_minor = MESH_MGMT_MINOR_V1;
    signer->hello.features =
        MESH_MGMT_FEATURE_MEMBERSHIP |
        MESH_MGMT_FEATURE_TARGETED_RPC |
        MESH_MGMT_FEATURE_NODE_EXECUTION;
    signer->hello.platform = MESH_MGMT_PLATFORM_OTHER;
    memcpy(signer->hello.build_version, "meshd-test", 10u);
    signer->hello.build_version_len = 10u;
    memcpy(signer->hello.certificate, certificate,
           sizeof(signer->hello.certificate));
    signer->hello.principal_type = MESH_MGMT_PRINCIPAL_NODE;
    memcpy(signer->hello.management_key, management_public_key,
           sizeof(signer->hello.management_key));
    memcpy(signer->hello.managed_node_id, managed_node_id,
           sizeof(signer->hello.managed_node_id));
    memset(signer->hello.connection_id, 0x71,
           sizeof(signer->hello.connection_id));
    signer->hello.max_frame = MESH_MGMT_FRAME_MAX;
    signer->hello.max_digest_entries = 64u;
    signer->hello.max_delta_batch = 32u;
    memset(signer->session_id, 0x61, sizeof(signer->session_id));
    signer->incarnation = turbo_realtime_ms();
    signer->first_sequence = 1u;
    signer->frame_ttl_ms = MESHD_MGMT_FRAME_TTL_MS;

    memcpy(dispatch->session.expected_mesh_id_hash, mesh_id_hash,
           sizeof(dispatch->session.expected_mesh_id_hash));
    memcpy(dispatch->session.trusted_issuer_key, trusted_issuer_key,
           sizeof(dispatch->session.trusted_issuer_key));
    dispatch->session.min_minor = MESH_MGMT_MINOR_V1;
    dispatch->session.max_minor = MESH_MGMT_MINOR_V1;
    dispatch->session.features = signer->hello.features;
    memcpy(dispatch->session.connection_id, signer->hello.connection_id,
           sizeof(dispatch->session.connection_id));
    dispatch->session.max_frame = signer->hello.max_frame;
    dispatch->session.max_digest_entries = 64u;
    dispatch->session.max_delta_batch = 32u;
    dispatch->replay.capacity = MESHD_MGMT_REPLAY_CAPACITY;
    dispatch->replay.ttl_ms = MESHD_MGMT_REPLAY_TTL_MS;
    dispatch->enable_node_execution_shadow = 1u;
    memcpy(dispatch->node_execution_grant_issuer_key,
           execution_grant_issuer_key,
           sizeof(dispatch->node_execution_grant_issuer_key));
    mesh_mgmt_crypto_wipe(management_public_key,
                          sizeof(management_public_key));
    return 0;
}

static void test_production_management_loader_resolves_remote_signed_service(void) {
    static const uint8_t ISSUER_PRIVATE_KEY[32] = {
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
        0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
        0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
    };
    static const uint8_t MANAGEMENT_KEY1[32] = {
        1u, 3u, 5u, 7u, 9u, 11u, 13u, 15u,
        17u, 19u, 21u, 23u, 25u, 27u, 29u, 31u,
        2u, 4u, 6u, 8u, 10u, 12u, 14u, 16u,
        18u, 20u, 22u, 24u, 26u, 28u, 30u, 32u,
    };
    static const uint8_t MANAGEMENT_KEY2[32] = {
        32u, 30u, 28u, 26u, 24u, 22u, 20u, 18u,
        16u, 14u, 12u, 10u, 8u, 6u, 4u, 2u,
        31u, 29u, 27u, 25u, 23u, 21u, 19u, 17u,
        15u, 13u, 11u, 9u, 7u, 5u, 3u, 1u,
    };
    static const uint8_t EXECUTION_GRANT_PRIVATE_KEY[32] = {
        0x81u, 0x81u, 0x81u, 0x81u, 0x81u, 0x81u, 0x81u, 0x81u,
        0x81u, 0x81u, 0x81u, 0x81u, 0x81u, 0x81u, 0x81u, 0x81u,
        0x81u, 0x81u, 0x81u, 0x81u, 0x81u, 0x81u, 0x81u, 0x81u,
        0x81u, 0x81u, 0x81u, 0x81u, 0x81u, 0x81u, 0x81u, 0x81u,
    };
    mesh_config_t mesh_config1;
    mesh_config_t mesh_config2;
    mesh_node_config_t daemon_config1;
    mesh_network_t *mesh1 = NULL;
    mesh_network_t *mesh2 = NULL;
    mesh_mgmt_peer_signer_config_v1_t signer2;
    mesh_mgmt_dispatch_config_v1_t dispatch2;
    mesh_mgmt_agent_runtime_config_v1_t runtime_config2;
    mesh_mgmt_agent_runtime_v1_t runtime2;
    meshd_test_disabled_runtime_context_t disabled_runtime_context2;
    mesh_mgmt_agent_router_identity_snapshot_v1_t identity_snapshot;
    mesh_mgmt_execution_rpc_binding_v1_t execution_binding;
    mesh_mgmt_execution_rpc_completion_v1_t execution_completion;
    mesh_mgmt_service_publish_v1_t service;
    meshd_verified_service_snapshot_t resolved;
    const char *bootstraps2[1];
    char endpoint1[64];
    char transport_secret_hex1[65];
    char transport_secret_hex2[65];
    char mesh_id_hex[65];
    char managed_node_id2_hex[65];
    char *management_key_path = NULL;
    char *certificate_path = NULL;
    char *issuer_path = NULL;
    char *execution_issuer_path = NULL;
    char *epoch_path = NULL;
    uint8_t transport_secret1[32];
    uint8_t transport_secret2[32];
    uint8_t transport_peer_id1[32];
    uint8_t transport_peer_id2[32];
    uint8_t managed_node_id1[32];
    uint8_t managed_node_id2[32];
    uint8_t mesh_id_hash[32];
    uint8_t issuer_public_key[32];
    uint8_t execution_grant_public_key[32];
    uint8_t management_public_key1[32];
    uint8_t certificate1[MESH_MGMT_CERTIFICATE_V1_SIZE];
    uint8_t certificate2[MESH_MGMT_CERTIFICATE_V1_SIZE];
    uint8_t execution_payload[
        MESH_MGMT_EXECUTION_COMMAND_REQUEST_MAX_SIZE_V1];
    size_t execution_payload_size = 0u;
    uint64_t record_epoch = 0u;
    uint64_t local_record_epoch = 0u;
    uint64_t deadline;
    unsigned short port1 = 0u;
    unsigned short port2 = 0u;
    int management1_started = 0;
    int runtime2_initialized = 0;
    int runtime2_started = 0;
    int mesh1_started = 0;
    int mesh2_started = 0;
    int sessions_established = 0;
    int execution_completed = 0;
    meshd_service_resolve_result_t resolve_result =
        MESHD_SERVICE_RESOLVE_NOT_FOUND;

    memset(&signer2, 0, sizeof(signer2));
    memset(&dispatch2, 0, sizeof(dispatch2));
    memset(&runtime_config2, 0, sizeof(runtime_config2));
    memset(&runtime2, 0, sizeof(runtime2));
    memset(&disabled_runtime_context2, 0,
           sizeof(disabled_runtime_context2));
    memset(&identity_snapshot, 0, sizeof(identity_snapshot));
    memset(&execution_binding, 0, sizeof(execution_binding));
    memset(&execution_completion, 0, sizeof(execution_completion));
    memset(&service, 0, sizeof(service));
    memset(&resolved, 0, sizeof(resolved));
    memset(transport_secret1, 0x11, sizeof(transport_secret1));
    memset(transport_secret2, 0x22, sizeof(transport_secret2));
    memset(managed_node_id1, 0x51, sizeof(managed_node_id1));
    memset(managed_node_id2, 0x52, sizeof(managed_node_id2));
    memset(mesh_id_hash, 0x42, sizeof(mesh_id_hash));
    meshd_test_hex_encode(transport_secret1, sizeof(transport_secret1),
                          transport_secret_hex1);
    meshd_test_hex_encode(transport_secret2, sizeof(transport_secret2),
                          transport_secret_hex2);
    meshd_test_hex_encode(mesh_id_hash, sizeof(mesh_id_hash), mesh_id_hex);
    meshd_test_hex_encode(managed_node_id2, sizeof(managed_node_id2),
                          managed_node_id2_hex);

    check_int_eq(meshd_test_pick_loopback_ports(&port1, &port2), 0);
    if (port1 == 0u || port2 == 0u) {
        goto cleanup;
    }
    snprintf(endpoint1, sizeof(endpoint1), "127.0.0.1:%u",
             (unsigned int)port1);
    bootstraps2[0] = endpoint1;

    mesh_config_init(&mesh_config1);
    mesh_config1.virtual_ip = "10.42.40.1";
    mesh_config1.listen_port = (int)port1;
    mesh_config1.advertise_ip = "127.0.0.1";
    mesh_config1.identity_secret_hex = transport_secret_hex1;
    mesh_config1.network_id = "meshd-management-e2e";
    mesh_config_init(&mesh_config2);
    mesh_config2.virtual_ip = "10.42.40.2";
    mesh_config2.listen_port = (int)port2;
    mesh_config2.advertise_ip = "127.0.0.1";
    mesh_config2.identity_secret_hex = transport_secret_hex2;
    mesh_config2.network_id = "meshd-management-e2e";
    mesh_config2.bootstrap_peers = bootstraps2;
    mesh_config2.bootstrap_count = 1;
    mesh1 = mesh_create(&mesh_config1);
    mesh2 = mesh_create(&mesh_config2);
    check_not_null(mesh1);
    check_not_null(mesh2);
    if (!mesh1 || !mesh2) {
        goto cleanup;
    }
    check_int_eq(
        p2p_node_get_public_key(mesh_mgmt_mesh_borrow_p2p_node_v1(mesh1),
                                transport_peer_id1),
        P2P_OK);
    check_int_eq(
        p2p_node_get_public_key(mesh_mgmt_mesh_borrow_p2p_node_v1(mesh2),
                                transport_peer_id2),
        P2P_OK);
    check_int_eq(mesh_mgmt_ed25519_public_from_private(
                     ISSUER_PRIVATE_KEY, issuer_public_key),
                 MESH_MGMT_CRYPTO_OK);
    check_int_eq(mesh_mgmt_ed25519_public_from_private(
                     EXECUTION_GRANT_PRIVATE_KEY,
                     execution_grant_public_key),
                 MESH_MGMT_CRYPTO_OK);
    check_int_eq(mesh_mgmt_ed25519_public_from_private(
                     MANAGEMENT_KEY1, management_public_key1),
                 MESH_MGMT_CRYPTO_OK);
    check_int_eq(meshd_test_issue_node_certificate(
                     ISSUER_PRIVATE_KEY, MANAGEMENT_KEY1,
                     transport_peer_id1, managed_node_id1, mesh_id_hash,
                     1u, certificate1),
                 0);
    check_int_eq(meshd_test_issue_node_certificate(
                     ISSUER_PRIVATE_KEY, MANAGEMENT_KEY2,
                     transport_peer_id2, managed_node_id2, mesh_id_hash,
                     2u, certificate2),
                 0);

    management_key_path = tt_make_temp_file("meshd-mgmt-key", ".hex");
    certificate_path = tt_make_temp_file("meshd-mgmt-cert", ".hex");
    issuer_path = tt_make_temp_file("meshd-mgmt-issuer", ".hex");
    execution_issuer_path =
        tt_make_temp_file("meshd-execution-issuer", ".hex");
    epoch_path = tt_make_temp_file("meshd-mgmt-epoch", ".txt");
    check_not_null(management_key_path);
    check_not_null(certificate_path);
    check_not_null(issuer_path);
    check_not_null(execution_issuer_path);
    check_not_null(epoch_path);
    if (!management_key_path || !certificate_path || !issuer_path ||
        !execution_issuer_path || !epoch_path) {
        goto cleanup;
    }
    check_int_eq(tt_remove_file(epoch_path), 0);
    check_int_eq(meshd_test_write_hex_file(
                     management_key_path, MANAGEMENT_KEY1,
                     sizeof(MANAGEMENT_KEY1)),
                 0);
    check_int_eq(meshd_test_write_hex_file(
                     certificate_path, certificate1, sizeof(certificate1)),
                 0);
    check_int_eq(meshd_test_write_hex_file(
                     issuer_path, issuer_public_key, sizeof(issuer_public_key)),
                 0);
    check_int_eq(meshd_test_write_hex_file(
                     execution_issuer_path, execution_grant_public_key,
                     sizeof(execution_grant_public_key)),
                 0);

    mesh_node_config_init(&daemon_config1);
    snprintf(daemon_config1.identity_secret_hex,
             sizeof(daemon_config1.identity_secret_hex), "%s",
             transport_secret_hex1);
    snprintf(daemon_config1.mgmt_private_key_file,
             sizeof(daemon_config1.mgmt_private_key_file), "%s",
             management_key_path);
    snprintf(daemon_config1.mgmt_certificate_file,
             sizeof(daemon_config1.mgmt_certificate_file), "%s",
             certificate_path);
    snprintf(daemon_config1.mgmt_trusted_issuer_key_file,
             sizeof(daemon_config1.mgmt_trusted_issuer_key_file), "%s",
             issuer_path);
    snprintf(daemon_config1.mgmt_execution_grant_issuer_key_file,
             sizeof(daemon_config1.mgmt_execution_grant_issuer_key_file),
             "%s", execution_issuer_path);
    snprintf(daemon_config1.mgmt_mesh_id_hex,
             sizeof(daemon_config1.mgmt_mesh_id_hex), "%s", mesh_id_hex);
    daemon_config1.mgmt_first_record_epoch = 100u;
    snprintf(daemon_config1.mgmt_record_epoch_file,
             sizeof(daemon_config1.mgmt_record_epoch_file), "%s", epoch_path);
    check_int_eq(mesh_node_config_validate(&daemon_config1), 0);
    check_int_eq(meshd_management_start(mesh1, &daemon_config1), 0);
    management1_started = 1;
    check_int_eq(meshd_management_epoch_allocate(
                     &g_management_epoch_state, &local_record_epoch),
                 0);
    check_hex64_eq(local_record_epoch, 100u);
    meshd_management_stop();
    management1_started = 0;
    check_int_eq(meshd_management_start(mesh1, &daemon_config1), 0);
    management1_started = 1;
    check_int_eq(meshd_management_epoch_allocate(
                     &g_management_epoch_state, &local_record_epoch),
                 0);
    check_hex64_eq(local_record_epoch, 101u);

    check_int_eq(meshd_test_prepare_management_templates(
                     &signer2, &dispatch2, MANAGEMENT_KEY2,
                     issuer_public_key, execution_grant_public_key,
                     mesh_id_hash, transport_peer_id2, managed_node_id2,
                     certificate2),
                 0);
    disabled_runtime_context2.runtime = &runtime2;
    runtime_config2.shared_mesh = mesh2;
    runtime_config2.max_peers = 2u;
    runtime_config2.signer_template = &signer2;
    runtime_config2.dispatch_template = &dispatch2;
    runtime_config2.endpoint_capacity = 2u;
    runtime_config2.retry_base_ms = 10u;
    runtime_config2.retry_max_ms = 100u;
    runtime_config2.connect_timeout_ms = 8000u;
    runtime_config2.protocol_failure_limit = 2u;
    runtime_config2.first_endpoint_record_epoch = 200u;
    runtime_config2.first_service_record_epoch = 200u;
    runtime_config2.admit_peer = meshd_management_admit_peer;
    runtime_config2.on_event = meshd_test_disabled_runtime_event;
    runtime_config2.on_failure = meshd_test_disabled_runtime_failure;
    runtime_config2.callback_context = &disabled_runtime_context2;
    check_int_eq(mesh_mgmt_agent_runtime_init_v1(
                     &runtime2, &runtime_config2),
                 MESH_MGMT_AGENT_RUNTIME_OK);
    runtime2_initialized = 1;
    check_int_eq(mesh_mgmt_agent_runtime_start_v1(&runtime2),
                 MESH_MGMT_AGENT_RUNTIME_OK);
    runtime2_started = 1;
    check_int_eq(mesh_start(mesh1), MESH_OK);
    mesh1_started = 1;
    check_int_eq(mesh_start(mesh2), MESH_OK);
    mesh2_started = 1;

    deadline = turbo_monotonic_ms() + 8000u;
    while (turbo_monotonic_ms() < deadline) {
        mesh_poll(mesh1, 10);
        mesh_poll(mesh2, 10);
        if (mesh_mgmt_agent_router_identity_snapshot_v1(
                &g_management_runtime.router, managed_node_id2,
                &identity_snapshot) == MESH_MGMT_AGENT_ROUTER_OK &&
            mesh_mgmt_agent_router_identity_snapshot_v1(
                &runtime2.router, managed_node_id1,
                &identity_snapshot) == MESH_MGMT_AGENT_ROUTER_OK) {
            sessions_established = 1;
            break;
        }
        meshd_sleep_ms(1u);
    }
    check_true(sessions_established);
    if (!sessions_established) {
        goto cleanup;
    }
    check_size_eq(disabled_runtime_context2.failure_count, 0u);

    service.address_family = MESH_MGMT_SERVICE_ADDRESS_IPV4;
    check_int_eq(inet_pton(AF_INET, "10.42.40.2",
                           service.virtual_address),
                 1);
    service.dns_name = "node-b.mesh";
    service.port = 7878u;
    check_int_eq(mesh_mgmt_agent_runtime_publish_cached_service_v1(
                     &runtime2, &service, &record_epoch),
                 MESH_MGMT_AGENT_RUNTIME_OK);
    check_hex64_eq(record_epoch, 200u);

    deadline = turbo_monotonic_ms() + 8000u;
    while (turbo_monotonic_ms() < deadline) {
        mesh_poll(mesh1, 10);
        mesh_poll(mesh2, 10);
        resolve_result = meshd_management_resolve_service(
            &g_management_runtime, managed_node_id2_hex, &resolved);
        if (resolve_result == MESHD_SERVICE_RESOLVE_OK) {
            break;
        }
        meshd_sleep_ms(1u);
    }
    check_int_eq(resolve_result, MESHD_SERVICE_RESOLVE_OK);
    check_str_eq(resolved.virtual_host, "node-b.mesh");
    check_str_eq(resolved.virtual_ip, "10.42.40.2");
    check_uint_eq(resolved.port, 7878u);
    check_hex64_eq(resolved.record_epoch, 200u);

    execution_payload_size = meshd_test_make_execution_request(
        EXECUTION_GRANT_PRIVATE_KEY, mesh_id_hash, management_public_key1,
        managed_node_id2, turbo_realtime_ms(), execution_payload);
    check_true(execution_payload_size > 0u);
    if (execution_payload_size == 0u) {
        goto cleanup;
    }
    check_int_eq(mesh_mgmt_execution_rpc_control_submit_v1(
                     &g_execution_rpc_control, execution_payload,
                     execution_payload_size, &execution_binding),
                 MESH_MGMT_EXECUTION_RPC_CONTROL_OK);

    deadline = turbo_monotonic_ms() + 8000u;
    while (turbo_monotonic_ms() < deadline) {
        mesh_poll(mesh1, 10);
        mesh_poll(mesh2, 10);
        if (mesh_mgmt_execution_rpc_control_get_v1(
                &g_execution_rpc_control, execution_binding.correlation_id,
                &execution_completion) ==
                MESH_MGMT_EXECUTION_RPC_CONTROL_OK &&
            execution_completion.state == MESH_MGMT_EXECUTION_RPC_STATUS) {
            execution_completed = 1;
            break;
        }
        meshd_sleep_ms(1u);
    }
    check_true(execution_completed);
    check_int_eq(execution_completion.response.kind,
                 MESH_MGMT_KIND_COMMAND_STATUS);
    check_int_eq(execution_completion.response.status.code,
                 MESH_MGMT_EXECUTION_STATUS_DISABLED);
    check_int_eq(memcmp(execution_completion.binding.target_node_id,
                        managed_node_id2, sizeof(managed_node_id2)),
                 0);
    check_int_eq(disabled_runtime_context2.disabled_response_count, 1u);

cleanup:
    if (runtime2_started) {
        (void)mesh_mgmt_agent_runtime_stop_v1(&runtime2);
    }
    if (runtime2_initialized) {
        mesh_mgmt_agent_runtime_destroy_v1(&runtime2);
    }
    if (management1_started) {
        meshd_management_stop();
    }
    if (mesh2_started) {
        mesh_stop(mesh2);
    }
    if (mesh1_started) {
        mesh_stop(mesh1);
    }
    mesh_destroy(mesh2);
    mesh_destroy(mesh1);
    if (execution_issuer_path) {
        (void)tt_remove_file(execution_issuer_path);
        free(execution_issuer_path);
    }
    if (issuer_path) {
        (void)tt_remove_file(issuer_path);
        free(issuer_path);
    }
    if (certificate_path) {
        (void)tt_remove_file(certificate_path);
        free(certificate_path);
    }
    if (management_key_path) {
        (void)tt_remove_file(management_key_path);
        free(management_key_path);
    }
    if (epoch_path) {
        char epoch_lock_path[TURBO_FS_MAX_PATH + 6];
        snprintf(epoch_lock_path, sizeof(epoch_lock_path), "%s.lock", epoch_path);
        (void)tt_remove_file(epoch_path);
        (void)tt_remove_file(epoch_lock_path);
        free(epoch_path);
    }
    mesh_mgmt_crypto_wipe(&signer2, sizeof(signer2));
    mesh_mgmt_crypto_wipe(&dispatch2, sizeof(dispatch2));
    mesh_mgmt_crypto_wipe(certificate1, sizeof(certificate1));
    mesh_mgmt_crypto_wipe(certificate2, sizeof(certificate2));
}

#ifndef _WIN32
static void test_posix_sighup_requests_single_status_flush(void) {
    meshd_test_reset_signal_state();

    check(meshd_is_running());
    check_false(meshd_take_status_flush_request());

    meshd_signal_handler(SIGHUP);

    check(meshd_is_running());
    check(meshd_take_status_flush_request());
    check_false(meshd_take_status_flush_request());
    check(meshd_is_running());
}

static void test_posix_shutdown_signal_does_not_request_status_flush(void) {
    meshd_test_reset_signal_state();

    meshd_signal_handler(SIGTERM);

    check_false(meshd_is_running());
    check_false(meshd_take_status_flush_request());
}
#else
static void test_windows_console_shutdown_signal_stops_runtime(void) {
    meshd_test_reset_signal_state();

    check(meshd_console_handler(CTRL_C_EVENT));

    check_false(meshd_is_running());
}

static void test_windows_console_ignores_unhandled_signal(void) {
    meshd_test_reset_signal_state();

    check_false(meshd_console_handler(9999));
    check(meshd_is_running());
}
#endif

static void test_http_request_parser_accepts_fragmented_binary_body(void) {
    static const uint8_t fragment1[] =
        "POST /v1/executions HTTP/1.1\r\nContent-Length: 4\r";
    static const uint8_t fragment2[] = "\nX-Test: yes\r\n\r\n\x00\x01";
    static const uint8_t fragment3[] = {0x02u, 0x03u};
    meshd_mgmt_http_request_t request;

    memset(&request, 0, sizeof(request));
    check_int_eq(meshd_mgmt_http_request_feed(
                     &request, fragment1, sizeof(fragment1) - 1u),
                 MESHD_MGMT_HTTP_NEED_MORE);
    check_int_eq(meshd_mgmt_http_request_feed(
                     &request, fragment2, sizeof(fragment2) - 1u),
                 MESHD_MGMT_HTTP_NEED_MORE);
    check_int_eq(meshd_mgmt_http_request_feed(
                     &request, fragment3, sizeof(fragment3)),
                 MESHD_MGMT_HTTP_COMPLETE);
    check_true(request.headers_complete);
    check_int_eq(request.content_length, 4u);
    check_int_eq(request.body_size, 4u);
    check_int_eq(request.body[0], 0u);
    check_int_eq(request.body[3], 3u);
}

static void test_http_request_parser_rejects_ambiguous_framing(void) {
    static const uint8_t duplicate_length[] =
        "POST /v1/executions HTTP/1.1\r\n"
        "Content-Length: 1\r\nContent-Length: 1\r\n\r\nx";
    static const uint8_t transfer_encoding[] =
        "POST /v1/executions HTTP/1.1\r\n"
        "Transfer-Encoding: chunked\r\n\r\n";
    static const uint8_t trailing_bytes[] =
        "GET /v1/status HTTP/1.1\r\n\r\nx";
    meshd_mgmt_http_request_t request;

    memset(&request, 0, sizeof(request));
    check_int_eq(meshd_mgmt_http_request_feed(
                     &request, duplicate_length,
                     sizeof(duplicate_length) - 1u),
                 MESHD_MGMT_HTTP_INVALID);
    memset(&request, 0, sizeof(request));
    check_int_eq(meshd_mgmt_http_request_feed(
                     &request, transfer_encoding,
                     sizeof(transfer_encoding) - 1u),
                 MESHD_MGMT_HTTP_INVALID);
    memset(&request, 0, sizeof(request));
    check_int_eq(meshd_mgmt_http_request_feed(
                     &request, trailing_bytes,
                     sizeof(trailing_bytes) - 1u),
                 MESHD_MGMT_HTTP_INVALID);
}

static void test_http_request_parser_enforces_resource_bounds(void) {
    static const uint8_t oversized_body[] =
        "POST /v1/executions HTTP/1.1\r\n"
        "Content-Length: 999999999\r\n\r\n";
    meshd_mgmt_http_request_t request;
    uint8_t header_fill[MESHD_MGMT_HTTP_HEADER_MAX_SIZE + 1u];

    memset(&request, 0, sizeof(request));
    check_int_eq(meshd_mgmt_http_request_feed(
                     &request, oversized_body,
                     sizeof(oversized_body) - 1u),
                 MESHD_MGMT_HTTP_RESOURCE_EXHAUSTED);

    memset(&request, 0, sizeof(request));
    memset(header_fill, 'a', sizeof(header_fill));
    check_int_eq(meshd_mgmt_http_request_feed(
                     &request, header_fill, sizeof(header_fill)),
                 MESHD_MGMT_HTTP_RESOURCE_EXHAUSTED);
}

spec("meshd runtime") {
    describe("RPC control boundary") {
        it("separates data-plane reads from node-control mutations") {
            test_task_model_separates_data_plane_and_node_control();
        }

        it("fails closed for unknown tasks") {
            test_unknown_task_fails_closed();
        }

        it("preserves the task response contract") {
            test_task_response_preserves_the_control_contract();
        }

        it("rejects truncated task JSON") {
            test_task_response_rejects_truncated_json();
        }

        it("accepts unambiguous IPv4 listen endpoints") {
            test_rpc_listen_parser_accepts_unambiguous_ipv4_endpoints();
        }

        it("rejects ambiguous RPC listen endpoints") {
            test_rpc_listen_parser_rejects_ambiguous_endpoints();
        }

        it("builds the RPC service endpoint from the virtual address") {
            test_rpc_service_endpoint_uses_only_the_virtual_address();
        }

        it("publishes the virtual RPC service instead of the internal bind") {
            test_status_publishes_rpc_service_not_internal_bind();
        }

        it("resolves only injected verified virtual RPC services") {
            test_node_resolve_exposes_only_verified_virtual_service();
        }

        it("fails closed when the verified service resolver is unavailable") {
            test_node_resolve_fails_closed_without_verified_resolver();
        }

        it("accepts tokens only from one exact HTTP header") {
            test_rpc_token_accepts_only_an_exact_header();
        }

        it("allows missing tokens only when RPC authentication is unconfigured") {
            test_rpc_token_is_optional_only_when_unconfigured();
        }

        it("assembles fragmented HTTP headers and binary bodies") {
            test_http_request_parser_accepts_fragmented_binary_body();
        }

        it("rejects duplicate length, transfer encoding, and trailing bytes") {
            test_http_request_parser_rejects_ambiguous_framing();
        }

        it("enforces bounded HTTP header and body sizes") {
            test_http_request_parser_enforces_resource_bounds();
        }

        it("requires complete management enrollment material") {
            test_management_config_requires_complete_enrollment_material();
        }

        it("does not allow an execution issuer without management enrollment") {
            test_execution_issuer_requires_management_enrollment();
        }

        it("rejects corrupt persistent management epoch state") {
            test_management_epoch_state_rejects_corrupt_data();
        }

        it("excludes a second process from the management epoch state") {
            test_management_epoch_state_excludes_a_second_process();
        }

        it("decodes management identities with exact hex length and alphabet") {
            test_management_hex_decoder_is_exact();
        }

        it("resolves a signed service and completes disabled execution over RPC") {
            test_production_management_loader_resolves_remote_signed_service();
        }
    }

    describe("signal handling") {
#ifndef _WIN32
        it("turns SIGHUP into one status flush request without stopping") {
            test_posix_sighup_requests_single_status_flush();
        }

        it("turns shutdown signals into runtime stop without status flush request") {
            test_posix_shutdown_signal_does_not_request_status_flush();
        }
#else
        it("turns console shutdown signals into runtime stop") {
            test_windows_console_shutdown_signal_stops_runtime();
        }

        it("ignores unrelated console signals") {
            test_windows_console_ignores_unhandled_signal();
        }
#endif
    }
}
