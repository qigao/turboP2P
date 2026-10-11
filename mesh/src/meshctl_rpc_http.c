#include "meshctl_rpc_http.h"

#include <fmt.h>
#include <tlog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Preserve the CLI's host:port and :port loopback shorthand. Parsing a bounded
 * view avoids allocating or retaining argv storage across network progress. */
static int parse_host_port(const char *value, vstr *host, uint16_t *port) {
    const char *colon;
    size_t size;
    unsigned long number;
    char *end;
    if (!value || !host || !port) return -1;
    size = strlen(value);
    if (size == 0 || size >= 160u) return -1;
    colon = strrchr(value, ':');
    if (!colon || colon[1] == '\0') return -1;
    number = strtoul(colon + 1, &end, 10);
    if (end == colon + 1 || *end || !number || number > UINT16_MAX) return -1;
    *host = colon == value ? vstr_from_cstr("127.0.0.1") :
                            vstr_from_buf(value, (size_t)(colon - value));
    if (host->len >= 128u) return -1;
    *port = (uint16_t)number;
    return 0;
}

static int copy_output(tstr text, char *out, size_t out_size) {
    int result = -1;
    if (text && out && out_size > tstr_len(text)) {
        memcpy(out, text, tstr_len(text) + 1u);
        result = 0;
    }
    tstr_free(text);
    return result;
}

int meshctl_build_rpc_node_addr(const char *node, char *out, size_t out_size) {
    tstr candidate;
    vstr host;
    uint16_t port;
    if (!out || !out_size) return -1;
    out[0] = '\0';
    if (!node || !*node || *node == ':' || strlen(node) >= 160u) return -1;
    candidate = strchr(node, ':') ? tstr_dup(node) :
                                    tstr_format("{}:{}", node, MESHD_CTL_RPC_PORT_DEFAULT);
    if (!candidate) return -1;
    if (parse_host_port(candidate, &host, &port) != 0) {
        tstr_free(candidate);
        return -1;
    }
    tstr normalized = tstr_format("{}:{}", host, (unsigned int)port);
    tstr_free(candidate);
    return copy_output(normalized, out, out_size);
}

int meshctl_build_rpc_resolve_path(const char *node_id, char *out, size_t out_size) {
    if (!out || !out_size) return -1;
    out[0] = '\0';
    if (!node_id || strlen(node_id) != 64u) return -1;
    for (size_t i = 0; i < 64u; ++i) {
        if (!((node_id[i] >= '0' && node_id[i] <= '9') ||
              (node_id[i] >= 'a' && node_id[i] <= 'f'))) return -1;
    }
    return copy_output(tstr_format("/v1/node/resolve/{}", node_id), out, out_size);
}

int meshctl_rpc_token_is_valid(const char *token) {
    return !token || (strlen(token) <= MESHD_CTL_RPC_TOKEN_HEADER_MAX - sizeof("X-Meshd-Token: ") &&
                      !strchr(token, '\r') && !strchr(token, '\n'));
}

static chttp_client_config client_config(void) {
    chttp_client_config config = {0};
#if defined(_WIN32)
    config.network.backend = NATIVE_IO_BACKEND_IOCP;
#elif defined(__linux__)
    config.network.backend = NATIVE_IO_BACKEND_EPOLL;
#else
    config.network.backend = NATIVE_IO_BACKEND_KQUEUE;
#endif
    config.network.connection_capacity = 1u;
    config.network.command_capacity = 8u;
    config.network.request_capacity = 8u;
    config.network.completion_batch_capacity = 8u;
    config.network.event_capacity = 8u;
    config.network.max_send_bytes = MESHD_CTL_RPC_MAX_HEADER_SIZE;
    config.network.receive_buffer_bytes = 4096u;
    config.network.connect_timeout_ms = MESHD_CTL_RPC_TIMEOUT_MS;
    config.network.read_timeout_ms = MESHD_CTL_RPC_TIMEOUT_MS;
    config.network.write_timeout_ms = MESHD_CTL_RPC_TIMEOUT_MS;
    config.request_capacity = 1u;
    config.max_start_line_bytes = MESHD_CTL_RPC_MAX_HEADER_SIZE;
    /* Header count cannot grow beyond the existing wire-byte budget. */
    config.max_header_count = MESHD_CTL_RPC_MAX_HEADER_SIZE / 4u;
    config.max_header_bytes = MESHD_CTL_RPC_MAX_HEADER_SIZE;
    /* CHttp requires a nonzero storage bound; this adapter sends no body. */
    config.max_request_body_bytes = 1u;
    config.max_response_body_bytes = MESHD_CTL_RPC_MAX_RESPONSE_SIZE;
    config.max_informational_responses = 8u;
    return config;
}

int meshctl_rpc_http_request(chttp_client *client, const char *addr,
                             const char *path, const char *method,
                             const char *token, chttp_response *response,
                             chttp_error *error) {
    vstr host;
    uint16_t port;
    chttp_method verb;
    chttp_header header = {"X-Meshd-Token", token};
    chttp_options options = {0};
    chttp_client_config config;
    tstr authority = NULL, uri = NULL;
    int status = SALTS_EINVAL;
    if (error) *error = (chttp_error){SALTS_EINVAL, 0, "rpc-options"};
    if (!client || !response || !error || !path || !method ||
        parse_host_port(addr, &host, &port) != 0 || path[0] != '/' ||
        !meshctl_rpc_token_is_valid(token)) return SALTS_EINVAL;
    if (client->impl) {
        error->status = SALTS_EALREADY;
        return SALTS_EALREADY;
    }
    if (strcmp(method, "GET") == 0) verb = CHTTP_METHOD_GET;
    else if (strcmp(method, "POST") == 0) verb = CHTTP_METHOD_POST;
    else return SALTS_EINVAL;
    /* Keep the old complete http:// URL cap, including the terminating NUL. */
    if (strlen(path) >= MESHD_CTL_RPC_URL_MAX) {
        error->status = SALTS_EMSGSIZE;
        return SALTS_EMSGSIZE;
    }
    authority = tstr_format("{}:{}", host, (unsigned int)port);
    if (!authority) { status = SALTS_ENOMEM; goto cleanup; }
    if (7u + tstr_len(authority) + strlen(path) >= MESHD_CTL_RPC_URL_MAX) {
        status = SALTS_EMSGSIZE;
        goto cleanup;
    }
    uri = tstr_format("tcp://{}", authority);
    if (!uri) { status = SALTS_ENOMEM; goto cleanup; }
    options.connection_uri = uri;
    options.authority = authority;
    options.target = path;
    options.protocol = CHTTP_HTTP_1_1;
    options.timeout_ms = MESHD_CTL_RPC_TIMEOUT_MS;
    if (token && *token) { options.headers = &header; options.header_count = 1u; }
    config = client_config();
    status = chttp_client_init(client, &config);
    if (status != SALTS_OK) {
        *error = (chttp_error){status, 0, "rpc-client-init"};
        goto cleanup;
    }
    status = verb == CHTTP_METHOD_GET ? chttp_get(client, &options, response, error) :
                                      chttp_post(client, &options, response, error);
cleanup:
    tstr_free(uri);
    tstr_free(authority);
    if (status != SALTS_OK && error->stage && strcmp(error->stage, "rpc-options") == 0)
        *error = (chttp_error){status, 0, "rpc-options"};
    return status;
}

static int meshctl_rpc_is_task_model_response(const char *body) {
    return body && strstr(body, "\"task\":") && strstr(body, "\"ok\":") && strstr(body, "\"task\":{\"id\":");
}

static void meshctl_rpc_extract_json_field(const char *json, const char *prefix, char *out, size_t out_size) {
    const char *start = NULL;
    const char *value_start = NULL;
    const char *value_end = NULL;
    size_t value_len = 0;

    if (!json || !prefix || !out || out_size == 0) {
        if (out && out_size > 0) {
            out[0] = '\0';
        }
        return;
    }

    out[0] = '\0';
    start = strstr(json, prefix);
    if (!start) {
        return;
    }

    value_start = start + strlen(prefix);
    if (*value_start == '"') {
        value_start++;
        value_end = strchr(value_start, '"');
    } else {
        value_end = value_start;
        while (*value_end != '\0' && *value_end != ',' && *value_end != '}') {
            value_end++;
        }
    }

    if (!value_start || !value_end || value_end <= value_start) {
        return;
    }

    value_len = (size_t)(value_end - value_start);
    if (value_len >= out_size) {
        value_len = out_size - 1;
    }

    memcpy(out, value_start, value_len);
    out[value_len] = '\0';
}

static void meshctl_rpc_print_task_response(const char *body) {
    char task_id[64] = {0};
    char task_type[128] = {0};
    char task_layer[64] = {0};
    char task_impact[32] = {0};
    char task_safe_to_retry[8] = {0};
    char ok_flag[8] = {0};
    const char *control_scope = "unknown";

    meshctl_rpc_extract_json_field(body, "\"ok\":", ok_flag, sizeof(ok_flag));
    meshctl_rpc_extract_json_field(body, "\"id\":\"", task_id, sizeof(task_id));
    meshctl_rpc_extract_json_field(body, "\"type\":\"", task_type, sizeof(task_type));
    meshctl_rpc_extract_json_field(body, "\"target_layer\":\"", task_layer, sizeof(task_layer));
    meshctl_rpc_extract_json_field(body, "\"impact\":\"", task_impact, sizeof(task_impact));
    meshctl_rpc_extract_json_field(body, "\"safe_to_retry\":", task_safe_to_retry, sizeof(task_safe_to_retry));

    if (strcmp(task_layer, "mesh_data_plane") == 0) {
        control_scope = "mesh_data_plane (read/report only, safer)";
    } else if (strcmp(task_layer, "node_control") == 0) {
        control_scope = "node_control (mutating control, privileged)";
    }

    if (ok_flag[0] != '\0') {
        printf("ok=%s task=%s layer=%s impact=%s retry=%s id=%s\n",
               ok_flag[0] == 't' ? "true" : ok_flag,
               task_type[0] ? task_type : "unknown",
               task_layer[0] ? task_layer : "unknown",
               task_impact[0] ? task_impact : "unknown",
               task_safe_to_retry[0] ? task_safe_to_retry : "unknown",
               task_id[0] ? task_id : "unknown");
        printf("scope=%s\n", control_scope);
        if (strncmp(ok_flag, "true", 4) == 0) {
            const char *result = strstr(body, "\"result\":");
            if (result) {
                printf("result=%s\n", result + strlen("\"result\":"));
            }
        } else {
            const char *error = strstr(body, "\"error\":");
            if (error) {
                printf("error=%s\n", error + strlen("\"error\":"));
            }
        }
        return;
    }

    printf("%s\n", body);
}

static int print_header_line(tstr line) {
    if (!line || !tstr_len(line)) {
        tstr_free(line);
        return -1;
    }
    fwrite(line, 1u, tstr_len(line), stdout);
    tstr_free(line);
    return 0;
}

int meshctl_rpc_send(const char *addr, const char *path, const char *method,
                     const char *token, int print_raw) {
    chttp_client client = {0};
    chttp_response response = {0};
    chttp_error error = {0};
    tstr body_text = NULL;
    int result = 1;
    int status = meshctl_rpc_http_request(&client, addr, path, method, token,
                                         &response, &error);
    if (status != SALTS_OK) {
        TLOG_ERRORF("RPC request failed: status={} stage={}", status,
                    error.stage ? error.stage : "unknown");
        goto cleanup;
    }
    if (response.body && response.body_size > 0u) {
        if (!print_raw) {
            /* CHttp bodies are byte spans. Text inspection needs an owned,
             * terminated copy; binary/raw output keeps the exact byte count. */
            body_text = tstr_new_len(response.body, response.body_size);
            if (!body_text) {
                TLOG_ERROR("RPC response text allocation failed");
                goto cleanup;
            }
        }
        if (body_text && meshctl_rpc_is_task_model_response(body_text)) {
            meshctl_rpc_print_task_response(body_text);
        } else {
            fwrite(response.body, 1u, response.body_size, stdout);
            fputc('\n', stdout);
        }
    } else {
        if (print_header_line(tstr_format("HTTP/{}.{} {} {}\r\n",
                response.http_major, response.http_minor, response.status_code,
                response.reason ? response.reason : "")) != 0) goto render_failed;
        for (size_t i = 0; i < response.header_count; ++i) {
            if (print_header_line(tstr_format("{}: {}\r\n",
                    response.headers[i].name, response.headers[i].value)) != 0)
                goto render_failed;
        }
        fputc('\n', stdout);
    }
    result = 0;
    goto cleanup;
render_failed:
    TLOG_ERROR("RPC response header formatting failed");
cleanup:
    tstr_free(body_text);
    chttp_response_destroy(&response);
    /* The blocking call has terminally drained its request. Finish transport
     * shutdown before stack storage disappears; an unexpected owner failure
     * is fatal rather than silently losing a live client. */
    /* Zero is not an unlimited CHttp session-drain budget. A timeout retains
     * this owner; continue driving shutdown with a positive budget until its
     * actual terminal. This never resubmits the HTTP request. */
    do {
        status = chttp_client_destroy(&client, MESHD_CTL_RPC_TIMEOUT_MS);
    } while (status == SALTS_ETIMEDOUT);
    if (status != SALTS_OK) {
        TLOG_FATALF("RPC client shutdown failed: status={}", status);
        abort();
    }
    return result;
}
