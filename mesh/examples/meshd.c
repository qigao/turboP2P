#include <turbo_mesh.h>
#include <turbo_tunnel.h>
#include <turbo_fs.h>
#include <tlog.h>
#include "mesh_mgmt_agent_runtime.h"
#include "mesh_mgmt_crypto.h"
#include "mesh_mgmt_execution_rpc_control.h"
#include "mesh_mgmt_execution_wire.h"
#include "mesh_mgmt_identity.h"
#include "mesh_mgmt_mesh_bridge.h"
#include "mesh_config.h"
#include "mesh_runtime_health.h"
#ifdef TURBO_P2P_ENABLE_NODE_EXECUTION
#include "mesh_mgmt_execution_node.h"
#include "meshd_execution_config.h"
#endif

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>

#define MESH_SNAPSHOT_VERSION 1

#define MESHD_MGMT_HTTP_HEADER_MAX_SIZE 8192u
#define MESHD_MGMT_HTTP_RECV_CHUNK_SIZE 2048u
#define MESHD_MGMT_HTTP_READ_TIMEOUT_MS 1000u
#define MESHD_MGMT_HTTP_BODY_MAX_SIZE \
    MESH_MGMT_EXECUTION_COMMAND_REQUEST_MAX_SIZE_V1
#define MESHD_MGMT_RESPONSE_BUF_SIZE 16384
#define MESHD_NODE_ID_HEX_LENGTH 64
#define MESHD_MGMT_FRAME_TTL_MS 30000u
#define MESHD_MGMT_SERVICE_PUBLISH_INTERVAL_MS 10000u
#define MESHD_MGMT_REPLAY_CAPACITY 256u
#define MESHD_MGMT_REPLAY_TTL_MS 60000u
#define MESHD_MGMT_RUNTIME_MAX_PEERS 64u
#define MESHD_EXECUTION_RPC_CAPACITY 256u
#define MESHD_EXECUTION_RPC_RETENTION_MS 60000u
#ifdef TURBO_P2P_ENABLE_NODE_EXECUTION
#define MESHD_EXECUTION_EGRESS_DRAIN_BATCH 16u
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#define MESHD_INVALID_SOCKET INVALID_SOCKET
#define MESHD_SOCKET_CMP(a, b) ((a) == (b))
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#define MESHD_INVALID_SOCKET (-1)
#define MESHD_SOCKET_CMP(a, b) ((a) == (b))
#endif

#ifdef _WIN32
typedef SOCKET meshd_socket_t;
#else
typedef int meshd_socket_t;
#endif

typedef enum {
    MESHD_SERVICE_RESOLVE_OK = 0,
    MESHD_SERVICE_RESOLVE_NOT_FOUND = -1,
    MESHD_SERVICE_RESOLVE_UNAVAILABLE = -2,
    MESHD_SERVICE_RESOLVE_VERIFICATION_FAILED = -3
} meshd_service_resolve_result_t;

typedef struct {
    char virtual_host[128];
    char virtual_ip[64];
    uint16_t port;
    uint64_t record_epoch;
    uint64_t expires_at_ms;
} meshd_verified_service_snapshot_t;

typedef meshd_service_resolve_result_t (*meshd_service_resolver_fn)(
    void *context,
    const char node_id_hex[MESHD_NODE_ID_HEX_LENGTH + 1],
    meshd_verified_service_snapshot_t *out_snapshot);

typedef struct {
    meshd_socket_t listen_socket;
    char bind_host[64];
    uint16_t bind_port;
    char virtual_host[128];
    uint16_t service_port;
    char service_endpoint[160];
    char token[128];
    meshd_service_resolver_fn resolve_service;
    void *resolve_service_context;
} meshd_mgmt_server_t;

typedef enum {
    MESHD_MGMT_HTTP_NEED_MORE = 0,
    MESHD_MGMT_HTTP_COMPLETE = 1,
    MESHD_MGMT_HTTP_INVALID = -1,
    MESHD_MGMT_HTTP_RESOURCE_EXHAUSTED = -2
} meshd_mgmt_http_parse_result_t;

typedef struct {
    char header[MESHD_MGMT_HTTP_HEADER_MAX_SIZE + 1u];
    uint8_t body[MESHD_MGMT_HTTP_BODY_MAX_SIZE];
    size_t header_size;
    size_t body_size;
    size_t content_length;
    int headers_complete;
    meshd_mgmt_http_parse_result_t result;
} meshd_mgmt_http_request_t;

static int meshd_ascii_name_equal(const char *value,
                                  size_t value_size,
                                  const char *expected) {
    size_t index;
    size_t expected_size;

    if (!value || !expected) {
        return 0;
    }
    expected_size = strlen(expected);
    if (value_size != expected_size) {
        return 0;
    }
    for (index = 0u; index < value_size; index++) {
        if (tolower((unsigned char)value[index]) !=
            tolower((unsigned char)expected[index])) {
            return 0;
        }
    }
    return 1;
}

static int meshd_http_header_name_char_is_valid(unsigned char value) {
    return isalnum(value) ||
           value == '!' || value == '#' || value == '$' || value == '%' ||
           value == '&' || value == '\'' || value == '*' || value == '+' ||
           value == '-' || value == '.' || value == '^' || value == '_' ||
           value == '`' || value == '|' || value == '~';
}

static int meshd_http_find_crlf(const char *header,
                                size_t header_size,
                                size_t begin,
                                size_t *out_end) {
    size_t index;

    if (!header || !out_end || begin >= header_size) {
        return 0;
    }
    for (index = begin; index + 1u < header_size; index++) {
        if (header[index] == '\r' && header[index + 1u] == '\n') {
            *out_end = index;
            return 1;
        }
    }
    return 0;
}

static meshd_mgmt_http_parse_result_t
meshd_http_parse_content_length(const char *value,
                                size_t value_size,
                                size_t *out_length) {
    size_t begin = 0u;
    size_t end = value_size;
    size_t parsed = 0u;
    size_t index;

    if (!value || !out_length) {
        return MESHD_MGMT_HTTP_INVALID;
    }
    while (begin < end &&
           (value[begin] == ' ' || value[begin] == '\t')) {
        begin++;
    }
    while (end > begin &&
           (value[end - 1u] == ' ' || value[end - 1u] == '\t')) {
        end--;
    }
    if (begin == end) {
        return MESHD_MGMT_HTTP_INVALID;
    }
    for (index = begin; index < end; index++) {
        size_t digit;

        if (value[index] < '0' || value[index] > '9') {
            return MESHD_MGMT_HTTP_INVALID;
        }
        digit = (size_t)(value[index] - '0');
        if (parsed > (MESHD_MGMT_HTTP_BODY_MAX_SIZE - digit) / 10u) {
            return MESHD_MGMT_HTTP_RESOURCE_EXHAUSTED;
        }
        parsed = parsed * 10u + digit;
    }
    *out_length = parsed;
    return MESHD_MGMT_HTTP_COMPLETE;
}

static meshd_mgmt_http_parse_result_t
meshd_http_parse_headers(meshd_mgmt_http_request_t *request) {
    size_t line_begin = 0u;
    size_t line_end = 0u;
    int content_length_seen = 0;

    if (!request ||
        !meshd_http_find_crlf(request->header, request->header_size,
                              line_begin, &line_end) ||
        line_end == 0u) {
        return MESHD_MGMT_HTTP_INVALID;
    }
    line_begin = line_end + 2u;
    while (line_begin < request->header_size) {
        size_t colon;
        size_t index;
        meshd_mgmt_http_parse_result_t length_result;

        if (!meshd_http_find_crlf(request->header, request->header_size,
                                  line_begin, &line_end)) {
            return MESHD_MGMT_HTTP_INVALID;
        }
        if (line_end == line_begin) {
            return line_end + 2u == request->header_size
                       ? MESHD_MGMT_HTTP_COMPLETE
                       : MESHD_MGMT_HTTP_INVALID;
        }
        if (request->header[line_begin] == ' ' ||
            request->header[line_begin] == '\t') {
            return MESHD_MGMT_HTTP_INVALID;
        }
        colon = line_begin;
        while (colon < line_end && request->header[colon] != ':') {
            if (!meshd_http_header_name_char_is_valid(
                    (unsigned char)request->header[colon])) {
                return MESHD_MGMT_HTTP_INVALID;
            }
            colon++;
        }
        if (colon == line_begin || colon == line_end) {
            return MESHD_MGMT_HTTP_INVALID;
        }
        for (index = colon + 1u; index < line_end; index++) {
            unsigned char value =
                (unsigned char)request->header[index];
            if ((value < 0x20u && value != '\t') || value == 0x7fu) {
                return MESHD_MGMT_HTTP_INVALID;
            }
        }
        if (meshd_ascii_name_equal(request->header + line_begin,
                                   colon - line_begin,
                                   "Transfer-Encoding")) {
            return MESHD_MGMT_HTTP_INVALID;
        }
        if (meshd_ascii_name_equal(request->header + line_begin,
                                   colon - line_begin,
                                   "Content-Length")) {
            if (content_length_seen) {
                return MESHD_MGMT_HTTP_INVALID;
            }
            content_length_seen = 1;
            length_result = meshd_http_parse_content_length(
                request->header + colon + 1u,
                line_end - colon - 1u,
                &request->content_length);
            if (length_result != MESHD_MGMT_HTTP_COMPLETE) {
                return length_result;
            }
        }
        line_begin = line_end + 2u;
    }
    return MESHD_MGMT_HTTP_INVALID;
}

static meshd_mgmt_http_parse_result_t
meshd_mgmt_http_request_feed(meshd_mgmt_http_request_t *request,
                             const uint8_t *bytes,
                             size_t bytes_size) {
    size_t cursor = 0u;

    if (!request || (!bytes && bytes_size != 0u)) {
        return MESHD_MGMT_HTTP_INVALID;
    }
    if (request->result != MESHD_MGMT_HTTP_NEED_MORE) {
        return bytes_size == 0u ? request->result : MESHD_MGMT_HTTP_INVALID;
    }
    while (cursor < bytes_size) {
        if (!request->headers_complete) {
            meshd_mgmt_http_parse_result_t header_result;

            if (request->header_size >= MESHD_MGMT_HTTP_HEADER_MAX_SIZE) {
                request->result = MESHD_MGMT_HTTP_RESOURCE_EXHAUSTED;
                return request->result;
            }
            if (bytes[cursor] == 0u) {
                request->result = MESHD_MGMT_HTTP_INVALID;
                return request->result;
            }
            request->header[request->header_size++] = (char)bytes[cursor++];
            if (request->header_size < 4u ||
                memcmp(request->header + request->header_size - 4u,
                       "\r\n\r\n", 4u) != 0) {
                continue;
            }
            request->header[request->header_size] = '\0';
            header_result = meshd_http_parse_headers(request);
            if (header_result != MESHD_MGMT_HTTP_COMPLETE) {
                request->result = header_result;
                return request->result;
            }
            request->headers_complete = 1;
            if (request->content_length == 0u) {
                request->result =
                    cursor == bytes_size
                        ? MESHD_MGMT_HTTP_COMPLETE
                        : MESHD_MGMT_HTTP_INVALID;
                return request->result;
            }
        } else {
            size_t remaining =
                request->content_length - request->body_size;
            size_t available = bytes_size - cursor;
            size_t copy_size = available < remaining ? available : remaining;

            memcpy(request->body + request->body_size,
                   bytes + cursor, copy_size);
            request->body_size += copy_size;
            cursor += copy_size;
            if (request->body_size == request->content_length) {
                request->result =
                    cursor == bytes_size
                        ? MESHD_MGMT_HTTP_COMPLETE
                        : MESHD_MGMT_HTTP_INVALID;
                return request->result;
            }
        }
    }
    return MESHD_MGMT_HTTP_NEED_MORE;
}

static volatile sig_atomic_t g_running = 1;
#ifndef _WIN32
static volatile sig_atomic_t g_status_flush_requested = 0;
#endif
static mesh_network_t *g_mesh = NULL;
static tunnel_t *g_tunnel = NULL;
static mesh_node_config_t g_config;
static uint64_t g_started_ms = 0;
static uint32_t g_mgmt_task_counter = 0;
static meshd_mgmt_server_t g_mgmt_server;
static mesh_mgmt_agent_runtime_v1_t g_management_runtime;
static mesh_mgmt_peer_signer_config_v1_t g_management_signer;
static mesh_mgmt_dispatch_config_v1_t g_management_dispatch;
static int g_management_configured = 0;
static uint64_t g_management_last_publish_ms = 0;
static mesh_mgmt_execution_rpc_registry_v1_t g_execution_rpc_registry;
static mesh_mgmt_execution_rpc_control_v1_t g_execution_rpc_control;
static int g_execution_rpc_configured = 0;
#ifdef TURBO_P2P_ENABLE_NODE_EXECUTION
static meshd_execution_config_t g_execution_local_config;
static mesh_mgmt_execution_node_v1_t g_execution_node;
static int g_execution_node_configured = 0;
#endif

typedef struct {
    char path[TURBO_FS_MAX_PATH];
    uint64_t next_epoch;
    turbo_file_t lock_file;
    int lock_file_open;
    int lock_held;
    int initialized;
} meshd_management_epoch_state_t;

static meshd_management_epoch_state_t g_management_epoch_state;

typedef struct {
    const char *type;
    const char *layer;
    const char *impact;
    int requires_token;
    int safe_to_retry;
} meshd_task_model_t;

typedef enum {
    MESHD_TASK_LAYER_UNKNOWN = 0,
    MESHD_TASK_LAYER_MESH_DATA_PLANE = 1,
    MESHD_TASK_LAYER_NODE_CONTROL = 2
} meshd_task_layer_t;

static void meshd_request_shutdown(void) {
    g_running = 0;
}

static int meshd_is_running(void) {
    return g_running != 0;
}

#ifndef _WIN32
static void meshd_request_status_flush(void) {
    g_status_flush_requested = 1;
}

static int meshd_take_status_flush_request(void) {
    if (!g_status_flush_requested) {
        return 0;
    }

    g_status_flush_requested = 0;
    return 1;
}
#endif

static uint64_t meshd_now_ms(void) {
#ifdef _WIN32
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
#endif
}

static void meshd_sleep_ms(uint32_t timeout_ms) {
#ifdef _WIN32
    Sleep(timeout_ms);
#else
    struct timespec req;
    struct timespec rem;

    req.tv_sec = (time_t)(timeout_ms / 1000);
    req.tv_nsec = (long)(timeout_ms % 1000) * 1000000L;
    while (nanosleep(&req, &rem) != 0 && errno == EINTR && meshd_is_running()) {
        req = rem;
    }
#endif
}

static int meshd_hex_value(int ch) {
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }
    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }
    return -1;
}

static int meshd_decode_hex_exact(const char *text, uint8_t *output, size_t output_size) {
    size_t index;

    if (!text || !output || strlen(text) != output_size * 2u) {
        return -1;
    }
    memset(output, 0, output_size);
    for (index = 0; index < output_size; index++) {
        int high = meshd_hex_value((unsigned char)text[index * 2u]);
        int low = meshd_hex_value((unsigned char)text[index * 2u + 1u]);
        if (high < 0 || low < 0) {
            memset(output, 0, output_size);
            return -1;
        }
        output[index] = (uint8_t)((high << 4) | low);
    }
    return 0;
}

static int meshd_read_hex_file_exact(const char *path, uint8_t *output, size_t output_size) {
    FILE *fp;
    size_t nibble_count = 0;
    int ch;

    if (!path || path[0] == '\0' || !output || output_size == 0u) {
        return -1;
    }
    fp = fopen(path, "rb");
    if (!fp) {
        return -1;
    }
    memset(output, 0, output_size);
    while ((ch = fgetc(fp)) != EOF) {
        int value;
        size_t byte_index;

        if (isspace((unsigned char)ch)) {
            continue;
        }
        value = meshd_hex_value(ch);
        if (value < 0 || nibble_count >= output_size * 2u) {
            fclose(fp);
            memset(output, 0, output_size);
            return -1;
        }
        byte_index = nibble_count / 2u;
        if ((nibble_count & 1u) == 0u) {
            output[byte_index] = (uint8_t)(value << 4);
        } else {
            output[byte_index] |= (uint8_t)value;
        }
        nibble_count++;
    }
    if (ferror(fp) || fclose(fp) != 0 || nibble_count != output_size * 2u) {
        memset(output, 0, output_size);
        return -1;
    }
    return 0;
}

static int meshd_management_admit_peer(
    void *context,
    p2p_peer_t *peer,
    const uint8_t remote_transport_peer_id[P2P_KEY_SIZE],
    const mesh_mgmt_dispatch_event_v1_t *event) {
    (void)context;
    return peer && remote_transport_peer_id && event &&
                   event->type == MESH_MGMT_DISPATCH_EVENT_SESSION_ESTABLISHED
               ? 0
               : -1;
}

static int meshd_management_epoch_write(const char *path, uint64_t next_epoch) {
    char temp_path[TURBO_FS_MAX_PATH + 5];
    char encoded[32];
    size_t written = 0u;
    int encoded_len;
    int path_len;
    turbo_file_t file = TURBO_INVALID_FILE;

    if (!path || path[0] == '\0' || next_epoch == 0u) {
        return -1;
    }
    path_len = snprintf(temp_path, sizeof(temp_path), "%s.tmp", path);
    encoded_len = snprintf(encoded, sizeof(encoded), "%llu\n",
                           (unsigned long long)next_epoch);
    if (path_len < 0 || (size_t)path_len >= sizeof(temp_path) ||
        encoded_len < 0 || (size_t)encoded_len >= sizeof(encoded)) {
        return -1;
    }

    file = turbo_fs_open(temp_path,
                         TURBO_FS_O_WRONLY | TURBO_FS_O_CREAT | TURBO_FS_O_TRUNC,
                         0600);
    if (file == TURBO_INVALID_FILE) {
        return -1;
    }
    while (written < (size_t)encoded_len) {
        int result = turbo_fs_write(file, encoded + written,
                                    (size_t)encoded_len - written);
        if (result <= 0) {
            (void)turbo_fs_close(file);
            (void)turbo_fs_unlink(temp_path);
            return -1;
        }
        written += (size_t)result;
    }
    if (turbo_fs_fsync(file) != 0 || turbo_fs_close(file) != 0) {
        (void)turbo_fs_unlink(temp_path);
        return -1;
    }
    if (turbo_fs_rename(temp_path, path) != 0) {
        (void)turbo_fs_unlink(temp_path);
        return -1;
    }
    return 0;
}

static void meshd_management_epoch_close(
    meshd_management_epoch_state_t *state) {
    if (!state) {
        return;
    }
    if (state->lock_held) {
        (void)turbo_fs_unlock(state->lock_file, 0, 1u);
    }
    if (state->lock_file_open) {
        (void)turbo_fs_close(state->lock_file);
    }
    memset(state, 0, sizeof(*state));
    state->lock_file = TURBO_INVALID_FILE;
}

static int meshd_management_epoch_open(
    meshd_management_epoch_state_t *state,
    const char *path,
    uint64_t first_record_epoch) {
    turbo_fs_buf_t file_data;
    char encoded[64];
    char lock_path[TURBO_FS_MAX_PATH + 6];
    char *cursor;
    char *end;
    unsigned long long parsed;
    int lock_path_len;

    if (!state || !path || path[0] == '\0' || first_record_epoch == 0u ||
        strlen(path) >= sizeof(state->path)) {
        return -1;
    }
    memset(state, 0, sizeof(*state));
    state->lock_file = TURBO_INVALID_FILE;
    memset(&file_data, 0, sizeof(file_data));
    lock_path_len = snprintf(lock_path, sizeof(lock_path), "%s.lock", path);
    if (lock_path_len < 0 || (size_t)lock_path_len >= sizeof(lock_path)) {
        return -1;
    }

    state->lock_file = turbo_fs_open(
        lock_path, TURBO_FS_O_RDWR | TURBO_FS_O_CREAT, 0600);
    if (state->lock_file == TURBO_INVALID_FILE) {
        fprintf(stderr, "Failed to open management epoch lock: %s\n", lock_path);
        return -1;
    }
    state->lock_file_open = 1;
    if (turbo_fs_lock(state->lock_file,
                      TURBO_FS_LOCK_EXCLUSIVE | TURBO_FS_LOCK_NONBLOCK,
                      0, 1u) != 0) {
        fprintf(stderr, "Management epoch state is already in use: %s\n", path);
        meshd_management_epoch_close(state);
        return -1;
    }
    state->lock_held = 1;

    if (turbo_fs_access(path, TURBO_FS_ACCESS_EXISTS) != 0) {
        if (meshd_management_epoch_write(path, first_record_epoch) != 0) {
            fprintf(stderr, "Failed to initialize management epoch file: %s\n", path);
            meshd_management_epoch_close(state);
            return -1;
        }
        state->next_epoch = first_record_epoch;
    } else {
        if (turbo_fs_read_file(path, &file_data) != 0 ||
            file_data.len == 0u || file_data.len >= sizeof(encoded)) {
            turbo_fs_buf_free(&file_data);
            fprintf(stderr, "Invalid management epoch file: %s\n", path);
            meshd_management_epoch_close(state);
            return -1;
        }
        memcpy(encoded, file_data.base, file_data.len);
        encoded[file_data.len] = '\0';
        turbo_fs_buf_free(&file_data);

        cursor = encoded;
        while (*cursor != '\0' && isspace((unsigned char)*cursor)) {
            cursor++;
        }
        errno = 0;
        parsed = strtoull(cursor, &end, 10);
        if (cursor == end || errno == ERANGE || parsed == 0u ||
            parsed == (unsigned long long)UINT64_MAX) {
            fprintf(stderr, "Invalid management epoch value: %s\n", path);
            meshd_management_epoch_close(state);
            return -1;
        }
        while (*end != '\0' && isspace((unsigned char)*end)) {
            end++;
        }
        if (*end != '\0') {
            fprintf(stderr, "Invalid management epoch value: %s\n", path);
            meshd_management_epoch_close(state);
            return -1;
        }
        state->next_epoch = (uint64_t)parsed;
    }

    memcpy(state->path, path, strlen(path) + 1u);
    state->initialized = 1;
    return 0;
}

static int meshd_management_epoch_allocate(void *context,
                                           uint64_t *out_record_epoch) {
    meshd_management_epoch_state_t *state =
        (meshd_management_epoch_state_t *)context;
    uint64_t reserved_epoch;

    if (!state || !out_record_epoch || !state->initialized ||
        state->next_epoch == 0u || state->next_epoch == UINT64_MAX) {
        return -1;
    }
    *out_record_epoch = 0u;
    reserved_epoch = state->next_epoch;
    if (meshd_management_epoch_write(state->path, reserved_epoch + 1u) != 0) {
        fprintf(stderr, "Failed to reserve management record epoch\n");
        return -1;
    }
    state->next_epoch = reserved_epoch + 1u;
    *out_record_epoch = reserved_epoch;
    return 0;
}

static void meshd_management_reset(void) {
#ifdef TURBO_P2P_ENABLE_NODE_EXECUTION
    if (g_execution_node_configured || g_execution_node.initialized) {
        mesh_mgmt_execution_node_destroy_v1(&g_execution_node);
    }
    memset(&g_execution_node, 0, sizeof(g_execution_node));
    g_execution_node_configured = 0;
#endif
    meshd_management_epoch_close(&g_management_epoch_state);
    memset(&g_execution_rpc_control, 0, sizeof(g_execution_rpc_control));
    mesh_mgmt_execution_rpc_registry_destroy_v1(&g_execution_rpc_registry);
    mesh_mgmt_crypto_wipe(&g_management_signer, sizeof(g_management_signer));
    mesh_mgmt_crypto_wipe(&g_management_dispatch, sizeof(g_management_dispatch));
    memset(&g_management_runtime, 0, sizeof(g_management_runtime));
    g_management_configured = 0;
    g_execution_rpc_configured = 0;
    g_management_last_publish_ms = 0;
}

static uint64_t meshd_execution_clock_now_ms(void *context) {
    (void)context;
    return turbo_realtime_ms();
}

static mesh_mgmt_execution_rpc_transport_result_t
meshd_execution_send(void *context,
                     const uint8_t target_node_id[32],
                     const uint8_t *payload,
                     size_t payload_size) {
    mesh_mgmt_agent_runtime_result_t result;

    (void)context;
    result = mesh_mgmt_agent_runtime_send_execution_request_v1(
        &g_management_runtime, target_node_id, payload, payload_size);
    if (result == MESH_MGMT_AGENT_RUNTIME_OK) {
        return MESH_MGMT_EXECUTION_RPC_TRANSPORT_SENT;
    }
    if (result == MESH_MGMT_AGENT_RUNTIME_DISCOVERY_FAILED) {
        return MESH_MGMT_EXECUTION_RPC_TRANSPORT_UNAVAILABLE;
    }
    return MESH_MGMT_EXECUTION_RPC_TRANSPORT_AMBIGUOUS;
}

static int meshd_management_event(
    void *context,
    p2p_peer_t *peer,
    const uint8_t remote_transport_peer_id[P2P_KEY_SIZE],
    const mesh_mgmt_dispatch_event_v1_t *event) {
    mesh_mgmt_execution_response_v1_t response;
    mesh_mgmt_execution_response_consumer_result_t response_result;
    mesh_mgmt_execution_rpc_control_result_t control_result;

    (void)context;
    (void)remote_transport_peer_id;
    if (!event) {
        return -1;
    }
    if (event->type ==
        MESH_MGMT_DISPATCH_EVENT_NODE_EXECUTION_REQUEST_SHADOW) {
        if (!g_execution_rpc_configured) {
            return -1;
        }
#ifdef TURBO_P2P_ENABLE_NODE_EXECUTION
        if (g_execution_node_configured) {
            mesh_mgmt_execution_shadow_command_v1_t command;
            mesh_mgmt_execution_consumer_result_t consumer_result;
            mesh_mgmt_execution_node_result_t submit_result;
            uint16_t status_code;

            memset(&command, 0, sizeof(command));
            consumer_result =
                mesh_mgmt_agent_runtime_execution_command_from_event_v1(
                    &g_management_runtime, peer, event, turbo_realtime_ms(),
                    &command);
            if (consumer_result != MESH_MGMT_EXECUTION_CONSUMER_OK) {
                return -1;
            }
            submit_result =
                mesh_mgmt_execution_node_try_submit_v1(&g_execution_node,
                                                       &command);
            if (submit_result == MESH_MGMT_EXECUTION_NODE_OK) {
                return 0;
            }
            status_code =
                submit_result == MESH_MGMT_EXECUTION_NODE_BUSY ||
                        submit_result == MESH_MGMT_EXECUTION_NODE_CLOSED
                    ? MESH_MGMT_EXECUTION_STATUS_BUSY
                    : MESH_MGMT_EXECUTION_STATUS_INTERNAL;
            return mesh_mgmt_agent_runtime_send_execution_status_from_command_v1(
                       &g_management_runtime, peer, &command, status_code) ==
                       MESH_MGMT_EXECUTION_DISABLED_RESPONDER_OK
                       ? 0
                       : -1;
        }
#endif
        return mesh_mgmt_agent_runtime_send_execution_disabled_from_event_v1(
                   &g_management_runtime, peer, event, turbo_realtime_ms()) ==
                       MESH_MGMT_EXECUTION_DISABLED_RESPONDER_OK
                   ? 0
                   : -1;
    }
    if (event->type !=
             MESH_MGMT_DISPATCH_EVENT_NODE_EXECUTION_RESULT_SHADOW &&
        event->type !=
            MESH_MGMT_DISPATCH_EVENT_NODE_EXECUTION_STATUS_SHADOW) {
        return 0;
    }
    if (!g_execution_rpc_configured) {
        return -1;
    }
    memset(&response, 0, sizeof(response));
    response_result =
        mesh_mgmt_agent_runtime_execution_response_from_event_v1(
            &g_management_runtime, peer, event, &response);
    if (response_result != MESH_MGMT_EXECUTION_RESPONSE_CONSUMER_OK) {
        return -1;
    }
    control_result = mesh_mgmt_execution_rpc_control_complete_v1(
        &g_execution_rpc_control, &response);
    return control_result == MESH_MGMT_EXECUTION_RPC_CONTROL_OK ||
                   control_result ==
                       MESH_MGMT_EXECUTION_RPC_CONTROL_ALREADY_COMPLETE
               ? 0
               : -1;
}

#ifdef TURBO_P2P_ENABLE_NODE_EXECUTION
static int meshd_execution_drain(void) {
    size_t drained = 0u;

    if (!g_execution_node_configured) {
        return 0;
    }
    while (drained < MESHD_EXECUTION_EGRESS_DRAIN_BATCH) {
        mesh_mgmt_execution_node_result_t result =
            mesh_mgmt_execution_node_send_next_v1(&g_execution_node,
                                                  &g_management_runtime);
        if (result == MESH_MGMT_EXECUTION_NODE_EMPTY) {
            return 0;
        }
        if (result != MESH_MGMT_EXECUTION_NODE_OK) {
            return -1;
        }
        drained++;
    }
    return 0;
}
#endif

static void meshd_management_stop(void) {
#ifdef TURBO_P2P_ENABLE_NODE_EXECUTION
    if (g_execution_node_configured) {
        mesh_mgmt_execution_node_result_t send_result;

        (void)mesh_mgmt_execution_node_shutdown_v1(&g_execution_node);
        for (;;) {
            send_result = mesh_mgmt_execution_node_send_next_v1(
                &g_execution_node, &g_management_runtime);
            if (send_result == MESH_MGMT_EXECUTION_NODE_EMPTY) {
                break;
            }
            if (send_result != MESH_MGMT_EXECUTION_NODE_OK) {
                break;
            }
        }
        mesh_mgmt_execution_node_destroy_v1(&g_execution_node);
        memset(&g_execution_node, 0, sizeof(g_execution_node));
        g_execution_node_configured = 0;
    }
#endif
    if (g_management_runtime.state == MESH_MGMT_AGENT_RUNTIME_RUNNING) {
        if (mesh_mgmt_agent_runtime_stop_v1(&g_management_runtime) !=
            MESH_MGMT_AGENT_RUNTIME_OK) {
            fprintf(stderr, "Failed to stop shared management runtime\n");
        }
    }
    mesh_mgmt_agent_runtime_destroy_v1(&g_management_runtime);
    meshd_management_reset();
}

static int meshd_management_start(mesh_network_t *mesh,
                                  const mesh_node_config_t *config) {
    mesh_mgmt_agent_runtime_config_v1_t runtime_config;
    mesh_mgmt_execution_rpc_control_config_v1_t execution_config;
    mesh_mgmt_certificate_v1_t certificate;
    p2p_node_t *node;
    uint8_t transport_peer_id[P2P_KEY_SIZE];
    uint8_t management_public_key[32];
    uint8_t issuer_hash[32];
    uint8_t execution_grant_issuer_key[32];
    int execution_enabled;
    uint64_t now_ms;
#ifdef TURBO_P2P_ENABLE_NODE_EXECUTION
    mesh_mgmt_execution_node_config_v1_t node_execution_config;
#endif

    meshd_management_reset();
    if (!mesh_node_config_management_enabled(config)) {
        return 0;
    }

    memset(&runtime_config, 0, sizeof(runtime_config));
    memset(&certificate, 0, sizeof(certificate));
    memset(transport_peer_id, 0, sizeof(transport_peer_id));
    memset(management_public_key, 0, sizeof(management_public_key));
    memset(issuer_hash, 0, sizeof(issuer_hash));
    memset(execution_grant_issuer_key, 0,
           sizeof(execution_grant_issuer_key));
#ifdef TURBO_P2P_ENABLE_NODE_EXECUTION
    memset(&node_execution_config, 0, sizeof(node_execution_config));
#endif
    memset(&execution_config, 0, sizeof(execution_config));
    execution_enabled =
        config->mgmt_execution_grant_issuer_key_file[0] != '\0';

    if (meshd_read_hex_file_exact(config->mgmt_private_key_file,
                                  g_management_signer.private_key,
                                  sizeof(g_management_signer.private_key)) != 0 ||
        meshd_read_hex_file_exact(config->mgmt_certificate_file,
                                  g_management_signer.hello.certificate,
                                  sizeof(g_management_signer.hello.certificate)) != 0 ||
        meshd_read_hex_file_exact(config->mgmt_trusted_issuer_key_file,
                                  g_management_signer.trusted_issuer_key,
                                  sizeof(g_management_signer.trusted_issuer_key)) != 0 ||
        meshd_decode_hex_exact(config->mgmt_mesh_id_hex,
                               g_management_signer.expected_mesh_id_hash,
                               sizeof(g_management_signer.expected_mesh_id_hash)) != 0) {
        fprintf(stderr, "Failed to load exact management key/certificate material\n");
        goto failed;
    }
    if (execution_enabled &&
        meshd_read_hex_file_exact(
            config->mgmt_execution_grant_issuer_key_file,
            execution_grant_issuer_key,
            sizeof(execution_grant_issuer_key)) != 0) {
        fprintf(stderr, "Failed to load exact execution Grant issuer key\n");
        goto failed;
    }

    node = mesh_mgmt_mesh_borrow_p2p_node_v1(mesh);
    if (!node ||
        p2p_node_get_public_key(node, transport_peer_id) != P2P_OK ||
        mesh_mgmt_ed25519_public_from_private(g_management_signer.private_key,
                                              management_public_key) !=
            MESH_MGMT_CRYPTO_OK) {
        fprintf(stderr, "Failed to derive management transport identity\n");
        goto failed;
    }
    now_ms = turbo_realtime_ms();
    if (now_ms == 0u ||
        mesh_mgmt_certificate_verify_v1(
            g_management_signer.hello.certificate,
            sizeof(g_management_signer.hello.certificate),
            g_management_signer.trusted_issuer_key,
            g_management_signer.expected_mesh_id_hash,
            now_ms,
            &certificate) != MESH_MGMT_IDENTITY_OK ||
        certificate.principal_type != MESH_MGMT_PRINCIPAL_NODE ||
        !mesh_mgmt_crypto_equal_32(certificate.management_key,
                                   management_public_key) ||
        !mesh_mgmt_crypto_equal_32(certificate.transport_peer_id,
                                   transport_peer_id)) {
        fprintf(stderr, "Management certificate does not match trust, mesh, key, or P2P identity\n");
        goto failed;
    }
    if (execution_enabled &&
        (certificate.roles & MESH_MGMT_ROLE_OPERATOR) == 0u) {
        fprintf(stderr,
                "Node execution control requires an Operator management certificate\n");
        goto failed;
    }
    if (mesh_mgmt_blake2b_256(g_management_signer.trusted_issuer_key,
                              sizeof(g_management_signer.trusted_issuer_key),
                              issuer_hash) != MESH_MGMT_CRYPTO_OK ||
        turbo_secure_random(g_management_signer.session_id,
                            sizeof(g_management_signer.session_id)) != 0 ||
        turbo_secure_random(g_management_signer.hello.connection_id,
                            sizeof(g_management_signer.hello.connection_id)) != 0) {
        fprintf(stderr, "Failed to initialize management session entropy\n");
        goto failed;
    }

    memcpy(g_management_signer.local_transport_peer_id, transport_peer_id,
           sizeof(g_management_signer.local_transport_peer_id));
    g_management_signer.hello.major = MESH_MGMT_MAJOR_V1;
    g_management_signer.hello.min_minor = MESH_MGMT_MINOR_V1;
    g_management_signer.hello.max_minor = MESH_MGMT_MINOR_V1;
    g_management_signer.hello.features =
        MESH_MGMT_FEATURE_MEMBERSHIP |
        (execution_enabled
             ? MESH_MGMT_FEATURE_TARGETED_RPC |
                   MESH_MGMT_FEATURE_NODE_EXECUTION
             : 0u);
    g_management_signer.hello.platform = MESH_MGMT_PLATFORM_OTHER;
    memcpy(g_management_signer.hello.build_version, "meshd", 5u);
    g_management_signer.hello.build_version_len = 5u;
    memcpy(g_management_signer.hello.issuer_chain_hash, issuer_hash,
           sizeof(g_management_signer.hello.issuer_chain_hash));
    g_management_signer.hello.principal_type = certificate.principal_type;
    memcpy(g_management_signer.hello.management_key, certificate.management_key,
           sizeof(g_management_signer.hello.management_key));
    memcpy(g_management_signer.hello.managed_node_id, certificate.managed_node_id,
           sizeof(g_management_signer.hello.managed_node_id));
    g_management_signer.hello.max_frame =
        execution_enabled ? MESH_MGMT_FRAME_MAX
                          : MESH_MGMT_SESSION_MIN_FRAME;
    g_management_signer.hello.max_digest_entries = 64u;
    g_management_signer.hello.max_delta_batch = 32u;
    g_management_signer.incarnation = now_ms;
    g_management_signer.first_sequence = 1u;
    g_management_signer.frame_ttl_ms = MESHD_MGMT_FRAME_TTL_MS;

    memcpy(g_management_dispatch.session.expected_mesh_id_hash,
           g_management_signer.expected_mesh_id_hash,
           sizeof(g_management_dispatch.session.expected_mesh_id_hash));
    memcpy(g_management_dispatch.session.trusted_issuer_key,
           g_management_signer.trusted_issuer_key,
           sizeof(g_management_dispatch.session.trusted_issuer_key));
    g_management_dispatch.session.min_minor = MESH_MGMT_MINOR_V1;
    g_management_dispatch.session.max_minor = MESH_MGMT_MINOR_V1;
    g_management_dispatch.session.features =
        g_management_signer.hello.features;
    memcpy(g_management_dispatch.session.connection_id,
           g_management_signer.hello.connection_id,
           sizeof(g_management_dispatch.session.connection_id));
    g_management_dispatch.session.max_frame =
        g_management_signer.hello.max_frame;
    g_management_dispatch.session.max_digest_entries = 64u;
    g_management_dispatch.session.max_delta_batch = 32u;
    g_management_dispatch.replay.capacity = MESHD_MGMT_REPLAY_CAPACITY;
    g_management_dispatch.replay.ttl_ms = MESHD_MGMT_REPLAY_TTL_MS;
    if (execution_enabled) {
        g_management_dispatch.enable_node_execution_shadow = 1u;
        memcpy(g_management_dispatch.node_execution_grant_issuer_key,
               execution_grant_issuer_key,
               sizeof(g_management_dispatch.node_execution_grant_issuer_key));
        if (mesh_mgmt_execution_rpc_registry_init_v1(
                &g_execution_rpc_registry,
                MESHD_EXECUTION_RPC_CAPACITY,
                MESHD_EXECUTION_RPC_RETENTION_MS) !=
            MESH_MGMT_EXECUTION_RPC_REGISTRY_OK) {
            fprintf(stderr, "Failed to initialize execution RPC registry\n");
            goto failed;
        }
        execution_config.registry = &g_execution_rpc_registry;
        memcpy(execution_config.expected_mesh_id,
               g_management_signer.expected_mesh_id_hash,
               sizeof(execution_config.expected_mesh_id));
        memcpy(execution_config.local_principal_key,
               management_public_key,
               sizeof(execution_config.local_principal_key));
        memcpy(execution_config.expected_grant_issuer_key,
               execution_grant_issuer_key,
               sizeof(execution_config.expected_grant_issuer_key));
        execution_config.clock_now_ms = meshd_execution_clock_now_ms;
        execution_config.send = meshd_execution_send;
        if (mesh_mgmt_execution_rpc_control_init_v1(
                &g_execution_rpc_control, &execution_config) !=
            MESH_MGMT_EXECUTION_RPC_CONTROL_OK) {
            fprintf(stderr, "Failed to initialize execution RPC control\n");
            goto failed;
        }
        g_execution_rpc_configured = 1;
    }

#ifdef TURBO_P2P_ENABLE_NODE_EXECUTION
    if (g_execution_local_config.mode ==
        MESHD_EXECUTION_MODE_PRESTAGED_WASM) {
        if (!execution_enabled ||
            meshd_execution_config_build_node(
                &g_execution_local_config,
                g_management_signer.hello.managed_node_id,
                g_management_signer.private_key,
                execution_grant_issuer_key,
                meshd_execution_clock_now_ms,
                NULL,
                &node_execution_config) != 0 ||
            mesh_mgmt_execution_node_init_v1(
                &g_execution_node,
                &node_execution_config) != MESH_MGMT_EXECUTION_NODE_OK) {
            fprintf(stderr, "Failed to initialize node execution runtime\n");
            goto failed;
        }
        g_execution_node_configured = 1;
    }
#endif

    runtime_config.shared_mesh = mesh;
    runtime_config.max_peers = MESHD_MGMT_RUNTIME_MAX_PEERS;
    runtime_config.signer_template = &g_management_signer;
    runtime_config.dispatch_template = &g_management_dispatch;
    runtime_config.endpoint_capacity = MESHD_MGMT_RUNTIME_MAX_PEERS;
    runtime_config.retry_base_ms = 1000u;
    runtime_config.retry_max_ms = 60000u;
    runtime_config.connect_timeout_ms = 10000u;
    runtime_config.protocol_failure_limit = 2u;
    runtime_config.first_endpoint_record_epoch = config->mgmt_first_record_epoch;
    runtime_config.first_service_record_epoch = config->mgmt_first_record_epoch;
    if (meshd_management_epoch_open(&g_management_epoch_state,
                                    config->mgmt_record_epoch_file,
                                    config->mgmt_first_record_epoch) != 0) {
        goto failed;
    }
    runtime_config.allocate_record_epoch = meshd_management_epoch_allocate;
    runtime_config.record_epoch_context = &g_management_epoch_state;
    runtime_config.admit_peer = meshd_management_admit_peer;
    runtime_config.on_event = meshd_management_event;

    if (mesh_mgmt_agent_runtime_init_v1(&g_management_runtime, &runtime_config) !=
            MESH_MGMT_AGENT_RUNTIME_OK ||
        mesh_mgmt_agent_runtime_start_v1(&g_management_runtime) !=
            MESH_MGMT_AGENT_RUNTIME_OK) {
        fprintf(stderr, "Failed to start shared management runtime\n");
        goto failed;
    }
    g_management_configured = 1;
    mesh_mgmt_crypto_wipe(&certificate, sizeof(certificate));
    mesh_mgmt_crypto_wipe(transport_peer_id, sizeof(transport_peer_id));
    mesh_mgmt_crypto_wipe(management_public_key, sizeof(management_public_key));
    mesh_mgmt_crypto_wipe(issuer_hash, sizeof(issuer_hash));
    mesh_mgmt_crypto_wipe(execution_grant_issuer_key,
                          sizeof(execution_grant_issuer_key));
    return 0;

failed:
    mesh_mgmt_agent_runtime_destroy_v1(&g_management_runtime);
    mesh_mgmt_crypto_wipe(&certificate, sizeof(certificate));
    mesh_mgmt_crypto_wipe(transport_peer_id, sizeof(transport_peer_id));
    mesh_mgmt_crypto_wipe(management_public_key, sizeof(management_public_key));
    mesh_mgmt_crypto_wipe(issuer_hash, sizeof(issuer_hash));
    mesh_mgmt_crypto_wipe(execution_grant_issuer_key,
                          sizeof(execution_grant_issuer_key));
    meshd_management_reset();
    return -1;
}

static meshd_service_resolve_result_t meshd_management_resolve_service(
    void *context,
    const char node_id_hex[MESHD_NODE_ID_HEX_LENGTH + 1],
    meshd_verified_service_snapshot_t *out_snapshot) {
    mesh_mgmt_agent_runtime_v1_t *runtime =
        (mesh_mgmt_agent_runtime_v1_t *)context;
    mesh_mgmt_service_record_v1_t record;
    uint8_t node_id[32];
    mesh_mgmt_agent_runtime_result_t result;

    if (!runtime || !node_id_hex || !out_snapshot ||
        runtime->state != MESH_MGMT_AGENT_RUNTIME_RUNNING ||
        meshd_decode_hex_exact(node_id_hex, node_id, sizeof(node_id)) != 0) {
        return MESHD_SERVICE_RESOLVE_UNAVAILABLE;
    }
    memset(&record, 0, sizeof(record));
    result = mesh_mgmt_agent_runtime_resolve_cached_service_v1(
        runtime, node_id, turbo_realtime_ms(),
        MESH_MGMT_SERVICE_RECORD_MAX_TTL_MS, &record);
    mesh_mgmt_crypto_wipe(node_id, sizeof(node_id));
    if (result == MESH_MGMT_AGENT_RUNTIME_DISCOVERY_FAILED) {
        return MESHD_SERVICE_RESOLVE_NOT_FOUND;
    }
    if (result != MESH_MGMT_AGENT_RUNTIME_OK) {
        mesh_mgmt_crypto_wipe(&record, sizeof(record));
        return MESHD_SERVICE_RESOLVE_VERIFICATION_FAILED;
    }
    snprintf(out_snapshot->virtual_host, sizeof(out_snapshot->virtual_host),
             "%s", record.virtual_host);
    snprintf(out_snapshot->virtual_ip, sizeof(out_snapshot->virtual_ip),
             "%s", record.virtual_ip);
    out_snapshot->port = record.port;
    out_snapshot->record_epoch = record.record_epoch;
    out_snapshot->expires_at_ms = record.expires_at_ms;
    mesh_mgmt_crypto_wipe(&record, sizeof(record));
    return MESHD_SERVICE_RESOLVE_OK;
}

static int meshd_management_publish_rpc_service(void) {
    mesh_mgmt_service_publish_v1_t service;
    uint64_t record_epoch = 0u;

    if (!g_management_configured ||
        g_management_runtime.state != MESH_MGMT_AGENT_RUNTIME_RUNNING ||
        g_mgmt_server.service_port == 0u) {
        return -1;
    }
    memset(&service, 0, sizeof(service));
    service.address_family = MESH_MGMT_SERVICE_ADDRESS_IPV4;
    if (inet_pton(AF_INET, g_config.virtual_ip, service.virtual_address) != 1) {
        return -1;
    }
    service.dns_name =
        strcmp(g_mgmt_server.virtual_host, g_config.virtual_ip) == 0
            ? ""
            : g_mgmt_server.virtual_host;
    service.port = g_mgmt_server.service_port;
    if (mesh_mgmt_agent_runtime_publish_cached_service_v1(
            &g_management_runtime, &service, &record_epoch) !=
        MESH_MGMT_AGENT_RUNTIME_OK) {
        return -1;
    }
    g_management_last_publish_ms = meshd_now_ms();
    return 0;
}

static int meshd_socket_is_valid(meshd_socket_t socket_fd) {
    return !MESHD_SOCKET_CMP(socket_fd, MESHD_INVALID_SOCKET);
}

static void meshd_close_socket(meshd_socket_t socket_fd) {
    if (!meshd_socket_is_valid(socket_fd)) {
        return;
    }

#ifdef _WIN32
    closesocket(socket_fd);
#else
    close(socket_fd);
#endif
}

static int meshd_socket_set_nonblocking(meshd_socket_t socket_fd) {
#ifdef _WIN32
    u_long mode = 1;
    return ioctlsocket(socket_fd, FIONBIO, &mode) == 0 ? 0 : -1;
#else
    int flags = fcntl(socket_fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK);
#endif
}

static int meshd_socket_send_all(meshd_socket_t socket_fd, const char *data, size_t len) {
    size_t offset = 0;

    while (offset < len) {
        int sent = send(socket_fd, data + offset, (int)(len - offset), 0);
        if (sent > 0) {
            offset += (size_t)sent;
            continue;
        }

#ifdef _WIN32
        if (WSAGetLastError() == WSAEWOULDBLOCK || WSAGetLastError() == WSAEINPROGRESS) {
            continue;
        }
#else
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            continue;
        }
#endif
        return -1;
    }

    return 0;
}

static void meshd_task_generate_id(char *out, size_t out_size) {
    if (!out || out_size == 0) {
        return;
    }

    g_mgmt_task_counter++;
    snprintf(out, out_size, "task-%llu-%u",
             (unsigned long long)meshd_now_ms(),
             g_mgmt_task_counter);
}

static const char *meshd_task_layer_name(meshd_task_layer_t layer) {
    switch (layer) {
        case MESHD_TASK_LAYER_MESH_DATA_PLANE:
            return "mesh_data_plane";
        case MESHD_TASK_LAYER_NODE_CONTROL:
            return "node_control";
        default:
            break;
    }
    return "unknown";
}

static int meshd_parse_node_resolve_path(
    const char *path,
    char out_node_id[MESHD_NODE_ID_HEX_LENGTH + 1]) {
    static const char PREFIX[] = "/v1/node/resolve/";
    const char *node_id = NULL;
    size_t index = 0;

    if (out_node_id) {
        out_node_id[0] = '\0';
    }
    if (!path || strncmp(path, PREFIX, sizeof(PREFIX) - 1) != 0) {
        return -1;
    }
    node_id = path + sizeof(PREFIX) - 1;
    if (strlen(node_id) != MESHD_NODE_ID_HEX_LENGTH) {
        return -1;
    }
    for (index = 0; index < MESHD_NODE_ID_HEX_LENGTH; index++) {
        if (!((node_id[index] >= '0' && node_id[index] <= '9') ||
              (node_id[index] >= 'a' && node_id[index] <= 'f'))) {
            return -1;
        }
    }
    if (out_node_id) {
        memcpy(out_node_id, node_id, MESHD_NODE_ID_HEX_LENGTH + 1);
    }
    return 0;
}

static int meshd_service_host_is_canonical(const char *value,
                                           size_t capacity,
                                           int allow_hyphen) {
    size_t index = 0;

    if (!value || value[0] == '\0') {
        return 0;
    }
    for (index = 0; index < capacity && value[index] != '\0'; index++) {
        char ch = value[index];
        if ((ch >= '0' && ch <= '9') ||
            (ch >= 'a' && ch <= (allow_hyphen ? 'z' : 'f')) ||
            ch == '.' || ch == ':' || (allow_hyphen && ch == '-')) {
            continue;
        }
        return 0;
    }
    return index > 0 && index < capacity;
}

static meshd_service_resolve_result_t meshd_resolve_node_service_json(
    meshd_mgmt_server_t *server,
    const char *path,
    char *out,
    size_t out_size) {
    char node_id[MESHD_NODE_ID_HEX_LENGTH + 1] = {0};
    meshd_verified_service_snapshot_t snapshot = {0};
    meshd_service_resolve_result_t result;
    int written = 0;

    if (!server || !out || out_size == 0 ||
        meshd_parse_node_resolve_path(path, node_id) != 0) {
        return MESHD_SERVICE_RESOLVE_NOT_FOUND;
    }
    out[0] = '\0';
    if (!server->resolve_service) {
        return MESHD_SERVICE_RESOLVE_UNAVAILABLE;
    }
    result = server->resolve_service(server->resolve_service_context,
                                     node_id,
                                     &snapshot);
    if (result != MESHD_SERVICE_RESOLVE_OK) {
        return result;
    }
    if (!meshd_service_host_is_canonical(snapshot.virtual_host,
                                         sizeof(snapshot.virtual_host),
                                         1) ||
        !meshd_service_host_is_canonical(snapshot.virtual_ip,
                                         sizeof(snapshot.virtual_ip),
                                         0) ||
        snapshot.port == 0 || snapshot.record_epoch == 0 ||
        snapshot.expires_at_ms == 0) {
        return MESHD_SERVICE_RESOLVE_VERIFICATION_FAILED;
    }

    written = snprintf(
        out,
        out_size,
        "{\"node_id\":\"%s\",\"service\":\"rpc\",\"virtual_host\":\"%s\","
        "\"virtual_ip\":\"%s\",\"port\":%u,\"record_epoch\":%llu,"
        "\"expires_at_ms\":%llu,\"source\":\"verified_service_record\"}",
        node_id,
        snapshot.virtual_host,
        snapshot.virtual_ip,
        (unsigned)snapshot.port,
        (unsigned long long)snapshot.record_epoch,
        (unsigned long long)snapshot.expires_at_ms);
    if (written < 0 || (size_t)written >= out_size) {
        out[0] = '\0';
        return MESHD_SERVICE_RESOLVE_VERIFICATION_FAILED;
    }
    return MESHD_SERVICE_RESOLVE_OK;
}

static void meshd_classify_mgmt_task(const char *method,
                                     const char *path,
                                     meshd_task_model_t *out_task) {
    if (!out_task) {
        return;
    }

    out_task->type = "unknown";
    out_task->layer = meshd_task_layer_name(MESHD_TASK_LAYER_UNKNOWN);
    out_task->impact = "unknown";
    out_task->requires_token = 1;
    out_task->safe_to_retry = 1;

    if (!method || !path) {
        return;
    }

    if ((strcmp(method, "GET") == 0 && strcmp(path, "/health") == 0) ||
        (strcmp(method, "GET") == 0 && strcmp(path, "/v1/health") == 0)) {
        out_task->type = "mesh.health.query";
        out_task->layer = meshd_task_layer_name(MESHD_TASK_LAYER_MESH_DATA_PLANE);
        out_task->impact = "read";
        out_task->requires_token = 0;
        out_task->safe_to_retry = 1;
        return;
    }

    if ((strcmp(method, "GET") == 0 && strcmp(path, "/status") == 0) ||
        (strcmp(method, "GET") == 0 && strcmp(path, "/v1/status") == 0)) {
        out_task->type = "mesh.status.snapshot";
        out_task->layer = meshd_task_layer_name(MESHD_TASK_LAYER_MESH_DATA_PLANE);
        out_task->impact = "read";
        out_task->requires_token = 0;
        out_task->safe_to_retry = 1;
        return;
    }

    if (strcmp(method, "GET") == 0 && strcmp(path, "/ping") == 0) {
        out_task->type = "mesh.ping";
        out_task->layer = meshd_task_layer_name(MESHD_TASK_LAYER_MESH_DATA_PLANE);
        out_task->impact = "read";
        out_task->requires_token = 0;
        out_task->safe_to_retry = 1;
        return;
    }

    if (strcmp(method, "GET") == 0 &&
        meshd_parse_node_resolve_path(path, NULL) == 0) {
        out_task->type = "node.resolve";
        out_task->layer = meshd_task_layer_name(MESHD_TASK_LAYER_MESH_DATA_PLANE);
        out_task->impact = "read";
        out_task->requires_token = 1;
        out_task->safe_to_retry = 1;
        return;
    }

    if (strcmp(method, "POST") == 0 && strcmp(path, "/v1/shutdown") == 0) {
        out_task->type = "node.shutdown";
        out_task->layer = meshd_task_layer_name(MESHD_TASK_LAYER_NODE_CONTROL);
        out_task->impact = "mutating";
        out_task->requires_token = 1;
        out_task->safe_to_retry = 0;
        return;
    }

    if (strcmp(method, "POST") == 0 &&
        strcmp(path, "/v1/executions") == 0) {
        out_task->type = "node.execution.submit";
        out_task->layer = "node_execution";
        out_task->impact = "mutating";
        out_task->requires_token = 1;
        out_task->safe_to_retry = 1;
        return;
    }

    if (strcmp(method, "GET") == 0 &&
        strncmp(path, "/v1/executions/", 15u) == 0 &&
        strlen(path) == 15u + MESHD_NODE_ID_HEX_LENGTH) {
        out_task->type = "node.execution.query";
        out_task->layer = "node_execution";
        out_task->impact = "read";
        out_task->requires_token = 1;
        out_task->safe_to_retry = 1;
        return;
    }

    if (strcmp(method, "GET") == 0 && strcmp(path, "/v1/task-model") == 0) {
        out_task->type = "mesh.task-model";
        out_task->layer = meshd_task_layer_name(MESHD_TASK_LAYER_MESH_DATA_PLANE);
        out_task->impact = "read";
        out_task->requires_token = 0;
        out_task->safe_to_retry = 1;
    }
}

static int meshd_build_task_response_json(char *out,
                                         size_t out_size,
                                         const char *task_id,
                                         const meshd_task_model_t *task_model,
                                         int ok,
                                         const char *result_json,
                                         const char *error_code,
                                         const char *error_message) {
    int written = 0;

    if (!out || out_size == 0 || !task_id || !task_model) {
        return -1;
    }
    out[0] = '\0';

    if (ok) {
        if (!result_json) {
            result_json = "null";
        }
        written = snprintf(out, out_size,
                           "{\"ok\":true,\"task\":{\"id\":\"%s\",\"type\":\"%s\",\"target_layer\":\"%s\","
                           "\"impact\":\"%s\",\"safe_to_retry\":%s},\"result\":%s}",
                           task_id,
                           task_model->type,
                           task_model->layer,
                           task_model->impact,
                           task_model->safe_to_retry ? "true" : "false",
                           result_json);
    } else {
        written = snprintf(out, out_size,
                           "{\"ok\":false,\"task\":{\"id\":\"%s\",\"type\":\"%s\",\"target_layer\":\"%s\","
                           "\"impact\":\"%s\",\"safe_to_retry\":%s},\"error\":{\"code\":\"%s\",\"message\":\"%s\"}}",
                           task_id,
                           task_model->type,
                           task_model->layer,
                           task_model->impact,
                           task_model->safe_to_retry ? "true" : "false",
                           error_code ? error_code : "request.failed",
                           error_message ? error_message : "request failed");
    }
    if (written < 0 || (size_t)written >= out_size) {
        out[0] = '\0';
        return -1;
    }
    return 0;
}

static int meshd_parse_host_port(const char *value,
                                char *host,
                                size_t host_size,
                                uint16_t *port) {
    char copy[128] = {0};
    char *colon = NULL;
    char *port_end = NULL;
    const char *normalized_host = NULL;
    size_t host_len = 0;
    size_t value_len = 0;
    unsigned long parsed_port = 0;

    if (!value || !host || !port || host_size == 0) {
        return -1;
    }
    host[0] = '\0';
    *port = 0;

    value_len = strlen(value);
    if (value_len == 0 || value_len >= sizeof(copy)) {
        return -1;
    }
    memcpy(copy, value, value_len + 1);
    colon = strrchr(copy, ':');
    if (!colon) {
        return -1;
    }

    *colon = '\0';
    if (copy[0] == '\0') {
        normalized_host = "127.0.0.1";
    } else {
        normalized_host = copy;
    }
    host_len = strlen(normalized_host);
    if (host_len >= host_size) {
        return -1;
    }

    parsed_port = strtoul(colon + 1, &port_end, 10);
    if (port_end == colon + 1 || *port_end != '\0' ||
        parsed_port == 0 || parsed_port > 65535) {
        return -1;
    }

    memcpy(host, normalized_host, host_len + 1);
    *port = (uint16_t)parsed_port;
    return 0;
}

static int meshd_mgmt_configure_service_endpoint(meshd_mgmt_server_t *server,
                                                 mesh_network_t *mesh,
                                                 const char *virtual_ip,
                                                 uint16_t service_port) {
    char resolved_host[sizeof(server->virtual_host)] = {0};
    const char *virtual_host = virtual_ip;
    size_t virtual_host_len = 0;
    int written = 0;

    if (!server || !virtual_ip || virtual_ip[0] == '\0' || service_port == 0) {
        return -1;
    }
    if (mesh &&
        mesh_reverse_magic_dns(mesh,
                               virtual_ip,
                               resolved_host,
                               sizeof(resolved_host)) == MESH_OK) {
        virtual_host = resolved_host;
    }

    virtual_host_len = strlen(virtual_host);
    if (virtual_host_len == 0 || virtual_host_len >= sizeof(server->virtual_host)) {
        return -1;
    }
    memcpy(server->virtual_host, virtual_host, virtual_host_len + 1);
    server->service_port = service_port;
    written = snprintf(server->service_endpoint,
                       sizeof(server->service_endpoint),
                       "http://%s:%u",
                       server->virtual_host,
                       server->service_port);
    if (written < 0 || (size_t)written >= sizeof(server->service_endpoint)) {
        server->virtual_host[0] = '\0';
        server->service_port = 0;
        server->service_endpoint[0] = '\0';
        return -1;
    }
    return 0;
}

static int meshd_send_http_response(meshd_socket_t client_socket,
                                   int status_code,
                                   const char *status_text,
                                   const char *body,
                                   size_t body_len) {
    char header[512];
    int ret = 0;

    if (!meshd_socket_is_valid(client_socket) || !status_text || !body) {
        return -1;
    }

    snprintf(header, sizeof(header),
             "HTTP/1.1 %d %s\r\n"
             "Content-Type: application/json; charset=utf-8\r\n"
             "Content-Length: %zu\r\n"
             "Connection: close\r\n"
             "\r\n",
             status_code,
             status_text,
             body_len);

    ret = meshd_socket_send_all(client_socket, header, strlen(header));
    if (ret != 0) {
        return -1;
    }

    return meshd_socket_send_all(client_socket, body, body_len);
}

static int meshd_ascii_equal_ci(const char *left,
                                const char *right,
                                size_t length) {
    size_t index = 0;

    if (!left || !right) {
        return 0;
    }

    for (index = 0; index < length; index++) {
        unsigned char left_char = (unsigned char)left[index];
        unsigned char right_char = (unsigned char)right[index];

        if (left_char >= 'A' && left_char <= 'Z') {
            left_char = (unsigned char)(left_char + ('a' - 'A'));
        }
        if (right_char >= 'A' && right_char <= 'Z') {
            right_char = (unsigned char)(right_char + ('a' - 'A'));
        }
        if (left_char != right_char) {
            return 0;
        }
    }
    return 1;
}

static int meshd_token_equal(const char *expected,
                             size_t expected_len,
                             const char *actual,
                             size_t actual_len) {
    size_t index = 0;
    unsigned char difference = 0;

    if (!expected || !actual || expected_len != actual_len) {
        return 0;
    }
    for (index = 0; index < expected_len; index++) {
        difference |= (unsigned char)expected[index] ^ (unsigned char)actual[index];
    }
    return difference == 0;
}

static int meshd_check_token(const meshd_mgmt_server_t *server, const char *request_text) {
    static const char token_header_name[] = "X-Meshd-Token";
    const char *token = NULL;
    const char *line = NULL;
    int token_header_found = 0;
    int token_matches = 0;

    if (!server || !request_text) {
        return 0;
    }
    token = server->token[0] ? server->token : NULL;
    if (!token) {
        return 1;
    }

    line = strstr(request_text, "\r\n");
    if (!line) {
        return 0;
    }
    line += 2;

    while (*line) {
        const char *line_end = strstr(line, "\r\n");
        const char *colon = NULL;
        const char *value = NULL;
        const char *value_end = NULL;
        size_t name_len = 0;

        if (!line_end) {
            return 0;
        }
        if (line_end == line) {
            return token_header_found && token_matches;
        }

        colon = (const char *)memchr(line, ':', (size_t)(line_end - line));
        if (colon) {
            name_len = (size_t)(colon - line);
        }
        if (colon &&
            name_len == sizeof(token_header_name) - 1 &&
            meshd_ascii_equal_ci(line, token_header_name, name_len)) {
            if (token_header_found) {
                return 0;
            }
            token_header_found = 1;
            value = colon + 1;
            while (value < line_end && (*value == ' ' || *value == '\t')) {
                value++;
            }
            value_end = line_end;
            while (value_end > value &&
                   (value_end[-1] == ' ' || value_end[-1] == '\t')) {
                value_end--;
            }
            token_matches = meshd_token_equal(token,
                                              strlen(token),
                                              value,
                                              (size_t)(value_end - value));
        }
        line = line_end + 2;
    }
    return 0;
}

static int meshd_build_health_json(char *out, size_t out_size) {
    mesh_runtime_health_t health;
    int ret = mesh_runtime_health_eval(g_mesh, g_config.bootstrap_count, &health);

    if (out == NULL || out_size == 0) {
        return -1;
    }

    if (ret != 0) {
        snprintf(out, out_size, "{\"state\":\"unhealthy\",\"reason\":\"not_ready\",\"summary\":\"mesh unavailable\","
                                 "\"path_mode\":\"isolated\",\"signals\":{\"bootstrap_configured\":false,"
                                 "\"bootstrap_reconnect_pending\":false,\"has_direct_peer\":false,"
                                 "\"has_relay_path\":false,\"has_any_path\":false,\"ice_enabled\":false,"
                                 "\"ice_progressing\":false,\"ice_failed\":false}}");
        return 0;
    }

    snprintf(out, out_size,
             "{\"state\":\"%s\",\"reason\":\"%s\",\"summary\":\"%s\",\"path_mode\":\"%s\","
             "\"signals\":{\"bootstrap_configured\":%s,\"bootstrap_reconnect_pending\":%s,"
             "\"has_direct_peer\":%s,\"has_relay_path\":%s,\"has_any_path\":%s,"
             "\"ice_enabled\":%s,\"ice_progressing\":%s,\"ice_failed\":%s}}",
             mesh_runtime_health_state_string(health.state),
             mesh_runtime_health_reason_string(health.reason),
             mesh_runtime_health_summary(&health),
             mesh_path_mode_string(health.path_mode),
             health.bootstrap_configured ? "true" : "false",
             health.bootstrap_reconnect_pending ? "true" : "false",
             health.has_direct_peer ? "true" : "false",
             health.has_relay_path ? "true" : "false",
             health.has_any_path ? "true" : "false",
             health.ice_enabled ? "true" : "false",
             health.ice_progressing ? "true" : "false",
             health.ice_failed ? "true" : "false");
    return 0;
}

static int meshd_build_status_json(char *out, size_t out_size) {
    mesh_stats_t stats;
    mesh_diag_info_t diag;
    char health_body[1024] = {0};
    uint64_t now_ms = meshd_now_ms();
    int written = 0;
    int peer_count = 0;
    int route_count = 0;

    if (out == NULL || out_size == 0) {
        return -1;
    }
    out[0] = '\0';

    if (!g_mesh) {
        meshd_build_health_json(health_body, sizeof(health_body));
        written = snprintf(out, out_size,
                           "{\"running\":false,\"node_name\":\"%s\",\"network_id\":\"%s\","
                           "\"virtual_ip\":\"%s\",\"listen_port\":%d,\"uptime_ms\":%llu,"
                           "\"rpc\":{\"enabled\":%s,\"endpoint\":\"%s\",\"virtual_host\":\"%s\",\"port\":%u},"
                           "\"peer_count\":0,\"route_count\":0,\"dht_entries\":0,"
                           "\"health\":%s,\"connected_relay_routes\":0,"
                           "\"control_plane_refreshes\":0}",
                           g_config.node_name,
                           g_config.network_id,
                           g_config.virtual_ip,
                           g_config.listen_port,
                           (unsigned long long)(now_ms - g_started_ms),
                           g_mgmt_server.service_endpoint[0] ? "true" : "false",
                           g_mgmt_server.service_endpoint,
                           g_mgmt_server.virtual_host,
                           g_mgmt_server.service_port,
                           health_body[0] ? health_body : "{\"state\":\"unavailable\",\"reason\":\"not_ready\","
                                                           "\"summary\":\"mesh unavailable\","
                                                           "\"path_mode\":\"isolated\","
                                                           "\"signals\":{\"bootstrap_configured\":false,"
                                                           "\"bootstrap_reconnect_pending\":false,\"has_direct_peer\":false,"
                                                           "\"has_relay_path\":false,\"has_any_path\":false,"
                                                           "\"ice_enabled\":false,\"ice_progressing\":false,\"ice_failed\":false}}");
        if (written < 0 || (size_t)written >= out_size) {
            out[0] = '\0';
            return -1;
        }
        return 0;
    }

    memset(&stats, 0, sizeof(stats));
    memset(&diag, 0, sizeof(diag));
    if (mesh_get_stats(g_mesh, &stats) != MESH_OK) {
        return -1;
    }
    if (mesh_get_diag_info(g_mesh, &diag) != MESH_OK) {
        return -1;
    }
    peer_count = mesh_get_peer_count(g_mesh);
    route_count = mesh_get_route_count(g_mesh);

    if (meshd_build_health_json(health_body, sizeof(health_body)) != 0) {
        snprintf(health_body, sizeof(health_body),
                 "{\"state\":\"unavailable\",\"reason\":\"unknown\",\"summary\":\"health unavailable\",\"path_mode\":\"isolated\","
                 "\"signals\":{\"bootstrap_configured\":false,\"bootstrap_reconnect_pending\":false,"
                 "\"has_direct_peer\":false,\"has_relay_path\":false,\"has_any_path\":false,"
                 "\"ice_enabled\":false,\"ice_progressing\":false,\"ice_failed\":false}}");
    }

    written = snprintf(out, out_size,
                       "{\"running\":%s,\"node_name\":\"%s\",\"network_id\":\"%s\","
                       "\"virtual_ip\":\"%s\",\"listen_port\":%d,\"uptime_ms\":%llu,"
                       "\"rpc\":{\"enabled\":%s,\"endpoint\":\"%s\",\"virtual_host\":\"%s\",\"port\":%u},"
                       "\"peer_count\":%d,\"route_count\":%d,\"dht_entries\":%u,"
                       "\"health\":%s,\"connected_relay_routes\":%u,"
                       "\"control_plane_refreshes\":%u}",
                       meshd_is_running() ? "true" : "false",
                       g_config.node_name,
                       g_config.network_id,
                       g_config.virtual_ip,
                       g_config.listen_port,
                       (unsigned long long)(now_ms - g_started_ms),
                       g_mgmt_server.service_endpoint[0] ? "true" : "false",
                       g_mgmt_server.service_endpoint,
                       g_mgmt_server.virtual_host,
                       g_mgmt_server.service_port,
                       peer_count,
                       route_count,
                       stats.dht_entries,
                       health_body,
                       diag.connected_relay_route_count,
                       diag.control_plane_refreshes);
    if (written < 0 || (size_t)written >= out_size) {
        out[0] = '\0';
        return -1;
    }

    return 0;
}

static int meshd_mgmt_server_start(meshd_mgmt_server_t *server,
                                   const char *listen_arg,
                                   const char *token,
                                   mesh_network_t *mesh,
                                   const char *virtual_ip) {
    struct sockaddr_in bind_addr;
    int reuse = 1;

    if (!server || !listen_arg) {
        return -1;
    }

    memset(server, 0, sizeof(*server));
    server->listen_socket = MESHD_INVALID_SOCKET;

    if (meshd_parse_host_port(listen_arg, server->bind_host,
                              sizeof(server->bind_host), &server->bind_port) != 0) {
        fprintf(stderr, "Invalid --rpc-listen format: %s\n", listen_arg);
        return -1;
    }
    if (meshd_mgmt_configure_service_endpoint(server,
                                              mesh,
                                              virtual_ip,
                                              server->bind_port) != 0) {
        fprintf(stderr, "Failed to configure virtual RPC service endpoint\n");
        return -1;
    }
    if (token && token[0] != '\0') {
        snprintf(server->token, sizeof(server->token), "%s", token);
    }

#ifdef _WIN32
    {
        WSADATA wsa_data;
        if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
            fprintf(stderr, "Failed to initialize Winsock for RPC server\n");
            return -1;
        }
    }
#endif

    server->listen_socket = (meshd_socket_t)socket(AF_INET, SOCK_STREAM, 0);
    if (!meshd_socket_is_valid(server->listen_socket)) {
        fprintf(stderr, "RPC server socket create failed\n");
        return -1;
    }

    if (meshd_socket_set_nonblocking(server->listen_socket) != 0) {
        fprintf(stderr, "RPC server set nonblocking failed\n");
        meshd_close_socket(server->listen_socket);
        server->listen_socket = MESHD_INVALID_SOCKET;
        return -1;
    }

    if (setsockopt(server->listen_socket,
                   SOL_SOCKET,
                   SO_REUSEADDR,
                   (const char *)&reuse,
                   sizeof(reuse)) != 0) {
        fprintf(stderr, "RPC server setsockopt(SO_REUSEADDR) failed\n");
    }

    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(server->bind_port);
    if (inet_pton(AF_INET, server->bind_host, &bind_addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid RPC bind host: %s\n", server->bind_host);
        meshd_close_socket(server->listen_socket);
        server->listen_socket = MESHD_INVALID_SOCKET;
        return -1;
    }

    if (bind(server->listen_socket, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) != 0) {
        fprintf(stderr, "RPC bind failed on %s:%u\n", server->bind_host, server->bind_port);
        meshd_close_socket(server->listen_socket);
        server->listen_socket = MESHD_INVALID_SOCKET;
        return -1;
    }

    if (listen(server->listen_socket, 8) != 0) {
        fprintf(stderr, "RPC listen failed on %s:%u\n", server->bind_host, server->bind_port);
        meshd_close_socket(server->listen_socket);
        server->listen_socket = MESHD_INVALID_SOCKET;
        return -1;
    }

    fprintf(stdout, "RPC management bind: %s:%u\n", server->bind_host, server->bind_port);
    fprintf(stdout, "RPC service endpoint: %s\n", server->service_endpoint);
    return 0;
}

static void meshd_mgmt_server_stop(meshd_mgmt_server_t *server) {
    if (!server) {
        return;
    }

    meshd_close_socket(server->listen_socket);
    server->listen_socket = MESHD_INVALID_SOCKET;
    server->bind_port = 0;
    server->bind_host[0] = '\0';
    server->service_port = 0;
    server->virtual_host[0] = '\0';
    server->service_endpoint[0] = '\0';
    server->token[0] = '\0';
    server->resolve_service = NULL;
    server->resolve_service_context = NULL;

#ifdef _WIN32
    WSACleanup();
#endif
}

static void meshd_encode_hex(const uint8_t *bytes,
                             size_t bytes_size,
                             char *out,
                             size_t out_size) {
    static const char digits[] = "0123456789abcdef";
    size_t index;

    if (!bytes || !out || out_size < bytes_size * 2u + 1u) {
        if (out && out_size != 0u) {
            out[0] = '\0';
        }
        return;
    }
    for (index = 0u; index < bytes_size; index++) {
        out[index * 2u] = digits[bytes[index] >> 4u];
        out[index * 2u + 1u] = digits[bytes[index] & 0x0fu];
    }
    out[bytes_size * 2u] = '\0';
}

static int meshd_build_execution_json(
    char *out,
    size_t out_size,
    const mesh_mgmt_execution_rpc_completion_v1_t *completion) {
    char command_id[65];
    char correlation_id[65];
    char request_digest[65];
    char target_node_id[65];
    const char *state;
    unsigned int response_kind = 0u;
    unsigned int status_code = 0u;
    int written;

    if (!out || out_size == 0u || !completion) {
        return -1;
    }
    switch (completion->state) {
        case MESH_MGMT_EXECUTION_RPC_PENDING:
            state = "pending";
            break;
        case MESH_MGMT_EXECUTION_RPC_RESULT:
            state = "result";
            response_kind = completion->response.kind;
            break;
        case MESH_MGMT_EXECUTION_RPC_STATUS:
            state = "status";
            response_kind = completion->response.kind;
            status_code = completion->response.status.code;
            break;
        case MESH_MGMT_EXECUTION_RPC_TIMED_OUT:
            state = "timed_out";
            break;
        default:
            return -1;
    }
    meshd_encode_hex(completion->binding.command_id,
                     sizeof(completion->binding.command_id),
                     command_id, sizeof(command_id));
    meshd_encode_hex(completion->binding.correlation_id,
                     sizeof(completion->binding.correlation_id),
                     correlation_id, sizeof(correlation_id));
    meshd_encode_hex(completion->binding.request_digest,
                     sizeof(completion->binding.request_digest),
                     request_digest, sizeof(request_digest));
    meshd_encode_hex(completion->binding.target_node_id,
                     sizeof(completion->binding.target_node_id),
                     target_node_id, sizeof(target_node_id));
    written = snprintf(
        out, out_size,
        "{\"state\":\"%s\",\"command_id\":\"%s\","
        "\"correlation_id\":\"%s\",\"request_digest\":\"%s\","
        "\"target_node_id\":\"%s\",\"deadline_ms\":%llu,"
        "\"response_kind\":%u,\"status_code\":%u}",
        state, command_id, correlation_id, request_digest, target_node_id,
        (unsigned long long)completion->binding.deadline_ms,
        response_kind, status_code);
    return written < 0 || (size_t)written >= out_size ? -1 : 0;
}

static int meshd_send_execution_error(
    meshd_socket_t client_socket,
    const char *task_id,
    const meshd_task_model_t *task_model,
    int status,
    const char *status_text,
    const char *error_code,
    const char *error_message) {
    char body[MESHD_MGMT_RESPONSE_BUF_SIZE];

    if (meshd_build_task_response_json(
            body, sizeof(body), task_id, task_model, 0, NULL,
            error_code, error_message) != 0) {
        return -1;
    }
    return meshd_send_http_response(
        client_socket, status, status_text, body, strlen(body));
}

static int meshd_handle_execution_http(
    meshd_socket_t client_socket,
    const meshd_mgmt_http_request_t *request,
    const char *method,
    const char *path,
    const char *task_id,
    const meshd_task_model_t *task_model) {
    mesh_mgmt_execution_rpc_binding_v1_t binding;
    mesh_mgmt_execution_rpc_completion_v1_t completion;
    mesh_mgmt_execution_rpc_control_result_t result;
    uint8_t correlation_id[32];
    char result_json[1024];
    char body[MESHD_MGMT_RESPONSE_BUF_SIZE];
    int status = 200;
    const char *status_text = "OK";

    if (!g_execution_rpc_configured) {
        return meshd_send_execution_error(
            client_socket, task_id, task_model, 503,
            "Service Unavailable", "execution.unavailable",
            "node execution RPC is not configured");
    }
    memset(&binding, 0, sizeof(binding));
    memset(&completion, 0, sizeof(completion));
    if (strcmp(method, "POST") == 0 &&
        strcmp(path, "/v1/executions") == 0) {
        if (!request || request->body_size == 0u) {
            return meshd_send_execution_error(
                client_socket, task_id, task_model, 400, "Bad Request",
                "execution.request.invalid",
                "canonical COMMAND_REQUEST body is required");
        }
        result = mesh_mgmt_execution_rpc_control_submit_v1(
            &g_execution_rpc_control, request->body, request->body_size,
            &binding);
        if (result == MESH_MGMT_EXECUTION_RPC_CONTROL_OK ||
            result ==
                MESH_MGMT_EXECUTION_RPC_CONTROL_SEND_AMBIGUOUS ||
            result ==
                MESH_MGMT_EXECUTION_RPC_CONTROL_ALREADY_EXISTS) {
            if (mesh_mgmt_execution_rpc_control_get_v1(
                    &g_execution_rpc_control, binding.correlation_id,
                    &completion) !=
                MESH_MGMT_EXECUTION_RPC_CONTROL_OK) {
                return meshd_send_execution_error(
                    client_socket, task_id, task_model, 500,
                    "Internal Server Error", "execution.state.failed",
                    "registered execution state is unavailable");
            }
            status =
                result == MESH_MGMT_EXECUTION_RPC_CONTROL_ALREADY_EXISTS
                    ? 200
                    : 202;
            status_text = status == 200 ? "OK" : "Accepted";
        } else {
            switch (result) {
                case MESH_MGMT_EXECUTION_RPC_CONTROL_INVALID_REQUEST:
                case MESH_MGMT_EXECUTION_RPC_CONTROL_INVALID_ARG:
                    return meshd_send_execution_error(
                        client_socket, task_id, task_model, 400,
                        "Bad Request", "execution.request.invalid",
                        "invalid canonical COMMAND_REQUEST");
                case MESH_MGMT_EXECUTION_RPC_CONTROL_AUTH_FAILED:
                case MESH_MGMT_EXECUTION_RPC_CONTROL_SCOPE_MISMATCH:
                    return meshd_send_execution_error(
                        client_socket, task_id, task_model, 403,
                        "Forbidden", "execution.authorization.denied",
                        "execution Grant authority or scope rejected");
                case MESH_MGMT_EXECUTION_RPC_CONTROL_CONFLICT:
                    return meshd_send_execution_error(
                        client_socket, task_id, task_model, 409,
                        "Conflict", "execution.binding.conflict",
                        "command or correlation binding conflicts");
                case MESH_MGMT_EXECUTION_RPC_CONTROL_RESOURCE_EXHAUSTED:
                    return meshd_send_execution_error(
                        client_socket, task_id, task_model, 429,
                        "Too Many Requests", "execution.capacity.exhausted",
                        "execution RPC registry capacity exhausted");
                case MESH_MGMT_EXECUTION_RPC_CONTROL_SEND_UNAVAILABLE:
                    return meshd_send_execution_error(
                        client_socket, task_id, task_model, 503,
                        "Service Unavailable", "execution.target.unavailable",
                        "authenticated target session is unavailable");
                default:
                    return meshd_send_execution_error(
                        client_socket, task_id, task_model, 500,
                        "Internal Server Error", "execution.submit.failed",
                        "execution submission failed");
            }
        }
    } else if (strcmp(method, "GET") == 0 &&
               strncmp(path, "/v1/executions/", 15u) == 0 &&
               strlen(path) == 15u + MESHD_NODE_ID_HEX_LENGTH) {
        if (!request || request->body_size != 0u ||
            meshd_decode_hex_exact(path + 15u, correlation_id,
                                   sizeof(correlation_id)) != 0) {
            return meshd_send_execution_error(
                client_socket, task_id, task_model, 400, "Bad Request",
                "execution.correlation.invalid",
                "correlation id must be exactly 64 hexadecimal characters");
        }
        result = mesh_mgmt_execution_rpc_control_get_v1(
            &g_execution_rpc_control, correlation_id, &completion);
        if (result == MESH_MGMT_EXECUTION_RPC_CONTROL_NOT_FOUND) {
            return meshd_send_execution_error(
                client_socket, task_id, task_model, 404, "Not Found",
                "execution.not_found", "execution correlation was not found");
        }
        if (result != MESH_MGMT_EXECUTION_RPC_CONTROL_OK) {
            return meshd_send_execution_error(
                client_socket, task_id, task_model, 500,
                "Internal Server Error", "execution.query.failed",
                "execution state query failed");
        }
    } else {
        return meshd_send_execution_error(
            client_socket, task_id, task_model, 404, "Not Found",
            "endpoint.unsupported", "unsupported execution endpoint");
    }
    if (meshd_build_execution_json(
            result_json, sizeof(result_json), &completion) != 0 ||
        meshd_build_task_response_json(
            body, sizeof(body), task_id, task_model, 1, result_json,
            NULL, NULL) != 0) {
        return -1;
    }
    return meshd_send_http_response(
        client_socket, status, status_text, body, strlen(body));
}

static int meshd_mgmt_handle_request(meshd_mgmt_server_t *server,
                                    meshd_socket_t client_socket,
                                    const meshd_mgmt_http_request_t *request) {
    const char *request_text = request ? request->header : NULL;
    char method[16] = {0};
    char path[128] = {0};
    char health_body[1024] = {0};
    char status_body[MESHD_MGMT_RESPONSE_BUF_SIZE] = {0};
    char resolve_body[1024] = {0};
    char task_body[MESHD_MGMT_RESPONSE_BUF_SIZE] = {0};
    char task_id[64] = {0};
    meshd_task_model_t task_model = {0};
    int status = 200;
    const char *status_text = "OK";
    const char *body = NULL;
    size_t body_len = 0;

    if (!request_text) {
        meshd_task_generate_id(task_id, sizeof(task_id));
        meshd_classify_mgmt_task("UNKNOWN", "", &task_model);
        meshd_build_task_response_json(task_body,
                                      sizeof(task_body),
                                      task_id,
                                      &task_model,
                                      0,
                                      NULL,
                                      "request.invalid",
                                      "bad request");
        body = task_body;
        body_len = strlen(task_body);
        status = 400;
        status_text = "Bad Request";
        return meshd_send_http_response(client_socket, status, status_text, body, body_len);
    }

    if (sscanf(request_text, "%15s %127s", method, path) < 2) {
        meshd_task_generate_id(task_id, sizeof(task_id));
        meshd_classify_mgmt_task("UNKNOWN", "", &task_model);
        meshd_build_task_response_json(task_body,
                                      sizeof(task_body),
                                      task_id,
                                      &task_model,
                                      0,
                                      NULL,
                                      "request.invalid",
                                      "invalid request line");
        body = task_body;
        body_len = strlen(task_body);
        status = 400;
        status_text = "Bad Request";
        return meshd_send_http_response(client_socket, status, status_text, body, body_len);
    }

    meshd_classify_mgmt_task(method, path, &task_model);
    meshd_task_generate_id(task_id, sizeof(task_id));

    if (task_model.requires_token && server->token[0] == '\0') {
        meshd_build_task_response_json(task_body,
                                      sizeof(task_body),
                                      task_id,
                                      &task_model,
                                      0,
                                      NULL,
                                      "node_control.requires_token",
                                      "node-control task requires --rpc-token configured on meshd");
        body = task_body;
        body_len = strlen(task_body);
        status = 501;
        status_text = "Not Implemented";
        return meshd_send_http_response(client_socket, status, status_text, body, body_len);
    }

    if (!meshd_check_token(server, request_text)) {
        meshd_build_task_response_json(task_body,
                                      sizeof(task_body),
                                      task_id,
                                      &task_model,
                                      0,
                                      NULL,
                                      "auth.unauthorized",
                                      "missing/invalid X-Meshd-Token");
        body = task_body;
        body_len = strlen(task_body);
        status = 401;
        status_text = "Unauthorized";
        return meshd_send_http_response(client_socket, status, status_text, body, body_len);
    }

    if ((strcmp(method, "POST") == 0 &&
         strcmp(path, "/v1/executions") == 0) ||
        (strcmp(method, "GET") == 0 &&
         strncmp(path, "/v1/executions/", 15u) == 0)) {
        return meshd_handle_execution_http(
            client_socket, request, method, path, task_id, &task_model);
    }

    if ((strcmp(method, "GET") == 0 && strcmp(path, "/health") == 0) ||
        (strcmp(method, "GET") == 0 && strcmp(path, "/v1/health") == 0)) {
        if (meshd_build_health_json(health_body, sizeof(health_body)) == 0) {
            meshd_build_task_response_json(task_body,
                                          sizeof(task_body),
                                          task_id,
                                          &task_model,
                                          1,
                                          health_body,
                                          NULL,
                                          NULL);
            body = task_body;
            body_len = strlen(task_body);
        } else {
            meshd_build_task_response_json(task_body,
                                          sizeof(task_body),
                                          task_id,
                                          &task_model,
                                          0,
                                          NULL,
                                          "health.unavailable",
                                          "health unavailable");
            body = task_body;
            body_len = strlen(task_body);
            status = 500;
            status_text = "Internal Server Error";
        }
        return meshd_send_http_response(client_socket, status, status_text, body, body_len);
    }

    if ((strcmp(method, "GET") == 0 && strcmp(path, "/status") == 0) ||
        (strcmp(method, "GET") == 0 && strcmp(path, "/v1/status") == 0)) {
        if (meshd_build_status_json(status_body, sizeof(status_body)) == 0) {
            meshd_build_task_response_json(task_body,
                                          sizeof(task_body),
                                          task_id,
                                          &task_model,
                                          1,
                                          status_body,
                                          NULL,
                                          NULL);
            body = task_body;
            body_len = strlen(task_body);
        } else {
            meshd_build_task_response_json(task_body,
                                          sizeof(task_body),
                                          task_id,
                                          &task_model,
                                          0,
                                          NULL,
                                          "status.unavailable",
                                          "status unavailable");
            body = task_body;
            body_len = strlen(task_body);
            status = 500;
            status_text = "Internal Server Error";
        }
        return meshd_send_http_response(client_socket, status, status_text, body, body_len);
    }

    if (strcmp(method, "GET") == 0 && strcmp(path, "/ping") == 0) {
        meshd_build_task_response_json(task_body,
                                      sizeof(task_body),
                                      task_id,
                                      &task_model,
                                      1,
                                      "{\"pong\":\"meshd\"}",
                                      NULL,
                                      NULL);
        body = task_body;
        body_len = strlen(task_body);
        return meshd_send_http_response(client_socket, status, status_text, body, body_len);
    }

    if (strcmp(method, "GET") == 0 &&
        meshd_parse_node_resolve_path(path, NULL) == 0) {
        meshd_service_resolve_result_t resolve_result =
            meshd_resolve_node_service_json(server,
                                            path,
                                            resolve_body,
                                            sizeof(resolve_body));
        if (resolve_result == MESHD_SERVICE_RESOLVE_OK) {
            meshd_build_task_response_json(task_body,
                                          sizeof(task_body),
                                          task_id,
                                          &task_model,
                                          1,
                                          resolve_body,
                                          NULL,
                                          NULL);
        } else if (resolve_result == MESHD_SERVICE_RESOLVE_NOT_FOUND) {
            meshd_build_task_response_json(task_body,
                                          sizeof(task_body),
                                          task_id,
                                          &task_model,
                                          0,
                                          NULL,
                                          "service.resolve.not_found",
                                          "verified RPC service record not found");
            status = 404;
            status_text = "Not Found";
        } else if (resolve_result == MESHD_SERVICE_RESOLVE_UNAVAILABLE) {
            meshd_build_task_response_json(task_body,
                                          sizeof(task_body),
                                          task_id,
                                          &task_model,
                                          0,
                                          NULL,
                                          "service.resolve.unavailable",
                                          "verified service resolver unavailable");
            status = 503;
            status_text = "Service Unavailable";
        } else {
            meshd_build_task_response_json(task_body,
                                          sizeof(task_body),
                                          task_id,
                                          &task_model,
                                          0,
                                          NULL,
                                          "service.resolve.verification_failed",
                                          "RPC service record verification failed");
            status = 502;
            status_text = "Bad Gateway";
        }
        body = task_body;
        body_len = strlen(task_body);
        return meshd_send_http_response(client_socket,
                                        status,
                                        status_text,
                                        body,
                                        body_len);
    }

    if ((strcmp(method, "GET") == 0 && strcmp(path, "/v1/task-model") == 0)) {
        meshd_build_task_response_json(task_body,
                                      sizeof(task_body),
                                      task_id,
                                      &task_model,
                                      1,
                                      "{\"data_plane\":[\"mesh.health.query\",\"mesh.status.snapshot\",\"mesh.ping\",\"mesh.task-model\",\"node.resolve\"],"
                                      "\"node_execution\":[\"node.execution.submit\",\"node.execution.query\"],"
                                      "\"node_control\":[\"node.shutdown\"]}",
                                      NULL,
                                      NULL);
        body = task_body;
        body_len = strlen(task_body);
        return meshd_send_http_response(client_socket, status, status_text, body, body_len);
    }

    if (strcmp(method, "POST") == 0 && strcmp(path, "/v1/shutdown") == 0) {
        meshd_request_shutdown();
        meshd_build_task_response_json(task_body,
                                      sizeof(task_body),
                                      task_id,
                                      &task_model,
                                      1,
                                      "{\"action\":\"shutdown\"}",
                                      NULL,
                                      NULL);
        body = task_body;
        body_len = strlen(task_body);
        return meshd_send_http_response(client_socket, status, status_text, body, body_len);
    }

    meshd_build_task_response_json(task_body,
                                  sizeof(task_body),
                                  task_id,
                                  &task_model,
                                  0,
                                  NULL,
                                  "endpoint.unsupported",
                                  "unsupported endpoint");
    body = task_body;
    body_len = strlen(task_body);
    status = 404;
    status_text = "Not Found";
    return meshd_send_http_response(client_socket, status, status_text, body, body_len);
}

static int meshd_mgmt_accept_and_serve(meshd_mgmt_server_t *server) {
    meshd_socket_t client = MESHD_INVALID_SOCKET;
    struct sockaddr_in client_addr;
#ifdef _WIN32
    int client_addr_len = (int)sizeof(client_addr);
#else
    socklen_t client_addr_len = (socklen_t)sizeof(client_addr);
#endif
    meshd_mgmt_http_request_t request;
    uint8_t recv_buffer[MESHD_MGMT_HTTP_RECV_CHUNK_SIZE];
    meshd_mgmt_http_parse_result_t parse_result =
        MESHD_MGMT_HTTP_NEED_MORE;
    uint64_t read_deadline_ms = 0u;
    fd_set readfds;
    struct timeval timeout = {0, 0};

    if (!server || !meshd_socket_is_valid(server->listen_socket)) {
        return 0;
    }

    FD_ZERO(&readfds);
    FD_SET(server->listen_socket, &readfds);
#ifdef _WIN32
    if (select(0, &readfds, NULL, NULL, &timeout) <= 0) {
#else
    if (select((int)server->listen_socket + 1, &readfds, NULL, NULL, &timeout) <= 0) {
#endif
        return 0;
    }

    client = accept(server->listen_socket, (struct sockaddr *)&client_addr, &client_addr_len);
    if (!meshd_socket_is_valid(client)) {
        return 0;
    }

    memset(&request, 0, sizeof(request));
    read_deadline_ms =
        turbo_monotonic_ms() + MESHD_MGMT_HTTP_READ_TIMEOUT_MS;
    while (parse_result == MESHD_MGMT_HTTP_NEED_MORE) {
        uint64_t now_ms = turbo_monotonic_ms();
        uint64_t remaining_ms;
        int select_result;
        int read_len;

        if (now_ms >= read_deadline_ms) {
            parse_result = MESHD_MGMT_HTTP_INVALID;
            break;
        }
        remaining_ms = read_deadline_ms - now_ms;
        timeout.tv_sec = (long)(remaining_ms / 1000u);
        timeout.tv_usec = (long)((remaining_ms % 1000u) * 1000u);
        FD_ZERO(&readfds);
        FD_SET(client, &readfds);
#ifdef _WIN32
        select_result = select(0, &readfds, NULL, NULL, &timeout);
#else
        select_result =
            select((int)client + 1, &readfds, NULL, NULL, &timeout);
#endif
        if (select_result <= 0) {
            parse_result = MESHD_MGMT_HTTP_INVALID;
            break;
        }
        read_len =
            (int)recv(client, (char *)recv_buffer,
                      (int)sizeof(recv_buffer), 0);
        if (read_len <= 0) {
            parse_result = MESHD_MGMT_HTTP_INVALID;
            break;
        }
        parse_result = meshd_mgmt_http_request_feed(
            &request, recv_buffer, (size_t)read_len);
    }

    if (parse_result != MESHD_MGMT_HTTP_COMPLETE) {
        (void)meshd_mgmt_handle_request(server, client, NULL);
        meshd_close_socket(client);
        return 0;
    }
    if (meshd_mgmt_handle_request(server, client, &request) != 0) {
        meshd_close_socket(client);
        return -1;
    }

    meshd_close_socket(client);
    return 0;
}

static void meshd_json_string(FILE *fp, const char *value) {
    const unsigned char *p = (const unsigned char *)(value ? value : "");

    fputc('"', fp);
    while (*p) {
        switch (*p) {
            case '\\':
                fputs("\\\\", fp);
                break;
            case '"':
                fputs("\\\"", fp);
                break;
            case '\b':
                fputs("\\b", fp);
                break;
            case '\f':
                fputs("\\f", fp);
                break;
            case '\n':
                fputs("\\n", fp);
                break;
            case '\r':
                fputs("\\r", fp);
                break;
            case '\t':
                fputs("\\t", fp);
                break;
            default:
                if (*p < 0x20) {
                    fprintf(fp, "\\u%04x", (unsigned int)*p);
                } else {
                    fputc((int)*p, fp);
                }
                break;
        }
        p++;
    }
    fputc('"', fp);
}

static int meshd_write_atomic_file(const char *path, void (*write_body)(FILE *fp, void *user_data), void *user_data) {
    char temp_path[320];
    FILE *fp = NULL;

    if (!path || path[0] == '\0') {
        return 0;
    }

    snprintf(temp_path, sizeof(temp_path), "%s.tmp", path);
    fp = fopen(temp_path, "wb");
    if (!fp) {
        fprintf(stderr, "Failed to open temp status file: %s\n", temp_path);
        return -1;
    }

    write_body(fp, user_data);

    if (fclose(fp) != 0) {
        fprintf(stderr, "Failed to flush temp status file: %s\n", temp_path);
        return -1;
    }

#ifdef _WIN32
    if (!MoveFileExA(temp_path, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        fprintf(stderr, "Failed to replace status file: %s\n", path);
        remove(temp_path);
        return -1;
    }
#else
    if (rename(temp_path, path) != 0) {
        fprintf(stderr, "Failed to replace status file: %s\n", path);
        remove(temp_path);
        return -1;
    }
#endif

    return 0;
}

static void meshd_write_pid_file(void) {
    FILE *fp = NULL;

    if (g_config.pid_file[0] == '\0') {
        return;
    }

    fp = fopen(g_config.pid_file, "wb");
    if (!fp) {
        fprintf(stderr, "Failed to open pid file: %s\n", g_config.pid_file);
        return;
    }

#ifdef _WIN32
    fprintf(fp, "%lu\n", (unsigned long)GetCurrentProcessId());
#else
    fprintf(fp, "%ld\n", (long)getpid());
#endif

    fclose(fp);
}

static void meshd_remove_pid_file(void) {
    if (g_config.pid_file[0] != '\0') {
        remove(g_config.pid_file);
    }
}

typedef struct {
    mesh_network_t *mesh;
    tunnel_t *tunnel;
} meshd_status_context_t;

static void meshd_write_dht_json(FILE *fp,
                                 mesh_network_t *mesh,
                                 const mesh_stats_t *mesh_stats,
                                 const char *vip_key,
                                 const char *reverse_key,
                                 int has_reverse_key,
                                 const char *routes_key) {
    char dht_value[1024];
    size_t dht_value_len = 0;

    fprintf(fp, "\"dht\":{\"entry_count\":%u,\"known_entries\":[", mesh_stats->dht_entries);
    fputs("{\"label\":", fp);
    meshd_json_string(fp, "virtual_ip");
    fputs(",\"key\":", fp);
    meshd_json_string(fp, vip_key);
    dht_value_len = sizeof(dht_value);
    if (mesh_get_cached_dht_value(mesh, vip_key, dht_value, &dht_value_len) == MESH_OK) {
        fprintf(fp, ",\"present\":true,\"value\":");
        meshd_json_string(fp, dht_value);
    } else {
        fprintf(fp, ",\"present\":false,\"value\":\"\"");
    }
    fputc('}', fp);

    if (has_reverse_key) {
        fputs(",{\"label\":", fp);
        meshd_json_string(fp, "reverse_peer");
        fputs(",\"key\":", fp);
        meshd_json_string(fp, reverse_key);
        dht_value_len = sizeof(dht_value);
        if (mesh_get_cached_dht_value(mesh, reverse_key, dht_value, &dht_value_len) == MESH_OK) {
            fprintf(fp, ",\"present\":true,\"value\":");
            meshd_json_string(fp, dht_value);
        } else {
            fprintf(fp, ",\"present\":false,\"value\":\"\"");
        }
        fputc('}', fp);
    }

    fputs(",{\"label\":", fp);
    meshd_json_string(fp, "routes");
    fputs(",\"key\":", fp);
    meshd_json_string(fp, routes_key);
    dht_value_len = sizeof(dht_value);
    if (mesh_get_cached_dht_value(mesh, routes_key, dht_value, &dht_value_len) == MESH_OK) {
        fprintf(fp, ",\"present\":true,\"value\":");
        meshd_json_string(fp, dht_value);
    } else {
        fprintf(fp, ",\"present\":false,\"value\":\"\"");
    }
    fputs("}]}", fp);
}

static void meshd_write_health_json(FILE *fp, const mesh_runtime_health_t *mesh_health) {
    fprintf(fp, "\"health\":{\"state\":");
    meshd_json_string(fp, mesh_runtime_health_state_string(mesh_health->state));
    fputs(",\"reason\":", fp);
    meshd_json_string(fp, mesh_runtime_health_reason_string(mesh_health->reason));
    fputs(",\"summary\":", fp);
    meshd_json_string(fp, mesh_runtime_health_summary(mesh_health));
    fputs(",\"path_mode\":", fp);
    meshd_json_string(fp, mesh_path_mode_string(mesh_health->path_mode));
    fprintf(fp, ",\"signals\":{\"bootstrap_configured\":%s,"
                "\"bootstrap_reconnect_pending\":%s,"
                "\"has_direct_peer\":%s,\"has_relay_path\":%s,"
                "\"has_any_path\":%s,\"ice_enabled\":%s,"
                "\"ice_progressing\":%s,\"ice_failed\":%s}}",
            mesh_health->bootstrap_configured ? "true" : "false",
            mesh_health->bootstrap_reconnect_pending ? "true" : "false",
            mesh_health->has_direct_peer ? "true" : "false",
            mesh_health->has_relay_path ? "true" : "false",
            mesh_health->has_any_path ? "true" : "false",
            mesh_health->ice_enabled ? "true" : "false",
            mesh_health->ice_progressing ? "true" : "false",
            mesh_health->ice_failed ? "true" : "false");
}

static void meshd_write_diagnostics_json(FILE *fp, const mesh_diag_info_t *mesh_diag) {
    fprintf(fp, "\"diagnostics\":{\"path_mode\":");
    meshd_json_string(fp, mesh_path_mode_string(mesh_diag->path_mode));
    fprintf(fp, ",\"direct_peer_count\":%u,\"relay_route_count\":%u,"
                "\"connected_relay_route_count\":%u,"
                "\"bootstrap_connect_attempts\":%u,\"bootstrap_retry_rounds\":%u,"
                "\"bootstrap_reconnect_scheduled\":%u,"
                "\"bootstrap_reconnect_pending\":%s,"
                "\"reconnect_poll_count\":%u,"
                "\"direct_connect_attempts\":%u,\"direct_connect_started\":%u,"
                "\"peer_connect_events\":%u,\"peer_disconnect_events\":%u,"
                "\"control_plane_refreshes\":%u,"
                "\"last_reconnect_reason\":",
            mesh_diag->direct_peer_count,
            mesh_diag->relay_route_count,
            mesh_diag->connected_relay_route_count,
            mesh_diag->bootstrap_connect_attempts,
            mesh_diag->bootstrap_retry_rounds,
            mesh_diag->bootstrap_reconnect_scheduled,
            mesh_diag->bootstrap_reconnect_pending ? "true" : "false",
            mesh_diag->reconnect_poll_count,
            mesh_diag->direct_connect_attempts,
            mesh_diag->direct_connect_started,
            mesh_diag->peer_connect_events,
            mesh_diag->peer_disconnect_events,
            mesh_diag->control_plane_refreshes);
    meshd_json_string(fp, mesh_diag->last_reconnect_reason);
    fputs(",\"last_direct_attempt_endpoint\":", fp);
    meshd_json_string(fp, mesh_diag->last_direct_attempt_endpoint);
    fputs(",\"last_active_relay_next_hop\":{\"virtual_ip\":", fp);
    meshd_json_string(fp, mesh_diag->last_active_relay_next_hop_virtual_ip);
    fputs(",\"real_endpoint\":", fp);
    meshd_json_string(fp, mesh_diag->last_active_relay_next_hop_real_ip);
    fputs("},\"ice\":{\"enabled\":", fp);
    fputs(mesh_diag->ice_enabled ? "true" : "false", fp);
    fprintf(fp, ",\"peer_count\":%u,\"connected_peer_count\":%u,"
                "\"auth_tx\":%u,\"auth_rx\":%u,"
                "\"candidate_tx\":%u,\"candidate_rx\":%u,"
                "\"eoc_tx\":%u,\"eoc_rx\":%u,"
                "\"checks_started\":%u,"
                "\"last_check_local_candidates\":%u,"
                "\"last_check_remote_candidates\":%u,"
                "\"last_state\":",
            mesh_diag->ice_peer_count,
            mesh_diag->ice_connected_peer_count,
            mesh_diag->ice_auth_messages_tx,
            mesh_diag->ice_auth_messages_rx,
            mesh_diag->ice_candidate_messages_tx,
            mesh_diag->ice_candidate_messages_rx,
            mesh_diag->ice_end_of_candidates_tx,
            mesh_diag->ice_end_of_candidates_rx,
            mesh_diag->ice_checks_started,
            mesh_diag->ice_last_check_local_candidate_count,
            mesh_diag->ice_last_check_remote_candidate_count);
    meshd_json_string(fp, mesh_diag->last_ice_state);
    fputs(",\"last_selected_local_endpoint\":", fp);
    meshd_json_string(fp, mesh_diag->last_ice_selected_local_endpoint);
    fputs(",\"last_selected_remote_endpoint\":", fp);
    meshd_json_string(fp, mesh_diag->last_ice_selected_remote_endpoint);
    fputc('}', fp);
    fputc('}', fp);
}

static void meshd_write_control_plane_json(FILE *fp,
                                           meshd_status_context_t *ctx,
                                           const mesh_stats_t *mesh_stats,
                                           const mesh_diag_info_t *mesh_diag,
                                           const mesh_runtime_health_t *mesh_health,
                                           int peer_count,
                                           int route_count,
                                           int route_policy_count,
                                           int peer_admission_count,
                                           int peer_identity_admission_count,
                                           unsigned int peer_protocol_major_policy,
                                           const char *vip_key,
                                           const char *reverse_key,
                                           int has_reverse_key,
                                           const char *routes_key) {
    fprintf(fp, "\"control_plane\":{\"summary\":{\"direct_peers\":%d,\"relay_routes\":%d,"
                "\"route_policy\":%d,\"peer_admission\":%d,\"peer_identity_admission\":%d,"
                "\"peer_protocol_major_policy\":%u,\"peer_count\":%u,"
                "\"tx_packets\":%llu,\"rx_packets\":%llu,\"tx_bytes\":%llu,"
                "\"rx_bytes\":%llu,\"dht_entries\":%u},",
            peer_count > 0 ? peer_count : 0,
            route_count > 0 ? route_count : 0,
            route_policy_count > 0 ? route_policy_count : 0,
            peer_admission_count > 0 ? peer_admission_count : 0,
            peer_identity_admission_count > 0 ? peer_identity_admission_count : 0,
            peer_protocol_major_policy,
            mesh_stats->peer_count,
            (unsigned long long)mesh_stats->packets_tx,
            (unsigned long long)mesh_stats->packets_rx,
            (unsigned long long)mesh_stats->bytes_tx,
            (unsigned long long)mesh_stats->bytes_rx,
            mesh_stats->dht_entries);
    meshd_write_dht_json(fp, ctx->mesh, mesh_stats, vip_key, reverse_key, has_reverse_key, routes_key);
    fputc(',', fp);
    meshd_write_health_json(fp, mesh_health);
    fputc(',', fp);
    meshd_write_diagnostics_json(fp, mesh_diag);
    fputc('}', fp);
}

static void meshd_write_status_json(FILE *fp, void *user_data) {
    meshd_status_context_t *ctx = (meshd_status_context_t *)user_data;
    mesh_stats_t mesh_stats;
    mesh_diag_info_t mesh_diag;
    mesh_runtime_health_t mesh_health;
    tunnel_stats_t tunnel_stats;
    char node_id[65];
    int peer_count = mesh_get_peer_count(ctx->mesh);
    int route_count = mesh_get_route_count(ctx->mesh);
    int route_policy_count = mesh_get_route_rule_count(ctx->mesh);
    int peer_admission_count = mesh_get_peer_allow_count(ctx->mesh);
    int peer_identity_admission_count = mesh_get_peer_allow_node_id_count(ctx->mesh);
    unsigned int peer_protocol_major_policy = mesh_get_peer_protocol_major(ctx->mesh);
    int i = 0;
    int emitted = 0;
    uint64_t now_ms = meshd_now_ms();
    time_t wall_clock = time(NULL);
    char vip_key[128];
    char reverse_key[128];
    char routes_key[128];
    int has_reverse_key = 0;

    memset(&mesh_stats, 0, sizeof(mesh_stats));
    memset(&mesh_diag, 0, sizeof(mesh_diag));
    memset(&mesh_health, 0, sizeof(mesh_health));
    memset(&tunnel_stats, 0, sizeof(tunnel_stats));
    memset(node_id, 0, sizeof(node_id));
    mesh_get_stats(ctx->mesh, &mesh_stats);
    mesh_get_diag_info(ctx->mesh, &mesh_diag);
    mesh_runtime_health_eval(ctx->mesh, g_config.bootstrap_count, &mesh_health);
    tunnel_get_stats(ctx->tunnel, &tunnel_stats);
    if (mesh_get_node_id(ctx->mesh, node_id, sizeof(node_id)) != MESH_OK) {
        node_id[0] = '\0';
    }
    snprintf(vip_key, sizeof(vip_key), "mesh:%s:ip:%s",
             g_config.network_id, g_config.virtual_ip);
    snprintf(routes_key, sizeof(routes_key), "mesh:%s:routes:%s",
             g_config.network_id, g_config.virtual_ip);
    if (g_config.advertise_ip[0]) {
        snprintf(reverse_key, sizeof(reverse_key), "mesh:%s:peer:%s:%d",
                 g_config.network_id, g_config.advertise_ip, g_config.listen_port);
        has_reverse_key = 1;
    }

    fprintf(fp, "{\"snapshot_version\":%d,", MESH_SNAPSHOT_VERSION);
    fputs("\"node\":{", fp);
    fputs("\"name\":", fp);
    meshd_json_string(fp, g_config.node_name);
    fputs(",\"network_id\":", fp);
    meshd_json_string(fp, g_config.network_id);
    fputs(",\"virtual_ip\":", fp);
    meshd_json_string(fp, g_config.virtual_ip);
    fprintf(fp, ",\"virtual_prefix\":%u", g_config.virtual_prefix);
    fputs(",\"advertise_ip\":", fp);
    meshd_json_string(fp, g_config.advertise_ip[0] ? g_config.advertise_ip : "");
    fprintf(fp, ",\"identity_configured\":%s",
            g_config.identity_secret_hex[0] ? "true" : "false");
    fputs(",\"node_id\":", fp);
    meshd_json_string(fp, node_id);
    fprintf(fp, ",\"listen_port\":%d", g_config.listen_port);
    fprintf(fp, ",\"protocol_major\":%u,\"protocol_minor\":%u",
            (unsigned int)MESH_PROTOCOL_MAJOR,
            (unsigned int)MESH_PROTOCOL_MINOR);
    fputs(",\"status_file\":", fp);
    meshd_json_string(fp, g_config.status_file);
    fputs(",\"pid_file\":", fp);
    meshd_json_string(fp, g_config.pid_file);
    fputs(",\"bootstrap_peers\":[", fp);
    for (i = 0; i < g_config.bootstrap_count; i++) {
        if (i > 0) {
            fputc(',', fp);
        }
        meshd_json_string(fp, g_config.bootstrap_peers[i]);
    }
    fputs("]}", fp);

    fprintf(fp, ",\"runtime\":{\"running\":%s,\"uptime_ms\":%llu,\"timestamp_epoch\":%lld}",
            g_running ? "true" : "false",
            (unsigned long long)(now_ms - g_started_ms),
            (long long)wall_clock);

    fprintf(fp, ",\"mesh\":{\"direct_peers\":%d,\"relay_routes\":%d,\"route_policy\":%d,"
                "\"peer_admission\":%d,\"peer_identity_admission\":%d,\"peer_protocol_major_policy\":%u,"
                "\"peer_count\":%u,\"tx_packets\":%llu,\"rx_packets\":%llu,"
                "\"tx_bytes\":%llu,\"rx_bytes\":%llu,\"dht_entries\":%u}",
            peer_count > 0 ? peer_count : 0,
            route_count > 0 ? route_count : 0,
            route_policy_count > 0 ? route_policy_count : 0,
            peer_admission_count > 0 ? peer_admission_count : 0,
            peer_identity_admission_count > 0 ? peer_identity_admission_count : 0,
            peer_protocol_major_policy,
            mesh_stats.peer_count,
            (unsigned long long)mesh_stats.packets_tx,
            (unsigned long long)mesh_stats.packets_rx,
            (unsigned long long)mesh_stats.bytes_tx,
            (unsigned long long)mesh_stats.bytes_rx,
            mesh_stats.dht_entries);

    fputc(',', fp);
    meshd_write_dht_json(fp, ctx->mesh, &mesh_stats, vip_key, reverse_key, has_reverse_key, routes_key);
    fputc(',', fp);
    meshd_write_health_json(fp, &mesh_health);
    fputc(',', fp);
    meshd_write_diagnostics_json(fp, &mesh_diag);
    fputc(',', fp);
    meshd_write_control_plane_json(fp, ctx, &mesh_stats, &mesh_diag, &mesh_health,
                                   peer_count, route_count, route_policy_count, peer_admission_count,
                                   peer_identity_admission_count, peer_protocol_major_policy,
                                   vip_key, reverse_key, has_reverse_key, routes_key);

    fprintf(fp, ",\"tunnel\":{\"tx_packets\":%llu,\"rx_packets\":%llu,"
                "\"tx_bytes\":%llu,\"rx_bytes\":%llu,\"tcp_sessions\":%u,"
                "\"udp_sessions\":%u,\"total_sessions\":%u,\"connect_errors\":%u,"
                "\"timeout_errors\":%u,\"protocol_errors\":%u}",
            (unsigned long long)tunnel_stats.packets_tx,
            (unsigned long long)tunnel_stats.packets_rx,
            (unsigned long long)tunnel_stats.bytes_tx,
            (unsigned long long)tunnel_stats.bytes_rx,
            tunnel_stats.tcp_sessions,
            tunnel_stats.udp_sessions,
            tunnel_stats.total_sessions,
            tunnel_stats.connect_errors,
            tunnel_stats.timeout_errors,
            tunnel_stats.protocol_errors);

    fputs(",\"direct_peers\":[", fp);
    for (i = 0; i < peer_count; i++) {
        mesh_peer_info_t info;

        if (mesh_get_peer_info(ctx->mesh, i, &info) != MESH_OK) {
            continue;
        }

        if (emitted > 0) {
            fputc(',', fp);
        }
        emitted++;

        fputs("{\"virtual_ip\":", fp);
        meshd_json_string(fp, info.virtual_ip);
        fputs(",\"real_endpoint\":", fp);
        meshd_json_string(fp, info.real_ip);
        fputs(",\"node_id\":", fp);
        meshd_json_string(fp, info.node_id);
        fprintf(fp, ",\"protocol_major\":%u,\"protocol_minor\":%u",
                (unsigned int)info.protocol_major,
                (unsigned int)info.protocol_minor);
        fprintf(fp, ",\"is_connected\":%s,\"tx_bytes\":%llu,\"rx_bytes\":%llu,"
                    "\"last_seen_ms\":%llu}",
                info.is_connected ? "true" : "false",
                (unsigned long long)info.bytes_tx,
                (unsigned long long)info.bytes_rx,
                (unsigned long long)info.last_seen_ms);
    }
    fputc(']', fp);

    emitted = 0;
    fputs(",\"relay_routes\":[", fp);
    for (i = 0; i < route_count; i++) {
        mesh_route_info_t info;

        if (mesh_get_route_info(ctx->mesh, i, &info) != MESH_OK) {
            continue;
        }

        if (emitted > 0) {
            fputc(',', fp);
        }
        emitted++;

        fputs("{\"dest_ip\":", fp);
        meshd_json_string(fp, info.dest_ip);
        fputs(",\"dest_real_endpoint\":", fp);
        meshd_json_string(fp, info.dest_real_ip);
        fputs(",\"next_hop_virtual_ip\":", fp);
        meshd_json_string(fp, info.next_hop_virtual_ip);
        fputs(",\"next_hop_real_endpoint\":", fp);
        meshd_json_string(fp, info.next_hop_real_ip);
        fprintf(fp, ",\"hop_count\":%u,\"is_connected\":%s,\"last_update_ms\":%llu}",
                (unsigned)info.hop_count,
                info.is_connected ? "true" : "false",
                (unsigned long long)info.last_update_ms);
    }
    fputs("],\"route_policy\":[", fp);
    emitted = 0;
    for (i = 0; i < route_policy_count; i++) {
        mesh_route_rule_info_t info;

        if (mesh_get_route_rule_info(ctx->mesh, i, &info) != MESH_OK) {
            continue;
        }

        if (emitted > 0) {
            fputc(',', fp);
        }
        emitted++;

        fputs("{\"dest_cidr\":", fp);
        meshd_json_string(fp, info.dest_cidr);
        fputs(",\"next_hop_virtual_ip\":", fp);
        meshd_json_string(fp, info.next_hop_virtual_ip);
        fputs(",\"flags\":[", fp);
        if (info.flags & MESH_ROUTE_RULE_PINNED) {
            meshd_json_string(fp, "pin");
        }
        fputs("]}", fp);
    }
    fputs("],\"peer_admission\":{\"cidrs\":[", fp);
    emitted = 0;
    for (i = 0; i < peer_admission_count; i++) {
        mesh_peer_allow_info_t info;

        if (mesh_get_peer_allow_info(ctx->mesh, i, &info) != MESH_OK) {
            continue;
        }

        if (emitted > 0) {
            fputc(',', fp);
        }
        emitted++;

        fputs("{\"cidr\":", fp);
        meshd_json_string(fp, info.cidr);
        fputs("}", fp);
    }
    fputs("],\"node_ids\":[", fp);
    emitted = 0;
    for (i = 0; i < peer_identity_admission_count; i++) {
        mesh_peer_allow_node_info_t info;

        if (mesh_get_peer_allow_node_info(ctx->mesh, i, &info) != MESH_OK) {
            continue;
        }

        if (emitted > 0) {
            fputc(',', fp);
        }
        emitted++;

        fputs("{\"node_id\":", fp);
        meshd_json_string(fp, info.node_id);
        fputs("}", fp);
    }
    fprintf(fp, "],\"protocol_major\":%u}}\n", peer_protocol_major_policy);
}

static void meshd_flush_status(void) {
    meshd_status_context_t ctx;

    if (g_config.status_file[0] == '\0' || !g_mesh || !g_tunnel) {
        return;
    }

    ctx.mesh = g_mesh;
    ctx.tunnel = g_tunnel;
    meshd_write_atomic_file(g_config.status_file, meshd_write_status_json, &ctx);
}

static void meshd_log_peer_connected(mesh_peer_t *peer, void *user_data) {
    mesh_peer_info_t info;
    (void)user_data;

    if (mesh_get_peer_handle_info(peer, &info) == MESH_OK) {
        TLOG_INFO("mesh peer connected: {} ({})", info.virtual_ip, info.real_ip);
    } else {
        TLOG_INFO("mesh peer connected");
    }
}

static void meshd_log_peer_disconnected(mesh_peer_t *peer, void *user_data) {
    mesh_peer_info_t info;
    (void)user_data;

    if (mesh_get_peer_handle_info(peer, &info) == MESH_OK) {
        TLOG_INFO("mesh peer disconnected: {} ({})", info.virtual_ip, info.real_ip);
    } else {
        TLOG_INFO("mesh peer disconnected");
    }
}

static void meshd_on_mesh_packet(const uint8_t *data, size_t len, void *user_data) {
    tunnel_t *tunnel = (tunnel_t *)user_data;
    int ret = tunnel_write_packet(tunnel, data, len);

    if (ret != TUNNEL_OK) {
        TLOG_ERROR("failed to write packet to tunnel: {}", tunnel_error_string(ret));
    }
}

static void meshd_on_tun_packet(tunnel_t *tunnel, int direction,
                                const uint8_t *data, size_t len,
                                void *user_data) {
    mesh_network_t *mesh = (mesh_network_t *)user_data;
    (void)tunnel;

    if (direction == 0) {
        mesh_send_packet(mesh, data, len);
    }
}

#ifdef _WIN32
static BOOL WINAPI meshd_console_handler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT || signal == CTRL_CLOSE_EVENT) {
        meshd_request_shutdown();
        return TRUE;
    }
    return FALSE;
}
#else
static void meshd_signal_handler(int sig) {
    if (sig == SIGHUP) {
        meshd_request_status_flush();
        return;
    }

    meshd_request_shutdown();
}
#endif

static void meshd_init_signals(void) {
#ifdef _WIN32
    SetConsoleCtrlHandler(meshd_console_handler, TRUE);
#else
    signal(SIGINT, meshd_signal_handler);
    signal(SIGTERM, meshd_signal_handler);
    signal(SIGHUP, meshd_signal_handler);
#endif
}

static void meshd_init_logger(void) {
    tlog_config_t log_config = {0};
    turbo_console_sink_opts_t console_opts = {0};
    tlog_t *logger = NULL;

    log_config.min_level = TURBO_LOG_LEVEL_INFO;
    log_config.buffer_size = 64 * 1024;
    logger = tlog_create(&log_config);
    if (!logger) {
        return;
    }

    console_opts.output = stdout;
    console_opts.use_colors = 1;
    console_opts.pattern = "[{time}] [{level}] {message}";
    tlog_add_sink(logger, turbo_sink_console_create(&console_opts));
    tlog_set_default(logger);
}

static void meshd_usage(const char *argv0) {
    printf("Usage:\n");
    printf("  %s doctor -c <mesh.yaml>\n", argv0);
    printf("  %s run -c <mesh.yaml> [--status-file <path>] [--pid-file <path>] [--status-interval-ms <n>]\n",
           argv0);
    printf("             [--rpc-listen <ip:port>] [--rpc-token <token>]\n");
}

static void meshd_doctor_result(const char *label, int ok, const char *detail) {
    printf("[%s] %s", ok ? "OK" : "FAIL", label);
    if (detail && detail[0] != '\0') {
        printf(": %s", detail);
    }
    printf("\n");
}

static int meshd_doctor_check_path_writable(const char *label, const char *path) {
    char temp_path[512];
    FILE *fp = NULL;

    if (!path || path[0] == '\0') {
        meshd_doctor_result(label, 1, "not configured");
        return 1;
    }

    snprintf(temp_path, sizeof(temp_path), "%s.doctor.tmp", path);
    fp = fopen(temp_path, "wb");
    if (!fp) {
        char detail[256];
        snprintf(detail, sizeof(detail), "cannot create %s (%s)", temp_path, strerror(errno));
        meshd_doctor_result(label, 0, detail);
        return 0;
    }

    fclose(fp);
    remove(temp_path);
    meshd_doctor_result(label, 1, path);
    return 1;
}

static int meshd_doctor_check_listen_port(int port) {
    int ok = 0;
    char detail[128];
#ifdef _WIN32
    SOCKET fd = INVALID_SOCKET;
    struct sockaddr_in addr;
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        meshd_doctor_result("listen_port", 0, "WSAStartup failed");
        return 0;
    }
#else
    int fd = -1;
    struct sockaddr_in addr;
#endif

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    fd = socket(AF_INET, SOCK_STREAM, 0);
#ifdef _WIN32
    if (fd == INVALID_SOCKET) {
        meshd_doctor_result("listen_port", 0, "socket create failed");
        WSACleanup();
        return 0;
    }
#else
    if (fd < 0) {
        meshd_doctor_result("listen_port", 0, "socket create failed");
        return 0;
    }
#endif

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        snprintf(detail, sizeof(detail), "0.0.0.0:%d available", port);
        ok = 1;
    } else {
#ifdef _WIN32
        snprintf(detail, sizeof(detail), "0.0.0.0:%d unavailable (winsock=%d)", port, WSAGetLastError());
#else
        snprintf(detail, sizeof(detail), "0.0.0.0:%d unavailable (%s)", port, strerror(errno));
#endif
    }

#ifdef _WIN32
    closesocket(fd);
    WSACleanup();
#else
    close(fd);
#endif

    meshd_doctor_result("listen_port", ok, detail);
    return ok;
}

static int meshd_doctor_set_nonblocking(
#ifdef _WIN32
    SOCKET fd
#else
    int fd
#endif
) {
#ifdef _WIN32
    u_long mode = 1;
    return ioctlsocket(fd, FIONBIO, &mode) == 0 ? 0 : -1;
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif
}

static int meshd_doctor_check_bootstrap_peer(const char *endpoint) {
    char label[160];
    char ip[64];
    int port = 0;
    char detail[160];
    int ok = 0;
#ifdef _WIN32
    SOCKET fd = INVALID_SOCKET;
    struct timeval timeout = {1, 0};
    fd_set write_set;
    fd_set error_set;
    int so_error = 0;
    int so_error_len = (int)sizeof(so_error);
    WSADATA wsa_data;

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        snprintf(label, sizeof(label), "bootstrap[%s]", endpoint);
        meshd_doctor_result(label, 0, "WSAStartup failed");
        return 0;
    }
#else
    int fd = -1;
    struct timeval timeout = {1, 0};
    fd_set write_set;
    fd_set error_set;
    int so_error = 0;
    socklen_t so_error_len = (socklen_t)sizeof(so_error);
#endif
    struct sockaddr_in addr;

    snprintf(label, sizeof(label), "bootstrap[%s]", endpoint);
    if (!mesh_node_parse_bootstrap_endpoint(endpoint, ip, sizeof(ip), &port)) {
        meshd_doctor_result(label, 0, "invalid endpoint");
        return 0;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        meshd_doctor_result(label, 0, "invalid IPv4 address");
#ifdef _WIN32
        WSACleanup();
#endif
        return 0;
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
#ifdef _WIN32
    if (fd == INVALID_SOCKET) {
        meshd_doctor_result(label, 0, "socket create failed");
        WSACleanup();
        return 0;
    }
#else
    if (fd < 0) {
        meshd_doctor_result(label, 0, "socket create failed");
        return 0;
    }
#endif

    if (meshd_doctor_set_nonblocking(fd) != 0) {
        meshd_doctor_result(label, 0, "failed to set nonblocking");
        goto cleanup;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        snprintf(detail, sizeof(detail), "%s:%d reachable", ip, port);
        meshd_doctor_result(label, 1, detail);
        ok = 1;
        goto cleanup;
    }

#ifdef _WIN32
    if (WSAGetLastError() != WSAEWOULDBLOCK) {
        snprintf(detail, sizeof(detail), "%s:%d connect failed (winsock=%d)", ip, port, WSAGetLastError());
        meshd_doctor_result(label, 0, detail);
        goto cleanup;
    }
#else
    if (errno != EINPROGRESS) {
        snprintf(detail, sizeof(detail), "%s:%d connect failed (%s)", ip, port, strerror(errno));
        meshd_doctor_result(label, 0, detail);
        goto cleanup;
    }
#endif

    FD_ZERO(&write_set);
    FD_ZERO(&error_set);
    FD_SET(fd, &write_set);
    FD_SET(fd, &error_set);
    if (select((int)fd + 1, NULL, &write_set, &error_set, &timeout) <= 0) {
        snprintf(detail, sizeof(detail), "%s:%d timed out", ip, port);
        meshd_doctor_result(label, 0, detail);
        goto cleanup;
    }

    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&so_error, &so_error_len) != 0 || so_error != 0) {
#ifdef _WIN32
        snprintf(detail, sizeof(detail), "%s:%d connect failed (winsock=%d)", ip, port, so_error);
#else
        snprintf(detail, sizeof(detail), "%s:%d connect failed (%s)", ip, port, strerror(so_error));
#endif
        meshd_doctor_result(label, 0, detail);
        goto cleanup;
    }

    snprintf(detail, sizeof(detail), "%s:%d reachable", ip, port);
    meshd_doctor_result(label, 1, detail);
    ok = 1;

cleanup:
#ifdef _WIN32
    if (fd != INVALID_SOCKET) {
        closesocket(fd);
    }
    WSACleanup();
#else
    if (fd >= 0) {
        close(fd);
    }
#endif
    return ok;
}

static int meshd_doctor_check_bootstrap_peers(const mesh_node_config_t *cfg) {
    int ok = 1;

    if (!cfg || cfg->bootstrap_count <= 0) {
        meshd_doctor_result("bootstrap_peers", 1, "not configured");
        return 1;
    }

    for (int i = 0; i < cfg->bootstrap_count; i++) {
        ok &= meshd_doctor_check_bootstrap_peer(cfg->bootstrap_peers[i]);
    }

    return ok;
}

static int meshd_doctor_check_tunnel_access(void) {
#ifdef __linux__
    if (access("/dev/net/tun", R_OK | W_OK) != 0) {
        char detail[128];
        snprintf(detail, sizeof(detail), "/dev/net/tun unavailable (%s)", strerror(errno));
        meshd_doctor_result("tun_access", 0, detail);
        return 0;
    }
    if (geteuid() != 0) {
        meshd_doctor_result("tun_access", 0, "requires root to open /dev/net/tun");
        return 0;
    }
    meshd_doctor_result("tun_access", 1, "/dev/net/tun ready");
    return 1;
#elif defined(_WIN32)
    char path[MAX_PATH];
    DWORD len = SearchPathA(NULL, "wintun.dll", NULL, MAX_PATH, path, NULL);

    if (len == 0 || len >= MAX_PATH) {
        meshd_doctor_result("tun_access", 0, "wintun.dll not found");
        return 0;
    }

    meshd_doctor_result("tun_access", 1, path);
    printf("[NOTE] tun_access: administrator shell is still required to create the adapter\n");
    return 1;
#else
    meshd_doctor_result("tun_access", 1, "platform-specific check not implemented");
    return 1;
#endif
}

static int meshd_apply_tunnel_config(tunnel_config_t *tun_cfg, const mesh_node_config_t *cfg) {
    uint32_t mask = 0;
    char *netmask = NULL;

    mask = cfg->virtual_prefix == 32
         ? 0xffffffffU
         : ((0xffffffffU << (32 - cfg->virtual_prefix)) & 0xffffffffU);

    netmask = (char *)malloc(16);
    if (!netmask) {
        return -1;
    }

    snprintf(netmask, 16, "%u.%u.%u.%u",
             (unsigned)((mask >> 24) & 0xffU),
             (unsigned)((mask >> 16) & 0xffU),
             (unsigned)((mask >> 8) & 0xffU),
             (unsigned)(mask & 0xffU));

    tunnel_config_init(tun_cfg);
    tun_cfg->tun.name = NULL;
    tun_cfg->tun.ipv4_addr = cfg->virtual_ip;
    tun_cfg->tun.ipv4_netmask = netmask;
    tun_cfg->tun.mtu = 1500;
    tun_cfg->mode = TUNNEL_MODE_PACKET;
    tun_cfg->proxy.type = TUNNEL_PROXY_NONE;
    return 0;
}

static void meshd_free_tunnel_config(tunnel_config_t *tun_cfg) {
    free((void *)tun_cfg->tun.ipv4_netmask);
    tun_cfg->tun.ipv4_netmask = NULL;
}

static int meshd_run_doctor(const char *config_path) {
    mesh_node_config_t cfg;
    int ok = 1;

    mesh_node_config_init(&cfg);
    if (mesh_node_config_load(&cfg, config_path) != 0) {
        return 1;
    }

    if (mesh_node_config_validate(&cfg) != 0) {
        return 1;
    }

    meshd_doctor_result("config", 1, "parsed and validated");
    ok &= meshd_doctor_check_listen_port(cfg.listen_port);
    ok &= meshd_doctor_check_tunnel_access();
    ok &= meshd_doctor_check_bootstrap_peers(&cfg);
    ok &= meshd_doctor_check_path_writable("status_file", cfg.status_file);
    ok &= meshd_doctor_check_path_writable("pid_file", cfg.pid_file);
    mesh_node_config_print(&cfg);
    return ok ? 0 : 1;
}

static int meshd_run(const char *config_path,
                     const mesh_node_config_t *override_cfg,
                     const char *rpc_listen,
                     const char *rpc_token) {
    mesh_config_t mesh_cfg;
    tunnel_config_t tun_cfg;
    int ret = 0;
    uint64_t last_status_ms = 0;

    mesh_node_config_init(&g_config);
    if (mesh_node_config_load(&g_config, config_path) != 0) {
        return 1;
    }
#ifdef TURBO_P2P_ENABLE_NODE_EXECUTION
    if (meshd_execution_config_load(&g_execution_local_config, config_path) !=
        0) {
        fprintf(stderr, "Invalid node execution configuration\n");
        return 1;
    }
#endif

    if (override_cfg) {
        if (override_cfg->status_file[0] != '\0') {
            strncpy(g_config.status_file, override_cfg->status_file, sizeof(g_config.status_file) - 1);
        }
        if (override_cfg->pid_file[0] != '\0') {
            strncpy(g_config.pid_file, override_cfg->pid_file, sizeof(g_config.pid_file) - 1);
        }
        if (override_cfg->status_interval_ms != 0) {
            g_config.status_interval_ms = override_cfg->status_interval_ms;
        }
    }

    if (mesh_node_config_validate(&g_config) != 0) {
        return 1;
    }

    meshd_init_logger();
    meshd_init_signals();
    g_started_ms = meshd_now_ms();
    memset(&g_mgmt_server, 0, sizeof(g_mgmt_server));
    g_mgmt_server.listen_socket = MESHD_INVALID_SOCKET;

    if (tunnel_init() != TUNNEL_OK) {
        fprintf(stderr, "Failed to initialize tunnel\n");
        return 1;
    }

    if (meshd_apply_tunnel_config(&tun_cfg, &g_config) != 0) {
        tunnel_shutdown();
        return 1;
    }

    g_tunnel = tunnel_create(&tun_cfg);
    if (!g_tunnel) {
        fprintf(stderr, "Failed to create tunnel\n");
        meshd_free_tunnel_config(&tun_cfg);
        tunnel_shutdown();
        return 1;
    }

    mesh_config_init(&mesh_cfg);
    mesh_cfg.virtual_ip = g_config.virtual_ip;
    mesh_cfg.virtual_prefix = (uint8_t)g_config.virtual_prefix;
    mesh_cfg.listen_port = g_config.listen_port;
    mesh_cfg.advertise_ip = g_config.advertise_ip[0] ? g_config.advertise_ip : NULL;
    mesh_cfg.identity_secret_hex =
        g_config.identity_secret_hex[0] ? g_config.identity_secret_hex : NULL;
    mesh_cfg.network_id = g_config.network_id;
    mesh_cfg.enable_ice = g_config.ice_enabled;
    mesh_cfg.ice_stun_servers = g_config.stun_servers;
    mesh_cfg.ice_stun_count = g_config.stun_count;
    mesh_cfg.ice_allow_loopback = g_config.ice_allow_loopback;
    mesh_cfg.bootstrap_peers = g_config.bootstrap_peers;
    mesh_cfg.bootstrap_count = g_config.bootstrap_count;
    mesh_cfg.route_rules = g_config.route_rules;
    mesh_cfg.route_rule_count = g_config.route_rule_count;
    mesh_cfg.local_egress_cidrs = g_config.local_egress_cidrs;
    mesh_cfg.local_egress_count = g_config.local_egress_count;
    mesh_cfg.local_egress_allow_cidrs = g_config.local_egress_allow_cidrs;
    mesh_cfg.local_egress_allow_count = g_config.local_egress_allow_count;
    mesh_cfg.magic_dns_domain =
        g_config.magic_dns_domain[0] ? g_config.magic_dns_domain : NULL;
    mesh_cfg.magic_dns_records = g_config.magic_dns_records;
    mesh_cfg.magic_dns_record_count = g_config.magic_dns_record_count;
    mesh_cfg.packet_policy_rules = g_config.packet_policy_rules;
    mesh_cfg.packet_policy_rule_count = g_config.packet_policy_rule_count;
    mesh_cfg.peer_allow_cidrs = g_config.peer_allow_cidrs;
    mesh_cfg.peer_allow_count = g_config.peer_allow_count;
    mesh_cfg.peer_allow_node_ids = g_config.peer_allow_node_ids;
    mesh_cfg.peer_allow_node_id_count = g_config.peer_allow_node_id_count;
    mesh_cfg.peer_protocol_major = g_config.peer_protocol_major;
    mesh_cfg.on_peer_connected = meshd_log_peer_connected;
    mesh_cfg.on_peer_disconnected = meshd_log_peer_disconnected;
    mesh_cfg.on_packet_received = meshd_on_mesh_packet;
    mesh_cfg.user_data = g_tunnel;

    g_mesh = mesh_create(&mesh_cfg);
    if (!g_mesh) {
        fprintf(stderr, "Failed to create mesh\n");
        tunnel_destroy(g_tunnel);
        g_tunnel = NULL;
        meshd_free_tunnel_config(&tun_cfg);
        tunnel_shutdown();
        return 1;
    }
    if (g_config.stream_enabled &&
        mesh_stream_admission_enable(g_mesh) != MESH_OK) {
        fprintf(stderr, "Failed to enable stream admission\n");
        mesh_destroy(g_mesh);
        g_mesh = NULL;
        tunnel_destroy(g_tunnel);
        g_tunnel = NULL;
        meshd_free_tunnel_config(&tun_cfg);
        tunnel_shutdown();
        return 1;
    }
    if (meshd_management_start(g_mesh, &g_config) != 0) {
        mesh_destroy(g_mesh);
        g_mesh = NULL;
        tunnel_destroy(g_tunnel);
        g_tunnel = NULL;
        meshd_free_tunnel_config(&tun_cfg);
        tunnel_shutdown();
        return 1;
    }

    tunnel_set_traffic_callback(g_tunnel, meshd_on_tun_packet, g_mesh);

    printf("Starting meshd '%s'\n", g_config.node_name);
    mesh_node_config_print(&g_config);

    ret = tunnel_start(g_tunnel);
    if (ret != TUNNEL_OK) {
        fprintf(stderr, "Failed to start tunnel: %s\n", tunnel_error_string(ret));
        meshd_management_stop();
        mesh_destroy(g_mesh);
        g_mesh = NULL;
        tunnel_destroy(g_tunnel);
        g_tunnel = NULL;
        meshd_free_tunnel_config(&tun_cfg);
        tunnel_shutdown();
        return 1;
    }

    ret = mesh_start(g_mesh);
    if (ret != MESH_OK) {
        fprintf(stderr, "Failed to start mesh: %s\n", mesh_error_string((mesh_error_t)ret));
        tunnel_stop(g_tunnel);
        meshd_management_stop();
        mesh_destroy(g_mesh);
        g_mesh = NULL;
        tunnel_destroy(g_tunnel);
        g_tunnel = NULL;
        meshd_free_tunnel_config(&tun_cfg);
        tunnel_shutdown();
        meshd_mgmt_server_stop(&g_mgmt_server);
        return 1;
    }

    if (rpc_listen && rpc_listen[0] != '\0' &&
        meshd_mgmt_server_start(&g_mgmt_server,
                                rpc_listen,
                                rpc_token,
                                g_mesh,
                                g_config.virtual_ip) != 0) {
        tunnel_stop(g_tunnel);
        meshd_management_stop();
        mesh_destroy(g_mesh);
        g_mesh = NULL;
        tunnel_destroy(g_tunnel);
        g_tunnel = NULL;
        meshd_free_tunnel_config(&tun_cfg);
        meshd_mgmt_server_stop(&g_mgmt_server);
        tunnel_shutdown();
        return 1;
    }
    if (g_management_configured && g_mgmt_server.service_port != 0u) {
        g_mgmt_server.resolve_service = meshd_management_resolve_service;
        g_mgmt_server.resolve_service_context = &g_management_runtime;
        if (meshd_management_publish_rpc_service() != 0) {
            fprintf(stderr, "Failed to publish signed RPC virtual service\n");
            meshd_mgmt_server_stop(&g_mgmt_server);
            tunnel_stop(g_tunnel);
            meshd_management_stop();
            mesh_destroy(g_mesh);
            g_mesh = NULL;
            tunnel_destroy(g_tunnel);
            g_tunnel = NULL;
            meshd_free_tunnel_config(&tun_cfg);
            tunnel_shutdown();
            return 1;
        }
    }

    meshd_write_pid_file();
    meshd_flush_status();
    last_status_ms = meshd_now_ms();

    while (meshd_is_running()) {
        tunnel_poll(g_tunnel, 100);
        mesh_poll(g_mesh, 100);
        meshd_mgmt_accept_and_serve(&g_mgmt_server);
#ifdef TURBO_P2P_ENABLE_NODE_EXECUTION
        (void)meshd_execution_drain();
#endif

        if (g_management_configured &&
            g_mgmt_server.service_port != 0u &&
            meshd_now_ms() - g_management_last_publish_ms >=
                MESHD_MGMT_SERVICE_PUBLISH_INTERVAL_MS) {
            if (meshd_management_publish_rpc_service() != 0) {
                fprintf(stderr, "Failed to refresh signed RPC virtual service\n");
                g_management_last_publish_ms = meshd_now_ms();
            }
        }

        if (g_config.status_file[0] != '\0' &&
            meshd_now_ms() - last_status_ms >= g_config.status_interval_ms) {
            meshd_flush_status();
            last_status_ms = meshd_now_ms();
        }

#ifndef _WIN32
        if (meshd_take_status_flush_request()) {
            meshd_flush_status();
            last_status_ms = meshd_now_ms();
        }
#endif

        meshd_sleep_ms(100);
    }

    meshd_flush_status();
    meshd_remove_pid_file();
    meshd_mgmt_server_stop(&g_mgmt_server);
    meshd_management_stop();
    mesh_stop(g_mesh);
    mesh_destroy(g_mesh);
    g_mesh = NULL;
    tunnel_stop(g_tunnel);
    tunnel_destroy(g_tunnel);
    g_tunnel = NULL;
    meshd_free_tunnel_config(&tun_cfg);
    tunnel_shutdown();
    return 0;
}

#ifndef MESHD_NO_MAIN
int main(int argc, char **argv) {
    const char *command = NULL;
    const char *config_path = NULL;
    mesh_node_config_t override_cfg;
    const char *rpc_listen = NULL;
    const char *rpc_token = NULL;
    int i = 0;

    if (argc < 4) {
        meshd_usage(argv[0]);
        return 1;
    }

    memset(&override_cfg, 0, sizeof(override_cfg));
    command = argv[1];
    for (i = 2; i < argc; i++) {
        if ((strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) && i + 1 < argc) {
            config_path = argv[i + 1];
            i++;
            continue;
        }

        if (strcmp(argv[i], "--status-file") == 0 && i + 1 < argc) {
            strncpy(override_cfg.status_file, argv[i + 1], sizeof(override_cfg.status_file) - 1);
            i++;
            continue;
        }

        if (strcmp(argv[i], "--pid-file") == 0 && i + 1 < argc) {
            strncpy(override_cfg.pid_file, argv[i + 1], sizeof(override_cfg.pid_file) - 1);
            i++;
            continue;
        }

        if (strcmp(argv[i], "--status-interval-ms") == 0 && i + 1 < argc) {
            override_cfg.status_interval_ms = (unsigned int)strtoul(argv[i + 1], NULL, 10);
            i++;
            continue;
        }

        if (strcmp(argv[i], "--rpc-listen") == 0 && i + 1 < argc) {
            rpc_listen = argv[i + 1];
            i++;
            continue;
        }

        if (strcmp(argv[i], "--rpc-token") == 0 && i + 1 < argc) {
            rpc_token = argv[i + 1];
            i++;
            continue;
        }
    }

    if (!config_path) {
        meshd_usage(argv[0]);
        return 1;
    }

    if (strcmp(command, "doctor") == 0) {
        return meshd_run_doctor(config_path);
    }

    if (strcmp(command, "run") == 0) {
        return meshd_run(config_path, &override_cfg, rpc_listen, rpc_token);
    }

    meshd_usage(argv[0]);
    return 1;
}
#endif
