#include <turbo_mesh.h>
#include <turbo_tunnel.h>
#include <tlog.h>
#include "mesh_config.h"
#include "mesh_runtime_health.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>

#define MESH_SNAPSHOT_VERSION 1

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

static volatile sig_atomic_t g_running = 1;
#ifndef _WIN32
static volatile sig_atomic_t g_status_flush_requested = 0;
#endif
static mesh_network_t *g_mesh = NULL;
static tunnel_t *g_tunnel = NULL;
static mesh_node_config_t g_config;
static uint64_t g_started_ms = 0;

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
    printf("  %s run -c <mesh.yaml> [--status-file <path>] [--pid-file <path>] [--status-interval-ms <n>]\n", argv0);
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

static int meshd_run(const char *config_path, const mesh_node_config_t *override_cfg) {
    mesh_config_t mesh_cfg;
    tunnel_config_t tun_cfg;
    int ret = 0;
    uint64_t last_status_ms = 0;

    mesh_node_config_init(&g_config);
    if (mesh_node_config_load(&g_config, config_path) != 0) {
        return 1;
    }

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

    tunnel_set_traffic_callback(g_tunnel, meshd_on_tun_packet, g_mesh);

    printf("Starting meshd '%s'\n", g_config.node_name);
    mesh_node_config_print(&g_config);

    ret = tunnel_start(g_tunnel);
    if (ret != TUNNEL_OK) {
        fprintf(stderr, "Failed to start tunnel: %s\n", tunnel_error_string(ret));
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
        mesh_destroy(g_mesh);
        g_mesh = NULL;
        tunnel_destroy(g_tunnel);
        g_tunnel = NULL;
        meshd_free_tunnel_config(&tun_cfg);
        tunnel_shutdown();
        return 1;
    }

    meshd_write_pid_file();
    meshd_flush_status();
    last_status_ms = meshd_now_ms();

    while (meshd_is_running()) {
        tunnel_poll(g_tunnel, 100);
        mesh_poll(g_mesh, 100);

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
    }

    if (!config_path) {
        meshd_usage(argv[0]);
        return 1;
    }

    if (strcmp(command, "doctor") == 0) {
        return meshd_run_doctor(config_path);
    }

    if (strcmp(command, "run") == 0) {
        return meshd_run(config_path, &override_cfg);
    }

    meshd_usage(argv[0]);
    return 1;
}
#endif
