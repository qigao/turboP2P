/**
 * mesh.c - P2P Mesh VPN implementation
 * Good Taste: Simple routing, no special cases, direct peer discovery
 */

#include "turbo_mesh.h"
#include "mesh_flow_runtime.h"
#include "mesh_internal_flow_policy.h"
#include "mesh_mgmt_mesh_bridge.h"
#include "mesh_path_optimizer.h"
#include <fmt.h>
#include <p2p.h>
#include <turbo_coro.h>
#include <CoroNet/turbo_coro_context.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include "tlog.h"

#include <ice/turbo_ice.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

#define MESH_ICE_CONNECTIVITY_TIMEOUT_MS 8000
#define MESH_ICE_SHUTDOWN_DRAIN_MS 3500
#define MESH_ICE_CLOSE_DRAIN_MS 1000
#define MESH_LEARNED_ROUTE_TTL_MS 60000
#define MESH_STREAM_METRICS_REFRESH_MS 1000U

/* =============================================================================
 * Internal Structures
 * ============================================================================= */

typedef struct mesh_peer_s {
    struct mesh_network_s *mesh;
    char virtual_ip[16];
    char real_ip[64];
    char advertised_real_ip[64];
    char peer_id[65];
    uint16_t protocol_major;
    uint16_t protocol_minor;
    uint32_t capabilities;
    uint32_t negotiated_capabilities;
    p2p_peer_t *p2p_peer;
    int is_connected;
    int announced;
    int transport_authenticated;
    uint64_t bytes_tx;
    uint64_t bytes_rx;
    uint64_t last_seen_ms;
    uint32_t stream_srtt_ms;
    uint32_t stream_rttvar_ms;
    int stream_metrics_fresh;
    turbo_ice_agent_t *ice_agent;
    char ice_local_ufrag[32];
    char ice_local_pwd[64];
    char ice_remote_ufrag[32];
    char ice_remote_pwd[64];
    int ice_remote_credentials_set;
    int ice_gathering_complete;
    int ice_checks_started;
    int ice_checks_running;
    int ice_selected_io_running;
    int ice_local_candidate_count;
    int ice_remote_candidate_count;
    int ice_auth_sent;
    int ice_end_of_candidates_sent;
    int ice_remote_end_of_candidates;
    int ice_check_start_local_candidate_count;
    int ice_check_start_remote_candidate_count;
    char ice_state[32];
    char ice_selected_local_endpoint[64];
    char ice_selected_remote_endpoint[64];
    struct mesh_peer_s *next;
} mesh_peer_t;

/* Routing table entry */
typedef enum {
    MESH_ROUTE_SOURCE_LEARNED = 0
} mesh_route_source_t;

typedef struct mesh_route_s {
    char dest_ip[16];              /* Destination virtual IP */
    char dest_real_ip[64];         /* Destination real IP:port if known */
    char next_hop_virtual_ip[16];  /* Stable next-hop identity within the mesh */
    mesh_peer_t *next_hop;         /* Next hop peer (direct neighbor) */
    uint8_t hop_count;             /* Distance in hops */
    mesh_route_source_t source;    /* Where this route came from */
    uint64_t last_update_ms;       /* When this route was updated */
    uint64_t expires_at_ms;        /* Learned routes expire unless refreshed */
    uint64_t direct_connect_after_ms; /* Cooldown for proactive direct retry */
    struct mesh_route_s *next;
} mesh_route_t;

typedef enum {
    MESH_NEXT_HOP_NONE = 0,
    MESH_NEXT_HOP_POLICY,
    MESH_NEXT_HOP_DIRECT,
    MESH_NEXT_HOP_LEARNED
} mesh_next_hop_kind_t;

typedef struct {
    mesh_next_hop_kind_t kind;
    mesh_peer_t *peer;
    mesh_route_t *route;
    const struct mesh_route_rule_entry_s *rule;
} mesh_path_candidate_t;

typedef struct {
    mesh_path_candidate_t candidates[MESH_PATH_METRIC_CANDIDATE_LIMIT];
    size_t candidate_count;
} mesh_path_snapshot_t;

typedef struct {
    mesh_next_hop_kind_t kind;
    mesh_peer_t *peer;
    mesh_route_t *route;
    const struct mesh_route_rule_entry_s *rule;
} mesh_next_hop_result_t;

typedef struct mesh_route_rule_entry_s {
    char dest_cidr[32];
    char next_hop_virtual_ip[16];
    uint32_t flags;
    uint32_t network_ip;
    uint32_t mask;
    uint8_t prefix_len;
} mesh_route_rule_entry_t;

typedef struct {
    char cidr[32];
    uint32_t network_ip;
    uint32_t mask;
    uint8_t prefix_len;
} mesh_peer_acl_entry_t;

typedef enum {
    MESH_POLICY_ADMIT_PEER = 0,
    MESH_POLICY_LEARN_ROUTE,
    MESH_POLICY_SEND_CONTROL,
    MESH_POLICY_FORWARD_PACKET,
    MESH_POLICY_DIRECT_CONNECT,
} mesh_policy_action_t;

typedef struct {
    char cidr[32];
    uint32_t network_ip;
    uint32_t mask;
    uint8_t prefix_len;
} mesh_local_egress_entry_t;

typedef struct {
    char node_id[65];
} mesh_peer_identity_acl_entry_t;

typedef struct {
    char name[64];
    char virtual_ip[16];
} mesh_magic_dns_entry_t;

typedef struct {
    char src_cidr[32];
    uint32_t src_network_ip;
    uint32_t src_mask;
    uint8_t src_prefix_len;
    char dst_cidr[32];
    uint32_t dst_network_ip;
    uint32_t dst_mask;
    uint8_t dst_prefix_len;
    uint8_t ip_proto;
    uint16_t src_port_start;
    uint16_t src_port_end;
    uint16_t dst_port_start;
    uint16_t dst_port_end;
    uint32_t directions;
    int allow;
} mesh_packet_policy_entry_t;

typedef struct mesh_network_s {
    /* Configuration */
    char virtual_ip[16];
    char node_id[65];
    char advertise_ip[64];
    uint8_t virtual_prefix;
    char network_id[64];
    int listen_port;            /* P2P listen port */

    /* Bootstrap peers */
    char **bootstrap_peers;
    int bootstrap_count;
    int ice_enabled;
    int stream_enabled;
    int ice_allow_loopback;
    char **ice_stun_servers;
    int ice_stun_count;
    int virtual_ip_registered;

    /* P2P layer */
    p2p_node_t *p2p_node;
    mesh_mgmt_agent_router_v1_t *mgmt_router;
    coro_context_t *ice_ctx;


    int p2p_running;

    /* Peers (direct neighbors) */
    mesh_peer_t *peers;
    mesh_peer_t *retired_peers;
    int peer_count;

    /* Routing table (all reachable nodes) */
    mesh_route_t *routes;
    int route_count;

    /* Route policy (operator intent, separate from learned state) */
    mesh_route_rule_entry_t *route_rules;
    int route_rule_count;
    mesh_local_egress_entry_t *local_egress_cidrs;
    int local_egress_count;
    mesh_peer_acl_entry_t *local_egress_allow_cidrs;
    int local_egress_allow_count;
    mesh_peer_acl_entry_t *peer_allow_cidrs;
    int peer_allow_count;
    mesh_peer_identity_acl_entry_t *peer_allow_node_ids;
    int peer_allow_node_id_count;
    unsigned int peer_protocol_major;
    char magic_dns_domain[64];
    mesh_magic_dns_entry_t *magic_dns_records;
    int magic_dns_record_count;
    mesh_packet_policy_entry_t *packet_policy_rules;
    int packet_policy_rule_count;
    mesh_flow_runtime_v1_t runtime_flow_policy;

    /* Statistics */
    mesh_stats_t stats;

    /* Route discovery state */
    int poll_count;  /* For periodic route updates */
    int reconnect_poll_count;
    int control_plane_dirty;
    int bootstrap_reconnect_pending;
    uint32_t bootstrap_connect_attempts;
    uint32_t bootstrap_retry_rounds;
    uint32_t bootstrap_reconnect_scheduled;
    uint32_t direct_connect_attempts;
    uint32_t direct_connect_started;
    uint32_t peer_connect_events;
    uint32_t peer_disconnect_events;
    uint32_t control_plane_refreshes;
    uint32_t ice_auth_messages_tx;
    uint32_t ice_auth_messages_rx;
    uint32_t ice_candidate_messages_tx;
    uint32_t ice_candidate_messages_rx;
    uint32_t ice_end_of_candidates_tx;
    uint32_t ice_end_of_candidates_rx;
    uint32_t ice_checks_started;
    uint32_t ice_last_check_local_candidate_count;
    uint32_t ice_last_check_remote_candidate_count;
    uint64_t stream_metrics_last_refresh_ms;
    mesh_path_observer_store_t path_observer;
    mesh_path_trace_store_t path_trace;
    uint64_t path_metric_observations;
    uint64_t path_metric_recommendation_mismatches;
    mesh_path_metric_kind_t last_current_path_kind;
    mesh_path_metric_kind_t last_recommended_path_kind;
    uint32_t last_current_path_cost;
    uint32_t last_recommended_path_cost;
    int last_recommended_path_available;
    int last_path_policy_forced;
    char last_reconnect_reason[64];
    char last_direct_attempt_endpoint[64];
    char last_active_relay_next_hop_virtual_ip[16];
    char last_active_relay_next_hop_real_ip[64];
    char last_ice_state[32];
    char last_ice_selected_local_endpoint[64];
    char last_ice_selected_remote_endpoint[64];

    /* Callbacks */
    void (*on_peer_connected)(mesh_peer_t *peer, void *user_data);
    void (*on_peer_disconnected)(mesh_peer_t *peer, void *user_data);
    void (*on_packet_received)(const uint8_t *data, size_t len, void *user_data);
    void *user_data;
} mesh_network_t;

static void mesh_route_delete_via_peer(mesh_network_t *mesh, mesh_peer_t *peer);
static void mesh_route_delete(mesh_network_t *mesh, const char *dest_ip);
static void mesh_send_routes_to_peer(mesh_network_t *mesh, mesh_peer_t *target);
static void mesh_broadcast_routes(mesh_network_t *mesh);
static void mesh_connect_bootstrap_peers(mesh_network_t *mesh, int is_retry);
static int mesh_create_p2p_node(mesh_network_t *mesh);
static int mesh_register_virtual_ip(mesh_network_t *mesh);
static int mesh_ensure_virtual_ip_registered(mesh_network_t *mesh);
static void mesh_peer_destroy(mesh_peer_t *peer);
static mesh_peer_t *mesh_peer_create_virtual(mesh_network_t *mesh, const char *virtual_ip);
static void mesh_route_destroy(mesh_route_t *route);
static mesh_route_t *mesh_route_find(mesh_network_t *mesh, const char *dest_ip);
static void mesh_route_expire_stale(mesh_network_t *mesh);
static mesh_peer_t *mesh_find_peer_by_p2p(mesh_network_t *mesh, p2p_peer_t *p2p_peer);
static mesh_peer_t *mesh_find_peer_by_real(mesh_network_t *mesh, const char *real_ip);
static mesh_peer_t *mesh_find_peer_by_endpoint(mesh_network_t *mesh, const char *endpoint);
static mesh_peer_t *mesh_find_peer_internal(mesh_network_t *mesh, const char *virtual_ip);
static mesh_peer_t *mesh_find_peer_any_virtual(mesh_network_t *mesh, const char *virtual_ip);
static mesh_peer_t *mesh_find_or_create_signal_peer(mesh_network_t *mesh,
                                                    p2p_peer_t *p2p_peer,
                                                    const char *virtual_ip);
static mesh_peer_t *mesh_find_peer_by_virtual_except(mesh_network_t *mesh,
                                                     const char *virtual_ip,
                                                     mesh_peer_t *skip);
static int mesh_has_connected_peers(mesh_network_t *mesh);
static void mesh_schedule_control_plane_refresh(mesh_network_t *mesh,
                                                int reconnect_bootstrap,
                                                const char *reason);
static void mesh_on_p2p_peer_connected(p2p_peer_t *p2p_peer, void *user_data);
static void mesh_on_p2p_peer_disconnected(p2p_peer_t *p2p_peer, void *user_data);
static void mesh_on_p2p_message(p2p_node_t *node, p2p_peer_t *p2p_peer,
                                const void *data, size_t len, void *user_data);
static uint64_t mesh_now_ms(void);
static int mesh_parse_endpoint(const char *endpoint, char *ip, size_t ip_len, int *port);
static int mesh_ip_is_unspecified(const char *ip);
static int mesh_endpoint_is_routable(const char *endpoint);
static int mesh_try_direct_connect(mesh_network_t *mesh, const char *virtual_ip,
                                   const char *endpoint, int force);
static int mesh_send_control_message(mesh_network_t *mesh, const char *dest_virtual_ip,
                                     const char *msg);
static int mesh_handle_control_payload(mesh_network_t *mesh, p2p_peer_t *p2p_peer,
                                       const char *msg);
static mesh_path_mode_t mesh_get_path_mode_internal(mesh_network_t *mesh);
static void mesh_note_active_relay_next_hop(mesh_network_t *mesh, mesh_peer_t *next_hop);
static int mesh_parse_route_cidr(const char *cidr, uint32_t *network_ip,
                                 uint32_t *mask, uint8_t *prefix_len);
static int mesh_policy_allows_virtual_ip(const mesh_network_t *mesh,
                                         mesh_policy_action_t action,
                                         const char *virtual_ip);
static int mesh_policy_allows_local_egress_source(mesh_network_t *mesh,
                                                  const mesh_peer_t *incoming_peer,
                                                  uint32_t src_ip);
static int mesh_packet_policy_allows(mesh_network_t *mesh,
                                     uint32_t direction,
                                     const uint8_t *ip_packet,
                                     size_t len);
static int mesh_peer_acl_allows_node_id(const mesh_network_t *mesh, const char *node_id);
static int mesh_ip_in_virtual_network(mesh_network_t *mesh, uint32_t ip);
static int mesh_magic_dns_normalize_name(const char *name, char *buf, size_t buf_len);
static int mesh_magic_dns_name_valid(const char *name);
static int mesh_magic_dns_domain_matches(const mesh_network_t *mesh,
                                         const char *query,
                                         const char *record_name);
static const mesh_route_rule_entry_t *mesh_route_rule_find(mesh_network_t *mesh, uint32_t dst_ip);
static mesh_peer_t *mesh_route_rule_next_hop_find(mesh_network_t *mesh,
                                                  const mesh_route_rule_entry_t *rule);
static const mesh_local_egress_entry_t *mesh_local_egress_find(mesh_network_t *mesh,
                                                               uint32_t dst_ip);
static int mesh_try_routed_ice_connect(mesh_network_t *mesh, const char *virtual_ip, int force);
static void mesh_ice_tracef(const char *fmt, ...) {
    const char *path = getenv("TURBO_ICE_TRACE");
    FILE *fp = NULL;
    va_list args;

    if (!path || path[0] == '\0') {
        return;
    }

    fp = fopen(path, "a");
    if (!fp) {
        return;
    }

    va_start(args, fmt);
    vfprintf(fp, fmt, args);
    va_end(args);
    fputc('\n', fp);
    fclose(fp);
}

static int mesh_ice_agent_has_pending_work(turbo_ice_agent_t *agent) {
    ice_state_t state;

    if (!agent) {
        return 0;
    }

    /* Shutdown clears callbacks first, so the mirrored peer->ice_state string can
     * be stale while the agent is still finishing its own state machine. */
    state = ice_agent_get_state(agent);
    return state == ICE_STATE_GATHERING ||
           state == ICE_STATE_CONNECTING ||
           state == ICE_STATE_CONNECTED ||
           state == ICE_STATE_COMPLETED;
}

static void mesh_ice_init_peer(mesh_network_t *mesh, mesh_peer_t *peer);
static void mesh_ice_quiesce_peer(mesh_peer_t *peer);
static void mesh_ice_destroy_peer(mesh_peer_t *peer);
static void mesh_ice_send_auth(mesh_peer_t *peer);
static void mesh_ice_send_end_of_candidates(mesh_peer_t *peer);
static void mesh_ice_maybe_start_checks(mesh_peer_t *peer);
static int mesh_ice_can_gather_inline(const mesh_network_t *mesh);
static void mesh_ice_drain_context(coro_context_t *ctx, uint64_t drain_ms);
static void mesh_ice_gather_task(coro_t *co, void *arg);
static void mesh_ice_checks_task(coro_t *co, void *arg);
static void mesh_ice_selected_io_task(coro_t *co, void *arg);
static void mesh_ice_on_state_changed(turbo_ice_agent_t *agent, ice_state_t old_state,
                                      ice_state_t new_state, void *user_data);
static void mesh_ice_on_gathering_changed(turbo_ice_agent_t *agent,
                                          ice_gathering_state_t state,
                                          void *user_data);
static void mesh_ice_on_candidate_discovered(turbo_ice_agent_t *agent,
                                             const ice_candidate_t *candidate,
                                             void *user_data);
static void mesh_ice_on_data_received(turbo_ice_agent_t *agent, const void *data,
                                      size_t len, void *user_data);
static void mesh_ice_handle_auth(mesh_peer_t *peer, const char *payload);
static void mesh_ice_handle_candidate(mesh_peer_t *peer, const char *candidate_sdp);
static void mesh_ice_handle_end_of_candidates(mesh_peer_t *peer);
static int mesh_peer_has_active_ice_path(const mesh_peer_t *peer);
static int mesh_send_to_peer(mesh_peer_t *peer, const void *data, size_t len);
static void mesh_handle_ip_packet(mesh_network_t *mesh, mesh_peer_t *incoming_peer,
                                  const uint8_t *ip_packet, size_t len);
static void mesh_disconnect_all_p2p_peers(mesh_network_t *mesh);
static void mesh_send_hello(mesh_network_t *mesh, p2p_peer_t *p2p_peer);

/* =============================================================================
 * Utility Functions
 * ============================================================================= */

static uint32_t ip_str_to_uint32(const char *ip_str) {
    unsigned int a, b, c, d;
    if (sscanf(ip_str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
        return 0;
    }
    return (a << 24) | (b << 16) | (c << 8) | d;
}

static void uint32_to_ip_str(uint32_t ip, char *out) {
    sprintf(out, "%u.%u.%u.%u",
            (ip >> 24) & 0xFF,
            (ip >> 16) & 0xFF,
            (ip >> 8) & 0xFF,
            ip & 0xFF);
}

static int mesh_node_id_is_valid(const char *node_id) {
    int i = 0;

    if (!node_id || strlen(node_id) != 64) {
        return 0;
    }

    for (i = 0; i < 64; i++) {
        char c = node_id[i];
        if (!((c >= '0' && c <= '9') ||
              (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F'))) {
            return 0;
        }
    }

    return 1;
}

static void mesh_bytes_to_hex(const uint8_t *bytes, size_t len, char *out, size_t out_len) {
    static const char hex[] = "0123456789abcdef";
    size_t i = 0;

    if (!bytes || !out || out_len < len * 2 + 1) {
        return;
    }

    for (i = 0; i < len; i++) {
        out[i * 2] = hex[(bytes[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex[bytes[i] & 0x0F];
    }
    out[len * 2] = '\0';
}

static int mesh_hex_digit_value(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static int mesh_hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    size_t hex_len = 0;

    if (!hex || !out) {
        return 0;
    }

    hex_len = strlen(hex);
    if (hex_len != out_len * 2) {
        return 0;
    }

    for (size_t i = 0; i < out_len; i++) {
        int hi = mesh_hex_digit_value(hex[i * 2]);
        int lo = mesh_hex_digit_value(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return 0;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }

    return 1;
}

static int mesh_update_node_id_from_p2p(mesh_network_t *mesh) {
    uint8_t node_id[P2P_KEY_SIZE];

    if (!mesh || !mesh->p2p_node) {
        return 0;
    }

    if (p2p_node_get_public_key(mesh->p2p_node, node_id) != P2P_OK) {
        return 0;
    }

    mesh_bytes_to_hex(node_id, sizeof(node_id), mesh->node_id, sizeof(mesh->node_id));
    return mesh->node_id[0] != '\0';
}

static int mesh_p2p_peer_id_matches(p2p_peer_t *p2p_peer, const char *node_id) {
    uint8_t peer_id[P2P_KEY_SIZE];
    char peer_id_hex[65] = {0};
    int ret = 0;

    if (!p2p_peer || !node_id || node_id[0] == '\0') {
        return 1;
    }

    ret = p2p_peer_get_public_key(p2p_peer, peer_id);
    if (ret == P2P_ERR_NOT_FOUND) {
        return 1;
    }
    if (ret != P2P_OK) {
        return 0;
    }

    mesh_bytes_to_hex(peer_id, sizeof(peer_id), peer_id_hex, sizeof(peer_id_hex));
    return strcmp(peer_id_hex, node_id) == 0;
}

static int mesh_p2p_peer_identity_is_verified(p2p_peer_t *p2p_peer,
                                              const char *node_id) {
    uint8_t peer_id[P2P_KEY_SIZE];
    char peer_id_hex[65] = {0};

    if (!p2p_peer || !mesh_node_id_is_valid(node_id) ||
        p2p_peer_get_public_key(p2p_peer, peer_id) != P2P_OK) {
        return 0;
    }

    mesh_bytes_to_hex(peer_id, sizeof(peer_id), peer_id_hex,
                      sizeof(peer_id_hex));
    return strcmp(peer_id_hex, node_id) == 0;
}

static uint32_t mesh_local_capabilities(const mesh_network_t *mesh) {
    uint32_t capabilities = MESH_CAP_LOCAL_DEFAULT;

    if (mesh && mesh->ice_enabled) {
        capabilities |= MESH_CAP_SELECTED_PAIR_IP;
    }
    if (mesh && mesh->stream_enabled) {
        capabilities |= MESH_CAP_STREAM_V1;
    }
    return capabilities;
}

static int mesh_peer_has_capability(const mesh_peer_t *peer, uint32_t capability) {
    return peer && (peer->negotiated_capabilities & capability) == capability;
}

static int mesh_peer_stream_binding_is_valid(const mesh_peer_t *peer) {
    return peer && peer->mesh && peer->mesh->stream_enabled &&
           peer->transport_authenticated && peer->announced &&
           peer->is_connected &&
           peer->protocol_major == MESH_PROTOCOL_MAJOR &&
           mesh_p2p_peer_identity_is_verified(peer->p2p_peer, peer->peer_id);
}

static void mesh_peer_refresh_negotiated_capabilities(mesh_peer_t *peer) {
    uint32_t negotiated;

    if (!peer || !peer->mesh) {
        return;
    }

    negotiated = mesh_local_capabilities(peer->mesh) & peer->capabilities;
    if ((negotiated & MESH_CAP_STREAM_V1) != 0u &&
        !mesh_peer_stream_binding_is_valid(peer)) {
        negotiated &= ~MESH_CAP_STREAM_V1;
    }
    peer->negotiated_capabilities = negotiated;
}

static uint32_t mesh_parse_hello_capabilities(const char *payload) {
    const char *caps = NULL;
    char *end = NULL;
    unsigned long value = 0;

    if (!payload) {
        return 0;
    }

    caps = strstr(payload, ":caps=");
    if (!caps) {
        return 0;
    }

    caps += 6;
    if (*caps == '\0') {
        return 0;
    }

    value = strtoul(caps, &end, 16);
    if (end == caps || (*end != '\0' && *end != ':') || value > 0xFFFFFFFFul) {
        return 0;
    }

    return (uint32_t)value;
}

static int mesh_parse_hello_message(const char *payload,
                                    char *virtual_ip,
                                    size_t virtual_ip_len,
                                    char *advertised_ip,
                                    size_t advertised_ip_len,
                                    int *advertised_port,
                                    char *node_id,
                                    size_t node_id_len,
                                    unsigned int *protocol_major,
                                    unsigned int *protocol_minor,
                                    uint32_t *capabilities) {
    char parsed_virtual_ip[16] = {0};
    char parsed_advertised_ip[64] = {0};
    char parsed_node_id[65] = {0};
    unsigned int parsed_protocol_major = 0;
    unsigned int parsed_protocol_minor = 0;
    int parsed_port = 0;

    if (!payload || !virtual_ip || virtual_ip_len == 0 ||
        !advertised_ip || advertised_ip_len == 0 ||
        !advertised_port || !node_id || node_id_len == 0 ||
        !protocol_major || !protocol_minor || !capabilities) {
        return 0;
    }

    *protocol_major = 0;
    *protocol_minor = 0;
    *capabilities = 0;

    if (sscanf(payload, "%15[^:]:%63[^:]:%d:node=%64[0-9A-Fa-f]:proto=%u.%u",
               parsed_virtual_ip, parsed_advertised_ip, &parsed_port,
               parsed_node_id, &parsed_protocol_major, &parsed_protocol_minor) == 6) {
        strncpy(virtual_ip, parsed_virtual_ip, virtual_ip_len - 1);
        strncpy(advertised_ip, parsed_advertised_ip, advertised_ip_len - 1);
        *advertised_port = parsed_port;
        if (mesh_node_id_is_valid(parsed_node_id)) {
            strncpy(node_id, parsed_node_id, node_id_len - 1);
        }
        if (parsed_protocol_major == 0 || parsed_protocol_major > UINT16_MAX ||
            parsed_protocol_minor > UINT16_MAX) {
            return 0;
        }
        *protocol_major = parsed_protocol_major;
        *protocol_minor = parsed_protocol_minor;
        *capabilities = mesh_parse_hello_capabilities(payload);
        return 1;
    }

    memset(parsed_virtual_ip, 0, sizeof(parsed_virtual_ip));
    memset(parsed_node_id, 0, sizeof(parsed_node_id));
    parsed_protocol_major = 0;
    parsed_protocol_minor = 0;
    if (sscanf(payload, "%15[^:]:node=%64[0-9A-Fa-f]:proto=%u.%u",
               parsed_virtual_ip, parsed_node_id,
               &parsed_protocol_major, &parsed_protocol_minor) == 4) {
        strncpy(virtual_ip, parsed_virtual_ip, virtual_ip_len - 1);
        if (mesh_node_id_is_valid(parsed_node_id)) {
            strncpy(node_id, parsed_node_id, node_id_len - 1);
        }
        if (parsed_protocol_major == 0 || parsed_protocol_major > UINT16_MAX ||
            parsed_protocol_minor > UINT16_MAX) {
            return 0;
        }
        *protocol_major = parsed_protocol_major;
        *protocol_minor = parsed_protocol_minor;
        *capabilities = mesh_parse_hello_capabilities(payload);
        return 1;
    }

    memset(parsed_virtual_ip, 0, sizeof(parsed_virtual_ip));
    memset(parsed_advertised_ip, 0, sizeof(parsed_advertised_ip));
    memset(parsed_node_id, 0, sizeof(parsed_node_id));
    if (sscanf(payload, "%15[^:]:%63[^:]:%d:node=%64[0-9A-Fa-f]",
               parsed_virtual_ip, parsed_advertised_ip, &parsed_port,
               parsed_node_id) >= 3) {
        strncpy(virtual_ip, parsed_virtual_ip, virtual_ip_len - 1);
        strncpy(advertised_ip, parsed_advertised_ip, advertised_ip_len - 1);
        *advertised_port = parsed_port;
        if (mesh_node_id_is_valid(parsed_node_id)) {
            strncpy(node_id, parsed_node_id, node_id_len - 1);
        }
        return 1;
    }

    memset(parsed_virtual_ip, 0, sizeof(parsed_virtual_ip));
    memset(parsed_node_id, 0, sizeof(parsed_node_id));
    if (sscanf(payload, "%15[^:]:node=%64[0-9A-Fa-f]",
               parsed_virtual_ip, parsed_node_id) == 2) {
        strncpy(virtual_ip, parsed_virtual_ip, virtual_ip_len - 1);
        if (mesh_node_id_is_valid(parsed_node_id)) {
            strncpy(node_id, parsed_node_id, node_id_len - 1);
        }
        return 1;
    }

    memset(parsed_virtual_ip, 0, sizeof(parsed_virtual_ip));
    memset(parsed_advertised_ip, 0, sizeof(parsed_advertised_ip));
    parsed_port = 0;
    if (sscanf(payload, "%15[^:]:%63[^:]:%d",
               parsed_virtual_ip, parsed_advertised_ip, &parsed_port) >= 1) {
        strncpy(virtual_ip, parsed_virtual_ip, virtual_ip_len - 1);
        if (parsed_advertised_ip[0] != '\0' && parsed_port > 0) {
            strncpy(advertised_ip, parsed_advertised_ip, advertised_ip_len - 1);
            *advertised_port = parsed_port;
        }
        return 1;
    }

    return 0;
}

static int mesh_parse_route_cidr(const char *cidr, uint32_t *network_ip,
                                 uint32_t *mask, uint8_t *prefix_len) {
    char ip[32];
    const char *slash = NULL;
    char *end = NULL;
    long prefix = 32;
    uint32_t parsed_ip = 0;
    uint32_t parsed_mask = 0;
    size_t ip_len = 0;

    if (!cidr || cidr[0] == '\0') {
        return 0;
    }

    slash = strchr(cidr, '/');
    if (slash) {
        ip_len = (size_t)(slash - cidr);
        if (ip_len == 0 || ip_len >= sizeof(ip)) {
            return 0;
        }
        memcpy(ip, cidr, ip_len);
        ip[ip_len] = '\0';

        prefix = strtol(slash + 1, &end, 10);
        if (!end || *end != '\0' || prefix < 0 || prefix > 32) {
            return 0;
        }
    } else {
        if (strlen(cidr) >= sizeof(ip)) {
            return 0;
        }
        strncpy(ip, cidr, sizeof(ip) - 1);
        ip[sizeof(ip) - 1] = '\0';
    }

    parsed_ip = ip_str_to_uint32(ip);
    if (parsed_ip == 0 && strcmp(ip, "0.0.0.0") != 0) {
        return 0;
    }

    parsed_mask = prefix == 0 ? 0 : (0xFFFFFFFFu << (32 - prefix));

    if (network_ip) {
        *network_ip = parsed_ip & parsed_mask;
    }
    if (mask) {
        *mask = parsed_mask;
    }
    if (prefix_len) {
        *prefix_len = (uint8_t)prefix;
    }

    return 1;
}

static int mesh_cidr_entries_allow_ip(const mesh_peer_acl_entry_t *entries,
                                      int entry_count,
                                      uint32_t ip) {
    int i = 0;

    if (!entries || entry_count <= 0) {
        return 1;
    }

    if (ip == 0) {
        return 0;
    }

    for (i = 0; i < entry_count; i++) {
        const mesh_peer_acl_entry_t *entry = &entries[i];
        if ((ip & entry->mask) == entry->network_ip) {
            return 1;
        }
    }

    return 0;
}

static int mesh_policy_allows_virtual_ip(const mesh_network_t *mesh,
                                         mesh_policy_action_t action,
                                         const char *virtual_ip) {
    uint32_t ip = 0;

    (void)action;

    if (!mesh || !virtual_ip || virtual_ip[0] == '\0') {
        return 0;
    }

    ip = ip_str_to_uint32(virtual_ip);
    return mesh_cidr_entries_allow_ip(mesh->peer_allow_cidrs, mesh->peer_allow_count, ip);
}

static int mesh_peer_acl_allows_node_id(const mesh_network_t *mesh, const char *node_id) {
    int i = 0;

    if (!mesh) {
        return 0;
    }

    if (!mesh->peer_allow_node_ids || mesh->peer_allow_node_id_count <= 0) {
        return 1;
    }

    if (!node_id || node_id[0] == '\0') {
        return 0;
    }

    for (i = 0; i < mesh->peer_allow_node_id_count; i++) {
        const mesh_peer_identity_acl_entry_t *entry = &mesh->peer_allow_node_ids[i];
        if (strcmp(entry->node_id, node_id) == 0) {
            return 1;
        }
    }

    return 0;
}

static int mesh_peer_protocol_major_allowed(const mesh_network_t *mesh,
                                            unsigned int protocol_major) {
    if (!mesh || mesh->peer_protocol_major == 0) {
        return 1;
    }

    if (protocol_major == 0) {
        return 0;
    }

    return protocol_major == mesh->peer_protocol_major;
}

static int mesh_magic_dns_normalize_name(const char *name, char *buf, size_t buf_len) {
    size_t i = 0;
    size_t len = 0;

    if (!name || !buf || buf_len == 0 || name[0] == '\0') {
        return 0;
    }

    len = strlen(name);
    while (len > 0 && name[len - 1] == '.') {
        len--;
    }
    if (len == 0 || len >= buf_len) {
        return 0;
    }

    for (i = 0; i < len; i++) {
        buf[i] = (char)tolower((unsigned char)name[i]);
    }
    buf[len] = '\0';
    return 1;
}

static int mesh_magic_dns_name_valid(const char *name) {
    size_t label_len = 0;
    char prev = '\0';

    if (!name || name[0] == '\0' || strlen(name) > 127) {
        return 0;
    }

    for (const char *p = name; *p; p++) {
        unsigned char ch = (unsigned char)*p;

        if (*p == '.') {
            if (label_len == 0 || prev == '-') {
                return 0;
            }
            label_len = 0;
            prev = *p;
            continue;
        }

        if (!isalnum(ch) && *p != '-') {
            return 0;
        }
        if (label_len == 0 && *p == '-') {
            return 0;
        }
        label_len++;
        if (label_len > 63) {
            return 0;
        }
        prev = *p;
    }

    return label_len > 0 && prev != '-';
}

static int mesh_magic_dns_domain_matches(const mesh_network_t *mesh,
                                         const char *query,
                                         const char *record_name) {
    char fqdn[128];

    if (!query || !record_name) {
        return 0;
    }

    if (strcmp(query, record_name) == 0) {
        return 1;
    }

    if (!mesh || mesh->magic_dns_domain[0] == '\0') {
        return 0;
    }

    if (!strchr(record_name, '.')) {
        fmt(fqdn, sizeof(fqdn), "{}.{}", record_name, mesh->magic_dns_domain);
        if (strcmp(query, fqdn) == 0) {
            return 1;
        }
    }

    if (!strchr(query, '.')) {
        fmt(fqdn, sizeof(fqdn), "{}.{}", query, mesh->magic_dns_domain);
        if (strcmp(record_name, fqdn) == 0) {
            return 1;
        }
    }

    return 0;
}

static uint32_t extract_dst_ip(const uint8_t *ip_packet, size_t len) {
    if (len < 20) return 0;  /* Too short for IP header */

    /* IPv4 destination IP is at offset 16 */
    uint32_t dst = 0;
    dst |= (uint32_t)ip_packet[16] << 24;
    dst |= (uint32_t)ip_packet[17] << 16;
    dst |= (uint32_t)ip_packet[18] << 8;
    dst |= (uint32_t)ip_packet[19];

    return dst;
}

static uint32_t extract_src_ip(const uint8_t *ip_packet, size_t len) {
    if (len < 20) return 0;

    uint32_t src = 0;
    src |= (uint32_t)ip_packet[12] << 24;
    src |= (uint32_t)ip_packet[13] << 16;
    src |= (uint32_t)ip_packet[14] << 8;
    src |= (uint32_t)ip_packet[15];

    return src;
}

static uint64_t mesh_now_ms(void) {
    return turbo_hrtime() / 1000000;
}

static int mesh_refresh_stream_metrics(mesh_network_t *mesh) {
    mesh_peer_t *peer = NULL;
    uint64_t now_ms = 0;

    if (!mesh) {
        return 0;
    }

    now_ms = mesh_now_ms();
    if (mesh->stream_metrics_last_refresh_ms != 0 &&
        now_ms >= mesh->stream_metrics_last_refresh_ms &&
        now_ms - mesh->stream_metrics_last_refresh_ms <
            MESH_STREAM_METRICS_REFRESH_MS) {
        return 0;
    }
    mesh->stream_metrics_last_refresh_ms = now_ms;

    for (peer = mesh->peers; peer; peer = peer->next) {
        p2p_peer_stream_metrics_t metrics = {0};

        peer->stream_metrics_fresh = 0;
        peer->stream_srtt_ms = 0;
        peer->stream_rttvar_ms = 0;
        if (!peer->is_connected || !peer->p2p_peer ||
            p2p_peer_get_stream_metrics(peer->p2p_peer, &metrics) != P2P_OK ||
            metrics.sample_count == 0 || !metrics.is_fresh) {
            continue;
        }

        peer->stream_srtt_ms = metrics.srtt_ms;
        peer->stream_rttvar_ms = metrics.rttvar_ms;
        peer->stream_metrics_fresh = 1;
    }

    return 1;
}

static int mesh_ip_is_unspecified(const char *ip) {
    return ip == NULL || ip[0] == '\0' ||
           strcmp(ip, "0.0.0.0") == 0 ||
           strcmp(ip, "::") == 0;
}

static uint16_t mesh_ipv4_checksum(const uint8_t *data, size_t len) {
    uint32_t sum = 0;
    size_t i = 0;

    while (i + 1 < len) {
        sum += ((uint32_t)data[i] << 8) | data[i + 1];
        i += 2;
    }

    if (i < len) {
        sum += (uint32_t)data[i] << 8;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }

    return (uint16_t)~sum;
}

static int mesh_ip_is_multicast(uint32_t ip) {
    return (ip & 0xF0000000u) == 0xE0000000u;
}

static int mesh_ip_in_virtual_network(mesh_network_t *mesh, uint32_t ip) {
    uint32_t network_ip = 0;
    uint32_t mask = 0;

    if (!mesh) {
        return 0;
    }

    if (mesh->virtual_prefix == 0) {
        return 1;
    }
    if (mesh->virtual_prefix > 32) {
        return 0;
    }

    network_ip = ip_str_to_uint32(mesh->virtual_ip);
    mask = 0xFFFFFFFFu << (32 - mesh->virtual_prefix);

    return (ip & mask) == (network_ip & mask);
}

static int mesh_policy_allows_local_egress_source(mesh_network_t *mesh,
                                                  const mesh_peer_t *incoming_peer,
                                                  uint32_t src_ip) {
    uint32_t authenticated_src_ip = 0;

    if (!mesh || !incoming_peer || !incoming_peer->p2p_peer ||
        !incoming_peer->announced || src_ip == 0) {
        return 0;
    }

    if (!mesh_ip_in_virtual_network(mesh, src_ip)) {
        return 0;
    }

    authenticated_src_ip = ip_str_to_uint32(incoming_peer->virtual_ip);
    if (authenticated_src_ip == 0 || authenticated_src_ip != src_ip) {
        return 0;
    }

    return mesh_cidr_entries_allow_ip(mesh->local_egress_allow_cidrs,
                                      mesh->local_egress_allow_count,
                                      src_ip);
}

static int mesh_packet_extract_ports(const uint8_t *ip_packet, size_t len,
                                     uint16_t *src_port, uint16_t *dst_port) {
    size_t header_len = 0;
    uint8_t proto = 0;

    if (!ip_packet || len < 20) {
        return 0;
    }

    proto = ip_packet[9];
    if (proto != 6 && proto != 17) {
        return 0;
    }

    header_len = (size_t)(ip_packet[0] & 0x0fu) * 4u;
    if (header_len < 20 || header_len + 4 > len) {
        return 0;
    }

    if (src_port) {
        *src_port = (uint16_t)(((uint16_t)ip_packet[header_len] << 8) |
                               ip_packet[header_len + 1]);
    }
    if (dst_port) {
        *dst_port = (uint16_t)(((uint16_t)ip_packet[header_len + 2] << 8) |
                               ip_packet[header_len + 3]);
    }
    return 1;
}

static int mesh_packet_policy_rule_matches(const mesh_packet_policy_entry_t *rule,
                                           uint32_t direction,
                                           const uint8_t *ip_packet,
                                           size_t len) {
    uint32_t src_ip = 0;
    uint32_t dst_ip = 0;
    uint8_t proto = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    int have_ports = 0;

    if (!rule || !ip_packet || len < 20 || !(rule->directions & direction)) {
        return 0;
    }

    src_ip = extract_src_ip(ip_packet, len);
    dst_ip = extract_dst_ip(ip_packet, len);
    proto = ip_packet[9];

    if ((src_ip & rule->src_mask) != rule->src_network_ip) {
        return 0;
    }
    if ((dst_ip & rule->dst_mask) != rule->dst_network_ip) {
        return 0;
    }
    if (rule->ip_proto != 0 && rule->ip_proto != proto) {
        return 0;
    }

    if (rule->src_port_start != 0 || rule->dst_port_start != 0) {
        have_ports = mesh_packet_extract_ports(ip_packet, len, &src_port, &dst_port);
        if (!have_ports) {
            return 0;
        }
        if (rule->src_port_start != 0 &&
            (src_port < rule->src_port_start || src_port > rule->src_port_end)) {
            return 0;
        }
        if (rule->dst_port_start != 0 &&
            (dst_port < rule->dst_port_start || dst_port > rule->dst_port_end)) {
            return 0;
        }
    }

    return 1;
}

static int mesh_packet_policy_allows(mesh_network_t *mesh,
                                     uint32_t direction,
                                     const uint8_t *ip_packet,
                                     size_t len) {
    int direction_has_rules = 0;
    mesh_flow_decision_v1_t runtime_decision;
    mesh_flow_runtime_result_t runtime_result;

    if (!mesh || !ip_packet || len < 20) {
        return 0;
    }

    if (mesh->runtime_flow_policy.open) {
        runtime_result = mesh_flow_runtime_evaluate_ipv4_v1(
            &mesh->runtime_flow_policy, direction, ip_packet, len, NULL,
            &runtime_decision);
        if (runtime_result == MESH_FLOW_RUNTIME_OK) {
            return runtime_decision.action == MESH_FLOW_ACTION_ALLOW;
        }
        if (runtime_result != MESH_FLOW_RUNTIME_DISABLED) {
            return 0;
        }
    }

    if (!mesh->packet_policy_rules || mesh->packet_policy_rule_count <= 0) {
        return 1;
    }

    for (int i = 0; i < mesh->packet_policy_rule_count; i++) {
        const mesh_packet_policy_entry_t *rule = &mesh->packet_policy_rules[i];
        if (!(rule->directions & direction)) {
            continue;
        }
        direction_has_rules = 1;
        if (mesh_packet_policy_rule_matches(rule, direction, ip_packet, len)) {
            return rule->allow ? 1 : 0;
        }
    }

    return direction_has_rules ? 0 : 1;
}

static void mesh_connect_bootstrap_peers(mesh_network_t *mesh, int is_retry) {
    int ret = 0;

    if (!mesh || !mesh->bootstrap_peers || mesh->bootstrap_count <= 0) {
        return;
    }

    if (is_retry) {
        mesh->bootstrap_retry_rounds++;
        TLOG_INFO("Retrying {} bootstrap peer(s)...", mesh->bootstrap_count);
    } else {
        TLOG_INFO("Connecting to {} bootstrap peer(s)...", mesh->bootstrap_count);
    }

    for (int i = 0; i < mesh->bootstrap_count; i++) {
        const char *peer_addr = mesh->bootstrap_peers[i];
        char ip[64] = {0};
        int port = 9993;
        const char *colon = strchr(peer_addr, ':');

        if (colon) {
            size_t ip_len = (size_t)(colon - peer_addr);
            if (ip_len >= sizeof(ip)) {
                TLOG_WARN("Invalid bootstrap peer address: {}", peer_addr);
                continue;
            }
            memcpy(ip, peer_addr, ip_len);
            ip[ip_len] = '\0';
            port = atoi(colon + 1);
        } else {
            strncpy(ip, peer_addr, sizeof(ip) - 1);
        }

        TLOG_INFO("Connecting to bootstrap peer: {}:{}", ip, port);
        mesh->bootstrap_connect_attempts++;
        ret = p2p_connect(mesh->p2p_node, ip, port);
        if (ret != P2P_OK) {
            TLOG_WARN("Failed to connect to {}:{} (error {})", ip, port, ret);
        }
    }
}

static int mesh_create_p2p_node(mesh_network_t *mesh) {
    if (!mesh) {
        return MESH_ERR_INVALID_ARG;
    }

    mesh->p2p_node = p2p_create("0.0.0.0", mesh->listen_port);
    if (!mesh->p2p_node) {
        return MESH_ERR_NETWORK;
    }

    p2p_set_message_handler(mesh->p2p_node, mesh_on_p2p_message, mesh);
    p2p_set_peer_callbacks(mesh->p2p_node, mesh_on_p2p_peer_connected,
                           mesh_on_p2p_peer_disconnected, mesh);
    return MESH_OK;
}

static int mesh_register_virtual_ip(mesh_network_t *mesh) {
    char dht_key[128];
    char dht_value[256];
    char reverse_key[128];
    char reverse_value[64];
    const char *endpoint_ip = NULL;

    if (!mesh || !mesh->p2p_node) {
        return MESH_ERR_INVALID_ARG;
    }

    endpoint_ip = mesh->advertise_ip[0] ? mesh->advertise_ip : NULL;

    fmt(dht_key, sizeof(dht_key), "mesh:{}:ip:{}",
                   mesh->network_id, mesh->virtual_ip);
    if (mesh_ip_is_unspecified(endpoint_ip)) {
        fmt(dht_value, sizeof(dht_value), "{}", mesh->virtual_ip);
    } else {
        fmt(dht_value, sizeof(dht_value), "{}:{}",
                       endpoint_ip, mesh->listen_port);
    }
    p2p_dht_put_cached(mesh->p2p_node, dht_key, dht_value, strlen(dht_value) + 1);

    if (!mesh_ip_is_unspecified(endpoint_ip)) {
        fmt(reverse_key, sizeof(reverse_key), "mesh:{}:peer:{}:{}",
                       mesh->network_id, endpoint_ip, mesh->listen_port);
        fmt(reverse_value, sizeof(reverse_value), "{}", mesh->virtual_ip);
        p2p_dht_put_cached(mesh->p2p_node, reverse_key, reverse_value, strlen(reverse_value) + 1);
    }

    if (mesh_ip_is_unspecified(endpoint_ip)) {
        TLOG_INFO("Registered virtual IP {} in DHT without direct endpoint",
                  mesh->virtual_ip);
    } else {
        TLOG_INFO("Registered virtual IP {} -> {}:{} in DHT",
                  mesh->virtual_ip, endpoint_ip, mesh->listen_port);
    }
    mesh->virtual_ip_registered = 1;
    return MESH_OK;
}

static int mesh_ensure_virtual_ip_registered(mesh_network_t *mesh) {
    if (!mesh) {
        return MESH_ERR_INVALID_ARG;
    }

    if (mesh->virtual_ip_registered) {
        return MESH_OK;
    }

    if (mesh->bootstrap_count > 0 && !mesh_has_connected_peers(mesh)) {
        return MESH_ERR_NOT_FOUND;
    }

    return mesh_register_virtual_ip(mesh);
}

/* =============================================================================
 * Peer Management
 * ============================================================================= */

static mesh_peer_t *mesh_peer_create(mesh_network_t *mesh, p2p_peer_t *p2p_peer) {
    mesh_peer_t *peer = NULL;
    char real_ip[64];

    if (!mesh || !p2p_peer) return NULL;

    /* Get peer address */
    char peer_ip[64];
    int peer_port;
    int ret = p2p_peer_get_address(p2p_peer, peer_ip, &peer_port);
    if (ret != P2P_OK) {
        TLOG_ERROR("Failed to get peer address (error={})", ret);
        return NULL;
    }

    fmt(real_ip, sizeof(real_ip), "{}:{}", peer_ip, peer_port);

    peer = mesh_find_peer_by_p2p(mesh, p2p_peer);
    if (peer) {
        peer->is_connected = 1;
        peer->transport_authenticated = 1;
        return peer;
    }

    peer = mesh_find_peer_by_real(mesh, real_ip);
    if (peer) {
        TLOG_INFO("Reusing mesh peer for real endpoint: {}", real_ip);
        peer->p2p_peer = p2p_peer;
        peer->is_connected = 1;
        peer->transport_authenticated = 1;
        strncpy(peer->real_ip, real_ip, sizeof(peer->real_ip) - 1);
        peer->real_ip[sizeof(peer->real_ip) - 1] = '\0';
        return peer;
    }

    peer = (mesh_peer_t *)calloc(1, sizeof(mesh_peer_t));
    if (!peer) return NULL;

    TLOG_INFO("Creating mesh peer: {}:{}", peer_ip, peer_port);
    peer->mesh = mesh;

    /* Use P2P IP as placeholder - will be updated when HELLO message arrives */
    fmt(peer->virtual_ip, sizeof(peer->virtual_ip), "{}", peer_ip);
    strncpy(peer->real_ip, real_ip, sizeof(peer->real_ip) - 1);
    peer->real_ip[sizeof(peer->real_ip) - 1] = '\0';
    TLOG_DEBUG("Temporary virtual IP: {} (will be updated by HELLO)", peer->virtual_ip);

    peer->is_connected = 1;
    peer->transport_authenticated = 1;
    peer->p2p_peer = p2p_peer;

    /* Add to mesh peer list */
    peer->next = mesh->peers;
    mesh->peers = peer;
    mesh->peer_count++;

    return peer;
}

static mesh_peer_t *mesh_peer_create_virtual(mesh_network_t *mesh, const char *virtual_ip) {
    mesh_peer_t *peer = NULL;
    mesh_route_t *route = NULL;

    if (!mesh || !virtual_ip || virtual_ip[0] == '\0') {
        return NULL;
    }

    peer = (mesh_peer_t *)calloc(1, sizeof(mesh_peer_t));
    if (!peer) {
        return NULL;
    }

    peer->mesh = mesh;
    strncpy(peer->virtual_ip, virtual_ip, sizeof(peer->virtual_ip) - 1);
    route = mesh_route_find(mesh, virtual_ip);
    if (route && route->dest_real_ip[0] != '\0') {
        strncpy(peer->advertised_real_ip, route->dest_real_ip,
                sizeof(peer->advertised_real_ip) - 1);
        strncpy(peer->real_ip, route->dest_real_ip, sizeof(peer->real_ip) - 1);
    } else {
        fmt(peer->real_ip, sizeof(peer->real_ip), "relay:{}", virtual_ip);
    }

    peer->next = mesh->peers;
    mesh->peers = peer;
    mesh->peer_count++;
    return peer;
}

static void mesh_peer_destroy(mesh_peer_t *peer) {
    if (!peer) return;
    mesh_ice_destroy_peer(peer);
    free(peer);
}

static void mesh_peer_remove(mesh_network_t *mesh, mesh_peer_t *peer) {
    mesh_peer_t **prev = NULL;

    if (!mesh || !peer) {
        return;
    }

    mesh_route_delete_via_peer(mesh, peer);
    mesh_ice_quiesce_peer(peer);
    peer->ice_selected_io_running = 0;
    if (mesh->ice_ctx) {
        /*
         * ice_agent_close() tears down candidate sockets immediately. Give the
         * dedicated ICE context one short drain window here so UDP close
         * completions run before the retired peer becomes eligible for free.
         */
        mesh_ice_drain_context(mesh->ice_ctx, 10);
    }

    prev = &mesh->peers;
    while (*prev) {
        if (*prev == peer) {
            *prev = peer->next;
            mesh->peer_count--;
            peer->p2p_peer = NULL;
            peer->is_connected = 0;
            peer->announced = 0;
            peer->transport_authenticated = 0;
            peer->negotiated_capabilities = 0;
            peer->next = mesh->retired_peers;
            mesh->retired_peers = peer;
            return;
        }
        prev = &(*prev)->next;
    }
}

static mesh_peer_t *mesh_find_peer_internal(mesh_network_t *mesh, const char *virtual_ip) {
    mesh_peer_t *peer = mesh->peers;
    while (peer) {
        if (peer->announced &&
            peer->is_connected &&
            strcmp(peer->virtual_ip, virtual_ip) == 0) {
            return peer;
        }
        peer = peer->next;
    }
    return NULL;
}

static mesh_peer_t *mesh_find_peer_by_p2p(mesh_network_t *mesh, p2p_peer_t *p2p_peer) {
    mesh_peer_t *peer = NULL;

    if (!mesh || !p2p_peer) {
        return NULL;
    }

    peer = mesh->peers;
    while (peer) {
        if (peer->p2p_peer == p2p_peer) {
            return peer;
        }
        peer = peer->next;
    }
    return NULL;
}

static mesh_peer_t *mesh_find_peer_by_real(mesh_network_t *mesh, const char *real_ip) {
    mesh_peer_t *peer = NULL;

    if (!mesh || !real_ip) {
        return NULL;
    }

    peer = mesh->peers;
    while (peer) {
        if (strcmp(peer->real_ip, real_ip) == 0) {
            return peer;
        }
        peer = peer->next;
    }
    return NULL;
}

static mesh_peer_t *mesh_find_peer_by_endpoint(mesh_network_t *mesh, const char *endpoint) {
    mesh_peer_t *peer = NULL;

    if (!mesh || !endpoint || endpoint[0] == '\0') {
        return NULL;
    }

    peer = mesh->peers;
    while (peer) {
        if (strcmp(peer->real_ip, endpoint) == 0 ||
            strcmp(peer->advertised_real_ip, endpoint) == 0) {
            return peer;
        }
        peer = peer->next;
    }

    return NULL;
}

static mesh_peer_t *mesh_find_peer_any_virtual(mesh_network_t *mesh, const char *virtual_ip) {
    mesh_peer_t *peer = NULL;

    if (!mesh || !virtual_ip) {
        return NULL;
    }

    peer = mesh->peers;
    while (peer) {
        if (strcmp(peer->virtual_ip, virtual_ip) == 0) {
            return peer;
        }
        peer = peer->next;
    }

    return NULL;
}

static mesh_peer_t *mesh_find_peer_by_virtual_except(mesh_network_t *mesh,
                                                     const char *virtual_ip,
                                                     mesh_peer_t *skip) {
    mesh_peer_t *peer = NULL;

    if (!mesh || !virtual_ip) {
        return NULL;
    }

    peer = mesh->peers;
    while (peer) {
        if (peer != skip &&
            peer->announced &&
            peer->is_connected &&
            strcmp(peer->virtual_ip, virtual_ip) == 0) {
            return peer;
        }
        peer = peer->next;
    }
    return NULL;
}

static int mesh_peer_has_inflight_ice(const mesh_peer_t *peer) {
    if (!peer) {
        return 0;
    }

    return peer->ice_agent != NULL ||
           peer->ice_checks_started ||
           peer->ice_checks_running ||
           peer->ice_selected_io_running;
}

/* =============================================================================
 * Routing Table Management
 * ============================================================================= */

static mesh_route_t *mesh_route_create(const char *dest_ip, mesh_peer_t *next_hop,
                                       uint8_t hop_count, const char *dest_real_ip) {
    mesh_route_t *route = (mesh_route_t *)calloc(1, sizeof(mesh_route_t));
    uint64_t now_ms = 0;

    if (!route) return NULL;

    now_ms = mesh_now_ms();
    strncpy(route->dest_ip, dest_ip, sizeof(route->dest_ip) - 1);
    if (dest_real_ip) {
        strncpy(route->dest_real_ip, dest_real_ip, sizeof(route->dest_real_ip) - 1);
    }
    route->next_hop = next_hop;
    if (next_hop) {
        strncpy(route->next_hop_virtual_ip, next_hop->virtual_ip,
                sizeof(route->next_hop_virtual_ip) - 1);
    }
    route->hop_count = hop_count;
    route->source = MESH_ROUTE_SOURCE_LEARNED;
    route->last_update_ms = now_ms;
    route->expires_at_ms = now_ms + MESH_LEARNED_ROUTE_TTL_MS;

    return route;
}

static void mesh_route_destroy(mesh_route_t *route) {
    if (!route) return;
    free(route);
}

static mesh_route_t *mesh_route_find(mesh_network_t *mesh, const char *dest_ip) {
    mesh_route_t *route = NULL;

    mesh_route_expire_stale(mesh);
    route = mesh->routes;
    while (route) {
        if (strcmp(route->dest_ip, dest_ip) == 0) {
            return route;
        }
        route = route->next;
    }
    return NULL;
}

static int mesh_route_is_expired(const mesh_route_t *route, uint64_t now_ms) {
    return route && route->expires_at_ms != 0 && route->expires_at_ms <= now_ms;
}

static void mesh_route_expire_stale(mesh_network_t *mesh) {
    mesh_route_t **prev = NULL;
    mesh_route_t *route = NULL;
    uint64_t now_ms = 0;

    if (!mesh) {
        return;
    }

    now_ms = mesh_now_ms();
    prev = &mesh->routes;
    route = mesh->routes;
    while (route) {
        if (mesh_route_is_expired(route, now_ms)) {
            mesh_route_t *to_delete = route;
            *prev = route->next;
            route = route->next;
            mesh_route_destroy(to_delete);
            mesh->route_count--;
            continue;
        }

        prev = &route->next;
        route = route->next;
    }
}

static const mesh_route_rule_entry_t *mesh_route_rule_find(mesh_network_t *mesh, uint32_t dst_ip) {
    const mesh_route_rule_entry_t *best = NULL;
    int i = 0;

    if (!mesh || !mesh->route_rules || mesh->route_rule_count <= 0) {
        return NULL;
    }

    for (i = 0; i < mesh->route_rule_count; i++) {
        const mesh_route_rule_entry_t *rule = &mesh->route_rules[i];

        if ((dst_ip & rule->mask) != rule->network_ip) {
            continue;
        }

        if (!best || rule->prefix_len > best->prefix_len) {
            best = rule;
        }
    }

    return best;
}

static mesh_peer_t *mesh_route_rule_next_hop_find(mesh_network_t *mesh,
                                                  const mesh_route_rule_entry_t *rule) {
    if (!mesh || !rule) {
        return NULL;
    }

    return mesh_find_peer_internal(mesh, rule->next_hop_virtual_ip);
}

static const mesh_local_egress_entry_t *mesh_local_egress_find(mesh_network_t *mesh,
                                                               uint32_t dst_ip) {
    const mesh_local_egress_entry_t *best = NULL;
    int i = 0;

    if (!mesh || !mesh->local_egress_cidrs || mesh->local_egress_count <= 0) {
        return NULL;
    }

    for (i = 0; i < mesh->local_egress_count; i++) {
        const mesh_local_egress_entry_t *entry = &mesh->local_egress_cidrs[i];

        if ((dst_ip & entry->mask) != entry->network_ip) {
            continue;
        }

        if (!best || entry->prefix_len > best->prefix_len) {
            best = entry;
        }
    }

    return best;
}

static int mesh_parse_endpoint(const char *endpoint, char *ip, size_t ip_len, int *port) {
    if (!endpoint || !ip || ip_len == 0 || !port) {
        return 0;
    }

    if (sscanf(endpoint, "%63[^:]:%d", ip, port) != 2 || *port <= 0) {
        return 0;
    }

    return 1;
}

static int mesh_endpoint_is_routable(const char *endpoint) {
    char ip[64] = {0};
    int port = 0;

    if (!mesh_parse_endpoint(endpoint, ip, sizeof(ip), &port)) {
        return 0;
    }

    return !mesh_ip_is_unspecified(ip);
}

static void mesh_ice_update_last_state(mesh_peer_t *peer, const char *state_name) {
    mesh_network_t *mesh = NULL;

    if (!peer || !peer->mesh || !state_name) {
        return;
    }

    mesh = peer->mesh;
    strncpy(peer->ice_state, state_name, sizeof(peer->ice_state) - 1);
    strncpy(mesh->last_ice_state, state_name, sizeof(mesh->last_ice_state) - 1);
}

static void mesh_ice_send_auth(mesh_peer_t *peer) {
    char msg[224];
    mesh_network_t *mesh = NULL;

    if (!peer || !peer->mesh || !peer->ice_agent || peer->ice_auth_sent) {
        return;
    }

    mesh = peer->mesh;
    fmt(msg, sizeof(msg), "MESH_ICE_AUTH:{}:{}:{}:caps={:08x}",
                   mesh->virtual_ip, peer->ice_local_ufrag, peer->ice_local_pwd,
                   mesh_local_capabilities(mesh));
    if (mesh_send_control_message(mesh, peer->virtual_ip, msg) == MESH_OK) {
        peer->ice_auth_sent = 1;
        mesh->ice_auth_messages_tx++;
    }
}

static void mesh_ice_send_end_of_candidates(mesh_peer_t *peer) {
    char msg[64];
    mesh_network_t *mesh = NULL;

    if (!peer || !peer->mesh || !peer->ice_agent ||
        peer->ice_end_of_candidates_sent) {
        return;
    }

    mesh = peer->mesh;
    fmt(msg, sizeof(msg), "MESH_ICE_EOC:{}", mesh->virtual_ip);
    if (mesh_send_control_message(mesh, peer->virtual_ip, msg) == MESH_OK) {
        peer->ice_end_of_candidates_sent = 1;
        mesh->ice_end_of_candidates_tx++;
    }
}

static int mesh_ice_can_gather_inline(const mesh_network_t *mesh) {
    if (!mesh) {
        return 0;
    }

    /*
     * Host-candidate gather is fully synchronous. Running it on the main mesh
     * thread avoids pushing getifaddrs()/socket setup through a small fiber
     * stack in ASAN/debug runs. STUN/TURN gather still needs the coroutine
     * path because it performs coro_socket I/O.
     */
    return mesh->ice_stun_count == 0;
}

static void mesh_ice_drain_context(coro_context_t *ctx, uint64_t drain_ms) {
    uint64_t deadline_ms = 0;

    if (!ctx || drain_ms == 0) {
        return;
    }

    deadline_ms = mesh_now_ms() + drain_ms;
    do {
        coro_context_run(ctx, TURBO_RUN_ONCE);
        if (!coro_context_alive(ctx)) {
            break;
        }
        turbo_sleep_ms(1);
    } while (mesh_now_ms() < deadline_ms);
}

static void mesh_ice_maybe_start_checks(mesh_peer_t *peer) {
    coro_context_t *ctx = NULL;

    if (peer) {
        mesh_ice_tracef("mesh_ice_maybe_start_checks peer=%s real=%s started=%d gather=%d creds=%d remote=%d eoc=%d",
                        peer->virtual_ip, peer->real_ip, peer->ice_checks_started,
                        peer->ice_gathering_complete, peer->ice_remote_credentials_set,
                        peer->ice_remote_candidate_count, peer->ice_remote_end_of_candidates);
    }

    if (!peer || !peer->ice_agent || peer->ice_checks_started ||
        !peer->ice_gathering_complete || !peer->ice_remote_credentials_set ||
        peer->ice_remote_candidate_count == 0 ||
        !peer->ice_remote_end_of_candidates) {
        return;
    }

    ctx = peer->mesh->ice_ctx;
    if (!ctx) {
        return;
    }

    peer->ice_check_start_local_candidate_count = peer->ice_local_candidate_count;
    peer->ice_check_start_remote_candidate_count = peer->ice_remote_candidate_count;
    peer->mesh->ice_checks_started++;
    peer->mesh->ice_last_check_local_candidate_count = (uint32_t)peer->ice_local_candidate_count;
    peer->mesh->ice_last_check_remote_candidate_count = (uint32_t)peer->ice_remote_candidate_count;
    peer->ice_checks_started = 1;
    peer->ice_checks_running = 1;
    if (coro_context_spawn(ctx, mesh_ice_checks_task, peer) != 0) {
        peer->ice_checks_started = 0;
        peer->ice_checks_running = 0;
        TLOG_WARN("Failed to spawn ICE checks for {}", peer->real_ip);
    }
}

static void mesh_ice_on_state_changed(turbo_ice_agent_t *agent, ice_state_t old_state,
                                      ice_state_t new_state, void *user_data) {
    mesh_peer_t *peer = (mesh_peer_t *)user_data;
    coro_context_t *ctx = NULL;
    ice_candidate_t local;
    ice_candidate_t remote;
    char local_endpoint[64] = {0};
    char remote_endpoint[64] = {0};
    (void)agent;
    (void)old_state;

    if (!peer || !peer->mesh) {
        return;
    }

    mesh_ice_update_last_state(peer, ice_state_name(new_state));
    if ((new_state == ICE_STATE_CONNECTED || new_state == ICE_STATE_COMPLETED) &&
        ice_agent_get_selected_pair(peer->ice_agent, &local, &remote) == 0) {
        fmt(local_endpoint, sizeof(local_endpoint), "{}:{}",
                       local.ip, (unsigned)local.port);
        fmt(remote_endpoint, sizeof(remote_endpoint), "{}:{}",
                       remote.ip, (unsigned)remote.port);
        strncpy(peer->ice_selected_local_endpoint, local_endpoint,
                sizeof(peer->ice_selected_local_endpoint) - 1);
        strncpy(peer->ice_selected_remote_endpoint, remote_endpoint,
                sizeof(peer->ice_selected_remote_endpoint) - 1);
        strncpy(peer->mesh->last_ice_selected_local_endpoint, local_endpoint,
                sizeof(peer->mesh->last_ice_selected_local_endpoint) - 1);
        strncpy(peer->mesh->last_ice_selected_remote_endpoint, remote_endpoint,
                sizeof(peer->mesh->last_ice_selected_remote_endpoint) - 1);
        if (!peer->p2p_peer) {
            strncpy(peer->real_ip, remote_endpoint, sizeof(peer->real_ip) - 1);
            strncpy(peer->advertised_real_ip, remote_endpoint,
                    sizeof(peer->advertised_real_ip) - 1);
            if (!peer->is_connected) {
                peer->is_connected = 1;
            }
            if (!peer->announced) {
                peer->announced = 1;
                if (peer->mesh->on_peer_connected) {
                    peer->mesh->on_peer_connected(peer, peer->mesh->user_data);
                }
            }
        }
        TLOG_INFO("ICE selected pair for {} local={} remote={}",
                  peer->real_ip, local_endpoint, remote_endpoint);
        ctx = peer->mesh->ice_ctx;
        if (ctx && !peer->ice_selected_io_running) {
            peer->ice_selected_io_running = 1;
            if (coro_context_spawn(ctx, mesh_ice_selected_io_task, peer) != 0) {
                peer->ice_selected_io_running = 0;
                TLOG_WARN("Failed to spawn ICE selected I/O for {}", peer->real_ip);
            }
        }

    } else if (new_state == ICE_STATE_FAILED || new_state == ICE_STATE_DISCONNECTED ||
               new_state == ICE_STATE_CLOSED) {
        peer->ice_selected_io_running = 0;
        if (!peer->p2p_peer) {
            peer->is_connected = 0;
            peer->announced = 0;
        }
    }
}

static void mesh_ice_on_gathering_changed(turbo_ice_agent_t *agent,
                                          ice_gathering_state_t state,
                                          void *user_data) {
    mesh_peer_t *peer = (mesh_peer_t *)user_data;
    (void)agent;

    if (!peer) {
        return;
    }

    if (state == ICE_GATHERING_COMPLETE) {
        peer->ice_gathering_complete = 1;
        mesh_ice_tracef("mesh_ice_on_gathering_changed peer=%s real=%s state=complete",
                        peer->virtual_ip, peer->real_ip);
        mesh_ice_send_end_of_candidates(peer);
        mesh_ice_maybe_start_checks(peer);
    }
}

static void mesh_ice_on_candidate_discovered(turbo_ice_agent_t *agent,
                                             const ice_candidate_t *candidate,
                                             void *user_data) {
    mesh_peer_t *peer = (mesh_peer_t *)user_data;
    char candidate_sdp[512];
    char msg[640];
    int len = 0;
    (void)agent;

    if (!peer || !peer->mesh || !candidate) {
        return;
    }

    len = ice_candidate_to_sdp(candidate, candidate_sdp, sizeof(candidate_sdp));
    if (len <= 0) {
        return;
    }

    peer->ice_local_candidate_count++;
    fmt(msg, sizeof(msg), "MESH_ICE_CANDIDATE:{}:{}",
                   peer->mesh->virtual_ip, candidate_sdp);
    if (mesh_send_control_message(peer->mesh, peer->virtual_ip, msg) == MESH_OK) {
        peer->mesh->ice_candidate_messages_tx++;
    }
}

static void mesh_ice_on_data_received(turbo_ice_agent_t *agent, const void *data,
                                      size_t len, void *user_data) {
    mesh_peer_t *peer = (mesh_peer_t *)user_data;
    (void)agent;

    if (!peer || !peer->mesh || !data || len == 0) {
        return;
    }

    if (!mesh_peer_has_capability(peer, MESH_CAP_SELECTED_PAIR_IP)) {
        TLOG_DEBUG("Dropping ICE selected-pair payload from {} without negotiated capability",
                   peer->virtual_ip);
        return;
    }

    mesh_handle_ip_packet(peer->mesh, peer, (const uint8_t *)data, len);
}

static void mesh_ice_gather_task(coro_t *co, void *arg) {
    mesh_peer_t *peer = (mesh_peer_t *)arg;
    (void)co;

    if (!peer || !peer->ice_agent) {
        return;
    }

    if (ice_agent_gather_candidates(peer->ice_agent) != 0) {
        TLOG_WARN("ICE gather failed for {}", peer->real_ip);
    }
}

static void mesh_ice_checks_task(coro_t *co, void *arg) {
    mesh_peer_t *peer = (mesh_peer_t *)arg;
    (void)co;

    if (!peer || !peer->ice_agent) {
        return;
    }

    if (ice_agent_start_checks(peer->ice_agent) != 0) {
        peer->ice_checks_started = 0;
        peer->ice_checks_running = 0;
        TLOG_WARN("ICE checks failed for {}", peer->real_ip);
        return;
    }

    peer->ice_checks_running = 0;
}

static void mesh_ice_selected_io_task(coro_t *co, void *arg) {
    mesh_peer_t *peer = (mesh_peer_t *)arg;
    (void)co;

    if (!peer) {
        return;
    }

    while (peer->ice_selected_io_running) {
        if (!peer->ice_agent || !mesh_peer_has_active_ice_path(peer)) {
            break;
        }

        ice_agent_poll_selected_pair(peer->ice_agent, 1);
        coro_yield();
    }

    peer->ice_selected_io_running = 0;
}

static void mesh_ice_init_peer(mesh_network_t *mesh, mesh_peer_t *peer) {
    ice_config_t config;
    ice_callbacks_t callbacks;
    coro_context_t *ctx = NULL;
    int stun_count = 0;

    if (!mesh || !peer || !mesh->ice_enabled || peer->ice_agent) {
        return;
    }

    ctx = mesh->ice_ctx;
    if (!ctx) {
        return;
    }

    config = ice_default_config();
    config.is_controlling = strcmp(mesh->virtual_ip, peer->virtual_ip) < 0 ? 1 : 0;
    config.allow_loopback = mesh->ice_allow_loopback ? 1 : 0;
    /*
     * mesh currently uses ICE as direct-path control-plane groundwork, not as
     * the primary packet transport. Keep checks short so teardown does not sit
     * on a 12s connectivity loop when the process is stopping.
     */
    config.connectivity_timeout_ms = MESH_ICE_CONNECTIVITY_TIMEOUT_MS;
    stun_count = mesh->ice_stun_count > ICE_MAX_STUN_SERVERS
               ? ICE_MAX_STUN_SERVERS
               : mesh->ice_stun_count;
    config.stun_server_count = stun_count;
    for (int i = 0; i < stun_count; i++) {
        strncpy(config.stun_servers[i].url, mesh->ice_stun_servers[i],
                sizeof(config.stun_servers[i].url) - 1);
    }

    peer->ice_agent = ice_agent_create(ctx, &config);
    if (!peer->ice_agent) {
        TLOG_WARN("Failed to create ICE agent for {}", peer->real_ip);
        return;
    }

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.on_state_change = mesh_ice_on_state_changed;
    callbacks.on_gathering_change = mesh_ice_on_gathering_changed;
    callbacks.on_candidate = mesh_ice_on_candidate_discovered;
    callbacks.on_data = mesh_ice_on_data_received;
    callbacks.user_data = peer;
    ice_agent_set_callbacks(peer->ice_agent, &callbacks);
    ice_agent_set_allow_loopback(peer->ice_agent, mesh->ice_allow_loopback ? 1 : 0);
    ice_agent_get_local_credentials(peer->ice_agent,
                                    peer->ice_local_ufrag, sizeof(peer->ice_local_ufrag),
                                    peer->ice_local_pwd, sizeof(peer->ice_local_pwd));
    mesh_ice_update_last_state(peer, ice_state_name(ice_agent_get_state(peer->ice_agent)));
    mesh_ice_send_auth(peer);
    if (mesh_ice_can_gather_inline(mesh)) {
        mesh_ice_gather_task(NULL, peer);
        return;
    }
    if (coro_context_spawn(ctx, mesh_ice_gather_task, peer) != 0) {
        TLOG_WARN("Failed to spawn ICE gather for {}", peer->real_ip);
    }
}

static void mesh_ice_quiesce_peer(mesh_peer_t *peer) {
    ice_callbacks_t callbacks;

    if (!peer || !peer->ice_agent) {
        return;
    }

    peer->ice_selected_io_running = 0;

    /* Close first so the state machine stops scheduling work while its context drains. */
    ice_agent_close(peer->ice_agent);
    memset(&callbacks, 0, sizeof(callbacks));
    ice_agent_set_callbacks(peer->ice_agent, &callbacks);
}

static void mesh_ice_reset_peer_state(mesh_peer_t *peer) {
    if (!peer) {
        return;
    }

    memset(peer->ice_local_ufrag, 0, sizeof(peer->ice_local_ufrag));
    memset(peer->ice_local_pwd, 0, sizeof(peer->ice_local_pwd));
    memset(peer->ice_remote_ufrag, 0, sizeof(peer->ice_remote_ufrag));
    memset(peer->ice_remote_pwd, 0, sizeof(peer->ice_remote_pwd));
    peer->ice_remote_credentials_set = 0;
    peer->ice_gathering_complete = 0;
    peer->ice_checks_started = 0;
    peer->ice_checks_running = 0;
    peer->ice_selected_io_running = 0;
    peer->ice_local_candidate_count = 0;
    peer->ice_remote_candidate_count = 0;
    peer->ice_auth_sent = 0;
    peer->ice_end_of_candidates_sent = 0;
    peer->ice_remote_end_of_candidates = 0;
    peer->ice_check_start_local_candidate_count = 0;
    peer->ice_check_start_remote_candidate_count = 0;
    memset(peer->ice_state, 0, sizeof(peer->ice_state));
    memset(peer->ice_selected_local_endpoint, 0, sizeof(peer->ice_selected_local_endpoint));
    memset(peer->ice_selected_remote_endpoint, 0, sizeof(peer->ice_selected_remote_endpoint));
}

static void mesh_ice_destroy_peer(mesh_peer_t *peer) {
    if (!peer) {
        return;
    }
    if (!peer->ice_agent) {
        mesh_ice_reset_peer_state(peer);
        return;
    }

    mesh_ice_quiesce_peer(peer);
    if (peer->mesh && peer->mesh->ice_ctx) {
        /*
         * ice_agent_close() flips the public state to CLOSED immediately, but
         * the checks coroutine can still be unwinding on ice_ctx. Drain the
         * dedicated ICE context unconditionally before freeing the agent.
         */
        uint64_t deadline_ms = mesh_now_ms() + MESH_ICE_SHUTDOWN_DRAIN_MS;
        do {
            mesh_ice_drain_context(peer->mesh->ice_ctx, 1);
            if (!peer->ice_checks_running &&
                !peer->ice_selected_io_running &&
                ice_agent_get_gathering_state(peer->ice_agent) != ICE_GATHERING_GATHERING) {
                break;
            }
        } while (mesh_now_ms() < deadline_ms);
    }
    ice_agent_destroy(peer->ice_agent);
    peer->ice_agent = NULL;
    mesh_ice_reset_peer_state(peer);
}

static void mesh_ice_handle_auth(mesh_peer_t *peer, const char *payload) {
    char virtual_ip[16] = {0};
    char ufrag[32] = {0};
    char pwd[64] = {0};
    unsigned long capabilities = 0;
    int parsed = 0;

    if (!peer || !peer->mesh || !peer->ice_agent || !payload) {
        return;
    }

    parsed = sscanf(payload, "%15[^:]:%31[^:]:%63[^:]:caps=%lx",
                    virtual_ip, ufrag, pwd, &capabilities);
    if (parsed < 3) {
        return;
    }
    if (parsed == 4 && capabilities <= UINT32_MAX) {
        peer->capabilities = (uint32_t)capabilities;
        mesh_peer_refresh_negotiated_capabilities(peer);
    }

    strncpy(peer->ice_remote_ufrag, ufrag, sizeof(peer->ice_remote_ufrag) - 1);
    strncpy(peer->ice_remote_pwd, pwd, sizeof(peer->ice_remote_pwd) - 1);
    peer->ice_remote_credentials_set = 1;
    peer->mesh->ice_auth_messages_rx++;
    if (ice_agent_set_remote_credentials(peer->ice_agent, ufrag, pwd) == 0) {
        mesh_ice_tracef("mesh_ice_handle_auth peer=%s real=%s", peer->virtual_ip, peer->real_ip);
        mesh_ice_maybe_start_checks(peer);
    }
}

static void mesh_ice_handle_candidate(mesh_peer_t *peer, const char *candidate_sdp) {
    if (!peer || !peer->mesh || !peer->ice_agent || !candidate_sdp || candidate_sdp[0] == '\0') {
        return;
    }

    if (ice_agent_add_remote_candidate(peer->ice_agent, candidate_sdp) == 0) {
        peer->ice_remote_candidate_count++;
        peer->mesh->ice_candidate_messages_rx++;
        mesh_ice_tracef("mesh_ice_handle_candidate peer=%s real=%s remote=%d",
                        peer->virtual_ip, peer->real_ip, peer->ice_remote_candidate_count);
        mesh_ice_maybe_start_checks(peer);
    }
}

static void mesh_ice_handle_end_of_candidates(mesh_peer_t *peer) {
    if (!peer || !peer->ice_agent) {
        return;
    }

    peer->ice_remote_end_of_candidates = 1;
    peer->mesh->ice_end_of_candidates_rx++;
    ice_agent_end_of_candidates(peer->ice_agent);
    mesh_ice_tracef("mesh_ice_handle_end_of_candidates peer=%s real=%s remote=%d",
                    peer->virtual_ip, peer->real_ip, peer->ice_remote_candidate_count);
    mesh_ice_maybe_start_checks(peer);
}

static int mesh_ice_has_pending_work(mesh_network_t *mesh) {
    mesh_peer_t *peer = NULL;

    if (!mesh) {
        return 0;
    }

    peer = mesh->peers;
    while (peer) {
        if (mesh_ice_agent_has_pending_work(peer->ice_agent)) {
            return 1;
        }
        peer = peer->next;
    }

    peer = mesh->retired_peers;
    while (peer) {
        if (mesh_ice_agent_has_pending_work(peer->ice_agent)) {
            return 1;
        }
        peer = peer->next;
    }

    return 0;
}

static void mesh_cleanup_retired_peers(mesh_network_t *mesh) {
    mesh_peer_t **current = NULL;
    int destroyed_peer = 0;

    if (!mesh) {
        return;
    }

    current = &mesh->retired_peers;
    while (*current) {
        mesh_peer_t *peer = *current;
        int keep = 0;

        if (peer->p2p_peer != NULL) {
            keep = 1;
        }
        else if (mesh_ice_agent_has_pending_work(peer->ice_agent)) {
            keep = 1;
        }

        if (keep) {
            current = &peer->next;
            continue;
        }

        *current = peer->next;
        peer->next = NULL;
        mesh_peer_destroy(peer);
        destroyed_peer = 1;
    }

    if (destroyed_peer && mesh->ice_ctx) {
        mesh_ice_drain_context(mesh->ice_ctx, 1);
    }
}

static void mesh_ice_shutdown_all(mesh_network_t *mesh) {
    mesh_peer_t *peer = NULL;

    if (!mesh || !mesh->ice_ctx) {
        return;
    }

    peer = mesh->peers;
    while (peer) {
        mesh_ice_quiesce_peer(peer);
        peer = peer->next;
    }

    peer = mesh->retired_peers;
    while (peer) {
        mesh_ice_quiesce_peer(peer);
        peer = peer->next;
    }

    if (mesh_ice_has_pending_work(mesh)) {
        mesh_ice_drain_context(mesh->ice_ctx, MESH_ICE_SHUTDOWN_DRAIN_MS);
    }
}

static int mesh_try_direct_connect(mesh_network_t *mesh, const char *virtual_ip,
                                   const char *endpoint, int force) {
    char endpoint_ip[64] = {0};
    int endpoint_port = 0;
    mesh_route_t *route = NULL;
    mesh_peer_t *direct_peer = NULL;
    mesh_peer_t *endpoint_peer = NULL;
    uint64_t now_ms = 0;

    if (!mesh || !virtual_ip || !mesh_parse_endpoint(endpoint, endpoint_ip,
                                                     sizeof(endpoint_ip), &endpoint_port)) {
        return 0;
    }
    if (mesh_ip_is_unspecified(endpoint_ip)) {
        return 0;
    }

    if (strcmp(virtual_ip, mesh->virtual_ip) == 0) {
        return 0;
    }
    if (!mesh_policy_allows_virtual_ip(mesh, MESH_POLICY_DIRECT_CONNECT, virtual_ip)) {
        return 0;
    }

    direct_peer = mesh_find_peer_any_virtual(mesh, virtual_ip);
    if (direct_peer &&
        (direct_peer->is_connected || direct_peer->p2p_peer ||
         mesh_peer_has_inflight_ice(direct_peer))) {
        return 0;
    }

    endpoint_peer = mesh_find_peer_by_endpoint(mesh, endpoint);
    if (endpoint_peer &&
        (endpoint_peer->is_connected || endpoint_peer->p2p_peer ||
         mesh_peer_has_inflight_ice(endpoint_peer))) {
        return 0;
    }

    route = mesh_route_find(mesh, virtual_ip);
    now_ms = mesh_now_ms();
    if (!force && route && route->direct_connect_after_ms > now_ms) {
        return 0;
    }

    if (route) {
        route->direct_connect_after_ms = now_ms + 5000;
    }

    strncpy(mesh->last_direct_attempt_endpoint, endpoint,
            sizeof(mesh->last_direct_attempt_endpoint) - 1);
    mesh->direct_connect_attempts++;
    TLOG_INFO("Attempting direct mesh connect to {} via {}:{}", virtual_ip,
              endpoint_ip, endpoint_port);
    if (p2p_connect(mesh->p2p_node, endpoint_ip, endpoint_port) == P2P_OK) {
        mesh->direct_connect_started++;
        return 1;
    }

    return 0;
}

static int mesh_try_routed_ice_connect(mesh_network_t *mesh, const char *virtual_ip, int force) {
    mesh_route_t *route = NULL;
    mesh_peer_t *peer = NULL;
    uint64_t now_ms = 0;
    ice_state_t state;

    if (!mesh || !mesh->ice_enabled || !virtual_ip || virtual_ip[0] == '\0') {
        return 0;
    }

    if (strcmp(virtual_ip, mesh->virtual_ip) == 0) {
        return 0;
    }
    if (!mesh_policy_allows_virtual_ip(mesh, MESH_POLICY_DIRECT_CONNECT, virtual_ip)) {
        return 0;
    }

    if (mesh_find_peer_internal(mesh, virtual_ip)) {
        return 0;
    }

    route = mesh_route_find(mesh, virtual_ip);
    if (!route || !route->next_hop || !route->next_hop->is_connected) {
        return 0;
    }

    now_ms = mesh_now_ms();
    if (!force && route->direct_connect_after_ms > now_ms) {
        return 0;
    }
    route->direct_connect_after_ms = now_ms + 5000;

    peer = mesh_find_or_create_signal_peer(mesh, NULL, virtual_ip);
    if (!peer) {
        return 0;
    }

    if (peer->ice_agent) {
        state = ice_agent_get_state(peer->ice_agent);
        if (state == ICE_STATE_FAILED || state == ICE_STATE_DISCONNECTED ||
            state == ICE_STATE_CLOSED) {
            mesh_ice_destroy_peer(peer);
            peer->ice_remote_credentials_set = 0;
            peer->ice_gathering_complete = 0;
            peer->ice_checks_started = 0;
            peer->ice_checks_running = 0;
            peer->ice_selected_io_running = 0;
            peer->ice_local_candidate_count = 0;
            peer->ice_remote_candidate_count = 0;
            peer->ice_auth_sent = 0;
            peer->ice_end_of_candidates_sent = 0;
            peer->ice_remote_end_of_candidates = 0;
            peer->ice_check_start_local_candidate_count = 0;
            peer->ice_check_start_remote_candidate_count = 0;
            peer->ice_local_ufrag[0] = '\0';
            peer->ice_local_pwd[0] = '\0';
            peer->ice_remote_ufrag[0] = '\0';
            peer->ice_remote_pwd[0] = '\0';
            peer->ice_state[0] = '\0';
            peer->ice_selected_local_endpoint[0] = '\0';
            peer->ice_selected_remote_endpoint[0] = '\0';
        }
    }

    if (peer->ice_agent || peer->ice_checks_started || peer->ice_selected_io_running ||
        peer->is_connected) {
        return 0;
    }

    mesh->direct_connect_attempts++;
    strncpy(mesh->last_direct_attempt_endpoint, route->dest_real_ip,
            sizeof(mesh->last_direct_attempt_endpoint) - 1);
    TLOG_INFO("Attempting routed ICE direct path to {} via relay {}",
              virtual_ip, route->next_hop->virtual_ip);
    mesh_ice_init_peer(mesh, peer);
    mesh->direct_connect_started++;
    return 1;
}

static int mesh_has_connected_peers(mesh_network_t *mesh) {
    mesh_peer_t *peer = NULL;

    if (!mesh) {
        return 0;
    }

    peer = mesh->peers;
    while (peer) {
        if (peer->is_connected) {
            return 1;
        }
        peer = peer->next;
    }

    return 0;
}

static void mesh_schedule_control_plane_refresh(mesh_network_t *mesh,
                                                int reconnect_bootstrap,
                                                const char *reason) {
    if (!mesh) {
        return;
    }

    mesh->control_plane_dirty = 1;
    if (reconnect_bootstrap) {
        mesh->bootstrap_reconnect_scheduled++;
        mesh->bootstrap_reconnect_pending = 1;
        if (reason && reason[0] != '\0') {
            strncpy(mesh->last_reconnect_reason, reason,
                    sizeof(mesh->last_reconnect_reason) - 1);
        }
    }
}

static void mesh_note_active_relay_next_hop(mesh_network_t *mesh, mesh_peer_t *next_hop) {
    if (!mesh || !next_hop) {
        return;
    }

    strncpy(mesh->last_active_relay_next_hop_virtual_ip, next_hop->virtual_ip,
            sizeof(mesh->last_active_relay_next_hop_virtual_ip) - 1);
    strncpy(mesh->last_active_relay_next_hop_real_ip, next_hop->real_ip,
            sizeof(mesh->last_active_relay_next_hop_real_ip) - 1);
}

static mesh_path_mode_t mesh_get_path_mode_internal(mesh_network_t *mesh) {
    mesh_peer_t *peer = NULL;
    mesh_route_t *route = NULL;
    int direct_count = 0;
    int relay_count = 0;

    if (!mesh) {
        return MESH_PATH_MODE_ISOLATED;
    }

    peer = mesh->peers;
    while (peer) {
        if (peer->announced && peer->is_connected) {
            direct_count++;
        }
        peer = peer->next;
    }

    route = mesh->routes;
    while (route) {
        if (route->next_hop && route->next_hop->is_connected) {
            relay_count++;
        }
        route = route->next;
    }

    if (direct_count > 0 && relay_count > 0) {
        return MESH_PATH_MODE_HYBRID;
    }

    if (direct_count > 0) {
        return MESH_PATH_MODE_DIRECT_ONLY;
    }

    if (relay_count > 0) {
        return MESH_PATH_MODE_RELAY_ONLY;
    }

    return MESH_PATH_MODE_ISOLATED;
}

static const mesh_route_rule_entry_t *mesh_control_route_match(mesh_network_t *mesh,
                                                               const char *dest_ip) {
    const mesh_route_rule_entry_t *rule = NULL;
    uint32_t dst_ip_u32 = 0;

    if (!mesh || !dest_ip) {
        return NULL;
    }

    dst_ip_u32 = ip_str_to_uint32(dest_ip);
    if (dst_ip_u32 != 0) {
        rule = mesh_route_rule_find(mesh, dst_ip_u32);
    }

    return rule;
}

static mesh_peer_t *mesh_direct_peer_find(mesh_network_t *mesh, const char *dest_ip) {
    if (!mesh || !dest_ip) {
        return NULL;
    }

    return mesh_find_peer_internal(mesh, dest_ip);
}

static mesh_route_t *mesh_learned_route_find_connected(mesh_network_t *mesh,
                                                       const char *dest_ip) {
    mesh_route_t *route = NULL;
    mesh_peer_t *peer = NULL;

    if (!mesh || !dest_ip) {
        return NULL;
    }

    route = mesh_route_find(mesh, dest_ip);
    if (!route) {
        return NULL;
    }

    if (route->next_hop && route->next_hop->is_connected &&
        (route->next_hop_virtual_ip[0] == '\0' ||
         strcmp(route->next_hop->virtual_ip, route->next_hop_virtual_ip) == 0)) {
        return route;
    }

    if (route->next_hop_virtual_ip[0] == '\0') {
        return NULL;
    }

    peer = mesh_find_peer_internal(mesh, route->next_hop_virtual_ip);
    if (!peer || !peer->is_connected) {
        return NULL;
    }

    route->next_hop = peer;
    return route;
}

static void mesh_path_snapshot_add(mesh_path_snapshot_t *snapshot,
                                   mesh_next_hop_kind_t kind,
                                   mesh_peer_t *peer,
                                   mesh_route_t *route,
                                   const mesh_route_rule_entry_t *rule) {
    mesh_path_candidate_t *candidate = NULL;

    if (!snapshot ||
        snapshot->candidate_count >= MESH_PATH_METRIC_CANDIDATE_LIMIT) {
        return;
    }

    candidate = &snapshot->candidates[snapshot->candidate_count++];
    candidate->kind = kind;
    candidate->peer = peer;
    candidate->route = route;
    candidate->rule = rule;
}

static mesh_path_snapshot_t mesh_path_snapshot_build(mesh_network_t *mesh,
                                                     const char *dest_ip,
                                                     int include_policy) {
    mesh_path_snapshot_t snapshot;
    const mesh_route_rule_entry_t *rule = NULL;
    mesh_peer_t *peer = NULL;
    mesh_route_t *route = NULL;

    memset(&snapshot, 0, sizeof(snapshot));
    if (!mesh || !dest_ip) {
        return snapshot;
    }

    if (include_policy) {
        rule = mesh_control_route_match(mesh, dest_ip);
        if (rule) {
            mesh_path_snapshot_add(&snapshot, MESH_NEXT_HOP_POLICY,
                                   mesh_route_rule_next_hop_find(mesh, rule),
                                   NULL, rule);
        }
    }

    peer = mesh_direct_peer_find(mesh, dest_ip);
    if (peer) {
        mesh_path_snapshot_add(&snapshot, MESH_NEXT_HOP_DIRECT, peer, NULL, NULL);
    }

    route = mesh_learned_route_find_connected(mesh, dest_ip);
    if (route) {
        mesh_path_snapshot_add(&snapshot, MESH_NEXT_HOP_LEARNED,
                               route->next_hop, route, NULL);
    }

    return snapshot;
}

static mesh_next_hop_result_t mesh_path_snapshot_select(
    const mesh_path_snapshot_t *snapshot) {
    mesh_next_hop_result_t result;
    size_t i = 0;

    memset(&result, 0, sizeof(result));
    if (!snapshot) {
        return result;
    }

    for (i = 0; i < snapshot->candidate_count; i++) {
        const mesh_path_candidate_t *candidate = &snapshot->candidates[i];

        /* Operator policy is exclusive: an unavailable pinned next hop must
         * fail closed instead of silently selecting a lower-priority path. */
        if (candidate->kind == MESH_NEXT_HOP_POLICY || candidate->peer) {
            result.kind = candidate->kind;
            result.peer = candidate->peer;
            result.route = candidate->route;
            result.rule = candidate->rule;
            return result;
        }
    }

    return result;
}

static mesh_path_metric_kind_t mesh_path_metric_kind_from_next_hop(
    mesh_next_hop_kind_t kind) {
    switch (kind) {
        case MESH_NEXT_HOP_POLICY:
            return MESH_PATH_METRIC_KIND_POLICY;
        case MESH_NEXT_HOP_DIRECT:
            return MESH_PATH_METRIC_KIND_DIRECT;
        case MESH_NEXT_HOP_LEARNED:
            return MESH_PATH_METRIC_KIND_LEARNED;
        default:
            return MESH_PATH_METRIC_KIND_NONE;
    }
}

static void mesh_path_metric_candidate_set(
    mesh_path_metric_candidate_t *candidate,
    mesh_path_metric_kind_t kind,
    mesh_peer_t *peer,
    uint32_t identity,
    uint32_t hop_count) {
    if (!candidate) {
        return;
    }

    memset(candidate, 0, sizeof(*candidate));
    candidate->kind = kind;
    candidate->eligible = peer != NULL && peer->is_connected;
    candidate->identity = identity;
    candidate->tie_break = identity;
    candidate->hop_count = hop_count;
    if (peer && peer->stream_metrics_fresh) {
        candidate->available_metrics = MESH_PATH_METRIC_AVAILABLE_RTT;
        candidate->srtt_ms = peer->stream_srtt_ms;
        candidate->rttvar_ms = peer->stream_rttvar_ms;
        candidate->metric_provenance =
            MESH_PATH_METRIC_PROVENANCE_AUTHENTICATED_STREAM;
    }
}

static uint32_t mesh_path_identity(const mesh_next_hop_result_t *path) {
    if (!path) {
        return 0;
    }
    if (path->peer) {
        return ip_str_to_uint32(path->peer->virtual_ip);
    }
    if (path->rule) {
        return ip_str_to_uint32(path->rule->next_hop_virtual_ip);
    }
    if (path->route) {
        return ip_str_to_uint32(path->route->next_hop_virtual_ip);
    }
    return 0;
}

static int mesh_path_metric_candidate_contains(
    const mesh_path_metric_candidate_t *candidates,
    size_t candidate_count,
    mesh_path_metric_kind_t kind,
    uint32_t identity) {
    size_t i = 0;

    for (i = 0; i < candidate_count; i++) {
        if (candidates[i].kind == kind && candidates[i].identity == identity) {
            return 1;
        }
    }
    return 0;
}

/**
 * Evaluates bounded derived alternates on the owner loop. Time complexity is
 * O(D*(P+R+C^2)); D <= 64, C <= 7. Space is O(C).
 */
static void mesh_path_observer_evaluate(mesh_network_t *mesh) {
    uint64_t now_ms = 0;
    size_t entry_index = 0;

    if (!mesh) {
        return;
    }

    now_ms = mesh_now_ms();
    (void)mesh_path_observer_expire(&mesh->path_observer, now_ms);
    for (entry_index = 0; entry_index < MESH_PATH_OBSERVER_LIMIT;
         entry_index++) {
        mesh_path_observer_entry_t *entry =
            &mesh->path_observer.entries[entry_index];
        mesh_path_metric_candidate_t
            metric_candidates[MESH_PATH_METRIC_CANDIDATE_LIMIT];
        mesh_path_metric_observation_t observation;
        mesh_path_hysteresis_result_t hysteresis;
        mesh_path_snapshot_t snapshot;
        mesh_next_hop_result_t current;
        char dest_ip[16] = {0};
        size_t metric_count = 0;
        size_t i = 0;

        if (!entry->in_use) {
            continue;
        }

        uint32_to_ip_str(entry->dest_ip, dest_ip);
        snapshot = mesh_path_snapshot_build(mesh, dest_ip, 1);
        current = mesh_path_snapshot_select(&snapshot);
        memset(metric_candidates, 0, sizeof(metric_candidates));

        for (i = 0; i < snapshot.candidate_count &&
                    metric_count < MESH_PATH_METRIC_CANDIDATE_LIMIT; i++) {
            const mesh_path_candidate_t *source = &snapshot.candidates[i];
            mesh_next_hop_result_t source_path = {
                source->kind, source->peer, source->route, source->rule
            };
            uint32_t identity = mesh_path_identity(&source_path);
            uint32_t hop_count = source->route ? source->route->hop_count : 0;

            mesh_path_metric_candidate_set(
                &metric_candidates[metric_count++],
                mesh_path_metric_kind_from_next_hop(source->kind),
                source->peer, identity, hop_count);
        }

        for (i = 0; i < MESH_PATH_OBSERVER_NEXT_HOP_LIMIT &&
                    metric_count < MESH_PATH_METRIC_CANDIDATE_LIMIT; i++) {
            const mesh_path_observer_candidate_t *alternate =
                &entry->candidates[i];
            mesh_peer_t *peer = NULL;
            char next_hop_ip[16] = {0};

            if (!alternate->in_use ||
                mesh_path_metric_candidate_contains(
                    metric_candidates, metric_count,
                    MESH_PATH_METRIC_KIND_LEARNED,
                    alternate->next_hop_ip)) {
                continue;
            }
            uint32_to_ip_str(alternate->next_hop_ip, next_hop_ip);
            peer = mesh_find_peer_internal(mesh, next_hop_ip);
            mesh_path_metric_candidate_set(
                &metric_candidates[metric_count++],
                MESH_PATH_METRIC_KIND_LEARNED, peer,
                alternate->next_hop_ip, alternate->hop_count);
        }

    observation = mesh_path_metric_observe(
            metric_candidates, metric_count,
            mesh_path_metric_kind_from_next_hop(current.kind),
            mesh_path_identity(&current));
        hysteresis = mesh_path_hysteresis_observe(
            &entry->hysteresis, &observation, now_ms);

        if (mesh->path_metric_observations < UINT64_MAX) {
            mesh->path_metric_observations++;
        }
        if (observation.differs &&
            mesh->path_metric_recommendation_mismatches < UINT64_MAX) {
            mesh->path_metric_recommendation_mismatches++;
        }
        mesh->last_current_path_kind = observation.current_kind;
        mesh->last_recommended_path_kind = observation.recommended_kind;
        mesh->last_current_path_cost = observation.current_cost;
        mesh->last_recommended_path_cost = observation.recommended_cost;
        mesh->last_recommended_path_available = observation.recommended_available;
        mesh->last_path_policy_forced = observation.policy_forced;
        mesh_path_observer_record_diagnostic(
            entry, &observation, &hysteresis, metric_count, now_ms);
        (void)mesh_path_trace_append_if_changed(
            &mesh->path_trace, entry->dest_ip,
            &entry->diagnostic, &entry->trace_baseline);
    }
}

static mesh_next_hop_result_t mesh_next_hop_resolve(mesh_network_t *mesh,
                                                    const char *dest_ip,
                                                    int include_policy) {
    mesh_path_snapshot_t snapshot =
        mesh_path_snapshot_build(mesh, dest_ip, include_policy);
    mesh_next_hop_result_t result = mesh_path_snapshot_select(&snapshot);

    return result;
}

static mesh_peer_t *mesh_next_hop_find(mesh_network_t *mesh, const char *dest_ip) {
    mesh_next_hop_result_t result = mesh_next_hop_resolve(mesh, dest_ip, 1);
    return result.peer;
}

static mesh_peer_t *mesh_find_or_create_signal_peer(mesh_network_t *mesh,
                                                    p2p_peer_t *p2p_peer,
                                                    const char *virtual_ip) {
    mesh_peer_t *peer = NULL;
    mesh_route_t *route = NULL;

    if (!mesh || !virtual_ip || virtual_ip[0] == '\0') {
        return NULL;
    }
    if (!mesh_policy_allows_virtual_ip(mesh, MESH_POLICY_SEND_CONTROL, virtual_ip)) {
        TLOG_DEBUG("Dropping control signal peer {} blocked by peer admission policy",
                   virtual_ip);
        return NULL;
    }

    if (p2p_peer) {
        peer = mesh_find_peer_by_p2p(mesh, p2p_peer);
        if (peer) {
            return peer;
        }
    }

    peer = mesh_find_peer_any_virtual(mesh, virtual_ip);
    if (peer) {
        return peer;
    }

    peer = mesh_peer_create_virtual(mesh, virtual_ip);
    if (!peer) {
        return NULL;
    }

    route = mesh_route_find(mesh, virtual_ip);
    if (route && route->dest_real_ip[0] != '\0') {
        strncpy(peer->advertised_real_ip, route->dest_real_ip,
                sizeof(peer->advertised_real_ip) - 1);
        strncpy(peer->real_ip, route->dest_real_ip, sizeof(peer->real_ip) - 1);
    }

    return peer;
}

static int mesh_send_control_message(mesh_network_t *mesh, const char *dest_virtual_ip,
                                     const char *msg) {
    mesh_peer_t *next_hop = NULL;
    char *routed_msg = NULL;
    size_t routed_len = 0;
    int ret = MESH_OK;

    if (!mesh || !dest_virtual_ip || !msg || msg[0] == '\0') {
        return MESH_ERR_INVALID_ARG;
    }
    if (!mesh_policy_allows_virtual_ip(mesh, MESH_POLICY_SEND_CONTROL, dest_virtual_ip)) {
        return MESH_ERR_NOT_FOUND;
    }

    next_hop = mesh_next_hop_find(mesh, dest_virtual_ip);
    if (!next_hop || !next_hop->p2p_peer) {
        return MESH_ERR_NOT_FOUND;
    }

    if (strcmp(next_hop->virtual_ip, dest_virtual_ip) == 0) {
        return p2p_send_message(mesh->p2p_node, next_hop->p2p_peer, P2P_MSG_CUSTOM,
                                msg, strlen(msg) + 1) == P2P_OK
             ? MESH_OK
             : MESH_ERR_NETWORK;
    }

    if (!mesh_peer_has_capability(next_hop, MESH_CAP_ROUTED_CONTROL)) {
        TLOG_DEBUG("Dropping routed control message to {} via {} without routed-control capability",
                   dest_virtual_ip, next_hop->virtual_ip);
        return MESH_ERR_NOT_FOUND;
    }

    routed_len = strlen("MESH_CTRL:") + strlen(dest_virtual_ip) + 1 + strlen(msg) + 1;
    routed_msg = (char *)malloc(routed_len);
    if (!routed_msg) {
        return MESH_ERR_NO_MEMORY;
    }

    fmt(routed_msg, routed_len, "MESH_CTRL:{}:{}", dest_virtual_ip, msg);
    ret = p2p_send_message(mesh->p2p_node, next_hop->p2p_peer, P2P_MSG_CUSTOM,
                           routed_msg, routed_len) == P2P_OK
        ? MESH_OK
        : MESH_ERR_NETWORK;
    free(routed_msg);
    return ret;
}

static int mesh_route_add_or_update(mesh_network_t *mesh, const char *dest_ip,
                                    mesh_peer_t *next_hop, uint8_t hop_count,
                                    const char *dest_real_ip) {
    mesh_peer_t *direct_peer = NULL;
    uint64_t now_ms = 0;

    if (dest_real_ip && !mesh_endpoint_is_routable(dest_real_ip)) {
        dest_real_ip = NULL;
    }
    if (!mesh_policy_allows_virtual_ip(mesh, MESH_POLICY_LEARN_ROUTE, dest_ip)) {
        TLOG_WARN("Rejecting learned route to {}: blocked by peer admission policy", dest_ip);
        return 0;
    }
    now_ms = mesh_now_ms();
    if (next_hop) {
        (void)mesh_path_observer_upsert(
            &mesh->path_observer,
            ip_str_to_uint32(dest_ip),
            ip_str_to_uint32(next_hop->virtual_ip),
            hop_count, now_ms, MESH_LEARNED_ROUTE_TTL_MS);
    }
    direct_peer = mesh_find_peer_internal(mesh, dest_ip);
    if (direct_peer && direct_peer->is_connected) {
        mesh_route_delete(mesh, dest_ip);
        return 0;
    }

    /* Find existing route */
    mesh_route_t *route = mesh_route_find(mesh, dest_ip);

    if (route) {
        /* Update if new route is better (fewer hops) */
        if (hop_count < route->hop_count) {
            route->next_hop = next_hop;
            if (next_hop) {
                strncpy(route->next_hop_virtual_ip, next_hop->virtual_ip,
                        sizeof(route->next_hop_virtual_ip) - 1);
            }
            route->hop_count = hop_count;
            route->last_update_ms = now_ms;
            route->expires_at_ms = now_ms + MESH_LEARNED_ROUTE_TTL_MS;
            if (dest_real_ip) {
                strncpy(route->dest_real_ip, dest_real_ip, sizeof(route->dest_real_ip) - 1);
            }
            return 1; /* Route updated */
        }
        if (dest_real_ip &&
            (route->dest_real_ip[0] == '\0' || strcmp(route->dest_real_ip, dest_real_ip) != 0)) {
            strncpy(route->dest_real_ip, dest_real_ip, sizeof(route->dest_real_ip) - 1);
            route->last_update_ms = now_ms;
            route->expires_at_ms = now_ms + MESH_LEARNED_ROUTE_TTL_MS;
            return 1;
        }
        if (route->next_hop == next_hop && route->hop_count == hop_count) {
            if (next_hop) {
                strncpy(route->next_hop_virtual_ip, next_hop->virtual_ip,
                        sizeof(route->next_hop_virtual_ip) - 1);
            }
            route->last_update_ms = now_ms;
            route->expires_at_ms = now_ms + MESH_LEARNED_ROUTE_TTL_MS;
        }
        return 0; /* Route not updated */
    }

    /* Create new route */
    route = mesh_route_create(dest_ip, next_hop, hop_count, dest_real_ip);
    if (!route) return -1;

    /* Add to list */
    route->next = mesh->routes;
    mesh->routes = route;
    mesh->route_count++;

    return 1; /* Route added */
}

static void mesh_route_delete(mesh_network_t *mesh, const char *dest_ip) {
    mesh_route_t **prev = &mesh->routes;
    mesh_route_t *route = mesh->routes;

    while (route) {
        if (strcmp(route->dest_ip, dest_ip) == 0) {
            *prev = route->next;
            mesh_route_destroy(route);
            mesh->route_count--;
            return;
        }
        prev = &route->next;
        route = route->next;
    }
}

/* Delete all routes that use a specific peer as next hop */
static void mesh_route_delete_via_peer(mesh_network_t *mesh, mesh_peer_t *peer) {
    mesh_route_t **prev = &mesh->routes;
    mesh_route_t *route = mesh->routes;

    while (route) {
        if (route->next_hop == peer) {
            *prev = route->next;
            mesh_route_t *to_delete = route;
            route = route->next;
            mesh_route_destroy(to_delete);
            mesh->route_count--;
        } else {
            prev = &route->next;
            route = route->next;
        }
    }
}

static size_t mesh_uint_digits(unsigned value) {
    size_t digits = 1;

    while (value >= 10) {
        value /= 10;
        digits++;
    }
    return digits;
}

static size_t mesh_route_entry_len(const char *virtual_ip, unsigned hop_count,
                                   const char *endpoint, int needs_separator) {
    size_t len = needs_separator ? 1 : 0;

    len += strlen(virtual_ip) + 1 + mesh_uint_digits(hop_count);
    if (endpoint) {
        len += 1 + strlen(endpoint);
    }
    return len;
}

static int mesh_append_route_entry(char *msg, size_t cap, size_t *offset,
                                   int *entry_count, const char *virtual_ip,
                                   unsigned hop_count, const char *endpoint) {
    int written = 0;
    size_t required = 0;

    if (!msg || !offset || !entry_count || !virtual_ip || *offset >= cap) {
        return 0;
    }

    required = mesh_route_entry_len(virtual_ip, hop_count, endpoint,
                                    *entry_count > 0);
    if (required >= cap - *offset) {
        return 0;
    }

    if (endpoint) {
        written = fmt(msg + *offset, cap - *offset, "{}{}:{}|{}",
                      *entry_count > 0 ? "," : "", virtual_ip,
                      hop_count, endpoint);
    } else {
        written = fmt(msg + *offset, cap - *offset, "{}{}:{}",
                      *entry_count > 0 ? "," : "", virtual_ip,
                      hop_count);
    }
    if (written <= 0 || (size_t)written != required) {
        return 0;
    }

    *offset += (size_t)written;
    (*entry_count)++;
    return 1;
}

static void mesh_send_routes_to_peer(mesh_network_t *mesh, mesh_peer_t *target) {
    char *msg = NULL;
    size_t msg_len = strlen("MESH_ROUTES:") + 1;
    size_t offset = 0;
    int entry_count = 0;
    mesh_peer_t *peer = NULL;
    mesh_route_t *route = NULL;

    if (!mesh || !target || !target->is_connected || !target->announced) {
        return;
    }

    peer = mesh->peers;
    while (peer) {
        if (peer != target && peer->is_connected && peer->announced) {
            const char *endpoint = mesh_endpoint_is_routable(peer->advertised_real_ip)
                                       ? peer->advertised_real_ip
                                       : NULL;
            msg_len += mesh_route_entry_len(peer->virtual_ip, 1, endpoint,
                                            entry_count > 0);
            entry_count++;
        }
        peer = peer->next;
    }

    route = mesh->routes;
    while (route) {
        if (route->next_hop != target && route->hop_count < 15) {
            const char *endpoint = route->dest_real_ip[0] != '\0'
                                       ? route->dest_real_ip
                                       : NULL;
            msg_len += mesh_route_entry_len(route->dest_ip,
                                            (unsigned)(route->hop_count + 1),
                                            endpoint, entry_count > 0);
            entry_count++;
        }
        route = route->next;
    }

    msg = (char *)malloc(msg_len);
    if (!msg) {
        return;
    }

    memcpy(msg, "MESH_ROUTES:", strlen("MESH_ROUTES:") + 1);
    offset = strlen("MESH_ROUTES:");
    entry_count = 0;

    peer = mesh->peers;
    while (peer) {
        if (peer != target && peer->is_connected && peer->announced) {
            const char *endpoint = mesh_endpoint_is_routable(peer->advertised_real_ip)
                                       ? peer->advertised_real_ip
                                       : NULL;
            if (!mesh_append_route_entry(msg, msg_len, &offset, &entry_count,
                                         peer->virtual_ip, 1, endpoint)) {
                free(msg);
                return;
            }
        }
        peer = peer->next;
    }

    route = mesh->routes;
    while (route) {
        if (route->next_hop != target && route->hop_count < 15) {
            const char *endpoint = route->dest_real_ip[0] != '\0'
                                       ? route->dest_real_ip
                                       : NULL;
            if (!mesh_append_route_entry(msg, msg_len, &offset, &entry_count,
                                         route->dest_ip,
                                         (unsigned)(route->hop_count + 1),
                                         endpoint)) {
                free(msg);
                return;
            }
        }
        route = route->next;
    }

    TLOG_DEBUG("Sending routes to {} via {}: {}",
               target->virtual_ip, target->real_ip, msg);
    p2p_send_message(mesh->p2p_node, target->p2p_peer, P2P_MSG_CUSTOM,
                     msg, strlen(msg) + 1);
    free(msg);
}

static void mesh_broadcast_routes(mesh_network_t *mesh) {
    mesh_peer_t *peer = NULL;

    if (!mesh) {
        return;
    }

    peer = mesh->peers;
    while (peer) {
        mesh_send_routes_to_peer(mesh, peer);
        peer = peer->next;
    }
}

/* Publish our routing table to DHT for neighbors to discover */
static void mesh_publish_routes(mesh_network_t *mesh) {
    char dht_key[128];
    char *dht_value = NULL;
    size_t dht_value_len = 1;
    size_t offset = 0;
    int entry_count = 0;
    mesh_peer_t *peer = NULL;
    mesh_route_t *route = NULL;

    if (!mesh) return;

    if (mesh_ensure_virtual_ip_registered(mesh) != MESH_OK) {
        return;
    }
    mesh_route_expire_stale(mesh);

    /* Key: "mesh:<network_id>:routes:<my_ip>" */
    fmt(dht_key, sizeof(dht_key), "mesh:{}:routes:{}",
             mesh->network_id, mesh->virtual_ip);

    peer = mesh->peers;
    while (peer) {
        if (peer->is_connected) {
            dht_value_len += mesh_route_entry_len(peer->virtual_ip, 1, NULL,
                                                  entry_count > 0);
            entry_count++;
        }
        peer = peer->next;
    }

    route = mesh->routes;
    while (route) {
        dht_value_len += mesh_route_entry_len(route->dest_ip,
                                              (unsigned)(route->hop_count + 1),
                                              NULL, entry_count > 0);
        entry_count++;
        route = route->next;
    }

    dht_value = (char *)malloc(dht_value_len);
    if (!dht_value) {
        return;
    }
    dht_value[0] = '\0';

    entry_count = 0;
    peer = mesh->peers;
    while (peer) {
        if (peer->is_connected &&
            !mesh_append_route_entry(dht_value, dht_value_len, &offset,
                                     &entry_count, peer->virtual_ip, 1, NULL)) {
            free(dht_value);
            return;
        }
        peer = peer->next;
    }

    route = mesh->routes;
    while (route) {
        if (!mesh_append_route_entry(dht_value, dht_value_len, &offset,
                                     &entry_count, route->dest_ip,
                                     (unsigned)(route->hop_count + 1), NULL)) {
            free(dht_value);
            return;
        }
        route = route->next;
    }

    /* Publish to DHT */
    p2p_dht_put_cached(mesh->p2p_node, dht_key, dht_value, strlen(dht_value) + 1);
    free(dht_value);
}

/* Discover routes from neighbors via DHT */
static void mesh_discover_routes(mesh_network_t *mesh) {
    if (!mesh) return;

    /* Query each connected peer's routing table */
    mesh_peer_t *peer = mesh->peers;
    while (peer) {
        if (!peer->is_connected) {
            peer = peer->next;
            continue;
        }

        char dht_key[128];
        char dht_value[1024];
        size_t dht_len = sizeof(dht_value) - 1u; /* reserve room for NUL */

        fmt(dht_key, sizeof(dht_key), "mesh:{}:routes:{}",
                 mesh->network_id, peer->virtual_ip);

        if (p2p_dht_get_cached(mesh->p2p_node, dht_key, dht_value, &dht_len) != P2P_OK) {
            peer = peer->next;
            continue;
        }

        {
            /* Parse routes: "10.42.0.3:1,10.42.0.4:2,..." */
            char *token = strtok(dht_value, ",");
            while (token) {
                char ip[16];
                int hops;
                if (sscanf(token, "%15[^:]:%d", ip, &hops) == 2) {
                    /* Don't add route to ourselves */
                    if (strcmp(ip, mesh->virtual_ip) != 0) {
                        /* Add route via this peer */
                        mesh_route_add_or_update(mesh, ip, peer, hops, NULL);
                    }
                }
                token = strtok(NULL, ",");
            }
        }

        peer = peer->next;
    }
}

/* =============================================================================
 * P2P Peer Connection Callbacks
 * ============================================================================= */

static void mesh_send_hello(mesh_network_t *mesh, p2p_peer_t *p2p_peer) {
    char hello_msg[256];

    if (!mesh || !mesh->p2p_node || !p2p_peer) {
        return;
    }

    if (!mesh_ip_is_unspecified(mesh->advertise_ip)) {
        fmt(hello_msg, sizeof(hello_msg),
                       "MESH_HELLO:{}:{}:{}:node={}:proto={}.{}:caps={:08x}",
                       mesh->virtual_ip, mesh->advertise_ip, mesh->listen_port,
                       mesh->node_id, MESH_PROTOCOL_MAJOR, MESH_PROTOCOL_MINOR,
                       mesh_local_capabilities(mesh));
    } else {
        fmt(hello_msg, sizeof(hello_msg),
                       "MESH_HELLO:{}:node={}:proto={}.{}:caps={:08x}",
                       mesh->virtual_ip, mesh->node_id,
                       MESH_PROTOCOL_MAJOR, MESH_PROTOCOL_MINOR,
                       mesh_local_capabilities(mesh));
    }

    p2p_send_message(mesh->p2p_node, p2p_peer, P2P_MSG_CUSTOM,
                     hello_msg, strlen(hello_msg) + 1);
    TLOG_DEBUG("Sent HELLO with virtual IP {}", mesh->virtual_ip);
}

static void mesh_on_p2p_peer_connected(p2p_peer_t *p2p_peer, void *user_data) {
    mesh_network_t *mesh = (mesh_network_t *)user_data;
    mesh_peer_t *mesh_peer = NULL;
    mesh_mgmt_agent_router_result_t mgmt_result;
    if (!mesh) return;

    /* Get peer address for logging */
    char peer_ip[64];
    int peer_port;
    p2p_peer_get_address(p2p_peer, peer_ip, &peer_port);

    TLOG_INFO("P2P peer connected: {}:{}", peer_ip, peer_port);
    mesh->peer_connect_events++;

    /* Create mesh peer wrapper */
    mesh_peer = mesh_peer_create(mesh, p2p_peer);
    if (!mesh_peer) {
        TLOG_WARN("Failed to create mesh peer");
        return;
    }

    if (mesh->mgmt_router) {
        mgmt_result =
            mesh_mgmt_agent_router_offer_peer_connected_v1(mesh->mgmt_router, p2p_peer);
        if (mgmt_result != MESH_MGMT_AGENT_ROUTER_OK &&
            mgmt_result != MESH_MGMT_AGENT_ROUTER_DUPLICATE_PEER) {
            TLOG_WARN("Management peer attach failed: {}", (int)mgmt_result);
            return;
        }
    }

    mesh_send_hello(mesh, p2p_peer);

}

static void mesh_on_p2p_peer_disconnected(p2p_peer_t *p2p_peer, void *user_data) {
    mesh_network_t *mesh = (mesh_network_t *)user_data;
    if (!mesh) return;

    if (mesh->mgmt_router) {
        (void)mesh_mgmt_agent_router_offer_peer_disconnected_v1(mesh->mgmt_router,
                                                                p2p_peer);
    }

    /* Get peer address for logging */
    char peer_ip[64];  /* Match INET_ADDRSTRLEN (22) + safety margin */
    int peer_port;
    p2p_peer_get_address(p2p_peer, peer_ip, &peer_port);

    TLOG_INFO("P2P peer disconnected: {}:{}", peer_ip, peer_port);
    mesh->peer_disconnect_events++;

    mesh_peer_t *peer = mesh->peers;
    while (peer) {
        mesh_peer_t *next = peer->next;

        if (peer->p2p_peer == p2p_peer) {
            peer->transport_authenticated = 0;
            peer->negotiated_capabilities &= ~MESH_CAP_STREAM_V1;
            if (peer->announced && mesh->on_peer_disconnected) {
                mesh->on_peer_disconnected(peer, mesh->user_data);
            }
            mesh_peer_remove(mesh, peer);
            mesh_schedule_control_plane_refresh(mesh,
                                                !mesh_has_connected_peers(mesh) &&
                                                mesh->bootstrap_count > 0,
                                                "peer-disconnected-no-peers");
            return;
        }
        peer = next;
    }
}

/* =============================================================================
 * Packet Transport Helpers
 * ============================================================================= */

static int mesh_peer_has_active_ice_path(const mesh_peer_t *peer) {
    ice_state_t state;

    if (!peer || !peer->ice_agent) {
        return 0;
    }

    if (!mesh_peer_has_capability(peer, MESH_CAP_SELECTED_PAIR_IP)) {
        return 0;
    }

    state = ice_agent_get_state(peer->ice_agent);
    if (state != ICE_STATE_CONNECTED && state != ICE_STATE_COMPLETED) {
        return 0;
    }

    return ice_agent_get_selected_pair(peer->ice_agent, NULL, NULL) == 0;
}

static int mesh_send_to_peer(mesh_peer_t *peer, const void *data, size_t len) {
    if (!peer || !peer->mesh || !data || len == 0) {
        return MESH_ERR_INVALID_ARG;
    }

    if (mesh_peer_has_active_ice_path(peer)) {
        return ice_agent_send(peer->ice_agent, data, len) >= 0 ? MESH_OK : MESH_ERR_NETWORK;
    }

    if (!peer->p2p_peer) {
        return MESH_ERR_NETWORK;
    }

    return p2p_send(peer->mesh->p2p_node, peer->p2p_peer, data, len) == P2P_OK
         ? MESH_OK
         : MESH_ERR_NETWORK;
}

static void mesh_handle_ip_packet(mesh_network_t *mesh, mesh_peer_t *incoming_peer,
                                  const uint8_t *ip_packet, size_t len) {
    uint32_t dst_ip;
    uint32_t my_ip;
    uint8_t ttl;
    char dst_ip_str[16];
    char src_ip_str[16];

    if (!mesh || !ip_packet || len < 20) {
        return;
    }

    if (incoming_peer) {
        incoming_peer->bytes_rx += len;
        incoming_peer->last_seen_ms = mesh_now_ms();
    }

    dst_ip = extract_dst_ip(ip_packet, len);
    if (dst_ip == 0) {
        return;
    }

    uint32_to_ip_str(dst_ip, dst_ip_str);
    uint32_to_ip_str(extract_src_ip(ip_packet, len), src_ip_str);

    if (mesh_ip_is_multicast(dst_ip)) {
        TLOG_DEBUG("Dropping non-mesh packet {} -> {}", src_ip_str, dst_ip_str);
        return;
    }

    if (!mesh_ip_in_virtual_network(mesh, dst_ip)) {
        if (!mesh_local_egress_find(mesh, dst_ip)) {
            TLOG_DEBUG("Dropping non-mesh packet {} -> {} without local egress policy",
                       src_ip_str, dst_ip_str);
            return;
        }
        if (!mesh_policy_allows_local_egress_source(mesh, incoming_peer,
                                                    extract_src_ip(ip_packet, len))) {
            TLOG_DEBUG("Dropping non-mesh packet {} -> {} blocked by local egress source policy",
                       src_ip_str, dst_ip_str);
            return;
        }
        if (!mesh_packet_policy_allows(mesh, MESH_PACKET_POLICY_LOCAL_EGRESS, ip_packet, len)) {
            TLOG_DEBUG("Dropping non-mesh packet {} -> {} blocked by packet policy",
                       src_ip_str, dst_ip_str);
            return;
        }

        TLOG_DEBUG("Delivering packet {} -> {} to local egress", src_ip_str, dst_ip_str);
        if (mesh->on_packet_received) {
            mesh->on_packet_received(ip_packet, len, mesh->user_data);
        }
        mesh->stats.bytes_rx += len;
        mesh->stats.packets_rx++;
        return;
    }

    my_ip = ip_str_to_uint32(mesh->virtual_ip);
    if (dst_ip == my_ip) {
        if (!mesh_packet_policy_allows(mesh, MESH_PACKET_POLICY_IN, ip_packet, len)) {
            TLOG_DEBUG("Dropping inbound packet {} -> {} blocked by packet policy",
                       src_ip_str, dst_ip_str);
            return;
        }
        if (mesh->on_packet_received) {
            mesh->on_packet_received(ip_packet, len, mesh->user_data);
        }
        mesh->stats.bytes_rx += len;
        mesh->stats.packets_rx++;
        return;
    }

    ttl = ip_packet[8];
    if (ttl <= 1) {
        return;
    }

    if (!mesh_policy_allows_virtual_ip(mesh, MESH_POLICY_FORWARD_PACKET, dst_ip_str)) {
        TLOG_DEBUG("Dropping forwarded packet {} -> {} blocked by peer admission policy",
                   src_ip_str, dst_ip_str);
        return;
    }
    if (!mesh_packet_policy_allows(mesh, MESH_PACKET_POLICY_FORWARD, ip_packet, len)) {
        TLOG_DEBUG("Dropping forwarded packet {} -> {} blocked by packet policy",
                   src_ip_str, dst_ip_str);
        return;
    }

    {
        mesh_peer_t *next_hop = mesh_next_hop_find(mesh, dst_ip_str);
        if (next_hop) {
            uint8_t *forward_packet = (uint8_t *)malloc(len);
            if (!forward_packet) {
                return;
            }

            memcpy(forward_packet, ip_packet, len);
            forward_packet[8] = ttl - 1;

            {
                size_t header_len = (size_t)(forward_packet[0] & 0x0Fu) * 4u;
                if (header_len >= 20 && header_len <= len) {
                    uint16_t checksum;
                    forward_packet[10] = 0;
                    forward_packet[11] = 0;
                    checksum = mesh_ipv4_checksum(forward_packet, header_len);
                    forward_packet[10] = (uint8_t)(checksum >> 8);
                    forward_packet[11] = (uint8_t)(checksum & 0xFF);
                }
            }

            TLOG_DEBUG("Forwarding packet {} -> {} via {}",
                       src_ip_str, dst_ip_str, next_hop->virtual_ip);
            mesh_note_active_relay_next_hop(mesh, next_hop);
            if (mesh_send_to_peer(next_hop, forward_packet, len) == MESH_OK) {
                mesh->stats.bytes_tx += len;
                mesh->stats.packets_tx++;
                next_hop->bytes_tx += len;
            }
            free(forward_packet);
        }
    }
}

static void mesh_disconnect_all_p2p_peers(mesh_network_t *mesh) {
    p2p_peer_t **peers = NULL;
    size_t count = 0;
    coro_context_t *ctx = NULL;

    if (!mesh || !mesh->p2p_node) {
        return;
    }

    for (mesh_peer_t *peer = mesh->peers; peer; peer = peer->next) {
        if (peer->p2p_peer) {
            count++;
        }
    }
    for (mesh_peer_t *peer = mesh->retired_peers; peer; peer = peer->next) {
        if (peer->p2p_peer) {
            count++;
        }
    }
    if (count == 0) {
        return;
    }

    peers = (p2p_peer_t **)calloc(count, sizeof(*peers));
    if (!peers) {
        return;
    }

    count = 0;
    for (mesh_peer_t *peer = mesh->peers; peer; peer = peer->next) {
        if (peer->p2p_peer) {
            peers[count++] = peer->p2p_peer;
        }
    }
    for (mesh_peer_t *peer = mesh->retired_peers; peer; peer = peer->next) {
        if (peer->p2p_peer) {
            peers[count++] = peer->p2p_peer;
        }
    }

    for (size_t i = 0; i < count; i++) {
        if (peers[i]) {
            p2p_disconnect_peer(peers[i]);
        }
    }
    free(peers);

    ctx = p2p_get_loop(mesh->p2p_node);
    if (!ctx) {
        return;
    }

    for (int i = 0; i < 100; i++) {
        coro_context_run(ctx, TURBO_RUN_NOWAIT);
        turbo_sleep_ms(1);
    }
}

static int mesh_handle_control_payload(mesh_network_t *mesh, p2p_peer_t *p2p_peer,
                                       const char *msg) {
    mesh_peer_t *peer = NULL;
    char virtual_ip[16] = {0};
    const char *payload = NULL;
    const char *sep = NULL;

    if (!mesh || !msg) {
        return 0;
    }

    if (strncmp(msg, "MESH_ICE_AUTH:", 14) == 0) {
        payload = msg + 14;
        sep = strchr(payload, ':');
        if (!sep) {
            return 1;
        }
        if ((size_t)(sep - payload) >= sizeof(virtual_ip)) {
            return 1;
        }
        memcpy(virtual_ip, payload, (size_t)(sep - payload));
        peer = mesh_find_or_create_signal_peer(mesh, p2p_peer, virtual_ip);
        if (peer) {
            if (!peer->ice_agent) {
                mesh_ice_init_peer(mesh, peer);
            }
            mesh_ice_handle_auth(peer, payload);
        }
        return 1;
    }

    if (strncmp(msg, "MESH_ICE_CANDIDATE:", 19) == 0) {
        payload = msg + 19;
        sep = strchr(payload, ':');
        if (!sep) {
            return 1;
        }
        if ((size_t)(sep - payload) >= sizeof(virtual_ip)) {
            return 1;
        }
        memcpy(virtual_ip, payload, (size_t)(sep - payload));
        peer = mesh_find_or_create_signal_peer(mesh, p2p_peer, virtual_ip);
        if (peer) {
            if (!peer->ice_agent) {
                mesh_ice_init_peer(mesh, peer);
            }
            mesh_ice_handle_candidate(peer, sep + 1);
        }
        return 1;
    }

    if (strncmp(msg, "MESH_ICE_EOC:", 13) == 0) {
        payload = msg + 13;
        if (payload[0] == '\0' || strlen(payload) >= sizeof(virtual_ip)) {
            return 1;
        }
        strncpy(virtual_ip, payload, sizeof(virtual_ip) - 1);
        peer = mesh_find_or_create_signal_peer(mesh, p2p_peer, virtual_ip);
        if (peer) {
            if (!peer->ice_agent) {
                mesh_ice_init_peer(mesh, peer);
            }
            mesh_ice_handle_end_of_candidates(peer);
        }
        return 1;
    }

    return 0;
}

/* =============================================================================
 * Message Handling
 * ============================================================================= */

static void mesh_on_p2p_message(p2p_node_t *node, p2p_peer_t *p2p_peer,
                                  const void *data, size_t len, void *user_data) {
    mesh_network_t *mesh = (mesh_network_t *)user_data;
    mesh_peer_t *peer = NULL;
    if (!mesh || len == 0) return;

    if (mesh->mgmt_router) {
        mesh_mgmt_agent_router_result_t mgmt_result =
            mesh_mgmt_agent_router_offer_message_v1(mesh->mgmt_router, node, p2p_peer,
                                                     data, len);
        if (mgmt_result != MESH_MGMT_AGENT_ROUTER_NOT_MMP) {
            if (mgmt_result != MESH_MGMT_AGENT_ROUTER_OK) {
                TLOG_WARN("Management message rejected: {}", (int)mgmt_result);
            }
            return;
        }
    }

    const char *msg = (const char *)data;

    /* Check if this is a MESH_HELLO message */
    if (strncmp(msg, "MESH_HELLO:", 11) == 0) {
        char virtual_ip[16] = {0};
        char advertised_ip[64] = {0};
        int advertised_port = 0;
        char node_id[65] = {0};
        unsigned int protocol_major = 0;
        unsigned int protocol_minor = 0;
        uint32_t capabilities = 0;
        mesh_peer_t *duplicate = NULL;
        int notify_connected = 0;

        if (!mesh_parse_hello_message(msg + 11,
                                      virtual_ip, sizeof(virtual_ip),
                                      advertised_ip, sizeof(advertised_ip),
                                      &advertised_port,
                                      node_id, sizeof(node_id),
                                      &protocol_major, &protocol_minor,
                                      &capabilities)) {
            return;
        }

        TLOG_DEBUG("Received HELLO from peer with virtual IP: {}", virtual_ip);

        peer = mesh_find_peer_by_p2p(mesh, p2p_peer);
        if (!peer) {
            TLOG_WARN("HELLO from unknown peer");
            return;
        }

        if (!mesh_p2p_peer_id_matches(p2p_peer, node_id)) {
            TLOG_WARN("Rejecting mesh peer {} via {}: HELLO node id does not match P2P identity",
                      virtual_ip, peer->real_ip);
            mesh_peer_remove(mesh, peer);
            p2p_disconnect_peer(p2p_peer);
            if (mesh->ice_ctx) {
                mesh_ice_drain_context(mesh->ice_ctx, 50);
                mesh_cleanup_retired_peers(mesh);
            }
            return;
        }

        if (!mesh_policy_allows_virtual_ip(mesh, MESH_POLICY_ADMIT_PEER, virtual_ip)) {
            TLOG_WARN("Rejecting mesh peer {} via {}: blocked by peer admission policy",
                      virtual_ip, peer->real_ip);
            mesh_peer_remove(mesh, peer);
            p2p_disconnect_peer(p2p_peer);
            if (mesh->ice_ctx) {
                mesh_ice_drain_context(mesh->ice_ctx, 50);
                mesh_cleanup_retired_peers(mesh);
            }
            return;
        }

        if (!mesh_peer_acl_allows_node_id(mesh, node_id)) {
            TLOG_WARN("Rejecting mesh peer {} via {}: node id {} blocked by identity admission policy",
                      virtual_ip, peer->real_ip, node_id);
            mesh_peer_remove(mesh, peer);
            p2p_disconnect_peer(p2p_peer);
            if (mesh->ice_ctx) {
                mesh_ice_drain_context(mesh->ice_ctx, 50);
                mesh_cleanup_retired_peers(mesh);
            }
            return;
        }

        if (!mesh_peer_protocol_major_allowed(mesh, protocol_major)) {
            if (mesh->peer_protocol_major > 0 && protocol_major == 0) {
                TLOG_WARN("Rejecting mesh peer {} via {}: peer did not advertise protocol version, required major {}",
                          virtual_ip, peer->real_ip, mesh->peer_protocol_major);
            } else {
                TLOG_WARN("Rejecting mesh peer {} via {}: peer protocol {}.{} does not satisfy required major {}",
                          virtual_ip, peer->real_ip, protocol_major, protocol_minor,
                          mesh->peer_protocol_major);
            }
            mesh_peer_remove(mesh, peer);
            p2p_disconnect_peer(p2p_peer);
            if (mesh->ice_ctx) {
                mesh_ice_drain_context(mesh->ice_ctx, 50);
                mesh_cleanup_retired_peers(mesh);
            }
            return;
        }

        duplicate = mesh_find_peer_by_virtual_except(mesh, virtual_ip, peer);
        if (duplicate) {
            if (node_id[0] != '\0' && duplicate->peer_id[0] != '\0' &&
                strcmp(node_id, duplicate->peer_id) != 0) {
                TLOG_WARN("Rejecting duplicate mesh peer for {} via {}: node id mismatch",
                          virtual_ip, peer->real_ip);
            } else {
                TLOG_INFO("Dropping duplicate mesh peer for {} via {} (keeping {})",
                          virtual_ip, peer->real_ip, duplicate->real_ip);
            }
            mesh_peer_remove(mesh, peer);
            p2p_disconnect_peer(p2p_peer);
            if (mesh->ice_ctx) {
                mesh_ice_drain_context(mesh->ice_ctx, 50);
                mesh_cleanup_retired_peers(mesh);
            }
            return;
        }

        /* Update virtual IP */
        fmt(peer->virtual_ip, sizeof(peer->virtual_ip), "{}", virtual_ip);
        if (node_id[0] != '\0') {
            strncpy(peer->peer_id, node_id, sizeof(peer->peer_id) - 1);
        }
        peer->protocol_major = (uint16_t)protocol_major;
        peer->protocol_minor = (uint16_t)protocol_minor;
        peer->capabilities = capabilities;
        if (advertised_ip[0] != '\0' && advertised_port > 0 &&
            !mesh_ip_is_unspecified(advertised_ip)) {
            fmt(peer->advertised_real_ip, sizeof(peer->advertised_real_ip),
                "{}:{}", advertised_ip, advertised_port);
        }
        mesh_route_delete(mesh, peer->virtual_ip);
        TLOG_INFO("Updated peer virtual IP to: {}", peer->virtual_ip);
        if (!peer->announced) {
            peer->announced = 1;
            notify_connected = 1;
        }
        mesh_peer_refresh_negotiated_capabilities(peer);
        if (notify_connected && mesh->on_peer_connected) {
            mesh->on_peer_connected(peer, mesh->user_data);
        }
        if (mesh_peer_has_capability(peer, MESH_CAP_SELECTED_PAIR_IP)) {
            mesh_ice_init_peer(mesh, peer);
        } else {
            mesh_ice_destroy_peer(peer);
        }
        (void)mesh_ensure_virtual_ip_registered(mesh);
        mesh_publish_routes(mesh);
        mesh_send_routes_to_peer(mesh, peer);
        mesh_broadcast_routes(mesh);
        return;
    }

    if (strncmp(msg, "MESH_CTRL:", 10) == 0) {
        const char *dst = msg + 10;
        const char *sep = strchr(dst, ':');
        char dst_virtual_ip[16] = {0};
        mesh_peer_t *incoming = mesh_find_peer_by_p2p(mesh, p2p_peer);

        if (!sep) {
            return;
        }
        if (!mesh_peer_has_capability(incoming, MESH_CAP_ROUTED_CONTROL)) {
            TLOG_DEBUG("Dropping routed control message from peer without routed-control capability");
            return;
        }
        if ((size_t)(sep - dst) >= sizeof(dst_virtual_ip)) {
            return;
        }

        memcpy(dst_virtual_ip, dst, (size_t)(sep - dst));
        if (strcmp(dst_virtual_ip, mesh->virtual_ip) == 0) {
            (void)mesh_handle_control_payload(mesh, NULL, sep + 1);
            return;
        }
        if (!mesh_policy_allows_virtual_ip(mesh, MESH_POLICY_SEND_CONTROL, dst_virtual_ip)) {
            TLOG_DEBUG("Dropping routed control message to {} blocked by peer admission policy",
                       dst_virtual_ip);
            return;
        }

        peer = mesh_next_hop_find(mesh, dst_virtual_ip);
        if (peer && peer->p2p_peer) {
            if (strcmp(peer->virtual_ip, dst_virtual_ip) != 0 &&
                !mesh_peer_has_capability(peer, MESH_CAP_ROUTED_CONTROL)) {
                TLOG_DEBUG("Dropping routed control message to {} via {} without routed-control capability",
                           dst_virtual_ip, peer->virtual_ip);
                return;
            }
            p2p_send_message(mesh->p2p_node, peer->p2p_peer, P2P_MSG_CUSTOM,
                             msg, len);
        }
        return;
    }

    if (strncmp(msg, "MESH_ROUTES:", 12) == 0) {
        mesh_peer_t *next_hop = mesh->peers;
        char routes[1024];
        char *token = NULL;

        while (next_hop) {
            if (next_hop->p2p_peer == p2p_peer) {
                break;
            }
            next_hop = next_hop->next;
        }

        if (!next_hop || !next_hop->announced) {
            return;
        }

        strncpy(routes, msg + 12, sizeof(routes) - 1);
        routes[sizeof(routes) - 1] = '\0';
        TLOG_DEBUG("Received routes from {} via {}: {}",
                   next_hop->virtual_ip, next_hop->real_ip, routes);

        token = strtok(routes, ",");
        while (token) {
            char ip[16];
            int hops = 0;
            char dest_real_ip[64] = {0};

            if (sscanf(token, "%15[^:]:%d|%63s", ip, &hops, dest_real_ip) >= 2 &&
                hops > 0 &&
                strcmp(ip, mesh->virtual_ip) != 0 &&
                strcmp(ip, next_hop->virtual_ip) != 0) {
                TLOG_DEBUG("Route learned: {} via {} hops={}",
                           ip, next_hop->virtual_ip, hops);
                mesh_route_add_or_update(mesh, ip, next_hop, (uint8_t)hops,
                                         dest_real_ip[0] ? dest_real_ip : NULL);
            }

            token = strtok(NULL, ",");
        }
        return;
    }

    if (mesh_handle_control_payload(mesh, p2p_peer, msg)) {
        return;
    }

    peer = mesh_find_peer_by_p2p(mesh, p2p_peer);
    if (!peer || !peer->announced) {
        TLOG_DEBUG("Dropping mesh payload from unannounced peer");
        return;
    }

    mesh_handle_ip_packet(mesh, peer, (const uint8_t *)data, len);
}

/* =============================================================================
 * Lifecycle API
 * ============================================================================= */

static void mesh_ice_free_stun_servers(char **servers, int server_count) {
    if (!servers) {
        return;
    }

    for (int i = 0; i < server_count; i++) {
        free(servers[i]);
    }
    free(servers);
}

int mesh_ice_setup(mesh_network_t *mesh, const mesh_ice_config_t *config) {
    char **servers = NULL;

    if (!mesh || !config || config->stun_server_count < 0 ||
        config->stun_server_count > ICE_MAX_STUN_SERVERS ||
        (config->stun_server_count > 0 && !config->stun_servers)) {
        return MESH_ERR_INVALID_ARG;
    }
    if (mesh->ice_enabled || mesh->ice_ctx) {
        return MESH_ERR_BUSY;
    }

    if (config->stun_server_count > 0) {
        servers = (char **)calloc((size_t)config->stun_server_count, sizeof(char *));
        if (!servers) {
            return MESH_ERR_NO_MEMORY;
        }

        for (int i = 0; i < config->stun_server_count; i++) {
            const char *server = config->stun_servers[i];

            if (!server || server[0] == '\0' ||
                strlen(server) >= sizeof(((ice_config_t *)0)->stun_servers[0].url)) {
                mesh_ice_free_stun_servers(servers, config->stun_server_count);
                return MESH_ERR_INVALID_ARG;
            }
            servers[i] = strdup(server);
            if (!servers[i]) {
                mesh_ice_free_stun_servers(servers, config->stun_server_count);
                return MESH_ERR_NO_MEMORY;
            }
        }
    }

    mesh_ice_free_stun_servers(mesh->ice_stun_servers, mesh->ice_stun_count);
    mesh->ice_stun_servers = servers;
    mesh->ice_stun_count = config->stun_server_count;
    mesh->ice_allow_loopback = config->allow_loopback ? 1 : 0;
    return MESH_OK;
}

int mesh_ice_enable(mesh_network_t *mesh) {
    mesh_peer_t *peer = NULL;

    if (!mesh) {
        return MESH_ERR_INVALID_ARG;
    }
    if (mesh->ice_enabled) {
        return MESH_OK;
    }
    if (mesh->ice_ctx) {
        return MESH_ERR_BUSY;
    }

    mesh->ice_ctx = coro_context_create(NULL);
    if (!mesh->ice_ctx) {
        return MESH_ERR_NO_MEMORY;
    }
#if defined(__linux__) && !defined(__ANDROID__)
    coro_context_set_udp_backend(mesh->ice_ctx, TURBO_UDP_BACKEND_EPOLL);
#elif defined(_WIN32)
    coro_context_set_udp_backend(mesh->ice_ctx, TURBO_UDP_BACKEND_IOCP);
#endif
    mesh->ice_enabled = 1;

    peer = mesh->peers;
    while (peer) {
        mesh_peer_refresh_negotiated_capabilities(peer);
        if (peer->p2p_peer) {
            mesh_send_hello(mesh, peer->p2p_peer);
        }
        if (peer->announced && peer->is_connected &&
            mesh_peer_has_capability(peer, MESH_CAP_SELECTED_PAIR_IP)) {
            mesh_ice_init_peer(mesh, peer);
        }
        peer = peer->next;
    }

    return MESH_OK;
}

int mesh_ice_disable(mesh_network_t *mesh) {
    mesh_peer_t *peer = NULL;

    if (!mesh) {
        return MESH_ERR_INVALID_ARG;
    }
    if (!mesh->ice_enabled && !mesh->ice_ctx) {
        return MESH_OK;
    }

    mesh->ice_enabled = 0;
    peer = mesh->peers;
    while (peer) {
        mesh_peer_refresh_negotiated_capabilities(peer);
        if (peer->p2p_peer) {
            mesh_send_hello(mesh, peer->p2p_peer);
        }
        peer = peer->next;
    }

    mesh_ice_shutdown_all(mesh);
    if (mesh->ice_ctx) {
        mesh_ice_drain_context(mesh->ice_ctx, MESH_ICE_SHUTDOWN_DRAIN_MS);
    }

    peer = mesh->peers;
    while (peer) {
        mesh_ice_destroy_peer(peer);
        peer = peer->next;
    }

    peer = mesh->retired_peers;
    while (peer) {
        mesh_ice_destroy_peer(peer);
        peer = peer->next;
    }

    if (mesh->ice_ctx) {
        /* UDP socket close callbacks must run before the backend is destroyed. */
        coro_context_stop(mesh->ice_ctx);
        mesh_ice_drain_context(mesh->ice_ctx, MESH_ICE_CLOSE_DRAIN_MS);
        coro_context_destroy(mesh->ice_ctx);
        mesh->ice_ctx = NULL;
    }

    return MESH_OK;
}

int mesh_stream_admission_enable(mesh_network_t *mesh) {
    mesh_peer_t *peer = NULL;

    if (!mesh) {
        return MESH_ERR_INVALID_ARG;
    }
    if (mesh->stream_enabled) {
        return MESH_OK;
    }

    mesh->stream_enabled = 1;
    peer = mesh->peers;
    while (peer) {
        mesh_peer_refresh_negotiated_capabilities(peer);
        if (peer->p2p_peer) {
            mesh_send_hello(mesh, peer->p2p_peer);
        }
        peer = peer->next;
    }

    return MESH_OK;
}

int mesh_stream_admission_disable(mesh_network_t *mesh) {
    mesh_peer_t *peer = NULL;

    if (!mesh) {
        return MESH_ERR_INVALID_ARG;
    }
    if (!mesh->stream_enabled) {
        return MESH_OK;
    }

    mesh->stream_enabled = 0;
    peer = mesh->peers;
    while (peer) {
        mesh_peer_refresh_negotiated_capabilities(peer);
        if (peer->p2p_peer) {
            mesh_send_hello(mesh, peer->p2p_peer);
        }
        peer = peer->next;
    }

    return MESH_OK;
}

static int mesh_config_array_is_valid(const void *items, int count) {
    return count >= 0 && (count == 0 || items != NULL);
}

void mesh_config_init(mesh_config_t *config) {
    if (!config) return;

    memset(config, 0, sizeof(mesh_config_t));
    config->virtual_prefix = 16;
    config->listen_port = MESH_DEFAULT_PORT;
}

mesh_network_t *mesh_create(const mesh_config_t *config) {
    mesh_ice_config_t ice_config;

    if (!config || !config->virtual_ip ||
        !mesh_config_array_is_valid(config->bootstrap_peers, config->bootstrap_count) ||
        !mesh_config_array_is_valid(config->ice_stun_servers, config->ice_stun_count) ||
        !mesh_config_array_is_valid(config->route_rules, config->route_rule_count) ||
        !mesh_config_array_is_valid(config->local_egress_cidrs, config->local_egress_count) ||
        !mesh_config_array_is_valid(config->local_egress_allow_cidrs,
                                    config->local_egress_allow_count) ||
        !mesh_config_array_is_valid(config->magic_dns_records, config->magic_dns_record_count) ||
        !mesh_config_array_is_valid(config->peer_allow_cidrs, config->peer_allow_count) ||
        !mesh_config_array_is_valid(config->peer_allow_node_ids,
                                    config->peer_allow_node_id_count) ||
        !mesh_config_array_is_valid(config->packet_policy_rules,
                                    config->packet_policy_rule_count)) {
        return NULL;
    }

    mesh_network_t *mesh = (mesh_network_t *)calloc(1, sizeof(mesh_network_t));
    if (!mesh) return NULL;

    /* Copy configuration */
    strncpy(mesh->virtual_ip, config->virtual_ip, sizeof(mesh->virtual_ip) - 1);
    mesh->virtual_prefix = config->virtual_prefix;
    if (config->advertise_ip) {
        strncpy(mesh->advertise_ip, config->advertise_ip, sizeof(mesh->advertise_ip) - 1);
    }

    if (config->network_id) {
        strncpy(mesh->network_id, config->network_id, sizeof(mesh->network_id) - 1);
    } else {
        strcpy(mesh->network_id, "default");
    }

    if (config->magic_dns_domain && config->magic_dns_domain[0] != '\0') {
        if (!mesh_magic_dns_normalize_name(config->magic_dns_domain,
                                           mesh->magic_dns_domain,
                                           sizeof(mesh->magic_dns_domain)) ||
            !mesh_magic_dns_name_valid(mesh->magic_dns_domain)) {
            mesh_destroy(mesh);
            return NULL;
        }
    }

    if (config->magic_dns_records && config->magic_dns_record_count > 0) {
        mesh->magic_dns_records =
            (mesh_magic_dns_entry_t *)calloc((size_t)config->magic_dns_record_count,
                                             sizeof(mesh_magic_dns_entry_t));
        if (!mesh->magic_dns_records) {
            mesh_destroy(mesh);
            return NULL;
        }

        mesh->magic_dns_record_count = config->magic_dns_record_count;
        for (int i = 0; i < config->magic_dns_record_count; i++) {
            const mesh_magic_dns_record_t *src = &config->magic_dns_records[i];
            mesh_magic_dns_entry_t *dst = &mesh->magic_dns_records[i];
            uint32_t ip = 0;

            if (!src->name || !src->virtual_ip ||
                !mesh_magic_dns_normalize_name(src->name, dst->name, sizeof(dst->name)) ||
                !mesh_magic_dns_name_valid(dst->name)) {
                mesh_destroy(mesh);
                return NULL;
            }

            ip = ip_str_to_uint32(src->virtual_ip);
            if (ip == 0 || !mesh_ip_in_virtual_network(mesh, ip)) {
                mesh_destroy(mesh);
                return NULL;
            }
            strncpy(dst->virtual_ip, src->virtual_ip, sizeof(dst->virtual_ip) - 1);
        }
    }

    /* Copy bootstrap peers */
    if (config->bootstrap_peers && config->bootstrap_count > 0) {
        mesh->bootstrap_peers =
            (char **)calloc((size_t)config->bootstrap_count, sizeof(char *));
        if (!mesh->bootstrap_peers) {
            mesh_destroy(mesh);
            return NULL;
        }
        mesh->bootstrap_count = config->bootstrap_count;
        for (int i = 0; i < config->bootstrap_count; i++) {
            const char *src = config->bootstrap_peers[i];

            if (!src || src[0] == '\0') {
                mesh_destroy(mesh);
                return NULL;
            }
            mesh->bootstrap_peers[i] = strdup(src);
            if (!mesh->bootstrap_peers[i]) {
                mesh_destroy(mesh);
                return NULL;
            }
        }
    }

    memset(&ice_config, 0, sizeof(ice_config));
    ice_config.stun_servers = config->ice_stun_servers;
    ice_config.stun_server_count = config->ice_stun_count;
    ice_config.allow_loopback = config->ice_allow_loopback;
    if (mesh_ice_setup(mesh, &ice_config) != MESH_OK) {
        mesh_destroy(mesh);
        return NULL;
    }

    if (config->route_rules && config->route_rule_count > 0) {
        mesh->route_rules = (mesh_route_rule_entry_t *)calloc((size_t)config->route_rule_count,
                                                              sizeof(mesh_route_rule_entry_t));
        if (!mesh->route_rules) {
            mesh_destroy(mesh);
            return NULL;
        }

        mesh->route_rule_count = config->route_rule_count;
        for (int i = 0; i < config->route_rule_count; i++) {
            const mesh_route_rule_t *src = &config->route_rules[i];
            mesh_route_rule_entry_t *dst = &mesh->route_rules[i];

            if (!src->dest_cidr || !src->next_hop_virtual_ip ||
                src->flags != MESH_ROUTE_RULE_PINNED ||
                !mesh_parse_route_cidr(src->dest_cidr, &dst->network_ip, &dst->mask,
                                       &dst->prefix_len)) {
                mesh_destroy(mesh);
                return NULL;
            }

            strncpy(dst->dest_cidr, src->dest_cidr, sizeof(dst->dest_cidr) - 1);
            strncpy(dst->next_hop_virtual_ip, src->next_hop_virtual_ip,
                    sizeof(dst->next_hop_virtual_ip) - 1);
            dst->flags = src->flags;
        }
    }

    if (config->local_egress_cidrs && config->local_egress_count > 0) {
        mesh->local_egress_cidrs =
            (mesh_local_egress_entry_t *)calloc((size_t)config->local_egress_count,
                                                sizeof(mesh_local_egress_entry_t));
        if (!mesh->local_egress_cidrs) {
            mesh_destroy(mesh);
            return NULL;
        }

        mesh->local_egress_count = config->local_egress_count;
        for (int i = 0; i < config->local_egress_count; i++) {
            mesh_local_egress_entry_t *dst = &mesh->local_egress_cidrs[i];
            const char *src = config->local_egress_cidrs[i];

            if (!src || !mesh_parse_route_cidr(src, &dst->network_ip, &dst->mask,
                                               &dst->prefix_len)) {
                mesh_destroy(mesh);
                return NULL;
            }

            strncpy(dst->cidr, src, sizeof(dst->cidr) - 1);
        }
    }

    if (config->local_egress_allow_cidrs && config->local_egress_allow_count > 0) {
        mesh->local_egress_allow_cidrs =
            (mesh_peer_acl_entry_t *)calloc((size_t)config->local_egress_allow_count,
                                            sizeof(mesh_peer_acl_entry_t));
        if (!mesh->local_egress_allow_cidrs) {
            mesh_destroy(mesh);
            return NULL;
        }

        mesh->local_egress_allow_count = config->local_egress_allow_count;
        for (int i = 0; i < config->local_egress_allow_count; i++) {
            mesh_peer_acl_entry_t *dst = &mesh->local_egress_allow_cidrs[i];
            const char *src = config->local_egress_allow_cidrs[i];

            if (!src || !mesh_parse_route_cidr(src, &dst->network_ip, &dst->mask,
                                               &dst->prefix_len)) {
                mesh_destroy(mesh);
                return NULL;
            }

            strncpy(dst->cidr, src, sizeof(dst->cidr) - 1);
        }
    }

    if (config->peer_allow_cidrs && config->peer_allow_count > 0) {
        mesh->peer_allow_cidrs = (mesh_peer_acl_entry_t *)calloc((size_t)config->peer_allow_count,
                                                                 sizeof(mesh_peer_acl_entry_t));
        if (!mesh->peer_allow_cidrs) {
            mesh_destroy(mesh);
            return NULL;
        }

        mesh->peer_allow_count = config->peer_allow_count;
        for (int i = 0; i < config->peer_allow_count; i++) {
            mesh_peer_acl_entry_t *dst = &mesh->peer_allow_cidrs[i];
            const char *src = config->peer_allow_cidrs[i];

            if (!src || !mesh_parse_route_cidr(src, &dst->network_ip, &dst->mask,
                                               &dst->prefix_len)) {
                mesh_destroy(mesh);
                return NULL;
            }

            strncpy(dst->cidr, src, sizeof(dst->cidr) - 1);
        }
    }

    if (config->peer_allow_node_ids && config->peer_allow_node_id_count > 0) {
        mesh->peer_allow_node_ids =
            (mesh_peer_identity_acl_entry_t *)calloc((size_t)config->peer_allow_node_id_count,
                                                     sizeof(mesh_peer_identity_acl_entry_t));
        if (!mesh->peer_allow_node_ids) {
            mesh_destroy(mesh);
            return NULL;
        }

        mesh->peer_allow_node_id_count = config->peer_allow_node_id_count;
        for (int i = 0; i < config->peer_allow_node_id_count; i++) {
            mesh_peer_identity_acl_entry_t *dst = &mesh->peer_allow_node_ids[i];
            const char *src = config->peer_allow_node_ids[i];
            size_t j = 0;

            if (!src || strlen(src) != 64) {
                mesh_destroy(mesh);
                return NULL;
            }

            for (j = 0; j < 64; j++) {
                if (!isxdigit((unsigned char)src[j])) {
                    mesh_destroy(mesh);
                    return NULL;
                }
            }

            strncpy(dst->node_id, src, sizeof(dst->node_id) - 1);
        }
    }

    if (config->peer_protocol_major > UINT16_MAX) {
        mesh_destroy(mesh);
        return NULL;
    }
    mesh->peer_protocol_major = config->peer_protocol_major;

    if (config->packet_policy_rules && config->packet_policy_rule_count > 0) {
        mesh->packet_policy_rules =
            (mesh_packet_policy_entry_t *)calloc((size_t)config->packet_policy_rule_count,
                                                 sizeof(mesh_packet_policy_entry_t));
        if (!mesh->packet_policy_rules) {
            mesh_destroy(mesh);
            return NULL;
        }

        mesh->packet_policy_rule_count = config->packet_policy_rule_count;
        for (int i = 0; i < config->packet_policy_rule_count; i++) {
            const mesh_packet_policy_rule_t *src = &config->packet_policy_rules[i];
            mesh_packet_policy_entry_t *dst = &mesh->packet_policy_rules[i];
            const char *src_cidr = (src->src_cidr && src->src_cidr[0]) ?
                src->src_cidr : "0.0.0.0/0";
            const char *dst_cidr = (src->dst_cidr && src->dst_cidr[0]) ?
                src->dst_cidr : "0.0.0.0/0";

            dst->directions = src->directions ? src->directions : MESH_PACKET_POLICY_ANY;
            dst->directions &= MESH_PACKET_POLICY_ANY;
            if (dst->directions == 0 ||
                !mesh_parse_route_cidr(src_cidr, &dst->src_network_ip, &dst->src_mask,
                                       &dst->src_prefix_len) ||
                !mesh_parse_route_cidr(dst_cidr, &dst->dst_network_ip, &dst->dst_mask,
                                       &dst->dst_prefix_len)) {
                mesh_destroy(mesh);
                return NULL;
            }

            if ((src->src_port_start == 0 && src->src_port_end != 0) ||
                (src->dst_port_start == 0 && src->dst_port_end != 0)) {
                mesh_destroy(mesh);
                return NULL;
            }

            dst->ip_proto = src->ip_proto;
            dst->src_port_start = src->src_port_start;
            dst->src_port_end = src->src_port_end ? src->src_port_end : src->src_port_start;
            dst->dst_port_start = src->dst_port_start;
            dst->dst_port_end = src->dst_port_end ? src->dst_port_end : src->dst_port_start;
            if ((dst->src_port_start != 0 && dst->src_port_start > dst->src_port_end) ||
                (dst->dst_port_start != 0 && dst->dst_port_start > dst->dst_port_end)) {
                mesh_destroy(mesh);
                return NULL;
            }

            strncpy(dst->src_cidr, src_cidr, sizeof(dst->src_cidr) - 1);
            strncpy(dst->dst_cidr, dst_cidr, sizeof(dst->dst_cidr) - 1);
            dst->allow = src->allow ? 1 : 0;
        }
    }

    /* Callbacks */
    mesh->on_peer_connected = config->on_peer_connected;
    mesh->on_peer_disconnected = config->on_peer_disconnected;
    mesh->on_packet_received = config->on_packet_received;
    mesh->user_data = config->user_data;

    /* Create P2P node */
    mesh->listen_port = config->listen_port > 0 ? config->listen_port : MESH_DEFAULT_PORT;
    if (mesh_create_p2p_node(mesh) != MESH_OK) {
        mesh_destroy(mesh);
        return NULL;
    }
    if (config->identity_secret_hex) {
        uint8_t identity_secret[P2P_KEY_SIZE];

        if (!mesh_hex_to_bytes(config->identity_secret_hex,
                               identity_secret,
                               sizeof(identity_secret)) ||
            p2p_node_set_private_key(mesh->p2p_node, identity_secret) != P2P_OK) {
            mesh_destroy(mesh);
            return NULL;
        }
        memset(identity_secret, 0, sizeof(identity_secret));
    }
    if (!mesh_update_node_id_from_p2p(mesh)) {
        mesh_destroy(mesh);
        return NULL;
    }
    if (config->enable_ice && mesh_ice_enable(mesh) != MESH_OK) {
        mesh_destroy(mesh);
        return NULL;
    }

    return mesh;
}

void mesh_destroy(mesh_network_t *mesh) {
    if (!mesh) return;

    (void)mesh_ice_disable(mesh);

    if (mesh->mgmt_router) {
        mesh_mgmt_agent_router_v1_t *router = mesh->mgmt_router;
        mesh_mgmt_agent_router_result_t result =
            mesh_mgmt_mesh_router_detach_v1(mesh, router);
        if (result != MESH_MGMT_AGENT_ROUTER_OK) {
            TLOG_ERROR("Failed to detach management router during mesh destroy: {}",
                       (int)result);
        }
    }

    /* Destroy P2P node first so no more peer callbacks race with teardown. */
    if (mesh->p2p_node) {
        mesh_disconnect_all_p2p_peers(mesh);
        p2p_destroy(mesh->p2p_node);
        mesh->p2p_node = NULL;
    }

    /* Destroy routing table */
    mesh_route_t *route = mesh->routes;
    while (route) {
        mesh_route_t *next = route->next;
        mesh_route_destroy(route);
        route = next;
    }

    /* Destroy peers */
    mesh_peer_t *peer = mesh->peers;
    while (peer) {
        mesh_peer_t *next = peer->next;
        mesh_peer_destroy(peer);
        peer = next;
    }

    peer = mesh->retired_peers;
    while (peer) {
        mesh_peer_t *next = peer->next;
        mesh_peer_destroy(peer);
        peer = next;
    }

    /* Free bootstrap peers */
    if (mesh->bootstrap_peers) {
        for (int i = 0; i < mesh->bootstrap_count; i++) {
            free(mesh->bootstrap_peers[i]);
        }
        free(mesh->bootstrap_peers);
    }

    mesh_ice_free_stun_servers(mesh->ice_stun_servers, mesh->ice_stun_count);

    free(mesh->route_rules);
    free(mesh->local_egress_cidrs);
    free(mesh->local_egress_allow_cidrs);
    free(mesh->peer_allow_cidrs);
    free(mesh->peer_allow_node_ids);
    free(mesh->magic_dns_records);
    mesh_flow_runtime_destroy_v1(&mesh->runtime_flow_policy);
    free(mesh->packet_policy_rules);

    free(mesh);
}

p2p_node_t *mesh_mgmt_mesh_borrow_p2p_node_v1(mesh_network_t *mesh) {
    return mesh ? mesh->p2p_node : NULL;
}

mesh_mgmt_agent_router_result_t
mesh_mgmt_mesh_router_attach_v1(mesh_network_t *mesh,
                               mesh_mgmt_agent_router_v1_t *router) {
    mesh_mgmt_agent_router_result_t result;

    if (!mesh || !router)
        return MESH_MGMT_AGENT_ROUTER_INVALID_ARG;
    if (mesh->p2p_running || mesh->mgmt_router ||
        router->node != mesh->p2p_node ||
        router->state != MESH_MGMT_AGENT_ROUTER_READY)
        return MESH_MGMT_AGENT_ROUTER_INVALID_STATE;

    result = mesh_mgmt_agent_router_start_embedded_v1(router);
    if (result != MESH_MGMT_AGENT_ROUTER_OK)
        return result;
    mesh->mgmt_router = router;
    return MESH_MGMT_AGENT_ROUTER_OK;
}

mesh_mgmt_agent_router_result_t
mesh_mgmt_mesh_router_detach_v1(mesh_network_t *mesh,
                               mesh_mgmt_agent_router_v1_t *router) {
    mesh_mgmt_agent_router_result_t result;

    if (!mesh || !router)
        return MESH_MGMT_AGENT_ROUTER_INVALID_ARG;
    if (mesh->mgmt_router != router)
        return MESH_MGMT_AGENT_ROUTER_INVALID_STATE;

    mesh->mgmt_router = NULL;
    result = mesh_mgmt_agent_router_stop_v1(router);
    if (result != MESH_MGMT_AGENT_ROUTER_OK)
        mesh->mgmt_router = router;
    return result;
}

/* =============================================================================
 * P2P Thread
 * ============================================================================= */



int mesh_start(mesh_network_t *mesh) {
    if (!mesh) return MESH_ERR_INVALID_ARG;

    /* Start P2P in non-blocking mode */
    TLOG_INFO("Starting P2P node...");
    int ret = p2p_start_nonblocking(mesh->p2p_node);
    if (ret != P2P_OK) {
        TLOG_ERROR("Failed to start P2P node");
        return MESH_ERR_NETWORK;
    }

    /* NOTE: P2P event loop will be pumped by mesh_poll() in the MAIN thread */
    mesh->p2p_running = 1;

    if (mesh->bootstrap_count <= 0) {
        mesh_register_virtual_ip(mesh);
    } else {
        TLOG_INFO("Deferring virtual IP registration until mesh bootstrap completes");
    }

    mesh_connect_bootstrap_peers(mesh, 0);

    return MESH_OK;
}

void mesh_stop(mesh_network_t *mesh) {
    if (!mesh) return;

    mesh_disconnect_all_p2p_peers(mesh);

    /* Mark any remaining peer wrappers disconnected. P2P callbacks remove the
     * normal live peers; this covers wrappers without an active transport. */
    mesh_peer_t *peer = mesh->peers;
    while (peer) {
        if (peer->announced && peer->is_connected && mesh->on_peer_disconnected) {
            mesh->on_peer_disconnected(peer, mesh->user_data);
        }
        peer->is_connected = 0;
        peer = peer->next;
    }

    mesh_cleanup_retired_peers(mesh);
}

/* =============================================================================
 * Packet Routing
 * ============================================================================= */

int mesh_send_packet(mesh_network_t *mesh, const uint8_t *data, size_t len) {
    if (!mesh || !data || len == 0) return MESH_ERR_INVALID_ARG;

    /* Extract destination IP */
    uint32_t dst_ip = extract_dst_ip(data, len);
    if (dst_ip == 0) return MESH_ERR_INVALID_ARG;

    char dst_ip_str[16];
    mesh_next_hop_result_t next_hop_result;
    mesh_peer_t *send_to_peer = NULL;
    int dst_in_virtual_network = 0;
    uint32_to_ip_str(dst_ip, dst_ip_str);

    TLOG_DEBUG("Routing packet to {}", dst_ip_str);

    if (mesh_ip_is_multicast(dst_ip)) {
        TLOG_DEBUG("Dropping multicast packet: {}", dst_ip_str);
        return MESH_ERR_NOT_FOUND;
    }
    if (!mesh_packet_policy_allows(mesh, MESH_PACKET_POLICY_OUT, data, len)) {
        TLOG_DEBUG("Dropping outbound packet to {} blocked by packet policy", dst_ip_str);
        return MESH_ERR_NOT_FOUND;
    }

    dst_in_virtual_network = mesh_ip_in_virtual_network(mesh, dst_ip);
    next_hop_result = mesh_next_hop_resolve(mesh, dst_ip_str, 1);
    if (next_hop_result.kind == MESH_NEXT_HOP_POLICY) {
        send_to_peer = next_hop_result.peer;
        if (!send_to_peer) {
            TLOG_DEBUG("Pinned route matched {} but next hop {} is unavailable",
                       dst_ip_str, next_hop_result.rule->next_hop_virtual_ip);
            return MESH_ERR_NOT_FOUND;
        }

        TLOG_DEBUG("Pinned route matched {} via {}",
                   dst_ip_str, next_hop_result.rule->next_hop_virtual_ip);
        if (strcmp(send_to_peer->virtual_ip, dst_ip_str) != 0) {
            mesh_note_active_relay_next_hop(mesh, send_to_peer);
        }
    } else if (next_hop_result.kind == MESH_NEXT_HOP_DIRECT) {
        send_to_peer = next_hop_result.peer;
        TLOG_DEBUG("Found direct peer with virtual_ip={}", send_to_peer->virtual_ip);
    } else if (next_hop_result.kind == MESH_NEXT_HOP_LEARNED) {
        mesh_route_t *route = next_hop_result.route;
        mesh_peer_t *next_hop = next_hop_result.peer;

        if (mesh->ice_enabled && route && next_hop->announced &&
            strcmp(next_hop->virtual_ip, dst_ip_str) != 0) {
            (void)mesh_try_routed_ice_connect(mesh, dst_ip_str, 0);
        }
        if (next_hop->announced && route && route->dest_real_ip[0] != '\0') {
            (void)mesh_try_direct_connect(mesh, dst_ip_str, route->dest_real_ip, 0);
        }
        TLOG_DEBUG("Routing packet to {} via {}", dst_ip_str, next_hop->virtual_ip);
        mesh_note_active_relay_next_hop(mesh, next_hop);
        send_to_peer = next_hop;
    } else {
        mesh_peer_t *p = NULL;
        char dht_key[128];
        char dht_value[256] = {0};
        size_t dht_len = sizeof(dht_value) - 1u; /* reserve room for NUL */

        if (!dst_in_virtual_network) {
            TLOG_DEBUG("Dropping non-mesh packet {} without pinned route policy", dst_ip_str);
            return MESH_ERR_NOT_FOUND;
        }

        TLOG_DEBUG("No route found for {}", dst_ip_str);
        TLOG_DEBUG("Known peers:");
        p = mesh->peers;
        while (p) {
            TLOG_DEBUG("  - virtual_ip={}, connected={}", p->virtual_ip, p->is_connected);
            p = p->next;
        }

        if (!mesh_has_connected_peers(mesh)) {
            TLOG_DEBUG("No peers available for DHT discovery of {}", dst_ip_str);
            return MESH_ERR_NOT_FOUND;
        }
        if (!mesh_policy_allows_virtual_ip(mesh, MESH_POLICY_DIRECT_CONNECT, dst_ip_str)) {
            TLOG_DEBUG("Direct connect to {} blocked by peer admission policy",
                       dst_ip_str);
            return MESH_ERR_NOT_FOUND;
        }

        fmt(dht_key, sizeof(dht_key), "mesh:{}:ip:{}",
                       mesh->network_id, dst_ip_str);

        if (p2p_dht_get(mesh->p2p_node, dht_key, dht_value, &dht_len) == P2P_OK) {
            /* kademlia_find_value does not NUL-terminate; ensure it. */
            dht_value[dht_len] = '\0';
            char peer_ip[64];
            int peer_port;

            if (sscanf(dht_value, "%63[^:]:%d", peer_ip, &peer_port) == 2) {
                p2p_connect(mesh->p2p_node, peer_ip, peer_port);
            }
        }
    }

    if (!send_to_peer) {
        return MESH_ERR_NOT_FOUND;
    }

    int ret = mesh_send_to_peer(send_to_peer, data, len);
    if (ret == MESH_OK) {
        mesh->stats.bytes_tx += len;
        mesh->stats.packets_tx++;
        send_to_peer->bytes_tx += len;
    }

    return ret;
}

int mesh_poll(mesh_network_t *mesh, int timeout_ms) {
    if (!mesh) return -1;

    /* Run P2P event loop in non-blocking mode (single iteration) */
    /* This ensures all P2P callbacks run in the SAME thread as mesh_poll */
    coro_context_t *ctx = p2p_get_loop(mesh->p2p_node);
    if (ctx) {
        coro_context_run(ctx, TURBO_RUN_NOWAIT);
    }
    if (mesh->ice_ctx) {
        coro_context_run(mesh->ice_ctx, TURBO_RUN_NOWAIT);
    }
    mesh_cleanup_retired_peers(mesh);
    if (mesh_refresh_stream_metrics(mesh)) {
        mesh_path_observer_evaluate(mesh);
    }
    mesh_route_expire_stale(mesh);

    /* Periodic route discovery every 100 poll cycles (~10 seconds if polled every 100ms) */
    mesh->poll_count++;
    if (!mesh_has_connected_peers(mesh) && mesh->bootstrap_count > 0) {
        mesh->reconnect_poll_count++;
        if (mesh->reconnect_poll_count >= 50) {
            mesh->reconnect_poll_count = 0;
            strncpy(mesh->last_reconnect_reason, "poll-no-peers",
                    sizeof(mesh->last_reconnect_reason) - 1);
            mesh_connect_bootstrap_peers(mesh, 1);
        }
    } else {
        mesh->reconnect_poll_count = 0;
    }

    if (mesh->bootstrap_reconnect_pending) {
        mesh->bootstrap_reconnect_pending = 0;
        mesh->reconnect_poll_count = 0;
        if (mesh->last_reconnect_reason[0] == '\0') {
            strncpy(mesh->last_reconnect_reason, "control-plane-request",
                    sizeof(mesh->last_reconnect_reason) - 1);
        }
        mesh_connect_bootstrap_peers(mesh, 1);
    }

    if (mesh->control_plane_dirty) {
        mesh->control_plane_dirty = 0;
        mesh->control_plane_refreshes++;
        mesh_publish_routes(mesh);
        mesh_discover_routes(mesh);
        mesh_broadcast_routes(mesh);
    }

    if (mesh->poll_count >= 100) {
        mesh->poll_count = 0;
        mesh->control_plane_refreshes++;

        /* Publish our routes to DHT */
        mesh_publish_routes(mesh);

        /* Discover routes from neighbors */
        mesh_discover_routes(mesh);
        mesh_broadcast_routes(mesh);
    }

    (void)timeout_ms;
    return 0;
}

/* =============================================================================
 * Peer Management API
 * ============================================================================= */

int mesh_get_peer_count(mesh_network_t *mesh) {
    if (!mesh) return 0;
    return mesh->peer_count;
}

int mesh_get_peer_info(mesh_network_t *mesh, int index, mesh_peer_info_t *info) {
    if (!mesh || !info || index < 0 || index >= mesh->peer_count) {
        return MESH_ERR_INVALID_ARG;
    }

    mesh_peer_t *peer = mesh->peers;
    for (int i = 0; i < index && peer; i++) {
        peer = peer->next;
    }

    if (!peer) return MESH_ERR_NOT_FOUND;

    memset(info, 0, sizeof(*info));
    strncpy(info->virtual_ip, peer->virtual_ip, sizeof(info->virtual_ip) - 1);
    strncpy(info->real_ip, peer->real_ip, sizeof(info->real_ip) - 1);
    strncpy(info->node_id, peer->peer_id, sizeof(info->node_id) - 1);
    info->protocol_major = peer->protocol_major;
    info->protocol_minor = peer->protocol_minor;
    info->capabilities = peer->capabilities;
    info->negotiated_capabilities = peer->negotiated_capabilities;
    info->is_connected = peer->is_connected;
    info->bytes_tx = peer->bytes_tx;
    info->bytes_rx = peer->bytes_rx;
    info->last_seen_ms = peer->last_seen_ms;

    return MESH_OK;
}

int mesh_get_route_count(mesh_network_t *mesh) {
    if (!mesh) {
        return 0;
    }
    mesh_route_expire_stale(mesh);
    return mesh->route_count;
}

int mesh_get_route_info(mesh_network_t *mesh, int index, mesh_route_info_t *info) {
    mesh_route_t *route = NULL;

    if (!mesh || !info || index < 0) {
        return MESH_ERR_INVALID_ARG;
    }
    mesh_route_expire_stale(mesh);
    if (index >= mesh->route_count) {
        return MESH_ERR_INVALID_ARG;
    }

    route = mesh->routes;
    for (int i = 0; i < index && route; i++) {
        route = route->next;
    }

    if (!route) {
        return MESH_ERR_NOT_FOUND;
    }

    memset(info, 0, sizeof(*info));
    strncpy(info->dest_ip, route->dest_ip, sizeof(info->dest_ip) - 1);
    strncpy(info->dest_real_ip, route->dest_real_ip, sizeof(info->dest_real_ip) - 1);
    info->hop_count = route->hop_count;
    info->last_update_ms = route->last_update_ms;
    strncpy(info->next_hop_virtual_ip, route->next_hop_virtual_ip,
            sizeof(info->next_hop_virtual_ip) - 1);

    if (route->next_hop) {
        strncpy(info->next_hop_virtual_ip, route->next_hop->virtual_ip,
                sizeof(info->next_hop_virtual_ip) - 1);
        strncpy(info->next_hop_real_ip, route->next_hop->real_ip,
                sizeof(info->next_hop_real_ip) - 1);
        info->is_connected = route->next_hop->is_connected;
    }

    return MESH_OK;
}

int mesh_get_route_rule_count(mesh_network_t *mesh) {
    if (!mesh) {
        return 0;
    }

    return mesh->route_rule_count;
}

int mesh_get_route_rule_info(mesh_network_t *mesh, int index, mesh_route_rule_info_t *info) {
    mesh_route_rule_entry_t *rule = NULL;

    if (!mesh || !info || index < 0 || index >= mesh->route_rule_count) {
        return MESH_ERR_INVALID_ARG;
    }

    rule = &mesh->route_rules[index];
    memset(info, 0, sizeof(*info));
    strncpy(info->dest_cidr, rule->dest_cidr, sizeof(info->dest_cidr) - 1);
    strncpy(info->next_hop_virtual_ip, rule->next_hop_virtual_ip,
            sizeof(info->next_hop_virtual_ip) - 1);
    info->flags = rule->flags;
    return MESH_OK;
}

int mesh_get_local_egress_count(mesh_network_t *mesh) {
    if (!mesh) {
        return 0;
    }

    return mesh->local_egress_count;
}

int mesh_get_local_egress_info(mesh_network_t *mesh, int index,
                               mesh_local_egress_info_t *info) {
    mesh_local_egress_entry_t *entry = NULL;

    if (!mesh || !info || index < 0 || index >= mesh->local_egress_count) {
        return MESH_ERR_INVALID_ARG;
    }

    entry = &mesh->local_egress_cidrs[index];
    memset(info, 0, sizeof(*info));
    strncpy(info->cidr, entry->cidr, sizeof(info->cidr) - 1);
    return MESH_OK;
}

int mesh_get_local_egress_allow_count(mesh_network_t *mesh) {
    if (!mesh) {
        return 0;
    }

    return mesh->local_egress_allow_count;
}

int mesh_get_local_egress_allow_info(mesh_network_t *mesh, int index,
                                     mesh_local_egress_allow_info_t *info) {
    mesh_peer_acl_entry_t *entry = NULL;

    if (!mesh || !info || index < 0 || index >= mesh->local_egress_allow_count) {
        return MESH_ERR_INVALID_ARG;
    }

    entry = &mesh->local_egress_allow_cidrs[index];
    memset(info, 0, sizeof(*info));
    strncpy(info->cidr, entry->cidr, sizeof(info->cidr) - 1);
    return MESH_OK;
}

int mesh_get_peer_allow_count(mesh_network_t *mesh) {
    if (!mesh) {
        return 0;
    }

    return mesh->peer_allow_count;
}

int mesh_get_peer_allow_info(mesh_network_t *mesh, int index, mesh_peer_allow_info_t *info) {
    mesh_peer_acl_entry_t *entry = NULL;

    if (!mesh || !info || index < 0 || index >= mesh->peer_allow_count) {
        return MESH_ERR_INVALID_ARG;
    }

    entry = &mesh->peer_allow_cidrs[index];
    memset(info, 0, sizeof(*info));
    strncpy(info->cidr, entry->cidr, sizeof(info->cidr) - 1);
    return MESH_OK;
}

int mesh_get_peer_allow_node_id_count(mesh_network_t *mesh) {
    if (!mesh) {
        return 0;
    }

    return mesh->peer_allow_node_id_count;
}

int mesh_get_peer_allow_node_info(mesh_network_t *mesh, int index,
                                  mesh_peer_allow_node_info_t *info) {
    mesh_peer_identity_acl_entry_t *entry = NULL;

    if (!mesh || !info || index < 0 || index >= mesh->peer_allow_node_id_count) {
        return MESH_ERR_INVALID_ARG;
    }

    entry = &mesh->peer_allow_node_ids[index];
    memset(info, 0, sizeof(*info));
    strncpy(info->node_id, entry->node_id, sizeof(info->node_id) - 1);
    return MESH_OK;
}

unsigned int mesh_get_peer_protocol_major(mesh_network_t *mesh) {
    if (!mesh) {
        return 0;
    }

    return mesh->peer_protocol_major;
}

int mesh_get_packet_policy_count(mesh_network_t *mesh) {
    if (!mesh) {
        return 0;
    }

    return mesh->packet_policy_rule_count;
}

int mesh_get_packet_policy_info(mesh_network_t *mesh, int index,
                                mesh_packet_policy_info_t *info) {
    mesh_packet_policy_entry_t *entry = NULL;

    if (!mesh || !info || index < 0 || index >= mesh->packet_policy_rule_count) {
        return MESH_ERR_INVALID_ARG;
    }

    entry = &mesh->packet_policy_rules[index];
    memset(info, 0, sizeof(*info));
    strncpy(info->src_cidr, entry->src_cidr, sizeof(info->src_cidr) - 1);
    strncpy(info->dst_cidr, entry->dst_cidr, sizeof(info->dst_cidr) - 1);
    info->ip_proto = entry->ip_proto;
    info->src_port_start = entry->src_port_start;
    info->src_port_end = entry->src_port_end;
    info->dst_port_start = entry->dst_port_start;
    info->dst_port_end = entry->dst_port_end;
    info->directions = entry->directions;
    info->allow = entry->allow;
    return MESH_OK;
}

int mesh_get_magic_dns_count(mesh_network_t *mesh) {
    if (!mesh) {
        return 0;
    }

    return mesh->magic_dns_record_count;
}

int mesh_get_magic_dns_info(mesh_network_t *mesh, int index,
                            mesh_magic_dns_info_t *info) {
    mesh_magic_dns_entry_t *entry = NULL;

    if (!mesh || !info || index < 0 || index >= mesh->magic_dns_record_count) {
        return MESH_ERR_INVALID_ARG;
    }

    entry = &mesh->magic_dns_records[index];
    memset(info, 0, sizeof(*info));
    strncpy(info->name, entry->name, sizeof(info->name) - 1);
    strncpy(info->virtual_ip, entry->virtual_ip, sizeof(info->virtual_ip) - 1);
    return MESH_OK;
}

int mesh_resolve_magic_dns(mesh_network_t *mesh,
                           const char *name,
                           char *virtual_ip,
                           size_t virtual_ip_len) {
    char query[128];

    if (!mesh || !name || !virtual_ip || virtual_ip_len == 0) {
        return MESH_ERR_INVALID_ARG;
    }
    if (!mesh_magic_dns_normalize_name(name, query, sizeof(query)) ||
        !mesh_magic_dns_name_valid(query)) {
        return MESH_ERR_INVALID_ARG;
    }

    for (int i = 0; i < mesh->magic_dns_record_count; i++) {
        const mesh_magic_dns_entry_t *entry = &mesh->magic_dns_records[i];
        if (!mesh_magic_dns_domain_matches(mesh, query, entry->name)) {
            continue;
        }
        if (strlen(entry->virtual_ip) + 1 > virtual_ip_len) {
            return MESH_ERR_INVALID_ARG;
        }
        memset(virtual_ip, 0, virtual_ip_len);
        strncpy(virtual_ip, entry->virtual_ip, virtual_ip_len - 1);
        return MESH_OK;
    }

    return MESH_ERR_NOT_FOUND;
}

int mesh_reverse_magic_dns(mesh_network_t *mesh,
                           const char *virtual_ip,
                           char *name,
                           size_t name_len) {
    char resolved[128];

    if (!mesh || !virtual_ip || !name || name_len == 0) {
        return MESH_ERR_INVALID_ARG;
    }
    if (ip_str_to_uint32(virtual_ip) == 0) {
        return MESH_ERR_INVALID_ARG;
    }

    for (int i = 0; i < mesh->magic_dns_record_count; i++) {
        const mesh_magic_dns_entry_t *entry = &mesh->magic_dns_records[i];
        if (strcmp(entry->virtual_ip, virtual_ip) != 0) {
            continue;
        }
        if (mesh->magic_dns_domain[0] != '\0' && !strchr(entry->name, '.')) {
            fmt(resolved, sizeof(resolved), "{}.{}",
                           entry->name, mesh->magic_dns_domain);
        } else {
            fmt(resolved, sizeof(resolved), "{}", entry->name);
        }
        if (strlen(resolved) + 1 > name_len) {
            return MESH_ERR_INVALID_ARG;
        }
        memset(name, 0, name_len);
        strncpy(name, resolved, name_len - 1);
        return MESH_OK;
    }

    return MESH_ERR_NOT_FOUND;
}

int mesh_get_node_id(mesh_network_t *mesh, char *buf, size_t buf_len) {
    if (!mesh || !buf || buf_len < 65) {
        return MESH_ERR_INVALID_ARG;
    }

    memset(buf, 0, buf_len);
    strncpy(buf, mesh->node_id, buf_len - 1);
    return mesh->node_id[0] != '\0' ? MESH_OK : MESH_ERR_NOT_FOUND;
}

int mesh_get_peer_handle_info(mesh_peer_t *peer, mesh_peer_info_t *info) {
    if (!peer || !info) {
        return MESH_ERR_INVALID_ARG;
    }

    memset(info, 0, sizeof(*info));
    strncpy(info->virtual_ip, peer->virtual_ip, sizeof(info->virtual_ip) - 1);
    strncpy(info->real_ip, peer->real_ip, sizeof(info->real_ip) - 1);
    strncpy(info->node_id, peer->peer_id, sizeof(info->node_id) - 1);
    info->protocol_major = peer->protocol_major;
    info->protocol_minor = peer->protocol_minor;
    info->capabilities = peer->capabilities;
    info->negotiated_capabilities = peer->negotiated_capabilities;
    info->is_connected = peer->is_connected;
    info->bytes_tx = peer->bytes_tx;
    info->bytes_rx = peer->bytes_rx;
    info->last_seen_ms = peer->last_seen_ms;

    return MESH_OK;
}

mesh_flow_runtime_result_t mesh_internal_flow_policy_publish_v1(
    mesh_network_t *mesh, uint64_t committed_index, uint64_t policy_epoch,
    mesh_flow_action_v1_t default_action, const mesh_flow_rule_v1_t *rules,
    size_t rule_count) {
    mesh_flow_runtime_result_t result;

    if (!mesh) {
        return MESH_FLOW_RUNTIME_INVALID_ARG;
    }
    if (!mesh->runtime_flow_policy.open) {
        result = mesh_flow_runtime_init_v1(&mesh->runtime_flow_policy,
                                           MESH_FLOW_RULESET_MAX_RULES,
                                           default_action);
        if (result != MESH_FLOW_RUNTIME_OK) {
            return result;
        }
    }
    return mesh_flow_runtime_publish_v1(&mesh->runtime_flow_policy,
                                        committed_index, policy_epoch,
                                        default_action, rules, rule_count);
}

mesh_flow_runtime_result_t mesh_internal_flow_policy_prepare_v1(
    mesh_network_t *mesh) {
    if (!mesh) {
        return MESH_FLOW_RUNTIME_INVALID_ARG;
    }
    if (mesh->runtime_flow_policy.open) {
        return MESH_FLOW_RUNTIME_OK;
    }
    return mesh_flow_runtime_init_v1(&mesh->runtime_flow_policy,
                                     MESH_FLOW_RULESET_MAX_RULES,
                                     MESH_FLOW_ACTION_DENY);
}

mesh_flow_runtime_result_t mesh_internal_flow_policy_require_v1(
    mesh_network_t *mesh, uint64_t required_index) {
    mesh_flow_runtime_result_t result;

    if (!mesh || required_index == 0u) {
        return MESH_FLOW_RUNTIME_INVALID_ARG;
    }
    if (!mesh->runtime_flow_policy.open) {
        result = mesh_flow_runtime_init_v1(&mesh->runtime_flow_policy,
                                           MESH_FLOW_RULESET_MAX_RULES,
                                           MESH_FLOW_ACTION_DENY);
        if (result != MESH_FLOW_RUNTIME_OK) {
            return result;
        }
    }
    return mesh_flow_runtime_require_index_v1(&mesh->runtime_flow_policy,
                                              required_index);
}

int mesh_peer_stream_ready(const mesh_peer_t *peer) {
    return mesh_peer_stream_binding_is_valid(peer) &&
           mesh_peer_has_capability(peer, MESH_CAP_STREAM_V1);
}

mesh_peer_t *mesh_find_peer(mesh_network_t *mesh, const char *virtual_ip) {
    if (!mesh || !virtual_ip) return NULL;
    return mesh_find_peer_internal(mesh, virtual_ip);
}

int mesh_connect_peer(mesh_network_t *mesh, const char *virtual_ip) {
    mesh_route_t *route = NULL;
    mesh_peer_t *signal_peer = NULL;
    if (!mesh || !virtual_ip) return MESH_ERR_INVALID_ARG;
    if (!mesh_policy_allows_virtual_ip(mesh, MESH_POLICY_DIRECT_CONNECT, virtual_ip)) return MESH_ERR_NOT_FOUND;

    /* Check if already connected */
    mesh_peer_t *peer = mesh_find_peer_internal(mesh, virtual_ip);
    if (peer && peer->is_connected) {
        return MESH_OK;
    }

    route = mesh_route_find(mesh, virtual_ip);
    if (mesh->ice_enabled && route && route->next_hop && route->next_hop->is_connected) {
        if (mesh_try_routed_ice_connect(mesh, virtual_ip, 1)) {
            return MESH_OK;
        }
        signal_peer = mesh_find_peer_any_virtual(mesh, virtual_ip);
        if (mesh_peer_has_inflight_ice(signal_peer)) {
            return MESH_OK;
        }
    }
    if (route && route->dest_real_ip[0] != '\0') {
        if (mesh_try_direct_connect(mesh, virtual_ip, route->dest_real_ip, 1)) {
            return MESH_OK;
        }
    }

    /* Query DHT for peer */
    char dht_key[128];
    fmt(dht_key, sizeof(dht_key), "mesh:{}:ip:{}",
             mesh->network_id, virtual_ip);

    char dht_value[256];
    size_t dht_len = sizeof(dht_value) - 1u; /* reserve room for NUL */

    if (p2p_dht_get(mesh->p2p_node, dht_key, dht_value, &dht_len) != P2P_OK) {
        return MESH_ERR_NOT_FOUND;
    }
    /* kademlia_find_value does not NUL-terminate; ensure it. */
    dht_value[dht_len] = '\0';

    /* Parse and connect */
    char peer_ip[64];
    int peer_port;
    if (sscanf(dht_value, "%63[^:]:%d", peer_ip, &peer_port) != 2) {
        return MESH_ERR_INVALID_ARG;
    }

    p2p_connect(mesh->p2p_node, peer_ip, peer_port);

    /* Peer will be created automatically when P2P connection succeeds */
    return MESH_OK;
}

void mesh_disconnect_peer(mesh_network_t *mesh, mesh_peer_t *peer) {
    mesh_route_t *route = NULL;

    if (!mesh || !peer) return;

    route = mesh_route_find(mesh, peer->virtual_ip);
    if (route) {
        route->direct_connect_after_ms = mesh_now_ms() + 5000;
    }

    if (peer->p2p_peer) {
        p2p_disconnect_peer(peer->p2p_peer);
        return;
    }

    if (peer->announced && mesh->on_peer_disconnected) {
        mesh->on_peer_disconnected(peer, mesh->user_data);
    }
    mesh_peer_remove(mesh, peer);
}

/* =============================================================================
 * Statistics API
 * ============================================================================= */

int mesh_get_stats(mesh_network_t *mesh, mesh_stats_t *stats) {
    if (!mesh || !stats) return MESH_ERR_INVALID_ARG;

    stats->peer_count = mesh->peer_count;
    stats->bytes_tx = mesh->stats.bytes_tx;
    stats->bytes_rx = mesh->stats.bytes_rx;
    stats->packets_tx = mesh->stats.packets_tx;
    stats->packets_rx = mesh->stats.packets_rx;
    stats->dht_entries = (uint32_t)p2p_dht_get_entry_count(mesh->p2p_node);

    return MESH_OK;
}

int mesh_get_diag_info(mesh_network_t *mesh, mesh_diag_info_t *info) {
    mesh_peer_t *peer = NULL;
    mesh_route_t *route = NULL;

    if (!mesh || !info) {
        return MESH_ERR_INVALID_ARG;
    }

    memset(info, 0, sizeof(*info));
    info->bootstrap_connect_attempts = mesh->bootstrap_connect_attempts;
    info->bootstrap_retry_rounds = mesh->bootstrap_retry_rounds;
    info->bootstrap_reconnect_scheduled = mesh->bootstrap_reconnect_scheduled;
    info->direct_connect_attempts = mesh->direct_connect_attempts;
    info->direct_connect_started = mesh->direct_connect_started;
    info->peer_connect_events = mesh->peer_connect_events;
    info->peer_disconnect_events = mesh->peer_disconnect_events;
    info->control_plane_refreshes = mesh->control_plane_refreshes;
    info->reconnect_poll_count = (uint32_t)mesh->reconnect_poll_count;
    info->bootstrap_reconnect_pending = mesh->bootstrap_reconnect_pending;
    info->path_mode = mesh_get_path_mode_internal(mesh);
    strncpy(info->last_reconnect_reason, mesh->last_reconnect_reason,
            sizeof(info->last_reconnect_reason) - 1);
    strncpy(info->last_direct_attempt_endpoint, mesh->last_direct_attempt_endpoint,
            sizeof(info->last_direct_attempt_endpoint) - 1);
    strncpy(info->last_active_relay_next_hop_virtual_ip,
            mesh->last_active_relay_next_hop_virtual_ip,
            sizeof(info->last_active_relay_next_hop_virtual_ip) - 1);
    strncpy(info->last_active_relay_next_hop_real_ip,
            mesh->last_active_relay_next_hop_real_ip,
            sizeof(info->last_active_relay_next_hop_real_ip) - 1);
    info->ice_enabled = mesh->ice_enabled;
    info->ice_auth_messages_tx = mesh->ice_auth_messages_tx;
    info->ice_auth_messages_rx = mesh->ice_auth_messages_rx;
    info->ice_candidate_messages_tx = mesh->ice_candidate_messages_tx;
    info->ice_candidate_messages_rx = mesh->ice_candidate_messages_rx;
    info->ice_end_of_candidates_tx = mesh->ice_end_of_candidates_tx;
    info->ice_end_of_candidates_rx = mesh->ice_end_of_candidates_rx;
    info->ice_checks_started = mesh->ice_checks_started;
    info->ice_last_check_local_candidate_count = mesh->ice_last_check_local_candidate_count;
    info->ice_last_check_remote_candidate_count = mesh->ice_last_check_remote_candidate_count;
    strncpy(info->last_ice_state, mesh->last_ice_state,
            sizeof(info->last_ice_state) - 1);
    strncpy(info->last_ice_selected_local_endpoint, mesh->last_ice_selected_local_endpoint,
            sizeof(info->last_ice_selected_local_endpoint) - 1);
    strncpy(info->last_ice_selected_remote_endpoint, mesh->last_ice_selected_remote_endpoint,
            sizeof(info->last_ice_selected_remote_endpoint) - 1);

    peer = mesh->peers;
    while (peer) {
        if (peer->announced && peer->is_connected) {
            info->direct_peer_count++;
        }
        if (peer->ice_agent) {
            info->ice_peer_count++;
            if (peer->ice_state[0] != '\0' &&
                (strcmp(peer->ice_state, "CONNECTED") == 0 ||
                 strcmp(peer->ice_state, "COMPLETED") == 0)) {
                info->ice_connected_peer_count++;
            }
        }
        peer = peer->next;
    }

    route = mesh->routes;
    while (route) {
        info->relay_route_count++;
        if (route->next_hop && route->next_hop->is_connected) {
            info->connected_relay_route_count++;
        }
        route = route->next;
    }

    return MESH_OK;
}

static mesh_path_trace_kind_t mesh_path_trace_kind_to_v1(
    mesh_path_metric_kind_t kind) {
    switch (kind) {
        case MESH_PATH_METRIC_KIND_POLICY:
            return MESH_PATH_TRACE_KIND_POLICY;
        case MESH_PATH_METRIC_KIND_DIRECT:
            return MESH_PATH_TRACE_KIND_DIRECT;
        case MESH_PATH_METRIC_KIND_LEARNED:
            return MESH_PATH_TRACE_KIND_LEARNED;
        case MESH_PATH_METRIC_KIND_NONE:
        default:
            return MESH_PATH_TRACE_KIND_NONE;
    }
}

static mesh_path_trace_hysteresis_t mesh_path_trace_hysteresis_to_v1(
    mesh_path_hysteresis_reason_t reason) {
    switch (reason) {
        case MESH_PATH_HYSTERESIS_POLICY:
            return MESH_PATH_TRACE_HYSTERESIS_POLICY;
        case MESH_PATH_HYSTERESIS_UNAVAILABLE:
            return MESH_PATH_TRACE_HYSTERESIS_UNAVAILABLE;
        case MESH_PATH_HYSTERESIS_INSUFFICIENT_GAIN:
            return MESH_PATH_TRACE_HYSTERESIS_INSUFFICIENT_GAIN;
        case MESH_PATH_HYSTERESIS_WINDOW:
            return MESH_PATH_TRACE_HYSTERESIS_WINDOW;
        case MESH_PATH_HYSTERESIS_READY:
            return MESH_PATH_TRACE_HYSTERESIS_READY;
        case MESH_PATH_HYSTERESIS_HARD_FAIL:
            return MESH_PATH_TRACE_HYSTERESIS_HARD_FAIL;
        case MESH_PATH_HYSTERESIS_STABLE:
        default:
            return MESH_PATH_TRACE_HYSTERESIS_STABLE;
    }
}

static uint32_t mesh_path_trace_provenance_to_v1(uint32_t provenance) {
    uint32_t result = 0;

    if ((provenance &
         MESH_PATH_METRIC_PROVENANCE_AUTHENTICATED_STREAM) != 0u) {
        result |= MESH_PATH_TRACE_METRIC_AUTHENTICATED_STREAM;
    }
    return result;
}

static void mesh_path_trace_record_to_v1(
    const mesh_path_trace_record_t *source,
    mesh_path_trace_record_v1_t *target) {
    const mesh_path_observer_diagnostic_t *diagnostic = NULL;

    if (!source || !target) {
        return;
    }

    memset(target, 0, sizeof(*target));
    diagnostic = &source->diagnostic;
    target->version = MESH_PATH_TRACE_API_VERSION_V1;
    target->sequence = source->sequence;
    target->observed_at_ms = diagnostic->observed_at_ms;
    uint32_to_ip_str(source->dest_ip, target->dest_ip);
    if (diagnostic->current_identity != 0u) {
        uint32_to_ip_str(diagnostic->current_identity,
                         target->current_next_hop_ip);
    }
    if (diagnostic->recommended_identity != 0u) {
        uint32_to_ip_str(diagnostic->recommended_identity,
                         target->recommended_next_hop_ip);
    }
    target->current_kind =
        mesh_path_trace_kind_to_v1(diagnostic->current_kind);
    target->recommended_kind =
        mesh_path_trace_kind_to_v1(diagnostic->recommended_kind);
    target->current_cost = diagnostic->current_cost;
    target->recommended_cost = diagnostic->recommended_cost;
    target->current_metric_provenance =
        mesh_path_trace_provenance_to_v1(
            diagnostic->current_metric_provenance);
    target->recommended_metric_provenance =
        mesh_path_trace_provenance_to_v1(
            diagnostic->recommended_metric_provenance);
    target->candidate_count = diagnostic->candidate_count;
    target->hysteresis =
        mesh_path_trace_hysteresis_to_v1(diagnostic->hysteresis_reason);
    if (diagnostic->recommended_available) {
        target->flags |= MESH_PATH_TRACE_RECOMMENDED_AVAILABLE;
    }
    if (diagnostic->policy_forced) {
        target->flags |= MESH_PATH_TRACE_POLICY_FORCED;
    }
    if (diagnostic->differs) {
        target->flags |= MESH_PATH_TRACE_DIFFERS;
    }
    if (diagnostic->switch_ready) {
        target->flags |= MESH_PATH_TRACE_SWITCH_READY;
    }
    if (diagnostic->hard_fail) {
        target->flags |= MESH_PATH_TRACE_HARD_FAIL;
    }
}

int mesh_get_path_trace_v1(mesh_network_t *mesh,
                           uint64_t after_sequence,
                           mesh_path_trace_record_v1_t *records,
                           size_t record_capacity,
                           mesh_path_trace_page_v1_t *page) {
    mesh_path_trace_record_t snapshot[MESH_PATH_TRACE_PAGE_MAX];
    mesh_path_trace_page_t snapshot_page;
    size_t returned = 0;
    size_t i = 0;

    if (!mesh || !page || record_capacity > MESH_PATH_TRACE_PAGE_MAX ||
        (!records && record_capacity != 0u)) {
        return MESH_ERR_INVALID_ARG;
    }

    memset(snapshot, 0, sizeof(snapshot));
    memset(&snapshot_page, 0, sizeof(snapshot_page));
    memset(page, 0, sizeof(*page));
    if (records && record_capacity > 0u) {
        memset(records, 0, record_capacity * sizeof(*records));
    }

    returned = mesh_path_trace_snapshot_after(
        &mesh->path_trace, after_sequence, snapshot,
        record_capacity, &snapshot_page);
    for (i = 0; i < returned; i++) {
        mesh_path_trace_record_to_v1(&snapshot[i], &records[i]);
    }

    page->version = MESH_PATH_TRACE_API_VERSION_V1;
    page->returned_count = (uint32_t)returned;
    page->oldest_sequence = snapshot_page.oldest_sequence;
    page->latest_sequence = snapshot_page.latest_sequence;
    page->next_after_sequence = snapshot_page.next_after_sequence;
    page->overwrites = snapshot_page.overwrites;
    page->has_more = snapshot_page.has_more;
    page->gap_detected = snapshot_page.gap_detected;
    return MESH_OK;
}

int mesh_get_cached_dht_value(mesh_network_t *mesh,
                              const char *key,
                              void *buf,
                              size_t *buf_len) {
    int ret = P2P_OK;

    if (!mesh || !key || !buf || !buf_len) {
        return MESH_ERR_INVALID_ARG;
    }

    ret = p2p_dht_get_cached(mesh->p2p_node, key, buf, buf_len);
    return (ret == P2P_OK) ? MESH_OK : MESH_ERR_NOT_FOUND;
}

void mesh_reset_stats(mesh_network_t *mesh) {
    if (!mesh) return;

    memset(&mesh->stats, 0, sizeof(mesh->stats));

    /* Reset peer stats */
    mesh_peer_t *peer = mesh->peers;
    while (peer) {
        peer->bytes_tx = 0;
        peer->bytes_rx = 0;
        peer = peer->next;
    }
}

/* =============================================================================
 * Utility API
 * ============================================================================= */

CXX_C_API const char *mesh_error_string(mesh_error_t error) {
    switch (error) {
        case MESH_OK: return "Success";
        case MESH_ERR_INVALID_ARG: return "Invalid argument";
        case MESH_ERR_NO_MEMORY: return "Out of memory";
        case MESH_ERR_NOT_FOUND: return "Peer not found";
        case MESH_ERR_NETWORK: return "Network error";
        case MESH_ERR_TIMEOUT: return "Timeout";
        case MESH_ERR_ALREADY_EXISTS: return "Already exists";
        case MESH_ERR_BUSY: return "Resource busy";
        default: return "Unknown error";
    }
}

CXX_C_API const char *mesh_version(void) {
    return "1.0.0";
}

CXX_C_API const char *mesh_path_mode_string(mesh_path_mode_t mode) {
    switch (mode) {
        case MESH_PATH_MODE_DIRECT_ONLY:
            return "direct-only";
        case MESH_PATH_MODE_RELAY_ONLY:
            return "relay-only";
        case MESH_PATH_MODE_HYBRID:
            return "hybrid";
        case MESH_PATH_MODE_ISOLATED:
        default:
            return "isolated";
    }
}
