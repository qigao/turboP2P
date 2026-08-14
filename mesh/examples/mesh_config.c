#include "mesh_config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

static char *mesh_node_trim(char *s) {
    char *end = NULL;

    while (*s && isspace((unsigned char)*s)) {
        s++;
    }

    if (*s == '\0') {
        return s;
    }

    end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) {
        *end-- = '\0';
    }

    return s;
}

static char *mesh_node_strip_quotes(char *s) {
    size_t len = strlen(s);

    if (len >= 2 && ((s[0] == '"' && s[len - 1] == '"') ||
                     (s[0] == '\'' && s[len - 1] == '\''))) {
        s[len - 1] = '\0';
        return s + 1;
    }

    return s;
}

static int mesh_node_parse_ipv4(const char *ip) {
    unsigned int a = 0;
    unsigned int b = 0;
    unsigned int c = 0;
    unsigned int d = 0;

    if (sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
        return 0;
    }

    return a <= 255 && b <= 255 && c <= 255 && d <= 255;
}

static int mesh_node_hex_digit_value(char c) {
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

static int mesh_node_parse_identity_secret_hex(const char *hex) {
    size_t i = 0;

    if (!hex || hex[0] == '\0' || strlen(hex) != 64) {
        return 0;
    }

    for (i = 0; i < 64; i++) {
        if (mesh_node_hex_digit_value(hex[i]) < 0) {
            return 0;
        }
    }

    return 1;
}

static int mesh_node_parse_certificate_sha256(const char *fingerprint) {
    static const char prefix[] = "sha256:";
    size_t i;
    if (!fingerprint || strlen(fingerprint) != 71u ||
        memcmp(fingerprint, prefix, sizeof(prefix) - 1u) != 0) {
        return 0;
    }
    for (i = sizeof(prefix) - 1u; i < 71u; ++i) {
        if (!((fingerprint[i] >= '0' && fingerprint[i] <= '9') ||
              (fingerprint[i] >= 'a' && fingerprint[i] <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

static int mesh_node_parse_u64(const char *value, uint64_t *out) {
    char *end = NULL;
    unsigned long long parsed;

    if (!value || !out || value[0] == '\0' || value[0] == '-') {
        return 0;
    }
    errno = 0;
    parsed = strtoull(value, &end, 10);
    if (errno != 0 || !end || *end != '\0') {
        return 0;
    }
    *out = (uint64_t)parsed;
    return 1;
}

static int mesh_node_parse_size(const char *value, size_t *out) {
    uint64_t parsed = 0u;
    if (!out || !mesh_node_parse_u64(value, &parsed) || parsed > SIZE_MAX) {
        return 0;
    }
    *out = (size_t)parsed;
    return 1;
}

static int mesh_node_parse_bool(const char *value, int *out) {
    if (!value || !out) {
        return 0;
    }
    if (strcmp(value, "true") == 0 || strcmp(value, "1") == 0) {
        *out = 1;
        return 1;
    }
    if (strcmp(value, "false") == 0 || strcmp(value, "0") == 0) {
        *out = 0;
        return 1;
    }
    return 0;
}

static int mesh_node_parse_cidr(const char *cidr) {
    char ip[32];
    const char *slash = NULL;
    char *end = NULL;
    long prefix = 32;
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

    return mesh_node_parse_ipv4(ip);
}

static int mesh_node_parse_ip_proto(const char *value, uint8_t *proto_out) {
    char *end = NULL;
    long proto = 0;

    if (!value || !proto_out) {
        return 0;
    }

    if (strcmp(value, "any") == 0 || strcmp(value, "*") == 0) {
        *proto_out = 0;
        return 1;
    }
    if (strcmp(value, "icmp") == 0) {
        *proto_out = 1;
        return 1;
    }
    if (strcmp(value, "tcp") == 0) {
        *proto_out = 6;
        return 1;
    }
    if (strcmp(value, "udp") == 0) {
        *proto_out = 17;
        return 1;
    }

    proto = strtol(value, &end, 10);
    if (!end || *end != '\0' || proto < 0 || proto > 255) {
        return 0;
    }
    *proto_out = (uint8_t)proto;
    return 1;
}

static int mesh_node_parse_port_range(const char *value,
                                      uint16_t *start_out,
                                      uint16_t *end_out) {
    char tmp[32];
    char *dash = NULL;
    char *end = NULL;
    long start = 0;
    long stop = 0;

    if (!value || !start_out || !end_out) {
        return 0;
    }
    if (strcmp(value, "any") == 0 || strcmp(value, "*") == 0) {
        *start_out = 0;
        *end_out = 0;
        return 1;
    }
    if (strlen(value) >= sizeof(tmp)) {
        return 0;
    }
    strncpy(tmp, value, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    dash = strchr(tmp, '-');
    if (dash) {
        *dash = '\0';
        start = strtol(tmp, &end, 10);
        if (!end || *end != '\0') {
            return 0;
        }
        stop = strtol(dash + 1, &end, 10);
        if (!end || *end != '\0') {
            return 0;
        }
    } else {
        start = strtol(tmp, &end, 10);
        if (!end || *end != '\0') {
            return 0;
        }
        stop = start;
    }

    if (start < 1 || start > 65535 || stop < 1 || stop > 65535 || start > stop) {
        return 0;
    }
    *start_out = (uint16_t)start;
    *end_out = (uint16_t)stop;
    return 1;
}

static int mesh_node_parse_packet_direction(const char *value, uint32_t *directions_out) {
    char tmp[96];
    char *cursor = NULL;
    uint32_t directions = 0;

    if (!value || !directions_out || strlen(value) >= sizeof(tmp)) {
        return 0;
    }

    strncpy(tmp, value, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    cursor = tmp;
    while (cursor && *cursor) {
        char *sep = strchr(cursor, '|');
        char *token = NULL;
        if (sep) {
            *sep = '\0';
        }
        token = mesh_node_trim(cursor);
        if (strcmp(token, "any") == 0 || strcmp(token, "*") == 0) {
            directions |= MESH_PACKET_POLICY_ANY;
        } else if (strcmp(token, "in") == 0 || strcmp(token, "inbound") == 0) {
            directions |= MESH_PACKET_POLICY_IN;
        } else if (strcmp(token, "out") == 0 || strcmp(token, "outbound") == 0) {
            directions |= MESH_PACKET_POLICY_OUT;
        } else if (strcmp(token, "forward") == 0 || strcmp(token, "relay") == 0) {
            directions |= MESH_PACKET_POLICY_FORWARD;
        } else if (strcmp(token, "local-egress") == 0 ||
                   strcmp(token, "local_egress") == 0 ||
                   strcmp(token, "egress") == 0) {
            directions |= MESH_PACKET_POLICY_LOCAL_EGRESS;
        } else {
            return 0;
        }
        cursor = sep ? sep + 1 : NULL;
    }

    if (directions == 0) {
        return 0;
    }
    *directions_out = directions;
    return 1;
}

static int mesh_node_parse_dns_name(const char *name) {
    size_t label_len = 0;
    char prev = '\0';

    if (!name || name[0] == '\0' || strlen(name) > 63) {
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

int mesh_node_parse_bootstrap_endpoint(const char *value,
                                       char *ip,
                                       size_t ip_size,
                                       int *port_out) {
    const char *colon = strrchr(value, ':');
    long port = 0;
    char *end = NULL;
    size_t ip_len = 0;

    if (!colon || colon == value || *(colon + 1) == '\0') {
        return 0;
    }

    ip_len = (size_t)(colon - value);
    if (ip && ip_size > 0) {
        if (ip_len >= ip_size) {
            return 0;
        }
        memcpy(ip, value, ip_len);
        ip[ip_len] = '\0';
    }

    port = strtol(colon + 1, &end, 10);
    if (!end || *end != '\0' || port < 1 || port > 65535) {
        return 0;
    }

    if (port_out) {
        *port_out = (int)port;
    }

    return 1;
}

static int mesh_node_config_add_bootstrap(mesh_node_config_t *cfg, const char *value) {
    if (cfg->bootstrap_count >= MESH_NODE_MAX_BOOTSTRAP_PEERS) {
        return -1;
    }

    strncpy(cfg->bootstrap_storage[cfg->bootstrap_count],
            value,
            sizeof(cfg->bootstrap_storage[cfg->bootstrap_count]) - 1);
    cfg->bootstrap_peers[cfg->bootstrap_count] = cfg->bootstrap_storage[cfg->bootstrap_count];
    cfg->bootstrap_count++;
    return 0;
}

static int mesh_node_config_add_stun(mesh_node_config_t *cfg, const char *value) {
    if (cfg->stun_count >= MESH_NODE_MAX_STUN_SERVERS) {
        return -1;
    }

    strncpy(cfg->stun_storage[cfg->stun_count],
            value,
            sizeof(cfg->stun_storage[cfg->stun_count]) - 1);
    cfg->stun_servers[cfg->stun_count] = cfg->stun_storage[cfg->stun_count];
    cfg->stun_count++;
    return 0;
}

static int mesh_node_config_add_route_rule(mesh_node_config_t *cfg, const char *value) {
    char rule[128];
    char *equals = NULL;
    char *comma = NULL;
    char *dest = NULL;
    char *next_hop = NULL;
    char *flags = NULL;
    mesh_route_rule_t *route_rule = NULL;

    if (cfg->route_rule_count >= MESH_NODE_MAX_ROUTE_RULES) {
        return -1;
    }

    if (!value || strlen(value) >= sizeof(rule)) {
        return -1;
    }

    strncpy(rule, value, sizeof(rule) - 1);
    rule[sizeof(rule) - 1] = '\0';

    equals = strchr(rule, '=');
    if (!equals) {
        return -1;
    }

    *equals = '\0';
    dest = mesh_node_trim(rule);
    next_hop = mesh_node_trim(equals + 1);
    comma = strchr(next_hop, ',');
    if (comma) {
        *comma = '\0';
        flags = mesh_node_trim(comma + 1);
    }
    next_hop = mesh_node_trim(next_hop);

    if (!mesh_node_parse_cidr(dest) || !mesh_node_parse_ipv4(next_hop)) {
        return -1;
    }

    if (!flags || strcmp(flags, "pin") != 0) {
        return -1;
    }

    strncpy(cfg->route_rule_dest_storage[cfg->route_rule_count],
            dest,
            sizeof(cfg->route_rule_dest_storage[cfg->route_rule_count]) - 1);
    strncpy(cfg->route_rule_next_hop_storage[cfg->route_rule_count],
            next_hop,
            sizeof(cfg->route_rule_next_hop_storage[cfg->route_rule_count]) - 1);

    route_rule = &cfg->route_rules[cfg->route_rule_count];
    route_rule->dest_cidr = cfg->route_rule_dest_storage[cfg->route_rule_count];
    route_rule->next_hop_virtual_ip = cfg->route_rule_next_hop_storage[cfg->route_rule_count];
    route_rule->flags = MESH_ROUTE_RULE_PINNED;
    cfg->route_rule_count++;
    return 0;
}

static int mesh_node_config_add_peer_allow_cidr(mesh_node_config_t *cfg, const char *value) {
    if (cfg->peer_allow_count >= MESH_NODE_MAX_PEER_ALLOW_CIDRS) {
        return -1;
    }

    if (!mesh_node_parse_cidr(value)) {
        return -1;
    }

    strncpy(cfg->peer_allow_cidr_storage[cfg->peer_allow_count],
            value,
            sizeof(cfg->peer_allow_cidr_storage[cfg->peer_allow_count]) - 1);
    cfg->peer_allow_cidrs[cfg->peer_allow_count] =
        cfg->peer_allow_cidr_storage[cfg->peer_allow_count];
    cfg->peer_allow_count++;
    return 0;
}

static int mesh_node_config_add_local_egress_cidr(mesh_node_config_t *cfg, const char *value) {
    if (cfg->local_egress_count >= MESH_NODE_MAX_LOCAL_EGRESS_CIDRS) {
        return -1;
    }

    if (!mesh_node_parse_cidr(value)) {
        return -1;
    }

    strncpy(cfg->local_egress_cidr_storage[cfg->local_egress_count],
            value,
            sizeof(cfg->local_egress_cidr_storage[cfg->local_egress_count]) - 1);
    cfg->local_egress_cidrs[cfg->local_egress_count] =
        cfg->local_egress_cidr_storage[cfg->local_egress_count];
    cfg->local_egress_count++;
    return 0;
}

static int mesh_node_config_add_local_egress_allow_cidr(mesh_node_config_t *cfg,
                                                        const char *value) {
    if (cfg->local_egress_allow_count >= MESH_NODE_MAX_LOCAL_EGRESS_ALLOW_CIDRS) {
        return -1;
    }

    if (!mesh_node_parse_cidr(value)) {
        return -1;
    }

    strncpy(cfg->local_egress_allow_cidr_storage[cfg->local_egress_allow_count],
            value,
            sizeof(cfg->local_egress_allow_cidr_storage[cfg->local_egress_allow_count]) - 1);
    cfg->local_egress_allow_cidrs[cfg->local_egress_allow_count] =
        cfg->local_egress_allow_cidr_storage[cfg->local_egress_allow_count];
    cfg->local_egress_allow_count++;
    return 0;
}

static int mesh_node_config_add_magic_dns_record(mesh_node_config_t *cfg,
                                                 const char *value) {
    char tmp[128];
    char *sep = NULL;
    char *name = NULL;
    char *virtual_ip = NULL;

    if (cfg->magic_dns_record_count >= MESH_NODE_MAX_MAGIC_DNS_RECORDS ||
        !value || strlen(value) >= sizeof(tmp)) {
        return -1;
    }

    strncpy(tmp, value, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    sep = strchr(tmp, '=');
    if (!sep) {
        return -1;
    }

    *sep = '\0';
    name = mesh_node_trim(tmp);
    virtual_ip = mesh_node_trim(sep + 1);
    if (!mesh_node_parse_dns_name(name) || !mesh_node_parse_ipv4(virtual_ip)) {
        return -1;
    }

    strncpy(cfg->magic_dns_name_storage[cfg->magic_dns_record_count],
            name,
            sizeof(cfg->magic_dns_name_storage[cfg->magic_dns_record_count]) - 1);
    strncpy(cfg->magic_dns_ip_storage[cfg->magic_dns_record_count],
            virtual_ip,
            sizeof(cfg->magic_dns_ip_storage[cfg->magic_dns_record_count]) - 1);
    cfg->magic_dns_records[cfg->magic_dns_record_count].name =
        cfg->magic_dns_name_storage[cfg->magic_dns_record_count];
    cfg->magic_dns_records[cfg->magic_dns_record_count].virtual_ip =
        cfg->magic_dns_ip_storage[cfg->magic_dns_record_count];
    cfg->magic_dns_record_count++;
    return 0;
}

static void mesh_node_ascii_lower(char *s) {
    if (!s) {
        return;
    }
    for (; *s; s++) {
        *s = (char)tolower((unsigned char)*s);
    }
}

static int mesh_node_config_add_packet_policy_rule(mesh_node_config_t *cfg,
                                                   const char *value) {
    char tmp[256];
    char src_cidr[32] = "0.0.0.0/0";
    char dst_cidr[32] = "0.0.0.0/0";
    mesh_packet_policy_rule_t *rule = NULL;
    char *cursor = NULL;
    int allow_seen = 0;
    int allow = 0;
    uint32_t directions = MESH_PACKET_POLICY_ANY;
    uint8_t proto = 0;
    uint16_t sport_start = 0;
    uint16_t sport_end = 0;
    uint16_t dport_start = 0;
    uint16_t dport_end = 0;

    if (cfg->packet_policy_rule_count >= MESH_NODE_MAX_PACKET_POLICY_RULES ||
        !value || strlen(value) >= sizeof(tmp)) {
        return -1;
    }

    strncpy(tmp, value, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    cursor = tmp;

    while (cursor && *cursor) {
        char *sep = strchr(cursor, ',');
        char *token = NULL;
        char *equals = NULL;

        if (sep) {
            *sep = '\0';
        }
        token = mesh_node_strip_quotes(mesh_node_trim(cursor));
        equals = strchr(token, '=');

        if (equals) {
            char *key = NULL;
            char *val = NULL;
            *equals = '\0';
            key = mesh_node_trim(token);
            val = mesh_node_strip_quotes(mesh_node_trim(equals + 1));
            mesh_node_ascii_lower(key);

            if (strcmp(key, "src") == 0 || strcmp(key, "src_cidr") == 0) {
                if (!mesh_node_parse_cidr(val) || strlen(val) >= sizeof(src_cidr)) {
                    return -1;
                }
                strncpy(src_cidr, val, sizeof(src_cidr) - 1);
            } else if (strcmp(key, "dst") == 0 || strcmp(key, "dst_cidr") == 0) {
                if (!mesh_node_parse_cidr(val) || strlen(val) >= sizeof(dst_cidr)) {
                    return -1;
                }
                strncpy(dst_cidr, val, sizeof(dst_cidr) - 1);
            } else if (strcmp(key, "proto") == 0 || strcmp(key, "ip_proto") == 0) {
                mesh_node_ascii_lower(val);
                if (!mesh_node_parse_ip_proto(val, &proto)) {
                    return -1;
                }
            } else if (strcmp(key, "sport") == 0 || strcmp(key, "src_port") == 0) {
                if (!mesh_node_parse_port_range(val, &sport_start, &sport_end)) {
                    return -1;
                }
            } else if (strcmp(key, "dport") == 0 || strcmp(key, "dst_port") == 0 ||
                       strcmp(key, "port") == 0) {
                if (!mesh_node_parse_port_range(val, &dport_start, &dport_end)) {
                    return -1;
                }
            } else if (strcmp(key, "direction") == 0 || strcmp(key, "dir") == 0) {
                mesh_node_ascii_lower(val);
                if (!mesh_node_parse_packet_direction(val, &directions)) {
                    return -1;
                }
            } else if (strcmp(key, "action") == 0 || strcmp(key, "effect") == 0) {
                mesh_node_ascii_lower(val);
                if (strcmp(val, "allow") == 0) {
                    allow = 1;
                    allow_seen = 1;
                } else if (strcmp(val, "deny") == 0) {
                    allow = 0;
                    allow_seen = 1;
                } else {
                    return -1;
                }
            } else {
                return -1;
            }
        } else {
            mesh_node_ascii_lower(token);
            if (strcmp(token, "allow") == 0) {
                allow = 1;
                allow_seen = 1;
            } else if (strcmp(token, "deny") == 0) {
                allow = 0;
                allow_seen = 1;
            } else if (!mesh_node_parse_packet_direction(token, &directions)) {
                return -1;
            }
        }

        cursor = sep ? sep + 1 : NULL;
    }

    if (!allow_seen || !mesh_node_parse_cidr(src_cidr) || !mesh_node_parse_cidr(dst_cidr)) {
        return -1;
    }

    strncpy(cfg->packet_policy_src_storage[cfg->packet_policy_rule_count],
            src_cidr,
            sizeof(cfg->packet_policy_src_storage[cfg->packet_policy_rule_count]) - 1);
    strncpy(cfg->packet_policy_dst_storage[cfg->packet_policy_rule_count],
            dst_cidr,
            sizeof(cfg->packet_policy_dst_storage[cfg->packet_policy_rule_count]) - 1);

    rule = &cfg->packet_policy_rules[cfg->packet_policy_rule_count];
    rule->src_cidr = cfg->packet_policy_src_storage[cfg->packet_policy_rule_count];
    rule->dst_cidr = cfg->packet_policy_dst_storage[cfg->packet_policy_rule_count];
    rule->ip_proto = proto;
    rule->src_port_start = sport_start;
    rule->src_port_end = sport_end;
    rule->dst_port_start = dport_start;
    rule->dst_port_end = dport_end;
    rule->directions = directions;
    rule->allow = allow;
    cfg->packet_policy_rule_count++;
    return 0;
}

static int mesh_node_config_add_peer_allow_node_id(mesh_node_config_t *cfg, const char *value) {
    if (cfg->peer_allow_node_id_count >= MESH_NODE_MAX_PEER_ALLOW_NODE_IDS) {
        return -1;
    }

    if (!mesh_node_parse_identity_secret_hex(value)) {
        return -1;
    }

    strncpy(cfg->peer_allow_node_id_storage[cfg->peer_allow_node_id_count],
            value,
            sizeof(cfg->peer_allow_node_id_storage[cfg->peer_allow_node_id_count]) - 1);
    cfg->peer_allow_node_ids[cfg->peer_allow_node_id_count] =
        cfg->peer_allow_node_id_storage[cfg->peer_allow_node_id_count];
    cfg->peer_allow_node_id_count++;
    return 0;
}

void mesh_node_config_init(mesh_node_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    strncpy(cfg->node_name, "mesh-node", sizeof(cfg->node_name) - 1);
    strncpy(cfg->network_id, "dev-mesh", sizeof(cfg->network_id) - 1);
    strncpy(cfg->virtual_ip, "10.42.0.2", sizeof(cfg->virtual_ip) - 1);
    cfg->virtual_prefix = 16;
    cfg->listen_port = MESH_DEFAULT_PORT;
    cfg->ice_enabled = 0;
    cfg->stream_enabled = 0;
    cfg->ice_allow_loopback = 0;
    cfg->status_interval_ms = 1000;
    cfg->network_control_port = MESH_NODE_NETWORK_CONTROL_DEFAULT_PORT;
    cfg->network_control_identity_policy_generation = 1u;
    cfg->network_control_network_capacity =
        MESH_NODE_NETWORK_CONTROL_DEFAULT_NETWORK_CAPACITY;
    cfg->network_control_operation_capacity =
        MESH_NODE_NETWORK_CONTROL_DEFAULT_OPERATION_CAPACITY;
    cfg->network_control_channel_capacity =
        MESH_NODE_NETWORK_CONTROL_DEFAULT_CHANNEL_CAPACITY;
    cfg->network_control_channel_max_retained_bytes =
        MESH_NODE_NETWORK_CONTROL_DEFAULT_RETAINED_BYTES;
    cfg->network_control_command_budget =
        MESH_NODE_NETWORK_CONTROL_DEFAULT_COMMAND_BUDGET;
    cfg->network_control_send_budget =
        MESH_NODE_NETWORK_CONTROL_DEFAULT_SEND_BUDGET;
    cfg->network_control_io_timeout_ms =
        MESH_NODE_NETWORK_CONTROL_DEFAULT_IO_TIMEOUT_MS;
    cfg->network_control_heartbeat_interval_ms =
        MESH_NODE_NETWORK_CONTROL_DEFAULT_HEARTBEAT_INTERVAL_MS;
    cfg->network_control_heartbeat_timeout_ms =
        MESH_NODE_NETWORK_CONTROL_DEFAULT_HEARTBEAT_TIMEOUT_MS;
    cfg->network_control_delete_drain_timeout_ms =
        MESH_NODE_NETWORK_CONTROL_DEFAULT_DELETE_DRAIN_TIMEOUT_MS;
    cfg->network_control_shutdown_drain_timeout_ms =
        MESH_NODE_NETWORK_CONTROL_DEFAULT_SHUTDOWN_DRAIN_TIMEOUT_MS;
}

int mesh_node_config_load(mesh_node_config_t *cfg, const char *path) {
    FILE *fp = NULL;
    char line[512];
    int in_bootstrap_list = 0;
    int in_stun_list = 0;
    int in_route_rule_list = 0;
    int in_local_egress_list = 0;
    int in_local_egress_allow_list = 0;
    int in_magic_dns_list = 0;
    int in_packet_policy_list = 0;
    int in_peer_allow_list = 0;
    int in_peer_allow_node_id_list = 0;

    fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "Failed to open config: %s\n", path);
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        char *content = mesh_node_trim(line);
        char *colon = NULL;

        if (*content == '\0' || *content == '#') {
            continue;
        }

        if (in_bootstrap_list && content[0] == '-') {
            char *value = mesh_node_trim(content + 1);
            value = mesh_node_strip_quotes(value);
            if (*value != '\0' && mesh_node_config_add_bootstrap(cfg, value) != 0) {
                fprintf(stderr, "Too many bootstrap peers\n");
                fclose(fp);
                return -1;
            }
            continue;
        }

        if (in_stun_list && content[0] == '-') {
            char *value = mesh_node_trim(content + 1);
            value = mesh_node_strip_quotes(value);
            if (*value != '\0' && mesh_node_config_add_stun(cfg, value) != 0) {
                fprintf(stderr, "Too many stun servers\n");
                fclose(fp);
                return -1;
            }
            continue;
        }

        if (in_route_rule_list && content[0] == '-') {
            char *value = mesh_node_trim(content + 1);
            value = mesh_node_strip_quotes(value);
            if (*value != '\0' && mesh_node_config_add_route_rule(cfg, value) != 0) {
                fprintf(stderr, "Invalid or too many route rules: %s\n", value);
                fclose(fp);
                return -1;
            }
            continue;
        }

        if (in_local_egress_list && content[0] == '-') {
            char *value = mesh_node_trim(content + 1);
            value = mesh_node_strip_quotes(value);
            if (*value != '\0' && mesh_node_config_add_local_egress_cidr(cfg, value) != 0) {
                fprintf(stderr, "Invalid or too many local_egress_cidrs: %s\n", value);
                fclose(fp);
                return -1;
            }
            continue;
        }

        if (in_local_egress_allow_list && content[0] == '-') {
            char *value = mesh_node_trim(content + 1);
            value = mesh_node_strip_quotes(value);
            if (*value != '\0' && mesh_node_config_add_local_egress_allow_cidr(cfg, value) != 0) {
                fprintf(stderr, "Invalid or too many local_egress_allow_cidrs: %s\n", value);
                fclose(fp);
                return -1;
            }
            continue;
        }

        if (in_magic_dns_list && content[0] == '-') {
            char *value = mesh_node_trim(content + 1);
            value = mesh_node_strip_quotes(value);
            if (*value != '\0' && mesh_node_config_add_magic_dns_record(cfg, value) != 0) {
                fprintf(stderr, "Invalid or too many magic_dns_names: %s\n", value);
                fclose(fp);
                return -1;
            }
            continue;
        }

        if (in_packet_policy_list && content[0] == '-') {
            char *value = mesh_node_trim(content + 1);
            value = mesh_node_strip_quotes(value);
            if (*value != '\0' && mesh_node_config_add_packet_policy_rule(cfg, value) != 0) {
                fprintf(stderr, "Invalid or too many packet_policy rules: %s\n", value);
                fclose(fp);
                return -1;
            }
            continue;
        }

        if (in_peer_allow_list && content[0] == '-') {
            char *value = mesh_node_trim(content + 1);
            value = mesh_node_strip_quotes(value);
            if (*value != '\0' && mesh_node_config_add_peer_allow_cidr(cfg, value) != 0) {
                fprintf(stderr, "Invalid or too many peer_allow_cidrs: %s\n", value);
                fclose(fp);
                return -1;
            }
            continue;
        }

        if (in_peer_allow_node_id_list && content[0] == '-') {
            char *value = mesh_node_trim(content + 1);
            value = mesh_node_strip_quotes(value);
            if (*value != '\0' && mesh_node_config_add_peer_allow_node_id(cfg, value) != 0) {
                fprintf(stderr, "Invalid or too many peer_allow_node_ids: %s\n", value);
                fclose(fp);
                return -1;
            }
            continue;
        }

        in_bootstrap_list = 0;
        in_stun_list = 0;
        in_route_rule_list = 0;
        in_local_egress_list = 0;
        in_local_egress_allow_list = 0;
        in_magic_dns_list = 0;
        in_packet_policy_list = 0;
        in_peer_allow_list = 0;
        in_peer_allow_node_id_list = 0;
        colon = strchr(content, ':');
        if (!colon) {
            continue;
        }

        *colon = '\0';
        {
            char *key = mesh_node_trim(content);
            char *value = mesh_node_trim(colon + 1);

            if (strcmp(key, "bootstrap_peers") == 0) {
                in_bootstrap_list = 1;
                value = mesh_node_strip_quotes(value);
                if (*value != '\0' && strcmp(value, "[]") != 0) {
                    if (mesh_node_config_add_bootstrap(cfg, value) != 0) {
                        fprintf(stderr, "Too many bootstrap peers\n");
                        fclose(fp);
                        return -1;
                    }
                }
                continue;
            }

            if (strcmp(key, "stun_servers") == 0) {
                in_stun_list = 1;
                value = mesh_node_strip_quotes(value);
                if (*value != '\0' && strcmp(value, "[]") != 0) {
                    if (mesh_node_config_add_stun(cfg, value) != 0) {
                        fprintf(stderr, "Too many stun servers\n");
                        fclose(fp);
                        return -1;
                    }
                }
                continue;
            }

            if (strcmp(key, "route_rules") == 0) {
                in_route_rule_list = 1;
                value = mesh_node_strip_quotes(value);
                if (*value != '\0' && strcmp(value, "[]") != 0) {
                    if (mesh_node_config_add_route_rule(cfg, value) != 0) {
                        fprintf(stderr, "Invalid or too many route rules: %s\n", value);
                        fclose(fp);
                        return -1;
                    }
                }
                continue;
            }

            if (strcmp(key, "local_egress_cidrs") == 0) {
                in_local_egress_list = 1;
                value = mesh_node_strip_quotes(value);
                if (*value != '\0' && strcmp(value, "[]") != 0) {
                    if (mesh_node_config_add_local_egress_cidr(cfg, value) != 0) {
                        fprintf(stderr, "Invalid or too many local_egress_cidrs: %s\n", value);
                        fclose(fp);
                        return -1;
                    }
                }
                continue;
            }

            if (strcmp(key, "local_egress_allow_cidrs") == 0) {
                in_local_egress_allow_list = 1;
                value = mesh_node_strip_quotes(value);
                if (*value != '\0' && strcmp(value, "[]") != 0) {
                    if (mesh_node_config_add_local_egress_allow_cidr(cfg, value) != 0) {
                        fprintf(stderr, "Invalid or too many local_egress_allow_cidrs: %s\n", value);
                        fclose(fp);
                        return -1;
                    }
                }
                continue;
            }

            if (strcmp(key, "magic_dns_names") == 0) {
                in_magic_dns_list = 1;
                value = mesh_node_strip_quotes(value);
                if (*value != '\0' && strcmp(value, "[]") != 0) {
                    if (mesh_node_config_add_magic_dns_record(cfg, value) != 0) {
                        fprintf(stderr, "Invalid or too many magic_dns_names: %s\n", value);
                        fclose(fp);
                        return -1;
                    }
                }
                continue;
            }

            if (strcmp(key, "packet_policy") == 0) {
                in_packet_policy_list = 1;
                value = mesh_node_strip_quotes(value);
                if (*value != '\0' && strcmp(value, "[]") != 0) {
                    if (mesh_node_config_add_packet_policy_rule(cfg, value) != 0) {
                        fprintf(stderr, "Invalid or too many packet_policy rules: %s\n", value);
                        fclose(fp);
                        return -1;
                    }
                }
                continue;
            }

            if (strcmp(key, "peer_allow_cidrs") == 0) {
                in_peer_allow_list = 1;
                value = mesh_node_strip_quotes(value);
                if (*value != '\0' && strcmp(value, "[]") != 0) {
                    if (mesh_node_config_add_peer_allow_cidr(cfg, value) != 0) {
                        fprintf(stderr, "Invalid or too many peer_allow_cidrs: %s\n", value);
                        fclose(fp);
                        return -1;
                    }
                }
                continue;
            }

            if (strcmp(key, "peer_allow_node_ids") == 0) {
                in_peer_allow_node_id_list = 1;
                value = mesh_node_strip_quotes(value);
                if (*value != '\0' && strcmp(value, "[]") != 0) {
                    if (mesh_node_config_add_peer_allow_node_id(cfg, value) != 0) {
                        fprintf(stderr, "Invalid or too many peer_allow_node_ids: %s\n", value);
                        fclose(fp);
                        return -1;
                    }
                }
                continue;
            }

            value = mesh_node_strip_quotes(value);

            if (strcmp(key, "node_name") == 0) {
                strncpy(cfg->node_name, value, sizeof(cfg->node_name) - 1);
            } else if (strcmp(key, "network_id") == 0) {
                strncpy(cfg->network_id, value, sizeof(cfg->network_id) - 1);
            } else if (strcmp(key, "magic_dns_domain") == 0) {
                strncpy(cfg->magic_dns_domain, value, sizeof(cfg->magic_dns_domain) - 1);
            } else if (strcmp(key, "virtual_ip") == 0) {
                strncpy(cfg->virtual_ip, value, sizeof(cfg->virtual_ip) - 1);
            } else if (strcmp(key, "advertise_ip") == 0) {
                strncpy(cfg->advertise_ip, value, sizeof(cfg->advertise_ip) - 1);
            } else if (strcmp(key, "identity_private_key_file") == 0) {
                strncpy(cfg->identity_private_key_file, value,
                        sizeof(cfg->identity_private_key_file) - 1);
            } else if (strcmp(key, "identity_secret_hex") == 0) {
                strncpy(cfg->identity_secret_hex, value, sizeof(cfg->identity_secret_hex) - 1);
            } else if (strcmp(key, "mgmt_private_key_file") == 0) {
                strncpy(cfg->mgmt_private_key_file, value,
                        sizeof(cfg->mgmt_private_key_file) - 1);
            } else if (strcmp(key, "mgmt_certificate_file") == 0) {
                strncpy(cfg->mgmt_certificate_file, value,
                        sizeof(cfg->mgmt_certificate_file) - 1);
            } else if (strcmp(key, "mgmt_trusted_issuer_key_file") == 0) {
                strncpy(cfg->mgmt_trusted_issuer_key_file, value,
                        sizeof(cfg->mgmt_trusted_issuer_key_file) - 1);
            } else if (strcmp(key, "mgmt_execution_grant_issuer_key_file") == 0) {
                strncpy(cfg->mgmt_execution_grant_issuer_key_file, value,
                        sizeof(cfg->mgmt_execution_grant_issuer_key_file) - 1);
            } else if (strcmp(key, "mgmt_mesh_id_hex") == 0) {
                strncpy(cfg->mgmt_mesh_id_hex, value, sizeof(cfg->mgmt_mesh_id_hex) - 1);
            } else if (strcmp(key, "mgmt_first_record_epoch") == 0) {
                if (!mesh_node_parse_u64(value, &cfg->mgmt_first_record_epoch)) {
                    fprintf(stderr, "Invalid mgmt_first_record_epoch: %s\n", value);
                    fclose(fp);
                    return -1;
                }
            } else if (strcmp(key, "mgmt_record_epoch_file") == 0) {
                strncpy(cfg->mgmt_record_epoch_file, value,
                        sizeof(cfg->mgmt_record_epoch_file) - 1);
            } else if (strcmp(key, "network_control_enabled") == 0) {
                if (!mesh_node_parse_bool(value, &cfg->network_control_enabled)) {
                    fprintf(stderr, "Invalid network_control_enabled: %s\n", value);
                    fclose(fp);
                    return -1;
                }
            } else if (strcmp(key, "network_control_port") == 0) {
                cfg->network_control_port = (int)strtol(value, NULL, 10);
            } else if (strcmp(key, "network_control_certificate_file") == 0) {
                strncpy(cfg->network_control_certificate_file, value,
                        sizeof(cfg->network_control_certificate_file) - 1);
            } else if (strcmp(key, "network_control_private_key_file") == 0) {
                strncpy(cfg->network_control_private_key_file, value,
                        sizeof(cfg->network_control_private_key_file) - 1);
            } else if (strcmp(key, "network_control_client_ca_file") == 0) {
                strncpy(cfg->network_control_client_ca_file, value,
                        sizeof(cfg->network_control_client_ca_file) - 1);
            } else if (strcmp(key, "network_control_identity") == 0) {
                strncpy(cfg->network_control_identity, value,
                        sizeof(cfg->network_control_identity) - 1);
            } else if (strcmp(key, "network_control_expected_peer_identity") == 0) {
                strncpy(cfg->network_control_expected_peer_identity, value,
                        sizeof(cfg->network_control_expected_peer_identity) - 1);
            } else if (strcmp(key, "network_control_expected_peer_certificate_sha256") == 0) {
                strncpy(cfg->network_control_expected_peer_certificate_sha256,
                        value,
                        sizeof(cfg->network_control_expected_peer_certificate_sha256) - 1);
            } else if (strcmp(key, "network_control_expected_peer_certificate_sha256_next") == 0) {
                strncpy(cfg->network_control_expected_peer_certificate_sha256_next,
                        value,
                        sizeof(cfg->network_control_expected_peer_certificate_sha256_next) - 1);
            } else if (strcmp(key, "network_control_identity_policy_generation") == 0) {
                if (!mesh_node_parse_u64(
                        value,
                        &cfg->network_control_identity_policy_generation))
                    goto invalid_network_control_number;
            } else if (strcmp(key, "network_control_mesh_id_hex") == 0) {
                strncpy(cfg->network_control_mesh_id_hex, value,
                        sizeof(cfg->network_control_mesh_id_hex) - 1);
            } else if (strcmp(key, "network_control_provider_id_hex") == 0) {
                strncpy(cfg->network_control_provider_id_hex, value,
                        sizeof(cfg->network_control_provider_id_hex) - 1);
            } else if (strcmp(key, "network_control_membership_issuer_id_hex") == 0) {
                strncpy(cfg->network_control_membership_issuer_id_hex, value,
                        sizeof(cfg->network_control_membership_issuer_id_hex) - 1);
            } else if (strcmp(key, "network_control_membership_issuer_key_file") == 0) {
                strncpy(cfg->network_control_membership_issuer_key_file, value,
                        sizeof(cfg->network_control_membership_issuer_key_file) - 1);
            } else if (strcmp(key, "network_control_network_capacity") == 0) {
                if (!mesh_node_parse_size(
                        value, &cfg->network_control_network_capacity))
                    goto invalid_network_control_number;
            } else if (strcmp(key, "network_control_operation_capacity") == 0) {
                if (!mesh_node_parse_size(
                        value, &cfg->network_control_operation_capacity))
                    goto invalid_network_control_number;
            } else if (strcmp(key, "network_control_channel_capacity") == 0) {
                if (!mesh_node_parse_size(
                        value, &cfg->network_control_channel_capacity))
                    goto invalid_network_control_number;
            } else if (strcmp(key, "network_control_channel_max_retained_bytes") == 0) {
                if (!mesh_node_parse_size(
                        value,
                        &cfg->network_control_channel_max_retained_bytes))
                    goto invalid_network_control_number;
            } else if (strcmp(key, "network_control_command_budget") == 0) {
                if (!mesh_node_parse_size(
                        value, &cfg->network_control_command_budget))
                    goto invalid_network_control_number;
            } else if (strcmp(key, "network_control_send_budget") == 0) {
                if (!mesh_node_parse_size(
                        value, &cfg->network_control_send_budget))
                    goto invalid_network_control_number;
            } else if (strcmp(key, "network_control_io_timeout_ms") == 0) {
                if (!mesh_node_parse_u64(
                        value, &cfg->network_control_io_timeout_ms))
                    goto invalid_network_control_number;
            } else if (strcmp(key, "network_control_heartbeat_interval_ms") == 0) {
                if (!mesh_node_parse_u64(
                        value,
                        &cfg->network_control_heartbeat_interval_ms))
                    goto invalid_network_control_number;
            } else if (strcmp(key, "network_control_heartbeat_timeout_ms") == 0) {
                if (!mesh_node_parse_u64(
                        value,
                        &cfg->network_control_heartbeat_timeout_ms))
                    goto invalid_network_control_number;
            } else if (strcmp(key, "network_control_delete_drain_timeout_ms") == 0) {
                if (!mesh_node_parse_u64(
                        value,
                        &cfg->network_control_delete_drain_timeout_ms))
                    goto invalid_network_control_number;
            } else if (strcmp(key, "network_control_shutdown_drain_timeout_ms") == 0) {
                if (!mesh_node_parse_u64(
                        value,
                        &cfg->network_control_shutdown_drain_timeout_ms))
                    goto invalid_network_control_number;
            } else if (strcmp(key, "virtual_prefix") == 0) {
                cfg->virtual_prefix = (unsigned int)strtoul(value, NULL, 10);
            } else if (strcmp(key, "listen_port") == 0) {
                cfg->listen_port = (int)strtol(value, NULL, 10);
            } else if (strcmp(key, "ice_enabled") == 0) {
                cfg->ice_enabled = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0) ? 1 : 0;
            } else if (strcmp(key, "stream_enabled") == 0) {
                cfg->stream_enabled = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0) ? 1 : 0;
            } else if (strcmp(key, "ice_allow_loopback") == 0) {
                cfg->ice_allow_loopback = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0) ? 1 : 0;
            } else if (strcmp(key, "status_file") == 0) {
                strncpy(cfg->status_file, value, sizeof(cfg->status_file) - 1);
            } else if (strcmp(key, "pid_file") == 0) {
                strncpy(cfg->pid_file, value, sizeof(cfg->pid_file) - 1);
            } else if (strcmp(key, "status_interval_ms") == 0) {
                cfg->status_interval_ms = (unsigned int)strtoul(value, NULL, 10);
            } else if (strcmp(key, "peer_protocol_major") == 0) {
                cfg->peer_protocol_major = (unsigned int)strtoul(value, NULL, 10);
            }
            continue;

invalid_network_control_number:
            fprintf(stderr, "Invalid %s: %s\n", key, value);
            fclose(fp);
            return -1;
        }
    }

    fclose(fp);
    return 0;
}

int mesh_node_config_management_enabled(const mesh_node_config_t *cfg) {
    return cfg && cfg->mgmt_private_key_file[0] != '\0' &&
           cfg->mgmt_certificate_file[0] != '\0' &&
           cfg->mgmt_trusted_issuer_key_file[0] != '\0' &&
           cfg->mgmt_mesh_id_hex[0] != '\0' &&
           cfg->mgmt_first_record_epoch != 0u &&
           cfg->mgmt_record_epoch_file[0] != '\0';
}

int mesh_node_config_network_control_enabled(const mesh_node_config_t *cfg) {
    return cfg && cfg->network_control_enabled != 0;
}

int mesh_node_config_validate(const mesh_node_config_t *cfg) {
    int mgmt_field_count = 0;
    int i = 0;

    if (!mesh_node_parse_ipv4(cfg->virtual_ip)) {
        fprintf(stderr, "Invalid virtual_ip: %s\n", cfg->virtual_ip);
        return -1;
    }

    if (cfg->advertise_ip[0] != '\0' && !mesh_node_parse_ipv4(cfg->advertise_ip)) {
        fprintf(stderr, "Invalid advertise_ip: %s\n", cfg->advertise_ip);
        return -1;
    }

    if (cfg->identity_secret_hex[0] != '\0' &&
        !mesh_node_parse_identity_secret_hex(cfg->identity_secret_hex)) {
        fprintf(stderr, "Invalid identity_secret_hex: expected 64 hex characters\n");
        return -1;
    }
    if (cfg->identity_private_key_file[0] != '\0' &&
        cfg->identity_secret_hex[0] != '\0') {
        fprintf(stderr,
                "identity_private_key_file and identity_secret_hex are mutually exclusive\n");
        return -1;
    }

    mgmt_field_count += cfg->mgmt_private_key_file[0] != '\0';
    mgmt_field_count += cfg->mgmt_certificate_file[0] != '\0';
    mgmt_field_count += cfg->mgmt_trusted_issuer_key_file[0] != '\0';
    mgmt_field_count += cfg->mgmt_mesh_id_hex[0] != '\0';
    mgmt_field_count += cfg->mgmt_first_record_epoch != 0u;
    mgmt_field_count += cfg->mgmt_record_epoch_file[0] != '\0';
    if (mgmt_field_count != 0 && mgmt_field_count != 6) {
        fprintf(stderr, "Management configuration must provide all mgmt_* fields\n");
        return -1;
    }
    if (mesh_node_config_management_enabled(cfg)) {
        if (cfg->identity_private_key_file[0] == '\0') {
            fprintf(stderr,
                    "Management mode requires identity_private_key_file\n");
            return -1;
        }
        if (!mesh_node_parse_identity_secret_hex(cfg->mgmt_mesh_id_hex)) {
            fprintf(stderr, "Invalid mgmt_mesh_id_hex: expected 64 hex characters\n");
            return -1;
        }
    } else if (cfg->mgmt_execution_grant_issuer_key_file[0] != '\0') {
        fprintf(stderr,
                "Execution Grant issuer requires complete management configuration\n");
        return -1;
    }

    if (mesh_node_config_network_control_enabled(cfg)) {
        if (cfg->identity_private_key_file[0] == '\0') {
            fprintf(stderr,
                    "Network control requires identity_private_key_file\n");
            return -1;
        }
        if (cfg->network_control_certificate_file[0] == '\0' ||
            cfg->network_control_private_key_file[0] == '\0' ||
            cfg->network_control_client_ca_file[0] == '\0' ||
            cfg->network_control_membership_issuer_key_file[0] == '\0' ||
            cfg->network_control_identity[0] == '\0' ||
            cfg->network_control_expected_peer_identity[0] == '\0' ||
            cfg->network_control_expected_peer_certificate_sha256[0] == '\0' ||
            cfg->network_control_identity_policy_generation == 0u) {
            fprintf(stderr,
                    "Network control requires TLS files, identities, certificate binding, and membership issuer key\n");
            return -1;
        }
        if (!mesh_node_parse_certificate_sha256(
                cfg->network_control_expected_peer_certificate_sha256) ||
            (cfg->network_control_expected_peer_certificate_sha256_next[0] != '\0' &&
             !mesh_node_parse_certificate_sha256(
                 cfg->network_control_expected_peer_certificate_sha256_next))) {
            fprintf(stderr,
                    "Network control peer certificate fingerprints must use sha256: plus 64 lowercase hex characters\n");
            return -1;
        }
        if (!mesh_node_parse_identity_secret_hex(
                cfg->network_control_mesh_id_hex) ||
            !mesh_node_parse_identity_secret_hex(
                cfg->network_control_provider_id_hex) ||
            !mesh_node_parse_identity_secret_hex(
                cfg->network_control_membership_issuer_id_hex)) {
            fprintf(stderr,
                    "Network control mesh, provider, and issuer IDs must be 64 hex characters\n");
            return -1;
        }
    }
    if (cfg->network_control_port < 1 ||
        cfg->network_control_port > 65535) {
        fprintf(stderr, "Invalid network_control_port: %d\n",
                cfg->network_control_port);
        return -1;
    }
    if (cfg->network_control_network_capacity == 0u ||
        cfg->network_control_network_capacity >
            MESH_NODE_NETWORK_CONTROL_MAX_NETWORK_CAPACITY ||
        cfg->network_control_operation_capacity == 0u ||
        cfg->network_control_operation_capacity >
            MESH_NODE_NETWORK_CONTROL_MAX_OPERATION_CAPACITY ||
        cfg->network_control_channel_capacity == 0u ||
        cfg->network_control_channel_capacity >
            MESH_NODE_NETWORK_CONTROL_MAX_CHANNEL_CAPACITY ||
        cfg->network_control_channel_max_retained_bytes <
            MESH_NODE_NETWORK_CONTROL_MIN_FRAME_BYTES ||
        cfg->network_control_channel_max_retained_bytes >
            MESH_NODE_NETWORK_CONTROL_MAX_RETAINED_BYTES ||
        cfg->network_control_command_budget == 0u ||
        cfg->network_control_command_budget >
            cfg->network_control_channel_capacity ||
        cfg->network_control_send_budget == 0u ||
        cfg->network_control_send_budget >
            cfg->network_control_channel_capacity) {
        fprintf(stderr, "Invalid bounded network_control capacity or budget\n");
        return -1;
    }
    if (cfg->network_control_io_timeout_ms == 0u ||
        cfg->network_control_io_timeout_ms >
            MESH_NODE_NETWORK_CONTROL_MAX_TIMEOUT_MS ||
        cfg->network_control_heartbeat_interval_ms == 0u ||
        cfg->network_control_heartbeat_interval_ms >
            MESH_NODE_NETWORK_CONTROL_MAX_TIMEOUT_MS ||
        cfg->network_control_heartbeat_timeout_ms <=
            cfg->network_control_heartbeat_interval_ms ||
        cfg->network_control_heartbeat_timeout_ms >
            MESH_NODE_NETWORK_CONTROL_MAX_TIMEOUT_MS ||
        cfg->network_control_delete_drain_timeout_ms == 0u ||
        cfg->network_control_delete_drain_timeout_ms >
            MESH_NODE_NETWORK_CONTROL_MAX_TIMEOUT_MS ||
        cfg->network_control_shutdown_drain_timeout_ms == 0u ||
        cfg->network_control_shutdown_drain_timeout_ms >
            MESH_NODE_NETWORK_CONTROL_MAX_TIMEOUT_MS) {
        fprintf(stderr, "Invalid network_control timeout configuration\n");
        return -1;
    }

    if (cfg->virtual_prefix < 1 || cfg->virtual_prefix > 32) {
        fprintf(stderr, "Invalid virtual_prefix: %u\n", cfg->virtual_prefix);
        return -1;
    }

    if (cfg->listen_port < 1 || cfg->listen_port > 65535) {
        fprintf(stderr, "Invalid listen_port: %d\n", cfg->listen_port);
        return -1;
    }

    if (cfg->network_id[0] == '\0') {
        fprintf(stderr, "network_id must not be empty\n");
        return -1;
    }

    if (cfg->magic_dns_domain[0] != '\0' &&
        !mesh_node_parse_dns_name(cfg->magic_dns_domain)) {
        fprintf(stderr, "Invalid magic_dns_domain: %s\n", cfg->magic_dns_domain);
        return -1;
    }

    if (cfg->status_interval_ms == 0) {
        fprintf(stderr, "status_interval_ms must be > 0\n");
        return -1;
    }

    if (cfg->peer_protocol_major > UINT16_MAX) {
        fprintf(stderr, "Invalid peer_protocol_major: %u\n", cfg->peer_protocol_major);
        return -1;
    }

    for (i = 0; i < cfg->bootstrap_count; i++) {
        if (!mesh_node_parse_bootstrap_endpoint(cfg->bootstrap_peers[i], NULL, 0, NULL)) {
            fprintf(stderr, "Invalid bootstrap peer: %s\n", cfg->bootstrap_peers[i]);
            return -1;
        }
    }

    for (i = 0; i < cfg->stun_count; i++) {
        if (strncmp(cfg->stun_servers[i], "stun:", 5) != 0) {
            fprintf(stderr, "Invalid stun server: %s\n", cfg->stun_servers[i]);
            return -1;
        }
        if (!mesh_node_parse_bootstrap_endpoint(cfg->stun_servers[i] + 5, NULL, 0, NULL)) {
            fprintf(stderr, "Invalid stun server: %s\n", cfg->stun_servers[i]);
            return -1;
        }
    }

    for (i = 0; i < cfg->route_rule_count; i++) {
        if (!mesh_node_parse_cidr(cfg->route_rules[i].dest_cidr) ||
            !mesh_node_parse_ipv4(cfg->route_rules[i].next_hop_virtual_ip) ||
            cfg->route_rules[i].flags != MESH_ROUTE_RULE_PINNED) {
            fprintf(stderr, "Invalid route rule: %s=%s,pin\n",
                    cfg->route_rules[i].dest_cidr,
                    cfg->route_rules[i].next_hop_virtual_ip);
            return -1;
        }
    }

    for (i = 0; i < cfg->local_egress_count; i++) {
        if (!mesh_node_parse_cidr(cfg->local_egress_cidrs[i])) {
            fprintf(stderr, "Invalid local_egress_cidrs entry: %s\n",
                    cfg->local_egress_cidrs[i]);
            return -1;
        }
    }

    for (i = 0; i < cfg->local_egress_allow_count; i++) {
        if (!mesh_node_parse_cidr(cfg->local_egress_allow_cidrs[i])) {
            fprintf(stderr, "Invalid local_egress_allow_cidrs entry: %s\n",
                    cfg->local_egress_allow_cidrs[i]);
            return -1;
        }
    }

    for (i = 0; i < cfg->magic_dns_record_count; i++) {
        if (!mesh_node_parse_dns_name(cfg->magic_dns_records[i].name) ||
            !mesh_node_parse_ipv4(cfg->magic_dns_records[i].virtual_ip)) {
            fprintf(stderr, "Invalid magic_dns_names entry: %s=%s\n",
                    cfg->magic_dns_records[i].name,
                    cfg->magic_dns_records[i].virtual_ip);
            return -1;
        }
    }

    for (i = 0; i < cfg->packet_policy_rule_count; i++) {
        const mesh_packet_policy_rule_t *rule = &cfg->packet_policy_rules[i];
        if (!mesh_node_parse_cidr(rule->src_cidr) ||
            !mesh_node_parse_cidr(rule->dst_cidr) ||
            (rule->directions & MESH_PACKET_POLICY_ANY) == 0 ||
            (rule->src_port_start == 0 && rule->src_port_end != 0) ||
            (rule->dst_port_start == 0 && rule->dst_port_end != 0) ||
            (rule->src_port_start != 0 && rule->src_port_start > rule->src_port_end) ||
            (rule->dst_port_start != 0 && rule->dst_port_start > rule->dst_port_end)) {
            fprintf(stderr, "Invalid packet_policy rule at index %d\n", i);
            return -1;
        }
    }

    for (i = 0; i < cfg->peer_allow_count; i++) {
        if (!mesh_node_parse_cidr(cfg->peer_allow_cidrs[i])) {
            fprintf(stderr, "Invalid peer_allow_cidrs entry: %s\n", cfg->peer_allow_cidrs[i]);
            return -1;
        }
    }

    for (i = 0; i < cfg->peer_allow_node_id_count; i++) {
        if (!mesh_node_parse_identity_secret_hex(cfg->peer_allow_node_ids[i])) {
            fprintf(stderr, "Invalid peer_allow_node_ids entry: %s\n", cfg->peer_allow_node_ids[i]);
            return -1;
        }
    }

    return 0;
}

void mesh_node_config_print(const mesh_node_config_t *cfg) {
    int i = 0;

    printf("node_name      : %s\n", cfg->node_name);
    printf("network_id     : %s\n", cfg->network_id);
    printf("magic_dns_domain: %s\n",
           cfg->magic_dns_domain[0] ? cfg->magic_dns_domain : "(unset)");
    printf("virtual_ip     : %s/%u\n", cfg->virtual_ip, cfg->virtual_prefix);
    printf("advertise_ip   : %s\n", cfg->advertise_ip[0] ? cfg->advertise_ip : "(unset)");
    printf("identity       : %s\n",
           cfg->identity_private_key_file[0]
               ? "private-key-file"
               : (cfg->identity_secret_hex[0] ? "inline-dev" : "(ephemeral)"));
    printf("management     : %s\n",
           mesh_node_config_management_enabled(cfg) ? "shared-node" : "disabled");
    printf("node_execution : %s\n",
           cfg->mgmt_execution_grant_issuer_key_file[0] != '\0'
               ? "enabled"
               : "disabled");
    printf("network_control: %s\n",
           mesh_node_config_network_control_enabled(cfg)
               ? "flowmq-mtls-loopback"
               : "disabled");
    if (mesh_node_config_network_control_enabled(cfg)) {
        printf("network_control_port: %d\n", cfg->network_control_port);
        printf("network_control_identity_policy_generation: %llu\n",
               (unsigned long long)
                   cfg->network_control_identity_policy_generation);
        printf("network_control_capacity: networks=%zu operations=%zu channels=%zu retained=%zu\n",
               cfg->network_control_network_capacity,
               cfg->network_control_operation_capacity,
               cfg->network_control_channel_capacity,
               cfg->network_control_channel_max_retained_bytes);
    }
    if (mesh_node_config_management_enabled(cfg)) {
        printf("mgmt_epoch     : %llu\n",
               (unsigned long long)cfg->mgmt_first_record_epoch);
    }
    printf("listen_port    : %d\n", cfg->listen_port);
    printf("ice_enabled    : %s\n", cfg->ice_enabled ? "true" : "false");
    printf("stream_enabled : %s\n", cfg->stream_enabled ? "true" : "false");
    printf("ice_loopback   : %s\n", cfg->ice_allow_loopback ? "true" : "false");
    printf("status_file    : %s\n", cfg->status_file[0] ? cfg->status_file : "(unset)");
    printf("pid_file       : %s\n", cfg->pid_file[0] ? cfg->pid_file : "(unset)");
    printf("status_interval: %u ms\n", cfg->status_interval_ms);
    printf("bootstrap_peers: %d\n", cfg->bootstrap_count);

    for (i = 0; i < cfg->bootstrap_count; i++) {
        printf("  - %s\n", cfg->bootstrap_peers[i]);
    }

    printf("stun_servers   : %d\n", cfg->stun_count);
    for (i = 0; i < cfg->stun_count; i++) {
        printf("  - %s\n", cfg->stun_servers[i]);
    }

    printf("route_rules    : %d\n", cfg->route_rule_count);
    for (i = 0; i < cfg->route_rule_count; i++) {
        printf("  - %s=%s,pin\n",
               cfg->route_rules[i].dest_cidr,
               cfg->route_rules[i].next_hop_virtual_ip);
    }

    printf("local_egress_cidrs: %d\n", cfg->local_egress_count);
    for (i = 0; i < cfg->local_egress_count; i++) {
        printf("  - %s\n", cfg->local_egress_cidrs[i]);
    }

    printf("local_egress_allow_cidrs: %d\n", cfg->local_egress_allow_count);
    for (i = 0; i < cfg->local_egress_allow_count; i++) {
        printf("  - %s\n", cfg->local_egress_allow_cidrs[i]);
    }

    printf("magic_dns_names: %d\n", cfg->magic_dns_record_count);
    for (i = 0; i < cfg->magic_dns_record_count; i++) {
        printf("  - %s=%s\n",
               cfg->magic_dns_records[i].name,
               cfg->magic_dns_records[i].virtual_ip);
    }

    printf("packet_policy: %d\n", cfg->packet_policy_rule_count);
    for (i = 0; i < cfg->packet_policy_rule_count; i++) {
        const mesh_packet_policy_rule_t *rule = &cfg->packet_policy_rules[i];
        printf("  - %s,dir=%u,src=%s,dst=%s,proto=%u,sport=%u-%u,dport=%u-%u\n",
               rule->allow ? "allow" : "deny",
               rule->directions,
               rule->src_cidr,
               rule->dst_cidr,
               (unsigned int)rule->ip_proto,
               (unsigned int)rule->src_port_start,
               (unsigned int)rule->src_port_end,
               (unsigned int)rule->dst_port_start,
               (unsigned int)rule->dst_port_end);
    }

    printf("peer_allow_cidrs: %d\n", cfg->peer_allow_count);
    for (i = 0; i < cfg->peer_allow_count; i++) {
        printf("  - %s\n", cfg->peer_allow_cidrs[i]);
    }

    printf("peer_allow_node_ids: %d\n", cfg->peer_allow_node_id_count);
    for (i = 0; i < cfg->peer_allow_node_id_count; i++) {
        printf("  - %s\n", cfg->peer_allow_node_ids[i]);
    }

    if (cfg->peer_protocol_major > 0) {
        printf("peer_protocol_major: %u\n", cfg->peer_protocol_major);
    } else {
        printf("peer_protocol_major: any\n");
    }
}
