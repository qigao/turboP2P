#ifndef MESH_EXAMPLES_MESH_CONFIG_H
#define MESH_EXAMPLES_MESH_CONFIG_H

#include <turbo_mesh.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_NODE_MAX_BOOTSTRAP_PEERS 8
#define MESH_NODE_MAX_STUN_SERVERS 4
#define MESH_NODE_MAX_ROUTE_RULES 16
#define MESH_NODE_MAX_LOCAL_EGRESS_CIDRS 16
#define MESH_NODE_MAX_LOCAL_EGRESS_ALLOW_CIDRS 16
#define MESH_NODE_MAX_PEER_ALLOW_CIDRS 16
#define MESH_NODE_MAX_PEER_ALLOW_NODE_IDS 16
#define MESH_NODE_MAX_MAGIC_DNS_RECORDS 32
#define MESH_NODE_MAX_PACKET_POLICY_RULES 32

#define MESH_NODE_NETWORK_CONTROL_DEFAULT_PORT 24443
#define MESH_NODE_NETWORK_CONTROL_DEFAULT_NETWORK_CAPACITY 16u
#define MESH_NODE_NETWORK_CONTROL_DEFAULT_OPERATION_CAPACITY 256u
#define MESH_NODE_NETWORK_CONTROL_DEFAULT_CHANNEL_CAPACITY 256u
#define MESH_NODE_NETWORK_CONTROL_DEFAULT_RETAINED_BYTES (16u * 1024u * 1024u)
#define MESH_NODE_NETWORK_CONTROL_DEFAULT_COMMAND_BUDGET 32u
#define MESH_NODE_NETWORK_CONTROL_DEFAULT_SEND_BUDGET 32u
#define MESH_NODE_NETWORK_CONTROL_DEFAULT_IO_TIMEOUT_MS 1000u
#define MESH_NODE_NETWORK_CONTROL_DEFAULT_HEARTBEAT_INTERVAL_MS 1000u
#define MESH_NODE_NETWORK_CONTROL_DEFAULT_HEARTBEAT_TIMEOUT_MS 5000u
#define MESH_NODE_NETWORK_CONTROL_DEFAULT_DELETE_DRAIN_TIMEOUT_MS 5000u
#define MESH_NODE_NETWORK_CONTROL_DEFAULT_SHUTDOWN_DRAIN_TIMEOUT_MS 5000u
#define MESH_NODE_NETWORK_CONTROL_MAX_NETWORK_CAPACITY 64u
#define MESH_NODE_NETWORK_CONTROL_MAX_OPERATION_CAPACITY 4096u
#define MESH_NODE_NETWORK_CONTROL_MAX_CHANNEL_CAPACITY 4096u
#define MESH_NODE_NETWORK_CONTROL_MAX_RETAINED_BYTES (64u * 1024u * 1024u)
#define MESH_NODE_NETWORK_CONTROL_MIN_FRAME_BYTES (64u * 1024u)
#define MESH_NODE_NETWORK_CONTROL_MAX_TIMEOUT_MS (10u * 60u * 1000u)

typedef struct {
    char node_name[64];
    char network_id[64];
    char virtual_ip[16];
    char advertise_ip[64];
    char identity_private_key_file[260];
    char identity_secret_hex[65];
    char mgmt_private_key_file[260];
    char mgmt_certificate_file[260];
    char mgmt_trusted_issuer_key_file[260];
    char mgmt_execution_grant_issuer_key_file[260];
    char mgmt_mesh_id_hex[65];
    uint64_t mgmt_first_record_epoch;
    char mgmt_record_epoch_file[260];
    int network_control_enabled;
    int network_control_port;
    char network_control_certificate_file[260];
    char network_control_private_key_file[260];
    char network_control_client_ca_file[260];
    char network_control_identity[256];
    char network_control_expected_peer_identity[256];
    char network_control_expected_peer_certificate_sha256[72];
    char network_control_expected_peer_certificate_sha256_next[72];
    uint64_t network_control_identity_policy_generation;
    char network_control_mesh_id_hex[65];
    char network_control_provider_id_hex[65];
    char network_control_membership_issuer_id_hex[65];
    char network_control_membership_issuer_key_file[260];
    size_t network_control_network_capacity;
    size_t network_control_operation_capacity;
    size_t network_control_channel_capacity;
    size_t network_control_channel_max_retained_bytes;
    size_t network_control_command_budget;
    size_t network_control_send_budget;
    uint64_t network_control_io_timeout_ms;
    uint64_t network_control_heartbeat_interval_ms;
    uint64_t network_control_heartbeat_timeout_ms;
    uint64_t network_control_delete_drain_timeout_ms;
    uint64_t network_control_shutdown_drain_timeout_ms;
    unsigned int virtual_prefix;
    int listen_port;
    int ice_enabled;
    int stream_enabled;
    int ice_allow_loopback;
    char bootstrap_storage[MESH_NODE_MAX_BOOTSTRAP_PEERS][128];
    const char *bootstrap_peers[MESH_NODE_MAX_BOOTSTRAP_PEERS];
    int bootstrap_count;
    char stun_storage[MESH_NODE_MAX_STUN_SERVERS][256];
    const char *stun_servers[MESH_NODE_MAX_STUN_SERVERS];
    int stun_count;
    char route_rule_dest_storage[MESH_NODE_MAX_ROUTE_RULES][32];
    char route_rule_next_hop_storage[MESH_NODE_MAX_ROUTE_RULES][16];
    mesh_route_rule_t route_rules[MESH_NODE_MAX_ROUTE_RULES];
    int route_rule_count;
    char local_egress_cidr_storage[MESH_NODE_MAX_LOCAL_EGRESS_CIDRS][32];
    const char *local_egress_cidrs[MESH_NODE_MAX_LOCAL_EGRESS_CIDRS];
    int local_egress_count;
    char local_egress_allow_cidr_storage[MESH_NODE_MAX_LOCAL_EGRESS_ALLOW_CIDRS][32];
    const char *local_egress_allow_cidrs[MESH_NODE_MAX_LOCAL_EGRESS_ALLOW_CIDRS];
    int local_egress_allow_count;
    char magic_dns_domain[64];
    char magic_dns_name_storage[MESH_NODE_MAX_MAGIC_DNS_RECORDS][64];
    char magic_dns_ip_storage[MESH_NODE_MAX_MAGIC_DNS_RECORDS][16];
    mesh_magic_dns_record_t magic_dns_records[MESH_NODE_MAX_MAGIC_DNS_RECORDS];
    int magic_dns_record_count;
    char peer_allow_cidr_storage[MESH_NODE_MAX_PEER_ALLOW_CIDRS][32];
    const char *peer_allow_cidrs[MESH_NODE_MAX_PEER_ALLOW_CIDRS];
    int peer_allow_count;
    char peer_allow_node_id_storage[MESH_NODE_MAX_PEER_ALLOW_NODE_IDS][65];
    const char *peer_allow_node_ids[MESH_NODE_MAX_PEER_ALLOW_NODE_IDS];
    int peer_allow_node_id_count;
    unsigned int peer_protocol_major;
    char packet_policy_src_storage[MESH_NODE_MAX_PACKET_POLICY_RULES][32];
    char packet_policy_dst_storage[MESH_NODE_MAX_PACKET_POLICY_RULES][32];
    mesh_packet_policy_rule_t packet_policy_rules[MESH_NODE_MAX_PACKET_POLICY_RULES];
    int packet_policy_rule_count;
    char status_file[260];
    char pid_file[260];
    unsigned int status_interval_ms;
} mesh_node_config_t;

void mesh_node_config_init(mesh_node_config_t *cfg);
int mesh_node_config_load(mesh_node_config_t *cfg, const char *path);
int mesh_node_config_validate(const mesh_node_config_t *cfg);
int mesh_node_config_management_enabled(const mesh_node_config_t *cfg);
int mesh_node_config_network_control_enabled(const mesh_node_config_t *cfg);
void mesh_node_config_print(const mesh_node_config_t *cfg);
int mesh_node_parse_bootstrap_endpoint(const char *value,
                                       char *ip,
                                       size_t ip_size,
                                       int *port_out);

#ifdef __cplusplus
}
#endif

#endif
