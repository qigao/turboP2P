#include "turbo_mesh_multi_network.h"
#include "mesh_multi_network_internal.h"
#include "mesh_mgmt_crypto.h"

#include <turbo_crypto.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MESH_NETWORK_TICKET_MAGIC "MTK1"
#define MESH_NETWORK_TICKET_VERSION 1u
#define MESH_NETWORK_TICKET_BODY_SIZE 236u
#define MESH_NETWORK_TICKET_WIRE_SIZE 300u

#define MESH_NETWORK_FRAME_MAGIC "TMN2"
#define MESH_NETWORK_FRAME_VERSION 2u
#define MESH_NETWORK_FRAME_HEADER_SIZE 136u
#define MESH_NETWORK_FRAME_KIND_OPEN 1u
#define MESH_NETWORK_FRAME_KIND_DATA 2u
#define MESH_NETWORK_FRAME_KIND_CLOSE 3u
#define MESH_NETWORK_FRAME_FAMILY_IPV4 4u
#define MESH_NETWORK_FRAME_DIRECT_HOP_LIMIT 1u

#define MESH_NETWORK_REQUIRED_CAPABILITIES                                \
    (MESH_CAP_MULTI_NETWORK_V2 | MESH_CAP_NETWORK_FRAME_V2 |             \
     MESH_CAP_NETWORK_MEMBERSHIP_V1)

typedef enum {
    MESH_FABRIC_CREATED = 1,
    MESH_FABRIC_RUNNING = 2,
    MESH_FABRIC_DRAINING = 3,
    MESH_FABRIC_CLOSED = 4,
} mesh_fabric_lifecycle_v2_t;

typedef struct mesh_network_state_v2_s mesh_network_state_v2_t;

typedef struct mesh_network_binding_v2_s {
    mesh_network_state_v2_t *network;
    uint8_t node_id[MESH_NETWORK_IDENTITY_SIZE];
    uint32_t ipv4_address;
    uint64_t membership_generation;
    uint64_t node_key_epoch;
    uint64_t not_after_unix_s;
    uint32_t roles;
    uint64_t last_rx_sequence;
    uint64_t next_tx_sequence;
    int active;
    int open_sent;
    struct mesh_network_binding_v2_s *next;
} mesh_network_binding_v2_t;

struct mesh_network_state_v2_s {
    mesh_fabric_t *fabric;
    mesh_network_t *handle;
    mesh_network_uid_t uid;
    char name[MESH_NETWORK_NAME_MAX + 1u];
    uint64_t generation;
    uint64_t policy_epoch;
    uint16_t mtu;
    mesh_network_lifecycle_v2_t lifecycle;
    mesh_network_attach_mode_v2_t attach_mode;
    mesh_network_membership_ticket_v1_t local_membership;
    uint8_t *authorized_peer_node_ids;
    size_t authorized_peer_count;
    uint64_t route_epoch;
    mesh_network_route_v2_t *routes;
    size_t route_count;
    mesh_network_packet_authorizer_v2_fn authorize_packet;
    mesh_network_packet_received_v2_fn on_packet_received;
    void *user_data;
    uint64_t packets_tx;
    uint64_t packets_rx;
    uint64_t bytes_tx;
    uint64_t bytes_rx;
    uint64_t rejected_frames;
    uint64_t replay_drops;
    uint64_t routed_packets_tx;
    uint64_t routed_packets_rx;
    uint64_t route_misses;
    struct mesh_network_state_v2_s *next;
};

struct mesh_fabric_s {
    mesh_network_t *underlay;
    uint8_t mesh_id[MESH_NETWORK_IDENTITY_SIZE];
    uint8_t local_node_id[MESH_NETWORK_IDENTITY_SIZE];
    mesh_network_issuer_v1_t *issuers;
    size_t issuer_count;
    mesh_network_state_v2_t *networks;
    mesh_network_binding_v2_t *bindings;
    size_t network_count;
    size_t binding_count;
    size_t max_networks;
    size_t max_bindings;
    size_t max_packet_size;
    mesh_fabric_lifecycle_v2_t lifecycle;
    unsigned int dispatch_depth;
    uint64_t rejected_frames;
    uint64_t unauthorized_opens;
    uint64_t capacity_rejections;
};

typedef struct {
    uint8_t kind;
    mesh_network_uid_t network_uid;
    uint64_t generation;
    uint64_t policy_epoch;
    uint8_t source_node_id[MESH_NETWORK_IDENTITY_SIZE];
    uint8_t destination_node_id[MESH_NETWORK_IDENTITY_SIZE];
    uint64_t sequence;
    uint8_t hop_limit;
    uint8_t address_family;
    uint32_t source_ipv4;
    uint32_t destination_ipv4;
    const uint8_t *payload;
    size_t payload_len;
} mesh_network_frame_view_v2_t;

static void mesh_network_write_u16(uint8_t *out, uint16_t value) {
    out[0] = (uint8_t)(value >> 8);
    out[1] = (uint8_t)value;
}

static void mesh_network_write_u32(uint8_t *out, uint32_t value) {
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static void mesh_network_write_u64(uint8_t *out, uint64_t value) {
    size_t index;
    for (index = 0; index < 8u; ++index) {
        out[index] = (uint8_t)(value >> (56u - index * 8u));
    }
}

static uint16_t mesh_network_read_u16(const uint8_t *in) {
    return (uint16_t)(((uint16_t)in[0] << 8) | in[1]);
}

static uint32_t mesh_network_read_u32(const uint8_t *in) {
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8) | (uint32_t)in[3];
}

static uint64_t mesh_network_read_u64(const uint8_t *in) {
    uint64_t value = 0;
    size_t index;
    for (index = 0; index < 8u; ++index) {
        value = (value << 8) | in[index];
    }
    return value;
}

static int mesh_network_bytes_are_zero(const uint8_t *bytes, size_t length) {
    uint8_t value = 0;
    size_t index;
    if (!bytes) {
        return 1;
    }
    for (index = 0; index < length; ++index) {
        value |= bytes[index];
    }
    return value == 0;
}

static int mesh_network_uid_equal(const mesh_network_uid_t *left,
                                  const mesh_network_uid_t *right) {
    return left && right &&
           mesh_mgmt_crypto_equal_16(left->bytes, right->bytes);
}

static uint64_t mesh_network_now_unix_s(void) {
    time_t now = time(NULL);
    return now < 0 ? 0u : (uint64_t)now;
}

static int mesh_network_ticket_is_current(
    const mesh_network_membership_ticket_v1_t *ticket, uint64_t now_unix_s) {
    return ticket && now_unix_s >= ticket->not_before_unix_s &&
           now_unix_s <= ticket->not_after_unix_s;
}

static int mesh_network_name_valid(const char *name) {
    size_t length;
    size_t index;
    if (!name) {
        return 0;
    }
    length = strlen(name);
    if (length == 0u || length > MESH_NETWORK_NAME_MAX) {
        return 0;
    }
    for (index = 0; index < length; ++index) {
        unsigned char ch = (unsigned char)name[index];
        if (ch < 0x20u || ch == 0x7fu || ch == '/' || ch == '\\') {
            return 0;
        }
    }
    return 1;
}

static int mesh_network_ticket_encode_body(
    const mesh_network_membership_ticket_v1_t *ticket,
    uint8_t out[MESH_NETWORK_TICKET_BODY_SIZE]) {
    size_t offset = 0;
    if (!ticket || !out) {
        return MESH_ERR_INVALID_ARG;
    }

    memcpy(out + offset, MESH_NETWORK_TICKET_MAGIC, 4u);
    offset += 4u;
    mesh_network_write_u16(out + offset, MESH_NETWORK_TICKET_VERSION);
    offset += 2u;
    mesh_network_write_u16(out + offset, MESH_NETWORK_TICKET_WIRE_SIZE);
    offset += 2u;
    memcpy(out + offset, ticket->mesh_id, sizeof(ticket->mesh_id));
    offset += sizeof(ticket->mesh_id);
    memcpy(out + offset, ticket->network_uid.bytes,
           sizeof(ticket->network_uid.bytes));
    offset += sizeof(ticket->network_uid.bytes);
    memcpy(out + offset, ticket->membership_id, sizeof(ticket->membership_id));
    offset += sizeof(ticket->membership_id);
    memcpy(out + offset, ticket->managed_node_id,
           sizeof(ticket->managed_node_id));
    offset += sizeof(ticket->managed_node_id);
    memcpy(out + offset, ticket->node_public_key_digest,
           sizeof(ticket->node_public_key_digest));
    offset += sizeof(ticket->node_public_key_digest);
    mesh_network_write_u64(out + offset, ticket->network_generation);
    offset += 8u;
    mesh_network_write_u64(out + offset, ticket->membership_generation);
    offset += 8u;
    mesh_network_write_u64(out + offset, ticket->node_key_epoch);
    offset += 8u;
    mesh_network_write_u64(out + offset, ticket->policy_epoch);
    offset += 8u;
    mesh_network_write_u32(out + offset, ticket->ipv4_address);
    offset += 4u;
    out[offset++] = ticket->ipv4_prefix;
    memset(out + offset, 0, 3u);
    offset += 3u;
    mesh_network_write_u32(out + offset, ticket->roles);
    offset += 4u;
    mesh_network_write_u64(out + offset, ticket->issued_at_unix_s);
    offset += 8u;
    mesh_network_write_u64(out + offset, ticket->not_before_unix_s);
    offset += 8u;
    mesh_network_write_u64(out + offset, ticket->not_after_unix_s);
    offset += 8u;
    memcpy(out + offset, ticket->issuer_key_id,
           sizeof(ticket->issuer_key_id));
    offset += sizeof(ticket->issuer_key_id);
    return offset == MESH_NETWORK_TICKET_BODY_SIZE ? MESH_OK
                                                   : MESH_ERR_NETWORK;
}

static int mesh_network_ticket_decode(
    const uint8_t *wire, size_t wire_len,
    mesh_network_membership_ticket_v1_t *ticket) {
    size_t offset = 0;
    if (!wire || !ticket || wire_len != MESH_NETWORK_TICKET_WIRE_SIZE ||
        memcmp(wire, MESH_NETWORK_TICKET_MAGIC, 4u) != 0 ||
        mesh_network_read_u16(wire + 4u) != MESH_NETWORK_TICKET_VERSION ||
        mesh_network_read_u16(wire + 6u) != MESH_NETWORK_TICKET_WIRE_SIZE) {
        return MESH_ERR_INVALID_ARG;
    }
    memset(ticket, 0, sizeof(*ticket));
    offset = 8u;
    memcpy(ticket->mesh_id, wire + offset, sizeof(ticket->mesh_id));
    offset += sizeof(ticket->mesh_id);
    memcpy(ticket->network_uid.bytes, wire + offset,
           sizeof(ticket->network_uid.bytes));
    offset += sizeof(ticket->network_uid.bytes);
    memcpy(ticket->membership_id, wire + offset, sizeof(ticket->membership_id));
    offset += sizeof(ticket->membership_id);
    memcpy(ticket->managed_node_id, wire + offset,
           sizeof(ticket->managed_node_id));
    offset += sizeof(ticket->managed_node_id);
    memcpy(ticket->node_public_key_digest, wire + offset,
           sizeof(ticket->node_public_key_digest));
    offset += sizeof(ticket->node_public_key_digest);
    ticket->network_generation = mesh_network_read_u64(wire + offset);
    offset += 8u;
    ticket->membership_generation = mesh_network_read_u64(wire + offset);
    offset += 8u;
    ticket->node_key_epoch = mesh_network_read_u64(wire + offset);
    offset += 8u;
    ticket->policy_epoch = mesh_network_read_u64(wire + offset);
    offset += 8u;
    ticket->ipv4_address = mesh_network_read_u32(wire + offset);
    offset += 4u;
    ticket->ipv4_prefix = wire[offset++];
    if (wire[offset] != 0u || wire[offset + 1u] != 0u ||
        wire[offset + 2u] != 0u) {
        return MESH_ERR_INVALID_ARG;
    }
    offset += 3u;
    ticket->roles = mesh_network_read_u32(wire + offset);
    offset += 4u;
    ticket->issued_at_unix_s = mesh_network_read_u64(wire + offset);
    offset += 8u;
    ticket->not_before_unix_s = mesh_network_read_u64(wire + offset);
    offset += 8u;
    ticket->not_after_unix_s = mesh_network_read_u64(wire + offset);
    offset += 8u;
    memcpy(ticket->issuer_key_id, wire + offset,
           sizeof(ticket->issuer_key_id));
    offset += sizeof(ticket->issuer_key_id);
    memcpy(ticket->signature, wire + offset, sizeof(ticket->signature));
    offset += sizeof(ticket->signature);
    return offset == wire_len ? MESH_OK : MESH_ERR_INVALID_ARG;
}

int mesh_network_membership_ticket_decode_v1(
    const uint8_t *input, size_t input_len,
    mesh_network_membership_ticket_v1_t *out_ticket) {
    return mesh_network_ticket_decode(input, input_len, out_ticket);
}

void mesh_fabric_config_init_v2(mesh_fabric_config_v2_t *config) {
    if (!config) {
        return;
    }
    memset(config, 0, sizeof(*config));
    config->struct_size = sizeof(*config);
    mesh_config_init(&config->underlay);
    config->max_networks = MESH_NETWORK_DEFAULT_LIMIT;
    config->max_peer_network_bindings = MESH_NETWORK_BINDING_DEFAULT_LIMIT;
    config->max_packet_size = MESH_NETWORK_PACKET_DEFAULT_MAX;
}

int mesh_network_default_uid_v2(const char *network_id,
                                mesh_network_uid_t *out_uid) {
    static const char domain[] = "mesh-default-network/v1";
    uint8_t mesh_id[MESH_NETWORK_IDENTITY_SIZE];
    uint8_t digest[MESH_NETWORK_IDENTITY_SIZE];
    uint8_t input[(sizeof(domain) - 1u) + MESH_NETWORK_IDENTITY_SIZE];
    const char *effective_id = network_id ? network_id : "default";
    int result = MESH_ERR_NETWORK;

    if (!out_uid || effective_id[0] == '\0') {
        return MESH_ERR_INVALID_ARG;
    }
    if (turbo_crypto_sha256(effective_id, strlen(effective_id), mesh_id) !=
        TURBO_CRYPTO_OK) {
        goto cleanup;
    }
    memcpy(input, domain, sizeof(domain) - 1u);
    memcpy(input + sizeof(domain) - 1u, mesh_id, sizeof(mesh_id));
    if (turbo_crypto_sha256(input, sizeof(input), digest) != TURBO_CRYPTO_OK) {
        goto cleanup;
    }
    memcpy(out_uid->bytes, digest, sizeof(out_uid->bytes));
    result = MESH_OK;

cleanup:
    mesh_mgmt_crypto_wipe(mesh_id, sizeof(mesh_id));
    mesh_mgmt_crypto_wipe(digest, sizeof(digest));
    mesh_mgmt_crypto_wipe(input, sizeof(input));
    return result;
}

int mesh_network_public_key_digest_v1(
    const uint8_t public_key[MESH_NETWORK_IDENTITY_SIZE],
    uint8_t out_digest[MESH_NETWORK_IDENTITY_SIZE]) {
    if (!public_key || !out_digest) {
        return MESH_ERR_INVALID_ARG;
    }
    return turbo_crypto_sha256(public_key, MESH_NETWORK_IDENTITY_SIZE,
                               out_digest) == TURBO_CRYPTO_OK
               ? MESH_OK
               : MESH_ERR_NETWORK;
}

int mesh_network_membership_ticket_encode_v1(
    const mesh_network_membership_ticket_v1_t *ticket,
    uint8_t *out, size_t out_capacity, size_t *out_len) {
    int result;
    if (!ticket || !out || !out_len ||
        out_capacity < MESH_NETWORK_TICKET_WIRE_SIZE) {
        return MESH_ERR_INVALID_ARG;
    }
    *out_len = 0u;
    result = mesh_network_ticket_encode_body(ticket, out);
    if (result != MESH_OK) {
        return result;
    }
    memcpy(out + MESH_NETWORK_TICKET_BODY_SIZE, ticket->signature,
           sizeof(ticket->signature));
    *out_len = MESH_NETWORK_TICKET_WIRE_SIZE;
    return MESH_OK;
}

int mesh_network_membership_ticket_sign_v1(
    mesh_network_membership_ticket_v1_t *ticket,
    const uint8_t private_key[MESH_NETWORK_IDENTITY_SIZE]) {
    uint8_t body[MESH_NETWORK_TICKET_BODY_SIZE];
    int result;
    if (!ticket || !private_key) {
        return MESH_ERR_INVALID_ARG;
    }
    result = mesh_network_ticket_encode_body(ticket, body);
    if (result == MESH_OK &&
        mesh_mgmt_ed25519_sign(private_key, body, sizeof(body),
                               ticket->signature) != MESH_MGMT_CRYPTO_OK) {
        result = MESH_ERR_NETWORK;
    }
    mesh_mgmt_crypto_wipe(body, sizeof(body));
    return result;
}

int mesh_network_membership_ticket_verify_v1(
    const mesh_network_membership_ticket_v1_t *ticket,
    const mesh_network_issuer_v1_t *issuer,
    uint64_t now_unix_s) {
    uint8_t body[MESH_NETWORK_TICKET_BODY_SIZE];
    int result = MESH_ERR_UNAUTHORIZED;
    if (!ticket || !issuer || ticket->ipv4_address == 0u ||
        ticket->ipv4_prefix > 32u || ticket->network_generation == 0u ||
        ticket->membership_generation == 0u || ticket->node_key_epoch == 0u ||
        ticket->policy_epoch == 0u || ticket->issued_at_unix_s == 0u ||
        ticket->not_before_unix_s < ticket->issued_at_unix_s ||
        ticket->not_after_unix_s < ticket->not_before_unix_s ||
        now_unix_s < ticket->not_before_unix_s ||
        now_unix_s > ticket->not_after_unix_s ||
        (ticket->roles & MESH_NETWORK_ROLE_MEMBER) == 0u ||
        (ticket->roles & ~((uint32_t)MESH_NETWORK_ROLE_KNOWN_MASK)) != 0u ||
        mesh_network_bytes_are_zero(ticket->network_uid.bytes,
                                    sizeof(ticket->network_uid.bytes)) ||
        mesh_network_bytes_are_zero(ticket->membership_id,
                                    sizeof(ticket->membership_id)) ||
        mesh_network_bytes_are_zero(ticket->managed_node_id,
                                    sizeof(ticket->managed_node_id)) ||
        !mesh_mgmt_crypto_equal_32(ticket->issuer_key_id, issuer->key_id)) {
        return MESH_ERR_UNAUTHORIZED;
    }
    if (mesh_network_ticket_encode_body(ticket, body) == MESH_OK &&
        mesh_mgmt_ed25519_verify(issuer->public_key, body, sizeof(body),
                                 ticket->signature) == MESH_MGMT_CRYPTO_OK) {
        result = MESH_OK;
    }
    mesh_mgmt_crypto_wipe(body, sizeof(body));
    return result;
}

static mesh_network_state_v2_t *mesh_network_find(
    mesh_fabric_t *fabric, const mesh_network_uid_t *uid) {
    mesh_network_state_v2_t *network;
    if (!fabric || !uid) {
        return NULL;
    }
    for (network = fabric->networks; network; network = network->next) {
        if (mesh_network_uid_equal(&network->uid, uid)) {
            return network;
        }
    }
    return NULL;
}

static const mesh_network_issuer_v1_t *mesh_network_find_issuer(
    const mesh_fabric_t *fabric,
    const uint8_t key_id[MESH_NETWORK_IDENTITY_SIZE]) {
    size_t index;
    if (!fabric || !key_id) {
        return NULL;
    }
    for (index = 0; index < fabric->issuer_count; ++index) {
        if (mesh_mgmt_crypto_equal_32(fabric->issuers[index].key_id, key_id)) {
            return &fabric->issuers[index];
        }
    }
    return NULL;
}

static mesh_network_binding_v2_t *mesh_network_find_binding(
    mesh_fabric_t *fabric, mesh_network_state_v2_t *network,
    const uint8_t *node_id, uint32_t ipv4_address) {
    mesh_network_binding_v2_t *binding;
    if (!fabric || !network) {
        return NULL;
    }
    for (binding = fabric->bindings; binding; binding = binding->next) {
        if (binding->network != network) {
            continue;
        }
        if (node_id && mesh_mgmt_crypto_equal_32(binding->node_id, node_id)) {
            return binding;
        }
        if (!node_id && ipv4_address != 0u &&
            binding->ipv4_address == ipv4_address) {
            return binding;
        }
    }
    return NULL;
}

static int mesh_network_peer_authorized(
    const mesh_network_state_v2_t *network,
    const uint8_t node_id[MESH_NETWORK_IDENTITY_SIZE]) {
    size_t index;
    if (!network || !node_id) {
        return 0;
    }
    for (index = 0; index < network->authorized_peer_count; ++index) {
        if (mesh_mgmt_crypto_equal_32(
                network->authorized_peer_node_ids + index * 32u, node_id)) {
            return 1;
        }
    }
    return 0;
}

static int mesh_network_prefix_contains(uint32_t network_address,
                                        uint8_t prefix,
                                        uint32_t candidate) {
    uint32_t mask;
    if (prefix > 32u) {
        return 0;
    }
    mask = prefix == 0u ? 0u : UINT32_MAX << (32u - prefix);
    return (network_address & mask) == (candidate & mask);
}

static uint32_t mesh_network_route_required_role(
    const mesh_network_route_v2_t *route) {
    if (!route) {
        return 0u;
    }
    return route->kind == MESH_NETWORK_ROUTE_SUBNET
               ? MESH_NETWORK_ROLE_SUBNET_ROUTER
               : route->kind == MESH_NETWORK_ROUTE_EXIT
                     ? MESH_NETWORK_ROLE_EXIT
                     : 0u;
}

static int mesh_network_route_compare(const void *left_value,
                                      const void *right_value) {
    const mesh_network_route_v2_t *left =
        (const mesh_network_route_v2_t *)left_value;
    const mesh_network_route_v2_t *right =
        (const mesh_network_route_v2_t *)right_value;
    int node_order;
    if (left->destination_network != right->destination_network) {
        return left->destination_network < right->destination_network ? -1 : 1;
    }
    if (left->prefix_length != right->prefix_length) {
        return left->prefix_length > right->prefix_length ? -1 : 1;
    }
    if (left->metric != right->metric) {
        return left->metric < right->metric ? -1 : 1;
    }
    node_order = memcmp(left->next_hop_node_id, right->next_hop_node_id,
                        MESH_NETWORK_IDENTITY_SIZE);
    if (node_order != 0) {
        return node_order;
    }
    return (int)left->kind - (int)right->kind;
}

static int mesh_network_route_is_better(
    const mesh_network_route_v2_t *candidate,
    const mesh_network_route_v2_t *current) {
    if (!current) {
        return 1;
    }
    if (candidate->prefix_length != current->prefix_length) {
        return candidate->prefix_length > current->prefix_length;
    }
    if (candidate->metric != current->metric) {
        return candidate->metric < current->metric;
    }
    return memcmp(candidate->next_hop_node_id, current->next_hop_node_id,
                  MESH_NETWORK_IDENTITY_SIZE) < 0;
}

static int mesh_network_spec_peer_authorized(
    const mesh_network_spec_v2_t *spec,
    const uint8_t node_id[MESH_NETWORK_IDENTITY_SIZE]) {
    size_t peer_index;
    if (!spec || !node_id) {
        return 0;
    }
    for (peer_index = 0; peer_index < spec->authorized_peer_count;
         ++peer_index) {
        if (mesh_mgmt_crypto_equal_32(
                node_id, spec->authorized_peer_node_ids +
                             peer_index * MESH_NETWORK_IDENTITY_SIZE)) {
            return 1;
        }
    }
    return 0;
}

static int mesh_network_routes_validate(
    const mesh_fabric_t *fabric, const mesh_network_spec_v2_t *spec) {
    size_t index;
    if (!fabric || !spec || spec->route_epoch == 0u ||
        spec->route_count > MESH_NETWORK_ROUTE_HARD_LIMIT ||
        (spec->route_count != 0u && !spec->routes)) {
        return MESH_ERR_INVALID_ARG;
    }
    for (index = 0; index < spec->route_count; ++index) {
        const mesh_network_route_v2_t *route = &spec->routes[index];
        uint32_t required_role = mesh_network_route_required_role(route);
        uint32_t mask;
        size_t previous;
        if (route->prefix_length > 32u || required_role == 0u) {
            return MESH_ERR_INVALID_ARG;
        }
        mask = route->prefix_length == 0u
                   ? 0u
                   : UINT32_MAX << (32u - route->prefix_length);
        if (route->destination_network !=
                (route->destination_network & mask) ||
            (route->kind == MESH_NETWORK_ROUTE_EXIT &&
             (route->prefix_length != 0u ||
              route->destination_network != 0u)) ||
            (route->kind == MESH_NETWORK_ROUTE_SUBNET &&
             route->prefix_length == 0u) ||
            mesh_network_bytes_are_zero(route->next_hop_node_id,
                                        MESH_NETWORK_IDENTITY_SIZE)) {
            return MESH_ERR_INVALID_ARG;
        }
        if (mesh_mgmt_crypto_equal_32(route->next_hop_node_id,
                                      fabric->local_node_id)) {
            if ((spec->local_membership.roles & required_role) == 0u) {
                return MESH_ERR_UNAUTHORIZED;
            }
        } else if (!mesh_network_spec_peer_authorized(
                       spec, route->next_hop_node_id)) {
            return MESH_ERR_UNAUTHORIZED;
        }
        for (previous = 0; previous < index; ++previous) {
            const mesh_network_route_v2_t *seen = &spec->routes[previous];
            if (seen->destination_network == route->destination_network &&
                seen->prefix_length == route->prefix_length &&
                mesh_mgmt_crypto_equal_32(seen->next_hop_node_id,
                                          route->next_hop_node_id)) {
                return MESH_ERR_INVALID_ARG;
            }
        }
    }
    return MESH_OK;
}

static mesh_network_route_v2_t *mesh_network_routes_copy(
    const mesh_network_spec_v2_t *spec) {
    mesh_network_route_v2_t *routes;
    if (!spec || spec->route_count == 0u) {
        return NULL;
    }
    routes = (mesh_network_route_v2_t *)malloc(
        spec->route_count * sizeof(*routes));
    if (!routes) {
        return NULL;
    }
    memcpy(routes, spec->routes, spec->route_count * sizeof(*routes));
    qsort(routes, spec->route_count, sizeof(*routes),
          mesh_network_route_compare);
    return routes;
}

static int mesh_network_resolve_gateway(
    mesh_network_state_v2_t *network, uint32_t destination,
    uint64_t now_unix_s, const mesh_network_route_v2_t **out_route,
    mesh_network_binding_v2_t **out_binding) {
    const mesh_network_route_v2_t *best = NULL;
    mesh_network_binding_v2_t *best_binding = NULL;
    int saw_route = 0;
    int saw_local = 0;
    int saw_unauthorized = 0;
    size_t index;
    if (!network || !out_route || !out_binding) {
        return MESH_ERR_INVALID_ARG;
    }
    *out_route = NULL;
    *out_binding = NULL;
    for (index = 0; index < network->route_count; ++index) {
        const mesh_network_route_v2_t *route = &network->routes[index];
        mesh_network_binding_v2_t *binding;
        uint32_t required_role;
        if (!mesh_network_prefix_contains(route->destination_network,
                                          route->prefix_length,
                                          destination)) {
            continue;
        }
        saw_route = 1;
        if (mesh_mgmt_crypto_equal_32(route->next_hop_node_id,
                                      network->fabric->local_node_id)) {
            saw_local = 1;
            continue;
        }
        binding = mesh_network_find_binding(network->fabric, network,
                                            route->next_hop_node_id, 0u);
        if (!binding || !binding->active ||
            now_unix_s > binding->not_after_unix_s) {
            continue;
        }
        required_role = mesh_network_route_required_role(route);
        if ((binding->roles & required_role) == 0u) {
            saw_unauthorized = 1;
            continue;
        }
        if (mesh_network_route_is_better(route, best)) {
            best = route;
            best_binding = binding;
        }
    }
    if (best) {
        *out_route = best;
        *out_binding = best_binding;
        return MESH_OK;
    }
    if (saw_unauthorized) {
        return MESH_ERR_UNAUTHORIZED;
    }
    if (saw_local && saw_route) {
        return MESH_ERR_UNSUPPORTED;
    }
    return MESH_ERR_NOT_FOUND;
}

static int mesh_network_accepts_gateway_destination(
    const mesh_network_state_v2_t *network, uint32_t destination) {
    size_t index;
    if (!network || !network->fabric) {
        return 0;
    }
    for (index = 0; index < network->route_count; ++index) {
        const mesh_network_route_v2_t *route = &network->routes[index];
        uint32_t required_role = mesh_network_route_required_role(route);
        if (mesh_mgmt_crypto_equal_32(route->next_hop_node_id,
                                      network->fabric->local_node_id) &&
            (network->local_membership.roles & required_role) != 0u &&
            mesh_network_prefix_contains(route->destination_network,
                                         route->prefix_length,
                                         destination)) {
            return 1;
        }
    }
    return 0;
}

static int mesh_network_frame_encode(
    const mesh_network_frame_view_v2_t *view, uint8_t *out,
    size_t out_capacity, size_t *out_len) {
    size_t total;
    if (!view || !out || !out_len ||
        view->payload_len > UINT32_MAX ||
        view->payload_len > SIZE_MAX - MESH_NETWORK_FRAME_HEADER_SIZE) {
        return MESH_ERR_INVALID_ARG;
    }
    total = MESH_NETWORK_FRAME_HEADER_SIZE + view->payload_len;
    if (total > out_capacity || total > MESH_NETWORK_FRAME_MAX) {
        return MESH_ERR_RESOURCE_EXHAUSTED;
    }
    memset(out, 0, MESH_NETWORK_FRAME_HEADER_SIZE);
    memcpy(out, MESH_NETWORK_FRAME_MAGIC, 4u);
    out[4] = MESH_NETWORK_FRAME_VERSION;
    out[5] = view->kind;
    mesh_network_write_u16(out + 8u, MESH_NETWORK_FRAME_HEADER_SIZE);
    mesh_network_write_u32(out + 12u, (uint32_t)view->payload_len);
    memcpy(out + 16u, view->network_uid.bytes,
           sizeof(view->network_uid.bytes));
    mesh_network_write_u64(out + 32u, view->generation);
    mesh_network_write_u64(out + 40u, view->policy_epoch);
    memcpy(out + 48u, view->source_node_id,
           sizeof(view->source_node_id));
    memcpy(out + 80u, view->destination_node_id,
           sizeof(view->destination_node_id));
    mesh_network_write_u64(out + 112u, view->sequence);
    out[120] = view->hop_limit;
    out[121] = view->address_family;
    mesh_network_write_u32(out + 124u, view->source_ipv4);
    mesh_network_write_u32(out + 128u, view->destination_ipv4);
    if (view->payload_len > 0u) {
        memcpy(out + MESH_NETWORK_FRAME_HEADER_SIZE, view->payload,
               view->payload_len);
    }
    *out_len = total;
    return MESH_OK;
}

static int mesh_network_frame_decode(const uint8_t *frame, size_t frame_len,
                                     mesh_network_frame_view_v2_t *view) {
    size_t payload_len;
    size_t index;
    if (!frame || !view || frame_len < MESH_NETWORK_FRAME_HEADER_SIZE ||
        frame_len > MESH_NETWORK_FRAME_MAX ||
        memcmp(frame, MESH_NETWORK_FRAME_MAGIC, 4u) != 0 ||
        frame[4] != MESH_NETWORK_FRAME_VERSION || frame[6] != 0u ||
        frame[7] != 0u ||
        mesh_network_read_u16(frame + 8u) != MESH_NETWORK_FRAME_HEADER_SIZE ||
        frame[10] != 0u || frame[11] != 0u) {
        return MESH_ERR_INVALID_ARG;
    }
    for (index = 122u; index < 124u; ++index) {
        if (frame[index] != 0u) {
            return MESH_ERR_INVALID_ARG;
        }
    }
    for (index = 132u; index < MESH_NETWORK_FRAME_HEADER_SIZE; ++index) {
        if (frame[index] != 0u) {
            return MESH_ERR_INVALID_ARG;
        }
    }
    payload_len = mesh_network_read_u32(frame + 12u);
    if (payload_len != frame_len - MESH_NETWORK_FRAME_HEADER_SIZE) {
        return MESH_ERR_INVALID_ARG;
    }
    memset(view, 0, sizeof(*view));
    view->kind = frame[5];
    memcpy(view->network_uid.bytes, frame + 16u,
           sizeof(view->network_uid.bytes));
    view->generation = mesh_network_read_u64(frame + 32u);
    view->policy_epoch = mesh_network_read_u64(frame + 40u);
    memcpy(view->source_node_id, frame + 48u,
           sizeof(view->source_node_id));
    memcpy(view->destination_node_id, frame + 80u,
           sizeof(view->destination_node_id));
    view->sequence = mesh_network_read_u64(frame + 112u);
    view->hop_limit = frame[120];
    view->address_family = frame[121];
    view->source_ipv4 = mesh_network_read_u32(frame + 124u);
    view->destination_ipv4 = mesh_network_read_u32(frame + 128u);
    view->payload = frame + MESH_NETWORK_FRAME_HEADER_SIZE;
    view->payload_len = payload_len;
    if (mesh_network_bytes_are_zero(view->network_uid.bytes,
                                    sizeof(view->network_uid.bytes)) ||
        mesh_network_bytes_are_zero(view->source_node_id,
                                    sizeof(view->source_node_id))) {
        return MESH_ERR_INVALID_ARG;
    }
    return MESH_OK;
}

static int mesh_network_ipv4_packet_valid(const uint8_t *packet,
                                          size_t packet_len,
                                          uint32_t expected_source,
                                          uint32_t expected_destination) {
    size_t header_len;
    uint16_t total_len;
    uint32_t source;
    uint32_t destination;
    if (!packet || packet_len < 20u || (packet[0] >> 4) != 4u) {
        return 0;
    }
    header_len = (size_t)(packet[0] & 0x0fu) * 4u;
    total_len = mesh_network_read_u16(packet + 2u);
    if (header_len < 20u || header_len > packet_len ||
        total_len < header_len || total_len != packet_len) {
        return 0;
    }
    source = mesh_network_read_u32(packet + 12u);
    destination = mesh_network_read_u32(packet + 16u);
    return source == expected_source && destination == expected_destination;
}

static int mesh_network_send_frame(mesh_fabric_t *fabric,
                                   const uint8_t destination_node_id[32],
                                   const mesh_network_frame_view_v2_t *view) {
    uint8_t *frame;
    size_t frame_len = 0;
    size_t capacity;
    int result;
    if (!fabric || !destination_node_id || !view ||
        view->payload_len > SIZE_MAX - MESH_NETWORK_FRAME_HEADER_SIZE) {
        return MESH_ERR_INVALID_ARG;
    }
    capacity = MESH_NETWORK_FRAME_HEADER_SIZE + view->payload_len;
    frame = (uint8_t *)malloc(capacity);
    if (!frame) {
        return MESH_ERR_NO_MEMORY;
    }
    result = mesh_network_frame_encode(view, frame, capacity, &frame_len);
    if (result == MESH_OK) {
        result = mesh_internal_send_to_node_v2(
            fabric->underlay, destination_node_id, frame, frame_len);
    }
    free(frame);
    return result;
}

static int mesh_network_send_open_to_peer(
    mesh_network_state_v2_t *network,
    const uint8_t destination_node_id[MESH_NETWORK_IDENTITY_SIZE]) {
    mesh_network_frame_view_v2_t frame;
    uint8_t ticket[MESH_NETWORK_TICKET_WIRE_SIZE];
    size_t ticket_len = 0;
    int result;
    if (!network || !destination_node_id ||
        !mesh_network_peer_authorized(network, destination_node_id) ||
        network->lifecycle != MESH_NETWORK_ACTIVE ||
        !mesh_network_ticket_is_current(&network->local_membership,
                                        mesh_network_now_unix_s())) {
        return network && network->lifecycle == MESH_NETWORK_ACTIVE
                   ? MESH_ERR_UNAUTHORIZED
                   : MESH_ERR_CLOSED;
    }
    result = mesh_network_membership_ticket_encode_v1(
        &network->local_membership, ticket, sizeof(ticket), &ticket_len);
    if (result != MESH_OK) {
        return result;
    }
    memset(&frame, 0, sizeof(frame));
    frame.kind = MESH_NETWORK_FRAME_KIND_OPEN;
    frame.network_uid = network->uid;
    frame.generation = network->generation;
    frame.policy_epoch = network->policy_epoch;
    memcpy(frame.source_node_id, network->fabric->local_node_id,
           sizeof(frame.source_node_id));
    memcpy(frame.destination_node_id, destination_node_id,
           sizeof(frame.destination_node_id));
    frame.address_family = MESH_NETWORK_FRAME_FAMILY_IPV4;
    frame.source_ipv4 = network->local_membership.ipv4_address;
    frame.payload = ticket;
    frame.payload_len = ticket_len;
    result = mesh_network_send_frame(network->fabric, destination_node_id,
                                     &frame);
    mesh_mgmt_crypto_wipe(ticket, sizeof(ticket));
    return result;
}

static int mesh_network_peer_visit_send_open(
    const uint8_t node_id[MESH_NETWORK_IDENTITY_SIZE], void *user_data) {
    mesh_network_state_v2_t *network = (mesh_network_state_v2_t *)user_data;
    (void)mesh_network_send_open_to_peer(network, node_id);
    return 1;
}

static int mesh_network_validate_local_ticket(
    mesh_fabric_t *fabric, const mesh_network_spec_v2_t *spec) {
    const mesh_network_membership_ticket_v1_t *ticket;
    const mesh_network_issuer_v1_t *issuer;
    uint8_t digest[MESH_NETWORK_IDENTITY_SIZE];
    int result = MESH_ERR_UNAUTHORIZED;
    if (!fabric || !spec) {
        return MESH_ERR_INVALID_ARG;
    }
    ticket = &spec->local_membership;
    issuer = mesh_network_find_issuer(fabric, ticket->issuer_key_id);
    if (!issuer ||
        mesh_network_membership_ticket_verify_v1(
            ticket, issuer, mesh_network_now_unix_s()) != MESH_OK ||
        !mesh_mgmt_crypto_equal_32(ticket->mesh_id, fabric->mesh_id) ||
        !mesh_network_uid_equal(&ticket->network_uid, &spec->network_uid) ||
        ticket->network_generation != spec->generation ||
        ticket->policy_epoch != spec->policy_epoch ||
        !mesh_mgmt_crypto_equal_32(ticket->managed_node_id,
                                   fabric->local_node_id) ||
        mesh_network_public_key_digest_v1(fabric->local_node_id, digest) !=
            MESH_OK ||
        !mesh_mgmt_crypto_equal_32(ticket->node_public_key_digest, digest)) {
        goto cleanup;
    }
    result = MESH_OK;
cleanup:
    mesh_mgmt_crypto_wipe(digest, sizeof(digest));
    return result;
}

int mesh_fabric_create_v2(const mesh_fabric_config_v2_t *config,
                          mesh_fabric_t **out_fabric) {
    mesh_fabric_t *fabric = NULL;
    char node_id_hex[65];
    const char *network_id;
    size_t index;
    if (!config || !out_fabric || config->struct_size != sizeof(*config) ||
        !config->underlay.virtual_ip ||
        !config->trusted_issuers || config->trusted_issuer_count == 0u ||
        config->trusted_issuer_count > MESH_NETWORK_ISSUER_HARD_LIMIT ||
        config->max_networks == 0u ||
        config->max_networks > MESH_NETWORK_HARD_LIMIT ||
        config->max_peer_network_bindings == 0u ||
        config->max_peer_network_bindings > MESH_NETWORK_BINDING_HARD_LIMIT ||
        config->max_packet_size < 20u ||
        config->max_packet_size >
            MESH_NETWORK_FRAME_MAX - MESH_NETWORK_FRAME_HEADER_SIZE) {
        return MESH_ERR_INVALID_ARG;
    }
    *out_fabric = NULL;
    fabric = (mesh_fabric_t *)calloc(1, sizeof(*fabric));
    if (!fabric) {
        return MESH_ERR_NO_MEMORY;
    }
    fabric->issuers = (mesh_network_issuer_v1_t *)calloc(
        config->trusted_issuer_count, sizeof(*fabric->issuers));
    if (!fabric->issuers) {
        free(fabric);
        return MESH_ERR_NO_MEMORY;
    }
    memcpy(fabric->issuers, config->trusted_issuers,
           config->trusted_issuer_count * sizeof(*fabric->issuers));
    fabric->issuer_count = config->trusted_issuer_count;
    for (index = 0; index < fabric->issuer_count; ++index) {
        if (mesh_network_bytes_are_zero(fabric->issuers[index].key_id, 32u) ||
            mesh_network_bytes_are_zero(fabric->issuers[index].public_key, 32u)) {
            mesh_fabric_destroy_v2(fabric);
            return MESH_ERR_INVALID_ARG;
        }
    }
    fabric->max_networks = config->max_networks;
    fabric->max_bindings = config->max_peer_network_bindings;
    fabric->max_packet_size = config->max_packet_size;
    fabric->lifecycle = MESH_FABRIC_CREATED;
    fabric->underlay = mesh_create(&config->underlay);
    if (!fabric->underlay) {
        mesh_fabric_destroy_v2(fabric);
        return MESH_ERR_NETWORK;
    }
    if (mesh_get_node_id(fabric->underlay, node_id_hex, sizeof(node_id_hex)) !=
            MESH_OK ||
        strlen(node_id_hex) != 64u) {
        mesh_fabric_destroy_v2(fabric);
        return MESH_ERR_NETWORK;
    }
    for (index = 0; index < 32u; ++index) {
        unsigned int byte = 0;
        if (sscanf(node_id_hex + index * 2u, "%2x", &byte) != 1) {
            mesh_fabric_destroy_v2(fabric);
            return MESH_ERR_NETWORK;
        }
        fabric->local_node_id[index] = (uint8_t)byte;
    }
    network_id = config->underlay.network_id
                     ? config->underlay.network_id
                     : "default";
    if (turbo_crypto_sha256(network_id, strlen(network_id), fabric->mesh_id) !=
            TURBO_CRYPTO_OK ||
        mesh_internal_bind_fabric_v2(fabric->underlay, fabric) != MESH_OK) {
        mesh_fabric_destroy_v2(fabric);
        return MESH_ERR_NETWORK;
    }
    *out_fabric = fabric;
    return MESH_OK;
}

mesh_network_t *mesh_internal_fabric_underlay_v2(mesh_fabric_t *fabric) {
    return fabric ? fabric->underlay : NULL;
}

int mesh_fabric_start_v2(mesh_fabric_t *fabric) {
    int result;
    if (!fabric) {
        return MESH_ERR_INVALID_ARG;
    }
    if (fabric->lifecycle != MESH_FABRIC_CREATED) {
        return fabric->lifecycle == MESH_FABRIC_CLOSED ? MESH_ERR_CLOSED
                                                       : MESH_ERR_BUSY;
    }
    result = mesh_start(fabric->underlay);
    if (result == MESH_OK) {
        fabric->lifecycle = MESH_FABRIC_RUNNING;
    }
    return result;
}

int mesh_fabric_poll_v2(mesh_fabric_t *fabric, int timeout_ms) {
    if (!fabric || timeout_ms < 0) {
        return MESH_ERR_INVALID_ARG;
    }
    if (fabric->lifecycle != MESH_FABRIC_RUNNING) {
        return MESH_ERR_CLOSED;
    }
    return mesh_poll(fabric->underlay, timeout_ms);
}

static void mesh_network_remove_bindings(mesh_fabric_t *fabric,
                                         mesh_network_state_v2_t *network,
                                         const uint8_t *node_id) {
    mesh_network_binding_v2_t **link;
    if (!fabric) {
        return;
    }
    link = &fabric->bindings;
    while (*link) {
        mesh_network_binding_v2_t *binding = *link;
        if ((!network || binding->network == network) &&
            (!node_id || mesh_mgmt_crypto_equal_32(binding->node_id, node_id))) {
            *link = binding->next;
            mesh_mgmt_crypto_wipe(binding, sizeof(*binding));
            free(binding);
            fabric->binding_count--;
            continue;
        }
        link = &binding->next;
    }
}

static void mesh_network_send_close(mesh_network_binding_v2_t *binding) {
    mesh_network_frame_view_v2_t frame;
    if (!binding || !binding->active || !binding->network ||
        !binding->network->fabric) {
        return;
    }
    memset(&frame, 0, sizeof(frame));
    frame.kind = MESH_NETWORK_FRAME_KIND_CLOSE;
    frame.network_uid = binding->network->uid;
    frame.generation = binding->network->generation;
    frame.policy_epoch = binding->network->policy_epoch;
    memcpy(frame.source_node_id, binding->network->fabric->local_node_id, 32u);
    memcpy(frame.destination_node_id, binding->node_id, 32u);
    frame.address_family = MESH_NETWORK_FRAME_FAMILY_IPV4;
    frame.source_ipv4 = binding->network->local_membership.ipv4_address;
    frame.destination_ipv4 = binding->ipv4_address;
    (void)mesh_network_send_frame(binding->network->fabric, binding->node_id,
                                  &frame);
}

void mesh_fabric_stop_v2(mesh_fabric_t *fabric) {
    mesh_network_binding_v2_t *binding;
    mesh_network_state_v2_t *network;
    if (!fabric || fabric->lifecycle == MESH_FABRIC_CLOSED ||
        fabric->dispatch_depth != 0u) {
        return;
    }
    fabric->lifecycle = MESH_FABRIC_DRAINING;
    for (network = fabric->networks; network; network = network->next) {
        if (network->lifecycle == MESH_NETWORK_ACTIVE) {
            network->lifecycle = MESH_NETWORK_DRAINING;
        }
    }
    for (binding = fabric->bindings; binding; binding = binding->next) {
        mesh_network_send_close(binding);
    }
    mesh_network_remove_bindings(fabric, NULL, NULL);
    mesh_stop(fabric->underlay);
    for (network = fabric->networks; network; network = network->next) {
        network->lifecycle = MESH_NETWORK_TOMBSTONED;
    }
    fabric->lifecycle = MESH_FABRIC_CLOSED;
}

void mesh_fabric_destroy_v2(mesh_fabric_t *fabric) {
    mesh_network_state_v2_t *network;
    if (!fabric || fabric->dispatch_depth != 0u) {
        return;
    }
    if (fabric->underlay && fabric->lifecycle != MESH_FABRIC_CLOSED) {
        mesh_fabric_stop_v2(fabric);
    }
    mesh_network_remove_bindings(fabric, NULL, NULL);
    network = fabric->networks;
    while (network) {
        mesh_network_state_v2_t *next = network->next;
        mesh_internal_network_handle_destroy_v2(network->handle);
        if (network->authorized_peer_node_ids) {
            mesh_mgmt_crypto_wipe(network->authorized_peer_node_ids,
                                  network->authorized_peer_count * 32u);
            free(network->authorized_peer_node_ids);
        }
        if (network->routes) {
            mesh_mgmt_crypto_wipe(
                network->routes,
                network->route_count * sizeof(*network->routes));
            free(network->routes);
        }
        mesh_mgmt_crypto_wipe(&network->local_membership,
                              sizeof(network->local_membership));
        free(network);
        network = next;
    }
    fabric->networks = NULL;
    fabric->network_count = 0u;
    if (fabric->underlay) {
        mesh_internal_unbind_fabric_v2(fabric->underlay, fabric);
        mesh_destroy(fabric->underlay);
        fabric->underlay = NULL;
    }
    if (fabric->issuers) {
        mesh_mgmt_crypto_wipe(fabric->issuers,
                              fabric->issuer_count * sizeof(*fabric->issuers));
        free(fabric->issuers);
    }
    mesh_mgmt_crypto_wipe(fabric, sizeof(*fabric));
    free(fabric);
}

int mesh_fabric_attach_network_v2(mesh_fabric_t *fabric,
                                  const mesh_network_spec_v2_t *spec,
                                  mesh_network_t **out_network) {
    mesh_network_state_v2_t *network;
    mesh_network_state_v2_t *existing;
    size_t name_len;
    size_t peer_index;
    int route_result;
    if (!fabric || !spec || !out_network ||
        spec->struct_size != sizeof(*spec) ||
        !mesh_network_name_valid(spec->name) || spec->generation == 0u ||
        spec->policy_epoch == 0u || spec->mtu < MESH_NETWORK_MTU_MIN ||
        spec->mtu > MESH_NETWORK_MTU_MAX ||
        spec->lifecycle != MESH_NETWORK_ACTIVE ||
        spec->authorized_peer_count > MESH_NETWORK_PEER_HARD_LIMIT ||
        (spec->authorized_peer_count != 0u &&
         !spec->authorized_peer_node_ids) ||
        (spec->attach_mode != MESH_NETWORK_ATTACH_USERSPACE &&
         spec->attach_mode != MESH_NETWORK_ATTACH_OS_SHARED &&
         spec->attach_mode != MESH_NETWORK_ATTACH_OS_ISOLATED) ||
        mesh_network_bytes_are_zero(spec->network_uid.bytes,
                                    sizeof(spec->network_uid.bytes))) {
        return MESH_ERR_INVALID_ARG;
    }
    *out_network = NULL;
    if (fabric->dispatch_depth != 0u) {
        return MESH_ERR_BUSY;
    }
    if (spec->attach_mode != MESH_NETWORK_ATTACH_USERSPACE) {
        return MESH_ERR_UNSUPPORTED;
    }
    if (fabric->lifecycle == MESH_FABRIC_DRAINING ||
        fabric->lifecycle == MESH_FABRIC_CLOSED) {
        return MESH_ERR_CLOSED;
    }
    if (fabric->network_count >= fabric->max_networks) {
        fabric->capacity_rejections++;
        return MESH_ERR_RESOURCE_EXHAUSTED;
    }
    if (mesh_network_find(fabric, &spec->network_uid)) {
        return MESH_ERR_ALREADY_EXISTS;
    }
    if (mesh_network_validate_local_ticket(fabric, spec) != MESH_OK) {
        return MESH_ERR_UNAUTHORIZED;
    }
    for (peer_index = 0; peer_index < spec->authorized_peer_count;
         ++peer_index) {
        const uint8_t *peer_id = spec->authorized_peer_node_ids +
                                 peer_index * MESH_NETWORK_IDENTITY_SIZE;
        size_t previous;
        if (mesh_network_bytes_are_zero(peer_id,
                                        MESH_NETWORK_IDENTITY_SIZE) ||
            mesh_mgmt_crypto_equal_32(peer_id, fabric->local_node_id)) {
            return MESH_ERR_INVALID_ARG;
        }
        for (previous = 0; previous < peer_index; ++previous) {
            if (mesh_mgmt_crypto_equal_32(
                    peer_id, spec->authorized_peer_node_ids +
                                 previous * MESH_NETWORK_IDENTITY_SIZE)) {
                return MESH_ERR_INVALID_ARG;
            }
        }
    }
    route_result = mesh_network_routes_validate(fabric, spec);
    if (route_result != MESH_OK) {
        return route_result;
    }
    for (existing = fabric->networks; existing; existing = existing->next) {
        if (strcmp(existing->name, spec->name) == 0) {
            return MESH_ERR_CONFLICT;
        }
    }
    network = (mesh_network_state_v2_t *)calloc(1, sizeof(*network));
    if (!network) {
        return MESH_ERR_NO_MEMORY;
    }
    network->handle = mesh_internal_network_handle_create_v2(network);
    if (!network->handle) {
        free(network);
        return MESH_ERR_NO_MEMORY;
    }
    network->fabric = fabric;
    network->uid = spec->network_uid;
    name_len = strlen(spec->name);
    memcpy(network->name, spec->name, name_len + 1u);
    network->generation = spec->generation;
    network->policy_epoch = spec->policy_epoch;
    network->mtu = spec->mtu;
    network->lifecycle = spec->lifecycle;
    network->attach_mode = spec->attach_mode;
    network->local_membership = spec->local_membership;
    if (spec->authorized_peer_count != 0u) {
        network->authorized_peer_node_ids = (uint8_t *)malloc(
            spec->authorized_peer_count * MESH_NETWORK_IDENTITY_SIZE);
        if (!network->authorized_peer_node_ids) {
            mesh_internal_network_handle_destroy_v2(network->handle);
            mesh_mgmt_crypto_wipe(&network->local_membership,
                                  sizeof(network->local_membership));
            free(network);
            return MESH_ERR_NO_MEMORY;
        }
        memcpy(network->authorized_peer_node_ids,
               spec->authorized_peer_node_ids,
               spec->authorized_peer_count * MESH_NETWORK_IDENTITY_SIZE);
        network->authorized_peer_count = spec->authorized_peer_count;
    }
    network->routes = mesh_network_routes_copy(spec);
    if (spec->route_count != 0u && !network->routes) {
        if (network->authorized_peer_node_ids) {
            mesh_mgmt_crypto_wipe(
                network->authorized_peer_node_ids,
                network->authorized_peer_count * MESH_NETWORK_IDENTITY_SIZE);
            free(network->authorized_peer_node_ids);
        }
        mesh_internal_network_handle_destroy_v2(network->handle);
        mesh_mgmt_crypto_wipe(&network->local_membership,
                              sizeof(network->local_membership));
        free(network);
        return MESH_ERR_NO_MEMORY;
    }
    network->route_epoch = spec->route_epoch;
    network->route_count = spec->route_count;
    network->authorize_packet = spec->authorize_packet;
    network->on_packet_received = spec->on_packet_received;
    network->user_data = spec->user_data;
    network->next = fabric->networks;
    fabric->networks = network;
    fabric->network_count++;
    *out_network = network->handle;
    if (fabric->lifecycle == MESH_FABRIC_RUNNING) {
        (void)mesh_internal_visit_v2_peers(fabric->underlay,
                                           mesh_network_peer_visit_send_open,
                                           network);
    }
    return MESH_OK;
}

int mesh_network_apply_snapshot_v2(mesh_network_t *network_handle,
                                   uint64_t expected_generation,
                                   const mesh_network_spec_v2_t *spec,
                                   uint64_t *out_generation) {
    mesh_network_state_v2_t *network =
        (mesh_network_state_v2_t *)mesh_internal_network_handle_state_v2(
            network_handle);
    mesh_fabric_t *fabric;
    mesh_network_state_v2_t *other;
    mesh_network_binding_v2_t *binding;
    uint8_t *new_peer_ids = NULL;
    mesh_network_route_v2_t *new_routes = NULL;
    size_t peer_index;
    size_t name_len;
    int route_result;
    if (!network || !spec || !out_generation ||
        spec->struct_size != sizeof(*spec) ||
        !mesh_network_uid_equal(&network->uid, &spec->network_uid) ||
        !mesh_network_name_valid(spec->name) ||
        spec->lifecycle != MESH_NETWORK_ACTIVE ||
        spec->generation == 0u || spec->policy_epoch == 0u ||
        spec->mtu < MESH_NETWORK_MTU_MIN ||
        spec->mtu > MESH_NETWORK_MTU_MAX ||
        spec->authorized_peer_count > MESH_NETWORK_PEER_HARD_LIMIT ||
        (spec->authorized_peer_count != 0u &&
         !spec->authorized_peer_node_ids) ||
        (spec->attach_mode != MESH_NETWORK_ATTACH_USERSPACE &&
         spec->attach_mode != MESH_NETWORK_ATTACH_OS_SHARED &&
         spec->attach_mode != MESH_NETWORK_ATTACH_OS_ISOLATED)) {
        return MESH_ERR_INVALID_ARG;
    }
    *out_generation = network->generation;
    fabric = network->fabric;
    if (!fabric || fabric->dispatch_depth != 0u) {
        return MESH_ERR_BUSY;
    }
    if (spec->attach_mode != MESH_NETWORK_ATTACH_USERSPACE) {
        return MESH_ERR_UNSUPPORTED;
    }
    if (fabric->lifecycle == MESH_FABRIC_DRAINING ||
        fabric->lifecycle == MESH_FABRIC_CLOSED ||
        network->lifecycle != MESH_NETWORK_ACTIVE) {
        return MESH_ERR_CLOSED;
    }
    if (expected_generation != network->generation ||
        spec->generation <= network->generation) {
        return MESH_ERR_STALE_EPOCH;
    }
    if (mesh_network_validate_local_ticket(fabric, spec) != MESH_OK) {
        return MESH_ERR_UNAUTHORIZED;
    }
    for (peer_index = 0; peer_index < spec->authorized_peer_count;
         ++peer_index) {
        const uint8_t *peer_id = spec->authorized_peer_node_ids +
                                 peer_index * MESH_NETWORK_IDENTITY_SIZE;
        size_t previous;
        if (mesh_network_bytes_are_zero(peer_id, 32u) ||
            mesh_mgmt_crypto_equal_32(peer_id, fabric->local_node_id)) {
            return MESH_ERR_INVALID_ARG;
        }
        for (previous = 0; previous < peer_index; ++previous) {
            if (mesh_mgmt_crypto_equal_32(
                    peer_id, spec->authorized_peer_node_ids + previous * 32u)) {
                return MESH_ERR_INVALID_ARG;
            }
        }
    }
    route_result = mesh_network_routes_validate(fabric, spec);
    if (route_result != MESH_OK) {
        return route_result;
    }
    for (other = fabric->networks; other; other = other->next) {
        if (other == network) {
            continue;
        }
        if (strcmp(other->name, spec->name) == 0) {
            return MESH_ERR_CONFLICT;
        }
    }
    if (spec->authorized_peer_count != 0u) {
        new_peer_ids = (uint8_t *)malloc(spec->authorized_peer_count * 32u);
        if (!new_peer_ids) {
            return MESH_ERR_NO_MEMORY;
        }
        memcpy(new_peer_ids, spec->authorized_peer_node_ids,
               spec->authorized_peer_count * 32u);
    }
    new_routes = mesh_network_routes_copy(spec);
    if (spec->route_count != 0u && !new_routes) {
        if (new_peer_ids) {
            mesh_mgmt_crypto_wipe(new_peer_ids,
                                  spec->authorized_peer_count * 32u);
            free(new_peer_ids);
        }
        return MESH_ERR_NO_MEMORY;
    }

    /* Close under the old generation before the atomic local replacement.
     * A lost CLOSE is harmless: the new generation fences all old data. */
    for (binding = fabric->bindings; binding; binding = binding->next) {
        if (binding->network == network) {
            mesh_network_send_close(binding);
        }
    }
    mesh_network_remove_bindings(fabric, network, NULL);
    if (network->authorized_peer_node_ids) {
        mesh_mgmt_crypto_wipe(network->authorized_peer_node_ids,
                              network->authorized_peer_count * 32u);
        free(network->authorized_peer_node_ids);
    }
    if (network->routes) {
        mesh_mgmt_crypto_wipe(
            network->routes,
            network->route_count * sizeof(*network->routes));
        free(network->routes);
    }
    mesh_mgmt_crypto_wipe(&network->local_membership,
                          sizeof(network->local_membership));
    network->authorized_peer_node_ids = new_peer_ids;
    network->authorized_peer_count = spec->authorized_peer_count;
    network->routes = new_routes;
    network->route_count = spec->route_count;
    network->route_epoch = spec->route_epoch;
    network->local_membership = spec->local_membership;
    network->generation = spec->generation;
    network->policy_epoch = spec->policy_epoch;
    network->mtu = spec->mtu;
    network->attach_mode = spec->attach_mode;
    name_len = strlen(spec->name);
    memset(network->name, 0, sizeof(network->name));
    memcpy(network->name, spec->name, name_len + 1u);
    network->authorize_packet = spec->authorize_packet;
    network->on_packet_received = spec->on_packet_received;
    network->user_data = spec->user_data;
    *out_generation = network->generation;
    if (fabric->lifecycle == MESH_FABRIC_RUNNING) {
        (void)mesh_internal_visit_v2_peers(fabric->underlay,
                                           mesh_network_peer_visit_send_open,
                                           network);
    }
    return MESH_OK;
}

int mesh_fabric_detach_network_v2(mesh_fabric_t *fabric,
                                  const mesh_network_uid_t *network_uid,
                                  uint64_t drain_timeout_ms) {
    mesh_network_state_v2_t **link;
    mesh_network_state_v2_t *network;
    mesh_network_binding_v2_t *binding;
    if (!fabric || !network_uid || drain_timeout_ms == 0u) {
        return MESH_ERR_INVALID_ARG;
    }
    if (fabric->dispatch_depth != 0u) {
        return MESH_ERR_BUSY;
    }
    link = &fabric->networks;
    while (*link && !mesh_network_uid_equal(&(*link)->uid, network_uid)) {
        link = &(*link)->next;
    }
    if (!*link) {
        return MESH_ERR_NOT_FOUND;
    }
    network = *link;
    network->lifecycle = MESH_NETWORK_DRAINING;
    for (binding = fabric->bindings; binding; binding = binding->next) {
        if (binding->network == network) {
            mesh_network_send_close(binding);
        }
    }
    mesh_network_remove_bindings(fabric, network, NULL);
    *link = network->next;
    fabric->network_count--;
    network->lifecycle = MESH_NETWORK_TOMBSTONED;
    mesh_internal_network_handle_destroy_v2(network->handle);
    if (network->authorized_peer_node_ids) {
        mesh_mgmt_crypto_wipe(network->authorized_peer_node_ids,
                              network->authorized_peer_count * 32u);
        free(network->authorized_peer_node_ids);
    }
    if (network->routes) {
        mesh_mgmt_crypto_wipe(
            network->routes,
            network->route_count * sizeof(*network->routes));
        free(network->routes);
    }
    mesh_mgmt_crypto_wipe(&network->local_membership,
                          sizeof(network->local_membership));
    free(network);
    return MESH_OK;
}

int mesh_network_send_packet_v2(mesh_network_t *network_handle,
                                const uint8_t *packet, size_t packet_len,
                                uint64_t deadline_after_ms) {
    mesh_network_state_v2_t *network =
        (mesh_network_state_v2_t *)mesh_internal_network_handle_state_v2(
            network_handle);
    mesh_fabric_t *fabric;
    mesh_network_binding_v2_t *binding;
    const mesh_network_route_v2_t *route = NULL;
    mesh_network_frame_view_v2_t frame;
    uint32_t source;
    uint32_t destination;
    uint64_t now_unix_s;
    uint8_t expired_node_id[MESH_NETWORK_IDENTITY_SIZE];
    int routed = 0;
    int result;
    if (!network || !packet) {
        return MESH_ERR_INVALID_ARG;
    }
    if (deadline_after_ms == 0u) {
        return MESH_ERR_TIMEOUT;
    }
    fabric = network->fabric;
    if (!fabric || network->lifecycle != MESH_NETWORK_ACTIVE ||
        fabric->lifecycle != MESH_FABRIC_RUNNING) {
        return MESH_ERR_CLOSED;
    }
    now_unix_s = mesh_network_now_unix_s();
    if (!mesh_network_ticket_is_current(&network->local_membership,
                                        now_unix_s)) {
        return MESH_ERR_UNAUTHORIZED;
    }
    if (packet_len < 20u || packet_len > fabric->max_packet_size ||
        packet_len > network->mtu) {
        return MESH_ERR_INVALID_ARG;
    }
    source = mesh_network_read_u32(packet + 12u);
    destination = mesh_network_read_u32(packet + 16u);
    if (!mesh_network_ipv4_packet_valid(
            packet, packet_len, network->local_membership.ipv4_address,
            destination) ||
        source != network->local_membership.ipv4_address) {
        return MESH_ERR_INVALID_ARG;
    }
    binding = mesh_network_find_binding(fabric, network, NULL, destination);
    if (!binding || !binding->active) {
        result = mesh_network_resolve_gateway(
            network, destination, now_unix_s, &route, &binding);
        if (result != MESH_OK) {
            network->route_misses++;
            return result;
        }
        routed = 1;
    }
    if (now_unix_s > binding->not_after_unix_s) {
        memcpy(expired_node_id, binding->node_id, sizeof(expired_node_id));
        mesh_network_remove_bindings(fabric, network, expired_node_id);
        return MESH_ERR_UNAUTHORIZED;
    }
    if (!routed && destination != binding->ipv4_address) {
        return MESH_ERR_INVALID_ARG;
    }
    if (network->authorize_packet &&
        !network->authorize_packet(network->handle, MESH_NETWORK_PACKET_OUT,
                                   binding->node_id, packet, packet_len,
                                   network->user_data)) {
        return MESH_ERR_UNAUTHORIZED;
    }
    if (binding->next_tx_sequence == UINT64_MAX) {
        return MESH_ERR_STALE_EPOCH;
    }
    memset(&frame, 0, sizeof(frame));
    frame.kind = MESH_NETWORK_FRAME_KIND_DATA;
    frame.network_uid = network->uid;
    frame.generation = network->generation;
    frame.policy_epoch = network->policy_epoch;
    memcpy(frame.source_node_id, fabric->local_node_id, 32u);
    memcpy(frame.destination_node_id, binding->node_id, 32u);
    frame.sequence = ++binding->next_tx_sequence;
    frame.hop_limit = MESH_NETWORK_FRAME_DIRECT_HOP_LIMIT;
    frame.address_family = MESH_NETWORK_FRAME_FAMILY_IPV4;
    frame.source_ipv4 = source;
    frame.destination_ipv4 = destination;
    frame.payload = packet;
    frame.payload_len = packet_len;
    result = mesh_network_send_frame(fabric, binding->node_id, &frame);
    if (result == MESH_OK) {
        network->packets_tx++;
        network->bytes_tx += packet_len;
        if (routed) {
            network->routed_packets_tx++;
        }
    }
    return result;
}

static int mesh_network_accept_open(
    mesh_fabric_t *fabric,
    const uint8_t authenticated_node_id[MESH_NETWORK_IDENTITY_SIZE],
    const mesh_network_frame_view_v2_t *frame) {
    mesh_network_state_v2_t *network;
    mesh_network_membership_ticket_v1_t ticket;
    const mesh_network_issuer_v1_t *issuer;
    mesh_network_binding_v2_t *binding;
    mesh_network_binding_v2_t *address_owner;
    uint8_t digest[32];
    int new_binding = 0;
    int epoch_advanced = 0;
    int result = MESH_ERR_UNAUTHORIZED;
    memset(&ticket, 0, sizeof(ticket));
    memset(digest, 0, sizeof(digest));
    network = mesh_network_find(fabric, &frame->network_uid);
    if (!network || network->lifecycle != MESH_NETWORK_ACTIVE ||
        !mesh_network_peer_authorized(network, authenticated_node_id) ||
        frame->payload_len != MESH_NETWORK_TICKET_WIRE_SIZE ||
        frame->generation != network->generation ||
        frame->policy_epoch != network->policy_epoch ||
        frame->address_family != MESH_NETWORK_FRAME_FAMILY_IPV4 ||
        frame->sequence != 0u || frame->hop_limit != 0u ||
        !mesh_mgmt_crypto_equal_32(frame->source_node_id,
                                   authenticated_node_id) ||
        !mesh_mgmt_crypto_equal_32(frame->destination_node_id,
                                   fabric->local_node_id) ||
        mesh_network_ticket_decode(frame->payload, frame->payload_len,
                                   &ticket) != MESH_OK) {
        goto cleanup;
    }
    issuer = mesh_network_find_issuer(fabric, ticket.issuer_key_id);
    if (!issuer ||
        mesh_network_membership_ticket_verify_v1(
            &ticket, issuer, mesh_network_now_unix_s()) != MESH_OK ||
        !mesh_mgmt_crypto_equal_32(ticket.mesh_id, fabric->mesh_id) ||
        !mesh_network_uid_equal(&ticket.network_uid, &network->uid) ||
        ticket.network_generation != network->generation ||
        ticket.policy_epoch != network->policy_epoch ||
        !mesh_mgmt_crypto_equal_32(ticket.managed_node_id,
                                   authenticated_node_id) ||
        mesh_network_public_key_digest_v1(authenticated_node_id, digest) !=
            MESH_OK ||
        !mesh_mgmt_crypto_equal_32(ticket.node_public_key_digest, digest) ||
        frame->source_ipv4 != ticket.ipv4_address ||
        frame->destination_ipv4 != 0u ||
        !mesh_network_prefix_contains(
            network->local_membership.ipv4_address,
            network->local_membership.ipv4_prefix, ticket.ipv4_address)) {
        goto cleanup;
    }
    address_owner = mesh_network_find_binding(fabric, network, NULL,
                                              ticket.ipv4_address);
    if (address_owner &&
        !mesh_mgmt_crypto_equal_32(address_owner->node_id,
                                   authenticated_node_id)) {
        result = MESH_ERR_CONFLICT;
        goto cleanup;
    }
    binding = mesh_network_find_binding(fabric, network,
                                        authenticated_node_id, 0u);
    if (binding &&
        (ticket.membership_generation < binding->membership_generation ||
         ticket.node_key_epoch < binding->node_key_epoch)) {
        result = MESH_ERR_STALE_EPOCH;
        goto cleanup;
    }
    if (binding &&
        ticket.membership_generation == binding->membership_generation &&
        ticket.node_key_epoch == binding->node_key_epoch &&
        (binding->ipv4_address != ticket.ipv4_address ||
         binding->roles != ticket.roles)) {
        result = MESH_ERR_CONFLICT;
        goto cleanup;
    }
    if (!binding) {
        if (fabric->binding_count >= fabric->max_bindings) {
            fabric->capacity_rejections++;
            result = MESH_ERR_RESOURCE_EXHAUSTED;
            goto cleanup;
        }
        binding = (mesh_network_binding_v2_t *)calloc(1, sizeof(*binding));
        if (!binding) {
            result = MESH_ERR_NO_MEMORY;
            goto cleanup;
        }
        binding->network = network;
        memcpy(binding->node_id, authenticated_node_id, 32u);
        binding->next = fabric->bindings;
        fabric->bindings = binding;
        fabric->binding_count++;
        new_binding = 1;
    } else if (ticket.membership_generation > binding->membership_generation ||
               ticket.node_key_epoch > binding->node_key_epoch) {
        epoch_advanced = 1;
    }
    binding->ipv4_address = ticket.ipv4_address;
    binding->membership_generation = ticket.membership_generation;
    binding->node_key_epoch = ticket.node_key_epoch;
    binding->not_after_unix_s = ticket.not_after_unix_s;
    binding->roles = ticket.roles;
    if (new_binding || epoch_advanced) {
        binding->last_rx_sequence = 0u;
        binding->next_tx_sequence = 0u;
    }
    binding->active = 1;
    result = MESH_OK;
    if (new_binding || !binding->open_sent) {
        binding->open_sent = 1;
        (void)mesh_network_send_open_to_peer(network, authenticated_node_id);
    }

cleanup:
    mesh_mgmt_crypto_wipe(&ticket, sizeof(ticket));
    mesh_mgmt_crypto_wipe(digest, sizeof(digest));
    return result;
}

static int mesh_network_accept_data(
    mesh_fabric_t *fabric,
    const uint8_t authenticated_node_id[MESH_NETWORK_IDENTITY_SIZE],
    const mesh_network_frame_view_v2_t *frame) {
    mesh_network_state_v2_t *network =
        mesh_network_find(fabric, &frame->network_uid);
    mesh_network_binding_v2_t *binding;
    uint64_t now_unix_s;
    int routed;
    if (!network || network->lifecycle != MESH_NETWORK_ACTIVE) {
        return MESH_ERR_NOT_FOUND;
    }
    binding = mesh_network_find_binding(fabric, network,
                                        authenticated_node_id, 0u);
    now_unix_s = mesh_network_now_unix_s();
    routed = frame->destination_ipv4 !=
             network->local_membership.ipv4_address;
    if (binding &&
        (now_unix_s > binding->not_after_unix_s ||
         !mesh_network_ticket_is_current(&network->local_membership,
                                         now_unix_s))) {
        mesh_network_remove_bindings(fabric, network,
                                     authenticated_node_id);
        network->rejected_frames++;
        return MESH_ERR_UNAUTHORIZED;
    }
    if (!binding || !binding->active ||
        frame->generation != network->generation ||
        frame->policy_epoch != network->policy_epoch ||
        frame->address_family != MESH_NETWORK_FRAME_FAMILY_IPV4 ||
        frame->hop_limit != MESH_NETWORK_FRAME_DIRECT_HOP_LIMIT ||
        frame->sequence == 0u ||
        !mesh_mgmt_crypto_equal_32(frame->source_node_id,
                                   authenticated_node_id) ||
        !mesh_mgmt_crypto_equal_32(frame->destination_node_id,
                                   fabric->local_node_id) ||
        frame->source_ipv4 != binding->ipv4_address ||
        (routed && !mesh_network_accepts_gateway_destination(
                       network, frame->destination_ipv4)) ||
        frame->payload_len > fabric->max_packet_size ||
        frame->payload_len > network->mtu ||
        !mesh_network_ipv4_packet_valid(
            frame->payload, frame->payload_len, binding->ipv4_address,
            frame->destination_ipv4)) {
        network->rejected_frames++;
        return MESH_ERR_UNAUTHORIZED;
    }
    if (frame->sequence <= binding->last_rx_sequence) {
        network->replay_drops++;
        return MESH_ERR_STALE_EPOCH;
    }
    if (network->authorize_packet &&
        !network->authorize_packet(network->handle, MESH_NETWORK_PACKET_IN,
                                   binding->node_id, frame->payload,
                                   frame->payload_len, network->user_data)) {
        return MESH_ERR_UNAUTHORIZED;
    }
    binding->last_rx_sequence = frame->sequence;
    network->packets_rx++;
    network->bytes_rx += frame->payload_len;
    if (routed) {
        network->routed_packets_rx++;
    }
    if (network->on_packet_received) {
        fabric->dispatch_depth++;
        network->on_packet_received(network->handle, binding->node_id,
                                    frame->payload, frame->payload_len,
                                    network->user_data);
        fabric->dispatch_depth--;
    }
    return MESH_OK;
}

static int mesh_network_accept_close(
    mesh_fabric_t *fabric,
    const uint8_t authenticated_node_id[MESH_NETWORK_IDENTITY_SIZE],
    const mesh_network_frame_view_v2_t *frame) {
    mesh_network_state_v2_t *network =
        mesh_network_find(fabric, &frame->network_uid);
    if (!network || frame->payload_len != 0u || frame->sequence != 0u ||
        frame->generation != network->generation ||
        frame->policy_epoch != network->policy_epoch ||
        !mesh_mgmt_crypto_equal_32(frame->source_node_id,
                                   authenticated_node_id) ||
        !mesh_mgmt_crypto_equal_32(frame->destination_node_id,
                                   fabric->local_node_id)) {
        return MESH_ERR_UNAUTHORIZED;
    }
    mesh_network_remove_bindings(fabric, network, authenticated_node_id);
    return MESH_OK;
}

int mesh_multi_network_offer_message_v2(
    mesh_fabric_t *fabric,
    const uint8_t authenticated_node_id[MESH_NETWORK_IDENTITY_SIZE],
    const uint8_t *frame, size_t frame_len) {
    mesh_network_frame_view_v2_t view;
    int result;
    if (!frame || frame_len < 4u ||
        memcmp(frame, MESH_NETWORK_FRAME_MAGIC, 4u) != 0) {
        return 0;
    }
    if (!fabric || !authenticated_node_id ||
        fabric->lifecycle != MESH_FABRIC_RUNNING ||
        mesh_network_frame_decode(frame, frame_len, &view) != MESH_OK) {
        if (fabric) {
            fabric->rejected_frames++;
        }
        return 1;
    }
    switch (view.kind) {
        case MESH_NETWORK_FRAME_KIND_OPEN:
            result = mesh_network_accept_open(fabric, authenticated_node_id,
                                              &view);
            if (result == MESH_ERR_UNAUTHORIZED) {
                fabric->unauthorized_opens++;
            }
            break;
        case MESH_NETWORK_FRAME_KIND_DATA:
            result = mesh_network_accept_data(fabric, authenticated_node_id,
                                              &view);
            break;
        case MESH_NETWORK_FRAME_KIND_CLOSE:
            result = mesh_network_accept_close(fabric, authenticated_node_id,
                                               &view);
            break;
        default:
            result = MESH_ERR_INVALID_ARG;
            break;
    }
    if (result != MESH_OK) {
        fabric->rejected_frames++;
    }
    return 1;
}

void mesh_multi_network_peer_ready_v2(
    mesh_fabric_t *fabric,
    const uint8_t authenticated_node_id[MESH_NETWORK_IDENTITY_SIZE]) {
    mesh_network_state_v2_t *network;
    if (!fabric || !authenticated_node_id ||
        fabric->lifecycle != MESH_FABRIC_RUNNING) {
        return;
    }
    for (network = fabric->networks; network; network = network->next) {
        (void)mesh_network_send_open_to_peer(network, authenticated_node_id);
    }
}

void mesh_multi_network_peer_closed_v2(
    mesh_fabric_t *fabric,
    const uint8_t authenticated_node_id[MESH_NETWORK_IDENTITY_SIZE]) {
    if (!fabric || !authenticated_node_id) {
        return;
    }
    mesh_network_remove_bindings(fabric, NULL, authenticated_node_id);
}

int mesh_network_get_status_v2(mesh_network_t *network_handle,
                               mesh_network_status_v2_t *out_status) {
    mesh_network_state_v2_t *network =
        (mesh_network_state_v2_t *)mesh_internal_network_handle_state_v2(
            network_handle);
    mesh_network_binding_v2_t *binding;
    if (!network || !out_status ||
        out_status->struct_size != sizeof(*out_status)) {
        return MESH_ERR_INVALID_ARG;
    }
    memset(out_status, 0, sizeof(*out_status));
    out_status->struct_size = sizeof(*out_status);
    out_status->network_uid = network->uid;
    out_status->generation = network->generation;
    out_status->policy_epoch = network->policy_epoch;
    out_status->lifecycle = network->lifecycle;
    out_status->ipv4_address = network->local_membership.ipv4_address;
    out_status->ipv4_prefix = network->local_membership.ipv4_prefix;
    out_status->mtu = network->mtu;
    for (binding = network->fabric->bindings; binding; binding = binding->next) {
        if (binding->network == network && binding->active) {
            out_status->active_bindings++;
        }
    }
    out_status->packets_tx = network->packets_tx;
    out_status->packets_rx = network->packets_rx;
    out_status->bytes_tx = network->bytes_tx;
    out_status->bytes_rx = network->bytes_rx;
    out_status->rejected_frames = network->rejected_frames;
    out_status->replay_drops = network->replay_drops;
    out_status->route_epoch = network->route_epoch;
    out_status->route_count = network->route_count;
    out_status->routed_packets_tx = network->routed_packets_tx;
    out_status->routed_packets_rx = network->routed_packets_rx;
    out_status->route_misses = network->route_misses;
    return MESH_OK;
}

int mesh_network_get_route_v2(mesh_network_t *network_handle, size_t index,
                              mesh_network_route_v2_t *out_route) {
    mesh_network_state_v2_t *network =
        (mesh_network_state_v2_t *)mesh_internal_network_handle_state_v2(
            network_handle);
    if (!network || !out_route) {
        return MESH_ERR_INVALID_ARG;
    }
    if (network->lifecycle == MESH_NETWORK_TOMBSTONED) {
        return MESH_ERR_CLOSED;
    }
    if (index >= network->route_count) {
        return MESH_ERR_NOT_FOUND;
    }
    *out_route = network->routes[index];
    return MESH_OK;
}

int mesh_network_lookup_route_v2(mesh_network_t *network_handle,
                                 uint32_t destination_ipv4,
                                 mesh_network_route_v2_t *out_route) {
    mesh_network_state_v2_t *network =
        (mesh_network_state_v2_t *)mesh_internal_network_handle_state_v2(
            network_handle);
    const mesh_network_route_v2_t *best = NULL;
    size_t index;
    if (!network || !out_route) {
        return MESH_ERR_INVALID_ARG;
    }
    if (network->lifecycle == MESH_NETWORK_TOMBSTONED) {
        return MESH_ERR_CLOSED;
    }
    for (index = 0u; index < network->route_count; ++index) {
        const mesh_network_route_v2_t *candidate = &network->routes[index];
        if (mesh_network_prefix_contains(candidate->destination_network,
                                         candidate->prefix_length,
                                         destination_ipv4) &&
            mesh_network_route_is_better(candidate, best)) {
            best = candidate;
        }
    }
    if (!best) {
        return MESH_ERR_NOT_FOUND;
    }
    *out_route = *best;
    return MESH_OK;
}

int mesh_fabric_get_status_v2(mesh_fabric_t *fabric,
                              mesh_fabric_status_v2_t *out_status) {
    if (!fabric || !out_status ||
        out_status->struct_size != sizeof(*out_status)) {
        return MESH_ERR_INVALID_ARG;
    }
    memset(out_status, 0, sizeof(*out_status));
    out_status->struct_size = sizeof(*out_status);
    out_status->attached_networks = fabric->network_count;
    out_status->active_bindings = fabric->binding_count;
    out_status->max_networks = fabric->max_networks;
    out_status->max_bindings = fabric->max_bindings;
    out_status->rejected_frames = fabric->rejected_frames;
    out_status->unauthorized_opens = fabric->unauthorized_opens;
    out_status->capacity_rejections = fabric->capacity_rejections;
    return MESH_OK;
}
