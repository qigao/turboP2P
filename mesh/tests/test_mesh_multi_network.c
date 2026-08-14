#include <tinytest.h>

#include <turbo_mesh_multi_network.h>
#include <p2p.h>
#include <turbo_crypto.h>

#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#define mesh_test_sleep_ms(value) Sleep(value)
#else
#include <unistd.h>
#define mesh_test_sleep_ms(value) usleep((value) * 1000)
#endif

static const uint8_t CONTROLLER_PRIVATE_KEY[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};

static const uint8_t CONTROLLER_PUBLIC_KEY[32] = {
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
    0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
};

typedef struct {
    unsigned int received;
    uint8_t last_packet[64];
    size_t last_packet_len;
} mesh_multi_test_receiver_t;

static void mesh_multi_test_hex(const uint8_t bytes[32], char out[65]) {
    static const char digits[] = "0123456789abcdef";
    size_t index;
    for (index = 0; index < 32u; ++index) {
        out[index * 2u] = digits[bytes[index] >> 4u];
        out[index * 2u + 1u] = digits[bytes[index] & 0x0fu];
    }
    out[64] = '\0';
}

static void mesh_multi_test_packet_received(
    mesh_network_t *network, const uint8_t remote_node_id[32],
    const uint8_t *packet, size_t packet_len, void *user_data) {
    mesh_multi_test_receiver_t *receiver =
        (mesh_multi_test_receiver_t *)user_data;
    (void)network;
    (void)remote_node_id;
    if (!receiver || !packet || packet_len > sizeof(receiver->last_packet)) {
        return;
    }
    receiver->received++;
    receiver->last_packet_len = packet_len;
    memcpy(receiver->last_packet, packet, packet_len);
}

static void mesh_multi_test_make_packet(uint8_t packet[20],
                                        uint32_t source,
                                        uint32_t destination) {
    memset(packet, 0, 20u);
    packet[0] = 0x45u;
    packet[2] = 0u;
    packet[3] = 20u;
    packet[8] = 64u;
    packet[9] = 1u;
    packet[12] = (uint8_t)(source >> 24);
    packet[13] = (uint8_t)(source >> 16);
    packet[14] = (uint8_t)(source >> 8);
    packet[15] = (uint8_t)source;
    packet[16] = (uint8_t)(destination >> 24);
    packet[17] = (uint8_t)(destination >> 16);
    packet[18] = (uint8_t)(destination >> 8);
    packet[19] = (uint8_t)destination;
}

static void mesh_multi_test_fill_ticket(
    mesh_network_membership_ticket_v1_t *ticket,
    const uint8_t mesh_id[32], const mesh_network_uid_t *network_uid,
    const uint8_t node_id[32], uint32_t ipv4_address,
    uint8_t membership_marker, const mesh_network_issuer_v1_t *issuer) {
    uint64_t now = (uint64_t)time(NULL);
    memset(ticket, 0, sizeof(*ticket));
    memcpy(ticket->mesh_id, mesh_id, 32u);
    ticket->network_uid = *network_uid;
    memset(ticket->membership_id, membership_marker,
           sizeof(ticket->membership_id));
    memcpy(ticket->managed_node_id, node_id, 32u);
    check_int_eq(MESH_OK, mesh_network_public_key_digest_v1(
                                node_id, ticket->node_public_key_digest));
    ticket->network_generation = 1u;
    ticket->membership_generation = 1u;
    ticket->node_key_epoch = 1u;
    ticket->policy_epoch = 1u;
    ticket->ipv4_address = ipv4_address;
    ticket->ipv4_prefix = 24u;
    ticket->roles = MESH_NETWORK_ROLE_MEMBER;
    ticket->issued_at_unix_s = now - 1u;
    ticket->not_before_unix_s = now - 1u;
    ticket->not_after_unix_s = now + 3600u;
    memcpy(ticket->issuer_key_id, issuer->key_id, 32u);
    check_int_eq(MESH_OK, mesh_network_membership_ticket_sign_v1(
                                ticket, CONTROLLER_PRIVATE_KEY));
}

static void mesh_multi_test_ticket_round_trip_and_tamper(void) {
    mesh_network_membership_ticket_v1_t ticket;
    mesh_network_issuer_v1_t issuer;
    mesh_network_uid_t uid;
    uint8_t mesh_id[32];
    uint8_t node_id[32];
    uint8_t wire[512];
    size_t wire_len = 0;
    uint64_t now = (uint64_t)time(NULL);

    memset(&issuer, 0, sizeof(issuer));
    memset(&uid, 0x31, sizeof(uid));
    memset(mesh_id, 0x41, sizeof(mesh_id));
    memset(node_id, 0x51, sizeof(node_id));
    memset(issuer.key_id, 0x61, sizeof(issuer.key_id));
    memcpy(issuer.public_key, CONTROLLER_PUBLIC_KEY,
           sizeof(issuer.public_key));

    mesh_multi_test_fill_ticket(&ticket, mesh_id, &uid, node_id,
                                0x0a640001u, 0x71u, &issuer);
    check_int_eq(MESH_OK, mesh_network_membership_ticket_verify_v1(
                                &ticket, &issuer, now));
    check_int_eq(MESH_OK, mesh_network_membership_ticket_encode_v1(
                                &ticket, wire, sizeof(wire), &wire_len));
    check_uint_eq(300u, wire_len);

    ticket.signature[0] ^= 1u;
    check_int_eq(MESH_ERR_UNAUTHORIZED,
                 mesh_network_membership_ticket_verify_v1(
                     &ticket, &issuer, now));
    ticket.signature[0] ^= 1u;
    ticket.roles |= 0x80000000u;
    check_int_eq(MESH_OK, mesh_network_membership_ticket_sign_v1(
                                &ticket, CONTROLLER_PRIVATE_KEY));
    check_int_eq(MESH_ERR_UNAUTHORIZED,
                 mesh_network_membership_ticket_verify_v1(
                     &ticket, &issuer, now));
    ticket.roles = MESH_NETWORK_ROLE_MEMBER;
    check_int_eq(MESH_OK, mesh_network_membership_ticket_sign_v1(
                                &ticket, CONTROLLER_PRIVATE_KEY));
    check_int_eq(MESH_ERR_UNAUTHORIZED,
                 mesh_network_membership_ticket_verify_v1(
                     &ticket, &issuer, ticket.not_after_unix_s + 1u));
}

static void mesh_multi_test_default_uid_is_stable(void) {
    static const uint8_t expected[MESH_NETWORK_UID_SIZE] = {
        0x9f, 0xd1, 0x92, 0x40, 0xb4, 0xa4, 0xf4, 0x07,
        0xce, 0x0f, 0x19, 0x5b, 0x15, 0x3a, 0x53, 0x4c,
    };
    mesh_network_uid_t uid;
    memset(&uid, 0, sizeof(uid));
    check_int_eq(MESH_OK, mesh_network_default_uid_v2("multi-test", &uid));
    check_mem_eq(expected, uid.bytes, sizeof(expected));
}

static int mesh_multi_test_wait_bindings(mesh_fabric_t *left,
                                         mesh_fabric_t *right,
                                         mesh_network_t **networks,
                                         size_t network_count) {
    size_t round;
    for (round = 0; round < 500u; ++round) {
        size_t index;
        int ready = 1;
        (void)mesh_fabric_poll_v2(left, 0);
        (void)mesh_fabric_poll_v2(right, 0);
        for (index = 0; index < network_count; ++index) {
            mesh_network_status_v2_t status;
            memset(&status, 0, sizeof(status));
            status.struct_size = sizeof(status);
            if (mesh_network_get_status_v2(networks[index], &status) !=
                    MESH_OK ||
                status.active_bindings != 1u) {
                ready = 0;
                break;
            }
        }
        if (ready) {
            return 1;
        }
        mesh_test_sleep_ms(2);
    }
    return 0;
}

static void mesh_multi_test_shared_underlay_isolates_networks(void) {
    static const char *left_bootstrap[] = {"127.0.0.1:23992"};
    uint8_t left_private[32];
    uint8_t right_private[32];
    uint8_t left_public[32];
    uint8_t right_public[32];
    char left_public_hex[65];
    char right_public_hex[65];
    const char *trusted_nodes[2];
    mesh_network_issuer_v1_t issuer;
    mesh_fabric_config_v2_t left_config;
    mesh_fabric_config_v2_t right_config;
    mesh_fabric_t *left = NULL;
    mesh_fabric_t *right = NULL;
    mesh_network_uid_t network_a_uid;
    mesh_network_uid_t network_b_uid;
    mesh_network_uid_t network_os_uid;
    mesh_network_spec_v2_t spec;
    mesh_network_route_v2_t gateway_routes[2];
    mesh_network_route_v2_t route_info;
    mesh_network_t *left_a = NULL;
    mesh_network_t *right_a = NULL;
    mesh_network_t *left_b = NULL;
    mesh_network_t *right_b = NULL;
    mesh_network_t *unsupported_network = NULL;
    mesh_network_t *all_networks[4];
    mesh_multi_test_receiver_t left_a_rx = {0};
    mesh_multi_test_receiver_t right_a_rx = {0};
    mesh_multi_test_receiver_t left_b_rx = {0};
    mesh_multi_test_receiver_t right_b_rx = {0};
    uint8_t mesh_id[32];
    uint8_t packet[20];
    mesh_fabric_status_v2_t fabric_status;
    mesh_network_status_v2_t network_status;

    memset(left_private, 0x11, sizeof(left_private));
    memset(right_private, 0x22, sizeof(right_private));
    check_int_eq(P2P_OK, p2p_public_key_from_private_key(left_private,
                                                         left_public));
    check_int_eq(P2P_OK, p2p_public_key_from_private_key(right_private,
                                                         right_public));
    mesh_multi_test_hex(left_public, left_public_hex);
    mesh_multi_test_hex(right_public, right_public_hex);
    trusted_nodes[0] = left_public_hex;
    trusted_nodes[1] = right_public_hex;

    memset(&issuer, 0, sizeof(issuer));
    memset(issuer.key_id, 0x61, sizeof(issuer.key_id));
    memcpy(issuer.public_key, CONTROLLER_PUBLIC_KEY,
           sizeof(issuer.public_key));
    check_int_eq(TURBO_CRYPTO_OK,
                 turbo_crypto_sha256("multi-test", strlen("multi-test"),
                                     mesh_id));
    memset(&network_a_uid, 0xa1, sizeof(network_a_uid));
    memset(&network_b_uid, 0xb2, sizeof(network_b_uid));
    memset(&network_os_uid, 0xc3, sizeof(network_os_uid));
    memset(gateway_routes, 0, sizeof(gateway_routes));
    gateway_routes[0].kind = MESH_NETWORK_ROUTE_EXIT;
    gateway_routes[0].metric = 1u;
    memcpy(gateway_routes[0].next_hop_node_id, right_public,
           sizeof(gateway_routes[0].next_hop_node_id));
    gateway_routes[1].destination_network = 0xcb007100u;
    gateway_routes[1].prefix_length = 24u;
    gateway_routes[1].kind = MESH_NETWORK_ROUTE_SUBNET;
    gateway_routes[1].metric = 10u;
    memcpy(gateway_routes[1].next_hop_node_id, right_public,
           sizeof(gateway_routes[1].next_hop_node_id));

    mesh_fabric_config_init_v2(&left_config);
    left_config.underlay.virtual_ip = "10.90.0.1";
    left_config.underlay.virtual_prefix = 24u;
    left_config.underlay.listen_port = 23991;
    left_config.underlay.network_id = "multi-test";
    left_config.underlay.identity_private_key = left_private;
    left_config.underlay.identity_private_key_size = sizeof(left_private);
    left_config.underlay.peer_allow_node_ids = trusted_nodes;
    left_config.underlay.peer_allow_node_id_count = 2;
    left_config.underlay.bootstrap_peers = left_bootstrap;
    left_config.underlay.bootstrap_count = 1;
    left_config.trusted_issuers = &issuer;
    left_config.trusted_issuer_count = 1u;

    mesh_fabric_config_init_v2(&right_config);
    right_config.underlay.virtual_ip = "10.90.0.2";
    right_config.underlay.virtual_prefix = 24u;
    right_config.underlay.listen_port = 23992;
    right_config.underlay.network_id = "multi-test";
    right_config.underlay.identity_private_key = right_private;
    right_config.underlay.identity_private_key_size = sizeof(right_private);
    right_config.underlay.peer_allow_node_ids = trusted_nodes;
    right_config.underlay.peer_allow_node_id_count = 2;
    right_config.trusted_issuers = &issuer;
    right_config.trusted_issuer_count = 1u;

    check_int_eq(MESH_OK, mesh_fabric_create_v2(&right_config, &right));
    check_int_eq(MESH_OK, mesh_fabric_create_v2(&left_config, &left));

    memset(&spec, 0, sizeof(spec));
    spec.struct_size = sizeof(spec);
    spec.network_uid = network_a_uid;
    spec.name = "production";
    spec.generation = 1u;
    spec.policy_epoch = 1u;
    spec.route_epoch = 1u;
    spec.mtu = 1280u;
    spec.lifecycle = MESH_NETWORK_ACTIVE;
    spec.attach_mode = MESH_NETWORK_ATTACH_USERSPACE;
    spec.authorized_peer_node_ids = left_public;
    spec.authorized_peer_count = 1u;
    spec.routes = gateway_routes;
    spec.route_count = 2u;
    mesh_multi_test_fill_ticket(&spec.local_membership, mesh_id,
                                &network_a_uid, right_public, 0x0a640002u,
                                0x12u, &issuer);
    spec.local_membership.roles |=
        MESH_NETWORK_ROLE_SUBNET_ROUTER | MESH_NETWORK_ROLE_EXIT;
    check_int_eq(MESH_OK, mesh_network_membership_ticket_sign_v1(
                                &spec.local_membership,
                                CONTROLLER_PRIVATE_KEY));
    spec.on_packet_received = mesh_multi_test_packet_received;
    spec.user_data = &right_a_rx;
    check_int_eq(MESH_OK, mesh_fabric_attach_network_v2(
                                right, &spec, &right_a));

    mesh_multi_test_fill_ticket(&spec.local_membership, mesh_id,
                                &network_a_uid, left_public, 0x0a640001u,
                                0x11u, &issuer);
    spec.authorized_peer_node_ids = right_public;
    spec.user_data = &left_a_rx;
    check_int_eq(MESH_OK, mesh_fabric_attach_network_v2(left, &spec, &left_a));

    spec.network_uid = network_b_uid;
    spec.name = "backup";
    spec.routes = NULL;
    spec.route_count = 0u;
    mesh_multi_test_fill_ticket(&spec.local_membership, mesh_id,
                                &network_b_uid, right_public, 0x0a640002u,
                                0x22u, &issuer);
    spec.authorized_peer_node_ids = left_public;
    spec.user_data = &right_b_rx;
    check_int_eq(MESH_OK, mesh_fabric_attach_network_v2(
                                right, &spec, &right_b));

    mesh_multi_test_fill_ticket(&spec.local_membership, mesh_id,
                                &network_b_uid, left_public, 0x0a640001u,
                                0x21u, &issuer);
    spec.authorized_peer_node_ids = right_public;
    spec.routes = &gateway_routes[1];
    spec.route_count = 1u;
    spec.user_data = &left_b_rx;
    check_int_eq(MESH_OK, mesh_fabric_attach_network_v2(left, &spec, &left_b));

    spec.network_uid = network_os_uid;
    spec.name = "os-shared";
    spec.routes = NULL;
    spec.route_count = 0u;
    spec.mtu = MESH_NETWORK_MTU_MIN - 1u;
    mesh_multi_test_fill_ticket(&spec.local_membership, mesh_id,
                                &network_os_uid, left_public, 0x0a650001u,
                                0x31u, &issuer);
    check_int_eq(MESH_ERR_INVALID_ARG,
                 mesh_fabric_attach_network_v2(left, &spec,
                                               &unsupported_network));
    spec.mtu = 1280u;
    spec.routes = &gateway_routes[1];
    spec.route_count = MESH_NETWORK_ROUTE_HARD_LIMIT + 1u;
    check_int_eq(MESH_ERR_INVALID_ARG,
                 mesh_fabric_attach_network_v2(left, &spec,
                                               &unsupported_network));
    spec.route_count = 1u;
    gateway_routes[1].destination_network = 0xcb007101u;
    check_int_eq(MESH_ERR_INVALID_ARG,
                 mesh_fabric_attach_network_v2(left, &spec,
                                               &unsupported_network));
    gateway_routes[1].destination_network = 0xcb007100u;
    memcpy(gateway_routes[1].next_hop_node_id, left_public,
           sizeof(gateway_routes[1].next_hop_node_id));
    check_int_eq(MESH_ERR_UNAUTHORIZED,
                 mesh_fabric_attach_network_v2(left, &spec,
                                               &unsupported_network));
    memcpy(gateway_routes[1].next_hop_node_id, right_public,
           sizeof(gateway_routes[1].next_hop_node_id));
    spec.routes = NULL;
    spec.route_count = 0u;
    spec.attach_mode = MESH_NETWORK_ATTACH_OS_SHARED;
    check_int_eq(MESH_ERR_UNSUPPORTED,
                 mesh_fabric_attach_network_v2(left, &spec,
                                               &unsupported_network));
    check_null(unsupported_network);
    spec.attach_mode = MESH_NETWORK_ATTACH_USERSPACE;
    {
        mesh_fabric_status_v2_t attached_status;
        memset(&attached_status, 0, sizeof(attached_status));
        attached_status.struct_size = sizeof(attached_status);
        check_int_eq(MESH_OK,
                     mesh_fabric_get_status_v2(left, &attached_status));
        check_uint_eq(2u, attached_status.attached_networks);
    }

    check_int_eq(MESH_OK, mesh_fabric_start_v2(right));
    check_int_eq(MESH_OK, mesh_fabric_start_v2(left));
    all_networks[0] = left_a;
    all_networks[1] = right_a;
    all_networks[2] = left_b;
    all_networks[3] = right_b;
    check(mesh_multi_test_wait_bindings(left, right, all_networks, 4u));

    mesh_multi_test_make_packet(packet, 0x0a640001u, 0x0a640002u);
    check_int_eq(MESH_ERR_TIMEOUT,
                 mesh_network_send_packet_v2(left_a, packet, sizeof(packet),
                                             0u));
    check_int_eq(MESH_OK,
                 mesh_network_send_packet_v2(left_a, packet, sizeof(packet),
                                             1000u));
    for (size_t round = 0; right_a_rx.received == 0u && round < 200u; ++round) {
        (void)mesh_fabric_poll_v2(left, 0);
        (void)mesh_fabric_poll_v2(right, 0);
        mesh_test_sleep_ms(1);
    }
    check_uint_eq(1u, right_a_rx.received);
    check_uint_eq(0u, right_b_rx.received);

    mesh_multi_test_make_packet(packet, 0x0a640001u, 0xcb007107u);
    check_int_eq(MESH_OK,
                 mesh_network_send_packet_v2(left_a, packet, sizeof(packet),
                                             1000u));
    for (size_t round = 0; right_a_rx.received < 2u && round < 200u; ++round) {
        (void)mesh_fabric_poll_v2(left, 0);
        (void)mesh_fabric_poll_v2(right, 0);
        mesh_test_sleep_ms(1);
    }
    check_uint_eq(2u, right_a_rx.received);
    check_uint_eq(0u, right_b_rx.received);
    memset(&route_info, 0, sizeof(route_info));
    check_int_eq(MESH_OK, mesh_network_get_route_v2(left_a, 0u,
                                                    &route_info));
    check_uint_eq(0u, route_info.destination_network);
    check_uint_eq(MESH_NETWORK_ROUTE_EXIT, route_info.kind);
    check_int_eq(MESH_OK, mesh_network_get_route_v2(left_a, 1u,
                                                    &route_info));
    check_uint_eq(0xcb007100u, route_info.destination_network);
    check_uint_eq(24u, route_info.prefix_length);
    check_mem_eq(right_public, route_info.next_hop_node_id,
                 sizeof(route_info.next_hop_node_id));
    check_int_eq(MESH_ERR_NOT_FOUND,
                 mesh_network_get_route_v2(left_a, 2u, &route_info));
    check_int_eq(MESH_OK, mesh_network_lookup_route_v2(
                                left_a, 0xcb007107u, &route_info));
    check_uint_eq(MESH_NETWORK_ROUTE_SUBNET, route_info.kind);
    check_uint_eq(24u, route_info.prefix_length);
    memset(&network_status, 0, sizeof(network_status));
    network_status.struct_size = sizeof(network_status);
    check_int_eq(MESH_OK,
                 mesh_network_get_status_v2(left_a, &network_status));
    check_uint_eq(2u, network_status.route_count);
    check_uint_eq(1u, network_status.routed_packets_tx);

    mesh_multi_test_make_packet(packet, 0x0a640001u, 0xc6336407u);
    check_int_eq(MESH_OK,
                 mesh_network_send_packet_v2(left_a, packet, sizeof(packet),
                                             1000u));
    for (size_t round = 0; right_a_rx.received < 3u && round < 200u; ++round) {
        (void)mesh_fabric_poll_v2(left, 0);
        (void)mesh_fabric_poll_v2(right, 0);
        mesh_test_sleep_ms(1);
    }
    check_uint_eq(3u, right_a_rx.received);
    check_int_eq(MESH_OK, mesh_network_lookup_route_v2(
                                left_a, 0xc6336407u, &route_info));
    check_uint_eq(MESH_NETWORK_ROUTE_EXIT, route_info.kind);

    /* Network B has the same addresses and route prefix, but the target's
     * signed membership lacks SUBNET_ROUTER. The sender must fail closed. */
    mesh_multi_test_make_packet(packet, 0x0a640001u, 0xcb007107u);
    check_int_eq(MESH_ERR_UNAUTHORIZED,
                 mesh_network_send_packet_v2(left_b, packet, sizeof(packet),
                                             1000u));
    check_uint_eq(0u, right_b_rx.received);

    mesh_multi_test_make_packet(packet, 0x0a640001u, 0x0a640002u);
    check_int_eq(MESH_OK, mesh_network_send_packet_v2(
                                left_b, packet, sizeof(packet), 1000u));
    for (size_t round = 0; right_b_rx.received == 0u && round < 200u; ++round) {
        (void)mesh_fabric_poll_v2(left, 0);
        (void)mesh_fabric_poll_v2(right, 0);
        mesh_test_sleep_ms(1);
    }
    check_uint_eq(3u, right_a_rx.received);
    check_uint_eq(1u, right_b_rx.received);

    /* A committed snapshot generation fences all bindings from the old
     * generation. Both nodes must apply before the Network reopens. */
    spec.network_uid = network_b_uid;
    spec.name = "backup";
    spec.generation = 2u;
    spec.policy_epoch = 2u;
    spec.route_epoch = 2u;
    spec.routes = NULL;
    spec.route_count = 0u;
    spec.authorized_peer_node_ids = left_public;
    mesh_multi_test_fill_ticket(&spec.local_membership, mesh_id,
                                &network_b_uid, right_public, 0x0a640002u,
                                0x22u, &issuer);
    spec.local_membership.network_generation = 2u;
    spec.local_membership.membership_generation = 2u;
    spec.local_membership.policy_epoch = 2u;
    check_int_eq(MESH_OK, mesh_network_membership_ticket_sign_v1(
                                &spec.local_membership,
                                CONTROLLER_PRIVATE_KEY));
    spec.user_data = &right_b_rx;
    {
        uint64_t applied_generation = 0u;
        check_int_eq(MESH_ERR_STALE_EPOCH,
                     mesh_network_apply_snapshot_v2(
                         right_b, 0u, &spec, &applied_generation));
        check_uint_eq(1u, applied_generation);
        check_int_eq(MESH_OK, mesh_network_apply_snapshot_v2(
                                right_b, 1u, &spec, &applied_generation));
        check_uint_eq(2u, applied_generation);
    }

    spec.authorized_peer_node_ids = right_public;
    mesh_multi_test_fill_ticket(&spec.local_membership, mesh_id,
                                &network_b_uid, left_public, 0x0a640001u,
                                0x21u, &issuer);
    spec.local_membership.network_generation = 2u;
    spec.local_membership.membership_generation = 2u;
    spec.local_membership.policy_epoch = 2u;
    check_int_eq(MESH_OK, mesh_network_membership_ticket_sign_v1(
                                &spec.local_membership,
                                CONTROLLER_PRIVATE_KEY));
    spec.user_data = &left_b_rx;
    {
        uint64_t applied_generation = 0u;
        mesh_network_t *updated_networks[2] = {left_b, right_b};
        check_int_eq(MESH_OK, mesh_network_apply_snapshot_v2(
                                left_b, 1u, &spec, &applied_generation));
        check_uint_eq(2u, applied_generation);
        check(mesh_multi_test_wait_bindings(left, right, updated_networks,
                                            2u));
    }
    mesh_multi_test_make_packet(packet, 0x0a640001u, 0xcb007107u);
    check_int_eq(MESH_ERR_NOT_FOUND,
                 mesh_network_send_packet_v2(left_b, packet, sizeof(packet),
                                             1000u));
    memset(&network_status, 0, sizeof(network_status));
    network_status.struct_size = sizeof(network_status);
    check_int_eq(MESH_OK,
                 mesh_network_get_status_v2(left_b, &network_status));
    check_uint_eq(2u, network_status.route_epoch);
    check_uint_eq(0u, network_status.route_count);
    mesh_multi_test_make_packet(packet, 0x0a640001u, 0x0a640002u);

    check_int_eq(MESH_ERR_INVALID_ARG, mesh_fabric_detach_network_v2(
                                left, &network_a_uid, 0u));
    check_int_eq(MESH_OK, mesh_fabric_detach_network_v2(
                                left, &network_a_uid, 100u));
    left_a = NULL;
    for (size_t round = 0; round < 20u; ++round) {
        (void)mesh_fabric_poll_v2(left, 0);
        (void)mesh_fabric_poll_v2(right, 0);
        mesh_test_sleep_ms(1);
    }
    check_int_eq(MESH_OK, mesh_network_send_packet_v2(
                                left_b, packet, sizeof(packet), 1000u));
    for (size_t round = 0; right_b_rx.received < 2u && round < 200u; ++round) {
        (void)mesh_fabric_poll_v2(left, 0);
        (void)mesh_fabric_poll_v2(right, 0);
        mesh_test_sleep_ms(1);
    }
    check_uint_eq(2u, right_b_rx.received);
    memset(&fabric_status, 0, sizeof(fabric_status));
    fabric_status.struct_size = sizeof(fabric_status);
    check_int_eq(MESH_OK, mesh_fabric_get_status_v2(left, &fabric_status));
    check_uint_eq(1u, fabric_status.attached_networks);
    check_uint_eq(1u, fabric_status.active_bindings);

    mesh_fabric_destroy_v2(left);
    mesh_fabric_destroy_v2(right);
}

spec("mesh multi-network") {
    describe("membership ticket") {
        it("uses canonical signed bytes and rejects tamper or expiry") {
            mesh_multi_test_ticket_round_trip_and_tamper();
        }
        it("keeps the legacy default Network UID mapping stable") {
            mesh_multi_test_default_uid_is_stable();
        }
    }
    describe("shared underlay") {
        it("isolates overlapping addresses and drains one Network independently") {
            mesh_multi_test_shared_underlay_isolates_networks();
        }
    }
}
