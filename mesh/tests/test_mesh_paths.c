#include <tinytest.h>
#include <turbo_mesh.h>
#include <p2p.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
static void sleep_ms(int ms) {
    Sleep(ms);
}

static uint64_t now_ms(void) {
    return GetTickCount64();
}
#else
#include <unistd.h>
#include <time.h>
static void sleep_ms(int ms) {
    usleep((useconds_t)ms * 1000);
}

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}
#endif

typedef struct {
    int packet_received_count;
} mesh_packet_counter_t;

typedef struct {
    mesh_network_t *node1;
    mesh_network_t *node2;
    mesh_diag_info_t diag1;
    mesh_diag_info_t diag2;
    int auth_seen;
    int candidate_seen;
    int eoc_seen;
    int checks_started;
    int ice_connected;
} mesh_ice_two_node_progress_t;

static void on_packet_received_counting(const uint8_t *data, size_t len, void *user_data) {
    mesh_packet_counter_t *counter = (mesh_packet_counter_t *)user_data;

    (void)data;
    if (counter) {
        counter->packet_received_count++;
        printf("[TEST] Packet received: %zu bytes (count: %d)\n",
               len, counter->packet_received_count);
    }
}

static void mesh_test_build_ipv4_packet(uint8_t *packet, size_t len,
                                        uint8_t src_a, uint8_t src_b,
                                        uint8_t src_c, uint8_t src_d,
                                        uint8_t dst_a, uint8_t dst_b,
                                        uint8_t dst_c, uint8_t dst_d) {
    memset(packet, 0, len);
    packet[0] = 0x45;
    packet[8] = 64;
    packet[9] = 1;
    packet[12] = src_a;
    packet[13] = src_b;
    packet[14] = src_c;
    packet[15] = src_d;
    packet[16] = dst_a;
    packet[17] = dst_b;
    packet[18] = dst_c;
    packet[19] = dst_d;
}

static void mesh_test_build_tcp_packet(uint8_t *packet, size_t len,
                                       uint8_t src_a, uint8_t src_b,
                                       uint8_t src_c, uint8_t src_d,
                                       uint8_t dst_a, uint8_t dst_b,
                                       uint8_t dst_c, uint8_t dst_d,
                                       uint16_t src_port,
                                       uint16_t dst_port) {
    mesh_test_build_ipv4_packet(packet, len,
                                src_a, src_b, src_c, src_d,
                                dst_a, dst_b, dst_c, dst_d);
    if (len < 24) {
        return;
    }
    packet[9] = 6;
    packet[20] = (uint8_t)(src_port >> 8);
    packet[21] = (uint8_t)(src_port & 0xff);
    packet[22] = (uint8_t)(dst_port >> 8);
    packet[23] = (uint8_t)(dst_port & 0xff);
}

static int mesh_test_hex_value(char c) {
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

static void mesh_test_bytes_to_hex(const uint8_t *bytes, size_t len, char *out, size_t out_len) {
    static const char hex[] = "0123456789abcdef";
    size_t i = 0;

    if (!out || out_len == 0) {
        return;
    }

    if (!bytes || out_len < (len * 2 + 1)) {
        out[0] = '\0';
        return;
    }

    for (i = 0; i < len; i++) {
        out[i * 2] = hex[(bytes[i] >> 4) & 0x0f];
        out[i * 2 + 1] = hex[bytes[i] & 0x0f];
    }
    out[len * 2] = '\0';
}

static int mesh_test_hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    size_t hex_len = 0;
    size_t i = 0;

    if (!hex || !out) {
        return 0;
    }

    hex_len = strlen(hex);
    if (hex_len != out_len * 2) {
        return 0;
    }

    for (i = 0; i < out_len; i++) {
        int hi = mesh_test_hex_value(hex[i * 2]);
        int lo = mesh_test_hex_value(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return 0;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }

    return 1;
}

static int mesh_test_node_id_from_secret_hex(const char *secret_hex, char *node_id_hex, size_t node_id_hex_size) {
    uint8_t secret[P2P_KEY_SIZE] = {0};
    uint8_t public_key[P2P_KEY_SIZE] = {0};

    if (!mesh_test_hex_to_bytes(secret_hex, secret, sizeof(secret))) {
        return 0;
    }

    if (p2p_public_key_from_private_key(secret, public_key) != P2P_OK) {
        return 0;
    }

    mesh_test_bytes_to_hex(public_key, sizeof(public_key), node_id_hex, node_id_hex_size);
    return node_id_hex[0] != '\0';
}

static int mesh_test_find_peer_info(mesh_network_t *mesh, const char *virtual_ip,
                                    mesh_peer_info_t *info) {
    mesh_peer_info_t current;
    int peer_count = mesh_get_peer_count(mesh);

    for (int i = 0; i < peer_count; i++) {
        if (mesh_get_peer_info(mesh, i, &current) != MESH_OK) {
            continue;
        }

        if (strcmp(current.virtual_ip, virtual_ip) == 0) {
            if (info) {
                *info = current;
            }
            return 1;
        }
    }

    return 0;
}

static void mesh_test_stop_destroy(mesh_network_t **mesh_ptr) {
    if (!mesh_ptr || !*mesh_ptr) {
        return;
    }

    mesh_stop(*mesh_ptr);
    mesh_destroy(*mesh_ptr);
    *mesh_ptr = NULL;
}

static void mesh_test_poll_many(mesh_network_t **nodes, int node_count,
                                int iterations, int timeout_ms, int sleep_between_ms) {
    for (int i = 0; i < iterations; i++) {
        for (int j = 0; j < node_count; j++) {
            if (nodes[j]) {
                mesh_poll(nodes[j], timeout_ms);
            }
        }
        if (sleep_between_ms > 0) {
            sleep_ms(sleep_between_ms);
        }
    }
}

static int mesh_test_find_route(mesh_network_t *mesh, const char *dest_ip,
                                mesh_route_info_t *route_info) {
    mesh_route_info_t current;
    int route_count = mesh_get_route_count(mesh);

    for (int i = 0; i < route_count; i++) {
        if (mesh_get_route_info(mesh, i, &current) != MESH_OK) {
            continue;
        }

        if (strcmp(current.dest_ip, dest_ip) == 0) {
            if (route_info) {
                *route_info = current;
            }
            return 1;
        }
    }

    return 0;
}

static int mesh_test_wait_for_min_peers(mesh_network_t **nodes, int node_count,
                                        int expected_per_node, int iterations) {
    for (int i = 0; i < iterations; i++) {
        int ready = 1;

        mesh_test_poll_many(nodes, node_count, 1, 100, 50);
        for (int j = 0; j < node_count; j++) {
            if (!nodes[j]) {
                continue;
            }
            if (mesh_get_peer_count(nodes[j]) < expected_per_node) {
                ready = 0;
            }
        }

        if (ready) {
            return 1;
        }
    }

    return 0;
}

static void mesh_test_capture_ice_two_node_progress(mesh_ice_two_node_progress_t *progress) {
    if (!progress || !progress->node1 || !progress->node2) {
        return;
    }

    memset(&progress->diag1, 0, sizeof(progress->diag1));
    memset(&progress->diag2, 0, sizeof(progress->diag2));
    mesh_get_diag_info(progress->node1, &progress->diag1);
    mesh_get_diag_info(progress->node2, &progress->diag2);

    progress->auth_seen =
        (progress->diag1.ice_auth_messages_tx > 0 && progress->diag1.ice_auth_messages_rx > 0 &&
         progress->diag2.ice_auth_messages_tx > 0 && progress->diag2.ice_auth_messages_rx > 0);
    progress->candidate_seen =
        (progress->diag1.ice_candidate_messages_tx > 0 &&
         progress->diag1.ice_candidate_messages_rx > 0 &&
         progress->diag2.ice_candidate_messages_tx > 0 &&
         progress->diag2.ice_candidate_messages_rx > 0);
    progress->eoc_seen =
        (progress->diag1.ice_end_of_candidates_tx > 0 &&
         progress->diag1.ice_end_of_candidates_rx > 0 &&
         progress->diag2.ice_end_of_candidates_tx > 0 &&
         progress->diag2.ice_end_of_candidates_rx > 0);
    progress->checks_started =
        (progress->diag1.ice_checks_started > 0 && progress->diag2.ice_checks_started > 0 &&
         progress->diag1.ice_last_check_local_candidate_count > 0 &&
         progress->diag1.ice_last_check_remote_candidate_count > 0 &&
         progress->diag2.ice_last_check_local_candidate_count > 0 &&
         progress->diag2.ice_last_check_remote_candidate_count > 0);
    progress->ice_connected =
        (progress->diag1.ice_connected_peer_count == 1 &&
         progress->diag2.ice_connected_peer_count == 1 &&
         progress->diag1.last_ice_selected_local_endpoint[0] != '\0' &&
         progress->diag1.last_ice_selected_remote_endpoint[0] != '\0' &&
         progress->diag2.last_ice_selected_local_endpoint[0] != '\0' &&
         progress->diag2.last_ice_selected_remote_endpoint[0] != '\0');
}

static void test_ice_runtime_lifecycle(void) {
    const char *stun_servers[] = {"stun:stun.cloudflare.com:3478"};
    mesh_config_t mesh_config;
    mesh_ice_config_t ice_config = {stun_servers, 1, 0};
    mesh_diag_info_t diagnostics;
    mesh_network_t *mesh = NULL;

    mesh_config_init(&mesh_config);
    mesh_config.virtual_ip = "10.42.0.199";
    mesh_config.listen_port = 20999;
    mesh = mesh_create(&mesh_config);
    check_not_null(mesh);
    if (!mesh) {
        return;
    }

    check_int_eq(mesh_ice_setup(mesh, &ice_config), MESH_OK);
    check_int_eq(mesh_ice_enable(mesh), MESH_OK);
    check_int_eq(mesh_ice_enable(mesh), MESH_OK);
    check_int_eq(mesh_get_diag_info(mesh, &diagnostics), MESH_OK);
    check_int_eq(diagnostics.ice_enabled, 1);
    check_int_eq(mesh_ice_setup(mesh, &ice_config), MESH_ERR_BUSY);

    check_int_eq(mesh_ice_disable(mesh), MESH_OK);
    check_int_eq(mesh_ice_disable(mesh), MESH_OK);
    check_int_eq(mesh_get_diag_info(mesh, &diagnostics), MESH_OK);
    check_int_eq(diagnostics.ice_enabled, 0);

    ice_config.stun_servers = NULL;
    ice_config.stun_server_count = 0;
    ice_config.allow_loopback = 1;
    check_int_eq(mesh_ice_setup(mesh, &ice_config), MESH_OK);
    check_int_eq(mesh_ice_enable(mesh), MESH_OK);
    check_int_eq(mesh_ice_disable(mesh), MESH_OK);

    mesh_destroy(mesh);
}

static void test_ice_signaling_two_nodes(void) {
    const char *bootstrap_peers[] = {"127.0.0.1:20891"};
    mesh_ice_config_t ice_config = {NULL, 0, 1};
    mesh_network_t *node1 = NULL;
    mesh_network_t *node2 = NULL;
    mesh_network_t *nodes[2] = {NULL};
    mesh_ice_two_node_progress_t progress;
    mesh_peer_info_t node1_peer_info = {0};
    mesh_peer_info_t node2_peer_info = {0};
    mesh_packet_counter_t node1_packets = {0};
    uint8_t packet[60];
    uint64_t deadline_ms = 0;
    int node1_started = 0;
    int node2_started = 0;
    int peers_ready = 0;
    int packet_sent = 0;
    int packet_delivered = 0;
    int selected_pair_cap_negotiated = 0;

    printf("\n[TEST] test_ice_signaling_two_nodes\n");

    mesh_config_t cfg1;
    mesh_config_init(&cfg1);
    cfg1.virtual_ip = "10.42.9.11";
    cfg1.virtual_prefix = 16;
    cfg1.listen_port = 20891;
    cfg1.on_packet_received = on_packet_received_counting;
    cfg1.user_data = &node1_packets;

    mesh_config_t cfg2;
    mesh_config_init(&cfg2);
    cfg2.virtual_ip = "10.42.9.12";
    cfg2.virtual_prefix = 16;
    cfg2.listen_port = 20892;
    cfg2.bootstrap_peers = bootstrap_peers;
    cfg2.bootstrap_count = 1;

    mesh_test_build_ipv4_packet(packet, sizeof(packet),
                                10, 42, 9, 12,
                                10, 42, 9, 11);

    node1 = mesh_create(&cfg1);
    check_not_null(node1);
    node1_started = (mesh_start(node1) == MESH_OK);
    check(node1_started);
    sleep_ms(300);

    node2 = mesh_create(&cfg2);
    check_not_null(node2);
    node2_started = (mesh_start(node2) == MESH_OK);
    check(node2_started);

    nodes[0] = node1;
    nodes[1] = node2;
    for (int i = 0; node1_started && node2_started && i < 80; i++) {
        mesh_test_poll_many(nodes, 2, 1, 100, 40);
        if (mesh_get_peer_count(node1) == 1 && mesh_get_peer_count(node2) == 1) {
            peers_ready = 1;
            break;
        }
    }
    check(peers_ready);
    if (peers_ready) {
        check_int_eq(mesh_ice_setup(node1, &ice_config), MESH_OK);
        check_int_eq(mesh_ice_setup(node2, &ice_config), MESH_OK);
        check_int_eq(mesh_ice_enable(node1), MESH_OK);
        check_int_eq(mesh_ice_enable(node2), MESH_OK);
    }

    memset(&progress, 0, sizeof(progress));
    progress.node1 = node1;
    progress.node2 = node2;

    deadline_ms = now_ms() + 15000;
    while (now_ms() < deadline_ms) {
        mesh_test_poll_many(nodes, 2, 1, 100, 40);
        mesh_test_capture_ice_two_node_progress(&progress);

        if (progress.diag1.ice_peer_count == 1 &&
            progress.diag2.ice_peer_count == 1 &&
            progress.ice_connected) {
            break;
        }
    }

    printf("[TEST] ICE wait done: peers=(%u,%u) connected=%d auth=%d candidate=%d eoc=%d checks=%d\n",
           progress.diag1.ice_peer_count, progress.diag2.ice_peer_count,
           progress.ice_connected, progress.auth_seen, progress.candidate_seen,
           progress.eoc_seen, progress.checks_started);

    if (mesh_get_peer_info(node1, 0, &node1_peer_info) == MESH_OK &&
        mesh_get_peer_info(node2, 0, &node2_peer_info) == MESH_OK) {
        selected_pair_cap_negotiated =
            ((node1_peer_info.capabilities & MESH_CAP_SELECTED_PAIR_IP) != 0 &&
             (node1_peer_info.negotiated_capabilities & MESH_CAP_SELECTED_PAIR_IP) != 0 &&
             (node2_peer_info.capabilities & MESH_CAP_SELECTED_PAIR_IP) != 0 &&
             (node2_peer_info.negotiated_capabilities & MESH_CAP_SELECTED_PAIR_IP) != 0);
    }

    if (progress.ice_connected) {
        uint64_t diag_deadline_ms = now_ms() + 3000;
        while (now_ms() < diag_deadline_ms) {
            if (progress.auth_seen && progress.candidate_seen &&
                progress.eoc_seen && progress.checks_started) {
                break;
            }
            mesh_test_poll_many(nodes, 2, 1, 100, 20);
            mesh_test_capture_ice_two_node_progress(&progress);
        }

        packet_sent = (mesh_send_packet(node2, packet, sizeof(packet)) == MESH_OK);
        for (int i = 0; packet_sent && i < 50; i++) {
            mesh_poll(node1, 100);
            mesh_poll(node2, 100);
            sleep_ms(20);
            if (node1_packets.packet_received_count > 0) {
                packet_delivered = 1;
                break;
            }
        }
    }

    if (node2) {
        mesh_stop(node2);
    }
    if (node1) {
        mesh_stop(node1);
    }
    printf("[TEST] ICE entering destroy: sent=%d delivered=%d\n", packet_sent, packet_delivered);
    sleep_ms(200);
    mesh_test_stop_destroy(&node2);
    mesh_test_stop_destroy(&node1);

    if (!(progress.diag1.ice_peer_count == 1 &&
          progress.diag2.ice_peer_count == 1 &&
          progress.auth_seen &&
          progress.candidate_seen &&
          progress.eoc_seen &&
          progress.checks_started &&
          progress.ice_connected)) {
        printf("[TEST] ICE diag summary: peers=(%u,%u) auth=(%u,%u/%u,%u) "
               "cand=(%u,%u/%u,%u) eoc=(%u,%u/%u,%u) checks=(%u,%u) "
               "selected=(%s,%s/%s,%s)\n",
               progress.diag1.ice_peer_count, progress.diag2.ice_peer_count,
               progress.diag1.ice_auth_messages_tx, progress.diag1.ice_auth_messages_rx,
               progress.diag2.ice_auth_messages_tx, progress.diag2.ice_auth_messages_rx,
               progress.diag1.ice_candidate_messages_tx, progress.diag1.ice_candidate_messages_rx,
               progress.diag2.ice_candidate_messages_tx, progress.diag2.ice_candidate_messages_rx,
               progress.diag1.ice_end_of_candidates_tx, progress.diag1.ice_end_of_candidates_rx,
               progress.diag2.ice_end_of_candidates_tx, progress.diag2.ice_end_of_candidates_rx,
               progress.diag1.ice_checks_started, progress.diag2.ice_checks_started,
               progress.diag1.last_ice_selected_local_endpoint,
               progress.diag1.last_ice_selected_remote_endpoint,
               progress.diag2.last_ice_selected_local_endpoint,
               progress.diag2.last_ice_selected_remote_endpoint);
    }

    check_int_eq(1, progress.diag1.ice_enabled);
    check_int_eq(1, progress.diag2.ice_enabled);
    check_int_eq(1, progress.diag1.ice_peer_count);
    check_int_eq(1, progress.diag2.ice_peer_count);
    check(progress.auth_seen);
    check(progress.candidate_seen);
    check(progress.eoc_seen);
    check(progress.checks_started);
    check(progress.ice_connected);
    check(selected_pair_cap_negotiated);
    check(progress.diag1.ice_candidate_messages_tx >=
          progress.diag1.ice_last_check_local_candidate_count);
    check(progress.diag2.ice_candidate_messages_tx >=
          progress.diag2.ice_last_check_local_candidate_count);
    check(progress.diag1.ice_candidate_messages_rx >=
          progress.diag1.ice_last_check_remote_candidate_count);
    check(progress.diag2.ice_candidate_messages_rx >=
          progress.diag2.ice_last_check_remote_candidate_count);
    check_int_eq(1, (int)progress.diag1.peer_connect_events);
    check_int_eq(1, (int)progress.diag2.peer_connect_events);
    check(packet_sent);
    check(packet_delivered);
}

static void test_routed_ice_fails_closed_without_end_to_end_identity(void) {
    const char *bootstrap_peers[] = {"127.0.0.1:20801"};
    mesh_network_t *leader = NULL;
    mesh_network_t *node2 = NULL;
    mesh_network_t *node3 = NULL;
    mesh_network_t *nodes[3] = {NULL};
    mesh_diag_info_t diag2 = {0};
    mesh_diag_info_t diag3 = {0};
    mesh_route_info_t route_info = {0};
    mesh_peer_info_t leader_peer_after = {0};
    mesh_peer_info_t direct_peer_after = {0};
    mesh_packet_counter_t node3_packets = {0};
    uint8_t packet[60];
    int leader_started = 0;
    int node2_started = 0;
    int node3_started = 0;
    int peers_ready = 0;
    int relay_ready = 0;
    int kick_send_ok = 0;
    int ice_connected = 0;
    int direct_peer_ready = 0;
    int leader_peer_found = 0;
    int routed_signaling_seen = 0;
    int direct_send_ok = 0;
    int direct_packet_delivered = 0;
    int direct_selected_pair_cap_negotiated = 0;
    int relay_bytes_stayed_zero = 0;

    printf("\n[TEST] test_routed_ice_fails_closed_without_end_to_end_identity\n");

    mesh_test_build_ipv4_packet(packet, sizeof(packet),
                                10, 42, 8, 2,
                                10, 42, 8, 3);

    mesh_config_t leader_cfg;
    mesh_config_init(&leader_cfg);
    leader_cfg.virtual_ip = "10.42.8.1";
    leader_cfg.virtual_prefix = 16;
    leader_cfg.listen_port = 20801;
    leader = mesh_create(&leader_cfg);
    check_not_null(leader);
    leader_started = (mesh_start(leader) == MESH_OK);
    if (leader_started) {
        sleep_ms(300);
    }

    mesh_config_t node2_cfg;
    mesh_config_init(&node2_cfg);
    node2_cfg.virtual_ip = "10.42.8.2";
    node2_cfg.virtual_prefix = 16;
    node2_cfg.listen_port = 20802;
    node2_cfg.bootstrap_peers = bootstrap_peers;
    node2_cfg.bootstrap_count = 1;
    node2_cfg.enable_ice = 1;
    node2_cfg.ice_allow_loopback = 1;
    node2 = mesh_create(&node2_cfg);
    check_not_null(node2);
    node2_started = (mesh_start(node2) == MESH_OK);

    mesh_config_t node3_cfg;
    mesh_config_init(&node3_cfg);
    node3_cfg.virtual_ip = "10.42.8.3";
    node3_cfg.virtual_prefix = 16;
    node3_cfg.listen_port = 20803;
    node3_cfg.bootstrap_peers = bootstrap_peers;
    node3_cfg.bootstrap_count = 1;
    node3_cfg.enable_ice = 1;
    node3_cfg.ice_allow_loopback = 1;
    node3_cfg.on_packet_received = on_packet_received_counting;
    node3_cfg.user_data = &node3_packets;
    node3 = mesh_create(&node3_cfg);
    check_not_null(node3);
    node3_started = (mesh_start(node3) == MESH_OK);

    nodes[0] = leader;
    nodes[1] = node2;
    nodes[2] = node3;

    if (leader_started && node2_started && node3_started) {
        peers_ready = mesh_test_wait_for_min_peers(nodes, 3, 1, 60);
    }

    for (int i = 0; peers_ready && i < 80; i++) {
        mesh_test_poll_many(nodes, 3, 1, 100, 50);
        if (mesh_test_find_route(node2, "10.42.8.3", &route_info) &&
            strcmp(route_info.next_hop_virtual_ip, "10.42.8.1") == 0 &&
            route_info.hop_count == 1) {
            relay_ready = 1;
            break;
        }
    }

    if (relay_ready) {
        kick_send_ok = (mesh_send_packet(node2, packet, sizeof(packet)) == MESH_OK);
    }

    memset(&diag2, 0, sizeof(diag2));
    memset(&diag3, 0, sizeof(diag3));
    for (int i = 0; kick_send_ok && i < 20; i++) {
        mesh_test_poll_many(nodes, 3, 1, 100, 50);
        mesh_get_diag_info(node2, &diag2);
        mesh_get_diag_info(node3, &diag3);
        routed_signaling_seen = (diag2.ice_auth_messages_tx > 0 &&
                                 diag2.ice_candidate_messages_tx > 0 &&
                                 diag3.ice_auth_messages_rx > 0 &&
                                 diag3.ice_candidate_messages_rx > 0);
        ice_connected = (diag2.ice_connected_peer_count >= 1 &&
                         diag3.ice_connected_peer_count >= 1);
        direct_peer_ready = mesh_test_find_peer_info(node2, "10.42.8.3", &direct_peer_after) &&
                            direct_peer_after.is_connected &&
                            strcmp(direct_peer_after.real_ip, "127.0.0.1:20803") != 0;
        direct_selected_pair_cap_negotiated =
            direct_peer_ready &&
            ((direct_peer_after.capabilities & MESH_CAP_SELECTED_PAIR_IP) != 0) &&
            ((direct_peer_after.negotiated_capabilities & MESH_CAP_SELECTED_PAIR_IP) != 0);
        if (routed_signaling_seen && ice_connected && direct_peer_ready &&
            direct_selected_pair_cap_negotiated) {
            break;
        }
    }

    if (direct_peer_ready) {
        mesh_reset_stats(node2);
        node3_packets.packet_received_count = 0;
        direct_send_ok = (mesh_send_packet(node2, packet, sizeof(packet)) == MESH_OK);
        for (int i = 0; direct_send_ok && i < 40; i++) {
            mesh_test_poll_many(nodes, 3, 1, 100, 50);
            if (node3_packets.packet_received_count > 0) {
                direct_packet_delivered = 1;
                break;
            }
        }
        leader_peer_found = mesh_test_find_peer_info(node2, "10.42.8.1", &leader_peer_after);
        relay_bytes_stayed_zero = leader_peer_found && ((int)leader_peer_after.bytes_tx == 0);
    }

    mesh_test_stop_destroy(&node3);
    mesh_test_stop_destroy(&node2);
    mesh_test_stop_destroy(&leader);

    check(leader_started);
    check(node2_started);
    check(node3_started);
    check(peers_ready);
    check(relay_ready);
    check(kick_send_ok);
    check_false(routed_signaling_seen);
    check_false(ice_connected);
    check_false(direct_peer_ready);
    check_false(direct_selected_pair_cap_negotiated);
    check_false(direct_send_ok);
    check_false(direct_packet_delivered);
    check_false(leader_peer_found);
    check_false(relay_bytes_stayed_zero);
    check_uint_eq(0, diag2.ice_auth_messages_tx);
    check_uint_eq(0, diag2.ice_candidate_messages_tx);
    check_uint_eq(0, diag3.ice_auth_messages_rx);
    check_uint_eq(0, diag3.ice_candidate_messages_rx);
}

static void test_direct_path_preferred_over_relay(void) {
    const char *bootstrap_peers[] = {"127.0.0.1:20701"};
    mesh_network_t *leader = NULL;
    mesh_network_t *node2 = NULL;
    mesh_network_t *node3 = NULL;
    mesh_network_t *nodes[3] = {NULL};
    mesh_route_info_t route_info = {0};
    mesh_peer_info_t direct_peer_before = {0};
    mesh_peer_info_t leader_peer_after = {0};
    mesh_peer_info_t direct_peer_after = {0};
    mesh_packet_counter_t node3_packets = {0};
    uint8_t packet[60];
    int leader_started = 0;
    int node2_started = 0;
    int node3_started = 0;
    int peers_ready = 0;
    int relay_ready = 0;
    int direct_connect_started = 0;
    int direct_ready = 0;
    int direct_send_ok = 0;
    int direct_packet_delivered = 0;
    int fallback_route_ready = 0;
    int fallback_send_ok = 0;
    int leader_peer_found = 0;
    int direct_peer_found = 0;
    int relay_bytes_stayed_zero = 0;
    int leader_peer_found_after_fallback = 0;
    int relay_bytes_after_fallback = 0;
    int direct_peer_gone = 0;

    printf("\n[TEST] test_direct_path_preferred_over_relay\n");

    mesh_test_build_ipv4_packet(packet, sizeof(packet),
                                10, 42, 7, 2,
                                10, 42, 7, 3);

    mesh_config_t leader_cfg;
    mesh_config_init(&leader_cfg);
    leader_cfg.virtual_ip = "10.42.7.1";
    leader_cfg.virtual_prefix = 16;
    leader_cfg.listen_port = 20701;
    leader_cfg.advertise_ip = "127.0.0.1";
    leader = mesh_create(&leader_cfg);
    check_not_null(leader);
    leader_started = (mesh_start(leader) == MESH_OK);
    if (leader_started) {
        sleep_ms(500);
    }

    mesh_config_t node2_cfg;
    mesh_config_init(&node2_cfg);
    node2_cfg.virtual_ip = "10.42.7.2";
    node2_cfg.virtual_prefix = 16;
    node2_cfg.listen_port = 20702;
    node2_cfg.bootstrap_peers = bootstrap_peers;
    node2_cfg.bootstrap_count = 1;
    node2 = mesh_create(&node2_cfg);
    check_not_null(node2);
    node2_started = (mesh_start(node2) == MESH_OK);

    mesh_config_t node3_cfg;
    mesh_config_init(&node3_cfg);
    node3_cfg.virtual_ip = "10.42.7.3";
    node3_cfg.virtual_prefix = 16;
    node3_cfg.listen_port = 20703;
    node3_cfg.bootstrap_peers = bootstrap_peers;
    node3_cfg.bootstrap_count = 1;
    node3_cfg.advertise_ip = "127.0.0.1";
    node3_cfg.on_packet_received = on_packet_received_counting;
    node3_cfg.user_data = &node3_packets;
    node3 = mesh_create(&node3_cfg);
    check_not_null(node3);
    node3_started = (mesh_start(node3) == MESH_OK);

    nodes[0] = leader;
    nodes[1] = node2;
    nodes[2] = node3;

    if (leader_started && node2_started && node3_started) {
        peers_ready = mesh_test_wait_for_min_peers(nodes, 3, 1, 60);
    }

    for (int i = 0; peers_ready && i < 80; i++) {
        mesh_test_poll_many(nodes, 3, 1, 100, 50);
        if (mesh_test_find_route(node2, "10.42.7.3", &route_info) &&
            strcmp(route_info.next_hop_virtual_ip, "10.42.7.1") == 0 &&
            route_info.hop_count == 1) {
            relay_ready = 1;
            break;
        }
    }

    if (relay_ready) {
        direct_connect_started = (mesh_connect_peer(node2, "10.42.7.3") == MESH_OK);
    }

    for (int i = 0; direct_connect_started && i < 80; i++) {
        mesh_test_poll_many(nodes, 3, 1, 100, 50);
        if (mesh_test_find_peer_info(node2, "10.42.7.3", &direct_peer_before) &&
            strcmp(direct_peer_before.real_ip, "127.0.0.1:20703") == 0 &&
            direct_peer_before.is_connected) {
            direct_ready = 1;
            break;
        }
    }

    if (direct_ready) {
        leader_peer_found = mesh_test_find_peer_info(node2, "10.42.7.1", &leader_peer_after);
        mesh_reset_stats(node2);
        node3_packets.packet_received_count = 0;
        direct_send_ok = (mesh_send_packet(node2, packet, sizeof(packet)) == MESH_OK);

        for (int i = 0; direct_send_ok && i < 20; i++) {
            mesh_test_poll_many(nodes, 3, 1, 100, 50);
            if (node3_packets.packet_received_count > 0) {
                break;
            }
        }

        leader_peer_found = mesh_test_find_peer_info(node2, "10.42.7.1", &leader_peer_after);
        direct_peer_found = mesh_test_find_peer_info(node2, "10.42.7.3", &direct_peer_after);
        direct_packet_delivered = (node3_packets.packet_received_count > 0);
        relay_bytes_stayed_zero = leader_peer_found && ((int)leader_peer_after.bytes_tx == 0);
    }

    if (direct_ready) {
        mesh_disconnect_peer(node2, mesh_find_peer(node2, "10.42.7.3"));

        for (int i = 0; i < 40; i++) {
            mesh_test_poll_many(nodes, 3, 1, 100, 50);
            if (!mesh_find_peer(node2, "10.42.7.3") &&
                mesh_test_find_route(node2, "10.42.7.3", &route_info) &&
                strcmp(route_info.next_hop_virtual_ip, "10.42.7.1") == 0) {
                fallback_route_ready = 1;
                break;
            }
        }
    }

    if (fallback_route_ready) {
        direct_peer_gone = (mesh_find_peer(node2, "10.42.7.3") == NULL);
        mesh_reset_stats(node2);
        node3_packets.packet_received_count = 0;
        fallback_send_ok = (mesh_send_packet(node2, packet, sizeof(packet)) == MESH_OK);

        for (int i = 0; fallback_send_ok && i < 20; i++) {
            mesh_test_poll_many(nodes, 3, 1, 100, 50);
            if (node3_packets.packet_received_count > 0) {
                break;
            }
        }

        leader_peer_found_after_fallback = mesh_test_find_peer_info(node2, "10.42.7.1",
                                                                    &leader_peer_after);
        relay_bytes_after_fallback = leader_peer_found_after_fallback &&
                                     (leader_peer_after.bytes_tx > 0);
    }

    mesh_test_stop_destroy(&node3);
    mesh_test_stop_destroy(&node2);
    mesh_test_stop_destroy(&leader);

    check(leader_started);
    check(node2_started);
    check(node3_started);
    check(peers_ready);
    check(relay_ready);
    check(direct_connect_started);
    check(direct_ready);
    check(direct_send_ok);
    check(direct_packet_delivered);
    check(leader_peer_found);
    check(direct_peer_found);
    check(direct_peer_after.bytes_tx > 0);
    check(relay_bytes_stayed_zero);
    check(fallback_route_ready);
    check(direct_peer_gone);
    check(fallback_send_ok);
    check(node3_packets.packet_received_count > 0);
    check(leader_peer_found_after_fallback);
    check(relay_bytes_after_fallback);
    check_str_eq("127.0.0.1:20703", direct_peer_before.real_ip);
    check(direct_peer_before.is_connected);
    check_str_eq("10.42.7.1", route_info.next_hop_virtual_ip);
}

static void test_pinned_route_overrides_direct_path(void) {
    const char *bootstrap_peers[] = {"127.0.0.1:20711"};
    mesh_network_t *leader = NULL;
    mesh_network_t *node2 = NULL;
    mesh_network_t *node3 = NULL;
    mesh_network_t *nodes[3] = {NULL};
    mesh_route_info_t route_info = {0};
    mesh_route_rule_info_t rule_info = {0};
    mesh_peer_info_t leader_peer_after = {0};
    mesh_peer_info_t direct_peer_after = {0};
    mesh_packet_counter_t node3_packets = {0};
    mesh_route_rule_t node2_rules[] = {
        {"10.42.11.3/32", "10.42.11.1", MESH_ROUTE_RULE_PINNED},
    };
    uint8_t packet[60];
    int leader_started = 0;
    int node2_started = 0;
    int node3_started = 0;
    int peers_ready = 0;
    int relay_ready = 0;
    int direct_connect_started = 0;
    int direct_ready = 0;
    int rule_count_ok = 0;
    int rule_info_ok = 0;
    int pinned_send_ok = 0;
    int pinned_packet_delivered = 0;
    int leader_peer_found = 0;
    int direct_peer_found = 0;
    int pinned_used = 0;
    int direct_unused = 0;
    int leader_stopped = 0;
    int direct_still_ready = 0;
    int pinned_fail_no_fallback = 0;

    printf("\n[TEST] test_pinned_route_overrides_direct_path\n");

    mesh_test_build_ipv4_packet(packet, sizeof(packet),
                                10, 42, 11, 2,
                                10, 42, 11, 3);

    mesh_config_t leader_cfg;
    mesh_config_init(&leader_cfg);
    leader_cfg.virtual_ip = "10.42.11.1";
    leader_cfg.virtual_prefix = 16;
    leader_cfg.listen_port = 20711;
    leader_cfg.advertise_ip = "127.0.0.1";
    leader = mesh_create(&leader_cfg);
    check_not_null(leader);
    leader_started = (mesh_start(leader) == MESH_OK);
    if (leader_started) {
        sleep_ms(500);
    }

    mesh_config_t node2_cfg;
    mesh_config_init(&node2_cfg);
    node2_cfg.virtual_ip = "10.42.11.2";
    node2_cfg.virtual_prefix = 16;
    node2_cfg.listen_port = 20712;
    node2_cfg.bootstrap_peers = bootstrap_peers;
    node2_cfg.bootstrap_count = 1;
    node2_cfg.route_rules = node2_rules;
    node2_cfg.route_rule_count = 1;
    node2 = mesh_create(&node2_cfg);
    check_not_null(node2);
    node2_started = (mesh_start(node2) == MESH_OK);

    mesh_config_t node3_cfg;
    mesh_config_init(&node3_cfg);
    node3_cfg.virtual_ip = "10.42.11.3";
    node3_cfg.virtual_prefix = 16;
    node3_cfg.listen_port = 20713;
    node3_cfg.bootstrap_peers = bootstrap_peers;
    node3_cfg.bootstrap_count = 1;
    node3_cfg.advertise_ip = "127.0.0.1";
    node3_cfg.on_packet_received = on_packet_received_counting;
    node3_cfg.user_data = &node3_packets;
    node3 = mesh_create(&node3_cfg);
    check_not_null(node3);
    node3_started = (mesh_start(node3) == MESH_OK);

    nodes[0] = leader;
    nodes[1] = node2;
    nodes[2] = node3;

    if (leader_started && node2_started && node3_started) {
        peers_ready = mesh_test_wait_for_min_peers(nodes, 3, 1, 60);
    }

    for (int i = 0; peers_ready && i < 80; i++) {
        mesh_test_poll_many(nodes, 3, 1, 100, 50);
        if (mesh_test_find_route(node2, "10.42.11.3", &route_info) &&
            strcmp(route_info.next_hop_virtual_ip, "10.42.11.1") == 0 &&
            route_info.hop_count == 1) {
            relay_ready = 1;
            break;
        }
    }

    if (relay_ready) {
        direct_connect_started = (mesh_connect_peer(node2, "10.42.11.3") == MESH_OK);
    }

    for (int i = 0; direct_connect_started && i < 80; i++) {
        mesh_test_poll_many(nodes, 3, 1, 100, 50);
        if (mesh_test_find_peer_info(node2, "10.42.11.3", &direct_peer_after) &&
            strcmp(direct_peer_after.real_ip, "127.0.0.1:20713") == 0 &&
            direct_peer_after.is_connected) {
            direct_ready = 1;
            break;
        }
    }

    rule_count_ok = (mesh_get_route_rule_count(node2) == 1);
    if (rule_count_ok && mesh_get_route_rule_info(node2, 0, &rule_info) == MESH_OK) {
        rule_info_ok = 1;
    }

    if (direct_ready) {
        mesh_reset_stats(node2);
        node3_packets.packet_received_count = 0;
        pinned_send_ok = (mesh_send_packet(node2, packet, sizeof(packet)) == MESH_OK);

        for (int i = 0; pinned_send_ok && i < 20; i++) {
            mesh_test_poll_many(nodes, 3, 1, 100, 50);
            if (node3_packets.packet_received_count > 0) {
                pinned_packet_delivered = 1;
                break;
            }
        }

        leader_peer_found = mesh_test_find_peer_info(node2, "10.42.11.1", &leader_peer_after);
        direct_peer_found = mesh_test_find_peer_info(node2, "10.42.11.3", &direct_peer_after);
        pinned_used = leader_peer_found && (leader_peer_after.bytes_tx > 0);
        direct_unused = direct_peer_found && ((int)direct_peer_after.bytes_tx == 0);
    }

    if (direct_ready) {
        mesh_test_stop_destroy(&leader);
        nodes[0] = NULL;
        leader_stopped = 1;

        for (int i = 0; i < 40; i++) {
            mesh_test_poll_many(&nodes[1], 2, 1, 100, 50);
            if (!mesh_find_peer(node2, "10.42.11.1") &&
                mesh_test_find_peer_info(node2, "10.42.11.3", &direct_peer_after) &&
                direct_peer_after.is_connected) {
                direct_still_ready = 1;
                break;
            }
        }
    }

    if (direct_still_ready) {
        mesh_reset_stats(node2);
        node3_packets.packet_received_count = 0;
        pinned_fail_no_fallback =
            (mesh_send_packet(node2, packet, sizeof(packet)) == MESH_ERR_NOT_FOUND);
        mesh_test_poll_many(&nodes[1], 2, 4, 100, 50);
    }

    mesh_test_stop_destroy(&node3);
    mesh_test_stop_destroy(&node2);

    check(leader_started);
    check(node2_started);
    check(node3_started);
    check(peers_ready);
    check(relay_ready);
    check(direct_connect_started);
    check(direct_ready);
    check(rule_count_ok);
    check(rule_info_ok);
    check_str_eq("10.42.11.3/32", rule_info.dest_cidr);
    check_str_eq("10.42.11.1", rule_info.next_hop_virtual_ip);
    check_uint_eq(MESH_ROUTE_RULE_PINNED, rule_info.flags);
    check(pinned_send_ok);
    check(pinned_packet_delivered);
    check(leader_peer_found);
    check(direct_peer_found);
    check(pinned_used);
    check(direct_unused);
    check(leader_stopped);
    check(direct_still_ready);
    check(pinned_fail_no_fallback);
    check_int_eq(0, node3_packets.packet_received_count);
}

static void test_non_mesh_pinned_route_requires_explicit_egress_role(void) {
    mesh_network_t *node = NULL;
    mesh_route_rule_info_t rule_info = {0};
    mesh_stats_t stats = {0};
    mesh_route_rule_t rules[] = {
        {"0.0.0.0/0", "10.42.12.1", MESH_ROUTE_RULE_PINNED},
    };
    uint8_t packet[60];
    int send_ret = 0;

    printf("\n[TEST] test_non_mesh_pinned_route_requires_explicit_egress_role\n");

    mesh_test_build_ipv4_packet(packet, sizeof(packet),
                                10, 42, 12, 2,
                                8, 8, 8, 8);

    mesh_config_t cfg;
    mesh_config_init(&cfg);
    cfg.virtual_ip = "10.42.12.2";
    cfg.virtual_prefix = 16;
    cfg.listen_port = 20742;
    cfg.route_rules = rules;
    cfg.route_rule_count = 1;

    node = mesh_create(&cfg);
    check_not_null(node);
    check_int_eq(1, mesh_get_route_rule_count(node));
    check_int_eq(MESH_OK, mesh_get_route_rule_info(node, 0, &rule_info));
    check_str_eq("0.0.0.0/0", rule_info.dest_cidr);
    check_str_eq("10.42.12.1", rule_info.next_hop_virtual_ip);

    send_ret = mesh_send_packet(node, packet, sizeof(packet));
    check_int_eq(MESH_ERR_NOT_FOUND, send_ret);
    check_int_eq(MESH_OK, mesh_get_stats(node, &stats));
    check_int_eq(0, (int)stats.packets_tx);

    mesh_destroy(node);
}

static void test_non_mesh_pinned_route_uses_local_egress_role(void) {
    const char *bootstrap_peers[] = {"127.0.0.1:20781"};
    const char *router_egress[] = {"192.168.50.0/24"};
    const char *router_egress_allow[] = {"10.42.12.2/32", "10.42.12.3/32"};
    mesh_route_rule_t client_rules[] = {
        {"0.0.0.0/0", "10.42.12.1", MESH_ROUTE_RULE_PINNED},
    };
    mesh_network_t *router = NULL;
    mesh_network_t *client = NULL;
    mesh_network_t *nodes[2] = {NULL};
    mesh_packet_counter_t router_packets = {0};
    mesh_local_egress_info_t egress_info = {0};
    mesh_local_egress_allow_info_t egress_allow_info = {0};
    uint8_t allowed_packet[60];
    uint8_t denied_packet[60];
    uint8_t source_denied_packet[60];
    uint8_t impersonated_allowed_source_packet[60];
    int router_started = 0;
    int client_started = 0;
    int peers_ready = 0;
    int getter_ok = 0;
    int denied_send_ok = 0;
    int denied_dropped = 0;
    int source_denied_send_ok = 0;
    int source_denied_dropped = 0;
    int impersonated_source_send_ok = 0;
    int impersonated_source_dropped = 0;
    int allowed_send_ok = 0;
    int allowed_delivered = 0;

    printf("\n[TEST] test_non_mesh_pinned_route_uses_local_egress_role\n");

    mesh_test_build_ipv4_packet(denied_packet, sizeof(denied_packet),
                                10, 42, 12, 2,
                                203, 0, 113, 10);
    mesh_test_build_ipv4_packet(allowed_packet, sizeof(allowed_packet),
                                10, 42, 12, 2,
                                192, 168, 50, 10);
    mesh_test_build_ipv4_packet(source_denied_packet, sizeof(source_denied_packet),
                                10, 42, 99, 9,
                                192, 168, 50, 20);
    mesh_test_build_ipv4_packet(impersonated_allowed_source_packet,
                                sizeof(impersonated_allowed_source_packet),
                                10, 42, 12, 3,
                                192, 168, 50, 30);

    mesh_config_t router_cfg;
    mesh_config_init(&router_cfg);
    router_cfg.virtual_ip = "10.42.12.1";
    router_cfg.virtual_prefix = 16;
    router_cfg.listen_port = 20781;
    router_cfg.local_egress_cidrs = router_egress;
    router_cfg.local_egress_count = 1;
    router_cfg.local_egress_allow_cidrs = router_egress_allow;
    router_cfg.local_egress_allow_count = 2;
    router_cfg.on_packet_received = on_packet_received_counting;
    router_cfg.user_data = &router_packets;
    router = mesh_create(&router_cfg);
    check_not_null(router);
    router_started = (mesh_start(router) == MESH_OK);
    if (router_started) {
        sleep_ms(500);
    }

    mesh_config_t client_cfg;
    mesh_config_init(&client_cfg);
    client_cfg.virtual_ip = "10.42.12.2";
    client_cfg.virtual_prefix = 16;
    client_cfg.listen_port = 20782;
    client_cfg.bootstrap_peers = bootstrap_peers;
    client_cfg.bootstrap_count = 1;
    client_cfg.route_rules = client_rules;
    client_cfg.route_rule_count = 1;
    client = mesh_create(&client_cfg);
    check_not_null(client);
    client_started = (mesh_start(client) == MESH_OK);

    nodes[0] = router;
    nodes[1] = client;

    if (router_started && client_started) {
        peers_ready = mesh_test_wait_for_min_peers(nodes, 2, 1, 60);
    }

    if (router) {
        getter_ok = (mesh_get_local_egress_count(router) == 1 &&
                     mesh_get_local_egress_info(router, 0, &egress_info) == MESH_OK &&
                     strcmp(egress_info.cidr, "192.168.50.0/24") == 0 &&
                     mesh_get_local_egress_info(router, 1, &egress_info) == MESH_ERR_INVALID_ARG &&
                     mesh_get_local_egress_allow_count(router) == 2 &&
                     mesh_get_local_egress_allow_info(router, 0, &egress_allow_info) == MESH_OK &&
                     strcmp(egress_allow_info.cidr, "10.42.12.2/32") == 0 &&
                     mesh_get_local_egress_allow_info(router, 1, &egress_allow_info) == MESH_OK &&
                     strcmp(egress_allow_info.cidr, "10.42.12.3/32") == 0 &&
                     mesh_get_local_egress_allow_info(router, 2, &egress_allow_info) ==
                         MESH_ERR_INVALID_ARG);
    }

    if (peers_ready) {
        denied_send_ok = (mesh_send_packet(client, denied_packet, sizeof(denied_packet)) == MESH_OK);
        mesh_test_poll_many(nodes, 2, 10, 100, 20);
        denied_dropped = (router_packets.packet_received_count == 0);

        source_denied_send_ok =
            (mesh_send_packet(client, source_denied_packet, sizeof(source_denied_packet)) == MESH_OK);
        mesh_test_poll_many(nodes, 2, 10, 100, 20);
        source_denied_dropped = (router_packets.packet_received_count == 0);

        impersonated_source_send_ok =
            (mesh_send_packet(client, impersonated_allowed_source_packet,
                              sizeof(impersonated_allowed_source_packet)) == MESH_OK);
        mesh_test_poll_many(nodes, 2, 10, 100, 20);
        impersonated_source_dropped = (router_packets.packet_received_count == 0);

        allowed_send_ok = (mesh_send_packet(client, allowed_packet, sizeof(allowed_packet)) == MESH_OK);
        for (int i = 0; allowed_send_ok && i < 20; i++) {
            mesh_test_poll_many(nodes, 2, 1, 100, 20);
            if (router_packets.packet_received_count > 0) {
                allowed_delivered = 1;
                break;
            }
        }
    }

    mesh_test_stop_destroy(&client);
    mesh_test_stop_destroy(&router);

    check(router_started);
    check(client_started);
    check(peers_ready);
    check(getter_ok);
    check(denied_send_ok);
    check(denied_dropped);
    check(source_denied_send_ok);
    check(source_denied_dropped);
    check(impersonated_source_send_ok);
    check(impersonated_source_dropped);
    check(allowed_send_ok);
    check(allowed_delivered);
}

static void test_peer_admission_allowlist(void) {
    const char *bootstrap_peers[] = {"127.0.0.1:20721"};
    const char *leader_allow_cidrs[] = {"10.42.14.2/32"};
    mesh_network_t *leader = NULL;
    mesh_network_t *node2 = NULL;
    mesh_network_t *node3 = NULL;
    mesh_network_t *nodes[3] = {NULL};
    mesh_peer_info_t leader_peer_info;
    mesh_peer_info_t node2_peer_info;
    mesh_peer_allow_info_t allow_info = {0};
    uint8_t packet[60];
    int leader_started = 0;
    int node2_started = 0;
    int node3_started = 0;
    int allow_getter_ok = 0;
    int allow_invalid_index_rejected = 0;
    int leader_protocol_policy_disabled = 0;
    int allowed_connected = 0;
    int denied_rejected = 0;
    int leader_only_has_allowed_peer = 0;
    int denied_connect_blocked = 0;
    int denied_send_blocked = 0;

    printf("\n[TEST] test_peer_admission_allowlist\n");

    mesh_test_build_ipv4_packet(packet, sizeof(packet),
                                10, 42, 14, 1,
                                10, 42, 14, 3);

    mesh_config_t leader_cfg;
    mesh_config_init(&leader_cfg);
    leader_cfg.virtual_ip = "10.42.14.1";
    leader_cfg.virtual_prefix = 16;
    leader_cfg.listen_port = 20721;
    leader_cfg.peer_allow_cidrs = leader_allow_cidrs;
    leader_cfg.peer_allow_count = 1;
    leader = mesh_create(&leader_cfg);
    check_not_null(leader);
    if (leader) {
        allow_getter_ok = (mesh_get_peer_allow_count(leader) == 1 &&
                           mesh_get_peer_allow_info(leader, 0, &allow_info) == MESH_OK &&
                           strcmp(allow_info.cidr, "10.42.14.2/32") == 0);
        allow_invalid_index_rejected =
            (mesh_get_peer_allow_info(leader, 1, &allow_info) == MESH_ERR_INVALID_ARG);
        leader_protocol_policy_disabled = (mesh_get_peer_protocol_major(leader) == 0);
    }
    leader_started = (mesh_start(leader) == MESH_OK);
    if (leader_started) {
        sleep_ms(500);
    }

    mesh_config_t node2_cfg;
    mesh_config_init(&node2_cfg);
    node2_cfg.virtual_ip = "10.42.14.2";
    node2_cfg.virtual_prefix = 16;
    node2_cfg.listen_port = 20722;
    node2_cfg.bootstrap_peers = bootstrap_peers;
    node2_cfg.bootstrap_count = 1;
    node2 = mesh_create(&node2_cfg);
    check_not_null(node2);
    node2_started = (mesh_start(node2) == MESH_OK);

    mesh_config_t node3_cfg;
    mesh_config_init(&node3_cfg);
    node3_cfg.virtual_ip = "10.42.14.3";
    node3_cfg.virtual_prefix = 16;
    node3_cfg.listen_port = 20723;
    node3_cfg.bootstrap_peers = bootstrap_peers;
    node3_cfg.bootstrap_count = 1;
    node3 = mesh_create(&node3_cfg);
    check_not_null(node3);
    node3_started = (mesh_start(node3) == MESH_OK);

    nodes[0] = leader;
    nodes[1] = node2;
    nodes[2] = node3;

    for (int i = 0; leader_started && node2_started && node3_started && i < 80; i++) {
        mesh_test_poll_many(nodes, 3, 1, 100, 50);

        if (mesh_test_find_peer_info(leader, "10.42.14.2", &leader_peer_info) &&
            mesh_test_find_peer_info(node2, "10.42.14.1", &node2_peer_info) &&
            leader_peer_info.is_connected && node2_peer_info.is_connected) {
            allowed_connected = 1;
        }

        if (!mesh_test_find_peer_info(leader, "10.42.14.3", NULL) &&
            mesh_get_peer_count(node3) == 0) {
            denied_rejected = 1;
        }

        if (allowed_connected && denied_rejected) {
            break;
        }
    }

    if (allowed_connected && denied_rejected) {
        for (int i = 0; i < 20; i++) {
            mesh_test_poll_many(nodes, 3, 1, 50, 20);
            if (!mesh_test_find_peer_info(leader, "10.42.14.3", NULL) &&
                mesh_get_peer_count(leader) == 1) {
                leader_only_has_allowed_peer = 1;
                break;
            }
        }
    }

    if (allowed_connected) {
        denied_connect_blocked = (mesh_connect_peer(leader, "10.42.14.3") == MESH_ERR_NOT_FOUND);
        denied_send_blocked = (mesh_send_packet(leader, packet, sizeof(packet)) == MESH_ERR_NOT_FOUND);
    }

    mesh_test_stop_destroy(&node3);
    mesh_test_stop_destroy(&node2);
    mesh_test_stop_destroy(&leader);

    check(leader_started);
    check(node2_started);
    check(node3_started);
    check(allow_getter_ok);
    check(allow_invalid_index_rejected);
    check(leader_protocol_policy_disabled);
    check(allowed_connected);
    check(denied_rejected);
    check(leader_only_has_allowed_peer);
    check(denied_connect_blocked);
    check(denied_send_blocked);
    check_str_eq("10.42.14.2", leader_peer_info.virtual_ip);
    check_str_eq("10.42.14.1", node2_peer_info.virtual_ip);
}

static void test_peer_admission_blocks_learned_routes(void) {
    const char *node2_bootstrap_peers[] = {"127.0.0.1:20731"};
    const char *node3_bootstrap_peers[] = {"127.0.0.1:20732"};
    const char *leader_allow_cidrs[] = {"10.42.15.2/32"};
    mesh_network_t *leader = NULL;
    mesh_network_t *node2 = NULL;
    mesh_network_t *node3 = NULL;
    mesh_network_t *nodes[3] = {NULL};
    mesh_peer_info_t leader_node2_info;
    mesh_peer_info_t node2_leader_info;
    mesh_peer_info_t node2_node3_info;
    mesh_peer_info_t node3_node2_info;
    uint8_t packet[60];
    int leader_started = 0;
    int node2_started = 0;
    int node3_started = 0;
    int leader_node2_connected = 0;
    int node2_node3_connected = 0;
    int topology_ready = 0;
    int denied_route_seen = 0;
    int learned_route_blocked = 0;
    int denied_send_blocked = 0;

    printf("\n[TEST] test_peer_admission_blocks_learned_routes\n");

    memset(&leader_node2_info, 0, sizeof(leader_node2_info));
    memset(&node2_leader_info, 0, sizeof(node2_leader_info));
    memset(&node2_node3_info, 0, sizeof(node2_node3_info));
    memset(&node3_node2_info, 0, sizeof(node3_node2_info));

    mesh_test_build_ipv4_packet(packet, sizeof(packet),
                                10, 42, 15, 1,
                                10, 42, 15, 3);

    mesh_config_t leader_cfg;
    mesh_config_init(&leader_cfg);
    leader_cfg.virtual_ip = "10.42.15.1";
    leader_cfg.virtual_prefix = 16;
    leader_cfg.listen_port = 20731;
    leader_cfg.peer_allow_cidrs = leader_allow_cidrs;
    leader_cfg.peer_allow_count = 1;
    leader = mesh_create(&leader_cfg);
    check_not_null(leader);
    leader_started = (mesh_start(leader) == MESH_OK);
    if (leader_started) {
        sleep_ms(500);
    }

    mesh_config_t node2_cfg;
    mesh_config_init(&node2_cfg);
    node2_cfg.virtual_ip = "10.42.15.2";
    node2_cfg.virtual_prefix = 16;
    node2_cfg.listen_port = 20732;
    node2_cfg.bootstrap_peers = node2_bootstrap_peers;
    node2_cfg.bootstrap_count = 1;
    node2 = mesh_create(&node2_cfg);
    check_not_null(node2);
    node2_started = (mesh_start(node2) == MESH_OK);
    if (node2_started) {
        sleep_ms(300);
    }

    mesh_config_t node3_cfg;
    mesh_config_init(&node3_cfg);
    node3_cfg.virtual_ip = "10.42.15.3";
    node3_cfg.virtual_prefix = 16;
    node3_cfg.listen_port = 20733;
    node3_cfg.bootstrap_peers = node3_bootstrap_peers;
    node3_cfg.bootstrap_count = 1;
    node3 = mesh_create(&node3_cfg);
    check_not_null(node3);
    node3_started = (mesh_start(node3) == MESH_OK);

    nodes[0] = leader;
    nodes[1] = node2;
    nodes[2] = node3;

    for (int i = 0; leader_started && node2_started && node3_started && i < 120; i++) {
        mesh_test_poll_many(nodes, 3, 1, 100, 50);

        leader_node2_connected =
            mesh_test_find_peer_info(leader, "10.42.15.2", &leader_node2_info) &&
            mesh_test_find_peer_info(node2, "10.42.15.1", &node2_leader_info) &&
            leader_node2_info.is_connected &&
            node2_leader_info.is_connected;
        node2_node3_connected =
            mesh_test_find_peer_info(node2, "10.42.15.3", &node2_node3_info) &&
            mesh_test_find_peer_info(node3, "10.42.15.2", &node3_node2_info) &&
            node2_node3_info.is_connected &&
            node3_node2_info.is_connected;

        if (leader_node2_connected && node2_node3_connected) {
            topology_ready = 1;
            break;
        }
    }

    for (int i = 0; topology_ready && i < 80; i++) {
        mesh_test_poll_many(nodes, 3, 1, 100, 50);
        if (mesh_test_find_route(leader, "10.42.15.3", NULL)) {
            denied_route_seen = 1;
            break;
        }
    }

    if (topology_ready) {
        learned_route_blocked = !denied_route_seen &&
                                !mesh_test_find_route(leader, "10.42.15.3", NULL);
        denied_send_blocked = (mesh_send_packet(leader, packet, sizeof(packet)) == MESH_ERR_NOT_FOUND);
    }

    mesh_test_stop_destroy(&node3);
    mesh_test_stop_destroy(&node2);
    mesh_test_stop_destroy(&leader);

    check(leader_started);
    check(node2_started);
    check(node3_started);
    check(topology_ready);
    check(leader_node2_connected);
    check(node2_node3_connected);
    check(learned_route_blocked);
    check(denied_send_blocked);
    check_str_eq("10.42.15.2", leader_node2_info.virtual_ip);
    check_str_eq("10.42.15.1", node2_leader_info.virtual_ip);
    check_str_eq("10.42.15.3", node2_node3_info.virtual_ip);
    check_str_eq("10.42.15.2", node3_node2_info.virtual_ip);
}

static void test_peer_admission_rejects_duplicate_virtual_ip(void) {
    const char *bootstrap_peers[] = {"127.0.0.1:20741"};
    mesh_network_t *leader = NULL;
    mesh_network_t *node2 = NULL;
    mesh_network_t *node3 = NULL;
    mesh_network_t *nodes[3] = {NULL};
    mesh_peer_info_t leader_peer_before;
    mesh_peer_info_t leader_peer_after;
    mesh_peer_info_t node2_peer_info;
    mesh_diag_info_t leader_diag_before;
    mesh_diag_info_t leader_diag_after;
    int leader_started = 0;
    int node2_started = 0;
    int node3_started = 0;
    int first_peer_connected = 0;
    int duplicate_attempt_seen = 0;
    int duplicate_disconnect_seen = 0;
    int existing_peer_retained = 0;
    int leader_kept_single_peer = 0;
    int duplicate_rejected = 0;

    printf("\n[TEST] test_peer_admission_rejects_duplicate_virtual_ip\n");

    memset(&leader_peer_before, 0, sizeof(leader_peer_before));
    memset(&leader_peer_after, 0, sizeof(leader_peer_after));
    memset(&node2_peer_info, 0, sizeof(node2_peer_info));
    memset(&leader_diag_before, 0, sizeof(leader_diag_before));
    memset(&leader_diag_after, 0, sizeof(leader_diag_after));

    mesh_config_t leader_cfg;
    mesh_config_init(&leader_cfg);
    leader_cfg.virtual_ip = "10.42.16.1";
    leader_cfg.virtual_prefix = 16;
    leader_cfg.listen_port = 20741;
    leader = mesh_create(&leader_cfg);
    check_not_null(leader);
    leader_started = (mesh_start(leader) == MESH_OK);
    if (leader_started) {
        sleep_ms(500);
    }

    mesh_config_t node2_cfg;
    mesh_config_init(&node2_cfg);
    node2_cfg.virtual_ip = "10.42.16.2";
    node2_cfg.virtual_prefix = 16;
    node2_cfg.listen_port = 20742;
    node2_cfg.bootstrap_peers = bootstrap_peers;
    node2_cfg.bootstrap_count = 1;
    node2 = mesh_create(&node2_cfg);
    check_not_null(node2);
    node2_started = (mesh_start(node2) == MESH_OK);

    nodes[0] = leader;
    nodes[1] = node2;

    for (int i = 0; leader_started && node2_started && i < 80; i++) {
        mesh_test_poll_many(nodes, 2, 1, 100, 50);

        if (mesh_test_find_peer_info(leader, "10.42.16.2", &leader_peer_before) &&
            mesh_test_find_peer_info(node2, "10.42.16.1", &node2_peer_info) &&
            leader_peer_before.is_connected &&
            node2_peer_info.is_connected &&
            mesh_get_peer_count(leader) == 1) {
            first_peer_connected = 1;
            break;
        }
    }

    if (first_peer_connected) {
        mesh_get_diag_info(leader, &leader_diag_before);
    }

    mesh_config_t node3_cfg;
    mesh_config_init(&node3_cfg);
    node3_cfg.virtual_ip = "10.42.16.2";
    node3_cfg.virtual_prefix = 16;
    node3_cfg.listen_port = 20743;
    node3_cfg.bootstrap_peers = bootstrap_peers;
    node3_cfg.bootstrap_count = 1;
    node3 = mesh_create(&node3_cfg);
    check_not_null(node3);
    node3_started = (mesh_start(node3) == MESH_OK);

    nodes[2] = node3;

    for (int i = 0; first_peer_connected && node3_started && i < 120; i++) {
        mesh_test_poll_many(nodes, 3, 1, 100, 50);
        mesh_get_diag_info(leader, &leader_diag_after);

        duplicate_attempt_seen =
            leader_diag_after.peer_connect_events > leader_diag_before.peer_connect_events;
        duplicate_disconnect_seen =
            leader_diag_after.peer_disconnect_events > leader_diag_before.peer_disconnect_events;
        leader_kept_single_peer = (mesh_get_peer_count(leader) == 1);
        existing_peer_retained =
            mesh_test_find_peer_info(leader, "10.42.16.2", &leader_peer_after) &&
            leader_peer_after.is_connected &&
            strcmp(leader_peer_after.real_ip, leader_peer_before.real_ip) == 0;
        duplicate_rejected = duplicate_attempt_seen &&
                             duplicate_disconnect_seen &&
                             leader_kept_single_peer &&
                             mesh_get_peer_count(node3) == 0;

        if (existing_peer_retained && duplicate_rejected) {
            break;
        }
    }

    mesh_test_stop_destroy(&node3);
    mesh_test_stop_destroy(&node2);
    mesh_test_stop_destroy(&leader);

    check(leader_started);
    check(node2_started);
    check(node3_started);
    check(first_peer_connected);
    check(duplicate_attempt_seen);
    check(duplicate_disconnect_seen);
    check(existing_peer_retained);
    check(leader_kept_single_peer);
    check(duplicate_rejected);
    check_str_eq("10.42.16.2", leader_peer_before.virtual_ip);
    check_str_eq("10.42.16.2", leader_peer_after.virtual_ip);
    check_str_eq("10.42.16.1", node2_peer_info.virtual_ip);
}

static void test_peer_admission_identity_allowlist(void) {
    const char *bootstrap_peers[] = {"127.0.0.1:20751"};
    const char *leader_secret =
        "0102030405060708090a0b0c0d0e0f10"
        "1112131415161718191a1b1c1d1e1f20";
    const char *node2_secret =
        "202122232425262728292a2b2c2d2e2f"
        "303132333435363738393a3b3c3d3e3f";
    const char *node3_secret =
        "404142434445464748494a4b4c4d4e4f"
        "505152535455565758595a5b5c5d5e5f";
    char leader_id[65] = {0};
    char node2_id[65] = {0};
    const char *leader_allow_node_ids[1] = {node2_id};
    mesh_network_t *leader = NULL;
    mesh_network_t *node2 = NULL;
    mesh_network_t *node3 = NULL;
    mesh_network_t *nodes[3] = {NULL};
    mesh_peer_info_t leader_peer_info;
    mesh_peer_info_t node2_peer_info;
    mesh_peer_allow_node_info_t allow_node_info = {0};
    int leader_started = 0;
    int node2_started = 0;
    int node3_started = 0;
    int allow_node_getter_ok = 0;
    int allowed_connected = 0;
    int denied_rejected = 0;
    int leader_only_has_allowed_peer = 0;

    printf("\n[TEST] test_peer_admission_identity_allowlist\n");

    check(mesh_test_node_id_from_secret_hex(leader_secret, leader_id, sizeof(leader_id)));
    check(mesh_test_node_id_from_secret_hex(node2_secret, node2_id, sizeof(node2_id)));

    mesh_config_t leader_cfg;
    mesh_config_init(&leader_cfg);
    leader_cfg.virtual_ip = "10.42.18.1";
    leader_cfg.virtual_prefix = 16;
    leader_cfg.listen_port = 20751;
    leader_cfg.identity_secret_hex = leader_secret;
    leader_cfg.peer_allow_node_ids = leader_allow_node_ids;
    leader_cfg.peer_allow_node_id_count = 1;
    leader = mesh_create(&leader_cfg);
    check_not_null(leader);
    if (leader) {
        allow_node_getter_ok =
            (mesh_get_peer_allow_node_id_count(leader) == 1 &&
             mesh_get_peer_allow_node_info(leader, 0, &allow_node_info) == MESH_OK &&
             strcmp(allow_node_info.node_id, node2_id) == 0 &&
             mesh_get_peer_allow_node_info(leader, 1, &allow_node_info) == MESH_ERR_INVALID_ARG);
    }
    leader_started = (mesh_start(leader) == MESH_OK);
    if (leader_started) {
        sleep_ms(500);
    }

    mesh_config_t node2_cfg;
    mesh_config_init(&node2_cfg);
    node2_cfg.virtual_ip = "10.42.18.2";
    node2_cfg.virtual_prefix = 16;
    node2_cfg.listen_port = 20752;
    node2_cfg.bootstrap_peers = bootstrap_peers;
    node2_cfg.bootstrap_count = 1;
    node2_cfg.identity_secret_hex = node2_secret;
    node2 = mesh_create(&node2_cfg);
    check_not_null(node2);
    node2_started = (mesh_start(node2) == MESH_OK);

    mesh_config_t node3_cfg;
    mesh_config_init(&node3_cfg);
    node3_cfg.virtual_ip = "10.42.18.3";
    node3_cfg.virtual_prefix = 16;
    node3_cfg.listen_port = 20753;
    node3_cfg.bootstrap_peers = bootstrap_peers;
    node3_cfg.bootstrap_count = 1;
    node3_cfg.identity_secret_hex = node3_secret;
    node3 = mesh_create(&node3_cfg);
    check_not_null(node3);
    node3_started = (mesh_start(node3) == MESH_OK);

    nodes[0] = leader;
    nodes[1] = node2;
    nodes[2] = node3;

    for (int i = 0; leader_started && node2_started && node3_started && i < 80; i++) {
        mesh_test_poll_many(nodes, 3, 1, 100, 50);

        if (mesh_test_find_peer_info(leader, "10.42.18.2", &leader_peer_info) &&
            mesh_test_find_peer_info(node2, "10.42.18.1", &node2_peer_info) &&
            leader_peer_info.is_connected && node2_peer_info.is_connected) {
            allowed_connected = 1;
        }

        if (!mesh_test_find_peer_info(leader, "10.42.18.3", NULL) &&
            mesh_get_peer_count(node3) == 0) {
            denied_rejected = 1;
        }

        if (allowed_connected && denied_rejected) {
            break;
        }
    }

    if (allowed_connected && denied_rejected) {
        for (int i = 0; i < 20; i++) {
            mesh_test_poll_many(nodes, 3, 1, 50, 20);
            if (!mesh_test_find_peer_info(leader, "10.42.18.3", NULL) &&
                mesh_get_peer_count(leader) == 1) {
                leader_only_has_allowed_peer = 1;
                break;
            }
        }
    }

    mesh_test_stop_destroy(&node3);
    mesh_test_stop_destroy(&node2);
    mesh_test_stop_destroy(&leader);

    check(leader_started);
    check(node2_started);
    check(node3_started);
    check(allow_node_getter_ok);
    check(allowed_connected);
    check(denied_rejected);
    check(leader_only_has_allowed_peer);
    check_str_eq("10.42.18.2", leader_peer_info.virtual_ip);
    check_str_eq("10.42.18.1", node2_peer_info.virtual_ip);
    check_str_eq(node2_id, leader_peer_info.node_id);
    check_str_eq(leader_id, node2_peer_info.node_id);
    check_uint_eq(MESH_PROTOCOL_MAJOR, leader_peer_info.protocol_major);
    check_uint_eq(MESH_PROTOCOL_MINOR, leader_peer_info.protocol_minor);
    check_uint_eq(MESH_CAP_LOCAL_DEFAULT, leader_peer_info.capabilities);
    check_uint_eq(MESH_CAP_LOCAL_DEFAULT, leader_peer_info.negotiated_capabilities);
    check_uint_eq(MESH_PROTOCOL_MAJOR, node2_peer_info.protocol_major);
    check_uint_eq(MESH_PROTOCOL_MINOR, node2_peer_info.protocol_minor);
    check_uint_eq(MESH_CAP_LOCAL_DEFAULT, node2_peer_info.capabilities);
    check_uint_eq(MESH_CAP_LOCAL_DEFAULT, node2_peer_info.negotiated_capabilities);
}

static void test_peer_admission_protocol_major(void) {
    const char *bootstrap_peers[] = {"127.0.0.1:20761"};
    mesh_network_t *leader = NULL;
    mesh_network_t *node2 = NULL;
    mesh_network_t *nodes[2] = {NULL};
    int leader_started = 0;
    int node2_started = 0;
    int protocol_policy_getter_ok = 0;
    int rejected = 0;

    printf("\n[TEST] test_peer_admission_protocol_major\n");

    mesh_config_t leader_cfg;
    mesh_config_init(&leader_cfg);
    leader_cfg.virtual_ip = "10.42.19.1";
    leader_cfg.virtual_prefix = 16;
    leader_cfg.listen_port = 20761;
    leader_cfg.peer_protocol_major = MESH_PROTOCOL_MAJOR + 1;
    leader = mesh_create(&leader_cfg);
    check_not_null(leader);
    if (leader) {
        protocol_policy_getter_ok =
            (mesh_get_peer_protocol_major(leader) == MESH_PROTOCOL_MAJOR + 1);
    }
    leader_started = (mesh_start(leader) == MESH_OK);
    if (leader_started) {
        sleep_ms(500);
    }

    mesh_config_t node2_cfg;
    mesh_config_init(&node2_cfg);
    node2_cfg.virtual_ip = "10.42.19.2";
    node2_cfg.virtual_prefix = 16;
    node2_cfg.listen_port = 20762;
    node2_cfg.bootstrap_peers = bootstrap_peers;
    node2_cfg.bootstrap_count = 1;
    node2 = mesh_create(&node2_cfg);
    check_not_null(node2);
    node2_started = (mesh_start(node2) == MESH_OK);

    nodes[0] = leader;
    nodes[1] = node2;

    for (int i = 0; leader_started && node2_started && i < 60; i++) {
        mesh_test_poll_many(nodes, 2, 1, 100, 50);
        if (mesh_get_peer_count(leader) == 0 &&
            mesh_get_peer_count(node2) == 0 &&
            !mesh_test_find_peer_info(leader, "10.42.19.2", NULL) &&
            !mesh_test_find_peer_info(node2, "10.42.19.1", NULL)) {
            rejected = 1;
            break;
        }
    }

    mesh_test_stop_destroy(&node2);
    mesh_test_stop_destroy(&leader);

    check(leader_started);
    check(node2_started);
    check(protocol_policy_getter_ok);
    check(rejected);
}

static void test_packet_policy_filters_by_direction_and_port(void) {
    const char *bootstrap_peers[] = {"127.0.0.1:21731"};
    mesh_packet_policy_rule_t leader_policy[] = {
        {
            "10.42.21.2/32",
            "10.42.21.1/32",
            6,
            0,
            0,
            443,
            443,
            MESH_PACKET_POLICY_IN,
            1,
        },
    };
    mesh_packet_policy_rule_t node2_policy[] = {
        {
            "10.42.21.2/32",
            "10.42.21.1/32",
            6,
            0,
            0,
            22,
            22,
            MESH_PACKET_POLICY_OUT,
            1,
        },
        {
            "10.42.21.2/32",
            "10.42.21.1/32",
            6,
            0,
            0,
            443,
            443,
            MESH_PACKET_POLICY_OUT,
            1,
        },
    };
    uint8_t denied_out_packet[60];
    uint8_t denied_in_packet[60];
    uint8_t allowed_packet[60];
    mesh_packet_counter_t leader_counter = {0};
    mesh_packet_policy_info_t policy_info = {0};
    mesh_network_t *leader = NULL;
    mesh_network_t *node2 = NULL;
    mesh_network_t *nodes[2] = {NULL, NULL};
    int leader_started = 0;
    int node2_started = 0;
    int peers_ready = 0;
    int getter_ok = 0;
    int denied_out_send_blocked = 0;
    int denied_in_send_ok = 0;
    int denied_in_not_delivered = 0;
    int allowed_send_ok = 0;
    int allowed_delivered = 0;

    printf("\n[TEST] test_packet_policy_filters_by_direction_and_port\n");

    mesh_test_build_tcp_packet(denied_out_packet, sizeof(denied_out_packet),
                               10, 42, 21, 2,
                               10, 42, 21, 1,
                               50000, 25);
    mesh_test_build_tcp_packet(denied_in_packet, sizeof(denied_in_packet),
                               10, 42, 21, 2,
                               10, 42, 21, 1,
                               50001, 22);
    mesh_test_build_tcp_packet(allowed_packet, sizeof(allowed_packet),
                               10, 42, 21, 2,
                               10, 42, 21, 1,
                               50002, 443);

    mesh_config_t leader_cfg;
    mesh_config_init(&leader_cfg);
    leader_cfg.virtual_ip = "10.42.21.1";
    leader_cfg.virtual_prefix = 16;
    leader_cfg.listen_port = 21731;
    leader_cfg.packet_policy_rules = leader_policy;
    leader_cfg.packet_policy_rule_count = 1;
    leader_cfg.on_packet_received = on_packet_received_counting;
    leader_cfg.user_data = &leader_counter;
    leader = mesh_create(&leader_cfg);
    check_not_null(leader);
    if (leader) {
        getter_ok =
            (mesh_get_packet_policy_count(leader) == 1 &&
             mesh_get_packet_policy_info(leader, 0, &policy_info) == MESH_OK &&
             strcmp(policy_info.src_cidr, "10.42.21.2/32") == 0 &&
             strcmp(policy_info.dst_cidr, "10.42.21.1/32") == 0 &&
             policy_info.ip_proto == 6 &&
             policy_info.dst_port_start == 443 &&
             policy_info.dst_port_end == 443 &&
             policy_info.directions == MESH_PACKET_POLICY_IN &&
             policy_info.allow == 1 &&
             mesh_get_packet_policy_info(leader, 1, &policy_info) == MESH_ERR_INVALID_ARG);
    }
    leader_started = (mesh_start(leader) == MESH_OK);
    if (leader_started) {
        sleep_ms(500);
    }

    mesh_config_t node2_cfg;
    mesh_config_init(&node2_cfg);
    node2_cfg.virtual_ip = "10.42.21.2";
    node2_cfg.virtual_prefix = 16;
    node2_cfg.listen_port = 21732;
    node2_cfg.bootstrap_peers = bootstrap_peers;
    node2_cfg.bootstrap_count = 1;
    node2_cfg.packet_policy_rules = node2_policy;
    node2_cfg.packet_policy_rule_count = 2;
    node2 = mesh_create(&node2_cfg);
    check_not_null(node2);
    node2_started = (mesh_start(node2) == MESH_OK);

    nodes[0] = leader;
    nodes[1] = node2;
    peers_ready = mesh_test_wait_for_min_peers(nodes, 2, 1, 40);

    if (peers_ready) {
        denied_out_send_blocked =
            (mesh_send_packet(node2, denied_out_packet, sizeof(denied_out_packet)) != MESH_OK);
        mesh_test_poll_many(nodes, 2, 10, 20, 20);

        denied_in_send_ok =
            (mesh_send_packet(node2, denied_in_packet, sizeof(denied_in_packet)) == MESH_OK);
        mesh_test_poll_many(nodes, 2, 20, 20, 20);
        denied_in_not_delivered = (leader_counter.packet_received_count == 0);

        allowed_send_ok =
            (mesh_send_packet(node2, allowed_packet, sizeof(allowed_packet)) == MESH_OK);
        for (int i = 0; i < 30 && leader_counter.packet_received_count < 1; i++) {
            mesh_test_poll_many(nodes, 2, 1, 20, 20);
        }
        allowed_delivered = (leader_counter.packet_received_count == 1);
    }

    mesh_test_stop_destroy(&node2);
    mesh_test_stop_destroy(&leader);

    check(leader_started);
    check(node2_started);
    check(peers_ready);
    check(getter_ok);
    check(denied_out_send_blocked);
    check(denied_in_send_ok);
    check(denied_in_not_delivered);
    check(allowed_send_ok);
    check(allowed_delivered);
}

static void test_mesh_identity_secret_config_validation(void) {
    mesh_config_t cfg;
    mesh_network_t *mesh = NULL;
    char node_id[65] = {0};
    char expected_node_id[65] = {0};

    mesh_config_init(&cfg);
    cfg.virtual_ip = "10.42.17.1";
    cfg.listen_port = 21701;
    cfg.identity_secret_hex =
        "0102030405060708090a0b0c0d0e0f10"
        "1112131415161718191a1b1c1d1e1f20";
    check(mesh_test_node_id_from_secret_hex(cfg.identity_secret_hex,
                                            expected_node_id,
                                            sizeof(expected_node_id)));

    mesh = mesh_create(&cfg);
    check_not_null(mesh);
    check_int_eq(MESH_OK, mesh_get_node_id(mesh, node_id, sizeof(node_id)));
    check_str_eq(expected_node_id, node_id);
    mesh_destroy(mesh);

    cfg.identity_secret_hex = "not-a-64-byte-hex-secret";
    mesh = mesh_create(&cfg);
    check_null(mesh);

    cfg.identity_secret_hex = NULL;
    cfg.peer_allow_node_ids = (const char *[]){
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    };
    cfg.peer_allow_node_id_count = 1;
    cfg.peer_protocol_major = MESH_PROTOCOL_MAJOR;
    mesh = mesh_create(&cfg);
    check_not_null(mesh);
    mesh_destroy(mesh);

    cfg.peer_allow_node_ids = (const char *[]){ "not-a-64-byte-node-id" };
    cfg.peer_allow_node_id_count = 1;
    mesh = mesh_create(&cfg);
    check_null(mesh);

    cfg.peer_allow_node_ids = NULL;
    cfg.peer_allow_node_id_count = 0;
    cfg.peer_protocol_major = UINT16_MAX + 1u;
    mesh = mesh_create(&cfg);
    check_null(mesh);
}

static void test_magic_dns_static_records(void) {
    mesh_magic_dns_record_t records[] = {
        {"Router", "10.42.20.1"},
        {"laptop", "10.42.20.2"},
        {"db.mesh.test", "10.42.20.3"},
    };
    mesh_magic_dns_info_t info = {0};
    mesh_config_t cfg;
    mesh_network_t *mesh = NULL;
    char resolved_ip[16] = {0};
    char resolved_name[128] = {0};

    mesh_config_init(&cfg);
    cfg.virtual_ip = "10.42.20.1";
    cfg.virtual_prefix = 16;
    cfg.listen_port = 21721;
    cfg.magic_dns_domain = "mesh.test";
    cfg.magic_dns_records = records;
    cfg.magic_dns_record_count = 3;

    mesh = mesh_create(&cfg);
    check_not_null(mesh);
    check_int_eq(3, mesh_get_magic_dns_count(mesh));
    check_int_eq(MESH_OK, mesh_get_magic_dns_info(mesh, 0, &info));
    check_str_eq("router", info.name);
    check_str_eq("10.42.20.1", info.virtual_ip);
    check_int_eq(MESH_ERR_INVALID_ARG, mesh_get_magic_dns_info(mesh, 3, &info));

    check_int_eq(MESH_OK, mesh_resolve_magic_dns(mesh, "router", resolved_ip, sizeof(resolved_ip)));
    check_str_eq("10.42.20.1", resolved_ip);
    check_int_eq(MESH_OK,
                 mesh_resolve_magic_dns(mesh, "LAPTOP.mesh.test.", resolved_ip, sizeof(resolved_ip)));
    check_str_eq("10.42.20.2", resolved_ip);
    check_int_eq(MESH_OK, mesh_resolve_magic_dns(mesh, "db", resolved_ip, sizeof(resolved_ip)));
    check_str_eq("10.42.20.3", resolved_ip);
    check_int_eq(MESH_ERR_NOT_FOUND,
                 mesh_resolve_magic_dns(mesh, "missing", resolved_ip, sizeof(resolved_ip)));
    check_int_eq(MESH_ERR_INVALID_ARG,
                 mesh_resolve_magic_dns(mesh, "bad_name", resolved_ip, sizeof(resolved_ip)));

    check_int_eq(MESH_OK,
                 mesh_reverse_magic_dns(mesh, "10.42.20.2", resolved_name, sizeof(resolved_name)));
    check_str_eq("laptop.mesh.test", resolved_name);
    check_int_eq(MESH_OK,
                 mesh_reverse_magic_dns(mesh, "10.42.20.3", resolved_name, sizeof(resolved_name)));
    check_str_eq("db.mesh.test", resolved_name);
    check_int_eq(MESH_ERR_NOT_FOUND,
                 mesh_reverse_magic_dns(mesh, "10.42.20.99", resolved_name, sizeof(resolved_name)));
    mesh_destroy(mesh);

    records[0].name = "bad_name";
    mesh = mesh_create(&cfg);
    check_null(mesh);

    records[0].name = "router";
    records[0].virtual_ip = "192.0.2.1";
    mesh = mesh_create(&cfg);
    check_null(mesh);
}

spec("mesh path regressions") {
    describe("ice signaling") {
        it("supports runtime setup enable disable and re-enable") {
            test_ice_runtime_lifecycle();
        }

        it("exchanges ice signaling on two nodes") { test_ice_signaling_two_nodes(); }

        it("rejects routed ice until origin identity is authenticated end to end") {
            test_routed_ice_fails_closed_without_end_to_end_identity();
        }
    }

    describe("path selection") {
        it("prefers direct path over relay") { test_direct_path_preferred_over_relay(); }

        it("allows pinned route policy to override direct path") {
            test_pinned_route_overrides_direct_path();
        }

        it("keeps non-mesh pinned routes closed without an egress role") {
            test_non_mesh_pinned_route_requires_explicit_egress_role();
        }

        it("delivers non-mesh pinned routes only through explicit local egress") {
            test_non_mesh_pinned_route_uses_local_egress_role();
        }
    }

    describe("peer admission") {
        it("rejects peers outside the admission allowlist") {
            test_peer_admission_allowlist();
        }

        it("rejects peers outside the identity allowlist") {
            test_peer_admission_identity_allowlist();
        }

        it("rejects peers outside the protocol-major policy") {
            test_peer_admission_protocol_major();
        }

        it("rejects learned routes outside the admission allowlist") {
            test_peer_admission_blocks_learned_routes();
        }

        it("rejects duplicate virtual ip peer admission") {
            test_peer_admission_rejects_duplicate_virtual_ip();
        }
    }

    describe("packet policy") {
        it("filters packets by direction and port") {
            test_packet_policy_filters_by_direction_and_port();
        }
    }

    describe("identity") {
        it("validates configured node identity secrets") {
            test_mesh_identity_secret_config_validation();
        }
    }

    describe("magic dns") {
        it("resolves configured static mesh names") {
            test_magic_dns_static_records();
        }
    }
}
