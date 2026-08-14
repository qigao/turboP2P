#include <tinytest.h>
#include <turbo_mesh.h>
#include "mesh_test_security.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
static void sleep_ms(int ms) {
    Sleep(ms);
}
#else
#include <time.h>
#include <unistd.h>
static void sleep_ms(int ms) {
    usleep((useconds_t)ms * 1000);
}
#endif

static int g_node4_packet_count = 0;
static uint8_t g_node4_last_ttl = 0;

static void on_node4_packet_received(const uint8_t *data, size_t len, void *user_data) {
    (void)user_data;

    g_node4_packet_count++;
    if (data && len > 8) {
        g_node4_last_ttl = data[8];
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

static int mesh_test_alloc_port_block(int count) {
    static int next_port = 0;
    int start_port = 0;

    if (count <= 0) {
        count = 1;
    }

    if (next_port == 0) {
#ifdef _WIN32
        unsigned long pid = (unsigned long)GetCurrentProcessId();
        unsigned long tick = (unsigned long)GetTickCount64();
#else
        unsigned long pid = (unsigned long)getpid();
        unsigned long tick = (unsigned long)time(NULL);
#endif
        unsigned long seed = pid ^ tick;
        next_port = 36000 + (int)((seed % 600) * 10);
    }

    start_port = next_port;
    next_port += count + 8;
    return start_port;
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

static int mesh_test_find_connected_peer(mesh_network_t *mesh, const char *virtual_ip) {
    mesh_peer_t *peer = NULL;
    mesh_peer_info_t info;

    if (!mesh || !virtual_ip) {
        return 0;
    }

    peer = mesh_find_peer(mesh, virtual_ip);
    if (!peer) {
        return 0;
    }

    if (mesh_get_peer_handle_info(peer, &info) != MESH_OK) {
        return 0;
    }

    return info.is_connected;
}

static int mesh_test_has_forward_path(mesh_network_t *mesh, const char *dest_ip) {
    mesh_route_info_t route_info;

    if (mesh_test_find_connected_peer(mesh, dest_ip)) {
        return 1;
    }

    if (!mesh_test_find_route(mesh, dest_ip, &route_info)) {
        return 0;
    }

    return route_info.is_connected;
}

static int mesh_test_wait_for_min_peers(mesh_network_t **nodes, int node_count,
                                        int expected_per_node, int iterations) {
    for (int i = 0; i < iterations; i++) {
        int ready = 1;

        mesh_test_poll_many(nodes, node_count, 1, 100, 200);
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

static void test_multi_hop_route_learning_four_nodes_isolated(void) {
    int base_port = mesh_test_alloc_port_block(4);
    int port1 = base_port;
    int port2 = base_port + 1;
    int port3 = base_port + 2;
    int port4 = base_port + 3;
    char bootstrap_node1_addr[32];
    char bootstrap_node3_addr[32];
    const char *bootstrap_node1[] = {bootstrap_node1_addr};
    const char *bootstrap_node3[] = {bootstrap_node3_addr};
    mesh_network_t *node1 = NULL;
    mesh_network_t *node2 = NULL;
    mesh_network_t *node3 = NULL;
    mesh_network_t *node4 = NULL;
    mesh_network_t *nodes[4] = {NULL};
    mesh_route_info_t route_info;
    uint8_t packet[60];
    int packet_sent = 0;
    int packet_delivered = 0;
    int node2_has_node3 = 0;
    int node2_has_node4 = 0;
    int node3_has_node2 = 0;
    int node4_has_node2 = 0;
    int node1_forwards_node4 = 0;

    snprintf(bootstrap_node1_addr, sizeof(bootstrap_node1_addr), "127.0.0.1:%d", port1);
    snprintf(bootstrap_node3_addr, sizeof(bootstrap_node3_addr), "127.0.0.1:%d", port3);
    g_node4_packet_count = 0;
    g_node4_last_ttl = 0;

    mesh_config_t node1_cfg;
    mesh_config_init(&node1_cfg);
    node1_cfg.virtual_ip = "10.42.8.1";
    node1_cfg.virtual_prefix = 16;
    node1_cfg.listen_port = port1;
    check(mesh_test_security_configure(&node1_cfg, 0));

    node1 = mesh_create(&node1_cfg);
    check_not_null(node1);
    check_int_eq(MESH_OK, mesh_start(node1));
    sleep_ms(1000);

    mesh_config_t node2_cfg;
    mesh_config_init(&node2_cfg);
    node2_cfg.virtual_ip = "10.42.8.2";
    node2_cfg.virtual_prefix = 16;
    node2_cfg.listen_port = port2;
    node2_cfg.bootstrap_peers = bootstrap_node1;
    node2_cfg.bootstrap_count = 1;
    check(mesh_test_security_configure(&node2_cfg, 1));

    node2 = mesh_create(&node2_cfg);
    check_not_null(node2);
    check_int_eq(MESH_OK, mesh_start(node2));
    sleep_ms(500);
    nodes[0] = node1;
    nodes[1] = node2;
    check(mesh_test_wait_for_min_peers(nodes, 2, 1, 80));

    mesh_config_t node3_cfg;
    mesh_config_init(&node3_cfg);
    node3_cfg.virtual_ip = "10.42.8.3";
    node3_cfg.virtual_prefix = 16;
    node3_cfg.listen_port = port3;
    node3_cfg.bootstrap_peers = bootstrap_node1;
    node3_cfg.bootstrap_count = 1;
    check(mesh_test_security_configure(&node3_cfg, 2));

    node3 = mesh_create(&node3_cfg);
    check_not_null(node3);
    check_int_eq(MESH_OK, mesh_start(node3));
    nodes[2] = node3;
    check(mesh_test_wait_for_min_peers(nodes, 3, 1, 80));

    mesh_config_t node4_cfg;
    mesh_config_init(&node4_cfg);
    node4_cfg.virtual_ip = "10.42.8.4";
    node4_cfg.virtual_prefix = 16;
    node4_cfg.listen_port = port4;
    node4_cfg.bootstrap_peers = bootstrap_node3;
    node4_cfg.bootstrap_count = 1;
    node4_cfg.on_packet_received = on_node4_packet_received;
    check(mesh_test_security_configure(&node4_cfg, 3));

    node4 = mesh_create(&node4_cfg);
    check_not_null(node4);
    check_int_eq(MESH_OK, mesh_start(node4));
    nodes[3] = node4;
    check(mesh_test_wait_for_min_peers(&nodes[2], 2, 1, 80));

    for (int i = 0; i < 160; i++) {
        mesh_test_poll_many(nodes, 4, 1, 100, 50);

        node2_has_node3 = mesh_test_find_route(node2, "10.42.8.3", NULL);
        node2_has_node4 = mesh_test_find_route(node2, "10.42.8.4", NULL);
        node3_has_node2 = mesh_test_find_route(node3, "10.42.8.2", NULL);
        node4_has_node2 = mesh_test_find_route(node4, "10.42.8.2", NULL);
        node1_forwards_node4 = mesh_test_has_forward_path(node1, "10.42.8.4");

        if (node2_has_node3 && node2_has_node4 && node3_has_node2 &&
            node4_has_node2 && node1_forwards_node4) {
            break;
        }
    }

    check(node2_has_node3);
    check(node2_has_node4);
    check(node3_has_node2);
    check(node4_has_node2);
    check(node1_forwards_node4);

    check(mesh_test_find_route(node2, "10.42.8.3", &route_info));
    check_str_eq("10.42.8.1", route_info.next_hop_virtual_ip);
    check_int_eq(1, route_info.hop_count);

    check(mesh_test_find_route(node2, "10.42.8.4", &route_info));
    check_str_eq("10.42.8.1", route_info.next_hop_virtual_ip);
    check(route_info.hop_count >= 1);

    check(mesh_test_find_route(node3, "10.42.8.2", &route_info));
    check_str_eq("10.42.8.1", route_info.next_hop_virtual_ip);
    check_int_eq(1, route_info.hop_count);

    check(mesh_test_find_route(node4, "10.42.8.2", &route_info));
    check(strcmp(route_info.next_hop_virtual_ip, "10.42.8.1") == 0 ||
          strcmp(route_info.next_hop_virtual_ip, "10.42.8.3") == 0);
    check(route_info.hop_count >= 1);

    check(!mesh_test_find_route(node1, "10.42.8.2", NULL));
    check(!mesh_test_find_route(node1, "10.42.8.3", NULL));
    check(!mesh_test_find_route(node3, "10.42.8.4", NULL));
    check(!mesh_test_find_route(node4, "10.42.8.3", NULL));

    mesh_test_build_ipv4_packet(packet, sizeof(packet),
                                10, 42, 8, 2,
                                10, 42, 8, 4);
    packet_sent = mesh_send_packet(node2, packet, sizeof(packet)) == MESH_OK;
    check(packet_sent);

    for (int i = 0; i < 80; i++) {
        mesh_test_poll_many(nodes, 4, 1, 100, 25);
        if (g_node4_packet_count > 0) {
            packet_delivered = 1;
            break;
        }
    }

    check(packet_delivered);
    check_int_eq(1, g_node4_packet_count);
    check(g_node4_last_ttl < 64);

    mesh_test_stop_destroy(&node4);
    mesh_test_stop_destroy(&node3);
    mesh_test_stop_destroy(&node2);
    mesh_test_stop_destroy(&node1);
}

spec("mesh multihop") {
    it("learns four-node multi-hop routes in isolation") {
        test_multi_hop_route_learning_four_nodes_isolated();
    }
}
