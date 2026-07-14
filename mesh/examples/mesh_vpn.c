/**
 * mesh_vpn.c - Decentralized P2P VPN example
 * Good Taste: Simple ZeroTier-like mesh network
 *
 * This example demonstrates:
 * - Creating a mesh network with virtual IP
 * - Auto peer discovery via DHT
 * - Stream transport via TurboNet::CoroNet
 * - Zero-config mesh routing
 *
 * Usage:
 *   # Node 1 (bootstrap)
 *   mesh_vpn 10.42.0.1 16
 *
 *   # Node 2 (connect to node 1)
 *   mesh_vpn 10.42.0.2 16 127.0.0.1:9993 203.0.113.10
 *
 *   # Node 3 (connect to node 1)
 *   mesh_vpn 10.42.0.3 16 127.0.0.1:9993 203.0.113.11
 *
 * Now all nodes can ping each other:
 *   ping 10.42.0.1
 *   ping 10.42.0.2
 *   ping 10.42.0.3
 */

#include <turbo_mesh.h>
#include <turbo_tunnel.h>
#include "tlog.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

/* =============================================================================
 * Global State
 * ============================================================================= */

static mesh_network_t *g_mesh = NULL;
static tunnel_t *g_tunnel = NULL;
static int g_running = 1;

/* =============================================================================
 * Signal Handler
 * ============================================================================= */

#ifdef _WIN32
static BOOL WINAPI console_handler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT) {
        printf("\nShutting down...\n");
        g_running = 0;
        if (g_mesh) mesh_stop(g_mesh);
        if (g_tunnel) tunnel_stop(g_tunnel);
        return TRUE;
    }
    return FALSE;
}
#else
static void signal_handler(int sig) {
    (void)sig;
    printf("\nShutting down...\n");
    g_running = 0;
    if (g_mesh) mesh_stop(g_mesh);
    if (g_tunnel) tunnel_stop(g_tunnel);
}
#endif

/* =============================================================================
 * Protocol Headers (for packet parsing)
 * ============================================================================= */

/* IP header structure */
struct ip_header {
    uint8_t version_ihl;      /* Version (4 bits) + IHL (4 bits) */
    uint8_t tos;              /* Type of Service */
    uint16_t total_length;    /* Total length */
    uint16_t id;              /* Identification */
    uint16_t flags_offset;    /* Flags (3 bits) + Fragment offset (13 bits) */
    uint8_t ttl;              /* Time to Live */
    uint8_t protocol;         /* Protocol (17 = UDP) */
    uint16_t checksum;        /* Header checksum */
    uint32_t src_ip;          /* Source IP */
    uint32_t dst_ip;          /* Destination IP */
};

/* UDP header structure */
struct udp_header {
    uint16_t src_port;        /* Source port */
    uint16_t dst_port;        /* Destination port */
    uint16_t length;          /* Length */
    uint16_t checksum;        /* Checksum */
};

/* Forward declaration */
static void print_packet_info(const char *prefix, const uint8_t *data, size_t len);

/* =============================================================================
 * Mesh Callbacks
 * ============================================================================= */

static void on_peer_connected(mesh_peer_t *peer, void *user_data) {
    (void)user_data;

    mesh_peer_info_t info;
    if (mesh_get_peer_info(g_mesh, 0, &info) == MESH_OK) {
        printf("[MESH] Peer connected: %s\n", info.virtual_ip);
    }
}

static void on_peer_disconnected(mesh_peer_t *peer, void *user_data) {
    (void)peer;
    (void)user_data;

    printf("[MESH] Peer disconnected\n");
}

static void on_packet_received(const uint8_t *data, size_t len, void *user_data) {
    tunnel_t *tunnel = (tunnel_t *)user_data;

    /* Display packet details */
    print_packet_info("[MESH→TUN]", data, len);

    /* Inject packet into TUN device - OS will process it and generate reply */
    int ret = tunnel_write_packet(tunnel, data, len);
    if (ret != TUNNEL_OK) {
        fprintf(stderr, "[ERROR] Failed to write packet to TUN: %s\n",
                tunnel_error_string(ret));
    }
}

/* =============================================================================
 * Packet Parser (for displaying content)
 * ============================================================================= */

/* ICMP header */
struct icmp_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t rest;
};

/* TCP header */
struct tcp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t data_offset;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
};

/* Print IP packet details */
static void print_packet_info(const char *prefix, const uint8_t *data, size_t len) {
    if (len < sizeof(struct ip_header)) {
        printf("%s Unknown packet: %zu bytes\n", prefix, len);
        return;
    }

    struct ip_header *ip = (struct ip_header *)data;
    uint32_t src = ntohl(ip->src_ip);
    uint32_t dst = ntohl(ip->dst_ip);

    char src_str[32], dst_str[32];
    sprintf(src_str, "%u.%u.%u.%u", (src >> 24) & 0xFF, (src >> 16) & 0xFF, (src >> 8) & 0xFF, src & 0xFF);
    sprintf(dst_str, "%u.%u.%u.%u", (dst >> 24) & 0xFF, (dst >> 16) & 0xFF, (dst >> 8) & 0xFF, dst & 0xFF);

    const uint8_t *payload = data + sizeof(struct ip_header);
    size_t payload_len = len - sizeof(struct ip_header);

    /* ICMP */
    if (ip->protocol == 1 && payload_len >= sizeof(struct icmp_header)) {
        struct icmp_header *icmp = (struct icmp_header *)payload;
        const char *type_str = (icmp->type == 8) ? "Echo Request" :
                               (icmp->type == 0) ? "Echo Reply" : "Other";
        printf("%s ICMP %s: %s -> %s (%zu bytes)\n", prefix, type_str, src_str, dst_str, len);
    }
    /* TCP */
    else if (ip->protocol == 6 && payload_len >= sizeof(struct tcp_header)) {
        struct tcp_header *tcp = (struct tcp_header *)payload;
        uint16_t src_port = ntohs(tcp->src_port);
        uint16_t dst_port = ntohs(tcp->dst_port);

        char flags[32] = "";
        if (tcp->flags & 0x02) strcat(flags, "SYN ");
        if (tcp->flags & 0x10) strcat(flags, "ACK ");
        if (tcp->flags & 0x01) strcat(flags, "FIN ");
        if (tcp->flags & 0x04) strcat(flags, "RST ");
        if (tcp->flags & 0x08) strcat(flags, "PSH ");

        printf("%s TCP: %s:%u -> %s:%u [%s] (%zu bytes)\n",
               prefix, src_str, src_port, dst_str, dst_port, flags, len);
    }
    /* UDP */
    else if (ip->protocol == 17 && payload_len >= sizeof(struct udp_header)) {
        struct udp_header *udp = (struct udp_header *)payload;
        uint16_t src_port = ntohs(udp->src_port);
        uint16_t dst_port = ntohs(udp->dst_port);

        const uint8_t *udp_data = payload + sizeof(struct udp_header);
        size_t udp_data_len = payload_len - sizeof(struct udp_header);

        printf("%s UDP: %s:%u -> %s:%u", prefix, src_str, src_port, dst_str, dst_port);

        /* Check if data is printable text */
        if (udp_data_len > 0 && udp_data_len < 128) {
            int is_text = 1;
            for (size_t i = 0; i < udp_data_len; i++) {
                if (udp_data[i] < 32 && udp_data[i] != '\n' && udp_data[i] != '\r' && udp_data[i] != '\t') {
                    is_text = 0;
                    break;
                }
            }

            if (is_text) {
                printf(" payload: \"");
                for (size_t i = 0; i < udp_data_len && i < 64; i++) {
                    if (udp_data[i] >= 32 && udp_data[i] < 127) {
                        printf("%c", udp_data[i]);
                    }
                }
                printf("\"");
            }
        }

        printf(" (%zu bytes)\n", len);
    }
    /* Other protocols */
    else {
        printf("%s IP protocol %u: %s -> %s (%zu bytes)\n",
               prefix, ip->protocol, src_str, dst_str, len);
    }
}

/* =============================================================================
 * Tunnel Callbacks
 * ============================================================================= */

static void on_tun_packet_received(tunnel_t *tunnel, int direction,
                                     const uint8_t *data, size_t len,
                                     void *user_data) {
    (void)tunnel;

    if (direction == 0) {  /* RX from TUN = outgoing packet */
        /* Send through mesh */
        mesh_send_packet(g_mesh, data, len);
        print_packet_info("[TUN→MESH]", data, len);
    }

    (void)user_data;
}

static void print_stats(void) {
    mesh_stats_t mesh_stats;
    if (mesh_get_stats(g_mesh, &mesh_stats) == MESH_OK) {
        printf("\n=== Mesh Statistics ===\n");
        printf("Peers: %u\n", mesh_stats.peer_count);
        printf("TX: %.2f MB (%llu packets)\n",
               mesh_stats.bytes_tx / (1024.0 * 1024.0),
               (unsigned long long)mesh_stats.packets_tx);
        printf("RX: %.2f MB (%llu packets)\n",
               mesh_stats.bytes_rx / (1024.0 * 1024.0),
               (unsigned long long)mesh_stats.packets_rx);
        printf("DHT entries: %u\n", mesh_stats.dht_entries);
        printf("======================\n\n");
    }

    tunnel_stats_t tun_stats;
    if (tunnel_get_stats(g_tunnel, &tun_stats) == TUNNEL_OK) {
        printf("=== TUN Statistics ===\n");
        printf("Sessions: TCP=%u, UDP=%u\n",
               tun_stats.tcp_sessions, tun_stats.udp_sessions);
        printf("TX: %.2f MB\n", tun_stats.bytes_tx / (1024.0 * 1024.0));
        printf("RX: %.2f MB\n", tun_stats.bytes_rx / (1024.0 * 1024.0));
        printf("=====================\n\n");
    }
}

/* =============================================================================
 * Main
 * ============================================================================= */

int main(int argc, char *argv[]) {
    /* Initialize Logger */
    tlog_config_t log_config = {
        .min_level = TURBO_LOG_LEVEL_DEBUG,
        .buffer_size = 64 * 1024
    };
    tlog_t *logger = tlog_create(&log_config);
    if (logger) {
        turbo_console_sink_opts_t console_opts = {
            .output = stdout,
            .use_colors = 1,
            .pattern = "[{time}] [{level}] {message}"
        };
        tlog_add_sink(logger, turbo_sink_console_create(&console_opts));
        tlog_set_default(logger);
    }

    if (argc < 3) {
        printf("Usage: %s <virtual_ip> <prefix> [bootstrap_peer] [advertise_ip]\n", argv[0]);
        printf("\nExamples:\n");
        printf("  Node 1: %s 10.42.0.1 16              (listens on port 9993)\n", argv[0]);
        printf("  Node 2: %s 10.42.0.2 16 10.42.0.1:9993 203.0.113.10\n", argv[0]);
        printf("  Node 3: %s 10.42.0.3 16 10.42.0.1:9993 203.0.113.11\n", argv[0]);
        printf("\nNote: Port is auto-derived from last IP octet (9992 + last_octet)\n");
        printf("\nAfter setup, ping other nodes:\n");
        printf("  ping 10.42.0.2\n");
        return 1;
    }

    const char *virtual_ip = argv[1];
    uint8_t prefix = (uint8_t)atoi(argv[2]);
    const char *bootstrap_ip = (argc >= 4) ? argv[3] : NULL;
    const char *advertise_ip = (argc >= 5) ? argv[4] : NULL;

    /* Auto-derive port from virtual IP last octet */
    unsigned int a, b, c, d;
    if (sscanf(virtual_ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
        fprintf(stderr, "Invalid IP address format\n");
        return 1;
    }
    int listen_port = 9992 + d;  /* 10.42.0.1 → 9993, 10.42.0.2 → 9994, etc. */

    printf("=== Mesh VPN ===\n");
    printf("Version: %s\n", mesh_version());
    printf("Virtual IP: %s/%d\n", virtual_ip, prefix);
    printf("Listen Port: %d\n", listen_port);
    if (bootstrap_ip) {
        printf("Bootstrap: %s\n", bootstrap_ip);
    }
    if (advertise_ip) {
        printf("Advertise IP: %s\n", advertise_ip);
    }
    printf("\n");

    /* Setup signal handlers */
#ifdef _WIN32
    SetConsoleCtrlHandler(console_handler, TRUE);
#else
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
#endif

    /* Initialize tunnel library */
    int ret = tunnel_init();
    if (ret != TUNNEL_OK) {
        fprintf(stderr, "Failed to initialize tunnel: %s\n",
                tunnel_error_string(ret));
        return 1;
    }

    /* Create tunnel configuration */
    tunnel_config_t tun_config;
    tunnel_config_init(&tun_config);

    /* TUN device */
    tun_config.tun.name = NULL;  /* Auto-generate */
    tun_config.tun.ipv4_addr = virtual_ip;

    /* Calculate netmask from prefix */
    char netmask[16];
    uint32_t mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF;
    sprintf(netmask, "%u.%u.%u.%u",
            (mask >> 24) & 0xFF,
            (mask >> 16) & 0xFF,
            (mask >> 8) & 0xFF,
            mask & 0xFF);
    tun_config.tun.ipv4_netmask = netmask;
    tun_config.tun.mtu = 1500;

    /* No proxy - use mesh */
    tun_config.mode = TUNNEL_MODE_PACKET;
    tun_config.proxy.type = TUNNEL_PROXY_NONE;

    /* Create tunnel */
    g_tunnel = tunnel_create(&tun_config);
    if (!g_tunnel) {
        fprintf(stderr, "Failed to create tunnel\n");
        tunnel_shutdown();
        return 1;
    }

    /* Set traffic callback */
    tunnel_set_traffic_callback(g_tunnel, on_tun_packet_received, g_tunnel);

    /* Create mesh configuration */
    mesh_config_t mesh_config;
    mesh_config_init(&mesh_config);

    mesh_config.virtual_ip = virtual_ip;
    mesh_config.virtual_prefix = prefix;
    mesh_config.listen_port = listen_port;  /* Use calculated port */
    mesh_config.advertise_ip = advertise_ip;

    /* Bootstrap peers */
    const char *bootstrap_peers[1];
    if (bootstrap_ip) {
        bootstrap_peers[0] = bootstrap_ip;
        mesh_config.bootstrap_peers = bootstrap_peers;
        mesh_config.bootstrap_count = 1;
    }

    /* Callbacks */
    mesh_config.on_peer_connected = on_peer_connected;
    mesh_config.on_peer_disconnected = on_peer_disconnected;
    mesh_config.on_packet_received = on_packet_received;
    mesh_config.user_data = g_tunnel;

    /* Create mesh */
    g_mesh = mesh_create(&mesh_config);
    if (!g_mesh) {
        fprintf(stderr, "Failed to create mesh network\n");
        tunnel_destroy(g_tunnel);
        tunnel_shutdown();
        return 1;
    }

    /* Start tunnel */
    printf("Starting TUN device...\n");
    ret = tunnel_start(g_tunnel);
    if (ret != TUNNEL_OK) {
        fprintf(stderr, "Failed to start tunnel: %s\n",
                tunnel_error_string(ret));
        mesh_destroy(g_mesh);
        tunnel_destroy(g_tunnel);
        tunnel_shutdown();
        return 1;
    }

    /* Start mesh */
    printf("Starting mesh network...\n");
    ret = mesh_start(g_mesh);
    if (ret != MESH_OK) {
        fprintf(stderr, "Failed to start mesh: %s\n",
                mesh_error_string(ret));
        tunnel_stop(g_tunnel);
        mesh_destroy(g_mesh);
        tunnel_destroy(g_tunnel);
        tunnel_shutdown();
        return 1;
    }

    printf("\n=== Mesh VPN Running ===\n");
    printf("Virtual network: %s/%d\n", virtual_ip, prefix);
    printf("P2P port: %d\n", listen_port);
    printf("\nYou can now send data between nodes:\n");
    printf("  ping 10.42.0.x\n");
    printf("  nc -u 10.42.0.x 5000  (send UDP messages)\n");
    printf("Press Ctrl+C to stop\n\n");

    /* Event loop */
    int iterations = 0;
    while (g_running) {
        /* Poll tunnel */
        tunnel_poll(g_tunnel, 100);

        /* Poll mesh */
        mesh_poll(g_mesh, 100);

        /* Print stats every 30 seconds */
        iterations++;
        if (iterations % 300 == 0) {
            print_stats();
        }

#ifdef _WIN32
        Sleep(100);
#else
        usleep(100000);
#endif
    }

    /* Final stats */
    print_stats();

    /* Cleanup */
    printf("Stopping mesh network...\n");
    mesh_stop(g_mesh);
    mesh_destroy(g_mesh);

    printf("Stopping tunnel...\n");
    tunnel_stop(g_tunnel);
    tunnel_destroy(g_tunnel);
    tunnel_shutdown();

    printf("Done.\n");

    if (logger) {
        tlog_flush(logger);
        tlog_destroy(logger);
    }

    return 0;
}
