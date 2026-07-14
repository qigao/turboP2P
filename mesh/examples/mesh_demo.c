/**
 * mesh_demo.c - Simplified P2P Mesh Demo (No TUN Device)
 *
 * Purpose: Test P2P mesh connectivity without TUN device complexity
 * No admin rights required!
 *
 * Usage:
 *   # Node 1 (bootstrap)
 *   mesh_demo 10.42.0.1 9993
 *
 *   # Node 2 (connect to node 1)
 *   mesh_demo 10.42.0.2 9994 127.0.0.1:9993
 *
 *   # Node 3 (connect to node 1)
 *   mesh_demo 10.42.0.3 9995 127.0.0.1:9993
 */

#include <turbo_mesh.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "tlog.h"

#ifdef _WIN32
#include <conio.h>
#include <windows.h>
#define sleep_ms(ms) Sleep(ms)
#else
#include <unistd.h>
#define sleep_ms(ms) usleep((ms) * 1000)
#endif

/* =============================================================================
 * Global State
 * ============================================================================= */

static mesh_network_t *g_mesh = NULL;
static int g_running = 1;
static int g_peer_count = 0;
static int g_packet_count = 0;

/* =============================================================================
 * Signal Handler
 * ============================================================================= */

#ifdef _WIN32
static BOOL WINAPI console_handler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT) {
        printf("\n[DEMO] Shutting down...\n");
        g_running = 0;
        return TRUE;
    }
    return FALSE;
}
#else
static void signal_handler(int sig) {
    (void)sig;
    printf("\n[DEMO] Shutting down...\n");
    g_running = 0;
}
#endif

/* =============================================================================
 * Callbacks
 * ============================================================================= */

static void on_peer_connected(mesh_peer_t *peer, void *user_data) {
    (void)peer;
    (void)user_data;

    g_peer_count++;

    mesh_peer_info_t info;
    if (mesh_get_peer_info(g_mesh, g_peer_count - 1, &info) == MESH_OK) {
        printf("\n");
        printf("╔═══════════════════════════════════════════════════════════╗\n");
        printf("║  ✓ PEER CONNECTED!                                        ║\n");
        printf("╠═══════════════════════════════════════════════════════════╣\n");
        printf("║  Virtual IP : %-40s  ║\n", info.virtual_ip);
        printf("║  Status     : %-40s  ║\n", info.is_connected ? "Connected" : "Disconnected");
        printf("║  Total Peers: %-40d  ║\n", g_peer_count);
        printf("╚═══════════════════════════════════════════════════════════╝\n");
        printf("\n");
    }
}

static void on_peer_disconnected(mesh_peer_t *peer, void *user_data) {
    (void)peer;
    (void)user_data;

    g_peer_count--;

    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║  ✗ PEER DISCONNECTED                                      ║\n");
    printf("╠═══════════════════════════════════════════════════════════╣\n");
    printf("║  Remaining Peers: %-40d  ║\n", g_peer_count);
    printf("╚═══════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

static void on_packet_received(const uint8_t *data, size_t len, void *user_data) {
    (void)user_data;

    g_packet_count++;

    /* Display packet info */
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║  📦 PACKET RECEIVED                                       ║\n");
    printf("╠═══════════════════════════════════════════════════════════╣\n");
    printf("║  Packet #%d                                                ║\n", g_packet_count);
    printf("║  Size: %zu bytes                                           ║\n", len);

    /* Show first 32 bytes in hex */
    printf("║  Data: ");
    size_t show_len = len > 32 ? 32 : len;
    for (size_t i = 0; i < show_len; i++) {
        printf("%02x ", data[i]);
        if (i == 15) printf("\n║        ");
    }
    if (len > 32) printf("...");
    printf("\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

/* =============================================================================
 * Statistics Display
 * ============================================================================= */

static void print_stats(void) {
    mesh_stats_t stats;
    if (mesh_get_stats(g_mesh, &stats) != MESH_OK) {
        return;
    }

    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║  📊 MESH STATISTICS                                       ║\n");
    printf("╠═══════════════════════════════════════════════════════════╣\n");
    printf("║  Peers       : %-10u                                  ║\n", stats.peer_count);
    printf("║  TX Packets  : %-10llu                                  ║\n",
           (unsigned long long)stats.packets_tx);
    printf("║  RX Packets  : %-10llu                                  ║\n",
           (unsigned long long)stats.packets_rx);
    printf("║  TX Bytes    : %-10llu                                  ║\n",
           (unsigned long long)stats.bytes_tx);
    printf("║  RX Bytes    : %-10llu                                  ║\n",
           (unsigned long long)stats.bytes_rx);
    printf("╚═══════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

/* =============================================================================
 * Send Test Packet
 * ============================================================================= */

static void send_test_packet(void) {
    if (g_peer_count == 0) {
        printf("[DEMO] ⚠ No peers connected - cannot send packet\n");
        return;
    }

    /* Create a simple test packet (fake ICMP Echo Request) */
    uint8_t packet[60];
    memset(packet, 0, sizeof(packet));

    /* IP header */
    packet[0] = 0x45;  /* Version 4, IHL 5 */
    packet[9] = 1;     /* Protocol: ICMP */

    /* Source IP: our virtual IP (we'll get it from mesh) */
    /* Destination IP: first peer's virtual IP */
    mesh_peer_info_t peer_info;
    if (mesh_get_peer_info(g_mesh, 0, &peer_info) == MESH_OK) {
        /* Parse destination IP */
        unsigned int a, b, c, d;
        if (sscanf(peer_info.virtual_ip, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
            packet[16] = a;
            packet[17] = b;
            packet[18] = c;
            packet[19] = d;

            printf("[DEMO] 📤 Sending test packet to %s...\n", peer_info.virtual_ip);

            int ret = mesh_send_packet(g_mesh, packet, sizeof(packet));
            if (ret == MESH_OK) {
                printf("[DEMO] ✓ Packet sent successfully!\n");
            } else {
                printf("[DEMO] ✗ Failed to send packet: %s\n", mesh_error_string(ret));
            }
        }
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

    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║  🌐 TURBONET MESH DEMO (No TUN)                          ║\n");
    printf("║  Simplified P2P Mesh Testing Tool                        ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n");
    printf("\n");

    /* Parse arguments */
    if (argc < 3) {
        printf("Usage: %s <virtual_ip> <listen_port> [bootstrap_peer]\n", argv[0]);
        printf("\n");
        printf("Examples:\n");
        printf("  Node 1 (bootstrap): %s 10.42.0.1 9993\n", argv[0]);
        printf("  Node 2:             %s 10.42.0.2 9994 127.0.0.1:9993\n", argv[0]);
        printf("  Node 3:             %s 10.42.0.3 9995 127.0.0.1:9993\n", argv[0]);
        printf("\n");
        return 1;
    }

    const char *virtual_ip = argv[1];
    int listen_port = atoi(argv[2]);
    const char *bootstrap_peer = argc > 3 ? argv[3] : NULL;

    printf("[DEMO] Configuration:\n");
    printf("       Virtual IP    : %s\n", virtual_ip);
    printf("       Listen Port   : %d\n", listen_port);
    printf("       Bootstrap Peer: %s\n", bootstrap_peer ? bootstrap_peer : "(none - I am bootstrap)");
    printf("\n");

    /* Setup signal handler */
#ifdef _WIN32
    SetConsoleCtrlHandler(console_handler, TRUE);
#else
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
#endif

    /* Create mesh configuration */
    mesh_config_t config;
    mesh_config_init(&config);

    config.virtual_ip = virtual_ip;
    config.virtual_prefix = 16;
    config.listen_port = listen_port;
    config.network_id = "demo-network";

    /* Set callbacks */
    config.on_peer_connected = on_peer_connected;
    config.on_peer_disconnected = on_peer_disconnected;
    config.on_packet_received = on_packet_received;

    /* Bootstrap peer */
    if (bootstrap_peer) {
        config.bootstrap_peers = &bootstrap_peer;
        config.bootstrap_count = 1;
    }

    /* Create mesh */
    printf("[DEMO] Creating mesh network...\n");
    g_mesh = mesh_create(&config);
    if (!g_mesh) {
        fprintf(stderr, "[DEMO] ✗ Failed to create mesh network\n");
        return 1;
    }
    printf("[DEMO] ✓ Mesh network created\n");

    /* Start mesh */
    printf("[DEMO] Starting mesh network...\n");
    int ret = mesh_start(g_mesh);
    if (ret != MESH_OK) {
        fprintf(stderr, "[DEMO] ✗ Failed to start mesh: %s\n", mesh_error_string(ret));
        mesh_destroy(g_mesh);
        return 1;
    }
    printf("[DEMO] ✓ Mesh network started\n");
    printf("\n");

    if (bootstrap_peer) {
        printf("[DEMO] Connecting to bootstrap peer: %s\n", bootstrap_peer);
    } else {
        printf("[DEMO] Waiting for incoming connections...\n");
    }

    printf("[DEMO] Press Ctrl+C to quit, 's' to show stats, 'p' to send test packet\n");
    printf("\n");

    /* Main loop */
    int stats_counter = 0;
    while (g_running) {
        /* Poll mesh network */
        mesh_poll(g_mesh, 100);

        /* Sleep a bit */
        sleep_ms(100);

        /* Show stats every 10 seconds */
        stats_counter++;
        if (stats_counter >= 100) {  /* 100 * 100ms = 10 seconds */
            stats_counter = 0;
            print_stats();
        }

        /* Check for keyboard input (Windows only for simplicity) */
#ifdef _WIN32
        if (_kbhit()) {
            int ch = _getch();
            if (ch == 's' || ch == 'S') {
                print_stats();
            } else if (ch == 'p' || ch == 'P') {
                send_test_packet();
            }
        }
#endif
    }

    /* Cleanup */
    printf("\n[DEMO] Stopping mesh network...\n");
    mesh_stop(g_mesh);
    mesh_destroy(g_mesh);
    printf("[DEMO] ✓ Mesh network stopped\n");

    /* Final stats */
    printf("\n[DEMO] Final statistics:\n");
    printf("       Total peer connections: %d\n", g_peer_count);
    printf("       Total packets received: %d\n", g_packet_count);
    printf("\n");
    printf("[DEMO] Goodbye!\n");

    if (logger) {
        tlog_flush(logger);
        tlog_destroy(logger);
    }

    return 0;
}
