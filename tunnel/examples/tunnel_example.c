/**
 * @file tunnel_example.c
 * @brief Basic tunnel usage example
 *
 * This example demonstrates:
 * - Creating a tunnel with TUN device
 * - Configuring proxy settings
 * - Setting up callbacks for logging and session events
 * - Running the tunnel event loop
 *
 * Usage:
 *   tunnel_example [proxy_host] [proxy_port]
 *
 * Default: SOCKS5 proxy at 127.0.0.1:1080
 */

#include <turbo_tunnel.h>
#include <tlog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

/* Global tunnel handle for signal handler */
static tunnel_t *g_tunnel = NULL;

/* =============================================================================
 * Signal Handler
 * ============================================================================= */

#ifdef _WIN32
static BOOL WINAPI console_handler(DWORD signal)
{
    if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT) {
        printf("\nReceived shutdown signal...\n");
        if (g_tunnel) {
            tunnel_stop(g_tunnel);
        }
        return TRUE;
    }
    return FALSE;
}
#else
static void signal_handler(int sig)
{
    (void)sig;
    printf("\nReceived shutdown signal...\n");
    if (g_tunnel) {
        tunnel_stop(g_tunnel);
    }
}
#endif

/* =============================================================================
 * Callbacks
 * ============================================================================= */

static void log_callback(int level, const char *message, void *user_data)
{
    (void)user_data;

    const char *level_str;
    switch (level) {
        case 0: level_str = "ERROR"; break;
        case 1: level_str = "WARN";  break;
        case 2: level_str = "INFO";  break;
        case 3: level_str = "DEBUG"; break;
        case 4: level_str = "TRACE"; break;
        default: level_str = "???";  break;
    }

    /* Bridge tunnel logs to tlog if needed, though tunnel.c now uses tlog directly */
    /* Since we removed TUNNEL_LOG custom macros, this callback might be deprecated soon. */
    /* But for now, let's log it via TLOG */
    if (level == 0) TLOG_ERROR("[Tunnel] {}", message);
    else if (level == 1) TLOG_WARN("[Tunnel] {}", message);
    else if (level == 2) TLOG_INFO("[Tunnel] {}", message);
    else TLOG_DEBUG("[Tunnel] {}", message);
}

static void session_callback(tunnel_t *tunnel, tunnel_session_t *session,
                              const char *event, void *user_data)
{
    (void)tunnel;
    (void)user_data;

    const char *src = tunnel_session_get_src_addr(session);
    int src_port = tunnel_session_get_src_port(session);
    const char *dst = tunnel_session_get_dst_addr(session);
    int dst_port = tunnel_session_get_dst_port(session);

    TLOG_INFO("[SESSION] {}: {}:{} -> {}:{}",
           event, src, src_port, dst, dst_port);
}

static void print_stats(tunnel_t *tunnel)
{
    tunnel_stats_t stats;
    if (tunnel_get_stats(tunnel, &stats) != TUNNEL_OK) {
        return;
    }

    printf("\n=== Tunnel Statistics ===\n");
    printf("Uptime: %.1f seconds\n", stats.uptime_ms / 1000.0);
    printf("Active sessions: TCP=%u, UDP=%u\n",
           stats.tcp_sessions, stats.udp_sessions);
    printf("Total sessions: %u\n", stats.total_sessions);
    printf("Traffic: RX=%.2f MB, TX=%.2f MB\n",
           stats.bytes_rx / (1024.0 * 1024.0),
           stats.bytes_tx / (1024.0 * 1024.0));
    printf("Packets: RX=%llu, TX=%llu\n",
           (unsigned long long)stats.packets_rx,
           (unsigned long long)stats.packets_tx);
    printf("Errors: connect=%u, timeout=%u, protocol=%u\n",
           stats.connect_errors, stats.timeout_errors, stats.protocol_errors);
    if (stats.avg_latency_ms > 0) {
        printf("Avg latency: %.2f ms\n", stats.avg_latency_ms);
    }
    printf("========================\n\n");
}

/* =============================================================================
 * Main
 * ============================================================================= */

int main(int argc, char *argv[])
{
    const char *proxy_host = "127.0.0.1";
    int proxy_port = 1080;
    int ret;

    /* Parse arguments */
    if (argc >= 2) {
        proxy_host = argv[1];
    }
    if (argc >= 3) {
        proxy_port = atoi(argv[2]);
    }

    printf("TurboNet Tunnel Example\n");
    printf("=======================\n");
    printf("Version: %s\n", tunnel_version());
    printf("Proxy: %s:%d (SOCKS5)\n\n", proxy_host, proxy_port);

    /* Initialize tunnel library */
    tlog_config_t log_config = {0};
    log_config.min_level = TURBO_LOG_LEVEL_INFO;
    tlog_t *logger = tlog_create(&log_config);
    if (logger) {
        turbo_console_sink_opts_t opts = {0};
        opts.output = stdout;
        opts.use_colors = 1;
        turbo_log_sink_t *sink = turbo_sink_console_create(&opts);
        tlog_add_sink(logger, sink);
        tlog_set_default(logger);
    }

    ret = tunnel_init();
    if (ret != TUNNEL_OK) {
        TLOG_ERROR("Failed to initialize tunnel: {}", tunnel_error_string(ret));
        return 1;
    }

    /* Create configuration */
    tunnel_config_t config;
    tunnel_config_init(&config);

    /* TUN device configuration */
    config.tun.name = NULL;              /* Auto-generate name */
    config.tun.ipv4_addr = "10.0.0.1";
    config.tun.ipv4_netmask = "255.255.255.0";
    config.tun.ipv6_addr = NULL;         /* Disable IPv6 for simplicity */
    config.tun.mtu = 1500;

    /* Proxy configuration */
    config.proxy.type = TUNNEL_PROXY_SOCKS5;
    config.proxy.host = proxy_host;
    config.proxy.port = proxy_port;
    config.proxy.username = NULL;        /* No auth */
    config.proxy.password = NULL;
    config.proxy.use_tls = 0;

    /* DNS configuration */
    config.dns.ipv4_server = "8.8.8.8";
    config.dns.hijack_dns = 1;           /* Route DNS through proxy */
    config.dns.fake_dns = 1;             /* Enable Fake DNS */
    config.dns.fake_dns_range = "198.18.0.0/15";

    /* Routing - tunnel all traffic */
    config.route.include_ranges = NULL;
    config.route.include_count = 0;
    config.route.exclude_ranges = NULL;
    config.route.exclude_count = 0;

    /* UDP support */
    config.udp_mode = TUNNEL_UDP_OVER_TCP;

    /* Timeouts */
    config.tcp_keep_alive = 30;
    config.session_timeout = 300;

    /* Logging */
    config.log_level = 2;  /* INFO level */

    /* Create tunnel */
    g_tunnel = tunnel_create(&config);
    if (!g_tunnel) {
        TLOG_ERROR("Failed to create tunnel");
        tunnel_shutdown();
        return 1;
    }

    /* Set callbacks */
    tunnel_set_log_callback(g_tunnel, log_callback, NULL);
    tunnel_set_session_callback(g_tunnel, session_callback, NULL);

    /* Setup signal handlers */
#ifdef _WIN32
    SetConsoleCtrlHandler(console_handler, TRUE);
#else
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
#endif

    printf("Starting tunnel...\n");
    printf("Press Ctrl+C to stop\n\n");

    /* Start the tunnel */
    ret = tunnel_start(g_tunnel);
    if (ret != TUNNEL_OK) {
        TLOG_ERROR("Failed to start tunnel: {}", tunnel_error_string(ret));
        tunnel_destroy(g_tunnel);
        tunnel_shutdown();
        return 1;
    }

    /* Run event loop */
    printf("Tunnel running. TUN device created.\n");
    printf("Configure your applications to use the TUN device for routing.\n\n");

    /* Periodically print stats while running */
    int iterations = 0;
    while (1) {
        ret = tunnel_poll(g_tunnel, 1000);  /* Poll for 1 second */
        if (ret < 0) {
            break;  /* Tunnel stopped */
        }

        iterations++;
        if (iterations % 30 == 0) {  /* Every 30 seconds */
            print_stats(g_tunnel);
        }
    }

    /* Final stats */
    print_stats(g_tunnel);

    /* Cleanup */
    printf("Shutting down tunnel...\n");
    tunnel_destroy(g_tunnel);
    tunnel_shutdown();
    tlog_destroy(tlog_get_default());

    printf("Done.\n");
    return 0;
}
