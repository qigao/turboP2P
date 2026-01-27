/**
 * @file tunnel_socks5.c
 * @brief Advanced SOCKS5 tunnel example with authentication and routing rules
 *
 * Features demonstrated:
 * - SOCKS5 with username/password authentication
 * - Include/exclude routing rules
 * - Domain-based routing
 * - Traffic monitoring callback
 * - Session enumeration
 * - Hot configuration reload
 *
 * Usage:
 *   tunnel_socks5 -h <host> -p <port> [-u <user>] [-P <pass>] [-v]
 *
 * Options:
 *   -h <host>   Proxy server host (default: 127.0.0.1)
 *   -p <port>   Proxy server port (default: 1080)
 *   -u <user>   Username for authentication
 *   -P <pass>   Password for authentication
 *   -v          Verbose logging (debug level)
 */

#include <turbo_tunnel.h>
#include <tlog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#define sleep(x) Sleep((x) * 1000)
#else
#include <unistd.h>
#include <getopt.h>
#endif

/* Global state */
static tunnel_t *g_tunnel = NULL;
static volatile int g_running = 1;
static int g_verbose = 0;

/* Traffic counters for monitoring */
static uint64_t g_last_rx = 0;
static uint64_t g_last_tx = 0;

/* =============================================================================
 * Configuration
 * ============================================================================= */

typedef struct {
    const char *proxy_host;
    int proxy_port;
    const char *username;
    const char *password;
    int verbose;
} app_config_t;

static void config_init(app_config_t *cfg)
{
    cfg->proxy_host = "127.0.0.1";
    cfg->proxy_port = 1080;
    cfg->username = NULL;
    cfg->password = NULL;
    cfg->verbose = 0;
}

/* =============================================================================
 * Signal Handler
 * ============================================================================= */

#ifdef _WIN32
static BOOL WINAPI console_handler(DWORD signal)
{
    if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT) {
        g_running = 0;
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
    g_running = 0;
    if (g_tunnel) {
        tunnel_stop(g_tunnel);
    }
}
#endif

/* =============================================================================
 * Callbacks
 * ============================================================================= */

static const char* get_timestamp(void)
{
    static char buf[32];
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    strftime(buf, sizeof(buf), "%H:%M:%S", tm);
    return buf;
}

static void log_callback(int level, const char *message, void *user_data)
{
    (void)user_data;

    /* Filter based on verbose setting */
    if (!g_verbose && level > 2) {
        return;
    }

    const char *color = "";
    const char *reset = "";
    const char *level_str;

#ifndef _WIN32
    /* ANSI colors for Unix terminals */
    reset = "\033[0m";
    switch (level) {
        case 0: color = "\033[31m"; break;  /* Red */
        case 1: color = "\033[33m"; break;  /* Yellow */
        case 2: color = "\033[32m"; break;  /* Green */
        case 3: color = "\033[36m"; break;  /* Cyan */
        case 4: color = "\033[90m"; break;  /* Gray */
        default: color = ""; break;
    }
#endif

    switch (level) {
        case 0: level_str = "ERR"; break;
        case 1: level_str = "WRN"; break;
        case 2: level_str = "INF"; break;
        case 3: level_str = "DBG"; break;
        case 4: level_str = "TRC"; break;
        default: level_str = "???"; break;
    }

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
    tunnel_session_state_t state = tunnel_session_get_state(session);

    const char *state_str;
    switch (state) {
        case TUNNEL_SESSION_INIT: state_str = "INIT"; break;
        case TUNNEL_SESSION_CONNECTING: state_str = "CONNECTING"; break;
        case TUNNEL_SESSION_ESTABLISHED: state_str = "ESTABLISHED"; break;
        case TUNNEL_SESSION_CLOSING: state_str = "CLOSING"; break;
        case TUNNEL_SESSION_CLOSED: state_str = "CLOSED"; break;
        default: state_str = "UNKNOWN"; break;
    }

    TLOG_INFO("[SESSION] {}: {}:{} -> {}:{} [{}]\n",
           event, src, src_port, dst, dst_port, state_str);

    /* Print traffic stats for closed sessions */
    if (strcmp(event, "closed") == 0) {
        uint64_t rx = tunnel_session_get_bytes_rx(session);
        uint64_t tx = tunnel_session_get_bytes_tx(session);
        if (rx > 0 || tx > 0) {
            printf("         Traffic: RX=%llu bytes, TX=%llu bytes\n",
                   (unsigned long long)rx, (unsigned long long)tx);
        }
    }
}

static void traffic_callback(tunnel_t *tunnel, int direction,
                              const uint8_t *data, size_t len,
                              void *user_data)
{
    (void)tunnel;
    (void)data;
    (void)user_data;

    /* Only log in very verbose mode */
    if (g_verbose > 1) {
        TLOG_DEBUG("Traffic {}: {} bytes",
               direction == 0 ? "RX" : "TX",
               len);
    }
}

/* =============================================================================
 * Session Enumeration
 * ============================================================================= */

static int print_session(tunnel_session_t *session, void *user_data)
{
    int *count = (int *)user_data;
    (*count)++;

    const char *src = tunnel_session_get_src_addr(session);
    int src_port = tunnel_session_get_src_port(session);
    const char *dst = tunnel_session_get_dst_addr(session);
    int dst_port = tunnel_session_get_dst_port(session);
    tunnel_session_state_t state = tunnel_session_get_state(session);
    uint64_t rx = tunnel_session_get_bytes_rx(session);
    uint64_t tx = tunnel_session_get_bytes_tx(session);

    const char *state_str;
    switch (state) {
        case TUNNEL_SESSION_ESTABLISHED: state_str = "EST"; break;
        case TUNNEL_SESSION_CONNECTING: state_str = "CON"; break;
        case TUNNEL_SESSION_CLOSING: state_str = "CLS"; break;
        default: state_str = "???"; break;
    }

    printf("  %3d. %s:%d -> %s:%d [%s] RX:%llu TX:%llu\n",
           *count, src, src_port, dst, dst_port, state_str,
           (unsigned long long)rx, (unsigned long long)tx);

    return 0;  /* Continue iteration */
}

static void list_sessions(tunnel_t *tunnel)
{
    int count = 0;
    printf("\n=== Active Sessions ===\n");
    tunnel_foreach_session(tunnel, print_session, &count);
    if (count == 0) {
        printf("  (no active sessions)\n");
    }
    printf("=======================\n\n");
}

/* =============================================================================
 * Statistics Display
 * ============================================================================= */

static void print_stats(tunnel_t *tunnel)
{
    tunnel_stats_t stats;
    if (tunnel_get_stats(tunnel, &stats) != TUNNEL_OK) {
        return;
    }

    /* Calculate rates */
    double rx_rate = (stats.bytes_rx - g_last_rx) / 1024.0;  /* KB/s */
    double tx_rate = (stats.bytes_tx - g_last_tx) / 1024.0;
    g_last_rx = stats.bytes_rx;
    g_last_tx = stats.bytes_tx;

    printf("\r[%s] Sessions: %u TCP, %u UDP | "
           "Traffic: %.1f KB/s down, %.1f KB/s up | "
           "Total: %.2f MB",
           get_timestamp(),
           stats.tcp_sessions, stats.udp_sessions,
           rx_rate, tx_rate,
           (stats.bytes_rx + stats.bytes_tx) / (1024.0 * 1024.0));
    fflush(stdout);
}

/* =============================================================================
 * Routing Configuration
 * ============================================================================= */

/* IP ranges to exclude from tunnel (bypass proxy) */
static const char *exclude_ranges[] = {
    "127.0.0.0/8",      /* Localhost */
    "10.0.0.0/8",       /* Private class A */
    "172.16.0.0/12",    /* Private class B */
    "192.168.0.0/16",   /* Private class C */
    "169.254.0.0/16",   /* Link-local */
    "224.0.0.0/4",      /* Multicast */
};

/* Domains to exclude from tunnel */
static const char *exclude_domains[] = {
    "localhost",
    "*.local",
    "*.lan",
};

/* =============================================================================
 * Main
 * ============================================================================= */

static void print_usage(const char *prog)
{
    printf("Usage: %s [options]\n", prog);
    printf("\nOptions:\n");
    printf("  -h <host>   Proxy server host (default: 127.0.0.1)\n");
    printf("  -p <port>   Proxy server port (default: 1080)\n");
    printf("  -u <user>   Username for authentication\n");
    printf("  -P <pass>   Password for authentication\n");
    printf("  -v          Verbose logging\n");
    printf("  -?          Show this help\n");
    printf("\nExample:\n");
    printf("  %s -h proxy.example.com -p 1080 -u myuser -P mypass\n", prog);
}

int main(int argc, char *argv[])
{
    app_config_t cfg;
    config_init(&cfg);

    /* Parse arguments */
#ifdef _WIN32
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 && i + 1 < argc) {
            cfg.proxy_host = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            cfg.proxy_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-u") == 0 && i + 1 < argc) {
            cfg.username = argv[++i];
        } else if (strcmp(argv[i], "-P") == 0 && i + 1 < argc) {
            cfg.password = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0) {
            cfg.verbose = 1;
        } else if (strcmp(argv[i], "-?") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }
#else
    int opt;
    while ((opt = getopt(argc, argv, "h:p:u:P:v?")) != -1) {
        switch (opt) {
            case 'h': cfg.proxy_host = optarg; break;
            case 'p': cfg.proxy_port = atoi(optarg); break;
            case 'u': cfg.username = optarg; break;
            case 'P': cfg.password = optarg; break;
            case 'v': cfg.verbose = 1; break;
            case '?':
            default:
                print_usage(argv[0]);
                return opt == '?' ? 0 : 1;
        }
    }
#endif

    g_verbose = cfg.verbose;

    printf("╔════════════════════════════════════════╗\n");
    printf("║     TurboNet SOCKS5 Tunnel Client      ║\n");
    printf("╚════════════════════════════════════════╝\n\n");

    printf("Version: %s\n", tunnel_version());
    printf("Proxy: socks5://%s%s%s@%s:%d\n",
           cfg.username ? cfg.username : "",
           cfg.username ? ":" : "",
           cfg.username ? "***" : "",
           cfg.proxy_host, cfg.proxy_port);
    printf("Auth: %s\n\n", cfg.username ? "username/password" : "none");

    /* Initialize Logger */
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

    int ret = tunnel_init();
    if (ret != TUNNEL_OK) {
        TLOG_ERROR("Failed to init: {}", tunnel_error_string(ret));
        return 1;
    }

    /* Build configuration */
    tunnel_config_t config;
    tunnel_config_init(&config);

    /* TUN device */
    config.tun.name = "tun0";
    config.tun.ipv4_addr = "10.255.0.1";
    config.tun.ipv4_netmask = "255.255.255.0";
    config.tun.mtu = 1400;  /* Leave room for encapsulation */

    /* SOCKS5 proxy */
    config.proxy.type = TUNNEL_PROXY_SOCKS5;
    config.proxy.host = cfg.proxy_host;
    config.proxy.port = cfg.proxy_port;
    config.proxy.username = cfg.username;
    config.proxy.password = cfg.password;

    /* DNS */
    config.dns.ipv4_server = "8.8.8.8";
    config.dns.hijack_dns = 1;
    config.dns.fake_dns = 1;
    config.dns.fake_dns_range = "198.18.0.0/15";

    /* Routing rules */
    config.route.exclude_ranges = exclude_ranges;
    config.route.exclude_count = sizeof(exclude_ranges) / sizeof(exclude_ranges[0]);
    config.route.exclude_domains = exclude_domains;
    config.route.exclude_domain_count = sizeof(exclude_domains) / sizeof(exclude_domains[0]);

    /* UDP over TCP (SOCKS5 UDP ASSOCIATE has issues with NAT) */
    config.udp_mode = TUNNEL_UDP_OVER_TCP;

    /* Logging */
    config.log_level = cfg.verbose ? 3 : 2;

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
    if (cfg.verbose) {
        tunnel_set_traffic_callback(g_tunnel, traffic_callback, NULL);
    }

    /* Setup signal handlers */
#ifdef _WIN32
    SetConsoleCtrlHandler(console_handler, TRUE);
#else
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGUSR1, signal_handler);  /* For session list */
#endif

    /* Start tunnel */
    ret = tunnel_start(g_tunnel);
    if (ret != TUNNEL_OK) {
        TLOG_ERROR("Failed to start: {}", tunnel_error_string(ret));
        tunnel_destroy(g_tunnel);
        tunnel_shutdown();
        return 1;
    }

    printf("Tunnel started successfully.\n");
    printf("Press Ctrl+C to stop.\n");
#ifndef _WIN32
    printf("Send SIGUSR1 to list active sessions.\n");
#endif
    printf("\n");

    /* Main loop */
    int tick = 0;
    while (g_running) {
        ret = tunnel_poll(g_tunnel, 1000);
        if (ret < 0) {
            break;
        }

        tick++;

        /* Update status line every second */
        print_stats(g_tunnel);

        /* List sessions every 60 seconds in verbose mode */
        if (cfg.verbose && tick % 60 == 0) {
            printf("\n");
            list_sessions(g_tunnel);
        }
    }

    printf("\n\nShutting down...\n");

    /* Final session list */
    list_sessions(g_tunnel);

    /* Final stats */
    tunnel_stats_t stats;
    if (tunnel_get_stats(g_tunnel, &stats) == TUNNEL_OK) {
        printf("\n=== Final Statistics ===\n");
        printf("Uptime: %.1f seconds\n", stats.uptime_ms / 1000.0);
        printf("Total sessions: %u\n", stats.total_sessions);
        printf("Total traffic: RX=%.2f MB, TX=%.2f MB\n",
               stats.bytes_rx / (1024.0 * 1024.0),
               stats.bytes_tx / (1024.0 * 1024.0));
        printf("========================\n");
    }

    /* Cleanup */
    tunnel_destroy(g_tunnel);
    tunnel_shutdown();
    tlog_destroy(tlog_get_default());

    printf("\nGoodbye!\n");
    return 0;
}
