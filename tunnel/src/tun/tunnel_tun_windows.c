/**
 * @file tunnel_tun_windows.c
 * @brief Windows TUN device implementation using Wintun
 *
 * Uses WireGuard's Wintun driver for high-performance TUN functionality.
 * Wintun is a simple, efficient TUN driver without the overhead of TAP.
 */
 
#ifdef _WIN32
#include <Windows.h>
#include "tunnel_tun.h"
#include "../core/tunnel_types.h"
#include "../stack/tunnel_ip_stack.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <objbase.h>
#include <fmt.h>
#include <turbo_thread.h>

/* Wintun API typedefs */
typedef void *WINTUN_ADAPTER_HANDLE;
typedef void *WINTUN_SESSION_HANDLE;
typedef GUID WINTUN_ADAPTER_GUID;

/* Wintun function pointers */
typedef WINTUN_ADAPTER_HANDLE (WINAPI *WINTUN_CREATE_ADAPTER_FUNC)(
    const WCHAR *Name,
    const WCHAR *TunnelType,
    const GUID *RequestedGUID
);

typedef void (WINAPI *WINTUN_CLOSE_ADAPTER_FUNC)(
    WINTUN_ADAPTER_HANDLE Adapter
);

typedef WINTUN_SESSION_HANDLE (WINAPI *WINTUN_START_SESSION_FUNC)(
    WINTUN_ADAPTER_HANDLE Adapter,
    DWORD Capacity
);

typedef void (WINAPI *WINTUN_END_SESSION_FUNC)(
    WINTUN_SESSION_HANDLE Session
);

typedef BYTE* (WINAPI *WINTUN_RECEIVE_PACKET_FUNC)(
    WINTUN_SESSION_HANDLE Session,
    DWORD *PacketSize
);

typedef void (WINAPI *WINTUN_RELEASE_RECEIVE_PACKET_FUNC)(
    WINTUN_SESSION_HANDLE Session,
    const BYTE *Packet
);

typedef BYTE* (WINAPI *WINTUN_ALLOCATE_SEND_PACKET_FUNC)(
    WINTUN_SESSION_HANDLE Session,
    DWORD PacketSize
);

typedef void (WINAPI *WINTUN_SEND_PACKET_FUNC)(
    WINTUN_SESSION_HANDLE Session,
    const BYTE *Packet
);

typedef HANDLE (WINAPI *WINTUN_GET_READ_WAIT_EVENT_FUNC)(
    WINTUN_SESSION_HANDLE Session
);

/* Wintun library handle and function pointers */
static HMODULE g_wintun_module = NULL;
static WINTUN_CREATE_ADAPTER_FUNC WintunCreateAdapter = NULL;
static WINTUN_CLOSE_ADAPTER_FUNC WintunCloseAdapter = NULL;
static WINTUN_START_SESSION_FUNC WintunStartSession = NULL;
static WINTUN_END_SESSION_FUNC WintunEndSession = NULL;
static WINTUN_RECEIVE_PACKET_FUNC WintunReceivePacket = NULL;
static WINTUN_RELEASE_RECEIVE_PACKET_FUNC WintunReleaseReceivePacket = NULL;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC WintunAllocateSendPacket = NULL;
static WINTUN_SEND_PACKET_FUNC WintunSendPacket = NULL;
static WINTUN_GET_READ_WAIT_EVENT_FUNC WintunGetReadWaitEvent = NULL;

/* Windows-specific TUN state */
typedef struct {
    WINTUN_ADAPTER_HANDLE adapter;
    WINTUN_SESSION_HANDLE session;
    HANDLE read_event;
} tun_windows_t;

/* =============================================================================
 * Wintun Library Loading
 * ============================================================================= */

static int load_wintun(void)
{
    if (g_wintun_module) return TUNNEL_OK;

    g_wintun_module = LoadLibraryExW(L"wintun.dll", NULL,
                                      LOAD_LIBRARY_SEARCH_APPLICATION_DIR |
                                      LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!g_wintun_module) {
        return TUNNEL_ERR_TUN_OPEN;
    }

    #define LOAD_FUNC(name, type) \
        name = (type)GetProcAddress(g_wintun_module, #name); \
        if (!name) { FreeLibrary(g_wintun_module); g_wintun_module = NULL; return TUNNEL_ERR_TUN_OPEN; }

    LOAD_FUNC(WintunCreateAdapter, WINTUN_CREATE_ADAPTER_FUNC);
    LOAD_FUNC(WintunCloseAdapter, WINTUN_CLOSE_ADAPTER_FUNC);
    LOAD_FUNC(WintunStartSession, WINTUN_START_SESSION_FUNC);
    LOAD_FUNC(WintunEndSession, WINTUN_END_SESSION_FUNC);
    LOAD_FUNC(WintunReceivePacket, WINTUN_RECEIVE_PACKET_FUNC);
    LOAD_FUNC(WintunReleaseReceivePacket, WINTUN_RELEASE_RECEIVE_PACKET_FUNC);
    LOAD_FUNC(WintunAllocateSendPacket, WINTUN_ALLOCATE_SEND_PACKET_FUNC);
    LOAD_FUNC(WintunSendPacket, WINTUN_SEND_PACKET_FUNC);
    LOAD_FUNC(WintunGetReadWaitEvent, WINTUN_GET_READ_WAIT_EVENT_FUNC);

    #undef LOAD_FUNC

    return TUNNEL_OK;
}

/* =============================================================================
 * Helper Functions
 * ============================================================================= */

static void utf8_to_wide(const char *utf8, WCHAR *wide, size_t wide_len)
{
    MultiByteToWideChar(CP_UTF8, 0, utf8, -1, wide, (int)wide_len);
}

static int run_netsh_command(const char *fmt, ...)
{
    char cmd[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(cmd, sizeof(cmd), fmt, args);
    va_end(args);

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    char full_cmd[1100];
    fmt(full_cmd, sizeof(full_cmd), "netsh {}", cmd);

    if (!CreateProcessA(NULL, full_cmd, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return -1;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exit_code;
    GetExitCodeProcess(pi.hProcess, &exit_code);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return exit_code == 0 ? 0 : -1;
}

/* =============================================================================
 * TUN Device Lifecycle
 * ============================================================================= */

tunnel_tun_t* tunnel_tun_create(tunnel_t *tunnel, const tunnel_tun_config_t *config)
{
    if (!tunnel) return NULL;

    /* Load Wintun library */
    if (load_wintun() != TUNNEL_OK) {
        return NULL;
    }

    tunnel_tun_t *tun = calloc(1, sizeof(tunnel_tun_t));
    if (!tun) return NULL;

    tun->tunnel = tunnel;
    tun->fd = -1;

    /* Allocate Windows-specific state */
    tun->handle = calloc(1, sizeof(tun_windows_t));
    if (!tun->handle) {
        free(tun);
        return NULL;
    }

    /* Copy configuration */
    if (config) {
        if (config->name) {
            strncpy(tun->name, config->name, sizeof(tun->name) - 1);
        } else {
            strcpy(tun->name, "TurboTun");
        }
        if (config->ipv4_addr) {
            strncpy(tun->ipv4_addr, config->ipv4_addr, sizeof(tun->ipv4_addr) - 1);
        }
        if (config->ipv4_netmask) {
            strncpy(tun->ipv4_netmask, config->ipv4_netmask, sizeof(tun->ipv4_netmask) - 1);
        }
        if (config->ipv6_addr) {
            strncpy(tun->ipv6_addr, config->ipv6_addr, sizeof(tun->ipv6_addr) - 1);
        }
        tun->ipv6_prefix = config->ipv6_prefix;
        tun->mtu = config->mtu ? config->mtu : 1500;
    } else {
        strcpy(tun->name, "TurboTun");
        tun->mtu = 1500;
    }

    return tun;
}

void tunnel_tun_destroy(tunnel_tun_t *tun)
{
    if (!tun) return;

    tunnel_tun_close(tun);

    if (tun->handle) {
        free(tun->handle);
    }

    free(tun);
}

/* =============================================================================
 * TUN Device Open/Close
 * ============================================================================= */

int tunnel_tun_open(tunnel_tun_t *tun)
{
    if (!tun || !tun->handle) return TUNNEL_ERR_INVALID_ARG;

    tun_windows_t *win = (tun_windows_t *)tun->handle;

    /* Convert name to wide string */
    WCHAR wide_name[64];
    utf8_to_wide(tun->name, wide_name, 64);

    /* Create adapter */
    GUID guid;
    CoCreateGuid(&guid);

    win->adapter = WintunCreateAdapter(wide_name, L"TurboTunnel", &guid);
    if (!win->adapter) {
        return TUNNEL_ERR_TUN_OPEN;
    }

    /* Start session with 4MB ring buffer */
    win->session = WintunStartSession(win->adapter, 0x400000);
    if (!win->session) {
        WintunCloseAdapter(win->adapter);
        win->adapter = NULL;
        return TUNNEL_ERR_TUN_OPEN;
    }

    /* Get read event for async notification */
    win->read_event = WintunGetReadWaitEvent(win->session);

    return TUNNEL_OK;
}

void tunnel_tun_close(tunnel_tun_t *tun)
{
    if (!tun || !tun->handle) return;

    tun_windows_t *win = (tun_windows_t *)tun->handle;

    /* Wake any pending wait on the session read event before teardown. */
    if (win->read_event) {
        SetEvent(win->read_event);
    }

    /* End session */
    if (win->session) {
        WintunEndSession(win->session);
        win->session = NULL;
    }

    /* Close adapter */
    if (win->adapter) {
        WintunCloseAdapter(win->adapter);
        win->adapter = NULL;
    }

    win->read_event = NULL;
}

/* =============================================================================
 * TUN Device Configuration
 * ============================================================================= */

int tunnel_tun_configure(tunnel_tun_t *tun)
{
    if (!tun || !tun->handle) return TUNNEL_ERR_INVALID_ARG;

    tun_windows_t *win = (tun_windows_t *)tun->handle;
    if (!win->adapter) return TUNNEL_ERR_TUN_CONFIG;

    /* Get interface index */
    /* Note: In production, use GetAdaptersAddresses to get the proper index */

    /* Set IPv4 address using netsh */
    if (tun->ipv4_addr[0]) {
        /* Calculate prefix from netmask */
        int prefix = 24;  /* Default */
        if (tun->ipv4_netmask[0]) {
            unsigned int a, b, c, d;
            if (sscanf(tun->ipv4_netmask, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
                uint32_t mask = (a << 24) | (b << 16) | (c << 8) | d;
                prefix = 0;
                while (mask & 0x80000000) {
                    prefix++;
                    mask <<= 1;
                }
            }
        }

        if (run_netsh_command("interface ip set address \"%s\" static %s/%d",
                              tun->name, tun->ipv4_addr, prefix) != 0) {
            return TUNNEL_ERR_TUN_CONFIG;
        }
    }

    /* Set MTU */
    if (tun->mtu > 0) {
        run_netsh_command("interface ipv4 set subinterface \"%s\" mtu=%d",
                          tun->name, tun->mtu);
    }

    /* Set IPv6 address if specified */
    if (tun->ipv6_addr[0]) {
        run_netsh_command("interface ipv6 add address \"%s\" %s/%d",
                          tun->name, tun->ipv6_addr, tun->ipv6_prefix);
    }

    return TUNNEL_OK;
}

int tunnel_tun_start(tunnel_tun_t *tun)
{
    if (!tun || !tun->handle) return TUNNEL_ERR_INVALID_ARG;

    tun_windows_t *win = (tun_windows_t *)tun->handle;
    if (!win->session) return TUNNEL_ERR_TUN_CONFIG;

    return TUNNEL_OK;
}

void tunnel_tun_stop(tunnel_tun_t *tun)
{
    (void)tun;
}

int tunnel_tun_poll(tunnel_tun_t *tun)
{
    int processed = 0;
    int n;

    if (!tun || !tun->handle) {
        return 0;
    }

    for (;;) {
        n = tunnel_tun_read(tun, tun->recv_buf, sizeof(tun->recv_buf));
        if (n <= 0) {
            break;
        }

        processed++;
        if (tun->read_cb) {
            tun->read_cb(tun, tun->recv_buf, (size_t)n);
        }
    }

    return processed;
}

/* =============================================================================
 * Read/Write Operations
 * ============================================================================= */

int tunnel_tun_read(tunnel_tun_t *tun, uint8_t *buf, size_t len)
{
    if (!tun || !buf || !tun->handle) return TUNNEL_ERR_INVALID_ARG;

    tun_windows_t *win = (tun_windows_t *)tun->handle;
    if (!win->session) return TUNNEL_ERR_INVALID_ARG;

    DWORD packet_size;
    BYTE *packet = WintunReceivePacket(win->session, &packet_size);
    if (!packet) {
        return 0;  /* No packet available */
    }

    if (packet_size > len) {
        WintunReleaseReceivePacket(win->session, packet);
        return TUNNEL_ERR_INVALID_ARG;
    }

    memcpy(buf, packet, packet_size);
    WintunReleaseReceivePacket(win->session, packet);

    tun->packets_read++;
    tun->bytes_read += packet_size;

    return (int)packet_size;
}

int tunnel_tun_write(tunnel_tun_t *tun, const uint8_t *buf, size_t len)
{
    if (!tun || !buf || !tun->handle) return TUNNEL_ERR_INVALID_ARG;

    tun_windows_t *win = (tun_windows_t *)tun->handle;
    if (!win->session) return TUNNEL_ERR_INVALID_ARG;

    BYTE *packet = WintunAllocateSendPacket(win->session, (DWORD)len);
    if (!packet) {
        return TUNNEL_ERR_NO_MEMORY;
    }

    memcpy(packet, buf, len);
    WintunSendPacket(win->session, packet);

    tun->packets_written++;
    tun->bytes_written += len;

    return (int)len;
}

/* =============================================================================
 * Accessors
 * ============================================================================= */

const char* tunnel_tun_get_name(tunnel_tun_t *tun)
{
    return tun ? tun->name : NULL;
}

int tunnel_tun_get_fd(tunnel_tun_t *tun)
{
    /* Windows doesn't use file descriptors for TUN */
    (void)tun;
    return -1;
}

int tunnel_tun_set_fd(tunnel_tun_t *tun, int fd)
{
    /* Windows doesn't use file descriptors for TUN */
    (void)tun;
    (void)fd;
    return TUNNEL_ERR_NOT_SUPPORTED;
}

int tunnel_tun_get_mtu(tunnel_tun_t *tun)
{
    return tun ? tun->mtu : 0;
}

int tunnel_tun_set_mtu(tunnel_tun_t *tun, int mtu)
{
    if (!tun) return TUNNEL_ERR_INVALID_ARG;

    tun->mtu = mtu;

    /* Update MTU via netsh if device is open */
    tun_windows_t *win = (tun_windows_t *)tun->handle;
    if (win && win->adapter) {
        if (run_netsh_command("interface ipv4 set subinterface \"%s\" mtu=%d",
                              tun->name, mtu) != 0) {
            return TUNNEL_ERR_TUN_CONFIG;
        }
    }

    return TUNNEL_OK;
}

/* =============================================================================
 * Read Callback
 * ============================================================================= */

void tunnel_tun_set_read_cb(tunnel_tun_t *tun, tunnel_tun_read_cb cb)
{
    if (!tun) return;
    tun->read_cb = (tunnel_tun_read_cb_t)cb;
}

/* =============================================================================
 * Multi-Queue (Not supported on Windows)
 * ============================================================================= */

int tunnel_tun_set_multi_queue(tunnel_tun_t *tun, int num_queues)
{
    (void)tun;
    (void)num_queues;
    return TUNNEL_ERR_NOT_SUPPORTED;
}

/* =============================================================================
 * Packet Parsing (Shared with Linux)
 * ============================================================================= */

/* Note: tunnel_tun_parse_packet and tunnel_tun_build_packet are
 * implemented in tunnel_tun_linux.c as they are platform-independent.
 * On Windows, we link against that implementation or duplicate it here.
 */

int tunnel_tun_parse_packet(
    const uint8_t *data, size_t len,
    int *version, int *protocol,
    tunnel_endpoint_t *src, tunnel_endpoint_t *dst,
    const uint8_t **payload, size_t *payload_len)
{
    if (!data || len < 20) return TUNNEL_ERR_INVALID_ARG;

    int ip_version = (data[0] >> 4) & 0x0F;
    if (version) *version = ip_version;

    if (ip_version == 4) {
        int ihl = (data[0] & 0x0F) * 4;
        if ((size_t)ihl > len) return TUNNEL_ERR_INVALID_ARG;

        if (protocol) *protocol = data[9];

        if (src) {
            src->family = AF_INET;
            memcpy(&src->addr.v4, &data[12], 4);
            src->port = 0;
        }

        if (dst) {
            dst->family = AF_INET;
            memcpy(&dst->addr.v4, &data[16], 4);
            dst->port = 0;
        }

        int proto = data[9];
        if ((proto == 6 || proto == 17) && len >= (size_t)(ihl + 4)) {
            if (src) src->port = (data[ihl] << 8) | data[ihl + 1];
            if (dst) dst->port = (data[ihl + 2] << 8) | data[ihl + 3];
        }

        int transport_hdr = (proto == 6) ? 20 : 8;
        if (payload) *payload = data + ihl + transport_hdr;
        if (payload_len) {
            size_t hdr_total = ihl + transport_hdr;
            *payload_len = (len > hdr_total) ? len - hdr_total : 0;
        }
    } else if (ip_version == 6) {
        if (len < 40) return TUNNEL_ERR_INVALID_ARG;

        if (protocol) *protocol = data[6];

        if (src) {
            src->family = AF_INET6;
            memcpy(src->addr.v6, &data[8], 16);
            src->port = 0;
        }

        if (dst) {
            dst->family = AF_INET6;
            memcpy(dst->addr.v6, &data[24], 16);
            dst->port = 0;
        }

        int proto = data[6];
        if ((proto == 6 || proto == 17) && len >= 44) {
            if (src) src->port = (data[40] << 8) | data[41];
            if (dst) dst->port = (data[42] << 8) | data[43];
        }

        int transport_hdr = (proto == 6) ? 20 : 8;
        if (payload) *payload = data + 40 + transport_hdr;
        if (payload_len) {
            size_t hdr_total = 40 + transport_hdr;
            *payload_len = (len > hdr_total) ? len - hdr_total : 0;
        }
    } else {
        return TUNNEL_ERR_INVALID_ARG;
    }

    return TUNNEL_OK;
}

int tunnel_tun_build_packet(
    uint8_t *buf, size_t buf_len,
    int version, int protocol,
    const tunnel_endpoint_t *src, const tunnel_endpoint_t *dst,
    const uint8_t *payload, size_t payload_len)
{
    if (version == 4) {
        if (protocol == 6) {
            return tunnel_ip_build_tcp(buf, buf_len, src, dst,
                                        0, 0, 0, 65535, payload, payload_len);
        } else if (protocol == 17) {
            return tunnel_ip_build_udp(buf, buf_len, src, dst, payload, payload_len);
        }
    }

    return TUNNEL_ERR_NOT_SUPPORTED;
}

#endif /* _WIN32 */
