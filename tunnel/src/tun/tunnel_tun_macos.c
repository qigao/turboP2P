/**
 * @file tunnel_tun_macos.c
 * @brief macOS TUN device implementation using utun
 *
 * Uses macOS's native utun kernel control interface for TUN functionality.
 * utun devices are created via PF_SYSTEM sockets with SYSPROTO_CONTROL.
 */

#if defined(__APPLE__) && defined(__MACH__)

#include "tunnel_tun.h"
#include "../core/tunnel_types.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <net/if.h>
#include <net/if_utun.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fmt.h>

/* utun control name */
#define UTUN_CONTROL_NAME "com.apple.net.utun_control"

/* macOS-specific TUN state */
typedef struct {
    /* Reserved for future macOS-specific state */
    int placeholder;
} tun_macos_t;

/* =============================================================================
 * TUN Device Lifecycle
 * ============================================================================= */

tunnel_tun_t* tunnel_tun_create(tunnel_t *tunnel, const tunnel_tun_config_t *config)
{
    if (!tunnel) return NULL;

    tunnel_tun_t *tun = calloc(1, sizeof(tunnel_tun_t));
    if (!tun) return NULL;

    tun->tunnel = tunnel;
    tun->fd = -1;

    /* Allocate macOS-specific state */
    tun->handle = calloc(1, sizeof(tun_macos_t));
    if (!tun->handle) {
        free(tun);
        return NULL;
    }

    /* Copy configuration */
    if (config) {
        if (config->name) {
            /* On macOS, we'll try to parse utunX number from name */
            strncpy(tun->name, config->name, sizeof(tun->name) - 1);
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
    if (!tun) return TUNNEL_ERR_INVALID_ARG;

    /* Create socket for utun control */
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) {
        return TUNNEL_ERR_TUN_OPEN;
    }

    /* Get control ID for utun */
    struct ctl_info ctl_info;
    memset(&ctl_info, 0, sizeof(ctl_info));
    strncpy(ctl_info.ctl_name, UTUN_CONTROL_NAME, sizeof(ctl_info.ctl_name));

    if (ioctl(fd, CTLIOCGINFO, &ctl_info) < 0) {
        close(fd);
        return TUNNEL_ERR_TUN_OPEN;
    }

    /* Set up socket address for control */
    struct sockaddr_ctl sc;
    memset(&sc, 0, sizeof(sc));
    sc.sc_len = sizeof(sc);
    sc.sc_family = AF_SYSTEM;
    sc.ss_sysaddr = AF_SYS_CONTROL;
    sc.sc_id = ctl_info.ctl_id;

    /* Parse desired utun number from name, or use 0 for auto */
    sc.sc_unit = 0;
    if (tun->name[0] && strncmp(tun->name, "utun", 4) == 0) {
        int unit = atoi(tun->name + 4);
        if (unit >= 0) {
            sc.sc_unit = unit + 1;  /* unit is 1-indexed */
        }
    }

    /* Connect to create utun device */
    if (connect(fd, (struct sockaddr *)&sc, sizeof(sc)) < 0) {
        /* Try next available unit if specific unit failed */
        if (sc.sc_unit != 0) {
            sc.sc_unit = 0;
            if (connect(fd, (struct sockaddr *)&sc, sizeof(sc)) < 0) {
                close(fd);
                return TUNNEL_ERR_TUN_OPEN;
            }
        } else {
            close(fd);
            return TUNNEL_ERR_TUN_OPEN;
        }
    }

    /* Get the actual interface name */
    socklen_t name_len = sizeof(tun->name);
    if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, tun->name, &name_len) < 0) {
        /* Construct name from unit number */
        fmt(tun->name, sizeof(tun->name), "utun{}", sc.sc_unit - 1);
    }

    tun->fd = fd;

    /* Set non-blocking */
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    return TUNNEL_OK;
}

void tunnel_tun_close(tunnel_tun_t *tun)
{
    if (!tun) return;

    if (tun->fd >= 0) {
        close(tun->fd);
        tun->fd = -1;
    }
}

/* =============================================================================
 * TUN Device Configuration
 * ============================================================================= */

static int run_ifconfig(const char *fmt, ...)
{
    char cmd[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(cmd, sizeof(cmd), fmt, args);
    va_end(args);

    char full_cmd[1100];
    fmt(full_cmd, sizeof(full_cmd), "/sbin/ifconfig {}", cmd);

    return system(full_cmd);
}

static int run_route(const char *fmt, ...)
{
    char cmd[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(cmd, sizeof(cmd), fmt, args);
    va_end(args);

    char full_cmd[1100];
    fmt(full_cmd, sizeof(full_cmd), "/sbin/route {}", cmd);

    return system(full_cmd);
}

int tunnel_tun_configure(tunnel_tun_t *tun)
{
    if (!tun || tun->fd < 0) return TUNNEL_ERR_INVALID_ARG;

    /* Set IPv4 address */
    if (tun->ipv4_addr[0]) {
        /* On macOS, utun is point-to-point, need destination address */
        /* Use next IP as destination */
        unsigned int a, b, c, d;
        if (sscanf(tun->ipv4_addr, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
            /* Destination is typically .1 of the subnet or same address */
            if (run_ifconfig("%s inet %s %s.%u.%u.1 up",
                             tun->name, tun->ipv4_addr, a, b, c) != 0) {
                return TUNNEL_ERR_TUN_CONFIG;
            }
        }

        /* Set netmask */
        if (tun->ipv4_netmask[0]) {
            run_ifconfig("%s netmask %s", tun->name, tun->ipv4_netmask);
        }
    }

    /* Set MTU */
    if (tun->mtu > 0) {
        if (run_ifconfig("%s mtu %d", tun->name, tun->mtu) != 0) {
            return TUNNEL_ERR_TUN_CONFIG;
        }
    }

    /* Set IPv6 address if specified */
    if (tun->ipv6_addr[0]) {
        run_ifconfig("%s inet6 %s/%d", tun->name, tun->ipv6_addr, tun->ipv6_prefix);
    }

    return TUNNEL_OK;
}

int tunnel_tun_start(tunnel_tun_t *tun)
{
    return (!tun || tun->fd < 0) ? TUNNEL_ERR_INVALID_ARG : TUNNEL_OK;
}

void tunnel_tun_stop(tunnel_tun_t *tun)
{
    (void)tun;
}

int tunnel_tun_poll(tunnel_tun_t *tun)
{
    int processed = 0;
    int n;

    if (!tun || tun->fd < 0) {
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
    if (!tun || !buf || tun->fd < 0) return TUNNEL_ERR_INVALID_ARG;

    /* utun includes 4-byte protocol header */
    uint8_t temp[TUNNEL_RECV_BUF_SIZE];
    ssize_t n = read(tun->fd, temp, sizeof(temp));

    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        return TUNNEL_ERR_NETWORK;
    }

    if (n <= 4) {
        return 0;
    }

    /* Skip protocol header */
    size_t payload_len = n - 4;
    if (payload_len > len) {
        payload_len = len;
    }

    memcpy(buf, temp + 4, payload_len);

    tun->packets_read++;
    tun->bytes_read += payload_len;

    return (int)payload_len;
}

int tunnel_tun_write(tunnel_tun_t *tun, const uint8_t *buf, size_t len)
{
    if (!tun || !buf || tun->fd < 0) return TUNNEL_ERR_INVALID_ARG;

    /* Prepend 4-byte protocol header */
    uint8_t temp[TUNNEL_RECV_BUF_SIZE + 4];

    /* Determine protocol from IP version */
    uint8_t ip_version = (buf[0] >> 4) & 0x0F;
    uint32_t proto;

    if (ip_version == 4) {
        proto = htonl(AF_INET);
    } else if (ip_version == 6) {
        proto = htonl(AF_INET6);
    } else {
        return TUNNEL_ERR_INVALID_ARG;
    }

    memcpy(temp, &proto, 4);
    memcpy(temp + 4, buf, len);

    ssize_t n = write(tun->fd, temp, len + 4);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        return TUNNEL_ERR_NETWORK;
    }

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
    return tun ? tun->fd : -1;
}

int tunnel_tun_set_fd(tunnel_tun_t *tun, int fd)
{
    if (!tun) return TUNNEL_ERR_INVALID_ARG;

    if (tun->fd >= 0) {
        close(tun->fd);
    }

    tun->fd = fd;
    return TUNNEL_OK;
}

int tunnel_tun_get_mtu(tunnel_tun_t *tun)
{
    return tun ? tun->mtu : 0;
}

int tunnel_tun_set_mtu(tunnel_tun_t *tun, int mtu)
{
    if (!tun) return TUNNEL_ERR_INVALID_ARG;

    tun->mtu = mtu;

    if (tun->fd >= 0 && tun->name[0]) {
        if (run_ifconfig("%s mtu %d", tun->name, mtu) != 0) {
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
 * Multi-Queue (Not supported on macOS)
 * ============================================================================= */

int tunnel_tun_set_multi_queue(tunnel_tun_t *tun, int num_queues)
{
    (void)tun;
    (void)num_queues;
    return TUNNEL_ERR_NOT_SUPPORTED;
}

/* =============================================================================
 * Packet Parsing (Shared implementation)
 * ============================================================================= */

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

#endif /* __APPLE__ && __MACH__ */
