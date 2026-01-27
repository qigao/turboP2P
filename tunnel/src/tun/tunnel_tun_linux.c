/**
 * @file tunnel_tun_linux.c
 * @brief Linux TUN device implementation
 */

#ifdef __linux__

#include "tunnel_tun.h"
#include "../core/tunnel_types.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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

    /* Copy configuration */
    if (config) {
        if (config->name) {
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
    free(tun);
}

/* =============================================================================
 * TUN Device Open/Close
 * ============================================================================= */

int tunnel_tun_open(tunnel_tun_t *tun)
{
    if (!tun) return TUNNEL_ERR_INVALID_ARG;

    /* Open TUN device */
    tun->fd = open("/dev/net/tun", O_RDWR);
    if (tun->fd < 0) {
        return TUNNEL_ERR_TUN_OPEN;
    }

    /* Configure TUN interface */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  /* TUN device, no packet info */

    if (tun->name[0]) {
        strncpy(ifr.ifr_name, tun->name, IFNAMSIZ - 1);
    }

    if (ioctl(tun->fd, TUNSETIFF, &ifr) < 0) {
        close(tun->fd);
        tun->fd = -1;
        return TUNNEL_ERR_TUN_OPEN;
    }

    /* Store assigned name */
    strncpy(tun->name, ifr.ifr_name, sizeof(tun->name) - 1);

    /* Set non-blocking */
    int flags = fcntl(tun->fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(tun->fd, F_SETFL, flags | O_NONBLOCK);
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

static int set_interface_address(const char *ifname, const char *addr, const char *netmask)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    /* Set IP address */
    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    sin->sin_family = AF_INET;
    if (inet_pton(AF_INET, addr, &sin->sin_addr) != 1) {
        close(sock);
        return -1;
    }

    if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
        close(sock);
        return -1;
    }

    /* Set netmask */
    if (netmask) {
        sin = (struct sockaddr_in *)&ifr.ifr_netmask;
        sin->sin_family = AF_INET;
        if (inet_pton(AF_INET, netmask, &sin->sin_addr) == 1) {
            ioctl(sock, SIOCSIFNETMASK, &ifr);
        }
    }

    close(sock);
    return 0;
}

static int set_interface_mtu(const char *ifname, int mtu)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    ifr.ifr_mtu = mtu;

    int ret = ioctl(sock, SIOCSIFMTU, &ifr);
    close(sock);

    return ret;
}

static int set_interface_up(const char *ifname)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    /* Get current flags */
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        close(sock);
        return -1;
    }

    /* Set UP flag */
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;

    int ret = ioctl(sock, SIOCSIFFLAGS, &ifr);
    close(sock);

    return ret;
}

int tunnel_tun_configure(tunnel_tun_t *tun)
{
    if (!tun || tun->fd < 0) return TUNNEL_ERR_INVALID_ARG;

    /* Set IPv4 address */
    if (tun->ipv4_addr[0]) {
        if (set_interface_address(tun->name, tun->ipv4_addr, tun->ipv4_netmask) < 0) {
            return TUNNEL_ERR_TUN_CONFIG;
        }
    }

    /* Set MTU */
    if (tun->mtu > 0) {
        if (set_interface_mtu(tun->name, tun->mtu) < 0) {
            return TUNNEL_ERR_TUN_CONFIG;
        }
    }

    /* Bring interface up */
    if (set_interface_up(tun->name) < 0) {
        return TUNNEL_ERR_TUN_CONFIG;
    }

    /* TODO: Configure IPv6 if specified */

    return TUNNEL_OK;
}

/* =============================================================================
 * libuv Integration
 * ============================================================================= */

static void on_tun_poll(uv_poll_t *handle, int status, int events)
{
    tunnel_tun_t *tun = (tunnel_tun_t *)handle->data;

    if (status < 0) {
        return;
    }

    if (events & UV_READABLE) {
        /* Read packets from TUN */
        ssize_t n = read(tun->fd, tun->recv_buf, sizeof(tun->recv_buf));
        if (n > 0) {
            tun->packets_read++;
            tun->bytes_read += n;

            /* Call read callback */
            if (tun->read_cb) {
                tun->read_cb(tun, tun->recv_buf, n);
            }
        }
    }
}

int tunnel_tun_start(tunnel_tun_t *tun, uv_loop_t *loop)
{
    if (!tun || !loop || tun->fd < 0) return TUNNEL_ERR_INVALID_ARG;

    /* Initialize poll handle */
    int ret = uv_poll_init(loop, &tun->poll, tun->fd);
    if (ret < 0) {
        return TUNNEL_ERR_TUN_CONFIG;
    }

    tun->poll.data = tun;

    /* Start polling for read events */
    ret = uv_poll_start(&tun->poll, UV_READABLE, on_tun_poll);
    if (ret < 0) {
        return TUNNEL_ERR_TUN_CONFIG;
    }

    return TUNNEL_OK;
}

void tunnel_tun_stop(tunnel_tun_t *tun)
{
    if (!tun) return;

    uv_poll_stop(&tun->poll);
}

/* =============================================================================
 * Read/Write Operations
 * ============================================================================= */

int tunnel_tun_read(tunnel_tun_t *tun, uint8_t *buf, size_t len)
{
    if (!tun || !buf || tun->fd < 0) return TUNNEL_ERR_INVALID_ARG;

    ssize_t n = read(tun->fd, buf, len);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        return TUNNEL_ERR_NETWORK;
    }

    tun->packets_read++;
    tun->bytes_read += n;

    return (int)n;
}

int tunnel_tun_write(tunnel_tun_t *tun, const uint8_t *buf, size_t len)
{
    if (!tun || !buf || tun->fd < 0) return TUNNEL_ERR_INVALID_ARG;

    ssize_t n = write(tun->fd, buf, len);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        return TUNNEL_ERR_NETWORK;
    }

    tun->packets_written++;
    tun->bytes_written += n;

    return (int)n;
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
        if (set_interface_mtu(tun->name, mtu) < 0) {
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
 * Multi-Queue Support (Linux only)
 * ============================================================================= */

int tunnel_tun_set_multi_queue(tunnel_tun_t *tun, int num_queues)
{
    if (!tun || num_queues < 1) return TUNNEL_ERR_INVALID_ARG;

    /* Multi-queue requires re-opening the device with IFF_MULTI_QUEUE */
    /* This is a simplified implementation */
    (void)num_queues;

    return TUNNEL_ERR_NOT_SUPPORTED;
}

/* =============================================================================
 * Packet Parsing (shared implementation)
 * ============================================================================= */

int tunnel_tun_parse_packet(
    const uint8_t *data, size_t len,
    int *version, int *protocol,
    tunnel_endpoint_t *src, tunnel_endpoint_t *dst,
    const uint8_t **payload, size_t *payload_len)
{
    if (!data || len < 20) return TUNNEL_ERR_INVALID_ARG;

    /* Determine IP version */
    int ip_version = (data[0] >> 4) & 0x0F;
    if (version) *version = ip_version;

    if (ip_version == 4) {
        /* IPv4 */
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

        /* Parse transport header for ports */
        int proto = data[9];
        if ((proto == 6 || proto == 17) && len >= (size_t)(ihl + 4)) {
            if (src) src->port = (data[ihl] << 8) | data[ihl + 1];
            if (dst) dst->port = (data[ihl + 2] << 8) | data[ihl + 3];
        }

        int transport_hdr = (proto == 6) ? 20 : 8;  /* TCP or UDP */
        if (payload) *payload = data + ihl + transport_hdr;
        if (payload_len) {
            size_t hdr_total = ihl + transport_hdr;
            *payload_len = (len > hdr_total) ? len - hdr_total : 0;
        }
    } else if (ip_version == 6) {
        /* IPv6 */
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
    /* Use IP stack for building */
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

#endif /* __linux__ */
