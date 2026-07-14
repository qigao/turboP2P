/**
 * @file tunnel_tun.h
 * @brief TUN device abstraction layer
 *
 * Cross-platform TUN device interface supporting:
 * - Linux: /dev/net/tun with TUNSETIFF
 * - macOS: utun devices
 * - Windows: Wintun driver
 * - Android: VpnService fd passing
 * - iOS: NetworkExtension packet tunnel
 */

#ifndef TUNNEL_TUN_H
#define TUNNEL_TUN_H

#include "core/tunnel_types.h"

/* =============================================================================
 * Platform Detection
 * ============================================================================= */

#if defined(__linux__) || defined(__ANDROID__)
    #define TUNNEL_TUN_LINUX 1
#elif defined(__APPLE__)
    #include <TargetConditionals.h>
    #if TARGET_OS_IPHONE
        #define TUNNEL_TUN_IOS 1
    #else
        #define TUNNEL_TUN_MACOS 1
    #endif
#elif defined(_WIN32)
    #define TUNNEL_TUN_WINDOWS 1
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
    #define TUNNEL_TUN_BSD 1
#else
    #error "Unsupported platform for TUN device"
#endif

/* =============================================================================
 * TUN Device API
 * ============================================================================= */

/**
 * Create TUN device
 * @param tunnel Parent tunnel handle
 * @param config TUN configuration
 * @return TUN handle or NULL on error
 */
TUNNEL_INTERNAL tunnel_tun_t* tunnel_tun_create(tunnel_t *tunnel,
                                                 const tunnel_tun_config_t *config);

/**
 * Destroy TUN device
 * Closes the device and releases resources.
 * @param tun TUN handle
 */
TUNNEL_INTERNAL void tunnel_tun_destroy(tunnel_tun_t *tun);

/**
 * Open TUN device
 * Creates/opens the actual TUN interface.
 * @param tun TUN handle
 * @return TUNNEL_OK on success
 */
TUNNEL_INTERNAL int tunnel_tun_open(tunnel_tun_t *tun);

/**
 * Close TUN device
 * @param tun TUN handle
 */
TUNNEL_INTERNAL void tunnel_tun_close(tunnel_tun_t *tun);

/**
 * Configure TUN device
 * Sets IP addresses, MTU, and brings up the interface.
 * @param tun TUN handle
 * @return TUNNEL_OK on success
 */
TUNNEL_INTERNAL int tunnel_tun_configure(tunnel_tun_t *tun);

/**
 * Start TUN processing.
 * @param tun TUN handle
 * @return TUNNEL_OK on success
 */
TUNNEL_INTERNAL int tunnel_tun_start(tunnel_tun_t *tun);

/**
 * Stop TUN processing
 * @param tun TUN handle
 */
TUNNEL_INTERNAL void tunnel_tun_stop(tunnel_tun_t *tun);

/**
 * Poll TUN for pending packets
 * @param tun TUN handle
 * @return Number of packets processed
 */
TUNNEL_INTERNAL int tunnel_tun_poll(tunnel_tun_t *tun);

/**
 * Read packet from TUN
 * @param tun TUN handle
 * @param buf Output buffer
 * @param len Buffer size
 * @return Number of bytes read, or negative on error
 */
TUNNEL_INTERNAL int tunnel_tun_read(tunnel_tun_t *tun, uint8_t *buf, size_t len);

/**
 * Write packet to TUN
 * @param tun TUN handle
 * @param buf Packet data
 * @param len Packet length
 * @return Number of bytes written, or negative on error
 */
TUNNEL_INTERNAL int tunnel_tun_write(tunnel_tun_t *tun, const uint8_t *buf, size_t len);

/**
 * Get TUN device name
 * @param tun TUN handle
 * @return Device name string
 */
TUNNEL_INTERNAL const char* tunnel_tun_get_name(tunnel_tun_t *tun);

/**
 * Get TUN file descriptor (Unix only)
 * @param tun TUN handle
 * @return File descriptor or -1 on Windows
 */
TUNNEL_INTERNAL int tunnel_tun_get_fd(tunnel_tun_t *tun);

/**
 * Set TUN file descriptor (Android VpnService)
 * Allows passing an existing fd from Java VpnService.
 * @param tun TUN handle
 * @param fd File descriptor from VpnService
 * @return TUNNEL_OK on success
 */
TUNNEL_INTERNAL int tunnel_tun_set_fd(tunnel_tun_t *tun, int fd);

/**
 * Get MTU
 * @param tun TUN handle
 * @return MTU value
 */
TUNNEL_INTERNAL int tunnel_tun_get_mtu(tunnel_tun_t *tun);

/**
 * Set MTU
 * @param tun TUN handle
 * @param mtu New MTU value
 * @return TUNNEL_OK on success
 */
TUNNEL_INTERNAL int tunnel_tun_set_mtu(tunnel_tun_t *tun, int mtu);

/* =============================================================================
 * Platform-Specific Functions
 * ============================================================================= */

#ifdef TUNNEL_TUN_LINUX
/**
 * Enable multi-queue (Linux only)
 * @param tun TUN handle
 * @param num_queues Number of queues
 * @return TUNNEL_OK on success
 */
TUNNEL_INTERNAL int tunnel_tun_set_multi_queue(tunnel_tun_t *tun, int num_queues);
#endif

#ifdef TUNNEL_TUN_WINDOWS
/**
 * Get Wintun adapter handle (Windows only)
 * @param tun TUN handle
 * @return Wintun adapter handle
 */
TUNNEL_INTERNAL void* tunnel_tun_get_wintun_adapter(tunnel_tun_t *tun);
#endif

/* =============================================================================
 * Read Callback
 * ============================================================================= */

/**
 * TUN read callback type
 * Called when a packet is received from the TUN device.
 * @param tun TUN handle
 * @param data Packet data
 * @param len Packet length
 */
typedef void (*tunnel_tun_read_cb)(tunnel_tun_t *tun, const uint8_t *data, size_t len);

/**
 * Set read callback
 * @param tun TUN handle
 * @param cb Read callback function
 */
TUNNEL_INTERNAL void tunnel_tun_set_read_cb(tunnel_tun_t *tun, tunnel_tun_read_cb cb);

/* =============================================================================
 * Packet Inspection
 * ============================================================================= */

/**
 * Parse IP packet header
 * @param data Packet data
 * @param len Packet length
 * @param version Output: IP version (4 or 6)
 * @param protocol Output: Protocol number (TCP=6, UDP=17, ICMP=1)
 * @param src Output: Source address
 * @param dst Output: Destination address
 * @param src_port Output: Source port (TCP/UDP only)
 * @param dst_port Output: Destination port (TCP/UDP only)
 * @param payload Output: Pointer to payload
 * @param payload_len Output: Payload length
 * @return TUNNEL_OK on success
 */
TUNNEL_INTERNAL int tunnel_tun_parse_packet(
    const uint8_t *data, size_t len,
    int *version, int *protocol,
    tunnel_endpoint_t *src, tunnel_endpoint_t *dst,
    const uint8_t **payload, size_t *payload_len
);

/**
 * Build IP packet
 * @param buf Output buffer
 * @param buf_len Buffer size
 * @param version IP version (4 or 6)
 * @param protocol Protocol number
 * @param src Source endpoint
 * @param dst Destination endpoint
 * @param payload Payload data
 * @param payload_len Payload length
 * @return Packet length, or negative on error
 */
TUNNEL_INTERNAL int tunnel_tun_build_packet(
    uint8_t *buf, size_t buf_len,
    int version, int protocol,
    const tunnel_endpoint_t *src, const tunnel_endpoint_t *dst,
    const uint8_t *payload, size_t payload_len
);

#endif /* TUNNEL_TUN_H */
