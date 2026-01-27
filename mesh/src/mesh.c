/**
 * mesh.c - P2P Mesh VPN implementation
 * Good Taste: Simple routing, no special cases, direct peer discovery
 */

#include "turbo_mesh.h"
#define STB_SPRINTF_NOUNALIGNED  // Better performance on modern CPUs
#include "stb_sprintf.h"
#include <p2p.h>
#include <uv.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "tlog.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

/* =============================================================================
 * Internal Structures
 * ============================================================================= */

typedef struct mesh_peer_s {
    char virtual_ip[16];
    char peer_id[65];
    p2p_peer_t *p2p_peer;
    int is_connected;
    uint64_t bytes_tx;
    uint64_t bytes_rx;
    uint64_t last_seen_ms;
    struct mesh_peer_s *next;
} mesh_peer_t;

/* Routing table entry */
typedef struct mesh_route_s {
    char dest_ip[16];              /* Destination virtual IP */
    mesh_peer_t *next_hop;         /* Next hop peer (direct neighbor) */
    uint8_t hop_count;             /* Distance in hops */
    uint64_t last_update_ms;       /* When this route was updated */
    struct mesh_route_s *next;
} mesh_route_t;

typedef struct mesh_network_s {
    /* Configuration */
    char virtual_ip[16];
    uint8_t virtual_prefix;
    char network_id[64];
    int listen_port;            /* P2P listen port */

    /* Bootstrap peers */
    char **bootstrap_peers;
    int bootstrap_count;

    /* P2P layer */
    p2p_node_t *p2p_node;


    int p2p_running;

    /* Peers (direct neighbors) */
    mesh_peer_t *peers;
    int peer_count;

    /* Routing table (all reachable nodes) */
    mesh_route_t *routes;
    int route_count;

    /* Statistics */
    mesh_stats_t stats;

    /* Route discovery state */
    int poll_count;  /* For periodic route updates */

    /* Callbacks */
    void (*on_peer_connected)(mesh_peer_t *peer, void *user_data);
    void (*on_peer_disconnected)(mesh_peer_t *peer, void *user_data);
    void (*on_packet_received)(const uint8_t *data, size_t len, void *user_data);
    void *user_data;
} mesh_network_t;

/* =============================================================================
 * Utility Functions
 * ============================================================================= */

static uint32_t ip_str_to_uint32(const char *ip_str) {
    unsigned int a, b, c, d;
    if (sscanf(ip_str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
        return 0;
    }
    return (a << 24) | (b << 16) | (c << 8) | d;
}

static void uint32_to_ip_str(uint32_t ip, char *out) {
    sprintf(out, "%u.%u.%u.%u",
            (ip >> 24) & 0xFF,
            (ip >> 16) & 0xFF,
            (ip >> 8) & 0xFF,
            ip & 0xFF);
}

static uint32_t extract_dst_ip(const uint8_t *ip_packet, size_t len) {
    if (len < 20) return 0;  /* Too short for IP header */

    /* IPv4 destination IP is at offset 16 */
    uint32_t dst = 0;
    dst |= (uint32_t)ip_packet[16] << 24;
    dst |= (uint32_t)ip_packet[17] << 16;
    dst |= (uint32_t)ip_packet[18] << 8;
    dst |= (uint32_t)ip_packet[19];

    return dst;
}

/* =============================================================================
 * Peer Management
 * ============================================================================= */

static mesh_peer_t *mesh_peer_create(mesh_network_t *mesh, p2p_peer_t *p2p_peer) {
    if (!mesh || !p2p_peer) return NULL;

    mesh_peer_t *peer = (mesh_peer_t *)calloc(1, sizeof(mesh_peer_t));
    if (!peer) return NULL;

    /* Get peer address */
    char peer_ip[64];
    int peer_port;
    int ret = p2p_peer_get_address(p2p_peer, peer_ip, &peer_port);
    if (ret != P2P_OK) {
        TLOG_ERROR("Failed to get peer address (error={})", ret);
        free(peer);
        return NULL;
    }

    TLOG_INFO("Creating mesh peer: {}:{}", peer_ip, peer_port);

    /* Use P2P IP as placeholder - will be updated when HELLO message arrives */
    stbsp_snprintf(peer->virtual_ip, sizeof(peer->virtual_ip), "%s", peer_ip);
    TLOG_DEBUG("Temporary virtual IP: {} (will be updated by HELLO)", peer->virtual_ip);

    peer->is_connected = 1;
    peer->p2p_peer = p2p_peer;

    /* Add to mesh peer list */
    peer->next = mesh->peers;
    mesh->peers = peer;
    mesh->peer_count++;

    return peer;
}

static void mesh_peer_destroy(mesh_peer_t *peer) {
    if (!peer) return;
    free(peer);
}

static mesh_peer_t *mesh_find_peer_internal(mesh_network_t *mesh, const char *virtual_ip) {
    mesh_peer_t *peer = mesh->peers;
    while (peer) {
        if (strcmp(peer->virtual_ip, virtual_ip) == 0) {
            return peer;
        }
        peer = peer->next;
    }
    return NULL;
}

/* =============================================================================
 * Routing Table Management
 * ============================================================================= */

static mesh_route_t *mesh_route_create(const char *dest_ip, mesh_peer_t *next_hop, uint8_t hop_count) {
    mesh_route_t *route = (mesh_route_t *)calloc(1, sizeof(mesh_route_t));
    if (!route) return NULL;

    strncpy(route->dest_ip, dest_ip, sizeof(route->dest_ip) - 1);
    route->next_hop = next_hop;
    route->hop_count = hop_count;
    route->last_update_ms = 0; /* TODO: get current time */

    return route;
}

static void mesh_route_destroy(mesh_route_t *route) {
    if (!route) return;
    free(route);
}

static mesh_route_t *mesh_route_find(mesh_network_t *mesh, const char *dest_ip) {
    mesh_route_t *route = mesh->routes;
    while (route) {
        if (strcmp(route->dest_ip, dest_ip) == 0) {
            return route;
        }
        route = route->next;
    }
    return NULL;
}

static int mesh_route_add_or_update(mesh_network_t *mesh, const char *dest_ip,
                                     mesh_peer_t *next_hop, uint8_t hop_count) {
    /* Find existing route */
    mesh_route_t *route = mesh_route_find(mesh, dest_ip);

    if (route) {
        /* Update if new route is better (fewer hops) */
        if (hop_count < route->hop_count) {
            route->next_hop = next_hop;
            route->hop_count = hop_count;
            route->last_update_ms = 0; /* TODO: update timestamp */
            return 1; /* Route updated */
        }
        return 0; /* Route not updated */
    }

    /* Create new route */
    route = mesh_route_create(dest_ip, next_hop, hop_count);
    if (!route) return -1;

    /* Add to list */
    route->next = mesh->routes;
    mesh->routes = route;
    mesh->route_count++;

    return 1; /* Route added */
}

static void mesh_route_delete(mesh_network_t *mesh, const char *dest_ip) {
    mesh_route_t **prev = &mesh->routes;
    mesh_route_t *route = mesh->routes;

    while (route) {
        if (strcmp(route->dest_ip, dest_ip) == 0) {
            *prev = route->next;
            mesh_route_destroy(route);
            mesh->route_count--;
            return;
        }
        prev = &route->next;
        route = route->next;
    }
}

/* Delete all routes that use a specific peer as next hop */
static void mesh_route_delete_via_peer(mesh_network_t *mesh, mesh_peer_t *peer) {
    mesh_route_t **prev = &mesh->routes;
    mesh_route_t *route = mesh->routes;

    while (route) {
        if (route->next_hop == peer) {
            *prev = route->next;
            mesh_route_t *to_delete = route;
            route = route->next;
            mesh_route_destroy(to_delete);
            mesh->route_count--;
        } else {
            prev = &route->next;
            route = route->next;
        }
    }
}

/* Publish our routing table to DHT for neighbors to discover */
static void mesh_publish_routes(mesh_network_t *mesh) {
    if (!mesh) return;

    char dht_key[128];
    char dht_value[1024];
    int offset = 0;

    /* Key: "mesh:<network_id>:routes:<my_ip>" */
    stbsp_snprintf(dht_key, sizeof(dht_key), "mesh:%s:routes:%s",
             mesh->network_id, mesh->virtual_ip);

    /* Value: CSV of "ip:hops,ip:hops,..." */
    /* Include direct peers */
    mesh_peer_t *peer = mesh->peers;
    while (peer && offset < (int)sizeof(dht_value) - 32) {
        if (peer->is_connected) {
            offset += stbsp_snprintf(dht_value + offset, sizeof(dht_value) - offset,
                             "%s:1,", peer->virtual_ip);
        }
        peer = peer->next;
    }

    /* Include routes (increment hop count by 1) */
    mesh_route_t *route = mesh->routes;
    while (route && offset < (int)sizeof(dht_value) - 32) {
        offset += stbsp_snprintf(dht_value + offset, sizeof(dht_value) - offset,
                         "%s:%d,", route->dest_ip, route->hop_count + 1);
        route = route->next;
    }

    /* Remove trailing comma */
    if (offset > 0) {
        dht_value[offset - 1] = '\0';
    }

    /* Publish to DHT */
    p2p_dht_put(mesh->p2p_node, dht_key, dht_value, strlen(dht_value) + 1);
}

/* Discover routes from neighbors via DHT */
static void mesh_discover_routes(mesh_network_t *mesh) {
    if (!mesh) return;

    /* Query each connected peer's routing table */
    mesh_peer_t *peer = mesh->peers;
    while (peer) {
        if (!peer->is_connected) {
            peer = peer->next;
            continue;
        }

        char dht_key[128];
        char dht_value[1024];
        size_t dht_len = sizeof(dht_value);

        stbsp_snprintf(dht_key, sizeof(dht_key), "mesh:%s:routes:%s",
                 mesh->network_id, peer->virtual_ip);

        if (p2p_dht_get(mesh->p2p_node, dht_key, dht_value, &dht_len) == P2P_OK) {
            /* Parse routes: "10.42.0.3:1,10.42.0.4:2,..." */
            char *token = strtok(dht_value, ",");
            while (token) {
                char ip[16];
                int hops;
                if (sscanf(token, "%15[^:]:%d", ip, &hops) == 2) {
                    /* Don't add route to ourselves */
                    if (strcmp(ip, mesh->virtual_ip) != 0) {
                        /* Add route via this peer */
                        mesh_route_add_or_update(mesh, ip, peer, hops);
                    }
                }
                token = strtok(NULL, ",");
            }
        }

        peer = peer->next;
    }
}

/* =============================================================================
 * P2P Peer Connection Callbacks
 * ============================================================================= */

static void mesh_on_p2p_peer_connected(p2p_peer_t *p2p_peer, void *user_data) {
    mesh_network_t *mesh = (mesh_network_t *)user_data;
    if (!mesh) return;

    /* Get peer address for logging */
    char peer_ip[64];
    int peer_port;
    p2p_peer_get_address(p2p_peer, peer_ip, &peer_port);

    TLOG_INFO("P2P peer connected: {}:{}", peer_ip, peer_port);

    /* Create mesh peer wrapper */
    mesh_peer_t *mesh_peer = mesh_peer_create(mesh, p2p_peer);
    if (!mesh_peer) {
        TLOG_WARN("Failed to create mesh peer");
        return;
    }

    /* Send our virtual IP to the peer via a simple text message */
    /* Format: "MESH_HELLO:<virtual_ip>" */
    char hello_msg[128];
    stbsp_snprintf(hello_msg, sizeof(hello_msg), "MESH_HELLO:%s", mesh->virtual_ip);

    /* Use P2P_MSG_CUSTOM to ensure message is delivered to on_message callback */
    p2p_send_message(mesh->p2p_node, p2p_peer, P2P_MSG_CUSTOM, hello_msg, strlen(hello_msg) + 1);
    TLOG_DEBUG("Sent HELLO with virtual IP: {}", mesh->virtual_ip);

    /* Notify application */
    if (mesh->on_peer_connected) {
        mesh->on_peer_connected(mesh_peer, mesh->user_data);
    }
}

static void mesh_on_p2p_peer_disconnected(p2p_peer_t *p2p_peer, void *user_data) {
    mesh_network_t *mesh = (mesh_network_t *)user_data;
    if (!mesh) return;

    /* Get peer address for logging */
    char peer_ip[64];  /* Match INET_ADDRSTRLEN (22) + safety margin */
    int peer_port;
    p2p_peer_get_address(p2p_peer, peer_ip, &peer_port);

    TLOG_INFO("P2P peer disconnected: {}:{}", peer_ip, peer_port);

    /* Find corresponding mesh peer */
    mesh_peer_t *mesh_peer = mesh->peers;
    while (mesh_peer) {
        if (mesh_peer->p2p_peer == p2p_peer) {
            /* Notify application */
            if (mesh->on_peer_disconnected) {
                mesh->on_peer_disconnected(mesh_peer, mesh->user_data);
            }

            mesh_peer->is_connected = 0;
            break;
        }
        mesh_peer = mesh_peer->next;
    }
}

/* =============================================================================
 * Message Handling
 * ============================================================================= */

static void mesh_on_p2p_message(p2p_node_t *node, p2p_peer_t *p2p_peer,
                                  const void *data, size_t len, void *user_data) {
    (void)node;

    mesh_network_t *mesh = (mesh_network_t *)user_data;
    if (!mesh || len == 0) return;

    const char *msg = (const char *)data;

    /* Check if this is a MESH_HELLO message */
    if (strncmp(msg, "MESH_HELLO:", 11) == 0) {
        /* Parse virtual IP from HELLO message */
        const char *virtual_ip = msg + 11;
        TLOG_DEBUG("Received HELLO from peer with virtual IP: {}", virtual_ip);

        /* Find corresponding mesh peer by P2P peer */
        mesh_peer_t *peer = mesh->peers;
        while (peer) {
            if (peer->p2p_peer == p2p_peer) {
                /* Update virtual IP */
                stbsp_snprintf(peer->virtual_ip, sizeof(peer->virtual_ip), "%s", virtual_ip);
                TLOG_INFO("Updated peer virtual IP to: {}", peer->virtual_ip);
                return;
            }
            peer = peer->next;
        }
        TLOG_WARN("HELLO from unknown peer");
        return;
    }

    /* Normal packet handling - this is an IP packet */
    const uint8_t *ip_packet = (const uint8_t *)data;
    if (len < 20) return;  /* Too short for IP header */

    /* Extract destination IP from packet */
    uint32_t dst_ip = extract_dst_ip(ip_packet, len);
    if (dst_ip == 0) return;

    char dst_ip_str[16];
    uint32_to_ip_str(dst_ip, dst_ip_str);

    /* Check if packet is for us */
    uint32_t my_ip = ip_str_to_uint32(mesh->virtual_ip);
    if (dst_ip == my_ip) {
        /* Deliver to local TUN device */
        if (mesh->on_packet_received) {
            mesh->on_packet_received(ip_packet, len, mesh->user_data);
        }
        mesh->stats.bytes_rx += len;
        mesh->stats.packets_rx++;
        return;
    }

    /* Check TTL to prevent routing loops */
    uint8_t ttl = ip_packet[8]; /* TTL is at offset 8 in IPv4 header */
    if (ttl <= 1) {
        /* Packet expired, drop it */
        return;
    }

    /* Forward packet to next hop */
    mesh_route_t *route = mesh_route_find(mesh, dst_ip_str);
    if (route && route->next_hop && route->next_hop->is_connected) {
        /* Decrement TTL */
        uint8_t *mutable_packet = (uint8_t *)data;
        mutable_packet[8] = ttl - 1;

        /* Recalculate IP header checksum */
        /* TODO: For now, skip checksum recalculation (most NICs do this) */

        /* Forward to next hop */
        p2p_send_message(mesh->p2p_node, route->next_hop->p2p_peer, P2P_MSG_CUSTOM, data, len);

        mesh->stats.bytes_tx += len;
        mesh->stats.packets_tx++;
    }
    /* If no route found, drop packet silently */
}

/* =============================================================================
 * Lifecycle API
 * ============================================================================= */

void mesh_config_init(mesh_config_t *config) {
    if (!config) return;

    memset(config, 0, sizeof(mesh_config_t));
    config->virtual_prefix = 16;
    config->listen_port = MESH_DEFAULT_PORT;
}

mesh_network_t *mesh_create(const mesh_config_t *config) {
    if (!config || !config->virtual_ip) return NULL;

    mesh_network_t *mesh = (mesh_network_t *)calloc(1, sizeof(mesh_network_t));
    if (!mesh) return NULL;

    /* Copy configuration */
    strncpy(mesh->virtual_ip, config->virtual_ip, sizeof(mesh->virtual_ip) - 1);
    mesh->virtual_prefix = config->virtual_prefix;

    if (config->network_id) {
        strncpy(mesh->network_id, config->network_id, sizeof(mesh->network_id) - 1);
    } else {
        strcpy(mesh->network_id, "default");
    }

    /* Copy bootstrap peers */
    if (config->bootstrap_peers && config->bootstrap_count > 0) {
        mesh->bootstrap_peers = (char **)calloc(config->bootstrap_count, sizeof(char *));
        if (mesh->bootstrap_peers) {
            mesh->bootstrap_count = config->bootstrap_count;
            for (int i = 0; i < config->bootstrap_count; i++) {
                mesh->bootstrap_peers[i] = strdup(config->bootstrap_peers[i]);
            }
        }
    }

    /* Callbacks */
    mesh->on_peer_connected = config->on_peer_connected;
    mesh->on_peer_disconnected = config->on_peer_disconnected;
    mesh->on_packet_received = config->on_packet_received;
    mesh->user_data = config->user_data;

    /* Create P2P node */
    int port = config->listen_port > 0 ? config->listen_port : MESH_DEFAULT_PORT;
    mesh->listen_port = port;  /* Save the port */
    mesh->p2p_node = p2p_create("0.0.0.0", port);
    if (!mesh->p2p_node) {
        free(mesh);
        return NULL;
    }

    /* Set P2P message handler */
    p2p_set_message_handler(mesh->p2p_node, mesh_on_p2p_message, mesh);

    /* Set P2P peer connection callbacks */
    p2p_set_peer_callbacks(mesh->p2p_node, mesh_on_p2p_peer_connected,
                           mesh_on_p2p_peer_disconnected, mesh);

    return mesh;
}

void mesh_destroy(mesh_network_t *mesh) {
    if (!mesh) return;

    /* Destroy routing table */
    mesh_route_t *route = mesh->routes;
    while (route) {
        mesh_route_t *next = route->next;
        mesh_route_destroy(route);
        route = next;
    }

    /* Destroy peers */
    mesh_peer_t *peer = mesh->peers;
    while (peer) {
        mesh_peer_t *next = peer->next;
        mesh_peer_destroy(peer);
        peer = next;
    }

    /* Free bootstrap peers */
    if (mesh->bootstrap_peers) {
        for (int i = 0; i < mesh->bootstrap_count; i++) {
            free(mesh->bootstrap_peers[i]);
        }
        free(mesh->bootstrap_peers);
    }

    /* Destroy P2P node */
    if (mesh->p2p_node) {
        p2p_destroy(mesh->p2p_node);
    }

    free(mesh);
}

/* =============================================================================
 * P2P Thread
 * ============================================================================= */



int mesh_start(mesh_network_t *mesh) {
    if (!mesh) return MESH_ERR_INVALID_ARG;

    /* Start P2P in non-blocking mode */
    TLOG_INFO("Starting P2P node...");
    int ret = p2p_start_nonblocking(mesh->p2p_node);
    if (ret != P2P_OK) {
        TLOG_ERROR("Failed to start P2P node");
        return MESH_ERR_NETWORK;
    }

    /* NOTE: P2P event loop will be pumped by mesh_poll() in the MAIN thread */
    mesh->p2p_running = 1;

    /* Register our virtual IP in DHT */
    char dht_key[128];
    stbsp_snprintf(dht_key, sizeof(dht_key), "mesh:%s:ip:%s",
             mesh->network_id, mesh->virtual_ip);

    char dht_value[256];
    stbsp_snprintf(dht_value, sizeof(dht_value), "%s:%d",
             mesh->virtual_ip, mesh->listen_port);

    p2p_dht_put(mesh->p2p_node, dht_key, dht_value, strlen(dht_value) + 1);

    /* ALSO register reverse mapping: P2P address -> Virtual IP */
    char reverse_key[128];
    stbsp_snprintf(reverse_key, sizeof(reverse_key), "mesh:%s:peer:0.0.0.0:%d",
             mesh->network_id, mesh->listen_port);

    char reverse_value[64];
    stbsp_snprintf(reverse_value, sizeof(reverse_value), "%s", mesh->virtual_ip);

    p2p_dht_put(mesh->p2p_node, reverse_key, reverse_value, strlen(reverse_value) + 1);
    TLOG_INFO("Registered virtual IP {} for port {} in DHT",
           mesh->virtual_ip, mesh->listen_port);

    /* Connect to bootstrap peers */
    if (mesh->bootstrap_peers && mesh->bootstrap_count > 0) {
        TLOG_INFO("Connecting to {} bootstrap peer(s)...", mesh->bootstrap_count);

        for (int i = 0; i < mesh->bootstrap_count; i++) {
            const char *peer_addr = mesh->bootstrap_peers[i];

            /* Parse "IP" or "IP:port" format */
            char ip[64] = {0};
            int port = 9993;  /* Default port */

            const char *colon = strchr(peer_addr, ':');
            if (colon) {
                /* Has port */
                size_t ip_len = colon - peer_addr;
                if (ip_len < sizeof(ip)) {
                    memcpy(ip, peer_addr, ip_len);
                    ip[ip_len] = '\0';
                    port = atoi(colon + 1);
                }
            } else {
                /* No port, use default */
                strncpy(ip, peer_addr, sizeof(ip) - 1);
            }

            TLOG_INFO("Connecting to bootstrap peer: {}:{}", ip, port);
            ret = p2p_connect(mesh->p2p_node, ip, port);
            if (ret != P2P_OK) {
                TLOG_WARN("Failed to connect to {}:{} (error {})", ip, port, ret);
            }
        }
    }

    return MESH_OK;
}

void mesh_stop(mesh_network_t *mesh) {
    if (!mesh) return;

    /* Disconnect all peers */
    mesh_peer_t *peer = mesh->peers;
    while (peer) {
        if (peer->is_connected && mesh->on_peer_disconnected) {
            mesh->on_peer_disconnected(peer, mesh->user_data);
        }
        peer->is_connected = 0;
        peer = peer->next;
    }
}

/* =============================================================================
 * Packet Routing
 * ============================================================================= */

int mesh_send_packet(mesh_network_t *mesh, const uint8_t *data, size_t len) {
    if (!mesh || !data || len == 0) return MESH_ERR_INVALID_ARG;

    /* Extract destination IP */
    uint32_t dst_ip = extract_dst_ip(data, len);
    if (dst_ip == 0) return MESH_ERR_INVALID_ARG;

    char dst_ip_str[16];
    uint32_to_ip_str(dst_ip, dst_ip_str);

    TLOG_DEBUG("Routing packet to {}", dst_ip_str);

    mesh_peer_t *send_to_peer = NULL;

    /* Check if destination is a direct neighbor */
    mesh_peer_t *direct_peer = mesh_find_peer_internal(mesh, dst_ip_str);
    if (direct_peer && direct_peer->is_connected) {
        /* Direct connection exists */
        TLOG_DEBUG("Found direct peer with virtual_ip={}", direct_peer->virtual_ip);
        send_to_peer = direct_peer;
    } else {
        TLOG_DEBUG("No direct peer found for {}", dst_ip_str);

        /* Debug: Print all known peers */
        TLOG_DEBUG("Known peers:");
        mesh_peer_t *p = mesh->peers;
        while (p) {
            TLOG_DEBUG("  - virtual_ip={}, connected={}", p->virtual_ip, p->is_connected);
            p = p->next;
        }
        /* Check routing table for indirect route */
        mesh_route_t *route = mesh_route_find(mesh, dst_ip_str);
        if (route && route->next_hop && route->next_hop->is_connected) {
            /* Route exists via another peer */
            send_to_peer = route->next_hop;
        } else {
            /* No route found, try to discover via DHT */
            char dht_key[128];
            stbsp_snprintf(dht_key, sizeof(dht_key), "mesh:%s:ip:%s",
                     mesh->network_id, dst_ip_str);

            char dht_value[256];
            size_t dht_len = sizeof(dht_value);

            if (p2p_dht_get(mesh->p2p_node, dht_key, dht_value, &dht_len) == P2P_OK) {
                /* Found in DHT, try to connect */
                char peer_ip[64];
                int peer_port;
                if (sscanf(dht_value, "%[^:]:%d", peer_ip, &peer_port) == 2) {
                    /* Connect to peer - mesh peer will be created automatically in callback */
                    p2p_connect(mesh->p2p_node, peer_ip, peer_port);
                }
            }
        }
    }

    /* Send packet */
    if (!send_to_peer) {
        return MESH_ERR_NOT_FOUND;
    }

    /* Send directly to specific peer instead of broadcast */
    int ret = p2p_send(mesh->p2p_node, send_to_peer->p2p_peer, data, len);

    if (ret == P2P_OK) {
        mesh->stats.bytes_tx += len;
        mesh->stats.packets_tx++;
        send_to_peer->bytes_tx += len;
    }

    return ret == P2P_OK ? MESH_OK : MESH_ERR_NETWORK;
}

int mesh_poll(mesh_network_t *mesh, int timeout_ms) {
    if (!mesh) return -1;

    /* Run P2P event loop in non-blocking mode (single iteration) */
    /* This ensures all P2P callbacks run in the SAME thread as mesh_poll */
    struct uv_loop_s *loop = p2p_get_loop(mesh->p2p_node);
    if (loop) {
        uv_run(loop, UV_RUN_NOWAIT);
    }

    /* Periodic route discovery every 100 poll cycles (~10 seconds if polled every 100ms) */
    mesh->poll_count++;
    if (mesh->poll_count >= 100) {
        mesh->poll_count = 0;

        /* Publish our routes to DHT */
        mesh_publish_routes(mesh);

        /* Discover routes from neighbors */
        mesh_discover_routes(mesh);
    }

    (void)timeout_ms;
    return 0;
}

/* =============================================================================
 * Peer Management API
 * ============================================================================= */

int mesh_get_peer_count(mesh_network_t *mesh) {
    if (!mesh) return 0;
    return mesh->peer_count;
}

int mesh_get_peer_info(mesh_network_t *mesh, int index, mesh_peer_info_t *info) {
    if (!mesh || !info || index < 0 || index >= mesh->peer_count) {
        return MESH_ERR_INVALID_ARG;
    }

    mesh_peer_t *peer = mesh->peers;
    for (int i = 0; i < index && peer; i++) {
        peer = peer->next;
    }

    if (!peer) return MESH_ERR_NOT_FOUND;

    strncpy(info->virtual_ip, peer->virtual_ip, sizeof(info->virtual_ip) - 1);
    info->is_connected = peer->is_connected;
    info->bytes_tx = peer->bytes_tx;
    info->bytes_rx = peer->bytes_rx;
    info->last_seen_ms = peer->last_seen_ms;

    return MESH_OK;
}

mesh_peer_t *mesh_find_peer(mesh_network_t *mesh, const char *virtual_ip) {
    if (!mesh || !virtual_ip) return NULL;
    return mesh_find_peer_internal(mesh, virtual_ip);
}

int mesh_connect_peer(mesh_network_t *mesh, const char *virtual_ip) {
    if (!mesh || !virtual_ip) return MESH_ERR_INVALID_ARG;

    /* Check if already connected */
    mesh_peer_t *peer = mesh_find_peer_internal(mesh, virtual_ip);
    if (peer && peer->is_connected) {
        return MESH_OK;
    }

    /* Query DHT for peer */
    char dht_key[128];
    stbsp_snprintf(dht_key, sizeof(dht_key), "mesh:%s:ip:%s",
             mesh->network_id, virtual_ip);

    char dht_value[256];
    size_t dht_len = sizeof(dht_value);

    if (p2p_dht_get(mesh->p2p_node, dht_key, dht_value, &dht_len) != P2P_OK) {
        return MESH_ERR_NOT_FOUND;
    }

    /* Parse and connect */
    char peer_ip[64];
    int peer_port;
    if (sscanf(dht_value, "%[^:]:%d", peer_ip, &peer_port) != 2) {
        return MESH_ERR_INVALID_ARG;
    }

    p2p_connect(mesh->p2p_node, peer_ip, peer_port);

    /* Peer will be created automatically when P2P connection succeeds */
    return MESH_OK;
}

void mesh_disconnect_peer(mesh_network_t *mesh, mesh_peer_t *peer) {
    if (!mesh || !peer) return;

    peer->is_connected = 0;

    /* Delete all routes that go through this peer */
    mesh_route_delete_via_peer(mesh, peer);

    if (mesh->on_peer_disconnected) {
        mesh->on_peer_disconnected(peer, mesh->user_data);
    }
}

/* =============================================================================
 * Statistics API
 * ============================================================================= */

int mesh_get_stats(mesh_network_t *mesh, mesh_stats_t *stats) {
    if (!mesh || !stats) return MESH_ERR_INVALID_ARG;

    stats->peer_count = mesh->peer_count;
    stats->bytes_tx = mesh->stats.bytes_tx;
    stats->bytes_rx = mesh->stats.bytes_rx;
    stats->packets_tx = mesh->stats.packets_tx;
    stats->packets_rx = mesh->stats.packets_rx;
    stats->dht_entries = 0;  /* TODO: get from DHT */

    return MESH_OK;
}

void mesh_reset_stats(mesh_network_t *mesh) {
    if (!mesh) return;

    memset(&mesh->stats, 0, sizeof(mesh->stats));

    /* Reset peer stats */
    mesh_peer_t *peer = mesh->peers;
    while (peer) {
        peer->bytes_tx = 0;
        peer->bytes_rx = 0;
        peer = peer->next;
    }
}

/* =============================================================================
 * Utility API
 * ============================================================================= */

CXX_C_API const char *mesh_error_string(mesh_error_t error) {
    switch (error) {
        case MESH_OK: return "Success";
        case MESH_ERR_INVALID_ARG: return "Invalid argument";
        case MESH_ERR_NO_MEMORY: return "Out of memory";
        case MESH_ERR_NOT_FOUND: return "Peer not found";
        case MESH_ERR_NETWORK: return "Network error";
        case MESH_ERR_TIMEOUT: return "Timeout";
        case MESH_ERR_ALREADY_EXISTS: return "Already exists";
        default: return "Unknown error";
    }
}

CXX_C_API const char *mesh_version(void) {
    return "1.0.0";
}
