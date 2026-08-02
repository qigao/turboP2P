/**
 * node.c - P2P Node Management implementation
 * Professional version based on Kademlia DHT and unified connection
 */

#include "node.h"
#include "peer.h"
#include "../transfer/transfer.h"
#include "../internal.h"
#include <CoroNet/turbo_coro_context.h>
#include <CoroNet/turbo_stream.h>
#include <tlog.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "../crypto/p2p_crypto.h"

/* Forward declarations */
void node_maintenance_cb(turbo_timer_t *timer);
static int node_build_sockaddr(const char *ip, int port, struct sockaddr_storage *addr);
static int node_sockaddr_to_peer(const struct sockaddr_storage *addr, char *ip,
                                 size_t ip_size, int *port);
static void node_server_accept_cb(void *server_handle, void *client_handle, void *peer);
static int node_send_identity_ping(p2p_node_t *node, p2p_peer_t *peer);
static int node_ip_is_publishable(const char *ip);
typedef void (*node_peer_event_cb_t)(struct p2p_peer_s *peer, void *user_data);
static p2p_peer_t *node_find_connected_peer_by_id_locked(p2p_node_t *node,
                                                         const uint8_t *id,
                                                         const p2p_peer_t *exclude);
static p2p_peer_entry_t *node_find_peer_entry_locked(p2p_node_t *node, const p2p_peer_t *peer);
static void node_remove_peer_entry_locked(p2p_node_t *node, const p2p_peer_t *peer);
static void node_publish_peer_route_locked(p2p_node_t *node, const p2p_peer_t *peer);
static void node_capture_peer_event_locked(p2p_node_t *node, p2p_peer_t *peer,
                                           node_peer_event_cb_t callback, void *user_data,
                                           node_peer_event_cb_t *callback_out,
                                           void **user_data_out, int *hold_peer_out);
static void node_handle_peer_disconnect_locked(p2p_node_t *node, p2p_peer_t *peer);
static int node_activate_authenticated_peer_locked(p2p_node_t *node, p2p_peer_t *peer,
                                                   p2p_peer_t **stale_peer,
                                                   p2p_peer_t **duplicate_peer);
static p2p_peer_t *node_take_expired_pending_peer_locked(p2p_node_t *node,
                                                         uint64_t now_ms);

/* =============================================================================
 * Node Lifecycle
 * ============================================================================= */

p2p_node_t* p2p_node_create(const char *ip, int port) {
    if (!ip) return NULL;

    p2p_node_t *node = (p2p_node_t *)calloc(1, sizeof(p2p_node_t));
    if (!node) return NULL;

    strncpy(node->ip, ip, sizeof(node->ip) - 1);
    node->port = port;

    /* Initialize Hash Table for Peers */
    node->peers_table = NULL;
    node->peer_count = 0;

    /* Initialize Kademlia DHT */
    node->kad_dht = kademlia_create(ip, (uint16_t)port);
    if (!node->kad_dht) {
        free(node);
        return NULL;
    }

    /* Sync local ID from Kademlia instance */
    memcpy(node->id, node->kad_dht->routing->local_id.bytes, KADEMLIA_ID_BYTES);
    if (p2p_crypto_generate_identity(&node->crypto.identity) != P2P_OK) {
        kademlia_destroy(node->kad_dht);
        free(node);
        return NULL;
    }
    node->encryption_enabled = 1;

    node->ctx = coro_context_create(NULL);
    if (!node->ctx) {
        kademlia_destroy(node->kad_dht);
        free(node);
        return NULL;
    }

    /* Initialize node mutex */
    turbo_mutex_init(&node->mutex);

    node->transfers = (p2p_transfer_manager_t *)calloc(1, sizeof(p2p_transfer_manager_t));
    if (!node->transfers) {
        turbo_mutex_destroy(&node->mutex);
        coro_context_destroy(node->ctx);
        kademlia_destroy(node->kad_dht);
        free(node);
        return NULL;
    }
    p2p_transfer_manager_init(node->transfers);

    return node;
}

void p2p_node_destroy(p2p_node_t *node) {
    if (!node) return;
    
    /* Use professional cleanup orchestration from cleanup.c */
    void p2p_destroy_clean(p2p_node_t *node); /* Forward declaration */
    p2p_destroy_clean(node);
}

/* =============================================================================
 * File Management
 * ============================================================================= */

void p2p_node_add_file(p2p_node_t *node, p2p_file_t *file) {
    if (!node || !file) return;

    turbo_mutex_lock(&node->mutex);
    file->next_file = node->local_files;
    node->local_files = file;
    turbo_mutex_unlock(&node->mutex);
}

void p2p_node_remove_file(p2p_node_t *node, const char *key) {
    if (!node || !key) return;

    turbo_mutex_lock(&node->mutex);
    p2p_file_t **curr = &node->local_files;
    while (*curr) {
        if (strcmp((*curr)->hash, key) == 0) {
            p2p_file_t *to_remove = *curr;
            *curr = (*curr)->next_file;
            p2p_file_free(to_remove);
            turbo_mutex_unlock(&node->mutex);
            return;
        }
        curr = &(*curr)->next_file;
    }
    turbo_mutex_unlock(&node->mutex);
}

p2p_file_t *p2p_node_find_local_file_by_id(p2p_node_t *node, const p2p_id_t id) {
    p2p_file_t *file = NULL;

    if (!node || !id) {
        return NULL;
    }

    turbo_mutex_lock(&node->mutex);
    file = p2p_node_find_local_file_by_id_locked(node, id);
    turbo_mutex_unlock(&node->mutex);
    return file;
}

p2p_file_t *p2p_node_find_local_file_by_id_locked(p2p_node_t *node, const p2p_id_t id) {
    p2p_file_t *file = NULL;

    if (!node || !id) {
        return NULL;
    }

    file = node->local_files;
    while (file) {
        if (memcmp(file->id, id, P2P_HASH_SIZE) == 0) {
            return file;
        }
        file = file->next_file;
    }
    return NULL;
}

p2p_file_t *p2p_node_detach_local_files(p2p_node_t *node) {
    p2p_file_t *files = NULL;

    if (!node) {
        return NULL;
    }

    turbo_mutex_lock(&node->mutex);
    files = node->local_files;
    node->local_files = NULL;
    turbo_mutex_unlock(&node->mutex);

    return files;
}

p2p_download_t *p2p_node_detach_downloads(p2p_node_t *node) {
    p2p_download_t *downloads = NULL;

    if (!node) {
        return NULL;
    }

    turbo_mutex_lock(&node->mutex);
    downloads = node->downloads;
    node->downloads = NULL;
    turbo_mutex_unlock(&node->mutex);

    return downloads;
}

p2p_peer_t **p2p_node_snapshot_connected_peers(p2p_node_t *node, size_t *count_out) {
    p2p_peer_t **peers = NULL;
    p2p_peer_entry_t *curr = NULL;
    p2p_peer_entry_t *tmp = NULL;
    size_t count = 0;
    size_t capacity = 0;

    if (count_out) {
        *count_out = 0;
    }
    if (!node || !count_out) {
        return NULL;
    }

    turbo_mutex_lock(&node->mutex);
    capacity = (size_t)peer_table_count(node->peers_table);
    if (capacity > 0) {
        peers = (p2p_peer_t **)calloc(capacity, sizeof(*peers));
    }
    if (capacity > 0 && !peers) {
        turbo_mutex_unlock(&node->mutex);
        return NULL;
    }

    HASH_ITER(hh, node->peers_table, curr, tmp) {
        if (!curr->peer || !curr->peer->is_connected) {
            continue;
        }
        if (!p2p_peer_hold_locked(curr->peer)) {
            continue;
        }
        peers[count++] = curr->peer;
    }
    turbo_mutex_unlock(&node->mutex);

    *count_out = count;
    return peers;
}

p2p_peer_info_ex_t *p2p_node_snapshot_peer_info_ex(p2p_node_t *node, size_t *count_out) {
    p2p_peer_info_ex_t *infos = NULL;
    p2p_peer_entry_t *curr = NULL;
    p2p_peer_entry_t *tmp = NULL;
    size_t count = 0;
    size_t capacity = 0;

    if (count_out) {
        *count_out = 0;
    }
    if (!node || !count_out) {
        return NULL;
    }

    turbo_mutex_lock(&node->mutex);
    capacity = (size_t)peer_table_count(node->peers_table);
    if (capacity > 0) {
        infos = (p2p_peer_info_ex_t *)calloc(capacity, sizeof(*infos));
    }
    if (capacity > 0 && !infos) {
        turbo_mutex_unlock(&node->mutex);
        return NULL;
    }

    HASH_ITER(hh, node->peers_table, curr, tmp) {
        p2p_peer_t *peer = curr->peer;
        if (!peer || !peer->is_connected) {
            continue;
        }

        p2p_peer_fill_info_ex_locked(peer, &infos[count]);
        count++;
    }
    turbo_mutex_unlock(&node->mutex);

    *count_out = count;
    return infos;
}

void p2p_peer_fill_info_ex_locked(const p2p_peer_t *peer, p2p_peer_info_ex_t *info) {
    if (!peer || !info) {
        return;
    }

    strncpy(info->ip, peer->ip, sizeof(info->ip) - 1);
    info->ip[sizeof(info->ip) - 1] = '\0';
    info->port = peer->port;
    info->is_connected = peer->is_connected;
}

int p2p_id_is_zero(const uint8_t *id) {
    static const uint8_t zero_id[KADEMLIA_ID_BYTES] = {0};

    return id && memcmp(id, zero_id, KADEMLIA_ID_BYTES) == 0;
}

void p2p_endpoint_to_key(char *buf, size_t buf_size, const char *ip, int port) {
    if (!buf || buf_size == 0 || !ip) {
        return;
    }

    snprintf(buf, buf_size, "%s:%d", ip, port);
}

void p2p_endpoint_to_id(const char *ip, int port, kad_id_t *id) {
    char endpoint[96];

    if (!ip || !id) {
        return;
    }

    p2p_endpoint_to_key(endpoint, sizeof(endpoint), ip, port);
    kad_id_from_data(endpoint, strlen(endpoint), id);
}

void p2p_init_kad_node(kad_node_t *node, const uint8_t *id, const char *ip, int port) {
    if (!node || !ip) {
        return;
    }

    memset(node, 0, sizeof(*node));
    if (id && !p2p_id_is_zero(id)) {
        memcpy(node->id.bytes, id, KADEMLIA_ID_BYTES);
    } else {
        p2p_endpoint_to_id(ip, port, &node->id);
    }
    strncpy(node->ip, ip, sizeof(node->ip) - 1);
    node->port = (uint16_t)port;
    node->last_seen = (uint64_t)time(NULL);
}

p2p_peer_info_t *p2p_node_snapshot_peer_info(p2p_node_t *node, size_t *count_out) {
    p2p_peer_info_ex_t *infos_ex = NULL;
    p2p_peer_info_t *infos = NULL;
    size_t count = 0;

    if (count_out) {
        *count_out = 0;
    }
    if (!node || !count_out) {
        return NULL;
    }

    infos_ex = p2p_node_snapshot_peer_info_ex(node, &count);
    if (count > 0 && !infos_ex) {
        return NULL;
    }
    if (count > 0) {
        infos = (p2p_peer_info_t *)calloc(count, sizeof(*infos));
    }
    if (count > 0 && !infos) {
        free(infos_ex);
        return NULL;
    }

    for (size_t i = 0; i < count; i++) {
        strncpy(infos[i].ip, infos_ex[i].ip, sizeof(infos[i].ip) - 1);
        infos[i].ip[sizeof(infos[i].ip) - 1] = '\0';
        infos[i].port = infos_ex[i].port;
        infos[i].is_connected = infos_ex[i].is_connected;
    }

    free(infos_ex);
    *count_out = count;
    return infos;
}

/* =============================================================================
 * Network Operations
 * ============================================================================= */

void p2p_node_broadcast(p2p_node_t *node, p2p_message_t *msg) {
    p2p_peer_t **peers = NULL;
    size_t count = 0;

    if (!node || !msg) return;

    peers = p2p_node_snapshot_connected_peers(node, &count);
    if (count > 0 && !peers) {
        return;
    }

    for (size_t i = 0; i < count; i++) {
        if (peers[i]) {
            p2p_peer_send(peers[i], msg);
            p2p_peer_release(peers[i]);
        }
    }
    free(peers);
}

/* =============================================================================
 * DHT Integration
 * ============================================================================= */

int p2p_dht_join_ring(p2p_node_t *node, const char *bootstrap_ip, int bootstrap_port) {
    p2p_peer_t *peer = NULL;
    kad_id_t bootstrap_id;
    int ret = 0;

    if (!node || !bootstrap_ip) return P2P_ERR_INVALID_ARG;

    /* Professional Kademlia doesn't have a "ring", it has k-buckets.
     * Joining means contacting the bootstrap node to populate buckets. */
    
    /* Create a permanent peer for boostrap */
    peer = p2p_peer_create(node, bootstrap_ip, bootstrap_port);
    if (!peer) return P2P_ERR_NO_MEM;

    turbo_mutex_lock(&node->mutex);
    if (p2p_node_find_peer_by_endpoint_locked(node, bootstrap_ip, bootstrap_port)) {
        turbo_mutex_unlock(&node->mutex);
        p2p_peer_destroy(peer);
        return P2P_OK;
    }
    p2p_node_add_peer_locked(node, peer);
    turbo_mutex_unlock(&node->mutex);

    ret = p2p_peer_connect(peer);
    if (ret != P2P_OK) {
        turbo_mutex_lock(&node->mutex);
        p2p_node_remove_peer_by_endpoint_locked(node, bootstrap_ip, bootstrap_port);
        turbo_mutex_unlock(&node->mutex);
        p2p_peer_destroy(peer);
        return ret;
    }

    /* Keep the provisional route ID consistent with other endpoint-derived
     * Kademlia contacts until the authenticated peer ID is learned. */
    p2p_endpoint_to_id(bootstrap_ip, bootstrap_port, &bootstrap_id);
    turbo_mutex_lock(&node->mutex);
    p2p_node_add_route_locked(node, bootstrap_id.bytes, bootstrap_ip, bootstrap_port);
    turbo_mutex_unlock(&node->mutex);

    /* Start iterative lookup for OUR identity to discover our neighborhood */
    (void)p2p_dht_lookup_start(node, node->id, P2P_MSG_DHT_FIND_NODE);

    return P2P_OK;
}

void p2p_dht_create_ring(p2p_node_t *node) {
    /* No-op in Kademlia (ring creation is not a separate step) */
    (void)node;
}


/* =============================================================================
 * Peer Events & Dispatch
 * ============================================================================= */

void p2p_node_on_peer_connected(p2p_node_t *node, p2p_peer_t *peer) {
    if (!node || !peer) return;

    if (node->encryption_enabled) {
        if (peer->conn && peer->conn->type == P2P_CONN_OUTBOUND) {
            p2p_peer_start_handshake(peer);
        }
    } else {
        /* If no encryption, consider it authenticated immediately */
        p2p_node_on_peer_authenticated(node, peer);
    }
}

void p2p_node_on_peer_disconnected(p2p_node_t *node, p2p_peer_t *peer) {
    node_peer_event_cb_t on_peer_disconnected = NULL;
    void *peer_user_data = NULL;
    int hold_peer = 0;

    if (!node || !peer) return;

    turbo_mutex_lock(&node->mutex);
    node_handle_peer_disconnect_locked(node, peer);
    node_capture_peer_event_locked(node, peer, node->on_peer_disconnected,
                                   node->peer_user_data, &on_peer_disconnected,
                                   &peer_user_data, &hold_peer);
    turbo_mutex_unlock(&node->mutex);

    if (on_peer_disconnected) {
        on_peer_disconnected(peer, peer_user_data);
    }
    if (hold_peer) {
        p2p_peer_release(peer);
    }
}

void p2p_node_on_peer_authenticated(p2p_node_t *node, p2p_peer_t *peer) {
    int should_publish_endpoint = 0;
    p2p_peer_t *stale_peer = NULL;
    p2p_peer_t *duplicate_peer = NULL;
    node_peer_event_cb_t on_peer_connected = NULL;
    void *peer_user_data = NULL;
    int hold_peer = 0;

    if (!node || !peer) return;

    turbo_mutex_lock(&node->mutex);
    should_publish_endpoint = node_activate_authenticated_peer_locked(node, peer,
                                                                      &stale_peer,
                                                                      &duplicate_peer);
    if (!duplicate_peer) {
        if (should_publish_endpoint) {
            node_publish_peer_route_locked(node, peer);
        }
        node_capture_peer_event_locked(node, peer, node->on_peer_connected,
                                       node->peer_user_data, &on_peer_connected,
                                       &peer_user_data, &hold_peer);
    }
    turbo_mutex_unlock(&node->mutex);

    if (stale_peer) {
        p2p_peer_destroy(stale_peer);
    }
    if (duplicate_peer) {
        p2p_peer_destroy(duplicate_peer);
        return;
    }

    p2p_dht_lookup_try_progress(node);
    (void)node_send_identity_ping(node, peer);

    if (on_peer_connected) {
        on_peer_connected(peer, peer_user_data);
    }
    if (hold_peer) {
        p2p_peer_release(peer);
    }
}

static int node_send_identity_ping(p2p_node_t *node, p2p_peer_t *peer) {
    p2p_ping_payload_t ping = {0};
    int ret = P2P_ERR_INVALID_STATE;

    if (!node || !peer) {
        return P2P_ERR_INVALID_ARG;
    }

    turbo_mutex_lock(&node->mutex);
    if (!peer->is_connected || peer->state != P2P_PEER_STATE_CONNECTED ||
        !p2p_crypto_session_is_ready(&peer->crypto) ||
        peer->outstanding_ping_ms != 0) {
        turbo_mutex_unlock(&node->mutex);
        return P2P_ERR_INVALID_STATE;
    }

    memcpy(ping.node_id, node->id, P2P_DHT_KEY_SIZE);
    if (node_ip_is_publishable(node->ip)) {
        strncpy(ping.ip, node->ip, sizeof(ping.ip) - 1);
    }
    ping.port = (uint16_t)node->port;
    ping.timestamp = turbo_hrtime() / 1000000;
    memcpy(ping.coords, node->coord.coords, sizeof(ping.coords));
    ping.height = node->coord.height;
    ping.error = node->coord.error;
    peer->last_ping_sent_ms = ping.timestamp;
    peer->outstanding_ping_ms = ping.timestamp;
    turbo_mutex_unlock(&node->mutex);

    ret = p2p_send_message(node, peer, P2P_MSG_PING, &ping, sizeof(ping));
    if (ret != P2P_OK) {
        turbo_mutex_lock(&node->mutex);
        if (peer->outstanding_ping_ms == ping.timestamp) {
            peer->outstanding_ping_ms = 0;
            peer->last_ping_sent_ms = 0;
        }
        turbo_mutex_unlock(&node->mutex);
    }
    return ret;
}

static int node_ip_is_publishable(const char *ip) {
    return ip && ip[0] != '\0' &&
           strcmp(ip, "0.0.0.0") != 0 &&
           strcmp(ip, "::") != 0;
}

static void node_capture_peer_event_locked(p2p_node_t *node, p2p_peer_t *peer,
                                           node_peer_event_cb_t callback, void *user_data,
                                           node_peer_event_cb_t *callback_out,
                                           void **user_data_out, int *hold_peer_out) {
    if (callback_out) {
        *callback_out = NULL;
    }
    if (user_data_out) {
        *user_data_out = NULL;
    }
    if (hold_peer_out) {
        *hold_peer_out = 0;
    }
    if (!node || !peer || !callback) {
        return;
    }

    peer->callback_refs++;
    if (callback_out) {
        *callback_out = callback;
    }
    if (user_data_out) {
        *user_data_out = user_data;
    }
    if (hold_peer_out) {
        *hold_peer_out = 1;
    }
}

static void node_handle_peer_disconnect_locked(p2p_node_t *node, p2p_peer_t *peer) {
    if (!node || !peer) {
        return;
    }

    if (node->peers_table && (!peer->keep_entry || peer->destroying) &&
        node_find_peer_entry_locked(node, peer)) {
        node_remove_peer_entry_locked(node, peer);
    }

    if (peer->counted && node->peer_count > 0) {
        node->peer_count--;
        peer->counted = 0;
    }
}

static int node_activate_authenticated_peer_locked(p2p_node_t *node, p2p_peer_t *peer,
                                                   p2p_peer_t **stale_peer,
                                                   p2p_peer_t **duplicate_peer) {
    p2p_peer_entry_t *entry = NULL;
    p2p_peer_t *identity_peer = NULL;
    int should_publish_endpoint = 1;

    if (stale_peer) {
        *stale_peer = NULL;
    }
    if (duplicate_peer) {
        *duplicate_peer = NULL;
    }
    if (!node || !peer) {
        return 0;
    }

    identity_peer = node_find_connected_peer_by_id_locked(node, peer->id, peer);
    if (identity_peer) {
        if (node_find_peer_entry_locked(node, peer)) {
            node_remove_peer_entry_locked(node, peer);
        }
        if (peer->counted && node->peer_count > 0) {
            node->peer_count--;
            peer->counted = 0;
        }
        if (duplicate_peer) {
            *duplicate_peer = peer;
        }
        return 0;
    }

    entry = node_find_peer_entry_locked(node, peer);
    if (entry && entry->peer != peer) {
        if (entry->peer->is_connected) {
            if (duplicate_peer) {
                *duplicate_peer = peer;
            }
            return 0;
        }

        if (stale_peer) {
            *stale_peer = entry->peer;
        }
        node_remove_peer_entry_locked(node, peer);
    }

    peer->is_connected = 1;
    peer->state = P2P_PEER_STATE_CONNECTED;

    if (!node_find_peer_entry_locked(node, peer)) {
        p2p_node_add_peer_locked(node, peer);
    }

    if (!peer->counted) {
        node->peer_count++;
        peer->counted = 1;
    }

    /*
     * A server-accepted transport endpoint is just the caller's ephemeral source
     * port. Advertising it through the routing table teaches later lookups a
     * nondialable endpoint and creates duplicate reverse connects.
     */
    if (peer->conn && peer->conn->type == P2P_CONN_INBOUND) {
        should_publish_endpoint = 0;
    }

    return should_publish_endpoint;
}

static p2p_peer_t *node_find_connected_peer_by_id_locked(p2p_node_t *node,
                                                         const uint8_t *id,
                                                         const p2p_peer_t *exclude) {
    p2p_peer_entry_t *curr = NULL;
    p2p_peer_entry_t *tmp = NULL;

    if (!node || !id || p2p_id_is_zero(id)) {
        return NULL;
    }

    HASH_ITER(hh, node->peers_table, curr, tmp) {
        if (!curr->peer || curr->peer == exclude) {
            continue;
        }
        if (!curr->peer->is_connected || curr->peer->destroying) {
            continue;
        }
        if (memcmp(curr->peer->id, id, P2P_DHT_KEY_SIZE) == 0) {
            return curr->peer;
        }
    }

    return NULL;
}

CXX_C_API p2p_peer_t *p2p_node_find_peer_by_endpoint_locked(p2p_node_t *node,
                                                             const char *ip,
                                                             int port) {
    p2p_peer_entry_t *entry = NULL;

    if (!node || !ip) {
        return NULL;
    }

    entry = peer_table_find(node->peers_table, ip, port);
    return entry ? entry->peer : NULL;
}

CXX_C_API void p2p_node_add_peer_locked(p2p_node_t *node, p2p_peer_t *peer) {
    if (!node || !peer) {
        return;
    }

    peer_table_add(&node->peers_table, peer);
}

CXX_C_API int p2p_node_pending_peer_capacity_available_locked(p2p_node_t *node) {
    p2p_peer_entry_t *curr = NULL;
    p2p_peer_entry_t *tmp = NULL;
    int pending_count = 0;

    if (!node) {
        return 0;
    }

    HASH_ITER(hh, node->peers_table, curr, tmp) {
        if (curr->peer && !curr->peer->is_connected &&
            curr->peer->state == P2P_PEER_STATE_HANDSHAKING) {
            pending_count++;
            if (pending_count >= P2P_PENDING_PEER_LIMIT) {
                return 0;
            }
        }
    }

    return 1;
}

CXX_C_API void p2p_node_remove_peer_by_endpoint_locked(p2p_node_t *node,
                                                       const char *ip,
                                                       int port) {
    if (!node || !ip) {
        return;
    }

    peer_table_remove(&node->peers_table, ip, port);
}

CXX_C_API void p2p_node_add_route_locked(p2p_node_t *node, const uint8_t *id, const char *ip, int port) {
    kad_node_t knode;

    if (!node || !node->kad_dht || !node->kad_dht->routing || !ip) {
        return;
    }

    p2p_init_kad_node(&knode, id, ip, port);
    kad_routing_add_node(node->kad_dht->routing, &knode);
}

CXX_C_API void p2p_node_remove_route_locked(p2p_node_t *node, const uint8_t *id, const char *ip, int port) {
    kad_id_t route_id;

    if (!node || !node->kad_dht || !node->kad_dht->routing) {
        return;
    }

    if (id && !p2p_id_is_zero(id)) {
        memcpy(route_id.bytes, id, sizeof(route_id.bytes));
    } else if (ip) {
        p2p_endpoint_to_id(ip, port, &route_id);
    } else {
        return;
    }

    kad_routing_remove_node(node->kad_dht->routing, &route_id);
}

static p2p_peer_entry_t *node_find_peer_entry_locked(p2p_node_t *node, const p2p_peer_t *peer) {
    if (!node || !peer) {
        return NULL;
    }

    return peer_table_find(node->peers_table, peer->ip, peer->port);
}

static void node_remove_peer_entry_locked(p2p_node_t *node, const p2p_peer_t *peer) {
    if (!node || !peer) {
        return;
    }

    p2p_node_remove_peer_by_endpoint_locked(node, peer->ip, peer->port);
}

static void node_publish_peer_route_locked(p2p_node_t *node, const p2p_peer_t *peer) {
    if (!node || !peer) {
        return;
    }

    p2p_node_add_route_locked(node, peer->id, peer->ip, peer->port);
}

void p2p_node_dispatch_message(p2p_node_t *node, p2p_peer_t *peer, p2p_message_t *msg) {
    if (!node || !peer || !msg) return;

    /* Handle handshake messages separately if handshaking */
    if (msg->header.type == P2P_MSG_NOISE_HANDSHAKE) {
        p2p_peer_handle_handshake(peer, msg);
        return;
    }

    /* For custom messages, notify user */
    if (msg->header.type == P2P_MSG_CUSTOM) {
        if (node->on_message) {
            node->on_message(node, peer, msg->payload.raw, msg->header.payload_len, node->user_data);
            return;
        }
        return;
    }

    p2p_handlers_dispatch(node, peer, msg);
}

/* =============================================================================
 * Infrastructure implementation
 * ============================================================================= */

static int node_build_sockaddr(const char *ip, int port, struct sockaddr_storage *addr) {
    struct sockaddr_in *addr4;
    struct sockaddr_in6 *addr6;

    if (!ip || !addr) {
        return -1;
    }

    memset(addr, 0, sizeof(*addr));
    addr4 = (struct sockaddr_in *)addr;
    if (inet_pton(AF_INET, ip, &addr4->sin_addr) == 1) {
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons((uint16_t)port);
        return 0;
    }

    addr6 = (struct sockaddr_in6 *)addr;
    if (inet_pton(AF_INET6, ip, &addr6->sin6_addr) == 1) {
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons((uint16_t)port);
        return 0;
    }

    return -1;
}

static int node_sockaddr_to_peer(const struct sockaddr_storage *addr, char *ip,
                                 size_t ip_size, int *port) {
    const void *src = NULL;

    if (!addr || !ip || !port) {
        return -1;
    }

    if (addr->ss_family == AF_INET) {
        const struct sockaddr_in *addr4 = (const struct sockaddr_in *)addr;
        src = &addr4->sin_addr;
        *port = ntohs(addr4->sin_port);
    } else if (addr->ss_family == AF_INET6) {
        const struct sockaddr_in6 *addr6 = (const struct sockaddr_in6 *)addr;
        src = &addr6->sin6_addr;
        *port = ntohs(addr6->sin6_port);
    } else {
        return -1;
    }

    return inet_ntop(addr->ss_family, src, ip, (socklen_t)ip_size) ? 0 : -1;
}

static void node_server_accept_cb(void *server_handle, void *client_handle, void *peer) {
    turbo_stream_listener_t *listener = (turbo_stream_listener_t *)server_handle;
    turbo_stream_t *client = (turbo_stream_t *)client_handle;
    p2p_node_t *node = (p2p_node_t *)turbo_stream_listener_get_user_data(listener);
    struct sockaddr_storage addr;
    const struct sockaddr *peer_addr = (const struct sockaddr *)peer;
    char ip[P2P_MAX_IP];
    int port = 0;
    p2p_peer_t *accepted_peer;
    int peer_tracked = 0;

    if (!node || !client) return;

    memset(&addr, 0, sizeof(addr));
    if (peer_addr && peer_addr->sa_family == AF_INET) {
        memcpy(&addr, peer_addr, sizeof(struct sockaddr_in));
    } else if (peer_addr && peer_addr->sa_family == AF_INET6) {
        memcpy(&addr, peer_addr, sizeof(struct sockaddr_in6));
    } else if (turbo_stream_get_peer_addr(client, &addr) != 0) {
        turbo_stream_destroy(client);
        return;
    }

    if (node_sockaddr_to_peer(&addr, ip, sizeof(ip), &port) != 0) {
        turbo_stream_destroy(client);
        return;
    }

    accepted_peer = p2p_peer_create(node, ip, port);
    if (!accepted_peer) {
        turbo_stream_destroy(client);
        return;
    }

    accepted_peer->conn = p2p_connection_create_inbound(client);
    if (!accepted_peer->conn) {
        turbo_stream_destroy(client);
        p2p_peer_destroy(accepted_peer);
        return;
    }

    turbo_stream_set_user_data(client, accepted_peer);
    if (turbo_stream_recv_start(client, p2p_peer_stream_recv) != 0) {
        turbo_stream_set_user_data(client, NULL);
        p2p_connection_destroy(accepted_peer->conn);
        accepted_peer->conn = NULL;
        p2p_peer_destroy(accepted_peer);
        return;
    }

    accepted_peer->state = P2P_PEER_STATE_HANDSHAKING;
    accepted_peer->is_connected = 0;
    accepted_peer->connect_time = turbo_hrtime();
    accepted_peer->last_seen = accepted_peer->connect_time;

    /* The peer table owns accepted transports from accept through teardown.
     * Keep unauthenticated peers hidden from connected-peer snapshots until
     * node_activate_authenticated_peer_locked() completes authentication. */
    turbo_mutex_lock(&node->mutex);
    if (p2p_node_pending_peer_capacity_available_locked(node) &&
        !p2p_node_find_peer_by_endpoint_locked(node, ip, port)) {
        p2p_node_add_peer_locked(node, accepted_peer);
    }
    peer_tracked = p2p_node_find_peer_by_endpoint_locked(node, ip, port) == accepted_peer;
    turbo_mutex_unlock(&node->mutex);

    if (!peer_tracked) {
        turbo_stream_set_user_data(client, NULL);
        p2p_peer_destroy(accepted_peer);
        return;
    }

    p2p_node_on_peer_connected(node, accepted_peer);
}

CXX_C_API int p2p_node_start_server(p2p_node_t *node) {
    struct sockaddr_storage addr;
    turbo_stream_kind_t kind;

    if (!node || node->server) return P2P_ERR_INVALID_ARG;

    if (node_build_sockaddr(node->ip, node->port, &addr) != 0) {
        return P2P_ERR_INVALID_ARG;
    }

    kind = (addr.ss_family == AF_INET6) ? TURBO_STREAM_TCP6 : TURBO_STREAM_TCP4;
    node->server = turbo_stream_listen(node->ctx, kind,
                                       (struct sockaddr *)&addr, 128,
                                       node_server_accept_cb);
    if (!node->server) {
        TLOG_ERROR("[P2P] Failed to listen on {}:{}", node->ip, node->port);
        return P2P_ERR_NETWORK;
    }
    turbo_stream_listener_set_user_data(node->server, node);

    TLOG_INFO("[P2P] Node listening on {}:{}", node->ip, node->port);

    /* Start Maintenance Timer (Gossip/Refresh) */
    node->gossip_timer = turbo_timer_create(p2p_get_loop(node));
    if (node->gossip_timer) {
        turbo_timer_set_data(node->gossip_timer, node);
        turbo_timer_start(node->gossip_timer, node_maintenance_cb, 
                          P2P_GOSSIP_INTERVAL, P2P_GOSSIP_INTERVAL);
    }

    return P2P_OK;
}

void p2p_node_stop_server(p2p_node_t *node) {
    if (!node) return;

    if (node->gossip_timer) {
        turbo_timer_stop(node->gossip_timer);
        turbo_timer_destroy(node->gossip_timer);
        node->gossip_timer = NULL;
    }

    if (!node->server) return;
    turbo_stream_listener_close(node->server);
    node->server = NULL;
}

void p2p_gossip_start(p2p_node_t *node) {
    if (!node) return;

    /* Professional Kademlia uses bucket refreshes instead of gossip.
     * We occasionally lookup our own ID to refresh buckets. */
    p2p_dht_lookup_start(node, node->id, P2P_MSG_DHT_FIND_NODE);
}

void node_maintenance_cb(turbo_timer_t *timer) {
    p2p_node_t *node = (p2p_node_t *)turbo_timer_get_data(timer);
    p2p_peer_t *expired_peer = NULL;
    p2p_peer_t **peers = NULL;
    size_t peer_count = 0;
    uint64_t now = 0;
    if (!node) return;

    turbo_mutex_lock(&node->mutex);
    TLOG_DEBUG("[P2P] Periodic maintenance starting");
    turbo_mutex_unlock(&node->mutex);

    /* 1. DHT Refresh */
    p2p_gossip_start(node);

    now = turbo_hrtime() / 1000000;
    for (;;) {
        turbo_mutex_lock(&node->mutex);
        expired_peer = node_take_expired_pending_peer_locked(node, now);
        turbo_mutex_unlock(&node->mutex);

        if (!expired_peer) {
            break;
        }

        TLOG_DEBUG("[P2P] Expiring unauthenticated peer {}:{}",
                   expired_peer->ip, expired_peer->port);
        p2p_peer_destroy(expired_peer);
    }

    /* 2. Probe healthy authenticated streams and prune stale peers. The
     * snapshot owns temporary holds so socket I/O never runs under node->mutex. */
    peers = p2p_node_snapshot_connected_peers(node, &peer_count);
    for (size_t i = 0; i < peer_count; i++) {
        p2p_peer_t *peer = peers[i];
        uint64_t last_seen_ms = 0;
        int stale = 0;
        int probe_due = 0;
        p2p_peer_info_ex_t peer_info = {0};

        if (!peer) {
            continue;
        }

        turbo_mutex_lock(&node->mutex);
        last_seen_ms = peer->last_seen / 1000000U;
        stale = now >= last_seen_ms &&
                now - last_seen_ms > P2P_PEER_TIMEOUT_MS;
        probe_due = !stale && peer->state == P2P_PEER_STATE_CONNECTED &&
                    p2p_crypto_session_is_ready(&peer->crypto) &&
                    peer->outstanding_ping_ms == 0 &&
                    (peer->last_ping_sent_ms == 0 ||
                     (now >= peer->last_ping_sent_ms &&
                      now - peer->last_ping_sent_ms >= P2P_RTT_PROBE_INTERVAL_MS));
        if (stale) {
            p2p_peer_fill_info_ex_locked(peer, &peer_info);
        }
        turbo_mutex_unlock(&node->mutex);

        if (stale) {
            TLOG_INFO("[P2P] Pruning stale peer {}:{}", peer_info.ip, peer_info.port);
            p2p_peer_disconnect(peer);
        } else if (probe_due) {
            (void)node_send_identity_ping(node, peer);
        }
        p2p_peer_release(peer);
    }
    free(peers);
}

static p2p_peer_t *node_take_expired_pending_peer_locked(p2p_node_t *node,
                                                         uint64_t now_ms) {
    p2p_peer_entry_t *curr = NULL;
    p2p_peer_entry_t *tmp = NULL;

    if (!node) {
        return NULL;
    }

    HASH_ITER(hh, node->peers_table, curr, tmp) {
        p2p_peer_t *peer = curr->peer;
        uint64_t connected_at_ms = 0;

        if (!peer || peer->is_connected ||
            peer->state != P2P_PEER_STATE_HANDSHAKING || peer->connect_time == 0) {
            continue;
        }

        connected_at_ms = peer->connect_time / 1000000;
        if (now_ms < connected_at_ms ||
            now_ms - connected_at_ms <= P2P_PEER_TIMEOUT_MS) {
            continue;
        }

        node_remove_peer_entry_locked(node, peer);
        return peer;
    }

    return NULL;
}

/* =============================================================================
 * Pub/Sub operations
 * ============================================================================= */

static p2p_topic_t *node_find_topic_locked(p2p_node_t *node, const char *name) {
    p2p_topic_t *curr = NULL;

    if (!node || !name) {
        return NULL;
    }

    curr = node->topics;
    while (curr) {
        if (strcmp(curr->name, name) == 0) {
            return curr;
        }
        curr = curr->next_topic;
    }

    return NULL;
}

static p2p_topic_t *node_find_or_create_topic_locked(p2p_node_t *node, const char *name) {
    p2p_topic_t *topic = NULL;

    if (!node || !name) {
        return NULL;
    }

    topic = node_find_topic_locked(node, name);
    if (topic) {
        return topic;
    }

    topic = (p2p_topic_t *)calloc(1, sizeof(p2p_topic_t));
    if (!topic) {
        return NULL;
    }

    strncpy(topic->name, name, sizeof(topic->name) - 1);
    topic->next_topic = node->topics;
    node->topics = topic;

    return topic;
}

void p2p_topic_destroy(p2p_topic_t *topic) {
    if (!topic) return;
    if (topic->subscribers) free(topic->subscribers);
    free(topic);
}

p2p_topic_t *p2p_topic_find(p2p_node_t *node, const char *name) {
    p2p_topic_t *topic = NULL;

    if (!node || !name) return NULL;

    turbo_mutex_lock(&node->mutex);
    topic = node_find_topic_locked(node, name);
    turbo_mutex_unlock(&node->mutex);

    return topic;
}

p2p_topic_t *p2p_topic_find_or_create(p2p_node_t *node, const char *name) {
    p2p_topic_t *topic = NULL;

    if (!node || !name) return NULL;

    turbo_mutex_lock(&node->mutex);
    topic = node_find_or_create_topic_locked(node, name);
    turbo_mutex_unlock(&node->mutex);

    return topic;
}

int p2p_topic_exists(p2p_node_t *node, const char *name) {
    int exists = 0;

    if (!node || !name) {
        return 0;
    }

    turbo_mutex_lock(&node->mutex);
    exists = node_find_topic_locked(node, name) != NULL;
    turbo_mutex_unlock(&node->mutex);

    return exists;
}

int p2p_node_remove_topic(p2p_node_t *node, const char *name) {
    if (!node || !name) return P2P_ERR_INVALID_ARG;

    turbo_mutex_lock(&node->mutex);
    p2p_topic_t **curr = &node->topics;
    while (*curr) {
        if (strcmp((*curr)->name, name) == 0) {
            p2p_topic_t *to_remove = *curr;
            *curr = (*curr)->next_topic;
            turbo_mutex_unlock(&node->mutex);
            p2p_topic_destroy(to_remove);
            return P2P_OK;
        }
        curr = &(*curr)->next_topic;
    }
    turbo_mutex_unlock(&node->mutex);
    return P2P_ERR_NOT_FOUND;
}

p2p_topic_t *p2p_node_detach_topics(p2p_node_t *node) {
    p2p_topic_t *topics = NULL;

    if (!node) {
        return NULL;
    }

    turbo_mutex_lock(&node->mutex);
    topics = node->topics;
    node->topics = NULL;
    turbo_mutex_unlock(&node->mutex);

    return topics;
}
