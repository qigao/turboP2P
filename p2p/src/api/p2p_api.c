/**
 * p2p_api.c - P2P Public API implementation
 * Implements the professional interface defined in p2p.h
 */

#include "p2p.h"
#include "../internal.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* =============================================================================
 * Node Lifecycle
 * ============================================================================= */

p2p_node_t *p2p_create(const char *ip, int port) {
    if (!ip) return NULL;

    p2p_node_t *node = (p2p_node_t *)calloc(1, sizeof(p2p_node_t));
    if (!node) return NULL;

    strncpy(node->ip, ip, sizeof(node->ip) - 1);
    node->port = port;

    /* Initialize Peer Table */
    node->peers_table = NULL;
    node->peer_count = 0;

    /* Initialize Kademlia DHT */
    node->kad_dht = kademlia_create(ip, (uint16_t)port);
    if (!node->kad_dht) {
        free(node);
        return NULL;
    }

    /* Initialize node mutex */
    turbo_mutex_init(&node->mutex);

    return node;
}

void p2p_destroy(p2p_node_t *node) {
    if (!node) return;
    
    /* Use professional cleanup orchestration */
    p2p_destroy_clean(node);
}

int p2p_start(p2p_node_t *node) {
    if (!node) return P2P_ERR_INVALID_ARG;
    
    turbo_mutex_lock(&node->mutex);
    
    /* Start server */
    int ret = p2p_node_start_server(node);
    if (ret != P2P_OK) {
        turbo_mutex_unlock(&node->mutex);
        return ret;
    }

    /* Gossip start */
    p2p_gossip_start(node);
    
    turbo_mutex_unlock(&node->mutex);

    /* Event loop blocking run */
    uv_run(uv_default_loop(), UV_RUN_DEFAULT);

    return P2P_OK;
}

int p2p_start_nonblocking(p2p_node_t *node) {
    if (!node) return P2P_ERR_INVALID_ARG;
    
    turbo_mutex_lock(&node->mutex);

    /* Start server */
    int ret = p2p_node_start_server(node);
    if (ret != P2P_OK) {
        turbo_mutex_unlock(&node->mutex);
        return ret;
    }

    p2p_gossip_start(node);
    
    turbo_mutex_unlock(&node->mutex);
    return P2P_OK;
}

struct uv_loop_s *p2p_get_loop(p2p_node_t *node) {
    (void)node;
    return (struct uv_loop_s *)uv_default_loop();
}

int p2p_connect(p2p_node_t *node, const char *ip, int port) {
    if (!node || !ip) return P2P_ERR_INVALID_ARG;

    /* Use hash table for O(1) existence check */
    turbo_mutex_lock(&node->mutex);
    if (peer_table_find(node->peers_table, ip, port)) {
        turbo_mutex_unlock(&node->mutex);
        return P2P_OK;
    }
    turbo_mutex_unlock(&node->mutex);

    p2p_peer_t *peer = p2p_peer_create(node, ip, port);
    if (!peer) return P2P_ERR_NO_MEM;

    int ret = p2p_peer_connect(peer);
    if (ret != P2P_OK) {
        p2p_peer_destroy(peer);
        return ret;
    }

    /* Add to hash table */
    turbo_mutex_lock(&node->mutex);
    peer_table_add(&node->peers_table, peer);
    turbo_mutex_unlock(&node->mutex);
    
    /* Add to Kademlia routing table */
    kad_id_t peer_id;
    char id_buf[64];
    snprintf(id_buf, sizeof(id_buf), "%s:%d", ip, port);
    kad_id_from_data(id_buf, strlen(id_buf), &peer_id);
    
    kad_node_t knode;
    memcpy(&knode.id, &peer_id, sizeof(kad_id_t));
    strncpy(knode.ip, ip, sizeof(knode.ip) - 1);
    knode.port = (uint16_t)port;
    
    kad_routing_add_node(node->kad_dht->routing, &knode);

    return P2P_OK;
}

/* =============================================================================
 * Message Handlers
 * ============================================================================= */

void p2p_set_message_handler(p2p_node_t *node, p2p_on_message_fn fn, void *user_data) {
    if (!node) return;
    node->on_message = fn;
    node->user_data = user_data;
}

void p2p_set_peer_callbacks(p2p_node_t *node,
                             void (*on_connected)(p2p_peer_t *peer, void *user_data),
                             void (*on_disconnected)(p2p_peer_t *peer, void *user_data),
                             void *user_data) {
    if (!node) return;
    node->on_peer_connected = on_connected;
    node->on_peer_disconnected = on_disconnected;
    node->peer_user_data = user_data;
}

int p2p_send(p2p_node_t *node, p2p_peer_t *peer, const void *data, size_t len) {
    return p2p_send_message(node, peer, P2P_MSG_CUSTOM, data, len);
}

int p2p_broadcast(p2p_node_t *node, const void *data, size_t len) {
    return p2p_send(node, NULL, data, len);
}

/* =============================================================================
 * DHT Operations
 * ============================================================================= */

int p2p_dht_put(p2p_node_t *node, const char *key, const void *data, size_t len) {
    if (!node || !key || !data) return P2P_ERR_INVALID_ARG;

    turbo_mutex_lock(&node->mutex);
    kad_id_t kkey;
    kad_id_from_data(key, strlen(key), &kkey);
    
    /* Store locally first */
    kademlia_store(node->kad_dht, &kkey, data, len);

    /* Professional Kademlia: 
     * 1. Start iterative FIND_NODE for the key
     * 2. When closest nodes are found, send P2P_MSG_DHT_PUT to them.
     */
    
    /* For now, just start iterative lookup for the neighborhood */
    int ret = p2p_dht_lookup_start(node, kkey.bytes, P2P_MSG_DHT_FIND_NODE);
    turbo_mutex_unlock(&node->mutex);
    return ret;
}

int p2p_dht_get(p2p_node_t *node, const char *key, void *buf, size_t *buf_len) {
    if (!node || !key || !buf || !buf_len) return P2P_ERR_INVALID_ARG;

    turbo_mutex_lock(&node->mutex);
    kad_id_t kkey;
    kad_id_from_data(key, strlen(key), &kkey);

    /* Try local first */
    if (kademlia_find_value(node->kad_dht, &kkey, buf, buf_len) == 0) {
        turbo_mutex_unlock(&node->mutex);
        return P2P_OK;
    }

    /* Professional Kademlia: 
     * 1. Start iterative FIND_VALUE for the key
     * 2. This will return either the value or closer nodes.
     */
    int ret = p2p_dht_lookup_start(node, kkey.bytes, P2P_MSG_DHT_GET);
    turbo_mutex_unlock(&node->mutex);
    return ret;
}

/* =============================================================================
 * Peer Information
 * ============================================================================= */

int p2p_get_peer_count(p2p_node_t *node) {
    if (!node) return 0;
    turbo_mutex_lock(&node->mutex);
    int count = peer_table_count(node->peers_table);
    turbo_mutex_unlock(&node->mutex);
    return count;
}

int p2p_get_peer_info(p2p_node_t *node, int index, p2p_peer_info_t *info) {
    if (!node || !info || index < 0) return P2P_ERR_INVALID_ARG;

    int i = 0;
    p2p_peer_entry_t *curr, *tmp;
    turbo_mutex_lock(&node->mutex);
    HASH_ITER(hh, node->peers_table, curr, tmp) {
        if (i == index) {
            strncpy(info->ip, curr->peer->ip, sizeof(info->ip) - 1);
            info->port = curr->peer->port;
            info->is_connected = curr->peer->is_connected;
            turbo_mutex_unlock(&node->mutex);
            return P2P_OK;
        }
        i++;
    }
    turbo_mutex_unlock(&node->mutex);

    return P2P_ERR_NOT_FOUND;
}

/* =============================================================================
 * File Sharing implementation
 * ============================================================================= */

int p2p_put_file(p2p_node_t *node, const char *filepath, char key_out[65]) {
    if (!node || !filepath) return P2P_ERR_INVALID_ARG;

    /* Check if file exists */
    FILE *f = fopen(filepath, "rb");
    if (!f) return P2P_ERR_IO;
    fclose(f);

    p2p_file_t *file = p2p_file_create(filepath, filepath); /* filename=path for now */
    if (!file) return P2P_ERR_IO;

    file->is_local = 1;
    p2p_node_add_file(node, file);

    /* Use Kademlia to announce the file */
    /* Implementation in file_network.c / file.c handles the announcement */
    p2p_file_announce(node, file);

    strncpy(key_out, file->hash, 64);
    key_out[64] = '\0';

    return P2P_OK;
}

int p2p_get_file(p2p_node_t *node, const char key[65], const char *output_path) {
    if (!node || !key || !output_path) return P2P_ERR_INVALID_ARG;

    /* 1. Search DHT for the file metadata */
    /* 2. Start transfer */
    /* This is complex to implement in one sync call. For now, stub iterative lookup. */
    kad_id_t file_id;
    kad_id_from_data(key, strlen(key), &file_id);
    
    return p2p_dht_lookup_start(node, file_id.bytes, P2P_MSG_DHT_GET);
}

/* =============================================================================
 * Pub/Sub implementation
 * ============================================================================= */

int p2p_subscribe(p2p_node_t *node, const char *topic) {
    if (!node || !topic) return P2P_ERR_INVALID_ARG;
    
    turbo_mutex_lock(&node->mutex);
    if (!p2p_topic_find_or_create(node, topic)) {
        turbo_mutex_unlock(&node->mutex);
        return P2P_ERR_NO_MEM;
    }

    p2p_message_t *msg = (p2p_message_t *)calloc(1, sizeof(p2p_message_t));
    if (!msg) {
        turbo_mutex_unlock(&node->mutex);
        return P2P_ERR_NO_MEM;
    }

    p2p_message_init(msg, P2P_MSG_PUBSUB_SUB);
    /* Payload setup would go here */
    p2p_node_broadcast(node, msg);
    free(msg);
    turbo_mutex_unlock(&node->mutex);
    return P2P_OK;
}

int p2p_unsubscribe(p2p_node_t *node, const char *topic) {
    if (!node || !topic) return P2P_ERR_INVALID_ARG;
    
    turbo_mutex_lock(&node->mutex);
    int ret = p2p_node_remove_topic(node, topic);
    if (ret != P2P_OK) {
        turbo_mutex_unlock(&node->mutex);
        return ret;
    }

    p2p_message_t *msg = (p2p_message_t *)calloc(1, sizeof(p2p_message_t));
    if (!msg) {
        turbo_mutex_unlock(&node->mutex);
        return P2P_ERR_NO_MEM;
    }

    p2p_message_init(msg, P2P_MSG_PUBSUB_UNSUB);
    p2p_node_broadcast(node, msg);
    free(msg);
    turbo_mutex_unlock(&node->mutex);
    return P2P_OK;
}

int p2p_publish(p2p_node_t *node, const char *topic, const void *data, size_t len) {
    if (!node || !topic || !data || len == 0) return P2P_ERR_INVALID;
    
    turbo_mutex_lock(&node->mutex);
    if (!p2p_topic_find(node, topic)) {
        turbo_mutex_unlock(&node->mutex);
        return P2P_ERR_NOT_FOUND;
    }

    p2p_message_t *msg = (p2p_message_t *)calloc(1, sizeof(p2p_message_t));
    if (!msg) {
        turbo_mutex_unlock(&node->mutex);
        return P2P_ERR_NO_MEM;
    }

    p2p_message_init(msg, P2P_MSG_PUBSUB_PUBLISH);
    p2p_node_broadcast(node, msg);
    free(msg);
    turbo_mutex_unlock(&node->mutex);
    return P2P_OK;
}

/* =============================================================================
 * Utility implementation
 * ============================================================================= */

int p2p_peer_get_address(p2p_peer_t *peer, char *ip_out, int *port_out) {
    if (!peer || !ip_out || !port_out) return P2P_ERR_INVALID_ARG;
    strncpy(ip_out, peer->ip, P2P_MAX_IP - 1);
    *port_out = peer->port;
    return P2P_OK;
}

int p2p_send_message(p2p_node_t *node, p2p_peer_t *peer, p2p_msg_type_t type,
                               const void *payload, size_t len) {
    if (!node) return P2P_ERR_INVALID_ARG;
    p2p_message_t *msg = (p2p_message_t *)calloc(1, sizeof(p2p_message_t));
    if (!msg) return P2P_ERR_NO_MEM;

    p2p_message_init(msg, type);
    if (len > 0) {
        size_t max_payload = sizeof(msg->payload.raw);
        size_t to_copy = (len < max_payload) ? len : max_payload;
        memcpy(msg->payload.raw, payload, to_copy);
        msg->header.payload_len = (uint16_t)to_copy;
    }

    if (peer) {
        int ret = p2p_peer_send(peer, msg);
        free(msg);
        return ret;
    }

    /* Broadcast */
    turbo_mutex_lock(&node->mutex);
    p2p_node_broadcast(node, msg);
    turbo_mutex_unlock(&node->mutex);
    free(msg);
    return P2P_OK;
}

const char *p2p_error_str(int error) {
    switch (error) {
        case P2P_OK: return "Success";
        case P2P_ERR_INVALID_ARG: return "Invalid argument";
        case P2P_ERR_NO_MEM: return "Out of memory";
        case P2P_ERR_NETWORK: return "Network error";
        case P2P_ERR_TIMEOUT: return "Timeout";
        case P2P_ERR_NOT_FOUND: return "Not found";
        case P2P_ERR_IO: return "I/O error";
        case P2P_ERR_INVALID: return "Invalid argument";
        default: return "Unknown error";
    }
}
