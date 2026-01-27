/**
 * node.c - P2P Node Management implementation
 * Professional version based on Kademlia DHT and unified connection
 */

#include "node.h"
#include "peer.h"
#include "../internal.h"
#include <turbo_async_server.h>
#include <tlog.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Forward declarations */
void node_maintenance_cb(turbo_timer_t *timer);

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

    /* Initialize node mutex */
    turbo_mutex_init(&node->mutex);

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

/* =============================================================================
 * Network Operations
 * ============================================================================= */

void p2p_node_broadcast(p2p_node_t *node, p2p_message_t *msg) {
    if (!node || !msg) return;

    p2p_peer_entry_t *curr, *tmp;
    /* Note: Caller must hold node->mutex */
    HASH_ITER(hh, node->peers_table, curr, tmp) {
        if (curr->peer && curr->peer->is_connected) {
            p2p_peer_send(curr->peer, msg);
        }
    }
}

/* =============================================================================
 * DHT Integration
 * ============================================================================= */

int p2p_dht_join_ring(p2p_node_t *node, const char *bootstrap_ip, int bootstrap_port) {
    if (!node || !bootstrap_ip) return P2P_ERR_INVALID_ARG;

    /* Professional Kademlia doesn't have a "ring", it has k-buckets.
     * Joining means contacting the bootstrap node to populate buckets. */
    
    /* Create a permanent peer for boostrap */
    p2p_peer_t *peer = p2p_peer_create(node, bootstrap_ip, bootstrap_port);
    if (!peer) return P2P_ERR_NO_MEM;

    int ret = p2p_peer_connect(peer);
    if (ret != P2P_OK) {
        p2p_peer_destroy(peer);
        return ret;
    }

    /* Add to peer table and routing table */
    turbo_mutex_lock(&node->mutex);
    peer_table_add(&node->peers_table, peer);
    turbo_mutex_unlock(&node->mutex);
    
    kad_node_t knode;
    kad_id_random(&knode.id); /* Identity logic will improve later */
    strncpy(knode.ip, bootstrap_ip, sizeof(knode.ip) - 1);
    knode.port = (uint16_t)bootstrap_port;
    
    turbo_mutex_lock(&node->mutex);
    kad_routing_add_node(node->kad_dht->routing, &knode);

    /* Start iterative lookup for OUR identity to discover our neighborhood */
    p2p_dht_lookup_start(node, node->id, P2P_MSG_DHT_FIND_NODE);
    turbo_mutex_unlock(&node->mutex);

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

    /* Start handshake if encryption is enabled */
    if (node->encryption_enabled) {
        p2p_peer_start_handshake(peer);
    } else {
        /* If no encryption, consider it authenticated immediately */
        p2p_node_on_peer_authenticated(node, peer);
    }
}

void p2p_node_on_peer_disconnected(p2p_node_t *node, p2p_peer_t *peer) {
    if (!node || !peer) return;

    /* Remove from peer table if it's there */
    if (node->peers_table) {
        peer_table_remove(&node->peers_table, peer->ip, peer->port);
        node->peer_count--;
    }

    /* Notify user via callback */
    if (node->on_peer_disconnected) {
        turbo_mutex_unlock(&node->mutex);
        node->on_peer_disconnected(peer, node->peer_user_data);
        turbo_mutex_lock(&node->mutex);
    }
}

void p2p_node_on_peer_authenticated(p2p_node_t *node, p2p_peer_t *peer) {
    if (!node || !peer) return;

    peer->state = P2P_PEER_STATE_CONNECTED;

    /* Add to peer table if not already present */
    if (!peer_table_find(node->peers_table, peer->ip, peer->port)) {
        peer_table_add(&node->peers_table, peer);
        node->peer_count++;
    }

    /* Notify user via callback */
    if (node->on_peer_connected) {
        turbo_mutex_unlock(&node->mutex);
        node->on_peer_connected(peer, node->peer_user_data);
        turbo_mutex_lock(&node->mutex);
    }
}

void p2p_node_dispatch_message(p2p_node_t *node, p2p_peer_t *peer, p2p_message_t *msg) {
    if (!node || !peer || !msg) return;

    turbo_mutex_lock(&node->mutex);

    /* Handle handshake messages separately if handshaking */
    if (msg->header.type == P2P_MSG_NOISE_HANDSHAKE) {
        p2p_peer_handle_handshake(peer, msg);
        turbo_mutex_unlock(&node->mutex);
        return;
    }

    /* For custom messages, notify user */
    if (msg->header.type == P2P_MSG_CUSTOM) {
        if (node->on_message) {
            turbo_mutex_unlock(&node->mutex);
            node->on_message(node, peer, msg->payload.raw, msg->header.payload_len, node->user_data);
            return; /* Note: already unlocked */
        }
    } else {
        /* Otherwise use standard protocol dispatcher */
        p2p_handlers_dispatch(node, peer, msg);
    }

    turbo_mutex_unlock(&node->mutex);
}

/* =============================================================================
 * Infrastructure implementation
 * ============================================================================= */

static void node_server_event_cb(async_server_t *server,
                                  const async_server_event_t *event,
                                  void *user_data) {
    p2p_node_t *node = (p2p_node_t *)user_data;
    if (!node) return;

    switch (event->type) {
        case ASYNC_SERVER_EVENT_CONNECTION: {
            async_server_connection_info_t info;
            if (async_server_get_connection_info(event->connection, &info) == ASYNC_SERVER_STATUS_OK) {
                p2p_peer_t *peer = p2p_peer_create(node, info.remote_address, info.remote_port);
                if (peer) {
                    peer->conn = p2p_connection_create_inbound(server, event->connection);
                    peer->state = P2P_PEER_STATE_HANDSHAKING;
                    peer->is_connected = 1;
                    async_server_connection_set_user_data(event->connection, peer);
                    
                    turbo_mutex_lock(&node->mutex);
                    p2p_node_on_peer_connected(node, peer);
                    turbo_mutex_unlock(&node->mutex);
                }
            }
            break;
        }
        case ASYNC_SERVER_EVENT_DATA: {
            p2p_peer_t *peer = (p2p_peer_t *)async_server_connection_get_user_data(event->connection);
            if (peer) {
                /* p2p_peer_on_data calls dispatch_message which locks */
                p2p_peer_on_data(peer, event->data, event->length);
            }
            break;
        }
        case ASYNC_SERVER_EVENT_DISCONNECTION: {
            p2p_peer_t *peer = (p2p_peer_t *)async_server_connection_get_user_data(event->connection);
            if (peer) {
                /* Clear user data to prevent re-entry/double-free from callbacks */
                async_server_connection_set_user_data(event->connection, NULL);
                
                turbo_mutex_lock(&node->mutex);
                p2p_node_on_peer_disconnected(node, peer);
                turbo_mutex_unlock(&node->mutex);
                
                p2p_peer_destroy(peer);
            }
            break;
        }
        default: break;
    }
}

CXX_C_API int p2p_node_start_server(p2p_node_t *node) {
    if (!node || node->server) return P2P_ERR_INVALID_ARG;

    node->server = async_server_create(node_server_event_cb, node);
    if (!node->server) return P2P_ERR_NO_MEM;

    char url[128];
    snprintf(url, sizeof(url), "tcp://%s:%d", node->ip, node->port);

    if (async_server_listen(node->server, url, 0) != ASYNC_SERVER_STATUS_OK) {
        TLOG_ERROR("[P2P] Failed to listen on {}", url);
        async_server_destroy(node->server);
        node->server = NULL;
        return P2P_ERR_NETWORK;
    }

    TLOG_INFO("[P2P] Node listening on {}", url);

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
    if (!node || !node->server) return;
    async_server_stop(node->server);
    async_server_destroy(node->server);
    node->server = NULL;
}

void p2p_gossip_start(p2p_node_t *node) {
    if (!node) return;
    
    /* Professional Kademlia uses bucket refreshes instead of gossip.
     * We occasionally looking up our own ID to refresh buckets. */
    /* Note: Expects node->mutex to be held */
    p2p_dht_lookup_start(node, node->id, P2P_MSG_DHT_FIND_NODE);
}

void node_maintenance_cb(turbo_timer_t *timer) {
    p2p_node_t *node = (p2p_node_t *)turbo_timer_get_data(timer);
    if (!node) return;

    turbo_mutex_lock(&node->mutex);
    TLOG_DEBUG("[P2P] Periodic maintenance starting");

    /* 1. DHT Refresh */
    p2p_gossip_start(node);

    /* 2. Peer Pruning (Remove inactive/dead peers) */
    p2p_peer_entry_t *curr, *tmp;
    uint64_t now = turbo_hrtime() / 1000000;
    
    HASH_ITER(hh, node->peers_table, curr, tmp) {
        if (curr->peer && !curr->peer->is_connected) {
            /* Peer was likely disconnected by async_server/client callback */
            continue;
        }

        /* If no activity for 30s, considering pinging or dropping */
        if (curr->peer && (now - (curr->peer->last_seen / 1000000)) > P2P_PEER_TIMEOUT_MS) {
            TLOG_INFO("[P2P] Pruning stale peer %s:%d", curr->peer->ip, curr->peer->port);
            p2p_peer_disconnect(curr->peer);
            /* Note: hash table removal handled by on_peer_disconnected callback */
        }
    }
    turbo_mutex_unlock(&node->mutex);
}

/* =============================================================================
 * Pub/Sub operations
 * ============================================================================= */

void p2p_topic_destroy(p2p_topic_t *topic) {
    if (!topic) return;
    if (topic->subscribers) free(topic->subscribers);
    free(topic);
}

p2p_topic_t *p2p_topic_find(p2p_node_t *node, const char *name) {
    if (!node || !name) return NULL;
    p2p_topic_t *curr = node->topics;
    while (curr) {
        if (strcmp(curr->name, name) == 0) {
            return curr;
        }
        curr = curr->next_topic;
    }
    return NULL;
}

p2p_topic_t *p2p_topic_find_or_create(p2p_node_t *node, const char *name) {
    if (!node || !name) return NULL;
    
    p2p_topic_t *topic = p2p_topic_find(node, name);
    if (topic) return topic;

    topic = (p2p_topic_t *)calloc(1, sizeof(p2p_topic_t));
    if (!topic) return NULL;

    strncpy(topic->name, name, sizeof(topic->name) - 1);
    topic->next_topic = node->topics;
    node->topics = topic;

    return topic;
}

int p2p_node_remove_topic(p2p_node_t *node, const char *name) {
    if (!node || !name) return P2P_ERR_INVALID_ARG;

    p2p_topic_t **curr = &node->topics;
    while (*curr) {
        if (strcmp((*curr)->name, name) == 0) {
            p2p_topic_t *to_remove = *curr;
            *curr = (*curr)->next_topic;
            p2p_topic_destroy(to_remove);
            return P2P_OK;
        }
        curr = &(*curr)->next_topic;
    }
    return P2P_ERR_NOT_FOUND;
}
