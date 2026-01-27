/**
 * cleanup.c - Clean node destruction
 * Professional version using HASH_ITER and Kademlia DHT
 */

#include "../internal.h"
#include <stdlib.h>

/* =============================================================================
 * Individual Cleanup Functions
 * ============================================================================= */

void p2p_cleanup_callbacks(p2p_node_t *node) {
    if (!node) return;
    
    /* Clear callbacks to prevent re-entry during cleanup */
    node->on_peer_connected = NULL;
    node->on_peer_disconnected = NULL;
    node->on_message = NULL;
}

void p2p_cleanup_timers(p2p_node_t *node) {
    if (!node) return;
    
    if (node->gossip_timer) {
        turbo_timer_stop(node->gossip_timer);
        turbo_timer_destroy(node->gossip_timer);
        node->gossip_timer = NULL;
    }
}

void p2p_cleanup_peers(p2p_node_t *node) {
    if (!node || !node->peers_table) return;
    
    /* Detach table from node first to prevent re-entry from callbacks */
    turbo_mutex_lock(&node->mutex);
    p2p_peer_entry_t *table = node->peers_table;
    node->peers_table = NULL;
    node->peer_count = 0;
    turbo_mutex_unlock(&node->mutex);
    
    p2p_peer_entry_t *curr, *tmp;
    HASH_ITER(hh, table, curr, tmp) {
        /* Disconnect and free peer through professional lifecycle */
        if (curr->peer) {
            p2p_peer_destroy(curr->peer);
        }
        /* Remove from table entry and free the wrapper */
        HASH_DEL(table, curr);
        free(curr);
    }
}

void p2p_cleanup_server(p2p_node_t *node) {
    if (!node || !node->server) return;
    
    p2p_node_stop_server(node);
}

void p2p_cleanup_topics(p2p_node_t *node) {
    if (!node) return;
    
    turbo_mutex_lock(&node->mutex);
    p2p_topic_t *topic = node->topics;
    node->topics = NULL;
    turbo_mutex_unlock(&node->mutex);

    while (topic) {
        p2p_topic_t *next = topic->next_topic;
        p2p_topic_destroy(topic);
        topic = next;
    }
}

void p2p_cleanup_files(p2p_node_t *node) {
    if (!node) return;
    
    /* 1. Clear DHT files first (some may be local aliases) */
    p2p_file_t *file = node->dht_files;
    while (file) {
        p2p_file_t *next = file->next;
        /* Only free if it's not a local file (local files are freed below) */
        if (!file->is_local) {
            p2p_file_free(file);
        }
        file = next;
    }
    node->dht_files = NULL;

    /* 2. Free all local files */
    file = node->local_files;
    while (file) {
        p2p_file_t *next = file->next_file;
        p2p_file_free(file);
        file = next;
    }
    node->local_files = NULL;
}

void p2p_cleanup_downloads(p2p_node_t *node) {
    if (!node) return;
    
    p2p_download_t *download = node->downloads;
    while (download) {
        p2p_download_t *next = download->next;
        
        if (download->fp) {
            fclose(download->fp);
        }
        
        free(download);
        download = next;
    }
    
    node->downloads = NULL;
}

void p2p_cleanup_dht(p2p_node_t *node) {
    if (!node || !node->kad_dht) return;
    
    /* Professional Kademlia cleanup */
    kademlia_destroy(node->kad_dht);
    node->kad_dht = NULL;
}

/* =============================================================================
 * Main Cleanup Orchestration
 * ============================================================================= */

void p2p_destroy_clean(p2p_node_t *node) {
    if (!node) return;
    
    p2p_cleanup_callbacks(node);
    p2p_cleanup_timers(node);
    p2p_cleanup_server(node);
    p2p_cleanup_peers(node);
    p2p_cleanup_topics(node);
    p2p_cleanup_files(node);
    p2p_cleanup_downloads(node);
    p2p_cleanup_dht(node);
    
    turbo_mutex_destroy(&node->mutex);
    free(node);
}
