/**
 * peer_table.c - O(1) peer lookup implementation
 * Uses uthash for professional hash table
 */

#include "peer_table.h"
#include "../internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* =============================================================================
 * Peer Table Operations
 * ============================================================================= */

p2p_peer_entry_t *peer_table_find(p2p_peer_entry_t *table, const char *ip, int port) {
    if (!table || !ip) return NULL;
    
    char key[64];
    p2p_endpoint_to_key(key, sizeof(key), ip, port);
    
    p2p_peer_entry_t *entry = NULL;
    HASH_FIND_STR(table, key, entry);
    return entry;
}

void peer_table_add(p2p_peer_entry_t **table, p2p_peer_t *peer) {
    if (!table || !peer) return;
    
    /* Check if already exists */
    char entry_key[64];
    p2p_endpoint_to_key(entry_key, sizeof(entry_key), peer->ip, peer->port);
    
    p2p_peer_entry_t *existing = NULL;
    HASH_FIND_STR(*table, entry_key, existing);
    if (existing) {
        return;
    }
    
    /* Create new entry */
    p2p_peer_entry_t *entry = (p2p_peer_entry_t *)malloc(sizeof(p2p_peer_entry_t));
    if (!entry) return;
    
    strncpy(entry->key, entry_key, sizeof(entry->key) - 1);
    entry->key[sizeof(entry->key) - 1] = '\0';
    entry->peer = peer;
    
    HASH_ADD_STR(*table, key, entry);
}

void peer_table_remove(p2p_peer_entry_t **table, const char *ip, int port) {
    if (!table || !*table || !ip) return;
    
    char key[64];
    p2p_endpoint_to_key(key, sizeof(key), ip, port);
    
    p2p_peer_entry_t *entry = NULL;
    HASH_FIND_STR(*table, key, entry);
    if (entry) {
        HASH_DEL(*table, entry);
        free(entry);
    }
}

void peer_table_destroy(p2p_peer_entry_t **table) {
    if (!table || !*table) return;
    
    p2p_peer_entry_t *entry, *tmp;
    HASH_ITER(hh, *table, entry, tmp) {
        HASH_DEL(*table, entry);
        /* Note: We don't free peer here - that's managed separately */
        free(entry);
    }
    
    *table = NULL;
}

int peer_table_count(p2p_peer_entry_t *table) {
    return HASH_COUNT(table);
}

CXX_C_API p2p_peer_t* p2p_peer_find(p2p_node_t *node, const char *ip, int port) {
    if (!node || !ip) return NULL;
    turbo_mutex_lock(&node->mutex);
    p2p_peer_entry_t *entry = peer_table_find(node->peers_table, ip, port);
    p2p_peer_t *peer = entry ? entry->peer : NULL;
    turbo_mutex_unlock(&node->mutex);
    return peer;
}
