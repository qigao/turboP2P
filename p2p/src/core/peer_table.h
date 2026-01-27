/**
 * peer_table.h - Hash table for O(1) peer lookups
 * Uses uthash for professional implementation
 */

#ifndef P2P_PEER_TABLE_H
#define P2P_PEER_TABLE_H

#include "uthash.h"
#include "../../include/p2p_types.h"

/* Peer with hash table support */
typedef struct p2p_peer_entry_s {
    char key[64];  /* "ip:port" */
    p2p_peer_t *peer;
    UT_hash_handle hh;
} p2p_peer_entry_t;

/* Peer table operations */
p2p_peer_entry_t *peer_table_find(p2p_peer_entry_t *table, const char *ip, int port);
void peer_table_add(p2p_peer_entry_t **table, p2p_peer_t *peer);
void peer_table_remove(p2p_peer_entry_t **table, const char *ip, int port);
void peer_table_destroy(p2p_peer_entry_t **table);
int peer_table_count(p2p_peer_entry_t *table);

#endif /* P2P_PEER_TABLE_H */
