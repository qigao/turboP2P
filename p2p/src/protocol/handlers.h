/**
 * handlers.h - Professional Protocol Handlers
 */

#ifndef P2P_HANDLERS_H
#define P2P_HANDLERS_H

#include "../src/internal.h"

/* Dispatch incoming messages */
void p2p_handlers_dispatch(p2p_node_t *node, p2p_peer_t *peer, const p2p_message_t *msg);

/* Core Handlers */
int p2p_handle_ping(p2p_node_t *node, p2p_peer_t *peer, const p2p_message_t *msg);
int p2p_handle_pong(p2p_node_t *node, p2p_peer_t *peer, const p2p_message_t *msg);

/* DHT Handlers */
int p2p_handle_dht_find_node(p2p_node_t *node, p2p_peer_t *peer, const p2p_message_t *msg);
int p2p_handle_dht_store(p2p_node_t *node, p2p_peer_t *peer, const p2p_message_t *msg);
int p2p_handle_dht_get(p2p_node_t *node, p2p_peer_t *peer, const p2p_message_t *msg);
int p2p_handle_dht_response(p2p_node_t *node, p2p_peer_t *peer, const p2p_message_t *msg);

#endif
