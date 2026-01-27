/**
 * P2P Peer Management
 *
 * Handles peer connections, I/O, and handshake protocol.
 */
#ifndef P2P_PEER_H
#define P2P_PEER_H

#include "types.h"
#include <stdbool.h>

/**
 * Get string representation of peer state
 */
const char* p2p_peer_state_str(p2p_peer_state_t state);

/**
 * Create a new peer instance
 */
p2p_peer_t* p2p_peer_create(p2p_node_t *node, const char *ip, int port);

/**
 * Destroy peer and free resources
 */
void p2p_peer_destroy(p2p_peer_t *peer);

/**
 * Initiate outbound connection to peer
 */
int p2p_peer_connect(p2p_peer_t *peer);

/**
 * Disconnect and close peer connection
 */
void p2p_peer_disconnect(p2p_peer_t *peer);

/**
 * Send a message to the peer
 * Handles encryption if crypto session is established
 */
int p2p_peer_send(p2p_peer_t *peer, const p2p_message_t *msg);

/**
 * Handle incoming data from peer
 * Parses frames and dispatches messages
 */
int p2p_peer_on_data(p2p_peer_t *peer, const void *data, size_t len);

/**
 * Set peer's node ID
 */
void p2p_peer_set_id(p2p_peer_t *peer, const p2p_id_t id);

/**
 * Check if peer is connected
 */
bool p2p_peer_is_connected(const p2p_peer_t *peer);

/**
 * Compare peer address with given ip:port
 */
bool p2p_peer_addr_equals(const p2p_peer_t *peer, const char *ip, int port);

/**
 * Compare two peers by their node IDs
 */
int p2p_peer_id_cmp(const p2p_peer_t *a, const p2p_peer_t *b);

/**
 * Start Noise XX handshake as initiator
 */
int p2p_peer_start_handshake(p2p_peer_t *peer);

/**
 * Handle incoming handshake message
 */
int p2p_peer_handle_handshake(p2p_peer_t *peer, const p2p_message_t *msg);

#endif /* P2P_PEER_H */
