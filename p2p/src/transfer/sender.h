/**
 * P2P File Transfer - Sender
 */
#ifndef P2P_SENDER_H
#define P2P_SENDER_H

#include "../core/types.h"

/**
 * Handle FILE_REQUEST - start sending a file
 */
int p2p_sender_handle_file_request(p2p_node_t *node, p2p_peer_t *peer,
                                    const p2p_id_t file_id, uint32_t chunk_size,
                                    uint32_t request_id);

/**
 * Handle CHUNK_REQUEST - send a specific chunk
 */
int p2p_sender_handle_chunk_request(p2p_node_t *node, p2p_peer_t *peer,
                                     uint32_t transfer_id, uint32_t chunk_index,
                                     uint32_t request_id);

/**
 * Handle FILE_ACK - finish and release the peer-scoped upload
 */
int p2p_sender_handle_file_ack(p2p_node_t *node, p2p_peer_t *peer,
                               uint32_t transfer_id, int success);

#endif /* P2P_SENDER_H */
