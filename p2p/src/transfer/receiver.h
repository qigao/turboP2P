/**
 * P2P File Transfer - Receiver
 */
#ifndef P2P_RECEIVER_H
#define P2P_RECEIVER_H

#include "../core/types.h"

/* Forward declare transfer type */
typedef struct p2p_transfer_s p2p_transfer_t;

/**
 * Request a specific chunk from peer
 */
int p2p_receiver_request_chunk(p2p_node_t *node, p2p_transfer_t *transfer, uint32_t chunk_index);

/**
 * Handle FILE_RESPONSE - file metadata received
 */
int p2p_receiver_handle_file_response(p2p_node_t *node, p2p_peer_t *peer,
                                       uint32_t request_id, uint64_t file_size,
                                       uint32_t total_chunks, const uint8_t *file_hash);

/**
 * Handle CHUNK_DATA - received chunk data
 */
int p2p_receiver_handle_chunk_data(p2p_node_t *node, p2p_peer_t *peer,
                                    uint32_t transfer_id, uint32_t chunk_index,
                                    const uint8_t *chunk_hash, const uint8_t *data,
                                    size_t data_len, int is_last);

#endif /* P2P_RECEIVER_H */
