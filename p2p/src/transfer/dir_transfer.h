/**
 * P2P Directory Transfer (Stub)
 */
#ifndef P2P_DIR_TRANSFER_H
#define P2P_DIR_TRANSFER_H

#include "../core/types.h"

/* Stub handlers - not implemented yet */
static inline int p2p_dir_sender_handle_request(p2p_node_t *node, p2p_peer_t *peer,
                                                 const p2p_id_t dir_id, const char *dir_name) {
    (void)node; (void)peer; (void)dir_id; (void)dir_name;
    return P2P_OK;
}

static inline int p2p_dir_receiver_handle_response(p2p_node_t *node, p2p_peer_t *peer,
                                                    uint32_t transfer_id, uint32_t file_count,
                                                    uint64_t total_size, const uint8_t *manifest,
                                                    size_t manifest_len) {
    (void)node; (void)peer; (void)transfer_id; (void)file_count;
    (void)total_size; (void)manifest; (void)manifest_len;
    return P2P_OK;
}

static inline int p2p_dir_receiver_handle_file_start(p2p_node_t *node, p2p_peer_t *peer,
                                                      uint32_t dir_transfer_id, uint32_t file_transfer_id,
                                                      uint32_t file_index, const char *relative_path,
                                                      uint64_t file_size, const uint8_t *file_hash) {
    (void)node; (void)peer; (void)dir_transfer_id; (void)file_transfer_id;
    (void)file_index; (void)relative_path; (void)file_size; (void)file_hash;
    return P2P_OK;
}

static inline int p2p_dir_receiver_handle_complete(p2p_node_t *node, p2p_peer_t *peer,
                                                    uint32_t transfer_id, int success,
                                                    uint32_t files_transferred) {
    (void)node; (void)peer; (void)transfer_id; (void)success; (void)files_transferred;
    return P2P_OK;
}

#endif /* P2P_DIR_TRANSFER_H */
