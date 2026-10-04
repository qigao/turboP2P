#include "handlers.h"
#include "../transfer/sender.h"
#include "../transfer/receiver.h"
#include "../transfer/transfer.h"
#include <stddef.h>

void p2p_handlers_dispatch_transfer(p2p_node_t *node, p2p_peer_t *peer, const p2p_message_t *msg) {
    if (!node || !msg) return;
    switch (msg->header.type) {
        case P2P_MSG_FILE_GET:
            if (peer && msg->header.payload_len >= P2P_HASH_SIZE) {
                p2p_sender_handle_file_request(
                    node, peer, msg->payload.file_response.file_id,
                    P2P_DEFAULT_CHUNK_SIZE, msg->header.request_id);
            }
            break;
        case P2P_MSG_FILE_PUT:
            if (peer &&
                msg->header.payload_len >= sizeof(p2p_file_response_payload_t)) {
                p2p_receiver_handle_file_response(
                    node, peer, msg->header.request_id,
                    msg->payload.file_response.file_size,
                    msg->payload.file_response.total_chunks,
                    msg->payload.file_response.file_hash);
            }
            break;
        case P2P_MSG_CHUNK_REQUEST:
            if (peer &&
                msg->header.payload_len >= sizeof(p2p_chunk_request_payload_t)) {
                p2p_sender_handle_chunk_request(
                    node, peer, msg->payload.chunk_request.transfer_id,
                    msg->payload.chunk_request.chunk_index,
                    msg->header.request_id);
            }
            break;
        case P2P_MSG_CHUNK_DATA:
            if (peer &&
                msg->header.payload_len >= offsetof(p2p_chunk_data_payload_t, data) &&
                msg->payload.chunk_data.data_len <=
                    sizeof(msg->payload.chunk_data.data) &&
                msg->header.payload_len ==
                    offsetof(p2p_chunk_data_payload_t, data) +
                    msg->payload.chunk_data.data_len) {
                p2p_receiver_handle_chunk_data(
                    node, peer, msg->payload.chunk_data.transfer_id,
                    msg->payload.chunk_data.chunk_index,
                    msg->payload.chunk_data.chunk_hash,
                    msg->payload.chunk_data.data,
                    msg->payload.chunk_data.data_len, 0);
            }
            break;
        case P2P_MSG_FILE_ACK:
            if (peer &&
                msg->header.payload_len >= sizeof(p2p_file_ack_payload_t)) {
                p2p_sender_handle_file_ack(
                    node, peer, msg->payload.file_ack.transfer_id,
                    msg->payload.file_ack.success != 0);
            }
            break;
        default: break;
    }
}
