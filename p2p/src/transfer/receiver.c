/**
 * P2P File Transfer - Receiver Implementation
 */

#include "receiver.h"
#include "transfer.h"
#include "../protocol/message.h"
#include <tlog.h>
#include <string.h>
#include <stdio.h>

/* =============================================================================
 * Request Chunk
 * ============================================================================= */

int p2p_receiver_request_chunk(p2p_node_t *node, p2p_transfer_t *transfer, uint32_t chunk_index) {
    if (!node || !transfer) return P2P_ERR_INVALID_ARG;
    if (chunk_index >= transfer->total_chunks) return P2P_ERR_INVALID_ARG;

    /* Select source peer */
    p2p_peer_t *peer = transfer->multi_source_enabled ?
        p2p_transfer_select_source(transfer) : transfer->peer;

    if (!peer) {
        TLOG_ERROR("[P2P] No peer available for chunk request");
        return P2P_ERR_INVALID_STATE;
    }

    /* Build CHUNK_REQUEST message */
    p2p_message_t *msg = (p2p_message_t *)calloc(1, sizeof(p2p_message_t));
    if (!msg) return P2P_ERR_NO_MEM;

    p2p_message_init(msg, P2P_MSG_CHUNK_REQUEST);
    msg->payload.chunk_request.transfer_id = transfer->id;
    msg->payload.chunk_request.chunk_index = chunk_index;

    TLOG_DEBUG("[P2P] Requesting chunk %u from %s:%d",
              chunk_index, peer->ip, peer->port);

    int ret = p2p_peer_send(peer, msg);
    free(msg);
    return ret;
}

/* =============================================================================
 * File Response Handler
 * ============================================================================= */

int p2p_receiver_handle_file_response(p2p_node_t *node, p2p_peer_t *peer,
                                       uint32_t request_id, uint64_t file_size,
                                       uint32_t total_chunks, const uint8_t *file_hash,
                                       uint32_t transfer_id) {
    if (!node || !peer) return P2P_ERR_INVALID_ARG;

    p2p_transfer_manager_t *mgr = (p2p_transfer_manager_t*)node->transfers;
    if (!mgr) return P2P_ERR_INVALID_STATE;

    /* Find pending transfer by request_id */
    p2p_transfer_t *transfer = p2p_transfer_find_by_id(mgr, transfer_id);
    if (!transfer) {
        TLOG_WARN("[P2P] FILE_RESPONSE for unknown transfer from %s:%d",
                 peer->ip, peer->port);
        return P2P_ERR_NOT_FOUND;
    }

    /* Check for error response */
    if (file_size == 0 && total_chunks == 0) {
        TLOG_WARN("[P2P] FILE_RESPONSE: file not found");
        p2p_transfer_complete(transfer, 0, "File not found");
        return P2P_ERR_NOT_FOUND;
    }

    /* Update transfer with file info */
    transfer->file_size = file_size;
    transfer->total_chunks = total_chunks;
    if (file_hash) {
        memcpy(transfer->file_hash, file_hash, P2P_SHA256_SIZE);
    }
    transfer->state = P2P_TRANSFER_STATE_ACTIVE;
    transfer->peer = peer;

    /* Initialize chunk bitmap */
    int ret = p2p_transfer_init_bitmap(transfer);
    if (ret != P2P_OK) {
        TLOG_ERROR("[P2P] Failed to init bitmap for transfer");
        return ret;
    }

    /* Open output file */
    ret = p2p_transfer_open_file(transfer, "wb");
    if (ret != P2P_OK) {
        TLOG_ERROR("[P2P] Failed to open output file for transfer");
        return ret;
    }

    TLOG_INFO("[P2P] Starting download: %zu bytes, %u chunks",
             transfer->file_size, transfer->total_chunks);

    /* Request first chunk(s) */
    if (transfer->parallel_enabled) {
        /* Request multiple chunks in parallel */
        for (int i = 0; i < P2P_PARALLEL_CHUNKS && i < (int)total_chunks; i++) {
            uint32_t chunk = p2p_transfer_get_next_to_request(transfer);
            if (chunk != (uint32_t)-1) {
                p2p_transfer_add_in_flight(transfer, chunk);
                /* Send CHUNK_REQUEST */
                p2p_message_t *msg = (p2p_message_t *)calloc(1, sizeof(p2p_message_t));
                if (msg) {
                    p2p_message_init(msg, P2P_MSG_CHUNK_REQUEST);
                    msg->payload.chunk_request.transfer_id = transfer->id;
                    msg->payload.chunk_request.chunk_index = chunk;
                    p2p_peer_send(peer, msg);
                    free(msg);
                }
            }
        }
    } else {
        /* Request first chunk */
        p2p_message_t *msg = (p2p_message_t *)calloc(1, sizeof(p2p_message_t));
        if (msg) {
            p2p_message_init(msg, P2P_MSG_CHUNK_REQUEST);
            msg->payload.chunk_request.transfer_id = transfer->id;
            msg->payload.chunk_request.chunk_index = 0;
            p2p_peer_send(peer, msg);
            free(msg);
        }
    }

    return P2P_OK;
}

/* =============================================================================
 * Chunk Data Handler
 * ============================================================================= */

int p2p_receiver_handle_chunk_data(p2p_node_t *node, p2p_peer_t *peer,
                                    uint32_t transfer_id, uint32_t chunk_index,
                                    const uint8_t *chunk_hash, const uint8_t *data,
                                    size_t data_len, int is_last) {
    (void)chunk_hash; /* Would verify hash in production */

    if (!node || !peer || !data) return P2P_ERR_INVALID_ARG;

    p2p_transfer_manager_t *mgr = (p2p_transfer_manager_t*)node->transfers;
    if (!mgr) return P2P_ERR_INVALID_STATE;

    p2p_transfer_t *transfer = p2p_transfer_find_by_id(mgr, transfer_id);
    if (!transfer) {
        TLOG_WARN("[P2P] CHUNK_DATA for unknown transfer %u", transfer_id);
        return P2P_ERR_NOT_FOUND;
    }

    if (transfer->direction != P2P_TRANSFER_DIR_DOWNLOAD) {
        TLOG_WARN("[P2P] CHUNK_DATA for upload transfer %u", transfer_id);
        return P2P_ERR_INVALID_STATE;
    }

    /* Remove from in-flight tracking */
    p2p_transfer_remove_in_flight(transfer, chunk_index);

    /* Update multi-source stats */
    p2p_transfer_source_received(transfer, peer, data_len);

    /* Write chunk to file */
    if (!transfer->fp) {
        TLOG_ERROR("[P2P] No file open for transfer %u", transfer_id);
        return P2P_ERR_INVALID_STATE;
    }

    size_t offset = p2p_transfer_get_chunk_offset(transfer, chunk_index);
    fseek(transfer->fp, (long)offset, SEEK_SET);

    size_t written = fwrite(data, 1, data_len, transfer->fp);
    if (written != data_len) {
        TLOG_ERROR("[P2P] Failed to write chunk %u", chunk_index);
        return P2P_ERR_IO;
    }

    /* Mark chunk as done */
    p2p_transfer_mark_chunk_done(transfer, chunk_index);
    p2p_transfer_update_progress(transfer, data_len);

    TLOG_DEBUG("[P2P] Received chunk %u/%u of transfer %u (%zu bytes)",
              chunk_index + 1, transfer->total_chunks, transfer_id, data_len);

    /* Check if transfer is complete */
    if (is_last || transfer->current_chunk >= transfer->total_chunks) {
        p2p_transfer_close_file(transfer);

        /* Verify file hash */
        /* In production, we would hash the entire file and compare */

        TLOG_INFO("[P2P] Transfer %u complete", transfer_id);
        p2p_transfer_complete(transfer, 1, NULL);

        /* Send FILE_ACK */
        p2p_message_t *ack = (p2p_message_t *)calloc(1, sizeof(p2p_message_t));
        if (ack) {
            p2p_message_init(ack, P2P_MSG_FILE_ACK);
            ack->payload.file_ack.transfer_id = transfer_id;
            ack->payload.file_ack.success = 1;
            /* p2p_peer_send(peer, ack); */
            free(ack);
        }

        return P2P_OK;
    }

    /* Request next chunk(s) */
    while (transfer->in_flight_count < P2P_PARALLEL_CHUNKS) {
        uint32_t next = p2p_transfer_get_next_to_request(transfer);
        if (next == (uint32_t)-1) break;

        p2p_transfer_add_in_flight(transfer, next);

        /* Select source for multi-source download */
        p2p_peer_t *source = transfer->multi_source_enabled ?
            p2p_transfer_select_source(transfer) : peer;

        p2p_message_t *msg = (p2p_message_t *)calloc(1, sizeof(p2p_message_t));
        if (msg) {
            p2p_message_init(msg, P2P_MSG_CHUNK_REQUEST);
            msg->payload.chunk_request.transfer_id = transfer->id;
            msg->payload.chunk_request.chunk_index = next;
            p2p_peer_send(source, msg);
            free(msg);
        }
    }

    return P2P_OK;
}
