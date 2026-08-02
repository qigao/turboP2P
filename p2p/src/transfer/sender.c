/**
 * sender.c - P2P File Transfer - Sender Implementation
 * Professional version based on Kademlia DHT and unified connection
 */

#include "sender.h"
#include "transfer.h"
#include "../../src/internal.h"
#include <tlog.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static int p2p_sender_decode_file_hash(
    const char hash[65], uint8_t digest[P2P_SHA256_DIGEST_SIZE]) {
    if (!hash || !digest || hash[64] != '\0') {
        return P2P_ERR_INVALID_ARG;
    }

    for (size_t i = 0; i < P2P_SHA256_DIGEST_SIZE; i++) {
        unsigned int byte = 0;
        if (sscanf(hash + (i * 2), "%2x", &byte) != 1) {
            return P2P_ERR_INVALID_ARG;
        }
        digest[i] = (uint8_t)byte;
    }
    return P2P_OK;
}

/* =============================================================================
 * File Request Handler
 * ============================================================================= */

int p2p_sender_handle_file_request(p2p_node_t *node, p2p_peer_t *peer,
                                    const p2p_id_t file_id, uint32_t chunk_size,
                                    uint32_t request_id) {
    p2p_file_t *file = NULL;
    p2p_transfer_manager_t *mgr = NULL;
    p2p_transfer_t *transfer = NULL;
    p2p_message_t *reply = NULL;
    p2p_peer_info_ex_t peer_info = {0};
    int ret = P2P_OK;

    if (!node || !peer || !file_id || request_id == 0 ||
        chunk_size == 0 || chunk_size > P2P_DEFAULT_CHUNK_SIZE) {
        return P2P_ERR_INVALID_ARG;
    }
    p2p_transfer_snapshot_peer_info(peer, &peer_info);

    /* Find file by ID in the node-owned local registry */
    file = p2p_node_find_local_file_by_id(node, file_id);

    if (!file) {
        TLOG_WARN("[P2P] FILE_REQUEST for unknown file from {}:{}", peer_info.ip, peer_info.port);

        /* Send negative response */
        reply = (p2p_message_t *)calloc(1, sizeof(p2p_message_t));
        if (reply) {
            p2p_message_init(reply, P2P_MSG_FILE_PUT);
            reply->header.request_id = request_id;
            reply->payload.file_response.file_size = 0;
            reply->payload.file_response.total_chunks = 0;
            reply->header.payload_len = sizeof(p2p_file_response_payload_t);
            (void)p2p_peer_send(peer, reply);
            free(reply);
        }

        return P2P_ERR_NOT_FOUND;
    }

    TLOG_INFO("[P2P] FILE_REQUEST for '{}' from {}:{}",
             file->filename, peer_info.ip, peer_info.port);

    mgr = node->transfers;
    if (!mgr) {
        return P2P_ERR_INVALID_STATE;
    }
    transfer = p2p_transfer_create(mgr, P2P_TRANSFER_DIR_UPLOAD);
    if (!transfer) {
        return P2P_ERR_NO_MEM;
    }

    turbo_mutex_lock(&transfer->mutex);
    memcpy(transfer->file_id, file_id, P2P_DHT_KEY_SIZE);
    strncpy(transfer->filepath, file->filepath, sizeof(transfer->filepath) - 1);
    strncpy(transfer->filename, file->filename, sizeof(transfer->filename) - 1);
    transfer->file_size = file->size;
    transfer->chunk_size = chunk_size;
    transfer->total_chunks = file->num_chunks;
    transfer->remote_id = request_id;
    transfer->peer = peer;
    ret = p2p_sender_decode_file_hash(file->hash, transfer->file_hash);
    if (ret == P2P_OK) {
        transfer->state = P2P_TRANSFER_STATE_ACTIVE;
    }
    turbo_mutex_unlock(&transfer->mutex);
    if (ret != P2P_OK) {
        p2p_transfer_destroy(mgr, transfer);
        return ret;
    }

    /* Send FILE_RESPONSE */
    reply = (p2p_message_t *)calloc(1, sizeof(p2p_message_t));
    if (!reply) {
        p2p_transfer_destroy(mgr, transfer);
        return P2P_ERR_NO_MEM;
    }
    p2p_message_init(reply, P2P_MSG_FILE_PUT);
    reply->header.request_id = request_id;
    memcpy(reply->payload.file_response.file_id, file_id, P2P_DHT_KEY_SIZE);
    reply->payload.file_response.file_size = transfer->file_size;
    reply->payload.file_response.total_chunks = transfer->total_chunks;
    memcpy(reply->payload.file_response.file_hash, transfer->file_hash,
           P2P_SHA256_DIGEST_SIZE);
    reply->header.payload_len = sizeof(p2p_file_response_payload_t);
    ret = p2p_peer_send(peer, reply);
    free(reply);
    if (ret != P2P_OK) {
        p2p_transfer_destroy(mgr, transfer);
    }
    return ret;
}

/* =============================================================================
 * Chunk Request Handler
 * ============================================================================= */

int p2p_sender_handle_chunk_request(p2p_node_t *node, p2p_peer_t *peer,
                                     uint32_t transfer_id, uint32_t chunk_index,
                                     uint32_t request_id) {
    int ret = P2P_OK;
    p2p_transfer_manager_t *mgr = NULL;
    p2p_transfer_t *transfer = NULL;
    p2p_message_t *msg = NULL;
    p2p_peer_info_ex_t peer_info = {0};
    size_t offset = 0;
    size_t size = 0;
    size_t read_bytes = 0;

    if (!node || !peer) return P2P_ERR_INVALID_ARG;
    p2p_transfer_snapshot_peer_info(peer, &peer_info);

    mgr = node->transfers;
    if (!mgr) {
        ret = P2P_ERR_INVALID_STATE;
        goto done;
    }

    /* Find transfer */
    transfer = p2p_transfer_find_upload_by_remote_id(mgr, transfer_id, peer);
    if (!transfer) {
        TLOG_WARN("[P2P] CHUNK_REQUEST for unknown transfer {} from {}:{}",
                 transfer_id, peer_info.ip, peer_info.port);
        ret = P2P_ERR_NOT_FOUND;
        goto done;
    }

    turbo_mutex_lock(&transfer->mutex);

    /* Open file if not already open */
    if (!transfer->fp) {
        ret = p2p_transfer_open_file_locked(transfer, "rb");
        if (ret != P2P_OK) {
            TLOG_ERROR("[P2P] Failed to open file for transfer {}", transfer_id);
            goto done;
        }
    }

    /* Build CHUNK_DATA message */
    msg = (p2p_message_t *)calloc(1, sizeof(p2p_message_t));
    if (!msg) {
        ret = P2P_ERR_NO_MEM;
        goto done;
    }

    p2p_message_init(msg, P2P_MSG_CHUNK_DATA);
    msg->header.request_id = request_id;
    msg->payload.chunk_data.transfer_id = transfer_id;
    msg->payload.chunk_data.chunk_index = chunk_index;

    offset = p2p_transfer_get_chunk_offset_locked(transfer, chunk_index);
    size = p2p_transfer_get_chunk_size_locked(transfer, chunk_index);
    if (chunk_index >= transfer->total_chunks ||
        size > sizeof(msg->payload.chunk_data.data)) {
        ret = P2P_ERR_INVALID_ARG;
        goto done;
    }
    
    fseek(transfer->fp, (long)offset, SEEK_SET);
    
    /* Using the msg payload buffer directly to avoid extra copy if possible */
    read_bytes = fread(msg->payload.chunk_data.data, 1, size, transfer->fp);
    
    if (read_bytes != size) {
        TLOG_ERROR("[P2P] Failed to read chunk {} from disk", chunk_index);
        ret = P2P_ERR_IO;
        goto done;
    }

    msg->payload.chunk_data.data_len = (uint16_t)read_bytes;
    p2p_sha256(msg->payload.chunk_data.data, read_bytes,
               msg->payload.chunk_data.chunk_hash);
    msg->header.payload_len = (uint16_t)(sizeof(p2p_chunk_data_payload_t) - (65536 - 128) + read_bytes);

    TLOG_DEBUG("[P2P] Sending chunk {} of transfer {} ({} bytes)", 
              chunk_index + 1, transfer_id, read_bytes);

    ret = p2p_peer_send(peer, msg);

done:
    if (transfer) {
        turbo_mutex_unlock(&transfer->mutex);
    }
    if (transfer) {
        p2p_transfer_release(transfer);
    }
    free(msg);
    return ret;
}

int p2p_sender_handle_file_ack(p2p_node_t *node, p2p_peer_t *peer,
                               uint32_t transfer_id, int success) {
    p2p_transfer_t *transfer = NULL;

    if (!node || !node->transfers || !peer || transfer_id == 0) {
        return P2P_ERR_INVALID_ARG;
    }

    transfer = p2p_transfer_find_upload_by_remote_id(
        node->transfers, transfer_id, peer);
    if (!transfer) {
        return P2P_ERR_NOT_FOUND;
    }

    p2p_transfer_complete(transfer, success,
                          success ? NULL : "Remote integrity check failed");
    p2p_transfer_destroy(node->transfers, transfer);
    p2p_transfer_release(transfer);
    return success ? P2P_OK : P2P_ERR_INVALID;
}
