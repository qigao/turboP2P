/**
 * P2P File Transfer - Receiver Implementation
 */

#include "receiver.h"
#include "transfer.h"
#include "../protocol/message.h"
#include "../../include/p2p.h"
#include <tlog.h>
#include <string.h>
#include <stdio.h>

enum {
    P2P_RECEIVER_HASH_BUFFER_SIZE = 32 * 1024,
};

static int p2p_receiver_verify_file_digest(
    const char *filepath,
    const uint8_t expected[P2P_SHA256_DIGEST_SIZE]) {
    uint8_t buffer[P2P_RECEIVER_HASH_BUFFER_SIZE];
    uint8_t actual[P2P_SHA256_DIGEST_SIZE];
    p2p_sha256_ctx_t hash;
    FILE *file = NULL;
    size_t bytes_read = 0;
    int ret = P2P_OK;

    if (!filepath || !expected) {
        return P2P_ERR_INVALID_ARG;
    }
    file = fopen(filepath, "rb");
    if (!file) {
        return P2P_ERR_IO;
    }

    p2p_sha256_init(&hash);
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        p2p_sha256_update(&hash, buffer, bytes_read);
    }
    if (ferror(file)) {
        ret = P2P_ERR_IO;
        goto done;
    }
    p2p_sha256_final(&hash, actual);
    if (memcmp(actual, expected, sizeof(actual)) != 0) {
        ret = P2P_ERR_INVALID;
    }

done:
    fclose(file);
    return ret;
}

static int p2p_receiver_request_peer_index_locked(
    const p2p_transfer_t *transfer, const p2p_peer_t *peer) {
    if (!transfer || !peer) {
        return -1;
    }

    for (uint8_t i = 0; i < transfer->request_peer_count; i++) {
        if (transfer->request_peers[i] == peer) {
            return (int)i;
        }
    }
    return -1;
}

static int p2p_receiver_source_index_locked(
    const p2p_transfer_t *transfer, const p2p_peer_t *peer) {
    if (!transfer || !peer) {
        return -1;
    }
    for (uint8_t i = 0; i < transfer->source_count; i++) {
        if (transfer->sources[i].active &&
            transfer->sources[i].peer == peer) {
            return (int)i;
        }
    }
    return -1;
}

static void p2p_receiver_send_file_ack(p2p_peer_t *peer,
                                       uint32_t transfer_id,
                                       int success) {
    p2p_message_t *ack = NULL;

    if (!peer || transfer_id == 0) {
        return;
    }
    ack = (p2p_message_t *)calloc(1, sizeof(*ack));
    if (!ack) {
        return;
    }

    p2p_message_init(ack, P2P_MSG_FILE_ACK);
    ack->payload.file_ack.transfer_id = transfer_id;
    ack->payload.file_ack.success = success ? 1 : 0;
    ack->header.payload_len = sizeof(p2p_file_ack_payload_t);
    (void)p2p_peer_send(peer, ack);
    free(ack);
}

static void p2p_receiver_send_source_acks(p2p_transfer_t *transfer,
                                          int success) {
    p2p_peer_t *peers[P2P_MAX_SOURCES] = {0};
    uint8_t peer_count = 0;
    uint32_t transfer_id = 0;

    if (!transfer) {
        return;
    }
    turbo_mutex_lock(&transfer->mutex);
    transfer_id = transfer->id;
    for (uint8_t i = 0; i < transfer->source_count; i++) {
        if (transfer->sources[i].peer) {
            peers[peer_count++] = transfer->sources[i].peer;
        }
    }
    turbo_mutex_unlock(&transfer->mutex);
    for (uint8_t i = 0; i < peer_count; i++) {
        p2p_receiver_send_file_ack(peers[i], transfer_id, success);
    }
}

/* =============================================================================
 * Request Chunk
 * ============================================================================= */

static int p2p_receiver_prepare_chunk_request_locked(p2p_transfer_t *transfer,
                                                     uint32_t chunk_index,
                                                     p2p_peer_t **peer_out,
                                                     uint32_t *transfer_id_out) {
    p2p_peer_t *peer = NULL;

    if (!transfer || !peer_out || !transfer_id_out) {
        return P2P_ERR_INVALID_ARG;
    }

    if (chunk_index >= transfer->total_chunks) {
        return P2P_ERR_INVALID_ARG;
    }

    peer = transfer->multi_source_enabled ?
        p2p_transfer_select_source_locked(transfer) : transfer->peer;
    if (!peer) {
        TLOG_ERROR("[P2P] No peer available for chunk request");
        return P2P_ERR_INVALID_STATE;
    }

    *peer_out = peer;
    *transfer_id_out = transfer->id;
    return P2P_OK;
}

int p2p_receiver_request_chunk(p2p_node_t *node, p2p_transfer_t *transfer, uint32_t chunk_index) {
    p2p_peer_t *peer = NULL;
    p2p_peer_info_ex_t peer_info = {0};
    uint32_t transfer_id = 0;
    int ret = P2P_OK;

    if (!node || !transfer) return P2P_ERR_INVALID_ARG;

    turbo_mutex_lock(&transfer->mutex);
    ret = p2p_receiver_prepare_chunk_request_locked(transfer, chunk_index, &peer, &transfer_id);
    turbo_mutex_unlock(&transfer->mutex);
    if (ret != P2P_OK) {
        return ret;
    }
    p2p_transfer_snapshot_peer_info(peer, &peer_info);

    /* Build CHUNK_REQUEST message */
    p2p_message_t *msg = (p2p_message_t *)calloc(1, sizeof(p2p_message_t));
    if (!msg) return P2P_ERR_NO_MEM;

    p2p_message_init(msg, P2P_MSG_CHUNK_REQUEST);
    msg->payload.chunk_request.transfer_id = transfer_id;
    msg->payload.chunk_request.chunk_index = chunk_index;
    msg->header.payload_len = sizeof(p2p_chunk_request_payload_t);

    TLOG_DEBUG("[P2P] Requesting chunk {} from {}:{}",
              chunk_index, peer_info.ip, peer_info.port);

    ret = p2p_peer_send(peer, msg);
    free(msg);
    return ret;
}

/* =============================================================================
 * File Response Handler
 * ============================================================================= */

int p2p_receiver_handle_file_response(p2p_node_t *node, p2p_peer_t *peer,
                                       uint32_t request_id, uint64_t file_size,
                                       uint32_t total_chunks, const uint8_t *file_hash) {
    p2p_peer_info_ex_t peer_info = {0};
    size_t expected_chunks = 0;
    int peer_index = -1;
    int reject_upload = 0;
    int complete_no_source = 0;
    int start_ret = P2P_OK;
    int ret = P2P_OK;

    if (!node || !peer || !file_hash || request_id == 0) {
        return P2P_ERR_INVALID_ARG;
    }
    p2p_transfer_snapshot_peer_info(peer, &peer_info);

    p2p_transfer_manager_t *mgr = (p2p_transfer_manager_t*)node->transfers;
    if (!mgr) return P2P_ERR_INVALID_STATE;

    /* Find pending transfer by request_id */
    p2p_transfer_t *transfer = p2p_transfer_find_by_id(mgr, request_id);
    if (!transfer) {
        TLOG_WARN("[P2P] FILE_RESPONSE for unknown transfer from {}:{}",
                 peer_info.ip, peer_info.port);
        return P2P_ERR_NOT_FOUND;
    }

    turbo_mutex_lock(&transfer->mutex);
    peer_index = p2p_receiver_request_peer_index_locked(transfer, peer);
    if (peer_index < 0) {
        reject_upload = !(file_size == 0 && total_chunks == 0);
        turbo_mutex_unlock(&transfer->mutex);
        if (reject_upload) {
            p2p_receiver_send_file_ack(peer, request_id, 0);
        }
        p2p_transfer_release(transfer);
        return P2P_ERR_INVALID_ARG;
    }
    if (transfer->request_peer_done[peer_index]) {
        reject_upload =
            transfer->peer != peer && !(file_size == 0 && total_chunks == 0);
        turbo_mutex_unlock(&transfer->mutex);
        if (reject_upload) {
            p2p_receiver_send_file_ack(peer, request_id, 0);
        }
        p2p_transfer_release(transfer);
        return P2P_ERR_INVALID_STATE;
    }
    transfer->request_peer_done[peer_index] = 1;
    transfer->response_count++;

    /* Check for error response */
    if (file_size == 0 && total_chunks == 0) {
        TLOG_WARN("[P2P] FILE_RESPONSE: file not found");
        complete_no_source =
            transfer->state == P2P_TRANSFER_STATE_PENDING &&
            transfer->response_count == transfer->request_peer_count;
        turbo_mutex_unlock(&transfer->mutex);
        if (complete_no_source) {
            p2p_transfer_complete(
                transfer, 0, "No peer provides the requested object");
        }
        p2p_transfer_release(transfer);
        return P2P_ERR_NOT_FOUND;
    }
    if (transfer->direction != P2P_TRANSFER_DIR_DOWNLOAD ||
        (transfer->state != P2P_TRANSFER_STATE_PENDING &&
         transfer->state != P2P_TRANSFER_STATE_ACTIVE) ||
        file_size > SIZE_MAX) {
        reject_upload = transfer->peer != peer;
        turbo_mutex_unlock(&transfer->mutex);
        if (reject_upload) {
            p2p_receiver_send_file_ack(peer, request_id, 0);
        }
        p2p_transfer_release(transfer);
        return P2P_ERR_INVALID_STATE;
    }
    expected_chunks = p2p_transfer_calc_chunk_count(
        (size_t)file_size, transfer->chunk_size);
    if (expected_chunks == 0) {
        expected_chunks = 1;
    }
    if (expected_chunks > UINT32_MAX || total_chunks != (uint32_t)expected_chunks) {
        complete_no_source =
            transfer->response_count == transfer->request_peer_count;
        turbo_mutex_unlock(&transfer->mutex);
        p2p_receiver_send_file_ack(peer, request_id, 0);
        if (complete_no_source) {
            p2p_transfer_complete(
                transfer, 0, "No peer returned valid object metadata");
        }
        p2p_transfer_release(transfer);
        return P2P_ERR_INVALID_ARG;
    }

    if (transfer->state == P2P_TRANSFER_STATE_ACTIVE) {
        if (transfer->file_size != (size_t)file_size ||
            transfer->total_chunks != total_chunks ||
            memcmp(transfer->file_hash, file_hash,
                   P2P_SHA256_DIGEST_SIZE) != 0) {
            turbo_mutex_unlock(&transfer->mutex);
            p2p_receiver_send_file_ack(peer, request_id, 0);
            p2p_transfer_release(transfer);
            return P2P_ERR_INVALID_ARG;
        }
        ret = p2p_transfer_source_add_locked(transfer, peer);
        if (ret != P2P_OK) {
            turbo_mutex_unlock(&transfer->mutex);
            p2p_receiver_send_file_ack(peer, request_id, 0);
            p2p_transfer_release(transfer);
            return ret;
        }
        transfer->multi_source_enabled = 1;
        turbo_mutex_unlock(&transfer->mutex);
        p2p_transfer_release(transfer);
        return P2P_OK;
    }

    /* Update transfer with file info */
    transfer->file_size = (size_t)file_size;
    transfer->total_chunks = total_chunks;
    memcpy(transfer->file_hash, file_hash, P2P_SHA256_SIZE);
    transfer->state = P2P_TRANSFER_STATE_ACTIVE;
    transfer->peer = peer;
    ret = p2p_transfer_source_add_locked(transfer, peer);
    if (ret != P2P_OK) {
        turbo_mutex_unlock(&transfer->mutex);
        p2p_transfer_complete(transfer, 0, "Failed to register file source");
        p2p_receiver_send_file_ack(peer, request_id, 0);
        p2p_transfer_release(transfer);
        return ret;
    }
    transfer->multi_source_enabled = 1;

    /* Initialize chunk bitmap */
    ret = p2p_transfer_init_bitmap_locked(transfer);
    if (ret != P2P_OK) {
        TLOG_ERROR("[P2P] Failed to init bitmap for transfer");
        turbo_mutex_unlock(&transfer->mutex);
        p2p_transfer_complete(transfer, 0, "Failed to initialize chunk state");
        p2p_receiver_send_file_ack(peer, request_id, 0);
        p2p_transfer_release(transfer);
        return ret;
    }

    /* Open output file */
    ret = p2p_transfer_open_file_locked(transfer, "wb");
    if (ret != P2P_OK) {
        TLOG_ERROR("[P2P] Failed to open output file for transfer");
        turbo_mutex_unlock(&transfer->mutex);
        p2p_transfer_complete(transfer, 0, "Failed to open output file");
        p2p_receiver_send_file_ack(peer, request_id, 0);
        p2p_transfer_release(transfer);
        return ret;
    }

    TLOG_INFO("[P2P] Starting download: {} bytes, {} chunks",
             transfer->file_size, transfer->total_chunks);

    /* Request first chunk(s) */
    if (transfer->parallel_enabled) {
        /* Request multiple chunks in parallel */
        for (int i = 0; i < P2P_PARALLEL_CHUNKS && i < (int)total_chunks; i++) {
            uint32_t chunk = p2p_transfer_get_next_to_request_locked(transfer);
            if (chunk != (uint32_t)-1) {
                int source_index =
                    p2p_receiver_source_index_locked(transfer, peer);
                if (source_index < 0 ||
                    !p2p_transfer_add_in_flight_multi_locked(
                        transfer, chunk, (uint8_t)source_index)) {
                    start_ret = P2P_ERR_INVALID_STATE;
                    break;
                }
                /* Send CHUNK_REQUEST */
                p2p_message_t *msg = (p2p_message_t *)calloc(1, sizeof(p2p_message_t));
                if (msg) {
                    p2p_message_init(msg, P2P_MSG_CHUNK_REQUEST);
                    msg->payload.chunk_request.transfer_id = transfer->id;
                    msg->payload.chunk_request.chunk_index = chunk;
                    msg->header.payload_len = sizeof(p2p_chunk_request_payload_t);
                    start_ret = p2p_peer_send(peer, msg);
                    free(msg);
                    if (start_ret != P2P_OK) {
                        p2p_transfer_remove_in_flight_locked(transfer, chunk);
                        p2p_transfer_source_failed_locked(transfer, peer);
                        break;
                    }
                } else {
                    p2p_transfer_remove_in_flight_locked(transfer, chunk);
                    p2p_transfer_source_failed_locked(transfer, peer);
                    start_ret = P2P_ERR_NO_MEM;
                    break;
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
            msg->header.payload_len = sizeof(p2p_chunk_request_payload_t);
            start_ret = p2p_peer_send(peer, msg);
            free(msg);
        } else {
            start_ret = P2P_ERR_NO_MEM;
        }
    }

    turbo_mutex_unlock(&transfer->mutex);
    if (start_ret != P2P_OK) {
        p2p_transfer_complete(transfer, 0, "Failed to request initial chunk");
        p2p_receiver_send_file_ack(peer, request_id, 0);
        p2p_transfer_release(transfer);
        return start_ret;
    }
    p2p_transfer_release(transfer);
    return P2P_OK;
}

/* =============================================================================
 * Chunk Data Handler
 * ============================================================================= */

int p2p_receiver_handle_chunk_data(p2p_node_t *node, p2p_peer_t *peer,
                                    uint32_t transfer_id, uint32_t chunk_index,
                                    const uint8_t *chunk_hash, const uint8_t *data,
                                    size_t data_len, int is_last) {
    p2p_transfer_manager_t *mgr = NULL;
    p2p_transfer_t *transfer = NULL;
    int ret = P2P_OK;
    int transfer_locked = 0;
    int complete_now = 0;
    uint32_t total_chunks = 0;
    uint8_t actual_chunk_hash[P2P_SHA256_DIGEST_SIZE];

    (void)is_last;

    if (!node || !peer || !chunk_hash || (!data && data_len > 0)) {
        return P2P_ERR_INVALID_ARG;
    }

    mgr = (p2p_transfer_manager_t*)node->transfers;
    if (!mgr) {
        ret = P2P_ERR_INVALID_STATE;
        goto done;
    }

    transfer = p2p_transfer_find_by_id(mgr, transfer_id);
    if (!transfer) {
        TLOG_WARN("[P2P] CHUNK_DATA for unknown transfer {}", transfer_id);
        ret = P2P_ERR_NOT_FOUND;
        goto done;
    }

    turbo_mutex_lock(&transfer->mutex);
    transfer_locked = 1;

    if (transfer->direction != P2P_TRANSFER_DIR_DOWNLOAD) {
        TLOG_WARN("[P2P] CHUNK_DATA for upload transfer {}", transfer_id);
        ret = P2P_ERR_INVALID_STATE;
        goto done;
    }
    if ((!transfer->multi_source_enabled && transfer->peer != peer) ||
        (transfer->multi_source_enabled &&
         p2p_receiver_source_index_locked(transfer, peer) < 0) ||
        transfer->state != P2P_TRANSFER_STATE_ACTIVE ||
        chunk_index >= transfer->total_chunks ||
        data_len != p2p_transfer_get_chunk_size_locked(transfer, chunk_index)) {
        ret = P2P_ERR_INVALID_ARG;
        goto done;
    }
    if (p2p_bitmap_get(transfer->chunk_bitmap, chunk_index)) {
        ret = P2P_OK;
        goto done;
    }
    p2p_sha256(data, data_len, actual_chunk_hash);
    if (memcmp(actual_chunk_hash, chunk_hash, sizeof(actual_chunk_hash)) != 0) {
        turbo_mutex_unlock(&transfer->mutex);
        transfer_locked = 0;
        p2p_transfer_complete(transfer, 0, "Chunk digest mismatch");
        ret = P2P_ERR_INVALID;
        goto done;
    }

    /* Remove from in-flight tracking */
    p2p_transfer_remove_in_flight_locked(transfer, chunk_index);

    /* Update multi-source stats */
    p2p_transfer_source_received_locked(transfer, peer, data_len);

    /* Write chunk to file */
    if (!transfer->fp) {
        TLOG_ERROR("[P2P] No file open for transfer {}", transfer_id);
        ret = P2P_ERR_INVALID_STATE;
        goto done;
    }

    size_t offset = p2p_transfer_get_chunk_offset_locked(transfer, chunk_index);
    fseek(transfer->fp, (long)offset, SEEK_SET);

    size_t written = fwrite(data, 1, data_len, transfer->fp);
    if (written != data_len) {
        TLOG_ERROR("[P2P] Failed to write chunk {}", chunk_index);
        ret = P2P_ERR_IO;
        goto done;
    }

    /* Mark chunk as done */
    p2p_transfer_mark_chunk_done_locked(transfer, chunk_index);
    total_chunks = transfer->total_chunks;
    complete_now = p2p_bitmap_is_complete(
        transfer->chunk_bitmap, transfer->total_chunks);
    if (complete_now) {
        p2p_transfer_close_file_locked(transfer);
    }
    turbo_mutex_unlock(&transfer->mutex);
    transfer_locked = 0;
    p2p_transfer_update_progress(transfer, data_len);

    TLOG_DEBUG("[P2P] Received chunk {}/{} of transfer {} ({} bytes)",
              chunk_index + 1, total_chunks, transfer_id, data_len);

    /* Check if transfer is complete */
    if (complete_now) {
        char seed_key[65];
        int seed_ret = P2P_OK;

        ret = p2p_receiver_verify_file_digest(
            transfer->filepath, transfer->file_hash);
        if (ret != P2P_OK) {
            p2p_transfer_complete(transfer, 0, "File digest mismatch");
        } else {
            seed_ret = p2p_put_file(node, transfer->filepath, seed_key);
            if (seed_ret != P2P_OK ||
                strcmp(seed_key, transfer->filename) != 0) {
                TLOG_WARN("[P2P] Download verified but could not become a seed");
            }
            p2p_transfer_complete(transfer, 1, NULL);
        }
        TLOG_INFO("[P2P] Transfer {} complete", transfer_id);

        /* Release every peer-scoped upload created for this swarm. */
        p2p_receiver_send_source_acks(transfer, ret == P2P_OK);

        goto done;
    }

    turbo_mutex_lock(&transfer->mutex);
    transfer_locked = 1;
    if (transfer->state != P2P_TRANSFER_STATE_ACTIVE) {
        goto done;
    }

    /* Request next chunk(s) */
    while (transfer->in_flight_count < P2P_PARALLEL_CHUNKS) {
        uint32_t next = p2p_transfer_get_next_to_request_locked(transfer);
        if (next == (uint32_t)-1) break;

        /* Select source for multi-source download */
        p2p_peer_t *source = transfer->multi_source_enabled ?
            p2p_transfer_select_source_locked(transfer) : peer;
        int source_index =
            p2p_receiver_source_index_locked(transfer, source);
        if (!source || source_index < 0 ||
            !p2p_transfer_add_in_flight_multi_locked(
                transfer, next, (uint8_t)source_index)) {
            break;
        }

        p2p_message_t *msg = (p2p_message_t *)calloc(1, sizeof(p2p_message_t));
        if (msg) {
            p2p_message_init(msg, P2P_MSG_CHUNK_REQUEST);
            msg->payload.chunk_request.transfer_id = transfer->id;
            msg->payload.chunk_request.chunk_index = next;
            msg->header.payload_len = sizeof(p2p_chunk_request_payload_t);
            if (p2p_peer_send(source, msg) != P2P_OK) {
                p2p_transfer_remove_in_flight_locked(transfer, next);
                p2p_transfer_source_failed_locked(transfer, source);
            }
            free(msg);
        } else {
            p2p_transfer_remove_in_flight_locked(transfer, next);
            p2p_transfer_source_failed_locked(transfer, source);
            break;
        }
    }

done:
    if (transfer && transfer_locked) {
        turbo_mutex_unlock(&transfer->mutex);
    }
    if (transfer) {
        p2p_transfer_release(transfer);
    }
    return ret;
}
