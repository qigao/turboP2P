#include "p2p.h"
#include "../internal.h"
#include "../transfer/transfer.h"
#include <stdlib.h>
#include <string.h>

enum {
    P2P_FILE_HASH_BUFFER_SIZE = 32 * 1024,
};

static int p2p_hex_digit_value(char value) {
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    if (value >= 'A' && value <= 'F') {
        return value - 'A' + 10;
    }
    return -1;
}

static void p2p_sha256_to_hex(const uint8_t digest[P2P_SHA256_DIGEST_SIZE],
                              char output[65]) {
    static const char digits[] = "0123456789abcdef";

    for (size_t i = 0; i < P2P_SHA256_DIGEST_SIZE; i++) {
        output[i * 2] = digits[digest[i] >> 4];
        output[i * 2 + 1] = digits[digest[i] & 0x0f];
    }
    output[64] = '\0';
}

static int p2p_sha256_key_decode(const char key[65],
                                 uint8_t digest[P2P_SHA256_DIGEST_SIZE]) {
    if (!key || !digest || key[64] != '\0') {
        return P2P_ERR_INVALID_ARG;
    }

    for (size_t i = 0; i < P2P_SHA256_DIGEST_SIZE; i++) {
        int high = p2p_hex_digit_value(key[i * 2]);
        int low = p2p_hex_digit_value(key[i * 2 + 1]);
        if (high < 0 || low < 0) {
            return P2P_ERR_INVALID_ARG;
        }
        digest[i] = (uint8_t)((high << 4) | low);
    }
    return P2P_OK;
}

static int p2p_hash_file(const char *filepath,
                         uint8_t digest[P2P_SHA256_DIGEST_SIZE],
                         size_t *size_out) {
    uint8_t buffer[P2P_FILE_HASH_BUFFER_SIZE];
    p2p_sha256_ctx_t hash;
    FILE *file = NULL;
    size_t total_size = 0;
    size_t bytes_read = 0;
    int ret = P2P_OK;

    if (!filepath || !digest || !size_out) {
        return P2P_ERR_INVALID_ARG;
    }

    file = fopen(filepath, "rb");
    if (!file) {
        return P2P_ERR_IO;
    }

    p2p_sha256_init(&hash);
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (total_size > SIZE_MAX - bytes_read) {
            ret = P2P_ERR_INVALID_ARG;
            goto done;
        }
        p2p_sha256_update(&hash, buffer, bytes_read);
        total_size += bytes_read;
    }
    if (ferror(file)) {
        ret = P2P_ERR_IO;
        goto done;
    }

    p2p_sha256_final(&hash, digest);
    *size_out = total_size;

done:
    fclose(file);
    return ret;
}

int p2p_put_file(p2p_node_t *node, const char *filepath, char key_out[65]) {
    uint8_t digest[P2P_SHA256_DIGEST_SIZE];
    p2p_file_t *file = NULL;
    size_t file_size = 0;
    int ret = P2P_OK;

    if (!node || !filepath || !key_out) return P2P_ERR_INVALID_ARG;

    ret = p2p_hash_file(filepath, digest, &file_size);
    if (ret != P2P_OK) {
        return ret;
    }
    p2p_sha256_to_hex(digest, key_out);

    file = p2p_file_create(key_out, filepath);
    if (!file) return P2P_ERR_NO_MEM;

    file->is_local = 1;
    memcpy(file->id, digest, P2P_HASH_SIZE);
    memcpy(file->hash, key_out, sizeof(file->hash));
    file->size = file_size;
    file->chunk_size = P2P_DEFAULT_CHUNK_SIZE;
    file->num_chunks = (uint32_t)p2p_transfer_calc_chunk_count(
        file_size, file->chunk_size);
    if (file->num_chunks == 0) {
        file->num_chunks = 1;
    }
    file->available_chunks = file->num_chunks;
    p2p_node_add_file(node, file);

    /* Local registration remains authoritative even with no connected DHT peer. */
    (void)p2p_file_announce(node, file);

    return P2P_OK;
}

int p2p_get_file_async(p2p_node_t *node, const char key[65],
                       const char *output_path,
                       p2p_transfer_complete_cb complete_cb,
                       void *user_data) {
    uint8_t digest[P2P_SHA256_DIGEST_SIZE];
    p2p_transfer_t *transfer = NULL;
    p2p_message_t *request = NULL;
    p2p_peer_t **peers = NULL;
    size_t peer_count = 0;
    size_t request_peer_count = 0;
    size_t sent_count = 0;
    int complete_no_source = 0;
    int ret = P2P_OK;

    if (!node || !key || !output_path || !node->transfers) {
        return P2P_ERR_INVALID_ARG;
    }
    if (strlen(output_path) >= P2P_MAX_FILEPATH) {
        return P2P_ERR_INVALID_ARG;
    }
    ret = p2p_sha256_key_decode(key, digest);
    if (ret != P2P_OK) {
        return ret;
    }

    transfer = p2p_transfer_create(node->transfers, P2P_TRANSFER_DIR_DOWNLOAD);
    if (!transfer) {
        return P2P_ERR_NO_MEM;
    }
    salts_mutex_lock(&transfer->mutex);
    memcpy(transfer->file_id, digest, P2P_HASH_SIZE);
    memcpy(transfer->file_hash, digest, P2P_SHA256_DIGEST_SIZE);
    strncpy(transfer->filepath, output_path, sizeof(transfer->filepath) - 1);
    strncpy(transfer->filename, key, sizeof(transfer->filename) - 1);
    transfer->complete_cb = complete_cb;
    transfer->user_data = user_data;
    salts_mutex_unlock(&transfer->mutex);

    peers = p2p_node_snapshot_connected_peers(node, &peer_count);
    if (peer_count == 0 || !peers) {
        p2p_transfer_destroy(node->transfers, transfer);
        free(peers);
        return P2P_ERR_NOT_FOUND;
    }
    request_peer_count = peer_count < P2P_MAX_SOURCES
        ? peer_count
        : P2P_MAX_SOURCES;
    salts_mutex_lock(&transfer->mutex);
    transfer->request_peer_count = (uint8_t)request_peer_count;
    for (size_t i = 0; i < request_peer_count; i++) {
        ret = p2p_transfer_hold_peer_locked(transfer, peers[i]);
        if (ret != P2P_OK) break;
        transfer->request_peers[i] = peers[i];
    }
    salts_mutex_unlock(&transfer->mutex);
    if (ret != P2P_OK) {
        for (size_t i = 0; i < peer_count; i++) p2p_peer_release(peers[i]);
        free(peers);
        p2p_transfer_destroy(node->transfers, transfer);
        return ret;
    }

    request = (p2p_message_t *)calloc(1, sizeof(*request));
    if (!request) {
        for (size_t i = 0; i < peer_count; i++) {
            p2p_peer_release(peers[i]);
        }
        free(peers);
        p2p_transfer_destroy(node->transfers, transfer);
        return P2P_ERR_NO_MEM;
    }

    p2p_message_init(request, P2P_MSG_FILE_GET);
    request->header.request_id = transfer->id;
    request->header.payload_len = P2P_HASH_SIZE;
    memcpy(request->payload.file_response.file_id, digest, P2P_HASH_SIZE);

    for (size_t i = 0; i < request_peer_count; i++) {
        if (p2p_peer_send(peers[i], request) == P2P_OK) {
            sent_count++;
        } else {
            salts_mutex_lock(&transfer->mutex);
            if (!transfer->request_peer_done[i]) {
                transfer->request_peer_done[i] = 1;
                transfer->response_count++;
            }
            salts_mutex_unlock(&transfer->mutex);
        }
    }
    for (size_t i = 0; i < peer_count; i++) {
        p2p_peer_release(peers[i]);
    }
    free(request);
    free(peers);

    if (sent_count == 0) {
        p2p_transfer_destroy(node->transfers, transfer);
        return P2P_ERR_NETWORK;
    }

    salts_mutex_lock(&transfer->mutex);
    complete_no_source =
        transfer->state == P2P_TRANSFER_STATE_PENDING &&
        transfer->response_count == transfer->request_peer_count;
    salts_mutex_unlock(&transfer->mutex);
    if (complete_no_source) {
        p2p_transfer_complete(transfer, 0, "No peer provides the requested object");
    }
    return P2P_OK;
}

int p2p_get_file(p2p_node_t *node, const char key[65],
                 const char *output_path) {
    return p2p_get_file_async(node, key, output_path, NULL, NULL);
}
