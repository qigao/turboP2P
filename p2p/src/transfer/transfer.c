#include "transfer.h"
#include "bitmap.h"
#include "resume.h"
#include "receiver.h"
#include "../core/node.h"
#include <platform.h>
#include <tlog.h>
#include <stdlib.h>
#include <string.h>

void p2p_transfer_manager_init(p2p_transfer_manager_t *mgr) {
    mgr->active = NULL;
    mgr->count = 0;
    mgr->next_id = 1;
    turbo_mutex_init(&mgr->mutex);
}

void p2p_transfer_manager_destroy(p2p_transfer_manager_t *mgr) {
    turbo_mutex_lock(&mgr->mutex);
    p2p_transfer_t *t = mgr->active;
    while (t) {
        p2p_transfer_t *next = t->next;
        p2p_transfer_close_file(t);
        p2p_transfer_free_bitmap(t);
        free(t);
        t = next;
    }
    mgr->active = NULL;
    mgr->count = 0;
    turbo_mutex_unlock(&mgr->mutex);
    turbo_mutex_destroy(&mgr->mutex);
}

p2p_transfer_t* p2p_transfer_create(p2p_transfer_manager_t *mgr, p2p_transfer_dir_t dir) {
    p2p_transfer_t *t = (p2p_transfer_t *)calloc(1, sizeof(p2p_transfer_t));
    if (!t) return NULL;

    turbo_mutex_lock(&mgr->mutex);
    t->id = mgr->next_id++;
    t->direction = dir;
    t->state = P2P_TRANSFER_PENDING;
    t->chunk_size = P2P_DEFAULT_CHUNK_SIZE;
    t->start_time = turbo_hrtime();
    t->last_activity = t->start_time;

    t->next = mgr->active;
    mgr->active = t;
    mgr->count++;
    turbo_mutex_unlock(&mgr->mutex);

    TLOG_DEBUG("[Transfer] Created transfer #%u (%s)",
              t->id, dir == P2P_TRANSFER_DIR_DOWNLOAD ? "download" : "upload");
    return t;
}

void p2p_transfer_destroy(p2p_transfer_manager_t *mgr, p2p_transfer_t *transfer) {
    if (!mgr || !transfer) return;

    turbo_mutex_lock(&mgr->mutex);
    p2p_transfer_t **pp = &mgr->active;
    while (*pp) {
        if (*pp == transfer) {
            *pp = transfer->next;
            mgr->count--;
            break;
        }
        pp = &(*pp)->next;
    }
    turbo_mutex_unlock(&mgr->mutex);

    p2p_transfer_close_file(transfer);
    p2p_transfer_free_bitmap(transfer);
    TLOG_DEBUG("[Transfer] Destroyed transfer #%u", transfer->id);
    free(transfer);
}

p2p_transfer_t* p2p_transfer_find_by_id(p2p_transfer_manager_t *mgr, uint32_t id) {
    turbo_mutex_lock(&mgr->mutex);
    p2p_transfer_t *t = mgr->active;
    while (t) {
        if (t->id == id) {
            turbo_mutex_unlock(&mgr->mutex);
            return t;
        }
        t = t->next;
    }
    turbo_mutex_unlock(&mgr->mutex);
    return NULL;
}

int p2p_transfer_open_file(p2p_transfer_t *transfer, const char *mode) {
    if (!transfer || !transfer->filepath[0]) return P2P_ERR_INVALID_ARG;
    if (transfer->fp) return P2P_OK;

    transfer->fp = fopen(transfer->filepath, mode);
    if (!transfer->fp) {
        TLOG_ERROR("[Transfer] Failed to open file: %s", transfer->filepath);
        return P2P_ERR_IO;
    }

    if (transfer->direction == P2P_TRANSFER_DIR_UPLOAD) {
        fseek(transfer->fp, 0, SEEK_END);
        transfer->file_size = (size_t)ftell(transfer->fp);
        fseek(transfer->fp, 0, SEEK_SET);
        transfer->total_chunks = (uint32_t)p2p_transfer_calc_chunk_count(
            transfer->file_size, transfer->chunk_size);
    }

    return P2P_OK;
}

void p2p_transfer_close_file(p2p_transfer_t *transfer) {
    if (transfer && transfer->fp) {
        fclose(transfer->fp);
        transfer->fp = NULL;
    }
}

void p2p_transfer_update_progress(p2p_transfer_t *transfer, size_t bytes) {
    transfer->bytes_transferred += bytes;
    transfer->last_activity = turbo_hrtime();

    if (transfer->progress_cb) {
        transfer->progress_cb(transfer, transfer->bytes_transferred, transfer->file_size, transfer->user_data);
    }
}

void p2p_transfer_complete(p2p_transfer_t *transfer, int success, const char *error) {
    transfer->state = success ? P2P_TRANSFER_COMPLETED : P2P_TRANSFER_FAILED;

    TLOG_INFO("[Transfer] Transfer #%u %s%s%s",
             transfer->id,
             success ? "completed" : "failed",
             error ? ": " : "",
             error ? error : "");

    if (success) {
        /* Delete resume file on success */
        if (transfer->resume_path[0]) {
            p2p_transfer_delete_state(transfer);
        }
    } else {
        /* Save resume file on failure for later resume */
        if (transfer->chunk_bitmap) {
            p2p_transfer_save_state(transfer);
        }
    }

    if (transfer->complete_cb) {
        transfer->complete_cb(transfer, success, error, transfer->user_data);
    }
}

size_t p2p_transfer_calc_chunk_count(size_t file_size, size_t chunk_size) {
    if (chunk_size == 0) return 0;
    return (file_size + chunk_size - 1) / chunk_size;
}

size_t p2p_transfer_get_chunk_offset(p2p_transfer_t *transfer, uint32_t chunk_index) {
    return (size_t)chunk_index * transfer->chunk_size;
}

size_t p2p_transfer_get_chunk_size(p2p_transfer_t *transfer, uint32_t chunk_index) {
    size_t offset = p2p_transfer_get_chunk_offset(transfer, chunk_index);
    if (offset >= transfer->file_size) return 0;

    size_t remaining = transfer->file_size - offset;
    return (remaining < transfer->chunk_size) ? remaining : transfer->chunk_size;
}

/* Bitmap management */
int p2p_transfer_init_bitmap(p2p_transfer_t *transfer) {
    if (!transfer || transfer->total_chunks == 0) return P2P_ERR_INVALID_ARG;
    if (transfer->chunk_bitmap) return P2P_OK;

    transfer->chunk_bitmap = p2p_bitmap_create();
    if (!transfer->chunk_bitmap) {
        return P2P_ERR_NO_MEM;
    }


    p2p_resume_path_from_filepath(transfer->filepath, transfer->resume_path,
                                   sizeof(transfer->resume_path));
    transfer->chunks_since_save = 0;
    return P2P_OK;
}

void p2p_transfer_free_bitmap(p2p_transfer_t *transfer) {
    if (transfer && transfer->chunk_bitmap) {
        p2p_bitmap_free(transfer->chunk_bitmap);
        transfer->chunk_bitmap = NULL;
    }
}


void p2p_transfer_mark_chunk_done(p2p_transfer_t *transfer, uint32_t chunk_index) {
    if (!transfer || !transfer->chunk_bitmap) return;
    if (chunk_index >= transfer->total_chunks) return;

    p2p_bitmap_set(transfer->chunk_bitmap, chunk_index);
    transfer->chunks_since_save++;

    if (transfer->chunks_since_save >= P2P_RESUME_SAVE_INTERVAL) {
        p2p_resume_save(transfer);
        transfer->chunks_since_save = 0;
    }
}

uint32_t p2p_transfer_next_chunk(p2p_transfer_t *transfer) {
    if (!transfer || !transfer->chunk_bitmap) {
        return transfer ? transfer->current_chunk : 0;
    }
    return p2p_bitmap_find_first_zero(transfer->chunk_bitmap, transfer->total_chunks);
}

/* Transfer control */
int p2p_transfer_mgr_pause(p2p_transfer_manager_t *mgr, uint32_t transfer_id) {
    p2p_transfer_t *t = p2p_transfer_find_by_id(mgr, transfer_id);
    if (!t) return P2P_ERR_NOT_FOUND;

    if (t->state != P2P_TRANSFER_ACTIVE) {
        return P2P_ERR_INVALID_STATE;
    }

    t->state = P2P_TRANSFER_PAUSED;

    if (t->chunk_bitmap) {
        p2p_resume_save(t);
    }

    TLOG_INFO("[Transfer] Transfer #%u paused", transfer_id);
    return P2P_OK;
}

int p2p_transfer_mgr_resume(p2p_transfer_manager_t *mgr, uint32_t transfer_id,
                            p2p_node_t *node) {
    p2p_transfer_t *t = p2p_transfer_find_by_id(mgr, transfer_id);
    if (!t) return P2P_ERR_NOT_FOUND;

    if (t->state != P2P_TRANSFER_PAUSED) {
        return P2P_ERR_INVALID_STATE;
    }

    t->state = P2P_TRANSFER_ACTIVE;
    t->last_activity = turbo_hrtime();

    TLOG_INFO("[Transfer] Transfer #%u resumed", transfer_id);

    /* Receiver will request next chunk when state becomes ACTIVE */
    (void)node;
    return P2P_OK;
}

int p2p_transfer_mgr_cancel(p2p_transfer_manager_t *mgr, uint32_t transfer_id) {
    p2p_transfer_t *t = p2p_transfer_find_by_id(mgr, transfer_id);
    if (!t) return P2P_ERR_NOT_FOUND;

    if (t->state == P2P_TRANSFER_COMPLETED ||
        t->state == P2P_TRANSFER_CANCELLED) {
        return P2P_ERR_INVALID_STATE;
    }

    t->state = P2P_TRANSFER_CANCELLED;

    if (t->resume_path[0]) {
        p2p_transfer_delete_state(t);
    }

    TLOG_INFO("[Transfer] Transfer #%u cancelled", transfer_id);

    if (t->complete_cb) {
        t->complete_cb(t, 0, "Cancelled by user", t->user_data);
    }

    return P2P_OK;
}

int p2p_transfer_mgr_get_status(p2p_transfer_manager_t *mgr, uint32_t transfer_id,
                                p2p_transfer_status_t *status) {
    if (!status) return P2P_ERR_INVALID_ARG;

    p2p_transfer_t *t = p2p_transfer_find_by_id(mgr, transfer_id);
    if (!t) return P2P_ERR_NOT_FOUND;

    status->id = t->id;
    status->state = (int)t->state;
    status->bytes_transferred = t->bytes_transferred;
    status->file_size = t->file_size;
    strncpy(status->filename, t->filename, sizeof(status->filename) - 1);
    status->error_code = t->error_code;

    return P2P_OK;
}

/* =============================================================================
 * Parallel Chunk Requests
 * ============================================================================= */

void p2p_transfer_enable_parallel(p2p_transfer_t *transfer, int enable) {
    if (transfer) {
        transfer->parallel_enabled = enable ? 1 : 0;
        if (!enable) {
            transfer->in_flight_count = 0;
        }
    }
}

int p2p_transfer_add_in_flight(p2p_transfer_t *transfer, uint32_t chunk_index) {
    if (!transfer) return 0;
    if (transfer->in_flight_count >= P2P_PARALLEL_CHUNKS) return 0;

    /* Check if already in flight */
    for (uint8_t i = 0; i < transfer->in_flight_count; i++) {
        if (transfer->in_flight[i].chunk_index == chunk_index) return 0;
    }

    p2p_in_flight_entry_t *entry = &transfer->in_flight[transfer->in_flight_count++];
    entry->chunk_index = chunk_index;
    entry->request_time = turbo_hrtime();
    entry->retry_count = 0;
    return 1;
}

void p2p_transfer_remove_in_flight(p2p_transfer_t *transfer, uint32_t chunk_index) {
    if (!transfer) return;

    for (uint8_t i = 0; i < transfer->in_flight_count; i++) {
        if (transfer->in_flight[i].chunk_index == chunk_index) {
            /* Shift remaining entries */
            for (uint8_t j = i; j < transfer->in_flight_count - 1; j++) {
                transfer->in_flight[j] = transfer->in_flight[j + 1];
            }
            transfer->in_flight_count--;
            return;
        }
    }
}

int p2p_transfer_is_in_flight(p2p_transfer_t *transfer, uint32_t chunk_index) {
    if (!transfer) return 0;

    for (uint8_t i = 0; i < transfer->in_flight_count; i++) {
        if (transfer->in_flight[i].chunk_index == chunk_index) return 1;
    }
    return 0;
}

uint32_t p2p_transfer_get_next_to_request(p2p_transfer_t *transfer) {
    if (!transfer || !transfer->chunk_bitmap) {
        return transfer ? transfer->current_chunk : 0;
    }

    /* Find first chunk that is: not done AND not in flight */
    for (uint32_t i = 0; i < transfer->total_chunks; i++) {
        if (!p2p_bitmap_get(transfer->chunk_bitmap, i) &&
            !p2p_transfer_is_in_flight(transfer, i)) {
            return i;
        }
    }
    return transfer->total_chunks;  /* All requested or done */
}

/* =============================================================================
 * Timeout and Retry
 * ============================================================================= */

int p2p_transfer_check_timeouts(p2p_transfer_t *transfer, uint32_t *timed_out_chunks,
                                 uint8_t *count, uint8_t max_count) {
    if (!transfer || !timed_out_chunks || !count) return 0;

    *count = 0;
    uint64_t now = turbo_hrtime();
    uint64_t timeout_ns = (uint64_t)P2P_CHUNK_TIMEOUT_MS * 1000000ULL;

    for (uint8_t i = 0; i < transfer->in_flight_count && *count < max_count; i++) {
        p2p_in_flight_entry_t *entry = &transfer->in_flight[i];
        uint64_t elapsed = now - entry->request_time;

        if (elapsed >= timeout_ns) {
            if (entry->retry_count >= P2P_MAX_CHUNK_RETRIES) {
                /* Max retries exceeded - will be handled by caller */
                TLOG_ERROR("[Transfer] Chunk %u exceeded max retries (%d)",
                          entry->chunk_index, P2P_MAX_CHUNK_RETRIES);
                return -1;  /* Fatal error */
            }

            timed_out_chunks[(*count)++] = entry->chunk_index;
            entry->retry_count++;
            entry->request_time = now;  /* Reset timer for retry */

            TLOG_WARN("[Transfer] Chunk %u timed out, retry %d/%d",
                     entry->chunk_index, entry->retry_count, P2P_MAX_CHUNK_RETRIES);
        }
    }

    return *count > 0 ? 1 : 0;
}

void p2p_transfer_manager_tick(p2p_transfer_manager_t *mgr, p2p_node_t *node) {
    if (!mgr || !node) return;

    turbo_mutex_lock(&mgr->mutex);
    p2p_transfer_t *transfer = mgr->active;
    turbo_mutex_unlock(&mgr->mutex);

    while (transfer) {
        /* Only check active downloads */
        if (transfer->state == P2P_TRANSFER_ACTIVE &&
            transfer->direction == P2P_TRANSFER_DIR_DOWNLOAD &&
            transfer->in_flight_count > 0) {

            uint32_t timed_out[P2P_PARALLEL_CHUNKS];
            uint8_t timed_out_count = 0;

            int rc = p2p_transfer_check_timeouts(transfer, timed_out,
                                                  &timed_out_count, P2P_PARALLEL_CHUNKS);

            if (rc == -1) {
                /* Max retries exceeded - fail transfer */
                p2p_transfer_complete(transfer, 0, "Max retries exceeded");
            } else if (timed_out_count > 0) {
                /* Re-request timed out chunks */
                for (uint8_t i = 0; i < timed_out_count; i++) {
                    p2p_receiver_request_chunk(node, transfer, timed_out[i]);
                }
            }
        }

        turbo_mutex_lock(&mgr->mutex);
        transfer = transfer->next;
        turbo_mutex_unlock(&mgr->mutex);
    }
}

/* =============================================================================
 * Multi-source Download
 * ============================================================================= */

void p2p_transfer_enable_multi_source(p2p_transfer_t *transfer, int enable) {
    if (!transfer) return;
    transfer->multi_source_enabled = enable ? 1 : 0;
    TLOG_DEBUG("[Transfer] Multi-source %s for transfer #%u",
              enable ? "enabled" : "disabled", transfer->id);
}

int p2p_transfer_source_add(p2p_transfer_t *transfer, p2p_peer_t *peer) {
    if (!transfer || !peer) return P2P_ERR_INVALID_ARG;

    /* Check if already added */
    for (uint8_t i = 0; i < transfer->source_count; i++) {
        if (transfer->sources[i].peer == peer) {
            return P2P_OK;  /* Already a source */
        }
    }

    if (transfer->source_count >= P2P_MAX_SOURCES) {
        TLOG_WARN("[Transfer] Max sources reached for transfer #%u", transfer->id);
        return P2P_ERR_NO_MEM;
    }

    p2p_transfer_source_t *src = &transfer->sources[transfer->source_count];
    src->peer = peer;
    src->bytes_received = 0;
    src->last_activity = turbo_hrtime();
    src->active = 1;
    src->failure_count = 0;
    src->chunks_in_flight = 0;
    transfer->source_count++;

    TLOG_INFO("[Transfer] Added source %s:%d for transfer #%u (total: %d)",
             peer->ip, peer->port, transfer->id, transfer->source_count);

    return P2P_OK;
}

void p2p_transfer_source_remove(p2p_transfer_t *transfer, p2p_peer_t *peer) {
    if (!transfer || !peer) return;

    for (uint8_t i = 0; i < transfer->source_count; i++) {
        if (transfer->sources[i].peer == peer) {
            /* Mark as inactive rather than removing to preserve indices */
            transfer->sources[i].active = 0;
            TLOG_INFO("[Transfer] Removed source %s:%d from transfer #%u",
                     peer->ip, peer->port, transfer->id);
            return;
        }
    }
}

p2p_peer_t* p2p_transfer_select_source(p2p_transfer_t *transfer) {
    if (!transfer) return NULL;

    /* If multi-source not enabled, use primary peer */
    if (!transfer->multi_source_enabled || transfer->source_count == 0) {
        return transfer->peer;
    }

    /* Round-robin selection among active sources with lowest in-flight count */
    p2p_peer_t *best = NULL;
    uint8_t best_in_flight = 255;
    uint8_t start = transfer->next_source_index;

    for (uint8_t i = 0; i < transfer->source_count; i++) {
        uint8_t idx = (start + i) % transfer->source_count;
        p2p_transfer_source_t *src = &transfer->sources[idx];

        if (src->active && src->peer && src->chunks_in_flight < best_in_flight) {
            best = src->peer;
            best_in_flight = src->chunks_in_flight;
            transfer->next_source_index = (idx + 1) % transfer->source_count;
        }
    }

    return best ? best : transfer->peer;
}

void p2p_transfer_source_received(p2p_transfer_t *transfer, p2p_peer_t *peer, size_t bytes) {
    if (!transfer || !peer) return;

    for (uint8_t i = 0; i < transfer->source_count; i++) {
        if (transfer->sources[i].peer == peer) {
            transfer->sources[i].bytes_received += bytes;
            transfer->sources[i].last_activity = turbo_hrtime();
            transfer->sources[i].failure_count = 0;  /* Reset on success */
            if (transfer->sources[i].chunks_in_flight > 0) {
                transfer->sources[i].chunks_in_flight--;
            }
            return;
        }
    }
}

void p2p_transfer_source_failed(p2p_transfer_t *transfer, p2p_peer_t *peer) {
    if (!transfer || !peer) return;

    for (uint8_t i = 0; i < transfer->source_count; i++) {
        if (transfer->sources[i].peer == peer) {
            transfer->sources[i].failure_count++;
            if (transfer->sources[i].chunks_in_flight > 0) {
                transfer->sources[i].chunks_in_flight--;
            }

            /* Deactivate after 3 consecutive failures */
            if (transfer->sources[i].failure_count >= 3) {
                transfer->sources[i].active = 0;
                TLOG_WARN("[Transfer] Source %s:%d deactivated after %d failures",
                         peer->ip, peer->port, transfer->sources[i].failure_count);
            }
            return;
        }
    }
}

int p2p_transfer_add_in_flight_multi(p2p_transfer_t *transfer, uint32_t chunk_index,
                                      uint8_t source_index) {
    if (!transfer || transfer->in_flight_count >= P2P_PARALLEL_CHUNKS) {
        return 0;
    }

    /* Find empty slot */
    for (uint8_t i = 0; i < P2P_PARALLEL_CHUNKS; i++) {
        if (transfer->in_flight[i].chunk_index == UINT32_MAX ||
            transfer->in_flight[i].request_time == 0) {
            transfer->in_flight[i].chunk_index = chunk_index;
            transfer->in_flight[i].request_time = turbo_hrtime();
            transfer->in_flight[i].retry_count = 0;
            transfer->in_flight[i].source_index = source_index;
            transfer->in_flight_count++;

            /* Update source in-flight count */
            if (source_index < transfer->source_count) {
                transfer->sources[source_index].chunks_in_flight++;
            }

            return 1;
        }
    }
    return 0;
}

uint8_t p2p_transfer_get_chunk_source(p2p_transfer_t *transfer, uint32_t chunk_index) {
    if (!transfer) return 255;

    for (uint8_t i = 0; i < P2P_PARALLEL_CHUNKS; i++) {
        if (transfer->in_flight[i].chunk_index == chunk_index &&
            transfer->in_flight[i].request_time != 0) {
            return transfer->in_flight[i].source_index;
        }
    }
    return 255;  /* Not found */
}
