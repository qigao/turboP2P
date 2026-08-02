#ifndef P2P_TRANSFER_H
#define P2P_TRANSFER_H

#include "../core/types.h"
#include "sha256.h"
#include "bitmap.h"

#include <platform.h>
#include <stdio.h>

/* Compatibility defines for transfer state */
#define P2P_TRANSFER_PENDING     P2P_TRANSFER_STATE_PENDING
#define P2P_TRANSFER_ACTIVE      P2P_TRANSFER_STATE_ACTIVE
#define P2P_TRANSFER_PAUSED      P2P_TRANSFER_STATE_PAUSED
#define P2P_TRANSFER_COMPLETED   P2P_TRANSFER_STATE_COMPLETED
#define P2P_TRANSFER_FAILED      P2P_TRANSFER_STATE_FAILED
#define P2P_TRANSFER_CANCELLED   P2P_TRANSFER_STATE_FAILED  /* Map to FAILED */

/* Resume constants */
#define P2P_RESUME_SAVE_INTERVAL 10  /* Save state every N chunks */

#define P2P_DEFAULT_CHUNK_SIZE   (32 * 1024)  /* 32KB */
#define P2P_MAX_CHUNK_SIZE       (64 * 1024)  /* 64KB */
#define P2P_TRANSFER_TIMEOUT_MS  30000        /* 30s */
#define P2P_PARALLEL_CHUNKS      4            /* Max concurrent chunk requests */
#define P2P_CHUNK_TIMEOUT_MS     5000         /* 5s per chunk timeout */
#define P2P_MAX_CHUNK_RETRIES    3            /* Max retries per chunk */
#define P2P_MAX_SOURCES          8            /* Max concurrent source peers */

typedef enum {
    P2P_TRANSFER_DIR_DOWNLOAD = 0,
    P2P_TRANSFER_DIR_UPLOAD,
} p2p_transfer_dir_t;

/* Source peer tracking for multi-source downloads */
typedef struct {
    p2p_peer_t *peer;
    uint64_t bytes_received;     /* Total bytes from this source */
    uint64_t last_activity;      /* Last data received time */
    uint8_t active;              /* Is this source currently active */
    uint8_t failure_count;       /* Number of consecutive failures */
    uint8_t chunks_in_flight;    /* Chunks currently requested from this source */
} p2p_transfer_source_t;

/* In-flight chunk tracking with timeout support */
typedef struct {
    uint32_t chunk_index;
    uint64_t request_time;       /* Time when chunk was requested */
    uint8_t retry_count;         /* Number of retries for this chunk */
    uint8_t source_index;        /* Which source peer (for multi-source) */
} p2p_in_flight_entry_t;

typedef struct p2p_transfer_s {
    struct p2p_transfer_manager_s *manager;
    uint32_t id;
    uint32_t remote_id;                 /* Remote peer's transfer ID (for dir transfers) */
    p2p_id_t file_id;
    p2p_transfer_dir_t direction;

    char filepath[P2P_MAX_FILEPATH];
    char filename[P2P_MAX_FILENAME];
    FILE *fp;
    size_t file_size;

    size_t chunk_size;
    uint32_t total_chunks;
    uint32_t current_chunk;
    size_t bytes_transferred;

    uint8_t file_hash[P2P_SHA256_DIGEST_SIZE];
    p2p_sha256_ctx_t hash_ctx;

    p2p_transfer_state_t state;
    int error_code;

    uint64_t start_time;
    uint64_t last_activity;

    p2p_transfer_progress_cb progress_cb;
    p2p_transfer_complete_cb complete_cb;
    void *user_data;

    p2p_peer_t *peer;                         /* Primary peer (single-source) */

    /* Bounded FILE_GET response arbitration */
    p2p_peer_t *request_peers[P2P_MAX_SOURCES];
    uint8_t request_peer_done[P2P_MAX_SOURCES];
    uint8_t request_peer_count;
    uint8_t response_count;

    /* Multi-source download support */
    p2p_transfer_source_t sources[P2P_MAX_SOURCES];
    uint8_t source_count;                     /* Number of active sources */
    uint8_t multi_source_enabled;             /* Enable multi-source download */
    uint8_t next_source_index;                /* Round-robin counter */

    /* Resume support */
    roaring_bitmap_t *chunk_bitmap;

    char resume_path[P2P_MAX_FILEPATH];
    int resuming;
    uint32_t chunks_since_save;

    /* Parallel chunk requests */
    p2p_in_flight_entry_t in_flight[P2P_PARALLEL_CHUNKS];  /* Chunks currently requested */
    uint8_t in_flight_count;                  /* Number of in-flight requests */
    uint8_t parallel_enabled;                 /* Enable parallel requests */
    uint8_t destroying;
    uint32_t ref_count;
    turbo_mutex_t mutex;

    struct p2p_transfer_s *next;
} p2p_transfer_t;

struct p2p_transfer_manager_s {
    p2p_transfer_t *active;
    uint32_t count;
    uint32_t next_id;
    turbo_mutex_t mutex;
};

void p2p_transfer_manager_init(p2p_transfer_manager_t *mgr);
void p2p_transfer_manager_destroy(p2p_transfer_manager_t *mgr);

p2p_transfer_t* p2p_transfer_create(p2p_transfer_manager_t *mgr, p2p_transfer_dir_t dir);
void p2p_transfer_destroy(p2p_transfer_manager_t *mgr, p2p_transfer_t *transfer);
p2p_transfer_t* p2p_transfer_find_by_id(p2p_transfer_manager_t *mgr, uint32_t id);
p2p_transfer_t* p2p_transfer_find_upload_by_remote_id(
    p2p_transfer_manager_t *mgr, uint32_t remote_id, p2p_peer_t *peer);
void p2p_transfer_release(p2p_transfer_t *transfer);

int p2p_transfer_open_file(p2p_transfer_t *transfer, const char *mode);
void p2p_transfer_close_file(p2p_transfer_t *transfer);
int p2p_transfer_open_file_locked(p2p_transfer_t *transfer, const char *mode);
void p2p_transfer_close_file_locked(p2p_transfer_t *transfer);

void p2p_transfer_update_progress(p2p_transfer_t *transfer, size_t bytes);
void p2p_transfer_complete(p2p_transfer_t *transfer, int success, const char *error);
void p2p_transfer_snapshot_peer_info(p2p_peer_t *peer, p2p_peer_info_ex_t *info);

size_t p2p_transfer_calc_chunk_count(size_t file_size, size_t chunk_size);
size_t p2p_transfer_get_chunk_offset(p2p_transfer_t *transfer, uint32_t chunk_index);
size_t p2p_transfer_get_chunk_size(p2p_transfer_t *transfer, uint32_t chunk_index);
size_t p2p_transfer_get_chunk_offset_locked(p2p_transfer_t *transfer, uint32_t chunk_index);
size_t p2p_transfer_get_chunk_size_locked(p2p_transfer_t *transfer, uint32_t chunk_index);

/* p2p_transfer_status_t is defined in p2p.h (public API) */

/* Transfer control */
int p2p_transfer_mgr_pause(p2p_transfer_manager_t *mgr, uint32_t transfer_id);
int p2p_transfer_mgr_resume(p2p_transfer_manager_t *mgr, uint32_t transfer_id,
                             p2p_node_t *node);
int p2p_transfer_mgr_cancel(p2p_transfer_manager_t *mgr, uint32_t transfer_id);
int p2p_transfer_mgr_get_status(p2p_transfer_manager_t *mgr, uint32_t transfer_id,
                                 p2p_transfer_status_t *status);
/* Bitmap management */
int p2p_transfer_init_bitmap(p2p_transfer_t *transfer);
void p2p_transfer_free_bitmap(p2p_transfer_t *transfer);
void p2p_transfer_mark_chunk_done(p2p_transfer_t *transfer, uint32_t chunk_index);
uint32_t p2p_transfer_next_chunk(p2p_transfer_t *transfer);
int p2p_transfer_init_bitmap_locked(p2p_transfer_t *transfer);
void p2p_transfer_free_bitmap_locked(p2p_transfer_t *transfer);
void p2p_transfer_mark_chunk_done_locked(p2p_transfer_t *transfer, uint32_t chunk_index);
uint32_t p2p_transfer_next_chunk_locked(p2p_transfer_t *transfer);

/* Parallel chunk requests */
void p2p_transfer_enable_parallel(p2p_transfer_t *transfer, int enable);
int p2p_transfer_add_in_flight(p2p_transfer_t *transfer, uint32_t chunk_index);
void p2p_transfer_remove_in_flight(p2p_transfer_t *transfer, uint32_t chunk_index);
int p2p_transfer_is_in_flight(p2p_transfer_t *transfer, uint32_t chunk_index);
uint32_t p2p_transfer_get_next_to_request(p2p_transfer_t *transfer);
int p2p_transfer_add_in_flight_locked(p2p_transfer_t *transfer, uint32_t chunk_index);
void p2p_transfer_remove_in_flight_locked(p2p_transfer_t *transfer, uint32_t chunk_index);
int p2p_transfer_is_in_flight_locked(p2p_transfer_t *transfer, uint32_t chunk_index);
uint32_t p2p_transfer_get_next_to_request_locked(p2p_transfer_t *transfer);

/* Timeout and retry */
int p2p_transfer_check_timeouts(p2p_transfer_t *transfer, uint32_t *timed_out_chunks,
                                 uint8_t *count, uint8_t max_count);
int p2p_transfer_check_timeouts_locked(p2p_transfer_t *transfer, uint32_t *timed_out_chunks,
                                        uint8_t *count, uint8_t max_count);
void p2p_transfer_manager_tick(p2p_transfer_manager_t *mgr, p2p_node_t *node);

/* Multi-source download */
void p2p_transfer_enable_multi_source(p2p_transfer_t *transfer, int enable);
int p2p_transfer_source_add(p2p_transfer_t *transfer, p2p_peer_t *peer);
void p2p_transfer_source_remove(p2p_transfer_t *transfer, p2p_peer_t *peer);
p2p_peer_t* p2p_transfer_select_source(p2p_transfer_t *transfer);
void p2p_transfer_source_received(p2p_transfer_t *transfer, p2p_peer_t *peer, size_t bytes);
void p2p_transfer_source_failed(p2p_transfer_t *transfer, p2p_peer_t *peer);
int p2p_transfer_add_in_flight_multi(p2p_transfer_t *transfer, uint32_t chunk_index,
                                      uint8_t source_index);
uint8_t p2p_transfer_get_chunk_source(p2p_transfer_t *transfer, uint32_t chunk_index);
int p2p_transfer_source_add_locked(p2p_transfer_t *transfer, p2p_peer_t *peer);
void p2p_transfer_source_remove_locked(p2p_transfer_t *transfer, p2p_peer_t *peer);
p2p_peer_t* p2p_transfer_select_source_locked(p2p_transfer_t *transfer);
void p2p_transfer_source_received_locked(p2p_transfer_t *transfer, p2p_peer_t *peer, size_t bytes);
void p2p_transfer_source_failed_locked(p2p_transfer_t *transfer, p2p_peer_t *peer);
int p2p_transfer_add_in_flight_multi_locked(p2p_transfer_t *transfer, uint32_t chunk_index,
                                             uint8_t source_index);
uint8_t p2p_transfer_get_chunk_source_locked(p2p_transfer_t *transfer, uint32_t chunk_index);

#endif /* P2P_TRANSFER_H */
