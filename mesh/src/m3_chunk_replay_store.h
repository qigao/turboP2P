#ifndef M3_CHUNK_REPLAY_STORE_H
#define M3_CHUNK_REPLAY_STORE_H

#include "m3_chunk_replay.h"

#include <turbo_fs.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  M3_CHUNK_REPLAY_STORE_OK = 0,
  M3_CHUNK_REPLAY_STORE_INVALID_ARG = -1,
  M3_CHUNK_REPLAY_STORE_LOCKED = -2,
  M3_CHUNK_REPLAY_STORE_IO = -3,
  M3_CHUNK_REPLAY_STORE_CORRUPT = -4,
  M3_CHUNK_REPLAY_STORE_RESOURCE_EXHAUSTED = -5,
  M3_CHUNK_REPLAY_STORE_CONFLICT = -6,
  M3_CHUNK_REPLAY_STORE_EXPIRED = -7,
  M3_CHUNK_REPLAY_STORE_NOT_FOUND = -8,
  M3_CHUNK_REPLAY_STORE_CRYPTO_FAILED = -9,
} m3_chunk_replay_store_result_t;

/**
 * Durable owner of one bounded replay journal.
 *
 * The struct must be zero-initialized before open. Calls are single-owner and
 * not thread-safe. The snapshot format is versioned and never auto-migrated.
 */
typedef struct {
  m3_chunk_replay_journal_v1_t journal;
  char path[TURBO_FS_MAX_PATH];
  char temp_path[TURBO_FS_MAX_PATH];
  char lock_path[TURBO_FS_MAX_PATH];
  turbo_file_t lock_file;
  uint64_t generation;
  uint8_t open;
} m3_chunk_replay_store_v1_t;

m3_chunk_replay_store_result_t m3_chunk_replay_store_open_v1(
    m3_chunk_replay_store_v1_t *store, const char *path, size_t capacity,
    uint64_t max_ttl_ms, uint64_t now_ms,
    size_t *out_recovered_in_progress);

void m3_chunk_replay_store_close_v1(
    m3_chunk_replay_store_v1_t *store);

m3_chunk_replay_store_result_t m3_chunk_replay_store_begin_v1(
    m3_chunk_replay_store_v1_t *store,
    const m3_chunk_authorized_access_v1_t *access, uint64_t now_ms,
    m3_chunk_replay_begin_v1_t *out_begin);

m3_chunk_replay_store_result_t m3_chunk_replay_store_complete_v1(
    m3_chunk_replay_store_v1_t *store,
    const m3_chunk_authorized_access_v1_t *access, int32_t result_code);

m3_chunk_replay_store_result_t m3_chunk_replay_store_sweep_v1(
    m3_chunk_replay_store_v1_t *store, uint64_t now_ms,
    size_t *out_removed);

#ifdef __cplusplus
}
#endif

#endif
