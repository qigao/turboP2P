#ifndef TURBO_P2P_MESH_SYNC_ENGINE_H
#define TURBO_P2P_MESH_SYNC_ENGINE_H

#include "m3_object_manifest.h"

#include <turbo_fs.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  MESH_SYNC_OK = 0,
  MESH_SYNC_AGAIN = 1,
  MESH_SYNC_END = 2,
  MESH_SYNC_INVALID_ARG = -1,
  MESH_SYNC_BUSY = -2,
  MESH_SYNC_INTEGRITY = -3,
  MESH_SYNC_IO = -4,
  MESH_SYNC_RESOURCE_EXHAUSTED = -5,
} mesh_sync_result_t;

typedef enum {
  MESH_SYNC_CONFLICT_LAST_WRITER_WINS = 1,
  MESH_SYNC_CONFLICT_KEEP_BOTH = 2,
} mesh_sync_conflict_policy_v1_t;

/**
 * Synchronous block fetch. Returns 0 with *out_len set when the chunk was
 * fetched (bytes must match the manifest chunk size), 1 when the fetch is
 * pending (caller retries), or <0 on failure.
 */
typedef struct {
  int (*fetch_chunk)(void *context, size_t chunk_index, uint8_t *out,
                     size_t cap, size_t *out_len);
  void *context;
} mesh_sync_io_v1_t;

typedef struct {
  mesh_sync_io_v1_t io;
  mesh_sync_conflict_policy_v1_t conflict_policy;
  char state_path[TURBO_FS_MAX_PATH];
  char output_path[TURBO_FS_MAX_PATH];
  uint64_t max_object_bytes;
  size_t max_chunks;
  uint64_t max_chunk_bytes;
} mesh_sync_config_v1_t;

typedef struct mesh_sync_prev_chunk_s mesh_sync_prev_chunk_v1_t;

typedef struct {
  mesh_sync_config_v1_t config;
  m3_object_manifest_owned_v2_t source;
  uint8_t *present;
  size_t present_count;
  char temp_path[TURBO_FS_MAX_PATH];
  char conflict_path[TURBO_FS_MAX_PATH];
  char local_read_path[TURBO_FS_MAX_PATH];
  turbo_file_t temp_file;
  turbo_file_t local_file;
  uint8_t *scratch;
  uint64_t *local_offsets;   /* per source chunk: offset in old output or SIZE_MAX */
  mesh_sync_prev_chunk_v1_t *prev_chunks; /* previous committed version's chunks */
  size_t prev_count;
  uint64_t write_offset;
  uint8_t temp_open;
  uint8_t conflict;
  uint8_t complete;
  uint8_t open;
} mesh_sync_engine_v1_t;

/**
 * Initialize a sync of `manifest_bytes` (a V2 object manifest) into
 * output_path. Loads the resume state: matching version resumes from the
 * present bitmap; a different committed version triggers the conflict policy
 * (LAST_WRITER_WINS overwrites, KEEP_BOTH renames the old file to
 * <output>.conflict-<version-hex>). The caller must zero-initialize the
 * engine before the first init call.
 */
mesh_sync_result_t mesh_sync_engine_init_v1(
    mesh_sync_engine_v1_t *engine, const mesh_sync_config_v1_t *config,
    const uint8_t *manifest_bytes, size_t manifest_size);

void mesh_sync_engine_destroy_v1(mesh_sync_engine_v1_t *engine);

/**
 * Fetch and verify the lowest missing chunk, write it into the temp file and
 * checkpoint the resume state. Returns AGAIN while a fetch is pending, END
 * once the file is atomically published (temp verified + renamed), or an
 * error. The engine fetches chunks in order, so the temp is written
 * sequentially and resume continues from the last verified chunk.
 */
mesh_sync_result_t mesh_sync_engine_pump_v1(mesh_sync_engine_v1_t *engine);

int mesh_sync_engine_complete(const mesh_sync_engine_v1_t *engine);

/** Non-zero when the output was replaced or a conflict copy was kept. */
uint8_t mesh_sync_engine_conflict(const mesh_sync_engine_v1_t *engine);

/** Conflict copy path (KEEP_BOTH) or NULL when none. */
const char *mesh_sync_engine_conflict_path(const mesh_sync_engine_v1_t *engine);

#ifdef __cplusplus
}
#endif

#endif
