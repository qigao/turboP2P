#ifndef MESH_CONTROL_CHECKPOINT_STORE_H
#define MESH_CONTROL_CHECKPOINT_STORE_H

#include "mesh_control_checkpoint.h"
#include "turbo_fs.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  MESH_CONTROL_CHECKPOINT_STORE_OK = 0,
  MESH_CONTROL_CHECKPOINT_STORE_INVALID_ARG = -1,
  MESH_CONTROL_CHECKPOINT_STORE_INVALID_STATE = -2,
  MESH_CONTROL_CHECKPOINT_STORE_IO = -3,
  MESH_CONTROL_CHECKPOINT_STORE_LOCKED = -4,
  MESH_CONTROL_CHECKPOINT_STORE_CORRUPT = -5,
  MESH_CONTROL_CHECKPOINT_STORE_RESOURCE_EXHAUSTED = -6,
  MESH_CONTROL_CHECKPOINT_STORE_BINDING_MISMATCH = -7,
  MESH_CONTROL_CHECKPOINT_STORE_AUTH_FAILED = -8
} mesh_control_checkpoint_store_result_t;

#define MESH_CONTROL_CHECKPOINT_STORE_AUTH_KEY_SIZE_V1 32u
#define MESH_CONTROL_CHECKPOINT_STORE_AUTH_TAG_SIZE_V1 32u

/**
 * Single-writer synchronous checkpoint store. Every call may block on file
 * I/O and therefore must run on a dedicated worker, never on a CoroNet/Iris
 * event loop or transport callback.
 */
typedef struct {
  char path[TURBO_FS_MAX_PATH];
  char temp_path[TURBO_FS_MAX_PATH + 5u];
  char lock_path[TURBO_FS_MAX_PATH + 6u];
  turbo_file_t lock_file;
  uint8_t authentication_key[MESH_CONTROL_CHECKPOINT_STORE_AUTH_KEY_SIZE_V1];
  uint8_t open;
  uint8_t authenticated;
} mesh_control_checkpoint_store_v1_t;

/** Acquires an exclusive nonblocking lock. path must be absolute. */
mesh_control_checkpoint_store_result_t
mesh_control_checkpoint_store_open_v1(mesh_control_checkpoint_store_v1_t *store, const char *path);

/** Opens a production store whose file carries an HMAC-SHA256 tail tag. */
mesh_control_checkpoint_store_result_t mesh_control_checkpoint_store_open_authenticated_v1(
    mesh_control_checkpoint_store_v1_t *store, const char *path,
    const uint8_t authentication_key[MESH_CONTROL_CHECKPOINT_STORE_AUTH_KEY_SIZE_V1]);

/**
 * Loads and atomically restores an existing checkpoint. A missing file is a
 * successful first start with out_found=0; malformed or mismatched files fail
 * closed and leave owner unchanged.
 */
mesh_control_checkpoint_store_result_t
mesh_control_checkpoint_store_load_v1(const mesh_control_checkpoint_store_v1_t *store,
                                      mesh_control_owner_v1_t *owner, uint64_t now_ms,
                                      uint8_t *out_found);

/** Writes temp -> fsync(file) -> close -> atomic rename. */
mesh_control_checkpoint_store_result_t
mesh_control_checkpoint_store_save_v1(const mesh_control_checkpoint_store_v1_t *store,
                                      const mesh_control_owner_v1_t *owner);

/**
 * Persists an already encoded immutable checkpoint. The caller retains bytes
 * for the duration of this synchronous call. Intended for a persistence
 * worker after the owner thread has produced a bounded canonical snapshot.
 */
mesh_control_checkpoint_store_result_t
mesh_control_checkpoint_store_save_bytes_v1(const mesh_control_checkpoint_store_v1_t *store,
                                            const uint8_t *bytes, size_t size);

void mesh_control_checkpoint_store_close_v1(mesh_control_checkpoint_store_v1_t *store);

#ifdef __cplusplus
}
#endif

#endif
