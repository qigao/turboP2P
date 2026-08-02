#ifndef M3_CHUNK_STORE_H
#define M3_CHUNK_STORE_H

#include <turbo_fs.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define M3_CHUNK_CID_DIGEST_SIZE 32u
#define M3_CHUNK_STORE_HASH_ALGORITHM_SHA256 1u

typedef enum {
  M3_CHUNK_STORE_OK = 0,
  M3_CHUNK_STORE_INVALID_ARG = -1,
  M3_CHUNK_STORE_IO = -2,
  M3_CHUNK_STORE_NOT_FOUND = -3,
  M3_CHUNK_STORE_CORRUPT = -4,
  M3_CHUNK_STORE_DIGEST_MISMATCH = -5,
  M3_CHUNK_STORE_RESOURCE_EXHAUSTED = -6,
  M3_CHUNK_STORE_LOCKED = -7,
  M3_CHUNK_STORE_CSPRNG_FAILED = -8,
} m3_chunk_store_result_t;

typedef struct {
  uint8_t hash_algorithm;
  uint64_t size;
  uint8_t digest[M3_CHUNK_CID_DIGEST_SIZE];
} m3_chunk_cid_v1_t;

typedef struct {
  char root[TURBO_FS_MAX_PATH];
  char chunks_path[TURBO_FS_MAX_PATH];
  char temp_path[TURBO_FS_MAX_PATH];
  char lock_path[TURBO_FS_MAX_PATH];
  turbo_file_t lock_file;
  uint64_t max_chunk_bytes;
  uint8_t open;
} m3_chunk_store_v1_t;

/**
 * Calculate a versioned immutable content identity for bounded bytes.
 *
 * The caller retains ownership of bytes. A zero-length chunk may use NULL.
 */
m3_chunk_store_result_t m3_chunk_cid_calculate_v1(
    const uint8_t *bytes, size_t size, m3_chunk_cid_v1_t *out_cid);

/**
 * Open one process-exclusive local CAS rooted at an absolute host path.
 *
 * The root parent must already exist. The store creates and validates its
 * versioned internal directories without following symbolic links.
 */
m3_chunk_store_result_t m3_chunk_store_open_v1(
    m3_chunk_store_v1_t *store, const char *root, uint64_t max_chunk_bytes);

/**
 * Close the store. Callers must externally exclude concurrent operations.
 */
void m3_chunk_store_close_v1(m3_chunk_store_v1_t *store);

/**
 * Publish bytes after verifying the caller-provided CID.
 *
 * Publication uses a CSPRNG-named temporary file, file fsync, and same-volume
 * atomic rename. An existing valid CID is idempotent. Existing corrupt bytes
 * are never overwritten. out_created is set to one only for a new publish.
 */
m3_chunk_store_result_t m3_chunk_store_put_bytes_v1(
    m3_chunk_store_v1_t *store, const m3_chunk_cid_v1_t *expected_cid,
    const uint8_t *bytes, size_t size, uint8_t *out_created);

/**
 * Read an exact range after validating the complete immutable chunk.
 *
 * offset and length must fit within cid->size. buffer must provide length
 * bytes. On integrity failure, out_read remains zero and buffer is unusable.
 */
m3_chunk_store_result_t m3_chunk_store_read_range_v1(
    const m3_chunk_store_v1_t *store, const m3_chunk_cid_v1_t *cid,
    uint64_t offset, size_t length, uint8_t *buffer, size_t *out_read);

#ifdef __cplusplus
}
#endif

#endif
