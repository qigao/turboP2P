#ifndef M3_CHUNK_ACCESS_STORE_H
#define M3_CHUNK_ACCESS_STORE_H

#include "m3_chunk_capability.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  M3_CHUNK_ACCESS_STORE_OK = 0,
  M3_CHUNK_ACCESS_STORE_INVALID_ARG = -1,
  M3_CHUNK_ACCESS_STORE_INVALID_ACCESS = -2,
  M3_CHUNK_ACCESS_STORE_EXPIRED = -3,
  M3_CHUNK_ACCESS_STORE_RESOURCE_EXHAUSTED = -4,
  M3_CHUNK_ACCESS_STORE_NOT_FOUND = -5,
  M3_CHUNK_ACCESS_STORE_CORRUPT = -6,
  M3_CHUNK_ACCESS_STORE_DIGEST_MISMATCH = -7,
  M3_CHUNK_ACCESS_STORE_IO = -8,
  M3_CHUNK_ACCESS_STORE_CSPRNG_FAILED = -9,
  M3_CHUNK_ACCESS_STORE_LOCKED = -10,
} m3_chunk_access_store_result_t;

/**
 * Publish a complete immutable chunk through an authorized PUT.
 *
 * The access must target the complete CID and remain live at now_ms.
 * out_created is zeroed before any validation.
 */
m3_chunk_access_store_result_t m3_chunk_access_store_put_v1(
    m3_chunk_store_v1_t *store,
    const m3_chunk_authorized_access_v1_t *access, uint64_t now_ms,
    const uint8_t *bytes, size_t size, uint8_t *out_created);

/**
 * Read the exact range carried by an authorized READ.
 *
 * The caller provides access->range_length bytes. The store validates the
 * complete chunk CID before out_read becomes nonzero.
 */
m3_chunk_access_store_result_t m3_chunk_access_store_read_v1(
    const m3_chunk_store_v1_t *store,
    const m3_chunk_authorized_access_v1_t *access, uint64_t now_ms,
    uint8_t *buffer, size_t buffer_size, size_t *out_read);

#ifdef __cplusplus
}
#endif

#endif
