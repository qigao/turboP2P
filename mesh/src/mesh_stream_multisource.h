#ifndef TURBO_P2P_MESH_STREAM_MULTISOURCE_H
#define TURBO_P2P_MESH_STREAM_MULTISOURCE_H

#include "mesh_stream_source_selector.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  MESH_STREAM_MULTISOURCE_OK = 0,
  MESH_STREAM_MULTISOURCE_AGAIN = 1,
  MESH_STREAM_MULTISOURCE_END = 2,
  MESH_STREAM_MULTISOURCE_INVALID_ARG = -1,
  MESH_STREAM_MULTISOURCE_BUSY = -2,
  MESH_STREAM_MULTISOURCE_INTEGRITY = -3,
  MESH_STREAM_MULTISOURCE_IO = -4,
  MESH_STREAM_MULTISOURCE_RESOURCE_EXHAUSTED = -5,
  MESH_STREAM_MULTISOURCE_FAILED = -6,
} mesh_stream_multisource_result_t;

/**
 * Async block fetch transport. start begins fetching block seq from
 * source_index into out (cap bytes) and returns 0 with *out_handle set, or <0
 * when the source cannot serve it (the caller reports a failure). poll returns
 * 0 when bytes are ready (*out_len set), 1 while pending, -1 on failure.
 * cancel aborts a pending handle. The io is not owned.
 */
typedef struct {
  int (*start)(void *context, size_t source_index, uint64_t seq, uint8_t *out,
               size_t cap, void **out_handle);
  int (*poll)(void *context, void *handle, size_t *out_len);
  void (*cancel)(void *context, void *handle);
  void *context;
} mesh_stream_multisource_io_v1_t;

typedef struct mesh_stream_multisource_s mesh_stream_multisource_t;

/**
 * Create a multi-source block puller. The selector is borrowed and updated
 * with per-fetch outcomes (bad sources are disabled at the selector
 * threshold). block_digests holds the SHA-256 of every block; blocks are
 * fetched across sources in parallel (up to max_pending in flight), verified,
 * retried on failure/timeout up to max_retries, and delivered in order.
 */
mesh_stream_multisource_t *mesh_stream_multisource_create(
    mesh_stream_source_selector_v1_t *selector,
    const mesh_stream_multisource_io_v1_t *io,
    const uint8_t block_digests[MESH_STREAM_DATA_HASH_SIZE], size_t block_count,
    uint64_t block_size, size_t max_pending, uint64_t fetch_timeout_ms,
    size_t max_retries);
void mesh_stream_multisource_destroy(mesh_stream_multisource_t *ms);

/**
 * Advance the pulls: poll in-flight fetches (verify / retry on failure or
 * timeout), report outcomes to the selector, and start fetches for the lowest
 * undone blocks across the best available sources. now_ms is the owner's
 * monotonic clock.
 */
mesh_stream_multisource_result_t mesh_stream_multisource_tick(
    mesh_stream_multisource_t *ms, uint64_t now_ms);

/** Deliver the next ordered block; AGAIN while waiting, END when complete. */
mesh_stream_multisource_result_t mesh_stream_multisource_recv(
    mesh_stream_multisource_t *ms, uint8_t *out, size_t cap, size_t *out_len);

int mesh_stream_multisource_complete(const mesh_stream_multisource_t *ms);

#ifdef __cplusplus
}
#endif

#endif
