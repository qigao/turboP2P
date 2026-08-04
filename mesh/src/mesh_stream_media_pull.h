#ifndef TURBO_P2P_MESH_STREAM_MEDIA_PULL_H
#define TURBO_P2P_MESH_STREAM_MEDIA_PULL_H

#include "mesh_media_index.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* P8: on-demand media range pull. Given an M3 object manifest (one media
 * rendition) and a byte range (HTTP Range/206 or a segment seek), resolve the
 * range to the covering chunk span through the media index, fetch exactly
 * those chunks through a pluggable fetch io (multi-source capable), verify
 * each chunk's SHA-256 and assemble the requested byte window. The manifest
 * and the derived index stay the single fact sources. */

typedef enum {
  MESH_STREAM_MEDIA_PULL_OK = 0,
  MESH_STREAM_MEDIA_PULL_AGAIN = 1,
  MESH_STREAM_MEDIA_PULL_INVALID_ARG = -1,
  MESH_STREAM_MEDIA_PULL_OUT_OF_RANGE = -2,
  MESH_STREAM_MEDIA_PULL_IO = -3,
  MESH_STREAM_MEDIA_PULL_INTEGRITY = -4,
  MESH_STREAM_MEDIA_PULL_RESOURCE_EXHAUSTED = -5,
} mesh_stream_media_pull_result_t;

/** Synchronous chunk fetch: 0 with *out_len set (bytes must match the
 * manifest chunk size), 1 when pending (caller retries), <0 on failure. */
typedef struct {
  int (*fetch_chunk)(void *context, size_t chunk_index, uint8_t *out,
                     size_t cap, size_t *out_len);
  void *context;
} mesh_stream_media_pull_io_v1_t;

typedef struct {
  mesh_stream_media_pull_io_v1_t io;
  uint64_t max_chunk_bytes;        /* >= every manifest chunk size */
  uint64_t target_segment_bytes;   /* media index segment granularity */
} mesh_stream_media_pull_config_v1_t;

typedef struct {
  m3_object_manifest_v2_t manifest; /* borrowed view */
  mesh_media_index_v1_t index;      /* owned (built from the manifest) */
  mesh_stream_media_pull_io_v1_t io;
  uint8_t *scratch;
  uint64_t max_chunk_bytes;

  uint64_t window_start;   /* object byte offset of the requested window */
  uint64_t window_len;
  uint64_t window_offset;  /* window start within the first chunk */
  uint64_t chunk_offset;   /* object byte offset of the next chunk to fetch */
  size_t first_chunk;
  size_t chunk_count;
  size_t next_chunk;
  uint8_t started;
  uint8_t done;
} mesh_stream_media_pull_v1_t;

/** Build the media index and prepare the pull. The manifest view must outlive
 * the pull. The caller zero-initializes the pull before the first init. */
mesh_stream_media_pull_result_t mesh_stream_media_pull_init_v1(
    mesh_stream_media_pull_v1_t *pull, const m3_object_manifest_v2_t *manifest,
    const mesh_stream_media_pull_config_v1_t *config);

void mesh_stream_media_pull_destroy_v1(mesh_stream_media_pull_v1_t *pull);

/** Resolve a byte range into the covering chunk span + window (Range/206
 * planning). byte_start at/after the object end fails with OUT_OF_RANGE
 * (HTTP 416); byte_len is clamped to the object end. */
mesh_stream_media_pull_result_t mesh_stream_media_pull_resolve_v1(
    const mesh_stream_media_pull_v1_t *pull, uint64_t byte_start,
    uint64_t byte_len, size_t *out_first_chunk, size_t *out_chunk_count,
    uint64_t *out_window_offset, uint64_t *out_window_len);

/** Start a range pull for [byte_start, byte_start + byte_len). */
mesh_stream_media_pull_result_t mesh_stream_media_pull_start_v1(
    mesh_stream_media_pull_v1_t *pull, uint64_t byte_start, uint64_t byte_len);

/**
 * Fetch, verify and assemble the window into out (cap must be >= the window
 * length). Returns OK with *out_len = window_len once the window is
 * assembled, AGAIN while a chunk fetch is pending, or an error. The caller
 * retries pump until OK.
 */
mesh_stream_media_pull_result_t mesh_stream_media_pull_pump_v1(
    mesh_stream_media_pull_v1_t *pull, uint8_t *out, size_t cap,
    size_t *out_len);

/** True once the requested window was fully assembled. */
int mesh_stream_media_pull_complete(const mesh_stream_media_pull_v1_t *pull);

/** The requested (clamped) window length; useful to size the output buffer. */
uint64_t mesh_stream_media_pull_window_len(const mesh_stream_media_pull_v1_t *pull);

#ifdef __cplusplus
}
#endif

#endif