#ifndef TURBO_P2P_MESH_STREAM_MEDIA_PULL_MULTISOURCE_H
#define TURBO_P2P_MESH_STREAM_MEDIA_PULL_MULTISOURCE_H

#include "mesh_stream_media_pull.h"
#include "mesh_stream_multisource.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* P10: wire the multi-source block puller (P2) as the fetch io of the media
 * range pull (P8). The multisource is created over the range's chunk digests
 * (uniform block size) and delivers the covering chunks in order across the
 * best available sources, verifying each digest internally; the media pull
 * then re-verifies and assembles the window. */

typedef struct {
  mesh_stream_multisource_t *ms; /* borrowed; created for the range's chunks */
  size_t first_chunk;            /* absolute index of the range's first chunk */
  uint64_t *now_ms;              /* borrowed monotonic clock for tick */
} mesh_stream_media_pull_multisource_ctx_v1_t;

/**
 * Build a media-pull fetch io backed by a multisource puller. Each fetch
 * advances *now_ms, ticks the puller once and delivers the next ordered
 * block; a pending pull maps to the media pull's "fetch pending" state.
 * The ctx is caller-owned and must outlive the media pull.
 */
mesh_stream_media_pull_result_t mesh_stream_media_pull_multisource_io_v1(
    mesh_stream_media_pull_multisource_ctx_v1_t *ctx,
    mesh_stream_media_pull_io_v1_t *out_io);

#ifdef __cplusplus
}
#endif

#endif