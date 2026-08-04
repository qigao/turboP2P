#ifndef TURBO_P2P_MESH_STREAM_LIVE_HLS_H
#define TURBO_P2P_MESH_STREAM_LIVE_HLS_H

#include <turbo_thread.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* P18: live-over-HTTP core. A sliding-window HLS live playlist over the
 * live session (P5): blocks delivered by the receiver are pushed as
 * segments; the playlist lists only the last `window` segments with a
 * monotonic EXT-X-MEDIA-SEQUENCE and no ENDLIST, and a client fetches a
 * segment by index. Segments evicted from the window return NOT_FOUND (the
 * HLS analogue of LIVE_SKIP: the client must skip them). */

#define MESH_STREAM_LIVE_HLS_DEFAULT_WINDOW 8u
#define MESH_STREAM_LIVE_HLS_DEFAULT_DURATION_MS 2000u
#define MESH_STREAM_LIVE_HLS_MAX_WINDOW 256u

typedef enum {
  MESH_STREAM_LIVE_HLS_OK = 0,
  MESH_STREAM_LIVE_HLS_INVALID_ARG = -1,
  MESH_STREAM_LIVE_HLS_RESOURCE_EXHAUSTED = -2,
  MESH_STREAM_LIVE_HLS_NOT_FOUND = -3,
} mesh_stream_live_hls_result_t;

typedef struct {
  uint64_t window;             /* segments kept in the sliding window */
  uint64_t segment_duration_ms; /* nominal EXTINF duration */
  uint64_t max_segment_bytes;
} mesh_stream_live_hls_config_v1_t;

typedef struct {
  mesh_stream_live_hls_config_v1_t config;
  turbo_mutex_t mutex; /* guards push vs playlist/segment (producer/HTTP) */
  uint8_t *pool;   /* window * max_segment_bytes */
  size_t *lens;    /* per-slot lengths */
  uint64_t *indexes; /* per-slot segment index, UINT64_MAX = empty */
  uint64_t live_edge; /* highest pushed index, UINT64_MAX = none */
} mesh_stream_live_hls_v1_t;

/** The caller zero-initializes before the first init. */
mesh_stream_live_hls_result_t mesh_stream_live_hls_init_v1(
    mesh_stream_live_hls_v1_t *hls, const mesh_stream_live_hls_config_v1_t *config);

void mesh_stream_live_hls_destroy_v1(mesh_stream_live_hls_v1_t *hls);

/**
 * Push the next live segment (auto-indexed from the live edge). The segment
 * enters the sliding window; the oldest segment is evicted.
 */
mesh_stream_live_hls_result_t mesh_stream_live_hls_push_v1(
    mesh_stream_live_hls_v1_t *hls, const uint8_t *bytes, size_t len,
    uint64_t *out_index);

/**
 * Build the HLS live playlist for the current window:
 * #EXTM3U / #EXT-X-VERSION:3 / #EXT-X-MEDIA-SEQUENCE:<first> /
 * #EXT-X-TARGETDURATION:<secs> and one #EXTINF + seg-<index> per segment.
 * No ENDLIST (the stream is live).
 */
mesh_stream_live_hls_result_t mesh_stream_live_hls_playlist_v1(
    const mesh_stream_live_hls_v1_t *hls, char *out, size_t cap,
    size_t *out_len);

/** Fetch a segment by index; NOT_FOUND once it left the window (LIVE_SKIP). */
mesh_stream_live_hls_result_t mesh_stream_live_hls_segment_v1(
    const mesh_stream_live_hls_v1_t *hls, uint64_t index, uint8_t *out,
    size_t cap, size_t *out_len);

/** Highest pushed segment index, or UINT64_MAX when nothing was pushed. */
uint64_t mesh_stream_live_hls_live_edge(const mesh_stream_live_hls_v1_t *hls);

/** First segment index still in the window (the media sequence). */
uint64_t mesh_stream_live_hls_first_index(const mesh_stream_live_hls_v1_t *hls);

#ifdef __cplusplus
}
#endif

#endif