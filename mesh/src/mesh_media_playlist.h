#ifndef TURBO_P2P_MESH_MEDIA_PLAYLIST_H
#define TURBO_P2P_MESH_MEDIA_PLAYLIST_H

#include "mesh_media_index.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* P12: HLS-style playlist generation over the media index. One rendition is
 * one M3 object; the media playlist lists every segment with an EXTINF
 * duration and an EXT-X-BYTERANGE, so a player can fetch a segment through
 * mesh_stream_media_pull (HTTP Range/206) using exactly that range. The
 * master playlist lists the ABR ladder renditions with their bandwidth for
 * mesh_media_abr_select_v1-driven selection. */

#define MESH_MEDIA_PLAYLIST_SEGMENT_URI_MAX 32u

typedef enum {
  MESH_MEDIA_PLAYLIST_OK = 0,
  MESH_MEDIA_PLAYLIST_INVALID_ARG = -1,
  MESH_MEDIA_PLAYLIST_RESOURCE_EXHAUSTED = -2,
} mesh_media_playlist_result_t;

/**
 * Build the HLS-style media playlist for one rendition:
 *   #EXTM3U / #EXT-X-VERSION:3 / #EXT-X-TARGETDURATION:<ceil(dur_ms/1000)>
 *   #EXTINF:<dur_s>, / #EXT-X-BYTERANGE:<len>@<offset> / seg-<index>
 * per segment. segment_duration_ms is the nominal per-segment duration.
 * Fails with RESOURCE_EXHAUSTED when out is too small.
 */
mesh_media_playlist_result_t mesh_media_playlist_media_v1(
    const m3_object_manifest_v2_t *manifest, const mesh_media_index_v1_t *index,
    uint64_t segment_duration_ms, char *out, size_t cap, size_t *out_len);

/**
 * Build the HLS-style master playlist from an ABR ladder:
 *   #EXT-X-STREAM-INF:BANDWIDTH=<bps> / rend-<id>.m3u8 per rendition.
 */
mesh_media_playlist_result_t mesh_media_playlist_master_v1(
    const mesh_media_abr_rendition_v1_t *ladder, size_t count, char *out,
    size_t cap, size_t *out_len);

/** Canonical segment URI ("seg-<index>") referenced by the media playlist. */
mesh_media_playlist_result_t mesh_media_playlist_segment_uri_v1(
    size_t segment_index, char *out, size_t cap);

#ifdef __cplusplus
}
#endif

#endif