#ifndef TURBO_P2P_MESH_MEDIA_INDEX_H
#define TURBO_P2P_MESH_MEDIA_INDEX_H

#include "m3_object_manifest.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* P4: media segment index + ABR ladder. A rendition is one M3 object; the
 * index derives segment boundaries from the object manifest's chunk list so a
 * client can seek (segment lookup), serve HTTP Range/206 (byte range -> chunk
 * span) and pick the best rendition for the measured bandwidth. The manifest
 * remains the single fact source: the index is rebuilt from it and holds no
 * independently mutable state. */

#define MESH_MEDIA_INDEX_MAX_SEGMENTS (UINT64_C(1) << 20)
#define MESH_MEDIA_INDEX_DEFAULT_SEGMENT_BYTES (UINT64_C(1) << 20) /* 1 MiB */
#define MESH_MEDIA_ABR_MAX_RENDITIONS 16u
#define MESH_MEDIA_ABR_RENDITION_ID_SIZE 16u
#define MESH_MEDIA_ABR_SESSION_DEFAULT_STABLE_OBSERVATIONS 3u
#define MESH_MEDIA_ABR_SESSION_DEFAULT_MIN_INTERVAL_MS 2000u

typedef enum {
  MESH_MEDIA_INDEX_OK = 0,
  MESH_MEDIA_INDEX_INVALID_ARG = -1,
  MESH_MEDIA_INDEX_RESOURCE_EXHAUSTED = -2,
  MESH_MEDIA_INDEX_OUT_OF_RANGE = -3,
} mesh_media_index_result_t;

/** One segment: a contiguous byte span aligned to chunk boundaries. */
typedef struct {
  uint64_t byte_offset; /* first byte of the segment in the object */
  uint64_t byte_len;    /* bytes covered by the segment */
  size_t first_chunk;   /* first source chunk index */
  size_t chunk_count;   /* chunks in this segment */
} mesh_media_segment_v1_t;

/** Derived segment index over one object manifest (owned segments). */
typedef struct {
  uint64_t object_size;
  size_t segment_count;
  mesh_media_segment_v1_t *segments; /* owned; segment_count entries */
} mesh_media_index_v1_t;

/** One rendition of the ABR ladder (bandwidth metadata only). */
typedef struct {
  char id[MESH_MEDIA_ABR_RENDITION_ID_SIZE];
  uint64_t bandwidth_bps;
  uint64_t object_size;
} mesh_media_abr_rendition_v1_t;

/**
 * Build the segment index: chunks are grouped so each segment stays at or
 * below target_segment_bytes (a chunk larger than the target forms a segment
 * of its own). Segments are contiguous and chunk-aligned, so
 * byte_offset[i+1] == byte_offset[i] + byte_len[i]. The index must be
 * zero-initialized before the first build. The manifest view must remain
 * valid for the index lifetime; the index stores no chunk bytes.
 */
mesh_media_index_result_t mesh_media_index_build_v1(
    mesh_media_index_v1_t *index, const m3_object_manifest_v2_t *manifest,
    uint64_t target_segment_bytes);

void mesh_media_index_destroy_v1(mesh_media_index_v1_t *index);

/** Map a byte offset to the segment containing it. */
mesh_media_index_result_t mesh_media_index_segment_at_v1(
    const mesh_media_index_v1_t *index, uint64_t byte_offset,
    size_t *out_segment);

/**
 * Resolve a byte range [byte_start, byte_start+byte_len) into the source
 * chunk span that covers it (for HTTP Range/206: fetch only those chunks).
 * byte_len is clamped to the object end; byte_start at/after the object end
 * fails with MESH_MEDIA_INDEX_OUT_OF_RANGE (HTTP 416). out_window_offset is
 * the byte offset of byte_start within the first chunk and out_window_len is
 * the (possibly clamped) requested length.
 */
mesh_media_index_result_t mesh_media_index_resolve_range_v1(
    const mesh_media_index_v1_t *index, const m3_object_manifest_v2_t *manifest,
    uint64_t byte_start, uint64_t byte_len, size_t *out_first_chunk,
    size_t *out_chunk_count, uint64_t *out_window_offset,
    uint64_t *out_window_len);

/**
 * Select the rendition for the measured bandwidth: the highest rendition
 * whose bitrate fits (ties keep the lowest index); when none fit, degrade to
 * the lowest bitrate instead of failing.
 */
mesh_media_index_result_t mesh_media_abr_select_v1(
    const mesh_media_abr_rendition_v1_t *ladder, size_t count,
    uint64_t available_bps, size_t *out_index);

typedef struct {
  uint64_t stable_observations; /* consecutive fits above the next tier to switch up */
  uint64_t min_interval_ms;     /* minimum wall time between switches */
} mesh_media_abr_session_config_v1_t;

/**
 * Dynamic ABR session with hysteresis: it drops to the highest tier the
 * measured bandwidth fits as soon as it can no longer sustain the current
 * tier, and climbs one tier at a time only after stable_observations
 * consecutive samples fit the next tier and min_interval_ms elapsed since the
 * last switch. The caller zero-initializes the session before the first
 * init.
 */
typedef struct {
  mesh_media_abr_session_config_v1_t config;
  size_t current_index;
  uint64_t last_switch_ms;
  uint64_t up_candidates; /* consecutive up-eligible observations */
  uint64_t switches_total;
  uint64_t switches_up;
  uint64_t switches_down;
} mesh_media_abr_session_v1_t;

mesh_media_index_result_t mesh_media_abr_session_init_v1(
    mesh_media_abr_session_v1_t *session,
    const mesh_media_abr_session_config_v1_t *config, size_t initial_index);

/**
 * Feed one measured throughput sample and return the rendition to use now.
 * Switches down immediately on degradation; switches up conservatively (see
 * the session doc).
 */
mesh_media_index_result_t mesh_media_abr_session_observe_v1(
    mesh_media_abr_session_v1_t *session,
    const mesh_media_abr_rendition_v1_t *ladder, size_t count,
    uint64_t measured_bps, uint64_t now_ms, size_t *out_index);

#ifdef __cplusplus
}
#endif

#endif