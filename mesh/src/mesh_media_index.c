#include "mesh_media_index.h"

#include <stdlib.h>
#include <string.h>

/* P4: media segment index. Segment boundaries are derived from the manifest
 * chunk list (chunk-aligned, target-segment-byte cap); the manifest stays the
 * single fact source for chunk sizes. Range resolution narrows the chunk scan
 * with a binary search over segments, then walks chunk sizes within and after
 * the containing segment. */

/* Count how many segments the chunk list splits into under the target. */
static size_t count_segments(const m3_object_manifest_v2_t *manifest,
                             uint64_t target) {
  size_t count = 0u;
  uint64_t acc = 0u;

  for (size_t i = 0u; i < manifest->chunk_count; i++) {
    uint64_t size = manifest->chunks[i].size;

    if (acc > 0u && acc + size > target) {
      count++;
      acc = 0u;
    }
    acc += size;
  }
  return count + 1u;
}

static void fill_segments(mesh_media_index_v1_t *index,
                          const m3_object_manifest_v2_t *manifest,
                          uint64_t target) {
  size_t s = 0u;
  uint64_t acc = 0u;
  uint64_t offset = 0u;
  size_t first = 0u;
  size_t chunks = 0u;

  for (size_t i = 0u; i < manifest->chunk_count; i++) {
    uint64_t size = manifest->chunks[i].size;

    if (acc > 0u && acc + size > target) {
      index->segments[s].byte_offset = offset - acc;
      index->segments[s].byte_len = acc;
      index->segments[s].first_chunk = first;
      index->segments[s].chunk_count = chunks;
      s++;
      acc = 0u;
      first = i;
      chunks = 0u;
    }
    acc += size;
    offset += size;
    chunks++;
  }
  index->segments[s].byte_offset = offset - acc;
  index->segments[s].byte_len = acc;
  index->segments[s].first_chunk = first;
  index->segments[s].chunk_count = chunks;
}

mesh_media_index_result_t mesh_media_index_build_v1(
    mesh_media_index_v1_t *index, const m3_object_manifest_v2_t *manifest,
    uint64_t target_segment_bytes) {
  size_t segment_count;
  uint64_t total = 0u;

  if (!index || index->segments || !manifest || !manifest->chunks ||
      manifest->chunk_count == 0u || target_segment_bytes == 0u) {
    return MESH_MEDIA_INDEX_INVALID_ARG;
  }
  for (size_t i = 0u; i < manifest->chunk_count; i++) {
    uint64_t size = manifest->chunks[i].size;

    if (size == 0u || size > manifest->object_cid.size - total)
      return MESH_MEDIA_INDEX_INVALID_ARG;
    total += size;
  }
  if (total != manifest->object_cid.size)
    return MESH_MEDIA_INDEX_INVALID_ARG;
  segment_count = count_segments(manifest, target_segment_bytes);
  if (segment_count > MESH_MEDIA_INDEX_MAX_SEGMENTS)
    return MESH_MEDIA_INDEX_RESOURCE_EXHAUSTED;
  index->segments =
      (mesh_media_segment_v1_t *)calloc(segment_count, sizeof(*index->segments));
  if (!index->segments)
    return MESH_MEDIA_INDEX_RESOURCE_EXHAUSTED;
  index->object_size = total;
  index->segment_count = segment_count;
  fill_segments(index, manifest, target_segment_bytes);
  return MESH_MEDIA_INDEX_OK;
}

void mesh_media_index_destroy_v1(mesh_media_index_v1_t *index) {
  if (!index)
    return;
  free(index->segments);
  memset(index, 0, sizeof(*index));
}

mesh_media_index_result_t mesh_media_index_segment_at_v1(
    const mesh_media_index_v1_t *index, uint64_t byte_offset,
    size_t *out_segment) {
  size_t lo;
  size_t hi;

  if (!index || !index->segments || !out_segment)
    return MESH_MEDIA_INDEX_INVALID_ARG;
  if (byte_offset >= index->object_size)
    return MESH_MEDIA_INDEX_OUT_OF_RANGE;
  lo = 0u;
  hi = index->segment_count;
  while (lo < hi) {
    size_t mid = lo + (hi - lo) / 2u;

    if (index->segments[mid].byte_offset +
            index->segments[mid].byte_len <= byte_offset) {
      lo = mid + 1u;
    } else {
      hi = mid;
    }
  }
  if (lo >= index->segment_count ||
      byte_offset < index->segments[lo].byte_offset) {
    return MESH_MEDIA_INDEX_OUT_OF_RANGE;
  }
  *out_segment = lo;
  return MESH_MEDIA_INDEX_OK;
}

mesh_media_index_result_t mesh_media_index_resolve_range_v1(
    const mesh_media_index_v1_t *index, const m3_object_manifest_v2_t *manifest,
    uint64_t byte_start, uint64_t byte_len, size_t *out_first_chunk,
    size_t *out_chunk_count, uint64_t *out_window_offset,
    uint64_t *out_window_len) {
  size_t seg;
  size_t first = SIZE_MAX;
  uint64_t offset;
  uint64_t window_offset;
  uint64_t covered;
  size_t i;

  if (!index || !index->segments || !manifest || !manifest->chunks ||
      byte_len == 0u || !out_first_chunk || !out_chunk_count ||
      !out_window_offset || !out_window_len) {
    return MESH_MEDIA_INDEX_INVALID_ARG;
  }
  if (byte_start >= index->object_size)
    return MESH_MEDIA_INDEX_OUT_OF_RANGE;
  if (byte_len > index->object_size - byte_start)
    byte_len = index->object_size - byte_start;

  {
    mesh_media_index_result_t rc =
        mesh_media_index_segment_at_v1(index, byte_start, &seg);

    if (rc != MESH_MEDIA_INDEX_OK)
      return rc;
  }
  /* Locate the chunk containing byte_start (starts inside its segment). */
  offset = index->segments[seg].byte_offset;
  for (i = index->segments[seg].first_chunk;
       i < index->segments[seg].first_chunk + index->segments[seg].chunk_count;
       i++) {
    uint64_t size = manifest->chunks[i].size;

    if (byte_start < offset + size) {
      first = i;
      break;
    }
    offset += size;
  }
  if (first == SIZE_MAX)
    return MESH_MEDIA_INDEX_OUT_OF_RANGE;
  window_offset = byte_start - offset;
  /* Count the chunks that cover the requested window. */
  covered = manifest->chunks[first].size - window_offset;
  for (i = first + 1u; covered < byte_len && i < manifest->chunk_count; i++)
    covered += manifest->chunks[i].size;

  *out_first_chunk = first;
  *out_chunk_count = i - first;
  *out_window_offset = window_offset;
  *out_window_len = byte_len;
  return MESH_MEDIA_INDEX_OK;
}

mesh_media_index_result_t mesh_media_abr_select_v1(
    const mesh_media_abr_rendition_v1_t *ladder, size_t count,
    uint64_t available_bps, size_t *out_index) {
  size_t best = SIZE_MAX;

  if (!ladder || count == 0u || count > MESH_MEDIA_ABR_MAX_RENDITIONS ||
      !out_index) {
    return MESH_MEDIA_INDEX_INVALID_ARG;
  }
  /* Highest rendition that fits; ties keep the lowest index. */
  for (size_t i = 0u; i < count; i++) {
    if (ladder[i].bandwidth_bps <= available_bps &&
        (best == SIZE_MAX || ladder[i].bandwidth_bps > ladder[best].bandwidth_bps)) {
      best = i;
    }
  }
  if (best == SIZE_MAX) {
    /* Nothing fits: degrade to the lowest bitrate instead of failing. */
    best = 0u;
    for (size_t i = 1u; i < count; i++) {
      if (ladder[i].bandwidth_bps < ladder[best].bandwidth_bps)
        best = i;
    }
  }
  *out_index = best;
  return MESH_MEDIA_INDEX_OK;
}

static size_t index_of_lowest(const mesh_media_abr_rendition_v1_t *ladder,
                              size_t count) {
  size_t best = 0u;

  for (size_t i = 1u; i < count; i++) {
    if (ladder[i].bandwidth_bps < ladder[best].bandwidth_bps)
      best = i;
  }
  return best;
}

mesh_media_index_result_t mesh_media_abr_session_init_v1(
    mesh_media_abr_session_v1_t *session,
    const mesh_media_abr_session_config_v1_t *config, size_t initial_index) {
  if (!session || !config || config->stable_observations == 0u)
    return MESH_MEDIA_INDEX_INVALID_ARG;
  memset(session, 0, sizeof(*session));
  session->config = *config;
  session->current_index = initial_index;
  return MESH_MEDIA_INDEX_OK;
}

mesh_media_index_result_t mesh_media_abr_session_observe_v1(
    mesh_media_abr_session_v1_t *session,
    const mesh_media_abr_rendition_v1_t *ladder, size_t count,
    uint64_t measured_bps, uint64_t now_ms, size_t *out_index) {
  const mesh_media_abr_rendition_v1_t *current;
  size_t next = SIZE_MAX;

  if (!session || !ladder || count == 0u || count > MESH_MEDIA_ABR_MAX_RENDITIONS ||
      !out_index || session->current_index >= count) {
    return MESH_MEDIA_INDEX_INVALID_ARG;
  }
  current = &ladder[session->current_index];

  if (measured_bps < current->bandwidth_bps) {
    /* Drop immediately to the highest tier the measured bandwidth fits. */
    size_t best = SIZE_MAX;

    for (size_t i = 0u; i < count; i++) {
      if (ladder[i].bandwidth_bps <= measured_bps &&
          (best == SIZE_MAX ||
           ladder[i].bandwidth_bps > ladder[best].bandwidth_bps)) {
        best = i;
      }
    }
    if (best == SIZE_MAX)
      best = index_of_lowest(ladder, count);
    if (best != session->current_index) {
      session->current_index = best;
      session->up_candidates = 0u;
      session->last_switch_ms = now_ms;
      session->switches_total++;
      session->switches_down++;
    }
    *out_index = session->current_index;
    return MESH_MEDIA_INDEX_OK;
  }

  /* The current tier is sustainable: try to climb one tier, conservatively. */
  for (size_t i = 0u; i < count; i++) {
    if (ladder[i].bandwidth_bps > current->bandwidth_bps &&
        (next == SIZE_MAX || ladder[i].bandwidth_bps < ladder[next].bandwidth_bps)) {
      next = i;
    }
  }
  if (next != SIZE_MAX && measured_bps >= ladder[next].bandwidth_bps) {
    session->up_candidates++;
  } else {
    session->up_candidates = 0u;
  }
  if (next != SIZE_MAX &&
      session->up_candidates >= session->config.stable_observations &&
      now_ms >= session->last_switch_ms &&
      now_ms - session->last_switch_ms >= session->config.min_interval_ms) {
    session->current_index = next;
    session->up_candidates = 0u;
    session->last_switch_ms = now_ms;
    session->switches_total++;
    session->switches_up++;
  }
  *out_index = session->current_index;
  return MESH_MEDIA_INDEX_OK;
}