#include "mesh_media_playlist.h"

#include <stdio.h>
#include <string.h>

/* P12: playlist generation. Pure text formatting over the derived media index
 * (the manifest stays the fact source). Playlist buffers must be sized by the
 * caller; generation fails fast when the capacity is insufficient. */

static uint64_t target_duration_seconds(uint64_t duration_ms) {
  return (duration_ms + 999u) / 1000u;
}

mesh_media_playlist_result_t mesh_media_playlist_segment_uri_v1(
    size_t segment_index, char *out, size_t cap) {
  int written;

  if (!out || cap == 0u)
    return MESH_MEDIA_PLAYLIST_INVALID_ARG;
  written = snprintf(out, cap, "seg-%zu", segment_index);
  if (written < 0 || (size_t)written >= cap)
    return MESH_MEDIA_PLAYLIST_RESOURCE_EXHAUSTED;
  return MESH_MEDIA_PLAYLIST_OK;
}

mesh_media_playlist_result_t mesh_media_playlist_media_v1(
    const m3_object_manifest_v2_t *manifest, const mesh_media_index_v1_t *index,
    uint64_t segment_duration_ms, char *out, size_t cap, size_t *out_len) {
  size_t used = 0u;
  int written;

  if (!manifest || !manifest->chunks || !index || !index->segments ||
      !out || !out_len || segment_duration_ms == 0u) {
    return MESH_MEDIA_PLAYLIST_INVALID_ARG;
  }
  *out_len = 0u;
#define PLAYLIST_APPEND(...)                                                   \
  do {                                                                         \
    written = snprintf(out + used, cap > used ? cap - used : 0u, __VA_ARGS__); \
    if (written < 0 || (size_t)written >= (cap > used ? cap - used : 0u))      \
      return MESH_MEDIA_PLAYLIST_RESOURCE_EXHAUSTED;                           \
    used += (size_t)written;                                                   \
  } while (0)

  PLAYLIST_APPEND("#EXTM3U\n");
  PLAYLIST_APPEND("#EXT-X-VERSION:3\n");
  PLAYLIST_APPEND("#EXT-X-TARGETDURATION:%llu\n",
                  (unsigned long long)target_duration_seconds(segment_duration_ms));
  PLAYLIST_APPEND("#EXT-X-MEDIA-SEQUENCE:0\n");
  for (size_t s = 0u; s < index->segment_count; s++) {
    const mesh_media_segment_v1_t *segment = &index->segments[s];

    PLAYLIST_APPEND("#EXTINF:%.3f,\n", (double)segment_duration_ms / 1000.0);
    PLAYLIST_APPEND("#EXT-X-BYTERANGE:%llu@%llu\n",
                    (unsigned long long)segment->byte_len,
                    (unsigned long long)segment->byte_offset);
    PLAYLIST_APPEND("seg-%zu\n", s);
  }
#undef PLAYLIST_APPEND
  *out_len = used;
  return MESH_MEDIA_PLAYLIST_OK;
}

mesh_media_playlist_result_t mesh_media_playlist_master_v1(
    const mesh_media_abr_rendition_v1_t *ladder, size_t count, char *out,
    size_t cap, size_t *out_len) {
  size_t used = 0u;
  int written;

  if (!ladder || count == 0u || count > MESH_MEDIA_ABR_MAX_RENDITIONS || !out ||
      !out_len) {
    return MESH_MEDIA_PLAYLIST_INVALID_ARG;
  }
  *out_len = 0u;
#define MASTER_APPEND(...)                                                     \
  do {                                                                         \
    written = snprintf(out + used, cap > used ? cap - used : 0u, __VA_ARGS__); \
    if (written < 0 || (size_t)written >= (cap > used ? cap - used : 0u))      \
      return MESH_MEDIA_PLAYLIST_RESOURCE_EXHAUSTED;                           \
    used += (size_t)written;                                                   \
  } while (0)

  MASTER_APPEND("#EXTM3U\n");
  MASTER_APPEND("#EXT-X-VERSION:3\n");
  for (size_t i = 0u; i < count; i++) {
    if (ladder[i].id[0] == '\0')
      return MESH_MEDIA_PLAYLIST_INVALID_ARG;
    MASTER_APPEND("#EXT-X-STREAM-INF:BANDWIDTH=%llu\n",
                  (unsigned long long)ladder[i].bandwidth_bps);
    MASTER_APPEND("rend-%s.m3u8\n", ladder[i].id);
  }
#undef MASTER_APPEND
  *out_len = used;
  return MESH_MEDIA_PLAYLIST_OK;
}