#include "mesh_stream_live_hls.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* P18: live HLS window. Segments are stored in a ring of `window` slots keyed
 * by index % window; pushing evicts the oldest (index - window). The playlist
 * iterates [first_index, live_edge] in order. */

#define HLS_EMPTY UINT64_MAX

static uint64_t first_index(const mesh_stream_live_hls_v1_t *hls) {
  if (hls->live_edge == HLS_EMPTY)
    return 0u;
  if (hls->live_edge >= hls->config.window)
    return hls->live_edge - (hls->config.window - 1u);
  return 0u;
}

mesh_stream_live_hls_result_t mesh_stream_live_hls_init_v1(
    mesh_stream_live_hls_v1_t *hls, const mesh_stream_live_hls_config_v1_t *config) {
  size_t pool_bytes;

  if (!hls || !config || config->window == 0u ||
      config->window > MESH_STREAM_LIVE_HLS_MAX_WINDOW ||
      config->segment_duration_ms == 0u || config->max_segment_bytes == 0u) {
    return MESH_STREAM_LIVE_HLS_INVALID_ARG;
  }
  memset(hls, 0, sizeof(*hls));
  hls->config = *config;
  hls->live_edge = HLS_EMPTY;
  pool_bytes = (size_t)config->window * (size_t)config->max_segment_bytes;
  hls->pool = (uint8_t *)malloc(pool_bytes);
  hls->lens = (size_t *)calloc((size_t)config->window, sizeof(*hls->lens));
  hls->indexes = (uint64_t *)malloc((size_t)config->window * sizeof(*hls->indexes));
  if (!hls->pool || !hls->lens || !hls->indexes)
    return MESH_STREAM_LIVE_HLS_RESOURCE_EXHAUSTED;
  for (size_t i = 0u; i < (size_t)config->window; i++)
    hls->indexes[i] = HLS_EMPTY;
  turbo_mutex_init(&hls->mutex);
  return MESH_STREAM_LIVE_HLS_OK;
}

void mesh_stream_live_hls_destroy_v1(mesh_stream_live_hls_v1_t *hls) {
  if (!hls)
    return;
  turbo_mutex_destroy(&hls->mutex);
  free(hls->indexes);
  free(hls->lens);
  free(hls->pool);
  memset(hls, 0, sizeof(*hls));
}

mesh_stream_live_hls_result_t mesh_stream_live_hls_push_v1(
    mesh_stream_live_hls_v1_t *hls, const uint8_t *bytes, size_t len,
    uint64_t *out_index) {
  uint64_t index;
  size_t slot;
  uint8_t *dst;

  if (!hls || !bytes || len == 0u || !out_index)
    return MESH_STREAM_LIVE_HLS_INVALID_ARG;
  if (len > (size_t)hls->config.max_segment_bytes)
    return MESH_STREAM_LIVE_HLS_RESOURCE_EXHAUSTED;
  turbo_mutex_lock(&hls->mutex);
  index = hls->live_edge == HLS_EMPTY ? 0u : hls->live_edge + 1u;
  slot = (size_t)(index % hls->config.window);
  dst = hls->pool + slot * (size_t)hls->config.max_segment_bytes;
  memcpy(dst, bytes, len);
  hls->lens[slot] = len;
  hls->indexes[slot] = index;
  hls->live_edge = index;
  turbo_mutex_unlock(&hls->mutex);
  *out_index = index;
  return MESH_STREAM_LIVE_HLS_OK;
}

mesh_stream_live_hls_result_t mesh_stream_live_hls_playlist_v1(
    const mesh_stream_live_hls_v1_t *hls, char *out, size_t cap,
    size_t *out_len) {
  uint64_t first;
  uint64_t target;
  size_t used = 0u;
  int written;

  if (!hls || !out || !out_len)
    return MESH_STREAM_LIVE_HLS_INVALID_ARG;
  *out_len = 0u;
  turbo_mutex_lock(&hls->mutex);
  if (hls->live_edge == HLS_EMPTY) {
    turbo_mutex_unlock(&hls->mutex);
    return MESH_STREAM_LIVE_HLS_OK; /* empty live playlist */
  }
  first = first_index(hls);
  target = (hls->config.segment_duration_ms + 999u) / 1000u;
#define PLAYLIST_APPEND(...)                                                   \
  do {                                                                         \
    written = snprintf(out + used, cap > used ? cap - used : 0u, __VA_ARGS__); \
    if (written < 0 || (size_t)written >= (cap > used ? cap - used : 0u)) {    \
      turbo_mutex_unlock(&hls->mutex);                                         \
      return MESH_STREAM_LIVE_HLS_RESOURCE_EXHAUSTED;                          \
    }                                                                          \
    used += (size_t)written;                                                   \
  } while (0)

  PLAYLIST_APPEND("#EXTM3U\n");
  PLAYLIST_APPEND("#EXT-X-VERSION:3\n");
  PLAYLIST_APPEND("#EXT-X-MEDIA-SEQUENCE:%llu\n", (unsigned long long)first);
  PLAYLIST_APPEND("#EXT-X-TARGETDURATION:%llu\n", (unsigned long long)target);
  for (uint64_t i = first; i <= hls->live_edge; i++) {
    size_t slot = (size_t)(i % hls->config.window);

    if (hls->indexes[slot] != i)
      continue; /* gap (never arrived or skipped) */
    PLAYLIST_APPEND("#EXTINF:%.3f,\n",
                    (double)hls->config.segment_duration_ms / 1000.0);
    PLAYLIST_APPEND("seg-%llu\n", (unsigned long long)i);
  }
#undef PLAYLIST_APPEND
  turbo_mutex_unlock(&hls->mutex);
  *out_len = used;
  return MESH_STREAM_LIVE_HLS_OK;
}

mesh_stream_live_hls_result_t mesh_stream_live_hls_segment_v1(
    const mesh_stream_live_hls_v1_t *hls, uint64_t index, uint8_t *out,
    size_t cap, size_t *out_len) {
  size_t slot;
  size_t len;

  if (!hls || !out || !out_len)
    return MESH_STREAM_LIVE_HLS_INVALID_ARG;
  *out_len = 0u;
  turbo_mutex_lock(&hls->mutex);
  if (hls->live_edge == HLS_EMPTY || index < first_index(hls) ||
      index > hls->live_edge) {
    turbo_mutex_unlock(&hls->mutex);
    return MESH_STREAM_LIVE_HLS_NOT_FOUND; /* evicted or not yet live */
  }
  slot = (size_t)(index % hls->config.window);
  if (hls->indexes[slot] != index) {
    turbo_mutex_unlock(&hls->mutex);
    return MESH_STREAM_LIVE_HLS_NOT_FOUND;
  }
  len = hls->lens[slot];
  if (len > cap) {
    turbo_mutex_unlock(&hls->mutex);
    return MESH_STREAM_LIVE_HLS_RESOURCE_EXHAUSTED;
  }
  memcpy(out, hls->pool + slot * (size_t)hls->config.max_segment_bytes, len);
  turbo_mutex_unlock(&hls->mutex);
  *out_len = len;
  return MESH_STREAM_LIVE_HLS_OK;
}

uint64_t mesh_stream_live_hls_live_edge(const mesh_stream_live_hls_v1_t *hls) {
  uint64_t edge;

  if (!hls)
    return HLS_EMPTY;
  turbo_mutex_lock(&hls->mutex);
  edge = hls->live_edge;
  turbo_mutex_unlock(&hls->mutex);
  return edge;
}

uint64_t mesh_stream_live_hls_first_index(const mesh_stream_live_hls_v1_t *hls) {
  uint64_t first;

  if (!hls)
    return 0u;
  turbo_mutex_lock(&hls->mutex);
  first = first_index(hls);
  turbo_mutex_unlock(&hls->mutex);
  return first;
}