#include "mesh_stream_media_pull.h"

#include <turbo_crypto.h>

#include <stdlib.h>
#include <string.h>

/* P8: media range pull. The window is assembled into the caller's buffer as
 * the covering chunks arrive in order; each chunk is verified against its CID
 * before any of its bytes are copied, so a corrupt chunk never contaminates
 * the window. */

static uint64_t object_offset_of_chunk(const m3_object_manifest_v2_t *manifest,
                                       size_t chunk_index) {
  uint64_t offset = 0u;

  for (size_t i = 0u; i < chunk_index; i++)
    offset += manifest->chunks[i].size;
  return offset;
}

mesh_stream_media_pull_result_t mesh_stream_media_pull_init_v1(
    mesh_stream_media_pull_v1_t *pull, const m3_object_manifest_v2_t *manifest,
    const mesh_stream_media_pull_config_v1_t *config) {
  mesh_media_index_result_t rc;

  if (!pull || pull->index.segments || !manifest || !manifest->chunks ||
      manifest->chunk_count == 0u || !config || !config->io.fetch_chunk ||
      config->max_chunk_bytes == 0u || config->target_segment_bytes == 0u) {
    return MESH_STREAM_MEDIA_PULL_INVALID_ARG;
  }
  for (size_t i = 0u; i < manifest->chunk_count; i++) {
    if (manifest->chunks[i].size > config->max_chunk_bytes)
      return MESH_STREAM_MEDIA_PULL_INVALID_ARG;
  }
  memset(pull, 0, sizeof(*pull));
  pull->manifest = *manifest;
  pull->io = config->io;
  pull->max_chunk_bytes = config->max_chunk_bytes;
  pull->scratch = (uint8_t *)malloc((size_t)config->max_chunk_bytes);
  if (!pull->scratch)
    return MESH_STREAM_MEDIA_PULL_RESOURCE_EXHAUSTED;
  rc = mesh_media_index_build_v1(&pull->index, manifest,
                                 config->target_segment_bytes);
  if (rc != MESH_MEDIA_INDEX_OK) {
    mesh_stream_media_pull_destroy_v1(pull);
    return rc == MESH_MEDIA_INDEX_RESOURCE_EXHAUSTED
               ? MESH_STREAM_MEDIA_PULL_RESOURCE_EXHAUSTED
               : MESH_STREAM_MEDIA_PULL_INVALID_ARG;
  }
  return MESH_STREAM_MEDIA_PULL_OK;
}

void mesh_stream_media_pull_destroy_v1(mesh_stream_media_pull_v1_t *pull) {
  if (!pull)
    return;
  mesh_media_index_destroy_v1(&pull->index);
  free(pull->scratch);
  memset(pull, 0, sizeof(*pull));
}

mesh_stream_media_pull_result_t mesh_stream_media_pull_resolve_v1(
    const mesh_stream_media_pull_v1_t *pull, uint64_t byte_start,
    uint64_t byte_len, size_t *out_first_chunk, size_t *out_chunk_count,
    uint64_t *out_window_offset, uint64_t *out_window_len) {
  mesh_media_index_result_t rc;

  if (!pull || !pull->index.segments || !out_first_chunk || !out_chunk_count ||
      !out_window_offset || !out_window_len) {
    return MESH_STREAM_MEDIA_PULL_INVALID_ARG;
  }
  rc = mesh_media_index_resolve_range_v1(
      &pull->index, &pull->manifest, byte_start, byte_len, out_first_chunk,
      out_chunk_count, out_window_offset, out_window_len);
  if (rc == MESH_MEDIA_INDEX_OUT_OF_RANGE)
    return MESH_STREAM_MEDIA_PULL_OUT_OF_RANGE;
  if (rc != MESH_MEDIA_INDEX_OK)
    return MESH_STREAM_MEDIA_PULL_INVALID_ARG;
  return MESH_STREAM_MEDIA_PULL_OK;
}

mesh_stream_media_pull_result_t mesh_stream_media_pull_start_v1(
    mesh_stream_media_pull_v1_t *pull, uint64_t byte_start, uint64_t byte_len) {
  mesh_stream_media_pull_result_t rc;

  if (!pull || !pull->index.segments)
    return MESH_STREAM_MEDIA_PULL_INVALID_ARG;
  if (byte_len == 0u)
    return MESH_STREAM_MEDIA_PULL_INVALID_ARG;
  rc = mesh_stream_media_pull_resolve_v1(
      pull, byte_start, byte_len, &pull->first_chunk, &pull->chunk_count,
      &pull->window_offset, &pull->window_len);
  if (rc != MESH_STREAM_MEDIA_PULL_OK)
    return rc;
  pull->window_start = byte_start;
  pull->chunk_offset = object_offset_of_chunk(&pull->manifest, pull->first_chunk);
  pull->next_chunk = pull->first_chunk;
  pull->started = 1u;
  pull->done = 0u;
  return MESH_STREAM_MEDIA_PULL_OK;
}

mesh_stream_media_pull_result_t mesh_stream_media_pull_pump_v1(
    mesh_stream_media_pull_v1_t *pull, uint8_t *out, size_t cap,
    size_t *out_len) {
  if (!pull || !pull->started || !out || !out_len ||
      cap < (size_t)pull->window_len) {
    return MESH_STREAM_MEDIA_PULL_INVALID_ARG;
  }
  *out_len = 0u;
  if (pull->done) {
    *out_len = (size_t)pull->window_len;
    return MESH_STREAM_MEDIA_PULL_OK;
  }
  while (pull->next_chunk < pull->first_chunk + pull->chunk_count) {
    size_t idx = pull->next_chunk;
    const m3_chunk_cid_v1_t *cid = &pull->manifest.chunks[idx];
    size_t len = 0u;
    int fetch_result =
        pull->io.fetch_chunk(pull->io.context, idx, pull->scratch,
                             (size_t)pull->max_chunk_bytes, &len);
    uint8_t digest[M3_CHUNK_CID_DIGEST_SIZE];
    uint64_t chunk_end;
    uint64_t window_end;
    uint64_t overlap_start;
    uint64_t overlap_end;

    if (fetch_result < 0)
      return MESH_STREAM_MEDIA_PULL_IO;
    if (fetch_result > 0)
      return MESH_STREAM_MEDIA_PULL_AGAIN; /* fetch pending */
    if (len != cid->size)
      return MESH_STREAM_MEDIA_PULL_INTEGRITY;
    if (turbo_crypto_sha256(pull->scratch, len, digest) != TURBO_CRYPTO_OK)
      return MESH_STREAM_MEDIA_PULL_INTEGRITY;
    if (memcmp(digest, cid->digest, sizeof(digest)) != 0)
      return MESH_STREAM_MEDIA_PULL_INTEGRITY;

    /* Copy the intersection of this chunk with the requested window. */
    chunk_end = pull->chunk_offset + cid->size;
    window_end = pull->window_start + pull->window_len;
    overlap_start = pull->chunk_offset > pull->window_start
                        ? pull->chunk_offset
                        : pull->window_start;
    overlap_end = chunk_end < window_end ? chunk_end : window_end;
    if (overlap_end > overlap_start) {
      size_t src = (size_t)(overlap_start - pull->chunk_offset);
      size_t count = (size_t)(overlap_end - overlap_start);
      size_t dst = (size_t)(overlap_start - pull->window_start);

      memcpy(out + dst, pull->scratch + src, count);
    }
    pull->chunk_offset += cid->size;
    pull->next_chunk++;
  }
  pull->done = 1u;
  *out_len = (size_t)pull->window_len;
  return MESH_STREAM_MEDIA_PULL_OK;
}

int mesh_stream_media_pull_complete(const mesh_stream_media_pull_v1_t *pull) {
  return pull && pull->started && pull->done;
}

uint64_t mesh_stream_media_pull_window_len(const mesh_stream_media_pull_v1_t *pull) {
  return pull ? pull->window_len : 0u;
}