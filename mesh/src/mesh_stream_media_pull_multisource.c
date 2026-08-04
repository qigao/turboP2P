#include "mesh_stream_media_pull_multisource.h"

/* P10: multisource-backed media pull. The puller delivers the range's chunks
 * in order (relative index 0..n-1), which matches the media pull's in-order
 * fetch of absolute chunks first_chunk..first_chunk+n-1. */

static int ms_fetch_chunk(void *context, size_t chunk_index, uint8_t *out,
                          size_t cap, size_t *out_len) {
  mesh_stream_media_pull_multisource_ctx_v1_t *ctx =
      (mesh_stream_media_pull_multisource_ctx_v1_t *)context;
  mesh_stream_multisource_result_t rc;

  *out_len = 0u;
  if (!ctx || !ctx->ms || !ctx->now_ms || chunk_index < ctx->first_chunk)
    return -1;
  *ctx->now_ms += 1u;
  (void)mesh_stream_multisource_tick(ctx->ms, *ctx->now_ms);
  rc = mesh_stream_multisource_recv(ctx->ms, out, cap, out_len);
  if (rc == MESH_STREAM_MULTISOURCE_AGAIN)
    return 1; /* fetch pending; the media pull retries */
  if (rc != MESH_STREAM_MULTISOURCE_OK)
    return -1; /* integrity/failure/end are all fatal for the range */
  return 0;
}

mesh_stream_media_pull_result_t mesh_stream_media_pull_multisource_io_v1(
    mesh_stream_media_pull_multisource_ctx_v1_t *ctx,
    mesh_stream_media_pull_io_v1_t *out_io) {
  if (!ctx || !ctx->ms || !ctx->now_ms || !out_io)
    return MESH_STREAM_MEDIA_PULL_INVALID_ARG;
  out_io->fetch_chunk = ms_fetch_chunk;
  out_io->context = ctx;
  return MESH_STREAM_MEDIA_PULL_OK;
}