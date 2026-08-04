#include "mesh_stream_kcp_adapter.h"

#include <stdlib.h>
#include <string.h>

/* P7: KCP transport binding. coro_socket_recv on KCP returns a byte stream
 * (frames coalesce), so the bridge reassembles complete live frames from the
 * stream buffer; coro_socket_recv timeouts/empty reads are "no data" so the
 * live session can poll from the owning coroutine. */

#define KCP_FEC_RECEIVE_GROUPS 16u
#define KCP_ADAPTER_MAX_BUFFER (4u * 1024u * 1024u)

struct mesh_stream_kcp_io_s {
  coro_socket_t *socket;
  uint64_t recv_timeout_ms;
  uint8_t *buf;
  size_t buf_cap;
  size_t buf_len;
};

static int kcp_live_send(void *context, const uint8_t *bytes, size_t len) {
  coro_socket_t *socket = ((mesh_stream_kcp_io_t *)context)->socket;

  return coro_socket_send(socket, (const char *)bytes, len) == 0 ? 0 : -1;
}

static int kcp_live_recv(void *context, uint8_t *bytes, size_t cap,
                         size_t *out_len) {
  mesh_stream_kcp_io_t *io = (mesh_stream_kcp_io_t *)context;

  *out_len = 0u;
  for (;;) {
    size_t frame_len = 0u;

    if (mesh_stream_live_frame_complete_v1(io->buf, io->buf_len, &frame_len)) {
      if (frame_len > cap)
        return -1;
      memcpy(bytes, io->buf, frame_len);
      memmove(io->buf, io->buf + frame_len, io->buf_len - frame_len);
      io->buf_len -= frame_len;
      *out_len = frame_len;
      return 0;
    }
    if (io->buf_len >= io->buf_cap)
      return -1; /* declared length exceeds the frame bound: corrupt */
    {
      char *data = NULL;
      size_t len = 0u;
      int rc = coro_socket_recv(io->socket, &data, &len);

      if (rc == 0 && data != NULL && len > 0u) {
        /* coro_socket_recv may return several coalesced frames in one chunk,
         * so grow the reassembly buffer to fit the whole chunk. */
        if (len > io->buf_cap - io->buf_len) {
          size_t new_cap = io->buf_cap == 0u ? 256u : io->buf_cap;

          while (new_cap < io->buf_len + len) {
            if (new_cap >= KCP_ADAPTER_MAX_BUFFER) {
              coro_socket_free_recv(data);
              return -1;
            }
            new_cap *= 2u;
          }
          {
            uint8_t *grown = (uint8_t *)realloc(io->buf, new_cap);

            if (!grown) {
              coro_socket_free_recv(data);
              return -1;
            }
            io->buf = grown;
            io->buf_cap = new_cap;
          }
        }
        memcpy(io->buf + io->buf_len, data, len);
        io->buf_len += len;
        coro_socket_free_recv(data);
        continue;
      }
      if (rc == TURBO_ETIMEDOUT || (rc == 0 && data == NULL) || rc == TURBO_EOF)
        return 0; /* no data (timeout/empty/eof); partial frames stay buffered */
      return -1;
    }
  }
}

mesh_stream_kcp_adapter_result_t mesh_stream_kcp_adapter_fec_config_v1(
    const mesh_stream_live_config_v1_t *live_config,
    turbo_kcp_fec_config_t *out_fec) {
  if (!live_config || !out_fec)
    return MESH_STREAM_KCP_ADAPTER_INVALID_ARG;
  memset(out_fec, 0, sizeof(*out_fec));
  if (live_config->fec_data_shards == 0u) {
    /* No live FEC: backend NONE signals "do not apply transport FEC".
     * Parity without data is a contradictory live config. */
    if (live_config->fec_parity_shards != 0u)
      return MESH_STREAM_KCP_ADAPTER_INVALID_ARG;
    out_fec->backend = TURBO_KCP_FEC_BACKEND_NONE;
    return MESH_STREAM_KCP_ADAPTER_OK;
  }
  if (live_config->fec_data_shards > MESH_STREAM_LIVE_MAX_SHARDS ||
      live_config->fec_parity_shards == 0u ||
      live_config->fec_parity_shards > MESH_STREAM_LIVE_MAX_SHARDS ||
      live_config->max_block_bytes == 0u) {
    return MESH_STREAM_KCP_ADAPTER_INVALID_ARG;
  }
  if (!turbo_kcp_fec_backend_available(TURBO_KCP_FEC_BACKEND_REED_SOLOMON))
    return MESH_STREAM_KCP_ADAPTER_UNSUPPORTED;
  out_fec->backend = TURBO_KCP_FEC_BACKEND_REED_SOLOMON;
  out_fec->data_shards = (uint16_t)live_config->fec_data_shards;
  out_fec->parity_shards = (uint16_t)live_config->fec_parity_shards;
  out_fec->max_payload_size = (uint16_t)live_config->max_block_bytes;
  out_fec->receive_group_count = KCP_FEC_RECEIVE_GROUPS;
  return MESH_STREAM_KCP_ADAPTER_OK;
}

mesh_stream_kcp_adapter_result_t mesh_stream_kcp_adapter_io_create_v1(
    coro_socket_t *socket, uint64_t recv_timeout_ms, size_t max_frame_bytes,
    mesh_stream_kcp_io_t **out_io) {
  mesh_stream_kcp_io_t *io;

  if (!socket || recv_timeout_ms == 0u || max_frame_bytes == 0u || !out_io)
    return MESH_STREAM_KCP_ADAPTER_INVALID_ARG;
  io = (mesh_stream_kcp_io_t *)calloc(1, sizeof(*io));
  if (!io)
    return MESH_STREAM_KCP_ADAPTER_IO;
  io->buf = (uint8_t *)malloc(max_frame_bytes);
  if (!io->buf) {
    free(io);
    return MESH_STREAM_KCP_ADAPTER_IO;
  }
  io->socket = socket;
  io->recv_timeout_ms = recv_timeout_ms;
  io->buf_cap = max_frame_bytes;
  coro_socket_set_timeout(socket, recv_timeout_ms);
  *out_io = io;
  return MESH_STREAM_KCP_ADAPTER_OK;
}

void mesh_stream_kcp_adapter_io_destroy_v1(mesh_stream_kcp_io_t *io) {
  if (!io)
    return;
  free(io->buf);
  free(io);
}

mesh_stream_kcp_adapter_result_t mesh_stream_kcp_adapter_io_live_io_v1(
    mesh_stream_kcp_io_t *io, mesh_stream_live_io_v1_t *out_io) {
  if (!io || !out_io)
    return MESH_STREAM_KCP_ADAPTER_INVALID_ARG;
  out_io->send = kcp_live_send;
  out_io->recv = kcp_live_recv;
  out_io->context = io;
  return MESH_STREAM_KCP_ADAPTER_OK;
}