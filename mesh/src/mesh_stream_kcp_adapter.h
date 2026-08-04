#ifndef TURBO_P2P_MESH_STREAM_KCP_ADAPTER_H
#define TURBO_P2P_MESH_STREAM_KCP_ADAPTER_H

#include "mesh_stream_live.h"

#include <CoroNet/turbo_coro_socket.h>

#ifdef __cplusplus
extern "C" {
#endif

/* P7: bind the mesh_stream_live session to a CoroNet KCP socket. The live
 * session's FEC group maps onto turbo_kcp's Reed-Solomon FEC config, and the
 * datagram io is bridged to coro_socket_send/recv with a stream-to-frame
 * reassembler (coro_socket_recv on KCP returns a byte stream, not one frame
 * per call). PSK/keying and connection setup stay the caller's job
 * (coro_socket_set_kcp_config + connect/listen). */

typedef enum {
  MESH_STREAM_KCP_ADAPTER_OK = 0,
  MESH_STREAM_KCP_ADAPTER_INVALID_ARG = -1,
  MESH_STREAM_KCP_ADAPTER_UNSUPPORTED = -2,
  MESH_STREAM_KCP_ADAPTER_IO = -3,
} mesh_stream_kcp_adapter_result_t;

typedef struct mesh_stream_kcp_io_s mesh_stream_kcp_io_t;

/**
 * Map the live session's FEC group (fec_data_shards data + fec_parity_shards
 * parity, max block bytes as the shard payload) to a turbo_kcp Reed-Solomon
 * FEC config. A live config with no FEC yields backend TURBO_KCP_FEC_BACKEND_NONE
 * (callers skip applying it). Fails with MESH_STREAM_KCP_ADAPTER_UNSUPPORTED
 * when the Reed-Solomon backend is not compiled into the transport. The
 * mapped config is applied by setting it on a turbo_kcp_config_t and passing
 * that to coro_socket_set_kcp_config before bind/connect.
 */
mesh_stream_kcp_adapter_result_t mesh_stream_kcp_adapter_fec_config_v1(
    const mesh_stream_live_config_v1_t *live_config,
    turbo_kcp_fec_config_t *out_fec);

/**
 * Create a stream-to-frame io bridge over a connected KCP coro_socket. The
 * bridge reassembles coro_socket_recv byte chunks into complete live frames
 * (mesh_stream_live_frame_complete_v1) so the session sees datagram
 * semantics. max_frame_bytes is the largest frame (max block + header). Must
 * be created/destroyed from the socket's owning coroutine context.
 */
mesh_stream_kcp_adapter_result_t mesh_stream_kcp_adapter_io_create_v1(
    coro_socket_t *socket, uint64_t recv_timeout_ms, size_t max_frame_bytes,
    mesh_stream_kcp_io_t **out_io);

void mesh_stream_kcp_adapter_io_destroy_v1(mesh_stream_kcp_io_t *io);

/** Fill the live datagram io backed by the bridge. */
mesh_stream_kcp_adapter_result_t mesh_stream_kcp_adapter_io_live_io_v1(
    mesh_stream_kcp_io_t *io, mesh_stream_live_io_v1_t *out_io);

#ifdef __cplusplus
}
#endif

#endif