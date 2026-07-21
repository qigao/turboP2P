#ifndef TURBO_P2P_MESH_MGMT_CORONET_ADAPTER_H
#define TURBO_P2P_MESH_MGMT_CORONET_ADAPTER_H

#include "mesh_mgmt_transport.h"

#include <CoroNet/turbo_coro_socket.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Build caller-owned transport IO over a fully-open TLS 1.3 CoroNet socket.
 * The returned callbacks borrow the socket and release only recv buffers.
 */
mesh_mgmt_transport_result_t mesh_mgmt_transport_coronet_io_v1(mesh_mgmt_transport_io_v1_t *out_io,
                                                               coro_socket_t *socket);

/**
 * Initialize over a caller-owned, fully-open TLS 1.3 CoroNet socket. The
 * transport releases recv buffers but never closes or destroys the socket.
 */
mesh_mgmt_transport_result_t
mesh_mgmt_transport_init_coronet_v1(mesh_mgmt_transport_v1_t *transport, coro_socket_t *socket);

#ifdef __cplusplus
}
#endif

#endif
