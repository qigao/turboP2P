#ifndef TURBO_P2P_MESH_MGMT_CONNECTION_H
#define TURBO_P2P_MESH_MGMT_CONNECTION_H

#include "mesh_mgmt_dispatch.h"
#include "mesh_mgmt_transport.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  MESH_MGMT_CONNECTION_OK = 0,
  MESH_MGMT_CONNECTION_PENDING = 1,
  MESH_MGMT_CONNECTION_BUSY = 2,
  MESH_MGMT_CONNECTION_INVALID_ARG = -1,
  MESH_MGMT_CONNECTION_INVALID_STATE = -2,
  MESH_MGMT_CONNECTION_INVALID_FRAME = -3,
  MESH_MGMT_CONNECTION_TRANSPORT_FAILED = -4,
  MESH_MGMT_CONNECTION_DISPATCH_FAILED = -5,
  MESH_MGMT_CONNECTION_EVENT_REJECTED = -6,
  MESH_MGMT_CONNECTION_LOCAL_FAILED = -7,
} mesh_mgmt_connection_result_t;

typedef enum {
  MESH_MGMT_CONNECTION_UNINITIALIZED = 0,
  MESH_MGMT_CONNECTION_READY = 1,
  MESH_MGMT_CONNECTION_TERMINAL = 2,
} mesh_mgmt_connection_state_t;

/**
 * Synchronous observer/consumer boundary. Borrowed envelope views are valid
 * only for this call. Return zero only after the event has been accepted.
 * Only mesh_mgmt_connection_send_event_response_v1() may re-enter the
 * connection from this callback.
 */
typedef int (*mesh_mgmt_connection_event_fn)(void *context,
                                             const mesh_mgmt_dispatch_event_v1_t *event);

typedef struct {
  mesh_mgmt_dispatch_config_v1_t dispatch;
  mesh_mgmt_transport_io_v1_t io;
  uint8_t transport_peer_id[32];
  mesh_mgmt_connection_event_fn on_event;
  void *event_context;
} mesh_mgmt_connection_config_v1_t;

/**
 * Single event-loop owner; no internal locking. The IO context and its socket
 * remain caller-owned and must outlive this object.
 */
typedef struct {
  mesh_mgmt_transport_v1_t transport;
  mesh_mgmt_dispatcher_v1_t dispatcher;
  uint8_t transport_peer_id[32];
  mesh_mgmt_connection_event_fn on_event;
  void *event_context;
  mesh_mgmt_connection_state_t state;
  mesh_mgmt_connection_result_t last_error;
  mesh_mgmt_transport_result_t last_transport_result;
  mesh_mgmt_dispatch_result_t last_dispatch_result;
  mesh_mgmt_dispatch_stage_t last_dispatch_stage;
  int last_event_result;
  int in_event_callback;
  uint8_t pending_send_kind;
} mesh_mgmt_connection_v1_t;

/** Initialize a zero-initialized connection over caller-owned secure IO. */
mesh_mgmt_connection_result_t
mesh_mgmt_connection_init_v1(mesh_mgmt_connection_v1_t *connection,
                             const mesh_mgmt_connection_config_v1_t *config);

/** Async init ignores config.io and uses the explicitly supplied async IO. */
mesh_mgmt_connection_result_t mesh_mgmt_connection_init_async_v1(
    mesh_mgmt_connection_v1_t *connection, const mesh_mgmt_connection_config_v1_t *config,
    const mesh_mgmt_transport_async_io_v1_t *io);

/** Complete an admitted write; only a successful matching HELLO/ACK marks it sent. */
mesh_mgmt_connection_result_t mesh_mgmt_connection_complete_send_v1(
    mesh_mgmt_connection_v1_t *connection, uint64_t token, int success, size_t bytes);

/** Destroy owned protocol state. The IO context/socket is never destroyed. */
void mesh_mgmt_connection_destroy_v1(mesh_mgmt_connection_v1_t *connection);

/** Mark a ready connection terminal after a local orchestration failure. */
mesh_mgmt_connection_result_t mesh_mgmt_connection_abort_v1(mesh_mgmt_connection_v1_t *connection);

/**
 * Receive, authenticate and synchronously deliver one frame, then commit its
 * borrowed transport receipt. Async PENDING/BUSY preserve the connection;
 * pumping is paused until the pending write completes. Failures are terminal.
 */
mesh_mgmt_connection_result_t
mesh_mgmt_connection_pump_once_v1(mesh_mgmt_connection_v1_t *connection, uint64_t now_ms);

/** Send HELLO; async admission returns PENDING and marks sent only on completion. */
mesh_mgmt_connection_result_t
mesh_mgmt_connection_send_hello_v1(mesh_mgmt_connection_v1_t *connection, const uint8_t *frame,
                                   size_t frame_len);

/** Send HELLO_ACK; async admission marks acknowledged only on completion. */
mesh_mgmt_connection_result_t
mesh_mgmt_connection_send_hello_ack_v1(mesh_mgmt_connection_v1_t *connection, const uint8_t *frame,
                                       size_t frame_len);

/** Send after establishment. Async PENDING admits a write; BUSY admits nothing. */
mesh_mgmt_connection_result_t mesh_mgmt_connection_send_v1(mesh_mgmt_connection_v1_t *connection,
                                                           const uint8_t *frame, size_t frame_len);

/**
 * Send one immediate non-handshake response while handling an accepted event.
 * This is the only connection operation permitted from on_event. The frame
 * passes the same outbound schema, feature, identity, and transport checks as
 * mesh_mgmt_connection_send_v1().
 */
mesh_mgmt_connection_result_t
mesh_mgmt_connection_send_event_response_v1(
    mesh_mgmt_connection_v1_t *connection,
    const uint8_t *frame,
    size_t frame_len);

#ifdef __cplusplus
}
#endif

#endif
