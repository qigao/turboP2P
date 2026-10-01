#ifndef TURBO_P2P_MESH_STREAM_TRANSPORT_H
#define TURBO_P2P_MESH_STREAM_TRANSPORT_H

#include "mesh_stream_session.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_STREAM_SEND_HWM_MAX (1024u * 1024u)
#define MESH_STREAM_RECV_TIMEOUT_MIN_MS 100u
#define MESH_STREAM_RECV_TIMEOUT_MAX_MS 600000u

typedef enum {
  MESH_STREAM_TRANSPORT_OK = 0,
  MESH_STREAM_TRANSPORT_INTERRUPTED = 1,
  MESH_STREAM_TRANSPORT_INVALID_ARG = -1,
  MESH_STREAM_TRANSPORT_NO_MEMORY = -2,
  MESH_STREAM_TRANSPORT_IO_ERROR = -3,
  MESH_STREAM_TRANSPORT_SESSION_ERROR = -4,
  MESH_STREAM_TRANSPORT_APPLICATION_REJECTED = -5,
  MESH_STREAM_TRANSPORT_INVALID_STATE = -6,
  MESH_STREAM_TRANSPORT_RESOURCE_EXHAUSTED = -7,
  MESH_STREAM_TRANSPORT_SECURE_CHANNEL_REQUIRED = -8,
} mesh_stream_transport_result_t;

typedef enum {
  MESH_STREAM_TRANSPORT_UNINITIALIZED = 0,
  MESH_STREAM_TRANSPORT_READY = 1,
  MESH_STREAM_TRANSPORT_CLOSED = 2,
  MESH_STREAM_TRANSPORT_FAILED = 3,
} mesh_stream_transport_state_t;

/**
 * recv returns an owned chunk on success; release_recv must release it exactly
 * once. send must copy or consume bytes before returning because control frames
 * are encoded in temporary storage. A synchronous send returns zero only
 * after the full write completes; asynchronous admission uses init_async.
 */
typedef struct {
  int (*recv)(void *context, uint8_t **out_bytes, size_t *out_len);
  void (*release_recv)(void *context, uint8_t *bytes);
  int (*send)(void *context, const uint8_t *bytes, size_t len);
  int (*set_send_hwm)(void *context, size_t bytes);
  int (*set_receive_timeout)(void *context, uint64_t timeout_ms);
  void *context;
} mesh_stream_transport_io_v1_t;

/** Admission only: copy/retain bytes before returning, then deliver exactly one
 * terminal through complete_send. Never complete inline or block this owner.
 * Tokens belong to one initialized transport lifetime; quiesce callbacks before
 * destroy/reinitialize. A backend must serialize all writes on this connection.
 */
typedef int (*mesh_stream_transport_async_send_fn)(void *context, const uint8_t *bytes,
                                                   size_t len, uint64_t token);

typedef int (*mesh_stream_transport_event_fn)(void *context,
                                              const mesh_stream_receive_event_v1_t *event);

typedef struct {
  mesh_stream_receiver_config_v1_t receiver;
  uint64_t window_update_threshold;
  uint64_t receive_timeout_ms;
  size_t send_high_watermark;
} mesh_stream_transport_config_v1_t;

/**
 * One coroutine/event-loop owner must serialize all calls. buffer owns one
 * allocation exactly receiver.max_frame_size bytes long. The adapter does not
 * own io.context (including the backend connection).
 */
typedef struct {
  mesh_stream_transport_config_v1_t config;
  mesh_stream_transport_io_v1_t io;
  mesh_stream_receiver_session_v1_t session;
  mesh_stream_transport_event_fn on_event;
  void *event_context;
  uint8_t *buffer;
  size_t buffer_begin;
  size_t buffer_end;
  mesh_stream_transport_state_t state;
  mesh_stream_session_result_t last_session_result;
  int last_io_result;
  int last_application_result;
  uint64_t received_bytes;
  uint64_t received_frames;
  uint64_t sent_control_frames;
  mesh_stream_transport_async_send_fn send_async;
  mesh_stream_control_preparation_v1_t pending_control;
  uint64_t pending_send_token;
  size_t pending_send_size;
  uint8_t send_pending;
} mesh_stream_transport_v1_t;

mesh_stream_transport_result_t
mesh_stream_transport_init_v1(mesh_stream_transport_v1_t *transport,
                              const mesh_stream_transport_config_v1_t *config,
                              const mesh_stream_transport_io_v1_t *io,
                              mesh_stream_transport_event_fn on_event, void *event_context);

/**
 * Callback-driven counterpart to init. io.send must be NULL; recv/release_recv
 * are unused and may be NULL. feed copies borrowed receive views into the same
 * bounded window. While one control send is pending, buffered frames wait for
 * its terminal; admission never advances advertised credit or activates ACCEPT.
 */
mesh_stream_transport_result_t mesh_stream_transport_init_async_v1(
    mesh_stream_transport_v1_t *transport, const mesh_stream_transport_config_v1_t *config,
    const mesh_stream_transport_io_v1_t *io, mesh_stream_transport_async_send_fn send_async,
    mesh_stream_transport_event_fn on_event, void *event_context);

/**
 * Settle the exact pending token. Success requires the complete encoded size;
 * error/cancellation/partial completion makes the transport terminally FAILED
 * without committing the control. Success commits then drains buffered frames,
 * possibly admitting the next control. Duplicate/stale tokens are rejected
 * without mutating the live pending control. Views in callbacks remain borrowed.
 */
mesh_stream_transport_result_t mesh_stream_transport_complete_send_v1(
    mesh_stream_transport_v1_t *transport, uint64_t token, int io_result,
    size_t sent_bytes, size_t *out_frames);

void mesh_stream_transport_destroy_v1(mesh_stream_transport_v1_t *transport);

/**
 * Copy arbitrary transport fragments into the bounded receive window and
 * synchronously deliver every complete frame. on_event views are invalid when
 * the callback returns. An error makes the adapter terminally FAILED.
 */
mesh_stream_transport_result_t mesh_stream_transport_feed_v1(mesh_stream_transport_v1_t *transport,
                                                             const uint8_t *bytes, size_t len,
                                                             size_t *out_frames);

/** Receive one owned chunk, release it once, and feed it into the adapter. */
mesh_stream_transport_result_t
mesh_stream_transport_pump_once_v1(mesh_stream_transport_v1_t *transport, size_t *out_frames);

#ifdef __cplusplus
}
#endif

#endif
