#ifndef TURBO_P2P_MESH_STREAM_CHANNEL_H
#define TURBO_P2P_MESH_STREAM_CHANNEL_H

#include "mesh_stream_transport.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_STREAM_CHANNEL_PEER_ID_SIZE 32u

typedef enum {
  MESH_STREAM_CHANNEL_OK = 0,
  MESH_STREAM_CHANNEL_INTERRUPTED = 1,
  MESH_STREAM_CHANNEL_INVALID_ARG = -1,
  MESH_STREAM_CHANNEL_INVALID_STATE = -2,
  MESH_STREAM_CHANNEL_STALE_ADMISSION = -3,
  MESH_STREAM_CHANNEL_TRANSPORT_ERROR = -4,
  MESH_STREAM_CHANNEL_AUTH_REQUIRED = -5,
} mesh_stream_channel_result_t;

typedef enum {
  MESH_STREAM_CHANNEL_UNINITIALIZED = 0,
  MESH_STREAM_CHANNEL_READY = 1,
  MESH_STREAM_CHANNEL_CLOSED = 2,
  MESH_STREAM_CHANNEL_REVOKED = 3,
  MESH_STREAM_CHANNEL_FAILED = 4,
} mesh_stream_channel_state_t;

/**
 * Immutable proof supplied by the authenticated mesh peer owner. generation
 * changes whenever that owner's authenticated lifecycle is replaced.
 */
typedef struct {
  uint8_t remote_peer_id[MESH_STREAM_CHANNEL_PEER_ID_SIZE];
  uint64_t generation;
  uint8_t stream_id[MESH_STREAM_ID_SIZE];
  uint64_t stream_epoch;
} mesh_stream_channel_admission_v1_t;

/**
 * Internal single-owner lifecycle wrapper. Calls are serialized by one
 * coroutine/event-loop owner. transport owns its receive buffer; neither the
 * channel nor transport owns io.context or a bound CoroNet socket. The caller
 * must zero-initialize this object and call destroy before reinitializing it.
 */
typedef struct {
  mesh_stream_channel_admission_v1_t admission;
  mesh_stream_transport_v1_t transport;
  mesh_stream_channel_state_t state;
  mesh_stream_transport_result_t last_transport_result;
  mesh_stream_session_result_t last_session_result;
  int last_io_result;
  int last_application_result;
  uint64_t received_bytes;
  uint64_t received_frames;
  uint64_t sent_control_frames;
} mesh_stream_channel_v1_t;

mesh_stream_channel_result_t mesh_stream_channel_init_v1(
    mesh_stream_channel_v1_t *channel, const mesh_stream_channel_admission_v1_t *admission,
    const mesh_stream_transport_config_v1_t *config, const mesh_stream_transport_io_v1_t *io,
    mesh_stream_transport_event_fn on_event, void *event_context);

/** Release channel-owned memory and return to UNINITIALIZED. */
void mesh_stream_channel_destroy_v1(mesh_stream_channel_v1_t *channel);

mesh_stream_channel_result_t mesh_stream_channel_feed_v1(mesh_stream_channel_v1_t *channel,
                                                         uint64_t admission_generation,
                                                         const uint8_t *bytes, size_t len,
                                                         size_t *out_frames);

mesh_stream_channel_result_t mesh_stream_channel_pump_once_v1(mesh_stream_channel_v1_t *channel,
                                                              uint64_t admission_generation,
                                                              size_t *out_frames);

/**
 * Revoke only the matching authenticated lifecycle. A stale disconnect cannot
 * revoke a channel created for a later peer generation.
 */
mesh_stream_channel_result_t mesh_stream_channel_revoke_v1(mesh_stream_channel_v1_t *channel,
                                                           uint64_t admission_generation);

/** Locally close a matching channel. Repeated shutdown of a terminal channel is harmless. */
mesh_stream_channel_result_t mesh_stream_channel_close_v1(mesh_stream_channel_v1_t *channel,
                                                          uint64_t admission_generation);

#ifdef __cplusplus
}
#endif

#endif
