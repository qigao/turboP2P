#ifndef MESH_CONTROL_CHANNEL_H
#define MESH_CONTROL_CHANNEL_H

#include "mesh_control_primitives.h"
#include "ring_buffer_spsc.h"

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_CONTROL_CHANNEL_STORAGE_FACTOR_V1 2u

typedef struct {
  mesh_control_envelope_v1_t envelope;
  const uint8_t *payload;
  size_t payload_size;
  /** Original authenticated transport frame, when supplied by the adapter. */
  const uint8_t *signed_frame;
  size_t signed_frame_size;
} mesh_control_message_view_v1_t;

typedef struct {
  size_t capacity;
  size_t pending;
  size_t retained_bytes;
  size_t max_retained_bytes;
  size_t max_payload_size;
  uint8_t accepting;
  uint64_t published;
  uint64_t consumed;
  uint64_t rejected_full;
  uint64_t rejected_bytes;
  uint64_t rejected_closed;
} mesh_control_channel_stats_v1_t;

/**
 * Bounded SPSC ownership-transfer channel. One transport thread is the sole
 * producer and one domain-owner thread is the sole consumer. A pair of these
 * channels provides full duplex communication without sharing mutable Mesh
 * state between Iris callbacks and the Mesh owner loop.
 */
typedef struct {
  ring_spsc_t ring;
  uint8_t *storage;
  size_t capacity;
  size_t max_retained_bytes;
  size_t max_payload_size;
  atomic_bool accepting;
  atomic_size_t pending;
  atomic_size_t retained_bytes;
  atomic_uint_fast64_t published;
  atomic_uint_fast64_t consumed;
  atomic_uint_fast64_t rejected_full;
  atomic_uint_fast64_t rejected_bytes;
  atomic_uint_fast64_t rejected_closed;
  uint8_t initialized;
} mesh_control_channel_v1_t;

mesh_control_result_t mesh_control_channel_init_v1(mesh_control_channel_v1_t *channel,
                                                   size_t capacity, size_t max_retained_bytes,
                                                   size_t max_payload_size);

/**
 * Copies a callback-borrowed payload before returning. On success ownership is
 * transferred to the consumer. This is the only producer operation.
 */
mesh_control_result_t mesh_control_channel_try_push_v1(mesh_control_channel_v1_t *channel,
                                                       const mesh_control_envelope_v1_t *envelope,
                                                       const uint8_t *payload, size_t payload_size);

/**
 * Copies both the decoded payload and its original signed frame into one
 * bounded owned allocation. Durable control paths require this variant.
 */
mesh_control_result_t
mesh_control_channel_try_push_signed_v1(mesh_control_channel_v1_t *channel,
                                        const mesh_control_envelope_v1_t *envelope,
                                        const uint8_t *payload, size_t payload_size,
                                        const uint8_t *signed_frame, size_t signed_frame_size);

/**
 * Returns a borrowed view of the queue head. It remains valid until consume,
 * destroy, or any consumer-side mutation. Only the consumer may call it.
 */
mesh_control_result_t mesh_control_channel_peek_v1(mesh_control_channel_v1_t *channel,
                                                   mesh_control_message_view_v1_t *out_message);

/** Releases the queue head and its owned payload. */
mesh_control_result_t mesh_control_channel_consume_v1(mesh_control_channel_v1_t *channel);

/** Stops new publications while leaving already published messages drainable. */
mesh_control_result_t mesh_control_channel_close_v1(mesh_control_channel_v1_t *channel);

mesh_control_result_t mesh_control_channel_get_stats_v1(const mesh_control_channel_v1_t *channel,
                                                        mesh_control_channel_stats_v1_t *out_stats);

/** Producer and consumer must be quiescent. Remaining messages are released. */
void mesh_control_channel_destroy_v1(mesh_control_channel_v1_t *channel);

#ifdef __cplusplus
}
#endif

#endif
