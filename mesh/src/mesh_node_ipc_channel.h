#ifndef MESH_NODE_IPC_CHANNEL_H
#define MESH_NODE_IPC_CHANNEL_H

#include "mesh_node_ipc.h"
#include "ring_buffer_spsc.h"

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_NODE_IPC_CHANNEL_STORAGE_FACTOR_V1 2u

typedef struct {
  const uint8_t *frame;
  size_t frame_size;
  mesh_node_ipc_envelope_v1_t envelope;
} mesh_node_ipc_frame_view_v1_t;

typedef struct {
  size_t capacity;
  size_t pending;
  size_t retained_bytes;
  size_t max_retained_bytes;
  size_t max_frame_size;
  uint8_t accepting;
  uint64_t published;
  uint64_t consumed;
  uint64_t rejected_invalid;
  uint64_t rejected_full;
  uint64_t rejected_bytes;
  uint64_t rejected_closed;
} mesh_node_ipc_channel_stats_v1_t;

/**
 * Bounded SPSC ownership-transfer channel for canonical MeshNodeIPC frames.
 * One FlowMQ/adapter owner is the sole producer and one domain owner is the
 * sole consumer. Callback-borrowed bytes are copied before publication.
 */
typedef struct {
  ring_spsc_t ring;
  uint8_t *storage;
  size_t capacity;
  size_t max_retained_bytes;
  size_t max_frame_size;
  atomic_bool accepting;
  atomic_size_t pending;
  atomic_size_t retained_bytes;
  atomic_uint_fast64_t published;
  atomic_uint_fast64_t consumed;
  atomic_uint_fast64_t rejected_invalid;
  atomic_uint_fast64_t rejected_full;
  atomic_uint_fast64_t rejected_bytes;
  atomic_uint_fast64_t rejected_closed;
  uint8_t initialized;
} mesh_node_ipc_channel_v1_t;

mesh_control_result_t mesh_node_ipc_channel_init_v1(
    mesh_node_ipc_channel_v1_t *channel, size_t capacity,
    size_t max_retained_bytes, size_t max_frame_size);

/** Validates and copies one complete canonical frame before returning. */
mesh_control_result_t mesh_node_ipc_channel_try_push_v1(
    mesh_node_ipc_channel_v1_t *channel, const uint8_t *frame,
    size_t frame_size);

/** Borrowed until consume, destroy, or another consumer-side mutation. */
mesh_control_result_t mesh_node_ipc_channel_peek_v1(
    mesh_node_ipc_channel_v1_t *channel,
    mesh_node_ipc_frame_view_v1_t *out_frame);

mesh_control_result_t mesh_node_ipc_channel_consume_v1(
    mesh_node_ipc_channel_v1_t *channel);
mesh_control_result_t mesh_node_ipc_channel_close_v1(
    mesh_node_ipc_channel_v1_t *channel);
mesh_control_result_t mesh_node_ipc_channel_get_stats_v1(
    const mesh_node_ipc_channel_v1_t *channel,
    mesh_node_ipc_channel_stats_v1_t *out_stats);

/** Producer and consumer must be quiescent. Pending frames are released. */
void mesh_node_ipc_channel_destroy_v1(mesh_node_ipc_channel_v1_t *channel);

#ifdef __cplusplus
}
#endif

#endif
