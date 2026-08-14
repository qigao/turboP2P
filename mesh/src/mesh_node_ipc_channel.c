#include "mesh_node_ipc_channel.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  size_t allocation_size;
  size_t frame_size;
  uint8_t frame[];
} mesh_node_ipc_owned_frame_v1_t;

#define MESH_NODE_IPC_CHANNEL_SLOT_SIZE_V1                                \
  sizeof(mesh_node_ipc_owned_frame_v1_t *)

static int channel_capacity_valid(size_t capacity) {
  return capacity != 0u && capacity <= MESH_CONTROL_OUTBOX_MAX_ENTRIES_V1 &&
         (capacity & (capacity - 1u)) == 0u &&
         capacity <= SIZE_MAX / MESH_NODE_IPC_CHANNEL_SLOT_SIZE_V1 /
                         MESH_NODE_IPC_CHANNEL_STORAGE_FACTOR_V1;
}

static mesh_control_result_t channel_head(
    mesh_node_ipc_channel_v1_t *channel,
    mesh_node_ipc_owned_frame_v1_t **out_frame) {
  uint8_t *slot;
  size_t available = 0u;
  if (!channel || !out_frame || channel->initialized == 0u ||
      !channel->storage)
    return MESH_CONTROL_INVALID_ARG;
  slot = ring_spsc_read_acquire(&channel->ring, &available);
  if (!slot || available < MESH_NODE_IPC_CHANNEL_SLOT_SIZE_V1)
    return MESH_CONTROL_EMPTY;
  memcpy(out_frame, slot, MESH_NODE_IPC_CHANNEL_SLOT_SIZE_V1);
  return *out_frame ? MESH_CONTROL_OK : MESH_CONTROL_INVALID_STATE;
}

mesh_control_result_t mesh_node_ipc_channel_init_v1(
    mesh_node_ipc_channel_v1_t *channel, size_t capacity,
    size_t max_retained_bytes, size_t max_frame_size) {
  size_t storage_size;
  if (!channel || !channel_capacity_valid(capacity) ||
      max_retained_bytes == 0u ||
      max_retained_bytes > MESH_CONTROL_OUTBOX_MAX_RETAINED_BYTES_V1 ||
      max_frame_size < MESH_NODE_IPC_HEADER_SIZE_V1 ||
      max_frame_size > MESH_NODE_IPC_MAX_FRAME_SIZE_V1)
    return MESH_CONTROL_INVALID_ARG;

  memset(channel, 0, sizeof(*channel));
  storage_size = capacity * MESH_NODE_IPC_CHANNEL_SLOT_SIZE_V1 *
                 MESH_NODE_IPC_CHANNEL_STORAGE_FACTOR_V1;
  channel->storage = (uint8_t *)calloc(1u, storage_size);
  if (!channel->storage)
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  if (!ring_spsc_init(&channel->ring, channel->storage, storage_size)) {
    free(channel->storage);
    memset(channel, 0, sizeof(*channel));
    return MESH_CONTROL_INVALID_ARG;
  }

  channel->capacity = capacity;
  channel->max_retained_bytes = max_retained_bytes;
  channel->max_frame_size = max_frame_size;
  atomic_init(&channel->accepting, true);
  atomic_init(&channel->pending, 0u);
  atomic_init(&channel->retained_bytes, 0u);
  atomic_init(&channel->published, 0u);
  atomic_init(&channel->consumed, 0u);
  atomic_init(&channel->rejected_invalid, 0u);
  atomic_init(&channel->rejected_full, 0u);
  atomic_init(&channel->rejected_bytes, 0u);
  atomic_init(&channel->rejected_closed, 0u);
  channel->initialized = 1u;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_node_ipc_channel_try_push_v1(
    mesh_node_ipc_channel_v1_t *channel, const uint8_t *frame,
    size_t frame_size) {
  mesh_node_ipc_owned_frame_v1_t *owned;
  mesh_node_ipc_envelope_v1_t decoded;
  uint8_t *slot;
  size_t allocation_size;
  size_t retained_bytes;

  if (!channel || channel->initialized == 0u || !channel->storage || !frame ||
      frame_size < MESH_NODE_IPC_HEADER_SIZE_V1 ||
      frame_size > channel->max_frame_size ||
      frame_size > SIZE_MAX - sizeof(*owned)) {
    if (channel && channel->initialized != 0u)
      atomic_fetch_add_explicit(&channel->rejected_invalid, 1u,
                                memory_order_relaxed);
    return MESH_CONTROL_INVALID_ARG;
  }
  if (mesh_node_ipc_envelope_decode_v1(frame, frame_size, &decoded) !=
      MESH_CONTROL_OK) {
    atomic_fetch_add_explicit(&channel->rejected_invalid, 1u,
                              memory_order_relaxed);
    return MESH_CONTROL_INVALID_ARG;
  }
  if (!atomic_load_explicit(&channel->accepting, memory_order_acquire)) {
    atomic_fetch_add_explicit(&channel->rejected_closed, 1u,
                              memory_order_relaxed);
    return MESH_CONTROL_CLOSED;
  }
  if (atomic_load_explicit(&channel->pending, memory_order_acquire) >=
      channel->capacity) {
    atomic_fetch_add_explicit(&channel->rejected_full, 1u,
                              memory_order_relaxed);
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  }

  allocation_size = sizeof(*owned) + frame_size;
  retained_bytes =
      atomic_load_explicit(&channel->retained_bytes, memory_order_acquire);
  if (allocation_size > channel->max_retained_bytes ||
      retained_bytes > channel->max_retained_bytes - allocation_size) {
    atomic_fetch_add_explicit(&channel->rejected_bytes, 1u,
                              memory_order_relaxed);
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  }

  owned = (mesh_node_ipc_owned_frame_v1_t *)malloc(allocation_size);
  if (!owned) {
    atomic_fetch_add_explicit(&channel->rejected_bytes, 1u,
                              memory_order_relaxed);
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  }
  owned->allocation_size = allocation_size;
  owned->frame_size = frame_size;
  memcpy(owned->frame, frame, frame_size);
  if (mesh_node_ipc_envelope_decode_v1(owned->frame, frame_size, &decoded) !=
      MESH_CONTROL_OK) {
    free(owned);
    atomic_fetch_add_explicit(&channel->rejected_invalid, 1u,
                              memory_order_relaxed);
    return MESH_CONTROL_INVALID_ARG;
  }

  slot = ring_spsc_write_acquire(&channel->ring,
                                 MESH_NODE_IPC_CHANNEL_SLOT_SIZE_V1);
  if (!slot) {
    free(owned);
    atomic_fetch_add_explicit(&channel->rejected_full, 1u,
                              memory_order_relaxed);
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  }
  memcpy(slot, &owned, MESH_NODE_IPC_CHANNEL_SLOT_SIZE_V1);
  atomic_fetch_add_explicit(&channel->pending, 1u, memory_order_release);
  atomic_fetch_add_explicit(&channel->retained_bytes, allocation_size,
                            memory_order_release);
  ring_spsc_write_release(&channel->ring,
                          MESH_NODE_IPC_CHANNEL_SLOT_SIZE_V1);
  atomic_fetch_add_explicit(&channel->published, 1u, memory_order_relaxed);
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_node_ipc_channel_peek_v1(
    mesh_node_ipc_channel_v1_t *channel,
    mesh_node_ipc_frame_view_v1_t *out_frame) {
  mesh_node_ipc_owned_frame_v1_t *owned;
  mesh_control_result_t result;
  if (!out_frame)
    return MESH_CONTROL_INVALID_ARG;
  memset(out_frame, 0, sizeof(*out_frame));
  result = channel_head(channel, &owned);
  if (result != MESH_CONTROL_OK)
    return result;
  result = mesh_node_ipc_envelope_decode_v1(
      owned->frame, owned->frame_size, &out_frame->envelope);
  if (result != MESH_CONTROL_OK)
    return MESH_CONTROL_INVALID_STATE;
  out_frame->frame = owned->frame;
  out_frame->frame_size = owned->frame_size;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_node_ipc_channel_consume_v1(
    mesh_node_ipc_channel_v1_t *channel) {
  mesh_node_ipc_owned_frame_v1_t *owned;
  mesh_control_result_t result = channel_head(channel, &owned);
  if (result != MESH_CONTROL_OK)
    return result;
  ring_spsc_read_release(&channel->ring,
                         MESH_NODE_IPC_CHANNEL_SLOT_SIZE_V1);
  atomic_fetch_sub_explicit(&channel->pending, 1u, memory_order_release);
  atomic_fetch_sub_explicit(&channel->retained_bytes, owned->allocation_size,
                            memory_order_release);
  atomic_fetch_add_explicit(&channel->consumed, 1u, memory_order_relaxed);
  free(owned);
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_node_ipc_channel_close_v1(
    mesh_node_ipc_channel_v1_t *channel) {
  if (!channel || channel->initialized == 0u || !channel->storage)
    return MESH_CONTROL_INVALID_ARG;
  atomic_store_explicit(&channel->accepting, false, memory_order_release);
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_node_ipc_channel_get_stats_v1(
    const mesh_node_ipc_channel_v1_t *channel,
    mesh_node_ipc_channel_stats_v1_t *out_stats) {
  if (!channel || !out_stats || channel->initialized == 0u ||
      !channel->storage)
    return MESH_CONTROL_INVALID_ARG;
  memset(out_stats, 0, sizeof(*out_stats));
  out_stats->capacity = channel->capacity;
  out_stats->pending =
      atomic_load_explicit(&channel->pending, memory_order_acquire);
  out_stats->retained_bytes =
      atomic_load_explicit(&channel->retained_bytes, memory_order_acquire);
  out_stats->max_retained_bytes = channel->max_retained_bytes;
  out_stats->max_frame_size = channel->max_frame_size;
  out_stats->accepting =
      atomic_load_explicit(&channel->accepting, memory_order_acquire);
  out_stats->published =
      atomic_load_explicit(&channel->published, memory_order_relaxed);
  out_stats->consumed =
      atomic_load_explicit(&channel->consumed, memory_order_relaxed);
  out_stats->rejected_invalid =
      atomic_load_explicit(&channel->rejected_invalid, memory_order_relaxed);
  out_stats->rejected_full =
      atomic_load_explicit(&channel->rejected_full, memory_order_relaxed);
  out_stats->rejected_bytes =
      atomic_load_explicit(&channel->rejected_bytes, memory_order_relaxed);
  out_stats->rejected_closed =
      atomic_load_explicit(&channel->rejected_closed, memory_order_relaxed);
  return MESH_CONTROL_OK;
}

void mesh_node_ipc_channel_destroy_v1(mesh_node_ipc_channel_v1_t *channel) {
  if (!channel)
    return;
  if (channel->initialized != 0u && channel->storage) {
    (void)mesh_node_ipc_channel_close_v1(channel);
    while (mesh_node_ipc_channel_consume_v1(channel) == MESH_CONTROL_OK) {
    }
  }
  free(channel->storage);
  memset(channel, 0, sizeof(*channel));
}
