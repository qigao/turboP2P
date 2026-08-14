#include "mesh_control_channel.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  mesh_control_envelope_v1_t envelope;
  size_t allocation_size;
  size_t signed_frame_size;
  uint8_t payload[];
} mesh_control_owned_message_v1_t;

#define MESH_CONTROL_CHANNEL_SLOT_SIZE_V1 sizeof(mesh_control_owned_message_v1_t *)

static int mesh_control_channel_capacity_valid(size_t capacity) {
  return capacity != 0u && capacity <= MESH_CONTROL_OUTBOX_MAX_ENTRIES_V1 &&
         (capacity & (capacity - 1u)) == 0u &&
         capacity <=
             SIZE_MAX / MESH_CONTROL_CHANNEL_SLOT_SIZE_V1 / MESH_CONTROL_CHANNEL_STORAGE_FACTOR_V1;
}

static mesh_control_result_t
mesh_control_channel_head_v1(mesh_control_channel_v1_t *channel,
                             mesh_control_owned_message_v1_t **out_message) {
  uint8_t *slot;
  size_t available = 0u;

  if (channel == NULL || out_message == NULL || channel->initialized == 0u ||
      channel->storage == NULL) {
    return MESH_CONTROL_INVALID_ARG;
  }
  slot = ring_spsc_read_acquire(&channel->ring, &available);
  if (slot == NULL || available < MESH_CONTROL_CHANNEL_SLOT_SIZE_V1) {
    return MESH_CONTROL_EMPTY;
  }
  memcpy(out_message, slot, MESH_CONTROL_CHANNEL_SLOT_SIZE_V1);
  if (*out_message == NULL) {
    return MESH_CONTROL_INVALID_STATE;
  }
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_channel_init_v1(mesh_control_channel_v1_t *channel,
                                                   size_t capacity, size_t max_retained_bytes,
                                                   size_t max_payload_size) {
  size_t storage_size;

  if (channel == NULL || !mesh_control_channel_capacity_valid(capacity) ||
      max_retained_bytes == 0u || max_retained_bytes > MESH_CONTROL_OUTBOX_MAX_RETAINED_BYTES_V1 ||
      max_payload_size == 0u || max_payload_size > MESH_CONTROL_MAX_FRAME_SIZE_V1) {
    return MESH_CONTROL_INVALID_ARG;
  }
  memset(channel, 0, sizeof(*channel));
  storage_size =
      capacity * MESH_CONTROL_CHANNEL_SLOT_SIZE_V1 * MESH_CONTROL_CHANNEL_STORAGE_FACTOR_V1;
  channel->storage = (uint8_t *)calloc(1u, storage_size);
  if (channel->storage == NULL) {
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  }
  if (!ring_spsc_init(&channel->ring, channel->storage, storage_size)) {
    free(channel->storage);
    memset(channel, 0, sizeof(*channel));
    return MESH_CONTROL_INVALID_ARG;
  }
  channel->capacity = capacity;
  channel->max_retained_bytes = max_retained_bytes;
  channel->max_payload_size = max_payload_size;
  atomic_init(&channel->accepting, true);
  atomic_init(&channel->pending, 0u);
  atomic_init(&channel->retained_bytes, 0u);
  atomic_init(&channel->published, 0u);
  atomic_init(&channel->consumed, 0u);
  atomic_init(&channel->rejected_full, 0u);
  atomic_init(&channel->rejected_bytes, 0u);
  atomic_init(&channel->rejected_closed, 0u);
  channel->initialized = 1u;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_channel_try_push_v1(mesh_control_channel_v1_t *channel,
                                                       const mesh_control_envelope_v1_t *envelope,
                                                       const uint8_t *payload,
                                                       size_t payload_size) {
  return mesh_control_channel_try_push_signed_v1(channel, envelope, payload, payload_size, NULL,
                                                 0u);
}

mesh_control_result_t
mesh_control_channel_try_push_signed_v1(mesh_control_channel_v1_t *channel,
                                        const mesh_control_envelope_v1_t *envelope,
                                        const uint8_t *payload, size_t payload_size,
                                        const uint8_t *signed_frame, size_t signed_frame_size) {
  mesh_control_owned_message_v1_t *message;
  uint8_t *slot;
  size_t allocation_size;
  size_t retained_bytes;

  if (channel == NULL || envelope == NULL || channel->initialized == 0u ||
      channel->storage == NULL || payload_size != envelope->payload_size ||
      payload_size > channel->max_payload_size || (payload_size != 0u && payload == NULL) ||
      signed_frame_size > MESH_CONTROL_MAX_FRAME_SIZE_V1 ||
      (signed_frame_size != 0u && signed_frame == NULL) ||
      mesh_control_envelope_validate_v1(envelope) != MESH_CONTROL_OK) {
    return MESH_CONTROL_INVALID_ARG;
  }
  if (!atomic_load_explicit(&channel->accepting, memory_order_acquire)) {
    atomic_fetch_add_explicit(&channel->rejected_closed, 1u, memory_order_relaxed);
    return MESH_CONTROL_CLOSED;
  }
  if (atomic_load_explicit(&channel->pending, memory_order_acquire) >= channel->capacity) {
    atomic_fetch_add_explicit(&channel->rejected_full, 1u, memory_order_relaxed);
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  }
  if (payload_size > SIZE_MAX - sizeof(*message) ||
      signed_frame_size > SIZE_MAX - sizeof(*message) - payload_size) {
    return MESH_CONTROL_INVALID_ARG;
  }
  allocation_size = sizeof(*message) + payload_size + signed_frame_size;
  retained_bytes = atomic_load_explicit(&channel->retained_bytes, memory_order_acquire);
  if (allocation_size > channel->max_retained_bytes ||
      retained_bytes > channel->max_retained_bytes - allocation_size) {
    atomic_fetch_add_explicit(&channel->rejected_bytes, 1u, memory_order_relaxed);
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  }

  message = (mesh_control_owned_message_v1_t *)malloc(allocation_size);
  if (message == NULL) {
    atomic_fetch_add_explicit(&channel->rejected_bytes, 1u, memory_order_relaxed);
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  }
  message->envelope = *envelope;
  message->allocation_size = allocation_size;
  message->signed_frame_size = signed_frame_size;
  if (payload_size != 0u) {
    memcpy(message->payload, payload, payload_size);
  }
  if (signed_frame_size != 0u) {
    memcpy(message->payload + payload_size, signed_frame, signed_frame_size);
  }

  slot = ring_spsc_write_acquire(&channel->ring, MESH_CONTROL_CHANNEL_SLOT_SIZE_V1);
  if (slot == NULL) {
    free(message);
    atomic_fetch_add_explicit(&channel->rejected_full, 1u, memory_order_relaxed);
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  }
  memcpy(slot, &message, MESH_CONTROL_CHANNEL_SLOT_SIZE_V1);
  atomic_fetch_add_explicit(&channel->pending, 1u, memory_order_release);
  atomic_fetch_add_explicit(&channel->retained_bytes, allocation_size, memory_order_release);
  ring_spsc_write_release(&channel->ring, MESH_CONTROL_CHANNEL_SLOT_SIZE_V1);
  atomic_fetch_add_explicit(&channel->published, 1u, memory_order_relaxed);
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_channel_peek_v1(mesh_control_channel_v1_t *channel,
                                                   mesh_control_message_view_v1_t *out_message) {
  mesh_control_owned_message_v1_t *message;
  mesh_control_result_t result;

  if (out_message == NULL) {
    return MESH_CONTROL_INVALID_ARG;
  }
  result = mesh_control_channel_head_v1(channel, &message);
  if (result != MESH_CONTROL_OK) {
    return result;
  }
  out_message->envelope = message->envelope;
  out_message->payload = message->payload;
  out_message->payload_size = message->envelope.payload_size;
  out_message->signed_frame =
      message->signed_frame_size != 0u ? message->payload + message->envelope.payload_size : NULL;
  out_message->signed_frame_size = message->signed_frame_size;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_channel_consume_v1(mesh_control_channel_v1_t *channel) {
  mesh_control_owned_message_v1_t *message;
  mesh_control_result_t result;

  result = mesh_control_channel_head_v1(channel, &message);
  if (result != MESH_CONTROL_OK) {
    return result;
  }
  ring_spsc_read_release(&channel->ring, MESH_CONTROL_CHANNEL_SLOT_SIZE_V1);
  atomic_fetch_sub_explicit(&channel->pending, 1u, memory_order_release);
  atomic_fetch_sub_explicit(&channel->retained_bytes, message->allocation_size,
                            memory_order_release);
  atomic_fetch_add_explicit(&channel->consumed, 1u, memory_order_relaxed);
  free(message);
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_channel_close_v1(mesh_control_channel_v1_t *channel) {
  if (channel == NULL || channel->initialized == 0u || channel->storage == NULL) {
    return MESH_CONTROL_INVALID_ARG;
  }
  atomic_store_explicit(&channel->accepting, false, memory_order_release);
  return MESH_CONTROL_OK;
}

mesh_control_result_t
mesh_control_channel_get_stats_v1(const mesh_control_channel_v1_t *channel,
                                  mesh_control_channel_stats_v1_t *out_stats) {
  if (channel == NULL || out_stats == NULL || channel->initialized == 0u ||
      channel->storage == NULL) {
    return MESH_CONTROL_INVALID_ARG;
  }
  memset(out_stats, 0, sizeof(*out_stats));
  out_stats->capacity = channel->capacity;
  out_stats->pending = atomic_load_explicit(&channel->pending, memory_order_acquire);
  out_stats->retained_bytes = atomic_load_explicit(&channel->retained_bytes, memory_order_acquire);
  out_stats->max_retained_bytes = channel->max_retained_bytes;
  out_stats->max_payload_size = channel->max_payload_size;
  out_stats->accepting = atomic_load_explicit(&channel->accepting, memory_order_acquire);
  out_stats->published = atomic_load_explicit(&channel->published, memory_order_relaxed);
  out_stats->consumed = atomic_load_explicit(&channel->consumed, memory_order_relaxed);
  out_stats->rejected_full = atomic_load_explicit(&channel->rejected_full, memory_order_relaxed);
  out_stats->rejected_bytes = atomic_load_explicit(&channel->rejected_bytes, memory_order_relaxed);
  out_stats->rejected_closed =
      atomic_load_explicit(&channel->rejected_closed, memory_order_relaxed);
  return MESH_CONTROL_OK;
}

void mesh_control_channel_destroy_v1(mesh_control_channel_v1_t *channel) {
  if (channel == NULL) {
    return;
  }
  if (channel->initialized != 0u && channel->storage != NULL) {
    (void)mesh_control_channel_close_v1(channel);
    while (mesh_control_channel_consume_v1(channel) == MESH_CONTROL_OK) {
    }
  }
  free(channel->storage);
  memset(channel, 0, sizeof(*channel));
}
