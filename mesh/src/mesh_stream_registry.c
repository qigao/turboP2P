#include "mesh_stream_registry.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

static int bytes_are_zero(const uint8_t *bytes, size_t len) {
  uint8_t combined = 0u;
  size_t index = 0u;

  for (index = 0u; index < len; index++)
    combined |= bytes[index];
  return combined == 0u;
}

static int handles_equal(mesh_stream_channel_handle_v1_t left,
                         mesh_stream_channel_handle_v1_t right) {
  return left.registry == right.registry && left.slot == right.slot &&
         left.generation == right.generation;
}

static mesh_stream_channel_handle_v1_t slot_handle(const mesh_stream_registry_v1_t *registry,
                                                   size_t index,
                                                   const mesh_stream_registry_slot_v1_t *slot) {
  mesh_stream_channel_handle_v1_t handle;

  handle.registry = registry;
  handle.slot = index;
  handle.registry_generation = 0u;
  handle.generation = slot->generation;
  return handle;
}

static mesh_stream_registry_result_t validate_handle(const mesh_stream_registry_v1_t *registry,
                                                     mesh_stream_channel_handle_v1_t handle,
                                                     mesh_stream_registry_slot_v1_t **out_slot) {
  mesh_stream_registry_slot_v1_t *slot = NULL;

  if (!registry || !out_slot)
    return MESH_STREAM_REGISTRY_INVALID_ARG;
  *out_slot = NULL;
  if (!registry->slots)
    return MESH_STREAM_REGISTRY_INVALID_STATE;
  if (handle.registry != registry || handle.registry_generation == 0u ||
      handle.registry_generation != registry->config.owner_generation || handle.generation == 0u ||
      handle.slot >= registry->config.capacity) {
    return MESH_STREAM_REGISTRY_STALE_HANDLE;
  }
  slot = &registry->slots[handle.slot];
  if (!slot->occupied || !handles_equal(handle, slot_handle(registry, handle.slot, slot)))
    return MESH_STREAM_REGISTRY_STALE_HANDLE;
  *out_slot = slot;
  return MESH_STREAM_REGISTRY_OK;
}

static mesh_stream_registry_result_t
map_channel_result(mesh_stream_channel_result_t channel_result) {
  switch (channel_result) {
  case MESH_STREAM_CHANNEL_OK:
    return MESH_STREAM_REGISTRY_OK;
  case MESH_STREAM_CHANNEL_INTERRUPTED:
    return MESH_STREAM_REGISTRY_INTERRUPTED;
  case MESH_STREAM_CHANNEL_INVALID_ARG:
    return MESH_STREAM_REGISTRY_INVALID_ARG;
  case MESH_STREAM_CHANNEL_INVALID_STATE:
    return MESH_STREAM_REGISTRY_INVALID_STATE;
  case MESH_STREAM_CHANNEL_AUTH_REQUIRED:
    return MESH_STREAM_REGISTRY_AUTH_REQUIRED;
  case MESH_STREAM_CHANNEL_STALE_ADMISSION:
  case MESH_STREAM_CHANNEL_TRANSPORT_ERROR:
  default:
    return MESH_STREAM_REGISTRY_CHANNEL_ERROR;
  }
}

static int stream_key_matches(const mesh_stream_registry_slot_v1_t *slot,
                              const mesh_stream_registry_open_v1_t *request) {
  return slot->channel.admission.generation == request->admission.generation &&
         slot->channel.admission.stream_epoch == request->admission.stream_epoch &&
         memcmp(slot->channel.admission.remote_peer_id, request->admission.remote_peer_id,
                sizeof(request->admission.remote_peer_id)) == 0 &&
         memcmp(slot->channel.admission.stream_id, request->admission.stream_id,
                sizeof(request->admission.stream_id)) == 0;
}

static size_t peer_channel_count(const mesh_stream_registry_v1_t *registry,
                                 const uint8_t remote_peer_id[MESH_STREAM_CHANNEL_PEER_ID_SIZE]) {
  size_t count = 0u;
  size_t index = 0u;

  for (index = 0u; index < registry->config.capacity; index++) {
    const mesh_stream_registry_slot_v1_t *slot = &registry->slots[index];
    if (slot->occupied && memcmp(slot->channel.admission.remote_peer_id, remote_peer_id,
                                 MESH_STREAM_CHANNEL_PEER_ID_SIZE) == 0) {
      count++;
    }
  }
  return count;
}

mesh_stream_registry_result_t
mesh_stream_registry_init_v1(mesh_stream_registry_v1_t *registry,
                             const mesh_stream_registry_config_v1_t *config) {
  mesh_stream_registry_slot_v1_t *slots = NULL;

  if (!registry || !config)
    return MESH_STREAM_REGISTRY_INVALID_ARG;
  if (registry->slots)
    return MESH_STREAM_REGISTRY_INVALID_STATE;
  if (config->capacity == 0u || config->capacity > MESH_STREAM_REGISTRY_CAPACITY_MAX ||
      config->max_channels_per_peer == 0u || config->max_channels_per_peer > config->capacity ||
      config->owner_generation == 0u) {
    return MESH_STREAM_REGISTRY_INVALID_ARG;
  }
  slots = (mesh_stream_registry_slot_v1_t *)calloc(config->capacity, sizeof(*slots));
  if (!slots)
    return MESH_STREAM_REGISTRY_CAPACITY_EXHAUSTED;
  memset(registry, 0, sizeof(*registry));
  registry->config = *config;
  registry->slots = slots;
  return MESH_STREAM_REGISTRY_OK;
}

void mesh_stream_registry_destroy_v1(mesh_stream_registry_v1_t *registry) {
  size_t index = 0u;

  if (!registry)
    return;
  if (registry->slots) {
    for (index = 0u; index < registry->config.capacity; index++) {
      if (registry->slots[index].occupied)
        mesh_stream_channel_destroy_v1(&registry->slots[index].channel);
    }
  }
  free(registry->slots);
  memset(registry, 0, sizeof(*registry));
}

mesh_stream_registry_result_t
mesh_stream_registry_open_v1(mesh_stream_registry_v1_t *registry,
                             const mesh_stream_registry_open_v1_t *request,
                             mesh_stream_channel_handle_v1_t *out_handle) {
  mesh_stream_registry_slot_v1_t *available = NULL;
  size_t available_index = 0u;
  size_t index = 0u;
  mesh_stream_channel_result_t channel_result;

  if (!registry || !request || !out_handle)
    return MESH_STREAM_REGISTRY_INVALID_ARG;
  memset(out_handle, 0, sizeof(*out_handle));
  if (!registry->slots)
    return MESH_STREAM_REGISTRY_INVALID_STATE;
  if (bytes_are_zero(request->admission.remote_peer_id,
                     sizeof(request->admission.remote_peer_id))) {
    return MESH_STREAM_REGISTRY_INVALID_ARG;
  }
  for (index = 0u; index < registry->config.capacity; index++) {
    mesh_stream_registry_slot_v1_t *slot = &registry->slots[index];
    if (!slot->occupied) {
      if (!available && slot->generation != UINT64_MAX) {
        available = slot;
        available_index = index;
      }
      continue;
    }
    if (stream_key_matches(slot, request))
      return MESH_STREAM_REGISTRY_DUPLICATE;
  }
  if (peer_channel_count(registry, request->admission.remote_peer_id) >=
      registry->config.max_channels_per_peer) {
    return MESH_STREAM_REGISTRY_PEER_LIMIT;
  }
  if (!available)
    return MESH_STREAM_REGISTRY_CAPACITY_EXHAUSTED;

  channel_result =
      mesh_stream_channel_init_v1(&available->channel, &request->admission, &request->transport,
                                  &request->io, request->on_event, request->event_context);
  if (channel_result != MESH_STREAM_CHANNEL_OK)
    return map_channel_result(channel_result);
  available->generation++;
  available->occupied = 1u;
  registry->occupied_channels++;
  if (registry->occupied_channels > registry->peak_occupied_channels)
    registry->peak_occupied_channels = registry->occupied_channels;
  *out_handle = slot_handle(registry, available_index, available);
  out_handle->registry_generation = registry->config.owner_generation;
  return MESH_STREAM_REGISTRY_OK;
}

mesh_stream_registry_result_t mesh_stream_registry_feed_v1(mesh_stream_registry_v1_t *registry,
                                                           mesh_stream_channel_handle_v1_t handle,
                                                           const uint8_t *bytes, size_t len,
                                                           size_t *out_frames) {
  mesh_stream_registry_slot_v1_t *slot = NULL;
  mesh_stream_registry_result_t validation_result = validate_handle(registry, handle, &slot);

  if (validation_result != MESH_STREAM_REGISTRY_OK)
    return validation_result;
  return map_channel_result(mesh_stream_channel_feed_v1(
      &slot->channel, slot->channel.admission.generation, bytes, len, out_frames));
}

mesh_stream_registry_result_t
mesh_stream_registry_pump_once_v1(mesh_stream_registry_v1_t *registry,
                                  mesh_stream_channel_handle_v1_t handle, size_t *out_frames) {
  mesh_stream_registry_slot_v1_t *slot = NULL;
  mesh_stream_registry_result_t validation_result = validate_handle(registry, handle, &slot);

  if (validation_result != MESH_STREAM_REGISTRY_OK)
    return validation_result;
  return map_channel_result(mesh_stream_channel_pump_once_v1(
      &slot->channel, slot->channel.admission.generation, out_frames));
}

mesh_stream_registry_result_t
mesh_stream_registry_close_v1(mesh_stream_registry_v1_t *registry,
                              mesh_stream_channel_handle_v1_t handle) {
  mesh_stream_registry_slot_v1_t *slot = NULL;
  mesh_stream_registry_result_t validation_result = validate_handle(registry, handle, &slot);

  if (validation_result != MESH_STREAM_REGISTRY_OK)
    return validation_result;
  return map_channel_result(
      mesh_stream_channel_close_v1(&slot->channel, slot->channel.admission.generation));
}

mesh_stream_registry_result_t
mesh_stream_registry_revoke_peer_v1(mesh_stream_registry_v1_t *registry,
                                    const uint8_t remote_peer_id[MESH_STREAM_CHANNEL_PEER_ID_SIZE],
                                    uint64_t admission_generation, size_t *out_revoked) {
  size_t index = 0u;

  if (!registry || !remote_peer_id || !out_revoked || admission_generation == 0u ||
      bytes_are_zero(remote_peer_id, MESH_STREAM_CHANNEL_PEER_ID_SIZE)) {
    return MESH_STREAM_REGISTRY_INVALID_ARG;
  }
  *out_revoked = 0u;
  if (!registry->slots)
    return MESH_STREAM_REGISTRY_INVALID_STATE;
  for (index = 0u; index < registry->config.capacity; index++) {
    mesh_stream_registry_slot_v1_t *slot = &registry->slots[index];
    mesh_stream_channel_result_t channel_result;

    if (!slot->occupied || slot->channel.admission.generation != admission_generation ||
        memcmp(slot->channel.admission.remote_peer_id, remote_peer_id,
               MESH_STREAM_CHANNEL_PEER_ID_SIZE) != 0) {
      continue;
    }
    if (slot->channel.state != MESH_STREAM_CHANNEL_READY)
      continue;
    channel_result = mesh_stream_channel_revoke_v1(&slot->channel, admission_generation);
    if (channel_result != MESH_STREAM_CHANNEL_OK)
      return map_channel_result(channel_result);
    (*out_revoked)++;
  }
  return MESH_STREAM_REGISTRY_OK;
}

mesh_stream_registry_result_t
mesh_stream_registry_release_v1(mesh_stream_registry_v1_t *registry,
                                mesh_stream_channel_handle_v1_t handle) {
  mesh_stream_registry_slot_v1_t *slot = NULL;
  mesh_stream_registry_result_t validation_result = validate_handle(registry, handle, &slot);

  if (validation_result != MESH_STREAM_REGISTRY_OK)
    return validation_result;
  if (slot->channel.state == MESH_STREAM_CHANNEL_READY)
    return MESH_STREAM_REGISTRY_INVALID_STATE;
  mesh_stream_channel_destroy_v1(&slot->channel);
  slot->occupied = 0u;
  registry->occupied_channels--;
  return MESH_STREAM_REGISTRY_OK;
}

mesh_stream_registry_result_t
mesh_stream_registry_query_channel_v1(const mesh_stream_registry_v1_t *registry,
                                      mesh_stream_channel_handle_v1_t handle,
                                      mesh_stream_registry_channel_info_v1_t *out_info) {
  mesh_stream_registry_slot_v1_t *slot = NULL;
  mesh_stream_registry_result_t validation_result;

  if (!out_info)
    return MESH_STREAM_REGISTRY_INVALID_ARG;
  memset(out_info, 0, sizeof(*out_info));
  validation_result = validate_handle(registry, handle, &slot);
  if (validation_result != MESH_STREAM_REGISTRY_OK)
    return validation_result;
  out_info->admission = slot->channel.admission;
  out_info->state = slot->channel.state;
  out_info->last_transport_result = slot->channel.last_transport_result;
  out_info->last_session_result = slot->channel.last_session_result;
  out_info->last_io_result = slot->channel.last_io_result;
  out_info->last_application_result = slot->channel.last_application_result;
  out_info->received_bytes = slot->channel.received_bytes;
  out_info->received_frames = slot->channel.received_frames;
  out_info->sent_control_frames = slot->channel.sent_control_frames;
  return MESH_STREAM_REGISTRY_OK;
}

mesh_stream_registry_result_t
mesh_stream_registry_query_stats_v1(const mesh_stream_registry_v1_t *registry,
                                    mesh_stream_registry_stats_v1_t *out_stats) {
  size_t index = 0u;

  if (!registry || !out_stats)
    return MESH_STREAM_REGISTRY_INVALID_ARG;
  memset(out_stats, 0, sizeof(*out_stats));
  if (!registry->slots)
    return MESH_STREAM_REGISTRY_INVALID_STATE;
  out_stats->capacity = registry->config.capacity;
  out_stats->max_channels_per_peer = registry->config.max_channels_per_peer;
  out_stats->owner_generation = registry->config.owner_generation;
  out_stats->occupied_channels = registry->occupied_channels;
  out_stats->peak_occupied_channels = registry->peak_occupied_channels;
  for (index = 0u; index < registry->config.capacity; index++) {
    if (!registry->slots[index].occupied)
      continue;
    if (registry->slots[index].channel.state == MESH_STREAM_CHANNEL_READY)
      out_stats->ready_channels++;
    else
      out_stats->terminal_channels++;
  }
  return MESH_STREAM_REGISTRY_OK;
}
