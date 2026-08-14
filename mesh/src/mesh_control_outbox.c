#include "mesh_control_outbox.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
  mesh_control_envelope_v1_t envelope;
  uint8_t *payload;
} mesh_control_outbox_entry_v1_t;

static int config_valid(const mesh_control_outbox_config_v1_t *config) {
  return config && config->entry_capacity != 0u &&
         config->entry_capacity <= MESH_CONTROL_OUTBOX_MAX_ENTRIES_V1 &&
         config->retained_byte_capacity != 0u &&
         config->retained_byte_capacity <=
             MESH_CONTROL_OUTBOX_MAX_RETAINED_BYTES_V1 &&
         config->max_payload_size != 0u &&
         config->max_payload_size <= MESH_CONTROL_MAX_FRAME_SIZE_V1 &&
         config->max_payload_size <= config->retained_byte_capacity;
}

mesh_control_result_t mesh_control_outbox_init_v1(
    mesh_control_outbox_v1_t *outbox,
    const mesh_control_outbox_config_v1_t *config) {
  if (!outbox || outbox->initialized || !config_valid(config))
    return MESH_CONTROL_INVALID_ARG;
  memset(outbox, 0, sizeof(*outbox));
  if (turbo_deque_init(&outbox->entries,
                       sizeof(mesh_control_outbox_entry_v1_t)) != 0) {
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  }
  if (turbo_deque_reserve(&outbox->entries, config->entry_capacity) != 0) {
    turbo_deque_destroy(&outbox->entries);
    memset(outbox, 0, sizeof(*outbox));
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  }
  outbox->config = *config;
  outbox->accepting = 1u;
  outbox->initialized = 1u;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_outbox_try_push_v1(
    mesh_control_outbox_v1_t *outbox,
    const mesh_control_envelope_v1_t *envelope,
    const uint8_t *payload, size_t payload_size) {
  mesh_control_outbox_entry_v1_t entry;

  if (!outbox || !outbox->initialized || !envelope ||
      mesh_control_envelope_validate_v1(envelope) != MESH_CONTROL_OK ||
      envelope->payload_size != payload_size ||
      (payload_size != 0u && !payload) ||
      payload_size > outbox->config.max_payload_size) {
    return MESH_CONTROL_INVALID_ARG;
  }
  if (!outbox->accepting) {
    ++outbox->rejected_closed;
    return MESH_CONTROL_CLOSED;
  }
  if (turbo_deque_size(&outbox->entries) >= outbox->config.entry_capacity ||
      payload_size > outbox->config.retained_byte_capacity -
                         outbox->retained_bytes) {
    ++outbox->rejected_full;
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  }

  memset(&entry, 0, sizeof(entry));
  entry.envelope = *envelope;
  if (payload_size != 0u) {
    entry.payload = (uint8_t *)malloc(payload_size);
    if (!entry.payload)
      return MESH_CONTROL_RESOURCE_EXHAUSTED;
    memcpy(entry.payload, payload, payload_size);
  }
  if (turbo_deque_push_back(&outbox->entries, &entry) != 0) {
    free(entry.payload);
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  }
  outbox->retained_bytes += payload_size;
  ++outbox->published;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_outbox_peek_v1(
    mesh_control_outbox_v1_t *outbox,
    mesh_control_outbox_view_v1_t *out_view) {
  const mesh_control_outbox_entry_v1_t *entry;

  if (!outbox || !outbox->initialized || !out_view)
    return MESH_CONTROL_INVALID_ARG;
  memset(out_view, 0, sizeof(*out_view));
  entry = (const mesh_control_outbox_entry_v1_t *)
      turbo_deque_front_const(&outbox->entries);
  if (!entry)
    return MESH_CONTROL_EMPTY;
  out_view->envelope = entry->envelope;
  out_view->payload = entry->payload;
  out_view->payload_size = entry->envelope.payload_size;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_outbox_consume_v1(
    mesh_control_outbox_v1_t *outbox) {
  mesh_control_outbox_entry_v1_t entry;

  if (!outbox || !outbox->initialized)
    return MESH_CONTROL_INVALID_ARG;
  memset(&entry, 0, sizeof(entry));
  if (turbo_deque_pop_front(&outbox->entries, &entry) != 0)
    return MESH_CONTROL_EMPTY;
  outbox->retained_bytes -= entry.envelope.payload_size;
  free(entry.payload);
  ++outbox->consumed;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_outbox_close_v1(
    mesh_control_outbox_v1_t *outbox) {
  if (!outbox || !outbox->initialized)
    return MESH_CONTROL_INVALID_ARG;
  outbox->accepting = 0u;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_outbox_get_stats_v1(
    const mesh_control_outbox_v1_t *outbox,
    mesh_control_outbox_stats_v1_t *out_stats) {
  if (!outbox || !outbox->initialized || !out_stats)
    return MESH_CONTROL_INVALID_ARG;
  memset(out_stats, 0, sizeof(*out_stats));
  out_stats->entry_capacity = outbox->config.entry_capacity;
  out_stats->retained_byte_capacity =
      outbox->config.retained_byte_capacity;
  out_stats->max_payload_size = outbox->config.max_payload_size;
  out_stats->pending = turbo_deque_size(&outbox->entries);
  out_stats->retained_bytes = outbox->retained_bytes;
  out_stats->accepting = outbox->accepting;
  out_stats->published = outbox->published;
  out_stats->consumed = outbox->consumed;
  out_stats->rejected_full = outbox->rejected_full;
  out_stats->rejected_closed = outbox->rejected_closed;
  return MESH_CONTROL_OK;
}

void mesh_control_outbox_destroy_v1(mesh_control_outbox_v1_t *outbox) {
  mesh_control_outbox_entry_v1_t entry;

  if (!outbox || !outbox->initialized)
    return;
  outbox->accepting = 0u;
  while (turbo_deque_pop_front(&outbox->entries, &entry) == 0)
    free(entry.payload);
  turbo_deque_destroy(&outbox->entries);
  memset(outbox, 0, sizeof(*outbox));
}
