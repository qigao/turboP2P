#include "mesh_mgmt_execution_egress.h"

#include <stdlib.h>
#include <string.h>

_Static_assert(sizeof(mesh_mgmt_execution_egress_item_v1_t) <=
                   MESH_MGMT_EXECUTION_EGRESS_SLOT_SIZE,
               "execution egress item exceeds fixed slot");

static int mesh_mgmt_execution_egress_capacity_valid(size_t capacity) {
  return capacity != 0u &&
         capacity <= MESH_MGMT_EXECUTION_EGRESS_MAX_CAPACITY &&
         (capacity & (capacity - 1u)) == 0u &&
         capacity <=
             SIZE_MAX / MESH_MGMT_EXECUTION_EGRESS_SLOT_SIZE /
                 MESH_MGMT_EXECUTION_EGRESS_STORAGE_FACTOR;
}

mesh_mgmt_execution_egress_result_t mesh_mgmt_execution_egress_init_v1(
    mesh_mgmt_execution_egress_v1_t *egress, size_t capacity) {
  size_t storage_size;

  if (egress == NULL ||
      !mesh_mgmt_execution_egress_capacity_valid(capacity)) {
    return MESH_MGMT_EXECUTION_EGRESS_INVALID_ARG;
  }
  memset(egress, 0, sizeof(*egress));
  storage_size = capacity * MESH_MGMT_EXECUTION_EGRESS_SLOT_SIZE *
                 MESH_MGMT_EXECUTION_EGRESS_STORAGE_FACTOR;
  egress->storage = (uint8_t *)calloc(1u, storage_size);
  if (egress->storage == NULL) {
    return MESH_MGMT_EXECUTION_EGRESS_RESOURCE_EXHAUSTED;
  }
  if (!ring_spsc_init(&egress->ring, egress->storage, storage_size)) {
    free(egress->storage);
    memset(egress, 0, sizeof(*egress));
    return MESH_MGMT_EXECUTION_EGRESS_INVALID_ARG;
  }
  egress->capacity = capacity;
  atomic_init(&egress->accepting, true);
  atomic_init(&egress->published, 0u);
  atomic_init(&egress->consumed, 0u);
  atomic_init(&egress->rejected_full, 0u);
  atomic_init(&egress->rejected_closed, 0u);
  atomic_init(&egress->pending, 0u);
  egress->initialized = 1u;
  return MESH_MGMT_EXECUTION_EGRESS_OK;
}

mesh_mgmt_execution_egress_result_t mesh_mgmt_execution_egress_try_push_v1(
    mesh_mgmt_execution_egress_v1_t *egress,
    const mesh_mgmt_execution_shadow_command_v1_t *command,
    mesh_mgmt_execution_service_result_t service_result,
    const uint8_t *result_payload,
    size_t result_payload_size,
    const mesh_mgmt_execution_result_v1_t *result) {
  mesh_mgmt_execution_egress_item_v1_t item;
  uint8_t *slot;

  if (egress == NULL || command == NULL || result == NULL ||
      egress->initialized == 0u || egress->storage == NULL ||
      result_payload_size > MESH_MGMT_EXECUTION_COMMAND_RESULT_SIZE_V1 ||
      (result_payload_size != 0u && result_payload == NULL) ||
      (service_result == MESH_MGMT_EXECUTION_SERVICE_OK &&
       result_payload_size != MESH_MGMT_EXECUTION_COMMAND_RESULT_SIZE_V1)) {
    return MESH_MGMT_EXECUTION_EGRESS_INVALID_ARG;
  }
  if (!atomic_load_explicit(&egress->accepting, memory_order_acquire)) {
    atomic_fetch_add_explicit(&egress->rejected_closed, 1u,
                              memory_order_relaxed);
    return MESH_MGMT_EXECUTION_EGRESS_CLOSED;
  }
  if (atomic_load_explicit(&egress->pending, memory_order_acquire) >=
      egress->capacity) {
    atomic_fetch_add_explicit(&egress->rejected_full, 1u,
                              memory_order_relaxed);
    return MESH_MGMT_EXECUTION_EGRESS_FULL;
  }

  slot = ring_spsc_write_acquire(
      &egress->ring, MESH_MGMT_EXECUTION_EGRESS_SLOT_SIZE);
  if (slot == NULL) {
    atomic_fetch_add_explicit(&egress->rejected_full, 1u,
                              memory_order_relaxed);
    return MESH_MGMT_EXECUTION_EGRESS_FULL;
  }

  memset(&item, 0, sizeof(item));
  memcpy(item.target_node_id, command->reply_node_id,
         sizeof(item.target_node_id));
  memcpy(item.command_id, command->request.command_id,
         sizeof(item.command_id));
  memcpy(item.correlation_id, command->request.correlation_id,
         sizeof(item.correlation_id));
  memcpy(item.request_digest, command->request_digest,
         sizeof(item.request_digest));
  memcpy(item.executor_node_id, command->grant.target_node_id,
         sizeof(item.executor_node_id));
  item.service_result = service_result;
  item.result_payload_size = result_payload_size;
  if (result_payload_size != 0u) {
    memcpy(item.result_payload, result_payload, result_payload_size);
  }
  item.result = *result;
  memset(slot, 0, MESH_MGMT_EXECUTION_EGRESS_SLOT_SIZE);
  memcpy(slot, &item, sizeof(item));
  atomic_fetch_add_explicit(&egress->pending, 1u, memory_order_release);
  ring_spsc_write_release(&egress->ring,
                          MESH_MGMT_EXECUTION_EGRESS_SLOT_SIZE);
  atomic_fetch_add_explicit(&egress->published, 1u, memory_order_relaxed);
  return MESH_MGMT_EXECUTION_EGRESS_OK;
}

void mesh_mgmt_execution_egress_completion_v1(
    void *context,
    const mesh_mgmt_execution_shadow_command_v1_t *command,
    mesh_mgmt_execution_service_result_t service_result,
    const uint8_t *result_payload,
    size_t result_payload_size,
    const mesh_mgmt_execution_result_v1_t *result) {
  (void)mesh_mgmt_execution_egress_try_push_v1(
      (mesh_mgmt_execution_egress_v1_t *)context, command, service_result,
      result_payload, result_payload_size, result);
}

mesh_mgmt_execution_egress_result_t mesh_mgmt_execution_egress_try_pop_v1(
    mesh_mgmt_execution_egress_v1_t *egress,
    mesh_mgmt_execution_egress_item_v1_t *out_item) {
  mesh_mgmt_execution_egress_result_t result;

  result = mesh_mgmt_execution_egress_peek_v1(egress, out_item);
  if (result != MESH_MGMT_EXECUTION_EGRESS_OK)
    return result;
  return mesh_mgmt_execution_egress_consume_v1(egress);
}

mesh_mgmt_execution_egress_result_t mesh_mgmt_execution_egress_peek_v1(
    mesh_mgmt_execution_egress_v1_t *egress,
    mesh_mgmt_execution_egress_item_v1_t *out_item) {
  uint8_t *slot;
  size_t available = 0u;

  if (egress == NULL || out_item == NULL || egress->initialized == 0u ||
      egress->storage == NULL) {
    return MESH_MGMT_EXECUTION_EGRESS_INVALID_ARG;
  }
  slot = ring_spsc_read_acquire(&egress->ring, &available);
  if (slot == NULL || available < MESH_MGMT_EXECUTION_EGRESS_SLOT_SIZE) {
    return MESH_MGMT_EXECUTION_EGRESS_EMPTY;
  }
  memcpy(out_item, slot, sizeof(*out_item));
  return MESH_MGMT_EXECUTION_EGRESS_OK;
}

mesh_mgmt_execution_egress_result_t mesh_mgmt_execution_egress_consume_v1(
    mesh_mgmt_execution_egress_v1_t *egress) {
  uint8_t *slot;
  size_t available = 0u;

  if (egress == NULL || egress->initialized == 0u ||
      egress->storage == NULL) {
    return MESH_MGMT_EXECUTION_EGRESS_INVALID_ARG;
  }
  slot = ring_spsc_read_acquire(&egress->ring, &available);
  if (slot == NULL || available < MESH_MGMT_EXECUTION_EGRESS_SLOT_SIZE) {
    return MESH_MGMT_EXECUTION_EGRESS_EMPTY;
  }
  ring_spsc_read_release(&egress->ring,
                         MESH_MGMT_EXECUTION_EGRESS_SLOT_SIZE);
  atomic_fetch_sub_explicit(&egress->pending, 1u, memory_order_release);
  atomic_fetch_add_explicit(&egress->consumed, 1u, memory_order_relaxed);
  return MESH_MGMT_EXECUTION_EGRESS_OK;
}

mesh_mgmt_execution_egress_result_t mesh_mgmt_execution_egress_close_v1(
    mesh_mgmt_execution_egress_v1_t *egress) {
  if (egress == NULL || egress->initialized == 0u ||
      egress->storage == NULL) {
    return MESH_MGMT_EXECUTION_EGRESS_INVALID_ARG;
  }
  atomic_store_explicit(&egress->accepting, false, memory_order_release);
  return MESH_MGMT_EXECUTION_EGRESS_OK;
}

mesh_mgmt_execution_egress_result_t mesh_mgmt_execution_egress_get_stats_v1(
    const mesh_mgmt_execution_egress_v1_t *egress,
    mesh_mgmt_execution_egress_stats_v1_t *out_stats) {
  if (egress == NULL || out_stats == NULL || egress->initialized == 0u ||
      egress->storage == NULL) {
    return MESH_MGMT_EXECUTION_EGRESS_INVALID_ARG;
  }
  memset(out_stats, 0, sizeof(*out_stats));
  out_stats->capacity = egress->capacity;
  out_stats->pending =
      atomic_load_explicit(&egress->pending, memory_order_acquire);
  out_stats->accepting =
      atomic_load_explicit(&egress->accepting, memory_order_acquire);
  out_stats->published =
      atomic_load_explicit(&egress->published, memory_order_relaxed);
  out_stats->consumed =
      atomic_load_explicit(&egress->consumed, memory_order_relaxed);
  out_stats->rejected_full =
      atomic_load_explicit(&egress->rejected_full, memory_order_relaxed);
  out_stats->rejected_closed =
      atomic_load_explicit(&egress->rejected_closed, memory_order_relaxed);
  return MESH_MGMT_EXECUTION_EGRESS_OK;
}

void mesh_mgmt_execution_egress_destroy_v1(
    mesh_mgmt_execution_egress_v1_t *egress) {
  if (egress == NULL)
    return;
  free(egress->storage);
  memset(egress, 0, sizeof(*egress));
}
