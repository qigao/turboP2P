#ifndef MESH_CONTROL_OUTBOX_H
#define MESH_CONTROL_OUTBOX_H

#include "mesh_control_primitives.h"
#include "turbo_deque.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  size_t entry_capacity;
  size_t retained_byte_capacity;
  size_t max_payload_size;
} mesh_control_outbox_config_v1_t;

typedef struct {
  mesh_control_envelope_v1_t envelope;
  const uint8_t *payload;
  size_t payload_size;
} mesh_control_outbox_view_v1_t;

typedef struct {
  size_t entry_capacity;
  size_t retained_byte_capacity;
  size_t max_payload_size;
  size_t pending;
  size_t retained_bytes;
  uint8_t accepting;
  uint64_t published;
  uint64_t consumed;
  uint64_t rejected_full;
  uint64_t rejected_closed;
} mesh_control_outbox_stats_v1_t;

/**
 * Single-owner FIFO. try_push copies the payload and owns it on success.
 * peek returns a borrowed view valid until consume, destroy, or any mutation
 * of this outbox. The type is intentionally not thread-safe.
 */
typedef struct {
  turbo_deque_t entries;
  mesh_control_outbox_config_v1_t config;
  size_t retained_bytes;
  uint64_t published;
  uint64_t consumed;
  uint64_t rejected_full;
  uint64_t rejected_closed;
  uint8_t accepting;
  uint8_t initialized;
} mesh_control_outbox_v1_t;

mesh_control_result_t mesh_control_outbox_init_v1(
    mesh_control_outbox_v1_t *outbox,
    const mesh_control_outbox_config_v1_t *config);

mesh_control_result_t mesh_control_outbox_try_push_v1(
    mesh_control_outbox_v1_t *outbox,
    const mesh_control_envelope_v1_t *envelope,
    const uint8_t *payload, size_t payload_size);

mesh_control_result_t mesh_control_outbox_peek_v1(
    mesh_control_outbox_v1_t *outbox,
    mesh_control_outbox_view_v1_t *out_view);

mesh_control_result_t mesh_control_outbox_consume_v1(
    mesh_control_outbox_v1_t *outbox);

mesh_control_result_t mesh_control_outbox_close_v1(
    mesh_control_outbox_v1_t *outbox);

mesh_control_result_t mesh_control_outbox_get_stats_v1(
    const mesh_control_outbox_v1_t *outbox,
    mesh_control_outbox_stats_v1_t *out_stats);

/** Caller must first stop the producer. Pending owned payloads are released. */
void mesh_control_outbox_destroy_v1(mesh_control_outbox_v1_t *outbox);

#ifdef __cplusplus
}
#endif

#endif
