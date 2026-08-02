#ifndef MESH_MGMT_EXECUTION_EGRESS_H
#define MESH_MGMT_EXECUTION_EGRESS_H

#include "mesh_mgmt_execution_worker.h"
#include "ring_buffer_spsc.h"

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_MGMT_EXECUTION_EGRESS_MAX_CAPACITY 1024u
#define MESH_MGMT_EXECUTION_EGRESS_SLOT_SIZE 4096u
#define MESH_MGMT_EXECUTION_EGRESS_STORAGE_FACTOR 2u

typedef enum mesh_mgmt_execution_egress_result {
  MESH_MGMT_EXECUTION_EGRESS_OK = 0,
  MESH_MGMT_EXECUTION_EGRESS_INVALID_ARG = -1,
  MESH_MGMT_EXECUTION_EGRESS_CLOSED = -2,
  MESH_MGMT_EXECUTION_EGRESS_FULL = -3,
  MESH_MGMT_EXECUTION_EGRESS_EMPTY = -4,
  MESH_MGMT_EXECUTION_EGRESS_RESOURCE_EXHAUSTED = -5
} mesh_mgmt_execution_egress_result_t;

typedef struct mesh_mgmt_execution_egress_item_v1 {
  uint8_t target_node_id[32];
  uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE];
  uint8_t correlation_id[MESH_MGMT_EXECUTION_ID_SIZE];
  uint8_t request_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint8_t executor_node_id[32];
  mesh_mgmt_execution_service_result_t service_result;
  size_t result_payload_size;
  uint8_t result_payload[MESH_MGMT_EXECUTION_COMMAND_RESULT_SIZE_V1];
  mesh_mgmt_execution_result_v1_t result;
} mesh_mgmt_execution_egress_item_v1_t;

typedef struct mesh_mgmt_execution_egress_stats_v1 {
  size_t capacity;
  size_t pending;
  uint8_t accepting;
  uint64_t published;
  uint64_t consumed;
  uint64_t rejected_full;
  uint64_t rejected_closed;
} mesh_mgmt_execution_egress_stats_v1_t;

typedef struct mesh_mgmt_execution_egress_v1 {
  ring_spsc_t ring;
  uint8_t *storage;
  size_t capacity;
  atomic_bool accepting;
  atomic_uint_fast64_t published;
  atomic_uint_fast64_t consumed;
  atomic_uint_fast64_t rejected_full;
  atomic_uint_fast64_t rejected_closed;
  atomic_size_t pending;
  uint8_t initialized;
} mesh_mgmt_execution_egress_v1_t;

mesh_mgmt_execution_egress_result_t mesh_mgmt_execution_egress_init_v1(
    mesh_mgmt_execution_egress_v1_t *egress, size_t capacity);

/*
 * Single-producer API. Copies all data into one fixed slot. A successful
 * service result requires the complete signed result payload.
 */
mesh_mgmt_execution_egress_result_t mesh_mgmt_execution_egress_try_push_v1(
    mesh_mgmt_execution_egress_v1_t *egress,
    const mesh_mgmt_execution_shadow_command_v1_t *command,
    mesh_mgmt_execution_service_result_t service_result,
    const uint8_t *result_payload,
    size_t result_payload_size,
    const mesh_mgmt_execution_result_v1_t *result);

/*
 * Adapter for mesh_mgmt_execution_worker_config_v1_t::completion. A full
 * outbox is observable in stats; terminal success remains replayable from the
 * durable execution store by resubmitting the same command.
 */
void mesh_mgmt_execution_egress_completion_v1(
    void *context,
    const mesh_mgmt_execution_shadow_command_v1_t *command,
    mesh_mgmt_execution_service_result_t service_result,
    const uint8_t *result_payload,
    size_t result_payload_size,
    const mesh_mgmt_execution_result_v1_t *result);

/* Single-consumer API. Peek copies without releasing the queue head. */
mesh_mgmt_execution_egress_result_t mesh_mgmt_execution_egress_peek_v1(
    mesh_mgmt_execution_egress_v1_t *egress,
    mesh_mgmt_execution_egress_item_v1_t *out_item);

/* Release exactly one previously observed head after its external side effect. */
mesh_mgmt_execution_egress_result_t mesh_mgmt_execution_egress_consume_v1(
    mesh_mgmt_execution_egress_v1_t *egress);

/* Convenience API for local consumers that do not need transactional send. */
mesh_mgmt_execution_egress_result_t mesh_mgmt_execution_egress_try_pop_v1(
    mesh_mgmt_execution_egress_v1_t *egress,
    mesh_mgmt_execution_egress_item_v1_t *out_item);

/* Stops new pushes without discarding items already published. */
mesh_mgmt_execution_egress_result_t mesh_mgmt_execution_egress_close_v1(
    mesh_mgmt_execution_egress_v1_t *egress);

mesh_mgmt_execution_egress_result_t mesh_mgmt_execution_egress_get_stats_v1(
    const mesh_mgmt_execution_egress_v1_t *egress,
    mesh_mgmt_execution_egress_stats_v1_t *out_stats);

/*
 * Producer and consumer must be quiescent. Call close and drain before destroy
 * when queued results must be delivered.
 */
void mesh_mgmt_execution_egress_destroy_v1(
    mesh_mgmt_execution_egress_v1_t *egress);

#ifdef __cplusplus
}
#endif

#endif
