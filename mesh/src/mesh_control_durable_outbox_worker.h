#ifndef MESH_CONTROL_DURABLE_OUTBOX_WORKER_H
#define MESH_CONTROL_DURABLE_OUTBOX_WORKER_H

#include "mesh_control_durable_outbox.h"
#include "turbo_thread.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  MESH_CONTROL_DURABLE_OUTBOX_WORKER_OK = 0,
  MESH_CONTROL_DURABLE_OUTBOX_WORKER_INVALID_ARG = -1,
  MESH_CONTROL_DURABLE_OUTBOX_WORKER_INVALID_STATE = -2,
  MESH_CONTROL_DURABLE_OUTBOX_WORKER_FULL = -3,
  MESH_CONTROL_DURABLE_OUTBOX_WORKER_EMPTY = -4,
  MESH_CONTROL_DURABLE_OUTBOX_WORKER_RESOURCE_EXHAUSTED = -5,
  MESH_CONTROL_DURABLE_OUTBOX_WORKER_RECOVERY_FAILED = -6
} mesh_control_durable_outbox_worker_result_t;

typedef enum {
  MESH_CONTROL_DURABLE_OUTBOX_WORKER_SUBMIT = 1,
  MESH_CONTROL_DURABLE_OUTBOX_WORKER_ACTIVATE_SESSION = 2,
  MESH_CONTROL_DURABLE_OUTBOX_WORKER_DEACTIVATE_SESSION = 3,
  MESH_CONTROL_DURABLE_OUTBOX_WORKER_CLAIM = 4,
  MESH_CONTROL_DURABLE_OUTBOX_WORKER_ACK = 5,
  MESH_CONTROL_DURABLE_OUTBOX_WORKER_RELEASE = 6,
  MESH_CONTROL_DURABLE_OUTBOX_WORKER_COMPACT = 7
} mesh_control_durable_outbox_worker_operation_v1_t;

typedef struct {
  uint64_t request_token;
  mesh_control_durable_outbox_worker_operation_v1_t operation;
  mesh_control_durable_outbox_result_t store_result;
  mesh_control_durable_outbox_view_v1_t view;
  uint64_t session_generation;
  size_t affected;
} mesh_control_durable_outbox_worker_completion_v1_t;

typedef struct {
  mesh_control_durable_outbox_stats_v1_t outbox;
  uint64_t submitted;
  uint64_t completed;
  uint64_t rejected_full;
  uint64_t persistence_failures;
  uint8_t accepting;
  uint8_t busy;
  uint8_t completion_ready;
} mesh_control_durable_outbox_worker_stats_v1_t;

/**
 * One-owner, one-in-flight persistence executor. Network callbacks only copy
 * into its fixed slot and never perform file I/O. Completion payload remains
 * bounded by MESH_CONTROL_MAX_FRAME_SIZE_V1 and is copied into caller storage
 * by try_take.
 */
typedef struct {
  mesh_control_durable_outbox_v1_t outbox;
  turbo_threadpool_t *pool;
  turbo_mutex_t mutex;
  mesh_control_durable_outbox_worker_operation_v1_t operation;
  uint64_t request_token;
  mesh_control_durable_outbox_message_v1_t message;
  uint8_t target_node_id[MESH_CONTROL_NODE_ID_SIZE];
  uint8_t message_id[MESH_CONTROL_ID_SIZE];
  uint8_t session_id[MESH_CONTROL_ID_SIZE];
  uint64_t session_generation;
  uint64_t lease_generation;
  uint64_t time_ms;
  uint64_t lease_ms;
  uint8_t request_payload[MESH_CONTROL_MAX_FRAME_SIZE_V1];
  mesh_control_durable_outbox_worker_completion_v1_t completion;
  uint8_t completion_payload[MESH_CONTROL_MAX_FRAME_SIZE_V1];
  size_t completion_payload_size;
  mesh_control_durable_outbox_stats_v1_t cached_stats;
  uint64_t submitted;
  uint64_t completed;
  uint64_t rejected_full;
  uint64_t persistence_failures;
  uint8_t mutex_initialized;
  uint8_t initialized;
  uint8_t accepting;
  uint8_t busy;
  uint8_t completion_ready;
} mesh_control_durable_outbox_worker_v1_t;

mesh_control_durable_outbox_worker_result_t
mesh_control_durable_outbox_worker_init_v1(
    mesh_control_durable_outbox_worker_v1_t *worker,
    const mesh_control_durable_outbox_config_v1_t *config,
    size_t *out_recovered_claims);

mesh_control_durable_outbox_worker_result_t
mesh_control_durable_outbox_worker_try_submit_message_v1(
    mesh_control_durable_outbox_worker_v1_t *worker, uint64_t request_token,
    const mesh_control_durable_outbox_message_v1_t *message);

mesh_control_durable_outbox_worker_result_t
mesh_control_durable_outbox_worker_try_activate_session_v1(
    mesh_control_durable_outbox_worker_v1_t *worker, uint64_t request_token,
    const uint8_t target_node_id[MESH_CONTROL_NODE_ID_SIZE],
    const uint8_t session_id[MESH_CONTROL_ID_SIZE], uint64_t connected_at_ms);

mesh_control_durable_outbox_worker_result_t
mesh_control_durable_outbox_worker_try_deactivate_session_v1(
    mesh_control_durable_outbox_worker_v1_t *worker, uint64_t request_token,
    const uint8_t target_node_id[MESH_CONTROL_NODE_ID_SIZE],
    const uint8_t session_id[MESH_CONTROL_ID_SIZE], uint64_t session_generation);

mesh_control_durable_outbox_worker_result_t
mesh_control_durable_outbox_worker_try_claim_v1(
    mesh_control_durable_outbox_worker_v1_t *worker, uint64_t request_token,
    const uint8_t target_node_id[MESH_CONTROL_NODE_ID_SIZE],
    const uint8_t session_id[MESH_CONTROL_ID_SIZE], uint64_t session_generation,
    uint64_t now_ms, uint64_t lease_ms);

mesh_control_durable_outbox_worker_result_t
mesh_control_durable_outbox_worker_try_ack_v1(
    mesh_control_durable_outbox_worker_v1_t *worker, uint64_t request_token,
    const uint8_t target_node_id[MESH_CONTROL_NODE_ID_SIZE],
    const uint8_t message_id[MESH_CONTROL_ID_SIZE],
    const uint8_t session_id[MESH_CONTROL_ID_SIZE], uint64_t session_generation,
    uint64_t lease_generation, uint64_t acked_at_ms);

mesh_control_durable_outbox_worker_result_t
mesh_control_durable_outbox_worker_try_release_v1(
    mesh_control_durable_outbox_worker_v1_t *worker, uint64_t request_token,
    const uint8_t target_node_id[MESH_CONTROL_NODE_ID_SIZE],
    const uint8_t message_id[MESH_CONTROL_ID_SIZE],
    const uint8_t session_id[MESH_CONTROL_ID_SIZE], uint64_t session_generation,
    uint64_t lease_generation);

mesh_control_durable_outbox_worker_result_t
mesh_control_durable_outbox_worker_try_compact_v1(
    mesh_control_durable_outbox_worker_v1_t *worker, uint64_t request_token,
    uint64_t now_ms);

/**
 * Takes one completion. If payload_capacity is too small, the completion is
 * retained and RESOURCE_EXHAUSTED is returned with the required size.
 */
mesh_control_durable_outbox_worker_result_t
mesh_control_durable_outbox_worker_try_take_v1(
    mesh_control_durable_outbox_worker_v1_t *worker,
    mesh_control_durable_outbox_worker_completion_v1_t *out_completion,
    uint8_t *payload, size_t payload_capacity, size_t *out_payload_size);

mesh_control_durable_outbox_worker_result_t
mesh_control_durable_outbox_worker_shutdown_v1(
    mesh_control_durable_outbox_worker_v1_t *worker);

mesh_control_durable_outbox_worker_result_t
mesh_control_durable_outbox_worker_get_stats_v1(
    mesh_control_durable_outbox_worker_v1_t *worker,
    mesh_control_durable_outbox_worker_stats_v1_t *out_stats);

void mesh_control_durable_outbox_worker_destroy_v1(
    mesh_control_durable_outbox_worker_v1_t *worker);

#ifdef __cplusplus
}
#endif

#endif
