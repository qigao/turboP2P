#ifndef MESH_CONTROL_WAL_WORKER_H
#define MESH_CONTROL_WAL_WORKER_H

#include "mesh_control_checkpoint_store.h"
#include "mesh_control_wal.h"
#include "turbo_thread.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  MESH_CONTROL_WAL_WORKER_OK = 0,
  MESH_CONTROL_WAL_WORKER_INVALID_ARG = -1,
  MESH_CONTROL_WAL_WORKER_INVALID_STATE = -2,
  MESH_CONTROL_WAL_WORKER_FULL = -3,
  MESH_CONTROL_WAL_WORKER_EMPTY = -4,
  MESH_CONTROL_WAL_WORKER_RESOURCE_EXHAUSTED = -5,
  MESH_CONTROL_WAL_WORKER_RECOVERY_FAILED = -6
} mesh_control_wal_worker_result_t;

#define MESH_CONTROL_WAL_WORKER_CHECKPOINT_RECORD_V1 0x8001u

typedef struct {
  mesh_control_wal_config_v1_t wal;
  /** Optional durable checkpoint path. Must be paired with checkpoint_owner. */
  const char *checkpoint_path;
  mesh_control_owner_v1_t *checkpoint_owner;
  uint64_t recovery_now_ms;
  uint64_t recovery_after_index;
  mesh_control_wal_replay_fn recovery;
  void *recovery_context;
} mesh_control_wal_worker_config_v1_t;

typedef struct {
  uint64_t expected_index;
  uint64_t log_index;
  uint64_t accepted_at_ms;
  uint16_t record_type;
  uint16_t reserved;
  mesh_control_wal_result_t wal_result;
  mesh_control_checkpoint_store_result_t checkpoint_result;
} mesh_control_wal_worker_completion_v1_t;

typedef struct {
  mesh_control_wal_stats_v1_t wal;
  uint64_t submitted;
  uint64_t completed;
  uint64_t rejected_full;
  uint64_t persistence_failures;
  uint64_t checkpoints_completed;
  uint64_t checkpoint_failures;
  uint8_t accepting;
  uint8_t busy;
  uint8_t completion_ready;
} mesh_control_wal_worker_stats_v1_t;

/**
 * One-owner, one-in-flight persistence worker. The worker owns the WAL and a
 * fixed-size signed-frame slot. It never calls owner code from its thread.
 */
typedef struct {
  mesh_control_wal_v1_t wal;
  mesh_control_checkpoint_store_v1_t checkpoint_store;
  turbo_threadpool_t *pool;
  turbo_mutex_t mutex;
  uint64_t expected_index;
  uint64_t accepted_at_ms;
  uint16_t record_type;
  size_t signed_frame_size;
  uint8_t signed_frame[MESH_MGMT_FRAME_MAX];
  mesh_control_wal_operation_result_v1_t operation_result;
  uint8_t *checkpoint_bytes;
  size_t checkpoint_size;
  mesh_control_wal_worker_completion_v1_t completion;
  mesh_control_wal_stats_v1_t wal_stats;
  uint64_t submitted;
  uint64_t completed;
  uint64_t rejected_full;
  uint64_t persistence_failures;
  uint64_t checkpoints_completed;
  uint64_t checkpoint_failures;
  uint8_t mutex_initialized;
  uint8_t initialized;
  uint8_t checkpoint_store_initialized;
  uint8_t accepting;
  uint8_t busy;
  uint8_t completion_ready;
} mesh_control_wal_worker_v1_t;

/**
 * Opens and authenticates the WAL, replays records after the supplied durable
 * checkpoint index synchronously, then starts one persistence thread.
 */
mesh_control_wal_worker_result_t
mesh_control_wal_worker_init_v1(mesh_control_wal_worker_v1_t *worker,
                                const mesh_control_wal_worker_config_v1_t *config);

/** Copies the signed frame into the bounded worker-owned slot. */
mesh_control_wal_worker_result_t
mesh_control_wal_worker_try_submit_v1(mesh_control_wal_worker_v1_t *worker, uint64_t expected_index,
                                      uint64_t accepted_at_ms, const uint8_t *signed_frame,
                                      size_t signed_frame_size);

mesh_control_wal_worker_result_t mesh_control_wal_worker_try_submit_operation_result_v1(
    mesh_control_wal_worker_v1_t *worker, uint64_t expected_index, uint64_t recorded_at_ms,
    const mesh_control_wal_operation_result_v1_t *operation_result);

/**
 * Transfers one canonical checkpoint allocation to the worker. On success it
 * writes the checkpoint atomically and only then compacts the WAL at the exact
 * checkpoint index. Before ownership transfer, the worker verifies the V2
 * checkpoint structure, digest and embedded committed WAL index. On failure
 * ownership remains with the caller.
 */
mesh_control_wal_worker_result_t
mesh_control_wal_worker_try_submit_checkpoint_v1(mesh_control_wal_worker_v1_t *worker,
                                                 uint64_t checkpoint_index,
                                                 uint8_t *checkpoint_bytes, size_t checkpoint_size);

/** Returns one completion and releases the slot for the next mutation. */
mesh_control_wal_worker_result_t
mesh_control_wal_worker_try_take_v1(mesh_control_wal_worker_v1_t *worker,
                                    mesh_control_wal_worker_completion_v1_t *out_completion);

/** Stops submissions and drains an accepted append. */
mesh_control_wal_worker_result_t
mesh_control_wal_worker_shutdown_v1(mesh_control_wal_worker_v1_t *worker);

mesh_control_wal_worker_result_t
mesh_control_wal_worker_get_stats_v1(mesh_control_wal_worker_v1_t *worker,
                                     mesh_control_wal_worker_stats_v1_t *out_stats);

void mesh_control_wal_worker_destroy_v1(mesh_control_wal_worker_v1_t *worker);

#ifdef __cplusplus
}
#endif

#endif
