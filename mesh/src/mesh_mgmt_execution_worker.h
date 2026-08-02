#ifndef MESH_MGMT_EXECUTION_WORKER_H
#define MESH_MGMT_EXECUTION_WORKER_H

#include "mesh_mgmt_execution_service.h"
#include "turbo_thread.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_MGMT_EXECUTION_WORKER_MAX_QUEUE_CAPACITY 4096u

typedef enum mesh_mgmt_execution_worker_result {
  MESH_MGMT_EXECUTION_WORKER_OK = 0,
  MESH_MGMT_EXECUTION_WORKER_INVALID_ARG = -1,
  MESH_MGMT_EXECUTION_WORKER_DISABLED = -2,
  MESH_MGMT_EXECUTION_WORKER_CLOSED = -3,
  MESH_MGMT_EXECUTION_WORKER_FULL = -4,
  MESH_MGMT_EXECUTION_WORKER_RESOURCE_EXHAUSTED = -5
} mesh_mgmt_execution_worker_result_t;

/*
 * All borrowed arguments are valid only for the callback duration. The
 * callback runs on the worker and must not call shutdown/destroy on it.
 */
typedef void (*mesh_mgmt_execution_worker_completion_v1_fn)(
    void *context,
    const mesh_mgmt_execution_shadow_command_v1_t *command,
    mesh_mgmt_execution_service_result_t service_result,
    const uint8_t *result_payload,
    size_t result_payload_size,
    const mesh_mgmt_execution_result_v1_t *result);

typedef struct mesh_mgmt_execution_worker_config_v1 {
  mesh_mgmt_execution_service_v1_t *service;
  size_t queue_capacity;
  const mesh_mgmt_execution_runner_io_v1_t *runner_io;
  mesh_mgmt_execution_worker_completion_v1_fn completion;
  void *completion_context;
} mesh_mgmt_execution_worker_config_v1_t;

typedef struct mesh_mgmt_execution_worker_stats_v1 {
  size_t queue_capacity;
  uint8_t accepting;
  uint64_t submitted;
  uint64_t started;
  uint64_t completed;
  uint64_t rejected;
  uint64_t queued;
} mesh_mgmt_execution_worker_stats_v1_t;

typedef struct mesh_mgmt_execution_worker_v1 {
  turbo_threadpool_t *pool;
  mesh_mgmt_execution_service_v1_t *service;
  mesh_mgmt_execution_runner_io_v1_t runner_io;
  mesh_mgmt_execution_worker_completion_v1_fn completion;
  void *completion_context;
  uint8_t has_runner_io;
  uint8_t initialized;
} mesh_mgmt_execution_worker_v1_t;

mesh_mgmt_execution_worker_result_t mesh_mgmt_execution_worker_init_v1(
    mesh_mgmt_execution_worker_v1_t *worker,
    const mesh_mgmt_execution_worker_config_v1_t *config);

/*
 * Copies command and authorization. Success transfers the copy to the worker;
 * failure retains nothing and permits the caller to retry elsewhere.
 */
mesh_mgmt_execution_worker_result_t mesh_mgmt_execution_worker_try_submit_v1(
    mesh_mgmt_execution_worker_v1_t *worker,
    const mesh_mgmt_execution_shadow_command_v1_t *command,
    const mesh_mgmt_execution_authorization_input_v1_t *authorization);

/*
 * Stops new submissions, drains accepted commands, and joins the worker.
 * Producers may race shutdown, but must be quiescent before destroy.
 */
mesh_mgmt_execution_worker_result_t mesh_mgmt_execution_worker_shutdown_v1(
    mesh_mgmt_execution_worker_v1_t *worker);

mesh_mgmt_execution_worker_result_t mesh_mgmt_execution_worker_get_stats_v1(
    mesh_mgmt_execution_worker_v1_t *worker,
    mesh_mgmt_execution_worker_stats_v1_t *out_stats);

void mesh_mgmt_execution_worker_destroy_v1(
    mesh_mgmt_execution_worker_v1_t *worker);

#ifdef __cplusplus
}
#endif

#endif
