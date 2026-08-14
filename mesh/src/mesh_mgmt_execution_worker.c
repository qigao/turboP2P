#include "mesh_mgmt_execution_worker.h"

#include <stdlib.h>
#include <string.h>

typedef struct mesh_mgmt_execution_worker_job_v1 {
  mesh_mgmt_execution_worker_v1_t *worker;
  mesh_mgmt_execution_shadow_command_v1_t command;
  mesh_mgmt_execution_authorization_input_v1_t authorization;
} mesh_mgmt_execution_worker_job_v1_t;

static void mesh_mgmt_execution_worker_run_job(void *argument) {
  mesh_mgmt_execution_worker_job_v1_t *job =
      (mesh_mgmt_execution_worker_job_v1_t *)argument;
  mesh_mgmt_execution_worker_v1_t *worker;
  mesh_mgmt_execution_result_v1_t result;
  uint8_t payload[MESH_MGMT_EXECUTION_COMMAND_RESULT_SIZE_V1];
  size_t payload_size = 0u;
  mesh_mgmt_execution_service_result_t service_result;

  if (job == NULL)
    return;
  worker = job->worker;
  memset(&result, 0, sizeof(result));
  memset(payload, 0, sizeof(payload));
  if (worker->execute) {
    service_result = worker->execute(
        worker->execute_context, worker->service, &job->command,
        &job->authorization,
        worker->has_runner_io != 0u ? &worker->runner_io : NULL, payload,
        sizeof(payload), &payload_size, &result);
  } else {
    service_result = mesh_mgmt_execution_service_execute_v1(
        worker->service, &job->command, &job->authorization,
        worker->has_runner_io != 0u ? &worker->runner_io : NULL, payload,
        sizeof(payload), &payload_size, &result);
  }
  if (service_result != MESH_MGMT_EXECUTION_SERVICE_OK)
    payload_size = 0u;
  worker->completion(worker->completion_context, &job->command, service_result,
                     payload, payload_size, &result);
  free(job);
}

mesh_mgmt_execution_worker_result_t mesh_mgmt_execution_worker_init_v1(
    mesh_mgmt_execution_worker_v1_t *worker,
    const mesh_mgmt_execution_worker_config_v1_t *config) {
  turbo_threadpool_config_t pool_config;

  if (worker == NULL || config == NULL || config->service == NULL ||
      config->completion == NULL || config->queue_capacity == 0u ||
      config->queue_capacity >
          MESH_MGMT_EXECUTION_WORKER_MAX_QUEUE_CAPACITY) {
    return MESH_MGMT_EXECUTION_WORKER_INVALID_ARG;
  }
  if (config->service->initialized == 0u) {
    return MESH_MGMT_EXECUTION_WORKER_INVALID_ARG;
  }
  if (config->service->enabled == 0u) {
    return MESH_MGMT_EXECUTION_WORKER_DISABLED;
  }

  memset(worker, 0, sizeof(*worker));
  memset(&pool_config, 0, sizeof(pool_config));
  pool_config.num_threads = 1;
  pool_config.queue_capacity = config->queue_capacity;
  worker->pool = turbo_threadpool_create_with_config(&pool_config);
  if (worker->pool == NULL) {
    return MESH_MGMT_EXECUTION_WORKER_RESOURCE_EXHAUSTED;
  }
  worker->service = config->service;
  worker->completion = config->completion;
  worker->completion_context = config->completion_context;
  worker->execute = config->execute;
  worker->execute_context = config->execute_context;
  if (config->runner_io != NULL) {
    worker->runner_io = *config->runner_io;
    worker->has_runner_io = 1u;
  }
  worker->initialized = 1u;
  return MESH_MGMT_EXECUTION_WORKER_OK;
}

mesh_mgmt_execution_worker_result_t mesh_mgmt_execution_worker_try_submit_v1(
    mesh_mgmt_execution_worker_v1_t *worker,
    const mesh_mgmt_execution_shadow_command_v1_t *command,
    const mesh_mgmt_execution_authorization_input_v1_t *authorization) {
  mesh_mgmt_execution_worker_job_v1_t *job;
  int accepting;

  if (worker == NULL || command == NULL || authorization == NULL ||
      worker->initialized == 0u || worker->pool == NULL) {
    return MESH_MGMT_EXECUTION_WORKER_INVALID_ARG;
  }
  if (turbo_threadpool_is_accepting(worker->pool) == 0) {
    return MESH_MGMT_EXECUTION_WORKER_CLOSED;
  }

  job = (mesh_mgmt_execution_worker_job_v1_t *)calloc(1u, sizeof(*job));
  if (job == NULL) {
    return MESH_MGMT_EXECUTION_WORKER_RESOURCE_EXHAUSTED;
  }
  job->worker = worker;
  job->command = *command;
  job->authorization = *authorization;
  if (turbo_threadpool_try_submit(
          worker->pool, mesh_mgmt_execution_worker_run_job, job) == 0) {
    return MESH_MGMT_EXECUTION_WORKER_OK;
  }

  accepting = turbo_threadpool_is_accepting(worker->pool);
  free(job);
  return accepting != 0 ? MESH_MGMT_EXECUTION_WORKER_FULL
                        : MESH_MGMT_EXECUTION_WORKER_CLOSED;
}

mesh_mgmt_execution_worker_result_t mesh_mgmt_execution_worker_shutdown_v1(
    mesh_mgmt_execution_worker_v1_t *worker) {
  if (worker == NULL || worker->initialized == 0u || worker->pool == NULL) {
    return MESH_MGMT_EXECUTION_WORKER_INVALID_ARG;
  }
  turbo_threadpool_shutdown(worker->pool);
  turbo_threadpool_wait(worker->pool);
  return MESH_MGMT_EXECUTION_WORKER_OK;
}

mesh_mgmt_execution_worker_result_t mesh_mgmt_execution_worker_get_stats_v1(
    mesh_mgmt_execution_worker_v1_t *worker,
    mesh_mgmt_execution_worker_stats_v1_t *out_stats) {
  turbo_threadpool_stats_t pool_stats;

  if (worker == NULL || out_stats == NULL || worker->initialized == 0u ||
      worker->pool == NULL) {
    return MESH_MGMT_EXECUTION_WORKER_INVALID_ARG;
  }
  memset(&pool_stats, 0, sizeof(pool_stats));
  memset(out_stats, 0, sizeof(*out_stats));
  turbo_threadpool_get_stats(worker->pool, &pool_stats);
  out_stats->queue_capacity = pool_stats.queue_capacity;
  out_stats->accepting = pool_stats.accepting != 0;
  out_stats->submitted = (uint64_t)pool_stats.submitted_tasks;
  out_stats->started = (uint64_t)pool_stats.started_tasks;
  out_stats->completed = (uint64_t)pool_stats.completed_tasks;
  out_stats->rejected = (uint64_t)pool_stats.rejected_tasks;
  out_stats->queued = (uint64_t)pool_stats.queued_tasks;
  return MESH_MGMT_EXECUTION_WORKER_OK;
}

void mesh_mgmt_execution_worker_destroy_v1(
    mesh_mgmt_execution_worker_v1_t *worker) {
  if (worker == NULL)
    return;
  if (worker->pool != NULL) {
    turbo_threadpool_shutdown(worker->pool);
    turbo_threadpool_wait(worker->pool);
    turbo_threadpool_destroy(worker->pool);
  }
  memset(worker, 0, sizeof(*worker));
}
