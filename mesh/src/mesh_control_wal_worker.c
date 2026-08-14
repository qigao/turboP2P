#include "mesh_control_wal_worker.h"

#include "mesh_mgmt_crypto.h"

#include <stdlib.h>
#include <string.h>

#define WAL_WORKER_QUEUE_CAPACITY 1u

static void wal_worker_run(void *argument) {
  mesh_control_wal_worker_v1_t *worker = (mesh_control_wal_worker_v1_t *)argument;
  mesh_control_wal_worker_completion_v1_t completion;
  mesh_control_wal_stats_v1_t wal_stats;

  if (!worker)
    return;
  memset(&completion, 0, sizeof(completion));
  memset(&wal_stats, 0, sizeof(wal_stats));
  completion.expected_index = worker->expected_index;
  completion.accepted_at_ms = worker->accepted_at_ms;
  completion.record_type = worker->record_type;
  completion.checkpoint_result = MESH_CONTROL_CHECKPOINT_STORE_OK;
  if (worker->record_type == MESH_CONTROL_WAL_WORKER_CHECKPOINT_RECORD_V1) {
    completion.checkpoint_result = mesh_control_checkpoint_store_save_bytes_v1(
        &worker->checkpoint_store, worker->checkpoint_bytes, worker->checkpoint_size);
    if (completion.checkpoint_result == MESH_CONTROL_CHECKPOINT_STORE_OK) {
      completion.wal_result = mesh_control_wal_compact_v1(&worker->wal, worker->expected_index);
      if (completion.wal_result == MESH_CONTROL_WAL_OK)
        completion.log_index = worker->expected_index;
    } else {
      completion.wal_result = MESH_CONTROL_WAL_INVALID_STATE;
    }
    mesh_mgmt_crypto_wipe(worker->checkpoint_bytes, worker->checkpoint_size);
    free(worker->checkpoint_bytes);
    worker->checkpoint_bytes = NULL;
    worker->checkpoint_size = 0u;
  } else if (worker->record_type == MESH_CONTROL_WAL_RECORD_SIGNED_INTENT) {
    completion.wal_result = mesh_control_wal_append_v1(
        &worker->wal, worker->expected_index, worker->accepted_at_ms, worker->signed_frame,
        worker->signed_frame_size, &completion.log_index);
  } else {
    completion.wal_result = mesh_control_wal_append_operation_result_v1(
        &worker->wal, worker->expected_index, worker->accepted_at_ms, &worker->operation_result,
        &completion.log_index);
  }
  (void)mesh_control_wal_get_stats_v1(&worker->wal, &wal_stats);

  turbo_mutex_lock(&worker->mutex);
  worker->completion = completion;
  worker->wal_stats = wal_stats;
  worker->completed++;
  if (completion.record_type == MESH_CONTROL_WAL_WORKER_CHECKPOINT_RECORD_V1) {
    if (completion.checkpoint_result == MESH_CONTROL_CHECKPOINT_STORE_OK &&
        completion.wal_result == MESH_CONTROL_WAL_OK) {
      worker->checkpoints_completed++;
    } else {
      worker->checkpoint_failures++;
      worker->persistence_failures++;
    }
  } else if (completion.wal_result != MESH_CONTROL_WAL_OK) {
    worker->persistence_failures++;
  }
  worker->completion_ready = 1u;
  turbo_mutex_unlock(&worker->mutex);
}

mesh_control_wal_worker_result_t
mesh_control_wal_worker_init_v1(mesh_control_wal_worker_v1_t *worker,
                                const mesh_control_wal_worker_config_v1_t *config) {
  turbo_threadpool_config_t pool_config;
  size_t replayed = 0u;
  uint8_t checkpoint_found = 0u;
  uint64_t replay_after_index;
  mesh_control_wal_result_t wal_result;

  if (!worker || !config || !config->recovery || worker->initialized ||
      ((config->checkpoint_path == NULL) != (config->checkpoint_owner == NULL)))
    return MESH_CONTROL_WAL_WORKER_INVALID_ARG;
  memset(worker, 0, sizeof(*worker));
  worker->checkpoint_store.lock_file = TURBO_INVALID_FILE;
  replay_after_index = config->recovery_after_index;
  if (config->checkpoint_path) {
    mesh_control_checkpoint_store_result_t checkpoint_result =
        mesh_control_checkpoint_store_open_authenticated_v1(
            &worker->checkpoint_store, config->checkpoint_path, config->wal.authentication_key);
    if (checkpoint_result != MESH_CONTROL_CHECKPOINT_STORE_OK)
      return MESH_CONTROL_WAL_WORKER_RECOVERY_FAILED;
    worker->checkpoint_store_initialized = 1u;
    checkpoint_result =
        mesh_control_checkpoint_store_load_v1(&worker->checkpoint_store, config->checkpoint_owner,
                                              config->recovery_now_ms, &checkpoint_found);
    if (checkpoint_result != MESH_CONTROL_CHECKPOINT_STORE_OK) {
      mesh_control_wal_worker_destroy_v1(worker);
      return MESH_CONTROL_WAL_WORKER_RECOVERY_FAILED;
    }
    replay_after_index = config->checkpoint_owner->committed_log_index;
    if (!checkpoint_found && replay_after_index != config->recovery_after_index) {
      mesh_control_wal_worker_destroy_v1(worker);
      return MESH_CONTROL_WAL_WORKER_RECOVERY_FAILED;
    }
  }
  wal_result = mesh_control_wal_open_v1(&worker->wal, &config->wal);
  if (wal_result != MESH_CONTROL_WAL_OK) {
    mesh_control_wal_worker_destroy_v1(worker);
    return MESH_CONTROL_WAL_WORKER_RECOVERY_FAILED;
  }
  wal_result = mesh_control_wal_replay_v1(&worker->wal, replay_after_index, config->recovery,
                                          config->recovery_context, &replayed);
  if (wal_result != MESH_CONTROL_WAL_OK) {
    mesh_control_wal_worker_destroy_v1(worker);
    return MESH_CONTROL_WAL_WORKER_RECOVERY_FAILED;
  }
  (void)mesh_control_wal_get_stats_v1(&worker->wal, &worker->wal_stats);

  turbo_mutex_init(&worker->mutex);
  worker->mutex_initialized = 1u;
  memset(&pool_config, 0, sizeof(pool_config));
  pool_config.num_threads = 1u;
  pool_config.queue_capacity = WAL_WORKER_QUEUE_CAPACITY;
  worker->pool = turbo_threadpool_create_with_config(&pool_config);
  if (!worker->pool) {
    mesh_control_wal_worker_destroy_v1(worker);
    return MESH_CONTROL_WAL_WORKER_RESOURCE_EXHAUSTED;
  }
  worker->accepting = 1u;
  worker->initialized = 1u;
  return MESH_CONTROL_WAL_WORKER_OK;
}

static mesh_control_wal_worker_result_t
submit_job(mesh_control_wal_worker_v1_t *worker, uint16_t record_type, uint64_t expected_index,
           uint64_t recorded_at_ms, const uint8_t *signed_frame, size_t signed_frame_size,
           const mesh_control_wal_operation_result_v1_t *operation_result) {
  int submit_result;

  if (!worker || expected_index == 0u || !worker->initialized || !worker->pool ||
      (record_type != MESH_CONTROL_WAL_RECORD_SIGNED_INTENT &&
       record_type != MESH_CONTROL_WAL_RECORD_OPERATION_RESULT) ||
      (record_type == MESH_CONTROL_WAL_RECORD_SIGNED_INTENT &&
       (!signed_frame || signed_frame_size == 0u || signed_frame_size > MESH_MGMT_FRAME_MAX)) ||
      (record_type == MESH_CONTROL_WAL_RECORD_OPERATION_RESULT && !operation_result)) {
    return MESH_CONTROL_WAL_WORKER_INVALID_ARG;
  }

  turbo_mutex_lock(&worker->mutex);
  if (!worker->accepting) {
    turbo_mutex_unlock(&worker->mutex);
    return MESH_CONTROL_WAL_WORKER_INVALID_STATE;
  }
  if (worker->busy || worker->completion_ready) {
    worker->rejected_full++;
    turbo_mutex_unlock(&worker->mutex);
    return MESH_CONTROL_WAL_WORKER_FULL;
  }
  worker->expected_index = expected_index;
  worker->accepted_at_ms = recorded_at_ms;
  worker->record_type = record_type;
  if (record_type == MESH_CONTROL_WAL_RECORD_SIGNED_INTENT) {
    worker->signed_frame_size = signed_frame_size;
    memcpy(worker->signed_frame, signed_frame, signed_frame_size);
  } else {
    worker->operation_result = *operation_result;
  }
  worker->busy = 1u;
  turbo_mutex_unlock(&worker->mutex);

  submit_result = turbo_threadpool_try_submit(worker->pool, wal_worker_run, worker);
  if (submit_result == 0) {
    turbo_mutex_lock(&worker->mutex);
    worker->submitted++;
    turbo_mutex_unlock(&worker->mutex);
    return MESH_CONTROL_WAL_WORKER_OK;
  }

  turbo_mutex_lock(&worker->mutex);
  worker->busy = 0u;
  worker->record_type = 0u;
  worker->signed_frame_size = 0u;
  mesh_mgmt_crypto_wipe(worker->signed_frame, sizeof(worker->signed_frame));
  mesh_mgmt_crypto_wipe(&worker->operation_result, sizeof(worker->operation_result));
  turbo_mutex_unlock(&worker->mutex);
  return turbo_threadpool_is_accepting(worker->pool) ? MESH_CONTROL_WAL_WORKER_FULL
                                                     : MESH_CONTROL_WAL_WORKER_INVALID_STATE;
}

mesh_control_wal_worker_result_t
mesh_control_wal_worker_try_submit_v1(mesh_control_wal_worker_v1_t *worker, uint64_t expected_index,
                                      uint64_t accepted_at_ms, const uint8_t *signed_frame,
                                      size_t signed_frame_size) {
  return submit_job(worker, MESH_CONTROL_WAL_RECORD_SIGNED_INTENT, expected_index, accepted_at_ms,
                    signed_frame, signed_frame_size, NULL);
}

mesh_control_wal_worker_result_t mesh_control_wal_worker_try_submit_operation_result_v1(
    mesh_control_wal_worker_v1_t *worker, uint64_t expected_index, uint64_t recorded_at_ms,
    const mesh_control_wal_operation_result_v1_t *operation_result) {
  return submit_job(worker, MESH_CONTROL_WAL_RECORD_OPERATION_RESULT, expected_index,
                    recorded_at_ms, NULL, 0u, operation_result);
}

mesh_control_wal_worker_result_t mesh_control_wal_worker_try_submit_checkpoint_v1(
    mesh_control_wal_worker_v1_t *worker, uint64_t checkpoint_index, uint8_t *checkpoint_bytes,
    size_t checkpoint_size) {
  int submit_result;
  uint64_t encoded_checkpoint_index = 0u;

  if (!worker || !worker->initialized || !worker->pool || !worker->checkpoint_store_initialized ||
      checkpoint_index == 0u || !checkpoint_bytes || checkpoint_size == 0u ||
      checkpoint_size > MESH_CONTROL_CHECKPOINT_MAX_SIZE_V1) {
    return MESH_CONTROL_WAL_WORKER_INVALID_ARG;
  }
  if (mesh_control_checkpoint_committed_log_index_v1(
          checkpoint_bytes, checkpoint_size, &encoded_checkpoint_index) !=
          MESH_CONTROL_CHECKPOINT_OK ||
      encoded_checkpoint_index != checkpoint_index) {
    return MESH_CONTROL_WAL_WORKER_INVALID_ARG;
  }
  turbo_mutex_lock(&worker->mutex);
  if (!worker->accepting) {
    turbo_mutex_unlock(&worker->mutex);
    return MESH_CONTROL_WAL_WORKER_INVALID_STATE;
  }
  if (worker->busy || worker->completion_ready) {
    worker->rejected_full++;
    turbo_mutex_unlock(&worker->mutex);
    return MESH_CONTROL_WAL_WORKER_FULL;
  }
  worker->expected_index = checkpoint_index;
  worker->accepted_at_ms = 0u;
  worker->record_type = MESH_CONTROL_WAL_WORKER_CHECKPOINT_RECORD_V1;
  worker->checkpoint_bytes = checkpoint_bytes;
  worker->checkpoint_size = checkpoint_size;
  worker->busy = 1u;
  turbo_mutex_unlock(&worker->mutex);

  submit_result = turbo_threadpool_try_submit(worker->pool, wal_worker_run, worker);
  if (submit_result == 0) {
    turbo_mutex_lock(&worker->mutex);
    worker->submitted++;
    turbo_mutex_unlock(&worker->mutex);
    return MESH_CONTROL_WAL_WORKER_OK;
  }
  turbo_mutex_lock(&worker->mutex);
  worker->checkpoint_bytes = NULL;
  worker->checkpoint_size = 0u;
  worker->busy = 0u;
  worker->record_type = 0u;
  turbo_mutex_unlock(&worker->mutex);
  return turbo_threadpool_is_accepting(worker->pool) ? MESH_CONTROL_WAL_WORKER_FULL
                                                     : MESH_CONTROL_WAL_WORKER_INVALID_STATE;
}

mesh_control_wal_worker_result_t
mesh_control_wal_worker_try_take_v1(mesh_control_wal_worker_v1_t *worker,
                                    mesh_control_wal_worker_completion_v1_t *out_completion) {
  if (!worker || !out_completion || !worker->initialized)
    return MESH_CONTROL_WAL_WORKER_INVALID_ARG;
  turbo_mutex_lock(&worker->mutex);
  if (!worker->completion_ready) {
    turbo_mutex_unlock(&worker->mutex);
    return MESH_CONTROL_WAL_WORKER_EMPTY;
  }
  *out_completion = worker->completion;
  memset(&worker->completion, 0, sizeof(worker->completion));
  mesh_mgmt_crypto_wipe(worker->signed_frame, sizeof(worker->signed_frame));
  mesh_mgmt_crypto_wipe(&worker->operation_result, sizeof(worker->operation_result));
  worker->record_type = 0u;
  worker->signed_frame_size = 0u;
  worker->busy = 0u;
  worker->completion_ready = 0u;
  turbo_mutex_unlock(&worker->mutex);
  return MESH_CONTROL_WAL_WORKER_OK;
}

mesh_control_wal_worker_result_t
mesh_control_wal_worker_shutdown_v1(mesh_control_wal_worker_v1_t *worker) {
  if (!worker || !worker->initialized || !worker->pool)
    return MESH_CONTROL_WAL_WORKER_INVALID_ARG;
  turbo_mutex_lock(&worker->mutex);
  worker->accepting = 0u;
  turbo_mutex_unlock(&worker->mutex);
  turbo_threadpool_shutdown(worker->pool);
  turbo_threadpool_wait(worker->pool);
  return MESH_CONTROL_WAL_WORKER_OK;
}

mesh_control_wal_worker_result_t
mesh_control_wal_worker_get_stats_v1(mesh_control_wal_worker_v1_t *worker,
                                     mesh_control_wal_worker_stats_v1_t *out_stats) {
  if (!worker || !out_stats || !worker->initialized)
    return MESH_CONTROL_WAL_WORKER_INVALID_ARG;
  memset(out_stats, 0, sizeof(*out_stats));
  turbo_mutex_lock(&worker->mutex);
  out_stats->submitted = worker->submitted;
  out_stats->completed = worker->completed;
  out_stats->rejected_full = worker->rejected_full;
  out_stats->persistence_failures = worker->persistence_failures;
  out_stats->checkpoints_completed = worker->checkpoints_completed;
  out_stats->checkpoint_failures = worker->checkpoint_failures;
  out_stats->accepting = worker->accepting;
  out_stats->busy = worker->busy;
  out_stats->completion_ready = worker->completion_ready;
  out_stats->wal = worker->wal_stats;
  turbo_mutex_unlock(&worker->mutex);
  return MESH_CONTROL_WAL_WORKER_OK;
}

void mesh_control_wal_worker_destroy_v1(mesh_control_wal_worker_v1_t *worker) {
  if (!worker)
    return;
  if (worker->pool) {
    turbo_threadpool_shutdown(worker->pool);
    turbo_threadpool_wait(worker->pool);
    turbo_threadpool_destroy(worker->pool);
  }
  if (worker->checkpoint_bytes) {
    mesh_mgmt_crypto_wipe(worker->checkpoint_bytes, worker->checkpoint_size);
    free(worker->checkpoint_bytes);
  }
  mesh_control_wal_close_v1(&worker->wal);
  if (worker->checkpoint_store_initialized)
    mesh_control_checkpoint_store_close_v1(&worker->checkpoint_store);
  if (worker->mutex_initialized)
    turbo_mutex_destroy(&worker->mutex);
  mesh_mgmt_crypto_wipe(worker, sizeof(*worker));
}
