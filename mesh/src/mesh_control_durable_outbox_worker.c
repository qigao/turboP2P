#include "mesh_control_durable_outbox_worker.h"

#include <openssl/crypto.h>

#include <string.h>

#define DURABLE_OUTBOX_WORKER_QUEUE_CAPACITY 1u

static int persistence_failed(mesh_control_durable_outbox_result_t result) {
  return result == MESH_CONTROL_DURABLE_OUTBOX_IO ||
         result == MESH_CONTROL_DURABLE_OUTBOX_CORRUPT ||
         result == MESH_CONTROL_DURABLE_OUTBOX_AUTH_FAILED ||
         result == MESH_CONTROL_DURABLE_OUTBOX_INVALID_STATE;
}

static void durable_outbox_worker_run(void *argument) {
  mesh_control_durable_outbox_worker_v1_t *worker =
      (mesh_control_durable_outbox_worker_v1_t *)argument;
  mesh_control_durable_outbox_worker_completion_v1_t completion;
  mesh_control_durable_outbox_view_v1_t view;
  mesh_control_durable_outbox_stats_v1_t stats;
  size_t affected = 0u;
  uint64_t session_generation = 0u;

  if (!worker)
    return;
  memset(&completion, 0, sizeof(completion));
  memset(&view, 0, sizeof(view));
  memset(&stats, 0, sizeof(stats));
  completion.request_token = worker->request_token;
  completion.operation = worker->operation;
  switch (worker->operation) {
  case MESH_CONTROL_DURABLE_OUTBOX_WORKER_SUBMIT:
    completion.store_result = mesh_control_durable_outbox_submit_v1(
        &worker->outbox, &worker->message, &view);
    break;
  case MESH_CONTROL_DURABLE_OUTBOX_WORKER_ACTIVATE_SESSION:
    completion.store_result = mesh_control_durable_outbox_activate_session_v1(
        &worker->outbox, worker->target_node_id, worker->session_id,
        worker->time_ms, &session_generation, &affected);
    break;
  case MESH_CONTROL_DURABLE_OUTBOX_WORKER_DEACTIVATE_SESSION:
    completion.store_result = mesh_control_durable_outbox_deactivate_session_v1(
        &worker->outbox, worker->target_node_id, worker->session_id,
        worker->session_generation);
    break;
  case MESH_CONTROL_DURABLE_OUTBOX_WORKER_CLAIM:
    completion.store_result = mesh_control_durable_outbox_claim_v1(
        &worker->outbox, worker->target_node_id, worker->session_id,
        worker->session_generation, worker->time_ms, worker->lease_ms, &view);
    break;
  case MESH_CONTROL_DURABLE_OUTBOX_WORKER_ACK:
    completion.store_result = mesh_control_durable_outbox_ack_v1(
        &worker->outbox, worker->target_node_id, worker->message_id,
        worker->session_id, worker->session_generation,
        worker->lease_generation, worker->time_ms);
    break;
  case MESH_CONTROL_DURABLE_OUTBOX_WORKER_RELEASE:
    completion.store_result = mesh_control_durable_outbox_release_v1(
        &worker->outbox, worker->target_node_id, worker->message_id,
        worker->session_id, worker->session_generation,
        worker->lease_generation);
    break;
  case MESH_CONTROL_DURABLE_OUTBOX_WORKER_COMPACT:
    completion.store_result = mesh_control_durable_outbox_compact_v1(
        &worker->outbox, worker->time_ms, &affected);
    break;
  default:
    completion.store_result = MESH_CONTROL_DURABLE_OUTBOX_INVALID_ARG;
    break;
  }
  completion.view = view;
  completion.session_generation = session_generation;
  completion.affected = affected;
  worker->completion_payload_size = 0u;
  if (completion.store_result == MESH_CONTROL_DURABLE_OUTBOX_OK &&
      view.payload_size > 0u) {
    memcpy(worker->completion_payload, view.payload, view.payload_size);
    worker->completion_payload_size = view.payload_size;
    completion.view.payload = worker->completion_payload;
  } else {
    completion.view.payload = NULL;
    completion.view.payload_size = 0u;
  }
  (void)mesh_control_durable_outbox_get_stats_v1(&worker->outbox, &stats);

  turbo_mutex_lock(&worker->mutex);
  worker->completion = completion;
  worker->cached_stats = stats;
  worker->completed++;
  if (persistence_failed(completion.store_result))
    worker->persistence_failures++;
  worker->completion_ready = 1u;
  turbo_mutex_unlock(&worker->mutex);
}

mesh_control_durable_outbox_worker_result_t
mesh_control_durable_outbox_worker_init_v1(
    mesh_control_durable_outbox_worker_v1_t *worker,
    const mesh_control_durable_outbox_config_v1_t *config,
    size_t *out_recovered_claims) {
  turbo_threadpool_config_t pool_config;
  mesh_control_durable_outbox_result_t result;
  if (!worker || worker->initialized || !config)
    return MESH_CONTROL_DURABLE_OUTBOX_WORKER_INVALID_ARG;
  memset(worker, 0, sizeof(*worker));
  worker->outbox.lock_file = TURBO_INVALID_FILE;
  result = mesh_control_durable_outbox_open_v1(
      &worker->outbox, config, out_recovered_claims);
  if (result != MESH_CONTROL_DURABLE_OUTBOX_OK) {
    mesh_control_durable_outbox_worker_destroy_v1(worker);
    return MESH_CONTROL_DURABLE_OUTBOX_WORKER_RECOVERY_FAILED;
  }
  (void)mesh_control_durable_outbox_get_stats_v1(&worker->outbox,
                                                  &worker->cached_stats);
  turbo_mutex_init(&worker->mutex);
  worker->mutex_initialized = 1u;
  memset(&pool_config, 0, sizeof(pool_config));
  pool_config.num_threads = 1u;
  pool_config.queue_capacity = DURABLE_OUTBOX_WORKER_QUEUE_CAPACITY;
  worker->pool = turbo_threadpool_create_with_config(&pool_config);
  if (!worker->pool) {
    mesh_control_durable_outbox_worker_destroy_v1(worker);
    return MESH_CONTROL_DURABLE_OUTBOX_WORKER_RESOURCE_EXHAUSTED;
  }
  worker->accepting = 1u;
  worker->initialized = 1u;
  return MESH_CONTROL_DURABLE_OUTBOX_WORKER_OK;
}

static mesh_control_durable_outbox_worker_result_t reserve_request(
    mesh_control_durable_outbox_worker_v1_t *worker,
    mesh_control_durable_outbox_worker_operation_v1_t operation,
    uint64_t request_token) {
  if (!worker || !worker->initialized || !worker->pool || request_token == 0u)
    return MESH_CONTROL_DURABLE_OUTBOX_WORKER_INVALID_ARG;
  turbo_mutex_lock(&worker->mutex);
  if (!worker->accepting) {
    turbo_mutex_unlock(&worker->mutex);
    return MESH_CONTROL_DURABLE_OUTBOX_WORKER_INVALID_STATE;
  }
  if (worker->busy || worker->completion_ready) {
    worker->rejected_full++;
    turbo_mutex_unlock(&worker->mutex);
    return MESH_CONTROL_DURABLE_OUTBOX_WORKER_FULL;
  }
  worker->operation = operation;
  worker->request_token = request_token;
  worker->busy = 1u;
  turbo_mutex_unlock(&worker->mutex);
  return MESH_CONTROL_DURABLE_OUTBOX_WORKER_OK;
}

static mesh_control_durable_outbox_worker_result_t start_reserved(
    mesh_control_durable_outbox_worker_v1_t *worker) {
  if (turbo_threadpool_try_submit(worker->pool, durable_outbox_worker_run,
                                  worker) == 0) {
    turbo_mutex_lock(&worker->mutex);
    worker->submitted++;
    turbo_mutex_unlock(&worker->mutex);
    return MESH_CONTROL_DURABLE_OUTBOX_WORKER_OK;
  }
  turbo_mutex_lock(&worker->mutex);
  worker->busy = 0u;
  worker->operation = 0;
  worker->request_token = 0u;
  turbo_mutex_unlock(&worker->mutex);
  return turbo_threadpool_is_accepting(worker->pool)
             ? MESH_CONTROL_DURABLE_OUTBOX_WORKER_FULL
             : MESH_CONTROL_DURABLE_OUTBOX_WORKER_INVALID_STATE;
}

static void copy_session_request(
    mesh_control_durable_outbox_worker_v1_t *worker,
    const uint8_t target_node_id[MESH_CONTROL_NODE_ID_SIZE],
    const uint8_t session_id[MESH_CONTROL_ID_SIZE]) {
  memcpy(worker->target_node_id, target_node_id, MESH_CONTROL_NODE_ID_SIZE);
  memcpy(worker->session_id, session_id, MESH_CONTROL_ID_SIZE);
}

mesh_control_durable_outbox_worker_result_t
mesh_control_durable_outbox_worker_try_submit_message_v1(
    mesh_control_durable_outbox_worker_v1_t *worker, uint64_t request_token,
    const mesh_control_durable_outbox_message_v1_t *message) {
  mesh_control_durable_outbox_worker_result_t result;
  if (!message || !message->payload || message->payload_size == 0u ||
      message->payload_size > MESH_CONTROL_MAX_FRAME_SIZE_V1)
    return MESH_CONTROL_DURABLE_OUTBOX_WORKER_INVALID_ARG;
  result = reserve_request(worker, MESH_CONTROL_DURABLE_OUTBOX_WORKER_SUBMIT,
                           request_token);
  if (result != MESH_CONTROL_DURABLE_OUTBOX_WORKER_OK)
    return result;
  worker->message = *message;
  memcpy(worker->request_payload, message->payload, message->payload_size);
  worker->message.payload = worker->request_payload;
  return start_reserved(worker);
}

mesh_control_durable_outbox_worker_result_t
mesh_control_durable_outbox_worker_try_activate_session_v1(
    mesh_control_durable_outbox_worker_v1_t *worker, uint64_t request_token,
    const uint8_t target_node_id[MESH_CONTROL_NODE_ID_SIZE],
    const uint8_t session_id[MESH_CONTROL_ID_SIZE], uint64_t connected_at_ms) {
  mesh_control_durable_outbox_worker_result_t result;
  if (!target_node_id || !session_id || connected_at_ms == 0u)
    return MESH_CONTROL_DURABLE_OUTBOX_WORKER_INVALID_ARG;
  result = reserve_request(worker,
                           MESH_CONTROL_DURABLE_OUTBOX_WORKER_ACTIVATE_SESSION,
                           request_token);
  if (result != MESH_CONTROL_DURABLE_OUTBOX_WORKER_OK)
    return result;
  copy_session_request(worker, target_node_id, session_id);
  worker->time_ms = connected_at_ms;
  return start_reserved(worker);
}

mesh_control_durable_outbox_worker_result_t
mesh_control_durable_outbox_worker_try_deactivate_session_v1(
    mesh_control_durable_outbox_worker_v1_t *worker, uint64_t request_token,
    const uint8_t target_node_id[MESH_CONTROL_NODE_ID_SIZE],
    const uint8_t session_id[MESH_CONTROL_ID_SIZE], uint64_t session_generation) {
  mesh_control_durable_outbox_worker_result_t result;
  if (!target_node_id || !session_id || session_generation == 0u)
    return MESH_CONTROL_DURABLE_OUTBOX_WORKER_INVALID_ARG;
  result = reserve_request(
      worker, MESH_CONTROL_DURABLE_OUTBOX_WORKER_DEACTIVATE_SESSION,
      request_token);
  if (result != MESH_CONTROL_DURABLE_OUTBOX_WORKER_OK)
    return result;
  copy_session_request(worker, target_node_id, session_id);
  worker->session_generation = session_generation;
  return start_reserved(worker);
}

mesh_control_durable_outbox_worker_result_t
mesh_control_durable_outbox_worker_try_claim_v1(
    mesh_control_durable_outbox_worker_v1_t *worker, uint64_t request_token,
    const uint8_t target_node_id[MESH_CONTROL_NODE_ID_SIZE],
    const uint8_t session_id[MESH_CONTROL_ID_SIZE], uint64_t session_generation,
    uint64_t now_ms, uint64_t lease_ms) {
  mesh_control_durable_outbox_worker_result_t result;
  if (!target_node_id || !session_id || session_generation == 0u ||
      now_ms == 0u || lease_ms == 0u)
    return MESH_CONTROL_DURABLE_OUTBOX_WORKER_INVALID_ARG;
  result = reserve_request(worker, MESH_CONTROL_DURABLE_OUTBOX_WORKER_CLAIM,
                           request_token);
  if (result != MESH_CONTROL_DURABLE_OUTBOX_WORKER_OK)
    return result;
  copy_session_request(worker, target_node_id, session_id);
  worker->session_generation = session_generation;
  worker->time_ms = now_ms;
  worker->lease_ms = lease_ms;
  return start_reserved(worker);
}

static mesh_control_durable_outbox_worker_result_t submit_delivery_mutation(
    mesh_control_durable_outbox_worker_v1_t *worker, uint64_t request_token,
    mesh_control_durable_outbox_worker_operation_v1_t operation,
    const uint8_t target_node_id[MESH_CONTROL_NODE_ID_SIZE],
    const uint8_t message_id[MESH_CONTROL_ID_SIZE],
    const uint8_t session_id[MESH_CONTROL_ID_SIZE], uint64_t session_generation,
    uint64_t lease_generation, uint64_t time_ms) {
  mesh_control_durable_outbox_worker_result_t result;
  if (!target_node_id || !message_id || !session_id ||
      session_generation == 0u || lease_generation == 0u)
    return MESH_CONTROL_DURABLE_OUTBOX_WORKER_INVALID_ARG;
  result = reserve_request(worker, operation, request_token);
  if (result != MESH_CONTROL_DURABLE_OUTBOX_WORKER_OK)
    return result;
  copy_session_request(worker, target_node_id, session_id);
  memcpy(worker->message_id, message_id, MESH_CONTROL_ID_SIZE);
  worker->session_generation = session_generation;
  worker->lease_generation = lease_generation;
  worker->time_ms = time_ms;
  return start_reserved(worker);
}

mesh_control_durable_outbox_worker_result_t
mesh_control_durable_outbox_worker_try_ack_v1(
    mesh_control_durable_outbox_worker_v1_t *worker, uint64_t request_token,
    const uint8_t target_node_id[MESH_CONTROL_NODE_ID_SIZE],
    const uint8_t message_id[MESH_CONTROL_ID_SIZE],
    const uint8_t session_id[MESH_CONTROL_ID_SIZE], uint64_t session_generation,
    uint64_t lease_generation, uint64_t acked_at_ms) {
  if (acked_at_ms == 0u)
    return MESH_CONTROL_DURABLE_OUTBOX_WORKER_INVALID_ARG;
  return submit_delivery_mutation(
      worker, request_token, MESH_CONTROL_DURABLE_OUTBOX_WORKER_ACK,
      target_node_id, message_id, session_id, session_generation,
      lease_generation, acked_at_ms);
}

mesh_control_durable_outbox_worker_result_t
mesh_control_durable_outbox_worker_try_release_v1(
    mesh_control_durable_outbox_worker_v1_t *worker, uint64_t request_token,
    const uint8_t target_node_id[MESH_CONTROL_NODE_ID_SIZE],
    const uint8_t message_id[MESH_CONTROL_ID_SIZE],
    const uint8_t session_id[MESH_CONTROL_ID_SIZE], uint64_t session_generation,
    uint64_t lease_generation) {
  return submit_delivery_mutation(
      worker, request_token, MESH_CONTROL_DURABLE_OUTBOX_WORKER_RELEASE,
      target_node_id, message_id, session_id, session_generation,
      lease_generation, 0u);
}

mesh_control_durable_outbox_worker_result_t
mesh_control_durable_outbox_worker_try_compact_v1(
    mesh_control_durable_outbox_worker_v1_t *worker, uint64_t request_token,
    uint64_t now_ms) {
  mesh_control_durable_outbox_worker_result_t result;
  if (now_ms == 0u)
    return MESH_CONTROL_DURABLE_OUTBOX_WORKER_INVALID_ARG;
  result = reserve_request(worker, MESH_CONTROL_DURABLE_OUTBOX_WORKER_COMPACT,
                           request_token);
  if (result != MESH_CONTROL_DURABLE_OUTBOX_WORKER_OK)
    return result;
  worker->time_ms = now_ms;
  return start_reserved(worker);
}

mesh_control_durable_outbox_worker_result_t
mesh_control_durable_outbox_worker_try_take_v1(
    mesh_control_durable_outbox_worker_v1_t *worker,
    mesh_control_durable_outbox_worker_completion_v1_t *out_completion,
    uint8_t *payload, size_t payload_capacity, size_t *out_payload_size) {
  if (!worker || !worker->initialized || !out_completion || !out_payload_size)
    return MESH_CONTROL_DURABLE_OUTBOX_WORKER_INVALID_ARG;
  turbo_mutex_lock(&worker->mutex);
  if (!worker->completion_ready) {
    turbo_mutex_unlock(&worker->mutex);
    return MESH_CONTROL_DURABLE_OUTBOX_WORKER_EMPTY;
  }
  *out_payload_size = worker->completion_payload_size;
  if (worker->completion_payload_size > payload_capacity ||
      (worker->completion_payload_size > 0u && !payload)) {
    turbo_mutex_unlock(&worker->mutex);
    return MESH_CONTROL_DURABLE_OUTBOX_WORKER_RESOURCE_EXHAUSTED;
  }
  *out_completion = worker->completion;
  if (worker->completion_payload_size > 0u) {
    memcpy(payload, worker->completion_payload, worker->completion_payload_size);
    out_completion->view.payload = payload;
    out_completion->view.payload_size = worker->completion_payload_size;
  } else {
    out_completion->view.payload = NULL;
    out_completion->view.payload_size = 0u;
  }
  OPENSSL_cleanse(worker->request_payload, sizeof(worker->request_payload));
  OPENSSL_cleanse(worker->completion_payload, sizeof(worker->completion_payload));
  memset(&worker->message, 0, sizeof(worker->message));
  memset(&worker->completion, 0, sizeof(worker->completion));
  worker->completion_payload_size = 0u;
  worker->operation = 0;
  worker->request_token = 0u;
  worker->busy = 0u;
  worker->completion_ready = 0u;
  turbo_mutex_unlock(&worker->mutex);
  return MESH_CONTROL_DURABLE_OUTBOX_WORKER_OK;
}

mesh_control_durable_outbox_worker_result_t
mesh_control_durable_outbox_worker_shutdown_v1(
    mesh_control_durable_outbox_worker_v1_t *worker) {
  if (!worker || !worker->initialized || !worker->pool)
    return MESH_CONTROL_DURABLE_OUTBOX_WORKER_INVALID_ARG;
  turbo_mutex_lock(&worker->mutex);
  worker->accepting = 0u;
  turbo_mutex_unlock(&worker->mutex);
  turbo_threadpool_shutdown(worker->pool);
  turbo_threadpool_wait(worker->pool);
  return MESH_CONTROL_DURABLE_OUTBOX_WORKER_OK;
}

mesh_control_durable_outbox_worker_result_t
mesh_control_durable_outbox_worker_get_stats_v1(
    mesh_control_durable_outbox_worker_v1_t *worker,
    mesh_control_durable_outbox_worker_stats_v1_t *out_stats) {
  if (!worker || !worker->initialized || !out_stats)
    return MESH_CONTROL_DURABLE_OUTBOX_WORKER_INVALID_ARG;
  memset(out_stats, 0, sizeof(*out_stats));
  turbo_mutex_lock(&worker->mutex);
  out_stats->outbox = worker->cached_stats;
  out_stats->submitted = worker->submitted;
  out_stats->completed = worker->completed;
  out_stats->rejected_full = worker->rejected_full;
  out_stats->persistence_failures = worker->persistence_failures;
  out_stats->accepting = worker->accepting;
  out_stats->busy = worker->busy;
  out_stats->completion_ready = worker->completion_ready;
  turbo_mutex_unlock(&worker->mutex);
  return MESH_CONTROL_DURABLE_OUTBOX_WORKER_OK;
}

void mesh_control_durable_outbox_worker_destroy_v1(
    mesh_control_durable_outbox_worker_v1_t *worker) {
  if (!worker)
    return;
  if (worker->pool) {
    turbo_threadpool_shutdown(worker->pool);
    turbo_threadpool_wait(worker->pool);
    turbo_threadpool_destroy(worker->pool);
  }
  mesh_control_durable_outbox_close_v1(&worker->outbox);
  if (worker->mutex_initialized)
    turbo_mutex_destroy(&worker->mutex);
  OPENSSL_cleanse(worker, sizeof(*worker));
}
