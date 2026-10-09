#include "p2p_key_worker.h"
#include <salts/clock.h>
#include <salts/thread.h>
#include <salts/thread_pool.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

struct p2p_key_work_s {
    p2p_key_worker_t *worker;
    p2p_key_work_t *next;
    p2p_noise_handshake_t *handshake;
    p2p_key_complete_fn complete;
    void *context;
    uint64_t generation, deadline_ms;
    uint8_t payload[P2P_SECURITY_CREDENTIAL_MAX];
    uint8_t output[P2P_SECURITY_HANDSHAKE_FRAME_MAX];
    size_t payload_len, output_len;
    int result;
    atomic_int cancelled, completed, references;
};

struct p2p_key_worker_s {
    cmeta_threadpool_t *pool;
    cmeta_mutex_t mutex;
    p2p_blocking_private_key_provider_v4_t provider;
    p2p_key_notify_fn notify;
    void *notify_context;
    p2p_key_work_t *operations;
    p2p_private_key_executor_status_v4_t status;
    atomic_int closing;
    int polling;
};

_Static_assert(sizeof(p2p_key_work_t) <= 6U * 1024U,
    "private-key work exceeds retained-memory budget");

static void release_work(p2p_key_work_t *work) {
    if (atomic_fetch_sub_explicit(&work->references, 1, memory_order_acq_rel) == 1) {
        p2p_crypto_wipe(work, sizeof(*work));
        free(work);
    }
}

static int cancelled(void *context) {
    p2p_key_work_t *work = context;
    return atomic_load_explicit(&work->cancelled, memory_order_acquire) ||
           atomic_load_explicit(&work->worker->closing, memory_order_acquire);
}

static void discard_output(p2p_key_work_t *work) {
    p2p_crypto_wipe(work->output, sizeof(work->output));
    work->output_len = 0;
}

static void run_work(void *context) {
    p2p_key_work_t *work = context;
    p2p_private_key_cancel_v4_t cancel = {sizeof(cancel), cancelled, work};
    if (cancelled(work)) work->result = P2P_ERR_INVALID_STATE;
    else if (salts_monotonic_ms() >= work->deadline_ms) work->result = P2P_ERR_TIMEOUT;
    else work->result = p2p_noise_write_message_with_payload_blocking(
        work->handshake, work->payload, work->payload_len, work->deadline_ms, &cancel,
        work->output, &work->output_len, sizeof(work->output));
    if (cancelled(work)) work->result = P2P_ERR_INVALID_STATE;
    else if (salts_monotonic_ms() >= work->deadline_ms) work->result = P2P_ERR_TIMEOUT;
    if (work->result != P2P_OK) discard_output(work);
    p2p_crypto_wipe(work->payload, sizeof(work->payload));
    work->payload_len = 0;
}

static void cancel_queued(void *context) {
    p2p_key_work_t *work = context;
    work->result = P2P_ERR_INVALID_STATE;
    discard_output(work);
    p2p_crypto_wipe(work->payload, sizeof(work->payload));
    work->payload_len = 0;
}

static void finalize_work(void *context) {
    p2p_key_work_t *work = context;
    p2p_key_worker_t *worker = work->worker;
    /* The pool reference survives a concurrent owner poll. Neither a posted
     * wake nor an owner completion owns the pool callback's final reference. */
    atomic_store_explicit(&work->completed, 1, memory_order_release);
    if (worker->notify && worker->notify(worker->notify_context) != P2P_OK) {
        cmeta_mutex_lock(&worker->mutex);
        worker->status.completion_post_failures++;
        cmeta_mutex_unlock(&worker->mutex);
    }
    release_work(work);
}

int p2p_key_worker_create(const p2p_blocking_private_key_provider_v4_t *provider,
    p2p_key_notify_fn notify, void *notify_context, p2p_key_worker_t **output) {
    p2p_key_worker_t *worker;
    cmeta_threadpool_config_t config;
    uint16_t workers, capacity;
    uint32_t timeout;
    if (!output) return P2P_ERR_INVALID_ARG;
    *output = NULL;
    if (!provider || provider->struct_size != sizeof(*provider) ||
        !provider->get_public_key || !provider->calculate_x25519) return P2P_ERR_INVALID_ARG;
    workers = provider->executor_workers ? provider->executor_workers : P2P_PRIVATE_KEY_WORKERS_DEFAULT;
    capacity = provider->executor_capacity ? provider->executor_capacity : P2P_PRIVATE_KEY_CAPACITY_DEFAULT;
    timeout = provider->operation_timeout_ms ? provider->operation_timeout_ms : P2P_PRIVATE_KEY_TIMEOUT_DEFAULT_MS;
    if (workers > P2P_PRIVATE_KEY_WORKERS_MAX || workers > capacity ||
        capacity > P2P_PRIVATE_KEY_CAPACITY_MAX || timeout > P2P_PRIVATE_KEY_TIMEOUT_MAX_MS)
        return P2P_ERR_INVALID_ARG;
    worker = calloc(1, sizeof(*worker));
    if (!worker) return P2P_ERR_NO_MEM;
    cmeta_mutex_init(&worker->mutex);
    if (!worker->mutex) { free(worker); return P2P_ERR_NO_MEM; }
    config.num_threads = workers;
    config.queue_capacity = capacity;
    worker->pool = cmeta_threadpool_create_with_config(&config);
    if (!worker->pool) { cmeta_mutex_destroy(&worker->mutex); free(worker); return P2P_ERR_NO_MEM; }
    worker->provider = *provider;
    worker->notify = notify;
    worker->notify_context = notify_context;
    worker->status.struct_size = sizeof(worker->status);
    worker->status.workers = workers;
    worker->status.operation_capacity = capacity;
    worker->status.operation_timeout_ms = timeout;
    atomic_init(&worker->closing, 0);
    *output = worker;
    return P2P_OK;
}

static int matches_provider(const p2p_key_worker_t *worker, const p2p_noise_handshake_t *handshake) {
    return handshake->state && handshake->uses_blocking_provider &&
        handshake->blocking_provider.context == worker->provider.context &&
        handshake->blocking_provider.calculate_x25519 == worker->provider.calculate_x25519 &&
        handshake->blocking_provider.request_cancel == worker->provider.request_cancel;
}

int p2p_key_worker_submit(p2p_key_worker_t *worker,
    p2p_noise_handshake_t *handshake, uint64_t generation,
    const uint8_t *payload, size_t payload_len,
    p2p_key_complete_fn complete, void *context, p2p_key_work_t **output) {
    p2p_key_work_t *work;
    cmeta_threadpool_task_t task;
    uint64_t now_ms;
    int result;
    if (!output) return P2P_ERR_INVALID_ARG;
    *output = NULL;
    if (!worker || !handshake || !generation || !complete || (!payload && payload_len) ||
        payload_len > P2P_SECURITY_CREDENTIAL_MAX || !matches_provider(worker, handshake))
        return P2P_ERR_INVALID_ARG;
    if (atomic_load_explicit(&worker->closing, memory_order_acquire)) return P2P_ERR_INVALID_STATE;
    work = calloc(1, sizeof(*work));
    if (!work) return P2P_ERR_NO_MEM;
    work->worker = worker;
    work->handshake = handshake;
    work->generation = generation;
    work->complete = complete;
    work->context = context;
    work->payload_len = payload_len;
    if (payload_len) memcpy(work->payload, payload, payload_len);
    now_ms = salts_monotonic_ms();
    work->deadline_ms = UINT64_MAX - now_ms < worker->status.operation_timeout_ms ?
        UINT64_MAX : now_ms + worker->status.operation_timeout_ms;
    atomic_init(&work->cancelled, 0);
    atomic_init(&work->completed, 0);
    atomic_init(&work->references, 2); /* admitted list + pool terminal */
    task = (cmeta_threadpool_task_t){run_work, cancel_queued, finalize_work, work};
    cmeta_mutex_lock(&worker->mutex);
    result = worker->status.active_operations >= worker->status.operation_capacity ?
        P2P_ERR_RESOURCE_EXHAUSTED : P2P_OK;
    for (p2p_key_work_t *item = worker->operations; item && result == P2P_OK; item = item->next)
        if (item->handshake == handshake) result = P2P_ERR_INVALID_STATE;
    if (result == P2P_OK) {
        int status = cmeta_threadpool_try_submit_task(worker->pool, &task);
        if (status != SALTS_OK) result = status == SALTS_ENOBUFS ?
            P2P_ERR_RESOURCE_EXHAUSTED : P2P_ERR_INVALID_STATE;
    }
    if (result == P2P_OK) {
        work->next = worker->operations;
        worker->operations = work;
        worker->status.active_operations++;
        worker->status.submitted++;
        *output = work;
    } else worker->status.rejected++;
    cmeta_mutex_unlock(&worker->mutex);
    if (result != P2P_OK) {
        /* Rejected descriptors invoke no run/cancel/finalize callback. */
        release_work(work);
        release_work(work);
    }
    return result;
}

int p2p_key_work_cancel(p2p_key_work_t *work) {
    return work && !atomic_exchange_explicit(&work->cancelled, 1, memory_order_acq_rel);
}

int p2p_key_work_ready(const p2p_key_work_t *work) {
    return work && atomic_load_explicit(&work->completed, memory_order_acquire);
}

uint64_t p2p_key_work_deadline(const p2p_key_work_t *work) {
    return work ? work->deadline_ms : 0;
}

int p2p_key_worker_poll(p2p_key_worker_t *worker) {
    if (!worker) return P2P_ERR_INVALID_ARG;
    if (worker->polling) return P2P_ERR_INVALID_STATE;
    worker->polling = 1;
    for (size_t i = 0; i < worker->status.operation_capacity; ++i) {
        p2p_key_work_t *work = NULL;
        p2p_key_work_t **link;
        p2p_key_result_t result;
        cmeta_mutex_lock(&worker->mutex);
        for (link = &worker->operations; *link; link = &(*link)->next) {
            if (p2p_key_work_ready(*link)) { work = *link; *link = work->next; break; }
        }
        if (!work) { cmeta_mutex_unlock(&worker->mutex); break; }
        if (cancelled(work)) work->result = P2P_ERR_INVALID_STATE;
        else if (work->result == P2P_OK && salts_monotonic_ms() >= work->deadline_ms)
            work->result = P2P_ERR_TIMEOUT;
        if (work->result != P2P_OK) discard_output(work);
        worker->status.active_operations--;
        worker->status.completed++;
        if (work->result == P2P_ERR_TIMEOUT) worker->status.timed_out++;
        if (cancelled(work)) worker->status.cancelled++;
        cmeta_mutex_unlock(&worker->mutex);
        result = (p2p_key_result_t){work->handshake, work->generation, work->deadline_ms,
                                  work->result, work->output, work->output_len};
        work->complete(work, &result, work->context);
        release_work(work);
    }
    worker->polling = 0;
    return P2P_OK;
}

int p2p_key_worker_stop(p2p_key_worker_t *worker) {
    cmeta_threadpool_t *pool;
    int result;
    if (!worker) return P2P_ERR_INVALID_ARG;
    if (worker->polling) return P2P_ERR_INVALID_STATE;
    cmeta_mutex_lock(&worker->mutex);
    pool = worker->pool;
    atomic_store_explicit(&worker->closing, 1, memory_order_release);
    for (p2p_key_work_t *work = worker->operations; work; work = work->next)
        atomic_store_explicit(&work->cancelled, 1, memory_order_release);
    result = worker->status.active_operations != 0;
    cmeta_mutex_unlock(&worker->mutex);
    if (!pool) return P2P_OK;
    if (result && worker->provider.request_cancel) worker->provider.request_cancel(worker->provider.context);
    if (cmeta_threadpool_shutdown_with_policy(pool, SALTS_THREADPOOL_SHUTDOWN_CANCEL_PENDING) != SALTS_OK ||
        cmeta_threadpool_wait_status(pool) != SALTS_OK) return P2P_ERR_INVALID_STATE;
    result = p2p_key_worker_poll(worker);
    if (result != P2P_OK) return result;
    cmeta_mutex_lock(&worker->mutex);
    worker->pool = NULL;
    cmeta_mutex_unlock(&worker->mutex);
    cmeta_threadpool_destroy(pool);
    return P2P_OK;
}

int p2p_key_worker_destroy(p2p_key_worker_t *worker) {
    int result;
    if (!worker) return P2P_OK;
    result = p2p_key_worker_stop(worker);
    if (result != P2P_OK) return result;
    cmeta_mutex_destroy(&worker->mutex);
    p2p_crypto_wipe(worker, sizeof(*worker));
    free(worker);
    return P2P_OK;
}

int p2p_key_worker_status(p2p_key_worker_t *worker,
    p2p_private_key_executor_status_v4_t *output) {
    cmeta_threadpool_stats_t pool = {0};
    if (!worker || !output) return P2P_ERR_INVALID_ARG;
    cmeta_mutex_lock(&worker->mutex);
    *output = worker->status;
    if (worker->pool) cmeta_threadpool_get_stats(worker->pool, &pool);
    output->queued_operations = pool.queued_tasks > 0 ? (size_t)pool.queued_tasks : 0;
    output->accepting = !atomic_load_explicit(&worker->closing, memory_order_acquire) && pool.accepting;
    cmeta_mutex_unlock(&worker->mutex);
    return P2P_OK;
}
