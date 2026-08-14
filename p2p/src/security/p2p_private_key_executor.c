#include "p2p_private_key_executor.h"

#include "../core/peer.h"
#include "../internal.h"

#include <CoroNet/turbo_coro_context.h>
#include <platform.h>
#include <turbo_thread.h>

#include <stdlib.h>
#include <string.h>

_Static_assert(sizeof(p2p_private_key_operation_t) <= 6U * 1024U,
               "private-key operation exceeds its retained-memory budget");

static int operation_is_cancelled(void *context) {
    p2p_private_key_operation_t *operation =
        (p2p_private_key_operation_t *)context;

    return !operation ||
           atomic_load_explicit(&operation->cancel_requested,
                                memory_order_acquire) != 0;
}

static void operation_release(p2p_private_key_operation_t *operation) {
    if (!operation) {
        return;
    }
    if (atomic_fetch_sub_explicit(&operation->references, 1,
                                  memory_order_acq_rel) == 1) {
        p2p_crypto_wipe(operation, sizeof(*operation));
        free(operation);
    }
}

static void executor_remove_operation_locked(
    p2p_private_key_executor_t *executor,
    p2p_private_key_operation_t *operation) {
    p2p_private_key_operation_t **current;

    if (!executor || !operation) {
        return;
    }
    current = &executor->operations;
    while (*current) {
        if (*current == operation) {
            *current = operation->next;
            operation->next = NULL;
            if (executor->active_operations > 0) {
                executor->active_operations--;
            }
            return;
        }
        current = &(*current)->next;
    }
}

static void executor_finish_on_owner(
    p2p_private_key_operation_t *operation) {
    p2p_private_key_executor_t *executor;
    p2p_peer_t *peer;
    p2p_node_t *node;
    uint64_t now_ms;
    int was_current = 0;

    if (!operation) {
        return;
    }
    executor = operation->executor;
    peer = operation->peer;
    node = operation->node;
    if (!executor || !peer || !node) {
        operation_release(operation);
        return;
    }

    now_ms = turbo_hrtime() / 1000000U;
    if (operation->result == P2P_OK && now_ms > operation->deadline_ms) {
        operation->result = P2P_ERR_TIMEOUT;
        p2p_crypto_wipe(operation->output, sizeof(operation->output));
        operation->output_len = 0;
    }

    turbo_mutex_lock(&node->mutex);
    if (peer->private_key_operation == operation) {
        peer->private_key_operation = NULL;
        was_current = 1;
    }
    executor_remove_operation_locked(executor, operation);
    executor->completed++;
    if (operation->result == P2P_ERR_TIMEOUT) {
        executor->timed_out++;
    }
    if (atomic_load_explicit(&operation->cancel_requested,
                             memory_order_acquire) != 0) {
        executor->cancelled++;
    }
    turbo_mutex_unlock(&node->mutex);

    p2p_peer_complete_private_key_operation(operation, was_current);
    p2p_peer_release(peer);
    operation_release(operation);
}

static void executor_completion_post(void *arg1, void *arg2) {
    p2p_private_key_operation_t *operation =
        (p2p_private_key_operation_t *)arg1;
    int expected = 0;
    (void)arg2;

    if (operation && atomic_compare_exchange_strong_explicit(
                         &operation->owner_claimed, &expected, 1,
                         memory_order_acq_rel, memory_order_acquire)) {
        executor_finish_on_owner(operation);
    }
    operation_release(operation);
}

static void executor_run_operation(void *argument) {
    p2p_private_key_operation_t *operation =
        (p2p_private_key_operation_t *)argument;
    p2p_private_key_executor_t *executor;
    p2p_private_key_cancel_v4_t cancel;
    uint64_t now_ms;
    int post_result;

    if (!operation || !operation->executor || !operation->peer) {
        return;
    }
    executor = operation->executor;
    cancel.struct_size = sizeof(cancel);
    cancel.is_cancelled = operation_is_cancelled;
    cancel.context = operation;

    now_ms = turbo_hrtime() / 1000000U;
    if (p2p_private_key_executor_is_closing(executor) ||
        operation_is_cancelled(operation)) {
        operation->result = P2P_ERR_INVALID_STATE;
    } else if (now_ms >= operation->deadline_ms) {
        operation->result = P2P_ERR_TIMEOUT;
    } else {
        operation->result = p2p_noise_write_message_with_payload_blocking(
            operation->handshake, operation->payload,
            operation->payload_len, operation->deadline_ms, &cancel,
            operation->output, &operation->output_len,
            sizeof(operation->output));
    }

    now_ms = turbo_hrtime() / 1000000U;
    if (operation_is_cancelled(operation) ||
        p2p_private_key_executor_is_closing(executor)) {
        operation->result = P2P_ERR_INVALID_STATE;
    } else if (now_ms > operation->deadline_ms) {
        operation->result = P2P_ERR_TIMEOUT;
    }
    if (operation->result != P2P_OK) {
        p2p_crypto_wipe(operation->output, sizeof(operation->output));
        operation->output_len = 0;
    }
    p2p_crypto_wipe(operation->payload, sizeof(operation->payload));
    operation->payload_len = 0;
    /* Publish a completion only after reserving the post callback's
     * reference.  The owner-side fallback pump may observe completed as soon
     * as it is released and is then allowed to drop the list reference. */
    atomic_fetch_add_explicit(&operation->references, 1,
                              memory_order_relaxed);
    atomic_store_explicit(&operation->completed, 1, memory_order_release);
    do {
        post_result = coro_post(operation->node->ctx,
                                executor_completion_post,
                                operation, NULL);
        if (post_result == 0 ||
            p2p_private_key_executor_is_closing(executor) ||
            operation_is_cancelled(operation)) {
            break;
        }
        now_ms = turbo_hrtime() / 1000000U;
        if (now_ms >= operation->deadline_ms) {
            break;
        }
        turbo_sleep_ms(1);
    } while (1);
    if (post_result != 0) {
        turbo_mutex_lock(&operation->node->mutex);
        executor->completion_post_failures++;
        turbo_mutex_unlock(&operation->node->mutex);
        /* Keep the completion reference until the last operation/node access.
         * The owner fallback pump may concurrently drop the list reference. */
        operation_release(operation);
    }
}

p2p_private_key_executor_t *p2p_private_key_executor_create(
    p2p_node_t *node,
    const p2p_blocking_private_key_provider_v4_t *provider) {
    p2p_private_key_executor_t *executor;
    turbo_threadpool_config_t config;
    uint16_t workers;
    uint16_t capacity;
    uint32_t timeout_ms;

    if (!node || !provider || provider->struct_size != sizeof(*provider) ||
        !provider->get_public_key || !provider->calculate_x25519) {
        return NULL;
    }
    workers = provider->executor_workers
                  ? provider->executor_workers
                  : P2P_PRIVATE_KEY_WORKERS_DEFAULT;
    capacity = provider->executor_capacity
                   ? provider->executor_capacity
                   : P2P_PRIVATE_KEY_CAPACITY_DEFAULT;
    timeout_ms = provider->operation_timeout_ms
                     ? provider->operation_timeout_ms
                     : P2P_PRIVATE_KEY_TIMEOUT_DEFAULT_MS;
    if (workers > P2P_PRIVATE_KEY_WORKERS_MAX || capacity == 0 ||
        capacity > P2P_PRIVATE_KEY_CAPACITY_MAX || workers > capacity ||
        timeout_ms > P2P_PRIVATE_KEY_TIMEOUT_MAX_MS) {
        return NULL;
    }

    executor = (p2p_private_key_executor_t *)calloc(1, sizeof(*executor));
    if (!executor) {
        return NULL;
    }
    config.num_threads = workers;
    config.queue_capacity = capacity;
    executor->pool = turbo_threadpool_create_with_config(&config);
    if (!executor->pool) {
        free(executor);
        return NULL;
    }
    executor->node = node;
    executor->provider = *provider;
    executor->provider.executor_workers = workers;
    executor->provider.executor_capacity = capacity;
    executor->provider.operation_timeout_ms = timeout_ms;
    executor->workers = workers;
    executor->capacity = capacity;
    executor->operation_timeout_ms = timeout_ms;
    atomic_init(&executor->closing, 0);
    return executor;
}

int p2p_private_key_executor_submit(
    p2p_peer_t *peer,
    const uint8_t *payload,
    size_t payload_len,
    uint8_t next_noise_step,
    int finish_noise) {
    p2p_private_key_executor_t *executor;
    p2p_private_key_operation_t *operation;
    p2p_node_t *node;
    uint64_t now_ms;

    if (!peer || !peer->node || !peer->handshake ||
        (!payload && payload_len != 0) ||
        payload_len > P2P_SECURITY_CREDENTIAL_MAX) {
        return P2P_ERR_INVALID_ARG;
    }
    node = peer->node;
    executor = node->private_key_executor;
    if (!executor || p2p_private_key_executor_is_closing(executor)) {
        return P2P_ERR_INVALID_STATE;
    }
    operation = (p2p_private_key_operation_t *)calloc(1, sizeof(*operation));
    if (!operation) {
        return P2P_ERR_NO_MEM;
    }
    atomic_init(&operation->cancel_requested, 0);
    atomic_init(&operation->completed, 0);
    atomic_init(&operation->owner_claimed, 0);
    atomic_init(&operation->references, 1);
    operation->executor = executor;
    operation->node = node;
    operation->peer = peer;
    operation->handshake = peer->handshake;
    operation->handshake_generation = peer->handshake_generation;
    operation->next_noise_step = next_noise_step;
    operation->finish_noise = finish_noise != 0;
    if (payload_len > 0) {
        memcpy(operation->payload, payload, payload_len);
    }
    operation->payload_len = payload_len;
    now_ms = turbo_hrtime() / 1000000U;
    operation->deadline_ms = now_ms + executor->operation_timeout_ms;
    if (operation->deadline_ms < now_ms) {
        operation->deadline_ms = UINT64_MAX;
    }

    turbo_mutex_lock(&node->mutex);
    if (atomic_load_explicit(&executor->closing, memory_order_acquire) != 0 ||
        executor->active_operations >= executor->capacity ||
        peer->private_key_operation || !p2p_peer_hold_locked(peer)) {
        executor->rejected++;
        turbo_mutex_unlock(&node->mutex);
        operation_release(operation);
        return P2P_ERR_RESOURCE_EXHAUSTED;
    }
    executor->next_operation_id++;
    if (executor->next_operation_id == 0) {
        executor->next_operation_id++;
    }
    operation->operation_id = executor->next_operation_id;
    operation->next = executor->operations;
    executor->operations = operation;
    executor->active_operations++;
    executor->submitted++;
    peer->private_key_operation = operation;
    turbo_mutex_unlock(&node->mutex);

    if (turbo_threadpool_try_submit(executor->pool,
                                    executor_run_operation,
                                    operation) != 0) {
        turbo_mutex_lock(&node->mutex);
        if (peer->private_key_operation == operation) {
            peer->private_key_operation = NULL;
        }
        executor_remove_operation_locked(executor, operation);
        executor->rejected++;
        turbo_mutex_unlock(&node->mutex);
        p2p_peer_release(peer);
        operation_release(operation);
        return P2P_ERR_RESOURCE_EXHAUSTED;
    }
    return P2P_OK;
}

void p2p_private_key_executor_cancel_peer(p2p_peer_t *peer) {
    p2p_private_key_operation_t *operation;
    p2p_private_key_executor_t *executor;
    void (*request_cancel)(void *context) = NULL;
    void *provider_context = NULL;

    if (!peer || !peer->node) {
        return;
    }
    turbo_mutex_lock(&peer->node->mutex);
    operation = peer->private_key_operation;
    executor = peer->node->private_key_executor;
    if (operation) {
        atomic_store_explicit(&operation->cancel_requested, 1,
                              memory_order_release);
    }
    if (operation && executor) {
        request_cancel = executor->provider.request_cancel;
        provider_context = executor->provider.context;
    }
    turbo_mutex_unlock(&peer->node->mutex);
    if (request_cancel) {
        request_cancel(provider_context);
    }
}

void p2p_private_key_executor_pump(p2p_node_t *node) {
    p2p_private_key_executor_t *executor;
    p2p_private_key_operation_t *operation;
    int expected;

    if (!node || !node->private_key_executor) {
        return;
    }
    executor = node->private_key_executor;
    for (;;) {
        operation = NULL;
        turbo_mutex_lock(&node->mutex);
        for (operation = executor->operations; operation;
             operation = operation->next) {
            if (atomic_load_explicit(&operation->completed,
                                     memory_order_acquire) == 0) {
                continue;
            }
            expected = 0;
            if (atomic_compare_exchange_strong_explicit(
                    &operation->owner_claimed, &expected, 1,
                    memory_order_acq_rel, memory_order_acquire)) {
                break;
            }
        }
        turbo_mutex_unlock(&node->mutex);
        if (!operation) {
            break;
        }
        executor_finish_on_owner(operation);
    }
}

void p2p_private_key_executor_shutdown(
    p2p_private_key_executor_t *executor) {
    p2p_private_key_operation_t *operation;
    void (*request_cancel)(void *context);
    void *provider_context;
    int has_operations;

    if (!executor || !executor->pool) {
        return;
    }
    if (atomic_exchange_explicit(&executor->closing, 1,
                                 memory_order_acq_rel) != 0) {
        return;
    }
    turbo_mutex_lock(&executor->node->mutex);
    for (operation = executor->operations; operation;
         operation = operation->next) {
        atomic_store_explicit(&operation->cancel_requested, 1,
                              memory_order_release);
    }
    request_cancel = executor->provider.request_cancel;
    provider_context = executor->provider.context;
    has_operations = executor->operations != NULL;
    turbo_mutex_unlock(&executor->node->mutex);
    if (has_operations && request_cancel) {
        request_cancel(provider_context);
    }
    turbo_threadpool_shutdown(executor->pool);
    turbo_threadpool_wait(executor->pool);
    p2p_private_key_executor_pump(executor->node);
    turbo_threadpool_destroy(executor->pool);
    executor->pool = NULL;
}

void p2p_private_key_executor_destroy(
    p2p_private_key_executor_t *executor) {
    if (!executor) {
        return;
    }
    p2p_private_key_executor_shutdown(executor);
    p2p_crypto_wipe(&executor->provider, sizeof(executor->provider));
    free(executor);
}

int p2p_private_key_executor_is_closing(
    const p2p_private_key_executor_t *executor) {
    return !executor ||
           atomic_load_explicit(&executor->closing,
                                memory_order_acquire) != 0;
}
