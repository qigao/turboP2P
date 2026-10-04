#include "p2p_private_key_executor.h"
#include "../core/peer.h"
#include "../internal.h"
#include <stdlib.h>

static void executor_complete(p2p_key_work_t *work,
    const p2p_key_result_t *result, void *context) {
    p2p_private_key_operation_t *operation = context;
    p2p_peer_t *peer = operation->peer;
    p2p_node_t *node = operation->node;
    int was_current = 0;
    salts_mutex_lock(&node->mutex);
    if (peer->private_key_operation == operation && operation->work == work) {
        peer->private_key_operation = NULL;
        was_current = 1;
    }
    operation->result = result->status;
    operation->output = result->output;
    operation->output_len = result->output_len;
    salts_mutex_unlock(&node->mutex);
    p2p_peer_complete_private_key_operation(operation, was_current);
    p2p_peer_release(peer);
    p2p_crypto_wipe(operation, sizeof(*operation));
    free(operation);
}

p2p_private_key_executor_t *p2p_private_key_executor_create_with_notify(
    p2p_node_t *node, const p2p_blocking_private_key_provider_v4_t *provider,
    p2p_key_notify_fn notify) {
    p2p_private_key_executor_t *executor;
    p2p_private_key_executor_status_v4_t status;
    if (!node) return NULL;
    executor = calloc(1, sizeof(*executor));
    if (!executor) return NULL;
    if (p2p_key_worker_create(provider, notify, node, &executor->worker) != P2P_OK) {
        free(executor);
        return NULL;
    }
    executor->node = node;
    executor->provider = *provider;
    p2p_key_worker_status(executor->worker, &status);
    executor->operation_timeout_ms = status.operation_timeout_ms;
    atomic_init(&executor->closing, 0);
    return executor;
}

int p2p_private_key_executor_submit(p2p_peer_t *peer,
    const uint8_t *payload, size_t payload_len,
    uint8_t next_noise_step, int finish_noise) {
    p2p_private_key_executor_t *executor;
    p2p_private_key_operation_t *operation;
    p2p_node_t *node;
    int result;
    if (!peer || !peer->node || !peer->handshake || (!payload && payload_len) ||
        payload_len > P2P_SECURITY_CREDENTIAL_MAX) return P2P_ERR_INVALID_ARG;
    node = peer->node;
    executor = node->private_key_executor;
    if (p2p_private_key_executor_is_closing(executor)) return P2P_ERR_INVALID_STATE;
    operation = calloc(1, sizeof(*operation));
    if (!operation) return P2P_ERR_NO_MEM;
    salts_mutex_lock(&node->mutex);
    if (p2p_private_key_executor_is_closing(executor) ||
        peer->private_key_operation || !p2p_peer_hold_locked(peer)) {
        executor->rejected++;
        salts_mutex_unlock(&node->mutex);
        free(operation);
        return P2P_ERR_RESOURCE_EXHAUSTED;
    }
    operation->executor = executor;
    operation->node = node;
    operation->peer = peer;
    operation->handshake = peer->handshake;
    operation->handshake_generation = peer->handshake_generation;
    operation->next_noise_step = next_noise_step;
    operation->finish_noise = finish_noise != 0;
    result = p2p_key_worker_submit(executor->worker, operation->handshake,
        operation->handshake_generation, payload, payload_len,
        executor_complete, operation, &operation->work);
    if (result == P2P_OK) {
        operation->deadline_ms = p2p_key_work_deadline(operation->work);
        peer->private_key_operation = operation;
    }
    salts_mutex_unlock(&node->mutex);
    if (result != P2P_OK) {
        p2p_peer_release(peer);
        p2p_crypto_wipe(operation, sizeof(*operation));
        free(operation);
    }
    return result;
}

void p2p_private_key_executor_cancel_peer(p2p_peer_t *peer) {
    void (*request_cancel)(void *) = NULL;
    void *context = NULL;
    if (!peer || !peer->node) return;
    salts_mutex_lock(&peer->node->mutex);
    if (peer->private_key_operation && p2p_key_work_cancel(peer->private_key_operation->work)) {
        request_cancel = peer->private_key_operation->executor->provider.request_cancel;
        context = peer->private_key_operation->executor->provider.context;
    }
    salts_mutex_unlock(&peer->node->mutex);
    if (request_cancel) request_cancel(context);
}

void p2p_private_key_executor_pump(p2p_node_t *node) {
    if (node && node->private_key_executor)
        p2p_key_worker_poll(node->private_key_executor->worker);
}

void p2p_private_key_executor_shutdown(p2p_private_key_executor_t *executor) {
    if (!executor) return;
    atomic_store_explicit(&executor->closing, 1, memory_order_release);
    p2p_key_worker_stop(executor->worker);
}

void p2p_private_key_executor_destroy(p2p_private_key_executor_t *executor) {
    if (!executor) return;
    atomic_store_explicit(&executor->closing, 1, memory_order_release);
    /* As with owner destruction, lifecycle callbacks may not synchronously
     * destroy their current executor. Retain storage on a rejected drain. */
    if (p2p_key_worker_destroy(executor->worker) != P2P_OK) return;
    p2p_crypto_wipe(executor, sizeof(*executor));
    free(executor);
}

int p2p_private_key_executor_is_closing(const p2p_private_key_executor_t *executor) {
    return !executor || atomic_load_explicit(&executor->closing, memory_order_acquire);
}
