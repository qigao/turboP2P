#ifndef TURBO_P2P_PRIVATE_KEY_EXECUTOR_H
#define TURBO_P2P_PRIVATE_KEY_EXECUTOR_H

#include "p2p_key_worker.h"
#include <stdatomic.h>

typedef struct p2p_node_s p2p_node_t;
typedef struct p2p_peer_s p2p_peer_t;
typedef struct p2p_private_key_executor_s p2p_private_key_executor_t;

typedef struct p2p_private_key_operation_s {
    p2p_private_key_executor_t *executor;
    p2p_node_t *node;
    p2p_peer_t *peer;
    p2p_key_work_t *work;
    p2p_noise_handshake_t *handshake;
    uint64_t handshake_generation;
    uint64_t deadline_ms;
    const uint8_t *output; /* Borrowed only during owner completion. */
    size_t output_len;
    int result;
    uint8_t next_noise_step;
    uint8_t finish_noise;
} p2p_private_key_operation_t;

/* Legacy node binding only. Worker owns all task/terminal state; the node owns
 * the peer lease, generation check and protocol continuation. CNet uses the
 * same worker with explicit owner polling and no CoroNet notification. */
struct p2p_private_key_executor_s {
    p2p_key_worker_t *worker;
    p2p_node_t *node;
    p2p_blocking_private_key_provider_v4_t provider;
    uint64_t rejected;
    uint32_t operation_timeout_ms;
    atomic_int closing;
};

p2p_private_key_executor_t *p2p_private_key_executor_create(
    p2p_node_t *node, const p2p_blocking_private_key_provider_v4_t *provider);
int p2p_private_key_executor_submit(p2p_peer_t *peer,
    const uint8_t *payload, size_t payload_len,
    uint8_t next_noise_step, int finish_noise);
void p2p_private_key_executor_cancel_peer(p2p_peer_t *peer);
void p2p_private_key_executor_pump(p2p_node_t *node);
void p2p_private_key_executor_shutdown(p2p_private_key_executor_t *executor);
void p2p_private_key_executor_destroy(p2p_private_key_executor_t *executor);
int p2p_private_key_executor_is_closing(const p2p_private_key_executor_t *executor);

#endif
