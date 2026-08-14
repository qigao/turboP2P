#ifndef TURBO_P2P_PRIVATE_KEY_EXECUTOR_H
#define TURBO_P2P_PRIVATE_KEY_EXECUTOR_H

#include "../crypto/p2p_crypto.h"

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

typedef struct p2p_node_s p2p_node_t;
typedef struct p2p_peer_s p2p_peer_t;
typedef struct turbo_threadpool_s turbo_threadpool_t;

enum {
    P2P_PRIVATE_KEY_WORKERS_DEFAULT = 1,
    P2P_PRIVATE_KEY_WORKERS_MAX = 4,
    P2P_PRIVATE_KEY_CAPACITY_DEFAULT = 64,
    P2P_PRIVATE_KEY_CAPACITY_MAX = 128,
    P2P_PRIVATE_KEY_TIMEOUT_DEFAULT_MS = 2000,
    P2P_PRIVATE_KEY_TIMEOUT_MAX_MS = 30000,
};

typedef struct p2p_private_key_executor_s p2p_private_key_executor_t;

typedef struct p2p_private_key_operation_s {
    p2p_private_key_executor_t *executor;
    p2p_node_t *node;
    p2p_peer_t *peer;
    p2p_noise_handshake_t *handshake;
    struct p2p_private_key_operation_s *next;
    uint64_t operation_id;
    uint64_t handshake_generation;
    uint64_t deadline_ms;
    uint8_t payload[P2P_SECURITY_CREDENTIAL_MAX];
    size_t payload_len;
    uint8_t output[P2P_SECURITY_HANDSHAKE_FRAME_MAX];
    size_t output_len;
    int result;
    uint8_t next_noise_step;
    uint8_t finish_noise;
    atomic_int cancel_requested;
    atomic_int completed;
    atomic_int owner_claimed;
    atomic_int references;
} p2p_private_key_operation_t;

struct p2p_private_key_executor_s {
    turbo_threadpool_t *pool;
    p2p_node_t *node;
    p2p_blocking_private_key_provider_v4_t provider;
    p2p_private_key_operation_t *operations;
    size_t active_operations;
    uint64_t next_operation_id;
    uint64_t submitted;
    uint64_t completed;
    uint64_t rejected;
    uint64_t timed_out;
    uint64_t cancelled;
    uint64_t completion_post_failures;
    uint16_t capacity;
    uint16_t workers;
    uint32_t operation_timeout_ms;
    atomic_int closing;
};

p2p_private_key_executor_t *p2p_private_key_executor_create(
    p2p_node_t *node,
    const p2p_blocking_private_key_provider_v4_t *provider);

int p2p_private_key_executor_submit(
    p2p_peer_t *peer,
    const uint8_t *payload,
    size_t payload_len,
    uint8_t next_noise_step,
    int finish_noise);

void p2p_private_key_executor_cancel_peer(p2p_peer_t *peer);
void p2p_private_key_executor_pump(p2p_node_t *node);
void p2p_private_key_executor_shutdown(
    p2p_private_key_executor_t *executor);
void p2p_private_key_executor_destroy(
    p2p_private_key_executor_t *executor);
int p2p_private_key_executor_is_closing(
    const p2p_private_key_executor_t *executor);

#endif
