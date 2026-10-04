#ifndef P2P_KEY_WORKER_H
#define P2P_KEY_WORKER_H

#include "../crypto/p2p_crypto.h"

enum {
    P2P_PRIVATE_KEY_WORKERS_DEFAULT = 1,
    P2P_PRIVATE_KEY_WORKERS_MAX = 4,
    P2P_PRIVATE_KEY_CAPACITY_DEFAULT = 64,
    P2P_PRIVATE_KEY_CAPACITY_MAX = 128,
    P2P_PRIVATE_KEY_TIMEOUT_DEFAULT_MS = 2000,
    P2P_PRIVATE_KEY_TIMEOUT_MAX_MS = 30000,
};

typedef struct p2p_key_worker_s p2p_key_worker_t;
typedef struct p2p_key_work_s p2p_key_work_t;
typedef struct {
    p2p_noise_handshake_t *handshake;
    uint64_t generation;
    uint64_t deadline_ms;
    int status;
    const uint8_t *output;
    size_t output_len;
} p2p_key_result_t;

typedef void (*p2p_key_complete_fn)(p2p_key_work_t *work,
    const p2p_key_result_t *result, void *context);
/* Optional wake notification, executed in pool callback context. It must not
 * drive/destroy the worker or access peer state. A notification failure is
 * counted but cannot lose a result; only owner poll consumes completions. */
typedef int (*p2p_key_notify_fn)(void *context);

/* Internal executor independent of node/network types. Provider/config copied;
 * provider and notification contexts must live through successful destroy.
 * A NULL notify explicitly selects polling (the CNet owner path). */
int p2p_key_worker_create(const p2p_blocking_private_key_provider_v4_t *provider,
    p2p_key_notify_fn notify, void *notify_context, p2p_key_worker_t **output);
/* Owner-thread submission. Retains a payload copy and exclusively borrows the
 * handshake until complete returns. Caller must retain its peer/handshake and
 * pause protocol receive. One outstanding work per handshake; total capacity
 * includes running, queued, and completed-but-unconsumed work. No inline done.
 * On failure no ownership is transferred and no completion is delivered. */
int p2p_key_worker_submit(p2p_key_worker_t *worker,
    p2p_noise_handshake_t *handshake, uint64_t generation,
    const uint8_t *payload, size_t payload_len,
    p2p_key_complete_fn complete, void *context, p2p_key_work_t **output);
/* Work token lives until its completion returns. Caller serializes cancellation
 * with completion/token release; cancellation is cooperative and never frees
 * a handshake still in use by the provider. Returns 1 only for a new cancel
 * request. An adapter may then invoke provider.request_cancel outside its
 * own peer lock; the token itself never calls application code. */
int p2p_key_work_cancel(p2p_key_work_t *work);
int p2p_key_work_ready(const p2p_key_work_t *work);
uint64_t p2p_key_work_deadline(const p2p_key_work_t *work);
/* One bounded owner pass. Callback output is borrowed only until return. Late
 * success (at or past the deadline), cancellation and shutdown discard output.
 * Completion is not a network send terminal and must not publish READY. */
int p2p_key_worker_poll(p2p_key_worker_t *worker);
/* Stop rejects admission, cancels pending/running work, joins provider calls,
 * then delivers remaining completions on this caller/owner thread. Providers
 * must obey the existing v4 deadline/cancel contract; no forced thread kill.
 * Poll/stop/destroy reentrancy from completion is rejected. */
int p2p_key_worker_stop(p2p_key_worker_t *worker);
int p2p_key_worker_destroy(p2p_key_worker_t *worker);
int p2p_key_worker_status(p2p_key_worker_t *worker,
    p2p_private_key_executor_status_v4_t *output);

#endif
