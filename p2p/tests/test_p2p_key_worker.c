#include <tinytest.h>
#include "security/p2p_key_worker.h"
#include "p2p_security_fixture.h"
#include <salts/clock.h>
#include <salts/thread.h>
#include <salts/thread_pool.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

enum { TEST_WAIT_MS = 3000 };
static SALTS_THREAD_LOCAL int on_owner;

typedef struct {
    uint8_t secret[32], public_key[32];
    atomic_int release, calls, finished, cancel_calls, notifications, notify_release;
    int error, ignore_cancel;
    uint32_t delay_ms;
} provider_t;

typedef struct {
    p2p_identity_t local, remote;
    p2p_noise_handshake_t writer, reader;
    p2p_key_worker_t *worker;
    p2p_key_work_t *work;
    uint64_t generation;
    int completions, status, stale, callback_on_owner, reentrant_poll, reentrant_destroy;
    size_t length;
    uint8_t bytes[P2P_SECURITY_HANDSHAKE_FRAME_MAX];
} peer_t;

static int public_key(void *context, uint8_t output[32]) {
    provider_t *provider = context;
    memcpy(output, provider->public_key, 32);
    return P2P_OK;
}

static int calculate(void *context, const uint8_t remote[32], uint64_t deadline,
    const p2p_private_key_cancel_v4_t *cancel, uint8_t output[32]) {
    provider_t *provider = context;
    uint64_t started = salts_monotonic_ms();
    int result;
    atomic_fetch_add(&provider->calls, 1);
    while (!atomic_load(&provider->release) || salts_monotonic_ms() - started < provider->delay_ms) {
        if (!provider->ignore_cancel && cancel->is_cancelled(cancel->context)) {
            atomic_fetch_add(&provider->finished, 1);
            return P2P_ERR_INVALID_STATE;
        }
        if (!provider->ignore_cancel && salts_monotonic_ms() >= deadline) {
            atomic_fetch_add(&provider->finished, 1);
            return P2P_ERR_TIMEOUT;
        }
        salts_sleep_ms(1);
    }
    result = provider->error ? provider->error : p2p_test_x25519(output, provider->secret, remote);
    atomic_fetch_add(&provider->finished, 1);
    return result;
}

static void request_cancel(void *context) {
    provider_t *provider = context;
    atomic_fetch_add(&provider->cancel_calls, 1);
}

static p2p_blocking_private_key_provider_v4_t make_provider(provider_t *context) {
    p2p_blocking_private_key_provider_v4_t provider = {0};
    context->secret[0] = 17;
    crypto_x25519_public_key(context->public_key, context->secret);
    atomic_init(&context->release, 0);
    atomic_init(&context->calls, 0);
    atomic_init(&context->finished, 0);
    atomic_init(&context->cancel_calls, 0);
    atomic_init(&context->notifications, 0);
    atomic_init(&context->notify_release, 0);
    provider.struct_size = sizeof(provider);
    provider.get_public_key = public_key;
    provider.calculate_x25519 = calculate;
    provider.request_cancel = request_cancel;
    provider.context = context;
    provider.executor_workers = 1;
    provider.executor_capacity = 2;
    provider.operation_timeout_ms = TEST_WAIT_MS;
    return provider;
}

static int failed_notify(void *context) {
    provider_t *provider = context;
    atomic_fetch_add(&provider->notifications, 1);
    return P2P_ERR_RESOURCE_EXHAUSTED;
}

static void prepare_peer(peer_t *peer, const p2p_blocking_private_key_provider_v4_t *provider,
    p2p_key_worker_t *worker) {
    uint8_t message[128];
    size_t length;
    provider_t *context = provider->context;
    peer->worker = worker;
    peer->generation = 1;
    check_equal(P2P_OK, p2p_crypto_identity_from_blocking_provider(&peer->local, provider, context->public_key));
    check_equal(P2P_OK, p2p_crypto_generate_identity(&peer->remote));
    check_equal(P2P_OK, p2p_noise_init_responder(&peer->writer, &peer->local));
    check_equal(P2P_OK, p2p_noise_init_initiator(&peer->reader, &peer->remote, NULL));
    check_equal(P2P_OK, p2p_noise_write_message(&peer->reader, message, &length, sizeof(message)));
    check_equal(P2P_OK, p2p_noise_read_message(&peer->writer, message, length));
}

static void complete(p2p_key_work_t *work, const p2p_key_result_t *result, void *context) {
    peer_t *peer = context;
    check_true(work == peer->work);
    peer->work = NULL;
    peer->completions++;
    peer->callback_on_owner = on_owner;
    peer->reentrant_poll = p2p_key_worker_poll(peer->worker);
    peer->reentrant_destroy = p2p_key_worker_destroy(peer->worker);
    if (peer->generation != result->generation) { peer->stale++; return; }
    peer->status = result->status;
    peer->length = result->output_len;
    if (peer->length) memcpy(peer->bytes, result->output, peer->length);
    else {
        uint8_t zero[P2P_SECURITY_HANDSHAKE_FRAME_MAX] = {0};
        check_equal(zero, result->output, sizeof(zero));
    }
}

static void submit(peer_t *peer, const void *payload, size_t length) {
    check_equal(P2P_OK, p2p_key_worker_submit(peer->worker, &peer->writer, peer->generation,
        payload, length, complete, peer, &peer->work));
}

static void wait_ready(peer_t *peer) {
    uint64_t deadline = salts_monotonic_ms() + TEST_WAIT_MS;
    while (!p2p_key_work_ready(peer->work) && salts_monotonic_ms() < deadline) salts_sleep_ms(1);
    check_true(p2p_key_work_ready(peer->work));
}

static void dispose_peer(peer_t *peer) {
    check_true(peer->work == NULL);
    p2p_noise_handshake_destroy(&peer->writer);
    p2p_noise_handshake_destroy(&peer->reader);
    p2p_crypto_wipe(peer, sizeof(*peer));
}

static void test_owner_completion(int notify_failure, int stale) {
    provider_t context = {0};
    p2p_blocking_private_key_provider_v4_t provider = make_provider(&context);
    p2p_key_worker_t *worker = NULL;
    p2p_private_key_executor_status_v4_t status;
    peer_t peer = {0};
    uint8_t payload[] = "credential bytes";
    uint8_t decoded[64];
    size_t length;
    check_equal(P2P_OK, p2p_key_worker_create(&provider,
        notify_failure ? failed_notify : NULL, &context, &worker));
    prepare_peer(&peer, &provider, worker);
    submit(&peer, payload, sizeof(payload));
    memset(payload, 0xa5, sizeof(payload));
    check_equal(0, peer.completions);
    atomic_store(&context.release, 1);
    wait_ready(&peer);
    check_equal(0, peer.completions);
    if (stale) peer.generation++;
    check_equal(P2P_OK, p2p_key_worker_poll(worker));
    check_equal(1, peer.completions);
    check_equal(1, peer.callback_on_owner);
    check_equal(P2P_ERR_INVALID_STATE, peer.reentrant_poll);
    check_equal(P2P_ERR_INVALID_STATE, peer.reentrant_destroy);
    if (stale) {
        check_equal(1, peer.stale);
        check_equal((size_t)0, peer.length);
    } else {
        check_equal(P2P_OK, peer.status);
        check_equal(P2P_OK, p2p_noise_read_message_with_payload(&peer.reader,
            peer.bytes, peer.length, decoded, sizeof(decoded), &length));
        check_equal(sizeof(payload), length);
        check_equal("credential bytes", decoded, length);
    }
    check_equal(P2P_OK, p2p_key_worker_stop(worker));
    check_equal(P2P_OK, p2p_key_worker_status(worker, &status));
    check_equal((uint64_t)(notify_failure ? 1 : 0), status.completion_post_failures);
    check_equal((uint64_t)1, status.completed);
    check_equal((size_t)0, status.active_operations);
    check_equal(P2P_OK, p2p_key_worker_poll(worker));
    check_equal(1, peer.completions);
    check_equal(P2P_OK, p2p_key_worker_destroy(worker));
    dispose_peer(&peer);
}

static void test_capacity(void) {
    enum { CAPACITY = P2P_PRIVATE_KEY_CAPACITY_DEFAULT };
    provider_t context = {0};
    p2p_blocking_private_key_provider_v4_t provider = make_provider(&context);
    p2p_key_worker_t *worker = NULL;
    p2p_private_key_executor_status_v4_t status;
    peer_t *peers = calloc(CAPACITY + 1, sizeof(*peers));
    p2p_key_work_t *rejected_work = NULL;
    provider.executor_capacity = CAPACITY;
    check_not_null(peers);
    check_equal(P2P_OK, p2p_key_worker_create(&provider, NULL, NULL, &worker));
    for (size_t i = 0; i <= CAPACITY; ++i) prepare_peer(&peers[i], &provider, worker);
    for (size_t i = 0; i < CAPACITY; ++i) submit(&peers[i], NULL, 0);
    check_equal(P2P_ERR_RESOURCE_EXHAUSTED, p2p_key_worker_submit(worker,
        &peers[CAPACITY].writer, 1, NULL, 0, complete, &peers[CAPACITY], &rejected_work));
    check_true(rejected_work == NULL);
    atomic_store(&context.release, 1);
    for (size_t i = 0; i < CAPACITY; ++i) wait_ready(&peers[i]);
    check_equal(P2P_ERR_RESOURCE_EXHAUSTED, p2p_key_worker_submit(worker,
        &peers[CAPACITY].writer, 1, NULL, 0, complete, &peers[CAPACITY], &rejected_work));
    check_equal(P2P_OK, p2p_key_worker_status(worker, &status));
    check_equal((size_t)CAPACITY, status.active_operations);
    check_equal((uint64_t)2, status.rejected);
    check_equal(P2P_OK, p2p_key_worker_poll(worker));
    submit(&peers[CAPACITY], NULL, 0);
    wait_ready(&peers[CAPACITY]);
    check_equal(P2P_OK, p2p_key_worker_poll(worker));
    check_equal(P2P_OK, p2p_key_worker_destroy(worker));
    for (size_t i = 0; i <= CAPACITY; ++i) { check_equal(1, peers[i].completions); dispose_peer(&peers[i]); }
    free(peers);
}

static void test_failure(int reason) {
    provider_t context = {0};
    p2p_blocking_private_key_provider_v4_t provider = make_provider(&context);
    p2p_key_worker_t *worker = NULL;
    peer_t peer = {0};
    int expected = reason == 0 ? P2P_ERR_CRYPTO : reason == 1 ? P2P_ERR_INVALID_STATE : P2P_ERR_TIMEOUT;
    provider.operation_timeout_ms = 50;
    context.error = reason == 0 ? P2P_ERR_CRYPTO : 0;
    context.ignore_cancel = reason == 3;
    context.delay_ms = reason == 3 ? 70 : 0;
    check_equal(P2P_OK, p2p_key_worker_create(&provider, NULL, NULL, &worker));
    prepare_peer(&peer, &provider, worker);
    submit(&peer, NULL, 0);
    if (reason == 1) { check_equal(1, p2p_key_work_cancel(peer.work)); check_equal(0, p2p_key_work_cancel(peer.work)); }
    atomic_store(&context.release, 1);
    wait_ready(&peer);
    if (reason == 2) {
        uint64_t deadline = p2p_key_work_deadline(peer.work);
        while (salts_monotonic_ms() < deadline) salts_sleep_ms(1);
    }
    check_equal(P2P_OK, p2p_key_worker_poll(worker));
    check_equal(expected, peer.status);
    check_equal((size_t)0, peer.length);
    check_equal(1, peer.completions);
    check_equal(P2P_OK, p2p_key_worker_destroy(worker));
    dispose_peer(&peer);
}

static void test_stop_queued(void) {
    provider_t context = {0};
    p2p_blocking_private_key_provider_v4_t provider = make_provider(&context);
    p2p_key_worker_t *worker = NULL;
    p2p_private_key_executor_status_v4_t status;
    peer_t first = {0}, second = {0};
    uint64_t deadline;
    check_equal(P2P_OK, p2p_key_worker_create(&provider, NULL, NULL, &worker));
    prepare_peer(&first, &provider, worker);
    prepare_peer(&second, &provider, worker);
    submit(&first, NULL, 0);
    deadline = salts_monotonic_ms() + TEST_WAIT_MS;
    while (!atomic_load(&context.calls) && salts_monotonic_ms() < deadline) salts_sleep_ms(1);
    check_equal(1, atomic_load(&context.calls));
    submit(&second, NULL, 0);
    check_equal(P2P_OK, p2p_key_worker_stop(worker));
    check_equal(P2P_OK, p2p_key_worker_stop(worker));
    check_equal(1, atomic_load(&context.calls));
    check_equal(1, atomic_load(&context.cancel_calls));
    check_equal(1, first.completions);
    check_equal(1, second.completions);
    check_equal(P2P_ERR_INVALID_STATE, first.status);
    check_equal(P2P_ERR_INVALID_STATE, second.status);
    check_equal(P2P_OK, p2p_key_worker_status(worker, &status));
    check_equal((uint64_t)2, status.cancelled);
    check_equal((size_t)0, status.active_operations);
    check_equal(0, status.accepting);
    check_equal(P2P_ERR_INVALID_STATE, p2p_key_worker_submit(worker,
        &first.writer, 2, NULL, 0, complete, &first, &first.work));
    check_equal(P2P_OK, p2p_key_worker_destroy(worker));
    dispose_peer(&first);
    dispose_peer(&second);
}

static int blocked_notify(void *context) {
    provider_t *provider = context;
    atomic_fetch_add(&provider->notifications, 1);
    while (!atomic_load(&provider->notify_release)) salts_sleep_ms(1);
    return P2P_ERR_RESOURCE_EXHAUSTED;
}

static void test_owner_finishes_before_notifier(void) {
    provider_t context = {0};
    p2p_blocking_private_key_provider_v4_t provider = make_provider(&context);
    p2p_key_worker_t *worker = NULL;
    p2p_private_key_executor_status_v4_t status;
    peer_t peer = {0};
    uint64_t deadline;
    check_equal(P2P_OK, p2p_key_worker_create(&provider, blocked_notify, &context, &worker));
    prepare_peer(&peer, &provider, worker);
    submit(&peer, NULL, 0);
    atomic_store(&context.release, 1);
    deadline = salts_monotonic_ms() + TEST_WAIT_MS;
    while (!atomic_load(&context.notifications) && salts_monotonic_ms() < deadline) salts_sleep_ms(1);
    check_equal(1, atomic_load(&context.notifications));
    check_equal(P2P_OK, p2p_key_worker_poll(worker));
    check_equal(1, peer.completions);
    /* Free owner context and handshake while the pool terminal still borrows
     * work: only the pool reference may release the final work allocation. */
    dispose_peer(&peer);
    atomic_store(&context.notify_release, 1);
    check_equal(P2P_OK, p2p_key_worker_stop(worker));
    check_equal(P2P_OK, p2p_key_worker_status(worker, &status));
    check_equal((uint64_t)1, status.completion_post_failures);
    check_equal((uint64_t)1, status.completed);
    check_equal(P2P_OK, p2p_key_worker_destroy(worker));
}

static void test_queued_deadline(void) {
    provider_t context = {0};
    p2p_blocking_private_key_provider_v4_t provider = make_provider(&context);
    p2p_key_worker_t *worker = NULL;
    peer_t first = {0}, queued = {0};
    provider.operation_timeout_ms = 50;
    check_equal(P2P_OK, p2p_key_worker_create(&provider, NULL, NULL, &worker));
    prepare_peer(&first, &provider, worker);
    prepare_peer(&queued, &provider, worker);
    submit(&first, NULL, 0);
    submit(&queued, NULL, 0);
    wait_ready(&first);
    wait_ready(&queued);
    check_equal(P2P_OK, p2p_key_worker_poll(worker));
    check_equal(P2P_ERR_TIMEOUT, first.status);
    check_equal(P2P_ERR_TIMEOUT, queued.status);
    check_equal(P2P_OK, p2p_key_worker_destroy(worker));
    dispose_peer(&first);
    dispose_peer(&queued);
}

static void test_invalid_and_duplicate(void) {
    provider_t context = {0};
    p2p_blocking_private_key_provider_v4_t provider = make_provider(&context);
    p2p_blocking_private_key_provider_v4_t invalid = provider;
    p2p_key_worker_t *worker = NULL;
    p2p_key_work_t *extra = NULL;
    peer_t peer = {0};
    invalid.executor_workers = P2P_PRIVATE_KEY_WORKERS_MAX + 1;
    check_equal(P2P_ERR_INVALID_ARG, p2p_key_worker_create(&invalid, NULL, NULL, &worker));
    check_true(worker == NULL);
    check_equal(P2P_OK, p2p_key_worker_create(&provider, NULL, NULL, &worker));
    prepare_peer(&peer, &provider, worker);
    check_equal(P2P_ERR_INVALID_ARG, p2p_key_worker_submit(worker,
        &peer.writer, 0, NULL, 0, complete, &peer, &extra));
    check_equal(P2P_ERR_INVALID_ARG, p2p_key_worker_submit(worker,
        &peer.writer, 1, "x", P2P_SECURITY_CREDENTIAL_MAX + 1, complete, &peer, &extra));
    peer.writer.blocking_provider.context = NULL;
    check_equal(P2P_ERR_INVALID_ARG, p2p_key_worker_submit(worker,
        &peer.writer, 1, NULL, 0, complete, &peer, &extra));
    peer.writer.blocking_provider.context = &context;
    submit(&peer, NULL, 0);
    check_equal(P2P_ERR_INVALID_STATE, p2p_key_worker_submit(worker,
        &peer.writer, 2, NULL, 0, complete, &peer, &extra));
    check_true(extra == NULL);
    check_equal(P2P_OK, p2p_key_worker_stop(worker));
    check_equal(1, peer.completions);
    check_equal(P2P_OK, p2p_key_worker_destroy(worker));
    dispose_peer(&peer);
}

#ifdef P2P_KEY_WORKER_TEST_WRAP
static int reject_submit;
int __real_salts_threadpool_try_submit_task(salts_threadpool_t *, const salts_threadpool_task_t *);
int __wrap_salts_threadpool_try_submit_task(salts_threadpool_t *pool, const salts_threadpool_task_t *task) {
    if (reject_submit) { reject_submit = 0; return SALTS_ENOBUFS; }
    return __real_salts_threadpool_try_submit_task(pool, task);
}
static void test_pool_rejection(void) {
    provider_t context = {0};
    p2p_blocking_private_key_provider_v4_t provider = make_provider(&context);
    p2p_key_worker_t *worker = NULL;
    p2p_private_key_executor_status_v4_t status;
    peer_t peer = {0};
    check_equal(P2P_OK, p2p_key_worker_create(&provider, NULL, NULL, &worker));
    prepare_peer(&peer, &provider, worker);
    reject_submit = 1;
    check_equal(P2P_ERR_RESOURCE_EXHAUSTED, p2p_key_worker_submit(worker,
        &peer.writer, 1, NULL, 0, complete, &peer, &peer.work));
    check_true(peer.work == NULL);
    check_equal(P2P_OK, p2p_key_worker_status(worker, &status));
    check_equal((size_t)0, status.active_operations);
    check_equal((uint64_t)0, status.submitted);
    check_equal((uint64_t)1, status.rejected);
    check_equal(0, peer.completions);
    submit(&peer, NULL, 0);
    atomic_store(&context.release, 1);
    wait_ready(&peer);
    check_equal(P2P_OK, p2p_key_worker_poll(worker));
    check_equal(P2P_OK, p2p_key_worker_destroy(worker));
    dispose_peer(&peer);
}
#endif

spec("P2P owner-polled private-key worker") {
    on_owner = 1;
    it("copies credentials and completes exactly once on its owner") { test_owner_completion(0, 0); }
    it("retains a result independently of a failed wake notification") { test_owner_completion(1, 0); }
    it("returns generation identity without touching a replacement peer") { test_owner_completion(0, 1); }
    it("counts queued, running and unconsumed results at the 64/65 boundary") { test_capacity(); }
    it("discards provider error output") { test_failure(0); }
    it("cancels without allowing a late success") { test_failure(1); }
    it("rejects success consumed at or after its deadline") { test_failure(2); }
    it("rejects a provider returning after the deadline") { test_failure(3); }
    it("joins running calls and cancels queued calls before handshake release") { test_stop_queued(); }
    it("keeps the pool terminal alive after owner context is released") { test_owner_finishes_before_notifier(); }
    it("includes queue residence in the provider deadline") { test_queued_deadline(); }
    it("rejects invalid limits, mismatched providers and duplicate handshakes") { test_invalid_and_duplicate(); }
#ifdef P2P_KEY_WORKER_TEST_WRAP
    it("rolls back a pool rejection without an orphan terminal or lost slot") { test_pool_rejection(); }
#endif
}
