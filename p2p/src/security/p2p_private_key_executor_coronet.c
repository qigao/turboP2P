#include "p2p_private_key_executor.h"
#include "../internal.h"
#include <CoroNet/turbo_coro_context.h>

static void executor_completion_post(void *arg1, void *arg2) {
    (void)arg2;
    /* The node outlives its context. A delayed wake consults its current
     * executor, never a replaced executor or a freed operation pointer. */
    p2p_private_key_executor_pump(arg1);
}

static int executor_notify(void *context) {
    p2p_node_t *node = context;
    return coro_post(node->ctx, executor_completion_post, node, NULL) == 0 ?
        P2P_OK : P2P_ERR_RESOURCE_EXHAUSTED;
}

p2p_private_key_executor_t *p2p_private_key_executor_create(
    p2p_node_t *node, const p2p_blocking_private_key_provider_v4_t *provider) {
    return p2p_private_key_executor_create_with_notify(node, provider, executor_notify);
}
