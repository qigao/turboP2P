/**
 * cleanup.c - Clean node destruction
 * Professional version using HASH_ITER and Kademlia DHT
 */

#include "../internal.h"
#include "node_state.h"
#include <tlog.h>
#include "../transfer/transfer.h"
#include "../security/p2p_private_key_executor.h"
#include <CoroNet/turbo_coro_context.h>
#include <stdlib.h>

/* =============================================================================
 * Individual Cleanup Functions
 * ============================================================================= */

void p2p_cleanup_callbacks(p2p_node_t *node) {
    if (!node) return;

    /* Clear callbacks to prevent re-entry during cleanup */
    node->on_peer_connected = NULL;
    node->on_peer_disconnected = NULL;
    node->on_message = NULL;
}

void p2p_cleanup_timers(p2p_node_t *node) {
    if (!node) return;

    if (node->gossip_timer) {
        turbo_timer_stop(node->gossip_timer);
        turbo_timer_destroy(node->gossip_timer);
        node->gossip_timer = NULL;
    }
}

void p2p_cleanup_server(p2p_node_t *node) {
    if (!node || !node->server) return;

    p2p_node_stop_server(node);
}

void p2p_cleanup_context(p2p_node_t *node) {
    int max_drain = 500;

    if (!node || !node->ctx) return;

    coro_context_stop(node->ctx);
    while (max_drain-- > 0 && coro_context_alive(node->ctx)) {
        coro_context_run(node->ctx, TURBO_RUN_NOWAIT);
        turbo_sleep_ms(1);
    }
    coro_context_destroy(node->ctx);
    node->ctx = NULL;
}

/* =============================================================================
 * Main Cleanup Orchestration
 * ============================================================================= */

void p2p_destroy_clean(p2p_node_t *node) {
    if (!node) return;
    if (node->runtime_v2) {
        TLOG_ERROR("[P2P] CNet nodes require p2p_destroy_v2 with checked retry");
        return;
    }
    p2p_cleanup_callbacks(node);
    p2p_cleanup_timers(node);
    p2p_cleanup_server(node);
    p2p_node_cleanup_cookie_gates(node);
    p2p_private_key_executor_shutdown(node->private_key_executor);
    p2p_cleanup_peers(node);
    p2p_cleanup_context(node);
    node->network_ops = NULL;
    if (p2p_node_state_destroy(node) != P2P_OK)
        TLOG_ERROR("[P2P] node destruction requires released transfer leases");
}
