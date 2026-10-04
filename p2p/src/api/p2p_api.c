/**
 * p2p_api.c - P2P Public API implementation
 * Implements the professional interface defined in p2p.h
 */

#include "p2p.h"
#include "../internal.h"
#include "../core/node.h"
#include <CoroNet/turbo_coro_context.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <time.h>

/* =============================================================================
 * Node Lifecycle
 * ============================================================================= */

p2p_node_t *p2p_create(const char *ip, int port) {
    return p2p_node_create(ip, port);
}

void p2p_destroy(p2p_node_t *node) {
    if (!node) return;

    /* Use professional cleanup orchestration */
    p2p_destroy_clean(node);
}

int p2p_start(p2p_node_t *node) {
    int ret = 0;

    if (!node) return P2P_ERR_INVALID_ARG;

    ret = p2p_node_start_server(node);
    if (ret != P2P_OK) {
        return ret;
    }

    p2p_gossip_start(node);

    /* Event loop blocking run */
    coro_context_run(node->ctx, TURBO_RUN_DEFAULT);

    return P2P_OK;
}

int p2p_start_nonblocking(p2p_node_t *node) {
    int ret = 0;

    if (!node) return P2P_ERR_INVALID_ARG;

    ret = p2p_node_start_server(node);
    if (ret != P2P_OK) {
        return ret;
    }

    p2p_gossip_start(node);
    return P2P_OK;
}

coro_context_t *p2p_get_loop(p2p_node_t *node) {
    return node ? node->ctx : NULL;
}

/* =============================================================================
 * Pub/Sub implementation
 * ============================================================================= */

int p2p_subscribe(p2p_node_t *node, const char *topic) {
    p2p_message_t *msg = NULL;

    if (!node || !topic) return P2P_ERR_INVALID_ARG;
    if (!p2p_topic_find_or_create(node, topic)) {
        return P2P_ERR_NO_MEM;
    }

    msg = (p2p_message_t *)calloc(1, sizeof(p2p_message_t));
    if (!msg) {
        return P2P_ERR_NO_MEM;
    }

    p2p_message_init(msg, P2P_MSG_PUBSUB_SUB);
    /* Payload setup would go here */
    p2p_node_broadcast(node, msg);
    free(msg);
    return P2P_OK;
}

int p2p_unsubscribe(p2p_node_t *node, const char *topic) {
    p2p_message_t *msg = NULL;
    int ret = P2P_OK;

    if (!node || !topic) return P2P_ERR_INVALID_ARG;
    ret = p2p_node_remove_topic(node, topic);
    if (ret != P2P_OK) {
        return ret;
    }

    msg = (p2p_message_t *)calloc(1, sizeof(p2p_message_t));
    if (!msg) {
        return P2P_ERR_NO_MEM;
    }

    p2p_message_init(msg, P2P_MSG_PUBSUB_UNSUB);
    p2p_node_broadcast(node, msg);
    free(msg);
    return P2P_OK;
}

int p2p_publish(p2p_node_t *node, const char *topic, const void *data, size_t len) {
    p2p_message_t *msg = NULL;

    if (!node || !topic || !data || len == 0) return P2P_ERR_INVALID;

    if (!p2p_topic_exists(node, topic)) {
        return P2P_ERR_NOT_FOUND;
    }

    msg = (p2p_message_t *)calloc(1, sizeof(p2p_message_t));
    if (!msg) {
        return P2P_ERR_NO_MEM;
    }

    p2p_message_init(msg, P2P_MSG_PUBSUB_PUBLISH);
    p2p_node_broadcast(node, msg);
    free(msg);
    return P2P_OK;
}
