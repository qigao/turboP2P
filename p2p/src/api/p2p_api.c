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

static int p2p_send_dht_store_to_peer(p2p_peer_t *peer,
                                      const kad_id_t *key,
                                      const void *data,
                                      size_t len) {
    p2p_message_t *msg = NULL;
    int ret = 0;

    if (!peer || !peer->is_connected || !key || !data || len == 0 ||
        len > sizeof(((p2p_dht_store_payload_t *)0)->data)) {
        return 0;
    }

    msg = (p2p_message_t *)calloc(1, sizeof(p2p_message_t));
    if (!msg) {
        return 0;
    }

    p2p_message_init(msg, P2P_MSG_DHT_PUT);
    memcpy(msg->payload.dht_store.key, key->bytes, KADEMLIA_ID_BYTES);
    msg->payload.dht_store.data_len = (uint16_t)len;
    memcpy(msg->payload.dht_store.data, data, len);
    msg->header.payload_len =
        (uint16_t)(offsetof(p2p_dht_store_payload_t, data) + len);

    ret = (p2p_peer_send(peer, msg) == P2P_OK) ? 1 : 0;
    free(msg);
    return ret;
}

static int p2p_send_dht_store_to_connected_peers(p2p_node_t *node,
                                                 const kad_id_t *key,
                                                 const void *data,
                                                 size_t len) {
    p2p_peer_t **peers = NULL;
    size_t count = 0;
    int sent = 0;

    if (!node || !key || !data || len == 0 || len > sizeof(((p2p_dht_store_payload_t *)0)->data)) {
        return 0;
    }

    peers = p2p_node_snapshot_connected_peers(node, &count);
    if (count > 0 && !peers) {
        return 0;
    }

    for (size_t i = 0; i < count; i++) {
        if (peers[i]) {
            sent += p2p_send_dht_store_to_peer(peers[i], key, data, len);
            p2p_peer_release(peers[i]);
        }
    }
    free(peers);

    return sent;
}

static int p2p_send_dht_store_to_lookup_candidates(p2p_node_t *node,
                                                   const p2p_dht_lookup_t *lookup,
                                                   const kad_id_t *key,
                                                   const void *data,
                                                   size_t len) {
    p2p_peer_t **peers = NULL;
    size_t count = 0;
    int sent = 0;

    if (!node || !lookup || !key || !data || len == 0) {
        return 0;
    }

    salts_mutex_lock(&node->mutex);
    if (lookup->candidate_count > 0) {
        peers = (p2p_peer_t **)calloc((size_t)lookup->candidate_count, sizeof(*peers));
    }
    if (lookup->candidate_count > 0 && !peers) {
        salts_mutex_unlock(&node->mutex);
        return 0;
    }

    for (int i = 0; i < lookup->candidate_count; i++) {
        p2p_peer_t *peer = p2p_node_find_peer_by_endpoint_locked(node,
                                                                 lookup->candidates[i].ip,
                                                                 lookup->candidates[i].port);
        if (!peer) {
            continue;
        }
        if (!p2p_peer_hold_locked(peer)) {
            continue;
        }
        peers[count++] = peer;
    }
    salts_mutex_unlock(&node->mutex);

    for (size_t i = 0; i < count; i++) {
        if (peers[i]) {
            sent += p2p_send_dht_store_to_peer(peers[i], key, data, len);
            p2p_peer_release(peers[i]);
        }
    }
    free(peers);

    return sent;
}

typedef struct {
    p2p_node_t *node;
    kad_id_t key;
    size_t len;
    uint8_t data[sizeof(((p2p_dht_store_payload_t *)0)->data)];
} p2p_pending_put_t;

static void p2p_dht_put_lookup_complete(void *result, void *user_data) {
    p2p_pending_put_t *put = (p2p_pending_put_t *)user_data;
    p2p_dht_lookup_t *lookup = (p2p_dht_lookup_t *)result;

    if (!lookup || !put || !put->node) {
        return;
    }

    (void)p2p_send_dht_store_to_lookup_candidates(put->node, lookup, &put->key,
                                                  put->data, put->len);
}

static int p2p_try_get_local_dht_value(p2p_node_t *node,
                                       const kad_id_t *key,
                                       void *buf,
                                       size_t *buf_len) {
    int found = -1;

    if (!node || !key || !buf || !buf_len) {
        return P2P_ERR_INVALID_ARG;
    }

    salts_mutex_lock(&node->mutex);
    found = kademlia_find_value(node->kad_dht, key, buf, buf_len);
    salts_mutex_unlock(&node->mutex);

    return (found == 0) ? P2P_OK : P2P_ERR_NOT_FOUND;
}

static int p2p_dht_lookup_is_active(p2p_node_t *node, uint32_t request_id) {
    int active = 0;

    if (!node) {
        return 0;
    }

    salts_mutex_lock(&node->mutex);
    active = p2p_dht_lookup_find(node, request_id) != NULL;
    salts_mutex_unlock(&node->mutex);

    return active;
}

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
 * DHT API
 * ============================================================================= */

int p2p_dht_put(p2p_node_t *node, const char *key, const void *data, size_t len) {
    int ret = P2P_OK;
    p2p_pending_put_t *pending = NULL;
    p2p_dht_lookup_t *lookup = NULL;
    kad_id_t kkey;

    if (!node || !key || !data) return P2P_ERR_INVALID_ARG;
    if (len == 0 || len > sizeof(((p2p_dht_store_payload_t *)0)->data)) {
        return P2P_ERR_INVALID_ARG;
    }

    kad_id_from_data(key, strlen(key), &kkey);
    salts_mutex_lock(&node->mutex);

    /* Store locally first */
    kademlia_store(node->kad_dht, &kkey, data, len);
    salts_mutex_unlock(&node->mutex);
    (void)p2p_send_dht_store_to_connected_peers(node, &kkey, data, len);

    /* Professional Kademlia:
     * 1. Start iterative FIND_NODE for the key
     * 2. When closest nodes are found, send P2P_MSG_DHT_PUT to them.
     */

    /* For now, just start iterative lookup for the neighborhood */
    lookup = p2p_dht_lookup_start(node, kkey.bytes, P2P_MSG_DHT_FIND_NODE);
    if (lookup) {
        pending = (p2p_pending_put_t *)calloc(1, sizeof(p2p_pending_put_t));
        if (pending) {
            pending->node = node;
            pending->key = kkey;
            pending->len = len;
            memcpy(pending->data, data, len);
            lookup->callback = p2p_dht_put_lookup_complete;
            lookup->cleanup = free;
            lookup->user_data = pending;
        } else {
            p2p_dht_lookup_finish(node, lookup);
            ret = P2P_ERR_NO_MEM;
        }
    } else {
        ret = P2P_OK;
    }
    return ret;
}

int p2p_dht_put_cached(p2p_node_t *node, const char *key, const void *data, size_t len) {
    kad_id_t kkey;

    if (!node || !key || !data) return P2P_ERR_INVALID_ARG;
    if (len == 0 || len > sizeof(((p2p_dht_store_payload_t *)0)->data)) {
        return P2P_ERR_INVALID_ARG;
    }

    kad_id_from_data(key, strlen(key), &kkey);
    salts_mutex_lock(&node->mutex);
    kademlia_store(node->kad_dht, &kkey, data, len);
    salts_mutex_unlock(&node->mutex);

    (void)p2p_send_dht_store_to_connected_peers(node, &kkey, data, len);
    return P2P_OK;
}

int p2p_dht_get(p2p_node_t *node, const char *key, void *buf, size_t *buf_len) {
    uint64_t deadline_ms = 0;
    int ret = 0;
    p2p_dht_lookup_t *lookup = NULL;
    uint32_t request_id = 0;
    kad_id_t kkey;

    if (!node || !key || !buf || !buf_len) return P2P_ERR_INVALID_ARG;

    kad_id_from_data(key, strlen(key), &kkey);
    if (p2p_try_get_local_dht_value(node, &kkey, buf, buf_len) == P2P_OK) {
        return P2P_OK;
    }

    /* Professional Kademlia:
     * 1. Start iterative FIND_VALUE for the key
     * 2. This will return either the value or closer nodes.
     */
    /*
     * This API is synchronous from the caller's point of view: P2P_OK means
     * buf contains a value right now. We can still kick off an async lookup as
     * a side effect, but we must not claim success until a value is present.
     */
    lookup = p2p_dht_lookup_start(node, kkey.bytes, P2P_MSG_DHT_GET);
    if (lookup) {
        request_id = lookup->request_id;
        ret = P2P_OK;
    } else {
        ret = P2P_ERR_NOT_FOUND;
    }
    if (ret != P2P_OK) {
        return ret;
    }

    deadline_ms = (turbo_hrtime() / 1000000) + P2P_DHT_GET_TIMEOUT_MS;
    while ((turbo_hrtime() / 1000000) < deadline_ms) {
        coro_context_run(node->ctx, TURBO_RUN_NOWAIT);

        if (p2p_try_get_local_dht_value(node, &kkey, buf, buf_len) == P2P_OK) {
            return P2P_OK;
        }
        if (!p2p_dht_lookup_is_active(node, request_id)) {
            return P2P_ERR_NOT_FOUND;
        }

        turbo_sleep_ms(10);
    }

    if (p2p_try_get_local_dht_value(node, &kkey, buf, buf_len) == P2P_OK) {
        return P2P_OK;
    }
    return P2P_ERR_NOT_FOUND;
}

int p2p_dht_get_cached(p2p_node_t *node, const char *key, void *buf, size_t *buf_len) {
    kad_id_t kkey;

    if (!node || !key || !buf || !buf_len) {
        return P2P_ERR_INVALID_ARG;
    }

    kad_id_from_data(key, strlen(key), &kkey);
    return p2p_try_get_local_dht_value(node, &kkey, buf, buf_len);
}

size_t p2p_dht_get_entry_count(p2p_node_t *node) {
    size_t count = 0;

    if (!node) {
        return 0;
    }

    salts_mutex_lock(&node->mutex);
    count = kademlia_storage_count(node->kad_dht);
    salts_mutex_unlock(&node->mutex);
    return count;
}

/* =============================================================================
 * Peer Information
 * ============================================================================= */

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
