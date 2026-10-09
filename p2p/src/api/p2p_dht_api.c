#include "p2p.h"
#include "../internal.h"
#include "../core/node_network.h"
#include <salts/clock.h>
#include <salts/thread.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

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

    cmeta_mutex_lock(&node->mutex);
    if (lookup->candidate_count > 0) {
        peers = (p2p_peer_t **)calloc((size_t)lookup->candidate_count, sizeof(*peers));
    }
    if (lookup->candidate_count > 0 && !peers) {
        cmeta_mutex_unlock(&node->mutex);
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
    cmeta_mutex_unlock(&node->mutex);

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
    size_t capacity;

    if (!node || !key || !buf || !buf_len) {
        return P2P_ERR_INVALID_ARG;
    }

    capacity = *buf_len;
    cmeta_mutex_lock(&node->mutex);
    found = kademlia_find_value(node->kad_dht, key, buf, buf_len);
    cmeta_mutex_unlock(&node->mutex);

    if (found != 0 && *buf_len > capacity) return P2P_ERR_RESOURCE_EXHAUSTED;
    return (found == 0) ? P2P_OK : P2P_ERR_NOT_FOUND;
}

static int p2p_dht_lookup_is_active(p2p_node_t *node, uint32_t request_id) {
    int active = 0;

    if (!node) {
        return 0;
    }

    cmeta_mutex_lock(&node->mutex);
    active = p2p_dht_lookup_find(node, request_id) != NULL;
    cmeta_mutex_unlock(&node->mutex);

    return active;
}

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
    cmeta_mutex_lock(&node->mutex);

    /* Store locally first */
    ret = kademlia_store(node->kad_dht, &kkey, data, len);
    cmeta_mutex_unlock(&node->mutex);
    if (ret != 0) return P2P_ERR_NO_MEM;
    (void)p2p_send_dht_store_to_connected_peers(node, &kkey, data, len);

    /* Replicate to the discovered neighborhood after FIND_NODE completes. */
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
    int ret;

    if (!node || !key || !data) return P2P_ERR_INVALID_ARG;
    if (len == 0 || len > sizeof(((p2p_dht_store_payload_t *)0)->data)) {
        return P2P_ERR_INVALID_ARG;
    }

    kad_id_from_data(key, strlen(key), &kkey);
    cmeta_mutex_lock(&node->mutex);
    ret = kademlia_store(node->kad_dht, &kkey, data, len);
    cmeta_mutex_unlock(&node->mutex);
    if (ret != 0) return P2P_ERR_NO_MEM;

    (void)p2p_send_dht_store_to_connected_peers(node, &kkey, data, len);
    return P2P_OK;
}

static int p2p_dht_poll_owner(p2p_node_t *node) {
    const p2p_node_network_ops_t *ops = node->network_ops;
    int ret = p2p_poll(node);
    if (ret == P2P_OK && node->network_ops != ops) return P2P_ERR_INVALID_STATE;
    return ret;
}

int p2p_dht_get(p2p_node_t *node, const char *key, void *buf, size_t *buf_len) {
    uint64_t deadline_ms;
    p2p_dht_lookup_t *lookup;
    uint32_t request_id;
    kad_id_t kkey;
    int ret;

    if (!node || !key || !buf || !buf_len) return P2P_ERR_INVALID_ARG;
    kad_id_from_data(key, strlen(key), &kkey);
    ret = p2p_try_get_local_dht_value(node, &kkey, buf, buf_len);
    if (ret != P2P_ERR_NOT_FOUND) return ret;

    /* Validate progress before sending a request: a callback may read cached
     * values, but a miss must not recursively enter its network owner. */
    ret = p2p_dht_poll_owner(node);
    if (ret != P2P_OK) return ret;
    ret = p2p_try_get_local_dht_value(node, &kkey, buf, buf_len);
    if (ret != P2P_ERR_NOT_FOUND) return ret;

    lookup = p2p_dht_lookup_start(node, kkey.bytes, P2P_MSG_DHT_GET);
    if (!lookup) return node->network_ops ? P2P_ERR_NOT_FOUND : P2P_ERR_INVALID_STATE;
    request_id = lookup->request_id;
    deadline_ms = salts_monotonic_ms();
    deadline_ms = UINT64_MAX - deadline_ms < P2P_DHT_GET_TIMEOUT_MS
        ? UINT64_MAX : deadline_ms + P2P_DHT_GET_TIMEOUT_MS;
    for (;;) {
        uint64_t now_ms;
        ret = p2p_dht_poll_owner(node);
        if (ret != P2P_OK) break;
        ret = p2p_try_get_local_dht_value(node, &kkey, buf, buf_len);
        if (ret != P2P_ERR_NOT_FOUND || !p2p_dht_lookup_is_active(node, request_id)) break;
        now_ms = salts_monotonic_ms();
        if (now_ms >= deadline_ms) break;
        cmeta_sleep_ms((uint32_t)(deadline_ms - now_ms < P2P_DHT_POLL_INTERVAL_MS
            ? deadline_ms - now_ms : P2P_DHT_POLL_INTERVAL_MS));
    }
    /* Only this call's lookup is owned here. Completion/stop may already have
     * detached it; cancellation by id remains safe in either case. */
    p2p_dht_lookup_cancel(node, request_id);
    return ret;
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

    cmeta_mutex_lock(&node->mutex);
    count = kademlia_storage_count(node->kad_dht);
    cmeta_mutex_unlock(&node->mutex);
    return count;
}
