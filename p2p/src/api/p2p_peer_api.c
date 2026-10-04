#include "p2p.h"
#include "../internal.h"
#include <salts/clock.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void p2p_set_manual_connect_suppression_locked(p2p_node_t *node,
                                                      const char *ip,
                                                      int port,
                                                      uint64_t until_ms) {
    p2p_connect_suppression_t *suppression = NULL;
    char key[96];

    if (!node || !ip) {
        return;
    }

    p2p_endpoint_to_key(key, sizeof(key), ip, port);
    HASH_FIND_STR(node->connect_suppressions, key, suppression);
    if (!suppression) {
        suppression = (p2p_connect_suppression_t *)calloc(1, sizeof(*suppression));
        if (!suppression) {
            return;
        }
        strncpy(suppression->key, key, sizeof(suppression->key) - 1);
        strncpy(suppression->ip, ip, sizeof(suppression->ip) - 1);
        suppression->port = port;
        HASH_ADD_STR(node->connect_suppressions, key, suppression);
    }

    suppression->until_ms = until_ms;
}

static void p2p_remove_peer_from_routing_locked(p2p_node_t *node, p2p_peer_t *peer) {
    if (!node || !node->kad_dht || !node->kad_dht->routing || !peer) {
        return;
    }

    p2p_node_remove_route_locked(node, NULL, peer->ip, peer->port);

    if (!p2p_id_is_zero(peer->id)) {
        p2p_node_remove_route_locked(node, peer->id, NULL, 0);
    }
}

static void p2p_mark_manual_disconnect_locked(p2p_node_t *node, p2p_peer_t *peer) {
    if (!node || !peer) {
        return;
    }

    peer->keep_entry = 0;
    p2p_set_manual_connect_suppression_locked(node, peer->ip, peer->port,
                                              salts_monotonic_ms() +
                                                  P2P_MANUAL_DISCONNECT_SUPPRESS_MS);
    p2p_remove_peer_from_routing_locked(node, peer);
}

void p2p_set_message_handler(p2p_node_t *node, p2p_on_message_fn fn, void *user_data) {
    if (!node) return;
    node->on_message = fn;
    node->user_data = user_data;
}

void p2p_set_peer_callbacks(p2p_node_t *node,
                             void (*on_connected)(p2p_peer_t *peer, void *user_data),
                             void (*on_disconnected)(p2p_peer_t *peer, void *user_data),
                             void *user_data) {
    if (!node) return;
    node->on_peer_connected = on_connected;
    node->on_peer_disconnected = on_disconnected;
    node->peer_user_data = user_data;
}

int p2p_send(p2p_node_t *node, p2p_peer_t *peer, const void *data, size_t len) {
    return p2p_send_message(node, peer, P2P_MSG_CUSTOM, data, len);
}

int p2p_broadcast(p2p_node_t *node, const void *data, size_t len) {
    return p2p_send(node, NULL, data, len);
}

/* =============================================================================
 * DHT Operations
 * ============================================================================= */

static void p2p_copy_peer_info_legacy(p2p_peer_info_t *dst,
                                      const p2p_peer_info_ex_t *src) {
    if (!dst || !src) {
        return;
    }

    strncpy(dst->ip, src->ip, sizeof(dst->ip) - 1);
    dst->ip[sizeof(dst->ip) - 1] = '\0';
    dst->port = src->port;
    dst->is_connected = src->is_connected;
}

int p2p_get_peer_count(p2p_node_t *node) {
    p2p_peer_info_ex_t *infos = NULL;
    size_t count = 0;

    if (!node) return 0;
    infos = p2p_node_snapshot_peer_info_ex(node, &count);
    if (count > 0 && !infos) {
        return 0;
    }
    free(infos);
    return (int)count;
}

void p2p_disconnect_peer(p2p_peer_t *peer) {
    p2p_node_t *node = NULL;

    if (!peer || !peer->node) {
        return;
    }
    if (!p2p_peer_hold(peer)) {
        return;
    }

    node = peer->node;
    salts_mutex_lock(&node->mutex);
    p2p_mark_manual_disconnect_locked(node, peer);
    salts_mutex_unlock(&node->mutex);

    p2p_peer_disconnect(peer);
    p2p_node_on_peer_disconnected(node, peer);
    p2p_peer_destroy(peer);
    p2p_peer_release(peer);
}

int p2p_get_peer_info_ex(p2p_node_t *node, int index, p2p_peer_info_ex_t *info) {
    p2p_peer_info_ex_t *infos = NULL;
    size_t count = 0;

    if (!node || !info || index < 0) return P2P_ERR_INVALID_ARG;
    infos = p2p_node_snapshot_peer_info_ex(node, &count);
    if (count > 0 && !infos) {
        return P2P_ERR_NO_MEM;
    }
    if ((size_t)index >= count) {
        free(infos);
        return P2P_ERR_NOT_FOUND;
    }

    *info = infos[index];
    free(infos);
    return P2P_OK;
}

int p2p_get_peer_info(p2p_node_t *node, int index, p2p_peer_info_t *info) {
    p2p_peer_info_ex_t info_ex = {0};
    int ret = P2P_OK;

    if (!node || !info || index < 0) {
        return P2P_ERR_INVALID_ARG;
    }
    ret = p2p_get_peer_info_ex(node, index, &info_ex);
    if (ret != P2P_OK) {
        return ret;
    }

    p2p_copy_peer_info_legacy(info, &info_ex);
    return P2P_OK;
}

/* =============================================================================
 * File Sharing implementation
 * ============================================================================= */

int p2p_peer_get_stream_metrics(p2p_peer_t *peer,
                                p2p_peer_stream_metrics_t *metrics) {
    p2p_node_t *node = NULL;
    uint64_t now_ms = 0;
    uint64_t age_ms = 0;

    if (!peer || !metrics) {
        return P2P_ERR_INVALID_ARG;
    }

    memset(metrics, 0, sizeof(*metrics));
    metrics->sample_age_ms = UINT32_MAX;
    node = peer->node;
    if (node) {
        salts_mutex_lock(&node->mutex);
    }
    now_ms = salts_monotonic_ms();

    metrics->srtt_ms = peer->avg_rtt_ms > UINT32_MAX
        ? UINT32_MAX
        : (uint32_t)peer->avg_rtt_ms;
    metrics->rttvar_ms = peer->rttvar_ms > UINT32_MAX
        ? UINT32_MAX
        : (uint32_t)peer->rttvar_ms;
    metrics->sample_count = peer->rtt_sample_count;
    if (peer->rtt_sample_count > 0 && peer->last_rtt_sample_ms > 0 &&
        now_ms >= peer->last_rtt_sample_ms) {
        age_ms = now_ms - peer->last_rtt_sample_ms;
        metrics->sample_age_ms = age_ms > UINT32_MAX
            ? UINT32_MAX
            : (uint32_t)age_ms;
        metrics->is_fresh = peer->is_connected &&
                            peer->state == P2P_PEER_STATE_CONNECTED &&
                            age_ms <= P2P_RTT_METRIC_FRESH_MS;
    }

    if (node) {
        salts_mutex_unlock(&node->mutex);
    }
    return P2P_OK;
}

int p2p_peer_get_info(p2p_peer_t *peer, p2p_peer_info_t *info) {
    p2p_peer_info_ex_t info_ex = {0};

    if (!info) {
        return P2P_ERR_INVALID_ARG;
    }
    if (p2p_peer_get_info_ex(peer, &info_ex) != P2P_OK) {
        return P2P_ERR_INVALID_ARG;
    }

    p2p_copy_peer_info_legacy(info, &info_ex);
    return P2P_OK;
}

int p2p_peer_get_address(p2p_peer_t *peer, char *ip_out, int *port_out) {
    p2p_peer_info_ex_t info = {0};

    if (!ip_out || !port_out) {
        return P2P_ERR_INVALID_ARG;
    }
    if (p2p_peer_get_info_ex(peer, &info) != P2P_OK) {
        return P2P_ERR_INVALID_ARG;
    }

    strncpy(ip_out, info.ip, P2P_MAX_IP - 1);
    ip_out[P2P_MAX_IP - 1] = '\0';
    *port_out = info.port;
    return P2P_OK;
}

int p2p_peer_get_id(p2p_peer_t *peer, uint8_t id_out[P2P_HASH_SIZE]) {
    p2p_node_t *node = NULL;

    if (!peer || !id_out) {
        return P2P_ERR_INVALID_ARG;
    }

    node = peer->node;
    if (node) {
        salts_mutex_lock(&node->mutex);
    }
    if (p2p_id_is_zero(peer->id)) {
        if (node) {
            salts_mutex_unlock(&node->mutex);
        }
        return P2P_ERR_NOT_FOUND;
    }
    memcpy(id_out, peer->id, P2P_HASH_SIZE);
    if (node) {
        salts_mutex_unlock(&node->mutex);
    }
    return P2P_OK;
}

int p2p_peer_get_public_key(p2p_peer_t *peer,
                            uint8_t public_key_out[P2P_KEY_SIZE]) {
    p2p_node_t *node = NULL;

    if (!peer || !public_key_out) {
        return P2P_ERR_INVALID_ARG;
    }

    node = peer->node;
    if (node) {
        salts_mutex_lock(&node->mutex);
    }
    if (!peer->remote_public_key_ready) {
        if (node) {
            salts_mutex_unlock(&node->mutex);
        }
        return P2P_ERR_NOT_FOUND;
    }
    memcpy(public_key_out, peer->remote_public_key, P2P_KEY_SIZE);
    if (node) {
        salts_mutex_unlock(&node->mutex);
    }
    return P2P_OK;
}

int p2p_peer_get_security_info_v2(
    p2p_peer_t *peer, p2p_peer_security_info_v2_t *info) {
    p2p_node_t *node;
    p2p_peer_security_info_v2_t snapshot = {0};

    if (!peer || !info || info->struct_size != sizeof(*info)) {
        return P2P_ERR_INVALID_ARG;
    }
    node = peer->node;
    if (node) {
        salts_mutex_lock(&node->mutex);
    }
    if (!peer->ready_received || peer->state != P2P_PEER_STATE_CONNECTED) {
        if (node) {
            salts_mutex_unlock(&node->mutex);
        }
        return P2P_ERR_NOT_FOUND;
    }
    snapshot.struct_size = sizeof(snapshot);
    snapshot.secure_wire_version = P2P_SECURE_WIRE_VERSION_V2;
    snapshot.noise_suite = P2P_NOISE_SUITE_XX_25519_CHACHAPOLY_BLAKE2S;
    snapshot.authenticated = 1;
    memcpy(snapshot.remote_noise_static, peer->remote_public_key,
           sizeof(snapshot.remote_noise_static));
    memcpy(snapshot.channel_binding, peer->channel_binding,
           sizeof(snapshot.channel_binding));
    snapshot.identity = peer->authenticated_identity;
    snapshot.sent_frames = peer->crypto.sent_frames;
    snapshot.received_frames = peer->crypto.received_frames;
    snapshot.session_started_ms = peer->session_started_ms;
    snapshot.sent_bytes = peer->sent_bytes;
    snapshot.received_bytes = peer->received_bytes;
    *info = snapshot;
    if (node) {
        salts_mutex_unlock(&node->mutex);
    }
    return P2P_OK;
}

const char *p2p_error_str(int error) {
    switch (error) {
        case P2P_OK: return "Success";
        case P2P_ERR_INVALID_ARG: return "Invalid argument";
        case P2P_ERR_NO_MEM: return "Out of memory";
        case P2P_ERR_NETWORK: return "Network error";
        case P2P_ERR_TIMEOUT: return "Timeout";
        case P2P_ERR_NOT_FOUND: return "Not found";
        case P2P_ERR_IO: return "I/O error";
        case P2P_ERR_INVALID: return "Invalid argument";
        case P2P_ERR_AUTH_REQUIRED: return "Authentication required";
        case P2P_ERR_UNTRUSTED_IDENTITY: return "Untrusted identity";
        case P2P_ERR_RESOURCE_EXHAUSTED: return "Resource exhausted";
        case P2P_ERR_KEY_EXHAUSTED: return "Session key exhausted";
        default: return "Unknown error";
    }
}
