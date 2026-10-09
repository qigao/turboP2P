#include "node_network.h"
#include "peer.h"
#include "../protocol/handlers.h"
#include <salts/clock.h>
#include <tlog.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

static int node_send_identity_ping(p2p_node_t *node, p2p_peer_t *peer);
static int node_ip_is_publishable(const char *ip);
typedef void (*node_peer_event_cb_t)(struct p2p_peer_s *peer, void *user_data);
static p2p_peer_t *node_find_connected_peer_by_id_locked(p2p_node_t *node,
                                                         const uint8_t *id,
                                                         const p2p_peer_t *exclude);
static int node_authenticated_peer_is_preferred(const p2p_node_t *node,
                                                const p2p_peer_t *peer);
static p2p_peer_entry_t *node_find_peer_entry_locked(p2p_node_t *node, const p2p_peer_t *peer);
static void node_remove_peer_entry_locked(p2p_node_t *node, const p2p_peer_t *peer);
static void node_publish_peer_route_locked(p2p_node_t *node, const p2p_peer_t *peer);
static void node_capture_peer_event_locked(p2p_node_t *node, p2p_peer_t *peer,
                                           node_peer_event_cb_t callback, void *user_data,
                                           node_peer_event_cb_t *callback_out,
                                           void **user_data_out, int *hold_peer_out);
static void node_handle_peer_disconnect_locked(p2p_node_t *node, p2p_peer_t *peer);
static int node_activate_authenticated_peer_locked(p2p_node_t *node, p2p_peer_t *peer,
                                                   p2p_peer_t **stale_peer,
                                                   p2p_peer_t **duplicate_peer);
static p2p_peer_t *node_take_expired_pending_peer_locked(p2p_node_t *node,
                                                         uint64_t now_ms);
p2p_peer_t **p2p_node_snapshot_connected_peers(p2p_node_t *node, size_t *count_out) {
    p2p_peer_t **peers = NULL;
    p2p_peer_entry_t *curr = NULL;
    p2p_peer_entry_t *tmp = NULL;
    size_t count = 0;
    size_t capacity = 0;

    if (count_out) {
        *count_out = 0;
    }
    if (!node || !count_out) {
        return NULL;
    }

    cmeta_mutex_lock(&node->mutex);
    capacity = (size_t)peer_table_count(node->peers_table);
    if (capacity > 0) {
        peers = (p2p_peer_t **)calloc(capacity, sizeof(*peers));
    }
    if (capacity > 0 && !peers) {
        cmeta_mutex_unlock(&node->mutex);
        return NULL;
    }

    HASH_ITER(hh, node->peers_table, curr, tmp) {
        if (!curr->peer || !curr->peer->is_connected) {
            continue;
        }
        if (!p2p_peer_hold_locked(curr->peer)) {
            continue;
        }
        peers[count++] = curr->peer;
    }
    cmeta_mutex_unlock(&node->mutex);

    *count_out = count;
    return peers;
}

p2p_peer_info_ex_t *p2p_node_snapshot_peer_info_ex(p2p_node_t *node, size_t *count_out) {
    p2p_peer_info_ex_t *infos = NULL;
    p2p_peer_entry_t *curr = NULL;
    p2p_peer_entry_t *tmp = NULL;
    size_t count = 0;
    size_t capacity = 0;

    if (count_out) {
        *count_out = 0;
    }
    if (!node || !count_out) {
        return NULL;
    }

    cmeta_mutex_lock(&node->mutex);
    capacity = (size_t)peer_table_count(node->peers_table);
    if (capacity > 0) {
        infos = (p2p_peer_info_ex_t *)calloc(capacity, sizeof(*infos));
    }
    if (capacity > 0 && !infos) {
        cmeta_mutex_unlock(&node->mutex);
        return NULL;
    }

    HASH_ITER(hh, node->peers_table, curr, tmp) {
        p2p_peer_t *peer = curr->peer;
        if (!peer || !peer->is_connected) {
            continue;
        }

        p2p_peer_fill_info_ex_locked(peer, &infos[count]);
        count++;
    }
    cmeta_mutex_unlock(&node->mutex);

    *count_out = count;
    return infos;
}

void p2p_peer_fill_info_ex_locked(const p2p_peer_t *peer, p2p_peer_info_ex_t *info) {
    if (!peer || !info) {
        return;
    }

    strncpy(info->ip, peer->ip, sizeof(info->ip) - 1);
    info->ip[sizeof(info->ip) - 1] = '\0';
    info->port = peer->port;
    info->is_connected = peer->is_connected;
}

int p2p_id_is_zero(const uint8_t *id) {
    static const uint8_t zero_id[KADEMLIA_ID_BYTES] = {0};

    return id && memcmp(id, zero_id, KADEMLIA_ID_BYTES) == 0;
}

void p2p_endpoint_to_key(char *buf, size_t buf_size, const char *ip, int port) {
    if (!buf || buf_size == 0 || !ip) {
        return;
    }

    snprintf(buf, buf_size, "%s:%d", ip, port);
}

void p2p_endpoint_to_id(const char *ip, int port, kad_id_t *id) {
    char endpoint[96];

    if (!ip || !id) {
        return;
    }

    p2p_endpoint_to_key(endpoint, sizeof(endpoint), ip, port);
    kad_id_from_data(endpoint, strlen(endpoint), id);
}

void p2p_init_kad_node(kad_node_t *node, const uint8_t *id, const char *ip, int port) {
    if (!node || !ip) {
        return;
    }

    memset(node, 0, sizeof(*node));
    if (id && !p2p_id_is_zero(id)) {
        memcpy(node->id.bytes, id, KADEMLIA_ID_BYTES);
    } else {
        p2p_endpoint_to_id(ip, port, &node->id);
    }
    strncpy(node->ip, ip, sizeof(node->ip) - 1);
    node->port = (uint16_t)port;
    node->last_seen = (uint64_t)time(NULL);
}

p2p_peer_info_t *p2p_node_snapshot_peer_info(p2p_node_t *node, size_t *count_out) {
    p2p_peer_info_ex_t *infos_ex = NULL;
    p2p_peer_info_t *infos = NULL;
    size_t count = 0;

    if (count_out) {
        *count_out = 0;
    }
    if (!node || !count_out) {
        return NULL;
    }

    infos_ex = p2p_node_snapshot_peer_info_ex(node, &count);
    if (count > 0 && !infos_ex) {
        return NULL;
    }
    if (count > 0) {
        infos = (p2p_peer_info_t *)calloc(count, sizeof(*infos));
    }
    if (count > 0 && !infos) {
        free(infos_ex);
        return NULL;
    }

    for (size_t i = 0; i < count; i++) {
        strncpy(infos[i].ip, infos_ex[i].ip, sizeof(infos[i].ip) - 1);
        infos[i].ip[sizeof(infos[i].ip) - 1] = '\0';
        infos[i].port = infos_ex[i].port;
        infos[i].is_connected = infos_ex[i].is_connected;
    }

    free(infos_ex);
    *count_out = count;
    return infos;
}

/* =============================================================================
 * Network Operations
 * ============================================================================= */

void p2p_node_broadcast(p2p_node_t *node, p2p_message_t *msg) {
    p2p_peer_t **peers = NULL;
    size_t count = 0;

    if (!node || !msg) return;

    peers = p2p_node_snapshot_connected_peers(node, &count);
    if (count > 0 && !peers) {
        return;
    }

    for (size_t i = 0; i < count; i++) {
        if (peers[i]) {
            p2p_peer_send(peers[i], msg);
            p2p_peer_release(peers[i]);
        }
    }
    free(peers);
}

/* =============================================================================
 * DHT Integration
 * ============================================================================= */

int p2p_dht_join_ring(p2p_node_t *node, const char *bootstrap_ip, int bootstrap_port) {
    p2p_peer_t *peer = NULL;
    kad_id_t bootstrap_id;
    int ret = 0;

    if (!node || !bootstrap_ip) return P2P_ERR_INVALID_ARG;

    /* Professional Kademlia doesn't have a "ring", it has k-buckets.
     * Joining means contacting the bootstrap node to populate buckets. */

    /* Create a permanent peer for boostrap */
    peer = p2p_peer_create(node, bootstrap_ip, bootstrap_port);
    if (!peer) return P2P_ERR_NO_MEM;

    cmeta_mutex_lock(&node->mutex);
    if (p2p_node_find_peer_by_endpoint_locked(node, bootstrap_ip, bootstrap_port)) {
        cmeta_mutex_unlock(&node->mutex);
        p2p_peer_destroy(peer);
        return P2P_OK;
    }
    p2p_node_add_peer_locked(node, peer);
    cmeta_mutex_unlock(&node->mutex);

    ret = p2p_peer_connect(peer);
    if (ret != P2P_OK) {
        cmeta_mutex_lock(&node->mutex);
        p2p_node_remove_peer_by_endpoint_locked(node, bootstrap_ip, bootstrap_port);
        cmeta_mutex_unlock(&node->mutex);
        p2p_peer_destroy(peer);
        return ret;
    }

    /* Keep the provisional route ID consistent with other endpoint-derived
     * Kademlia contacts until the authenticated peer ID is learned. */
    p2p_endpoint_to_id(bootstrap_ip, bootstrap_port, &bootstrap_id);
    cmeta_mutex_lock(&node->mutex);
    p2p_node_add_route_locked(node, bootstrap_id.bytes, bootstrap_ip, bootstrap_port);
    cmeta_mutex_unlock(&node->mutex);

    /* Start iterative lookup for OUR identity to discover our neighborhood */
    (void)p2p_dht_lookup_start(node, node->id, P2P_MSG_DHT_FIND_NODE);

    return P2P_OK;
}

void p2p_dht_create_ring(p2p_node_t *node) {
    /* No-op in Kademlia (ring creation is not a separate step) */
    (void)node;
}


/* =============================================================================
 * Peer Events & Dispatch
 * ============================================================================= */

void p2p_node_on_peer_connected(p2p_node_t *node, p2p_peer_t *peer) {
    int ret;

    if (!node || !peer) return;

    ret = p2p_peer_start_handshake(peer);
    if (ret != P2P_OK) {
        p2p_node_record_security_failure(node, peer->security_stage, ret);
        p2p_peer_disconnect(peer);
    }
}

int p2p_node_reserve_transport_send_capacity(p2p_node_t *node,
                                             p2p_peer_t *peer) {
    size_t reservation;
    size_t budget;
    int ret = P2P_OK;

    if (!node || !peer || peer->node != node) {
        return P2P_ERR_INVALID_ARG;
    }

    cmeta_mutex_lock(&node->mutex);
    reservation = node->security_config.send_hwm_bytes;
    budget = node->security_config.node_send_budget_bytes;
    if (!node->security_configured) {
        ret = P2P_ERR_AUTH_REQUIRED;
    } else if (reservation == 0 || budget < reservation) {
        ret = P2P_ERR_INVALID_STATE;
    } else if (peer->reserved_send_capacity_bytes != 0) {
        ret = P2P_OK;
    } else if (node->reserved_send_capacity_bytes > budget ||
               reservation > budget - node->reserved_send_capacity_bytes) {
        node->send_budget_rejections++;
        node->security_rejection_counts[
            P2P_SECURITY_REJECTION_SEND_BUDGET]++;
        ret = P2P_ERR_RESOURCE_EXHAUSTED;
    } else {
        node->reserved_send_capacity_bytes += reservation;
        node->transport_send_reservations++;
        peer->reserved_send_capacity_bytes = reservation;
    }
    cmeta_mutex_unlock(&node->mutex);
    return ret;
}

void p2p_node_release_transport_send_capacity(p2p_node_t *node,
                                              p2p_peer_t *peer) {
    size_t reservation;
    int accounting_invalid = 0;

    if (!node || !peer || peer->node != node) {
        return;
    }

    cmeta_mutex_lock(&node->mutex);
    reservation = peer->reserved_send_capacity_bytes;
    if (reservation != 0) {
        if (node->reserved_send_capacity_bytes < reservation ||
            node->transport_send_reservations == 0) {
            accounting_invalid = 1;
        } else {
            node->reserved_send_capacity_bytes -= reservation;
            node->transport_send_reservations--;
            peer->reserved_send_capacity_bytes = 0;
        }
    }
    cmeta_mutex_unlock(&node->mutex);

    if (accounting_invalid) {
        TLOG_ERROR("[P2P] transport send-capacity accounting invariant failed");
    }
}

void p2p_node_record_security_failure(p2p_node_t *node,
                                      uint8_t security_stage,
                                      int error_code) {
    p2p_security_rejection_reason_v2_t reason;
    int established = security_stage == P2P_SECURITY_STAGE_ESTABLISHED;

    if (!node || error_code == P2P_OK || error_code == P2P_ERR_NETWORK ||
        error_code == P2P_ERR_TIMEOUT) {
        return;
    }
    if (security_stage == P2P_SECURITY_STAGE_COOKIE) {
        if (error_code == P2P_ERR_CRYPTO ||
            error_code == P2P_ERR_UNTRUSTED_IDENTITY) {
            reason = P2P_SECURITY_REJECTION_COOKIE_AUTH;
        } else if (error_code == P2P_ERR_NO_MEM ||
                   error_code == P2P_ERR_RESOURCE_EXHAUSTED) {
            reason = P2P_SECURITY_REJECTION_HANDSHAKE_RESOURCE;
        } else {
            reason = P2P_SECURITY_REJECTION_COOKIE_PROTOCOL;
        }
    } else if (established) {
        if (error_code == P2P_ERR_KEY_EXHAUSTED) {
            reason = P2P_SECURITY_REJECTION_SESSION_KEY_LIMIT;
        } else if (error_code == P2P_ERR_CRYPTO ||
                   error_code == P2P_ERR_UNTRUSTED_IDENTITY) {
            reason = P2P_SECURITY_REJECTION_SESSION_CRYPTO;
        } else if (error_code == P2P_ERR_NO_MEM ||
                   error_code == P2P_ERR_RESOURCE_EXHAUSTED) {
            reason = P2P_SECURITY_REJECTION_SESSION_RESOURCE;
        } else {
            reason = P2P_SECURITY_REJECTION_SESSION_PROTOCOL;
        }
    } else if (error_code == P2P_ERR_UNTRUSTED_IDENTITY ||
               error_code == P2P_ERR_AUTH_REQUIRED) {
        reason = P2P_SECURITY_REJECTION_HANDSHAKE_IDENTITY;
    } else if (error_code == P2P_ERR_CRYPTO ||
               error_code == P2P_ERR_KEY_EXHAUSTED) {
        reason = P2P_SECURITY_REJECTION_HANDSHAKE_CRYPTO;
    } else if (error_code == P2P_ERR_NO_MEM ||
               error_code == P2P_ERR_RESOURCE_EXHAUSTED) {
        reason = P2P_SECURITY_REJECTION_HANDSHAKE_RESOURCE;
    } else {
        reason = P2P_SECURITY_REJECTION_HANDSHAKE_PROTOCOL;
    }

    cmeta_mutex_lock(&node->mutex);
    node->security_rejection_counts[reason]++;
    cmeta_mutex_unlock(&node->mutex);
}

static uint64_t node_saturating_add_u64(uint64_t left, uint64_t right) {
    return right > UINT64_MAX - left ? UINT64_MAX : left + right;
}

const uint64_t p2p_security_latency_bucket_upper_bounds_ms
    [P2P_SECURITY_LATENCY_BUCKET_COUNT] = {
        1U,   5U,    10U,   25U,   50U,   100U,
        250U, 500U,  1000U, 2500U, 5000U, UINT64_MAX,
};

void p2p_node_record_handshake_latency_locked(
    p2p_node_t *node, p2p_security_role_t role,
    p2p_security_latency_stage_t stage, uint64_t started_ms,
    uint64_t completed_ms) {
    p2p_security_latency_accumulator_t *accumulator;
    uint64_t elapsed_ms;
    size_t bucket_index;

    if (!node || role >= P2P_SECURITY_ROLE_COUNT ||
        stage >= P2P_SECURITY_LATENCY_STAGE_COUNT ||
        completed_ms < started_ms) {
        return;
    }
    elapsed_ms = completed_ms - started_ms;
    accumulator = &node->security_handshake_latency[role][stage];
    accumulator->completed =
        node_saturating_add_u64(accumulator->completed, 1U);
    accumulator->total_ms =
        node_saturating_add_u64(accumulator->total_ms, elapsed_ms);
    if (elapsed_ms > accumulator->maximum_ms) {
        accumulator->maximum_ms = elapsed_ms;
    }
    for (bucket_index = 0;
         bucket_index < P2P_SECURITY_LATENCY_BUCKET_COUNT;
         ++bucket_index) {
        if (elapsed_ms <=
            p2p_security_latency_bucket_upper_bounds_ms[bucket_index]) {
            accumulator->buckets[bucket_index] = node_saturating_add_u64(
                accumulator->buckets[bucket_index], 1U);
            break;
        }
    }
}

void p2p_node_record_handshake_latency(
    p2p_node_t *node, p2p_security_role_t role,
    p2p_security_latency_stage_t stage, uint64_t started_ms,
    uint64_t completed_ms) {
    if (!node) {
        return;
    }
    cmeta_mutex_lock(&node->mutex);
    p2p_node_record_handshake_latency_locked(node, role, stage, started_ms,
                                         completed_ms);
    cmeta_mutex_unlock(&node->mutex);
}

void p2p_node_on_peer_disconnected(p2p_node_t *node, p2p_peer_t *peer) {
    node_peer_event_cb_t on_peer_disconnected = NULL;
    void *peer_user_data = NULL;
    int hold_peer = 0;

    if (!node || !peer) return;

    cmeta_mutex_lock(&node->mutex);
    node_handle_peer_disconnect_locked(node, peer);
    node_capture_peer_event_locked(node, peer, node->on_peer_disconnected,
                                   node->peer_user_data, &on_peer_disconnected,
                                   &peer_user_data, &hold_peer);
    cmeta_mutex_unlock(&node->mutex);

    if (on_peer_disconnected) {
        on_peer_disconnected(peer, peer_user_data);
    }
    if (hold_peer) {
        p2p_peer_release(peer);
    }
}

void p2p_node_on_peer_authenticated(p2p_node_t *node, p2p_peer_t *peer) {
    int should_publish_endpoint = 0;
    p2p_peer_t *stale_peer = NULL;
    p2p_peer_t *duplicate_peer = NULL;
    node_peer_event_cb_t on_peer_connected = NULL;
    void *peer_user_data = NULL;
    int hold_peer = 0;

    if (!node || !peer) return;

    cmeta_mutex_lock(&node->mutex);
    should_publish_endpoint = node_activate_authenticated_peer_locked(node, peer,
                                                                      &stale_peer,
                                                                      &duplicate_peer);
    if (!duplicate_peer) {
        if (should_publish_endpoint) {
            node_publish_peer_route_locked(node, peer);
        }
        node_capture_peer_event_locked(node, peer, node->on_peer_connected,
                                       node->peer_user_data, &on_peer_connected,
                                       &peer_user_data, &hold_peer);
    }
    cmeta_mutex_unlock(&node->mutex);

    if (stale_peer) {
        p2p_peer_destroy(stale_peer);
    }
    if (duplicate_peer) {
        p2p_peer_destroy(duplicate_peer);
        return;
    }

    p2p_dht_lookup_try_progress(node);
    (void)node_send_identity_ping(node, peer);

    if (on_peer_connected) {
        on_peer_connected(peer, peer_user_data);
    }
    if (hold_peer) {
        p2p_peer_release(peer);
    }
}

static int node_send_identity_ping(p2p_node_t *node, p2p_peer_t *peer) {
    p2p_ping_payload_t ping = {0};
    int ret = P2P_ERR_INVALID_STATE;

    if (!node || !peer) {
        return P2P_ERR_INVALID_ARG;
    }

    cmeta_mutex_lock(&node->mutex);
    if (!peer->is_connected || peer->state != P2P_PEER_STATE_CONNECTED ||
        !p2p_crypto_session_is_ready(&peer->crypto) ||
        peer->outstanding_ping_ms != 0) {
        cmeta_mutex_unlock(&node->mutex);
        return P2P_ERR_INVALID_STATE;
    }

    memcpy(ping.node_id, node->id, P2P_DHT_KEY_SIZE);
    if (node_ip_is_publishable(node->ip)) {
        strncpy(ping.ip, node->ip, sizeof(ping.ip) - 1);
    }
    ping.port = (uint16_t)node->port;
    ping.timestamp = salts_hrtime() / 1000000;
    memcpy(ping.coords, node->coord.coords, sizeof(ping.coords));
    ping.height = node->coord.height;
    ping.error = node->coord.error;
    peer->last_ping_sent_ms = ping.timestamp;
    peer->outstanding_ping_ms = ping.timestamp;
    cmeta_mutex_unlock(&node->mutex);

    ret = p2p_send_message(node, peer, P2P_MSG_PING, &ping, sizeof(ping));
    if (ret != P2P_OK) {
        cmeta_mutex_lock(&node->mutex);
        if (peer->outstanding_ping_ms == ping.timestamp) {
            peer->outstanding_ping_ms = 0;
            peer->last_ping_sent_ms = 0;
        }
        cmeta_mutex_unlock(&node->mutex);
    }
    return ret;
}

static int node_ip_is_publishable(const char *ip) {
    return ip && ip[0] != '\0' &&
           strcmp(ip, "0.0.0.0") != 0 &&
           strcmp(ip, "::") != 0;
}

static void node_capture_peer_event_locked(p2p_node_t *node, p2p_peer_t *peer,
                                           node_peer_event_cb_t callback, void *user_data,
                                           node_peer_event_cb_t *callback_out,
                                           void **user_data_out, int *hold_peer_out) {
    if (callback_out) {
        *callback_out = NULL;
    }
    if (user_data_out) {
        *user_data_out = NULL;
    }
    if (hold_peer_out) {
        *hold_peer_out = 0;
    }
    if (!node || !peer || !callback) {
        return;
    }

    peer->callback_refs++;
    if (callback_out) {
        *callback_out = callback;
    }
    if (user_data_out) {
        *user_data_out = user_data;
    }
    if (hold_peer_out) {
        *hold_peer_out = 1;
    }
}

static void node_handle_peer_disconnect_locked(p2p_node_t *node, p2p_peer_t *peer) {
    if (!node || !peer) {
        return;
    }

    if (node->peers_table && (!peer->keep_entry || peer->destroying) &&
        node_find_peer_entry_locked(node, peer)) {
        node_remove_peer_entry_locked(node, peer);
    }

    if (peer->counted && node->peer_count > 0) {
        node->peer_count--;
        peer->counted = 0;
    }
}

static int node_activate_authenticated_peer_locked(p2p_node_t *node, p2p_peer_t *peer,
                                                   p2p_peer_t **stale_peer,
                                                   p2p_peer_t **duplicate_peer) {
    p2p_peer_entry_t *entry = NULL;
    p2p_peer_t *identity_peer = NULL;
    int should_publish_endpoint = 1;

    if (stale_peer) {
        *stale_peer = NULL;
    }
    if (duplicate_peer) {
        *duplicate_peer = NULL;
    }
    if (!node || !peer) {
        return 0;
    }

    identity_peer = node_find_connected_peer_by_id_locked(node, peer->id, peer);
    if (identity_peer) {
        int existing_preferred =
            node_authenticated_peer_is_preferred(node, identity_peer);
        int candidate_preferred =
            node_authenticated_peer_is_preferred(node, peer);

        if (candidate_preferred && !existing_preferred) {
            if (node_find_peer_entry_locked(node, identity_peer)) {
                node_remove_peer_entry_locked(node, identity_peer);
            }
            if (identity_peer->counted && node->peer_count > 0) {
                node->peer_count--;
                identity_peer->counted = 0;
            }
            identity_peer->keep_entry = 0;
            identity_peer->is_connected = 0;
            if (stale_peer) {
                *stale_peer = identity_peer;
            }
        } else {
            if (node_find_peer_entry_locked(node, peer)) {
                node_remove_peer_entry_locked(node, peer);
            }
            if (peer->counted && node->peer_count > 0) {
                node->peer_count--;
                peer->counted = 0;
            }
            if (duplicate_peer) {
                *duplicate_peer = peer;
            }
            return 0;
        }
    }

    entry = node_find_peer_entry_locked(node, peer);
    if (entry && entry->peer != peer) {
        if (entry->peer->is_connected) {
            if (duplicate_peer) {
                *duplicate_peer = peer;
            }
            return 0;
        }

        if (stale_peer) {
            *stale_peer = entry->peer;
        }
        node_remove_peer_entry_locked(node, peer);
    }

    peer->is_connected = 1;
    peer->state = P2P_PEER_STATE_CONNECTED;

    if (!node_find_peer_entry_locked(node, peer)) {
        p2p_node_add_peer_locked(node, peer);
    }

    if (!peer->counted) {
        node->peer_count++;
        peer->counted = 1;
    }

    /*
     * A server-accepted transport endpoint is just the caller's ephemeral source
     * port. Advertising it through the routing table teaches later lookups a
     * nondialable endpoint and creates duplicate reverse connects.
     */
    if (peer->conn && peer->conn->type == P2P_CONN_INBOUND) {
        should_publish_endpoint = 0;
    }

    return should_publish_endpoint;
}

static int node_authenticated_peer_is_preferred(const p2p_node_t *node,
                                                const p2p_peer_t *peer) {
    int identity_order;
    p2p_conn_type_t preferred_type;

    if (!node || !peer || !peer->conn) {
        return 0;
    }
    identity_order = memcmp(
        node->local_authenticated_identity.routing_id,
        peer->authenticated_identity.routing_id,
        P2P_SECURITY_ID_SIZE);
    if (identity_order == 0) {
        return 0;
    }
    preferred_type = identity_order < 0 ? P2P_CONN_OUTBOUND
                                        : P2P_CONN_INBOUND;
    return peer->conn->type == preferred_type;
}

static p2p_peer_t *node_find_connected_peer_by_id_locked(p2p_node_t *node,
                                                         const uint8_t *id,
                                                         const p2p_peer_t *exclude) {
    p2p_peer_entry_t *curr = NULL;
    p2p_peer_entry_t *tmp = NULL;

    if (!node || !id || p2p_id_is_zero(id)) {
        return NULL;
    }

    HASH_ITER(hh, node->peers_table, curr, tmp) {
        if (!curr->peer || curr->peer == exclude) {
            continue;
        }
        if (!curr->peer->is_connected || curr->peer->destroying) {
            continue;
        }
        if (memcmp(curr->peer->id, id, P2P_DHT_KEY_SIZE) == 0) {
            return curr->peer;
        }
    }

    return NULL;
}

CXX_C_API p2p_peer_t *p2p_node_find_peer_by_endpoint_locked(p2p_node_t *node,
                                                             const char *ip,
                                                             int port) {
    p2p_peer_entry_t *entry = NULL;

    if (!node || !ip) {
        return NULL;
    }

    entry = peer_table_find(node->peers_table, ip, port);
    return entry ? entry->peer : NULL;
}

CXX_C_API void p2p_node_add_peer_locked(p2p_node_t *node, p2p_peer_t *peer) {
    if (!node || !peer) {
        return;
    }

    peer_table_add(&node->peers_table, peer);
}

int p2p_node_source_prefix_matches(const char *left, const char *right) {
    struct in_addr left4;
    struct in_addr right4;
    struct in6_addr left6;
    struct in6_addr right6;

    if (!left || !right) {
        return 0;
    }
    if (inet_pton(AF_INET, left, &left4) == 1 &&
        inet_pton(AF_INET, right, &right4) == 1) {
        return memcmp(&left4, &right4, sizeof(left4)) == 0;
    }
    if (inet_pton(AF_INET6, left, &left6) == 1 &&
        inet_pton(AF_INET6, right, &right6) == 1) {
        return memcmp(&left6, &right6, 8) == 0;
    }
    return 0;
}

p2p_security_rejection_reason_v2_t
p2p_node_pending_peer_rejection_locked(p2p_node_t *node,
                                   const char *source_ip) {
    p2p_peer_entry_t *curr = NULL;
    p2p_peer_entry_t *tmp = NULL;
    size_t pending_count = 0, source_count = 0;
    if (!node->network_ops || !node->network_ops->pending_gates ||
        node->network_ops->pending_gates(node, source_ip, &pending_count,
            &source_count, node->network_context) != P2P_OK)
        return P2P_SECURITY_REJECTION_PENDING_GLOBAL;
    if (pending_count >= P2P_PENDING_PEER_LIMIT)
        return P2P_SECURITY_REJECTION_PENDING_GLOBAL;
    if (source_count >= P2P_PENDING_PEER_SOURCE_LIMIT)
        return P2P_SECURITY_REJECTION_PENDING_SOURCE;

    HASH_ITER(hh, node->peers_table, curr, tmp) {
        if (curr->peer && !curr->peer->is_connected &&
            (curr->peer->state == P2P_PEER_STATE_HANDSHAKING ||
             curr->peer->state == P2P_PEER_STATE_CONNECTING)) {
            pending_count++;
            if (pending_count >= P2P_PENDING_PEER_LIMIT) {
                return P2P_SECURITY_REJECTION_PENDING_GLOBAL;
            }
            if (source_ip &&
                p2p_node_source_prefix_matches(source_ip, curr->peer->ip)) {
                source_count++;
                if (source_count >= P2P_PENDING_PEER_SOURCE_LIMIT) {
                    return P2P_SECURITY_REJECTION_PENDING_SOURCE;
                }
            }
        }
    }
    return P2P_SECURITY_REJECTION_REASON_COUNT;
}

CXX_C_API int p2p_node_pending_peer_source_capacity_available_locked(
    p2p_node_t *node, const char *source_ip) {
    if (!node) {
        return 0;
    }
    if (source_ip) {
        struct in_addr source4;
        struct in6_addr source6;
        if (inet_pton(AF_INET, source_ip, &source4) != 1 &&
            inet_pton(AF_INET6, source_ip, &source6) != 1) {
            return 0;
        }
    }

    return p2p_node_pending_peer_rejection_locked(node, source_ip) ==
           P2P_SECURITY_REJECTION_REASON_COUNT;
}

static int node_source_admission_key(const char *source_ip, uint8_t *family,
                                     uint8_t prefix[8]) {
    struct in_addr address4;
    struct in6_addr address6;

    memset(prefix, 0, 8);
    if (inet_pton(AF_INET, source_ip, &address4) == 1) {
        *family = 4u;
        memcpy(prefix, &address4, sizeof(address4));
        return 1;
    }
    if (inet_pton(AF_INET6, source_ip, &address6) == 1) {
        *family = 6u;
        memcpy(prefix, &address6, 8);
        return 1;
    }
    return 0;
}

static void node_source_admission_refill_locked(
    const p2p_node_t *node, p2p_source_admission_bucket_t *bucket,
    uint64_t now_ms) {
    uint64_t capacity =
        (uint64_t)node->security_config.source_admission_burst *
        P2P_SECURITY_SOURCE_TOKEN_UNITS;
    uint64_t refill =
        node->security_config.source_admission_refill_per_second;
    uint64_t elapsed;
    uint64_t needed;

    if (now_ms <= bucket->last_refill_ms) {
        return;
    }
    if (bucket->tokens >= capacity) {
        bucket->last_refill_ms = now_ms;
        return;
    }
    elapsed = now_ms - bucket->last_refill_ms;
    needed = capacity - bucket->tokens;
    if (elapsed >= (needed + refill - 1u) / refill) {
        bucket->tokens = capacity;
    } else {
        bucket->tokens += elapsed * refill;
    }
    bucket->last_refill_ms = now_ms;
}

CXX_C_API int p2p_node_source_admission_acquire_locked(
    p2p_node_t *node, const char *source_ip, uint64_t now_ms) {
    p2p_source_admission_bucket_t *bucket = NULL;
    p2p_source_admission_bucket_t *reclaim = NULL;
    uint8_t family = 0;
    uint8_t prefix[8];
    uint64_t capacity;
    size_t index;

    if (!node || !source_ip || !node->security_configured ||
        !node_source_admission_key(source_ip, &family, prefix)) {
        return P2P_ERR_INVALID_ARG;
    }
    capacity = (uint64_t)node->security_config.source_admission_burst *
               P2P_SECURITY_SOURCE_TOKEN_UNITS;
    for (index = 0;
         index < node->security_config.source_admission_bucket_limit; ++index) {
        p2p_source_admission_bucket_t *candidate =
            &node->source_admission_buckets[index];
        if (!candidate->used) {
            if (!bucket) {
                bucket = candidate;
            }
            continue;
        }
        node_source_admission_refill_locked(node, candidate, now_ms);
        if (candidate->family == family &&
            memcmp(candidate->prefix, prefix, sizeof(prefix)) == 0) {
            bucket = candidate;
            break;
        }
        if (candidate->tokens == capacity &&
            (!reclaim || candidate->last_seen_ms < reclaim->last_seen_ms)) {
            reclaim = candidate;
        }
    }

    if (!bucket || (bucket->used &&
                    (bucket->family != family ||
                     memcmp(bucket->prefix, prefix, sizeof(prefix)) != 0))) {
        bucket = reclaim;
    }
    if (!bucket) {
        node->security_rejection_counts[
            P2P_SECURITY_REJECTION_SOURCE_BUCKET_CAPACITY]++;
        return P2P_ERR_RESOURCE_EXHAUSTED;
    }
    if (!bucket->used || bucket->family != family ||
        memcmp(bucket->prefix, prefix, sizeof(prefix)) != 0) {
        memset(bucket, 0, sizeof(*bucket));
        memcpy(bucket->prefix, prefix, sizeof(prefix));
        bucket->family = family;
        bucket->used = 1u;
        bucket->tokens = capacity;
        bucket->last_refill_ms = now_ms;
    }
    bucket->last_seen_ms = now_ms;
    if (bucket->tokens < P2P_SECURITY_SOURCE_TOKEN_UNITS) {
        node->security_rejection_counts[
            P2P_SECURITY_REJECTION_SOURCE_RATE]++;
        return P2P_ERR_RESOURCE_EXHAUSTED;
    }
    bucket->tokens -= P2P_SECURITY_SOURCE_TOKEN_UNITS;
    return P2P_OK;
}

CXX_C_API int p2p_node_pending_peer_capacity_available_locked(p2p_node_t *node) {
    return p2p_node_pending_peer_source_capacity_available_locked(node, NULL);
}

CXX_C_API void p2p_node_remove_peer_by_endpoint_locked(p2p_node_t *node,
                                                       const char *ip,
                                                       int port) {
    if (!node || !ip) {
        return;
    }

    peer_table_remove(&node->peers_table, ip, port);
}

CXX_C_API void p2p_node_add_route_locked(p2p_node_t *node, const uint8_t *id, const char *ip, int port) {
    kad_node_t knode;

    if (!node || !node->kad_dht || !node->kad_dht->routing || !ip) {
        return;
    }

    p2p_init_kad_node(&knode, id, ip, port);
    kad_routing_add_node(node->kad_dht->routing, &knode);
}

CXX_C_API void p2p_node_remove_route_locked(p2p_node_t *node, const uint8_t *id, const char *ip, int port) {
    kad_id_t route_id;

    if (!node || !node->kad_dht || !node->kad_dht->routing) {
        return;
    }

    if (id && !p2p_id_is_zero(id)) {
        memcpy(route_id.bytes, id, sizeof(route_id.bytes));
    } else if (ip) {
        p2p_endpoint_to_id(ip, port, &route_id);
    } else {
        return;
    }

    kad_routing_remove_node(node->kad_dht->routing, &route_id);
}

static p2p_peer_entry_t *node_find_peer_entry_locked(p2p_node_t *node, const p2p_peer_t *peer) {
    if (!node || !peer) {
        return NULL;
    }

    return peer_table_find(node->peers_table, peer->ip, peer->port);
}

static void node_remove_peer_entry_locked(p2p_node_t *node, const p2p_peer_t *peer) {
    if (!node || !peer) {
        return;
    }

    p2p_node_remove_peer_by_endpoint_locked(node, peer->ip, peer->port);
}

static void node_publish_peer_route_locked(p2p_node_t *node, const p2p_peer_t *peer) {
    if (!node || !peer) {
        return;
    }

    p2p_node_add_route_locked(node, peer->id, peer->ip, peer->port);
}

void p2p_node_dispatch_message(p2p_node_t *node, p2p_peer_t *peer, p2p_message_t *msg) {
    if (!node || !peer || !msg) return;

    /* Secure-wire v2 handshake bytes never enter the application codec. */
    if (msg->header.type == P2P_MSG_RESERVED_LEGACY_HANDSHAKE) {
        p2p_peer_disconnect(peer);
        return;
    }

    /* For custom messages, notify user */
    if (msg->header.type == P2P_MSG_CUSTOM) {
        if (node->on_message) {
            node->on_message(node, peer, msg->payload.raw, msg->header.payload_len, node->user_data);
            return;
        }
        return;
    }

    p2p_handlers_dispatch(node, peer, msg);
}

void p2p_gossip_start(p2p_node_t *node) {
    if (!node) return;

    /* Professional Kademlia uses bucket refreshes instead of gossip.
     * We occasionally lookup our own ID to refresh buckets. */
    p2p_dht_lookup_start(node, node->id, P2P_MSG_DHT_FIND_NODE);
}

void p2p_node_expire_pending_peers(p2p_node_t *node, uint64_t now) {
    p2p_peer_t *expired_peer = NULL;
    if (!node) return;
    for (;;) {
        cmeta_mutex_lock(&node->mutex);
        expired_peer = node_take_expired_pending_peer_locked(node, now);
        cmeta_mutex_unlock(&node->mutex);

        if (!expired_peer) {
            break;
        }

        TLOG_DEBUGF("[P2P] Expiring unauthenticated peer {}:{}",
                   expired_peer->ip, expired_peer->port);
        p2p_peer_destroy(expired_peer);
    }

}

void p2p_node_maintain_peers(p2p_node_t *node, uint64_t now) {
    p2p_peer_t **peers = NULL;
    size_t peer_count = 0;
    if (!node) return;
    p2p_node_expire_pending_peers(node, now);
    /* Probe healthy authenticated streams and prune stale peers. The
     * snapshot owns temporary holds so socket I/O never runs under node->mutex. */
    peers = p2p_node_snapshot_connected_peers(node, &peer_count);
    for (size_t i = 0; i < peer_count; i++) {
        p2p_peer_t *peer = peers[i];
        uint64_t last_seen_ms = 0;
        int stale = 0;
        int probe_due = 0;
        p2p_peer_info_ex_t peer_info = {0};

        if (!peer) {
            continue;
        }

        cmeta_mutex_lock(&node->mutex);
        last_seen_ms = peer->last_seen / 1000000U;
        stale = now >= last_seen_ms &&
                now - last_seen_ms > P2P_PEER_TIMEOUT_MS;
        probe_due = !stale && peer->state == P2P_PEER_STATE_CONNECTED &&
                    p2p_crypto_session_is_ready(&peer->crypto) &&
                    peer->outstanding_ping_ms == 0 &&
                    (peer->last_ping_sent_ms == 0 ||
                     (now >= peer->last_ping_sent_ms &&
                      now - peer->last_ping_sent_ms >= P2P_RTT_PROBE_INTERVAL_MS));
        if (stale) {
            p2p_peer_fill_info_ex_locked(peer, &peer_info);
        }
        cmeta_mutex_unlock(&node->mutex);

        if (stale) {
            TLOG_INFOF("[P2P] Pruning stale peer {}:{}", peer_info.ip, peer_info.port);
            p2p_peer_transport_closed(peer, !peer->keep_entry);
        } else if (probe_due) {
            (void)node_send_identity_ping(node, peer);
        }
        p2p_peer_release(peer);
    }
    free(peers);
}
static p2p_peer_t *node_take_expired_pending_peer_locked(p2p_node_t *node,
                                                         uint64_t now_ms) {
    p2p_peer_entry_t *curr = NULL;
    p2p_peer_entry_t *tmp = NULL;

    if (!node) {
        return NULL;
    }

    HASH_ITER(hh, node->peers_table, curr, tmp) {
        p2p_peer_t *peer = curr->peer;
        uint64_t connected_at_ms = 0;

        if (!peer || peer->is_connected ||
            (peer->state != P2P_PEER_STATE_HANDSHAKING &&
             peer->state != P2P_PEER_STATE_CONNECTING) || peer->connect_time == 0) {
            continue;
        }

        if (peer->security_deadline_ms != 0) {
            if (now_ms < peer->security_deadline_ms) {
                continue;
            }
        } else {
            connected_at_ms = peer->connect_time / 1000000;
            if (now_ms < connected_at_ms ||
                now_ms - connected_at_ms <= P2P_PEER_TIMEOUT_MS) {
                continue;
            }
        }

        node->security_rejection_counts[
            P2P_SECURITY_REJECTION_HANDSHAKE_TIMEOUT]++;
        node_remove_peer_entry_locked(node, peer);
        return peer;
    }

    return NULL;
}

static void p2p_clear_manual_connect_suppression_locked(p2p_node_t *node,
                                                        const char *ip,
                                                        int port) {
    p2p_connect_suppression_t *suppression = NULL;
    char key[96];

    if (!node || !ip) {
        return;
    }

    p2p_endpoint_to_key(key, sizeof(key), ip, port);
    HASH_FIND_STR(node->connect_suppressions, key, suppression);
    if (!suppression) {
        return;
    }

    HASH_DEL(node->connect_suppressions, suppression);
    free(suppression);
}


static p2p_peer_t *p2p_prepare_connect_peer_locked(p2p_node_t *node,
                                                   const char *ip,
                                                   int port,
                                                   int force_retry) {
    p2p_peer_t *peer = NULL;

    if (!node || !ip) {
        return NULL;
    }

    peer = p2p_node_find_peer_by_endpoint_locked(node, ip, port);
    if (!peer) {
        return NULL;
    }
    peer->keep_entry = 1;
    if (force_retry) {
        peer->reconnect_after_ms = 0;
    }

    return peer;
}

static int p2p_connect_internal(p2p_node_t *node, const char *ip, int port,
                                int force_retry) {
    p2p_peer_t *existing_peer = NULL;
    p2p_peer_t *peer = NULL;
    int added_to_table = 0;
    int ret = 0;

    if (!node || !ip) {
        return P2P_ERR_INVALID_ARG;
    }

    cmeta_mutex_lock(&node->mutex);
    if (force_retry) {
        p2p_clear_manual_connect_suppression_locked(node, ip, port);
    }
    peer = p2p_prepare_connect_peer_locked(node, ip, port, force_retry);
    cmeta_mutex_unlock(&node->mutex);
    if (peer) {
        return p2p_peer_connect(peer);
    }

    peer = p2p_peer_create(node, ip, port);
    if (!peer) {
        return P2P_ERR_NO_MEM;
    }
    peer->keep_entry = 1;

    cmeta_mutex_lock(&node->mutex);
    existing_peer = p2p_prepare_connect_peer_locked(node, ip, port, force_retry);
    if (existing_peer) {
        cmeta_mutex_unlock(&node->mutex);
        p2p_peer_destroy(peer);
        return p2p_peer_connect(existing_peer);
    }
    p2p_node_add_peer_locked(node, peer);
    added_to_table = p2p_node_find_peer_by_endpoint_locked(node, ip, port) == peer;
    if (!added_to_table) {
        cmeta_mutex_unlock(&node->mutex);
        p2p_peer_destroy(peer);
        return P2P_ERR_NO_MEM;
    }
    cmeta_mutex_unlock(&node->mutex);

    ret = p2p_peer_connect(peer);
    if (ret != P2P_OK) {
        if (added_to_table) {
            cmeta_mutex_lock(&node->mutex);
            p2p_node_remove_peer_by_endpoint_locked(node, ip, port);
            cmeta_mutex_unlock(&node->mutex);
        }
        p2p_peer_destroy(peer);
        return ret;
    }
    return P2P_OK;
}


int p2p_connect(p2p_node_t *node, const char *ip, int port) {
    return p2p_connect_internal(node, ip, port, 1);
}

int p2p_connect_candidate(p2p_node_t *node, const char *ip, int port) {
    return p2p_connect_internal(node, ip, port, 0);
}


int p2p_peer_get_info_ex(p2p_peer_t *peer, p2p_peer_info_ex_t *info) {
    p2p_node_t *node = NULL;

    if (!peer || !info) return P2P_ERR_INVALID_ARG;

    node = peer->node;
    if (node) {
        cmeta_mutex_lock(&node->mutex);
    }
    p2p_peer_fill_info_ex_locked(peer, info);
    if (node) {
        cmeta_mutex_unlock(&node->mutex);
    }
    return P2P_OK;
}


int p2p_send_message(p2p_node_t *node, p2p_peer_t *peer, p2p_msg_type_t type,
                               const void *payload, size_t len) {
    if (!node || (!payload && len != 0) ||
        len > P2P_NOISE_MAX_PLAINTEXT_SIZE - 8U) {
        return P2P_ERR_INVALID_ARG;
    }
    p2p_message_t *msg = (p2p_message_t *)calloc(1, sizeof(p2p_message_t));
    if (!msg) return P2P_ERR_NO_MEM;

    p2p_message_init(msg, type);
    if (len > 0) {
        memcpy(msg->payload.raw, payload, len);
        msg->header.payload_len = (uint16_t)len;
    }

    if (peer) {
        int ret = p2p_peer_send(peer, msg);
        free(msg);
        return ret;
    }

    /* Broadcast */
    p2p_node_broadcast(node, msg);
    free(msg);
    return P2P_OK;
}


int p2p_peer_connect(p2p_peer_t *peer) {
    if (!peer || !peer->node) return P2P_ERR_INVALID_ARG;
    if (!peer->node->network_ops || !peer->node->network_ops->connect)
        return P2P_ERR_INVALID_STATE;
    return peer->node->network_ops->connect(peer, peer->node->network_context);
}
