/**
 * kademlia_rpc.c - Kademlia Network RPC Engine
 */

#include "../internal.h"
#include <tlog.h>
#include <stdlib.h>
#include <string.h>

/* =============================================================================
 * Iterative Lookup Implementation
 * ============================================================================= */

/* =============================================================================
 * Helper Functions
 * ============================================================================= */

typedef enum {
    LOOKUP_WAVE_ACTION_NONE = 0,
    LOOKUP_WAVE_ACTION_SEND,
    LOOKUP_WAVE_ACTION_CONNECT
} lookup_wave_action_type_t;

typedef struct {
    lookup_wave_action_type_t type;
    p2p_peer_t *peer;
    p2p_msg_type_t msg_type;
    uint8_t target[KADEMLIA_ID_BYTES];
    int candidate_index;
    char ip[P2P_MAX_IP];
    int port;
} lookup_wave_action_t;

typedef struct {
    p2p_dht_lookup_t *finished_lookup;
    uint32_t progress_request_id;
    int should_progress;
} lookup_progress_decision_t;

static p2p_dht_lookup_t *lookup_detach_locked(p2p_node_t *node,
                                              p2p_dht_lookup_t *lookup);

static void lookup_sort_candidates(p2p_dht_lookup_t *lookup) {
    /* Bubble sort for simplicity in small candidate list */
    for (int i = 0; i < lookup->candidate_count - 1; i++) {
        for (int j = i + 1; j < lookup->candidate_count; j++) {
            kad_id_t target, id_i, id_j;
            memcpy(target.bytes, lookup->target, KADEMLIA_ID_BYTES);
            memcpy(id_i.bytes, lookup->candidates[i].id, KADEMLIA_ID_BYTES);
            memcpy(id_j.bytes, lookup->candidates[j].id, KADEMLIA_ID_BYTES);
            
            if (kad_id_distance_cmp(&target, &id_i, &id_j) > 0) {
                kad_lookup_node_t tmp = lookup->candidates[i];
                lookup->candidates[i] = lookup->candidates[j];
                lookup->candidates[j] = tmp;
            }
        }
    }
}

static int lookup_candidate_exists(const p2p_dht_lookup_t *lookup,
                                   const char *ip,
                                   int port) {
    if (!lookup || !ip) {
        return 0;
    }

    for (int i = 0; i < lookup->candidate_count; i++) {
        if (lookup->candidates[i].port == port &&
            strcmp(lookup->candidates[i].ip, ip) == 0) {
            return 1;
        }
    }

    return 0;
}

static void lookup_add_candidate(p2p_dht_lookup_t *lookup,
                                 const uint8_t *id,
                                 const char *ip,
                                 int port) {
    kad_lookup_node_t *candidate = NULL;
    kad_id_t derived_id;

    if (!lookup || !ip || port <= 0) {
        return;
    }
    if (lookup->candidate_count >= KADEMLIA_MAX_LOOKUP_NODES) {
        return;
    }
    if (lookup_candidate_exists(lookup, ip, port)) {
        return;
    }

    candidate = &lookup->candidates[lookup->candidate_count++];
    if (id && !p2p_id_is_zero(id)) {
        memcpy(candidate->id, id, KADEMLIA_ID_BYTES);
    } else {
        p2p_endpoint_to_id(ip, port, &derived_id);
        memcpy(candidate->id, derived_id.bytes, KADEMLIA_ID_BYTES);
    }
    strncpy(candidate->ip, ip, P2P_MAX_IP - 1);
    candidate->port = (uint16_t)port;
}

static int lookup_send_request_raw(p2p_msg_type_t type,
                                   uint32_t request_id,
                                   const uint8_t *target,
                                   p2p_peer_t *peer) {
    p2p_message_t *msg = NULL;

    if (!target || !peer || !peer->is_connected) {
        return 0;
    }

    msg = (p2p_message_t *)calloc(1, sizeof(p2p_message_t));
    if (!msg) {
        return 0;
    }

    p2p_message_init(msg, type);
    msg->header.request_id = request_id;
    if (type == P2P_MSG_DHT_FIND_NODE || type == P2P_MSG_DHT_GET) {
        memcpy(msg->payload.dht_find_node.target_id, target, KADEMLIA_ID_BYTES);
        msg->header.payload_len = sizeof(p2p_dht_find_node_payload_t);
    } else {
        free(msg);
        return 0;
    }

    if (p2p_peer_send(peer, msg) != P2P_OK) {
        free(msg);
        return 0;
    }

    free(msg);
    return 1;
}

static void lookup_finish_detached(p2p_dht_lookup_t *lookup) {
    if (!lookup) {
        return;
    }

    TLOG_INFO("[P2P] DHT lookup finished (request_id={})", lookup->request_id);
    if (lookup->callback) {
        lookup->callback(lookup, lookup->user_data);
    }
    if (lookup->cleanup && lookup->user_data) {
        lookup->cleanup(lookup->user_data);
    }
    free(lookup);
}

static p2p_dht_lookup_t *lookup_detach_locked(p2p_node_t *node,
                                              p2p_dht_lookup_t *lookup) {
    if (!node || !lookup) {
        return NULL;
    }

    HASH_DEL(node->dht_lookups, lookup);
    return lookup;
}

static void lookup_merge_response_candidates(p2p_dht_lookup_t *lookup,
                                             p2p_node_t *node,
                                             const p2p_dht_response_payload_t *res) {
    if (!lookup || !node || !res) {
        return;
    }

    for (int i = 0; i < res->node_count; i++) {
        if (strcmp(res->nodes[i].ip, node->ip) == 0 &&
            res->nodes[i].port == node->port) {
            continue;
        }

        lookup_add_candidate(lookup,
                             res->nodes[i].id,
                             res->nodes[i].ip,
                             res->nodes[i].port);
    }
}

static p2p_dht_lookup_t *lookup_try_resolve_get_hit_locked(p2p_node_t *node,
                                                           p2p_dht_lookup_t *lookup,
                                                           p2p_peer_t *peer,
                                                           const p2p_dht_response_payload_t *res) {
    kad_id_t key;
    p2p_peer_info_ex_t peer_info = {0};

    if (!node || !lookup || !peer || !res) {
        return NULL;
    }
    if (lookup->type != P2P_MSG_DHT_GET || !res->found || res->data_len == 0) {
        return NULL;
    }

    memcpy(key.bytes, lookup->target, KADEMLIA_ID_BYTES);
    if (kademlia_store(node->kad_dht, &key, res->data, res->data_len) == 0) {
        p2p_peer_fill_info_ex_locked(peer, &peer_info);
        TLOG_DEBUG("[P2P] DHT GET resolved from {}:{} (len={})",
                   peer_info.ip, peer_info.port, res->data_len);
    }

    return lookup_detach_locked(node, lookup);
}

static int lookup_has_uncontacted_candidates(const p2p_dht_lookup_t *lookup) {
    if (!lookup) {
        return 0;
    }

    for (int i = 0; i < lookup->candidate_count; i++) {
        if (!lookup->candidates[i].contacted) {
            return 1;
        }
    }

    return 0;
}

static lookup_progress_decision_t lookup_decide_progress_locked(p2p_node_t *node,
                                                                p2p_dht_lookup_t *lookup) {
    lookup_progress_decision_t decision;

    memset(&decision, 0, sizeof(decision));
    if (!node || !lookup) {
        return decision;
    }

    if (lookup->active_requests > 0) {
        return decision;
    }
    if (lookup_has_uncontacted_candidates(lookup)) {
        decision.progress_request_id = lookup->request_id;
        decision.should_progress = 1;
        return decision;
    }

    decision.finished_lookup = lookup_detach_locked(node, lookup);
    return decision;
}

static int lookup_is_self_endpoint(const p2p_node_t *node,
                                   const char *ip,
                                   int port) {
    if (!node || !ip || port != node->port) {
        return 0;
    }

    if (strcmp(ip, node->ip) == 0) {
        return 1;
    }

    if (strcmp(node->ip, "0.0.0.0") == 0 || strcmp(node->ip, "::") == 0) {
        return strcmp(ip, "127.0.0.1") == 0 ||
               strcmp(ip, "::1") == 0 ||
               strcmp(ip, "localhost") == 0;
    }

    return 0;
}

static p2p_peer_t *lookup_find_connected_identity_locked(
    const p2p_node_t *node, const kad_lookup_node_t *candidate) {
    p2p_peer_entry_t *entry = NULL;
    p2p_peer_entry_t *tmp = NULL;

    if (!node || !candidate || p2p_id_is_zero(candidate->id)) {
        return NULL;
    }

    HASH_ITER(hh, node->peers_table, entry, tmp) {
        p2p_peer_t *peer = entry->peer;

        if (!peer || !peer->is_connected || p2p_id_is_zero(peer->id)) {
            continue;
        }
        if (memcmp(peer->id, candidate->id, P2P_DHT_KEY_SIZE) != 0) {
            continue;
        }
        if (!peer->destroying && peer->conn &&
            peer->state == P2P_PEER_STATE_CONNECTED) {
            return peer;
        }
    }

    return NULL;
}

static int lookup_prepare_wave_action_locked(p2p_node_t *node,
                                             p2p_dht_lookup_t *lookup,
                                             lookup_wave_action_t *action) {
    if (!node || !lookup || !action) {
        return 0;
    }

    memset(action, 0, sizeof(*action));
    action->candidate_index = -1;

    for (int i = 0; i < lookup->candidate_count; i++) {
        p2p_peer_entry_t *entry = NULL;
        p2p_peer_t *peer = NULL;

        if (lookup->candidates[i].contacted) {
            continue;
        }
        if (lookup_is_self_endpoint(node,
                                    lookup->candidates[i].ip,
                                    lookup->candidates[i].port)) {
            lookup->candidates[i].contacted = 1;
            return 1;
        }

        entry = peer_table_find(node->peers_table,
                                lookup->candidates[i].ip,
                                lookup->candidates[i].port);
        peer = entry ? entry->peer : NULL;
        if (peer && peer->is_connected && !peer->destroying && peer->conn &&
            peer->state == P2P_PEER_STATE_CONNECTED) {
            if (!p2p_peer_hold_locked(peer)) {
                continue;
            }
            action->type = LOOKUP_WAVE_ACTION_SEND;
            action->peer = peer;
            action->msg_type = lookup->type;
            memcpy(action->target, lookup->target, sizeof(action->target));
            action->candidate_index = i;
            return 1;
        }

        peer = lookup_find_connected_identity_locked(
            node, &lookup->candidates[i]);
        if (peer) {
            if (!p2p_peer_hold_locked(peer)) {
                continue;
            }
            action->type = LOOKUP_WAVE_ACTION_SEND;
            action->peer = peer;
            action->msg_type = lookup->type;
            memcpy(action->target, lookup->target, sizeof(action->target));
            action->candidate_index = i;
            return 1;
        }

        action->type = LOOKUP_WAVE_ACTION_CONNECT;
        action->msg_type = lookup->type;
        strncpy(action->ip, lookup->candidates[i].ip, sizeof(action->ip) - 1);
        action->port = lookup->candidates[i].port;
        return 1;
    }

    return 0;
}

static int lookup_mark_sent_request_locked(p2p_dht_lookup_t *lookup,
                                           const lookup_wave_action_t *action) {
    kad_lookup_node_t *candidate = NULL;

    if (!lookup || !action || !action->peer) {
        return 0;
    }
    if (action->candidate_index < 0 ||
        action->candidate_index >= lookup->candidate_count) {
        return 0;
    }

    candidate = &lookup->candidates[action->candidate_index];
    if ((strcmp(candidate->ip, action->peer->ip) != 0 ||
         candidate->port != action->peer->port) &&
        (p2p_id_is_zero(candidate->id) ||
         p2p_id_is_zero(action->peer->id) ||
         memcmp(candidate->id, action->peer->id,
                P2P_DHT_KEY_SIZE) != 0)) {
        return 0;
    }

    candidate->contacted = 1;
    lookup->active_requests++;
    return 1;
}

static void lookup_mark_candidate_contacted_locked(p2p_dht_lookup_t *lookup,
                                                   const lookup_wave_action_t *action) {
    if (!lookup || !action) {
        return;
    }
    if (action->candidate_index < 0 ||
        action->candidate_index >= lookup->candidate_count) {
        return;
    }

    lookup->candidates[action->candidate_index].contacted = 1;
}

static void lookup_seed_from_kad_locked(p2p_node_t *node,
                                        p2p_dht_lookup_t *lookup,
                                        const uint8_t *target) {
    kad_id_t kad_target;
    kad_node_t **initial = NULL;

    if (!node || !lookup || !target) {
        return;
    }

    memcpy(kad_target.bytes, target, KADEMLIA_ID_BYTES);
    initial = kademlia_find_node(node->kad_dht, &kad_target, KADEMLIA_K);
    if (!initial) {
        return;
    }

    for (int i = 0; i < KADEMLIA_K && initial[i]; i++) {
        if (lookup_is_self_endpoint(node, initial[i]->ip, initial[i]->port)) {
            continue;
        }
        lookup_add_candidate(lookup,
                             initial[i]->id.bytes,
                             initial[i]->ip,
                             initial[i]->port);
        if (lookup->candidate_count >= KADEMLIA_MAX_LOOKUP_NODES) {
            break;
        }
    }
    free(initial);
}

static void lookup_seed_from_connected_peers_locked(p2p_node_t *node,
                                                    p2p_dht_lookup_t *lookup) {
    p2p_peer_entry_t *entry = NULL;
    p2p_peer_entry_t *tmp = NULL;

    if (!node || !lookup) {
        return;
    }

    HASH_ITER(hh, node->peers_table, entry, tmp) {
        p2p_peer_t *peer = entry->peer;

        if (!peer || !peer->is_connected) {
            continue;
        }
        if (p2p_id_is_zero(peer->id)) {
            continue;
        }
        if (lookup_is_self_endpoint(node, peer->ip, peer->port)) {
            continue;
        }

        lookup_add_candidate(lookup, peer->id, peer->ip, peer->port);
        if (lookup->candidate_count >= KADEMLIA_MAX_LOOKUP_NODES) {
            break;
        }
    }
}

static void lookup_next_wave_by_id(p2p_node_t *node, uint32_t request_id) {
    int sent = 0;

    while (sent < KADEMLIA_ALPHA) {
        lookup_wave_action_t action;
        int progressed = 0;

        turbo_mutex_lock(&node->mutex);
        p2p_dht_lookup_t *lookup = p2p_dht_lookup_find(node, request_id);
        if (!lookup) {
            turbo_mutex_unlock(&node->mutex);
            return;
        }
        progressed = lookup_prepare_wave_action_locked(node, lookup, &action);
        turbo_mutex_unlock(&node->mutex);

        if (action.type == LOOKUP_WAVE_ACTION_SEND) {
            int send_ok = lookup_send_request_raw(action.msg_type,
                                                  request_id,
                                                  action.target,
                                                  action.peer);

            turbo_mutex_lock(&node->mutex);
            lookup = p2p_dht_lookup_find(node, request_id);
            if (lookup && send_ok &&
                lookup_mark_sent_request_locked(lookup, &action)) {
                sent++;
                progressed = 1;
            } else if (lookup) {
                lookup_mark_candidate_contacted_locked(lookup, &action);
                progressed = 1;
            }
            turbo_mutex_unlock(&node->mutex);
            p2p_peer_release(action.peer);
        }

        if (action.type == LOOKUP_WAVE_ACTION_CONNECT) {
            (void)p2p_connect_candidate(node, action.ip, action.port);
            return;
        }
        if (!progressed) {
            return;
        }
    }
}

p2p_dht_lookup_t *p2p_dht_lookup_find(p2p_node_t *node, uint32_t request_id) {
    p2p_dht_lookup_t *lookup = NULL;

    if (!node) {
        return NULL;
    }

    HASH_FIND(hh, node->dht_lookups, &request_id, sizeof(request_id), lookup);
    return lookup;
}

void p2p_dht_lookup_finish(p2p_node_t *node, p2p_dht_lookup_t *lookup) {
    if (!node || !lookup) return;

    turbo_mutex_lock(&node->mutex);
    lookup = lookup_detach_locked(node, lookup);
    turbo_mutex_unlock(&node->mutex);
    lookup_finish_detached(lookup);
}

void p2p_dht_lookup_try_progress(p2p_node_t *node) {
    p2p_dht_lookup_t *lookup = NULL;
    p2p_dht_lookup_t *tmp = NULL;
    uint32_t request_ids[KADEMLIA_MAX_LOOKUP_NODES];
    int request_count = 0;

    if (!node || !node->dht_lookups) {
        return;
    }

    turbo_mutex_lock(&node->mutex);
    HASH_ITER(hh, node->dht_lookups, lookup, tmp) {
        if (lookup->active_requests >= KADEMLIA_ALPHA) {
            continue;
        }
        if (request_count < KADEMLIA_MAX_LOOKUP_NODES) {
            request_ids[request_count++] = lookup->request_id;
        }
    }
    turbo_mutex_unlock(&node->mutex);

    for (int i = 0; i < request_count; i++) {
        lookup_next_wave_by_id(node, request_ids[i]);
    }
}

/* =============================================================================
 * Public API
 * ============================================================================= */

p2p_dht_lookup_t *p2p_dht_lookup_start(p2p_node_t *node, const uint8_t *target, p2p_msg_type_t type) {
    p2p_dht_lookup_t *lookup = NULL;

    if (!node || !target) return NULL;

    lookup = (p2p_dht_lookup_t*)calloc(1, sizeof(p2p_dht_lookup_t));
    if (!lookup) return NULL;

    lookup->request_id = p2p_generate_request_id();
    memcpy(lookup->target, target, KADEMLIA_ID_BYTES);
    lookup->type = type;

    turbo_mutex_lock(&node->mutex);
    lookup_seed_from_kad_locked(node, lookup, target);
    lookup_seed_from_connected_peers_locked(node, lookup);

    if (lookup->candidate_count == 0) {
        turbo_mutex_unlock(&node->mutex);
        TLOG_DEBUG("[P2P] Skipping DHT lookup without candidates");
        free(lookup);
        return NULL;
    }

    lookup_sort_candidates(lookup);
    HASH_ADD(hh, node->dht_lookups, request_id, sizeof(lookup->request_id), lookup);
    turbo_mutex_unlock(&node->mutex);
    lookup_next_wave_by_id(node, lookup->request_id);

    return lookup;
}

int p2p_dht_lookup_on_response(p2p_node_t *node, p2p_peer_t *peer, const p2p_message_t *msg) {
    p2p_dht_lookup_t *lookup = NULL;
    lookup_progress_decision_t decision;
    p2p_dht_lookup_t *finished_lookup = NULL;
    const p2p_dht_response_payload_t *res = NULL;

    if (!node || !peer || !msg) {
        return P2P_ERR_INVALID_ARG;
    }

    turbo_mutex_lock(&node->mutex);
    lookup = p2p_dht_lookup_find(node, msg->header.request_id);
    if (!lookup) {
        turbo_mutex_unlock(&node->mutex);
        return P2P_OK;
    }

    res = &msg->payload.dht_response;
    finished_lookup = lookup_try_resolve_get_hit_locked(node, lookup, peer, res);
    if (finished_lookup) {
        turbo_mutex_unlock(&node->mutex);
        lookup_finish_detached(finished_lookup);
        return P2P_OK;
    }

    lookup->active_requests--;
    lookup_merge_response_candidates(lookup, node, res);
    lookup_sort_candidates(lookup);
    decision = lookup_decide_progress_locked(node, lookup);

    turbo_mutex_unlock(&node->mutex);
    if (decision.finished_lookup) {
        lookup_finish_detached(decision.finished_lookup);
        return P2P_OK;
    }
    if (decision.should_progress) {
        lookup_next_wave_by_id(node, decision.progress_request_id);
    }
    return P2P_OK;
}
