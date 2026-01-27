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

static int lookup_compare(const void *a, const void *b, void *user_data) {
    kad_id_t target;
    memcpy(target.bytes, (uint8_t*)user_data, KADEMLIA_ID_BYTES);
    
    kad_id_t id_a, id_b;
    memcpy(id_a.bytes, ((kad_lookup_node_t*)a)->id, KADEMLIA_ID_BYTES);
    memcpy(id_b.bytes, ((kad_lookup_node_t*)b)->id, KADEMLIA_ID_BYTES);
    
    return kad_id_distance_cmp(&target, &id_a, &id_b);
}

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

static void lookup_next_wave(p2p_node_t *node, p2p_dht_lookup_t *lookup) {
    int sent = 0;
    for (int i = 0; i < lookup->candidate_count && sent < KADEMLIA_ALPHA; i++) {
        if (!lookup->candidates[i].contacted) {
            p2p_peer_t *peer = peer_table_find(node->peers_table, 
                                             lookup->candidates[i].ip, 
                                             lookup->candidates[i].port) ? 
                               peer_table_find(node->peers_table, 
                                             lookup->candidates[i].ip, 
                                             lookup->candidates[i].port)->peer : NULL;
            
            if (!peer) {
                peer = p2p_peer_create(node, lookup->candidates[i].ip, lookup->candidates[i].port);
                if (peer) {
                    p2p_peer_connect(peer);
                    peer_table_add(&node->peers_table, peer);
                }
            }

            if (peer && peer->is_connected) {
                p2p_message_t *msg = (p2p_message_t *)calloc(1, sizeof(p2p_message_t));
                if (msg) {
                    p2p_message_init(msg, lookup->type);
                    if (lookup->type == P2P_MSG_DHT_FIND_NODE || lookup->type == P2P_MSG_DHT_GET) {
                        memcpy(msg->payload.dht_find_node.target_id, lookup->target, KADEMLIA_ID_BYTES);
                    }
                    p2p_peer_send(peer, msg);
                    free(msg);
                }
                lookup->candidates[i].contacted = 1;
                lookup->active_requests++;
                sent++;
            }
        }
    }
}

void p2p_dht_lookup_finish(p2p_node_t *node) {
    if (!node->active_lookup) return;
    TLOG_INFO("[P2P] DHT lookup for %.8s finished", (char*)node->active_lookup->target);
    free(node->active_lookup);
    node->active_lookup = NULL;
}

/* =============================================================================
 * Public API
 * ============================================================================= */

int p2p_dht_lookup_start(p2p_node_t *node, const uint8_t *target, p2p_msg_type_t type) {
    if (!node || !target) return P2P_ERR_INVALID_ARG;

    /* Cleanup previous lookup if any */
    if (node->active_lookup) p2p_dht_lookup_finish(node);

    node->active_lookup = (p2p_dht_lookup_t*)calloc(1, sizeof(p2p_dht_lookup_t));
    if (!node->active_lookup) return P2P_ERR_NO_MEM;

    memcpy(node->active_lookup->target, target, KADEMLIA_ID_BYTES);
    node->active_lookup->type = type;

    /* Get initial alpha nodes */
    kad_id_t kad_target;
    memcpy(kad_target.bytes, target, KADEMLIA_ID_BYTES);
    kad_node_t **initial = kademlia_find_node(node->kad_dht, &kad_target, KADEMLIA_K);
    
    if (initial) {
        for (int i = 0; i < KADEMLIA_K && initial[i]; i++) {
            kad_lookup_node_t *c = &node->active_lookup->candidates[node->active_lookup->candidate_count++];
            memcpy(c->id, initial[i]->id.bytes, KADEMLIA_ID_BYTES);
            strncpy(c->ip, initial[i]->ip, P2P_MAX_IP - 1);
            c->port = initial[i]->port;
            if (node->active_lookup->candidate_count >= KADEMLIA_MAX_LOOKUP_NODES) break;
        }
        free(initial);
    }

    if (node->active_lookup->candidate_count == 0) {
        TLOG_WARN("[P2P] No DHT candidates to start lookup");
        p2p_dht_lookup_finish(node);
        return P2P_ERR_NOT_FOUND;
    }

    lookup_sort_candidates(node->active_lookup);
    lookup_next_wave(node, node->active_lookup);

    return P2P_OK;
}

int p2p_dht_lookup_on_response(p2p_node_t *node, p2p_peer_t *peer, const p2p_message_t *msg) {
    p2p_dht_lookup_t *lookup = node->active_lookup;
    if (!lookup) return P2P_OK;

    lookup->active_requests--;

    /* Add new candidates from response */
    const p2p_dht_response_payload_t *res = &msg->payload.dht_response;
    for (int i = 0; i < res->node_count; i++) {
        /* Check if already in candidates */
        int exists = 0;
        for (int j = 0; j < lookup->candidate_count; j++) {
            if (memcmp(lookup->candidates[j].id, res->nodes[i].id, KADEMLIA_ID_BYTES) == 0) {
                exists = 1;
                break;
            }
        }

        if (!exists && lookup->candidate_count < KADEMLIA_MAX_LOOKUP_NODES) {
            kad_lookup_node_t *c = &lookup->candidates[lookup->candidate_count++];
            memcpy(c->id, res->nodes[i].id, KADEMLIA_ID_BYTES);
            strncpy(c->ip, res->nodes[i].ip, P2P_MAX_IP - 1);
            c->port = res->nodes[i].port;
        }
    }

    lookup_sort_candidates(lookup);

    if (lookup->active_requests <= 0) {
        /* If no more waves possible, finish */
        int found_new = 0;
        for (int i = 0; i < lookup->candidate_count; i++) {
            if (!lookup->candidates[i].contacted) {
                found_new = 1;
                break;
            }
        }
        
        if (found_new) {
            lookup_next_wave(node, lookup);
        } else {
            p2p_dht_lookup_finish(node);
        }
    }

    return P2P_OK;
}
