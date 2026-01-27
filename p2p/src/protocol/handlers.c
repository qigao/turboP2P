/**
 * handlers.c - P2P Protocol Handlers implementation
 * Professional version based on Kademlia DHT
 */

#include "handlers.h"
#include "../../src/internal.h"
#include "../protocol/message.h"
#include "../transfer/sender.h"
#include "../transfer/receiver.h"
#include <tlog.h>
#include <string.h>
#include <time.h>

/* =============================================================================
 * Dispatch Function
 * ============================================================================= */

void p2p_handlers_dispatch(p2p_node_t *node, p2p_peer_t *peer, const p2p_message_t *msg) {
    if (!node || !msg) return;

    p2p_msg_type_t type = (p2p_msg_type_t)msg->header.type;

    /* Basic connection checks */
    if (peer && !peer->is_connected && type != P2P_MSG_PING) {
        return;
    }

    switch (type) {
        case P2P_MSG_PING:
            p2p_handle_ping(node, peer, msg);
            break;
        case P2P_MSG_PONG:
            p2p_handle_pong(node, peer, msg);
            break;
        case P2P_MSG_DHT_FIND_NODE:
            p2p_handle_dht_find_node(node, peer, msg);
            break;
        case P2P_MSG_DHT_PUT:
            p2p_handle_dht_store(node, peer, msg);
            break;
        case P2P_MSG_DHT_GET:
            p2p_handle_dht_get(node, peer, msg);
            break;
        case P2P_MSG_DHT_RESPONSE:
            p2p_handle_dht_response(node, peer, msg);
            break;
        case P2P_MSG_CHUNK_REQUEST:
            p2p_sender_handle_chunk_request(node, peer, 
                                            msg->payload.chunk_request.transfer_id,
                                            msg->payload.chunk_request.chunk_index,
                                            msg->header.request_id);
            break;
        case P2P_MSG_CHUNK_DATA:
            p2p_receiver_handle_chunk_data(node, peer,
                                           msg->payload.chunk_data.transfer_id,
                                           msg->payload.chunk_data.chunk_index,
                                           msg->payload.chunk_data.chunk_hash,
                                           msg->payload.chunk_data.data,
                                           msg->payload.chunk_data.data_len,
                                           0); /* TODO: handle is_last correctly */
            break;
        case P2P_MSG_CUSTOM:
            if (node->on_message) {
                node->on_message(node, peer, msg->payload.raw, msg->header.payload_len, node->user_data);
            }
            break;
        default:
            TLOG_DEBUG("[P2P] No handler for msg type %s", p2p_message_type_name(type));
            break;
    }
}

/* =============================================================================
 * Core Handlers
 * ============================================================================= */

int p2p_handle_ping(p2p_node_t *node, p2p_peer_t *peer, const p2p_message_t *msg) {
    if (!node || !peer || !msg) return P2P_ERR_INVALID_ARG;

    /* Sync identity */
    memcpy(peer->id, msg->payload.ping.node_id, P2P_DHT_KEY_SIZE);
    
    /* Sync Vivaldi coordinates */
    memcpy(peer->coord.coords, msg->payload.ping.coords, sizeof(double)*4);
    peer->coord.height = msg->payload.ping.height;
    peer->coord.error = msg->payload.ping.error;

    /* Send PONG reply */
    p2p_message_t *reply = (p2p_message_t *)calloc(1, sizeof(p2p_message_t));
    if (!reply) return P2P_ERR_NO_MEM;

    reply->header.type = P2P_MSG_PONG;
    reply->header.request_id = msg->header.request_id;
    
    memcpy(reply->payload.ping.node_id, node->id, P2P_DHT_KEY_SIZE);
    strncpy(reply->payload.ping.ip, node->ip, P2P_MAX_IP - 1);
    reply->payload.ping.port = (uint16_t)node->port;
    
    /* Include our Vivaldi coords */
    memcpy(reply->payload.ping.coords, node->coord.coords, sizeof(double)*4);
    reply->payload.ping.height = node->coord.height;
    reply->payload.ping.error = node->coord.error;

    int ret = p2p_peer_send(peer, reply);
    free(reply);
    return ret;
}

int p2p_handle_pong(p2p_node_t *node, p2p_peer_t *peer, const p2p_message_t *msg) {
    if (!node || !peer || !msg) return P2P_ERR_INVALID_ARG;

    /* Update RTT and Vivaldi */
    uint64_t now = turbo_hrtime() / 1000000;
    uint64_t rtt = now - msg->payload.ping.timestamp;
    
    peer->avg_rtt_ms = (peer->avg_rtt_ms == 0) ? rtt : (uint64_t)(peer->avg_rtt_ms * 0.8 + rtt * 0.2);
    
    vivaldi_coord_t remote_coord;
    memcpy(remote_coord.coords, msg->payload.ping.coords, sizeof(double)*4);
    remote_coord.height = msg->payload.ping.height;
    remote_coord.error = msg->payload.ping.error;
    
    vivaldi_update(&node->coord, &remote_coord, (double)rtt);

    TLOG_DEBUG("[P2P] PONG from %s:%d (RTT=%llu ms)", peer->ip, peer->port, rtt);
    return P2P_OK;
}

/* =============================================================================
 * DHT Handlers
 * ============================================================================= */

int p2p_handle_dht_find_node(p2p_node_t *node, p2p_peer_t *peer, const p2p_message_t *msg) {
    if (!node || !peer || !msg) return P2P_ERR_INVALID_ARG;

    kad_id_t target;
    memcpy(target.bytes, msg->payload.dht_find_node.target_id, KADEMLIA_ID_BYTES);

    /* Find closest nodes in our routing table */
    kad_node_t **closest = kademlia_find_node(node->kad_dht, &target, KADEMLIA_K);
    
    p2p_message_t *response = (p2p_message_t *)calloc(1, sizeof(p2p_message_t));
    if (!response) return P2P_ERR_NO_MEM;

    response->header.type = P2P_MSG_DHT_RESPONSE;
    response->header.request_id = msg->header.request_id;
    response->payload.dht_response.found = 0;

    int count = 0;
    if (closest) {
        for (; closest[count] && count < KADEMLIA_K; count++) {
            memcpy(response->payload.dht_response.nodes[count].id, closest[count]->id.bytes, KADEMLIA_ID_BYTES);
            strncpy(response->payload.dht_response.nodes[count].ip, closest[count]->ip, P2P_MAX_IP - 1);
            response->payload.dht_response.nodes[count].port = closest[count]->port;
        }
        free(closest);
    }
    response->payload.dht_response.node_count = (uint8_t)count;

    int ret = p2p_peer_send(peer, response);
    free(response);
    return ret;
}

int p2p_handle_dht_store(p2p_node_t *node, p2p_peer_t *peer, const p2p_message_t *msg) {
    if (!node || !peer || !msg) return P2P_ERR_INVALID_ARG;

    kad_id_t key;
    memcpy(key.bytes, msg->payload.dht_store.key, KADEMLIA_ID_BYTES);

    /* Store value locally */
    int ret = kademlia_store(node->kad_dht, &key, 
                             msg->payload.dht_store.data, 
                             msg->payload.dht_store.data_len);

    TLOG_DEBUG("[P2P] DHT STORE from %s:%d (key=%.8s, len=%u) -> %s",
              peer->ip, peer->port, (char*)key.bytes, msg->payload.dht_store.data_len,
              ret == 0 ? "OK" : "ERR");

    /* We could send an ACK, but Kademlia usually doesn't require one for STORE */
    return P2P_OK;
}

int p2p_handle_dht_get(p2p_node_t *node, p2p_peer_t *peer, const p2p_message_t *msg) {
    if (!node || !peer || !msg) return P2P_ERR_INVALID_ARG;

    kad_id_t key;
    memcpy(key.bytes, msg->payload.dht_find_node.target_id, KADEMLIA_ID_BYTES);

    p2p_message_t *response = (p2p_message_t *)calloc(1, sizeof(p2p_message_t));
    if (!response) return P2P_ERR_NO_MEM;

    response->header.type = P2P_MSG_DHT_RESPONSE;
    response->header.request_id = msg->header.request_id;

    /* Try to find value locally */
    size_t data_len = sizeof(response->payload.dht_response.data);
    if (kademlia_find_value(node->kad_dht, &key, 
                            response->payload.dht_response.data, 
                            &data_len) == 0) {
        response->payload.dht_response.found = 1;
        response->payload.dht_response.data_len = (uint16_t)data_len;
        response->payload.dht_response.node_count = 0;
    } else {
        /* Not found, return closest nodes */
        response->payload.dht_response.found = 0;
        kad_node_t **closest = kademlia_find_node(node->kad_dht, &key, KADEMLIA_K);
        int count = 0;
        if (closest) {
            for (; closest[count] && count < KADEMLIA_K; count++) {
                memcpy(response->payload.dht_response.nodes[count].id, closest[count]->id.bytes, KADEMLIA_ID_BYTES);
                strncpy(response->payload.dht_response.nodes[count].ip, closest[count]->ip, P2P_MAX_IP - 1);
                response->payload.dht_response.nodes[count].port = closest[count]->port;
            }
            free(closest);
        }
        response->payload.dht_response.node_count = (uint8_t)count;
    }

    int ret = p2p_peer_send(peer, response);
    free(response);
    return ret;
}

int p2p_handle_dht_response(p2p_node_t *node, p2p_peer_t *peer, const p2p_message_t *msg) {
    if (!node || !peer || !msg) return P2P_ERR_INVALID_ARG;

    const p2p_dht_response_payload_t *res = &msg->payload.dht_response;
    TLOG_DEBUG("[P2P] DHT RESPONSE from %s:%d (%u nodes)", 
              peer->ip, peer->port, res->node_count);

    /* In a professional implementation, we'd update p2p_node_t's active_lookup state.
     * For now, we contribute discovered nodes to our routing table. */
    for (int i = 0; i < res->node_count; i++) {
        kad_node_t discovered;
        memcpy(discovered.id.bytes, res->nodes[i].id, KADEMLIA_ID_BYTES);
        strncpy(discovered.ip, res->nodes[i].ip, sizeof(discovered.ip) - 1);
        discovered.port = res->nodes[i].port;
        discovered.last_seen = (uint64_t)time(NULL);

        kad_routing_add_node(node->kad_dht->routing, &discovered);
    }

    /* Advance iterative lookup logic */
    p2p_dht_lookup_on_response(node, peer, msg);

    return P2P_OK;
}
