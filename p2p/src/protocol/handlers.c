/**
 * handlers.c - P2P Protocol Handlers implementation
 * Professional version based on Kademlia DHT
 */

#include "handlers.h"
#include "../../src/internal.h"
#include "../protocol/message.h"
#include "../transfer/sender.h"
#include "../transfer/receiver.h"
#include "../transfer/transfer.h"
#include <tlog.h>
#include <stddef.h>
#include <string.h>
#include <time.h>

static int p2p_ip_is_publishable(const char *ip) {
    return ip && ip[0] != '\0' &&
           strcmp(ip, "0.0.0.0") != 0 &&
           strcmp(ip, "::") != 0;
}

static int p2p_send_owned_message(p2p_peer_t *peer, p2p_message_t *msg) {
    int ret = P2P_ERR_INVALID_ARG;

    if (peer && msg) {
        ret = p2p_peer_send(peer, msg);
    }
    free(msg);
    return ret;
}

static void p2p_init_dht_response_message(p2p_message_t *response, uint32_t request_id) {
    if (!response) {
        return;
    }

    response->header.type = P2P_MSG_DHT_RESPONSE;
    response->header.request_id = request_id;
    response->header.payload_len = offsetof(p2p_dht_response_payload_t, data);
    response->payload.dht_response.found = 0;
    response->payload.dht_response.data_len = 0;
    response->payload.dht_response.node_count = 0;
}

static p2p_message_t *p2p_create_dht_response_message(uint32_t request_id) {
    p2p_message_t *response = (p2p_message_t *)calloc(1, sizeof(p2p_message_t));

    if (!response) {
        return NULL;
    }

    p2p_init_dht_response_message(response, request_id);
    return response;
}

static void p2p_fill_dht_response_nodes_locked(p2p_node_t *node,
                                               const kad_id_t *target,
                                               p2p_message_t *response) {
    kad_node_t **closest = NULL;
    int count = 0;

    if (!node || !target || !response) {
        return;
    }

    closest = kademlia_find_node(node->kad_dht, target, KADEMLIA_K);
    if (closest) {
        for (; closest[count] && count < KADEMLIA_K; count++) {
            memcpy(response->payload.dht_response.nodes[count].id,
                   closest[count]->id.bytes,
                   KADEMLIA_ID_BYTES);
            strncpy(response->payload.dht_response.nodes[count].ip,
                    closest[count]->ip,
                    P2P_MAX_IP - 1);
            response->payload.dht_response.nodes[count].port = closest[count]->port;
        }
        free(closest);
    }
    response->payload.dht_response.node_count = (uint8_t)count;
}

static void p2p_import_dht_response_nodes_locked(p2p_node_t *node,
                                                 const p2p_dht_response_payload_t *res) {
    if (!node || !res) {
        return;
    }

    for (int i = 0; i < res->node_count; i++) {
        p2p_node_add_route_locked(node, res->nodes[i].id, res->nodes[i].ip, res->nodes[i].port);
    }
}

static void p2p_fill_dht_get_response_locked(p2p_node_t *node,
                                             const kad_id_t *key,
                                             p2p_message_t *response) {
    size_t data_len = 0;

    if (!node || !key || !response) {
        return;
    }

    data_len = sizeof(response->payload.dht_response.data);
    if (kademlia_find_value(node->kad_dht, key,
                            response->payload.dht_response.data,
                            &data_len) == 0) {
        response->payload.dht_response.found = 1;
        response->payload.dht_response.data_len = (uint16_t)data_len;
        response->payload.dht_response.node_count = 0;
        response->header.payload_len =
            (uint16_t)(offsetof(p2p_dht_response_payload_t, data) + data_len);
        return;
    }

    p2p_fill_dht_response_nodes_locked(node, key, response);
}

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
        case P2P_MSG_FILE_GET:
            if (peer && msg->header.payload_len >= P2P_HASH_SIZE) {
                p2p_sender_handle_file_request(
                    node, peer, msg->payload.file_response.file_id,
                    P2P_DEFAULT_CHUNK_SIZE, msg->header.request_id);
            }
            break;
        case P2P_MSG_FILE_PUT:
            if (peer &&
                msg->header.payload_len >= sizeof(p2p_file_response_payload_t)) {
                p2p_receiver_handle_file_response(
                    node, peer, msg->header.request_id,
                    msg->payload.file_response.file_size,
                    msg->payload.file_response.total_chunks,
                    msg->payload.file_response.file_hash);
            }
            break;
        case P2P_MSG_CHUNK_REQUEST:
            if (peer &&
                msg->header.payload_len >= sizeof(p2p_chunk_request_payload_t)) {
                p2p_sender_handle_chunk_request(
                    node, peer, msg->payload.chunk_request.transfer_id,
                    msg->payload.chunk_request.chunk_index,
                    msg->header.request_id);
            }
            break;
        case P2P_MSG_CHUNK_DATA:
            if (peer &&
                msg->header.payload_len >= offsetof(p2p_chunk_data_payload_t, data) &&
                msg->payload.chunk_data.data_len <=
                    sizeof(msg->payload.chunk_data.data) &&
                msg->header.payload_len ==
                    offsetof(p2p_chunk_data_payload_t, data) +
                    msg->payload.chunk_data.data_len) {
                p2p_receiver_handle_chunk_data(
                    node, peer, msg->payload.chunk_data.transfer_id,
                    msg->payload.chunk_data.chunk_index,
                    msg->payload.chunk_data.chunk_hash,
                    msg->payload.chunk_data.data,
                    msg->payload.chunk_data.data_len, 0);
            }
            break;
        case P2P_MSG_FILE_ACK:
            if (peer &&
                msg->header.payload_len >= sizeof(p2p_file_ack_payload_t)) {
                p2p_sender_handle_file_ack(
                    node, peer, msg->payload.file_ack.transfer_id,
                    msg->payload.file_ack.success != 0);
            }
            break;
        case P2P_MSG_CUSTOM:
            if (node->on_message) {
                node->on_message(node, peer, msg->payload.raw, msg->header.payload_len, node->user_data);
            }
            break;
        default:
            TLOG_DEBUG("[P2P] No handler for msg type {}", p2p_message_type_name(type));
            break;
    }
}

/* =============================================================================
 * Core Handlers
 * ============================================================================= */

static void p2p_publish_peer_route(p2p_node_t *node, const p2p_ping_payload_t *ping) {
    if (!node || !ping || ping->port == 0 || !p2p_ip_is_publishable(ping->ip)) {
        return;
    }

    p2p_node_add_route_locked(node, ping->node_id, ping->ip, ping->port);
}

int p2p_handle_ping(p2p_node_t *node, p2p_peer_t *peer, const p2p_message_t *msg) {
    p2p_ping_payload_t reply_ping = {0};

    if (!node || !peer || !msg) return P2P_ERR_INVALID_ARG;

    turbo_mutex_lock(&node->mutex);
    /* Sync identity */
    memcpy(peer->id, msg->payload.ping.node_id, P2P_DHT_KEY_SIZE);
    p2p_publish_peer_route(node, &msg->payload.ping);
    
    /* Sync Vivaldi coordinates */
    memcpy(peer->coord.coords, msg->payload.ping.coords, sizeof(double)*4);
    peer->coord.height = msg->payload.ping.height;
    peer->coord.error = msg->payload.ping.error;

    memcpy(reply_ping.node_id, node->id, P2P_DHT_KEY_SIZE);
    if (p2p_ip_is_publishable(node->ip)) {
        strncpy(reply_ping.ip, node->ip, P2P_MAX_IP - 1);
    }
    reply_ping.port = (uint16_t)node->port;
    reply_ping.timestamp = msg->payload.ping.timestamp;
    memcpy(reply_ping.coords, node->coord.coords, sizeof(double) * 4);
    reply_ping.height = node->coord.height;
    reply_ping.error = node->coord.error;
    turbo_mutex_unlock(&node->mutex);

    /* Send PONG reply */
    p2p_message_t *reply = (p2p_message_t *)calloc(1, sizeof(p2p_message_t));
    if (!reply) return P2P_ERR_NO_MEM;

    reply->header.type = P2P_MSG_PONG;
    reply->header.request_id = msg->header.request_id;
    reply->header.payload_len = sizeof(p2p_ping_payload_t);
    memcpy(&reply->payload.ping, &reply_ping, sizeof(reply_ping));

    return p2p_send_owned_message(peer, reply);
}

int p2p_peer_record_rtt_sample_locked(p2p_peer_t *peer,
                                      uint64_t sent_ms,
                                      uint64_t received_ms) {
    uint64_t rtt_ms = 0;
    uint64_t delta_ms = 0;

    if (!peer || sent_ms == 0 || peer->outstanding_ping_ms != sent_ms) {
        return 0;
    }

    /* A matching response consumes the outstanding probe even when its clock
     * value is invalid, so one malformed response cannot pin the probe state. */
    peer->outstanding_ping_ms = 0;
    if (received_ms < sent_ms) {
        return 0;
    }

    rtt_ms = received_ms - sent_ms;
    if (rtt_ms > P2P_RTT_SAMPLE_MAX_MS) {
        return 0;
    }

    if (peer->rtt_sample_count == 0) {
        peer->avg_rtt_ms = rtt_ms;
        peer->rttvar_ms = rtt_ms / 2U;
    } else {
        delta_ms = peer->avg_rtt_ms > rtt_ms
            ? peer->avg_rtt_ms - rtt_ms
            : rtt_ms - peer->avg_rtt_ms;
        peer->rttvar_ms = (3U * peer->rttvar_ms + delta_ms) / 4U;
        peer->avg_rtt_ms = (7U * peer->avg_rtt_ms + rtt_ms) / 8U;
    }

    if (peer->rtt_sample_count < UINT32_MAX) {
        peer->rtt_sample_count++;
    }
    peer->last_rtt_sample_ms = received_ms;
    return 1;
}

int p2p_handle_pong(p2p_node_t *node, p2p_peer_t *peer, const p2p_message_t *msg) {
    p2p_peer_info_ex_t peer_info = {0};
    uint64_t now_ms = 0;
    uint64_t rtt_ms = 0;
    int sample_accepted = 0;

    if (!node || !peer || !msg) return P2P_ERR_INVALID_ARG;

    now_ms = turbo_hrtime() / 1000000U;
    turbo_mutex_lock(&node->mutex);
    memcpy(peer->id, msg->payload.ping.node_id, P2P_DHT_KEY_SIZE);
    p2p_publish_peer_route(node, &msg->payload.ping);

    sample_accepted = p2p_peer_record_rtt_sample_locked(
        peer, msg->payload.ping.timestamp, now_ms);
    if (sample_accepted) {
        vivaldi_coord_t remote_coord;

        rtt_ms = now_ms - msg->payload.ping.timestamp;
        memcpy(remote_coord.coords, msg->payload.ping.coords, sizeof(double) * 4);
        remote_coord.height = msg->payload.ping.height;
        remote_coord.error = msg->payload.ping.error;
        vivaldi_update(&node->coord, &remote_coord, (double)rtt_ms);
        p2p_peer_fill_info_ex_locked(peer, &peer_info);
    }
    turbo_mutex_unlock(&node->mutex);

    if (sample_accepted) {
        TLOG_DEBUG("[P2P] PONG from {}:{} (RTT={} ms)",
                   peer_info.ip, peer_info.port, rtt_ms);
    }
    return P2P_OK;
}

/* =============================================================================
 * DHT Handlers
 * ============================================================================= */

int p2p_handle_dht_find_node(p2p_node_t *node, p2p_peer_t *peer, const p2p_message_t *msg) {
    p2p_message_t *response = NULL;

    if (!node || !peer || !msg) return P2P_ERR_INVALID_ARG;
    if (msg->header.payload_len < sizeof(p2p_dht_find_node_payload_t)) {

        return P2P_ERR_INVALID_ARG;

    }


    kad_id_t target;
    memcpy(target.bytes, msg->payload.dht_find_node.target_id, KADEMLIA_ID_BYTES);

    response = p2p_create_dht_response_message(msg->header.request_id);
    if (!response) return P2P_ERR_NO_MEM;

    /* Find closest nodes in our routing table */
    turbo_mutex_lock(&node->mutex);
    p2p_fill_dht_response_nodes_locked(node, &target, response);
    turbo_mutex_unlock(&node->mutex);

    return p2p_send_owned_message(peer, response);
}

int p2p_handle_dht_store(p2p_node_t *node, p2p_peer_t *peer, const p2p_message_t *msg) {
    int ret = 0;
    p2p_peer_info_ex_t peer_info = {0};

    if (!node || !peer || !msg) return P2P_ERR_INVALID_ARG;
    if (msg->header.payload_len < offsetof(p2p_dht_store_payload_t, data)) {

        return P2P_ERR_INVALID_ARG;

    }

    if (msg->payload.dht_store.data_len > sizeof(msg->payload.dht_store.data) ||

        msg->header.payload_len != offsetof(p2p_dht_store_payload_t, data) +

                                      msg->payload.dht_store.data_len) {

        return P2P_ERR_INVALID_ARG;

    }

    p2p_peer_get_info_ex(peer, &peer_info);

    kad_id_t key;
    memcpy(key.bytes, msg->payload.dht_store.key, KADEMLIA_ID_BYTES);

    /* Store value locally */
    turbo_mutex_lock(&node->mutex);
    ret = kademlia_store(node->kad_dht, &key,
                         msg->payload.dht_store.data,
                         msg->payload.dht_store.data_len);
    turbo_mutex_unlock(&node->mutex);

    TLOG_DEBUG("[P2P] DHT STORE from {}:{} (len={}) -> {}",
              peer_info.ip, peer_info.port, msg->payload.dht_store.data_len,
              ret == 0 ? "OK" : "ERR");

    /* We could send an ACK, but Kademlia usually doesn't require one for STORE */
    return P2P_OK;
}

int p2p_handle_dht_get(p2p_node_t *node, p2p_peer_t *peer, const p2p_message_t *msg) {
    p2p_message_t *response = NULL;

    if (!node || !peer || !msg) return P2P_ERR_INVALID_ARG;
    if (msg->header.payload_len < sizeof(p2p_dht_find_node_payload_t)) {

        return P2P_ERR_INVALID_ARG;

    }


    kad_id_t key;
    memcpy(key.bytes, msg->payload.dht_find_node.target_id, KADEMLIA_ID_BYTES);

    response = p2p_create_dht_response_message(msg->header.request_id);
    if (!response) return P2P_ERR_NO_MEM;

    /* Try to find value locally */
    turbo_mutex_lock(&node->mutex);
    p2p_fill_dht_get_response_locked(node, &key, response);
    turbo_mutex_unlock(&node->mutex);

    return p2p_send_owned_message(peer, response);
}

int p2p_handle_dht_response(p2p_node_t *node, p2p_peer_t *peer, const p2p_message_t *msg) {
    p2p_peer_info_ex_t peer_info = {0};

    if (!node || !peer || !msg) return P2P_ERR_INVALID_ARG;
    if (msg->header.payload_len < offsetof(p2p_dht_response_payload_t, data)) {

        return P2P_ERR_INVALID_ARG;

    }

    p2p_peer_get_info_ex(peer, &peer_info);

    const p2p_dht_response_payload_t *res = &msg->payload.dht_response;
    if (res->node_count > KADEMLIA_K ||

        res->data_len > sizeof(res->data)) {

        return P2P_ERR_INVALID_ARG;

    }

    turbo_mutex_lock(&node->mutex);
    TLOG_DEBUG("[P2P] DHT RESPONSE from {}:{} ({} nodes)", 
              peer_info.ip, peer_info.port, res->node_count);

    p2p_import_dht_response_nodes_locked(node, res);
    turbo_mutex_unlock(&node->mutex);
    return p2p_dht_lookup_on_response(node, peer, msg);
}
