#include "peer_cnet.h"
#include <salts/clock.h>
#include <string.h>

static int connected(p2p_connection_t *connection, void *context) {
    p2p_peer_t *peer = context;
    int result = P2P_OK;
    if (!p2p_peer_hold(peer)) return P2P_ERR_INVALID_STATE;
    if (peer->conn && peer->conn != connection) {
        p2p_peer_release(peer);
        return P2P_ERR_INVALID_STATE;
    }
    peer->conn = connection;
    result = p2p_cnet_connection_set_send_hwm(connection, peer->node->security_config.send_hwm_bytes);
    if (result != P2P_OK) {
        p2p_peer_release(peer);
        return result;
    }
    if (connection->type == P2P_CONN_INBOUND) {
        uint8_t preface[P2P_SECURE_PREFACE_SIZE], binding[P2P_COOKIE_BINDING_SIZE];
        memcpy(preface, peer->remote_preface, sizeof(preface));
        memcpy(binding, peer->cookie_binding, sizeof(binding));
        peer->connect_time = peer->last_seen = salts_hrtime();
        result = p2p_peer_start_inbound_handshake_after_cookie(peer, preface, binding);
        p2p_crypto_wipe(preface, sizeof(preface));
        p2p_crypto_wipe(binding, sizeof(binding));
    } else {
        p2p_peer_transport_connected(peer);
        if (!peer->conn) result = P2P_ERR_NETWORK;
    }
    p2p_peer_release(peer);
    return result;
}

static int receive(p2p_connection_t *connection, const uint8_t *bytes,
    size_t length, size_t *consumed, void *context) {
    p2p_peer_t *peer = context;
    int result;
    if (!p2p_peer_hold(peer)) return P2P_ERR_INVALID_STATE;
    if (peer->conn != connection) {
        p2p_peer_release(peer);
        return P2P_ERR_INVALID_STATE;
    }
    result = p2p_peer_on_data(peer, bytes, length);
    if (result == P2P_OK) *consumed = length;
    else p2p_node_record_security_failure(peer->node, peer->security_stage, result);
    p2p_peer_release(peer);
    return result;
}

static void closed(p2p_connection_t *connection, int status, void *context) {
    p2p_peer_t *peer = context;
    if (!p2p_peer_hold(peer)) return;
    /* Admission can reject a prepared descriptor before connected runs. */
    if (!peer->conn) peer->conn = connection;
    if (peer->conn == connection) {
        if (status != P2P_OK)
            p2p_node_record_security_failure(peer->node, peer->security_stage, status);
        p2p_peer_transport_closed(peer, peer->keep_entry ? 0 : 1);
    }
    p2p_peer_release(peer);
}

static p2p_cnet_callbacks_t callbacks(p2p_peer_t *peer) {
    p2p_cnet_callbacks_t result = {connected, receive, NULL, closed, peer};
    return result;
}

int p2p_peer_connect_cnet(p2p_peer_t *peer, p2p_cnet_owner_t *owner) {
    cnet_stream_peer remote = {0};
    p2p_cnet_callbacks_t events;
    int start = 0, result;
    if (!owner || !peer || peer->port < 1 || peer->port > UINT16_MAX)
        return P2P_ERR_INVALID_ARG;
    if (inet_pton(AF_INET, peer->ip, remote.address) == 1)
        remote.family = CNET_DATAGRAM_ADDRESS_IPV4;
    else if (inet_pton(AF_INET6, peer->ip, remote.address) == 1)
        remote.family = CNET_DATAGRAM_ADDRESS_IPV6;
    else return P2P_ERR_INVALID_ARG;
    result = p2p_peer_prepare_connect(peer, &start);
    if (result != P2P_OK || !start) return result;
    remote.port = (uint16_t)peer->port;
    events = callbacks(peer);
    result = p2p_cnet_owner_connect(owner, &remote, &events, &peer->conn);
    if (result == P2P_OK) {
        peer->state = P2P_PEER_STATE_CONNECTING;
        peer->connect_time = salts_hrtime();
    } else p2p_node_release_transport_send_capacity(peer->node, peer);
    return result;
}

int p2p_peer_prepare_cnet_inbound(p2p_peer_t *peer,
    const uint8_t preface[P2P_SECURE_PREFACE_SIZE],
    const uint8_t binding[P2P_COOKIE_BINDING_SIZE], p2p_cnet_callbacks_t *output) {
    int result;
    if (!peer || !peer->node || !preface || !binding || !output)
        return P2P_ERR_INVALID_ARG;
    if (peer->destroying || peer->conn || peer->private_key_operation ||
        peer->security_send_action || peer->state != P2P_PEER_STATE_DISCONNECTED)
        return P2P_ERR_INVALID_STATE;
    result = p2p_node_reserve_transport_send_capacity(peer->node, peer);
    if (result != P2P_OK) return result;
    memcpy(peer->remote_preface, preface, P2P_SECURE_PREFACE_SIZE);
    memcpy(peer->cookie_binding, binding, P2P_COOKIE_BINDING_SIZE);
    peer->state = P2P_PEER_STATE_HANDSHAKING;
    *output = callbacks(peer);
    return P2P_OK;
}
