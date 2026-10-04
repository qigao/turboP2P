/* Legacy transport adapter; the protocol lives in peer.c. */
#include "peer_coronet.h"
#include <CoroNet/turbo_stream.h>
#include <tlog.h>

static turbo_stream_kind_t peer_stream_kind_from_ip(const char *ip) {
    struct in6_addr addr6;
    if (ip && inet_pton(AF_INET6, ip, &addr6) == 1) {
        return TURBO_STREAM_TCP6;
    }
    return TURBO_STREAM_TCP4;
}


int p2p_peer_connect_coronet(p2p_peer_t *peer) {
    int start = 0;
    int result = p2p_peer_prepare_connect(peer, &start);
    if (result != P2P_OK || !start) return result;
    turbo_stream_t *stream = turbo_stream_create(peer->node->ctx,
                                                 peer_stream_kind_from_ip(peer->ip));
    if (!stream) {
        TLOG_ERROR("[P2P] peer_connect: failed to create stream");
        p2p_node_release_transport_send_capacity(peer->node, peer);
        return P2P_ERR_NO_MEM;
    }
    if (turbo_stream_set_send_hwm(
            stream, peer->node->security_config.send_hwm_bytes) != 0) {
        turbo_stream_destroy(stream);
        p2p_node_release_transport_send_capacity(peer->node, peer);
        return P2P_ERR_INVALID_STATE;
    }
    turbo_stream_set_user_data(stream, peer);

    /* Create unified connection abstraction */
    peer->conn = p2p_connection_create_outbound(stream);
    if (!peer->conn) {
        turbo_stream_destroy(stream);
        p2p_node_release_transport_send_capacity(peer->node, peer);
        return P2P_ERR_NO_MEM;
    }

    if (turbo_stream_connect(stream, peer->ip, (unsigned short)peer->port,
                             p2p_peer_stream_connect, p2p_peer_stream_close) != 0) {
        TLOG_DEBUG("[P2P] peer_connect: connect to {}:{} failed", peer->ip, peer->port);
        p2p_connection_destroy(peer->conn);
        peer->conn = NULL;
        p2p_node_release_transport_send_capacity(peer->node, peer);
        return P2P_ERR_NETWORK;
    }

    peer->state = P2P_PEER_STATE_CONNECTING;
    peer->connect_time = turbo_hrtime();
    TLOG_DEBUG("[P2P] peer_connect: connecting to {}:{}", peer->ip, peer->port);
    return P2P_OK;
}


void p2p_peer_stream_connect(void *handle, int status, void *arg) {
    turbo_stream_t *stream = (turbo_stream_t *)handle;
    p2p_peer_t *peer;

    (void)arg;
    if (!stream) return;
    peer = (p2p_peer_t *)turbo_stream_get_user_data(stream);
    if (!peer || !peer->node) return;
    if (!p2p_peer_hold(peer)) return;

    if (status != 0) {
        TLOG_DEBUG("[P2P] peer connect failed {}:{} status={}", peer->ip, peer->port, status);
        p2p_peer_transport_closed(peer, peer->keep_entry ? 0 : 1);
        p2p_peer_release(peer);
        return;
    }

    if (turbo_stream_recv_start(stream, p2p_peer_stream_recv) != 0) {
        TLOG_ERROR("[P2P] failed to start recv for {}:{}", peer->ip, peer->port);
        p2p_peer_transport_closed(peer, peer->keep_entry ? 0 : 1);
        p2p_peer_release(peer);
        return;
    }

    p2p_peer_transport_connected(peer);
    p2p_peer_release(peer);
}

int p2p_peer_stream_recv(void *handle, const mem_slice_t *slice, void *peer_ctx) {
    turbo_stream_t *stream = (turbo_stream_t *)handle;
    p2p_peer_t *peer = (p2p_peer_t *)turbo_stream_get_user_data(stream);
    int ret;
    (void)peer_ctx;

    if (!peer) {
        return 0;
    }
    if (!p2p_peer_hold(peer)) {
        return 0;
    }

    if (!slice || !slice->data || slice->length == 0) {
        turbo_stream_set_user_data(stream, NULL);
        p2p_peer_transport_closed(peer, peer->keep_entry ? 0 : 1);
        p2p_peer_release(peer);
        return 0;
    }

    ret = p2p_peer_on_data(peer, slice->data, slice->length);
    if (ret != P2P_OK) {
        p2p_node_record_security_failure(peer->node, peer->security_stage,
                                         ret);
        if (peer->conn) turbo_stream_set_user_data(stream, NULL);
        p2p_peer_transport_closed(peer, peer->keep_entry ? 0 : 1);
        p2p_peer_release(peer);
        return 1;
    }

    p2p_peer_release(peer);
    return 0;
}

void p2p_peer_stream_close(void *handle) {
    turbo_stream_t *stream = (turbo_stream_t *)handle;
    p2p_peer_t *peer;

    if (!stream) return;
    peer = (p2p_peer_t *)turbo_stream_get_user_data(stream);
    if (!peer) return;
    if (!p2p_peer_hold(peer)) return;

    turbo_stream_set_user_data(stream, NULL);
    p2p_peer_transport_closed(peer, peer->keep_entry ? 0 : 1);
    p2p_peer_release(peer);
}
