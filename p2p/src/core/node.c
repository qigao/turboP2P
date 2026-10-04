/**
 * node.c - P2P Node Management implementation
 * Professional version based on Kademlia DHT and unified connection
 */

#include "node.h"
#include "node_network.h"
#include "node_state.h"
#include "../protocol/handlers.h"
#include "peer.h"
#include "peer_coronet.h"
#include "../transfer/transfer.h"
#include "../internal.h"
#include <CoroNet/turbo_coro_context.h>
#include <CoroNet/turbo_stream.h>
#include <tlog.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "../crypto/p2p_crypto.h"
#include "../security/p2p_cookie.h"
#include "../security/p2p_private_key_executor.h"

/* Forward declarations */
void node_maintenance_cb(turbo_timer_t *timer);
static int node_build_sockaddr(const char *ip, int port, struct sockaddr_storage *addr);
static int node_sockaddr_to_peer(const struct sockaddr_storage *addr, char *ip,
                                 size_t ip_size, int *port);
static void node_server_accept_cb(void *server_handle, void *client_handle, void *peer);
static turbo_stream_t *node_take_expired_cookie_stream_locked(
    p2p_node_t *node, uint64_t now_ms);
static int node_cookie_gate_recv(void *handle, const mem_slice_t *slice,
                                 void *peer_ctx);
static p2p_cookie_gate_t *node_cookie_gate_allocate_locked(
    p2p_node_t *node, turbo_stream_t *stream, const char *source_ip,
    int source_port, uint64_t now_ms);
static int node_promote_cookie_gate(
    p2p_cookie_gate_t *gate,
    const uint8_t cookie_binding[P2P_COOKIE_BINDING_SIZE]);

/* =============================================================================
 * Node Lifecycle
 * ============================================================================= */

static int node_connect_coronet(p2p_peer_t *peer, void *context) {
    (void)context;
    return p2p_peer_connect_coronet(peer);
}

static int node_pending_coronet(p2p_node_t *node, const char *ip,
    size_t *total, size_t *source, void *context) {
    (void)context;
    *total = node->active_cookie_gates;
    *source = 0;
    for (size_t i = 0; ip && i < node->security_config.cookie_gate_limit; ++i)
        if (node->cookie_gates[i].state != P2P_COOKIE_GATE_FREE &&
            p2p_node_source_prefix_matches(ip, node->cookie_gates[i].source_ip))
            ++*source;
    return P2P_OK;
}

static const p2p_node_network_ops_t node_coronet_ops = {
    node_connect_coronet, node_pending_coronet
};

p2p_node_t* p2p_node_create(const char *ip, int port) {
    p2p_node_t *node = p2p_node_state_create(ip, port);
    if (!node) return NULL;
    node->ctx = coro_context_create(NULL);
    if (!node->ctx) {
        (void)p2p_node_state_destroy(node);
        return NULL;
    }
    node->network_ops = &node_coronet_ops;
    return node;
}

void p2p_node_destroy(p2p_node_t *node) {
    if (!node) return;

    /* Use professional cleanup orchestration from cleanup.c */
    void p2p_destroy_clean(p2p_node_t *node); /* Forward declaration */
    p2p_destroy_clean(node);
}

/* =============================================================================
 * Infrastructure implementation
 * ============================================================================= */

static int node_build_sockaddr(const char *ip, int port, struct sockaddr_storage *addr) {
    struct sockaddr_in *addr4;
    struct sockaddr_in6 *addr6;

    if (!ip || !addr) {
        return -1;
    }

    memset(addr, 0, sizeof(*addr));
    addr4 = (struct sockaddr_in *)addr;
    if (inet_pton(AF_INET, ip, &addr4->sin_addr) == 1) {
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons((uint16_t)port);
        return 0;
    }

    addr6 = (struct sockaddr_in6 *)addr;
    if (inet_pton(AF_INET6, ip, &addr6->sin6_addr) == 1) {
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons((uint16_t)port);
        return 0;
    }

    return -1;
}

static int node_sockaddr_to_peer(const struct sockaddr_storage *addr, char *ip,
                                 size_t ip_size, int *port) {
    const void *src = NULL;

    if (!addr || !ip || !port) {
        return -1;
    }

    if (addr->ss_family == AF_INET) {
        const struct sockaddr_in *addr4 = (const struct sockaddr_in *)addr;
        src = &addr4->sin_addr;
        *port = ntohs(addr4->sin_port);
    } else if (addr->ss_family == AF_INET6) {
        const struct sockaddr_in6 *addr6 = (const struct sockaddr_in6 *)addr;
        src = &addr6->sin6_addr;
        *port = ntohs(addr6->sin6_port);
    } else {
        return -1;
    }

    return inet_ntop(addr->ss_family, src, ip, (socklen_t)ip_size) ? 0 : -1;
}

static p2p_cookie_gate_t *node_cookie_gate_allocate_locked(
    p2p_node_t *node, turbo_stream_t *stream, const char *source_ip,
    int source_port, uint64_t now_ms) {
    size_t index;

    if (!node || !stream || !source_ip) {
        return NULL;
    }
    for (index = 0; index < node->security_config.cookie_gate_limit; ++index) {
        p2p_cookie_gate_t *gate = &node->cookie_gates[index];
        if (gate->state != P2P_COOKIE_GATE_FREE) {
            continue;
        }
        memset(gate, 0, sizeof(*gate));
        gate->node = node;
        gate->stream = stream;
        strncpy(gate->source_ip, source_ip, sizeof(gate->source_ip) - 1);
        gate->source_port = source_port;
        gate->deadline_ms = now_ms + node->security_config.handshake_timeout_ms;
        gate->stage_started_ms = now_ms;
        gate->state = P2P_COOKIE_GATE_WAIT_PREFACE;
        node->active_cookie_gates++;
        return gate;
    }
    return NULL;
}

static void node_cookie_gate_reject(
    p2p_cookie_gate_t *gate,
    p2p_security_rejection_reason_v2_t reason) {
    p2p_node_t *node;
    turbo_stream_t *stream;

    if (!gate || !gate->node || !gate->stream) {
        return;
    }
    node = gate->node;
    stream = (turbo_stream_t *)gate->stream;
    turbo_stream_set_user_data(stream, NULL);
    turbo_stream_recv_stop(stream);
    salts_mutex_lock(&node->mutex);
    if (gate->state != P2P_COOKIE_GATE_FREE && gate->stream == stream) {
        if (reason < P2P_SECURITY_REJECTION_REASON_COUNT) {
            node->security_rejection_counts[reason]++;
        }
        memset(gate, 0, sizeof(*gate));
        if (node->active_cookie_gates > 0) {
            node->active_cookie_gates--;
        }
    }
    salts_mutex_unlock(&node->mutex);
    turbo_stream_destroy(stream);
}

static int node_promote_cookie_gate(
    p2p_cookie_gate_t *gate,
    const uint8_t cookie_binding[P2P_COOKIE_BINDING_SIZE]) {
    p2p_node_t *node;
    turbo_stream_t *stream;
    p2p_peer_t *accepted_peer = NULL;
    uint8_t initiator_preface[P2P_SECURE_PREFACE_SIZE];
    char source_ip[P2P_MAX_IP];
    int source_port;
    int peer_tracked = 0;
    int ret = P2P_ERR_INVALID_STATE;
    p2p_security_rejection_reason_v2_t pending_rejection;

    if (!gate || !gate->node || !gate->stream || !cookie_binding) {
        return P2P_ERR_INVALID_ARG;
    }
    node = gate->node;
    stream = (turbo_stream_t *)gate->stream;
    memcpy(initiator_preface, gate->initiator_preface,
           sizeof(initiator_preface));
    memcpy(source_ip, gate->source_ip, sizeof(source_ip));
    source_ip[sizeof(source_ip) - 1] = '\0';
    source_port = gate->source_port;

    turbo_stream_set_user_data(stream, NULL);
    turbo_stream_recv_stop(stream);
    salts_mutex_lock(&node->mutex);
    if (gate->state != P2P_COOKIE_GATE_WAIT_RESPONSE ||
        gate->stream != stream) {
        salts_mutex_unlock(&node->mutex);
        return P2P_ERR_INVALID_STATE;
    }
    p2p_node_record_handshake_latency_locked(
        node, P2P_SECURITY_ROLE_RESPONDER, P2P_SECURITY_LATENCY_COOKIE,
        gate->stage_started_ms, turbo_hrtime() / 1000000U);
    memset(gate, 0, sizeof(*gate));
    if (node->active_cookie_gates > 0) {
        node->active_cookie_gates--;
    }
    node->cookie_verifications_succeeded++;
    salts_mutex_unlock(&node->mutex);

    if (turbo_stream_set_send_hwm(
            stream, node->security_config.send_hwm_bytes) != 0) {
        ret = P2P_ERR_INVALID_STATE;
        goto fail_stream;
    }
    accepted_peer = p2p_peer_create(node, source_ip, source_port);
    if (!accepted_peer) {
        ret = P2P_ERR_NO_MEM;
        goto fail_stream;
    }
    ret = p2p_node_reserve_transport_send_capacity(node, accepted_peer);
    if (ret != P2P_OK) {
        goto fail_peer;
    }
    accepted_peer->conn = p2p_connection_create_inbound(stream);
    if (!accepted_peer->conn) {
        ret = P2P_ERR_NO_MEM;
        p2p_peer_destroy(accepted_peer);
        goto fail_stream;
    }
    turbo_stream_set_user_data(stream, accepted_peer);
    if (turbo_stream_recv_start(stream, p2p_peer_stream_recv) != 0) {
        turbo_stream_set_user_data(stream, NULL);
        ret = P2P_ERR_NETWORK;
        goto fail_peer;
    }

    accepted_peer->state = P2P_PEER_STATE_HANDSHAKING;
    accepted_peer->is_connected = 0;
    accepted_peer->connect_time = turbo_hrtime();
    accepted_peer->last_seen = accepted_peer->connect_time;

    salts_mutex_lock(&node->mutex);
    pending_rejection = p2p_node_pending_peer_rejection_locked(node, source_ip);
    if (pending_rejection == P2P_SECURITY_REJECTION_REASON_COUNT &&
        !p2p_node_find_peer_by_endpoint_locked(node, source_ip, source_port)) {
        p2p_node_add_peer_locked(node, accepted_peer);
    } else if (pending_rejection != P2P_SECURITY_REJECTION_REASON_COUNT) {
        node->security_rejection_counts[pending_rejection]++;
    }
    peer_tracked =
        p2p_node_find_peer_by_endpoint_locked(node, source_ip, source_port) ==
        accepted_peer;
    salts_mutex_unlock(&node->mutex);
    if (!peer_tracked) {
        ret = P2P_ERR_RESOURCE_EXHAUSTED;
        goto fail_peer;
    }

    ret = p2p_peer_start_inbound_handshake_after_cookie(
        accepted_peer, initiator_preface, cookie_binding);
    p2p_crypto_wipe(initiator_preface, sizeof(initiator_preface));
    if (ret != P2P_OK) {
        p2p_node_record_security_failure(node, accepted_peer->security_stage,
                                         ret);
        salts_mutex_lock(&node->mutex);
        if (p2p_node_find_peer_by_endpoint_locked(
                node, source_ip, source_port) == accepted_peer) {
            node_remove_peer_entry_locked(node, accepted_peer);
        }
        salts_mutex_unlock(&node->mutex);
        p2p_peer_destroy(accepted_peer);
    }
    return ret;

fail_peer:
    p2p_crypto_wipe(initiator_preface, sizeof(initiator_preface));
    if (peer_tracked) {
        salts_mutex_lock(&node->mutex);
        if (p2p_node_find_peer_by_endpoint_locked(
                node, source_ip, source_port) == accepted_peer) {
            node_remove_peer_entry_locked(node, accepted_peer);
        }
        salts_mutex_unlock(&node->mutex);
    }
    p2p_peer_destroy(accepted_peer);
    return ret;

fail_stream:
    p2p_crypto_wipe(initiator_preface, sizeof(initiator_preface));
    turbo_stream_destroy(stream);
    return ret;
}

static int node_cookie_gate_recv(void *handle, const mem_slice_t *slice,
                                 void *peer_ctx) {
    turbo_stream_t *stream = (turbo_stream_t *)handle;
    p2p_cookie_gate_t *gate;
    p2p_node_t *node;
    size_t target_size;
    uint8_t packet[P2P_COOKIE_PACKET_SIZE];
    uint8_t binding[P2P_COOKIE_BINDING_SIZE];
    uint64_t now_ms;
    int ret;

    (void)peer_ctx;
    if (!stream) {
        return 1;
    }
    gate = (p2p_cookie_gate_t *)turbo_stream_get_user_data(stream);
    if (!gate || !gate->node || gate->stream != stream) {
        return 1;
    }
    node = gate->node;
    if (!slice || !slice->data || slice->length == 0) {
        node_cookie_gate_reject(gate,
                                P2P_SECURITY_REJECTION_COOKIE_PROTOCOL);
        return 1;
    }
    now_ms = turbo_hrtime() / 1000000U;
    if (now_ms > gate->deadline_ms) {
        node_cookie_gate_reject(gate,
                                P2P_SECURITY_REJECTION_COOKIE_EXPIRED);
        return 1;
    }
    target_size = gate->state == P2P_COOKIE_GATE_WAIT_PREFACE
                      ? P2P_SECURE_PREFACE_SIZE
                      : P2P_COOKIE_PACKET_SIZE;
    if ((gate->state != P2P_COOKIE_GATE_WAIT_PREFACE &&
         gate->state != P2P_COOKIE_GATE_WAIT_RESPONSE) ||
        gate->recv_len > target_size ||
        slice->length > target_size - gate->recv_len) {
        node_cookie_gate_reject(gate,
                                P2P_SECURITY_REJECTION_COOKIE_PROTOCOL);
        return 1;
    }
    memcpy(gate->recv_buffer + gate->recv_len, slice->data, slice->length);
    gate->recv_len += slice->length;
    if (gate->recv_len < target_size) {
        return 0;
    }

    if (gate->state == P2P_COOKIE_GATE_WAIT_PREFACE) {
        ret = p2p_secure_preface_validate(
            node->security_config.network_id_hash, gate->recv_buffer);
        if (ret != P2P_OK) {
            node_cookie_gate_reject(
                gate, P2P_SECURITY_REJECTION_COOKIE_PROTOCOL);
            return 1;
        }
        memcpy(gate->initiator_preface, gate->recv_buffer,
               P2P_SECURE_PREFACE_SIZE);
        ret = p2p_cookie_build_challenge(
            node->cookie_master_secret, gate->source_ip,
            gate->initiator_preface, now_ms,
            node->security_config.cookie_lifetime_ms,
            node->security_config.cookie_key_rotation_ms, packet);
        if (ret != P2P_OK ||
            turbo_stream_send(stream, (const char *)packet,
                              sizeof(packet)) != 0) {
            p2p_crypto_wipe(packet, sizeof(packet));
            node_cookie_gate_reject(
                gate, ret == P2P_ERR_CRYPTO
                          ? P2P_SECURITY_REJECTION_COOKIE_AUTH
                          : P2P_SECURITY_REJECTION_HANDSHAKE_RESOURCE);
            return 1;
        }
        p2p_crypto_wipe(packet, sizeof(packet));
        salts_mutex_lock(&node->mutex);
        p2p_node_record_handshake_latency_locked(
            node, P2P_SECURITY_ROLE_RESPONDER,
            P2P_SECURITY_LATENCY_PREFACE, gate->stage_started_ms, now_ms);
        salts_mutex_unlock(&node->mutex);
        gate->recv_len = 0;
        gate->stage_started_ms = now_ms;
        gate->state = P2P_COOKIE_GATE_WAIT_RESPONSE;
        salts_mutex_lock(&node->mutex);
        node->cookie_challenges_issued++;
        salts_mutex_unlock(&node->mutex);
        return 0;
    }

    ret = p2p_cookie_verify_response(
        node->cookie_master_secret, gate->source_ip,
        gate->initiator_preface, now_ms,
        node->security_config.cookie_lifetime_ms,
        node->security_config.cookie_key_rotation_ms, gate->recv_buffer,
        binding);
    if (ret != P2P_OK) {
        p2p_crypto_wipe(binding, sizeof(binding));
        node_cookie_gate_reject(
            gate, ret == P2P_ERR_TIMEOUT
                      ? P2P_SECURITY_REJECTION_COOKIE_EXPIRED
                      : ret == P2P_ERR_CRYPTO
                            ? P2P_SECURITY_REJECTION_COOKIE_AUTH
                            : P2P_SECURITY_REJECTION_COOKIE_PROTOCOL);
        return 1;
    }
    ret = node_promote_cookie_gate(gate, binding);
    p2p_crypto_wipe(binding, sizeof(binding));
    return ret == P2P_OK ? 0 : 1;
}

static void node_server_accept_cb(void *server_handle, void *client_handle, void *peer) {
    turbo_stream_listener_t *listener = (turbo_stream_listener_t *)server_handle;
    turbo_stream_t *client = (turbo_stream_t *)client_handle;
    p2p_node_t *node = (p2p_node_t *)turbo_stream_listener_get_user_data(listener);
    struct sockaddr_storage addr;
    const struct sockaddr *peer_addr = (const struct sockaddr *)peer;
    char ip[P2P_MAX_IP];
    int port = 0;
    p2p_cookie_gate_t *gate = NULL;
    int admitted = 0;
    p2p_security_rejection_reason_v2_t pending_rejection;

    if (!node || !client) return;

    if (turbo_stream_set_send_hwm(client, P2P_COOKIE_PACKET_SIZE) != 0) {
        turbo_stream_destroy(client);
        return;
    }

    memset(&addr, 0, sizeof(addr));
    if (peer_addr && peer_addr->sa_family == AF_INET) {
        memcpy(&addr, peer_addr, sizeof(struct sockaddr_in));
    } else if (peer_addr && peer_addr->sa_family == AF_INET6) {
        memcpy(&addr, peer_addr, sizeof(struct sockaddr_in6));
    } else if (turbo_stream_get_peer_addr(client, &addr) != 0) {
        turbo_stream_destroy(client);
        return;
    }

    if (node_sockaddr_to_peer(&addr, ip, sizeof(ip), &port) != 0) {
        turbo_stream_destroy(client);
        return;
    }

    salts_mutex_lock(&node->mutex);
    pending_rejection = p2p_node_pending_peer_rejection_locked(node, ip);
    admitted = pending_rejection == P2P_SECURITY_REJECTION_REASON_COUNT;
    if (!admitted) {
        node->security_rejection_counts[pending_rejection]++;
    } else if (p2p_node_source_admission_acquire_locked(
                   node, ip, turbo_hrtime() / 1000000U) != P2P_OK) {
        admitted = 0;
    } else {
        gate = node_cookie_gate_allocate_locked(
            node, client, ip, port, turbo_hrtime() / 1000000U);
        if (!gate) {
            admitted = 0;
            node->security_rejection_counts[
                P2P_SECURITY_REJECTION_COOKIE_GATE_CAPACITY]++;
        }
    }
    salts_mutex_unlock(&node->mutex);
    if (!admitted) {
        turbo_stream_destroy(client);
        return;
    }
    turbo_stream_set_user_data(client, gate);
    if (turbo_stream_recv_start(client, node_cookie_gate_recv) != 0) {
        turbo_stream_set_user_data(client, NULL);
        salts_mutex_lock(&node->mutex);
        memset(gate, 0, sizeof(*gate));
        node->active_cookie_gates--;
        salts_mutex_unlock(&node->mutex);
        turbo_stream_destroy(client);
    }
}

CXX_C_API int p2p_node_start_server(p2p_node_t *node) {
    struct sockaddr_storage addr;
    turbo_stream_kind_t kind;

    if (!node || node->server) return P2P_ERR_INVALID_ARG;
    if (!node->security_configured) return P2P_ERR_AUTH_REQUIRED;

    if (node_build_sockaddr(node->ip, node->port, &addr) != 0) {
        return P2P_ERR_INVALID_ARG;
    }

    kind = (addr.ss_family == AF_INET6) ? TURBO_STREAM_TCP6 : TURBO_STREAM_TCP4;
    node->server = turbo_stream_listen(node->ctx, kind,
                                       (struct sockaddr *)&addr, 128,
                                       node_server_accept_cb);
    if (!node->server) {
        TLOG_ERROR("[P2P] Failed to listen on {}:{}", node->ip, node->port);
        return P2P_ERR_NETWORK;
    }
    turbo_stream_listener_set_user_data(node->server, node);

    TLOG_INFO("[P2P] Node listening on {}:{}", node->ip, node->port);

    /* Start Maintenance Timer (Gossip/Refresh) */
    node->gossip_timer = turbo_timer_create(p2p_get_loop(node));
    if (node->gossip_timer) {
        turbo_timer_set_data(node->gossip_timer, node);
        turbo_timer_start(node->gossip_timer, node_maintenance_cb,
                          P2P_GOSSIP_INTERVAL, P2P_GOSSIP_INTERVAL);
    }

    return P2P_OK;
}

void p2p_node_stop_server(p2p_node_t *node) {
    if (!node) return;

    if (node->gossip_timer) {
        turbo_timer_stop(node->gossip_timer);
        turbo_timer_destroy(node->gossip_timer);
        node->gossip_timer = NULL;
    }

    if (node->server) {
        turbo_stream_listener_close(node->server);
        node->server = NULL;
    }
    p2p_node_cleanup_cookie_gates(node);
}

void p2p_node_cleanup_cookie_gates(p2p_node_t *node) {
    size_t index;

    if (!node) {
        return;
    }
    for (index = 0; index < P2P_SECURITY_COOKIE_GATE_LIMIT_MAX; ++index) {
        turbo_stream_t *stream = NULL;

        salts_mutex_lock(&node->mutex);
        if (node->cookie_gates[index].state != P2P_COOKIE_GATE_FREE) {
            stream = (turbo_stream_t *)node->cookie_gates[index].stream;
            memset(&node->cookie_gates[index], 0,
                   sizeof(node->cookie_gates[index]));
            if (node->active_cookie_gates > 0) {
                node->active_cookie_gates--;
            }
        }
        salts_mutex_unlock(&node->mutex);
        if (stream) {
            turbo_stream_set_user_data(stream, NULL);
            turbo_stream_recv_stop(stream);
            turbo_stream_destroy(stream);
        }
    }
}

void node_maintenance_cb(turbo_timer_t *timer) {
    p2p_node_t *node = (p2p_node_t *)turbo_timer_get_data(timer);
    uint64_t now = 0;
    if (!node) return;

    p2p_private_key_executor_pump(node);

    salts_mutex_lock(&node->mutex);
    TLOG_DEBUG("[P2P] Periodic maintenance starting");
    salts_mutex_unlock(&node->mutex);

    /* 1. DHT Refresh */
    p2p_gossip_start(node);

    now = turbo_hrtime() / 1000000;
    for (;;) {
        turbo_stream_t *expired_stream;

        salts_mutex_lock(&node->mutex);
        expired_stream =
            node_take_expired_cookie_stream_locked(node, now);
        salts_mutex_unlock(&node->mutex);
        if (!expired_stream) {
            break;
        }
        turbo_stream_set_user_data(expired_stream, NULL);
        turbo_stream_recv_stop(expired_stream);
        turbo_stream_destroy(expired_stream);
    }
    p2p_node_maintain_peers(node, now);
}

static turbo_stream_t *node_take_expired_cookie_stream_locked(
    p2p_node_t *node, uint64_t now_ms) {
    size_t index;

    if (!node) {
        return NULL;
    }
    for (index = 0; index < node->security_config.cookie_gate_limit; ++index) {
        p2p_cookie_gate_t *gate = &node->cookie_gates[index];
        turbo_stream_t *stream;

        if (gate->state == P2P_COOKIE_GATE_FREE ||
            now_ms <= gate->deadline_ms) {
            continue;
        }
        stream = (turbo_stream_t *)gate->stream;
        memset(gate, 0, sizeof(*gate));
        if (node->active_cookie_gates > 0) {
            node->active_cookie_gates--;
        }
        node->security_rejection_counts[
            P2P_SECURITY_REJECTION_COOKIE_EXPIRED]++;
        return stream;
    }
    return NULL;
}

/* =============================================================================
 * Pub/Sub operations
 * ============================================================================= */
