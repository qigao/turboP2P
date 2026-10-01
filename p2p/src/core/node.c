/**
 * node.c - P2P Node Management implementation
 * Professional version based on Kademlia DHT and unified connection
 */

#include "node.h"
#include "peer.h"
#include "../transfer/transfer.h"
#include "../internal.h"
#include <tlog.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "../crypto/p2p_crypto.h"
#include "../security/p2p_cookie.h"
#include "../security/p2p_private_key_executor.h"

/* Forward declarations */
static native_io_backend_kind node_network_backend(void);
static cnet_client_config node_network_config(void);
static int node_accept_ready(p2p_node_t *node);
static void node_maintenance_run(p2p_node_t *node);
static void node_cnet_state(void *user, cnet_connection connection,
                            cnet_connection_state state, const cnet_error *error);
static void node_cnet_receive(void *user, cnet_connection connection,
                              const cnet_receive_view *view);
static void node_cnet_send(void *user, cnet_connection connection, size_t size);
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
static int node_take_expired_cookie_connection_locked(
    p2p_node_t *node, uint64_t now_ms, cnet_connection *out_connection);
static void node_cookie_gate_receive(p2p_cookie_gate_t *gate,
                                     const cnet_receive_view *view);
static p2p_cookie_gate_t *node_cookie_gate_allocate_locked(
    p2p_node_t *node, cnet_connection connection, const char *source_ip,
    int source_port, uint64_t now_ms);
static int node_promote_cookie_gate(
    p2p_cookie_gate_t *gate,
    const uint8_t cookie_binding[P2P_COOKIE_BINDING_SIZE]);

/* =============================================================================
 * Node Lifecycle
 * ============================================================================= */

static native_io_backend_kind node_network_backend(void) {
#if defined(_WIN32)
    return NATIVE_IO_BACKEND_IOCP;
#elif defined(__linux__)
    return NATIVE_IO_BACKEND_EPOLL;
#else
    return NATIVE_IO_BACKEND_KQUEUE;
#endif
}

static cnet_client_config node_network_config(void) {
    cnet_client_config config;
    memset(&config, 0, sizeof(config));
    config.backend = node_network_backend();
    config.connection_capacity = 512u;
    config.command_capacity = 1024u;
    config.request_capacity = 1024u;
    config.completion_batch_capacity = 128u;
    config.event_capacity = 1024u;
    config.max_send_bytes = P2P_SECURITY_SEND_HWM_MAX_BYTES;
    config.receive_buffer_bytes = 256u * 1024u;
    config.connect_timeout_ms = P2P_PEER_TIMEOUT_MS;
    config.read_timeout_ms = P2P_PEER_TIMEOUT_MS;
    config.write_timeout_ms = P2P_PEER_TIMEOUT_MS;
    return config;
}

p2p_node_t* p2p_node_create(const char *ip, int port) {
    cnet_client_config network_config;
    p2p_node_t *node;
    if (!ip || port < 0 || port > UINT16_MAX) return NULL;

    node = (p2p_node_t *)calloc(1, sizeof(*node));
    if (!node) return NULL;
    strncpy(node->ip, ip, sizeof(node->ip) - 1);
    node->port = port;
    vivaldi_init(&node->coord);

    node->kad_dht = kademlia_create(ip, (uint16_t)port);
    if (!node->kad_dht) {
        free(node);
        return NULL;
    }
    memcpy(node->id, node->kad_dht->routing->local_id.bytes, KADEMLIA_ID_BYTES);
    if (p2p_crypto_generate_identity(&node->crypto.identity) != P2P_OK) {
        kademlia_destroy(node->kad_dht);
        free(node);
        return NULL;
    }

    salts_mutex_init(&node->mutex);
    network_config = node_network_config();
    if (cnet_client_init(&node->network, &network_config) != SALTS_OK) {
        salts_mutex_destroy(&node->mutex);
        kademlia_destroy(node->kad_dht);
        p2p_crypto_wipe(&node->crypto.identity, sizeof(node->crypto.identity));
        free(node);
        return NULL;
    }
    node->network_initialized = 1;

    node->transfers = (p2p_transfer_manager_t *)calloc(1, sizeof(*node->transfers));
    if (!node->transfers) {
        (void)cnet_client_stop(&node->network, 0u);
        (void)cnet_client_destroy(&node->network);
        node->network_initialized = 0;
        salts_mutex_destroy(&node->mutex);
        kademlia_destroy(node->kad_dht);
        p2p_crypto_wipe(&node->crypto.identity, sizeof(node->crypto.identity));
        free(node);
        return NULL;
    }
    p2p_transfer_manager_init(node->transfers);
    return node;
}

void p2p_node_destroy(p2p_node_t *node) {
    if (!node) return;
    p2p_destroy_clean(node);
}

int p2p_node_run_internal(p2p_node_t *node) {
    int status;
    if (!node || !node->network_initialized) return P2P_ERR_INVALID_ARG;
    node->stop_requested = 0;
    while (!node->stop_requested) {
        status = p2p_node_poll_internal(node, 50u);
        if (status != P2P_OK) return status;
    }
    return P2P_OK;
}

int p2p_node_poll_internal(p2p_node_t *node, uint32_t timeout_ms) {
    size_t events = 0u;
    uint64_t now_ms;
    int status;
    if (!node || !node->network_initialized) return P2P_ERR_INVALID_ARG;

    status = node_accept_ready(node);
    if (status != P2P_OK) return status;
    status = cnet_client_poll(&node->network, timeout_ms, &events);
    if (status != SALTS_OK) {
        if (status == SALTS_ESHUTDOWN && node->stop_requested) return P2P_OK;
        return P2P_ERR_NETWORK;
    }
    status = node_accept_ready(node);
    if (status != P2P_OK) return status;

    now_ms = salts_monotonic_ms();
    if (node->last_maintenance_ms == 0u ||
        now_ms - node->last_maintenance_ms >= P2P_GOSSIP_INTERVAL) {
        node->last_maintenance_ms = now_ms;
        node_maintenance_run(node);
    }
    return P2P_OK;
}

void p2p_node_stop_internal(p2p_node_t *node) {
    if (!node) return;
    node->stop_requested = 1;
    if (node->network_initialized) (void)cnet_client_wake(&node->network);
}

cnet_observer p2p_node_transport_observer(p2p_node_t *node) {
    cnet_observer observer;
    memset(&observer, 0, sizeof(observer));
    observer.on_state = node_cnet_state;
    observer.on_receive = node_cnet_receive;
    observer.on_send = node_cnet_send;
    observer.user = node;
    return observer;
}

/* =============================================================================
 * File Management
 * ============================================================================= */

void p2p_node_add_file(p2p_node_t *node, p2p_file_t *file) {
    if (!node || !file) return;

    salts_mutex_lock(&node->mutex);
    file->next_file = node->local_files;
    node->local_files = file;
    salts_mutex_unlock(&node->mutex);
}

void p2p_node_remove_file(p2p_node_t *node, const char *key) {
    if (!node || !key) return;

    salts_mutex_lock(&node->mutex);
    p2p_file_t **curr = &node->local_files;
    while (*curr) {
        if (strcmp((*curr)->hash, key) == 0) {
            p2p_file_t *to_remove = *curr;
            *curr = (*curr)->next_file;
            p2p_file_free(to_remove);
            salts_mutex_unlock(&node->mutex);
            return;
        }
        curr = &(*curr)->next_file;
    }
    salts_mutex_unlock(&node->mutex);
}

p2p_file_t *p2p_node_find_local_file_by_id(p2p_node_t *node, const p2p_id_t id) {
    p2p_file_t *file = NULL;

    if (!node || !id) {
        return NULL;
    }

    salts_mutex_lock(&node->mutex);
    file = p2p_node_find_local_file_by_id_locked(node, id);
    salts_mutex_unlock(&node->mutex);
    return file;
}

p2p_file_t *p2p_node_find_local_file_by_id_locked(p2p_node_t *node, const p2p_id_t id) {
    p2p_file_t *file = NULL;

    if (!node || !id) {
        return NULL;
    }

    file = node->local_files;
    while (file) {
        if (memcmp(file->id, id, P2P_HASH_SIZE) == 0) {
            return file;
        }
        file = file->next_file;
    }
    return NULL;
}

p2p_file_t *p2p_node_detach_local_files(p2p_node_t *node) {
    p2p_file_t *files = NULL;

    if (!node) {
        return NULL;
    }

    salts_mutex_lock(&node->mutex);
    files = node->local_files;
    node->local_files = NULL;
    salts_mutex_unlock(&node->mutex);

    return files;
}

p2p_download_t *p2p_node_detach_downloads(p2p_node_t *node) {
    p2p_download_t *downloads = NULL;

    if (!node) {
        return NULL;
    }

    salts_mutex_lock(&node->mutex);
    downloads = node->downloads;
    node->downloads = NULL;
    salts_mutex_unlock(&node->mutex);

    return downloads;
}

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

    salts_mutex_lock(&node->mutex);
    capacity = (size_t)peer_table_count(node->peers_table);
    if (capacity > 0) {
        peers = (p2p_peer_t **)calloc(capacity, sizeof(*peers));
    }
    if (capacity > 0 && !peers) {
        salts_mutex_unlock(&node->mutex);
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
    salts_mutex_unlock(&node->mutex);

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

    salts_mutex_lock(&node->mutex);
    capacity = (size_t)peer_table_count(node->peers_table);
    if (capacity > 0) {
        infos = (p2p_peer_info_ex_t *)calloc(capacity, sizeof(*infos));
    }
    if (capacity > 0 && !infos) {
        salts_mutex_unlock(&node->mutex);
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
    salts_mutex_unlock(&node->mutex);

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

    salts_mutex_lock(&node->mutex);
    if (p2p_node_find_peer_by_endpoint_locked(node, bootstrap_ip, bootstrap_port)) {
        salts_mutex_unlock(&node->mutex);
        p2p_peer_destroy(peer);
        return P2P_OK;
    }
    p2p_node_add_peer_locked(node, peer);
    salts_mutex_unlock(&node->mutex);

    ret = p2p_peer_connect(peer);
    if (ret != P2P_OK) {
        salts_mutex_lock(&node->mutex);
        p2p_node_remove_peer_by_endpoint_locked(node, bootstrap_ip, bootstrap_port);
        salts_mutex_unlock(&node->mutex);
        p2p_peer_destroy(peer);
        return ret;
    }

    /* Keep the provisional route ID consistent with other endpoint-derived
     * Kademlia contacts until the authenticated peer ID is learned. */
    p2p_endpoint_to_id(bootstrap_ip, bootstrap_port, &bootstrap_id);
    salts_mutex_lock(&node->mutex);
    p2p_node_add_route_locked(node, bootstrap_id.bytes, bootstrap_ip, bootstrap_port);
    salts_mutex_unlock(&node->mutex);

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

    salts_mutex_lock(&node->mutex);
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
    salts_mutex_unlock(&node->mutex);
    return ret;
}

void p2p_node_release_transport_send_capacity(p2p_node_t *node,
                                              p2p_peer_t *peer) {
    size_t reservation;
    int accounting_invalid = 0;

    if (!node || !peer || peer->node != node) {
        return;
    }

    salts_mutex_lock(&node->mutex);
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
    salts_mutex_unlock(&node->mutex);

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

    salts_mutex_lock(&node->mutex);
    node->security_rejection_counts[reason]++;
    salts_mutex_unlock(&node->mutex);
}

static uint64_t node_saturating_add_u64(uint64_t left, uint64_t right) {
    return right > UINT64_MAX - left ? UINT64_MAX : left + right;
}

const uint64_t p2p_security_latency_bucket_upper_bounds_ms
    [P2P_SECURITY_LATENCY_BUCKET_COUNT] = {
        1U,   5U,    10U,   25U,   50U,   100U,
        250U, 500U,  1000U, 2500U, 5000U, UINT64_MAX,
};

static void node_record_handshake_latency_locked(
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
    salts_mutex_lock(&node->mutex);
    node_record_handshake_latency_locked(node, role, stage, started_ms,
                                         completed_ms);
    salts_mutex_unlock(&node->mutex);
}

void p2p_node_on_peer_disconnected(p2p_node_t *node, p2p_peer_t *peer) {
    node_peer_event_cb_t on_peer_disconnected = NULL;
    void *peer_user_data = NULL;
    int hold_peer = 0;

    if (!node || !peer) return;

    salts_mutex_lock(&node->mutex);
    node_handle_peer_disconnect_locked(node, peer);
    node_capture_peer_event_locked(node, peer, node->on_peer_disconnected,
                                   node->peer_user_data, &on_peer_disconnected,
                                   &peer_user_data, &hold_peer);
    salts_mutex_unlock(&node->mutex);

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

    salts_mutex_lock(&node->mutex);
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
    salts_mutex_unlock(&node->mutex);

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

    salts_mutex_lock(&node->mutex);
    if (!peer->is_connected || peer->state != P2P_PEER_STATE_CONNECTED ||
        !p2p_crypto_session_is_ready(&peer->crypto) ||
        peer->outstanding_ping_ms != 0) {
        salts_mutex_unlock(&node->mutex);
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
    salts_mutex_unlock(&node->mutex);

    ret = p2p_send_message(node, peer, P2P_MSG_PING, &ping, sizeof(ping));
    if (ret != P2P_OK) {
        salts_mutex_lock(&node->mutex);
        if (peer->outstanding_ping_ms == ping.timestamp) {
            peer->outstanding_ping_ms = 0;
            peer->last_ping_sent_ms = 0;
        }
        salts_mutex_unlock(&node->mutex);
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

P2P_API p2p_peer_t *p2p_node_find_peer_by_endpoint_locked(p2p_node_t *node,
                                                             const char *ip,
                                                             int port) {
    p2p_peer_entry_t *entry = NULL;

    if (!node || !ip) {
        return NULL;
    }

    entry = peer_table_find(node->peers_table, ip, port);
    return entry ? entry->peer : NULL;
}

P2P_API void p2p_node_add_peer_locked(p2p_node_t *node, p2p_peer_t *peer) {
    if (!node || !peer) {
        return;
    }

    peer_table_add(&node->peers_table, peer);
}

static int node_source_prefix_matches(const char *left, const char *right) {
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

static p2p_security_rejection_reason_v2_t
node_pending_peer_rejection_locked(p2p_node_t *node,
                                   const char *source_ip) {
    p2p_peer_entry_t *curr = NULL;
    p2p_peer_entry_t *tmp = NULL;
    int pending_count = (int)node->active_cookie_gates;
    int source_count = 0;
    size_t gate_index;

    if (pending_count >= P2P_PENDING_PEER_LIMIT) {
        return P2P_SECURITY_REJECTION_PENDING_GLOBAL;
    }
    if (source_ip) {
        for (gate_index = 0;
             gate_index < node->security_config.cookie_gate_limit;
             ++gate_index) {
            p2p_cookie_gate_t *gate = &node->cookie_gates[gate_index];
            if (gate->state != P2P_COOKIE_GATE_FREE &&
                node_source_prefix_matches(source_ip, gate->source_ip)) {
                source_count++;
                if (source_count >= P2P_PENDING_PEER_SOURCE_LIMIT) {
                    return P2P_SECURITY_REJECTION_PENDING_SOURCE;
                }
            }
        }
    }

    HASH_ITER(hh, node->peers_table, curr, tmp) {
        if (curr->peer && !curr->peer->is_connected &&
            curr->peer->state == P2P_PEER_STATE_HANDSHAKING) {
            pending_count++;
            if (pending_count >= P2P_PENDING_PEER_LIMIT) {
                return P2P_SECURITY_REJECTION_PENDING_GLOBAL;
            }
            if (source_ip &&
                node_source_prefix_matches(source_ip, curr->peer->ip)) {
                source_count++;
                if (source_count >= P2P_PENDING_PEER_SOURCE_LIMIT) {
                    return P2P_SECURITY_REJECTION_PENDING_SOURCE;
                }
            }
        }
    }
    return P2P_SECURITY_REJECTION_REASON_COUNT;
}

P2P_API int p2p_node_pending_peer_source_capacity_available_locked(
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

    return node_pending_peer_rejection_locked(node, source_ip) ==
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

P2P_API int p2p_node_source_admission_acquire_locked(
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

P2P_API int p2p_node_pending_peer_capacity_available_locked(p2p_node_t *node) {
    return p2p_node_pending_peer_source_capacity_available_locked(node, NULL);
}

P2P_API void p2p_node_remove_peer_by_endpoint_locked(p2p_node_t *node,
                                                       const char *ip,
                                                       int port) {
    if (!node || !ip) {
        return;
    }

    peer_table_remove(&node->peers_table, ip, port);
}

P2P_API void p2p_node_add_route_locked(p2p_node_t *node, const uint8_t *id, const char *ip, int port) {
    kad_node_t knode;

    if (!node || !node->kad_dht || !node->kad_dht->routing || !ip) {
        return;
    }

    p2p_init_kad_node(&knode, id, ip, port);
    kad_routing_add_node(node->kad_dht->routing, &knode);
}

P2P_API void p2p_node_remove_route_locked(p2p_node_t *node, const uint8_t *id, const char *ip, int port) {
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

/* =============================================================================
 * Infrastructure implementation
 * ============================================================================= */

static int node_connection_equal(cnet_connection left,
                                 cnet_connection right) {
    return left.generation != 0u && left.slot == right.slot &&
           left.generation == right.generation;
}

static int node_stream_peer_to_text(const cnet_stream_peer *peer,
                                    char *ip, size_t ip_size, int *port) {
    int family;
    const void *address;
    if (!peer || !ip || ip_size == 0u || !port) return -1;
    if (peer->family == CNET_DATAGRAM_ADDRESS_IPV4) {
        family = AF_INET;
        address = peer->address;
    } else if (peer->family == CNET_DATAGRAM_ADDRESS_IPV6) {
        family = AF_INET6;
        address = peer->address;
    } else {
        return -1;
    }
    if (!inet_ntop(family, address, ip, (socklen_t)ip_size)) return -1;
    *port = (int)peer->port;
    return 0;
}

static p2p_cookie_gate_t *node_find_cookie_gate_locked(
    p2p_node_t *node, cnet_connection connection) {
    size_t index;
    if (!node) return NULL;
    for (index = 0u; index < node->security_config.cookie_gate_limit; ++index) {
        p2p_cookie_gate_t *gate = &node->cookie_gates[index];
        if (gate->state != P2P_COOKIE_GATE_FREE &&
            node_connection_equal(gate->connection, connection)) {
            return gate;
        }
    }
    return NULL;
}

static p2p_peer_t *node_find_peer_by_connection_locked(
    p2p_node_t *node, cnet_connection connection) {
    p2p_peer_entry_t *entry;
    p2p_peer_entry_t *tmp;
    if (!node) return NULL;
    HASH_ITER(hh, node->peers_table, entry, tmp) {
        p2p_peer_t *peer = entry->peer;
        if (peer && peer->conn &&
            node_connection_equal(peer->conn->handle, connection)) {
            return peer;
        }
    }
    return NULL;
}

static int node_send_cnet_copy(p2p_node_t *node, cnet_connection connection,
                               const void *data, size_t size) {
    mem_buffer_t *buffer;
    int status;
    if (!node || !node->network_initialized || !data || size == 0u)
        return SALTS_EINVAL;
    buffer = mem_get_buffer(mem_global(), size);
    if (!buffer) return SALTS_ENOMEM;
    memcpy(mem_buffer_data(buffer), data, size);
    mem_set_used(buffer, size);
    status = cnet_send_buffer(&node->network, connection, buffer);
    mem_buffer_release(buffer);
    return status;
}

static p2p_cookie_gate_t *node_cookie_gate_allocate_locked(
    p2p_node_t *node, cnet_connection connection, const char *source_ip,
    int source_port, uint64_t now_ms) {
    size_t index;
    if (!node || connection.generation == 0u || !source_ip) return NULL;
    for (index = 0u; index < node->security_config.cookie_gate_limit; ++index) {
        p2p_cookie_gate_t *gate = &node->cookie_gates[index];
        if (gate->state != P2P_COOKIE_GATE_FREE) continue;
        memset(gate, 0, sizeof(*gate));
        gate->node = node;
        gate->connection = connection;
        strncpy(gate->source_ip, source_ip, sizeof(gate->source_ip) - 1u);
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
    cnet_connection connection;
    if (!gate || !gate->node ||
        gate->state == P2P_COOKIE_GATE_FREE) return;
    node = gate->node;
    connection = gate->connection;
    salts_mutex_lock(&node->mutex);
    if (gate->state != P2P_COOKIE_GATE_FREE &&
        node_connection_equal(gate->connection, connection)) {
        if (reason < P2P_SECURITY_REJECTION_REASON_COUNT)
            node->security_rejection_counts[reason]++;
        memset(gate, 0, sizeof(*gate));
        if (node->active_cookie_gates > 0u) node->active_cookie_gates--;
    }
    salts_mutex_unlock(&node->mutex);
    (void)cnet_close(&node->network, connection);
}

static int node_promote_cookie_gate(
    p2p_cookie_gate_t *gate,
    const uint8_t cookie_binding[P2P_COOKIE_BINDING_SIZE]) {
    p2p_node_t *node;
    p2p_peer_t *accepted_peer = NULL;
    cnet_connection connection;
    uint8_t initiator_preface[P2P_SECURE_PREFACE_SIZE];
    char source_ip[P2P_MAX_IP];
    int source_port;
    int peer_tracked = 0;
    int ret = P2P_ERR_INVALID_STATE;
    p2p_security_rejection_reason_v2_t pending_rejection;

    if (!gate || !gate->node || gate->state != P2P_COOKIE_GATE_WAIT_RESPONSE ||
        !cookie_binding) {
        return P2P_ERR_INVALID_ARG;
    }
    node = gate->node;
    connection = gate->connection;
    memcpy(initiator_preface, gate->initiator_preface, sizeof(initiator_preface));
    memcpy(source_ip, gate->source_ip, sizeof(source_ip));
    source_ip[sizeof(source_ip) - 1u] = '\0';
    source_port = gate->source_port;

    salts_mutex_lock(&node->mutex);
    if (gate->state != P2P_COOKIE_GATE_WAIT_RESPONSE ||
        !node_connection_equal(gate->connection, connection)) {
        salts_mutex_unlock(&node->mutex);
        return P2P_ERR_INVALID_STATE;
    }
    node_record_handshake_latency_locked(
        node, P2P_SECURITY_ROLE_RESPONDER, P2P_SECURITY_LATENCY_COOKIE,
        gate->stage_started_ms, salts_monotonic_ms());
    memset(gate, 0, sizeof(*gate));
    if (node->active_cookie_gates > 0u) node->active_cookie_gates--;
    node->cookie_verifications_succeeded++;
    salts_mutex_unlock(&node->mutex);

    accepted_peer = p2p_peer_create(node, source_ip, source_port);
    if (!accepted_peer) {
        ret = P2P_ERR_NO_MEM;
        goto fail_connection;
    }
    ret = p2p_node_reserve_transport_send_capacity(node, accepted_peer);
    if (ret != P2P_OK) goto fail_peer;
    accepted_peer->conn =
        p2p_connection_create(P2P_CONN_INBOUND, &node->network, connection);
    if (!accepted_peer->conn) {
        ret = P2P_ERR_NO_MEM;
        goto fail_peer;
    }
    accepted_peer->state = P2P_PEER_STATE_HANDSHAKING;
    accepted_peer->is_connected = 0;
    accepted_peer->connect_time = salts_hrtime();
    accepted_peer->last_seen = accepted_peer->connect_time;

    salts_mutex_lock(&node->mutex);
    pending_rejection = node_pending_peer_rejection_locked(node, source_ip);
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
    if (ret == P2P_OK && accepted_peer->conn &&
        !accepted_peer->private_key_operation &&
        cnet_receive(&node->network, connection, 1u) != SALTS_OK) {
        ret = P2P_ERR_NETWORK;
    }
    if (ret == P2P_OK) return P2P_OK;

    p2p_node_record_security_failure(node, accepted_peer->security_stage, ret);
    salts_mutex_lock(&node->mutex);
    if (p2p_node_find_peer_by_endpoint_locked(node, source_ip, source_port) ==
        accepted_peer) {
        node_remove_peer_entry_locked(node, accepted_peer);
    }
    salts_mutex_unlock(&node->mutex);

fail_peer:
    p2p_crypto_wipe(initiator_preface, sizeof(initiator_preface));
    if (accepted_peer) p2p_peer_destroy(accepted_peer);
fail_connection:
    (void)cnet_close(&node->network, connection);
    return ret;
}

static void node_cookie_gate_receive(p2p_cookie_gate_t *gate,
                                     const cnet_receive_view *view) {
    p2p_node_t *node;
    size_t target_size;
    uint8_t packet[P2P_COOKIE_PACKET_SIZE];
    uint8_t binding[P2P_COOKIE_BINDING_SIZE];
    uint64_t now_ms;
    int ret;

    if (!gate || !gate->node || gate->state == P2P_COOKIE_GATE_FREE) return;
    node = gate->node;
    if (!view || view->kind != CNET_MESSAGE_BYTES || !view->data ||
        view->size == 0u) {
        node_cookie_gate_reject(gate, P2P_SECURITY_REJECTION_COOKIE_PROTOCOL);
        return;
    }
    now_ms = salts_monotonic_ms();
    if (now_ms > gate->deadline_ms) {
        node_cookie_gate_reject(gate, P2P_SECURITY_REJECTION_COOKIE_EXPIRED);
        return;
    }
    target_size = gate->state == P2P_COOKIE_GATE_WAIT_PREFACE
                      ? P2P_SECURE_PREFACE_SIZE
                      : P2P_COOKIE_PACKET_SIZE;
    if ((gate->state != P2P_COOKIE_GATE_WAIT_PREFACE &&
         gate->state != P2P_COOKIE_GATE_WAIT_RESPONSE) ||
        gate->recv_len > target_size ||
        view->size > target_size - gate->recv_len) {
        node_cookie_gate_reject(gate, P2P_SECURITY_REJECTION_COOKIE_PROTOCOL);
        return;
    }
    memcpy(gate->recv_buffer + gate->recv_len, view->data, view->size);
    gate->recv_len += view->size;
    if (gate->recv_len < target_size) {
        if (cnet_receive(&node->network, gate->connection, 1u) != SALTS_OK)
            node_cookie_gate_reject(
                gate, P2P_SECURITY_REJECTION_HANDSHAKE_RESOURCE);
        return;
    }

    if (gate->state == P2P_COOKIE_GATE_WAIT_PREFACE) {
        ret = p2p_secure_preface_validate(
            node->security_config.network_id_hash, gate->recv_buffer);
        if (ret != P2P_OK) {
            node_cookie_gate_reject(gate,
                                    P2P_SECURITY_REJECTION_COOKIE_PROTOCOL);
            return;
        }
        memcpy(gate->initiator_preface, gate->recv_buffer,
               P2P_SECURE_PREFACE_SIZE);
        ret = p2p_cookie_build_challenge(
            node->cookie_master_secret, gate->source_ip,
            gate->initiator_preface, now_ms,
            node->security_config.cookie_lifetime_ms,
            node->security_config.cookie_key_rotation_ms, packet);
        if (ret != P2P_OK ||
            node_send_cnet_copy(node, gate->connection, packet,
                                sizeof(packet)) != SALTS_OK) {
            p2p_crypto_wipe(packet, sizeof(packet));
            node_cookie_gate_reject(
                gate, ret == P2P_ERR_CRYPTO
                          ? P2P_SECURITY_REJECTION_COOKIE_AUTH
                          : P2P_SECURITY_REJECTION_HANDSHAKE_RESOURCE);
            return;
        }
        p2p_crypto_wipe(packet, sizeof(packet));
        salts_mutex_lock(&node->mutex);
        node_record_handshake_latency_locked(
            node, P2P_SECURITY_ROLE_RESPONDER,
            P2P_SECURITY_LATENCY_PREFACE, gate->stage_started_ms, now_ms);
        node->cookie_challenges_issued++;
        salts_mutex_unlock(&node->mutex);
        gate->recv_len = 0u;
        gate->stage_started_ms = now_ms;
        gate->state = P2P_COOKIE_GATE_WAIT_RESPONSE;
        if (cnet_receive(&node->network, gate->connection, 1u) != SALTS_OK)
            node_cookie_gate_reject(
                gate, P2P_SECURITY_REJECTION_HANDSHAKE_RESOURCE);
        return;
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
        return;
    }
    ret = node_promote_cookie_gate(gate, binding);
    p2p_crypto_wipe(binding, sizeof(binding));
    if (ret != P2P_OK) return;
}

static void node_cnet_state(void *user, cnet_connection connection,
                            cnet_connection_state state,
                            const cnet_error *error) {
    p2p_node_t *node = (p2p_node_t *)user;
    p2p_cookie_gate_t *gate = NULL;
    p2p_peer_t *peer = NULL;
    if (!node) return;

    salts_mutex_lock(&node->mutex);
    gate = node_find_cookie_gate_locked(node, connection);
    if (!gate) {
        peer = node_find_peer_by_connection_locked(node, connection);
        if (peer && !p2p_peer_hold_locked(peer)) peer = NULL;
    }
    salts_mutex_unlock(&node->mutex);

    if (gate) {
        if (state == CNET_CONNECTION_CONNECTED) {
            if (cnet_receive(&node->network, connection, 1u) != SALTS_OK)
                node_cookie_gate_reject(
                    gate, P2P_SECURITY_REJECTION_HANDSHAKE_RESOURCE);
        } else if (state == CNET_CONNECTION_FAILED ||
                   state == CNET_CONNECTION_CLOSED) {
            salts_mutex_lock(&node->mutex);
            if (gate->state != P2P_COOKIE_GATE_FREE &&
                node_connection_equal(gate->connection, connection)) {
                memset(gate, 0, sizeof(*gate));
                if (node->active_cookie_gates > 0u) node->active_cookie_gates--;
            }
            salts_mutex_unlock(&node->mutex);
        }
        return;
    }
    if (peer) {
        p2p_peer_transport_state(peer, connection, state, error);
        p2p_peer_release(peer);
        return;
    }
    if (state == CNET_CONNECTION_CONNECTED)
        (void)cnet_close(&node->network, connection);
}

static void node_cnet_receive(void *user, cnet_connection connection,
                              const cnet_receive_view *view) {
    p2p_node_t *node = (p2p_node_t *)user;
    p2p_cookie_gate_t *gate = NULL;
    p2p_peer_t *peer = NULL;
    if (!node) return;

    salts_mutex_lock(&node->mutex);
    gate = node_find_cookie_gate_locked(node, connection);
    if (!gate) {
        peer = node_find_peer_by_connection_locked(node, connection);
        if (peer && !p2p_peer_hold_locked(peer)) peer = NULL;
    }
    salts_mutex_unlock(&node->mutex);

    if (gate) {
        node_cookie_gate_receive(gate, view);
    } else if (peer) {
        p2p_peer_transport_receive(peer, connection, view);
        p2p_peer_release(peer);
    } else {
        (void)cnet_close(&node->network, connection);
    }
}

static void node_cnet_send(void *user, cnet_connection connection, size_t size) {
    (void)user;
    (void)connection;
    (void)size;
}

static int node_accept_ready(p2p_node_t *node) {
    cnet_observer observer;
    if (!node || !node->listener_initialized) return P2P_OK;
    observer = p2p_node_transport_observer(node);
    for (;;) {
        int ready = 0;
        int status = cnet_listener_wait(&node->listener, 0u, &ready);
        if (status != SALTS_OK) return P2P_ERR_NETWORK;
        if (!ready) return P2P_OK;
        for (;;) {
            cnet_connection connection = {0};
            cnet_stream_peer source;
            char ip[P2P_MAX_IP];
            int port = 0;
            p2p_cookie_gate_t *gate = NULL;
            int admitted = 0;
            p2p_security_rejection_reason_v2_t pending_rejection;
            memset(&source, 0, sizeof(source));
            status = cnet_listener_accept_peer(
                &node->listener, &node->network, &observer,
                &connection, &source);
            if (status == SALTS_ETIMEDOUT) break;
            if (status == SALTS_ENOBUFS) break;
            if (status != SALTS_OK) return P2P_ERR_NETWORK;
            if (node_stream_peer_to_text(&source, ip, sizeof(ip), &port) != 0) {
                (void)cnet_close(&node->network, connection);
                continue;
            }

            salts_mutex_lock(&node->mutex);
            pending_rejection = node_pending_peer_rejection_locked(node, ip);
            admitted =
                pending_rejection == P2P_SECURITY_REJECTION_REASON_COUNT;
            if (!admitted) {
                node->security_rejection_counts[pending_rejection]++;
            } else if (p2p_node_source_admission_acquire_locked(
                           node, ip, salts_monotonic_ms()) != P2P_OK) {
                admitted = 0;
            } else {
                gate = node_cookie_gate_allocate_locked(
                    node, connection, ip, port, salts_monotonic_ms());
                if (!gate) {
                    admitted = 0;
                    node->security_rejection_counts[
                        P2P_SECURITY_REJECTION_COOKIE_GATE_CAPACITY]++;
                }
            }
            salts_mutex_unlock(&node->mutex);
            if (!admitted) (void)cnet_close(&node->network, connection);
        }
    }
}

P2P_API int p2p_node_start_server(p2p_node_t *node) {
    cnet_listener_config config;
    uint16_t bound_port = 0u;
    int status;
    if (!node || node->listener_initialized) return P2P_ERR_INVALID_ARG;
    if (!node->security_configured) return P2P_ERR_AUTH_REQUIRED;

    memset(&config, 0, sizeof(config));
    config.backend = node_network_backend();
    config.host = node->ip;
    config.port = (uint16_t)node->port;
    config.backlog = 128u;
    status = cnet_listener_init(&node->listener, &config);
    if (status != SALTS_OK) return P2P_ERR_NETWORK;
    node->listener_initialized = 1;
    if (cnet_listener_port(&node->listener, &bound_port) == SALTS_OK)
        node->port = (int)bound_port;
    node->last_maintenance_ms = salts_monotonic_ms();
    TLOG_INFOF("[P2P] Node listening on {}:{}", node->ip, node->port);
    return P2P_OK;
}

void p2p_node_stop_server(p2p_node_t *node) {
    if (!node) return;
    if (node->listener_initialized) {
        (void)cnet_listener_close(&node->listener);
        (void)cnet_listener_destroy(&node->listener);
        node->listener_initialized = 0;
    }
    p2p_node_cleanup_cookie_gates(node);
}

void p2p_node_cleanup_cookie_gates(p2p_node_t *node) {
    size_t index;
    if (!node) return;
    for (index = 0u; index < P2P_SECURITY_COOKIE_GATE_LIMIT_MAX; ++index) {
        cnet_connection connection = {0};
        salts_mutex_lock(&node->mutex);
        if (node->cookie_gates[index].state != P2P_COOKIE_GATE_FREE) {
            connection = node->cookie_gates[index].connection;
            memset(&node->cookie_gates[index], 0,
                   sizeof(node->cookie_gates[index]));
            if (node->active_cookie_gates > 0u) node->active_cookie_gates--;
        }
        salts_mutex_unlock(&node->mutex);
        if (connection.generation != 0u)
            (void)cnet_close(&node->network, connection);
    }
}

void p2p_gossip_start(p2p_node_t *node) {
    if (!node) return;
    p2p_dht_lookup_start(node, node->id, P2P_MSG_DHT_FIND_NODE);
}

static void node_maintenance_run(p2p_node_t *node) {
    p2p_peer_t *expired_peer = NULL;
    p2p_peer_t **peers = NULL;
    size_t peer_count = 0u;
    uint64_t now;
    if (!node) return;

    p2p_private_key_executor_pump(node);
    p2p_gossip_start(node);
    now = salts_monotonic_ms();

    for (;;) {
        cnet_connection expired = {0};
        salts_mutex_lock(&node->mutex);
        if (!node_take_expired_cookie_connection_locked(node, now, &expired)) {
            salts_mutex_unlock(&node->mutex);
            break;
        }
        salts_mutex_unlock(&node->mutex);
        (void)cnet_close(&node->network, expired);
    }
    for (;;) {
        salts_mutex_lock(&node->mutex);
        expired_peer = node_take_expired_pending_peer_locked(node, now);
        salts_mutex_unlock(&node->mutex);
        if (!expired_peer) break;
        p2p_peer_destroy(expired_peer);
    }

    peers = p2p_node_snapshot_connected_peers(node, &peer_count);
    for (size_t i = 0u; i < peer_count; ++i) {
        p2p_peer_t *peer = peers[i];
        uint64_t last_seen_ms;
        int stale;
        int probe_due;
        p2p_peer_info_ex_t peer_info = {0};
        if (!peer) continue;

        salts_mutex_lock(&node->mutex);
        last_seen_ms = peer->last_seen / 1000000U;
        stale = now >= last_seen_ms &&
                now - last_seen_ms > P2P_PEER_TIMEOUT_MS;
        probe_due = !stale && peer->state == P2P_PEER_STATE_CONNECTED &&
                    p2p_crypto_session_is_ready(&peer->crypto) &&
                    peer->outstanding_ping_ms == 0u &&
                    (peer->last_ping_sent_ms == 0u ||
                     (now >= peer->last_ping_sent_ms &&
                      now - peer->last_ping_sent_ms >=
                          P2P_RTT_PROBE_INTERVAL_MS));
        if (stale) p2p_peer_fill_info_ex_locked(peer, &peer_info);
        salts_mutex_unlock(&node->mutex);

        if (stale) {
            TLOG_INFOF("[P2P] Pruning stale peer {}:{}",
                      peer_info.ip, peer_info.port);
            p2p_peer_disconnect(peer);
        } else if (probe_due) {
            (void)node_send_identity_ping(node, peer);
        }
        p2p_peer_release(peer);
    }
    free(peers);
}

static int node_take_expired_cookie_connection_locked(
    p2p_node_t *node, uint64_t now_ms, cnet_connection *out_connection) {
    size_t index;
    if (!node || !out_connection) return 0;
    memset(out_connection, 0, sizeof(*out_connection));
    for (index = 0u; index < node->security_config.cookie_gate_limit; ++index) {
        p2p_cookie_gate_t *gate = &node->cookie_gates[index];
        if (gate->state == P2P_COOKIE_GATE_FREE ||
            now_ms <= gate->deadline_ms) {
            continue;
        }
        *out_connection = gate->connection;
        memset(gate, 0, sizeof(*gate));
        if (node->active_cookie_gates > 0u) node->active_cookie_gates--;
        node->security_rejection_counts[
            P2P_SECURITY_REJECTION_COOKIE_EXPIRED]++;
        return 1;
    }
    return 0;
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
            peer->state != P2P_PEER_STATE_HANDSHAKING || peer->connect_time == 0) {
            continue;
        }

        if (peer->security_deadline_ms != 0) {
            if (now_ms <= peer->security_deadline_ms) {
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

/* =============================================================================
 * Pub/Sub operations
 * ============================================================================= */

static p2p_topic_t *node_find_topic_locked(p2p_node_t *node, const char *name) {
    p2p_topic_t *curr = NULL;

    if (!node || !name) {
        return NULL;
    }

    curr = node->topics;
    while (curr) {
        if (strcmp(curr->name, name) == 0) {
            return curr;
        }
        curr = curr->next_topic;
    }

    return NULL;
}

static p2p_topic_t *node_find_or_create_topic_locked(p2p_node_t *node, const char *name) {
    p2p_topic_t *topic = NULL;

    if (!node || !name) {
        return NULL;
    }

    topic = node_find_topic_locked(node, name);
    if (topic) {
        return topic;
    }

    topic = (p2p_topic_t *)calloc(1, sizeof(p2p_topic_t));
    if (!topic) {
        return NULL;
    }

    strncpy(topic->name, name, sizeof(topic->name) - 1);
    topic->next_topic = node->topics;
    node->topics = topic;

    return topic;
}

void p2p_topic_destroy(p2p_topic_t *topic) {
    if (!topic) return;
    if (topic->subscribers) free(topic->subscribers);
    free(topic);
}

p2p_topic_t *p2p_topic_find(p2p_node_t *node, const char *name) {
    p2p_topic_t *topic = NULL;

    if (!node || !name) return NULL;

    salts_mutex_lock(&node->mutex);
    topic = node_find_topic_locked(node, name);
    salts_mutex_unlock(&node->mutex);

    return topic;
}

p2p_topic_t *p2p_topic_find_or_create(p2p_node_t *node, const char *name) {
    p2p_topic_t *topic = NULL;

    if (!node || !name) return NULL;

    salts_mutex_lock(&node->mutex);
    topic = node_find_or_create_topic_locked(node, name);
    salts_mutex_unlock(&node->mutex);

    return topic;
}

int p2p_topic_exists(p2p_node_t *node, const char *name) {
    int exists = 0;

    if (!node || !name) {
        return 0;
    }

    salts_mutex_lock(&node->mutex);
    exists = node_find_topic_locked(node, name) != NULL;
    salts_mutex_unlock(&node->mutex);

    return exists;
}

int p2p_node_remove_topic(p2p_node_t *node, const char *name) {
    if (!node || !name) return P2P_ERR_INVALID_ARG;

    salts_mutex_lock(&node->mutex);
    p2p_topic_t **curr = &node->topics;
    while (*curr) {
        if (strcmp((*curr)->name, name) == 0) {
            p2p_topic_t *to_remove = *curr;
            *curr = (*curr)->next_topic;
            salts_mutex_unlock(&node->mutex);
            p2p_topic_destroy(to_remove);
            return P2P_OK;
        }
        curr = &(*curr)->next_topic;
    }
    salts_mutex_unlock(&node->mutex);
    return P2P_ERR_NOT_FOUND;
}

p2p_topic_t *p2p_node_detach_topics(p2p_node_t *node) {
    p2p_topic_t *topics = NULL;

    if (!node) {
        return NULL;
    }

    salts_mutex_lock(&node->mutex);
    topics = node->topics;
    node->topics = NULL;
    salts_mutex_unlock(&node->mutex);

    return topics;
}
