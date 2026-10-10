#include "node_cnet.h"
#include "node_state.h"
#include "peer_cnet.h"
#include "../transfer/transfer.h"
#include "../security/p2p_private_key_executor.h"
#include <salts/clock.h>
#include <stdlib.h>
#include <string.h>

struct p2p_node_cnet_s {
    p2p_node_t *node;
    p2p_cnet_owner_t *transport;
    p2p_cnet_admission_t *admission;
    size_t peer_limit;
    uint64_t maintenance_ms;
    int externally_hosted;
    int busy;
    int stopping;
    int detached;
    int stopped;
};

static int capacity_locked(p2p_node_t *node, const char *ip);

static int source_ip(const cnet_stream_peer *source, char ip[P2P_MAX_IP]) {
    int family = source->family == CNET_DATAGRAM_ADDRESS_IPV4 ? AF_INET :
        source->family == CNET_DATAGRAM_ADDRESS_IPV6 ? AF_INET6 : 0;
    if (!family || !inet_ntop(family, source->address, ip, P2P_MAX_IP))
        return P2P_ERR_INVALID_ARG;
    return P2P_OK;
}

static int connect_peer(p2p_peer_t *peer, void *context) {
    p2p_node_cnet_t *owner = context;
    int result = P2P_OK;
    if (owner->stopping) return P2P_ERR_INVALID_STATE;
    if (peer->state == P2P_PEER_STATE_DISCONNECTED) {
        cmeta_mutex_lock(&owner->node->mutex);
        /* The connector has already inserted a new endpoint. Retained failed
         * endpoints count too, so retries cannot grow an unbounded peer table. */
        if ((size_t)peer_table_count(owner->node->peers_table) > owner->peer_limit) {
            owner->node->security_rejection_counts[P2P_SECURITY_REJECTION_HANDSHAKE_RESOURCE]++;
            result = P2P_ERR_RESOURCE_EXHAUSTED;
        } else result = capacity_locked(owner->node, peer->ip);
        cmeta_mutex_unlock(&owner->node->mutex);
    }
    if (result != P2P_OK) return result;
    return p2p_peer_connect_cnet(peer, owner->transport);
}

static int pending_gates(p2p_node_t *node, const char *ip, size_t *total,
    size_t *source, void *context) {
    p2p_node_cnet_t *owner = context;
    (void)node;
    return p2p_cnet_admission_pending(owner->admission, ip, total, source);
}

static int poll_node(p2p_node_t *node, void *context) {
    (void)node;
    return p2p_node_cnet_poll(context);
}

static const p2p_node_network_ops_t network_ops = {connect_peer, pending_gates, poll_node};

static void cookie_status_locked(const p2p_node_t *node, p2p_node_cookie_status_t *output) {
    const p2p_node_cnet_t *owner = node->network_context;
    p2p_cnet_admission_stats_t stats;
    p2p_cnet_admission_stats_locked(owner->admission, &stats);
    output->active = stats.active;
    output->challenges_issued = stats.challenges_issued;
    output->verifications_succeeded = stats.verifications_succeeded;
}

static void stage_completed_locked(p2p_cnet_admission_stage_t stage,
    uint64_t started_ms, uint64_t completed_ms, void *context) {
    p2p_node_cnet_t *owner = context;
    p2p_node_record_handshake_latency_locked(owner->node, P2P_SECURITY_ROLE_RESPONDER,
        stage == P2P_CNET_ADMISSION_PREFACE ? P2P_SECURITY_LATENCY_PREFACE : P2P_SECURITY_LATENCY_COOKIE,
        started_ms, completed_ms);
}

static int capacity_locked(p2p_node_t *node, const char *ip) {
    p2p_security_rejection_reason_v2_t reason =
        p2p_node_pending_peer_rejection_locked(node, ip);
    if (reason == P2P_SECURITY_REJECTION_REASON_COUNT) return P2P_OK;
    node->security_rejection_counts[reason]++;
    return P2P_ERR_RESOURCE_EXHAUSTED;
}

static int admit(const cnet_stream_peer *source, void *context) {
    p2p_node_cnet_t *owner = context;
    p2p_node_t *node = owner->node;
    char ip[P2P_MAX_IP];
    int result;
    if (owner->stopping) return P2P_ERR_INVALID_STATE;
    result = source_ip(source, ip);
    if (result != P2P_OK) return result;
    cmeta_mutex_lock(&node->mutex);
    result = capacity_locked(node, ip);
    if (result == P2P_OK)
        result = p2p_node_source_admission_acquire_locked(node, ip, cmeta_monotonic_ms());
    cmeta_mutex_unlock(&node->mutex);
    return result;
}

static int promote(const cnet_stream_peer *source,
    const uint8_t preface[P2P_SECURE_PREFACE_SIZE],
    const uint8_t binding[P2P_COOKIE_BINDING_SIZE],
    p2p_cnet_callbacks_t *output, void *context) {
    p2p_node_cnet_t *owner = context;
    p2p_node_t *node = owner->node;
    p2p_peer_t *peer;
    char ip[P2P_MAX_IP];
    int result;
    if (owner->stopping) return P2P_ERR_INVALID_STATE;
    result = source_ip(source, ip);
    if (result != P2P_OK) return result;
    peer = p2p_peer_create(node, ip, source->port);
    if (!peer) {
        p2p_node_record_security_failure(node, P2P_SECURITY_STAGE_NOISE, P2P_ERR_NO_MEM);
        return P2P_ERR_NO_MEM;
    }
    cmeta_mutex_lock(&node->mutex);
    result = capacity_locked(node, ip);
    if (result == P2P_OK && (size_t)peer_table_count(node->peers_table) >= owner->peer_limit) {
        node->security_rejection_counts[P2P_SECURITY_REJECTION_HANDSHAKE_RESOURCE]++;
        result = P2P_ERR_RESOURCE_EXHAUSTED;
    }
    if (result == P2P_OK && p2p_node_find_peer_by_endpoint_locked(node, ip, source->port))
        result = P2P_ERR_INVALID_STATE;
    if (result == P2P_OK) {
        p2p_node_add_peer_locked(node, peer);
        if (p2p_node_find_peer_by_endpoint_locked(node, ip, source->port) != peer)
            result = P2P_ERR_NO_MEM;
    }
    cmeta_mutex_unlock(&node->mutex);
    if (result == P2P_OK)
        result = p2p_peer_prepare_cnet_inbound(peer, preface, binding, output);
    if (result != P2P_OK) {
        cmeta_mutex_lock(&node->mutex);
        if (p2p_node_find_peer_by_endpoint_locked(node, ip, source->port) == peer)
            p2p_node_remove_peer_by_endpoint_locked(node, ip, source->port);
        cmeta_mutex_unlock(&node->mutex);
        p2p_peer_destroy(peer);
        if (result != P2P_ERR_RESOURCE_EXHAUSTED)
            p2p_node_record_security_failure(node, P2P_SECURITY_STAGE_NOISE, result);
    }
    return result;
}

static void rejected(const cnet_stream_peer *source, int status,
    p2p_cnet_rejection_origin_t origin, void *context) {
    p2p_node_cnet_t *owner = context;
    p2p_security_rejection_reason_v2_t reason;
    (void)source;
    if (origin == P2P_CNET_REJECT_NODE_POLICY || origin == P2P_CNET_REJECT_PEER_POLICY)
        return; /* The rejecting node policy already classified this failure. */
    if (origin == P2P_CNET_REJECT_GATE_CAPACITY)
        reason = P2P_SECURITY_REJECTION_COOKIE_GATE_CAPACITY;
    else if (origin == P2P_CNET_REJECT_SOURCE_CAPACITY)
        reason = P2P_SECURITY_REJECTION_PENDING_SOURCE;
    else if (status == P2P_ERR_TIMEOUT)
        reason = P2P_SECURITY_REJECTION_COOKIE_EXPIRED;
    else {
        p2p_node_record_security_failure(owner->node, P2P_SECURITY_STAGE_COOKIE, status);
        return;
    }
    cmeta_mutex_lock(&owner->node->mutex);
    owner->node->security_rejection_counts[reason]++;
    cmeta_mutex_unlock(&owner->node->mutex);
}

static int node_cnet_create_impl(p2p_node_t *node, const p2p_cnet_config_t *config,
    native_io_backend *external_backend,
    native_io_sharded_host_lease host_lease, p2p_node_cnet_t **output) {
    p2p_node_cnet_t *owner;
    p2p_cnet_admission_config_t policy = {0};
    p2p_cnet_admission_callbacks_t callbacks = {
        admit, promote, rejected, NULL, stage_completed_locked};
    int result;
    if (!node || !config || !output) return P2P_ERR_INVALID_ARG;
    *output = NULL;
    if (node->ctx || node->server || node->gossip_timer || node->network_ops || node->network_context ||
        node->peers_table || node->dht_lookups || node->active_cookie_gates ||
        node->reserved_send_capacity_bytes || !node->kad_dht || !node->mutex ||
        !node->transfers || node->transfers->closing ||
        (node->private_key_executor && p2p_private_key_executor_is_closing(node->private_key_executor)))
        return P2P_ERR_INVALID_STATE;
    if (!node->security_configured) return P2P_ERR_AUTH_REQUIRED;
    if (!node->security_config.source_admission_burst ||
        !node->security_config.source_admission_refill_per_second ||
        !node->security_config.source_admission_bucket_limit ||
        node->security_config.source_admission_bucket_limit > P2P_SECURITY_SOURCE_ADMISSION_BUCKET_LIMIT ||
        node->security_config.cookie_gate_limit > P2P_SECURITY_COOKIE_GATE_LIMIT_MAX ||
        node->security_config.send_hwm_bytes > config->send_hwm_bytes ||
        node->security_config.node_send_budget_bytes < node->security_config.send_hwm_bytes)
        return P2P_ERR_INVALID_ARG;
    owner = calloc(1, sizeof(*owner));
    if (!owner) return P2P_ERR_NO_MEM;
    owner->node = node;
    owner->peer_limit = config->client.connection_capacity;
    owner->externally_hosted = external_backend != NULL;
    result = external_backend
        ? p2p_cnet_owner_create_external(config, external_backend,
                                         host_lease, &owner->transport)
        : p2p_cnet_owner_create(config, &owner->transport);
    if (result != P2P_OK) { free(owner); return result; }
    policy.gate_limit = node->security_config.cookie_gate_limit;
    policy.source_limit = policy.gate_limit < P2P_PENDING_PEER_SOURCE_LIMIT ?
        policy.gate_limit : P2P_PENDING_PEER_SOURCE_LIMIT;
    policy.peer_send_hwm_bytes = node->security_config.send_hwm_bytes;
    policy.handshake_timeout_ms = node->security_config.handshake_timeout_ms;
    policy.cookie_lifetime_ms = node->security_config.cookie_lifetime_ms;
    policy.cookie_key_rotation_ms = node->security_config.cookie_key_rotation_ms;
    policy.status_mutex = &node->mutex;
    memcpy(policy.network_id_hash, node->security_config.network_id_hash, sizeof(policy.network_id_hash));
    memcpy(policy.cookie_master_secret, node->cookie_master_secret, sizeof(policy.cookie_master_secret));
    callbacks.context = owner;
    result = p2p_cnet_admission_create(owner->transport, &policy, &callbacks, &owner->admission);
    p2p_crypto_wipe(&policy, sizeof(policy));
    if (result != P2P_OK) {
        /* No connections or callbacks exist yet. */
        p2p_cnet_owner_destroy(owner->transport);
        free(owner);
        return result;
    }
    cmeta_mutex_lock(&node->mutex);
    node->network_ops = &network_ops;
    node->network_context = owner;
    node->query_cookie_status_locked = cookie_status_locked;
    cmeta_mutex_unlock(&node->mutex);
    owner->maintenance_ms = cmeta_monotonic_ms();
    *output = owner;
    return P2P_OK;
}

int p2p_node_cnet_create(p2p_node_t *node, const p2p_cnet_config_t *config,
    p2p_node_cnet_t **output) {
    return node_cnet_create_impl(node, config, NULL,
                                 (native_io_sharded_host_lease){0}, output);
}

int p2p_node_cnet_create_external(p2p_node_t *node,
                                  const p2p_cnet_config_t *config,
                                  native_io_backend *borrowed_backend,
                                  native_io_sharded_host_lease lease,
                                  p2p_node_cnet_t **output) {
    if (!borrowed_backend) {
        if (output) *output = NULL;
        return P2P_ERR_INVALID_ARG;
    }
    return node_cnet_create_impl(node, config, borrowed_backend, lease, output);
}

int p2p_node_cnet_bind_handoff_accept(p2p_node_cnet_t *owner) {
    if (!owner || owner->busy || owner->stopping || !owner->admission)
        return P2P_ERR_INVALID_STATE;
    return p2p_cnet_owner_bind_handoff_accept(
        owner->transport, p2p_cnet_admission_accept, owner->admission);
}

p2p_cnet_owner_t *p2p_node_cnet_transport_owner(p2p_node_cnet_t *owner) {
    if (!owner || owner->stopping || owner->stopped || !owner->transport)
        return NULL;
    return owner->transport;
}

int p2p_node_cnet_listen(p2p_node_cnet_t *owner) {
    cnet_stream_peer local;
    int result;
    if (!owner) return P2P_ERR_INVALID_ARG;
    if (owner->busy || owner->stopping) return P2P_ERR_INVALID_STATE;
    if (owner->node->port < 0 || owner->node->port > UINT16_MAX) return P2P_ERR_INVALID_ARG;
    result = p2p_cnet_owner_listen(owner->transport, owner->node->ip,
        (uint16_t)owner->node->port, P2P_PENDING_PEER_LIMIT,
        p2p_cnet_admission_accept, owner->admission, &local);
    if (result == P2P_OK) owner->node->port = local.port;
    return result;
}

/* Direct protocol disconnects detach transport callbacks. Reconcile their
 * node membership on the same owner turn, with a lease through user callbacks.
 * O(P^2) worst-case removal scan, O(1) storage; P is bounded by the configured
 * CNet connection capacity, including retained disconnected endpoints. */
static void reap_disconnected(p2p_node_t *node) {
    for (;;) {
        p2p_peer_entry_t *entry, *tmp;
        p2p_peer_t *peer = NULL;
        cmeta_mutex_lock(&node->mutex);
        HASH_ITER(hh, node->peers_table, entry, tmp) {
            if (!entry->peer->conn && entry->peer->state == P2P_PEER_STATE_DISCONNECTED &&
                (entry->peer->counted || !entry->peer->keep_entry) &&
                p2p_peer_hold_locked(entry->peer)) { peer = entry->peer; break; }
        }
        cmeta_mutex_unlock(&node->mutex);
        if (!peer) break;
        int destroy = !peer->keep_entry;
        p2p_node_on_peer_disconnected(node, peer);
        if (destroy) p2p_peer_destroy(peer);
        p2p_peer_release(peer);
    }
}

static int node_cnet_poll_impl(p2p_node_cnet_t *owner,
                               cnet_client *const *extras, size_t extra_count,
                               native_io_sharded_context *context,
                               const native_io_sharded_host_lease *lease,
                               size_t *out_observed, size_t *out_sg_settled) {
    uint64_t now;
    int result;
    if (out_observed) *out_observed = 0u;
    if (out_sg_settled) *out_sg_settled = 0u;
    if (!owner) return P2P_ERR_INVALID_ARG;
    if (owner->busy || owner->stopping ||
        (context != NULL) != (owner->externally_hosted != 0))
        return P2P_ERR_INVALID_STATE;
    if (extra_count > P2P_CNET_SG_MAX_COHOST_CLIENTS ||
        (extra_count != 0u && (!extras || context == NULL)))
        return P2P_ERR_INVALID_ARG;
    /* Node-level failfast too: malformed external consumer lists must be
     * rejected before any P2P expiry, key-executor pump or Owner progress.
     * Transport's own check additionally rejects aliasing its private client. */
    for (size_t i = 0u; i < extra_count; ++i) {
        if (!extras[i]) return P2P_ERR_INVALID_ARG;
        for (size_t j = 0u; j < i; ++j)
            if (extras[i] == extras[j]) return P2P_ERR_INVALID_ARG;
    }
    owner->busy = 1;
    now = cmeta_monotonic_ms();
    result = p2p_cnet_admission_expire(owner->admission, now);
    p2p_node_expire_pending_peers(owner->node, now);
    if (result == P2P_OK && !owner->stopping) {
        p2p_private_key_executor_pump(owner->node);
        if (!owner->stopping)
            result = context
                ? p2p_cnet_owner_poll_sg_host_cohosted(
                    owner->transport, extras, extra_count, context,
                    *lease, out_observed, out_sg_settled)
                : p2p_cnet_owner_poll(owner->transport);
    }
    reap_disconnected(owner->node);
    if (!owner->stopping && now >= owner->maintenance_ms &&
        now - owner->maintenance_ms >= P2P_GOSSIP_INTERVAL) {
        owner->maintenance_ms = now;
        p2p_node_maintain_peers(owner->node, now);
        if (!owner->stopping && owner->node->transfers)
            p2p_transfer_manager_tick(owner->node->transfers, owner->node);
        if (!owner->stopping) p2p_gossip_start(owner->node);
    }
    owner->busy = 0;
    if (owner->stopping) return p2p_node_cnet_stop(owner);
    return result;
}

int p2p_node_cnet_poll(p2p_node_cnet_t *owner) {
    return node_cnet_poll_impl(owner, NULL, 0u,
                               NULL, NULL, NULL, NULL);
}

int p2p_node_cnet_poll_sg_host_cohosted(
    p2p_node_cnet_t *owner, cnet_client *const *extras, size_t extra_count,
    native_io_sharded_context *context,
    native_io_sharded_host_lease lease,
    size_t *out_observed, size_t *out_sg_settled) {
    if (!context || !out_observed || !out_sg_settled)
        return P2P_ERR_INVALID_ARG;
    return node_cnet_poll_impl(owner, extras, extra_count, context, &lease,
                               out_observed, out_sg_settled);
}

int p2p_node_cnet_poll_sg_host(p2p_node_cnet_t *owner,
                               native_io_sharded_context *context,
                               native_io_sharded_host_lease lease,
                               size_t *out_observed, size_t *out_sg_settled) {
    return p2p_node_cnet_poll_sg_host_cohosted(
        owner, NULL, 0u, context, lease, out_observed, out_sg_settled);
}

static void detach_node(p2p_node_cnet_t *owner) {
    p2p_node_t *node = owner->node;
    p2p_peer_entry_t *peers, *entry, *tmp;
    p2p_dht_lookup_t *lookups, *lookup, *next;
    /* Detach memberships before shutdown invokes any cancellation cleanup. */
    cmeta_mutex_lock(&node->mutex);
    peers = node->peers_table;
    node->peers_table = NULL;
    node->peer_count = 0;
    lookups = node->dht_lookups;
    node->dht_lookups = NULL;
    cmeta_mutex_unlock(&node->mutex);
    HASH_ITER(hh, peers, entry, tmp) {
        HASH_DEL(peers, entry);
        entry->peer->counted = 0;
        p2p_peer_destroy(entry->peer);
        free(entry);
    }
    p2p_private_key_executor_shutdown(node->private_key_executor);
    HASH_ITER(hh, lookups, lookup, next) {
        HASH_DEL(lookups, lookup);
        if (lookup->cleanup && lookup->user_data) lookup->cleanup(lookup->user_data);
        free(lookup);
    }
}

int p2p_node_cnet_stop(p2p_node_cnet_t *owner) {
    int result;
    if (!owner) return P2P_ERR_INVALID_ARG;
    owner->stopping = 1;
    /* Reentrant cleanup/application callbacks cannot enqueue a new lookup or
     * connection. Keep network_context borrowed until drain/destroy succeeds. */
    owner->node->network_ops = NULL;
    if (owner->busy || owner->stopped) return P2P_OK;
    owner->busy = 1;
    result = p2p_cnet_admission_stop(owner->admission);
    if (result == P2P_OK) {
        p2p_private_key_executor_shutdown(owner->node->private_key_executor);
        result = p2p_node_cleanup_transfers(owner->node);
    }
    if (result == P2P_OK && !owner->detached) {
        owner->detached = 1;
        detach_node(owner);
    }
    if (result == P2P_OK) result = p2p_cnet_owner_stop(owner->transport);
    if (result == P2P_OK) owner->stopped = 1;
    owner->busy = 0;
    return result;
}

int p2p_node_cnet_destroy(p2p_node_cnet_t *owner) {
    int result;
    if (!owner) return P2P_OK;
    if (owner->busy) return P2P_ERR_INVALID_STATE;
    result = p2p_node_cnet_stop(owner);
    if (result != P2P_OK) return result;
    result = p2p_cnet_owner_destroy(owner->transport);
    if (result != P2P_OK) return result;
    /* Transfer the final, quiescent counters before releasing their owner.
     * A concurrent status reader holds this same mutex and cannot observe a
     * retired query target. No live counter mirror exists during operation. */
    cmeta_mutex_lock(&owner->node->mutex);
    p2p_node_cookie_status_t final_status;
    cookie_status_locked(owner->node, &final_status);
    owner->node->active_cookie_gates = final_status.active;
    owner->node->cookie_challenges_issued = final_status.challenges_issued;
    owner->node->cookie_verifications_succeeded = final_status.verifications_succeeded;
    owner->node->query_cookie_status_locked = p2p_node_saved_cookie_status_locked;
    cmeta_mutex_unlock(&owner->node->mutex);
    result = p2p_cnet_admission_destroy(owner->admission);
    if (result != P2P_OK) return result;
    owner->node->network_ops = NULL;
    owner->node->network_context = NULL;
    free(owner);
    return P2P_OK;
}

int p2p_node_cnet_admission_stats(const p2p_node_cnet_t *owner,
    p2p_cnet_admission_stats_t *output) {
    if (!owner) return P2P_ERR_INVALID_ARG;
    return p2p_cnet_admission_stats(owner->admission, output);
}
