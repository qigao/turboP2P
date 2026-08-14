/**
 * p2p_api.c - P2P Public API implementation
 * Implements the professional interface defined in p2p.h
 */

#include "p2p.h"
#include "../internal.h"
#include "../core/node.h"
#include "../transfer/sha256.h"
#include "../transfer/transfer.h"
#include "../security/p2p_private_key_executor.h"
#include <CoroNet/turbo_coro_context.h>
#include <turbo_crypto.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <time.h>

static void p2p_set_manual_connect_suppression_locked(p2p_node_t *node,
                                                      const char *ip,
                                                      int port,
                                                      uint64_t until_ms) {
    p2p_connect_suppression_t *suppression = NULL;
    char key[96];

    if (!node || !ip) {
        return;
    }

    p2p_endpoint_to_key(key, sizeof(key), ip, port);
    HASH_FIND_STR(node->connect_suppressions, key, suppression);
    if (!suppression) {
        suppression = (p2p_connect_suppression_t *)calloc(1, sizeof(*suppression));
        if (!suppression) {
            return;
        }
        strncpy(suppression->key, key, sizeof(suppression->key) - 1);
        strncpy(suppression->ip, ip, sizeof(suppression->ip) - 1);
        suppression->port = port;
        HASH_ADD_STR(node->connect_suppressions, key, suppression);
    }

    suppression->until_ms = until_ms;
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

static void p2p_remove_peer_from_routing_locked(p2p_node_t *node, p2p_peer_t *peer) {
    if (!node || !node->kad_dht || !node->kad_dht->routing || !peer) {
        return;
    }

    p2p_node_remove_route_locked(node, NULL, peer->ip, peer->port);

    if (!p2p_id_is_zero(peer->id)) {
        p2p_node_remove_route_locked(node, peer->id, NULL, 0);
    }
}

static void p2p_mark_manual_disconnect_locked(p2p_node_t *node, p2p_peer_t *peer) {
    if (!node || !peer) {
        return;
    }

    peer->keep_entry = 0;
    p2p_set_manual_connect_suppression_locked(node, peer->ip, peer->port,
                                              (turbo_hrtime() / 1000000) +
                                                  P2P_MANUAL_DISCONNECT_SUPPRESS_MS);
    p2p_remove_peer_from_routing_locked(node, peer);
}

static int p2p_send_dht_store_to_peer(p2p_peer_t *peer,
                                      const kad_id_t *key,
                                      const void *data,
                                      size_t len) {
    p2p_message_t *msg = NULL;
    int ret = 0;

    if (!peer || !peer->is_connected || !key || !data || len == 0 ||
        len > sizeof(((p2p_dht_store_payload_t *)0)->data)) {
        return 0;
    }

    msg = (p2p_message_t *)calloc(1, sizeof(p2p_message_t));
    if (!msg) {
        return 0;
    }

    p2p_message_init(msg, P2P_MSG_DHT_PUT);
    memcpy(msg->payload.dht_store.key, key->bytes, KADEMLIA_ID_BYTES);
    msg->payload.dht_store.data_len = (uint16_t)len;
    memcpy(msg->payload.dht_store.data, data, len);
    msg->header.payload_len =
        (uint16_t)(offsetof(p2p_dht_store_payload_t, data) + len);

    ret = (p2p_peer_send(peer, msg) == P2P_OK) ? 1 : 0;
    free(msg);
    return ret;
}

static int p2p_send_dht_store_to_connected_peers(p2p_node_t *node,
                                                 const kad_id_t *key,
                                                 const void *data,
                                                 size_t len) {
    p2p_peer_t **peers = NULL;
    size_t count = 0;
    int sent = 0;

    if (!node || !key || !data || len == 0 || len > sizeof(((p2p_dht_store_payload_t *)0)->data)) {
        return 0;
    }

    peers = p2p_node_snapshot_connected_peers(node, &count);
    if (count > 0 && !peers) {
        return 0;
    }

    for (size_t i = 0; i < count; i++) {
        if (peers[i]) {
            sent += p2p_send_dht_store_to_peer(peers[i], key, data, len);
            p2p_peer_release(peers[i]);
        }
    }
    free(peers);

    return sent;
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

    turbo_mutex_lock(&node->mutex);
    if (force_retry) {
        p2p_clear_manual_connect_suppression_locked(node, ip, port);
    }
    peer = p2p_prepare_connect_peer_locked(node, ip, port, force_retry);
    turbo_mutex_unlock(&node->mutex);
    if (peer) {
        return p2p_peer_connect(peer);
    }

    peer = p2p_peer_create(node, ip, port);
    if (!peer) {
        return P2P_ERR_NO_MEM;
    }
    peer->keep_entry = 1;

    turbo_mutex_lock(&node->mutex);
    existing_peer = p2p_prepare_connect_peer_locked(node, ip, port, force_retry);
    if (existing_peer) {
        turbo_mutex_unlock(&node->mutex);
        p2p_peer_destroy(peer);
        return p2p_peer_connect(existing_peer);
    }
    p2p_node_add_peer_locked(node, peer);
    added_to_table = 1;
    turbo_mutex_unlock(&node->mutex);

    ret = p2p_peer_connect(peer);
    if (ret != P2P_OK) {
        if (added_to_table) {
            turbo_mutex_lock(&node->mutex);
            p2p_node_remove_peer_by_endpoint_locked(node, ip, port);
            turbo_mutex_unlock(&node->mutex);
        }
        p2p_peer_destroy(peer);
        return ret;
    }
    return P2P_OK;
}

static int p2p_send_dht_store_to_lookup_candidates(p2p_node_t *node,
                                                   const p2p_dht_lookup_t *lookup,
                                                   const kad_id_t *key,
                                                   const void *data,
                                                   size_t len) {
    p2p_peer_t **peers = NULL;
    size_t count = 0;
    int sent = 0;

    if (!node || !lookup || !key || !data || len == 0) {
        return 0;
    }

    turbo_mutex_lock(&node->mutex);
    if (lookup->candidate_count > 0) {
        peers = (p2p_peer_t **)calloc((size_t)lookup->candidate_count, sizeof(*peers));
    }
    if (lookup->candidate_count > 0 && !peers) {
        turbo_mutex_unlock(&node->mutex);
        return 0;
    }

    for (int i = 0; i < lookup->candidate_count; i++) {
        p2p_peer_t *peer = p2p_node_find_peer_by_endpoint_locked(node,
                                                                 lookup->candidates[i].ip,
                                                                 lookup->candidates[i].port);
        if (!peer) {
            continue;
        }
        if (!p2p_peer_hold_locked(peer)) {
            continue;
        }
        peers[count++] = peer;
    }
    turbo_mutex_unlock(&node->mutex);

    for (size_t i = 0; i < count; i++) {
        if (peers[i]) {
            sent += p2p_send_dht_store_to_peer(peers[i], key, data, len);
            p2p_peer_release(peers[i]);
        }
    }
    free(peers);

    return sent;
}

typedef struct {
    p2p_node_t *node;
    kad_id_t key;
    size_t len;
    uint8_t data[sizeof(((p2p_dht_store_payload_t *)0)->data)];
} p2p_pending_put_t;

static void p2p_dht_put_lookup_complete(void *result, void *user_data) {
    p2p_pending_put_t *put = (p2p_pending_put_t *)user_data;
    p2p_dht_lookup_t *lookup = (p2p_dht_lookup_t *)result;

    if (!lookup || !put || !put->node) {
        return;
    }

    (void)p2p_send_dht_store_to_lookup_candidates(put->node, lookup, &put->key,
                                                  put->data, put->len);
}

static int p2p_try_get_local_dht_value(p2p_node_t *node,
                                       const kad_id_t *key,
                                       void *buf,
                                       size_t *buf_len) {
    int found = -1;

    if (!node || !key || !buf || !buf_len) {
        return P2P_ERR_INVALID_ARG;
    }

    turbo_mutex_lock(&node->mutex);
    found = kademlia_find_value(node->kad_dht, key, buf, buf_len);
    turbo_mutex_unlock(&node->mutex);

    return (found == 0) ? P2P_OK : P2P_ERR_NOT_FOUND;
}

static int p2p_dht_lookup_is_active(p2p_node_t *node, uint32_t request_id) {
    int active = 0;

    if (!node) {
        return 0;
    }

    turbo_mutex_lock(&node->mutex);
    active = p2p_dht_lookup_find(node, request_id) != NULL;
    turbo_mutex_unlock(&node->mutex);

    return active;
}

/* =============================================================================
 * Node Lifecycle
 * ============================================================================= */

p2p_node_t *p2p_create(const char *ip, int port) {
    return p2p_node_create(ip, port);
}

void p2p_destroy(p2p_node_t *node) {
    if (!node) return;
    
    /* Use professional cleanup orchestration */
    p2p_destroy_clean(node);
}

int p2p_start(p2p_node_t *node) {
    int ret = 0;

    if (!node) return P2P_ERR_INVALID_ARG;

    ret = p2p_node_start_server(node);
    if (ret != P2P_OK) {
        return ret;
    }

    p2p_gossip_start(node);

    /* Event loop blocking run */
    coro_context_run(node->ctx, TURBO_RUN_DEFAULT);

    return P2P_OK;
}

int p2p_start_nonblocking(p2p_node_t *node) {
    int ret = 0;

    if (!node) return P2P_ERR_INVALID_ARG;

    ret = p2p_node_start_server(node);
    if (ret != P2P_OK) {
        return ret;
    }

    p2p_gossip_start(node);
    return P2P_OK;
}

coro_context_t *p2p_get_loop(p2p_node_t *node) {
    return node ? node->ctx : NULL;
}

static int p2p_node_identity_is_mutable_locked(const p2p_node_t *node) {
    return !node->server && node->peer_count == 0 &&
           !node->security_configured;
}

static int p2p_normalize_private_key_provider_error(int error) {
    switch (error) {
        case P2P_ERR_CRYPTO:
        case P2P_ERR_IO:
        case P2P_ERR_TIMEOUT:
        case P2P_ERR_RESOURCE_EXHAUSTED:
            return error;
        default:
            return P2P_ERR_CRYPTO;
    }
}

static int p2p_bytes_are_zero(const uint8_t *bytes, size_t size) {
    uint8_t value = 0;
    size_t index;

    for (index = 0; index < size; ++index) {
        value |= bytes[index];
    }
    return value == 0;
}

static int p2p_constant_time_equal(const uint8_t *left, const uint8_t *right,
                                   size_t size) {
    uint8_t difference = 0;
    size_t index;

    for (index = 0; index < size; ++index) {
        difference |= (uint8_t)(left[index] ^ right[index]);
    }
    return difference == 0;
}

static int p2p_private_key_provider_self_test(
    const p2p_private_key_provider_v3_t *provider,
    const uint8_t expected_public_key[P2P_KEY_SIZE]) {
    static const uint8_t x25519_basepoint[P2P_KEY_SIZE] = {9};
    uint8_t derived_public_key[P2P_KEY_SIZE] = {0};
    int ret;

    ret = provider->calculate_x25519(provider->context, x25519_basepoint,
                                     derived_public_key);
    if (ret != P2P_OK) {
        ret = p2p_normalize_private_key_provider_error(ret);
    } else if (!p2p_constant_time_equal(derived_public_key,
                                        expected_public_key,
                                        sizeof(derived_public_key))) {
        ret = P2P_ERR_CRYPTO;
    }
    p2p_crypto_wipe(derived_public_key, sizeof(derived_public_key));
    return ret;
}

static int p2p_private_key_self_test_not_cancelled(void *context) {
    (void)context;
    return 0;
}

static int p2p_blocking_private_key_provider_self_test(
    const p2p_blocking_private_key_provider_v4_t *provider,
    const uint8_t expected_public_key[P2P_KEY_SIZE],
    uint32_t timeout_ms) {
    static const uint8_t x25519_basepoint[P2P_KEY_SIZE] = {9};
    p2p_private_key_cancel_v4_t cancel = {0};
    uint8_t derived_public_key[P2P_KEY_SIZE] = {0};
    uint64_t now_ms = turbo_hrtime() / 1000000U;
    uint64_t deadline_ms = now_ms + timeout_ms;
    int ret;

    if (deadline_ms < now_ms) {
        deadline_ms = UINT64_MAX;
    }
    cancel.struct_size = sizeof(cancel);
    cancel.is_cancelled = p2p_private_key_self_test_not_cancelled;
    ret = provider->calculate_x25519(
        provider->context, x25519_basepoint, deadline_ms, &cancel,
        derived_public_key);
    now_ms = turbo_hrtime() / 1000000U;
    if (ret != P2P_OK) {
        ret = p2p_normalize_private_key_provider_error(ret);
    } else if (now_ms > deadline_ms) {
        ret = P2P_ERR_TIMEOUT;
    } else if (!p2p_constant_time_equal(derived_public_key,
                                        expected_public_key,
                                        sizeof(derived_public_key))) {
        ret = P2P_ERR_CRYPTO;
    }
    p2p_crypto_wipe(derived_public_key, sizeof(derived_public_key));
    return ret;
}

int p2p_node_get_id(p2p_node_t *node, uint8_t id_out[P2P_HASH_SIZE]) {
    if (!node || !id_out) {
        return P2P_ERR_INVALID_ARG;
    }

    turbo_mutex_lock(&node->mutex);
    memcpy(id_out, node->id, P2P_HASH_SIZE);
    turbo_mutex_unlock(&node->mutex);
    return P2P_OK;
}

int p2p_node_get_public_key(p2p_node_t *node,
                            uint8_t public_key_out[P2P_KEY_SIZE]) {
    if (!node || !public_key_out) {
        return P2P_ERR_INVALID_ARG;
    }

    turbo_mutex_lock(&node->mutex);
    memcpy(public_key_out, node->crypto.identity.public_key, P2P_KEY_SIZE);
    turbo_mutex_unlock(&node->mutex);
    return P2P_OK;
}

int p2p_node_set_private_key(p2p_node_t *node,
                             const uint8_t secret_key[P2P_KEY_SIZE]) {
    p2p_private_key_executor_t *old_executor = NULL;
    int ret = P2P_OK;

    if (!node || !secret_key) {
        return P2P_ERR_INVALID_ARG;
    }

    turbo_mutex_lock(&node->mutex);
    if (!p2p_node_identity_is_mutable_locked(node)) {
        ret = P2P_ERR_INVALID_STATE;
    } else {
        ret = p2p_crypto_identity_from_secret(&node->crypto.identity, secret_key);
        if (ret == P2P_OK) {
            old_executor = node->private_key_executor;
            node->private_key_executor = NULL;
        }
    }
    turbo_mutex_unlock(&node->mutex);
    p2p_private_key_executor_destroy(old_executor);
    return ret;
}

int p2p_node_set_private_key_provider_v3(
    p2p_node_t *node, const p2p_private_key_provider_v3_t *provider) {
    p2p_private_key_executor_t *old_executor = NULL;
    uint8_t public_key[P2P_KEY_SIZE] = {0};
    int ret;

    if (!node || !provider || provider->struct_size != sizeof(*provider) ||
        !provider->get_public_key || !provider->calculate_x25519) {
        return P2P_ERR_INVALID_ARG;
    }

    turbo_mutex_lock(&node->mutex);
    ret = p2p_node_identity_is_mutable_locked(node) ? P2P_OK
                                                     : P2P_ERR_INVALID_STATE;
    turbo_mutex_unlock(&node->mutex);
    if (ret != P2P_OK) {
        return ret;
    }

    ret = provider->get_public_key(provider->context, public_key);
    if (ret != P2P_OK) {
        p2p_crypto_wipe(public_key, sizeof(public_key));
        return p2p_normalize_private_key_provider_error(ret);
    }
    if (p2p_bytes_are_zero(public_key, sizeof(public_key))) {
        p2p_crypto_wipe(public_key, sizeof(public_key));
        return P2P_ERR_CRYPTO;
    }
    ret = p2p_private_key_provider_self_test(provider, public_key);
    if (ret != P2P_OK) {
        p2p_crypto_wipe(public_key, sizeof(public_key));
        return ret;
    }

    turbo_mutex_lock(&node->mutex);
    if (!p2p_node_identity_is_mutable_locked(node)) {
        ret = P2P_ERR_INVALID_STATE;
    } else {
        ret = p2p_crypto_identity_from_provider(&node->crypto.identity,
                                                provider, public_key);
        if (ret == P2P_OK) {
            old_executor = node->private_key_executor;
            node->private_key_executor = NULL;
        }
    }
    turbo_mutex_unlock(&node->mutex);
    p2p_crypto_wipe(public_key, sizeof(public_key));
    p2p_private_key_executor_destroy(old_executor);
    return ret;
}

int p2p_node_set_blocking_private_key_provider_v4(
    p2p_node_t *node,
    const p2p_blocking_private_key_provider_v4_t *provider) {
    p2p_private_key_executor_t *candidate = NULL;
    p2p_private_key_executor_t *old_executor = NULL;
    uint8_t public_key[P2P_KEY_SIZE] = {0};
    uint16_t workers;
    uint16_t capacity;
    uint32_t timeout_ms;
    int ret;

    if (!node || !provider || provider->struct_size != sizeof(*provider) ||
        !provider->get_public_key || !provider->calculate_x25519) {
        return P2P_ERR_INVALID_ARG;
    }
    workers = provider->executor_workers
                  ? provider->executor_workers
                  : P2P_PRIVATE_KEY_WORKERS_DEFAULT;
    capacity = provider->executor_capacity
                   ? provider->executor_capacity
                   : P2P_PRIVATE_KEY_CAPACITY_DEFAULT;
    timeout_ms = provider->operation_timeout_ms
                     ? provider->operation_timeout_ms
                     : P2P_PRIVATE_KEY_TIMEOUT_DEFAULT_MS;
    if (workers == 0 || workers > P2P_PRIVATE_KEY_WORKERS_MAX ||
        capacity == 0 || capacity > P2P_PRIVATE_KEY_CAPACITY_MAX ||
        workers > capacity || timeout_ms == 0 ||
        timeout_ms > P2P_PRIVATE_KEY_TIMEOUT_MAX_MS) {
        return P2P_ERR_INVALID_ARG;
    }

    turbo_mutex_lock(&node->mutex);
    ret = p2p_node_identity_is_mutable_locked(node) ? P2P_OK
                                                     : P2P_ERR_INVALID_STATE;
    turbo_mutex_unlock(&node->mutex);
    if (ret != P2P_OK) {
        return ret;
    }

    ret = provider->get_public_key(provider->context, public_key);
    if (ret != P2P_OK) {
        p2p_crypto_wipe(public_key, sizeof(public_key));
        return p2p_normalize_private_key_provider_error(ret);
    }
    if (p2p_bytes_are_zero(public_key, sizeof(public_key))) {
        p2p_crypto_wipe(public_key, sizeof(public_key));
        return P2P_ERR_CRYPTO;
    }
    ret = p2p_blocking_private_key_provider_self_test(
        provider, public_key, timeout_ms);
    if (ret != P2P_OK) {
        p2p_crypto_wipe(public_key, sizeof(public_key));
        return ret;
    }
    candidate = p2p_private_key_executor_create(node, provider);
    if (!candidate) {
        p2p_crypto_wipe(public_key, sizeof(public_key));
        return P2P_ERR_NO_MEM;
    }

    turbo_mutex_lock(&node->mutex);
    if (!p2p_node_identity_is_mutable_locked(node)) {
        ret = P2P_ERR_INVALID_STATE;
    } else {
        ret = p2p_crypto_identity_from_blocking_provider(
            &node->crypto.identity, &candidate->provider, public_key);
        if (ret == P2P_OK) {
            old_executor = node->private_key_executor;
            node->private_key_executor = candidate;
            candidate = NULL;
        }
    }
    turbo_mutex_unlock(&node->mutex);
    p2p_crypto_wipe(public_key, sizeof(public_key));
    p2p_private_key_executor_destroy(candidate);
    p2p_private_key_executor_destroy(old_executor);
    return ret;
}

static int p2p_pinned_derive_identity(
    const p2p_node_t *node, const uint8_t static_key[P2P_KEY_SIZE],
    p2p_authenticated_identity_v2_t *identity) {
    static const uint8_t principal_domain[] =
        "turbo-p2p-static-principal-v2";
    static const uint8_t routing_domain[] = "turbo-p2p-routing-id-v2";
    turbo_crypto_sha256_ctx_t hash;

    memset(identity, 0, sizeof(*identity));
    if (turbo_crypto_sha256_init(&hash) != TURBO_CRYPTO_OK ||
        turbo_crypto_sha256_update(&hash, principal_domain,
                                   sizeof(principal_domain) - 1) !=
            TURBO_CRYPTO_OK ||
        turbo_crypto_sha256_update(&hash, static_key, P2P_KEY_SIZE) !=
            TURBO_CRYPTO_OK ||
        turbo_crypto_sha256_final(&hash, identity->principal_id) !=
            TURBO_CRYPTO_OK ||
        turbo_crypto_sha256_init(&hash) != TURBO_CRYPTO_OK ||
        turbo_crypto_sha256_update(&hash, routing_domain,
                                   sizeof(routing_domain) - 1) !=
            TURBO_CRYPTO_OK ||
        turbo_crypto_sha256_update(&hash,
                                   node->security_config.network_id_hash,
                                   P2P_SECURITY_ID_SIZE) != TURBO_CRYPTO_OK ||
        turbo_crypto_sha256_update(&hash, identity->principal_id,
                                   P2P_SECURITY_ID_SIZE) != TURBO_CRYPTO_OK ||
        turbo_crypto_sha256_final(&hash, identity->routing_id) !=
            TURBO_CRYPTO_OK ||
        turbo_crypto_sha256("", 0, identity->credential_digest) !=
            TURBO_CRYPTO_OK) {
        p2p_crypto_wipe(&hash, sizeof(hash));
        p2p_crypto_wipe(identity, sizeof(*identity));
        return P2P_ERR_CRYPTO;
    }
    p2p_crypto_wipe(&hash, sizeof(hash));
    identity->trust_epoch = 1;
    identity->flags = 1;
    return P2P_OK;
}

static int p2p_pinned_build_local_credential(
    void *context, const uint8_t local_noise_static[P2P_KEY_SIZE],
    uint8_t *output, size_t output_capacity, size_t *out_len,
    p2p_authenticated_identity_v2_t *out_identity) {
    p2p_node_t *node = (p2p_node_t *)context;

    if (!node || !local_noise_static || !output || output_capacity == 0 ||
        !out_len || !out_identity) {
        return P2P_ERR_INVALID_ARG;
    }
    *out_len = 0;
    return p2p_pinned_derive_identity(node, local_noise_static, out_identity);
}

static int p2p_pinned_verify_remote_credential(
    void *context, const uint8_t remote_noise_static[P2P_KEY_SIZE],
    const uint8_t channel_binding[P2P_SECURITY_ID_SIZE],
    const uint8_t *credential, size_t credential_len, uint64_t now_ms,
    p2p_authenticated_identity_v2_t *out_identity) {
    p2p_node_t *node = (p2p_node_t *)context;
    size_t index;
    int trusted = 0;

    (void)channel_binding;
    (void)now_ms;
    if (!node || !remote_noise_static || !credential || credential_len != 0 ||
        !out_identity) {
        return P2P_ERR_UNTRUSTED_IDENTITY;
    }
    for (index = 0; index < node->pinned_trusted_key_count; ++index) {
        trusted |= p2p_constant_time_equal(
            remote_noise_static,
            node->pinned_trusted_keys + index * P2P_KEY_SIZE,
            P2P_KEY_SIZE);
    }
    if (!trusted) {
        return P2P_ERR_UNTRUSTED_IDENTITY;
    }
    return p2p_pinned_derive_identity(node, remote_noise_static,
                                      out_identity);
}

static int p2p_node_configure_security_locked(
    p2p_node_t *node, const p2p_security_config_v2_t *config) {
    p2p_authenticated_identity_v2_t local_identity = {0};
    uint8_t local_credential[P2P_SECURITY_CREDENTIAL_MAX] = {0};
    size_t local_credential_len = 0;
    uint16_t credential_limit;
    uint16_t frame_limit;
    size_t send_hwm_bytes;
    size_t node_send_budget_bytes;
    uint64_t session_max_age_ms;
    uint64_t session_max_bytes;
    uint16_t source_admission_burst;
    uint16_t source_admission_refill_per_second;
    uint16_t source_admission_bucket_limit;
    uint16_t cookie_gate_limit;
    uint32_t cookie_lifetime_ms;
    uint32_t cookie_key_rotation_ms;
    uint32_t handshake_timeout_ms;
    uint8_t cookie_master_secret[P2P_SECURITY_COOKIE_SECRET_SIZE] = {0};
    int ret;

    if (!node || !config || config->struct_size != sizeof(*config) ||
        !config->identity_provider.build_local_credential ||
        !config->identity_provider.verify_remote_credential ||
        p2p_bytes_are_zero(config->network_id_hash,
                           sizeof(config->network_id_hash))) {
        return P2P_ERR_INVALID_ARG;
    }
    credential_limit = config->credential_limit
                           ? config->credential_limit
                           : P2P_SECURITY_CREDENTIAL_MAX;
    frame_limit = config->handshake_frame_limit
                      ? config->handshake_frame_limit
                      : P2P_SECURITY_HANDSHAKE_FRAME_MAX;
    send_hwm_bytes = config->send_hwm_bytes
                         ? config->send_hwm_bytes
                         : P2P_SECURITY_SEND_HWM_DEFAULT_BYTES;
    node_send_budget_bytes = config->node_send_budget_bytes
                                 ? config->node_send_budget_bytes
                                 : P2P_SECURITY_NODE_SEND_BUDGET_DEFAULT_BYTES;
    source_admission_burst = config->source_admission_burst
                                 ? config->source_admission_burst
                                 : P2P_SECURITY_SOURCE_ADMISSION_BURST_DEFAULT;
    source_admission_refill_per_second =
        config->source_admission_refill_per_second
            ? config->source_admission_refill_per_second
            : P2P_SECURITY_SOURCE_ADMISSION_REFILL_DEFAULT;
    source_admission_bucket_limit = config->source_admission_bucket_limit
                                        ? config->source_admission_bucket_limit
                                        : P2P_SECURITY_SOURCE_ADMISSION_BUCKET_LIMIT;
    cookie_gate_limit = config->cookie_gate_limit
                            ? config->cookie_gate_limit
                            : P2P_SECURITY_COOKIE_GATE_LIMIT_DEFAULT;
    cookie_lifetime_ms = config->cookie_lifetime_ms
                             ? config->cookie_lifetime_ms
                             : P2P_SECURITY_COOKIE_LIFETIME_DEFAULT_MS;
    cookie_key_rotation_ms = config->cookie_key_rotation_ms
                                 ? config->cookie_key_rotation_ms
                                 : P2P_SECURITY_COOKIE_ROTATION_DEFAULT_MS;
    session_max_age_ms = config->session_max_age_ms
                             ? config->session_max_age_ms
                             : P2P_SECURITY_SESSION_MAX_AGE_DEFAULT_MS;
    session_max_bytes = config->session_max_bytes_per_direction
                            ? config->session_max_bytes_per_direction
                            : P2P_SECURITY_SESSION_MAX_BYTES_DEFAULT;
    handshake_timeout_ms = config->handshake_timeout_ms
                               ? config->handshake_timeout_ms
                               : P2P_SECURITY_HANDSHAKE_TIMEOUT_DEFAULT_MS;
    if (credential_limit > P2P_SECURITY_CREDENTIAL_MAX ||
        frame_limit > P2P_SECURITY_HANDSHAKE_FRAME_MAX ||
        frame_limit < credential_limit + P2P_SECURITY_HANDSHAKE_FIXED_OVERHEAD ||
        send_hwm_bytes < P2P_SECURITY_MAX_WIRE_FRAME_BYTES ||
        send_hwm_bytes > P2P_SECURITY_SEND_HWM_MAX_BYTES ||
        node_send_budget_bytes < send_hwm_bytes ||
        node_send_budget_bytes >
            P2P_SECURITY_NODE_SEND_BUDGET_DEFAULT_BYTES ||
        source_admission_burst > P2P_SECURITY_SOURCE_ADMISSION_BURST_MAX ||
        source_admission_refill_per_second >
            P2P_SECURITY_SOURCE_ADMISSION_REFILL_MAX ||
        source_admission_bucket_limit >
            P2P_SECURITY_SOURCE_ADMISSION_BUCKET_LIMIT ||
        cookie_gate_limit > P2P_SECURITY_COOKIE_GATE_LIMIT_MAX ||
        cookie_lifetime_ms > P2P_SECURITY_COOKIE_LIFETIME_MAX_MS ||
        cookie_key_rotation_ms > P2P_SECURITY_COOKIE_ROTATION_MAX_MS ||
        cookie_key_rotation_ms < cookie_lifetime_ms ||
        cookie_key_rotation_ms % cookie_lifetime_ms != 0 ||
        session_max_age_ms > P2P_SECURITY_SESSION_MAX_AGE_DEFAULT_MS ||
        session_max_bytes < P2P_SECURITY_MAX_WIRE_FRAME_BYTES ||
        session_max_bytes > P2P_SECURITY_SESSION_MAX_BYTES_DEFAULT ||
        (node->private_key_executor &&
         node->private_key_executor->operation_timeout_ms >
             handshake_timeout_ms)) {
        return P2P_ERR_INVALID_ARG;
    }
    if (node->server || node->peer_count > 0 || node->security_configured) {
        return P2P_ERR_INVALID_STATE;
    }

    ret = p2p_crypto_random(cookie_master_secret,
                            sizeof(cookie_master_secret));
    if (ret != P2P_OK) {
        return ret;
    }

    ret = config->identity_provider.build_local_credential(
        config->identity_provider.context, node->crypto.identity.public_key,
        local_credential, credential_limit, &local_credential_len,
        &local_identity);
    if (ret != P2P_OK || local_credential_len > credential_limit ||
        p2p_bytes_are_zero(local_identity.principal_id,
                           sizeof(local_identity.principal_id)) ||
        p2p_bytes_are_zero(local_identity.routing_id,
                           sizeof(local_identity.routing_id)) ||
        p2p_bytes_are_zero(local_identity.credential_digest,
                           sizeof(local_identity.credential_digest))) {
        p2p_crypto_wipe(local_credential, sizeof(local_credential));
        p2p_crypto_wipe(&local_identity, sizeof(local_identity));
        p2p_crypto_wipe(cookie_master_secret,
                        sizeof(cookie_master_secret));
        return ret == P2P_OK ? P2P_ERR_UNTRUSTED_IDENTITY : ret;
    }

    node->security_config = *config;
    node->security_config.credential_limit = credential_limit;
    node->security_config.handshake_frame_limit = frame_limit;
    node->security_config.send_hwm_bytes = send_hwm_bytes;
    node->security_config.node_send_budget_bytes = node_send_budget_bytes;
    node->security_config.source_admission_burst = source_admission_burst;
    node->security_config.source_admission_refill_per_second =
        source_admission_refill_per_second;
    node->security_config.source_admission_bucket_limit =
        source_admission_bucket_limit;
    node->security_config.cookie_gate_limit = cookie_gate_limit;
    node->security_config.cookie_lifetime_ms = cookie_lifetime_ms;
    node->security_config.cookie_key_rotation_ms = cookie_key_rotation_ms;
    node->security_config.session_max_age_ms = session_max_age_ms;
    node->security_config.session_max_bytes_per_direction = session_max_bytes;
    node->security_config.handshake_timeout_ms = handshake_timeout_ms;
    if (!node->security_config.ready_timeout_ms) {
        node->security_config.ready_timeout_ms =
            P2P_SECURITY_READY_TIMEOUT_DEFAULT_MS;
    }
    memcpy(node->local_credential, local_credential,
           local_credential_len);
    memcpy(node->cookie_master_secret, cookie_master_secret,
           sizeof(cookie_master_secret));
    node->local_credential_len = local_credential_len;
    node->local_authenticated_identity = local_identity;
    memcpy(node->id, local_identity.routing_id, P2P_HASH_SIZE);
    memcpy(node->kad_dht->routing->local_id.bytes,
           local_identity.routing_id, P2P_HASH_SIZE);
    node->security_configured = 1;
    ret = P2P_OK;
    p2p_crypto_wipe(local_credential, sizeof(local_credential));
    p2p_crypto_wipe(&local_identity, sizeof(local_identity));
    p2p_crypto_wipe(cookie_master_secret, sizeof(cookie_master_secret));
    return ret;
}

_Static_assert(P2P_SECURITY_ROLE_INITIATOR == 0 &&
                   P2P_SECURITY_ROLE_RESPONDER == 1 &&
                   P2P_SECURITY_ROLE_COUNT == 2,
               "internal security role order changed");
_Static_assert(P2P_SECURITY_HANDSHAKE_ROLE_INITIATOR_V3 == 0 &&
                   P2P_SECURITY_HANDSHAKE_ROLE_RESPONDER_V3 == 1 &&
                   P2P_SECURITY_HANDSHAKE_ROLE_COUNT_V3 == 2,
               "public security role order changed");
_Static_assert(P2P_SECURITY_LATENCY_COOKIE == 0 &&
                   P2P_SECURITY_LATENCY_PREFACE == 1 &&
                   P2P_SECURITY_LATENCY_NOISE == 2 &&
                   P2P_SECURITY_LATENCY_READY == 3 &&
                   P2P_SECURITY_LATENCY_STAGE_COUNT == 4,
               "internal security stage order changed");
_Static_assert(P2P_SECURITY_HANDSHAKE_STAGE_COOKIE_V3 == 0 &&
                   P2P_SECURITY_HANDSHAKE_STAGE_PREFACE_V3 == 1 &&
                   P2P_SECURITY_HANDSHAKE_STAGE_NOISE_V3 == 2 &&
                   P2P_SECURITY_HANDSHAKE_STAGE_READY_V3 == 3 &&
                   P2P_SECURITY_HANDSHAKE_STAGE_COUNT_V3 == 4,
               "public security stage order changed");
_Static_assert(P2P_SECURITY_LATENCY_BUCKET_COUNT ==
                   P2P_SECURITY_LATENCY_BUCKET_COUNT_V3,
               "public and internal latency bucket counts must match");

static void p2p_node_fill_security_status_v2_locked(
    const p2p_node_t *node, p2p_node_security_status_v2_t *status) {
    size_t bucket_index;

    memset(status, 0, sizeof(*status));
    status->struct_size = sizeof(*status);
    status->send_budget_bytes =
        node->security_config.node_send_budget_bytes;
    status->reserved_send_capacity_bytes =
        node->reserved_send_capacity_bytes;
    status->available_send_capacity_bytes =
        node->reserved_send_capacity_bytes <=
                node->security_config.node_send_budget_bytes
            ? node->security_config.node_send_budget_bytes -
                  node->reserved_send_capacity_bytes
            : 0;
    status->transport_reservations = node->transport_send_reservations;
    status->send_budget_rejections = node->send_budget_rejections;
    status->source_admission_burst =
        node->security_config.source_admission_burst;
    status->source_admission_refill_per_second =
        node->security_config.source_admission_refill_per_second;
    status->source_admission_bucket_limit =
        node->security_config.source_admission_bucket_limit;
    status->cookie_gate_limit = node->security_config.cookie_gate_limit;
    status->active_cookie_gates = node->active_cookie_gates;
    status->cookie_challenges_issued = node->cookie_challenges_issued;
    status->cookie_verifications_succeeded =
        node->cookie_verifications_succeeded;
    for (bucket_index = 0;
         bucket_index < node->security_config.source_admission_bucket_limit;
         ++bucket_index) {
        if (node->source_admission_buckets[bucket_index].used) {
            status->active_source_admission_buckets++;
        }
    }
    memcpy(status->rejection_counts, node->security_rejection_counts,
           sizeof(status->rejection_counts));
}

static void p2p_node_fill_private_key_executor_status_v4_locked(
    const p2p_private_key_executor_t *executor,
    p2p_private_key_executor_status_v4_t *status) {
    turbo_threadpool_stats_t pool_status = {0};

    memset(status, 0, sizeof(*status));
    status->struct_size = sizeof(*status);
    if (executor->pool) {
        turbo_threadpool_get_stats(executor->pool, &pool_status);
    }
    status->workers = executor->workers;
    status->operation_capacity = executor->capacity;
    status->operation_timeout_ms = executor->operation_timeout_ms;
    status->active_operations = executor->active_operations;
    status->queued_operations = pool_status.queued_tasks > 0
                                    ? (size_t)pool_status.queued_tasks
                                    : 0;
    status->accepting =
        !p2p_private_key_executor_is_closing(executor) &&
        pool_status.accepting != 0;
    status->submitted = executor->submitted;
    status->completed = executor->completed;
    status->rejected = executor->rejected;
    status->timed_out = executor->timed_out;
    status->cancelled = executor->cancelled;
    status->completion_post_failures = executor->completion_post_failures;
}

int p2p_node_get_security_status_v2(
    p2p_node_t *node, p2p_node_security_status_v2_t *status) {
    if (!node || !status || status->struct_size != sizeof(*status)) {
        return P2P_ERR_INVALID_ARG;
    }

    turbo_mutex_lock(&node->mutex);
    if (!node->security_configured) {
        turbo_mutex_unlock(&node->mutex);
        return P2P_ERR_INVALID_STATE;
    }
    p2p_node_fill_security_status_v2_locked(node, status);
    turbo_mutex_unlock(&node->mutex);
    return P2P_OK;
}

int p2p_node_get_security_status_v3(
    p2p_node_t *node, p2p_node_security_status_v3_t *status) {
    size_t role;
    size_t stage;

    if (!node || !status || status->struct_size != sizeof(*status)) {
        return P2P_ERR_INVALID_ARG;
    }

    turbo_mutex_lock(&node->mutex);
    if (!node->security_configured) {
        turbo_mutex_unlock(&node->mutex);
        return P2P_ERR_INVALID_STATE;
    }
    memset(status, 0, sizeof(*status));
    status->struct_size = sizeof(*status);
    status->secure_wire_version = P2P_SECURE_WIRE_VERSION_V2;
    status->noise_suite = P2P_NOISE_SUITE_XX_25519_CHACHAPOLY_BLAKE2S;
    p2p_node_fill_security_status_v2_locked(node, &status->security);
    status->private_key_executor.struct_size =
        sizeof(status->private_key_executor);
    if (node->private_key_executor) {
        status->private_key_executor_available = 1;
        p2p_node_fill_private_key_executor_status_v4_locked(
            node->private_key_executor, &status->private_key_executor);
    }
    memcpy(status->latency_bucket_upper_bounds_ms,
           p2p_security_latency_bucket_upper_bounds_ms,
           sizeof(status->latency_bucket_upper_bounds_ms));
    for (role = 0; role < P2P_SECURITY_HANDSHAKE_ROLE_COUNT_V3; ++role) {
        for (stage = 0; stage < P2P_SECURITY_HANDSHAKE_STAGE_COUNT_V3;
             ++stage) {
            const p2p_security_latency_accumulator_t *source =
                &node->security_handshake_latency[role][stage];
            p2p_security_handshake_latency_v3_t *destination =
                &status->handshake_latency[role][stage];

            destination->completed = source->completed;
            destination->total_ms = source->total_ms;
            destination->maximum_ms = source->maximum_ms;
            memcpy(destination->buckets, source->buckets,
                   sizeof(destination->buckets));
        }
    }
    turbo_mutex_unlock(&node->mutex);
    return P2P_OK;
}

int p2p_node_get_private_key_executor_status_v4(
    p2p_node_t *node, p2p_private_key_executor_status_v4_t *status) {
    p2p_private_key_executor_t *executor;

    if (!node || !status || status->struct_size != sizeof(*status)) {
        return P2P_ERR_INVALID_ARG;
    }
    turbo_mutex_lock(&node->mutex);
    executor = node->private_key_executor;
    if (!executor) {
        turbo_mutex_unlock(&node->mutex);
        return P2P_ERR_INVALID_STATE;
    }
    p2p_node_fill_private_key_executor_status_v4_locked(executor, status);
    turbo_mutex_unlock(&node->mutex);
    return P2P_OK;
}

static size_t p2p_node_disconnect_all_security_sessions(
    p2p_node_t *node) {
    size_t disconnected = 0;

    for (;;) {
        p2p_peer_entry_t *entry = NULL;
        p2p_peer_entry_t *temporary = NULL;
        p2p_peer_t *peer = NULL;

        turbo_mutex_lock(&node->mutex);
        HASH_ITER(hh, node->peers_table, entry, temporary) {
            if (entry->peer && !entry->peer->destroying &&
                entry->peer->is_connected && entry->peer->conn &&
                entry->peer->security_stage ==
                    P2P_SECURITY_STAGE_ESTABLISHED &&
                p2p_peer_hold_locked(entry->peer)) {
                peer = entry->peer;
                break;
            }
        }
        turbo_mutex_unlock(&node->mutex);

        if (!peer) {
            return disconnected;
        }
        p2p_disconnect_peer(peer);
        p2p_peer_release(peer);
        disconnected++;
    }
}

int p2p_node_revalidate_security_v2(
    p2p_node_t *node, p2p_security_revalidation_result_v2_t *result) {
    p2p_peer_t **peers = NULL;
    size_t peer_count = 0;
    size_t index;

    if (!node || !result || result->struct_size != sizeof(*result)) {
        return P2P_ERR_INVALID_ARG;
    }
    memset((uint8_t *)result + sizeof(result->struct_size), 0,
           sizeof(*result) - sizeof(result->struct_size));

    turbo_mutex_lock(&node->mutex);
    if (!node->security_configured) {
        turbo_mutex_unlock(&node->mutex);
        return P2P_ERR_INVALID_STATE;
    }
    turbo_mutex_unlock(&node->mutex);

    peers = p2p_node_snapshot_connected_peers(node, &peer_count);
    if (peer_count > 0 && !peers) {
        result->disconnected_sessions =
            p2p_node_disconnect_all_security_sessions(node);
        turbo_mutex_lock(&node->mutex);
        node->security_rejection_counts[
            P2P_SECURITY_REJECTION_REVALIDATION_FAIL_CLOSED]++;
        turbo_mutex_unlock(&node->mutex);
        return P2P_ERR_NO_MEM;
    }

    for (index = 0; index < peer_count; ++index) {
        p2p_peer_t *peer = peers[index];
        p2p_authenticated_identity_v2_t previous_identity = {0};
        p2p_authenticated_identity_v2_t current_identity = {0};
        uint8_t remote_key[P2P_KEY_SIZE] = {0};
        uint8_t channel_binding[P2P_SECURITY_ID_SIZE] = {0};
        uint8_t credential[P2P_SECURITY_CREDENTIAL_MAX] = {0};
        size_t credential_len = 0;
        int eligible = 0;
        int verify_ret;

        if (!peer) {
            continue;
        }
        turbo_mutex_lock(&node->mutex);
        if (!peer->destroying && peer->is_connected && peer->conn &&
            peer->security_stage == P2P_SECURITY_STAGE_ESTABLISHED &&
            peer->remote_public_key_ready &&
            peer->remote_credential_len <= sizeof(credential)) {
            memcpy(remote_key, peer->remote_public_key, sizeof(remote_key));
            memcpy(channel_binding, peer->channel_binding,
                   sizeof(channel_binding));
            credential_len = peer->remote_credential_len;
            memcpy(credential, peer->remote_credential, credential_len);
            previous_identity = peer->authenticated_identity;
            eligible = 1;
        }
        turbo_mutex_unlock(&node->mutex);

        if (!eligible) {
            p2p_peer_release(peer);
            continue;
        }
        result->examined_sessions++;
        verify_ret =
            node->security_config.identity_provider.verify_remote_credential(
                node->security_config.identity_provider.context, remote_key,
                channel_binding, credential, credential_len,
                (uint64_t)time(NULL) * 1000U, &current_identity);
        if (verify_ret != P2P_OK) {
            result->provider_rejections++;
            result->disconnected_sessions++;
            p2p_disconnect_peer(peer);
        } else if (memcmp(&current_identity, &previous_identity,
                          sizeof(current_identity)) != 0) {
            result->identity_changes++;
            result->disconnected_sessions++;
            p2p_disconnect_peer(peer);
        } else {
            result->retained_sessions++;
        }

        p2p_crypto_wipe(&previous_identity, sizeof(previous_identity));
        p2p_crypto_wipe(&current_identity, sizeof(current_identity));
        p2p_crypto_wipe(remote_key, sizeof(remote_key));
        p2p_crypto_wipe(channel_binding, sizeof(channel_binding));
        p2p_crypto_wipe(credential, sizeof(credential));
        p2p_peer_release(peer);
    }
    free(peers);
    turbo_mutex_lock(&node->mutex);
    node->security_rejection_counts[
        P2P_SECURITY_REJECTION_REVALIDATION_REJECTED] +=
        result->provider_rejections;
    node->security_rejection_counts[
        P2P_SECURITY_REJECTION_REVALIDATION_IDENTITY_CHANGE] +=
        result->identity_changes;
    turbo_mutex_unlock(&node->mutex);
    return P2P_OK;
}

int p2p_node_configure_security_v2(
    p2p_node_t *node, const p2p_security_config_v2_t *config) {
    int ret;

    if (!node) {
        return P2P_ERR_INVALID_ARG;
    }
    turbo_mutex_lock(&node->mutex);
    ret = p2p_node_configure_security_locked(node, config);
    turbo_mutex_unlock(&node->mutex);
    return ret;
}

int p2p_node_configure_pinned_security_v2(
    p2p_node_t *node,
    const uint8_t network_id_hash[P2P_SECURITY_ID_SIZE],
    const uint8_t *trusted_public_keys,
    size_t trusted_key_count) {
    p2p_security_config_v2_t config = {0};
    uint8_t *key_copy;
    int ret;

    if (!node || !network_id_hash || !trusted_public_keys ||
        trusted_key_count == 0 ||
        trusted_key_count > P2P_PINNED_TRUST_KEY_LIMIT ||
        p2p_bytes_are_zero(network_id_hash, P2P_SECURITY_ID_SIZE)) {
        return P2P_ERR_INVALID_ARG;
    }
    key_copy = (uint8_t *)malloc(trusted_key_count * P2P_KEY_SIZE);
    if (!key_copy) {
        return P2P_ERR_NO_MEM;
    }
    memcpy(key_copy, trusted_public_keys,
           trusted_key_count * P2P_KEY_SIZE);

    turbo_mutex_lock(&node->mutex);
    if (node->server || node->peer_count > 0 || node->security_configured ||
        node->pinned_trusted_keys) {
        turbo_mutex_unlock(&node->mutex);
        p2p_crypto_wipe(key_copy, trusted_key_count * P2P_KEY_SIZE);
        free(key_copy);
        return P2P_ERR_INVALID_STATE;
    }
    node->pinned_trusted_keys = key_copy;
    node->pinned_trusted_key_count = trusted_key_count;
    memcpy(node->security_config.network_id_hash, network_id_hash,
           P2P_SECURITY_ID_SIZE);
    config.struct_size = sizeof(config);
    memcpy(config.network_id_hash, network_id_hash,
           P2P_SECURITY_ID_SIZE);
    config.identity_provider.build_local_credential =
        p2p_pinned_build_local_credential;
    config.identity_provider.verify_remote_credential =
        p2p_pinned_verify_remote_credential;
    config.identity_provider.context = node;
    ret = p2p_node_configure_security_locked(node, &config);
    if (ret != P2P_OK) {
        node->pinned_trusted_keys = NULL;
        node->pinned_trusted_key_count = 0;
        memset(node->security_config.network_id_hash, 0,
               P2P_SECURITY_ID_SIZE);
        p2p_crypto_wipe(key_copy, trusted_key_count * P2P_KEY_SIZE);
        free(key_copy);
    }
    turbo_mutex_unlock(&node->mutex);
    return ret;
}

int p2p_node_update_pinned_trust_v2(
    p2p_node_t *node, const uint8_t *trusted_public_keys,
    size_t trusted_key_count,
    p2p_security_revalidation_result_v2_t *out_revalidation) {
    uint8_t *key_copy = NULL;
    uint8_t *old_keys = NULL;
    size_t old_key_count = 0;
    int pinned_provider = 0;

    if (!node || !out_revalidation ||
        out_revalidation->struct_size != sizeof(*out_revalidation) ||
        trusted_key_count > P2P_PINNED_TRUST_KEY_LIMIT ||
        (trusted_key_count > 0 && !trusted_public_keys)) {
        return P2P_ERR_INVALID_ARG;
    }
    memset((uint8_t *)out_revalidation +
               sizeof(out_revalidation->struct_size),
           0, sizeof(*out_revalidation) -
                  sizeof(out_revalidation->struct_size));
    if (trusted_key_count > 0) {
        key_copy = (uint8_t *)malloc(trusted_key_count * P2P_KEY_SIZE);
        if (!key_copy) {
            return P2P_ERR_NO_MEM;
        }
        memcpy(key_copy, trusted_public_keys,
               trusted_key_count * P2P_KEY_SIZE);
    }

    turbo_mutex_lock(&node->mutex);
    pinned_provider =
        node->security_configured &&
        node->security_config.identity_provider.context == node &&
        node->security_config.identity_provider.build_local_credential ==
            p2p_pinned_build_local_credential &&
        node->security_config.identity_provider.verify_remote_credential ==
            p2p_pinned_verify_remote_credential;
    if (pinned_provider) {
        old_keys = node->pinned_trusted_keys;
        old_key_count = node->pinned_trusted_key_count;
        node->pinned_trusted_keys = key_copy;
        node->pinned_trusted_key_count = trusted_key_count;
    }
    turbo_mutex_unlock(&node->mutex);

    if (!pinned_provider) {
        if (key_copy) {
            p2p_crypto_wipe(key_copy,
                            trusted_key_count * P2P_KEY_SIZE);
            free(key_copy);
        }
        return P2P_ERR_INVALID_STATE;
    }
    if (old_keys) {
        p2p_crypto_wipe(old_keys, old_key_count * P2P_KEY_SIZE);
        free(old_keys);
    }
    return p2p_node_revalidate_security_v2(node, out_revalidation);
}

int p2p_generate_private_key(uint8_t secret_key_out[P2P_KEY_SIZE]) {
    p2p_identity_t identity = {0};
    int ret = P2P_OK;

    if (!secret_key_out) {
        return P2P_ERR_INVALID_ARG;
    }

    ret = p2p_crypto_generate_identity(&identity);
    if (ret != P2P_OK) {
        return ret;
    }

    memcpy(secret_key_out, identity.secret_key, P2P_KEY_SIZE);
    p2p_crypto_wipe(&identity, sizeof(identity));
    return P2P_OK;
}

int p2p_public_key_from_private_key(const uint8_t secret_key[P2P_KEY_SIZE],
                                    uint8_t public_key_out[P2P_KEY_SIZE]) {
    p2p_identity_t identity = {0};
    int ret = P2P_OK;

    if (!secret_key || !public_key_out) {
        return P2P_ERR_INVALID_ARG;
    }

    ret = p2p_crypto_identity_from_secret(&identity, secret_key);
    if (ret != P2P_OK) {
        return ret;
    }

    memcpy(public_key_out, identity.public_key, P2P_KEY_SIZE);
    p2p_crypto_wipe(&identity, sizeof(identity));
    return P2P_OK;
}

int p2p_connect(p2p_node_t *node, const char *ip, int port) {
    return p2p_connect_internal(node, ip, port, 1);
}

int p2p_connect_candidate(p2p_node_t *node, const char *ip, int port) {
    return p2p_connect_internal(node, ip, port, 0);
}

/* =============================================================================
 * Message Handlers
 * ============================================================================= */

void p2p_set_message_handler(p2p_node_t *node, p2p_on_message_fn fn, void *user_data) {
    if (!node) return;
    node->on_message = fn;
    node->user_data = user_data;
}

void p2p_set_peer_callbacks(p2p_node_t *node,
                             void (*on_connected)(p2p_peer_t *peer, void *user_data),
                             void (*on_disconnected)(p2p_peer_t *peer, void *user_data),
                             void *user_data) {
    if (!node) return;
    node->on_peer_connected = on_connected;
    node->on_peer_disconnected = on_disconnected;
    node->peer_user_data = user_data;
}

int p2p_send(p2p_node_t *node, p2p_peer_t *peer, const void *data, size_t len) {
    return p2p_send_message(node, peer, P2P_MSG_CUSTOM, data, len);
}

int p2p_broadcast(p2p_node_t *node, const void *data, size_t len) {
    return p2p_send(node, NULL, data, len);
}

/* =============================================================================
 * DHT Operations
 * ============================================================================= */

int p2p_dht_put(p2p_node_t *node, const char *key, const void *data, size_t len) {
    int ret = P2P_OK;
    p2p_pending_put_t *pending = NULL;
    p2p_dht_lookup_t *lookup = NULL;
    kad_id_t kkey;

    if (!node || !key || !data) return P2P_ERR_INVALID_ARG;
    if (len == 0 || len > sizeof(((p2p_dht_store_payload_t *)0)->data)) {
        return P2P_ERR_INVALID_ARG;
    }

    kad_id_from_data(key, strlen(key), &kkey);
    turbo_mutex_lock(&node->mutex);

    /* Store locally first */
    kademlia_store(node->kad_dht, &kkey, data, len);
    turbo_mutex_unlock(&node->mutex);
    (void)p2p_send_dht_store_to_connected_peers(node, &kkey, data, len);

    /* Professional Kademlia: 
     * 1. Start iterative FIND_NODE for the key
     * 2. When closest nodes are found, send P2P_MSG_DHT_PUT to them.
     */
    
    /* For now, just start iterative lookup for the neighborhood */
    lookup = p2p_dht_lookup_start(node, kkey.bytes, P2P_MSG_DHT_FIND_NODE);
    if (lookup) {
        pending = (p2p_pending_put_t *)calloc(1, sizeof(p2p_pending_put_t));
        if (pending) {
            pending->node = node;
            pending->key = kkey;
            pending->len = len;
            memcpy(pending->data, data, len);
            lookup->callback = p2p_dht_put_lookup_complete;
            lookup->cleanup = free;
            lookup->user_data = pending;
        } else {
            p2p_dht_lookup_finish(node, lookup);
            ret = P2P_ERR_NO_MEM;
        }
    } else {
        ret = P2P_OK;
    }
    return ret;
}

int p2p_dht_put_cached(p2p_node_t *node, const char *key, const void *data, size_t len) {
    kad_id_t kkey;

    if (!node || !key || !data) return P2P_ERR_INVALID_ARG;
    if (len == 0 || len > sizeof(((p2p_dht_store_payload_t *)0)->data)) {
        return P2P_ERR_INVALID_ARG;
    }

    kad_id_from_data(key, strlen(key), &kkey);
    turbo_mutex_lock(&node->mutex);
    kademlia_store(node->kad_dht, &kkey, data, len);
    turbo_mutex_unlock(&node->mutex);

    (void)p2p_send_dht_store_to_connected_peers(node, &kkey, data, len);
    return P2P_OK;
}

int p2p_dht_get(p2p_node_t *node, const char *key, void *buf, size_t *buf_len) {
    uint64_t deadline_ms = 0;
    int ret = 0;
    p2p_dht_lookup_t *lookup = NULL;
    uint32_t request_id = 0;
    kad_id_t kkey;

    if (!node || !key || !buf || !buf_len) return P2P_ERR_INVALID_ARG;

    kad_id_from_data(key, strlen(key), &kkey);
    if (p2p_try_get_local_dht_value(node, &kkey, buf, buf_len) == P2P_OK) {
        return P2P_OK;
    }

    /* Professional Kademlia: 
     * 1. Start iterative FIND_VALUE for the key
     * 2. This will return either the value or closer nodes.
     */
    /*
     * This API is synchronous from the caller's point of view: P2P_OK means
     * buf contains a value right now. We can still kick off an async lookup as
     * a side effect, but we must not claim success until a value is present.
     */
    lookup = p2p_dht_lookup_start(node, kkey.bytes, P2P_MSG_DHT_GET);
    if (lookup) {
        request_id = lookup->request_id;
        ret = P2P_OK;
    } else {
        ret = P2P_ERR_NOT_FOUND;
    }
    if (ret != P2P_OK) {
        return ret;
    }

    deadline_ms = (turbo_hrtime() / 1000000) + P2P_DHT_GET_TIMEOUT_MS;
    while ((turbo_hrtime() / 1000000) < deadline_ms) {
        coro_context_run(node->ctx, TURBO_RUN_NOWAIT);

        if (p2p_try_get_local_dht_value(node, &kkey, buf, buf_len) == P2P_OK) {
            return P2P_OK;
        }
        if (!p2p_dht_lookup_is_active(node, request_id)) {
            return P2P_ERR_NOT_FOUND;
        }

        turbo_sleep_ms(10);
    }

    if (p2p_try_get_local_dht_value(node, &kkey, buf, buf_len) == P2P_OK) {
        return P2P_OK;
    }
    return P2P_ERR_NOT_FOUND;
}

int p2p_dht_get_cached(p2p_node_t *node, const char *key, void *buf, size_t *buf_len) {
    kad_id_t kkey;

    if (!node || !key || !buf || !buf_len) {
        return P2P_ERR_INVALID_ARG;
    }

    kad_id_from_data(key, strlen(key), &kkey);
    return p2p_try_get_local_dht_value(node, &kkey, buf, buf_len);
}

size_t p2p_dht_get_entry_count(p2p_node_t *node) {
    size_t count = 0;

    if (!node) {
        return 0;
    }

    turbo_mutex_lock(&node->mutex);
    count = kademlia_storage_count(node->kad_dht);
    turbo_mutex_unlock(&node->mutex);
    return count;
}

/* =============================================================================
 * Peer Information
 * ============================================================================= */

static void p2p_copy_peer_info_legacy(p2p_peer_info_t *dst,
                                      const p2p_peer_info_ex_t *src) {
    if (!dst || !src) {
        return;
    }

    strncpy(dst->ip, src->ip, sizeof(dst->ip) - 1);
    dst->ip[sizeof(dst->ip) - 1] = '\0';
    dst->port = src->port;
    dst->is_connected = src->is_connected;
}

int p2p_get_peer_count(p2p_node_t *node) {
    p2p_peer_info_ex_t *infos = NULL;
    size_t count = 0;

    if (!node) return 0;
    infos = p2p_node_snapshot_peer_info_ex(node, &count);
    if (count > 0 && !infos) {
        return 0;
    }
    free(infos);
    return (int)count;
}

void p2p_disconnect_peer(p2p_peer_t *peer) {
    p2p_node_t *node = NULL;

    if (!peer || !peer->node) {
        return;
    }
    if (!p2p_peer_hold(peer)) {
        return;
    }

    node = peer->node;
    turbo_mutex_lock(&node->mutex);
    p2p_mark_manual_disconnect_locked(node, peer);
    turbo_mutex_unlock(&node->mutex);

    p2p_peer_disconnect(peer);
    p2p_node_on_peer_disconnected(node, peer);
    p2p_peer_destroy(peer);
    p2p_peer_release(peer);
}

int p2p_get_peer_info_ex(p2p_node_t *node, int index, p2p_peer_info_ex_t *info) {
    p2p_peer_info_ex_t *infos = NULL;
    size_t count = 0;

    if (!node || !info || index < 0) return P2P_ERR_INVALID_ARG;
    infos = p2p_node_snapshot_peer_info_ex(node, &count);
    if (count > 0 && !infos) {
        return P2P_ERR_NO_MEM;
    }
    if ((size_t)index >= count) {
        free(infos);
        return P2P_ERR_NOT_FOUND;
    }

    *info = infos[index];
    free(infos);
    return P2P_OK;
}

int p2p_get_peer_info(p2p_node_t *node, int index, p2p_peer_info_t *info) {
    p2p_peer_info_ex_t info_ex = {0};
    int ret = P2P_OK;

    if (!node || !info || index < 0) {
        return P2P_ERR_INVALID_ARG;
    }
    ret = p2p_get_peer_info_ex(node, index, &info_ex);
    if (ret != P2P_OK) {
        return ret;
    }

    p2p_copy_peer_info_legacy(info, &info_ex);
    return P2P_OK;
}

/* =============================================================================
 * File Sharing implementation
 * ============================================================================= */

enum {
    P2P_FILE_HASH_BUFFER_SIZE = 32 * 1024,
};

static int p2p_hex_digit_value(char value) {
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    if (value >= 'A' && value <= 'F') {
        return value - 'A' + 10;
    }
    return -1;
}

static void p2p_sha256_to_hex(const uint8_t digest[P2P_SHA256_DIGEST_SIZE],
                              char output[65]) {
    static const char digits[] = "0123456789abcdef";

    for (size_t i = 0; i < P2P_SHA256_DIGEST_SIZE; i++) {
        output[i * 2] = digits[digest[i] >> 4];
        output[i * 2 + 1] = digits[digest[i] & 0x0f];
    }
    output[64] = '\0';
}

static int p2p_sha256_key_decode(const char key[65],
                                 uint8_t digest[P2P_SHA256_DIGEST_SIZE]) {
    if (!key || !digest || key[64] != '\0') {
        return P2P_ERR_INVALID_ARG;
    }

    for (size_t i = 0; i < P2P_SHA256_DIGEST_SIZE; i++) {
        int high = p2p_hex_digit_value(key[i * 2]);
        int low = p2p_hex_digit_value(key[i * 2 + 1]);
        if (high < 0 || low < 0) {
            return P2P_ERR_INVALID_ARG;
        }
        digest[i] = (uint8_t)((high << 4) | low);
    }
    return P2P_OK;
}

static int p2p_hash_file(const char *filepath,
                         uint8_t digest[P2P_SHA256_DIGEST_SIZE],
                         size_t *size_out) {
    uint8_t buffer[P2P_FILE_HASH_BUFFER_SIZE];
    p2p_sha256_ctx_t hash;
    FILE *file = NULL;
    size_t total_size = 0;
    size_t bytes_read = 0;
    int ret = P2P_OK;

    if (!filepath || !digest || !size_out) {
        return P2P_ERR_INVALID_ARG;
    }

    file = fopen(filepath, "rb");
    if (!file) {
        return P2P_ERR_IO;
    }

    p2p_sha256_init(&hash);
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (total_size > SIZE_MAX - bytes_read) {
            ret = P2P_ERR_INVALID_ARG;
            goto done;
        }
        p2p_sha256_update(&hash, buffer, bytes_read);
        total_size += bytes_read;
    }
    if (ferror(file)) {
        ret = P2P_ERR_IO;
        goto done;
    }

    p2p_sha256_final(&hash, digest);
    *size_out = total_size;

done:
    fclose(file);
    return ret;
}

int p2p_put_file(p2p_node_t *node, const char *filepath, char key_out[65]) {
    uint8_t digest[P2P_SHA256_DIGEST_SIZE];
    p2p_file_t *file = NULL;
    size_t file_size = 0;
    int ret = P2P_OK;

    if (!node || !filepath || !key_out) return P2P_ERR_INVALID_ARG;

    ret = p2p_hash_file(filepath, digest, &file_size);
    if (ret != P2P_OK) {
        return ret;
    }
    p2p_sha256_to_hex(digest, key_out);

    file = p2p_file_create(key_out, filepath);
    if (!file) return P2P_ERR_NO_MEM;

    file->is_local = 1;
    memcpy(file->id, digest, P2P_HASH_SIZE);
    memcpy(file->hash, key_out, sizeof(file->hash));
    file->size = file_size;
    file->chunk_size = P2P_DEFAULT_CHUNK_SIZE;
    file->num_chunks = (uint32_t)p2p_transfer_calc_chunk_count(
        file_size, file->chunk_size);
    if (file->num_chunks == 0) {
        file->num_chunks = 1;
    }
    file->available_chunks = file->num_chunks;
    p2p_node_add_file(node, file);

    /* Local registration remains authoritative even with no connected DHT peer. */
    (void)p2p_file_announce(node, file);

    return P2P_OK;
}

int p2p_get_file_async(p2p_node_t *node, const char key[65],
                       const char *output_path,
                       p2p_transfer_complete_cb complete_cb,
                       void *user_data) {
    uint8_t digest[P2P_SHA256_DIGEST_SIZE];
    p2p_transfer_t *transfer = NULL;
    p2p_message_t *request = NULL;
    p2p_peer_t **peers = NULL;
    size_t peer_count = 0;
    size_t request_peer_count = 0;
    size_t sent_count = 0;
    int complete_no_source = 0;
    int ret = P2P_OK;

    if (!node || !key || !output_path || !node->transfers) {
        return P2P_ERR_INVALID_ARG;
    }
    if (strlen(output_path) >= P2P_MAX_FILEPATH) {
        return P2P_ERR_INVALID_ARG;
    }
    ret = p2p_sha256_key_decode(key, digest);
    if (ret != P2P_OK) {
        return ret;
    }

    transfer = p2p_transfer_create(node->transfers, P2P_TRANSFER_DIR_DOWNLOAD);
    if (!transfer) {
        return P2P_ERR_NO_MEM;
    }
    turbo_mutex_lock(&transfer->mutex);
    memcpy(transfer->file_id, digest, P2P_HASH_SIZE);
    memcpy(transfer->file_hash, digest, P2P_SHA256_DIGEST_SIZE);
    strncpy(transfer->filepath, output_path, sizeof(transfer->filepath) - 1);
    strncpy(transfer->filename, key, sizeof(transfer->filename) - 1);
    transfer->complete_cb = complete_cb;
    transfer->user_data = user_data;
    turbo_mutex_unlock(&transfer->mutex);

    peers = p2p_node_snapshot_connected_peers(node, &peer_count);
    if (peer_count == 0 || !peers) {
        p2p_transfer_destroy(node->transfers, transfer);
        free(peers);
        return P2P_ERR_NOT_FOUND;
    }
    request_peer_count = peer_count < P2P_MAX_SOURCES
        ? peer_count
        : P2P_MAX_SOURCES;
    turbo_mutex_lock(&transfer->mutex);
    transfer->request_peer_count = (uint8_t)request_peer_count;
    for (size_t i = 0; i < request_peer_count; i++) {
        transfer->request_peers[i] = peers[i];
    }
    turbo_mutex_unlock(&transfer->mutex);

    request = (p2p_message_t *)calloc(1, sizeof(*request));
    if (!request) {
        for (size_t i = 0; i < peer_count; i++) {
            p2p_peer_release(peers[i]);
        }
        free(peers);
        p2p_transfer_destroy(node->transfers, transfer);
        return P2P_ERR_NO_MEM;
    }

    p2p_message_init(request, P2P_MSG_FILE_GET);
    request->header.request_id = transfer->id;
    request->header.payload_len = P2P_HASH_SIZE;
    memcpy(request->payload.file_response.file_id, digest, P2P_HASH_SIZE);

    for (size_t i = 0; i < request_peer_count; i++) {
        if (p2p_peer_send(peers[i], request) == P2P_OK) {
            sent_count++;
        } else {
            turbo_mutex_lock(&transfer->mutex);
            if (!transfer->request_peer_done[i]) {
                transfer->request_peer_done[i] = 1;
                transfer->response_count++;
            }
            turbo_mutex_unlock(&transfer->mutex);
        }
    }
    for (size_t i = 0; i < peer_count; i++) {
        p2p_peer_release(peers[i]);
    }
    free(request);
    free(peers);

    if (sent_count == 0) {
        p2p_transfer_destroy(node->transfers, transfer);
        return P2P_ERR_NETWORK;
    }

    turbo_mutex_lock(&transfer->mutex);
    complete_no_source =
        transfer->state == P2P_TRANSFER_STATE_PENDING &&
        transfer->response_count == transfer->request_peer_count;
    turbo_mutex_unlock(&transfer->mutex);
    if (complete_no_source) {
        p2p_transfer_complete(transfer, 0, "No peer provides the requested object");
    }
    return P2P_OK;
}

int p2p_get_file(p2p_node_t *node, const char key[65],
                 const char *output_path) {
    return p2p_get_file_async(node, key, output_path, NULL, NULL);
}

/* =============================================================================
 * Pub/Sub implementation
 * ============================================================================= */

int p2p_subscribe(p2p_node_t *node, const char *topic) {
    p2p_message_t *msg = NULL;

    if (!node || !topic) return P2P_ERR_INVALID_ARG;
    if (!p2p_topic_find_or_create(node, topic)) {
        return P2P_ERR_NO_MEM;
    }

    msg = (p2p_message_t *)calloc(1, sizeof(p2p_message_t));
    if (!msg) {
        return P2P_ERR_NO_MEM;
    }

    p2p_message_init(msg, P2P_MSG_PUBSUB_SUB);
    /* Payload setup would go here */
    p2p_node_broadcast(node, msg);
    free(msg);
    return P2P_OK;
}

int p2p_unsubscribe(p2p_node_t *node, const char *topic) {
    p2p_message_t *msg = NULL;
    int ret = P2P_OK;

    if (!node || !topic) return P2P_ERR_INVALID_ARG;
    ret = p2p_node_remove_topic(node, topic);
    if (ret != P2P_OK) {
        return ret;
    }

    msg = (p2p_message_t *)calloc(1, sizeof(p2p_message_t));
    if (!msg) {
        return P2P_ERR_NO_MEM;
    }

    p2p_message_init(msg, P2P_MSG_PUBSUB_UNSUB);
    p2p_node_broadcast(node, msg);
    free(msg);
    return P2P_OK;
}

int p2p_publish(p2p_node_t *node, const char *topic, const void *data, size_t len) {
    p2p_message_t *msg = NULL;

    if (!node || !topic || !data || len == 0) return P2P_ERR_INVALID;

    if (!p2p_topic_exists(node, topic)) {
        return P2P_ERR_NOT_FOUND;
    }

    msg = (p2p_message_t *)calloc(1, sizeof(p2p_message_t));
    if (!msg) {
        return P2P_ERR_NO_MEM;
    }

    p2p_message_init(msg, P2P_MSG_PUBSUB_PUBLISH);
    p2p_node_broadcast(node, msg);
    free(msg);
    return P2P_OK;
}

/* =============================================================================
 * Utility implementation
 * ============================================================================= */

int p2p_peer_get_info_ex(p2p_peer_t *peer, p2p_peer_info_ex_t *info) {
    p2p_node_t *node = NULL;

    if (!peer || !info) return P2P_ERR_INVALID_ARG;

    node = peer->node;
    if (node) {
        turbo_mutex_lock(&node->mutex);
    }
    p2p_peer_fill_info_ex_locked(peer, info);
    if (node) {
        turbo_mutex_unlock(&node->mutex);
    }
    return P2P_OK;
}

int p2p_peer_get_stream_metrics(p2p_peer_t *peer,
                                p2p_peer_stream_metrics_t *metrics) {
    p2p_node_t *node = NULL;
    uint64_t now_ms = 0;
    uint64_t age_ms = 0;

    if (!peer || !metrics) {
        return P2P_ERR_INVALID_ARG;
    }

    memset(metrics, 0, sizeof(*metrics));
    metrics->sample_age_ms = UINT32_MAX;
    node = peer->node;
    if (node) {
        turbo_mutex_lock(&node->mutex);
    }
    now_ms = turbo_hrtime() / 1000000U;

    metrics->srtt_ms = peer->avg_rtt_ms > UINT32_MAX
        ? UINT32_MAX
        : (uint32_t)peer->avg_rtt_ms;
    metrics->rttvar_ms = peer->rttvar_ms > UINT32_MAX
        ? UINT32_MAX
        : (uint32_t)peer->rttvar_ms;
    metrics->sample_count = peer->rtt_sample_count;
    if (peer->rtt_sample_count > 0 && peer->last_rtt_sample_ms > 0 &&
        now_ms >= peer->last_rtt_sample_ms) {
        age_ms = now_ms - peer->last_rtt_sample_ms;
        metrics->sample_age_ms = age_ms > UINT32_MAX
            ? UINT32_MAX
            : (uint32_t)age_ms;
        metrics->is_fresh = peer->is_connected &&
                            peer->state == P2P_PEER_STATE_CONNECTED &&
                            age_ms <= P2P_RTT_METRIC_FRESH_MS;
    }

    if (node) {
        turbo_mutex_unlock(&node->mutex);
    }
    return P2P_OK;
}

int p2p_peer_get_info(p2p_peer_t *peer, p2p_peer_info_t *info) {
    p2p_peer_info_ex_t info_ex = {0};

    if (!info) {
        return P2P_ERR_INVALID_ARG;
    }
    if (p2p_peer_get_info_ex(peer, &info_ex) != P2P_OK) {
        return P2P_ERR_INVALID_ARG;
    }

    p2p_copy_peer_info_legacy(info, &info_ex);
    return P2P_OK;
}

int p2p_peer_get_address(p2p_peer_t *peer, char *ip_out, int *port_out) {
    p2p_peer_info_ex_t info = {0};

    if (!ip_out || !port_out) {
        return P2P_ERR_INVALID_ARG;
    }
    if (p2p_peer_get_info_ex(peer, &info) != P2P_OK) {
        return P2P_ERR_INVALID_ARG;
    }

    strncpy(ip_out, info.ip, P2P_MAX_IP - 1);
    ip_out[P2P_MAX_IP - 1] = '\0';
    *port_out = info.port;
    return P2P_OK;
}

int p2p_peer_get_id(p2p_peer_t *peer, uint8_t id_out[P2P_HASH_SIZE]) {
    p2p_node_t *node = NULL;

    if (!peer || !id_out) {
        return P2P_ERR_INVALID_ARG;
    }

    node = peer->node;
    if (node) {
        turbo_mutex_lock(&node->mutex);
    }
    if (p2p_id_is_zero(peer->id)) {
        if (node) {
            turbo_mutex_unlock(&node->mutex);
        }
        return P2P_ERR_NOT_FOUND;
    }
    memcpy(id_out, peer->id, P2P_HASH_SIZE);
    if (node) {
        turbo_mutex_unlock(&node->mutex);
    }
    return P2P_OK;
}

int p2p_peer_get_public_key(p2p_peer_t *peer,
                            uint8_t public_key_out[P2P_KEY_SIZE]) {
    p2p_node_t *node = NULL;

    if (!peer || !public_key_out) {
        return P2P_ERR_INVALID_ARG;
    }

    node = peer->node;
    if (node) {
        turbo_mutex_lock(&node->mutex);
    }
    if (!peer->remote_public_key_ready) {
        if (node) {
            turbo_mutex_unlock(&node->mutex);
        }
        return P2P_ERR_NOT_FOUND;
    }
    memcpy(public_key_out, peer->remote_public_key, P2P_KEY_SIZE);
    if (node) {
        turbo_mutex_unlock(&node->mutex);
    }
    return P2P_OK;
}

int p2p_peer_get_security_info_v2(
    p2p_peer_t *peer, p2p_peer_security_info_v2_t *info) {
    p2p_node_t *node;
    p2p_peer_security_info_v2_t snapshot = {0};

    if (!peer || !info || info->struct_size != sizeof(*info)) {
        return P2P_ERR_INVALID_ARG;
    }
    node = peer->node;
    if (node) {
        turbo_mutex_lock(&node->mutex);
    }
    if (!peer->ready_received || peer->state != P2P_PEER_STATE_CONNECTED) {
        if (node) {
            turbo_mutex_unlock(&node->mutex);
        }
        return P2P_ERR_NOT_FOUND;
    }
    snapshot.struct_size = sizeof(snapshot);
    snapshot.secure_wire_version = P2P_SECURE_WIRE_VERSION_V2;
    snapshot.noise_suite = P2P_NOISE_SUITE_XX_25519_CHACHAPOLY_BLAKE2S;
    snapshot.authenticated = 1;
    memcpy(snapshot.remote_noise_static, peer->remote_public_key,
           sizeof(snapshot.remote_noise_static));
    memcpy(snapshot.channel_binding, peer->channel_binding,
           sizeof(snapshot.channel_binding));
    snapshot.identity = peer->authenticated_identity;
    snapshot.sent_frames = peer->crypto.sent_frames;
    snapshot.received_frames = peer->crypto.received_frames;
    snapshot.session_started_ms = peer->session_started_ms;
    snapshot.sent_bytes = peer->sent_bytes;
    snapshot.received_bytes = peer->received_bytes;
    *info = snapshot;
    if (node) {
        turbo_mutex_unlock(&node->mutex);
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

const char *p2p_error_str(int error) {
    switch (error) {
        case P2P_OK: return "Success";
        case P2P_ERR_INVALID_ARG: return "Invalid argument";
        case P2P_ERR_NO_MEM: return "Out of memory";
        case P2P_ERR_NETWORK: return "Network error";
        case P2P_ERR_TIMEOUT: return "Timeout";
        case P2P_ERR_NOT_FOUND: return "Not found";
        case P2P_ERR_IO: return "I/O error";
        case P2P_ERR_INVALID: return "Invalid argument";
        case P2P_ERR_AUTH_REQUIRED: return "Authentication required";
        case P2P_ERR_UNTRUSTED_IDENTITY: return "Untrusted identity";
        case P2P_ERR_RESOURCE_EXHAUSTED: return "Resource exhausted";
        case P2P_ERR_KEY_EXHAUSTED: return "Session key exhausted";
        default: return "Unknown error";
    }
}
