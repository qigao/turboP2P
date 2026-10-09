#include "p2p.h"
#include "../internal.h"
#include <salts/clock.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../security/p2p_private_key_executor.h"
#include <salts/crypto.h>

static int p2p_node_identity_is_mutable_locked(const p2p_node_t *node) {
    return !node->server && !node->network_context && !node->peers_table && node->peer_count == 0 &&
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
    uint64_t now_ms = cmeta_monotonic_ms();
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
    now_ms = cmeta_monotonic_ms();
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

    cmeta_mutex_lock(&node->mutex);
    memcpy(id_out, node->id, P2P_HASH_SIZE);
    cmeta_mutex_unlock(&node->mutex);
    return P2P_OK;
}

int p2p_node_get_public_key(p2p_node_t *node,
                            uint8_t public_key_out[P2P_KEY_SIZE]) {
    if (!node || !public_key_out) {
        return P2P_ERR_INVALID_ARG;
    }

    cmeta_mutex_lock(&node->mutex);
    memcpy(public_key_out, node->crypto.identity.public_key, P2P_KEY_SIZE);
    cmeta_mutex_unlock(&node->mutex);
    return P2P_OK;
}

int p2p_node_set_private_key(p2p_node_t *node,
                             const uint8_t secret_key[P2P_KEY_SIZE]) {
    p2p_private_key_executor_t *old_executor = NULL;
    int ret = P2P_OK;

    if (!node || !secret_key) {
        return P2P_ERR_INVALID_ARG;
    }

    cmeta_mutex_lock(&node->mutex);
    if (!p2p_node_identity_is_mutable_locked(node)) {
        ret = P2P_ERR_INVALID_STATE;
    } else {
        ret = p2p_crypto_identity_from_secret(&node->crypto.identity, secret_key);
        if (ret == P2P_OK) {
            old_executor = node->private_key_executor;
            node->private_key_executor = NULL;
        }
    }
    cmeta_mutex_unlock(&node->mutex);
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

    cmeta_mutex_lock(&node->mutex);
    ret = p2p_node_identity_is_mutable_locked(node) ? P2P_OK
                                                     : P2P_ERR_INVALID_STATE;
    cmeta_mutex_unlock(&node->mutex);
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

    cmeta_mutex_lock(&node->mutex);
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
    cmeta_mutex_unlock(&node->mutex);
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

    cmeta_mutex_lock(&node->mutex);
    ret = p2p_node_identity_is_mutable_locked(node) ? P2P_OK
                                                     : P2P_ERR_INVALID_STATE;
    cmeta_mutex_unlock(&node->mutex);
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
    if (!node->create_private_key_executor) {
        p2p_crypto_wipe(public_key, sizeof(public_key));
        return P2P_ERR_INVALID_STATE;
    }
    candidate = node->create_private_key_executor(node, provider);
    if (!candidate) {
        p2p_crypto_wipe(public_key, sizeof(public_key));
        return P2P_ERR_NO_MEM;
    }

    cmeta_mutex_lock(&node->mutex);
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
    cmeta_mutex_unlock(&node->mutex);
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
    salts_crypto_sha256_ctx_t hash;

    memset(identity, 0, sizeof(*identity));
    if (salts_crypto_sha256_init(&hash) != SALTS_CRYPTO_OK ||
        salts_crypto_sha256_update(&hash, principal_domain,
                                   sizeof(principal_domain) - 1) !=
            SALTS_CRYPTO_OK ||
        salts_crypto_sha256_update(&hash, static_key, P2P_KEY_SIZE) !=
            SALTS_CRYPTO_OK ||
        salts_crypto_sha256_final(&hash, identity->principal_id) !=
            SALTS_CRYPTO_OK ||
        salts_crypto_sha256_init(&hash) != SALTS_CRYPTO_OK ||
        salts_crypto_sha256_update(&hash, routing_domain,
                                   sizeof(routing_domain) - 1) !=
            SALTS_CRYPTO_OK ||
        salts_crypto_sha256_update(&hash,
                                   node->security_config.network_id_hash,
                                   P2P_SECURITY_ID_SIZE) != SALTS_CRYPTO_OK ||
        salts_crypto_sha256_update(&hash, identity->principal_id,
                                   P2P_SECURITY_ID_SIZE) != SALTS_CRYPTO_OK ||
        salts_crypto_sha256_final(&hash, identity->routing_id) !=
            SALTS_CRYPTO_OK ||
        salts_crypto_sha256("", 0, identity->credential_digest) !=
            SALTS_CRYPTO_OK) {
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
    if (node->server || node->network_context || node->peers_table || node->peer_count > 0 || node->security_configured) {
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
    p2p_node_cookie_status_t cookies = {0};
    node->query_cookie_status_locked(node, &cookies);
    status->active_cookie_gates = cookies.active;
    status->cookie_challenges_issued = cookies.challenges_issued;
    status->cookie_verifications_succeeded = cookies.verifications_succeeded;
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
    p2p_key_worker_status(executor->worker, status);
    status->rejected += executor->rejected;
    if (p2p_private_key_executor_is_closing(executor)) status->accepting = 0;
}

int p2p_node_get_security_status_v2(
    p2p_node_t *node, p2p_node_security_status_v2_t *status) {
    if (!node || !status || status->struct_size != sizeof(*status)) {
        return P2P_ERR_INVALID_ARG;
    }

    cmeta_mutex_lock(&node->mutex);
    if (!node->security_configured) {
        cmeta_mutex_unlock(&node->mutex);
        return P2P_ERR_INVALID_STATE;
    }
    p2p_node_fill_security_status_v2_locked(node, status);
    cmeta_mutex_unlock(&node->mutex);
    return P2P_OK;
}

int p2p_node_get_security_status_v3(
    p2p_node_t *node, p2p_node_security_status_v3_t *status) {
    size_t role;
    size_t stage;

    if (!node || !status || status->struct_size != sizeof(*status)) {
        return P2P_ERR_INVALID_ARG;
    }

    cmeta_mutex_lock(&node->mutex);
    if (!node->security_configured) {
        cmeta_mutex_unlock(&node->mutex);
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
    cmeta_mutex_unlock(&node->mutex);
    return P2P_OK;
}

int p2p_node_get_private_key_executor_status_v4(
    p2p_node_t *node, p2p_private_key_executor_status_v4_t *status) {
    p2p_private_key_executor_t *executor;

    if (!node || !status || status->struct_size != sizeof(*status)) {
        return P2P_ERR_INVALID_ARG;
    }
    cmeta_mutex_lock(&node->mutex);
    executor = node->private_key_executor;
    if (!executor) {
        cmeta_mutex_unlock(&node->mutex);
        return P2P_ERR_INVALID_STATE;
    }
    p2p_node_fill_private_key_executor_status_v4_locked(executor, status);
    cmeta_mutex_unlock(&node->mutex);
    return P2P_OK;
}

static size_t p2p_node_disconnect_all_security_sessions(
    p2p_node_t *node) {
    size_t disconnected = 0;

    for (;;) {
        p2p_peer_entry_t *entry = NULL;
        p2p_peer_entry_t *temporary = NULL;
        p2p_peer_t *peer = NULL;

        cmeta_mutex_lock(&node->mutex);
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
        cmeta_mutex_unlock(&node->mutex);

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

    cmeta_mutex_lock(&node->mutex);
    if (!node->security_configured) {
        cmeta_mutex_unlock(&node->mutex);
        return P2P_ERR_INVALID_STATE;
    }
    cmeta_mutex_unlock(&node->mutex);

    peers = p2p_node_snapshot_connected_peers(node, &peer_count);
    if (peer_count > 0 && !peers) {
        result->disconnected_sessions =
            p2p_node_disconnect_all_security_sessions(node);
        cmeta_mutex_lock(&node->mutex);
        node->security_rejection_counts[
            P2P_SECURITY_REJECTION_REVALIDATION_FAIL_CLOSED]++;
        cmeta_mutex_unlock(&node->mutex);
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
        cmeta_mutex_lock(&node->mutex);
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
        cmeta_mutex_unlock(&node->mutex);

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
    cmeta_mutex_lock(&node->mutex);
    node->security_rejection_counts[
        P2P_SECURITY_REJECTION_REVALIDATION_REJECTED] +=
        result->provider_rejections;
    node->security_rejection_counts[
        P2P_SECURITY_REJECTION_REVALIDATION_IDENTITY_CHANGE] +=
        result->identity_changes;
    cmeta_mutex_unlock(&node->mutex);
    return P2P_OK;
}

int p2p_node_configure_security_v2(
    p2p_node_t *node, const p2p_security_config_v2_t *config) {
    int ret;

    if (!node) {
        return P2P_ERR_INVALID_ARG;
    }
    cmeta_mutex_lock(&node->mutex);
    ret = p2p_node_configure_security_locked(node, config);
    cmeta_mutex_unlock(&node->mutex);
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

    cmeta_mutex_lock(&node->mutex);
    if (node->server || node->network_context || node->peers_table || node->peer_count > 0 || node->security_configured ||
        node->pinned_trusted_keys) {
        cmeta_mutex_unlock(&node->mutex);
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
    cmeta_mutex_unlock(&node->mutex);
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

    cmeta_mutex_lock(&node->mutex);
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
    cmeta_mutex_unlock(&node->mutex);

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
