#include "p2p_cnet_admission.h"
#include "../crypto/p2p_crypto.h"
#include <salts/clock.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

typedef enum { GATE_FREE, GATE_PREFACE, GATE_RESPONSE, GATE_VERIFIED } gate_state_t;
typedef struct {
    p2p_cnet_admission_t *admission;
    p2p_connection_t *connection;
    cnet_stream_peer source;
    char source_ip[INET6_ADDRSTRLEN];
    uint8_t preface[P2P_SECURE_PREFACE_SIZE];
    uint8_t packet[P2P_COOKIE_PACKET_SIZE];
    uint8_t binding[P2P_COOKIE_BINDING_SIZE];
    size_t used;
    uint64_t started_ms;
    uint64_t cookie_started_ms;
    gate_state_t state;
    int challenge_completed;
} gate_t;

struct p2p_cnet_admission_s {
    p2p_cnet_owner_t *owner;
    p2p_cnet_admission_config_t config;
    p2p_cnet_admission_callbacks_t callbacks;
    p2p_cnet_admission_stats_t stats;
    salts_mutex_t owned_status_mutex;
    salts_mutex_t *status_mutex;
    gate_t *gates;
    int busy;
    int stopped;
};

static void reject(p2p_cnet_admission_t *admission,
    const cnet_stream_peer *source, int status, p2p_cnet_rejection_origin_t origin) {
    salts_mutex_lock(admission->status_mutex);
    admission->stats.rejected++;
    salts_mutex_unlock(admission->status_mutex);
    if (admission->callbacks.rejected)
        admission->callbacks.rejected(source, status, origin, admission->callbacks.context);
}

static void release_gate(gate_t *gate) {
    salts_mutex_lock(gate->admission->status_mutex);
    gate->admission->stats.active--;
    salts_mutex_unlock(gate->admission->status_mutex);
    p2p_crypto_wipe(gate, sizeof(*gate));
}

static void fail_gate(gate_t *gate, int status) {
    p2p_cnet_admission_t *admission = gate->admission;
    cnet_stream_peer source = gate->source;
    /* Detach first: even delayed CLOSED/send notifications cannot access a
     * recycled gate. Transport observer storage survives until quiescence. */
    p2p_connection_destroy(gate->connection);
    release_gate(gate);
    reject(admission, &source, status, P2P_CNET_REJECT_COOKIE);
}

static int expired(const gate_t *gate, uint64_t now_ms) {
    return now_ms < gate->started_ms || now_ms - gate->started_ms >=
        gate->admission->config.handshake_timeout_ms;
}

static void promote(gate_t *gate) {
    p2p_cnet_admission_t *admission = gate->admission;
    p2p_connection_t *connection = gate->connection;
    p2p_cnet_callbacks_t next = {0};
    gate_t verified;
    int result, produced;
    if (gate->state != GATE_VERIFIED || !gate->challenge_completed) return;
    if (expired(gate, salts_monotonic_ms())) {
        fail_gate(gate, P2P_ERR_TIMEOUT);
        return;
    }
    result = p2p_cnet_connection_set_send_hwm(connection,
                                               admission->config.peer_send_hwm_bytes);
    if (result == P2P_OK) result = p2p_cnet_connection_pause(connection, 0);
    if (result != P2P_OK) { fail_gate(gate, result); return; }
    /* Replace a pending gate with a pending peer, never count both. Keep the
     * verified inputs on this stack while the node rechecks its total quota. */
    verified = *gate;
    release_gate(gate);
    result = admission->callbacks.promote(&verified.source, verified.preface,
        verified.binding, &next, admission->callbacks.context);
    produced = result == P2P_OK;
    if (!next.receive || !next.closed) {
        if (result == P2P_OK) result = P2P_ERR_INVALID_ARG;
    } else if (result == P2P_OK) {
        result = p2p_cnet_connection_handoff(connection, &next);
    }
    if (result != P2P_OK) {
        p2p_connection_destroy(connection);
        reject(admission, &verified.source, result,
            produced ? P2P_CNET_REJECT_TRANSPORT : P2P_CNET_REJECT_PEER_POLICY);
        p2p_crypto_wipe(&verified, sizeof(verified));
        if (produced && next.closed) next.closed(connection, result, next.context);
        return;
    }
    p2p_crypto_wipe(&verified, sizeof(verified));
    salts_mutex_lock(admission->status_mutex);
    admission->stats.promoted++;
    salts_mutex_unlock(admission->status_mutex);
    result = next.connected ? next.connected(connection, next.context) : P2P_OK;
    if (result != P2P_OK) {
        p2p_connection_destroy(connection);
        next.closed(connection, result, next.context);
    }
}

static int gate_receive(p2p_connection_t *connection, const uint8_t *bytes,
                         size_t length, size_t *consumed, void *context) {
    gate_t *gate = context;
    p2p_cnet_admission_t *admission = gate->admission;
    size_t required, take;
    uint64_t now_ms = salts_monotonic_ms();
    int result = P2P_OK;
    (void)connection;
    *consumed = 0;
    admission->busy++;
    if (expired(gate, now_ms)) { fail_gate(gate, P2P_ERR_TIMEOUT); goto done; }
    if (gate->state != GATE_PREFACE && gate->state != GATE_RESPONSE) {
        fail_gate(gate, P2P_ERR_INVALID_STATE);
        goto done;
    }
    required = gate->state == GATE_PREFACE ? P2P_SECURE_PREFACE_SIZE : P2P_COOKIE_PACKET_SIZE;
    take = required - gate->used;
    if (take > length) take = length;
    memcpy(gate->packet + gate->used, bytes, take);
    gate->used += take;
    *consumed = take;
    if (gate->used != required) goto done;
    if (gate->state == GATE_PREFACE) {
        uint8_t challenge[P2P_COOKIE_PACKET_SIZE];
        result = p2p_secure_preface_validate(admission->config.network_id_hash, gate->packet);
        if (result != P2P_OK) { fail_gate(gate, result); goto done; }
        memcpy(gate->preface, gate->packet, sizeof(gate->preface));
        result = p2p_cookie_build_challenge(admission->config.cookie_master_secret,
            gate->source_ip, gate->preface, now_ms, admission->config.cookie_lifetime_ms,
            admission->config.cookie_key_rotation_ms, challenge);
        if (result == P2P_OK) result = p2p_connection_send(gate->connection, challenge, sizeof(challenge));
        p2p_crypto_wipe(challenge, sizeof(challenge));
        if (result != P2P_OK) { fail_gate(gate, result); goto done; }
        gate->used = 0;
        gate->state = GATE_RESPONSE;
        gate->cookie_started_ms = now_ms;
        salts_mutex_lock(admission->status_mutex);
        admission->stats.challenges_issued++;
        if (admission->callbacks.stage_completed_locked)
            admission->callbacks.stage_completed_locked(P2P_CNET_ADMISSION_PREFACE,
                gate->started_ms, now_ms, admission->callbacks.context);
        salts_mutex_unlock(admission->status_mutex);
    } else {
        result = p2p_cookie_verify_response(admission->config.cookie_master_secret,
            gate->source_ip, gate->preface, now_ms, admission->config.cookie_lifetime_ms,
            admission->config.cookie_key_rotation_ms, gate->packet, gate->binding);
        if (result != P2P_OK) { fail_gate(gate, result); goto done; }
        gate->state = GATE_VERIFIED;
        salts_mutex_lock(admission->status_mutex);
        admission->stats.verifications_succeeded++;
        if (admission->callbacks.stage_completed_locked)
            admission->callbacks.stage_completed_locked(P2P_CNET_ADMISSION_COOKIE,
                gate->cookie_started_ms, now_ms, admission->callbacks.context);
        salts_mutex_unlock(admission->status_mutex);
        /* Proof may arrive before the local write terminal. Pause at the exact
         * response boundary so the transport retains a coalesced Noise tail. */
        result = p2p_cnet_connection_pause(gate->connection, 1);
        if (result != P2P_OK) { fail_gate(gate, result); goto done; }
        promote(gate);
    }
done:
    admission->busy--;
    /* Rejection already destroyed/detached this connection. No callback is
     * left behind for transport to report the same failure a second time. */
    return P2P_OK;
}

static void gate_sent(p2p_connection_t *connection, size_t length, void *context) {
    gate_t *gate = context;
    p2p_cnet_admission_t *admission = gate->admission;
    (void)connection;
    admission->busy++;
    if (gate->challenge_completed || length != P2P_COOKIE_PACKET_SIZE ||
        (gate->state != GATE_RESPONSE && gate->state != GATE_VERIFIED)) {
        fail_gate(gate, P2P_ERR_PROTOCOL);
    } else {
        gate->challenge_completed = 1;
        salts_mutex_lock(admission->status_mutex);
        admission->stats.challenges_completed++;
        salts_mutex_unlock(admission->status_mutex);
        promote(gate);
    }
    admission->busy--;
}

static void gate_closed(p2p_connection_t *connection, int status, void *context) {
    gate_t *gate = context;
    p2p_cnet_admission_t *admission = gate->admission;
    (void)connection;
    admission->busy++;
    fail_gate(gate, status == P2P_OK ? P2P_ERR_NETWORK : status);
    admission->busy--;
}

int p2p_cnet_admission_create(p2p_cnet_owner_t *owner,
    const p2p_cnet_admission_config_t *config,
    const p2p_cnet_admission_callbacks_t *callbacks,
    p2p_cnet_admission_t **output) {
    p2p_cnet_admission_t *admission;
    if (!output) return P2P_ERR_INVALID_ARG;
    *output = NULL;
    if (!owner || !config || !callbacks || !callbacks->admit || !callbacks->promote ||
        !config->gate_limit || config->gate_limit > SIZE_MAX / sizeof(gate_t) ||
        !config->source_limit || config->source_limit > config->gate_limit ||
        !config->peer_send_hwm_bytes || !config->handshake_timeout_ms ||
        !config->cookie_lifetime_ms ||
        config->cookie_key_rotation_ms < config->cookie_lifetime_ms ||
        config->cookie_key_rotation_ms % config->cookie_lifetime_ms ||
        (config->status_mutex && !*config->status_mutex))
        return P2P_ERR_INVALID_ARG;
    admission = calloc(1, sizeof(*admission));
    if (!admission) return P2P_ERR_NO_MEM;
    admission->gates = calloc(config->gate_limit, sizeof(*admission->gates));
    if (!admission->gates) { free(admission); return P2P_ERR_NO_MEM; }
    admission->owner = owner;
    admission->config = *config;
    admission->callbacks = *callbacks;
    if (config->status_mutex) admission->status_mutex = config->status_mutex;
    else {
        salts_mutex_init(&admission->owned_status_mutex);
        if (!admission->owned_status_mutex) {
            free(admission->gates);
            p2p_crypto_wipe(admission, sizeof(*admission));
            free(admission);
            return P2P_ERR_NO_MEM;
        }
        admission->status_mutex = &admission->owned_status_mutex;
    }
    *output = admission;
    return P2P_OK;
}

int p2p_cnet_admission_accept(p2p_cnet_owner_t *owner,
    p2p_connection_t *connection, const cnet_stream_peer *source, void *context) {
    p2p_cnet_admission_t *admission = context;
    p2p_cnet_callbacks_t events = {0};
    gate_t *free_gate = NULL;
    size_t source_count = 0;
    size_t prefix_size;
    char ip[INET6_ADDRSTRLEN];
    int family, result = P2P_OK;
    p2p_cnet_rejection_origin_t origin = P2P_CNET_REJECT_TRANSPORT;
    if (!admission || !source || !connection || owner != admission->owner)
        return P2P_ERR_INVALID_ARG;
    if (admission->busy || admission->stopped) return P2P_ERR_INVALID_STATE;
    family = source->family == CNET_DATAGRAM_ADDRESS_IPV4 ? AF_INET :
             source->family == CNET_DATAGRAM_ADDRESS_IPV6 ? AF_INET6 : 0;
    if (!family || !inet_ntop(family, source->address, ip, sizeof(ip)))
        return P2P_ERR_INVALID_ARG;
    prefix_size = family == AF_INET ? 4 : 8;
    admission->busy = 1;
    /* O(gate_limit), bounded by startup policy; no allocation on accept. */
    for (size_t i = 0; i < admission->config.gate_limit; ++i) {
        gate_t *gate = &admission->gates[i];
        if (gate->state == GATE_FREE) { if (!free_gate) free_gate = gate; }
        else if (gate->source.family == source->family &&
                 !memcmp(gate->source.address, source->address, prefix_size)) source_count++;
    }
    if (!free_gate || source_count >= admission->config.source_limit) {
        origin = !free_gate ? P2P_CNET_REJECT_GATE_CAPACITY : P2P_CNET_REJECT_SOURCE_CAPACITY;
        result = P2P_ERR_RESOURCE_EXHAUSTED;
        goto reject_accept;
    }
    result = admission->callbacks.admit(source, admission->callbacks.context);
    if (result != P2P_OK) { origin = P2P_CNET_REJECT_NODE_POLICY; goto reject_accept; }
    result = p2p_cnet_connection_set_send_hwm(connection, P2P_COOKIE_PACKET_SIZE);
    if (result != P2P_OK) goto reject_accept;
    free_gate->admission = admission;
    free_gate->connection = connection;
    free_gate->source = *source;
    strcpy(free_gate->source_ip, ip);
    free_gate->started_ms = salts_monotonic_ms();
    free_gate->state = GATE_PREFACE;
    events.receive = gate_receive;
    events.sent = gate_sent;
    events.closed = gate_closed;
    events.context = free_gate;
    result = p2p_cnet_connection_handoff(connection, &events);
    if (result != P2P_OK) {
        p2p_crypto_wipe(free_gate, sizeof(*free_gate));
        goto reject_accept;
    }
    salts_mutex_lock(admission->status_mutex);
    admission->stats.active++;
    admission->stats.accepted++;
    salts_mutex_unlock(admission->status_mutex);
    admission->busy = 0;
    return P2P_OK;
reject_accept:
    reject(admission, source, result, origin);
    admission->busy = 0;
    return result;
}

int p2p_cnet_admission_expire(p2p_cnet_admission_t *admission, uint64_t now_ms) {
    if (!admission) return P2P_ERR_INVALID_ARG;
    if (admission->busy || admission->stopped) return P2P_ERR_INVALID_STATE;
    admission->busy = 1;
    for (size_t i = 0; i < admission->config.gate_limit; ++i) {
        gate_t *gate = &admission->gates[i];
        if (gate->state != GATE_FREE && expired(gate, now_ms)) fail_gate(gate, P2P_ERR_TIMEOUT);
    }
    admission->busy = 0;
    return P2P_OK;
}

int p2p_cnet_admission_stop(p2p_cnet_admission_t *admission) {
    if (!admission) return P2P_ERR_INVALID_ARG;
    if (admission->busy) return P2P_ERR_INVALID_STATE;
    admission->stopped = 1;
    for (size_t i = 0; i < admission->config.gate_limit; ++i) {
        gate_t *gate = &admission->gates[i];
        if (gate->state == GATE_FREE) continue;
        p2p_connection_destroy(gate->connection);
        release_gate(gate);
    }
    p2p_crypto_wipe(admission->config.cookie_master_secret,
                     sizeof(admission->config.cookie_master_secret));
    return P2P_OK;
}

int p2p_cnet_admission_destroy(p2p_cnet_admission_t *admission) {
    if (!admission) return P2P_OK;
    if (admission->busy || !admission->stopped) return P2P_ERR_INVALID_STATE;
    free(admission->gates);
    if (admission->owned_status_mutex) salts_mutex_destroy(&admission->owned_status_mutex);
    p2p_crypto_wipe(admission, sizeof(*admission));
    free(admission);
    return P2P_OK;
}

int p2p_cnet_admission_stats(const p2p_cnet_admission_t *admission,
                            p2p_cnet_admission_stats_t *output) {
    if (!admission || !output) return P2P_ERR_INVALID_ARG;
    salts_mutex_lock(admission->status_mutex);
    p2p_cnet_admission_stats_locked(admission, output);
    salts_mutex_unlock(admission->status_mutex);
    return P2P_OK;
}

void p2p_cnet_admission_stats_locked(const p2p_cnet_admission_t *admission,
    p2p_cnet_admission_stats_t *output) {
    *output = admission->stats;
}

int p2p_cnet_admission_pending(const p2p_cnet_admission_t *admission,
    const char *source_ip, size_t *total, size_t *source) {
    uint8_t address[16] = {0};
    cnet_datagram_address_family family = CNET_DATAGRAM_ADDRESS_IPV4;
    size_t prefix_size = 4;
    if (!admission || !total || !source) return P2P_ERR_INVALID_ARG;
    if (source_ip && inet_pton(AF_INET, source_ip, address) != 1) {
        if (inet_pton(AF_INET6, source_ip, address) != 1)
            return P2P_ERR_INVALID_ARG;
        family = CNET_DATAGRAM_ADDRESS_IPV6;
        prefix_size = 8;
    }
    *total = admission->stats.active;
    *source = 0;
    for (size_t i = 0; source_ip && i < admission->config.gate_limit; ++i) {
        const gate_t *gate = &admission->gates[i];
        if (gate->state != GATE_FREE && gate->source.family == family &&
            !memcmp(gate->source.address, address, prefix_size)) ++*source;
    }
    return P2P_OK;
}
