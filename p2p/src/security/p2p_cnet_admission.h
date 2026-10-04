#ifndef P2P_CNET_ADMISSION_H
#define P2P_CNET_ADMISSION_H

#include "../core/cnet_transport.h"
#include "p2p_cookie.h"

typedef struct p2p_cnet_admission_s p2p_cnet_admission_t;

typedef struct {
    size_t gate_limit;
    size_t source_limit; /* IPv4 address or IPv6 /64, across pending gates. */
    size_t peer_send_hwm_bytes;
    uint32_t handshake_timeout_ms;
    uint32_t cookie_lifetime_ms;
    uint32_t cookie_key_rotation_ms;
    uint8_t network_id_hash[32];
    uint8_t cookie_master_secret[P2P_COOKIE_SECRET_SIZE];
} p2p_cnet_admission_config_t;

typedef struct {
    /* Mandatory node policy: apply rate/denylist and total pending-peer limits
     * before a gate is allocated. Promotion must recheck the node's peer quota.
     * Callbacks run on the owner thread; recursive admission mutation fails. */
    int (*admit)(const cnet_stream_peer *source, void *context);
    /* Called only after valid proof AND completed challenge send. The current
     * gate has already left the pending count when the node rechecks quota.
     * This is a
     * cookie proof, not identity authentication or application readiness.
     * Output receive/closed callbacks are mandatory. On success their context
     * transfers to the connection; connected runs once after handoff and may
     * start Noise or pause. On failure the producer owns its partial context.
     * Source/preface/binding are borrowed only for the duration of this call. */
    int (*promote)(const cnet_stream_peer *source,
                   const uint8_t preface[P2P_SECURE_PREFACE_SIZE],
                   const uint8_t binding[P2P_COOKIE_BINDING_SIZE],
                   p2p_cnet_callbacks_t *output, void *context);
    void (*rejected)(const cnet_stream_peer *source, int status, void *context);
    void *context;
} p2p_cnet_admission_callbacks_t;

typedef struct {
    size_t active;
    uint64_t accepted;
    uint64_t challenges_completed;
    uint64_t promoted;
    uint64_t rejected;
} p2p_cnet_admission_stats_t;

/* Internal bounded ingress component, explicitly attached to one CNet owner.
 * It does not select a backend for p2p_create/start or replace the node policy.
 * Configuration and descriptors are copied; callback context is borrowed. */
int p2p_cnet_admission_create(p2p_cnet_owner_t *owner,
    const p2p_cnet_admission_config_t *config,
    const p2p_cnet_admission_callbacks_t *callbacks,
    p2p_cnet_admission_t **output);
/* Use directly as p2p_cnet_owner_listen's accept callback, with the admission
 * object as context. The transport owns rejected connections. */
int p2p_cnet_admission_accept(p2p_cnet_owner_t *owner,
    p2p_connection_t *connection, const cnet_stream_peer *source, void *context);
/* Call on every owner turn, including idle turns. now_ms uses Salts' monotonic
 * clock; a backward clock invalidates pending gates instead of extending them. */
int p2p_cnet_admission_expire(p2p_cnet_admission_t *admission, uint64_t now_ms);
/* Shutdown order: stop admission (detaches its gate callbacks), stop/destroy
 * CNet owner (quiesces the listener), then destroy admission. Stop is terminal
 * and leaves the accept context alive to reject new accepts during drain.
 * Promoted peers belong to the node and are unaffected by admission stop. */
int p2p_cnet_admission_stop(p2p_cnet_admission_t *admission);
int p2p_cnet_admission_destroy(p2p_cnet_admission_t *admission);
int p2p_cnet_admission_stats(const p2p_cnet_admission_t *admission,
                            p2p_cnet_admission_stats_t *output);

#endif
