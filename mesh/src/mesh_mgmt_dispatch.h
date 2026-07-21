#ifndef TURBO_P2P_MESH_MGMT_DISPATCH_H
#define TURBO_P2P_MESH_MGMT_DISPATCH_H

#include "mesh_mgmt_replay.h"
#include "mesh_mgmt_session.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    MESH_MGMT_DISPATCH_OK = 0,
    MESH_MGMT_DISPATCH_INVALID_ARG = -1,
    MESH_MGMT_DISPATCH_INVALID_FRAME = -2,
    MESH_MGMT_DISPATCH_UNSUPPORTED_VERSION = -3,
    MESH_MGMT_DISPATCH_AUTH_FAILED = -4,
    MESH_MGMT_DISPATCH_EXPIRED = -5,
    MESH_MGMT_DISPATCH_NOT_ESTABLISHED = -6,
    MESH_MGMT_DISPATCH_UNSUPPORTED_FEATURE = -7,
    MESH_MGMT_DISPATCH_REPLAYED = -8,
    MESH_MGMT_DISPATCH_RESOURCE_EXHAUSTED = -9,
    MESH_MGMT_DISPATCH_SIDE_EFFECT_DISABLED = -10,
    MESH_MGMT_DISPATCH_INVALID_STATE = -11,
    MESH_MGMT_DISPATCH_CRYPTO_FAILURE = -12,
} mesh_mgmt_dispatch_result_t;

typedef enum {
    MESH_MGMT_DISPATCH_STAGE_STRUCTURE = 1,
    MESH_MGMT_DISPATCH_STAGE_ENVELOPE = 2,
    MESH_MGMT_DISPATCH_STAGE_SESSION = 3,
    MESH_MGMT_DISPATCH_STAGE_REPLAY = 4,
    MESH_MGMT_DISPATCH_STAGE_TYPED_DISPATCH = 5,
} mesh_mgmt_dispatch_stage_t;

typedef enum {
    MESH_MGMT_DISPATCH_EVENT_HELLO_ACK_REQUIRED = 1,
    MESH_MGMT_DISPATCH_EVENT_HELLO_ACK_ACCEPTED = 2,
    MESH_MGMT_DISPATCH_EVENT_SESSION_ESTABLISHED = 3,
    MESH_MGMT_DISPATCH_EVENT_MEMBERSHIP = 4,
    MESH_MGMT_DISPATCH_EVENT_ANTI_ENTROPY = 5,
    MESH_MGMT_DISPATCH_EVENT_AUDIT = 6,
    MESH_MGMT_DISPATCH_EVENT_ERROR = 7,
    MESH_MGMT_DISPATCH_EVENT_STREAM_TICKET_REQUEST = 8,
    MESH_MGMT_DISPATCH_EVENT_STREAM_TICKET_ISSUED = 9,
} mesh_mgmt_dispatch_event_type_t;

typedef struct {
    mesh_mgmt_session_config_v1_t session;
    mesh_mgmt_replay_config_v1_t replay;
} mesh_mgmt_dispatch_config_v1_t;

/**
 * Observer-only event. envelope payload storage is borrowed from the raw frame
 * and must not outlive it. No callback or external side effect is performed.
 */
typedef struct {
    mesh_mgmt_dispatch_event_type_t type;
    uint8_t kind;
    mesh_mgmt_hello_ack_v1_t hello_ack;
    mesh_mgmt_verified_envelope_v1_t envelope;
} mesh_mgmt_dispatch_event_v1_t;

/** Single event-loop owner; no internal locking. */
typedef struct {
    mesh_mgmt_session_v1_t session;
    mesh_mgmt_replay_gate_v1_t replay;
} mesh_mgmt_dispatcher_v1_t;

/** Shared fail-closed baseline for incoming and outgoing observer traffic. */
int mesh_mgmt_dispatch_kind_is_observer_safe_v1(uint8_t kind);

mesh_mgmt_dispatch_result_t mesh_mgmt_dispatcher_init_v1(
    mesh_mgmt_dispatcher_v1_t *dispatcher,
    const mesh_mgmt_dispatch_config_v1_t *config,
    mesh_mgmt_dispatch_stage_t *out_stage);

void mesh_mgmt_dispatcher_destroy_v1(
    mesh_mgmt_dispatcher_v1_t *dispatcher);

mesh_mgmt_dispatch_result_t mesh_mgmt_dispatcher_mark_hello_sent_v1(
    mesh_mgmt_dispatcher_v1_t *dispatcher,
    mesh_mgmt_dispatch_stage_t *out_stage);

mesh_mgmt_dispatch_result_t mesh_mgmt_dispatcher_mark_ack_sent_v1(
    mesh_mgmt_dispatcher_v1_t *dispatcher,
    mesh_mgmt_dispatch_stage_t *out_stage);

mesh_mgmt_dispatch_result_t mesh_mgmt_dispatcher_receive_v1(
    mesh_mgmt_dispatcher_v1_t *dispatcher,
    const uint8_t *frame,
    size_t frame_len,
    const uint8_t transport_peer_id[32],
    uint64_t now_ms,
    mesh_mgmt_dispatch_event_v1_t *out_event,
    mesh_mgmt_dispatch_stage_t *out_stage);

#ifdef __cplusplus
}
#endif

#endif
