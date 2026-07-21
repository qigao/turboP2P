#include "mesh_mgmt_dispatch.h"

#include "mesh_mgmt_crypto.h"

#include <string.h>

static mesh_mgmt_dispatch_result_t map_session_result(
    mesh_mgmt_session_result_t result) {
    switch (result) {
        case MESH_MGMT_SESSION_OK:
            return MESH_MGMT_DISPATCH_OK;
        case MESH_MGMT_SESSION_INVALID_ARG:
            return MESH_MGMT_DISPATCH_INVALID_ARG;
        case MESH_MGMT_SESSION_UNSUPPORTED_VERSION:
            return MESH_MGMT_DISPATCH_UNSUPPORTED_VERSION;
        case MESH_MGMT_SESSION_AUTH_FAILED:
            return MESH_MGMT_DISPATCH_AUTH_FAILED;
        case MESH_MGMT_SESSION_EXPIRED:
            return MESH_MGMT_DISPATCH_EXPIRED;
        case MESH_MGMT_SESSION_NOT_ESTABLISHED:
            return MESH_MGMT_DISPATCH_NOT_ESTABLISHED;
        case MESH_MGMT_SESSION_UNSUPPORTED_FEATURE:
            return MESH_MGMT_DISPATCH_UNSUPPORTED_FEATURE;
        case MESH_MGMT_SESSION_RESOURCE_EXHAUSTED:
            return MESH_MGMT_DISPATCH_RESOURCE_EXHAUSTED;
        case MESH_MGMT_SESSION_CRYPTO_FAILURE:
            return MESH_MGMT_DISPATCH_CRYPTO_FAILURE;
        case MESH_MGMT_SESSION_INVALID_STATE:
            return MESH_MGMT_DISPATCH_INVALID_STATE;
        case MESH_MGMT_SESSION_INVALID_SCHEMA:
        default:
            return MESH_MGMT_DISPATCH_INVALID_FRAME;
    }
}

static mesh_mgmt_dispatch_result_t map_envelope_result(
    mesh_mgmt_envelope_result_t result) {
    switch (result) {
        case MESH_MGMT_ENVELOPE_OK:
            return MESH_MGMT_DISPATCH_OK;
        case MESH_MGMT_ENVELOPE_INVALID_ARG:
            return MESH_MGMT_DISPATCH_INVALID_ARG;
        case MESH_MGMT_ENVELOPE_UNSUPPORTED_VERSION:
            return MESH_MGMT_DISPATCH_UNSUPPORTED_VERSION;
        case MESH_MGMT_ENVELOPE_AUTH_FAILED:
        case MESH_MGMT_ENVELOPE_PAYLOAD_HASH_MISMATCH:
            return MESH_MGMT_DISPATCH_AUTH_FAILED;
        case MESH_MGMT_ENVELOPE_RESOURCE_EXHAUSTED:
            return MESH_MGMT_DISPATCH_RESOURCE_EXHAUSTED;
        case MESH_MGMT_ENVELOPE_CRYPTO_FAILURE:
            return MESH_MGMT_DISPATCH_CRYPTO_FAILURE;
        case MESH_MGMT_ENVELOPE_INVALID_FRAME:
        case MESH_MGMT_ENVELOPE_INVALID_SCHEMA:
        default:
            return MESH_MGMT_DISPATCH_INVALID_FRAME;
    }
}

static mesh_mgmt_dispatch_result_t map_replay_result(
    mesh_mgmt_replay_result_t result) {
    switch (result) {
        case MESH_MGMT_REPLAY_OK:
            return MESH_MGMT_DISPATCH_OK;
        case MESH_MGMT_REPLAY_INVALID_ARG:
            return MESH_MGMT_DISPATCH_INVALID_ARG;
        case MESH_MGMT_REPLAY_EXPIRED:
            return MESH_MGMT_DISPATCH_EXPIRED;
        case MESH_MGMT_REPLAY_REPLAYED:
        case MESH_MGMT_REPLAY_STALE_PREPARATION:
            return MESH_MGMT_DISPATCH_REPLAYED;
        case MESH_MGMT_REPLAY_RESOURCE_EXHAUSTED:
            return MESH_MGMT_DISPATCH_RESOURCE_EXHAUSTED;
        case MESH_MGMT_REPLAY_BINDING_MISMATCH:
            return MESH_MGMT_DISPATCH_AUTH_FAILED;
        case MESH_MGMT_REPLAY_INVALID_SCHEMA:
        default:
            return MESH_MGMT_DISPATCH_INVALID_FRAME;
    }
}

static mesh_mgmt_dispatch_result_t bind_replay_if_established(
    mesh_mgmt_dispatcher_v1_t *dispatcher) {
    mesh_mgmt_replay_binding_v1_t binding;
    mesh_mgmt_replay_result_t result;

    if (dispatcher->session.state != MESH_MGMT_SESSION_ESTABLISHED ||
        dispatcher->replay.bound) {
        return MESH_MGMT_DISPATCH_OK;
    }
    memset(&binding, 0, sizeof(binding));
    memcpy(binding.principal_key,
           dispatcher->session.remote_certificate.management_key, 32);
    binding.principal_epoch =
        dispatcher->session.remote_certificate.principal_epoch;
    binding.incarnation = dispatcher->session.remote_incarnation;
    memcpy(binding.session_id, dispatcher->session.remote_session_id, 16);
    result = mesh_mgmt_replay_bind_v1(&dispatcher->replay, &binding);
    return map_replay_result(result);
}

int mesh_mgmt_dispatch_kind_is_observer_safe_v1(uint8_t kind) {
    return kind != MESH_MGMT_KIND_FORWARD &&
           kind != MESH_MGMT_KIND_COMMAND_REQUEST &&
           kind != MESH_MGMT_KIND_COMMAND_ACCEPTED &&
           kind != MESH_MGMT_KIND_COMMAND_RESULT &&
           kind != MESH_MGMT_KIND_COMMAND_STATUS;
}

static mesh_mgmt_dispatch_event_type_t event_type_for_kind(uint8_t kind) {
    switch (kind) {
        case MESH_MGMT_KIND_PROBE:
        case MESH_MGMT_KIND_PROBE_ACK:
        case MESH_MGMT_KIND_INDIRECT_PROBE:
        case MESH_MGMT_KIND_INDIRECT_ACK:
        case MESH_MGMT_KIND_MEMBERSHIP_DELTA:
            return MESH_MGMT_DISPATCH_EVENT_MEMBERSHIP;
        case MESH_MGMT_KIND_DIGEST:
        case MESH_MGMT_KIND_DELTA_REQUEST:
        case MESH_MGMT_KIND_DELTA_BATCH:
            return MESH_MGMT_DISPATCH_EVENT_ANTI_ENTROPY;
        case MESH_MGMT_KIND_AUDIT_ANCHOR:
            return MESH_MGMT_DISPATCH_EVENT_AUDIT;
        case MESH_MGMT_KIND_STREAM_TICKET_REQUEST:
            return MESH_MGMT_DISPATCH_EVENT_STREAM_TICKET_REQUEST;
        case MESH_MGMT_KIND_STREAM_TICKET_ISSUED:
            return MESH_MGMT_DISPATCH_EVENT_STREAM_TICKET_ISSUED;
        case MESH_MGMT_KIND_ERROR:
        default:
            return MESH_MGMT_DISPATCH_EVENT_ERROR;
    }
}

static int envelope_matches_session(
    const mesh_mgmt_dispatcher_v1_t *dispatcher,
    const mesh_mgmt_verified_envelope_v1_t *envelope) {
    const mesh_mgmt_session_v1_t *session = &dispatcher->session;
    return mesh_mgmt_crypto_equal_32(
               envelope->header.mesh_id_hash,
               session->config.expected_mesh_id_hash) &&
           mesh_mgmt_crypto_equal_32(
               envelope->header.origin_principal_key,
               session->remote_certificate.management_key) &&
           mesh_mgmt_crypto_equal_32(
               envelope->header.origin_node_id,
               session->remote_certificate.managed_node_id) &&
           envelope->header.certificate_serial ==
               session->remote_certificate.serial &&
           envelope->header.principal_epoch ==
               session->remote_certificate.principal_epoch &&
           envelope->header.incarnation == session->remote_incarnation &&
           mesh_mgmt_crypto_equal_16(envelope->header.session_id,
                                     session->remote_session_id);
}

mesh_mgmt_dispatch_result_t mesh_mgmt_dispatcher_init_v1(
    mesh_mgmt_dispatcher_v1_t *dispatcher,
    const mesh_mgmt_dispatch_config_v1_t *config,
    mesh_mgmt_dispatch_stage_t *out_stage) {
    mesh_mgmt_session_result_t session_result;
    mesh_mgmt_replay_result_t replay_result;

    if (!dispatcher || !config || !out_stage)
        return MESH_MGMT_DISPATCH_INVALID_ARG;
    memset(dispatcher, 0, sizeof(*dispatcher));
    *out_stage = MESH_MGMT_DISPATCH_STAGE_SESSION;
    session_result = mesh_mgmt_session_init_v1(&dispatcher->session,
                                                &config->session);
    if (session_result != MESH_MGMT_SESSION_OK)
        return map_session_result(session_result);
    *out_stage = MESH_MGMT_DISPATCH_STAGE_REPLAY;
    replay_result = mesh_mgmt_replay_init_v1(&dispatcher->replay,
                                              &config->replay);
    if (replay_result != MESH_MGMT_REPLAY_OK) {
        memset(&dispatcher->session, 0, sizeof(dispatcher->session));
        return map_replay_result(replay_result);
    }
    return MESH_MGMT_DISPATCH_OK;
}

void mesh_mgmt_dispatcher_destroy_v1(
    mesh_mgmt_dispatcher_v1_t *dispatcher) {
    if (!dispatcher) return;
    mesh_mgmt_replay_destroy_v1(&dispatcher->replay);
    memset(dispatcher, 0, sizeof(*dispatcher));
}

mesh_mgmt_dispatch_result_t mesh_mgmt_dispatcher_mark_hello_sent_v1(
    mesh_mgmt_dispatcher_v1_t *dispatcher,
    mesh_mgmt_dispatch_stage_t *out_stage) {
    if (!dispatcher || !out_stage) return MESH_MGMT_DISPATCH_INVALID_ARG;
    *out_stage = MESH_MGMT_DISPATCH_STAGE_SESSION;
    return map_session_result(
        mesh_mgmt_session_mark_hello_sent_v1(&dispatcher->session));
}

mesh_mgmt_dispatch_result_t mesh_mgmt_dispatcher_mark_ack_sent_v1(
    mesh_mgmt_dispatcher_v1_t *dispatcher,
    mesh_mgmt_dispatch_stage_t *out_stage) {
    mesh_mgmt_session_result_t session_result;

    if (!dispatcher || !out_stage) return MESH_MGMT_DISPATCH_INVALID_ARG;
    *out_stage = MESH_MGMT_DISPATCH_STAGE_SESSION;
    session_result = mesh_mgmt_session_mark_ack_sent_v1(&dispatcher->session);
    if (session_result != MESH_MGMT_SESSION_OK)
        return map_session_result(session_result);
    *out_stage = MESH_MGMT_DISPATCH_STAGE_REPLAY;
    return bind_replay_if_established(dispatcher);
}

mesh_mgmt_dispatch_result_t mesh_mgmt_dispatcher_receive_v1(
    mesh_mgmt_dispatcher_v1_t *dispatcher,
    const uint8_t *frame,
    size_t frame_len,
    const uint8_t transport_peer_id[32],
    uint64_t now_ms,
    mesh_mgmt_dispatch_event_v1_t *out_event,
    mesh_mgmt_dispatch_stage_t *out_stage) {
    mesh_mgmt_frame_view_t structural;
    mesh_mgmt_verified_envelope_v1_t verified;
    mesh_mgmt_replay_preparation_v1_t preparation;
    mesh_mgmt_session_result_t session_result;
    mesh_mgmt_envelope_result_t envelope_result;
    mesh_mgmt_replay_result_t replay_result;
    mesh_mgmt_dispatch_result_t result;

    if (!dispatcher || !frame || !transport_peer_id || !out_event ||
        !out_stage) return MESH_MGMT_DISPATCH_INVALID_ARG;
    memset(out_event, 0, sizeof(*out_event));
    *out_stage = MESH_MGMT_DISPATCH_STAGE_STRUCTURE;
    switch (mesh_mgmt_frame_decode(frame, frame_len, &structural)) {
        case MESH_MGMT_CODEC_OK:
            break;
        case MESH_MGMT_CODEC_UNSUPPORTED_VERSION:
            return MESH_MGMT_DISPATCH_UNSUPPORTED_VERSION;
        case MESH_MGMT_CODEC_RESOURCE_EXHAUSTED:
            return MESH_MGMT_DISPATCH_RESOURCE_EXHAUSTED;
        case MESH_MGMT_CODEC_INVALID_ARG:
            return MESH_MGMT_DISPATCH_INVALID_ARG;
        case MESH_MGMT_CODEC_INVALID_FRAME:
        default:
            return MESH_MGMT_DISPATCH_INVALID_FRAME;
    }

    *out_stage = MESH_MGMT_DISPATCH_STAGE_SESSION;
    if (structural.kind == MESH_MGMT_KIND_HELLO) {
        session_result = mesh_mgmt_session_accept_hello_v1(
            &dispatcher->session, frame, frame_len, transport_peer_id,
            now_ms, &out_event->hello_ack);
        if (session_result != MESH_MGMT_SESSION_OK)
            return map_session_result(session_result);
        out_event->type = MESH_MGMT_DISPATCH_EVENT_HELLO_ACK_REQUIRED;
        out_event->kind = structural.kind;
        return MESH_MGMT_DISPATCH_OK;
    }
    if (structural.kind == MESH_MGMT_KIND_HELLO_ACK) {
        session_result = mesh_mgmt_session_accept_hello_ack_v1(
            &dispatcher->session, frame, frame_len, now_ms);
        if (session_result != MESH_MGMT_SESSION_OK)
            return map_session_result(session_result);
        *out_stage = MESH_MGMT_DISPATCH_STAGE_REPLAY;
        result = bind_replay_if_established(dispatcher);
        if (result != MESH_MGMT_DISPATCH_OK) return result;
        out_event->type = dispatcher->session.state ==
                                  MESH_MGMT_SESSION_ESTABLISHED
                              ? MESH_MGMT_DISPATCH_EVENT_SESSION_ESTABLISHED
                              : MESH_MGMT_DISPATCH_EVENT_HELLO_ACK_ACCEPTED;
        out_event->kind = structural.kind;
        return MESH_MGMT_DISPATCH_OK;
    }
    if (dispatcher->session.state != MESH_MGMT_SESSION_ESTABLISHED)
        return MESH_MGMT_DISPATCH_NOT_ESTABLISHED;
    if (frame_len > dispatcher->session.negotiated.max_frame)
        return MESH_MGMT_DISPATCH_RESOURCE_EXHAUSTED;

    *out_stage = MESH_MGMT_DISPATCH_STAGE_ENVELOPE;
    envelope_result = mesh_mgmt_envelope_verify_v1(frame, frame_len,
                                                    &verified);
    if (envelope_result != MESH_MGMT_ENVELOPE_OK)
        return map_envelope_result(envelope_result);
    if (verified.header.issued_at_ms > now_ms ||
        verified.header.expires_at_ms <= now_ms)
        return MESH_MGMT_DISPATCH_EXPIRED;

    *out_stage = MESH_MGMT_DISPATCH_STAGE_SESSION;
    if (!envelope_matches_session(dispatcher, &verified))
        return MESH_MGMT_DISPATCH_AUTH_FAILED;
    session_result = mesh_mgmt_session_authorize_kind_v1(
        &dispatcher->session, verified.frame.kind);
    if (session_result != MESH_MGMT_SESSION_OK)
        return map_session_result(session_result);
    if (!mesh_mgmt_dispatch_kind_is_observer_safe_v1(verified.frame.kind))
        return MESH_MGMT_DISPATCH_SIDE_EFFECT_DISABLED;
    if (verified.header.forward_budget != 0u)
        return MESH_MGMT_DISPATCH_INVALID_FRAME;

    *out_stage = MESH_MGMT_DISPATCH_STAGE_REPLAY;
    replay_result = mesh_mgmt_replay_prepare_v1(
        &dispatcher->replay, &verified.header, now_ms, &preparation);
    if (replay_result != MESH_MGMT_REPLAY_OK)
        return map_replay_result(replay_result);
    replay_result = mesh_mgmt_replay_commit_v1(&dispatcher->replay,
                                                &preparation);
    if (replay_result != MESH_MGMT_REPLAY_OK)
        return map_replay_result(replay_result);

    *out_stage = MESH_MGMT_DISPATCH_STAGE_TYPED_DISPATCH;
    out_event->type = event_type_for_kind(verified.frame.kind);
    out_event->kind = verified.frame.kind;
    out_event->envelope = verified;
    return MESH_MGMT_DISPATCH_OK;
}
