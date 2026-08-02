#include "mesh_mgmt_dispatch.h"

#include "mesh_mgmt_crypto.h"
#include "mesh_mgmt_execution_wire.h"

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

static mesh_mgmt_dispatch_result_t map_execution_wire_result(
    mesh_mgmt_execution_wire_result_t result) {
    switch (result) {
        case MESH_MGMT_EXECUTION_WIRE_OK:
            return MESH_MGMT_DISPATCH_OK;
        case MESH_MGMT_EXECUTION_WIRE_INVALID_ARG:
            return MESH_MGMT_DISPATCH_INVALID_ARG;
        case MESH_MGMT_EXECUTION_WIRE_RESOURCE_EXHAUSTED:
            return MESH_MGMT_DISPATCH_RESOURCE_EXHAUSTED;
        case MESH_MGMT_EXECUTION_WIRE_CRYPTO_FAILED:
            return MESH_MGMT_DISPATCH_CRYPTO_FAILURE;
        case MESH_MGMT_EXECUTION_WIRE_AUTH_FAILED:
            return MESH_MGMT_DISPATCH_AUTH_FAILED;
        case MESH_MGMT_EXECUTION_WIRE_EXPIRED:
            return MESH_MGMT_DISPATCH_EXPIRED;
        case MESH_MGMT_EXECUTION_WIRE_INVALID_SCHEMA:
        default:
            return MESH_MGMT_DISPATCH_INVALID_FRAME;
    }
}

static int key_is_present(const uint8_t key[32]) {
    size_t index;

    for (index = 0u; index < 32u; ++index) {
        if (key[index] != 0u) return 1;
    }
    return 0;
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

mesh_mgmt_dispatch_result_t
mesh_mgmt_dispatcher_validate_node_execution_shadow_v1(
    const mesh_mgmt_dispatcher_v1_t *dispatcher,
    const uint8_t *payload,
    size_t payload_len,
    uint64_t now_ms) {
    mesh_mgmt_execution_grant_v1_t grant;
    mesh_mgmt_execution_request_v1_t request;
    mesh_mgmt_execution_wire_result_t wire_result;
    mesh_mgmt_session_result_t session_result;

    if (!dispatcher || !payload)
        return MESH_MGMT_DISPATCH_INVALID_ARG;
    if (!dispatcher->enable_node_execution_shadow)
        return MESH_MGMT_DISPATCH_SIDE_EFFECT_DISABLED;
    session_result = mesh_mgmt_session_authorize_feature_v1(
        &dispatcher->session, MESH_MGMT_FEATURE_NODE_EXECUTION);
    if (session_result != MESH_MGMT_SESSION_OK)
        return map_session_result(session_result);
    if (!key_is_present(dispatcher->node_execution_grant_issuer_key))
        return MESH_MGMT_DISPATCH_INVALID_STATE;
    if ((dispatcher->session.remote_certificate.roles &
         MESH_MGMT_ROLE_OPERATOR) == 0u)
        return MESH_MGMT_DISPATCH_AUTH_FAILED;

    wire_result = mesh_mgmt_execution_command_request_decode_compatible_v2(
        payload, payload_len, &grant, &request, NULL, NULL);
    if (wire_result != MESH_MGMT_EXECUTION_WIRE_OK)
        return map_execution_wire_result(wire_result);
    wire_result = mesh_mgmt_execution_grant_verify_v1(
        &grant, dispatcher->node_execution_grant_issuer_key, now_ms);
    if (wire_result != MESH_MGMT_EXECUTION_WIRE_OK)
        return map_execution_wire_result(wire_result);
    if (!mesh_mgmt_crypto_equal_32(
            grant.mesh_id,
            dispatcher->session.config.expected_mesh_id_hash) ||
        !mesh_mgmt_crypto_equal_32(
            grant.subject_principal,
            dispatcher->session.remote_certificate.management_key))
        return MESH_MGMT_DISPATCH_AUTH_FAILED;
    if (mesh_mgmt_execution_request_validate_v1(&request, now_ms) ==
        MESH_MGMT_EXECUTION_EXPIRED)
        return MESH_MGMT_DISPATCH_EXPIRED;
    return MESH_MGMT_DISPATCH_OK;
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

mesh_mgmt_dispatch_result_t
mesh_mgmt_dispatcher_validate_node_execution_outbound_shadow_v1(
    const mesh_mgmt_dispatcher_v1_t *dispatcher,
    const uint8_t *frame,
    size_t frame_len) {
    mesh_mgmt_verified_envelope_v1_t verified;
    mesh_mgmt_execution_grant_v1_t grant;
    mesh_mgmt_execution_request_v1_t request;
    mesh_mgmt_envelope_result_t envelope_result;
    mesh_mgmt_execution_wire_result_t wire_result;
    mesh_mgmt_session_result_t session_result;

    if (!dispatcher || !frame)
        return MESH_MGMT_DISPATCH_INVALID_ARG;
    if (!dispatcher->enable_node_execution_shadow)
        return MESH_MGMT_DISPATCH_SIDE_EFFECT_DISABLED;
    if (dispatcher->session.state != MESH_MGMT_SESSION_ESTABLISHED)
        return MESH_MGMT_DISPATCH_NOT_ESTABLISHED;
    if (frame_len > dispatcher->session.negotiated.max_frame)
        return MESH_MGMT_DISPATCH_RESOURCE_EXHAUSTED;
    session_result = mesh_mgmt_session_authorize_kind_v1(
        &dispatcher->session, MESH_MGMT_KIND_COMMAND_REQUEST);
    if (session_result != MESH_MGMT_SESSION_OK)
        return map_session_result(session_result);
    session_result = mesh_mgmt_session_authorize_feature_v1(
        &dispatcher->session, MESH_MGMT_FEATURE_NODE_EXECUTION);
    if (session_result != MESH_MGMT_SESSION_OK)
        return map_session_result(session_result);
    if (!key_is_present(dispatcher->node_execution_grant_issuer_key))
        return MESH_MGMT_DISPATCH_INVALID_STATE;

    envelope_result = mesh_mgmt_envelope_verify_v1(frame, frame_len, &verified);
    if (envelope_result != MESH_MGMT_ENVELOPE_OK)
        return map_envelope_result(envelope_result);
    if (verified.frame.kind != MESH_MGMT_KIND_COMMAND_REQUEST ||
        verified.header.forward_budget != 0u)
        return MESH_MGMT_DISPATCH_INVALID_FRAME;
    wire_result = mesh_mgmt_execution_command_request_decode_compatible_v2(
        verified.frame.payload, verified.frame.payload_len, &grant, &request,
        NULL, NULL);
    if (wire_result != MESH_MGMT_EXECUTION_WIRE_OK)
        return map_execution_wire_result(wire_result);
    wire_result = mesh_mgmt_execution_grant_verify_v1(
        &grant, dispatcher->node_execution_grant_issuer_key,
        verified.header.issued_at_ms);
    if (wire_result != MESH_MGMT_EXECUTION_WIRE_OK)
        return map_execution_wire_result(wire_result);
    if (!mesh_mgmt_crypto_equal_32(
            verified.header.mesh_id_hash,
            dispatcher->session.config.expected_mesh_id_hash) ||
        !mesh_mgmt_crypto_equal_32(grant.mesh_id,
                                   verified.header.mesh_id_hash) ||
        !mesh_mgmt_crypto_equal_32(
            grant.subject_principal,
            verified.header.origin_principal_key) ||
        !mesh_mgmt_crypto_equal_32(
            grant.target_node_id,
            dispatcher->session.remote_certificate.managed_node_id) ||
        !mesh_mgmt_crypto_equal_32(grant.target_node_id,
                                   verified.header.target_node_id))
        return MESH_MGMT_DISPATCH_AUTH_FAILED;
    if (mesh_mgmt_execution_request_validate_v1(
            &request, verified.header.issued_at_ms) !=
            MESH_MGMT_EXECUTION_OK)
        return MESH_MGMT_DISPATCH_EXPIRED;
    if (verified.header.expires_at_ms > grant.expires_at_ms ||
        verified.header.expires_at_ms > request.deadline_ms)
        return MESH_MGMT_DISPATCH_EXPIRED;
    return MESH_MGMT_DISPATCH_OK;
}

mesh_mgmt_dispatch_result_t
mesh_mgmt_dispatcher_validate_node_execution_result_outbound_shadow_v1(
    const mesh_mgmt_dispatcher_v1_t *dispatcher,
    const uint8_t *frame,
    size_t frame_len) {
    mesh_mgmt_verified_envelope_v1_t verified;
    mesh_mgmt_execution_result_v1_t result;
    mesh_mgmt_envelope_result_t envelope_result;
    mesh_mgmt_execution_wire_result_t wire_result;
    mesh_mgmt_session_result_t session_result;

    if (!dispatcher || !frame)
        return MESH_MGMT_DISPATCH_INVALID_ARG;
    if (!dispatcher->enable_node_execution_shadow)
        return MESH_MGMT_DISPATCH_SIDE_EFFECT_DISABLED;
    if (dispatcher->session.state != MESH_MGMT_SESSION_ESTABLISHED)
        return MESH_MGMT_DISPATCH_NOT_ESTABLISHED;
    if (frame_len > dispatcher->session.negotiated.max_frame)
        return MESH_MGMT_DISPATCH_RESOURCE_EXHAUSTED;
    session_result = mesh_mgmt_session_authorize_kind_v1(
        &dispatcher->session, MESH_MGMT_KIND_COMMAND_RESULT);
    if (session_result != MESH_MGMT_SESSION_OK)
        return map_session_result(session_result);
    session_result = mesh_mgmt_session_authorize_feature_v1(
        &dispatcher->session, MESH_MGMT_FEATURE_NODE_EXECUTION);
    if (session_result != MESH_MGMT_SESSION_OK)
        return map_session_result(session_result);

    envelope_result = mesh_mgmt_envelope_verify_v1(frame, frame_len, &verified);
    if (envelope_result != MESH_MGMT_ENVELOPE_OK)
        return map_envelope_result(envelope_result);
    if (verified.frame.kind != MESH_MGMT_KIND_COMMAND_RESULT ||
        verified.header.forward_budget != 0u)
        return MESH_MGMT_DISPATCH_INVALID_FRAME;
    wire_result = mesh_mgmt_execution_command_result_decode_v1(
        verified.frame.payload, verified.frame.payload_len, &result);
    if (wire_result != MESH_MGMT_EXECUTION_WIRE_OK)
        return map_execution_wire_result(wire_result);
    if (mesh_mgmt_execution_result_verify_v1(
            &result, result.signer_public_key) !=
        MESH_MGMT_EXECUTION_RESULT_OK)
        return MESH_MGMT_DISPATCH_AUTH_FAILED;
    if (!mesh_mgmt_crypto_equal_32(
            verified.header.mesh_id_hash,
            dispatcher->session.config.expected_mesh_id_hash) ||
        !mesh_mgmt_crypto_equal_32(
            result.target_node_id, verified.header.origin_node_id) ||
        !mesh_mgmt_crypto_equal_32(
            verified.header.target_node_id,
            dispatcher->session.remote_certificate.managed_node_id))
        return MESH_MGMT_DISPATCH_AUTH_FAILED;
    return MESH_MGMT_DISPATCH_OK;
}

mesh_mgmt_dispatch_result_t
mesh_mgmt_dispatcher_validate_node_execution_status_outbound_shadow_v1(
    const mesh_mgmt_dispatcher_v1_t *dispatcher,
    const uint8_t *frame,
    size_t frame_len) {
    mesh_mgmt_verified_envelope_v1_t verified;
    mesh_mgmt_execution_status_v1_t status;
    mesh_mgmt_envelope_result_t envelope_result;
    mesh_mgmt_execution_wire_result_t wire_result;
    mesh_mgmt_session_result_t session_result;

    if (!dispatcher || !frame)
        return MESH_MGMT_DISPATCH_INVALID_ARG;
    if (!dispatcher->enable_node_execution_shadow)
        return MESH_MGMT_DISPATCH_SIDE_EFFECT_DISABLED;
    if (dispatcher->session.state != MESH_MGMT_SESSION_ESTABLISHED)
        return MESH_MGMT_DISPATCH_NOT_ESTABLISHED;
    if (frame_len > dispatcher->session.negotiated.max_frame)
        return MESH_MGMT_DISPATCH_RESOURCE_EXHAUSTED;
    session_result = mesh_mgmt_session_authorize_kind_v1(
        &dispatcher->session, MESH_MGMT_KIND_COMMAND_STATUS);
    if (session_result != MESH_MGMT_SESSION_OK)
        return map_session_result(session_result);
    session_result = mesh_mgmt_session_authorize_feature_v1(
        &dispatcher->session, MESH_MGMT_FEATURE_NODE_EXECUTION);
    if (session_result != MESH_MGMT_SESSION_OK)
        return map_session_result(session_result);
    envelope_result = mesh_mgmt_envelope_verify_v1(frame, frame_len, &verified);
    if (envelope_result != MESH_MGMT_ENVELOPE_OK)
        return map_envelope_result(envelope_result);
    if (verified.frame.kind != MESH_MGMT_KIND_COMMAND_STATUS ||
        verified.header.forward_budget != 0u)
        return MESH_MGMT_DISPATCH_INVALID_FRAME;
    wire_result = mesh_mgmt_execution_command_status_decode_v1(
        verified.frame.payload, verified.frame.payload_len, &status);
    if (wire_result != MESH_MGMT_EXECUTION_WIRE_OK)
        return map_execution_wire_result(wire_result);
    if (!mesh_mgmt_crypto_equal_32(
            verified.header.mesh_id_hash,
            dispatcher->session.config.expected_mesh_id_hash) ||
        !mesh_mgmt_crypto_equal_32(
            status.responder_node_id, verified.header.origin_node_id) ||
        !mesh_mgmt_crypto_equal_32(
            verified.header.target_node_id,
            dispatcher->session.remote_certificate.managed_node_id))
        return MESH_MGMT_DISPATCH_AUTH_FAILED;
    return MESH_MGMT_DISPATCH_OK;
}

static mesh_mgmt_dispatch_result_t validate_node_execution_response_payload(
    const mesh_mgmt_verified_envelope_v1_t *verified) {
    mesh_mgmt_execution_result_v1_t execution_result;
    mesh_mgmt_execution_status_v1_t status;
    mesh_mgmt_execution_wire_result_t wire_result;

    if (verified->frame.kind == MESH_MGMT_KIND_COMMAND_RESULT) {
        wire_result = mesh_mgmt_execution_command_result_decode_v1(
            verified->frame.payload, verified->frame.payload_len,
            &execution_result);
        if (wire_result != MESH_MGMT_EXECUTION_WIRE_OK)
            return map_execution_wire_result(wire_result);
        if (mesh_mgmt_execution_result_verify_v1(
                &execution_result, execution_result.signer_public_key) !=
            MESH_MGMT_EXECUTION_RESULT_OK)
            return MESH_MGMT_DISPATCH_AUTH_FAILED;
        return mesh_mgmt_crypto_equal_32(
                   execution_result.target_node_id,
                   verified->header.origin_node_id)
                   ? MESH_MGMT_DISPATCH_OK
                   : MESH_MGMT_DISPATCH_AUTH_FAILED;
    }
    if (verified->frame.kind == MESH_MGMT_KIND_COMMAND_STATUS) {
        wire_result = mesh_mgmt_execution_command_status_decode_v1(
            verified->frame.payload, verified->frame.payload_len, &status);
        if (wire_result != MESH_MGMT_EXECUTION_WIRE_OK)
            return map_execution_wire_result(wire_result);
        return mesh_mgmt_crypto_equal_32(
                   status.responder_node_id,
                   verified->header.origin_node_id)
                   ? MESH_MGMT_DISPATCH_OK
                   : MESH_MGMT_DISPATCH_AUTH_FAILED;
    }
    return MESH_MGMT_DISPATCH_INVALID_FRAME;
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
    if (config->enable_node_execution_shadow &&
        (((config->session.features &
           (MESH_MGMT_FEATURE_TARGETED_RPC |
            MESH_MGMT_FEATURE_NODE_EXECUTION)) !=
          (MESH_MGMT_FEATURE_TARGETED_RPC |
           MESH_MGMT_FEATURE_NODE_EXECUTION)) ||
         !key_is_present(config->node_execution_grant_issuer_key))) {
        return MESH_MGMT_DISPATCH_UNSUPPORTED_FEATURE;
    }
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
    dispatcher->enable_node_execution_shadow =
        config->enable_node_execution_shadow;
    memcpy(dispatcher->node_execution_grant_issuer_key,
           config->node_execution_grant_issuer_key,
           sizeof(dispatcher->node_execution_grant_issuer_key));
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
    int node_execution_shadow = 0;

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
    if (!mesh_mgmt_dispatch_kind_is_observer_safe_v1(verified.frame.kind)) {
        if ((verified.frame.kind != MESH_MGMT_KIND_COMMAND_REQUEST &&
             verified.frame.kind != MESH_MGMT_KIND_COMMAND_RESULT &&
             verified.frame.kind != MESH_MGMT_KIND_COMMAND_STATUS) ||
            !dispatcher->enable_node_execution_shadow)
            return MESH_MGMT_DISPATCH_SIDE_EFFECT_DISABLED;
        session_result = mesh_mgmt_session_authorize_feature_v1(
            &dispatcher->session, MESH_MGMT_FEATURE_NODE_EXECUTION);
        if (session_result != MESH_MGMT_SESSION_OK)
            return map_session_result(session_result);
        if (verified.header.forward_budget != 0u)
            return MESH_MGMT_DISPATCH_INVALID_FRAME;
        *out_stage = MESH_MGMT_DISPATCH_STAGE_TYPED_DISPATCH;
        result = verified.frame.kind == MESH_MGMT_KIND_COMMAND_REQUEST
            ? mesh_mgmt_dispatcher_validate_node_execution_shadow_v1(
                  dispatcher, verified.frame.payload,
                  verified.frame.payload_len, now_ms)
            : validate_node_execution_response_payload(&verified);
        if (result != MESH_MGMT_DISPATCH_OK)
            return result;
        node_execution_shadow =
            verified.frame.kind == MESH_MGMT_KIND_COMMAND_REQUEST ? 1 :
            verified.frame.kind == MESH_MGMT_KIND_COMMAND_RESULT ? 2 : 3;
    }
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
    out_event->type =
        node_execution_shadow == 1
            ? MESH_MGMT_DISPATCH_EVENT_NODE_EXECUTION_REQUEST_SHADOW
        : node_execution_shadow == 2
            ? MESH_MGMT_DISPATCH_EVENT_NODE_EXECUTION_RESULT_SHADOW
        : node_execution_shadow == 3
            ? MESH_MGMT_DISPATCH_EVENT_NODE_EXECUTION_STATUS_SHADOW
            : event_type_for_kind(verified.frame.kind);
    out_event->kind = verified.frame.kind;
    out_event->envelope = verified;
    return MESH_MGMT_DISPATCH_OK;
}
