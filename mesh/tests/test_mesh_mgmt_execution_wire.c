#include "mesh_mgmt_execution_wire.h"
#include "mesh_mgmt_crypto.h"
#include "mesh_mgmt_dispatch.h"
#include "mesh_mgmt_envelope.h"
#include "mesh_mgmt_session.h"
#include "tinytest.h"

#include <string.h>

static const uint8_t issuer_private_key[32] = {
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40};

static void fill_bytes(uint8_t *bytes, size_t size, uint8_t value) {
  memset(bytes, value, size);
}

static void make_grant(mesh_mgmt_execution_grant_v1_t *grant) {
  memset(grant, 0, sizeof(*grant));
  grant->version = MESH_MGMT_EXECUTION_SCHEMA_V1;
  fill_bytes(grant->grant_id, sizeof(grant->grant_id), 1u);
  fill_bytes(grant->mesh_id, sizeof(grant->mesh_id), 2u);
  grant->policy_epoch = 3u;
  fill_bytes(grant->subject_principal, sizeof(grant->subject_principal), 4u);
  fill_bytes(grant->target_node_id, sizeof(grant->target_node_id), 5u);
  fill_bytes(grant->deployment_id, sizeof(grant->deployment_id), 6u);
  grant->deployment_generation = 7u;
  fill_bytes(grant->package_digest, sizeof(grant->package_digest), 8u);
  grant->operation = MESH_MGMT_EXECUTION_OPERATION_RUN_PRESTAGED_WASM;
  grant->capabilities = MESH_MGMT_EXECUTION_CAP_CORE;
  fill_bytes(grant->mount_ids[0], sizeof(grant->mount_ids[0]), 9u);
  grant->mount_count = 1u;
  fill_bytes(grant->service_ids[0], sizeof(grant->service_ids[0]), 10u);
  grant->service_count = 1u;
  fill_bytes(grant->provider_ids[0], sizeof(grant->provider_ids[0]), 11u);
  grant->provider_count = 1u;
  grant->max_limits.module_bytes = 1024u;
  grant->max_limits.stack_bytes = 1024u;
  grant->max_limits.linear_memory_bytes = 4096u;
  grant->max_limits.timeout_ms = 1000u;
  grant->max_limits.control_flow_steps = 10000u;
  grant->max_limits.host_calls = 8u;
  grant->max_limits.copied_guest_bytes = 4096u;
  grant->max_limits.input_bytes = 64u;
  grant->max_limits.stdout_bytes = 64u;
  grant->max_limits.stderr_bytes = 64u;
  grant->not_before_ms = 100u;
  grant->expires_at_ms = 1000u;
}

static void make_request(
    const mesh_mgmt_execution_grant_v1_t *grant,
    mesh_mgmt_execution_request_v1_t *request) {
  memset(request, 0, sizeof(*request));
  request->version = MESH_MGMT_EXECUTION_SCHEMA_V1;
  fill_bytes(request->command_id, sizeof(request->command_id), 12u);
  memcpy(request->grant_id, grant->grant_id, sizeof(request->grant_id));
  memcpy(request->target_node_id, grant->target_node_id,
         sizeof(request->target_node_id));
  memcpy(request->deployment_id, grant->deployment_id,
         sizeof(request->deployment_id));
  request->deployment_generation = grant->deployment_generation;
  memcpy(request->package_digest, grant->package_digest,
         sizeof(request->package_digest));
  request->input_kind = MESH_MGMT_EXECUTION_INPUT_INLINE;
  fill_bytes(request->input_digest, sizeof(request->input_digest), 13u);
  request->input_length = 3u;
  memcpy(request->inline_input, "rpc", 3u);
  request->inline_input_size = 3u;
  request->output_mode = MESH_MGMT_EXECUTION_OUTPUT_DIGEST;
  request->deadline_ms = 900u;
  fill_bytes(request->request_nonce, sizeof(request->request_nonce), 14u);
  fill_bytes(request->correlation_id, sizeof(request->correlation_id), 15u);
}

static void make_result(mesh_mgmt_execution_result_v1_t *result) {
  memset(result, 0, sizeof(*result));
  result->version = MESH_MGMT_EXECUTION_RESULT_VERSION_V1;
  fill_bytes(result->command_id, sizeof(result->command_id), 12u);
  fill_bytes(result->request_digest, sizeof(result->request_digest), 13u);
  fill_bytes(result->target_node_id, sizeof(result->target_node_id), 5u);
  fill_bytes(result->deployment_id, sizeof(result->deployment_id), 6u);
  result->deployment_generation = 7u;
  fill_bytes(result->package_digest, sizeof(result->package_digest), 8u);
  result->policy_epoch = 3u;
  fill_bytes(result->grant_id, sizeof(result->grant_id), 1u);
  result->state = MESH_MGMT_EXECUTION_STATE_SUCCEEDED;
  result->runtime_stage = 7;
  fill_bytes(result->stdout_digest, sizeof(result->stdout_digest), 16u);
  fill_bytes(result->stderr_digest, sizeof(result->stderr_digest), 17u);
  result->started_at_ms = 200u;
  result->finished_at_ms = 201u;
  result->worker_generation = 1u;
  fill_bytes(result->correlation_id, sizeof(result->correlation_id), 15u);
}

static void test_feature_authorization_is_additive(void) {
  mesh_mgmt_session_v1_t session;

  memset(&session, 0, sizeof(session));
  session.state = MESH_MGMT_SESSION_ESTABLISHED;
  session.negotiated.features = MESH_MGMT_FEATURE_TARGETED_RPC;
  check_int_eq(mesh_mgmt_session_authorize_kind_v1(
                   &session, MESH_MGMT_KIND_COMMAND_REQUEST),
               MESH_MGMT_SESSION_OK);
  check_int_eq(mesh_mgmt_session_authorize_feature_v1(
                   &session, MESH_MGMT_FEATURE_NODE_EXECUTION),
               MESH_MGMT_SESSION_UNSUPPORTED_FEATURE);
  session.negotiated.features |= MESH_MGMT_FEATURE_NODE_EXECUTION;
  check_int_eq(mesh_mgmt_session_authorize_feature_v1(
                   &session, MESH_MGMT_FEATURE_NODE_EXECUTION),
               MESH_MGMT_SESSION_OK);
}

static void test_signed_grant_and_request_round_trip(void) {
  mesh_mgmt_execution_grant_v1_t grant;
  mesh_mgmt_execution_grant_v1_t decoded_grant;
  mesh_mgmt_execution_request_v1_t request;
  mesh_mgmt_execution_request_v1_t decoded_request;
  uint8_t payload[MESH_MGMT_EXECUTION_COMMAND_REQUEST_MAX_SIZE_V1];
  uint8_t original_digest[32];
  uint8_t decoded_digest[32];
  size_t payload_size = 0u;

  make_grant(&grant);
  check_int_eq(mesh_mgmt_execution_grant_sign_v1(&grant, issuer_private_key),
               MESH_MGMT_EXECUTION_WIRE_OK);
  make_request(&grant, &request);
  check_int_eq(mesh_mgmt_execution_command_request_encode_v1(
                   &grant, &request, payload, sizeof(payload), &payload_size),
               MESH_MGMT_EXECUTION_WIRE_OK);
  check_int_eq(mesh_mgmt_execution_command_request_decode_v1(
                   payload, payload_size, &decoded_grant, &decoded_request),
               MESH_MGMT_EXECUTION_WIRE_OK);
  check_int_eq(mesh_mgmt_execution_grant_verify_v1(
                   &decoded_grant, grant.issuer_key, 200u),
               MESH_MGMT_EXECUTION_WIRE_OK);
  check_int_eq(mesh_mgmt_execution_request_digest_v1(&request,
                                                     original_digest),
               MESH_MGMT_EXECUTION_RESULT_OK);
  check_int_eq(mesh_mgmt_execution_request_digest_v1(&decoded_request,
                                                     decoded_digest),
               MESH_MGMT_EXECUTION_RESULT_OK);
  check_mem_eq(original_digest, decoded_digest, sizeof(original_digest));

  decoded_grant.signature[0] ^= 1u;
  check_int_eq(mesh_mgmt_execution_grant_verify_v1(
                   &decoded_grant, grant.issuer_key, 200u),
               MESH_MGMT_EXECUTION_WIRE_AUTH_FAILED);
  payload[0] ^= 1u;
  check_int_eq(mesh_mgmt_execution_command_request_decode_v1(
                   payload, payload_size, &decoded_grant, &decoded_request),
               MESH_MGMT_EXECUTION_WIRE_INVALID_SCHEMA);
}

static void test_v2_request_round_trips_lease_fencing_proof(void) {
  mesh_mgmt_execution_grant_v1_t grant;
  mesh_mgmt_execution_grant_v1_t decoded_grant;
  mesh_mgmt_execution_request_v1_t request;
  mesh_mgmt_execution_request_v1_t decoded_request;
  mesh_mgmt_execution_lease_proof_v2_t proof;
  mesh_mgmt_execution_lease_proof_v2_t decoded_proof;
  uint8_t payload[MESH_MGMT_EXECUTION_COMMAND_REQUEST_MAX_SIZE_V2];
  uint16_t version = 0u;
  size_t payload_size = 0u;

  make_grant(&grant);
  check_int_eq(mesh_mgmt_execution_grant_sign_v1(&grant, issuer_private_key),
               MESH_MGMT_EXECUTION_WIRE_OK);
  make_request(&grant, &request);
  memset(&proof, 0, sizeof(proof));
  proof.fencing_token = 41u;
  proof.worker_generation = 7u;
  proof.quorum_read_index = 43u;
  proof.lease_expires_at_ms = request.deadline_ms - 1u;

  check_int_eq(mesh_mgmt_execution_command_request_encode_v2(
                   &grant, &request, &proof, payload, sizeof(payload),
                   &payload_size),
               MESH_MGMT_EXECUTION_WIRE_OK);
  check_int_eq(mesh_mgmt_execution_command_request_decode_compatible_v2(
                   payload, payload_size, &decoded_grant, &decoded_request,
                   &version, &decoded_proof),
               MESH_MGMT_EXECUTION_WIRE_OK);
  check_uint_eq(version, MESH_MGMT_EXECUTION_COMMAND_VERSION_V2);
  check_uint_eq(decoded_proof.fencing_token, proof.fencing_token);
  check_uint_eq(decoded_proof.worker_generation, proof.worker_generation);
  check_uint_eq(decoded_proof.quorum_read_index, proof.quorum_read_index);
  check_uint_eq(decoded_proof.lease_expires_at_ms, proof.lease_expires_at_ms);
  check_mem_eq(decoded_request.command_id, request.command_id,
               sizeof(request.command_id));
  check_int_eq(mesh_mgmt_execution_command_request_decode_v1(
                   payload, payload_size, &decoded_grant, &decoded_request),
               MESH_MGMT_EXECUTION_WIRE_INVALID_SCHEMA);

  proof.quorum_read_index = proof.fencing_token - 1u;
  check_int_eq(mesh_mgmt_execution_command_request_encode_v2(
                   &grant, &request, &proof, payload, sizeof(payload),
                   &payload_size),
               MESH_MGMT_EXECUTION_WIRE_INVALID_ARG);
}

static void test_signed_result_round_trip(void) {
  mesh_mgmt_execution_result_v1_t result;
  mesh_mgmt_execution_result_v1_t decoded;
  uint8_t payload[MESH_MGMT_EXECUTION_COMMAND_RESULT_SIZE_V1];
  size_t payload_size = 0u;

  make_result(&result);
  check_int_eq(mesh_mgmt_execution_result_sign_v1(&result,
                                                  issuer_private_key),
               MESH_MGMT_EXECUTION_RESULT_OK);
  check_int_eq(mesh_mgmt_execution_command_result_encode_v1(
                   &result, payload, sizeof(payload), &payload_size),
               MESH_MGMT_EXECUTION_WIRE_OK);
  check_size_eq(payload_size, MESH_MGMT_EXECUTION_COMMAND_RESULT_SIZE_V1);
  check_int_eq(mesh_mgmt_execution_command_result_decode_v1(
                   payload, payload_size, &decoded),
               MESH_MGMT_EXECUTION_WIRE_OK);
  check_int_eq(mesh_mgmt_execution_result_verify_v1(
                   &decoded, result.signer_public_key),
               MESH_MGMT_EXECUTION_RESULT_OK);
  decoded.finished_at_ms++;
  check_int_eq(mesh_mgmt_execution_result_verify_v1(
                   &decoded, result.signer_public_key),
               MESH_MGMT_EXECUTION_RESULT_AUTH_FAILED);
}

static void test_shadow_validator_requires_feature_subject_and_issuer(void) {
  mesh_mgmt_execution_grant_v1_t grant;
  mesh_mgmt_execution_request_v1_t request;
  mesh_mgmt_dispatcher_v1_t dispatcher;
  uint8_t payload[MESH_MGMT_EXECUTION_COMMAND_REQUEST_MAX_SIZE_V1];
  size_t payload_size = 0u;

  make_grant(&grant);
  check_int_eq(mesh_mgmt_execution_grant_sign_v1(&grant, issuer_private_key),
               MESH_MGMT_EXECUTION_WIRE_OK);
  make_request(&grant, &request);
  check_int_eq(mesh_mgmt_execution_command_request_encode_v1(
                   &grant, &request, payload, sizeof(payload), &payload_size),
               MESH_MGMT_EXECUTION_WIRE_OK);

  memset(&dispatcher, 0, sizeof(dispatcher));
  dispatcher.enable_node_execution_shadow = 1u;
  memcpy(dispatcher.node_execution_grant_issuer_key, grant.issuer_key,
         sizeof(dispatcher.node_execution_grant_issuer_key));
  dispatcher.session.state = MESH_MGMT_SESSION_ESTABLISHED;
  dispatcher.session.negotiated.features =
      MESH_MGMT_FEATURE_TARGETED_RPC | MESH_MGMT_FEATURE_NODE_EXECUTION;
  memcpy(dispatcher.session.config.expected_mesh_id_hash, grant.mesh_id,
         sizeof(grant.mesh_id));
  memcpy(dispatcher.session.remote_certificate.management_key,
         grant.subject_principal, sizeof(grant.subject_principal));
  dispatcher.session.remote_certificate.roles = MESH_MGMT_ROLE_OPERATOR;

  check_int_eq(mesh_mgmt_dispatcher_validate_node_execution_shadow_v1(
                   &dispatcher, payload, payload_size, 200u),
               MESH_MGMT_DISPATCH_OK);
  dispatcher.session.negotiated.features &=
      ~MESH_MGMT_FEATURE_NODE_EXECUTION;
  check_int_eq(mesh_mgmt_dispatcher_validate_node_execution_shadow_v1(
                   &dispatcher, payload, payload_size, 200u),
               MESH_MGMT_DISPATCH_UNSUPPORTED_FEATURE);
  dispatcher.session.negotiated.features |=
      MESH_MGMT_FEATURE_NODE_EXECUTION;
  dispatcher.node_execution_grant_issuer_key[0] ^= 1u;
  check_int_eq(mesh_mgmt_dispatcher_validate_node_execution_shadow_v1(
                   &dispatcher, payload, payload_size, 200u),
               MESH_MGMT_DISPATCH_AUTH_FAILED);
  memcpy(dispatcher.node_execution_grant_issuer_key, grant.issuer_key,
         sizeof(dispatcher.node_execution_grant_issuer_key));
  dispatcher.session.remote_certificate.management_key[0] ^= 1u;
  check_int_eq(mesh_mgmt_dispatcher_validate_node_execution_shadow_v1(
                   &dispatcher, payload, payload_size, 200u),
               MESH_MGMT_DISPATCH_AUTH_FAILED);
  memcpy(dispatcher.session.remote_certificate.management_key,
         grant.subject_principal, sizeof(grant.subject_principal));
  check_int_eq(mesh_mgmt_dispatcher_validate_node_execution_shadow_v1(
                   &dispatcher, payload, payload_size, grant.expires_at_ms),
               MESH_MGMT_DISPATCH_EXPIRED);
}

static void test_outbound_shadow_binds_signed_origin_and_remote_target(void) {
  mesh_mgmt_execution_grant_v1_t grant;
  mesh_mgmt_execution_request_v1_t request;
  mesh_mgmt_dispatcher_v1_t dispatcher;
  mesh_mgmt_sign_input_v1_t input;
  mesh_mgmt_verified_envelope_v1_t verified;
  mesh_mgmt_execution_grant_v1_t decoded_grant;
  mesh_mgmt_execution_request_v1_t decoded_request;
  uint8_t payload[MESH_MGMT_EXECUTION_COMMAND_REQUEST_MAX_SIZE_V1];
  uint8_t frame[MESH_MGMT_FRAME_MAX];
  uint8_t subject_key[32];
  size_t payload_size = 0u;
  size_t frame_size = 0u;

  make_grant(&grant);
  check_int_eq(mesh_mgmt_ed25519_public_from_private(
                   issuer_private_key, subject_key),
               MESH_MGMT_CRYPTO_OK);
  memcpy(grant.subject_principal, subject_key, sizeof(subject_key));
  check_int_eq(mesh_mgmt_execution_grant_sign_v1(&grant, issuer_private_key),
               MESH_MGMT_EXECUTION_WIRE_OK);
  make_request(&grant, &request);
  check_int_eq(mesh_mgmt_execution_command_request_encode_v1(
                   &grant, &request, payload, sizeof(payload), &payload_size),
               MESH_MGMT_EXECUTION_WIRE_OK);

  memset(&input, 0, sizeof(input));
  input.minor = MESH_MGMT_MINOR_V1;
  input.kind = MESH_MGMT_KIND_COMMAND_REQUEST;
  input.private_key = issuer_private_key;
  input.payload = payload;
  input.payload_len = payload_size;
  memcpy(input.header.mesh_id_hash, grant.mesh_id, sizeof(grant.mesh_id));
  fill_bytes(input.header.origin_node_id,
             sizeof(input.header.origin_node_id), 18u);
  memcpy(input.header.target_node_id, grant.target_node_id,
         sizeof(grant.target_node_id));
  input.header.principal_epoch = 1u;
  input.header.incarnation = 1u;
  fill_bytes(input.header.session_id, sizeof(input.header.session_id), 19u);
  input.header.origin_sequence = 1u;
  fill_bytes(input.header.message_id, sizeof(input.header.message_id), 20u);
  input.header.issued_at_ms = 200u;
  input.header.expires_at_ms = 300u;
  input.header.certificate_serial = 1u;
  check_int_eq(mesh_mgmt_envelope_sign_v1(
                   &input, frame, sizeof(frame), &frame_size),
               MESH_MGMT_ENVELOPE_OK);
  check_int_eq(mesh_mgmt_envelope_verify_v1(
                   frame, frame_size, &verified),
               MESH_MGMT_ENVELOPE_OK);
  check_int_eq(mesh_mgmt_execution_command_request_decode_v1(
                   verified.frame.payload, verified.frame.payload_len,
                   &decoded_grant, &decoded_request),
               MESH_MGMT_EXECUTION_WIRE_OK);

  memset(&dispatcher, 0, sizeof(dispatcher));
  dispatcher.enable_node_execution_shadow = 1u;
  memcpy(dispatcher.node_execution_grant_issuer_key, grant.issuer_key,
         sizeof(dispatcher.node_execution_grant_issuer_key));
  dispatcher.session.state = MESH_MGMT_SESSION_ESTABLISHED;
  dispatcher.session.negotiated.features =
      MESH_MGMT_FEATURE_TARGETED_RPC | MESH_MGMT_FEATURE_NODE_EXECUTION;
  dispatcher.session.negotiated.max_frame = MESH_MGMT_FRAME_MAX;
  memcpy(dispatcher.session.config.expected_mesh_id_hash, grant.mesh_id,
         sizeof(grant.mesh_id));
  memcpy(dispatcher.session.remote_certificate.managed_node_id,
         grant.target_node_id, sizeof(grant.target_node_id));

  check_int_eq(
      mesh_mgmt_dispatcher_validate_node_execution_outbound_shadow_v1(
          &dispatcher, frame, frame_size),
      MESH_MGMT_DISPATCH_OK);
  dispatcher.session.remote_certificate.managed_node_id[0] ^= 1u;
  check_int_eq(
      mesh_mgmt_dispatcher_validate_node_execution_outbound_shadow_v1(
          &dispatcher, frame, frame_size),
      MESH_MGMT_DISPATCH_AUTH_FAILED);
  dispatcher.session.remote_certificate.managed_node_id[0] ^= 1u;
  frame[frame_size - 1u] ^= 1u;
  check_int_eq(
      mesh_mgmt_dispatcher_validate_node_execution_outbound_shadow_v1(
          &dispatcher, frame, frame_size),
      MESH_MGMT_DISPATCH_AUTH_FAILED);
}

spec("mesh management node execution wire E3") {
  describe("feature negotiation") {
    it("keeps generic targeted RPC separate from node execution") {
      test_feature_authorization_is_additive();
    }
  }
  describe("execution command payloads") {
    it("round trips a signed grant and canonical request") {
        test_signed_grant_and_request_round_trip();
    }
    it("round trips a V2 lease fencing proof and rejects it as V1") {
        test_v2_request_round_trips_lease_fencing_proof();
    }
    it("round trips a signed terminal result") {
      test_signed_result_round_trip();
    }
    it("shadow-validates feature, subject, issuer, and expiry") {
      test_shadow_validator_requires_feature_subject_and_issuer();
    }
    it("binds outbound signed origin and remote target") {
      test_outbound_shadow_binds_signed_origin_and_remote_target();
    }
  }
}
