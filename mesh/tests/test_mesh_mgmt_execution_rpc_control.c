#include "mesh_mgmt_crypto.h"
#include "mesh_mgmt_execution_rpc_control.h"

#include <tinytest.h>

#include <string.h>

#define TEST_NOW_MS 1000u
#define TEST_DEADLINE_MS 1500u
#define TEST_RETENTION_MS 500u

typedef struct {
  mesh_mgmt_execution_rpc_registry_v1_t registry;
  mesh_mgmt_execution_rpc_control_v1_t control;
  uint64_t now_ms;
  mesh_mgmt_execution_rpc_transport_result_t send_result;
  size_t send_count;
  uint8_t last_target[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  size_t last_payload_size;
} control_fixture_t;

static uint64_t fixture_clock(void *context) {
  return ((control_fixture_t *)context)->now_ms;
}

static mesh_mgmt_execution_rpc_transport_result_t
fixture_send(void *context,
             const uint8_t target_node_id[MESH_MGMT_EXECUTION_DIGEST_SIZE],
             const uint8_t *payload, size_t payload_size) {
  control_fixture_t *fixture = (control_fixture_t *)context;

  fixture->send_count++;
  memcpy(fixture->last_target, target_node_id, sizeof(fixture->last_target));
  fixture->last_payload_size = payload_size;
  check_not_null(payload);
  return fixture->send_result;
}

static void fill_bytes(uint8_t *bytes, size_t size, uint8_t value) {
  memset(bytes, value, size);
}

static size_t make_request(
    const uint8_t issuer_private_key[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    const uint8_t mesh_id[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    const uint8_t subject_key[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    const uint8_t target_node_id[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    uint8_t output[MESH_MGMT_EXECUTION_COMMAND_REQUEST_MAX_SIZE_V1]) {
  mesh_mgmt_execution_grant_v1_t grant;
  mesh_mgmt_execution_request_v1_t request;
  size_t output_size = 0u;

  memset(&grant, 0, sizeof(grant));
  memset(&request, 0, sizeof(request));
  grant.version = MESH_MGMT_EXECUTION_SCHEMA_V1;
  fill_bytes(grant.grant_id, sizeof(grant.grant_id), 0x11u);
  memcpy(grant.mesh_id, mesh_id, sizeof(grant.mesh_id));
  grant.policy_epoch = 1u;
  memcpy(grant.subject_principal, subject_key,
         sizeof(grant.subject_principal));
  memcpy(grant.target_node_id, target_node_id,
         sizeof(grant.target_node_id));
  fill_bytes(grant.deployment_id, sizeof(grant.deployment_id), 0x21u);
  grant.deployment_generation = 1u;
  fill_bytes(grant.package_digest, sizeof(grant.package_digest), 0x31u);
  grant.operation = MESH_MGMT_EXECUTION_OPERATION_RUN_PRESTAGED_WASM;
  grant.capabilities = MESH_MGMT_EXECUTION_CAP_CORE;
  grant.max_limits.module_bytes = 1024u;
  grant.max_limits.stack_bytes = 1024u;
  grant.max_limits.linear_memory_bytes = 4096u;
  grant.max_limits.timeout_ms = 100u;
  grant.max_limits.control_flow_steps = 1000u;
  grant.max_limits.host_calls = 4u;
  grant.max_limits.copied_guest_bytes = 1024u;
  grant.max_limits.input_bytes = 64u;
  grant.max_limits.stdout_bytes = 64u;
  grant.max_limits.stderr_bytes = 64u;
  grant.not_before_ms = TEST_NOW_MS - 1u;
  grant.expires_at_ms = TEST_DEADLINE_MS + 100u;
  check_int_eq(mesh_mgmt_execution_grant_sign_v1(
                   &grant, issuer_private_key),
               MESH_MGMT_EXECUTION_WIRE_OK);

  request.version = MESH_MGMT_EXECUTION_SCHEMA_V1;
  fill_bytes(request.command_id, sizeof(request.command_id), 0x41u);
  memcpy(request.grant_id, grant.grant_id, sizeof(request.grant_id));
  memcpy(request.target_node_id, grant.target_node_id,
         sizeof(request.target_node_id));
  memcpy(request.deployment_id, grant.deployment_id,
         sizeof(request.deployment_id));
  request.deployment_generation = grant.deployment_generation;
  memcpy(request.package_digest, grant.package_digest,
         sizeof(request.package_digest));
  request.input_kind = MESH_MGMT_EXECUTION_INPUT_INLINE;
  fill_bytes(request.input_digest, sizeof(request.input_digest), 0x51u);
  memcpy(request.inline_input, "input", 5u);
  request.inline_input_size = 5u;
  request.input_length = 5u;
  request.output_mode = MESH_MGMT_EXECUTION_OUTPUT_DIGEST;
  request.deadline_ms = TEST_DEADLINE_MS;
  fill_bytes(request.request_nonce, sizeof(request.request_nonce), 0x61u);
  fill_bytes(request.correlation_id, sizeof(request.correlation_id), 0x71u);
  check_int_eq(mesh_mgmt_execution_command_request_encode_v1(
                   &grant, &request, output,
                   MESH_MGMT_EXECUTION_COMMAND_REQUEST_MAX_SIZE_V1,
                   &output_size),
               MESH_MGMT_EXECUTION_WIRE_OK);
  return output_size;
}

static void init_fixture(
    control_fixture_t *fixture,
    const uint8_t expected_mesh_id[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    const uint8_t local_principal[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    const uint8_t issuer_public_key[MESH_MGMT_EXECUTION_DIGEST_SIZE]) {
  mesh_mgmt_execution_rpc_control_config_v1_t config;

  memset(fixture, 0, sizeof(*fixture));
  fixture->now_ms = TEST_NOW_MS;
  fixture->send_result = MESH_MGMT_EXECUTION_RPC_TRANSPORT_SENT;
  check_int_eq(mesh_mgmt_execution_rpc_registry_init_v1(
                   &fixture->registry, 1u, TEST_RETENTION_MS),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  memset(&config, 0, sizeof(config));
  config.registry = &fixture->registry;
  memcpy(config.expected_mesh_id, expected_mesh_id,
         sizeof(config.expected_mesh_id));
  memcpy(config.local_principal_key, local_principal,
         sizeof(config.local_principal_key));
  memcpy(config.expected_grant_issuer_key, issuer_public_key,
         sizeof(config.expected_grant_issuer_key));
  config.clock_now_ms = fixture_clock;
  config.clock_context = fixture;
  config.send = fixture_send;
  config.send_context = fixture;
  check_int_eq(mesh_mgmt_execution_rpc_control_init_v1(
                   &fixture->control, &config),
               MESH_MGMT_EXECUTION_RPC_CONTROL_OK);
}

static void make_keys(uint8_t issuer_private_key[32],
                      uint8_t issuer_public_key[32],
                      uint8_t subject_public_key[32]) {
  uint8_t subject_private_key[32];

  fill_bytes(issuer_private_key, 32u, 0x81u);
  fill_bytes(subject_private_key, 32u, 0x91u);
  check_int_eq(mesh_mgmt_ed25519_public_from_private(
                   issuer_private_key, issuer_public_key),
               MESH_MGMT_CRYPTO_OK);
  check_int_eq(mesh_mgmt_ed25519_public_from_private(
                   subject_private_key, subject_public_key),
               MESH_MGMT_CRYPTO_OK);
}

static void test_submit_is_bound_and_idempotent(void) {
  control_fixture_t fixture;
  mesh_mgmt_execution_rpc_binding_v1_t binding;
  mesh_mgmt_execution_rpc_binding_v1_t duplicate_binding;
  mesh_mgmt_execution_rpc_completion_v1_t completion;
  mesh_mgmt_execution_response_v1_t response;
  uint8_t issuer_private[32];
  uint8_t issuer_public[32];
  uint8_t subject_public[32];
  uint8_t mesh_id[32];
  uint8_t target_node_id[32];
  uint8_t payload[MESH_MGMT_EXECUTION_COMMAND_REQUEST_MAX_SIZE_V1];
  size_t payload_size;

  make_keys(issuer_private, issuer_public, subject_public);
  fill_bytes(mesh_id, sizeof(mesh_id), 0x42u);
  fill_bytes(target_node_id, sizeof(target_node_id), 0x52u);
  payload_size = make_request(issuer_private, mesh_id, subject_public,
                              target_node_id, payload);
  init_fixture(&fixture, mesh_id, subject_public, issuer_public);

  check_int_eq(mesh_mgmt_execution_rpc_control_submit_v1(
                   &fixture.control, payload, payload_size, &binding),
               MESH_MGMT_EXECUTION_RPC_CONTROL_OK);
  check_int_eq(fixture.send_count, 1u);
  check_int_eq(fixture.last_payload_size, payload_size);
  check_int_eq(memcmp(fixture.last_target, target_node_id,
                      sizeof(target_node_id)),
               0);
  check_int_eq(mesh_mgmt_execution_rpc_control_submit_v1(
                   &fixture.control, payload, payload_size,
                   &duplicate_binding),
               MESH_MGMT_EXECUTION_RPC_CONTROL_ALREADY_EXISTS);
  check_int_eq(fixture.send_count, 1u);
  check_int_eq(mesh_mgmt_execution_rpc_control_get_v1(
                   &fixture.control, binding.correlation_id, &completion),
               MESH_MGMT_EXECUTION_RPC_CONTROL_OK);
  check_int_eq(completion.state, MESH_MGMT_EXECUTION_RPC_PENDING);

  memset(&response, 0, sizeof(response));
  response.kind = MESH_MGMT_KIND_COMMAND_STATUS;
  response.status.version = MESH_MGMT_EXECUTION_SCHEMA_V1;
  response.status.code = MESH_MGMT_EXECUTION_STATUS_BUSY;
  memcpy(response.status.command_id, binding.command_id,
         sizeof(response.status.command_id));
  memcpy(response.status.correlation_id, binding.correlation_id,
         sizeof(response.status.correlation_id));
  memcpy(response.status.request_digest, binding.request_digest,
         sizeof(response.status.request_digest));
  memcpy(response.status.responder_node_id, binding.target_node_id,
         sizeof(response.status.responder_node_id));
  check_int_eq(mesh_mgmt_execution_rpc_control_complete_v1(
                   &fixture.control, &response),
               MESH_MGMT_EXECUTION_RPC_CONTROL_OK);
  check_int_eq(mesh_mgmt_execution_rpc_control_get_v1(
                   &fixture.control, binding.correlation_id, &completion),
               MESH_MGMT_EXECUTION_RPC_CONTROL_OK);
  check_int_eq(completion.state, MESH_MGMT_EXECUTION_RPC_STATUS);
  mesh_mgmt_execution_rpc_registry_destroy_v1(&fixture.registry);
}

static void test_authority_and_scope_fail_before_send(void) {
  control_fixture_t fixture;
  mesh_mgmt_execution_rpc_binding_v1_t binding;
  uint8_t issuer_private[32];
  uint8_t issuer_public[32];
  uint8_t wrong_issuer_public[32];
  uint8_t subject_public[32];
  uint8_t mesh_id[32];
  uint8_t wrong_mesh_id[32];
  uint8_t target_node_id[32];
  uint8_t payload[MESH_MGMT_EXECUTION_COMMAND_REQUEST_MAX_SIZE_V1];
  size_t payload_size;

  make_keys(issuer_private, issuer_public, subject_public);
  fill_bytes(mesh_id, sizeof(mesh_id), 0x42u);
  fill_bytes(wrong_mesh_id, sizeof(wrong_mesh_id), 0x43u);
  fill_bytes(target_node_id, sizeof(target_node_id), 0x52u);
  fill_bytes(wrong_issuer_public, sizeof(wrong_issuer_public), 0xa1u);
  payload_size = make_request(issuer_private, mesh_id, subject_public,
                              target_node_id, payload);

  init_fixture(&fixture, wrong_mesh_id, subject_public, issuer_public);
  check_int_eq(mesh_mgmt_execution_rpc_control_submit_v1(
                   &fixture.control, payload, payload_size, &binding),
               MESH_MGMT_EXECUTION_RPC_CONTROL_SCOPE_MISMATCH);
  check_int_eq(fixture.send_count, 0u);
  mesh_mgmt_execution_rpc_registry_destroy_v1(&fixture.registry);

  init_fixture(&fixture, mesh_id, subject_public, wrong_issuer_public);
  check_int_eq(mesh_mgmt_execution_rpc_control_submit_v1(
                   &fixture.control, payload, payload_size, &binding),
               MESH_MGMT_EXECUTION_RPC_CONTROL_AUTH_FAILED);
  check_int_eq(fixture.send_count, 0u);
  mesh_mgmt_execution_rpc_registry_destroy_v1(&fixture.registry);
}

static void test_send_failure_preserves_only_ambiguous_work(void) {
  control_fixture_t fixture;
  mesh_mgmt_execution_rpc_binding_v1_t binding;
  mesh_mgmt_execution_rpc_completion_v1_t completion;
  uint8_t issuer_private[32];
  uint8_t issuer_public[32];
  uint8_t subject_public[32];
  uint8_t mesh_id[32];
  uint8_t target_node_id[32];
  uint8_t payload[MESH_MGMT_EXECUTION_COMMAND_REQUEST_MAX_SIZE_V1];
  size_t payload_size;

  make_keys(issuer_private, issuer_public, subject_public);
  fill_bytes(mesh_id, sizeof(mesh_id), 0x42u);
  fill_bytes(target_node_id, sizeof(target_node_id), 0x52u);
  payload_size = make_request(issuer_private, mesh_id, subject_public,
                              target_node_id, payload);
  init_fixture(&fixture, mesh_id, subject_public, issuer_public);

  fixture.send_result = MESH_MGMT_EXECUTION_RPC_TRANSPORT_UNAVAILABLE;
  check_int_eq(mesh_mgmt_execution_rpc_control_submit_v1(
                   &fixture.control, payload, payload_size, &binding),
               MESH_MGMT_EXECUTION_RPC_CONTROL_SEND_UNAVAILABLE);
  check_int_eq(mesh_mgmt_execution_rpc_control_get_v1(
                   &fixture.control, binding.correlation_id, &completion),
               MESH_MGMT_EXECUTION_RPC_CONTROL_NOT_FOUND);

  fixture.send_result = MESH_MGMT_EXECUTION_RPC_TRANSPORT_AMBIGUOUS;
  check_int_eq(mesh_mgmt_execution_rpc_control_submit_v1(
                   &fixture.control, payload, payload_size, &binding),
               MESH_MGMT_EXECUTION_RPC_CONTROL_SEND_AMBIGUOUS);
  check_int_eq(mesh_mgmt_execution_rpc_control_get_v1(
                   &fixture.control, binding.correlation_id, &completion),
               MESH_MGMT_EXECUTION_RPC_CONTROL_OK);
  check_int_eq(completion.state, MESH_MGMT_EXECUTION_RPC_PENDING);
  check_int_eq(fixture.send_count, 2u);
  mesh_mgmt_execution_rpc_registry_destroy_v1(&fixture.registry);
}

spec("mesh management execution RPC control E10b") {
  describe("submission coordination") {
    it("binds, sends, queries, completes, and deduplicates") {
      test_submit_is_bound_and_idempotent();
    }
    it("rejects untrusted authority and cross-mesh scope") {
      test_authority_and_scope_fail_before_send();
    }
    it("abandons definitive failures but retains ambiguous sends") {
      test_send_failure_preserves_only_ambiguous_work();
    }
  }
}
