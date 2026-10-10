#include "mesh_mgmt_execution_rpc_registry.h"
#include "mesh_mgmt_crypto.h"

#include <tinytest.h>

#include <string.h>

#define TEST_NOW_MS 1000u
#define TEST_DEADLINE_MS 2000u
#define TEST_RETENTION_MS 500u

/* Deterministic public test signer, never a product or user credential. */
static const uint8_t TEST_RESULT_PRIVATE[32] = {
    1u, 3u, 5u, 7u, 9u, 11u, 13u, 15u,
    17u, 19u, 21u, 23u, 25u, 27u, 29u, 31u,
    2u, 4u, 6u, 8u, 10u, 12u, 14u, 16u,
    18u, 20u, 22u, 24u, 26u, 28u, 30u, 32u
};

static void fill_bytes(uint8_t *bytes, size_t size, uint8_t first) {
  size_t index;

  for (index = 0u; index < size; ++index)
    bytes[index] = (uint8_t)(first + index);
}

static void make_binding(mesh_mgmt_execution_rpc_binding_v1_t *binding,
                         uint8_t first) {
  memset(binding, 0, sizeof(*binding));
  fill_bytes(binding->command_id, sizeof(binding->command_id), first);
  fill_bytes(binding->correlation_id, sizeof(binding->correlation_id),
             (uint8_t)(first + 0x10u));
  fill_bytes(binding->request_digest, sizeof(binding->request_digest),
             (uint8_t)(first + 0x20u));
  fill_bytes(binding->target_node_id, sizeof(binding->target_node_id),
             (uint8_t)(first + 0x40u));
  check_equal(mesh_mgmt_ed25519_public_from_private(
      TEST_RESULT_PRIVATE, binding->result_signer_public_key),
      MESH_MGMT_CRYPTO_OK);
  binding->deadline_ms = TEST_DEADLINE_MS;
}

static void make_result_response(
    const mesh_mgmt_execution_rpc_binding_v1_t *binding,
    mesh_mgmt_execution_response_v1_t *response) {
  memset(response, 0, sizeof(*response));
  response->kind = MESH_MGMT_KIND_COMMAND_RESULT;
  memcpy(response->result.command_id, binding->command_id,
         sizeof(response->result.command_id));
  memcpy(response->result.correlation_id, binding->correlation_id,
         sizeof(response->result.correlation_id));
  memcpy(response->result.request_digest, binding->request_digest,
         sizeof(response->result.request_digest));
  memcpy(response->result.target_node_id, binding->target_node_id,
         sizeof(response->result.target_node_id));
  response->result.version = MESH_MGMT_EXECUTION_RESULT_VERSION_V1;
  fill_bytes(response->result.deployment_id,
             sizeof(response->result.deployment_id), 0x31u);
  response->result.deployment_generation = 1u;
  fill_bytes(response->result.package_digest,
             sizeof(response->result.package_digest), 0x42u);
  response->result.policy_epoch = 1u;
  fill_bytes(response->result.grant_id, sizeof(response->result.grant_id), 0x51u);
  response->result.state = MESH_MGMT_EXECUTION_STATE_FAILED;
  response->result.runtime_stage = 7;
  response->result.guest_exit_code = 7;
  response->result.usage.invocations = 1u;
  fill_bytes(response->result.stdout_digest,
             sizeof(response->result.stdout_digest), 0x61u);
  fill_bytes(response->result.stderr_digest,
             sizeof(response->result.stderr_digest), 0x71u);
  response->result.started_at_ms = TEST_NOW_MS;
  response->result.finished_at_ms = TEST_NOW_MS + 1u;
  response->result.worker_generation = 1u;
  check_equal(mesh_mgmt_execution_result_sign_v1(
      &response->result, TEST_RESULT_PRIVATE),
      MESH_MGMT_EXECUTION_RESULT_OK);
}

static void make_status_response(
    const mesh_mgmt_execution_rpc_binding_v1_t *binding,
    mesh_mgmt_execution_response_v1_t *response) {
  memset(response, 0, sizeof(*response));
  response->kind = MESH_MGMT_KIND_COMMAND_STATUS;
  response->status.version = MESH_MGMT_EXECUTION_SCHEMA_V1;
  response->status.code = MESH_MGMT_EXECUTION_STATUS_BUSY;
  memcpy(response->status.command_id, binding->command_id,
         sizeof(response->status.command_id));
  memcpy(response->status.correlation_id, binding->correlation_id,
         sizeof(response->status.correlation_id));
  memcpy(response->status.request_digest, binding->request_digest,
         sizeof(response->status.request_digest));
  memcpy(response->status.responder_node_id, binding->target_node_id,
         sizeof(response->status.responder_node_id));
}

static void test_registry_commits_an_exact_result_once(void) {
  mesh_mgmt_execution_rpc_registry_v1_t registry = {0};
  mesh_mgmt_execution_rpc_binding_v1_t binding;
  mesh_mgmt_execution_rpc_completion_v1_t completion;
  mesh_mgmt_execution_response_v1_t response;

  make_binding(&binding, 0x11u);
  make_result_response(&binding, &response);
  check_equal(mesh_mgmt_execution_rpc_registry_init_v1(
                   &registry, 2u, TEST_RETENTION_MS),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  check_equal(mesh_mgmt_execution_rpc_registry_register_v1(
                   &registry, &binding, TEST_NOW_MS),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  check_equal(mesh_mgmt_execution_rpc_registry_get_v1(
                   &registry, binding.correlation_id, TEST_NOW_MS,
                   &completion),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  check_equal(completion.state, MESH_MGMT_EXECUTION_RPC_PENDING);
  check_equal(mesh_mgmt_execution_rpc_registry_release_v1(
                   &registry, binding.correlation_id),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_NOT_READY);
  check_equal(mesh_mgmt_execution_rpc_registry_complete_v1(
                   &registry, &response, 1200u),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  check_equal(mesh_mgmt_execution_rpc_registry_complete_v1(
                   &registry, &response, 1201u),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_ALREADY_COMPLETE);
  check_equal(mesh_mgmt_execution_rpc_registry_get_v1(
                   &registry, binding.correlation_id, 1201u, &completion),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  check_equal(completion.state, MESH_MGMT_EXECUTION_RPC_RESULT);
  check_equal(completion.response.result.request_digest,
               binding.request_digest, sizeof(binding.request_digest));
  check_equal(mesh_mgmt_execution_rpc_registry_release_v1(
                   &registry, binding.correlation_id),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  check_equal(mesh_mgmt_execution_rpc_registry_get_v1(
                   &registry, binding.correlation_id, 1202u, &completion),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_NOT_FOUND);
  mesh_mgmt_execution_rpc_registry_destroy_v1(&registry);
}

/* An envelope-valid payload with its OWN internally valid signature must
 * still be denied if it is not the signer chosen at request admission.
 * A tampered previously signed result must also leave PENDING untouched. */
static void test_registry_requires_pinned_result_signer(void) {
  mesh_mgmt_execution_rpc_registry_v1_t registry = {0};
  mesh_mgmt_execution_rpc_binding_v1_t binding;
  mesh_mgmt_execution_rpc_completion_v1_t snapshot = {0};
  mesh_mgmt_execution_response_v1_t response;
  uint8_t rogue_private[32];
  make_binding(&binding, 0x51u);
  make_result_response(&binding, &response);
  check_equal(mesh_mgmt_execution_rpc_registry_init_v1(
      &registry, 2u, TEST_RETENTION_MS),
      MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  check_equal(mesh_mgmt_execution_rpc_registry_register_v1(
      &registry, &binding, TEST_NOW_MS),
      MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);

  fill_bytes(rogue_private, sizeof(rogue_private), 0x83u);
  check_equal(mesh_mgmt_execution_result_sign_v1(
      &response.result, rogue_private), MESH_MGMT_EXECUTION_RESULT_OK);
  check_equal(mesh_mgmt_execution_result_verify_v1(
      &response.result, response.result.signer_public_key),
      MESH_MGMT_EXECUTION_RESULT_OK); /* valid cryptographically, rogue */
  check_equal(mesh_mgmt_execution_rpc_registry_complete_v1(
      &registry, &response, TEST_NOW_MS + 1u),
      MESH_MGMT_EXECUTION_RPC_REGISTRY_AUTH_FAILED);
  check_equal(mesh_mgmt_execution_rpc_registry_get_v1(
      &registry, binding.correlation_id, TEST_NOW_MS + 1u, &snapshot),
      MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  check_equal(snapshot.state, MESH_MGMT_EXECUTION_RPC_PENDING);

  make_result_response(&binding, &response);
  response.result.request_digest[0] ^= 1u;
  check_equal(mesh_mgmt_execution_rpc_registry_complete_v1(
      &registry, &response, TEST_NOW_MS + 1u),
      MESH_MGMT_EXECUTION_RPC_REGISTRY_AUTH_FAILED);
  response.result.request_digest[0] ^= 1u;
  response.result.signature[0] ^= 1u;
  check_equal(mesh_mgmt_execution_rpc_registry_complete_v1(
      &registry, &response, TEST_NOW_MS + 1u),
      MESH_MGMT_EXECUTION_RPC_REGISTRY_AUTH_FAILED);
  make_result_response(&binding, &response);
  check_equal(mesh_mgmt_execution_rpc_registry_complete_v1(
      &registry, &response, TEST_NOW_MS + 1u),
      MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  check_equal(mesh_mgmt_execution_rpc_registry_get_v1(
      &registry, binding.correlation_id, TEST_NOW_MS + 2u, &snapshot),
      MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  check_equal(snapshot.state, MESH_MGMT_EXECUTION_RPC_RESULT);
  mesh_mgmt_execution_rpc_registry_destroy_v1(&registry);
}

static void test_registry_preserves_retryable_status(void) {
  mesh_mgmt_execution_rpc_registry_v1_t registry = {0};
  mesh_mgmt_execution_rpc_binding_v1_t binding;
  mesh_mgmt_execution_rpc_completion_v1_t completion;
  mesh_mgmt_execution_response_v1_t response;

  make_binding(&binding, 0x21u);
  make_status_response(&binding, &response);
  check_equal(mesh_mgmt_execution_rpc_registry_init_v1(
                   &registry, 1u, TEST_RETENTION_MS),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  check_equal(mesh_mgmt_execution_rpc_registry_register_v1(
                   &registry, &binding, TEST_NOW_MS),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  check_equal(mesh_mgmt_execution_rpc_registry_complete_v1(
                   &registry, &response, 1100u),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  check_equal(mesh_mgmt_execution_rpc_registry_get_v1(
                   &registry, binding.correlation_id, 1100u, &completion),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  check_equal(completion.state, MESH_MGMT_EXECUTION_RPC_STATUS);
  check_equal(completion.response.status.code,
               MESH_MGMT_EXECUTION_STATUS_BUSY);
  check_true(mesh_mgmt_execution_status_is_retryable_v1(
      completion.response.status.code));
  mesh_mgmt_execution_rpc_registry_destroy_v1(&registry);
}

static void test_registry_rejects_mismatched_response_bindings(void) {
  mesh_mgmt_execution_rpc_registry_v1_t registry = {0};
  mesh_mgmt_execution_rpc_binding_v1_t binding;
  mesh_mgmt_execution_rpc_completion_v1_t completion;
  mesh_mgmt_execution_response_v1_t response;

  make_binding(&binding, 0x31u);
  make_result_response(&binding, &response);
  check_equal(mesh_mgmt_execution_rpc_registry_init_v1(
                   &registry, 1u, TEST_RETENTION_MS),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  check_equal(mesh_mgmt_execution_rpc_registry_register_v1(
                   &registry, &binding, TEST_NOW_MS),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  response.result.target_node_id[0] ^= 1u;
  check_equal(mesh_mgmt_execution_rpc_registry_complete_v1(
                   &registry, &response, 1100u),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_AUTH_FAILED);
  check_equal(mesh_mgmt_execution_rpc_registry_get_v1(
                   &registry, binding.correlation_id, 1100u, &completion),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  check_equal(completion.state, MESH_MGMT_EXECUTION_RPC_PENDING);
  mesh_mgmt_execution_rpc_registry_destroy_v1(&registry);
}

static void test_registry_bounds_identity_and_retention(void) {
  mesh_mgmt_execution_rpc_registry_v1_t registry = {0};
  mesh_mgmt_execution_rpc_binding_v1_t first;
  mesh_mgmt_execution_rpc_binding_v1_t second;
  mesh_mgmt_execution_rpc_binding_v1_t conflict;
  mesh_mgmt_execution_rpc_completion_v1_t completion;

  make_binding(&first, 0x41u);
  make_binding(&second, 0x71u);
  conflict = first;
  conflict.request_digest[0] ^= 1u;
  check_equal(mesh_mgmt_execution_rpc_registry_init_v1(
                   &registry, 1u, TEST_RETENTION_MS),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  check_equal(mesh_mgmt_execution_rpc_registry_register_v1(
                   &registry, &first, TEST_NOW_MS),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  check_equal(mesh_mgmt_execution_rpc_registry_register_v1(
                   &registry, &first, TEST_NOW_MS),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_ALREADY_EXISTS);
  check_equal(mesh_mgmt_execution_rpc_registry_register_v1(
                   &registry, &conflict, TEST_NOW_MS),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_CONFLICT);
  conflict = first;
  conflict.result_signer_public_key[0] ^= 1u;
  check_equal(mesh_mgmt_execution_rpc_registry_register_v1(
                   &registry, &conflict, TEST_NOW_MS),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_CONFLICT);
  check_equal(mesh_mgmt_execution_rpc_registry_register_v1(
                   &registry, &second, TEST_NOW_MS),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_RESOURCE_EXHAUSTED);
  check_equal(mesh_mgmt_execution_rpc_registry_get_v1(
                   &registry, first.correlation_id, TEST_DEADLINE_MS,
                   &completion),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  check_equal(completion.state, MESH_MGMT_EXECUTION_RPC_TIMED_OUT);
  check_equal(mesh_mgmt_execution_rpc_registry_sweep_v1(
                    &registry, TEST_DEADLINE_MS + TEST_RETENTION_MS),
                1u);
  check_equal(mesh_mgmt_execution_rpc_registry_get_v1(
                   &registry, first.correlation_id,
                   TEST_DEADLINE_MS + TEST_RETENTION_MS, &completion),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_NOT_FOUND);
  check_equal(mesh_mgmt_execution_rpc_registry_register_v1(
                   &registry, &second,
                   TEST_DEADLINE_MS + TEST_RETENTION_MS),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_INVALID_ARG);
  second.deadline_ms = TEST_DEADLINE_MS + TEST_RETENTION_MS + 1000u;
  check_equal(mesh_mgmt_execution_rpc_registry_register_v1(
                   &registry, &second,
                   TEST_DEADLINE_MS + TEST_RETENTION_MS),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  mesh_mgmt_execution_rpc_registry_destroy_v1(&registry);
}

spec("mesh management execution RPC registry E9") {
  describe("bounded correlation state") {
    it("commits an exactly bound result only once") {
      test_registry_commits_an_exact_result_once();
    }
    it("rejects self-signed untrusted results and tampered signatures") {
      test_registry_requires_pinned_result_signer();
    }
    it("preserves a retryable status response") {
      test_registry_preserves_retryable_status();
    }
    it("rejects a mismatched responder binding") {
      test_registry_rejects_mismatched_response_bindings();
    }
    it("bounds identity reuse, capacity, timeout, and retention") {
      test_registry_bounds_identity_and_retention();
    }
  }
}
