#include "mesh_mgmt_execution_runner.h"
#include "tinytest.h"

#include <string.h>

static void fill_bytes(uint8_t *bytes, size_t size, uint8_t value) {
  memset(bytes, value, size);
}

static void make_request(mesh_mgmt_execution_request_v1_t *request,
                         const uint8_t deployment_id[MESH_MGMT_EXECUTION_ID_SIZE],
                         const uint8_t digest[MESH_MGMT_EXECUTION_DIGEST_SIZE]) {
  memset(request, 0, sizeof(*request));
  request->version = MESH_MGMT_EXECUTION_SCHEMA_V1;
  fill_bytes(request->command_id, sizeof(request->command_id), 1u);
  fill_bytes(request->grant_id, sizeof(request->grant_id), 2u);
  fill_bytes(request->target_node_id, sizeof(request->target_node_id), 3u);
  memcpy(request->deployment_id, deployment_id,
         MESH_MGMT_EXECUTION_ID_SIZE);
  request->deployment_generation = 1u;
  memcpy(request->package_digest, digest,
         MESH_MGMT_EXECUTION_DIGEST_SIZE);
  request->input_kind = MESH_MGMT_EXECUTION_INPUT_NONE;
  request->output_mode = MESH_MGMT_EXECUTION_OUTPUT_DIGEST;
  request->deadline_ms = 2000u;
  fill_bytes(request->request_nonce, sizeof(request->request_nonce), 4u);
  fill_bytes(request->correlation_id, sizeof(request->correlation_id), 5u);
}

static void make_policy(
    mesh_mgmt_execution_effective_policy_v1_t *policy) {
  memset(policy, 0, sizeof(*policy));
  policy->capabilities = MESH_MGMT_EXECUTION_CAP_CORE |
                         MESH_MGMT_EXECUTION_CAP_UTILS |
                         MESH_MGMT_EXECUTION_CAP_APP;
  policy->limits.module_bytes = 1024u * 1024u;
  policy->limits.stack_bytes = 64u * 1024u;
  policy->limits.linear_memory_bytes = 256u * 1024u;
  policy->limits.timeout_ms = 1000u;
  policy->limits.control_flow_steps = 1000000u;
  policy->limits.host_calls = 64u;
  policy->limits.copied_guest_bytes = 64u * 1024u;
  policy->limits.input_bytes = MESH_MGMT_EXECUTION_INLINE_INPUT_MAX;
  policy->limits.stdout_bytes = 64u * 1024u;
  policy->limits.stderr_bytes = 64u * 1024u;
}

static void test_registry_and_digest_binding(void) {
  mesh_mgmt_execution_runner_v1_t runner;
  mesh_mgmt_execution_deployment_v1_t deployment;
  uint8_t digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint8_t other_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];

  check_int_eq(mesh_mgmt_execution_runner_module_digest_v1(
                   MESH_TEST_EXECUTION_WASM, 1024u * 1024u, digest, NULL),
               MESH_MGMT_EXECUTION_RUNNER_OK);
  memset(&deployment, 0, sizeof(deployment));
  fill_bytes(deployment.deployment_id, sizeof(deployment.deployment_id), 9u);
  deployment.generation = 1u;
  memcpy(deployment.module_digest, digest, sizeof(digest));
  deployment.module_path = MESH_TEST_EXECUTION_WASM;

  check_int_eq(mesh_mgmt_execution_runner_init_v1(&runner, 2u),
               MESH_MGMT_EXECUTION_RUNNER_OK);
  check_int_eq(mesh_mgmt_execution_runner_register_v1(&runner, &deployment),
               MESH_MGMT_EXECUTION_RUNNER_OK);
  check_int_eq(mesh_mgmt_execution_runner_register_v1(&runner, &deployment),
               MESH_MGMT_EXECUTION_RUNNER_OK);
  memcpy(other_digest, digest, sizeof(digest));
  other_digest[0] ^= 0xffu;
  memcpy(deployment.module_digest, other_digest, sizeof(other_digest));
  check_int_eq(mesh_mgmt_execution_runner_register_v1(&runner, &deployment),
               MESH_MGMT_EXECUTION_RUNNER_CONFLICT);
  mesh_mgmt_execution_runner_destroy_v1(&runner);
}

static void test_runs_only_the_registered_digest(void) {
  mesh_mgmt_execution_runner_v1_t runner;
  mesh_mgmt_execution_deployment_v1_t deployment;
  mesh_mgmt_execution_request_v1_t request;
  mesh_mgmt_execution_effective_policy_v1_t policy;
  mesh_mgmt_execution_runner_output_v1_t output;
  uint8_t digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];

  check_int_eq(mesh_mgmt_execution_runner_module_digest_v1(
                   MESH_TEST_EXECUTION_WASM, 1024u * 1024u, digest, NULL),
               MESH_MGMT_EXECUTION_RUNNER_OK);
  memset(&deployment, 0, sizeof(deployment));
  fill_bytes(deployment.deployment_id, sizeof(deployment.deployment_id), 8u);
  deployment.generation = 1u;
  memcpy(deployment.module_digest, digest, sizeof(digest));
  deployment.module_path = MESH_TEST_EXECUTION_WASM;
  make_request(&request, deployment.deployment_id, digest);
  make_policy(&policy);

  check_int_eq(mesh_mgmt_execution_runner_init_v1(&runner, 1u),
               MESH_MGMT_EXECUTION_RUNNER_OK);
  check_int_eq(mesh_mgmt_execution_runner_register_v1(&runner, &deployment),
               MESH_MGMT_EXECUTION_RUNNER_OK);
  request.package_digest[0] ^= 0xffu;
  check_int_eq(mesh_mgmt_execution_runner_run_v1(
                   &runner, &request, &policy, 1000u, NULL, &output),
               MESH_MGMT_EXECUTION_RUNNER_DIGEST_MISMATCH);
  request.package_digest[0] ^= 0xffu;
  check_int_eq(mesh_mgmt_execution_runner_run_v1(
                   &runner, &request, &policy, 1000u, NULL, &output),
               MESH_MGMT_EXECUTION_RUNNER_OK);
  check_int_eq(output.runtime_code, 0);
  check_int_eq(output.guest_exit_code, 7);
  check_uint_eq(output.invocations, 1u);
  mesh_mgmt_execution_runner_destroy_v1(&runner);
}

static void test_rejects_capability_semantic_drift(void) {
  mesh_mgmt_execution_runner_v1_t runner;
  mesh_mgmt_execution_request_v1_t request;
  mesh_mgmt_execution_effective_policy_v1_t policy;
  mesh_mgmt_execution_runner_output_v1_t output;
  uint8_t deployment_id[MESH_MGMT_EXECUTION_ID_SIZE];
  uint8_t digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];

  fill_bytes(deployment_id, sizeof(deployment_id), 7u);
  fill_bytes(digest, sizeof(digest), 6u);
  make_request(&request, deployment_id, digest);
  make_policy(&policy);
  policy.capabilities |= MESH_MGMT_EXECUTION_CAP_HTTP;
  check_int_eq(mesh_mgmt_execution_runner_init_v1(&runner, 1u),
               MESH_MGMT_EXECUTION_RUNNER_OK);
  check_int_eq(mesh_mgmt_execution_runner_run_v1(
                   &runner, &request, &policy, 1000u, NULL, &output),
               MESH_MGMT_EXECUTION_RUNNER_POLICY_DENIED);
  mesh_mgmt_execution_runner_destroy_v1(&runner);
}

spec("mesh management local node execution runner E1") {
  describe("prestaged deployment registry") {
    it("is idempotent and rejects digest rebinding") {
      test_registry_and_digest_binding();
    }
  }
  describe("TurboRuntime execution") {
    it("runs only the registered generation and digest") {
      test_runs_only_the_registered_digest();
    }
    it("rejects capabilities outside the raw Wasm profile") {
      test_rejects_capability_semantic_drift();
    }
  }
}
