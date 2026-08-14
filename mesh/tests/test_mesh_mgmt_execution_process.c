#include "mesh_mgmt_execution_process.h"
#include "tinytest.h"

#include <string.h>

static void make_limits(mesh_mgmt_execution_limits_v1_t *limits) {
  memset(limits, 0, sizeof(*limits));
  limits->module_bytes = 1024u * 1024u;
  limits->stack_bytes = 64u * 1024u;
  limits->linear_memory_bytes = 256u * 1024u;
  limits->timeout_ms = 5000u;
  limits->control_flow_steps = 1000000u;
  limits->host_calls = 64u;
  limits->copied_guest_bytes = 64u * 1024u;
  limits->input_bytes = MESH_MGMT_EXECUTION_INLINE_INPUT_MAX;
  limits->stdout_bytes = 64u * 1024u;
  limits->stderr_bytes = 64u * 1024u;
}

static void test_wasm_vm_runs_in_authenticated_child(void) {
  mesh_mgmt_execution_runner_v1_t runner;
  mesh_mgmt_execution_deployment_v1_t deployment;
  mesh_mgmt_execution_request_v1_t request;
  mesh_mgmt_execution_effective_policy_v1_t policy;
  mesh_mgmt_execution_runner_output_v1_t output;
  mesh_mgmt_execution_process_config_v1_t config;
  mesh_mgmt_execution_process_v1_t process = {0};
  uint8_t worker_digest[32];
  memset(&deployment, 0, sizeof(deployment));
  memset(&request, 0, sizeof(request));
  memset(&policy, 0, sizeof(policy));
  memset(&config, 0, sizeof(config));
  memset(deployment.deployment_id, 0x44, sizeof(deployment.deployment_id));
  deployment.generation = 1u;
  deployment.module_path = MESH_TEST_EXECUTION_WASM;
  check_int_eq(mesh_mgmt_execution_runner_module_digest_v1(
                   deployment.module_path, 1024u * 1024u,
                   deployment.module_digest, NULL),
               MESH_MGMT_EXECUTION_RUNNER_OK);
  check_int_eq(mesh_mgmt_execution_runner_module_digest_v1(
                   MESH_TEST_EXECUTION_WORKER, 64u * 1024u * 1024u,
                   worker_digest, NULL),
               MESH_MGMT_EXECUTION_RUNNER_OK);
  check_int_eq(mesh_mgmt_execution_runner_init_v1(&runner, 1u),
               MESH_MGMT_EXECUTION_RUNNER_OK);
  check_int_eq(mesh_mgmt_execution_runner_register_v1(&runner, &deployment),
               MESH_MGMT_EXECUTION_RUNNER_OK);
  request.version = MESH_MGMT_EXECUTION_SCHEMA_V1;
  memset(request.command_id, 1, sizeof(request.command_id));
  memset(request.grant_id, 2, sizeof(request.grant_id));
  memset(request.target_node_id, 3, sizeof(request.target_node_id));
  memcpy(request.deployment_id, deployment.deployment_id,
         sizeof(request.deployment_id));
  request.deployment_generation = deployment.generation;
  memcpy(request.package_digest, deployment.module_digest,
         sizeof(request.package_digest));
  request.input_kind = MESH_MGMT_EXECUTION_INPUT_NONE;
  request.output_mode = MESH_MGMT_EXECUTION_OUTPUT_DIGEST;
  request.deadline_ms = 10000u;
  memset(request.request_nonce, 4, sizeof(request.request_nonce));
  memset(request.correlation_id, 5, sizeof(request.correlation_id));
  policy.capabilities = MESH_MGMT_EXECUTION_CAP_CORE |
                        MESH_MGMT_EXECUTION_CAP_UTILS |
                        MESH_MGMT_EXECUTION_CAP_APP;
  make_limits(&policy.limits);
  config.worker_program = MESH_TEST_EXECUTION_WORKER;
  memcpy(config.worker_sha256, worker_digest, sizeof(worker_digest));
  config.maximum_worker_bytes = 64u * 1024u * 1024u;
  config.allow_direct_process_for_tests = 1u;
  config.maximum_output_bytes = 64u * 1024u;
  check_int_eq(mesh_mgmt_execution_process_init_v1(&process, &config),
               MESH_MGMT_EXECUTION_RUNNER_OK);
  {
    mesh_mgmt_execution_runner_result_t run_result =
        mesh_mgmt_execution_process_run_v1(
            &process, &runner, &request, &policy, 1000u, NULL, &output);
    check_uint_eq(process.crashed, 0u);
    check_uint_eq(process.timed_out, 0u);
    check_str_eq(output.error_text, "");
    check_uint_eq(process.started, 1u);
    check_uint_eq(process.succeeded, 1u);
    check_int_eq(run_result, MESH_MGMT_EXECUTION_RUNNER_OK);
    check_int_eq(output.runtime_code, 0);
  }
  check_int_eq(output.runtime_code, 0);
  check_int_eq(output.guest_exit_code, 7);
  check_uint_eq(output.invocations, 1u);
  check_uint_eq(process.started, 1u);
  check_uint_eq(process.succeeded, 1u);
  request.deadline_ms = 999u;
  check_int_eq(mesh_mgmt_execution_process_run_v1(
                   &process, &runner, &request, &policy, 1000u, NULL,
                   &output),
               MESH_MGMT_EXECUTION_RUNNER_INVALID_ARG);
  check_uint_eq(process.started, 1u);
  mesh_mgmt_execution_process_destroy_v1(&process);
  mesh_mgmt_execution_runner_destroy_v1(&runner);
}

static void test_production_requires_sandbox_launcher(void) {
  mesh_mgmt_execution_process_config_v1_t config;
  mesh_mgmt_execution_process_v1_t process = {0};
  char sandbox_argument[] = "--";
  const char *sandbox_args[] = {sandbox_argument};
  memset(&config, 0, sizeof(config));
  config.worker_program = MESH_TEST_EXECUTION_WORKER;
  memset(config.worker_sha256, 1, sizeof(config.worker_sha256));
  config.maximum_worker_bytes = 64u * 1024u * 1024u;
  config.maximum_output_bytes = 64u * 1024u;
  check_int_eq(mesh_mgmt_execution_process_init_v1(&process, &config),
               MESH_MGMT_EXECUTION_RUNNER_INVALID_ARG);
  config.sandbox_program = MESH_TEST_EXECUTION_WORKER;
  memset(config.sandbox_sha256, 2, sizeof(config.sandbox_sha256));
  config.sandbox_args = sandbox_args;
  config.sandbox_arg_count = 1u;
  check_int_eq(mesh_mgmt_execution_process_init_v1(&process, &config),
               MESH_MGMT_EXECUTION_RUNNER_OK);
  sandbox_argument[0] = 'x';
  check_str_eq(process.config.sandbox_args[0], "--");
  mesh_mgmt_execution_process_destroy_v1(&process);
}

static void test_native_binary_runs_with_exact_capability_profile(void) {
  mesh_mgmt_execution_runner_v1_t runner;
  mesh_mgmt_execution_deployment_v1_t deployment;
  mesh_mgmt_execution_request_v1_t request;
  mesh_mgmt_execution_effective_policy_v1_t policy;
  mesh_mgmt_execution_runner_output_v1_t output;
  mesh_mgmt_execution_process_config_v1_t config;
  mesh_mgmt_execution_process_v1_t process = {0};
  uint8_t worker_digest[32];
  static const uint8_t input[] = {0xde, 0xad, 0xbe, 0xef};

  memset(&deployment, 0, sizeof(deployment));
  memset(&request, 0, sizeof(request));
  memset(&policy, 0, sizeof(policy));
  memset(&config, 0, sizeof(config));
  memset(deployment.deployment_id, 0x54, sizeof(deployment.deployment_id));
  deployment.generation = 2u;
  deployment.module_path = MESH_TEST_NATIVE_WORKER;
  deployment.runtime = MESH_MGMT_EXECUTION_DEPLOYMENT_NATIVE_PROCESS_V1;
  check_int_eq(mesh_mgmt_execution_runner_module_digest_v1(
                   deployment.module_path, 1024u * 1024u,
                   deployment.module_digest, NULL),
               MESH_MGMT_EXECUTION_RUNNER_OK);
  check_int_eq(mesh_mgmt_execution_runner_module_digest_v1(
                   MESH_TEST_EXECUTION_WORKER, 64u * 1024u * 1024u,
                   worker_digest, NULL),
               MESH_MGMT_EXECUTION_RUNNER_OK);
  check_int_eq(mesh_mgmt_execution_runner_init_v1(&runner, 1u),
               MESH_MGMT_EXECUTION_RUNNER_OK);
  check_int_eq(mesh_mgmt_execution_runner_register_v1(&runner, &deployment),
               MESH_MGMT_EXECUTION_RUNNER_OK);

  request.version = MESH_MGMT_EXECUTION_SCHEMA_V1;
  memset(request.command_id, 1, sizeof(request.command_id));
  memset(request.grant_id, 2, sizeof(request.grant_id));
  memset(request.target_node_id, 3, sizeof(request.target_node_id));
  memcpy(request.deployment_id, deployment.deployment_id,
         sizeof(request.deployment_id));
  request.deployment_generation = deployment.generation;
  memcpy(request.package_digest, deployment.module_digest,
         sizeof(request.package_digest));
  request.input_kind = MESH_MGMT_EXECUTION_INPUT_INLINE;
  memset(request.input_digest, 0x55, sizeof(request.input_digest));
  request.input_length = sizeof(input);
  memcpy(request.inline_input, input, sizeof(input));
  request.inline_input_size = sizeof(input);
  request.output_mode = MESH_MGMT_EXECUTION_OUTPUT_DIGEST;
  request.deadline_ms = 10000u;
  memset(request.request_nonce, 4, sizeof(request.request_nonce));
  memset(request.correlation_id, 5, sizeof(request.correlation_id));
  policy.capabilities = MESH_MGMT_EXECUTION_CAP_CORE;
  make_limits(&policy.limits);

  config.worker_program = MESH_TEST_EXECUTION_WORKER;
  memcpy(config.worker_sha256, worker_digest, sizeof(worker_digest));
  config.maximum_worker_bytes = 64u * 1024u * 1024u;
  config.allow_direct_process_for_tests = 1u;
  config.maximum_output_bytes = 64u * 1024u;
  config.native_capabilities = MESH_MGMT_EXECUTION_CAP_CORE;
  check_int_eq(mesh_mgmt_execution_process_init_v1(&process, &config),
               MESH_MGMT_EXECUTION_RUNNER_OK);
  check_int_eq(mesh_mgmt_execution_process_run_v1(
                   &process, &runner, &request, &policy, 1000u, NULL,
                   &output),
               MESH_MGMT_EXECUTION_RUNNER_OK);
  check_int_eq(output.guest_exit_code, 0);
  check_uint_eq(output.stdout_bytes, sizeof(input));
  check_uint_eq(output.stderr_bytes, sizeof("native-stderr") - 1u);
  check_uint_eq(output.invocations, 1u);
  check_uint_eq(process.succeeded, 1u);

  request.deadline_ms = 999u;
  check_int_eq(mesh_mgmt_execution_process_run_v1(
                   &process, &runner, &request, &policy, 1000u, NULL,
                   &output),
               MESH_MGMT_EXECUTION_RUNNER_INVALID_ARG);
  check_uint_eq(process.started, 1u);
  request.deadline_ms = 10000u;
  policy.capabilities |= MESH_MGMT_EXECUTION_CAP_APP;
  check_int_eq(mesh_mgmt_execution_process_run_v1(
                   &process, &runner, &request, &policy, 1000u, NULL,
                   &output),
               MESH_MGMT_EXECUTION_RUNNER_POLICY_DENIED);
  check_uint_eq(process.started, 1u);
  mesh_mgmt_execution_process_destroy_v1(&process);
  mesh_mgmt_execution_runner_destroy_v1(&runner);
}

spec("isolated node execution process") {
  describe("TurboWASM worker") {
    it("runs the VM in an authenticated bounded child process") {
      test_wasm_vm_runs_in_authenticated_child();
    }
    it("fails closed when production has no OS sandbox launcher") {
      test_production_requires_sandbox_launcher();
    }
  }
  describe("Native process worker") {
    it("runs only a prestaged digest under the exact capability profile") {
      test_native_binary_runs_with_exact_capability_profile();
    }
  }
}
