#include <tinytest.h>

#include "meshd_execution_config.h"

#include <string.h>

#ifdef _WIN32
#define TEST_MODULE_PATH "C:\\wasm\\app.wasm"
#define TEST_WORKER_PATH "C:\\mesh\\mesh-execution-worker.exe"
#define TEST_SANDBOX_PATH "C:\\mesh\\sandbox-launcher.exe"
#else
#define TEST_MODULE_PATH "/wasm/app.wasm"
#define TEST_WORKER_PATH "/opt/mesh/mesh-execution-worker"
#define TEST_SANDBOX_PATH "/opt/mesh/sandbox-launcher"
#endif

static const char valid_config[] =
    "mgmt_execution_mode: prestaged_isolated\n"
    "mgmt_execution_store_file: execution.journal\n"
    "mgmt_execution_worker_program: " TEST_WORKER_PATH "\n"
    "mgmt_execution_worker_sha256: 4141414141414141414141414141414141414141414141414141414141414141\n"
    "mgmt_execution_sandbox_program: " TEST_SANDBOX_PATH "\n"
    "mgmt_execution_sandbox_sha256: 4242424242424242424242424242424242424242424242424242424242424242\n"
    "mgmt_execution_sandbox_args: --unshare-all,--die-with-parent,--\n"
    "mgmt_execution_max_worker_bytes: 67108864\n"
    "mgmt_execution_max_output_bytes: 65536\n"
    "mgmt_execution_worker_queue_capacity: 64\n"
    "mgmt_execution_egress_capacity: 64\n"
    "mgmt_execution_capabilities: core,utils,app\n"
    "mgmt_execution_module_bytes: 1048576\n"
    "mgmt_execution_stack_bytes: 65536\n"
    "mgmt_execution_linear_memory_bytes: 262144\n"
    "mgmt_execution_timeout_ms: 1000\n"
    "mgmt_execution_control_flow_steps: 1000000\n"
    "mgmt_execution_host_calls: 128\n"
    "mgmt_execution_copied_guest_bytes: 1048576\n"
    "mgmt_execution_input_bytes: 65536\n"
    "mgmt_execution_stdout_bytes: 65536\n"
    "mgmt_execution_stderr_bytes: 65536\n"
    "mgmt_execution_deployments:\n"
    "  - \"21212121212121212121212121212121,"
    "1,3131313131313131313131313131313131313131313131313131313131313131,"
    TEST_MODULE_PATH "\"\n"
    "  - \"native,22222222222222222222222222222222,2,"
    "3232323232323232323232323232323232323232323232323232323232323232,"
    TEST_MODULE_PATH "\"\n";

static const char control_bound_config[] =
    "mgmt_execution_mode: prestaged_isolated\n"
    "mgmt_execution_store_file: execution.journal\n"
    "mgmt_execution_worker_program: " TEST_WORKER_PATH "\n"
    "mgmt_execution_worker_sha256: 4141414141414141414141414141414141414141414141414141414141414141\n"
    "mgmt_execution_sandbox_program: " TEST_SANDBOX_PATH "\n"
    "mgmt_execution_sandbox_sha256: 4242424242424242424242424242424242424242424242424242424242424242\n"
    "mgmt_execution_sandbox_args: --unshare-all,--die-with-parent,--\n"
    "mgmt_execution_max_worker_bytes: 67108864\n"
    "mgmt_execution_max_output_bytes: 65536\n"
    "mgmt_execution_worker_queue_capacity: 64\n"
    "mgmt_execution_egress_capacity: 64\n"
    "mgmt_execution_capabilities: core,utils,app\n"
    "mgmt_execution_module_bytes: 1048576\n"
    "mgmt_execution_stack_bytes: 65536\n"
    "mgmt_execution_linear_memory_bytes: 262144\n"
    "mgmt_execution_timeout_ms: 1000\n"
    "mgmt_execution_control_flow_steps: 1000000\n"
    "mgmt_execution_host_calls: 128\n"
    "mgmt_execution_copied_guest_bytes: 1048576\n"
    "mgmt_execution_input_bytes: 65536\n"
    "mgmt_execution_stdout_bytes: 65536\n"
    "mgmt_execution_stderr_bytes: 65536\n"
    "mgmt_execution_deployments:\n"
    "  - \"wasm,23232323232323232323232323232323,3,"
    "3333333333333333333333333333333333333333333333333333333333333333,"
    "4343434343434343434343434343434343434343434343434343434343434343,"
    "5353535353535353535353535353535353535353535353535353535353535353,"
    TEST_MODULE_PATH "\"\n";

static void test_parses_complete_prestaged_policy(void) {
  meshd_execution_config_t config;

  check_int_eq(meshd_execution_config_parse(
                   &config, valid_config, strlen(valid_config)),
               0);
  check_int_eq(config.mode, MESHD_EXECUTION_MODE_PRESTAGED_ISOLATED);
  check_size_eq(config.worker_queue_capacity, 64u);
  check_size_eq(config.egress_capacity, 64u);
  check_size_eq(config.deployment_count, 2u);
  check_size_eq(config.sandbox_arg_count, 3u);
  check_str_eq(config.sandbox_args[0], "--unshare-all");
  check_int_eq(config.capabilities,
               MESH_MGMT_EXECUTION_NODE_RAW_CAPABILITIES);
  check_int_eq(config.deployments[0].generation, 1u);
  check_int_eq(config.deployments[0].runtime,
               MESH_MGMT_EXECUTION_DEPLOYMENT_WASM_V1);
  check_str_eq(config.deployments[0].module_path, TEST_MODULE_PATH);
  check_int_eq(config.deployments[1].generation, 2u);
  check_int_eq(config.deployments[1].runtime,
               MESH_MGMT_EXECUTION_DEPLOYMENT_NATIVE_PROCESS_V1);
}

static void test_disabled_is_default_and_fail_closed(void) {
  static const char unrelated[] = "virtual_ip: 10.42.0.1\n";
  static const char incomplete[] =
      "mgmt_execution_mode: prestaged_wasm\n"
      "mgmt_execution_store_file: execution.journal\n";
  static const char unknown[] =
      "mgmt_execution_mode: disabled\n"
      "mgmt_execution_fallback: true\n";
  meshd_execution_config_t config;

  check_int_eq(meshd_execution_config_parse(
                   &config, unrelated, strlen(unrelated)),
               0);
  check_int_eq(config.mode, MESHD_EXECUTION_MODE_DISABLED);
  check_int_eq(meshd_execution_config_parse(
                   &config, incomplete, strlen(incomplete)),
               -1);
  check_int_eq(meshd_execution_config_parse(
                   &config, unknown, strlen(unknown)),
               -1);
}

static void test_parses_control_plane_deployment_binding(void) {
  meshd_execution_config_t config;

  check_int_eq(meshd_execution_config_parse(
                   &config, control_bound_config,
                   strlen(control_bound_config)),
               0);
  check_size_eq(config.deployment_count, 1u);
  check_int_eq(config.deployment_has_control_binding[0], 1u);
  check_int_eq(config.deployments[0].runtime,
               MESH_MGMT_EXECUTION_DEPLOYMENT_WASM_V1);
  check_int_eq(config.deployment_config_digests[0][0], 0x43);
  check_int_eq(config.deployment_network_policy_digests[0][0], 0x53);
}

static void test_rejects_partial_raw_wasm_capability_profile(void) {
  meshd_execution_config_t config;

  check_int_eq(meshd_execution_config_parse(
                   &config, control_bound_config,
                   strlen(control_bound_config)),
               0);
  config.capabilities = MESH_MGMT_EXECUTION_CAP_CORE;
  check_int_eq(meshd_execution_config_validate(&config), -1);
}

spec("meshd execution configuration") {
  describe("local TurboRuntime policy") {
    it("parses a complete prestaged policy") {
      test_parses_complete_prestaged_policy();
    }
    it("defaults disabled and rejects incomplete or unknown policy") {
      test_disabled_is_default_and_fail_closed();
    }
    it("binds control-plane config and network policy digests") {
      test_parses_control_plane_deployment_binding();
    }
    it("rejects a partial capability profile for raw WASM") {
      test_rejects_partial_raw_wasm_capability_profile();
    }
  }
}
