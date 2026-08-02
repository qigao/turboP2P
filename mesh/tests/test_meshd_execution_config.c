#include <tinytest.h>

#include "meshd_execution_config.h"

#include <string.h>

#ifdef _WIN32
#define TEST_MODULE_PATH "C:\\wasm\\app.wasm"
#else
#define TEST_MODULE_PATH "/wasm/app.wasm"
#endif

static const char valid_config[] =
    "mgmt_execution_mode: prestaged_wasm\n"
    "mgmt_execution_store_file: execution.journal\n"
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
    "  - \"2121212121212121212121212121212121212121212121212121212121212121,"
    "1,3131313131313131313131313131313131313131313131313131313131313131,"
    TEST_MODULE_PATH "\"\n";

static void test_parses_complete_prestaged_policy(void) {
  meshd_execution_config_t config;

  check_int_eq(meshd_execution_config_parse(
                   &config, valid_config, strlen(valid_config)),
               0);
  check_int_eq(config.mode, MESHD_EXECUTION_MODE_PRESTAGED_WASM);
  check_size_eq(config.worker_queue_capacity, 64u);
  check_size_eq(config.egress_capacity, 64u);
  check_size_eq(config.deployment_count, 1u);
  check_int_eq(config.capabilities,
               MESH_MGMT_EXECUTION_NODE_RAW_CAPABILITIES);
  check_int_eq(config.deployments[0].generation, 1u);
  check_str_eq(config.deployments[0].module_path, TEST_MODULE_PATH);
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

spec("meshd execution configuration") {
  describe("local TurboRuntime policy") {
    it("parses a complete prestaged policy") {
      test_parses_complete_prestaged_policy();
    }
    it("defaults disabled and rejects incomplete or unknown policy") {
      test_disabled_is_default_and_fail_closed();
    }
  }
}
