#include "mesh_control_execution_provider.h"
#include "platform.h"
#include "tinytest.h"
#include "turbo_thread.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void cleanup_store_files(const char *path) {
  char lock_path[TURBO_FS_MAX_PATH + 6u];
  char temp_path[TURBO_FS_MAX_PATH + 5u];
  (void)snprintf(lock_path, sizeof(lock_path), "%s.lock", path);
  (void)snprintf(temp_path, sizeof(temp_path), "%s.tmp", path);
  if (turbo_fs_access(path, TURBO_FS_ACCESS_EXISTS) == 0)
    (void)turbo_fs_unlink(path);
  if (turbo_fs_access(lock_path, TURBO_FS_ACCESS_EXISTS) == 0)
    (void)turbo_fs_unlink(lock_path);
  if (turbo_fs_access(temp_path, TURBO_FS_ACCESS_EXISTS) == 0)
    (void)turbo_fs_unlink(temp_path);
}

static uint64_t test_now(void *context) {
  (void)context;
  return 1000u;
}

static void make_limits(mesh_mgmt_execution_limits_v1_t *limits) {
  memset(limits, 0, sizeof(*limits));
  limits->module_bytes = 1024u * 1024u;
  limits->stack_bytes = 64u * 1024u;
  limits->linear_memory_bytes = 256u * 1024u;
  limits->timeout_ms = 5000u;
  limits->control_flow_steps = 1000000u;
  limits->host_calls = 64u;
  limits->copied_guest_bytes = 64u * 1024u;
  limits->input_bytes = 64u * 1024u;
  limits->stdout_bytes = 64u * 1024u;
  limits->stderr_bytes = 64u * 1024u;
}

static void make_request(
    mesh_control_provider_request_v1_t *request,
    const mesh_control_execution_deployment_v1_t *deployment,
    uint16_t runtime, uint16_t desired_state, uint8_t operation_byte) {
  memset(request, 0, sizeof(*request));
  memset(request->operation.operation_id, operation_byte,
         sizeof(request->operation.operation_id));
  request->operation.action = MESH_CONTROL_DESIRED_APPLY;
  request->spec.schema_version = MESH_CONTROL_SCHEMA_V1;
  request->spec.runtime = runtime;
  request->spec.desired_state = desired_state;
  request->spec.flags = MESH_CONTROL_FUNCTION_FLAG_PRESTAGED |
                        MESH_CONTROL_FUNCTION_FLAG_OUT_OF_PROCESS;
  memset(request->spec.function_id, 0x11,
         sizeof(request->spec.function_id));
  memset(request->spec.provider_id, 0x22,
         sizeof(request->spec.provider_id));
  memcpy(request->spec.artifact_digest,
         deployment->deployment.module_digest,
         sizeof(request->spec.artifact_digest));
  memcpy(request->spec.config_digest, deployment->config_digest,
         sizeof(request->spec.config_digest));
  memcpy(request->spec.network_policy_digest,
         deployment->network_policy_digest,
         sizeof(request->spec.network_policy_digest));
  request->spec.generation = 1u;
  request->spec.required_capabilities = MESH_MGMT_EXECUTION_CAP_CORE;
  request->spec.limits.memory_bytes = 128u * 1024u;
  request->spec.limits.cpu_time_ms = 3000u;
  request->spec.limits.input_bytes = 4096u;
  request->spec.limits.output_bytes = 8192u;
  request->spec.limits.concurrency = 1u;
  request->spec.limits.host_calls = 8u;
}

static int wait_completion(
    mesh_control_provider_v1_t *descriptor,
    mesh_control_provider_completion_v1_t *completion) {
  uint64_t started = turbo_monotonic_ms();
  while (turbo_monotonic_ms() - started < 10000u) {
    mesh_control_result_t result = descriptor->ops.try_peek_completion(
        descriptor->context, completion);
    if (result == MESH_CONTROL_OK) return 1;
    if (result != MESH_CONTROL_EMPTY) return 0;
    turbo_sleep_ms(1u);
  }
  return 0;
}

static int wait_drained(mesh_control_provider_v1_t *descriptor) {
  uint64_t started = turbo_monotonic_ms();
  while (turbo_monotonic_ms() - started < 10000u) {
    if (descriptor->ops.is_drained(descriptor->context)) return 1;
    turbo_sleep_ms(1u);
  }
  return 0;
}

static void run_provider_case(uint16_t runtime, const char *module_path,
                              uint64_t deployment_generation,
                              uint16_t expected_running_state,
                              int seed_interrupted_claim) {
  mesh_mgmt_execution_process_config_v1_t process_config;
  mesh_mgmt_execution_process_v1_t process = {0};
  mesh_control_execution_deployment_v1_t deployment;
  mesh_control_execution_provider_config_v1_t provider_config;
  mesh_control_execution_provider_v1_t provider = {0};
  mesh_control_provider_v1_t descriptor;
  mesh_control_provider_request_v1_t request;
  mesh_control_provider_completion_v1_t completion;
  uint8_t worker_digest[MESH_CONTROL_DIGEST_SIZE];
  char *journal_path = tt_make_temp_file("mesh-control-execution", ".bin");

  check_not_null(journal_path);
  if (!journal_path) return;
  cleanup_store_files(journal_path);

  memset(&process_config, 0, sizeof(process_config));
  check_int_eq(mesh_mgmt_execution_runner_module_digest_v1(
                   MESH_TEST_EXECUTION_WORKER, 64u * 1024u * 1024u,
                   worker_digest, NULL),
               MESH_MGMT_EXECUTION_RUNNER_OK);
  process_config.worker_program = MESH_TEST_EXECUTION_WORKER;
  memcpy(process_config.worker_sha256, worker_digest,
         sizeof(process_config.worker_sha256));
  process_config.maximum_worker_bytes = 64u * 1024u * 1024u;
  process_config.allow_direct_process_for_tests = 1u;
  process_config.maximum_output_bytes = 64u * 1024u;
  process_config.native_capabilities = MESH_MGMT_EXECUTION_CAP_CORE;
  check_int_eq(mesh_mgmt_execution_process_init_v1(&process,
                                                    &process_config),
               MESH_MGMT_EXECUTION_RUNNER_OK);

  memset(&deployment, 0, sizeof(deployment));
  memset(deployment.deployment.deployment_id, 0x33,
         sizeof(deployment.deployment.deployment_id));
  deployment.deployment.generation = deployment_generation;
  deployment.deployment.module_path = module_path;
  deployment.deployment.runtime =
      runtime == MESH_CONTROL_FUNCTION_WASM
          ? MESH_MGMT_EXECUTION_DEPLOYMENT_WASM_V1
          : MESH_MGMT_EXECUTION_DEPLOYMENT_NATIVE_PROCESS_V1;
  check_int_eq(mesh_mgmt_execution_runner_module_digest_v1(
                   module_path, 1024u * 1024u,
                   deployment.deployment.module_digest, NULL),
               MESH_MGMT_EXECUTION_RUNNER_OK);
  memset(deployment.config_digest, 0x44,
         sizeof(deployment.config_digest));
  memset(deployment.network_policy_digest, 0x55,
         sizeof(deployment.network_policy_digest));

  memset(&provider_config, 0, sizeof(provider_config));
  memset(provider_config.provider_id, 0x22,
         sizeof(provider_config.provider_id));
  memset(provider_config.local_node_id, 0x66,
         sizeof(provider_config.local_node_id));
  provider_config.runtime = runtime;
  provider_config.capabilities =
      runtime == MESH_CONTROL_FUNCTION_WASM
          ? MESH_MGMT_EXECUTION_RAW_WASM_CAPABILITIES_V1
          : MESH_MGMT_EXECUTION_CAP_CORE;
  make_limits(&provider_config.hard_limits);
  provider_config.deployments = &deployment;
  provider_config.deployment_count = 1u;
  provider_config.process = &process;
  provider_config.journal_path = journal_path;
  provider_config.journal_capacity = 4u;
  memset(provider_config.result_private_key, 0x61,
         sizeof(provider_config.result_private_key));
  provider_config.worker_generation = 1u;
  provider_config.now_ms = test_now;
  if (seed_interrupted_claim) {
    mesh_mgmt_execution_store_v1_t store;
    mesh_mgmt_execution_journal_entry_v1_t entry;
    uint8_t request_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
    make_request(&request, &deployment, runtime,
                 MESH_CONTROL_FUNCTION_RUNNING, 0x72);
    request.spec.required_capabilities = provider_config.capabilities;
    check_int_eq(mesh_control_execution_provider_request_digest_v1(
                     &request, request_digest),
                 MESH_CONTROL_OK);
    check_int_eq(mesh_mgmt_execution_store_open_v1(
                     &store, journal_path,
                     provider_config.journal_capacity, NULL),
                 MESH_MGMT_EXECUTION_STORE_OK);
    check_int_eq(mesh_mgmt_execution_store_submit_v1(
                     &store, request.operation.operation_id,
                     request_digest, &entry),
                 MESH_MGMT_EXECUTION_STORE_OK);
    check_int_eq(mesh_mgmt_execution_store_transition_v1(
                     &store, request.operation.operation_id,
                     MESH_MGMT_EXECUTION_STATE_STAGING, 0, &entry),
                 MESH_MGMT_EXECUTION_STORE_OK);
    check_int_eq(mesh_mgmt_execution_store_transition_v1(
                     &store, request.operation.operation_id,
                     MESH_MGMT_EXECUTION_STATE_RUNNING, 0, &entry),
                 MESH_MGMT_EXECUTION_STORE_OK);
    mesh_mgmt_execution_store_close_v1(&store);
  }
  if (runtime == MESH_CONTROL_FUNCTION_WASM) {
    provider_config.capabilities = MESH_MGMT_EXECUTION_CAP_CORE;
    check_int_eq(mesh_control_execution_provider_init_v1(
                     &provider, &provider_config, &descriptor),
                 MESH_CONTROL_INVALID_ARG);
    provider_config.capabilities =
        MESH_MGMT_EXECUTION_RAW_WASM_CAPABILITIES_V1;
  }
  check_int_eq(mesh_control_execution_provider_init_v1(
                   &provider, &provider_config, &descriptor),
               MESH_CONTROL_OK);

  make_request(&request, &deployment, runtime,
               MESH_CONTROL_FUNCTION_STAGED, 0x71);
  request.spec.required_capabilities = provider_config.capabilities;
  check_int_eq(descriptor.ops.try_start(descriptor.context, &request),
               MESH_CONTROL_OK);
  check_int_eq(descriptor.ops.try_start(descriptor.context, &request),
               MESH_CONTROL_RESOURCE_EXHAUSTED);
  check_true(wait_completion(&descriptor, &completion));
  check_int_eq(completion.state, MESH_CONTROL_PROVIDER_COMPLETED);
  check_int_eq(descriptor.ops.ack_completion(
                   descriptor.context, request.operation.operation_id),
               MESH_CONTROL_OK);

  make_request(&request, &deployment, runtime,
               MESH_CONTROL_FUNCTION_RUNNING, 0x72);
  request.spec.required_capabilities = provider_config.capabilities;
  check_int_eq(descriptor.ops.try_start(descriptor.context, &request),
               MESH_CONTROL_OK);
  check_true(wait_completion(&descriptor, &completion));
  check_int_eq(completion.state, expected_running_state);
  if (seed_interrupted_claim)
    check_true(process.started == 0u);
  else
    check_true(process.started != 0u);
  descriptor.ops.close(descriptor.context);
  check_false(descriptor.ops.is_drained(descriptor.context));
  check_int_eq(descriptor.ops.ack_completion(
                   descriptor.context, request.operation.operation_id),
               MESH_CONTROL_OK);
  check_true(descriptor.ops.is_drained(descriptor.context));
  mesh_control_execution_provider_destroy_v1(&provider);

  {
    uint64_t starts_before_replay = process.started;
    check_int_eq(mesh_control_execution_provider_init_v1(
                     &provider, &provider_config, &descriptor),
                 MESH_CONTROL_OK);
    check_int_eq(descriptor.ops.try_start(descriptor.context, &request),
                 MESH_CONTROL_OK);
    check_true(wait_completion(&descriptor, &completion));
    check_int_eq(completion.state, expected_running_state);
    check_true(process.started == starts_before_replay);
    check_int_eq(descriptor.ops.ack_completion(
                     descriptor.context, request.operation.operation_id),
                 MESH_CONTROL_OK);
    descriptor.ops.close(descriptor.context);
    check_true(wait_drained(&descriptor));
    mesh_control_execution_provider_destroy_v1(&provider);
  }
  mesh_mgmt_execution_process_destroy_v1(&process);
  cleanup_store_files(journal_path);
  free(journal_path);
}

spec("mesh control isolated execution provider") {
  describe("bounded Native and TurboWASM strategy") {
    it("runs a prestaged WASM module in the authenticated child") {
      run_provider_case(MESH_CONTROL_FUNCTION_WASM,
                        MESH_TEST_EXECUTION_SUCCESS_WASM, 1u,
                        MESH_CONTROL_PROVIDER_COMPLETED, 0);
    }
    it("runs a prestaged Native binary outside the agent process") {
      run_provider_case(MESH_CONTROL_FUNCTION_NATIVE,
                        MESH_TEST_NATIVE_WORKER, 2u,
                        MESH_CONTROL_PROVIDER_COMPLETED, 0);
    }
    it("fences an interrupted durable claim instead of rerunning it") {
      run_provider_case(MESH_CONTROL_FUNCTION_NATIVE,
                        MESH_TEST_NATIVE_WORKER, 3u,
                        MESH_CONTROL_PROVIDER_FAILED, 1);
    }
  }
}
