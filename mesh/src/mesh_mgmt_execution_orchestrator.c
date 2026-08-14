#include "mesh_mgmt_execution_orchestrator.h"

#include "mesh_mgmt_crypto.h"
#include "turbo_fs.h"

#include <openssl/evp.h>
#include <string.h>

static int bytes_are_zero(const uint8_t *bytes, size_t size) {
  size_t index;

  for (index = 0u; index < size; ++index) {
    if (bytes[index] != 0u)
      return 0;
  }
  return 1;
}

static mesh_mgmt_execution_orchestrator_result_t map_store_result(
    mesh_mgmt_execution_store_result_t result) {
  if (result == MESH_MGMT_EXECUTION_STORE_CONFLICT)
    return MESH_MGMT_EXECUTION_ORCHESTRATOR_CONFLICT;
  if (result == MESH_MGMT_EXECUTION_STORE_INVALID_STATE)
    return MESH_MGMT_EXECUTION_ORCHESTRATOR_BUSY;
  return MESH_MGMT_EXECUTION_ORCHESTRATOR_STORE_FAILED;
}

static int fill_empty_digest(
    uint8_t digest[MESH_MGMT_EXECUTION_DIGEST_SIZE]) {
  unsigned int digest_size = 0u;

  return EVP_Digest("", 0u, digest, &digest_size, EVP_sha256(), NULL) == 1 &&
         digest_size == MESH_MGMT_EXECUTION_DIGEST_SIZE;
}

static void build_result(
    mesh_mgmt_execution_result_v1_t *result,
    const mesh_mgmt_execution_grant_v1_t *grant,
    const mesh_mgmt_execution_request_v1_t *request,
    const uint8_t request_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    mesh_mgmt_execution_state_t state, int runner_code,
    const mesh_mgmt_execution_runner_output_v1_t *runner_output,
    uint64_t started_at_ms, uint64_t finished_at_ms,
    uint64_t worker_generation) {
  memset(result, 0, sizeof(*result));
  result->version = MESH_MGMT_EXECUTION_RESULT_VERSION_V1;
  memcpy(result->command_id, request->command_id, sizeof(result->command_id));
  memcpy(result->request_digest, request_digest,
         sizeof(result->request_digest));
  memcpy(result->target_node_id, request->target_node_id,
         sizeof(result->target_node_id));
  memcpy(result->deployment_id, request->deployment_id,
         sizeof(result->deployment_id));
  result->deployment_generation = request->deployment_generation;
  memcpy(result->package_digest, request->package_digest,
         sizeof(result->package_digest));
  result->policy_epoch = grant->policy_epoch;
  memcpy(result->grant_id, request->grant_id, sizeof(result->grant_id));
  result->state = state;
  result->runtime_code =
      runner_output->runtime_code != 0 ? runner_output->runtime_code
                                       : runner_code;
  result->runtime_stage = runner_output->runtime_stage;
  result->guest_exit_code = runner_output->guest_exit_code;
  result->usage.invocations = runner_output->invocations;
  result->usage.host_calls = runner_output->host_calls;
  result->usage.copied_guest_bytes = runner_output->copied_guest_bytes;
  result->usage.modules_loaded = runner_output->modules_loaded;
  result->usage.modules_rejected = runner_output->modules_rejected;
  result->usage.open_handles = runner_output->open_handles;
  result->stdout_bytes = runner_output->stdout_bytes;
  result->stderr_bytes = runner_output->stderr_bytes;
  memcpy(result->stdout_digest, runner_output->stdout_digest,
         sizeof(result->stdout_digest));
  memcpy(result->stderr_digest, runner_output->stderr_digest,
         sizeof(result->stderr_digest));
  result->started_at_ms = started_at_ms;
  result->finished_at_ms = finished_at_ms;
  result->worker_generation = worker_generation;
  memcpy(result->correlation_id, request->correlation_id,
         sizeof(result->correlation_id));
}

mesh_mgmt_execution_orchestrator_result_t
mesh_mgmt_execution_orchestrator_init_v1(
    mesh_mgmt_execution_orchestrator_v1_t *orchestrator,
    const mesh_mgmt_execution_orchestrator_config_v1_t *config) {
  if (!orchestrator || !config || !config->store || !config->store->open ||
      !config->runner || !config->runner->entries ||
      bytes_are_zero(config->local_node_id,
                     sizeof(config->local_node_id)) ||
      bytes_are_zero(config->result_private_key,
                     sizeof(config->result_private_key)) ||
      config->worker_generation == 0u || !config->verify_grant ||
      !config->clock_now_ms)
    return MESH_MGMT_EXECUTION_ORCHESTRATOR_INVALID_ARG;
  memset(orchestrator, 0, sizeof(*orchestrator));
  orchestrator->store = config->store;
  orchestrator->runner = config->runner;
  memcpy(orchestrator->local_node_id, config->local_node_id,
         sizeof(orchestrator->local_node_id));
  memcpy(orchestrator->result_private_key, config->result_private_key,
         sizeof(orchestrator->result_private_key));
  if (mesh_mgmt_ed25519_public_from_private(
          orchestrator->result_private_key,
          orchestrator->result_public_key) != MESH_MGMT_CRYPTO_OK) {
    mesh_mgmt_execution_orchestrator_destroy_v1(orchestrator);
    return MESH_MGMT_EXECUTION_ORCHESTRATOR_INVALID_ARG;
  }
  orchestrator->worker_generation = config->worker_generation;
  orchestrator->verify_grant = config->verify_grant;
  orchestrator->verify_grant_context = config->verify_grant_context;
  orchestrator->clock_now_ms = config->clock_now_ms;
  orchestrator->clock_context = config->clock_context;
  orchestrator->execute_runner = config->execute_runner;
  orchestrator->execute_runner_context = config->execute_runner_context;
  orchestrator->initialized = 1u;
  return MESH_MGMT_EXECUTION_ORCHESTRATOR_OK;
}

void mesh_mgmt_execution_orchestrator_destroy_v1(
    mesh_mgmt_execution_orchestrator_v1_t *orchestrator) {
  if (!orchestrator)
    return;
  mesh_mgmt_crypto_wipe(orchestrator->result_private_key,
                        sizeof(orchestrator->result_private_key));
  memset(orchestrator, 0, sizeof(*orchestrator));
}

mesh_mgmt_execution_orchestrator_result_t
mesh_mgmt_execution_orchestrator_execute_v1(
    mesh_mgmt_execution_orchestrator_v1_t *orchestrator,
    const mesh_mgmt_execution_grant_v1_t *grant,
    const mesh_mgmt_execution_request_v1_t *request,
    const mesh_mgmt_execution_authorization_input_v1_t *authorization,
    const mesh_mgmt_execution_runner_io_v1_t *io,
    mesh_mgmt_execution_result_v1_t *out_result) {
  mesh_mgmt_execution_effective_policy_v1_t effective_policy;
  mesh_mgmt_execution_deployment_v1_t deployment;
  mesh_mgmt_execution_journal_entry_v1_t entry;
  mesh_mgmt_execution_runner_output_v1_t runner_output;
  char deployment_path[TURBO_FS_MAX_PATH];
  uint8_t request_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint64_t now_ms;
  uint64_t started_at_ms;
  uint64_t finished_at_ms;
  int runner_code;
  mesh_mgmt_execution_state_t terminal_state;
  mesh_mgmt_execution_store_result_t store_result;

  if (!orchestrator || !orchestrator->initialized || !grant || !request ||
      !authorization || !out_result)
    return MESH_MGMT_EXECUTION_ORCHESTRATOR_INVALID_ARG;
  memset(out_result, 0, sizeof(*out_result));
  now_ms = orchestrator->clock_now_ms(orchestrator->clock_context);
  if (now_ms == 0u)
    return MESH_MGMT_EXECUTION_ORCHESTRATOR_CLOCK_FAILED;
  if (mesh_mgmt_execution_grant_validate_v1(grant, now_ms) !=
          MESH_MGMT_EXECUTION_OK ||
      mesh_mgmt_execution_request_validate_v1(request, now_ms) !=
          MESH_MGMT_EXECUTION_OK ||
      mesh_mgmt_execution_request_bind_v1(grant, request) !=
          MESH_MGMT_EXECUTION_OK ||
      !mesh_mgmt_crypto_equal_32(grant->target_node_id,
                                 orchestrator->local_node_id) ||
      orchestrator->verify_grant(orchestrator->verify_grant_context, grant,
                                 now_ms) != 0 ||
      mesh_mgmt_execution_authorize_v1(
          grant, authorization, &effective_policy) !=
          MESH_MGMT_EXECUTION_OK)
    return MESH_MGMT_EXECUTION_ORCHESTRATOR_AUTH_FAILED;
  if (mesh_mgmt_execution_runner_resolve_v1(
          orchestrator->runner, request->deployment_id,
          request->deployment_generation, &deployment, deployment_path,
          sizeof(deployment_path)) != MESH_MGMT_EXECUTION_RUNNER_OK ||
      (grant->operation ==
           MESH_MGMT_EXECUTION_OPERATION_RUN_PRESTAGED_WASM &&
       deployment.runtime != MESH_MGMT_EXECUTION_DEPLOYMENT_WASM_V1) ||
      (grant->operation ==
           MESH_MGMT_EXECUTION_OPERATION_RUN_PRESTAGED_NATIVE &&
       deployment.runtime !=
           MESH_MGMT_EXECUTION_DEPLOYMENT_NATIVE_PROCESS_V1))
    return MESH_MGMT_EXECUTION_ORCHESTRATOR_AUTH_FAILED;
  if (mesh_mgmt_execution_request_digest_v1(request, request_digest) !=
      MESH_MGMT_EXECUTION_RESULT_OK)
    return MESH_MGMT_EXECUTION_ORCHESTRATOR_INVALID_ARG;

  store_result = mesh_mgmt_execution_store_submit_v1(
      orchestrator->store, request->command_id, request_digest, &entry);
  if (store_result != MESH_MGMT_EXECUTION_STORE_OK)
    return map_store_result(store_result);
  if (mesh_mgmt_execution_state_is_terminal_v1(entry.state)) {
    store_result = mesh_mgmt_execution_store_get_result_v1(
        orchestrator->store, request->command_id, out_result);
    if (store_result == MESH_MGMT_EXECUTION_STORE_NOT_FOUND)
      return MESH_MGMT_EXECUTION_ORCHESTRATOR_INDETERMINATE;
    if (store_result != MESH_MGMT_EXECUTION_STORE_OK ||
        mesh_mgmt_execution_result_verify_v1(
            out_result, orchestrator->result_public_key) !=
            MESH_MGMT_EXECUTION_RESULT_OK)
      return MESH_MGMT_EXECUTION_ORCHESTRATOR_STORE_FAILED;
    return MESH_MGMT_EXECUTION_ORCHESTRATOR_OK;
  }
  if (entry.state != MESH_MGMT_EXECUTION_STATE_ACCEPTED)
    return MESH_MGMT_EXECUTION_ORCHESTRATOR_BUSY;

  store_result = mesh_mgmt_execution_store_transition_v1(
      orchestrator->store, request->command_id,
      MESH_MGMT_EXECUTION_STATE_STAGING, 0, &entry);
  if (store_result != MESH_MGMT_EXECUTION_STORE_OK)
    return map_store_result(store_result);
  store_result = mesh_mgmt_execution_store_transition_v1(
      orchestrator->store, request->command_id,
      MESH_MGMT_EXECUTION_STATE_RUNNING, 0, &entry);
  if (store_result != MESH_MGMT_EXECUTION_STORE_OK)
    return map_store_result(store_result);

  started_at_ms = orchestrator->clock_now_ms(orchestrator->clock_context);
  if (started_at_ms == 0u)
    return MESH_MGMT_EXECUTION_ORCHESTRATOR_CLOCK_FAILED;
  memset(&runner_output, 0, sizeof(runner_output));
  runner_code = orchestrator->execute_runner
                    ? orchestrator->execute_runner(
                          orchestrator->execute_runner_context,
                          orchestrator->runner, request, &effective_policy,
                          started_at_ms, io, &runner_output)
                    : mesh_mgmt_execution_runner_run_v1(
                          orchestrator->runner, request, &effective_policy,
                          started_at_ms, io, &runner_output);
  finished_at_ms = orchestrator->clock_now_ms(orchestrator->clock_context);
  if (finished_at_ms < started_at_ms)
    return MESH_MGMT_EXECUTION_ORCHESTRATOR_CLOCK_FAILED;
  if (bytes_are_zero(runner_output.stdout_digest,
                     sizeof(runner_output.stdout_digest)) &&
      !fill_empty_digest(runner_output.stdout_digest))
    return MESH_MGMT_EXECUTION_ORCHESTRATOR_SIGN_FAILED;
  if (bytes_are_zero(runner_output.stderr_digest,
                     sizeof(runner_output.stderr_digest)) &&
      !fill_empty_digest(runner_output.stderr_digest))
    return MESH_MGMT_EXECUTION_ORCHESTRATOR_SIGN_FAILED;
  terminal_state =
      runner_code == MESH_MGMT_EXECUTION_RUNNER_OK &&
              runner_output.guest_exit_code == 0
          ? MESH_MGMT_EXECUTION_STATE_SUCCEEDED
          : MESH_MGMT_EXECUTION_STATE_FAILED;
  build_result(out_result, grant, request, request_digest, terminal_state,
               runner_code, &runner_output, started_at_ms, finished_at_ms,
               orchestrator->worker_generation);
  if (mesh_mgmt_execution_result_sign_v1(
          out_result, orchestrator->result_private_key) !=
      MESH_MGMT_EXECUTION_RESULT_OK)
    return MESH_MGMT_EXECUTION_ORCHESTRATOR_SIGN_FAILED;
  store_result = mesh_mgmt_execution_store_commit_result_v1(
      orchestrator->store, out_result, &entry);
  if (store_result != MESH_MGMT_EXECUTION_STORE_OK) {
    memset(out_result, 0, sizeof(*out_result));
    return map_store_result(store_result);
  }
  return MESH_MGMT_EXECUTION_ORCHESTRATOR_OK;
}
