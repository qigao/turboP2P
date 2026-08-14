#include "mesh_control_execution_provider.h"

#include "mesh_mgmt_crypto.h"
#include "platform.h"
#include "turbo_thread.h"

#include <openssl/evp.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

enum {
  EXECUTION_PROVIDER_IDLE = 0,
  EXECUTION_PROVIDER_RUNNING = 1,
  EXECUTION_PROVIDER_READY = 2,
  EXECUTION_PROVIDER_CLEANING = 3
};

enum {
  EXECUTION_CLAIM_ERROR = 0,
  EXECUTION_CLAIM_RUN = 1,
  EXECUTION_CLAIM_COMPLETED = 2,
  EXECUTION_CLAIM_FAILED = 3
};

static const uint8_t EXECUTION_CLAIM_DOMAIN_V1[] =
    "mesh.control.execution.claim.v1";

typedef struct {
  mesh_mgmt_execution_deployment_v1_t deployment;
  char module_path[TURBO_FS_MAX_PATH];
  uint8_t config_digest[MESH_CONTROL_DIGEST_SIZE];
  uint8_t network_policy_digest[MESH_CONTROL_DIGEST_SIZE];
} execution_deployment_v1_t;

typedef struct {
  struct mesh_control_execution_provider_impl_v1 *provider;
  mesh_control_provider_request_v1_t request;
  size_t deployment_index;
} execution_job_v1_t;

typedef struct {
  struct mesh_control_execution_provider_impl_v1 *provider;
  uint8_t operation_id[MESH_CONTROL_ID_SIZE];
} execution_cleanup_job_v1_t;

struct mesh_control_execution_provider_impl_v1 {
  mesh_control_execution_provider_config_v1_t config;
  mesh_mgmt_execution_runner_v1_t runner;
  execution_deployment_v1_t *deployments;
  mesh_mgmt_execution_store_v1_t journal;
  uint8_t result_public_key[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  turbo_threadpool_t *pool;
  mesh_control_provider_completion_v1_t completion;
  uint8_t completion_journaled;
  atomic_int phase;
  atomic_bool accepting;
  atomic_bool journal_failed;
};

static int bytes_zero(const uint8_t *bytes, size_t size) {
  uint8_t value = 0u;
  size_t index;
  for (index = 0u; index < size; ++index) value |= bytes[index];
  return value == 0u;
}

static int limits_valid(const mesh_mgmt_execution_limits_v1_t *limits) {
  return limits && limits->module_bytes != 0u && limits->stack_bytes != 0u &&
         limits->linear_memory_bytes != 0u && limits->timeout_ms != 0u &&
         limits->control_flow_steps != 0u && limits->host_calls != 0u &&
         limits->copied_guest_bytes != 0u && limits->input_bytes != 0u &&
         limits->stdout_bytes != 0u && limits->stderr_bytes != 0u;
}

mesh_control_result_t mesh_control_execution_provider_request_digest_v1(
    const mesh_control_provider_request_v1_t *request,
    uint8_t out_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE]) {
  uint8_t canonical[MESH_CONTROL_FUNCTION_DOCUMENT_SIZE_V1];
  uint8_t input[sizeof(EXECUTION_CLAIM_DOMAIN_V1) - 1u + 2u + 8u +
                MESH_CONTROL_DIGEST_SIZE +
                MESH_CONTROL_FUNCTION_DOCUMENT_SIZE_V1];
  size_t canonical_size = 0u;
  size_t offset = 0u;
  size_t index;

  if (!request || !out_digest ||
      mesh_control_function_document_encode_v1(
          &request->spec, canonical, sizeof(canonical),
          &canonical_size) != MESH_CONTROL_OK ||
      canonical_size != sizeof(canonical))
    return MESH_CONTROL_INVALID_ARG;
  memcpy(input + offset, EXECUTION_CLAIM_DOMAIN_V1,
         sizeof(EXECUTION_CLAIM_DOMAIN_V1) - 1u);
  offset += sizeof(EXECUTION_CLAIM_DOMAIN_V1) - 1u;
  input[offset++] = (uint8_t)(request->operation.action >> 8u);
  input[offset++] = (uint8_t)request->operation.action;
  for (index = 0u; index < 8u; ++index)
    input[offset++] =
        (uint8_t)(request->operation.desired_epoch >> (56u - index * 8u));
  memcpy(input + offset, request->operation.desired_digest,
         MESH_CONTROL_DIGEST_SIZE);
  offset += MESH_CONTROL_DIGEST_SIZE;
  memcpy(input + offset, canonical, sizeof(canonical));
  offset += sizeof(canonical);
  if (offset != sizeof(input) ||
      mesh_mgmt_blake2b_256(input, sizeof(input), out_digest) !=
          MESH_MGMT_CRYPTO_OK) {
    memset(out_digest, 0, MESH_MGMT_EXECUTION_DIGEST_SIZE);
    return MESH_CONTROL_INVALID_STATE;
  }
  return MESH_CONTROL_OK;
}

static int deployment_matches(
    const execution_deployment_v1_t *deployment,
    const mesh_control_function_spec_v1_t *spec) {
  return memcmp(deployment->deployment.module_digest, spec->artifact_digest,
                MESH_CONTROL_DIGEST_SIZE) == 0 &&
         memcmp(deployment->config_digest, spec->config_digest,
                MESH_CONTROL_DIGEST_SIZE) == 0 &&
         memcmp(deployment->network_policy_digest,
                spec->network_policy_digest,
                MESH_CONTROL_DIGEST_SIZE) == 0;
}

static size_t find_deployment(
    const struct mesh_control_execution_provider_impl_v1 *provider,
    const mesh_control_function_spec_v1_t *spec) {
  size_t index;
  for (index = 0u; index < provider->config.deployment_count; ++index)
    if (deployment_matches(&provider->deployments[index], spec)) return index;
  return SIZE_MAX;
}

static int limits_from_spec(
    const struct mesh_control_execution_provider_impl_v1 *provider,
    const mesh_control_function_spec_v1_t *spec,
    mesh_mgmt_execution_effective_policy_v1_t *out_policy) {
  const mesh_mgmt_execution_limits_v1_t *hard = &provider->config.hard_limits;
  uint64_t stdout_bytes;
  uint64_t stderr_bytes;
  if (spec->required_capabilities == 0u ||
      spec->required_capabilities > UINT32_MAX ||
      (uint32_t)spec->required_capabilities != provider->config.capabilities ||
      spec->limits.memory_bytes == 0u ||
      spec->limits.memory_bytes > hard->linear_memory_bytes ||
      spec->limits.memory_bytes > UINT32_MAX ||
      spec->limits.cpu_time_ms == 0u ||
      spec->limits.cpu_time_ms > hard->timeout_ms ||
      spec->limits.input_bytes == 0u ||
      spec->limits.input_bytes > hard->input_bytes ||
      spec->limits.input_bytes > hard->copied_guest_bytes ||
      spec->limits.output_bytes < 2u || spec->limits.concurrency != 1u ||
      spec->limits.host_calls == 0u ||
      spec->limits.host_calls > hard->host_calls)
    return 0;
  stdout_bytes = (spec->limits.output_bytes + 1u) / 2u;
  stderr_bytes = spec->limits.output_bytes / 2u;
  if (stdout_bytes > hard->stdout_bytes || stderr_bytes > hard->stderr_bytes)
    return 0;
  memset(out_policy, 0, sizeof(*out_policy));
  out_policy->capabilities = provider->config.capabilities;
  out_policy->limits.module_bytes = hard->module_bytes;
  out_policy->limits.stack_bytes = hard->stack_bytes;
  out_policy->limits.linear_memory_bytes =
      (uint32_t)spec->limits.memory_bytes;
  out_policy->limits.timeout_ms = spec->limits.cpu_time_ms;
  out_policy->limits.control_flow_steps = hard->control_flow_steps;
  out_policy->limits.host_calls = spec->limits.host_calls;
  out_policy->limits.copied_guest_bytes = spec->limits.input_bytes;
  out_policy->limits.input_bytes = spec->limits.input_bytes;
  out_policy->limits.stdout_bytes = stdout_bytes;
  out_policy->limits.stderr_bytes = stderr_bytes;
  return 1;
}

static int begin_durable_claim(
    struct mesh_control_execution_provider_impl_v1 *provider,
    const mesh_control_provider_request_v1_t *control_request,
    uint8_t out_request_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE]) {
  mesh_mgmt_execution_journal_entry_v1_t entry;
  mesh_mgmt_execution_store_result_t result;

  if (mesh_control_execution_provider_request_digest_v1(
          control_request, out_request_digest) != MESH_CONTROL_OK)
    return EXECUTION_CLAIM_ERROR;
  result = mesh_mgmt_execution_store_submit_v1(
      &provider->journal, control_request->operation.operation_id,
      out_request_digest, &entry);
  if (result != MESH_MGMT_EXECUTION_STORE_OK)
    return EXECUTION_CLAIM_ERROR;
  if (mesh_mgmt_execution_state_is_terminal_v1(entry.state)) {
    mesh_mgmt_execution_result_v1_t stored_result;
    if (entry.state == MESH_MGMT_EXECUTION_STATE_FAILED_INDETERMINATE)
      return EXECUTION_CLAIM_FAILED;
    if (mesh_mgmt_execution_store_get_result_v1(
            &provider->journal, control_request->operation.operation_id,
            &stored_result) != MESH_MGMT_EXECUTION_STORE_OK ||
        stored_result.state != entry.state ||
        mesh_mgmt_execution_result_verify_v1(
            &stored_result, provider->result_public_key) !=
            MESH_MGMT_EXECUTION_RESULT_OK)
      return EXECUTION_CLAIM_ERROR;
    return entry.state == MESH_MGMT_EXECUTION_STATE_SUCCEEDED
               ? EXECUTION_CLAIM_COMPLETED
               : EXECUTION_CLAIM_FAILED;
  }
  if (entry.state == MESH_MGMT_EXECUTION_STATE_ACCEPTED) {
    result = mesh_mgmt_execution_store_transition_v1(
        &provider->journal, control_request->operation.operation_id,
        MESH_MGMT_EXECUTION_STATE_STAGING, 0, &entry);
    if (result != MESH_MGMT_EXECUTION_STORE_OK)
      return EXECUTION_CLAIM_ERROR;
  }
  if (entry.state == MESH_MGMT_EXECUTION_STATE_STAGING) {
    result = mesh_mgmt_execution_store_transition_v1(
        &provider->journal, control_request->operation.operation_id,
        MESH_MGMT_EXECUTION_STATE_RUNNING, 0, &entry);
    if (result != MESH_MGMT_EXECUTION_STORE_OK)
      return EXECUTION_CLAIM_ERROR;
  }
  return entry.state == MESH_MGMT_EXECUTION_STATE_RUNNING
             ? EXECUTION_CLAIM_RUN
             : EXECUTION_CLAIM_ERROR;
}

static int ensure_output_digests(
    mesh_mgmt_execution_runner_output_v1_t *output) {
  static const uint8_t empty = 0u;
  unsigned int digest_size = 0u;
  if (bytes_zero(output->stdout_digest, sizeof(output->stdout_digest)) &&
      (EVP_Digest(&empty, 0u, output->stdout_digest, &digest_size,
                  EVP_sha256(), NULL) != 1 ||
       digest_size != sizeof(output->stdout_digest)))
      return 0;
  digest_size = 0u;
  if (bytes_zero(output->stderr_digest, sizeof(output->stderr_digest)) &&
      (EVP_Digest(&empty, 0u, output->stderr_digest, &digest_size,
                  EVP_sha256(), NULL) != 1 ||
       digest_size != sizeof(output->stderr_digest)))
      return 0;
  return 1;
}

static int commit_durable_result(
    struct mesh_control_execution_provider_impl_v1 *provider,
    const mesh_control_provider_request_v1_t *control_request,
    const mesh_mgmt_execution_request_v1_t *request,
    const uint8_t request_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    mesh_mgmt_execution_runner_result_t run_result,
    mesh_mgmt_execution_runner_output_v1_t *output,
    uint64_t started_at_ms, uint64_t finished_at_ms) {
  mesh_mgmt_execution_result_v1_t result;
  mesh_mgmt_execution_journal_entry_v1_t entry;
  int succeeded = run_result == MESH_MGMT_EXECUTION_RUNNER_OK &&
                  output->guest_exit_code == 0;

  if (!ensure_output_digests(output)) return 0;
  memset(&result, 0, sizeof(result));
  result.version = MESH_MGMT_EXECUTION_RESULT_VERSION_V1;
  memcpy(result.command_id, request->command_id, sizeof(result.command_id));
  memcpy(result.request_digest, request_digest,
         sizeof(result.request_digest));
  memcpy(result.target_node_id, request->target_node_id,
         sizeof(result.target_node_id));
  memcpy(result.deployment_id, request->deployment_id,
         sizeof(result.deployment_id));
  result.deployment_generation = request->deployment_generation;
  memcpy(result.package_digest, request->package_digest,
         sizeof(result.package_digest));
  result.policy_epoch = control_request->spec.generation;
  memcpy(result.grant_id, request->grant_id, sizeof(result.grant_id));
  result.state = succeeded ? MESH_MGMT_EXECUTION_STATE_SUCCEEDED
                           : MESH_MGMT_EXECUTION_STATE_FAILED;
  result.runtime_code = output->runtime_code != 0
                            ? output->runtime_code
                            : (int32_t)run_result;
  result.runtime_stage = output->runtime_stage;
  result.guest_exit_code = output->guest_exit_code;
  result.usage.invocations = output->invocations;
  result.usage.host_calls = output->host_calls;
  result.usage.copied_guest_bytes = output->copied_guest_bytes;
  result.usage.modules_loaded = output->modules_loaded;
  result.usage.modules_rejected = output->modules_rejected;
  result.usage.open_handles = output->open_handles;
  result.stdout_bytes = output->stdout_bytes;
  result.stderr_bytes = output->stderr_bytes;
  memcpy(result.stdout_digest, output->stdout_digest,
         sizeof(result.stdout_digest));
  memcpy(result.stderr_digest, output->stderr_digest,
         sizeof(result.stderr_digest));
  result.started_at_ms = started_at_ms;
  result.finished_at_ms = finished_at_ms;
  result.worker_generation = provider->config.worker_generation;
  memcpy(result.correlation_id, request->correlation_id,
         sizeof(result.correlation_id));
  return mesh_mgmt_execution_result_sign_v1(
             &result, provider->config.result_private_key) ==
             MESH_MGMT_EXECUTION_RESULT_OK &&
         mesh_mgmt_execution_store_commit_result_v1(
             &provider->journal, &result, &entry) ==
             MESH_MGMT_EXECUTION_STORE_OK;
}

static void publish_completion(
    struct mesh_control_execution_provider_impl_v1 *provider,
    const uint8_t operation_id[MESH_CONTROL_ID_SIZE], uint16_t state,
    int journaled) {
  memset(&provider->completion, 0, sizeof(provider->completion));
  memcpy(provider->completion.operation_id, operation_id,
         sizeof(provider->completion.operation_id));
  provider->completion.state = state;
  provider->completion_journaled = journaled ? 1u : 0u;
  atomic_store_explicit(&provider->phase, EXECUTION_PROVIDER_READY,
                        memory_order_release);
}

static void run_job(void *argument) {
  execution_job_v1_t *job = (execution_job_v1_t *)argument;
  struct mesh_control_execution_provider_impl_v1 *provider;
  mesh_mgmt_execution_request_v1_t request;
  mesh_mgmt_execution_effective_policy_v1_t policy;
  mesh_mgmt_execution_runner_output_v1_t output;
  mesh_mgmt_execution_runner_result_t run_result;
  uint8_t request_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint64_t now_ms;
  uint64_t finished_at_ms;
  uint16_t completion_state = MESH_CONTROL_PROVIDER_FAILED;
  int claim = EXECUTION_CLAIM_ERROR;
  int journaled = 0;
  if (!job) return;
  provider = job->provider;
  now_ms = provider->config.now_ms(provider->config.now_context);
  memset(&request, 0, sizeof(request));
  memset(&policy, 0, sizeof(policy));
  memset(&output, 0, sizeof(output));
  if (now_ms != 0u &&
      limits_from_spec(provider, &job->request.spec, &policy)) {
    if (job->request.operation.action == MESH_CONTROL_DESIRED_DELETE ||
        job->request.spec.desired_state == MESH_CONTROL_FUNCTION_STOPPED) {
      completion_state = MESH_CONTROL_PROVIDER_COMPLETED;
    } else if (job->request.spec.desired_state ==
               MESH_CONTROL_FUNCTION_STAGED) {
      uint8_t digest[MESH_CONTROL_DIGEST_SIZE];
      execution_deployment_v1_t *deployment =
          &provider->deployments[job->deployment_index];
      if (mesh_mgmt_execution_runner_module_digest_v1(
              deployment->module_path, policy.limits.module_bytes, digest,
              NULL) == MESH_MGMT_EXECUTION_RUNNER_OK &&
          memcmp(digest, deployment->deployment.module_digest,
                 sizeof(digest)) == 0)
        completion_state = MESH_CONTROL_PROVIDER_COMPLETED;
      memset(digest, 0, sizeof(digest));
    } else if (now_ms <= UINT64_MAX - policy.limits.timeout_ms) {
      const mesh_mgmt_execution_deployment_v1_t *deployment =
          &provider->deployments[job->deployment_index].deployment;
      request.version = MESH_MGMT_EXECUTION_SCHEMA_V1;
      memcpy(request.command_id, job->request.operation.operation_id,
             sizeof(request.command_id));
      memset(request.grant_id, 0x47, sizeof(request.grant_id));
      memcpy(request.target_node_id, provider->config.local_node_id,
             sizeof(request.target_node_id));
      memcpy(request.deployment_id, deployment->deployment_id,
             sizeof(request.deployment_id));
      request.deployment_generation = deployment->generation;
      memcpy(request.package_digest, deployment->module_digest,
             sizeof(request.package_digest));
      request.input_kind = MESH_MGMT_EXECUTION_INPUT_NONE;
      request.output_mode = MESH_MGMT_EXECUTION_OUTPUT_DIGEST;
      request.deadline_ms = now_ms + policy.limits.timeout_ms;
      memcpy(request.request_nonce, job->request.operation.operation_id,
             sizeof(request.request_nonce));
      request.request_nonce[0] ^= 0xa5u;
      memcpy(request.correlation_id, job->request.operation.operation_id,
             sizeof(request.correlation_id));
      claim = begin_durable_claim(provider, &job->request, request_digest);
      if (claim == EXECUTION_CLAIM_COMPLETED) {
        completion_state = MESH_CONTROL_PROVIDER_COMPLETED;
        journaled = 1;
      } else if (claim == EXECUTION_CLAIM_FAILED) {
        journaled = 1;
      } else if (claim == EXECUTION_CLAIM_RUN) {
        run_result = mesh_mgmt_execution_process_run_v1(
            provider->config.process, &provider->runner, &request, &policy,
            now_ms, NULL, &output);
        finished_at_ms = provider->config.now_ms(provider->config.now_context);
        if (finished_at_ms >= now_ms &&
            commit_durable_result(provider, &job->request, &request,
                                  request_digest, run_result, &output, now_ms,
                                  finished_at_ms)) {
          journaled = 1;
          if (run_result == MESH_MGMT_EXECUTION_RUNNER_OK &&
              output.guest_exit_code == 0)
            completion_state = MESH_CONTROL_PROVIDER_COMPLETED;
        } else {
          atomic_store_explicit(&provider->journal_failed, true,
                                memory_order_release);
        }
      } else {
        atomic_store_explicit(&provider->journal_failed, true,
                              memory_order_release);
      }
    }
  }
  publish_completion(provider, job->request.operation.operation_id,
                     completion_state, journaled);
  memset(job, 0, sizeof(*job));
  free(job);
}

static mesh_control_result_t provider_try_start(
    void *context, const mesh_control_provider_request_v1_t *request) {
  struct mesh_control_execution_provider_impl_v1 *provider =
      (struct mesh_control_execution_provider_impl_v1 *)context;
  execution_job_v1_t *job;
  size_t deployment_index;
  int expected = EXECUTION_PROVIDER_IDLE;
  if (!provider || !request ||
      !atomic_load_explicit(&provider->accepting, memory_order_acquire))
    return MESH_CONTROL_CLOSED;
  if (atomic_load_explicit(&provider->journal_failed,
                           memory_order_acquire))
    return MESH_CONTROL_INVALID_STATE;
  if (request->spec.runtime != provider->config.runtime ||
      request->spec.required_capabilities > UINT32_MAX ||
      request->spec.limits.concurrency != 1u)
    return MESH_CONTROL_CONFLICT;
  deployment_index = find_deployment(provider, &request->spec);
  if (deployment_index == SIZE_MAX) return MESH_CONTROL_CONFLICT;
  if (!atomic_compare_exchange_strong_explicit(
          &provider->phase, &expected, EXECUTION_PROVIDER_RUNNING,
          memory_order_acq_rel, memory_order_acquire))
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  job = (execution_job_v1_t *)calloc(1u, sizeof(*job));
  if (!job) {
    atomic_store_explicit(&provider->phase, EXECUTION_PROVIDER_IDLE,
                          memory_order_release);
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  }
  job->provider = provider;
  job->request = *request;
  job->deployment_index = deployment_index;
  if (turbo_threadpool_try_submit(provider->pool, run_job, job) != 0) {
    memset(job, 0, sizeof(*job));
    free(job);
    atomic_store_explicit(&provider->phase, EXECUTION_PROVIDER_IDLE,
                          memory_order_release);
    return atomic_load_explicit(&provider->accepting, memory_order_acquire)
               ? MESH_CONTROL_RESOURCE_EXHAUSTED
               : MESH_CONTROL_CLOSED;
  }
  return MESH_CONTROL_OK;
}

static mesh_control_result_t provider_try_peek(
    void *context, mesh_control_provider_completion_v1_t *out_completion) {
  struct mesh_control_execution_provider_impl_v1 *provider =
      (struct mesh_control_execution_provider_impl_v1 *)context;
  if (!provider || !out_completion) return MESH_CONTROL_INVALID_ARG;
  if (atomic_load_explicit(&provider->phase, memory_order_acquire) !=
      EXECUTION_PROVIDER_READY)
    return MESH_CONTROL_EMPTY;
  *out_completion = provider->completion;
  return MESH_CONTROL_OK;
}

static void cleanup_terminal_claim(void *argument) {
  execution_cleanup_job_v1_t *job =
      (execution_cleanup_job_v1_t *)argument;
  struct mesh_control_execution_provider_impl_v1 *provider;
  mesh_mgmt_execution_store_result_t result;
  if (!job) return;
  provider = job->provider;
  result = mesh_mgmt_execution_store_forget_terminal_v1(
      &provider->journal, job->operation_id);
  if (result != MESH_MGMT_EXECUTION_STORE_OK &&
      result != MESH_MGMT_EXECUTION_STORE_NOT_FOUND)
    atomic_store_explicit(&provider->journal_failed, true,
                          memory_order_release);
  memset(job, 0, sizeof(*job));
  free(job);
  atomic_store_explicit(&provider->phase, EXECUTION_PROVIDER_IDLE,
                        memory_order_release);
}

static mesh_control_result_t provider_ack(
    void *context, const uint8_t operation_id[MESH_CONTROL_ID_SIZE]) {
  struct mesh_control_execution_provider_impl_v1 *provider =
      (struct mesh_control_execution_provider_impl_v1 *)context;
  execution_cleanup_job_v1_t *cleanup = NULL;
  if (!provider || !operation_id ||
      atomic_load_explicit(&provider->phase, memory_order_acquire) !=
          EXECUTION_PROVIDER_READY ||
      memcmp(provider->completion.operation_id, operation_id,
             MESH_CONTROL_ID_SIZE) != 0)
    return MESH_CONTROL_CONFLICT;
  if (provider->completion_journaled &&
      atomic_load_explicit(&provider->accepting, memory_order_acquire)) {
    cleanup = (execution_cleanup_job_v1_t *)calloc(1u, sizeof(*cleanup));
    if (!cleanup) return MESH_CONTROL_RESOURCE_EXHAUSTED;
    cleanup->provider = provider;
    memcpy(cleanup->operation_id, operation_id,
           sizeof(cleanup->operation_id));
    atomic_store_explicit(&provider->phase, EXECUTION_PROVIDER_CLEANING,
                          memory_order_release);
    if (turbo_threadpool_try_submit(provider->pool, cleanup_terminal_claim,
                                    cleanup) != 0) {
      atomic_store_explicit(&provider->phase, EXECUTION_PROVIDER_READY,
                            memory_order_release);
      memset(cleanup, 0, sizeof(*cleanup));
      free(cleanup);
      return MESH_CONTROL_RESOURCE_EXHAUSTED;
    }
  }
  memset(&provider->completion, 0, sizeof(provider->completion));
  provider->completion_journaled = 0u;
  if (!cleanup)
    atomic_store_explicit(&provider->phase, EXECUTION_PROVIDER_IDLE,
                          memory_order_release);
  return MESH_CONTROL_OK;
}

static void provider_close(void *context) {
  struct mesh_control_execution_provider_impl_v1 *provider =
      (struct mesh_control_execution_provider_impl_v1 *)context;
  if (!provider) return;
  if (atomic_exchange_explicit(&provider->accepting, false,
                               memory_order_acq_rel))
    turbo_threadpool_shutdown(provider->pool);
}

static int provider_is_drained(void *context) {
  struct mesh_control_execution_provider_impl_v1 *provider =
      (struct mesh_control_execution_provider_impl_v1 *)context;
  return provider &&
         !atomic_load_explicit(&provider->accepting, memory_order_acquire) &&
         atomic_load_explicit(&provider->phase, memory_order_acquire) ==
             EXECUTION_PROVIDER_IDLE;
}

mesh_control_result_t mesh_control_execution_provider_init_v1(
    mesh_control_execution_provider_v1_t *provider,
    const mesh_control_execution_provider_config_v1_t *config,
    mesh_control_provider_v1_t *out_descriptor) {
  struct mesh_control_execution_provider_impl_v1 *impl = NULL;
  turbo_threadpool_config_t pool_config;
  mesh_control_result_t failure_result = MESH_CONTROL_INVALID_ARG;
  size_t index;
  if (!provider || provider->impl || !config || !out_descriptor ||
      bytes_zero(config->provider_id, sizeof(config->provider_id)) ||
      bytes_zero(config->local_node_id, sizeof(config->local_node_id)) ||
      (config->runtime != MESH_CONTROL_FUNCTION_WASM &&
       config->runtime != MESH_CONTROL_FUNCTION_NATIVE) ||
      config->reserved != 0u || config->capabilities == 0u ||
      (config->capabilities & ~MESH_MGMT_EXECUTION_CAP_ALL) != 0u ||
      (config->runtime == MESH_CONTROL_FUNCTION_WASM &&
       config->capabilities !=
           MESH_MGMT_EXECUTION_RAW_WASM_CAPABILITIES_V1) ||
      !limits_valid(&config->hard_limits) || !config->deployments ||
      config->deployment_count == 0u ||
      config->deployment_count >
          MESH_CONTROL_EXECUTION_PROVIDER_MAX_DEPLOYMENTS_V1 ||
      !config->process || !config->process->initialized || !config->now_ms)
    return MESH_CONTROL_INVALID_ARG;
  if (!config->journal_path || config->journal_path[0] == '\0' ||
      config->journal_capacity == 0u ||
      config->journal_capacity > MESH_MGMT_EXECUTION_JOURNAL_MAX ||
      bytes_zero(config->result_private_key,
                 sizeof(config->result_private_key)) ||
      config->worker_generation == 0u)
    return MESH_CONTROL_INVALID_ARG;
  impl = (struct mesh_control_execution_provider_impl_v1 *)calloc(
      1u, sizeof(*impl));
  if (!impl) return MESH_CONTROL_RESOURCE_EXHAUSTED;
  if (mesh_mgmt_ed25519_public_from_private(
          config->result_private_key, impl->result_public_key) !=
      MESH_MGMT_CRYPTO_OK)
    goto failed;
  impl->deployments = (execution_deployment_v1_t *)calloc(
      config->deployment_count, sizeof(*impl->deployments));
  if (!impl->deployments) goto failed;
  impl->config = *config;
  if (mesh_mgmt_execution_runner_init_v1(&impl->runner,
                                          config->deployment_count) !=
      MESH_MGMT_EXECUTION_RUNNER_OK)
    goto failed;
  for (index = 0u; index < config->deployment_count; ++index) {
    const mesh_control_execution_deployment_v1_t *source =
        &config->deployments[index];
    mesh_mgmt_execution_deployment_runtime_v1_t expected_runtime =
        config->runtime == MESH_CONTROL_FUNCTION_WASM
            ? MESH_MGMT_EXECUTION_DEPLOYMENT_WASM_V1
            : MESH_MGMT_EXECUTION_DEPLOYMENT_NATIVE_PROCESS_V1;
    size_t prior;
    if (source->deployment.runtime != expected_runtime ||
        !source->deployment.module_path ||
        strlen(source->deployment.module_path) >= TURBO_FS_MAX_PATH ||
        bytes_zero(source->config_digest, sizeof(source->config_digest)) ||
        bytes_zero(source->network_policy_digest,
                   sizeof(source->network_policy_digest)))
      goto failed;
    for (prior = 0u; prior < index; ++prior)
      if (memcmp(impl->deployments[prior].deployment.module_digest,
                 source->deployment.module_digest,
                 MESH_CONTROL_DIGEST_SIZE) == 0)
        goto failed;
    impl->deployments[index].deployment = source->deployment;
    memcpy(impl->deployments[index].module_path,
           source->deployment.module_path,
           strlen(source->deployment.module_path) + 1u);
    impl->deployments[index].deployment.module_path =
        impl->deployments[index].module_path;
    memcpy(impl->deployments[index].config_digest, source->config_digest,
           sizeof(source->config_digest));
    memcpy(impl->deployments[index].network_policy_digest,
           source->network_policy_digest,
           sizeof(source->network_policy_digest));
    if (mesh_mgmt_execution_runner_register_v1(
            &impl->runner, &impl->deployments[index].deployment) !=
        MESH_MGMT_EXECUTION_RUNNER_OK)
      goto failed;
  }
  memset(&pool_config, 0, sizeof(pool_config));
  pool_config.num_threads = 1u;
  pool_config.queue_capacity = 1u;
  impl->pool = turbo_threadpool_create_with_config(&pool_config);
  if (!impl->pool) goto failed;
  if (mesh_mgmt_execution_store_open_v1(
          &impl->journal, config->journal_path,
          config->journal_capacity, NULL) != MESH_MGMT_EXECUTION_STORE_OK) {
    failure_result = MESH_CONTROL_INVALID_STATE;
    goto failed;
  }
  atomic_init(&impl->phase, EXECUTION_PROVIDER_IDLE);
  atomic_init(&impl->accepting, true);
  atomic_init(&impl->journal_failed, false);
  memset(out_descriptor, 0, sizeof(*out_descriptor));
  memcpy(out_descriptor->provider_id, config->provider_id,
         sizeof(out_descriptor->provider_id));
  out_descriptor->runtime = config->runtime;
  out_descriptor->ops.try_start = provider_try_start;
  out_descriptor->ops.try_peek_completion = provider_try_peek;
  out_descriptor->ops.ack_completion = provider_ack;
  out_descriptor->ops.close = provider_close;
  out_descriptor->ops.is_drained = provider_is_drained;
  out_descriptor->context = impl;
  provider->impl = impl;
  return MESH_CONTROL_OK;

failed:
  if (impl) {
    if (impl->pool) turbo_threadpool_destroy(impl->pool);
    if (impl->journal.open)
      mesh_mgmt_execution_store_close_v1(&impl->journal);
    mesh_mgmt_execution_runner_destroy_v1(&impl->runner);
    free(impl->deployments);
    memset(impl, 0, sizeof(*impl));
    free(impl);
  }
  return failure_result;
}

static int control_operation_is_terminal(uint16_t state) {
  return state == MESH_CONTROL_OPERATION_SUCCEEDED ||
         state == MESH_CONTROL_OPERATION_FAILED ||
         state == MESH_CONTROL_OPERATION_REJECTED ||
         state == MESH_CONTROL_OPERATION_EXPIRED ||
         state == MESH_CONTROL_OPERATION_INTERRUPTED;
}

mesh_control_result_t mesh_control_execution_provider_reconcile_journal_v1(
    mesh_control_execution_provider_v1_t *provider,
    const mesh_control_state_v1_t *control_state, size_t *out_removed) {
  struct mesh_control_execution_provider_impl_v1 *impl;
  mesh_mgmt_execution_journal_entry_v1_t *entries = NULL;
  size_t entry_count = 0u;
  size_t removed = 0u;
  size_t index;

  if (!provider || !provider->impl || !control_state || !out_removed)
    return MESH_CONTROL_INVALID_ARG;
  *out_removed = 0u;
  impl = provider->impl;
  if (!atomic_load_explicit(&impl->accepting, memory_order_acquire) ||
      atomic_load_explicit(&impl->phase, memory_order_acquire) !=
          EXECUTION_PROVIDER_IDLE)
    return MESH_CONTROL_INVALID_STATE;
  if (impl->journal.journal.count == 0u) return MESH_CONTROL_OK;
  entries = (mesh_mgmt_execution_journal_entry_v1_t *)calloc(
      impl->journal.journal.count, sizeof(*entries));
  if (!entries) return MESH_CONTROL_RESOURCE_EXHAUSTED;
  if (mesh_mgmt_execution_journal_export_v1(
          &impl->journal.journal, entries, impl->journal.journal.count,
          &entry_count) != MESH_MGMT_EXECUTION_OK) {
    free(entries);
    return MESH_CONTROL_INVALID_STATE;
  }
  for (index = 0u; index < entry_count; ++index) {
    mesh_control_operation_v1_t operation;
    mesh_control_result_t result;
    if (!mesh_mgmt_execution_state_is_terminal_v1(entries[index].state))
      continue;
    result = mesh_control_state_get_operation_v1(
        control_state, entries[index].command_id, &operation);
    if (result == MESH_CONTROL_EMPTY) continue;
    if (result != MESH_CONTROL_OK ||
        !control_operation_is_terminal(operation.state) ||
        mesh_mgmt_execution_store_forget_terminal_v1(
            &impl->journal, entries[index].command_id) !=
            MESH_MGMT_EXECUTION_STORE_OK) {
      free(entries);
      atomic_store_explicit(&impl->journal_failed, true,
                            memory_order_release);
      return MESH_CONTROL_INVALID_STATE;
    }
    removed++;
  }
  free(entries);
  *out_removed = removed;
  return MESH_CONTROL_OK;
}

void mesh_control_execution_provider_destroy_v1(
    mesh_control_execution_provider_v1_t *provider) {
  struct mesh_control_execution_provider_impl_v1 *impl;
  if (!provider || !provider->impl) return;
  impl = provider->impl;
  if (atomic_load_explicit(&impl->accepting, memory_order_acquire) ||
      atomic_load_explicit(&impl->phase, memory_order_acquire) !=
          EXECUTION_PROVIDER_IDLE)
    return;
  turbo_threadpool_wait(impl->pool);
  turbo_threadpool_destroy(impl->pool);
  mesh_mgmt_execution_store_close_v1(&impl->journal);
  mesh_mgmt_execution_runner_destroy_v1(&impl->runner);
  free(impl->deployments);
  memset(impl, 0, sizeof(*impl));
  free(impl);
  provider->impl = NULL;
}
