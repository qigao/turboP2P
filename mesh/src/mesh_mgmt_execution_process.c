#include "mesh_mgmt_execution_process.h"

#include "mesh_mgmt_execution_result.h"
#include "mesh_mgmt_wire.h"
#include "platform.h"
#include "turbo_error.h"
#include "turbo_process.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

#define PROCESS_KEY_SIZE 32u
#define PROCESS_POLICY_SIZE 68u
#define PROCESS_REQUEST_HEADER_SIZE 120u
#define PROCESS_REQUEST_HMAC_OFFSET 88u
#define PROCESS_OUTPUT_SIZE 392u
#define PROCESS_RESPONSE_SIZE 440u
#define PROCESS_RESPONSE_HMAC_OFFSET 408u

static const uint8_t REQUEST_MAGIC[4] = {'M', 'E', 'X', 'Q'};
static const uint8_t RESPONSE_MAGIC[4] = {'M', 'E', 'X', 'R'};

static int zero_bytes(const uint8_t *bytes, size_t size) {
  uint8_t value = 0u;
  size_t index;
  for (index = 0u; index < size; ++index) value |= bytes[index];
  return value == 0u;
}

static int absolute_path(const char *path) {
  size_t size;
  if (!path) return 0;
  size = strlen(path);
  if (size == 0u || size >= TURBO_FS_MAX_PATH) return 0;
  if (path[0] == '/') return 1;
  return size >= 3u && path[1] == ':' &&
         (path[2] == '/' || path[2] == '\\');
}

static int digest_equal(const uint8_t lhs[32], const uint8_t rhs[32]) {
  return CRYPTO_memcmp(lhs, rhs, 32u) == 0;
}

static int verify_file(const char *path, uint32_t maximum,
                       const uint8_t expected[32]) {
  uint8_t digest[32];
  int result = mesh_mgmt_execution_runner_module_digest_v1(
                   path, maximum, digest, NULL) ==
                   MESH_MGMT_EXECUTION_RUNNER_OK &&
               digest_equal(digest, expected);
  OPENSSL_cleanse(digest, sizeof(digest));
  return result;
}

static int hmac_sha256(const uint8_t key[32], const uint8_t *data,
                       size_t size, uint8_t output[32]) {
  unsigned int output_size = 0u;
  return HMAC(EVP_sha256(), key, 32, data, size, output, &output_size) &&
         output_size == 32u;
}

static int request_hmac(const uint8_t key[32], const uint8_t *header,
                        const uint8_t *request, size_t request_size,
                        uint8_t output[32]) {
  HMAC_CTX *context = HMAC_CTX_new();
  unsigned int output_size = 0u;
  int ok = context && HMAC_Init_ex(context, key, 32, EVP_sha256(), NULL) &&
           HMAC_Update(context, header, PROCESS_REQUEST_HMAC_OFFSET) &&
           HMAC_Update(context, request, request_size) &&
           HMAC_Final(context, output, &output_size) && output_size == 32u;
  HMAC_CTX_free(context);
  return ok;
}

static size_t encode_limits(const mesh_mgmt_execution_limits_v1_t *limits,
                            uint8_t *output) {
  size_t offset = 0u;
#define WRITE32(value) do { mesh_mgmt_wire_write_u32(output + offset, (value)); offset += 4u; } while (0)
#define WRITE64(value) do { mesh_mgmt_wire_write_u64(output + offset, (value)); offset += 8u; } while (0)
  WRITE32(limits->module_bytes);
  WRITE32(limits->stack_bytes);
  WRITE32(limits->linear_memory_bytes);
  WRITE64(limits->timeout_ms);
  WRITE64(limits->control_flow_steps);
  WRITE32(limits->host_calls);
  WRITE64(limits->copied_guest_bytes);
  WRITE64(limits->input_bytes);
  WRITE64(limits->stdout_bytes);
  WRITE64(limits->stderr_bytes);
#undef WRITE32
#undef WRITE64
  return offset;
}

static int decode_limits(const uint8_t *input,
                         mesh_mgmt_execution_limits_v1_t *limits) {
  size_t offset = 0u;
#define READ32(field) do { (field) = mesh_mgmt_wire_read_u32(input + offset); offset += 4u; } while (0)
#define READ64(field) do { (field) = mesh_mgmt_wire_read_u64(input + offset); offset += 8u; } while (0)
  memset(limits, 0, sizeof(*limits));
  READ32(limits->module_bytes);
  READ32(limits->stack_bytes);
  READ32(limits->linear_memory_bytes);
  READ64(limits->timeout_ms);
  READ64(limits->control_flow_steps);
  READ32(limits->host_calls);
  READ64(limits->copied_guest_bytes);
  READ64(limits->input_bytes);
  READ64(limits->stdout_bytes);
  READ64(limits->stderr_bytes);
#undef READ32
#undef READ64
  return offset == 64u;
}

static size_t encode_output(const mesh_mgmt_execution_runner_output_v1_t *out,
                            uint8_t *bytes) {
  size_t offset = 0u;
  mesh_mgmt_wire_write_u32(bytes + offset, (uint32_t)out->runtime_code); offset += 4u;
  mesh_mgmt_wire_write_u32(bytes + offset, (uint32_t)out->runtime_stage); offset += 4u;
  mesh_mgmt_wire_write_u32(bytes + offset, (uint32_t)out->guest_exit_code); offset += 4u;
#define WRITE64(value) do { mesh_mgmt_wire_write_u64(bytes + offset, (value)); offset += 8u; } while (0)
  WRITE64(out->invocations); WRITE64(out->host_calls);
  WRITE64(out->copied_guest_bytes); WRITE64(out->modules_loaded);
  WRITE64(out->modules_rejected);
#undef WRITE64
  mesh_mgmt_wire_write_u32(bytes + offset, out->open_handles); offset += 4u;
  mesh_mgmt_wire_write_u64(bytes + offset, out->stdout_bytes); offset += 8u;
  mesh_mgmt_wire_write_u64(bytes + offset, out->stderr_bytes); offset += 8u;
  memcpy(bytes + offset, out->stdout_digest, 32u); offset += 32u;
  memcpy(bytes + offset, out->stderr_digest, 32u); offset += 32u;
  memcpy(bytes + offset, out->error_text, sizeof(out->error_text));
  offset += sizeof(out->error_text);
  return offset;
}

static int decode_output(const uint8_t *bytes,
                         mesh_mgmt_execution_runner_output_v1_t *out) {
  size_t offset = 0u;
  memset(out, 0, sizeof(*out));
  out->runtime_code = (int32_t)mesh_mgmt_wire_read_u32(bytes + offset); offset += 4u;
  out->runtime_stage = (int32_t)mesh_mgmt_wire_read_u32(bytes + offset); offset += 4u;
  out->guest_exit_code = (int32_t)mesh_mgmt_wire_read_u32(bytes + offset); offset += 4u;
#define READ64(field) do { (field) = mesh_mgmt_wire_read_u64(bytes + offset); offset += 8u; } while (0)
  READ64(out->invocations); READ64(out->host_calls);
  READ64(out->copied_guest_bytes); READ64(out->modules_loaded);
  READ64(out->modules_rejected);
#undef READ64
  out->open_handles = mesh_mgmt_wire_read_u32(bytes + offset); offset += 4u;
  out->stdout_bytes = mesh_mgmt_wire_read_u64(bytes + offset); offset += 8u;
  out->stderr_bytes = mesh_mgmt_wire_read_u64(bytes + offset); offset += 8u;
  memcpy(out->stdout_digest, bytes + offset, 32u); offset += 32u;
  memcpy(out->stderr_digest, bytes + offset, 32u); offset += 32u;
  memcpy(out->error_text, bytes + offset, sizeof(out->error_text));
  out->error_text[sizeof(out->error_text) - 1u] = '\0';
  offset += sizeof(out->error_text);
  return offset == PROCESS_OUTPUT_SIZE;
}

mesh_mgmt_execution_runner_result_t mesh_mgmt_execution_process_init_v1(
    mesh_mgmt_execution_process_v1_t *process,
    const mesh_mgmt_execution_process_config_v1_t *config) {
  size_t index;
  if (!process || process->initialized || !config ||
      !absolute_path(config->worker_program) ||
      zero_bytes(config->worker_sha256, sizeof(config->worker_sha256)) ||
      config->maximum_worker_bytes == 0u ||
      config->maximum_output_bytes < PROCESS_RESPONSE_SIZE ||
      (config->native_capabilities & ~MESH_MGMT_EXECUTION_CAP_ALL) != 0u ||
      config->sandbox_arg_count > MESH_MGMT_EXECUTION_PROCESS_MAX_SANDBOX_ARGS_V1 ||
      (config->sandbox_arg_count && !config->sandbox_args) ||
      (!config->sandbox_program && !config->allow_direct_process_for_tests))
    return MESH_MGMT_EXECUTION_RUNNER_INVALID_ARG;
  if (config->sandbox_program &&
      (!absolute_path(config->sandbox_program) ||
       zero_bytes(config->sandbox_sha256, sizeof(config->sandbox_sha256))))
    return MESH_MGMT_EXECUTION_RUNNER_INVALID_ARG;
  for (index = 0u; index < config->sandbox_arg_count; ++index)
    if (!config->sandbox_args[index] || !config->sandbox_args[index][0] ||
        strlen(config->sandbox_args[index]) >=
            MESH_MGMT_EXECUTION_PROCESS_MAX_SANDBOX_ARG_SIZE_V1)
      return MESH_MGMT_EXECUTION_RUNNER_INVALID_ARG;
  memset(process, 0, sizeof(*process));
  process->config = *config;
  memcpy(process->worker_program, config->worker_program,
         strlen(config->worker_program) + 1u);
  process->config.worker_program = process->worker_program;
  if (config->sandbox_program) {
    memcpy(process->sandbox_program, config->sandbox_program,
           strlen(config->sandbox_program) + 1u);
    process->config.sandbox_program = process->sandbox_program;
  }
  for (index = 0u; index < config->sandbox_arg_count; ++index) {
    memcpy(process->sandbox_arg_storage[index], config->sandbox_args[index],
           strlen(config->sandbox_args[index]) + 1u);
    process->sandbox_args[index] = process->sandbox_arg_storage[index];
  }
  process->config.sandbox_args = process->sandbox_args;
  process->initialized = 1u;
  return MESH_MGMT_EXECUTION_RUNNER_OK;
}

static int write_bytes(turbo_process_t *child, const uint8_t *data, size_t size) {
  size_t offset = 0u;
  while (offset < size) {
    size_t written = 0u;
    if (turbo_process_write_stdin(child, data + offset, size - offset,
                                  &written) != TURBO_OK || written == 0u)
      return 0;
    offset += written;
  }
  return 1;
}

static size_t read_stdout_all(turbo_process_t *child, uint8_t *output,
                              size_t capacity) {
  size_t total = 0u;
  for (;;) {
    size_t count = 0u;
    int result = turbo_process_read_stdout(child, output + total,
                                           capacity - total, &count);
    total += count;
    if (result == TURBO_EOF) return total;
    if (result != TURBO_OK || total == capacity) return 0u;
  }
}

static mesh_mgmt_execution_runner_result_t hash_captured_stream(
    turbo_process_t *child, int stderr_stream, uint64_t maximum_bytes,
    uint8_t digest[MESH_MGMT_EXECUTION_DIGEST_SIZE], uint64_t *out_bytes) {
  EVP_MD_CTX *hash = NULL;
  uint8_t buffer[4096];
  uint64_t total = 0u;
  unsigned int digest_size = 0u;
  mesh_mgmt_execution_runner_result_t result =
      MESH_MGMT_EXECUTION_RUNNER_RUNTIME;
  hash = EVP_MD_CTX_new();
  if (!hash || EVP_DigestInit_ex(hash, EVP_sha256(), NULL) != 1)
    goto cleanup;
  for (;;) {
    size_t count = 0u;
    int read_result = stderr_stream
                          ? turbo_process_read_stderr(child, buffer,
                                                      sizeof(buffer), &count)
                          : turbo_process_read_stdout(child, buffer,
                                                      sizeof(buffer), &count);
    if (count > maximum_bytes - total) {
      result = MESH_MGMT_EXECUTION_RUNNER_RESOURCE_EXHAUSTED;
      goto cleanup;
    }
    if (count != 0u &&
        EVP_DigestUpdate(hash, buffer, count) != 1)
      goto cleanup;
    total += count;
    if (read_result == TURBO_EOF) break;
    if (read_result != TURBO_OK) goto cleanup;
  }
  if (EVP_DigestFinal_ex(hash, digest, &digest_size) != 1 ||
      digest_size != MESH_MGMT_EXECUTION_DIGEST_SIZE)
    goto cleanup;
  *out_bytes = total;
  result = MESH_MGMT_EXECUTION_RUNNER_OK;
cleanup:
  OPENSSL_cleanse(buffer, sizeof(buffer));
  EVP_MD_CTX_free(hash);
  return result;
}

static mesh_mgmt_execution_runner_result_t run_native_process(
    mesh_mgmt_execution_process_v1_t *process,
    const mesh_mgmt_execution_deployment_v1_t *deployment,
    const char *module_path, const mesh_mgmt_execution_request_v1_t *request,
    const mesh_mgmt_execution_effective_policy_v1_t *policy,
    mesh_mgmt_execution_runner_output_v1_t *out) {
  const char *args[MESH_MGMT_EXECUTION_PROCESS_MAX_SANDBOX_ARGS_V1 + 2u];
  size_t arg_count = 0u;
  size_t index;
  size_t capture_limit;
  uint64_t policy_output_limit;
  turbo_process_options_t options;
  turbo_process_t *child = NULL;
  turbo_process_result_t child_result;
  mesh_mgmt_execution_runner_result_t result =
      MESH_MGMT_EXECUTION_RUNNER_RUNTIME;

  if (deployment->runtime !=
          MESH_MGMT_EXECUTION_DEPLOYMENT_NATIVE_PROCESS_V1 ||
      process->config.native_capabilities == 0u ||
      policy->capabilities != process->config.native_capabilities ||
      (request->input_kind != MESH_MGMT_EXECUTION_INPUT_NONE &&
       request->input_kind != MESH_MGMT_EXECUTION_INPUT_INLINE) ||
      (request->output_mode != MESH_MGMT_EXECUTION_OUTPUT_NONE &&
       request->output_mode != MESH_MGMT_EXECUTION_OUTPUT_DIGEST) ||
      request->inline_input_size > policy->limits.input_bytes)
    return MESH_MGMT_EXECUTION_RUNNER_POLICY_DENIED;
  if (!digest_equal(deployment->module_digest, request->package_digest) ||
      !verify_file(module_path, policy->limits.module_bytes,
                   deployment->module_digest)) {
    process->rejected_digest++;
    return MESH_MGMT_EXECUTION_RUNNER_DIGEST_MISMATCH;
  }
  if (policy->limits.stdout_bytes > UINT64_MAX - policy->limits.stderr_bytes)
    return MESH_MGMT_EXECUTION_RUNNER_RESOURCE_EXHAUSTED;
  policy_output_limit =
      policy->limits.stdout_bytes + policy->limits.stderr_bytes;
  capture_limit = policy_output_limit < process->config.maximum_output_bytes
                      ? (size_t)policy_output_limit
                      : process->config.maximum_output_bytes;
  if (capture_limit == 0u)
    return MESH_MGMT_EXECUTION_RUNNER_RESOURCE_EXHAUSTED;

  if (process->config.sandbox_program) {
    for (index = 0u; index < process->config.sandbox_arg_count; ++index)
      args[arg_count++] = process->config.sandbox_args[index];
    args[arg_count++] = module_path;
    args[arg_count] = NULL;
  }
  turbo_process_options_init(&options);
  options.program = process->config.sandbox_program
                        ? process->sandbox_program
                        : module_path;
  options.args = process->config.sandbox_program ? args : NULL;
  options.env = NULL;
  options.flags = TURBO_PROCESS_PIPE_STDIN | TURBO_PROCESS_CAPTURE_STDOUT |
                  TURBO_PROCESS_CAPTURE_STDERR;
  if (process->config.sandbox_program)
    options.flags |= TURBO_PROCESS_CLEAN_ENVIRONMENT;
  options.timeout_ms = policy->limits.timeout_ms;
  options.max_output_bytes = capture_limit;
  process->started++;
  if (turbo_process_spawn(&options, &child) != TURBO_OK || !child)
    goto cleanup;
  if ((request->inline_input_size != 0u &&
       !write_bytes(child, request->inline_input,
                    request->inline_input_size)) ||
      turbo_process_close_stdin(child) != TURBO_OK ||
      turbo_process_wait(child, &child_result) != TURBO_OK)
    goto cleanup;
  if (child_result.state == TURBO_PROCESS_TIMED_OUT) {
    process->timed_out++;
    goto cleanup;
  }
  if (child_result.state == TURBO_PROCESS_OUTPUT_LIMIT_EXCEEDED) {
    result = MESH_MGMT_EXECUTION_RUNNER_RESOURCE_EXHAUSTED;
    goto cleanup;
  }
  if (child_result.state != TURBO_PROCESS_EXITED) {
    process->crashed++;
    goto cleanup;
  }
  result = hash_captured_stream(child, 0, policy->limits.stdout_bytes,
                                out->stdout_digest, &out->stdout_bytes);
  if (result != MESH_MGMT_EXECUTION_RUNNER_OK) goto cleanup;
  result = hash_captured_stream(child, 1, policy->limits.stderr_bytes,
                                out->stderr_digest, &out->stderr_bytes);
  if (result != MESH_MGMT_EXECUTION_RUNNER_OK) goto cleanup;
  out->guest_exit_code = child_result.exit_code;
  out->runtime_stage = 1;
  out->invocations = 1u;
  out->copied_guest_bytes = request->inline_input_size;
  out->modules_loaded = 1u;
  process->succeeded++;
  result = MESH_MGMT_EXECUTION_RUNNER_OK;
cleanup:
  if (child) turbo_process_destroy(child);
  return result;
}

mesh_mgmt_execution_runner_result_t mesh_mgmt_execution_process_run_v1(
    void *context, const mesh_mgmt_execution_runner_v1_t *runner,
    const mesh_mgmt_execution_request_v1_t *request,
    const mesh_mgmt_execution_effective_policy_v1_t *policy,
    uint64_t now_ms, const mesh_mgmt_execution_runner_io_v1_t *io,
    mesh_mgmt_execution_runner_output_v1_t *out) {
  mesh_mgmt_execution_process_v1_t *process =
      (mesh_mgmt_execution_process_v1_t *)context;
  mesh_mgmt_execution_deployment_v1_t deployment;
  char module_path[TURBO_FS_MAX_PATH];
  char generation[32];
  char deployment_hex[33];
  char digest_hex[65];
  const char *args[MESH_MGMT_EXECUTION_PROCESS_MAX_SANDBOX_ARGS_V1 + 7u];
  uint8_t request_bytes[MESH_MGMT_EXECUTION_REQUEST_CANONICAL_MAX_SIZE_V1];
  uint8_t frame[PROCESS_REQUEST_HEADER_SIZE + MESH_MGMT_EXECUTION_REQUEST_CANONICAL_MAX_SIZE_V1];
  uint8_t response[PROCESS_RESPONSE_SIZE + 1u];
  uint8_t key[PROCESS_KEY_SIZE];
  uint8_t expected_hmac[32];
  size_t request_size = 0u;
  size_t arg_count = 0u;
  size_t input_size;
  size_t response_size;
  size_t index;
  turbo_process_options_t options;
  turbo_process_t *child = NULL;
  turbo_process_result_t child_result;
  int32_t runner_code;
  mesh_mgmt_execution_runner_result_t result = MESH_MGMT_EXECUTION_RUNNER_RUNTIME;
  (void)io;
  if (!process || !process->initialized || !runner || !request || !policy ||
      now_ms == 0u || !out)
    return MESH_MGMT_EXECUTION_RUNNER_INVALID_ARG;
  memset(out, 0, sizeof(*out));
  if (mesh_mgmt_execution_request_validate_v1(request, now_ms) !=
      MESH_MGMT_EXECUTION_OK)
    return MESH_MGMT_EXECUTION_RUNNER_INVALID_ARG;
  if (process->config.sandbox_program &&
      !verify_file(process->sandbox_program, process->config.maximum_worker_bytes,
                   process->config.sandbox_sha256)) {
    process->rejected_sandbox++;
    return MESH_MGMT_EXECUTION_RUNNER_POLICY_DENIED;
  }
  if (mesh_mgmt_execution_runner_resolve_v1(
          runner, request->deployment_id, request->deployment_generation,
          &deployment, module_path, sizeof(module_path)) !=
      MESH_MGMT_EXECUTION_RUNNER_OK)
    return MESH_MGMT_EXECUTION_RUNNER_NOT_FOUND;
  if (deployment.runtime ==
      MESH_MGMT_EXECUTION_DEPLOYMENT_NATIVE_PROCESS_V1)
    return run_native_process(process, &deployment, module_path, request,
                              policy, out);
  if (!verify_file(process->worker_program,
                   process->config.maximum_worker_bytes,
                   process->config.worker_sha256)) {
    process->rejected_digest++;
    return MESH_MGMT_EXECUTION_RUNNER_DIGEST_MISMATCH;
  }
  if (mesh_mgmt_execution_request_encode_canonical_v1(
          request, request_bytes, sizeof(request_bytes), &request_size) !=
      MESH_MGMT_EXECUTION_RESULT_OK)
    return MESH_MGMT_EXECUTION_RUNNER_INVALID_ARG;
  memset(frame, 0, sizeof(frame));
  memcpy(frame, REQUEST_MAGIC, sizeof(REQUEST_MAGIC));
  mesh_mgmt_wire_write_u16(frame + 4u, 1u);
  mesh_mgmt_wire_write_u32(frame + 8u, (uint32_t)request_size);
  mesh_mgmt_wire_write_u32(frame + 12u, policy->capabilities);
  if (encode_limits(&policy->limits, frame + 16u) != 64u)
    return MESH_MGMT_EXECUTION_RUNNER_INVALID_ARG;
  mesh_mgmt_wire_write_u64(frame + 80u, now_ms);
  memcpy(frame + PROCESS_REQUEST_HEADER_SIZE, request_bytes, request_size);
  if (turbo_secure_random(key, sizeof(key)) != 0)
    return MESH_MGMT_EXECUTION_RUNNER_RESOURCE_EXHAUSTED;
  if (!request_hmac(key, frame, request_bytes, request_size,
                    frame + PROCESS_REQUEST_HMAC_OFFSET)) {
    OPENSSL_cleanse(key, sizeof(key));
    return MESH_MGMT_EXECUTION_RUNNER_RESOURCE_EXHAUSTED;
  }
  for (index = 0u; index < 16u; ++index)
    (void)snprintf(deployment_hex + index * 2u, 3u, "%02x", deployment.deployment_id[index]);
  for (index = 0u; index < 32u; ++index)
    (void)snprintf(digest_hex + index * 2u, 3u, "%02x", deployment.module_digest[index]);
  (void)snprintf(generation, sizeof(generation), "%llu",
                 (unsigned long long)deployment.generation);
  if (process->config.sandbox_program)
    for (index = 0u; index < process->config.sandbox_arg_count; ++index)
      args[arg_count++] = process->config.sandbox_args[index];
  if (process->config.sandbox_program) args[arg_count++] = process->worker_program;
  args[arg_count++] = "--mesh-execution-worker-v1";
  args[arg_count++] = module_path;
  args[arg_count++] = deployment_hex;
  args[arg_count++] = generation;
  args[arg_count++] = digest_hex;
  args[arg_count] = NULL;
  turbo_process_options_init(&options);
  options.program = process->config.sandbox_program
                        ? process->sandbox_program
                        : process->worker_program;
  options.args = args;
  options.env = NULL;
  options.flags = TURBO_PROCESS_PIPE_STDIN | TURBO_PROCESS_CAPTURE_STDOUT |
                  TURBO_PROCESS_CAPTURE_STDERR;
  if (process->config.sandbox_program)
    options.flags |= TURBO_PROCESS_CLEAN_ENVIRONMENT;
  options.timeout_ms = policy->limits.timeout_ms;
  options.max_output_bytes = process->config.maximum_output_bytes;
  process->started++;
  if (turbo_process_spawn(&options, &child) != TURBO_OK || !child)
    goto cleanup;
  input_size = PROCESS_REQUEST_HEADER_SIZE + request_size;
  if (!write_bytes(child, key, sizeof(key)) ||
      !write_bytes(child, frame, input_size) ||
      turbo_process_close_stdin(child) != TURBO_OK ||
      turbo_process_wait(child, &child_result) != TURBO_OK)
    goto cleanup;
  if (child_result.state == TURBO_PROCESS_TIMED_OUT) {
    process->timed_out++;
    result = MESH_MGMT_EXECUTION_RUNNER_RUNTIME;
    goto cleanup;
  }
  if (child_result.state != TURBO_PROCESS_EXITED || child_result.exit_code != 0) {
    process->crashed++;
    goto cleanup;
  }
  response_size = read_stdout_all(child, response, sizeof(response));
  if (response_size != PROCESS_RESPONSE_SIZE ||
      memcmp(response, RESPONSE_MAGIC, sizeof(RESPONSE_MAGIC)) != 0 ||
      mesh_mgmt_wire_read_u16(response + 4u) != 1u ||
      mesh_mgmt_wire_read_u32(response + 12u) != PROCESS_OUTPUT_SIZE ||
      !hmac_sha256(key, response, PROCESS_RESPONSE_HMAC_OFFSET,
                   expected_hmac) ||
      !digest_equal(expected_hmac, response + PROCESS_RESPONSE_HMAC_OFFSET) ||
      !decode_output(response + 16u, out))
    goto cleanup;
  runner_code = (int32_t)mesh_mgmt_wire_read_u32(response + 8u);
  process->succeeded++;
  result = (mesh_mgmt_execution_runner_result_t)runner_code;
cleanup:
  if (child) turbo_process_destroy(child);
  OPENSSL_cleanse(key, sizeof(key));
  OPENSSL_cleanse(expected_hmac, sizeof(expected_hmac));
  return result;
}

static int parse_hex(const char *text, uint8_t *output, size_t size) {
  size_t index;
  if (!text || strlen(text) != size * 2u) return 0;
  for (index = 0u; index < size; ++index) {
    unsigned int value;
    if (sscanf(text + index * 2u, "%2x", &value) != 1) return 0;
    output[index] = (uint8_t)value;
  }
  return 1;
}

int mesh_mgmt_execution_process_worker_main_v1(int argc, char **argv) {
  mesh_mgmt_execution_runner_v1_t runner;
  mesh_mgmt_execution_deployment_v1_t deployment;
  mesh_mgmt_execution_request_v1_t request;
  mesh_mgmt_execution_effective_policy_v1_t policy;
  mesh_mgmt_execution_runner_output_v1_t output;
  uint8_t key[32];
  uint8_t frame[PROCESS_REQUEST_HEADER_SIZE + MESH_MGMT_EXECUTION_REQUEST_CANONICAL_MAX_SIZE_V1];
  uint8_t response[PROCESS_RESPONSE_SIZE];
  uint8_t hmac[32];
  uint32_t request_size;
  uint64_t now_ms;
  unsigned long long generation;
  int runner_code;
  int exit_code = 1;
#ifdef _WIN32
  (void)_setmode(_fileno(stdin), _O_BINARY);
  (void)_setmode(_fileno(stdout), _O_BINARY);
#endif
  if (argc != 6 || strcmp(argv[1], "--mesh-execution-worker-v1") != 0 ||
      sscanf(argv[4], "%llu", &generation) != 1 || generation == 0u)
    return 2;
  memset(&deployment, 0, sizeof(deployment));
  if (!parse_hex(argv[3], deployment.deployment_id,
                 sizeof(deployment.deployment_id)) ||
      !parse_hex(argv[5], deployment.module_digest,
                 sizeof(deployment.module_digest)))
    return 2;
  deployment.generation = (uint64_t)generation;
  deployment.module_path = argv[2];
  if (fread(key, 1u, sizeof(key), stdin) != sizeof(key) ||
      fread(frame, 1u, PROCESS_REQUEST_HEADER_SIZE, stdin) !=
          PROCESS_REQUEST_HEADER_SIZE ||
      memcmp(frame, REQUEST_MAGIC, sizeof(REQUEST_MAGIC)) != 0 ||
      mesh_mgmt_wire_read_u16(frame + 4u) != 1u)
    goto cleanup;
  request_size = mesh_mgmt_wire_read_u32(frame + 8u);
  if (request_size == 0u ||
      request_size > MESH_MGMT_EXECUTION_REQUEST_CANONICAL_MAX_SIZE_V1 ||
      fread(frame + PROCESS_REQUEST_HEADER_SIZE, 1u, request_size, stdin) !=
          request_size ||
      !request_hmac(key, frame, frame + PROCESS_REQUEST_HEADER_SIZE,
                    request_size, hmac) ||
      !digest_equal(hmac, frame + PROCESS_REQUEST_HMAC_OFFSET) ||
      mesh_mgmt_execution_request_decode_canonical_v1(
          frame + PROCESS_REQUEST_HEADER_SIZE, request_size, &request) !=
          MESH_MGMT_EXECUTION_RESULT_OK)
    goto cleanup;
  memset(&policy, 0, sizeof(policy));
  policy.capabilities = mesh_mgmt_wire_read_u32(frame + 12u);
  now_ms = mesh_mgmt_wire_read_u64(frame + 80u);
  if (!decode_limits(frame + 16u, &policy.limits) ||
      now_ms == 0u ||
      mesh_mgmt_execution_runner_init_v1(&runner, 1u) !=
          MESH_MGMT_EXECUTION_RUNNER_OK)
    goto cleanup;
  if (mesh_mgmt_execution_runner_register_v1(&runner, &deployment) !=
      MESH_MGMT_EXECUTION_RUNNER_OK) {
    mesh_mgmt_execution_runner_destroy_v1(&runner);
    goto cleanup;
  }
  memset(&output, 0, sizeof(output));
  runner_code = mesh_mgmt_execution_runner_run_v1(
      &runner, &request, &policy, now_ms, NULL, &output);
  mesh_mgmt_execution_runner_destroy_v1(&runner);
  memset(response, 0, sizeof(response));
  memcpy(response, RESPONSE_MAGIC, sizeof(RESPONSE_MAGIC));
  mesh_mgmt_wire_write_u16(response + 4u, 1u);
  mesh_mgmt_wire_write_u32(response + 8u, (uint32_t)runner_code);
  mesh_mgmt_wire_write_u32(response + 12u, PROCESS_OUTPUT_SIZE);
  if (encode_output(&output, response + 16u) != PROCESS_OUTPUT_SIZE ||
      !hmac_sha256(key, response, PROCESS_RESPONSE_HMAC_OFFSET,
                   response + PROCESS_RESPONSE_HMAC_OFFSET) ||
      fwrite(response, 1u, sizeof(response), stdout) != sizeof(response) ||
      fflush(stdout) != 0)
    goto cleanup;
  exit_code = 0;
cleanup:
  OPENSSL_cleanse(key, sizeof(key));
  OPENSSL_cleanse(hmac, sizeof(hmac));
  return exit_code;
}

void mesh_mgmt_execution_process_destroy_v1(
    mesh_mgmt_execution_process_v1_t *process) {
  if (process) memset(process, 0, sizeof(*process));
}
