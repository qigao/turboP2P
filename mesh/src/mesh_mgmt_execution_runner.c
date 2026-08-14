#include "mesh_mgmt_execution_runner.h"

#include "turbo_fs.h"
#include "turbo_runtime.h"

#include <ctype.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

#define MESH_MGMT_EXECUTION_RUNNER_HASH_CHUNK (16u * 1024u)

struct mesh_mgmt_execution_deployment_entry_v1_s {
  uint8_t deployment_id[MESH_MGMT_EXECUTION_ID_SIZE];
  uint64_t generation;
  uint8_t module_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  char module_path[TURBO_FS_MAX_PATH];
  mesh_mgmt_execution_deployment_runtime_v1_t runtime;
  uint8_t occupied;
};

typedef struct {
  const mesh_mgmt_execution_runner_io_v1_t *io;
  EVP_MD_CTX *stdout_hash;
  EVP_MD_CTX *stderr_hash;
  uint64_t stdout_bytes;
  uint64_t stderr_bytes;
} runner_io_context_t;

static int bytes_are_zero(const uint8_t *bytes, size_t size) {
  size_t index;

  for (index = 0u; index < size; ++index) {
    if (bytes[index] != 0u)
      return 0;
  }
  return 1;
}

static int path_is_absolute(const char *path) {
  if (!path || path[0] == '\0')
    return 0;
  if (path[0] == '/')
    return 1;
  if ((path[0] == '\\' && path[1] == '\\') ||
      (isalpha((unsigned char)path[0]) && path[1] == ':' &&
       (path[2] == '/' || path[2] == '\\')))
    return 1;
  return 0;
}

static const mesh_mgmt_execution_deployment_entry_v1_t *find_deployment(
    const mesh_mgmt_execution_runner_v1_t *runner,
    const uint8_t deployment_id[MESH_MGMT_EXECUTION_ID_SIZE],
    uint64_t generation) {
  size_t index;

  for (index = 0u; index < runner->capacity; ++index) {
    const mesh_mgmt_execution_deployment_entry_v1_t *entry =
        &runner->entries[index];
    if (entry->occupied && entry->generation == generation &&
        memcmp(entry->deployment_id, deployment_id,
               MESH_MGMT_EXECUTION_ID_SIZE) == 0)
      return entry;
  }
  return NULL;
}

static void copy_runtime_error(const turbo_runtime_t *runtime,
                               mesh_mgmt_execution_runner_output_v1_t *out) {
  const char *error_text = turbo_runtime_last_error(runtime);

  if (!error_text)
    return;
  strncpy(out->error_text, error_text, sizeof(out->error_text) - 1u);
  out->error_text[sizeof(out->error_text) - 1u] = '\0';
}

static int write_stdout(const uint8_t *data, size_t size, void *user_data) {
  runner_io_context_t *context = (runner_io_context_t *)user_data;

  if (EVP_DigestUpdate(context->stdout_hash, data, size) != 1)
    return -1;
  context->stdout_bytes += size;
  if (context->io && context->io->write_stdout)
    return context->io->write_stdout(data, size, context->io->user_data);
  return 0;
}

static int write_stderr(const uint8_t *data, size_t size, void *user_data) {
  runner_io_context_t *context = (runner_io_context_t *)user_data;

  if (EVP_DigestUpdate(context->stderr_hash, data, size) != 1)
    return -1;
  context->stderr_bytes += size;
  if (context->io && context->io->write_stderr)
    return context->io->write_stderr(data, size, context->io->user_data);
  return 0;
}

static mesh_mgmt_execution_runner_result_t finish_output_hashes(
    runner_io_context_t *context,
    mesh_mgmt_execution_runner_output_v1_t *out) {
  unsigned int digest_size = 0u;

  if (EVP_DigestFinal_ex(context->stdout_hash, out->stdout_digest,
                         &digest_size) != 1 ||
      digest_size != MESH_MGMT_EXECUTION_DIGEST_SIZE)
    return MESH_MGMT_EXECUTION_RUNNER_RUNTIME;
  digest_size = 0u;
  if (EVP_DigestFinal_ex(context->stderr_hash, out->stderr_digest,
                         &digest_size) != 1 ||
      digest_size != MESH_MGMT_EXECUTION_DIGEST_SIZE)
    return MESH_MGMT_EXECUTION_RUNNER_RUNTIME;
  out->stdout_bytes = context->stdout_bytes;
  out->stderr_bytes = context->stderr_bytes;
  return MESH_MGMT_EXECUTION_RUNNER_OK;
}

mesh_mgmt_execution_runner_result_t
mesh_mgmt_execution_runner_module_digest_v1(
    const char *module_path, uint32_t max_module_bytes,
    uint8_t out_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    uint64_t *out_module_bytes) {
  turbo_fs_stat_t stat;
  turbo_file_t file = TURBO_INVALID_FILE;
  EVP_MD_CTX *hash = NULL;
  uint8_t buffer[MESH_MGMT_EXECUTION_RUNNER_HASH_CHUNK];
  uint64_t total = 0u;
  unsigned int digest_size = 0u;
  int read_size;
  mesh_mgmt_execution_runner_result_t result =
      MESH_MGMT_EXECUTION_RUNNER_IO;

  if (!module_path || !out_digest || max_module_bytes == 0u)
    return MESH_MGMT_EXECUTION_RUNNER_INVALID_ARG;
  if (!path_is_absolute(module_path) ||
      strlen(module_path) >= TURBO_FS_MAX_PATH)
    return MESH_MGMT_EXECUTION_RUNNER_INVALID_DEPLOYMENT;
  if (turbo_fs_stat(module_path, &stat) != 0 || !stat.is_file)
    return MESH_MGMT_EXECUTION_RUNNER_IO;
  if (stat.size == 0u || stat.size > max_module_bytes)
    return MESH_MGMT_EXECUTION_RUNNER_RESOURCE_EXHAUSTED;

  hash = EVP_MD_CTX_new();
  if (!hash)
    return MESH_MGMT_EXECUTION_RUNNER_RESOURCE_EXHAUSTED;
  if (EVP_DigestInit_ex(hash, EVP_sha256(), NULL) != 1)
    goto cleanup;
  file = turbo_fs_open(module_path, TURBO_FS_O_RDONLY, 0);
  if (file == TURBO_INVALID_FILE)
    goto cleanup;

  while ((read_size = turbo_fs_read(file, (char *)buffer, sizeof(buffer))) > 0) {
    total += (uint64_t)read_size;
    if (total > max_module_bytes ||
        EVP_DigestUpdate(hash, buffer, (size_t)read_size) != 1) {
      result = MESH_MGMT_EXECUTION_RUNNER_RESOURCE_EXHAUSTED;
      goto cleanup;
    }
  }
  if (read_size < 0 || total != stat.size)
    goto cleanup;
  if (EVP_DigestFinal_ex(hash, out_digest, &digest_size) != 1 ||
      digest_size != MESH_MGMT_EXECUTION_DIGEST_SIZE)
    goto cleanup;
  if (out_module_bytes)
    *out_module_bytes = total;
  result = MESH_MGMT_EXECUTION_RUNNER_OK;

cleanup:
  if (file != TURBO_INVALID_FILE && turbo_fs_close(file) != 0)
    result = MESH_MGMT_EXECUTION_RUNNER_IO;
  EVP_MD_CTX_free(hash);
  return result;
}

mesh_mgmt_execution_runner_result_t mesh_mgmt_execution_runner_init_v1(
    mesh_mgmt_execution_runner_v1_t *runner, size_t capacity) {
  if (!runner)
    return MESH_MGMT_EXECUTION_RUNNER_INVALID_ARG;
  memset(runner, 0, sizeof(*runner));
  if (capacity == 0u ||
      capacity > MESH_MGMT_EXECUTION_RUNNER_MAX_DEPLOYMENTS)
    return MESH_MGMT_EXECUTION_RUNNER_INVALID_ARG;
  runner->entries = (mesh_mgmt_execution_deployment_entry_v1_t *)calloc(
      capacity, sizeof(*runner->entries));
  if (!runner->entries)
    return MESH_MGMT_EXECUTION_RUNNER_RESOURCE_EXHAUSTED;
  runner->capacity = capacity;
  return MESH_MGMT_EXECUTION_RUNNER_OK;
}

void mesh_mgmt_execution_runner_destroy_v1(
    mesh_mgmt_execution_runner_v1_t *runner) {
  if (!runner)
    return;
  free(runner->entries);
  memset(runner, 0, sizeof(*runner));
}

mesh_mgmt_execution_runner_result_t mesh_mgmt_execution_runner_register_v1(
    mesh_mgmt_execution_runner_v1_t *runner,
    const mesh_mgmt_execution_deployment_v1_t *deployment) {
  mesh_mgmt_execution_deployment_entry_v1_t *free_entry = NULL;
  size_t path_size;
  size_t index;

  if (!runner || !runner->entries || !deployment || !deployment->module_path)
    return MESH_MGMT_EXECUTION_RUNNER_INVALID_ARG;
  path_size = strlen(deployment->module_path);
  if (bytes_are_zero(deployment->deployment_id,
                     MESH_MGMT_EXECUTION_ID_SIZE) ||
      deployment->generation == 0u ||
      bytes_are_zero(deployment->module_digest,
                     MESH_MGMT_EXECUTION_DIGEST_SIZE) ||
      (deployment->runtime != MESH_MGMT_EXECUTION_DEPLOYMENT_WASM_V1 &&
       deployment->runtime !=
           MESH_MGMT_EXECUTION_DEPLOYMENT_NATIVE_PROCESS_V1) ||
      !path_is_absolute(deployment->module_path) || path_size == 0u ||
      path_size >= TURBO_FS_MAX_PATH)
    return MESH_MGMT_EXECUTION_RUNNER_INVALID_DEPLOYMENT;

  for (index = 0u; index < runner->capacity; ++index) {
    mesh_mgmt_execution_deployment_entry_v1_t *entry =
        &runner->entries[index];
    if (!entry->occupied) {
      if (!free_entry)
        free_entry = entry;
      continue;
    }
    if (entry->generation == deployment->generation &&
        memcmp(entry->deployment_id, deployment->deployment_id,
               MESH_MGMT_EXECUTION_ID_SIZE) == 0) {
      if (memcmp(entry->module_digest, deployment->module_digest,
                 MESH_MGMT_EXECUTION_DIGEST_SIZE) == 0 &&
          entry->runtime == deployment->runtime &&
          strcmp(entry->module_path, deployment->module_path) == 0)
        return MESH_MGMT_EXECUTION_RUNNER_OK;
      return MESH_MGMT_EXECUTION_RUNNER_CONFLICT;
    }
  }

  if (!free_entry)
    return MESH_MGMT_EXECUTION_RUNNER_RESOURCE_EXHAUSTED;
  memcpy(free_entry->deployment_id, deployment->deployment_id,
         MESH_MGMT_EXECUTION_ID_SIZE);
  free_entry->generation = deployment->generation;
  memcpy(free_entry->module_digest, deployment->module_digest,
         MESH_MGMT_EXECUTION_DIGEST_SIZE);
  free_entry->runtime = deployment->runtime;
  memcpy(free_entry->module_path, deployment->module_path, path_size + 1u);
  free_entry->occupied = 1u;
  runner->count += 1u;
  return MESH_MGMT_EXECUTION_RUNNER_OK;
}

mesh_mgmt_execution_runner_result_t mesh_mgmt_execution_runner_resolve_v1(
    const mesh_mgmt_execution_runner_v1_t *runner,
    const uint8_t deployment_id[MESH_MGMT_EXECUTION_ID_SIZE],
    uint64_t generation, mesh_mgmt_execution_deployment_v1_t *out_deployment,
    char *module_path, size_t module_path_capacity) {
  const mesh_mgmt_execution_deployment_entry_v1_t *entry;
  size_t path_size;
  if (!runner || !runner->entries || !deployment_id || generation == 0u ||
      !out_deployment || !module_path)
    return MESH_MGMT_EXECUTION_RUNNER_INVALID_ARG;
  entry = find_deployment(runner, deployment_id, generation);
  if (!entry) return MESH_MGMT_EXECUTION_RUNNER_NOT_FOUND;
  path_size = strlen(entry->module_path) + 1u;
  if (module_path_capacity < path_size)
    return MESH_MGMT_EXECUTION_RUNNER_RESOURCE_EXHAUSTED;
  memset(out_deployment, 0, sizeof(*out_deployment));
  memcpy(out_deployment->deployment_id, entry->deployment_id,
         sizeof(out_deployment->deployment_id));
  out_deployment->generation = entry->generation;
  memcpy(out_deployment->module_digest, entry->module_digest,
         sizeof(out_deployment->module_digest));
  out_deployment->runtime = entry->runtime;
  memcpy(module_path, entry->module_path, path_size);
  out_deployment->module_path = module_path;
  return MESH_MGMT_EXECUTION_RUNNER_OK;
}

mesh_mgmt_execution_runner_result_t mesh_mgmt_execution_runner_run_v1(
    const mesh_mgmt_execution_runner_v1_t *runner,
    const mesh_mgmt_execution_request_v1_t *request,
    const mesh_mgmt_execution_effective_policy_v1_t *effective_policy,
    uint64_t now_ms, const mesh_mgmt_execution_runner_io_v1_t *io,
    mesh_mgmt_execution_runner_output_v1_t *out) {
  const mesh_mgmt_execution_deployment_entry_v1_t *deployment;
  turbo_runtime_config_t config;
  turbo_runtime_run_request_t runtime_request;
  turbo_runtime_run_result_t runtime_result;
  turbo_runtime_t *runtime = NULL;
  turbo_runtime_app_t *app = NULL;
  runner_io_context_t io_context;
  uint8_t digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  int runtime_code;
  mesh_mgmt_execution_runner_result_t result =
      MESH_MGMT_EXECUTION_RUNNER_RUNTIME;

  if (!runner || !runner->entries || !request || !effective_policy || !out)
    return MESH_MGMT_EXECUTION_RUNNER_INVALID_ARG;
  memset(out, 0, sizeof(*out));
  if (mesh_mgmt_execution_request_validate_v1(request, now_ms) !=
      MESH_MGMT_EXECUTION_OK)
    return MESH_MGMT_EXECUTION_RUNNER_INVALID_ARG;
  if ((request->input_kind != MESH_MGMT_EXECUTION_INPUT_NONE &&
       request->input_kind != MESH_MGMT_EXECUTION_INPUT_INLINE) ||
      (request->output_mode != MESH_MGMT_EXECUTION_OUTPUT_NONE &&
       request->output_mode != MESH_MGMT_EXECUTION_OUTPUT_DIGEST))
    return MESH_MGMT_EXECUTION_RUNNER_POLICY_DENIED;
  if (effective_policy->capabilities !=
      MESH_MGMT_EXECUTION_RAW_WASM_CAPABILITIES_V1)
    return MESH_MGMT_EXECUTION_RUNNER_POLICY_DENIED;
  if (request->inline_input_size > effective_policy->limits.input_bytes)
    return MESH_MGMT_EXECUTION_RUNNER_RESOURCE_EXHAUSTED;

  deployment =
      find_deployment(runner, request->deployment_id,
                      request->deployment_generation);
  if (!deployment)
    return MESH_MGMT_EXECUTION_RUNNER_NOT_FOUND;
  if (deployment->runtime != MESH_MGMT_EXECUTION_DEPLOYMENT_WASM_V1)
    return MESH_MGMT_EXECUTION_RUNNER_POLICY_DENIED;
  if (memcmp(deployment->module_digest, request->package_digest,
             MESH_MGMT_EXECUTION_DIGEST_SIZE) != 0)
    return MESH_MGMT_EXECUTION_RUNNER_DIGEST_MISMATCH;
  result = mesh_mgmt_execution_runner_module_digest_v1(
      deployment->module_path, effective_policy->limits.module_bytes, digest,
      NULL);
  if (result != MESH_MGMT_EXECUTION_RUNNER_OK)
    return result;
  if (memcmp(digest, deployment->module_digest,
             MESH_MGMT_EXECUTION_DIGEST_SIZE) != 0)
    return MESH_MGMT_EXECUTION_RUNNER_DIGEST_MISMATCH;

  turbo_runtime_config_init(&config);
  config.allowed_capabilities = TURBO_WASM_CAP_CORE | TURBO_WASM_CAP_UTILS |
                                TURBO_WASM_CAP_APP;
  config.limits.execution.stack_bytes =
      effective_policy->limits.stack_bytes;
  config.limits.execution.linear_memory_bytes =
      effective_policy->limits.linear_memory_bytes;
  config.limits.execution.module_bytes =
      effective_policy->limits.module_bytes;
  config.limits.execution.call_timeout_ms =
      effective_policy->limits.timeout_ms;
  config.limits.execution.control_flow_steps =
      effective_policy->limits.control_flow_steps;
  config.limits.execution.host_calls_per_invocation =
      effective_policy->limits.host_calls;
  config.limits.execution.copied_guest_bytes_per_invocation =
      effective_policy->limits.copied_guest_bytes;
  config.limits.input_bytes = effective_policy->limits.input_bytes;
  config.limits.stdout_bytes = effective_policy->limits.stdout_bytes;
  config.limits.stderr_bytes = effective_policy->limits.stderr_bytes;

  runtime_code = turbo_runtime_create(&config, &runtime);
  if (runtime_code != TURBO_RUNTIME_OK) {
    out->runtime_code = runtime_code;
    return MESH_MGMT_EXECUTION_RUNNER_RUNTIME;
  }
  runtime_code =
      turbo_runtime_load_wasm(runtime, deployment->module_path, &app);
  if (runtime_code != TURBO_RUNTIME_OK) {
    out->runtime_code = runtime_code;
    copy_runtime_error(runtime, out);
    goto cleanup;
  }

  result = mesh_mgmt_execution_runner_module_digest_v1(
      deployment->module_path, effective_policy->limits.module_bytes, digest,
      NULL);
  if (result != MESH_MGMT_EXECUTION_RUNNER_OK)
    goto cleanup;
  if (memcmp(digest, deployment->module_digest,
             MESH_MGMT_EXECUTION_DIGEST_SIZE) != 0) {
    result = MESH_MGMT_EXECUTION_RUNNER_DIGEST_MISMATCH;
    goto cleanup;
  }

  memset(&io_context, 0, sizeof(io_context));
  io_context.io = io;
  io_context.stdout_hash = EVP_MD_CTX_new();
  io_context.stderr_hash = EVP_MD_CTX_new();
  if (!io_context.stdout_hash || !io_context.stderr_hash ||
      EVP_DigestInit_ex(io_context.stdout_hash, EVP_sha256(), NULL) != 1 ||
      EVP_DigestInit_ex(io_context.stderr_hash, EVP_sha256(), NULL) != 1) {
    EVP_MD_CTX_free(io_context.stdout_hash);
    EVP_MD_CTX_free(io_context.stderr_hash);
    result = MESH_MGMT_EXECUTION_RUNNER_RESOURCE_EXHAUSTED;
    goto cleanup;
  }

  memset(&runtime_request, 0, sizeof(runtime_request));
  runtime_request.struct_size = sizeof(runtime_request);
  runtime_request.input = request->input_kind == MESH_MGMT_EXECUTION_INPUT_INLINE
                              ? request->inline_input
                              : NULL;
  runtime_request.input_size = request->inline_input_size;
  runtime_request.write_stdout = write_stdout;
  runtime_request.write_stderr = write_stderr;
  runtime_request.io_user_data = &io_context;
  memset(&runtime_result, 0, sizeof(runtime_result));
  runtime_result.struct_size = sizeof(runtime_result);

  runtime_code =
      turbo_runtime_app_run(app, &runtime_request, &runtime_result);
  out->runtime_code = runtime_result.runtime_code;
  out->runtime_stage = (int)runtime_result.stage;
  out->guest_exit_code = runtime_result.guest_exit_code;
  out->invocations = runtime_result.wasm_usage.invocations;
  out->host_calls = runtime_result.wasm_usage.host_calls;
  out->copied_guest_bytes = runtime_result.wasm_usage.copied_guest_bytes;
  out->modules_loaded = runtime_result.wasm_usage.modules_loaded;
  out->modules_rejected = runtime_result.wasm_usage.modules_rejected;
  out->open_handles = runtime_result.wasm_usage.open_handles;
  result = finish_output_hashes(&io_context, out);
  EVP_MD_CTX_free(io_context.stdout_hash);
  EVP_MD_CTX_free(io_context.stderr_hash);
  if (result != MESH_MGMT_EXECUTION_RUNNER_OK)
    goto cleanup;
  if (runtime_code != TURBO_RUNTIME_OK) {
    copy_runtime_error(runtime, out);
    result = MESH_MGMT_EXECUTION_RUNNER_RUNTIME;
    goto cleanup;
  }
  result = MESH_MGMT_EXECUTION_RUNNER_OK;

cleanup:
  if (app)
    turbo_runtime_app_destroy(app);
  turbo_runtime_destroy(runtime);
  return result;
}
