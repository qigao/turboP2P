#include "mesh_mgmt_execution_runner.h"

#include <turbowasm/turbowasm.h>
#include <salts/clock.h>

#include <ctype.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MESH_MGMT_EXECUTION_RUNNER_HASH_CHUNK (16u * 1024u)
#define MESH_MGMT_EXECUTION_RUNNER_PATH_MAX 4096u

struct mesh_mgmt_execution_deployment_entry_v1_s {
  uint8_t deployment_id[MESH_MGMT_EXECUTION_ID_SIZE];
  uint64_t generation;
  uint8_t module_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  char module_path[MESH_MGMT_EXECUTION_RUNNER_PATH_MAX];
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


static void describe_runtime_status(
    mesh_mgmt_execution_runner_output_v1_t *out, turbowasm_status status) {
  const char *description = turbowasm_status_string(status);
  out->runtime_code = (int)status;
  if (description) {
    strncpy(out->error_text, description, sizeof(out->error_text) - 1u);
    out->error_text[sizeof(out->error_text) - 1u] = '\0';
  }
}

/* This runtime's only guest ABI is the import-free, zero-argument
 * "turbo_main" export returning i32. No ungranted WASI/host providers,
 * mutable shared stores, or implicit application replay are admitted. */
static int is_turbo_main(const turbowasm_export_desc *entry) {
  static const char name[] = "turbo_main";
  return entry != NULL &&
         entry->kind == TURBOWASM_EXTERN_FUNCTION &&
         entry->name.size == sizeof(name) - 1u &&
         entry->name.bytes != NULL &&
         memcmp(entry->name.bytes, name, sizeof(name) - 1u) == 0;
}

typedef struct {
  uint64_t deadline_ms;
} runner_deadline_v1_t;

static bool runtime_interrupted(void *context) {
  const runner_deadline_v1_t *deadline = context;
  return cmeta_monotonic_ms() >= deadline->deadline_ms;
}

static int safe_allocation_budget(
    const mesh_mgmt_execution_limits_v1_t *limits, size_t *out_budget) {
  size_t module_budget, memory_budget, stack_budget;
  if (!limits || !out_budget ||
      limits->module_bytes == 0u || limits->linear_memory_bytes == 0u ||
      limits->stack_bytes == 0u || limits->control_flow_steps == 0u ||
      limits->timeout_ms == 0u ||
      (size_t)limits->module_bytes > SIZE_MAX / 16u)
    return 0;
  module_budget = (size_t)limits->module_bytes * 16u;
  memory_budget = (size_t)limits->linear_memory_bytes;
  stack_budget = (size_t)limits->stack_bytes;
  if (SIZE_MAX - module_budget < memory_budget ||
      SIZE_MAX - module_budget - memory_budget < stack_budget)
    return 0;
  *out_budget = module_budget + memory_budget + stack_budget;
  return 1;
}

mesh_mgmt_execution_runner_result_t
mesh_mgmt_execution_runner_module_digest_v1(
    const char *module_path, uint32_t max_module_bytes,
    uint8_t out_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    uint64_t *out_module_bytes) {
  FILE *file = NULL;
  EVP_MD_CTX *hash = NULL;
  uint8_t buffer[MESH_MGMT_EXECUTION_RUNNER_HASH_CHUNK];
  size_t read_bytes;
  uint64_t total = 0u;
  unsigned int digest_size = 0u;
  mesh_mgmt_execution_runner_result_t result =
      MESH_MGMT_EXECUTION_RUNNER_IO;

  if (out_module_bytes) *out_module_bytes = 0u;
  if (!module_path || !out_digest || max_module_bytes == 0u)
    return MESH_MGMT_EXECUTION_RUNNER_INVALID_ARG;
  if (!path_is_absolute(module_path) ||
      strlen(module_path) >= MESH_MGMT_EXECUTION_RUNNER_PATH_MAX)
    return MESH_MGMT_EXECUTION_RUNNER_INVALID_DEPLOYMENT;
  file = fopen(module_path, "rb");
  if (!file) return MESH_MGMT_EXECUTION_RUNNER_IO;
  hash = EVP_MD_CTX_new();
  if (!hash) {
    result = MESH_MGMT_EXECUTION_RUNNER_RESOURCE_EXHAUSTED;
    goto cleanup;
  }
  if (EVP_DigestInit_ex(hash, EVP_sha256(), NULL) != 1)
    goto cleanup;
  while ((read_bytes = fread(buffer, 1u, sizeof(buffer), file)) != 0u) {
    total += (uint64_t)read_bytes;
    if (total > max_module_bytes) {
      result = MESH_MGMT_EXECUTION_RUNNER_RESOURCE_EXHAUSTED;
      goto cleanup;
    }
    if (EVP_DigestUpdate(hash, buffer, read_bytes) != 1)
      goto cleanup;
  }
  if (ferror(file) || total == 0u)
    goto cleanup;
  if (EVP_DigestFinal_ex(hash, out_digest, &digest_size) != 1 ||
      digest_size != MESH_MGMT_EXECUTION_DIGEST_SIZE)
    goto cleanup;
  if (out_module_bytes) *out_module_bytes = total;
  result = MESH_MGMT_EXECUTION_RUNNER_OK;

cleanup:
  if (fclose(file) != 0)
    result = MESH_MGMT_EXECUTION_RUNNER_IO;
  EVP_MD_CTX_free(hash);
  return result;
}

/* TurboWasm borrows the ENTIRE module buffer. Caller keeps this allocation
 * immutable until the instance AND module are destroyed. A second digest
 * check protects the payload actually submitted to TurboWasm from file
 * replacement between the initial preflight and this read. */
static mesh_mgmt_execution_runner_result_t read_verified_module(
    const char *path, const uint8_t expected[32], size_t capacity,
    uint8_t **out_bytes, size_t *out_size) {
  FILE *file = NULL;
  uint8_t *bytes = NULL;
  uint8_t digest[32] = {0};
  unsigned int digest_size = 0u;
  uint64_t source_size = 0u;
  size_t read_bytes = 0u;
  mesh_mgmt_execution_runner_result_t result =
      MESH_MGMT_EXECUTION_RUNNER_IO;

  *out_bytes = NULL;
  *out_size = 0u;
  result = mesh_mgmt_execution_runner_module_digest_v1(
      path, (uint32_t)capacity, digest, &source_size);
  if (result != MESH_MGMT_EXECUTION_RUNNER_OK) return result;
  if (CRYPTO_memcmp(expected, digest, 32u) != 0)
    return MESH_MGMT_EXECUTION_RUNNER_DIGEST_MISMATCH;
  bytes = malloc((size_t)source_size);
  if (!bytes) return MESH_MGMT_EXECUTION_RUNNER_RESOURCE_EXHAUSTED;
  file = fopen(path, "rb");
  if (!file) goto cleanup;
  read_bytes = fread(bytes, 1u, (size_t)source_size, file);
  if (read_bytes != source_size || fgetc(file) != EOF || ferror(file))
    goto cleanup;
  if (EVP_Digest(bytes, (size_t)source_size, digest, &digest_size,
                 EVP_sha256(), NULL) != 1 ||
      digest_size != sizeof(digest)) {
    result = MESH_MGMT_EXECUTION_RUNNER_RUNTIME;
    goto cleanup;
  }
  if (CRYPTO_memcmp(digest, expected, sizeof(digest)) != 0) {
    result = MESH_MGMT_EXECUTION_RUNNER_DIGEST_MISMATCH;
    goto cleanup;
  }
  *out_bytes = bytes;
  *out_size = (size_t)source_size;
  bytes = NULL;
  result = MESH_MGMT_EXECUTION_RUNNER_OK;

cleanup:
  if (file && fclose(file) != 0) result = MESH_MGMT_EXECUTION_RUNNER_IO;
  free(bytes);
  OPENSSL_cleanse(digest, sizeof(digest));
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
      path_size >= MESH_MGMT_EXECUTION_RUNNER_PATH_MAX)
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

/* Runs exactly one prestaged import-free Wasm function with no implicit
 * host capabilities or network retry. The execution Worker owns this call;
 * a CNet/NativeIO SG owner must NEVER run the guest inline. */
mesh_mgmt_execution_runner_result_t mesh_mgmt_execution_runner_run_v1(
    const mesh_mgmt_execution_runner_v1_t *runner,
    const mesh_mgmt_execution_request_v1_t *request,
    const mesh_mgmt_execution_effective_policy_v1_t *effective_policy,
    uint64_t now_ms, const mesh_mgmt_execution_runner_io_v1_t *io,
    mesh_mgmt_execution_runner_output_v1_t *out) {
  const mesh_mgmt_execution_deployment_entry_v1_t *deployment;
  turbowasm_runtime_config config = {0};
  turbowasm_module module = {0};
  turbowasm_instance instance = {0};
  turbowasm_module_summary summary = {0};
  turbowasm_function_signature signature = {0};
  turbowasm_execution_options options = {0};
  turbowasm_value guest_result = {0};
  turbowasm_trap trap = TURBOWASM_TRAP_NONE;
  turbowasm_status status = TURBOWASM_INVALID_ARGUMENT;
  runner_deadline_v1_t deadline = {0};
  uint8_t *borrowed_bytes = NULL;
  size_t borrowed_size = 0u, allocation_budget = 0u, result_count = 0u;
  uint32_t entry_function = 0u;
  unsigned int hash_len = 0u;
  int found_entry = 0;
  mesh_mgmt_execution_runner_result_t result =
      MESH_MGMT_EXECUTION_RUNNER_RUNTIME;
  static const uint8_t empty_output[] = {0};

  if (!runner || !runner->entries || !request || !effective_policy || !out)
    return MESH_MGMT_EXECUTION_RUNNER_INVALID_ARG;
  memset(out, 0, sizeof(*out));
  if (mesh_mgmt_execution_request_validate_v1(request, now_ms) !=
      MESH_MGMT_EXECUTION_OK)
    return MESH_MGMT_EXECUTION_RUNNER_INVALID_ARG;
  /* No WASI, filesystem, networking, stdout or input-import capability is
   * accidentally granted. The V1 raw guest accepts no inline input; reject
   * such requests instead of silently discarding their application payload. */
  if (request->input_kind != MESH_MGMT_EXECUTION_INPUT_NONE ||
      (request->output_mode != MESH_MGMT_EXECUTION_OUTPUT_NONE &&
       request->output_mode != MESH_MGMT_EXECUTION_OUTPUT_DIGEST) ||
      effective_policy->capabilities !=
          MESH_MGMT_EXECUTION_RAW_WASM_CAPABILITIES_V1)
    return MESH_MGMT_EXECUTION_RUNNER_POLICY_DENIED;
  (void)io; /* Import-free raw ABI cannot emit stdout/stderr events. */
  if (!safe_allocation_budget(&effective_policy->limits,
                              &allocation_budget))
    return MESH_MGMT_EXECUTION_RUNNER_RESOURCE_EXHAUSTED;

  deployment = find_deployment(
      runner, request->deployment_id, request->deployment_generation);
  if (!deployment)
    return MESH_MGMT_EXECUTION_RUNNER_NOT_FOUND;
  if (deployment->runtime != MESH_MGMT_EXECUTION_DEPLOYMENT_WASM_V1)
    return MESH_MGMT_EXECUTION_RUNNER_POLICY_DENIED;
  if (CRYPTO_memcmp(deployment->module_digest, request->package_digest,
                    MESH_MGMT_EXECUTION_DIGEST_SIZE) != 0)
    return MESH_MGMT_EXECUTION_RUNNER_DIGEST_MISMATCH;
  result = read_verified_module(
      deployment->module_path, deployment->module_digest,
      effective_policy->limits.module_bytes,
      &borrowed_bytes, &borrowed_size);
  if (result != MESH_MGMT_EXECUTION_RUNNER_OK)
    return result;
  result = MESH_MGMT_EXECUTION_RUNNER_RUNTIME;

  turbowasm_runtime_config_init(&config);
  config.limits.max_module_bytes = effective_policy->limits.module_bytes;
  config.limits.max_linear_memory_bytes =
      effective_policy->limits.linear_memory_bytes;
  config.limits.max_allocation_bytes = allocation_budget;
  config.limits.max_table_elements = 64u;
  status = turbowasm_module_load_borrowed_with_config(
      &module, borrowed_bytes, borrowed_size, &config);
  if (status != TURBOWASM_OK) goto cleanup;
  out->modules_loaded = 1u;

  if (!turbowasm_module_summary_get(&module, &summary)) {
    status = TURBOWASM_MALFORMED_MODULE;
    goto cleanup;
  }
  /* Explicitly deny start-section execution and imports. Instance creation
   * can therefore never execute unbudgeted start code or hidden host effects. */
  if (summary.has_start || turbowasm_module_import_count(&module) != 0u ||
      turbowasm_module_memory_count(&module) > 1u) {
    result = MESH_MGMT_EXECUTION_RUNNER_POLICY_DENIED;
    goto cleanup;
  }
  for (size_t i = 0u; i < turbowasm_module_memory_count(&module); ++i) {
    turbowasm_memory_desc memory = {0};
    if (!turbowasm_module_memory_at(&module, i, &memory) ||
        memory.imported || memory.shared || memory.memory64 ||
        memory.page_size == 0u ||
        memory.minimum64 >
            effective_policy->limits.linear_memory_bytes / memory.page_size) {
      result = MESH_MGMT_EXECUTION_RUNNER_POLICY_DENIED;
      goto cleanup;
    }
  }
  for (size_t i = 0u; i < turbowasm_module_export_count(&module); ++i) {
    const turbowasm_export_desc *entry =
        turbowasm_module_export_at(&module, i);
    if (!is_turbo_main(entry)) continue;
    if (found_entry) {
      result = MESH_MGMT_EXECUTION_RUNNER_POLICY_DENIED;
      goto cleanup;
    }
    entry_function = entry->item_index;
    found_entry = 1;
  }
  if (!found_entry ||
      !turbowasm_module_function_signature_get(
          &module, entry_function, &signature) ||
      signature.param_count != 0u || signature.result_count != 1u ||
      turbowasm_module_function_result_type(
          &module, entry_function, 0u) !=
          turbowasm_value_type_descriptor(TURBOWASM_VALUE_I32)) {
    result = MESH_MGMT_EXECUTION_RUNNER_POLICY_DENIED;
    goto cleanup;
  }
  status = turbowasm_instance_create(&instance, &module);
  if (status != TURBOWASM_OK) goto cleanup;

  deadline.deadline_ms = cmeta_monotonic_ms();
  if (UINT64_MAX - deadline.deadline_ms <
      effective_policy->limits.timeout_ms)
    deadline.deadline_ms = UINT64_MAX;
  else
    deadline.deadline_ms += effective_policy->limits.timeout_ms;
  options.has_fuel_limit = true;
  options.fuel = effective_policy->limits.control_flow_steps;
  options.should_interrupt = runtime_interrupted;
  options.interrupt_context = &deadline;
  status = turbowasm_instance_invoke_with_options(
      &instance, entry_function, NULL, 0u, &guest_result, 1u,
      &result_count, &trap, &options);
  out->runtime_stage = 7; /* actual guest invocation */
  if (status != TURBOWASM_OK || trap != TURBOWASM_TRAP_NONE)
    goto cleanup;
  if (result_count != 1u || guest_result.kind != TURBOWASM_VALUE_I32) {
    status = TURBOWASM_TYPE_MISMATCH;
    goto cleanup;
  }
  out->runtime_code = (int)TURBOWASM_OK;
  out->guest_exit_code = guest_result.as.i32;
  out->invocations = 1u;
  /* An import-free guest has no stdout/stderr or host effects. Record
   * canonical SHA-256 of empty output; no synthetic host usage is reported. */
  if (EVP_Digest(empty_output, 0u, out->stdout_digest, &hash_len,
                 EVP_sha256(), NULL) != 1 ||
      hash_len != MESH_MGMT_EXECUTION_DIGEST_SIZE ||
      EVP_Digest(empty_output, 0u, out->stderr_digest, &hash_len,
                 EVP_sha256(), NULL) != 1 ||
      hash_len != MESH_MGMT_EXECUTION_DIGEST_SIZE) {
    status = TURBOWASM_INVALID_ARGUMENT;
    goto cleanup;
  }
  result = MESH_MGMT_EXECUTION_RUNNER_OK;

cleanup:
  if (result == MESH_MGMT_EXECUTION_RUNNER_RUNTIME)
    describe_runtime_status(out, status);
  /* This order is mandatory: instance → validated module → borrowed bytes.
   * No instance, module or pooled NativeIO object may escape this Worker. */
  turbowasm_instance_destroy(&instance);
  turbowasm_module_destroy(&module);
  free(borrowed_bytes);
  return result;
}
