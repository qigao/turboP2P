#ifndef TURBO_P2P_MESH_MGMT_EXECUTION_RUNNER_H
#define TURBO_P2P_MESH_MGMT_EXECUTION_RUNNER_H

#include "mesh_mgmt_execution.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_MGMT_EXECUTION_RUNNER_MAX_DEPLOYMENTS 256u
#define MESH_MGMT_EXECUTION_RUNNER_ERROR_TEXT_MAX 256u

typedef enum {
  MESH_MGMT_EXECUTION_RUNNER_OK = 0,
  MESH_MGMT_EXECUTION_RUNNER_INVALID_ARG = -1,
  MESH_MGMT_EXECUTION_RUNNER_INVALID_DEPLOYMENT = -2,
  MESH_MGMT_EXECUTION_RUNNER_NOT_FOUND = -3,
  MESH_MGMT_EXECUTION_RUNNER_CONFLICT = -4,
  MESH_MGMT_EXECUTION_RUNNER_RESOURCE_EXHAUSTED = -5,
  MESH_MGMT_EXECUTION_RUNNER_DIGEST_MISMATCH = -6,
  MESH_MGMT_EXECUTION_RUNNER_POLICY_DENIED = -7,
  MESH_MGMT_EXECUTION_RUNNER_IO = -8,
  MESH_MGMT_EXECUTION_RUNNER_RUNTIME = -9,
} mesh_mgmt_execution_runner_result_t;

typedef enum {
  /** Zero preserves the original V1 prestaged-WASM deployment format. */
  MESH_MGMT_EXECUTION_DEPLOYMENT_WASM_V1 = 0,
  MESH_MGMT_EXECUTION_DEPLOYMENT_NATIVE_PROCESS_V1 = 1,
} mesh_mgmt_execution_deployment_runtime_v1_t;

typedef struct {
  uint8_t deployment_id[MESH_MGMT_EXECUTION_ID_SIZE];
  uint64_t generation;
  uint8_t module_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  const char *module_path;
  mesh_mgmt_execution_deployment_runtime_v1_t runtime;
} mesh_mgmt_execution_deployment_v1_t;

typedef struct mesh_mgmt_execution_deployment_entry_v1_s
    mesh_mgmt_execution_deployment_entry_v1_t;

/**
 * Bounded local deployment registry. The host path is copied at registration
 * and is never part of the RPC or MMP request. One owner must serialize calls.
 */
typedef struct {
  mesh_mgmt_execution_deployment_entry_v1_t *entries;
  size_t capacity;
  size_t count;
} mesh_mgmt_execution_runner_v1_t;

typedef struct {
  int (*write_stdout)(const uint8_t *data, size_t size, void *user_data);
  int (*write_stderr)(const uint8_t *data, size_t size, void *user_data);
  void *user_data;
} mesh_mgmt_execution_runner_io_v1_t;

typedef struct {
  int runtime_code;
  int runtime_stage;
  int32_t guest_exit_code;
  uint64_t invocations;
  uint64_t host_calls;
  uint64_t copied_guest_bytes;
  uint64_t modules_loaded;
  uint64_t modules_rejected;
  uint32_t open_handles;
  uint64_t stdout_bytes;
  uint64_t stderr_bytes;
  uint8_t stdout_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint8_t stderr_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  char error_text[MESH_MGMT_EXECUTION_RUNNER_ERROR_TEXT_MAX];
} mesh_mgmt_execution_runner_output_v1_t;

mesh_mgmt_execution_runner_result_t
mesh_mgmt_execution_runner_module_digest_v1(
    const char *module_path, uint32_t max_module_bytes,
    uint8_t out_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    uint64_t *out_module_bytes);

mesh_mgmt_execution_runner_result_t mesh_mgmt_execution_runner_init_v1(
    mesh_mgmt_execution_runner_v1_t *runner, size_t capacity);

void mesh_mgmt_execution_runner_destroy_v1(
    mesh_mgmt_execution_runner_v1_t *runner);

mesh_mgmt_execution_runner_result_t mesh_mgmt_execution_runner_register_v1(
    mesh_mgmt_execution_runner_v1_t *runner,
    const mesh_mgmt_execution_deployment_v1_t *deployment);

/** Copies a prestaged immutable deployment; no internal pointer escapes. */
mesh_mgmt_execution_runner_result_t mesh_mgmt_execution_runner_resolve_v1(
    const mesh_mgmt_execution_runner_v1_t *runner,
    const uint8_t deployment_id[MESH_MGMT_EXECUTION_ID_SIZE],
    uint64_t generation, mesh_mgmt_execution_deployment_v1_t *out_deployment,
    char *module_path, size_t module_path_capacity);

mesh_mgmt_execution_runner_result_t mesh_mgmt_execution_runner_run_v1(
    const mesh_mgmt_execution_runner_v1_t *runner,
    const mesh_mgmt_execution_request_v1_t *request,
    const mesh_mgmt_execution_effective_policy_v1_t *effective_policy,
    uint64_t now_ms, const mesh_mgmt_execution_runner_io_v1_t *io,
    mesh_mgmt_execution_runner_output_v1_t *out);

#ifdef __cplusplus
}
#endif

#endif
