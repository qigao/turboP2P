#ifndef MESH_MGMT_EXECUTION_PROCESS_H
#define MESH_MGMT_EXECUTION_PROCESS_H

#include "mesh_mgmt_execution_orchestrator.h"
#include "turbo_fs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_MGMT_EXECUTION_PROCESS_MAX_SANDBOX_ARGS_V1 8u
#define MESH_MGMT_EXECUTION_PROCESS_MAX_SANDBOX_ARG_SIZE_V1 1024u

typedef struct {
  /** Exact prestaged worker executable. */
  const char *worker_program;
  uint8_t worker_sha256[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint32_t maximum_worker_bytes;
  /**
   * Production sandbox launcher. Its contract is to apply an OS policy, then
   * exec the appended worker argv. NULL is accepted only for explicit test
   * mode; direct mode provides crash isolation but not an OS security sandbox.
   */
  const char *sandbox_program;
  uint8_t sandbox_sha256[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  /** Borrowed immutable strings; they must outlive the initialized process. */
  const char *const *sandbox_args;
  size_t sandbox_arg_count;
  uint8_t allow_direct_process_for_tests;
  size_t maximum_output_bytes;
  /** Exact capability profile enforced by the trusted Native sandbox. */
  uint32_t native_capabilities;
} mesh_mgmt_execution_process_config_v1_t;

typedef struct {
  mesh_mgmt_execution_process_config_v1_t config;
  char worker_program[TURBO_FS_MAX_PATH];
  char sandbox_program[TURBO_FS_MAX_PATH];
  const char *sandbox_args[MESH_MGMT_EXECUTION_PROCESS_MAX_SANDBOX_ARGS_V1];
  char sandbox_arg_storage[MESH_MGMT_EXECUTION_PROCESS_MAX_SANDBOX_ARGS_V1]
                          [MESH_MGMT_EXECUTION_PROCESS_MAX_SANDBOX_ARG_SIZE_V1];
  uint64_t started;
  uint64_t succeeded;
  uint64_t crashed;
  uint64_t timed_out;
  uint64_t rejected_digest;
  uint64_t rejected_sandbox;
  uint8_t initialized;
} mesh_mgmt_execution_process_v1_t;

mesh_mgmt_execution_runner_result_t mesh_mgmt_execution_process_init_v1(
    mesh_mgmt_execution_process_v1_t *process,
    const mesh_mgmt_execution_process_config_v1_t *config);

/** Orchestrator runner callback; all input/output is copied and bounded. */
mesh_mgmt_execution_runner_result_t mesh_mgmt_execution_process_run_v1(
    void *context, const mesh_mgmt_execution_runner_v1_t *runner,
    const mesh_mgmt_execution_request_v1_t *request,
    const mesh_mgmt_execution_effective_policy_v1_t *effective_policy,
    uint64_t now_ms, const mesh_mgmt_execution_runner_io_v1_t *io,
    mesh_mgmt_execution_runner_output_v1_t *out);

/** Entry used only by the dedicated mesh-execution-worker executable. */
int mesh_mgmt_execution_process_worker_main_v1(int argc, char **argv);

void mesh_mgmt_execution_process_destroy_v1(
    mesh_mgmt_execution_process_v1_t *process);

#ifdef __cplusplus
}
#endif

#endif
