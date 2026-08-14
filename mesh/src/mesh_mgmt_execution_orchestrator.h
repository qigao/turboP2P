#ifndef TURBO_P2P_MESH_MGMT_EXECUTION_ORCHESTRATOR_H
#define TURBO_P2P_MESH_MGMT_EXECUTION_ORCHESTRATOR_H

#include "mesh_mgmt_execution_result.h"
#include "mesh_mgmt_execution_runner.h"
#include "mesh_mgmt_execution_store.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  MESH_MGMT_EXECUTION_ORCHESTRATOR_OK = 0,
  MESH_MGMT_EXECUTION_ORCHESTRATOR_INVALID_ARG = -1,
  MESH_MGMT_EXECUTION_ORCHESTRATOR_AUTH_FAILED = -2,
  MESH_MGMT_EXECUTION_ORCHESTRATOR_CONFLICT = -3,
  MESH_MGMT_EXECUTION_ORCHESTRATOR_BUSY = -4,
  MESH_MGMT_EXECUTION_ORCHESTRATOR_INDETERMINATE = -5,
  MESH_MGMT_EXECUTION_ORCHESTRATOR_STORE_FAILED = -6,
  MESH_MGMT_EXECUTION_ORCHESTRATOR_SIGN_FAILED = -7,
  MESH_MGMT_EXECUTION_ORCHESTRATOR_CLOCK_FAILED = -8,
} mesh_mgmt_execution_orchestrator_result_t;

typedef int (*mesh_mgmt_execution_verify_grant_v1_fn)(
    void *context, const mesh_mgmt_execution_grant_v1_t *grant,
    uint64_t now_ms);

typedef uint64_t (*mesh_mgmt_execution_clock_v1_fn)(void *context);

typedef mesh_mgmt_execution_runner_result_t
(*mesh_mgmt_execution_orchestrator_runner_v1_fn)(
    void *context, const mesh_mgmt_execution_runner_v1_t *runner,
    const mesh_mgmt_execution_request_v1_t *request,
    const mesh_mgmt_execution_effective_policy_v1_t *effective_policy,
    uint64_t now_ms, const mesh_mgmt_execution_runner_io_v1_t *io,
    mesh_mgmt_execution_runner_output_v1_t *out);

typedef struct {
  mesh_mgmt_execution_store_v1_t *store;
  mesh_mgmt_execution_runner_v1_t *runner;
  uint8_t local_node_id[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint8_t result_private_key[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint64_t worker_generation;
  mesh_mgmt_execution_verify_grant_v1_fn verify_grant;
  void *verify_grant_context;
  mesh_mgmt_execution_clock_v1_fn clock_now_ms;
  void *clock_context;
  /** Optional isolated runner boundary; NULL preserves in-process behavior. */
  mesh_mgmt_execution_orchestrator_runner_v1_fn execute_runner;
  void *execute_runner_context;
} mesh_mgmt_execution_orchestrator_config_v1_t;

/**
 * Synchronous E2 adapter. Callers must run it outside Mesh/MMP event loops and
 * serialize access to the referenced store and runner.
 */
typedef struct {
  mesh_mgmt_execution_store_v1_t *store;
  mesh_mgmt_execution_runner_v1_t *runner;
  uint8_t local_node_id[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint8_t result_private_key[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint8_t result_public_key[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint64_t worker_generation;
  mesh_mgmt_execution_verify_grant_v1_fn verify_grant;
  void *verify_grant_context;
  mesh_mgmt_execution_clock_v1_fn clock_now_ms;
  void *clock_context;
  mesh_mgmt_execution_orchestrator_runner_v1_fn execute_runner;
  void *execute_runner_context;
  uint8_t initialized;
} mesh_mgmt_execution_orchestrator_v1_t;

mesh_mgmt_execution_orchestrator_result_t
mesh_mgmt_execution_orchestrator_init_v1(
    mesh_mgmt_execution_orchestrator_v1_t *orchestrator,
    const mesh_mgmt_execution_orchestrator_config_v1_t *config);

void mesh_mgmt_execution_orchestrator_destroy_v1(
    mesh_mgmt_execution_orchestrator_v1_t *orchestrator);

mesh_mgmt_execution_orchestrator_result_t
mesh_mgmt_execution_orchestrator_execute_v1(
    mesh_mgmt_execution_orchestrator_v1_t *orchestrator,
    const mesh_mgmt_execution_grant_v1_t *grant,
    const mesh_mgmt_execution_request_v1_t *request,
    const mesh_mgmt_execution_authorization_input_v1_t *authorization,
    const mesh_mgmt_execution_runner_io_v1_t *io,
    mesh_mgmt_execution_result_v1_t *out_result);

#ifdef __cplusplus
}
#endif

#endif
