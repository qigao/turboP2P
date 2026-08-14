#ifndef MESH_CONTROL_EXECUTION_PROVIDER_H
#define MESH_CONTROL_EXECUTION_PROVIDER_H

#include "mesh_control_reconciler.h"
#include "mesh_mgmt_execution_process.h"
#include "mesh_mgmt_execution_store.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_CONTROL_EXECUTION_PROVIDER_MAX_DEPLOYMENTS_V1 256u

typedef struct {
  mesh_mgmt_execution_deployment_v1_t deployment;
  /** Exact immutable config/network profiles accepted for this artifact. */
  uint8_t config_digest[MESH_CONTROL_DIGEST_SIZE];
  uint8_t network_policy_digest[MESH_CONTROL_DIGEST_SIZE];
} mesh_control_execution_deployment_v1_t;

typedef struct {
  uint8_t provider_id[MESH_CONTROL_DIGEST_SIZE];
  uint16_t runtime;
  uint16_t reserved;
  uint8_t local_node_id[MESH_CONTROL_NODE_ID_SIZE];
  uint32_t capabilities;
  mesh_mgmt_execution_limits_v1_t hard_limits;
  const mesh_control_execution_deployment_v1_t *deployments;
  size_t deployment_count;
  mesh_mgmt_execution_process_v1_t *process;
  /** Absolute, provider-exclusive durable claim journal path. */
  const char *journal_path;
  size_t journal_capacity;
  uint8_t result_private_key[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint64_t worker_generation;
  uint64_t (*now_ms)(void *context);
  void *now_context;
} mesh_control_execution_provider_config_v1_t;

struct mesh_control_execution_provider_impl_v1;

/**
 * One-inflight provider bridge. It copies accepted requests, executes them on
 * one TurboUtils worker thread, and retains exactly one completion until ACK.
 * The runner registry and process boundary are immutable after init.
 */
typedef struct {
  struct mesh_control_execution_provider_impl_v1 *impl;
} mesh_control_execution_provider_v1_t;

mesh_control_result_t mesh_control_execution_provider_init_v1(
    mesh_control_execution_provider_v1_t *provider,
    const mesh_control_execution_provider_config_v1_t *config,
    mesh_control_provider_v1_t *out_descriptor);

/** Stable identity persisted before a Native/WASM side effect begins. */
mesh_control_result_t mesh_control_execution_provider_request_digest_v1(
    const mesh_control_provider_request_v1_t *request,
    uint8_t out_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE]);

/**
 * Startup-only maintenance after the control WAL has been restored. It
 * removes provider claims whose terminal control operation is already the
 * durable fact source. No provider job may be running concurrently.
 */
mesh_control_result_t mesh_control_execution_provider_reconcile_journal_v1(
    mesh_control_execution_provider_v1_t *provider,
    const mesh_control_state_v1_t *control_state, size_t *out_removed);

/** Requires close plus a drained/ACKed completion. */
void mesh_control_execution_provider_destroy_v1(
    mesh_control_execution_provider_v1_t *provider);

#ifdef __cplusplus
}
#endif

#endif
