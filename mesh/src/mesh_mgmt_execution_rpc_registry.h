#ifndef MESH_MGMT_EXECUTION_RPC_REGISTRY_H
#define MESH_MGMT_EXECUTION_RPC_REGISTRY_H

#include "mesh_mgmt_execution_response_consumer.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_MGMT_EXECUTION_RPC_REGISTRY_MAX_CAPACITY_V1 4096u

typedef enum {
  MESH_MGMT_EXECUTION_RPC_REGISTRY_OK = 0,
  MESH_MGMT_EXECUTION_RPC_REGISTRY_INVALID_ARG = -1,
  MESH_MGMT_EXECUTION_RPC_REGISTRY_RESOURCE_EXHAUSTED = -2,
  MESH_MGMT_EXECUTION_RPC_REGISTRY_ALREADY_EXISTS = -3,
  MESH_MGMT_EXECUTION_RPC_REGISTRY_CONFLICT = -4,
  MESH_MGMT_EXECUTION_RPC_REGISTRY_NOT_FOUND = -5,
  MESH_MGMT_EXECUTION_RPC_REGISTRY_AUTH_FAILED = -6,
  MESH_MGMT_EXECUTION_RPC_REGISTRY_EXPIRED = -7,
  MESH_MGMT_EXECUTION_RPC_REGISTRY_ALREADY_COMPLETE = -8,
  MESH_MGMT_EXECUTION_RPC_REGISTRY_NOT_READY = -9
} mesh_mgmt_execution_rpc_registry_result_t;

typedef enum {
  MESH_MGMT_EXECUTION_RPC_PENDING = 1,
  MESH_MGMT_EXECUTION_RPC_RESULT = 2,
  MESH_MGMT_EXECUTION_RPC_STATUS = 3,
  MESH_MGMT_EXECUTION_RPC_TIMED_OUT = 4
} mesh_mgmt_execution_rpc_state_t;

typedef struct {
  uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE];
  uint8_t correlation_id[MESH_MGMT_EXECUTION_ID_SIZE];
  uint8_t request_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint8_t target_node_id[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint64_t deadline_ms;
} mesh_mgmt_execution_rpc_binding_v1_t;

typedef struct {
  mesh_mgmt_execution_rpc_state_t state;
  mesh_mgmt_execution_rpc_binding_v1_t binding;
  mesh_mgmt_execution_response_v1_t response;
} mesh_mgmt_execution_rpc_completion_v1_t;

struct mesh_mgmt_execution_rpc_registry_impl_v1;

/**
 * Single-owner bounded registry. No function is thread-safe; the RPC owner
 * must serialize registration, completion, lookup, sweep, and release.
 */
typedef struct {
  struct mesh_mgmt_execution_rpc_registry_impl_v1 *impl;
} mesh_mgmt_execution_rpc_registry_v1_t;

mesh_mgmt_execution_rpc_registry_result_t
mesh_mgmt_execution_rpc_registry_init_v1(
    mesh_mgmt_execution_rpc_registry_v1_t *registry, size_t capacity,
    uint64_t terminal_retention_ms);

void mesh_mgmt_execution_rpc_registry_destroy_v1(
    mesh_mgmt_execution_rpc_registry_v1_t *registry);

/**
 * Registers an immutable request binding. Reusing either command_id or
 * correlation_id with different fields is a conflict.
 */
mesh_mgmt_execution_rpc_registry_result_t
mesh_mgmt_execution_rpc_registry_register_v1(
    mesh_mgmt_execution_rpc_registry_v1_t *registry,
    const mesh_mgmt_execution_rpc_binding_v1_t *binding, uint64_t now_ms);

/**
 * Remove a pending entry only when every immutable binding field matches.
 * This is reserved for a transport that can prove no send side effect
 * occurred. Ambiguous send failures must remain registered until completion
 * or timeout.
 */
mesh_mgmt_execution_rpc_registry_result_t
mesh_mgmt_execution_rpc_registry_abandon_v1(
    mesh_mgmt_execution_rpc_registry_v1_t *registry,
    const mesh_mgmt_execution_rpc_binding_v1_t *binding);

/**
 * Completes a pending binding from an owned response produced by
 * mesh_mgmt_execution_response_from_event_v1(). Identity, digest, command,
 * and correlation bindings are checked again before committing the terminal
 * state.
 */
mesh_mgmt_execution_rpc_registry_result_t
mesh_mgmt_execution_rpc_registry_complete_v1(
    mesh_mgmt_execution_rpc_registry_v1_t *registry,
    const mesh_mgmt_execution_response_v1_t *response, uint64_t now_ms);

mesh_mgmt_execution_rpc_registry_result_t
mesh_mgmt_execution_rpc_registry_get_v1(
    mesh_mgmt_execution_rpc_registry_v1_t *registry,
    const uint8_t correlation_id[MESH_MGMT_EXECUTION_ID_SIZE],
    uint64_t now_ms, mesh_mgmt_execution_rpc_completion_v1_t *out_completion);

/**
 * Releases only a terminal entry after its RPC consumer has durably consumed
 * the response. Pending entries cannot be removed through this API.
 */
mesh_mgmt_execution_rpc_registry_result_t
mesh_mgmt_execution_rpc_registry_release_v1(
    mesh_mgmt_execution_rpc_registry_v1_t *registry,
    const uint8_t correlation_id[MESH_MGMT_EXECUTION_ID_SIZE]);

/**
 * Converts expired pending entries to TIMED_OUT and removes terminal entries
 * whose retention interval has elapsed. Returns the number removed.
 * Complexity is O(capacity), with capacity fixed at initialization.
 */
size_t mesh_mgmt_execution_rpc_registry_sweep_v1(
    mesh_mgmt_execution_rpc_registry_v1_t *registry, uint64_t now_ms);

#ifdef __cplusplus
}
#endif

#endif
