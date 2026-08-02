#ifndef MESH_MGMT_EXECUTION_RPC_CONTROL_H
#define MESH_MGMT_EXECUTION_RPC_CONTROL_H

#include "mesh_mgmt_execution_rpc_registry.h"
#include "mesh_mgmt_execution_wire.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  MESH_MGMT_EXECUTION_RPC_CONTROL_OK = 0,
  MESH_MGMT_EXECUTION_RPC_CONTROL_INVALID_ARG = -1,
  MESH_MGMT_EXECUTION_RPC_CONTROL_CLOCK_FAILED = -2,
  MESH_MGMT_EXECUTION_RPC_CONTROL_INVALID_REQUEST = -3,
  MESH_MGMT_EXECUTION_RPC_CONTROL_AUTH_FAILED = -4,
  MESH_MGMT_EXECUTION_RPC_CONTROL_SCOPE_MISMATCH = -5,
  MESH_MGMT_EXECUTION_RPC_CONTROL_ALREADY_EXISTS = -6,
  MESH_MGMT_EXECUTION_RPC_CONTROL_CONFLICT = -7,
  MESH_MGMT_EXECUTION_RPC_CONTROL_RESOURCE_EXHAUSTED = -8,
  MESH_MGMT_EXECUTION_RPC_CONTROL_SEND_UNAVAILABLE = -9,
  MESH_MGMT_EXECUTION_RPC_CONTROL_SEND_AMBIGUOUS = -10,
  MESH_MGMT_EXECUTION_RPC_CONTROL_NOT_FOUND = -11,
  MESH_MGMT_EXECUTION_RPC_CONTROL_ALREADY_COMPLETE = -12,
  MESH_MGMT_EXECUTION_RPC_CONTROL_NOT_READY = -13,
  MESH_MGMT_EXECUTION_RPC_CONTROL_STATE_ERROR = -14
} mesh_mgmt_execution_rpc_control_result_t;

typedef enum {
  MESH_MGMT_EXECUTION_RPC_TRANSPORT_SENT = 0,
  MESH_MGMT_EXECUTION_RPC_TRANSPORT_UNAVAILABLE = -1,
  MESH_MGMT_EXECUTION_RPC_TRANSPORT_AMBIGUOUS = -2
} mesh_mgmt_execution_rpc_transport_result_t;

typedef uint64_t (*mesh_mgmt_execution_rpc_clock_v1_fn)(void *context);

/**
 * The payload and target are borrowed for the duration of the call.
 * UNAVAILABLE may be returned only when the callback can prove that no
 * transport side effect occurred.
 */
typedef mesh_mgmt_execution_rpc_transport_result_t
(*mesh_mgmt_execution_rpc_send_v1_fn)(
    void *context,
    const uint8_t target_node_id[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    const uint8_t *payload, size_t payload_size);

typedef struct {
  mesh_mgmt_execution_rpc_registry_v1_t *registry;
  uint8_t expected_mesh_id[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint8_t local_principal_key[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint8_t expected_grant_issuer_key[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  mesh_mgmt_execution_rpc_clock_v1_fn clock_now_ms;
  void *clock_context;
  mesh_mgmt_execution_rpc_send_v1_fn send;
  void *send_context;
} mesh_mgmt_execution_rpc_control_config_v1_t;

/**
 * Single-owner control-plane coordinator. It does not own the registry or
 * callback contexts and is not thread-safe.
 */
typedef struct {
  mesh_mgmt_execution_rpc_control_config_v1_t config;
  uint8_t initialized;
} mesh_mgmt_execution_rpc_control_v1_t;

mesh_mgmt_execution_rpc_control_result_t
mesh_mgmt_execution_rpc_control_init_v1(
    mesh_mgmt_execution_rpc_control_v1_t *control,
    const mesh_mgmt_execution_rpc_control_config_v1_t *config);

/**
 * Validate and register one canonical COMMAND_REQUEST before sending it.
 * Exact duplicates are idempotent and are not sent a second time.
 */
mesh_mgmt_execution_rpc_control_result_t
mesh_mgmt_execution_rpc_control_submit_v1(
    mesh_mgmt_execution_rpc_control_v1_t *control, const uint8_t *payload,
    size_t payload_size,
    mesh_mgmt_execution_rpc_binding_v1_t *out_binding);

mesh_mgmt_execution_rpc_control_result_t
mesh_mgmt_execution_rpc_control_get_v1(
    mesh_mgmt_execution_rpc_control_v1_t *control,
    const uint8_t correlation_id[MESH_MGMT_EXECUTION_ID_SIZE],
    mesh_mgmt_execution_rpc_completion_v1_t *out_completion);

/**
 * Commit a response only after the caller has verified transport, session,
 * envelope, responder identity, and execution response signatures.
 */
mesh_mgmt_execution_rpc_control_result_t
mesh_mgmt_execution_rpc_control_complete_v1(
    mesh_mgmt_execution_rpc_control_v1_t *control,
    const mesh_mgmt_execution_response_v1_t *verified_response);

size_t mesh_mgmt_execution_rpc_control_sweep_v1(
    mesh_mgmt_execution_rpc_control_v1_t *control);

#ifdef __cplusplus
}
#endif

#endif
