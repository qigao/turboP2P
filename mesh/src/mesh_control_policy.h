#ifndef MESH_CONTROL_POLICY_H
#define MESH_CONTROL_POLICY_H

#include "mesh_control_document.h"
#include "mesh_control_primitives.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  MESH_CONTROL_RUNTIME_AVAILABLE_BUILTIN = 1u << 0,
  MESH_CONTROL_RUNTIME_AVAILABLE_NATIVE = 1u << 1,
  MESH_CONTROL_RUNTIME_AVAILABLE_WASM = 1u << 2
} mesh_control_runtime_availability_v1_t;

#define MESH_CONTROL_RUNTIME_AVAILABLE_KNOWN_V1                            \
  (MESH_CONTROL_RUNTIME_AVAILABLE_BUILTIN |                              \
   MESH_CONTROL_RUNTIME_AVAILABLE_NATIVE |                               \
   MESH_CONTROL_RUNTIME_AVAILABLE_WASM)

typedef struct {
  uint64_t local_permissions;
  uint32_t available_runtimes;
} mesh_control_node_policy_v1_t;

/**
 * Safe production baseline: observation, management and built-in execution
 * are available. Native requires explicit local opt-in. WASM permission and
 * availability bits are reserved but rejected by the V1 policy validator.
 */
void mesh_control_node_policy_default_v1(
    mesh_control_node_policy_v1_t *out_policy);

mesh_control_result_t mesh_control_node_policy_validate_v1(
    const mesh_control_node_policy_v1_t *policy);

/**
 * Applies both permissions and actual runtime availability. This keeps the
 * WASM schema stable while third-party WASM execution remains unavailable.
 */
mesh_control_result_t mesh_control_node_policy_authorize_function_v1(
    const mesh_control_node_policy_v1_t *policy,
    const mesh_control_function_spec_v1_t *spec,
    uint64_t granted_permissions, uint64_t *out_effective_permissions);

/**
 * Authorizes and decodes a canonical function INTENT. APPLY binds the
 * function ID and generation to the envelope. DELETE must have no document
 * and requires MANAGE only. out_spec is cleared for DELETE.
 */
mesh_control_result_t mesh_control_node_policy_authorize_function_intent_v1(
    const mesh_control_node_policy_v1_t *policy,
    const mesh_control_envelope_v1_t *envelope, const uint8_t *payload,
    size_t payload_size, uint64_t granted_permissions,
    uint64_t *out_effective_permissions,
    mesh_control_function_spec_v1_t *out_spec);

#ifdef __cplusplus
}
#endif

#endif
