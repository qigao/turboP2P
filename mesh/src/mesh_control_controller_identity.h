#ifndef MESH_CONTROL_CONTROLLER_IDENTITY_H
#define MESH_CONTROL_CONTROLLER_IDENTITY_H

#include "mesh_certificate_lifecycle.h"
#include "mesh_control_controller_session.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_CONTROL_CONTROLLER_IDENTITY_MAX_V1 4096u

typedef uint64_t (*mesh_control_controller_identity_now_fn)(void *context);

typedef struct {
  uint8_t node_id[MESH_CONTROL_NODE_ID_SIZE];
  uint8_t management_public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE];
  /** Borrowed immutable-on-callback snapshot; owner serializes reloads. */
  const mesh_certificate_lifecycle_v1_t *certificate;
  uint64_t identity_policy_generation;
} mesh_control_controller_identity_entry_v1_t;

typedef struct {
  mesh_control_controller_identity_entry_v1_t *entries;
  size_t capacity;
  size_t count;
  mesh_control_controller_identity_now_fn now_ms;
  void *now_context;
  uint8_t initialized;
} mesh_control_controller_identity_registry_v1_t;

mesh_control_result_t mesh_control_controller_identity_registry_init_v1(
    mesh_control_controller_identity_registry_v1_t *registry,
    size_t capacity, mesh_control_controller_identity_now_fn now_ms,
    void *now_context);

/** Insert or atomically replace one node at a strictly newer generation. */
mesh_control_result_t mesh_control_controller_identity_registry_put_v1(
    mesh_control_controller_identity_registry_v1_t *registry,
    const mesh_control_controller_identity_entry_v1_t *entry);

/** mesh_control_controller_identity_fn implementation. */
mesh_control_result_t mesh_control_controller_identity_authorize_v1(
    void *context,
    const uint8_t claimed_node_id[MESH_CONTROL_NODE_ID_SIZE],
    const uint8_t actual_tls_certificate_sha256[MESH_CONTROL_DIGEST_SIZE],
    mesh_control_agent_sync_hello_policy_v1_t *out_policy);

void mesh_control_controller_identity_registry_destroy_v1(
    mesh_control_controller_identity_registry_v1_t *registry);

#ifdef __cplusplus
}
#endif

#endif
