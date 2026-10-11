#ifndef MESH_CONTROL_COMPONENT_PROVIDER_H
#define MESH_CONTROL_COMPONENT_PROVIDER_H

#include "mesh_control_reconciler.h"
#include <cmeta/data_reflect.h>
#include <salts/component_plugin.h>

/* Read-only native projection: omitted callbacks/context remain opaque. This
 * does not grant value lifecycle or change the existing provider's layout. */
cmeta_reflect_data(mesh_control_provider_v1_t, "turbo.mesh.control.provider.v1",
    cmeta_data_field(uint16_t, runtime, &cmeta_data_uint16, &cmeta_type_uint16)
    cmeta_data_field(uint16_t, reserved, &cmeta_data_uint16, &cmeta_type_uint16));

#define MESH_CONTROL_COMPONENT_PROVIDER_METHODS_V1(X, I) \
    X(I, R2, mesh_control_result_t, identity, uint8_t *, provider_id, uint16_t *, runtime) \
    X(I, R1, mesh_control_result_t, try_start, const mesh_control_provider_request_v1_t *, request) \
    X(I, R1, mesh_control_result_t, try_peek_completion, mesh_control_provider_completion_v1_t *, completion) \
    X(I, R1, mesh_control_result_t, ack_completion, const uint8_t *, operation_id) \
    X(I, V0, void, close, _) \
    X(I, R0, int, is_drained, _)

CMETA_INTERFACE(mesh_control_component_provider_v1,
                MESH_CONTROL_COMPONENT_PROVIDER_METHODS_V1);
CMETA_OBJECT_INTERFACE_ADAPTER(mesh_control_component_provider_v1);

#ifdef __cplusplus
extern "C" {
#endif

extern const cmeta_object_interface_provider mesh_control_component_interfaces_v1;
cmeta_status SALTS_COMPONENT_CALL mesh_control_component_create_v1(
    void *provider_context, const cmeta_data_desc *config_data,
    const void *config_value, const salts_component_dependency *dependencies,
    size_t dependency_count, cmeta_object_ref *out_instance);

/* Explicit static binding for an already initialized provider. The immutable
 * descriptor, context and component metadata must outlive generation drain.
 * The original owner retains destruction responsibility after drain. Config
 * is intentionally absent: provider construction belongs to that owner.
 * Each component ID selects one provider; no discovery/ranking is performed. */
#define MESH_CONTROL_COMPONENT_BINDING_V1(component_, provider_) \
    { sizeof(salts_component_provider_binding), \
      SALTS_COMPONENT_PROVIDER_BINDING_ABI_VERSION, cmeta_component_meta(component_), \
      (void *)(provider_), &mesh_control_component_interfaces_v1, \
      mesh_control_component_create_v1, NULL, NULL }

/* Zero initialize before acquire. A live lease is single-owner, address-stable,
 * noncopyable, and used on the provider's owner thread. The host must select a
 * native provider in only one live lease/generation: scopes pin code and do
 * not arbitrate exclusive native I/O authority. The legacy view is
 * borrowed by the reconciler until it has closed, drained and been destroyed.
 * Release requires close + drained (including exact completion ACK). */
typedef struct mesh_control_component_lease_v1 {
  salts_component_plugin_scope scope;
  mesh_control_component_provider_v1 service;
  mesh_control_provider_v1_t provider;
  int closed;
} mesh_control_component_lease_v1_t;

#define MESH_CONTROL_COMPONENT_LEASE_INIT_V1 {0}

salts_component_plugin_status mesh_control_component_lease_acquire_v1(
    mesh_control_component_lease_v1_t *lease,
    salts_component_plugin_runtime *runtime, const char *component_id);

/* NULL for empty, released, copied or moved leases. The returned descriptor
 * and any reconciler copy of its callbacks/context expire at release. */
const mesh_control_provider_v1_t *mesh_control_component_lease_provider_v1(
    const mesh_control_component_lease_v1_t *lease);

/* BUSY preserves ownership. Finish/ACK provider work and destroy every
 * reconciler borrowing this lease before successful release; then close/drain
 * the generation, request Plugin stop, poll quiescence and unload. */
salts_component_plugin_status mesh_control_component_lease_release_v1(
    mesh_control_component_lease_v1_t *lease);

#ifdef __cplusplus
}
#endif
#endif
