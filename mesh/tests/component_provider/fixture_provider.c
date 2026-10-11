#include "mesh_control_component_provider.h"
#include "mesh_mgmt_service_component.h"
#include "fixture_service_gate.h"
#include <salts/plugin_decl.h>
#include <stdlib.h>
#include <string.h>

/* A real DSO fixture with one retained completion and owned ObjectRef. Plugin
 * quiescence depends on Component destruction, making release order observable. */
static struct {
  mesh_control_provider_completion_v1_t completion;
  int ready;
  int closed;
  int created;
  int destroyed;
} state;

static mesh_control_result_t start(void *context, const mesh_control_provider_request_v1_t *r) {
  (void)context;
  if (r == NULL) return MESH_CONTROL_INVALID_ARG;
  if (state.closed) return MESH_CONTROL_CLOSED;
  if (state.ready) return MESH_CONTROL_RESOURCE_EXHAUSTED;
  memcpy(state.completion.operation_id, r->operation.operation_id, MESH_CONTROL_ID_SIZE);
  state.completion.state = MESH_CONTROL_PROVIDER_COMPLETED;
  state.ready = 1;
  return MESH_CONTROL_OK;
}
static mesh_control_result_t peek(void *context, mesh_control_provider_completion_v1_t *out) {
  (void)context;
  if (out == NULL) return MESH_CONTROL_INVALID_ARG;
  if (!state.ready) return MESH_CONTROL_EMPTY;
  *out = state.completion;
  return MESH_CONTROL_OK;
}
static mesh_control_result_t ack(void *context, const uint8_t *id) {
  (void)context;
  if (id == NULL || !state.ready ||
      memcmp(id, state.completion.operation_id, MESH_CONTROL_ID_SIZE) != 0)
    return MESH_CONTROL_INVALID_ARG;
  state.ready = 0;
  return MESH_CONTROL_OK;
}
static void close_provider(void *context) { (void)context; state.closed = 1; }
static int drained(void *context) { (void)context; return state.closed && !state.ready; }

static const mesh_control_provider_v1_t provider = {
  {0x22}, MESH_CONTROL_FUNCTION_NATIVE, 0,
  {start, peek, ack, close_provider, drained}, &state
};
cmeta_component(MeshControlFixture, cmeta_provides(mesh_control_component_provider_v1));

static void destroy_object(void *context, void *object) {
  (void)context; (void)object;
  /* A failed candidate may be destroyed before any work has been admitted. */
  if (state.ready || state.destroyed) abort();
  state.destroyed = 1;
}
static const cmeta_object_lifecycle lifecycle = {
  sizeof(cmeta_object_lifecycle), NULL, NULL, NULL, destroy_object
};
static cmeta_status SALTS_COMPONENT_CALL create(
    void *context, const cmeta_data_desc *data, const void *config,
    const salts_component_dependency *dependencies, size_t count, cmeta_object_ref *out) {
  cmeta_status result;
  if (state.created) return CMETA_INVALID_ARGUMENT;
  result = mesh_control_component_create_v1(context, data, config, dependencies, count, out);
  if (result != CMETA_OK) return result;
  result = cmeta_object_take(out, &lifecycle);
  if (result == CMETA_OK) state.created = 1;
  return result;
}
static const salts_component_provider_binding binding = {
  sizeof(salts_component_provider_binding), SALTS_COMPONENT_PROVIDER_BINDING_ABI_VERSION,
  cmeta_component_meta(MeshControlFixture), (void *)&provider,
  &mesh_control_component_interfaces_v1, create, NULL, NULL
};
static cmeta_status SALTS_COMPONENT_CALL failing_create(
    void *context, const cmeta_data_desc *data, const void *config,
    const salts_component_dependency *dependencies, size_t count, cmeta_object_ref *out) {
  cmeta_status result = create(context, data, config, dependencies, count, out);
  return result == CMETA_OK ? CMETA_CALLBACK_ERROR : result;
}
static const salts_component_provider_binding failing_binding = {
  sizeof(salts_component_provider_binding), SALTS_COMPONENT_PROVIDER_BINDING_ABI_VERSION,
  cmeta_component_meta(MeshControlFixture), (void *)&provider,
  &mesh_control_component_interfaces_v1, failing_create, NULL, NULL
};
static const salts_component_provider_binding *get_binding(void *self) { return self; }
CMETA_IMPLEMENTS(salts_component_provider, fixture_impl, 0u, .get_binding = get_binding);
static salts_component_provider carrier = {(void *)&binding, &fixture_impl_vtable};
static salts_component_provider failing_carrier = {(void *)&failing_binding, &fixture_impl_vtable};
static salts_component_provider service_carrier = {
  (void *)&mesh_mgmt_rpc_service_component_binding_v1, &fixture_impl_vtable
};
static salts_component_provider gated_carrier = {
  (void *)&mesh_test_service_gate_binding, &fixture_impl_vtable
};

static cmeta_plugin_status CMETA_PLUGIN_CALL plugin_start(void *self) {
  (void)self;
  memset(&state, 0, sizeof(state));
  return CMETA_PLUGIN_OK;
}
static cmeta_plugin_status CMETA_PLUGIN_CALL plugin_stop(void *self) {
  (void)self;
  close_provider(NULL);
  return CMETA_PLUGIN_OK;
}
static bool CMETA_PLUGIN_CALL quiet(const void *self) {
  (void)self;
  return !state.ready && (!state.created || state.destroyed);
}
static void CMETA_PLUGIN_CALL plugin_destroy(void *self) {
  if (!quiet(self)) abort();
}
#define EXPORTS(X) \
  X(interface, (salts_component_provider, &carrier), "mesh-control-provider", \
    SALTS_COMPONENT_PROVIDER_CONTRACT_ID, SALTS_COMPONENT_PROVIDER_CONTRACT_VERSION, 0) \
  X(interface, (salts_component_provider, &failing_carrier), "failing-mesh-control-provider", \
    SALTS_COMPONENT_PROVIDER_CONTRACT_ID, SALTS_COMPONENT_PROVIDER_CONTRACT_VERSION, 0) \
  X(interface, (salts_component_provider, &service_carrier), "mesh-rpc-service", \
    SALTS_COMPONENT_PROVIDER_CONTRACT_ID, SALTS_COMPONENT_PROVIDER_CONTRACT_VERSION, 0) \
  X(interface, (salts_component_provider, &gated_carrier), "gated-mesh-rpc-service", \
    SALTS_COMPONENT_PROVIDER_CONTRACT_ID, SALTS_COMPONENT_PROVIDER_CONTRACT_VERSION, 0)
CMETA_PLUGIN_DECLARE(mesh_control_fixture, "test.turbo.mesh.control", (1,0,0), EXPORTS,
    CMETA_PLUGIN_LIFECYCLE(&state, plugin_start, plugin_stop, quiet, plugin_destroy));
