#include "fixture_service_gate.h"
#include <stdlib.h>

typedef struct {
  cmeta_object_ref service;
  mesh_mgmt_service_provider_v1 provider;
  void (*pause)(void *context);
  void *context;
  int fixture_version;
} gated_service;

static mesh_mgmt_service_config_result_t snapshot(void *self, mesh_mgmt_service_publish_v1_t *out) {
  gated_service *owner = self;
  mesh_mgmt_service_config_result_t result =
      mesh_mgmt_service_provider_v1_snapshot(&owner->provider, out);
  if (result == MESH_MGMT_SERVICE_CONFIG_OK) owner->pause(owner->context);
  return result;
}
CMETA_IMPLEMENTS(mesh_mgmt_service_provider_v1, gated_service_impl, 0u, .snapshot = snapshot);

static cmeta_status project(void *context, const cmeta_object_ref *object,
    const cmeta_interface_desc *expected, cmeta_interface_projection *out) {
  (void)context;
  if (object == NULL || out == NULL) return CMETA_INVALID_ARGUMENT;
  if (!cmeta_interface_desc_equal(expected, mesh_mgmt_service_provider_v1_interface()))
    return CMETA_TRAIT_MISSING;
  out->size = sizeof(*out);
  out->interface = mesh_mgmt_service_provider_v1_interface();
  out->self = object->object;
  out->dispatch = &gated_service_impl_vtable;
  return CMETA_OK;
}
static const cmeta_object_interface_provider interfaces = {
  sizeof(cmeta_object_interface_provider), NULL, project
};
cmeta_reflect_data(gated_service, "test.turbo.mesh.service.gated.owner",
    cmeta_field(int, fixture_version));
static void destroy(void *context, void *object) {
  gated_service *owner = object;
  (void)context;
  cmeta_object_release(&owner->service);
  free(owner);
}
static const cmeta_object_lifecycle lifecycle = {
  sizeof(cmeta_object_lifecycle), NULL, NULL, NULL, destroy
};

static cmeta_status SALTS_COMPONENT_CALL create(void *context,
    const cmeta_data_desc *data, const void *config,
    const salts_component_dependency *dependencies, size_t count, cmeta_object_ref *out) {
  const mesh_test_service_gate_config *input = config;
  gated_service *owner;
  cmeta_status status;
  (void)context; (void)dependencies;
  if (out == NULL || input == NULL || count != 0 ||
      !cmeta_data_desc_equal(data, cmeta_reflected_data(mesh_test_service_gate_config)) ||
      input->pause == NULL || input->context == NULL)
    return CMETA_INVALID_ARGUMENT;
  owner = calloc(1, sizeof(*owner));
  if (owner == NULL) return CMETA_OUT_OF_MEMORY;
  status = mesh_mgmt_service_component_create_v1(NULL,
      cmeta_reflected_data(mesh_mgmt_service_config_v1_t), &input->service, NULL, 0, &owner->service);
  if (status == CMETA_OK)
    status = mesh_mgmt_service_provider_v1_borrow_from_object(&owner->service,
        &mesh_mgmt_service_component_interfaces_v1, &owner->provider);
  if (status != CMETA_OK) {
    destroy(NULL, owner);
    return status;
  }
  owner->pause = input->pause;
  owner->context = input->context;
  owner->fixture_version = 1;
  status = cmeta_object_borrow(out, owner, cmeta_reflected_data(gated_service), NULL);
  if (status == CMETA_OK) status = cmeta_object_take(out, &lifecycle);
  if (status != CMETA_OK) {
    cmeta_object_release(out);
    destroy(NULL, owner);
  }
  return status;
}
cmeta_component_configured(MeshMgmtGatedServiceFixture,
    cmeta_reflected_data(mesh_test_service_gate_config),
    cmeta_provides(mesh_mgmt_service_provider_v1));
const salts_component_provider_binding mesh_test_service_gate_binding = {
  sizeof(salts_component_provider_binding), SALTS_COMPONENT_PROVIDER_BINDING_ABI_VERSION,
  cmeta_component_meta(MeshMgmtGatedServiceFixture), NULL, &interfaces, create, NULL, NULL
};
