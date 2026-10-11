#include "mesh_mgmt_service_component.h"
#include <stdlib.h>
#include <string.h>

static mesh_mgmt_service_config_result_t snapshot(void *self, mesh_mgmt_service_publish_v1_t *out) {
  const mesh_mgmt_service_config_v1_t *config = self;
  if (out == NULL) return MESH_MGMT_SERVICE_CONFIG_INVALID_ARG;
  memset(out, 0, sizeof(*out));
  /* Admission made this owner immutable and canonical. No schema/descriptor
   * traversal is needed on subsequent typed calls. */
  out->address_family = config->address_family;
  memcpy(out->virtual_address, config->virtual_address, sizeof(out->virtual_address));
  out->port = config->port;
  out->dns_name = config->dns_name;
  return MESH_MGMT_SERVICE_CONFIG_OK;
}
CMETA_IMPLEMENTS(mesh_mgmt_service_provider_v1, mesh_mgmt_service_component_impl_v1,
                 0u, .snapshot = snapshot);

static cmeta_status project(void *context, const cmeta_object_ref *object,
                            const cmeta_interface_desc *expected, cmeta_interface_projection *out) {
  (void)context;
  if (object == NULL || out == NULL) return CMETA_INVALID_ARGUMENT;
  if (!cmeta_interface_desc_equal(expected, mesh_mgmt_service_provider_v1_interface()))
    return CMETA_TRAIT_MISSING;
  out->size = sizeof(*out);
  out->interface = mesh_mgmt_service_provider_v1_interface();
  out->self = object->object;
  out->dispatch = &mesh_mgmt_service_component_impl_v1_vtable;
  return CMETA_OK;
}
const cmeta_object_interface_provider mesh_mgmt_service_component_interfaces_v1 = {
  sizeof(cmeta_object_interface_provider), NULL, project
};
static void destroy(void *context, void *object) {
  (void)context;
  free(object);
}
static const cmeta_object_lifecycle lifecycle = {
  sizeof(cmeta_object_lifecycle), NULL, NULL, NULL, destroy
};
cmeta_status SALTS_COMPONENT_CALL mesh_mgmt_service_component_create_v1(
    void *context, const cmeta_data_desc *data, const void *config,
    const salts_component_dependency *dependencies, size_t count, cmeta_object_ref *out) {
  mesh_mgmt_service_config_v1_t *owned;
  mesh_mgmt_service_publish_v1_t checked;
  cmeta_status status;
  (void)context; (void)dependencies;
  if (out == NULL || config == NULL || count != 0 ||
      !cmeta_data_desc_equal(data, cmeta_reflected_data(mesh_mgmt_service_config_v1_t)))
    return CMETA_INVALID_ARGUMENT;
  if (mesh_mgmt_service_config_publish_view_v1(config, &checked) != MESH_MGMT_SERVICE_CONFIG_OK)
    return CMETA_INVALID_ARGUMENT;
  /* One fixed-size snapshot per admitted deployment, bounded by the host's
   * generation storage. Nothing is allocated or retained per publication. */
  owned = malloc(sizeof(*owned));
  if (owned == NULL) return CMETA_OUT_OF_MEMORY;
  *owned = *(const mesh_mgmt_service_config_v1_t *)config;
  status = cmeta_object_borrow(out, owned, cmeta_reflected_data(mesh_mgmt_service_config_v1_t), NULL);
  if (status == CMETA_OK) status = cmeta_object_take(out, &lifecycle);
  if (status != CMETA_OK) {
    cmeta_object_release(out);
    free(owned);
  }
  return status;
}
const salts_component_provider_binding mesh_mgmt_rpc_service_component_binding_v1 =
    MESH_MGMT_SERVICE_COMPONENT_BINDING_V1(MeshMgmtRpcServiceV1);

salts_component_plugin_status mesh_mgmt_service_component_bind_v1(
    const salts_component_plugin_scope *scope, const char *id,
    mesh_mgmt_service_component_view_v1_t *out) {
  salts_component_service service;
  salts_component_plugin_status status;
  if (out == NULL) return SALTS_COMPONENT_PLUGIN_INVALID_ARGUMENT;
  memset(out, 0, sizeof(*out));
  if (id == NULL) return SALTS_COMPONENT_PLUGIN_INVALID_ARGUMENT;
  status = salts_component_plugin_scope_find_service_from(scope, id,
      mesh_mgmt_service_provider_v1_interface(), &service);
  if (status != SALTS_COMPONENT_PLUGIN_OK) return status;
  if (mesh_mgmt_service_provider_v1_borrow_from_object(service.object, service.interfaces,
                                                     &out->provider) != CMETA_OK)
    return SALTS_COMPONENT_PLUGIN_PROVIDER_ERROR;
  out->scope = scope;
  out->generation_id = salts_component_plugin_scope_generation_id(scope);
  return SALTS_COMPONENT_PLUGIN_OK;
}
mesh_mgmt_service_config_result_t mesh_mgmt_service_component_snapshot_v1(
    const mesh_mgmt_service_component_view_v1_t *view, mesh_mgmt_service_publish_v1_t *out) {
  mesh_mgmt_service_config_result_t result;
  mesh_mgmt_service_provider_v1 provider;
  if (out == NULL) return MESH_MGMT_SERVICE_CONFIG_INVALID_ARG;
  memset(out, 0, sizeof(*out));
  if (view == NULL || view->generation_id == 0 ||
      salts_component_plugin_scope_generation_id(view->scope) != view->generation_id ||
      !mesh_mgmt_service_provider_v1_valid(&view->provider))
    return MESH_MGMT_SERVICE_CONFIG_INVALID_ARG;
  provider = view->provider;
  result = mesh_mgmt_service_provider_v1_snapshot(&provider, out);
  if (result != MESH_MGMT_SERVICE_CONFIG_OK) memset(out, 0, sizeof(*out));
  return result;
}
