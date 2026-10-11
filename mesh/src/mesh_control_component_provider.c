#include "mesh_control_component_provider.h"
#include <string.h>

static int identity_valid(const mesh_control_provider_v1_t *provider) {
  size_t i;
  uint8_t aggregate = 0;
  for (i = 0; i < sizeof(provider->provider_id); ++i)
    aggregate |= provider->provider_id[i];
  return aggregate != 0 && provider->reserved == 0 &&
      (provider->runtime == MESH_CONTROL_FUNCTION_BUILTIN ||
       provider->runtime == MESH_CONTROL_FUNCTION_NATIVE ||
       provider->runtime == MESH_CONTROL_FUNCTION_WASM);
}

static mesh_control_result_t provider_identity(void *self, uint8_t *id, uint16_t *runtime) {
  const mesh_control_provider_v1_t *p = self;
  if (id == NULL || runtime == NULL) return MESH_CONTROL_INVALID_ARG;
  memcpy(id, p->provider_id, sizeof(p->provider_id));
  *runtime = p->runtime;
  return MESH_CONTROL_OK;
}
static mesh_control_result_t provider_start(void *self, const mesh_control_provider_request_v1_t *r) {
  const mesh_control_provider_v1_t *p = self;
  return p->ops.try_start(p->context, r);
}
static mesh_control_result_t provider_peek(void *self, mesh_control_provider_completion_v1_t *c) {
  const mesh_control_provider_v1_t *p = self;
  return p->ops.try_peek_completion(p->context, c);
}
static mesh_control_result_t provider_ack(void *self, const uint8_t *id) {
  const mesh_control_provider_v1_t *p = self;
  return p->ops.ack_completion(p->context, id);
}
static void provider_close(void *self) {
  const mesh_control_provider_v1_t *p = self;
  p->ops.close(p->context);
}
static int provider_drained(void *self) {
  const mesh_control_provider_v1_t *p = self;
  return p->ops.is_drained(p->context);
}
CMETA_IMPLEMENTS(mesh_control_component_provider_v1, mesh_control_component_impl_v1, 0u,
    .identity = provider_identity, .try_start = provider_start,
    .try_peek_completion = provider_peek, .ack_completion = provider_ack,
    .close = provider_close, .is_drained = provider_drained);

static cmeta_status project(void *context, const cmeta_object_ref *object,
                            const cmeta_interface_desc *expected,
                            cmeta_interface_projection *out) {
  (void)context;
  if (object == NULL || out == NULL) return CMETA_INVALID_ARGUMENT;
  if (!cmeta_interface_desc_equal(expected, mesh_control_component_provider_v1_interface()))
    return CMETA_TRAIT_MISSING;
  out->size = sizeof(*out);
  out->self = object->object;
  out->interface = mesh_control_component_provider_v1_interface();
  out->dispatch = &mesh_control_component_impl_v1_vtable;
  return CMETA_OK;
}
const cmeta_object_interface_provider mesh_control_component_interfaces_v1 = {
    sizeof(cmeta_object_interface_provider), NULL, project
};

cmeta_status SALTS_COMPONENT_CALL mesh_control_component_create_v1(
    void *context, const cmeta_data_desc *data, const void *config,
    const salts_component_dependency *dependencies, size_t dependency_count,
    cmeta_object_ref *out) {
  const mesh_control_provider_v1_t *p = context;
  (void)dependencies;
  if (p == NULL || out == NULL || data != NULL || config != NULL || dependency_count != 0)
    return CMETA_INVALID_ARGUMENT;
  if (!identity_valid(p) || p->ops.try_start == NULL || p->ops.try_peek_completion == NULL ||
      p->ops.ack_completion == NULL || p->ops.close == NULL || p->ops.is_drained == NULL)
    return CMETA_INVALID_ARGUMENT;
  return cmeta_object_borrow(out, context, cmeta_reflected_data(mesh_control_provider_v1_t), NULL);
}
static int lease_live(const mesh_control_component_lease_v1_t *lease) {
  return lease != NULL && salts_component_plugin_scope_generation_id(&lease->scope) != 0;
}
static mesh_control_result_t lease_start(void *context, const mesh_control_provider_request_v1_t *r) {
  mesh_control_component_lease_v1_t *lease = context;
  if (!lease_live(lease)) return MESH_CONTROL_INVALID_STATE;
  if (lease->closed) return MESH_CONTROL_CLOSED;
  return mesh_control_component_provider_v1_try_start(&lease->service, r);
}
static mesh_control_result_t lease_peek(void *context, mesh_control_provider_completion_v1_t *c) {
  mesh_control_component_lease_v1_t *lease = context;
  if (!lease_live(lease)) return MESH_CONTROL_INVALID_STATE;
  return mesh_control_component_provider_v1_try_peek_completion(&lease->service, c);
}
static mesh_control_result_t lease_ack(void *context, const uint8_t *id) {
  mesh_control_component_lease_v1_t *lease = context;
  if (!lease_live(lease)) return MESH_CONTROL_INVALID_STATE;
  return mesh_control_component_provider_v1_ack_completion(&lease->service, id);
}
static void lease_close(void *context) {
  mesh_control_component_lease_v1_t *lease = context;
  if (lease_live(lease) && !lease->closed) {
    lease->closed = 1;
    mesh_control_component_provider_v1_close(&lease->service);
  }
}
static int lease_drained(void *context) {
  mesh_control_component_lease_v1_t *lease = context;
  return lease_live(lease) && lease->closed &&
      mesh_control_component_provider_v1_is_drained(&lease->service);
}

salts_component_plugin_status mesh_control_component_lease_acquire_v1(
    mesh_control_component_lease_v1_t *lease,
    salts_component_plugin_runtime *runtime, const char *id) {
  salts_component_service service;
  salts_component_plugin_status status;
  if (lease == NULL || id == NULL || lease->scope.live || lease->scope.runtime != NULL ||
      lease->scope.owner_address != NULL) return SALTS_COMPONENT_PLUGIN_INVALID_ARGUMENT;
  status = salts_component_plugin_scope_acquire(runtime, &lease->scope);
  if (status != SALTS_COMPONENT_PLUGIN_OK) return status;
  status = salts_component_plugin_scope_find_service_from(&lease->scope, id,
      mesh_control_component_provider_v1_interface(), &service);
  if (status == SALTS_COMPONENT_PLUGIN_OK) {
    if (mesh_control_component_provider_v1_borrow_from_object(service.object, service.interfaces,
        &lease->service) != CMETA_OK) status = SALTS_COMPONENT_PLUGIN_PROVIDER_ERROR;
  }
  if (status == SALTS_COMPONENT_PLUGIN_OK) {
    memset(&lease->provider, 0, sizeof(lease->provider));
    if (mesh_control_component_provider_v1_identity(&lease->service, lease->provider.provider_id,
        &lease->provider.runtime) != MESH_CONTROL_OK || !identity_valid(&lease->provider))
      status = SALTS_COMPONENT_PLUGIN_PROVIDER_ERROR;
  }
  if (status != SALTS_COMPONENT_PLUGIN_OK) {
    salts_component_plugin_status released = salts_component_plugin_scope_release(&lease->scope);
    if (released != SALTS_COMPONENT_PLUGIN_OK) return released;
    memset(lease, 0, sizeof(*lease));
    return status;
  }
  lease->provider.ops.try_start = lease_start;
  lease->provider.ops.try_peek_completion = lease_peek;
  lease->provider.ops.ack_completion = lease_ack;
  lease->provider.ops.close = lease_close;
  lease->provider.ops.is_drained = lease_drained;
  lease->provider.context = lease;
  lease->closed = 0;
  return SALTS_COMPONENT_PLUGIN_OK;
}
const mesh_control_provider_v1_t *mesh_control_component_lease_provider_v1(
    const mesh_control_component_lease_v1_t *lease) {
  return lease_live(lease) ? &lease->provider : NULL;
}
salts_component_plugin_status mesh_control_component_lease_release_v1(
    mesh_control_component_lease_v1_t *lease) {
  salts_component_plugin_status status;
  if (!lease_live(lease)) return SALTS_COMPONENT_PLUGIN_INVALID_STATE;
  if (!lease_drained(lease)) return SALTS_COMPONENT_PLUGIN_BUSY;
  status = salts_component_plugin_scope_release(&lease->scope);
  if (status == SALTS_COMPONENT_PLUGIN_OK) memset(lease, 0, sizeof(*lease));
  return status;
}
