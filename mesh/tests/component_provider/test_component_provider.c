#include "mesh_control_component_provider.h"
#include "tinytest.h"
#include <string.h>

extern const cmeta_interface_desc *mesh_test_provider_cpp_interface(void);
extern const cmeta_data_desc *mesh_test_provider_cpp_data(void);
#define WRONG_METHODS(X,I) X(I,R0,int,other,_)
CMETA_INTERFACE(mesh_test_wrong_provider, WRONG_METHODS);

static cmeta_plugin_registry registry;
static cmeta_plugin_ref ref;
static salts_component_plugin_runtime runtime;
static salts_component_plugin_generation generation;
static salts_component_plugin_generation *previous;
static salts_component_deployment deployments[1];
static salts_component_instance instances[1];
static salts_component_dependency dependencies[1];
static size_t order[1];
static salts_component_plugin_module modules[1];
static mesh_control_component_lease_v1_t lease;
static const salts_component_plugin_generation_storage storage = {
  deployments, 1, instances, 1, dependencies, 1, order, 1, modules, 1
};

static salts_component_plugin_status build(const cmeta_data_desc *data, const void *config,
                                           const char *export_id) {
  const salts_component_plugin_source source = {ref, export_id, data, config};
  return salts_component_plugin_generation_build(&generation, 1, &registry, &storage,
      NULL, 0, &source, 1, NULL, 0);
}
static void publish(void) {
  check_equal(build(NULL, NULL, "mesh-control-provider"), SALTS_COMPONENT_PLUGIN_OK);
  check_equal(salts_component_plugin_runtime_publish(&runtime, &generation, &previous),
              SALTS_COMPONENT_PLUGIN_OK);
  check_equal(mesh_control_component_lease_acquire_v1(&lease, &runtime, "MeshControlFixture"),
              SALTS_COMPONENT_PLUGIN_OK);
}

suite("mesh Component provider and Plugin lifetime") {
  before_each() {
    const cmeta_plugin_registry_config config = {1};
    memset(&registry, 0, sizeof(registry));
    memset(&runtime, 0, sizeof(runtime));
    memset(&generation, 0, sizeof(generation));
    memset(&lease, 0, sizeof(lease));
    check_equal(cmeta_plugin_registry_init(&registry, &config), CMETA_PLUGIN_OK);
    check_equal(cmeta_plugin_registry_load(&registry, MESH_PROVIDER_PLUGIN_PATH, &ref),
                CMETA_PLUGIN_OK);
    check_equal(cmeta_plugin_registry_start(&registry, ref), CMETA_PLUGIN_OK);
    check_equal(salts_component_plugin_runtime_init(&runtime), SALTS_COMPONENT_PLUGIN_OK);
  }
  after_each() {
    bool quiescent = false;
    cmeta_plugin_lifecycle_info info;
    if (mesh_control_component_lease_provider_v1(&lease) != NULL) {
      const mesh_control_provider_v1_t *p = mesh_control_component_lease_provider_v1(&lease);
      mesh_control_provider_completion_v1_t completion;
      p->ops.close(p->context);
      if (p->ops.try_peek_completion(p->context, &completion) == MESH_CONTROL_OK)
        check_equal(p->ops.ack_completion(p->context, completion.operation_id), MESH_CONTROL_OK);
      check_equal(mesh_control_component_lease_release_v1(&lease), SALTS_COMPONENT_PLUGIN_OK);
    }
    if (runtime.current != NULL)
      check_equal(salts_component_plugin_runtime_close(&runtime, &previous), SALTS_COMPONENT_PLUGIN_OK);
    if (generation.state == SALTS_COMPONENT_PLUGIN_GENERATION_DRAINING)
      check_equal(salts_component_plugin_generation_drain(&runtime, &generation),
                  SALTS_COMPONENT_PLUGIN_OK);
    if (generation.state == SALTS_COMPONENT_PLUGIN_GENERATION_BUILT)
      check_equal(salts_component_plugin_generation_discard(&generation), SALTS_COMPONENT_PLUGIN_OK);
    check_equal(salts_component_plugin_runtime_destroy(&runtime), SALTS_COMPONENT_PLUGIN_OK);
    check_equal(cmeta_plugin_registry_get_lifecycle(&registry, ref, &info), CMETA_PLUGIN_OK);
    if (info.state == CMETA_PLUGIN_LIFECYCLE_STARTED)
      check_equal(cmeta_plugin_registry_request_stop(&registry, ref), CMETA_PLUGIN_OK);
    check_equal(cmeta_plugin_registry_poll_quiescent(&registry, ref, &quiescent), CMETA_PLUGIN_OK);
    check_true(quiescent);
    check_equal(cmeta_plugin_registry_unload(&registry, ref), CMETA_PLUGIN_OK);
    check_equal(cmeta_plugin_registry_destroy(&registry), CMETA_PLUGIN_OK);
  }

  it("compares immutable C11/C++17 descriptors by semantics") {
    check_true(cmeta_interface_desc_equal(mesh_control_component_provider_v1_interface(),
                                         mesh_test_provider_cpp_interface()));
    check_true(cmeta_data_desc_equal(cmeta_reflected_data(mesh_control_provider_v1_t),
                                    mesh_test_provider_cpp_data()));
    publish();
    {
      salts_component_service service;
      const cmeta_data_desc *data = NULL;
      const void *value = NULL;
      uint16_t replacement = MESH_CONTROL_FUNCTION_WASM;
      cmeta_interface_projection projection = CMETA_INTERFACE_PROJECTION_INIT;
      check_equal(salts_component_plugin_scope_find_service_from(&lease.scope, "MeshControlFixture",
          mesh_control_component_provider_v1_interface(), &service), SALTS_COMPONENT_PLUGIN_OK);
      check_equal(cmeta_object_field_read(service.object, "runtime", &data, &value), CMETA_OK);
      check_equal(*(const uint16_t *)value, (uint16_t)MESH_CONTROL_FUNCTION_NATIVE);
      check_equal(cmeta_object_field_assign((cmeta_object_ref *)service.object, "runtime", data,
                                           &replacement), CMETA_TRAIT_MISSING);
      check_equal(cmeta_object_interface_project_borrowed(service.object, service.interfaces,
          mesh_test_wrong_provider_interface(), &projection), CMETA_TRAIT_MISSING);
      check_null(projection.self);
    }
  }
  it("retains completion across close and pins DSO until exact ACK and object destruction") {
    mesh_control_provider_request_v1_t request = {0};
    mesh_control_provider_completion_v1_t completion, again;
    uint8_t wrong_id[MESH_CONTROL_ID_SIZE] = {9};
    bool quiet = true;
    mesh_control_provider_v1_t stale;
    const mesh_control_provider_v1_t *p;
    publish();
    p = mesh_control_component_lease_provider_v1(&lease);
    stale = *p;
    request.operation.operation_id[0] = 7;
    check_equal(p->ops.try_start(p->context, &request), MESH_CONTROL_OK);
    check_equal(p->ops.try_start(p->context, &request), MESH_CONTROL_RESOURCE_EXHAUSTED);
    check_equal(mesh_control_component_lease_release_v1(&lease), SALTS_COMPONENT_PLUGIN_BUSY);
    p->ops.close(p->context);
    p->ops.close(p->context);
    check_equal(p->ops.try_start(p->context, &request), MESH_CONTROL_CLOSED);
    check_equal(mesh_control_component_lease_release_v1(&lease), SALTS_COMPONENT_PLUGIN_BUSY);
    check_equal(salts_component_plugin_runtime_close(&runtime, &previous), SALTS_COMPONENT_PLUGIN_OK);
    check_equal(salts_component_plugin_generation_drain(&runtime, &generation),
                SALTS_COMPONENT_PLUGIN_BUSY);
    check_equal(cmeta_plugin_registry_request_stop(&registry, ref), CMETA_PLUGIN_OK);
    check_equal(cmeta_plugin_registry_unload(&registry, ref), CMETA_PLUGIN_BUSY);
    check_equal(p->ops.try_peek_completion(p->context, &completion), MESH_CONTROL_OK);
    check_equal(p->ops.ack_completion(p->context, wrong_id), MESH_CONTROL_INVALID_ARG);
    check_equal(p->ops.try_peek_completion(p->context, &again), MESH_CONTROL_OK);
    check_equal(again.operation_id, completion.operation_id, MESH_CONTROL_ID_SIZE);
    check_equal(p->ops.ack_completion(p->context, completion.operation_id), MESH_CONTROL_OK);
    check_true(p->ops.is_drained(p->context));
    check_equal(mesh_control_component_lease_release_v1(&lease), SALTS_COMPONENT_PLUGIN_OK);
    check_null(mesh_control_component_lease_provider_v1(&lease));
    check_equal(mesh_control_component_lease_release_v1(&lease), SALTS_COMPONENT_PLUGIN_INVALID_STATE);
    check_equal(stale.ops.try_start(stale.context, &request), MESH_CONTROL_INVALID_STATE);
    check_equal(cmeta_plugin_registry_poll_quiescent(&registry, ref, &quiet), CMETA_PLUGIN_OK);
    check_false(quiet); /* Component's owned ObjectRef is still alive. */
    check_equal(salts_component_plugin_generation_drain(&runtime, &generation),
                SALTS_COMPONENT_PLUGIN_OK);
    check_equal(cmeta_plugin_registry_poll_quiescent(&registry, ref, &quiet), CMETA_PLUGIN_OK);
    check_true(quiet);
  }
  it("rejects copied scopes and repeated acquire without losing the original pin") {
    mesh_control_component_lease_v1_t copied;
    publish();
    copied = lease;
    check_null(mesh_control_component_lease_provider_v1(&copied));
    check_equal(mesh_control_component_lease_release_v1(&copied), SALTS_COMPONENT_PLUGIN_INVALID_STATE);
    check_equal(mesh_control_component_lease_acquire_v1(&lease, &runtime, "MeshControlFixture"),
                SALTS_COMPONENT_PLUGIN_INVALID_ARGUMENT);
    check_equal(generation.active_scopes, (size_t)1);
    check_not_null(mesh_control_component_lease_provider_v1(&lease));
  }
  it("releases the scope on failed explicit service selection") {
    check_equal(build(NULL, NULL, "mesh-control-provider"), SALTS_COMPONENT_PLUGIN_OK);
    check_equal(salts_component_plugin_runtime_publish(&runtime, &generation, &previous),
                SALTS_COMPONENT_PLUGIN_OK);
    check_not_equal(mesh_control_component_lease_acquire_v1(&lease, &runtime, "missing"),
                    SALTS_COMPONENT_PLUGIN_OK);
    check_equal(generation.active_scopes, (size_t)0);
    check_null(mesh_control_component_lease_provider_v1(&lease));
  }
  it("rejects undeclared config and rolls back the candidate module lease") {
    cmeta_plugin_lifecycle_info info;
    int config = 1;
    check_equal(build(&cmeta_data_int, &config, "mesh-control-provider"),
                SALTS_COMPONENT_PLUGIN_COMPONENT_ERROR);
    check_equal(cmeta_plugin_registry_get_lifecycle(&registry, ref, &info), CMETA_PLUGIN_OK);
    check_equal(info.active_leases, (size_t)0);
  }
  it("rolls back missing exports without retaining a module lease") {
    cmeta_plugin_lifecycle_info info;
    check_equal(build(NULL, NULL, "missing"), SALTS_COMPONENT_PLUGIN_PLUGIN_ERROR);
    check_equal(cmeta_plugin_registry_get_lifecycle(&registry, ref, &info), CMETA_PLUGIN_OK);
    check_equal(info.active_leases, (size_t)0);
  }
  it("destroys a valid partial owned result when create fails before releasing its module") {
    cmeta_plugin_lifecycle_info info;
    bool quiescent = false;
    check_equal(build(NULL, NULL, "failing-mesh-control-provider"),
                SALTS_COMPONENT_PLUGIN_COMPONENT_ERROR);
    check_equal(generation.failure.component_status, SALTS_COMPONENT_CREATE_FAILED);
    check_equal(cmeta_plugin_registry_get_lifecycle(&registry, ref, &info), CMETA_PLUGIN_OK);
    check_equal(info.active_leases, (size_t)0);
    check_equal(cmeta_plugin_registry_request_stop(&registry, ref), CMETA_PLUGIN_OK);
    check_equal(cmeta_plugin_registry_poll_quiescent(&registry, ref, &quiescent), CMETA_PLUGIN_OK);
    check_true(quiescent); /* Requires the partial result's destructor. */
  }
  it("adapts the admitted provider into the real reconciler's bounded shutdown") {
    mesh_control_reconciler_v1_t reconciler = {0};
    mesh_control_reconciler_config_v1_t config;
    publish();
    config.providers = mesh_control_component_lease_provider_v1(&lease);
    config.provider_count = 1;
    config.inflight_capacity = 1;
    check_equal(mesh_control_reconciler_init_v1(&reconciler, &config), MESH_CONTROL_OK);
    check_equal(mesh_control_reconciler_has_provider_v1(&reconciler, config.providers->provider_id,
                 MESH_CONTROL_FUNCTION_NATIVE), MESH_CONTROL_OK);
    check_equal(mesh_control_reconciler_close_v1(&reconciler), MESH_CONTROL_OK);
    check_true(mesh_control_reconciler_is_drained_v1(&reconciler));
    mesh_control_reconciler_destroy_v1(&reconciler);
    check_equal(mesh_control_component_lease_release_v1(&lease), SALTS_COMPONENT_PLUGIN_OK);
  }
}
