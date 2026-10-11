#include "mesh_mgmt_service_component.h"
#include <tinytest.h>
#include <string.h>

extern const cmeta_interface_desc *mesh_test_service_cpp_interface(void);
extern const cmeta_data_desc *mesh_test_service_cpp_data(void);

static cmeta_plugin_registry registry;
static cmeta_plugin_ref ref;
static salts_component_plugin_runtime runtime;
static salts_component_plugin_generation generation;
static salts_component_plugin_generation *previous;
static salts_component_plugin_scope scope;
static mesh_mgmt_service_component_view_v1_t view;
static mesh_mgmt_service_config_v1_t config;
static salts_component_deployment deployments[2];
static salts_component_instance instances[2];
static salts_component_dependency dependencies[2];
static size_t order[2];
static salts_component_plugin_module modules[1];
static const salts_component_plugin_generation_storage storage = {
  deployments, 2, instances, 2, dependencies, 2, order, 2, modules, 1
};
static const char json[] =
  "{\"schema_version\":1,\"address_family\":4,\"octet0\":100,"
  "\"octet1\":64,\"octet2\":0,\"octet3\":2,\"port\":7878,"
  "\"dns_name\":\"node-b.mesh\"}";

static salts_component_plugin_status build(const cmeta_data_desc *data, const char *id) {
  const salts_component_plugin_source source = {ref, id, data, &config};
  return salts_component_plugin_generation_build(&generation, 1, &registry, &storage,
      NULL, 0, &source, 1, NULL, 0);
}
static void publish(void) {
  check_equal(build(cmeta_reflected_data(mesh_mgmt_service_config_v1_t), "mesh-rpc-service"),
              SALTS_COMPONENT_PLUGIN_OK);
  check_equal(salts_component_plugin_runtime_publish(&runtime, &generation, &previous),
              SALTS_COMPONENT_PLUGIN_OK);
  check_equal(salts_component_plugin_scope_acquire(&runtime, &scope), SALTS_COMPONENT_PLUGIN_OK);
  check_equal(mesh_mgmt_service_component_bind_v1(&scope, "MeshMgmtRpcServiceV1", &view),
              SALTS_COMPONENT_PLUGIN_OK);
}
static void withdraw(void) {
  memset(&view, 0, sizeof(view));
  if (salts_component_plugin_scope_generation_id(&scope) != 0)
    check_equal(salts_component_plugin_scope_release(&scope), SALTS_COMPONENT_PLUGIN_OK);
  if (runtime.current != NULL)
    check_equal(salts_component_plugin_runtime_close(&runtime, &previous), SALTS_COMPONENT_PLUGIN_OK);
  if (generation.state == SALTS_COMPONENT_PLUGIN_GENERATION_DRAINING)
    check_equal(salts_component_plugin_generation_drain(&runtime, &generation), SALTS_COMPONENT_PLUGIN_OK);
  if (generation.state == SALTS_COMPONENT_PLUGIN_GENERATION_BUILT)
    check_equal(salts_component_plugin_generation_discard(&generation), SALTS_COMPONENT_PLUGIN_OK);
}
static void unload(void) {
  cmeta_plugin_lifecycle_info info;
  bool quiet = false;
  check_equal(cmeta_plugin_registry_get_lifecycle(&registry, ref, &info), CMETA_PLUGIN_OK);
  if (info.state == CMETA_PLUGIN_LIFECYCLE_STARTED)
    check_equal(cmeta_plugin_registry_request_stop(&registry, ref), CMETA_PLUGIN_OK);
  check_equal(cmeta_plugin_registry_poll_quiescent(&registry, ref, &quiet), CMETA_PLUGIN_OK);
  check_true(quiet);
  check_equal(cmeta_plugin_registry_unload(&registry, ref), CMETA_PLUGIN_OK);
}

suite("immutable management service Component") {
  before_each() {
    const cmeta_plugin_registry_config options = {1};
    memset(&registry, 0, sizeof(registry));
    memset(&runtime, 0, sizeof(runtime));
    memset(&generation, 0, sizeof(generation));
    memset(&scope, 0, sizeof(scope));
    memset(&view, 0, sizeof(view));
    check_equal(mesh_mgmt_service_config_from_json_v1(json, sizeof(json) - 1, &config),
                MESH_MGMT_SERVICE_CONFIG_OK);
    check_equal(cmeta_plugin_registry_init(&registry, &options), CMETA_PLUGIN_OK);
    check_equal(cmeta_plugin_registry_load(&registry, MESH_PROVIDER_PLUGIN_PATH, &ref), CMETA_PLUGIN_OK);
    check_equal(cmeta_plugin_registry_start(&registry, ref), CMETA_PLUGIN_OK);
    check_equal(salts_component_plugin_runtime_init(&runtime), SALTS_COMPONENT_PLUGIN_OK);
  }
  after_each() {
    withdraw();
    check_equal(salts_component_plugin_runtime_destroy(&runtime), SALTS_COMPONENT_PLUGIN_OK);
    unload();
    check_equal(cmeta_plugin_registry_destroy(&registry), CMETA_PLUGIN_OK);
  }
  it("admits C11/C++17/DSO semantic descriptors and preserves readonly array extents") {
    salts_component_service service;
    const cmeta_data_desc *field = NULL;
    const void *value = NULL;
    char replacement[MESH_MGMT_SERVICE_DNS_NAME_MAX + 1u] = "changed.mesh";
    check_true(cmeta_data_desc_equal(cmeta_reflected_data(mesh_mgmt_service_config_v1_t),
                                    mesh_test_service_cpp_data()));
    check_true(cmeta_interface_desc_equal(mesh_mgmt_service_provider_v1_interface(),
                                         mesh_test_service_cpp_interface()));
    publish();
    check_equal(salts_component_plugin_scope_find_service_from(&scope, "MeshMgmtRpcServiceV1",
        mesh_test_service_cpp_interface(), &service), SALTS_COMPONENT_PLUGIN_OK);
    check_true(cmeta_data_desc_equal(service.object->data, mesh_test_service_cpp_data()));
    check_equal(cmeta_object_field_read(service.object, "dns_name", &field, &value), CMETA_OK);
    check_true(cmeta_data_desc_equal(field, &mesh_mgmt_service_dns_v1_cmeta_data));
    check_equal((const char *)value, "node-b.mesh");
    check_equal(cmeta_object_field_assign((cmeta_object_ref *)service.object, "dns_name", field,
                                         replacement), CMETA_TRAIT_MISSING);
    check_equal(cmeta_object_field_read(service.object, "virtual_address", &field, &value), CMETA_OK);
    check_true(cmeta_data_desc_equal(field, &mesh_mgmt_service_address_v1_cmeta_data));
    check_equal(value, config.virtual_address, sizeof(config.virtual_address));
  }
  it("owns a bounded snapshot independent of the startup configuration") {
    mesh_mgmt_service_publish_v1_t snapshot;
    publish();
    memset(&config, 0, sizeof(config));
    check_equal(mesh_mgmt_service_component_snapshot_v1(&view, &snapshot), MESH_MGMT_SERVICE_CONFIG_OK);
    check_equal(snapshot.dns_name, "node-b.mesh");
    check_equal(snapshot.port, (uint16_t)7878);
    check_equal(snapshot.virtual_address[0], (uint8_t)100);
    check_equal(snapshot.virtual_address[3], (uint8_t)2);
  }
  it("rejects incompatible config metadata and releases the candidate module pin") {
    check_equal(build(&cmeta_data_uint32, "mesh-rpc-service"), SALTS_COMPONENT_PLUGIN_COMPONENT_ERROR);
    check_equal(cmeta_plugin_registry_request_stop(&registry, ref), CMETA_PLUGIN_OK);
    /* after_each must be able to unload a failed candidate without a scope. */
  }
  it("rejects missing selected exports before publication") {
    check_equal(build(cmeta_reflected_data(mesh_mgmt_service_config_v1_t), "missing-service"),
                SALTS_COMPONENT_PLUGIN_PLUGIN_ERROR);
    check_null(runtime.current);
  }
  it("rejects invalid native config before acquiring ObjectRef ownership") {
    cmeta_object_ref object = CMETA_OBJECT_REF_INIT;
    config.version++;
    check_equal(mesh_mgmt_service_component_create_v1(NULL,
        cmeta_reflected_data(mesh_mgmt_service_config_v1_t), &config, NULL, 0, &object),
        CMETA_INVALID_ARGUMENT);
    check_false(cmeta_object_ref_valid(&object));
    config.version--;
    memset(config.dns_name, 'x', sizeof(config.dns_name));
    check_equal(build(cmeta_reflected_data(mesh_mgmt_service_config_v1_t), "mesh-rpc-service"),
                SALTS_COMPONENT_PLUGIN_COMPONENT_ERROR);
    check_null(runtime.current);
  }
  it("rejects copied and released scopes without dispatch or losing the live pin") {
    salts_component_plugin_scope copy;
    mesh_mgmt_service_component_view_v1_t bad, stale;
    mesh_mgmt_service_publish_v1_t snapshot;
    publish();
    copy = scope;
    check_equal(mesh_mgmt_service_component_bind_v1(&copy, "MeshMgmtRpcServiceV1", &bad),
                SALTS_COMPONENT_PLUGIN_INVALID_STATE);
    check_equal(mesh_mgmt_service_component_snapshot_v1(&bad, &snapshot), MESH_MGMT_SERVICE_CONFIG_INVALID_ARG);
    check_null(snapshot.dns_name);
    check_equal(salts_component_plugin_scope_release(&copy), SALTS_COMPONENT_PLUGIN_INVALID_STATE);
    check_equal(generation.active_scopes, (size_t)1);
    stale = view;
    check_equal(salts_component_plugin_scope_release(&scope), SALTS_COMPONENT_PLUGIN_OK);
    check_equal(mesh_mgmt_service_component_snapshot_v1(&stale, &snapshot), MESH_MGMT_SERVICE_CONFIG_INVALID_ARG);
    check_null(snapshot.dns_name);
    check_equal(mesh_mgmt_service_component_bind_v1(&scope, "MeshMgmtRpcServiceV1", &bad),
                SALTS_COMPONENT_PLUGIN_INVALID_ARGUMENT);
  }
  it("pins the DSO through scope drain and rejects stale capabilities after unload/reload") {
    mesh_mgmt_service_component_view_v1_t stale;
    mesh_mgmt_service_publish_v1_t snapshot;
    cmeta_plugin_ref old_ref;
    cmeta_plugin_lifecycle_info info;
    publish();
    stale = view;
    check_equal(salts_component_plugin_runtime_close(&runtime, &previous), SALTS_COMPONENT_PLUGIN_OK);
    check_equal(salts_component_plugin_generation_drain(&runtime, &generation), SALTS_COMPONENT_PLUGIN_BUSY);
    check_equal(cmeta_plugin_registry_request_stop(&registry, ref), CMETA_PLUGIN_OK);
    check_equal(cmeta_plugin_registry_unload(&registry, ref), CMETA_PLUGIN_BUSY);
    check_equal(mesh_mgmt_service_component_snapshot_v1(&view, &snapshot), MESH_MGMT_SERVICE_CONFIG_OK);
    withdraw();
    unload();
    check_equal(mesh_mgmt_service_component_snapshot_v1(&stale, &snapshot), MESH_MGMT_SERVICE_CONFIG_INVALID_ARG);
    check_null(snapshot.dns_name);
    old_ref = ref;
    check_equal(cmeta_plugin_registry_load(&registry, MESH_PROVIDER_PLUGIN_PATH, &ref), CMETA_PLUGIN_OK);
    check_equal(cmeta_plugin_registry_get_lifecycle(&registry, old_ref, &info), CMETA_PLUGIN_STALE);
    check_equal(cmeta_plugin_registry_start(&registry, ref), CMETA_PLUGIN_OK);
    /* A new DSO admission does not revive the expired service capability. */
    check_equal(mesh_mgmt_service_component_snapshot_v1(&stale, &snapshot), MESH_MGMT_SERVICE_CONFIG_INVALID_ARG);
  }
  it("rolls back an owned service snapshot when another selected provider fails create") {
    const salts_component_plugin_source sources[] = {
      {ref, "mesh-rpc-service", cmeta_reflected_data(mesh_mgmt_service_config_v1_t), &config},
      {ref, "failing-mesh-control-provider", NULL, NULL}
    };
    bool quiet = false;
    check_equal(salts_component_plugin_generation_build(&generation, 1, &registry, &storage,
        NULL, 0, sources, 2, NULL, 0), SALTS_COMPONENT_PLUGIN_COMPONENT_ERROR);
    check_equal(generation.failure.component_status, SALTS_COMPONENT_CREATE_FAILED);
    check_null(runtime.current);
    check_equal(cmeta_plugin_registry_request_stop(&registry, ref), CMETA_PLUGIN_OK);
    check_equal(cmeta_plugin_registry_poll_quiescent(&registry, ref, &quiet), CMETA_PLUGIN_OK);
    check_true(quiet);
    /* after_each unloads: both owned instances and the module lease retired. */
  }
}
