#include "fixture_service_gate.h"
#include <salts/thread.h>
#include <tinytest.h>
#include <string.h>

enum { RELOAD_ROUNDS = 16 };
static const uint64_t WAIT_NS = UINT64_C(5000000000);

typedef struct {
  salts_component_plugin_generation generation;
  salts_component_deployment deployments[1];
  salts_component_instance instances[1];
  salts_component_dependency dependencies[1];
  size_t order[1];
  salts_component_plugin_module modules[1];
} generation_fixture;
typedef struct {
  cmeta_mutex_t mutex;
  cmeta_cond_t changed;
  bool entered;
  bool returned;
  unsigned phase;
} call_gate;
typedef struct {
  call_gate *gate;
  salts_component_plugin_runtime *runtime;
  salts_component_plugin_scope scope;
  mesh_mgmt_service_component_view_v1_t view;
  salts_component_plugin_status acquire, bind, release;
  mesh_mgmt_service_config_result_t snapshot;
  cmeta_status field_read;
  uint64_t generation_id;
  uint16_t port;
  int fixture_version;
  char dns[MESH_MGMT_SERVICE_DNS_NAME_MAX + 1u];
} service_reader;

static cmeta_plugin_registry registry;
static cmeta_plugin_ref ref;
static bool loaded;
static salts_component_plugin_runtime runtime;
static generation_fixture generations[2];
static salts_component_plugin_scope new_scope;
static call_gate gate;
static service_reader reader;
static cmeta_thread_t thread;
static mesh_test_service_gate_config old_config;
static mesh_mgmt_service_config_v1_t new_config;

/* All gate state is mutex-protected. Each scope has one thread owner. Registry
 * lifecycle runs on the runner; the worker only uses synchronized runtime
 * admission and its own immutable service. Results are read after join. */
static void pause_call(void *context) {
  call_gate *g = context;
  cmeta_mutex_lock(&g->mutex);
  g->entered = true;
  cmeta_cond_broadcast(&g->changed);
  while (g->phase < 1) cmeta_cond_wait(&g->changed, &g->mutex);
  cmeta_mutex_unlock(&g->mutex);
}
static void advance(unsigned phase) {
  cmeta_mutex_lock(&gate.mutex);
  gate.phase = phase;
  cmeta_cond_broadcast(&gate.changed);
  cmeta_mutex_unlock(&gate.mutex);
}
static int wait_stage(bool *stage) {
  int status = 0;
  cmeta_mutex_lock(&gate.mutex);
  while (!*stage && status == 0)
    status = cmeta_cond_timedwait(&gate.changed, &gate.mutex, WAIT_NS);
  cmeta_mutex_unlock(&gate.mutex);
  return status;
}
static void read_service(void *arg) {
  service_reader *r = arg;
  mesh_mgmt_service_publish_v1_t snapshot = {0};
  salts_component_service service;
  const cmeta_data_desc *data = NULL;
  const void *value = NULL;
  r->acquire = salts_component_plugin_scope_acquire(r->runtime, &r->scope);
  if (r->acquire == SALTS_COMPONENT_PLUGIN_OK) {
    r->generation_id = salts_component_plugin_scope_generation_id(&r->scope);
    r->bind = mesh_mgmt_service_component_bind_v1(&r->scope, "MeshMgmtGatedServiceFixture", &r->view);
    if (r->bind == SALTS_COMPONENT_PLUGIN_OK)
      r->snapshot = mesh_mgmt_service_component_snapshot_v1(&r->view, &snapshot);
  }
  cmeta_mutex_lock(&r->gate->mutex);
  r->gate->returned = true;
  cmeta_cond_broadcast(&r->gate->changed);
  while (r->gate->phase < 2) cmeta_cond_wait(&r->gate->changed, &r->gate->mutex);
  cmeta_mutex_unlock(&r->gate->mutex);
  /* This DNS borrow and DSO-owned DataDesc remain valid after snapshot return,
   * until the worker releases its scope. No runner touches the live scope. */
  if (r->snapshot == MESH_MGMT_SERVICE_CONFIG_OK && snapshot.dns_name != NULL) {
    const char *end = memchr(snapshot.dns_name, '\0', sizeof(r->dns));
    if (end != NULL) memcpy(r->dns, snapshot.dns_name, (size_t)(end - snapshot.dns_name) + 1);
    r->port = snapshot.port;
    if (salts_component_plugin_scope_find_service_from(&r->scope, "MeshMgmtGatedServiceFixture",
        mesh_mgmt_service_provider_v1_interface(), &service) == SALTS_COMPONENT_PLUGIN_OK) {
      r->field_read = cmeta_object_field_read(service.object, "fixture_version", &data, &value);
      if (r->field_read == CMETA_OK && cmeta_data_desc_equal(data, &cmeta_data_int))
        r->fixture_version = *(const int *)value;
    }
  }
  if (r->acquire == SALTS_COMPONENT_PLUGIN_OK)
    r->release = salts_component_plugin_scope_release(&r->scope);
}
static salts_component_plugin_status build(generation_fixture *fixture, uint64_t id,
    const char *export_id, const cmeta_data_desc *data, const void *config) {
  const salts_component_plugin_generation_storage storage = {
    fixture->deployments, 1, fixture->instances, 1, fixture->dependencies, 1,
    fixture->order, 1, fixture->modules, 1
  };
  const salts_component_plugin_source source = {ref, export_id, data, config};
  return salts_component_plugin_generation_build(&fixture->generation, id, &registry, &storage,
      NULL, 0, &source, 1, NULL, 0);
}
static void start_reader(void) {
  salts_component_plugin_generation *previous = NULL;
  check_equal(build(&generations[0], 1, "gated-mesh-rpc-service",
      cmeta_reflected_data(mesh_test_service_gate_config), &old_config), SALTS_COMPONENT_PLUGIN_OK);
  check_equal(salts_component_plugin_runtime_publish(&runtime, &generations[0].generation, &previous),
              SALTS_COMPONENT_PLUGIN_OK);
  reader.gate = &gate;
  reader.runtime = &runtime;
  reader.snapshot = MESH_MGMT_SERVICE_CONFIG_INVALID_ARG;
  reader.field_read = CMETA_INVALID_ARGUMENT;
  check_equal(cmeta_thread_create(&thread, read_service, &reader), 0);
  check_equal(wait_stage(&gate.entered), 0);
}
static void finish_reader(void) {
  mesh_mgmt_service_publish_v1_t expired;
  advance(2);
  check_equal(cmeta_thread_join(&thread), 0);
  check_equal(reader.acquire, SALTS_COMPONENT_PLUGIN_OK);
  check_equal(reader.bind, SALTS_COMPONENT_PLUGIN_OK);
  check_equal(reader.snapshot, MESH_MGMT_SERVICE_CONFIG_OK);
  check_equal(reader.release, SALTS_COMPONENT_PLUGIN_OK);
  check_equal(reader.generation_id, UINT64_C(1));
  check_equal(reader.port, (uint16_t)7878);
  check_equal(reader.dns, "node-b.mesh");
  check_equal(reader.field_read, CMETA_OK);
  check_equal(reader.fixture_version, 1);
  check_equal(mesh_mgmt_service_component_snapshot_v1(&reader.view, &expired),
              MESH_MGMT_SERVICE_CONFIG_INVALID_ARG);
  check_null(expired.dns_name);
  memset(&reader.view, 0, sizeof(reader.view));
}
static void stop_and_unload(void) {
  bool quiet = false;
  cmeta_plugin_lifecycle_info info;
  check_equal(cmeta_plugin_registry_get_lifecycle(&registry, ref, &info), CMETA_PLUGIN_OK);
  if (info.state == CMETA_PLUGIN_LIFECYCLE_STARTED)
    check_equal(cmeta_plugin_registry_request_stop(&registry, ref), CMETA_PLUGIN_OK);
  check_equal(cmeta_plugin_registry_poll_quiescent(&registry, ref, &quiet), CMETA_PLUGIN_OK);
  check_true(quiet);
  check_equal(cmeta_plugin_registry_unload(&registry, ref), CMETA_PLUGIN_OK);
  loaded = false;
}

suite("mesh service DSO calls across generation retirement") {
  before_each() {
    const cmeta_plugin_registry_config options = {1};
    static const char json[] =
      "{\"schema_version\":1,\"address_family\":4,\"octet0\":100,"
      "\"octet1\":64,\"octet2\":0,\"octet3\":2,\"port\":7878,"
      "\"dns_name\":\"node-b.mesh\"}";
    memset(&registry, 0, sizeof(registry));
    memset(&runtime, 0, sizeof(runtime));
    memset(generations, 0, sizeof(generations));
    memset(&new_scope, 0, sizeof(new_scope));
    memset(&reader, 0, sizeof(reader));
    memset(&gate, 0, sizeof(gate));
    thread = NULL;
    loaded = false;
    cmeta_mutex_init(&gate.mutex);
    cmeta_cond_init(&gate.changed);
    check_not_null(gate.mutex);
    check_not_null(gate.changed);
    check_equal(mesh_mgmt_service_config_from_json_v1(json, sizeof(json) - 1, &old_config.service),
                MESH_MGMT_SERVICE_CONFIG_OK);
    old_config.pause = pause_call;
    old_config.context = &gate;
    new_config = old_config.service;
    memcpy(new_config.dns_name, "node-c.mesh", sizeof("node-c.mesh"));
    new_config.port = 7979;
    check_equal(cmeta_plugin_registry_init(&registry, &options), CMETA_PLUGIN_OK);
    check_equal(cmeta_plugin_registry_load(&registry, MESH_PROVIDER_PLUGIN_PATH, &ref), CMETA_PLUGIN_OK);
    loaded = true;
    check_equal(cmeta_plugin_registry_start(&registry, ref), CMETA_PLUGIN_OK);
    check_equal(salts_component_plugin_runtime_init(&runtime), SALTS_COMPONENT_PLUGIN_OK);
  }
  after_each() {
    salts_component_plugin_generation *previous = NULL;
    /* Fatal runner assertions must wake/join before destroying any borrowed
     * gate, scope, generation, ObjectRef or DSO storage. */
    if (gate.mutex != NULL && gate.changed != NULL) advance(2);
    if (thread != NULL) check_equal(cmeta_thread_join(&thread), 0);
    if (salts_component_plugin_scope_generation_id(&new_scope) != 0)
      check_equal(salts_component_plugin_scope_release(&new_scope), SALTS_COMPONENT_PLUGIN_OK);
    if (runtime.initialized) {
      if (runtime.current != NULL)
        check_equal(salts_component_plugin_runtime_close(&runtime, &previous), SALTS_COMPONENT_PLUGIN_OK);
      for (size_t i = 0; i < 2; ++i) {
        salts_component_plugin_generation *g = &generations[i].generation;
        if (g->state == SALTS_COMPONENT_PLUGIN_GENERATION_BUILT)
          check_equal(salts_component_plugin_generation_discard(g), SALTS_COMPONENT_PLUGIN_OK);
        if (g->runtime_owner == &runtime)
          check_equal(salts_component_plugin_generation_drain(&runtime, g), SALTS_COMPONENT_PLUGIN_OK);
      }
      check_equal(salts_component_plugin_runtime_destroy(&runtime), SALTS_COMPONENT_PLUGIN_OK);
    }
    if (loaded) stop_and_unload();
    if (registry.impl != NULL) check_equal(cmeta_plugin_registry_destroy(&registry), CMETA_PLUGIN_OK);
    cmeta_cond_destroy(&gate.changed);
    cmeta_mutex_destroy(&gate.mutex);
  }
  it("rejects unload during stop while a real DSO call and its returned DNS borrow are live across reloads") {
    for (unsigned round = 0; round < RELOAD_ROUNDS; ++round) {
      salts_component_plugin_generation *previous = NULL;
      salts_component_plugin_scope rejected = SALTS_COMPONENT_PLUGIN_SCOPE_INIT;
      cmeta_plugin_lease denied = {0};
      const cmeta_plugin_manifest *manifest = NULL;
      cmeta_plugin_ref retired;
      cmeta_plugin_lifecycle_info info;
      start_reader();
      check_equal(salts_component_plugin_runtime_close(&runtime, &previous), SALTS_COMPONENT_PLUGIN_OK);
      check_true(previous == &generations[0].generation);
      check_equal(salts_component_plugin_scope_acquire(&runtime, &rejected), SALTS_COMPONENT_PLUGIN_INVALID_STATE);
      check_equal(cmeta_plugin_registry_request_stop(&registry, ref), CMETA_PLUGIN_OK);
      check_equal(cmeta_plugin_registry_acquire(&registry, ref, &denied, &manifest), CMETA_PLUGIN_INVALID_STATE);
      check_equal(cmeta_plugin_registry_unload(&registry, ref), CMETA_PLUGIN_BUSY);
      check_equal(salts_component_plugin_generation_drain(&runtime, previous), SALTS_COMPONENT_PLUGIN_BUSY);
      advance(1);
      check_equal(wait_stage(&gate.returned), 0);
      check_equal(salts_component_plugin_generation_drain(&runtime, previous), SALTS_COMPONENT_PLUGIN_BUSY);
      check_equal(cmeta_plugin_registry_unload(&registry, ref), CMETA_PLUGIN_BUSY);
      finish_reader();
      check_equal(salts_component_plugin_generation_drain(&runtime, previous), SALTS_COMPONENT_PLUGIN_OK);
      stop_and_unload();
      retired = ref;
      if (round + 1 < RELOAD_ROUNDS) {
        check_equal(salts_component_plugin_runtime_destroy(&runtime), SALTS_COMPONENT_PLUGIN_OK);
        memset(generations, 0, sizeof(generations));
        memset(&reader, 0, sizeof(reader));
        cmeta_mutex_lock(&gate.mutex);
        gate.entered = gate.returned = false;
        gate.phase = 0;
        cmeta_mutex_unlock(&gate.mutex);
        check_equal(cmeta_plugin_registry_load(&registry, MESH_PROVIDER_PLUGIN_PATH, &ref), CMETA_PLUGIN_OK);
        loaded = true;
        check_equal(cmeta_plugin_registry_get_lifecycle(&registry, retired, &info), CMETA_PLUGIN_STALE);
        check_equal(cmeta_plugin_registry_start(&registry, ref), CMETA_PLUGIN_OK);
        check_equal(salts_component_plugin_runtime_init(&runtime), SALTS_COMPONENT_PLUGIN_OK);
      }
    }
  }
  it("keeps old in-flight service data isolated while a new generation admits readers") {
    salts_component_plugin_generation *previous = NULL;
    mesh_mgmt_service_component_view_v1_t current = MESH_MGMT_SERVICE_COMPONENT_VIEW_INIT_V1;
    mesh_mgmt_service_publish_v1_t snapshot;
    start_reader();
    check_equal(build(&generations[1], 2, "mesh-rpc-service",
        cmeta_reflected_data(mesh_mgmt_service_config_v1_t), &new_config), SALTS_COMPONENT_PLUGIN_OK);
    check_equal(salts_component_plugin_runtime_publish(&runtime, &generations[1].generation, &previous),
                SALTS_COMPONENT_PLUGIN_OK);
    check_true(previous == &generations[0].generation);
    check_equal(salts_component_plugin_scope_acquire(&runtime, &new_scope), SALTS_COMPONENT_PLUGIN_OK);
    check_equal(salts_component_plugin_scope_generation_id(&new_scope), UINT64_C(2));
    check_equal(mesh_mgmt_service_component_bind_v1(&new_scope, "MeshMgmtRpcServiceV1", &current),
                SALTS_COMPONENT_PLUGIN_OK);
    check_equal(mesh_mgmt_service_component_snapshot_v1(&current, &snapshot), MESH_MGMT_SERVICE_CONFIG_OK);
    check_equal(snapshot.dns_name, "node-c.mesh");
    check_equal(snapshot.port, (uint16_t)7979);
    check_equal(salts_component_plugin_generation_drain(&runtime, previous), SALTS_COMPONENT_PLUGIN_BUSY);
    finish_reader();
    check_equal(salts_component_plugin_generation_drain(&runtime, previous), SALTS_COMPONENT_PLUGIN_OK);
    check_equal(mesh_mgmt_service_component_snapshot_v1(&current, &snapshot), MESH_MGMT_SERVICE_CONFIG_OK);
    check_equal(snapshot.dns_name, "node-c.mesh");
    check_equal(cmeta_plugin_registry_request_stop(&registry, ref), CMETA_PLUGIN_OK);
    check_equal(cmeta_plugin_registry_unload(&registry, ref), CMETA_PLUGIN_BUSY);
    memset(&current, 0, sizeof(current));
    check_equal(salts_component_plugin_scope_release(&new_scope), SALTS_COMPONENT_PLUGIN_OK);
  }
}
