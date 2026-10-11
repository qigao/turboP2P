#include "meshd_rpc_service_component.h"
#include <tinytest.h>
#include <salts/clock.h>
#include <string.h>

static meshd_rpc_service_component_t owner;
static mesh_mgmt_service_config_v1_t config;
static salts_component_plugin_scope observer;
static mesh_mgmt_service_component_view_v1_t observed;
static cmeta_thread_t foreign_thread;
static struct {
  meshd_rpc_service_component_t *owner;
  mesh_mgmt_agent_runtime_v1_t agent;
  salts_component_plugin_status destroy;
  salts_component_plugin_status init_native;
  mesh_mgmt_agent_runtime_result_t publish;
  mesh_mgmt_agent_runtime_result_t refresh;
  uint64_t epoch;
} foreign;
static void foreign_owner_call(void *context) {
  (void)context;
  foreign.destroy = meshd_rpc_service_component_destroy(foreign.owner);
  foreign.init_native = meshd_rpc_service_component_init_native(foreign.owner,
      vstr_from_buf("100.64.0.2", sizeof("100.64.0.2")),
      vstr_from_buf("node-b.mesh", sizeof("node-b.mesh")), 7878);
  foreign.publish = meshd_rpc_service_component_publish(foreign.owner, &foreign.agent, &foreign.epoch);
  foreign.refresh = meshd_rpc_service_component_refresh(foreign.owner, &foreign.agent, cmeta_monotonic_ms, &foreign.epoch);
}

suite("meshd RPC service Component Owner") {
  before_each() {
    static const char json[] =
      "{\"schema_version\":1,\"address_family\":4,\"octet0\":100,"
      "\"octet1\":64,\"octet2\":0,\"octet3\":2,\"port\":7878,"
      "\"dns_name\":\"node-b.mesh\"}";
    memset(&owner, 0, sizeof(owner));
    memset(&observer, 0, sizeof(observer));
    memset(&observed, 0, sizeof(observed));
    memset(&foreign, 0, sizeof(foreign));
    foreign_thread = NULL;
    check_equal(mesh_mgmt_service_config_from_json_v1(json, sizeof(json) - 1, &config),
                MESH_MGMT_SERVICE_CONFIG_OK);
  }
  after_each() {
    if (foreign_thread != NULL) check_equal(cmeta_thread_join(&foreign_thread), 0);
    memset(&observed, 0, sizeof(observed));
    if (salts_component_plugin_scope_generation_id(&observer) != 0)
      check_equal(salts_component_plugin_scope_release(&observer), SALTS_COMPONENT_PLUGIN_OK);
    check_equal(meshd_rpc_service_component_destroy(&owner), SALTS_COMPONENT_PLUGIN_OK);
    check_false(owner.runtime.initialized);
    check_equal(owner.generation.state, SALTS_COMPONENT_PLUGIN_GENERATION_ZERO);
  }
  it("owns one immutable startup service through repeated snapshot use") {
    mesh_mgmt_service_publish_v1_t snapshot;
    check_equal(meshd_rpc_service_component_init(&owner, &config), SALTS_COMPONENT_PLUGIN_OK);
    memset(&config, 0, sizeof(config));
    for (unsigned i = 0; i < 3; ++i) {
      check_equal(mesh_mgmt_service_component_snapshot_v1(&owner.view, &snapshot), MESH_MGMT_SERVICE_CONFIG_OK);
      check_equal(snapshot.dns_name, "node-b.mesh");
      check_equal(snapshot.port, (uint16_t)7878);
    }
    check_equal(owner.generation.active_scopes, (size_t)1);
    check_equal(owner.generation.deployment_count, (size_t)1);
    check_equal(owner.generation.module_count, (size_t)0);
  }
  it("admits bounded native IPv4 and maximum canonical DNS then owns the complete snapshot") {
    char ip[16] = "223.255.255.255";
    char dns[MESH_MGMT_SERVICE_DNS_NAME_MAX + 1];
    char expected_dns[sizeof(dns)];
    const uint8_t expected_address[16] = {223, 255, 255, 255};
    mesh_mgmt_service_publish_v1_t snapshot;
    memset(dns, 'a', 63);
    dns[63] = '.';
    memset(dns + 64, 'b', 63);
    dns[127] = '\0';
    memcpy(expected_dns, dns, sizeof(dns));
    check_equal(meshd_rpc_service_component_init_native(&owner,
        vstr_from_buf(ip, sizeof(ip)), vstr_from_buf(dns, sizeof(dns)), UINT16_MAX),
        SALTS_COMPONENT_PLUGIN_OK);
    memset(ip, 'x', sizeof(ip));
    memset(dns, 'x', sizeof(dns));
    check_equal(mesh_mgmt_service_component_snapshot_v1(&owner.view, &snapshot), MESH_MGMT_SERVICE_CONFIG_OK);
    check_equal(snapshot.virtual_address, expected_address, sizeof(expected_address));
    check_equal(snapshot.dns_name, expected_dns);
    check_equal(snapshot.port, UINT16_MAX);
    check_equal(owner.generation.active_scopes, (size_t)1);
  }
  it("keeps native IP-only discovery and exact host comparison compatible") {
    char ip[16] = "100.64.0.2";
    char host[128] = "100.64.0.2";
    mesh_mgmt_service_publish_v1_t snapshot;
    /* A C storage field may have stale bytes after its terminator. */
    memset(ip + sizeof("100.64.0.2"), 'x', sizeof(ip) - sizeof("100.64.0.2"));
    memset(host + sizeof("100.64.0.2"), 'x', sizeof(host) - sizeof("100.64.0.2"));
    check_equal(meshd_rpc_service_component_init_native(&owner,
        vstr_from_buf(ip, sizeof(ip)), vstr_from_buf(host, sizeof(host)), 7878), SALTS_COMPONENT_PLUGIN_OK);
    check_equal(mesh_mgmt_service_component_snapshot_v1(&owner.view, &snapshot), MESH_MGMT_SERVICE_CONFIG_OK);
    check_equal(snapshot.dns_name, "");
    check_equal(meshd_rpc_service_component_destroy(&owner), SALTS_COMPONENT_PLUGIN_OK);
    check_equal(meshd_rpc_service_component_init_native(&owner,
        vstr_from_buf(ip, sizeof(ip)), vstr_from_buf("100.64.0.2.mesh", sizeof("100.64.0.2.mesh")), 7878),
        SALTS_COMPONENT_PLUGIN_OK);
    check_equal(mesh_mgmt_service_component_snapshot_v1(&owner.view, &snapshot), MESH_MGMT_SERVICE_CONFIG_OK);
    check_equal(snapshot.dns_name, "100.64.0.2.mesh");
    check_equal(meshd_rpc_service_component_destroy(&owner), SALTS_COMPONENT_PLUGIN_OK);
    check_equal(meshd_rpc_service_component_init_native(&owner,
        vstr_from_buf(ip, sizeof(ip)), vstr_from_buf("", sizeof("")), 7878), SALTS_COMPONENT_PLUGIN_OK);
    check_equal(mesh_mgmt_service_component_snapshot_v1(&owner.view, &snapshot), MESH_MGMT_SERVICE_CONFIG_OK);
    check_equal(snapshot.dns_name, "");
  }
  it("rejects unterminated or invalid native storage before ownership and permits corrected admission") {
    char ip[16], host[128];
    const vstr invalid = {NULL, 1};
    mesh_mgmt_service_publish_v1_t snapshot;
    memset(ip, '1', sizeof(ip));
    memset(host, 'a', sizeof(host));
    check_equal(meshd_rpc_service_component_init_native(&owner,
        vstr_from_buf(ip, sizeof(ip)), vstr_from_buf("node-b.mesh", sizeof("node-b.mesh")), 7878),
        SALTS_COMPONENT_PLUGIN_INVALID_ARGUMENT);
    check_equal(meshd_rpc_service_component_init_native(&owner,
        vstr_from_buf("100.64.0.2", sizeof("100.64.0.2")), vstr_from_buf(host, sizeof(host)), 7878),
        SALTS_COMPONENT_PLUGIN_INVALID_ARGUMENT);
    check_equal(meshd_rpc_service_component_init_native(&owner, invalid, invalid, 7878),
        SALTS_COMPONENT_PLUGIN_INVALID_ARGUMENT);
    check_equal(meshd_rpc_service_component_init_native(&owner,
        vstr_from_buf(NULL, 0), vstr_from_buf("", sizeof("")), 7878), SALTS_COMPONENT_PLUGIN_INVALID_ARGUMENT);
    check_equal(meshd_rpc_service_component_init_native(&owner,
        vstr_from_buf("100.64.0.2", sizeof("100.64.0.2")), vstr_from_buf("", sizeof("")), 0),
        SALTS_COMPONENT_PLUGIN_INVALID_ARGUMENT);
    check_equal(meshd_rpc_service_component_init_native(NULL,
        vstr_from_buf(NULL, 0), vstr_from_buf(NULL, 0), 0), SALTS_COMPONENT_PLUGIN_INVALID_ARGUMENT);
    check_null(owner.affinity.owner);
    check_false(owner.runtime.initialized);
    check_false(owner.scope.live);
    check_equal(meshd_rpc_service_component_init_native(&owner,
        vstr_from_buf("100.64.0.2", sizeof("100.64.0.2")),
        vstr_from_buf("node-b.mesh", sizeof("node-b.mesh")), 7878), SALTS_COMPONENT_PLUGIN_OK);
    check_equal(meshd_rpc_service_component_init_native(&owner, invalid, invalid, 0),
        SALTS_COMPONENT_PLUGIN_INVALID_STATE);
    check_equal(mesh_mgmt_service_component_snapshot_v1(&owner.view, &snapshot), MESH_MGMT_SERVICE_CONFIG_OK);
    check_equal(snapshot.dns_name, "node-b.mesh");
  }
  it("uses native IPv4 parsing and canonical Component policy without partial admission") {
    static const char *invalid_ips[] = {"", "1.2.3", "1.2.3.256", "1.2.3.4:7878", "::1", "100.64.0.2 "};
    static const char *invalid_hosts[] = {"Node-b.mesh", "node-b.mesh.", "node..mesh", "-node.mesh"};
    for (size_t i = 0; i < sizeof(invalid_ips) / sizeof(invalid_ips[0]); ++i) {
      check_equal(meshd_rpc_service_component_init_native(&owner,
          vstr_from_buf(invalid_ips[i], strlen(invalid_ips[i]) + 1),
          vstr_from_buf("node-b.mesh", sizeof("node-b.mesh")), 7878), SALTS_COMPONENT_PLUGIN_INVALID_ARGUMENT);
      check_false(owner.runtime.initialized);
      check_null(owner.affinity.owner);
    }
    for (size_t i = 0; i < sizeof(invalid_hosts) / sizeof(invalid_hosts[0]); ++i) {
      check_equal(meshd_rpc_service_component_init_native(&owner,
          vstr_from_buf("100.64.0.2", sizeof("100.64.0.2")),
          vstr_from_buf(invalid_hosts[i], strlen(invalid_hosts[i]) + 1), 7878), SALTS_COMPONENT_PLUGIN_COMPONENT_ERROR);
      check_false(owner.runtime.initialized);
      check_false(owner.scope.live);
      check_null(owner.affinity.owner);
    }
    check_equal(meshd_rpc_service_component_init_native(&owner,
        vstr_from_buf("224.0.0.1", sizeof("224.0.0.1")),
        vstr_from_buf("node-b.mesh", sizeof("node-b.mesh")), 7878), SALTS_COMPONENT_PLUGIN_COMPONENT_ERROR);
    check_false(owner.runtime.initialized);
    check_equal(meshd_rpc_service_component_init(&owner, &config), SALTS_COMPONENT_PLUGIN_OK);
  }
  it("rolls back invalid startup config and permits corrected initialization") {
    config.version++;
    check_equal(meshd_rpc_service_component_init(&owner, &config), SALTS_COMPONENT_PLUGIN_COMPONENT_ERROR);
    check_false(owner.runtime.initialized);
    check_false(owner.scope.live);
    check_null(owner.affinity.owner);
    check_equal(owner.generation.state, SALTS_COMPONENT_PLUGIN_GENERATION_ZERO);
    config.version--;
    check_equal(meshd_rpc_service_component_init(&owner, &config), SALTS_COMPONENT_PLUGIN_OK);
    check_equal(meshd_rpc_service_component_init(&owner, &config), SALTS_COMPONENT_PLUGIN_INVALID_STATE);
    check_equal(owner.generation.active_scopes, (size_t)1);
  }
  it("rejects copied live Owners without withdrawing the original generation") {
    meshd_rpc_service_component_t copied;
    mesh_mgmt_agent_runtime_v1_t agent = {0};
    mesh_mgmt_service_publish_v1_t snapshot;
    uint64_t epoch = 99;
    check_equal(meshd_rpc_service_component_init(&owner, &config), SALTS_COMPONENT_PLUGIN_OK);
    copied = owner;
    check_equal(meshd_rpc_service_component_init_native(&copied,
        vstr_from_buf("100.64.0.2", sizeof("100.64.0.2")),
        vstr_from_buf("node-b.mesh", sizeof("node-b.mesh")), 7878), SALTS_COMPONENT_PLUGIN_INVALID_STATE);
    check_equal(meshd_rpc_service_component_destroy(&copied), SALTS_COMPONENT_PLUGIN_INVALID_STATE);
    check_equal(meshd_rpc_service_component_publish(&copied, &agent, &epoch), MESH_MGMT_AGENT_RUNTIME_INVALID_STATE);
    check_equal(epoch, UINT64_C(0));
    check_equal(meshd_rpc_service_component_refresh(&copied, &agent, cmeta_monotonic_ms, &epoch), MESH_MGMT_AGENT_RUNTIME_INVALID_STATE);
    check_equal(epoch, UINT64_C(0));
    check_false(owner.refresh_attempted);
    check_true(owner.runtime.current == &owner.generation);
    check_equal(owner.generation.active_scopes, (size_t)1);
    check_equal(mesh_mgmt_service_component_snapshot_v1(&owner.view, &snapshot), MESH_MGMT_SERVICE_CONFIG_OK);
  }
  it("rejects lifecycle and publication from a foreign thread while preserving the Owner") {
    check_equal(meshd_rpc_service_component_init(&owner, &config), SALTS_COMPONENT_PLUGIN_OK);
    foreign.owner = &owner;
    foreign.epoch = 99;
    check_equal(cmeta_thread_create(&foreign_thread, foreign_owner_call, NULL), 0);
    check_equal(cmeta_thread_join(&foreign_thread), 0);
    check_equal(foreign.destroy, SALTS_COMPONENT_PLUGIN_INVALID_STATE);
    check_equal(foreign.init_native, SALTS_COMPONENT_PLUGIN_INVALID_STATE);
    check_equal(foreign.publish, MESH_MGMT_AGENT_RUNTIME_INVALID_STATE);
    check_equal(foreign.refresh, MESH_MGMT_AGENT_RUNTIME_INVALID_STATE);
    check_equal(foreign.epoch, UINT64_C(0));
    check_true(owner.runtime.current == &owner.generation);
    check_equal(owner.generation.active_scopes, (size_t)1);
  }
  it("retains withdrawn storage on BUSY and completes checked destruction after borrowed views retire") {
    mesh_mgmt_service_publish_v1_t snapshot;
    mesh_mgmt_agent_runtime_v1_t agent = {0};
    uint64_t epoch = 99;
    check_equal(meshd_rpc_service_component_init(&owner, &config), SALTS_COMPONENT_PLUGIN_OK);
    check_equal(salts_component_plugin_scope_acquire(&owner.runtime, &observer), SALTS_COMPONENT_PLUGIN_OK);
    check_equal(mesh_mgmt_service_component_bind_v1(&observer, "MeshMgmtRpcServiceV1", &observed),
                SALTS_COMPONENT_PLUGIN_OK);
    check_equal(meshd_rpc_service_component_destroy(&owner), SALTS_COMPONENT_PLUGIN_BUSY);
    check_true(owner.runtime.initialized);
    check_null(owner.runtime.current);
    check_equal(owner.generation.state, SALTS_COMPONENT_PLUGIN_GENERATION_DRAINING);
    check_equal(owner.generation.active_scopes, (size_t)1);
    check_equal(mesh_mgmt_service_component_snapshot_v1(&observed, &snapshot), MESH_MGMT_SERVICE_CONFIG_OK);
    check_equal(snapshot.dns_name, "node-b.mesh");
    check_equal(meshd_rpc_service_component_publish(&owner, &agent, &epoch), MESH_MGMT_AGENT_RUNTIME_INVALID_STATE);
    check_equal(epoch, UINT64_C(0));
    check_equal(meshd_rpc_service_component_refresh(&owner, &agent, cmeta_monotonic_ms, &epoch), MESH_MGMT_AGENT_RUNTIME_INVALID_STATE);
    check_equal(epoch, UINT64_C(0));
    memset(&observed, 0, sizeof(observed));
    check_equal(salts_component_plugin_scope_release(&observer), SALTS_COMPONENT_PLUGIN_OK);
    check_equal(meshd_rpc_service_component_destroy(&owner), SALTS_COMPONENT_PLUGIN_OK);
    check_equal(meshd_rpc_service_component_destroy(&owner), SALTS_COMPONENT_PLUGIN_OK);
    check_equal(meshd_rpc_service_component_init(&owner, &config), SALTS_COMPONENT_PLUGIN_OK);
  }
  it("rejects uninitialized/stopped agent publication and clears the epoch output") {
    mesh_mgmt_agent_runtime_v1_t agent = {0};
    uint64_t epoch = 99;
    check_equal(meshd_rpc_service_component_publish(&owner, &agent, &epoch), MESH_MGMT_AGENT_RUNTIME_INVALID_STATE);
    check_equal(epoch, UINT64_C(0));
    check_equal(meshd_rpc_service_component_refresh(&owner, &agent, cmeta_monotonic_ms, &epoch), MESH_MGMT_AGENT_RUNTIME_INVALID_STATE);
    check_equal(epoch, UINT64_C(0));
    check_equal(meshd_rpc_service_component_init(&owner, &config), SALTS_COMPONENT_PLUGIN_OK);
    check_equal(meshd_rpc_service_component_refresh(&owner, &agent, cmeta_monotonic_ms, &epoch), MESH_MGMT_AGENT_RUNTIME_INVALID_STATE);
    check_equal(epoch, UINT64_C(0));
    check_false(owner.refresh_attempted);
    check_equal(meshd_rpc_service_component_refresh(NULL, &agent, cmeta_monotonic_ms, &epoch), MESH_MGMT_AGENT_RUNTIME_INVALID_ARG);
    check_equal(meshd_rpc_service_component_refresh(&owner, NULL, cmeta_monotonic_ms, &epoch), MESH_MGMT_AGENT_RUNTIME_INVALID_ARG);
    check_equal(meshd_rpc_service_component_refresh(&owner, &agent, cmeta_monotonic_ms, NULL), MESH_MGMT_AGENT_RUNTIME_INVALID_ARG);
    check_equal(meshd_rpc_service_component_refresh(&owner, &agent, NULL, &epoch), MESH_MGMT_AGENT_RUNTIME_INVALID_ARG);
    check_equal(meshd_rpc_service_component_publish(&owner, &agent, &epoch), MESH_MGMT_AGENT_RUNTIME_INVALID_STATE);
    check_equal(epoch, UINT64_C(0));
    check_equal(meshd_rpc_service_component_publish(NULL, &agent, &epoch), MESH_MGMT_AGENT_RUNTIME_INVALID_ARG);
    check_equal(epoch, UINT64_C(0));
    check_equal(meshd_rpc_service_component_init(NULL, &config), SALTS_COMPONENT_PLUGIN_INVALID_ARGUMENT);
    check_equal(meshd_rpc_service_component_init(&owner, NULL), SALTS_COMPONENT_PLUGIN_INVALID_ARGUMENT);
    check_equal(meshd_rpc_service_component_destroy(NULL), SALTS_COMPONENT_PLUGIN_INVALID_ARGUMENT);
  }
}
