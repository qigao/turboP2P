#include "meshd_rpc_service_component.h"
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

/* Reuse SDK ownership relationships to reject a copied live Owner before
 * touching its shared runtime lock or its original scope's admission count. */
static bool original_storage(const meshd_rpc_service_component_t *owner) {
  return (!owner->scope.live || owner->scope.owner_address == &owner->scope) &&
      (owner->generation.runtime_owner == NULL ||
       owner->generation.runtime_owner == &owner->runtime) &&
      (owner->runtime.current == NULL || owner->runtime.current == &owner->generation);
}
static bool publishable(const meshd_rpc_service_component_t *owner) {
  return cmeta_thread_affine_check(&owner->affinity, owner) == SALTS_OK &&
      original_storage(owner) && owner->runtime.initialized &&
      owner->runtime.current == &owner->generation;
}
static bool initializable(const meshd_rpc_service_component_t *owner) {
  return owner->affinity.owner == NULL && !owner->runtime.initialized && !owner->scope.live &&
      owner->generation.state == SALTS_COMPONENT_PLUGIN_GENERATION_ZERO;
}
salts_component_plugin_status meshd_rpc_service_component_destroy(
    meshd_rpc_service_component_t *owner) {
  salts_component_plugin_generation *previous = NULL;
  salts_component_plugin_status status;
  int affinity;
  if (owner == NULL) return SALTS_COMPONENT_PLUGIN_INVALID_ARGUMENT;
  if (owner->affinity.owner != NULL) {
    affinity = cmeta_thread_affine_check(&owner->affinity, owner);
    if (affinity == SALTS_EBUSY) return SALTS_COMPONENT_PLUGIN_BUSY;
    if (affinity != SALTS_OK) return SALTS_COMPONENT_PLUGIN_INVALID_STATE;
  }
  if (!original_storage(owner)) return SALTS_COMPONENT_PLUGIN_INVALID_STATE;
  if (owner->runtime.current != NULL) {
    status = salts_component_plugin_runtime_close(&owner->runtime, &previous);
    if (status != SALTS_COMPONENT_PLUGIN_OK) return status;
  }
  if (owner->scope.live) {
    status = salts_component_plugin_scope_release(&owner->scope);
    if (status != SALTS_COMPONENT_PLUGIN_OK) return status;
  }
  memset(&owner->view, 0, sizeof(owner->view));
  if (owner->generation.state == SALTS_COMPONENT_PLUGIN_GENERATION_BUILT) {
    status = salts_component_plugin_generation_discard(&owner->generation);
    if (status != SALTS_COMPONENT_PLUGIN_OK) return status;
  }
  if (owner->generation.runtime_owner != NULL) {
    status = salts_component_plugin_generation_drain(&owner->runtime, &owner->generation);
    if (status != SALTS_COMPONENT_PLUGIN_OK) return status;
  }
  if (owner->runtime.initialized) {
    status = salts_component_plugin_runtime_destroy(&owner->runtime);
    if (status != SALTS_COMPONENT_PLUGIN_OK) return status;
  }
  if (owner->affinity.owner != NULL &&
      cmeta_thread_affine_reset(&owner->affinity, owner) != SALTS_OK)
    return SALTS_COMPONENT_PLUGIN_INVALID_STATE;
  memset(owner, 0, sizeof(*owner));
  return SALTS_COMPONENT_PLUGIN_OK;
}
salts_component_plugin_status meshd_rpc_service_component_init(
    meshd_rpc_service_component_t *owner, const mesh_mgmt_service_config_v1_t *config) {
  salts_component_plugin_status status, cleanup;
  salts_component_plugin_generation *previous = NULL;
  if (owner == NULL || config == NULL) return SALTS_COMPONENT_PLUGIN_INVALID_ARGUMENT;
  if (!initializable(owner))
    return SALTS_COMPONENT_PLUGIN_INVALID_STATE;
  if (cmeta_thread_affine_init(&owner->affinity, owner) != SALTS_OK)
    return SALTS_COMPONENT_PLUGIN_INVALID_STATE;
  status = salts_component_plugin_runtime_init(&owner->runtime);
  if (status == SALTS_COMPONENT_PLUGIN_OK) {
    const salts_component_deployment deployment = {
      &mesh_mgmt_rpc_service_component_binding_v1,
      cmeta_reflected_data(mesh_mgmt_service_config_v1_t), config
    };
    const salts_component_plugin_generation_storage storage = {
      owner->deployments, 1, owner->instances, 1, NULL, 0, owner->order, 1, NULL, 0
    };
    status = salts_component_plugin_generation_build(&owner->generation, 1, NULL, &storage,
        &deployment, 1, NULL, 0, NULL, 0);
  }
  if (status == SALTS_COMPONENT_PLUGIN_OK)
    status = salts_component_plugin_runtime_publish(&owner->runtime, &owner->generation, &previous);
  if (status == SALTS_COMPONENT_PLUGIN_OK)
    status = salts_component_plugin_scope_acquire(&owner->runtime, &owner->scope);
  if (status == SALTS_COMPONENT_PLUGIN_OK)
    status = mesh_mgmt_service_component_bind_v1(&owner->scope, "MeshMgmtRpcServiceV1", &owner->view);
  if (status == SALTS_COMPONENT_PLUGIN_OK) return status;
  cleanup = meshd_rpc_service_component_destroy(owner);
  return cleanup == SALTS_COMPONENT_PLUGIN_OK ? status : cleanup;
}

/* The protocol maxima also bound the terminator search, even when the native
 * storage is larger. This adapter never assumes a view is NUL-terminated. */
static bool native_string(vstr storage, size_t max_length, vstr *value) {
  const char *end;
  size_t search_length;
  if (!vstr_is_valid(storage) || storage.len == 0) return false;
  search_length = storage.len < max_length + 1 ? storage.len : max_length + 1;
  end = memchr(storage.data, '\0', search_length);
  if (end == NULL) return false;
  *value = vstr_from_buf(storage.data, (size_t)(end - storage.data));
  return true;
}
salts_component_plugin_status meshd_rpc_service_component_init_native(
    meshd_rpc_service_component_t *owner, vstr ip_storage, vstr host_storage, uint16_t port) {
  mesh_mgmt_service_config_v1_t config = {0};
  vstr ip, dns;
  if (owner == NULL) return SALTS_COMPONENT_PLUGIN_INVALID_ARGUMENT;
  if (!initializable(owner)) return SALTS_COMPONENT_PLUGIN_INVALID_STATE;
  if (!native_string(ip_storage, INET_ADDRSTRLEN - 1, &ip) ||
      !native_string(host_storage, MESH_MGMT_SERVICE_DNS_NAME_MAX, &dns) || port == 0)
    return SALTS_COMPONENT_PLUGIN_INVALID_ARGUMENT;
  config.size = sizeof(config);
  config.version = MESH_MGMT_SERVICE_CONFIG_VERSION;
  config.address_family = MESH_MGMT_SERVICE_ADDRESS_IPV4;
  if (inet_pton(AF_INET, ip.data, config.virtual_address) != 1)
    return SALTS_COMPONENT_PLUGIN_INVALID_ARGUMENT;
  if (!vstr_eq(ip, dns) && dns.len != 0) memcpy(config.dns_name, dns.data, dns.len);
  config.port = port;
  return meshd_rpc_service_component_init(owner, &config);
}

mesh_mgmt_agent_runtime_result_t meshd_rpc_service_component_publish(
    meshd_rpc_service_component_t *owner, mesh_mgmt_agent_runtime_v1_t *agent, uint64_t *epoch) {
  mesh_mgmt_agent_runtime_result_t result;
  if (epoch == NULL) return MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
  *epoch = 0;
  if (owner == NULL || agent == NULL) return MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
  if (!publishable(owner))
    return MESH_MGMT_AGENT_RUNTIME_INVALID_STATE;
  if (cmeta_thread_affine_set_busy(&owner->affinity, owner, true) != SALTS_OK)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_STATE;
  result = mesh_mgmt_agent_runtime_publish_component_service_v1(agent, &owner->view, epoch);
  if (cmeta_thread_affine_set_busy(&owner->affinity, owner, false) != SALTS_OK) {
    *epoch = 0;
    return MESH_MGMT_AGENT_RUNTIME_INVALID_STATE;
  }
  return result;
}

mesh_mgmt_agent_runtime_result_t meshd_rpc_service_component_refresh(
    meshd_rpc_service_component_t *owner, mesh_mgmt_agent_runtime_v1_t *agent,
    uint64_t (*clock_ms)(void), uint64_t *epoch) {
  mesh_mgmt_agent_runtime_result_t result;
  uint64_t now_ms;
  if (epoch == NULL) return MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
  *epoch = 0;
  if (owner == NULL || agent == NULL || clock_ms == NULL) return MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
  if (!publishable(owner) || agent->state != MESH_MGMT_AGENT_RUNTIME_RUNNING)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_STATE;
  if (cmeta_thread_affine_set_busy(&owner->affinity, owner, true) != SALTS_OK)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_STATE;
  now_ms = clock_ms();
  if (owner->refresh_attempted) {
    if (now_ms < owner->last_refresh_attempt_ms) {
      result = MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
      goto finish;
    }
    if (now_ms - owner->last_refresh_attempt_ms < MESHD_MGMT_SERVICE_PUBLISH_INTERVAL_MS) {
      result = MESH_MGMT_AGENT_RUNTIME_OK;
      goto finish;
    }
  }
  result = mesh_mgmt_agent_runtime_publish_component_service_v1(agent, &owner->view, epoch);
  owner->last_refresh_attempt_ms = clock_ms();
  owner->refresh_attempted = true;
finish:
  if (cmeta_thread_affine_set_busy(&owner->affinity, owner, false) != SALTS_OK) {
    *epoch = 0;
    return MESH_MGMT_AGENT_RUNTIME_INVALID_STATE;
  }
  return result;
}
