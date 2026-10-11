#ifndef MESH_TEST_SERVICE_GATE_H
#define MESH_TEST_SERVICE_GATE_H

#include "mesh_mgmt_service_component.h"

/* Test-only callback/config: the host owns the address-stable gate until all
 * calls, scopes and generation objects retire. The callback is deliberately
 * opaque to Reflection; the native fixture owns its invocation contract. */
typedef struct {
  mesh_mgmt_service_config_v1_t service;
  void (*pause)(void *context);
  void *context;
} mesh_test_service_gate_config;
cmeta_reflect_data(mesh_test_service_gate_config, "test.turbo.mesh.service.gate.config",
    cmeta_data_field(mesh_mgmt_service_config_v1_t, service,
        cmeta_reflected_data(mesh_mgmt_service_config_v1_t),
        cmeta_reflected_storage(mesh_mgmt_service_config_v1_t)));

extern const salts_component_provider_binding mesh_test_service_gate_binding;
#endif
