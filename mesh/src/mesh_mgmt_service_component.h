#ifndef MESH_MGMT_SERVICE_COMPONENT_H
#define MESH_MGMT_SERVICE_COMPONENT_H

#include "mesh_mgmt_service_config.h"
#include <cmeta/data_reflect.h>
#include <salts/component_plugin.h>

/* Describe the complete existing native layout without granting field writes
 * or automatic value lifecycle. DNS remains canonical NUL-terminated storage;
 * the fixed-byte descriptor records its extent, not a second string policy. */
typedef uint8_t mesh_mgmt_service_address_storage_v1_t[16];
typedef char mesh_mgmt_service_dns_storage_v1_t[MESH_MGMT_SERVICE_DNS_NAME_MAX + 1u];
CMETA_DEFINE_FIXED_BYTES(mesh_mgmt_service_address_v1,
    mesh_mgmt_service_address_storage_v1_t, 16u,
    "turbo.mesh.mgmt.service.address.v1", "ServiceAddress");
CMETA_DEFINE_FIXED_BYTES(mesh_mgmt_service_dns_v1,
    mesh_mgmt_service_dns_storage_v1_t, MESH_MGMT_SERVICE_DNS_NAME_MAX + 1u,
    "turbo.mesh.mgmt.service.dns.v1", "ServiceDnsStorage");
cmeta_reflect_data(mesh_mgmt_service_config_v1_t, "turbo.mesh.mgmt.service.config.v1",
    cmeta_data_field(size_t, size, &cmeta_data_size, &cmeta_type_size)
    cmeta_data_field(uint32_t, version, &cmeta_data_uint32, &cmeta_type_uint32)
    cmeta_data_field(uint8_t, address_family, &cmeta_data_uint8, &cmeta_type_uint8)
    cmeta_data_field(mesh_mgmt_service_address_storage_v1_t, virtual_address,
        &mesh_mgmt_service_address_v1_cmeta_data, &mesh_mgmt_service_address_v1_cmeta_type)
    cmeta_data_field(uint16_t, port, &cmeta_data_uint16, &cmeta_type_uint16)
    cmeta_data_field(mesh_mgmt_service_dns_storage_v1_t, dns_name,
        &mesh_mgmt_service_dns_v1_cmeta_data, &mesh_mgmt_service_dns_v1_cmeta_type));

#define MESH_MGMT_SERVICE_PROVIDER_METHODS_V1(X, I) \
    X(I, R1, mesh_mgmt_service_config_result_t, snapshot, mesh_mgmt_service_publish_v1_t *, out)
CMETA_INTERFACE(mesh_mgmt_service_provider_v1, MESH_MGMT_SERVICE_PROVIDER_METHODS_V1);
CMETA_OBJECT_INTERFACE_ADAPTER(mesh_mgmt_service_provider_v1);

/* One opt-in RPC service Component. Host parsing remains DataBind's existing
 * strict startup schema. create copies and validates the entire config once;
 * Component owns its immutable snapshot through ObjectRef destruction. */
cmeta_component_configured(MeshMgmtRpcServiceV1,
    cmeta_reflected_data(mesh_mgmt_service_config_v1_t),
    cmeta_provides(mesh_mgmt_service_provider_v1));

#ifdef __cplusplus
extern "C" {
#endif
extern const cmeta_object_interface_provider mesh_mgmt_service_component_interfaces_v1;
cmeta_status SALTS_COMPONENT_CALL mesh_mgmt_service_component_create_v1(
    void *context, const cmeta_data_desc *data, const void *config,
    const salts_component_dependency *dependencies, size_t count, cmeta_object_ref *out);

/* Also usable by a DSO's canonical salts_component_provider export. Metadata
 * and lifecycle callbacks borrow the DSO; ComponentPlugin owns the module pin. */
#define MESH_MGMT_SERVICE_COMPONENT_BINDING_V1(component_) \
    { sizeof(salts_component_provider_binding), SALTS_COMPONENT_PROVIDER_BINDING_ABI_VERSION, \
      cmeta_component_meta(component_), NULL, &mesh_mgmt_service_component_interfaces_v1, \
      mesh_mgmt_service_component_create_v1, NULL, NULL }

extern const salts_component_provider_binding mesh_mgmt_rpc_service_component_binding_v1;

/* A freely copyable borrowed capability, without scope ownership. Bind once
 * at startup/admission. The original scope is noncopyable/address-stable and
 * must remain live on this owner thread through snapshot/sign/cache completion.
 * Every copy expires when that scope is released; clear before scope reuse. */
typedef struct {
  const salts_component_plugin_scope *scope;
  uint64_t generation_id;
  mesh_mgmt_service_provider_v1 provider;
} mesh_mgmt_service_component_view_v1_t;
#define MESH_MGMT_SERVICE_COMPONENT_VIEW_INIT_V1 {0}

salts_component_plugin_status mesh_mgmt_service_component_bind_v1(
    const salts_component_plugin_scope *scope, const char *component_id,
    mesh_mgmt_service_component_view_v1_t *out);

/* Snapshot's DNS is borrowed from the immutable Component until scope release.
 * Failures clear output; invalid/released/copied scopes dispatch no provider. */
mesh_mgmt_service_config_result_t mesh_mgmt_service_component_snapshot_v1(
    const mesh_mgmt_service_component_view_v1_t *view,
    mesh_mgmt_service_publish_v1_t *out);
#ifdef __cplusplus
}
#endif
#endif
