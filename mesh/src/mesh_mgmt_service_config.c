#include "mesh_mgmt_service_config.h"

#define DATABIND_NATIVE_ENABLE_CMETA
#define DATABIND_NATIVE_ENABLE_DATABIND
#include "mesh_rpc_service_config_contract_native.h"
#include "rpc_service_config_schema.h"

#include <data_bind_message_plan.h>
#include <data_bind_json_provider.h>

#include <string.h>

/* Bounded scratch for a flat eight-field startup record. Generated descriptor
 * storage stays at its final address until the borrowing plan is freed. The
 * compiler-owned text carrier exists only in staging and never reaches CNet. */
enum { RPC_CONFIG_WORKSPACE_BYTES = 4096, RPC_CONFIG_DEPTH = 4,
       RPC_CONFIG_ITEMS = 32 };

/* Reuse the canonical MMP wire encoder strictly as startup validation.
 * A dummy nonzero signer identity/epoch/expiry makes the address/DNS policy
 * identical to the real publisher; this function signs or sends nothing. */
static int service_is_canonical(const mesh_mgmt_service_config_v1_t *config) {
  mesh_mgmt_service_announcement_v1_t claim = {0};
  uint8_t buffer[MESH_MGMT_SERVICE_RECORD_V1_MAX_SIZE];
  size_t encoded = 0u;
  const char *terminator;
  if (config == NULL || config->size != sizeof(*config) ||
      config->version != MESH_MGMT_SERVICE_CONFIG_VERSION ||
      config->address_family != MESH_MGMT_SERVICE_ADDRESS_IPV4 ||
      config->port == 0u)
    return 0;
  terminator = (const char *)memchr(config->dns_name, '\0', sizeof(config->dns_name));
  if (terminator == NULL) return 0;

  claim.owner_node_id[0] = 1u;
  claim.service_type = MESH_MGMT_SERVICE_RPC;
  claim.address_family = (mesh_mgmt_service_address_family_t)config->address_family;
  memcpy(claim.virtual_address, config->virtual_address, sizeof(claim.virtual_address));
  memcpy(claim.dns_name, config->dns_name,
         (size_t)(terminator - config->dns_name) + 1u);
  claim.port = config->port;
  claim.record_epoch = 1u;
  claim.expires_at_ms = 1u;
  return mesh_mgmt_service_record_encode_v1(
      &claim, buffer, sizeof(buffer), &encoded) == MESH_MGMT_SERVICE_RECORD_OK;
}

mesh_mgmt_service_config_result_t mesh_mgmt_service_config_from_json_v1(
    const char *json, size_t json_length,
    mesh_mgmt_service_config_v1_t *out_config) {
  DataBind *codec = NULL;
  DataBindMessagePlan *plan = NULL;
  MeshRpcServiceConfig_native_cmeta_binding metadata = {0};
  DataBindNativeTypeBinding binding = DATA_BIND_NATIVE_TYPE_BINDING_INIT(NULL, NULL);
  MeshRpcServiceConfig record = {0};
  DataBindError error = DATA_BIND_ERROR_INIT;
  DataBindMessagePlanDiagnostic diagnostic = DATA_BIND_MESSAGE_PLAN_DIAGNOSTIC_INIT;
  DataBindNativeOptions options = DATA_BIND_NATIVE_OPTIONS_INIT;
  DataBindFormatReader reader = DATA_BIND_FORMAT_READER_INIT;
  unsigned char workspace[RPC_CONFIG_WORKSPACE_BYTES];
  cserde_token tail;
  mesh_mgmt_service_config_v1_t pending = {0};
  mesh_mgmt_service_config_result_t result = MESH_MGMT_SERVICE_CONFIG_RECORD_FAILED;
  uint32_t octets[4];

  if (!out_config)
    return MESH_MGMT_SERVICE_CONFIG_INVALID_ARG;
  memset(out_config, 0, sizeof(*out_config));
  if (!json || !json_length || json_length > MESH_MGMT_SERVICE_CONFIG_MAX_JSON_BYTES)
    return MESH_MGMT_SERVICE_CONFIG_INVALID_ARG;

  if (data_bind_create_from_text(
          MESH_RPC_SERVICE_CONFIG_SCHEMA,
          sizeof(MESH_RPC_SERVICE_CONFIG_SCHEMA) - 1u,
          &codec, &error) != DATA_BIND_OK) {
    result = MESH_MGMT_SERVICE_CONFIG_SCHEMA_FAILED;
    goto completed;
  }
  if (MeshRpcServiceConfig_native_type_binding(&metadata, &binding) != 0 ||
      data_bind_message_plan_compile(
          codec, binding.idl_type_name, &binding, &plan, &diagnostic) != DATA_BIND_OK) {
    result = MESH_MGMT_SERVICE_CONFIG_SCHEMA_FAILED;
    goto completed;
  }
  options.workspace = workspace;
  options.workspace_bytes = sizeof(workspace);
  options.max_depth = RPC_CONFIG_DEPTH;
  options.max_items = RPC_CONFIG_ITEMS;
  options.max_owned_bytes = MESH_MGMT_SERVICE_CONFIG_MAX_JSON_BYTES;
  if (data_bind_format_reader_open(data_bind_json_format_provider(),
          json, json_length, RPC_CONFIG_DEPTH, &reader, &error) != DATA_BIND_OK)
    goto completed;
  if (data_bind_message_plan_decode_native(plan, &options, reader.reader,
          &record, sizeof(record), &diagnostic) != DATA_BIND_OK ||
      cserde_reader_next(reader.reader, &tail) != CSERDE_DONE ||
      data_bind_message_plan_validate_native(plan, &record, sizeof(record),
          &error) != DATA_BIND_OK)
    goto completed;
  if (data_bind_format_reader_close(&reader) != DATA_BIND_OK)
    goto completed;

  if (record.schema_version != MESH_MGMT_SERVICE_CONFIG_VERSION ||
      record.address_family != MESH_MGMT_SERVICE_ADDRESS_IPV4 ||
      !record.port || record.port > UINT16_MAX ||
      record.dns_name.size > MESH_MGMT_SERVICE_DNS_NAME_MAX ||
      (record.dns_name.size && (!record.dns_name.data ||
          memchr(record.dns_name.data, '\0', record.dns_name.size)))) {
    result = MESH_MGMT_SERVICE_CONFIG_SERVICE_INVALID;
    goto completed;
  }

  pending.size = sizeof(pending);
  pending.version = MESH_MGMT_SERVICE_CONFIG_VERSION;
  pending.address_family = (uint8_t)record.address_family;
  pending.port = (uint16_t)record.port;
  octets[0] = record.octet0;
  octets[1] = record.octet1;
  octets[2] = record.octet2;
  octets[3] = record.octet3;
  for (size_t i = 0u; i < 4u; ++i) {
    if (octets[i] > 255u) {
      result = MESH_MGMT_SERVICE_CONFIG_SERVICE_INVALID;
      goto completed;
    }
    pending.virtual_address[i] = (uint8_t)octets[i];
  }
  if (record.dns_name.size != 0u)
    memcpy(pending.dns_name, record.dns_name.data, record.dns_name.size);
  pending.dns_name[record.dns_name.size] = '\0';
  if (!service_is_canonical(&pending)) {
    result = MESH_MGMT_SERVICE_CONFIG_SERVICE_INVALID;
    goto completed;
  }
  *out_config = pending;
  result = MESH_MGMT_SERVICE_CONFIG_OK;

completed:
  data_bind_format_reader_close(&reader);
  MeshRpcServiceConfig_clear(&record);
  data_bind_message_plan_free(plan);
  data_bind_free(codec);
  return result;
}

mesh_mgmt_service_config_result_t mesh_mgmt_service_config_publish_view_v1(
    const mesh_mgmt_service_config_v1_t *owner,
    mesh_mgmt_service_publish_v1_t *out_service) {
  if (!out_service) return MESH_MGMT_SERVICE_CONFIG_INVALID_ARG;
  memset(out_service, 0, sizeof(*out_service));
  if (!service_is_canonical(owner))
    return MESH_MGMT_SERVICE_CONFIG_SERVICE_INVALID;
  out_service->address_family = owner->address_family;
  memcpy(out_service->virtual_address, owner->virtual_address,
         sizeof(out_service->virtual_address));
  out_service->dns_name = owner->dns_name;
  out_service->port = owner->port;
  return MESH_MGMT_SERVICE_CONFIG_OK;
}
