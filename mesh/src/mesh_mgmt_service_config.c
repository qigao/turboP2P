#include "mesh_mgmt_service_config.h"

#include <data_bind.h>
#include <data_bind_validation_plan.h>

#include <string.h>

/* SaltsUtils 4.3 validates the canonical Binary field order while compiling
 * any schema, including this JSON-only one: fixed scalars first, variable
 * string last. No Binary layout or admission is inferred for live MMP. */
static const char MESH_RPC_SERVICE_CONFIG_SCHEMA[] =
    "message MeshRpcServiceConfig {"
    " @Min(1) @Max(1) uint32 schema_version;"
    " @Min(4) @Max(4) uint32 address_family;"
    " @Min(1) @Max(223) uint32 octet0;"
    " @Min(0) @Max(255) uint32 octet1;"
    " @Min(0) @Max(255) uint32 octet2;"
    " @Min(0) @Max(255) uint32 octet3;"
    " @Min(1) @Max(65535) uint32 port;"
    " string dns_name;"
    "}";

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
  DataBindValidationPlan *plan = NULL;
  DataBindRecord *record = NULL;
  DataBindError error = DATA_BIND_ERROR_INIT;
  DataBindJsonOptions exact = DATA_BIND_JSON_OPTIONS_INIT;
  DataBindStringView dns = DATA_BIND_STRING_VIEW_INIT;
  mesh_mgmt_service_config_v1_t pending = {0};
  mesh_mgmt_service_config_result_t result = MESH_MGMT_SERVICE_CONFIG_RECORD_FAILED;
  uint32_t schema_version = 0u;
  uint32_t family = 0u;
  uint32_t octets[4] = {0};
  uint32_t port = 0u;

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
  if (data_bind_validation_plan_compile(
          codec, "MeshRpcServiceConfig", &plan, &error) != DATA_BIND_OK) {
    result = MESH_MGMT_SERVICE_CONFIG_SCHEMA_FAILED;
    goto completed;
  }
  exact.flags = DATA_BIND_JSON_BIND_EXACT_SCALAR_TOKENS |
                DATA_BIND_JSON_BIND_REJECT_UNKNOWN_FIELDS;
  if (data_bind_record_from_json_ex(
          codec, "MeshRpcServiceConfig", json, json_length, &exact,
          &record, &error) != DATA_BIND_OK || !record)
    goto completed;
  if (data_bind_validation_plan_validate(
          plan, data_bind_object_value((const DataBindObject *)record),
          &error) != DATA_BIND_OK)
    goto completed;

  if (data_bind_record_get_u32(record, "schema_version", &schema_version, &error) !=
          DATA_BIND_OK ||
      data_bind_record_get_u32(record, "address_family", &family, &error) !=
          DATA_BIND_OK ||
      data_bind_record_get_u32(record, "octet0", &octets[0], &error) != DATA_BIND_OK ||
      data_bind_record_get_u32(record, "octet1", &octets[1], &error) != DATA_BIND_OK ||
      data_bind_record_get_u32(record, "octet2", &octets[2], &error) != DATA_BIND_OK ||
      data_bind_record_get_u32(record, "octet3", &octets[3], &error) != DATA_BIND_OK ||
      data_bind_record_get_u32(record, "port", &port, &error) != DATA_BIND_OK ||
      data_bind_record_get_string(record, "dns_name", &dns, &error) != DATA_BIND_OK)
    goto completed;

  if (schema_version != 1u || family != MESH_MGMT_SERVICE_ADDRESS_IPV4 ||
      !port || port > UINT16_MAX ||
      dns.length > MESH_MGMT_SERVICE_DNS_NAME_MAX ||
      (dns.length && (!dns.data || memchr(dns.data, '\0', dns.length))) ) {
    result = MESH_MGMT_SERVICE_CONFIG_SERVICE_INVALID;
    goto completed;
  }

  pending.size = sizeof(pending);
  pending.version = MESH_MGMT_SERVICE_CONFIG_VERSION;
  pending.address_family = (uint8_t)family;
  pending.port = (uint16_t)port;
  for (size_t i = 0u; i < 4u; ++i) {
    if (octets[i] > 255u) {
      result = MESH_MGMT_SERVICE_CONFIG_SERVICE_INVALID;
      goto completed;
    }
    pending.virtual_address[i] = (uint8_t)octets[i];
  }
  if (dns.length != 0u) memcpy(pending.dns_name, dns.data, dns.length);
  pending.dns_name[dns.length] = '\0';
  if (!service_is_canonical(&pending)) {
    result = MESH_MGMT_SERVICE_CONFIG_SERVICE_INVALID;
    goto completed;
  }
  *out_config = pending;
  result = MESH_MGMT_SERVICE_CONFIG_OK;

completed:
  data_bind_record_free(record);
  data_bind_validation_plan_free(plan);
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
