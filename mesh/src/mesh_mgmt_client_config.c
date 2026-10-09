#include "mesh_mgmt_client_config.h"

#include <data_bind.h>
#include <data_bind_validation_plan.h>
#include <string.h>
#ifdef MESH_MGMT_CLIENT_CONFIG_DIAGNOSTICS
#include <stdio.h>
#define REPORT_DATABIND_ERROR(stage, error) \
  fprintf(stderr, "mesh-client %s failed: status=%d path=%s message=%s\n", \
          (stage), (int)(error).code, (error).path, (error).message)
#else
#define REPORT_DATABIND_ERROR(stage, error) ((void)0)
#endif

static const char MESH_CLIENT_SCHEMA[] =
    "message MeshClientPolicy {"
    " @Min(1) @Max(1) uint32 schema_version;"
    " string kind;"
    " uint64 key_hash;"
    " string transport_peer_id;"
    "}";

static int string_is(const DataBindStringView *text, const char *literal) {
  return text->data && text->length == strlen(literal) &&
         memcmp(text->data, literal, text->length) == 0;
}

static int from_lower_hex(char digit) {
  if (digit >= '0' && digit <= '9') return digit - '0';
  if (digit >= 'a' && digit <= 'f') return digit - 'a' + 10;
  return -1;
}

static int decode_transport_id(
    const DataBindStringView *text, uint8_t id[P2P_KEY_SIZE]) {
  if (!text->data || text->length != P2P_KEY_SIZE * 2u)
    return 0;
  uint8_t nonzero = 0u;
  for (size_t i = 0u; i < P2P_KEY_SIZE; i++) {
    int hi = from_lower_hex(text->data[i * 2u]);
    int lo = from_lower_hex(text->data[i * 2u + 1u]);
    if (hi < 0 || lo < 0) return 0;
    id[i] = (uint8_t)((hi << 4) | lo);
    nonzero |= id[i];
  }
  return nonzero != 0u;
}

mesh_mgmt_client_config_result_t mesh_mgmt_client_policy_from_json_v1(
    const char *json, size_t json_length,
    mesh_mgmt_client_destination_policy_v2_t *out_policy) {
  DataBind *codec = NULL;
  DataBindValidationPlan *plan = NULL;
  DataBindRecord *record = NULL;
  DataBindJsonOptions exact = DATA_BIND_JSON_OPTIONS_INIT;
  DataBindError error = DATA_BIND_ERROR_INIT;
  DataBindStringView kind = DATA_BIND_STRING_VIEW_INIT;
  DataBindStringView peer = DATA_BIND_STRING_VIEW_INIT;
  mesh_mgmt_client_destination_policy_v2_t pending = {0};
  mesh_mgmt_client_config_result_t result = MESH_MGMT_CLIENT_CONFIG_RECORD_FAILED;
  uint32_t version = 0u;
  uint64_t key_hash = 0u;

  if (!out_policy)
    return MESH_MGMT_CLIENT_CONFIG_INVALID_ARG;
  memset(out_policy, 0, sizeof(*out_policy));
  if (!json || json_length == 0u || json_length > MESH_MGMT_CLIENT_CONFIG_MAX_BYTES)
    return MESH_MGMT_CLIENT_CONFIG_INVALID_ARG;

  if (data_bind_create_from_text(MESH_CLIENT_SCHEMA, sizeof(MESH_CLIENT_SCHEMA) - 1u,
                                 &codec, &error) != DATA_BIND_OK) {
    REPORT_DATABIND_ERROR("schema", error);
    result = MESH_MGMT_CLIENT_CONFIG_SCHEMA_FAILED;
    goto completed;
  }
  if (data_bind_validation_plan_compile(codec, "MeshClientPolicy", &plan, &error) !=
      DATA_BIND_OK) {
    REPORT_DATABIND_ERROR("plan", error);
    result = MESH_MGMT_CLIENT_CONFIG_SCHEMA_FAILED;
    goto completed;
  }
  exact.flags = DATA_BIND_JSON_BIND_EXACT_SCALAR_TOKENS |
                DATA_BIND_JSON_BIND_REJECT_UNKNOWN_FIELDS;
  if (data_bind_record_from_json_ex(codec, "MeshClientPolicy", json, json_length,
                                    &exact, &record, &error) != DATA_BIND_OK ||
      !record)
    goto completed;
  if (data_bind_validation_plan_validate(
          plan, data_bind_object_value((const DataBindObject *)record), &error) !=
      DATA_BIND_OK)
    goto completed;
  if (data_bind_record_get_u32(record, "schema_version", &version, &error) !=
          DATA_BIND_OK ||
      version != 1u ||
      data_bind_record_get_string(record, "kind", &kind, &error) != DATA_BIND_OK ||
      data_bind_record_get_u64(record, "key_hash", &key_hash, &error) != DATA_BIND_OK ||
      data_bind_record_get_string(record, "transport_peer_id", &peer, &error) !=
          DATA_BIND_OK)
    goto completed;

  pending.size = sizeof(pending);
  pending.version = MESH_MGMT_CLIENT_DESTINATION_POLICY_VERSION;
  if (string_is(&kind, "ROUND_ROBIN")) {
    if (key_hash != 0u || peer.length != 0u) {
      result = MESH_MGMT_CLIENT_CONFIG_POLICY_INVALID;
      goto completed;
    }
    pending.kind = CNET_DESTINATION_ROUND_ROBIN;
  } else if (string_is(&kind, "STRICT_KEY")) {
    if (peer.length != 0u) {
      result = MESH_MGMT_CLIENT_CONFIG_POLICY_INVALID;
      goto completed;
    }
    pending.kind = CNET_DESTINATION_STRICT_KEY;
    pending.key_hash = key_hash;
    pending.key_known = true;
  } else if (string_is(&kind, "EXPLICIT")) {
    if (key_hash != 0u ||
        !decode_transport_id(&peer, pending.explicit_transport_peer_id)) {
      result = MESH_MGMT_CLIENT_CONFIG_POLICY_INVALID;
      goto completed;
    }
    pending.kind = CNET_DESTINATION_EXPLICIT;
  } else {
    result = MESH_MGMT_CLIENT_CONFIG_POLICY_INVALID;
    goto completed;
  }
  *out_policy = pending;
  result = MESH_MGMT_CLIENT_CONFIG_OK;

completed:
  data_bind_record_free(record);
  data_bind_validation_plan_free(plan);
  data_bind_free(codec);
  return result;
}
