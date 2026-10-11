#include <tinytest.h>
#include "mesh_mgmt_service_config.h"
#define DATABIND_NATIVE_ENABLE_CMETA
#define DATABIND_NATIVE_ENABLE_DATABIND
#include "mesh_rpc_service_config_contract_native.h"
#include <data_bind_native.h>
#include <tstr.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern const cmeta_data_desc *mesh_test_service_config_native_data(void);
static MeshRpcServiceConfig native_value, native_copy;
static tstr boundary_json;

static const char VALID_RPC[] =
    "{\"schema_version\":1,\"address_family\":4,\"octet0\":100,"
    "\"octet1\":64,\"octet2\":0,\"octet3\":2,\"port\":7878,"
    "\"dns_name\":\"node-b.mesh\"}";

static void test_owned_service_and_borrowed_publish_view(void) {
  mesh_mgmt_service_config_v1_t config = {0};
  mesh_mgmt_service_publish_v1_t publish = {0};
  check_equal(MESH_MGMT_SERVICE_CONFIG_OK,
      mesh_mgmt_service_config_from_json_v1(VALID_RPC, sizeof(VALID_RPC) - 1u,
                                             &config));
  check_equal(sizeof(config), config.size);
  check_equal(MESH_MGMT_SERVICE_CONFIG_VERSION, config.version);
  check_equal(MESH_MGMT_SERVICE_ADDRESS_IPV4, config.address_family);
  check_equal((uint8_t)100u, config.virtual_address[0]);
  check_equal((uint8_t)64u, config.virtual_address[1]);
  check_equal((uint8_t)0u, config.virtual_address[2]);
  check_equal((uint8_t)2u, config.virtual_address[3]);
  check_equal((uint16_t)7878u, config.port);
  check_equal("node-b.mesh", config.dns_name);
  /* Valid across DataBind codec/plan/record destruction. */
  check_equal(MESH_MGMT_SERVICE_CONFIG_OK,
      mesh_mgmt_service_config_publish_view_v1(&config, &publish));
  check_true(publish.dns_name == config.dns_name);
  check_equal("node-b.mesh", publish.dns_name);
  check_equal((uint8_t)100u, publish.virtual_address[0]);
  check_equal((uint8_t)2u, publish.virtual_address[3]);
  check_equal((uint16_t)7878u, publish.port);
  check_equal(MESH_MGMT_SERVICE_ADDRESS_IPV4, publish.address_family);
  memset(&publish, 0xdd, sizeof(publish));
  config.version++;
  check_equal(MESH_MGMT_SERVICE_CONFIG_SERVICE_INVALID,
      mesh_mgmt_service_config_publish_view_v1(&config, &publish));
  check_true(publish.dns_name == NULL);
  check_equal((uint16_t)0, publish.port);
}

static void reject_bad(const char *json,
                       mesh_mgmt_service_config_result_t expected) {
  mesh_mgmt_service_config_v1_t config;
  memset(&config, 0xff, sizeof(config));
  check_equal(expected,
      mesh_mgmt_service_config_from_json_v1(json, strlen(json), &config));
  const uint8_t *bytes = (const uint8_t *)&config;
  for (size_t i = 0u; i < sizeof(config); i++)
    check_equal((uint8_t)0u, bytes[i]);
}

static void test_exact_schema_boundary(void) {
  reject_bad(
    "{\"schema_version\":2,\"address_family\":4,\"octet0\":100,"
    "\"octet1\":64,\"octet2\":0,\"octet3\":2,\"port\":7878,"
    "\"dns_name\":\"node-b.mesh\"}", MESH_MGMT_SERVICE_CONFIG_RECORD_FAILED);
  reject_bad(
    "{\"schema_version\":1,\"address_family\":6,\"octet0\":100,"
    "\"octet1\":64,\"octet2\":0,\"octet3\":2,\"port\":7878,"
    "\"dns_name\":\"node-b.mesh\"}", MESH_MGMT_SERVICE_CONFIG_RECORD_FAILED);
  reject_bad(
    "{\"schema_version\":1,\"address_family\":4,\"octet0\":100,"
    "\"octet1\":64,\"octet2\":0,\"octet3\":2,\"port\":\"7878\","
    "\"dns_name\":\"node-b.mesh\"}", MESH_MGMT_SERVICE_CONFIG_RECORD_FAILED);
  reject_bad(
    "{\"schema_version\":1,\"address_family\":4,\"octet0\":100,"
    "\"octet1\":64,\"octet2\":0,\"octet3\":2,\"port\":7878,"
    "\"dns_name\":\"node-b.mesh\",\"alternate_backend\":true}",
    MESH_MGMT_SERVICE_CONFIG_RECORD_FAILED);
  reject_bad(
    "{\"schema_version\":1,\"address_family\":4,\"octet0\":100,"
    "\"octet1\":64,\"octet2\":0,\"octet3\":2,\"port\":7878}",
    MESH_MGMT_SERVICE_CONFIG_RECORD_FAILED);
}

static void test_canonical_encoder_catches_dns_and_address(void) {
  reject_bad(
    "{\"schema_version\":1,\"address_family\":4,\"octet0\":100,"
    "\"octet1\":64,\"octet2\":0,\"octet3\":2,\"port\":7878,"
    "\"dns_name\":\"Node-B.mesh\"}",
    MESH_MGMT_SERVICE_CONFIG_SERVICE_INVALID);
  reject_bad(
    "{\"schema_version\":1,\"address_family\":4,\"octet0\":100,"
    "\"octet1\":64,\"octet2\":0,\"octet3\":2,\"port\":7878,"
    "\"dns_name\":\"node--.mesh\"}",
    MESH_MGMT_SERVICE_CONFIG_SERVICE_INVALID);
  reject_bad(
    "{\"schema_version\":1,\"address_family\":4,\"octet0\":224,"
    "\"octet1\":0,\"octet2\":0,\"octet3\":1,\"port\":7878,"
    "\"dns_name\":\"node-b.mesh\"}",
    MESH_MGMT_SERVICE_CONFIG_RECORD_FAILED);
  reject_bad(
    "{\"schema_version\":1,\"address_family\":4,\"octet0\":100,"
    "\"octet1\":64,\"octet2\":0,\"octet3\":256,\"port\":7878,"
    "\"dns_name\":\"node-b.mesh\"}",
    MESH_MGMT_SERVICE_CONFIG_RECORD_FAILED);
  reject_bad(
    "{\"schema_version\":1,\"address_family\":4,\"octet0\":100,"
    "\"octet1\":64,\"octet2\":0,\"octet3\":2,\"port\":0,"
    "\"dns_name\":\"node-b.mesh\"}",
    MESH_MGMT_SERVICE_CONFIG_RECORD_FAILED);

  static const char NO_DNS[] =
    "{\"schema_version\":1,\"address_family\":4,\"octet0\":100,"
    "\"octet1\":64,\"octet2\":0,\"octet3\":2,\"port\":7878,"
    "\"dns_name\":\"\"}";
  mesh_mgmt_service_config_v1_t config = {0};
  mesh_mgmt_service_publish_v1_t publish = {0};
  check_equal(MESH_MGMT_SERVICE_CONFIG_OK,
      mesh_mgmt_service_config_from_json_v1(NO_DNS, sizeof(NO_DNS)-1u, &config));
  check_equal(MESH_MGMT_SERVICE_CONFIG_OK,
      mesh_mgmt_service_config_publish_view_v1(&config, &publish));
  check_equal("", publish.dns_name);
  /* Tampering with the owned snapshot must not create an unchecked view. */
  config.dns_name[0] = 'A';
  check_equal(MESH_MGMT_SERVICE_CONFIG_SERVICE_INVALID,
      mesh_mgmt_service_config_publish_view_v1(&config, &publish));
  check_null(publish.dns_name);
}

static void test_input_limits_and_nul_rejection(void) {
  mesh_mgmt_service_config_v1_t config;
  char oversized[MESH_MGMT_SERVICE_CONFIG_MAX_JSON_BYTES + 1u];
  memset(oversized, 'a', sizeof(oversized));
  check_equal(MESH_MGMT_SERVICE_CONFIG_INVALID_ARG,
      mesh_mgmt_service_config_from_json_v1(NULL, 0u, &config));
  check_equal(MESH_MGMT_SERVICE_CONFIG_INVALID_ARG,
      mesh_mgmt_service_config_from_json_v1(VALID_RPC, 0u, &config));
  check_equal(MESH_MGMT_SERVICE_CONFIG_INVALID_ARG,
      mesh_mgmt_service_config_from_json_v1(oversized, sizeof(oversized), &config));
  check_equal((size_t)0u, config.size);

  static const char EMBEDDED_NUL[] =
    "{\"schema_version\":1,\"address_family\":4,\"octet0\":100,"
    "\"octet1\":64,\"octet2\":0,\"octet3\":2,\"port\":7878,"
    "\"dns_name\":\"node\\u0000.mesh\"}";
  memset(&config, 0xff, sizeof(config));
  check_true(mesh_mgmt_service_config_from_json_v1(
      EMBEDDED_NUL, sizeof(EMBEDDED_NUL)-1u, &config) != MESH_MGMT_SERVICE_CONFIG_OK);
  check_equal((size_t)0u, config.size);
}

static void test_generated_value_contract(void) {
  MeshRpcServiceConfig_native_cmeta_binding metadata = {0};
  MeshRpcServiceConfig_native_cmeta_binding view = {0};
  DataBindNativeTypeBinding binding = DATA_BIND_NATIVE_TYPE_BINDING_INIT(NULL, NULL);
  DataBindNativeOptions options = DATA_BIND_NATIVE_OPTIONS_INIT;
  DataBindNativeDiagnostic diagnostic = DATA_BIND_NATIVE_DIAGNOSTIC_INIT;
  DataBindNativePlan *rejected = NULL;
  unsigned char workspace[4096];
  check_equal(data_bind_abi_version(), (uint32_t)DATA_BIND_ABI_VERSION);
  check_equal(MeshRpcServiceConfig_native_type_binding(&metadata, &binding), 0);
  check_equal(binding.abi_version, (uint32_t)DATA_BIND_NATIVE_BINDING_ABI_VERSION);
  check_equal(binding.idl_type_name, "MeshRpcServiceConfig");
  check_equal(binding.presence_count, (size_t)0);
  check_equal(binding.null_count, (size_t)0);
  check_equal(metadata.reflection.mode, CMETA_DATA_REFLECTION_VALUE);
  check_true(cmeta_data_desc_equal(binding.data, mesh_test_service_config_native_data()));
  check_equal(metadata.reflection.structure.field_count, (size_t)8);
  for (size_t i = 0; i < 7; ++i)
    check_true(cmeta_data_desc_equal(metadata.data_fields[i].value, &cmeta_data_uint32));
  check_equal(metadata.data_fields[6].offset, offsetof(MeshRpcServiceConfig, port));
  check_equal(metadata.data_fields[7].offset, offsetof(MeshRpcServiceConfig, dns_name));
  check_equal(metadata.data_fields[7].value->kind, CMETA_DATA_STRING);
  check_true(cmeta_data_value_traits_supported(binding.data));
  check_equal(cmeta_data_value_init_zero(binding.data, &native_value), CMETA_OK);
  check_equal(cmeta_data_value_init_zero(binding.data, &native_copy), CMETA_OK);
  native_value.port = UINT16_MAX;
  check_equal(cmeta_data_buffer_assign(metadata.data_fields[7].value, &native_value.dns_name,
      (const unsigned char *)"owned.mesh", 10, 127), CMETA_OK);
  check_equal(cmeta_data_value_copy(binding.data, &native_copy, &native_value), CMETA_OK);
  check_equal(native_copy.port, (uint32_t)UINT16_MAX);
  check_equal(native_copy.dns_name.size, (size_t)10);
  check_equal(native_copy.dns_name.data, "owned.mesh");
  check_true(native_copy.dns_name.data != native_value.dns_name.data);
  cmeta_data_value_destroy(binding.data, &native_value);
  check_equal(native_copy.dns_name.data, "owned.mesh");
  cmeta_data_value_destroy(binding.data, &native_copy);

  /* Read visibility alone cannot authorize native value lifecycle. */
  check_equal(MeshRpcServiceConfig_native_cmeta_bind(&view), 0);
  options.workspace = workspace;
  options.workspace_bytes = sizeof(workspace);
  options.max_depth = 4;
  options.max_items = 32;
  options.max_owned_bytes = 4096;
  check_equal(data_bind_native_plan_compile(&options, &view.data, &rejected, &diagnostic),
      DATA_BIND_ERR_SCHEMA);
  check_null(rejected);
  data_bind_native_plan_free(rejected);
}

static void test_exact_native_tokens_and_late_rollback(void) {
  static const char *const rejected[] = {
    "null", "[]", "{}",
    "{\"dns_name\":\"allocated-before-error.mesh\",\"schema_version\":1,"
      "\"address_family\":4,\"octet0\":100,\"octet1\":64,\"octet2\":0,"
      "\"octet3\":2,\"port\":\"7878\"}",
    "{\"dns_name\":\"allocated-before-error.mesh\",\"schema_version\":1,"
      "\"address_family\":4,\"octet0\":100,\"octet1\":64,\"octet2\":0,"
      "\"octet3\":2,\"port\":7878.0}",
    "{\"schema_version\":1,\"address_family\":4,\"octet0\":100,"
      "\"octet1\":64,\"octet2\":0,\"octet3\":2,\"port\":true,\"dns_name\":\"\"}",
    "{\"schema_version\":1,\"address_family\":4,\"octet0\":100,"
      "\"octet1\":64,\"octet2\":0,\"octet3\":2,\"port\":null,\"dns_name\":\"\"}",
    "{\"schema_version\":1,\"address_family\":4,\"octet0\":100,"
      "\"octet1\":64,\"octet2\":0,\"octet3\":2,\"port\":-1,\"dns_name\":\"\"}",
    "{\"schema_version\":1,\"address_family\":4,\"octet0\":100,"
      "\"octet1\":64,\"octet2\":0,\"octet3\":2,\"port\":4294967296,\"dns_name\":\"\"}",
    "{\"schema_version\":1,\"address_family\":4,\"octet0\":100,"
      "\"octet1\":64,\"octet2\":0,\"octet3\":2,\"port\":7878,\"dns_name\":null}",
    "{\"schema_version\":1,\"address_family\":4,\"octet0\":100,"
      "\"octet1\":64,\"octet2\":0,\"octet3\":2,\"port\":7878,\"dns_name\":{}}",
    "{\"dns_name\":\"allocated-before-error.mesh\",\"schema_version\":1,"
      "\"address_family\":4,\"octet0\":100,\"octet1\":64,\"octet2\":0,"
      "\"octet3\":2,\"port\":7878,\"unexpected\":1}",
    "{\"schema_version\":1,\"address_family\":4,\"octet0\":100,"
      "\"octet1\":64,\"octet2\":0,\"octet3\":2,\"port\":7878,"
      "\"dns_name\":\"first.mesh\",\"dns_name\":\"second.mesh\"}",
    "{\"schema_version\":1,\"address_family\":4,\"octet0\":100,"
      "\"octet1\":64,\"octet2\":0,\"octet3\":2,\"port\":7878,\"dns_name\":\"\"} {}"
  };
  for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i)
    reject_bad(rejected[i], MESH_MGMT_SERVICE_CONFIG_RECORD_FAILED);
}

static void test_dns_storage_boundary(void) {
  static const char max_dns[] =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  mesh_mgmt_service_config_v1_t config;
  tstr appended;
  check_equal(sizeof(max_dns) - 1, (size_t)MESH_MGMT_SERVICE_DNS_NAME_MAX);
  boundary_json = tstr_dup(
    "{\"schema_version\":1,\"address_family\":4,\"octet0\":100,"
    "\"octet1\":64,\"octet2\":0,\"octet3\":2,\"port\":7878,\"dns_name\":\"");
  check_not_null(boundary_json);
  appended = tstr_cat(boundary_json, max_dns);
  check_not_null(appended);
  boundary_json = appended;
  appended = tstr_cat(boundary_json, "\"}");
  check_not_null(appended);
  boundary_json = appended;
  check_equal(mesh_mgmt_service_config_from_json_v1(
      boundary_json, tstr_len(boundary_json), &config), MESH_MGMT_SERVICE_CONFIG_OK);
  check_equal(config.dns_name, max_dns);
  /* One extra DNS byte remains SERVICE_INVALID, preserving error semantics. */
  boundary_json[tstr_len(boundary_json) - 2] = 'b';
  boundary_json[tstr_len(boundary_json) - 1] = '"';
  appended = tstr_cat(boundary_json, "}");
  check_not_null(appended);
  boundary_json = appended;
  reject_bad(boundary_json, MESH_MGMT_SERVICE_CONFIG_SERVICE_INVALID);
}

static void test_reordered_and_source_independent(void) {
  char json[] =
    "{\"dns_name\":\"node-b.mesh\",\"port\":65535,\"octet3\":255,"
    "\"octet2\":255,\"octet1\":255,\"octet0\":223,"
    "\"address_family\":4,\"schema_version\":1}";
  mesh_mgmt_service_config_v1_t config = {0};
  mesh_mgmt_service_publish_v1_t view = {0};
  check_equal(mesh_mgmt_service_config_from_json_v1(json, sizeof(json) - 1, &config),
      MESH_MGMT_SERVICE_CONFIG_OK);
  memset(json, 'x', sizeof(json));
  check_equal(mesh_mgmt_service_config_publish_view_v1(&config, &view),
      MESH_MGMT_SERVICE_CONFIG_OK);
  check_equal(view.dns_name, "node-b.mesh");
  check_equal(view.port, (uint16_t)65535);
  check_equal(view.virtual_address[0], (uint8_t)223);
  check_equal(view.virtual_address[3], (uint8_t)255);
}

spec("DataBind 4.3 canonical RPC service ACE Configurator") {
  after_each() {
    MeshRpcServiceConfig_clear(&native_value);
    MeshRpcServiceConfig_clear(&native_copy);
    tstr_freep(&boundary_json);
  }
  it("projects an owned typed service snapshot with an address-stable publish view") {
    test_owned_service_and_borrowed_publish_view();
  }
  it("rejects version drift, unknown fields, missing required fields and token coercion") {
    test_exact_schema_boundary();
  }
  it("reuses the canonical service encoder for DNS/IP admission and permits empty DNS") {
    test_canonical_encoder_catches_dns_and_address();
  }
  it("rejects over-limit payloads and an embedded NUL before service publication") {
    test_input_limits_and_nul_rejection();
  }
  it("admits generated C11 descriptors across TUs and refuses VIEW ownership") {
    test_generated_value_contract();
  }
  it("rejects exact native token drift and rolls back a partially owned value") {
    test_exact_native_tokens_and_late_rollback();
  }
  it("owns reordered boundary scalars and DNS after the input and parser expire") {
    test_reordered_and_source_independent();
  }
  it("preserves exact maximum DNS storage and one-byte-over-limit error semantics") {
    test_dns_storage_boundary();
  }
}
