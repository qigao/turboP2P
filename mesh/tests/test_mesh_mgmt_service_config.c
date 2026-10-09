#include <tinytest.h>
#include "mesh_mgmt_service_config.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

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

spec("DataBind 4.3 canonical RPC service ACE Configurator") {
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
}
