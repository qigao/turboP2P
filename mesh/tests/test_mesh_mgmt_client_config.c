#include <tinytest.h>
#include "mesh_mgmt_client_config.h"
#include <string.h>
#include <stdio.h>

static const char POLICY_RR[] =
    "{\"schema_version\":1,\"kind\":\"ROUND_ROBIN\",\"key_hash\":0,"
    "\"transport_peer_id\":\"\"}";
static const char POLICY_STRICT[] =
    "{\"schema_version\":1,\"kind\":\"STRICT_KEY\",\"key_hash\":123456,"
    "\"transport_peer_id\":\"\"}";

typedef struct {
  char called_host[32];
  unsigned calls;
} selected_dial_t;

static int connect_selected(void *ctx, p2p_node_t *node, const char *host, uint16_t port) {
  selected_dial_t *result = ctx;
  if (node != (p2p_node_t *)ctx || strcmp(host, "peer.example") != 0 || port != 443u)
    return P2P_ERR_INVALID_ARG;
  memcpy(result->called_host, host, strlen(host) + 1u);
  result->calls++;
  return P2P_OK;
}

static void test_valid_policy_records_and_owned_output(void) {
  mesh_mgmt_client_destination_policy_v2_t policy = {0};
  char hex_id[P2P_KEY_SIZE * 2u + 1u];
  char json[256];
  memset(hex_id, '1', P2P_KEY_SIZE * 2u);
  hex_id[P2P_KEY_SIZE * 2u] = '\0';

  check_equal(MESH_MGMT_CLIENT_CONFIG_OK,
      mesh_mgmt_client_policy_from_json_v1(POLICY_RR, sizeof(POLICY_RR) - 1u, &policy));
  check_equal(CNET_DESTINATION_ROUND_ROBIN, policy.kind);
  check_equal(sizeof(policy), policy.size);
  check_equal(MESH_MGMT_CLIENT_DESTINATION_POLICY_VERSION, policy.version);
  check_equal(0u, policy.key_hash);

  check_equal(MESH_MGMT_CLIENT_CONFIG_OK,
      mesh_mgmt_client_policy_from_json_v1(POLICY_STRICT,
                                            sizeof(POLICY_STRICT) - 1u, &policy));
  check_equal(CNET_DESTINATION_STRICT_KEY, policy.kind);
  check_true(policy.key_known);
  check_equal(UINT64_C(123456), policy.key_hash);

  snprintf(json, sizeof(json),
      "{\"schema_version\":1,\"kind\":\"EXPLICIT\",\"key_hash\":0,"
      "\"transport_peer_id\":\"%s\"}", hex_id);
  check_equal(MESH_MGMT_CLIENT_CONFIG_OK,
      mesh_mgmt_client_policy_from_json_v1(json, strlen(json), &policy));
  check_equal(CNET_DESTINATION_EXPLICIT, policy.kind);
  for (size_t i = 0u; i < P2P_KEY_SIZE; i++)
    check_equal((uint8_t)0x11u, policy.explicit_transport_peer_id[i]);

  /* DataBind objects and codec no longer exist; the public CNet policy is
   * fully owned and can be installed on a clean management endpoint pool. */
  mesh_mgmt_endpoint_pool_v1_t pool = {0};
  mesh_mgmt_endpoint_pool_config_v1_t config = {0};
  selected_dial_t dial = {0};
  uint8_t signed_peer_id[P2P_KEY_SIZE];
  memset(signed_peer_id, 0x11, sizeof(signed_peer_id));
  config.node = (p2p_node_t *)&dial;
  config.capacity = 2u;
  config.retry_base_ms = 10u;
  config.retry_max_ms = 40u;
  config.connect_timeout_ms = 30u;
  config.protocol_failure_limit = 2u;
  config.connect_peer = connect_selected;
  config.callback_context = &dial;
  check_equal(MESH_MGMT_ENDPOINT_POOL_OK, mesh_mgmt_endpoint_pool_init_v1(&pool, &config));
  check_equal(MESH_MGMT_ENDPOINT_POOL_OK, mesh_mgmt_endpoint_pool_add_static_v1(
      &pool, signed_peer_id, "peer.example", 443u));
  check_equal(MESH_MGMT_ENDPOINT_POOL_OK, mesh_mgmt_endpoint_pool_set_client_policy_v2(&pool, &policy));
  check_equal(MESH_MGMT_ENDPOINT_POOL_OK, mesh_mgmt_endpoint_pool_start_v1(&pool));
  check_equal(MESH_MGMT_ENDPOINT_POOL_OK, mesh_mgmt_endpoint_pool_tick_v2(&pool, 100u));
  check_equal(1u, dial.calls);
  check_equal("peer.example", dial.called_host);
  mesh_mgmt_endpoint_pool_stop_v1(&pool);
  mesh_mgmt_endpoint_pool_destroy_v1(&pool);
}

static void check_bad(const char *text, mesh_mgmt_client_config_result_t expected) {
  mesh_mgmt_client_destination_policy_v2_t policy;
  memset(&policy, 0xcc, sizeof(policy));
  check_equal(expected, mesh_mgmt_client_policy_from_json_v1(text, strlen(text), &policy));
  for (size_t i = 0u; i < sizeof(policy); i++)
    check_equal((uint8_t)0u, ((const uint8_t *)&policy)[i]);
}

static void test_schema_kind_and_record_fail_closed(void) {
  check_bad("{\"schema_version\":2,\"kind\":\"ROUND_ROBIN\",\"key_hash\":0,"
            "\"transport_peer_id\":\"\"}", MESH_MGMT_CLIENT_CONFIG_RECORD_FAILED);
  check_bad("{\"schema_version\":1,\"kind\":\"ROUND_ROBIN\",\"key_hash\":\"0\","
            "\"transport_peer_id\":\"\"}", MESH_MGMT_CLIENT_CONFIG_RECORD_FAILED);
  check_bad("{\"schema_version\":1,\"kind\":\"ROUND_ROBIN\",\"key_hash\":0,"
            "\"transport_peer_id\":\"\",\"fallback\":true}", MESH_MGMT_CLIENT_CONFIG_RECORD_FAILED);
  check_bad("{\"schema_version\":1,\"kind\":\"ROUND_ROBIN\"}",
            MESH_MGMT_CLIENT_CONFIG_RECORD_FAILED);
  check_bad("{\"schema_version\":1,\"kind\":\"LEAST_INFLIGHT\",\"key_hash\":0,"
            "\"transport_peer_id\":\"\"}", MESH_MGMT_CLIENT_CONFIG_POLICY_INVALID);
  check_bad("{\"schema_version\":1,\"kind\":\"ROUND_ROBIN\",\"key_hash\":7,"
            "\"transport_peer_id\":\"\"}", MESH_MGMT_CLIENT_CONFIG_POLICY_INVALID);
  check_bad("{\"schema_version\":1,\"kind\":\"STRICT_KEY\",\"key_hash\":0,"
            "\"transport_peer_id\":\"22\"}", MESH_MGMT_CLIENT_CONFIG_POLICY_INVALID);
  check_bad("{\"schema_version\":1,\"kind\":\"EXPLICIT\",\"key_hash\":0,"
            "\"transport_peer_id\":\"0A\"}", MESH_MGMT_CLIENT_CONFIG_POLICY_INVALID);
  check_bad("{\"schema_version\":1,\"kind\":\"EXPLICIT\",\"key_hash\":1,"
            "\"transport_peer_id\":\"\"}", MESH_MGMT_CLIENT_CONFIG_POLICY_INVALID);
  check_bad("{\"schema_version\":1,\"kind\":\"STRICT_KEY\",\"key_hash\":true,"
            "\"transport_peer_id\":\"\"}", MESH_MGMT_CLIENT_CONFIG_RECORD_FAILED);
}

static void test_input_size_and_explicit_empty_reject(void) {
  mesh_mgmt_client_destination_policy_v2_t policy;
  char huge[MESH_MGMT_CLIENT_CONFIG_MAX_BYTES + 1u];
  memset(huge, ' ', sizeof(huge));
  memset(&policy, 0xee, sizeof(policy));
  check_equal(MESH_MGMT_CLIENT_CONFIG_INVALID_ARG,
      mesh_mgmt_client_policy_from_json_v1(NULL, 0u, &policy));
  check_equal(0u, policy.size);
  check_equal(MESH_MGMT_CLIENT_CONFIG_INVALID_ARG,
      mesh_mgmt_client_policy_from_json_v1(huge, sizeof(huge), &policy));
  check_equal(MESH_MGMT_CLIENT_CONFIG_INVALID_ARG,
      mesh_mgmt_client_policy_from_json_v1(POLICY_RR, 0u, &policy));
  check_bad("{\"schema_version\":1,\"kind\":\"EXPLICIT\",\"key_hash\":0,"
            "\"transport_peer_id\":\"\"}", MESH_MGMT_CLIENT_CONFIG_POLICY_INVALID);
}

spec("DataBind 4.3 typed ACE client policy Configurator") {
  it("maps strict JSON records into owned CNet policy and real endpoint admission") {
    test_valid_policy_records_and_owned_output();
  }
  it("fails closed on unknown kinds, schema versions, field coercion and extra fields") {
    test_schema_kind_and_record_fail_closed();
  }
  it("enforces input limits and requires a complete explicit transport identity") {
    test_input_size_and_explicit_empty_reject();
  }
}
