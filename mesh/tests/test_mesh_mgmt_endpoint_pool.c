#include <tinytest.h>

#include "mesh_mgmt_endpoint_pool.h"

#include <string.h>

typedef struct {
  p2p_node_t *expected_node;
  const char *expected_host;
  uint16_t expected_port;
  int connect_result;
  size_t connect_calls;
  int random_result;
  uint32_t random_value;
} endpoint_callbacks_t;

static int fake_connect(void *context, p2p_node_t *node, const char *host, uint16_t port) {
  endpoint_callbacks_t *callbacks = (endpoint_callbacks_t *)context;

  if (!callbacks || node != callbacks->expected_node ||
      strcmp(host, callbacks->expected_host) != 0 || port != callbacks->expected_port) {
    return P2P_ERR_INVALID_ARG;
  }
  callbacks->connect_calls++;
  return callbacks->connect_result;
}

static int fake_random(void *context, uint8_t *output, size_t output_len) {
  endpoint_callbacks_t *callbacks = (endpoint_callbacks_t *)context;

  if (!callbacks || !output || output_len != sizeof(callbacks->random_value))
    return -1;
  if (callbacks->random_result != 0)
    return callbacks->random_result;
  memcpy(output, &callbacks->random_value, output_len);
  return 0;
}

static mesh_mgmt_endpoint_pool_config_v1_t pool_config(endpoint_callbacks_t *callbacks,
                                                       size_t capacity) {
  mesh_mgmt_endpoint_pool_config_v1_t config;

  memset(&config, 0, sizeof(config));
  config.node = callbacks->expected_node;
  config.capacity = capacity;
  config.retry_base_ms = 100u;
  config.retry_max_ms = 800u;
  config.connect_timeout_ms = 50u;
  config.protocol_failure_limit = 2u;
  config.connect_peer = fake_connect;
  config.random_bytes = fake_random;
  config.callback_context = callbacks;
  return config;
}

static mesh_mgmt_endpoint_record_v1_t verified_record(const uint8_t peer_id[P2P_KEY_SIZE],
                                                      const char *host, uint16_t port,
                                                      uint64_t epoch, uint64_t expires_at_ms) {
  mesh_mgmt_endpoint_record_v1_t record;

  memset(&record, 0, sizeof(record));
  memcpy(record.transport_peer_id, peer_id, P2P_KEY_SIZE);
  memcpy(record.host, host, strlen(host) + 1u);
  record.port = port;
  record.source = MESH_MGMT_ENDPOINT_SOURCE_VERIFIED_RECORD;
  record.record_epoch = epoch;
  record.expires_at_ms = expires_at_ms;
  return record;
}

static void test_static_authority_and_verified_record_ordering(void) {
  static const uint8_t PEER1[P2P_KEY_SIZE] = {1u};
  static const uint8_t PEER2[P2P_KEY_SIZE] = {2u};
  static const uint8_t PEER3[P2P_KEY_SIZE] = {3u};
  endpoint_callbacks_t callbacks;
  mesh_mgmt_endpoint_pool_config_v1_t config;
  mesh_mgmt_endpoint_pool_v1_t pool;
  mesh_mgmt_endpoint_record_v1_t record;
  mesh_mgmt_endpoint_snapshot_v1_t snapshot;

  memset(&callbacks, 0, sizeof(callbacks));
  memset(&pool, 0, sizeof(pool));
  callbacks.expected_node = (p2p_node_t *)&callbacks;
  callbacks.expected_host = "eu.example.net";
  callbacks.expected_port = 8443u;
  callbacks.connect_result = P2P_OK;
  config = pool_config(&callbacks, 2u);

  check_int_eq(mesh_mgmt_endpoint_pool_init_v1(&pool, &config), MESH_MGMT_ENDPOINT_POOL_OK);
  check_int_eq(mesh_mgmt_endpoint_pool_add_static_v1(&pool, PEER1, "eu.example.net", 8443u),
               MESH_MGMT_ENDPOINT_POOL_OK);
  check_int_eq(mesh_mgmt_endpoint_pool_add_static_v1(&pool, PEER1, "eu.example.net", 8443u),
               MESH_MGMT_ENDPOINT_POOL_OK);
  check_size_eq(pool.count, 1u);
  check_int_eq(mesh_mgmt_endpoint_pool_add_static_v1(&pool, PEER2, "eu.example.net", 8443u),
               MESH_MGMT_ENDPOINT_POOL_CONFLICT);

  record = verified_record(PEER1, "other.example.net", 8443u, 1u, 2000u);
  check_int_eq(mesh_mgmt_endpoint_pool_apply_verified_v1(&pool, &record, 1000u),
               MESH_MGMT_ENDPOINT_POOL_CONFLICT);
  record = verified_record(PEER2, "bj.example.net", 9443u, 2u, 2000u);
  check_int_eq(mesh_mgmt_endpoint_pool_apply_verified_v1(&pool, &record, 2000u),
               MESH_MGMT_ENDPOINT_POOL_EXPIRED);
  check_int_eq(mesh_mgmt_endpoint_pool_apply_verified_v1(&pool, &record, 1000u),
               MESH_MGMT_ENDPOINT_POOL_OK);
  record.record_epoch = 1u;
  check_int_eq(mesh_mgmt_endpoint_pool_apply_verified_v1(&pool, &record, 1000u),
               MESH_MGMT_ENDPOINT_POOL_STALE);
  record.record_epoch = 2u;
  memcpy(record.host, "sh.example.net", sizeof("sh.example.net"));
  check_int_eq(mesh_mgmt_endpoint_pool_apply_verified_v1(&pool, &record, 1000u),
               MESH_MGMT_ENDPOINT_POOL_CONFLICT);
  record = verified_record(PEER3, "sh.example.net", 10443u, 1u, 2000u);
  check_int_eq(mesh_mgmt_endpoint_pool_apply_verified_v1(&pool, &record, 1000u),
               MESH_MGMT_ENDPOINT_POOL_RESOURCE_EXHAUSTED);

  check_int_eq(mesh_mgmt_endpoint_pool_snapshot_v1(&pool, PEER2, &snapshot),
               MESH_MGMT_ENDPOINT_POOL_OK);
  check_int_eq(snapshot.record.source, MESH_MGMT_ENDPOINT_SOURCE_VERIFIED_RECORD);
  check_uint_eq(snapshot.record.record_epoch, 2u);
  check_str_eq(snapshot.record.host, "bj.example.net");
  mesh_mgmt_endpoint_pool_destroy_v1(&pool);
}

static void test_dial_timeout_backoff_authentication_and_quarantine(void) {
  static const uint8_t PEER[P2P_KEY_SIZE] = {7u};
  endpoint_callbacks_t callbacks;
  mesh_mgmt_endpoint_pool_config_v1_t config;
  mesh_mgmt_endpoint_pool_v1_t pool;
  mesh_mgmt_endpoint_snapshot_v1_t snapshot;

  memset(&callbacks, 0, sizeof(callbacks));
  memset(&pool, 0, sizeof(pool));
  callbacks.expected_node = (p2p_node_t *)&callbacks;
  callbacks.expected_host = "eu.example.net";
  callbacks.expected_port = 8443u;
  callbacks.connect_result = P2P_OK;
  config = pool_config(&callbacks, 1u);

  check_int_eq(mesh_mgmt_endpoint_pool_init_v1(&pool, &config), MESH_MGMT_ENDPOINT_POOL_OK);
  check_int_eq(mesh_mgmt_endpoint_pool_add_static_v1(&pool, PEER, callbacks.expected_host,
                                                     callbacks.expected_port),
               MESH_MGMT_ENDPOINT_POOL_OK);
  check_int_eq(mesh_mgmt_endpoint_pool_start_v1(&pool), MESH_MGMT_ENDPOINT_POOL_OK);
  check_int_eq(mesh_mgmt_endpoint_pool_tick_v1(&pool, 1000u), MESH_MGMT_ENDPOINT_POOL_OK);
  check_size_eq(callbacks.connect_calls, 1u);
  check_int_eq(mesh_mgmt_endpoint_pool_snapshot_v1(&pool, PEER, &snapshot),
               MESH_MGMT_ENDPOINT_POOL_OK);
  check_int_eq(snapshot.state, MESH_MGMT_ENDPOINT_DIALING);
  check_uint_eq(snapshot.connect_deadline_ms, 1050u);

  check_int_eq(mesh_mgmt_endpoint_pool_tick_v1(&pool, 1049u), MESH_MGMT_ENDPOINT_POOL_OK);
  check_int_eq(mesh_mgmt_endpoint_pool_tick_v1(&pool, 1050u), MESH_MGMT_ENDPOINT_POOL_OK);
  check_int_eq(mesh_mgmt_endpoint_pool_snapshot_v1(&pool, PEER, &snapshot),
               MESH_MGMT_ENDPOINT_POOL_OK);
  check_int_eq(snapshot.state, MESH_MGMT_ENDPOINT_BACKOFF);
  check_uint_eq(snapshot.next_attempt_ms, 1150u);
  check_uint_eq(snapshot.transport_failures, 1u);
  check_int_eq(mesh_mgmt_endpoint_pool_tick_v1(&pool, 1149u), MESH_MGMT_ENDPOINT_POOL_OK);
  check_size_eq(callbacks.connect_calls, 1u);
  check_int_eq(mesh_mgmt_endpoint_pool_tick_v1(&pool, 1150u), MESH_MGMT_ENDPOINT_POOL_OK);
  check_size_eq(callbacks.connect_calls, 2u);

  check_int_eq(mesh_mgmt_endpoint_pool_mark_authenticated_v1(&pool, PEER, 1151u),
               MESH_MGMT_ENDPOINT_POOL_OK);
  check_int_eq(mesh_mgmt_endpoint_pool_snapshot_v1(&pool, PEER, &snapshot),
               MESH_MGMT_ENDPOINT_POOL_OK);
  check_int_eq(snapshot.state, MESH_MGMT_ENDPOINT_ACTIVE);
  check_uint_eq(snapshot.transport_failures, 0u);
  check_uint_eq(snapshot.protocol_failures, 0u);

  check_int_eq(mesh_mgmt_endpoint_pool_mark_failed_v1(&pool, PEER,
                                                      MESH_MGMT_ENDPOINT_FAILURE_PROTOCOL, 1200u),
               MESH_MGMT_ENDPOINT_POOL_OK);
  check_int_eq(mesh_mgmt_endpoint_pool_snapshot_v1(&pool, PEER, &snapshot),
               MESH_MGMT_ENDPOINT_POOL_OK);
  check_int_eq(snapshot.state, MESH_MGMT_ENDPOINT_BACKOFF);
  check_uint_eq(snapshot.protocol_failures, 1u);
  check_int_eq(mesh_mgmt_endpoint_pool_tick_v1(&pool, snapshot.next_attempt_ms),
               MESH_MGMT_ENDPOINT_POOL_OK);
  check_size_eq(callbacks.connect_calls, 3u);
  check_int_eq(mesh_mgmt_endpoint_pool_mark_failed_v1(
                   &pool, PEER, MESH_MGMT_ENDPOINT_FAILURE_PROTOCOL, snapshot.next_attempt_ms + 1u),
               MESH_MGMT_ENDPOINT_POOL_OK);
  check_int_eq(mesh_mgmt_endpoint_pool_snapshot_v1(&pool, PEER, &snapshot),
               MESH_MGMT_ENDPOINT_POOL_OK);
  check_int_eq(snapshot.state, MESH_MGMT_ENDPOINT_QUARANTINED);
  check_uint_eq(snapshot.protocol_failures, 2u);
  check_int_eq(mesh_mgmt_endpoint_pool_tick_v1(&pool, 10000u), MESH_MGMT_ENDPOINT_POOL_OK);
  check_size_eq(callbacks.connect_calls, 3u);

  check_int_eq(mesh_mgmt_endpoint_pool_reset_v1(&pool, PEER), MESH_MGMT_ENDPOINT_POOL_OK);
  check_int_eq(mesh_mgmt_endpoint_pool_tick_v1(&pool, 10001u), MESH_MGMT_ENDPOINT_POOL_OK);
  check_size_eq(callbacks.connect_calls, 4u);
  check_int_eq(mesh_mgmt_endpoint_pool_mark_authenticated_v1(&pool, PEER, 10002u),
               MESH_MGMT_ENDPOINT_POOL_OK);
  callbacks.random_result = -1;
  check_int_eq(mesh_mgmt_endpoint_pool_mark_failed_v1(&pool, PEER,
                                                      MESH_MGMT_ENDPOINT_FAILURE_TRANSPORT, 10003u),
               MESH_MGMT_ENDPOINT_POOL_RANDOM_FAILED);
  check_int_eq(mesh_mgmt_endpoint_pool_snapshot_v1(&pool, PEER, &snapshot),
               MESH_MGMT_ENDPOINT_POOL_OK);
  check_int_eq(snapshot.state, MESH_MGMT_ENDPOINT_QUARANTINED);

  mesh_mgmt_endpoint_pool_stop_v1(&pool);
  mesh_mgmt_endpoint_pool_destroy_v1(&pool);
}

static void test_verified_expiry_prevents_redial_after_active_close(void) {
  static const uint8_t PEER[P2P_KEY_SIZE] = {9u};
  endpoint_callbacks_t callbacks;
  mesh_mgmt_endpoint_pool_config_v1_t config;
  mesh_mgmt_endpoint_pool_v1_t pool;
  mesh_mgmt_endpoint_record_v1_t record;
  mesh_mgmt_endpoint_snapshot_v1_t snapshot;

  memset(&callbacks, 0, sizeof(callbacks));
  memset(&pool, 0, sizeof(pool));
  callbacks.expected_node = (p2p_node_t *)&callbacks;
  callbacks.expected_host = "bj.example.net";
  callbacks.expected_port = 8443u;
  callbacks.connect_result = P2P_OK;
  config = pool_config(&callbacks, 1u);
  record = verified_record(PEER, callbacks.expected_host, callbacks.expected_port, 1u, 2000u);

  check_int_eq(mesh_mgmt_endpoint_pool_init_v1(&pool, &config), MESH_MGMT_ENDPOINT_POOL_OK);
  check_int_eq(mesh_mgmt_endpoint_pool_apply_verified_v1(&pool, &record, 1000u),
               MESH_MGMT_ENDPOINT_POOL_OK);
  check_int_eq(mesh_mgmt_endpoint_pool_start_v1(&pool), MESH_MGMT_ENDPOINT_POOL_OK);
  check_int_eq(mesh_mgmt_endpoint_pool_tick_v1(&pool, 1000u), MESH_MGMT_ENDPOINT_POOL_OK);
  check_int_eq(mesh_mgmt_endpoint_pool_mark_authenticated_v1(&pool, PEER, 1001u),
               MESH_MGMT_ENDPOINT_POOL_OK);
  check_int_eq(mesh_mgmt_endpoint_pool_tick_v1(&pool, 2000u), MESH_MGMT_ENDPOINT_POOL_OK);
  check_int_eq(mesh_mgmt_endpoint_pool_snapshot_v1(&pool, PEER, &snapshot),
               MESH_MGMT_ENDPOINT_POOL_OK);
  check_int_eq(snapshot.state, MESH_MGMT_ENDPOINT_ACTIVE);
  check_int_eq(mesh_mgmt_endpoint_pool_mark_failed_v1(&pool, PEER,
                                                      MESH_MGMT_ENDPOINT_FAILURE_TRANSPORT, 2001u),
               MESH_MGMT_ENDPOINT_POOL_EXPIRED);
  check_int_eq(mesh_mgmt_endpoint_pool_snapshot_v1(&pool, PEER, &snapshot),
               MESH_MGMT_ENDPOINT_POOL_OK);
  check_int_eq(snapshot.state, MESH_MGMT_ENDPOINT_EXPIRED);
  check_int_eq(mesh_mgmt_endpoint_pool_tick_v1(&pool, 3000u), MESH_MGMT_ENDPOINT_POOL_OK);
  check_size_eq(callbacks.connect_calls, 1u);

  mesh_mgmt_endpoint_pool_stop_v1(&pool);
  mesh_mgmt_endpoint_pool_destroy_v1(&pool);
}

spec("mesh management endpoint pool") {
  describe("trusted discovery and reconnect policy") {
    it("keeps static authority above verified record updates") {
      test_static_authority_and_verified_record_ordering();
    }
    it("uses bounded timeout, backoff and protocol quarantine") {
      test_dial_timeout_backoff_authentication_and_quarantine();
    }
    it("does not redial an expired verified endpoint after close") {
      test_verified_expiry_prevents_redial_after_active_close();
    }
  }
}
