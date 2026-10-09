#include <tinytest.h>
#include "mesh_mgmt_agent_runtime.h"
#include "mesh_mgmt_client_config.h"
#include "mesh_mgmt_service_config.h"
#include "mesh_mgmt_test_identity.h"
#include "core/node_state.h"
#include "transfer/transfer.h"
#include <cnet/cnet.h>
#include <salts/clock.h>
#include <salts/thread.h>
#include <stdio.h>

enum { WAIT_MS = 5000, RETRY_MS = 10, MAX_RETRY_MS = 100, TEST_PEERS = 2 };
typedef struct {
  mesh_mgmt_agent_runtime_v1_t runtime;
  mesh_mgmt_agent_runtime_config_v1_t config;
  mesh_mgmt_p2p_peer_config_v1_t identity;
  runtime_callbacks_t signer_callbacks;
  p2p_runtime_config_v2_t network;
  p2p_peer_t *peer;
  uint8_t secret[P2P_KEY_SIZE], public_key[P2P_KEY_SIZE];
  unsigned established, failures, closed, admitted;
  int port, reject, random_fail;
} endpoint_t;

static void check_reentry(endpoint_t *endpoint) {
  check_equal(MESH_MGMT_AGENT_RUNTIME_INVALID_STATE,
              mesh_mgmt_agent_runtime_stop_v1(&endpoint->runtime));
  check_equal(MESH_MGMT_AGENT_RUNTIME_INVALID_STATE,
              mesh_mgmt_agent_runtime_destroy_v2(&endpoint->runtime));
}
static int event(void *context, p2p_peer_t *peer, const uint8_t remote[P2P_KEY_SIZE],
                 const mesh_mgmt_dispatch_event_v1_t *message) {
  endpoint_t *endpoint = context;
  check_reentry(endpoint);
  check_not_null(remote);
  if (message->type == MESH_MGMT_DISPATCH_EVENT_SESSION_ESTABLISHED) {
    endpoint->peer = peer;
    endpoint->established++;
  }
  return 0;
}
static int admit(void *context, p2p_peer_t *peer, const uint8_t remote[P2P_KEY_SIZE],
                 const mesh_mgmt_dispatch_event_v1_t *message) {
  endpoint_t *endpoint = context;
  check_reentry(endpoint);
  check_not_null(peer); check_not_null(remote); check_not_null(message);
  endpoint->admitted++;
  return endpoint->reject ? -1 : 0;
}
static void closed(void *context, p2p_peer_t *peer, const uint8_t remote[P2P_KEY_SIZE],
                   mesh_mgmt_agent_router_close_reason_t reason) {
  endpoint_t *endpoint = context;
  (void)remote; (void)reason;
  check_reentry(endpoint);
  endpoint->closed++;
  if (endpoint->peer == peer) endpoint->peer = NULL;
}
static void failed(void *context, p2p_peer_t *peer,
                   mesh_mgmt_agent_router_result_t router,
                   mesh_mgmt_p2p_peer_result_t result) {
  endpoint_t *endpoint = context;
  (void)peer; (void)router; (void)result;
  endpoint->failures++;
}
static int namespace_random(void *context, uint8_t *output, size_t length) {
  endpoint_t *endpoint = context;
  check_reentry(endpoint);
  if (endpoint->random_fail) return -1;
  return runtime_random_bytes(&endpoint->signer_callbacks, output, length);
}
static void prepare(endpoint_t *endpoint, uint8_t seed) {
  uint8_t management_key[P2P_KEY_SIZE] = {0};
  endpoint->secret[0] = seed;
  management_key[0] = (uint8_t)(seed + 1u);
  endpoint->signer_callbacks.next_message_byte = seed;
  check_equal(P2P_OK, p2p_public_key_from_private_key(endpoint->secret, endpoint->public_key));
  check_equal(0, prepare_runtime_config(&endpoint->identity, NULL, NULL,
      endpoint->public_key, management_key, seed, seed, seed, seed,
      &endpoint->signer_callbacks));
  check_equal(P2P_OK, p2p_runtime_config_v2_init(&endpoint->network));
  endpoint->network.receive_buffer_bytes = 97u;
  endpoint->network.stop_timeout_ms = MAX_RETRY_MS;
  endpoint->config.listen_host = "127.0.0.1";
  endpoint->config.p2p_private_key = endpoint->secret;
  endpoint->config.max_peers = TEST_PEERS;
  endpoint->config.signer_template = &endpoint->identity.signer;
  endpoint->config.dispatch_template = &endpoint->identity.dispatch;
  endpoint->config.endpoint_capacity = TEST_PEERS;
  endpoint->config.retry_base_ms = RETRY_MS;
  endpoint->config.retry_max_ms = MAX_RETRY_MS;
  endpoint->config.connect_timeout_ms = WAIT_MS;
  endpoint->config.protocol_failure_limit = 2u;
  endpoint->config.first_endpoint_record_epoch = 1u;
  endpoint->config.first_service_record_epoch = 1u;
  endpoint->config.admit_peer = admit;
  endpoint->config.on_event = event;
  endpoint->config.on_peer_closed = closed;
  endpoint->config.on_failure = failed;
  endpoint->config.callback_context = endpoint;
  endpoint->config.random_bytes = namespace_random;
  endpoint->config.random_context = endpoint;
}
static void initialize(endpoint_t *endpoint) {
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK, mesh_mgmt_agent_runtime_init_v2(
      &endpoint->runtime, &endpoint->config, &endpoint->network));
}
static void start(endpoint_t *endpoint) {
  char ip[P2P_MAX_IP];
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK, mesh_mgmt_agent_runtime_start_v1(&endpoint->runtime));
  check_equal(P2P_OK, p2p_node_get_listen_address_v2(endpoint->runtime.node,
      ip, sizeof(ip), &endpoint->port));
  check_true(endpoint->port > 0);
}
static void poll_pair(endpoint_t *left, endpoint_t *right) {
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK, mesh_mgmt_agent_runtime_poll_v1(&left->runtime));
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK, mesh_mgmt_agent_runtime_poll_v1(&right->runtime));
  cmeta_sleep_ms(1u);
}
static void wait_established(endpoint_t *server, endpoint_t *client, unsigned count) {
  uint64_t deadline = cmeta_monotonic_ms() + WAIT_MS;
  while ((server->established < count || client->established < count) &&
         cmeta_monotonic_ms() < deadline)
    poll_pair(server, client);
  check_equal(count, server->established);
  check_equal(count, client->established);
  check_equal(0u, server->failures); check_equal(0u, client->failures);
}
static void start_pair(endpoint_t *server, endpoint_t *client) {
  mesh_mgmt_agent_bootstrap_v1_t bootstrap = {0};
  prepare(server, 17); initialize(server); start(server);
  prepare(client, 33);
  memcpy(bootstrap.transport_peer_id, server->public_key, sizeof(bootstrap.transport_peer_id));
  bootstrap.host = "127.0.0.1";
  bootstrap.port = (uint16_t)server->port;
  client->config.bootstraps = &bootstrap;
  client->config.bootstrap_count = 1u;
  initialize(client);
  client->config.bootstraps = NULL; /* Initialization copies bootstrap content. */
  memset(&client->network, 0, sizeof(client->network)); /* Network options are copied too. */
  start(client);
}
static void destroy(endpoint_t *endpoint) {
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK, mesh_mgmt_agent_runtime_destroy_v2(&endpoint->runtime));
  check_equal(MESH_MGMT_AGENT_RUNTIME_UNINITIALIZED, endpoint->runtime.state);
  check_true(endpoint->runtime.node == NULL);
  check_equal(0, endpoint->runtime.p2p_security_provider.initialized);
}
static void wait_record(endpoint_t *server, endpoint_t *client, const char *key,
                        uint8_t *frame, size_t *length) {
  uint64_t deadline = cmeta_monotonic_ms() + WAIT_MS;
  int result = P2P_ERR_NOT_FOUND;
  while (cmeta_monotonic_ms() < deadline) {
    poll_pair(server, client);
    size_t available = *length;
    result = p2p_dht_get_cached(server->runtime.node, key, frame, &available);
    if (result == P2P_OK) { *length = available; break; }
  }
  check_equal(P2P_OK, result);
}
static void test_session_records_reconnect(void) {
  endpoint_t server = {0}, client = {0};
  mesh_mgmt_endpoint_snapshot_v1_t snapshot;
  mesh_mgmt_service_publish_v1_t service = {0};
  mesh_mgmt_service_config_v1_t service_config = {0};
  static const char SERVICE_JSON[] =
      "{\"schema_version\":1,\"address_family\":4,\"octet0\":100,"
      "\"octet1\":64,\"octet2\":0,\"octet3\":2,\"port\":7878,"
      "\"dns_name\":\"node-b.mesh\"}";
  mesh_mgmt_service_record_v1_t record;
  mesh_mgmt_endpoint_publish_v1_t endpoint = {0};
  mesh_mgmt_agent_cached_endpoint_v1_t cached = {0};
  uint8_t frame[MESH_MGMT_SERVICE_FRAME_V1_MAX];
  char key[MESH_MGMT_SERVICE_DHT_KEY_V1_SIZE];
  uint64_t epoch = 0;
  size_t length = sizeof(frame), key_length = 0;
  start_pair(&server, &client);
  wait_established(&server, &client, 1u);
  check_equal(1u, server.admitted);
  check_equal(0u, client.admitted);
  check_equal(MESH_MGMT_ENDPOINT_POOL_OK, mesh_mgmt_endpoint_pool_snapshot_v1(
      &client.runtime.endpoint_pool, server.public_key, &snapshot));
  check_equal(MESH_MGMT_ENDPOINT_ACTIVE, snapshot.state);

  check_equal(MESH_MGMT_SERVICE_CONFIG_OK,
      mesh_mgmt_service_config_from_json_v1(
          SERVICE_JSON, sizeof(SERVICE_JSON) - 1u, &service_config));
  check_equal(MESH_MGMT_SERVICE_CONFIG_OK,
      mesh_mgmt_service_config_publish_view_v1(&service_config, &service));
  check_true(service.dns_name == service_config.dns_name);
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK, mesh_mgmt_agent_runtime_publish_cached_service_v1(
      &client.runtime, &service, &epoch));
  check_equal(1u, epoch);
  check_equal(MESH_MGMT_SERVICE_RECORD_OK, mesh_mgmt_service_dht_key_build_v1(
      client.identity.signer.expected_mesh_id_hash, client.identity.signer.hello.managed_node_id,
      key, sizeof(key), &key_length));
  wait_record(&server, &client, key, frame, &length);
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK, mesh_mgmt_agent_runtime_resolve_cached_service_v1(
      &server.runtime, client.identity.signer.hello.managed_node_id, TEST_NOW_MS,
      client.identity.signer.frame_ttl_ms, &record));
  check_equal("node-b.mesh", record.virtual_host);
  check_equal("100.64.0.2", record.virtual_ip);
  frame[length - 1u] ^= 1u;
  check_equal(P2P_OK, p2p_dht_put_cached(server.runtime.node, key, frame, length));
  check_equal(MESH_MGMT_AGENT_RUNTIME_SERVICE_RECORD_FAILED,
      mesh_mgmt_agent_runtime_resolve_cached_service_v1(&server.runtime,
          client.identity.signer.hello.managed_node_id, TEST_NOW_MS,
          client.identity.signer.frame_ttl_ms, &record));
  check_equal(MESH_MGMT_SERVICE_RECORD_AUTH_FAILED, server.runtime.last_service_record_result);

  p2p_disconnect_peer(client.peer);
  wait_established(&server, &client, 2u);
  check_true(server.closed > 0u && client.closed > 0u);

  endpoint.address_family = MESH_MGMT_ENDPOINT_ADDRESS_IPV4;
  endpoint.address[0] = 127; endpoint.address[3] = 1; endpoint.port = (uint16_t)client.port;
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK, mesh_mgmt_agent_runtime_publish_cached_endpoint_v1(
      &client.runtime, &endpoint, &epoch));
  check_equal(MESH_MGMT_ENDPOINT_RECORD_OK, mesh_mgmt_endpoint_dht_key_build_v1(
      client.identity.signer.expected_mesh_id_hash, client.identity.signer.hello.managed_node_id,
      key, sizeof(key), &key_length));
  length = sizeof(frame);
  wait_record(&server, &client, key, frame, &length);
  cached.mesh_id_hash = client.identity.signer.expected_mesh_id_hash;
  cached.owner_node_id = client.identity.signer.hello.managed_node_id;
  cached.certificate = client.identity.signer.hello.certificate;
  cached.certificate_len = sizeof(client.identity.signer.hello.certificate);
  cached.trusted_issuer_key = client.identity.signer.trusted_issuer_key;
  cached.now_ms = TEST_NOW_MS; cached.max_ttl_ms = client.identity.signer.frame_ttl_ms;
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_apply_cached_endpoint_v1(&server.runtime, &cached));
  check_equal(MESH_MGMT_ENDPOINT_POOL_OK, mesh_mgmt_endpoint_pool_snapshot_v1(
      &server.runtime.endpoint_pool, client.public_key, &snapshot));
  check_equal(client.port, snapshot.record.port);

  check_equal(MESH_MGMT_AGENT_RUNTIME_OK, mesh_mgmt_agent_runtime_stop_v1(&client.runtime));
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK, mesh_mgmt_agent_runtime_stop_v1(&client.runtime));
  check_equal(MESH_MGMT_AGENT_RUNTIME_INVALID_STATE, mesh_mgmt_agent_runtime_start_v1(&client.runtime));
  destroy(&client); destroy(&server);
}

static void test_explicit_client_strategy_real_noise_mmp(void) {
  endpoint_t alpha = {0}, beta = {0}, client = {0};
  mesh_mgmt_agent_bootstrap_v1_t bootstraps[2] = {{0}, {0}};
  mesh_mgmt_client_destination_policy_v2_t policy = {0};
  mesh_mgmt_endpoint_snapshot_v1_t snapshot = {0};

  prepare(&alpha, 17); initialize(&alpha); start(&alpha);
  prepare(&beta, 49); initialize(&beta); start(&beta);
  prepare(&client, 33);
  memcpy(bootstraps[0].transport_peer_id, alpha.public_key, P2P_KEY_SIZE);
  memcpy(bootstraps[1].transport_peer_id, beta.public_key, P2P_KEY_SIZE);
  bootstraps[0].host = bootstraps[1].host = "127.0.0.1";
  bootstraps[0].port = (uint16_t)alpha.port;
  bootstraps[1].port = (uint16_t)beta.port;
  client.config.bootstraps = bootstraps;
  client.config.bootstrap_count = 2u;
  initialize(&client);

  /* DataBind strict JSON parsing occurs at startup, outside CNet callbacks. */
  static const char digits[] = "0123456789abcdef";
  char peer_hex[P2P_KEY_SIZE * 2u + 1u] = {0};
  char json[256] = {0};
  for (size_t i = 0u; i < P2P_KEY_SIZE; i++) {
    peer_hex[i * 2u] = digits[beta.public_key[i] >> 4u];
    peer_hex[i * 2u + 1u] = digits[beta.public_key[i] & 15u];
  }
  int n = snprintf(json, sizeof(json),
      "{\"schema_version\":1,\"kind\":\"EXPLICIT\",\"key_hash\":0,"
      "\"transport_peer_id\":\"%s\"}", peer_hex);
  check_true(n > 0 && (size_t)n < sizeof(json));
  check_equal(MESH_MGMT_CLIENT_CONFIG_OK,
      mesh_mgmt_client_policy_from_json_v1(json, (size_t)n, &policy));
  check_equal(CNET_DESTINATION_EXPLICIT, policy.kind);
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_set_client_policy_v2(&client.runtime, &policy));
  check_equal(MESH_MGMT_AGENT_RUNTIME_INVALID_STATE,
      mesh_mgmt_agent_runtime_set_client_policy_v2(&client.runtime, &policy));
  client.config.bootstraps = NULL;
  client.config.bootstrap_count = 0u;
  start(&client);

  uint64_t deadline = cmeta_monotonic_ms() + WAIT_MS;
  while ((beta.established == 0u || client.established == 0u) &&
         cmeta_monotonic_ms() < deadline) {
    check_equal(MESH_MGMT_AGENT_RUNTIME_OK, mesh_mgmt_agent_runtime_poll_v1(&alpha.runtime));
    check_equal(MESH_MGMT_AGENT_RUNTIME_OK, mesh_mgmt_agent_runtime_poll_v1(&beta.runtime));
    check_equal(MESH_MGMT_AGENT_RUNTIME_OK, mesh_mgmt_agent_runtime_poll_v1(&client.runtime));
    cmeta_sleep_ms(1u);
  }
  check_equal(1u, beta.established);
  check_equal(1u, client.established);
  check_equal(0u, alpha.established);
  check_equal(0u, alpha.admitted);
  check_equal(0u, client.failures);
  check_equal(MESH_MGMT_ENDPOINT_POOL_OK,
      mesh_mgmt_endpoint_pool_snapshot_v1(
          &client.runtime.endpoint_pool, alpha.public_key, &snapshot));
  check_equal(MESH_MGMT_ENDPOINT_IDLE, snapshot.state);
  check_equal(MESH_MGMT_ENDPOINT_POOL_OK,
      mesh_mgmt_endpoint_pool_snapshot_v1(
          &client.runtime.endpoint_pool, beta.public_key, &snapshot));
  check_equal(MESH_MGMT_ENDPOINT_ACTIVE, snapshot.state);

  /* Application MMP readiness, not TCP CONNECTED, was published by router.
   * The other pinned authority stayed uncontacted throughout real CNet turns. */
  check_equal(MESH_MGMT_AGENT_RUNTIME_INVALID_STATE,
      mesh_mgmt_agent_runtime_set_client_policy_v2(&client.runtime, &policy));
  destroy(&client); destroy(&beta); destroy(&alpha);
}

static void test_external_progress_reentry(void) {
  endpoint_t server = {0}, client = {0};
  start_pair(&server, &client);
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK, mesh_mgmt_agent_runtime_poll_v1(&client.runtime));
  uint64_t deadline = cmeta_monotonic_ms() + WAIT_MS;
  while ((server.established == 0u || client.established == 0u) &&
         cmeta_monotonic_ms() < deadline) {
    /* Exercise router callback guards with runtime.in_api clear, as when
     * a shared owner advances its borrowed P2P node. No mesh is emulated. */
    check_equal(P2P_OK, p2p_poll(server.runtime.node));
    check_equal(P2P_OK, p2p_poll(client.runtime.node));
    cmeta_sleep_ms(1u);
  }
  check_equal(1u, server.established); check_equal(1u, client.established);
  destroy(&client); destroy(&server);
}
static void test_membership_rejection(void) {
  endpoint_t server = {0}, client = {0};
  server.reject = 1;
  start_pair(&server, &client);
  uint64_t deadline = cmeta_monotonic_ms() + WAIT_MS;
  while (server.failures == 0u && cmeta_monotonic_ms() < deadline)
    poll_pair(&server, &client);
  check_true(server.admitted > 0u && server.failures > 0u);
  check_equal(0u, server.established);
  check_equal(0u, mesh_mgmt_agent_router_active_peers_v1(&server.runtime.router));
  destroy(&client); destroy(&server);
}
static void test_expiry_clock_domains(void) {
  endpoint_t endpoint = {0};
  mesh_mgmt_endpoint_record_v1_t record = {0};
  mesh_mgmt_endpoint_snapshot_v1_t snapshot;
  const uint64_t real_now = UINT64_C(1700000000000), mono_now = 1000u;
  prepare(&endpoint, 17); initialize(&endpoint);
  record.transport_peer_id[0] = 33;
  memcpy(record.host, "127.0.0.1", sizeof("127.0.0.1"));
  record.port = 12345;
  record.source = MESH_MGMT_ENDPOINT_SOURCE_VERIFIED_RECORD;
  record.record_epoch = 1;
  record.expires_at_ms = real_now + MAX_RETRY_MS;
  mesh_mgmt_endpoint_pool_v1_t *pool = &endpoint.runtime.endpoint_pool;
  check_equal(MESH_MGMT_ENDPOINT_POOL_RESOURCE_EXHAUSTED,
      mesh_mgmt_endpoint_pool_apply_verified_v2(pool, &record, real_now, UINT64_MAX));
  check_equal(0u, pool->count);
  check_equal(MESH_MGMT_ENDPOINT_POOL_OK,
      mesh_mgmt_endpoint_pool_apply_verified_v2(pool, &record, real_now, mono_now));
  check_equal(MESH_MGMT_ENDPOINT_POOL_OK,
      mesh_mgmt_endpoint_pool_mark_authenticated_v1(pool, record.transport_peer_id,
                                                    mono_now + MAX_RETRY_MS - 1u));
  check_equal(MESH_MGMT_ENDPOINT_POOL_OK,
      mesh_mgmt_endpoint_pool_apply_verified_v2(pool, &record, real_now, mono_now + MAX_RETRY_MS));
  check_equal(MESH_MGMT_ENDPOINT_POOL_EXPIRED,
      mesh_mgmt_endpoint_pool_mark_authenticated_v1(pool, record.transport_peer_id,
                                                    mono_now + MAX_RETRY_MS));
  check_equal(MESH_MGMT_ENDPOINT_POOL_OK,
      mesh_mgmt_endpoint_pool_snapshot_v1(pool, record.transport_peer_id, &snapshot));
  check_equal(record.expires_at_ms, snapshot.record.expires_at_ms);
  check_equal(MESH_MGMT_ENDPOINT_POOL_OK, mesh_mgmt_endpoint_pool_start_v1(pool));
  check_equal(MESH_MGMT_ENDPOINT_POOL_OK, mesh_mgmt_endpoint_pool_tick_v1(pool, mono_now + MAX_RETRY_MS));
  check_equal(MESH_MGMT_ENDPOINT_POOL_EXPIRED, mesh_mgmt_endpoint_pool_mark_failed_v1(
      pool, record.transport_peer_id, MESH_MGMT_ENDPOINT_FAILURE_TRANSPORT, mono_now + MAX_RETRY_MS));
  check_equal(MESH_MGMT_ENDPOINT_POOL_OK,
      mesh_mgmt_endpoint_pool_snapshot_v1(pool, record.transport_peer_id, &snapshot));
  check_equal(MESH_MGMT_ENDPOINT_EXPIRED, snapshot.state);
  record.record_epoch++;
  check_equal(MESH_MGMT_ENDPOINT_POOL_OK,
      mesh_mgmt_endpoint_pool_apply_verified_v1(pool, &record, real_now));
  check_equal(MESH_MGMT_ENDPOINT_POOL_OK,
      mesh_mgmt_endpoint_pool_mark_authenticated_v1(pool, record.transport_peer_id,
                                                    record.expires_at_ms - 1u));
  check_equal(MESH_MGMT_ENDPOINT_POOL_EXPIRED,
      mesh_mgmt_endpoint_pool_mark_authenticated_v1(pool, record.transport_peer_id,
                                                    record.expires_at_ms));
  destroy(&endpoint);
}
static void test_init_failure_and_ready_stop(void) {
  endpoint_t endpoint = {0};
  prepare(&endpoint, 17);
  endpoint.random_fail = 1;
  check_equal(MESH_MGMT_AGENT_RUNTIME_ROUTER_FAILED, mesh_mgmt_agent_runtime_init_v2(
      &endpoint.runtime, &endpoint.config, &endpoint.network));
  check_equal(MESH_MGMT_AGENT_RUNTIME_UNINITIALIZED, endpoint.runtime.state);
  check_true(endpoint.runtime.node == NULL);
  check_equal(0, endpoint.runtime.p2p_security_provider.initialized);
  endpoint.random_fail = 0;
  initialize(&endpoint);
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK, mesh_mgmt_agent_runtime_stop_v1(&endpoint.runtime));
  check_equal(MESH_MGMT_AGENT_RUNTIME_STOPPED, endpoint.runtime.state);
  destroy(&endpoint);
}
static void test_invalid_start(void) {
  endpoint_t endpoint = {0};
  prepare(&endpoint, 17);
  endpoint.network.connection_capacity = 0;
  initialize(&endpoint);
  check_equal(MESH_MGMT_AGENT_RUNTIME_P2P_FAILED, mesh_mgmt_agent_runtime_start_v1(&endpoint.runtime));
  check_equal(P2P_ERR_INVALID_ARG, endpoint.runtime.last_p2p_result);
  check_equal(MESH_MGMT_AGENT_RUNTIME_STOPPED, endpoint.runtime.state);
  check_true(endpoint.runtime.node == NULL);
  check_equal(MESH_MGMT_AGENT_RUNTIME_INVALID_STATE, mesh_mgmt_agent_runtime_start_v1(&endpoint.runtime));
  destroy(&endpoint);
}
static void test_lease_retention(void) {
  endpoint_t endpoint = {0};
  prepare(&endpoint, 17); initialize(&endpoint);
  p2p_node_t *node = endpoint.runtime.node;
  p2p_transfer_t *transfer = p2p_transfer_create(node->transfers, P2P_TRANSFER_DIR_DOWNLOAD);
  check_not_null(transfer);
  p2p_transfer_t *lease = p2p_transfer_find_by_id(node->transfers, transfer->id);
  check_not_null(lease);
  check_equal(MESH_MGMT_AGENT_RUNTIME_P2P_FAILED, mesh_mgmt_agent_runtime_destroy_v2(&endpoint.runtime));
  check_equal(P2P_ERR_INVALID_STATE, endpoint.runtime.last_p2p_result);
  check_equal(MESH_MGMT_AGENT_RUNTIME_STOPPING, endpoint.runtime.state);
  check_true(endpoint.runtime.node == node);
  check_true(endpoint.runtime.p2p_security_provider.initialized);
  check_not_null(endpoint.runtime.router.slots.data);
  check_not_null(endpoint.runtime.endpoint_pool.entries.data);
  p2p_transfer_release(lease);
  destroy(&endpoint);
}
#ifdef MESH_MGMT_RUNTIME_TEST_WRAP
static int timeout_stop, fail_destroy;
int __real_cnet_client_stop(cnet_client *, uint32_t);
int __wrap_cnet_client_stop(cnet_client *client, uint32_t timeout_ms) {
  if (timeout_stop) return SALTS_ETIMEDOUT;
  return __real_cnet_client_stop(client, timeout_ms);
}
int __real_p2p_destroy_v2(p2p_node_t *);
int __wrap_p2p_destroy_v2(p2p_node_t *node) {
  if (fail_destroy) return P2P_ERR_TIMEOUT;
  return __real_p2p_destroy_v2(node);
}
static void test_drain_retention(void) {
  endpoint_t server = {0}, client = {0};
  start_pair(&server, &client);
  wait_established(&server, &client, 1u);
  p2p_node_t *node = client.runtime.node;
  void *slots = client.runtime.router.slots.data;
  timeout_stop = 1;
  check_equal(MESH_MGMT_AGENT_RUNTIME_P2P_FAILED, mesh_mgmt_agent_runtime_stop_v1(&client.runtime));
  check_equal(P2P_ERR_TIMEOUT, client.runtime.last_p2p_result);
  check_equal(MESH_MGMT_AGENT_RUNTIME_STOPPING, client.runtime.state);
  check_true(client.runtime.node == node && client.runtime.owns_node);
  check_true(client.runtime.router.slots.data == slots);
  check_true(client.runtime.p2p_security_provider.initialized);
  check_equal(MESH_MGMT_AGENT_RUNTIME_INVALID_STATE, mesh_mgmt_agent_runtime_poll_v1(&client.runtime));
  mesh_mgmt_agent_runtime_destroy_v1(&client.runtime);
  check_true(client.runtime.node == node && client.runtime.p2p_security_provider.initialized);
  check_equal(P2P_ERR_TIMEOUT, client.runtime.last_p2p_result);
  timeout_stop = 0;
  destroy(&client); destroy(&server);
}
static void test_partial_init_retention(void) {
  endpoint_t endpoint = {0};
  prepare(&endpoint, 17);
  mesh_mgmt_agent_bootstrap_v1_t invalid_bootstrap = {0};
  invalid_bootstrap.transport_peer_id[0] = 33;
  invalid_bootstrap.host = "127.0.0.1";
  endpoint.config.bootstraps = &invalid_bootstrap;
  endpoint.config.bootstrap_count = 1u;
  fail_destroy = 1;
  check_equal(MESH_MGMT_AGENT_RUNTIME_P2P_FAILED, mesh_mgmt_agent_runtime_init_v2(
      &endpoint.runtime, &endpoint.config, &endpoint.network));
  check_equal(P2P_ERR_TIMEOUT, endpoint.runtime.last_p2p_result);
  check_equal(MESH_MGMT_ENDPOINT_POOL_INVALID_ARG, endpoint.runtime.last_endpoint_result);
  check_equal(MESH_MGMT_AGENT_RUNTIME_STOPPING, endpoint.runtime.state);
  check_not_null(endpoint.runtime.node);
  check_not_null(endpoint.runtime.router.slots.data);
  check_true(endpoint.runtime.p2p_security_provider.initialized);
  check_not_null(endpoint.runtime.endpoint_pool.entries.data);
  check_equal(MESH_MGMT_ENDPOINT_PUBLISHER_READY, endpoint.runtime.endpoint_publisher.state);
  check_equal(MESH_MGMT_AGENT_RUNTIME_INVALID_STATE, mesh_mgmt_agent_runtime_init_v2(
      &endpoint.runtime, &endpoint.config, &endpoint.network));
  fail_destroy = 0;
  destroy(&endpoint);
}
#endif
static void test_listener_conflict(int timeout) {
  endpoint_t server = {0}, client = {0};
  prepare(&server, 17); initialize(&server); start(&server);
  prepare(&client, 33); client.config.listen_port = (uint16_t)server.port;
  initialize(&client);
#ifdef MESH_MGMT_RUNTIME_TEST_WRAP
  timeout_stop = timeout;
#endif
  check_equal(MESH_MGMT_AGENT_RUNTIME_P2P_FAILED, mesh_mgmt_agent_runtime_start_v1(&client.runtime));
  check_equal(timeout ? P2P_ERR_TIMEOUT : P2P_ERR_NETWORK, client.runtime.last_p2p_result);
  check_equal(timeout ? MESH_MGMT_AGENT_RUNTIME_STOPPING : MESH_MGMT_AGENT_RUNTIME_STOPPED,
              client.runtime.state);
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK, mesh_mgmt_agent_runtime_poll_v1(&server.runtime));
#ifdef MESH_MGMT_RUNTIME_TEST_WRAP
  timeout_stop = 0;
#endif
  destroy(&client); destroy(&server);
}
spec("Dedicated management runtime on CNet") {
  it("uses configured CNet EXPLICIT Client strategy for real Noise and MMP admission") {
    test_explicit_client_strategy_real_noise_mmp();
  }
  it("authenticates real MMP sessions, publishes signed discovery, and reconnects") { test_session_records_reconnect(); }
  it("rejects lifecycle reentry when the public node advances outside runtime polling") { test_external_progress_reentry(); }
  it("rejects authenticated transport peers denied by management membership") { test_membership_rejection(); }
  it("converts realtime expiry once without overflow or duplicate lifetime extension") { test_expiry_clock_domains(); }
  it("cleans failed initialization and stops a ready runtime") { test_init_failure_and_ready_stop(); }
  it("makes invalid startup terminal and preserves the P2P cause") { test_invalid_start(); }
  it("retains node and all borrowed contexts until a transfer lease is released") { test_lease_retention(); }
  it("keeps an existing listener intact after address conflict") { test_listener_conflict(0); }
#ifdef MESH_MGMT_RUNTIME_TEST_WRAP
  it("retains composition storage on drain timeout, including the void compatibility wrapper") { test_drain_retention(); }
  it("retains partial initialization when checked destruction fails") { test_partial_init_retention(); }
  it("reports cleanup timeout after bind failure and supports retry") { test_listener_conflict(1); }
#endif
}
