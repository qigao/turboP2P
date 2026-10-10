#include <tinytest.h>
#include "mesh_mgmt_agent_runtime.h"
#include "mesh_mgmt_client_config.h"
#include "mesh_mgmt_service_config.h"
#include "mesh_mgmt_test_identity.h"
#include "mesh_mgmt_execution_wire.h"
#include "core/node_state.h"
#include "core/peer_cnet.h"
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
/* Three independent Owner progresses: no application retry or background
 * polling is introduced by the test or the signed ClientPool Runtime. */
static void poll_three(endpoint_t *server, endpoint_t *first, endpoint_t *second) {
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_poll_v1(&server->runtime));
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_poll_v1(&first->runtime));
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_poll_v1(&second->runtime));
  cmeta_sleep_ms(1u);
}

static void start_signed_client(endpoint_t *client, const endpoint_t *server,
                                uint8_t seed) {
  mesh_mgmt_agent_bootstrap_v1_t bootstrap = {0};
  prepare(client, seed);
  memcpy(bootstrap.transport_peer_id, server->public_key,
         sizeof(bootstrap.transport_peer_id));
  bootstrap.host = "127.0.0.1";
  bootstrap.port = (uint16_t)server->port;
  client->config.bootstraps = &bootstrap;
  client->config.bootstrap_count = 1u;
  initialize(client);
  client->config.bootstraps = NULL;
  client->config.bootstrap_count = 0u;
  start(client);
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

/* These READY facts originate from real signed MMP SESSION_ESTABLISHED,
 * not raw CNet CONNECTED, a fabricated event or a guessed Pool key.
 * Reconnect changes the canonical Router connection_id, so old proof
 * generations cannot be promoted to ClientPool READY after a new session. */
static void test_router_signed_pool_ready_capability(void) {
  endpoint_t server = {0}, client = {0};
  mesh_mgmt_agent_router_ready_v1_t proof = {0}, second = {0};
  mesh_mgmt_agent_router_physical_ready_v1_t same = {0};
  p2p_cnet_managed_binding_v1_t inbound = {0}, next_inbound = {0};
  cnet_managed_connection first_managed = {0};
  cnet_manager *physical_manager = NULL;
  uint8_t first_connection_id[16] = {0};
  uint8_t wrong_id[P2P_KEY_SIZE] = {0};
  uint8_t wrong_node_id[32] = {0};

  start_pair(&server, &client);
  wait_established(&server, &client, 1u);
  check_not_null(server.peer);
  check_equal(MESH_MGMT_AGENT_ROUTER_OK,
      mesh_mgmt_agent_router_ready_session_v1(
          &server.runtime.router, server.peer,
          client.public_key,
          client.identity.signer.hello.managed_node_id,
          NULL, &proof));
  check_equal(sizeof(proof), proof.size);
  check_equal(MESH_MGMT_AGENT_ROUTER_READY_VERSION, proof.version);
  check_equal(client.public_key, proof.remote_transport_peer_id, P2P_KEY_SIZE);
  check_equal(client.identity.signer.hello.managed_node_id,
              proof.remote_managed_node_id, 32u);
  check_true(memcmp(proof.connection_id, first_connection_id, 16u) != 0);
  check_equal((uint64_t)1u, proof.remote_incarnation);
  memcpy(first_connection_id, proof.connection_id, sizeof(first_connection_id));

  /* This is the REAL inbound P2P TCP stream carrying the same Noise/MMP
   * peer. The original CNet Manager now owns its physical attachment and
   * its generation; unrelated cohosted echo Manager can never be substituted. */
  check_equal(P2P_OK,
      p2p_peer_cnet_managed_binding_v1(server.peer, &inbound));
  check_not_null(inbound.manager);
  check_equal(P2P_CNET_MANAGED_BINDING_VERSION, inbound.version);
  check_true(inbound.physical.slot != 0u && inbound.managed.slot != 0u);
  physical_manager = inbound.manager;
  first_managed = inbound.managed;
  cnet_manager_entry entry = {0};
  check_equal(SALTS_OK,
      cnet_manager_lookup(physical_manager, inbound.managed, &entry));
  check_equal(CNET_MANAGER_BOUND, entry.state);
  check_equal(inbound.physical.slot, entry.connection.slot);
  check_equal(inbound.physical.generation, entry.connection.generation);
  check_not_null(entry.context);
  check_equal(MESH_MGMT_AGENT_ROUTER_OK,
      mesh_mgmt_agent_router_physical_ready_v1(
          &server.runtime.router, server.peer, client.public_key,
          client.identity.signer.hello.managed_node_id, first_connection_id,
          physical_manager, &same));
  check_equal(sizeof(same), same.size);
  check_equal(MESH_MGMT_AGENT_ROUTER_PHYSICAL_READY_VERSION, same.version);
  check_true(same.manager == physical_manager);
  check_equal(first_managed.generation, same.managed.generation);
  check_equal(inbound.physical.generation, same.physical.generation);
  check_equal(first_connection_id, same.signed_session.connection_id, 16u);

  /* A different CNet Manager (even if hosted on the same SG shard) has no
   * claim on the signed session's P2P physical connection. */
  cnet_manager unrelated = {0};
  check_equal(MESH_MGMT_AGENT_ROUTER_IDENTITY_MISMATCH,
      mesh_mgmt_agent_router_physical_ready_v1(
          &server.runtime.router, server.peer, client.public_key,
          client.identity.signer.hello.managed_node_id,
          first_connection_id, &unrelated, &same));
  check_equal((size_t)0u, same.size);
  check_true(same.manager == NULL);

  /* The client outbound numeric CNet connection has not yet migrated to
   * Manager; do not borrow the server's inbound physical READY. */
  check_equal(P2P_ERR_INVALID_STATE,
      p2p_peer_cnet_managed_binding_v1(client.peer, &inbound));
  check_equal((size_t)0u, inbound.size);

  /* The right signed managed node but the wrong P2P transport key must
   * fail with fully zeroed output; no stale or partial capability leaks. */
  memcpy(wrong_id, client.public_key, P2P_KEY_SIZE);
  wrong_id[0] ^= 1u;
  check_equal(MESH_MGMT_AGENT_ROUTER_IDENTITY_MISMATCH,
      mesh_mgmt_agent_router_ready_session_v1(
          &server.runtime.router, server.peer, wrong_id,
          client.identity.signer.hello.managed_node_id,
          first_connection_id, &proof));
  check_equal((size_t)0u, proof.size);
  memcpy(wrong_node_id,
         client.identity.signer.hello.managed_node_id, 32u);
  wrong_node_id[0] ^= 1u;
  check_equal(MESH_MGMT_AGENT_ROUTER_IDENTITY_MISMATCH,
      mesh_mgmt_agent_router_ready_session_v1(
          &server.runtime.router, server.peer, client.public_key,
          wrong_node_id, first_connection_id, &proof));
  check_equal((size_t)0u, proof.size);
  /* A live session proves its *own* Router peer, not a different
   * endpoint's peer pointer, even when the claimed identities match. */
  check_equal(MESH_MGMT_AGENT_ROUTER_PEER_NOT_FOUND,
      mesh_mgmt_agent_router_ready_session_v1(
          &server.runtime.router, client.peer, client.public_key,
          client.identity.signer.hello.managed_node_id,
          NULL, &proof));
  check_equal((size_t)0u, proof.size);

  /* Close the real signed session and let the two MMP Routers negotiate
   * a new one. The prior local connection_id is generation-stale. */
  p2p_disconnect_peer(client.peer);
  wait_established(&server, &client, 2u);
  check_not_null(server.peer);
  check_equal(MESH_MGMT_AGENT_ROUTER_IDENTITY_MISMATCH,
      mesh_mgmt_agent_router_ready_session_v1(
          &server.runtime.router, server.peer, client.public_key,
          client.identity.signer.hello.managed_node_id,
          first_connection_id, &proof));
  check_equal((size_t)0u, proof.size);
  check_equal(MESH_MGMT_AGENT_ROUTER_OK,
      mesh_mgmt_agent_router_ready_session_v1(
          &server.runtime.router, server.peer, client.public_key,
          client.identity.signer.hello.managed_node_id,
          NULL, &second));
  check_true(memcmp(first_connection_id, second.connection_id, 16u) != 0);
  check_equal(MESH_MGMT_AGENT_ROUTER_READY_VERSION, second.version);
  check_equal(client.public_key, second.remote_transport_peer_id, P2P_KEY_SIZE);

  /* Physical CNet/Manager is generation-safe too, independently of the
   * Router-local signed connection_id. Closed transport must recycle the
   * first attachment; the new authenticated peer must be a new generation. */
  check_equal(SALTS_ENOENT,
      cnet_manager_lookup(physical_manager, first_managed, &entry));
  check_equal(P2P_OK,
      p2p_peer_cnet_managed_binding_v1(server.peer, &next_inbound));
  check_true(next_inbound.manager == physical_manager);
  check_true(next_inbound.managed.generation != first_managed.generation ||
             next_inbound.managed.slot != first_managed.slot);
  check_equal(MESH_MGMT_AGENT_ROUTER_IDENTITY_MISMATCH,
      mesh_mgmt_agent_router_physical_ready_v1(
          &server.runtime.router, server.peer, client.public_key,
          client.identity.signer.hello.managed_node_id, first_connection_id,
          physical_manager, &same));
  check_equal((size_t)0u, same.size);
  check_equal(MESH_MGMT_AGENT_ROUTER_OK,
      mesh_mgmt_agent_router_physical_ready_v1(
          &server.runtime.router, server.peer, client.public_key,
          client.identity.signer.hello.managed_node_id, second.connection_id,
          physical_manager, &same));
  check_equal(next_inbound.managed.generation, same.managed.generation);
  check_equal(next_inbound.physical.generation, same.physical.generation);

  destroy(&client);
  destroy(&server);
}


/* Real inbound P2P CNet Manager physical stream + real signed MMP session.
 * Only after those two proofs are simultaneously valid does upstream CNet
 * ClientPool receive one post-auth READY record and a one-slot lease.
 * No provisional/guessable pre-Noise authority or separate TCP echo is
 * allowed to authorize an MMP protocol reuse lease. */
static void test_signed_same_physical_cnet_pool_lease(void) {
  endpoint_t server = {0}, client = {0};
  p2p_cnet_managed_binding_v1_t transport = {0};
  mesh_mgmt_agent_router_physical_ready_v1_t authenticated = {0};
  cnet_client_pool pool = {0};
  cnet_pool_connection physical = {0}, extra_physical = {0};
  cnet_pool_lease lease = {0}, retry_lease = {0};
  cnet_pool_key key = {0}, mismatch = {0};
  cnet_pool_snapshot status = {0};
  uint8_t initial_router_id[16] = {0};

  start_pair(&server, &client);
  wait_established(&server, &client, 1u);
  check_equal(P2P_OK,
      p2p_peer_cnet_managed_binding_v1(server.peer, &transport));
  check_not_null(transport.manager);
  check_equal(MESH_MGMT_AGENT_ROUTER_OK,
      mesh_mgmt_agent_router_physical_ready_v1(
          &server.runtime.router, server.peer,
          client.public_key, client.identity.signer.hello.managed_node_id,
          NULL, transport.manager, &authenticated));
  memcpy(initial_router_id, authenticated.signed_session.connection_id,
         sizeof(initial_router_id));

  const cnet_pool_config cfg = {
      sizeof(cnet_pool_config), CNET_CLIENT_POOL_VERSION, transport.manager,
      7u, 1u, 1u, 1u
  };
  check_equal(SALTS_OK, cnet_pool_init(&pool, &cfg));
  check_equal(SALTS_OK, cnet_pool_get_snapshot(&pool, &status));
  check_equal((size_t)0u, status.connecting);
  check_equal((size_t)0u, status.ready);

  /* Wrong Manager cannot borrow signed Router READY even while owning a
   * different CNet Client on the same machine. No Pool record is created. */
  cnet_manager unrelated = {0};
  check_equal(MESH_MGMT_AGENT_ROUTER_IDENTITY_MISMATCH,
      mesh_mgmt_agent_router_pool_bind_ready_v1(
          &server.runtime.router, server.peer,
          client.public_key, client.identity.signer.hello.managed_node_id,
          initial_router_id, &unrelated, &pool, 7u, &physical, &key));
  check_equal((size_t)0u, physical.slot);
  check_equal((size_t)0u, key.size);

  /* Owner ID is an explicit Host control and must exactly match Pool
   * configuration; the other compatibility fields come from signed facts. */
  check_equal(MESH_MGMT_AGENT_ROUTER_CONFIG_INVALID,
      mesh_mgmt_agent_router_pool_bind_ready_v1(
          &server.runtime.router, server.peer,
          client.public_key, client.identity.signer.hello.managed_node_id,
          initial_router_id, transport.manager, &pool, 99u, &physical, &key));
  check_equal((size_t)0u, physical.slot);
  check_equal((size_t)0u, key.size);

  check_equal(MESH_MGMT_AGENT_ROUTER_OK,
      mesh_mgmt_agent_router_pool_bind_ready_v1(
          &server.runtime.router, server.peer,
          client.public_key, client.identity.signer.hello.managed_node_id,
          initial_router_id, transport.manager, &pool, 7u, &physical, &key));
  check_true(physical.slot != 0u && physical.generation != 0u);
  check_equal(sizeof(key), key.size);
  check_equal(CNET_CLIENT_POOL_VERSION, key.version);
  check_equal((uint64_t)7u, key.owner_id);
  check_true(key.runtime_id != 0u && key.endpoint_id != 0u &&
             key.authority_id != 0u && key.transport_id != 0u &&
             key.peer_generation != 0u && key.session_id != 0u &&
             key.protocol_id != 0u && key.client_identity_id != 0u);
  check_equal((uint64_t)0u, key.tls_trust_id);
  check_equal((uint64_t)0u, key.tls_sni_id);
  check_equal((uint64_t)0u, key.alpn_id);

  check_equal(SALTS_OK, cnet_pool_get_snapshot(&pool, &status));
  check_equal((size_t)1u, status.ready);
  check_equal((size_t)0u, status.connecting);
  check_equal((size_t)0u, status.active_leases);
  check_equal(SALTS_ENOBUFS,
      cnet_pool_reserve_connecting(&pool, &key, &extra_physical));
  check_equal((size_t)0u, extra_physical.slot);
  mismatch = key;
  mismatch.authority_id ^= UINT64_C(1);
  cnet_managed_connection out_managed = {0};
  check_equal(SALTS_ENOBUFS,
      cnet_pool_try_acquire(&pool, &mismatch, NULL, &retry_lease,
                            &out_managed));
  check_equal((size_t)0u, retry_lease.slot);
  mismatch = key;
  mismatch.session_id ^= UINT64_C(1);
  check_equal(SALTS_ENOBUFS,
      cnet_pool_try_acquire(&pool, &mismatch, NULL, &retry_lease,
                            &out_managed));
  check_equal((size_t)0u, retry_lease.slot);

  /* Lease admission itself rechecks signed Router proof and the exact
   * original physical Manager generation, not just Pool's READY flag. */
  check_equal(MESH_MGMT_AGENT_ROUTER_IDENTITY_MISMATCH,
      mesh_mgmt_agent_router_pool_acquire_v1(
          &server.runtime.router, server.peer, client.public_key,
          client.identity.signer.hello.managed_node_id,
          initial_router_id, &unrelated, &pool, 7u, &retry_lease));
  check_equal((size_t)0u, retry_lease.slot);
  check_equal(MESH_MGMT_AGENT_ROUTER_OK,
      mesh_mgmt_agent_router_pool_acquire_v1(
          &server.runtime.router, server.peer, client.public_key,
          client.identity.signer.hello.managed_node_id,
          initial_router_id, transport.manager, &pool, 7u, &lease));
  check_true(lease.slot != 0u);
  check_equal(MESH_MGMT_AGENT_ROUTER_RESOURCE_EXHAUSTED,
      mesh_mgmt_agent_router_pool_acquire_v1(
          &server.runtime.router, server.peer, client.public_key,
          client.identity.signer.hello.managed_node_id,
          initial_router_id, transport.manager, &pool, 7u, &retry_lease));
  check_equal((size_t)0u, retry_lease.slot);
  check_equal(SALTS_EBUSY, cnet_pool_terminal(&pool, physical));

  /* The old signed session dies. Real per-peer endpoint reconnect policy
   * restores a new signed Router generation and new Manager physical
   * attachment; the old READY proof cannot issue a new lease. */
  p2p_disconnect_peer(client.peer);
  wait_established(&server, &client, 2u);
  check_equal(MESH_MGMT_AGENT_ROUTER_IDENTITY_MISMATCH,
      mesh_mgmt_agent_router_pool_acquire_v1(
          &server.runtime.router, server.peer, client.public_key,
          client.identity.signer.hello.managed_node_id,
          initial_router_id, transport.manager, &pool, 7u, &retry_lease));
  check_equal((size_t)0u, retry_lease.slot);
  check_equal(SALTS_OK, cnet_pool_terminal(&pool, physical));
  check_equal(SALTS_OK, cnet_pool_get_snapshot(&pool, &status));
  check_equal((size_t)1u, status.terminal_waiting_for_leases);
  check_equal((size_t)1u, status.active_leases);
  check_equal(SALTS_EBUSY, cnet_pool_destroy(&pool));
  check_equal(SALTS_OK, cnet_pool_release(&pool, lease));
  check_equal(SALTS_ENOENT, cnet_pool_release(&pool, lease));
  check_equal(SALTS_OK, cnet_pool_get_snapshot(&pool, &status));
  check_true(status.drained);
  check_equal(SALTS_OK, cnet_pool_destroy(&pool));

  /* Never destroy borrowed Manager or P2P Owner while any Pool lease exists. */
  destroy(&client);
  destroy(&server);
}


/* Production Mesh Runtime owns automatic signed MMP ClientPool admission:
 * real P2P Noise and MMP HELLO => exact inbound Manager-bound Pool READY.
 * User operations own actual one-slot leases; Router close marks DRAINING
 * and Stop retains every borrowed Manager/Pool object until leases drain.
 * No new CNet connection, NativeIO observer, retry clock or application
 * send replay is created by this runtime composition. */
static void test_runtime_signed_pool_callback_stop_and_lease(void) {
  endpoint_t server = {0}, client = {0};
  mesh_mgmt_agent_bootstrap_v1_t bootstrap = {0};
  cnet_pool_lease lease = {0}, extra = {0};
  cnet_pool_snapshot pool = {0};
  mesh_mgmt_agent_runtime_result_t stop_status;

  prepare(&server, 17);
  initialize(&server);
  check_equal(MESH_MGMT_AGENT_RUNTIME_INVALID_ARG,
      mesh_mgmt_agent_runtime_enable_signed_pool_v3(
          &server.runtime, 0u, 1u, 1u));
  check_equal(MESH_MGMT_AGENT_RUNTIME_INVALID_ARG,
      mesh_mgmt_agent_runtime_enable_signed_pool_v3(
          &server.runtime, 7u, 0u, 1u));
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_enable_signed_pool_v3(
          &server.runtime, 7u, 1u, 1u));
  check_equal(MESH_MGMT_AGENT_RUNTIME_INVALID_STATE,
      mesh_mgmt_agent_runtime_enable_signed_pool_v3(
          &server.runtime, 7u, 1u, 1u));
  check_equal(MESH_MGMT_AGENT_RUNTIME_INVALID_STATE,
      mesh_mgmt_agent_runtime_signed_pool_snapshot_v3(
          &server.runtime, &pool));
  check_true(server.runtime.signed_pool.impl == NULL);
  start(&server);
  check_equal(MESH_MGMT_AGENT_RUNTIME_INVALID_STATE,
      mesh_mgmt_agent_runtime_enable_signed_pool_v3(
          &server.runtime, 7u, 1u, 1u));

  prepare(&client, 33);
  memcpy(bootstrap.transport_peer_id, server.public_key,
         sizeof(bootstrap.transport_peer_id));
  bootstrap.host = "127.0.0.1";
  bootstrap.port = (uint16_t)server.port;
  client.config.bootstraps = &bootstrap;
  client.config.bootstrap_count = 1u;
  initialize(&client);
  client.config.bootstraps = NULL;
  client.config.bootstrap_count = 0u;
  start(&client);
  wait_established(&server, &client, 1u);
  check_not_null(server.peer);
  /* The Router itself delivered signed SESSION_ESTABLISHED, after the
   * endpoint membership/admission decision. The inbound physical Manager
   * and ClientPool now share the SAME exact P2P connection. */
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_signed_pool_snapshot_v3(
          &server.runtime, &pool));
  check_true(server.runtime.signed_pool_manager != NULL);
  check_equal((size_t)1u, pool.ready);
  check_equal((size_t)1u, pool.physical_in_use);
  check_equal((size_t)0u, pool.active_leases);
  check_equal((size_t)0u, pool.connecting);
  check_equal((size_t)0u, server.runtime.signed_pool_records[0].draining);
  check_equal(MESH_MGMT_AGENT_RUNTIME_INVALID_STATE,
      mesh_mgmt_agent_runtime_signed_pool_snapshot_v3(
          &client.runtime, &pool)); /* client is unmanaged outbound */
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_signed_pool_acquire_v3(
          &server.runtime, server.peer, &lease));
  check_true(lease.slot != 0u);
  check_equal(MESH_MGMT_AGENT_RUNTIME_RESOURCE_EXHAUSTED,
      mesh_mgmt_agent_runtime_signed_pool_acquire_v3(
          &server.runtime, server.peer, &extra));
  check_equal((size_t)0u, extra.slot);
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_signed_pool_snapshot_v3(
          &server.runtime, &pool));
  check_equal((size_t)1u, pool.active_leases);

  /* Server Stop disconnects the authenticated peer. The close callback
   * immediately revokes future Pool eligibility but must NOT fabricate
   * CNet physical terminal or confiscate the operation's lease. Owner
   * drain remains retryable while that lease is still borrowed. */
  stop_status = mesh_mgmt_agent_runtime_stop_v1(&server.runtime);
  check_equal(MESH_MGMT_AGENT_RUNTIME_INVALID_STATE, stop_status);
  check_equal(MESH_MGMT_AGENT_RUNTIME_STOPPING, server.runtime.state);
  check_not_null(server.runtime.node);
  check_true(server.runtime.signed_pool.impl != NULL);
  check_true(server.runtime.signed_pool_manager != NULL);
  check_equal(MESH_MGMT_AGENT_RUNTIME_INVALID_STATE,
      mesh_mgmt_agent_runtime_destroy_v2(&server.runtime));
  check_equal(MESH_MGMT_AGENT_RUNTIME_INVALID_STATE,
      mesh_mgmt_agent_runtime_signed_pool_acquire_v3(
          &server.runtime, client.peer, &extra));
  check_equal((size_t)0u, extra.slot);
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_signed_pool_snapshot_v3(
          &server.runtime, &pool));
  /* A real TCP terminal may complete in a later bounded Owner pass.
   * Each Stop retry uses the same retained Manager/Pool objects rather
   * than discarding outstanding callbacks or a borrowed lease. */
  for (unsigned pass = 0u;
       pass < 32u && pool.terminal_waiting_for_leases == 0u; ++pass) {
    cmeta_sleep_ms(1u);
    check_equal(MESH_MGMT_AGENT_RUNTIME_INVALID_STATE,
        mesh_mgmt_agent_runtime_stop_v1(&server.runtime));
    check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
        mesh_mgmt_agent_runtime_signed_pool_snapshot_v3(
            &server.runtime, &pool));
  }
  check_true(pool.sealed);
  check_equal((size_t)0u, pool.ready);
  check_equal((size_t)1u, pool.active_leases);
  check_equal((size_t)1u, pool.terminal_waiting_for_leases);

  /* The caller returns the original operation lease after Router close;
   * pool is now drained, so the real Manager/P2P Owner may be destroyed. */
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_signed_pool_release_v3(
          &server.runtime, lease));
  check_equal(MESH_MGMT_AGENT_RUNTIME_INVALID_STATE,
      mesh_mgmt_agent_runtime_signed_pool_release_v3(
          &server.runtime, lease));
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_signed_pool_snapshot_v3(
          &server.runtime, &pool));
  check_true(pool.drained);
  check_equal((size_t)0u, pool.active_leases);
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_stop_v1(&server.runtime));
  check_equal(MESH_MGMT_AGENT_RUNTIME_STOPPED, server.runtime.state);
  check_true(server.runtime.node == NULL);
  destroy(&server);
  destroy(&client);
}


/* A retired signed MMP connection may retain an application-owned Lease
 * while the endpoint pool restores a fresh signed session. The Router
 * generation, CNet Manager generation and Pool key must not alias: the new
 * physical connection can grant its own exclusive Lease, and releasing the
 * old one must never revoke or resurrect the new connection's credit. */
static void test_runtime_signed_pool_reconnect_preserves_old_lease(void) {
  endpoint_t server = {0}, client = {0};
  mesh_mgmt_agent_bootstrap_v1_t bootstrap = {0};
  mesh_mgmt_runtime_pool_record_v3_t previous = {0}, next = {0};
  mesh_mgmt_agent_router_ready_v1_t signed_ready = {0};
  cnet_manager_entry old_entry = {0};
  cnet_managed_connection unused_managed = {0};
  cnet_pool_lease old_lease = {0}, new_lease = {0}, denied = {0};
  cnet_pool_snapshot pool = {0};
  uint64_t deadline;

  prepare(&server, 17);
  initialize(&server);
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_enable_signed_pool_v3(
          &server.runtime, 7u, 2u, 2u));
  start(&server);

  prepare(&client, 33);
  memcpy(bootstrap.transport_peer_id, server.public_key,
         sizeof(bootstrap.transport_peer_id));
  bootstrap.host = "127.0.0.1";
  bootstrap.port = (uint16_t)server.port;
  client.config.bootstraps = &bootstrap;
  client.config.bootstrap_count = 1u;
  initialize(&client);
  client.config.bootstraps = NULL;
  client.config.bootstrap_count = 0u;
  start(&client);
  wait_established(&server, &client, 1u);

  check_not_null(server.peer);
  check_true(server.runtime.signed_pool_records[0].active);
  previous = server.runtime.signed_pool_records[0];
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_signed_pool_acquire_v3(
          &server.runtime, server.peer, &old_lease));
  check_true(old_lease.slot != 0u);

  /* An actual client-side TCP disconnect triggers Router DRAINING, native
   * Manager retirement, and endpoint-policy reconnect without a new timer. */
  p2p_disconnect_peer(client.peer);
  wait_established(&server, &client, 2u);
  check_true(server.closed > 0u && client.closed > 0u);
  check_not_null(server.peer);
  check_equal(MESH_MGMT_AGENT_ROUTER_OK,
      mesh_mgmt_agent_router_ready_peer_v1(
          &server.runtime.router, server.peer, &signed_ready));
  check_true(memcmp(previous.connection_id, signed_ready.connection_id,
                    sizeof(previous.connection_id)) != 0);
  check_equal(SALTS_ENOENT,
      cnet_manager_lookup(server.runtime.signed_pool_manager,
                          previous.managed, &old_entry));

  /* Even after reconnection has installed a fresh READY, the old signed
   * session key cannot acquire the new Manager/Pool generation. */
  check_equal(SALTS_ENOBUFS,
      cnet_pool_try_acquire(&server.runtime.signed_pool, &previous.key,
                            NULL, &denied, &unused_managed));
  check_equal((size_t)0u, denied.slot);
  for (size_t i = 0u; i < server.runtime.signed_pool_capacity; ++i) {
    mesh_mgmt_runtime_pool_record_v3_t *record =
        &server.runtime.signed_pool_records[i];
    if (record->active && !record->draining &&
        record->peer == server.peer) {
      next = *record;
      break;
    }
  }
  check_true(next.active);
  check_true(next.managed.slot != previous.managed.slot ||
             next.managed.generation != previous.managed.generation);
  check_true(next.physical.slot != previous.physical.slot ||
             next.physical.generation != previous.physical.generation);
  check_true(next.key.peer_generation != previous.key.peer_generation ||
             next.key.session_id != previous.key.session_id);

  /* The old physical terminal is sourced only from the native Owner.
   * Holding its Lease may prevent old Pool reclamation, but must not
   * consume the separate new connection's exclusive operation slot. */
  deadline = cmeta_monotonic_ms() + WAIT_MS;
  do {
    check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
        mesh_mgmt_agent_runtime_signed_pool_snapshot_v3(
            &server.runtime, &pool));
    if (pool.terminal_waiting_for_leases == 1u && pool.ready == 1u)
      break;
    poll_pair(&server, &client);
  } while (cmeta_monotonic_ms() < deadline);
  check_equal((size_t)1u, pool.terminal_waiting_for_leases);
  check_equal((size_t)1u, pool.ready);
  check_equal((size_t)1u, pool.active_leases);
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_signed_pool_acquire_v3(
          &server.runtime, server.peer, &new_lease));
  check_true(new_lease.slot != 0u);
  check_equal(MESH_MGMT_AGENT_RUNTIME_RESOURCE_EXHAUSTED,
      mesh_mgmt_agent_runtime_signed_pool_acquire_v3(
          &server.runtime, server.peer, &denied));
  check_equal((size_t)0u, denied.slot);
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_signed_pool_snapshot_v3(
          &server.runtime, &pool));
  check_equal((size_t)2u, pool.active_leases);

  /* Exactly-once return of the old generation cannot touch the newly
   * leased connection, even if its callback-index storage was reused. */
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_signed_pool_release_v3(
          &server.runtime, old_lease));
  check_equal(MESH_MGMT_AGENT_RUNTIME_INVALID_STATE,
      mesh_mgmt_agent_runtime_signed_pool_release_v3(
          &server.runtime, old_lease));
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_signed_pool_snapshot_v3(
          &server.runtime, &pool));
  check_equal((size_t)0u, pool.terminal_waiting_for_leases);
  check_equal((size_t)1u, pool.active_leases);
  check_equal((size_t)1u, pool.ready);

  /* Now stop with the NEW generation still leased. The old lease has
   * already drained, but the new Pool/Manager/Owner borrows must survive
   * checked Stop and Destroy independently of the reused callback index. */
  check_equal(MESH_MGMT_AGENT_RUNTIME_INVALID_STATE,
      mesh_mgmt_agent_runtime_stop_v1(&server.runtime));
  check_equal(MESH_MGMT_AGENT_RUNTIME_STOPPING, server.runtime.state);
  check_not_null(server.runtime.node);
  check_true(server.runtime.signed_pool.impl != NULL);
  check_true(server.runtime.signed_pool_manager != NULL);
  check_equal(MESH_MGMT_AGENT_RUNTIME_INVALID_STATE,
      mesh_mgmt_agent_runtime_destroy_v2(&server.runtime));
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_signed_pool_snapshot_v3(
          &server.runtime, &pool));
  check_true(pool.sealed);
  check_equal((size_t)1u, pool.active_leases);
  check_equal((size_t)0u, pool.ready);

  /* The checked Release is still legal in STOPPING; only then may
   * another Stop release the real upstream Pool before CNet Owner. */
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_signed_pool_release_v3(
          &server.runtime, new_lease));
  check_equal(MESH_MGMT_AGENT_RUNTIME_INVALID_STATE,
      mesh_mgmt_agent_runtime_signed_pool_release_v3(
          &server.runtime, new_lease));
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_signed_pool_snapshot_v3(
          &server.runtime, &pool));
  check_equal((size_t)0u, pool.active_leases);
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_stop_v1(&server.runtime));
  check_equal(MESH_MGMT_AGENT_RUNTIME_STOPPED, server.runtime.state);
  check_true(server.runtime.node == NULL);

  destroy(&server);
  destroy(&client);
}


/* One authenticated inbound MMP stream already owns the real Pool READY
 * connection and its application Lease. A second, independently signed
 * transport may reach post-auth admission but must not evict the first
 * READY, steal its exclusive slot or start a competing retry policy when
 * the opt-in Pool's physical capacity is FULL. */
static void test_runtime_signed_pool_full_keeps_existing_lease(void) {
  endpoint_t server = {0}, first = {0}, second = {0};
  mesh_mgmt_agent_bootstrap_v1_t first_bootstrap = {0};
  mesh_mgmt_agent_bootstrap_v1_t second_bootstrap = {0};
  mesh_mgmt_agent_router_ready_v1_t signed_first = {0};
  cnet_pool_lease borrowed = {0}, again = {0}, denied = {0};
  cnet_pool_snapshot pool = {0};
  p2p_peer_t *first_peer;
  uint64_t deadline;

  prepare(&server, 17);
  initialize(&server);
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_enable_signed_pool_v3(
          &server.runtime, 7u, 1u, 1u));
  start(&server);

  prepare(&first, 33);
  memcpy(first_bootstrap.transport_peer_id, server.public_key,
         sizeof(first_bootstrap.transport_peer_id));
  first_bootstrap.host = "127.0.0.1";
  first_bootstrap.port = (uint16_t)server.port;
  first.config.bootstraps = &first_bootstrap;
  first.config.bootstrap_count = 1u;
  initialize(&first);
  first.config.bootstraps = NULL;
  first.config.bootstrap_count = 0u;
  start(&first);
  wait_established(&server, &first, 1u);
  check_not_null(server.peer);
  first_peer = server.peer;
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_signed_pool_acquire_v3(
          &server.runtime, first_peer, &borrowed));
  check_true(borrowed.slot != 0u);
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_signed_pool_snapshot_v3(
          &server.runtime, &pool));
  check_equal((size_t)1u, pool.ready);
  check_equal((size_t)1u, pool.active_leases);

  /* A different signed client exercises real post-Noise / post-MMP Pool
   * capacity refusal; it has no privilege to replace the first key.
   * Only the existing EndpointPool owns any retry/backoff for that peer. */
  prepare(&second, 49);
  memcpy(second_bootstrap.transport_peer_id, server.public_key,
         sizeof(second_bootstrap.transport_peer_id));
  second_bootstrap.host = "127.0.0.1";
  second_bootstrap.port = (uint16_t)server.port;
  second.config.bootstraps = &second_bootstrap;
  second.config.bootstrap_count = 1u;
  initialize(&second);
  second.config.bootstraps = NULL;
  second.config.bootstrap_count = 0u;
  start(&second);

  deadline = cmeta_monotonic_ms() + WAIT_MS;
  while (server.closed == 0u && cmeta_monotonic_ms() < deadline) {
    check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
        mesh_mgmt_agent_runtime_poll_v1(&server.runtime));
    check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
        mesh_mgmt_agent_runtime_poll_v1(&first.runtime));
    check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
        mesh_mgmt_agent_runtime_poll_v1(&second.runtime));
    cmeta_sleep_ms(1u);
  }
  check_true(server.admitted >= 2u);
  check_true(server.closed > 0u);
  check_equal(1u, server.established);
  check_equal(0u, first.closed);
  check_true(server.peer == first_peer);
  check_equal(MESH_MGMT_AGENT_ROUTER_OK,
      mesh_mgmt_agent_router_ready_peer_v1(
          &server.runtime.router, first_peer, &signed_first));
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_signed_pool_snapshot_v3(
          &server.runtime, &pool));
  check_true(!pool.sealed);
  check_equal((size_t)1u, pool.ready);
  check_equal((size_t)1u, pool.physical_in_use);
  check_equal((size_t)1u, pool.active_leases);
  check_equal(MESH_MGMT_AGENT_RUNTIME_RESOURCE_EXHAUSTED,
      mesh_mgmt_agent_runtime_signed_pool_acquire_v3(
          &server.runtime, first_peer, &denied));
  check_equal((size_t)0u, denied.slot);

  /* Backpressure on the second peer is not a terminal event for the
   * first generation. Its exactly-once Lease return restores ordinary
   * acquisition while the signed first MMP session remains live. */
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_signed_pool_release_v3(
          &server.runtime, borrowed));
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_signed_pool_acquire_v3(
          &server.runtime, first_peer, &again));
  check_true(again.slot != 0u);
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_signed_pool_release_v3(
          &server.runtime, again));
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_signed_pool_snapshot_v3(
          &server.runtime, &pool));
  check_equal((size_t)0u, pool.active_leases);
  check_equal((size_t)1u, pool.ready);

  destroy(&second);
  destroy(&first);
  destroy(&server);
}


typedef struct {
  endpoint_t *server;
  unsigned terminals;
  uint64_t ticket;
  int status;
} command_terminal_probe_v4_t;

static void on_command_wire_terminal(void *context, uint64_t ticket, int status) {
  command_terminal_probe_v4_t *probe = context;
  check_reentry(probe->server);
  ++probe->terminals;
  probe->ticket = ticket;
  probe->status = status;
}

/* The ordinary fixture negotiates MEMBERSHIP ONLY; execution must
 * be an explicit authenticated capability, not silently enabled by a new
 * send-terminal function. Keep both P2P signers and dispatchers aligned. */
static void enable_execution_capability_v4(endpoint_t *endpoint) {
  const uint64_t features =
      MESH_MGMT_FEATURE_MEMBERSHIP |
      MESH_MGMT_FEATURE_TARGETED_RPC |
      MESH_MGMT_FEATURE_NODE_EXECUTION;
  endpoint->identity.signer.hello.features = features;
  endpoint->identity.dispatch.session.features = features;
  endpoint->identity.dispatch.enable_node_execution_shadow = 1u;
  /* Dispatcher admission requires a real, pinned issuer public key even
   * before a command executes; the test's certificate issuer provides it. */
  memcpy(endpoint->identity.dispatch.node_execution_grant_issuer_key,
         endpoint->identity.dispatch.session.trusted_issuer_key,
         sizeof(endpoint->identity.dispatch.node_execution_grant_issuer_key));
  endpoint->identity.signer.hello.max_frame = MESH_MGMT_FRAME_MAX;
  endpoint->identity.dispatch.session.max_frame = MESH_MGMT_FRAME_MAX;
}

static size_t execution_status_payload_v4(
    const endpoint_t *server, uint8_t output[MESH_MGMT_EXECUTION_COMMAND_STATUS_SIZE_V1]) {
  mesh_mgmt_execution_status_v1_t status = {0};
  size_t output_size = 0u;
  status.version = MESH_MGMT_EXECUTION_SCHEMA_V1;
  status.code = MESH_MGMT_EXECUTION_STATUS_DISABLED;
  memset(status.command_id, 0x41, sizeof(status.command_id));
  memset(status.correlation_id, 0x42, sizeof(status.correlation_id));
  memset(status.request_digest, 0x43, sizeof(status.request_digest));
  memcpy(status.responder_node_id, server->identity.signer.hello.managed_node_id,
         sizeof(status.responder_node_id));
  check_equal(MESH_MGMT_EXECUTION_WIRE_OK,
      mesh_mgmt_execution_command_status_encode_v1(
          &status, output, MESH_MGMT_EXECUTION_COMMAND_STATUS_SIZE_V1, &output_size));
  return output_size;
}

/* Production CNet/Noise path: a signed MMP command reserves its exact
 * inbound Manager/Pool Lease BEFORE encryption, and retains it until the
 * upstream full encrypted wire-write callback, never on enqueue alone.
 * Outbound/unmanaged clients and stale/unknown signed targets fail closed. */
static void test_signed_execution_command_wire_terminal_v4(void) {
  endpoint_t server = {0}, client = {0};
  command_terminal_probe_v4_t probe = {0};
  cnet_pool_snapshot pool = {0};
  uint8_t payload[MESH_MGMT_EXECUTION_COMMAND_STATUS_SIZE_V1] = {0};
  mesh_mgmt_agent_bootstrap_v1_t bootstrap = {0};
  uint8_t bad_target[32] = {0};
  size_t payload_len = 0u;
  uint64_t ticket = 0u, refused = 99u, deadline;

  prepare(&server, 17u);
  enable_execution_capability_v4(&server);
  initialize(&server);
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_enable_signed_pool_v3(
          &server.runtime, 7u, 1u, 1u));
  start(&server);
  prepare(&client, 33u);
  enable_execution_capability_v4(&client);
  memcpy(bootstrap.transport_peer_id, server.public_key,
         sizeof(bootstrap.transport_peer_id));
  bootstrap.host = "127.0.0.1";
  bootstrap.port = (uint16_t)server.port;
  client.config.bootstraps = &bootstrap;
  client.config.bootstrap_count = 1u;
  initialize(&client);
  client.config.bootstraps = NULL;
  client.config.bootstrap_count = 0u;
  start(&client);
  wait_established(&server, &client, 1u);
  payload_len = execution_status_payload_v4(&server, payload);
  check_not_null(server.peer);
  probe.server = &server;

  memset(bad_target, 0xA5, sizeof(bad_target));
  check_equal(MESH_MGMT_AGENT_RUNTIME_DISCOVERY_FAILED,
      mesh_mgmt_agent_runtime_send_execution_leased_v4(
          &server.runtime, MESH_MGMT_KIND_COMMAND_STATUS,
          bad_target, payload, payload_len,
          on_command_wire_terminal, &probe, &refused));
  check_equal((uint64_t)0u, refused);
  check_equal((unsigned)0u, probe.terminals);

  /* Only the inbound signed session is attached to the P2P Manager. An
   * outgoing peer's Runtime cannot accidentally lease the server's Pool. */
  check_equal(MESH_MGMT_AGENT_RUNTIME_INVALID_STATE,
      mesh_mgmt_agent_runtime_send_execution_leased_v4(
          &client.runtime, MESH_MGMT_KIND_COMMAND_STATUS,
          server.identity.signer.hello.managed_node_id,
          payload, payload_len, on_command_wire_terminal, &probe, &refused));
  check_equal((uint64_t)0u, refused);

  /* A syntactically-valid STATUS payload is NOT a typed COMMAND_REQUEST.
   * The common outbound Dispatcher preflight must reject it without
   * encryption, Lease retention, or a terminal callback. */
  refused = 91u;
  check_equal(MESH_MGMT_AGENT_RUNTIME_SEND_FAILED,
      mesh_mgmt_agent_runtime_send_execution_leased_v4(
          &server.runtime, MESH_MGMT_KIND_COMMAND_REQUEST,
          client.identity.signer.hello.managed_node_id,
          payload, payload_len, on_command_wire_terminal, &probe, &refused));
  check_equal((uint64_t)0u, refused);
  check_equal((size_t)0u, server.runtime.command_terminal_inflight);
  check_equal((unsigned)0u, probe.terminals);

  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_send_execution_leased_v4(
          &server.runtime, MESH_MGMT_KIND_COMMAND_STATUS,
          client.identity.signer.hello.managed_node_id,
          payload, payload_len,
          on_command_wire_terminal, &probe, &ticket));
  check_true(ticket != 0u);
  check_equal((unsigned)0u, probe.terminals); /* not an enqueue callback */
  check_equal((size_t)1u, server.runtime.command_terminal_inflight);
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_signed_pool_snapshot_v3(
          &server.runtime, &pool));
  check_equal((size_t)1u, pool.active_leases);
  refused = 44u;
  check_equal(MESH_MGMT_AGENT_RUNTIME_RESOURCE_EXHAUSTED,
      mesh_mgmt_agent_runtime_send_execution_leased_v4(
          &server.runtime, MESH_MGMT_KIND_COMMAND_STATUS,
          client.identity.signer.hello.managed_node_id,
          payload, payload_len,
          on_command_wire_terminal, &probe, &refused));
  check_equal((uint64_t)0u, refused);
  check_equal((size_t)1u, server.runtime.command_terminal_inflight);

  /* Only the SERVER final Owner progresses. No remote-application callback
   * or command reply is needed to prove the CNet full-write terminal. */
  deadline = cmeta_monotonic_ms() + WAIT_MS;
  while (!probe.terminals && cmeta_monotonic_ms() < deadline) {
    check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
        mesh_mgmt_agent_runtime_poll_v1(&server.runtime));
    cmeta_sleep_ms(1u);
  }
  check_equal((unsigned)1u, probe.terminals);
  check_equal(ticket, probe.ticket);
  check_equal(P2P_OK, probe.status);
  check_equal((size_t)0u, server.runtime.command_terminal_inflight);
  check_equal(ticket, server.runtime.last_command_ticket);
  check_equal(P2P_OK, server.runtime.last_command_terminal_status);
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_signed_pool_snapshot_v3(
          &server.runtime, &pool));
  check_equal((size_t)0u, pool.active_leases);

  /* Existing response API MUST NOT bypass the signed Pool once enabled:
   * it too holds a bounded operation Lease until definitive send terminal. */
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_send_execution_response_v1(
          &server.runtime, MESH_MGMT_KIND_COMMAND_STATUS,
          client.identity.signer.hello.managed_node_id,
          payload, payload_len));
  check_equal((size_t)1u, server.runtime.command_terminal_inflight);
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_signed_pool_snapshot_v3(
          &server.runtime, &pool));
  check_equal((size_t)1u, pool.active_leases);
  deadline = cmeta_monotonic_ms() + WAIT_MS;
  while (server.runtime.command_terminal_inflight &&
         cmeta_monotonic_ms() < deadline) {
    check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
        mesh_mgmt_agent_runtime_poll_v1(&server.runtime));
    cmeta_sleep_ms(1u);
  }
  check_equal((size_t)0u, server.runtime.command_terminal_inflight);
  check_equal(P2P_OK, server.runtime.last_command_terminal_status);
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_signed_pool_snapshot_v3(
          &server.runtime, &pool));
  check_equal((size_t)0u, pool.active_leases);

  for (unsigned turn = 0u; turn < 4u; ++turn)
    check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
        mesh_mgmt_agent_runtime_poll_v1(&server.runtime));
  check_equal((unsigned)1u, probe.terminals); /* one callback per ticket */
  destroy(&server);
  destroy(&client);
}

/* Two simultaneous, independently signed inbound MMP connections share
 * exactly one production CNet Manager and Pool, but keep different physical
 * Manager generations, immutable Pool keys and exclusive operation Leases.
 * Closing the first TCP peer cannot terminal or revoke the second Lease. */
static void test_runtime_signed_pool_two_peer_terminal_isolation(void) {
  endpoint_t server = {0}, first = {0}, second = {0};
  mesh_mgmt_runtime_pool_record_v3_t first_record = {0}, second_record = {0};
  mesh_mgmt_agent_router_ready_v1_t second_signed = {0};
  cnet_pool_lease first_lease = {0}, second_lease = {0}, again = {0};
  cnet_managed_connection unused = {0};
  cnet_pool_snapshot pool = {0};
  cnet_manager_entry old_manager = {0};
  p2p_peer_t *first_server_peer, *second_server_peer;
  uint64_t deadline;

  prepare(&server, 17);
  server.config.max_peers = 4u;
  server.config.endpoint_capacity = 4u;
  initialize(&server);
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_enable_signed_pool_v3(
          &server.runtime, 7u, 2u, 2u));
  start(&server);

  start_signed_client(&first, &server, 33u);
  wait_established(&server, &first, 1u);
  first_server_peer = server.peer;
  check_not_null(first_server_peer);
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_signed_pool_acquire_v3(
          &server.runtime, first_server_peer, &first_lease));
  check_true(first_lease.slot != 0u);

  start_signed_client(&second, &server, 49u);
  deadline = cmeta_monotonic_ms() + WAIT_MS;
  while ((server.established < 2u || second.established < 1u) &&
         cmeta_monotonic_ms() < deadline)
    poll_three(&server, &first, &second);
  check_equal(2u, server.established);
  check_equal(1u, second.established);
  check_not_null(server.peer);
  second_server_peer = server.peer;
  check_true(first_server_peer != second_server_peer);

  for (size_t i = 0u; i < server.runtime.signed_pool_capacity; ++i) {
    const mesh_mgmt_runtime_pool_record_v3_t *record =
        &server.runtime.signed_pool_records[i];
    if (!record->active || record->draining) continue;
    if (record->peer == first_server_peer) first_record = *record;
    if (record->peer == second_server_peer) second_record = *record;
  }
  check_true(first_record.active && second_record.active);
  check_true(first_record.physical.slot != second_record.physical.slot ||
             first_record.physical.generation != second_record.physical.generation);
  check_true(first_record.managed.slot != second_record.managed.slot ||
             first_record.managed.generation != second_record.managed.generation);
  check_true(first_record.key.peer_generation != second_record.key.peer_generation ||
             first_record.key.session_id != second_record.key.session_id);
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_signed_pool_acquire_v3(
          &server.runtime, second_server_peer, &second_lease));
  check_true(second_lease.slot != 0u);
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_signed_pool_snapshot_v3(
          &server.runtime, &pool));
  check_equal((size_t)2u, pool.ready);
  check_equal((size_t)2u, pool.physical_in_use);
  check_equal((size_t)2u, pool.active_leases);
  check_equal((size_t)0u, pool.connecting);

  /* The first client deliberately dies while BOTH leases are checked
   * out. Runtime close revokes only that peer's future lease eligibility;
   * physical TERMINAL is still governed by CNet Manager's real recycle. */
  p2p_disconnect_peer(first.peer);
  deadline = cmeta_monotonic_ms() + WAIT_MS;
  do {
    poll_three(&server, &first, &second);
    check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
        mesh_mgmt_agent_runtime_signed_pool_snapshot_v3(
            &server.runtime, &pool));
    if (server.closed > 0u && pool.terminal_waiting_for_leases == 1u &&
        pool.ready == 1u) break;
  } while (cmeta_monotonic_ms() < deadline);
  check_true(server.closed > 0u && first.closed > 0u);
  check_equal(0u, second.closed);
  check_equal((size_t)1u, pool.terminal_waiting_for_leases);
  check_equal((size_t)1u, pool.ready);
  check_equal((size_t)2u, pool.active_leases);
  check_equal(MESH_MGMT_AGENT_ROUTER_OK,
      mesh_mgmt_agent_router_ready_peer_v1(
          &server.runtime.router, second_server_peer, &second_signed));
  check_equal(second_record.connection_id, second_signed.connection_id, 16u);
  int lookup = cnet_manager_lookup(server.runtime.signed_pool_manager,
                                   first_record.managed, &old_manager);
  check_true(lookup == SALTS_ENOENT ||
             (lookup == SALTS_OK && old_manager.state == CNET_MANAGER_RETIRED));

  /* Only the first retired physical entry reclaims its capacity. Its
   * stale key cannot acquire the second connection even when one global
   * lease slot is free. The other live peer remains exclusively leased. */
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_signed_pool_release_v3(
          &server.runtime, first_lease));
  check_equal(MESH_MGMT_AGENT_RUNTIME_INVALID_STATE,
      mesh_mgmt_agent_runtime_signed_pool_release_v3(
          &server.runtime, first_lease));
  check_equal(SALTS_ENOBUFS,
      cnet_pool_try_acquire(&server.runtime.signed_pool, &first_record.key,
                            NULL, &again, &unused));
  check_equal((size_t)0u, again.slot);
  check_equal(MESH_MGMT_AGENT_RUNTIME_RESOURCE_EXHAUSTED,
      mesh_mgmt_agent_runtime_signed_pool_acquire_v3(
          &server.runtime, second_server_peer, &again));
  check_equal((size_t)0u, again.slot);
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_signed_pool_release_v3(
          &server.runtime, second_lease));
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_signed_pool_acquire_v3(
          &server.runtime, second_server_peer, &again));
  check_true(again.slot != 0u);
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_signed_pool_release_v3(
          &server.runtime, again));
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_signed_pool_snapshot_v3(
          &server.runtime, &pool));
  check_equal((size_t)0u, pool.active_leases);
  check_true(pool.ready >= 1u);
  destroy(&first);
  destroy(&second);
  destroy(&server);
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
  it("retains signed execution ClientPool Lease until real CNet wire terminal") {
    test_signed_execution_command_wire_terminal_v4();
  }
  it("keeps two real inbound signed Leases isolated while one Manager generation retires") {
    test_runtime_signed_pool_two_peer_terminal_isolation();
  }
  it("does not evict a leased signed MMP connection when another inbound peer hits Pool FULL") {
    test_runtime_signed_pool_full_keeps_existing_lease();
  }
  it("keeps old signed leases isolated across real MMP disconnect and reconnect") {
    test_runtime_signed_pool_reconnect_preserves_old_lease();
  }
  it("automatically binds signed MMP Pool READY and retains owner on outstanding Stop leases") {
    test_runtime_signed_pool_callback_stop_and_lease();
  }
  it("binds real signed MMP READY to the same CNet Manager physical Pool lease") {
    test_signed_same_physical_cnet_pool_lease();
  }
  it("issues only live signed MMP READY proofs and rejects stale reconnect generations") {
    test_router_signed_pool_ready_capability();
  }
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
