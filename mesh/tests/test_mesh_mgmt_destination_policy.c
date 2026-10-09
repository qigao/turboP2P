#include <tinytest.h>
#include "mesh_mgmt_endpoint_pool.h"
#include <cstl/vec.h>
#include <string.h>

enum { TEST_CAPACITY = 4 };
static const uint8_t PEER_A[P2P_KEY_SIZE] = {0x11u};
static const uint8_t PEER_B[P2P_KEY_SIZE] = {0x22u};
static const uint8_t PEER_C[P2P_KEY_SIZE] = {0x33u};

typedef struct {
  p2p_node_t *node;
  mesh_mgmt_endpoint_pool_v1_t *pool;
  mesh_mgmt_client_destination_policy_v2_t policy;
  char first_host[MESH_MGMT_ENDPOINT_HOST_MAX];
  unsigned attempts[3];
  unsigned total;
  int callback_reentry;
  int dial_result;
} fake_io_t;

static int connect_peer(void *context, p2p_node_t *node, const char *host, uint16_t port) {
  fake_io_t *io = context;
  size_t index = 3u;
  if (strcmp(host, "alpha") == 0 && port == 1001u) index = 0u;
  if (strcmp(host, "beta") == 0 && port == 1002u) index = 1u;
  if (strcmp(host, "gamma") == 0 && port == 1003u) index = 2u;
  if (node != io->node || index == 3u || !io->pool || !io->pool->in_api)
    return P2P_ERR_INVALID_ARG;
  if (!io->total) strcpy(io->first_host, host);
  io->attempts[index]++;
  io->total++;
  if (mesh_mgmt_endpoint_pool_set_client_policy_v2(io->pool, &io->policy) ==
      MESH_MGMT_ENDPOINT_POOL_INVALID_STATE)
    io->callback_reentry++;
  return io->dial_result;
}

static int fake_random(void *context, uint8_t *output, size_t length) {
  (void)context;
  if (!output || length != 4u) return -1;
  memset(output, 0, length);
  return 0;
}

static mesh_mgmt_endpoint_pool_config_v1_t pool_config(fake_io_t *io) {
  mesh_mgmt_endpoint_pool_config_v1_t config = {0};
  io->node = (p2p_node_t *)io;
  config.node = io->node;
  config.capacity = TEST_CAPACITY;
  config.retry_base_ms = 20u;
  config.retry_max_ms = 80u;
  config.connect_timeout_ms = 10u;
  config.protocol_failure_limit = 2u;
  config.connect_peer = connect_peer;
  config.random_bytes = fake_random;
  config.callback_context = io;
  return config;
}

static void set_rr_policy(fake_io_t *io) {
  memset(&io->policy, 0, sizeof(io->policy));
  io->policy.size = sizeof(io->policy);
  io->policy.version = MESH_MGMT_CLIENT_DESTINATION_POLICY_VERSION;
  io->policy.kind = CNET_DESTINATION_ROUND_ROBIN;
}

static void set_strict_policy(fake_io_t *io, uint64_t key) {
  set_rr_policy(io);
  io->policy.kind = CNET_DESTINATION_STRICT_KEY;
  io->policy.key_known = true;
  io->policy.key_hash = key;
}

static void set_explicit_policy(fake_io_t *io, const uint8_t peer_id[P2P_KEY_SIZE]) {
  set_rr_policy(io);
  io->policy.kind = CNET_DESTINATION_EXPLICIT;
  memcpy(io->policy.explicit_transport_peer_id, peer_id, P2P_KEY_SIZE);
}

static void init_pool(mesh_mgmt_endpoint_pool_v1_t *pool, fake_io_t *io) {
  mesh_mgmt_endpoint_pool_config_v1_t config = pool_config(io);
  io->pool = pool;
  check_equal(MESH_MGMT_ENDPOINT_POOL_OK,
              mesh_mgmt_endpoint_pool_init_v1(pool, &config));
}

static void add_peers(mesh_mgmt_endpoint_pool_v1_t *pool, int reversed) {
  if (reversed) {
    check_equal(MESH_MGMT_ENDPOINT_POOL_OK,
        mesh_mgmt_endpoint_pool_add_static_v1(pool, PEER_C, "gamma", 1003u));
    check_equal(MESH_MGMT_ENDPOINT_POOL_OK,
        mesh_mgmt_endpoint_pool_add_static_v1(pool, PEER_B, "beta", 1002u));
    check_equal(MESH_MGMT_ENDPOINT_POOL_OK,
        mesh_mgmt_endpoint_pool_add_static_v1(pool, PEER_A, "alpha", 1001u));
  } else {
    check_equal(MESH_MGMT_ENDPOINT_POOL_OK,
        mesh_mgmt_endpoint_pool_add_static_v1(pool, PEER_A, "alpha", 1001u));
    check_equal(MESH_MGMT_ENDPOINT_POOL_OK,
        mesh_mgmt_endpoint_pool_add_static_v1(pool, PEER_B, "beta", 1002u));
    check_equal(MESH_MGMT_ENDPOINT_POOL_OK,
        mesh_mgmt_endpoint_pool_add_static_v1(pool, PEER_C, "gamma", 1003u));
  }
}

static void dispose(mesh_mgmt_endpoint_pool_v1_t *pool) {
  mesh_mgmt_endpoint_pool_stop_v1(pool);
  mesh_mgmt_endpoint_pool_destroy_v1(pool);
}

static void test_explicit_pinned_identity_never_falls_back(void) {
  mesh_mgmt_endpoint_pool_v1_t pool = {0};
  fake_io_t io = {0};
  mesh_mgmt_endpoint_snapshot_v1_t snapshot;
  init_pool(&pool, &io);
  add_peers(&pool, 0);
  set_explicit_policy(&io, PEER_B);
  check_equal(MESH_MGMT_ENDPOINT_POOL_OK,
      mesh_mgmt_endpoint_pool_set_client_policy_v2(&pool, &io.policy));
  check_equal(MESH_MGMT_ENDPOINT_POOL_INVALID_STATE,
      mesh_mgmt_endpoint_pool_set_client_policy_v2(&pool, &io.policy));
  check_equal(MESH_MGMT_ENDPOINT_POOL_OK, mesh_mgmt_endpoint_pool_start_v1(&pool));

  check_equal(MESH_MGMT_ENDPOINT_POOL_OK, mesh_mgmt_endpoint_pool_tick_v2(&pool, 100u));
  check_equal(1u, io.total);
  check_equal(1u, io.attempts[1]);
  check_equal(0u, io.attempts[0] + io.attempts[2]);
  check_equal("beta", io.first_host);
  check_equal(1, io.callback_reentry);
  check_equal(MESH_MGMT_ENDPOINT_POOL_NO_SOURCE, mesh_mgmt_endpoint_pool_tick_v2(&pool, 101u));
  check_equal(1u, io.total);
  check_equal(MESH_MGMT_ENDPOINT_POOL_OK,
      mesh_mgmt_endpoint_pool_snapshot_v1(&pool, PEER_A, &snapshot));
  check_equal(MESH_MGMT_ENDPOINT_IDLE, snapshot.state);
  check_equal(MESH_MGMT_ENDPOINT_POOL_OK,
      mesh_mgmt_endpoint_pool_mark_failed_v1(&pool, PEER_B,
          MESH_MGMT_ENDPOINT_FAILURE_PROTOCOL, 102u));
  check_equal(MESH_MGMT_ENDPOINT_POOL_NO_SOURCE, mesh_mgmt_endpoint_pool_tick_v2(&pool, 110u));
  check_equal(1u, io.total);
  check_equal(MESH_MGMT_ENDPOINT_POOL_OK, mesh_mgmt_endpoint_pool_tick_v2(&pool, 122u));
  check_equal(2u, io.attempts[1]);
  check_equal(0u, io.attempts[0] + io.attempts[2]);
  check_equal(MESH_MGMT_ENDPOINT_POOL_OK,
      mesh_mgmt_endpoint_pool_mark_authenticated_v1(&pool, PEER_B, 123u));
  check_equal(MESH_MGMT_ENDPOINT_POOL_NO_SOURCE, mesh_mgmt_endpoint_pool_tick_v2(&pool, 124u));
  dispose(&pool);
}

static void test_round_robin_commits_one_real_dial_per_turn(void) {
  mesh_mgmt_endpoint_pool_v1_t pool = {0};
  fake_io_t io = {0};
  init_pool(&pool, &io);
  add_peers(&pool, 1);
  set_rr_policy(&io);
  check_equal(MESH_MGMT_ENDPOINT_POOL_OK,
      mesh_mgmt_endpoint_pool_set_client_policy_v2(&pool, &io.policy));
  check_equal(MESH_MGMT_ENDPOINT_POOL_OK, mesh_mgmt_endpoint_pool_start_v1(&pool));
  for (unsigned turn = 0u; turn < 3u; turn++) {
    check_equal(MESH_MGMT_ENDPOINT_POOL_OK, mesh_mgmt_endpoint_pool_tick_v2(&pool, 100u));
    check_equal(turn + 1u, io.total);
  }
  check_equal(1u, io.attempts[0]);
  check_equal(1u, io.attempts[1]);
  check_equal(1u, io.attempts[2]);
  check_equal(MESH_MGMT_ENDPOINT_POOL_NO_SOURCE, mesh_mgmt_endpoint_pool_tick_v2(&pool, 101u));
  check_equal(3u, io.total);
  dispose(&pool);
}

static void test_strict_key_stable_under_record_reordering(void) {
  mesh_mgmt_endpoint_pool_v1_t left = {0}, right = {0};
  fake_io_t first = {0}, second = {0};
  init_pool(&left, &first);
  init_pool(&right, &second);
  add_peers(&left, 0);
  add_peers(&right, 1);
  set_strict_policy(&first, UINT64_C(0xabc123));
  set_strict_policy(&second, UINT64_C(0xabc123));
  check_equal(MESH_MGMT_ENDPOINT_POOL_OK,
      mesh_mgmt_endpoint_pool_set_client_policy_v2(&left, &first.policy));
  check_equal(MESH_MGMT_ENDPOINT_POOL_OK,
      mesh_mgmt_endpoint_pool_set_client_policy_v2(&right, &second.policy));
  check_equal(MESH_MGMT_ENDPOINT_POOL_OK, mesh_mgmt_endpoint_pool_start_v1(&left));
  check_equal(MESH_MGMT_ENDPOINT_POOL_OK, mesh_mgmt_endpoint_pool_start_v1(&right));
  check_equal(MESH_MGMT_ENDPOINT_POOL_OK, mesh_mgmt_endpoint_pool_tick_v2(&left, 100u));
  check_equal(MESH_MGMT_ENDPOINT_POOL_OK, mesh_mgmt_endpoint_pool_tick_v2(&right, 100u));
  check_equal(first.first_host, second.first_host);
  check_equal(1u, first.total);
  check_equal(1u, second.total);
  /* Other entries remain eligible but STRICT_KEY cannot select a neighbor. */
  check_equal(MESH_MGMT_ENDPOINT_POOL_NO_SOURCE, mesh_mgmt_endpoint_pool_tick_v2(&left, 101u));
  check_equal(1u, first.total);
  dispose(&left);
  dispose(&right);
}

static void test_invalid_policy_and_missing_identity_fail_closed(void) {
  mesh_mgmt_endpoint_pool_v1_t pool = {0};
  fake_io_t io = {0};
  init_pool(&pool, &io);
  add_peers(&pool, 0);
  set_strict_policy(&io, 77u);
  io.policy.key_known = false;
  check_equal(MESH_MGMT_ENDPOINT_POOL_INVALID_ARG,
      mesh_mgmt_endpoint_pool_set_client_policy_v2(&pool, &io.policy));
  set_rr_policy(&io);
  io.policy.version++;
  check_equal(MESH_MGMT_ENDPOINT_POOL_INVALID_ARG,
      mesh_mgmt_endpoint_pool_set_client_policy_v2(&pool, &io.policy));
  set_rr_policy(&io);
  io.policy.kind = CNET_DESTINATION_WEIGHTED_RR;
  check_equal(MESH_MGMT_ENDPOINT_POOL_INVALID_ARG,
      mesh_mgmt_endpoint_pool_set_client_policy_v2(&pool, &io.policy));
  set_explicit_policy(&io, PEER_B);
  io.policy.explicit_transport_peer_id[0] = 0x44u;
  check_equal(MESH_MGMT_ENDPOINT_POOL_OK,
      mesh_mgmt_endpoint_pool_set_client_policy_v2(&pool, &io.policy));
  check_equal(MESH_MGMT_ENDPOINT_POOL_OK, mesh_mgmt_endpoint_pool_start_v1(&pool));
  check_equal(MESH_MGMT_ENDPOINT_POOL_NO_SOURCE, mesh_mgmt_endpoint_pool_tick_v2(&pool, 100u));
  check_equal(0u, io.total);
  check_equal(MESH_MGMT_ENDPOINT_POOL_INVALID_STATE, mesh_mgmt_endpoint_pool_tick_v1(&pool, 101u));
  dispose(&pool);
}

spec("CNet 2.3 client destination strategy drives management endpoint admission") {
  it("pins explicit signed transport identity without hidden fallback") {
    test_explicit_pinned_identity_never_falls_back();
  }
  it("uses one bounded Client admission per Owner progress turn") {
    test_round_robin_commits_one_real_dial_per_turn();
  }
  it("keeps rendezvous destination identity stable across registration order") {
    test_strict_key_stable_under_record_reordering();
  }
  it("rejects invalid policy versions and missing explicit signed peers") {
    test_invalid_policy_and_missing_identity_fail_closed();
  }
}
