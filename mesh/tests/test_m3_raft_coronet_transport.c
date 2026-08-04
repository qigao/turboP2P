#include <tinytest.h>

#include <turbo_error.h>
#include <turboraft/raft_coronet_transport.h>

#include <string.h>

/* Phase 2b-ii groundwork: verify the CoroNet raft transport component API
 * (deterministic dial direction, peer manager config validation, certificate
 * identity resolution) so a real multi-process deployment can build on it. */

static void test_expected_direction_rules(void) {
  tr_raft_coronet_connection_direction_t direction;

  /* The smaller node ID dials outbound; the larger accepts inbound. */
  check_int_eq(TR_RAFT_CORONET_CONNECTION_OUTBOUND,
               tr_raft_coronet_expected_direction(1u, 2u, &direction) == TURBO_OK ? direction : -1);
  check_int_eq(TR_RAFT_CORONET_CONNECTION_INBOUND,
               tr_raft_coronet_expected_direction(2u, 1u, &direction) == TURBO_OK ? direction : -1);
  check_int_eq(TR_RAFT_CORONET_CONNECTION_OUTBOUND,
               tr_raft_coronet_expected_direction(1u, 3u, &direction) == TURBO_OK ? direction : -1);
  check_int_eq(TR_RAFT_CORONET_CONNECTION_INBOUND,
               tr_raft_coronet_expected_direction(3u, 1u, &direction) == TURBO_OK ? direction : -1);
  /* Same node id is invalid. */
  check_int_ne(TURBO_OK, tr_raft_coronet_expected_direction(1u, 1u, &direction));
}

static void test_peer_manager_config_validation(void) {
  static const tr_raft_node_id_t peers[] = {2u, 3u, 4u};
  static const tr_raft_node_id_t duplicate[] = {2u, 2u, 4u};
  static const tr_raft_node_id_t unsorted[] = {3u, 2u, 4u};
  static const tr_raft_node_id_t contains_self[] = {1u, 2u, 3u};
  tr_raft_coronet_peer_manager_config_t config;
  tr_raft_coronet_peer_manager_t *manager = NULL;
  tr_raft_coronet_peer_manager_t *bad = NULL;

  memset(&config, 0, sizeof(config));
  memset(&config.cluster_id, 0x3c, sizeof(config.cluster_id));
  config.local_node_id = 1u;
  config.peer_node_ids = peers;
  config.peer_count = 3u;
  check_int_eq(TURBO_OK, tr_raft_coronet_peer_manager_create(&config, &manager));
  check_not_null(manager);
  check_int_eq(TURBO_OK, tr_raft_coronet_peer_manager_destroy(manager));

  /* Duplicate peer ids must be rejected. */
  config.peer_node_ids = duplicate;
  check_int_eq(TURBO_EINVAL, tr_raft_coronet_peer_manager_create(&config, &bad));
  /* Unsorted ids must be rejected. */
  config.peer_node_ids = unsorted;
  check_int_eq(TURBO_EINVAL, tr_raft_coronet_peer_manager_create(&config, &bad));
  /* Peer list containing the local id must be rejected. */
  config.peer_node_ids = contains_self;
  check_int_eq(TURBO_EINVAL, tr_raft_coronet_peer_manager_create(&config, &bad));
  /* An empty peer list is accepted (single-node transport). */
  config.peer_node_ids = peers;
  config.peer_count = 0u;
  check_int_eq(TURBO_OK, tr_raft_coronet_peer_manager_create(&config, &manager));
  check_int_eq(TURBO_OK, tr_raft_coronet_peer_manager_destroy(manager));
}

static void test_identity_registry_resolution(void) {
  tr_raft_coronet_identity_entry_t entries[2];
  tr_raft_coronet_identity_registry_t *registry = NULL;
  tr_raft_node_id_t node_id = 0u;

  memset(entries, 0, sizeof(entries));
  strcpy(entries[0].certificate_sha256,
         "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
  entries[0].node_id = 1u;
  strcpy(entries[1].certificate_sha256,
         "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
  entries[1].node_id = 2u;

  check_int_eq(TURBO_OK, tr_raft_coronet_identity_registry_create(entries, 2u, &registry));
  check_not_null(registry);
  check_int_eq(TURBO_OK, tr_raft_coronet_identity_registry_resolve(
                             registry, entries[1].certificate_sha256, &node_id));
  check_int_eq(2u, node_id);
  {
    char unknown[CORO_TLS_PEER_CERT_SHA256_CAPACITY];
    strcpy(unknown, "sha256:1111111111111111111111111111111111111111111111111111111111111111");
    check_true(tr_raft_coronet_identity_registry_resolve(registry, unknown, &node_id) != TURBO_OK);
  }
  tr_raft_coronet_identity_registry_destroy(registry);
}

spec("m3 raft coronet transport") {
  describe("CoroNet raft transport component API") {
    it("deterministically assigns dial direction by node id") { test_expected_direction_rules(); }
    it("validates peer manager configuration") { test_peer_manager_config_validation(); }
    it("resolves certificate identities to node ids") { test_identity_registry_resolution(); }
  }
}
