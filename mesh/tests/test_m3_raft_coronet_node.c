#include <tinytest.h>

#include "m3_raft_node.h"

#include <platform.h>
#include <turbo_error.h>

#include <stdio.h>
#include <string.h>

/* Phase 2b-ii step 2-4: two in-process raft nodes over real CoroNet TLS.
 * Node 1 dials node 2 (deterministic direction), mutual mTLS verifies the
 * peer certificate fingerprint against the identity registry, sessions admit,
 * raft elects a leader and a PUT proposed on the leader converges on both
 * nodes' namespace stores. */

#ifndef M3_TEST_TLS_DIR
#define M3_TEST_TLS_DIR "mesh/tests/data/m3tls"
#endif

static const char k_node1_fingerprint[] =
    "sha256:a9a12784e612bd3ced3dbc4ec6b9f1f58b84a4592650fda8be88f5d777f49800";
static const char k_node2_fingerprint[] =
    "sha256:66a4ee96d3c72dacc600ecda40ff0d3a308e2bf06a1ff2d45e74d36d88e7f465";
static const char k_node3_fingerprint[] =
    "sha256:56fdbb74472b0d77a2fc182a44be32a41c4b9dbfab34a6cc68374b50066d24e1";

typedef struct {
  m3_raft_node_t *node;
  uint64_t target_index;
  int done;
} converge_state_t;

static int converge_done(void *ctx, m3_raft_node_t *node) {
  converge_state_t *state = (converge_state_t *)ctx;
  (void)node;
  if (m3_raft_node_applied_index(state->node) >= state->target_index) {
    state->done = 1;
    return 1;
  }
  return 0;
}

static int leader_elected(void *ctx, m3_raft_node_t *node) {
  int leader = 0;
  (void)ctx;
  if (m3_raft_node_is_leader(node, &leader) == TURBO_OK && leader) {
    return 1;
  }
  return 0;
}

static int connections_up(void *ctx, m3_raft_node_t *node) {
  int leader = 0;
  (void)ctx;
  /* A leader can only be elected after the mTLS session admitted and raft
   * messages flowed, so leader election is the connection+quorum proof. */
  return m3_raft_node_is_leader(node, &leader) == TURBO_OK && leader;
}

static int make_manifest(uint8_t **out_bytes, size_t *out_size) {
  m3_object_manifest_v1_t manifest;

  memset(&manifest, 0, sizeof(manifest));
  manifest.version = M3_OBJECT_MANIFEST_VERSION;
  manifest.object_cid.hash_algorithm = M3_CHUNK_STORE_HASH_ALGORITHM_SHA256;
  manifest.object_cid.size = 0u;
  memset(manifest.object_cid.digest, 1u, sizeof(manifest.object_cid.digest));
  manifest.chunks = NULL;
  manifest.chunk_count = 0u;
  return m3_object_manifest_encode_v1(&manifest, UINT64_C(1) << 30, 4096u,
                                      out_bytes, out_size) ==
                 M3_OBJECT_MANIFEST_OK
             ? 0
             : -1;
}

static void configure_peer(m3_raft_node_peer_config_t *peer, tr_raft_node_id_t id,
                           int port, const char *fingerprint) {
  memset(peer, 0, sizeof(*peer));
  peer->node_id = id;
  strcpy(peer->connect_host, "127.0.0.1");
  strcpy(peer->request_host, "localhost");
  peer->port = port;
  strcpy(peer->certificate_sha256, fingerprint);
}

static m3_raft_node_t *create_node(tr_raft_node_id_t node_id, int listen_port,
                                   const char *sqlite,
                                   const tr_raft_node_id_t *voters,
                                   size_t voter_count,
                                   const m3_raft_node_peer_config_t *peers,
                                   size_t peer_count, const char *cert,
                                   const char *key) {
  m3_raft_node_config_t config;
  m3_raft_node_t *node = NULL;
  char cert_path[256];
  char key_path[256];
  char ca_path[256];

  snprintf(cert_path, sizeof(cert_path), "%s/%s", M3_TEST_TLS_DIR, cert);
  snprintf(key_path, sizeof(key_path), "%s/%s", M3_TEST_TLS_DIR, key);
  snprintf(ca_path, sizeof(ca_path), "%s/m3ca.crt", M3_TEST_TLS_DIR);

  memset(&config, 0, sizeof(config));
  config.node_id = node_id;
  config.listen_host = "127.0.0.1";
  config.listen_port = listen_port;
  config.sqlite_path = sqlite;
  config.cert_file = cert_path;
  config.key_file = key_path;
  config.ca_file = ca_path;
  config.voters = voters;
  config.voter_count = voter_count;
  config.peers = peers;
  config.peer_count = peer_count;
  config.max_snapshot_bytes = 4u * 1024 * 1024;
  config.max_pending_reads = 64u;
  check_int_eq(TURBO_OK, m3_raft_node_create(&config, &node));
  return node;
}

/* Drive up to three node loops until one node reports leader (quorum
 * election). Returns the leader node (or NULL on timeout). */
static m3_raft_node_t *drive_until_leader(m3_raft_node_t *nodes[3], size_t count,
                                          uint64_t timeout_ms) {
  uint64_t deadline = turbo_monotonic_ms() + timeout_ms;
  m3_raft_node_t *leader = NULL;

  while (turbo_monotonic_ms() < deadline && leader == NULL) {
    for (size_t i = 0u; i < count; ++i) {
      int is_leader = 0;
      if (m3_raft_node_poll(nodes[i]) != TURBO_OK) {
        return NULL;
      }
      if (m3_raft_node_is_leader(nodes[i], &is_leader) == TURBO_OK && is_leader) {
        leader = nodes[i];
        break;
      }
    }
  }
  return leader;
}

/* Drive up to three node loops until every node applied >= target. */
static int drive_until_applied(m3_raft_node_t *nodes[3], size_t count,
                               uint64_t target, uint64_t timeout_ms) {
  uint64_t deadline = turbo_monotonic_ms() + timeout_ms;
  int all_applied = 0;

  while (turbo_monotonic_ms() < deadline && !all_applied) {
    all_applied = 1;
    for (size_t i = 0u; i < count; ++i) {
      if (m3_raft_node_poll(nodes[i]) != TURBO_OK) {
        return 0;
      }
      if (m3_raft_node_applied_index(nodes[i]) < target) {
        all_applied = 0;
      }
    }
  }
  return all_applied;
}

/* Drive up to three node loops until the linearizable read completes. */
static int drive_until_read(m3_raft_node_t *nodes[3], size_t count,
                            m3_raft_node_lookup_t *handle, int *out_found,
                            uint64_t timeout_ms) {
  uint64_t deadline = turbo_monotonic_ms() + timeout_ms;
  int done = 0;

  while (turbo_monotonic_ms() < deadline && !done) {
    for (size_t i = 0u; i < count; ++i) {
      if (m3_raft_node_poll(nodes[i]) != TURBO_OK) {
        return 0;
      }
    }
    check_int_eq(TURBO_OK, m3_raft_node_lookup_try(handle, out_found, &done));
  }
  return done;
}

static void test_two_node_quorum_commit(void) {
  const char *sqlite1 = ":memory:";
  const char *sqlite2 = ":memory:";
  m3_raft_node_t *node1 = NULL;
  m3_raft_node_t *node2 = NULL;
  m3_raft_node_t *leader = NULL;
  uint64_t before;
  uint8_t tenant[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE];
  uint8_t *manifest = NULL;
  size_t manifest_size = 0u;
  int found1 = 0;
  int found2 = 0;

  {
    static const tr_raft_node_id_t voters[] = {1u, 2u};
    m3_raft_node_peer_config_t peer1[1];
    m3_raft_node_peer_config_t peer2[1];
    configure_peer(&peer1[0], 2u, 19402, k_node2_fingerprint);
    configure_peer(&peer2[0], 1u, 19401, k_node1_fingerprint);
    node1 = create_node(1u, 19401, sqlite1, voters, 2u, peer1, 1u, "node1.crt",
                        "node1.key");
    node2 = create_node(2u, 19402, sqlite2, voters, 2u, peer2, 1u, "node2.crt",
                        "node2.key");
  }
  check_not_null(node1);
  check_not_null(node2);

  /* Drive both event loops until one node is elected leader (this requires
   * the mTLS session, handshake and raft message flow to all work). */
  {
    uint64_t deadline = turbo_monotonic_ms() + 15000u;
    int elected = 0;
    while (turbo_monotonic_ms() < deadline && !elected) {
      int is_leader = 0;
      if (m3_raft_node_poll(node1) != TURBO_OK ||
          m3_raft_node_poll(node2) != TURBO_OK) {
        break;
      }
      if (m3_raft_node_is_leader(node1, &is_leader) == TURBO_OK && is_leader) {
        leader = node1;
        elected = 1;
      } else if (m3_raft_node_is_leader(node2, &is_leader) == TURBO_OK && is_leader) {
        leader = node2;
        elected = 1;
      }
    }
    if (!elected) {
      m3_raft_node_status_t s1;
      m3_raft_node_status_t s2;
      memset(&s1, 0, sizeof(s1));
      memset(&s2, 0, sizeof(s2));
      (void)m3_raft_node_status(node1, &s1);
      (void)m3_raft_node_status(node2, &s2);
      fprintf(stderr,
              "m3 node election timeout n1(conn=%zu queued=%zu pump=%d) "
              "n2(conn=%zu queued=%zu pump=%d)\n",
              s1.connected_peers, s1.queued_messages, s1.last_pump_error,
              s2.connected_peers, s2.queued_messages, s2.last_pump_error);
    }
    check_true(elected);
  }
  check_not_null(leader);

  memset(tenant, 0x77, sizeof(tenant));
  check_int_eq(0, make_manifest(&manifest, &manifest_size));
  before = m3_raft_node_applied_index(leader);
  check_int_eq(TURBO_OK,
               m3_raft_node_propose_put(leader, tenant, "bucket-a", "obj-1",
                                        manifest, manifest_size));

  {
    converge_state_t s1;
    converge_state_t s2;
    memset(&s1, 0, sizeof(s1));
    memset(&s2, 0, sizeof(s2));
    s1.node = node1;
    s1.target_index = before + 1u;
    s2.node = node2;
    s2.target_index = before + 1u;
    {
      uint64_t deadline = turbo_monotonic_ms() + 15000u;
      while (turbo_monotonic_ms() < deadline && (!s1.done || !s2.done)) {
        if (m3_raft_node_poll(node1) != TURBO_OK ||
            m3_raft_node_poll(node2) != TURBO_OK) {
          break;
        }
        (void)converge_done(&s1, node1);
        (void)converge_done(&s2, node2);
      }
    }
    check_true(s1.done);
    check_true(s2.done);
  }

  /* Linearizable reads are leader-only. Drive the read-index barrier with
   * both node loops (the barrier needs the follower to respond), then verify
   * the leader sees the object and the follower rejects the read. */
  {
    m3_raft_node_lookup_t *handle = NULL;
    int done = 0;
    uint64_t deadline = turbo_monotonic_ms() + 15000u;
    check_int_eq(TURBO_OK,
                 m3_raft_node_lookup_start(leader, tenant, "bucket-a", "obj-1", &handle));
    /* Keep pumping both loops until the barrier completes; release only after
     * completion so the adapter never writes into a freed capture. */
    while (!done && turbo_monotonic_ms() < deadline) {
      (void)m3_raft_node_poll(node1);
      (void)m3_raft_node_poll(node2);
      check_int_eq(TURBO_OK, m3_raft_node_lookup_try(handle, &found1, &done));
    }
    check_true(done);
    check_int_eq(1, found1);
    if (done) {
      m3_raft_node_lookup_release(handle);
    }
  }
  {
    m3_raft_node_t *follower = (leader == node1) ? node2 : node1;
    check_int_eq(TURBO_EPROTO,
                 m3_raft_node_lookup(follower, tenant, "bucket-a", "obj-1", &found2));
    check_int_eq(0, found2);
  }

  m3_raft_node_destroy(node2);
  m3_raft_node_destroy(node1);
  m3_object_manifest_bytes_free_v1(manifest);
}


static void test_three_node_quorum_commit(void) {
  static const tr_raft_node_id_t voters[] = {1u, 2u, 3u};
  m3_raft_node_peer_config_t peers1[2];
  m3_raft_node_peer_config_t peers2[2];
  m3_raft_node_peer_config_t peers3[2];
  m3_raft_node_t *nodes[3] = {NULL, NULL, NULL};
  m3_raft_node_t *leader = NULL;
  uint8_t tenant[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE];
  uint8_t *manifest = NULL;
  size_t manifest_size = 0u;
  uint64_t before;
  int found = 0;

  configure_peer(&peers1[0], 2u, 19501, k_node2_fingerprint);
  configure_peer(&peers1[1], 3u, 19502, k_node3_fingerprint);
  configure_peer(&peers2[0], 1u, 19500, k_node1_fingerprint);
  configure_peer(&peers2[1], 3u, 19502, k_node3_fingerprint);
  configure_peer(&peers3[0], 1u, 19500, k_node1_fingerprint);
  configure_peer(&peers3[1], 2u, 19501, k_node2_fingerprint);

  nodes[0] = create_node(1u, 19500, ":memory:", voters, 3u, peers1, 2u,
                         "node1.crt", "node1.key");
  nodes[1] = create_node(2u, 19501, ":memory:", voters, 3u, peers2, 2u,
                         "node2.crt", "node2.key");
  nodes[2] = create_node(3u, 19502, ":memory:", voters, 3u, peers3, 2u,
                         "node3.crt", "node3.key");
  check_not_null(nodes[0]);
  check_not_null(nodes[1]);
  check_not_null(nodes[2]);

  /* Quorum is 2 of 3: a leader needs one follower vote plus itself. */
  leader = drive_until_leader(nodes, 3u, 20000u);
  check_not_null(leader);

  memset(tenant, 0x77, sizeof(tenant));
  check_int_eq(0, make_manifest(&manifest, &manifest_size));
  before = m3_raft_node_applied_index(leader);
  check_int_eq(TURBO_OK,
               m3_raft_node_propose_put(leader, tenant, "bucket-b", "obj-2",
                                        manifest, manifest_size));

  /* All three nodes must converge past the proposed index. */
  check_true(drive_until_applied(nodes, 3u, before + 1u, 20000u));

  {
    m3_raft_node_lookup_t *handle = NULL;
    check_int_eq(TURBO_OK,
                 m3_raft_node_lookup_start(leader, tenant, "bucket-b", "obj-2",
                                           &handle));
    check_true(drive_until_read(nodes, 3u, handle, &found, 20000u));
    check_int_eq(1, found);
    m3_raft_node_lookup_release(handle);
  }

  for (size_t i = 0u; i < 3u; ++i) {
    m3_raft_node_destroy(nodes[i]);
  }
  m3_object_manifest_bytes_free_v1(manifest);
}


static void test_three_node_leader_switch_after_crash(void) {
  static const tr_raft_node_id_t voters[] = {1u, 2u, 3u};
  m3_raft_node_peer_config_t peers1[2];
  m3_raft_node_peer_config_t peers2[2];
  m3_raft_node_peer_config_t peers3[2];
  m3_raft_node_t *nodes[3] = {NULL, NULL, NULL};
  m3_raft_node_t *leader = NULL;
  m3_raft_node_t *survivors[2] = {NULL, NULL};
  size_t leader_index = SIZE_MAX;
  size_t survivor_count = 0u;
  uint8_t tenant[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE];
  uint8_t *manifest = NULL;
  size_t manifest_size = 0u;
  tr_raft_node_id_t leader_id = 0u;
  tr_raft_node_id_t new_leader_id = 0u;
  uint64_t before;
  int found = 0;

  configure_peer(&peers1[0], 2u, 19601, k_node2_fingerprint);
  configure_peer(&peers1[1], 3u, 19602, k_node3_fingerprint);
  configure_peer(&peers2[0], 1u, 19600, k_node1_fingerprint);
  configure_peer(&peers2[1], 3u, 19602, k_node3_fingerprint);
  configure_peer(&peers3[0], 1u, 19600, k_node1_fingerprint);
  configure_peer(&peers3[1], 2u, 19601, k_node2_fingerprint);

  nodes[0] = create_node(1u, 19600, ":memory:", voters, 3u, peers1, 2u,
                         "node1.crt", "node1.key");
  nodes[1] = create_node(2u, 19601, ":memory:", voters, 3u, peers2, 2u,
                         "node2.crt", "node2.key");
  nodes[2] = create_node(3u, 19602, ":memory:", voters, 3u, peers3, 2u,
                         "node3.crt", "node3.key");
  check_not_null(nodes[0]);
  check_not_null(nodes[1]);
  check_not_null(nodes[2]);

  memset(tenant, 0x77, sizeof(tenant));
  check_int_eq(0, make_manifest(&manifest, &manifest_size));

  /* Phase A: elect, commit PUT "crash-a", converge everywhere. */
  leader = drive_until_leader(nodes, 3u, 20000u);
  check_not_null(leader);
  check_int_eq(TURBO_OK, m3_raft_node_leader(leader, &leader_id));
  check_true(leader_id != 0u);
  before = m3_raft_node_applied_index(leader);
  check_int_eq(TURBO_OK,
               m3_raft_node_propose_put(leader, tenant, "crash-a", "obj-a",
                                        manifest, manifest_size));
  check_true(drive_until_applied(nodes, 3u, before + 1u, 20000u));

  /* Read back on the leader before the crash. */
  {
    m3_raft_node_lookup_t *handle = NULL;
    check_int_eq(TURBO_OK,
                 m3_raft_node_lookup_start(leader, tenant, "crash-a", "obj-a",
                                           &handle));
    check_true(drive_until_read(nodes, 3u, handle, &found, 20000u));
    check_int_eq(1, found);
    m3_raft_node_lookup_release(handle);
  }

  /* Phase B: crash the leader; the two survivors (quorum of 3) must elect a
   * new leader and keep committing without the dead peer faulting them. */
  for (size_t i = 0u; i < 3u; ++i) {
    if (nodes[i] == leader) {
      leader_index = i;
    } else {
      survivors[survivor_count++] = nodes[i];
    }
  }
  check_size_eq(2u, survivor_count);
  m3_raft_node_destroy(leader);
  nodes[leader_index] = NULL;

  {
    m3_raft_node_t *new_leader = NULL;
    int elected = 0;
    uint64_t deadline = turbo_monotonic_ms() + 20000u;
    while (turbo_monotonic_ms() < deadline && !elected) {
      for (size_t i = 0u; i < survivor_count; ++i) {
        int is_leader = 0;
        if (m3_raft_node_poll(survivors[i]) != TURBO_OK) {
          break;
        }
        if (m3_raft_node_is_leader(survivors[i], &is_leader) == TURBO_OK &&
            is_leader) {
          new_leader = survivors[i];
          elected = 1;
          break;
        }
      }
    }
    check_true(elected);
    check_not_null(new_leader);
    check_true(new_leader != leader);

    /* A newly elected leader must commit an entry in its own term before
     * serving linearizable reads (raft invariant). Commit "crash-b" first;
     * quorum is 2 of 3, so the dead peer does not block the commit. */
    check_int_eq(TURBO_OK, m3_raft_node_leader(new_leader, &new_leader_id));
    check_true(new_leader_id != 0u);
    check_true(new_leader_id != leader_id);
    before = m3_raft_node_applied_index(new_leader);
    check_int_eq(TURBO_OK,
                 m3_raft_node_propose_put(new_leader, tenant, "crash-b",
                                          "obj-b", manifest, manifest_size));
    check_true(drive_until_applied(survivors, survivor_count, before + 1u,
                                   20000u));

    /* The new leader must still serve the pre-crash committed object: the
     * committed entry survives the leader switch (no committed-entry loss). */
    {
      m3_raft_node_lookup_t *handle = NULL;
      check_int_eq(TURBO_OK,
                   m3_raft_node_lookup_start(new_leader, tenant, "crash-a",
                                             "obj-a", &handle));
      check_true(drive_until_read(survivors, survivor_count, handle, &found,
                                  20000u));
      check_int_eq(1, found);
      m3_raft_node_lookup_release(handle);
    }

    /* Survivors agree on the new leader id. */
    for (size_t i = 0u; i < survivor_count; ++i) {
      tr_raft_node_id_t reported = 0u;
      check_int_eq(TURBO_OK, m3_raft_node_leader(survivors[i], &reported));
      check_int_eq((int)new_leader_id, (int)reported);
    }

    for (size_t i = 0u; i < survivor_count; ++i) {
      m3_raft_node_destroy(survivors[i]);
    }
  }
  m3_object_manifest_bytes_free_v1(manifest);
}


static void test_two_node_transient_partition_heals(void) {
  static const tr_raft_node_id_t voters[] = {1u, 2u};
  m3_raft_node_peer_config_t peer1[1];
  m3_raft_node_peer_config_t peer2[1];
  m3_raft_node_t *nodes[2] = {NULL, NULL};
  m3_raft_node_t *leader = NULL;
  uint8_t tenant[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE];
  uint8_t *manifest = NULL;
  size_t manifest_size = 0u;
  uint64_t before;

  configure_peer(&peer1[0], 2u, 19702, k_node2_fingerprint);
  configure_peer(&peer2[0], 1u, 19701, k_node1_fingerprint);
  nodes[0] = create_node(1u, 19701, ":memory:", voters, 2u, peer1, 1u, "node1.crt",
                         "node1.key");
  nodes[1] = create_node(2u, 19702, ":memory:", voters, 2u, peer2, 1u, "node2.crt",
                         "node2.key");
  check_not_null(nodes[0]);
  check_not_null(nodes[1]);

  memset(tenant, 0x77, sizeof(tenant));
  check_int_eq(0, make_manifest(&manifest, &manifest_size));

  /* Phase A: elect and commit "part-a" on both nodes. */
  leader = drive_until_leader(nodes, 2u, 20000u);
  check_not_null(leader);
  before = m3_raft_node_applied_index(leader);
  check_int_eq(TURBO_OK,
               m3_raft_node_propose_put(leader, tenant, "part-a", "obj-a",
                                        manifest, manifest_size));
  check_true(drive_until_applied(nodes, 2u, before + 1u, 20000u));

  /* Phase B: transient partition. Node 1 always dials node 2, so closing that
   * session isolates the pair regardless of who is leader. */
  check_int_eq(TURBO_OK, m3_raft_node_disconnect_peer(nodes[0], 2u));

  /* While partitioned, a proposal on the leader must NOT commit (no quorum).
   * Poll only the leader so the other side cannot ack. */
  before = m3_raft_node_applied_index(leader);
  check_int_eq(TURBO_OK,
               m3_raft_node_propose_put(leader, tenant, "part-b", "obj-b",
                                        manifest, manifest_size));
  for (size_t i = 0u; i < 200u; i++) {
    (void)m3_raft_node_poll(leader);
  }
  check_int_eq((int)before, (int)m3_raft_node_applied_index(leader));

  /* Heal: drive both loops; the dial scheduler reconnects and the follower
   * catches up with the queued append. */
  check_true(drive_until_applied(nodes, 2u, before + 1u, 20000u));

  /* No committed-entry loss: both part-a and part-b are readable on the
   * leader after the partition healed. */
  {
    m3_raft_node_lookup_t *handle = NULL;
    int found = 0;
    check_int_eq(TURBO_OK,
                 m3_raft_node_lookup_start(leader, tenant, "part-a", "obj-a",
                                           &handle));
    check_true(drive_until_read(nodes, 2u, handle, &found, 20000u));
    check_int_eq(1, found);
    m3_raft_node_lookup_release(handle);
  }
  {
    m3_raft_node_lookup_t *handle = NULL;
    int found = 0;
    check_int_eq(TURBO_OK,
                 m3_raft_node_lookup_start(leader, tenant, "part-b", "obj-b",
                                           &handle));
    check_true(drive_until_read(nodes, 2u, handle, &found, 20000u));
    check_int_eq(1, found);
    m3_raft_node_lookup_release(handle);
  }

  for (size_t i = 0u; i < 2u; i++) {
    m3_raft_node_destroy(nodes[i]);
  }
  m3_object_manifest_bytes_free_v1(manifest);
}

spec("m3 raft coronet node") {
  describe("CoroNet TLS raft deployment") {
    it("elects a leader and converges a PUT on both nodes") {
      test_two_node_quorum_commit();
    }
    it("elects a leader and converges a PUT on three voters (quorum 2)") {
      test_three_node_quorum_commit();
    }
    it("switches leader after a crash and keeps committing (quorum 2 of 3)") {
      test_three_node_leader_switch_after_crash();
    }
    it("heals after a transient partition (no commit without quorum)") {
      test_two_node_transient_partition_heals();
    }
  }
}
