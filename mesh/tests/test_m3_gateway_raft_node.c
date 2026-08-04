#include <tinytest.h>

#include "m3_gateway.h"
#include "m3_object_manifest.h"
#include "m3_raft_node.h"

#include <platform.h>
#include <turbo_error.h>

#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#endif

/* Step 6: leader read routing for the M3 gateway. Two gateways each embed a
 * two-voter raft node; metadata PUT replicates through raft, reads are served
 * via the linearizable read-index barrier on the leader, and the follower
 * reports NOT_LEADER with the leader id so the caller can route. */

#ifndef M3_TEST_TLS_DIR
#define M3_TEST_TLS_DIR "mesh/tests/data/m3tls"
#endif

static const char k_node1_fingerprint[] =
    "sha256:a9a12784e612bd3ced3dbc4ec6b9f1f58b84a4592650fda8be88f5d777f49800";
static const char k_node2_fingerprint[] =
    "sha256:66a4ee96d3c72dacc600ecda40ff0d3a308e2bf06a1ff2d45e74d36d88e7f465";

static void fill_credential(m3_sigv4_credential_v1_t *cred) {
  memset(cred, 0, sizeof(*cred));
  strcpy(cred->access_key, "AKIDEXAMPLE");
  cred->region = "us-east-1";
  cred->service = "s3";
  cred->clock_skew_seconds = 900;
  for (int i = 0; i < 32; i++) {
    cred->secret_key[i] = (uint8_t)(0x60 + i);
  }
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

typedef struct {
  int count;
  char key[64];
} list_capture_v1_t;

static void list_capture_cb(const uint8_t *bucket, size_t bucket_size,
                            const uint8_t *object_key, size_t object_key_size,
                            const uint8_t *manifest_bytes, size_t manifest_size,
                            void *user_data) {
  list_capture_v1_t *capture = (list_capture_v1_t *)user_data;
  (void)bucket;
  (void)bucket_size;
  (void)manifest_bytes;
  (void)manifest_size;
  if (capture != NULL && capture->count < 4 && object_key_size < sizeof(capture->key)) {
    memcpy(capture->key, object_key, object_key_size);
    capture->key[object_key_size] = 0;
    capture->count++;
  }
}

static void list_bucket_capture_cb(const uint8_t *bucket, size_t bucket_size,
                                     const uint8_t *object_key, size_t object_key_size,
                                     const uint8_t *manifest_bytes, size_t manifest_size,
                                     void *user_data) {
  list_capture_v1_t *capture = (list_capture_v1_t *)user_data;
  (void)object_key;
  (void)object_key_size;
  (void)manifest_bytes;
  (void)manifest_size;
  if (capture != NULL && capture->count < 4 && bucket_size < sizeof(capture->key)) {
    memcpy(capture->key, bucket, bucket_size);
    capture->key[bucket_size] = 0;
    capture->count++;
  }
}

static void make_store_dir(char *path, size_t cap, const char *tag) {
#ifdef _WIN32
  char tmp[MAX_PATH];
  DWORD len = GetTempPathA((DWORD)sizeof(tmp), tmp);
  if (len == 0u || len >= sizeof(tmp)) {
    strcpy(path, tag);
  } else {
    snprintf(path, cap, "%s%s-%lu", tmp, tag, (unsigned long)GetCurrentProcessId());
  }
  _mkdir(path);
#else
  snprintf(path, cap, "/tmp/%s-%d", tag, (int)getpid());
  mkdir(path, 0755);
#endif
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

static void create_gateway(m3_gateway_t *gateway, tr_raft_node_id_t node_id,
                           int listen_port, int peer_port, tr_raft_node_id_t peer_id,
                           const char *peer_fingerprint, const char *store_root,
                           const char *cert, const char *key) {
  static const tr_raft_node_id_t voters[] = {1u, 2u};
  m3_raft_node_config_t config;
  m3_raft_node_peer_config_t peers[1];
  m3_sigv4_credential_v1_t credential;
  char cert_path[256];
  char key_path[256];
  char ca_path[256];

  snprintf(cert_path, sizeof(cert_path), "%s/%s", M3_TEST_TLS_DIR, cert);
  snprintf(key_path, sizeof(key_path), "%s/%s", M3_TEST_TLS_DIR, key);
  snprintf(ca_path, sizeof(ca_path), "%s/m3ca.crt", M3_TEST_TLS_DIR);
  configure_peer(&peers[0], peer_id, peer_port, peer_fingerprint);

  memset(&config, 0, sizeof(config));
  config.node_id = node_id;
  config.listen_host = "127.0.0.1";
  config.listen_port = listen_port;
  config.sqlite_path = ":memory:";
  config.cert_file = cert_path;
  config.key_file = key_path;
  config.ca_file = ca_path;
  config.voters = voters;
  config.voter_count = 2u;
  config.peers = peers;
  config.peer_count = 1u;
  config.max_snapshot_bytes = 4u * 1024 * 1024;
  config.max_pending_reads = 64u;

  fill_credential(&credential);
  check_int_eq(0, m3_gateway_init_node_v1(gateway, store_root, UINT64_C(1024) * 1024,
                                          &credential, 1024u, &config));
}

static void drive_both(m3_gateway_t *g1, m3_gateway_t *g2) {
  m3_gateway_poll_v1(g1);
  m3_gateway_poll_v1(g2);
}

static m3_gateway_t *drive_until_leader(m3_gateway_t *g1, m3_gateway_t *g2,
                                        uint64_t timeout_ms) {
  uint64_t deadline = turbo_monotonic_ms() + timeout_ms;
  while (turbo_monotonic_ms() < deadline) {
    int l1 = 0;
    int l2 = 0;
    drive_both(g1, g2);
    if (m3_raft_node_is_leader(g1->node, &l1) == TURBO_OK && l1) {
      return g1;
    }
    if (m3_raft_node_is_leader(g2->node, &l2) == TURBO_OK && l2) {
      return g2;
    }
  }
  return NULL;
}

static void test_two_gateway_leader_routing(void) {
  m3_gateway_t gateway1;
  m3_gateway_t gateway2;
  m3_gateway_t *leader = NULL;
  m3_gateway_t *follower = NULL;
  m3_gateway_lookup_result_v1_t lr;
  tr_raft_node_id_t leader_id = 0u;
  char store1[512];
  char store2[512];
  uint8_t *manifest = NULL;
  size_t manifest_size = 0u;
  uint8_t out[4096];
  size_t out_size = 0u;
  int put_rc;

  memset(&gateway1, 0, sizeof(gateway1));
  memset(&gateway2, 0, sizeof(gateway2));
  check_int_eq(0, make_manifest(&manifest, &manifest_size));
  {
    /* Sanity: the manifest must decode under the store's limits (empty
     * object with zero chunks) before it can be applied. */
    m3_object_manifest_owned_v1_t dec = {0};
    check_int_eq(M3_OBJECT_MANIFEST_OK,
                 m3_object_manifest_decode_v1(manifest, manifest_size,
                                              UINT64_C(1) << 30, 4096u, &dec));
    m3_object_manifest_owned_destroy_v1(&dec);
  }
  make_store_dir(store1, sizeof(store1), "m3-gw-node1");
  make_store_dir(store2, sizeof(store2), "m3-gw-node2");

  create_gateway(&gateway1, 1u, 19701, 19702, 2u, k_node2_fingerprint, store1,
                 "node1.crt", "node1.key");
  create_gateway(&gateway2, 2u, 19702, 19701, 1u, k_node1_fingerprint, store2,
                 "node2.crt", "node2.key");

  leader = drive_until_leader(&gateway1, &gateway2, 20000u);
  check_not_null(leader);
  follower = (leader == &gateway1) ? &gateway2 : &gateway1;
  check_true(m3_gateway_leader_v1(leader, &leader_id) == 0 && leader_id != 0u);

  /* A follower rejects metadata mutations with NOT_LEADER (1). */
  put_rc = m3_gateway_meta_put_v1(follower, "bkt", "obj", manifest, manifest_size);
  check_int_eq(1, put_rc);

  /* The leader starts the PUT; both node loops are driven until the proposal
   * applies locally (quorum needs the follower's ack, which requires pumping
   * the follower's loop too). */
  check_int_eq(0, m3_gateway_meta_put_start_v1(leader, "bkt", "obj", manifest,
                                               manifest_size));
  {
    uint64_t deadline = turbo_monotonic_ms() + 10000u;
    while (turbo_monotonic_ms() < deadline &&
           m3_gateway_meta_mutation_pending_v1(leader)) {
      drive_both(&gateway1, &gateway2);
    }
    check_true(!m3_gateway_meta_mutation_pending_v1(leader));
  }
  {
    int done = 0;
    uint64_t deadline = turbo_monotonic_ms() + 10000u;
    memset(&lr, 0, sizeof(lr));
    check_int_eq(0, m3_gateway_meta_lookup_start_v1(leader, "bkt", "obj", out,
                                                    sizeof(out), &out_size, &lr));
    while (turbo_monotonic_ms() < deadline && !done) {
      drive_both(&gateway1, &gateway2);
      (void)m3_gateway_meta_lookup_try_v1(leader, &lr, &done);
    }
    check_true(done);
  }
  check_int_eq(1, lr.found);
  check_size_eq(manifest_size, out_size);
  check_mem_eq(manifest, out, manifest_size);

  /* The leader lists the committed object; the follower routes lists to the
   * leader (NOT_LEADER). */
  {
    list_capture_v1_t cap;
    memset(&cap, 0, sizeof(cap));
    check_int_eq(0, m3_gateway_meta_list_v1(leader, "bkt", NULL, list_capture_cb, &cap));
    check_int_eq(1, cap.count);
    check_str_eq("obj", cap.key);
  }
  {
    list_capture_v1_t cap;
    memset(&cap, 0, sizeof(cap));
    check_int_eq(1, m3_gateway_meta_list_v1(follower, "bkt", NULL, list_capture_cb, &cap));
    check_int_eq(0, cap.count);
  }

  /* Bucket enumeration routes to the leader too. */
  {
    list_capture_v1_t cap;
    memset(&cap, 0, sizeof(cap));
    check_int_eq(0, m3_gateway_meta_list_v1(leader, NULL, NULL, list_bucket_capture_cb, &cap));
    check_int_eq(1, cap.count);
    check_str_eq("bkt", cap.key);
  }
  {
    list_capture_v1_t cap;
    memset(&cap, 0, sizeof(cap));
    check_int_eq(1, m3_gateway_meta_list_v1(follower, NULL, NULL, list_bucket_capture_cb, &cap));
    check_int_eq(0, cap.count);
  }

  /* The follower routes reads: NOT_LEADER with the current leader id. */
  memset(&lr, 0, sizeof(lr));
  out_size = 0u;
  check_int_eq(1, m3_gateway_meta_lookup_v1(follower, "bkt", "obj", out, sizeof(out),
                                            &out_size, &lr));
  check_int_eq(1, lr.not_leader);
  {
    tr_raft_node_id_t reported = 0u;
    check_int_eq(0, m3_gateway_leader_v1(follower, &reported));
    check_int_eq((int)reported, (int)lr.leader_id);
    check_int_eq((int)leader_id, (int)reported);
  }

  /* Tombstone on the leader converges; the object is then gone. */
  check_int_eq(0, m3_gateway_meta_tombstone_start_v1(leader, "bkt", "obj"));
  {
    uint64_t deadline = turbo_monotonic_ms() + 10000u;
    while (turbo_monotonic_ms() < deadline &&
           m3_gateway_meta_mutation_pending_v1(leader)) {
      drive_both(&gateway1, &gateway2);
    }
    check_true(!m3_gateway_meta_mutation_pending_v1(leader));
  }
  {
    int done = 0;
    uint64_t deadline = turbo_monotonic_ms() + 10000u;
    memset(&lr, 0, sizeof(lr));
    check_int_eq(0, m3_gateway_meta_lookup_start_v1(leader, "bkt", "obj", out,
                                                    sizeof(out), &out_size, &lr));
    while (turbo_monotonic_ms() < deadline && !done) {
      drive_both(&gateway1, &gateway2);
      (void)m3_gateway_meta_lookup_try_v1(leader, &lr, &done);
    }
    check_true(done);
  }
  check_int_eq(0, lr.found);

  m3_gateway_destroy_v1(&gateway2);
  m3_gateway_destroy_v1(&gateway1);
  m3_object_manifest_bytes_free_v1(manifest);
}

spec("m3 gateway raft node") {
  describe("multi-node gateway metadata leader routing") {
    it("routes reads to the raft leader (follower returns NOT_LEADER)") {
      test_two_gateway_leader_routing();
    }
  }
}
