#include <tinytest.h>

#include "m3_gateway.h"
#include "m3_object_manifest.h"
#include "m3_raft_node.h"
#include "m3_store_node.h"

#include <platform.h>
#include <turbo_crypto.h>
#include <turbo_error.h>

#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#endif

/* P3: gateway cross-node data plane. A PUT durably replicates every chunk to
 * target_replicas store nodes and only commits the metadata (V2 manifest with
 * placement) after min_durable_replicas verified receipts; a GET reads chunks
 * through the placement replicas, so a leader switch no longer loses access
 * to object bytes (the Phase-1 leader-local CAS is only a fallback). */

#ifndef M3_TEST_TLS_DIR
#define M3_TEST_TLS_DIR "mesh/tests/data/m3tls"
#endif

static const char k_node1_fingerprint[] =
    "sha256:a9a12784e612bd3ced3dbc4ec6b9f1f58b84a4592650fda8be88f5d777f49800";
static const char k_node2_fingerprint[] =
    "sha256:66a4ee96d3c72dacc600ecda40ff0d3a308e2bf06a1ff2d45e74d36d88e7f465";
static const char k_node3_fingerprint[] =
    "sha256:56fdbb74472b0d77a2fc182a44be32a41c4b9dbfab34a6cc68374b50066d24e1";

static const uint8_t STORE_KEY_A[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};

static const uint8_t STORE_KEY_B[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE] = {
    0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda,
    0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
    0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24,
    0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
};

static const m3_chunk_capability_policy_v1_t TEST_POLICY = {
    7200u * 1000u, 64u * 1024u * 1024u, 64u * 1024u * 1024u,
};

static void fill_credential(m3_sigv4_credential_v1_t *cred) {
  memset(cred, 0, sizeof(*cred));
  strcpy(cred->access_key, "AKIDEXAMPLE");
  cred->region = "us-east-1";
  cred->service = "s3";
  cred->clock_skew_seconds = 900;
  for (int i = 0; i < 32; i++)
    cred->secret_key[i] = (uint8_t)(0x60 + i);
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

static void create_store_node(m3_store_node_v1_t *node, const char *root,
                              uint8_t id_seed, const uint8_t key[32],
                              uint8_t public_key[32]) {
  m3_store_node_config_v1_t config;

  memset(&config, 0, sizeof(config));
  snprintf(config.store_root, sizeof(config.store_root), "%s", root);
  config.max_chunk_bytes = 1024u * 1024u;
  config.max_tenant_bytes = 1024u * 1024u;
  for (int i = 0; i < 32; i++)
    config.node_id[i] = (uint8_t)(id_seed + i);
  memcpy(config.signing_private_key, key, sizeof(config.signing_private_key));
  snprintf(config.failure_domain, sizeof(config.failure_domain), "dc-%c",
           (char)('a' + (id_seed & 0x0fu)));
  config.policy = TEST_POLICY;
  memset(node, 0, sizeof(*node));
  check_int_eq(m3_store_node_init_v1(node, &config), M3_STORE_NODE_OK);
  check_int_eq(mesh_mgmt_ed25519_public_from_private(key, public_key),
               MESH_MGMT_CRYPTO_OK);
}

static void attach_stores(m3_gateway_t *gateway, m3_store_node_v1_t *stores[],
                          uint8_t public_keys[][32], size_t store_count) {
  check_int_eq(0, m3_gateway_attach_datapane_v1(gateway, store_count, store_count,
                                                &TEST_POLICY));
  for (size_t i = 0u; i < store_count; i++) {
    check_int_eq(0, m3_gateway_register_store_v1(
                        gateway, stores[i]->config.node_id, public_keys[i],
                        stores[i]));
  }
}

static void create_gateway_node(m3_gateway_t *gateway, tr_raft_node_id_t node_id,
                                int listen_port, const tr_raft_node_id_t *voters,
                                size_t voter_count, m3_raft_node_peer_config_t *peers,
                                size_t peer_count, const char *store_root,
                                const char *cert, const char *key) {
  m3_raft_node_config_t config;
  m3_sigv4_credential_v1_t credential;
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
  config.sqlite_path = ":memory:";
  config.cert_file = cert_path;
  config.key_file = key_path;
  config.ca_file = ca_path;
  config.voters = voters;
  config.voter_count = voter_count;
  config.peers = peers;
  config.peer_count = peer_count;
  config.max_snapshot_bytes = 4u * 1024u * 1024u;
  config.max_pending_reads = 64u;

  fill_credential(&credential);
  memset(gateway, 0, sizeof(*gateway));
  check_int_eq(0, m3_gateway_init_node_v1(gateway, store_root, UINT64_C(1024) * 1024,
                                          &credential, 1024u, &config));
}

typedef struct {
  int completed;
  int found;
  uint8_t *out;
  size_t cap;
  size_t *out_size;
} manifest_capture_t;

static void manifest_capture_cb(m3_namespace_lookup_result_t result,
                                const m3_namespace_lookup_response_v1_t *response,
                                void *user_data) {
  manifest_capture_t *capture = (manifest_capture_t *)user_data;

  capture->completed = 1;
  if (result == M3_NAMESPACE_LOOKUP_OK && response &&
      response->manifest_size <= capture->cap) {
    memcpy(capture->out, response->manifest_bytes, response->manifest_size);
    *capture->out_size = response->manifest_size;
    capture->found = 1;
  }
}

static int lookup_manifest_local(m3_gateway_t *gateway, const char *bucket,
                                 const char *object, uint8_t *out, size_t cap,
                                 size_t *out_size) {
  m3_namespace_lookup_request_v1_t request = {0};
  m3_namespace_lookup_adapter_v1_t adapter;
  manifest_capture_t capture = {0};

  capture.out = out;
  capture.cap = cap;
  capture.out_size = out_size;
  memcpy(request.tenant_id, gateway->tenant_id, sizeof(request.tenant_id));
  request.bucket = (const uint8_t *)bucket;
  request.bucket_size = strlen(bucket);
  request.object_key = (const uint8_t *)object;
  request.object_key_size = strlen(object);
  request.require_linearizable = 1u;
  adapter = m3_namespace_local_store_adapter_v1(&gateway->namespace_store);
  if (adapter.start(adapter.context, &request, manifest_capture_cb, &capture) !=
      M3_NAMESPACE_LOOKUP_OK) {
    return -1;
  }
  return capture.found ? 0 : -1;
}

static void store_read_claims(const m3_store_node_v1_t *store,
                              const m3_chunk_cid_v1_t *cid,
                              m3_chunk_capability_claims_v1_t *claims,
                              m3_chunk_access_request_v1_t *request,
                              uint64_t now_ms) {
  memset(claims, 0, sizeof(*claims));
  memset(request, 0, sizeof(*request));
  for (size_t i = 0u; i < sizeof(claims->tenant_id); i++)
    claims->tenant_id[i] = (uint8_t)(0x11u + i);
  claims->cid = *cid;
  claims->operation = M3_CHUNK_OPERATION_READ;
  claims->range_offset = 0u;
  claims->range_length = cid->size;
  memcpy(claims->audience_node_id, store->config.node_id,
         sizeof(claims->audience_node_id));
  claims->request_id.bytes[0] = 0x77u;
  claims->issued_at_ms = now_ms;
  claims->expires_at_ms = now_ms + TEST_POLICY.max_ttl_ms;
  memcpy(request->tenant_id, claims->tenant_id, sizeof(request->tenant_id));
  request->cid = *cid;
  request->operation = M3_CHUNK_OPERATION_READ;
  request->range_offset = 0u;
  request->range_length = cid->size;
  memcpy(request->local_node_id, store->config.node_id,
         sizeof(request->local_node_id));
  request->request_id = claims->request_id;
  request->now_ms = now_ms;
}

static void test_two_store_put_get(void) {
  char store1_root[512];
  char store2_root[512];
  char gateway_root[512];
  m3_store_node_v1_t store1;
  m3_store_node_v1_t store2;
  uint8_t public1[32];
  uint8_t public2[32];
  m3_store_node_v1_t *stores[2];
  uint8_t publics[2][32];
  m3_gateway_t gateway;
  m3_sigv4_credential_v1_t credential;
  uint8_t manifest[4096];
  size_t manifest_size = 0u;
  m3_object_manifest_owned_v2_t owned = {0};
  m3_chunk_cid_v1_t chunk_cid;
  char etag[2u + 2u * M3_CHUNK_CID_DIGEST_SIZE + 1u];
  uint8_t *out = NULL;
  size_t out_len = 0u;
  uint8_t buffer[128];
  size_t read = 0u;
  m3_chunk_capability_claims_v1_t claims;
  m3_chunk_access_request_v1_t request;
  uint64_t now_ms = (uint64_t)time(NULL) * 1000u;
  static const uint8_t body[] =
      "hello cross-node replication: data durable on two stores before commit";

  make_store_dir(store1_root, sizeof(store1_root), "m3-dp-store1");
  make_store_dir(store2_root, sizeof(store2_root), "m3-dp-store2");
  make_store_dir(gateway_root, sizeof(gateway_root), "m3-dp-gw");
  create_store_node(&store1, store1_root, 0x10u, STORE_KEY_A, public1);
  create_store_node(&store2, store2_root, 0x20u, STORE_KEY_B, public2);
  stores[0] = &store1;
  stores[1] = &store2;
  memcpy(publics[0], public1, sizeof(public1));
  memcpy(publics[1], public2, sizeof(public2));

  fill_credential(&credential);
  memset(&gateway, 0, sizeof(gateway));
  check_int_eq(0, m3_gateway_init_v1(&gateway, gateway_root, UINT64_C(1024) * 1024,
                                     &credential, 1024u));
  attach_stores(&gateway, stores, publics, 2u);

  check_int_eq(0, m3_gateway_put_object_v1(&gateway, "bkt", "obj", body,
                                           sizeof(body) - 1u, etag, sizeof(etag)));

  /* The committed manifest is V2 and carries two placements per chunk. */
  check_int_eq(0, lookup_manifest_local(&gateway, "bkt", "obj", manifest,
                                        sizeof(manifest), &manifest_size));
  check_int_eq(M3_OBJECT_MANIFEST_OK,
               m3_object_manifest_decode_v2(manifest, manifest_size,
                                            M3_GATEWAY_MAX_OBJECT_BYTES,
                                            M3_GATEWAY_MAX_CHUNKS,
                                            M3_GATEWAY_MAX_CHUNKS *
                                                M3_GATEWAY_DATAPANE_MAX_STORES,
                                            &owned));
  check_uint_eq(M3_OBJECT_MANIFEST_VERSION_2, owned.manifest.version);
  check_size_eq(1u, owned.manifest.chunk_count);
  check_size_eq(2u, owned.manifest.placement_count);

  /* Both stores hold the chunk bytes (durable before metadata commit). */
  chunk_cid = owned.manifest.chunks[0];
  store_read_claims(&store1, &chunk_cid, &claims, &request, now_ms);
  check_int_eq(M3_STORE_NODE_OK,
               m3_store_node_read_chunk_v1(&store1, &claims, &request, buffer,
                                           sizeof(buffer), &read));
  check_size_eq(read, sizeof(body) - 1u);
  check_mem_eq(buffer, body, read);
  store_read_claims(&store2, &chunk_cid, &claims, &request, now_ms);
  check_int_eq(M3_STORE_NODE_OK,
               m3_store_node_read_chunk_v1(&store2, &claims, &request, buffer,
                                           sizeof(buffer), &read));
  check_mem_eq(buffer, body, read);

  /* GET assembles the object through the placement replicas. */
  check_int_eq(0, m3_gateway_read_object_v1(&gateway, manifest, manifest_size,
                                            0u, owned.manifest.object_cid.size - 1u,
                                            &out, &out_len));
  check_size_eq(out_len, sizeof(body) - 1u);
  check_mem_eq(out, body, out_len);
  free(out);

  m3_object_manifest_owned_destroy_v2(&owned);
  m3_gateway_destroy_v1(&gateway);
  m3_store_node_destroy_v1(&store2);
  m3_store_node_destroy_v1(&store1);
}

static void drive_all(m3_gateway_t **gateways, size_t count) {
  for (size_t i = 0u; i < count; i++) {
    if (gateways[i])
      m3_gateway_poll_v1(gateways[i]);
  }
}

static m3_gateway_t *drive_until_leader(m3_gateway_t **gateways, size_t count,
                                        uint64_t timeout_ms) {
  uint64_t deadline = turbo_monotonic_ms() + timeout_ms;

  while (turbo_monotonic_ms() < deadline) {
    drive_all(gateways, count);
    for (size_t i = 0u; i < count; i++) {
      int is_leader = 0;
      if (gateways[i] &&
          m3_raft_node_is_leader(gateways[i]->node, &is_leader) == TURBO_OK &&
          is_leader) {
        return gateways[i];
      }
    }
  }
  return NULL;
}

static void gateway_put_and_wait(m3_gateway_t *leader, m3_gateway_t **all,
                                 size_t count, const char *bucket,
                                 const char *object, const uint8_t *body,
                                 size_t body_len, char *etag_out,
                                 size_t etag_cap) {
  check_int_eq(0, m3_gateway_put_object_start_v1(leader, bucket, object, body,
                                                 body_len, etag_out, etag_cap));
  {
    uint64_t deadline = turbo_monotonic_ms() + 15000u;
    while (turbo_monotonic_ms() < deadline &&
           m3_gateway_meta_mutation_pending_v1(leader)) {
      drive_all(all, count);
    }
    check_true(!m3_gateway_meta_mutation_pending_v1(leader));
  }
}

static int gateway_read_manifest(m3_gateway_t *leader, m3_gateway_t **all,
                                 size_t count, const char *bucket,
                                 const char *object, uint8_t *manifest_out,
                                 size_t manifest_cap, size_t *manifest_size,
                                 m3_gateway_lookup_result_v1_t *out) {
  int done = 0;
  uint64_t deadline = turbo_monotonic_ms() + 15000u;

  memset(out, 0, sizeof(*out));
  if (m3_gateway_meta_lookup_start_v1(leader, bucket, object, manifest_out,
                                      manifest_cap, manifest_size, out) != 0) {
    return -1;
  }
  while (turbo_monotonic_ms() < deadline && !done) {
    drive_all(all, count);
    (void)m3_gateway_meta_lookup_try_v1(leader, out, &done);
  }
  return done && out->found ? 0 : -1;
}

static void test_leader_switch_reads_from_stores(void) {
  static const tr_raft_node_id_t voters[] = {1u, 2u, 3u};
  m3_raft_node_peer_config_t peers1[2];
  m3_raft_node_peer_config_t peers2[2];
  m3_raft_node_peer_config_t peers3[2];
  m3_gateway_t gateway1;
  m3_gateway_t gateway2;
  m3_gateway_t gateway3;
  m3_gateway_t *all[3];
  m3_store_node_v1_t store_a;
  m3_store_node_v1_t store_b;
  uint8_t public_a[32];
  uint8_t public_b[32];
  m3_store_node_v1_t *stores[2];
  uint8_t publics[2][32];
  char gw_root1[512];
  char gw_root2[512];
  char gw_root3[512];
  char store_a_root[512];
  char store_b_root[512];
  m3_gateway_t *leader = NULL;
  m3_gateway_t *new_leader = NULL;
  uint8_t manifest[4096];
  size_t manifest_size = 0u;
  m3_gateway_lookup_result_v1_t lookup;
  uint8_t *out = NULL;
  size_t out_len = 0u;
  char etag[2u + 2u * M3_CHUNK_CID_DIGEST_SIZE + 1u];
  static const uint8_t body[] = "leader-switch durability via replicated stores";

  configure_peer(&peers1[0], 2u, 19801, k_node2_fingerprint);
  configure_peer(&peers1[1], 3u, 19802, k_node3_fingerprint);
  configure_peer(&peers2[0], 1u, 19800, k_node1_fingerprint);
  configure_peer(&peers2[1], 3u, 19802, k_node3_fingerprint);
  configure_peer(&peers3[0], 1u, 19800, k_node1_fingerprint);
  configure_peer(&peers3[1], 2u, 19801, k_node2_fingerprint);

  make_store_dir(gw_root1, sizeof(gw_root1), "m3-dp-gw1");
  make_store_dir(gw_root2, sizeof(gw_root2), "m3-dp-gw2");
  make_store_dir(gw_root3, sizeof(gw_root3), "m3-dp-gw3");
  make_store_dir(store_a_root, sizeof(store_a_root), "m3-dp-store-a");
  make_store_dir(store_b_root, sizeof(store_b_root), "m3-dp-store-b");

  create_store_node(&store_a, store_a_root, 0x30u, STORE_KEY_A, public_a);
  create_store_node(&store_b, store_b_root, 0x40u, STORE_KEY_B, public_b);
  stores[0] = &store_a;
  stores[1] = &store_b;
  memcpy(publics[0], public_a, sizeof(public_a));
  memcpy(publics[1], public_b, sizeof(public_b));

  create_gateway_node(&gateway1, 1u, 19800, voters, 3u, peers1, 2u, gw_root1,
                      "node1.crt", "node1.key");
  create_gateway_node(&gateway2, 2u, 19801, voters, 3u, peers2, 2u, gw_root2,
                      "node2.crt", "node2.key");
  create_gateway_node(&gateway3, 3u, 19802, voters, 3u, peers3, 2u, gw_root3,
                      "node3.crt", "node3.key");
  all[0] = &gateway1;
  all[1] = &gateway2;
  all[2] = &gateway3;
  attach_stores(&gateway1, stores, publics, 2u);
  attach_stores(&gateway2, stores, publics, 2u);
  attach_stores(&gateway3, stores, publics, 2u);

  leader = drive_until_leader(all, 3u, 20000u);
  check_not_null(leader);

  /* PUT through the leader: chunks land on both stores, metadata commits. */
  gateway_put_and_wait(leader, all, 3u, "bkt", "obj", body, sizeof(body) - 1u,
                       etag, sizeof(etag));
  check_int_eq(0, gateway_read_manifest(leader, all, 3u, "bkt", "obj", manifest,
                                        sizeof(manifest), &manifest_size, &lookup));
  check_int_eq(0, m3_gateway_read_object_v1(leader, manifest, manifest_size,
                                            0u, sizeof(body) - 2u, &out, &out_len));
  check_size_eq(out_len, sizeof(body) - 1u);
  check_mem_eq(out, body, out_len);
  free(out);
  out = NULL;

  /* Crash the leader; the two survivors must elect a new leader. */
  {
    size_t survivor_count = 0u;
    m3_gateway_t *survivors[2];
    uint64_t deadline = turbo_monotonic_ms() + 20000u;
    tr_raft_node_id_t leader_id = 0u;
    int elected = 0;

    check_int_eq(0, m3_gateway_leader_v1(leader, &leader_id));
    check_true(leader_id != 0u);
    for (size_t i = 0u; i < 3u; i++) {
      if (all[i] == leader) {
        all[i] = NULL;
      } else {
        survivors[survivor_count++] = all[i];
      }
    }
    check_size_eq(2u, survivor_count);
    m3_gateway_destroy_v1(leader);

    while (turbo_monotonic_ms() < deadline && !elected) {
      drive_all(all, 3u);
      for (size_t i = 0u; i < survivor_count; i++) {
        int is_leader = 0;
        if (m3_raft_node_is_leader(survivors[i]->node, &is_leader) == TURBO_OK &&
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

    /* New leader commits a term entry (empty object) before linearizable
     * reads; no store write is needed for a zero-chunk object. */
    gateway_put_and_wait(new_leader, all, 3u, "bkt", "term", NULL, 0u, etag,
                         sizeof(etag));
  }

  /* The new leader must serve the pre-crash object from the replicated
   * stores: the committed V2 manifest survives the switch and the bytes are
   * reachable through the placement (no dependency on the dead leader's CAS). */
  check_int_eq(0, gateway_read_manifest(new_leader, all, 3u, "bkt", "obj",
                                        manifest, sizeof(manifest),
                                        &manifest_size, &lookup));
  check_int_eq(0, m3_gateway_read_object_v1(new_leader, manifest, manifest_size,
                                            0u, sizeof(body) - 2u, &out, &out_len));
  check_size_eq(out_len, sizeof(body) - 1u);
  check_mem_eq(out, body, out_len);
  free(out);

  for (size_t i = 0u; i < 3u; i++) {
    if (all[i])
      m3_gateway_destroy_v1(all[i]);
  }
  m3_store_node_destroy_v1(&store_b);
  m3_store_node_destroy_v1(&store_a);
}

spec("m3 gateway datapane") {
    describe("cross-node data plane") {
        it("replicates chunks to two stores and reads them back through placement") {
            test_two_store_put_get();
        }
        it("serves object reads after a leader switch from the replicated stores") {
            test_leader_switch_reads_from_stores();
        }
    }
}
