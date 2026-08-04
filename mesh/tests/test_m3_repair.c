#include <tinytest.h>

#include "m3_gateway_datapane.h"
#include "m3_namespace_local_store.h"
#include "m3_namespace_raft_adapter.h"
#include "m3_object_manifest.h"
#include "m3_repair.h"
#include "m3_store_node.h"

#include <string.h>
#include <time.h>

/* P5 repair: a committed manifest whose chunk lost a replica is backfilled
 * from a healthy replica onto an unused store; the updated manifest (same
 * object version) is applied via UPDATE_PLACEMENT and the placement converges
 * to target_replicas. */

static const uint8_t STORE_KEYS[3][MESH_MGMT_ED25519_PRIVATE_KEY_SIZE] = {
    {0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
     0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
     0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
     0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60},
    {0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda,
     0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
     0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24,
     0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb},
    {0x1b, 0x9d, 0x4c, 0xe8, 0x37, 0xa1, 0x5f, 0x22,
     0x80, 0x6c, 0x93, 0x4a, 0xd7, 0x0e, 0x55, 0x68,
     0x2f, 0x91, 0xc4, 0x3b, 0x7a, 0xd2, 0x6e, 0x15,
     0x49, 0x88, 0xa0, 0x5d, 0xc1, 0x33, 0xf4, 0x8b},
};

static const m3_chunk_capability_policy_v1_t TEST_POLICY = {
    7200u * 1000u, 64u * 1024u * 1024u, 64u * 1024u * 1024u,
};

static uint64_t g_now_ms(void) { return (uint64_t)time(NULL) * 1000u; }

static void make_store(m3_store_node_v1_t *node, char *root, size_t root_cap,
                       const char *tag, int index) {
  m3_store_node_config_v1_t config;

#ifdef _WIN32
  char tmp[MAX_PATH];
  GetTempPathA((DWORD)sizeof(tmp), tmp);
  snprintf(root, root_cap, "%s%s-%d-%lu", tmp, tag, index,
           (unsigned long)GetCurrentProcessId());
  _mkdir(root);
#else
  snprintf(root, root_cap, "/tmp/%s-%d-%d", tag, index, (int)getpid());
  mkdir(root, 0755);
#endif
  memset(&config, 0, sizeof(config));
  snprintf(config.store_root, sizeof(config.store_root), "%s", root);
  config.max_chunk_bytes = 1024u * 1024u;
  config.max_tenant_bytes = 1024u * 1024u;
  for (int i = 0; i < 32; i++)
    config.node_id[i] = (uint8_t)(0x20u + index * 16u + i);
  memcpy(config.signing_private_key, STORE_KEYS[index],
         sizeof(config.signing_private_key));
  snprintf(config.failure_domain, sizeof(config.failure_domain), "dc-%c",
           (char)('a' + index));
  config.policy = TEST_POLICY;
  memset(node, 0, sizeof(*node));
  check_int_eq(m3_store_node_init_v1(node, &config), M3_STORE_NODE_OK);
}

static void ns_lookup_cb(m3_namespace_lookup_result_t result,
                         const m3_namespace_lookup_response_v1_t *response,
                         void *user_data);

static void test_repair_backfills_and_converges(void) {
  m3_store_node_v1_t stores[3];
  char roots[3][512];
  uint8_t publics[3][MESH_MGMT_ED25519_PUBLIC_KEY_SIZE];
  m3_gateway_datapane_v1_t datapane;
  uint8_t tenant[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE];
  m3_object_manifest_owned_v2_t original = {0};
  m3_object_manifest_owned_v2_t updated = {0};
  m3_object_manifest_placement_debt_v1_t debt[4];
  size_t debt_count = 0u;
  uint8_t *manifest_bytes = NULL;
  size_t manifest_size = 0u;
  uint64_t object_size = 0u;
  uint64_t now_ms = g_now_ms();
  static const uint8_t body[] =
      "repair-me-twice-this-is-one-chunk-boundary-and-more";
  size_t chunk_count;
  size_t i;

  for (i = 0u; i < 3u; i++) {
    make_store(&stores[i], roots[i], sizeof(roots[i]), "m3-repair-store",
               (int)i);
    check_int_eq(mesh_mgmt_ed25519_public_from_private(
                     STORE_KEYS[i], publics[i]),
                 MESH_MGMT_CRYPTO_OK);
  }
  for (i = 0u; i < sizeof(tenant); i++)
    tenant[i] = (uint8_t)(0x11u + i);

  /* Publish with target 2 (stores 0 and 1); the third store is the repair
   * target. */
  check_int_eq(M3_GATEWAY_DATAPANE_OK,
               m3_gateway_datapane_init_v1(&datapane, tenant, 2u, 2u,
                                           &TEST_POLICY));
  for (i = 0u; i < 3u; i++) {
    check_int_eq(M3_GATEWAY_DATAPANE_OK,
                 m3_gateway_datapane_register_store_v1(
                     &datapane, stores[i].config.node_id, publics[i],
                     &stores[i]));
  }
  check_int_eq(M3_GATEWAY_DATAPANE_OK,
               m3_gateway_datapane_put_object_v1(
                   &datapane, body, sizeof(body) - 1u, 16u, now_ms,
                   &manifest_bytes, &manifest_size, &object_size));
  check_int_eq(M3_OBJECT_MANIFEST_OK,
               m3_object_manifest_decode_v2(manifest_bytes, manifest_size,
                                            UINT64_C(1) << 30, 64u, 512u,
                                            &original));
  chunk_count = original.manifest.chunk_count;
  check_true(chunk_count >= 2u);
  for (i = 0u; i < chunk_count; i++) {
    size_t count = 0u;

    for (size_t j = 0u; j < original.manifest.placement_count; j++) {
      if (original.manifest.placements[j].chunk_index == i)
        count++;
    }
    check_size_eq(count, 2u);
  }

  /* Simulate a replica loss on store 0: delete every chunk from it. */
  for (i = 0u; i < chunk_count; i++) {
    check_int_eq(M3_CHUNK_STORE_OK,
                 m3_chunk_store_delete_v1(&stores[0].store,
                                          &original.manifest.chunks[i]));
  }

  /* Repair to target 3: reads from the surviving replica and writes store 2. */
  check_int_eq(M3_REPAIR_OK,
               m3_repair_execute_v1(&datapane, &original.manifest, 3u, now_ms,
                                    &updated));
  check_size_eq(updated.manifest.chunk_count, chunk_count);
  check_size_eq(updated.manifest.placement_count, chunk_count * 3u);
  check_int_eq(M3_OBJECT_MANIFEST_OK,
               m3_object_manifest_placement_policy_v2(&updated.manifest, 2u, 3u,
                                                      debt, 4u, &debt_count));
  check_size_eq(debt_count, 0u);

  /* The new replica on store 2 holds every chunk and the receipts verify. */
  for (i = 0u; i < chunk_count; i++) {
    m3_chunk_capability_claims_v1_t claims;
    m3_chunk_access_request_v1_t request;
    uint8_t buffer[64];
    size_t read = 0u;
    uint64_t chunk_size = original.manifest.chunks[i].size;

    memset(&claims, 0, sizeof(claims));
    memset(&request, 0, sizeof(request));
    for (size_t t = 0u; t < sizeof(claims.tenant_id); t++)
      claims.tenant_id[t] = (uint8_t)(0x11u + t);
    claims.cid = original.manifest.chunks[i];
    claims.operation = M3_CHUNK_OPERATION_READ;
    claims.range_offset = 0u;
    claims.range_length = chunk_size;
    memcpy(claims.audience_node_id, stores[2].config.node_id,
           sizeof(claims.audience_node_id));
    claims.request_id.bytes[0] = (uint8_t)(0x60u + i);
    claims.issued_at_ms = now_ms;
    claims.expires_at_ms = now_ms + TEST_POLICY.max_ttl_ms;
    memcpy(request.tenant_id, claims.tenant_id, sizeof(request.tenant_id));
    request.cid = original.manifest.chunks[i];
    request.operation = M3_CHUNK_OPERATION_READ;
    request.range_offset = 0u;
    request.range_length = chunk_size;
    memcpy(request.local_node_id, stores[2].config.node_id,
           sizeof(request.local_node_id));
    request.request_id = claims.request_id;
    request.now_ms = now_ms;
    check_int_eq(M3_STORE_NODE_OK,
                 m3_store_node_read_chunk_v1(&stores[2], &claims, &request,
                                             buffer, sizeof(buffer), &read));
    check_uint_eq(read, chunk_size);
  }

  m3_object_manifest_owned_destroy_v2(&updated);
  m3_object_manifest_owned_destroy_v2(&original);
  m3_object_manifest_bytes_free_v2(manifest_bytes);
  m3_gateway_datapane_destroy_v1(&datapane);
  for (i = 0u; i < 3u; i++)
    m3_store_node_destroy_v1(&stores[i]);
}

static void test_update_placement_apply_and_codec(void) {
  m3_namespace_local_store_v1_t ns;
  m3_object_manifest_owned_v2_t original = {0};
  m3_object_manifest_owned_v2_t augmented = {0};
  uint8_t tenant[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE];
  uint8_t *original_bytes = NULL;
  size_t original_size = 0u;
  uint8_t *augmented_bytes = NULL;
  size_t augmented_size = 0u;
  uint8_t fetched[2048];
  size_t fetched_size = 0u;
  char *root = tt_make_temp_dir("m3-repair-ns");
  m3_namespace_lookup_request_v1_t request = {0};
  m3_namespace_lookup_adapter_v1_t adapter;
  m3_namespace_raft_command_v1_t command = {0};
  m3_namespace_raft_command_v1_t decoded = {0};
  uint8_t frame[2048];
  size_t frame_size = 0u;
  m3_chunk_cid_v1_t chunk;
  m3_object_manifest_placement_v1_t placements[2];

  check_not_null(root);
  memset(&ns, 0, sizeof(ns));
  check_int_eq(M3_NAMESPACE_LOCAL_OK,
               m3_namespace_local_store_init_v1(&ns, 8u, 128u, 1024u, 65536u,
                                                UINT64_C(1) << 30, 64u));
  for (size_t i = 0u; i < sizeof(tenant); i++)
    tenant[i] = (uint8_t)(0x11u + i);

  memset(&chunk, 0, sizeof(chunk));
  chunk.hash_algorithm = M3_CHUNK_STORE_HASH_ALGORITHM_SHA256;
  chunk.size = 11u;
  memset(chunk.digest, 0x5a, sizeof(chunk.digest));
  memset(placements, 0, sizeof(placements));
  for (size_t i = 0u; i < 2u; i++) {
    placements[i].chunk_index = 0u;
    memset(placements[i].store_node_id, 0x40u + i,
           sizeof(placements[i].store_node_id));
    memset(placements[i].receipt_digest, 0x70u + i,
           sizeof(placements[i].receipt_digest));
  }

  original.manifest.version = M3_OBJECT_MANIFEST_VERSION_2;
  original.manifest.object_cid.hash_algorithm = M3_CHUNK_STORE_HASH_ALGORITHM_SHA256;
  original.manifest.object_cid.size = 11u;
  memset(original.manifest.object_cid.digest, 0x2a, sizeof(original.manifest.object_cid.digest));
  original.manifest.chunk_count = 1u;
  original.owned_chunks = (m3_chunk_cid_v1_t *)malloc(sizeof(chunk));
  *original.owned_chunks = chunk;
  original.manifest.chunks = original.owned_chunks;
  original.manifest.placement_count = 1u;
  original.owned_placements = (m3_object_manifest_placement_v1_t *)malloc(sizeof(placements[0]));
  original.owned_placements[0] = placements[0];
  original.manifest.placements = original.owned_placements;
  check_int_eq(M3_OBJECT_MANIFEST_OK,
               m3_object_manifest_encode_v2(&original.manifest, UINT64_C(1) << 30,
                                            64u, 512u, &original_bytes,
                                            &original_size));

  /* Augmented manifest: same object version, two placements. */
  augmented.manifest.version = M3_OBJECT_MANIFEST_VERSION_2;
  augmented.manifest.object_cid = original.manifest.object_cid;
  augmented.manifest.chunk_count = 1u;
  augmented.owned_chunks = (m3_chunk_cid_v1_t *)malloc(sizeof(chunk));
  *augmented.owned_chunks = chunk;
  augmented.manifest.chunks = augmented.owned_chunks;
  augmented.owned_placements = (m3_object_manifest_placement_v1_t *)malloc(
      2u * sizeof(placements[0]));
  augmented.owned_placements[0] = placements[0];
  augmented.owned_placements[1] = placements[1];
  augmented.manifest.placements = augmented.owned_placements;
  augmented.manifest.placement_count = 2u;
  check_int_eq(M3_OBJECT_MANIFEST_OK,
               m3_object_manifest_encode_v2(&augmented.manifest, UINT64_C(1) << 30,
                                            64u, 512u, &augmented_bytes,
                                            &augmented_size));

  check_int_eq(M3_NAMESPACE_LOCAL_OK,
               m3_namespace_local_store_apply_put_v1(
                   &ns, 1u, tenant, (const uint8_t *)"bkt", 3u,
                   (const uint8_t *)"obj", 3u, original_bytes, original_size));

  /* Version mismatch is CONFLICT; same version updates placements. */
  {
    uint8_t *wrong = NULL;
    size_t wrong_size = 0u;
    m3_object_manifest_v2_t wrong_manifest = augmented.manifest;

    wrong_manifest.object_cid.digest[0] ^= 0x01u;
    check_int_eq(M3_OBJECT_MANIFEST_OK,
                 m3_object_manifest_encode_v2(&wrong_manifest, UINT64_C(1) << 30,
                                              64u, 512u, &wrong, &wrong_size));
    check_int_eq(M3_NAMESPACE_LOCAL_CONFLICT,
                 m3_namespace_local_store_apply_update_placement_v1(
                     &ns, 2u, tenant, (const uint8_t *)"bkt", 3u,
                     (const uint8_t *)"obj", 3u, wrong, wrong_size));
  }
  check_int_eq(M3_NAMESPACE_LOCAL_OK,
               m3_namespace_local_store_apply_update_placement_v1(
                   &ns, 2u, tenant, (const uint8_t *)"bkt", 3u,
                   (const uint8_t *)"obj", 3u, augmented_bytes, augmented_size));
  check_int_eq(M3_NAMESPACE_LOCAL_NOT_FOUND,
               m3_namespace_local_store_apply_update_placement_v1(
                   &ns, 3u, tenant, (const uint8_t *)"nope", 4u,
                   (const uint8_t *)"x", 1u, augmented_bytes, augmented_size));

  /* Lookup returns the augmented manifest (placement count 2, same version). */
  memcpy(request.tenant_id, tenant, sizeof(request.tenant_id));
  request.bucket = (const uint8_t *)"bkt";
  request.bucket_size = 3u;
  request.object_key = (const uint8_t *)"obj";
  request.object_key_size = 3u;
  request.require_linearizable = 1u;
  adapter = m3_namespace_local_store_adapter_v1(&ns);
  {
    typedef struct {
      int done;
      int found;
      uint8_t *out;
      size_t cap;
      size_t *size;
    } capture_t;
    capture_t cap = {0, 0, fetched, sizeof(fetched), &fetched_size};
    check_int_eq(M3_NAMESPACE_LOOKUP_OK,
                 adapter.start(adapter.context, &request, ns_lookup_cb, &cap));
    check_true(cap.done && cap.found);
  }
  {
    m3_object_manifest_owned_v2_t result = {0};

    check_int_eq(M3_OBJECT_MANIFEST_OK,
                 m3_object_manifest_decode_v2(fetched, fetched_size,
                                              UINT64_C(1) << 30, 64u, 512u,
                                              &result));
    check_size_eq(result.manifest.placement_count, 2u);
    check_mem_eq(result.manifest.object_cid.digest,
                 original.manifest.object_cid.digest,
                 sizeof(result.manifest.object_cid.digest));
    m3_object_manifest_owned_destroy_v2(&result);
  }

  /* Raft UPDATE_PLACEMENT command codec round-trip. */
  memset(&command, 0, sizeof(command));
  command.type = M3_NAMESPACE_RAFT_COMMAND_UPDATE_PLACEMENT;
  memcpy(command.tenant_id, tenant, sizeof(command.tenant_id));
  command.bucket = (const uint8_t *)"bkt";
  command.bucket_size = 3u;
  command.object_key = (const uint8_t *)"obj";
  command.object_key_size = 3u;
  command.manifest_bytes = augmented_bytes;
  command.manifest_size = augmented_size;
  check_int_eq(TURBO_OK,
               m3_namespace_raft_command_encode_v1(&command, frame,
                                                   sizeof(frame), &frame_size));
  check_int_eq(TURBO_OK,
               m3_namespace_raft_command_decode_v1(frame, frame_size, &decoded));
  check_int_eq((int)M3_NAMESPACE_RAFT_COMMAND_UPDATE_PLACEMENT, (int)decoded.type);
  check_size_eq(decoded.manifest_size, augmented_size);
  check_mem_eq(decoded.manifest_bytes, augmented_bytes, augmented_size);

  m3_object_manifest_bytes_free_v2(original_bytes);
  m3_object_manifest_bytes_free_v2(augmented_bytes);
  m3_object_manifest_owned_destroy_v2(&augmented);
  m3_object_manifest_owned_destroy_v2(&original);
  m3_namespace_local_store_destroy_v1(&ns);
  check_int_eq(tt_remove_tree(root), 0);
  free(root);
}

static void ns_lookup_cb(m3_namespace_lookup_result_t result,
                         const m3_namespace_lookup_response_v1_t *response,
                         void *user_data) {
  typedef struct {
    int done;
    int found;
    uint8_t *out;
    size_t cap;
    size_t *size;
  } capture_t;
  capture_t *cap = (capture_t *)user_data;

  cap->done = 1;
  if (result == M3_NAMESPACE_LOOKUP_OK && response &&
      response->manifest_size <= cap->cap) {
    memcpy(cap->out, response->manifest_bytes, response->manifest_size);
    *cap->size = response->manifest_size;
    cap->found = 1;
  }
}

spec("m3 repair") {
    describe("placement repair") {
        it("backfills a lost replica and converges the placement") {
            test_repair_backfills_and_converges();
        }
        it("applies UPDATE_PLACEMENT without changing the object version") {
            test_update_placement_apply_and_codec();
        }
    }
}
