#include <tinytest.h>

#include "m3_store_node.h"

#include <string.h>
#include <time.h>

/* P5 GC: the store reclaims published chunks that are not in the live-CID
 * snapshot once their file mtime passes the grace window; live chunks and
 * too-recent orphans are kept. */

static const uint8_t STORE_KEY[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE] = {
    0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda,
    0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
    0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24,
    0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
};

static const m3_chunk_capability_policy_v1_t TEST_POLICY = {
    7200u * 1000u, 64u * 1024u * 1024u, 64u * 1024u * 1024u,
};

static uint64_t g_now_ms(void) { return (uint64_t)time(NULL) * 1000u; }

static void make_store(m3_store_node_v1_t *node, char *root, size_t root_cap,
                       const char *tag) {
  m3_store_node_config_v1_t config;

#ifdef _WIN32
  char tmp[MAX_PATH];
  GetTempPathA((DWORD)sizeof(tmp), tmp);
  snprintf(root, root_cap, "%s%s-%lu", tmp, tag, (unsigned long)GetCurrentProcessId());
  _mkdir(root);
#else
  snprintf(root, root_cap, "/tmp/%s-%d", tag, (int)getpid());
  mkdir(root, 0755);
#endif
  memset(&config, 0, sizeof(config));
  snprintf(config.store_root, sizeof(config.store_root), "%s", root);
  config.max_chunk_bytes = 1024u * 1024u;
  config.max_tenant_bytes = 1024u * 1024u;
  for (int i = 0; i < 32; i++)
    config.node_id[i] = (uint8_t)(0x30u + i);
  memcpy(config.signing_private_key, STORE_KEY, sizeof(config.signing_private_key));
  snprintf(config.failure_domain, sizeof(config.failure_domain), "dc-a");
  config.policy = TEST_POLICY;
  memset(node, 0, sizeof(*node));
  check_int_eq(m3_store_node_init_v1(node, &config), M3_STORE_NODE_OK);
}

static void make_claims(const m3_store_node_v1_t *store, const m3_chunk_cid_v1_t *cid,
                        m3_chunk_operation_v1_t operation,
                        m3_chunk_capability_claims_v1_t *claims,
                        m3_chunk_access_request_v1_t *request, uint64_t now_ms,
                        uint8_t tag) {
  memset(claims, 0, sizeof(*claims));
  memset(request, 0, sizeof(*request));
  for (size_t i = 0u; i < sizeof(claims->tenant_id); i++)
    claims->tenant_id[i] = (uint8_t)(0x11u + i);
  claims->cid = *cid;
  claims->operation = operation;
  claims->range_offset = 0u;
  claims->range_length = cid->size;
  memcpy(claims->audience_node_id, store->config.node_id,
         sizeof(claims->audience_node_id));
  claims->request_id.bytes[0] = tag;
  claims->issued_at_ms = now_ms;
  claims->expires_at_ms = now_ms + TEST_POLICY.max_ttl_ms;
  memcpy(request->tenant_id, claims->tenant_id, sizeof(request->tenant_id));
  request->cid = *cid;
  request->operation = operation;
  request->range_offset = 0u;
  request->range_length = cid->size;
  memcpy(request->local_node_id, store->config.node_id,
         sizeof(request->local_node_id));
  request->request_id = claims->request_id;
  request->now_ms = now_ms;
}

static void test_gc_reclaims_orphans_keeps_live(void) {
  m3_store_node_v1_t node;
  char root[512];
  uint64_t now_ms = g_now_ms();
  static const uint8_t live_bytes[] = "live-chunk-data";
  static const uint8_t orphan_bytes[] = "orphan-chunk-data";
  m3_chunk_cid_v1_t live_cid;
  m3_chunk_cid_v1_t orphan_cid;
  m3_chunk_capability_claims_v1_t claims;
  m3_chunk_access_request_v1_t request;
  m3_chunk_receipt_v1_t receipt;
  uint8_t buffer[64];
  size_t read = 0u;
  uint64_t reclaimed = 0u;

  make_store(&node, root, sizeof(root), "m3-gc-store");
  check_int_eq(M3_CHUNK_STORE_OK,
               m3_chunk_cid_calculate_v1(live_bytes, sizeof(live_bytes) - 1u,
                                         &live_cid));
  check_int_eq(M3_CHUNK_STORE_OK,
               m3_chunk_cid_calculate_v1(orphan_bytes, sizeof(orphan_bytes) - 1u,
                                         &orphan_cid));

  make_claims(&node, &live_cid, M3_CHUNK_OPERATION_PUT, &claims, &request, now_ms, 0x41u);
  check_int_eq(M3_STORE_NODE_OK,
               m3_store_node_put_chunk_v1(&node, &claims, &request, live_bytes,
                                          sizeof(live_bytes) - 1u, &receipt));
  make_claims(&node, &orphan_cid, M3_CHUNK_OPERATION_PUT, &claims, &request, now_ms, 0x42u);
  check_int_eq(M3_STORE_NODE_OK,
               m3_store_node_put_chunk_v1(&node, &claims, &request, orphan_bytes,
                                          sizeof(orphan_bytes) - 1u, &receipt));

  /* Too-recent chunks survive a short grace window. */
  check_int_eq(M3_STORE_NODE_OK,
               m3_store_node_gc_v1(&node, &live_cid, 1u, 3600u * 1000u, now_ms,
                                   &reclaimed));
  check_uint_eq(reclaimed, 0u);
  make_claims(&node, &orphan_cid, M3_CHUNK_OPERATION_READ, &claims, &request, now_ms, 0x43u);
  check_int_eq(M3_STORE_NODE_OK,
               m3_store_node_read_chunk_v1(&node, &claims, &request, buffer,
                                           sizeof(buffer), &read));

  /* Grace elapsed: the orphan is reclaimed, the live chunk is kept. */
  now_ms += 2u * 3600u * 1000u;
  check_int_eq(M3_STORE_NODE_OK,
               m3_store_node_gc_v1(&node, &live_cid, 1u, 3600u * 1000u, now_ms,
                                   &reclaimed));
  check_uint_eq(reclaimed, sizeof(orphan_bytes) - 1u);

  memset(&claims, 0, sizeof(claims));
  memset(&request, 0, sizeof(request));
  make_claims(&node, &live_cid, M3_CHUNK_OPERATION_READ, &claims, &request, now_ms, 0x44u);
  check_int_eq(M3_STORE_NODE_OK,
               m3_store_node_read_chunk_v1(&node, &claims, &request, buffer,
                                           sizeof(buffer), &read));
  check_size_eq(read, sizeof(live_bytes) - 1u);
  check_mem_eq(buffer, live_bytes, read);

  make_claims(&node, &orphan_cid, M3_CHUNK_OPERATION_READ, &claims, &request, now_ms, 0x45u);
  check_int_eq(M3_STORE_NODE_NOT_FOUND,
               m3_store_node_read_chunk_v1(&node, &claims, &request, buffer,
                                           sizeof(buffer), &read));

  check_int_eq(M3_STORE_NODE_INVALID_ARG,
               m3_store_node_gc_v1(&node, NULL, 1u, 0u, now_ms, &reclaimed));
  check_int_eq(M3_STORE_NODE_INVALID_ARG,
               m3_store_node_gc_v1(NULL, &live_cid, 1u, 0u, now_ms, &reclaimed));

  m3_store_node_destroy_v1(&node);
}

spec("m3 gc") {
    describe("store garbage collection") {
        it("reclaims expired orphans and keeps live chunks") {
            test_gc_reclaims_orphans_keeps_live();
        }
    }
}
