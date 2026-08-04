#include <tinytest.h>

#include "m3_store_node.h"

#include <string.h>

static const uint8_t TEST_PRIVATE_KEY[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};

static uint64_t g_now_ms = 1000u * 1000u;

static void fill_bytes(uint8_t *bytes, size_t size, uint8_t seed) {
  for (size_t i = 0u; i < size; i++)
    bytes[i] = (uint8_t)(seed + i);
}

static void make_config(m3_store_node_config_v1_t *config, const char *root) {
  memset(config, 0, sizeof(*config));
  snprintf(config->store_root, sizeof(config->store_root), "%s", root);
  config->max_chunk_bytes = 1024u * 1024u;
  config->max_tenant_bytes = 1024u * 1024u;
  fill_bytes(config->node_id, sizeof(config->node_id), 0x20u);
  memcpy(config->signing_private_key, TEST_PRIVATE_KEY,
         sizeof(config->signing_private_key));
  snprintf(config->failure_domain, sizeof(config->failure_domain), "dc-a");
  config->policy.max_ttl_ms = 7200u * 1000u;
  config->policy.max_read_bytes = 1024u * 1024u;
  config->policy.max_put_bytes = 1024u * 1024u;
}

static void make_claims(m3_chunk_capability_claims_v1_t *claims,
                        const m3_chunk_cid_v1_t *cid,
                        m3_chunk_operation_v1_t operation,
                        const uint8_t audience_node_id[32],
                        const turbo_uuid_t *request_id) {
  memset(claims, 0, sizeof(*claims));
  fill_bytes(claims->tenant_id, sizeof(claims->tenant_id), 0x11u);
  claims->cid = *cid;
  claims->operation = operation;
  claims->range_offset = 0u;
  claims->range_length = cid->size;
  memcpy(claims->audience_node_id, audience_node_id,
         sizeof(claims->audience_node_id));
  claims->request_id = *request_id;
  claims->issued_at_ms = g_now_ms - 1000u;
  claims->expires_at_ms = g_now_ms + 3600u * 1000u;
}

static void make_request(m3_chunk_access_request_v1_t *request,
                         const m3_chunk_cid_v1_t *cid,
                         m3_chunk_operation_v1_t operation,
                         const turbo_uuid_t *request_id) {
  memset(request, 0, sizeof(*request));
  fill_bytes(request->tenant_id, sizeof(request->tenant_id), 0x11u);
  request->cid = *cid;
  request->operation = operation;
  request->range_offset = 0u;
  request->range_length = cid->size;
  fill_bytes(request->local_node_id, sizeof(request->local_node_id), 0x22u);
  request->request_id = *request_id;
  request->now_ms = g_now_ms;
}

static void test_store_node_put_read_round_trip(void) {
  m3_store_node_config_v1_t config;
  m3_store_node_v1_t node;
  m3_store_node_health_v1_t health;
  m3_chunk_capability_claims_v1_t claims;
  m3_chunk_access_request_v1_t request;
  m3_chunk_cid_v1_t cid;
  m3_chunk_receipt_v1_t receipt;
  uint8_t public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE];
  uint8_t buffer[64];
  size_t out_read = 0u;
  char *root = tt_make_temp_dir("m3store");
  static const uint8_t data[] = "hello world";

  check_not_null(root);
  make_config(&config, root);
  memset(&node, 0, sizeof(node));
  check_int_eq(m3_store_node_init_v1(&node, &config), M3_STORE_NODE_OK);

  check_int_eq(m3_chunk_cid_calculate_v1(data, sizeof(data) - 1u, &cid),
               M3_CHUNK_STORE_OK);
  check_uint_eq(cid.size, sizeof(data) - 1u);

  make_claims(&claims, &cid, M3_CHUNK_OPERATION_PUT, config.node_id,
              &(turbo_uuid_t){0});
  claims.request_id.bytes[0] = 0x42u;
  make_request(&request, &cid, M3_CHUNK_OPERATION_PUT, &claims.request_id);
  check_int_eq(m3_store_node_put_chunk_v1(&node, &claims, &request, data,
                                          sizeof(data) - 1u, &receipt),
               M3_STORE_NODE_OK);
  check_int_eq(mesh_mgmt_ed25519_public_from_private(TEST_PRIVATE_KEY,
                                                     public_key),
               MESH_MGMT_CRYPTO_OK);
  check_int_eq(m3_chunk_receipt_verify_v1(public_key, &receipt),
               M3_CHUNK_RECEIPT_OK);
  check_int_eq(m3_chunk_receipt_check_binding_v1(
                   &receipt, config.node_id, &cid, &claims.request_id,
                   g_now_ms, 3600u * 1000u),
               M3_CHUNK_RECEIPT_OK);

  make_claims(&claims, &cid, M3_CHUNK_OPERATION_READ, config.node_id,
              &(turbo_uuid_t){0});
  claims.request_id.bytes[0] = 0x43u;
  make_request(&request, &cid, M3_CHUNK_OPERATION_READ, &claims.request_id);
  check_int_eq(m3_store_node_read_chunk_v1(&node, &claims, &request, buffer,
                                           sizeof(buffer), &out_read),
               M3_STORE_NODE_OK);
  check_size_eq(out_read, sizeof(data) - 1u);
  check_mem_eq(buffer, data, out_read);

  check_int_eq(m3_store_node_health_v1(&node, &health), M3_STORE_NODE_OK);
  check_str_eq(health.failure_domain, "dc-a");
  check_size_eq(health.tenant_count, 1u);
  check_uint_eq(health.used_bytes, sizeof(data) - 1u);
  check_uint_eq(health.quota_limit_bytes, config.max_tenant_bytes);
  check_uint_eq(health.free_capacity_bytes,
                config.max_tenant_bytes - (sizeof(data) - 1u));

  m3_store_node_destroy_v1(&node);
  check_int_eq(tt_remove_tree(root), 0);
  free(root);
}

static void test_store_node_put_idempotent(void) {
  m3_store_node_config_v1_t config;
  m3_store_node_v1_t node;
  m3_store_node_health_v1_t health;
  m3_chunk_capability_claims_v1_t claims;
  m3_chunk_access_request_v1_t request;
  m3_chunk_cid_v1_t cid;
  m3_chunk_receipt_v1_t receipt;
  char *root = tt_make_temp_dir("m3store");
  static const uint8_t data[] = "same-bytes";

  check_not_null(root);
  make_config(&config, root);
  memset(&node, 0, sizeof(node));
  check_int_eq(m3_store_node_init_v1(&node, &config), M3_STORE_NODE_OK);
  check_int_eq(m3_chunk_cid_calculate_v1(data, sizeof(data) - 1u, &cid),
               M3_CHUNK_STORE_OK);

  make_claims(&claims, &cid, M3_CHUNK_OPERATION_PUT, config.node_id,
              &(turbo_uuid_t){0});
  claims.request_id.bytes[0] = 0x51u;
  make_request(&request, &cid, M3_CHUNK_OPERATION_PUT, &claims.request_id);
  check_int_eq(m3_store_node_put_chunk_v1(&node, &claims, &request, data,
                                          sizeof(data) - 1u, &receipt),
               M3_STORE_NODE_OK);

  claims.request_id.bytes[0] = 0x52u;
  make_request(&request, &cid, M3_CHUNK_OPERATION_PUT, &claims.request_id);
  check_int_eq(m3_store_node_put_chunk_v1(&node, &claims, &request, data,
                                          sizeof(data) - 1u, &receipt),
               M3_STORE_NODE_OK);

  check_int_eq(m3_store_node_health_v1(&node, &health), M3_STORE_NODE_OK);
  check_uint_eq(health.used_bytes, sizeof(data) - 1u);

  m3_store_node_destroy_v1(&node);
  check_int_eq(tt_remove_tree(root), 0);
  free(root);
}

static void test_store_node_quota(void) {
  m3_store_node_config_v1_t config;
  m3_store_node_v1_t node;
  m3_store_node_health_v1_t health;
  m3_chunk_capability_claims_v1_t claims;
  m3_chunk_access_request_v1_t request;
  m3_chunk_cid_v1_t cid;
  m3_chunk_receipt_v1_t receipt;
  char *root = tt_make_temp_dir("m3store");
  static const uint8_t data_a[60] = {0};
  static uint8_t data_b[60] = {0};

  check_not_null(root);
  make_config(&config, root);
  config.max_tenant_bytes = 100u;
  memset(&node, 0, sizeof(node));
  check_int_eq(m3_store_node_init_v1(&node, &config), M3_STORE_NODE_OK);

  data_b[0] = 0x01u; /* distinct chunk from data_a */
  check_int_eq(m3_chunk_cid_calculate_v1(data_a, sizeof(data_a), &cid),
               M3_CHUNK_STORE_OK);
  make_claims(&claims, &cid, M3_CHUNK_OPERATION_PUT, config.node_id,
              &(turbo_uuid_t){0});
  claims.request_id.bytes[0] = 0x61u;
  make_request(&request, &cid, M3_CHUNK_OPERATION_PUT, &claims.request_id);
  check_int_eq(m3_store_node_put_chunk_v1(&node, &claims, &request, data_a,
                                          sizeof(data_a), &receipt),
               M3_STORE_NODE_OK);

  check_int_eq(m3_chunk_cid_calculate_v1(data_b, sizeof(data_b), &cid),
               M3_CHUNK_STORE_OK);
  make_claims(&claims, &cid, M3_CHUNK_OPERATION_PUT, config.node_id,
              &(turbo_uuid_t){0});
  claims.request_id.bytes[0] = 0x62u;
  make_request(&request, &cid, M3_CHUNK_OPERATION_PUT, &claims.request_id);
  check_int_eq(m3_store_node_put_chunk_v1(&node, &claims, &request, data_b,
                                          sizeof(data_b), &receipt),
               M3_STORE_NODE_QUOTA_EXCEEDED);

  check_int_eq(m3_store_node_health_v1(&node, &health), M3_STORE_NODE_OK);
  check_uint_eq(health.used_bytes, 60u);
  check_uint_eq(health.min_tenant_headroom_bytes, 40u);

  m3_store_node_destroy_v1(&node);
  check_int_eq(tt_remove_tree(root), 0);
  free(root);
}

static void test_store_node_rejects_bad_capability(void) {
  m3_store_node_config_v1_t config;
  m3_store_node_v1_t node;
  m3_chunk_capability_claims_v1_t claims;
  m3_chunk_access_request_v1_t request;
  m3_chunk_cid_v1_t cid;
  m3_chunk_receipt_v1_t receipt;
  uint8_t other_node[32];
  char *root = tt_make_temp_dir("m3store");
  static const uint8_t data[] = "payload";

  check_not_null(root);
  make_config(&config, root);
  memset(&node, 0, sizeof(node));
  check_int_eq(m3_store_node_init_v1(&node, &config), M3_STORE_NODE_OK);
  check_int_eq(m3_chunk_cid_calculate_v1(data, sizeof(data) - 1u, &cid),
               M3_CHUNK_STORE_OK);

  /* Audience bound to a different store node. */
  fill_bytes(other_node, sizeof(other_node), 0x40u);
  make_claims(&claims, &cid, M3_CHUNK_OPERATION_PUT, other_node,
              &(turbo_uuid_t){0});
  claims.request_id.bytes[0] = 0x71u;
  make_request(&request, &cid, M3_CHUNK_OPERATION_PUT, &claims.request_id);
  check_int_eq(m3_store_node_put_chunk_v1(&node, &claims, &request, data,
                                          sizeof(data) - 1u, &receipt),
               M3_STORE_NODE_AUTH_DENIED);

  /* Request UUID reused for different claims. */
  make_claims(&claims, &cid, M3_CHUNK_OPERATION_PUT, config.node_id,
              &(turbo_uuid_t){0});
  claims.request_id.bytes[0] = 0x72u;
  make_request(&request, &cid, M3_CHUNK_OPERATION_PUT, &claims.request_id);
  request.request_id.bytes[0] = 0x73u;
  check_int_eq(m3_store_node_put_chunk_v1(&node, &claims, &request, data,
                                          sizeof(data) - 1u, &receipt),
               M3_STORE_NODE_AUTH_DENIED);

  /* Expired capability. */
  make_claims(&claims, &cid, M3_CHUNK_OPERATION_PUT, config.node_id,
              &(turbo_uuid_t){0});
  claims.request_id.bytes[0] = 0x74u;
  claims.issued_at_ms = 1000u;
  claims.expires_at_ms = 2000u;
  make_request(&request, &cid, M3_CHUNK_OPERATION_PUT, &claims.request_id);
  check_int_eq(m3_store_node_put_chunk_v1(&node, &claims, &request, data,
                                          sizeof(data) - 1u, &receipt),
               M3_STORE_NODE_EXPIRED);

  m3_store_node_destroy_v1(&node);
  check_int_eq(tt_remove_tree(root), 0);
  free(root);
}

static void test_store_node_read_not_found_and_invalid_args(void) {
  m3_store_node_config_v1_t config;
  m3_store_node_v1_t node;
  m3_chunk_capability_claims_v1_t claims;
  m3_chunk_access_request_v1_t request;
  m3_chunk_cid_v1_t cid;
  m3_chunk_receipt_v1_t receipt;
  m3_store_node_health_v1_t health;
  char missing_root[512];
  char *root = tt_make_temp_dir("m3store");
  static const uint8_t data[] = "ghost";
  uint8_t buffer[16];
  size_t out_read = 0u;

  check_not_null(root);
  make_config(&config, root);
  check_int_eq(m3_chunk_cid_calculate_v1(data, sizeof(data) - 1u, &cid),
               M3_CHUNK_STORE_OK);

  make_claims(&claims, &cid, M3_CHUNK_OPERATION_READ, config.node_id,
              &(turbo_uuid_t){0});
  claims.request_id.bytes[0] = 0x81u;
  make_request(&request, &cid, M3_CHUNK_OPERATION_READ, &claims.request_id);
  check_int_eq(m3_store_node_read_chunk_v1(&node, &claims, &request, buffer,
                                           sizeof(buffer), &out_read),
               M3_STORE_NODE_INVALID_ARG); /* node not initialized */

  memset(&node, 0, sizeof(node));
  check_int_eq(m3_store_node_init_v1(&node, &config), M3_STORE_NODE_OK);
  check_int_eq(m3_store_node_read_chunk_v1(&node, &claims, &request, buffer,
                                           sizeof(buffer), &out_read),
               M3_STORE_NODE_NOT_FOUND);
  check_size_eq(out_read, 0u);
  m3_store_node_destroy_v1(&node);

  snprintf(missing_root, sizeof(missing_root), "%s%cno-such-dir", root, '/');
  make_config(&config, missing_root);
  snprintf(missing_root, sizeof(missing_root), "%s%cno-parent%cchild", root,
           '/', '/');
  make_config(&config, missing_root);
  memset(&node, 0, sizeof(node));
  check_int_eq(m3_store_node_init_v1(&node, &config), M3_STORE_NODE_IO);

  memset(&node, 0, sizeof(node));
  check_int_eq(m3_store_node_init_v1(&node, NULL), M3_STORE_NODE_INVALID_ARG);
  make_config(&config, root);
  memset(config.node_id, 0, sizeof(config.node_id));
  memset(&node, 0, sizeof(node));
  check_int_eq(m3_store_node_init_v1(&node, &config), M3_STORE_NODE_INVALID_ARG);
  make_config(&config, root);
  memset(&node, 0, sizeof(node));
  check_int_eq(m3_store_node_init_v1(&node, &config), M3_STORE_NODE_OK);
  check_int_eq(m3_store_node_put_chunk_v1(&node, NULL, &request, data,
                                          sizeof(data) - 1u, &receipt),
               M3_STORE_NODE_INVALID_ARG);
  check_int_eq(m3_store_node_read_chunk_v1(&node, NULL, &request, buffer,
                                           sizeof(buffer), &out_read),
               M3_STORE_NODE_INVALID_ARG);
  check_int_eq(m3_store_node_health_v1(&node, NULL), M3_STORE_NODE_INVALID_ARG);
  check_int_eq(m3_store_node_health_v1(NULL, &health),
               M3_STORE_NODE_INVALID_ARG);
  m3_store_node_destroy_v1(&node);

  check_int_eq(tt_remove_tree(root), 0);
  free(root);
}

spec("m3 store node") {
    describe("data plane service") {
        it("puts a chunk and reads it back with receipts") {
            test_store_node_put_read_round_trip();
        }
        it("is idempotent for repeated publishes") {
            test_store_node_put_idempotent();
        }
        it("enforces the per-tenant quota") {
            test_store_node_quota();
        }
        it("rejects wrong audience, request and expired capabilities") {
            test_store_node_rejects_bad_capability();
        }
        it("handles missing chunks and invalid arguments") {
            test_store_node_read_not_found_and_invalid_args();
        }
    }
}
