#include <tinytest.h>

#include "m3_chunk_mesh.h"
#include "m3_store_node.h"

#include <CoroNet/turbo_coro_context.h>
#include <turbo_thread.h>

#include <stdio.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <direct.h>
#include <windows.h>
#endif

/* P4: authenticated chunk transport over p2p nodes. The gateway signs a
 * capability with its p2p identity key; the store verifies it against the
 * connected peer's public key, authorizes against its own audience, executes
 * PUT/READ and replies with a signed receipt / range bytes. */

static const uint8_t GATEWAY_KEY[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};

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

typedef struct {
  p2p_node_t *node;
  volatile LONG running;
  HANDLE thread;
} pump_ctx_t;

static DWORD WINAPI pump_loop(LPVOID arg) {
  pump_ctx_t *ctx = (pump_ctx_t *)arg;
  while (InterlockedCompareExchange(&ctx->running, 0, 0) != 0) {
    coro_context_run(p2p_get_loop(ctx->node), TURBO_RUN_NOWAIT);
    turbo_sleep_ms(2);
  }
  return 0;
}

static void pump_start(pump_ctx_t *ctx, p2p_node_t *node) {
  memset(ctx, 0, sizeof(*ctx));
  ctx->node = node;
  InterlockedExchange(&ctx->running, 1);
  ctx->thread = CreateThread(NULL, 0, pump_loop, ctx, 0, NULL);
  check_true(ctx->thread != NULL);
}

static void pump_stop(pump_ctx_t *ctx) {
  if (ctx->thread == NULL)
    return;
  InterlockedExchange(&ctx->running, 0);
  WaitForSingleObject(ctx->thread, 5000);
  CloseHandle(ctx->thread);
  ctx->thread = NULL;
}

static void make_store_node(m3_store_node_v1_t *node, char *root, size_t root_cap,
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

static void make_claims(m3_chunk_capability_claims_v1_t *claims,
                        const m3_chunk_cid_v1_t *cid,
                        m3_chunk_operation_v1_t operation,
                        const uint8_t audience[32]) {
  memset(claims, 0, sizeof(*claims));
  for (size_t i = 0u; i < sizeof(claims->tenant_id); i++)
    claims->tenant_id[i] = (uint8_t)(0x11u + i);
  claims->cid = *cid;
  claims->operation = operation;
  claims->range_offset = 0u;
  claims->range_length = cid->size;
  memcpy(claims->audience_node_id, audience, sizeof(claims->audience_node_id));
  claims->request_id.bytes[0] = 0x51u;
  claims->issued_at_ms = g_now_ms();
  claims->expires_at_ms = claims->issued_at_ms + TEST_POLICY.max_ttl_ms;
}

static void test_wire_codec(void) {
  m3_chunk_capability_claims_v1_t claims;
  m3_chunk_capability_claims_v1_t decoded;
  uint8_t encoded[M3_CHUNK_MESH_CLAIMS_SIZE];
  uint8_t signature[M3_CHUNK_MESH_SIGNATURE_SIZE];
  uint8_t public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE];
  uint8_t channel_key[M3_CHUNK_MESH_CHANNEL_KEY_SIZE];
  uint8_t signer_key[M3_CHUNK_MESH_SIGNER_KEY_SIZE];
  uint8_t frame[M3_CHUNK_MESH_FRAME_MAX];
  size_t frame_size = 0u;
  m3_chunk_mesh_frame_type_t type;
  m3_chunk_mesh_operation_t op;
  int32_t status;
  uint8_t corr[16];
  const uint8_t *claims_view;
  const uint8_t *sig_view;
  const uint8_t *channel_view;
  const uint8_t *signer_view;
  const uint8_t *payload_view;
  size_t payload_len = 0u;
  static const uint8_t payload[] = "chunk-bytes";
  uint8_t corr_src[16];

  make_claims(&claims, &(m3_chunk_cid_v1_t){0}, M3_CHUNK_OPERATION_READ,
              (uint8_t[32]){0});
  claims.cid.hash_algorithm = M3_CHUNK_STORE_HASH_ALGORITHM_SHA256;
  claims.cid.size = 3u;
  memset(claims.cid.digest, 0x5a, sizeof(claims.cid.digest));
  memset(claims.audience_node_id, 0x40, sizeof(claims.audience_node_id));

  check_int_eq(M3_CHUNK_MESH_OK,
               m3_chunk_mesh_claims_encode_v1(&claims, encoded));
  check_int_eq(M3_CHUNK_MESH_OK,
               m3_chunk_mesh_claims_decode_v1(encoded, &decoded));
  check_mem_eq(&claims, &decoded, sizeof(claims));
  encoded[10] ^= 0x01u;
  check_int_eq(M3_CHUNK_MESH_OK,
               m3_chunk_mesh_claims_decode_v1(encoded, &decoded));
  check_int_ne(decoded.tenant_id[10], claims.tenant_id[10]);

  check_int_eq(mesh_mgmt_ed25519_public_from_private(GATEWAY_KEY, public_key),
               MESH_MGMT_CRYPTO_OK);
  memset(channel_key, 0x22, sizeof(channel_key));
  memcpy(signer_key, public_key, sizeof(signer_key));
  check_int_eq(M3_CHUNK_MESH_OK,
               m3_chunk_mesh_claims_sign_v1(GATEWAY_KEY, &claims, signature));
  check_int_eq(M3_CHUNK_MESH_OK,
               m3_chunk_mesh_claims_verify_v1(public_key, &claims, signature));
  signature[0] ^= 0x01u;
  check_int_eq(M3_CHUNK_MESH_AUTH_FAILED,
               m3_chunk_mesh_claims_verify_v1(public_key, &claims, signature));
  signature[0] ^= 0x01u;

  memset(corr_src, 0x33, sizeof(corr_src));
  check_int_eq(M3_CHUNK_MESH_OK,
               m3_chunk_mesh_frame_encode_v1(
                   M3_CHUNK_MESH_FRAME_REQUEST, M3_CHUNK_MESH_OP_PUT, 0,
                   corr_src, encoded, signature, channel_key, signer_key,
                   payload, sizeof(payload), frame, sizeof(frame), &frame_size));
  check_int_eq(M3_CHUNK_MESH_OK,
               m3_chunk_mesh_frame_decode_v1(frame, frame_size, &type, &op,
                                             &status, corr, &claims_view,
                                             &sig_view, &channel_view,
                                             &signer_view, &payload_view,
                                             &payload_len));
  check_int_eq((int)M3_CHUNK_MESH_FRAME_REQUEST, (int)type);
  check_int_eq((int)M3_CHUNK_MESH_OP_PUT, (int)op);
  check_int_eq(0, status);
  check_mem_eq(corr, corr_src, sizeof(corr));
  check_mem_eq(claims_view, encoded, M3_CHUNK_MESH_CLAIMS_SIZE);
  check_mem_eq(sig_view, signature, M3_CHUNK_MESH_SIGNATURE_SIZE);
  check_mem_eq(channel_view, channel_key, M3_CHUNK_MESH_CHANNEL_KEY_SIZE);
  check_mem_eq(signer_view, signer_key, M3_CHUNK_MESH_SIGNER_KEY_SIZE);
  check_size_eq(payload_len, sizeof(payload));
  check_mem_eq(payload_view, payload, sizeof(payload));

  check_int_eq(M3_CHUNK_MESH_OVERFLOW,
               m3_chunk_mesh_frame_encode_v1(
                   M3_CHUNK_MESH_FRAME_REQUEST, M3_CHUNK_MESH_OP_PUT, 0,
                   corr_src, encoded, signature, channel_key, signer_key,
                   payload, M3_CHUNK_MESH_MAX_PAYLOAD + 1u, frame,
                   sizeof(frame), &frame_size));
  frame[0] ^= 0xffu;
  check_int_eq(M3_CHUNK_MESH_CORRUPT,
               m3_chunk_mesh_frame_decode_v1(frame, frame_size, &type, &op,
                                             &status, corr, &claims_view,
                                             &sig_view, &channel_view,
                                             &signer_view, &payload_view,
                                             &payload_len));
}

static void test_store_service_over_p2p(void) {
  m3_store_node_v1_t store;
  char root[512];
  p2p_node_t *store_node = NULL;
  p2p_node_t *gateway_node = NULL;
  m3_chunk_mesh_service_v1_t service;
  m3_chunk_mesh_router_v1_t router;
  m3_chunk_mesh_client_v1_t client;
  pump_ctx_t store_pump;
  pump_ctx_t gateway_pump;
  uint8_t store_public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE];
  uint8_t gateway_public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE];
  uint8_t store_node_id[32];
  m3_chunk_capability_claims_v1_t claims;
  m3_chunk_receipt_v1_t receipt;
  m3_chunk_cid_v1_t cid;
  uint8_t signature[M3_CHUNK_MESH_SIGNATURE_SIZE];
  uint8_t buffer[128];
  size_t read = 0u;
  static const uint8_t body[] = "mesh-transported chunk payload";

  make_store_node(&store, root, sizeof(root), "m3-mesh-store");
  for (int i = 0; i < 32; i++)
    store_node_id[i] = (uint8_t)(0x30u + i);
  check_int_eq(mesh_mgmt_ed25519_public_from_private(STORE_KEY, store_public_key),
               MESH_MGMT_CRYPTO_OK);
  check_int_eq(mesh_mgmt_ed25519_public_from_private(GATEWAY_KEY,
                                                     gateway_public_key),
               MESH_MGMT_CRYPTO_OK);
  check_int_eq(m3_chunk_cid_calculate_v1(body, sizeof(body) - 1u, &cid),
               M3_CHUNK_STORE_OK);

  store_node = p2p_create("127.0.0.1", 20401);
  gateway_node = p2p_create("127.0.0.1", 20402);
  check_not_null(store_node);
  check_not_null(gateway_node);
  check_int_eq(P2P_OK, p2p_node_set_private_key(gateway_node, GATEWAY_KEY));

  memset(&service, 0, sizeof(service));
  memset(&router, 0, sizeof(router));
  memset(&client, 0, sizeof(client));
  check_int_eq(M3_CHUNK_MESH_OK,
               m3_chunk_mesh_service_init_v1(&service, store_node, &store));
  check_int_eq(M3_CHUNK_MESH_OK,
               m3_chunk_mesh_service_add_trusted_key_v1(&service,
                                                        gateway_public_key));
  check_int_eq(M3_CHUNK_MESH_OK,
               m3_chunk_mesh_router_init_v1(&router, gateway_node));
  check_int_eq(M3_CHUNK_MESH_OK,
               m3_chunk_mesh_client_connect_v1(&client, gateway_node,
                                               store_node_id, store_public_key,
                                               "127.0.0.1", 20401));
  check_int_eq(M3_CHUNK_MESH_OK,
               m3_chunk_mesh_router_add_client_v1(&router, &client));

  /* Establish the connection by pumping both loops in this thread (the
   * known-good p2p pattern), then hand the loops to background pumps for the
   * blocking chunk calls. */
  check_int_eq(P2P_OK, p2p_start_nonblocking(store_node));
  check_int_eq(P2P_OK, p2p_start_nonblocking(gateway_node));
  {
    uint64_t deadline = turbo_monotonic_ms() + 10000u;
    while (turbo_monotonic_ms() < deadline && !client.peer) {
      coro_context_run(p2p_get_loop(store_node), TURBO_RUN_NOWAIT);
      coro_context_run(p2p_get_loop(gateway_node), TURBO_RUN_NOWAIT);
      turbo_sleep_ms(5);
    }
    check_true(client.peer != NULL);
  }
  pump_start(&store_pump, store_node);
  pump_start(&gateway_pump, gateway_node);

  /* PUT over the authenticated channel; the store signs a durable receipt. */
  /* PUT over the authenticated channel; the store signs a durable receipt. */
  make_claims(&claims, &cid, M3_CHUNK_OPERATION_PUT, store_node_id);
  check_int_eq(M3_CHUNK_MESH_OK,
               m3_chunk_mesh_claims_sign_v1(GATEWAY_KEY, &claims, signature));
  check_int_eq(M3_CHUNK_MESH_OK,
               m3_chunk_mesh_client_put_v1(&client, &claims, signature,
                                           gateway_public_key, body,
                                           sizeof(body) - 1u, 15000u, &receipt));
  check_int_eq(M3_CHUNK_RECEIPT_OK,
               m3_chunk_receipt_verify_v1(store_public_key, &receipt));
  check_int_eq(M3_CHUNK_RECEIPT_OK,
               m3_chunk_receipt_check_binding_v1(&receipt, store_node_id, &cid,
                                                 &claims.request_id, g_now_ms(),
                                                 TEST_POLICY.max_ttl_ms));

  /* GET returns the range bytes with full chunk verification on the store. */
  make_claims(&claims, &cid, M3_CHUNK_OPERATION_READ, store_node_id);
  check_int_eq(M3_CHUNK_MESH_OK,
               m3_chunk_mesh_claims_sign_v1(GATEWAY_KEY, &claims, signature));
  check_int_eq(M3_CHUNK_MESH_OK,
               m3_chunk_mesh_client_get_v1(&client, &claims, signature,
                                           gateway_public_key, buffer,
                                           sizeof(buffer), &read, 15000u));
  check_size_eq(read, sizeof(body) - 1u);
  check_mem_eq(buffer, body, read);

  /* A capability signed by a different identity is rejected. */
  make_claims(&claims, &cid, M3_CHUNK_OPERATION_PUT, store_node_id);
  check_int_eq(M3_CHUNK_MESH_OK,
               m3_chunk_mesh_claims_sign_v1(STORE_KEY, &claims, signature));
  check_int_eq(M3_CHUNK_MESH_AUTH_FAILED,
               m3_chunk_mesh_client_put_v1(&client, &claims, signature,
                                           gateway_public_key, body,
                                           sizeof(body) - 1u, 15000u, &receipt));

  pump_stop(&gateway_pump);
  pump_stop(&store_pump);
  m3_chunk_mesh_client_destroy_v1(&client);
  m3_chunk_mesh_router_destroy_v1(&router);
  m3_chunk_mesh_service_destroy_v1(&service);
  p2p_destroy(gateway_node);
  p2p_destroy(store_node);
  m3_store_node_destroy_v1(&store);
}

spec("m3 chunk mesh") {
    describe("authenticated chunk transport") {
        it("round-trips the wire codec and rejects tampering") {
            test_wire_codec();
        }
        it("transfers chunks between a gateway client and a store service") {
            test_store_service_over_p2p();
        }
    }
}
