/* m3_store_node_main.c - M3 store-node executable (data plane).
 *
 * Opens the local immutable CAS as one store node and runs one command, then
 * closes. Sequential processes may share the same store root: the CAS lock is
 * released on close, so a chunk published by one process is readable by the
 * next (cross-process durability smoke).
 *
 * Usage:
 *   m3_store_node_main --root <dir> --node-id <hex32> --key <hex32>
 *       [--max-chunk <bytes>] [--max-tenant <bytes>] [--domain <label>]
 *       put <data>
 *       get <cid-hex> <size>
 *       health
 */

#include "m3_chunk_mesh.h"
#include "m3_store_node.h"

#include <CoroNet/turbo_coro_context.h>
#include <platform.h>
#include <turbo_thread.h>

#include <stdio.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#endif
#include <stdlib.h>
#include <string.h>

static const uint64_t DEFAULT_MAX_CHUNK_BYTES = 64u * 1024u * 1024u;
static const uint64_t DEFAULT_MAX_TENANT_BYTES = 64u * 1024u * 1024u;

static uint64_t g_now_ms(void) {
#ifdef _WIN32
  FILETIME ft;
  ULARGE_INTEGER ul;
  GetSystemTimeAsFileTime(&ft);
  ul.LowPart = ft.dwLowDateTime;
  ul.HighPart = ft.dwHighDateTime;
  /* 100ns intervals since 1601-01-01 -> ms since epoch. */
  return (uint64_t)(ul.QuadPart / 10000u) - 11644473600000ULL;
#else
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000u);
#endif
}

static int hex_value(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

static int hex_to_bytes(const char *text, uint8_t *out, size_t out_size) {
  size_t length = strlen(text);

  if (length != out_size * 2u)
    return -1;
  for (size_t i = 0u; i < out_size; i++) {
    int hi = hex_value(text[i * 2u]);
    int lo = hex_value(text[i * 2u + 1u]);

    if (hi < 0 || lo < 0)
      return -1;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return 0;
}

static void bytes_to_hex(const uint8_t *bytes, size_t size, char *output) {
  static const char digits[] = "0123456789abcdef";

  for (size_t i = 0u; i < size; i++) {
    output[i * 2u] = digits[bytes[i] >> 4u];
    output[i * 2u + 1u] = digits[bytes[i] & 0x0fu];
  }
  output[size * 2u] = '\0';
}

static void fill_tenant(uint8_t tenant_id[32]) {
  for (size_t i = 0u; i < 32u; i++)
    tenant_id[i] = (uint8_t)(0x80u + i);
}

static int build_request(m3_store_node_config_v1_t *config,
                         const m3_chunk_cid_v1_t *cid,
                         m3_chunk_operation_v1_t operation,
                         m3_chunk_capability_claims_v1_t *claims,
                         m3_chunk_access_request_v1_t *request) {
  uint64_t now = g_now_ms();

  memset(claims, 0, sizeof(*claims));
  memset(request, 0, sizeof(*request));
  fill_tenant(claims->tenant_id);
  claims->cid = *cid;
  claims->operation = operation;
  claims->range_offset = 0u;
  claims->range_length = cid->size;
  memcpy(claims->audience_node_id, config->node_id,
         sizeof(claims->audience_node_id));
  claims->request_id.bytes[0] = 0x42u;
  claims->issued_at_ms = now;
  claims->expires_at_ms = now + 3600u * 1000u;

  memcpy(request->tenant_id, claims->tenant_id, sizeof(request->tenant_id));
  request->cid = *cid;
  request->operation = operation;
  request->range_offset = 0u;
  request->range_length = cid->size;
  memcpy(request->local_node_id, config->node_id,
         sizeof(request->local_node_id));
  request->request_id = claims->request_id;
  request->now_ms = now;
  return 0;
}

static int cmd_put(m3_store_node_v1_t *node, m3_store_node_config_v1_t *config,
                   const char *data) {
  m3_chunk_cid_v1_t cid;
  m3_chunk_capability_claims_v1_t claims;
  m3_chunk_access_request_v1_t request;
  m3_chunk_receipt_v1_t receipt;
  uint8_t receipt_digest[32];
  char cid_hex[65];
  char digest_hex[65];
  size_t data_size = strlen(data);
  m3_store_node_result_t result;

  if (m3_chunk_cid_calculate_v1((const uint8_t *)data, data_size, &cid) !=
      M3_CHUNK_STORE_OK) {
    fprintf(stderr, "cid calculation failed\n");
    return 1;
  }
  if (build_request(config, &cid, M3_CHUNK_OPERATION_PUT, &claims, &request) !=
      0) {
    return 1;
  }
  result = m3_store_node_put_chunk_v1(
      node, &claims, &request, (const uint8_t *)data, data_size, &receipt);
  if (result != M3_STORE_NODE_OK) {
    fprintf(stderr, "put failed: %d\n", (int)result);
    return 1;
  }
  if (m3_chunk_receipt_digest_v1(&receipt, receipt_digest) !=
      M3_CHUNK_RECEIPT_OK) {
    return 1;
  }
  bytes_to_hex(cid.digest, sizeof(cid.digest), cid_hex);
  bytes_to_hex(receipt_digest, sizeof(receipt_digest), digest_hex);
  printf("PUT OK cid=%s size=%llu receipt=%s\n", cid_hex,
         (unsigned long long)cid.size, digest_hex);
  return 0;
}

static int cmd_get(m3_store_node_v1_t *node, m3_store_node_config_v1_t *config,
                   const char *cid_hex, const char *size_text) {
  m3_chunk_cid_v1_t cid;
  m3_chunk_capability_claims_v1_t claims;
  m3_chunk_access_request_v1_t request;
  uint8_t *buffer;
  size_t out_read = 0u;
  char data_hex[256];
  m3_store_node_result_t result;

  memset(&cid, 0, sizeof(cid));
  cid.hash_algorithm = M3_CHUNK_STORE_HASH_ALGORITHM_SHA256;
  cid.size = (uint64_t)strtoull(size_text, NULL, 10);
  if (hex_to_bytes(cid_hex, cid.digest, sizeof(cid.digest)) != 0 ||
      cid.size == 0u || cid.size > 128u * 1024u) {
    fprintf(stderr, "bad cid/size\n");
    return 1;
  }
  buffer = (uint8_t *)malloc((size_t)cid.size);
  if (!buffer)
    return 1;
  if (build_request(config, &cid, M3_CHUNK_OPERATION_READ, &claims, &request) !=
      0) {
    free(buffer);
    return 1;
  }
  result = m3_store_node_read_chunk_v1(node, &claims, &request, buffer,
                                       (size_t)cid.size, &out_read);
  if (result != M3_STORE_NODE_OK) {
    fprintf(stderr, "get failed: %d\n", (int)result);
    free(buffer);
    return 1;
  }
  bytes_to_hex(buffer, out_read, data_hex);
  printf("GET OK size=%llu data=%s\n", (unsigned long long)out_read, data_hex);
  free(buffer);
  return 0;
}

static int cmd_health(m3_store_node_v1_t *node) {
  m3_store_node_health_v1_t health;
  m3_store_node_result_t result;

  result = m3_store_node_health_v1(node, &health);
  if (result != M3_STORE_NODE_OK) {
    fprintf(stderr, "health failed: %d\n", (int)result);
    return 1;
  }
  printf("HEALTH domain=%s tenants=%zu used=%llu quota=%llu free=%llu "
         "headroom=%llu\n",
         health.failure_domain, health.tenant_count,
         (unsigned long long)health.used_bytes,
         (unsigned long long)health.quota_limit_bytes,
         (unsigned long long)health.free_capacity_bytes,
         (unsigned long long)health.min_tenant_headroom_bytes);
  return 0;
}

static volatile int g_mesh_stop = 0;

#ifdef _WIN32
static BOOL WINAPI mesh_ctrl_handler(DWORD ctrl_type) {
  (void)ctrl_type;
  g_mesh_stop = 1;
  return TRUE;
}
#endif

typedef struct {
  p2p_node_t *node;
  volatile LONG running;
  HANDLE thread;
} mesh_pump_ctx_t;

static DWORD WINAPI mesh_pump_loop(LPVOID arg) {
  mesh_pump_ctx_t *ctx = (mesh_pump_ctx_t *)arg;
  while (InterlockedCompareExchange(&ctx->running, 0, 0) != 0) {
    coro_context_run(p2p_get_loop(ctx->node), TURBO_RUN_NOWAIT);
    turbo_sleep_ms(2);
  }
  return 0;
}

/* Serve chunk PUT/GET over p2p until interrupted. trusted_gateway_keys are
 * the Ed25519 private keys of the gateways allowed to write (the service
 * derives and allowlists their public keys). */
static int run_mesh_serve(m3_store_node_config_v1_t *config,
                          const uint8_t node_id[M3_CHUNK_CAPABILITY_NODE_ID_SIZE],
                          int mesh_port,
                          const uint8_t *const gateway_keys[],
                          size_t gateway_count) {
  m3_store_node_v1_t node;
  m3_chunk_mesh_service_v1_t service;
  p2p_node_t *p2p = NULL;
  mesh_pump_ctx_t pump = {0};
  uint8_t public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE];

  memset(&node, 0, sizeof(node));
  memset(&service, 0, sizeof(service));
  if (m3_store_node_init_v1(&node, config) != M3_STORE_NODE_OK) {
    fprintf(stderr, "store node init failed\n");
    return 1;
  }
  p2p = p2p_create("127.0.0.1", mesh_port);
  if (!p2p) {
    fprintf(stderr, "p2p create failed\n");
    m3_store_node_destroy_v1(&node);
    return 1;
  }
  if (m3_chunk_mesh_service_init_v1(&service, p2p, &node) !=
      M3_CHUNK_MESH_OK) {
    fprintf(stderr, "mesh service init failed\n");
    p2p_destroy(p2p);
    m3_store_node_destroy_v1(&node);
    return 1;
  }
  for (size_t i = 0u; i < gateway_count; i++) {
    if (mesh_mgmt_ed25519_public_from_private(gateway_keys[i], public_key) !=
            MESH_MGMT_CRYPTO_OK ||
        m3_chunk_mesh_service_add_trusted_key_v1(&service, public_key) !=
            M3_CHUNK_MESH_OK) {
      fprintf(stderr, "trusted gateway key %zu invalid\n", i);
      m3_chunk_mesh_service_destroy_v1(&service);
      p2p_destroy(p2p);
      m3_store_node_destroy_v1(&node);
      return 1;
    }
  }
  if (p2p_start_nonblocking(p2p) != P2P_OK) {
    fprintf(stderr, "p2p start failed\n");
    m3_chunk_mesh_service_destroy_v1(&service);
    p2p_destroy(p2p);
    m3_store_node_destroy_v1(&node);
    return 1;
  }
  pump.node = p2p;
  InterlockedExchange(&pump.running, 1);
  pump.thread = CreateThread(NULL, 0, mesh_pump_loop, &pump, 0, NULL);
  printf("store mesh serving on :%d (node=%02x.. trusted gateways=%zu) pubkey=",
         mesh_port, node_id[0], gateway_count);
  {
    char key_hex[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE * 2u + 1u];

    if (mesh_mgmt_ed25519_public_from_private(
            config->signing_private_key, public_key) == MESH_MGMT_CRYPTO_OK) {
      bytes_to_hex(public_key, sizeof(public_key), key_hex);
      printf("%s", key_hex);
    } else {
      printf("(unavailable)");
    }
  }
  printf("\n");
  fflush(stdout);
  while (!g_mesh_stop)
    turbo_sleep_ms(100);
  InterlockedExchange(&pump.running, 0);
  WaitForSingleObject(pump.thread, 5000);
  CloseHandle(pump.thread);
  m3_chunk_mesh_service_destroy_v1(&service);
  p2p_destroy(p2p);
  m3_store_node_destroy_v1(&node);
  return 0;
}

int main(int argc, char **argv) {
  m3_store_node_config_v1_t config;
  m3_store_node_v1_t node;
  const char *root = NULL;
  const char *node_id_hex = NULL;
  const char *key_hex = NULL;
  int command_index = 0;
  int exit_code = 1;
  int mesh_serve = 0;
  int mesh_port = 0;
  const uint8_t *trusted_gateway_keys[M3_CHUNK_MESH_MAX_TRUSTED_KEYS];
  uint8_t trusted_gateway_storage[M3_CHUNK_MESH_MAX_TRUSTED_KEYS]
                                 [MESH_MGMT_ED25519_PRIVATE_KEY_SIZE];
  size_t trusted_gateway_count = 0u;

  memset(&config, 0, sizeof(config));
  config.max_chunk_bytes = DEFAULT_MAX_CHUNK_BYTES;
  config.max_tenant_bytes = DEFAULT_MAX_TENANT_BYTES;
  snprintf(config.failure_domain, sizeof(config.failure_domain), "dc-a");
  config.policy.max_ttl_ms = 7200u * 1000u;
  config.policy.max_read_bytes = 64u * 1024u * 1024u;
  config.policy.max_put_bytes = 64u * 1024u * 1024u;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--root") == 0 && i + 1 < argc) {
      root = argv[++i];
    } else if (strcmp(argv[i], "--node-id") == 0 && i + 1 < argc) {
      node_id_hex = argv[++i];
    } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
      key_hex = argv[++i];
    } else if (strcmp(argv[i], "--max-chunk") == 0 && i + 1 < argc) {
      config.max_chunk_bytes = (uint64_t)strtoull(argv[++i], NULL, 10);
    } else if (strcmp(argv[i], "--max-tenant") == 0 && i + 1 < argc) {
      config.max_tenant_bytes = (uint64_t)strtoull(argv[++i], NULL, 10);
    } else if (strcmp(argv[i], "--domain") == 0 && i + 1 < argc) {
      snprintf(config.failure_domain, sizeof(config.failure_domain), "%s",
               argv[++i]);
    } else if (strcmp(argv[i], "--mesh-serve") == 0) {
      mesh_serve = 1;
    } else if (strcmp(argv[i], "--mesh-listen") == 0 && i + 1 < argc) {
      mesh_port = atoi(argv[++i]);
    } else if (strcmp(argv[i], "--trusted-gateway") == 0 && i + 1 < argc) {
      if (trusted_gateway_count >= M3_CHUNK_MESH_MAX_TRUSTED_KEYS ||
          hex_to_bytes(argv[++i], trusted_gateway_storage[trusted_gateway_count],
                       MESH_MGMT_ED25519_PRIVATE_KEY_SIZE) != 0) {
        fprintf(stderr, "invalid --trusted-gateway key\n");
        return 2;
      }
      trusted_gateway_keys[trusted_gateway_count] =
          trusted_gateway_storage[trusted_gateway_count];
      trusted_gateway_count++;
    } else if (argv[i][0] == '-') {
      fprintf(stderr, "unknown option: %s\n", argv[i]);
      return 2;
    } else {
      command_index = i;
      break; /* command begins */
    }
  }
  if ((!mesh_serve && argc - 1 < 1) || !root || !node_id_hex || !key_hex ||
      hex_to_bytes(node_id_hex, config.node_id, sizeof(config.node_id)) != 0 ||
      hex_to_bytes(key_hex, config.signing_private_key,
                   sizeof(config.signing_private_key)) != 0) {
    fprintf(stderr,
            "usage: %s --root <dir> --node-id <hex32> --key <hex32> "
            "[--max-chunk <bytes>] [--max-tenant <bytes>] [--domain <label>] "
            "[--mesh-serve --mesh-listen <port> --trusted-gateway <hex32>...] "
            "{ put <data> | get <cid-hex> <size> | health }\n",
            argv[0]);
    return 2;
  }
  snprintf(config.store_root, sizeof(config.store_root), "%s", root);

  if (mesh_serve) {
    if (mesh_port <= 0 || mesh_port > 65535 || trusted_gateway_count == 0u) {
      fprintf(stderr,
              "--mesh-serve requires --mesh-listen <port> and "
              "--trusted-gateway <hex32>\n");
      return 2;
    }
    return run_mesh_serve(&config, config.node_id, mesh_port,
                          trusted_gateway_keys, trusted_gateway_count);
  }

  memset(&node, 0, sizeof(node));
  if (m3_store_node_init_v1(&node, &config) != M3_STORE_NODE_OK) {
    fprintf(stderr, "store node init failed\n");
    return 1;
  }
  if (strcmp(argv[command_index], "health") == 0) {
    exit_code = cmd_health(&node);
  } else if (strcmp(argv[command_index], "put") == 0 &&
             argc - command_index >= 2) {
    exit_code = cmd_put(&node, &config, argv[command_index + 1]);
  } else if (strcmp(argv[command_index], "get") == 0 &&
             argc - command_index >= 3) {
    exit_code = cmd_get(&node, &config, argv[command_index + 1],
                        argv[command_index + 2]);
  } else {
    fprintf(stderr, "unknown command\n");
    exit_code = 2;
  }
  m3_store_node_destroy_v1(&node);
  return exit_code;
}
