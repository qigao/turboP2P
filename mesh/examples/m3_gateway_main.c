/* m3_gateway_main.c - Phase 1 single-node M3 S3 gateway entry point.
 *
 * Usage: m3_gateway_main <store-root> [port]
 *
 * Demo credential: access key "AKIDEXAMPLE", secret from M3_SECRET_HEX
 * (32-byte hex; defaults to the same test secret used by
 * test_m3_gateway_sigv4). region=us-east-1, service=s3.
 */

#include "m3_gateway.h"

#ifdef TURBO_P2P_M3_RAFT_ENABLED
  #include "m3_gateway_raft.h"
  #include "m3_raft_node.h"
#endif

#include <CoroNet/turbo_coro_context.h>
#include <iris/iris.h>
#include <turbo_fs.h>
#include <turbo_thread.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hex_value(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

static int parse_hex(const char *hex, uint8_t *out, size_t out_cap) {
  size_t len = strlen(hex);
  size_t i;

  if (len != out_cap * 2u)
    return -1;
  for (i = 0u; i < out_cap; i++) {
    int hi = hex_value(hex[i * 2u]);
    int lo = hex_value(hex[i * 2u + 1u]);
    if (hi < 0 || lo < 0)
      return -1;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return 0;
}

#ifdef _WIN32
#include <windows.h>
#ifdef TURBO_P2P_M3_RAFT_ENABLED
static volatile LONG g_gateway_pump_stop = 0;
static HANDLE g_gateway_pump_thread = NULL;

static DWORD WINAPI gateway_node_pump(LPVOID arg) {
  m3_gateway_t *gateway = (m3_gateway_t *)arg;
  uint64_t last_status_ms = 0u;
  while (InterlockedCompareExchange(&g_gateway_pump_stop, 0, 0) == 0) {
    m3_gateway_poll_v1(gateway);
    if (turbo_monotonic_ms() - last_status_ms >= 2000u) {
      int leader = 0;
      last_status_ms = turbo_monotonic_ms();
      (void)m3_raft_node_is_leader(gateway->node, &leader);
      printf("gateway raft leader=%d applied=%llu\n", leader,
             (unsigned long long)m3_raft_node_applied_index(gateway->node));
      fflush(stdout);
    }
    Sleep(1);
  }
  return 0;
}
#endif
#endif

typedef struct {
  p2p_node_t *node;
  volatile LONG running;
  HANDLE thread;
} gateway_mesh_pump_ctx_t;

static gateway_mesh_pump_ctx_t g_mesh_pump = {0};

static DWORD WINAPI gateway_mesh_pump_loop(LPVOID arg) {
  gateway_mesh_pump_ctx_t *ctx = (gateway_mesh_pump_ctx_t *)arg;
  while (InterlockedCompareExchange(&ctx->running, 0, 0) != 0) {
    coro_context_run(p2p_get_loop(ctx->node), TURBO_RUN_NOWAIT);
    turbo_sleep_ms(2);
  }
  return 0;
}

static void gateway_mesh_pump_stop(gateway_mesh_pump_ctx_t *ctx) {
  if (ctx->thread == NULL)
    return;
  InterlockedExchange(&ctx->running, 0);
  WaitForSingleObject(ctx->thread, 5000);
  CloseHandle(ctx->thread);
  ctx->thread = NULL;
}

static int parse_hex_id(const char *hex, size_t hex_len,
                        uint8_t out[M3_CHUNK_CAPABILITY_NODE_ID_SIZE]) {
  static const char digits[] = "0123456789abcdef";

  if (hex_len != M3_CHUNK_CAPABILITY_NODE_ID_SIZE * 2u)
    return -1;
  for (size_t i = 0u; i < M3_CHUNK_CAPABILITY_NODE_ID_SIZE; i++) {
    int hi = -1;
    int lo = -1;

    for (int d = 0; d < 16; d++) {
      if ((char)hex[i * 2u] == digits[d])
        hi = d;
      if ((char)hex[i * 2u + 1u] == digits[d])
        lo = d;
    }
    if (hi < 0 || lo < 0)
      return -1;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return 0;
}

static int ensure_directory(const char *path) {
  turbo_fs_stat_t stat;

  if (turbo_fs_access(path, TURBO_FS_ACCESS_EXISTS) == 0) {
    if (turbo_fs_stat(path, &stat) == 0 && stat.is_directory)
      return 0;
    return -1;
  }
  return turbo_fs_mkdir(path, 0755);
}

int main(int argc, char **argv) {
  enum { M3_GATEWAY_MAIN_MAX_RAFT_PEERS = 32 };
  const char *root;
  const char *secret_hex;
  const char *raft_sqlite = NULL;
  int port = 8080;
  int raft_node = 0;
  uint64_t node_id = 0u;
  int raft_listen_port = 0;
  const char *cert = NULL;
  const char *key = NULL;
  const char *ca = NULL;
  uint64_t node_voters[M3_GATEWAY_MAIN_MAX_RAFT_PEERS + 1u];
#ifdef TURBO_P2P_M3_RAFT_ENABLED
  m3_raft_node_peer_config_t peers[M3_GATEWAY_MAIN_MAX_RAFT_PEERS];
  size_t peer_count = 0u;
#endif
  size_t voter_count = 0u;
  int mesh_listen_port = 0;
  const char *mesh_key_hex = NULL;
  char mesh_store_hosts[M3_GATEWAY_DATAPANE_MAX_STORES][128];
  int mesh_store_ports[M3_GATEWAY_DATAPANE_MAX_STORES];
  uint8_t mesh_store_ids[M3_GATEWAY_DATAPANE_MAX_STORES]
                        [M3_CHUNK_CAPABILITY_NODE_ID_SIZE];
  uint8_t mesh_store_pubkeys[M3_GATEWAY_DATAPANE_MAX_STORES]
                            [MESH_MGMT_ED25519_PUBLIC_KEY_SIZE];
  uint8_t mesh_store_transport_keys[M3_GATEWAY_DATAPANE_MAX_STORES]
                                  [P2P_KEY_SIZE];
  size_t mesh_store_count = 0u;
  uint64_t max_chunk_bytes = UINT64_C(1024) * 1024;
  size_t target_replicas = 2u;
  size_t min_durable_replicas = 2u;
  m3_sigv4_credential_v1_t credential = {0};
  m3_gateway_t gateway;
  iris_app_t *app;

  if (argc < 2) {
    fprintf(stderr,
            "usage: %s <store-root> [port] [--raft <sqlite>]\n"
            "       [--raft-node --node-id <id> --raft-listen-port <p> --sqlite <s>\n"
            "        --cert <file> --key <file> --ca <file> --voter <id>...\n"
            "        --peer <id>@<host>:<port>:<sha256:fp>...]\n"
            "       [--mesh-listen <port> --mesh-key <hex32>\n"
            "        --store-peer <id>:<signing-pubkey>:<transport-pubkey>@<host>:<port>...]\n",
            argv[0]);
    return 2;
  }
  root = argv[1];
  if (argc > 2)
    port = atoi(argv[2]);
  for (int i = 3; i < argc; i++) {
    if (strcmp(argv[i], "--raft") == 0 && i + 1 < argc) {
      raft_sqlite = argv[i + 1];
      i++;
    } else if (strcmp(argv[i], "--sqlite") == 0 && i + 1 < argc) {
      raft_sqlite = argv[i + 1];
      i++;
    } else if (strcmp(argv[i], "--raft-node") == 0) {
      raft_node = 1;
    } else if (strcmp(argv[i], "--node-id") == 0 && i + 1 < argc) {
      node_id = (uint64_t)strtoull(argv[++i], NULL, 10);
    } else if (strcmp(argv[i], "--raft-listen-port") == 0 && i + 1 < argc) {
      raft_listen_port = atoi(argv[++i]);
    } else if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
      cert = argv[++i];
    } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
      key = argv[++i];
    } else if (strcmp(argv[i], "--ca") == 0 && i + 1 < argc) {
      ca = argv[++i];
    } else if (strcmp(argv[i], "--voter") == 0 && i + 1 < argc) {
      if (voter_count < sizeof(node_voters) / sizeof(node_voters[0])) {
        node_voters[voter_count++] = (uint64_t)strtoull(argv[++i], NULL, 10);
      }
    } else if (strcmp(argv[i], "--max-chunk") == 0 && i + 1 < argc) {
      max_chunk_bytes = (uint64_t)strtoull(argv[++i], NULL, 10);
    } else if (strcmp(argv[i], "--replicas") == 0 && i + 2 < argc) {
      target_replicas = (size_t)strtoul(argv[++i], NULL, 10);
      min_durable_replicas = (size_t)strtoul(argv[++i], NULL, 10);
    } else if (strcmp(argv[i], "--mesh-listen") == 0 && i + 1 < argc) {
      mesh_listen_port = atoi(argv[++i]);
    } else if (strcmp(argv[i], "--mesh-key") == 0 && i + 1 < argc) {
      mesh_key_hex = argv[++i];
    } else if (strcmp(argv[i], "--store-peer") == 0 && i + 1 < argc) {
      const char *spec = argv[++i];
      const char *at = strchr(spec, '@');
      const char *colon = strchr(spec, ':');
      const char *transport_colon = colon ? strchr(colon + 1, ':') : NULL;
      char host[128];
      char port_s[16];
      uint8_t id[32];
      uint8_t pub[32];
      uint8_t transport_pub[32];

      if (at && colon && transport_colon && colon < transport_colon &&
          transport_colon < at &&
          mesh_store_count < M3_GATEWAY_DATAPANE_MAX_STORES &&
          parse_hex_id(colon + 1,
                       (size_t)(transport_colon - colon - 1u), pub) == 0 &&
          parse_hex_id(transport_colon + 1,
                       (size_t)(at - transport_colon - 1u),
                       transport_pub) == 0 &&
          parse_hex_id(spec, (size_t)(colon - spec), id) == 0 &&
          sscanf(at + 1, "%127[^:]:%15[0-9]", host, port_s) == 2) {
        memcpy(mesh_store_ids[mesh_store_count], id, sizeof(id));
        memcpy(mesh_store_pubkeys[mesh_store_count], pub, sizeof(pub));
        memcpy(mesh_store_transport_keys[mesh_store_count], transport_pub,
               sizeof(transport_pub));
        snprintf(mesh_store_hosts[mesh_store_count],
                 sizeof(mesh_store_hosts[mesh_store_count]), "%s", host);
        mesh_store_ports[mesh_store_count] = atoi(port_s);
        mesh_store_count++;
      } else {
        fprintf(stderr,
                "invalid --store-peer spec "
                "(id:signing-pubkey:transport-pubkey@host:port): %s\n",
                spec);
        return 2;
      }
    } else if (strcmp(argv[i], "--peer") == 0 && i + 1 < argc) {
#ifdef TURBO_P2P_M3_RAFT_ENABLED
      const char *spec = argv[++i];
      const char *at = strchr(spec, '@');
      char host[128];
      char port_s[16];
      char fingerprint[96];
      if (at && peer_count < M3_GATEWAY_MAIN_MAX_RAFT_PEERS &&
          sscanf(at + 1, "%127[^:]:%15[0-9]:%95s", host, port_s, fingerprint) == 3) {
        memset(&peers[peer_count], 0, sizeof(peers[peer_count]));
        peers[peer_count].node_id = (tr_raft_node_id_t)strtoul(spec, NULL, 10);
        snprintf(peers[peer_count].connect_host, sizeof(peers[peer_count].connect_host),
                 "%s", host);
        snprintf(peers[peer_count].request_host, sizeof(peers[peer_count].request_host),
                 "localhost");
        peers[peer_count].port = atoi(port_s);
        snprintf(peers[peer_count].certificate_sha256,
                 sizeof(peers[peer_count].certificate_sha256), "%s", fingerprint);
        peer_count++;
      } else {
        fprintf(stderr, "invalid --peer spec: %s\n", spec);
        return 2;
      }
#else
      fprintf(stderr, "--peer requires a TurboRaft-enabled build\n");
      return 2;
#endif
    }
  }
  secret_hex = getenv("M3_SECRET_HEX");
  if (!secret_hex) {
    secret_hex = "606162636465666768696a6b6c6d6e6f"
                 "707172737475767778797a3031323334";
  }

  strcpy(credential.access_key, "AKIDEXAMPLE");
  credential.region = "us-east-1";
  credential.service = "s3";
  credential.clock_skew_seconds = 900;
  if (parse_hex(secret_hex, credential.secret_key, sizeof(credential.secret_key)) != 0) {
    fprintf(stderr, "M3_SECRET_HEX must be 64 hex chars\n");
    return 2;
  }

  if (ensure_directory(root) != 0) {
    fprintf(stderr, "cannot prepare store root %s\n", root);
    return 1;
  }
  {
    int init_result = -1;
#ifdef TURBO_P2P_M3_RAFT_ENABLED
    if (raft_node) {
      m3_raft_node_config_t node_config = {0};

      if (node_id == 0u || raft_listen_port <= 0 || !cert || !key || !ca ||
          voter_count == 0u || peer_count == 0u) {
        fprintf(stderr, "--raft-node requires --node-id/--raft-listen-port/--cert/"
                        "--key/--ca/--voter/--peer\n");
        return 2;
      }
      node_config.node_id = node_id;
      node_config.listen_host = "127.0.0.1";
      node_config.listen_port = raft_listen_port;
      node_config.sqlite_path = raft_sqlite;
      node_config.cert_file = cert;
      node_config.key_file = key;
      node_config.ca_file = ca;
      node_config.voters = node_voters;
      node_config.voter_count = voter_count;
      node_config.peers = peers;
      node_config.peer_count = peer_count;
      node_config.max_snapshot_bytes = 4u * 1024 * 1024;
      node_config.max_pending_reads = 64u;
      init_result = m3_gateway_init_node_v1(&gateway, root, max_chunk_bytes,
                                            &credential, 1024u, &node_config);
      if (init_result != 0)
        fprintf(stderr, "m3_gateway_init_node_v1 failed\n");
    } else if (raft_sqlite) {
      static const tr_raft_node_id_t voters[] = {1u};
      m3_gateway_raft_config_v1_t raft_config = {0};

      raft_config.sqlite_path = raft_sqlite;
      raft_config.self_id = 1u;
      raft_config.voters = voters;
      raft_config.voter_count = 1u;
      raft_config.max_snapshot_bytes = 4u * 1024 * 1024;
      raft_config.max_pending_reads = 64u;
      init_result = m3_gateway_init_raft_v1(&gateway, root, max_chunk_bytes, &credential,
                                            1024u, &raft_config);
      if (init_result != 0)
        fprintf(stderr, "m3_gateway_init_raft_v1 failed\n");
    } else
#endif
    {
      init_result = m3_gateway_init_v1(&gateway, root, max_chunk_bytes, &credential, 1024u);
      if (init_result != 0)
        fprintf(stderr, "m3_gateway_init_v1 failed\n");
    }
    if (init_result != 0)
      return 1;
  }

  {
    /* Mesh data plane (P4): the gateway dials the store nodes over p2p,
     * signs chunk capabilities with its identity key and reads replicas over
     * the authenticated channel. The p2p loop is pumped on a background
     * thread while the HTTP handlers run. */
    static const m3_chunk_capability_policy_v1_t k_mesh_policy = {
        7200u * 1000u, 64u * 1024u * 1024u, 64u * 1024u * 1024u,
    };
    p2p_node_t *mesh_node = NULL;
    uint8_t mesh_key[32];
    static const uint8_t mesh_network_id[P2P_SECURITY_ID_SIZE] = {
        0x4d, 0x33, 0x2d, 0x63, 0x68, 0x75, 0x6e, 0x6b,
        0x2d, 0x6d, 0x65, 0x73, 0x68, 0x2d, 0x73, 0x65,
        0x63, 0x75, 0x72, 0x65, 0x2d, 0x77, 0x69, 0x72,
        0x65, 0x2d, 0x76, 0x32, 0x00, 0x00, 0x00, 0x01,
    };

    if (mesh_listen_port > 0) {
      if (!mesh_key_hex || mesh_store_count == 0u ||
          parse_hex(mesh_key_hex, mesh_key, sizeof(mesh_key)) != 0) {
        fprintf(stderr,
                "--mesh-listen requires --mesh-key <hex32> and --store-peer "
                "<id>:<signing-pubkey>:<transport-pubkey>@host:port\n");
        m3_gateway_destroy_v1(&gateway);
        return 1;
      }
      mesh_node = p2p_create("127.0.0.1", mesh_listen_port);
      if (!mesh_node ||
          p2p_node_set_private_key(mesh_node, mesh_key) != P2P_OK ||
          p2p_node_configure_pinned_security_v2(
              mesh_node, mesh_network_id, mesh_store_transport_keys[0],
              mesh_store_count) != P2P_OK ||
          p2p_start_nonblocking(mesh_node) != P2P_OK ||
          m3_gateway_attach_datapane_v1(&gateway, target_replicas,
                                        min_durable_replicas,
                                        &k_mesh_policy) != 0 ||
          m3_gateway_attach_mesh_v1(&gateway, mesh_node, mesh_key) != 0) {
        fprintf(stderr, "mesh setup failed\n");
        if (mesh_node)
          p2p_destroy(mesh_node);
        m3_gateway_destroy_v1(&gateway);
        return 1;
      }
      for (size_t i = 0u; i < mesh_store_count; i++) {
        if (m3_gateway_register_mesh_store_v1(
                &gateway, mesh_store_ids[i], mesh_store_pubkeys[i],
                mesh_store_hosts[i], mesh_store_ports[i]) != 0) {
          fprintf(stderr, "register mesh store %zu failed\n", i);
          p2p_destroy(mesh_node);
          m3_gateway_destroy_v1(&gateway);
          return 1;
        }
      }
      InterlockedExchange(&g_mesh_pump.running, 1);
      g_mesh_pump.node = mesh_node;
      g_mesh_pump.thread =
          CreateThread(NULL, 0, gateway_mesh_pump_loop, &g_mesh_pump, 0, NULL);
      printf("gateway mesh p2p on :%d with %zu store peers\n",
             mesh_listen_port, mesh_store_count);
    }
  }

  app = iris_app_create();
  {
    /* Phase 1 buffers request bodies; raise the default body cap so the
     * gateway can accept multi-chunk objects. A streaming route replaces
     * this in a later phase. */
    const iris_security_limits_t *defaults = iris_security_get_limits();
    iris_security_limits_t limits = defaults ? *defaults : (iris_security_limits_t){0};
    limits.max_request_body_size = (size_t)64 * 1024 * 1024;
    iris_app_set_security_limits(app, &limits);
  }
  m3_gateway_register_routes_v1(app);
  printf("M3 gateway listening on :%d (store=%s, access-key=%s, metadata=%s)\n", port, root,
         credential.access_key, raft_node ? "raft-node" : (raft_sqlite ? "raft" : "local"));
#if defined(_WIN32) && defined(TURBO_P2P_M3_RAFT_ENABLED)
  if (raft_node) {
    /* Pump the embedded raft node continuously so elections/heartbeats advance
     * between HTTP requests; handlers sleep-poll instead of touching the node
     * context concurrently. */
    InterlockedExchange(&g_gateway_pump_stop, 0);
    g_gateway_pump_thread =
        CreateThread(NULL, 0, gateway_node_pump, &gateway, 0, NULL);
  }
#endif

  iris_app_listen(app, port);

#if defined(_WIN32) && defined(TURBO_P2P_M3_RAFT_ENABLED)
  if (g_gateway_pump_thread != NULL) {
    InterlockedExchange(&g_gateway_pump_stop, 1);
    WaitForSingleObject(g_gateway_pump_thread, 5000);
    CloseHandle(g_gateway_pump_thread);
    g_gateway_pump_thread = NULL;
  }
#endif
#ifdef _WIN32
  gateway_mesh_pump_stop(&g_mesh_pump);
#endif

  m3_gateway_destroy_v1(&gateway);
  if (g_mesh_pump.node != NULL) {
    p2p_destroy(g_mesh_pump.node);
    g_mesh_pump.node = NULL;
  }
  iris_app_destroy(app);
  return 0;
}
