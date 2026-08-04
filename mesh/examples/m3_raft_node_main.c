/* m3_raft_node_main.c - Phase 2b-ii: M3 raft node executable.
 *
 * Two modes:
 *   --self-test  : local single-voter smoke test (Phase 2b-ii step 1).
 *   default      : real multi-process CoroNet TLS raft node. Listens for
 *                  inbound mTLS sessions and dials larger peer ids
 *                  (deterministic direction); runs until Ctrl+C.
 *
 * Usage:
 *   m3_raft_node_main --node-id <id> --listen-host <host> --listen-port <port>
 *       --sqlite <path> --cert <file> --key <file> --ca <file>
 *       --voter <id> [--voter <id> ...]
 *       --peer <id>@<host>:<port>:<sha256-fingerprint> [--peer ...]
 *   m3_raft_node_main --self-test [--node-id <id> --sqlite <path>]
 */

#include "m3_raft_node.h"
#include "m3_gateway_raft.h"
#include "m3_object_manifest.h"

#include <platform.h>
#include <turbo_error.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#endif

static volatile int g_stop = 0;

#ifdef _WIN32
static BOOL WINAPI console_ctrl_handler(DWORD ctrl_type) {
  (void)ctrl_type;
  g_stop = 1;
  return TRUE;
}
#endif

static void print_usage(const char *program) {
  fprintf(stderr,
          "usage:\n"
          "  %s --node-id <id> --listen-host <host> --listen-port <port>\n"
          "     --sqlite <path> --cert <file> --key <file> --ca <file>\n"
          "     --voter <id>... --peer <id>@<host>:<port>:<sha256:fp>...\n"
          "     [--probe-put]  (leader proposes a fixed probe object once)\n"
          "  %s --self-test [--node-id <id> --sqlite <path>]\n",
          program, program);
}

static int make_manifest(uint8_t **out_bytes, size_t *out_size);

static int parse_peer(const char *spec, m3_raft_node_peer_config_t *peer) {
  const char *at;
  char host[TR_RAFT_CORONET_ENDPOINT_HOST_CAPACITY];
  char port_s[16];
  char fingerprint[96];
  long node_id;
  int port;
  int n;

  if (!spec || !peer) {
    return -1;
  }
  memset(peer, 0, sizeof(*peer));
  at = strchr(spec, '@');
  if (!at) {
    return -1;
  }
  {
    char id_s[32];
    size_t id_len = (size_t)(at - spec);
    if (id_len == 0u || id_len >= sizeof(id_s)) {
      return -1;
    }
    memcpy(id_s, spec, id_len);
    id_s[id_len] = '\0';
    node_id = strtol(id_s, NULL, 10);
  }
  n = sscanf(at + 1, "%255[^:]:%15[0-9]:%95s", host, port_s, fingerprint);
  if (n != 3) {
    return -1;
  }
  port = atoi(port_s);
  if (node_id <= 0 || port <= 0 || port > 65535 ||
      fingerprint[0] == '\0' ||
      strncmp(fingerprint, "sha256:", 7u) != 0) {
    return -1;
  }
  peer->node_id = (tr_raft_node_id_t)node_id;
  snprintf(peer->connect_host, sizeof(peer->connect_host), "%s", host);
  snprintf(peer->request_host, sizeof(peer->request_host), "localhost");
  peer->port = port;
  snprintf(peer->certificate_sha256, sizeof(peer->certificate_sha256), "%s",
           fingerprint);
  return 0;
}

static int run_node_mode(int argc, char **argv) {
  m3_raft_node_config_t config;
  m3_raft_node_peer_config_t peers[M3_RAFT_NODE_MAX_PEERS];
  tr_raft_node_id_t voters[TR_RAFT_MAX_VOTERS];
  m3_raft_node_t *node = NULL;
  const char *listen_host = "127.0.0.1";
  const char *sqlite = NULL;
  const char *cert = NULL;
  const char *key = NULL;
  const char *ca = NULL;
  int listen_port = 0;
  tr_raft_node_id_t node_id = 0u;
  size_t voter_count = 0u;
  size_t peer_count = 0u;
  uint64_t last_status_ms = 0u;
  int probe_put = 0;
  int probe_proposed = 0;
  int probe_done = 0;
  uint64_t probe_before = 0u;

  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--node-id") == 0 && i + 1 < argc) {
      node_id = (tr_raft_node_id_t)strtoul(argv[++i], NULL, 10);
    } else if (strcmp(argv[i], "--listen-host") == 0 && i + 1 < argc) {
      listen_host = argv[++i];
    } else if (strcmp(argv[i], "--listen-port") == 0 && i + 1 < argc) {
      listen_port = atoi(argv[++i]);
    } else if (strcmp(argv[i], "--sqlite") == 0 && i + 1 < argc) {
      sqlite = argv[++i];
    } else if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
      cert = argv[++i];
    } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
      key = argv[++i];
    } else if (strcmp(argv[i], "--ca") == 0 && i + 1 < argc) {
      ca = argv[++i];
    } else if (strcmp(argv[i], "--voter") == 0 && i + 1 < argc) {
      if (voter_count < TR_RAFT_MAX_VOTERS) {
        voters[voter_count++] = (tr_raft_node_id_t)strtoul(argv[++i], NULL, 10);
      }
    } else if (strcmp(argv[i], "--peer") == 0 && i + 1 < argc) {
      if (peer_count < M3_RAFT_NODE_MAX_PEERS &&
          parse_peer(argv[++i], &peers[peer_count]) == 0) {
        peer_count++;
      }
    } else if (strcmp(argv[i], "--probe-put") == 0) {
      probe_put = 1;
    } else {
      fprintf(stderr, "unknown argument: %s\n", argv[i]);
      print_usage(argv[0]);
      return 2;
    }
  }

  if (node_id == 0u || listen_port <= 0 || listen_port > 65535 || !sqlite ||
      !cert || !key || !ca || voter_count == 0u) {
    fprintf(stderr, "missing required arguments\n");
    print_usage(argv[0]);
    return 2;
  }

  memset(&config, 0, sizeof(config));
  config.node_id = node_id;
  config.listen_host = listen_host;
  config.listen_port = listen_port;
  config.sqlite_path = sqlite;
  config.cert_file = cert;
  config.key_file = key;
  config.ca_file = ca;
  config.voters = voters;
  config.voter_count = voter_count;
  config.peers = peers;
  config.peer_count = peer_count;
  config.max_snapshot_bytes = 4u * 1024 * 1024;
  config.max_pending_reads = 64u;

  if (m3_raft_node_create(&config, &node) != TURBO_OK) {
    fprintf(stderr, "m3 raft node: create failed\n");
    return 1;
  }
  printf("m3 raft node %llu listening on %s:%d\n",
         (unsigned long long)node_id, listen_host, listen_port);
#ifdef _WIN32
  SetConsoleCtrlHandler(console_ctrl_handler, TRUE);
#endif

  while (!g_stop) {
    int leader = 0;
    if (m3_raft_node_poll(node) != TURBO_OK) {
      fprintf(stderr, "m3 raft node: poll failed\n");
      break;
    }
    if (probe_put && !probe_done) {
      (void)m3_raft_node_is_leader(node, &leader);
      if (leader && !probe_proposed) {
        uint8_t tenant[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE];
        uint8_t *manifest = NULL;
        size_t manifest_size = 0u;
        memset(tenant, 0x77, sizeof(tenant));
        if (make_manifest(&manifest, &manifest_size) == 0) {
          probe_before = m3_raft_node_applied_index(node);
          if (m3_raft_node_propose_put(node, tenant, "probe", "object", manifest,
                                       manifest_size) == TURBO_OK) {
            probe_proposed = 1;
          }
          m3_object_manifest_bytes_free_v1(manifest);
        }
      }
      if (probe_proposed && m3_raft_node_applied_index(node) > probe_before) {
        printf("PROBE-COMMITTED node=%llu index=%llu\n",
               (unsigned long long)node_id,
               (unsigned long long)m3_raft_node_applied_index(node));
        fflush(stdout);
        probe_done = 1;
      }
    }
    if (turbo_monotonic_ms() - last_status_ms >= 2000u) {
      last_status_ms = turbo_monotonic_ms();
      (void)m3_raft_node_is_leader(node, &leader);
      printf("node %llu leader=%d applied=%llu\n", (unsigned long long)node_id,
             leader, (unsigned long long)m3_raft_node_applied_index(node));
      fflush(stdout);
    }
  }

  m3_raft_node_destroy(node);
  printf("m3 raft node %llu stopped\n", (unsigned long long)node_id);
  return 0;
}

/* ── Self test (Phase 2b-ii step 1): single-voter put + read-back ── */

static int make_manifest(uint8_t **out_bytes, size_t *out_size) {
  m3_object_manifest_v1_t manifest;

  memset(&manifest, 0, sizeof(manifest));
  manifest.version = M3_OBJECT_MANIFEST_VERSION;
  manifest.object_cid.hash_algorithm = M3_CHUNK_STORE_HASH_ALGORITHM_SHA256;
  manifest.object_cid.size = 0u;
  memset(manifest.object_cid.digest, 1u, sizeof(manifest.object_cid.digest));
  manifest.chunks = NULL;
  manifest.chunk_count = 0u;
  return m3_object_manifest_encode_v1(&manifest, UINT64_C(1) << 30, 4096u, out_bytes, out_size) ==
                 M3_OBJECT_MANIFEST_OK
             ? 0
             : -1;
}

typedef struct {
  int completed;
  int found;
} self_test_capture_t;

static void self_test_lookup_cb(m3_namespace_lookup_result_t result,
                                const m3_namespace_lookup_response_v1_t *response,
                                void *user_data) {
  self_test_capture_t *capture = (self_test_capture_t *)user_data;

  capture->completed = 1;
  capture->found = result == M3_NAMESPACE_LOOKUP_OK && response != NULL;
}

static int run_self_test(const char *sqlite_path, tr_raft_node_id_t node_id) {
  m3_namespace_local_store_v1_t store;
  m3_gateway_raft_config_v1_t config;
  m3_gateway_raft_v1_t *raft = NULL;
  m3_namespace_lookup_adapter_v1_t lookup;
  m3_namespace_lookup_request_v1_t request;
  uint8_t tenant[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE];
  uint8_t *manifest = NULL;
  size_t manifest_size = 0u;
  int result = 0;

  memset(&store, 0, sizeof(store));
  if (m3_namespace_local_store_init_v1(&store, 64u, 128u, 1024u, 65536u, UINT64_C(1) << 30,
                                       4096u) != M3_NAMESPACE_LOCAL_OK) {
    fprintf(stderr, "namespace init failed\n");
    return 1;
  }
  memset(&config, 0, sizeof(config));
  config.sqlite_path = sqlite_path;
  config.self_id = node_id;
  {
    static const tr_raft_node_id_t voters[] = {1u};
    config.voters = voters;
    config.voter_count = 1u;
  }
  config.max_snapshot_bytes = 4u * 1024 * 1024;
  config.max_pending_reads = 64u;
  if (m3_gateway_raft_open_v1(&config, &store, &raft) != TURBO_OK) {
    fprintf(stderr, "raft open failed\n");
    m3_namespace_local_store_destroy_v1(&store);
    return 1;
  }
  memset(tenant, 0x77, sizeof(tenant));
  if (make_manifest(&manifest, &manifest_size) != 0 ||
      m3_gateway_raft_put_v1(raft, tenant, "self-test", "object", manifest, manifest_size) !=
          TURBO_OK) {
    fprintf(stderr, "self-test put failed\n");
    result = 1;
    goto cleanup;
  }
  memset(&request, 0, sizeof(request));
  memcpy(request.tenant_id, tenant, sizeof(request.tenant_id));
  request.bucket = (const uint8_t *)"self-test";
  request.bucket_size = 9u;
  request.object_key = (const uint8_t *)"object";
  request.object_key_size = 6u;
  request.require_linearizable = 1u;
  lookup = m3_namespace_local_store_adapter_v1(&store);
  {
    struct {
      int completed;
      int found;
    } capture = {0, 0};
    if (lookup.start(lookup.context, &request, self_test_lookup_cb, &capture) ==
            M3_NAMESPACE_LOOKUP_OK &&
        capture.completed && capture.found) {
      /* persisted and readable */
    } else {
      fprintf(stderr, "self-test read-back failed\n");
      result = 1;
      goto cleanup;
    }
  }
  printf("self-test OK (node %llu, sqlite %s)\n", (unsigned long long)node_id, sqlite_path);
  result = 0;

cleanup:
  m3_gateway_raft_close_v1(raft);
  m3_namespace_local_store_destroy_v1(&store);
  m3_object_manifest_bytes_free_v1(manifest);
  return result;
}

int main(int argc, char **argv) {
  int self_test = 0;
  tr_raft_node_id_t node_id = 1u;
  const char *sqlite = NULL;

  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--self-test") == 0) {
      self_test = 1;
    } else if (strcmp(argv[i], "--node-id") == 0 && i + 1 < argc) {
      node_id = (tr_raft_node_id_t)strtoul(argv[++i], NULL, 10);
    } else if (strcmp(argv[i], "--sqlite") == 0 && i + 1 < argc) {
      sqlite = argv[++i];
    }
  }
  if (self_test) {
    const char *path = sqlite ? sqlite : ":memory:";
    return run_self_test(path, node_id);
  }
  return run_node_mode(argc, argv);
}
