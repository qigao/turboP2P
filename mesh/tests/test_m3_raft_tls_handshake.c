#include <tinytest.h>

#include <turboraft/raft_coronet_transport.h>

#include <CoroNet/turbo_coro_context.h>
#include <CoroNet/turbo_coro_socket.h>
#include <turbo_error.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Phase 2b-ii step 2: single-process CoroNet TLS peer handshake.
 * mTLS (mutual certificate verification) is required so each side can read
 * the peer certificate fingerprint used by the raft identity registry. */

#ifndef M3_TEST_TLS_DIR
#define M3_TEST_TLS_DIR "mesh/tests/data/m3tls"
#endif

#define M3TLS_DIR M3_TEST_TLS_DIR

typedef struct {
  coro_context_t *ctx;
  int port;
  tr_raft_coronet_identity_registry_t *identity;
  tr_raft_handshake_result_t result;
  coro_socket_t *listener;
  int done;
  int failed;
} handshake_env_t;

static void fill_cluster_id(tr_raft_cluster_id_t *id) { memset(id, 0x4d, sizeof(*id)); }

static void fill_raft_handshake_config(tr_raft_handshake_config_t *config,
                                       tr_raft_node_id_t node_id) {
  memset(config, 0, sizeof(*config));
  fill_cluster_id(&config->cluster_id);
  config->local_node_id = node_id;
  memset(&config->process_incarnation, 0x33, sizeof(config->process_incarnation));
  config->config_epoch = 1u;
  config->feature_bits = TR_RAFT_HANDSHAKE_FEATURE_CURRENT;
  config->wire_major_min = TR_RAFT_HANDSHAKE_WIRE_MAJOR;
  config->wire_major_max = TR_RAFT_HANDSHAKE_WIRE_MAJOR;
  config->wire_minor_min = TR_RAFT_HANDSHAKE_WIRE_MINOR;
  config->wire_minor_max = TR_RAFT_HANDSHAKE_WIRE_MINOR;
  config->max_frame_size = TR_RAFT_HANDSHAKE_MIN_FRAME_SIZE;
  config->max_snapshot_chunk_size = TR_RAFT_HANDSHAKE_MIN_SNAPSHOT_CHUNK_SIZE;
}

static int resolve_identity(void *context, const char *fingerprint,
                            tr_raft_node_id_t *out_node_id) {
  return tr_raft_coronet_identity_registry_resolve((tr_raft_coronet_identity_registry_t *)context,
                                                   fingerprint, out_node_id);
}

static void run_server_handshake(handshake_env_t *env, coro_socket_t *accepted) {
  tr_raft_coronet_handshake_config_t handshake;
  tr_raft_handshake_config_t raft_config;
  tr_raft_coronet_receive_remainder_t remainder;
  char peer_fingerprint[CORO_TLS_PEER_CERT_SHA256_CAPACITY];
  tr_raft_node_id_t peer_node_id = 0u;

  memset(&remainder, 0, sizeof(remainder));
  if (coro_socket_tls_get_verified_peer_certificate_sha256(accepted, peer_fingerprint) != 0 ||
      resolve_identity(env->identity, peer_fingerprint, &peer_node_id) != TURBO_OK) {
    env->failed = 1;
    env->done = 1;
    coro_socket_destroy(accepted);
    return;
  }
  memset(&handshake, 0, sizeof(handshake));
  fill_raft_handshake_config(&raft_config, 1u);
  handshake.handshake = &raft_config;
  handshake.timeout_ms = 5000u;
  handshake.resolve_peer_identity = resolve_identity;
  handshake.identity_context = env->identity;
  if (tr_raft_coronet_handshake_exchange(accepted, &handshake, &env->result, &remainder) !=
          TURBO_OK ||
      !env->result.complete) {
    env->failed = 1;
  }
  tr_raft_coronet_receive_remainder_release(&remainder);
  coro_socket_destroy(accepted);
  env->done = 1;
}

static void server_handler(coro_socket_t *client, void *arg) {
  run_server_handshake((handshake_env_t *)arg, client);
}

static void server_coro(coro_t *co, void *arg) {
  handshake_env_t *env = (handshake_env_t *)arg;
  coro_socket_t *listener = NULL;
  turbo_tls_server_config_t tls;
  char cert_path[256];
  char key_path[256];
  char ca_path[256];

  listener = coro_socket_create(env->ctx, CORO_SOCKET_TLS);
  if (!listener) {
    env->failed = 1;
    env->done = 1;
    return;
  }
  memset(&tls, 0, sizeof(tls));
  tls.size = sizeof(tls);
  snprintf(cert_path, sizeof(cert_path), "%s/node1.crt", M3TLS_DIR);
  tls.cert_file = cert_path;
  snprintf(key_path, sizeof(key_path), "%s/node1.key", M3TLS_DIR);
  tls.key_file = key_path;
  snprintf(ca_path, sizeof(ca_path), "%s/m3ca.crt", M3TLS_DIR);
  tls.ca_file = ca_path;
  tls.client_auth = TURBO_TLS_CLIENT_AUTH_REQUIRED;
  if (coro_socket_set_tls_server_config(listener, &tls) != 0 ||
      coro_socket_listen_on(listener, "127.0.0.1", env->port, server_handler, env) != 0) {
    env->failed = 1;
    env->done = 1;
    coro_socket_destroy(listener);
    return;
  }
  env->listener = listener;
  /* keep the listener alive; accept happens via the handler */
}

static void client_coro(coro_t *co, void *arg) {
  handshake_env_t *env = (handshake_env_t *)arg;
  coro_socket_t *socket = NULL;
  turbo_tls_client_config_t tls;
  tr_raft_coronet_handshake_config_t handshake;
  tr_raft_handshake_config_t raft_config;
  tr_raft_coronet_receive_remainder_t remainder;
  char peer_fingerprint[CORO_TLS_PEER_CERT_SHA256_CAPACITY];
  tr_raft_node_id_t peer_node_id = 0u;
  char cert_path[256];
  char key_path[256];
  char ca_path[256];

  memset(&remainder, 0, sizeof(remainder));
  socket = coro_socket_create(env->ctx, CORO_SOCKET_TLS);
  if (!socket) {
    env->failed = 1;
    env->done = 1;
    return;
  }
  memset(&tls, 0, sizeof(tls));
  snprintf(cert_path, sizeof(cert_path), "%s/node2.crt", M3TLS_DIR);
  tls.cert_file = cert_path;
  snprintf(key_path, sizeof(key_path), "%s/node2.key", M3TLS_DIR);
  tls.key_file = key_path;
  snprintf(ca_path, sizeof(ca_path), "%s/m3ca.crt", M3TLS_DIR);
  tls.ca_file = ca_path;
  tls.verify_peer = 1;
  if (coro_socket_set_tls_client_config(socket, &tls) != 0 ||
      coro_socket_connect(socket, "127.0.0.1", env->port) != 0) {
    env->failed = 1;
    env->done = 1;
    coro_socket_destroy(socket);
    return;
  }
  if (coro_socket_tls_get_verified_peer_certificate_sha256(socket, peer_fingerprint) != 0 ||
      resolve_identity(env->identity, peer_fingerprint, &peer_node_id) != TURBO_OK) {
    env->failed = 1;
    env->done = 1;
    coro_socket_destroy(socket);
    return;
  }
  memset(&handshake, 0, sizeof(handshake));
  fill_raft_handshake_config(&raft_config, 2u);
  handshake.handshake = &raft_config;
  handshake.timeout_ms = 5000u;
  handshake.resolve_peer_identity = resolve_identity;
  handshake.identity_context = env->identity;
  if (tr_raft_coronet_handshake_exchange(socket, &handshake, &env->result, &remainder) !=
          TURBO_OK ||
      !env->result.complete) {
    env->failed = 1;
  }
  tr_raft_coronet_receive_remainder_release(&remainder);
  coro_socket_destroy(socket);
  env->done = 1;
}

static void test_tls_handshake_completes(void) {
  char ca_path[256];
  char cert_path[256];
  char key_path[256];
  tr_raft_coronet_identity_entry_t entries[2];
  tr_raft_coronet_identity_registry_t *identity = NULL;
  handshake_env_t server_env;
  handshake_env_t client_env;
  coro_context_t *ctx = NULL;

  snprintf(ca_path, sizeof(ca_path), "%s/m3ca.crt", M3TLS_DIR);
  snprintf(cert_path, sizeof(cert_path), "%s/node1.crt", M3TLS_DIR);
  snprintf(key_path, sizeof(key_path), "%s/node1.key", M3TLS_DIR);
  (void)_putenv_s("TURBONET_TLS_CA_FILE", ca_path);
  (void)_putenv_s("TURBONET_TLS_CERT_FILE", cert_path);
  (void)_putenv_s("TURBONET_TLS_KEY_FILE", key_path);

  memset(entries, 0, sizeof(entries));
  strcpy(entries[0].certificate_sha256,
         "sha256:a9a12784e612bd3ced3dbc4ec6b9f1f58b84a4592650fda8be88f5d777f49800");
  entries[0].node_id = 1u;
  strcpy(entries[1].certificate_sha256,
         "sha256:66a4ee96d3c72dacc600ecda40ff0d3a308e2bf06a1ff2d45e74d36d88e7f465");
  entries[1].node_id = 2u;
  check_int_eq(TURBO_OK, tr_raft_coronet_identity_registry_create(entries, 2u, &identity));

  memset(&server_env, 0, sizeof(server_env));
  memset(&client_env, 0, sizeof(client_env));
  ctx = coro_context_create(NULL);
  check_not_null(ctx);
  server_env.ctx = ctx;
  client_env.ctx = ctx;
  server_env.port = 18443;
  client_env.port = 18443;
  server_env.identity = identity;
  client_env.identity = identity;

  {
    int ss = coro_context_spawn(ctx, server_coro, &server_env);
    int cs = coro_context_spawn(ctx, client_coro, &client_env);
    check_int_eq(0, ss);
    check_int_eq(0, cs);
  }
  for (int i = 0; i < 200000 && (!server_env.done || !client_env.done); i++) {
    coro_context_run(ctx, TURBO_RUN_NOWAIT);
  }
  check_int_eq(0, server_env.failed);
  check_int_eq(0, client_env.failed);
  check_int_eq(1, server_env.done);
  check_int_eq(1, client_env.done);
  check_int_eq(1, server_env.result.complete);
  check_int_eq(1, client_env.result.complete);
  check_int_eq(2u, server_env.result.peer_node_id);
  check_int_eq(1u, client_env.result.peer_node_id);

  /* Stop the listener and drain the accept loop so context teardown is clean
   * (otherwise destroy waits for the full shutdown drain window). */
  if (server_env.listener) {
    coro_socket_destroy(server_env.listener);
  }
  for (int i = 0; i < 100 && coro_context_alive(ctx); i++) {
    coro_context_run(ctx, TURBO_RUN_NOWAIT);
  }
  coro_context_destroy(ctx);
  tr_raft_coronet_identity_registry_destroy(identity);
}

spec("m3 raft tls handshake") {
  describe("CoroNet TLS peer handshake") {
    it("completes HELLO/ACK with fingerprint-based identity (mTLS)") {
      test_tls_handshake_completes();
    }
  }
}
