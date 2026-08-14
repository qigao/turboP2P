#include "mesh_control_agent_runtime.h"
#include "tinytest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t TEST_PRIVATE_KEY[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60};

#define TEST_NOW_MS UINT64_C(1786690000000)
#define TEST_CLIENT_CERT_SHA256                                             \
  "sha256:36f828b7dfeeeb70c1088ab417e6a473dbe7f8c479513894ef7a620f7c164eac"

static void cert_path(char output[TURBO_FS_MAX_PATH], const char *name) {
  (void)snprintf(output, TURBO_FS_MAX_PATH, "%s/%s",
                 MESH_TEST_CERTIFICATE_DIR, name);
}

static uint64_t test_now(void *context) {
  (void)context;
  return TEST_NOW_MS;
}

static int test_random(void *context, uint8_t *output, size_t output_size) {
  size_t index;
  (void)context;
  for (index = 0u; index < output_size; ++index)
    output[index] = (uint8_t)(0x80u + index);
  return 0;
}

static void remove_wal(const char *path) {
  char lock_path[TURBO_FS_MAX_PATH + 6u];
  char temp_path[TURBO_FS_MAX_PATH + 5u];
  (void)snprintf(lock_path, sizeof(lock_path), "%s.lock", path);
  (void)snprintf(temp_path, sizeof(temp_path), "%s.tmp", path);
  (void)remove(path);
  (void)remove(lock_path);
  (void)remove(temp_path);
}

static void configure_lifecycle(
    mesh_certificate_lifecycle_config_v1_t *config, int server,
    int promote_next, uint64_t generation) {
  static char ca[TURBO_FS_MAX_PATH];
  static char server_current_cert[TURBO_FS_MAX_PATH];
  static char server_current_key[TURBO_FS_MAX_PATH];
  static char server_next_cert[TURBO_FS_MAX_PATH];
  static char server_next_key[TURBO_FS_MAX_PATH];
  static char client_current_cert[TURBO_FS_MAX_PATH];
  static char client_current_key[TURBO_FS_MAX_PATH];
  static char client_next_cert[TURBO_FS_MAX_PATH];
  static char client_next_key[TURBO_FS_MAX_PATH];
  cert_path(ca, "ca.pem");
  cert_path(server_current_cert, "server-current-cert.pem");
  cert_path(server_current_key, "server-current-key.pem");
  cert_path(server_next_cert, "server-next-cert.pem");
  cert_path(server_next_key, "server-next-key.pem");
  cert_path(client_current_cert, "client-current-cert.pem");
  cert_path(client_current_key, "client-current-key.pem");
  cert_path(client_next_cert, "client-next-cert.pem");
  cert_path(client_next_key, "client-next-key.pem");
  memset(config, 0, sizeof(*config));
  config->ca_file = ca;
  config->role = server ? MESH_CERTIFICATE_ROLE_SERVER_V1
                        : MESH_CERTIFICATE_ROLE_CLIENT_V1;
  if (server) {
    config->current.certificate_file = server_current_cert;
    config->current.private_key_file = server_current_key;
    config->next.certificate_file = server_next_cert;
    config->next.private_key_file = server_next_key;
  } else if (promote_next) {
    config->current.certificate_file = client_next_cert;
    config->current.private_key_file = client_next_key;
  } else {
    config->current.certificate_file = client_current_cert;
    config->current.private_key_file = client_current_key;
    config->next.certificate_file = client_next_cert;
    config->next.private_key_file = client_next_key;
  }
  config->policy_generation = generation;
  config->now_ms = TEST_NOW_MS;
}

static void configure_runtime(mesh_control_agent_runtime_config_v1_t *config,
                              const char *wal_path) {
  mesh_control_agent_config_v1_t *agent;
  uint8_t public_key[32];
  static char ca[TURBO_FS_MAX_PATH];
  memset(config, 0, sizeof(*config));
  cert_path(ca, "ca.pem");
  configure_lifecycle(&config->server_certificate, 1, 0, 1u);
  configure_lifecycle(&config->client_certificate, 0, 0, 1u);
  config->controller_client_ca_file = ca;
  config->controller_tls.ca_file = ca;
  config->controller_tls.verify_peer = 1;
  config->controller_sync_url =
      "https://127.0.0.1:65530/v1/agent/sync";
  config->controller_timeout_ms = 100u;

  agent = &config->local_agent;
  agent->host = "127.0.0.1";
  agent->port = 0u;
  agent->controller_tls_certificate_sha256 = TEST_CLIENT_CERT_SHA256;
  memset(agent->controller_node_id, 0x21, sizeof(agent->controller_node_id));
  agent->controller_certificate_serial = 2001u;
  agent->controller_permissions =
      MESH_CONTROL_PERMISSION_OBSERVE | MESH_CONTROL_PERMISSION_MANAGE;
  mesh_control_node_policy_default_v1(&agent->node_policy);
  agent->owner.state.resource_capacity = 4u;
  agent->owner.state.operation_capacity = 4u;
  agent->owner.state.event_capacity = 8u;
  agent->owner.state.terminal_retention_ms = 1000u;
  agent->owner.state.desired_document_max_bytes = 4096u;
  agent->owner.state.desired_document_retained_bytes = 16u * 1024u;
  agent->owner.replay.capacity = 8u;
  agent->owner.replay.ttl_ms = 1000u;
  memset(agent->owner.mesh_id, 0x31, sizeof(agent->owner.mesh_id));
  memset(agent->owner.node_id, 0x41, sizeof(agent->owner.node_id));
  check_int_eq(mesh_mgmt_ed25519_public_from_private(TEST_PRIVATE_KEY,
                                                      public_key),
               MESH_MGMT_CRYPTO_OK);
  memcpy(agent->owner.replay_binding.principal_key, public_key,
         sizeof(public_key));
  agent->owner.replay_binding.principal_epoch = 1u;
  agent->owner.replay_binding.incarnation = 2u;
  memset(agent->owner.replay_binding.session_id, 0x51,
         sizeof(agent->owner.replay_binding.session_id));
  agent->channel_capacity = 8u;
  agent->channel_retained_bytes = 64u * 1024u;
  agent->channel_max_payload = 4096u;
  agent->max_commands_per_poll = 8u;
  agent->status_page_resource_limit = 8u;
  agent->status_page_operation_limit = 8u;
  agent->status_event_limit = 16u;
  agent->shutdown_drain_timeout_ms = 2000u;
  agent->now_ms = test_now;
  agent->durability_enabled = 1u;
  agent->wal.path = wal_path;
  agent->wal.record_capacity = 8u;
  agent->wal.byte_capacity = 64u * 1024u;
  memcpy(agent->wal.mesh_id, agent->owner.mesh_id,
         sizeof(agent->wal.mesh_id));
  memcpy(agent->wal.node_id, agent->owner.node_id,
         sizeof(agent->wal.node_id));
  memcpy(agent->wal.controller_principal,
         agent->owner.replay_binding.principal_key,
         sizeof(agent->wal.controller_principal));
  memcpy(agent->wal.controller_node_id, agent->controller_node_id,
         sizeof(agent->wal.controller_node_id));
  agent->wal.principal_epoch = agent->owner.replay_binding.principal_epoch;
  agent->wal.incarnation = agent->owner.replay_binding.incarnation;
  agent->wal.certificate_serial = agent->controller_certificate_serial;
  memcpy(agent->wal.session_id, agent->owner.replay_binding.session_id,
         sizeof(agent->wal.session_id));
  memset(agent->wal.authentication_key, 0x61,
         sizeof(agent->wal.authentication_key));

  memcpy(config->identity.node_id, agent->owner.node_id,
         sizeof(config->identity.node_id));
  memcpy(config->identity.management_public_key, public_key,
         sizeof(public_key));
  config->identity.management_private_key = TEST_PRIVATE_KEY;
  config->identity.hello_lifetime_ms = 1000u;
  config->identity.claim_interval_ms = 100u;
  config->identity.now_ms = test_now;
  config->identity.random_bytes = test_random;
}

static void test_composes_durable_agent_and_rotates_client(void) {
  mesh_control_agent_runtime_config_v1_t config;
  mesh_certificate_lifecycle_config_v1_t rotation;
  mesh_control_agent_runtime_v1_t runtime = {0};
  mesh_control_agent_service_stats_v1_t stats;
  char *wal_path = tt_make_temp_file("mesh-agent-runtime", ".wal");
  check_not_null(wal_path);
  if (!wal_path) return;
  remove_wal(wal_path);
  configure_runtime(&config, wal_path);
  check_int_eq(mesh_control_agent_runtime_init_v1(&runtime, &config),
               MESH_CONTROL_OK);
  check_true(runtime.agent.running);
  check_true(runtime.agent.wal_worker_initialized);
  check_uint_eq(runtime.client_certificate.current.serial, 2001u);

  configure_lifecycle(&rotation, 0, 1, 2u);
  check_int_eq(mesh_control_agent_runtime_rotate_client_v1(&runtime,
                                                            &rotation),
               MESH_CONTROL_OK);
  check_uint_eq(runtime.client_certificate.current.serial, 2002u);
  check_int_eq(mesh_control_agent_service_get_stats_v1(&runtime.service,
                                                        &stats),
               MESH_CONTROL_OK);
  check_uint_eq(stats.certificate_rotations, 1u);
  check_int_eq(stats.state, MESH_CONTROL_AGENT_SERVICE_DISCONNECTED);
  check_int_eq(mesh_control_agent_runtime_stop_v1(&runtime),
               MESH_CONTROL_OK);
  mesh_control_agent_runtime_destroy_v1(&runtime);
  remove_wal(wal_path);
  free(wal_path);
}

spec("mesh-agent production composition") {
  describe("durable local domain and outbound identity") {
    it("starts the durable agent and rotates the H2 client leaf") {
      test_composes_durable_agent_and_rotates_client();
    }
  }
}
