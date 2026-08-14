#include "mesh_control_controller_runtime.h"
#include "tinytest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_NOW_MS UINT64_C(1786690000000)

static const uint8_t TEST_PRIVATE_KEY[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60};

typedef struct {
  char ca[TURBO_FS_MAX_PATH];
  char server_cert[TURBO_FS_MAX_PATH];
  char server_key[TURBO_FS_MAX_PATH];
  char client_cert[TURBO_FS_MAX_PATH];
  char client_key[TURBO_FS_MAX_PATH];
  char client_next_cert[TURBO_FS_MAX_PATH];
  char client_next_key[TURBO_FS_MAX_PATH];
} test_paths_v1_t;

static uint64_t test_now(void *context) {
  (void)context;
  return TEST_NOW_MS;
}

static void cert_path(char output[TURBO_FS_MAX_PATH], const char *name) {
  (void)snprintf(output, TURBO_FS_MAX_PATH, "%s/%s",
                 MESH_TEST_CERTIFICATE_DIR, name);
}

static void make_paths(test_paths_v1_t *paths) {
  cert_path(paths->ca, "ca.pem");
  cert_path(paths->server_cert, "server-current-cert.pem");
  cert_path(paths->server_key, "server-current-key.pem");
  cert_path(paths->client_cert, "client-current-cert.pem");
  cert_path(paths->client_key, "client-current-key.pem");
  cert_path(paths->client_next_cert, "client-next-cert.pem");
  cert_path(paths->client_next_key, "client-next-key.pem");
}

static void remove_outbox(const char *path) {
  char lock_path[TURBO_FS_MAX_PATH + 6u];
  char temp_path[TURBO_FS_MAX_PATH + 5u];
  (void)snprintf(lock_path, sizeof(lock_path), "%s.lock", path);
  (void)snprintf(temp_path, sizeof(temp_path), "%s.tmp", path);
  (void)remove(path);
  (void)remove(lock_path);
  (void)remove(temp_path);
}

static void configure_runtime(
    mesh_control_controller_runtime_config_v1_t *config,
    mesh_control_controller_runtime_identity_config_v1_t *identity,
    const test_paths_v1_t *paths, const char *outbox_path) {
  size_t index;
  memset(config, 0, sizeof(*config));
  memset(identity, 0, sizeof(*identity));
  memset(identity->node_id, 0x41, sizeof(identity->node_id));
  check_int_eq(mesh_mgmt_ed25519_public_from_private(
                   TEST_PRIVATE_KEY, identity->management_public_key),
               MESH_MGMT_CRYPTO_OK);
  identity->certificate.ca_file = paths->ca;
  identity->certificate.role = MESH_CERTIFICATE_ROLE_CLIENT_V1;
  identity->certificate.current.certificate_file = paths->client_cert;
  identity->certificate.next.certificate_file = paths->client_next_cert;
  identity->certificate.certificate_only = 1u;
  identity->certificate.policy_generation = 1u;
  identity->certificate.now_ms = TEST_NOW_MS;
  identity->identity_policy_generation = 1u;

  config->host = "127.0.0.1";
  config->port = 0u;
  config->server_certificate.ca_file = paths->ca;
  config->server_certificate.role = MESH_CERTIFICATE_ROLE_SERVER_V1;
  config->server_certificate.current.certificate_file = paths->server_cert;
  config->server_certificate.current.private_key_file = paths->server_key;
  config->server_certificate.policy_generation = 1u;
  config->server_certificate.now_ms = TEST_NOW_MS;
  config->agent_client_ca_file = paths->ca;
  config->identities = identity;
  config->identity_count = 1u;
  config->identity_capacity = 2u;
  config->now_ms = test_now;
  config->session.outbox.path = outbox_path;
  config->session.outbox.entry_capacity = 8u;
  config->session.outbox.session_capacity = 4u;
  config->session.outbox.byte_capacity = 256u * 1024u;
  config->session.outbox.max_payload_size =
      MESH_CONTROL_AGENT_SYNC_MAX_PAYLOAD_V1;
  config->session.outbox.max_claim_lease_ms = 2000u;
  config->session.outbox.ack_retention_ms = 1000u;
  for (index = 0u;
       index < sizeof(config->session.outbox.authentication_key); ++index)
    config->session.outbox.authentication_key[index] =
        (uint8_t)(0xa0u + index);
  config->session.session_capacity = 4u;
  config->session.claim_lease_ms = 1000u;
  config->session.maximum_clock_skew_ms = 100u;
  config->session.maximum_hello_lifetime_ms = 2000u;
  config->persistence_timeout_ms = 2000u;
  config->shutdown_drain_timeout_ms = 2000u;
}

static void test_runtime_owns_listener_outbox_and_identity_rotation(void) {
  mesh_control_controller_runtime_v1_t runtime = {0};
  mesh_control_controller_runtime_config_v1_t config;
  mesh_control_controller_runtime_identity_config_v1_t identity;
  mesh_control_controller_runtime_identity_config_v1_t rotation;
  mesh_control_agent_sync_hello_policy_v1_t policy;
  test_paths_v1_t paths;
  uint8_t old_digest[MESH_CONTROL_DIGEST_SIZE];
  size_t recovered_claims = 99u;
  char *outbox_path = tt_make_temp_file("mesh-controller-runtime", ".bin");
  check_not_null(outbox_path);
  if (!outbox_path) return;
  remove_outbox(outbox_path);
  make_paths(&paths);
  configure_runtime(&config, &identity, &paths, outbox_path);
  check_int_eq(mesh_control_controller_runtime_init_v1(
                   &runtime, &config, &recovered_claims),
               MESH_CONTROL_OK);
  check_uint_eq(recovered_claims, 0u);
  check_not_null(runtime.listener);
  check_true(runtime.session.initialized);
  memcpy(old_digest, runtime.client_certificates[0].current.certificate_sha256,
         sizeof(old_digest));
  check_int_eq(mesh_control_controller_identity_authorize_v1(
                   &runtime.identities, identity.node_id, old_digest, &policy),
               MESH_CONTROL_OK);

  rotation = identity;
  rotation.certificate.current.certificate_file = paths.client_next_cert;
  rotation.certificate.next.certificate_file = NULL;
  rotation.certificate.policy_generation = 2u;
  rotation.identity_policy_generation = 2u;
  check_int_eq(mesh_control_controller_runtime_rotate_identity_v1(
                   &runtime, &rotation),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_controller_identity_authorize_v1(
                   &runtime.identities, identity.node_id, old_digest, &policy),
               MESH_CONTROL_UNAUTHORIZED);
  check_int_eq(mesh_control_controller_identity_authorize_v1(
                   &runtime.identities, identity.node_id,
                   runtime.client_certificates[0].current.certificate_sha256,
                   &policy),
               MESH_CONTROL_OK);
  check_uint_eq(policy.identity_policy_generation, 2u);

  check_int_eq(mesh_control_controller_runtime_stop_v1(&runtime),
               MESH_CONTROL_OK);
  mesh_control_controller_runtime_destroy_v1(&runtime);
  remove_outbox(outbox_path);
  free(outbox_path);
}

spec("Controller production composition") {
  describe("listener, durable outbox and identity policy") {
    it("owns shutdown and atomically fences a rotated agent identity") {
      test_runtime_owns_listener_outbox_and_identity_rotation();
    }
  }
}
