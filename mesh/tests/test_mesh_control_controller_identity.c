#include "mesh_control_controller_identity.h"
#include "tinytest.h"

#include <stdio.h>
#include <string.h>

#define TEST_NOW_MS UINT64_C(1786690000000)

static void path(char output[TURBO_FS_MAX_PATH], const char *name) {
  (void)snprintf(output, TURBO_FS_MAX_PATH, "%s/%s",
                 MESH_TEST_CERTIFICATE_DIR, name);
}

static uint64_t now_ms(void *context) {
  (void)context;
  return TEST_NOW_MS;
}

static void lifecycle_config(
    mesh_certificate_lifecycle_config_v1_t *config, uint64_t generation,
    int promote_next, const uint64_t *revoked) {
  static char ca[TURBO_FS_MAX_PATH];
  static char current_cert[TURBO_FS_MAX_PATH];
  static char current_key[TURBO_FS_MAX_PATH];
  static char next_cert[TURBO_FS_MAX_PATH];
  static char next_key[TURBO_FS_MAX_PATH];
  path(ca, "ca.pem");
  path(current_cert, "client-current-cert.pem");
  path(current_key, "client-current-key.pem");
  path(next_cert, "client-next-cert.pem");
  path(next_key, "client-next-key.pem");
  memset(config, 0, sizeof(*config));
  config->ca_file = ca;
  config->role = MESH_CERTIFICATE_ROLE_CLIENT_V1;
  config->current.certificate_file =
      promote_next ? next_cert : current_cert;
  config->current.private_key_file = promote_next ? next_key : current_key;
  if (!promote_next) {
    config->next.certificate_file = next_cert;
    config->next.private_key_file = next_key;
  }
  config->revoked_serials = revoked;
  config->revoked_serial_count = revoked ? 1u : 0u;
  config->policy_generation = generation;
  config->now_ms = TEST_NOW_MS;
}

static void test_registry_binds_leaf_key_and_generation(void) {
  mesh_certificate_lifecycle_v1_t lifecycle = {0};
  mesh_certificate_lifecycle_config_v1_t config;
  mesh_control_controller_identity_registry_v1_t registry = {0};
  mesh_control_controller_identity_entry_v1_t entry;
  mesh_control_agent_sync_hello_policy_v1_t policy;
  uint8_t old_digest[MESH_CONTROL_DIGEST_SIZE];
  uint64_t revoked = 2001u;
  memset(&entry, 0, sizeof(entry));
  lifecycle_config(&config, 1u, 0, NULL);
  check_int_eq(mesh_certificate_lifecycle_init_v1(&lifecycle, &config),
               MESH_CONTROL_OK);
  memcpy(old_digest, lifecycle.current.certificate_sha256,
         sizeof(old_digest));
  memset(entry.node_id, 0x11, sizeof(entry.node_id));
  memset(entry.management_public_key, 0x22,
         sizeof(entry.management_public_key));
  entry.certificate = &lifecycle;
  entry.identity_policy_generation = 1u;
  check_int_eq(mesh_control_controller_identity_registry_init_v1(
                   &registry, 1u, now_ms, NULL),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_controller_identity_registry_put_v1(&registry,
                                                                 &entry),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_controller_identity_authorize_v1(
                   &registry, entry.node_id, old_digest, &policy),
               MESH_CONTROL_OK);
  check_uint_eq(policy.minimum_certificate_serial, 2001u);
  check_uint_eq(policy.maximum_certificate_serial, 2002u);
  check_uint_eq(policy.identity_policy_generation, 1u);

  lifecycle_config(&config, 2u, 1, &revoked);
  check_int_eq(mesh_certificate_lifecycle_reload_v1(&lifecycle, &config),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_controller_identity_authorize_v1(
                   &registry, entry.node_id,
                   lifecycle.current.certificate_sha256, &policy),
               MESH_CONTROL_UNAUTHORIZED);
  entry.identity_policy_generation = 2u;
  check_int_eq(mesh_control_controller_identity_registry_put_v1(&registry,
                                                                 &entry),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_controller_identity_authorize_v1(
                   &registry, entry.node_id,
                   lifecycle.current.certificate_sha256, &policy),
               MESH_CONTROL_OK);
  check_uint_eq(policy.minimum_certificate_serial, 2002u);
  check_uint_eq(policy.identity_policy_generation, 2u);
  check_int_eq(mesh_control_controller_identity_authorize_v1(
                   &registry, entry.node_id, old_digest, &policy),
               MESH_CONTROL_UNAUTHORIZED);
  check_int_eq(mesh_control_controller_identity_registry_put_v1(&registry,
                                                                 &entry),
               MESH_CONTROL_STALE_EPOCH);
  mesh_control_controller_identity_registry_destroy_v1(&registry);
  mesh_certificate_lifecycle_destroy_v1(&lifecycle);
}

spec("Controller production identity registry") {
  describe("certificate and HELLO identity binding") {
    it("authorizes exact overlap leaves and fences policy generations") {
      test_registry_binds_leaf_key_and_generation();
    }
  }
}
