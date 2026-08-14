#include "mesh_mgmt_p2p_security.h"

#include <tinytest.h>

#include <string.h>

enum { TEST_NOW_MS = 100000u };

typedef struct {
  mesh_mgmt_p2p_security_provider_v2_t provider;
  p2p_security_config_v2_t p2p_config;
  uint8_t certificate[MESH_MGMT_CERTIFICATE_V1_SIZE];
  uint8_t issuer_public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE];
  uint8_t mesh_id_hash[P2P_SECURITY_ID_SIZE];
  uint8_t transport_key[P2P_KEY_SIZE];
  uint8_t management_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE];
  uint8_t managed_node_id[P2P_SECURITY_ID_SIZE];
  uint64_t now_ms;
} security_fixture_t;

static const uint8_t TEST_ISSUER_PRIVATE_KEY[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};

static uint64_t fixture_now_ms(void *context) {
  return ((security_fixture_t *)context)->now_ms;
}

static int fixture_issue_certificate(security_fixture_t *fixture,
                                     uint64_t roles,
                                     uint64_t serial,
                                     uint64_t principal_epoch) {
  mesh_mgmt_certificate_claims_v1_t claims;
  size_t certificate_len = 0u;

  memset(fixture, 0, sizeof(*fixture));
  fixture->now_ms = TEST_NOW_MS;
  memset(fixture->mesh_id_hash, 0x41, sizeof(fixture->mesh_id_hash));
  memset(fixture->transport_key, 0x52, sizeof(fixture->transport_key));
  memset(fixture->management_key, 0x63, sizeof(fixture->management_key));
  memset(fixture->managed_node_id, 0x74, sizeof(fixture->managed_node_id));
  if (mesh_mgmt_ed25519_public_from_private(
          TEST_ISSUER_PRIVATE_KEY, fixture->issuer_public_key) !=
      MESH_MGMT_CRYPTO_OK)
    return -1;

  memset(&claims, 0, sizeof(claims));
  claims.principal_type = MESH_MGMT_PRINCIPAL_NODE;
  memcpy(claims.management_key, fixture->management_key,
         sizeof(claims.management_key));
  memcpy(claims.transport_peer_id, fixture->transport_key,
         sizeof(claims.transport_peer_id));
  memcpy(claims.managed_node_id, fixture->managed_node_id,
         sizeof(claims.managed_node_id));
  memcpy(claims.mesh_id_hash, fixture->mesh_id_hash,
         sizeof(claims.mesh_id_hash));
  claims.roles = roles;
  claims.not_before_ms = TEST_NOW_MS - 100u;
  claims.expires_at_ms = TEST_NOW_MS + 100u;
  claims.serial = serial;
  claims.principal_epoch = principal_epoch;
  return mesh_mgmt_certificate_issue_v1(
             &claims, TEST_ISSUER_PRIVATE_KEY, fixture->certificate,
             sizeof(fixture->certificate), &certificate_len) ==
                 MESH_MGMT_IDENTITY_OK &&
             certificate_len == sizeof(fixture->certificate)
         ? 0
         : -1;
}

static int fixture_init_provider(security_fixture_t *fixture,
                                 uint64_t minimum_epoch,
                                 uint64_t required_roles,
                                 const uint64_t *revoked_serials,
                                 size_t revoked_serial_count) {
  mesh_mgmt_p2p_security_config_v2_t config;

  memset(&config, 0, sizeof(config));
  config.local_certificate = fixture->certificate;
  config.local_certificate_len = sizeof(fixture->certificate);
  config.trusted_issuer_key = fixture->issuer_public_key;
  config.mesh_id_hash = fixture->mesh_id_hash;
  config.minimum_principal_epoch = minimum_epoch;
  config.required_remote_roles = required_roles;
  config.revoked_serials = revoked_serials;
  config.revoked_serial_count = revoked_serial_count;
  config.now_ms = fixture_now_ms;
  config.now_context = fixture;
  return mesh_mgmt_p2p_security_provider_init_v2(
      &fixture->provider, &config, &fixture->p2p_config);
}

static int fixture_build_local(
    security_fixture_t *fixture,
    p2p_authenticated_identity_v2_t *out_identity) {
  uint8_t credential[P2P_SECURITY_CREDENTIAL_MAX];
  size_t credential_len = 0u;

  memset(credential, 0, sizeof(credential));
  return fixture->p2p_config.identity_provider.build_local_credential(
      fixture->p2p_config.identity_provider.context,
      fixture->transport_key, credential, sizeof(credential),
      &credential_len, out_identity);
}

static int fixture_verify_remote(
    security_fixture_t *fixture, const uint8_t transport_key[P2P_KEY_SIZE],
    const uint8_t *credential, size_t credential_len,
    p2p_authenticated_identity_v2_t *out_identity) {
  uint8_t channel_binding[P2P_SECURITY_ID_SIZE];

  memset(channel_binding, 0xa5, sizeof(channel_binding));
  return fixture->p2p_config.identity_provider.verify_remote_credential(
      fixture->p2p_config.identity_provider.context, transport_key,
      channel_binding, credential, credential_len, fixture->now_ms,
      out_identity);
}

static void test_accepts_bound_node_certificate(void) {
  security_fixture_t fixture;
  p2p_authenticated_identity_v2_t local_identity;
  p2p_authenticated_identity_v2_t remote_identity;
  uint8_t zero[P2P_SECURITY_ID_SIZE] = {0};

  check_int_eq(0, fixture_issue_certificate(
                      &fixture, MESH_MGMT_ROLE_OPERATOR, 7u, 5u));
  check_int_eq(P2P_OK, fixture_init_provider(
                               &fixture, 5u, MESH_MGMT_ROLE_OPERATOR,
                               NULL, 0u));
  memset(&local_identity, 0, sizeof(local_identity));
  memset(&remote_identity, 0, sizeof(remote_identity));
  check_int_eq(P2P_OK, fixture_build_local(&fixture, &local_identity));
  check_int_eq(P2P_OK, fixture_verify_remote(
                               &fixture, fixture.transport_key,
                               fixture.certificate,
                               sizeof(fixture.certificate),
                               &remote_identity));
  check_mem_eq(fixture.management_key, remote_identity.principal_id,
               sizeof(fixture.management_key));
  check_mem_ne(remote_identity.routing_id, zero, sizeof(zero));
  check_mem_ne(remote_identity.credential_digest, zero, sizeof(zero));
  check_hex64_eq(remote_identity.trust_epoch, 5u);
  check_int_eq((int)MESH_MGMT_ROLE_OPERATOR, (int)remote_identity.flags);
  mesh_mgmt_p2p_security_provider_destroy_v2(&fixture.provider);
}

static void test_rejects_transport_key_and_certificate_tampering(void) {
  security_fixture_t fixture;
  p2p_authenticated_identity_v2_t identity;
  uint8_t wrong_transport[P2P_KEY_SIZE];
  uint8_t tampered[MESH_MGMT_CERTIFICATE_V1_SIZE];

  check_int_eq(0, fixture_issue_certificate(
                      &fixture, MESH_MGMT_ROLE_OPERATOR, 8u, 5u));
  check_int_eq(P2P_OK, fixture_init_provider(
                               &fixture, 5u, MESH_MGMT_ROLE_OPERATOR,
                               NULL, 0u));
  memcpy(wrong_transport, fixture.transport_key, sizeof(wrong_transport));
  wrong_transport[0] ^= 1u;
  check_int_eq(P2P_ERR_UNTRUSTED_IDENTITY,
               fixture_verify_remote(&fixture, wrong_transport,
                                     fixture.certificate,
                                     sizeof(fixture.certificate), &identity));
  memcpy(tampered, fixture.certificate, sizeof(tampered));
  tampered[100] ^= 1u;
  check_int_eq(P2P_ERR_UNTRUSTED_IDENTITY,
               fixture_verify_remote(&fixture, fixture.transport_key,
                                     tampered, sizeof(tampered), &identity));
  mesh_mgmt_p2p_security_provider_destroy_v2(&fixture.provider);
}

static void test_rejects_expired_revoked_and_stale_certificates(void) {
  security_fixture_t fixture;
  p2p_authenticated_identity_v2_t identity;
  uint64_t revoked_serial = 9u;

  check_int_eq(0, fixture_issue_certificate(
                      &fixture, MESH_MGMT_ROLE_OPERATOR, revoked_serial, 5u));
  check_int_eq(P2P_OK, fixture_init_provider(
                               &fixture, 5u, MESH_MGMT_ROLE_OPERATOR,
                               &revoked_serial, 1u));
  check_int_eq(P2P_ERR_UNTRUSTED_IDENTITY,
               fixture_verify_remote(&fixture, fixture.transport_key,
                                     fixture.certificate,
                                     sizeof(fixture.certificate), &identity));
  mesh_mgmt_p2p_security_provider_destroy_v2(&fixture.provider);

  check_int_eq(P2P_OK, fixture_init_provider(
                               &fixture, 6u, MESH_MGMT_ROLE_OPERATOR,
                               NULL, 0u));
  check_int_eq(P2P_ERR_UNTRUSTED_IDENTITY,
               fixture_verify_remote(&fixture, fixture.transport_key,
                                     fixture.certificate,
                                     sizeof(fixture.certificate), &identity));
  mesh_mgmt_p2p_security_provider_destroy_v2(&fixture.provider);

  check_int_eq(P2P_OK, fixture_init_provider(
                               &fixture, 5u, MESH_MGMT_ROLE_OPERATOR,
                               NULL, 0u));
  fixture.now_ms = TEST_NOW_MS + 100u;
  check_int_eq(P2P_ERR_UNTRUSTED_IDENTITY,
               fixture_verify_remote(&fixture, fixture.transport_key,
                                     fixture.certificate,
                                     sizeof(fixture.certificate), &identity));
  mesh_mgmt_p2p_security_provider_destroy_v2(&fixture.provider);
}

static void test_applies_remote_role_policy_without_rejecting_local_role(void) {
  security_fixture_t fixture;
  p2p_authenticated_identity_v2_t identity;

  check_int_eq(0, fixture_issue_certificate(
                      &fixture, MESH_MGMT_ROLE_OBSERVER, 10u, 5u));
  check_int_eq(P2P_OK, fixture_init_provider(
                               &fixture, 5u, MESH_MGMT_ROLE_OPERATOR,
                               NULL, 0u));
  check_int_eq(P2P_OK, fixture_build_local(&fixture, &identity));
  check_int_eq(P2P_ERR_UNTRUSTED_IDENTITY,
               fixture_verify_remote(&fixture, fixture.transport_key,
                                     fixture.certificate,
                                     sizeof(fixture.certificate), &identity));
  mesh_mgmt_p2p_security_provider_destroy_v2(&fixture.provider);
}

static void test_rejects_invalid_trust_policy(void) {
  security_fixture_t fixture;
  uint64_t duplicate_revocations[2] = {11u, 11u};

  check_int_eq(0, fixture_issue_certificate(
                      &fixture, MESH_MGMT_ROLE_OPERATOR, 11u, 5u));
  check_int_eq(P2P_ERR_INVALID_ARG,
               fixture_init_provider(&fixture, 5u, 1ull << 40u,
                                     NULL, 0u));
  check_int_eq(P2P_ERR_INVALID_ARG,
               fixture_init_provider(&fixture, 5u,
                                     MESH_MGMT_ROLE_OPERATOR,
                                     duplicate_revocations, 2u));
}

static void test_updates_remote_trust_before_session_revalidation(void) {
  security_fixture_t fixture;
  p2p_authenticated_identity_v2_t identity;
  mesh_mgmt_p2p_remote_trust_v2_t trust;
  uint64_t revoked_serial = 12u;

  check_int_eq(0, fixture_issue_certificate(
                      &fixture, MESH_MGMT_ROLE_OPERATOR, revoked_serial, 5u));
  check_int_eq(P2P_OK, fixture_init_provider(
                               &fixture, 5u, MESH_MGMT_ROLE_OPERATOR,
                               NULL, 0u));
  check_int_eq(P2P_OK, fixture_verify_remote(
                               &fixture, fixture.transport_key,
                               fixture.certificate,
                               sizeof(fixture.certificate), &identity));

  memset(&trust, 0, sizeof(trust));
  trust.struct_size = sizeof(trust);
  trust.minimum_remote_principal_epoch = 5u;
  trust.required_remote_roles = MESH_MGMT_ROLE_OPERATOR;
  trust.revoked_serials = &revoked_serial;
  trust.revoked_serial_count = 1u;
  check_int_eq(P2P_OK,
               mesh_mgmt_p2p_security_provider_update_remote_trust_v2(
                   &fixture.provider, &trust));
  check_int_eq(P2P_ERR_UNTRUSTED_IDENTITY,
               fixture_verify_remote(&fixture, fixture.transport_key,
                                     fixture.certificate,
                                     sizeof(fixture.certificate), &identity));
  mesh_mgmt_p2p_security_provider_destroy_v2(&fixture.provider);
}

spec("Mesh management Noise identity provider") {
  it("accepts a certificate bound to the Noise static key") {
    test_accepts_bound_node_certificate();
  }
  it("rejects a substituted key and tampered credential") {
    test_rejects_transport_key_and_certificate_tampering();
  }
  it("rejects expired, revoked and stale certificates") {
    test_rejects_expired_revoked_and_stale_certificates();
  }
  it("applies required roles only to remote identities") {
    test_applies_remote_role_policy_without_rejecting_local_role();
  }
  it("rejects malformed trust snapshots") {
    test_rejects_invalid_trust_policy();
  }
  it("atomically updates remote trust for session revalidation") {
    test_updates_remote_trust_before_session_revalidation();
  }
}
