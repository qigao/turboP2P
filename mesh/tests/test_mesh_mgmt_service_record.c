#include "mesh_mgmt_service_record.h"

#include "mesh_mgmt_crypto.h"
#include "mesh_mgmt_envelope.h"
#include "tinytest.h"

#include <string.h>

static const uint8_t ROOT_PRIVATE_KEY[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};

static const uint8_t NODE_PRIVATE_KEY[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
};

enum {
  TEST_NOW_MS = 1500u,
  TEST_ISSUED_AT_MS = 1000u,
  TEST_EXPIRES_AT_MS = 2500u,
  TEST_CERT_EXPIRES_AT_MS = 4000u,
  TEST_CERT_SERIAL = 42u,
  TEST_PRINCIPAL_EPOCH = 7u,
};

typedef struct {
  uint8_t root_public_key[32];
  uint8_t node_public_key[32];
  uint8_t mesh_id_hash[32];
  uint8_t node_id[32];
  uint8_t certificate[MESH_MGMT_CERTIFICATE_V1_SIZE];
  size_t certificate_len;
  mesh_mgmt_service_announcement_v1_t announcement;
  uint8_t payload[MESH_MGMT_SERVICE_RECORD_V1_MAX_SIZE];
  size_t payload_len;
  uint8_t frame[MESH_MGMT_FRAME_MAX];
  size_t frame_len;
  mesh_mgmt_service_record_verify_input_v1_t verify;
} service_fixture_t;

static void fill_bytes(uint8_t *bytes, size_t length, uint8_t first) {
  size_t index;

  for (index = 0u; index < length; index++)
    bytes[index] = (uint8_t)(first + index);
}

static void sign_fixture(service_fixture_t *fixture, uint64_t origin_sequence) {
  mesh_mgmt_sign_input_v1_t input;

  fixture->payload_len = 0u;
  check_int_eq(mesh_mgmt_service_record_encode_v1(
                   &fixture->announcement, fixture->payload, sizeof(fixture->payload),
                   &fixture->payload_len),
               MESH_MGMT_SERVICE_RECORD_OK);
  memset(&input, 0, sizeof(input));
  input.minor = MESH_MGMT_MINOR_V1;
  input.kind = MESH_MGMT_KIND_MEMBERSHIP_DELTA;
  input.private_key = NODE_PRIVATE_KEY;
  input.payload = fixture->payload;
  input.payload_len = fixture->payload_len;
  memcpy(input.header.mesh_id_hash, fixture->mesh_id_hash, 32u);
  memcpy(input.header.origin_node_id, fixture->node_id, 32u);
  input.header.principal_epoch = TEST_PRINCIPAL_EPOCH;
  input.header.incarnation = 3u;
  fill_bytes(input.header.session_id, sizeof(input.header.session_id), 0x40u);
  input.header.origin_sequence = origin_sequence;
  fill_bytes(input.header.message_id, sizeof(input.header.message_id), 0x60u);
  input.header.issued_at_ms = TEST_ISSUED_AT_MS;
  input.header.expires_at_ms = fixture->announcement.expires_at_ms;
  input.header.certificate_serial = TEST_CERT_SERIAL;
  fixture->frame_len = 0u;
  check_int_eq(mesh_mgmt_envelope_sign_v1(&input, fixture->frame, sizeof(fixture->frame),
                                          &fixture->frame_len),
               MESH_MGMT_ENVELOPE_OK);
  fixture->verify.frame = fixture->frame;
  fixture->verify.frame_len = fixture->frame_len;
}

static void prepare_fixture(service_fixture_t *fixture) {
  mesh_mgmt_certificate_claims_v1_t claims;

  memset(fixture, 0, sizeof(*fixture));
  check_int_eq(mesh_mgmt_ed25519_public_from_private(ROOT_PRIVATE_KEY, fixture->root_public_key),
               MESH_MGMT_CRYPTO_OK);
  check_int_eq(mesh_mgmt_ed25519_public_from_private(NODE_PRIVATE_KEY, fixture->node_public_key),
               MESH_MGMT_CRYPTO_OK);
  fill_bytes(fixture->mesh_id_hash, 32u, 0x20u);
  fill_bytes(fixture->node_id, 32u, 0x70u);

  memset(&claims, 0, sizeof(claims));
  claims.principal_type = MESH_MGMT_PRINCIPAL_NODE;
  memcpy(claims.management_key, fixture->node_public_key, 32u);
  fill_bytes(claims.transport_peer_id, sizeof(claims.transport_peer_id), 0xa0u);
  memcpy(claims.managed_node_id, fixture->node_id, 32u);
  memcpy(claims.mesh_id_hash, fixture->mesh_id_hash, 32u);
  claims.roles = MESH_MGMT_ROLE_OBSERVER;
  claims.not_before_ms = 500u;
  claims.expires_at_ms = TEST_CERT_EXPIRES_AT_MS;
  claims.serial = TEST_CERT_SERIAL;
  claims.principal_epoch = TEST_PRINCIPAL_EPOCH;
  check_int_eq(mesh_mgmt_certificate_issue_v1(&claims, ROOT_PRIVATE_KEY, fixture->certificate,
                                              sizeof(fixture->certificate),
                                              &fixture->certificate_len),
               MESH_MGMT_IDENTITY_OK);

  memcpy(fixture->announcement.owner_node_id, fixture->node_id, 32u);
  fixture->announcement.service_type = MESH_MGMT_SERVICE_RPC;
  fixture->announcement.address_family = MESH_MGMT_SERVICE_ADDRESS_IPV4;
  fixture->announcement.virtual_address[0] = 100u;
  fixture->announcement.virtual_address[1] = 64u;
  fixture->announcement.virtual_address[3] = 1u;
  memcpy(fixture->announcement.dns_name, "node-a.mesh", sizeof("node-a.mesh"));
  fixture->announcement.port = 7878u;
  fixture->announcement.record_epoch = 1u;
  fixture->announcement.expires_at_ms = TEST_EXPIRES_AT_MS;

  fixture->verify.certificate = fixture->certificate;
  fixture->verify.certificate_len = fixture->certificate_len;
  fixture->verify.trusted_issuer_key = fixture->root_public_key;
  fixture->verify.expected_mesh_id_hash = fixture->mesh_id_hash;
  fixture->verify.expected_owner_node_id = fixture->node_id;
  fixture->verify.now_ms = TEST_NOW_MS;
  fixture->verify.max_ttl_ms = 2000u;
  sign_fixture(fixture, fixture->announcement.record_epoch);
}

static void test_service_key_has_independent_namespace(void) {
  static const char RPC_SUFFIX[] = ":service:rpc";
  service_fixture_t fixture;
  uint8_t parsed_mesh_id_hash[32];
  uint8_t parsed_node_id[32];
  char key[MESH_MGMT_SERVICE_DHT_KEY_V1_SIZE];
  size_t key_len = 0u;

  prepare_fixture(&fixture);
  check_int_eq(mesh_mgmt_service_dht_key_build_v1(
                   fixture.mesh_id_hash, fixture.node_id, key, sizeof(key), &key_len),
               MESH_MGMT_SERVICE_RECORD_OK);
  check_size_eq(key_len, MESH_MGMT_SERVICE_DHT_KEY_V1_LENGTH);
  check_mem_eq(key + key_len - (sizeof(RPC_SUFFIX) - 1u), RPC_SUFFIX, sizeof(RPC_SUFFIX) - 1u);
  check_int_eq(mesh_mgmt_service_dht_key_parse_v1(
                   key, key_len, parsed_mesh_id_hash, parsed_node_id),
               MESH_MGMT_SERVICE_RECORD_OK);
  check_mem_eq(parsed_mesh_id_hash, fixture.mesh_id_hash, sizeof(parsed_mesh_id_hash));
  check_mem_eq(parsed_node_id, fixture.node_id, sizeof(parsed_node_id));

  key[key_len - 1u] = 'x';
  check_int_eq(mesh_mgmt_service_dht_key_parse_v1(
                   key, key_len, parsed_mesh_id_hash, parsed_node_id),
               MESH_MGMT_SERVICE_RECORD_INVALID_SCHEMA);
}

static void test_service_payload_is_canonical(void) {
  service_fixture_t fixture;
  mesh_mgmt_service_announcement_v1_t decoded;

  prepare_fixture(&fixture);
  check_int_eq(mesh_mgmt_service_record_decode_v1(
                   fixture.payload, fixture.payload_len, &decoded),
               MESH_MGMT_SERVICE_RECORD_OK);
  check_mem_eq(&decoded, &fixture.announcement, sizeof(decoded));

  fixture.announcement.dns_name[0] = 'N';
  check_int_eq(mesh_mgmt_service_record_encode_v1(
                   &fixture.announcement, fixture.payload, sizeof(fixture.payload),
                   &fixture.payload_len),
               MESH_MGMT_SERVICE_RECORD_INVALID_SCHEMA);
}

static void test_signed_service_record_is_bound_to_virtual_identity(void) {
  service_fixture_t fixture;
  mesh_mgmt_service_record_v1_t record;

  prepare_fixture(&fixture);
  check_int_eq(mesh_mgmt_service_record_verify_v1(&fixture.verify, &record),
               MESH_MGMT_SERVICE_RECORD_OK);
  check_mem_eq(record.owner_node_id, fixture.node_id, sizeof(record.owner_node_id));
  check_str_eq(record.virtual_ip, "100.64.0.1");
  check_str_eq(record.dns_name, "node-a.mesh");
  check_str_eq(record.virtual_host, "node-a.mesh");
  check_uint_eq(record.port, 7878u);

  fixture.frame[fixture.frame_len - 1u] ^= 1u;
  check_int_eq(mesh_mgmt_service_record_verify_v1(&fixture.verify, &record),
               MESH_MGMT_SERVICE_RECORD_AUTH_FAILED);
  check_mem_eq(&record, &(mesh_mgmt_service_record_v1_t){0}, sizeof(record));

  prepare_fixture(&fixture);
  fixture.announcement.record_epoch++;
  sign_fixture(&fixture, fixture.announcement.record_epoch - 1u);
  check_int_eq(mesh_mgmt_service_record_verify_v1(&fixture.verify, &record),
               MESH_MGMT_SERVICE_RECORD_AUTH_FAILED);
  check_mem_eq(&record, &(mesh_mgmt_service_record_v1_t){0}, sizeof(record));
}

spec("mesh management RPC service record") {
  describe("virtual service discovery trust boundary") {
    it("uses a DHT namespace separate from physical transport endpoints") {
      test_service_key_has_independent_namespace();
    }
    it("encodes only canonical virtual addresses and DNS names") {
      test_service_payload_is_canonical();
    }
    it("binds the signed RPC service to the enrolled node identity") {
      test_signed_service_record_is_bound_to_virtual_identity();
    }
  }
}
