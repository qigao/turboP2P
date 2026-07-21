#include <tinytest.h>

#include "mesh_mgmt_agent_runtime.h"

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
  uint8_t transport_peer_id[P2P_KEY_SIZE];
  uint8_t certificate[MESH_MGMT_CERTIFICATE_V1_SIZE];
  size_t certificate_len;
  mesh_mgmt_endpoint_announcement_v1_t announcement;
  uint8_t payload[MESH_MGMT_ENDPOINT_RECORD_IPV6_V1_SIZE];
  size_t payload_len;
  uint8_t frame[MESH_MGMT_FRAME_MAX];
  size_t frame_len;
  mesh_mgmt_endpoint_record_verify_input_v1_t verify;
} endpoint_fixture_t;

static void fill_bytes(uint8_t *bytes, size_t length, uint8_t first) {
  size_t index;

  for (index = 0u; index < length; index++)
    bytes[index] = (uint8_t)(first + index);
}

static void sign_fixture(endpoint_fixture_t *fixture, uint8_t kind) {
  mesh_mgmt_sign_input_v1_t input;

  fixture->payload_len = 0u;
  check_int_eq(mesh_mgmt_endpoint_record_encode_v1(&fixture->announcement, fixture->payload,
                                                   sizeof(fixture->payload), &fixture->payload_len),
               MESH_MGMT_ENDPOINT_RECORD_OK);
  memset(&input, 0, sizeof(input));
  input.minor = MESH_MGMT_MINOR_V1;
  input.kind = kind;
  input.private_key = NODE_PRIVATE_KEY;
  input.payload = fixture->payload;
  input.payload_len = fixture->payload_len;
  memcpy(input.header.mesh_id_hash, fixture->mesh_id_hash, 32u);
  memcpy(input.header.origin_node_id, fixture->node_id, 32u);
  input.header.principal_epoch = TEST_PRINCIPAL_EPOCH;
  input.header.incarnation = 3u;
  fill_bytes(input.header.session_id, sizeof(input.header.session_id), 0x40u);
  input.header.origin_sequence = fixture->announcement.record_epoch;
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

static void prepare_fixture(endpoint_fixture_t *fixture) {
  mesh_mgmt_certificate_claims_v1_t claims;

  memset(fixture, 0, sizeof(*fixture));
  check_int_eq(mesh_mgmt_ed25519_public_from_private(ROOT_PRIVATE_KEY, fixture->root_public_key),
               MESH_MGMT_CRYPTO_OK);
  check_int_eq(mesh_mgmt_ed25519_public_from_private(NODE_PRIVATE_KEY, fixture->node_public_key),
               MESH_MGMT_CRYPTO_OK);
  fill_bytes(fixture->mesh_id_hash, 32u, 0x20u);
  fill_bytes(fixture->node_id, 32u, 0x70u);
  fill_bytes(fixture->transport_peer_id, P2P_KEY_SIZE, 0xa0u);

  memset(&claims, 0, sizeof(claims));
  claims.principal_type = MESH_MGMT_PRINCIPAL_NODE;
  memcpy(claims.management_key, fixture->node_public_key, 32u);
  memcpy(claims.transport_peer_id, fixture->transport_peer_id, P2P_KEY_SIZE);
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
  memcpy(fixture->announcement.transport_peer_id, fixture->transport_peer_id, P2P_KEY_SIZE);
  fixture->announcement.address_family = MESH_MGMT_ENDPOINT_ADDRESS_IPV4;
  fixture->announcement.address[0] = 127u;
  fixture->announcement.address[3] = 1u;
  fixture->announcement.port = 8443u;
  fixture->announcement.record_epoch = 1u;
  fixture->announcement.expires_at_ms = TEST_EXPIRES_AT_MS;

  fixture->verify.certificate = fixture->certificate;
  fixture->verify.certificate_len = fixture->certificate_len;
  fixture->verify.trusted_issuer_key = fixture->root_public_key;
  fixture->verify.expected_mesh_id_hash = fixture->mesh_id_hash;
  fixture->verify.expected_owner_node_id = fixture->node_id;
  fixture->verify.now_ms = TEST_NOW_MS;
  fixture->verify.max_ttl_ms = 2000u;
  sign_fixture(fixture, MESH_MGMT_KIND_MEMBERSHIP_DELTA);
}

static void test_canonical_ipv4_and_ipv6_payloads(void) {
  endpoint_fixture_t fixture;
  mesh_mgmt_endpoint_announcement_v1_t decoded;
  mesh_mgmt_tlv_reader_t reader;
  mesh_mgmt_tlv_view_t field;
  uint8_t output[MESH_MGMT_ENDPOINT_RECORD_IPV6_V1_SIZE];
  uint8_t unchanged[sizeof(output)];
  size_t output_len = 0u;

  prepare_fixture(&fixture);
  memset(output, 0xa5, sizeof(output));
  memcpy(unchanged, output, sizeof(output));
  check_int_eq(mesh_mgmt_endpoint_record_encode_v1(&fixture.announcement, output,
                                                   MESH_MGMT_ENDPOINT_RECORD_IPV4_V1_SIZE - 1u,
                                                   &output_len),
               MESH_MGMT_ENDPOINT_RECORD_RESOURCE_EXHAUSTED);
  check_size_eq(output_len, MESH_MGMT_ENDPOINT_RECORD_IPV4_V1_SIZE);
  check_mem_eq(output, unchanged, sizeof(output));
  check_int_eq(mesh_mgmt_endpoint_record_decode_v1(fixture.payload, fixture.payload_len, &decoded),
               MESH_MGMT_ENDPOINT_RECORD_OK);
  check_mem_eq(&decoded, &fixture.announcement, sizeof(decoded));

  fixture.announcement.address_family = MESH_MGMT_ENDPOINT_ADDRESS_IPV6;
  memset(fixture.announcement.address, 0, sizeof(fixture.announcement.address));
  fixture.announcement.address[0] = 0x20u;
  fixture.announcement.address[1] = 0x01u;
  fixture.announcement.address[2] = 0x0du;
  fixture.announcement.address[3] = 0xb8u;
  fixture.announcement.address[15] = 1u;
  check_int_eq(mesh_mgmt_endpoint_record_encode_v1(&fixture.announcement, output, sizeof(output),
                                                   &output_len),
               MESH_MGMT_ENDPOINT_RECORD_OK);
  check_size_eq(output_len, MESH_MGMT_ENDPOINT_RECORD_IPV6_V1_SIZE);
  check_int_eq(mesh_mgmt_endpoint_record_decode_v1(output, output_len, &decoded),
               MESH_MGMT_ENDPOINT_RECORD_OK);
  check_mem_eq(&decoded, &fixture.announcement, sizeof(decoded));

  fixture.announcement.address[0] = 0u;
  fixture.announcement.address[1] = 0u;
  fixture.announcement.address[2] = 0u;
  fixture.announcement.address[3] = 0u;
  fixture.announcement.address[10] = 0xffu;
  fixture.announcement.address[11] = 0xffu;
  fixture.announcement.address[12] = 127u;
  fixture.announcement.address[15] = 1u;
  check_int_eq(mesh_mgmt_endpoint_record_encode_v1(&fixture.announcement, output, sizeof(output),
                                                   &output_len),
               MESH_MGMT_ENDPOINT_RECORD_INVALID_SCHEMA);
  fixture.announcement.address_family = MESH_MGMT_ENDPOINT_ADDRESS_IPV4;
  memset(fixture.announcement.address, 0, sizeof(fixture.announcement.address));
  fixture.announcement.address[0] = 224u;
  fixture.announcement.address[3] = 1u;
  check_int_eq(mesh_mgmt_endpoint_record_encode_v1(&fixture.announcement, output, sizeof(output),
                                                   &output_len),
               MESH_MGMT_ENDPOINT_RECORD_INVALID_SCHEMA);

  mesh_mgmt_tlv_reader_init(&reader, fixture.payload, fixture.payload_len);
  check_int_eq(mesh_mgmt_tlv_reader_next(&reader, &field), 1);
  check_int_eq(mesh_mgmt_tlv_reader_next(&reader, &field), 1);
  check_int_eq(mesh_mgmt_tlv_reader_next(&reader, &field), 1);
  check_int_eq(mesh_mgmt_tlv_reader_next(&reader, &field), 1);
  ((uint8_t *)field.value)[0] = MESH_MGMT_ENDPOINT_ADDRESS_IPV6;
  check_int_eq(mesh_mgmt_endpoint_record_decode_v1(fixture.payload, fixture.payload_len, &decoded),
               MESH_MGMT_ENDPOINT_RECORD_INVALID_SCHEMA);
  check_mem_eq(&decoded, &(mesh_mgmt_endpoint_announcement_v1_t){0}, sizeof(decoded));
}

static void test_canonical_dht_key_round_trip(void) {
  static const char EXPECTED_KEY[] =
      "mgmt:202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f:node:"
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";
  endpoint_fixture_t fixture;
  uint8_t parsed_mesh_id_hash[32];
  uint8_t parsed_node_id[32];
  uint8_t zero_id[32] = {0};
  char key[MESH_MGMT_ENDPOINT_DHT_KEY_V1_SIZE];
  char unchanged[sizeof(key)];
  size_t key_len = 0u;

  prepare_fixture(&fixture);
  memset(key, 0xa5, sizeof(key));
  memcpy(unchanged, key, sizeof(key));
  check_int_eq(mesh_mgmt_endpoint_dht_key_build_v1(fixture.mesh_id_hash, fixture.node_id, key,
                                                   sizeof(key) - 1u, &key_len),
               MESH_MGMT_ENDPOINT_RECORD_RESOURCE_EXHAUSTED);
  check_size_eq(key_len, MESH_MGMT_ENDPOINT_DHT_KEY_V1_LENGTH);
  check_mem_eq(key, unchanged, sizeof(key));
  check_int_eq(mesh_mgmt_endpoint_dht_key_build_v1(fixture.mesh_id_hash, fixture.node_id, key,
                                                   sizeof(key), &key_len),
               MESH_MGMT_ENDPOINT_RECORD_OK);
  check_size_eq(key_len, MESH_MGMT_ENDPOINT_DHT_KEY_V1_LENGTH);
  check_str_eq(key, EXPECTED_KEY);
  check_int_eq(
      mesh_mgmt_endpoint_dht_key_parse_v1(key, key_len, parsed_mesh_id_hash, parsed_node_id),
      MESH_MGMT_ENDPOINT_RECORD_OK);
  check_mem_eq(parsed_mesh_id_hash, fixture.mesh_id_hash, sizeof(parsed_mesh_id_hash));
  check_mem_eq(parsed_node_id, fixture.node_id, sizeof(parsed_node_id));

  key[5] = 'A';
  memset(parsed_mesh_id_hash, 0xa5, sizeof(parsed_mesh_id_hash));
  memset(parsed_node_id, 0xa5, sizeof(parsed_node_id));
  check_int_eq(
      mesh_mgmt_endpoint_dht_key_parse_v1(key, key_len, parsed_mesh_id_hash, parsed_node_id),
      MESH_MGMT_ENDPOINT_RECORD_INVALID_SCHEMA);
  check_mem_eq(parsed_mesh_id_hash, zero_id, sizeof(parsed_mesh_id_hash));
  check_mem_eq(parsed_node_id, zero_id, sizeof(parsed_node_id));
  key[5] = EXPECTED_KEY[5];
  key[0] = 'M';
  check_int_eq(
      mesh_mgmt_endpoint_dht_key_parse_v1(key, key_len, parsed_mesh_id_hash, parsed_node_id),
      MESH_MGMT_ENDPOINT_RECORD_INVALID_SCHEMA);
  key[0] = EXPECTED_KEY[0];
  check_int_eq(
      mesh_mgmt_endpoint_dht_key_parse_v1(key, key_len - 1u, parsed_mesh_id_hash, parsed_node_id),
      MESH_MGMT_ENDPOINT_RECORD_INVALID_SCHEMA);
  check_int_eq(
      mesh_mgmt_endpoint_dht_key_build_v1(zero_id, fixture.node_id, key, sizeof(key), &key_len),
      MESH_MGMT_ENDPOINT_RECORD_INVALID_SCHEMA);
  check_size_eq(key_len, 0u);
}

static void test_signed_record_verification_is_fail_closed(void) {
  endpoint_fixture_t fixture;
  mesh_mgmt_endpoint_record_v1_t record;
  uint8_t wrong_node[32];

  prepare_fixture(&fixture);
  check_int_eq(mesh_mgmt_endpoint_record_verify_v1(&fixture.verify, &record),
               MESH_MGMT_ENDPOINT_RECORD_OK);
  check_mem_eq(record.transport_peer_id, fixture.transport_peer_id, P2P_KEY_SIZE);
  check_str_eq(record.host, "127.0.0.1");
  check_uint_eq(record.port, 8443u);
  check_uint_eq(record.record_epoch, 1u);
  check_uint_eq(record.expires_at_ms, TEST_EXPIRES_AT_MS);

  fixture.announcement.address_family = MESH_MGMT_ENDPOINT_ADDRESS_IPV6;
  memset(fixture.announcement.address, 0, sizeof(fixture.announcement.address));
  fixture.announcement.address[0] = 0x20u;
  fixture.announcement.address[1] = 0x01u;
  fixture.announcement.address[2] = 0x0du;
  fixture.announcement.address[3] = 0xb8u;
  fixture.announcement.address[15] = 1u;
  sign_fixture(&fixture, MESH_MGMT_KIND_MEMBERSHIP_DELTA);
  check_int_eq(mesh_mgmt_endpoint_record_verify_v1(&fixture.verify, &record),
               MESH_MGMT_ENDPOINT_RECORD_OK);
  check_str_eq(record.host, "2001:db8::1");

  prepare_fixture(&fixture);

  fixture.frame[fixture.frame_len - 1u] ^= 1u;
  check_int_eq(mesh_mgmt_endpoint_record_verify_v1(&fixture.verify, &record),
               MESH_MGMT_ENDPOINT_RECORD_AUTH_FAILED);
  check_mem_eq(&record, &(mesh_mgmt_endpoint_record_v1_t){0}, sizeof(record));
  fixture.frame[fixture.frame_len - 1u] ^= 1u;

  fill_bytes(wrong_node, sizeof(wrong_node), 0xc0u);
  fixture.verify.expected_owner_node_id = wrong_node;
  check_int_eq(mesh_mgmt_endpoint_record_verify_v1(&fixture.verify, &record),
               MESH_MGMT_ENDPOINT_RECORD_AUTH_FAILED);
  fixture.verify.expected_owner_node_id = fixture.node_id;
  fixture.verify.trusted_issuer_key = fixture.node_public_key;
  check_int_eq(mesh_mgmt_endpoint_record_verify_v1(&fixture.verify, &record),
               MESH_MGMT_ENDPOINT_RECORD_AUTH_FAILED);
  fixture.verify.trusted_issuer_key = fixture.root_public_key;
  fixture.verify.now_ms = TEST_EXPIRES_AT_MS;
  check_int_eq(mesh_mgmt_endpoint_record_verify_v1(&fixture.verify, &record),
               MESH_MGMT_ENDPOINT_RECORD_EXPIRED);
  fixture.verify.now_ms = TEST_NOW_MS;
  fixture.verify.max_ttl_ms = 1000u;
  check_int_eq(mesh_mgmt_endpoint_record_verify_v1(&fixture.verify, &record),
               MESH_MGMT_ENDPOINT_RECORD_EXPIRED);
  fixture.verify.max_ttl_ms = 2000u;

  fixture.announcement.transport_peer_id[0] ^= 1u;
  sign_fixture(&fixture, MESH_MGMT_KIND_MEMBERSHIP_DELTA);
  check_int_eq(mesh_mgmt_endpoint_record_verify_v1(&fixture.verify, &record),
               MESH_MGMT_ENDPOINT_RECORD_AUTH_FAILED);
  fixture.announcement.transport_peer_id[0] ^= 1u;
  sign_fixture(&fixture, MESH_MGMT_KIND_PROBE);
  check_int_eq(mesh_mgmt_endpoint_record_verify_v1(&fixture.verify, &record),
               MESH_MGMT_ENDPOINT_RECORD_INVALID_SCHEMA);
}

static void test_runtime_accepts_only_verified_endpoint_frames(void) {
  endpoint_fixture_t fixture;
  mesh_mgmt_agent_runtime_v1_t runtime;
  mesh_mgmt_endpoint_pool_config_v1_t config;
  mesh_mgmt_endpoint_snapshot_v1_t snapshot;

  prepare_fixture(&fixture);
  memset(&runtime, 0, sizeof(runtime));
  memset(&config, 0, sizeof(config));
  runtime.node = (p2p_node_t *)&runtime;
  config.node = runtime.node;
  config.capacity = 1u;
  config.retry_base_ms = 100u;
  config.retry_max_ms = 800u;
  config.connect_timeout_ms = 50u;
  config.protocol_failure_limit = 2u;
  check_int_eq(mesh_mgmt_endpoint_pool_init_v1(&runtime.endpoint_pool, &config),
               MESH_MGMT_ENDPOINT_POOL_OK);
  runtime.state = MESH_MGMT_AGENT_RUNTIME_READY;

  check_int_eq(mesh_mgmt_agent_runtime_apply_endpoint_frame_v1(&runtime, &fixture.verify),
               MESH_MGMT_AGENT_RUNTIME_OK);
  check_int_eq(mesh_mgmt_endpoint_pool_snapshot_v1(&runtime.endpoint_pool,
                                                   fixture.transport_peer_id, &snapshot),
               MESH_MGMT_ENDPOINT_POOL_OK);
  check_str_eq(snapshot.record.host, "127.0.0.1");
  check_uint_eq(snapshot.record.port, 8443u);

  fixture.frame[fixture.frame_len - 1u] ^= 1u;
  check_int_eq(mesh_mgmt_agent_runtime_apply_endpoint_frame_v1(&runtime, &fixture.verify),
               MESH_MGMT_AGENT_RUNTIME_ENDPOINT_RECORD_FAILED);
  check_int_eq(runtime.last_endpoint_record_result, MESH_MGMT_ENDPOINT_RECORD_AUTH_FAILED);
  check_int_eq(mesh_mgmt_endpoint_pool_snapshot_v1(&runtime.endpoint_pool,
                                                   fixture.transport_peer_id, &snapshot),
               MESH_MGMT_ENDPOINT_POOL_OK);
  check_uint_eq(snapshot.record.record_epoch, 1u);

  runtime.node = NULL;
  mesh_mgmt_endpoint_pool_destroy_v1(&runtime.endpoint_pool);
}

static void test_runtime_consumes_only_verified_cached_dht_frames(void) {
  endpoint_fixture_t fixture;
  mesh_mgmt_agent_runtime_v1_t runtime;
  mesh_mgmt_agent_cached_endpoint_v1_t cached_input;
  mesh_mgmt_endpoint_pool_config_v1_t config;
  mesh_mgmt_endpoint_snapshot_v1_t snapshot;
  char key[MESH_MGMT_ENDPOINT_DHT_KEY_V1_SIZE];
  size_t key_len = 0u;

  prepare_fixture(&fixture);
  memset(&runtime, 0, sizeof(runtime));
  memset(&cached_input, 0, sizeof(cached_input));
  memset(&config, 0, sizeof(config));
  runtime.node = p2p_create("127.0.0.1", 0);
  check_not_null(runtime.node);
  if (!runtime.node)
    return;
  config.node = runtime.node;
  config.capacity = 1u;
  config.retry_base_ms = 100u;
  config.retry_max_ms = 800u;
  config.connect_timeout_ms = 50u;
  config.protocol_failure_limit = 2u;
  check_int_eq(mesh_mgmt_endpoint_pool_init_v1(&runtime.endpoint_pool, &config),
               MESH_MGMT_ENDPOINT_POOL_OK);
  runtime.state = MESH_MGMT_AGENT_RUNTIME_READY;

  cached_input.mesh_id_hash = fixture.mesh_id_hash;
  cached_input.owner_node_id = fixture.node_id;
  cached_input.certificate = fixture.certificate;
  cached_input.certificate_len = fixture.certificate_len;
  cached_input.trusted_issuer_key = fixture.root_public_key;
  cached_input.now_ms = TEST_NOW_MS;
  cached_input.max_ttl_ms = 2000u;
  check_int_eq(mesh_mgmt_agent_runtime_apply_cached_endpoint_v1(&runtime, &cached_input),
               MESH_MGMT_AGENT_RUNTIME_DISCOVERY_FAILED);
  check_int_eq(runtime.last_p2p_result, P2P_ERR_NOT_FOUND);
  check_size_eq(runtime.endpoint_pool.count, 0u);

  check_int_eq(mesh_mgmt_endpoint_dht_key_build_v1(fixture.mesh_id_hash, fixture.node_id, key,
                                                   sizeof(key), &key_len),
               MESH_MGMT_ENDPOINT_RECORD_OK);
  check_int_eq(p2p_dht_put_cached(runtime.node, key, fixture.frame, fixture.frame_len), P2P_OK);
  check_int_eq(mesh_mgmt_agent_runtime_apply_cached_endpoint_v1(&runtime, &cached_input),
               MESH_MGMT_AGENT_RUNTIME_OK);
  check_int_eq(mesh_mgmt_endpoint_pool_snapshot_v1(&runtime.endpoint_pool,
                                                   fixture.transport_peer_id, &snapshot),
               MESH_MGMT_ENDPOINT_POOL_OK);
  check_str_eq(snapshot.record.host, "127.0.0.1");
  check_uint_eq(snapshot.record.record_epoch, 1u);

  fixture.frame[fixture.frame_len - 1u] ^= 1u;
  check_int_eq(p2p_dht_put_cached(runtime.node, key, fixture.frame, fixture.frame_len), P2P_OK);
  check_int_eq(mesh_mgmt_agent_runtime_apply_cached_endpoint_v1(&runtime, &cached_input),
               MESH_MGMT_AGENT_RUNTIME_ENDPOINT_RECORD_FAILED);
  check_int_eq(runtime.last_endpoint_record_result, MESH_MGMT_ENDPOINT_RECORD_AUTH_FAILED);
  check_int_eq(mesh_mgmt_endpoint_pool_snapshot_v1(&runtime.endpoint_pool,
                                                   fixture.transport_peer_id, &snapshot),
               MESH_MGMT_ENDPOINT_POOL_OK);
  check_uint_eq(snapshot.record.record_epoch, 1u);

  mesh_mgmt_endpoint_pool_destroy_v1(&runtime.endpoint_pool);
  p2p_destroy(runtime.node);
  runtime.node = NULL;
}

spec("mesh management endpoint record") {
  describe("canonical discovery trust boundary") {
    it("round-trips only the canonical lowercase DHT owner key") {
      test_canonical_dht_key_round_trip();
    }
    it("encodes only canonical binary IPv4 and IPv6 endpoints") {
      test_canonical_ipv4_and_ipv6_payloads();
    }
    it("binds signed endpoint records to direct trust and node identity") {
      test_signed_record_verification_is_fail_closed();
    }
    it("prevents runtime dial state from consuming unverified frames") {
      test_runtime_accepts_only_verified_endpoint_frames();
    }
    it("consumes cached DHT frames without starting a network lookup") {
      test_runtime_consumes_only_verified_cached_dht_frames();
    }
  }
}
