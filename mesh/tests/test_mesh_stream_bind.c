#include <tinytest.h>

#include "mesh_stream_bind.h"

#include <string.h>

#define TEST_NOW_MS 1000u
#define TEST_TTL_MS 5000u
#define TEST_CONFIRM_CHANNEL_OFFSET 72u

static const uint8_t INITIATOR_PRIVATE_KEY[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};

static const uint8_t RESPONDER_PRIVATE_KEY[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
};

typedef struct {
  mesh_stream_bind_store_v1_t store;
  mesh_stream_bind_ticket_v1_t ticket;
  uint8_t channel_binding[32];
} bind_fixture_t;

static void fill_bytes(uint8_t *bytes, size_t length, uint8_t first) {
  size_t index = 0;
  for (index = 0; index < length; index++)
    bytes[index] = (uint8_t)(first + index);
}

static mesh_stream_bind_claims_v1_t test_claims(void) {
  mesh_stream_bind_claims_v1_t claims;

  memset(&claims, 0, sizeof(claims));
  fill_bytes(claims.mesh_id_hash, sizeof(claims.mesh_id_hash), 0x10);
  fill_bytes(claims.initiator_node_id, sizeof(claims.initiator_node_id), 0x40);
  fill_bytes(claims.responder_node_id, sizeof(claims.responder_node_id), 0x80);
  fill_bytes(claims.stream_id, sizeof(claims.stream_id), 0xc0);
  claims.stream_epoch = 17u;
  claims.admission_generation = 23u;
  check_int_eq(
      mesh_mgmt_ed25519_public_from_private(INITIATOR_PRIVATE_KEY, claims.initiator_principal_key),
      MESH_MGMT_CRYPTO_OK);
  check_int_eq(
      mesh_mgmt_ed25519_public_from_private(RESPONDER_PRIVATE_KEY, claims.responder_principal_key),
      MESH_MGMT_CRYPTO_OK);
  return claims;
}

static void fixture_init(bind_fixture_t *fixture, size_t capacity) {
  mesh_stream_bind_store_config_v1_t config;
  mesh_stream_bind_claims_v1_t claims = test_claims();

  memset(fixture, 0, sizeof(*fixture));
  config.capacity = capacity;
  config.max_ttl_ms = TEST_TTL_MS;
  fill_bytes(fixture->channel_binding, sizeof(fixture->channel_binding), 0xe0);
  check_int_eq(mesh_stream_bind_store_init_v1(&fixture->store, &config), MESH_STREAM_BIND_OK);
  check_int_eq(mesh_stream_bind_ticket_issue_v1(&fixture->store, &claims, TEST_NOW_MS, TEST_TTL_MS,
                                                &fixture->ticket),
               MESH_STREAM_BIND_OK);
}

static void run_to_confirm(bind_fixture_t *fixture, mesh_stream_bind_initiator_v1_t *initiator,
                           uint8_t init[MESH_STREAM_BIND_INIT_SIZE],
                           uint8_t accept[MESH_STREAM_BIND_ACCEPT_SIZE],
                           uint8_t confirm[MESH_STREAM_BIND_CONFIRM_SIZE]) {
  memset(initiator, 0, sizeof(*initiator));
  check_int_eq(mesh_stream_bind_initiator_start_v1(initiator, &fixture->ticket,
                                                   INITIATOR_PRIVATE_KEY, fixture->channel_binding,
                                                   init),
               MESH_STREAM_BIND_OK);
  check_int_eq(mesh_stream_bind_responder_accept_v1(
                   &fixture->store, init, MESH_STREAM_BIND_INIT_SIZE, RESPONDER_PRIVATE_KEY,
                   fixture->channel_binding, TEST_NOW_MS, accept),
               MESH_STREAM_BIND_OK);
  check_int_eq(mesh_stream_bind_initiator_confirm_v1(
                   initiator, accept, MESH_STREAM_BIND_ACCEPT_SIZE, INITIATOR_PRIVATE_KEY,
                   fixture->channel_binding, confirm),
               MESH_STREAM_BIND_OK);
}

static void test_round_trip_consumes_ticket_and_rejects_replay(void) {
  bind_fixture_t fixture;
  mesh_stream_bind_initiator_v1_t initiator;
  mesh_stream_bind_ticket_v1_t admitted;
  uint8_t init[MESH_STREAM_BIND_INIT_SIZE];
  uint8_t accept[MESH_STREAM_BIND_ACCEPT_SIZE];
  uint8_t confirm[MESH_STREAM_BIND_CONFIRM_SIZE];

  fixture_init(&fixture, 2u);
  run_to_confirm(&fixture, &initiator, init, accept, confirm);
  check_int_eq(mesh_stream_bind_responder_finish_v1(&fixture.store, confirm, sizeof(confirm),
                                                    fixture.channel_binding, TEST_NOW_MS, &admitted),
               MESH_STREAM_BIND_OK);
  check_mem_eq(&admitted, &fixture.ticket, sizeof(admitted));
  check_int_eq(mesh_stream_bind_responder_finish_v1(&fixture.store, confirm, sizeof(confirm),
                                                    fixture.channel_binding, TEST_NOW_MS, &admitted),
               MESH_STREAM_BIND_REPLAY);
  check_mem_eq(&admitted, &(mesh_stream_bind_ticket_v1_t){0}, sizeof(admitted));
  mesh_stream_bind_store_destroy_v1(&fixture.store);
}

static void test_channel_binding_mismatch_does_not_burn_ticket(void) {
  bind_fixture_t fixture;
  mesh_stream_bind_initiator_v1_t initiator;
  mesh_stream_bind_ticket_v1_t admitted;
  uint8_t wrong_binding[32];
  uint8_t zero_binding[32] = {0};
  uint8_t init[MESH_STREAM_BIND_INIT_SIZE];
  uint8_t accept[MESH_STREAM_BIND_ACCEPT_SIZE];
  uint8_t confirm[MESH_STREAM_BIND_CONFIRM_SIZE];

  fixture_init(&fixture, 1u);
  memset(&initiator, 0, sizeof(initiator));
  memcpy(wrong_binding, fixture.channel_binding, sizeof(wrong_binding));
  wrong_binding[0] ^= 0x80u;
  check_int_eq(mesh_stream_bind_initiator_start_v1(&initiator, &fixture.ticket,
                                                   INITIATOR_PRIVATE_KEY, fixture.channel_binding,
                                                   init),
               MESH_STREAM_BIND_OK);
  check_int_eq(mesh_stream_bind_responder_accept_v1(&fixture.store, init, sizeof(init),
                                                    RESPONDER_PRIVATE_KEY, zero_binding,
                                                    TEST_NOW_MS, accept),
               MESH_STREAM_BIND_INVALID_ARG);
  check_int_eq(mesh_stream_bind_responder_accept_v1(&fixture.store, init, sizeof(init),
                                                    RESPONDER_PRIVATE_KEY, wrong_binding,
                                                    TEST_NOW_MS, accept),
               MESH_STREAM_BIND_CHANNEL_MISMATCH);
  check_int_eq(mesh_stream_bind_responder_accept_v1(&fixture.store, init, sizeof(init),
                                                    RESPONDER_PRIVATE_KEY, fixture.channel_binding,
                                                    TEST_NOW_MS, accept),
               MESH_STREAM_BIND_OK);
  check_int_eq(mesh_stream_bind_initiator_confirm_v1(&initiator, accept, sizeof(accept),
                                                     INITIATOR_PRIVATE_KEY, wrong_binding, confirm),
               MESH_STREAM_BIND_CHANNEL_MISMATCH);
  check_int_eq(mesh_stream_bind_initiator_confirm_v1(
                   &initiator, accept, sizeof(accept), INITIATOR_PRIVATE_KEY,
                   fixture.channel_binding, confirm),
               MESH_STREAM_BIND_OK);
  check_int_eq(mesh_stream_bind_responder_finish_v1(&fixture.store, confirm, sizeof(confirm),
                                                    wrong_binding, TEST_NOW_MS, &admitted),
               MESH_STREAM_BIND_CHANNEL_MISMATCH);
  check_int_eq(mesh_stream_bind_responder_finish_v1(&fixture.store, confirm, sizeof(confirm),
                                                    fixture.channel_binding, TEST_NOW_MS, &admitted),
               MESH_STREAM_BIND_OK);
  mesh_stream_bind_store_destroy_v1(&fixture.store);
}

static void test_tampering_fails_without_advancing_state(void) {
  bind_fixture_t fixture;
  mesh_stream_bind_initiator_v1_t initiator;
  mesh_stream_bind_ticket_v1_t admitted;
  uint8_t init[MESH_STREAM_BIND_INIT_SIZE];
  uint8_t accept[MESH_STREAM_BIND_ACCEPT_SIZE];
  uint8_t valid_accept[MESH_STREAM_BIND_ACCEPT_SIZE];
  uint8_t confirm[MESH_STREAM_BIND_CONFIRM_SIZE];

  fixture_init(&fixture, 1u);
  memset(&initiator, 0, sizeof(initiator));
  check_int_eq(mesh_stream_bind_initiator_start_v1(&initiator, &fixture.ticket,
                                                   INITIATOR_PRIVATE_KEY, fixture.channel_binding,
                                                   init),
               MESH_STREAM_BIND_OK);
  init[60] ^= 0x01u;
  check_int_eq(mesh_stream_bind_responder_accept_v1(&fixture.store, init, sizeof(init),
                                                    RESPONDER_PRIVATE_KEY, fixture.channel_binding,
                                                    TEST_NOW_MS, accept),
               MESH_STREAM_BIND_AUTH_FAILED);
  init[60] ^= 0x01u;
  check_int_eq(mesh_stream_bind_responder_accept_v1(&fixture.store, init, sizeof(init),
                                                    RESPONDER_PRIVATE_KEY, fixture.channel_binding,
                                                    TEST_NOW_MS, valid_accept),
               MESH_STREAM_BIND_OK);

  memcpy(accept, valid_accept, sizeof(accept));
  accept[sizeof(accept) - 1u] ^= 0x01u;
  check_int_eq(mesh_stream_bind_initiator_confirm_v1(&initiator, accept, sizeof(accept),
                                                     INITIATOR_PRIVATE_KEY, fixture.channel_binding,
                                                     confirm),
               MESH_STREAM_BIND_AUTH_FAILED);
  check_int_eq(mesh_stream_bind_initiator_confirm_v1(&initiator, valid_accept, sizeof(valid_accept),
                                                     INITIATOR_PRIVATE_KEY, fixture.channel_binding,
                                                     confirm),
               MESH_STREAM_BIND_OK);
  confirm[TEST_CONFIRM_CHANNEL_OFFSET] ^= 0x01u;
  check_int_eq(mesh_stream_bind_responder_finish_v1(&fixture.store, confirm, sizeof(confirm),
                                                    fixture.channel_binding, TEST_NOW_MS, &admitted),
               MESH_STREAM_BIND_CHANNEL_MISMATCH);
  confirm[TEST_CONFIRM_CHANNEL_OFFSET] ^= 0x01u;
  confirm[sizeof(confirm) - 1u] ^= 0x01u;
  check_int_eq(mesh_stream_bind_responder_finish_v1(&fixture.store, confirm, sizeof(confirm),
                                                    fixture.channel_binding, TEST_NOW_MS, &admitted),
               MESH_STREAM_BIND_AUTH_FAILED);
  confirm[sizeof(confirm) - 1u] ^= 0x01u;
  check_int_eq(mesh_stream_bind_responder_finish_v1(&fixture.store, confirm, sizeof(confirm),
                                                    fixture.channel_binding, TEST_NOW_MS, &admitted),
               MESH_STREAM_BIND_OK);
  mesh_stream_bind_store_destroy_v1(&fixture.store);
}

static void test_expiry_and_capacity_are_bounded(void) {
  bind_fixture_t fixture;
  mesh_stream_bind_claims_v1_t claims = test_claims();
  mesh_stream_bind_ticket_v1_t ticket;
  mesh_stream_bind_initiator_v1_t initiator;
  uint8_t init[MESH_STREAM_BIND_INIT_SIZE];
  uint8_t accept[MESH_STREAM_BIND_ACCEPT_SIZE];

  fixture_init(&fixture, 1u);
  memset(&initiator, 0, sizeof(initiator));
  check_int_eq(mesh_stream_bind_initiator_start_v1(&initiator, &fixture.ticket,
                                                   INITIATOR_PRIVATE_KEY, fixture.channel_binding,
                                                   init),
               MESH_STREAM_BIND_OK);
  check_int_eq(mesh_stream_bind_responder_accept_v1(&fixture.store, init, sizeof(init),
                                                    RESPONDER_PRIVATE_KEY, fixture.channel_binding,
                                                    TEST_NOW_MS + TEST_TTL_MS, accept),
               MESH_STREAM_BIND_EXPIRED);
  check_int_eq(
      mesh_stream_bind_ticket_issue_v1(&fixture.store, &claims, TEST_NOW_MS, TEST_TTL_MS, &ticket),
      MESH_STREAM_BIND_RESOURCE_EXHAUSTED);
  check_size_eq(mesh_stream_bind_ticket_sweep_v1(&fixture.store, TEST_NOW_MS + TEST_TTL_MS - 1u),
                0u);
  check_size_eq(mesh_stream_bind_ticket_sweep_v1(&fixture.store, TEST_NOW_MS + TEST_TTL_MS), 1u);
  check_int_eq(mesh_stream_bind_ticket_issue_v1(&fixture.store, &claims, TEST_NOW_MS + TEST_TTL_MS,
                                                TEST_TTL_MS, &ticket),
               MESH_STREAM_BIND_OK);
  mesh_stream_bind_store_destroy_v1(&fixture.store);
}

static void test_role_reflection_and_wrong_private_key_are_rejected(void) {
  mesh_stream_bind_store_v1_t store;
  mesh_stream_bind_store_config_v1_t config = {1u, TEST_TTL_MS};
  mesh_stream_bind_claims_v1_t claims = test_claims();
  mesh_stream_bind_ticket_v1_t ticket;
  mesh_stream_bind_initiator_v1_t initiator;
  uint8_t channel_binding[32];
  uint8_t init[MESH_STREAM_BIND_INIT_SIZE];

  memset(&store, 0, sizeof(store));
  memset(&initiator, 0, sizeof(initiator));
  fill_bytes(channel_binding, sizeof(channel_binding), 0xe0);
  check_int_eq(mesh_stream_bind_store_init_v1(&store, &config), MESH_STREAM_BIND_OK);
  memcpy(claims.responder_principal_key, claims.initiator_principal_key, 32);
  check_int_eq(mesh_stream_bind_ticket_issue_v1(&store, &claims, TEST_NOW_MS, TEST_TTL_MS, &ticket),
               MESH_STREAM_BIND_INVALID_ARG);
  claims = test_claims();
  check_int_eq(mesh_stream_bind_ticket_issue_v1(&store, &claims, TEST_NOW_MS, TEST_TTL_MS, &ticket),
               MESH_STREAM_BIND_OK);
  check_int_eq(mesh_stream_bind_initiator_start_v1(&initiator, &ticket, RESPONDER_PRIVATE_KEY,
                                                   channel_binding, init),
               MESH_STREAM_BIND_AUTH_FAILED);
  mesh_stream_bind_store_destroy_v1(&store);
}

static void test_invalid_frames_and_explicit_invalidation_fail_closed(void) {
  bind_fixture_t fixture;
  mesh_stream_bind_initiator_v1_t initiator;
  uint8_t init[MESH_STREAM_BIND_INIT_SIZE];
  uint8_t accept[MESH_STREAM_BIND_ACCEPT_SIZE];

  fixture_init(&fixture, 1u);
  memset(&initiator, 0, sizeof(initiator));
  check_int_eq(mesh_stream_bind_initiator_start_v1(&initiator, &fixture.ticket,
                                                   INITIATOR_PRIVATE_KEY, fixture.channel_binding,
                                                   init),
               MESH_STREAM_BIND_OK);
  check_int_eq(mesh_stream_bind_responder_accept_v1(&fixture.store, init, sizeof(init) - 1u,
                                                    RESPONDER_PRIVATE_KEY, fixture.channel_binding,
                                                    TEST_NOW_MS, accept),
               MESH_STREAM_BIND_INVALID_FRAME);
  check_int_eq(mesh_stream_bind_responder_abort_init_v1(&fixture.store, init, sizeof(init) - 1u,
                                                        TEST_NOW_MS),
               MESH_STREAM_BIND_INVALID_FRAME);
  check_int_eq(mesh_stream_bind_responder_abort_init_v1(&fixture.store, init, sizeof(init),
                                                        TEST_NOW_MS),
               MESH_STREAM_BIND_OK);
  check_int_eq(mesh_stream_bind_responder_accept_v1(&fixture.store, init, sizeof(init),
                                                    RESPONDER_PRIVATE_KEY, fixture.channel_binding,
                                                    TEST_NOW_MS, accept),
               MESH_STREAM_BIND_REPLAY);
  mesh_stream_bind_store_destroy_v1(&fixture.store);
}

spec("mesh stream secure bind") {
  describe("one-time identity and TLS channel binding") {
    it("completes mutual transcript authentication and rejects replay") {
      test_round_trip_consumes_ticket_and_rejects_replay();
    }
    it("rejects another TLS channel without burning the ticket") {
      test_channel_binding_mismatch_does_not_burn_ticket();
    }
    it("rejects tampering at every handshake stage without hidden progress") {
      test_tampering_fails_without_advancing_state();
    }
    it("bounds capacity and reclaims only expired tickets") {
      test_expiry_and_capacity_are_bounded();
    }
    it("binds initiator and responder roles to distinct management keys") {
      test_role_reflection_and_wrong_private_key_are_rejected();
    }
    it("rejects truncated input and preserves invalidation tombstones") {
      test_invalid_frames_and_explicit_invalidation_fail_closed();
    }
  }
}
