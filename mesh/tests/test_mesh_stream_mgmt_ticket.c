#include "tinytest.h"

#include "mesh_mgmt_crypto.h"
#include "mesh_stream_mgmt_ticket.h"

#include <string.h>

#define TEST_NOW_MS 1500u
#define TEST_ACCEPT_NOW_MS 1550u
#define TEST_TTL_MS 500u

static const uint8_t INITIATOR_PRIVATE_KEY[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
};

static const uint8_t RESPONDER_PRIVATE_KEY[32] = {
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
};

typedef struct {
  uint8_t mesh_id_hash[32];
  uint8_t initiator_node_id[32];
  uint8_t initiator_principal_key[32];
  uint8_t responder_node_id[32];
  uint8_t responder_principal_key[32];
  uint8_t request_message_id[16];
  uint8_t session_id[16];
  mesh_stream_mgmt_ticket_request_v1_t request;
} ticket_fixture_t;

static void fill_bytes(uint8_t *bytes, size_t length, uint8_t first) {
  size_t index = 0;

  for (index = 0; index < length; index++)
    bytes[index] = (uint8_t)(first + index);
}

static void prepare_fixture(ticket_fixture_t *fixture) {
  memset(fixture, 0, sizeof(*fixture));
  fill_bytes(fixture->mesh_id_hash, sizeof(fixture->mesh_id_hash), 0x10);
  fill_bytes(fixture->initiator_node_id, sizeof(fixture->initiator_node_id), 0x40);
  fill_bytes(fixture->responder_node_id, sizeof(fixture->responder_node_id), 0x80);
  fill_bytes(fixture->request_message_id, sizeof(fixture->request_message_id), 0xc0);
  fill_bytes(fixture->session_id, sizeof(fixture->session_id), 0xd0);
  fill_bytes(fixture->request.stream_id, sizeof(fixture->request.stream_id), 0xe0);
  fixture->request.stream_epoch = 7u;
  fixture->request.admission_generation = 9u;
  fixture->request.ttl_ms = TEST_TTL_MS;
  check_int_eq(mesh_mgmt_ed25519_public_from_private(INITIATOR_PRIVATE_KEY,
                                                     fixture->initiator_principal_key),
               MESH_MGMT_CRYPTO_OK);
  check_int_eq(mesh_mgmt_ed25519_public_from_private(RESPONDER_PRIVATE_KEY,
                                                     fixture->responder_principal_key),
               MESH_MGMT_CRYPTO_OK);
}

static void prepare_dispatcher(mesh_mgmt_dispatcher_v1_t *dispatcher,
                               const ticket_fixture_t *fixture, const uint8_t remote_node_id[32],
                               const uint8_t remote_principal_key[32]) {
  memset(dispatcher, 0, sizeof(*dispatcher));
  dispatcher->session.state = MESH_MGMT_SESSION_ESTABLISHED;
  dispatcher->session.negotiated.features = MESH_MGMT_FEATURE_STREAM_TICKET;
  memcpy(dispatcher->session.config.expected_mesh_id_hash, fixture->mesh_id_hash, 32);
  memcpy(dispatcher->session.remote_certificate.managed_node_id, remote_node_id, 32);
  memcpy(dispatcher->session.remote_certificate.management_key, remote_principal_key, 32);
  dispatcher->session.remote_certificate.principal_type = MESH_MGMT_PRINCIPAL_NODE;
  dispatcher->session.remote_certificate.roles = MESH_MGMT_ROLE_OPERATOR;
  dispatcher->session.remote_certificate.serial = 11u;
  dispatcher->session.remote_certificate.principal_epoch = 13u;
  dispatcher->session.remote_incarnation = 17u;
  memcpy(dispatcher->session.remote_session_id, fixture->session_id, 16);
}

static void prepare_event(mesh_mgmt_dispatch_event_v1_t *event,
                          const mesh_mgmt_dispatcher_v1_t *dispatcher, uint8_t kind,
                          mesh_mgmt_dispatch_event_type_t type, const uint8_t *payload,
                          size_t payload_len, const uint8_t message_id[16]) {
  memset(event, 0, sizeof(*event));
  event->type = type;
  event->kind = kind;
  event->envelope.frame.kind = kind;
  event->envelope.frame.payload = payload;
  event->envelope.frame.payload_len = payload_len;
  memcpy(event->envelope.header.mesh_id_hash, dispatcher->session.config.expected_mesh_id_hash, 32);
  memcpy(event->envelope.header.origin_node_id,
         dispatcher->session.remote_certificate.managed_node_id, 32);
  memcpy(event->envelope.header.origin_principal_key,
         dispatcher->session.remote_certificate.management_key, 32);
  event->envelope.header.certificate_serial = dispatcher->session.remote_certificate.serial;
  event->envelope.header.principal_epoch = dispatcher->session.remote_certificate.principal_epoch;
  event->envelope.header.incarnation = dispatcher->session.remote_incarnation;
  memcpy(event->envelope.header.session_id, dispatcher->session.remote_session_id, 16);
  memcpy(event->envelope.header.message_id, message_id, 16);
  event->envelope.header.issued_at_ms = TEST_NOW_MS - 100u;
  event->envelope.header.expires_at_ms = TEST_NOW_MS + 200u;
}

static void test_ticket_payloads_round_trip_canonically(void) {
  ticket_fixture_t fixture;
  mesh_stream_mgmt_ticket_request_v1_t decoded_request;
  mesh_stream_bind_ticket_v1_t ticket;
  mesh_stream_bind_ticket_v1_t decoded_ticket;
  uint8_t decoded_message_id[16];
  uint8_t request_payload[MESH_STREAM_MGMT_TICKET_REQUEST_V1_SIZE];
  uint8_t ticket_payload[MESH_STREAM_MGMT_TICKET_ISSUED_V1_SIZE];
  size_t payload_len = 0;

  prepare_fixture(&fixture);
  check_int_eq(mesh_stream_mgmt_ticket_request_encode_v1(&fixture.request, request_payload,
                                                         sizeof(request_payload), &payload_len),
               MESH_STREAM_MGMT_TICKET_OK);
  check_size_eq(payload_len, sizeof(request_payload));
  check_int_eq(
      mesh_stream_mgmt_ticket_request_decode_v1(request_payload, payload_len, &decoded_request),
      MESH_STREAM_MGMT_TICKET_OK);
  check_mem_eq(&decoded_request, &fixture.request, sizeof(decoded_request));

  memset(&ticket, 0, sizeof(ticket));
  fill_bytes(ticket.ticket_id, sizeof(ticket.ticket_id), 0x22);
  memcpy(ticket.claims.mesh_id_hash, fixture.mesh_id_hash, 32);
  memcpy(ticket.claims.initiator_node_id, fixture.initiator_node_id, 32);
  memcpy(ticket.claims.initiator_principal_key, fixture.initiator_principal_key, 32);
  memcpy(ticket.claims.responder_node_id, fixture.responder_node_id, 32);
  memcpy(ticket.claims.responder_principal_key, fixture.responder_principal_key, 32);
  memcpy(ticket.claims.stream_id, fixture.request.stream_id, MESH_STREAM_ID_SIZE);
  ticket.claims.stream_epoch = fixture.request.stream_epoch;
  ticket.claims.admission_generation = fixture.request.admission_generation;
  ticket.issued_at_ms = TEST_NOW_MS;
  ticket.expires_at_ms = TEST_NOW_MS + TEST_TTL_MS;
  check_int_eq(mesh_stream_mgmt_ticket_issued_encode_v1(fixture.request_message_id, &ticket,
                                                        ticket_payload, sizeof(ticket_payload),
                                                        &payload_len),
               MESH_STREAM_MGMT_TICKET_OK);
  check_size_eq(payload_len, sizeof(ticket_payload));
  check_int_eq(mesh_stream_mgmt_ticket_issued_decode_v1(ticket_payload, payload_len,
                                                        decoded_message_id, &decoded_ticket),
               MESH_STREAM_MGMT_TICKET_OK);
  check_mem_eq(decoded_message_id, fixture.request_message_id, 16);
  check_mem_eq(&decoded_ticket, &ticket, sizeof(ticket));
}

static void test_authenticated_request_issues_and_delivers_one_ticket(void) {
  ticket_fixture_t fixture;
  mesh_mgmt_dispatcher_v1_t responder_dispatcher;
  mesh_mgmt_dispatcher_v1_t initiator_dispatcher;
  mesh_mgmt_dispatch_event_v1_t request_event;
  mesh_mgmt_dispatch_event_v1_t issued_event;
  mesh_stream_bind_store_v1_t store;
  mesh_stream_bind_store_config_v1_t store_config = {2u, 1000u};
  mesh_stream_bind_ticket_v1_t issued_ticket;
  mesh_stream_bind_ticket_v1_t accepted_ticket;
  mesh_stream_bind_initiator_v1_t initiator;
  uint8_t request_payload[MESH_STREAM_MGMT_TICKET_REQUEST_V1_SIZE];
  uint8_t issued_payload[MESH_STREAM_MGMT_TICKET_ISSUED_V1_SIZE];
  uint8_t init_frame[MESH_STREAM_BIND_INIT_SIZE];
  uint8_t channel_binding[MESH_STREAM_BIND_CHANNEL_BINDING_SIZE];
  size_t request_len = 0;
  size_t issued_len = 0;

  prepare_fixture(&fixture);
  prepare_dispatcher(&responder_dispatcher, &fixture, fixture.initiator_node_id,
                     fixture.initiator_principal_key);
  prepare_dispatcher(&initiator_dispatcher, &fixture, fixture.responder_node_id,
                     fixture.responder_principal_key);
  memset(&store, 0, sizeof(store));
  check_int_eq(mesh_stream_bind_store_init_v1(&store, &store_config), MESH_STREAM_BIND_OK);
  check_int_eq(mesh_stream_mgmt_ticket_request_encode_v1(&fixture.request, request_payload,
                                                         sizeof(request_payload), &request_len),
               MESH_STREAM_MGMT_TICKET_OK);
  prepare_event(&request_event, &responder_dispatcher, MESH_MGMT_KIND_STREAM_TICKET_REQUEST,
                MESH_MGMT_DISPATCH_EVENT_STREAM_TICKET_REQUEST, request_payload, request_len,
                fixture.request_message_id);
  check_int_eq(mesh_stream_mgmt_ticket_issue_from_event_v1(
                   &store, &responder_dispatcher, &request_event, fixture.responder_node_id,
                   fixture.responder_principal_key, TEST_NOW_MS, issued_payload,
                   sizeof(issued_payload), &issued_len, &issued_ticket),
               MESH_STREAM_MGMT_TICKET_OK);
  check_size_eq(issued_len, sizeof(issued_payload));
  check_int_eq(store.entries[0].state, MESH_STREAM_BIND_TICKET_ISSUED);

  prepare_event(&issued_event, &initiator_dispatcher, MESH_MGMT_KIND_STREAM_TICKET_ISSUED,
                MESH_MGMT_DISPATCH_EVENT_STREAM_TICKET_ISSUED, issued_payload, issued_len,
                fixture.request_message_id);
  issued_event.envelope.header.issued_at_ms = TEST_NOW_MS;
  check_int_eq(mesh_stream_mgmt_ticket_accept_from_event_v1(
                   &initiator_dispatcher, &issued_event, fixture.initiator_node_id,
                   fixture.initiator_principal_key, fixture.request_message_id, &fixture.request,
                   1000u, TEST_ACCEPT_NOW_MS, &accepted_ticket),
               MESH_STREAM_MGMT_TICKET_OK);
  check_mem_eq(&accepted_ticket, &issued_ticket, sizeof(accepted_ticket));

  memset(&initiator, 0, sizeof(initiator));
  fill_bytes(channel_binding, sizeof(channel_binding), 0x70);
  check_int_eq(mesh_stream_bind_initiator_start_v1(&initiator, &accepted_ticket,
                                                   INITIATOR_PRIVATE_KEY, channel_binding,
                                                   init_frame),
               MESH_STREAM_BIND_OK);
  mesh_stream_bind_store_destroy_v1(&store);
}

static void test_invalid_request_cannot_allocate_or_broaden_ticket(void) {
  ticket_fixture_t fixture;
  mesh_mgmt_dispatcher_v1_t responder_dispatcher;
  mesh_mgmt_dispatch_event_v1_t request_event;
  mesh_stream_bind_store_v1_t store;
  mesh_stream_bind_store_config_v1_t store_config = {1u, 1000u};
  mesh_stream_bind_ticket_v1_t ticket;
  uint8_t request_payload[MESH_STREAM_MGMT_TICKET_REQUEST_V1_SIZE];
  uint8_t output[MESH_STREAM_MGMT_TICKET_ISSUED_V1_SIZE];
  size_t request_len = 0;
  size_t output_len = 0;

  prepare_fixture(&fixture);
  prepare_dispatcher(&responder_dispatcher, &fixture, fixture.initiator_node_id,
                     fixture.initiator_principal_key);
  memset(&store, 0, sizeof(store));
  check_int_eq(mesh_stream_bind_store_init_v1(&store, &store_config), MESH_STREAM_BIND_OK);
  check_int_eq(mesh_stream_mgmt_ticket_request_encode_v1(&fixture.request, request_payload,
                                                         sizeof(request_payload), &request_len),
               MESH_STREAM_MGMT_TICKET_OK);
  prepare_event(&request_event, &responder_dispatcher, MESH_MGMT_KIND_STREAM_TICKET_REQUEST,
                MESH_MGMT_DISPATCH_EVENT_STREAM_TICKET_REQUEST, request_payload, request_len,
                fixture.request_message_id);

  memset(output, 0xa5, sizeof(output));
  check_int_eq(mesh_stream_mgmt_ticket_issue_from_event_v1(
                   &store, &responder_dispatcher, &request_event, fixture.responder_node_id,
                   fixture.responder_principal_key, TEST_NOW_MS, output, sizeof(output) - 1u,
                   &output_len, &ticket),
               MESH_STREAM_MGMT_TICKET_RESOURCE_EXHAUSTED);
  check_int_eq(store.entries[0].state, MESH_STREAM_BIND_TICKET_FREE);
  check_uint_eq(output[0], 0xa5);
  check_mem_eq(&ticket, &(mesh_stream_bind_ticket_v1_t){0}, sizeof(ticket));

  request_event.envelope.header.origin_node_id[0] ^= 1u;
  check_int_eq(mesh_stream_mgmt_ticket_issue_from_event_v1(
                   &store, &responder_dispatcher, &request_event, fixture.responder_node_id,
                   fixture.responder_principal_key, TEST_NOW_MS, output, sizeof(output),
                   &output_len, &ticket),
               MESH_STREAM_MGMT_TICKET_AUTH_FAILED);
  check_int_eq(store.entries[0].state, MESH_STREAM_BIND_TICKET_FREE);
  request_event.envelope.header.origin_node_id[0] ^= 1u;
  responder_dispatcher.session.remote_certificate.roles = MESH_MGMT_ROLE_OBSERVER;
  check_int_eq(mesh_stream_mgmt_ticket_issue_from_event_v1(
                   &store, &responder_dispatcher, &request_event, fixture.responder_node_id,
                   fixture.responder_principal_key, TEST_NOW_MS, output, sizeof(output),
                   &output_len, &ticket),
               MESH_STREAM_MGMT_TICKET_AUTH_FAILED);
  check_int_eq(store.entries[0].state, MESH_STREAM_BIND_TICKET_FREE);
  mesh_stream_bind_store_destroy_v1(&store);
}

static void test_delivery_rejects_wrong_correlation_expiry_and_schema(void) {
  ticket_fixture_t fixture;
  mesh_mgmt_dispatcher_v1_t initiator_dispatcher;
  mesh_mgmt_dispatch_event_v1_t event;
  mesh_stream_bind_ticket_v1_t ticket;
  mesh_stream_bind_ticket_v1_t output;
  uint8_t payload[MESH_STREAM_MGMT_TICKET_ISSUED_V1_SIZE];
  uint8_t wrong_message_id[16];
  size_t payload_len = 0;

  prepare_fixture(&fixture);
  prepare_dispatcher(&initiator_dispatcher, &fixture, fixture.responder_node_id,
                     fixture.responder_principal_key);
  memset(&ticket, 0, sizeof(ticket));
  fill_bytes(ticket.ticket_id, sizeof(ticket.ticket_id), 0x20);
  memcpy(ticket.claims.mesh_id_hash, fixture.mesh_id_hash, 32);
  memcpy(ticket.claims.initiator_node_id, fixture.initiator_node_id, 32);
  memcpy(ticket.claims.initiator_principal_key, fixture.initiator_principal_key, 32);
  memcpy(ticket.claims.responder_node_id, fixture.responder_node_id, 32);
  memcpy(ticket.claims.responder_principal_key, fixture.responder_principal_key, 32);
  memcpy(ticket.claims.stream_id, fixture.request.stream_id, MESH_STREAM_ID_SIZE);
  ticket.claims.stream_epoch = fixture.request.stream_epoch;
  ticket.claims.admission_generation = fixture.request.admission_generation;
  ticket.issued_at_ms = TEST_NOW_MS;
  ticket.expires_at_ms = TEST_NOW_MS + TEST_TTL_MS;
  check_int_eq(mesh_stream_mgmt_ticket_issued_encode_v1(fixture.request_message_id, &ticket,
                                                        payload, sizeof(payload), &payload_len),
               MESH_STREAM_MGMT_TICKET_OK);
  prepare_event(&event, &initiator_dispatcher, MESH_MGMT_KIND_STREAM_TICKET_ISSUED,
                MESH_MGMT_DISPATCH_EVENT_STREAM_TICKET_ISSUED, payload, payload_len,
                fixture.request_message_id);
  event.envelope.header.issued_at_ms = TEST_NOW_MS;

  memcpy(wrong_message_id, fixture.request_message_id, 16);
  wrong_message_id[0] ^= 1u;
  check_int_eq(mesh_stream_mgmt_ticket_accept_from_event_v1(
                   &initiator_dispatcher, &event, fixture.initiator_node_id,
                   fixture.initiator_principal_key, wrong_message_id, &fixture.request, 1000u,
                   TEST_ACCEPT_NOW_MS, &output),
               MESH_STREAM_MGMT_TICKET_AUTH_FAILED);
  check_mem_eq(&output, &(mesh_stream_bind_ticket_v1_t){0}, sizeof(output));

  check_int_eq(mesh_stream_mgmt_ticket_accept_from_event_v1(
                   &initiator_dispatcher, &event, fixture.initiator_node_id,
                   fixture.initiator_principal_key, fixture.request_message_id, &fixture.request,
                   1000u, TEST_NOW_MS + TEST_TTL_MS, &output),
               MESH_STREAM_MGMT_TICKET_EXPIRED);
  check_int_eq(mesh_stream_mgmt_ticket_issued_decode_v1(payload, payload_len - 1u, wrong_message_id,
                                                        &output),
               MESH_STREAM_MGMT_TICKET_INVALID_SCHEMA);
  check_mem_eq(&output, &(mesh_stream_bind_ticket_v1_t){0}, sizeof(output));
}

spec("mesh stream MMP ticket delivery") {
  describe("canonical ticket schemas") {
    it("round trips request and issued payloads") { test_ticket_payloads_round_trip_canonically(); }
    it("rejects invalid deliveries without partial output") {
      test_delivery_rejects_wrong_correlation_expiry_and_schema();
    }
  }
  describe("authenticated responder-owned issuance") {
    it("issues one stored ticket and delivers it to the initiator") {
      test_authenticated_request_issues_and_delivers_one_ticket();
    }
    it("does not allocate for insufficient output or forged events") {
      test_invalid_request_cannot_allocate_or_broaden_ticket();
    }
  }
}
