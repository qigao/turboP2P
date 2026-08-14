#include "mesh_control_agent_service.h"
#include "mesh_control_status.h"
#include "tinytest.h"

#include <string.h>

static const uint8_t TEST_PRIVATE_KEY[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60};

typedef struct {
  uint8_t node_id[MESH_CONTROL_NODE_ID_SIZE];
  uint8_t message_id[MESH_CONTROL_ID_SIZE];
  uint8_t first_session_id[MESH_CONTROL_ID_SIZE];
  uint8_t command[32];
  size_t command_size;
  uint64_t now_ms;
  uint64_t session_generation;
  uint64_t lease_generation;
  unsigned random_seed;
  size_t exchanges;
  size_t local_polls;
  size_t ingested;
  uint8_t durable;
  uint8_t delivered;
} fixture_t;

static void fill(uint8_t *bytes, size_t size, uint8_t seed) {
  size_t index;
  for (index = 0u; index < size; ++index) bytes[index] = (uint8_t)(seed + index);
}

static uint64_t test_now(void *context) {
  return ((fixture_t *)context)->now_ms;
}

static int test_random(void *context, uint8_t *output, size_t output_size) {
  fixture_t *fixture = (fixture_t *)context;
  fixture->random_seed++;
  fill(output, output_size, (uint8_t)(0x30u + fixture->random_seed));
  return 0;
}

static mesh_control_result_t encode_reply(
    const mesh_control_agent_sync_message_v1_t *request,
    mesh_control_agent_sync_kind_v1_t kind, int32_t status,
    uint64_t session_generation, uint64_t lease_generation,
    const uint8_t *message_id, const uint8_t *payload, size_t payload_size,
    uint8_t *output, size_t output_capacity, size_t *out_size) {
  mesh_control_agent_sync_message_v1_t response;
  memset(&response, 0, sizeof(response));
  response.kind = kind;
  response.status = status;
  memcpy(response.node_id, request->node_id, sizeof(response.node_id));
  memcpy(response.session_id, request->session_id, sizeof(response.session_id));
  response.session_generation = session_generation;
  response.request_token = request->request_token;
  response.lease_generation = lease_generation;
  response.sent_at_ms = request->sent_at_ms;
  if (message_id) memcpy(response.message_id, message_id, sizeof(response.message_id));
  response.payload = payload;
  response.payload_size = payload_size;
  return mesh_control_agent_sync_encode_v1(&response, output, output_capacity,
                                            out_size) ==
                 MESH_CONTROL_AGENT_SYNC_OK
             ? MESH_CONTROL_OK
             : MESH_CONTROL_INVALID_STATE;
}

static mesh_control_result_t test_exchange(
    void *context, const uint8_t *request_bytes, size_t request_size,
    uint8_t *response, size_t response_capacity, size_t *out_response_size) {
  fixture_t *fixture = (fixture_t *)context;
  mesh_control_agent_sync_message_v1_t request;
  mesh_control_receipt_v1_t receipt;
  fixture->exchanges++;
  if (mesh_control_agent_sync_decode_v1(request_bytes, request_size, &request) !=
      MESH_CONTROL_AGENT_SYNC_OK)
    return MESH_CONTROL_INVALID_ARG;
  if (request.kind == MESH_CONTROL_AGENT_SYNC_HELLO) {
    mesh_control_agent_sync_hello_v1_t hello;
    if (mesh_control_agent_sync_hello_decode_v1(request.payload,
                                                request.payload_size,
                                                &hello) !=
            MESH_CONTROL_AGENT_SYNC_OK ||
        !mesh_mgmt_crypto_equal_32(hello.tls_certificate_sha256,
                                   fixture->command))
      return MESH_CONTROL_UNAUTHORIZED;
    if (fixture->first_session_id[0] == 0u)
      memcpy(fixture->first_session_id, request.session_id,
             sizeof(fixture->first_session_id));
    fixture->session_generation++;
    return encode_reply(&request, MESH_CONTROL_AGENT_SYNC_HELLO_ACK,
                        MESH_CONTROL_OK, fixture->session_generation, 0u,
                        NULL, NULL, 0u, response, response_capacity,
                        out_response_size);
  }
  if (request.kind == MESH_CONTROL_AGENT_SYNC_CLAIM_REQUEST) {
    if (fixture->delivered)
      return encode_reply(&request, MESH_CONTROL_AGENT_SYNC_ERROR,
                          MESH_CONTROL_EMPTY, request.session_generation, 0u,
                          NULL, NULL, 0u, response, response_capacity,
                          out_response_size);
    fixture->delivered = 1u;
    fixture->lease_generation = 7u;
    return encode_reply(&request, MESH_CONTROL_AGENT_SYNC_COMMAND,
                        MESH_CONTROL_OK, request.session_generation,
                        fixture->lease_generation, fixture->message_id,
                        fixture->command, fixture->command_size, response,
                        response_capacity, out_response_size);
  }
  if (request.kind != MESH_CONTROL_AGENT_SYNC_RECEIPT || !fixture->durable ||
      request.lease_generation != fixture->lease_generation ||
      mesh_control_receipt_decode_v1(request.payload, request.payload_size,
                                     &receipt) != MESH_CONTROL_OK ||
      !mesh_mgmt_crypto_equal_16(receipt.operation.operation_id,
                                 fixture->message_id))
    return MESH_CONTROL_INVALID_STATE;
  return encode_reply(&request, MESH_CONTROL_AGENT_SYNC_HEARTBEAT,
                      MESH_CONTROL_OK, request.session_generation, 0u, NULL,
                      NULL, 0u, response, response_capacity,
                      out_response_size);
}

static mesh_control_result_t test_poll_local(void *context,
                                             size_t *out_progress) {
  fixture_t *fixture = (fixture_t *)context;
  fixture->local_polls++;
  if (fixture->ingested && !fixture->durable) {
    fixture->durable = 1u;
    *out_progress = 1u;
  } else {
    *out_progress = 0u;
  }
  return MESH_CONTROL_OK;
}

static mesh_control_result_t test_ingest(void *context, const uint8_t *frame,
                                         size_t frame_size) {
  fixture_t *fixture = (fixture_t *)context;
  if (!frame || frame_size != fixture->command_size ||
      memcmp(frame, fixture->command, frame_size) != 0)
    return MESH_CONTROL_INVALID_ARG;
  fixture->ingested++;
  return MESH_CONTROL_OK;
}

static mesh_control_result_t test_receipt(
    void *context, const uint8_t operation_id[MESH_CONTROL_ID_SIZE],
    uint8_t output[MESH_CONTROL_RECEIPT_SIZE_V1], size_t *out_size) {
  fixture_t *fixture = (fixture_t *)context;
  mesh_control_receipt_v1_t receipt;
  if (!fixture->durable) return MESH_CONTROL_EMPTY;
  memset(&receipt, 0, sizeof(receipt));
  receipt.flags = MESH_CONTROL_RECEIPT_FLAG_DURABLE_V1;
  receipt.operation.state = MESH_CONTROL_OPERATION_ACCEPTED;
  receipt.operation.resource_kind = MESH_CONTROL_RESOURCE_FUNCTION;
  receipt.operation.action = MESH_CONTROL_DESIRED_APPLY;
  memcpy(receipt.operation.operation_id, operation_id,
         sizeof(receipt.operation.operation_id));
  memcpy(receipt.operation.message_id, operation_id,
         sizeof(receipt.operation.message_id));
  fill(receipt.operation.request_id, sizeof(receipt.operation.request_id),
       0x70u);
  fill(receipt.operation.resource_id, sizeof(receipt.operation.resource_id),
       0x80u);
  receipt.operation.desired_epoch = 1u;
  receipt.durable_through_index = 1u;
  receipt.state_generation = 1u;
  return mesh_control_receipt_encode_v1(&receipt, output,
                                        MESH_CONTROL_RECEIPT_SIZE_V1,
                                        out_size);
}

static void test_command_waits_for_durable_receipt(void) {
  fixture_t fixture;
  mesh_control_agent_service_config_v1_t config;
  mesh_control_agent_service_v1_t service = {0};
  mesh_control_agent_service_stats_v1_t stats;
  size_t progress = 0u;
  memset(&fixture, 0, sizeof(fixture));
  memset(&config, 0, sizeof(config));
  fixture.now_ms = 1000u;
  fixture.command_size = sizeof(fixture.command);
  fill(fixture.command, sizeof(fixture.command), 0x90u);
  fill(fixture.node_id, sizeof(fixture.node_id), 0x20u);
  fill(fixture.message_id, sizeof(fixture.message_id), 0x50u);
  memcpy(config.node_id, fixture.node_id, sizeof(config.node_id));
  check_int_eq(mesh_mgmt_ed25519_public_from_private(
                   TEST_PRIVATE_KEY, config.management_public_key),
               MESH_MGMT_CRYPTO_OK);
  config.management_private_key = TEST_PRIVATE_KEY;
  memcpy(config.tls_certificate_sha256, fixture.command,
         sizeof(config.tls_certificate_sha256));
  config.certificate_serial = 10u;
  config.certificate_policy_generation = 1u;
  config.hello_lifetime_ms = 1000u;
  config.claim_interval_ms = 1u;
  config.now_ms = test_now;
  config.now_context = &fixture;
  config.random_bytes = test_random;
  config.random_context = &fixture;
  config.exchange = test_exchange;
  config.exchange_context = &fixture;
  config.poll_local = test_poll_local;
  config.ingest = test_ingest;
  config.receipt = test_receipt;
  config.local_context = &fixture;
  check_int_eq(mesh_control_agent_service_init_v1(&service, &config),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_agent_service_poll_v1(&service, &progress),
               MESH_CONTROL_OK);
  fixture.now_ms++;
  check_int_eq(mesh_control_agent_service_poll_v1(&service, &progress),
               MESH_CONTROL_OK);
  check_uint_eq(fixture.ingested, 1u);
  check_uint_eq(fixture.exchanges, 2u);
  fixture.now_ms++;
  check_int_eq(mesh_control_agent_service_poll_v1(&service, &progress),
               MESH_CONTROL_OK);
  check_uint_eq(fixture.exchanges, 3u);
  check_int_eq(mesh_control_agent_service_get_stats_v1(&service, &stats),
               MESH_CONTROL_OK);
  check_uint_eq(stats.hellos, 1u);
  check_uint_eq(stats.commands, 1u);
  check_uint_eq(stats.receipts, 1u);
  check_int_eq(stats.state, MESH_CONTROL_AGENT_SERVICE_READY);
  check_int_eq(mesh_control_agent_service_close_v1(&service),
               MESH_CONTROL_OK);
  mesh_control_agent_service_destroy_v1(&service);
}

spec("mesh-agent outbound service") {
  describe("durable Controller delivery") {
    it("acks a command only after the local durable receipt exists") {
      test_command_waits_for_durable_receipt();
    }
  }
}
