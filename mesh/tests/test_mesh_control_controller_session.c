#include "mesh_control_controller_session.h"
#include "mesh_control_mmp.h"
#include "mesh_control_status.h"
#include "platform.h"
#include "tinytest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t TEST_PRIVATE_KEY[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60};

typedef struct {
  uint8_t node_id[MESH_CONTROL_NODE_ID_SIZE];
  uint8_t public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE];
  uint8_t tls_digest[MESH_CONTROL_DIGEST_SIZE];
  uint64_t policy_generation;
} test_identity_t;

static void fill_bytes(uint8_t *output, size_t size, uint8_t seed) {
  size_t index;
  for (index = 0u; index < size; ++index)
    output[index] = (uint8_t)(seed + index);
}

static mesh_control_result_t authorize_identity(
    void *context, const uint8_t claimed_node_id[MESH_CONTROL_NODE_ID_SIZE],
    const uint8_t actual_tls_digest[MESH_CONTROL_DIGEST_SIZE],
    mesh_control_agent_sync_hello_policy_v1_t *out_policy) {
  test_identity_t *identity = (test_identity_t *)context;
  if (!identity || !out_policy ||
      !mesh_mgmt_crypto_equal_32(identity->node_id, claimed_node_id) ||
      !mesh_mgmt_crypto_equal_32(identity->tls_digest, actual_tls_digest))
    return MESH_CONTROL_UNAUTHORIZED;
  memset(out_policy, 0, sizeof(*out_policy));
  memcpy(out_policy->expected_node_id, identity->node_id,
         sizeof(out_policy->expected_node_id));
  memcpy(out_policy->expected_management_public_key, identity->public_key,
         sizeof(out_policy->expected_management_public_key));
  out_policy->minimum_certificate_serial = 10u;
  out_policy->maximum_certificate_serial = 11u;
  out_policy->identity_policy_generation = identity->policy_generation;
  return MESH_CONTROL_OK;
}

static char *make_path(char **out_directory) {
  char *directory = tt_make_temp_dir("mesh-controller-session");
  char *path;
  size_t size;
  if (!directory) return NULL;
  size = strlen(directory) + strlen("/outbox.bin") + 1u;
  path = (char *)malloc(size);
  if (!path) {
    (void)tt_remove_tree(directory);
    free(directory);
    return NULL;
  }
  (void)snprintf(path, size, "%s/outbox.bin", directory);
  *out_directory = directory;
  return path;
}

static void configure(mesh_control_controller_session_config_v1_t *config,
                      const char *path, test_identity_t *identity) {
  memset(config, 0, sizeof(*config));
  config->outbox.path = path;
  config->outbox.entry_capacity = 8u;
  config->outbox.session_capacity = 4u;
  config->outbox.byte_capacity = 256u * 1024u;
  config->outbox.max_payload_size =
      MESH_CONTROL_AGENT_SYNC_MAX_PAYLOAD_V1;
  config->outbox.max_claim_lease_ms = 1000u;
  config->outbox.ack_retention_ms = 1000u;
  fill_bytes(config->outbox.authentication_key,
             sizeof(config->outbox.authentication_key), 0xa0u);
  config->session_capacity = 4u;
  config->claim_lease_ms = 500u;
  config->maximum_clock_skew_ms = 100u;
  config->maximum_hello_lifetime_ms = 2000u;
  config->authorize_identity = authorize_identity;
  config->identity_context = identity;
}

static void make_identity(test_identity_t *identity) {
  memset(identity, 0, sizeof(*identity));
  fill_bytes(identity->node_id, sizeof(identity->node_id), 0x20u);
  fill_bytes(identity->tls_digest, sizeof(identity->tls_digest), 0x60u);
  identity->policy_generation = 1u;
  check_int_eq(mesh_mgmt_ed25519_public_from_private(
                   TEST_PRIVATE_KEY, identity->public_key),
               MESH_MGMT_CRYPTO_OK);
}

static size_t make_hello_frame(
    const test_identity_t *identity,
    const uint8_t session_id[MESH_CONTROL_ID_SIZE], uint64_t request_token,
    uint64_t sent_at_ms, uint8_t output[MESH_CONTROL_MAX_FRAME_SIZE_V1]) {
  mesh_control_agent_sync_message_v1_t message;
  mesh_control_agent_sync_hello_v1_t hello;
  uint8_t payload[MESH_CONTROL_AGENT_SYNC_HELLO_PAYLOAD_SIZE_V1];
  size_t payload_size = 0u;
  size_t output_size = 0u;
  memset(&message, 0, sizeof(message));
  memset(&hello, 0, sizeof(hello));
  message.kind = MESH_CONTROL_AGENT_SYNC_HELLO;
  memcpy(message.node_id, identity->node_id, sizeof(message.node_id));
  memcpy(message.session_id, session_id, sizeof(message.session_id));
  message.request_token = request_token;
  message.sent_at_ms = sent_at_ms;
  message.payload = payload;
  message.payload_size = sizeof(payload);
  hello.certificate_serial = 10u;
  hello.not_before_ms = sent_at_ms - 10u;
  hello.expires_at_ms = sent_at_ms + 1000u;
  fill_bytes(hello.nonce, sizeof(hello.nonce), 0x90u);
  memcpy(hello.tls_certificate_sha256, identity->tls_digest,
         sizeof(hello.tls_certificate_sha256));
  memcpy(hello.management_public_key, identity->public_key,
         sizeof(hello.management_public_key));
  check_int_eq(mesh_control_agent_sync_hello_sign_v1(
                   &message, TEST_PRIVATE_KEY, &hello),
               MESH_CONTROL_AGENT_SYNC_OK);
  check_int_eq(mesh_control_agent_sync_hello_encode_v1(
                   &hello, payload, sizeof(payload), &payload_size),
               MESH_CONTROL_AGENT_SYNC_OK);
  check_int_eq(mesh_control_agent_sync_encode_v1(
                   &message, output, MESH_CONTROL_MAX_FRAME_SIZE_V1,
                   &output_size),
               MESH_CONTROL_AGENT_SYNC_OK);
  return output_size;
}

static size_t make_sync_frame(
    mesh_control_agent_sync_kind_v1_t kind, const test_identity_t *identity,
    const uint8_t session_id[MESH_CONTROL_ID_SIZE], uint64_t session_generation,
    uint64_t request_token, uint64_t lease_generation,
    const uint8_t message_id[MESH_CONTROL_ID_SIZE], const uint8_t *payload,
    size_t payload_size, uint64_t sent_at_ms,
    uint8_t output[MESH_CONTROL_MAX_FRAME_SIZE_V1]) {
  mesh_control_agent_sync_message_v1_t message;
  size_t output_size = 0u;
  memset(&message, 0, sizeof(message));
  message.kind = kind;
  memcpy(message.node_id, identity->node_id, sizeof(message.node_id));
  memcpy(message.session_id, session_id, sizeof(message.session_id));
  message.session_generation = session_generation;
  message.request_token = request_token;
  message.lease_generation = lease_generation;
  message.sent_at_ms = sent_at_ms;
  if (message_id) memcpy(message.message_id, message_id, sizeof(message.message_id));
  message.payload = payload;
  message.payload_size = payload_size;
  check_int_eq(mesh_control_agent_sync_encode_v1(
                   &message, output, MESH_CONTROL_MAX_FRAME_SIZE_V1,
                   &output_size),
               MESH_CONTROL_AGENT_SYNC_OK);
  return output_size;
}

static mesh_control_result_t await_response(
    mesh_control_controller_session_v1_t *controller, uint8_t *output,
    size_t *out_size) {
  size_t iteration;
  for (iteration = 0u; iteration < 2000u; ++iteration) {
    size_t progress = 0u;
    mesh_control_result_t result =
        mesh_control_controller_session_poll_v1(controller, &progress);
    if (result != MESH_CONTROL_OK) return result;
    result = mesh_control_controller_session_try_take_response_v1(
        controller, output, MESH_CONTROL_MAX_FRAME_SIZE_V1, out_size);
    if (result != MESH_CONTROL_EMPTY) return result;
    turbo_sleep_ms(1u);
  }
  return MESH_CONTROL_TIMEOUT;
}

static mesh_control_result_t await_submit(
    mesh_control_controller_session_v1_t *controller,
    mesh_control_controller_submit_completion_v1_t *out_completion) {
  size_t iteration;
  for (iteration = 0u; iteration < 2000u; ++iteration) {
    size_t progress = 0u;
    mesh_control_result_t result =
        mesh_control_controller_session_poll_v1(controller, &progress);
    if (result != MESH_CONTROL_OK) return result;
    result = mesh_control_controller_session_try_take_submit_v1(
        controller, out_completion);
    if (result != MESH_CONTROL_EMPTY) return result;
    turbo_sleep_ms(1u);
  }
  return MESH_CONTROL_TIMEOUT;
}

static size_t make_signed_command(
    const test_identity_t *identity,
    const uint8_t message_id[MESH_CONTROL_ID_SIZE],
    const uint8_t request_id[MESH_CONTROL_ID_SIZE],
    uint8_t output[MESH_CONTROL_MAX_FRAME_SIZE_V1]) {
  static const uint8_t body[] = {0x81u, 0x01u, 0x02u};
  mesh_control_envelope_v1_t envelope;
  mesh_mgmt_sign_input_v1_t sign_input;
  uint8_t payload[256];
  size_t payload_size = 0u;
  size_t output_size = 0u;
  memset(&envelope, 0, sizeof(envelope));
  envelope.schema_version = MESH_CONTROL_SCHEMA_V1;
  envelope.kind = MESH_CONTROL_MESSAGE_INTENT;
  envelope.resource_kind = MESH_CONTROL_RESOURCE_FUNCTION;
  envelope.epoch = 3u;
  envelope.sequence = 1u;
  envelope.issued_at_ms = 900u;
  envelope.expires_at_ms = 3000u;
  envelope.payload_size = sizeof(body);
  memcpy(envelope.message_id, message_id, sizeof(envelope.message_id));
  memcpy(envelope.request_id, request_id, sizeof(envelope.request_id));
  memcpy(envelope.target_node_id, identity->node_id,
         sizeof(envelope.target_node_id));
  fill_bytes(envelope.mesh_id, sizeof(envelope.mesh_id), 0xb0u);
  fill_bytes(envelope.origin_principal, sizeof(envelope.origin_principal),
             0xc0u);
  fill_bytes(envelope.resource_id, sizeof(envelope.resource_id), 0xd0u);
  check_int_eq(mesh_control_mmp_body_digest_v1(
                   body, sizeof(body), envelope.payload_digest),
               MESH_CONTROL_MMP_OK);
  check_int_eq(mesh_control_mmp_payload_encode_v1(
                   &envelope, body, sizeof(body), payload, sizeof(payload),
                   &payload_size),
               MESH_CONTROL_MMP_OK);
  memset(&sign_input, 0, sizeof(sign_input));
  sign_input.minor = MESH_MGMT_MINOR_V1;
  sign_input.kind = MESH_MGMT_KIND_CONTROL_FRAME;
  sign_input.private_key = TEST_PRIVATE_KEY;
  sign_input.payload = payload;
  sign_input.payload_len = payload_size;
  memcpy(sign_input.header.mesh_id_hash, envelope.mesh_id,
         sizeof(sign_input.header.mesh_id_hash));
  fill_bytes(sign_input.header.origin_node_id,
             sizeof(sign_input.header.origin_node_id), 0xe0u);
  memcpy(sign_input.header.target_node_id, identity->node_id,
         sizeof(sign_input.header.target_node_id));
  sign_input.header.principal_epoch = 1u;
  sign_input.header.incarnation = 1u;
  fill_bytes(sign_input.header.session_id,
             sizeof(sign_input.header.session_id), 0xf0u);
  sign_input.header.origin_sequence = 1u;
  memcpy(sign_input.header.message_id, message_id,
         sizeof(sign_input.header.message_id));
  sign_input.header.issued_at_ms = envelope.issued_at_ms;
  sign_input.header.expires_at_ms = envelope.expires_at_ms;
  sign_input.header.certificate_serial = 1u;
  check_int_eq(mesh_mgmt_envelope_sign_v1(
                   &sign_input, output, MESH_CONTROL_MAX_FRAME_SIZE_V1,
                   &output_size),
               MESH_MGMT_ENVELOPE_OK);
  return output_size;
}

static void activate(mesh_control_controller_session_v1_t *controller,
                     const test_identity_t *identity,
                     const uint8_t session_id[MESH_CONTROL_ID_SIZE],
                     uint64_t now_ms, uint64_t *out_generation) {
  mesh_control_agent_sync_message_v1_t response;
  uint8_t frame[MESH_CONTROL_MAX_FRAME_SIZE_V1];
  size_t frame_size = make_hello_frame(identity, session_id, 51u, now_ms, frame);
  size_t response_size = 0u;
  check_int_eq(mesh_control_controller_session_receive_v1(
                   controller, identity->tls_digest, frame, frame_size, now_ms),
               MESH_CONTROL_OK);
  check_int_eq(await_response(controller, frame, &response_size),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_agent_sync_decode_v1(
                   frame, response_size, &response),
               MESH_CONTROL_AGENT_SYNC_OK);
  check_int_eq(response.kind, MESH_CONTROL_AGENT_SYNC_HELLO_ACK);
  check_uint_eq(response.request_token, 51u);
  check_uint_ne(response.session_generation, 0u);
  *out_generation = response.session_generation;
}

static void test_activation_and_live_reconnect_fence_old_session(void) {
  mesh_control_controller_session_v1_t controller = {0};
  mesh_control_controller_session_config_v1_t config;
  test_identity_t identity;
  uint8_t old_session[MESH_CONTROL_ID_SIZE];
  uint8_t new_session[MESH_CONTROL_ID_SIZE];
  uint8_t frame[MESH_CONTROL_MAX_FRAME_SIZE_V1];
  char *directory = NULL;
  char *path = make_path(&directory);
  size_t recovered = 0u;
  size_t frame_size;
  uint64_t old_generation = 0u;
  uint64_t new_generation = 0u;

  check_not_null(path);
  make_identity(&identity);
  configure(&config, path, &identity);
  fill_bytes(old_session, sizeof(old_session), 0x30u);
  fill_bytes(new_session, sizeof(new_session), 0x40u);
  check_int_eq(mesh_control_controller_session_init_v1(
                   &controller, &config, &recovered),
               MESH_CONTROL_OK);
  activate(&controller, &identity, old_session, 1000u, &old_generation);
  {
    size_t rejected_size = make_sync_frame(
        MESH_CONTROL_AGENT_SYNC_CLAIM_REQUEST, &identity, old_session,
        old_generation, 50u, 0u, NULL, NULL, 0u, 1005u, frame);
    identity.policy_generation++;
    check_int_eq(mesh_control_controller_session_receive_v1(
                     &controller, identity.tls_digest, frame, rejected_size,
                     1005u),
                 MESH_CONTROL_STALE_EPOCH);
  }
  activate(&controller, &identity, new_session, 1010u, &new_generation);
  check_uint_eq(new_generation, old_generation + 1u);
  frame_size = make_sync_frame(
      MESH_CONTROL_AGENT_SYNC_CLAIM_REQUEST, &identity, old_session,
      old_generation, 52u, 0u, NULL, NULL, 0u, 1020u, frame);
  check_int_eq(mesh_control_controller_session_receive_v1(
                   &controller, identity.tls_digest, frame, frame_size, 1020u),
               MESH_CONTROL_STALE_EPOCH);
  check_int_eq(mesh_control_controller_session_shutdown_v1(&controller),
               MESH_CONTROL_OK);
  mesh_control_controller_session_destroy_v1(&controller);
  free(path);
  (void)tt_remove_tree(directory);
  free(directory);
}

static void test_command_is_acked_only_after_durable_agent_receipt(void) {
  mesh_control_controller_session_v1_t controller = {0};
  mesh_control_controller_session_config_v1_t config;
  mesh_control_controller_session_stats_v1_t stats;
  mesh_control_agent_sync_message_v1_t response;
  mesh_control_receipt_v1_t receipt;
  test_identity_t identity;
  uint8_t session[MESH_CONTROL_ID_SIZE];
  uint8_t message_id[MESH_CONTROL_ID_SIZE];
  uint8_t request_id[MESH_CONTROL_ID_SIZE];
  uint8_t command[MESH_CONTROL_MAX_FRAME_SIZE_V1];
  uint8_t frame[MESH_CONTROL_MAX_FRAME_SIZE_V1];
  uint8_t receipt_bytes[MESH_CONTROL_RECEIPT_SIZE_V1];
  char *directory = NULL;
  char *path = make_path(&directory);
  size_t command_size;
  size_t frame_size;
  size_t response_size = 0u;
  size_t receipt_size = 0u;
  size_t recovered = 0u;
  uint64_t generation = 0u;
  uint64_t lease_generation;
  uint64_t submit_token = 0u;
  mesh_control_durable_outbox_message_v1_t outbox_message;
  mesh_control_controller_submit_completion_v1_t submit_completion;

  check_not_null(path);
  make_identity(&identity);
  configure(&config, path, &identity);
  fill_bytes(session, sizeof(session), 0x35u);
  fill_bytes(message_id, sizeof(message_id), 0x45u);
  fill_bytes(request_id, sizeof(request_id), 0x55u);
  command_size = make_signed_command(&identity, message_id, request_id, command);
  check_int_eq(mesh_control_controller_session_init_v1(
                   &controller, &config, &recovered),
               MESH_CONTROL_OK);
  memset(&outbox_message, 0, sizeof(outbox_message));
  memcpy(outbox_message.target_node_id, identity.node_id,
         sizeof(outbox_message.target_node_id));
  memcpy(outbox_message.message_id, message_id,
         sizeof(outbox_message.message_id));
  memcpy(outbox_message.request_id, request_id,
         sizeof(outbox_message.request_id));
  outbox_message.sequence = 1u;
  outbox_message.payload = command;
  outbox_message.payload_size = command_size;
  outbox_message.created_at_ms = 900u;
  check_int_eq(mesh_control_controller_session_try_submit_v1(
                   &controller, &outbox_message, &submit_token),
               MESH_CONTROL_OK);
  check_uint_ne(submit_token, 0u);
  check_int_eq(mesh_control_controller_session_abandon_submit_v1(
                   &controller, submit_token),
               MESH_CONTROL_OK);
  {
    size_t iteration;
    for (iteration = 0u;
         iteration < 2000u && controller.pending_operation; ++iteration) {
      size_t progress = 0u;
      check_int_eq(mesh_control_controller_session_poll_v1(
                       &controller, &progress),
                   MESH_CONTROL_OK);
      if (progress == 0u) turbo_sleep_ms(1u);
    }
    check_false(controller.pending_operation);
  }
  check_int_eq(mesh_control_controller_session_try_take_submit_v1(
                   &controller, &submit_completion),
               MESH_CONTROL_EMPTY);
  submit_token = 0u;
  check_int_eq(mesh_control_controller_session_try_submit_v1(
                   &controller, &outbox_message, &submit_token),
               MESH_CONTROL_OK);
  check_int_eq(await_submit(&controller, &submit_completion),
               MESH_CONTROL_OK);
  check_uint_eq(submit_completion.request_token, submit_token);
  check_int_eq(submit_completion.store_result,
               MESH_CONTROL_DURABLE_OUTBOX_OK);
  check_mem_eq(submit_completion.view.message_id, message_id,
               sizeof(message_id));
  activate(&controller, &identity, session, 1000u, &generation);

  frame_size = make_sync_frame(
      MESH_CONTROL_AGENT_SYNC_CLAIM_REQUEST, &identity, session, generation,
      61u, 0u, NULL, NULL, 0u, 1010u, frame);
  check_int_eq(mesh_control_controller_session_receive_v1(
                   &controller, identity.tls_digest, frame, frame_size, 1010u),
               MESH_CONTROL_OK);
  check_int_eq(await_response(&controller, frame, &response_size),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_agent_sync_decode_v1(
                   frame, response_size, &response),
               MESH_CONTROL_AGENT_SYNC_OK);
  check_int_eq(response.kind, MESH_CONTROL_AGENT_SYNC_COMMAND);
  check_mem_eq(response.message_id, message_id, sizeof(message_id));
  check_mem_eq(response.payload, command, command_size);
  lease_generation = response.lease_generation;
  check_uint_ne(lease_generation, 0u);

  memset(&receipt, 0, sizeof(receipt));
  receipt.flags = MESH_CONTROL_RECEIPT_FLAG_DURABLE_V1;
  receipt.operation.state = MESH_CONTROL_OPERATION_ACCEPTED;
  receipt.operation.resource_kind = MESH_CONTROL_RESOURCE_FUNCTION;
  receipt.operation.action = MESH_CONTROL_DESIRED_APPLY;
  memcpy(receipt.operation.operation_id, message_id,
         sizeof(receipt.operation.operation_id));
  memcpy(receipt.operation.message_id, message_id,
         sizeof(receipt.operation.message_id));
  memcpy(receipt.operation.request_id, request_id,
         sizeof(receipt.operation.request_id));
  fill_bytes(receipt.operation.resource_id,
             sizeof(receipt.operation.resource_id), 0xd0u);
  receipt.operation.desired_epoch = 3u;
  receipt.durable_through_index = 1u;
  receipt.state_generation = 1u;
  check_int_eq(mesh_control_receipt_encode_v1(
                   &receipt, receipt_bytes, sizeof(receipt_bytes),
                   &receipt_size),
               MESH_CONTROL_OK);
  frame_size = make_sync_frame(
      MESH_CONTROL_AGENT_SYNC_RECEIPT, &identity, session, generation, 62u,
      lease_generation, message_id, receipt_bytes, receipt_size, 1020u, frame);
  check_int_eq(mesh_control_controller_session_receive_v1(
                   &controller, identity.tls_digest, frame, frame_size, 1020u),
               MESH_CONTROL_OK);
  check_int_eq(await_response(&controller, frame, &response_size),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_agent_sync_decode_v1(
                   frame, response_size, &response),
               MESH_CONTROL_AGENT_SYNC_OK);
  check_int_eq(response.kind, MESH_CONTROL_AGENT_SYNC_HEARTBEAT);
  check_int_eq(response.status, MESH_CONTROL_OK);
  check_int_eq(mesh_control_controller_session_get_stats_v1(
                   &controller, &stats),
               MESH_CONTROL_OK);
  check_uint_eq(stats.commands, 1u);
  check_uint_eq(stats.durable_receipts, 1u);
  check_uint_eq(stats.outbox_submitted, 2u);
  check_int_eq(mesh_control_controller_session_shutdown_v1(&controller),
               MESH_CONTROL_OK);
  mesh_control_controller_session_destroy_v1(&controller);
  free(path);
  (void)tt_remove_tree(directory);
  free(directory);
}

spec("Controller durable online sessions") {
  describe("authenticated activation and fencing") {
    it("durably activates a reconnect and fences the old live session") {
      test_activation_and_live_reconnect_fence_old_session();
    }
    it("acks a signed command only after the agent durable receipt") {
      test_command_is_acked_only_after_durable_agent_receipt();
    }
  }
}
