#include "mesh_node_ipc.h"
#include "mesh_node_ipc_channel.h"
#include "mesh_node_ipc_client.h"
#include "mesh_node_ipc_owner.h"
#include "tinytest.h"

#include <string.h>

static const uint8_t SHA256_ABC[32] = {
    0xbau, 0x78u, 0x16u, 0xbfu, 0x8fu, 0x01u, 0xcfu, 0xeau,
    0x41u, 0x41u, 0x40u, 0xdeu, 0x5du, 0xaeu, 0x22u, 0x23u,
    0xb0u, 0x03u, 0x61u, 0xa3u, 0x96u, 0x17u, 0x7au, 0x9cu,
    0xb4u, 0x10u, 0xffu, 0x61u, 0xf2u, 0x00u, 0x15u, 0xadu};

static size_t make_command_frame(uint8_t *frame, size_t capacity) {
  static const uint8_t document[] = {'a', 'b', 'c'};
  mesh_node_ipc_command_v1_t command;
  mesh_node_ipc_envelope_v1_t envelope;
  uint8_t body[256];
  size_t body_size = 0u;
  size_t frame_size = 0u;

  memset(&command, 0, sizeof(command));
  command.action = MESH_CONTROL_DESIRED_APPLY;
  command.resource_kind = MESH_CONTROL_RESOURCE_NETWORK;
  command.precondition_epoch = 6u;
  command.mesh_id[0] = 0x11u;
  command.resource_id[0] = 0x22u;
  command.provider_id[0] = 0x33u;
  memcpy(command.document_digest, SHA256_ABC, sizeof(SHA256_ABC));
  command.document = document;
  command.document_size = sizeof(document);
  check_int_eq(mesh_node_ipc_command_encode_v1(
                   &command, body, sizeof(body), &body_size),
               MESH_CONTROL_OK);

  memset(&envelope, 0, sizeof(envelope));
  envelope.kind = MESH_NODE_IPC_COMMAND_V1;
  envelope.request_id[0] = 1u;
  envelope.operation_id[0] = 2u;
  envelope.sender_incarnation[0] = 3u;
  envelope.sequence = 4u;
  envelope.desired_epoch = 7u;
  envelope.body = body;
  envelope.body_size = body_size;
  check_int_eq(mesh_node_ipc_envelope_encode_v1(
                   &envelope, frame, capacity, &frame_size),
               MESH_CONTROL_OK);
  return frame_size;
}

static size_t make_delete_frame(uint8_t *frame, size_t capacity) {
  mesh_node_ipc_command_v1_t command;
  mesh_node_ipc_envelope_v1_t envelope;
  uint8_t body[MESH_NODE_IPC_COMMAND_HEADER_SIZE_V1];
  size_t body_size = 0u;
  size_t frame_size = 0u;

  memset(&command, 0, sizeof(command));
  command.action = MESH_CONTROL_DESIRED_DELETE;
  command.resource_kind = MESH_CONTROL_RESOURCE_NETWORK;
  command.precondition_epoch = 6u;
  command.mesh_id[0] = 0x11u;
  command.resource_id[0] = 0x22u;
  command.provider_id[0] = 0x33u;
  check_int_eq(mesh_node_ipc_command_encode_v1(
                   &command, body, sizeof(body), &body_size),
               MESH_CONTROL_OK);

  memset(&envelope, 0, sizeof(envelope));
  envelope.kind = MESH_NODE_IPC_COMMAND_V1;
  envelope.request_id[0] = 1u;
  envelope.operation_id[0] = 2u;
  envelope.sender_incarnation[0] = 3u;
  envelope.sequence = 5u;
  envelope.desired_epoch = 7u;
  envelope.body = body;
  envelope.body_size = body_size;
  check_int_eq(mesh_node_ipc_envelope_encode_v1(
                   &envelope, frame, capacity, &frame_size),
               MESH_CONTROL_OK);
  return frame_size;
}

static size_t make_ack_frame(uint8_t *frame, size_t capacity) {
  mesh_node_ipc_envelope_v1_t envelope;
  size_t frame_size = 0u;
  memset(&envelope, 0, sizeof(envelope));
  envelope.kind = MESH_NODE_IPC_ACK_RESULT_V1;
  envelope.request_id[0] = 1u;
  envelope.operation_id[0] = 2u;
  envelope.sender_incarnation[0] = 9u;
  envelope.sequence = 1u;
  check_int_eq(mesh_node_ipc_envelope_encode_v1(
                   &envelope, frame, capacity, &frame_size),
               MESH_CONTROL_OK);
  return frame_size;
}

static void test_command_and_envelope_round_trip(void) {
  mesh_node_ipc_envelope_v1_t envelope;
  mesh_node_ipc_command_v1_t command;
  uint8_t frame[512];
  size_t frame_size = make_command_frame(frame, sizeof(frame));

  check_int_eq(mesh_node_ipc_envelope_decode_v1(frame, frame_size, &envelope),
               MESH_CONTROL_OK);
  check_uint_eq(envelope.kind, MESH_NODE_IPC_COMMAND_V1);
  check_uint_eq(envelope.desired_epoch, 7u);
  check_int_eq(mesh_node_ipc_command_decode_v1(
                   envelope.body, envelope.body_size, &command),
               MESH_CONTROL_OK);
  check_uint_eq(command.resource_kind, MESH_CONTROL_RESOURCE_NETWORK);
  check_uint_eq(command.precondition_epoch, 6u);
  check_uint_eq(command.mesh_id[0], 0x11u);
  check_uint_eq(command.resource_id[0], 0x22u);
  check_size_eq(command.document_size, 3u);
  check_int_eq(memcmp(command.document, "abc", 3u), 0);

  /* These offsets are a compatibility vector, not a native struct layout. */
  check_uint_eq(envelope.body[20u], 0x11u);
  check_uint_eq(envelope.body[52u], 0x22u);
  check_uint_eq(envelope.body[84u], 0x33u);
}

static void test_tampering_and_shape_fail_closed(void) {
  mesh_node_ipc_envelope_v1_t envelope;
  mesh_node_ipc_command_v1_t command;
  uint8_t frame[512];
  uint8_t command_body[256];
  size_t frame_size = make_command_frame(frame, sizeof(frame));
  size_t command_size = frame_size - MESH_NODE_IPC_HEADER_SIZE_V1;

  memcpy(command_body, frame + MESH_NODE_IPC_HEADER_SIZE_V1, command_size);
  command_body[command_size - 1u] ^= 1u;
  memset(&command, 0xa5, sizeof(command));
  check_int_eq(mesh_node_ipc_command_decode_v1(
                   command_body, command_size, &command),
               MESH_CONTROL_INVALID_ARG);
  check_size_eq(command.document_size, 0u);

  frame[frame_size - 1u] ^= 1u;
  memset(&envelope, 0xa5, sizeof(envelope));
  check_int_eq(mesh_node_ipc_envelope_decode_v1(frame, frame_size, &envelope),
               MESH_CONTROL_INVALID_ARG);
  check_size_eq(envelope.body_size, 0u);
  check_int_eq(mesh_node_ipc_envelope_decode_v1(frame, frame_size - 1u,
                                                &envelope),
               MESH_CONTROL_INVALID_ARG);
}

static void test_envelope_identity_and_scope_rules(void) {
  mesh_node_ipc_envelope_v1_t envelope;
  uint8_t frame[256];
  size_t frame_size = 0u;

  memset(&envelope, 0, sizeof(envelope));
  envelope.kind = MESH_NODE_IPC_COMMAND_V1;
  envelope.request_id[0] = 1u;
  envelope.sender_incarnation[0] = 2u;
  envelope.sequence = 1u;
  envelope.desired_epoch = 1u;
  check_int_eq(mesh_node_ipc_envelope_encode_v1(
                   &envelope, frame, sizeof(frame), &frame_size),
               MESH_CONTROL_INVALID_ARG);

  envelope.kind = MESH_NODE_IPC_QUERY_V1;
  envelope.operation_id[0] = 3u;
  envelope.desired_epoch = 4u;
  check_int_eq(mesh_node_ipc_envelope_encode_v1(
                   &envelope, frame, sizeof(frame), &frame_size),
               MESH_CONTROL_OK);

  envelope.kind = MESH_NODE_IPC_DRAIN_V1;
  check_int_eq(mesh_node_ipc_envelope_encode_v1(
                   &envelope, frame, sizeof(frame), &frame_size),
               MESH_CONTROL_INVALID_ARG);
}

static void test_result_round_trip_and_invariants(void) {
  mesh_node_ipc_result_v1_t result;
  mesh_node_ipc_result_v1_t decoded;
  uint8_t body[MESH_NODE_IPC_RESULT_SIZE_V1];

  memset(&result, 0, sizeof(result));
  result.outcome = MESH_NODE_IPC_OUTCOME_SUCCEEDED_V1;
  result.resource_kind = MESH_CONTROL_RESOURCE_NETWORK;
  result.action = MESH_CONTROL_DESIRED_APPLY;
  result.applied_epoch = 9u;
  result.resource_id[0] = 1u;
  result.observed_digest[0] = 2u;
  check_int_eq(mesh_node_ipc_result_encode_v1(&result, body),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_result_decode_v1(body, sizeof(body), &decoded),
               MESH_CONTROL_OK);
  check_uint_eq(decoded.applied_epoch, 9u);
  check_uint_eq(decoded.observed_digest[0], 2u);

  result.stable_error = MESH_NODE_IPC_ERROR_INTERNAL_V1;
  check_int_eq(mesh_node_ipc_result_encode_v1(&result, body),
               MESH_CONTROL_INVALID_ARG);

  memset(&result, 0, sizeof(result));
  result.outcome = MESH_NODE_IPC_OUTCOME_FAILED_V1;
  result.stable_error = MESH_NODE_IPC_ERROR_FENCED_V1;
  result.failure_stage = MESH_NODE_IPC_STAGE_ADMISSION_V1;
  result.resource_kind = MESH_CONTROL_RESOURCE_NETWORK;
  result.action = MESH_CONTROL_DESIRED_DELETE;
  result.resource_id[0] = 1u;
  check_int_eq(mesh_node_ipc_result_encode_v1(&result, body),
               MESH_CONTROL_OK);
}

static void test_channel_copies_bounds_and_drains(void) {
  mesh_node_ipc_channel_v1_t channel;
  mesh_node_ipc_channel_stats_v1_t stats;
  mesh_node_ipc_frame_view_v1_t view;
  uint8_t frame[512];
  uint8_t original_magic;
  size_t frame_size = make_command_frame(frame, sizeof(frame));

  check_int_eq(mesh_node_ipc_channel_init_v1(
                   &channel, 2u, 4096u, sizeof(frame)),
               MESH_CONTROL_OK);
  original_magic = frame[0];
  check_int_eq(mesh_node_ipc_channel_try_push_v1(
                   &channel, frame, frame_size),
               MESH_CONTROL_OK);
  frame[0] = 0u;
  check_int_eq(mesh_node_ipc_channel_peek_v1(&channel, &view),
               MESH_CONTROL_OK);
  check_uint_eq(view.frame[0], original_magic);
  check_uint_eq(view.envelope.kind, MESH_NODE_IPC_COMMAND_V1);

  frame[0] = original_magic;
  check_int_eq(mesh_node_ipc_channel_try_push_v1(
                   &channel, frame, frame_size),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_channel_try_push_v1(
                   &channel, frame, frame_size),
               MESH_CONTROL_RESOURCE_EXHAUSTED);
  check_int_eq(mesh_node_ipc_channel_close_v1(&channel), MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_channel_try_push_v1(
                   &channel, frame, frame_size),
               MESH_CONTROL_CLOSED);
  check_int_eq(mesh_node_ipc_channel_consume_v1(&channel), MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_channel_consume_v1(&channel), MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_channel_consume_v1(&channel), MESH_CONTROL_EMPTY);
  check_int_eq(mesh_node_ipc_channel_get_stats_v1(&channel, &stats),
               MESH_CONTROL_OK);
  check_size_eq(stats.pending, 0u);
  check_size_eq(stats.retained_bytes, 0u);
  check_uint_eq(stats.published, 2u);
  check_uint_eq(stats.consumed, 2u);
  check_uint_eq(stats.rejected_full, 1u);
  check_uint_eq(stats.rejected_closed, 1u);
  mesh_node_ipc_channel_destroy_v1(&channel);
}

static void test_channel_rejects_invalid_and_byte_exhaustion(void) {
  mesh_node_ipc_channel_v1_t channel;
  mesh_node_ipc_channel_stats_v1_t stats;
  uint8_t frame[512];
  size_t frame_size = make_command_frame(frame, sizeof(frame));

  check_int_eq(mesh_node_ipc_channel_init_v1(
                   &channel, 2u, frame_size, sizeof(frame)),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_channel_try_push_v1(
                   &channel, frame, frame_size),
               MESH_CONTROL_RESOURCE_EXHAUSTED);
  frame[0] = 0u;
  check_int_eq(mesh_node_ipc_channel_try_push_v1(
                   &channel, frame, frame_size),
               MESH_CONTROL_INVALID_ARG);
  check_int_eq(mesh_node_ipc_channel_get_stats_v1(&channel, &stats),
               MESH_CONTROL_OK);
  check_uint_eq(stats.rejected_bytes, 1u);
  check_uint_eq(stats.rejected_invalid, 1u);
  mesh_node_ipc_channel_destroy_v1(&channel);

  check_int_eq(mesh_node_ipc_channel_init_v1(
                   &channel, 3u, 4096u, sizeof(frame)),
               MESH_CONTROL_INVALID_ARG);
}

typedef struct {
  size_t calls;
  mesh_control_result_t result;
} fake_executor_v1_t;

static mesh_control_result_t fake_execute(
    void *context, const mesh_node_ipc_command_v1_t *command,
    uint64_t desired_epoch, mesh_node_ipc_execution_output_v1_t *out_execution) {
  fake_executor_v1_t *fake = (fake_executor_v1_t *)context;
  fake->calls++;
  if (fake->result != MESH_CONTROL_OK)
    return fake->result;
  out_execution->applied_epoch = desired_epoch;
  if (command->action == MESH_CONTROL_DESIRED_APPLY)
    memcpy(out_execution->observed_digest, command->document_digest,
           sizeof(out_execution->observed_digest));
  return MESH_CONTROL_OK;
}

static void init_owner_fixture(mesh_node_ipc_owner_v1_t *owner,
                               mesh_node_ipc_channel_v1_t *inbound,
                               mesh_node_ipc_channel_v1_t *outbound,
                               fake_executor_v1_t *executor,
                               uint8_t mesh_marker,
                               size_t operation_capacity) {
  mesh_node_ipc_owner_config_v1_t config;
  memset(owner, 0, sizeof(*owner));
  memset(&config, 0, sizeof(config));
  check_int_eq(mesh_node_ipc_channel_init_v1(
                   inbound, 4u, 8192u, MESH_NODE_IPC_MAX_FRAME_SIZE_V1),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_channel_init_v1(
                   outbound, 4u, 8192u, MESH_NODE_IPC_MAX_FRAME_SIZE_V1),
               MESH_CONTROL_OK);
  config.inbound = inbound;
  config.outbound = outbound;
  config.execute = fake_execute;
  config.execute_context = executor;
  config.mesh_id[0] = mesh_marker;
  config.provider_id[0] = 0x33u;
  config.sender_incarnation[0] = 0x44u;
  config.allowed_resource_mask =
      UINT64_C(1) << MESH_CONTROL_RESOURCE_NETWORK;
  config.operation_capacity = operation_capacity;
  check_int_eq(mesh_node_ipc_owner_init_v1(owner, &config),
               MESH_CONTROL_OK);
}

static void destroy_owner_fixture(mesh_node_ipc_owner_v1_t *owner,
                                  mesh_node_ipc_channel_v1_t *inbound,
                                  mesh_node_ipc_channel_v1_t *outbound) {
  mesh_node_ipc_owner_destroy_v1(owner);
  mesh_node_ipc_channel_destroy_v1(inbound);
  mesh_node_ipc_channel_destroy_v1(outbound);
}

static void test_owner_executes_once_and_releases_exact_ack(void) {
  mesh_node_ipc_owner_v1_t owner;
  mesh_node_ipc_owner_stats_v1_t stats;
  mesh_node_ipc_channel_v1_t inbound;
  mesh_node_ipc_channel_v1_t outbound;
  mesh_node_ipc_frame_view_v1_t view;
  mesh_node_ipc_result_v1_t result;
  fake_executor_v1_t executor = {0u, MESH_CONTROL_OK};
  uint8_t command[512];
  uint8_t ack[256];
  size_t command_size = make_command_frame(command, sizeof(command));
  size_t ack_size = make_ack_frame(ack, sizeof(ack));
  size_t processed = 0u;

  init_owner_fixture(&owner, &inbound, &outbound, &executor, 0x11u, 4u);
  check_int_eq(mesh_node_ipc_channel_try_push_v1(
                   &inbound, command, command_size),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_owner_poll_v1(&owner, 1u, &processed),
               MESH_CONTROL_OK);
  check_size_eq(processed, 1u);
  check_size_eq(executor.calls, 1u);

  check_int_eq(mesh_node_ipc_channel_peek_v1(&outbound, &view),
               MESH_CONTROL_OK);
  check_uint_eq(view.envelope.kind, MESH_NODE_IPC_ACCEPTED_V1);
  check_int_eq(mesh_node_ipc_channel_consume_v1(&outbound), MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_channel_peek_v1(&outbound, &view),
               MESH_CONTROL_OK);
  check_uint_eq(view.envelope.kind, MESH_NODE_IPC_RESULT_V1);
  check_int_eq(mesh_node_ipc_result_decode_v1(
                   view.envelope.body, view.envelope.body_size, &result),
               MESH_CONTROL_OK);
  check_uint_eq(result.outcome, MESH_NODE_IPC_OUTCOME_SUCCEEDED_V1);
  check_uint_eq(result.applied_epoch, 7u);
  check_int_eq(mesh_node_ipc_channel_consume_v1(&outbound), MESH_CONTROL_OK);

  check_int_eq(mesh_node_ipc_channel_try_push_v1(
                   &inbound, command, command_size),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_owner_poll_v1(&owner, 1u, &processed),
               MESH_CONTROL_OK);
  check_size_eq(executor.calls, 1u);
  check_int_eq(mesh_node_ipc_channel_consume_v1(&outbound), MESH_CONTROL_OK);

  check_int_eq(mesh_node_ipc_channel_try_push_v1(&inbound, ack, ack_size),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_owner_poll_v1(&owner, 1u, &processed),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_owner_get_stats_v1(&owner, &stats),
               MESH_CONTROL_OK);
  check_size_eq(stats.retained_operations, 0u);
  check_uint_eq(stats.duplicate_commands, 1u);
  check_uint_eq(stats.results_acked, 1u);
  destroy_owner_fixture(&owner, &inbound, &outbound);
}

static void test_owner_rejects_cross_mesh_and_operation_collision(void) {
  mesh_node_ipc_owner_v1_t owner;
  mesh_node_ipc_owner_stats_v1_t stats;
  mesh_node_ipc_channel_v1_t inbound;
  mesh_node_ipc_channel_v1_t outbound;
  mesh_node_ipc_frame_view_v1_t view;
  mesh_node_ipc_result_v1_t result;
  fake_executor_v1_t executor = {0u, MESH_CONTROL_OK};
  uint8_t apply[512];
  uint8_t delete_frame[512];
  size_t apply_size = make_command_frame(apply, sizeof(apply));
  size_t delete_size = make_delete_frame(delete_frame, sizeof(delete_frame));
  size_t processed = 0u;

  init_owner_fixture(&owner, &inbound, &outbound, &executor, 0x55u, 4u);
  check_int_eq(mesh_node_ipc_channel_try_push_v1(&inbound, apply, apply_size),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_owner_poll_v1(&owner, 1u, &processed),
               MESH_CONTROL_OK);
  check_size_eq(executor.calls, 0u);
  check_int_eq(mesh_node_ipc_channel_peek_v1(&outbound, &view),
               MESH_CONTROL_OK);
  check_uint_eq(view.envelope.kind, MESH_NODE_IPC_RESULT_V1);
  check_int_eq(mesh_node_ipc_result_decode_v1(
                   view.envelope.body, view.envelope.body_size, &result),
               MESH_CONTROL_OK);
  check_uint_eq(result.stable_error,
                MESH_NODE_IPC_ERROR_PERMISSION_DENIED_V1);
  destroy_owner_fixture(&owner, &inbound, &outbound);

  executor.calls = 0u;
  init_owner_fixture(&owner, &inbound, &outbound, &executor, 0x11u, 4u);
  check_int_eq(mesh_node_ipc_channel_try_push_v1(&inbound, apply, apply_size),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_owner_poll_v1(&owner, 1u, &processed),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_channel_consume_v1(&outbound), MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_channel_consume_v1(&outbound), MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_channel_try_push_v1(
                   &inbound, delete_frame, delete_size),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_owner_poll_v1(&owner, 1u, &processed),
               MESH_CONTROL_OK);
  check_size_eq(executor.calls, 1u);
  check_int_eq(mesh_node_ipc_channel_peek_v1(&outbound, &view),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_result_decode_v1(
                   view.envelope.body, view.envelope.body_size, &result),
               MESH_CONTROL_OK);
  check_uint_eq(result.stable_error, MESH_NODE_IPC_ERROR_CONFLICT_V1);
  check_int_eq(mesh_node_ipc_owner_get_stats_v1(&owner, &stats),
               MESH_CONTROL_OK);
  check_uint_eq(stats.operation_collisions, 1u);
  destroy_owner_fixture(&owner, &inbound, &outbound);
}

static void test_owner_capacity_rejection_does_not_block_ack(void) {
  mesh_node_ipc_owner_v1_t owner;
  mesh_node_ipc_owner_stats_v1_t stats;
  mesh_node_ipc_channel_v1_t inbound;
  mesh_node_ipc_channel_v1_t outbound;
  mesh_node_ipc_frame_view_v1_t view;
  mesh_node_ipc_envelope_v1_t decoded;
  mesh_node_ipc_envelope_v1_t second_envelope;
  mesh_node_ipc_result_v1_t result;
  fake_executor_v1_t executor = {0u, MESH_CONTROL_OK};
  uint8_t first[512];
  uint8_t second[512];
  uint8_t ack[256];
  size_t first_size = make_command_frame(first, sizeof(first));
  size_t second_size = 0u;
  size_t ack_size = make_ack_frame(ack, sizeof(ack));
  size_t processed = 0u;

  check_int_eq(mesh_node_ipc_envelope_decode_v1(
                   first, first_size, &decoded),
               MESH_CONTROL_OK);
  second_envelope = decoded;
  second_envelope.request_id[0] = 8u;
  second_envelope.operation_id[0] = 9u;
  second_envelope.sequence = 6u;
  check_int_eq(mesh_node_ipc_envelope_encode_v1(
                   &second_envelope, second, sizeof(second), &second_size),
               MESH_CONTROL_OK);

  init_owner_fixture(&owner, &inbound, &outbound, &executor, 0x11u, 1u);
  check_int_eq(mesh_node_ipc_channel_try_push_v1(
                   &inbound, first, first_size),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_owner_poll_v1(&owner, 1u, &processed),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_channel_consume_v1(&outbound), MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_channel_consume_v1(&outbound), MESH_CONTROL_OK);

  check_int_eq(mesh_node_ipc_channel_try_push_v1(
                   &inbound, second, second_size),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_channel_try_push_v1(&inbound, ack, ack_size),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_owner_poll_v1(&owner, 1u, &processed),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_channel_peek_v1(&outbound, &view),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_result_decode_v1(
                   view.envelope.body, view.envelope.body_size, &result),
               MESH_CONTROL_OK);
  check_uint_eq(result.stable_error,
                MESH_NODE_IPC_ERROR_RESOURCE_EXHAUSTED_V1);
  check_int_eq(mesh_node_ipc_channel_consume_v1(&outbound), MESH_CONTROL_OK);

  check_int_eq(mesh_node_ipc_owner_poll_v1(&owner, 1u, &processed),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_owner_get_stats_v1(&owner, &stats),
               MESH_CONTROL_OK);
  check_size_eq(stats.retained_operations, 0u);
  check_uint_eq(stats.results_acked, 1u);
  check_size_eq(executor.calls, 1u);
  destroy_owner_fixture(&owner, &inbound, &outbound);
}

static void test_client_submits_retains_and_acks_terminal_result(void) {
  static const uint8_t document[] = {'a', 'b', 'c'};
  mesh_node_ipc_channel_v1_t to_owner;
  mesh_node_ipc_channel_v1_t to_client;
  mesh_node_ipc_owner_v1_t owner;
  mesh_node_ipc_client_v1_t client;
  mesh_node_ipc_client_config_v1_t client_config;
  mesh_node_ipc_client_stats_v1_t client_stats;
  mesh_node_ipc_owner_stats_v1_t owner_stats;
  mesh_node_ipc_command_v1_t command;
  mesh_node_ipc_result_v1_t result;
  fake_executor_v1_t executor = {0u, MESH_CONTROL_OK};
  uint8_t request_id[MESH_CONTROL_ID_SIZE] = {0u};
  uint8_t operation_id[MESH_CONTROL_ID_SIZE] = {0u};
  uint8_t result_operation_id[MESH_CONTROL_ID_SIZE];
  uint8_t filler[512];
  size_t filler_size;
  size_t filler_index;
  size_t processed = 0u;

  memset(&to_owner, 0, sizeof(to_owner));
  memset(&to_client, 0, sizeof(to_client));
  memset(&owner, 0, sizeof(owner));
  memset(&client, 0, sizeof(client));
  init_owner_fixture(&owner, &to_owner, &to_client, &executor, 0x11u, 2u);

  memset(&client_config, 0, sizeof(client_config));
  client_config.inbound = &to_client;
  client_config.outbound = &to_owner;
  client_config.mesh_id[0] = 0x11u;
  client_config.provider_id[0] = 0x33u;
  client_config.sender_incarnation[0] = 0x55u;
  client_config.operation_capacity = 2u;
  check_int_eq(mesh_node_ipc_client_init_v1(&client, &client_config),
               MESH_CONTROL_OK);

  memset(&command, 0, sizeof(command));
  command.action = MESH_CONTROL_DESIRED_APPLY;
  command.resource_kind = MESH_CONTROL_RESOURCE_NETWORK;
  command.precondition_epoch = 6u;
  command.mesh_id[0] = 0x11u;
  command.resource_id[0] = 0x22u;
  command.provider_id[0] = 0x33u;
  memcpy(command.document_digest, SHA256_ABC, sizeof(SHA256_ABC));
  command.document = document;
  command.document_size = sizeof(document);
  request_id[0] = 0x61u;
  operation_id[0] = 0x62u;

  check_int_eq(mesh_node_ipc_client_submit_v1(
                   &client, request_id, operation_id, 7u, &command),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_client_submit_v1(
                   &client, request_id, operation_id, 7u, &command),
               MESH_CONTROL_OK);
  command.resource_id[0] = 0x23u;
  check_int_eq(mesh_node_ipc_client_submit_v1(
                   &client, request_id, operation_id, 7u, &command),
               MESH_CONTROL_CONFLICT);
  command.resource_id[0] = 0x22u;

  check_int_eq(mesh_node_ipc_owner_poll_v1(&owner, 1u, &processed),
               MESH_CONTROL_OK);
  check_size_eq(processed, 1u);
  check_size_eq(executor.calls, 1u);
  check_int_eq(mesh_node_ipc_client_poll_v1(&client, 2u, &processed),
               MESH_CONTROL_OK);
  check_size_eq(processed, 2u);
  check_int_eq(mesh_node_ipc_client_peek_result_v1(
                   &client, result_operation_id, &result),
               MESH_CONTROL_OK);
  check_mem_eq(result_operation_id, operation_id, sizeof(operation_id));
  check_uint_eq(result.outcome, MESH_NODE_IPC_OUTCOME_SUCCEEDED_V1);
  check_uint_eq(result.applied_epoch, 7u);

  filler_size = make_command_frame(filler, sizeof(filler));
  for (filler_index = 0u; filler_index < 4u; ++filler_index)
    check_int_eq(mesh_node_ipc_channel_try_push_v1(
                     &to_owner, filler, filler_size),
                 MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_client_ack_result_v1(&client, operation_id),
               MESH_CONTROL_RESOURCE_EXHAUSTED);
  check_int_eq(mesh_node_ipc_client_peek_result_v1(
                   &client, result_operation_id, &result),
               MESH_CONTROL_OK);
  for (filler_index = 0u; filler_index < 4u; ++filler_index)
    check_int_eq(mesh_node_ipc_channel_consume_v1(&to_owner),
                 MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_client_ack_result_v1(&client, operation_id),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_client_peek_result_v1(
                   &client, result_operation_id, &result),
               MESH_CONTROL_EMPTY);
  check_int_eq(mesh_node_ipc_owner_poll_v1(&owner, 1u, &processed),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_client_get_stats_v1(&client, &client_stats),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_owner_get_stats_v1(&owner, &owner_stats),
               MESH_CONTROL_OK);
  check_size_eq(client_stats.retained_operations, 0u);
  check_uint_eq(client_stats.commands_submitted, 1u);
  check_uint_eq(client_stats.accepted_received, 1u);
  check_uint_eq(client_stats.results_received, 1u);
  check_uint_eq(client_stats.results_acked, 1u);
  check_size_eq(owner_stats.retained_operations, 0u);
  check_uint_eq(owner_stats.results_acked, 1u);
  check_int_eq(mesh_node_ipc_client_begin_drain_v1(&client),
               MESH_CONTROL_OK);
  check_true(mesh_node_ipc_client_is_drained_v1(&client));

  mesh_node_ipc_client_destroy_v1(&client);
  mesh_node_ipc_owner_destroy_v1(&owner);
  mesh_node_ipc_channel_destroy_v1(&to_client);
  mesh_node_ipc_channel_destroy_v1(&to_owner);
}

spec("MeshNodeIPC canonical local control protocol") {
  describe("typed codec") {
    it("round trips Mesh-scoped Network commands") {
      test_command_and_envelope_round_trip();
    }
    it("rejects tampering, truncation and invalid body digests") {
      test_tampering_and_shape_fail_closed();
    }
    it("enforces operation and epoch rules by message kind") {
      test_envelope_identity_and_scope_rules();
    }
    it("round trips terminal results and rejects inconsistent outcomes") {
      test_result_round_trip_and_invariants();
    }
  }
  describe("bounded FlowMQ callback bridge") {
    it("copies borrowed frames, bounds entries and drains after close") {
      test_channel_copies_bounds_and_drains();
    }
    it("rejects invalid frames and retained-byte exhaustion") {
      test_channel_rejects_invalid_and_byte_exhaustion();
    }
  }
  describe("single-owner command execution") {
    it("executes once, replays retained results and releases exact ACKs") {
      test_owner_executes_once_and_releases_exact_ack();
    }
    it("rejects cross-Mesh commands and operation-ID collisions") {
      test_owner_rejects_cross_mesh_and_operation_collision();
    }
    it("rejects capacity before ACCEPTED without blocking later ACKs") {
      test_owner_capacity_rejection_does_not_block_ack();
    }
  }
  describe("single-owner command client") {
    it("retains terminal results until exact ACK admission") {
      test_client_submits_retains_and_acks_terminal_result();
    }
  }
}
