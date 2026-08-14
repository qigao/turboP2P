#include "mesh_control_owner.h"
#include "tinytest.h"

#include <string.h>

static void make_config(mesh_control_owner_config_v1_t *config) {
  memset(config, 0, sizeof(*config));
  config->state.resource_capacity = 2u;
  config->state.operation_capacity = 2u;
  config->state.event_capacity = 4u;
  config->state.terminal_retention_ms = 500u;
  config->state.desired_document_max_bytes = 1024u;
  config->state.desired_document_retained_bytes = 2048u;
  config->replay.capacity = 4u;
  config->replay.ttl_ms = 1000u;
  config->mesh_id[0] = 1u;
  config->node_id[0] = 2u;
  config->replay_binding.principal_key[0] = 3u;
  config->replay_binding.principal_epoch = 4u;
  config->replay_binding.incarnation = 5u;
  config->replay_binding.session_id[0] = 6u;
}

static size_t make_message(mesh_control_envelope_v1_t *envelope, uint8_t message_identity,
                           uint64_t sequence, uint8_t output[64]) {
  static const uint8_t document[] = {0xaau, 0xbbu};
  size_t output_size = 0u;

  memset(envelope, 0, sizeof(*envelope));
  check_int_eq(mesh_control_intent_encode_v1(MESH_CONTROL_DESIRED_APPLY, document, sizeof(document),
                                             output, 64u, &output_size),
               MESH_CONTROL_OK);
  envelope->schema_version = MESH_CONTROL_SCHEMA_V1;
  envelope->kind = MESH_CONTROL_MESSAGE_INTENT;
  envelope->message_id[0] = message_identity;
  envelope->request_id[0] = 9u;
  envelope->mesh_id[0] = 1u;
  envelope->origin_principal[0] = 3u;
  envelope->origin_node_id[0] = 7u;
  envelope->session_id[0] = 6u;
  envelope->target_node_id[0] = 2u;
  envelope->resource_kind = MESH_CONTROL_RESOURCE_NETWORK;
  envelope->resource_id[0] = 8u;
  envelope->epoch = 1u;
  envelope->sequence = sequence;
  envelope->issued_at_ms = 1000u;
  envelope->expires_at_ms = 2000u;
  envelope->principal_epoch = 4u;
  envelope->incarnation = 5u;
  envelope->certificate_serial = 6u;
  envelope->payload_size = output_size;
  check_int_eq(mesh_control_mmp_body_digest_v1(output, output_size, envelope->payload_digest),
               MESH_CONTROL_MMP_OK);
  return output_size;
}

static void test_owner_commits_replay_after_desired_state(void) {
  mesh_control_channel_v1_t channel;
  mesh_control_owner_v1_t owner = {0};
  mesh_control_owner_config_v1_t config;
  mesh_control_envelope_v1_t envelope;
  mesh_control_operation_v1_t first_operation;
  mesh_control_operation_v1_t retried_operation;
  mesh_control_owner_stats_v1_t stats;
  uint8_t body[64];
  size_t body_size;

  make_config(&config);
  check_int_eq(mesh_control_channel_init_v1(&channel, 4u, 4096u, 1024u), MESH_CONTROL_OK);
  check_int_eq(mesh_control_owner_init_v1(&owner, &channel, &config), MESH_CONTROL_OK);
  body_size = make_message(&envelope, 10u, 1u, body);
  check_int_eq(mesh_control_channel_try_push_v1(&channel, &envelope, body, body_size),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_owner_process_next_v1(&owner, 1100u, &first_operation),
               MESH_CONTROL_OK);
  check_int_eq(first_operation.state, MESH_CONTROL_OPERATION_ACCEPTED);

  check_int_eq(mesh_control_channel_try_push_v1(&channel, &envelope, body, body_size),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_owner_process_next_v1(&owner, 1101u, NULL), MESH_CONTROL_CONFLICT);

  body_size = make_message(&envelope, 11u, 2u, body);
  check_int_eq(mesh_control_channel_try_push_v1(&channel, &envelope, body, body_size),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_owner_process_next_v1(&owner, 1102u, &retried_operation),
               MESH_CONTROL_OK);
  check_mem_eq(retried_operation.operation_id, first_operation.operation_id,
               sizeof(first_operation.operation_id));
  check_int_eq(mesh_control_owner_get_stats_v1(&owner, &stats), MESH_CONTROL_OK);
  check_int_eq(stats.processed, 2u);
  check_int_eq(stats.rejected_replay, 1u);

  mesh_control_owner_destroy_v1(&owner);
  mesh_control_channel_destroy_v1(&channel);
}

static void test_owner_rejects_binding_and_schema_before_replay_commit(void) {
  mesh_control_channel_v1_t channel;
  mesh_control_owner_v1_t owner = {0};
  mesh_control_owner_config_v1_t config;
  mesh_control_envelope_v1_t envelope;
  mesh_control_owner_stats_v1_t stats;
  uint8_t body[64];
  size_t body_size;

  make_config(&config);
  check_int_eq(mesh_control_channel_init_v1(&channel, 4u, 4096u, 1024u), MESH_CONTROL_OK);
  check_int_eq(mesh_control_owner_init_v1(&owner, &channel, &config), MESH_CONTROL_OK);
  body_size = make_message(&envelope, 20u, 1u, body);
  envelope.target_node_id[0] ^= 1u;
  check_int_eq(mesh_control_channel_try_push_v1(&channel, &envelope, body, body_size),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_owner_process_next_v1(&owner, 1100u, NULL), MESH_CONTROL_CONFLICT);

  body_size = make_message(&envelope, 21u, 1u, body);
  body[0] = 'X';
  check_int_eq(mesh_control_mmp_body_digest_v1(body, body_size, envelope.payload_digest),
               MESH_CONTROL_MMP_OK);
  check_int_eq(mesh_control_channel_try_push_v1(&channel, &envelope, body, body_size),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_owner_process_next_v1(&owner, 1101u, NULL), MESH_CONTROL_INVALID_ARG);

  body_size = make_message(&envelope, 22u, 1u, body);
  check_int_eq(mesh_control_channel_try_push_v1(&channel, &envelope, body, body_size),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_owner_process_next_v1(&owner, 1102u, NULL), MESH_CONTROL_OK);
  check_int_eq(mesh_control_owner_get_stats_v1(&owner, &stats), MESH_CONTROL_OK);
  check_int_eq(stats.rejected_binding, 1u);
  check_int_eq(stats.rejected_schema, 1u);
  check_int_eq(stats.processed, 1u);

  mesh_control_owner_destroy_v1(&owner);
  mesh_control_channel_destroy_v1(&channel);
}

static void test_owner_prepares_without_mutation_until_durable_commit(void) {
  mesh_control_channel_v1_t channel;
  mesh_control_channel_stats_v1_t channel_stats;
  mesh_control_owner_v1_t owner = {0};
  mesh_control_owner_config_v1_t config;
  mesh_control_owner_prepared_v1_t prepared;
  mesh_control_envelope_v1_t envelope;
  mesh_control_operation_v1_t operation;
  mesh_control_resource_status_v1_t status;
  uint8_t body[64];
  uint8_t signed_frame[] = {1u, 2u, 3u};
  size_t body_size;

  make_config(&config);
  check_int_eq(mesh_control_channel_init_v1(&channel, 4u, 4096u, 1024u), MESH_CONTROL_OK);
  check_int_eq(mesh_control_owner_init_v1(&owner, &channel, &config), MESH_CONTROL_OK);
  body_size = make_message(&envelope, 30u, 1u, body);
  check_int_eq(mesh_control_channel_try_push_signed_v1(&channel, &envelope, body, body_size,
                                                       signed_frame, sizeof(signed_frame)),
               MESH_CONTROL_OK);

  check_int_eq(mesh_control_owner_prepare_next_v1(&owner, 1100u, &prepared), MESH_CONTROL_OK);
  check_uint_eq(prepared.expected_log_index, 1u);
  check_uint_eq(prepared.accepted_at_ms, 1100u);
  check_size_eq(prepared.signed_frame_size, sizeof(signed_frame));
  check_mem_eq(prepared.signed_frame, signed_frame, sizeof(signed_frame));
  check_int_eq(mesh_control_state_get_resource_v1(mesh_control_owner_state_v1(&owner),
                                                  envelope.resource_kind, envelope.resource_id,
                                                  &status),
               MESH_CONTROL_EMPTY);
  check_int_eq(mesh_control_channel_get_stats_v1(&channel, &channel_stats), MESH_CONTROL_OK);
  check_size_eq(channel_stats.pending, 1u);
  check_int_eq(mesh_control_owner_prepare_next_v1(&owner, 1100u, &prepared),
               MESH_CONTROL_INVALID_STATE);
  check_int_eq(mesh_control_owner_commit_prepared_v1(&owner, 2u, &operation),
               MESH_CONTROL_CONFLICT);
  check_int_eq(mesh_control_owner_commit_prepared_v1(&owner, 1u, &operation), MESH_CONTROL_OK);
  check_int_eq(operation.state, MESH_CONTROL_OPERATION_ACCEPTED);
  check_int_eq(mesh_control_channel_get_stats_v1(&channel, &channel_stats), MESH_CONTROL_OK);
  check_size_eq(channel_stats.pending, 0u);

  mesh_control_owner_destroy_v1(&owner);
  mesh_control_channel_destroy_v1(&channel);
}

spec("mesh control domain owner") {
  describe("replay-safe bounded command application") {
    it("commits replay only after desired state submission") {
      test_owner_commits_replay_after_desired_state();
    }
    it("rejects binding and schema without consuming replay sequence") {
      test_owner_rejects_binding_and_schema_before_replay_commit();
    }
    it("does not mutate desired state before the durable commit gate") {
      test_owner_prepares_without_mutation_until_durable_commit();
    }
  }
}
