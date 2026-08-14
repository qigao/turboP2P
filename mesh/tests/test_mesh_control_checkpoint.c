#include "mesh_control_checkpoint.h"
#include "mesh_control_mmp.h"
#include "tinytest.h"

#include <string.h>

static void make_config(mesh_control_owner_config_v1_t *config, uint8_t node_identity) {
  memset(config, 0, sizeof(*config));
  config->state.resource_capacity = 2u;
  config->state.operation_capacity = 2u;
  config->state.event_capacity = 8u;
  config->state.terminal_retention_ms = 500u;
  config->state.desired_document_max_bytes = 1024u;
  config->state.desired_document_retained_bytes = 2048u;
  config->replay.capacity = 4u;
  config->replay.ttl_ms = 1000u;
  config->mesh_id[0] = 1u;
  config->node_id[0] = node_identity;
  config->replay_binding.principal_key[0] = 3u;
  config->replay_binding.principal_epoch = 4u;
  config->replay_binding.incarnation = 5u;
  config->replay_binding.session_id[0] = 6u;
}

static size_t make_message(mesh_control_envelope_v1_t *envelope, uint8_t output[64]) {
  static const uint8_t document[] = {0xaau, 0xbbu, 0xccu};
  size_t output_size = 0u;

  memset(envelope, 0, sizeof(*envelope));
  check_int_eq(mesh_control_intent_encode_v1(MESH_CONTROL_DESIRED_APPLY, document, sizeof(document),
                                             output, 64u, &output_size),
               MESH_CONTROL_OK);
  envelope->schema_version = MESH_CONTROL_SCHEMA_V1;
  envelope->kind = MESH_CONTROL_MESSAGE_INTENT;
  envelope->message_id[0] = 10u;
  envelope->request_id[0] = 9u;
  envelope->mesh_id[0] = 1u;
  envelope->origin_principal[0] = 3u;
  envelope->origin_node_id[0] = 7u;
  envelope->session_id[0] = 6u;
  envelope->target_node_id[0] = 2u;
  envelope->resource_kind = MESH_CONTROL_RESOURCE_NETWORK;
  envelope->resource_id[0] = 8u;
  envelope->epoch = 1u;
  envelope->sequence = 1u;
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

static void test_checkpoint_round_trip_binds_state_and_replay(void) {
  mesh_control_channel_v1_t source_channel;
  mesh_control_channel_v1_t restored_channel;
  mesh_control_owner_v1_t source = {0};
  mesh_control_owner_v1_t restored = {0};
  mesh_control_owner_config_v1_t config;
  mesh_control_envelope_v1_t envelope;
  mesh_control_operation_v1_t operation;
  mesh_control_operation_v1_t restored_operation;
  mesh_control_resource_status_v1_t status;
  mesh_control_state_usage_v1_t usage;
  const uint8_t *document = NULL;
  uint8_t *checkpoint = NULL;
  uint8_t body[64];
  size_t checkpoint_size = 0u;
  size_t document_size = 0u;
  size_t body_size;

  make_config(&config, 2u);
  check_int_eq(mesh_control_channel_init_v1(&source_channel, 4u, 4096u, 1024u), MESH_CONTROL_OK);
  check_int_eq(mesh_control_channel_init_v1(&restored_channel, 4u, 4096u, 1024u), MESH_CONTROL_OK);
  check_int_eq(mesh_control_owner_init_v1(&source, &source_channel, &config), MESH_CONTROL_OK);
  check_int_eq(mesh_control_owner_init_v1(&restored, &restored_channel, &config), MESH_CONTROL_OK);
  body_size = make_message(&envelope, body);
  check_int_eq(mesh_control_channel_try_push_v1(&source_channel, &envelope, body, body_size),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_owner_process_next_v1(&source, 1100u, &operation), MESH_CONTROL_OK);
  check_uint_eq(source.committed_log_index, 1u);
  check_int_eq(mesh_control_state_transition_operation_v1(&source.state, operation.operation_id,
                                                          MESH_CONTROL_OPERATION_RUNNING, 1110u),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_checkpoint_encode_v1(&source, &checkpoint, &checkpoint_size),
               MESH_CONTROL_CHECKPOINT_OK);
  check_true(checkpoint != NULL);
  check_true(checkpoint_size > 256u);

  check_int_eq(mesh_control_checkpoint_restore_v1(&restored, checkpoint, checkpoint_size, 1500u),
               MESH_CONTROL_CHECKPOINT_OK);
  check_uint_eq(restored.committed_log_index, 1u);
  mesh_control_checkpoint_free_v1(checkpoint);
  check_int_eq(mesh_control_state_get_usage_v1(&restored.state, &usage), MESH_CONTROL_OK);
  check_size_eq(usage.resource_count, 1u);
  check_size_eq(usage.operation_count, 1u);
  check_size_eq(usage.event_count, 2u);
  check_int_eq(mesh_control_state_get_resource_v1(&restored.state, envelope.resource_kind,
                                                  envelope.resource_id, &status),
               MESH_CONTROL_OK);
  check_int_eq(status.desired_epoch, 1u);
  check_int_eq(mesh_control_state_get_operation_v1(&restored.state, operation.operation_id,
                                                   &restored_operation),
               MESH_CONTROL_OK);
  check_int_eq(restored_operation.state, MESH_CONTROL_OPERATION_RUNNING);
  check_int_eq(mesh_control_state_get_desired_document_v1(&restored.state, envelope.resource_kind,
                                                          envelope.resource_id, &document,
                                                          &document_size),
               MESH_CONTROL_OK);
  check_size_eq(document_size, 3u);
  check_int_eq(document[0], 0xaau);
  check_int_eq(document[2], 0xccu);

  check_int_eq(mesh_control_channel_try_push_v1(&restored_channel, &envelope, body, body_size),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_owner_process_next_v1(&restored, 1600u, NULL), MESH_CONTROL_CONFLICT);

  mesh_control_owner_destroy_v1(&restored);
  mesh_control_owner_destroy_v1(&source);
  mesh_control_channel_destroy_v1(&restored_channel);
  mesh_control_channel_destroy_v1(&source_channel);
}

static void test_corruption_is_atomic_and_identity_is_bound(void) {
  mesh_control_channel_v1_t source_channel;
  mesh_control_channel_v1_t target_channel;
  mesh_control_owner_v1_t source = {0};
  mesh_control_owner_v1_t target = {0};
  mesh_control_owner_config_v1_t source_config;
  mesh_control_owner_config_v1_t target_config;
  mesh_control_envelope_v1_t envelope;
  mesh_control_state_usage_v1_t usage;
  uint8_t *checkpoint = NULL;
  uint8_t body[64];
  size_t checkpoint_size = 0u;
  size_t body_size;

  make_config(&source_config, 2u);
  make_config(&target_config, 3u);
  check_int_eq(mesh_control_channel_init_v1(&source_channel, 4u, 4096u, 1024u), MESH_CONTROL_OK);
  check_int_eq(mesh_control_channel_init_v1(&target_channel, 4u, 4096u, 1024u), MESH_CONTROL_OK);
  check_int_eq(mesh_control_owner_init_v1(&source, &source_channel, &source_config),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_owner_init_v1(&target, &target_channel, &target_config),
               MESH_CONTROL_OK);
  body_size = make_message(&envelope, body);
  check_int_eq(mesh_control_channel_try_push_v1(&source_channel, &envelope, body, body_size),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_owner_process_next_v1(&source, 1100u, NULL), MESH_CONTROL_OK);
  check_int_eq(mesh_control_checkpoint_encode_v1(&source, &checkpoint, &checkpoint_size),
               MESH_CONTROL_CHECKPOINT_OK);

  checkpoint[checkpoint_size - 1u] ^= 1u;
  check_int_eq(mesh_control_checkpoint_restore_v1(&target, checkpoint, checkpoint_size, 1500u),
               MESH_CONTROL_CHECKPOINT_CORRUPT);
  check_int_eq(mesh_control_state_get_usage_v1(&target.state, &usage), MESH_CONTROL_OK);
  check_size_eq(usage.resource_count, 0u);
  checkpoint[checkpoint_size - 1u] ^= 1u;
  check_int_eq(mesh_control_checkpoint_restore_v1(&target, checkpoint, checkpoint_size, 1500u),
               MESH_CONTROL_CHECKPOINT_BINDING_MISMATCH);
  check_int_eq(mesh_control_state_get_usage_v1(&target.state, &usage), MESH_CONTROL_OK);
  check_size_eq(usage.resource_count, 0u);

  mesh_control_checkpoint_free_v1(checkpoint);
  mesh_control_owner_destroy_v1(&target);
  mesh_control_owner_destroy_v1(&source);
  mesh_control_channel_destroy_v1(&target_channel);
  mesh_control_channel_destroy_v1(&source_channel);
}

spec("mesh control checkpoint") {
  describe("versioned owner fact-source recovery") {
    it("round trips desired state, operations, events and replay") {
      test_checkpoint_round_trip_binds_state_and_replay();
    }
    it("rejects corruption atomically and binds snapshots to a node") {
      test_corruption_is_atomic_and_identity_is_bound();
    }
  }
}
