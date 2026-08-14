#include "mesh_control_owner.h"

#include <string.h>

static int bytes_zero(const uint8_t *bytes, size_t size) {
  uint8_t aggregate = 0u;
  size_t index;
  for (index = 0u; index < size; ++index)
    aggregate |= bytes[index];
  return aggregate == 0u;
}

mesh_control_result_t mesh_control_owner_init_v1(mesh_control_owner_v1_t *owner,
                                                 mesh_control_channel_v1_t *inbound,
                                                 const mesh_control_owner_config_v1_t *config) {
  mesh_control_channel_stats_v1_t channel_stats;

  if (owner == NULL || inbound == NULL || config == NULL || owner->initialized != 0u ||
      bytes_zero(config->mesh_id, sizeof(config->mesh_id)) ||
      bytes_zero(config->node_id, sizeof(config->node_id)) ||
      mesh_control_channel_get_stats_v1(inbound, &channel_stats) != MESH_CONTROL_OK) {
    return MESH_CONTROL_INVALID_ARG;
  }
  memset(owner, 0, sizeof(*owner));
  if (mesh_control_state_init_v1(&owner->state, &config->state) != MESH_CONTROL_OK) {
    return MESH_CONTROL_INVALID_ARG;
  }
  if (mesh_mgmt_replay_init_v1(&owner->replay, &config->replay) != MESH_MGMT_REPLAY_OK ||
      mesh_mgmt_replay_bind_v1(&owner->replay, &config->replay_binding) != MESH_MGMT_REPLAY_OK) {
    mesh_control_state_destroy_v1(&owner->state);
    mesh_mgmt_replay_destroy_v1(&owner->replay);
    return MESH_CONTROL_INVALID_ARG;
  }
  owner->inbound = inbound;
  owner->config = *config;
  owner->initialized = 1u;
  return MESH_CONTROL_OK;
}

static int message_binding_valid(const mesh_control_owner_v1_t *owner,
                                 const mesh_control_envelope_v1_t *envelope, uint64_t now_ms) {
  return memcmp(owner->config.mesh_id, envelope->mesh_id, sizeof(owner->config.mesh_id)) == 0 &&
         memcmp(owner->config.node_id, envelope->target_node_id, sizeof(owner->config.node_id)) ==
             0 &&
         memcmp(owner->config.replay_binding.principal_key, envelope->origin_principal,
                sizeof(owner->config.replay_binding.principal_key)) == 0 &&
         owner->config.replay_binding.principal_epoch == envelope->principal_epoch &&
         owner->config.replay_binding.incarnation == envelope->incarnation &&
         memcmp(owner->config.replay_binding.session_id, envelope->session_id,
                sizeof(owner->config.replay_binding.session_id)) == 0 &&
         now_ms >= envelope->issued_at_ms && now_ms < envelope->expires_at_ms;
}

static void make_replay_header(const mesh_control_envelope_v1_t *envelope,
                               mesh_mgmt_header_v1_t *header) {
  memset(header, 0, sizeof(*header));
  memcpy(header->origin_principal_key, envelope->origin_principal,
         sizeof(header->origin_principal_key));
  header->principal_epoch = envelope->principal_epoch;
  header->incarnation = envelope->incarnation;
  memcpy(header->session_id, envelope->session_id, sizeof(header->session_id));
  header->origin_sequence = envelope->sequence;
  memcpy(header->message_id, envelope->message_id, sizeof(header->message_id));
  header->issued_at_ms = envelope->issued_at_ms;
  header->expires_at_ms = envelope->expires_at_ms;
}

mesh_control_result_t
mesh_control_owner_process_next_v1(mesh_control_owner_v1_t *owner, uint64_t now_ms,
                                   mesh_control_operation_v1_t *out_operation) {
  mesh_control_owner_prepared_v1_t prepared;
  mesh_control_result_t result;

  result = mesh_control_owner_prepare_next_v1(owner, now_ms, &prepared);
  if (result != MESH_CONTROL_OK)
    return result;
  return mesh_control_owner_commit_prepared_v1(owner, prepared.expected_log_index, out_operation);
}

static mesh_control_result_t consume_rejected(mesh_control_owner_v1_t *owner,
                                              mesh_control_result_t result) {
  if (mesh_control_channel_consume_v1(owner->inbound) != MESH_CONTROL_OK)
    return MESH_CONTROL_INVALID_STATE;
  return result;
}

mesh_control_result_t
mesh_control_owner_prepare_next_v1(mesh_control_owner_v1_t *owner, uint64_t now_ms,
                                   mesh_control_owner_prepared_v1_t *out_prepared) {
  mesh_control_message_view_v1_t message;
  mesh_control_intent_view_v1_t intent;
  mesh_mgmt_header_v1_t replay_header;
  mesh_mgmt_replay_preparation_v1_t preparation;
  mesh_control_result_t result;

  if (!owner || !out_prepared || !owner->initialized)
    return MESH_CONTROL_INVALID_ARG;
  memset(out_prepared, 0, sizeof(*out_prepared));
  if (owner->preparation_active)
    return MESH_CONTROL_INVALID_STATE;
  result = mesh_control_channel_peek_v1(owner->inbound, &message);
  if (result != MESH_CONTROL_OK)
    return result;

  if (!message_binding_valid(owner, &message.envelope, now_ms)) {
    ++owner->stats.rejected_binding;
    return consume_rejected(owner, MESH_CONTROL_CONFLICT);
  }
  make_replay_header(&message.envelope, &replay_header);
  if (mesh_mgmt_replay_prepare_v1(&owner->replay, &replay_header, now_ms, &preparation) !=
      MESH_MGMT_REPLAY_OK) {
    ++owner->stats.rejected_replay;
    return consume_rejected(owner, MESH_CONTROL_CONFLICT);
  }
  if (message.envelope.kind != MESH_CONTROL_MESSAGE_INTENT ||
      mesh_control_intent_decode_v1(message.payload, message.payload_size, &intent) !=
          MESH_CONTROL_OK) {
    ++owner->stats.rejected_schema;
    return consume_rejected(owner, MESH_CONTROL_INVALID_ARG);
  }
  (void)mesh_control_state_sweep_v1(&owner->state, now_ms);
  result = mesh_control_state_validate_document_v1(&owner->state, &message.envelope, intent.action,
                                                   intent.document, intent.document_size, now_ms);
  if (result != MESH_CONTROL_OK) {
    ++owner->stats.rejected_state;
    return consume_rejected(owner, result);
  }
  if (owner->committed_log_index == UINT64_MAX)
    return consume_rejected(owner, MESH_CONTROL_INVALID_STATE);

  owner->pending_replay = preparation;
  memset(&owner->pending, 0, sizeof(owner->pending));
  owner->pending.envelope = message.envelope;
  owner->pending.action = intent.action;
  owner->pending.document = intent.document;
  owner->pending.document_size = intent.document_size;
  owner->pending.signed_frame = message.signed_frame;
  owner->pending.signed_frame_size = message.signed_frame_size;
  owner->pending.accepted_at_ms = now_ms;
  owner->pending.expected_log_index = owner->committed_log_index + 1u;
  owner->preparation_active = 1u;
  *out_prepared = owner->pending;
  return MESH_CONTROL_OK;
}

mesh_control_result_t
mesh_control_owner_commit_prepared_v1(mesh_control_owner_v1_t *owner, uint64_t durable_log_index,
                                      mesh_control_operation_v1_t *out_operation) {
  mesh_control_operation_v1_t operation;
  mesh_control_result_t result;

  if (!owner || !owner->initialized)
    return MESH_CONTROL_INVALID_ARG;
  if (out_operation)
    memset(out_operation, 0, sizeof(*out_operation));
  if (!owner->preparation_active || durable_log_index != owner->pending.expected_log_index) {
    return MESH_CONTROL_CONFLICT;
  }
  result = mesh_control_state_submit_document_v1(
      &owner->state, &owner->pending.envelope, owner->pending.action, owner->pending.document,
      owner->pending.document_size, owner->pending.accepted_at_ms, &operation);
  if (result != MESH_CONTROL_OK)
    return result;
  /* No owner mutation is allowed while a preparation is active, therefore
   * this replay token cannot become stale after state preflight. */
  if (mesh_mgmt_replay_commit_v1(&owner->replay, &owner->pending_replay) != MESH_MGMT_REPLAY_OK) {
    ++owner->stats.rejected_state;
    return MESH_CONTROL_INVALID_STATE;
  }
  if (mesh_control_channel_consume_v1(owner->inbound) != MESH_CONTROL_OK)
    return MESH_CONTROL_INVALID_STATE;
  owner->committed_log_index = durable_log_index;
  memset(&owner->pending_replay, 0, sizeof(owner->pending_replay));
  memset(&owner->pending, 0, sizeof(owner->pending));
  owner->preparation_active = 0u;
  ++owner->stats.processed;
  if (out_operation)
    *out_operation = operation;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_owner_advance_log_index_v1(mesh_control_owner_v1_t *owner,
                                                              uint64_t durable_log_index) {
  if (!owner || !owner->initialized || owner->preparation_active)
    return MESH_CONTROL_INVALID_ARG;
  if (owner->committed_log_index == UINT64_MAX ||
      durable_log_index != owner->committed_log_index + 1u) {
    return MESH_CONTROL_CONFLICT;
  }
  owner->committed_log_index = durable_log_index;
  return MESH_CONTROL_OK;
}

mesh_control_state_v1_t *mesh_control_owner_state_v1(mesh_control_owner_v1_t *owner) {
  return owner != NULL && owner->initialized != 0u ? &owner->state : NULL;
}

mesh_control_result_t mesh_control_owner_get_stats_v1(const mesh_control_owner_v1_t *owner,
                                                      mesh_control_owner_stats_v1_t *out_stats) {
  if (owner == NULL || owner->initialized == 0u || out_stats == NULL)
    return MESH_CONTROL_INVALID_ARG;
  *out_stats = owner->stats;
  return MESH_CONTROL_OK;
}

void mesh_control_owner_destroy_v1(mesh_control_owner_v1_t *owner) {
  if (owner == NULL)
    return;
  if (owner->initialized != 0u) {
    mesh_mgmt_replay_destroy_v1(&owner->replay);
    mesh_control_state_destroy_v1(&owner->state);
  }
  memset(owner, 0, sizeof(*owner));
}
