#ifndef MESH_CONTROL_OWNER_H
#define MESH_CONTROL_OWNER_H

#include "mesh_control_channel.h"
#include "mesh_control_document.h"
#include "mesh_control_mmp.h"
#include "mesh_control_state.h"
#include "mesh_mgmt_replay.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  mesh_control_state_config_v1_t state;
  mesh_mgmt_replay_config_v1_t replay;
  mesh_mgmt_replay_binding_v1_t replay_binding;
  uint8_t mesh_id[MESH_CONTROL_DIGEST_SIZE];
  uint8_t node_id[MESH_CONTROL_NODE_ID_SIZE];
} mesh_control_owner_config_v1_t;

typedef struct {
  uint64_t processed;
  uint64_t rejected_binding;
  uint64_t rejected_replay;
  uint64_t rejected_schema;
  uint64_t rejected_state;
} mesh_control_owner_stats_v1_t;

typedef struct {
  mesh_control_envelope_v1_t envelope;
  mesh_control_desired_action_v1_t action;
  const uint8_t *document;
  size_t document_size;
  const uint8_t *signed_frame;
  size_t signed_frame_size;
  uint64_t accepted_at_ms;
  uint64_t expected_log_index;
} mesh_control_owner_prepared_v1_t;

/**
 * Single domain owner. Only the owner loop may call process/state APIs. The
 * Iris thread is restricted to publishing immutable messages to inbound.
 */
typedef struct {
  mesh_control_channel_v1_t *inbound;
  mesh_control_state_v1_t state;
  mesh_mgmt_replay_gate_v1_t replay;
  mesh_control_owner_config_v1_t config;
  mesh_control_owner_stats_v1_t stats;
  mesh_mgmt_replay_preparation_v1_t pending_replay;
  mesh_control_owner_prepared_v1_t pending;
  uint64_t committed_log_index;
  uint8_t preparation_active;
  uint8_t initialized;
} mesh_control_owner_v1_t;

mesh_control_result_t mesh_control_owner_init_v1(mesh_control_owner_v1_t *owner,
                                                 mesh_control_channel_v1_t *inbound,
                                                 const mesh_control_owner_config_v1_t *config);

/**
 * Processes and consumes one queue head. EMPTY means no work. Replay is
 * committed only after parsing, binding checks and desired-state submission
 * succeed, so backpressure/resource errors remain safely retryable.
 */
mesh_control_result_t
mesh_control_owner_process_next_v1(mesh_control_owner_v1_t *owner, uint64_t now_ms,
                                   mesh_control_operation_v1_t *out_operation);

/**
 * Validates but does not mutate desired state, replay state, or consume the
 * queue head. The returned views remain borrowed until commit or destroy.
 */
mesh_control_result_t
mesh_control_owner_prepare_next_v1(mesh_control_owner_v1_t *owner, uint64_t now_ms,
                                   mesh_control_owner_prepared_v1_t *out_prepared);

/**
 * Commits a previously prepared command only after its exact WAL index is
 * durable, then consumes the queue head. On a transient state allocation
 * failure the preparation remains active and is retryable.
 */
mesh_control_result_t
mesh_control_owner_commit_prepared_v1(mesh_control_owner_v1_t *owner, uint64_t durable_log_index,
                                      mesh_control_operation_v1_t *out_operation);

/** Advances the shared durable log after a non-intent owner-state mutation. */
mesh_control_result_t mesh_control_owner_advance_log_index_v1(mesh_control_owner_v1_t *owner,
                                                              uint64_t durable_log_index);

mesh_control_state_v1_t *mesh_control_owner_state_v1(mesh_control_owner_v1_t *owner);

mesh_control_result_t mesh_control_owner_get_stats_v1(const mesh_control_owner_v1_t *owner,
                                                      mesh_control_owner_stats_v1_t *out_stats);

/** Inbound producer and owner consumer must be quiescent. */
void mesh_control_owner_destroy_v1(mesh_control_owner_v1_t *owner);

#ifdef __cplusplus
}
#endif

#endif
