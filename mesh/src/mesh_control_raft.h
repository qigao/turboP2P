#ifndef MESH_CONTROL_RAFT_H
#define MESH_CONTROL_RAFT_H

#include "mesh_flow_ruleset_raft_adapter.h"
#include "mesh_task_lease_raft_adapter.h"

#include <turboraft/raft_service.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mesh_control_raft_s mesh_control_raft_v1_t;

#define MESH_CONTROL_RAFT_MAX_PENDING_READS 64u

typedef void (*mesh_control_raft_read_complete_v1_fn)(
    int result, uint64_t safe_index, uint64_t local_applied_index,
    void *user_data);

/* Both stores are borrowed and share one ordered TurboRaft control group. */
int mesh_control_raft_create_v1(
    mesh_flow_ruleset_raft_store_v1_t *flow_store,
    mesh_task_lease_store_v1_t *task_store,
    mesh_control_raft_v1_t **out_control);

void mesh_control_raft_destroy_v1(mesh_control_raft_v1_t *control);

tr_raft_state_machine_t mesh_control_raft_state_machine_v1(
    mesh_control_raft_v1_t *control);

int mesh_control_raft_bind_service_v1(mesh_control_raft_v1_t *control,
                                      tr_raft_service_t *service);

int mesh_control_raft_set_flow_publisher_v1(
    mesh_control_raft_v1_t *control,
    mesh_flow_ruleset_raft_require_v1_fn require,
    mesh_flow_ruleset_raft_publish_v1_fn publish, void *publisher_context);

int mesh_control_raft_poll_v1(mesh_control_raft_v1_t *control,
                              uint8_t *out_flow_published);

int mesh_control_raft_applied_index_v1(const mesh_control_raft_v1_t *control,
                                       uint64_t *out_applied_index);

int mesh_control_raft_read_index_v1(
    mesh_control_raft_v1_t *control,
    mesh_control_raft_read_complete_v1_fn complete, void *user_data,
    uint64_t *out_context_id);

/* This control owner must exclusively consume its service's read states. */
int mesh_control_raft_poll_reads_v1(mesh_control_raft_v1_t *control,
                                    size_t *out_completed);

int mesh_control_raft_propose_flow_snapshot_v1(
    mesh_control_raft_v1_t *control, uint64_t first_command_id,
    uint64_t policy_epoch, mesh_flow_action_v1_t default_action,
    const mesh_flow_rule_v1_t *rules, size_t rule_count,
    tr_raft_operation_status_t *receipts, size_t receipt_capacity,
    size_t *out_submitted);

int mesh_control_raft_propose_task_v1(
    mesh_control_raft_v1_t *control, uint64_t command_id,
    const mesh_task_lease_raft_command_v1_t *command,
    tr_raft_operation_status_t *out_receipt);

#ifdef __cplusplus
}
#endif

#endif
