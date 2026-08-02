#ifndef MESH_FLOW_RULESET_RAFT_ADAPTER_H
#define MESH_FLOW_RULESET_RAFT_ADAPTER_H

#include "mesh_flow_ruleset_raft.h"

#include <turboraft/raft_service.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_FLOW_RULESET_RAFT_MAX_TRANSACTION_ENTRIES 20u

typedef struct mesh_flow_ruleset_raft_adapter_s
    mesh_flow_ruleset_raft_adapter_v1_t;

typedef int (*mesh_flow_ruleset_raft_require_v1_fn)(void *context,
                                                     uint64_t required_index);
typedef int (*mesh_flow_ruleset_raft_publish_v1_fn)(
    void *context, const mesh_flow_ruleset_v1_t *committed_ruleset);

int mesh_flow_ruleset_raft_adapter_create_v1(
    mesh_flow_ruleset_raft_store_v1_t *store,
    mesh_flow_ruleset_raft_adapter_v1_t **out_adapter);

void mesh_flow_ruleset_raft_adapter_destroy_v1(
    mesh_flow_ruleset_raft_adapter_v1_t *adapter);

tr_raft_state_machine_t mesh_flow_ruleset_raft_state_machine_v1(
    mesh_flow_ruleset_raft_adapter_v1_t *adapter);

int mesh_flow_ruleset_raft_adapter_bind_service_v1(
    mesh_flow_ruleset_raft_adapter_v1_t *adapter, tr_raft_service_t *service);

int mesh_flow_ruleset_raft_adapter_set_publisher_v1(
    mesh_flow_ruleset_raft_adapter_v1_t *adapter,
    mesh_flow_ruleset_raft_require_v1_fn require,
    mesh_flow_ruleset_raft_publish_v1_fn publish, void *publisher_context);

int mesh_flow_ruleset_raft_adapter_poll_publish_v1(
    mesh_flow_ruleset_raft_adapter_v1_t *adapter, uint8_t *out_published);

/*
 * Receipts prove admission/index assignment only. A partial submission is not
 * resumed: callers must issue a higher policy_epoch snapshot from BEGIN.
 */
int mesh_flow_ruleset_raft_propose_snapshot_v1(
    mesh_flow_ruleset_raft_adapter_v1_t *adapter, uint64_t first_command_id,
    uint64_t policy_epoch, mesh_flow_action_v1_t default_action,
    const mesh_flow_rule_v1_t *rules, size_t rule_count,
    tr_raft_operation_status_t *receipts, size_t receipt_capacity,
    size_t *out_submitted);

#ifdef __cplusplus
}
#endif

#endif
