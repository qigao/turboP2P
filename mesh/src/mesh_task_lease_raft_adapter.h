#ifndef MESH_TASK_LEASE_RAFT_ADAPTER_H
#define MESH_TASK_LEASE_RAFT_ADAPTER_H

#include "mesh_task_lease_raft.h"

#include <turboraft/raft_service.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mesh_task_lease_raft_adapter_s
    mesh_task_lease_raft_adapter_v1_t;

/* The store is borrowed and must remain open until adapter destruction. */
int mesh_task_lease_raft_adapter_create_v1(
    mesh_task_lease_store_v1_t *store,
    mesh_task_lease_raft_adapter_v1_t **out_adapter);

void mesh_task_lease_raft_adapter_destroy_v1(
    mesh_task_lease_raft_adapter_v1_t *adapter);

tr_raft_state_machine_t mesh_task_lease_raft_state_machine_v1(
    mesh_task_lease_raft_adapter_v1_t *adapter);

int mesh_task_lease_raft_adapter_bind_service_v1(
    mesh_task_lease_raft_adapter_v1_t *adapter, tr_raft_service_t *service);

/* Receipt confirms Raft admission/index assignment, not committed execution. */
int mesh_task_lease_raft_propose_v1(
    mesh_task_lease_raft_adapter_v1_t *adapter, uint64_t command_id,
    const mesh_task_lease_raft_command_v1_t *command,
    tr_raft_operation_status_t *out_receipt);

#ifdef __cplusplus
}
#endif

#endif
