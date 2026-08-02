#ifndef MESH_CONTROL_RAFT_SERVICE_H
#define MESH_CONTROL_RAFT_SERVICE_H

#include "mesh_control_raft.h"

#include <turboraft/raft_service.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mesh_control_raft_service_s mesh_control_raft_service_v1_t;

typedef struct {
  const char *sqlite_path;
  int sqlite_busy_timeout_ms;
  bool create_if_missing;
  size_t max_snapshot_bytes;
  size_t flow_rule_capacity;
  size_t task_capacity;
  uint64_t max_lease_duration_ms;
  mesh_flow_action_v1_t initial_flow_default_action;
  tr_raft_core_config_t core;
  tr_raft_transport_t transport;
} mesh_control_raft_service_config_v1_t;

int mesh_control_raft_service_open_v1(
    const mesh_control_raft_service_config_v1_t *config,
    mesh_control_raft_service_v1_t **out_runtime);

void mesh_control_raft_service_close_v1(
    mesh_control_raft_service_v1_t *runtime);

int mesh_control_raft_service_tick_v1(mesh_control_raft_service_v1_t *runtime,
                                      const tr_raft_tick_t *tick);

int mesh_control_raft_service_step_v1(
    mesh_control_raft_service_v1_t *runtime,
    const tr_raft_message_t *message);

int mesh_control_raft_service_poll_v1(
    mesh_control_raft_service_v1_t *runtime, size_t *out_read_completed,
    uint8_t *out_flow_published);

tr_raft_service_t *mesh_control_raft_service_borrow_v1(
    mesh_control_raft_service_v1_t *runtime);

mesh_control_raft_v1_t *mesh_control_raft_service_control_v1(
    mesh_control_raft_service_v1_t *runtime);

const mesh_task_lease_store_v1_t *mesh_control_raft_service_tasks_v1(
    const mesh_control_raft_service_v1_t *runtime);

#ifdef __cplusplus
}
#endif

#endif
