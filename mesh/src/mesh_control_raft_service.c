#include "mesh_control_raft_service.h"

#include <turboraft/raft_sqlite_storage.h>
#include <turbo_error.h>

#include <stdlib.h>
#include <string.h>

struct mesh_control_raft_service_s {
  mesh_flow_ruleset_v1_t active_flow;
  mesh_flow_ruleset_raft_store_v1_t flow_store;
  mesh_task_lease_store_v1_t task_store;
  mesh_control_raft_v1_t *control;
  tr_raft_sqlite_storage_t *storage;
  tr_raft_service_t *service;
  uint8_t open;
};

static int config_valid(const mesh_control_raft_service_config_v1_t *config) {
  return config && config->sqlite_path && config->sqlite_path[0] != '\0' &&
         config->sqlite_busy_timeout_ms >= 0 &&
         config->max_snapshot_bytes != 0u &&
         config->max_snapshot_bytes <= TR_RAFT_SQLITE_MAX_SNAPSHOT_BYTES &&
         config->flow_rule_capacity != 0u &&
         config->flow_rule_capacity <= MESH_FLOW_RULESET_MAX_RULES &&
         config->task_capacity != 0u &&
         config->task_capacity <= MESH_TASK_LEASE_MAX_TASKS &&
         config->max_lease_duration_ms != 0u &&
         config->core.self_id != 0u && config->core.voters &&
         config->core.voter_count != 0u && config->transport.enqueue;
}

static void close_members(mesh_control_raft_service_v1_t *runtime) {
  if (runtime->service) {
    tr_raft_service_destroy(runtime->service);
  }
  if (runtime->storage) {
    (void)tr_raft_sqlite_storage_close(runtime->storage);
  }
  mesh_control_raft_destroy_v1(runtime->control);
  mesh_task_lease_store_destroy_v1(&runtime->task_store);
  mesh_flow_ruleset_raft_store_destroy_v1(&runtime->flow_store);
  mesh_flow_ruleset_destroy_v1(&runtime->active_flow);
}

int mesh_control_raft_service_open_v1(
    const mesh_control_raft_service_config_v1_t *config,
    mesh_control_raft_service_v1_t **out_runtime) {
  mesh_control_raft_service_v1_t *runtime;
  tr_raft_sqlite_storage_config_t storage_config;
  tr_raft_sqlite_recovery_t recovery;
  tr_raft_storage_t storage_adapter;
  tr_raft_service_config_t service_config;
  int result;

  if (!out_runtime) {
    return TURBO_EINVAL;
  }
  *out_runtime = NULL;
  if (!config_valid(config)) {
    return TURBO_EINVAL;
  }
  runtime = (mesh_control_raft_service_v1_t *)calloc(1u, sizeof(*runtime));
  if (!runtime) {
    return TURBO_ENOMEM;
  }
  result = mesh_flow_ruleset_init_v1(
      &runtime->active_flow, config->flow_rule_capacity,
      config->initial_flow_default_action);
  if (result != MESH_FLOW_RULESET_OK) {
    free(runtime);
    return result == MESH_FLOW_RULESET_RESOURCE_EXHAUSTED ? TURBO_ENOMEM
                                                          : TURBO_EINVAL;
  }
  if (mesh_flow_ruleset_raft_store_init_v1(&runtime->flow_store,
                                            &runtime->active_flow) !=
          MESH_FLOW_RULESET_OK ||
      mesh_task_lease_store_init_v1(
          &runtime->task_store, config->task_capacity,
          config->max_lease_duration_ms) != MESH_TASK_LEASE_OK) {
    close_members(runtime);
    free(runtime);
    return TURBO_ENOMEM;
  }
  result = mesh_control_raft_create_v1(&runtime->flow_store,
                                       &runtime->task_store,
                                       &runtime->control);
  if (result != TURBO_OK) {
    close_members(runtime);
    free(runtime);
    return result;
  }

  memset(&storage_config, 0, sizeof(storage_config));
  storage_config.path = config->sqlite_path;
  storage_config.busy_timeout_ms = config->sqlite_busy_timeout_ms;
  storage_config.create_if_missing = config->create_if_missing;
  storage_config.max_snapshot_bytes = config->max_snapshot_bytes;
  result = tr_raft_sqlite_storage_open(&storage_config, &runtime->storage);
  if (result != TURBO_OK) {
    close_members(runtime);
    free(runtime);
    return result;
  }
  memset(&storage_adapter, 0, sizeof(storage_adapter));
  result = tr_raft_sqlite_storage_bind(runtime->storage, &storage_adapter);
  if (result != TURBO_OK) {
    close_members(runtime);
    free(runtime);
    return result;
  }
  memset(&recovery, 0, sizeof(recovery));
  result = tr_raft_sqlite_storage_load(runtime->storage, &recovery);
  if (result != TURBO_OK) {
    close_members(runtime);
    free(runtime);
    return result;
  }
  if (recovery.snapshot_index != 0u || recovery.snapshot_term != 0u ||
      recovery.snapshot_size != 0u || recovery.has_snapshot_configuration) {
    tr_raft_sqlite_recovery_destroy(&recovery);
    close_members(runtime);
    free(runtime);
    return TURBO_EPROTO;
  }

  memset(&service_config, 0, sizeof(service_config));
  service_config.core = config->core;
  service_config.core.initial_term = recovery.term;
  service_config.core.initial_vote = recovery.voted_for;
  service_config.core.initial_last_log_index = recovery.snapshot_index;
  service_config.core.initial_last_log_term = recovery.snapshot_term;
  service_config.core.initial_log_entries = recovery.entries;
  service_config.core.initial_log_entry_count = recovery.entry_count;
  service_config.core.initial_commit_index = recovery.commit_index;
  service_config.core.initial_applied_index = recovery.snapshot_index;
  service_config.storage = storage_adapter;
  service_config.transport = config->transport;
  service_config.state_machine =
      mesh_control_raft_state_machine_v1(runtime->control);
  result = tr_raft_service_create(&service_config, &runtime->service);
  tr_raft_sqlite_recovery_destroy(&recovery);
  if (result != TURBO_OK) {
    close_members(runtime);
    free(runtime);
    return result;
  }
  result = mesh_control_raft_bind_service_v1(runtime->control,
                                             runtime->service);
  if (result == TURBO_OK) {
    result = tr_raft_service_poll(runtime->service);
  }
  if (result != TURBO_OK) {
    close_members(runtime);
    free(runtime);
    return result;
  }
  runtime->open = 1u;
  *out_runtime = runtime;
  return TURBO_OK;
}

void mesh_control_raft_service_close_v1(
    mesh_control_raft_service_v1_t *runtime) {
  if (!runtime) {
    return;
  }
  close_members(runtime);
  memset(runtime, 0, sizeof(*runtime));
  free(runtime);
}

int mesh_control_raft_service_tick_v1(mesh_control_raft_service_v1_t *runtime,
                                      const tr_raft_tick_t *tick) {
  if (!runtime || !runtime->open || !tick) {
    return TURBO_EINVAL;
  }
  return tr_raft_service_tick(runtime->service, tick);
}

int mesh_control_raft_service_step_v1(
    mesh_control_raft_service_v1_t *runtime,
    const tr_raft_message_t *message) {
  if (!runtime || !runtime->open || !message) {
    return TURBO_EINVAL;
  }
  return tr_raft_service_step(runtime->service, message);
}

int mesh_control_raft_service_poll_v1(
    mesh_control_raft_service_v1_t *runtime, size_t *out_read_completed,
    uint8_t *out_flow_published) {
  int result;
  if (!runtime || !runtime->open || !out_read_completed ||
      !out_flow_published) {
    return TURBO_EINVAL;
  }
  result = tr_raft_service_poll(runtime->service);
  if (result == TURBO_OK) {
    result = mesh_control_raft_poll_reads_v1(runtime->control,
                                             out_read_completed);
  }
  if (result == TURBO_OK) {
    result = mesh_control_raft_poll_v1(runtime->control,
                                       out_flow_published);
  }
  return result;
}

tr_raft_service_t *mesh_control_raft_service_borrow_v1(
    mesh_control_raft_service_v1_t *runtime) {
  return runtime && runtime->open ? runtime->service : NULL;
}

mesh_control_raft_v1_t *mesh_control_raft_service_control_v1(
    mesh_control_raft_service_v1_t *runtime) {
  return runtime && runtime->open ? runtime->control : NULL;
}

const mesh_task_lease_store_v1_t *mesh_control_raft_service_tasks_v1(
    const mesh_control_raft_service_v1_t *runtime) {
  return runtime && runtime->open ? &runtime->task_store : NULL;
}
