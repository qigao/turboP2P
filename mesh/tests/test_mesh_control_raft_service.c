#include "mesh_control_raft_service.h"
#include "tinytest.h"

#include <stdlib.h>
#include <string.h>
#include <turbo_error.h>

typedef struct {
  size_t calls;
  int result;
  uint64_t safe_index;
  uint64_t local_index;
} read_capture_t;

static int discard_message(void *context, const tr_raft_message_t *message) {
  (void)context;
  (void)message;
  return TURBO_OK;
}

static void capture_read(int result, uint64_t safe_index,
                         uint64_t local_applied_index, void *user_data) {
  read_capture_t *capture = (read_capture_t *)user_data;
  ++capture->calls;
  capture->result = result;
  capture->safe_index = safe_index;
  capture->local_index = local_applied_index;
}

static void init_single_node_config(
    mesh_control_raft_service_config_v1_t *config, const char *sqlite_path) {
  static const tr_raft_node_id_t voters[] = {1u};

  memset(config, 0, sizeof(*config));
  config->sqlite_path = sqlite_path;
  config->sqlite_busy_timeout_ms = 1000;
  config->create_if_missing = true;
  config->max_snapshot_bytes = 1024u;
  config->flow_rule_capacity = 4u;
  config->task_capacity = 4u;
  config->max_lease_duration_ms = 100u;
  config->initial_flow_default_action = MESH_FLOW_ACTION_DENY;
  config->core.self_id = 1u;
  config->core.voters = voters;
  config->core.voter_count = 1u;
  config->core.heartbeat_ticks = 1u;
  config->core.election_min_ticks = 3u;
  config->core.election_max_ticks = 5u;
  config->core.initial_election_timeout_ticks = 3u;
  config->core.max_log_entries = 64u;
  config->transport.enqueue = discard_message;
}

static void test_sqlite_service_applies_and_fences_linearizable_read(void) {
  mesh_control_raft_service_config_v1_t config;
  mesh_control_raft_service_v1_t *runtime = NULL;
  mesh_control_raft_v1_t *control;
  mesh_task_lease_raft_command_v1_t command;
  mesh_task_lease_entry_v1_t stored;
  tr_raft_tick_t tick = {3u, 4u};
  tr_raft_operation_status_t receipt;
  read_capture_t capture;
  uint64_t read_context = 0u;
  size_t reads = 0u;
  uint8_t published = 0u;

  memset(&capture, 0, sizeof(capture));
  init_single_node_config(&config, ":memory:");

  check_int_eq(mesh_control_raft_service_open_v1(&config, &runtime),
               TURBO_OK);
  check_int_eq(mesh_control_raft_service_tick_v1(runtime, &tick), TURBO_OK);
  control = mesh_control_raft_service_control_v1(runtime);
  check_not_null(control);

  memset(&command, 0, sizeof(command));
  command.operation = MESH_TASK_LEASE_RAFT_REGISTER;
  memset(command.command_id, 0x51, sizeof(command.command_id));
  memset(command.request_digest, 0x61, sizeof(command.request_digest));
  command.task_deadline_ms = 1000u;
  check_int_eq(mesh_control_raft_propose_task_v1(control, 901u, &command,
                                                 &receipt),
               TURBO_OK);
  check_int_eq(mesh_task_lease_get_v1(
                   mesh_control_raft_service_tasks_v1(runtime),
                   command.command_id, &stored),
               MESH_TASK_LEASE_OK);
  check_uint_eq(stored.registered_index, receipt.index);

  check_int_eq(mesh_control_raft_read_index_v1(
                   control, capture_read, &capture, &read_context),
               TURBO_OK);
  check_true(read_context != 0u);
  check_int_eq(mesh_control_raft_service_poll_v1(runtime, &reads, &published),
               TURBO_OK);
  check_uint_eq(reads, 1u);
  check_uint_eq(capture.calls, 1u);
  check_int_eq(capture.result, TURBO_OK);
  check_true(capture.safe_index >= receipt.index);
  check_true(capture.local_index >= capture.safe_index);

  mesh_control_raft_service_close_v1(runtime);
}

static void test_sqlite_service_replays_committed_tasks_after_restart(void) {
  mesh_control_raft_service_config_v1_t config;
  mesh_control_raft_service_v1_t *runtime = NULL;
  mesh_task_lease_raft_command_v1_t command;
  mesh_task_lease_entry_v1_t stored;
  tr_raft_operation_status_t register_receipt;
  tr_raft_operation_status_t acquire_receipt;
  tr_raft_tick_t tick = {3u, 4u};
  char database_path[512];
  char *temp_dir = tt_make_temp_dir("mesh-control-raft-");

  check_not_null(temp_dir);
  check_true(snprintf(database_path, sizeof(database_path), "%s/control.db",
                      temp_dir) > 0);
  init_single_node_config(&config, database_path);
  check_int_eq(mesh_control_raft_service_open_v1(&config, &runtime),
               TURBO_OK);
  check_int_eq(mesh_control_raft_service_tick_v1(runtime, &tick), TURBO_OK);

  memset(&command, 0, sizeof(command));
  command.operation = MESH_TASK_LEASE_RAFT_REGISTER;
  memset(command.command_id, 0x71, sizeof(command.command_id));
  memset(command.request_digest, 0x81, sizeof(command.request_digest));
  command.task_deadline_ms = 5000u;
  check_int_eq(mesh_control_raft_propose_task_v1(
                   mesh_control_raft_service_control_v1(runtime), 1901u,
                   &command, &register_receipt),
               TURBO_OK);
  check_true(register_receipt.index != 0u);

  command.operation = MESH_TASK_LEASE_RAFT_ACQUIRE;
  memset(command.holder_node_id, 0x91, sizeof(command.holder_node_id));
  command.task_deadline_ms = 0u;
  command.observed_now_ms = 100u;
  command.lease_expires_at_ms = 150u;
  check_int_eq(mesh_control_raft_propose_task_v1(
                   mesh_control_raft_service_control_v1(runtime), 1902u,
                   &command, &acquire_receipt),
               TURBO_OK);
  check_true(acquire_receipt.index > register_receipt.index);
  mesh_control_raft_service_close_v1(runtime);
  runtime = NULL;

  check_int_eq(mesh_control_raft_service_open_v1(&config, &runtime),
               TURBO_OK);
  check_int_eq(mesh_task_lease_get_v1(
                   mesh_control_raft_service_tasks_v1(runtime),
                   command.command_id, &stored),
               MESH_TASK_LEASE_OK);
  check_int_eq(stored.state, MESH_TASK_STATE_LEASED);
  check_uint_eq(stored.registered_index, register_receipt.index);
  check_uint_eq(stored.mutation_index, acquire_receipt.index);
  check_uint_eq(stored.fencing_token, acquire_receipt.index);
  check_uint_eq(stored.lease_generation, 1u);
  check_uint_eq(stored.lease_expires_at_ms, command.lease_expires_at_ms);
  check_mem_eq(stored.request_digest, command.request_digest,
               sizeof(stored.request_digest));
  check_mem_eq(stored.holder_node_id, command.holder_node_id,
               sizeof(stored.holder_node_id));

  mesh_control_raft_service_close_v1(runtime);
  check_int_eq(tt_remove_tree(temp_dir), 0);
  free(temp_dir);
}

spec("mesh persistent control Raft service") {
  it("applies SQLite-backed commands and fences quorum reads") {
    test_sqlite_service_applies_and_fences_linearizable_read();
  }
  it("replays committed task leases after a process restart") {
    test_sqlite_service_replays_committed_tasks_after_restart();
  }
}
