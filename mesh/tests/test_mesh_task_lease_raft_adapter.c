#include "mesh_task_lease_raft_adapter.h"
#include "tinytest.h"

#include <string.h>
#include <turbo_error.h>

static void fill_bytes(uint8_t *bytes, size_t size, uint8_t seed) {
  size_t index;
  for (index = 0u; index < size; ++index) {
    bytes[index] = (uint8_t)(seed + index);
  }
}

static void test_apply_batch_uses_committed_entry_index(void) {
  mesh_task_lease_store_v1_t store;
  mesh_task_lease_raft_adapter_v1_t *adapter = NULL;
  mesh_task_lease_raft_command_v1_t command;
  mesh_task_lease_entry_v1_t stored;
  tr_raft_state_machine_t state_machine;
  tr_raft_entry_t entry;
  size_t encoded_size = 0u;

  memset(&store, 0, sizeof(store));
  memset(&command, 0, sizeof(command));
  memset(&entry, 0, sizeof(entry));
  check_int_eq(mesh_task_lease_store_init_v1(&store, 2u, 100u),
               MESH_TASK_LEASE_OK);
  check_int_eq(mesh_task_lease_raft_adapter_create_v1(&store, &adapter),
               TURBO_OK);
  state_machine = mesh_task_lease_raft_state_machine_v1(adapter);
  check_not_null(state_machine.apply_batch);

  command.operation = MESH_TASK_LEASE_RAFT_REGISTER;
  fill_bytes(command.command_id, sizeof(command.command_id), 11u);
  fill_bytes(command.request_digest, sizeof(command.request_digest), 51u);
  command.task_deadline_ms = 900u;
  check_int_eq(mesh_task_lease_raft_encode_v1(
                   &command, entry.data, sizeof(entry.data), &encoded_size),
               MESH_TASK_LEASE_OK);
  entry.index = 77u;
  entry.data_length = encoded_size;
  check_int_eq(state_machine.apply_batch(state_machine.context, &entry, 1u),
               TURBO_OK);
  check_int_eq(mesh_task_lease_get_v1(&store, command.command_id, &stored),
               MESH_TASK_LEASE_OK);
  check_uint_eq(stored.registered_index, 77u);
  check_uint_eq(store.applied_index, 77u);

  check_int_eq(state_machine.apply_batch(state_machine.context, &entry, 1u),
               TURBO_EPROTO);
  entry.data[0] ^= 0xffu;
  entry.index = 78u;
  check_int_eq(state_machine.apply_batch(state_machine.context, &entry, 1u),
               TURBO_EPROTO);
  check_uint_eq(store.applied_index, 77u);

  mesh_task_lease_raft_adapter_destroy_v1(adapter);
  mesh_task_lease_store_destroy_v1(&store);
}

spec("mesh task lease TurboRaft adapter") {
  it("applies only committed canonical entries with index fencing") {
    test_apply_batch_uses_committed_entry_index();
  }
}
