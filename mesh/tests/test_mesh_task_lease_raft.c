#include "mesh_task_lease_raft.h"
#include "tinytest.h"

#include <string.h>

static void fill_bytes(uint8_t *bytes, size_t size, uint8_t seed) {
  size_t index;
  for (index = 0u; index < size; ++index) {
    bytes[index] = (uint8_t)(seed + index);
  }
}

static void encode_apply(mesh_task_lease_store_v1_t *store,
                         uint64_t committed_index,
                         const mesh_task_lease_raft_command_v1_t *command,
                         mesh_task_lease_entry_v1_t *out_entry) {
  uint8_t encoded[MESH_TASK_LEASE_RAFT_COMMAND_SIZE];
  size_t encoded_size = 0u;
  check_int_eq(mesh_task_lease_raft_encode_v1(
                   command, encoded, sizeof(encoded), &encoded_size),
               MESH_TASK_LEASE_OK);
  check_uint_eq(encoded_size, MESH_TASK_LEASE_RAFT_COMMAND_SIZE);
  check_int_eq(mesh_task_lease_raft_apply_v1(
                   store, committed_index, encoded, encoded_size, out_entry),
               MESH_TASK_LEASE_OK);
}

static void test_committed_commands_replay_with_fencing(void) {
  mesh_task_lease_store_v1_t first;
  mesh_task_lease_store_v1_t replay;
  mesh_task_lease_raft_command_v1_t command;
  mesh_task_lease_entry_v1_t first_entry;
  mesh_task_lease_entry_v1_t replay_entry;
  uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE];
  uint8_t digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint8_t holder[MESH_MGMT_EXECUTION_DIGEST_SIZE];

  fill_bytes(command_id, sizeof(command_id), 1u);
  fill_bytes(digest, sizeof(digest), 21u);
  fill_bytes(holder, sizeof(holder), 71u);
  memset(&first, 0, sizeof(first));
  memset(&replay, 0, sizeof(replay));
  check_int_eq(mesh_task_lease_store_init_v1(&first, 4u, 100u),
               MESH_TASK_LEASE_OK);
  check_int_eq(mesh_task_lease_store_init_v1(&replay, 4u, 100u),
               MESH_TASK_LEASE_OK);

  memset(&command, 0, sizeof(command));
  command.operation = MESH_TASK_LEASE_RAFT_REGISTER;
  memcpy(command.command_id, command_id, sizeof(command_id));
  memcpy(command.request_digest, digest, sizeof(digest));
  command.task_deadline_ms = 1000u;
  encode_apply(&first, 10u, &command, &first_entry);
  encode_apply(&replay, 10u, &command, &replay_entry);

  memset(command.holder_node_id, 0, sizeof(command.holder_node_id));
  command.operation = MESH_TASK_LEASE_RAFT_ACQUIRE;
  command.task_deadline_ms = 0u;
  memcpy(command.holder_node_id, holder, sizeof(holder));
  command.observed_now_ms = 100u;
  command.lease_expires_at_ms = 150u;
  encode_apply(&first, 11u, &command, &first_entry);
  encode_apply(&replay, 11u, &command, &replay_entry);

  command.operation = MESH_TASK_LEASE_RAFT_COMPLETE;
  command.observed_now_ms = 120u;
  command.lease_expires_at_ms = 0u;
  command.expected_fencing_token = 11u;
  command.result_code = 23;
  command.terminal_state = MESH_TASK_STATE_SUCCEEDED;
  encode_apply(&first, 12u, &command, &first_entry);
  encode_apply(&replay, 12u, &command, &replay_entry);

  check_uint_eq(first_entry.fencing_token, 11u);
  check_uint_eq(first_entry.mutation_index, 12u);
  check_int_eq(first_entry.state, MESH_TASK_STATE_SUCCEEDED);
  check_int_eq(first_entry.result_code, 23);
  check_mem_eq(&first_entry, &replay_entry, sizeof(first_entry));

  mesh_task_lease_store_destroy_v1(&replay);
  mesh_task_lease_store_destroy_v1(&first);
}

static void test_codec_rejects_noncanonical_or_corrupt_commands(void) {
  mesh_task_lease_raft_command_v1_t command;
  mesh_task_lease_raft_command_v1_t decoded;
  uint8_t encoded[MESH_TASK_LEASE_RAFT_COMMAND_SIZE];
  size_t encoded_size = 0u;

  memset(&command, 0, sizeof(command));
  command.operation = MESH_TASK_LEASE_RAFT_REGISTER;
  fill_bytes(command.command_id, sizeof(command.command_id), 3u);
  fill_bytes(command.request_digest, sizeof(command.request_digest), 33u);
  command.task_deadline_ms = 500u;
  check_int_eq(mesh_task_lease_raft_encode_v1(
                   &command, encoded, sizeof(encoded), &encoded_size),
               MESH_TASK_LEASE_OK);

  encoded[6] = 1u;
  check_int_eq(mesh_task_lease_raft_decode_v1(encoded, encoded_size, &decoded),
               MESH_TASK_LEASE_INVALID_ARG);
  encoded[6] = 0u;
  check_int_eq(mesh_task_lease_raft_decode_v1(encoded, encoded_size - 1u,
                                              &decoded),
               MESH_TASK_LEASE_INVALID_ARG);

  command.observed_now_ms = 1u;
  check_int_eq(mesh_task_lease_raft_encode_v1(
                   &command, encoded, sizeof(encoded), &encoded_size),
               MESH_TASK_LEASE_INVALID_ARG);
}

spec("mesh task lease raft command boundary") {
  it("replays committed commands with stable fencing") {
    test_committed_commands_replay_with_fencing();
  }
  it("rejects noncanonical and corrupt commands") {
    test_codec_rejects_noncanonical_or_corrupt_commands();
  }
}
