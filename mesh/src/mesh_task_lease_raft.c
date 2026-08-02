#include "mesh_task_lease_raft.h"

#include <string.h>

static const uint8_t MESH_TASK_LEASE_RAFT_MAGIC[4] = {'M', 'T', 'L', '1'};

static void write_u32_le(uint8_t *output, uint32_t value) {
  output[0] = (uint8_t)value;
  output[1] = (uint8_t)(value >> 8u);
  output[2] = (uint8_t)(value >> 16u);
  output[3] = (uint8_t)(value >> 24u);
}

static uint32_t read_u32_le(const uint8_t *input) {
  return (uint32_t)input[0] | ((uint32_t)input[1] << 8u) |
         ((uint32_t)input[2] << 16u) | ((uint32_t)input[3] << 24u);
}

static void write_u64_le(uint8_t *output, uint64_t value) {
  size_t index;
  for (index = 0u; index < sizeof(value); ++index) {
    output[index] = (uint8_t)(value >> (index * 8u));
  }
}

static uint64_t read_u64_le(const uint8_t *input) {
  uint64_t value = 0u;
  size_t index;
  for (index = 0u; index < sizeof(value); ++index) {
    value |= ((uint64_t)input[index]) << (index * 8u);
  }
  return value;
}

static int bytes_are_zero(const uint8_t *bytes, size_t size) {
  size_t index;
  for (index = 0u; index < size; ++index) {
    if (bytes[index] != 0u) {
      return 0;
    }
  }
  return 1;
}

static int command_is_canonical(
    const mesh_task_lease_raft_command_v1_t *command) {
  int terminal_state_valid;

  if (!command ||
      bytes_are_zero(command->command_id, sizeof(command->command_id)) ||
      bytes_are_zero(command->request_digest,
                     sizeof(command->request_digest))) {
    return 0;
  }

  switch (command->operation) {
  case MESH_TASK_LEASE_RAFT_REGISTER:
    return bytes_are_zero(command->holder_node_id,
                          sizeof(command->holder_node_id)) &&
           command->task_deadline_ms != 0u && command->observed_now_ms == 0u &&
           command->lease_expires_at_ms == 0u &&
           command->expected_fencing_token == 0u && command->result_code == 0 &&
           command->terminal_state == 0;
  case MESH_TASK_LEASE_RAFT_ACQUIRE:
    return !bytes_are_zero(command->holder_node_id,
                           sizeof(command->holder_node_id)) &&
           command->task_deadline_ms == 0u && command->observed_now_ms != 0u &&
           command->lease_expires_at_ms != 0u &&
           command->expected_fencing_token == 0u && command->result_code == 0 &&
           command->terminal_state == 0;
  case MESH_TASK_LEASE_RAFT_RENEW:
    return !bytes_are_zero(command->holder_node_id,
                           sizeof(command->holder_node_id)) &&
           command->task_deadline_ms == 0u && command->observed_now_ms != 0u &&
           command->lease_expires_at_ms != 0u &&
           command->expected_fencing_token != 0u && command->result_code == 0 &&
           command->terminal_state == 0;
  case MESH_TASK_LEASE_RAFT_EXPIRE:
    return bytes_are_zero(command->holder_node_id,
                          sizeof(command->holder_node_id)) &&
           command->task_deadline_ms == 0u && command->observed_now_ms != 0u &&
           command->lease_expires_at_ms == 0u &&
           command->expected_fencing_token != 0u && command->result_code == 0 &&
           command->terminal_state == 0;
  case MESH_TASK_LEASE_RAFT_COMPLETE:
    terminal_state_valid = command->terminal_state == MESH_TASK_STATE_SUCCEEDED ||
                           command->terminal_state == MESH_TASK_STATE_FAILED ||
                           command->terminal_state == MESH_TASK_STATE_CANCELLED;
    return terminal_state_valid &&
           !bytes_are_zero(command->holder_node_id,
                           sizeof(command->holder_node_id)) &&
           command->task_deadline_ms == 0u && command->observed_now_ms != 0u &&
           command->lease_expires_at_ms == 0u &&
           command->expected_fencing_token != 0u;
  default:
    return 0;
  }
}

mesh_task_lease_result_t mesh_task_lease_raft_encode_v1(
    const mesh_task_lease_raft_command_v1_t *command, uint8_t *output,
    size_t output_capacity, size_t *out_size) {
  size_t offset = 0u;

  if (!command_is_canonical(command) || !output || !out_size ||
      output_capacity < MESH_TASK_LEASE_RAFT_COMMAND_SIZE) {
    return MESH_TASK_LEASE_INVALID_ARG;
  }

  memcpy(output + offset, MESH_TASK_LEASE_RAFT_MAGIC,
         sizeof(MESH_TASK_LEASE_RAFT_MAGIC));
  offset += sizeof(MESH_TASK_LEASE_RAFT_MAGIC);
  output[offset++] = MESH_TASK_LEASE_RAFT_COMMAND_VERSION;
  output[offset++] = (uint8_t)command->operation;
  output[offset++] = 0u;
  output[offset++] = 0u;
  memcpy(output + offset, command->command_id, sizeof(command->command_id));
  offset += sizeof(command->command_id);
  memcpy(output + offset, command->request_digest,
         sizeof(command->request_digest));
  offset += sizeof(command->request_digest);
  memcpy(output + offset, command->holder_node_id,
         sizeof(command->holder_node_id));
  offset += sizeof(command->holder_node_id);
  write_u64_le(output + offset, command->task_deadline_ms);
  offset += sizeof(uint64_t);
  write_u64_le(output + offset, command->observed_now_ms);
  offset += sizeof(uint64_t);
  write_u64_le(output + offset, command->lease_expires_at_ms);
  offset += sizeof(uint64_t);
  write_u64_le(output + offset, command->expected_fencing_token);
  offset += sizeof(uint64_t);
  write_u32_le(output + offset, (uint32_t)command->result_code);
  offset += sizeof(uint32_t);
  write_u32_le(output + offset, (uint32_t)command->terminal_state);
  offset += sizeof(uint32_t);

  *out_size = offset;
  return MESH_TASK_LEASE_OK;
}

mesh_task_lease_result_t mesh_task_lease_raft_decode_v1(
    const uint8_t *input, size_t input_size,
    mesh_task_lease_raft_command_v1_t *out_command) {
  mesh_task_lease_raft_command_v1_t command;
  size_t offset = 0u;

  if (!input || !out_command ||
      input_size != MESH_TASK_LEASE_RAFT_COMMAND_SIZE ||
      memcmp(input, MESH_TASK_LEASE_RAFT_MAGIC,
             sizeof(MESH_TASK_LEASE_RAFT_MAGIC)) != 0 ||
      input[4] != MESH_TASK_LEASE_RAFT_COMMAND_VERSION || input[6] != 0u ||
      input[7] != 0u) {
    return MESH_TASK_LEASE_INVALID_ARG;
  }

  memset(&command, 0, sizeof(command));
  command.operation = (mesh_task_lease_raft_operation_v1_t)input[5];
  offset = MESH_TASK_LEASE_RAFT_COMMAND_HEADER_SIZE;
  memcpy(command.command_id, input + offset, sizeof(command.command_id));
  offset += sizeof(command.command_id);
  memcpy(command.request_digest, input + offset,
         sizeof(command.request_digest));
  offset += sizeof(command.request_digest);
  memcpy(command.holder_node_id, input + offset,
         sizeof(command.holder_node_id));
  offset += sizeof(command.holder_node_id);
  command.task_deadline_ms = read_u64_le(input + offset);
  offset += sizeof(uint64_t);
  command.observed_now_ms = read_u64_le(input + offset);
  offset += sizeof(uint64_t);
  command.lease_expires_at_ms = read_u64_le(input + offset);
  offset += sizeof(uint64_t);
  command.expected_fencing_token = read_u64_le(input + offset);
  offset += sizeof(uint64_t);
  command.result_code = (int32_t)read_u32_le(input + offset);
  offset += sizeof(uint32_t);
  command.terminal_state = (mesh_task_state_v1_t)read_u32_le(input + offset);
  if (!command_is_canonical(&command)) {
    return MESH_TASK_LEASE_INVALID_ARG;
  }

  *out_command = command;
  return MESH_TASK_LEASE_OK;
}

mesh_task_lease_result_t mesh_task_lease_raft_apply_v1(
    mesh_task_lease_store_v1_t *store, uint64_t committed_index,
    const uint8_t *command_data, size_t command_size,
    mesh_task_lease_entry_v1_t *out_entry) {
  mesh_task_lease_raft_command_v1_t command;
  mesh_task_lease_entry_v1_t discarded_entry;
  mesh_task_lease_entry_v1_t *result_entry = out_entry;
  mesh_task_lease_result_t result = mesh_task_lease_raft_decode_v1(
      command_data, command_size, &command);

  if (result != MESH_TASK_LEASE_OK) {
    return result;
  }
  if (!result_entry) {
    memset(&discarded_entry, 0, sizeof(discarded_entry));
    result_entry = &discarded_entry;
  }

  switch (command.operation) {
  case MESH_TASK_LEASE_RAFT_REGISTER:
    return mesh_task_lease_register_v1(
        store, committed_index, command.command_id, command.request_digest,
        command.task_deadline_ms, result_entry);
  case MESH_TASK_LEASE_RAFT_ACQUIRE:
    return mesh_task_lease_acquire_v1(
        store, committed_index, command.command_id, command.request_digest,
        command.holder_node_id, command.observed_now_ms,
        command.lease_expires_at_ms, result_entry);
  case MESH_TASK_LEASE_RAFT_RENEW:
    return mesh_task_lease_renew_v1(
        store, committed_index, command.command_id, command.request_digest,
        command.holder_node_id, command.expected_fencing_token,
        command.observed_now_ms, command.lease_expires_at_ms, result_entry);
  case MESH_TASK_LEASE_RAFT_EXPIRE:
    return mesh_task_lease_expire_v1(
        store, committed_index, command.command_id, command.request_digest,
        command.expected_fencing_token, command.observed_now_ms, result_entry);
  case MESH_TASK_LEASE_RAFT_COMPLETE:
    return mesh_task_lease_complete_v1(
        store, committed_index, command.command_id, command.request_digest,
        command.holder_node_id, command.expected_fencing_token,
        command.observed_now_ms, command.terminal_state, command.result_code,
        result_entry);
  default:
    return MESH_TASK_LEASE_INVALID_ARG;
  }
}
