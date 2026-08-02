#include "mesh_mgmt_execution.h"

#include <stdlib.h>
#include <string.h>

static int bytes_are_zero(const uint8_t *bytes, size_t length) {
  size_t index;
  uint8_t combined = 0u;

  if (!bytes)
    return 1;
  for (index = 0u; index < length; index++)
    combined |= bytes[index];
  return combined == 0u;
}

static int refs_are_valid(
    const uint8_t refs[MESH_MGMT_EXECUTION_MAX_REFS][MESH_MGMT_EXECUTION_ID_SIZE],
    size_t count) {
  size_t index;
  size_t previous;

  if (count > MESH_MGMT_EXECUTION_MAX_REFS)
    return 0;
  for (index = 0u; index < count; index++) {
    if (bytes_are_zero(refs[index], MESH_MGMT_EXECUTION_ID_SIZE))
      return 0;
    for (previous = 0u; previous < index; previous++) {
      if (memcmp(refs[index], refs[previous], MESH_MGMT_EXECUTION_ID_SIZE) == 0)
        return 0;
    }
  }
  return 1;
}

static int limits_are_valid(const mesh_mgmt_execution_limits_v1_t *limits) {
  return limits && limits->module_bytes != 0u && limits->stack_bytes != 0u &&
         limits->linear_memory_bytes != 0u && limits->timeout_ms != 0u &&
         limits->control_flow_steps != 0u && limits->host_calls != 0u &&
         limits->copied_guest_bytes != 0u && limits->input_bytes != 0u &&
         limits->stdout_bytes != 0u && limits->stderr_bytes != 0u;
}

static uint32_t min_u32(uint32_t lhs, uint32_t rhs) {
  return lhs < rhs ? lhs : rhs;
}

static uint64_t min_u64(uint64_t lhs, uint64_t rhs) {
  return lhs < rhs ? lhs : rhs;
}

static mesh_mgmt_execution_limits_v1_t limits_intersect(
    const mesh_mgmt_execution_limits_v1_t *first,
    const mesh_mgmt_execution_limits_v1_t *second,
    const mesh_mgmt_execution_limits_v1_t *third,
    const mesh_mgmt_execution_limits_v1_t *fourth) {
  mesh_mgmt_execution_limits_v1_t result;

  memset(&result, 0, sizeof(result));
  result.module_bytes =
      min_u32(min_u32(first->module_bytes, second->module_bytes),
              min_u32(third->module_bytes, fourth->module_bytes));
  result.stack_bytes =
      min_u32(min_u32(first->stack_bytes, second->stack_bytes),
              min_u32(third->stack_bytes, fourth->stack_bytes));
  result.linear_memory_bytes =
      min_u32(min_u32(first->linear_memory_bytes, second->linear_memory_bytes),
              min_u32(third->linear_memory_bytes, fourth->linear_memory_bytes));
  result.timeout_ms =
      min_u64(min_u64(first->timeout_ms, second->timeout_ms),
              min_u64(third->timeout_ms, fourth->timeout_ms));
  result.control_flow_steps =
      min_u64(min_u64(first->control_flow_steps, second->control_flow_steps),
              min_u64(third->control_flow_steps, fourth->control_flow_steps));
  result.host_calls =
      min_u32(min_u32(first->host_calls, second->host_calls),
              min_u32(third->host_calls, fourth->host_calls));
  result.copied_guest_bytes =
      min_u64(min_u64(first->copied_guest_bytes, second->copied_guest_bytes),
              min_u64(third->copied_guest_bytes, fourth->copied_guest_bytes));
  result.input_bytes =
      min_u64(min_u64(first->input_bytes, second->input_bytes),
              min_u64(third->input_bytes, fourth->input_bytes));
  result.stdout_bytes =
      min_u64(min_u64(first->stdout_bytes, second->stdout_bytes),
              min_u64(third->stdout_bytes, fourth->stdout_bytes));
  result.stderr_bytes =
      min_u64(min_u64(first->stderr_bytes, second->stderr_bytes),
              min_u64(third->stderr_bytes, fourth->stderr_bytes));
  return result;
}

mesh_mgmt_execution_result_t mesh_mgmt_execution_grant_validate_v1(
    const mesh_mgmt_execution_grant_v1_t *grant, uint64_t now_ms) {
  if (!grant)
    return MESH_MGMT_EXECUTION_INVALID_ARG;
  if (grant->version != MESH_MGMT_EXECUTION_SCHEMA_V1 ||
      bytes_are_zero(grant->grant_id, sizeof(grant->grant_id)) ||
      bytes_are_zero(grant->mesh_id, sizeof(grant->mesh_id)) ||
      grant->policy_epoch == 0u ||
      bytes_are_zero(grant->subject_principal, sizeof(grant->subject_principal)) ||
      bytes_are_zero(grant->target_node_id, sizeof(grant->target_node_id)) ||
      bytes_are_zero(grant->deployment_id, sizeof(grant->deployment_id)) ||
      grant->deployment_generation == 0u ||
      bytes_are_zero(grant->package_digest, sizeof(grant->package_digest)) ||
      grant->operation != MESH_MGMT_EXECUTION_OPERATION_RUN_PRESTAGED_WASM ||
      grant->capabilities == 0u ||
      (grant->capabilities & ~MESH_MGMT_EXECUTION_CAP_ALL) != 0u ||
      !refs_are_valid(grant->mount_ids, grant->mount_count) ||
      !refs_are_valid(grant->service_ids, grant->service_count) ||
      !refs_are_valid(grant->provider_ids, grant->provider_count) ||
      !limits_are_valid(&grant->max_limits) ||
      grant->not_before_ms >= grant->expires_at_ms ||
      bytes_are_zero(grant->issuer_key, sizeof(grant->issuer_key)) ||
      bytes_are_zero(grant->signature, sizeof(grant->signature))) {
    return MESH_MGMT_EXECUTION_INVALID_SCHEMA;
  }
  if (now_ms < grant->not_before_ms || now_ms >= grant->expires_at_ms)
    return MESH_MGMT_EXECUTION_EXPIRED;
  return MESH_MGMT_EXECUTION_OK;
}

mesh_mgmt_execution_result_t mesh_mgmt_execution_request_validate_v1(
    const mesh_mgmt_execution_request_v1_t *request, uint64_t now_ms) {
  int digest_is_zero;

  if (!request)
    return MESH_MGMT_EXECUTION_INVALID_ARG;
  digest_is_zero =
      bytes_are_zero(request->input_digest, sizeof(request->input_digest));
  if (request->version != MESH_MGMT_EXECUTION_SCHEMA_V1 ||
      bytes_are_zero(request->command_id, sizeof(request->command_id)) ||
      bytes_are_zero(request->grant_id, sizeof(request->grant_id)) ||
      bytes_are_zero(request->target_node_id, sizeof(request->target_node_id)) ||
      bytes_are_zero(request->deployment_id, sizeof(request->deployment_id)) ||
      request->deployment_generation == 0u ||
      bytes_are_zero(request->package_digest, sizeof(request->package_digest)) ||
      request->input_kind < MESH_MGMT_EXECUTION_INPUT_NONE ||
      request->input_kind > MESH_MGMT_EXECUTION_INPUT_PRESTAGED_OBJECT ||
      request->output_mode < MESH_MGMT_EXECUTION_OUTPUT_NONE ||
      request->output_mode > MESH_MGMT_EXECUTION_OUTPUT_M3_OBJECT ||
      request->inline_input_size > MESH_MGMT_EXECUTION_INLINE_INPUT_MAX ||
      bytes_are_zero(request->request_nonce, sizeof(request->request_nonce)) ||
      bytes_are_zero(request->correlation_id, sizeof(request->correlation_id))) {
    return MESH_MGMT_EXECUTION_INVALID_SCHEMA;
  }
  if (request->input_kind == MESH_MGMT_EXECUTION_INPUT_NONE) {
    if (request->input_length != 0u || request->inline_input_size != 0u ||
        !digest_is_zero)
      return MESH_MGMT_EXECUTION_INVALID_SCHEMA;
  } else if (request->input_kind == MESH_MGMT_EXECUTION_INPUT_INLINE) {
    if (request->input_length == 0u ||
        request->input_length > MESH_MGMT_EXECUTION_INLINE_INPUT_MAX ||
        request->inline_input_size != (size_t)request->input_length ||
        digest_is_zero)
      return MESH_MGMT_EXECUTION_INVALID_SCHEMA;
  } else if (request->input_length == 0u ||
             request->inline_input_size != 0u || digest_is_zero) {
    return MESH_MGMT_EXECUTION_INVALID_SCHEMA;
  }
  if (request->deadline_ms <= now_ms)
    return MESH_MGMT_EXECUTION_EXPIRED;
  return MESH_MGMT_EXECUTION_OK;
}

mesh_mgmt_execution_result_t mesh_mgmt_execution_request_bind_v1(
    const mesh_mgmt_execution_grant_v1_t *grant,
    const mesh_mgmt_execution_request_v1_t *request) {
  if (!grant || !request)
    return MESH_MGMT_EXECUTION_INVALID_ARG;
  if (memcmp(grant->grant_id, request->grant_id, sizeof(grant->grant_id)) != 0 ||
      memcmp(grant->target_node_id, request->target_node_id,
             sizeof(grant->target_node_id)) != 0 ||
      memcmp(grant->deployment_id, request->deployment_id,
             sizeof(grant->deployment_id)) != 0 ||
      grant->deployment_generation != request->deployment_generation ||
      memcmp(grant->package_digest, request->package_digest,
             sizeof(grant->package_digest)) != 0 ||
      request->deadline_ms > grant->expires_at_ms) {
    return MESH_MGMT_EXECUTION_BINDING_MISMATCH;
  }
  return MESH_MGMT_EXECUTION_OK;
}

mesh_mgmt_execution_result_t mesh_mgmt_execution_authorize_v1(
    const mesh_mgmt_execution_grant_v1_t *grant,
    const mesh_mgmt_execution_authorization_input_v1_t *input,
    mesh_mgmt_execution_effective_policy_v1_t *out_effective) {
  uint32_t effective_capabilities;

  if (!grant || !input || !out_effective)
    return MESH_MGMT_EXECUTION_INVALID_ARG;
  memset(out_effective, 0, sizeof(*out_effective));
  if (input->requested_capabilities == 0u ||
      (input->requested_capabilities & ~MESH_MGMT_EXECUTION_CAP_ALL) != 0u ||
      (input->host_capabilities & ~MESH_MGMT_EXECUTION_CAP_ALL) != 0u ||
      (input->hard_capabilities & ~MESH_MGMT_EXECUTION_CAP_ALL) != 0u ||
      !limits_are_valid(&input->requested_limits) ||
      !limits_are_valid(&input->host_limits) ||
      !limits_are_valid(&input->hard_limits) ||
      !limits_are_valid(&grant->max_limits)) {
    return MESH_MGMT_EXECUTION_INVALID_SCHEMA;
  }
  effective_capabilities =
      input->requested_capabilities & input->host_capabilities &
      input->hard_capabilities & grant->capabilities;
  if (effective_capabilities != input->requested_capabilities)
    return MESH_MGMT_EXECUTION_DENIED;
  out_effective->capabilities = effective_capabilities;
  out_effective->limits =
      limits_intersect(&input->requested_limits, &input->host_limits,
                       &grant->max_limits, &input->hard_limits);
  return MESH_MGMT_EXECUTION_OK;
}

int mesh_mgmt_execution_state_is_terminal_v1(
    mesh_mgmt_execution_state_t state) {
  return state == MESH_MGMT_EXECUTION_STATE_SUCCEEDED ||
         state == MESH_MGMT_EXECUTION_STATE_FAILED ||
         state == MESH_MGMT_EXECUTION_STATE_EXPIRED ||
         state == MESH_MGMT_EXECUTION_STATE_CANCELLED ||
         state == MESH_MGMT_EXECUTION_STATE_FAILED_INDETERMINATE ||
         state == MESH_MGMT_EXECUTION_STATE_REJECTED;
}

static int transition_is_valid(mesh_mgmt_execution_state_t current,
                               mesh_mgmt_execution_state_t next) {
  if (mesh_mgmt_execution_state_is_terminal_v1(current))
    return 0;
  if (current == MESH_MGMT_EXECUTION_STATE_ACCEPTED)
    return next == MESH_MGMT_EXECUTION_STATE_STAGING ||
           next == MESH_MGMT_EXECUTION_STATE_CANCELLED ||
           next == MESH_MGMT_EXECUTION_STATE_EXPIRED ||
           next == MESH_MGMT_EXECUTION_STATE_FAILED;
  if (current == MESH_MGMT_EXECUTION_STATE_STAGING)
    return next == MESH_MGMT_EXECUTION_STATE_RUNNING ||
           next == MESH_MGMT_EXECUTION_STATE_CANCELLED ||
           next == MESH_MGMT_EXECUTION_STATE_EXPIRED ||
           next == MESH_MGMT_EXECUTION_STATE_FAILED;
  if (current == MESH_MGMT_EXECUTION_STATE_RUNNING)
    return next == MESH_MGMT_EXECUTION_STATE_SUCCEEDED ||
           next == MESH_MGMT_EXECUTION_STATE_FAILED ||
           next == MESH_MGMT_EXECUTION_STATE_EXPIRED ||
           next == MESH_MGMT_EXECUTION_STATE_CANCELLED ||
           next == MESH_MGMT_EXECUTION_STATE_FAILED_INDETERMINATE;
  return 0;
}

static mesh_mgmt_execution_journal_entry_v1_t *find_entry(
    mesh_mgmt_execution_journal_v1_t *journal,
    const uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE]) {
  size_t index;

  if (!journal || !journal->entries || !command_id)
    return NULL;
  for (index = 0u; index < journal->capacity; index++) {
    if (journal->entries[index].occupied &&
        memcmp(journal->entries[index].command_id, command_id,
               MESH_MGMT_EXECUTION_ID_SIZE) == 0)
      return &journal->entries[index];
  }
  return NULL;
}

mesh_mgmt_execution_result_t mesh_mgmt_execution_journal_init_v1(
    mesh_mgmt_execution_journal_v1_t *journal, size_t capacity) {
  if (!journal)
    return MESH_MGMT_EXECUTION_INVALID_ARG;
  memset(journal, 0, sizeof(*journal));
  if (capacity == 0u || capacity > MESH_MGMT_EXECUTION_JOURNAL_MAX)
    return MESH_MGMT_EXECUTION_INVALID_SCHEMA;
  journal->entries = (mesh_mgmt_execution_journal_entry_v1_t *)calloc(
      capacity, sizeof(*journal->entries));
  if (!journal->entries)
    return MESH_MGMT_EXECUTION_RESOURCE_EXHAUSTED;
  journal->capacity = capacity;
  return MESH_MGMT_EXECUTION_OK;
}

void mesh_mgmt_execution_journal_destroy_v1(
    mesh_mgmt_execution_journal_v1_t *journal) {
  if (!journal)
    return;
  free(journal->entries);
  memset(journal, 0, sizeof(*journal));
}

mesh_mgmt_execution_result_t mesh_mgmt_execution_journal_submit_v1(
    mesh_mgmt_execution_journal_v1_t *journal,
    const uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE],
    const uint8_t request_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    mesh_mgmt_execution_journal_entry_v1_t *out_entry) {
  mesh_mgmt_execution_journal_entry_v1_t *entry;
  size_t index;

  if (!journal || !journal->entries || !command_id || !request_digest ||
      !out_entry)
    return MESH_MGMT_EXECUTION_INVALID_ARG;
  memset(out_entry, 0, sizeof(*out_entry));
  if (bytes_are_zero(command_id, MESH_MGMT_EXECUTION_ID_SIZE) ||
      bytes_are_zero(request_digest, MESH_MGMT_EXECUTION_DIGEST_SIZE))
    return MESH_MGMT_EXECUTION_INVALID_SCHEMA;
  entry = find_entry(journal, command_id);
  if (entry) {
    *out_entry = *entry;
    return memcmp(entry->request_digest, request_digest,
                  MESH_MGMT_EXECUTION_DIGEST_SIZE) == 0
               ? MESH_MGMT_EXECUTION_OK
               : MESH_MGMT_EXECUTION_CONFLICT;
  }
  if (journal->count >= journal->capacity)
    return MESH_MGMT_EXECUTION_RESOURCE_EXHAUSTED;
  for (index = 0u; index < journal->capacity; index++) {
    if (!journal->entries[index].occupied) {
      entry = &journal->entries[index];
      memset(entry, 0, sizeof(*entry));
      memcpy(entry->command_id, command_id, MESH_MGMT_EXECUTION_ID_SIZE);
      memcpy(entry->request_digest, request_digest,
             MESH_MGMT_EXECUTION_DIGEST_SIZE);
      entry->state = MESH_MGMT_EXECUTION_STATE_ACCEPTED;
      entry->occupied = 1u;
      entry->generation = ++journal->generation;
      journal->count++;
      *out_entry = *entry;
      return MESH_MGMT_EXECUTION_OK;
    }
  }
  return MESH_MGMT_EXECUTION_RESOURCE_EXHAUSTED;
}

mesh_mgmt_execution_result_t mesh_mgmt_execution_journal_get_v1(
    const mesh_mgmt_execution_journal_v1_t *journal,
    const uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE],
    mesh_mgmt_execution_journal_entry_v1_t *out_entry) {
  mesh_mgmt_execution_journal_entry_v1_t *entry;

  if (!journal || !command_id || !out_entry)
    return MESH_MGMT_EXECUTION_INVALID_ARG;
  memset(out_entry, 0, sizeof(*out_entry));
  entry = find_entry((mesh_mgmt_execution_journal_v1_t *)journal, command_id);
  if (!entry)
    return MESH_MGMT_EXECUTION_NOT_FOUND;
  *out_entry = *entry;
  return MESH_MGMT_EXECUTION_OK;
}

mesh_mgmt_execution_result_t mesh_mgmt_execution_journal_transition_v1(
    mesh_mgmt_execution_journal_v1_t *journal,
    const uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE],
    mesh_mgmt_execution_state_t next_state, int32_t result_code,
    mesh_mgmt_execution_journal_entry_v1_t *out_entry) {
  mesh_mgmt_execution_journal_entry_v1_t *entry;

  if (!journal || !command_id || !out_entry)
    return MESH_MGMT_EXECUTION_INVALID_ARG;
  memset(out_entry, 0, sizeof(*out_entry));
  entry = find_entry(journal, command_id);
  if (!entry)
    return MESH_MGMT_EXECUTION_NOT_FOUND;
  if (!transition_is_valid(entry->state, next_state))
    return MESH_MGMT_EXECUTION_INVALID_STATE;
  if (!mesh_mgmt_execution_state_is_terminal_v1(next_state) &&
      result_code != 0)
    return MESH_MGMT_EXECUTION_INVALID_SCHEMA;
  entry->state = next_state;
  entry->result_code = result_code;
  entry->generation = ++journal->generation;
  *out_entry = *entry;
  return MESH_MGMT_EXECUTION_OK;
}

mesh_mgmt_execution_result_t mesh_mgmt_execution_journal_recover_v1(
    mesh_mgmt_execution_journal_v1_t *journal, size_t *out_recovered) {
  size_t index;

  if (!journal || !journal->entries || !out_recovered)
    return MESH_MGMT_EXECUTION_INVALID_ARG;
  *out_recovered = 0u;
  for (index = 0u; index < journal->capacity; index++) {
    mesh_mgmt_execution_journal_entry_v1_t *entry = &journal->entries[index];
    if (entry->occupied &&
        entry->state == MESH_MGMT_EXECUTION_STATE_RUNNING) {
      entry->state = MESH_MGMT_EXECUTION_STATE_FAILED_INDETERMINATE;
      entry->result_code = MESH_MGMT_EXECUTION_INVALID_STATE;
      entry->generation = ++journal->generation;
      (*out_recovered)++;
    }
  }
  return MESH_MGMT_EXECUTION_OK;
}

mesh_mgmt_execution_result_t mesh_mgmt_execution_journal_export_v1(
    const mesh_mgmt_execution_journal_v1_t *journal,
    mesh_mgmt_execution_journal_entry_v1_t *out_entries, size_t out_capacity,
    size_t *out_count) {
  size_t index;
  size_t output_index = 0u;

  if (!journal || !journal->entries || !out_count ||
      (!out_entries && journal->count != 0u))
    return MESH_MGMT_EXECUTION_INVALID_ARG;
  *out_count = 0u;
  if (out_capacity < journal->count)
    return MESH_MGMT_EXECUTION_RESOURCE_EXHAUSTED;
  for (index = 0u; index < journal->capacity; index++) {
    if (journal->entries[index].occupied)
      out_entries[output_index++] = journal->entries[index];
  }
  *out_count = output_index;
  return MESH_MGMT_EXECUTION_OK;
}

mesh_mgmt_execution_result_t mesh_mgmt_execution_journal_import_v1(
    mesh_mgmt_execution_journal_v1_t *journal,
    const mesh_mgmt_execution_journal_entry_v1_t *entries,
    size_t entry_count) {
  size_t index;
  size_t previous;
  uint64_t max_generation = 0u;

  if (!journal || !journal->entries || (!entries && entry_count != 0u))
    return MESH_MGMT_EXECUTION_INVALID_ARG;
  if (journal->count != 0u)
    return MESH_MGMT_EXECUTION_INVALID_STATE;
  if (entry_count > journal->capacity)
    return MESH_MGMT_EXECUTION_RESOURCE_EXHAUSTED;
  for (index = 0u; index < entry_count; index++) {
    if (!entries[index].occupied ||
        bytes_are_zero(entries[index].command_id,
                       MESH_MGMT_EXECUTION_ID_SIZE) ||
        bytes_are_zero(entries[index].request_digest,
                       MESH_MGMT_EXECUTION_DIGEST_SIZE) ||
        entries[index].generation == 0u ||
        entries[index].state < MESH_MGMT_EXECUTION_STATE_ACCEPTED ||
        entries[index].state > MESH_MGMT_EXECUTION_STATE_REJECTED) {
      return MESH_MGMT_EXECUTION_INVALID_SCHEMA;
    }
    for (previous = 0u; previous < index; previous++) {
      if (memcmp(entries[index].command_id, entries[previous].command_id,
                 MESH_MGMT_EXECUTION_ID_SIZE) == 0)
        return MESH_MGMT_EXECUTION_CONFLICT;
    }
    if (entries[index].generation > max_generation)
      max_generation = entries[index].generation;
  }
  memcpy(journal->entries, entries, entry_count * sizeof(*entries));
  journal->count = entry_count;
  journal->generation = max_generation;
  return MESH_MGMT_EXECUTION_OK;
}
