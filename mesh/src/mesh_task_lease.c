#include "mesh_task_lease.h"

#include <stdlib.h>
#include <string.h>

static int bytes_nonzero(const uint8_t *bytes, size_t size) {
  uint8_t aggregate = 0u;

  if (!bytes) {
    return 0;
  }
  for (size_t i = 0u; i < size; ++i) {
    aggregate |= bytes[i];
  }
  return aggregate != 0u;
}

static int terminal_state_valid(mesh_task_state_v1_t state) {
  return state == MESH_TASK_STATE_SUCCEEDED ||
         state == MESH_TASK_STATE_FAILED ||
         state == MESH_TASK_STATE_CANCELLED;
}

static mesh_task_lease_entry_v1_t *find_entry(
    mesh_task_lease_store_v1_t *store,
    const uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE]) {
  for (size_t i = 0u; i < store->capacity; ++i) {
    if (store->entries[i].occupied &&
        memcmp(store->entries[i].command_id, command_id,
               MESH_MGMT_EXECUTION_ID_SIZE) == 0) {
      return &store->entries[i];
    }
  }
  return NULL;
}

static const mesh_task_lease_entry_v1_t *find_entry_const(
    const mesh_task_lease_store_v1_t *store,
    const uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE]) {
  for (size_t i = 0u; i < store->capacity; ++i) {
    if (store->entries[i].occupied &&
        memcmp(store->entries[i].command_id, command_id,
               MESH_MGMT_EXECUTION_ID_SIZE) == 0) {
      return &store->entries[i];
    }
  }
  return NULL;
}

static mesh_task_lease_result_t validate_command(
    mesh_task_lease_store_v1_t *store, uint64_t committed_index,
    const uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE],
    const uint8_t request_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE]) {
  if (!store || !store->open) {
    return MESH_TASK_LEASE_INVALID_STATE;
  }
  if (committed_index == 0u ||
      !bytes_nonzero(command_id, MESH_MGMT_EXECUTION_ID_SIZE) ||
      !bytes_nonzero(request_digest, MESH_MGMT_EXECUTION_DIGEST_SIZE)) {
    return MESH_TASK_LEASE_INVALID_ARG;
  }
  if (committed_index <= store->applied_index) {
    return MESH_TASK_LEASE_OUT_OF_ORDER;
  }
  return MESH_TASK_LEASE_OK;
}

static mesh_task_lease_result_t validate_identity(
    const mesh_task_lease_entry_v1_t *entry,
    const uint8_t request_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE]) {
  if (!entry) {
    return MESH_TASK_LEASE_NOT_FOUND;
  }
  return memcmp(entry->request_digest, request_digest,
                MESH_MGMT_EXECUTION_DIGEST_SIZE) == 0
             ? MESH_TASK_LEASE_OK
             : MESH_TASK_LEASE_CONFLICT;
}

static int interval_valid(const mesh_task_lease_store_v1_t *store,
                          const mesh_task_lease_entry_v1_t *entry,
                          uint64_t now_ms, uint64_t expires_at_ms) {
  return now_ms != 0u && now_ms < expires_at_ms &&
         expires_at_ms <= entry->task_deadline_ms &&
         expires_at_ms - now_ms <= store->max_lease_duration_ms;
}

static void clear_holder(mesh_task_lease_entry_v1_t *entry) {
  memset(entry->holder_node_id, 0, sizeof(entry->holder_node_id));
  entry->lease_expires_at_ms = 0u;
}

mesh_task_lease_result_t mesh_task_lease_store_init_v1(
    mesh_task_lease_store_v1_t *store, size_t capacity,
    uint64_t max_lease_duration_ms) {
  mesh_task_lease_entry_v1_t *entries;

  if (!store || store->open || capacity == 0u ||
      capacity > MESH_TASK_LEASE_MAX_TASKS ||
      capacity > SIZE_MAX / sizeof(*entries) || max_lease_duration_ms == 0u) {
    return MESH_TASK_LEASE_INVALID_ARG;
  }
  entries = (mesh_task_lease_entry_v1_t *)calloc(capacity,
                                                  sizeof(*entries));
  if (!entries) {
    return MESH_TASK_LEASE_RESOURCE_EXHAUSTED;
  }
  memset(store, 0, sizeof(*store));
  store->entries = entries;
  store->capacity = capacity;
  store->max_lease_duration_ms = max_lease_duration_ms;
  store->open = 1u;
  return MESH_TASK_LEASE_OK;
}

void mesh_task_lease_store_destroy_v1(mesh_task_lease_store_v1_t *store) {
  if (!store) {
    return;
  }
  if (store->entries) {
    memset(store->entries, 0, store->capacity * sizeof(*store->entries));
    free(store->entries);
  }
  memset(store, 0, sizeof(*store));
}

mesh_task_lease_result_t mesh_task_lease_register_v1(
    mesh_task_lease_store_v1_t *store, uint64_t committed_index,
    const uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE],
    const uint8_t request_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    uint64_t task_deadline_ms, mesh_task_lease_entry_v1_t *out_entry) {
  mesh_task_lease_entry_v1_t *entry;
  mesh_task_lease_result_t result =
      validate_command(store, committed_index, command_id, request_digest);

  if (out_entry) {
    memset(out_entry, 0, sizeof(*out_entry));
  }
  if (result != MESH_TASK_LEASE_OK || !out_entry || task_deadline_ms == 0u) {
    return result == MESH_TASK_LEASE_OK ? MESH_TASK_LEASE_INVALID_ARG : result;
  }
  entry = find_entry(store, command_id);
  if (entry) {
    if (memcmp(entry->request_digest, request_digest,
               MESH_MGMT_EXECUTION_DIGEST_SIZE) != 0 ||
        entry->task_deadline_ms != task_deadline_ms) {
      return MESH_TASK_LEASE_CONFLICT;
    }
    store->applied_index = committed_index;
    *out_entry = *entry;
    return MESH_TASK_LEASE_OK;
  }
  if (store->count == store->capacity) {
    return MESH_TASK_LEASE_RESOURCE_EXHAUSTED;
  }
  for (size_t i = 0u; i < store->capacity; ++i) {
    if (!store->entries[i].occupied) {
      entry = &store->entries[i];
      memset(entry, 0, sizeof(*entry));
      memcpy(entry->command_id, command_id, sizeof(entry->command_id));
      memcpy(entry->request_digest, request_digest,
             sizeof(entry->request_digest));
      entry->state = MESH_TASK_STATE_READY;
      entry->task_deadline_ms = task_deadline_ms;
      entry->registered_index = committed_index;
      entry->mutation_index = committed_index;
      entry->occupied = 1u;
      ++store->count;
      store->applied_index = committed_index;
      *out_entry = *entry;
      return MESH_TASK_LEASE_OK;
    }
  }
  return MESH_TASK_LEASE_RESOURCE_EXHAUSTED;
}

mesh_task_lease_result_t mesh_task_lease_acquire_v1(
    mesh_task_lease_store_v1_t *store, uint64_t committed_index,
    const uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE],
    const uint8_t request_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    const uint8_t holder_node_id[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    uint64_t observed_now_ms, uint64_t lease_expires_at_ms,
    mesh_task_lease_entry_v1_t *out_entry) {
  mesh_task_lease_entry_v1_t *entry;
  mesh_task_lease_result_t result =
      validate_command(store, committed_index, command_id, request_digest);

  if (out_entry) {
    memset(out_entry, 0, sizeof(*out_entry));
  }
  if (result != MESH_TASK_LEASE_OK || !out_entry ||
      !bytes_nonzero(holder_node_id, MESH_MGMT_EXECUTION_DIGEST_SIZE)) {
    return result == MESH_TASK_LEASE_OK ? MESH_TASK_LEASE_INVALID_ARG : result;
  }
  entry = find_entry(store, command_id);
  result = validate_identity(entry, request_digest);
  if (result != MESH_TASK_LEASE_OK) {
    return result;
  }
  if (entry->state == MESH_TASK_STATE_LEASED) {
    return MESH_TASK_LEASE_BUSY;
  }
  if (entry->state != MESH_TASK_STATE_READY) {
    return MESH_TASK_LEASE_INVALID_STATE;
  }
  if (!interval_valid(store, entry, observed_now_ms, lease_expires_at_ms)) {
    return MESH_TASK_LEASE_INVALID_ARG;
  }
  memcpy(entry->holder_node_id, holder_node_id,
         sizeof(entry->holder_node_id));
  entry->state = MESH_TASK_STATE_LEASED;
  entry->lease_expires_at_ms = lease_expires_at_ms;
  ++entry->lease_generation;
  entry->fencing_token = committed_index;
  entry->mutation_index = committed_index;
  store->applied_index = committed_index;
  *out_entry = *entry;
  return MESH_TASK_LEASE_OK;
}

static mesh_task_lease_result_t validate_live_holder(
    const mesh_task_lease_entry_v1_t *entry,
    const uint8_t holder_node_id[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    uint64_t expected_fencing_token, uint64_t observed_now_ms) {
  if (entry->state != MESH_TASK_STATE_LEASED) {
    return MESH_TASK_LEASE_INVALID_STATE;
  }
  if (expected_fencing_token == 0u ||
      entry->fencing_token != expected_fencing_token ||
      memcmp(entry->holder_node_id, holder_node_id,
             MESH_MGMT_EXECUTION_DIGEST_SIZE) != 0) {
    return MESH_TASK_LEASE_FENCED;
  }
  if (observed_now_ms == 0u || observed_now_ms >= entry->lease_expires_at_ms ||
      observed_now_ms >= entry->task_deadline_ms) {
    return MESH_TASK_LEASE_FENCED;
  }
  return MESH_TASK_LEASE_OK;
}

mesh_task_lease_result_t mesh_task_lease_renew_v1(
    mesh_task_lease_store_v1_t *store, uint64_t committed_index,
    const uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE],
    const uint8_t request_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    const uint8_t holder_node_id[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    uint64_t expected_fencing_token, uint64_t observed_now_ms,
    uint64_t lease_expires_at_ms, mesh_task_lease_entry_v1_t *out_entry) {
  mesh_task_lease_entry_v1_t *entry;
  mesh_task_lease_result_t result =
      validate_command(store, committed_index, command_id, request_digest);

  if (out_entry) {
    memset(out_entry, 0, sizeof(*out_entry));
  }
  if (result != MESH_TASK_LEASE_OK || !out_entry ||
      !bytes_nonzero(holder_node_id, MESH_MGMT_EXECUTION_DIGEST_SIZE)) {
    return result == MESH_TASK_LEASE_OK ? MESH_TASK_LEASE_INVALID_ARG : result;
  }
  entry = find_entry(store, command_id);
  result = validate_identity(entry, request_digest);
  if (result == MESH_TASK_LEASE_OK) {
    result = validate_live_holder(entry, holder_node_id,
                                  expected_fencing_token, observed_now_ms);
  }
  if (result != MESH_TASK_LEASE_OK) {
    return result;
  }
  if (lease_expires_at_ms <= entry->lease_expires_at_ms ||
      !interval_valid(store, entry, observed_now_ms, lease_expires_at_ms)) {
    return MESH_TASK_LEASE_INVALID_ARG;
  }
  entry->lease_expires_at_ms = lease_expires_at_ms;
  entry->fencing_token = committed_index;
  entry->mutation_index = committed_index;
  store->applied_index = committed_index;
  *out_entry = *entry;
  return MESH_TASK_LEASE_OK;
}

mesh_task_lease_result_t mesh_task_lease_expire_v1(
    mesh_task_lease_store_v1_t *store, uint64_t committed_index,
    const uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE],
    const uint8_t request_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    uint64_t expected_fencing_token, uint64_t observed_now_ms,
    mesh_task_lease_entry_v1_t *out_entry) {
  mesh_task_lease_entry_v1_t *entry;
  mesh_task_lease_result_t result =
      validate_command(store, committed_index, command_id, request_digest);

  if (out_entry) {
    memset(out_entry, 0, sizeof(*out_entry));
  }
  if (result != MESH_TASK_LEASE_OK || !out_entry || observed_now_ms == 0u) {
    return result == MESH_TASK_LEASE_OK ? MESH_TASK_LEASE_INVALID_ARG : result;
  }
  entry = find_entry(store, command_id);
  result = validate_identity(entry, request_digest);
  if (result != MESH_TASK_LEASE_OK) {
    return result;
  }
  if (entry->state != MESH_TASK_STATE_READY &&
      entry->state != MESH_TASK_STATE_LEASED) {
    return MESH_TASK_LEASE_INVALID_STATE;
  }
  if (observed_now_ms >= entry->task_deadline_ms) {
    entry->state = MESH_TASK_STATE_EXPIRED;
    clear_holder(entry);
  } else {
    if (entry->state != MESH_TASK_STATE_LEASED ||
        expected_fencing_token != entry->fencing_token ||
        observed_now_ms < entry->lease_expires_at_ms) {
      return MESH_TASK_LEASE_FENCED;
    }
    entry->state = MESH_TASK_STATE_READY;
    clear_holder(entry);
  }
  entry->mutation_index = committed_index;
  store->applied_index = committed_index;
  *out_entry = *entry;
  return MESH_TASK_LEASE_OK;
}

mesh_task_lease_result_t mesh_task_lease_complete_v1(
    mesh_task_lease_store_v1_t *store, uint64_t committed_index,
    const uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE],
    const uint8_t request_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    const uint8_t holder_node_id[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    uint64_t expected_fencing_token, uint64_t observed_now_ms,
    mesh_task_state_v1_t terminal_state, int32_t result_code,
    mesh_task_lease_entry_v1_t *out_entry) {
  mesh_task_lease_entry_v1_t *entry;
  mesh_task_lease_result_t result =
      validate_command(store, committed_index, command_id, request_digest);

  if (out_entry) {
    memset(out_entry, 0, sizeof(*out_entry));
  }
  if (result != MESH_TASK_LEASE_OK || !out_entry ||
      !terminal_state_valid(terminal_state) ||
      !bytes_nonzero(holder_node_id, MESH_MGMT_EXECUTION_DIGEST_SIZE)) {
    return result == MESH_TASK_LEASE_OK ? MESH_TASK_LEASE_INVALID_ARG : result;
  }
  entry = find_entry(store, command_id);
  result = validate_identity(entry, request_digest);
  if (result == MESH_TASK_LEASE_OK) {
    result = validate_live_holder(entry, holder_node_id,
                                  expected_fencing_token, observed_now_ms);
  }
  if (result != MESH_TASK_LEASE_OK) {
    return result;
  }
  entry->state = terminal_state;
  entry->result_code = result_code;
  clear_holder(entry);
  entry->mutation_index = committed_index;
  store->applied_index = committed_index;
  *out_entry = *entry;
  return MESH_TASK_LEASE_OK;
}

mesh_task_lease_result_t mesh_task_lease_get_v1(
    const mesh_task_lease_store_v1_t *store,
    const uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE],
    mesh_task_lease_entry_v1_t *out_entry) {
  const mesh_task_lease_entry_v1_t *entry;

  if (!out_entry) {
    return MESH_TASK_LEASE_INVALID_ARG;
  }
  memset(out_entry, 0, sizeof(*out_entry));
  if (!store || !store->open) {
    return MESH_TASK_LEASE_INVALID_STATE;
  }
  if (!bytes_nonzero(command_id, MESH_MGMT_EXECUTION_ID_SIZE)) {
    return MESH_TASK_LEASE_INVALID_ARG;
  }
  entry = find_entry_const(store, command_id);
  if (!entry) {
    return MESH_TASK_LEASE_NOT_FOUND;
  }
  *out_entry = *entry;
  return MESH_TASK_LEASE_OK;
}
