#include "m3_gateway_raft.h"

#include <platform.h>
#include <turbo_error.h>
#include <turboraft/raft_sqlite_storage.h>

#include <stdlib.h>
#include <string.h>

/* Phase 2a: single-voter raft metadata backend. The namespace local store is
 * the raft state machine target; SQLite holds the raft log and snapshot. */

static uint64_t g_raft_command_sequence = 0u;

#define M3_GATEWAY_RAFT_MAX_APPLY_POLLS 100000u

struct m3_gateway_raft_s {
  m3_namespace_local_store_v1_t *store;
  tr_raft_sqlite_storage_t *storage;
  m3_namespace_raft_adapter_v1_t *adapter;
  tr_raft_service_t *service;
  uint32_t election_min_ticks;
  uint32_t election_max_ticks;
  uint8_t open;
};

/* Raft requires randomized per-node election timeouts so simultaneous
 * candidates do not reject each other's votes at the same term. The core keeps
 * the caller-supplied next_election_timeout_ticks verbatim, so the caller must
 * randomize it within [min, max] on every tick. */
static uint32_t election_timeout_ticks(uint32_t min_ticks, uint32_t max_ticks) {
  uint32_t value = 0u;
  uint32_t range;

  if (min_ticks >= max_ticks) {
    return min_ticks;
  }
  if (turbo_secure_random(&value, sizeof(value)) != 0) {
    value = (uint32_t)rand();
  }
  range = max_ticks - min_ticks + 1u;
  return min_ticks + (value % range);
}

static int discard_message(void *context, const tr_raft_message_t *message) {
  (void)context;
  (void)message;
  return TURBO_OK;
}

static int config_valid(const m3_gateway_raft_config_v1_t *config) {
  return config && config->sqlite_path && config->sqlite_path[0] != '\0' && config->self_id != 0u &&
         config->voters && config->voter_count != 0u && config->max_snapshot_bytes != 0u &&
         config->max_snapshot_bytes <= TR_RAFT_SQLITE_MAX_SNAPSHOT_BYTES &&
         config->max_pending_reads != 0u &&
         config->max_pending_reads <= M3_NAMESPACE_RAFT_MAX_PENDING_READS;
}

static void close_members(m3_gateway_raft_v1_t *raft) {
  if (raft->service) {
    tr_raft_service_destroy(raft->service);
  }
  if (raft->storage) {
    (void)tr_raft_sqlite_storage_close(raft->storage);
  }
  if (raft->adapter) {
    m3_namespace_raft_adapter_destroy_v1(raft->adapter);
  }
}

int m3_gateway_raft_open_v1(const m3_gateway_raft_config_v1_t *config,
                            m3_namespace_local_store_v1_t *store, m3_gateway_raft_v1_t **out_raft) {
  m3_gateway_raft_v1_t *raft;
  tr_raft_sqlite_storage_config_t storage_config;
  tr_raft_sqlite_recovery_t recovery;
  tr_raft_storage_t storage_adapter;
  tr_raft_service_config_t service_config;
  tr_raft_transport_t transport;
  int result;

  if (!out_raft) {
    return TURBO_EINVAL;
  }
  *out_raft = NULL;
  if (!config_valid(config) || !store || !store->open) {
    return TURBO_EINVAL;
  }
  raft = (m3_gateway_raft_v1_t *)calloc(1u, sizeof(*raft));
  if (!raft) {
    return TURBO_ENOMEM;
  }
  raft->store = store;

  result = m3_namespace_raft_adapter_create_v1(store, config->max_pending_reads, &raft->adapter);
  if (result != TURBO_OK) {
    free(raft);
    return result;
  }

  memset(&storage_config, 0, sizeof(storage_config));
  storage_config.path = config->sqlite_path;
  storage_config.busy_timeout_ms = 1000;
  storage_config.create_if_missing = 1;
  storage_config.max_snapshot_bytes = config->max_snapshot_bytes;
  result = tr_raft_sqlite_storage_open(&storage_config, &raft->storage);
  if (result != TURBO_OK) {
    close_members(raft);
    free(raft);
    return result;
  }
  memset(&storage_adapter, 0, sizeof(storage_adapter));
  result = tr_raft_sqlite_storage_bind(raft->storage, &storage_adapter);
  if (result != TURBO_OK) {
    close_members(raft);
    free(raft);
    return result;
  }
  memset(&recovery, 0, sizeof(recovery));
  result = tr_raft_sqlite_storage_load(raft->storage, &recovery);
  if (result != TURBO_OK) {
    close_members(raft);
    free(raft);
    return result;
  }

  memset(&service_config, 0, sizeof(service_config));
  service_config.core.self_id = config->self_id;
  service_config.core.voters = config->voters;
  service_config.core.voter_count = config->voter_count;
  service_config.core.heartbeat_ticks = 1u;
  service_config.core.election_min_ticks = 3u;
  service_config.core.election_max_ticks = 5u;
  service_config.core.initial_election_timeout_ticks = 3u;
  raft->election_min_ticks = service_config.core.election_min_ticks;
  raft->election_max_ticks = service_config.core.election_max_ticks;
  service_config.core.max_log_entries = 64u;
  service_config.core.initial_term = recovery.term;
  service_config.core.initial_vote = recovery.voted_for;
  service_config.core.initial_last_log_index = recovery.snapshot_index;
  service_config.core.initial_last_log_term = recovery.snapshot_term;
  service_config.core.initial_log_entries = recovery.entries;
  service_config.core.initial_log_entry_count = recovery.entry_count;
  service_config.core.initial_commit_index = recovery.commit_index;
  service_config.core.initial_applied_index = recovery.snapshot_index;
  service_config.storage = storage_adapter;
  memset(&transport, 0, sizeof(transport));
  if (config->transport != NULL) {
    transport = *config->transport;
  } else {
    transport.context = NULL;
    transport.enqueue = discard_message;
  }
  service_config.transport = transport;
  service_config.state_machine = m3_namespace_raft_state_machine_v1(raft->adapter);
  result = tr_raft_service_create(&service_config, &raft->service);
  tr_raft_sqlite_recovery_destroy(&recovery);
  if (result != TURBO_OK) {
    close_members(raft);
    free(raft);
    return result;
  }
  result = m3_namespace_raft_adapter_bind_service_v1(raft->adapter, raft->service);
  if (result == TURBO_OK) {
    result = tr_raft_service_poll(raft->service);
  }
  if (result == TURBO_OK && config->voter_count == 1u) {
    /* Drive the single voter to self-election so proposals commit.
     * Multi-voter clusters elect naturally through the event loop. */
    tr_raft_tick_t tick;
    memset(&tick, 0, sizeof(tick));
    tick.elapsed_ticks = 3u;
    tick.next_election_timeout_ticks = election_timeout_ticks(raft->election_min_ticks,
                                                           raft->election_max_ticks);
    for (int round = 0; round < 3 && result == TURBO_OK; round++) {
      result = tr_raft_service_tick(raft->service, &tick);
      if (result == TURBO_OK)
        result = tr_raft_service_poll(raft->service);
    }
  }
  if (result != TURBO_OK) {
    close_members(raft);
    free(raft);
    return result;
  }
  raft->open = 1u;
  *out_raft = raft;
  return TURBO_OK;
}

void m3_gateway_raft_close_v1(m3_gateway_raft_v1_t *raft) {
  if (!raft) {
    return;
  }
  close_members(raft);
  memset(raft, 0, sizeof(*raft));
  free(raft);
}

int m3_gateway_raft_poll_v1(m3_gateway_raft_v1_t *raft, size_t *out_completed) {
  size_t completed = 0u;
  int result;

  if (!out_completed) {
    return TURBO_EINVAL;
  }
  *out_completed = 0u;
  if (!raft || !raft->open) {
    return TURBO_EINVAL;
  }
  {
    tr_raft_tick_t tick;
    memset(&tick, 0, sizeof(tick));
    tick.elapsed_ticks = 1u;
    tick.next_election_timeout_ticks = election_timeout_ticks(raft->election_min_ticks,
                                                           raft->election_max_ticks);
    result = tr_raft_service_tick(raft->service, &tick);
  }
  if (result != TURBO_OK) {
    return result;
  }
  result = tr_raft_service_poll(raft->service);
  if (result != TURBO_OK) {
    return result;
  }
  return m3_namespace_raft_adapter_poll_v1(raft->adapter, &completed);
}

static int raft_wait_applied(m3_gateway_raft_v1_t *raft, uint64_t before_index) {
  size_t completed = 0u;
  size_t polls = 0u;

  /* Single-voter leader applies synchronously after poll; bounded retries keep
   * a stalled raft from hanging the gateway. */
  while (raft->store->applied_index <= before_index && polls < M3_GATEWAY_RAFT_MAX_APPLY_POLLS) {
    tr_raft_tick_t tick;
    memset(&tick, 0, sizeof(tick));
    tick.elapsed_ticks = 1u;
    tick.next_election_timeout_ticks = election_timeout_ticks(raft->election_min_ticks,
                                                           raft->election_max_ticks);
    (void)tr_raft_service_tick(raft->service, &tick);
    (void)tr_raft_service_poll(raft->service);
    (void)m3_namespace_raft_adapter_poll_v1(raft->adapter, &completed);
    polls++;
  }
  return raft->store->applied_index > before_index ? TURBO_OK : TURBO_EPROTO;
}

int m3_gateway_raft_put_v1(m3_gateway_raft_v1_t *raft,
                           const uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE],
                           const char *bucket, const char *object, const uint8_t *manifest_bytes,
                           size_t manifest_size) {
  m3_namespace_raft_command_v1_t command;
  tr_raft_operation_status_t receipt;
  uint64_t before_index;

  if (!raft || !raft->open || !tenant_id || !bucket || !object || !manifest_bytes ||
      manifest_size == 0u) {
    return TURBO_EINVAL;
  }
  memset(&command, 0, sizeof(command));
  command.type = M3_NAMESPACE_RAFT_COMMAND_PUT;
  memcpy(command.tenant_id, tenant_id, sizeof(command.tenant_id));
  command.bucket = (const uint8_t *)bucket;
  command.bucket_size = strlen(bucket);
  command.object_key = (const uint8_t *)object;
  command.object_key_size = strlen(object);
  command.manifest_bytes = manifest_bytes;
  command.manifest_size = manifest_size;

  before_index = raft->store->applied_index;
  {
    uint64_t command_id = ++g_raft_command_sequence;
    int result = m3_namespace_raft_propose_v1(raft->adapter, command_id, &command, &receipt);
    if (result != TURBO_OK) {
      return result;
    }
  }
  return raft_wait_applied(raft, before_index);
}

int m3_gateway_raft_tombstone_v1(m3_gateway_raft_v1_t *raft,
                                 const uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE],
                                 const char *bucket, const char *object) {
  m3_namespace_raft_command_v1_t command;
  tr_raft_operation_status_t receipt;
  uint64_t before_index;

  if (!raft || !raft->open || !tenant_id || !bucket || !object) {
    return TURBO_EINVAL;
  }
  memset(&command, 0, sizeof(command));
  command.type = M3_NAMESPACE_RAFT_COMMAND_TOMBSTONE;
  memcpy(command.tenant_id, tenant_id, sizeof(command.tenant_id));
  command.bucket = (const uint8_t *)bucket;
  command.bucket_size = strlen(bucket);
  command.object_key = (const uint8_t *)object;
  command.object_key_size = strlen(object);

  before_index = raft->store->applied_index;
  {
    uint64_t command_id = ++g_raft_command_sequence;
    int result = m3_namespace_raft_propose_v1(raft->adapter, command_id, &command, &receipt);
    if (result != TURBO_OK) {
      return result;
    }
  }
  return raft_wait_applied(raft, before_index);
}

m3_namespace_lookup_adapter_v1_t m3_gateway_raft_lookup_v1(m3_gateway_raft_v1_t *raft) {
  if (!raft || !raft->open) {
    m3_namespace_lookup_adapter_v1_t empty;
    memset(&empty, 0, sizeof(empty));
    return empty;
  }
  return m3_namespace_raft_lookup_adapter_v1(raft->adapter);
}

tr_raft_service_t *m3_gateway_raft_service_v1(m3_gateway_raft_v1_t *raft) {
  return (raft && raft->open) ? raft->service : NULL;
}

int m3_gateway_raft_propose_v1(m3_gateway_raft_v1_t *raft, uint64_t command_id,
                               const m3_namespace_raft_command_v1_t *command,
                               tr_raft_operation_status_t *out_receipt) {
  if (!raft || !raft->open || command == NULL || out_receipt == NULL) {
    return TURBO_EINVAL;
  }
  return m3_namespace_raft_propose_v1(raft->adapter, command_id, command, out_receipt);
}

uint64_t m3_gateway_raft_applied_index_v1(const m3_gateway_raft_v1_t *raft) {
  return (raft && raft->open && raft->store) ? raft->store->applied_index : 0u;
}

int m3_gateway_raft_role_v1(const m3_gateway_raft_v1_t *raft, tr_raft_role_t *out_role) {
  tr_raft_service_status_t status;

  if (!raft || !raft->open || out_role == NULL) {
    return TURBO_EINVAL;
  }
  memset(&status, 0, sizeof(status));
  if (tr_raft_service_status(raft->service, &status) != TURBO_OK) {
    return TURBO_EPROTO;
  }
  *out_role = status.core.role;
  return TURBO_OK;
}

int m3_gateway_raft_leader_v1(const m3_gateway_raft_v1_t *raft,
                              tr_raft_node_id_t *out_leader_id) {
  tr_raft_service_status_t status;

  if (!raft || !raft->open || out_leader_id == NULL) {
    return TURBO_EINVAL;
  }
  memset(&status, 0, sizeof(status));
  if (tr_raft_service_status(raft->service, &status) != TURBO_OK) {
    return TURBO_EPROTO;
  }
  *out_leader_id = status.core.leader_id;
  return TURBO_OK;
}

int m3_gateway_raft_service_status_v1(const m3_gateway_raft_v1_t *raft,
                                      tr_raft_service_status_t *out_status) {
  if (!raft || !raft->open || out_status == NULL) {
    return TURBO_EINVAL;
  }
  memset(out_status, 0, sizeof(*out_status));
  return tr_raft_service_status(raft->service, out_status);
}
