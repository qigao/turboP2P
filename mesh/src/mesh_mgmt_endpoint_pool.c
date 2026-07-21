#include "mesh_mgmt_endpoint_pool.h"

#include "mesh_mgmt_crypto.h"

#include <platform.h>
#include <turbo_error.h>

#include <string.h>

static int bytes_are_zero(const uint8_t *bytes, size_t length) {
  size_t index;
  uint8_t combined = 0u;

  for (index = 0u; index < length; index++)
    combined |= bytes[index];
  return combined == 0u;
}

static int endpoint_host_is_valid(const char *host) {
  size_t length = 0u;

  if (!host)
    return 0;
  while (length < MESH_MGMT_ENDPOINT_HOST_MAX && host[length] != '\0') {
    unsigned char value = (unsigned char)host[length];
    if (value <= 0x20u || value == 0x7fu || value == '/' || value == '\\')
      return 0;
    length++;
  }
  return length > 0u && length < MESH_MGMT_ENDPOINT_HOST_MAX;
}

static mesh_mgmt_endpoint_entry_v1_t *entry_at(mesh_mgmt_endpoint_pool_v1_t *pool, size_t index) {
  return (mesh_mgmt_endpoint_entry_v1_t *)turbo_vec_at(&pool->entries, index);
}

static const mesh_mgmt_endpoint_entry_v1_t *entry_at_const(const mesh_mgmt_endpoint_pool_v1_t *pool,
                                                           size_t index) {
  return (const mesh_mgmt_endpoint_entry_v1_t *)turbo_vec_at_const(&pool->entries, index);
}

static mesh_mgmt_endpoint_entry_v1_t *
find_by_identity(mesh_mgmt_endpoint_pool_v1_t *pool,
                 const uint8_t transport_peer_id[P2P_KEY_SIZE]) {
  size_t index;

  for (index = 0u; index < pool->capacity; index++) {
    mesh_mgmt_endpoint_entry_v1_t *entry = entry_at(pool, index);
    if (entry && entry->occupied &&
        mesh_mgmt_crypto_equal_32(entry->record.transport_peer_id, transport_peer_id)) {
      return entry;
    }
  }
  return NULL;
}

static mesh_mgmt_endpoint_entry_v1_t *find_free(mesh_mgmt_endpoint_pool_v1_t *pool) {
  size_t index;

  for (index = 0u; index < pool->capacity; index++) {
    mesh_mgmt_endpoint_entry_v1_t *entry = entry_at(pool, index);
    if (entry && !entry->occupied)
      return entry;
  }
  return NULL;
}

static int endpoint_conflicts(const mesh_mgmt_endpoint_pool_v1_t *pool,
                              const uint8_t transport_peer_id[P2P_KEY_SIZE], const char *host,
                              uint16_t port) {
  size_t index;

  for (index = 0u; index < pool->capacity; index++) {
    const mesh_mgmt_endpoint_entry_v1_t *entry = entry_at_const(pool, index);
    if (entry && entry->occupied && entry->record.port == port &&
        strcmp(entry->record.host, host) == 0 &&
        !mesh_mgmt_crypto_equal_32(entry->record.transport_peer_id, transport_peer_id)) {
      return 1;
    }
  }
  return 0;
}

static int records_are_equal(const mesh_mgmt_endpoint_record_v1_t *left,
                             const mesh_mgmt_endpoint_record_v1_t *right) {
  return mesh_mgmt_crypto_equal_32(left->transport_peer_id, right->transport_peer_id) &&
         strcmp(left->host, right->host) == 0 && left->port == right->port &&
         left->source == right->source && left->record_epoch == right->record_epoch &&
         left->expires_at_ms == right->expires_at_ms;
}

static int pool_random(mesh_mgmt_endpoint_pool_v1_t *pool, uint8_t *output, size_t output_len) {
  return pool->random_bytes ? pool->random_bytes(pool->callback_context, output, output_len)
                            : turbo_secure_random(output, output_len);
}

static int pool_connect(mesh_mgmt_endpoint_pool_v1_t *pool,
                        const mesh_mgmt_endpoint_record_v1_t *record) {
  return pool->connect_peer
             ? pool->connect_peer(pool->callback_context, pool->node, record->host, record->port)
             : p2p_connect(pool->node, record->host, (int)record->port);
}

static mesh_mgmt_endpoint_pool_result_t retry_deadline(mesh_mgmt_endpoint_pool_v1_t *pool,
                                                       uint32_t failure_count, uint64_t now_ms,
                                                       uint64_t *out_deadline) {
  uint8_t random_bytes[4];
  uint32_t random_value;
  uint64_t delay;
  uint64_t jitter;
  uint32_t exponent;

  if (!out_deadline || failure_count == 0u)
    return MESH_MGMT_ENDPOINT_POOL_INVALID_ARG;
  delay = pool->retry_base_ms;
  exponent = failure_count - 1u;
  while (exponent > 0u && delay < pool->retry_max_ms) {
    delay = delay > pool->retry_max_ms / 2u ? pool->retry_max_ms : delay * 2u;
    exponent--;
  }
  if (delay > pool->retry_max_ms)
    delay = pool->retry_max_ms;
  if (pool_random(pool, random_bytes, sizeof(random_bytes)) != 0) {
    mesh_mgmt_crypto_wipe(random_bytes, sizeof(random_bytes));
    return MESH_MGMT_ENDPOINT_POOL_RANDOM_FAILED;
  }
  memcpy(&random_value, random_bytes, sizeof(random_value));
  mesh_mgmt_crypto_wipe(random_bytes, sizeof(random_bytes));
  jitter = (uint64_t)random_value % (delay / 4u + 1u);
  if (delay > UINT64_MAX - jitter || now_ms > UINT64_MAX - delay - jitter)
    return MESH_MGMT_ENDPOINT_POOL_RESOURCE_EXHAUSTED;
  *out_deadline = now_ms + delay + jitter;
  return MESH_MGMT_ENDPOINT_POOL_OK;
}

static mesh_mgmt_endpoint_pool_result_t schedule_failure(mesh_mgmt_endpoint_pool_v1_t *pool,
                                                         mesh_mgmt_endpoint_entry_v1_t *entry,
                                                         mesh_mgmt_endpoint_failure_t failure,
                                                         uint64_t now_ms) {
  mesh_mgmt_endpoint_pool_result_t result;
  uint32_t transport_failures = entry->transport_failures;
  uint32_t protocol_failures = entry->protocol_failures;
  uint64_t deadline = 0u;

  if (failure == MESH_MGMT_ENDPOINT_FAILURE_PROTOCOL) {
    if (protocol_failures == UINT32_MAX)
      return MESH_MGMT_ENDPOINT_POOL_RESOURCE_EXHAUSTED;
    protocol_failures++;
    if (protocol_failures >= pool->protocol_failure_limit) {
      entry->protocol_failures = protocol_failures;
      entry->state = MESH_MGMT_ENDPOINT_QUARANTINED;
      entry->next_attempt_ms = 0u;
      entry->connect_deadline_ms = 0u;
      return MESH_MGMT_ENDPOINT_POOL_OK;
    }
  } else if (failure != MESH_MGMT_ENDPOINT_FAILURE_TRANSPORT) {
    return MESH_MGMT_ENDPOINT_POOL_INVALID_ARG;
  }
  if (transport_failures == UINT32_MAX)
    return MESH_MGMT_ENDPOINT_POOL_RESOURCE_EXHAUSTED;
  transport_failures++;
  result = retry_deadline(pool, transport_failures, now_ms, &deadline);
  if (result != MESH_MGMT_ENDPOINT_POOL_OK) {
    entry->transport_failures = transport_failures;
    entry->protocol_failures = protocol_failures;
    entry->state = MESH_MGMT_ENDPOINT_QUARANTINED;
    entry->next_attempt_ms = 0u;
    entry->connect_deadline_ms = 0u;
    return result;
  }

  entry->transport_failures = transport_failures;
  entry->protocol_failures = protocol_failures;
  entry->state = MESH_MGMT_ENDPOINT_BACKOFF;
  entry->next_attempt_ms = deadline;
  entry->connect_deadline_ms = 0u;
  return MESH_MGMT_ENDPOINT_POOL_OK;
}

static void assign_record(mesh_mgmt_endpoint_entry_v1_t *entry,
                          const mesh_mgmt_endpoint_record_v1_t *record) {
  mesh_mgmt_endpoint_state_t previous_state = entry->state;
  uint8_t was_occupied = entry->occupied;

  entry->record = *record;
  entry->occupied = 1u;
  entry->retire_on_close = 0u;
  if (!was_occupied || previous_state == MESH_MGMT_ENDPOINT_EXPIRED) {
    entry->state = MESH_MGMT_ENDPOINT_IDLE;
    entry->next_attempt_ms = 0u;
    entry->connect_deadline_ms = 0u;
    entry->transport_failures = 0u;
    entry->protocol_failures = 0u;
  }
}

mesh_mgmt_endpoint_pool_result_t
mesh_mgmt_endpoint_pool_init_v1(mesh_mgmt_endpoint_pool_v1_t *pool,
                                const mesh_mgmt_endpoint_pool_config_v1_t *config) {
  if (!pool || !config || !config->node || config->capacity == 0u ||
      config->capacity > MESH_MGMT_ENDPOINT_POOL_MAX_ENDPOINTS || config->retry_base_ms == 0u ||
      config->retry_max_ms < config->retry_base_ms ||
      config->retry_max_ms > MESH_MGMT_ENDPOINT_RETRY_MAX_MS || config->connect_timeout_ms == 0u ||
      config->connect_timeout_ms > MESH_MGMT_ENDPOINT_CONNECT_TIMEOUT_MAX_MS ||
      config->protocol_failure_limit == 0u)
    return MESH_MGMT_ENDPOINT_POOL_INVALID_ARG;
  if (pool->initialized || pool->entries.data)
    return MESH_MGMT_ENDPOINT_POOL_INVALID_STATE;

  memset(pool, 0, sizeof(*pool));
  pool->node = config->node;
  pool->capacity = config->capacity;
  pool->retry_base_ms = config->retry_base_ms;
  pool->retry_max_ms = config->retry_max_ms;
  pool->connect_timeout_ms = config->connect_timeout_ms;
  pool->protocol_failure_limit = config->protocol_failure_limit;
  pool->connect_peer = config->connect_peer;
  pool->random_bytes = config->random_bytes;
  pool->callback_context = config->callback_context;
  if (turbo_vec_init(&pool->entries, sizeof(mesh_mgmt_endpoint_entry_v1_t)) != TURBO_OK ||
      turbo_vec_reserve(&pool->entries, pool->capacity) != TURBO_OK ||
      turbo_vec_resize(&pool->entries, pool->capacity) != TURBO_OK) {
    turbo_vec_destroy(&pool->entries);
    memset(pool, 0, sizeof(*pool));
    return MESH_MGMT_ENDPOINT_POOL_RESOURCE_EXHAUSTED;
  }
  memset(turbo_vec_data(&pool->entries), 0, pool->capacity * sizeof(mesh_mgmt_endpoint_entry_v1_t));
  pool->initialized = 1u;
  pool->last_error = MESH_MGMT_ENDPOINT_POOL_OK;
  return MESH_MGMT_ENDPOINT_POOL_OK;
}

void mesh_mgmt_endpoint_pool_destroy_v1(mesh_mgmt_endpoint_pool_v1_t *pool) {
  if (!pool || pool->in_api)
    return;
  if (pool->entries.data) {
    mesh_mgmt_crypto_wipe(turbo_vec_data(&pool->entries),
                          turbo_vec_size(&pool->entries) * sizeof(mesh_mgmt_endpoint_entry_v1_t));
    turbo_vec_destroy(&pool->entries);
  }
  memset(pool, 0, sizeof(*pool));
}

mesh_mgmt_endpoint_pool_result_t
mesh_mgmt_endpoint_pool_add_static_v1(mesh_mgmt_endpoint_pool_v1_t *pool,
                                      const uint8_t transport_peer_id[P2P_KEY_SIZE],
                                      const char *host, uint16_t port) {
  mesh_mgmt_endpoint_entry_v1_t *entry;
  mesh_mgmt_endpoint_record_v1_t record;

  if (!pool || !transport_peer_id || !endpoint_host_is_valid(host) || port == 0u ||
      bytes_are_zero(transport_peer_id, P2P_KEY_SIZE))
    return MESH_MGMT_ENDPOINT_POOL_INVALID_ARG;
  if (!pool->initialized || pool->in_api)
    return MESH_MGMT_ENDPOINT_POOL_INVALID_STATE;
  if (endpoint_conflicts(pool, transport_peer_id, host, port))
    return MESH_MGMT_ENDPOINT_POOL_CONFLICT;

  entry = find_by_identity(pool, transport_peer_id);
  if (!entry) {
    entry = find_free(pool);
    if (!entry)
      return MESH_MGMT_ENDPOINT_POOL_RESOURCE_EXHAUSTED;
    pool->count++;
  }
  memset(&record, 0, sizeof(record));
  memcpy(record.transport_peer_id, transport_peer_id, P2P_KEY_SIZE);
  memcpy(record.host, host, strlen(host) + 1u);
  record.port = port;
  record.source = MESH_MGMT_ENDPOINT_SOURCE_STATIC;
  assign_record(entry, &record);
  pool->last_error = MESH_MGMT_ENDPOINT_POOL_OK;
  return MESH_MGMT_ENDPOINT_POOL_OK;
}

mesh_mgmt_endpoint_pool_result_t
mesh_mgmt_endpoint_pool_apply_verified_v1(mesh_mgmt_endpoint_pool_v1_t *pool,
                                          const mesh_mgmt_endpoint_record_v1_t *record,
                                          uint64_t now_ms) {
  mesh_mgmt_endpoint_entry_v1_t *entry;

  if (!pool || !record || record->source != MESH_MGMT_ENDPOINT_SOURCE_VERIFIED_RECORD ||
      bytes_are_zero(record->transport_peer_id, P2P_KEY_SIZE) ||
      !endpoint_host_is_valid(record->host) || record->port == 0u || record->record_epoch == 0u ||
      record->expires_at_ms == 0u)
    return MESH_MGMT_ENDPOINT_POOL_INVALID_ARG;
  if (!pool->initialized || pool->in_api)
    return MESH_MGMT_ENDPOINT_POOL_INVALID_STATE;
  if (record->expires_at_ms <= now_ms)
    return MESH_MGMT_ENDPOINT_POOL_EXPIRED;
  if (endpoint_conflicts(pool, record->transport_peer_id, record->host, record->port))
    return MESH_MGMT_ENDPOINT_POOL_CONFLICT;

  entry = find_by_identity(pool, record->transport_peer_id);
  if (entry) {
    if (entry->record.source == MESH_MGMT_ENDPOINT_SOURCE_STATIC)
      return MESH_MGMT_ENDPOINT_POOL_CONFLICT;
    if (record->record_epoch < entry->record.record_epoch)
      return MESH_MGMT_ENDPOINT_POOL_STALE;
    if (record->record_epoch == entry->record.record_epoch) {
      return records_are_equal(&entry->record, record) ? MESH_MGMT_ENDPOINT_POOL_OK
                                                       : MESH_MGMT_ENDPOINT_POOL_CONFLICT;
    }
  } else {
    entry = find_free(pool);
    if (!entry)
      return MESH_MGMT_ENDPOINT_POOL_RESOURCE_EXHAUSTED;
    pool->count++;
  }
  assign_record(entry, record);
  pool->last_error = MESH_MGMT_ENDPOINT_POOL_OK;
  return MESH_MGMT_ENDPOINT_POOL_OK;
}

mesh_mgmt_endpoint_pool_result_t
mesh_mgmt_endpoint_pool_start_v1(mesh_mgmt_endpoint_pool_v1_t *pool) {
  if (!pool)
    return MESH_MGMT_ENDPOINT_POOL_INVALID_ARG;
  if (!pool->initialized || pool->running || pool->in_api)
    return MESH_MGMT_ENDPOINT_POOL_INVALID_STATE;
  pool->running = 1u;
  pool->last_error = MESH_MGMT_ENDPOINT_POOL_OK;
  return MESH_MGMT_ENDPOINT_POOL_OK;
}

void mesh_mgmt_endpoint_pool_stop_v1(mesh_mgmt_endpoint_pool_v1_t *pool) {
  if (!pool || !pool->initialized || pool->in_api)
    return;
  pool->running = 0u;
}

mesh_mgmt_endpoint_pool_result_t mesh_mgmt_endpoint_pool_tick_v1(mesh_mgmt_endpoint_pool_v1_t *pool,
                                                                 uint64_t now_ms) {
  size_t index;
  mesh_mgmt_endpoint_pool_result_t result = MESH_MGMT_ENDPOINT_POOL_OK;

  if (!pool)
    return MESH_MGMT_ENDPOINT_POOL_INVALID_ARG;
  if (!pool->initialized || !pool->running || pool->in_api)
    return MESH_MGMT_ENDPOINT_POOL_INVALID_STATE;
  pool->in_api = 1u;
  for (index = 0u; index < pool->capacity; index++) {
    mesh_mgmt_endpoint_entry_v1_t *entry = entry_at(pool, index);

    if (!entry || !entry->occupied)
      continue;
    if (entry->record.source == MESH_MGMT_ENDPOINT_SOURCE_VERIFIED_RECORD &&
        entry->record.expires_at_ms <= now_ms) {
      if (entry->state == MESH_MGMT_ENDPOINT_ACTIVE)
        entry->retire_on_close = 1u;
      else
        entry->state = MESH_MGMT_ENDPOINT_EXPIRED;
      continue;
    }
    if (entry->state == MESH_MGMT_ENDPOINT_DIALING) {
      if (now_ms < entry->connect_deadline_ms)
        continue;
      result = schedule_failure(pool, entry, MESH_MGMT_ENDPOINT_FAILURE_TRANSPORT, now_ms);
      if (result != MESH_MGMT_ENDPOINT_POOL_OK)
        goto failed;
      continue;
    }
    if (entry->state != MESH_MGMT_ENDPOINT_IDLE && entry->state != MESH_MGMT_ENDPOINT_BACKOFF)
      continue;
    if (entry->state == MESH_MGMT_ENDPOINT_BACKOFF && now_ms < entry->next_attempt_ms)
      continue;
    if (now_ms > UINT64_MAX - pool->connect_timeout_ms) {
      result = MESH_MGMT_ENDPOINT_POOL_RESOURCE_EXHAUSTED;
      goto failed;
    }
    entry->last_connect_result = pool_connect(pool, &entry->record);
    if (entry->last_connect_result == P2P_OK) {
      entry->state = MESH_MGMT_ENDPOINT_DIALING;
      entry->connect_deadline_ms = now_ms + pool->connect_timeout_ms;
      entry->next_attempt_ms = 0u;
    } else {
      result = schedule_failure(pool, entry, MESH_MGMT_ENDPOINT_FAILURE_TRANSPORT, now_ms);
      if (result != MESH_MGMT_ENDPOINT_POOL_OK)
        goto failed;
    }
  }
  pool->in_api = 0u;
  pool->last_error = MESH_MGMT_ENDPOINT_POOL_OK;
  return MESH_MGMT_ENDPOINT_POOL_OK;

failed:
  pool->in_api = 0u;
  pool->last_error = result;
  return result;
}

mesh_mgmt_endpoint_pool_result_t
mesh_mgmt_endpoint_pool_mark_authenticated_v1(mesh_mgmt_endpoint_pool_v1_t *pool,
                                              const uint8_t transport_peer_id[P2P_KEY_SIZE],
                                              uint64_t now_ms) {
  mesh_mgmt_endpoint_entry_v1_t *entry;

  if (!pool || !transport_peer_id)
    return MESH_MGMT_ENDPOINT_POOL_INVALID_ARG;
  if (!pool->initialized || pool->in_api)
    return MESH_MGMT_ENDPOINT_POOL_INVALID_STATE;
  entry = find_by_identity(pool, transport_peer_id);
  if (!entry)
    return MESH_MGMT_ENDPOINT_POOL_NOT_FOUND;
  if (entry->record.source == MESH_MGMT_ENDPOINT_SOURCE_VERIFIED_RECORD &&
      entry->record.expires_at_ms <= now_ms)
    return MESH_MGMT_ENDPOINT_POOL_EXPIRED;
  entry->state = MESH_MGMT_ENDPOINT_ACTIVE;
  entry->next_attempt_ms = 0u;
  entry->connect_deadline_ms = 0u;
  entry->transport_failures = 0u;
  entry->protocol_failures = 0u;
  entry->retire_on_close = 0u;
  pool->last_error = MESH_MGMT_ENDPOINT_POOL_OK;
  return MESH_MGMT_ENDPOINT_POOL_OK;
}

mesh_mgmt_endpoint_pool_result_t
mesh_mgmt_endpoint_pool_mark_failed_v1(mesh_mgmt_endpoint_pool_v1_t *pool,
                                       const uint8_t transport_peer_id[P2P_KEY_SIZE],
                                       mesh_mgmt_endpoint_failure_t failure, uint64_t now_ms) {
  mesh_mgmt_endpoint_entry_v1_t *entry;
  mesh_mgmt_endpoint_pool_result_t result;

  if (!pool || !transport_peer_id)
    return MESH_MGMT_ENDPOINT_POOL_INVALID_ARG;
  if (!pool->initialized || pool->in_api)
    return MESH_MGMT_ENDPOINT_POOL_INVALID_STATE;
  entry = find_by_identity(pool, transport_peer_id);
  if (!entry)
    return MESH_MGMT_ENDPOINT_POOL_NOT_FOUND;
  if (!pool->running) {
    entry->state = MESH_MGMT_ENDPOINT_IDLE;
    entry->next_attempt_ms = 0u;
    entry->connect_deadline_ms = 0u;
    return MESH_MGMT_ENDPOINT_POOL_OK;
  }
  if (entry->retire_on_close) {
    entry->state = MESH_MGMT_ENDPOINT_EXPIRED;
    entry->next_attempt_ms = 0u;
    entry->connect_deadline_ms = 0u;
    return MESH_MGMT_ENDPOINT_POOL_EXPIRED;
  }
  result = schedule_failure(pool, entry, failure, now_ms);
  pool->last_error = result;
  return result;
}

mesh_mgmt_endpoint_pool_result_t
mesh_mgmt_endpoint_pool_reset_v1(mesh_mgmt_endpoint_pool_v1_t *pool,
                                 const uint8_t transport_peer_id[P2P_KEY_SIZE]) {
  mesh_mgmt_endpoint_entry_v1_t *entry;

  if (!pool || !transport_peer_id)
    return MESH_MGMT_ENDPOINT_POOL_INVALID_ARG;
  if (!pool->initialized || pool->in_api)
    return MESH_MGMT_ENDPOINT_POOL_INVALID_STATE;
  entry = find_by_identity(pool, transport_peer_id);
  if (!entry)
    return MESH_MGMT_ENDPOINT_POOL_NOT_FOUND;
  if (entry->state == MESH_MGMT_ENDPOINT_EXPIRED)
    return MESH_MGMT_ENDPOINT_POOL_EXPIRED;
  entry->state = MESH_MGMT_ENDPOINT_IDLE;
  entry->next_attempt_ms = 0u;
  entry->connect_deadline_ms = 0u;
  entry->transport_failures = 0u;
  entry->protocol_failures = 0u;
  pool->last_error = MESH_MGMT_ENDPOINT_POOL_OK;
  return MESH_MGMT_ENDPOINT_POOL_OK;
}

mesh_mgmt_endpoint_pool_result_t
mesh_mgmt_endpoint_pool_snapshot_v1(const mesh_mgmt_endpoint_pool_v1_t *pool,
                                    const uint8_t transport_peer_id[P2P_KEY_SIZE],
                                    mesh_mgmt_endpoint_snapshot_v1_t *out_snapshot) {
  size_t index;

  if (out_snapshot)
    memset(out_snapshot, 0, sizeof(*out_snapshot));
  if (!pool || !transport_peer_id || !out_snapshot)
    return MESH_MGMT_ENDPOINT_POOL_INVALID_ARG;
  if (!pool->initialized)
    return MESH_MGMT_ENDPOINT_POOL_INVALID_STATE;
  for (index = 0u; index < pool->capacity; index++) {
    const mesh_mgmt_endpoint_entry_v1_t *entry = entry_at_const(pool, index);
    if (entry && entry->occupied &&
        mesh_mgmt_crypto_equal_32(entry->record.transport_peer_id, transport_peer_id)) {
      out_snapshot->record = entry->record;
      out_snapshot->state = entry->state;
      out_snapshot->next_attempt_ms = entry->next_attempt_ms;
      out_snapshot->connect_deadline_ms = entry->connect_deadline_ms;
      out_snapshot->transport_failures = entry->transport_failures;
      out_snapshot->protocol_failures = entry->protocol_failures;
      out_snapshot->last_connect_result = entry->last_connect_result;
      return MESH_MGMT_ENDPOINT_POOL_OK;
    }
  }
  return MESH_MGMT_ENDPOINT_POOL_NOT_FOUND;
}
