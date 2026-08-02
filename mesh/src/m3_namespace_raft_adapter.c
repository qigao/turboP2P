#include "m3_namespace_raft_adapter.h"

#include <turbo_error.h>

#include <limits.h>
#include <stdlib.h>
#include <string.h>

enum {
  COMMAND_MAGIC_SIZE = 4,
  COMMAND_VERSION_OFFSET = 4,
  COMMAND_TYPE_OFFSET = 5,
  COMMAND_BUCKET_SIZE_OFFSET = 6,
  COMMAND_KEY_SIZE_OFFSET = 8,
  COMMAND_MANIFEST_SIZE_OFFSET = 10,
  COMMAND_TENANT_OFFSET = 12,
  COMMAND_HEADER_SIZE = COMMAND_TENANT_OFFSET +
                        M3_CHUNK_CAPABILITY_TENANT_ID_SIZE,
};

static const uint8_t COMMAND_MAGIC[COMMAND_MAGIC_SIZE] = {'M', '3', 'N', 'S'};
static const uint64_t READ_CONTEXT_PREFIX = UINT64_C(0x4d33000000000000);
static const uint64_t READ_CONTEXT_SEQUENCE_MASK = UINT64_C(0x0000ffffffffffff);

typedef struct {
  uint8_t active;
  uint64_t context_id;
  uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE];
  uint8_t key_bytes[TR_RAFT_MAX_ENTRY_BYTES];
  size_t bucket_size;
  size_t object_key_size;
  m3_namespace_lookup_complete_cb complete_cb;
  void *user_data;
} m3_namespace_pending_read_v1_t;

struct m3_namespace_raft_adapter_s {
  m3_namespace_local_store_v1_t *store;
  tr_raft_service_t *service;
  m3_namespace_pending_read_v1_t *pending;
  size_t pending_capacity;
  size_t pending_count;
  uint64_t next_read_sequence;
  uint8_t open;
};

static void write_u16(uint8_t *output, uint16_t value) {
  output[0] = (uint8_t)(value >> 8u);
  output[1] = (uint8_t)value;
}

static uint16_t read_u16(const uint8_t *input) {
  return (uint16_t)(((uint16_t)input[0] << 8u) | input[1]);
}

static int checked_frame_size(size_t bucket_size, size_t object_key_size,
                              size_t manifest_size, size_t *out_size) {
  size_t size = COMMAND_HEADER_SIZE;

  if (!out_size || bucket_size == 0u || object_key_size == 0u ||
      bucket_size > UINT16_MAX || object_key_size > UINT16_MAX ||
      manifest_size > UINT16_MAX || bucket_size > SIZE_MAX - size) {
    return TURBO_EINVAL;
  }
  size += bucket_size;
  if (object_key_size > SIZE_MAX - size) {
    return TURBO_EINVAL;
  }
  size += object_key_size;
  if (manifest_size > SIZE_MAX - size) {
    return TURBO_EINVAL;
  }
  size += manifest_size;
  if (size > TR_RAFT_MAX_ENTRY_BYTES) {
    return TURBO_EINVAL;
  }
  *out_size = size;
  return TURBO_OK;
}

int m3_namespace_raft_command_encode_v1(
    const m3_namespace_raft_command_v1_t *command, uint8_t *output,
    size_t output_capacity, size_t *out_size) {
  size_t size;
  uint8_t *cursor;

  if (!out_size) {
    return TURBO_EINVAL;
  }
  *out_size = 0u;
  if (!command || !output || !command->bucket || !command->object_key ||
      (command->type != M3_NAMESPACE_RAFT_COMMAND_PUT &&
       command->type != M3_NAMESPACE_RAFT_COMMAND_TOMBSTONE) ||
      (command->type == M3_NAMESPACE_RAFT_COMMAND_PUT &&
       (!command->manifest_bytes || command->manifest_size == 0u)) ||
      (command->type == M3_NAMESPACE_RAFT_COMMAND_TOMBSTONE &&
       (command->manifest_bytes || command->manifest_size != 0u))) {
    return TURBO_EINVAL;
  }
  if (checked_frame_size(command->bucket_size, command->object_key_size,
                         command->manifest_size, &size) != TURBO_OK ||
      output_capacity < size) {
    return TURBO_EINVAL;
  }

  memcpy(output, COMMAND_MAGIC, sizeof(COMMAND_MAGIC));
  output[COMMAND_VERSION_OFFSET] = M3_NAMESPACE_RAFT_COMMAND_VERSION;
  output[COMMAND_TYPE_OFFSET] = (uint8_t)command->type;
  write_u16(output + COMMAND_BUCKET_SIZE_OFFSET,
            (uint16_t)command->bucket_size);
  write_u16(output + COMMAND_KEY_SIZE_OFFSET,
            (uint16_t)command->object_key_size);
  write_u16(output + COMMAND_MANIFEST_SIZE_OFFSET,
            (uint16_t)command->manifest_size);
  memcpy(output + COMMAND_TENANT_OFFSET, command->tenant_id,
         sizeof(command->tenant_id));
  cursor = output + COMMAND_HEADER_SIZE;
  memcpy(cursor, command->bucket, command->bucket_size);
  cursor += command->bucket_size;
  memcpy(cursor, command->object_key, command->object_key_size);
  cursor += command->object_key_size;
  if (command->manifest_size != 0u) {
    memcpy(cursor, command->manifest_bytes, command->manifest_size);
  }
  *out_size = size;
  return TURBO_OK;
}

int m3_namespace_raft_command_decode_v1(
    const uint8_t *bytes, size_t size,
    m3_namespace_raft_command_v1_t *out_command) {
  m3_namespace_raft_command_v1_t decoded;
  size_t expected_size;

  if (!bytes || !out_command || size < COMMAND_HEADER_SIZE ||
      size > TR_RAFT_MAX_ENTRY_BYTES ||
      memcmp(bytes, COMMAND_MAGIC, sizeof(COMMAND_MAGIC)) != 0 ||
      bytes[COMMAND_VERSION_OFFSET] != M3_NAMESPACE_RAFT_COMMAND_VERSION) {
    return TURBO_EPROTO;
  }
  memset(&decoded, 0, sizeof(decoded));
  decoded.type = (m3_namespace_raft_command_type_t)bytes[COMMAND_TYPE_OFFSET];
  decoded.bucket_size = read_u16(bytes + COMMAND_BUCKET_SIZE_OFFSET);
  decoded.object_key_size = read_u16(bytes + COMMAND_KEY_SIZE_OFFSET);
  decoded.manifest_size = read_u16(bytes + COMMAND_MANIFEST_SIZE_OFFSET);
  if ((decoded.type != M3_NAMESPACE_RAFT_COMMAND_PUT &&
       decoded.type != M3_NAMESPACE_RAFT_COMMAND_TOMBSTONE) ||
      (decoded.type == M3_NAMESPACE_RAFT_COMMAND_PUT &&
       decoded.manifest_size == 0u) ||
      (decoded.type == M3_NAMESPACE_RAFT_COMMAND_TOMBSTONE &&
       decoded.manifest_size != 0u) ||
      checked_frame_size(decoded.bucket_size, decoded.object_key_size,
                         decoded.manifest_size, &expected_size) != TURBO_OK ||
      expected_size != size) {
    return TURBO_EPROTO;
  }

  memcpy(decoded.tenant_id, bytes + COMMAND_TENANT_OFFSET,
         sizeof(decoded.tenant_id));
  decoded.bucket = bytes + COMMAND_HEADER_SIZE;
  decoded.object_key = decoded.bucket + decoded.bucket_size;
  decoded.manifest_bytes = decoded.manifest_size == 0u
                               ? NULL
                               : decoded.object_key + decoded.object_key_size;
  *out_command = decoded;
  return TURBO_OK;
}

static int map_store_result(m3_namespace_local_result_t result) {
  switch (result) {
  case M3_NAMESPACE_LOCAL_OK:
    return TURBO_OK;
  case M3_NAMESPACE_LOCAL_INVALID_ARG:
    return TURBO_EINVAL;
  case M3_NAMESPACE_LOCAL_RESOURCE_EXHAUSTED:
    return TURBO_ENOMEM;
  case M3_NAMESPACE_LOCAL_INVALID_STATE:
  case M3_NAMESPACE_LOCAL_OUT_OF_ORDER:
  case M3_NAMESPACE_LOCAL_CORRUPT:
  default:
    return TURBO_EPROTO;
  }
}

static int apply_batch(void *context, const tr_raft_entry_t *entries,
                       size_t entry_count) {
  m3_namespace_raft_adapter_v1_t *adapter =
      (m3_namespace_raft_adapter_v1_t *)context;

  if (!adapter || !adapter->open || !adapter->store || !entries ||
      entry_count == 0u) {
    return TURBO_EINVAL;
  }
  for (size_t i = 0u; i < entry_count; ++i) {
    m3_namespace_raft_command_v1_t command;
    m3_namespace_local_result_t result;
    int decode_result = m3_namespace_raft_command_decode_v1(
        entries[i].data, entries[i].data_length, &command);

    if (decode_result != TURBO_OK) {
      return decode_result;
    }
    if (command.type == M3_NAMESPACE_RAFT_COMMAND_PUT) {
      result = m3_namespace_local_store_apply_put_v1(
          adapter->store, entries[i].index, command.tenant_id, command.bucket,
          command.bucket_size, command.object_key, command.object_key_size,
          command.manifest_bytes, command.manifest_size);
    } else {
      result = m3_namespace_local_store_apply_tombstone_v1(
          adapter->store, entries[i].index, command.tenant_id, command.bucket,
          command.bucket_size, command.object_key, command.object_key_size);
    }
    if (result != M3_NAMESPACE_LOCAL_OK) {
      return map_store_result(result);
    }
  }
  return TURBO_OK;
}

int m3_namespace_raft_adapter_create_v1(
    m3_namespace_local_store_v1_t *store, size_t max_pending_reads,
    m3_namespace_raft_adapter_v1_t **out_adapter) {
  m3_namespace_raft_adapter_v1_t *adapter;

  if (!out_adapter) {
    return TURBO_EINVAL;
  }
  *out_adapter = NULL;
  if (!store || !store->open || max_pending_reads == 0u ||
      max_pending_reads > M3_NAMESPACE_RAFT_MAX_PENDING_READS ||
      max_pending_reads > SIZE_MAX / sizeof(m3_namespace_pending_read_v1_t)) {
    return TURBO_EINVAL;
  }
  adapter = (m3_namespace_raft_adapter_v1_t *)calloc(1u, sizeof(*adapter));
  if (!adapter) {
    return TURBO_ENOMEM;
  }
  adapter->pending = (m3_namespace_pending_read_v1_t *)calloc(
      max_pending_reads, sizeof(*adapter->pending));
  if (!adapter->pending) {
    free(adapter);
    return TURBO_ENOMEM;
  }
  adapter->store = store;
  adapter->pending_capacity = max_pending_reads;
  adapter->open = 1u;
  *out_adapter = adapter;
  return TURBO_OK;
}

void m3_namespace_raft_adapter_destroy_v1(
    m3_namespace_raft_adapter_v1_t *adapter) {
  if (!adapter) {
    return;
  }
  if (adapter->pending) {
    memset(adapter->pending, 0,
           adapter->pending_capacity * sizeof(*adapter->pending));
    free(adapter->pending);
  }
  memset(adapter, 0, sizeof(*adapter));
  free(adapter);
}

tr_raft_state_machine_t m3_namespace_raft_state_machine_v1(
    m3_namespace_raft_adapter_v1_t *adapter) {
  tr_raft_state_machine_t state_machine;

  memset(&state_machine, 0, sizeof(state_machine));
  if (adapter && adapter->open) {
    state_machine.context = adapter;
    state_machine.apply_batch = apply_batch;
  }
  return state_machine;
}

int m3_namespace_raft_adapter_bind_service_v1(
    m3_namespace_raft_adapter_v1_t *adapter, tr_raft_service_t *service) {
  if (!adapter || !adapter->open || !service ||
      (adapter->service && adapter->service != service)) {
    return TURBO_EINVAL;
  }
  adapter->service = service;
  return TURBO_OK;
}

static m3_namespace_pending_read_v1_t *find_pending_by_context(
    m3_namespace_raft_adapter_v1_t *adapter, uint64_t context_id) {
  for (size_t i = 0u; i < adapter->pending_capacity; ++i) {
    if (adapter->pending[i].active &&
        adapter->pending[i].context_id == context_id) {
      return &adapter->pending[i];
    }
  }
  return NULL;
}

static uint64_t allocate_context_id(m3_namespace_raft_adapter_v1_t *adapter) {
  for (size_t attempt = 0u; attempt <= adapter->pending_count; ++attempt) {
    uint64_t context_id;

    adapter->next_read_sequence =
        (adapter->next_read_sequence + 1u) & READ_CONTEXT_SEQUENCE_MASK;
    if (adapter->next_read_sequence == 0u) {
      adapter->next_read_sequence = 1u;
    }
    context_id = READ_CONTEXT_PREFIX | adapter->next_read_sequence;
    if (!find_pending_by_context(adapter, context_id)) {
      return context_id;
    }
  }
  return 0u;
}

static m3_namespace_lookup_result_t lookup_start(
    void *context, const m3_namespace_lookup_request_v1_t *request,
    m3_namespace_lookup_complete_cb complete_cb, void *user_data) {
  m3_namespace_raft_adapter_v1_t *adapter =
      (m3_namespace_raft_adapter_v1_t *)context;
  m3_namespace_pending_read_v1_t *slot = NULL;
  size_t key_size;
  int result;

  if (!adapter || !adapter->open || !adapter->service || !request ||
      !complete_cb || !request->bucket || request->bucket_size == 0u ||
      !request->object_key || request->object_key_size == 0u ||
      !request->require_linearizable ||
      request->bucket_size > SIZE_MAX - request->object_key_size) {
    return M3_NAMESPACE_LOOKUP_INVALID_ARG;
  }
  key_size = request->bucket_size + request->object_key_size;
  if (key_size > TR_RAFT_MAX_ENTRY_BYTES) {
    return M3_NAMESPACE_LOOKUP_RESOURCE_EXHAUSTED;
  }
  for (size_t i = 0u; i < adapter->pending_capacity; ++i) {
    if (!adapter->pending[i].active) {
      slot = &adapter->pending[i];
      break;
    }
  }
  if (!slot) {
    return M3_NAMESPACE_LOOKUP_RESOURCE_EXHAUSTED;
  }

  slot->context_id = allocate_context_id(adapter);
  if (slot->context_id == 0u) {
    return M3_NAMESPACE_LOOKUP_RESOURCE_EXHAUSTED;
  }
  slot->active = 1u;
  memcpy(slot->tenant_id, request->tenant_id, sizeof(slot->tenant_id));
  memcpy(slot->key_bytes, request->bucket, request->bucket_size);
  memcpy(slot->key_bytes + request->bucket_size, request->object_key,
         request->object_key_size);
  slot->bucket_size = request->bucket_size;
  slot->object_key_size = request->object_key_size;
  slot->complete_cb = complete_cb;
  slot->user_data = user_data;
  ++adapter->pending_count;

  result = tr_raft_service_read_index(adapter->service, slot->context_id);
  if (result != TURBO_OK) {
    memset(slot, 0, sizeof(*slot));
    --adapter->pending_count;
    return result == TURBO_EINVAL ? M3_NAMESPACE_LOOKUP_INVALID_ARG
                                 : M3_NAMESPACE_LOOKUP_UNAVAILABLE;
  }
  return M3_NAMESPACE_LOOKUP_OK;
}

m3_namespace_lookup_adapter_v1_t m3_namespace_raft_lookup_adapter_v1(
    m3_namespace_raft_adapter_v1_t *adapter) {
  m3_namespace_lookup_adapter_v1_t lookup;

  memset(&lookup, 0, sizeof(lookup));
  if (adapter && adapter->open) {
    lookup.context = adapter;
    lookup.start = lookup_start;
  }
  return lookup;
}

typedef struct {
  m3_namespace_raft_adapter_v1_t *adapter;
  m3_namespace_pending_read_v1_t *pending;
  uint64_t safe_index;
  uint8_t called;
} lookup_bridge_v1_t;

static void complete_linearizable_lookup(
    m3_namespace_lookup_result_t result,
    const m3_namespace_lookup_response_v1_t *response, void *user_data) {
  lookup_bridge_v1_t *bridge = (lookup_bridge_v1_t *)user_data;
  m3_namespace_lookup_complete_cb complete_cb = bridge->pending->complete_cb;
  void *complete_user_data = bridge->pending->user_data;
  m3_namespace_lookup_response_v1_t safe_response;

  bridge->called = 1u;
  memset(bridge->pending, 0, sizeof(*bridge->pending));
  --bridge->adapter->pending_count;
  if (result != M3_NAMESPACE_LOOKUP_OK || !response) {
    complete_cb(result, NULL, complete_user_data);
    return;
  }
  safe_response = *response;
  safe_response.applied_index = bridge->safe_index;
  safe_response.linearizable = 1u;
  complete_cb(M3_NAMESPACE_LOOKUP_OK, &safe_response, complete_user_data);
}

int m3_namespace_raft_adapter_poll_v1(
    m3_namespace_raft_adapter_v1_t *adapter, size_t *out_completed) {
  size_t completed = 0u;

  if (!out_completed) {
    return TURBO_EINVAL;
  }
  *out_completed = 0u;
  if (!adapter || !adapter->open || !adapter->service || !adapter->store) {
    return TURBO_EINVAL;
  }
  for (;;) {
    tr_raft_read_state_t read_state;
    m3_namespace_pending_read_v1_t *pending;
    m3_namespace_lookup_request_v1_t request;
    m3_namespace_lookup_adapter_v1_t local_lookup;
    lookup_bridge_v1_t bridge;
    m3_namespace_lookup_result_t lookup_result;
    m3_namespace_lookup_complete_cb failed_cb;
    void *failed_user_data;
    int result = tr_raft_service_take_read_state(adapter->service, &read_state);

    if (result == TURBO_ENOENT) {
      *out_completed = completed;
      return TURBO_OK;
    }
    if (result != TURBO_OK) {
      return result;
    }
    pending = find_pending_by_context(adapter, read_state.context_id);
    if (!pending) {
      return TURBO_EPROTO;
    }

    memset(&request, 0, sizeof(request));
    memcpy(request.tenant_id, pending->tenant_id, sizeof(request.tenant_id));
    request.bucket = pending->key_bytes;
    request.bucket_size = pending->bucket_size;
    request.object_key = pending->key_bytes + pending->bucket_size;
    request.object_key_size = pending->object_key_size;
    request.require_linearizable = 1u;
    bridge.adapter = adapter;
    bridge.pending = pending;
    bridge.safe_index = read_state.index;
    bridge.called = 0u;
    local_lookup = m3_namespace_local_store_adapter_v1(adapter->store);
    lookup_result = local_lookup.start(local_lookup.context, &request,
                                       complete_linearizable_lookup, &bridge);
    if (lookup_result != M3_NAMESPACE_LOOKUP_OK) {
      failed_cb = pending->complete_cb;
      failed_user_data = pending->user_data;
      memset(pending, 0, sizeof(*pending));
      --adapter->pending_count;
      failed_cb(lookup_result, NULL, failed_user_data);
    } else if (!bridge.called) {
      return TURBO_EPROTO;
    }
    ++completed;
  }
}

int m3_namespace_raft_propose_v1(
    m3_namespace_raft_adapter_v1_t *adapter, uint64_t command_id,
    const m3_namespace_raft_command_v1_t *command,
    tr_raft_operation_status_t *out_receipt) {
  uint8_t bytes[TR_RAFT_MAX_ENTRY_BYTES];
  size_t size = 0u;
  tr_raft_proposal_t proposal;
  int result;

  if (!adapter || !adapter->open || !adapter->service || command_id == 0u ||
      !out_receipt) {
    return TURBO_EINVAL;
  }
  result = m3_namespace_raft_command_encode_v1(command, bytes, sizeof(bytes),
                                               &size);
  if (result != TURBO_OK) {
    return result;
  }
  proposal.command_id = command_id;
  proposal.data = bytes;
  proposal.data_length = size;
  return tr_raft_service_propose_with_receipt(adapter->service, &proposal,
                                              out_receipt);
}
