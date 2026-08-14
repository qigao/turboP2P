#include "mesh_control_checkpoint.h"

#include <limits.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

#define CHECKPOINT_HEADER_SIZE 256u
#define CHECKPOINT_DIGEST_OFFSET 224u
#define CHECKPOINT_DIGEST_SIZE 32u
#define CHECKPOINT_RESOURCE_HEADER_SIZE 128u
#define CHECKPOINT_OPERATION_SIZE 152u
#define CHECKPOINT_EVENT_SIZE 80u
#define CHECKPOINT_REPLAY_ENTRY_SIZE 24u
#define CHECKPOINT_FLAG_REPLAY_HAS_SEQUENCE (1u << 0)
#define CHECKPOINT_FLAG_REPLAY_BOUND (1u << 1)
#define CHECKPOINT_KNOWN_FLAGS (CHECKPOINT_FLAG_REPLAY_HAS_SEQUENCE | CHECKPOINT_FLAG_REPLAY_BOUND)

static const uint8_t checkpoint_magic[8] = {'T', 'M', 'C', 'T', 'R', 'L', '0', '1'};

typedef struct {
  mesh_control_state_resource_record_v1_t *resources;
  mesh_control_state_operation_record_v1_t *operations;
  mesh_control_event_v1_t *events;
  mesh_mgmt_replay_entry_v1_t *replay_entries;
  mesh_control_state_checkpoint_info_v1_t state_info;
  mesh_mgmt_replay_snapshot_v1_t replay_snapshot;
} checkpoint_capture_v1_t;

static void write_u16(uint8_t *output, uint16_t value) {
  output[0] = (uint8_t)(value >> 8u);
  output[1] = (uint8_t)value;
}

static void write_u32(uint8_t *output, uint32_t value) {
  output[0] = (uint8_t)(value >> 24u);
  output[1] = (uint8_t)(value >> 16u);
  output[2] = (uint8_t)(value >> 8u);
  output[3] = (uint8_t)value;
}

static void write_u64(uint8_t *output, uint64_t value) {
  write_u32(output, (uint32_t)(value >> 32u));
  write_u32(output + 4u, (uint32_t)value);
}

static uint16_t read_u16(const uint8_t *input) {
  return (uint16_t)(((uint16_t)input[0] << 8u) | (uint16_t)input[1]);
}

static uint32_t read_u32(const uint8_t *input) {
  return ((uint32_t)input[0] << 24u) | ((uint32_t)input[1] << 16u) | ((uint32_t)input[2] << 8u) |
         (uint32_t)input[3];
}

static uint64_t read_u64(const uint8_t *input) {
  return ((uint64_t)read_u32(input) << 32u) | (uint64_t)read_u32(input + 4u);
}

static int bytes_zero(const uint8_t *bytes, size_t size) {
  uint8_t aggregate = 0u;
  size_t index;
  for (index = 0u; index < size; ++index)
    aggregate |= bytes[index];
  return aggregate == 0u;
}

static int checked_add_size(size_t left, size_t right, size_t *out) {
  if (!out || left > SIZE_MAX - right)
    return 0;
  *out = left + right;
  return 1;
}

static int checked_multiply_size(size_t left, size_t right, size_t *out) {
  if (!out || (left != 0u && right > SIZE_MAX / left))
    return 0;
  *out = left * right;
  return 1;
}

static int checkpoint_digest(const uint8_t *bytes, size_t size,
                             uint8_t output[CHECKPOINT_DIGEST_SIZE]) {
  EVP_MD_CTX *context = NULL;
  unsigned int digest_size = 0u;
  uint8_t zeros[CHECKPOINT_DIGEST_SIZE] = {0};
  int result = 0;

  if (!bytes || size < CHECKPOINT_HEADER_SIZE || !output)
    return 0;
  context = EVP_MD_CTX_new();
  if (!context)
    return 0;
  if (EVP_DigestInit_ex(context, EVP_sha256(), NULL) == 1 &&
      EVP_DigestUpdate(context, bytes, CHECKPOINT_DIGEST_OFFSET) == 1 &&
      EVP_DigestUpdate(context, zeros, sizeof(zeros)) == 1 &&
      EVP_DigestUpdate(context, bytes + CHECKPOINT_HEADER_SIZE, size - CHECKPOINT_HEADER_SIZE) ==
          1 &&
      EVP_DigestFinal_ex(context, output, &digest_size) == 1 &&
      digest_size == CHECKPOINT_DIGEST_SIZE) {
    result = 1;
  }
  EVP_MD_CTX_free(context);
  return result;
}

static void capture_destroy(checkpoint_capture_v1_t *capture) {
  if (!capture)
    return;
  free(capture->resources);
  free(capture->operations);
  free(capture->events);
  free(capture->replay_entries);
  memset(capture, 0, sizeof(*capture));
}

static int allocate_array(size_t count, size_t element_size, void **output) {
  size_t bytes;
  if (!output || !checked_multiply_size(count, element_size, &bytes))
    return 0;
  *output = count == 0u ? NULL : calloc(1u, bytes);
  return count == 0u || *output != NULL;
}

static mesh_control_checkpoint_result_t capture_owner(const mesh_control_owner_v1_t *owner,
                                                      checkpoint_capture_v1_t *capture) {
  mesh_control_state_usage_v1_t usage;
  mesh_mgmt_replay_result_t replay_result;

  if (!owner || !capture || owner->initialized == 0u || owner->preparation_active ||
      mesh_control_state_get_usage_v1(&owner->state, &usage) != MESH_CONTROL_OK) {
    return MESH_CONTROL_CHECKPOINT_INVALID_ARG;
  }
  memset(capture, 0, sizeof(*capture));
  if (!allocate_array(usage.resource_count, sizeof(*capture->resources),
                      (void **)&capture->resources) ||
      !allocate_array(usage.operation_count, sizeof(*capture->operations),
                      (void **)&capture->operations) ||
      !allocate_array(usage.event_count, sizeof(*capture->events), (void **)&capture->events)) {
    capture_destroy(capture);
    return MESH_CONTROL_CHECKPOINT_RESOURCE_EXHAUSTED;
  }
  if (mesh_control_state_export_v1(&owner->state, capture->resources, usage.resource_count,
                                   capture->operations, usage.operation_count, capture->events,
                                   usage.event_count, &capture->state_info) != MESH_CONTROL_OK) {
    capture_destroy(capture);
    return MESH_CONTROL_CHECKPOINT_INVALID_STATE;
  }

  replay_result = mesh_mgmt_replay_export_v1(&owner->replay, NULL, 0u, &capture->replay_snapshot);
  if (replay_result != MESH_MGMT_REPLAY_OK &&
      replay_result != MESH_MGMT_REPLAY_RESOURCE_EXHAUSTED) {
    capture_destroy(capture);
    return MESH_CONTROL_CHECKPOINT_INVALID_STATE;
  }
  if (!allocate_array(capture->replay_snapshot.entry_count, sizeof(*capture->replay_entries),
                      (void **)&capture->replay_entries)) {
    capture_destroy(capture);
    return MESH_CONTROL_CHECKPOINT_RESOURCE_EXHAUSTED;
  }
  if (mesh_mgmt_replay_export_v1(&owner->replay, capture->replay_entries,
                                 capture->replay_snapshot.entry_count,
                                 &capture->replay_snapshot) != MESH_MGMT_REPLAY_OK) {
    capture_destroy(capture);
    return MESH_CONTROL_CHECKPOINT_INVALID_STATE;
  }
  return MESH_CONTROL_CHECKPOINT_OK;
}

static int calculate_sizes(const checkpoint_capture_v1_t *capture,
                           size_t *out_resource_section_size, size_t *out_total_size) {
  size_t resource_size = 0u;
  size_t section_size;
  size_t total = CHECKPOINT_HEADER_SIZE;
  size_t index;

  if (!capture || !out_resource_section_size || !out_total_size)
    return 0;
  for (index = 0u; index < capture->state_info.resource_count; ++index) {
    if (capture->resources[index].document_size > UINT32_MAX ||
        !checked_add_size(CHECKPOINT_RESOURCE_HEADER_SIZE, capture->resources[index].document_size,
                          &section_size) ||
        !checked_add_size(resource_size, section_size, &resource_size)) {
      return 0;
    }
  }
  if (!checked_add_size(total, resource_size, &total) ||
      !checked_multiply_size(capture->state_info.operation_count, CHECKPOINT_OPERATION_SIZE,
                             &section_size) ||
      !checked_add_size(total, section_size, &total) ||
      !checked_multiply_size(capture->state_info.event_count, CHECKPOINT_EVENT_SIZE,
                             &section_size) ||
      !checked_add_size(total, section_size, &total) ||
      !checked_multiply_size(capture->replay_snapshot.entry_count, CHECKPOINT_REPLAY_ENTRY_SIZE,
                             &section_size) ||
      !checked_add_size(total, section_size, &total)) {
    return 0;
  }
  *out_resource_section_size = resource_size;
  *out_total_size = total;
  return 1;
}

static uint8_t *encode_resource(uint8_t *output,
                                const mesh_control_state_resource_record_v1_t *record) {
  write_u16(output, record->status.resource_kind);
  write_u16(output + 2u, record->status.desired_presence);
  write_u16(output + 4u, record->status.observed_presence);
  write_u32(output + 8u, (uint32_t)record->document_size);
  write_u64(output + 16u, record->status.desired_epoch);
  write_u64(output + 24u, record->status.observed_epoch);
  memcpy(output + 32u, record->status.resource_id, MESH_CONTROL_DIGEST_SIZE);
  memcpy(output + 64u, record->status.desired_digest, MESH_CONTROL_DIGEST_SIZE);
  memcpy(output + 96u, record->status.observed_digest, MESH_CONTROL_DIGEST_SIZE);
  if (record->document_size != 0u) {
    memcpy(output + CHECKPOINT_RESOURCE_HEADER_SIZE, record->document, record->document_size);
  }
  return output + CHECKPOINT_RESOURCE_HEADER_SIZE + record->document_size;
}

static uint8_t *encode_operation(uint8_t *output,
                                 const mesh_control_state_operation_record_v1_t *record) {
  const mesh_control_operation_v1_t *operation = &record->operation;
  memcpy(output, operation->operation_id, MESH_CONTROL_ID_SIZE);
  memcpy(output + 16u, operation->request_id, MESH_CONTROL_ID_SIZE);
  memcpy(output + 32u, operation->message_id, MESH_CONTROL_ID_SIZE);
  write_u16(output + 48u, operation->resource_kind);
  write_u16(output + 50u, operation->action);
  write_u16(output + 52u, operation->state);
  memcpy(output + 56u, operation->resource_id, MESH_CONTROL_DIGEST_SIZE);
  memcpy(output + 88u, operation->desired_digest, MESH_CONTROL_DIGEST_SIZE);
  write_u64(output + 120u, operation->desired_epoch);
  write_u64(output + 128u, operation->created_at_ms);
  write_u64(output + 136u, operation->updated_at_ms);
  write_u64(output + 144u, record->terminal_expires_at_ms);
  return output + CHECKPOINT_OPERATION_SIZE;
}

static uint8_t *encode_event(uint8_t *output, const mesh_control_event_v1_t *event) {
  write_u64(output, event->cursor);
  memcpy(output + 8u, event->operation_id, MESH_CONTROL_ID_SIZE);
  write_u16(output + 24u, event->resource_kind);
  write_u16(output + 26u, event->operation_state);
  memcpy(output + 32u, event->resource_id, MESH_CONTROL_DIGEST_SIZE);
  write_u64(output + 64u, event->desired_epoch);
  write_u64(output + 72u, event->recorded_at_ms);
  return output + CHECKPOINT_EVENT_SIZE;
}

mesh_control_checkpoint_result_t
mesh_control_checkpoint_encode_v1(const mesh_control_owner_v1_t *owner, uint8_t **out_bytes,
                                  size_t *out_size) {
  checkpoint_capture_v1_t capture;
  mesh_control_checkpoint_result_t result;
  uint8_t digest[CHECKPOINT_DIGEST_SIZE];
  uint8_t *bytes = NULL;
  uint8_t *cursor;
  size_t resource_section_size;
  size_t total_size;
  size_t index;
  uint32_t flags = 0u;

  if (!out_bytes || !out_size)
    return MESH_CONTROL_CHECKPOINT_INVALID_ARG;
  *out_bytes = NULL;
  *out_size = 0u;
  result = capture_owner(owner, &capture);
  if (result != MESH_CONTROL_CHECKPOINT_OK)
    return result;
  if (capture.state_info.resource_count > UINT32_MAX ||
      capture.state_info.operation_count > UINT32_MAX ||
      capture.state_info.event_count > UINT32_MAX ||
      capture.replay_snapshot.entry_count > UINT32_MAX ||
      !calculate_sizes(&capture, &resource_section_size, &total_size) ||
      total_size > MESH_CONTROL_CHECKPOINT_MAX_SIZE_V1) {
    result = MESH_CONTROL_CHECKPOINT_RESOURCE_EXHAUSTED;
    goto cleanup;
  }
  bytes = (uint8_t *)calloc(1u, total_size);
  if (!bytes) {
    result = MESH_CONTROL_CHECKPOINT_RESOURCE_EXHAUSTED;
    goto cleanup;
  }

  if (capture.replay_snapshot.has_sequence)
    flags |= CHECKPOINT_FLAG_REPLAY_HAS_SEQUENCE;
  if (capture.replay_snapshot.bound)
    flags |= CHECKPOINT_FLAG_REPLAY_BOUND;
  memcpy(bytes, checkpoint_magic, sizeof(checkpoint_magic));
  write_u32(bytes + 8u, MESH_CONTROL_CHECKPOINT_VERSION_V2);
  write_u32(bytes + 12u, CHECKPOINT_HEADER_SIZE);
  write_u64(bytes + 16u, total_size);
  write_u32(bytes + 24u, (uint32_t)capture.state_info.resource_count);
  write_u32(bytes + 28u, (uint32_t)capture.state_info.operation_count);
  write_u32(bytes + 32u, (uint32_t)capture.state_info.event_count);
  write_u32(bytes + 36u, (uint32_t)capture.replay_snapshot.entry_count);
  write_u64(bytes + 40u, capture.state_info.snapshot_generation);
  write_u64(bytes + 48u, capture.state_info.next_event_cursor);
  write_u64(bytes + 56u, capture.replay_snapshot.last_sequence);
  write_u64(bytes + 64u, capture.replay_snapshot.generation);
  write_u32(bytes + 72u, flags);
  memcpy(bytes + 80u, owner->config.mesh_id, MESH_CONTROL_DIGEST_SIZE);
  memcpy(bytes + 112u, owner->config.node_id, MESH_CONTROL_NODE_ID_SIZE);
  memcpy(bytes + 144u, capture.replay_snapshot.binding.principal_key,
         sizeof(capture.replay_snapshot.binding.principal_key));
  write_u64(bytes + 176u, capture.replay_snapshot.binding.principal_epoch);
  write_u64(bytes + 184u, capture.replay_snapshot.binding.incarnation);
  memcpy(bytes + 192u, capture.replay_snapshot.binding.session_id,
         sizeof(capture.replay_snapshot.binding.session_id));
  write_u64(bytes + 208u, resource_section_size);
  write_u64(bytes + 216u, owner->committed_log_index);

  cursor = bytes + CHECKPOINT_HEADER_SIZE;
  for (index = 0u; index < capture.state_info.resource_count; ++index)
    cursor = encode_resource(cursor, &capture.resources[index]);
  for (index = 0u; index < capture.state_info.operation_count; ++index)
    cursor = encode_operation(cursor, &capture.operations[index]);
  for (index = 0u; index < capture.state_info.event_count; ++index)
    cursor = encode_event(cursor, &capture.events[index]);
  for (index = 0u; index < capture.replay_snapshot.entry_count; ++index) {
    memcpy(cursor, capture.replay_entries[index].message_id, MESH_CONTROL_ID_SIZE);
    write_u64(cursor + 16u, capture.replay_entries[index].expires_at_ms);
    cursor += CHECKPOINT_REPLAY_ENTRY_SIZE;
  }
  if ((size_t)(cursor - bytes) != total_size || !checkpoint_digest(bytes, total_size, digest)) {
    result = MESH_CONTROL_CHECKPOINT_INVALID_STATE;
    goto cleanup;
  }
  memcpy(bytes + CHECKPOINT_DIGEST_OFFSET, digest, sizeof(digest));
  *out_bytes = bytes;
  *out_size = total_size;
  bytes = NULL;
  result = MESH_CONTROL_CHECKPOINT_OK;

cleanup:
  free(bytes);
  capture_destroy(&capture);
  return result;
}

static int owner_unused(const mesh_control_owner_v1_t *owner) {
  mesh_control_state_usage_v1_t usage;
  mesh_control_channel_stats_v1_t channel_stats;
  mesh_mgmt_replay_snapshot_v1_t replay_snapshot;
  mesh_mgmt_replay_result_t replay_result;

  if (!owner || owner->initialized == 0u ||
      mesh_control_state_get_usage_v1(&owner->state, &usage) != MESH_CONTROL_OK ||
      mesh_control_channel_get_stats_v1(owner->inbound, &channel_stats) != MESH_CONTROL_OK ||
      usage.resource_count != 0u || usage.operation_count != 0u || usage.event_count != 0u ||
      channel_stats.pending != 0u || owner->committed_log_index != 0u ||
      owner->preparation_active || owner->stats.processed != 0u ||
      owner->stats.rejected_binding != 0u || owner->stats.rejected_replay != 0u ||
      owner->stats.rejected_schema != 0u || owner->stats.rejected_state != 0u) {
    return 0;
  }
  replay_result = mesh_mgmt_replay_export_v1(&owner->replay, NULL, 0u, &replay_snapshot);
  return replay_result == MESH_MGMT_REPLAY_OK && replay_snapshot.entry_count == 0u &&
         !replay_snapshot.has_sequence;
}

static int calculate_encoded_total(uint32_t operation_count, uint32_t event_count,
                                   uint32_t replay_count, size_t resource_section_size,
                                   size_t *out_total) {
  size_t total = CHECKPOINT_HEADER_SIZE;
  size_t section;
  return checked_add_size(total, resource_section_size, &total) &&
         checked_multiply_size(operation_count, CHECKPOINT_OPERATION_SIZE, &section) &&
         checked_add_size(total, section, &total) &&
         checked_multiply_size(event_count, CHECKPOINT_EVENT_SIZE, &section) &&
         checked_add_size(total, section, &total) &&
         checked_multiply_size(replay_count, CHECKPOINT_REPLAY_ENTRY_SIZE, &section) &&
         checked_add_size(total, section, out_total);
}

static const uint8_t *decode_resource(const uint8_t *cursor, const uint8_t *end,
                                      mesh_control_state_resource_record_v1_t *record) {
  uint32_t document_size;
  if (!cursor || !end || !record || (size_t)(end - cursor) < CHECKPOINT_RESOURCE_HEADER_SIZE ||
      cursor[6] != 0u || cursor[7] != 0u || !bytes_zero(cursor + 12u, 4u)) {
    return NULL;
  }
  document_size = read_u32(cursor + 8u);
  if (document_size > (size_t)(end - cursor) - CHECKPOINT_RESOURCE_HEADER_SIZE)
    return NULL;
  memset(record, 0, sizeof(*record));
  record->status.resource_kind = read_u16(cursor);
  record->status.desired_presence = read_u16(cursor + 2u);
  record->status.observed_presence = read_u16(cursor + 4u);
  record->document_size = document_size;
  record->status.desired_epoch = read_u64(cursor + 16u);
  record->status.observed_epoch = read_u64(cursor + 24u);
  memcpy(record->status.resource_id, cursor + 32u, MESH_CONTROL_DIGEST_SIZE);
  memcpy(record->status.desired_digest, cursor + 64u, MESH_CONTROL_DIGEST_SIZE);
  memcpy(record->status.observed_digest, cursor + 96u, MESH_CONTROL_DIGEST_SIZE);
  record->document = document_size == 0u ? NULL : cursor + CHECKPOINT_RESOURCE_HEADER_SIZE;
  return cursor + CHECKPOINT_RESOURCE_HEADER_SIZE + document_size;
}

static const uint8_t *decode_operation(const uint8_t *cursor, const uint8_t *end,
                                       mesh_control_state_operation_record_v1_t *record) {
  mesh_control_operation_v1_t *operation;
  if (!cursor || !end || !record || (size_t)(end - cursor) < CHECKPOINT_OPERATION_SIZE ||
      cursor[54] != 0u || cursor[55] != 0u) {
    return NULL;
  }
  memset(record, 0, sizeof(*record));
  operation = &record->operation;
  memcpy(operation->operation_id, cursor, MESH_CONTROL_ID_SIZE);
  memcpy(operation->request_id, cursor + 16u, MESH_CONTROL_ID_SIZE);
  memcpy(operation->message_id, cursor + 32u, MESH_CONTROL_ID_SIZE);
  operation->resource_kind = read_u16(cursor + 48u);
  operation->action = read_u16(cursor + 50u);
  operation->state = read_u16(cursor + 52u);
  memcpy(operation->resource_id, cursor + 56u, MESH_CONTROL_DIGEST_SIZE);
  memcpy(operation->desired_digest, cursor + 88u, MESH_CONTROL_DIGEST_SIZE);
  operation->desired_epoch = read_u64(cursor + 120u);
  operation->created_at_ms = read_u64(cursor + 128u);
  operation->updated_at_ms = read_u64(cursor + 136u);
  record->terminal_expires_at_ms = read_u64(cursor + 144u);
  return cursor + CHECKPOINT_OPERATION_SIZE;
}

static const uint8_t *decode_event(const uint8_t *cursor, const uint8_t *end,
                                   mesh_control_event_v1_t *event) {
  if (!cursor || !end || !event || (size_t)(end - cursor) < CHECKPOINT_EVENT_SIZE ||
      !bytes_zero(cursor + 28u, 4u)) {
    return NULL;
  }
  memset(event, 0, sizeof(*event));
  event->cursor = read_u64(cursor);
  memcpy(event->operation_id, cursor + 8u, MESH_CONTROL_ID_SIZE);
  event->resource_kind = read_u16(cursor + 24u);
  event->operation_state = read_u16(cursor + 26u);
  memcpy(event->resource_id, cursor + 32u, MESH_CONTROL_DIGEST_SIZE);
  event->desired_epoch = read_u64(cursor + 64u);
  event->recorded_at_ms = read_u64(cursor + 72u);
  return cursor + CHECKPOINT_EVENT_SIZE;
}

mesh_control_checkpoint_result_t
mesh_control_checkpoint_committed_log_index_v1(const uint8_t *bytes, size_t size,
                                               uint64_t *out_index) {
  mesh_control_state_resource_record_v1_t resource;
  mesh_control_state_operation_record_v1_t operation;
  mesh_control_event_v1_t event;
  const uint8_t *cursor;
  const uint8_t *resource_end;
  const uint8_t *end;
  uint8_t digest[CHECKPOINT_DIGEST_SIZE];
  uint64_t encoded_size;
  uint64_t encoded_resource_size;
  uint32_t resource_count;
  uint32_t operation_count;
  uint32_t event_count;
  uint32_t replay_count;
  uint32_t flags;
  size_t expected_size;
  size_t index;

  if (out_index)
    *out_index = 0u;
  if (!bytes || !out_index || size < CHECKPOINT_HEADER_SIZE ||
      size > MESH_CONTROL_CHECKPOINT_MAX_SIZE_V1) {
    return MESH_CONTROL_CHECKPOINT_INVALID_ARG;
  }
  if (memcmp(bytes, checkpoint_magic, sizeof(checkpoint_magic)) != 0 ||
      read_u32(bytes + 8u) != MESH_CONTROL_CHECKPOINT_VERSION_V2 ||
      read_u32(bytes + 12u) != CHECKPOINT_HEADER_SIZE || !bytes_zero(bytes + 76u, 4u)) {
    return MESH_CONTROL_CHECKPOINT_CORRUPT;
  }
  encoded_size = read_u64(bytes + 16u);
  encoded_resource_size = read_u64(bytes + 208u);
  if (encoded_size != size || encoded_resource_size > SIZE_MAX)
    return MESH_CONTROL_CHECKPOINT_CORRUPT;

  resource_count = read_u32(bytes + 24u);
  operation_count = read_u32(bytes + 28u);
  event_count = read_u32(bytes + 32u);
  replay_count = read_u32(bytes + 36u);
  flags = read_u32(bytes + 72u);
  if ((flags & ~CHECKPOINT_KNOWN_FLAGS) != 0u ||
      !calculate_encoded_total(operation_count, event_count, replay_count,
                               (size_t)encoded_resource_size, &expected_size) ||
      expected_size != size || !checkpoint_digest(bytes, size, digest) ||
      memcmp(digest, bytes + CHECKPOINT_DIGEST_OFFSET, sizeof(digest)) != 0) {
    return MESH_CONTROL_CHECKPOINT_CORRUPT;
  }

  end = bytes + size;
  cursor = bytes + CHECKPOINT_HEADER_SIZE;
  resource_end = cursor + (size_t)encoded_resource_size;
  for (index = 0u; index < resource_count; ++index) {
    cursor = decode_resource(cursor, resource_end, &resource);
    if (!cursor)
      return MESH_CONTROL_CHECKPOINT_CORRUPT;
  }
  if (cursor != resource_end)
    return MESH_CONTROL_CHECKPOINT_CORRUPT;
  for (index = 0u; index < operation_count; ++index) {
    cursor = decode_operation(cursor, end, &operation);
    if (!cursor)
      return MESH_CONTROL_CHECKPOINT_CORRUPT;
  }
  for (index = 0u; index < event_count; ++index) {
    cursor = decode_event(cursor, end, &event);
    if (!cursor)
      return MESH_CONTROL_CHECKPOINT_CORRUPT;
  }
  if ((size_t)(end - cursor) != (size_t)replay_count * CHECKPOINT_REPLAY_ENTRY_SIZE)
    return MESH_CONTROL_CHECKPOINT_CORRUPT;

  *out_index = read_u64(bytes + 216u);
  return MESH_CONTROL_CHECKPOINT_OK;
}

static mesh_control_checkpoint_result_t
initialize_restore_targets(const mesh_control_owner_v1_t *owner, mesh_control_state_v1_t *state,
                           mesh_mgmt_replay_gate_v1_t *replay) {
  memset(state, 0, sizeof(*state));
  memset(replay, 0, sizeof(*replay));
  if (mesh_control_state_init_v1(state, &owner->config.state) != MESH_CONTROL_OK) {
    return MESH_CONTROL_CHECKPOINT_RESOURCE_EXHAUSTED;
  }
  if (mesh_mgmt_replay_init_v1(replay, &owner->config.replay) != MESH_MGMT_REPLAY_OK ||
      mesh_mgmt_replay_bind_v1(replay, &owner->config.replay_binding) != MESH_MGMT_REPLAY_OK) {
    mesh_control_state_destroy_v1(state);
    mesh_mgmt_replay_destroy_v1(replay);
    return MESH_CONTROL_CHECKPOINT_RESOURCE_EXHAUSTED;
  }
  return MESH_CONTROL_CHECKPOINT_OK;
}

mesh_control_checkpoint_result_t mesh_control_checkpoint_restore_v1(mesh_control_owner_v1_t *owner,
                                                                    const uint8_t *bytes,
                                                                    size_t size, uint64_t now_ms) {
  mesh_control_state_resource_record_v1_t *resources = NULL;
  mesh_control_state_operation_record_v1_t *operations = NULL;
  mesh_control_event_v1_t *events = NULL;
  mesh_mgmt_replay_entry_v1_t *replay_entries = NULL;
  mesh_control_state_checkpoint_info_v1_t state_info;
  mesh_mgmt_replay_snapshot_v1_t replay_snapshot;
  mesh_control_state_v1_t restored_state;
  mesh_mgmt_replay_gate_v1_t restored_replay;
  mesh_control_checkpoint_result_t result = MESH_CONTROL_CHECKPOINT_CORRUPT;
  const uint8_t *cursor;
  const uint8_t *resource_end;
  const uint8_t *end;
  uint8_t digest[CHECKPOINT_DIGEST_SIZE];
  uint32_t resource_count;
  uint32_t operation_count;
  uint32_t event_count;
  uint32_t replay_count;
  uint32_t flags;
  uint32_t format_version;
  uint64_t encoded_size;
  uint64_t encoded_resource_size;
  size_t maximum_resource_size;
  size_t resource_headers_size;
  size_t expected_size;
  size_t index;

  memset(&state_info, 0, sizeof(state_info));
  memset(&replay_snapshot, 0, sizeof(replay_snapshot));
  memset(&restored_state, 0, sizeof(restored_state));
  memset(&restored_replay, 0, sizeof(restored_replay));
  if (!owner || !bytes || size < CHECKPOINT_HEADER_SIZE ||
      size > MESH_CONTROL_CHECKPOINT_MAX_SIZE_V1)
    return MESH_CONTROL_CHECKPOINT_INVALID_ARG;
  if (!owner_unused(owner))
    return MESH_CONTROL_CHECKPOINT_INVALID_STATE;
  format_version = read_u32(bytes + 8u);
  if (memcmp(bytes, checkpoint_magic, sizeof(checkpoint_magic)) != 0 ||
      (format_version != MESH_CONTROL_CHECKPOINT_VERSION_V1 &&
       format_version != MESH_CONTROL_CHECKPOINT_VERSION_V2) ||
      read_u32(bytes + 12u) != CHECKPOINT_HEADER_SIZE || !bytes_zero(bytes + 76u, 4u) ||
      (format_version == MESH_CONTROL_CHECKPOINT_VERSION_V1 && !bytes_zero(bytes + 216u, 8u))) {
    return MESH_CONTROL_CHECKPOINT_CORRUPT;
  }
  encoded_size = read_u64(bytes + 16u);
  encoded_resource_size = read_u64(bytes + 208u);
  if (encoded_size != size || encoded_resource_size > SIZE_MAX)
    return MESH_CONTROL_CHECKPOINT_CORRUPT;
  resource_count = read_u32(bytes + 24u);
  operation_count = read_u32(bytes + 28u);
  event_count = read_u32(bytes + 32u);
  replay_count = read_u32(bytes + 36u);
  flags = read_u32(bytes + 72u);
  if (!checked_multiply_size(resource_count, CHECKPOINT_RESOURCE_HEADER_SIZE,
                             &resource_headers_size) ||
      !checked_add_size(resource_headers_size, owner->config.state.desired_document_retained_bytes,
                        &maximum_resource_size) ||
      (flags & ~CHECKPOINT_KNOWN_FLAGS) != 0u ||
      resource_count > owner->config.state.resource_capacity ||
      operation_count > owner->config.state.operation_capacity ||
      event_count > owner->config.state.event_capacity ||
      replay_count > owner->config.replay.capacity ||
      encoded_resource_size > maximum_resource_size ||
      !calculate_encoded_total(operation_count, event_count, replay_count,
                               (size_t)encoded_resource_size, &expected_size) ||
      expected_size != size || !checkpoint_digest(bytes, size, digest) ||
      memcmp(digest, bytes + CHECKPOINT_DIGEST_OFFSET, sizeof(digest)) != 0) {
    return MESH_CONTROL_CHECKPOINT_CORRUPT;
  }
  if (memcmp(bytes + 80u, owner->config.mesh_id, MESH_CONTROL_DIGEST_SIZE) != 0 ||
      memcmp(bytes + 112u, owner->config.node_id, MESH_CONTROL_NODE_ID_SIZE) != 0 ||
      memcmp(bytes + 144u, owner->config.replay_binding.principal_key,
             sizeof(owner->config.replay_binding.principal_key)) != 0 ||
      read_u64(bytes + 176u) != owner->config.replay_binding.principal_epoch ||
      read_u64(bytes + 184u) != owner->config.replay_binding.incarnation ||
      memcmp(bytes + 192u, owner->config.replay_binding.session_id,
             sizeof(owner->config.replay_binding.session_id)) != 0) {
    return MESH_CONTROL_CHECKPOINT_BINDING_MISMATCH;
  }

  if (!allocate_array(resource_count, sizeof(*resources), (void **)&resources) ||
      !allocate_array(operation_count, sizeof(*operations), (void **)&operations) ||
      !allocate_array(event_count, sizeof(*events), (void **)&events) ||
      !allocate_array(replay_count, sizeof(*replay_entries), (void **)&replay_entries)) {
    result = MESH_CONTROL_CHECKPOINT_RESOURCE_EXHAUSTED;
    goto cleanup;
  }
  end = bytes + size;
  cursor = bytes + CHECKPOINT_HEADER_SIZE;
  resource_end = cursor + (size_t)encoded_resource_size;
  for (index = 0u; index < resource_count; ++index) {
    cursor = decode_resource(cursor, resource_end, &resources[index]);
    if (!cursor)
      goto cleanup;
  }
  if (cursor != resource_end)
    goto cleanup;
  for (index = 0u; index < operation_count; ++index) {
    cursor = decode_operation(cursor, end, &operations[index]);
    if (!cursor)
      goto cleanup;
  }
  for (index = 0u; index < event_count; ++index) {
    cursor = decode_event(cursor, end, &events[index]);
    if (!cursor)
      goto cleanup;
  }
  for (index = 0u; index < replay_count; ++index) {
    if ((size_t)(end - cursor) < CHECKPOINT_REPLAY_ENTRY_SIZE)
      goto cleanup;
    memcpy(replay_entries[index].message_id, cursor, MESH_CONTROL_ID_SIZE);
    replay_entries[index].expires_at_ms = read_u64(cursor + 16u);
    replay_entries[index].occupied = 1u;
    cursor += CHECKPOINT_REPLAY_ENTRY_SIZE;
  }
  if (cursor != end)
    goto cleanup;

  state_info.snapshot_generation = read_u64(bytes + 40u);
  state_info.next_event_cursor = read_u64(bytes + 48u);
  state_info.resource_count = resource_count;
  state_info.operation_count = operation_count;
  state_info.event_count = event_count;
  memcpy(replay_snapshot.binding.principal_key, bytes + 144u,
         sizeof(replay_snapshot.binding.principal_key));
  replay_snapshot.binding.principal_epoch = read_u64(bytes + 176u);
  replay_snapshot.binding.incarnation = read_u64(bytes + 184u);
  memcpy(replay_snapshot.binding.session_id, bytes + 192u,
         sizeof(replay_snapshot.binding.session_id));
  replay_snapshot.last_sequence = read_u64(bytes + 56u);
  replay_snapshot.generation = read_u64(bytes + 64u);
  replay_snapshot.entry_count = replay_count;
  replay_snapshot.has_sequence = (flags & CHECKPOINT_FLAG_REPLAY_HAS_SEQUENCE) != 0u;
  replay_snapshot.bound = (flags & CHECKPOINT_FLAG_REPLAY_BOUND) != 0u;

  result = initialize_restore_targets(owner, &restored_state, &restored_replay);
  if (result != MESH_CONTROL_CHECKPOINT_OK)
    goto cleanup;
  if (mesh_control_state_import_v1(&restored_state, &state_info, resources, operations, events) !=
          MESH_CONTROL_OK ||
      mesh_mgmt_replay_import_v1(&restored_replay, &replay_snapshot, replay_entries, now_ms) !=
          MESH_MGMT_REPLAY_OK) {
    result = MESH_CONTROL_CHECKPOINT_CORRUPT;
    goto cleanup;
  }

  mesh_control_state_destroy_v1(&owner->state);
  mesh_mgmt_replay_destroy_v1(&owner->replay);
  owner->state = restored_state;
  owner->replay = restored_replay;
  owner->committed_log_index =
      format_version == MESH_CONTROL_CHECKPOINT_VERSION_V2 ? read_u64(bytes + 216u) : 0u;
  memset(&restored_state, 0, sizeof(restored_state));
  memset(&restored_replay, 0, sizeof(restored_replay));
  result = MESH_CONTROL_CHECKPOINT_OK;

cleanup:
  mesh_control_state_destroy_v1(&restored_state);
  mesh_mgmt_replay_destroy_v1(&restored_replay);
  free(resources);
  free(operations);
  free(events);
  free(replay_entries);
  return result;
}

void mesh_control_checkpoint_free_v1(uint8_t *bytes) { free(bytes); }
