#include "mesh_control_state.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  uint8_t occupied;
  mesh_control_resource_status_v1_t status;
  uint8_t *desired_document;
  size_t desired_document_size;
} mesh_control_resource_slot_v1_t;

typedef struct {
  uint8_t occupied;
  uint64_t terminal_expires_at_ms;
  mesh_control_operation_v1_t operation;
} mesh_control_operation_slot_v1_t;

struct mesh_control_state_impl_v1 {
  mesh_control_state_config_v1_t config;
  mesh_control_resource_slot_v1_t *resources;
  mesh_control_operation_slot_v1_t *operations;
  mesh_control_event_v1_t *events;
  size_t event_count;
  size_t event_head;
  uint64_t next_cursor;
  uint64_t snapshot_generation;
  size_t retained_document_bytes;
};

static int bytes_zero(const uint8_t *bytes, size_t size) {
  uint8_t aggregate = 0u;
  size_t index;
  for (index = 0u; index < size; ++index)
    aggregate |= bytes[index];
  return aggregate == 0u;
}

static int resource_kind_valid(uint16_t resource_kind) {
  return resource_kind >= MESH_CONTROL_RESOURCE_NODE &&
         resource_kind <= MESH_CONTROL_RESOURCE_RELEASE;
}

static int presence_valid(uint16_t presence) {
  return presence == MESH_CONTROL_PRESENCE_ABSENT || presence == MESH_CONTROL_PRESENCE_PRESENT;
}

static int operation_state_valid(uint16_t state) {
  return state >= MESH_CONTROL_OPERATION_SUBMITTED && state <= MESH_CONTROL_OPERATION_INTERRUPTED;
}

static uint64_t saturating_add(uint64_t left, uint64_t right) {
  return UINT64_MAX - left < right ? UINT64_MAX : left + right;
}

static int mutation_with_event_available(const struct mesh_control_state_impl_v1 *impl) {
  return impl->snapshot_generation != UINT64_MAX && impl->next_cursor != UINT64_MAX;
}

static mesh_control_resource_slot_v1_t *
find_resource(struct mesh_control_state_impl_v1 *impl, uint16_t resource_kind,
              const uint8_t resource_id[MESH_CONTROL_DIGEST_SIZE]) {
  size_t index;
  for (index = 0u; index < impl->config.resource_capacity; ++index) {
    mesh_control_resource_slot_v1_t *slot = &impl->resources[index];
    if (slot->occupied && slot->status.resource_kind == resource_kind &&
        memcmp(slot->status.resource_id, resource_id, MESH_CONTROL_DIGEST_SIZE) == 0)
      return slot;
  }
  return NULL;
}

static mesh_control_operation_slot_v1_t *
find_operation(struct mesh_control_state_impl_v1 *impl,
               const uint8_t operation_id[MESH_CONTROL_ID_SIZE]) {
  size_t index;
  for (index = 0u; index < impl->config.operation_capacity; ++index) {
    mesh_control_operation_slot_v1_t *slot = &impl->operations[index];
    if (slot->occupied &&
        memcmp(slot->operation.operation_id, operation_id, MESH_CONTROL_ID_SIZE) == 0)
      return slot;
  }
  return NULL;
}

static mesh_control_operation_slot_v1_t *
find_request(struct mesh_control_state_impl_v1 *impl,
             const uint8_t request_id[MESH_CONTROL_ID_SIZE]) {
  size_t index;
  for (index = 0u; index < impl->config.operation_capacity; ++index) {
    mesh_control_operation_slot_v1_t *slot = &impl->operations[index];
    if (slot->occupied && memcmp(slot->operation.request_id, request_id, MESH_CONTROL_ID_SIZE) == 0)
      return slot;
  }
  return NULL;
}

static void append_event(struct mesh_control_state_impl_v1 *impl,
                         const mesh_control_operation_v1_t *operation, uint64_t now_ms) {
  size_t index;
  mesh_control_event_v1_t *event;

  if (impl->event_count < impl->config.event_capacity) {
    index = (impl->event_head + impl->event_count) % impl->config.event_capacity;
    ++impl->event_count;
  } else {
    index = impl->event_head;
    impl->event_head = (impl->event_head + 1u) % impl->config.event_capacity;
  }
  event = &impl->events[index];
  memset(event, 0, sizeof(*event));
  event->cursor = impl->next_cursor++;
  memcpy(event->operation_id, operation->operation_id, sizeof(event->operation_id));
  event->resource_kind = operation->resource_kind;
  event->operation_state = operation->state;
  memcpy(event->resource_id, operation->resource_id, sizeof(event->resource_id));
  event->desired_epoch = operation->desired_epoch;
  event->recorded_at_ms = now_ms;
}

static int operation_binding_equal(const mesh_control_operation_v1_t *operation,
                                   const mesh_control_envelope_v1_t *envelope,
                                   mesh_control_desired_action_v1_t action) {
  return operation->resource_kind == envelope->resource_kind && operation->action == action &&
         operation->desired_epoch == envelope->epoch &&
         memcmp(operation->resource_id, envelope->resource_id, sizeof(operation->resource_id)) ==
             0 &&
         memcmp(operation->desired_digest, envelope->payload_digest,
                sizeof(operation->desired_digest)) == 0;
}

mesh_control_result_t mesh_control_state_init_v1(mesh_control_state_v1_t *state,
                                                 const mesh_control_state_config_v1_t *config) {
  struct mesh_control_state_impl_v1 *impl;

  if (state == NULL || config == NULL || state->impl != NULL || config->resource_capacity == 0u ||
      config->resource_capacity > MESH_CONTROL_STATE_MAX_RESOURCES_V1 ||
      config->operation_capacity == 0u ||
      config->operation_capacity > MESH_CONTROL_STATE_MAX_OPERATIONS_V1 ||
      config->event_capacity == 0u || config->event_capacity > MESH_CONTROL_STATE_MAX_EVENTS_V1 ||
      config->terminal_retention_ms == 0u || config->desired_document_max_bytes == 0u ||
      config->desired_document_max_bytes > MESH_CONTROL_STATE_MAX_DESIRED_DOCUMENT_SIZE_V1 ||
      config->desired_document_retained_bytes < config->desired_document_max_bytes ||
      config->desired_document_retained_bytes > MESH_CONTROL_STATE_MAX_RETAINED_DOCUMENT_BYTES_V1) {
    return MESH_CONTROL_INVALID_ARG;
  }
  impl = (struct mesh_control_state_impl_v1 *)calloc(1u, sizeof(*impl));
  if (impl == NULL)
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  impl->resources = (mesh_control_resource_slot_v1_t *)calloc(config->resource_capacity,
                                                              sizeof(*impl->resources));
  impl->operations = (mesh_control_operation_slot_v1_t *)calloc(config->operation_capacity,
                                                                sizeof(*impl->operations));
  impl->events = (mesh_control_event_v1_t *)calloc(config->event_capacity, sizeof(*impl->events));
  if (impl->resources == NULL || impl->operations == NULL || impl->events == NULL) {
    free(impl->events);
    free(impl->operations);
    free(impl->resources);
    free(impl);
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  }
  impl->config = *config;
  impl->next_cursor = 1u;
  impl->snapshot_generation = 1u;
  state->impl = impl;
  return MESH_CONTROL_OK;
}

void mesh_control_state_destroy_v1(mesh_control_state_v1_t *state) {
  size_t index;
  if (state == NULL || state->impl == NULL)
    return;
  for (index = 0u; index < state->impl->config.resource_capacity; ++index)
    free(state->impl->resources[index].desired_document);
  free(state->impl->events);
  free(state->impl->operations);
  free(state->impl->resources);
  memset(state->impl, 0, sizeof(*state->impl));
  free(state->impl);
  state->impl = NULL;
}

size_t mesh_control_state_sweep_v1(mesh_control_state_v1_t *state, uint64_t now_ms) {
  size_t index;
  size_t removed = 0u;
  if (state == NULL || state->impl == NULL)
    return 0u;
  if (state->impl->snapshot_generation == UINT64_MAX)
    return 0u;
  for (index = 0u; index < state->impl->config.operation_capacity; ++index) {
    mesh_control_operation_slot_v1_t *slot = &state->impl->operations[index];
    if (slot->occupied &&
        mesh_control_operation_state_is_terminal_v1(
            (mesh_control_operation_state_v1_t)slot->operation.state) &&
        now_ms >= slot->terminal_expires_at_ms) {
      memset(slot, 0, sizeof(*slot));
      ++removed;
    }
  }
  if (removed != 0u)
    ++state->impl->snapshot_generation;
  return removed;
}

mesh_control_result_t mesh_control_state_submit_v1(mesh_control_state_v1_t *state,
                                                   const mesh_control_envelope_v1_t *envelope,
                                                   mesh_control_desired_action_v1_t action,
                                                   uint64_t now_ms,
                                                   mesh_control_operation_v1_t *out_operation) {
  return mesh_control_state_submit_document_v1(state, envelope, action, NULL, 0u, now_ms,
                                               out_operation);
}

mesh_control_result_t mesh_control_state_validate_document_v1(
    const mesh_control_state_v1_t *state, const mesh_control_envelope_v1_t *envelope,
    mesh_control_desired_action_v1_t action, const uint8_t *document, size_t document_size,
    uint64_t now_ms) {
  struct mesh_control_state_impl_v1 *impl;
  mesh_control_resource_slot_v1_t *resource = NULL;
  mesh_control_resource_slot_v1_t *free_resource = NULL;
  mesh_control_operation_slot_v1_t *operation;
  mesh_control_operation_slot_v1_t *free_operation = NULL;
  size_t previous_document_size = 0u;
  int preserve_document;
  size_t index;

  if (!state || !state->impl || !envelope ||
      (action != MESH_CONTROL_DESIRED_APPLY && action != MESH_CONTROL_DESIRED_DELETE) ||
      (document_size != 0u && !document) ||
      mesh_control_envelope_validate_v1(envelope) != MESH_CONTROL_OK ||
      bytes_zero(envelope->request_id, sizeof(envelope->request_id)) ||
      now_ms < envelope->issued_at_ms || now_ms >= envelope->expires_at_ms) {
    return MESH_CONTROL_INVALID_ARG;
  }
  impl = state->impl;
  operation = find_request(impl, envelope->request_id);
  if (operation) {
    return operation_binding_equal(&operation->operation, envelope, action) ? MESH_CONTROL_OK
                                                                            : MESH_CONTROL_CONFLICT;
  }
  resource = find_resource(impl, envelope->resource_kind, envelope->resource_id);
  if (document_size > impl->config.desired_document_max_bytes)
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  if (resource)
    previous_document_size = resource->desired_document_size;
  preserve_document =
      action == MESH_CONTROL_DESIRED_DELETE && document_size == 0u && resource != NULL;
  if (!preserve_document && impl->retained_document_bytes - previous_document_size >
                                impl->config.desired_document_retained_bytes - document_size) {
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  }
  for (index = 0u; index < impl->config.resource_capacity; ++index) {
    if (!impl->resources[index].occupied && !free_resource)
      free_resource = &impl->resources[index];
  }
  for (index = 0u; index < impl->config.operation_capacity; ++index) {
    if (!impl->operations[index].occupied && !free_operation)
      free_operation = &impl->operations[index];
  }
  if ((!resource && !free_resource) || !free_operation)
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  if (!mutation_with_event_available(impl))
    return MESH_CONTROL_INVALID_STATE;
  if (resource) {
    if (envelope->precondition_epoch != resource->status.desired_epoch ||
        envelope->epoch <= resource->status.desired_epoch) {
      return MESH_CONTROL_CONFLICT;
    }
  } else if (envelope->precondition_epoch != 0u) {
    return MESH_CONTROL_CONFLICT;
  }
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_state_submit_document_v1(
    mesh_control_state_v1_t *state, const mesh_control_envelope_v1_t *envelope,
    mesh_control_desired_action_v1_t action, const uint8_t *document, size_t document_size,
    uint64_t now_ms, mesh_control_operation_v1_t *out_operation) {
  mesh_control_resource_slot_v1_t *resource = NULL;
  mesh_control_resource_slot_v1_t *free_resource = NULL;
  mesh_control_operation_slot_v1_t *operation;
  mesh_control_operation_slot_v1_t *free_operation = NULL;
  uint8_t *document_copy = NULL;
  size_t previous_document_size = 0u;
  int preserve_document = 0;
  size_t index;

  if (state == NULL || state->impl == NULL || envelope == NULL || out_operation == NULL ||
      envelope->kind != MESH_CONTROL_MESSAGE_INTENT ||
      (action != MESH_CONTROL_DESIRED_APPLY && action != MESH_CONTROL_DESIRED_DELETE) ||
      (document_size != 0u && document == NULL) ||
      mesh_control_envelope_validate_v1(envelope) != MESH_CONTROL_OK ||
      bytes_zero(envelope->request_id, sizeof(envelope->request_id)) ||
      now_ms < envelope->issued_at_ms || now_ms >= envelope->expires_at_ms) {
    return MESH_CONTROL_INVALID_ARG;
  }
  memset(out_operation, 0, sizeof(*out_operation));
  (void)mesh_control_state_sweep_v1(state, now_ms);
  operation = find_request(state->impl, envelope->request_id);
  if (operation != NULL) {
    if (!operation_binding_equal(&operation->operation, envelope, action))
      return MESH_CONTROL_CONFLICT;
    *out_operation = operation->operation;
    return MESH_CONTROL_OK;
  }
  resource = find_resource(state->impl, envelope->resource_kind, envelope->resource_id);
  if (document_size > state->impl->config.desired_document_max_bytes)
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  if (resource != NULL)
    previous_document_size = resource->desired_document_size;
  preserve_document =
      action == MESH_CONTROL_DESIRED_DELETE && document_size == 0u && resource != NULL;
  if (!preserve_document && state->impl->retained_document_bytes - previous_document_size >
                                state->impl->config.desired_document_retained_bytes - document_size)
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  for (index = 0u; index < state->impl->config.resource_capacity; ++index) {
    if (!state->impl->resources[index].occupied && free_resource == NULL)
      free_resource = &state->impl->resources[index];
  }
  for (index = 0u; index < state->impl->config.operation_capacity; ++index) {
    if (!state->impl->operations[index].occupied && free_operation == NULL)
      free_operation = &state->impl->operations[index];
  }
  if ((resource == NULL && free_resource == NULL) || free_operation == NULL)
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  if (!mutation_with_event_available(state->impl))
    return MESH_CONTROL_INVALID_STATE;
  if (resource != NULL) {
    if (envelope->precondition_epoch != resource->status.desired_epoch ||
        envelope->epoch <= resource->status.desired_epoch)
      return MESH_CONTROL_CONFLICT;
  } else if (envelope->precondition_epoch != 0u) {
    return MESH_CONTROL_CONFLICT;
  }

  if (document_size != 0u) {
    document_copy = (uint8_t *)malloc(document_size);
    if (document_copy == NULL)
      return MESH_CONTROL_RESOURCE_EXHAUSTED;
    memcpy(document_copy, document, document_size);
  }

  if (resource == NULL) {
    resource = free_resource;
    memset(resource, 0, sizeof(*resource));
    resource->occupied = 1u;
    resource->status.resource_kind = envelope->resource_kind;
    memcpy(resource->status.resource_id, envelope->resource_id,
           sizeof(resource->status.resource_id));
    resource->status.observed_presence = MESH_CONTROL_PRESENCE_ABSENT;
  }
  resource->status.desired_epoch = envelope->epoch;
  resource->status.desired_presence = action == MESH_CONTROL_DESIRED_APPLY
                                          ? MESH_CONTROL_PRESENCE_PRESENT
                                          : MESH_CONTROL_PRESENCE_ABSENT;
  if (action == MESH_CONTROL_DESIRED_APPLY) {
    memcpy(resource->status.desired_digest, envelope->payload_digest,
           sizeof(resource->status.desired_digest));
  } else {
    memset(resource->status.desired_digest, 0, sizeof(resource->status.desired_digest));
  }
  if (!preserve_document) {
    free(resource->desired_document);
    resource->desired_document = document_copy;
    resource->desired_document_size = document_size;
    state->impl->retained_document_bytes =
        state->impl->retained_document_bytes - previous_document_size + document_size;
  }

  memset(free_operation, 0, sizeof(*free_operation));
  free_operation->occupied = 1u;
  memcpy(free_operation->operation.operation_id, envelope->message_id,
         sizeof(free_operation->operation.operation_id));
  memcpy(free_operation->operation.request_id, envelope->request_id,
         sizeof(free_operation->operation.request_id));
  memcpy(free_operation->operation.message_id, envelope->message_id,
         sizeof(free_operation->operation.message_id));
  free_operation->operation.resource_kind = envelope->resource_kind;
  free_operation->operation.action = action;
  memcpy(free_operation->operation.resource_id, envelope->resource_id,
         sizeof(free_operation->operation.resource_id));
  memcpy(free_operation->operation.desired_digest, envelope->payload_digest,
         sizeof(free_operation->operation.desired_digest));
  free_operation->operation.desired_epoch = envelope->epoch;
  free_operation->operation.created_at_ms = now_ms;
  free_operation->operation.updated_at_ms = now_ms;
  free_operation->operation.state = MESH_CONTROL_OPERATION_ACCEPTED;
  append_event(state->impl, &free_operation->operation, now_ms);
  ++state->impl->snapshot_generation;
  *out_operation = free_operation->operation;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_state_transition_operation_v1(
    mesh_control_state_v1_t *state, const uint8_t operation_id[MESH_CONTROL_ID_SIZE],
    mesh_control_operation_state_v1_t next_state, uint64_t now_ms) {
  mesh_control_operation_slot_v1_t *slot;

  if (state == NULL || state->impl == NULL || operation_id == NULL ||
      bytes_zero(operation_id, MESH_CONTROL_ID_SIZE))
    return MESH_CONTROL_INVALID_ARG;
  slot = find_operation(state->impl, operation_id);
  if (slot == NULL)
    return MESH_CONTROL_EMPTY;
  if (!mesh_control_operation_transition_allowed_v1(
          (mesh_control_operation_state_v1_t)slot->operation.state, next_state))
    return MESH_CONTROL_INVALID_STATE;
  if (slot->operation.state == next_state)
    return MESH_CONTROL_OK;
  if (!mutation_with_event_available(state->impl))
    return MESH_CONTROL_INVALID_STATE;
  slot->operation.state = next_state;
  slot->operation.updated_at_ms = now_ms;
  if (mesh_control_operation_state_is_terminal_v1(next_state)) {
    slot->terminal_expires_at_ms =
        saturating_add(now_ms, state->impl->config.terminal_retention_ms);
  }
  append_event(state->impl, &slot->operation, now_ms);
  ++state->impl->snapshot_generation;
  return MESH_CONTROL_OK;
}

mesh_control_result_t
mesh_control_state_observe_v1(mesh_control_state_v1_t *state, uint16_t resource_kind,
                              const uint8_t resource_id[MESH_CONTROL_DIGEST_SIZE],
                              uint64_t observed_epoch, mesh_control_presence_v1_t presence,
                              const uint8_t digest[MESH_CONTROL_DIGEST_SIZE], uint64_t now_ms) {
  mesh_control_resource_slot_v1_t *resource;
  mesh_control_operation_slot_v1_t *matching_operation = NULL;
  int completes_desired;
  size_t index;

  if (state == NULL || state->impl == NULL || resource_id == NULL || digest == NULL ||
      bytes_zero(resource_id, MESH_CONTROL_DIGEST_SIZE) || observed_epoch == 0u ||
      (presence != MESH_CONTROL_PRESENCE_ABSENT && presence != MESH_CONTROL_PRESENCE_PRESENT) ||
      (presence == MESH_CONTROL_PRESENCE_PRESENT && bytes_zero(digest, MESH_CONTROL_DIGEST_SIZE)) ||
      (presence == MESH_CONTROL_PRESENCE_ABSENT && !bytes_zero(digest, MESH_CONTROL_DIGEST_SIZE))) {
    return MESH_CONTROL_INVALID_ARG;
  }
  resource = find_resource(state->impl, resource_kind, resource_id);
  if (resource == NULL)
    return MESH_CONTROL_EMPTY;
  if (observed_epoch < resource->status.observed_epoch ||
      observed_epoch > resource->status.desired_epoch)
    return MESH_CONTROL_CONFLICT;
  if (observed_epoch == resource->status.observed_epoch &&
      presence == resource->status.observed_presence &&
      memcmp(resource->status.observed_digest, digest, sizeof(resource->status.observed_digest)) ==
          0)
    return MESH_CONTROL_OK;
  completes_desired =
      observed_epoch == resource->status.desired_epoch &&
      presence == resource->status.desired_presence &&
      memcmp(digest, resource->status.desired_digest, sizeof(resource->status.desired_digest)) == 0;
  if (completes_desired) {
    for (index = 0u; index < state->impl->config.operation_capacity; ++index) {
      mesh_control_operation_slot_v1_t *slot = &state->impl->operations[index];
      if (slot->occupied && slot->operation.resource_kind == resource_kind &&
          slot->operation.desired_epoch == observed_epoch &&
          !mesh_control_operation_state_is_terminal_v1(
              (mesh_control_operation_state_v1_t)slot->operation.state) &&
          memcmp(slot->operation.resource_id, resource_id, MESH_CONTROL_DIGEST_SIZE) == 0) {
        matching_operation = slot;
        break;
      }
    }
  }
  if (state->impl->snapshot_generation == UINT64_MAX ||
      (matching_operation != NULL && state->impl->next_cursor == UINT64_MAX))
    return MESH_CONTROL_INVALID_STATE;
  resource->status.observed_epoch = observed_epoch;
  resource->status.observed_presence = presence;
  memcpy(resource->status.observed_digest, digest, sizeof(resource->status.observed_digest));
  if (matching_operation != NULL) {
    matching_operation->operation.state = MESH_CONTROL_OPERATION_SUCCEEDED;
    matching_operation->operation.updated_at_ms = now_ms;
    matching_operation->terminal_expires_at_ms =
        saturating_add(now_ms, state->impl->config.terminal_retention_ms);
    append_event(state->impl, &matching_operation->operation, now_ms);
  }
  ++state->impl->snapshot_generation;
  return MESH_CONTROL_OK;
}

mesh_control_result_t
mesh_control_state_get_resource_v1(const mesh_control_state_v1_t *state, uint16_t resource_kind,
                                   const uint8_t resource_id[MESH_CONTROL_DIGEST_SIZE],
                                   mesh_control_resource_status_v1_t *out_status) {
  mesh_control_resource_slot_v1_t *slot;
  if (state == NULL || state->impl == NULL || resource_id == NULL || out_status == NULL)
    return MESH_CONTROL_INVALID_ARG;
  slot = find_resource(state->impl, resource_kind, resource_id);
  if (slot == NULL)
    return MESH_CONTROL_EMPTY;
  *out_status = slot->status;
  return MESH_CONTROL_OK;
}

mesh_control_result_t
mesh_control_state_get_operation_v1(const mesh_control_state_v1_t *state,
                                    const uint8_t operation_id[MESH_CONTROL_ID_SIZE],
                                    mesh_control_operation_v1_t *out_operation) {
  mesh_control_operation_slot_v1_t *slot;
  if (state == NULL || state->impl == NULL || operation_id == NULL || out_operation == NULL)
    return MESH_CONTROL_INVALID_ARG;
  slot = find_operation(state->impl, operation_id);
  if (slot == NULL)
    return MESH_CONTROL_EMPTY;
  *out_operation = slot->operation;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_state_get_desired_document_v1(
    const mesh_control_state_v1_t *state, uint16_t resource_kind,
    const uint8_t resource_id[MESH_CONTROL_DIGEST_SIZE], const uint8_t **out_document,
    size_t *out_document_size) {
  mesh_control_resource_slot_v1_t *slot;
  if (state == NULL || state->impl == NULL || resource_id == NULL || out_document == NULL ||
      out_document_size == NULL)
    return MESH_CONTROL_INVALID_ARG;
  *out_document = NULL;
  *out_document_size = 0u;
  slot = find_resource(state->impl, resource_kind, resource_id);
  if (slot == NULL)
    return MESH_CONTROL_EMPTY;
  *out_document = slot->desired_document;
  *out_document_size = slot->desired_document_size;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_state_get_usage_v1(const mesh_control_state_v1_t *state,
                                                      mesh_control_state_usage_v1_t *out_usage) {
  size_t index;
  if (state == NULL || state->impl == NULL || out_usage == NULL)
    return MESH_CONTROL_INVALID_ARG;
  memset(out_usage, 0, sizeof(*out_usage));
  for (index = 0u; index < state->impl->config.resource_capacity; ++index) {
    if (state->impl->resources[index].occupied)
      ++out_usage->resource_count;
  }
  for (index = 0u; index < state->impl->config.operation_capacity; ++index) {
    if (state->impl->operations[index].occupied)
      ++out_usage->operation_count;
  }
  out_usage->event_count = state->impl->event_count;
  out_usage->retained_document_bytes = state->impl->retained_document_bytes;
  out_usage->retained_document_capacity = state->impl->config.desired_document_retained_bytes;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_state_export_v1(
    const mesh_control_state_v1_t *state, mesh_control_state_resource_record_v1_t *resources,
    size_t resource_capacity, mesh_control_state_operation_record_v1_t *operations,
    size_t operation_capacity, mesh_control_event_v1_t *events, size_t event_capacity,
    mesh_control_state_checkpoint_info_v1_t *out_info) {
  size_t resource_count = 0u;
  size_t operation_count = 0u;
  size_t index;

  if (state == NULL || state->impl == NULL || out_info == NULL ||
      (resource_capacity != 0u && resources == NULL) ||
      (operation_capacity != 0u && operations == NULL) || (event_capacity != 0u && events == NULL))
    return MESH_CONTROL_INVALID_ARG;
  memset(out_info, 0, sizeof(*out_info));
  for (index = 0u; index < state->impl->config.resource_capacity; ++index) {
    if (state->impl->resources[index].occupied)
      ++resource_count;
  }
  for (index = 0u; index < state->impl->config.operation_capacity; ++index) {
    if (state->impl->operations[index].occupied)
      ++operation_count;
  }
  out_info->snapshot_generation = state->impl->snapshot_generation;
  out_info->next_event_cursor = state->impl->next_cursor;
  out_info->resource_count = resource_count;
  out_info->operation_count = operation_count;
  out_info->event_count = state->impl->event_count;
  if (resource_capacity < resource_count || operation_capacity < operation_count ||
      event_capacity < state->impl->event_count)
    return MESH_CONTROL_RESOURCE_EXHAUSTED;

  resource_count = 0u;
  for (index = 0u; index < state->impl->config.resource_capacity; ++index) {
    const mesh_control_resource_slot_v1_t *slot = &state->impl->resources[index];
    if (!slot->occupied)
      continue;
    resources[resource_count].status = slot->status;
    resources[resource_count].document = slot->desired_document;
    resources[resource_count].document_size = slot->desired_document_size;
    ++resource_count;
  }
  operation_count = 0u;
  for (index = 0u; index < state->impl->config.operation_capacity; ++index) {
    const mesh_control_operation_slot_v1_t *slot = &state->impl->operations[index];
    if (!slot->occupied)
      continue;
    operations[operation_count].operation = slot->operation;
    operations[operation_count].terminal_expires_at_ms = slot->terminal_expires_at_ms;
    ++operation_count;
  }
  for (index = 0u; index < state->impl->event_count; ++index) {
    events[index] =
        state->impl->events[(state->impl->event_head + index) % state->impl->config.event_capacity];
  }
  return MESH_CONTROL_OK;
}

static int resource_record_valid(const mesh_control_state_resource_record_v1_t *record,
                                 const mesh_control_state_config_v1_t *config) {
  const mesh_control_resource_status_v1_t *status = &record->status;
  if (!resource_kind_valid(status->resource_kind) ||
      bytes_zero(status->resource_id, sizeof(status->resource_id)) || status->desired_epoch == 0u ||
      status->observed_epoch > status->desired_epoch || !presence_valid(status->desired_presence) ||
      !presence_valid(status->observed_presence) ||
      (status->desired_presence == MESH_CONTROL_PRESENCE_PRESENT) !=
          !bytes_zero(status->desired_digest, sizeof(status->desired_digest)) ||
      (status->observed_presence == MESH_CONTROL_PRESENCE_PRESENT) !=
          !bytes_zero(status->observed_digest, sizeof(status->observed_digest)) ||
      (status->observed_presence == MESH_CONTROL_PRESENCE_PRESENT &&
       status->observed_epoch == 0u) ||
      record->document_size > config->desired_document_max_bytes ||
      (record->document_size != 0u && record->document == NULL))
    return 0;
  return 1;
}

static int operation_record_valid(const mesh_control_state_operation_record_v1_t *record) {
  const mesh_control_operation_v1_t *operation = &record->operation;
  int terminal;
  if (bytes_zero(operation->operation_id, sizeof(operation->operation_id)) ||
      bytes_zero(operation->request_id, sizeof(operation->request_id)) ||
      bytes_zero(operation->message_id, sizeof(operation->message_id)) ||
      memcmp(operation->operation_id, operation->message_id, sizeof(operation->operation_id)) !=
          0 ||
      !resource_kind_valid(operation->resource_kind) ||
      (operation->action != MESH_CONTROL_DESIRED_APPLY &&
       operation->action != MESH_CONTROL_DESIRED_DELETE) ||
      bytes_zero(operation->resource_id, sizeof(operation->resource_id)) ||
      bytes_zero(operation->desired_digest, sizeof(operation->desired_digest)) ||
      operation->desired_epoch == 0u || operation->updated_at_ms < operation->created_at_ms ||
      !operation_state_valid(operation->state))
    return 0;
  terminal = mesh_control_operation_state_is_terminal_v1(
      (mesh_control_operation_state_v1_t)operation->state);
  return terminal ? record->terminal_expires_at_ms != 0u : record->terminal_expires_at_ms == 0u;
}

static int event_record_valid(const mesh_control_event_v1_t *event) {
  return event->cursor != 0u && !bytes_zero(event->operation_id, sizeof(event->operation_id)) &&
         resource_kind_valid(event->resource_kind) &&
         operation_state_valid(event->operation_state) &&
         !bytes_zero(event->resource_id, sizeof(event->resource_id)) && event->desired_epoch != 0u;
}

static int
checkpoint_inputs_unique_and_bound(const mesh_control_state_checkpoint_info_v1_t *info,
                                   const mesh_control_state_resource_record_v1_t *resources,
                                   const mesh_control_state_operation_record_v1_t *operations,
                                   const mesh_control_event_v1_t *events) {
  size_t left;
  size_t right;
  for (left = 0u; left < info->resource_count; ++left) {
    for (right = left + 1u; right < info->resource_count; ++right) {
      if (resources[left].status.resource_kind == resources[right].status.resource_kind &&
          memcmp(resources[left].status.resource_id, resources[right].status.resource_id,
                 MESH_CONTROL_DIGEST_SIZE) == 0)
        return 0;
    }
  }
  /* Import runs only at startup and capacities are capped at 4096. The
   * bounded O(n^2) validation avoids introducing a second hash index. */
  for (left = 0u; left < info->operation_count; ++left) {
    const mesh_control_operation_v1_t *operation = &operations[left].operation;
    int resource_found = 0;
    for (right = left + 1u; right < info->operation_count; ++right) {
      if (memcmp(operation->operation_id, operations[right].operation.operation_id,
                 MESH_CONTROL_ID_SIZE) == 0 ||
          memcmp(operation->request_id, operations[right].operation.request_id,
                 MESH_CONTROL_ID_SIZE) == 0)
        return 0;
    }
    for (right = 0u; right < info->resource_count; ++right) {
      if (operation->resource_kind == resources[right].status.resource_kind &&
          memcmp(operation->resource_id, resources[right].status.resource_id,
                 MESH_CONTROL_DIGEST_SIZE) == 0) {
        if (operation->desired_epoch > resources[right].status.desired_epoch)
          return 0;
        resource_found = 1;
        break;
      }
    }
    if (!resource_found)
      return 0;
  }
  for (left = 0u; left < info->event_count; ++left) {
    int resource_found = 0;
    for (right = 0u; right < info->resource_count; ++right) {
      if (events[left].resource_kind == resources[right].status.resource_kind &&
          memcmp(events[left].resource_id, resources[right].status.resource_id,
                 MESH_CONTROL_DIGEST_SIZE) == 0) {
        if (events[left].desired_epoch > resources[right].status.desired_epoch)
          return 0;
        resource_found = 1;
        break;
      }
    }
    if (!resource_found)
      return 0;
  }
  return 1;
}

mesh_control_result_t
mesh_control_state_import_v1(mesh_control_state_v1_t *state,
                             const mesh_control_state_checkpoint_info_v1_t *info,
                             const mesh_control_state_resource_record_v1_t *resources,
                             const mesh_control_state_operation_record_v1_t *operations,
                             const mesh_control_event_v1_t *events) {
  uint8_t **document_copies = NULL;
  size_t retained_document_bytes = 0u;
  size_t index;
  mesh_control_state_usage_v1_t usage;

  if (state == NULL || state->impl == NULL || info == NULL || info->snapshot_generation == 0u ||
      info->snapshot_generation == UINT64_MAX || info->next_event_cursor == 0u ||
      info->next_event_cursor == UINT64_MAX ||
      info->resource_count > state->impl->config.resource_capacity ||
      info->operation_count > state->impl->config.operation_capacity ||
      info->event_count > state->impl->config.event_capacity ||
      (info->resource_count != 0u && resources == NULL) ||
      (info->operation_count != 0u && operations == NULL) ||
      (info->event_count != 0u && events == NULL) ||
      mesh_control_state_get_usage_v1(state, &usage) != MESH_CONTROL_OK ||
      usage.resource_count != 0u || usage.operation_count != 0u || usage.event_count != 0u)
    return MESH_CONTROL_INVALID_ARG;

  for (index = 0u; index < info->resource_count; ++index) {
    if (!resource_record_valid(&resources[index], &state->impl->config) ||
        retained_document_bytes >
            state->impl->config.desired_document_retained_bytes - resources[index].document_size)
      return MESH_CONTROL_INVALID_ARG;
    retained_document_bytes += resources[index].document_size;
  }
  for (index = 0u; index < info->operation_count; ++index) {
    if (!operation_record_valid(&operations[index]))
      return MESH_CONTROL_INVALID_ARG;
  }
  if (info->next_event_cursor <= (uint64_t)info->event_count)
    return MESH_CONTROL_INVALID_ARG;
  for (index = 0u; index < info->event_count; ++index) {
    uint64_t expected_cursor =
        info->next_event_cursor - (uint64_t)info->event_count + (uint64_t)index;
    if (!event_record_valid(&events[index]) || events[index].cursor != expected_cursor)
      return MESH_CONTROL_INVALID_ARG;
  }
  if (!checkpoint_inputs_unique_and_bound(info, resources, operations, events))
    return MESH_CONTROL_INVALID_ARG;

  if (info->resource_count != 0u) {
    document_copies = (uint8_t **)calloc(info->resource_count, sizeof(*document_copies));
    if (document_copies == NULL)
      return MESH_CONTROL_RESOURCE_EXHAUSTED;
  }
  for (index = 0u; index < info->resource_count; ++index) {
    if (resources[index].document_size == 0u)
      continue;
    document_copies[index] = (uint8_t *)malloc(resources[index].document_size);
    if (document_copies[index] == NULL)
      goto allocation_failed;
    memcpy(document_copies[index], resources[index].document, resources[index].document_size);
  }

  for (index = 0u; index < info->resource_count; ++index) {
    mesh_control_resource_slot_v1_t *slot = &state->impl->resources[index];
    slot->occupied = 1u;
    slot->status = resources[index].status;
    slot->desired_document = document_copies[index];
    slot->desired_document_size = resources[index].document_size;
    document_copies[index] = NULL;
  }
  for (index = 0u; index < info->operation_count; ++index) {
    mesh_control_operation_slot_v1_t *slot = &state->impl->operations[index];
    slot->occupied = 1u;
    slot->operation = operations[index].operation;
    slot->terminal_expires_at_ms = operations[index].terminal_expires_at_ms;
  }
  if (info->event_count != 0u)
    memcpy(state->impl->events, events, info->event_count * sizeof(*events));
  state->impl->event_count = info->event_count;
  state->impl->event_head = 0u;
  state->impl->next_cursor = info->next_event_cursor;
  state->impl->snapshot_generation = info->snapshot_generation;
  state->impl->retained_document_bytes = retained_document_bytes;
  free(document_copies);
  return MESH_CONTROL_OK;

allocation_failed:
  for (index = 0u; index < info->resource_count; ++index)
    free(document_copies[index]);
  free(document_copies);
  return MESH_CONTROL_RESOURCE_EXHAUSTED;
}

mesh_control_result_t mesh_control_state_snapshot_v1(
    const mesh_control_state_v1_t *state, mesh_control_resource_status_v1_t *resources,
    size_t resource_capacity, size_t *out_resource_count, mesh_control_operation_v1_t *operations,
    size_t operation_capacity, size_t *out_operation_count, uint64_t *out_event_cursor) {
  size_t resource_count = 0u;
  size_t operation_count = 0u;
  size_t index;

  if (state == NULL || state->impl == NULL || out_resource_count == NULL ||
      out_operation_count == NULL || out_event_cursor == NULL ||
      (resource_capacity != 0u && resources == NULL) ||
      (operation_capacity != 0u && operations == NULL)) {
    return MESH_CONTROL_INVALID_ARG;
  }
  *out_resource_count = 0u;
  *out_operation_count = 0u;
  *out_event_cursor = state->impl->next_cursor - 1u;
  for (index = 0u; index < state->impl->config.resource_capacity; ++index) {
    if (state->impl->resources[index].occupied)
      ++resource_count;
  }
  for (index = 0u; index < state->impl->config.operation_capacity; ++index) {
    if (state->impl->operations[index].occupied)
      ++operation_count;
  }
  *out_resource_count = resource_count;
  *out_operation_count = operation_count;
  if (resource_capacity < resource_count || operation_capacity < operation_count) {
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  }
  resource_count = 0u;
  operation_count = 0u;
  for (index = 0u; index < state->impl->config.resource_capacity; ++index) {
    if (state->impl->resources[index].occupied)
      resources[resource_count++] = state->impl->resources[index].status;
  }
  for (index = 0u; index < state->impl->config.operation_capacity; ++index) {
    if (state->impl->operations[index].occupied)
      operations[operation_count++] = state->impl->operations[index].operation;
  }
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_state_snapshot_page_v1(
    const mesh_control_state_v1_t *state, uint64_t expected_generation, size_t resource_offset,
    mesh_control_resource_status_v1_t *resources, size_t resource_capacity, size_t operation_offset,
    mesh_control_operation_v1_t *operations, size_t operation_capacity,
    mesh_control_snapshot_page_info_v1_t *out_info) {
  size_t resource_seen = 0u;
  size_t operation_seen = 0u;
  size_t index;

  if (state == NULL || state->impl == NULL || out_info == NULL ||
      (resource_capacity != 0u && resources == NULL) ||
      (operation_capacity != 0u && operations == NULL))
    return MESH_CONTROL_INVALID_ARG;
  memset(out_info, 0, sizeof(*out_info));
  out_info->generation = state->impl->snapshot_generation;
  out_info->event_cursor = state->impl->next_cursor - 1u;
  if (expected_generation != 0u && expected_generation != state->impl->snapshot_generation)
    return MESH_CONTROL_CONFLICT;
  for (index = 0u; index < state->impl->config.resource_capacity; ++index) {
    if (state->impl->resources[index].occupied)
      ++out_info->resource_total;
  }
  for (index = 0u; index < state->impl->config.operation_capacity; ++index) {
    if (state->impl->operations[index].occupied)
      ++out_info->operation_total;
  }
  if (resource_offset > out_info->resource_total || operation_offset > out_info->operation_total)
    return MESH_CONTROL_INVALID_ARG;
  out_info->resource_offset = resource_offset;
  out_info->operation_offset = operation_offset;
  for (index = 0u; index < state->impl->config.resource_capacity; ++index) {
    if (!state->impl->resources[index].occupied)
      continue;
    if (resource_seen++ < resource_offset)
      continue;
    if (out_info->resource_count == resource_capacity)
      break;
    resources[out_info->resource_count++] = state->impl->resources[index].status;
  }
  for (index = 0u; index < state->impl->config.operation_capacity; ++index) {
    if (!state->impl->operations[index].occupied)
      continue;
    if (operation_seen++ < operation_offset)
      continue;
    if (out_info->operation_count == operation_capacity)
      break;
    operations[out_info->operation_count++] = state->impl->operations[index].operation;
  }
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_state_events_after_v1(const mesh_control_state_v1_t *state,
                                                         uint64_t cursor,
                                                         mesh_control_event_v1_t *output,
                                                         size_t output_capacity, size_t *out_count,
                                                         uint64_t *out_next_cursor) {
  uint64_t oldest_cursor;
  size_t index;
  size_t count = 0u;

  if (state == NULL || state->impl == NULL || out_count == NULL || out_next_cursor == NULL ||
      (output_capacity != 0u && output == NULL))
    return MESH_CONTROL_INVALID_ARG;
  *out_count = 0u;
  *out_next_cursor = cursor;
  if (state->impl->event_count == 0u)
    return MESH_CONTROL_OK;
  oldest_cursor = state->impl->events[state->impl->event_head].cursor;
  if (cursor != 0u && cursor < oldest_cursor - 1u)
    return MESH_CONTROL_CONFLICT;
  for (index = 0u; index < state->impl->event_count && count < output_capacity; ++index) {
    const mesh_control_event_v1_t *event =
        &state->impl
             ->events[(state->impl->event_head + index) % state->impl->config.event_capacity];
    if (event->cursor <= cursor)
      continue;
    output[count++] = *event;
    *out_next_cursor = event->cursor;
  }
  *out_count = count;
  return MESH_CONTROL_OK;
}
