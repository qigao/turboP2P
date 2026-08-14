#include "mesh_control_reconciler.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
  RECONCILE_ENTRY_QUEUED = 1,
  RECONCILE_ENTRY_INFLIGHT = 2,
  RECONCILE_ENTRY_COMPLETION_APPLIED = 3
} reconcile_entry_state_v1_t;

typedef struct {
  uint8_t occupied;
  uint8_t state;
  size_t provider_index;
  uint16_t completion_state;
  uint64_t enqueue_sequence;
  mesh_control_provider_request_v1_t request;
} reconcile_entry_v1_t;

struct mesh_control_reconciler_impl_v1 {
  mesh_control_provider_v1_t *providers;
  size_t provider_count;
  reconcile_entry_v1_t *entries;
  size_t capacity;
  size_t completion_provider_cursor;
  size_t prepared_provider_index;
  mesh_control_provider_completion_v1_t prepared_completion;
  uint64_t next_enqueue_sequence;
  mesh_control_reconciler_stats_v1_t stats;
  uint8_t completion_prepared;
  uint8_t closed;
};

static int bytes_zero(const uint8_t *bytes, size_t size) {
  uint8_t aggregate = 0u;
  size_t index;
  for (index = 0u; index < size; ++index)
    aggregate |= bytes[index];
  return aggregate == 0u;
}

static int provider_valid(const mesh_control_provider_v1_t *provider) {
  return provider != NULL && !bytes_zero(provider->provider_id, sizeof(provider->provider_id)) &&
         (provider->runtime == MESH_CONTROL_FUNCTION_BUILTIN ||
          provider->runtime == MESH_CONTROL_FUNCTION_NATIVE ||
          provider->runtime == MESH_CONTROL_FUNCTION_WASM) &&
         provider->reserved == 0u && provider->ops.try_start != NULL &&
         provider->ops.try_peek_completion != NULL && provider->ops.ack_completion != NULL &&
         provider->ops.close != NULL && provider->ops.is_drained != NULL;
}

static size_t find_provider(const struct mesh_control_reconciler_impl_v1 *impl,
                            const uint8_t provider_id[MESH_CONTROL_DIGEST_SIZE], uint16_t runtime) {
  size_t index;
  for (index = 0u; index < impl->provider_count; ++index) {
    if (impl->providers[index].runtime == runtime &&
        memcmp(impl->providers[index].provider_id, provider_id, MESH_CONTROL_DIGEST_SIZE) == 0)
      return index;
  }
  return SIZE_MAX;
}

static reconcile_entry_v1_t *find_entry(struct mesh_control_reconciler_impl_v1 *impl,
                                        const uint8_t operation_id[MESH_CONTROL_ID_SIZE]) {
  size_t index;
  for (index = 0u; index < impl->capacity; ++index) {
    reconcile_entry_v1_t *entry = &impl->entries[index];
    if (entry->occupied &&
        memcmp(entry->request.operation.operation_id, operation_id, MESH_CONTROL_ID_SIZE) == 0)
      return entry;
  }
  return NULL;
}

static int same_resource(const reconcile_entry_v1_t *left, const reconcile_entry_v1_t *right) {
  return left->request.operation.resource_kind == right->request.operation.resource_kind &&
         memcmp(left->request.operation.resource_id, right->request.operation.resource_id,
                MESH_CONTROL_DIGEST_SIZE) == 0;
}

static int resource_has_inflight(const struct mesh_control_reconciler_impl_v1 *impl,
                                 const reconcile_entry_v1_t *candidate) {
  size_t index;
  for (index = 0u; index < impl->capacity; ++index) {
    const reconcile_entry_v1_t *entry = &impl->entries[index];
    if (entry != candidate && entry->occupied && entry->state == RECONCILE_ENTRY_INFLIGHT &&
        same_resource(entry, candidate))
      return 1;
  }
  return 0;
}

static reconcile_entry_v1_t *next_queued(struct mesh_control_reconciler_impl_v1 *impl) {
  reconcile_entry_v1_t *selected = NULL;
  size_t index;
  for (index = 0u; index < impl->capacity; ++index) {
    reconcile_entry_v1_t *entry = &impl->entries[index];
    if (!entry->occupied || entry->state != RECONCILE_ENTRY_QUEUED ||
        resource_has_inflight(impl, entry))
      continue;
    if (selected == NULL || entry->enqueue_sequence < selected->enqueue_sequence)
      selected = entry;
  }
  return selected;
}

mesh_control_result_t
mesh_control_reconciler_init_v1(mesh_control_reconciler_v1_t *reconciler,
                                const mesh_control_reconciler_config_v1_t *config) {
  struct mesh_control_reconciler_impl_v1 *impl;
  size_t left;
  size_t right;

  if (reconciler == NULL || reconciler->impl != NULL || config == NULL ||
      config->providers == NULL || config->provider_count == 0u ||
      config->provider_count > MESH_CONTROL_RECONCILER_MAX_PROVIDERS_V1 ||
      config->inflight_capacity == 0u ||
      config->inflight_capacity > MESH_CONTROL_RECONCILER_MAX_INFLIGHT_V1)
    return MESH_CONTROL_INVALID_ARG;
  for (left = 0u; left < config->provider_count; ++left) {
    if (!provider_valid(&config->providers[left]))
      return MESH_CONTROL_INVALID_ARG;
    for (right = left + 1u; right < config->provider_count; ++right) {
      if (memcmp(config->providers[left].provider_id, config->providers[right].provider_id,
                 MESH_CONTROL_DIGEST_SIZE) == 0)
        return MESH_CONTROL_CONFLICT;
    }
  }
  impl = (struct mesh_control_reconciler_impl_v1 *)calloc(1u, sizeof(*impl));
  if (impl == NULL)
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  impl->providers =
      (mesh_control_provider_v1_t *)calloc(config->provider_count, sizeof(*impl->providers));
  impl->entries = (reconcile_entry_v1_t *)calloc(config->inflight_capacity, sizeof(*impl->entries));
  if (impl->providers == NULL || impl->entries == NULL) {
    free(impl->entries);
    free(impl->providers);
    free(impl);
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  }
  memcpy(impl->providers, config->providers, config->provider_count * sizeof(*impl->providers));
  impl->provider_count = config->provider_count;
  impl->capacity = config->inflight_capacity;
  impl->next_enqueue_sequence = 1u;
  impl->stats.capacity = impl->capacity;
  reconciler->impl = impl;
  return MESH_CONTROL_OK;
}

mesh_control_result_t
mesh_control_reconciler_has_provider_v1(const mesh_control_reconciler_v1_t *reconciler,
                                        const uint8_t provider_id[MESH_CONTROL_DIGEST_SIZE],
                                        uint16_t runtime) {
  if (reconciler == NULL || reconciler->impl == NULL || provider_id == NULL ||
      bytes_zero(provider_id, MESH_CONTROL_DIGEST_SIZE))
    return MESH_CONTROL_INVALID_ARG;
  return find_provider(reconciler->impl, provider_id, runtime) != SIZE_MAX ? MESH_CONTROL_OK
                                                                           : MESH_CONTROL_CONFLICT;
}

mesh_control_result_t
mesh_control_reconciler_enqueue_v1(mesh_control_reconciler_v1_t *reconciler,
                                   const mesh_control_operation_v1_t *operation,
                                   const uint8_t *document, size_t document_size) {
  struct mesh_control_reconciler_impl_v1 *impl;
  mesh_control_function_spec_v1_t spec;
  reconcile_entry_v1_t *entry;
  reconcile_entry_v1_t *free_entry = NULL;
  size_t provider_index;
  size_t index;

  if (reconciler == NULL || reconciler->impl == NULL || operation == NULL || document == NULL ||
      document_size == 0u || operation->resource_kind != MESH_CONTROL_RESOURCE_FUNCTION ||
      (operation->state != MESH_CONTROL_OPERATION_ACCEPTED &&
       operation->state != MESH_CONTROL_OPERATION_RUNNING) ||
      (operation->action != MESH_CONTROL_DESIRED_APPLY &&
       operation->action != MESH_CONTROL_DESIRED_DELETE) ||
      bytes_zero(operation->operation_id, sizeof(operation->operation_id)) ||
      mesh_control_function_document_decode_v1(document, document_size, &spec) != MESH_CONTROL_OK ||
      memcmp(operation->resource_id, spec.function_id, MESH_CONTROL_DIGEST_SIZE) != 0)
    return MESH_CONTROL_INVALID_ARG;
  impl = reconciler->impl;
  if (impl->closed)
    return MESH_CONTROL_CLOSED;
  if (operation->action == MESH_CONTROL_DESIRED_APPLY &&
      operation->desired_epoch != spec.generation)
    return MESH_CONTROL_CONFLICT;
  provider_index = find_provider(impl, spec.provider_id, spec.runtime);
  if (provider_index == SIZE_MAX)
    return MESH_CONTROL_CONFLICT;
  entry = find_entry(impl, operation->operation_id);
  if (entry != NULL) {
    return memcmp(&entry->request.operation, operation, sizeof(*operation)) == 0
               ? MESH_CONTROL_OK
               : MESH_CONTROL_CONFLICT;
  }
  if (impl->next_enqueue_sequence == UINT64_MAX)
    return MESH_CONTROL_INVALID_STATE;
  for (index = 0u; index < impl->capacity; ++index) {
    if (!impl->entries[index].occupied) {
      free_entry = &impl->entries[index];
      break;
    }
  }
  if (free_entry == NULL)
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  memset(free_entry, 0, sizeof(*free_entry));
  free_entry->occupied = 1u;
  free_entry->state = RECONCILE_ENTRY_QUEUED;
  free_entry->provider_index = provider_index;
  free_entry->enqueue_sequence = impl->next_enqueue_sequence++;
  free_entry->request.operation = *operation;
  free_entry->request.spec = spec;
  ++impl->stats.queued;
  return MESH_CONTROL_OK;
}

static mesh_control_result_t
apply_completion(reconcile_entry_v1_t *entry,
                 const mesh_control_provider_completion_v1_t *completion,
                 mesh_control_state_v1_t *state, uint64_t now_ms) {
  mesh_control_result_t result;
  uint8_t digest[MESH_CONTROL_DIGEST_SIZE] = {0u};

  if (completion->reserved != 0u || (completion->state != MESH_CONTROL_PROVIDER_COMPLETED &&
                                     completion->state != MESH_CONTROL_PROVIDER_FAILED))
    return MESH_CONTROL_INVALID_STATE;
  if (completion->state == MESH_CONTROL_PROVIDER_COMPLETED) {
    if (entry->request.operation.action == MESH_CONTROL_DESIRED_APPLY)
      memcpy(digest, entry->request.operation.desired_digest, sizeof(digest));
    result = mesh_control_state_observe_v1(
        state, entry->request.operation.resource_kind, entry->request.operation.resource_id,
        entry->request.operation.desired_epoch,
        entry->request.operation.action == MESH_CONTROL_DESIRED_APPLY
            ? MESH_CONTROL_PRESENCE_PRESENT
            : MESH_CONTROL_PRESENCE_ABSENT,
        digest, now_ms);
    if (result != MESH_CONTROL_OK)
      return result;
    result = mesh_control_state_transition_operation_v1(
        state, entry->request.operation.operation_id, MESH_CONTROL_OPERATION_SUCCEEDED, now_ms);
    if (result != MESH_CONTROL_OK)
      return result;
  } else {
    result = mesh_control_state_transition_operation_v1(
        state, entry->request.operation.operation_id, MESH_CONTROL_OPERATION_FAILED, now_ms);
    if (result != MESH_CONTROL_OK)
      return result;
  }
  entry->completion_state = completion->state;
  entry->state = RECONCILE_ENTRY_COMPLETION_APPLIED;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_reconciler_prepare_completion_v1(
    mesh_control_reconciler_v1_t *reconciler,
    mesh_control_reconciler_prepared_completion_v1_t *out_prepared) {
  struct mesh_control_reconciler_impl_v1 *impl;
  size_t empty_providers = 0u;

  if (!reconciler || !reconciler->impl || !out_prepared)
    return MESH_CONTROL_INVALID_ARG;
  impl = reconciler->impl;
  memset(out_prepared, 0, sizeof(*out_prepared));
  if (impl->completion_prepared) {
    reconcile_entry_v1_t *entry = find_entry(impl, impl->prepared_completion.operation_id);
    if (!entry)
      return MESH_CONTROL_INVALID_STATE;
    out_prepared->operation = entry->request.operation;
    out_prepared->completion = impl->prepared_completion;
    return MESH_CONTROL_OK;
  }
  while (empty_providers < impl->provider_count) {
    size_t provider_index = impl->completion_provider_cursor;
    mesh_control_provider_completion_v1_t completion;
    reconcile_entry_v1_t *entry;
    mesh_control_result_t result;
    impl->completion_provider_cursor =
        (impl->completion_provider_cursor + 1u) % impl->provider_count;
    memset(&completion, 0, sizeof(completion));
    result = impl->providers[provider_index].ops.try_peek_completion(
        impl->providers[provider_index].context, &completion);
    if (result == MESH_CONTROL_EMPTY) {
      ++empty_providers;
      continue;
    }
    empty_providers = 0u;
    if (result != MESH_CONTROL_OK) {
      ++impl->stats.rejected_completions;
      return MESH_CONTROL_INVALID_STATE;
    }
    entry = find_entry(impl, completion.operation_id);
    if (entry == NULL ||
        (entry->state != RECONCILE_ENTRY_INFLIGHT &&
         entry->state != RECONCILE_ENTRY_COMPLETION_APPLIED) ||
        entry->provider_index != provider_index) {
      ++impl->stats.rejected_completions;
      return MESH_CONTROL_INVALID_STATE;
    }
    impl->prepared_provider_index = provider_index;
    impl->prepared_completion = completion;
    impl->completion_prepared = 1u;
    out_prepared->operation = entry->request.operation;
    out_prepared->completion = completion;
    return MESH_CONTROL_OK;
  }
  return MESH_CONTROL_EMPTY;
}

mesh_control_result_t
mesh_control_reconciler_apply_completion_v1(mesh_control_reconciler_v1_t *reconciler,
                                            mesh_control_state_v1_t *state, uint64_t now_ms) {
  struct mesh_control_reconciler_impl_v1 *impl;
  reconcile_entry_v1_t *entry;
  mesh_control_result_t result;

  if (!reconciler || !reconciler->impl || !state)
    return MESH_CONTROL_INVALID_ARG;
  impl = reconciler->impl;
  if (!impl->completion_prepared || impl->prepared_provider_index >= impl->provider_count) {
    return MESH_CONTROL_INVALID_STATE;
  }
  entry = find_entry(impl, impl->prepared_completion.operation_id);
  if (!entry || entry->provider_index != impl->prepared_provider_index)
    return MESH_CONTROL_INVALID_STATE;
  if (entry->state == RECONCILE_ENTRY_INFLIGHT) {
    result = apply_completion(entry, &impl->prepared_completion, state, now_ms);
    if (result != MESH_CONTROL_OK)
      return result;
  } else if (entry->state != RECONCILE_ENTRY_COMPLETION_APPLIED ||
             entry->completion_state != impl->prepared_completion.state) {
    return MESH_CONTROL_INVALID_STATE;
  }
  return MESH_CONTROL_OK;
}

mesh_control_result_t
mesh_control_reconciler_ack_completion_v1(mesh_control_reconciler_v1_t *reconciler) {
  struct mesh_control_reconciler_impl_v1 *impl;
  reconcile_entry_v1_t *entry;
  mesh_control_result_t result;

  if (!reconciler || !reconciler->impl)
    return MESH_CONTROL_INVALID_ARG;
  impl = reconciler->impl;
  if (!impl->completion_prepared || impl->prepared_provider_index >= impl->provider_count)
    return MESH_CONTROL_INVALID_STATE;
  entry = find_entry(impl, impl->prepared_completion.operation_id);
  if (!entry || entry->provider_index != impl->prepared_provider_index ||
      entry->state != RECONCILE_ENTRY_COMPLETION_APPLIED ||
      entry->completion_state != impl->prepared_completion.state) {
    return MESH_CONTROL_INVALID_STATE;
  }
  result = impl->providers[impl->prepared_provider_index].ops.ack_completion(
      impl->providers[impl->prepared_provider_index].context,
      impl->prepared_completion.operation_id);
  if (result != MESH_CONTROL_OK) {
    ++impl->stats.rejected_completions;
    return MESH_CONTROL_INVALID_STATE;
  }
  if (entry->completion_state == MESH_CONTROL_PROVIDER_COMPLETED)
    ++impl->stats.succeeded;
  else
    ++impl->stats.failed;
  --impl->stats.inflight;
  memset(entry, 0, sizeof(*entry));
  memset(&impl->prepared_completion, 0, sizeof(impl->prepared_completion));
  impl->completion_prepared = 0u;
  return MESH_CONTROL_OK;
}

mesh_control_result_t
mesh_control_reconciler_commit_completion_v1(mesh_control_reconciler_v1_t *reconciler,
                                             mesh_control_state_v1_t *state, uint64_t now_ms) {
  mesh_control_result_t result =
      mesh_control_reconciler_apply_completion_v1(reconciler, state, now_ms);
  return result == MESH_CONTROL_OK ? mesh_control_reconciler_ack_completion_v1(reconciler) : result;
}

static mesh_control_result_t poll_completions(mesh_control_reconciler_v1_t *reconciler,
                                              mesh_control_state_v1_t *state, size_t budget,
                                              uint64_t now_ms, size_t *out_progress) {
  while (*out_progress < budget) {
    mesh_control_reconciler_prepared_completion_v1_t prepared;
    mesh_control_result_t result =
        mesh_control_reconciler_prepare_completion_v1(reconciler, &prepared);
    if (result == MESH_CONTROL_EMPTY)
      break;
    if (result != MESH_CONTROL_OK)
      return result;
    result = mesh_control_reconciler_commit_completion_v1(reconciler, state, now_ms);
    if (result != MESH_CONTROL_OK)
      return result;
    ++*out_progress;
  }
  return MESH_CONTROL_OK;
}

static mesh_control_result_t poll_starts(struct mesh_control_reconciler_impl_v1 *impl,
                                         mesh_control_state_v1_t *state, size_t budget,
                                         uint64_t now_ms, size_t *out_progress) {
  size_t attempts = 0u;

  while (*out_progress < budget && attempts < budget) {
    reconcile_entry_v1_t *entry = next_queued(impl);
    mesh_control_provider_v1_t *provider;
    mesh_control_result_t result;
    if (entry == NULL)
      break;
    ++attempts;
    provider = &impl->providers[entry->provider_index];
    result = provider->ops.try_start(provider->context, &entry->request);
    if (result == MESH_CONTROL_RESOURCE_EXHAUSTED) {
      ++impl->stats.provider_backpressure;
      /* Move this request behind other queued resources for this poll. */
      if (impl->next_enqueue_sequence == UINT64_MAX)
        return MESH_CONTROL_INVALID_STATE;
      entry->enqueue_sequence = impl->next_enqueue_sequence++;
      continue;
    }
    if (result == MESH_CONTROL_OK) {
      result = mesh_control_state_transition_operation_v1(
          state, entry->request.operation.operation_id, MESH_CONTROL_OPERATION_RUNNING, now_ms);
      if (result != MESH_CONTROL_OK)
        return result;
      entry->state = RECONCILE_ENTRY_INFLIGHT;
      --impl->stats.queued;
      ++impl->stats.inflight;
      ++impl->stats.started;
    } else {
      result = mesh_control_state_transition_operation_v1(
          state, entry->request.operation.operation_id, MESH_CONTROL_OPERATION_FAILED, now_ms);
      if (result != MESH_CONTROL_OK)
        return result;
      --impl->stats.queued;
      ++impl->stats.failed;
      memset(entry, 0, sizeof(*entry));
    }
    ++*out_progress;
  }
  return MESH_CONTROL_OK;
}

static int providers_are_drained(const struct mesh_control_reconciler_impl_v1 *impl) {
  size_t index;
  for (index = 0u; index < impl->provider_count; ++index) {
    if (!impl->providers[index].ops.is_drained(impl->providers[index].context))
      return 0;
  }
  return 1;
}

static mesh_control_result_t
interrupt_after_provider_drain(struct mesh_control_reconciler_impl_v1 *impl,
                               mesh_control_state_v1_t *state, uint64_t now_ms, size_t budget,
                               size_t *out_progress) {
  size_t index;
  if (!impl->closed || !providers_are_drained(impl))
    return MESH_CONTROL_OK;
  for (index = 0u; index < impl->capacity && *out_progress < budget; ++index) {
    reconcile_entry_v1_t *entry = &impl->entries[index];
    mesh_control_result_t result;
    if (!entry->occupied)
      continue;
    result = mesh_control_state_transition_operation_v1(
        state, entry->request.operation.operation_id, MESH_CONTROL_OPERATION_INTERRUPTED, now_ms);
    if (result != MESH_CONTROL_OK)
      return result;
    if (entry->state == RECONCILE_ENTRY_QUEUED)
      --impl->stats.queued;
    else
      --impl->stats.inflight;
    ++impl->stats.interrupted;
    ++*out_progress;
    memset(entry, 0, sizeof(*entry));
  }
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_reconciler_poll_v1(mesh_control_reconciler_v1_t *reconciler,
                                                      mesh_control_state_v1_t *state,
                                                      size_t completion_budget, size_t start_budget,
                                                      uint64_t now_ms, size_t *out_progress) {
  size_t completion_progress = 0u;
  size_t start_progress = 0u;
  mesh_control_result_t result;

  if (reconciler == NULL || reconciler->impl == NULL || state == NULL || completion_budget == 0u ||
      start_budget == 0u || out_progress == NULL)
    return MESH_CONTROL_INVALID_ARG;
  *out_progress = 0u;
  result = poll_completions(reconciler, state, completion_budget, now_ms, &completion_progress);
  if (result != MESH_CONTROL_OK)
    return result;
  if (!reconciler->impl->closed) {
    result = poll_starts(reconciler->impl, state, start_budget, now_ms, &start_progress);
    if (result != MESH_CONTROL_OK)
      return result;
  } else {
    result = interrupt_after_provider_drain(reconciler->impl, state, now_ms, completion_budget,
                                            &completion_progress);
    if (result != MESH_CONTROL_OK)
      return result;
  }
  *out_progress = completion_progress + start_progress;
  return MESH_CONTROL_OK;
}

mesh_control_result_t
mesh_control_reconciler_poll_starts_v1(mesh_control_reconciler_v1_t *reconciler,
                                       mesh_control_state_v1_t *state, size_t start_budget,
                                       uint64_t now_ms, size_t *out_progress) {
  if (!reconciler || !reconciler->impl || !state || start_budget == 0u || !out_progress)
    return MESH_CONTROL_INVALID_ARG;
  *out_progress = 0u;
  if (reconciler->impl->closed)
    return MESH_CONTROL_CLOSED;
  return poll_starts(reconciler->impl, state, start_budget, now_ms, out_progress);
}

mesh_control_result_t
mesh_control_reconciler_poll_shutdown_v1(mesh_control_reconciler_v1_t *reconciler,
                                         mesh_control_state_v1_t *state, size_t budget,
                                         uint64_t now_ms, size_t *out_progress) {
  if (!reconciler || !reconciler->impl || !state || budget == 0u || !out_progress)
    return MESH_CONTROL_INVALID_ARG;
  *out_progress = 0u;
  if (!reconciler->impl->closed)
    return MESH_CONTROL_INVALID_STATE;
  return interrupt_after_provider_drain(reconciler->impl, state, now_ms, budget, out_progress);
}

mesh_control_result_t mesh_control_reconciler_close_v1(mesh_control_reconciler_v1_t *reconciler) {
  size_t index;
  if (reconciler == NULL || reconciler->impl == NULL)
    return MESH_CONTROL_INVALID_ARG;
  if (reconciler->impl->closed)
    return MESH_CONTROL_OK;
  reconciler->impl->closed = 1u;
  for (index = 0u; index < reconciler->impl->provider_count; ++index)
    reconciler->impl->providers[index].ops.close(reconciler->impl->providers[index].context);
  return MESH_CONTROL_OK;
}

int mesh_control_reconciler_is_drained_v1(const mesh_control_reconciler_v1_t *reconciler) {
  size_t index;
  if (reconciler == NULL || reconciler->impl == NULL || !reconciler->impl->closed)
    return 0;
  if (!providers_are_drained(reconciler->impl))
    return 0;
  for (index = 0u; index < reconciler->impl->capacity; ++index) {
    if (reconciler->impl->entries[index].occupied)
      return 0;
  }
  return 1;
}

mesh_control_result_t
mesh_control_reconciler_get_stats_v1(const mesh_control_reconciler_v1_t *reconciler,
                                     mesh_control_reconciler_stats_v1_t *out_stats) {
  if (reconciler == NULL || reconciler->impl == NULL || out_stats == NULL)
    return MESH_CONTROL_INVALID_ARG;
  *out_stats = reconciler->impl->stats;
  return MESH_CONTROL_OK;
}

void mesh_control_reconciler_destroy_v1(mesh_control_reconciler_v1_t *reconciler) {
  size_t index;
  if (reconciler == NULL || reconciler->impl == NULL)
    return;
  if (!reconciler->impl->closed)
    (void)mesh_control_reconciler_close_v1(reconciler);
  for (index = 0u; index < reconciler->impl->capacity; ++index) {
    if (!reconciler->impl->entries[index].occupied)
      continue;
    if (reconciler->impl->entries[index].state == RECONCILE_ENTRY_QUEUED)
      --reconciler->impl->stats.queued;
    else
      --reconciler->impl->stats.inflight;
    ++reconciler->impl->stats.interrupted;
  }
  free(reconciler->impl->entries);
  free(reconciler->impl->providers);
  memset(reconciler->impl, 0, sizeof(*reconciler->impl));
  free(reconciler->impl);
  reconciler->impl = NULL;
}
