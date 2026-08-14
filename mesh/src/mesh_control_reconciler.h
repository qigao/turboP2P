#ifndef MESH_CONTROL_RECONCILER_H
#define MESH_CONTROL_RECONCILER_H

#include "mesh_control_document.h"
#include "mesh_control_state.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_CONTROL_RECONCILER_MAX_PROVIDERS_V1 32u
#define MESH_CONTROL_RECONCILER_MAX_INFLIGHT_V1 MESH_CONTROL_STATE_MAX_OPERATIONS_V1

typedef enum {
  MESH_CONTROL_PROVIDER_COMPLETED = 1,
  MESH_CONTROL_PROVIDER_FAILED = 2
} mesh_control_provider_completion_state_v1_t;

/**
 * Immutable request passed to a prestaged provider. The provider must copy
 * everything it retains before try_start returns. No path, argv, dynamic
 * library name, executable bytes, or ambient authority crosses this boundary.
 */
typedef struct {
  mesh_control_operation_v1_t operation;
  mesh_control_function_spec_v1_t spec;
} mesh_control_provider_request_v1_t;

typedef struct {
  uint8_t operation_id[MESH_CONTROL_ID_SIZE];
  uint16_t state;
  uint16_t reserved;
} mesh_control_provider_completion_v1_t;

typedef struct {
  mesh_control_operation_v1_t operation;
  mesh_control_provider_completion_v1_t completion;
} mesh_control_reconciler_prepared_completion_v1_t;

/**
 * Non-blocking provider strategy. try_start returns RESOURCE_EXHAUSTED for
 * temporary backpressure without consuming the request; every non-OK return
 * means the request was not consumed. try_peek_completion returns EMPTY when
 * no completion is ready and must retain the same completion until an exact
 * ack_completion succeeds. close is idempotent and starts cancellation/drain;
 * it MUST NOT discard a ready, unacknowledged completion. is_drained becomes
 * true only when provider-owned work and retained request data, including any
 * unacknowledged completion, have been released.
 */
typedef struct {
  mesh_control_result_t (*try_start)(void *context,
                                     const mesh_control_provider_request_v1_t *request);
  mesh_control_result_t (*try_peek_completion)(
      void *context, mesh_control_provider_completion_v1_t *out_completion);
  mesh_control_result_t (*ack_completion)(void *context,
                                          const uint8_t operation_id[MESH_CONTROL_ID_SIZE]);
  void (*close)(void *context);
  int (*is_drained)(void *context);
} mesh_control_provider_ops_v1_t;

typedef struct {
  uint8_t provider_id[MESH_CONTROL_DIGEST_SIZE];
  uint16_t runtime;
  uint16_t reserved;
  mesh_control_provider_ops_v1_t ops;
  void *context;
} mesh_control_provider_v1_t;

typedef struct {
  const mesh_control_provider_v1_t *providers;
  size_t provider_count;
  size_t inflight_capacity;
} mesh_control_reconciler_config_v1_t;

typedef struct {
  size_t queued;
  size_t inflight;
  size_t capacity;
  uint64_t started;
  uint64_t succeeded;
  uint64_t failed;
  uint64_t interrupted;
  uint64_t provider_backpressure;
  uint64_t rejected_completions;
} mesh_control_reconciler_stats_v1_t;

struct mesh_control_reconciler_impl_v1;

/** Single-owner registry and reconciliation loop; no API is thread-safe. */
typedef struct {
  struct mesh_control_reconciler_impl_v1 *impl;
} mesh_control_reconciler_v1_t;

mesh_control_result_t
mesh_control_reconciler_init_v1(mesh_control_reconciler_v1_t *reconciler,
                                const mesh_control_reconciler_config_v1_t *config);

/** Returns OK only for an exactly registered provider/runtime pair. */
mesh_control_result_t
mesh_control_reconciler_has_provider_v1(const mesh_control_reconciler_v1_t *reconciler,
                                        const uint8_t provider_id[MESH_CONTROL_DIGEST_SIZE],
                                        uint16_t runtime);

/**
 * Adds an ACCEPTED function operation to the bounded reconcile set. For
 * DELETE, document is the retained last APPLY document used to select the
 * provider. A duplicate identical operation is idempotent.
 */
mesh_control_result_t
mesh_control_reconciler_enqueue_v1(mesh_control_reconciler_v1_t *reconciler,
                                   const mesh_control_operation_v1_t *operation,
                                   const uint8_t *document, size_t document_size);

/**
 * Polls at most the supplied completion/start budgets and commits results to
 * state. Both budgets must be non-zero. Provider callbacks must not block.
 */
mesh_control_result_t mesh_control_reconciler_poll_v1(mesh_control_reconciler_v1_t *reconciler,
                                                      mesh_control_state_v1_t *state,
                                                      size_t completion_budget, size_t start_budget,
                                                      uint64_t now_ms, size_t *out_progress);

/** Peeks and retains one provider completion without changing owner state. */
mesh_control_result_t mesh_control_reconciler_prepare_completion_v1(
    mesh_control_reconciler_v1_t *reconciler,
    mesh_control_reconciler_prepared_completion_v1_t *out_prepared);

/** Applies the prepared result and ACKs the provider after durable logging. */
mesh_control_result_t
mesh_control_reconciler_commit_completion_v1(mesh_control_reconciler_v1_t *reconciler,
                                             mesh_control_state_v1_t *state, uint64_t now_ms);

mesh_control_result_t
mesh_control_reconciler_apply_completion_v1(mesh_control_reconciler_v1_t *reconciler,
                                            mesh_control_state_v1_t *state, uint64_t now_ms);

mesh_control_result_t
mesh_control_reconciler_ack_completion_v1(mesh_control_reconciler_v1_t *reconciler);

/** Starts queued work without consuming provider completions. */
mesh_control_result_t
mesh_control_reconciler_poll_starts_v1(mesh_control_reconciler_v1_t *reconciler,
                                       mesh_control_state_v1_t *state, size_t start_budget,
                                       uint64_t now_ms, size_t *out_progress);

/**
 * Interrupts queued/cancelled work only after all closed providers are drained.
 * It never peeks, applies, or ACKs a provider completion and is therefore safe
 * to pair with an external durable-result gate during shutdown.
 */
mesh_control_result_t
mesh_control_reconciler_poll_shutdown_v1(mesh_control_reconciler_v1_t *reconciler,
                                         mesh_control_state_v1_t *state, size_t budget,
                                         uint64_t now_ms, size_t *out_progress);

/** Stops new work and asks every provider to cancel/drain exactly once. */
mesh_control_result_t mesh_control_reconciler_close_v1(mesh_control_reconciler_v1_t *reconciler);

int mesh_control_reconciler_is_drained_v1(const mesh_control_reconciler_v1_t *reconciler);

mesh_control_result_t
mesh_control_reconciler_get_stats_v1(const mesh_control_reconciler_v1_t *reconciler,
                                     mesh_control_reconciler_stats_v1_t *out_stats);

/** Providers and their contexts must be drained and quiescent. */
void mesh_control_reconciler_destroy_v1(mesh_control_reconciler_v1_t *reconciler);

#ifdef __cplusplus
}
#endif

#endif
