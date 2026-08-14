#ifndef MESH_CONTROL_STATE_H
#define MESH_CONTROL_STATE_H

#include "mesh_control_primitives.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_CONTROL_STATE_MAX_RESOURCES_V1 4096u
#define MESH_CONTROL_STATE_MAX_OPERATIONS_V1 4096u
#define MESH_CONTROL_STATE_MAX_EVENTS_V1 8192u
#define MESH_CONTROL_STATE_MAX_DESIRED_DOCUMENT_SIZE_V1 MESH_CONTROL_MAX_FRAME_SIZE_V1
#define MESH_CONTROL_STATE_MAX_RETAINED_DOCUMENT_BYTES_V1 MESH_CONTROL_OUTBOX_MAX_RETAINED_BYTES_V1

typedef enum {
  MESH_CONTROL_PRESENCE_ABSENT = 1,
  MESH_CONTROL_PRESENCE_PRESENT = 2
} mesh_control_presence_v1_t;

typedef struct {
  size_t resource_capacity;
  size_t operation_capacity;
  size_t event_capacity;
  uint64_t terminal_retention_ms;
  size_t desired_document_max_bytes;
  size_t desired_document_retained_bytes;
} mesh_control_state_config_v1_t;

typedef struct {
  size_t resource_count;
  size_t operation_count;
  size_t event_count;
  size_t retained_document_bytes;
  size_t retained_document_capacity;
} mesh_control_state_usage_v1_t;

typedef struct {
  uint16_t resource_kind;
  uint8_t resource_id[MESH_CONTROL_DIGEST_SIZE];
  uint64_t desired_epoch;
  uint64_t observed_epoch;
  uint16_t desired_presence;
  uint16_t observed_presence;
  uint8_t desired_digest[MESH_CONTROL_DIGEST_SIZE];
  uint8_t observed_digest[MESH_CONTROL_DIGEST_SIZE];
} mesh_control_resource_status_v1_t;

typedef struct {
  uint8_t operation_id[MESH_CONTROL_ID_SIZE];
  uint8_t request_id[MESH_CONTROL_ID_SIZE];
  uint8_t message_id[MESH_CONTROL_ID_SIZE];
  uint16_t resource_kind;
  uint16_t action;
  uint8_t resource_id[MESH_CONTROL_DIGEST_SIZE];
  uint8_t desired_digest[MESH_CONTROL_DIGEST_SIZE];
  uint64_t desired_epoch;
  uint64_t created_at_ms;
  uint64_t updated_at_ms;
  uint16_t state;
} mesh_control_operation_v1_t;

typedef struct {
  uint64_t cursor;
  uint8_t operation_id[MESH_CONTROL_ID_SIZE];
  uint16_t resource_kind;
  uint16_t operation_state;
  uint8_t resource_id[MESH_CONTROL_DIGEST_SIZE];
  uint64_t desired_epoch;
  uint64_t recorded_at_ms;
} mesh_control_event_v1_t;

typedef struct {
  uint64_t generation;
  uint64_t event_cursor;
  size_t resource_total;
  size_t operation_total;
  size_t resource_offset;
  size_t resource_count;
  size_t operation_offset;
  size_t operation_count;
} mesh_control_snapshot_page_info_v1_t;

typedef struct {
  mesh_control_resource_status_v1_t status;
  const uint8_t *document;
  size_t document_size;
} mesh_control_state_resource_record_v1_t;

typedef struct {
  mesh_control_operation_v1_t operation;
  uint64_t terminal_expires_at_ms;
} mesh_control_state_operation_record_v1_t;

typedef struct {
  uint64_t snapshot_generation;
  uint64_t next_event_cursor;
  size_t resource_count;
  size_t operation_count;
  size_t event_count;
} mesh_control_state_checkpoint_info_v1_t;

struct mesh_control_state_impl_v1;

/** Single-owner desired/observed fact source. No operation is thread-safe. */
typedef struct {
  struct mesh_control_state_impl_v1 *impl;
} mesh_control_state_v1_t;

mesh_control_result_t mesh_control_state_init_v1(mesh_control_state_v1_t *state,
                                                 const mesh_control_state_config_v1_t *config);

void mesh_control_state_destroy_v1(mesh_control_state_v1_t *state);

/**
 * Atomically creates an operation and advances desired state. The envelope
 * must be INTENT. precondition_epoch is compared with current desired epoch.
 * A DELETE records an ABSENT tombstone; it never immediately destroys data.
 */
mesh_control_result_t mesh_control_state_submit_v1(mesh_control_state_v1_t *state,
                                                   const mesh_control_envelope_v1_t *envelope,
                                                   mesh_control_desired_action_v1_t action,
                                                   uint64_t now_ms,
                                                   mesh_control_operation_v1_t *out_operation);

/**
 * Same transaction as submit_v1, additionally retaining a bounded owned copy
 * of the canonical reconciliation document. APPLY replaces it. DELETE with
 * an empty document preserves the last APPLY document so a reconciler can
 * identify the prestaged provider that owns removal. No state changes on
 * allocation or byte-budget failure.
 */
mesh_control_result_t mesh_control_state_submit_document_v1(
    mesh_control_state_v1_t *state, const mesh_control_envelope_v1_t *envelope,
    mesh_control_desired_action_v1_t action, const uint8_t *document, size_t document_size,
    uint64_t now_ms, mesh_control_operation_v1_t *out_operation);

/**
 * Pure preflight for submit_document_v1 after any desired retention sweep.
 * It validates deterministic schema, capacity, request and epoch constraints
 * without allocating memory or changing state. A single owner must prevent
 * intervening state mutations before the corresponding submit.
 */
mesh_control_result_t mesh_control_state_validate_document_v1(
    const mesh_control_state_v1_t *state, const mesh_control_envelope_v1_t *envelope,
    mesh_control_desired_action_v1_t action, const uint8_t *document, size_t document_size,
    uint64_t now_ms);

/**
 * Records reconciler-observed state and completes the matching operation when
 * desired and observed presence/digest agree. observed_epoch cannot move
 * backward or exceed desired_epoch.
 */
mesh_control_result_t
mesh_control_state_observe_v1(mesh_control_state_v1_t *state, uint16_t resource_kind,
                              const uint8_t resource_id[MESH_CONTROL_DIGEST_SIZE],
                              uint64_t observed_epoch, mesh_control_presence_v1_t presence,
                              const uint8_t digest[MESH_CONTROL_DIGEST_SIZE], uint64_t now_ms);

mesh_control_result_t mesh_control_state_transition_operation_v1(
    mesh_control_state_v1_t *state, const uint8_t operation_id[MESH_CONTROL_ID_SIZE],
    mesh_control_operation_state_v1_t next_state, uint64_t now_ms);

mesh_control_result_t
mesh_control_state_get_resource_v1(const mesh_control_state_v1_t *state, uint16_t resource_kind,
                                   const uint8_t resource_id[MESH_CONTROL_DIGEST_SIZE],
                                   mesh_control_resource_status_v1_t *out_status);

mesh_control_result_t
mesh_control_state_get_operation_v1(const mesh_control_state_v1_t *state,
                                    const uint8_t operation_id[MESH_CONTROL_ID_SIZE],
                                    mesh_control_operation_v1_t *out_operation);

/**
 * Returns the read-only reconciliation-document view owned by the state. For
 * an ABSENT tombstone this can be the retained last APPLY document. It remains
 * valid only until the next state mutation or destroy and must not cross the
 * owner thread boundary.
 */
mesh_control_result_t
mesh_control_state_get_desired_document_v1(const mesh_control_state_v1_t *state,
                                           uint16_t resource_kind,
                                           const uint8_t resource_id[MESH_CONTROL_DIGEST_SIZE],
                                           const uint8_t **out_document, size_t *out_document_size);

mesh_control_result_t mesh_control_state_get_usage_v1(const mesh_control_state_v1_t *state,
                                                      mesh_control_state_usage_v1_t *out_usage);

/**
 * Exports the complete state needed for a durable checkpoint. Document
 * pointers are borrowed and become invalid on the next state mutation or
 * destroy. Counts are always returned; insufficient arrays produce
 * RESOURCE_EXHAUSTED without a partial copy.
 */
mesh_control_result_t mesh_control_state_export_v1(
    const mesh_control_state_v1_t *state, mesh_control_state_resource_record_v1_t *resources,
    size_t resource_capacity, mesh_control_state_operation_record_v1_t *operations,
    size_t operation_capacity, mesh_control_event_v1_t *events, size_t event_capacity,
    mesh_control_state_checkpoint_info_v1_t *out_info);

/**
 * Imports a fully validated checkpoint into a newly initialized empty state.
 * All document bytes are copied before commit. On any validation, capacity or
 * allocation failure the state remains empty. The caller owns all inputs.
 */
mesh_control_result_t
mesh_control_state_import_v1(mesh_control_state_v1_t *state,
                             const mesh_control_state_checkpoint_info_v1_t *info,
                             const mesh_control_state_resource_record_v1_t *resources,
                             const mesh_control_state_operation_record_v1_t *operations,
                             const mesh_control_event_v1_t *events);

/**
 * Copies one owner-consistent full snapshot into caller-owned bounded arrays.
 * The output counts are always set to the required capacities. If either
 * array is too small, returns RESOURCE_EXHAUSTED without copying a partial
 * snapshot. out_event_cursor is the cursor after which incremental events can
 * resume. Only the domain owner may call this API.
 */
mesh_control_result_t mesh_control_state_snapshot_v1(
    const mesh_control_state_v1_t *state, mesh_control_resource_status_v1_t *resources,
    size_t resource_capacity, size_t *out_resource_count, mesh_control_operation_v1_t *operations,
    size_t operation_capacity, size_t *out_operation_count, uint64_t *out_event_cursor);

/**
 * Copies a bounded page from one owner-consistent state generation. Pass
 * expected_generation=0 to start a snapshot and use the returned generation
 * for every subsequent page. CONFLICT means any visible state changed between
 * pages and the caller must restart at offset zero. Offsets may equal totals
 * to request only the other record class. No pointers are retained.
 */
mesh_control_result_t mesh_control_state_snapshot_page_v1(
    const mesh_control_state_v1_t *state, uint64_t expected_generation, size_t resource_offset,
    mesh_control_resource_status_v1_t *resources, size_t resource_capacity, size_t operation_offset,
    mesh_control_operation_v1_t *operations, size_t operation_capacity,
    mesh_control_snapshot_page_info_v1_t *out_info);

/**
 * Returns events strictly after cursor. cursor=0 starts at the oldest retained
 * event. CONFLICT means the cursor fell behind retention and the caller must
 * fetch a full status snapshot. out_next_cursor is the last returned cursor.
 */
mesh_control_result_t mesh_control_state_events_after_v1(const mesh_control_state_v1_t *state,
                                                         uint64_t cursor,
                                                         mesh_control_event_v1_t *output,
                                                         size_t output_capacity, size_t *out_count,
                                                         uint64_t *out_next_cursor);

/** Removes expired terminal operations only; resources and events are bounded. */
size_t mesh_control_state_sweep_v1(mesh_control_state_v1_t *state, uint64_t now_ms);

#ifdef __cplusplus
}
#endif

#endif
