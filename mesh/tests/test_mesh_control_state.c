#include "mesh_control_state.h"
#include "tinytest.h"

#include <string.h>

static const mesh_control_state_config_v1_t TEST_CONFIG = {
    2u, 2u, 4u, 500u, 1024u, 2048u};

static void make_intent(mesh_control_envelope_v1_t *envelope,
                        uint8_t identity, uint64_t epoch,
                        uint64_t precondition_epoch) {
  memset(envelope, 0, sizeof(*envelope));
  envelope->schema_version = MESH_CONTROL_SCHEMA_V1;
  envelope->kind = MESH_CONTROL_MESSAGE_INTENT;
  envelope->message_id[0] = identity;
  envelope->request_id[0] = (uint8_t)(identity + 1u);
  envelope->mesh_id[0] = 1u;
  envelope->origin_principal[0] = 2u;
  envelope->target_node_id[0] = 3u;
  envelope->resource_kind = MESH_CONTROL_RESOURCE_FUNCTION;
  envelope->resource_id[0] = 4u;
  envelope->epoch = epoch;
  envelope->sequence = epoch;
  envelope->issued_at_ms = 1000u;
  envelope->expires_at_ms = 2000u;
  envelope->precondition_epoch = precondition_epoch;
  envelope->payload_digest[0] = identity;
  envelope->payload_size = 1u;
}

static void test_desired_observed_reconciliation_is_idempotent(void) {
  mesh_control_state_v1_t state = {0};
  mesh_control_envelope_v1_t intent;
  mesh_control_operation_v1_t operation;
  mesh_control_operation_v1_t replay;
  mesh_control_resource_status_v1_t status;

  make_intent(&intent, 10u, 1u, 0u);
  check_int_eq(mesh_control_state_init_v1(&state, &TEST_CONFIG),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_state_submit_v1(
                   &state, &intent, MESH_CONTROL_DESIRED_APPLY, 1100u,
                   &operation),
               MESH_CONTROL_OK);
  check_int_eq(operation.state, MESH_CONTROL_OPERATION_ACCEPTED);
  check_int_eq(mesh_control_state_submit_v1(
                   &state, &intent, MESH_CONTROL_DESIRED_APPLY, 1101u,
                   &replay),
               MESH_CONTROL_OK);
  check_mem_eq(replay.operation_id, operation.operation_id,
               sizeof(operation.operation_id));

  check_int_eq(mesh_control_state_observe_v1(
                   &state, intent.resource_kind, intent.resource_id, 1u,
                   MESH_CONTROL_PRESENCE_PRESENT, intent.payload_digest,
                   1200u),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_state_get_operation_v1(
                   &state, operation.operation_id, &operation),
               MESH_CONTROL_OK);
  check_int_eq(operation.state, MESH_CONTROL_OPERATION_SUCCEEDED);
  check_int_eq(mesh_control_state_get_resource_v1(
                   &state, intent.resource_kind, intent.resource_id, &status),
               MESH_CONTROL_OK);
  check_int_eq(status.desired_epoch, 1u);
  check_int_eq(status.observed_epoch, 1u);
  check_int_eq(status.desired_presence, MESH_CONTROL_PRESENCE_PRESENT);
  check_int_eq(status.observed_presence, MESH_CONTROL_PRESENCE_PRESENT);
  mesh_control_state_destroy_v1(&state);
}

static void test_preconditions_and_request_bindings_conflict(void) {
  mesh_control_state_v1_t state = {0};
  mesh_control_envelope_v1_t first;
  mesh_control_envelope_v1_t next;
  mesh_control_operation_v1_t operation;

  make_intent(&first, 20u, 1u, 0u);
  check_int_eq(mesh_control_state_init_v1(&state, &TEST_CONFIG),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_state_submit_v1(
                   &state, &first, MESH_CONTROL_DESIRED_APPLY, 1100u,
                   &operation),
               MESH_CONTROL_OK);
  first.payload_digest[0] ^= 1u;
  check_int_eq(mesh_control_state_submit_v1(
                   &state, &first, MESH_CONTROL_DESIRED_APPLY, 1101u,
                   &operation),
               MESH_CONTROL_CONFLICT);

  make_intent(&next, 30u, 2u, 0u);
  check_int_eq(mesh_control_state_submit_v1(
                   &state, &next, MESH_CONTROL_DESIRED_APPLY, 1102u,
                   &operation),
               MESH_CONTROL_CONFLICT);
  next.precondition_epoch = 1u;
  check_int_eq(mesh_control_state_submit_v1(
                   &state, &next, MESH_CONTROL_DESIRED_APPLY, 1103u,
                   &operation),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_state_observe_v1(
                   &state, next.resource_kind, next.resource_id, 3u,
                   MESH_CONTROL_PRESENCE_PRESENT, next.payload_digest,
                   1200u),
               MESH_CONTROL_CONFLICT);
  mesh_control_state_destroy_v1(&state);
}

static void test_delete_is_an_observed_tombstone(void) {
  mesh_control_state_v1_t state = {0};
  mesh_control_envelope_v1_t apply;
  mesh_control_envelope_v1_t remove;
  mesh_control_operation_v1_t operation;
  mesh_control_resource_status_v1_t status;
  uint8_t zero_digest[MESH_CONTROL_DIGEST_SIZE] = {0u};
  static const uint8_t reconciliation_document[] = {1u, 2u, 3u};
  const uint8_t *stored_document = NULL;
  size_t stored_document_size = 0u;

  make_intent(&apply, 40u, 1u, 0u);
  check_int_eq(mesh_control_state_init_v1(&state, &TEST_CONFIG),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_state_submit_document_v1(
                   &state, &apply, MESH_CONTROL_DESIRED_APPLY,
                   reconciliation_document,
                   sizeof(reconciliation_document), 1100u, &operation),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_state_observe_v1(
                   &state, apply.resource_kind, apply.resource_id, 1u,
                   MESH_CONTROL_PRESENCE_PRESENT, apply.payload_digest,
                   1110u),
               MESH_CONTROL_OK);

  make_intent(&remove, 50u, 2u, 1u);
  check_int_eq(mesh_control_state_submit_v1(
                   &state, &remove, MESH_CONTROL_DESIRED_DELETE, 1200u,
                   &operation),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_state_get_resource_v1(
                   &state, remove.resource_kind, remove.resource_id, &status),
               MESH_CONTROL_OK);
  check_int_eq(status.desired_presence, MESH_CONTROL_PRESENCE_ABSENT);
  check_mem_eq(status.desired_digest, zero_digest, sizeof(zero_digest));
  check_int_eq(mesh_control_state_get_desired_document_v1(
                   &state, remove.resource_kind, remove.resource_id,
                   &stored_document, &stored_document_size),
               MESH_CONTROL_OK);
  check_int_eq(stored_document_size, sizeof(reconciliation_document));
  check_mem_eq(stored_document, reconciliation_document,
               sizeof(reconciliation_document));
  check_int_eq(mesh_control_state_observe_v1(
                   &state, remove.resource_kind, remove.resource_id, 2u,
                   MESH_CONTROL_PRESENCE_ABSENT, zero_digest, 1250u),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_state_get_operation_v1(
                   &state, operation.operation_id, &operation),
               MESH_CONTROL_OK);
  check_int_eq(operation.state, MESH_CONTROL_OPERATION_SUCCEEDED);
  mesh_control_state_destroy_v1(&state);
}

static void test_event_cursor_replays_or_requires_snapshot(void) {
  mesh_control_state_v1_t state = {0};
  mesh_control_state_config_v1_t config = {
      2u, 2u, 2u, 500u, 1024u, 2048u};
  mesh_control_envelope_v1_t intent;
  mesh_control_operation_v1_t operation;
  mesh_control_operation_v1_t operations[2];
  mesh_control_event_v1_t events[2];
  mesh_control_resource_status_v1_t resources[2];
  mesh_control_envelope_v1_t second;
  size_t count = 0u;
  size_t resource_count = 0u;
  size_t operation_count = 0u;
  uint64_t cursor = 0u;

  make_intent(&intent, 60u, 1u, 0u);
  check_int_eq(mesh_control_state_init_v1(&state, &config), MESH_CONTROL_OK);
  check_int_eq(mesh_control_state_submit_v1(
                   &state, &intent, MESH_CONTROL_DESIRED_APPLY, 1100u,
                   &operation),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_state_transition_operation_v1(
                   &state, operation.operation_id,
                   MESH_CONTROL_OPERATION_RUNNING, 1110u),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_state_observe_v1(
                   &state, intent.resource_kind, intent.resource_id, 1u,
                   MESH_CONTROL_PRESENCE_PRESENT, intent.payload_digest,
                   1120u),
               MESH_CONTROL_OK);
  make_intent(&second, 70u, 1u, 0u);
  second.resource_id[0] = 5u;
  check_int_eq(mesh_control_state_submit_v1(
                   &state, &second, MESH_CONTROL_DESIRED_APPLY, 1130u,
                   &operation),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_state_events_after_v1(
                   &state, 0u, events, 2u, &count, &cursor),
               MESH_CONTROL_OK);
  check_int_eq(count, 2u);
  check_int_eq(events[0].operation_state, MESH_CONTROL_OPERATION_SUCCEEDED);
  check_int_eq(events[1].operation_state, MESH_CONTROL_OPERATION_ACCEPTED);
  check_int_eq(mesh_control_state_events_after_v1(
                   &state, 1u, events, 2u, &count, &cursor),
               MESH_CONTROL_CONFLICT);
  check_int_eq(mesh_control_state_snapshot_v1(
                   &state, resources, 1u, &resource_count, operations, 2u,
                   &operation_count, &cursor),
               MESH_CONTROL_RESOURCE_EXHAUSTED);
  check_int_eq(resource_count, 2u);
  check_int_eq(operation_count, 2u);
  check_int_eq(cursor, 4u);
  check_int_eq(mesh_control_state_snapshot_v1(
                   &state, resources, 2u, &resource_count, operations, 2u,
                   &operation_count, &cursor),
               MESH_CONTROL_OK);
  check_int_eq(resources[0].desired_epoch, 1u);
  check_int_eq(operations[0].state, MESH_CONTROL_OPERATION_SUCCEEDED);
  mesh_control_state_destroy_v1(&state);
}

static void test_snapshot_pages_require_one_generation(void) {
  mesh_control_state_v1_t state = {0};
  mesh_control_envelope_v1_t first;
  mesh_control_envelope_v1_t second;
  mesh_control_operation_v1_t operation;
  mesh_control_operation_v1_t operations[1];
  mesh_control_resource_status_v1_t resources[1];
  mesh_control_snapshot_page_info_v1_t first_page;
  mesh_control_snapshot_page_info_v1_t next_page;

  make_intent(&first, 80u, 1u, 0u);
  make_intent(&second, 90u, 1u, 0u);
  second.resource_id[0] = 5u;
  check_int_eq(mesh_control_state_init_v1(&state, &TEST_CONFIG),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_state_submit_v1(
                   &state, &first, MESH_CONTROL_DESIRED_APPLY, 1100u,
                   &operation),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_state_submit_v1(
                   &state, &second, MESH_CONTROL_DESIRED_APPLY, 1101u,
                   &operation),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_state_snapshot_page_v1(
                   &state, 0u, 0u, resources, 1u, 0u, operations, 1u,
                   &first_page),
               MESH_CONTROL_OK);
  check_int_eq(first_page.resource_total, 2u);
  check_int_eq(first_page.operation_total, 2u);
  check_int_eq(first_page.resource_count, 1u);
  check_int_eq(first_page.operation_count, 1u);

  check_int_eq(mesh_control_state_transition_operation_v1(
                   &state, operation.operation_id,
                   MESH_CONTROL_OPERATION_RUNNING, 1110u),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_state_snapshot_page_v1(
                   &state, first_page.generation, 1u, resources, 1u, 1u,
                   operations, 1u, &next_page),
               MESH_CONTROL_CONFLICT);
  check_true(next_page.generation > first_page.generation);
  check_int_eq(mesh_control_state_snapshot_page_v1(
                   &state, next_page.generation, 1u, resources, 1u, 1u,
                   operations, 1u, &next_page),
               MESH_CONTROL_OK);
  check_int_eq(next_page.resource_count, 1u);
  check_int_eq(next_page.operation_count, 1u);
  mesh_control_state_destroy_v1(&state);
}

static void test_desired_documents_are_owned_and_byte_bounded(void) {
  mesh_control_state_v1_t state = {0};
  mesh_control_state_config_v1_t config = {
      2u, 2u, 4u, 500u, 4u, 5u};
  mesh_control_envelope_v1_t first;
  mesh_control_envelope_v1_t second;
  mesh_control_operation_v1_t operation;
  mesh_control_resource_status_v1_t status;
  mesh_control_state_usage_v1_t usage;
  uint8_t document[4] = {1u, 2u, 3u, 4u};
  const uint8_t *stored = NULL;
  size_t stored_size = 0u;

  make_intent(&first, 100u, 1u, 0u);
  make_intent(&second, 110u, 1u, 0u);
  second.resource_id[0] = 5u;
  check_int_eq(mesh_control_state_init_v1(&state, &config),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_state_submit_document_v1(
                   &state, &first, MESH_CONTROL_DESIRED_APPLY, document,
                   sizeof(document), 1100u, &operation),
               MESH_CONTROL_OK);
  memset(document, 0xff, sizeof(document));
  check_int_eq(mesh_control_state_get_desired_document_v1(
                   &state, first.resource_kind, first.resource_id, &stored,
                   &stored_size),
               MESH_CONTROL_OK);
  check_int_eq(stored_size, 4u);
  check_int_eq(stored[0], 1u);
  check_int_eq(stored[3], 4u);

  check_int_eq(mesh_control_state_submit_document_v1(
                   &state, &second, MESH_CONTROL_DESIRED_APPLY, document, 2u,
                   1101u, &operation),
               MESH_CONTROL_RESOURCE_EXHAUSTED);
  check_int_eq(mesh_control_state_get_resource_v1(
                   &state, second.resource_kind, second.resource_id, &status),
               MESH_CONTROL_EMPTY);
  check_int_eq(mesh_control_state_get_usage_v1(&state, &usage),
               MESH_CONTROL_OK);
  check_int_eq(usage.resource_count, 1u);
  check_int_eq(usage.operation_count, 1u);
  check_int_eq(usage.retained_document_bytes, 4u);
  check_int_eq(usage.retained_document_capacity, 5u);
  mesh_control_state_destroy_v1(&state);
}

static void test_checkpoint_round_trip_preserves_owned_state(void) {
  mesh_control_state_v1_t source = {0};
  mesh_control_state_v1_t restored = {0};
  mesh_control_envelope_v1_t intent;
  mesh_control_operation_v1_t operation;
  mesh_control_operation_v1_t restored_operation;
  mesh_control_state_resource_record_v1_t resources[2];
  mesh_control_state_operation_record_v1_t operations[2];
  mesh_control_event_v1_t events[4];
  mesh_control_event_v1_t restored_events[4];
  mesh_control_state_checkpoint_info_v1_t info;
  mesh_control_resource_status_v1_t status;
  const uint8_t *restored_document = NULL;
  size_t restored_document_size = 0u;
  size_t restored_event_count = 0u;
  uint64_t restored_cursor = 0u;
  static const uint8_t document[] = {0x10u, 0x20u, 0x30u};

  memset(resources, 0, sizeof(resources));
  memset(operations, 0, sizeof(operations));
  memset(events, 0, sizeof(events));
  make_intent(&intent, 120u, 1u, 0u);
  check_int_eq(mesh_control_state_init_v1(&source, &TEST_CONFIG),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_state_submit_document_v1(
                   &source, &intent, MESH_CONTROL_DESIRED_APPLY, document,
                   sizeof(document), 1100u, &operation),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_state_transition_operation_v1(
                   &source, operation.operation_id,
                   MESH_CONTROL_OPERATION_RUNNING, 1110u),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_state_observe_v1(
                   &source, intent.resource_kind, intent.resource_id, 1u,
                   MESH_CONTROL_PRESENCE_PRESENT, intent.payload_digest,
                   1120u),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_state_export_v1(
                   &source, resources, 2u, operations, 2u, events, 4u,
                   &info),
               MESH_CONTROL_OK);
  check_size_eq(info.resource_count, 1u);
  check_size_eq(info.operation_count, 1u);
  check_size_eq(info.event_count, 3u);
  check_true(operations[0].terminal_expires_at_ms > 1120u);

  check_int_eq(mesh_control_state_init_v1(&restored, &TEST_CONFIG),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_state_import_v1(
                   &restored, &info, resources, operations, events),
               MESH_CONTROL_OK);
  mesh_control_state_destroy_v1(&source);
  check_int_eq(mesh_control_state_get_resource_v1(
                   &restored, intent.resource_kind, intent.resource_id,
                   &status),
               MESH_CONTROL_OK);
  check_int_eq(status.observed_epoch, 1u);
  check_int_eq(mesh_control_state_get_operation_v1(
                   &restored, operation.operation_id,
                   &restored_operation),
               MESH_CONTROL_OK);
  check_int_eq(restored_operation.state,
               MESH_CONTROL_OPERATION_SUCCEEDED);
  check_int_eq(mesh_control_state_get_desired_document_v1(
                   &restored, intent.resource_kind, intent.resource_id,
                   &restored_document, &restored_document_size),
               MESH_CONTROL_OK);
  check_size_eq(restored_document_size, sizeof(document));
  check_mem_eq(restored_document, document, sizeof(document));
  check_int_eq(mesh_control_state_events_after_v1(
                   &restored, 0u, restored_events, 4u,
                   &restored_event_count, &restored_cursor),
               MESH_CONTROL_OK);
  check_size_eq(restored_event_count, 3u);
  check_uint_eq(restored_cursor, info.next_event_cursor - 1u);
  mesh_control_state_destroy_v1(&restored);
}

static void test_checkpoint_import_is_atomic_on_corruption(void) {
  mesh_control_state_v1_t source = {0};
  mesh_control_state_v1_t restored = {0};
  mesh_control_envelope_v1_t intent;
  mesh_control_operation_v1_t operation;
  mesh_control_state_resource_record_v1_t resources[2];
  mesh_control_state_operation_record_v1_t operations[2];
  mesh_control_event_v1_t events[4];
  mesh_control_state_checkpoint_info_v1_t info;
  mesh_control_state_usage_v1_t usage;

  make_intent(&intent, 130u, 1u, 0u);
  check_int_eq(mesh_control_state_init_v1(&source, &TEST_CONFIG),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_state_submit_v1(
                   &source, &intent, MESH_CONTROL_DESIRED_APPLY, 1100u,
                   &operation),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_state_export_v1(
                   &source, resources, 2u, operations, 2u, events, 4u,
                   &info),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_state_init_v1(&restored, &TEST_CONFIG),
               MESH_CONTROL_OK);
  events[0].cursor++;
  check_int_eq(mesh_control_state_import_v1(
                   &restored, &info, resources, operations, events),
               MESH_CONTROL_INVALID_ARG);
  check_int_eq(mesh_control_state_get_usage_v1(&restored, &usage),
               MESH_CONTROL_OK);
  check_size_eq(usage.resource_count, 0u);
  check_size_eq(usage.operation_count, 0u);
  check_size_eq(usage.event_count, 0u);
  events[0].cursor--;
  info.snapshot_generation = UINT64_MAX;
  check_int_eq(mesh_control_state_import_v1(
                   &restored, &info, resources, operations, events),
               MESH_CONTROL_INVALID_ARG);
  info.snapshot_generation = 1u;
  info.next_event_cursor = UINT64_MAX;
  check_int_eq(mesh_control_state_import_v1(
                   &restored, &info, resources, operations, events),
               MESH_CONTROL_INVALID_ARG);
  mesh_control_state_destroy_v1(&restored);
  mesh_control_state_destroy_v1(&source);
}

spec("mesh control desired observed state") {
  describe("bounded single-owner reconciliation") {
    it("submits idempotently and completes from observed state") {
      test_desired_observed_reconciliation_is_idempotent();
    }
    it("enforces optimistic epoch and request bindings") {
      test_preconditions_and_request_bindings_conflict();
    }
    it("models deletion as an observed tombstone") {
      test_delete_is_an_observed_tombstone();
    }
    it("replays retained events or requires a full snapshot") {
      test_event_cursor_replays_or_requires_snapshot();
    }
    it("rejects pages from different state generations") {
      test_snapshot_pages_require_one_generation();
    }
    it("owns desired documents and rejects retained-byte overflow") {
      test_desired_documents_are_owned_and_byte_bounded();
    }
    it("round trips a complete owned checkpoint") {
      test_checkpoint_round_trip_preserves_owned_state();
    }
    it("keeps an empty state unchanged when checkpoint validation fails") {
      test_checkpoint_import_is_atomic_on_corruption();
    }
  }
}
