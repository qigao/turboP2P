#include "mesh_control_outbox.h"

#include <tinytest.h>

#include <string.h>

static void fill_bytes(uint8_t *bytes, size_t size, uint8_t first) {
  size_t index;

  for (index = 0u; index < size; ++index)
    bytes[index] = (uint8_t)(first + index);
}

static void make_envelope(mesh_control_envelope_v1_t *envelope,
                          uint8_t first, size_t payload_size) {
  memset(envelope, 0, sizeof(*envelope));
  envelope->schema_version = MESH_CONTROL_SCHEMA_V1;
  envelope->kind = MESH_CONTROL_MESSAGE_EVENT;
  envelope->resource_kind = MESH_CONTROL_RESOURCE_NODE;
  fill_bytes(envelope->message_id, sizeof(envelope->message_id), first);
  fill_bytes(envelope->request_id, sizeof(envelope->request_id),
             (uint8_t)(first + 0x10u));
  fill_bytes(envelope->mesh_id, sizeof(envelope->mesh_id),
             (uint8_t)(first + 0x20u));
  fill_bytes(envelope->origin_principal, sizeof(envelope->origin_principal),
             (uint8_t)(first + 0x30u));
  fill_bytes(envelope->target_node_id, sizeof(envelope->target_node_id),
             (uint8_t)(first + 0x40u));
  fill_bytes(envelope->resource_id, sizeof(envelope->resource_id),
             (uint8_t)(first + 0x50u));
  envelope->epoch = 1u;
  envelope->sequence = first;
  envelope->issued_at_ms = 1000u;
  envelope->expires_at_ms = 2000u;
  envelope->payload_size = payload_size;
  if (payload_size != 0u)
    fill_bytes(envelope->payload_digest, sizeof(envelope->payload_digest),
               (uint8_t)(first + 0x60u));
}

static void test_outbox_copies_and_preserves_fifo(void) {
  mesh_control_outbox_v1_t outbox = {0};
  mesh_control_outbox_config_v1_t config = {2u, 8u, 4u};
  mesh_control_envelope_v1_t first;
  mesh_control_envelope_v1_t second;
  mesh_control_outbox_view_v1_t view;
  mesh_control_outbox_stats_v1_t stats;
  uint8_t first_payload[4] = {1u, 2u, 3u, 4u};
  uint8_t second_payload[4] = {5u, 6u, 7u, 8u};
  const uint8_t expected_first[4] = {1u, 2u, 3u, 4u};

  make_envelope(&first, 1u, sizeof(first_payload));
  make_envelope(&second, 2u, sizeof(second_payload));
  check_int_eq(mesh_control_outbox_init_v1(&outbox, &config),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_outbox_try_push_v1(
                   &outbox, &first, first_payload, sizeof(first_payload)),
               MESH_CONTROL_OK);
  memset(first_payload, 0, sizeof(first_payload));
  check_int_eq(mesh_control_outbox_peek_v1(&outbox, &view),
               MESH_CONTROL_OK);
  check_mem_eq(view.payload, expected_first, sizeof(expected_first));
  check_int_eq(mesh_control_outbox_try_push_v1(
                   &outbox, &second, second_payload,
                   sizeof(second_payload)),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_outbox_try_push_v1(
                   &outbox, &second, second_payload,
                   sizeof(second_payload)),
               MESH_CONTROL_RESOURCE_EXHAUSTED);
  check_int_eq(mesh_control_outbox_consume_v1(&outbox), MESH_CONTROL_OK);
  check_int_eq(mesh_control_outbox_peek_v1(&outbox, &view),
               MESH_CONTROL_OK);
  check_mem_eq(view.payload, second_payload, sizeof(second_payload));
  check_int_eq(mesh_control_outbox_get_stats_v1(&outbox, &stats),
               MESH_CONTROL_OK);
  check_size_eq(stats.pending, 1u);
  check_size_eq(stats.retained_bytes, sizeof(second_payload));
  check_hex64_eq(stats.published, 2u);
  check_hex64_eq(stats.consumed, 1u);
  check_hex64_eq(stats.rejected_full, 1u);
  mesh_control_outbox_destroy_v1(&outbox);
}

static void test_outbox_enforces_byte_budget_and_close_drain(void) {
  mesh_control_outbox_v1_t outbox = {0};
  mesh_control_outbox_config_v1_t config = {4u, 6u, 4u};
  mesh_control_envelope_v1_t envelope;
  mesh_control_outbox_view_v1_t view;
  mesh_control_outbox_stats_v1_t stats;
  uint8_t payload[4] = {1u, 2u, 3u, 4u};

  make_envelope(&envelope, 3u, sizeof(payload));
  check_int_eq(mesh_control_outbox_init_v1(&outbox, &config),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_outbox_try_push_v1(
                   &outbox, &envelope, payload, sizeof(payload)),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_outbox_try_push_v1(
                   &outbox, &envelope, payload, sizeof(payload)),
               MESH_CONTROL_RESOURCE_EXHAUSTED);
  check_int_eq(mesh_control_outbox_close_v1(&outbox), MESH_CONTROL_OK);
  check_int_eq(mesh_control_outbox_try_push_v1(
                   &outbox, &envelope, payload, sizeof(payload)),
               MESH_CONTROL_CLOSED);
  check_int_eq(mesh_control_outbox_peek_v1(&outbox, &view),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_outbox_consume_v1(&outbox), MESH_CONTROL_OK);
  check_int_eq(mesh_control_outbox_peek_v1(&outbox, &view),
               MESH_CONTROL_EMPTY);
  check_int_eq(mesh_control_outbox_get_stats_v1(&outbox, &stats),
               MESH_CONTROL_OK);
  check_false(stats.accepting);
  check_hex64_eq(stats.rejected_full, 1u);
  check_hex64_eq(stats.rejected_closed, 1u);
  mesh_control_outbox_destroy_v1(&outbox);
}

static void test_outbox_rejects_unbounded_configuration(void) {
  mesh_control_outbox_v1_t outbox = {0};
  mesh_control_outbox_config_v1_t config = {0u, 1u, 1u};

  check_int_eq(mesh_control_outbox_init_v1(&outbox, &config),
               MESH_CONTROL_INVALID_ARG);
  config.entry_capacity = MESH_CONTROL_OUTBOX_MAX_ENTRIES_V1 + 1u;
  check_int_eq(mesh_control_outbox_init_v1(&outbox, &config),
               MESH_CONTROL_INVALID_ARG);
  config.entry_capacity = 1u;
  config.retained_byte_capacity = 4u;
  config.max_payload_size = 5u;
  check_int_eq(mesh_control_outbox_init_v1(&outbox, &config),
               MESH_CONTROL_INVALID_ARG);
}

spec("mesh H2 WebSocket control outbox") {
  describe("single-owner bounded delivery") {
    it("copies borrowed payloads and preserves FIFO order") {
      test_outbox_copies_and_preserves_fifo();
    }
    it("enforces retained bytes and drains after close") {
      test_outbox_enforces_byte_budget_and_close_drain();
    }
    it("rejects capacities outside the documented hard limits") {
      test_outbox_rejects_unbounded_configuration();
    }
  }
}
