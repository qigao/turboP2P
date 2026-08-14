#include "mesh_control_channel.h"
#include "tinytest.h"

#include <string.h>

static void make_event(mesh_control_envelope_v1_t *envelope, size_t payload_size) {
  memset(envelope, 0, sizeof(*envelope));
  envelope->schema_version = MESH_CONTROL_SCHEMA_V1;
  envelope->kind = MESH_CONTROL_MESSAGE_EVENT;
  envelope->message_id[0] = 1u;
  envelope->mesh_id[0] = 2u;
  envelope->origin_principal[0] = 3u;
  envelope->target_node_id[0] = 4u;
  envelope->resource_kind = MESH_CONTROL_RESOURCE_NODE;
  envelope->resource_id[0] = 5u;
  envelope->epoch = 1u;
  envelope->sequence = 1u;
  envelope->issued_at_ms = 1000u;
  envelope->expires_at_ms = 2000u;
  envelope->payload_size = payload_size;
  if (payload_size != 0u) {
    envelope->payload_digest[0] = 6u;
  }
}

static void test_channel_copies_borrowed_payload(void) {
  mesh_control_channel_v1_t channel;
  mesh_control_channel_stats_v1_t stats;
  mesh_control_message_view_v1_t view;
  mesh_control_envelope_v1_t envelope;
  uint8_t payload[] = {1u, 2u, 3u, 4u};

  check_int_eq(mesh_control_channel_init_v1(&channel, 2u, 4096u, 1024u), MESH_CONTROL_OK);
  make_event(&envelope, sizeof(payload));
  check_int_eq(mesh_control_channel_try_push_v1(&channel, &envelope, payload, sizeof(payload)),
               MESH_CONTROL_OK);
  memset(payload, 0xff, sizeof(payload));

  check_int_eq(mesh_control_channel_peek_v1(&channel, &view), MESH_CONTROL_OK);
  check_int_eq(view.payload_size, 4u);
  check_int_eq(view.payload[0], 1u);
  check_int_eq(view.payload[3], 4u);
  check_int_eq(view.envelope.sequence, 1u);

  check_int_eq(mesh_control_channel_consume_v1(&channel), MESH_CONTROL_OK);
  check_int_eq(mesh_control_channel_peek_v1(&channel, &view), MESH_CONTROL_EMPTY);
  check_int_eq(mesh_control_channel_get_stats_v1(&channel, &stats), MESH_CONTROL_OK);
  check_int_eq(stats.pending, 0u);
  check_int_eq(stats.retained_bytes, 0u);
  check_int_eq(stats.published, 1u);
  check_int_eq(stats.consumed, 1u);
  mesh_control_channel_destroy_v1(&channel);
}

static void test_channel_copies_original_signed_frame(void) {
  mesh_control_channel_v1_t channel;
  mesh_control_message_view_v1_t view;
  mesh_control_envelope_v1_t envelope;
  uint8_t payload[] = {1u, 2u};
  uint8_t frame[] = {3u, 4u, 5u};

  check_int_eq(mesh_control_channel_init_v1(&channel, 2u, 4096u, 32u), MESH_CONTROL_OK);
  make_event(&envelope, sizeof(payload));
  check_int_eq(mesh_control_channel_try_push_signed_v1(&channel, &envelope, payload,
                                                       sizeof(payload), frame, sizeof(frame)),
               MESH_CONTROL_OK);
  memset(payload, 0xff, sizeof(payload));
  memset(frame, 0xff, sizeof(frame));
  check_int_eq(mesh_control_channel_peek_v1(&channel, &view), MESH_CONTROL_OK);
  check_size_eq(view.payload_size, 2u);
  check_size_eq(view.signed_frame_size, 3u);
  check_uint_eq(view.payload[0], 1u);
  check_uint_eq(view.signed_frame[0], 3u);
  check_uint_eq(view.signed_frame[2], 5u);
  mesh_control_channel_destroy_v1(&channel);
}

static void test_channel_enforces_entry_and_byte_bounds(void) {
  mesh_control_channel_v1_t channel;
  mesh_control_channel_stats_v1_t stats;
  mesh_control_envelope_v1_t envelope;
  uint8_t payload[32] = {0u};

  payload[0] = 1u;
  check_int_eq(mesh_control_channel_init_v1(&channel, 2u, 4096u, 32u), MESH_CONTROL_OK);
  make_event(&envelope, sizeof(payload));
  check_int_eq(mesh_control_channel_try_push_v1(&channel, &envelope, payload, sizeof(payload)),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_channel_try_push_v1(&channel, &envelope, payload, sizeof(payload)),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_channel_try_push_v1(&channel, &envelope, payload, sizeof(payload)),
               MESH_CONTROL_RESOURCE_EXHAUSTED);
  check_int_eq(mesh_control_channel_get_stats_v1(&channel, &stats), MESH_CONTROL_OK);
  check_int_eq(stats.pending, 2u);
  check_int_eq(stats.rejected_full, 1u);
  mesh_control_channel_destroy_v1(&channel);

  check_int_eq(mesh_control_channel_init_v1(&channel, 2u, sizeof(mesh_control_envelope_v1_t), 32u),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_channel_try_push_v1(&channel, &envelope, payload, sizeof(payload)),
               MESH_CONTROL_RESOURCE_EXHAUSTED);
  check_int_eq(mesh_control_channel_get_stats_v1(&channel, &stats), MESH_CONTROL_OK);
  check_int_eq(stats.rejected_bytes, 1u);
  mesh_control_channel_destroy_v1(&channel);
}

static void test_close_rejects_new_messages_and_preserves_pending(void) {
  mesh_control_channel_v1_t channel;
  mesh_control_message_view_v1_t view;
  mesh_control_envelope_v1_t envelope;
  uint8_t payload = 7u;

  check_int_eq(mesh_control_channel_init_v1(&channel, 2u, 4096u, 32u), MESH_CONTROL_OK);
  make_event(&envelope, 1u);
  check_int_eq(mesh_control_channel_try_push_v1(&channel, &envelope, &payload, 1u),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_channel_close_v1(&channel), MESH_CONTROL_OK);
  check_int_eq(mesh_control_channel_try_push_v1(&channel, &envelope, &payload, 1u),
               MESH_CONTROL_CLOSED);
  check_int_eq(mesh_control_channel_peek_v1(&channel, &view), MESH_CONTROL_OK);
  check_int_eq(view.payload[0], 7u);
  check_int_eq(mesh_control_channel_consume_v1(&channel), MESH_CONTROL_OK);
  mesh_control_channel_destroy_v1(&channel);
}

static void test_invalid_configuration_and_payload_fail_fast(void) {
  mesh_control_channel_v1_t channel;
  mesh_control_envelope_v1_t envelope;
  uint8_t payload[2] = {1u, 2u};

  check_int_eq(mesh_control_channel_init_v1(&channel, 0u, 4096u, 32u), MESH_CONTROL_INVALID_ARG);
  check_int_eq(mesh_control_channel_init_v1(&channel, 3u, 4096u, 32u), MESH_CONTROL_INVALID_ARG);
  check_int_eq(mesh_control_channel_init_v1(&channel, 2u, 4096u, 1u), MESH_CONTROL_OK);
  make_event(&envelope, sizeof(payload));
  check_int_eq(mesh_control_channel_try_push_v1(&channel, &envelope, payload, sizeof(payload)),
               MESH_CONTROL_INVALID_ARG);
  envelope.payload_size = 1u;
  check_int_eq(mesh_control_channel_try_push_v1(&channel, &envelope, payload, sizeof(payload)),
               MESH_CONTROL_INVALID_ARG);
  mesh_control_channel_destroy_v1(&channel);
}

spec("mesh H2 WebSocket cross-thread control channel") {
  describe("bounded SPSC ownership transfer") {
    it("copies callback-borrowed payloads") { test_channel_copies_borrowed_payload(); }
    it("copies the original signed transport frame") {
      test_channel_copies_original_signed_frame();
    }
    it("enforces entry and retained-byte limits") { test_channel_enforces_entry_and_byte_bounds(); }
    it("closes producers while preserving pending messages") {
      test_close_rejects_new_messages_and_preserves_pending();
    }
    it("fails fast on invalid configuration and payloads") {
      test_invalid_configuration_and_payload_fail_fast();
    }
  }
}
