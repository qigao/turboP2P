#include <tinytest.h>

#include "mesh_stream_session.h"

#include <string.h>

#define TEST_FRAME_MAX 1024u
#define TEST_STREAM_EPOCH 17u

static const uint8_t TEST_PAYLOAD[] = {1u, 2u, 3u, 4u, 5u, 6u};
static const uint8_t REASON_NORMAL[] = {0x00u, 0x01u, 0x00u, 0x02u, 0x00u, 0x00u};

static void write_u16(uint8_t *bytes, uint16_t value) {
  bytes[0] = (uint8_t)(value >> 8u);
  bytes[1] = (uint8_t)value;
}

static void write_u64(uint8_t *bytes, uint64_t value) {
  size_t index = 0u;

  for (index = 0u; index < sizeof(value); index++)
    bytes[index] = (uint8_t)(value >> (56u - index * 8u));
}

static void fill_stream_id(uint8_t stream_id[MESH_STREAM_ID_SIZE]) {
  size_t index = 0u;

  for (index = 0u; index < MESH_STREAM_ID_SIZE; index++)
    stream_id[index] = (uint8_t)(0x60u + index);
}

static mesh_stream_receiver_config_v1_t receiver_config(void) {
  mesh_stream_receiver_config_v1_t config;

  memset(&config, 0, sizeof(config));
  fill_stream_id(config.stream_id);
  config.stream_epoch = TEST_STREAM_EPOCH;
  config.max_frame_size = TEST_FRAME_MAX;
  config.initial_receive_window = 8u;
  config.max_receive_window = 16u;
  config.max_total_size = 100u;
  config.allowed_class_mask = MESH_STREAM_CLASS_BLOB_MASK | MESH_STREAM_CLASS_MEDIA_MASK;
  return config;
}

static size_t make_open_metadata(uint8_t *metadata, uint8_t stream_class, uint64_t total_size,
                                 const char *content_type) {
  size_t cursor = 0u;
  size_t content_type_len = content_type ? strlen(content_type) : 0u;

  write_u16(metadata + cursor, 1u);
  write_u16(metadata + cursor + 2u, 1u);
  metadata[cursor + 4u] = stream_class;
  cursor += 5u;
  write_u16(metadata + cursor, 2u);
  write_u16(metadata + cursor + 2u, 8u);
  write_u64(metadata + cursor + 4u, total_size);
  cursor += 12u;
  if (content_type) {
    write_u16(metadata + cursor, 3u);
    write_u16(metadata + cursor + 2u, (uint16_t)content_type_len);
    memcpy(metadata + cursor + 4u, content_type, content_type_len);
    cursor += 4u + content_type_len;
  }
  return cursor;
}

static size_t encode_frame(const mesh_stream_receiver_config_v1_t *config, uint8_t type,
                           uint8_t flags, uint64_t sequence, uint64_t offset,
                           const uint8_t *metadata, size_t metadata_len, const uint8_t *payload,
                           size_t payload_len, uint8_t *output, size_t output_capacity) {
  mesh_stream_frame_input_t input;
  size_t output_len = 0u;

  memset(&input, 0, sizeof(input));
  input.type = type;
  input.flags = flags;
  memcpy(input.stream_id, config->stream_id, sizeof(input.stream_id));
  input.stream_epoch = config->stream_epoch;
  input.sequence = sequence;
  input.offset = offset;
  input.metadata = metadata;
  input.metadata_len = metadata_len;
  input.payload = payload;
  input.payload_len = payload_len;
  check_int_eq(mesh_stream_frame_encode(&input, config->max_frame_size, output, output_capacity,
                                        &output_len),
               MESH_STREAM_CODEC_OK);
  return output_len;
}

static mesh_stream_session_result_t
prepare_frame(const mesh_stream_receiver_session_v1_t *session, const uint8_t *frame,
              size_t frame_len, mesh_stream_receive_event_v1_t *event,
              mesh_stream_receive_preparation_v1_t *preparation) {
  size_t consumed = 0u;
  size_t required = 0u;
  mesh_stream_session_result_t result = mesh_stream_receiver_prepare_v1(
      session, frame, frame_len, event, preparation, &consumed, &required);

  if (result == MESH_STREAM_SESSION_OK) {
    check_size_eq(consumed, frame_len);
    check_size_eq(required, frame_len);
  } else {
    check_size_eq(consumed, 0u);
  }
  return result;
}

static void open_and_accept(mesh_stream_receiver_session_v1_t *session,
                            mesh_stream_receiver_config_v1_t *config, uint64_t total_size) {
  mesh_stream_receive_event_v1_t event;
  mesh_stream_receive_preparation_v1_t receive_preparation;
  mesh_stream_control_preparation_v1_t control_preparation;
  uint8_t metadata[64];
  uint8_t frame[128];
  size_t metadata_len =
      make_open_metadata(metadata, MESH_STREAM_CLASS_MEDIA, total_size, "video/h264");
  size_t frame_len = encode_frame(config, MESH_STREAM_FRAME_OPEN, 0u, 0u, 0u, metadata,
                                  metadata_len, NULL, 0u, frame, sizeof(frame));

  check_int_eq(mesh_stream_receiver_init_v1(session, config), MESH_STREAM_SESSION_OK);
  check_int_eq(prepare_frame(session, frame, frame_len, &event, &receive_preparation),
               MESH_STREAM_SESSION_OK);
  check_int_eq(session->state, MESH_STREAM_SESSION_AWAIT_OPEN);
  check_int_eq(event.open.stream_class, MESH_STREAM_CLASS_MEDIA);
  check_int_eq(event.open.total_size_known, 1);
  check_hex64_eq(event.open.total_size, total_size);
  check_str_eq(event.open.content_type, "video/h264");
  check_int_eq(mesh_stream_receiver_commit_v1(session, &receive_preparation),
               MESH_STREAM_SESSION_OK);
  check_int_eq(session->state, MESH_STREAM_SESSION_AWAIT_ACCEPT_SEND);

  check_int_eq(mesh_stream_receiver_prepare_accept_v1(session, &control_preparation),
               MESH_STREAM_SESSION_OK);
  check_int_eq(control_preparation.frame.type, MESH_STREAM_FRAME_ACCEPT);
  check_hex64_eq(control_preparation.frame.sequence, 0u);
  check_hex64_eq(control_preparation.frame.offset, session->receive_limit);
  check_int_eq(session->state, MESH_STREAM_SESSION_AWAIT_ACCEPT_SEND);
  check_int_eq(mesh_stream_receiver_commit_control_v1(session, &control_preparation),
               MESH_STREAM_SESSION_OK);
  check_int_eq(session->state, MESH_STREAM_SESSION_ACTIVE);
}

static void test_runs_authorized_stream_with_absolute_credit(void) {
  mesh_stream_receiver_config_v1_t config = receiver_config();
  mesh_stream_receiver_session_v1_t session;
  mesh_stream_receive_event_v1_t event;
  mesh_stream_receive_preparation_v1_t receive_preparation;
  mesh_stream_control_preparation_v1_t control_preparation;
  uint8_t frame[128];
  size_t frame_len = 0u;

  open_and_accept(&session, &config, 12u);
  frame_len = encode_frame(&config, MESH_STREAM_FRAME_DATA, 0u, 1u, 0u, NULL, 0u, TEST_PAYLOAD,
                           sizeof(TEST_PAYLOAD), frame, sizeof(frame));
  check_int_eq(prepare_frame(&session, frame, frame_len, &event, &receive_preparation),
               MESH_STREAM_SESSION_OK);
  check_ptr_eq(event.frame.payload, frame + MESH_STREAM_FIXED_HEADER_SIZE);
  check_size_eq(event.frame.payload_len, sizeof(TEST_PAYLOAD));
  check_hex64_eq(session.committed_offset, 0u);
  check_int_eq(mesh_stream_receiver_commit_v1(&session, &receive_preparation),
               MESH_STREAM_SESSION_OK);
  check_hex64_eq(session.committed_offset, 6u);

  frame_len = encode_frame(&config, MESH_STREAM_FRAME_DATA, MESH_STREAM_FLAG_END_STREAM, 2u, 6u,
                           NULL, 0u, TEST_PAYLOAD, sizeof(TEST_PAYLOAD), frame, sizeof(frame));
  check_int_eq(prepare_frame(&session, frame, frame_len, &event, &receive_preparation),
               MESH_STREAM_SESSION_FLOW_CONTROL);
  check_hex64_eq(session.committed_offset, 6u);

  check_int_eq(mesh_stream_receiver_prepare_window_v1(&session, 4u, &control_preparation),
               MESH_STREAM_SESSION_OK);
  check_int_eq(control_preparation.frame.type, MESH_STREAM_FRAME_WINDOW_UPDATE);
  check_hex64_eq(control_preparation.frame.sequence, 1u);
  check_hex64_eq(control_preparation.frame.offset, 12u);
  check_hex64_eq(session.receive_limit, 8u);
  check_int_eq(mesh_stream_receiver_commit_control_v1(&session, &control_preparation),
               MESH_STREAM_SESSION_OK);
  check_hex64_eq(session.receive_limit, 12u);
  check_int_eq(prepare_frame(&session, frame, frame_len, &event, &receive_preparation),
               MESH_STREAM_SESSION_OK);
  check_int_eq(mesh_stream_receiver_commit_v1(&session, &receive_preparation),
               MESH_STREAM_SESSION_OK);
  check_int_eq(session.state, MESH_STREAM_SESSION_END_RECEIVED);
  check_hex64_eq(session.committed_offset, 12u);

  frame_len = encode_frame(&config, MESH_STREAM_FRAME_CLOSE, 0u, 3u, 12u, REASON_NORMAL,
                           sizeof(REASON_NORMAL), NULL, 0u, frame, sizeof(frame));
  check_int_eq(prepare_frame(&session, frame, frame_len, &event, &receive_preparation),
               MESH_STREAM_SESSION_OK);
  check_int_eq(event.reason_code, 0);
  check_int_eq(mesh_stream_receiver_commit_v1(&session, &receive_preparation),
               MESH_STREAM_SESSION_OK);
  check_int_eq(session.state, MESH_STREAM_SESSION_CLOSED);
}

static void test_rejects_binding_order_and_stale_commit(void) {
  mesh_stream_receiver_config_v1_t config = receiver_config();
  mesh_stream_receiver_session_v1_t session;
  mesh_stream_receive_event_v1_t event;
  mesh_stream_receive_preparation_v1_t first;
  mesh_stream_receive_preparation_v1_t second;
  uint8_t frame[128];
  size_t frame_len = 0u;

  open_and_accept(&session, &config, 12u);
  frame_len = encode_frame(&config, MESH_STREAM_FRAME_DATA, 0u, 2u, 0u, NULL, 0u, TEST_PAYLOAD,
                           sizeof(TEST_PAYLOAD), frame, sizeof(frame));
  check_int_eq(prepare_frame(&session, frame, frame_len, &event, &first),
               MESH_STREAM_SESSION_OUT_OF_ORDER);

  frame_len = encode_frame(&config, MESH_STREAM_FRAME_DATA, 0u, 1u, 0u, NULL, 0u, TEST_PAYLOAD,
                           sizeof(TEST_PAYLOAD), frame, sizeof(frame));
  frame[8] ^= 0x01u;
  check_int_eq(prepare_frame(&session, frame, frame_len, &event, &first),
               MESH_STREAM_SESSION_BINDING_MISMATCH);
  frame[8] ^= 0x01u;
  check_int_eq(prepare_frame(&session, frame, frame_len, &event, &first), MESH_STREAM_SESSION_OK);
  check_int_eq(prepare_frame(&session, frame, frame_len, &event, &second), MESH_STREAM_SESSION_OK);
  check_int_eq(mesh_stream_receiver_commit_v1(&session, &first), MESH_STREAM_SESSION_OK);
  check_int_eq(mesh_stream_receiver_commit_v1(&session, &second),
               MESH_STREAM_SESSION_STALE_PREPARATION);
}

static void test_rejects_unauthorized_and_unbounded_open(void) {
  mesh_stream_receiver_config_v1_t config = receiver_config();
  mesh_stream_receiver_session_v1_t session;
  mesh_stream_receive_event_v1_t event;
  mesh_stream_receive_preparation_v1_t preparation;
  uint8_t metadata[64];
  uint8_t frame[128];
  size_t metadata_len = 0u;
  size_t frame_len = 0u;

  check_int_eq(mesh_stream_receiver_init_v1(&session, &config), MESH_STREAM_SESSION_OK);
  metadata_len = make_open_metadata(metadata, MESH_STREAM_CLASS_DIAGNOSTIC, 12u, NULL);
  frame_len = encode_frame(&config, MESH_STREAM_FRAME_OPEN, 0u, 0u, 0u, metadata, metadata_len,
                           NULL, 0u, frame, sizeof(frame));
  check_int_eq(prepare_frame(&session, frame, frame_len, &event, &preparation),
               MESH_STREAM_SESSION_UNAUTHORIZED);

  metadata_len = make_open_metadata(metadata, MESH_STREAM_CLASS_MEDIA, UINT64_MAX, NULL);
  frame_len = encode_frame(&config, MESH_STREAM_FRAME_OPEN, 0u, 0u, 0u, metadata, metadata_len,
                           NULL, 0u, frame, sizeof(frame));
  check_int_eq(prepare_frame(&session, frame, frame_len, &event, &preparation),
               MESH_STREAM_SESSION_UNAUTHORIZED);

  metadata_len =
      make_open_metadata(metadata, MESH_STREAM_CLASS_MEDIA, config.max_total_size + 1u, NULL);
  frame_len = encode_frame(&config, MESH_STREAM_FRAME_OPEN, 0u, 0u, 0u, metadata, metadata_len,
                           NULL, 0u, frame, sizeof(frame));
  check_int_eq(prepare_frame(&session, frame, frame_len, &event, &preparation),
               MESH_STREAM_SESSION_RESOURCE_EXHAUSTED);
  check_int_eq(session.state, MESH_STREAM_SESSION_AWAIT_OPEN);
}

static void test_cancel_is_terminal_and_reason_is_strict(void) {
  mesh_stream_receiver_config_v1_t config = receiver_config();
  mesh_stream_receiver_session_v1_t session;
  mesh_stream_receive_event_v1_t event;
  mesh_stream_receive_preparation_v1_t preparation;
  uint8_t frame[128];
  size_t frame_len = 0u;

  open_and_accept(&session, &config, 12u);
  frame_len = encode_frame(&config, MESH_STREAM_FRAME_CANCEL, 0u, 1u, 0u, NULL, 0u, NULL, 0u, frame,
                           sizeof(frame));
  check_int_eq(prepare_frame(&session, frame, frame_len, &event, &preparation),
               MESH_STREAM_SESSION_INVALID_SCHEMA);

  frame_len = encode_frame(&config, MESH_STREAM_FRAME_CANCEL, 0u, 1u, 0u, REASON_NORMAL,
                           sizeof(REASON_NORMAL), NULL, 0u, frame, sizeof(frame));
  check_int_eq(prepare_frame(&session, frame, frame_len, &event, &preparation),
               MESH_STREAM_SESSION_OK);
  check_int_eq(mesh_stream_receiver_commit_v1(&session, &preparation), MESH_STREAM_SESSION_OK);
  check_int_eq(session.state, MESH_STREAM_SESSION_CANCELLED);
  check_int_eq(prepare_frame(&session, frame, frame_len, &event, &preparation),
               MESH_STREAM_SESSION_INVALID_STATE);
}

static void test_reports_fragment_requirement_without_state_change(void) {
  mesh_stream_receiver_config_v1_t config = receiver_config();
  mesh_stream_receiver_session_v1_t session;
  mesh_stream_receive_event_v1_t event;
  mesh_stream_receive_preparation_v1_t preparation;
  uint8_t metadata[64];
  uint8_t frame[128];
  size_t metadata_len = make_open_metadata(metadata, MESH_STREAM_CLASS_MEDIA, 12u, NULL);
  size_t frame_len = encode_frame(&config, MESH_STREAM_FRAME_OPEN, 0u, 0u, 0u, metadata,
                                  metadata_len, NULL, 0u, frame, sizeof(frame));
  size_t consumed = 99u;
  size_t required = 99u;

  check_int_eq(mesh_stream_receiver_init_v1(&session, &config), MESH_STREAM_SESSION_OK);
  check_int_eq(mesh_stream_receiver_prepare_v1(&session, frame, frame_len - 1u, &event,
                                               &preparation, &consumed, &required),
               MESH_STREAM_SESSION_NEED_MORE);
  check_size_eq(consumed, 0u);
  check_size_eq(required, frame_len);
  check_int_eq(session.state, MESH_STREAM_SESSION_AWAIT_OPEN);
  check_hex64_eq(session.generation, 0u);
}

static void test_control_credit_is_bounded_and_transactional(void) {
  mesh_stream_receiver_config_v1_t config = receiver_config();
  mesh_stream_receiver_session_v1_t session;
  mesh_stream_control_preparation_v1_t first;
  mesh_stream_control_preparation_v1_t second;

  open_and_accept(&session, &config, 100u);
  check_int_eq(mesh_stream_receiver_prepare_window_v1(&session, 9u, &first),
               MESH_STREAM_SESSION_FLOW_CONTROL);
  check_hex64_eq(session.receive_limit, 8u);
  check_int_eq(mesh_stream_receiver_prepare_window_v1(&session, 8u, &first),
               MESH_STREAM_SESSION_OK);
  check_int_eq(mesh_stream_receiver_prepare_window_v1(&session, 8u, &second),
               MESH_STREAM_SESSION_OK);
  check_hex64_eq(session.receive_limit, 8u);
  check_int_eq(mesh_stream_receiver_commit_control_v1(&session, &first), MESH_STREAM_SESSION_OK);
  check_hex64_eq(session.receive_limit, 16u);
  check_int_eq(mesh_stream_receiver_commit_control_v1(&session, &second),
               MESH_STREAM_SESSION_STALE_PREPARATION);
}

static void test_unknown_size_requires_explicit_local_policy(void) {
  mesh_stream_receiver_config_v1_t config = receiver_config();
  mesh_stream_receiver_session_v1_t session;
  mesh_stream_receive_event_v1_t event;
  mesh_stream_receive_preparation_v1_t preparation;
  mesh_stream_control_preparation_v1_t control_preparation;
  uint8_t metadata[32];
  uint8_t frame[128];
  size_t metadata_len = 0u;
  size_t frame_len = 0u;

  config.allow_unknown_total_size = 1u;
  config.max_total_size = 12u;
  check_int_eq(mesh_stream_receiver_init_v1(&session, &config), MESH_STREAM_SESSION_OK);
  metadata_len = make_open_metadata(metadata, MESH_STREAM_CLASS_BLOB, UINT64_MAX, NULL);
  frame_len = encode_frame(&config, MESH_STREAM_FRAME_OPEN, 0u, 0u, 0u, metadata, metadata_len,
                           NULL, 0u, frame, sizeof(frame));
  check_int_eq(prepare_frame(&session, frame, frame_len, &event, &preparation),
               MESH_STREAM_SESSION_OK);
  check_int_eq(event.open.total_size_known, 0);
  check_int_eq(mesh_stream_receiver_commit_v1(&session, &preparation), MESH_STREAM_SESSION_OK);
  check_hex64_eq(session.receive_limit, config.initial_receive_window);
  check_int_eq(mesh_stream_receiver_prepare_accept_v1(&session, &control_preparation),
               MESH_STREAM_SESSION_OK);
  check_int_eq(mesh_stream_receiver_commit_control_v1(&session, &control_preparation),
               MESH_STREAM_SESSION_OK);
  check_int_eq(mesh_stream_receiver_prepare_window_v1(
                   &session, config.max_total_size - config.initial_receive_window + 1u,
                   &control_preparation),
               MESH_STREAM_SESSION_RESOURCE_EXHAUSTED);
}

spec("mesh stream receiver session") {
  describe("authorized unidirectional stream state") {
    it("runs OPEN, ACCEPT, DATA, WINDOW_UPDATE and CLOSE") {
      test_runs_authorized_stream_with_absolute_credit();
    }
    it("rejects binding, order and stale two-phase commits") {
      test_rejects_binding_order_and_stale_commit();
    }
    it("rejects unauthorized, unknown and oversized OPEN schemas") {
      test_rejects_unauthorized_and_unbounded_open();
    }
    it("makes CANCEL terminal and requires a typed reason") {
      test_cancel_is_terminal_and_reason_is_strict();
    }
    it("reports fragmented input without advancing state") {
      test_reports_fragment_requirement_without_state_change();
    }
    it("bounds absolute credit and rejects stale control commits") {
      test_control_credit_is_bounded_and_transactional();
    }
    it("allows unknown totals only under explicit local policy") {
      test_unknown_size_requires_explicit_local_policy();
    }
  }
}
