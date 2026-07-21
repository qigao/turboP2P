#include <tinytest.h>

#include "mesh_stream_coronet_adapter.h"
#include "mesh_stream_transport.h"

#include <stdlib.h>
#include <string.h>

#define TEST_FRAME_MAX 128u
#define TEST_SEND_HWM 256u
#define TEST_RECV_TIMEOUT_MS 30000u
#define TEST_EPOCH 23u
#define TEST_CHUNK_MAX 8u
#define TEST_SEND_MAX 8u

static const uint8_t TEST_PAYLOAD[] = {1u, 2u, 3u, 4u, 5u, 6u};
static const uint8_t REASON_NORMAL[] = {0x00u, 0x01u, 0x00u, 0x02u, 0x00u, 0x00u};

typedef struct {
  const uint8_t *chunks[TEST_CHUNK_MAX];
  size_t chunk_lengths[TEST_CHUNK_MAX];
  size_t chunk_count;
  size_t next_chunk;
  size_t release_count;
  uint8_t sent[TEST_SEND_MAX][MESH_STREAM_FIXED_HEADER_SIZE];
  size_t sent_lengths[TEST_SEND_MAX];
  size_t sent_count;
  size_t configured_hwm;
  uint64_t configured_timeout_ms;
  int recv_result;
  int send_result;
  int hwm_result;
  int timeout_result;
} fake_io_t;

typedef struct {
  size_t event_count;
  size_t data_bytes;
  uint8_t event_types[8];
  uint8_t reject_type;
} fake_application_t;

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
    stream_id[index] = (uint8_t)(0x40u + index);
}

static mesh_stream_transport_config_v1_t transport_config(void) {
  mesh_stream_transport_config_v1_t config;

  memset(&config, 0, sizeof(config));
  fill_stream_id(config.receiver.stream_id);
  config.receiver.stream_epoch = TEST_EPOCH;
  config.receiver.max_frame_size = TEST_FRAME_MAX;
  config.receiver.initial_receive_window = 8u;
  config.receiver.max_receive_window = 16u;
  config.receiver.max_total_size = 100u;
  config.receiver.allowed_class_mask = MESH_STREAM_CLASS_MEDIA_MASK;
  config.window_update_threshold = 4u;
  config.receive_timeout_ms = TEST_RECV_TIMEOUT_MS;
  config.send_high_watermark = TEST_SEND_HWM;
  return config;
}

static size_t make_open_metadata(uint8_t *metadata, uint64_t total_size) {
  size_t cursor = 0u;

  write_u16(metadata + cursor, 1u);
  write_u16(metadata + cursor + 2u, 1u);
  metadata[cursor + 4u] = MESH_STREAM_CLASS_MEDIA;
  cursor += 5u;
  write_u16(metadata + cursor, 2u);
  write_u16(metadata + cursor + 2u, 8u);
  write_u64(metadata + cursor + 4u, total_size);
  return cursor + 12u;
}

static size_t encode_frame(const mesh_stream_transport_config_v1_t *config, uint8_t type,
                           uint8_t flags, uint64_t sequence, uint64_t offset,
                           const uint8_t *metadata, size_t metadata_len, const uint8_t *payload,
                           size_t payload_len, uint8_t *output, size_t capacity) {
  mesh_stream_frame_input_t input;
  size_t output_len = 0u;

  memset(&input, 0, sizeof(input));
  input.type = type;
  input.flags = flags;
  memcpy(input.stream_id, config->receiver.stream_id, sizeof(input.stream_id));
  input.stream_epoch = config->receiver.stream_epoch;
  input.sequence = sequence;
  input.offset = offset;
  input.metadata = metadata;
  input.metadata_len = metadata_len;
  input.payload = payload;
  input.payload_len = payload_len;
  check_int_eq(mesh_stream_frame_encode(&input, config->receiver.max_frame_size, output, capacity,
                                        &output_len),
               MESH_STREAM_CODEC_OK);
  return output_len;
}

static size_t build_complete_stream(const mesh_stream_transport_config_v1_t *config, uint8_t *wire,
                                    size_t capacity) {
  uint8_t metadata[32];
  size_t metadata_len = make_open_metadata(metadata, 12u);
  size_t cursor = 0u;

  cursor += encode_frame(config, MESH_STREAM_FRAME_OPEN, 0u, 0u, 0u, metadata, metadata_len, NULL,
                         0u, wire + cursor, capacity - cursor);
  cursor += encode_frame(config, MESH_STREAM_FRAME_DATA, 0u, 1u, 0u, NULL, 0u, TEST_PAYLOAD,
                         sizeof(TEST_PAYLOAD), wire + cursor, capacity - cursor);
  cursor += encode_frame(config, MESH_STREAM_FRAME_DATA, MESH_STREAM_FLAG_END_STREAM, 2u, 6u, NULL,
                         0u, TEST_PAYLOAD, sizeof(TEST_PAYLOAD), wire + cursor, capacity - cursor);
  cursor += encode_frame(config, MESH_STREAM_FRAME_CLOSE, 0u, 3u, 12u, REASON_NORMAL,
                         sizeof(REASON_NORMAL), NULL, 0u, wire + cursor, capacity - cursor);
  return cursor;
}

static int fake_recv(void *context, uint8_t **out_bytes, size_t *out_len) {
  fake_io_t *io = (fake_io_t *)context;
  uint8_t *copy = NULL;
  size_t length = 0u;

  *out_bytes = NULL;
  *out_len = 0u;
  if (io->recv_result != 0)
    return io->recv_result;
  if (io->next_chunk >= io->chunk_count)
    return 0;
  length = io->chunk_lengths[io->next_chunk];
  if (length == 0u) {
    io->next_chunk++;
    return 0;
  }
  copy = (uint8_t *)malloc(length);
  if (!copy)
    return -99;
  memcpy(copy, io->chunks[io->next_chunk], length);
  io->next_chunk++;
  *out_bytes = copy;
  *out_len = length;
  return 0;
}

static void fake_release_recv(void *context, uint8_t *bytes) {
  fake_io_t *io = (fake_io_t *)context;

  io->release_count++;
  free(bytes);
}

static int fake_send(void *context, const uint8_t *bytes, size_t len) {
  fake_io_t *io = (fake_io_t *)context;

  if (io->send_result != 0)
    return io->send_result;
  if (io->sent_count >= TEST_SEND_MAX || len > sizeof(io->sent[io->sent_count]))
    return -98;
  memcpy(io->sent[io->sent_count], bytes, len);
  io->sent_lengths[io->sent_count] = len;
  io->sent_count++;
  return 0;
}

static int fake_set_send_hwm(void *context, size_t bytes) {
  fake_io_t *io = (fake_io_t *)context;

  io->configured_hwm = bytes;
  return io->hwm_result;
}

static int fake_set_receive_timeout(void *context, uint64_t timeout_ms) {
  fake_io_t *io = (fake_io_t *)context;

  io->configured_timeout_ms = timeout_ms;
  return io->timeout_result;
}

static mesh_stream_transport_io_v1_t fake_ops(fake_io_t *fake) {
  mesh_stream_transport_io_v1_t io;

  io.recv = fake_recv;
  io.release_recv = fake_release_recv;
  io.send = fake_send;
  io.set_send_hwm = fake_set_send_hwm;
  io.set_receive_timeout = fake_set_receive_timeout;
  io.context = fake;
  return io;
}

static int accept_event(void *context, const mesh_stream_receive_event_v1_t *event) {
  fake_application_t *application = (fake_application_t *)context;

  if (application->reject_type == event->frame.type)
    return -77;
  application->event_types[application->event_count] = event->frame.type;
  application->event_count++;
  if (event->frame.type == MESH_STREAM_FRAME_DATA) {
    check_mem_eq(event->frame.payload, TEST_PAYLOAD, event->frame.payload_len);
    application->data_bytes += event->frame.payload_len;
  }
  return 0;
}

static mesh_stream_transport_result_t init_transport(mesh_stream_transport_v1_t *transport,
                                                     mesh_stream_transport_config_v1_t *config,
                                                     fake_io_t *fake,
                                                     fake_application_t *application) {
  mesh_stream_transport_io_v1_t io = fake_ops(fake);

  return mesh_stream_transport_init_v1(transport, config, &io, accept_event, application);
}

static mesh_stream_frame_view_t decode_sent(const fake_io_t *fake, size_t index) {
  mesh_stream_frame_view_t view;
  size_t consumed = 0u;
  size_t required = 0u;

  check_int_eq(mesh_stream_frame_decode(fake->sent[index], fake->sent_lengths[index],
                                        TEST_FRAME_MAX, &view, &consumed, &required),
               MESH_STREAM_CODEC_OK);
  check_size_eq(consumed, fake->sent_lengths[index]);
  return view;
}

static void test_pumps_fragmented_stream_and_releases_every_chunk(void) {
  mesh_stream_transport_config_v1_t config = transport_config();
  mesh_stream_transport_v1_t transport;
  fake_io_t fake;
  fake_application_t application;
  mesh_stream_frame_view_t control;
  uint8_t wire[320];
  size_t wire_len = build_complete_stream(&config, wire, sizeof(wire));
  size_t frames = 0u;

  memset(&fake, 0, sizeof(fake));
  memset(&application, 0, sizeof(application));
  fake.chunks[0] = wire;
  fake.chunk_lengths[0] = 3u;
  fake.chunks[1] = wire + 3u;
  fake.chunk_lengths[1] = 97u;
  fake.chunks[2] = wire + 100u;
  fake.chunk_lengths[2] = wire_len - 100u;
  fake.chunk_count = 3u;

  check_int_eq(init_transport(&transport, &config, &fake, &application), MESH_STREAM_TRANSPORT_OK);
  check_size_eq(fake.configured_hwm, TEST_SEND_HWM);
  check_hex64_eq(fake.configured_timeout_ms, TEST_RECV_TIMEOUT_MS);
  check_size_eq(transport.config.receiver.max_frame_size, TEST_FRAME_MAX);

  check_int_eq(mesh_stream_transport_pump_once_v1(&transport, &frames), MESH_STREAM_TRANSPORT_OK);
  check_size_eq(frames, 0u);
  check_int_eq(mesh_stream_transport_pump_once_v1(&transport, &frames), MESH_STREAM_TRANSPORT_OK);
  check_size_eq(frames, 1u);
  check_int_eq(mesh_stream_transport_pump_once_v1(&transport, &frames), MESH_STREAM_TRANSPORT_OK);
  check_size_eq(frames, 3u);

  check_int_eq(transport.state, MESH_STREAM_TRANSPORT_CLOSED);
  check_size_eq(fake.release_count, 3u);
  check_size_eq(application.event_count, 4u);
  check_size_eq(application.data_bytes, 12u);
  check_int_eq(application.event_types[0], MESH_STREAM_FRAME_OPEN);
  check_int_eq(application.event_types[3], MESH_STREAM_FRAME_CLOSE);
  check_size_eq(fake.sent_count, 2u);
  control = decode_sent(&fake, 0u);
  check_int_eq(control.type, MESH_STREAM_FRAME_ACCEPT);
  check_hex64_eq(control.sequence, 0u);
  check_hex64_eq(control.offset, 8u);
  control = decode_sent(&fake, 1u);
  check_int_eq(control.type, MESH_STREAM_FRAME_WINDOW_UPDATE);
  check_hex64_eq(control.sequence, 1u);
  check_hex64_eq(control.offset, 12u);
  check_hex64_eq(transport.received_bytes, wire_len);
  check_hex64_eq(transport.received_frames, 4u);
  check_hex64_eq(transport.sent_control_frames, 2u);
  mesh_stream_transport_destroy_v1(&transport);
}

static void test_application_rejection_does_not_commit_open(void) {
  mesh_stream_transport_config_v1_t config = transport_config();
  mesh_stream_transport_v1_t transport;
  fake_io_t fake;
  fake_application_t application;
  uint8_t wire[96];
  uint8_t metadata[32];
  size_t metadata_len = make_open_metadata(metadata, 12u);
  size_t wire_len = encode_frame(&config, MESH_STREAM_FRAME_OPEN, 0u, 0u, 0u, metadata,
                                 metadata_len, NULL, 0u, wire, sizeof(wire));
  size_t frames = 0u;

  memset(&fake, 0, sizeof(fake));
  memset(&application, 0, sizeof(application));
  application.reject_type = MESH_STREAM_FRAME_OPEN;
  fake.chunks[0] = wire;
  fake.chunk_lengths[0] = wire_len;
  fake.chunk_count = 1u;
  check_int_eq(init_transport(&transport, &config, &fake, &application), MESH_STREAM_TRANSPORT_OK);
  check_int_eq(mesh_stream_transport_pump_once_v1(&transport, &frames),
               MESH_STREAM_TRANSPORT_APPLICATION_REJECTED);
  check_int_eq(transport.state, MESH_STREAM_TRANSPORT_FAILED);
  check_int_eq(transport.last_application_result, -77);
  check_int_eq(transport.session.state, MESH_STREAM_SESSION_AWAIT_OPEN);
  check_hex64_eq(transport.session.generation, 0u);
  check_size_eq(frames, 0u);
  check_size_eq(fake.sent_count, 0u);
  check_size_eq(fake.release_count, 1u);
  mesh_stream_transport_destroy_v1(&transport);
}

static void test_send_failure_does_not_commit_accept(void) {
  mesh_stream_transport_config_v1_t config = transport_config();
  mesh_stream_transport_v1_t transport;
  fake_io_t fake;
  fake_application_t application;
  uint8_t wire[96];
  uint8_t metadata[32];
  size_t metadata_len = make_open_metadata(metadata, 12u);
  size_t wire_len = encode_frame(&config, MESH_STREAM_FRAME_OPEN, 0u, 0u, 0u, metadata,
                                 metadata_len, NULL, 0u, wire, sizeof(wire));
  size_t frames = 0u;

  memset(&fake, 0, sizeof(fake));
  memset(&application, 0, sizeof(application));
  fake.send_result = -55;
  fake.chunks[0] = wire;
  fake.chunk_lengths[0] = wire_len;
  fake.chunk_count = 1u;
  check_int_eq(init_transport(&transport, &config, &fake, &application), MESH_STREAM_TRANSPORT_OK);
  check_int_eq(mesh_stream_transport_pump_once_v1(&transport, &frames),
               MESH_STREAM_TRANSPORT_IO_ERROR);
  check_int_eq(transport.last_io_result, -55);
  check_int_eq(transport.state, MESH_STREAM_TRANSPORT_FAILED);
  check_int_eq(transport.session.state, MESH_STREAM_SESSION_AWAIT_ACCEPT_SEND);
  check_hex64_eq(transport.session.next_control_sequence, 0u);
  check_size_eq(frames, 1u);
  check_size_eq(fake.release_count, 1u);
  mesh_stream_transport_destroy_v1(&transport);
}

static void test_binding_error_is_terminal_and_chunk_is_released(void) {
  mesh_stream_transport_config_v1_t config = transport_config();
  mesh_stream_transport_v1_t transport;
  fake_io_t fake;
  fake_application_t application;
  uint8_t wire[96];
  uint8_t metadata[32];
  size_t metadata_len = make_open_metadata(metadata, 12u);
  size_t wire_len = encode_frame(&config, MESH_STREAM_FRAME_OPEN, 0u, 0u, 0u, metadata,
                                 metadata_len, NULL, 0u, wire, sizeof(wire));
  size_t frames = 0u;

  memset(&fake, 0, sizeof(fake));
  memset(&application, 0, sizeof(application));
  wire[8] ^= 1u;
  fake.chunks[0] = wire;
  fake.chunk_lengths[0] = wire_len;
  fake.chunk_count = 1u;
  check_int_eq(init_transport(&transport, &config, &fake, &application), MESH_STREAM_TRANSPORT_OK);
  check_int_eq(mesh_stream_transport_pump_once_v1(&transport, &frames),
               MESH_STREAM_TRANSPORT_SESSION_ERROR);
  check_int_eq(transport.last_session_result, MESH_STREAM_SESSION_BINDING_MISMATCH);
  check_int_eq(transport.state, MESH_STREAM_TRANSPORT_FAILED);
  check_size_eq(fake.release_count, 1u);
  check_size_eq(application.event_count, 0u);
  mesh_stream_transport_destroy_v1(&transport);
}

static void test_interrupt_is_nonterminal_and_has_no_owned_chunk(void) {
  mesh_stream_transport_config_v1_t config = transport_config();
  mesh_stream_transport_v1_t transport;
  fake_io_t fake;
  fake_application_t application;
  size_t frames = 9u;

  memset(&fake, 0, sizeof(fake));
  memset(&application, 0, sizeof(application));
  check_int_eq(init_transport(&transport, &config, &fake, &application), MESH_STREAM_TRANSPORT_OK);
  check_int_eq(mesh_stream_transport_pump_once_v1(&transport, &frames),
               MESH_STREAM_TRANSPORT_INTERRUPTED);
  check_size_eq(frames, 0u);
  check_int_eq(transport.state, MESH_STREAM_TRANSPORT_READY);
  check_size_eq(fake.release_count, 0u);
  mesh_stream_transport_destroy_v1(&transport);
}

static void test_rejects_trailing_bytes_after_terminal_frame(void) {
  mesh_stream_transport_config_v1_t config = transport_config();
  mesh_stream_transport_v1_t transport;
  fake_io_t fake;
  fake_application_t application;
  uint8_t wire[160];
  uint8_t metadata[32];
  size_t metadata_len = make_open_metadata(metadata, 12u);
  size_t cursor = 0u;
  size_t frames = 0u;

  memset(&fake, 0, sizeof(fake));
  memset(&application, 0, sizeof(application));
  cursor += encode_frame(&config, MESH_STREAM_FRAME_OPEN, 0u, 0u, 0u, metadata, metadata_len, NULL,
                         0u, wire + cursor, sizeof(wire) - cursor);
  cursor += encode_frame(&config, MESH_STREAM_FRAME_CANCEL, 0u, 1u, 0u, REASON_NORMAL,
                         sizeof(REASON_NORMAL), NULL, 0u, wire + cursor, sizeof(wire) - cursor);
  wire[cursor++] = 0xa5u;
  fake.chunks[0] = wire;
  fake.chunk_lengths[0] = cursor;
  fake.chunk_count = 1u;
  check_int_eq(init_transport(&transport, &config, &fake, &application), MESH_STREAM_TRANSPORT_OK);
  check_int_eq(mesh_stream_transport_pump_once_v1(&transport, &frames),
               MESH_STREAM_TRANSPORT_SESSION_ERROR);
  check_int_eq(transport.last_session_result, MESH_STREAM_SESSION_INVALID_STATE);
  check_int_eq(transport.state, MESH_STREAM_TRANSPORT_FAILED);
  check_size_eq(frames, 2u);
  check_size_eq(fake.release_count, 1u);
  mesh_stream_transport_destroy_v1(&transport);
}

static void test_hwm_setup_failure_leaves_no_owned_buffer(void) {
  mesh_stream_transport_config_v1_t config = transport_config();
  mesh_stream_transport_v1_t transport;
  fake_io_t fake;
  fake_application_t application;

  memset(&fake, 0, sizeof(fake));
  memset(&application, 0, sizeof(application));
  fake.hwm_result = -66;
  check_int_eq(init_transport(&transport, &config, &fake, &application),
               MESH_STREAM_TRANSPORT_IO_ERROR);
  check_int_eq(transport.last_io_result, -66);
  check_null(transport.buffer);
  check_int_eq(transport.state, MESH_STREAM_TRANSPORT_UNINITIALIZED);
  check_size_eq(fake.configured_hwm, TEST_SEND_HWM);
  mesh_stream_transport_destroy_v1(&transport);

  check_int_eq(
      mesh_stream_transport_init_coronet_v1(&transport, &config, NULL, accept_event, &application),
      MESH_STREAM_TRANSPORT_INVALID_ARG);
}

spec("mesh stream transport adapter") {
  describe("bounded CoroNet ownership boundary") {
    it("pumps arbitrary fragments and releases every owned chunk") {
      test_pumps_fragmented_stream_and_releases_every_chunk();
    }
    it("does not commit an application-rejected OPEN") {
      test_application_rejection_does_not_commit_open();
    }
    it("does not commit ACCEPT when its send fails") { test_send_failure_does_not_commit_accept(); }
    it("makes binding errors terminal while releasing the recv chunk") {
      test_binding_error_is_terminal_and_chunk_is_released();
    }
    it("keeps an interrupted receive nonterminal") {
      test_interrupt_is_nonterminal_and_has_no_owned_chunk();
    }
    it("rejects bytes trailing a terminal stream frame") {
      test_rejects_trailing_bytes_after_terminal_frame();
    }
    it("cleans initialization state when CoroNet HWM setup fails") {
      test_hwm_setup_failure_leaves_no_owned_buffer();
    }
  }
}
