#include <tinytest.h>

#include "mesh_stream_channel.h"

#include <string.h>

#define TEST_FRAME_MAX 128u
#define TEST_IO_TIMEOUT_MS 1000u
#define TEST_SEND_HWM 256u
#define TEST_STREAM_EPOCH 31u
#define TEST_ADMISSION_GENERATION 47u
#define TEST_IO_CONFIG_ERROR -17

typedef struct {
  int set_hwm_result;
  int set_timeout_result;
  size_t configured_hwm;
  uint64_t configured_timeout_ms;
  size_t release_count;
} fake_io_t;

static void fill_stream_id(uint8_t stream_id[MESH_STREAM_ID_SIZE]) {
  size_t index = 0u;

  for (index = 0u; index < MESH_STREAM_ID_SIZE; index++)
    stream_id[index] = (uint8_t)(0x20u + index);
}

static mesh_stream_transport_config_v1_t test_config(void) {
  mesh_stream_transport_config_v1_t config;

  memset(&config, 0, sizeof(config));
  fill_stream_id(config.receiver.stream_id);
  config.receiver.stream_epoch = TEST_STREAM_EPOCH;
  config.receiver.max_frame_size = TEST_FRAME_MAX;
  config.receiver.initial_receive_window = 8u;
  config.receiver.max_receive_window = 16u;
  config.receiver.max_total_size = 100u;
  config.receiver.allowed_class_mask = MESH_STREAM_CLASS_MEDIA_MASK;
  config.window_update_threshold = 4u;
  config.receive_timeout_ms = TEST_IO_TIMEOUT_MS;
  config.send_high_watermark = TEST_SEND_HWM;
  return config;
}

static mesh_stream_channel_admission_v1_t test_admission(void) {
  mesh_stream_channel_admission_v1_t admission;
  size_t index = 0u;

  memset(&admission, 0, sizeof(admission));
  for (index = 0u; index < sizeof(admission.remote_peer_id); index++)
    admission.remote_peer_id[index] = (uint8_t)(0x80u + index);
  admission.generation = TEST_ADMISSION_GENERATION;
  fill_stream_id(admission.stream_id);
  admission.stream_epoch = TEST_STREAM_EPOCH;
  return admission;
}

static int fake_recv(void *context, uint8_t **out_bytes, size_t *out_len) {
  (void)context;
  *out_bytes = NULL;
  *out_len = 0u;
  return 0;
}

static void fake_release_recv(void *context, uint8_t *bytes) {
  fake_io_t *fake = (fake_io_t *)context;

  (void)bytes;
  fake->release_count++;
}

static int fake_send(void *context, const uint8_t *bytes, size_t len) {
  (void)context;
  (void)bytes;
  (void)len;
  return 0;
}

static int fake_set_hwm(void *context, size_t bytes) {
  fake_io_t *fake = (fake_io_t *)context;

  fake->configured_hwm = bytes;
  return fake->set_hwm_result;
}

static int fake_set_timeout(void *context, uint64_t timeout_ms) {
  fake_io_t *fake = (fake_io_t *)context;

  fake->configured_timeout_ms = timeout_ms;
  return fake->set_timeout_result;
}

static mesh_stream_transport_io_v1_t test_io(fake_io_t *fake) {
  mesh_stream_transport_io_v1_t io;

  memset(&io, 0, sizeof(io));
  io.recv = fake_recv;
  io.release_recv = fake_release_recv;
  io.send = fake_send;
  io.set_send_hwm = fake_set_hwm;
  io.set_receive_timeout = fake_set_timeout;
  io.context = fake;
  return io;
}

static int accept_event(void *context, const mesh_stream_receive_event_v1_t *event) {
  (void)context;
  (void)event;
  return 0;
}

static void test_rejects_invalid_admission_binding(void) {
  mesh_stream_channel_v1_t channel;
  mesh_stream_channel_admission_v1_t admission = test_admission();
  mesh_stream_transport_config_v1_t config = test_config();
  fake_io_t fake;
  mesh_stream_transport_io_v1_t io;

  memset(&channel, 0, sizeof(channel));
  memset(&fake, 0, sizeof(fake));
  io = test_io(&fake);
  memset(admission.remote_peer_id, 0, sizeof(admission.remote_peer_id));
  check_int_eq(mesh_stream_channel_init_v1(&channel, &admission, &config, &io, accept_event, NULL),
               MESH_STREAM_CHANNEL_INVALID_ARG);
  check_int_eq(channel.state, MESH_STREAM_CHANNEL_UNINITIALIZED);
  check_null(channel.transport.buffer);

  admission = test_admission();
  admission.stream_epoch++;
  check_int_eq(mesh_stream_channel_init_v1(&channel, &admission, &config, &io, accept_event, NULL),
               MESH_STREAM_CHANNEL_INVALID_ARG);
  check_int_eq(channel.state, MESH_STREAM_CHANNEL_UNINITIALIZED);

  admission = test_admission();
  admission.stream_id[0]++;
  check_int_eq(mesh_stream_channel_init_v1(&channel, &admission, &config, &io, accept_event, NULL),
               MESH_STREAM_CHANNEL_INVALID_ARG);
  check_int_eq(channel.state, MESH_STREAM_CHANNEL_UNINITIALIZED);
}

static void test_stale_generation_cannot_touch_live_channel(void) {
  mesh_stream_channel_v1_t channel;
  mesh_stream_channel_admission_v1_t admission = test_admission();
  mesh_stream_transport_config_v1_t config = test_config();
  fake_io_t fake;
  mesh_stream_transport_io_v1_t io;
  size_t frames = 99u;

  memset(&channel, 0, sizeof(channel));
  memset(&fake, 0, sizeof(fake));
  io = test_io(&fake);
  check_int_eq(mesh_stream_channel_init_v1(&channel, &admission, &config, &io, accept_event, NULL),
               MESH_STREAM_CHANNEL_OK);
  check_not_null(channel.transport.buffer);
  check_int_eq(mesh_stream_channel_pump_once_v1(&channel, admission.generation - 1u, &frames),
               MESH_STREAM_CHANNEL_STALE_ADMISSION);
  check_size_eq(frames, 0u);
  check_int_eq(mesh_stream_channel_revoke_v1(&channel, admission.generation - 1u),
               MESH_STREAM_CHANNEL_STALE_ADMISSION);
  check_int_eq(mesh_stream_channel_close_v1(&channel, admission.generation - 1u),
               MESH_STREAM_CHANNEL_STALE_ADMISSION);
  check_int_eq(channel.state, MESH_STREAM_CHANNEL_READY);
  check_not_null(channel.transport.buffer);
  mesh_stream_channel_destroy_v1(&channel);
}

static void test_interrupt_is_non_terminal(void) {
  mesh_stream_channel_v1_t channel;
  mesh_stream_channel_admission_v1_t admission = test_admission();
  mesh_stream_transport_config_v1_t config = test_config();
  fake_io_t fake;
  mesh_stream_transport_io_v1_t io;
  size_t frames = 99u;

  memset(&channel, 0, sizeof(channel));
  memset(&fake, 0, sizeof(fake));
  io = test_io(&fake);
  check_int_eq(mesh_stream_channel_init_v1(&channel, &admission, &config, &io, accept_event, NULL),
               MESH_STREAM_CHANNEL_OK);
  check_int_eq(mesh_stream_channel_pump_once_v1(&channel, admission.generation, &frames),
               MESH_STREAM_CHANNEL_INTERRUPTED);
  check_size_eq(frames, 0u);
  check_int_eq(channel.state, MESH_STREAM_CHANNEL_READY);
  check_not_null(channel.transport.buffer);
  check_size_eq(fake.release_count, 0u);
  mesh_stream_channel_destroy_v1(&channel);
}

static void test_revoke_releases_owned_memory_and_is_idempotent(void) {
  mesh_stream_channel_v1_t channel;
  mesh_stream_channel_admission_v1_t admission = test_admission();
  mesh_stream_transport_config_v1_t config = test_config();
  fake_io_t fake;
  mesh_stream_transport_io_v1_t io;
  size_t frames = 99u;

  memset(&channel, 0, sizeof(channel));
  memset(&fake, 0, sizeof(fake));
  io = test_io(&fake);
  check_int_eq(mesh_stream_channel_init_v1(&channel, &admission, &config, &io, accept_event, NULL),
               MESH_STREAM_CHANNEL_OK);
  check_int_eq(mesh_stream_channel_revoke_v1(&channel, admission.generation),
               MESH_STREAM_CHANNEL_OK);
  check_int_eq(channel.state, MESH_STREAM_CHANNEL_REVOKED);
  check_null(channel.transport.buffer);
  check_int_eq(mesh_stream_channel_revoke_v1(&channel, admission.generation),
               MESH_STREAM_CHANNEL_OK);
  check_int_eq(mesh_stream_channel_pump_once_v1(&channel, admission.generation, &frames),
               MESH_STREAM_CHANNEL_INVALID_STATE);
  check_int_eq(mesh_stream_channel_close_v1(&channel, admission.generation),
               MESH_STREAM_CHANNEL_OK);
  check_int_eq(channel.state, MESH_STREAM_CHANNEL_REVOKED);
  mesh_stream_channel_destroy_v1(&channel);
  check_int_eq(channel.state, MESH_STREAM_CHANNEL_UNINITIALIZED);
}

static void test_local_close_releases_owned_memory_and_is_idempotent(void) {
  mesh_stream_channel_v1_t channel;
  mesh_stream_channel_admission_v1_t admission = test_admission();
  mesh_stream_transport_config_v1_t config = test_config();
  fake_io_t fake;
  mesh_stream_transport_io_v1_t io;

  memset(&channel, 0, sizeof(channel));
  memset(&fake, 0, sizeof(fake));
  io = test_io(&fake);
  check_int_eq(mesh_stream_channel_init_v1(&channel, &admission, &config, &io, accept_event, NULL),
               MESH_STREAM_CHANNEL_OK);
  check_int_eq(mesh_stream_channel_close_v1(&channel, admission.generation),
               MESH_STREAM_CHANNEL_OK);
  check_int_eq(channel.state, MESH_STREAM_CHANNEL_CLOSED);
  check_null(channel.transport.buffer);
  check_int_eq(mesh_stream_channel_close_v1(&channel, admission.generation),
               MESH_STREAM_CHANNEL_OK);
  check_int_eq(channel.state, MESH_STREAM_CHANNEL_CLOSED);
  mesh_stream_channel_destroy_v1(&channel);
}

static void test_transport_failure_preserves_diagnostics_and_releases_memory(void) {
  mesh_stream_channel_v1_t channel;
  mesh_stream_channel_admission_v1_t admission = test_admission();
  mesh_stream_transport_config_v1_t config = test_config();
  fake_io_t fake;
  mesh_stream_transport_io_v1_t io;
  uint8_t invalid_frame[MESH_STREAM_FIXED_HEADER_SIZE];
  size_t frames = 99u;

  memset(&channel, 0, sizeof(channel));
  memset(&fake, 0, sizeof(fake));
  memset(invalid_frame, 0, sizeof(invalid_frame));
  io = test_io(&fake);
  check_int_eq(mesh_stream_channel_init_v1(&channel, &admission, &config, &io, accept_event, NULL),
               MESH_STREAM_CHANNEL_OK);
  check_int_eq(mesh_stream_channel_feed_v1(&channel, admission.generation, invalid_frame,
                                           sizeof(invalid_frame), &frames),
               MESH_STREAM_CHANNEL_TRANSPORT_ERROR);
  check_size_eq(frames, 0u);
  check_int_eq(channel.state, MESH_STREAM_CHANNEL_FAILED);
  check_int_eq(channel.last_transport_result, MESH_STREAM_TRANSPORT_SESSION_ERROR);
  check_int_eq(channel.last_session_result, MESH_STREAM_SESSION_INVALID_FRAME);
  check_size_eq(channel.received_bytes, sizeof(invalid_frame));
  check_null(channel.transport.buffer);
  check_int_eq(mesh_stream_channel_close_v1(&channel, admission.generation),
               MESH_STREAM_CHANNEL_OK);
  check_int_eq(channel.state, MESH_STREAM_CHANNEL_FAILED);
  mesh_stream_channel_destroy_v1(&channel);
}

static void test_init_failure_preserves_transport_error(void) {
  mesh_stream_channel_v1_t channel;
  mesh_stream_channel_admission_v1_t admission = test_admission();
  mesh_stream_transport_config_v1_t config = test_config();
  fake_io_t fake;
  mesh_stream_transport_io_v1_t io;

  memset(&channel, 0, sizeof(channel));
  memset(&fake, 0, sizeof(fake));
  fake.set_hwm_result = TEST_IO_CONFIG_ERROR;
  io = test_io(&fake);
  check_int_eq(mesh_stream_channel_init_v1(&channel, &admission, &config, &io, accept_event, NULL),
               MESH_STREAM_CHANNEL_TRANSPORT_ERROR);
  check_int_eq(channel.state, MESH_STREAM_CHANNEL_UNINITIALIZED);
  check_int_eq(channel.last_transport_result, MESH_STREAM_TRANSPORT_IO_ERROR);
  check_int_eq(channel.last_io_result, TEST_IO_CONFIG_ERROR);
  check_null(channel.transport.buffer);
  check_size_eq(fake.configured_hwm, TEST_SEND_HWM);
}

spec("mesh stream channel") {
  describe("authenticated lifecycle ownership") {
    it("rejects an invalid peer or epoch binding") { test_rejects_invalid_admission_binding(); }
    it("does not let stale disconnect work touch a live channel") {
      test_stale_generation_cannot_touch_live_channel();
    }
    it("keeps interrupted receives non-terminal") { test_interrupt_is_non_terminal(); }
    it("releases the receive window immediately on admission revoke") {
      test_revoke_releases_owned_memory_and_is_idempotent();
    }
    it("releases the receive window on an idempotent local close") {
      test_local_close_releases_owned_memory_and_is_idempotent();
    }
    it("preserves terminal transport diagnostics after cleanup") {
      test_transport_failure_preserves_diagnostics_and_releases_memory();
    }
    it("preserves transport initialization failures") {
      test_init_failure_preserves_transport_error();
    }
  }
}
