#include <tinytest.h>

#include "mesh_stream_registry.h"

#include <string.h>

#define TEST_FRAME_MAX 128u
#define TEST_IO_TIMEOUT_MS 1000u
#define TEST_SEND_HWM 256u
#define TEST_STREAM_EPOCH 31u
#define TEST_ADMISSION_GENERATION 47u
#define TEST_REGISTRY_GENERATION 71u

typedef struct {
  size_t configured_hwm;
  uint64_t configured_timeout_ms;
} fake_io_t;

static int fake_recv(void *context, uint8_t **out_bytes, size_t *out_len) {
  (void)context;
  *out_bytes = NULL;
  *out_len = 0u;
  return 0;
}

static void fake_release_recv(void *context, uint8_t *bytes) {
  (void)context;
  (void)bytes;
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
  return 0;
}

static int fake_set_timeout(void *context, uint64_t timeout_ms) {
  fake_io_t *fake = (fake_io_t *)context;

  fake->configured_timeout_ms = timeout_ms;
  return 0;
}

static int accept_event(void *context, const mesh_stream_receive_event_v1_t *event) {
  (void)context;
  (void)event;
  return 0;
}

static mesh_stream_registry_config_v1_t registry_config(size_t capacity,
                                                        size_t max_channels_per_peer) {
  mesh_stream_registry_config_v1_t config;

  config.capacity = capacity;
  config.max_channels_per_peer = max_channels_per_peer;
  config.owner_generation = TEST_REGISTRY_GENERATION;
  return config;
}

static void prepare_open(mesh_stream_registry_open_v1_t *request, fake_io_t *fake,
                         uint8_t peer_byte, uint64_t admission_generation, uint8_t stream_byte,
                         uint64_t stream_epoch) {
  memset(request, 0, sizeof(*request));
  memset(request->admission.remote_peer_id, peer_byte, sizeof(request->admission.remote_peer_id));
  request->admission.generation = admission_generation;
  memset(request->admission.stream_id, stream_byte, sizeof(request->admission.stream_id));
  request->admission.stream_epoch = stream_epoch;
  memcpy(request->transport.receiver.stream_id, request->admission.stream_id,
         sizeof(request->admission.stream_id));
  request->transport.receiver.stream_epoch = stream_epoch;
  request->transport.receiver.max_frame_size = TEST_FRAME_MAX;
  request->transport.receiver.initial_receive_window = 8u;
  request->transport.receiver.max_receive_window = 16u;
  request->transport.receiver.max_total_size = 100u;
  request->transport.receiver.allowed_class_mask = MESH_STREAM_CLASS_MEDIA_MASK;
  request->transport.window_update_threshold = 4u;
  request->transport.receive_timeout_ms = TEST_IO_TIMEOUT_MS;
  request->transport.send_high_watermark = TEST_SEND_HWM;
  request->io.recv = fake_recv;
  request->io.release_recv = fake_release_recv;
  request->io.send = fake_send;
  request->io.set_send_hwm = fake_set_hwm;
  request->io.set_receive_timeout = fake_set_timeout;
  request->io.context = fake;
  request->on_event = accept_event;
}

static void close_and_release(mesh_stream_registry_v1_t *registry,
                              mesh_stream_channel_handle_v1_t handle) {
  check_int_eq(mesh_stream_registry_close_v1(registry, handle), MESH_STREAM_REGISTRY_OK);
  check_int_eq(mesh_stream_registry_release_v1(registry, handle), MESH_STREAM_REGISTRY_OK);
}

static void test_rejects_invalid_capacity_policy(void) {
  mesh_stream_registry_v1_t registry;
  mesh_stream_registry_config_v1_t config = registry_config(0u, 1u);

  memset(&registry, 0, sizeof(registry));
  check_int_eq(mesh_stream_registry_init_v1(&registry, &config), MESH_STREAM_REGISTRY_INVALID_ARG);
  check_null(registry.slots);
  config = registry_config(2u, 3u);
  check_int_eq(mesh_stream_registry_init_v1(&registry, &config), MESH_STREAM_REGISTRY_INVALID_ARG);
  check_null(registry.slots);
}

static void test_rejects_duplicate_and_peer_quota_without_mutation(void) {
  mesh_stream_registry_v1_t registry;
  mesh_stream_registry_config_v1_t config = registry_config(2u, 1u);
  mesh_stream_registry_open_v1_t request;
  mesh_stream_registry_open_v1_t second;
  mesh_stream_channel_handle_v1_t handle;
  mesh_stream_channel_handle_v1_t rejected;
  mesh_stream_registry_stats_v1_t stats;
  fake_io_t fake;

  memset(&registry, 0, sizeof(registry));
  memset(&fake, 0, sizeof(fake));
  prepare_open(&request, &fake, 0x31u, TEST_ADMISSION_GENERATION, 0x41u, TEST_STREAM_EPOCH);
  check_int_eq(mesh_stream_registry_init_v1(&registry, &config), MESH_STREAM_REGISTRY_OK);
  check_int_eq(mesh_stream_registry_open_v1(&registry, &request, &handle), MESH_STREAM_REGISTRY_OK);
  check_int_eq(mesh_stream_registry_open_v1(&registry, &request, &rejected),
               MESH_STREAM_REGISTRY_DUPLICATE);
  check_hex64_eq(rejected.generation, 0u);
  second = request;
  memset(second.admission.stream_id, 0x42, sizeof(second.admission.stream_id));
  memcpy(second.transport.receiver.stream_id, second.admission.stream_id,
         sizeof(second.admission.stream_id));
  check_int_eq(mesh_stream_registry_open_v1(&registry, &second, &rejected),
               MESH_STREAM_REGISTRY_PEER_LIMIT);
  check_int_eq(mesh_stream_registry_query_stats_v1(&registry, &stats), MESH_STREAM_REGISTRY_OK);
  check_size_eq(stats.occupied_channels, 1u);
  check_size_eq(stats.peak_occupied_channels, 1u);
  close_and_release(&registry, handle);
  mesh_stream_registry_destroy_v1(&registry);
}

static void test_fails_closed_at_capacity_and_preserves_peak(void) {
  mesh_stream_registry_v1_t registry;
  mesh_stream_registry_config_v1_t config = registry_config(2u, 2u);
  mesh_stream_registry_open_v1_t first;
  mesh_stream_registry_open_v1_t second;
  mesh_stream_registry_open_v1_t third;
  mesh_stream_channel_handle_v1_t first_handle;
  mesh_stream_channel_handle_v1_t second_handle;
  mesh_stream_channel_handle_v1_t rejected;
  mesh_stream_registry_stats_v1_t stats;
  fake_io_t fake;

  memset(&registry, 0, sizeof(registry));
  memset(&fake, 0, sizeof(fake));
  prepare_open(&first, &fake, 0x31u, TEST_ADMISSION_GENERATION, 0x41u, TEST_STREAM_EPOCH);
  prepare_open(&second, &fake, 0x32u, TEST_ADMISSION_GENERATION, 0x42u, TEST_STREAM_EPOCH);
  prepare_open(&third, &fake, 0x33u, TEST_ADMISSION_GENERATION, 0x43u, TEST_STREAM_EPOCH);
  check_int_eq(mesh_stream_registry_init_v1(&registry, &config), MESH_STREAM_REGISTRY_OK);
  check_int_eq(mesh_stream_registry_open_v1(&registry, &first, &first_handle),
               MESH_STREAM_REGISTRY_OK);
  check_int_eq(mesh_stream_registry_open_v1(&registry, &second, &second_handle),
               MESH_STREAM_REGISTRY_OK);
  check_int_eq(mesh_stream_registry_open_v1(&registry, &third, &rejected),
               MESH_STREAM_REGISTRY_CAPACITY_EXHAUSTED);
  check_int_eq(mesh_stream_registry_query_stats_v1(&registry, &stats), MESH_STREAM_REGISTRY_OK);
  check_size_eq(stats.capacity, 2u);
  check_hex64_eq(stats.owner_generation, TEST_REGISTRY_GENERATION);
  check_size_eq(stats.occupied_channels, 2u);
  check_size_eq(stats.peak_occupied_channels, 2u);
  check_size_eq(stats.ready_channels, 2u);
  close_and_release(&registry, first_handle);
  close_and_release(&registry, second_handle);
  mesh_stream_registry_destroy_v1(&registry);
}

static void test_reused_slot_rejects_stale_handle(void) {
  mesh_stream_registry_v1_t registry;
  mesh_stream_registry_v1_t other_registry;
  mesh_stream_registry_config_v1_t config = registry_config(1u, 1u);
  mesh_stream_registry_open_v1_t first;
  mesh_stream_registry_open_v1_t second;
  mesh_stream_channel_handle_v1_t old_handle;
  mesh_stream_channel_handle_v1_t new_handle;
  mesh_stream_channel_handle_v1_t reincarnated_handle;
  mesh_stream_registry_channel_info_v1_t info;
  fake_io_t fake;

  memset(&registry, 0, sizeof(registry));
  memset(&other_registry, 0, sizeof(other_registry));
  memset(&fake, 0, sizeof(fake));
  prepare_open(&first, &fake, 0x31u, TEST_ADMISSION_GENERATION, 0x41u, TEST_STREAM_EPOCH);
  prepare_open(&second, &fake, 0x32u, TEST_ADMISSION_GENERATION, 0x42u, TEST_STREAM_EPOCH);
  check_int_eq(mesh_stream_registry_init_v1(&registry, &config), MESH_STREAM_REGISTRY_OK);
  check_int_eq(mesh_stream_registry_open_v1(&registry, &first, &old_handle),
               MESH_STREAM_REGISTRY_OK);
  check_int_eq(mesh_stream_registry_init_v1(&other_registry, &config), MESH_STREAM_REGISTRY_OK);
  check_int_eq(mesh_stream_registry_query_channel_v1(&other_registry, old_handle, &info),
               MESH_STREAM_REGISTRY_STALE_HANDLE);
  mesh_stream_registry_destroy_v1(&other_registry);
  close_and_release(&registry, old_handle);
  check_int_eq(mesh_stream_registry_open_v1(&registry, &second, &new_handle),
               MESH_STREAM_REGISTRY_OK);
  check_size_eq(new_handle.slot, old_handle.slot);
  check_hex64_eq(new_handle.generation, old_handle.generation + 1u);
  check_int_eq(mesh_stream_registry_query_channel_v1(&registry, old_handle, &info),
               MESH_STREAM_REGISTRY_STALE_HANDLE);
  check_int_eq(mesh_stream_registry_close_v1(&registry, old_handle),
               MESH_STREAM_REGISTRY_STALE_HANDLE);
  check_int_eq(mesh_stream_registry_query_channel_v1(&registry, new_handle, &info),
               MESH_STREAM_REGISTRY_OK);
  check_int_eq(info.state, MESH_STREAM_CHANNEL_READY);
  close_and_release(&registry, new_handle);
  mesh_stream_registry_destroy_v1(&registry);

  config.owner_generation++;
  check_int_eq(mesh_stream_registry_init_v1(&registry, &config), MESH_STREAM_REGISTRY_OK);
  check_int_eq(mesh_stream_registry_open_v1(&registry, &first, &reincarnated_handle),
               MESH_STREAM_REGISTRY_OK);
  check_size_eq(reincarnated_handle.slot, old_handle.slot);
  check_hex64_eq(reincarnated_handle.generation, old_handle.generation);
  check_int_eq(mesh_stream_registry_query_channel_v1(&registry, old_handle, &info),
               MESH_STREAM_REGISTRY_STALE_HANDLE);
  close_and_release(&registry, reincarnated_handle);
  mesh_stream_registry_destroy_v1(&registry);
}

static void test_revoke_matches_peer_and_admission_generation(void) {
  mesh_stream_registry_v1_t registry;
  mesh_stream_registry_config_v1_t config = registry_config(3u, 3u);
  mesh_stream_registry_open_v1_t old_peer;
  mesh_stream_registry_open_v1_t new_peer_generation;
  mesh_stream_registry_open_v1_t other_peer;
  mesh_stream_channel_handle_v1_t old_handle;
  mesh_stream_channel_handle_v1_t new_handle;
  mesh_stream_channel_handle_v1_t other_handle;
  mesh_stream_registry_channel_info_v1_t info;
  mesh_stream_registry_stats_v1_t stats;
  fake_io_t fake;
  size_t revoked = 99u;

  memset(&registry, 0, sizeof(registry));
  memset(&fake, 0, sizeof(fake));
  prepare_open(&old_peer, &fake, 0x31u, TEST_ADMISSION_GENERATION, 0x41u, TEST_STREAM_EPOCH);
  prepare_open(&new_peer_generation, &fake, 0x31u, TEST_ADMISSION_GENERATION + 1u, 0x42u,
               TEST_STREAM_EPOCH + 1u);
  prepare_open(&other_peer, &fake, 0x32u, TEST_ADMISSION_GENERATION, 0x43u, TEST_STREAM_EPOCH);
  check_int_eq(mesh_stream_registry_init_v1(&registry, &config), MESH_STREAM_REGISTRY_OK);
  check_int_eq(mesh_stream_registry_open_v1(&registry, &old_peer, &old_handle),
               MESH_STREAM_REGISTRY_OK);
  check_int_eq(mesh_stream_registry_open_v1(&registry, &new_peer_generation, &new_handle),
               MESH_STREAM_REGISTRY_OK);
  check_int_eq(mesh_stream_registry_open_v1(&registry, &other_peer, &other_handle),
               MESH_STREAM_REGISTRY_OK);
  check_int_eq(mesh_stream_registry_revoke_peer_v1(&registry, old_peer.admission.remote_peer_id,
                                                   TEST_ADMISSION_GENERATION, &revoked),
               MESH_STREAM_REGISTRY_OK);
  check_size_eq(revoked, 1u);
  check_int_eq(mesh_stream_registry_query_channel_v1(&registry, old_handle, &info),
               MESH_STREAM_REGISTRY_OK);
  check_int_eq(info.state, MESH_STREAM_CHANNEL_REVOKED);
  check_int_eq(mesh_stream_registry_query_channel_v1(&registry, new_handle, &info),
               MESH_STREAM_REGISTRY_OK);
  check_int_eq(info.state, MESH_STREAM_CHANNEL_READY);
  check_int_eq(mesh_stream_registry_query_channel_v1(&registry, other_handle, &info),
               MESH_STREAM_REGISTRY_OK);
  check_int_eq(info.state, MESH_STREAM_CHANNEL_READY);
  check_int_eq(mesh_stream_registry_revoke_peer_v1(&registry, old_peer.admission.remote_peer_id,
                                                   TEST_ADMISSION_GENERATION, &revoked),
               MESH_STREAM_REGISTRY_OK);
  check_size_eq(revoked, 0u);
  check_int_eq(mesh_stream_registry_query_stats_v1(&registry, &stats), MESH_STREAM_REGISTRY_OK);
  check_size_eq(stats.ready_channels, 2u);
  check_size_eq(stats.terminal_channels, 1u);
  check_int_eq(mesh_stream_registry_release_v1(&registry, old_handle), MESH_STREAM_REGISTRY_OK);
  close_and_release(&registry, new_handle);
  close_and_release(&registry, other_handle);
  mesh_stream_registry_destroy_v1(&registry);
}

static void test_terminal_failure_remains_queryable_until_release(void) {
  mesh_stream_registry_v1_t registry;
  mesh_stream_registry_config_v1_t config = registry_config(1u, 1u);
  mesh_stream_registry_open_v1_t request;
  mesh_stream_channel_handle_v1_t handle;
  mesh_stream_channel_handle_v1_t rejected;
  mesh_stream_registry_channel_info_v1_t info;
  uint8_t invalid_frame[MESH_STREAM_FIXED_HEADER_SIZE];
  fake_io_t fake;
  size_t frames = 99u;

  memset(&registry, 0, sizeof(registry));
  memset(&fake, 0, sizeof(fake));
  memset(invalid_frame, 0, sizeof(invalid_frame));
  prepare_open(&request, &fake, 0x31u, TEST_ADMISSION_GENERATION, 0x41u, TEST_STREAM_EPOCH);
  check_int_eq(mesh_stream_registry_init_v1(&registry, &config), MESH_STREAM_REGISTRY_OK);
  check_int_eq(mesh_stream_registry_open_v1(&registry, &request, &handle), MESH_STREAM_REGISTRY_OK);
  check_int_eq(mesh_stream_registry_release_v1(&registry, handle),
               MESH_STREAM_REGISTRY_INVALID_STATE);
  check_int_eq(mesh_stream_registry_feed_v1(&registry, handle, invalid_frame, sizeof(invalid_frame),
                                            &frames),
               MESH_STREAM_REGISTRY_CHANNEL_ERROR);
  check_size_eq(frames, 0u);
  check_int_eq(mesh_stream_registry_query_channel_v1(&registry, handle, &info),
               MESH_STREAM_REGISTRY_OK);
  check_int_eq(info.state, MESH_STREAM_CHANNEL_FAILED);
  check_int_eq(info.last_transport_result, MESH_STREAM_TRANSPORT_SESSION_ERROR);
  check_int_eq(info.last_session_result, MESH_STREAM_SESSION_INVALID_FRAME);
  check_size_eq(info.received_bytes, sizeof(invalid_frame));
  check_int_eq(mesh_stream_registry_open_v1(&registry, &request, &rejected),
               MESH_STREAM_REGISTRY_DUPLICATE);
  check_hex64_eq(rejected.generation, 0u);
  check_int_eq(mesh_stream_registry_release_v1(&registry, handle), MESH_STREAM_REGISTRY_OK);
  check_int_eq(mesh_stream_registry_query_channel_v1(&registry, handle, &info),
               MESH_STREAM_REGISTRY_STALE_HANDLE);
  mesh_stream_registry_destroy_v1(&registry);
}

spec("mesh stream registry") {
  describe("bounded owner-loop channel management") {
    it("rejects invalid total and per-peer capacities") { test_rejects_invalid_capacity_policy(); }
    it("rejects duplicate streams and per-peer quota overflow without mutation") {
      test_rejects_duplicate_and_peer_quota_without_mutation();
    }
    it("fails closed at total capacity and preserves the peak") {
      test_fails_closed_at_capacity_and_preserves_peak();
    }
    it("rejects an old handle after its slot is reused") {
      test_reused_slot_rejects_stale_handle();
    }
    it("revokes only the matching peer admission generation") {
      test_revoke_matches_peer_and_admission_generation();
    }
    it("keeps terminal diagnostics until explicit release") {
      test_terminal_failure_remains_queryable_until_release();
    }
  }
}
