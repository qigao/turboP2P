#include <tinytest.h>

#include "mesh_stream_coronet_adapter.h"

#include <CoroNet.h>

#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <sys/socket.h>
  #include <unistd.h>
#endif

#define TEST_FRAME_MAX 128u
#define TEST_IO_TIMEOUT_MS 3000u
#define TEST_RUN_TIMEOUT_MS 5000u
#define TEST_SEND_HWM 256u
#define TEST_STREAM_EPOCH 31u
#define TEST_AUTH_NOW_MS 1000u
#define TEST_PENDING_RESULT -1000

static const uint8_t TEST_PAYLOAD[] = {1u, 2u, 3u, 4u, 5u, 6u};
static const uint8_t REASON_NORMAL[] = {0x00u, 0x01u, 0x00u, 0x02u, 0x00u, 0x00u};
static const uint8_t INITIATOR_PRIVATE_KEY[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};
static const uint8_t RESPONDER_PRIVATE_KEY[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
};

typedef struct {
  coro_context_t *context;
  coro_socket_t *server;
  unsigned short port;
  mesh_stream_transport_config_v1_t config;
  mesh_stream_bind_store_v1_t bind_store;
  mesh_stream_bind_ticket_v1_t bind_ticket;
  mesh_stream_coronet_authorization_v1_t server_authorization;
  mesh_stream_coronet_authorization_v1_t client_authorization;
  uint8_t open_frame[96];
  size_t open_frame_len;
  uint8_t first_data_frame[64];
  size_t first_data_frame_len;
  uint8_t terminal_frames[128];
  size_t terminal_frames_len;
  int server_result;
  int client_result;
  int server_done;
  int client_done;
  int accept_valid;
  int window_valid;
  size_t event_count;
  size_t data_bytes;
  mesh_stream_channel_state_t final_channel_state;
} coronet_stream_test_state_t;

static void fill_bytes(uint8_t *bytes, size_t length, uint8_t first) {
  size_t index = 0u;

  for (index = 0u; index < length; index++)
    bytes[index] = (uint8_t)(first + index);
}

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
  admission.generation = TEST_STREAM_EPOCH;
  fill_stream_id(admission.stream_id);
  admission.stream_epoch = TEST_STREAM_EPOCH;
  return admission;
}

static mesh_stream_coronet_authorization_v1_t
test_forged_authorization(const mesh_stream_channel_admission_v1_t *admission) {
  mesh_stream_coronet_authorization_v1_t authorization;

  memset(&authorization, 0, sizeof(authorization));
  authorization.ticket.issued_at_ms = TEST_AUTH_NOW_MS - 1u;
  authorization.ticket.expires_at_ms = TEST_AUTH_NOW_MS + 1u;
  memcpy(authorization.ticket.claims.responder_node_id, admission->remote_peer_id,
         sizeof(admission->remote_peer_id));
  memcpy(authorization.ticket.claims.stream_id, admission->stream_id,
         sizeof(admission->stream_id));
  authorization.ticket.claims.stream_epoch = admission->stream_epoch;
  authorization.ticket.claims.admission_generation = admission->generation;
  memset(authorization.channel_binding, 0xa5, sizeof(authorization.channel_binding));
  authorization.local_role = MESH_STREAM_CORONET_ROLE_INITIATOR;
  authorization.authenticated = 1u;
  return authorization;
}

static int set_tls_test_environment(void) {
#ifdef _WIN32
  if (_putenv_s("TURBONET_TLS_CA_FILE", MESH_TEST_TLS_CERT_FILE) != 0)
    return -1;
  if (_putenv_s("TURBONET_TLS_CA_PATH", "") != 0)
    return -1;
  if (_putenv_s("TURBONET_TLS_CERT_FILE", MESH_TEST_TLS_CERT_FILE) != 0)
    return -1;
  return _putenv_s("TURBONET_TLS_KEY_FILE", MESH_TEST_TLS_KEY_FILE) == 0 ? 0 : -1;
#else
  if (setenv("TURBONET_TLS_CA_FILE", MESH_TEST_TLS_CERT_FILE, 1) != 0)
    return -1;
  if (unsetenv("TURBONET_TLS_CA_PATH") != 0)
    return -1;
  if (setenv("TURBONET_TLS_CERT_FILE", MESH_TEST_TLS_CERT_FILE, 1) != 0)
    return -1;
  return setenv("TURBONET_TLS_KEY_FILE", MESH_TEST_TLS_KEY_FILE, 1) == 0 ? 0 : -1;
#endif
}

static void clear_tls_test_environment(void) {
#ifdef _WIN32
  (void)_putenv_s("TURBONET_TLS_CA_FILE", "");
  (void)_putenv_s("TURBONET_TLS_CA_PATH", "");
  (void)_putenv_s("TURBONET_TLS_CERT_FILE", "");
  (void)_putenv_s("TURBONET_TLS_KEY_FILE", "");
#else
  (void)unsetenv("TURBONET_TLS_CA_FILE");
  (void)unsetenv("TURBONET_TLS_CA_PATH");
  (void)unsetenv("TURBONET_TLS_CERT_FILE");
  (void)unsetenv("TURBONET_TLS_KEY_FILE");
#endif
}

static int prepare_bind_ticket(coronet_stream_test_state_t *state) {
  mesh_stream_bind_store_config_v1_t store_config = {1u, 5000u};
  mesh_stream_bind_claims_v1_t claims;

  memset(&claims, 0, sizeof(claims));
  fill_bytes(claims.mesh_id_hash, sizeof(claims.mesh_id_hash), 0x10u);
  fill_bytes(claims.initiator_node_id, sizeof(claims.initiator_node_id), 0x40u);
  fill_bytes(claims.responder_node_id, sizeof(claims.responder_node_id), 0x80u);
  fill_stream_id(claims.stream_id);
  claims.stream_epoch = TEST_STREAM_EPOCH;
  claims.admission_generation = TEST_STREAM_EPOCH;
  if (mesh_mgmt_ed25519_public_from_private(INITIATOR_PRIVATE_KEY,
                                             claims.initiator_principal_key) !=
          MESH_MGMT_CRYPTO_OK ||
      mesh_mgmt_ed25519_public_from_private(RESPONDER_PRIVATE_KEY,
                                             claims.responder_principal_key) !=
          MESH_MGMT_CRYPTO_OK) {
    return -1;
  }
  if (mesh_stream_bind_store_init_v1(&state->bind_store, &store_config) != MESH_STREAM_BIND_OK)
    return -1;
  return mesh_stream_bind_ticket_issue_v1(&state->bind_store, &claims, TEST_AUTH_NOW_MS, 1000u,
                                          &state->bind_ticket) == MESH_STREAM_BIND_OK
             ? 0
             : -1;
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
  if (mesh_stream_frame_encode(&input, config->receiver.max_frame_size, output, capacity,
                               &output_len) != MESH_STREAM_CODEC_OK) {
    return 0u;
  }
  return output_len;
}

static int prepare_wire(coronet_stream_test_state_t *state) {
  uint8_t open_metadata[32];
  size_t metadata_len = 0u;
  size_t cursor = 0u;

  write_u16(open_metadata, 1u);
  write_u16(open_metadata + 2u, 1u);
  open_metadata[4] = MESH_STREAM_CLASS_MEDIA;
  write_u16(open_metadata + 5u, 2u);
  write_u16(open_metadata + 7u, 8u);
  write_u64(open_metadata + 9u, 12u);
  metadata_len = 17u;

  state->open_frame_len =
      encode_frame(&state->config, MESH_STREAM_FRAME_OPEN, 0u, 0u, 0u, open_metadata, metadata_len,
                   NULL, 0u, state->open_frame, sizeof(state->open_frame));
  state->first_data_frame_len =
      encode_frame(&state->config, MESH_STREAM_FRAME_DATA, 0u, 1u, 0u, NULL, 0u, TEST_PAYLOAD,
                   sizeof(TEST_PAYLOAD), state->first_data_frame, sizeof(state->first_data_frame));
  cursor += encode_frame(&state->config, MESH_STREAM_FRAME_DATA, MESH_STREAM_FLAG_END_STREAM, 2u,
                         6u, NULL, 0u, TEST_PAYLOAD, sizeof(TEST_PAYLOAD),
                         state->terminal_frames + cursor, sizeof(state->terminal_frames) - cursor);
  cursor += encode_frame(&state->config, MESH_STREAM_FRAME_CLOSE, 0u, 3u, 12u, REASON_NORMAL,
                         sizeof(REASON_NORMAL), NULL, 0u, state->terminal_frames + cursor,
                         sizeof(state->terminal_frames) - cursor);
  state->terminal_frames_len = cursor;
  return state->open_frame_len != 0u && state->first_data_frame_len != 0u &&
                 state->terminal_frames_len != 0u
             ? 0
             : -1;
}

static unsigned short pick_loopback_port(void) {
  unsigned short port = 0u;
  struct sockaddr_in address;
#ifdef _WIN32
  int address_len = (int)sizeof(address);
  SOCKET socket_handle = INVALID_SOCKET;
#else
  socklen_t address_len = (socklen_t)sizeof(address);
  int socket_handle = -1;
#endif

  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = htons(0u);
  socket_handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#ifdef _WIN32
  if (socket_handle == INVALID_SOCKET)
    return 0u;
#else
  if (socket_handle < 0)
    return 0u;
#endif
  if (bind(socket_handle, (struct sockaddr *)&address, sizeof(address)) == 0 &&
      getsockname(socket_handle, (struct sockaddr *)&address, &address_len) == 0) {
    port = ntohs(address.sin_port);
  }
#ifdef _WIN32
  closesocket(socket_handle);
#else
  close(socket_handle);
#endif
  return port;
}

static int receive_control(coro_socket_t *socket, const mesh_stream_transport_config_v1_t *config,
                           uint8_t expected_type, uint64_t expected_sequence,
                           uint64_t expected_offset) {
  uint8_t frame[MESH_STREAM_FIXED_HEADER_SIZE];
  size_t used = 0u;

  while (used < sizeof(frame)) {
    mesh_stream_frame_view_t view;
    char *chunk = NULL;
    size_t chunk_len = 0u;
    size_t consumed = 0u;
    size_t required = 0u;
    mesh_stream_codec_result_t decode_result;
    int recv_result = coro_socket_recv(socket, &chunk, &chunk_len);

    if (recv_result != 0 || !chunk || chunk_len == 0u || chunk_len > sizeof(frame) - used) {
      if (chunk)
        coro_socket_free_recv(chunk);
      return recv_result != 0 ? recv_result : -1;
    }
    memcpy(frame + used, chunk, chunk_len);
    used += chunk_len;
    coro_socket_free_recv(chunk);
    decode_result = mesh_stream_frame_decode(frame, used, config->receiver.max_frame_size, &view,
                                             &consumed, &required);
    if (decode_result == MESH_STREAM_CODEC_NEED_MORE)
      continue;
    if (decode_result != MESH_STREAM_CODEC_OK || consumed != used || view.type != expected_type ||
        view.sequence != expected_sequence || view.offset != expected_offset ||
        view.metadata_len != 0u || view.payload_len != 0u) {
      return -2;
    }
    return 0;
  }
  return -3;
}

static int accept_application_event(void *context, const mesh_stream_receive_event_v1_t *event) {
  coronet_stream_test_state_t *state = (coronet_stream_test_state_t *)context;

  state->event_count++;
  if (event->frame.type == MESH_STREAM_FRAME_DATA) {
    if (event->frame.payload_len != sizeof(TEST_PAYLOAD) ||
        memcmp(event->frame.payload, TEST_PAYLOAD, sizeof(TEST_PAYLOAD)) != 0) {
      return -1;
    }
    state->data_bytes += event->frame.payload_len;
  }
  return 0;
}

static int receive_exact(coro_socket_t *socket, uint8_t *output, size_t output_len) {
  size_t used = 0u;

  if (!socket || !output || output_len == 0u)
    return -1;
  while (used < output_len) {
    char *chunk = NULL;
    size_t chunk_len = 0u;
    int result = coro_socket_recv(socket, &chunk, &chunk_len);

    if (result != 0 || !chunk || chunk_len == 0u || chunk_len > output_len - used) {
      if (chunk)
        coro_socket_free_recv(chunk);
      return result != 0 ? result : -1;
    }
    memcpy(output + used, chunk, chunk_len);
    used += chunk_len;
    coro_socket_free_recv(chunk);
  }
  return 0;
}

static void server_task(coro_t *coroutine, void *argument) {
  coronet_stream_test_state_t *state = (coronet_stream_test_state_t *)argument;
  coro_socket_t *accepted = NULL;
  int result = 0;

  (void)coroutine;
  result = coro_socket_accept(state->server, &accepted);
  if (result != 0)
    goto cleanup;
  if (!accepted) {
    result = -1;
    goto cleanup;
  }
  coro_socket_set_timeout(accepted, TEST_IO_TIMEOUT_MS);
  result = coro_socket_send(accepted, (const char *)state->open_frame, 3u);
  if (result != 0)
    goto cleanup;
  result =
      coro_socket_send(accepted, (const char *)state->open_frame + 3u, state->open_frame_len - 3u);
  if (result != 0)
    goto cleanup;
  result = receive_control(accepted, &state->config, MESH_STREAM_FRAME_ACCEPT, 0u, 8u);
  state->accept_valid = result == 0;
  if (result != 0)
    goto cleanup;
  result = coro_socket_send(accepted, (const char *)state->first_data_frame,
                            state->first_data_frame_len);
  if (result != 0)
    goto cleanup;
  result = receive_control(accepted, &state->config, MESH_STREAM_FRAME_WINDOW_UPDATE, 1u, 12u);
  state->window_valid = result == 0;
  if (result != 0)
    goto cleanup;
  result =
      coro_socket_send(accepted, (const char *)state->terminal_frames, state->terminal_frames_len);

cleanup:
  state->server_result = result;
  if (accepted)
    coro_socket_destroy(accepted);
  state->server_done = 1;
}

static void client_task(coro_t *coroutine, void *argument) {
  coronet_stream_test_state_t *state = (coronet_stream_test_state_t *)argument;
  mesh_stream_registry_v1_t registry;
  mesh_stream_registry_config_v1_t registry_config;
  mesh_stream_channel_handle_v1_t handle;
  mesh_stream_channel_admission_v1_t admission = test_admission();
  mesh_stream_coronet_authorization_v1_t authorization = test_forged_authorization(&admission);
  coro_socket_t *client = NULL;
  mesh_stream_registry_result_t registry_result = MESH_STREAM_REGISTRY_OK;
  int result = 0;

  (void)coroutine;
  memset(&registry, 0, sizeof(registry));
  memset(&handle, 0, sizeof(handle));
  registry_config.capacity = 2u;
  registry_config.max_channels_per_peer = 2u;
  registry_config.owner_generation = TEST_STREAM_EPOCH;
  registry_result = mesh_stream_registry_init_v1(&registry, &registry_config);
  if (registry_result != MESH_STREAM_REGISTRY_OK) {
    result = registry_result;
    goto cleanup;
  }
  client = coro_socket_create_tcpv4(state->context);
  if (!client) {
    result = -1;
    goto cleanup;
  }
  coro_socket_set_timeout(client, TEST_IO_TIMEOUT_MS);
  result = coro_socket_connect(client, "127.0.0.1", state->port);
  if (result != 0)
    goto cleanup;
  registry_result = mesh_stream_registry_open_coronet_v1(
      &registry, &admission, &state->config, &authorization, TEST_AUTH_NOW_MS, client,
      accept_application_event, state, &handle);
  if (registry_result == MESH_STREAM_REGISTRY_AUTH_REQUIRED) {
    result = 0;
    goto cleanup;
  }
  if (registry_result != MESH_STREAM_REGISTRY_OK) {
    result = registry_result;
    goto cleanup;
  }
  result = -4;

cleanup:
  mesh_stream_registry_destroy_v1(&registry);
  if (client)
    coro_socket_destroy(client);
  state->client_result = result;
  state->client_done = 1;
}

static void secure_server_handler(coro_socket_t *client, void *argument) {
  coronet_stream_test_state_t *state = (coronet_stream_test_state_t *)argument;
  uint8_t init[MESH_STREAM_BIND_INIT_SIZE];
  uint8_t accept[MESH_STREAM_BIND_ACCEPT_SIZE];
  uint8_t confirm[MESH_STREAM_BIND_CONFIRM_SIZE];
  int result;

  coro_socket_set_timeout(client, TEST_IO_TIMEOUT_MS);
  result = receive_exact(client, init, sizeof(init));
  if (result == 0) {
    result = mesh_stream_bind_responder_accept_coronet_v1(
        &state->bind_store, init, sizeof(init), RESPONDER_PRIVATE_KEY, client,
        TEST_AUTH_NOW_MS, accept);
  }
  if (result == 0)
    result = receive_exact(client, confirm, sizeof(confirm));
  if (result == 0) {
    result = mesh_stream_bind_responder_finish_coronet_v1(
        &state->bind_store, confirm, sizeof(confirm), client, TEST_AUTH_NOW_MS,
        &state->server_authorization);
  }
  if (result == 0)
    result = coro_socket_send(client, (const char *)state->open_frame, state->open_frame_len);
  if (result == 0)
    result = receive_control(client, &state->config, MESH_STREAM_FRAME_ACCEPT, 0u, 8u);
  state->accept_valid = result == 0;
  if (result == 0) {
    result = coro_socket_send(client, (const char *)state->first_data_frame,
                              state->first_data_frame_len);
  }
  if (result == 0)
    result = receive_control(client, &state->config, MESH_STREAM_FRAME_WINDOW_UPDATE, 1u, 12u);
  state->window_valid = result == 0;
  if (result == 0) {
    result = coro_socket_send(client, (const char *)state->terminal_frames,
                              state->terminal_frames_len);
  }
  state->server_result = result;
  state->server_done = 1;
}

static void secure_client_task(coro_t *coroutine, void *argument) {
  coronet_stream_test_state_t *state = (coronet_stream_test_state_t *)argument;
  mesh_stream_registry_v1_t registry;
  mesh_stream_registry_config_v1_t registry_config;
  mesh_stream_registry_channel_info_v1_t channel_info;
  mesh_stream_channel_handle_v1_t handle;
  mesh_stream_channel_admission_v1_t admission = test_admission();
  mesh_stream_bind_initiator_v1_t initiator;
  uint8_t init[MESH_STREAM_BIND_INIT_SIZE];
  uint8_t accept[MESH_STREAM_BIND_ACCEPT_SIZE];
  uint8_t confirm[MESH_STREAM_BIND_CONFIRM_SIZE];
  coro_socket_t *client = NULL;
  mesh_stream_registry_result_t registry_result;
  int result = 0;

  (void)coroutine;
  memset(&registry, 0, sizeof(registry));
  memset(&handle, 0, sizeof(handle));
  memset(&initiator, 0, sizeof(initiator));
  registry_config.capacity = 2u;
  registry_config.max_channels_per_peer = 2u;
  registry_config.owner_generation = TEST_STREAM_EPOCH;
  registry_result = mesh_stream_registry_init_v1(&registry, &registry_config);
  if (registry_result != MESH_STREAM_REGISTRY_OK) {
    result = registry_result;
    goto cleanup;
  }
  client = coro_socket_create(state->context, CORO_SOCKET_TLS);
  if (!client) {
    result = -1;
    goto cleanup;
  }
  coro_socket_set_timeout(client, TEST_IO_TIMEOUT_MS);
  result = coro_socket_connect(client, "localhost", state->port);
  if (result == 0) {
    result = mesh_stream_bind_initiator_start_coronet_v1(
        &initiator, &state->bind_ticket, INITIATOR_PRIVATE_KEY, client, init);
  }
  if (result == 0)
    result = receive_exact(client, accept, sizeof(accept));
  if (result == 0) {
    result = mesh_stream_bind_initiator_confirm_coronet_v1(
        &initiator, accept, sizeof(accept), INITIATOR_PRIVATE_KEY, client, confirm,
        &state->client_authorization);
  }
  if (result != 0)
    goto cleanup;
  registry_result = mesh_stream_registry_open_coronet_v1(
      &registry, &admission, &state->config, &state->client_authorization,
      TEST_AUTH_NOW_MS, client, accept_application_event, state, &handle);
  if (registry_result != MESH_STREAM_REGISTRY_OK) {
    result = registry_result;
    goto cleanup;
  }
  registry_result = mesh_stream_registry_query_channel_v1(&registry, handle, &channel_info);
  if (registry_result != MESH_STREAM_REGISTRY_OK) {
    result = registry_result;
    goto cleanup;
  }
  while (channel_info.state == MESH_STREAM_CHANNEL_READY) {
    size_t frames = 0u;

    registry_result = mesh_stream_registry_pump_once_v1(&registry, handle, &frames);
    if (registry_result == MESH_STREAM_REGISTRY_INTERRUPTED)
      continue;
    if (registry_result != MESH_STREAM_REGISTRY_OK) {
      result = registry_result;
      break;
    }
    registry_result = mesh_stream_registry_query_channel_v1(&registry, handle, &channel_info);
    if (registry_result != MESH_STREAM_REGISTRY_OK) {
      result = registry_result;
      break;
    }
  }
  state->final_channel_state = channel_info.state;
  if (result == 0 && channel_info.state != MESH_STREAM_CHANNEL_CLOSED)
    result = -2;
  if (result == 0 &&
      mesh_stream_registry_release_v1(&registry, handle) != MESH_STREAM_REGISTRY_OK) {
    result = -3;
  }

cleanup:
  mesh_stream_registry_destroy_v1(&registry);
  if (client)
    coro_socket_destroy(client);
  state->client_result = result;
  state->client_done = 1;
}

static int tasks_done(const coronet_stream_test_state_t *state) {
  return state->server_done && state->client_done;
}

static int run_until_tasks_done(coronet_stream_test_state_t *state) {
  uint64_t deadline = turbo_monotonic_ms() + TEST_RUN_TIMEOUT_MS;

  while (!tasks_done(state) && turbo_monotonic_ms() < deadline)
    coro_context_run(state->context, TURBO_RUN_ONCE);
  return tasks_done(state) ? 0 : -1;
}

static int close_context(coronet_stream_test_state_t *state) {
  uint64_t deadline = turbo_monotonic_ms() + TEST_RUN_TIMEOUT_MS;
  int remaining;

  if (state->server) {
    coro_socket_destroy(state->server);
    state->server = NULL;
  }
  while (coro_context_alive(state->context) && turbo_monotonic_ms() < deadline) {
    coro_context_run(state->context, TURBO_RUN_NOWAIT);
  }
  remaining = coro_context_alive(state->context);
  coro_context_destroy(state->context);
  state->context = NULL;
  return remaining == 0 ? 0 : -1;
}

static void test_raw_tcp_cannot_enter_mesh_stream_registry(void) {
  coronet_stream_test_state_t state;
  struct sockaddr_in address;

  memset(&state, 0, sizeof(state));
  state.server_result = TEST_PENDING_RESULT;
  state.client_result = TEST_PENDING_RESULT;
  state.config = test_config();
  state.context = coro_context_create(NULL);
  check_not_null(state.context);
  state.port = pick_loopback_port();
  check_int_gt(state.port, 0);
  check_int_eq(prepare_wire(&state), 0);
  state.server = coro_socket_create_tcpv4(state.context);
  check_not_null(state.server);
  coro_socket_set_timeout(state.server, TEST_IO_TIMEOUT_MS);
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = htons(state.port);
  check_int_eq(coro_socket_bind(state.server, (struct sockaddr *)&address), 0);
  check_int_eq(coro_socket_listen(state.server, 4), 0);
  check_int_eq(coro_context_spawn(state.context, server_task, &state), 0);
  check_int_eq(coro_context_spawn(state.context, client_task, &state), 0);

  check_int_eq(run_until_tasks_done(&state), 0);
  check_int_eq(state.server_done, 1);
  check_int_eq(state.client_done, 1);
  check(state.server_result != 0);
  check_int_eq(state.client_result, 0);
  check_int_eq(state.accept_valid, 0);
  check_int_eq(state.window_valid, 0);
  check_size_eq(state.event_count, 0u);
  check_size_eq(state.data_bytes, 0u);
  check_int_eq(state.final_channel_state, MESH_STREAM_CHANNEL_UNINITIALIZED);
  check_int_eq(close_context(&state), 0);
}

static void test_raw_tcp_cannot_create_bind_or_transport(void) {
  coro_context_t *context = coro_context_create(NULL);
  coro_socket_t *socket;
  mesh_stream_bind_initiator_v1_t initiator;
  mesh_stream_bind_ticket_v1_t ticket;
  mesh_stream_transport_v1_t transport;
  mesh_stream_transport_config_v1_t config = test_config();
  uint8_t private_key[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE] = {0};
  uint8_t output[MESH_STREAM_BIND_INIT_SIZE];
  uint8_t zero[MESH_STREAM_BIND_INIT_SIZE] = {0};

  check_not_null(context);
  socket = coro_socket_create_tcpv4(context);
  check_not_null(socket);
  memset(&initiator, 0, sizeof(initiator));
  memset(&ticket, 0, sizeof(ticket));
  memset(&transport, 0, sizeof(transport));
  memset(output, 0xa5, sizeof(output));

  check_int_eq(mesh_stream_bind_initiator_start_coronet_v1(
                   &initiator, &ticket, private_key, socket, output),
               MESH_STREAM_BIND_TLS_REQUIRED);
  check_mem_eq(output, zero, sizeof(output));
  check_int_eq(mesh_stream_transport_init_coronet_v1(
                   &transport, &config, socket, accept_application_event, NULL),
               MESH_STREAM_TRANSPORT_SECURE_CHANNEL_REQUIRED);
  check_null(transport.buffer);

  coro_socket_destroy(socket);
  coro_context_destroy(context);
}

static void test_tls_bind_authorizes_registry_stream(void) {
  coronet_stream_test_state_t state;

  memset(&state, 0, sizeof(state));
  state.server_result = TEST_PENDING_RESULT;
  state.client_result = TEST_PENDING_RESULT;
  state.config = test_config();
  check_int_eq(set_tls_test_environment(), 0);
  check_int_eq(turbo_stream_tls_set_protocol_mode(TURBO_TLS_PROTOCOL_TLS13_ONLY), 0);
  check_int_eq(prepare_bind_ticket(&state), 0);
  state.context = coro_context_create(NULL);
  check_not_null(state.context);
  state.port = pick_loopback_port();
  check_int_gt(state.port, 0);
  check_int_eq(prepare_wire(&state), 0);
  state.server = coro_socket_create(state.context, CORO_SOCKET_TLS);
  check_not_null(state.server);
  coro_socket_set_timeout(state.server, TEST_IO_TIMEOUT_MS);
  check_int_eq(coro_socket_listen_on(state.server, "127.0.0.1", state.port,
                                     secure_server_handler, &state),
               0);
  check_int_eq(coro_context_spawn(state.context, secure_client_task, &state), 0);

  check_int_eq(run_until_tasks_done(&state), 0);
  check_int_eq(state.server_result, 0);
  check_int_eq(state.client_result, 0);
  check_int_eq(state.server_authorization.authenticated, 1);
  check_int_eq(state.client_authorization.authenticated, 1);
  check_mem_eq(state.server_authorization.channel_binding,
               state.client_authorization.channel_binding,
               MESH_STREAM_BIND_CHANNEL_BINDING_SIZE);
  check_int_eq(state.accept_valid, 1);
  check_int_eq(state.window_valid, 1);
  check_size_eq(state.event_count, 4u);
  check_size_eq(state.data_bytes, 12u);
  check_int_eq(state.final_channel_state, MESH_STREAM_CHANNEL_CLOSED);
  check_int_eq(close_context(&state), 0);

  mesh_stream_coronet_authorization_clear_v1(&state.client_authorization);
  mesh_stream_coronet_authorization_clear_v1(&state.server_authorization);
  mesh_stream_bind_store_destroy_v1(&state.bind_store);
  (void)turbo_stream_tls_set_protocol_mode(TURBO_TLS_PROTOCOL_DEFAULT);
  turbo_stream_tls_reset_client_session_cache();
  turbo_stream_tls_global_cleanup();
  turbo_stream_tls_thread_cleanup();
  clear_tls_test_environment();
}

spec("mesh stream CoroNet integration") {
  describe("secure transport boundary") {
    it("admits a registry stream only after TLS-bound mutual authentication") {
      test_tls_bind_authorizes_registry_stream();
    }
    it("rejects raw TCP before a registry channel is admitted") {
      test_raw_tcp_cannot_enter_mesh_stream_registry();
    }
    it("rejects raw TCP before bind or transport state is created") {
      test_raw_tcp_cannot_create_bind_or_transport();
    }
  }
}
