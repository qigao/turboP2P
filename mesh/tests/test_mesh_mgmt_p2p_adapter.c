#include <tinytest.h>

#include "mesh_mgmt_agent_router.h"
#include "mesh_mgmt_agent_runtime.h"
#include "mesh_mgmt_crypto.h"
#include "mesh_mgmt_endpoint_pool.h"
#include "mesh_mgmt_execution_wire.h"
#include "mesh_mgmt_mesh_bridge.h"
#include "mesh_mgmt_p2p_peer.h"

#include <CoroNet.h>

#include <stdio.h>
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

#define TEST_CONNECT_TIMEOUT_MS 8000u
#define TEST_FRAME_CAPACITY 256u
#define TEST_NOW_MS 100000u

static const uint8_t CAPACITY_PROBE_KEY[P2P_KEY_SIZE] = {
    0xa1u, 0xa2u, 0xa3u, 0xa4u, 0xa5u, 0xa6u, 0xa7u, 0xa8u,
    0xa9u, 0xaau, 0xabu, 0xacu, 0xadu, 0xaeu, 0xafu, 0xb0u,
    0xb1u, 0xb2u, 0xb3u, 0xb4u, 0xb5u, 0xb6u, 0xb7u, 0xb8u,
    0xb9u, 0xbau, 0xbbu, 0xbcu, 0xbdu, 0xbeu, 0xbfu, 0xc0u,
};
static const uint8_t TEST_P2P_NETWORK_ID[P2P_SECURITY_ID_SIZE] = {
    0x4d, 0x4d, 0x50, 0x2d, 0x50, 0x32, 0x50, 0x2d,
    0x54, 0x65, 0x73, 0x74, 0x2d, 0x4e, 0x65, 0x74,
    0x77, 0x6f, 0x72, 0x6b, 0x2d, 0x76, 0x32, 0x2d,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31,
};

static void test_bytes_to_hex(const uint8_t *bytes, size_t length,
                              char *output) {
  static const char hex[] = "0123456789abcdef";
  size_t index;

  for (index = 0; index < length; ++index) {
    output[index * 2u] = hex[bytes[index] >> 4];
    output[index * 2u + 1u] = hex[bytes[index] & 0x0fu];
  }
  output[length * 2u] = '\0';
}

typedef struct {
  p2p_node_t *node1;
  p2p_node_t *node2;
  p2p_peer_t *node1_peer;
  p2p_peer_t *node2_peer;
  mesh_mgmt_p2p_peer_v1_t *runtime1;
  mesh_mgmt_p2p_peer_v1_t *runtime2;
  mesh_mgmt_p2p_peer_result_t runtime1_result;
  mesh_mgmt_p2p_peer_result_t runtime2_result;
  uint8_t received[TEST_FRAME_CAPACITY];
  size_t received_len;
} p2p_adapter_test_state_t;

typedef struct {
  uint8_t next_message_byte;
  int random_result;
  size_t event_count;
  int last_event_type;
} runtime_callbacks_t;

typedef struct {
  p2p_peer_t *peer;
  uint8_t remote_transport_peer_id[P2P_KEY_SIZE];
  uint8_t next_namespace_byte;
  size_t event_count;
  int last_event_type;
  size_t non_mmp_count;
  size_t failure_count;
  mesh_mgmt_agent_router_result_t last_router_failure;
  mesh_mgmt_p2p_peer_result_t last_peer_failure;
  mesh_mgmt_endpoint_pool_v1_t *endpoint_pool;
  mesh_mgmt_endpoint_pool_result_t last_endpoint_result;
  mesh_mgmt_agent_router_close_reason_t last_close_reason;
  size_t close_count;
  size_t admission_count;
} router_callbacks_t;

static int pick_loopback_ports(unsigned short *out_port1, unsigned short *out_port2) {
  struct sockaddr_in address1;
  struct sockaddr_in address2;
#ifdef _WIN32
  int address1_len = (int)sizeof(address1);
  int address2_len = (int)sizeof(address2);
  SOCKET socket1 = INVALID_SOCKET;
  SOCKET socket2 = INVALID_SOCKET;
  WSADATA winsock_data;
#else
  socklen_t address1_len = (socklen_t)sizeof(address1);
  socklen_t address2_len = (socklen_t)sizeof(address2);
  int socket1 = -1;
  int socket2 = -1;
#endif

  if (!out_port1 || !out_port2)
    return -1;
  *out_port1 = 0u;
  *out_port2 = 0u;
  memset(&address1, 0, sizeof(address1));
  memset(&address2, 0, sizeof(address2));
  address1.sin_family = AF_INET;
  address1.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address2.sin_family = AF_INET;
  address2.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#ifdef _WIN32
  if (WSAStartup(MAKEWORD(2, 2), &winsock_data) != 0)
    return -1;
#endif
  socket1 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  socket2 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#ifdef _WIN32
  if (socket1 == INVALID_SOCKET || socket2 == INVALID_SOCKET)
    goto cleanup;
#else
  if (socket1 < 0 || socket2 < 0)
    goto cleanup;
#endif
  if (bind(socket1, (struct sockaddr *)&address1, sizeof(address1)) != 0 ||
      getsockname(socket1, (struct sockaddr *)&address1, &address1_len) != 0 ||
      bind(socket2, (struct sockaddr *)&address2, sizeof(address2)) != 0 ||
      getsockname(socket2, (struct sockaddr *)&address2, &address2_len) != 0)
    goto cleanup;
  *out_port1 = ntohs(address1.sin_port);
  *out_port2 = ntohs(address2.sin_port);

cleanup:
#ifdef _WIN32
  if (socket2 != INVALID_SOCKET)
    closesocket(socket2);
  if (socket1 != INVALID_SOCKET)
    closesocket(socket1);
  WSACleanup();
#else
  if (socket2 >= 0)
    close(socket2);
  if (socket1 >= 0)
    close(socket1);
#endif
  return *out_port1 != 0u && *out_port2 != 0u && *out_port1 != *out_port2 ? 0 : -1;
}

static size_t encode_test_frame(uint8_t *output, size_t capacity) {
  mesh_mgmt_frame_input_t input;
  uint8_t signature[MESH_MGMT_SIGNATURE_SIZE];
  size_t output_len = 0u;

  memset(&input, 0, sizeof(input));
  memset(signature, 0x5au, sizeof(signature));
  input.major = MESH_MGMT_MAJOR_V1;
  input.minor = MESH_MGMT_MINOR_V1;
  input.kind = MESH_MGMT_KIND_ERROR;
  input.signature = signature;
  if (mesh_mgmt_frame_encode(&input, output, capacity, &output_len) != MESH_MGMT_CODEC_OK)
    return 0u;
  return output_len;
}

static void node1_connected(p2p_peer_t *peer, void *context) {
  ((p2p_adapter_test_state_t *)context)->node1_peer = peer;
}

static void node2_connected(p2p_peer_t *peer, void *context) {
  ((p2p_adapter_test_state_t *)context)->node2_peer = peer;
}

static void peer_disconnected(p2p_peer_t *peer, void *context) {
  p2p_adapter_test_state_t *state = (p2p_adapter_test_state_t *)context;

  if (state->node1_peer == peer)
    state->node1_peer = NULL;
  if (state->node2_peer == peer)
    state->node2_peer = NULL;
}

static void node1_message(p2p_node_t *node, p2p_peer_t *peer, const void *bytes, size_t length,
                          void *context) {
  p2p_adapter_test_state_t *state = (p2p_adapter_test_state_t *)context;

  (void)node;
  (void)peer;
  if (state->runtime1) {
    state->runtime1_result =
        mesh_mgmt_p2p_peer_handle_message_v1(state->runtime1, bytes, length, TEST_NOW_MS);
  }
}

static void node2_message(p2p_node_t *node, p2p_peer_t *peer, const void *bytes, size_t length,
                          void *context) {
  p2p_adapter_test_state_t *state = (p2p_adapter_test_state_t *)context;

  (void)node;
  (void)peer;
  if (state->runtime2) {
    state->runtime2_result =
        mesh_mgmt_p2p_peer_handle_message_v1(state->runtime2, bytes, length, TEST_NOW_MS);
  }
  if (length <= sizeof(state->received)) {
    memcpy(state->received, bytes, length);
    state->received_len = length;
  }
}

static int pump_until_connected(p2p_adapter_test_state_t *state) {
  uint64_t deadline = turbo_monotonic_ms() + TEST_CONNECT_TIMEOUT_MS;

  while ((!state->node1_peer || !state->node2_peer) && turbo_monotonic_ms() < deadline) {
    coro_context_run(p2p_get_loop(state->node1), TURBO_RUN_NOWAIT);
    coro_context_run(p2p_get_loop(state->node2), TURBO_RUN_NOWAIT);
    turbo_sleep_ms(1u);
  }
  return state->node1_peer && state->node2_peer ? 0 : -1;
}

static int pump_until_received(p2p_adapter_test_state_t *state) {
  uint64_t deadline = turbo_monotonic_ms() + TEST_CONNECT_TIMEOUT_MS;

  while (state->received_len == 0u && turbo_monotonic_ms() < deadline) {
    coro_context_run(p2p_get_loop(state->node1), TURBO_RUN_NOWAIT);
    coro_context_run(p2p_get_loop(state->node2), TURBO_RUN_NOWAIT);
    turbo_sleep_ms(1u);
  }
  return state->received_len > 0u ? 0 : -1;
}

static int create_nodes(p2p_adapter_test_state_t *state, unsigned short *out_node1_port) {
  static const uint8_t NODE1_KEY[P2P_KEY_SIZE] = {
      1u,  2u,  3u,  4u,  5u,  6u,  7u,  8u,  9u,  10u, 11u, 12u, 13u, 14u, 15u, 16u,
      17u, 18u, 19u, 20u, 21u, 22u, 23u, 24u, 25u, 26u, 27u, 28u, 29u, 30u, 31u, 32u,
  };
  static const uint8_t NODE2_KEY[P2P_KEY_SIZE] = {
      32u, 31u, 30u, 29u, 28u, 27u, 26u, 25u, 24u, 23u, 22u, 21u, 20u, 19u, 18u, 17u,
      16u, 15u, 14u, 13u, 12u, 11u, 10u, 9u,  8u,  7u,  6u,  5u,  4u,  3u,  2u,  1u,
  };
  unsigned short port1;
  unsigned short port2;
  uint8_t trusted_keys[3 * P2P_KEY_SIZE];

  if (!state || !out_node1_port || pick_loopback_ports(&port1, &port2) != 0)
    return -11;
  state->node1 = p2p_create("127.0.0.1", (int)port1);
  state->node2 = p2p_create("127.0.0.1", (int)port2);
  if (!state->node1 || !state->node2)
    return -12;
  if (p2p_node_set_private_key(state->node1, NODE1_KEY) != P2P_OK ||
      p2p_node_set_private_key(state->node2, NODE2_KEY) != P2P_OK)
    return -13;
  if (p2p_node_get_public_key(state->node1, trusted_keys) != P2P_OK ||
      p2p_node_get_public_key(state->node2,
                              trusted_keys + P2P_KEY_SIZE) != P2P_OK ||
      p2p_public_key_from_private_key(CAPACITY_PROBE_KEY,
                                      trusted_keys + 2u * P2P_KEY_SIZE) !=
          P2P_OK ||
      p2p_node_configure_pinned_security_v2(state->node1, TEST_P2P_NETWORK_ID,
                                            trusted_keys, 3u) != P2P_OK ||
      p2p_node_configure_pinned_security_v2(state->node2, TEST_P2P_NETWORK_ID,
                                            trusted_keys, 3u) != P2P_OK)
    return -18;
  memset(trusted_keys, 0, sizeof(trusted_keys));
  *out_node1_port = port1;
  return 0;
}

static int start_nodes(p2p_adapter_test_state_t *state) {
  unsigned short port1;

  if (create_nodes(state, &port1) != 0)
    return -11;

  p2p_set_peer_callbacks(state->node1, node1_connected, peer_disconnected, state);
  p2p_set_peer_callbacks(state->node2, node2_connected, peer_disconnected, state);
  p2p_set_message_handler(state->node1, node1_message, state);
  p2p_set_message_handler(state->node2, node2_message, state);
  if (p2p_start_nonblocking(state->node1) != P2P_OK)
    return -14;
  if (p2p_start_nonblocking(state->node2) != P2P_OK)
    return -15;
  if (p2p_connect(state->node2, "127.0.0.1", (int)port1) != P2P_OK)
    return -16;
  return pump_until_connected(state) == 0 ? 0 : -17;
}

static uint64_t runtime_now_ms(void *context) {
  (void)context;
  return TEST_NOW_MS;
}

static int runtime_random_bytes(void *context, uint8_t *output, size_t output_len) {
  runtime_callbacks_t *callbacks = (runtime_callbacks_t *)context;
  size_t index;

  if (callbacks->random_result != 0)
    return callbacks->random_result;
  for (index = 0u; index < output_len; index++)
    output[index] = (uint8_t)(callbacks->next_message_byte + index);
  callbacks->next_message_byte = (uint8_t)(callbacks->next_message_byte + 0x20u);
  return 0;
}

static int runtime_event(void *context, const mesh_mgmt_dispatch_event_v1_t *event) {
  runtime_callbacks_t *callbacks = (runtime_callbacks_t *)context;

  if (!callbacks || !event)
    return -1;
  callbacks->event_count++;
  callbacks->last_event_type = event->type;
  return 0;
}

static void fill_execution_bytes(uint8_t *bytes, size_t size, uint8_t first) {
  size_t index;

  for (index = 0u; index < size; ++index)
    bytes[index] = (uint8_t)(first + index);
}

static size_t make_p2p_execution_request(
    const mesh_mgmt_p2p_peer_config_v1_t *origin,
    const mesh_mgmt_p2p_peer_config_v1_t *target,
    const uint8_t issuer_private_key[32],
    uint8_t output[MESH_MGMT_EXECUTION_COMMAND_REQUEST_MAX_SIZE_V1]) {
  mesh_mgmt_execution_grant_v1_t grant;
  mesh_mgmt_execution_request_v1_t request;
  uint8_t subject_public_key[32];
  size_t output_size = 0u;

  memset(&grant, 0, sizeof(grant));
  memset(&request, 0, sizeof(request));
  check_int_eq(mesh_mgmt_ed25519_public_from_private(
                   origin->signer.private_key, subject_public_key),
               MESH_MGMT_CRYPTO_OK);
  grant.version = MESH_MGMT_EXECUTION_SCHEMA_V1;
  fill_execution_bytes(grant.grant_id, sizeof(grant.grant_id), 0x11u);
  memset(grant.mesh_id, 0x42, sizeof(grant.mesh_id));
  grant.policy_epoch = 1u;
  memcpy(grant.subject_principal, subject_public_key,
         sizeof(grant.subject_principal));
  memcpy(grant.target_node_id, target->signer.hello.managed_node_id,
         sizeof(grant.target_node_id));
  fill_execution_bytes(grant.deployment_id, sizeof(grant.deployment_id),
                       0x21u);
  grant.deployment_generation = 1u;
  fill_execution_bytes(grant.package_digest, sizeof(grant.package_digest),
                       0x31u);
  grant.operation = MESH_MGMT_EXECUTION_OPERATION_RUN_PRESTAGED_WASM;
  grant.capabilities = MESH_MGMT_EXECUTION_CAP_CORE;
  grant.max_limits.module_bytes = 1024u;
  grant.max_limits.stack_bytes = 1024u;
  grant.max_limits.linear_memory_bytes = 4096u;
  grant.max_limits.timeout_ms = 100u;
  grant.max_limits.control_flow_steps = 1000u;
  grant.max_limits.host_calls = 4u;
  grant.max_limits.copied_guest_bytes = 1024u;
  grant.max_limits.input_bytes = 64u;
  grant.max_limits.stdout_bytes = 64u;
  grant.max_limits.stderr_bytes = 64u;
  grant.not_before_ms = TEST_NOW_MS - 1u;
  grant.expires_at_ms = TEST_NOW_MS + 1000u;
  check_int_eq(mesh_mgmt_execution_grant_sign_v1(
                   &grant, issuer_private_key),
               MESH_MGMT_EXECUTION_WIRE_OK);

  request.version = MESH_MGMT_EXECUTION_SCHEMA_V1;
  fill_execution_bytes(request.command_id, sizeof(request.command_id), 0x41u);
  memcpy(request.grant_id, grant.grant_id, sizeof(request.grant_id));
  memcpy(request.target_node_id, grant.target_node_id,
         sizeof(request.target_node_id));
  memcpy(request.deployment_id, grant.deployment_id,
         sizeof(request.deployment_id));
  request.deployment_generation = grant.deployment_generation;
  memcpy(request.package_digest, grant.package_digest,
         sizeof(request.package_digest));
  request.input_kind = MESH_MGMT_EXECUTION_INPUT_NONE;
  request.output_mode = MESH_MGMT_EXECUTION_OUTPUT_NONE;
  request.deadline_ms = TEST_NOW_MS + 1000u;
  fill_execution_bytes(request.request_nonce, sizeof(request.request_nonce),
                       0x51u);
  fill_execution_bytes(request.correlation_id,
                       sizeof(request.correlation_id), 0x61u);
  check_int_eq(mesh_mgmt_execution_command_request_encode_v1(
                   &grant, &request, output,
                   MESH_MGMT_EXECUTION_COMMAND_REQUEST_MAX_SIZE_V1,
                   &output_size),
               MESH_MGMT_EXECUTION_WIRE_OK);
  return output_size;
}

static int pump_until_execution_request(
    p2p_adapter_test_state_t *state, const runtime_callbacks_t *callbacks) {
  uint64_t deadline = turbo_monotonic_ms() + TEST_CONNECT_TIMEOUT_MS;

  while (callbacks->last_event_type !=
             MESH_MGMT_DISPATCH_EVENT_NODE_EXECUTION_REQUEST_SHADOW &&
         turbo_monotonic_ms() < deadline) {
    coro_context_run(p2p_get_loop(state->node1), TURBO_RUN_NOWAIT);
    coro_context_run(p2p_get_loop(state->node2), TURBO_RUN_NOWAIT);
    turbo_sleep_ms(1u);
  }
  return callbacks->last_event_type ==
                 MESH_MGMT_DISPATCH_EVENT_NODE_EXECUTION_REQUEST_SHADOW
             ? 0
             : -1;
}

static int pump_until_router_event(
    p2p_adapter_test_state_t *state,
    const router_callbacks_t *callbacks,
    int event_type) {
  uint64_t deadline = turbo_monotonic_ms() + TEST_CONNECT_TIMEOUT_MS;

  while (callbacks->last_event_type != event_type &&
         turbo_monotonic_ms() < deadline) {
    coro_context_run(p2p_get_loop(state->node1), TURBO_RUN_NOWAIT);
    coro_context_run(p2p_get_loop(state->node2), TURBO_RUN_NOWAIT);
    turbo_sleep_ms(1u);
  }
  return callbacks->last_event_type == event_type ? 0 : -1;
}

static int router_namespace_random(void *context, uint8_t *output, size_t output_len) {
  router_callbacks_t *callbacks = (router_callbacks_t *)context;
  size_t index;

  if (!callbacks || !output)
    return -1;
  for (index = 0u; index < output_len; index++)
    output[index] = (uint8_t)(callbacks->next_namespace_byte + index);
  callbacks->next_namespace_byte = (uint8_t)(callbacks->next_namespace_byte + 0x20u);
  return 0;
}

static int router_zero_random(void *context, uint8_t *output, size_t output_len) {
  (void)context;
  memset(output, 0, output_len);
  return 0;
}

static int router_event(void *context, p2p_peer_t *peer,
                        const uint8_t remote_transport_peer_id[P2P_KEY_SIZE],
                        const mesh_mgmt_dispatch_event_v1_t *event) {
  router_callbacks_t *callbacks = (router_callbacks_t *)context;

  if (!callbacks || !peer || !remote_transport_peer_id || !event)
    return -1;
  callbacks->peer = peer;
  memcpy(callbacks->remote_transport_peer_id, remote_transport_peer_id,
         sizeof(callbacks->remote_transport_peer_id));
  callbacks->event_count++;
  callbacks->last_event_type = event->type;
  if (callbacks->endpoint_pool && event->type == MESH_MGMT_DISPATCH_EVENT_SESSION_ESTABLISHED) {
    callbacks->last_endpoint_result = mesh_mgmt_endpoint_pool_mark_authenticated_v1(
        callbacks->endpoint_pool, remote_transport_peer_id, turbo_monotonic_ms());
    if (callbacks->last_endpoint_result != MESH_MGMT_ENDPOINT_POOL_OK &&
        callbacks->last_endpoint_result != MESH_MGMT_ENDPOINT_POOL_NOT_FOUND) {
      return -1;
    }
  }
  return 0;
}

static int router_admit_peer(void *context, p2p_peer_t *peer,
                             const uint8_t remote_transport_peer_id[P2P_KEY_SIZE],
                             const mesh_mgmt_dispatch_event_v1_t *event) {
  router_callbacks_t *callbacks = (router_callbacks_t *)context;

  if (!callbacks || !peer || !remote_transport_peer_id || !event ||
      event->type != MESH_MGMT_DISPATCH_EVENT_SESSION_ESTABLISHED)
    return -1;
  callbacks->admission_count++;
  return 0;
}

static void router_non_mmp(void *context, p2p_node_t *node, p2p_peer_t *peer, const void *bytes,
                           size_t length) {
  router_callbacks_t *callbacks = (router_callbacks_t *)context;

  if (callbacks && node && peer && bytes && length > 0u)
    callbacks->non_mmp_count++;
}

static void router_failure(void *context, p2p_peer_t *peer,
                           mesh_mgmt_agent_router_result_t router_result,
                           mesh_mgmt_p2p_peer_result_t peer_result) {
  router_callbacks_t *callbacks = (router_callbacks_t *)context;

  (void)peer;
  if (!callbacks)
    return;
  callbacks->failure_count++;
  callbacks->last_router_failure = router_result;
  callbacks->last_peer_failure = peer_result;
}

static void router_peer_closed(void *context, p2p_peer_t *peer,
                               const uint8_t remote_transport_peer_id[P2P_KEY_SIZE],
                               mesh_mgmt_agent_router_close_reason_t reason) {
  router_callbacks_t *callbacks = (router_callbacks_t *)context;

  (void)peer;
  if (!callbacks || !remote_transport_peer_id)
    return;
  callbacks->close_count++;
  callbacks->last_close_reason = reason;
  if (callbacks->endpoint_pool) {
    mesh_mgmt_endpoint_failure_t failure = reason == MESH_MGMT_AGENT_ROUTER_CLOSE_PROTOCOL
                                               ? MESH_MGMT_ENDPOINT_FAILURE_PROTOCOL
                                               : MESH_MGMT_ENDPOINT_FAILURE_TRANSPORT;
    callbacks->last_endpoint_result = mesh_mgmt_endpoint_pool_mark_failed_v1(
        callbacks->endpoint_pool, remote_transport_peer_id, failure, turbo_monotonic_ms());
  }
}

static int prepare_runtime_config(mesh_mgmt_p2p_peer_config_v1_t *config, p2p_node_t *node,
                                  p2p_peer_t *peer, const uint8_t transport_peer_id[P2P_KEY_SIZE],
                                  const uint8_t management_private_key[32], uint8_t node_byte,
                                  uint8_t connection_byte, uint8_t session_byte, uint64_t serial,
                                  runtime_callbacks_t *callbacks) {
  static const uint8_t ISSUER_PRIVATE_KEY[32] = {
      0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a,
      0xf4, 0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32,
      0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
  };
  mesh_mgmt_certificate_claims_v1_t claims;
  uint8_t issuer_public_key[32];
  uint8_t management_public_key[32];
  uint8_t mesh_id_hash[32];
  uint8_t issuer_hash[32];
  size_t certificate_len = 0u;

  memset(config, 0, sizeof(*config));
  memset(&claims, 0, sizeof(claims));
  memset(mesh_id_hash, 0x42, sizeof(mesh_id_hash));
  if (mesh_mgmt_ed25519_public_from_private(ISSUER_PRIVATE_KEY, issuer_public_key) !=
          MESH_MGMT_CRYPTO_OK ||
      mesh_mgmt_ed25519_public_from_private(management_private_key, management_public_key) !=
          MESH_MGMT_CRYPTO_OK ||
      mesh_mgmt_blake2b_256(issuer_public_key, sizeof(issuer_public_key), issuer_hash) !=
          MESH_MGMT_CRYPTO_OK) {
    return -1;
  }

  claims.principal_type = MESH_MGMT_PRINCIPAL_NODE;
  memcpy(claims.management_key, management_public_key, sizeof(claims.management_key));
  memcpy(claims.transport_peer_id, transport_peer_id, sizeof(claims.transport_peer_id));
  memset(claims.managed_node_id, node_byte, sizeof(claims.managed_node_id));
  memcpy(claims.mesh_id_hash, mesh_id_hash, sizeof(claims.mesh_id_hash));
  claims.roles = MESH_MGMT_ROLE_OPERATOR;
  claims.not_before_ms = TEST_NOW_MS - 1000u;
  claims.expires_at_ms = TEST_NOW_MS + 60000u;
  claims.serial = serial;
  claims.principal_epoch = 1u;

  config->node = node;
  config->peer = peer;
  memcpy(config->signer.private_key, management_private_key, sizeof(config->signer.private_key));
  memcpy(config->signer.trusted_issuer_key, issuer_public_key,
         sizeof(config->signer.trusted_issuer_key));
  memcpy(config->signer.expected_mesh_id_hash, mesh_id_hash,
         sizeof(config->signer.expected_mesh_id_hash));
  memcpy(config->signer.local_transport_peer_id, transport_peer_id,
         sizeof(config->signer.local_transport_peer_id));
  config->signer.hello.major = MESH_MGMT_MAJOR_V1;
  config->signer.hello.min_minor = MESH_MGMT_MINOR_V1;
  config->signer.hello.max_minor = MESH_MGMT_MINOR_V1;
  config->signer.hello.features = MESH_MGMT_FEATURE_MEMBERSHIP;
  config->signer.hello.platform = MESH_MGMT_PLATFORM_OTHER;
  memcpy(config->signer.hello.build_version, "p2p-test", 8u);
  config->signer.hello.build_version_len = 8u;
  if (mesh_mgmt_certificate_issue_v1(&claims, ISSUER_PRIVATE_KEY, config->signer.hello.certificate,
                                     sizeof(config->signer.hello.certificate),
                                     &certificate_len) != MESH_MGMT_IDENTITY_OK ||
      certificate_len != sizeof(config->signer.hello.certificate)) {
    return -1;
  }
  memcpy(config->signer.hello.issuer_chain_hash, issuer_hash,
         sizeof(config->signer.hello.issuer_chain_hash));
  config->signer.hello.principal_type = MESH_MGMT_PRINCIPAL_NODE;
  memcpy(config->signer.hello.management_key, management_public_key,
         sizeof(config->signer.hello.management_key));
  memcpy(config->signer.hello.managed_node_id, claims.managed_node_id,
         sizeof(config->signer.hello.managed_node_id));
  memset(config->signer.hello.connection_id, connection_byte,
         sizeof(config->signer.hello.connection_id));
  config->signer.hello.max_frame = MESH_MGMT_SESSION_MIN_FRAME;
  config->signer.hello.max_digest_entries = 8u;
  config->signer.hello.max_delta_batch = 4u;
  memset(config->signer.session_id, session_byte, sizeof(config->signer.session_id));
  config->signer.incarnation = 1u;
  config->signer.first_sequence = 1u;
  config->signer.frame_ttl_ms = 1000u;
  config->signer.now_ms = runtime_now_ms;
  config->signer.random_bytes = runtime_random_bytes;
  config->signer.callback_context = callbacks;

  memcpy(config->dispatch.session.expected_mesh_id_hash, mesh_id_hash,
         sizeof(config->dispatch.session.expected_mesh_id_hash));
  memcpy(config->dispatch.session.trusted_issuer_key, issuer_public_key,
         sizeof(config->dispatch.session.trusted_issuer_key));
  config->dispatch.session.min_minor = MESH_MGMT_MINOR_V1;
  config->dispatch.session.max_minor = MESH_MGMT_MINOR_V1;
  config->dispatch.session.features = MESH_MGMT_FEATURE_MEMBERSHIP;
  memcpy(config->dispatch.session.connection_id, config->signer.hello.connection_id,
         sizeof(config->dispatch.session.connection_id));
  config->dispatch.session.max_frame = MESH_MGMT_SESSION_MIN_FRAME;
  config->dispatch.session.max_digest_entries = 8u;
  config->dispatch.session.max_delta_batch = 4u;
  config->dispatch.replay.capacity = 8u;
  config->dispatch.replay.ttl_ms = 2000u;
  config->on_event = runtime_event;
  config->event_context = callbacks;
  return 0;
}

static int pump_until_established(p2p_adapter_test_state_t *state) {
  uint64_t deadline = turbo_monotonic_ms() + TEST_CONNECT_TIMEOUT_MS;

  while (turbo_monotonic_ms() < deadline) {
    mesh_mgmt_session_state_t state1;
    mesh_mgmt_session_state_t state2;

    coro_context_run(p2p_get_loop(state->node1), TURBO_RUN_NOWAIT);
    coro_context_run(p2p_get_loop(state->node2), TURBO_RUN_NOWAIT);
    state1 = state->runtime1->protocol_peer.connection.dispatcher.session.state;
    state2 = state->runtime2->protocol_peer.connection.dispatcher.session.state;
    if (state1 == MESH_MGMT_SESSION_ESTABLISHED && state2 == MESH_MGMT_SESSION_ESTABLISHED)
      return 0;
    if (state->runtime1->state == MESH_MGMT_P2P_PEER_TERMINAL)
      return -2;
    if (state->runtime2->state == MESH_MGMT_P2P_PEER_TERMINAL)
      return -3;
    turbo_sleep_ms(1u);
  }
  return -4;
}

static void stop_nodes(p2p_adapter_test_state_t *state) {
  if (state->node2)
    p2p_destroy(state->node2);
  if (state->node1)
    p2p_destroy(state->node1);
  state->node1 = NULL;
  state->node2 = NULL;
  state->node1_peer = NULL;
  state->node2_peer = NULL;
}

static int pump_until_router_established(p2p_adapter_test_state_t *state,
                                         mesh_mgmt_agent_router_v1_t *router1,
                                         mesh_mgmt_agent_router_v1_t *router2,
                                         router_callbacks_t *callbacks1,
                                         router_callbacks_t *callbacks2) {
  uint64_t deadline = turbo_monotonic_ms() + TEST_CONNECT_TIMEOUT_MS;

  while (turbo_monotonic_ms() < deadline) {
    mesh_mgmt_agent_router_peer_snapshot_v1_t snapshot1;
    mesh_mgmt_agent_router_peer_snapshot_v1_t snapshot2;

    coro_context_run(p2p_get_loop(state->node1), TURBO_RUN_NOWAIT);
    coro_context_run(p2p_get_loop(state->node2), TURBO_RUN_NOWAIT);
    if (callbacks1->peer && callbacks2->peer &&
        mesh_mgmt_agent_router_peer_snapshot_v1(router1, callbacks1->peer, &snapshot1) ==
            MESH_MGMT_AGENT_ROUTER_OK &&
        mesh_mgmt_agent_router_peer_snapshot_v1(router2, callbacks2->peer, &snapshot2) ==
            MESH_MGMT_AGENT_ROUTER_OK &&
        snapshot1.session_state == MESH_MGMT_SESSION_ESTABLISHED &&
        snapshot2.session_state == MESH_MGMT_SESSION_ESTABLISHED) {
      return 0;
    }
    if (callbacks1->failure_count != 0u || callbacks2->failure_count != 0u)
      return -2;
    turbo_sleep_ms(1u);
  }
  return -1;
}

static int pump_until_router_non_mmp(p2p_adapter_test_state_t *state,
                                     const router_callbacks_t *callbacks) {
  uint64_t deadline = turbo_monotonic_ms() + TEST_CONNECT_TIMEOUT_MS;

  while (callbacks->non_mmp_count == 0u && turbo_monotonic_ms() < deadline) {
    coro_context_run(p2p_get_loop(state->node1), TURBO_RUN_NOWAIT);
    coro_context_run(p2p_get_loop(state->node2), TURBO_RUN_NOWAIT);
    turbo_sleep_ms(1u);
  }
  return callbacks->non_mmp_count != 0u ? 0 : -1;
}

static int pump_until_router_empty(p2p_adapter_test_state_t *state,
                                   const mesh_mgmt_agent_router_v1_t *router) {
  uint64_t deadline = turbo_monotonic_ms() + TEST_CONNECT_TIMEOUT_MS;

  while (mesh_mgmt_agent_router_active_peers_v1(router) != 0u && turbo_monotonic_ms() < deadline) {
    coro_context_run(p2p_get_loop(state->node1), TURBO_RUN_NOWAIT);
    coro_context_run(p2p_get_loop(state->node2), TURBO_RUN_NOWAIT);
    turbo_sleep_ms(1u);
  }
  return mesh_mgmt_agent_router_active_peers_v1(router) == 0u ? 0 : -1;
}

static void test_authenticated_peer_identity_and_message_lifetime(void) {
  p2p_adapter_test_state_t state;
  mesh_mgmt_p2p_adapter_v1_t adapter;
  mesh_mgmt_transport_io_v1_t io;
  mesh_mgmt_transport_v1_t transport;
  mesh_mgmt_transport_receipt_v1_t receipt;
  uint8_t expected_remote_key[P2P_KEY_SIZE];
  uint8_t remote_key[P2P_KEY_SIZE];
  uint8_t channel_binding[P2P_SECURITY_ID_SIZE];
  p2p_peer_security_info_v2_t security_info;
  uint8_t frame[TEST_FRAME_CAPACITY];
  uint8_t coalesced[TEST_FRAME_CAPACITY * 2u];
  size_t frame_len;

  memset(&state, 0, sizeof(state));
  memset(&adapter, 0, sizeof(adapter));
  memset(&io, 0, sizeof(io));
  memset(&transport, 0, sizeof(transport));
  memset(&receipt, 0, sizeof(receipt));
  memset(&security_info, 0, sizeof(security_info));
  frame_len = encode_test_frame(frame, sizeof(frame));
  check_size_gt(frame_len, 0u);
  check_int_eq(start_nodes(&state), 0);
  if (!state.node1_peer || !state.node2_peer) {
    stop_nodes(&state);
    return;
  }

  check_int_eq(p2p_node_get_public_key(state.node2, expected_remote_key), P2P_OK);
  security_info.struct_size = sizeof(security_info);
  check_int_eq(p2p_peer_get_security_info_v2(state.node1_peer, &security_info),
               P2P_OK);
  check_int_eq(
      mesh_mgmt_p2p_adapter_init_v1(&adapter, state.node1, state.node1_peer,
                                    &io, remote_key, channel_binding),
      MESH_MGMT_P2P_ADAPTER_OK);
  check_mem_eq(remote_key, expected_remote_key, sizeof(remote_key));
  check_mem_eq(channel_binding, security_info.channel_binding,
               sizeof(channel_binding));
  check_int_eq(mesh_mgmt_transport_init_v1(&transport, &io), MESH_MGMT_TRANSPORT_OK);

  check_false(mesh_mgmt_p2p_message_is_mmp_v1("MESH_HELLO", 10u));
  check_true(mesh_mgmt_p2p_message_is_mmp_v1(frame, frame_len));
  check_int_eq(mesh_mgmt_p2p_adapter_offer_message_v1(&adapter, "MESH_HELLO", 10u),
               MESH_MGMT_P2P_ADAPTER_NOT_MMP);
  check_int_eq(mesh_mgmt_p2p_adapter_offer_message_v1(&adapter, frame, frame_len),
               MESH_MGMT_P2P_ADAPTER_OK);
  check_int_eq(mesh_mgmt_p2p_adapter_offer_message_v1(&adapter, frame, frame_len),
               MESH_MGMT_P2P_ADAPTER_INVALID_STATE);
  check_int_eq(mesh_mgmt_transport_receive_v1(&transport, &receipt), MESH_MGMT_TRANSPORT_OK);
  check_size_eq(receipt.frame_len, frame_len);
  check_mem_eq(receipt.frame, frame, frame_len);
  check_int_eq(mesh_mgmt_transport_commit_v1(&transport, &receipt), MESH_MGMT_TRANSPORT_OK);
  check_int_eq(mesh_mgmt_p2p_adapter_finish_message_v1(&adapter), MESH_MGMT_P2P_ADAPTER_OK);

  check_int_eq(mesh_mgmt_p2p_adapter_offer_message_v1(&adapter, frame, frame_len),
               MESH_MGMT_P2P_ADAPTER_OK);
  check_int_eq(mesh_mgmt_p2p_adapter_finish_message_v1(&adapter),
               MESH_MGMT_P2P_ADAPTER_MESSAGE_NOT_CONSUMED);
  check_false(adapter.message_offered);
  check_false(adapter.recv_borrowed);

  check_int_eq(mesh_mgmt_transport_send_v1(&transport, frame, frame_len), MESH_MGMT_TRANSPORT_OK);
  check_int_eq(pump_until_received(&state), 0);
  check_size_eq(state.received_len, frame_len);
  check_mem_eq(state.received, frame, frame_len);

  memcpy(coalesced, frame, frame_len);
  memcpy(coalesced + frame_len, frame, frame_len);
  check_int_eq(mesh_mgmt_p2p_adapter_offer_message_v1(&adapter, coalesced, frame_len * 2u),
               MESH_MGMT_P2P_ADAPTER_OK);
  memset(&receipt, 0, sizeof(receipt));
  check_int_eq(mesh_mgmt_transport_receive_v1(&transport, &receipt), MESH_MGMT_TRANSPORT_OK);
  check_int_eq(mesh_mgmt_transport_commit_v1(&transport, &receipt), MESH_MGMT_TRANSPORT_OK);
  check_int_eq(mesh_mgmt_p2p_adapter_finish_message_v1(&adapter),
               MESH_MGMT_P2P_ADAPTER_MESSAGE_NOT_CONSUMED);
  check_true(adapter.message_offered);
  check_true(adapter.recv_borrowed);
  mesh_mgmt_transport_destroy_v1(&transport);
  check_false(adapter.message_offered);
  check_false(adapter.recv_borrowed);
  mesh_mgmt_p2p_adapter_destroy_v1(&adapter);
  check_false(adapter.initialized);
  stop_nodes(&state);
}

static void test_two_authenticated_p2p_peers_complete_signed_handshake(void) {
  static const uint8_t MANAGEMENT_KEY1[32] = {
      1u, 3u, 5u, 7u, 9u,  11u, 13u, 15u, 17u, 19u, 21u, 23u, 25u, 27u, 29u, 31u,
      2u, 4u, 6u, 8u, 10u, 12u, 14u, 16u, 18u, 20u, 22u, 24u, 26u, 28u, 30u, 32u,
  };
  static const uint8_t MANAGEMENT_KEY2[32] = {
      32u, 30u, 28u, 26u, 24u, 22u, 20u, 18u, 16u, 14u, 12u, 10u, 8u, 6u, 4u, 2u,
      31u, 29u, 27u, 25u, 23u, 21u, 19u, 17u, 15u, 13u, 11u, 9u,  7u, 5u, 3u, 1u,
  };
  p2p_adapter_test_state_t state;
  runtime_callbacks_t callbacks1;
  runtime_callbacks_t callbacks2;
  mesh_mgmt_p2p_peer_config_v1_t config1;
  mesh_mgmt_p2p_peer_config_v1_t config2;
  mesh_mgmt_p2p_peer_config_v1_t mismatched_config;
  mesh_mgmt_p2p_peer_v1_t runtime1;
  mesh_mgmt_p2p_peer_v1_t runtime2;
  mesh_mgmt_p2p_peer_v1_t rejected_runtime;
  p2p_peer_security_info_v2_t security_info1;
  p2p_peer_security_info_v2_t security_info2;
  uint8_t transport_key1[P2P_KEY_SIZE];
  uint8_t transport_key2[P2P_KEY_SIZE];
  uint8_t execution_payload[
      MESH_MGMT_EXECUTION_COMMAND_REQUEST_MAX_SIZE_V1];
  size_t execution_payload_size;
  mesh_mgmt_p2p_peer_result_t execution_send_result;

  memset(&state, 0, sizeof(state));
  memset(&callbacks1, 0, sizeof(callbacks1));
  memset(&callbacks2, 0, sizeof(callbacks2));
  memset(&runtime1, 0, sizeof(runtime1));
  memset(&runtime2, 0, sizeof(runtime2));
  memset(&rejected_runtime, 0, sizeof(rejected_runtime));
  memset(&security_info1, 0, sizeof(security_info1));
  memset(&security_info2, 0, sizeof(security_info2));
  callbacks1.next_message_byte = 0x20u;
  callbacks2.next_message_byte = 0x80u;
  state.runtime1_result = MESH_MGMT_P2P_PEER_OK;
  state.runtime2_result = MESH_MGMT_P2P_PEER_OK;
  check_int_eq(start_nodes(&state), 0);
  if (!state.node1_peer || !state.node2_peer) {
    stop_nodes(&state);
    return;
  }

  check_int_eq(p2p_node_get_public_key(state.node1, transport_key1), P2P_OK);
  check_int_eq(p2p_node_get_public_key(state.node2, transport_key2), P2P_OK);
  check_int_eq(prepare_runtime_config(&config1, state.node1, state.node1_peer, transport_key1,
                                      MANAGEMENT_KEY1, 0x31u, 0x41u, 0x51u, 1u, &callbacks1),
               0);
  check_int_eq(prepare_runtime_config(&config2, state.node2, state.node2_peer, transport_key2,
                                      MANAGEMENT_KEY2, 0x32u, 0x42u, 0x52u, 2u, &callbacks2),
               0);
  config1.signer.hello.features |=
      MESH_MGMT_FEATURE_TARGETED_RPC | MESH_MGMT_FEATURE_NODE_EXECUTION;
  config2.signer.hello.features |=
      MESH_MGMT_FEATURE_TARGETED_RPC | MESH_MGMT_FEATURE_NODE_EXECUTION;
  config1.dispatch.session.features |=
      MESH_MGMT_FEATURE_TARGETED_RPC | MESH_MGMT_FEATURE_NODE_EXECUTION;
  config2.dispatch.session.features |=
      MESH_MGMT_FEATURE_TARGETED_RPC | MESH_MGMT_FEATURE_NODE_EXECUTION;
  config1.signer.hello.max_frame = MESH_MGMT_FRAME_MAX;
  config2.signer.hello.max_frame = MESH_MGMT_FRAME_MAX;
  config1.dispatch.session.max_frame = MESH_MGMT_FRAME_MAX;
  config2.dispatch.session.max_frame = MESH_MGMT_FRAME_MAX;
  config1.dispatch.enable_node_execution_shadow = 1u;
  config2.dispatch.enable_node_execution_shadow = 1u;
  check_int_eq(mesh_mgmt_ed25519_public_from_private(
                   MANAGEMENT_KEY2,
                   config2.dispatch.node_execution_grant_issuer_key),
               MESH_MGMT_CRYPTO_OK);
  memcpy(config1.dispatch.node_execution_grant_issuer_key,
         config2.dispatch.node_execution_grant_issuer_key,
         sizeof(config1.dispatch.node_execution_grant_issuer_key));
  execution_payload_size = make_p2p_execution_request(
      &config1, &config2, MANAGEMENT_KEY2, execution_payload);

  mismatched_config = config1;
  mismatched_config.signer.local_transport_peer_id[0] ^= 1u;
  check_int_eq(mesh_mgmt_p2p_peer_init_v1(&rejected_runtime, &mismatched_config),
               MESH_MGMT_P2P_PEER_IDENTITY_MISMATCH);
  check_int_eq(rejected_runtime.state, MESH_MGMT_P2P_PEER_UNINITIALIZED);

  check_int_eq(mesh_mgmt_p2p_peer_init_v1(&runtime1, &config1), MESH_MGMT_P2P_PEER_OK);
  check_int_eq(mesh_mgmt_p2p_peer_init_v1(&runtime2, &config2), MESH_MGMT_P2P_PEER_OK);
  security_info1.struct_size = sizeof(security_info1);
  security_info2.struct_size = sizeof(security_info2);
  check_int_eq(p2p_peer_get_security_info_v2(state.node1_peer, &security_info1),
               P2P_OK);
  check_int_eq(p2p_peer_get_security_info_v2(state.node2_peer, &security_info2),
               P2P_OK);
  check_mem_eq(runtime1.signer.hello.channel_binding,
               security_info1.channel_binding, P2P_SECURITY_ID_SIZE);
  check_mem_eq(runtime1.protocol_peer.connection.dispatcher.session.config.channel_binding,
               security_info1.channel_binding, P2P_SECURITY_ID_SIZE);
  check_mem_eq(runtime2.signer.hello.channel_binding,
               security_info2.channel_binding, P2P_SECURITY_ID_SIZE);
  check_mem_eq(runtime2.protocol_peer.connection.dispatcher.session.config.channel_binding,
               security_info2.channel_binding, P2P_SECURITY_ID_SIZE);
  state.runtime1 = &runtime1;
  state.runtime2 = &runtime2;
  check_int_eq(mesh_mgmt_p2p_peer_handle_message_v1(&runtime1, "MESH_HELLO", 10u, TEST_NOW_MS),
               MESH_MGMT_P2P_PEER_NOT_MMP);
  check_int_eq(runtime1.state, MESH_MGMT_P2P_PEER_READY);
  check_int_eq(mesh_mgmt_p2p_peer_start_v1(&runtime1, TEST_NOW_MS), MESH_MGMT_P2P_PEER_OK);
  check_int_eq(mesh_mgmt_p2p_peer_start_v1(&runtime2, TEST_NOW_MS), MESH_MGMT_P2P_PEER_OK);
  check_int_eq(pump_until_established(&state), 0);
  check_int_eq(state.runtime1_result, MESH_MGMT_P2P_PEER_OK);
  check_int_eq(state.runtime2_result, MESH_MGMT_P2P_PEER_OK);
  check_int_eq(runtime1.protocol_peer.connection.dispatcher.session.state,
               MESH_MGMT_SESSION_ESTABLISHED);
  check_int_eq(runtime2.protocol_peer.connection.dispatcher.session.state,
               MESH_MGMT_SESSION_ESTABLISHED);
  check_size_eq(callbacks1.event_count, 2u);
  check_size_eq(callbacks2.event_count, 2u);
  check_true(runtime1.signer.hello_built);
  check_true(runtime1.signer.ack_built);
  check_true(runtime2.signer.hello_built);
  check_true(runtime2.signer.ack_built);
  execution_send_result = mesh_mgmt_p2p_peer_send_execution_request_v1(
      &runtime1, config2.signer.hello.managed_node_id,
      execution_payload, execution_payload_size);
  check_int_eq(
      runtime1.protocol_peer.connection.last_dispatch_result,
      MESH_MGMT_DISPATCH_OK);
  check_int_eq(
      runtime1.protocol_peer.connection.last_dispatch_stage,
      MESH_MGMT_DISPATCH_STAGE_TYPED_DISPATCH);
  check_int_eq(execution_send_result, MESH_MGMT_P2P_PEER_OK);
  check_int_eq(pump_until_execution_request(&state, &callbacks2), 0);
  check_int_eq(callbacks2.last_event_type,
               MESH_MGMT_DISPATCH_EVENT_NODE_EXECUTION_REQUEST_SHADOW);

  state.runtime1 = NULL;
  state.runtime2 = NULL;
  mesh_mgmt_p2p_peer_destroy_v1(&runtime2);
  mesh_mgmt_p2p_peer_destroy_v1(&runtime1);
  stop_nodes(&state);
}

static void test_agent_router_owns_callbacks_and_reconnect_lifecycle(void) {
  static const uint8_t MANAGEMENT_KEY1[32] = {
      1u, 3u, 5u, 7u, 9u,  11u, 13u, 15u, 17u, 19u, 21u, 23u, 25u, 27u, 29u, 31u,
      2u, 4u, 6u, 8u, 10u, 12u, 14u, 16u, 18u, 20u, 22u, 24u, 26u, 28u, 30u, 32u,
  };
  static const uint8_t MANAGEMENT_KEY2[32] = {
      32u, 30u, 28u, 26u, 24u, 22u, 20u, 18u, 16u, 14u, 12u, 10u, 8u, 6u, 4u, 2u,
      31u, 29u, 27u, 25u, 23u, 21u, 19u, 17u, 15u, 13u, 11u, 9u,  7u, 5u, 3u, 1u,
  };
  static const char LEGACY_MESSAGE[] = "legacy-mesh-message";
  p2p_adapter_test_state_t state;
  runtime_callbacks_t signer_callbacks1;
  runtime_callbacks_t signer_callbacks2;
  router_callbacks_t router_callbacks1;
  router_callbacks_t router_callbacks2;
  mesh_mgmt_p2p_peer_config_v1_t peer_config1;
  mesh_mgmt_p2p_peer_config_v1_t peer_config2;
  mesh_mgmt_agent_router_config_v1_t router_config1;
  mesh_mgmt_agent_router_config_v1_t router_config2;
  mesh_mgmt_agent_router_config_v1_t rejected_config;
  mesh_mgmt_agent_router_v1_t router1;
  mesh_mgmt_agent_router_v1_t router2;
  mesh_mgmt_agent_router_v1_t rejected_router;
  mesh_mgmt_endpoint_pool_config_v1_t endpoint_config2;
  mesh_mgmt_endpoint_pool_v1_t endpoint_pool2;
  mesh_mgmt_endpoint_snapshot_v1_t endpoint_snapshot2;
  mesh_mgmt_agent_router_peer_snapshot_v1_t first_snapshot;
  mesh_mgmt_agent_router_peer_snapshot_v1_t second_snapshot;
  mesh_mgmt_execution_grant_v1_t decoded_grant;
  mesh_mgmt_execution_request_v1_t decoded_request;
  mesh_mgmt_execution_status_v1_t status;
  p2p_node_t *capacity_probe = NULL;
  uint8_t execution_payload[
      MESH_MGMT_EXECUTION_COMMAND_REQUEST_MAX_SIZE_V1];
  uint8_t status_payload[MESH_MGMT_EXECUTION_COMMAND_STATUS_SIZE_V1];
  uint8_t transport_key1[P2P_KEY_SIZE];
  uint8_t transport_key2[P2P_KEY_SIZE];
  uint8_t zero_id[16];
  size_t execution_payload_size = 0u;
  size_t status_payload_size = 0u;
  unsigned short node1_port = 0u;
  int router1_installed = 0;
  int router2_installed = 0;
  int endpoint_pool_initialized = 0;
  int endpoint_pool_running = 0;

  memset(&state, 0, sizeof(state));
  memset(&signer_callbacks1, 0, sizeof(signer_callbacks1));
  memset(&signer_callbacks2, 0, sizeof(signer_callbacks2));
  memset(&router_callbacks1, 0, sizeof(router_callbacks1));
  memset(&router_callbacks2, 0, sizeof(router_callbacks2));
  memset(&router_config1, 0, sizeof(router_config1));
  memset(&router_config2, 0, sizeof(router_config2));
  memset(&router1, 0, sizeof(router1));
  memset(&router2, 0, sizeof(router2));
  memset(&rejected_router, 0, sizeof(rejected_router));
  memset(&endpoint_config2, 0, sizeof(endpoint_config2));
  memset(&endpoint_pool2, 0, sizeof(endpoint_pool2));
  memset(&endpoint_snapshot2, 0, sizeof(endpoint_snapshot2));
  memset(&first_snapshot, 0, sizeof(first_snapshot));
  memset(&second_snapshot, 0, sizeof(second_snapshot));
  memset(&decoded_grant, 0, sizeof(decoded_grant));
  memset(&decoded_request, 0, sizeof(decoded_request));
  memset(&status, 0, sizeof(status));
  memset(execution_payload, 0, sizeof(execution_payload));
  memset(status_payload, 0, sizeof(status_payload));
  memset(zero_id, 0, sizeof(zero_id));
  signer_callbacks1.next_message_byte = 0x20u;
  signer_callbacks2.next_message_byte = 0x80u;
  router_callbacks1.next_namespace_byte = 0x11u;
  router_callbacks2.next_namespace_byte = 0x71u;

  check_int_eq(create_nodes(&state, &node1_port), 0);
  if (!state.node1 || !state.node2)
    goto cleanup;
  check_int_eq(p2p_node_get_public_key(state.node1, transport_key1), P2P_OK);
  check_int_eq(p2p_node_get_public_key(state.node2, transport_key2), P2P_OK);
  check_int_eq(prepare_runtime_config(&peer_config1, state.node1, NULL, transport_key1,
                                      MANAGEMENT_KEY1, 0x31u, 0x41u, 0x51u, 1u, &signer_callbacks1),
               0);
  check_int_eq(prepare_runtime_config(&peer_config2, state.node2, NULL, transport_key2,
                                      MANAGEMENT_KEY2, 0x32u, 0x42u, 0x52u, 2u, &signer_callbacks2),
               0);
  peer_config1.signer.hello.features |=
      MESH_MGMT_FEATURE_TARGETED_RPC | MESH_MGMT_FEATURE_NODE_EXECUTION;
  peer_config2.signer.hello.features =
      peer_config1.signer.hello.features;
  peer_config1.signer.hello.max_frame = MESH_MGMT_FRAME_MAX;
  peer_config2.signer.hello.max_frame = MESH_MGMT_FRAME_MAX;
  peer_config1.dispatch.session.features =
      peer_config1.signer.hello.features;
  peer_config2.dispatch.session.features =
      peer_config2.signer.hello.features;
  peer_config1.dispatch.session.max_frame = MESH_MGMT_FRAME_MAX;
  peer_config2.dispatch.session.max_frame = MESH_MGMT_FRAME_MAX;
  peer_config1.dispatch.enable_node_execution_shadow = 1u;
  peer_config2.dispatch.enable_node_execution_shadow = 1u;
  check_int_eq(mesh_mgmt_ed25519_public_from_private(
                   MANAGEMENT_KEY2,
                   peer_config2.dispatch.node_execution_grant_issuer_key),
               MESH_MGMT_CRYPTO_OK);
  memcpy(peer_config1.dispatch.node_execution_grant_issuer_key,
         peer_config2.dispatch.node_execution_grant_issuer_key,
         sizeof(peer_config1.dispatch.node_execution_grant_issuer_key));
  execution_payload_size = make_p2p_execution_request(
      &peer_config1, &peer_config2, MANAGEMENT_KEY2, execution_payload);
  check_int_eq(mesh_mgmt_execution_command_request_decode_v1(
                   execution_payload, execution_payload_size,
                   &decoded_grant, &decoded_request),
               MESH_MGMT_EXECUTION_WIRE_OK);

  router_config1.node = state.node1;
  router_config1.max_peers = 1u;
  router_config1.signer_template = &peer_config1.signer;
  router_config1.dispatch_template = &peer_config1.dispatch;
  router_config1.random_bytes = router_namespace_random;
  router_config1.random_context = &router_callbacks1;
  router_config1.on_event = router_event;
  router_config1.on_non_mmp = router_non_mmp;
  router_config1.on_failure = router_failure;
  router_config1.on_peer_closed = router_peer_closed;
  router_config1.callback_context = &router_callbacks1;
  router_config2 = router_config1;
  router_config2.node = state.node2;
  router_config2.signer_template = &peer_config2.signer;
  router_config2.dispatch_template = &peer_config2.dispatch;
  router_config2.random_context = &router_callbacks2;
  router_config2.callback_context = &router_callbacks2;

  rejected_config = router_config1;
  rejected_config.random_bytes = router_zero_random;
  check_int_eq(mesh_mgmt_agent_router_init_v1(&rejected_router, &rejected_config),
               MESH_MGMT_AGENT_ROUTER_RANDOM_FAILED);
  check_int_eq(rejected_router.state, MESH_MGMT_AGENT_ROUTER_UNINITIALIZED);

  check_int_eq(mesh_mgmt_agent_router_init_v1(&router1, &router_config1),
               MESH_MGMT_AGENT_ROUTER_OK);
  check_int_eq(mesh_mgmt_agent_router_init_v1(&router2, &router_config2),
               MESH_MGMT_AGENT_ROUTER_OK);

  endpoint_config2.node = state.node2;
  endpoint_config2.capacity = 1u;
  endpoint_config2.retry_base_ms = 10u;
  endpoint_config2.retry_max_ms = 100u;
  endpoint_config2.connect_timeout_ms = TEST_CONNECT_TIMEOUT_MS;
  endpoint_config2.protocol_failure_limit = 2u;
  endpoint_config2.random_bytes = router_namespace_random;
  endpoint_config2.callback_context = &router_callbacks2;
  check_int_eq(mesh_mgmt_endpoint_pool_init_v1(&endpoint_pool2, &endpoint_config2),
               MESH_MGMT_ENDPOINT_POOL_OK);
  endpoint_pool_initialized = 1;
  router_callbacks2.endpoint_pool = &endpoint_pool2;
  check_int_eq(mesh_mgmt_endpoint_pool_add_static_v1(&endpoint_pool2, transport_key1, "127.0.0.1",
                                                     node1_port),
               MESH_MGMT_ENDPOINT_POOL_OK);
  check_int_eq(mesh_mgmt_agent_router_install_v1(&router1), MESH_MGMT_AGENT_ROUTER_OK);
  router1_installed = 1;
  check_int_eq(mesh_mgmt_agent_router_install_v1(&router2), MESH_MGMT_AGENT_ROUTER_OK);
  router2_installed = 1;
  check_int_eq(p2p_start_nonblocking(state.node1), P2P_OK);
  check_int_eq(p2p_start_nonblocking(state.node2), P2P_OK);
  check_int_eq(mesh_mgmt_endpoint_pool_start_v1(&endpoint_pool2), MESH_MGMT_ENDPOINT_POOL_OK);
  endpoint_pool_running = 1;
  check_int_eq(mesh_mgmt_endpoint_pool_tick_v1(&endpoint_pool2, turbo_monotonic_ms()),
               MESH_MGMT_ENDPOINT_POOL_OK);
  check_int_eq(pump_until_router_established(&state, &router1, &router2, &router_callbacks1,
                                             &router_callbacks2),
               0);
  check_size_eq(mesh_mgmt_agent_router_active_peers_v1(&router1), 1u);
  check_size_eq(mesh_mgmt_agent_router_active_peers_v1(&router2), 1u);
  check_size_eq(router_callbacks1.event_count, 2u);
  check_size_eq(router_callbacks2.event_count, 2u);
  check_size_eq(router_callbacks1.failure_count, 0u);
  check_size_eq(router_callbacks2.failure_count, 0u);
  check_int_eq(
      mesh_mgmt_endpoint_pool_snapshot_v1(&endpoint_pool2, transport_key1, &endpoint_snapshot2),
      MESH_MGMT_ENDPOINT_POOL_OK);
  check_int_eq(endpoint_snapshot2.state, MESH_MGMT_ENDPOINT_ACTIVE);
  check_int_eq(
      mesh_mgmt_agent_router_peer_snapshot_v1(&router1, router_callbacks1.peer, &first_snapshot),
      MESH_MGMT_AGENT_ROUTER_OK);
  check_int_eq(first_snapshot.runtime_state, MESH_MGMT_P2P_PEER_READY);
  check_int_eq(first_snapshot.session_state, MESH_MGMT_SESSION_ESTABLISHED);
  check_mem_eq(first_snapshot.remote_transport_peer_id, transport_key2, P2P_KEY_SIZE);
  check_false(memcmp(first_snapshot.connection_id, zero_id, sizeof(zero_id)) == 0);

  router_callbacks2.last_event_type = 0;
  check_int_eq(mesh_mgmt_agent_router_send_execution_request_v1(
                   &router1, peer_config2.signer.hello.managed_node_id,
                   execution_payload, execution_payload_size),
               MESH_MGMT_AGENT_ROUTER_OK);
  check_int_eq(pump_until_router_event(
                   &state, &router_callbacks2,
                   MESH_MGMT_DISPATCH_EVENT_NODE_EXECUTION_REQUEST_SHADOW),
               0);

  status.version = MESH_MGMT_EXECUTION_SCHEMA_V1;
  status.code = MESH_MGMT_EXECUTION_STATUS_DISABLED;
  memcpy(status.command_id, decoded_request.command_id,
         sizeof(status.command_id));
  memcpy(status.correlation_id, decoded_request.correlation_id,
         sizeof(status.correlation_id));
  check_int_eq(mesh_mgmt_execution_request_digest_v1(
                   &decoded_request, status.request_digest),
               0);
  memcpy(status.responder_node_id,
         peer_config2.signer.hello.managed_node_id,
         sizeof(status.responder_node_id));
  check_int_eq(mesh_mgmt_execution_command_status_encode_v1(
                   &status, status_payload, sizeof(status_payload),
                   &status_payload_size),
               MESH_MGMT_EXECUTION_WIRE_OK);
  router_callbacks1.last_event_type = 0;
  check_int_eq(mesh_mgmt_agent_router_send_execution_response_v1(
                   &router2, MESH_MGMT_KIND_COMMAND_STATUS,
                   peer_config1.signer.hello.managed_node_id, status_payload,
                   status_payload_size),
               MESH_MGMT_AGENT_ROUTER_OK);
  check_int_eq(pump_until_router_event(
                   &state, &router_callbacks1,
                   MESH_MGMT_DISPATCH_EVENT_NODE_EXECUTION_STATUS_SHADOW),
               0);

  capacity_probe = p2p_create("127.0.0.1", 0);
  check_not_null(capacity_probe);
  if (capacity_probe) {
    uint64_t deadline = turbo_monotonic_ms() + TEST_CONNECT_TIMEOUT_MS;
    uint8_t trusted_keys[3 * P2P_KEY_SIZE];

    check_int_eq(p2p_node_set_private_key(capacity_probe, CAPACITY_PROBE_KEY), P2P_OK);
    check_int_eq(p2p_node_get_public_key(state.node1, trusted_keys), P2P_OK);
    check_int_eq(p2p_node_get_public_key(state.node2,
                                         trusted_keys + P2P_KEY_SIZE), P2P_OK);
    check_int_eq(p2p_node_get_public_key(capacity_probe,
                                         trusted_keys + 2u * P2P_KEY_SIZE), P2P_OK);
    check_int_eq(p2p_node_configure_pinned_security_v2(
                      capacity_probe, TEST_P2P_NETWORK_ID, trusted_keys, 3u),
                 P2P_OK);
    memset(trusted_keys, 0, sizeof(trusted_keys));
    check_int_eq(p2p_start_nonblocking(capacity_probe), P2P_OK);
    check_int_eq(p2p_connect(capacity_probe, "127.0.0.1", (int)node1_port), P2P_OK);
    while (router_callbacks1.failure_count == 0u && turbo_monotonic_ms() < deadline) {
      coro_context_run(p2p_get_loop(state.node1), TURBO_RUN_NOWAIT);
      coro_context_run(p2p_get_loop(state.node2), TURBO_RUN_NOWAIT);
      coro_context_run(p2p_get_loop(capacity_probe), TURBO_RUN_NOWAIT);
      turbo_sleep_ms(1u);
    }
    check_true(router_callbacks1.failure_count >= 1u);
    check_int_eq(router_callbacks1.last_router_failure, MESH_MGMT_AGENT_ROUTER_RESOURCE_EXHAUSTED);
    check_size_eq(mesh_mgmt_agent_router_active_peers_v1(&router1), 1u);
    check_int_eq(
        mesh_mgmt_agent_router_peer_snapshot_v1(&router1, router_callbacks1.peer, &second_snapshot),
        MESH_MGMT_AGENT_ROUTER_OK);
    check_int_eq(second_snapshot.session_state, MESH_MGMT_SESSION_ESTABLISHED);
    p2p_destroy(capacity_probe);
    capacity_probe = NULL;
    router_callbacks1.failure_count = 0u;
  }

  check_int_eq(p2p_send_message(state.node1, router_callbacks1.peer, P2P_MSG_CUSTOM, LEGACY_MESSAGE,
                                sizeof(LEGACY_MESSAGE) - 1u),
               P2P_OK);
  check_int_eq(pump_until_router_non_mmp(&state, &router_callbacks2), 0);
  check_size_eq(router_callbacks2.non_mmp_count, 1u);
  check_size_eq(mesh_mgmt_agent_router_active_peers_v1(&router2), 1u);

  p2p_disconnect_peer(router_callbacks1.peer);
  check_int_eq(pump_until_router_empty(&state, &router1), 0);
  check_int_eq(pump_until_router_empty(&state, &router2), 0);
  check_size_eq(router_callbacks1.close_count, 1u);
  check_size_eq(router_callbacks2.close_count, 1u);
  check_int_eq(router_callbacks1.last_close_reason, MESH_MGMT_AGENT_ROUTER_CLOSE_TRANSPORT);
  check_int_eq(router_callbacks2.last_close_reason, MESH_MGMT_AGENT_ROUTER_CLOSE_TRANSPORT);
  check_int_eq(
      mesh_mgmt_endpoint_pool_snapshot_v1(&endpoint_pool2, transport_key1, &endpoint_snapshot2),
      MESH_MGMT_ENDPOINT_POOL_OK);
  check_int_eq(endpoint_snapshot2.state, MESH_MGMT_ENDPOINT_BACKOFF);
  router_callbacks1.peer = NULL;
  router_callbacks2.peer = NULL;
  router_callbacks1.event_count = 0u;
  router_callbacks2.event_count = 0u;

  check_int_eq(mesh_mgmt_endpoint_pool_tick_v1(&endpoint_pool2, endpoint_snapshot2.next_attempt_ms),
               MESH_MGMT_ENDPOINT_POOL_OK);
  check_int_eq(pump_until_router_established(&state, &router1, &router2, &router_callbacks1,
                                             &router_callbacks2),
               0);
  check_int_eq(
      mesh_mgmt_agent_router_peer_snapshot_v1(&router1, router_callbacks1.peer, &second_snapshot),
      MESH_MGMT_AGENT_ROUTER_OK);
  check_false(memcmp(first_snapshot.connection_id, second_snapshot.connection_id,
                     sizeof(first_snapshot.connection_id)) == 0);
  check_int_eq(
      mesh_mgmt_endpoint_pool_snapshot_v1(&endpoint_pool2, transport_key1, &endpoint_snapshot2),
      MESH_MGMT_ENDPOINT_POOL_OK);
  check_int_eq(endpoint_snapshot2.state, MESH_MGMT_ENDPOINT_ACTIVE);
  check_size_eq(router_callbacks1.failure_count, 0u);
  check_size_eq(router_callbacks2.failure_count, 0u);

cleanup:
  if (capacity_probe)
    p2p_destroy(capacity_probe);
  if (endpoint_pool_running) {
    mesh_mgmt_endpoint_pool_stop_v1(&endpoint_pool2);
    endpoint_pool_running = 0;
  }
  if (router1_installed)
    (void)mesh_mgmt_agent_router_stop_v1(&router1);
  if (router2_installed) {
    (void)pump_until_router_empty(&state, &router2);
    (void)mesh_mgmt_agent_router_stop_v1(&router2);
  }
  mesh_mgmt_agent_router_destroy_v1(&router2);
  mesh_mgmt_agent_router_destroy_v1(&router1);
  if (endpoint_pool_initialized)
    mesh_mgmt_endpoint_pool_destroy_v1(&endpoint_pool2);
  stop_nodes(&state);
}

static void test_mesh_bridge_shares_callbacks_and_detaches_without_disconnect(void) {
  static const uint8_t MANAGEMENT_KEY1[32] = {
      1u, 3u, 5u, 7u, 9u,  11u, 13u, 15u, 17u, 19u, 21u, 23u, 25u, 27u, 29u, 31u,
      2u, 4u, 6u, 8u, 10u, 12u, 14u, 16u, 18u, 20u, 22u, 24u, 26u, 28u, 30u, 32u,
  };
  static const uint8_t MANAGEMENT_KEY2[32] = {
      32u, 30u, 28u, 26u, 24u, 22u, 20u, 18u, 16u, 14u, 12u, 10u, 8u, 6u, 4u, 2u,
      31u, 29u, 27u, 25u, 23u, 21u, 19u, 17u, 15u, 13u, 11u, 9u,  7u, 5u, 3u, 1u,
  };
  mesh_config_t mesh_config1;
  mesh_config_t mesh_config2;
  mesh_network_t *mesh1 = NULL;
  mesh_network_t *mesh2 = NULL;
  p2p_node_t *node1;
  p2p_node_t *node2;
  runtime_callbacks_t signer_callbacks1;
  runtime_callbacks_t signer_callbacks2;
  router_callbacks_t router_callbacks1;
  router_callbacks_t router_callbacks2;
  mesh_mgmt_p2p_peer_config_v1_t peer_config1;
  mesh_mgmt_p2p_peer_config_v1_t peer_config2;
  mesh_mgmt_agent_router_config_v1_t router_config1;
  mesh_mgmt_agent_router_config_v1_t router_config2;
  mesh_mgmt_agent_router_v1_t router1;
  mesh_mgmt_agent_router_v1_t router2;
  const char *node2_bootstraps[1];
  char node1_endpoint[64];
  uint8_t transport_key1[P2P_KEY_SIZE];
  uint8_t transport_key2[P2P_KEY_SIZE];
  uint8_t pinned_public_key1[P2P_KEY_SIZE];
  uint8_t pinned_public_key2[P2P_KEY_SIZE];
  char identity_secret1[65];
  char identity_secret2[65];
  char pinned_node_id1[65];
  char pinned_node_id2[65];
  const char *node1_allowed_ids[1];
  const char *node2_allowed_ids[1];
  uint64_t deadline;
  unsigned short port1 = 0u;
  unsigned short port2 = 0u;
  int router1_initialized = 0;
  int router2_initialized = 0;
  int router1_attached = 0;
  int router2_attached = 0;
  int mesh1_started = 0;
  int mesh2_started = 0;
  int established = 0;

  memset(&signer_callbacks1, 0, sizeof(signer_callbacks1));
  memset(&signer_callbacks2, 0, sizeof(signer_callbacks2));
  memset(&router_callbacks1, 0, sizeof(router_callbacks1));
  memset(&router_callbacks2, 0, sizeof(router_callbacks2));
  memset(&peer_config1, 0, sizeof(peer_config1));
  memset(&peer_config2, 0, sizeof(peer_config2));
  memset(&router_config1, 0, sizeof(router_config1));
  memset(&router_config2, 0, sizeof(router_config2));
  memset(&router1, 0, sizeof(router1));
  memset(&router2, 0, sizeof(router2));
  signer_callbacks1.next_message_byte = 0x20u;
  signer_callbacks2.next_message_byte = 0x80u;
  router_callbacks1.next_namespace_byte = 0x11u;
  router_callbacks2.next_namespace_byte = 0x71u;

  check_int_eq(pick_loopback_ports(&port1, &port2), 0);
  if (port1 == 0u || port2 == 0u)
    goto cleanup;
  snprintf(node1_endpoint, sizeof(node1_endpoint), "127.0.0.1:%u", (unsigned int)port1);
  node2_bootstraps[0] = node1_endpoint;
  check_int_eq(p2p_public_key_from_private_key(MANAGEMENT_KEY1,
                                               pinned_public_key1), P2P_OK);
  check_int_eq(p2p_public_key_from_private_key(MANAGEMENT_KEY2,
                                               pinned_public_key2), P2P_OK);
  test_bytes_to_hex(MANAGEMENT_KEY1, sizeof(MANAGEMENT_KEY1), identity_secret1);
  test_bytes_to_hex(MANAGEMENT_KEY2, sizeof(MANAGEMENT_KEY2), identity_secret2);
  test_bytes_to_hex(pinned_public_key1, sizeof(pinned_public_key1), pinned_node_id1);
  test_bytes_to_hex(pinned_public_key2, sizeof(pinned_public_key2), pinned_node_id2);
  node1_allowed_ids[0] = pinned_node_id2;
  node2_allowed_ids[0] = pinned_node_id1;

  mesh_config_init(&mesh_config1);
  mesh_config1.virtual_ip = "10.42.30.1";
  mesh_config1.listen_port = (int)port1;
  mesh_config1.advertise_ip = "127.0.0.1";
  mesh_config1.network_id = "mgmt-shared-node-test";
  mesh_config1.identity_secret_hex = identity_secret1;
  mesh_config1.peer_allow_node_ids = node1_allowed_ids;
  mesh_config1.peer_allow_node_id_count = 1;

  mesh_config_init(&mesh_config2);
  mesh_config2.virtual_ip = "10.42.30.2";
  mesh_config2.listen_port = (int)port2;
  mesh_config2.advertise_ip = "127.0.0.1";
  mesh_config2.network_id = "mgmt-shared-node-test";
  mesh_config2.identity_secret_hex = identity_secret2;
  mesh_config2.peer_allow_node_ids = node2_allowed_ids;
  mesh_config2.peer_allow_node_id_count = 1;
  mesh_config2.bootstrap_peers = node2_bootstraps;
  mesh_config2.bootstrap_count = 1;

  mesh1 = mesh_create(&mesh_config1);
  mesh2 = mesh_create(&mesh_config2);
  check_not_null(mesh1);
  check_not_null(mesh2);
  if (!mesh1 || !mesh2)
    goto cleanup;

  node1 = mesh_mgmt_mesh_borrow_p2p_node_v1(mesh1);
  node2 = mesh_mgmt_mesh_borrow_p2p_node_v1(mesh2);
  check_not_null(node1);
  check_not_null(node2);
  if (!node1 || !node2)
    goto cleanup;
  check_int_eq(p2p_node_get_public_key(node1, transport_key1), P2P_OK);
  check_int_eq(p2p_node_get_public_key(node2, transport_key2), P2P_OK);
  check_int_eq(prepare_runtime_config(&peer_config1, node1, NULL, transport_key1,
                                      MANAGEMENT_KEY1, 0x31u, 0x41u, 0x51u, 1u,
                                      &signer_callbacks1),
               0);
  check_int_eq(prepare_runtime_config(&peer_config2, node2, NULL, transport_key2,
                                      MANAGEMENT_KEY2, 0x32u, 0x42u, 0x52u, 2u,
                                      &signer_callbacks2),
               0);

  router_config1.node = node1;
  router_config1.max_peers = 2u;
  router_config1.signer_template = &peer_config1.signer;
  router_config1.dispatch_template = &peer_config1.dispatch;
  router_config1.random_bytes = router_namespace_random;
  router_config1.random_context = &router_callbacks1;
  router_config1.on_event = router_event;
  router_config1.on_non_mmp = router_non_mmp;
  router_config1.on_failure = router_failure;
  router_config1.on_peer_closed = router_peer_closed;
  router_config1.callback_context = &router_callbacks1;
  router_config2 = router_config1;
  router_config2.node = node2;
  router_config2.signer_template = &peer_config2.signer;
  router_config2.dispatch_template = &peer_config2.dispatch;
  router_config2.random_context = &router_callbacks2;
  router_config2.callback_context = &router_callbacks2;

  check_int_eq(mesh_mgmt_agent_router_init_v1(&router1, &router_config1),
               MESH_MGMT_AGENT_ROUTER_OK);
  router1_initialized = 1;
  check_int_eq(mesh_mgmt_agent_router_init_v1(&router2, &router_config2),
               MESH_MGMT_AGENT_ROUTER_OK);
  router2_initialized = 1;
  check_int_eq(mesh_mgmt_mesh_router_attach_v1(mesh1, &router1),
               MESH_MGMT_AGENT_ROUTER_OK);
  router1_attached = 1;
  check_int_eq(mesh_mgmt_mesh_router_attach_v1(mesh2, &router2),
               MESH_MGMT_AGENT_ROUTER_OK);
  router2_attached = 1;
  check_false(router1.owns_callbacks);
  check_false(router2.owns_callbacks);

  check_int_eq(mesh_start(mesh1), MESH_OK);
  mesh1_started = 1;
  check_int_eq(mesh_start(mesh2), MESH_OK);
  mesh2_started = 1;

  deadline = turbo_monotonic_ms() + TEST_CONNECT_TIMEOUT_MS;
  while (turbo_monotonic_ms() < deadline) {
    mesh_poll(mesh1, 10);
    mesh_poll(mesh2, 10);
    if (mesh_get_peer_count(mesh1) == 1 && mesh_get_peer_count(mesh2) == 1 &&
        mesh_mgmt_agent_router_active_peers_v1(&router1) == 1u &&
        mesh_mgmt_agent_router_active_peers_v1(&router2) == 1u &&
        router_callbacks1.event_count >= 2u && router_callbacks2.event_count >= 2u) {
      established = 1;
      break;
    }
    turbo_sleep_ms(1u);
  }

  check_true(established);
  check_size_eq(router_callbacks1.failure_count, 0u);
  check_size_eq(router_callbacks2.failure_count, 0u);
  check_size_eq(router_callbacks1.non_mmp_count, 0u);
  check_size_eq(router_callbacks2.non_mmp_count, 0u);

  check_int_eq(mesh_mgmt_mesh_router_detach_v1(mesh1, &router1),
               MESH_MGMT_AGENT_ROUTER_OK);
  router1_attached = 0;
  check_int_eq(mesh_mgmt_mesh_router_detach_v1(mesh2, &router2),
               MESH_MGMT_AGENT_ROUTER_OK);
  router2_attached = 0;
  check_size_eq(mesh_mgmt_agent_router_active_peers_v1(&router1), 0u);
  check_size_eq(mesh_mgmt_agent_router_active_peers_v1(&router2), 0u);
  check_size_eq(router_callbacks1.close_count, 1u);
  check_size_eq(router_callbacks2.close_count, 1u);
  check_int_eq(router_callbacks1.last_close_reason, MESH_MGMT_AGENT_ROUTER_CLOSE_LOCAL_STOP);
  check_int_eq(router_callbacks2.last_close_reason, MESH_MGMT_AGENT_ROUTER_CLOSE_LOCAL_STOP);

  for (int index = 0; index < 10; index++) {
    mesh_poll(mesh1, 10);
    mesh_poll(mesh2, 10);
    turbo_sleep_ms(1u);
  }
  check_int_eq(mesh_get_peer_count(mesh1), 1);
  check_int_eq(mesh_get_peer_count(mesh2), 1);

cleanup:
  if (router2_attached)
    (void)mesh_mgmt_mesh_router_detach_v1(mesh2, &router2);
  if (router1_attached)
    (void)mesh_mgmt_mesh_router_detach_v1(mesh1, &router1);
  if (router2_initialized)
    mesh_mgmt_agent_router_destroy_v1(&router2);
  if (router1_initialized)
    mesh_mgmt_agent_router_destroy_v1(&router1);
  if (mesh2_started)
    mesh_stop(mesh2);
  if (mesh1_started)
    mesh_stop(mesh1);
  mesh_destroy(mesh2);
  mesh_destroy(mesh1);
}

static void test_agent_runtime_borrows_mesh_node_without_owning_event_loop(void) {
  static const uint8_t MANAGEMENT_KEY[32] = {
      1u, 3u, 5u, 7u, 9u,  11u, 13u, 15u, 17u, 19u, 21u, 23u, 25u, 27u, 29u, 31u,
      2u, 4u, 6u, 8u, 10u, 12u, 14u, 16u, 18u, 20u, 22u, 24u, 26u, 28u, 30u, 32u,
  };
  mesh_config_t mesh_config;
  mesh_network_t *mesh = NULL;
  p2p_node_t *borrowed_node;
  runtime_callbacks_t signer_callbacks;
  router_callbacks_t router_callbacks;
  mesh_mgmt_p2p_peer_config_v1_t peer_config;
  mesh_mgmt_agent_runtime_config_v1_t runtime_config;
  mesh_mgmt_agent_runtime_config_v1_t invalid_config;
  mesh_mgmt_agent_runtime_v1_t runtime;
  uint8_t transport_key[P2P_KEY_SIZE];
  unsigned short port1 = 0u;
  unsigned short port2 = 0u;
  int runtime_initialized = 0;
  int runtime_running = 0;
  int mesh_started = 0;

  memset(&signer_callbacks, 0, sizeof(signer_callbacks));
  memset(&router_callbacks, 0, sizeof(router_callbacks));
  memset(&peer_config, 0, sizeof(peer_config));
  memset(&runtime_config, 0, sizeof(runtime_config));
  memset(&invalid_config, 0, sizeof(invalid_config));
  memset(&runtime, 0, sizeof(runtime));
  signer_callbacks.next_message_byte = 0x20u;
  router_callbacks.next_namespace_byte = 0x11u;

  check_int_eq(pick_loopback_ports(&port1, &port2), 0);
  if (port1 == 0u)
    goto cleanup;
  mesh_config_init(&mesh_config);
  mesh_config.virtual_ip = "10.42.31.1";
  mesh_config.listen_port = (int)port1;
  mesh_config.advertise_ip = "127.0.0.1";
  mesh_config.network_id = "mgmt-shared-runtime-test";
  mesh = mesh_create(&mesh_config);
  check_not_null(mesh);
  if (!mesh)
    goto cleanup;

  borrowed_node = mesh_mgmt_mesh_borrow_p2p_node_v1(mesh);
  check_not_null(borrowed_node);
  if (!borrowed_node)
    goto cleanup;
  check_int_eq(p2p_node_get_public_key(borrowed_node, transport_key), P2P_OK);
  check_int_eq(prepare_runtime_config(&peer_config, borrowed_node, NULL, transport_key,
                                      MANAGEMENT_KEY, 0x31u, 0x41u, 0x51u, 1u,
                                      &signer_callbacks),
               0);

  runtime_config.shared_mesh = mesh;
  runtime_config.max_peers = 2u;
  runtime_config.signer_template = &peer_config.signer;
  runtime_config.dispatch_template = &peer_config.dispatch;
  runtime_config.endpoint_capacity = 2u;
  runtime_config.retry_base_ms = 10u;
  runtime_config.retry_max_ms = 100u;
  runtime_config.connect_timeout_ms = TEST_CONNECT_TIMEOUT_MS;
  runtime_config.protocol_failure_limit = 2u;
  runtime_config.first_endpoint_record_epoch = 1u;
  runtime_config.first_service_record_epoch = 1u;
  runtime_config.random_bytes = router_namespace_random;
  runtime_config.random_context = &router_callbacks;
  runtime_config.admit_peer = router_admit_peer;
  runtime_config.on_event = router_event;
  runtime_config.on_non_mmp = router_non_mmp;
  runtime_config.on_failure = router_failure;
  runtime_config.on_peer_closed = router_peer_closed;
  runtime_config.callback_context = &router_callbacks;

  invalid_config = runtime_config;
  invalid_config.listen_host = "127.0.0.1";
  invalid_config.listen_port = port2;
  check_int_eq(mesh_mgmt_agent_runtime_init_v1(&runtime, &invalid_config),
               MESH_MGMT_AGENT_RUNTIME_INVALID_ARG);
  check_int_eq(mesh_mgmt_agent_runtime_init_v1(&runtime, &runtime_config),
               MESH_MGMT_AGENT_RUNTIME_OK);
  runtime_initialized = 1;
  check_false(runtime.owns_node);
  check_true(runtime.node == borrowed_node);
  check_int_eq(mesh_mgmt_agent_runtime_start_v1(&runtime), MESH_MGMT_AGENT_RUNTIME_OK);
  runtime_running = 1;
  check_false(runtime.router.owns_callbacks);

  check_int_eq(mesh_start(mesh), MESH_OK);
  mesh_started = 1;
  mesh_poll(mesh, 10);
  check_int_eq(mesh_mgmt_agent_runtime_poll_v1(&runtime), MESH_MGMT_AGENT_RUNTIME_OK);
  check_true(mesh_mgmt_mesh_borrow_p2p_node_v1(mesh) == borrowed_node);

  check_int_eq(mesh_mgmt_agent_runtime_stop_v1(&runtime), MESH_MGMT_AGENT_RUNTIME_OK);
  runtime_running = 0;
  check_int_eq(runtime.state, MESH_MGMT_AGENT_RUNTIME_STOPPED);
  check_true(mesh_mgmt_mesh_borrow_p2p_node_v1(mesh) == borrowed_node);

cleanup:
  if (runtime_running)
    (void)mesh_mgmt_agent_runtime_stop_v1(&runtime);
  if (runtime_initialized)
    mesh_mgmt_agent_runtime_destroy_v1(&runtime);
  if (mesh_started)
    mesh_stop(mesh);
  mesh_destroy(mesh);
}

static void prepare_agent_runtime_config(mesh_mgmt_agent_runtime_config_v1_t *config, uint16_t port,
                                         const uint8_t private_key[32],
                                         const mesh_mgmt_p2p_peer_config_v1_t *peer_config,
                                         const mesh_mgmt_agent_bootstrap_v1_t *bootstraps,
                                         size_t bootstrap_count, router_callbacks_t *callbacks,
                                         mesh_mgmt_agent_admit_peer_fn admit_peer) {
  memset(config, 0, sizeof(*config));
  config->listen_host = "127.0.0.1";
  config->listen_port = port;
  config->p2p_private_key = private_key;
  config->max_peers = 2u;
  config->signer_template = &peer_config->signer;
  config->dispatch_template = &peer_config->dispatch;
  config->endpoint_capacity = 2u;
  config->retry_base_ms = 10u;
  config->retry_max_ms = 100u;
  config->connect_timeout_ms = TEST_CONNECT_TIMEOUT_MS;
  config->protocol_failure_limit = 2u;
  config->first_endpoint_record_epoch = 1u;
  config->first_service_record_epoch = 1u;
  config->bootstraps = bootstraps;
  config->bootstrap_count = bootstrap_count;
  config->random_bytes = router_namespace_random;
  config->random_context = callbacks;
  config->admit_peer = admit_peer;
  config->on_event = router_event;
  config->on_non_mmp = router_non_mmp;
  config->on_failure = router_failure;
  config->on_peer_closed = router_peer_closed;
  config->callback_context = callbacks;
}

static int pump_agent_runtimes_until_established(mesh_mgmt_agent_runtime_v1_t *runtime1,
                                                 mesh_mgmt_agent_runtime_v1_t *runtime2,
                                                 const router_callbacks_t *callbacks1,
                                                 const router_callbacks_t *callbacks2) {
  uint64_t deadline = turbo_monotonic_ms() + TEST_CONNECT_TIMEOUT_MS;

  while (turbo_monotonic_ms() < deadline) {
    if (mesh_mgmt_agent_runtime_poll_v1(runtime1) != MESH_MGMT_AGENT_RUNTIME_OK ||
        mesh_mgmt_agent_runtime_poll_v1(runtime2) != MESH_MGMT_AGENT_RUNTIME_OK)
      return -1;
    if (callbacks1->event_count >= 2u && callbacks2->event_count >= 2u &&
        mesh_mgmt_agent_router_active_peers_v1(&runtime1->router) == 1u &&
        mesh_mgmt_agent_router_active_peers_v1(&runtime2->router) == 1u)
      return 0;
    if (callbacks1->failure_count != 0u || callbacks2->failure_count != 0u)
      return -2;
    turbo_sleep_ms(1u);
  }
  return -3;
}

static int pump_agent_runtime_until_endpoint_state(mesh_mgmt_agent_runtime_v1_t *runtime,
                                                   const uint8_t transport_peer_id[32],
                                                   mesh_mgmt_endpoint_state_t expected_state) {
  mesh_mgmt_endpoint_snapshot_v1_t snapshot;
  uint64_t deadline = turbo_monotonic_ms() + TEST_CONNECT_TIMEOUT_MS;

  while (turbo_monotonic_ms() < deadline) {
    if (mesh_mgmt_agent_runtime_poll_v1(runtime) != MESH_MGMT_AGENT_RUNTIME_OK)
      return -1;
    if (mesh_mgmt_endpoint_pool_snapshot_v1(&runtime->endpoint_pool, transport_peer_id,
                                            &snapshot) == MESH_MGMT_ENDPOINT_POOL_OK &&
        snapshot.state == expected_state)
      return 0;
    turbo_sleep_ms(1u);
  }
  return -2;
}

static int pump_agent_runtimes_until_dht_value(mesh_mgmt_agent_runtime_v1_t *runtime1,
                                               mesh_mgmt_agent_runtime_v1_t *runtime2,
                                               const char *key, uint8_t *output,
                                               size_t *output_len) {
  uint64_t deadline = turbo_monotonic_ms() + TEST_CONNECT_TIMEOUT_MS;

  while (turbo_monotonic_ms() < deadline) {
    size_t capacity = *output_len;

    if (mesh_mgmt_agent_runtime_poll_v1(runtime1) != MESH_MGMT_AGENT_RUNTIME_OK ||
        mesh_mgmt_agent_runtime_poll_v1(runtime2) != MESH_MGMT_AGENT_RUNTIME_OK)
      return -1;
    if (p2p_dht_get_cached(runtime1->node, key, output, &capacity) == P2P_OK) {
      *output_len = capacity;
      return 0;
    }
    turbo_sleep_ms(1u);
  }
  return -2;
}

static void test_agent_runtime_pushes_verified_endpoint_discovery(void) {
  static const uint8_t TRANSPORT_KEY1[P2P_KEY_SIZE] = {
      1u,  2u,  3u,  4u,  5u,  6u,  7u,  8u,  9u,  10u, 11u, 12u, 13u, 14u, 15u, 16u,
      17u, 18u, 19u, 20u, 21u, 22u, 23u, 24u, 25u, 26u, 27u, 28u, 29u, 30u, 31u, 32u,
  };
  static const uint8_t TRANSPORT_KEY2[P2P_KEY_SIZE] = {
      32u, 31u, 30u, 29u, 28u, 27u, 26u, 25u, 24u, 23u, 22u, 21u, 20u, 19u, 18u, 17u,
      16u, 15u, 14u, 13u, 12u, 11u, 10u, 9u,  8u,  7u,  6u,  5u,  4u,  3u,  2u,  1u,
  };
  static const uint8_t MANAGEMENT_KEY1[32] = {
      0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3,
      0x46, 0xec, 0x11, 0x4e, 0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab,
      0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
  };
  static const uint8_t MANAGEMENT_KEY2[32] = {
      0xc5, 0xaa, 0x8d, 0xf4, 0x3f, 0x9f, 0x83, 0x7b, 0xed, 0xb7, 0x44,
      0x2f, 0x31, 0xdc, 0xb7, 0xb1, 0x66, 0xd3, 0x85, 0x35, 0x07, 0x6f,
      0x09, 0x4b, 0x85, 0xce, 0x3a, 0x2e, 0x0b, 0x44, 0x58, 0xf7,
  };
  mesh_mgmt_agent_runtime_v1_t runtime1;
  mesh_mgmt_agent_runtime_v1_t runtime2;
  mesh_mgmt_agent_runtime_config_v1_t config1;
  mesh_mgmt_agent_runtime_config_v1_t config2;
  mesh_mgmt_p2p_peer_config_v1_t peer_config1;
  mesh_mgmt_p2p_peer_config_v1_t peer_config2;
  mesh_mgmt_agent_bootstrap_v1_t bootstrap2;
  mesh_mgmt_endpoint_publish_v1_t endpoint;
  mesh_mgmt_service_publish_v1_t service;
  mesh_mgmt_service_record_v1_t service_record;
  mesh_mgmt_agent_cached_endpoint_v1_t cached_input;
  mesh_mgmt_endpoint_snapshot_v1_t snapshot;
  runtime_callbacks_t signer_callbacks1;
  runtime_callbacks_t signer_callbacks2;
  router_callbacks_t callbacks1;
  router_callbacks_t callbacks2;
  uint8_t transport_id1[P2P_KEY_SIZE];
  uint8_t transport_id2[P2P_KEY_SIZE];
  uint8_t frame[MESH_MGMT_ENDPOINT_FRAME_V1_MAX];
  uint8_t service_frame[MESH_MGMT_SERVICE_FRAME_V1_MAX];
  char key[MESH_MGMT_ENDPOINT_DHT_KEY_V1_SIZE];
  char service_key[MESH_MGMT_SERVICE_DHT_KEY_V1_SIZE];
  size_t frame_len = sizeof(frame);
  size_t service_frame_len = sizeof(service_frame);
  size_t key_len = 0u;
  size_t service_key_len = 0u;
  uint64_t record_epoch = 0u;
  uint64_t service_record_epoch = 0u;
  uint64_t next_epoch;
  uint64_t certificate_expires_at_ms;
  unsigned short port1 = 0u;
  unsigned short port2 = 0u;

  memset(&runtime1, 0, sizeof(runtime1));
  memset(&runtime2, 0, sizeof(runtime2));
  memset(&signer_callbacks1, 0, sizeof(signer_callbacks1));
  memset(&signer_callbacks2, 0, sizeof(signer_callbacks2));
  memset(&callbacks1, 0, sizeof(callbacks1));
  memset(&callbacks2, 0, sizeof(callbacks2));
  memset(&bootstrap2, 0, sizeof(bootstrap2));
  memset(&endpoint, 0, sizeof(endpoint));
  memset(&service, 0, sizeof(service));
  memset(&service_record, 0, sizeof(service_record));
  memset(&cached_input, 0, sizeof(cached_input));
  signer_callbacks1.next_message_byte = 0x21u;
  signer_callbacks2.next_message_byte = 0x81u;
  callbacks1.next_namespace_byte = 0x12u;
  callbacks2.next_namespace_byte = 0x72u;

  check_int_eq(pick_loopback_ports(&port1, &port2), 0);
  check_int_eq(p2p_public_key_from_private_key(TRANSPORT_KEY1, transport_id1), P2P_OK);
  check_int_eq(p2p_public_key_from_private_key(TRANSPORT_KEY2, transport_id2), P2P_OK);
  check_int_eq(prepare_runtime_config(&peer_config1, NULL, NULL, transport_id1, MANAGEMENT_KEY1,
                                      0x41u, 0x51u, 0x61u, 11u, &signer_callbacks1),
               0);
  check_int_eq(prepare_runtime_config(&peer_config2, NULL, NULL, transport_id2, MANAGEMENT_KEY2,
                                      0x42u, 0x52u, 0x62u, 12u, &signer_callbacks2),
               0);
  memcpy(bootstrap2.transport_peer_id, transport_id1, sizeof(bootstrap2.transport_peer_id));
  bootstrap2.host = "127.0.0.1";
  bootstrap2.port = port1;
  prepare_agent_runtime_config(&config1, port1, TRANSPORT_KEY1, &peer_config1, NULL, 0u,
                               &callbacks1, router_admit_peer);
  prepare_agent_runtime_config(&config2, port2, TRANSPORT_KEY2, &peer_config2, &bootstrap2, 1u,
                               &callbacks2, NULL);
  check_int_eq(mesh_mgmt_agent_runtime_init_v1(&runtime1, &config1), MESH_MGMT_AGENT_RUNTIME_OK);
  check_int_eq(mesh_mgmt_agent_runtime_start_v1(&runtime1), MESH_MGMT_AGENT_RUNTIME_OK);
  check_int_eq(mesh_mgmt_agent_runtime_init_v1(&runtime2, &config2), MESH_MGMT_AGENT_RUNTIME_OK);
  check_int_eq(mesh_mgmt_agent_runtime_start_v1(&runtime2), MESH_MGMT_AGENT_RUNTIME_OK);
  check_int_eq(
      pump_agent_runtimes_until_established(&runtime1, &runtime2, &callbacks1, &callbacks2), 0);

  service.address_family = MESH_MGMT_SERVICE_ADDRESS_IPV4;
  service.virtual_address[0] = 100u;
  service.virtual_address[1] = 64u;
  service.virtual_address[3] = 2u;
  service.dns_name = "node-b.mesh";
  service.port = 7878u;
  check_int_eq(mesh_mgmt_agent_runtime_publish_cached_service_v1(
                   &runtime2, &service, &service_record_epoch),
               MESH_MGMT_AGENT_RUNTIME_OK);
  check_hex64_eq(service_record_epoch, 1u);
  check_int_eq(mesh_mgmt_service_dht_key_build_v1(
                   peer_config2.signer.expected_mesh_id_hash,
                   peer_config2.signer.hello.managed_node_id, service_key,
                   sizeof(service_key), &service_key_len),
               MESH_MGMT_SERVICE_RECORD_OK);
  check_int_eq(pump_agent_runtimes_until_dht_value(
                   &runtime1, &runtime2, service_key, service_frame,
                   &service_frame_len),
               0);
  check_int_eq(mesh_mgmt_agent_runtime_resolve_cached_service_v1(
                   &runtime1, peer_config2.signer.hello.managed_node_id,
                   TEST_NOW_MS, peer_config2.signer.frame_ttl_ms, &service_record),
               MESH_MGMT_AGENT_RUNTIME_OK);
  check_str_eq(service_record.virtual_host, "node-b.mesh");
  check_str_eq(service_record.virtual_ip, "100.64.0.2");
  check_int_eq(service_record.port, 7878u);

  service_frame[service_frame_len - 1u] ^= 1u;
  check_int_eq(p2p_dht_put_cached(
                   runtime1.node, service_key, service_frame, service_frame_len),
               P2P_OK);
  check_int_eq(mesh_mgmt_agent_runtime_resolve_cached_service_v1(
                   &runtime1, peer_config2.signer.hello.managed_node_id,
                   TEST_NOW_MS, peer_config2.signer.frame_ttl_ms, &service_record),
               MESH_MGMT_AGENT_RUNTIME_SERVICE_RECORD_FAILED);
  check_int_eq(runtime1.last_service_record_result,
               MESH_MGMT_SERVICE_RECORD_AUTH_FAILED);
  check_mem_eq(&service_record, &(mesh_mgmt_service_record_v1_t){0},
               sizeof(service_record));

  endpoint.address_family = MESH_MGMT_ENDPOINT_ADDRESS_IPV4;
  endpoint.address[0] = 224u;
  endpoint.address[3] = 1u;
  endpoint.port = port2;
  next_epoch = runtime2.endpoint_publisher.next_record_epoch;
  check_int_eq(
      mesh_mgmt_agent_runtime_publish_cached_endpoint_v1(&runtime2, &endpoint, &record_epoch),
      MESH_MGMT_AGENT_RUNTIME_PUBLISH_FAILED);
  check_int_eq(runtime2.last_publisher_result, MESH_MGMT_ENDPOINT_PUBLISHER_ENCODE_FAILED);
  check_hex64_eq(record_epoch, 0u);
  check_hex64_eq(runtime2.endpoint_publisher.next_record_epoch, next_epoch);

  memset(endpoint.address, 0, sizeof(endpoint.address));
  endpoint.address[0] = 127u;
  endpoint.address[3] = 1u;
  signer_callbacks2.random_result = -77;
  check_int_eq(
      mesh_mgmt_agent_runtime_publish_cached_endpoint_v1(&runtime2, &endpoint, &record_epoch),
      MESH_MGMT_AGENT_RUNTIME_PUBLISH_FAILED);
  check_int_eq(runtime2.last_publisher_result, MESH_MGMT_ENDPOINT_PUBLISHER_RANDOM_FAILED);
  check_int_eq(runtime2.endpoint_publisher.last_random_result, -77);
  check_hex64_eq(record_epoch, 0u);
  check_hex64_eq(runtime2.endpoint_publisher.next_record_epoch, next_epoch);
  signer_callbacks2.random_result = 0;

  certificate_expires_at_ms = runtime2.endpoint_publisher.certificate_expires_at_ms;
  runtime2.endpoint_publisher.certificate_expires_at_ms =
      TEST_NOW_MS + runtime2.endpoint_publisher.signer.frame_ttl_ms - 1u;
  check_int_eq(
      mesh_mgmt_agent_runtime_publish_cached_endpoint_v1(&runtime2, &endpoint, &record_epoch),
      MESH_MGMT_AGENT_RUNTIME_PUBLISH_FAILED);
  check_int_eq(runtime2.last_publisher_result, MESH_MGMT_ENDPOINT_PUBLISHER_IDENTITY_FAILED);
  check_hex64_eq(record_epoch, 0u);
  check_hex64_eq(runtime2.endpoint_publisher.next_record_epoch, next_epoch);
  runtime2.endpoint_publisher.certificate_expires_at_ms = certificate_expires_at_ms;

  check_int_eq(
      mesh_mgmt_agent_runtime_publish_cached_endpoint_v1(&runtime2, &endpoint, &record_epoch),
      MESH_MGMT_AGENT_RUNTIME_OK);
  check_hex64_eq(record_epoch, next_epoch);
  check_int_eq(mesh_mgmt_endpoint_dht_key_build_v1(peer_config2.signer.expected_mesh_id_hash,
                                                   peer_config2.signer.hello.managed_node_id, key,
                                                   sizeof(key), &key_len),
               MESH_MGMT_ENDPOINT_RECORD_OK);
  check_int_eq(pump_agent_runtimes_until_dht_value(&runtime1, &runtime2, key, frame, &frame_len),
               0);

  cached_input.mesh_id_hash = peer_config2.signer.expected_mesh_id_hash;
  cached_input.owner_node_id = peer_config2.signer.hello.managed_node_id;
  cached_input.certificate = peer_config2.signer.hello.certificate;
  cached_input.certificate_len = sizeof(peer_config2.signer.hello.certificate);
  cached_input.trusted_issuer_key = peer_config2.signer.trusted_issuer_key;
  cached_input.now_ms = TEST_NOW_MS;
  cached_input.max_ttl_ms = peer_config2.signer.frame_ttl_ms;
  check_int_eq(mesh_mgmt_agent_runtime_apply_cached_endpoint_v1(&runtime1, &cached_input),
               MESH_MGMT_AGENT_RUNTIME_OK);
  check_int_eq(
      mesh_mgmt_endpoint_pool_snapshot_v1(&runtime1.endpoint_pool, transport_id2, &snapshot),
      MESH_MGMT_ENDPOINT_POOL_OK);
  check_str_eq(snapshot.record.host, "127.0.0.1");
  check_int_eq(snapshot.record.port, port2);
  check_hex64_eq(snapshot.record.record_epoch, record_epoch);

  frame[frame_len - 1u] ^= 1u;
  check_int_eq(p2p_dht_put_cached(runtime1.node, key, frame, frame_len), P2P_OK);
  check_int_eq(mesh_mgmt_agent_runtime_apply_cached_endpoint_v1(&runtime1, &cached_input),
               MESH_MGMT_AGENT_RUNTIME_ENDPOINT_RECORD_FAILED);
  check_int_eq(runtime1.last_endpoint_record_result, MESH_MGMT_ENDPOINT_RECORD_AUTH_FAILED);
  check_int_eq(
      mesh_mgmt_endpoint_pool_snapshot_v1(&runtime1.endpoint_pool, transport_id2, &snapshot),
      MESH_MGMT_ENDPOINT_POOL_OK);
  check_hex64_eq(snapshot.record.record_epoch, record_epoch);

  runtime2.endpoint_publisher.next_record_epoch = UINT64_MAX;
  check_int_eq(
      mesh_mgmt_agent_runtime_publish_cached_endpoint_v1(&runtime2, &endpoint, &record_epoch),
      MESH_MGMT_AGENT_RUNTIME_OK);
  check_hex64_eq(record_epoch, UINT64_MAX);
  check_int_eq(
      mesh_mgmt_agent_runtime_publish_cached_endpoint_v1(&runtime2, &endpoint, &record_epoch),
      MESH_MGMT_AGENT_RUNTIME_PUBLISH_FAILED);
  check_int_eq(runtime2.last_publisher_result, MESH_MGMT_ENDPOINT_PUBLISHER_RESOURCE_EXHAUSTED);
  check_hex64_eq(record_epoch, 0u);

  mesh_mgmt_agent_runtime_destroy_v1(&runtime2);
  mesh_mgmt_agent_runtime_destroy_v1(&runtime1);
}

static void test_agent_runtime_owns_listener_policy_and_reconnect(void) {
  static const uint8_t TRANSPORT_KEY1[P2P_KEY_SIZE] = {
      1u,  2u,  3u,  4u,  5u,  6u,  7u,  8u,  9u,  10u, 11u, 12u, 13u, 14u, 15u, 16u,
      17u, 18u, 19u, 20u, 21u, 22u, 23u, 24u, 25u, 26u, 27u, 28u, 29u, 30u, 31u, 32u,
  };
  static const uint8_t TRANSPORT_KEY2[P2P_KEY_SIZE] = {
      32u, 31u, 30u, 29u, 28u, 27u, 26u, 25u, 24u, 23u, 22u, 21u, 20u, 19u, 18u, 17u,
      16u, 15u, 14u, 13u, 12u, 11u, 10u, 9u,  8u,  7u,  6u,  5u,  4u,  3u,  2u,  1u,
  };
  static const uint8_t MANAGEMENT_KEY1[32] = {
      0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3,
      0x46, 0xec, 0x11, 0x4e, 0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab,
      0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
  };
  static const uint8_t MANAGEMENT_KEY2[32] = {
      0xc5, 0xaa, 0x8d, 0xf4, 0x3f, 0x9f, 0x83, 0x7b, 0xed, 0xb7, 0x44,
      0x2f, 0x31, 0xdc, 0xb7, 0xb1, 0x66, 0xd3, 0x85, 0x35, 0x07, 0x6f,
      0x09, 0x4b, 0x85, 0xce, 0x3a, 0x2e, 0x0b, 0x44, 0x58, 0xf7,
  };
  mesh_mgmt_agent_runtime_v1_t runtime1;
  mesh_mgmt_agent_runtime_v1_t runtime1_restart;
  mesh_mgmt_agent_runtime_v1_t invalid_runtime;
  mesh_mgmt_agent_runtime_v1_t runtime2;
  mesh_mgmt_agent_runtime_config_v1_t config1;
  mesh_mgmt_agent_runtime_config_v1_t config2;
  mesh_mgmt_agent_runtime_config_v1_t invalid_config;
  mesh_mgmt_p2p_peer_config_v1_t peer_config1;
  mesh_mgmt_p2p_peer_config_v1_t peer_config2;
  mesh_mgmt_agent_bootstrap_v1_t bootstrap2;
  mesh_mgmt_endpoint_snapshot_v1_t endpoint_snapshot;
  mesh_mgmt_p2p_remote_trust_v2_t remote_trust;
  p2p_security_revalidation_result_v2_t revalidation;
  runtime_callbacks_t signer_callbacks1;
  runtime_callbacks_t signer_callbacks2;
  router_callbacks_t callbacks1;
  router_callbacks_t callbacks2;
  uint8_t transport_id1[P2P_KEY_SIZE];
  uint8_t transport_id2[P2P_KEY_SIZE];
  uint64_t revoked_serial = 12u;
  uint64_t deadline;
  unsigned short port1 = 0u;
  unsigned short port2 = 0u;

  memset(&runtime1, 0, sizeof(runtime1));
  memset(&runtime1_restart, 0, sizeof(runtime1_restart));
  memset(&invalid_runtime, 0, sizeof(invalid_runtime));
  memset(&runtime2, 0, sizeof(runtime2));
  memset(&signer_callbacks1, 0, sizeof(signer_callbacks1));
  memset(&signer_callbacks2, 0, sizeof(signer_callbacks2));
  memset(&callbacks1, 0, sizeof(callbacks1));
  memset(&callbacks2, 0, sizeof(callbacks2));
  memset(&bootstrap2, 0, sizeof(bootstrap2));
  memset(&remote_trust, 0, sizeof(remote_trust));
  memset(&revalidation, 0, sizeof(revalidation));
  signer_callbacks1.next_message_byte = 0x21u;
  signer_callbacks2.next_message_byte = 0x81u;
  callbacks1.next_namespace_byte = 0x12u;
  callbacks2.next_namespace_byte = 0x72u;

  check_int_eq(pick_loopback_ports(&port1, &port2), 0);
  check_int_eq(p2p_public_key_from_private_key(TRANSPORT_KEY1, transport_id1), P2P_OK);
  check_int_eq(p2p_public_key_from_private_key(TRANSPORT_KEY2, transport_id2), P2P_OK);
  check_int_eq(prepare_runtime_config(&peer_config1, NULL, NULL, transport_id1, MANAGEMENT_KEY1,
                                      0x41u, 0x51u, 0x61u, 11u, &signer_callbacks1),
               0);
  check_int_eq(prepare_runtime_config(&peer_config2, NULL, NULL, transport_id2, MANAGEMENT_KEY2,
                                      0x42u, 0x52u, 0x62u, 12u, &signer_callbacks2),
               0);
  memcpy(bootstrap2.transport_peer_id, transport_id1, sizeof(bootstrap2.transport_peer_id));
  bootstrap2.host = "127.0.0.1";
  bootstrap2.port = port1;
  prepare_agent_runtime_config(&config1, port1, TRANSPORT_KEY1, &peer_config1, NULL, 0u,
                               &callbacks1, router_admit_peer);
  prepare_agent_runtime_config(&config2, port2, TRANSPORT_KEY2, &peer_config2, &bootstrap2, 1u,
                               &callbacks2, NULL);
  invalid_config = config1;
  invalid_config.listen_port = 0u;
  check_int_eq(mesh_mgmt_agent_runtime_init_v1(&invalid_runtime, &invalid_config),
               MESH_MGMT_AGENT_RUNTIME_INVALID_ARG);
  invalid_config = config1;
  invalid_config.first_endpoint_record_epoch = 0u;
  check_int_eq(mesh_mgmt_agent_runtime_init_v1(&invalid_runtime, &invalid_config),
               MESH_MGMT_AGENT_RUNTIME_INVALID_ARG);
  invalid_config = config1;
  invalid_config.first_service_record_epoch = 0u;
  check_int_eq(mesh_mgmt_agent_runtime_init_v1(&invalid_runtime, &invalid_config),
               MESH_MGMT_AGENT_RUNTIME_INVALID_ARG);

  config1.admit_peer = NULL;
  check_int_eq(mesh_mgmt_agent_runtime_init_v1(&runtime1, &config1), MESH_MGMT_AGENT_RUNTIME_OK);
  check_int_eq(mesh_mgmt_agent_runtime_start_v1(&runtime1), MESH_MGMT_AGENT_RUNTIME_OK);
  check_int_eq(mesh_mgmt_agent_runtime_init_v1(&runtime2, &config2), MESH_MGMT_AGENT_RUNTIME_OK);
  check_int_eq(mesh_mgmt_agent_runtime_start_v1(&runtime2), MESH_MGMT_AGENT_RUNTIME_OK);
  deadline = turbo_monotonic_ms() + TEST_CONNECT_TIMEOUT_MS;
  while (callbacks1.failure_count == 0u && turbo_monotonic_ms() < deadline) {
    check_int_eq(mesh_mgmt_agent_runtime_poll_v1(&runtime1), MESH_MGMT_AGENT_RUNTIME_OK);
    check_int_eq(mesh_mgmt_agent_runtime_poll_v1(&runtime2), MESH_MGMT_AGENT_RUNTIME_OK);
    turbo_sleep_ms(1u);
  }
  check_true(callbacks1.failure_count >= 1u);
  check_size_eq(callbacks1.admission_count, 0u);
  check_int_eq(callbacks1.last_close_reason, MESH_MGMT_AGENT_ROUTER_CLOSE_PROTOCOL);
  mesh_mgmt_agent_runtime_destroy_v1(&runtime2);
  mesh_mgmt_agent_runtime_destroy_v1(&runtime1);
  callbacks1.peer = NULL;
  callbacks1.event_count = 0u;
  callbacks1.failure_count = 0u;
  callbacks1.close_count = 0u;
  callbacks2.peer = NULL;
  callbacks2.event_count = 0u;
  callbacks2.failure_count = 0u;
  callbacks2.close_count = 0u;
  config1.admit_peer = router_admit_peer;

  check_int_eq(mesh_mgmt_agent_runtime_init_v1(&runtime1, &config1), MESH_MGMT_AGENT_RUNTIME_OK);
  check_int_eq(mesh_mgmt_agent_runtime_start_v1(&runtime1), MESH_MGMT_AGENT_RUNTIME_OK);

  check_int_eq(mesh_mgmt_agent_runtime_init_v1(&runtime2, &config2), MESH_MGMT_AGENT_RUNTIME_OK);
  check_int_eq(mesh_mgmt_agent_runtime_start_v1(&runtime2), MESH_MGMT_AGENT_RUNTIME_OK);
  check_int_eq(
      pump_agent_runtimes_until_established(&runtime1, &runtime2, &callbacks1, &callbacks2), 0);
  check_size_eq(callbacks1.admission_count, 1u);
  check_size_eq(callbacks2.admission_count, 0u);
  check_int_eq(mesh_mgmt_endpoint_pool_snapshot_v1(&runtime2.endpoint_pool, transport_id1,
                                                   &endpoint_snapshot),
               MESH_MGMT_ENDPOINT_POOL_OK);
  check_int_eq(endpoint_snapshot.state, MESH_MGMT_ENDPOINT_ACTIVE);

  check_int_eq(mesh_mgmt_agent_runtime_stop_v1(&runtime1), MESH_MGMT_AGENT_RUNTIME_OK);
  check_int_eq(runtime1.state, MESH_MGMT_AGENT_RUNTIME_STOPPED);
  check_int_eq(mesh_mgmt_agent_runtime_start_v1(&runtime1), MESH_MGMT_AGENT_RUNTIME_INVALID_STATE);
  check_int_eq(
      pump_agent_runtime_until_endpoint_state(&runtime2, transport_id1, MESH_MGMT_ENDPOINT_BACKOFF),
      0);
  mesh_mgmt_agent_runtime_destroy_v1(&runtime1);
  callbacks1.peer = NULL;
  callbacks1.event_count = 0u;
  callbacks1.failure_count = 0u;

  check_int_eq(mesh_mgmt_agent_runtime_init_v1(&runtime1_restart, &config1),
               MESH_MGMT_AGENT_RUNTIME_OK);
  check_int_eq(mesh_mgmt_agent_runtime_start_v1(&runtime1_restart), MESH_MGMT_AGENT_RUNTIME_OK);
  check_int_eq(
      pump_agent_runtimes_until_established(&runtime1_restart, &runtime2, &callbacks1, &callbacks2),
      0);
  check_size_eq(callbacks1.admission_count, 2u);
  check_int_eq(mesh_mgmt_endpoint_pool_snapshot_v1(&runtime2.endpoint_pool, transport_id1,
                                                   &endpoint_snapshot),
               MESH_MGMT_ENDPOINT_POOL_OK);
  check_int_eq(endpoint_snapshot.state, MESH_MGMT_ENDPOINT_ACTIVE);

  remote_trust.struct_size = sizeof(remote_trust);
  remote_trust.minimum_remote_principal_epoch = 1u;
  remote_trust.required_remote_roles = MESH_MGMT_ROLE_OPERATOR;
  remote_trust.revoked_serials = &revoked_serial;
  remote_trust.revoked_serial_count = 1u;
  revalidation.struct_size = sizeof(revalidation);
  check_int_eq(mesh_mgmt_agent_runtime_update_remote_trust_v2(
                   &runtime1_restart, &remote_trust, &revalidation),
               MESH_MGMT_AGENT_RUNTIME_OK);
  check_size_eq(revalidation.examined_sessions, 1u);
  check_size_eq(revalidation.provider_rejections, 1u);
  check_size_eq(revalidation.disconnected_sessions, 1u);
  check_size_eq(revalidation.retained_sessions, 0u);
  check_size_eq(revalidation.identity_changes, 0u);

  mesh_mgmt_agent_runtime_destroy_v1(&runtime2);
  mesh_mgmt_agent_runtime_destroy_v1(&runtime1_restart);
}

spec("mesh management P2P adapter") {
  describe("encrypted custom-message identity boundary") {
    it("binds the encrypted peer key and consumes one borrowed MMP message") {
      test_authenticated_peer_identity_and_message_lifetime();
    }
    it("completes a signed bilateral handshake over real encrypted P2P peers") {
      test_two_authenticated_p2p_peers_complete_signed_handshake();
    }
    it("routes bounded peer lifecycles and reconnects with a fresh connection id") {
      test_agent_router_owns_callbacks_and_reconnect_lifecycle();
    }
    it("shares mesh callbacks and detaches management without dropping data-plane peers") {
      test_mesh_bridge_shares_callbacks_and_detaches_without_disconnect();
    }
    it("runs the management runtime on a borrowed mesh node and event loop") {
      test_agent_runtime_borrows_mesh_node_without_owning_event_loop();
    }
    it("owns explicit listeners, admission policy, shutdown and reconnect") {
      test_agent_runtime_owns_listener_policy_and_reconnect();
    }
    it("pushes only signed endpoint discovery and rejects tampered cache values") {
      test_agent_runtime_pushes_verified_endpoint_discovery();
    }
  }
}
