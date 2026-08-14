#include "mesh_node_control_client_runtime.h"
#include "mesh_node_control_flowmq_provider.h"
#include "mesh_node_control_flowmq_network_provider.h"
#include "mesh_node_network_control_service.h"
#include "mesh_node_control_runtime.h"
#include "mesh_node_ipc_flowmq.h"
#include "meshd_network_control.h"
#include "tinytest.h"

#include <p2p.h>
#include <turbo_crypto.h>
#include <turbo_thread.h>

#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#define TEST_WAIT_ATTEMPTS 400
#define TEST_WAIT_STEP_MS 5u
#define TEST_FRAME_HWM_BYTES (1024u * 1024u)
#define TEST_TIMEOUT_MS 2000u
#define TEST_HEARTBEAT_INTERVAL_MS 100u
#define TEST_HEARTBEAT_TIMEOUT_MS 500u
#define TEST_SERVER_TLS_CERTIFICATE_SHA256 \
  "sha256:b8a72062af4690ea8066fb14191c988f4b80fd4d72c164bd976a505cb72ee742"
#define TEST_SERVER_NEXT_TLS_CERTIFICATE_SHA256 \
  "sha256:a568c7e7493b69df9271cfc2764717fb5679dac400a146c2d37c87dddf81aa74"
#define TEST_CLIENT_TLS_CERTIFICATE_SHA256 \
  "sha256:36f828b7dfeeeb70c1088ab417e6a473dbe7f8c479513894ef7a620f7c164eac"
#define TEST_CLIENT_NEXT_TLS_CERTIFICATE_SHA256 \
  "sha256:926a0752678c074862549e21c6375219d92fe57ac9a5def1f0f85e5d39809879"
#define TEST_SERVER_CLIENT_AUTH_ONLY_CERTIFICATE_SHA256 \
  "sha256:1a7982015d28374ac3a7377bc7c29171d164bbd4bc889b1c32785baf3f8442e4"
#define TEST_IDENTITY_POLICY_GENERATION UINT64_C(1)

enum test_rejected_peer_scenario_v1 {
  TEST_REJECT_REMOVED_SERVER_CERTIFICATE_V1 = 1,
  TEST_REJECT_REMOVED_CLIENT_CERTIFICATE_V1 = 2,
  TEST_REJECT_SERVER_CLIENT_AUTH_EKU_V1 = 3,
  TEST_REJECT_CLIENT_SERVER_AUTH_EKU_V1 = 4
};

static const uint8_t TEST_NETWORK_ISSUER_PRIVATE_KEY[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};

static const uint8_t TEST_NETWORK_ISSUER_PUBLIC_KEY[32] = {
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
    0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
};

typedef struct {
  uint8_t wire[MESH_CONTROL_NETWORK_DOCUMENT_BASE_SIZE_V1 +
               MESH_CONTROL_NETWORK_ROUTE_SIZE_V1];
  size_t wire_size;
  uint8_t resource_id[MESH_CONTROL_DIGEST_SIZE];
} flowmq_test_network_intent_v1_t;

typedef struct {
  size_t calls;
} runtime_executor_state_v1_t;

static void bytes_to_hex_32(const uint8_t bytes[32], char output[65]) {
  static const char digits[] = "0123456789abcdef";
  size_t index;
  for (index = 0u; index < 32u; ++index) {
    output[index * 2u] = digits[bytes[index] >> 4u];
    output[index * 2u + 1u] = digits[bytes[index] & 0x0fu];
  }
  output[64] = '\0';
}

static void make_flowmq_network_intent(
    flowmq_test_network_intent_v1_t *intent, const uint8_t mesh_id[32],
    const uint8_t node_id[32], const mesh_network_issuer_v1_t *issuer,
    uint8_t uid_marker, const char *name) {
  mesh_control_network_document_v1_t document;
  mesh_network_membership_ticket_v1_t ticket;
  mesh_network_uid_t uid;
  uint64_t now = (uint64_t)time(NULL);
  size_t ticket_size = 0u;

  memset(intent, 0, sizeof(*intent));
  memset(&document, 0, sizeof(document));
  memset(&ticket, 0, sizeof(ticket));
  memset(&uid, uid_marker, sizeof(uid));
  memcpy(ticket.mesh_id, mesh_id, sizeof(ticket.mesh_id));
  ticket.network_uid = uid;
  memset(ticket.membership_id, (uint8_t)(uid_marker + 1u),
         sizeof(ticket.membership_id));
  memcpy(ticket.managed_node_id, node_id, sizeof(ticket.managed_node_id));
  check_int_eq(MESH_OK, mesh_network_public_key_digest_v1(
                                node_id, ticket.node_public_key_digest));
  ticket.network_generation = 1u;
  ticket.membership_generation = 1u;
  ticket.node_key_epoch = 1u;
  ticket.policy_epoch = 1u;
  ticket.ipv4_address = 0x0a660000u | uid_marker;
  ticket.ipv4_prefix = 24u;
  ticket.roles = MESH_NETWORK_ROLE_MEMBER;
  ticket.issued_at_unix_s = now - 1u;
  ticket.not_before_unix_s = now - 1u;
  ticket.not_after_unix_s = now + 3600u;
  memcpy(ticket.issuer_key_id, issuer->key_id,
         sizeof(ticket.issuer_key_id));
  check_int_eq(MESH_OK, mesh_network_membership_ticket_sign_v1(
                                &ticket, TEST_NETWORK_ISSUER_PRIVATE_KEY));

  document.schema_version = MESH_CONTROL_SCHEMA_V1;
  document.lifecycle = MESH_CONTROL_NETWORK_ACTIVE_V1;
  document.attach_mode = MESH_CONTROL_NETWORK_USERSPACE_V1;
  memcpy(document.network_uid, uid.bytes, sizeof(document.network_uid));
  memcpy(document.mesh_id, mesh_id, sizeof(document.mesh_id));
  memcpy(document.managed_node_id, node_id, sizeof(document.managed_node_id));
  document.generation = 1u;
  document.policy_epoch = 1u;
  document.route_epoch = 1u;
  document.key_epoch = 1u;
  document.ipv4_address = ticket.ipv4_address;
  document.ipv4_prefix = ticket.ipv4_prefix;
  document.mtu = 1280u;
  memcpy(document.name, name, strlen(name) + 1u);
  memset(document.policy_digest, 0x31, sizeof(document.policy_digest));
  memset(document.address_pool_digest, 0x32,
         sizeof(document.address_pool_digest));
  check_int_eq(MESH_CONTROL_OK, mesh_control_network_routes_digest_v1(
                                      NULL, 0u, document.route_digest));
  check_int_eq(MESH_OK, mesh_network_membership_ticket_encode_v1(
                                &ticket, document.membership_ticket,
                                sizeof(document.membership_ticket),
                                &ticket_size));
  check_uint_eq(MESH_CONTROL_NETWORK_TICKET_SIZE_V1, ticket_size);
  check_int_eq(MESH_CONTROL_OK, mesh_control_network_document_encode_v1(
                                       &document, intent->wire,
                                       sizeof(intent->wire),
                                       &intent->wire_size));
  check_int_eq(MESH_CONTROL_OK,
               mesh_network_resource_id_v1(mesh_id, document.network_uid,
                                           intent->resource_id));
}

static unsigned short test_port(void) {
  struct sockaddr_in address;
#ifdef _WIN32
  SOCKET socket_handle = INVALID_SOCKET;
  int address_size = (int)sizeof(address);
  WSADATA data;
  if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return 0u;
#else
  int socket_handle = -1;
  socklen_t address_size = (socklen_t)sizeof(address);
#endif
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0u;
  socket_handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#ifdef _WIN32
  if (socket_handle == INVALID_SOCKET) return 0u;
#else
  if (socket_handle < 0) return 0u;
#endif
  if (bind(socket_handle, (struct sockaddr *)&address, sizeof(address)) != 0 ||
      getsockname(socket_handle, (struct sockaddr *)&address,
                  &address_size) != 0) {
#ifdef _WIN32
    closesocket(socket_handle);
#else
    close(socket_handle);
#endif
    return 0u;
  }
#ifdef _WIN32
  closesocket(socket_handle);
#else
  close(socket_handle);
#endif
  return ntohs(address.sin_port);
}

static void set_timeouts(flowmq_coronet_timeout_config_t *timeouts) {
  memset(timeouts, 0, sizeof(*timeouts));
  timeouts->timeout_ms = TEST_TIMEOUT_MS;
  timeouts->connect_timeout_ms = TEST_TIMEOUT_MS;
  timeouts->send_timeout_ms = TEST_TIMEOUT_MS;
  timeouts->recv_timeout_ms = TEST_TIMEOUT_MS;
  timeouts->handshake_timeout_ms = TEST_TIMEOUT_MS;
  timeouts->set_flags = FLOWMQ_TIMEOUT_SET_ALL;
  timeouts->explicit_flags = FLOWMQ_TIMEOUT_SET_ALL;
}

static void server_config(flowmq_router_endpoint_config_t *endpoint,
                          unsigned short port,
                          const flowmq_coronet_tls_server_config_t *tls) {
  flowmq_router_endpoint_config_init(endpoint);
  endpoint->transport = FLOWMQ_TRANSPORT_TLS;
  endpoint->host = "127.0.0.1";
  endpoint->path = "/mesh-node-control";
  endpoint->topic = "mesh.node.control";
  endpoint->identity = "meshd";
  endpoint->tls = tls;
  endpoint->port = (int)port;
  endpoint->max_frame_size = MESH_NODE_IPC_FLOWMQ_MAX_FRAME_SIZE_V1;
  endpoint->max_connections = 1u;
  endpoint->heartbeat_interval_ms = TEST_HEARTBEAT_INTERVAL_MS;
  endpoint->heartbeat_timeout_ms = TEST_HEARTBEAT_TIMEOUT_MS;
  set_timeouts(&endpoint->timeouts);
}

static void client_config(flowmq_connect_endpoint_config_t *endpoint,
                          unsigned short port,
                          const flowmq_coronet_tls_client_config_t *tls) {
  flowmq_connect_endpoint_config_init(endpoint);
  endpoint->transport = FLOWMQ_TRANSPORT_TLS;
  endpoint->pattern = FLOWMQ_PROTOCOL_DEALER;
  endpoint->host = "localhost";
  endpoint->path = "/mesh-node-control";
  endpoint->topic = "mesh.node.control";
  endpoint->identity = "mesh-agent";
  endpoint->tls = tls;
  endpoint->port = (int)port;
  endpoint->max_frame_size = MESH_NODE_IPC_FLOWMQ_MAX_FRAME_SIZE_V1;
  endpoint->reconnect_initial_ms = 20u;
  endpoint->reconnect_max_ms = 200u;
  endpoint->heartbeat_interval_ms = TEST_HEARTBEAT_INTERVAL_MS;
  endpoint->heartbeat_timeout_ms = TEST_HEARTBEAT_TIMEOUT_MS;
  set_timeouts(&endpoint->timeouts);
}

static size_t command_frame(uint8_t *frame, size_t capacity) {
  mesh_node_ipc_command_v1_t command;
  mesh_node_ipc_envelope_v1_t envelope;
  uint8_t body[MESH_NODE_IPC_COMMAND_HEADER_SIZE_V1];
  size_t body_size = 0u;
  size_t frame_size = 0u;
  memset(&command, 0, sizeof(command));
  command.action = MESH_CONTROL_DESIRED_DELETE;
  command.resource_kind = MESH_CONTROL_RESOURCE_NETWORK;
  command.precondition_epoch = 1u;
  command.mesh_id[0] = 1u;
  command.resource_id[0] = 2u;
  command.provider_id[0] = 3u;
  check_int_eq(mesh_node_ipc_command_encode_v1(
                   &command, body, sizeof(body), &body_size),
               MESH_CONTROL_OK);
  memset(&envelope, 0, sizeof(envelope));
  envelope.kind = MESH_NODE_IPC_COMMAND_V1;
  envelope.request_id[0] = 4u;
  envelope.operation_id[0] = 5u;
  envelope.sender_incarnation[0] = 6u;
  envelope.sequence = 1u;
  envelope.desired_epoch = 2u;
  envelope.body = body;
  envelope.body_size = body_size;
  check_int_eq(mesh_node_ipc_envelope_encode_v1(
                   &envelope, frame, capacity, &frame_size),
               MESH_CONTROL_OK);
  return frame_size;
}

static size_t ack_frame(uint8_t *frame, size_t capacity) {
  mesh_node_ipc_envelope_v1_t envelope;
  size_t frame_size = 0u;
  memset(&envelope, 0, sizeof(envelope));
  envelope.kind = MESH_NODE_IPC_ACK_RESULT_V1;
  envelope.request_id[0] = 4u;
  envelope.operation_id[0] = 5u;
  envelope.sender_incarnation[0] = 7u;
  envelope.sequence = 2u;
  check_int_eq(mesh_node_ipc_envelope_encode_v1(
                   &envelope, frame, capacity, &frame_size),
               MESH_CONTROL_OK);
  return frame_size;
}

static int wait_for_pending(mesh_node_ipc_channel_v1_t *channel,
                            size_t expected) {
  mesh_node_ipc_channel_stats_v1_t stats;
  int attempt;
  for (attempt = 0; attempt < TEST_WAIT_ATTEMPTS; ++attempt) {
    if (mesh_node_ipc_channel_get_stats_v1(channel, &stats) ==
            MESH_CONTROL_OK &&
        stats.pending >= expected)
      return 1;
    turbo_sleep_ms(TEST_WAIT_STEP_MS);
  }
  return 0;
}

static int wait_for_no_route(mesh_node_ipc_flowmq_v1_t *adapter) {
  int attempt;
  for (attempt = 0; attempt < TEST_WAIT_ATTEMPTS; ++attempt) {
    if (atomic_load_explicit(&adapter->route_generation,
                             memory_order_acquire) == 0u)
      return 1;
    turbo_sleep_ms(TEST_WAIT_STEP_MS);
  }
  return 0;
}

static mesh_control_result_t pump_until_sent(
    mesh_node_ipc_flowmq_v1_t *adapter) {
  mesh_control_result_t result = MESH_CONTROL_PROVIDER_UNAVAILABLE;
  int attempt;
  for (attempt = 0; attempt < TEST_WAIT_ATTEMPTS; ++attempt) {
    size_t sent = 0u;
    result = mesh_node_ipc_flowmq_pump_send_v1(adapter, 1u, &sent);
    if (result == MESH_CONTROL_OK && sent == 1u) return MESH_CONTROL_OK;
    if (result != MESH_CONTROL_PROVIDER_UNAVAILABLE &&
        result != MESH_CONTROL_TIMEOUT &&
        result != MESH_CONTROL_RESOURCE_EXHAUSTED)
      return result;
    turbo_sleep_ms(TEST_WAIT_STEP_MS);
  }
  return result;
}

static mesh_control_result_t runtime_execute(
    void *context, const mesh_node_ipc_command_v1_t *command,
    uint64_t desired_epoch, mesh_node_ipc_execution_output_v1_t *out_execution) {
  runtime_executor_state_v1_t *state = (runtime_executor_state_v1_t *)context;
  if (!state || !command || !out_execution) return MESH_CONTROL_INVALID_ARG;
  state->calls++;
  out_execution->applied_epoch = desired_epoch;
  if (command->action == MESH_CONTROL_DESIRED_APPLY)
    memcpy(out_execution->observed_digest, command->document_digest,
           sizeof(out_execution->observed_digest));
  return MESH_CONTROL_OK;
}

static int network_control_poll_result(
    mesh_node_network_control_service_v1_t *service,
    mesh_node_control_client_runtime_v1_t *client,
    uint8_t out_operation_id[MESH_CONTROL_ID_SIZE],
    mesh_node_ipc_result_v1_t *out_result) {
  int attempt;
  for (attempt = 0; attempt < TEST_WAIT_ATTEMPTS; ++attempt) {
    size_t processed = 0u;
    size_t sent = 0u;
    mesh_control_result_t client_result =
        mesh_node_control_client_runtime_poll_v1(
            client, 4u, 4u, &processed, &sent);
    mesh_control_result_t service_result =
        mesh_node_network_control_service_poll_v1(
            service, &processed, &sent);
    int client_progress =
        client_result == MESH_CONTROL_OK ||
        client_result == MESH_CONTROL_PROVIDER_UNAVAILABLE ||
        client_result == MESH_CONTROL_TIMEOUT ||
        client_result == MESH_CONTROL_RESOURCE_EXHAUSTED;
    int service_progress =
        service_result == MESH_CONTROL_OK ||
        service_result == MESH_CONTROL_PROVIDER_UNAVAILABLE ||
        service_result == MESH_CONTROL_TIMEOUT ||
        service_result == MESH_CONTROL_RESOURCE_EXHAUSTED;
    check_true(client_progress);
    check_true(service_progress);
    if (!client_progress || !service_progress)
      return 0;
    (void)mesh_node_control_client_runtime_poll_v1(
        client, 4u, 4u, &processed, &sent);
    if (mesh_node_control_client_runtime_peek_result_v1(
            client, out_operation_id, out_result) == MESH_CONTROL_OK)
      return 1;
    turbo_sleep_ms(TEST_WAIT_STEP_MS);
  }
  return 0;
}

static int network_control_poll_until_acked(
    mesh_node_network_control_service_v1_t *service,
    mesh_node_control_client_runtime_v1_t *client) {
  int attempt;
  for (attempt = 0; attempt < TEST_WAIT_ATTEMPTS; ++attempt) {
    mesh_node_network_control_service_stats_v1_t service_stats;
    mesh_node_control_client_runtime_stats_v1_t client_stats;
    size_t processed = 0u;
    size_t sent = 0u;
    (void)mesh_node_control_client_runtime_poll_v1(
        client, 4u, 4u, &processed, &sent);
    (void)mesh_node_network_control_service_poll_v1(
        service, &processed, &sent);
    if (mesh_node_network_control_service_get_stats_v1(
            service, &service_stats) != MESH_CONTROL_OK ||
        mesh_node_control_client_runtime_get_stats_v1(
            client, &client_stats) != MESH_CONTROL_OK)
      return 0;
    if (service_stats.runtime.owner.retained_operations == 0u &&
        service_stats.runtime.outbound.pending == 0u &&
        service_stats.runtime.transport.send_pending == 0u &&
        client_stats.outbound.pending == 0u &&
        client_stats.transport.send_pending == 0u)
      return 1;
    turbo_sleep_ms(TEST_WAIT_STEP_MS);
  }
  return 0;
}

static mesh_control_result_t poll_runtime_until_processed(
    mesh_node_control_runtime_v1_t *runtime, size_t *out_sent) {
  mesh_control_result_t result = MESH_CONTROL_PROVIDER_UNAVAILABLE;
  int attempt;
  *out_sent = 0u;
  for (attempt = 0; attempt < TEST_WAIT_ATTEMPTS; ++attempt) {
    size_t processed = 0u;
    size_t sent = 0u;
    result = mesh_node_control_runtime_poll_v1(runtime, 4u, 4u, &processed,
                                               &sent);
    *out_sent += sent;
    if (result == MESH_CONTROL_OK && processed != 0u) return MESH_CONTROL_OK;
    if (result != MESH_CONTROL_OK &&
        result != MESH_CONTROL_PROVIDER_UNAVAILABLE &&
        result != MESH_CONTROL_TIMEOUT &&
        result != MESH_CONTROL_RESOURCE_EXHAUSTED)
      return result;
    turbo_sleep_ms(TEST_WAIT_STEP_MS);
  }
  return result;
}

static void configure_tls(flowmq_coronet_tls_server_config_t *server_tls,
                          flowmq_coronet_tls_client_config_t *client_tls) {
  check_int_eq(flowmq_coronet_tls_require_tls13(), TURBO_OK);
  memset(server_tls, 0, sizeof(*server_tls));
  server_tls->ca_file = MESH_TEST_FLOWMQ_CA_FILE;
  server_tls->cert_file = MESH_TEST_FLOWMQ_SERVER_CERT_FILE;
  server_tls->key_file = MESH_TEST_FLOWMQ_SERVER_KEY_FILE;
  server_tls->require_client_certificate = 1;
  memset(client_tls, 0, sizeof(*client_tls));
  client_tls->ca_file = MESH_TEST_FLOWMQ_CA_FILE;
  client_tls->cert_file = MESH_TEST_FLOWMQ_CLIENT_CERT_FILE;
  client_tls->key_file = MESH_TEST_FLOWMQ_CLIENT_KEY_FILE;
  client_tls->server_name = "localhost";
  client_tls->verify_peer = 1;
}

static void test_profile_rejects_insecure_endpoints(void) {
  unsigned short port = test_port();
  flowmq_coronet_tls_server_config_t server_tls;
  flowmq_coronet_tls_client_config_t client_tls;
  flowmq_router_endpoint_config_t server_endpoint;
  flowmq_connect_endpoint_config_t client_endpoint;
  mesh_node_ipc_flowmq_config_v1_t config;
  mesh_node_ipc_channel_v1_t inbound;
  mesh_node_ipc_channel_v1_t outbound;
  check_int_gt((int)port, 0);
  configure_tls(&server_tls, &client_tls);
  server_config(&server_endpoint, port, &server_tls);
  client_config(&client_endpoint, port, &client_tls);
  memset(&inbound, 0, sizeof(inbound));
  memset(&outbound, 0, sizeof(outbound));
  memset(&config, 0, sizeof(config));
  config.mode = MESH_NODE_IPC_FLOWMQ_BIND_V1;
  config.bind_endpoint = &server_endpoint;
  config.expected_peer_identity = "mesh-agent";
  config.expected_peer_certificate_sha256 = TEST_CLIENT_TLS_CERTIFICATE_SHA256;
  config.identity_policy_generation = TEST_IDENTITY_POLICY_GENERATION;
  config.inbound = &inbound;
  config.outbound = &outbound;
  check_int_eq(mesh_node_ipc_flowmq_profile_validate_v1(&config),
               MESH_CONTROL_OK);
  server_tls.require_client_certificate = 0;
  check_int_eq(mesh_node_ipc_flowmq_profile_validate_v1(&config),
               MESH_CONTROL_INVALID_ARG);
  server_tls.require_client_certificate = 1;
  server_endpoint.host = "0.0.0.0";
  check_int_eq(mesh_node_ipc_flowmq_profile_validate_v1(&config),
               MESH_CONTROL_INVALID_ARG);
  server_endpoint.host = "127.0.0.1";
  config.expected_peer_certificate_sha256 =
      "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  check_int_eq(mesh_node_ipc_flowmq_profile_validate_v1(&config),
               MESH_CONTROL_INVALID_ARG);
  config.expected_peer_certificate_sha256 = TEST_CLIENT_TLS_CERTIFICATE_SHA256;
  config.expected_peer_certificate_sha256_next = "sha256:bad";
  check_int_eq(mesh_node_ipc_flowmq_profile_validate_v1(&config),
               MESH_CONTROL_INVALID_ARG);
  config.expected_peer_certificate_sha256_next = NULL;
  config.identity_policy_generation = 0u;
  check_int_eq(mesh_node_ipc_flowmq_profile_validate_v1(&config),
               MESH_CONTROL_INVALID_ARG);
  config.identity_policy_generation = TEST_IDENTITY_POLICY_GENERATION;
  config.mode = MESH_NODE_IPC_FLOWMQ_CONNECT_V1;
  config.bind_endpoint = NULL;
  config.connect_endpoint = &client_endpoint;
  config.expected_peer_identity = "meshd";
  config.expected_peer_certificate_sha256 = TEST_SERVER_TLS_CERTIFICATE_SHA256;
  check_int_eq(mesh_node_ipc_flowmq_profile_validate_v1(&config),
               MESH_CONTROL_OK);
  client_tls.verify_peer = 0;
  check_int_eq(mesh_node_ipc_flowmq_profile_validate_v1(&config),
               MESH_CONTROL_INVALID_ARG);
  client_tls.verify_peer = 1;
  client_tls.cert_file = NULL;
  check_int_eq(mesh_node_ipc_flowmq_profile_validate_v1(&config),
               MESH_CONTROL_INVALID_ARG);
}

static void test_secure_router_dealer_and_runtime(void) {
  unsigned short port = test_port();
  flowmq_coronet_tls_server_config_t server_tls;
  flowmq_coronet_tls_client_config_t client_tls;
  flowmq_router_endpoint_config_t server_endpoint;
  flowmq_connect_endpoint_config_t client_endpoint;
  mesh_node_ipc_channel_v1_t server_inbound;
  mesh_node_ipc_channel_v1_t server_outbound;
  mesh_node_ipc_channel_v1_t client_inbound;
  mesh_node_ipc_channel_v1_t client_outbound;
  mesh_node_ipc_flowmq_v1_t server;
  mesh_node_ipc_flowmq_v1_t client;
  mesh_node_ipc_flowmq_config_v1_t adapter_config;
  mesh_node_ipc_frame_view_v1_t view;
  mesh_node_ipc_channel_stats_v1_t channel_stats;
  mesh_node_ipc_flowmq_stats_v1_t transport_stats;
  uint8_t frame[512];
  size_t frame_size;

  check_int_gt((int)port, 0);
  configure_tls(&server_tls, &client_tls);
  server_config(&server_endpoint, port, &server_tls);
  client_config(&client_endpoint, port, &client_tls);
  memset(&server_inbound, 0, sizeof(server_inbound));
  memset(&server_outbound, 0, sizeof(server_outbound));
  memset(&client_inbound, 0, sizeof(client_inbound));
  memset(&client_outbound, 0, sizeof(client_outbound));
  memset(&server, 0, sizeof(server));
  memset(&client, 0, sizeof(client));
  check_int_eq(mesh_node_ipc_channel_init_v1(
                   &server_inbound, 8u, TEST_FRAME_HWM_BYTES,
                   MESH_NODE_IPC_MAX_FRAME_SIZE_V1), MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_channel_init_v1(
                   &server_outbound, 8u, TEST_FRAME_HWM_BYTES,
                   MESH_NODE_IPC_MAX_FRAME_SIZE_V1), MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_channel_init_v1(
                   &client_inbound, 8u, TEST_FRAME_HWM_BYTES,
                   MESH_NODE_IPC_MAX_FRAME_SIZE_V1), MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_channel_init_v1(
                   &client_outbound, 8u, TEST_FRAME_HWM_BYTES,
                   MESH_NODE_IPC_MAX_FRAME_SIZE_V1), MESH_CONTROL_OK);

  memset(&adapter_config, 0, sizeof(adapter_config));
  adapter_config.mode = MESH_NODE_IPC_FLOWMQ_BIND_V1;
  adapter_config.bind_endpoint = &server_endpoint;
  adapter_config.expected_peer_identity = "mesh-agent";
  adapter_config.expected_peer_certificate_sha256 =
      TEST_CLIENT_TLS_CERTIFICATE_SHA256;
  adapter_config.identity_policy_generation =
      TEST_IDENTITY_POLICY_GENERATION;
  adapter_config.inbound = &server_inbound;
  adapter_config.outbound = &server_outbound;
  check_int_eq(mesh_node_ipc_flowmq_init_v1(&server, &adapter_config),
               MESH_CONTROL_OK);
  check_uint_eq(flowmq_tls_identity_map_generation(server.identity_map),
                TEST_IDENTITY_POLICY_GENERATION);
  memset(&adapter_config, 0, sizeof(adapter_config));
  adapter_config.mode = MESH_NODE_IPC_FLOWMQ_CONNECT_V1;
  adapter_config.connect_endpoint = &client_endpoint;
  adapter_config.expected_peer_identity = "meshd";
  adapter_config.expected_peer_certificate_sha256 =
      TEST_SERVER_TLS_CERTIFICATE_SHA256;
  adapter_config.identity_policy_generation =
      TEST_IDENTITY_POLICY_GENERATION;
  adapter_config.inbound = &client_inbound;
  adapter_config.outbound = &client_outbound;
  check_int_eq(mesh_node_ipc_flowmq_init_v1(&client, &adapter_config),
               MESH_CONTROL_OK);
  check_uint_eq(flowmq_tls_identity_map_generation(client.identity_map),
                TEST_IDENTITY_POLICY_GENERATION);
  check_int_eq(mesh_node_ipc_flowmq_start_v1(&server), MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_flowmq_start_v1(&client), MESH_CONTROL_OK);

  frame_size = command_frame(frame, sizeof(frame));
  check_int_eq(mesh_node_ipc_channel_try_push_v1(
                   &server_outbound, frame, frame_size), MESH_CONTROL_OK);
  {
    size_t sent = 1u;
    check_int_eq(mesh_node_ipc_flowmq_pump_send_v1(&server, 1u, &sent),
                 MESH_CONTROL_PROVIDER_UNAVAILABLE);
    check_size_eq(sent, 0u);
  }
  check_int_eq(mesh_node_ipc_channel_get_stats_v1(&server_outbound,
                                                   &channel_stats),
               MESH_CONTROL_OK);
  check_size_eq(channel_stats.pending, 1u);
  check_int_eq(mesh_node_ipc_flowmq_stop_v1(&server),
               MESH_CONTROL_RESOURCE_EXHAUSTED);

  check_int_eq(mesh_node_ipc_channel_try_push_v1(
                   &client_outbound, frame, frame_size), MESH_CONTROL_OK);
  check_int_eq(pump_until_sent(&client), MESH_CONTROL_OK);
  check_true(wait_for_pending(&server_inbound, 1u));
  check_int_eq(mesh_node_ipc_channel_peek_v1(&server_inbound, &view),
               MESH_CONTROL_OK);
  check_mem_eq(view.frame, frame, frame_size);
  check_int_eq(mesh_node_ipc_channel_consume_v1(&server_inbound),
               MESH_CONTROL_OK);
  check_int_eq(pump_until_sent(&server), MESH_CONTROL_OK);
  check_true(wait_for_pending(&client_inbound, 1u));
  check_int_eq(mesh_node_ipc_channel_consume_v1(&client_inbound),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_flowmq_get_stats_v1(&client,
                                                  &transport_stats),
               MESH_CONTROL_OK);
  check_size_eq(transport_stats.send_pending, 0u);
  check_size_eq(transport_stats.send_high_water, 1u);
  check_uint_eq(transport_stats.send_completed, 1u);
  check_uint_eq(transport_stats.send_admission_failed, 0u);

  check_int_eq(mesh_node_ipc_flowmq_stop_v1(&client), MESH_CONTROL_OK);
  mesh_node_ipc_flowmq_destroy_v1(&client);
  mesh_node_ipc_channel_destroy_v1(&client_outbound);
  mesh_node_ipc_channel_destroy_v1(&client_inbound);
  check_true(wait_for_no_route(&server));

  check_int_eq(mesh_node_ipc_channel_try_push_v1(
                   &server_outbound, frame, frame_size), MESH_CONTROL_OK);
  {
    size_t sent = 1u;
    check_int_eq(mesh_node_ipc_flowmq_pump_send_v1(&server, 1u, &sent),
                 MESH_CONTROL_PROVIDER_UNAVAILABLE);
    check_size_eq(sent, 0u);
  }
  check_int_eq(mesh_node_ipc_channel_get_stats_v1(&server_outbound,
                                                   &channel_stats),
               MESH_CONTROL_OK);
  check_size_eq(channel_stats.pending, 1u);

  memset(&client_inbound, 0, sizeof(client_inbound));
  memset(&client_outbound, 0, sizeof(client_outbound));
  check_int_eq(mesh_node_ipc_channel_init_v1(
                   &client_inbound, 8u, TEST_FRAME_HWM_BYTES,
                   MESH_NODE_IPC_MAX_FRAME_SIZE_V1), MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_channel_init_v1(
                   &client_outbound, 8u, TEST_FRAME_HWM_BYTES,
                   MESH_NODE_IPC_MAX_FRAME_SIZE_V1), MESH_CONTROL_OK);
  memset(&adapter_config, 0, sizeof(adapter_config));
  adapter_config.mode = MESH_NODE_IPC_FLOWMQ_CONNECT_V1;
  adapter_config.connect_endpoint = &client_endpoint;
  adapter_config.expected_peer_identity = "meshd";
  adapter_config.expected_peer_certificate_sha256 =
      TEST_SERVER_TLS_CERTIFICATE_SHA256;
  adapter_config.identity_policy_generation =
      TEST_IDENTITY_POLICY_GENERATION;
  adapter_config.inbound = &client_inbound;
  adapter_config.outbound = &client_outbound;
  check_int_eq(mesh_node_ipc_flowmq_init_v1(&client, &adapter_config),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_flowmq_start_v1(&client), MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_channel_try_push_v1(
                   &client_outbound, frame, frame_size), MESH_CONTROL_OK);
  check_int_eq(pump_until_sent(&client), MESH_CONTROL_OK);
  check_true(wait_for_pending(&server_inbound, 1u));
  check_int_eq(mesh_node_ipc_channel_consume_v1(&server_inbound),
               MESH_CONTROL_OK);
  check_int_eq(pump_until_sent(&server), MESH_CONTROL_OK);
  check_true(wait_for_pending(&client_inbound, 1u));
  check_int_eq(mesh_node_ipc_channel_consume_v1(&client_inbound),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_flowmq_get_stats_v1(&server,
                                                  &transport_stats),
               MESH_CONTROL_OK);
  check_size_eq(transport_stats.send_pending, 0u);
  check_size_eq(transport_stats.send_high_water, 1u);
  check_uint_eq(transport_stats.send_completed, 2u);
  check_uint_eq(transport_stats.send_admission_failed, 0u);

  check_int_eq(mesh_node_ipc_flowmq_stop_v1(&client), MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_flowmq_stop_v1(&server), MESH_CONTROL_OK);
  mesh_node_ipc_flowmq_destroy_v1(&client);
  mesh_node_ipc_flowmq_destroy_v1(&server);
  mesh_node_ipc_channel_destroy_v1(&client_outbound);
  mesh_node_ipc_channel_destroy_v1(&client_inbound);
  mesh_node_ipc_channel_destroy_v1(&server_outbound);
  mesh_node_ipc_channel_destroy_v1(&server_inbound);

  {
    mesh_node_control_runtime_v1_t runtime;
    mesh_node_control_runtime_config_v1_t runtime_config;
    mesh_node_control_runtime_stats_v1_t runtime_stats;
    runtime_executor_state_v1_t executor = {0u};
    port = test_port();
    server_config(&server_endpoint, port, &server_tls);
    client_config(&client_endpoint, port, &client_tls);
    memset(&runtime, 0, sizeof(runtime));
    memset(&client, 0, sizeof(client));
    memset(&client_inbound, 0, sizeof(client_inbound));
    memset(&client_outbound, 0, sizeof(client_outbound));
    check_int_eq(mesh_node_ipc_channel_init_v1(
                     &client_inbound, 8u, TEST_FRAME_HWM_BYTES,
                     MESH_NODE_IPC_MAX_FRAME_SIZE_V1), MESH_CONTROL_OK);
    check_int_eq(mesh_node_ipc_channel_init_v1(
                     &client_outbound, 8u, TEST_FRAME_HWM_BYTES,
                     MESH_NODE_IPC_MAX_FRAME_SIZE_V1), MESH_CONTROL_OK);
    memset(&adapter_config, 0, sizeof(adapter_config));
    adapter_config.mode = MESH_NODE_IPC_FLOWMQ_CONNECT_V1;
    adapter_config.connect_endpoint = &client_endpoint;
    adapter_config.expected_peer_identity = "meshd";
    adapter_config.expected_peer_certificate_sha256 =
        TEST_SERVER_TLS_CERTIFICATE_SHA256;
    adapter_config.identity_policy_generation =
        TEST_IDENTITY_POLICY_GENERATION;
    adapter_config.inbound = &client_inbound;
    adapter_config.outbound = &client_outbound;
    check_int_eq(mesh_node_ipc_flowmq_init_v1(&client, &adapter_config),
                 MESH_CONTROL_OK);
    memset(&runtime_config, 0, sizeof(runtime_config));
    runtime_config.mode = MESH_NODE_IPC_FLOWMQ_BIND_V1;
    runtime_config.bind_endpoint = &server_endpoint;
    runtime_config.expected_peer_identity = "mesh-agent";
    runtime_config.expected_peer_certificate_sha256 =
        TEST_CLIENT_TLS_CERTIFICATE_SHA256;
    runtime_config.identity_policy_generation =
        TEST_IDENTITY_POLICY_GENERATION;
    runtime_config.execute = runtime_execute;
    runtime_config.execute_context = &executor;
    runtime_config.mesh_id[0] = 1u;
    runtime_config.provider_id[0] = 3u;
    runtime_config.sender_incarnation[0] = 8u;
    runtime_config.allowed_resource_mask =
        UINT64_C(1) << MESH_CONTROL_RESOURCE_NETWORK;
    runtime_config.operation_capacity = 8u;
    runtime_config.channel_capacity = 8u;
    runtime_config.channel_max_retained_bytes = TEST_FRAME_HWM_BYTES;
    check_int_eq(mesh_node_control_runtime_init_v1(&runtime, &runtime_config),
                 MESH_CONTROL_OK);
    check_int_eq(mesh_node_control_runtime_start_v1(&runtime), MESH_CONTROL_OK);
    check_int_eq(mesh_node_ipc_flowmq_start_v1(&client), MESH_CONTROL_OK);
    frame_size = command_frame(frame, sizeof(frame));
    check_int_eq(mesh_node_ipc_channel_try_push_v1(
                     &client_outbound, frame, frame_size), MESH_CONTROL_OK);
    check_int_eq(pump_until_sent(&client), MESH_CONTROL_OK);
    {
      size_t sent = 0u;
      check_int_eq(poll_runtime_until_processed(&runtime, &sent),
                   MESH_CONTROL_OK);
      check_size_eq(sent, 2u);
    }
    check_true(wait_for_pending(&client_inbound, 2u));
    check_int_eq(mesh_node_ipc_channel_peek_v1(&client_inbound, &view),
                 MESH_CONTROL_OK);
    check_uint_eq(view.envelope.kind, MESH_NODE_IPC_ACCEPTED_V1);
    check_int_eq(mesh_node_ipc_channel_consume_v1(&client_inbound),
                 MESH_CONTROL_OK);
    check_int_eq(mesh_node_ipc_channel_peek_v1(&client_inbound, &view),
                 MESH_CONTROL_OK);
    check_uint_eq(view.envelope.kind, MESH_NODE_IPC_RESULT_V1);
    check_int_eq(mesh_node_ipc_channel_consume_v1(&client_inbound),
                 MESH_CONTROL_OK);
    check_size_eq(executor.calls, 1u);
    frame_size = ack_frame(frame, sizeof(frame));
    check_int_eq(mesh_node_ipc_channel_try_push_v1(
                     &client_outbound, frame, frame_size), MESH_CONTROL_OK);
    check_int_eq(pump_until_sent(&client), MESH_CONTROL_OK);
    {
      size_t sent = 0u;
      check_int_eq(poll_runtime_until_processed(&runtime, &sent),
                   MESH_CONTROL_OK);
    }
    check_int_eq(mesh_node_control_runtime_get_stats_v1(&runtime,
                                                         &runtime_stats),
                 MESH_CONTROL_OK);
    check_size_eq(runtime_stats.owner.retained_operations, 0u);
    check_uint_eq(runtime_stats.owner.results_acked, 1u);
    check_int_eq(mesh_node_control_runtime_begin_drain_v1(&runtime),
                 MESH_CONTROL_OK);
    check_int_eq(mesh_node_control_runtime_stop_v1(&runtime), MESH_CONTROL_OK);
    check_int_eq(mesh_node_ipc_flowmq_stop_v1(&client), MESH_CONTROL_OK);
    mesh_node_ipc_flowmq_destroy_v1(&client);
    mesh_node_control_runtime_destroy_v1(&runtime);
    mesh_node_ipc_channel_destroy_v1(&client_outbound);
    mesh_node_ipc_channel_destroy_v1(&client_inbound);
  }
}

static void test_rejects_disallowed_peer(
    enum test_rejected_peer_scenario_v1 scenario) {
  unsigned short port = test_port();
  flowmq_coronet_tls_server_config_t server_tls;
  flowmq_coronet_tls_client_config_t client_tls;
  flowmq_router_endpoint_config_t server_endpoint;
  flowmq_connect_endpoint_config_t client_endpoint;
  mesh_node_ipc_channel_v1_t server_inbound = {0};
  mesh_node_ipc_channel_v1_t server_outbound = {0};
  mesh_node_ipc_channel_v1_t client_inbound = {0};
  mesh_node_ipc_channel_v1_t client_outbound = {0};
  mesh_node_ipc_flowmq_v1_t server = {0};
  mesh_node_ipc_flowmq_v1_t client = {0};
  mesh_node_ipc_flowmq_config_v1_t adapter_config;
  mesh_node_ipc_channel_stats_v1_t stats;
  const char *expected_client_certificate =
      TEST_CLIENT_TLS_CERTIFICATE_SHA256;
  const char *expected_server_certificate =
      TEST_SERVER_TLS_CERTIFICATE_SHA256;

  check_int_gt((int)port, 0);
  configure_tls(&server_tls, &client_tls);
  switch (scenario) {
    case TEST_REJECT_REMOVED_SERVER_CERTIFICATE_V1:
      expected_server_certificate = TEST_SERVER_NEXT_TLS_CERTIFICATE_SHA256;
      break;
    case TEST_REJECT_REMOVED_CLIENT_CERTIFICATE_V1:
      expected_client_certificate = TEST_CLIENT_NEXT_TLS_CERTIFICATE_SHA256;
      break;
    case TEST_REJECT_SERVER_CLIENT_AUTH_EKU_V1:
      server_tls.cert_file =
          MESH_TEST_FLOWMQ_SERVER_CLIENT_AUTH_ONLY_CERT_FILE;
      server_tls.key_file = MESH_TEST_FLOWMQ_SERVER_CLIENT_AUTH_ONLY_KEY_FILE;
      expected_server_certificate =
          TEST_SERVER_CLIENT_AUTH_ONLY_CERTIFICATE_SHA256;
      break;
    case TEST_REJECT_CLIENT_SERVER_AUTH_EKU_V1:
      client_tls.cert_file = MESH_TEST_FLOWMQ_SERVER_CERT_FILE;
      client_tls.key_file = MESH_TEST_FLOWMQ_SERVER_KEY_FILE;
      expected_client_certificate = TEST_SERVER_TLS_CERTIFICATE_SHA256;
      break;
    default:
      check_true(0);
      return;
  }
  server_config(&server_endpoint, port, &server_tls);
  client_config(&client_endpoint, port, &client_tls);
  client_endpoint.timeouts.send_timeout_ms = 250u;
  check_int_eq(mesh_node_ipc_channel_init_v1(
                   &server_inbound, 2u, TEST_FRAME_HWM_BYTES,
                   MESH_NODE_IPC_MAX_FRAME_SIZE_V1), MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_channel_init_v1(
                   &server_outbound, 2u, TEST_FRAME_HWM_BYTES,
                   MESH_NODE_IPC_MAX_FRAME_SIZE_V1), MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_channel_init_v1(
                   &client_inbound, 2u, TEST_FRAME_HWM_BYTES,
                   MESH_NODE_IPC_MAX_FRAME_SIZE_V1), MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_channel_init_v1(
                   &client_outbound, 2u, TEST_FRAME_HWM_BYTES,
                   MESH_NODE_IPC_MAX_FRAME_SIZE_V1), MESH_CONTROL_OK);

  memset(&adapter_config, 0, sizeof(adapter_config));
  adapter_config.mode = MESH_NODE_IPC_FLOWMQ_BIND_V1;
  adapter_config.bind_endpoint = &server_endpoint;
  adapter_config.expected_peer_identity = "mesh-agent";
  adapter_config.expected_peer_certificate_sha256 =
      expected_client_certificate;
  adapter_config.identity_policy_generation =
      TEST_IDENTITY_POLICY_GENERATION;
  adapter_config.inbound = &server_inbound;
  adapter_config.outbound = &server_outbound;
  check_int_eq(mesh_node_ipc_flowmq_init_v1(&server, &adapter_config),
               MESH_CONTROL_OK);
  check_uint_eq(flowmq_tls_identity_map_generation(server.identity_map),
                TEST_IDENTITY_POLICY_GENERATION);

  memset(&adapter_config, 0, sizeof(adapter_config));
  adapter_config.mode = MESH_NODE_IPC_FLOWMQ_CONNECT_V1;
  adapter_config.connect_endpoint = &client_endpoint;
  adapter_config.expected_peer_identity = "meshd";
  adapter_config.expected_peer_certificate_sha256 =
      expected_server_certificate;
  adapter_config.identity_policy_generation =
      TEST_IDENTITY_POLICY_GENERATION;
  adapter_config.inbound = &client_inbound;
  adapter_config.outbound = &client_outbound;
  check_int_eq(mesh_node_ipc_flowmq_init_v1(&client, &adapter_config),
               MESH_CONTROL_OK);
  check_uint_eq(flowmq_tls_identity_map_generation(client.identity_map),
                TEST_IDENTITY_POLICY_GENERATION);
  check_int_eq(mesh_node_ipc_flowmq_start_v1(&server), MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_flowmq_start_v1(&client), MESH_CONTROL_TIMEOUT);
  check_int_eq(mesh_node_ipc_channel_get_stats_v1(&client_inbound, &stats),
               MESH_CONTROL_OK);
  check_size_eq(stats.pending, 0u);

  mesh_node_ipc_flowmq_destroy_v1(&client);
  mesh_node_ipc_flowmq_destroy_v1(&server);
  mesh_node_ipc_channel_destroy_v1(&client_outbound);
  mesh_node_ipc_channel_destroy_v1(&client_inbound);
  mesh_node_ipc_channel_destroy_v1(&server_outbound);
  mesh_node_ipc_channel_destroy_v1(&server_inbound);
}

static void test_accepts_certificate_during_explicit_rotation_overlap(void) {
  unsigned short port = test_port();
  flowmq_coronet_tls_server_config_t server_tls;
  flowmq_coronet_tls_client_config_t client_tls;
  flowmq_router_endpoint_config_t server_endpoint;
  flowmq_connect_endpoint_config_t client_endpoint;
  mesh_node_ipc_channel_v1_t server_inbound = {0};
  mesh_node_ipc_channel_v1_t server_outbound = {0};
  mesh_node_ipc_channel_v1_t client_inbound = {0};
  mesh_node_ipc_channel_v1_t client_outbound = {0};
  mesh_node_ipc_flowmq_v1_t server = {0};
  mesh_node_ipc_flowmq_v1_t client = {0};
  mesh_node_ipc_flowmq_config_v1_t adapter_config;
  uint8_t frame[512];
  size_t frame_size;

  check_int_gt((int)port, 0);
  configure_tls(&server_tls, &client_tls);
  server_tls.cert_file = MESH_TEST_FLOWMQ_SERVER_NEXT_CERT_FILE;
  server_tls.key_file = MESH_TEST_FLOWMQ_SERVER_NEXT_KEY_FILE;
  client_tls.cert_file = MESH_TEST_FLOWMQ_CLIENT_NEXT_CERT_FILE;
  client_tls.key_file = MESH_TEST_FLOWMQ_CLIENT_NEXT_KEY_FILE;
  server_config(&server_endpoint, port, &server_tls);
  client_config(&client_endpoint, port, &client_tls);
  check_int_eq(mesh_node_ipc_channel_init_v1(
                   &server_inbound, 2u, TEST_FRAME_HWM_BYTES,
                   MESH_NODE_IPC_MAX_FRAME_SIZE_V1), MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_channel_init_v1(
                   &server_outbound, 2u, TEST_FRAME_HWM_BYTES,
                   MESH_NODE_IPC_MAX_FRAME_SIZE_V1), MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_channel_init_v1(
                   &client_inbound, 2u, TEST_FRAME_HWM_BYTES,
                   MESH_NODE_IPC_MAX_FRAME_SIZE_V1), MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_channel_init_v1(
                   &client_outbound, 2u, TEST_FRAME_HWM_BYTES,
                   MESH_NODE_IPC_MAX_FRAME_SIZE_V1), MESH_CONTROL_OK);

  memset(&adapter_config, 0, sizeof(adapter_config));
  adapter_config.mode = MESH_NODE_IPC_FLOWMQ_BIND_V1;
  adapter_config.bind_endpoint = &server_endpoint;
  adapter_config.expected_peer_identity = "mesh-agent";
  adapter_config.expected_peer_certificate_sha256 =
      TEST_CLIENT_TLS_CERTIFICATE_SHA256;
  adapter_config.expected_peer_certificate_sha256_next =
      TEST_CLIENT_NEXT_TLS_CERTIFICATE_SHA256;
  adapter_config.identity_policy_generation =
      TEST_IDENTITY_POLICY_GENERATION + 1u;
  adapter_config.inbound = &server_inbound;
  adapter_config.outbound = &server_outbound;
  check_int_eq(mesh_node_ipc_flowmq_init_v1(&server, &adapter_config),
               MESH_CONTROL_OK);
  check_uint_eq(flowmq_tls_identity_map_generation(server.identity_map),
                TEST_IDENTITY_POLICY_GENERATION + 1u);

  memset(&adapter_config, 0, sizeof(adapter_config));
  adapter_config.mode = MESH_NODE_IPC_FLOWMQ_CONNECT_V1;
  adapter_config.connect_endpoint = &client_endpoint;
  adapter_config.expected_peer_identity = "meshd";
  adapter_config.expected_peer_certificate_sha256 =
      TEST_SERVER_TLS_CERTIFICATE_SHA256;
  adapter_config.expected_peer_certificate_sha256_next =
      TEST_SERVER_NEXT_TLS_CERTIFICATE_SHA256;
  adapter_config.identity_policy_generation =
      TEST_IDENTITY_POLICY_GENERATION + 1u;
  adapter_config.inbound = &client_inbound;
  adapter_config.outbound = &client_outbound;
  check_int_eq(mesh_node_ipc_flowmq_init_v1(&client, &adapter_config),
               MESH_CONTROL_OK);
  check_uint_eq(flowmq_tls_identity_map_generation(client.identity_map),
                TEST_IDENTITY_POLICY_GENERATION + 1u);
  check_int_eq(mesh_node_ipc_flowmq_start_v1(&server), MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_flowmq_start_v1(&client), MESH_CONTROL_OK);

  frame_size = command_frame(frame, sizeof(frame));
  check_int_eq(mesh_node_ipc_channel_try_push_v1(
                   &client_outbound, frame, frame_size), MESH_CONTROL_OK);
  check_int_eq(pump_until_sent(&client), MESH_CONTROL_OK);
  check_true(wait_for_pending(&server_inbound, 1u));
  check_int_eq(mesh_node_ipc_channel_consume_v1(&server_inbound),
               MESH_CONTROL_OK);

  check_int_eq(mesh_node_ipc_flowmq_stop_v1(&client), MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_flowmq_stop_v1(&server), MESH_CONTROL_OK);
  mesh_node_ipc_flowmq_destroy_v1(&client);
  mesh_node_ipc_flowmq_destroy_v1(&server);
  mesh_node_ipc_channel_destroy_v1(&client_outbound);
  mesh_node_ipc_channel_destroy_v1(&client_inbound);
  mesh_node_ipc_channel_destroy_v1(&server_outbound);
  mesh_node_ipc_channel_destroy_v1(&server_inbound);
}

static void test_client_reauthenticates_after_server_restart(void) {
  unsigned short port = test_port();
  flowmq_coronet_tls_server_config_t server_tls;
  flowmq_coronet_tls_client_config_t client_tls;
  flowmq_router_endpoint_config_t server_endpoint;
  flowmq_connect_endpoint_config_t client_endpoint;
  mesh_node_ipc_channel_v1_t server_inbound = {0};
  mesh_node_ipc_channel_v1_t server_outbound = {0};
  mesh_node_ipc_channel_v1_t client_inbound = {0};
  mesh_node_ipc_channel_v1_t client_outbound = {0};
  mesh_node_ipc_flowmq_v1_t server = {0};
  mesh_node_ipc_flowmq_v1_t client = {0};
  mesh_node_ipc_flowmq_config_v1_t adapter_config;
  uint8_t frame[512];
  size_t frame_size;

  check_int_gt((int)port, 0);
  configure_tls(&server_tls, &client_tls);
  server_config(&server_endpoint, port, &server_tls);
  client_config(&client_endpoint, port, &client_tls);
  check_int_eq(mesh_node_ipc_channel_init_v1(
                   &server_inbound, 2u, TEST_FRAME_HWM_BYTES,
                   MESH_NODE_IPC_MAX_FRAME_SIZE_V1), MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_channel_init_v1(
                   &server_outbound, 2u, TEST_FRAME_HWM_BYTES,
                   MESH_NODE_IPC_MAX_FRAME_SIZE_V1), MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_channel_init_v1(
                   &client_inbound, 2u, TEST_FRAME_HWM_BYTES,
                   MESH_NODE_IPC_MAX_FRAME_SIZE_V1), MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_channel_init_v1(
                   &client_outbound, 2u, TEST_FRAME_HWM_BYTES,
                   MESH_NODE_IPC_MAX_FRAME_SIZE_V1), MESH_CONTROL_OK);

  memset(&adapter_config, 0, sizeof(adapter_config));
  adapter_config.mode = MESH_NODE_IPC_FLOWMQ_BIND_V1;
  adapter_config.bind_endpoint = &server_endpoint;
  adapter_config.expected_peer_identity = "mesh-agent";
  adapter_config.expected_peer_certificate_sha256 =
      TEST_CLIENT_TLS_CERTIFICATE_SHA256;
  adapter_config.identity_policy_generation =
      TEST_IDENTITY_POLICY_GENERATION;
  adapter_config.inbound = &server_inbound;
  adapter_config.outbound = &server_outbound;
  check_int_eq(mesh_node_ipc_flowmq_init_v1(&server, &adapter_config),
               MESH_CONTROL_OK);

  memset(&adapter_config, 0, sizeof(adapter_config));
  adapter_config.mode = MESH_NODE_IPC_FLOWMQ_CONNECT_V1;
  adapter_config.connect_endpoint = &client_endpoint;
  adapter_config.expected_peer_identity = "meshd";
  adapter_config.expected_peer_certificate_sha256 =
      TEST_SERVER_TLS_CERTIFICATE_SHA256;
  adapter_config.identity_policy_generation =
      TEST_IDENTITY_POLICY_GENERATION;
  adapter_config.inbound = &client_inbound;
  adapter_config.outbound = &client_outbound;
  check_int_eq(mesh_node_ipc_flowmq_init_v1(&client, &adapter_config),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_flowmq_start_v1(&server), MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_flowmq_start_v1(&client), MESH_CONTROL_OK);

  check_int_eq(mesh_node_ipc_flowmq_stop_v1(&server), MESH_CONTROL_OK);
  mesh_node_ipc_flowmq_destroy_v1(&server);
  mesh_node_ipc_channel_destroy_v1(&server_outbound);
  mesh_node_ipc_channel_destroy_v1(&server_inbound);
  memset(&server_inbound, 0, sizeof(server_inbound));
  memset(&server_outbound, 0, sizeof(server_outbound));
  check_int_eq(mesh_node_ipc_channel_init_v1(
                   &server_inbound, 2u, TEST_FRAME_HWM_BYTES,
                   MESH_NODE_IPC_MAX_FRAME_SIZE_V1), MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_channel_init_v1(
                   &server_outbound, 2u, TEST_FRAME_HWM_BYTES,
                   MESH_NODE_IPC_MAX_FRAME_SIZE_V1), MESH_CONTROL_OK);
  memset(&adapter_config, 0, sizeof(adapter_config));
  adapter_config.mode = MESH_NODE_IPC_FLOWMQ_BIND_V1;
  adapter_config.bind_endpoint = &server_endpoint;
  adapter_config.expected_peer_identity = "mesh-agent";
  adapter_config.expected_peer_certificate_sha256 =
      TEST_CLIENT_TLS_CERTIFICATE_SHA256;
  adapter_config.identity_policy_generation =
      TEST_IDENTITY_POLICY_GENERATION;
  adapter_config.inbound = &server_inbound;
  adapter_config.outbound = &server_outbound;
  check_int_eq(mesh_node_ipc_flowmq_init_v1(&server, &adapter_config),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_flowmq_start_v1(&server), MESH_CONTROL_OK);

  frame_size = command_frame(frame, sizeof(frame));
  check_int_eq(mesh_node_ipc_channel_try_push_v1(
                   &client_outbound, frame, frame_size), MESH_CONTROL_OK);
  check_int_eq(pump_until_sent(&client), MESH_CONTROL_OK);
  check_true(wait_for_pending(&server_inbound, 1u));
  check_int_eq(mesh_node_ipc_channel_consume_v1(&server_inbound),
               MESH_CONTROL_OK);

  check_int_eq(mesh_node_ipc_flowmq_stop_v1(&client), MESH_CONTROL_OK);
  check_int_eq(mesh_node_ipc_flowmq_stop_v1(&server), MESH_CONTROL_OK);
  mesh_node_ipc_flowmq_destroy_v1(&client);
  mesh_node_ipc_flowmq_destroy_v1(&server);
  mesh_node_ipc_channel_destroy_v1(&client_outbound);
  mesh_node_ipc_channel_destroy_v1(&client_inbound);
  mesh_node_ipc_channel_destroy_v1(&server_outbound);
  mesh_node_ipc_channel_destroy_v1(&server_inbound);
}

static void test_client_and_server_runtimes_complete_exact_ack(void) {
  unsigned short port = test_port();
  flowmq_coronet_tls_server_config_t server_tls;
  flowmq_coronet_tls_client_config_t client_tls;
  flowmq_router_endpoint_config_t server_endpoint;
  flowmq_connect_endpoint_config_t client_endpoint;
  mesh_node_control_runtime_v1_t server_runtime;
  mesh_node_control_runtime_config_v1_t server_config_v1;
  mesh_node_control_client_runtime_v1_t client_runtime;
  mesh_node_control_client_runtime_config_v1_t client_config_v1;
  mesh_node_control_runtime_stats_v1_t server_stats;
  mesh_node_control_client_runtime_stats_v1_t client_stats;
  mesh_node_ipc_command_v1_t command;
  mesh_node_ipc_result_v1_t result;
  runtime_executor_state_v1_t executor = {0u};
  uint8_t request_id[MESH_CONTROL_ID_SIZE] = {0u};
  uint8_t operation_id[MESH_CONTROL_ID_SIZE] = {0u};
  uint8_t returned_operation_id[MESH_CONTROL_ID_SIZE];
  int attempt;
  int result_ready = 0;

  memset(&result, 0, sizeof(result));
  memset(returned_operation_id, 0, sizeof(returned_operation_id));
  check_int_gt((int)port, 0);
  configure_tls(&server_tls, &client_tls);
  server_config(&server_endpoint, port, &server_tls);
  client_config(&client_endpoint, port, &client_tls);
  memset(&server_runtime, 0, sizeof(server_runtime));
  memset(&client_runtime, 0, sizeof(client_runtime));
  memset(&server_config_v1, 0, sizeof(server_config_v1));
  server_config_v1.mode = MESH_NODE_IPC_FLOWMQ_BIND_V1;
  server_config_v1.bind_endpoint = &server_endpoint;
  server_config_v1.expected_peer_identity = "mesh-agent";
  server_config_v1.expected_peer_certificate_sha256 =
      TEST_CLIENT_TLS_CERTIFICATE_SHA256;
  server_config_v1.identity_policy_generation =
      TEST_IDENTITY_POLICY_GENERATION;
  server_config_v1.execute = runtime_execute;
  server_config_v1.execute_context = &executor;
  server_config_v1.mesh_id[0] = 1u;
  server_config_v1.provider_id[0] = 3u;
  server_config_v1.sender_incarnation[0] = 8u;
  server_config_v1.allowed_resource_mask =
      UINT64_C(1) << MESH_CONTROL_RESOURCE_NETWORK;
  server_config_v1.operation_capacity = 8u;
  server_config_v1.channel_capacity = 8u;
  server_config_v1.channel_max_retained_bytes = TEST_FRAME_HWM_BYTES;

  memset(&client_config_v1, 0, sizeof(client_config_v1));
  client_config_v1.connect_endpoint = &client_endpoint;
  client_config_v1.expected_peer_identity = "meshd";
  client_config_v1.expected_peer_certificate_sha256 =
      TEST_SERVER_TLS_CERTIFICATE_SHA256;
  client_config_v1.identity_policy_generation =
      TEST_IDENTITY_POLICY_GENERATION;
  client_config_v1.mesh_id[0] = 1u;
  client_config_v1.provider_id[0] = 3u;
  client_config_v1.sender_incarnation[0] = 6u;
  client_config_v1.operation_capacity = 8u;
  client_config_v1.channel_capacity = 8u;
  client_config_v1.channel_max_retained_bytes = TEST_FRAME_HWM_BYTES;

  check_int_eq(mesh_node_control_runtime_init_v1(
                   &server_runtime, &server_config_v1),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_control_client_runtime_init_v1(
                   &client_runtime, &client_config_v1),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_control_runtime_start_v1(&server_runtime),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_control_client_runtime_start_v1(&client_runtime),
               MESH_CONTROL_OK);

  memset(&command, 0, sizeof(command));
  command.action = MESH_CONTROL_DESIRED_DELETE;
  command.resource_kind = MESH_CONTROL_RESOURCE_NETWORK;
  command.precondition_epoch = 1u;
  command.mesh_id[0] = 1u;
  command.resource_id[0] = 2u;
  command.provider_id[0] = 3u;
  request_id[0] = 4u;
  operation_id[0] = 5u;
  check_int_eq(mesh_node_control_client_runtime_submit_v1(
                   &client_runtime, request_id, operation_id, 2u, &command),
               MESH_CONTROL_OK);

  for (attempt = 0; attempt < TEST_WAIT_ATTEMPTS && !result_ready; ++attempt) {
    size_t processed = 0u;
    size_t sent = 0u;
    mesh_control_result_t client_result =
        mesh_node_control_client_runtime_poll_v1(
            &client_runtime, 4u, 4u, &processed, &sent);
    mesh_control_result_t server_result = mesh_node_control_runtime_poll_v1(
        &server_runtime, 4u, 4u, &processed, &sent);
    check_true(client_result == MESH_CONTROL_OK ||
               client_result == MESH_CONTROL_PROVIDER_UNAVAILABLE ||
               client_result == MESH_CONTROL_TIMEOUT ||
               client_result == MESH_CONTROL_RESOURCE_EXHAUSTED);
    check_true(server_result == MESH_CONTROL_OK ||
               server_result == MESH_CONTROL_PROVIDER_UNAVAILABLE ||
               server_result == MESH_CONTROL_TIMEOUT ||
               server_result == MESH_CONTROL_RESOURCE_EXHAUSTED);
    (void)mesh_node_control_client_runtime_poll_v1(
        &client_runtime, 4u, 4u, &processed, &sent);
    result_ready =
        mesh_node_control_client_runtime_peek_result_v1(
            &client_runtime, returned_operation_id, &result) ==
        MESH_CONTROL_OK;
    if (!result_ready)
      turbo_sleep_ms(TEST_WAIT_STEP_MS);
  }
  check_true(result_ready);
  check_mem_eq(returned_operation_id, operation_id, sizeof(operation_id));
  check_uint_eq(result.outcome, MESH_NODE_IPC_OUTCOME_SUCCEEDED_V1);
  check_uint_eq(result.applied_epoch, 2u);
  check_size_eq(executor.calls, 1u);
  check_int_eq(mesh_node_control_client_runtime_ack_result_v1(
                   &client_runtime, operation_id),
               MESH_CONTROL_OK);

  for (attempt = 0; attempt < TEST_WAIT_ATTEMPTS; ++attempt) {
    size_t processed = 0u;
    size_t sent = 0u;
    (void)mesh_node_control_client_runtime_poll_v1(
        &client_runtime, 4u, 4u, &processed, &sent);
    (void)mesh_node_control_runtime_poll_v1(
        &server_runtime, 4u, 4u, &processed, &sent);
    check_int_eq(mesh_node_control_runtime_get_stats_v1(
                     &server_runtime, &server_stats),
                 MESH_CONTROL_OK);
    check_int_eq(mesh_node_control_client_runtime_get_stats_v1(
                     &client_runtime, &client_stats),
                 MESH_CONTROL_OK);
    if (server_stats.owner.retained_operations == 0u &&
        client_stats.outbound.pending == 0u)
      break;
    turbo_sleep_ms(TEST_WAIT_STEP_MS);
  }
  check_size_eq(server_stats.owner.retained_operations, 0u);
  check_uint_eq(server_stats.owner.results_acked, 1u);
  check_size_eq(client_stats.client.retained_operations, 0u);
  check_uint_eq(client_stats.client.results_acked, 1u);

  check_int_eq(mesh_node_control_client_runtime_begin_drain_v1(
                   &client_runtime),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_control_runtime_begin_drain_v1(&server_runtime),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_control_client_runtime_stop_v1(&client_runtime),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_control_runtime_stop_v1(&server_runtime),
               MESH_CONTROL_OK);
  mesh_node_control_client_runtime_destroy_v1(&client_runtime);
  mesh_node_control_runtime_destroy_v1(&server_runtime);
}

static void test_reconciler_drives_flowmq_prestaged_function(void) {
  const mesh_control_state_config_v1_t state_config = {
      4u, 4u, 16u, 500u, 1024u, 4096u};
  unsigned short port = test_port();
  flowmq_coronet_tls_server_config_t server_tls;
  flowmq_coronet_tls_client_config_t client_tls;
  flowmq_router_endpoint_config_t server_endpoint;
  flowmq_connect_endpoint_config_t client_endpoint;
  mesh_node_control_runtime_v1_t server_runtime;
  mesh_node_control_runtime_config_v1_t server_config_v1;
  mesh_node_control_flowmq_provider_v1_t provider;
  mesh_node_control_flowmq_provider_config_v1_t provider_config;
  const mesh_control_provider_v1_t *descriptor;
  mesh_control_reconciler_v1_t reconciler;
  mesh_control_reconciler_config_v1_t reconciler_config;
  mesh_control_reconciler_stats_v1_t reconciler_stats;
  mesh_control_state_v1_t state;
  mesh_control_function_spec_v1_t spec;
  mesh_control_envelope_v1_t envelope;
  mesh_control_operation_v1_t operation;
  mesh_control_resource_status_v1_t status;
  mesh_node_control_runtime_stats_v1_t server_stats;
  runtime_executor_state_v1_t executor = {0u};
  uint8_t document[MESH_CONTROL_FUNCTION_DOCUMENT_SIZE_V1];
  size_t document_size = 0u;
  int attempt;
  int operation_succeeded = 0;

  check_int_gt((int)port, 0);
  configure_tls(&server_tls, &client_tls);
  server_config(&server_endpoint, port, &server_tls);
  client_config(&client_endpoint, port, &client_tls);
  memset(&server_runtime, 0, sizeof(server_runtime));
  memset(&provider, 0, sizeof(provider));
  memset(&reconciler, 0, sizeof(reconciler));
  memset(&state, 0, sizeof(state));
  memset(&server_config_v1, 0, sizeof(server_config_v1));
  server_config_v1.mode = MESH_NODE_IPC_FLOWMQ_BIND_V1;
  server_config_v1.bind_endpoint = &server_endpoint;
  server_config_v1.expected_peer_identity = "mesh-agent";
  server_config_v1.expected_peer_certificate_sha256 =
      TEST_CLIENT_TLS_CERTIFICATE_SHA256;
  server_config_v1.identity_policy_generation =
      TEST_IDENTITY_POLICY_GENERATION;
  server_config_v1.execute = runtime_execute;
  server_config_v1.execute_context = &executor;
  server_config_v1.mesh_id[0] = 1u;
  server_config_v1.provider_id[0] = 0x32u;
  server_config_v1.sender_incarnation[0] = 8u;
  server_config_v1.allowed_resource_mask =
      UINT64_C(1) << MESH_CONTROL_RESOURCE_FUNCTION;
  server_config_v1.operation_capacity = 4u;
  server_config_v1.channel_capacity = 8u;
  server_config_v1.channel_max_retained_bytes = TEST_FRAME_HWM_BYTES;

  memset(&provider_config, 0, sizeof(provider_config));
  provider_config.runtime.connect_endpoint = &client_endpoint;
  provider_config.runtime.expected_peer_identity = "meshd";
  provider_config.runtime.expected_peer_certificate_sha256 =
      TEST_SERVER_TLS_CERTIFICATE_SHA256;
  provider_config.runtime.identity_policy_generation =
      TEST_IDENTITY_POLICY_GENERATION;
  provider_config.runtime.mesh_id[0] = 1u;
  provider_config.runtime.provider_id[0] = 0x32u;
  provider_config.runtime.sender_incarnation[0] = 6u;
  provider_config.runtime.operation_capacity =
      MESH_NODE_CONTROL_FLOWMQ_PROVIDER_OPERATION_CAPACITY_V1;
  provider_config.runtime.channel_capacity = 4u;
  provider_config.runtime.channel_max_retained_bytes = TEST_FRAME_HWM_BYTES;
  provider_config.provider_runtime = MESH_CONTROL_FUNCTION_NATIVE;
  provider_config.initial_applied_epoch = 0u;
  provider_config.response_budget = 4u;
  provider_config.send_budget = 4u;

  check_int_eq(mesh_node_control_runtime_init_v1(
                   &server_runtime, &server_config_v1),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_control_flowmq_provider_init_v1(
                   &provider, &provider_config),
               MESH_CONTROL_OK);
  descriptor = mesh_node_control_flowmq_provider_descriptor_v1(&provider);
  check_not_null(descriptor);
  memset(&reconciler_config, 0, sizeof(reconciler_config));
  reconciler_config.providers = descriptor;
  reconciler_config.provider_count = 1u;
  reconciler_config.inflight_capacity = 1u;
  check_int_eq(mesh_control_state_init_v1(&state, &state_config),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_reconciler_init_v1(
                   &reconciler, &reconciler_config),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_control_runtime_start_v1(&server_runtime),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_control_flowmq_provider_start_v1(&provider),
               MESH_CONTROL_OK);

  memset(&spec, 0, sizeof(spec));
  spec.schema_version = MESH_CONTROL_SCHEMA_V1;
  spec.runtime = MESH_CONTROL_FUNCTION_NATIVE;
  spec.desired_state = MESH_CONTROL_FUNCTION_RUNNING;
  spec.flags = MESH_CONTROL_FUNCTION_FLAG_PRESTAGED |
               MESH_CONTROL_FUNCTION_FLAG_OUT_OF_PROCESS;
  spec.function_id[0] = 0x31u;
  spec.provider_id[0] = 0x32u;
  spec.artifact_digest[0] = 0x33u;
  spec.config_digest[0] = 0x34u;
  spec.network_policy_digest[0] = 0x35u;
  spec.generation = 1u;
  spec.required_capabilities = 1u;
  spec.limits.memory_bytes = 1024u;
  spec.limits.cpu_time_ms = 100u;
  spec.limits.input_bytes = 1024u;
  spec.limits.output_bytes = 1024u;
  spec.limits.concurrency = 1u;
  spec.limits.host_calls = 1u;
  check_int_eq(mesh_control_function_document_encode_v1(
                   &spec, document, sizeof(document), &document_size),
               MESH_CONTROL_OK);
  memset(&envelope, 0, sizeof(envelope));
  envelope.schema_version = MESH_CONTROL_SCHEMA_V1;
  envelope.kind = MESH_CONTROL_MESSAGE_INTENT;
  envelope.message_id[0] = 0x41u;
  envelope.request_id[0] = 0x42u;
  envelope.mesh_id[0] = 1u;
  envelope.origin_principal[0] = 2u;
  envelope.target_node_id[0] = 3u;
  envelope.resource_kind = MESH_CONTROL_RESOURCE_FUNCTION;
  memcpy(envelope.resource_id, spec.function_id,
         sizeof(envelope.resource_id));
  envelope.epoch = 1u;
  envelope.sequence = 1u;
  envelope.issued_at_ms = 1000u;
  envelope.expires_at_ms = 5000u;
  envelope.payload_digest[0] = 0x43u;
  envelope.payload_size = document_size;
  check_int_eq(mesh_control_state_submit_document_v1(
                   &state, &envelope, MESH_CONTROL_DESIRED_APPLY,
                   document, document_size, 1100u, &operation),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_reconciler_enqueue_v1(
                   &reconciler, &operation, document, document_size),
               MESH_CONTROL_OK);

  for (attempt = 0; attempt < TEST_WAIT_ATTEMPTS && !operation_succeeded;
       ++attempt) {
    size_t processed = 0u;
    size_t sent = 0u;
    size_t progress = 0u;
    mesh_control_result_t reconcile_result = mesh_control_reconciler_poll_v1(
        &reconciler, &state, 1u, 1u, 1110u + (uint64_t)attempt,
        &progress);
    if (reconcile_result != MESH_CONTROL_OK)
      break;
    (void)mesh_node_control_runtime_poll_v1(
        &server_runtime, 4u, 4u, &processed, &sent);
    if (mesh_control_state_get_operation_v1(
            &state, operation.operation_id, &operation) == MESH_CONTROL_OK &&
        operation.state == MESH_CONTROL_OPERATION_SUCCEEDED)
      operation_succeeded = 1;
    if (!operation_succeeded)
      turbo_sleep_ms(TEST_WAIT_STEP_MS);
  }
  check_true(operation_succeeded);
  check_uint_eq(operation.state, MESH_CONTROL_OPERATION_SUCCEEDED);
  check_int_eq(mesh_control_state_get_resource_v1(
                   &state, MESH_CONTROL_RESOURCE_FUNCTION,
                   spec.function_id, &status),
               MESH_CONTROL_OK);
  check_uint_eq(status.observed_presence, MESH_CONTROL_PRESENCE_PRESENT);
  check_uint_eq(status.observed_epoch, 1u);
  check_mem_eq(status.observed_digest, envelope.payload_digest,
               sizeof(status.observed_digest));
  check_int_eq(mesh_control_reconciler_get_stats_v1(
                   &reconciler, &reconciler_stats),
               MESH_CONTROL_OK);
  check_uint_eq(reconciler_stats.started, 1u);
  check_uint_eq(reconciler_stats.succeeded, 1u);
  check_size_eq(reconciler_stats.inflight, 0u);
  check_size_eq(executor.calls, 1u);

  for (attempt = 0; attempt < TEST_WAIT_ATTEMPTS; ++attempt) {
    size_t processed = 0u;
    size_t sent = 0u;
    size_t progress = 0u;
    (void)mesh_node_control_flowmq_provider_poll_v1(&provider, &progress);
    (void)mesh_node_control_runtime_poll_v1(
        &server_runtime, 4u, 4u, &processed, &sent);
    check_int_eq(mesh_node_control_runtime_get_stats_v1(
                     &server_runtime, &server_stats),
                 MESH_CONTROL_OK);
    if (server_stats.owner.retained_operations == 0u)
      break;
    turbo_sleep_ms(TEST_WAIT_STEP_MS);
  }
  check_size_eq(server_stats.owner.retained_operations, 0u);
  check_uint_eq(server_stats.owner.results_acked, 1u);
  check_uint_eq(provider.applied_epoch, 1u);

  check_int_eq(mesh_control_reconciler_close_v1(&reconciler),
               MESH_CONTROL_OK);
  for (attempt = 0; attempt < TEST_WAIT_ATTEMPTS &&
                    !mesh_control_reconciler_is_drained_v1(&reconciler);
       ++attempt)
    turbo_sleep_ms(TEST_WAIT_STEP_MS);
  check_true(mesh_control_reconciler_is_drained_v1(&reconciler));
  check_int_eq(mesh_node_control_runtime_begin_drain_v1(&server_runtime),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_control_runtime_stop_v1(&server_runtime),
               MESH_CONTROL_OK);
  mesh_control_reconciler_destroy_v1(&reconciler);
  mesh_control_state_destroy_v1(&state);
  mesh_node_control_flowmq_provider_destroy_v1(&provider);
  mesh_node_control_runtime_destroy_v1(&server_runtime);
}

static int network_provider_poll_completion(
    mesh_node_network_control_service_v1_t *service,
    const mesh_control_network_provider_v1_t *provider,
    mesh_control_network_provider_completion_v1_t *completion) {
  int attempt;
  for (attempt = 0; attempt < TEST_WAIT_ATTEMPTS; ++attempt) {
    size_t processed = 0u;
    size_t sent = 0u;
    mesh_control_result_t result = provider->ops.try_peek_completion(
        provider->context, completion);
    if (result == MESH_CONTROL_OK)
      return 1;
    if (result != MESH_CONTROL_EMPTY)
      return 0;
    (void)mesh_node_network_control_service_poll_v1(
        service, &processed, &sent);
    turbo_sleep_ms(TEST_WAIT_STEP_MS);
  }
  return 0;
}

static int network_provider_poll_until_acked(
    mesh_node_network_control_service_v1_t *service,
    mesh_node_control_flowmq_network_provider_v1_t *provider) {
  int attempt;
  for (attempt = 0; attempt < TEST_WAIT_ATTEMPTS; ++attempt) {
    mesh_node_network_control_service_stats_v1_t stats;
    size_t processed = 0u;
    size_t sent = 0u;
    size_t progress = 0u;
    (void)mesh_node_control_flowmq_network_provider_poll_v1(provider,
                                                            &progress);
    (void)mesh_node_network_control_service_poll_v1(
        service, &processed, &sent);
    if (mesh_node_network_control_service_get_stats_v1(service, &stats) ==
            MESH_CONTROL_OK &&
        stats.runtime.owner.retained_operations == 0u)
      return 1;
    turbo_sleep_ms(TEST_WAIT_STEP_MS);
  }
  return 0;
}

static void test_network_control_service_applies_and_drains_network(void) {
  static const char network_id[] = "flowmq-network-control-service";
  unsigned short port = test_port();
  flowmq_coronet_tls_server_config_t server_tls;
  flowmq_coronet_tls_client_config_t client_tls;
  flowmq_router_endpoint_config_t server_endpoint;
  flowmq_connect_endpoint_config_t client_endpoint;
  mesh_fabric_config_v2_t fabric_config;
  mesh_fabric_t *fabric = NULL;
  mesh_network_issuer_v1_t issuer;
  mesh_node_network_control_service_v1_t service;
  mesh_node_network_control_service_config_v1_t service_config;
  mesh_node_network_control_service_stats_v1_t service_stats;
  mesh_node_control_flowmq_network_provider_v1_t provider;
  mesh_node_control_flowmq_network_provider_config_v1_t provider_config;
  const mesh_control_network_provider_v1_t *descriptor;
  flowmq_test_network_intent_v1_t intent;
  flowmq_test_network_intent_v1_t second_intent;
  mesh_control_network_provider_request_v1_t request;
  mesh_control_network_provider_completion_v1_t completion;
  uint8_t node_private[32];
  uint8_t node_public[32];
  uint8_t mesh_id[32];
  char node_public_hex[65];
  const char *allowed_nodes[1];

  memset(&completion, 0, sizeof(completion));
  check_int_gt((int)port, 0);
  configure_tls(&server_tls, &client_tls);
  server_config(&server_endpoint, port, &server_tls);
  client_config(&client_endpoint, port, &client_tls);
  memset(node_private, 0x44, sizeof(node_private));
  check_int_eq(P2P_OK,
               p2p_public_key_from_private_key(node_private, node_public));
  bytes_to_hex_32(node_public, node_public_hex);
  allowed_nodes[0] = node_public_hex;
  check_int_eq(TURBO_CRYPTO_OK,
               turbo_crypto_sha256(network_id, strlen(network_id), mesh_id));
  memset(&issuer, 0, sizeof(issuer));
  memset(issuer.key_id, 0x61, sizeof(issuer.key_id));
  memcpy(issuer.public_key, TEST_NETWORK_ISSUER_PUBLIC_KEY,
         sizeof(issuer.public_key));

  mesh_fabric_config_init_v2(&fabric_config);
  fabric_config.underlay.virtual_ip = "10.92.0.1";
  fabric_config.underlay.virtual_prefix = 24u;
  fabric_config.underlay.listen_port = 24992;
  fabric_config.underlay.network_id = network_id;
  fabric_config.underlay.identity_private_key = node_private;
  fabric_config.underlay.identity_private_key_size = sizeof(node_private);
  fabric_config.underlay.peer_allow_node_ids = allowed_nodes;
  fabric_config.underlay.peer_allow_node_id_count = 1u;
  fabric_config.trusted_issuers = &issuer;
  fabric_config.trusted_issuer_count = 1u;
  check_int_eq(MESH_OK, mesh_fabric_create_v2(&fabric_config, &fabric));

  memset(&service, 0, sizeof(service));
  memset(&service_config, 0, sizeof(service_config));
  service_config.fabric = fabric;
  service_config.bind_endpoint = &server_endpoint;
  service_config.expected_peer_identity = "mesh-agent";
  service_config.expected_peer_certificate_sha256 =
      TEST_CLIENT_TLS_CERTIFICATE_SHA256;
  service_config.identity_policy_generation =
      TEST_IDENTITY_POLICY_GENERATION;
  memcpy(service_config.mesh_id, mesh_id, sizeof(mesh_id));
  service_config.provider_id[0] = 0x71u;
  service_config.sender_incarnation[0] = 0x72u;
  service_config.network_capacity = 2u;
  service_config.operation_capacity = 4u;
  service_config.channel_capacity = 8u;
  service_config.channel_max_retained_bytes = TEST_FRAME_HWM_BYTES;
  service_config.command_budget = 4u;
  service_config.send_budget = 4u;
  service_config.delete_drain_timeout_ms = 100u;
  service_config.shutdown_drain_timeout_ms = 100u;

  memset(&provider, 0, sizeof(provider));
  memset(&provider_config, 0, sizeof(provider_config));
  provider_config.runtime.connect_endpoint = &client_endpoint;
  provider_config.runtime.expected_peer_identity = "meshd";
  provider_config.runtime.expected_peer_certificate_sha256 =
      TEST_SERVER_TLS_CERTIFICATE_SHA256;
  provider_config.runtime.identity_policy_generation =
      TEST_IDENTITY_POLICY_GENERATION;
  memcpy(provider_config.runtime.mesh_id, mesh_id, sizeof(mesh_id));
  provider_config.runtime.provider_id[0] = 0x71u;
  provider_config.runtime.sender_incarnation[0] = 0x73u;
  provider_config.runtime.operation_capacity =
      MESH_NODE_CONTROL_FLOWMQ_NETWORK_OPERATION_CAPACITY_V1;
  provider_config.runtime.channel_capacity = 8u;
  provider_config.runtime.channel_max_retained_bytes = TEST_FRAME_HWM_BYTES;
  provider_config.response_budget = 4u;
  provider_config.send_budget = 4u;

  check_int_eq(mesh_node_network_control_service_init_v1(
                   &service, &service_config),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_control_flowmq_network_provider_init_v1(
                   &provider, &provider_config),
               MESH_CONTROL_OK);
  descriptor = mesh_node_control_flowmq_network_provider_descriptor_v1(
      &provider);
  check_not_null(descriptor);
  check_int_eq(mesh_node_network_control_service_start_v1(&service),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_control_flowmq_network_provider_start_v1(&provider),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_network_control_service_destroy_v1(&service),
               MESH_CONTROL_INVALID_STATE);
  check_int_eq(mesh_node_network_control_service_stop_v1(&service),
               MESH_CONTROL_INVALID_STATE);

  make_flowmq_network_intent(&intent, mesh_id, node_public, &issuer,
                             0x51u, "flowmq-primary");
  memset(&request, 0, sizeof(request));
  request.operation.action = MESH_CONTROL_DESIRED_APPLY;
  request.operation.resource_kind = MESH_CONTROL_RESOURCE_NETWORK;
  request.operation.desired_epoch = 1u;
  request.operation.request_id[0] = 0x74u;
  request.operation.operation_id[0] = 0x75u;
  memcpy(request.operation.resource_id, intent.resource_id,
         sizeof(request.operation.resource_id));
  request.document = intent.wire;
  request.document_size = intent.wire_size;
  check_int_eq(TURBO_CRYPTO_OK,
               turbo_crypto_sha256(request.document, request.document_size,
                                   request.operation.desired_digest));
  check_int_eq(descriptor->ops.try_start(descriptor->context, &request),
               MESH_CONTROL_OK);

  check_true(network_provider_poll_completion(&service, descriptor,
                                              &completion));
  check_mem_eq(completion.operation_id, request.operation.operation_id,
               sizeof(completion.operation_id));
  check_uint_eq(completion.state,
                MESH_CONTROL_NETWORK_PROVIDER_COMPLETED);
  check_int_eq(mesh_node_network_control_service_get_stats_v1(
                   &service, &service_stats),
               MESH_CONTROL_OK);
  check_size_eq(service_stats.owned_networks, 1u);
  check_size_eq(service_stats.fabric.attached_networks, 1u);

  check_int_eq(descriptor->ops.ack_completion(
                   descriptor->context, request.operation.operation_id),
               MESH_CONTROL_OK);
  check_true(network_provider_poll_until_acked(&service, &provider));

  request.operation.request_id[0] = 0x7au;
  request.operation.operation_id[0] = 0x7bu;
  check_int_eq(descriptor->ops.try_start(descriptor->context, &request),
               MESH_CONTROL_OK);
  memset(&completion, 0, sizeof(completion));
  check_true(network_provider_poll_completion(&service, descriptor,
                                              &completion));
  check_uint_eq(completion.state,
                MESH_CONTROL_NETWORK_PROVIDER_COMPLETED);
  check_int_eq(descriptor->ops.ack_completion(
                   descriptor->context, request.operation.operation_id),
               MESH_CONTROL_OK);
  check_true(network_provider_poll_until_acked(&service, &provider));
  check_int_eq(mesh_node_network_control_service_get_stats_v1(
                   &service, &service_stats),
               MESH_CONTROL_OK);
  check_size_eq(service_stats.owned_networks, 1u);

  make_flowmq_network_intent(&second_intent, mesh_id, node_public, &issuer,
                             0x61u, "flowmq-backup");
  memset(&request, 0, sizeof(request));
  request.operation.action = MESH_CONTROL_DESIRED_APPLY;
  request.operation.resource_kind = MESH_CONTROL_RESOURCE_NETWORK;
  request.operation.desired_epoch = 1u;
  request.operation.request_id[0] = 0x76u;
  request.operation.operation_id[0] = 0x77u;
  memcpy(request.operation.resource_id, second_intent.resource_id,
         sizeof(request.operation.resource_id));
  request.document = second_intent.wire;
  request.document_size = second_intent.wire_size;
  check_int_eq(TURBO_CRYPTO_OK,
               turbo_crypto_sha256(request.document, request.document_size,
                                   request.operation.desired_digest));
  check_int_eq(descriptor->ops.try_start(descriptor->context, &request),
               MESH_CONTROL_OK);
  memset(&completion, 0, sizeof(completion));
  check_true(network_provider_poll_completion(&service, descriptor,
                                              &completion));
  check_mem_eq(completion.operation_id, request.operation.operation_id,
               sizeof(completion.operation_id));
  check_uint_eq(completion.state,
                MESH_CONTROL_NETWORK_PROVIDER_COMPLETED);
  check_int_eq(mesh_node_network_control_service_get_stats_v1(
                   &service, &service_stats),
               MESH_CONTROL_OK);
  check_size_eq(service_stats.owned_networks, 2u);
  check_size_eq(service_stats.fabric.attached_networks, 2u);
  check_int_eq(descriptor->ops.ack_completion(
                   descriptor->context, request.operation.operation_id),
               MESH_CONTROL_OK);
  check_true(network_provider_poll_until_acked(&service, &provider));

  memset(&request, 0, sizeof(request));
  request.operation.action = MESH_CONTROL_DESIRED_DELETE;
  request.operation.resource_kind = MESH_CONTROL_RESOURCE_NETWORK;
  request.operation.desired_epoch = 2u;
  request.operation.request_id[0] = 0x78u;
  request.operation.operation_id[0] = 0x79u;
  request.precondition_epoch = 1u;
  memcpy(request.operation.resource_id, intent.resource_id,
         sizeof(request.operation.resource_id));
  check_int_eq(descriptor->ops.try_start(descriptor->context, &request),
               MESH_CONTROL_OK);
  memset(&completion, 0, sizeof(completion));
  check_true(network_provider_poll_completion(&service, descriptor,
                                              &completion));
  check_mem_eq(completion.operation_id, request.operation.operation_id,
               sizeof(completion.operation_id));
  check_uint_eq(completion.state,
                MESH_CONTROL_NETWORK_PROVIDER_COMPLETED);
  check_int_eq(mesh_node_network_control_service_get_stats_v1(
                   &service, &service_stats),
               MESH_CONTROL_OK);
  check_size_eq(service_stats.owned_networks, 1u);
  check_size_eq(service_stats.fabric.attached_networks, 1u);
  check_mem_eq(service.reconciler.records[0].resource_id,
               second_intent.resource_id,
               sizeof(second_intent.resource_id));

  check_int_eq(mesh_node_network_control_service_begin_drain_v1(&service),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_network_control_service_stop_v1(&service),
               MESH_CONTROL_RESOURCE_EXHAUSTED);
  check_int_eq(descriptor->ops.ack_completion(
                   descriptor->context, request.operation.operation_id),
               MESH_CONTROL_OK);
  check_true(network_provider_poll_until_acked(&service, &provider));
  descriptor->ops.close(descriptor->context);
  check_true(descriptor->ops.is_drained(descriptor->context));
  check_int_eq(mesh_node_network_control_service_stop_v1(&service),
               MESH_CONTROL_OK);
  check_int_eq(mesh_node_network_control_service_get_stats_v1(
                   &service, &service_stats),
               MESH_CONTROL_OK);
  check_uint_eq(service_stats.lifecycle,
                MESH_NODE_NETWORK_CONTROL_STOPPED_V1);
  check_size_eq(service_stats.owned_networks, 0u);
  check_size_eq(service_stats.fabric.attached_networks, 0u);
  check_int_eq(mesh_node_network_control_service_destroy_v1(&service),
               MESH_CONTROL_OK);
  mesh_node_control_flowmq_network_provider_destroy_v1(&provider);
  mesh_fabric_destroy_v2(fabric);
}

static void test_meshd_network_control_owns_one_compatible_underlay(void) {
  static const char network_id[] = "meshd-network-control-adapter";
  mesh_node_config_t node_config;
  mesh_config_t underlay;
  meshd_network_control_config_t config;
  meshd_network_control_t runtime;
  mesh_node_network_control_service_stats_v1_t stats;
  uint8_t node_private[32];
  char hex[65];

  check_int_eq(flowmq_coronet_tls_require_tls13(), TURBO_OK);
  mesh_node_config_init(&node_config);
  node_config.network_control_enabled = 1;
  snprintf(node_config.identity_private_key_file,
           sizeof(node_config.identity_private_key_file), "%s", "node.key");
  snprintf(node_config.network_control_certificate_file,
           sizeof(node_config.network_control_certificate_file), "%s",
           MESH_TEST_FLOWMQ_SERVER_CERT_FILE);
  snprintf(node_config.network_control_private_key_file,
           sizeof(node_config.network_control_private_key_file), "%s",
           MESH_TEST_FLOWMQ_SERVER_KEY_FILE);
  snprintf(node_config.network_control_client_ca_file,
           sizeof(node_config.network_control_client_ca_file), "%s",
           MESH_TEST_FLOWMQ_CA_FILE);
  snprintf(node_config.network_control_identity,
           sizeof(node_config.network_control_identity), "%s", "meshd");
  snprintf(node_config.network_control_expected_peer_identity,
           sizeof(node_config.network_control_expected_peer_identity), "%s",
           "mesh-agent");
  snprintf(node_config.network_control_expected_peer_certificate_sha256,
           sizeof(node_config.network_control_expected_peer_certificate_sha256),
           "%s", TEST_CLIENT_TLS_CERTIFICATE_SHA256);
  node_config.network_control_identity_policy_generation =
      TEST_IDENTITY_POLICY_GENERATION;
  snprintf(node_config.network_control_membership_issuer_key_file,
           sizeof(node_config.network_control_membership_issuer_key_file), "%s",
           "issuer.pub");

  memset(&config, 0, sizeof(config));
  check_int_eq(TURBO_CRYPTO_OK,
               turbo_crypto_sha256(network_id, strlen(network_id),
                                   config.mesh_id));
  bytes_to_hex_32(config.mesh_id, hex);
  snprintf(node_config.network_control_mesh_id_hex,
           sizeof(node_config.network_control_mesh_id_hex), "%s", hex);
  memset(config.provider_id, 0x31, sizeof(config.provider_id));
  bytes_to_hex_32(config.provider_id, hex);
  snprintf(node_config.network_control_provider_id_hex,
           sizeof(node_config.network_control_provider_id_hex), "%s", hex);
  memset(config.issuer_id, 0x41, sizeof(config.issuer_id));
  bytes_to_hex_32(config.issuer_id, hex);
  snprintf(node_config.network_control_membership_issuer_id_hex,
           sizeof(node_config.network_control_membership_issuer_id_hex), "%s",
           hex);
  memcpy(config.issuer_public_key, TEST_NETWORK_ISSUER_PUBLIC_KEY,
         sizeof(config.issuer_public_key));
  memset(config.sender_incarnation, 0x51,
         sizeof(config.sender_incarnation));
  check_int_eq(mesh_node_config_validate(&node_config), 0);

  memset(node_private, 0x44, sizeof(node_private));
  mesh_config_init(&underlay);
  underlay.virtual_ip = "10.93.0.1";
  underlay.virtual_prefix = 24u;
  underlay.listen_port = 24993;
  underlay.network_id = network_id;
  underlay.identity_private_key = node_private;
  underlay.identity_private_key_size = sizeof(node_private);
  config.node = &node_config;
  config.underlay = &underlay;

  memset(&runtime, 0, sizeof(runtime));
  config.mesh_id[0] ^= 0xffu;
  check_int_eq(meshd_network_control_init(&runtime, &config), -1);
  check_null(runtime.fabric);
  config.mesh_id[0] ^= 0xffu;
  check_int_eq(meshd_network_control_init(&runtime, &config), 0);
  check_not_null(meshd_network_control_borrow_underlay(&runtime));
  memset(&stats, 0, sizeof(stats));
  check_int_eq(mesh_node_network_control_service_get_stats_v1(
                   &runtime.service, &stats),
               MESH_CONTROL_OK);
  check_uint_eq(stats.lifecycle, MESH_NODE_NETWORK_CONTROL_READY_V1);
  check_size_eq(stats.fabric.attached_networks, 0u);
  meshd_network_control_destroy(&runtime);
  check_null(runtime.fabric);
}

spec("MeshNodeIPC standalone FlowMQ adapter") {
  describe("production profile") {
    it("rejects endpoints without the required TLS profile") {
      test_profile_rejects_insecure_endpoints();
    }
    it("runs typed control bidirectionally over mTLS ROUTER DEALER") {
      test_secure_router_dealer_and_runtime();
    }
    it("rejects the old server certificate after its pin is removed") {
      test_rejects_disallowed_peer(
          TEST_REJECT_REMOVED_SERVER_CERTIFICATE_V1);
    }
    it("rejects the old client certificate after its pin is removed") {
      test_rejects_disallowed_peer(
          TEST_REJECT_REMOVED_CLIENT_CERTIFICATE_V1);
    }
    it("rejects a clientAuth-only certificate in the server role") {
      test_rejects_disallowed_peer(TEST_REJECT_SERVER_CLIENT_AUTH_EKU_V1);
    }
    it("rejects a serverAuth-only certificate in the client role") {
      test_rejects_disallowed_peer(TEST_REJECT_CLIENT_SERVER_AUTH_EKU_V1);
    }
    it("accepts the next certificate only during an explicit rotation overlap") {
      test_accepts_certificate_during_explicit_rotation_overlap();
    }
    it("reauthenticates and resumes sends after the server restarts") {
      test_client_reauthenticates_after_server_restart();
    }
    it("completes client server operation and exact ACK over mTLS") {
      test_client_and_server_runtimes_complete_exact_ack();
    }
    it("reconciles a prestaged Native function over the typed mTLS channel") {
      test_reconciler_drives_flowmq_prestaged_function();
    }
    it("independently applies and deletes Networks through the meshd composition") {
      test_network_control_service_applies_and_drains_network();
    }
    it("lets meshd own one fabric while borrowing its compatible underlay") {
      test_meshd_network_control_owns_one_compatible_underlay();
    }
  }
}
