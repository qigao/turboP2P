#include "mesh_node_ipc_flowmq.h"

#include <turbo_process.h>
#include <turbo_thread.h>

#include <errno.h>
#include <stdio.h>
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

#define PROCESS_TEST_WAIT_ATTEMPTS 600u
#define PROCESS_TEST_WAIT_STEP_MS 5u
#define PROCESS_TEST_TIMEOUT_MS 3000u
#define PROCESS_TEST_CHILD_DEADLINE_MS 15000u
#define PROCESS_TEST_CHILD_WAIT_MS 5000u
#define PROCESS_TEST_MAX_OUTPUT_BYTES (64u * 1024u)
#define PROCESS_TEST_CHANNEL_CAPACITY 4u
#define PROCESS_TEST_CHANNEL_BYTES (64u * 1024u)
#define PROCESS_TEST_SERVER_TLS_CERTIFICATE_SHA256 \
  "sha256:b8a72062af4690ea8066fb14191c988f4b80fd4d72c164bd976a505cb72ee742"
#define PROCESS_TEST_CLIENT_TLS_CERTIFICATE_SHA256 \
  "sha256:36f828b7dfeeeb70c1088ab417e6a473dbe7f8c479513894ef7a620f7c164eac"
#define PROCESS_TEST_POLICY_GENERATION UINT64_C(1)

typedef struct {
  mesh_node_ipc_channel_v1_t inbound;
  mesh_node_ipc_channel_v1_t outbound;
  mesh_node_ipc_flowmq_v1_t adapter;
  int inbound_initialized;
  int outbound_initialized;
} process_test_peer_v1_t;

static unsigned short process_test_port(void) {
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

static int process_test_parse_port(const char *text, unsigned short *out_port) {
  unsigned long value;
  char *end = NULL;
  if (!text || !out_port || text[0] == '\0') return -1;
  errno = 0;
  value = strtoul(text, &end, 10);
  if (errno != 0 || !end || end[0] != '\0' || value == 0u ||
      value > 65535u)
    return -1;
  *out_port = (unsigned short)value;
  return 0;
}

static void process_test_timeouts(flowmq_coronet_timeout_config_t *timeouts) {
  memset(timeouts, 0, sizeof(*timeouts));
  timeouts->timeout_ms = PROCESS_TEST_TIMEOUT_MS;
  timeouts->connect_timeout_ms = PROCESS_TEST_TIMEOUT_MS;
  timeouts->send_timeout_ms = PROCESS_TEST_TIMEOUT_MS;
  timeouts->recv_timeout_ms = PROCESS_TEST_TIMEOUT_MS;
  timeouts->handshake_timeout_ms = PROCESS_TEST_TIMEOUT_MS;
  timeouts->set_flags = FLOWMQ_TIMEOUT_SET_ALL;
  timeouts->explicit_flags = FLOWMQ_TIMEOUT_SET_ALL;
}

static void process_test_server_endpoint(
    flowmq_router_endpoint_config_t *endpoint, unsigned short port,
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
  endpoint->heartbeat_interval_ms = 100u;
  endpoint->heartbeat_timeout_ms = 500u;
  process_test_timeouts(&endpoint->timeouts);
}

static void process_test_client_endpoint(
    flowmq_connect_endpoint_config_t *endpoint, unsigned short port,
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
  endpoint->heartbeat_interval_ms = 100u;
  endpoint->heartbeat_timeout_ms = 500u;
  process_test_timeouts(&endpoint->timeouts);
}

static int process_test_peer_channels_init(process_test_peer_v1_t *peer) {
  if (!peer) return -1;
  memset(peer, 0, sizeof(*peer));
  if (mesh_node_ipc_channel_init_v1(
          &peer->inbound, PROCESS_TEST_CHANNEL_CAPACITY,
          PROCESS_TEST_CHANNEL_BYTES, MESH_NODE_IPC_MAX_FRAME_SIZE_V1) !=
      MESH_CONTROL_OK)
    return -1;
  peer->inbound_initialized = 1;
  if (mesh_node_ipc_channel_init_v1(
          &peer->outbound, PROCESS_TEST_CHANNEL_CAPACITY,
          PROCESS_TEST_CHANNEL_BYTES, MESH_NODE_IPC_MAX_FRAME_SIZE_V1) !=
      MESH_CONTROL_OK)
    return -1;
  peer->outbound_initialized = 1;
  return 0;
}

static void process_test_peer_destroy(process_test_peer_v1_t *peer) {
  if (!peer) return;
  mesh_node_ipc_flowmq_destroy_v1(&peer->adapter);
  if (peer->outbound_initialized)
    mesh_node_ipc_channel_destroy_v1(&peer->outbound);
  if (peer->inbound_initialized)
    mesh_node_ipc_channel_destroy_v1(&peer->inbound);
  memset(peer, 0, sizeof(*peer));
}

static size_t process_test_command_frame(uint8_t *frame, size_t capacity) {
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
  if (mesh_node_ipc_command_encode_v1(&command, body, sizeof(body),
                                      &body_size) != MESH_CONTROL_OK)
    return 0u;
  memset(&envelope, 0, sizeof(envelope));
  envelope.kind = MESH_NODE_IPC_COMMAND_V1;
  envelope.request_id[0] = 4u;
  envelope.operation_id[0] = 5u;
  envelope.sender_incarnation[0] = 6u;
  envelope.sequence = 1u;
  envelope.desired_epoch = 2u;
  envelope.body = body;
  envelope.body_size = body_size;
  if (mesh_node_ipc_envelope_encode_v1(&envelope, frame, capacity,
                                       &frame_size) != MESH_CONTROL_OK)
    return 0u;
  return frame_size;
}

static int process_test_wait_pending(mesh_node_ipc_channel_v1_t *channel) {
  unsigned int attempt;
  for (attempt = 0u; attempt < PROCESS_TEST_WAIT_ATTEMPTS; ++attempt) {
    mesh_node_ipc_channel_stats_v1_t stats;
    if (mesh_node_ipc_channel_get_stats_v1(channel, &stats) ==
            MESH_CONTROL_OK &&
        stats.pending != 0u)
      return 0;
    turbo_sleep_ms(PROCESS_TEST_WAIT_STEP_MS);
  }
  return -1;
}

static int process_test_pump_send(process_test_peer_v1_t *peer) {
  unsigned int attempt;
  for (attempt = 0u; attempt < PROCESS_TEST_WAIT_ATTEMPTS; ++attempt) {
    size_t sent = 0u;
    mesh_control_result_t result =
        mesh_node_ipc_flowmq_pump_send_v1(&peer->adapter, 1u, &sent);
    if (result == MESH_CONTROL_OK && sent == 1u) return 0;
    if (result != MESH_CONTROL_OK &&
        result != MESH_CONTROL_PROVIDER_UNAVAILABLE &&
        result != MESH_CONTROL_TIMEOUT &&
        result != MESH_CONTROL_RESOURCE_EXHAUSTED)
      return -1;
    turbo_sleep_ms(PROCESS_TEST_WAIT_STEP_MS);
  }
  return -1;
}

static int process_test_server(unsigned short port) {
  flowmq_coronet_tls_server_config_t tls;
  flowmq_router_endpoint_config_t endpoint;
  mesh_node_ipc_flowmq_config_v1_t config;
  mesh_node_ipc_frame_view_v1_t view;
  process_test_peer_v1_t peer;
  const char *failed_stage = "tls-profile";
  int result = 1;

  if (flowmq_coronet_tls_require_tls13() != TURBO_OK) return 1;
  memset(&tls, 0, sizeof(tls));
  tls.ca_file = MESH_TEST_FLOWMQ_CA_FILE;
  tls.cert_file = MESH_TEST_FLOWMQ_SERVER_CERT_FILE;
  tls.key_file = MESH_TEST_FLOWMQ_SERVER_KEY_FILE;
  tls.require_client_certificate = 1;
  process_test_server_endpoint(&endpoint, port, &tls);
  failed_stage = "channel-init";
  if (process_test_peer_channels_init(&peer) != 0) goto cleanup;
  memset(&config, 0, sizeof(config));
  config.mode = MESH_NODE_IPC_FLOWMQ_BIND_V1;
  config.bind_endpoint = &endpoint;
  config.expected_peer_identity = "mesh-agent";
  config.expected_peer_certificate_sha256 =
      PROCESS_TEST_CLIENT_TLS_CERTIFICATE_SHA256;
  config.identity_policy_generation = PROCESS_TEST_POLICY_GENERATION;
  config.inbound = &peer.inbound;
  config.outbound = &peer.outbound;
  failed_stage = "adapter-init";
  if (mesh_node_ipc_flowmq_init_v1(&peer.adapter, &config) !=
      MESH_CONTROL_OK)
    goto cleanup;
  failed_stage = "adapter-start";
  if (mesh_node_ipc_flowmq_start_v1(&peer.adapter) != MESH_CONTROL_OK)
    goto cleanup;
  fputs("READY\n", stdout);
  fflush(stdout);
  failed_stage = "receive";
  if (process_test_wait_pending(&peer.inbound) != 0) goto cleanup;
  failed_stage = "peek";
  if (mesh_node_ipc_channel_peek_v1(&peer.inbound, &view) !=
      MESH_CONTROL_OK)
    goto cleanup;
  failed_stage = "queue-response";
  if (mesh_node_ipc_channel_try_push_v1(&peer.outbound, view.frame,
                                        view.frame_size) != MESH_CONTROL_OK)
    goto cleanup;
  failed_stage = "consume-request";
  if (mesh_node_ipc_channel_consume_v1(&peer.inbound) != MESH_CONTROL_OK)
    goto cleanup;
  failed_stage = "send-response";
  if (process_test_pump_send(&peer) != 0) goto cleanup;
  failed_stage = "stop";
  if (mesh_node_ipc_flowmq_stop_v1(&peer.adapter) != MESH_CONTROL_OK)
    goto cleanup;
  result = 0;

cleanup:
  if (result != 0) fprintf(stderr, "server stage failed: %s\n", failed_stage);
  process_test_peer_destroy(&peer);
  return result;
}

static void process_test_print_child_stderr(turbo_process_t *process) {
  char output[512];
  size_t read_size = 0u;
  int read_result;
  if (!process) return;
  memset(output, 0, sizeof(output));
  read_result = turbo_process_read_stderr(process, output,
                                          sizeof(output) - 1u, &read_size);
  if ((read_result == TURBO_OK || read_result == TURBO_EOF) &&
      read_size != 0u) {
    output[read_size] = '\0';
    fprintf(stderr, "child stderr: %s\n", output);
  }
}

static int process_test_parent(const char *program) {
  unsigned short port = process_test_port();
  char port_text[16];
  const char *args[3];
  turbo_process_options_t options;
  turbo_process_t *child = NULL;
  turbo_process_result_t child_result;
  flowmq_coronet_tls_client_config_t tls;
  flowmq_connect_endpoint_config_t endpoint;
  mesh_node_ipc_flowmq_config_v1_t config;
  mesh_node_ipc_frame_view_v1_t view;
  process_test_peer_v1_t peer;
  uint8_t frame[512];
  char child_stdout[64];
  size_t frame_size;
  size_t child_stdout_size = 0u;
  const char *failed_stage = "select-port";
  int result = 1;

  memset(&peer, 0, sizeof(peer));
  memset(&child_result, 0, sizeof(child_result));
  if (!program || port == 0u ||
      snprintf(port_text, sizeof(port_text), "%u", (unsigned int)port) <= 0)
    goto cleanup;
  args[0] = "--server";
  args[1] = port_text;
  args[2] = NULL;
  turbo_process_options_init(&options);
  options.program = program;
  options.args = args;
  options.timeout_ms = PROCESS_TEST_CHILD_DEADLINE_MS;
  options.max_output_bytes = PROCESS_TEST_MAX_OUTPUT_BYTES;
  failed_stage = "spawn-child";
  if (turbo_process_spawn(&options, &child) != TURBO_OK) goto cleanup;

  failed_stage = "tls-profile";
  if (flowmq_coronet_tls_require_tls13() != TURBO_OK) goto cleanup;
  memset(&tls, 0, sizeof(tls));
  tls.ca_file = MESH_TEST_FLOWMQ_CA_FILE;
  tls.cert_file = MESH_TEST_FLOWMQ_CLIENT_CERT_FILE;
  tls.key_file = MESH_TEST_FLOWMQ_CLIENT_KEY_FILE;
  tls.server_name = "localhost";
  tls.verify_peer = 1;
  process_test_client_endpoint(&endpoint, port, &tls);
  failed_stage = "channel-init";
  if (process_test_peer_channels_init(&peer) != 0) goto cleanup;
  memset(&config, 0, sizeof(config));
  config.mode = MESH_NODE_IPC_FLOWMQ_CONNECT_V1;
  config.connect_endpoint = &endpoint;
  config.expected_peer_identity = "meshd";
  config.expected_peer_certificate_sha256 =
      PROCESS_TEST_SERVER_TLS_CERTIFICATE_SHA256;
  config.identity_policy_generation = PROCESS_TEST_POLICY_GENERATION;
  config.inbound = &peer.inbound;
  config.outbound = &peer.outbound;
  failed_stage = "adapter-init";
  if (mesh_node_ipc_flowmq_init_v1(&peer.adapter, &config) !=
      MESH_CONTROL_OK)
    goto cleanup;
  failed_stage = "adapter-start";
  if (mesh_node_ipc_flowmq_start_v1(&peer.adapter) != MESH_CONTROL_OK)
    goto cleanup;
  failed_stage = "encode-command";
  frame_size = process_test_command_frame(frame, sizeof(frame));
  if (frame_size == 0u) goto cleanup;
  failed_stage = "queue-command";
  if (mesh_node_ipc_channel_try_push_v1(&peer.outbound, frame, frame_size) !=
      MESH_CONTROL_OK)
    goto cleanup;
  failed_stage = "send-command";
  if (process_test_pump_send(&peer) != 0) goto cleanup;
  failed_stage = "receive-response";
  if (process_test_wait_pending(&peer.inbound) != 0) goto cleanup;
  failed_stage = "validate-response";
  if (mesh_node_ipc_channel_peek_v1(&peer.inbound, &view) !=
          MESH_CONTROL_OK ||
      view.frame_size != frame_size || memcmp(view.frame, frame, frame_size) != 0)
    goto cleanup;
  failed_stage = "consume-response";
  if (mesh_node_ipc_channel_consume_v1(&peer.inbound) != MESH_CONTROL_OK)
    goto cleanup;
  failed_stage = "stop";
  if (mesh_node_ipc_flowmq_stop_v1(&peer.adapter) != MESH_CONTROL_OK)
    goto cleanup;
  failed_stage = "wait-child-exit";
  if (turbo_process_wait_for(child, PROCESS_TEST_CHILD_WAIT_MS,
                             &child_result) != TURBO_OK ||
      child_result.state != TURBO_PROCESS_EXITED || child_result.exit_code != 0)
    goto cleanup;
  failed_stage = "validate-child-ready";
  memset(child_stdout, 0, sizeof(child_stdout));
  {
    int read_result = turbo_process_read_stdout(
        child, child_stdout, sizeof(child_stdout) - 1u, &child_stdout_size);
    if ((read_result != TURBO_OK && read_result != TURBO_EOF) ||
        child_stdout_size == 0u || !strstr(child_stdout, "READY"))
      goto cleanup;
  }
  result = 0;

cleanup:
  process_test_peer_destroy(&peer);
  if (child) {
    if (turbo_process_is_running(child)) {
      (void)turbo_process_terminate(child);
      (void)turbo_process_wait_for(child, PROCESS_TEST_CHILD_WAIT_MS,
                                   &child_result);
    }
    if (result != 0) process_test_print_child_stderr(child);
    turbo_process_destroy(child);
  }
  if (result != 0)
    fprintf(stderr,
            "cross-process FlowMQ certificate identity test failed at %s\n",
            failed_stage);
  return result;
}

int main(int argc, char **argv) {
  unsigned short port;
  if (argc == 3 && strcmp(argv[1], "--server") == 0) {
    if (process_test_parse_port(argv[2], &port) != 0) return 2;
    return process_test_server(port);
  }
  if (argc != 1) return 2;
  return process_test_parent(argv[0]);
}
