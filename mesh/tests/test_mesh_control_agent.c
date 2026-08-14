#include "mesh_control_agent.h"
#include "mesh_mgmt_crypto.h"
#include <p2p.h>
#include "tinytest.h"
#include <turbo_crypto.h>
#include <turbo_http.h>

#include <stdio.h>
#include <stdlib.h>
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

#define TEST_HTTP_RESPONSE_CAPACITY 4096u
#define TEST_HTTP_TIMEOUT_MS 3000u
#define TEST_RUN_TIMEOUT_MS 5000u

static const char TEST_CERTIFICATE_SHA256[] =
    "sha256:ebd76f304bc43bc2be697fca2f054206978c0558931529a7c1b2bb7d82a7a3c4";
static const uint8_t TEST_SIGNING_PRIVATE_KEY[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};

typedef struct {
  mesh_control_agent_v1_t *agent;
  uint16_t port;
  const char *path;
  uint8_t response[TEST_HTTP_RESPONSE_CAPACITY + 1u];
  size_t response_size;
  int result;
  int done;
} test_http_request_t;

typedef struct {
  turbo_http_t *client;
  const char *url;
  http_response_t *response;
  int done;
} test_h2_request_t;

static uint64_t test_now_ms(void *context) {
  (void)context;
  return 1500u;
}

typedef struct {
  mesh_control_provider_request_v1_t request;
  uint8_t active;
  uint8_t completion_ready;
  uint8_t closed;
} test_native_provider_t;

static mesh_control_result_t
test_native_try_start(void *context, const mesh_control_provider_request_v1_t *request) {
  test_native_provider_t *provider = (test_native_provider_t *)context;
  if (provider == NULL || request == NULL || provider->closed)
    return MESH_CONTROL_INVALID_STATE;
  if (provider->active)
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  provider->request = *request;
  provider->active = 1u;
  return MESH_CONTROL_OK;
}

static mesh_control_result_t
test_native_peek_completion(void *context, mesh_control_provider_completion_v1_t *out_completion) {
  test_native_provider_t *provider = (test_native_provider_t *)context;
  if (provider == NULL || out_completion == NULL)
    return MESH_CONTROL_INVALID_ARG;
  if (!provider->completion_ready)
    return MESH_CONTROL_EMPTY;
  memset(out_completion, 0, sizeof(*out_completion));
  memcpy(out_completion->operation_id, provider->request.operation.operation_id,
         sizeof(out_completion->operation_id));
  out_completion->state = MESH_CONTROL_PROVIDER_COMPLETED;
  return MESH_CONTROL_OK;
}

static mesh_control_result_t
test_native_ack_completion(void *context, const uint8_t operation_id[MESH_CONTROL_ID_SIZE]) {
  test_native_provider_t *provider = (test_native_provider_t *)context;
  if (provider == NULL || operation_id == NULL || !provider->completion_ready ||
      memcmp(operation_id, provider->request.operation.operation_id, MESH_CONTROL_ID_SIZE) != 0) {
    return MESH_CONTROL_INVALID_ARG;
  }
  provider->completion_ready = 0u;
  provider->active = 0u;
  return MESH_CONTROL_OK;
}

static void test_native_close(void *context) {
  test_native_provider_t *provider = (test_native_provider_t *)context;
  provider->closed = 1u;
  if (!provider->completion_ready)
    provider->active = 0u;
}

static int test_native_is_drained(void *context) {
  const test_native_provider_t *provider = (const test_native_provider_t *)context;
  return provider->closed && !provider->active && !provider->completion_ready;
}

static void configure_test_native_provider(mesh_control_agent_config_v1_t *config,
                                           mesh_control_provider_v1_t *descriptor,
                                           test_native_provider_t *provider) {
  memset(descriptor, 0, sizeof(*descriptor));
  descriptor->provider_id[0] = 0x32u;
  descriptor->runtime = MESH_CONTROL_FUNCTION_NATIVE;
  descriptor->ops.try_start = test_native_try_start;
  descriptor->ops.try_peek_completion = test_native_peek_completion;
  descriptor->ops.ack_completion = test_native_ack_completion;
  descriptor->ops.close = test_native_close;
  descriptor->ops.is_drained = test_native_is_drained;
  descriptor->context = provider;
  config->function_reconciler.providers = descriptor;
  config->function_reconciler.provider_count = 1u;
  config->function_reconciler.inflight_capacity = config->owner.state.operation_capacity;
  config->max_provider_completions_per_poll = 4u;
  config->max_provider_starts_per_poll = 4u;
}

static uint16_t agent_bound_port(const mesh_control_agent_v1_t *agent) {
  struct sockaddr_storage address;
  if (agent == NULL || agent->listener == NULL ||
      coro_socket_get_local_address(agent->listener, &address) != 0)
    return 0u;
  if (address.ss_family == AF_INET)
    return ntohs(((const struct sockaddr_in *)&address)->sin_port);
  if (address.ss_family == AF_INET6)
    return ntohs(((const struct sockaddr_in6 *)&address)->sin6_port);
  return 0u;
}

static uint16_t pick_loopback_port(void) {
  struct sockaddr_in address;
#ifdef _WIN32
  int address_size = (int)sizeof(address);
  SOCKET socket_handle = INVALID_SOCKET;
#else
  socklen_t address_size = (socklen_t)sizeof(address);
  int socket_handle = -1;
#endif
  uint16_t port = 0u;

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
      getsockname(socket_handle, (struct sockaddr *)&address, &address_size) == 0)
    port = ntohs(address.sin_port);
#ifdef _WIN32
  closesocket(socket_handle);
#else
  close(socket_handle);
#endif
  return port;
}

static int http_response_complete(const uint8_t *response, size_t size) {
  const char *headers_end;
  const char *content_length;
  char *end = NULL;
  unsigned long length;
  size_t header_size;

  if (response == NULL || size == 0u)
    return 0;
  headers_end = strstr((const char *)response, "\r\n\r\n");
  if (headers_end == NULL)
    return 0;
  content_length = strstr((const char *)response, "Content-Length: ");
  if (content_length == NULL || content_length > headers_end)
    return -1;
  content_length += strlen("Content-Length: ");
  length = strtoul(content_length, &end, 10);
  if (end == content_length || end == NULL || (end[0] != '\r' && end[0] != '\n') ||
      length > TEST_HTTP_RESPONSE_CAPACITY)
    return -1;
  header_size = (size_t)(headers_end + 4 - (const char *)response);
  return size >= header_size + (size_t)length ? 1 : 0;
}

static void test_http_client_task(coro_t *coroutine, void *context) {
  static const char *const alpn[] = {"http/1.1"};
  test_http_request_t *request = (test_http_request_t *)context;
  turbo_tls_client_config_t tls;
  coro_socket_t *client = NULL;
  char wire_request[512];
  int wire_size;
  int complete = 0;

  (void)coroutine;
  memset(&tls, 0, sizeof(tls));
  tls.ca_file = MESH_CONTROL_AGENT_TEST_CERT;
  tls.cert_file = MESH_CONTROL_AGENT_TEST_CERT;
  tls.key_file = MESH_CONTROL_AGENT_TEST_KEY;
  tls.verify_peer = 1;
  request->result = -2;
  client = coro_socket_create(request->agent->context, CORO_SOCKET_TLS);
  if (client == NULL)
    goto cleanup;
  coro_socket_set_timeout(client, TEST_HTTP_TIMEOUT_MS);
  request->result = -3;
  if (coro_socket_set_tls_client_config(client, &tls) != 0)
    goto cleanup;
  request->result = -4;
  if (coro_socket_set_tls_alpn(client, alpn, 1u) != 0)
    goto cleanup;
  request->result = -5;
  if (coro_socket_connect(client, "localhost", request->port) != 0)
    goto cleanup;
  wire_size = snprintf(wire_request, sizeof(wire_request),
                       "GET %s HTTP/1.1\r\n"
                       "Host: localhost\r\n"
                       "Connection: close\r\n\r\n",
                       request->path);
  request->result = -6;
  if (wire_size <= 0 || (size_t)wire_size >= sizeof(wire_request))
    goto cleanup;
  request->result = -7;
  if (coro_socket_send(client, wire_request, (size_t)wire_size) != 0)
    goto cleanup;
  while (request->response_size < TEST_HTTP_RESPONSE_CAPACITY) {
    char *data = NULL;
    size_t data_size = 0u;
    if (coro_socket_recv(client, &data, &data_size) != 0 || data == NULL || data_size == 0u ||
        data_size > TEST_HTTP_RESPONSE_CAPACITY - request->response_size) {
      if (data != NULL)
        coro_socket_free_recv(data);
      request->result = -8;
      goto cleanup;
    }
    memcpy(request->response + request->response_size, data, data_size);
    request->response_size += data_size;
    request->response[request->response_size] = '\0';
    coro_socket_free_recv(data);
    complete = http_response_complete(request->response, request->response_size);
    if (complete != 0)
      break;
  }
  request->result = complete == 1 ? 0 : -9;

cleanup:
  if (client != NULL)
    coro_socket_destroy(client);
  request->done = 1;
}

static void test_h2_client_task(coro_t *coroutine, void *context) {
  test_h2_request_t *request = (test_h2_request_t *)context;
  (void)coroutine;
  request->response =
      turbo_http_request(request->client, HTTP_GET, request->url, NULL, 0, NULL, 0u);
  request->done = 1;
}

static int run_http_get(mesh_control_agent_v1_t *agent, const char *path,
                        test_http_request_t *request) {
  uint64_t deadline;
  size_t processed;
  memset(request, 0, sizeof(*request));
  request->agent = agent;
  request->port = agent->config.port != 0u ? agent->config.port : agent_bound_port(agent);
  request->path = path;
  request->result = -10;
  if (request->port == 0u)
    return -11;
  if (coro_context_spawn(agent->context, test_http_client_task, request) != 0)
    return -12;
  deadline = turbo_monotonic_ms() + TEST_RUN_TIMEOUT_MS;
  while (!request->done && turbo_monotonic_ms() < deadline) {
    if (mesh_control_agent_poll_v1(agent, &processed) != MESH_CONTROL_OK)
      return -13;
  }
  return request->done ? request->result : -14;
}

static const uint8_t *http_response_body(const test_http_request_t *request, size_t *out_size) {
  const char *headers_end;
  const char *content_length;
  unsigned long length;
  size_t header_size;
  if (request == NULL || out_size == NULL)
    return NULL;
  headers_end = strstr((const char *)request->response, "\r\n\r\n");
  content_length = strstr((const char *)request->response, "Content-Length: ");
  if (headers_end == NULL || content_length == NULL || content_length > headers_end)
    return NULL;
  length = strtoul(content_length + strlen("Content-Length: "), NULL, 10);
  header_size = (size_t)(headers_end + 4 - (const char *)request->response);
  if (length > request->response_size - header_size)
    return NULL;
  *out_size = (size_t)length;
  return request->response + header_size;
}

static void make_agent_config(mesh_control_agent_config_v1_t *config,
                              turbo_tls_server_config_t *tls) {
  static const char *const alpn[] = {"h2", "http/1.1"};
  static const char fingerprint[] =
      "sha256:0000000000000000000000000000000000000000000000000000000000000000";

  memset(tls, 0, sizeof(*tls));
  tls->size = sizeof(*tls);
  tls->cert_file = MESH_CONTROL_AGENT_TEST_CERT;
  tls->key_file = MESH_CONTROL_AGENT_TEST_KEY;
  tls->ca_file = MESH_CONTROL_AGENT_TEST_CERT;
  tls->client_auth = TURBO_TLS_CLIENT_AUTH_REQUIRED;
  tls->alpn_protos = alpn;
  tls->alpn_proto_count = 2u;

  memset(config, 0, sizeof(*config));
  config->host = "127.0.0.1";
  config->port = 0u;
  config->tls = tls;
  config->controller_tls_certificate_sha256 = fingerprint;
  config->controller_node_id[0] = 7u;
  config->controller_certificate_serial = 8u;
  config->controller_permissions = MESH_CONTROL_PERMISSION_OBSERVE | MESH_CONTROL_PERMISSION_MANAGE;
  mesh_control_node_policy_default_v1(&config->node_policy);
  config->owner.state.resource_capacity = 4u;
  config->owner.state.operation_capacity = 4u;
  config->owner.state.event_capacity = 8u;
  config->owner.state.terminal_retention_ms = 1000u;
  config->owner.state.desired_document_max_bytes = 4096u;
  config->owner.state.desired_document_retained_bytes = 16u * 1024u;
  config->owner.replay.capacity = 8u;
  config->owner.replay.ttl_ms = 1000u;
  config->owner.mesh_id[0] = 1u;
  config->owner.node_id[0] = 2u;
  config->owner.replay_binding.principal_key[0] = 3u;
  config->owner.replay_binding.principal_epoch = 4u;
  config->owner.replay_binding.incarnation = 5u;
  config->owner.replay_binding.session_id[0] = 6u;
  config->channel_capacity = 8u;
  config->channel_retained_bytes = 64u * 1024u;
  config->channel_max_payload = 4096u;
  config->max_commands_per_poll = 8u;
  config->status_page_resource_limit = 8u;
  config->status_page_operation_limit = 8u;
  config->status_event_limit = 16u;
  config->shutdown_drain_timeout_ms = TEST_HTTP_TIMEOUT_MS;
  config->now_ms = test_now_ms;
}

static void test_agent_requires_mtls_and_both_alpn_protocols(void) {
  mesh_control_agent_v1_t agent = {0};
  mesh_control_agent_config_v1_t config;
  turbo_tls_server_config_t tls;

  make_agent_config(&config, &tls);
  tls.client_auth = TURBO_TLS_CLIENT_AUTH_NONE;
  check_int_eq(mesh_control_agent_start_v1(&agent, &config), MESH_CONTROL_INVALID_ARG);
  make_agent_config(&config, &tls);
  tls.alpn_proto_count = 1u;
  check_int_eq(mesh_control_agent_start_v1(&agent, &config), MESH_CONTROL_INVALID_ARG);
  make_agent_config(&config, &tls);
  config.controller_tls_certificate_sha256 = "sha256:ABC";
  check_int_eq(mesh_control_agent_start_v1(&agent, &config), MESH_CONTROL_INVALID_ARG);
  make_agent_config(&config, &tls);
  config.shutdown_drain_timeout_ms = 0u;
  check_int_eq(mesh_control_agent_start_v1(&agent, &config), MESH_CONTROL_INVALID_ARG);
}

static void test_agent_starts_polls_and_stops_cleanly(void) {
  mesh_control_agent_v1_t agent = {0};
  mesh_control_agent_config_v1_t config;
  turbo_tls_server_config_t tls;
  mesh_control_status_page_view_v1_t page;
  uint8_t status[512];
  size_t status_size = 0u;
  size_t processed = 99u;

  make_agent_config(&config, &tls);
  check_int_eq(mesh_control_agent_start_v1(&agent, &config), MESH_CONTROL_OK);
  check_not_null(mesh_control_agent_state_v1(&agent));
  check_int_eq(
      mesh_control_agent_status_page_v1(&agent, 0u, 0u, 0u, status, sizeof(status), &status_size),
      MESH_CONTROL_OK);
  check_int_eq(mesh_control_status_page_decode_v1(status, status_size, &page), MESH_CONTROL_OK);
  check_int_eq(page.resource_total, 0u);
  check_int_eq(page.operation_total, 0u);
  check_true(page.generation != 0u);
  check_int_eq(mesh_control_agent_poll_v1(&agent, &processed), MESH_CONTROL_OK);
  check_int_eq(processed, 0u);
  check_int_eq(mesh_control_agent_stop_v1(&agent), MESH_CONTROL_OK);
  check_null(mesh_control_agent_state_v1(&agent));
}

static void make_status_intent(mesh_control_envelope_v1_t *intent, uint8_t identity,
                               uint8_t resource_id) {
  memset(intent, 0, sizeof(*intent));
  intent->schema_version = MESH_CONTROL_SCHEMA_V1;
  intent->kind = MESH_CONTROL_MESSAGE_INTENT;
  intent->message_id[0] = identity;
  intent->request_id[0] = (uint8_t)(identity + 1u);
  intent->mesh_id[0] = 1u;
  intent->origin_principal[0] = 3u;
  intent->target_node_id[0] = 2u;
  intent->resource_kind = MESH_CONTROL_RESOURCE_NODE;
  intent->resource_id[0] = resource_id;
  intent->epoch = 1u;
  intent->sequence = identity;
  intent->issued_at_ms = 1000u;
  intent->expires_at_ms = 2000u;
  intent->payload_digest[0] = identity;
  intent->payload_size = 1u;
}

static size_t make_signed_function_frame(mesh_control_function_runtime_v1_t runtime,
                                         uint8_t identity, uint8_t frame[MESH_MGMT_FRAME_MAX]) {
  mesh_control_function_spec_v1_t spec;
  mesh_control_envelope_v1_t envelope;
  mesh_mgmt_sign_input_v1_t sign_input;
  uint8_t signing_public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE];
  uint8_t document[MESH_CONTROL_FUNCTION_DOCUMENT_SIZE_V1];
  uint8_t intent[MESH_CONTROL_FUNCTION_DOCUMENT_SIZE_V1 + MESH_CONTROL_INTENT_HEADER_SIZE_V1];
  uint8_t payload[MESH_CONTROL_MMP_PAYLOAD_HEADER_SIZE_V1 + sizeof(intent)];
  size_t document_size = 0u;
  size_t intent_size = 0u;
  size_t payload_size = 0u;
  size_t frame_size = 0u;

  memset(&spec, 0, sizeof(spec));
  spec.schema_version = MESH_CONTROL_SCHEMA_V1;
  spec.runtime = runtime;
  spec.desired_state = MESH_CONTROL_FUNCTION_RUNNING;
  spec.flags = MESH_CONTROL_FUNCTION_FLAG_PRESTAGED;
  if (runtime == MESH_CONTROL_FUNCTION_NATIVE)
    spec.flags |= MESH_CONTROL_FUNCTION_FLAG_OUT_OF_PROCESS;
  spec.function_id[0] = 0x31u;
  spec.provider_id[0] = 0x32u;
  spec.artifact_digest[0] = 0x33u;
  spec.config_digest[0] = 0x34u;
  spec.network_policy_digest[0] = 0x35u;
  spec.generation = 1u;
  spec.limits.memory_bytes = 1024u;
  spec.limits.cpu_time_ms = 100u;
  spec.limits.input_bytes = 1024u;
  spec.limits.output_bytes = 1024u;
  spec.limits.concurrency = 1u;
  spec.limits.host_calls = 1u;
  check_int_eq(
      mesh_control_function_document_encode_v1(&spec, document, sizeof(document), &document_size),
      MESH_CONTROL_OK);
  check_int_eq(mesh_control_intent_encode_v1(MESH_CONTROL_DESIRED_APPLY, document, document_size,
                                             intent, sizeof(intent), &intent_size),
               MESH_CONTROL_OK);

  memset(&envelope, 0, sizeof(envelope));
  check_int_eq(mesh_mgmt_ed25519_public_from_private(TEST_SIGNING_PRIVATE_KEY, signing_public_key),
               MESH_MGMT_CRYPTO_OK);
  envelope.schema_version = MESH_CONTROL_SCHEMA_V1;
  envelope.kind = MESH_CONTROL_MESSAGE_INTENT;
  envelope.message_id[0] = identity;
  envelope.request_id[0] = (uint8_t)(identity + 1u);
  envelope.mesh_id[0] = 1u;
  memcpy(envelope.origin_principal, signing_public_key, sizeof(envelope.origin_principal));
  envelope.origin_node_id[0] = 7u;
  envelope.session_id[0] = 6u;
  envelope.target_node_id[0] = 2u;
  envelope.resource_kind = MESH_CONTROL_RESOURCE_FUNCTION;
  memcpy(envelope.resource_id, spec.function_id, sizeof(envelope.resource_id));
  envelope.epoch = spec.generation;
  envelope.sequence = identity;
  envelope.issued_at_ms = 1000u;
  envelope.expires_at_ms = 2000u;
  envelope.principal_epoch = 4u;
  envelope.incarnation = 5u;
  envelope.certificate_serial = 8u;
  envelope.payload_size = intent_size;
  check_int_eq(mesh_control_mmp_body_digest_v1(intent, intent_size, envelope.payload_digest),
               MESH_CONTROL_MMP_OK);
  check_int_eq(mesh_control_mmp_payload_encode_v1(&envelope, intent, intent_size, payload,
                                                  sizeof(payload), &payload_size),
               MESH_CONTROL_MMP_OK);

  memset(&sign_input, 0, sizeof(sign_input));
  sign_input.minor = MESH_MGMT_MINOR_V1;
  sign_input.kind = MESH_MGMT_KIND_CONTROL_FRAME;
  sign_input.private_key = TEST_SIGNING_PRIVATE_KEY;
  sign_input.payload = payload;
  sign_input.payload_len = payload_size;
  memcpy(sign_input.header.mesh_id_hash, envelope.mesh_id, sizeof(sign_input.header.mesh_id_hash));
  memcpy(sign_input.header.origin_node_id, envelope.origin_node_id,
         sizeof(sign_input.header.origin_node_id));
  memcpy(sign_input.header.target_node_id, envelope.target_node_id,
         sizeof(sign_input.header.target_node_id));
  sign_input.header.principal_epoch = envelope.principal_epoch;
  sign_input.header.incarnation = envelope.incarnation;
  memcpy(sign_input.header.session_id, envelope.session_id, sizeof(sign_input.header.session_id));
  sign_input.header.origin_sequence = envelope.sequence;
  memcpy(sign_input.header.message_id, envelope.message_id, sizeof(sign_input.header.message_id));
  sign_input.header.issued_at_ms = envelope.issued_at_ms;
  sign_input.header.expires_at_ms = envelope.expires_at_ms;
  sign_input.header.certificate_serial = envelope.certificate_serial;
  check_int_eq(mesh_mgmt_envelope_sign_v1(&sign_input, frame, MESH_MGMT_FRAME_MAX, &frame_size),
               MESH_MGMT_ENVELOPE_OK);
  return frame_size;
}

static size_t make_signed_service_frame(uint8_t identity, uint8_t frame[MESH_MGMT_FRAME_MAX]) {
  static const uint8_t document[] = {0xaau, 0xbbu};
  mesh_control_envelope_v1_t envelope;
  mesh_mgmt_sign_input_v1_t sign_input;
  uint8_t signing_public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE];
  uint8_t intent[64];
  uint8_t payload[256];
  size_t intent_size = 0u;
  size_t payload_size = 0u;
  size_t frame_size = 0u;

  check_int_eq(mesh_control_intent_encode_v1(MESH_CONTROL_DESIRED_APPLY, document, sizeof(document),
                                             intent, sizeof(intent), &intent_size),
               MESH_CONTROL_OK);
  check_int_eq(mesh_mgmt_ed25519_public_from_private(TEST_SIGNING_PRIVATE_KEY, signing_public_key),
               MESH_MGMT_CRYPTO_OK);
  memset(&envelope, 0, sizeof(envelope));
  envelope.schema_version = MESH_CONTROL_SCHEMA_V1;
  envelope.kind = MESH_CONTROL_MESSAGE_INTENT;
  envelope.message_id[0] = identity;
  envelope.request_id[0] = (uint8_t)(identity + 1u);
  envelope.mesh_id[0] = 1u;
  memcpy(envelope.origin_principal, signing_public_key, sizeof(envelope.origin_principal));
  envelope.origin_node_id[0] = 7u;
  envelope.session_id[0] = 6u;
  envelope.target_node_id[0] = 2u;
  envelope.resource_kind = MESH_CONTROL_RESOURCE_SERVICE;
  envelope.resource_id[0] = 0x51u;
  envelope.epoch = 1u;
  envelope.sequence = identity;
  envelope.issued_at_ms = 1000u;
  envelope.expires_at_ms = 2000u;
  envelope.principal_epoch = 4u;
  envelope.incarnation = 5u;
  envelope.certificate_serial = 8u;
  envelope.payload_size = intent_size;
  check_int_eq(mesh_control_mmp_body_digest_v1(intent, intent_size, envelope.payload_digest),
               MESH_CONTROL_MMP_OK);
  check_int_eq(mesh_control_mmp_payload_encode_v1(&envelope, intent, intent_size, payload,
                                                  sizeof(payload), &payload_size),
               MESH_CONTROL_MMP_OK);

  memset(&sign_input, 0, sizeof(sign_input));
  sign_input.minor = MESH_MGMT_MINOR_V1;
  sign_input.kind = MESH_MGMT_KIND_CONTROL_FRAME;
  sign_input.private_key = TEST_SIGNING_PRIVATE_KEY;
  sign_input.payload = payload;
  sign_input.payload_len = payload_size;
  memcpy(sign_input.header.mesh_id_hash, envelope.mesh_id, sizeof(sign_input.header.mesh_id_hash));
  memcpy(sign_input.header.origin_node_id, envelope.origin_node_id,
         sizeof(sign_input.header.origin_node_id));
  memcpy(sign_input.header.target_node_id, envelope.target_node_id,
         sizeof(sign_input.header.target_node_id));
  sign_input.header.principal_epoch = envelope.principal_epoch;
  sign_input.header.incarnation = envelope.incarnation;
  memcpy(sign_input.header.session_id, envelope.session_id, sizeof(sign_input.header.session_id));
  sign_input.header.origin_sequence = envelope.sequence;
  memcpy(sign_input.header.message_id, envelope.message_id, sizeof(sign_input.header.message_id));
  sign_input.header.issued_at_ms = envelope.issued_at_ms;
  sign_input.header.expires_at_ms = envelope.expires_at_ms;
  sign_input.header.certificate_serial = envelope.certificate_serial;
  check_int_eq(mesh_mgmt_envelope_sign_v1(&sign_input, frame, MESH_MGMT_FRAME_MAX, &frame_size),
               MESH_MGMT_ENVELOPE_OK);
  return frame_size;
}

typedef struct {
  mesh_fabric_t *fabric;
  mesh_network_issuer_v1_t issuer;
  uint8_t mesh_id[MESH_CONTROL_DIGEST_SIZE];
  uint8_t node_private[MESH_NETWORK_IDENTITY_SIZE];
  uint8_t node_public[MESH_NETWORK_IDENTITY_SIZE];
} test_agent_network_fixture_t;

typedef struct {
  mesh_control_operation_v1_t operation;
  mesh_control_agent_v1_t *agent;
  uint64_t ack_log_index;
  size_t starts;
  size_t acks;
  uint8_t active;
  uint8_t closed;
} test_agent_network_provider_v1_t;

static mesh_control_result_t test_network_provider_start(
    void *context,
    const mesh_control_network_provider_request_v1_t *request) {
  test_agent_network_provider_v1_t *provider =
      (test_agent_network_provider_v1_t *)context;
  if (!provider || !request || provider->closed)
    return MESH_CONTROL_INVALID_ARG;
  if (provider->active)
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  provider->operation = request->operation;
  provider->active = 1u;
  provider->starts++;
  return MESH_CONTROL_OK;
}

static mesh_control_result_t test_network_provider_peek(
    void *context, mesh_control_network_provider_completion_v1_t *completion) {
  test_agent_network_provider_v1_t *provider =
      (test_agent_network_provider_v1_t *)context;
  if (!provider || !completion)
    return MESH_CONTROL_INVALID_ARG;
  if (!provider->active)
    return MESH_CONTROL_EMPTY;
  memset(completion, 0, sizeof(*completion));
  memcpy(completion->operation_id, provider->operation.operation_id,
         sizeof(completion->operation_id));
  completion->state = MESH_CONTROL_NETWORK_PROVIDER_COMPLETED;
  return MESH_CONTROL_OK;
}

static mesh_control_result_t test_network_provider_ack(
    void *context,
    const uint8_t operation_id[MESH_CONTROL_ID_SIZE]) {
  test_agent_network_provider_v1_t *provider =
      (test_agent_network_provider_v1_t *)context;
  if (!provider || !operation_id || !provider->active ||
      memcmp(operation_id, provider->operation.operation_id,
             MESH_CONTROL_ID_SIZE) != 0)
    return MESH_CONTROL_INVALID_ARG;
  provider->ack_log_index = provider->agent->owner.committed_log_index;
  provider->active = 0u;
  provider->acks++;
  return MESH_CONTROL_OK;
}

static void test_network_provider_close(void *context) {
  test_agent_network_provider_v1_t *provider =
      (test_agent_network_provider_v1_t *)context;
  if (provider)
    provider->closed = 1u;
}

static int test_network_provider_drained(void *context) {
  test_agent_network_provider_v1_t *provider =
      (test_agent_network_provider_v1_t *)context;
  return provider && provider->closed && !provider->active;
}

static void test_hex_32(const uint8_t bytes[32], char output[65]) {
  static const char digits[] = "0123456789abcdef";
  size_t index;
  for (index = 0u; index < 32u; ++index) {
    output[index * 2u] = digits[bytes[index] >> 4u];
    output[index * 2u + 1u] = digits[bytes[index] & 0x0fu];
  }
  output[64] = '\0';
}

static int test_agent_network_fixture_init(
    test_agent_network_fixture_t *fixture,
    mesh_control_agent_config_v1_t *config) {
  static const char network_id[] = "control-agent-network";
  mesh_fabric_config_v2_t fabric_config;
  char node_public_hex[65];
  const char *allowed_nodes[1];
  if (!fixture || !config)
    return -1;
  memset(fixture, 0, sizeof(*fixture));
  memset(fixture->node_private, 0x44, sizeof(fixture->node_private));
  if (p2p_public_key_from_private_key(fixture->node_private,
                                     fixture->node_public) != P2P_OK ||
      turbo_crypto_sha256(network_id, strlen(network_id), fixture->mesh_id) !=
          TURBO_CRYPTO_OK ||
      mesh_mgmt_ed25519_public_from_private(TEST_SIGNING_PRIVATE_KEY,
                                            fixture->issuer.public_key) !=
          MESH_MGMT_CRYPTO_OK)
    return -1;
  memset(fixture->issuer.key_id, 0x61, sizeof(fixture->issuer.key_id));
  test_hex_32(fixture->node_public, node_public_hex);
  allowed_nodes[0] = node_public_hex;
  mesh_fabric_config_init_v2(&fabric_config);
  fabric_config.underlay.virtual_ip = "10.92.0.1";
  fabric_config.underlay.virtual_prefix = 24u;
  fabric_config.underlay.listen_port = 24992u;
  fabric_config.underlay.network_id = network_id;
  fabric_config.underlay.identity_private_key = fixture->node_private;
  fabric_config.underlay.identity_private_key_size =
      sizeof(fixture->node_private);
  fabric_config.underlay.peer_allow_node_ids = allowed_nodes;
  fabric_config.underlay.peer_allow_node_id_count = 1u;
  fabric_config.trusted_issuers = &fixture->issuer;
  fabric_config.trusted_issuer_count = 1u;
  if (mesh_fabric_create_v2(&fabric_config, &fixture->fabric) != MESH_OK)
    return -1;
  memcpy(config->owner.mesh_id, fixture->mesh_id,
         sizeof(config->owner.mesh_id));
  memcpy(config->owner.node_id, fixture->node_public,
         sizeof(config->owner.node_id));
  memcpy(config->owner.replay_binding.principal_key,
         fixture->issuer.public_key,
         sizeof(config->owner.replay_binding.principal_key));
  config->network_fabric = fixture->fabric;
  config->network_capacity = 2u;
  return 0;
}

static void test_agent_network_fixture_destroy(
    test_agent_network_fixture_t *fixture) {
  if (fixture && fixture->fabric) {
    mesh_fabric_destroy_v2(fixture->fabric);
    fixture->fabric = NULL;
  }
}

static size_t make_signed_canonical_network_frame(
    const test_agent_network_fixture_t *fixture,
    mesh_control_agent_config_v1_t *config, uint8_t identity,
    mesh_control_desired_action_v1_t action, uint64_t generation,
    uint64_t precondition_generation,
    const uint8_t resource_id_for_delete[MESH_CONTROL_DIGEST_SIZE],
    uint8_t out_resource_id[MESH_CONTROL_DIGEST_SIZE],
    uint8_t frame[MESH_MGMT_FRAME_MAX]) {
  mesh_control_network_document_v1_t document;
  mesh_network_membership_ticket_v1_t ticket;
  mesh_control_envelope_v1_t envelope;
  mesh_mgmt_sign_input_v1_t sign_input;
  uint8_t signing_public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE];
  uint8_t document_wire[MESH_CONTROL_NETWORK_DOCUMENT_BASE_SIZE_V1];
  uint8_t intent[MESH_CONTROL_NETWORK_DOCUMENT_BASE_SIZE_V1 +
                 MESH_CONTROL_INTENT_HEADER_SIZE_V1];
  uint8_t payload[MESH_CONTROL_MAX_FRAME_SIZE_V1];
  size_t ticket_size = 0u;
  size_t document_size = 0u;
  size_t intent_size = 0u;
  size_t payload_size = 0u;
  size_t frame_size = 0u;
  uint64_t now_s = (uint64_t)time(NULL);

  memset(&document, 0, sizeof(document));
  memset(&ticket, 0, sizeof(ticket));
  memset(&envelope, 0, sizeof(envelope));
  memset(ticket.network_uid.bytes, 0x51, sizeof(ticket.network_uid.bytes));
  memcpy(ticket.mesh_id, fixture->mesh_id, sizeof(ticket.mesh_id));
  memset(ticket.membership_id, 0x52, sizeof(ticket.membership_id));
  memcpy(ticket.managed_node_id, fixture->node_public,
         sizeof(ticket.managed_node_id));
  check_int_eq(MESH_OK, mesh_network_public_key_digest_v1(
                                fixture->node_public,
                                ticket.node_public_key_digest));
  ticket.network_generation = generation;
  ticket.membership_generation = generation;
  ticket.node_key_epoch = generation;
  ticket.policy_epoch = generation;
  ticket.ipv4_address = 0x0a5c0001u;
  ticket.ipv4_prefix = 24u;
  ticket.roles = MESH_NETWORK_ROLE_MEMBER;
  ticket.issued_at_unix_s = now_s - 1u;
  ticket.not_before_unix_s = now_s - 1u;
  ticket.not_after_unix_s = now_s + 3600u;
  memcpy(ticket.issuer_key_id, fixture->issuer.key_id,
         sizeof(ticket.issuer_key_id));
  check_int_eq(MESH_OK, mesh_network_membership_ticket_sign_v1(
                                &ticket, TEST_SIGNING_PRIVATE_KEY));

  document.schema_version = MESH_CONTROL_SCHEMA_V1;
  document.lifecycle = MESH_CONTROL_NETWORK_ACTIVE_V1;
  document.attach_mode = MESH_CONTROL_NETWORK_USERSPACE_V1;
  memcpy(document.network_uid, ticket.network_uid.bytes,
         sizeof(document.network_uid));
  memcpy(document.mesh_id, fixture->mesh_id, sizeof(document.mesh_id));
  memcpy(document.managed_node_id, fixture->node_public,
         sizeof(document.managed_node_id));
  document.generation = generation;
  document.policy_epoch = generation;
  document.route_epoch = generation;
  document.key_epoch = generation;
  document.ipv4_address = ticket.ipv4_address;
  document.ipv4_prefix = ticket.ipv4_prefix;
  document.mtu = 1280u;
  memcpy(document.name, "edge-cdn", sizeof("edge-cdn"));
  memset(document.policy_digest, 0x31, sizeof(document.policy_digest));
  memset(document.address_pool_digest, 0x32,
         sizeof(document.address_pool_digest));
  check_int_eq(MESH_OK, mesh_network_membership_ticket_encode_v1(
                                &ticket, document.membership_ticket,
                                sizeof(document.membership_ticket),
                                &ticket_size));
  check_uint_eq(MESH_CONTROL_NETWORK_TICKET_SIZE_V1, ticket_size);
  check_int_eq(MESH_CONTROL_OK, mesh_network_resource_id_v1(
                                       fixture->mesh_id, document.network_uid,
                                       out_resource_id));
  if (action == MESH_CONTROL_DESIRED_APPLY) {
    check_int_eq(MESH_CONTROL_OK, mesh_control_network_document_encode_v1(
                                         &document, document_wire,
                                         sizeof(document_wire),
                                         &document_size));
  } else {
    memcpy(out_resource_id, resource_id_for_delete,
           MESH_CONTROL_DIGEST_SIZE);
  }
  check_int_eq(MESH_CONTROL_OK, mesh_control_intent_encode_v1(
                                       action,
                                       action == MESH_CONTROL_DESIRED_APPLY
                                           ? document_wire
                                           : NULL,
                                       document_size, intent, sizeof(intent),
                                       &intent_size));
  check_int_eq(mesh_mgmt_ed25519_public_from_private(TEST_SIGNING_PRIVATE_KEY,
                                                     signing_public_key),
               MESH_MGMT_CRYPTO_OK);
  envelope.schema_version = MESH_CONTROL_SCHEMA_V1;
  envelope.kind = MESH_CONTROL_MESSAGE_INTENT;
  envelope.message_id[0] = identity;
  envelope.request_id[0] = (uint8_t)(identity + 1u);
  memcpy(envelope.mesh_id, fixture->mesh_id, sizeof(envelope.mesh_id));
  memcpy(envelope.origin_principal, signing_public_key,
         sizeof(envelope.origin_principal));
  memcpy(envelope.origin_node_id, config->controller_node_id,
         sizeof(envelope.origin_node_id));
  memcpy(envelope.target_node_id, fixture->node_public,
         sizeof(envelope.target_node_id));
  envelope.session_id[0] = 6u;
  envelope.resource_kind = MESH_CONTROL_RESOURCE_NETWORK;
  memcpy(envelope.resource_id, out_resource_id,
         sizeof(envelope.resource_id));
  envelope.epoch = generation;
  envelope.precondition_epoch = precondition_generation;
  envelope.sequence = identity;
  envelope.issued_at_ms = 1000u;
  envelope.expires_at_ms = 2000u;
  envelope.principal_epoch = 4u;
  envelope.incarnation = 5u;
  envelope.certificate_serial = 8u;
  envelope.payload_size = intent_size;
  check_int_eq(mesh_control_mmp_body_digest_v1(
                   intent, intent_size, envelope.payload_digest),
               MESH_CONTROL_MMP_OK);
  check_int_eq(mesh_control_mmp_payload_encode_v1(
                   &envelope, intent, intent_size, payload, sizeof(payload),
                   &payload_size),
               MESH_CONTROL_MMP_OK);
  memset(&sign_input, 0, sizeof(sign_input));
  sign_input.minor = MESH_MGMT_MINOR_V1;
  sign_input.kind = MESH_MGMT_KIND_CONTROL_FRAME;
  sign_input.private_key = TEST_SIGNING_PRIVATE_KEY;
  sign_input.payload = payload;
  sign_input.payload_len = payload_size;
  memcpy(sign_input.header.mesh_id_hash, envelope.mesh_id,
         sizeof(sign_input.header.mesh_id_hash));
  memcpy(sign_input.header.origin_node_id, envelope.origin_node_id,
         sizeof(sign_input.header.origin_node_id));
  memcpy(sign_input.header.target_node_id, envelope.target_node_id,
         sizeof(sign_input.header.target_node_id));
  sign_input.header.principal_epoch = envelope.principal_epoch;
  sign_input.header.incarnation = envelope.incarnation;
  memcpy(sign_input.header.session_id, envelope.session_id,
         sizeof(sign_input.header.session_id));
  sign_input.header.origin_sequence = envelope.sequence;
  memcpy(sign_input.header.message_id, envelope.message_id,
         sizeof(sign_input.header.message_id));
  sign_input.header.issued_at_ms = envelope.issued_at_ms;
  sign_input.header.expires_at_ms = envelope.expires_at_ms;
  sign_input.header.certificate_serial = envelope.certificate_serial;
  check_int_eq(mesh_mgmt_envelope_sign_v1(
                   &sign_input, frame, MESH_MGMT_FRAME_MAX, &frame_size),
               MESH_MGMT_ENVELOPE_OK);
  return frame_size;
}

static void cleanup_wal_files(const char *path) {
  char lock_path[TURBO_FS_MAX_PATH];
  (void)snprintf(lock_path, sizeof(lock_path), "%s.lock", path);
  if (turbo_fs_access(path, TURBO_FS_ACCESS_EXISTS) == 0)
    (void)turbo_fs_unlink(path);
  if (turbo_fs_access(lock_path, TURBO_FS_ACCESS_EXISTS) == 0)
    (void)turbo_fs_unlink(lock_path);
}

static void cleanup_checkpoint_files(const char *path) {
  char lock_path[TURBO_FS_MAX_PATH + 6u];
  char temp_path[TURBO_FS_MAX_PATH + 5u];
  (void)snprintf(lock_path, sizeof(lock_path), "%s.lock", path);
  (void)snprintf(temp_path, sizeof(temp_path), "%s.tmp", path);
  if (turbo_fs_access(path, TURBO_FS_ACCESS_EXISTS) == 0)
    (void)turbo_fs_unlink(path);
  if (turbo_fs_access(lock_path, TURBO_FS_ACCESS_EXISTS) == 0)
    (void)turbo_fs_unlink(lock_path);
  if (turbo_fs_access(temp_path, TURBO_FS_ACCESS_EXISTS) == 0)
    (void)turbo_fs_unlink(temp_path);
}

static void enable_durability(mesh_control_agent_config_v1_t *config, const char *path) {
  uint8_t signing_public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE];
  check_int_eq(mesh_mgmt_ed25519_public_from_private(TEST_SIGNING_PRIVATE_KEY, signing_public_key),
               MESH_MGMT_CRYPTO_OK);
  memcpy(config->owner.replay_binding.principal_key, signing_public_key,
         sizeof(config->owner.replay_binding.principal_key));
  config->durability_enabled = 1u;
  config->wal.path = path;
  config->wal.record_capacity = 8u;
  config->wal.byte_capacity = 64u * 1024u;
  memcpy(config->wal.mesh_id, config->owner.mesh_id, sizeof(config->wal.mesh_id));
  memcpy(config->wal.node_id, config->owner.node_id, sizeof(config->wal.node_id));
  memcpy(config->wal.controller_principal, config->owner.replay_binding.principal_key,
         sizeof(config->wal.controller_principal));
  memcpy(config->wal.controller_node_id, config->controller_node_id,
         sizeof(config->wal.controller_node_id));
  config->wal.principal_epoch = config->owner.replay_binding.principal_epoch;
  config->wal.incarnation = config->owner.replay_binding.incarnation;
  config->wal.certificate_serial = config->controller_certificate_serial;
  memcpy(config->wal.session_id, config->owner.replay_binding.session_id,
         sizeof(config->wal.session_id));
  memset(config->wal.authentication_key, 0xa5, sizeof(config->wal.authentication_key));
}

static void test_agent_applies_and_deletes_network_resources(void) {
  mesh_control_agent_v1_t agent = {0};
  mesh_control_agent_config_v1_t config;
  test_agent_network_fixture_t fixture;
  turbo_tls_server_config_t tls;
  mesh_fabric_status_v2_t fabric_status;
  mesh_control_resource_status_v1_t resource_status;
  uint8_t resource_id[MESH_CONTROL_DIGEST_SIZE];
  uint8_t delete_resource_id[MESH_CONTROL_DIGEST_SIZE];
  uint8_t frame[MESH_MGMT_FRAME_MAX];
  size_t frame_size;
  size_t processed = 0u;

  make_agent_config(&config, &tls);
  check_int_eq(0, test_agent_network_fixture_init(&fixture, &config));
  frame_size = make_signed_canonical_network_frame(
      &fixture, &config, 60u, MESH_CONTROL_DESIRED_APPLY, 1u, 0u, NULL,
      resource_id, frame);
  check_int_eq(MESH_CONTROL_OK,
               mesh_control_agent_start_v1(&agent, &config));
  check_int_eq(MESH_CONTROL_OK, mesh_control_iris_receive_frame_v1(
                                       &agent.iris, frame, frame_size));
  check_int_eq(MESH_CONTROL_OK,
               mesh_control_agent_poll_v1(&agent, &processed));
  check_size_eq(1u, processed);
  memset(&fabric_status, 0, sizeof(fabric_status));
  fabric_status.struct_size = sizeof(fabric_status);
  check_int_eq(MESH_OK,
               mesh_fabric_get_status_v2(fixture.fabric, &fabric_status));
  check_size_eq(1u, fabric_status.attached_networks);
  check_int_eq(MESH_CONTROL_OK, mesh_control_state_get_resource_v1(
                                       mesh_control_agent_state_v1(&agent),
                                       MESH_CONTROL_RESOURCE_NETWORK,
                                       resource_id, &resource_status));
  check_uint_eq(MESH_CONTROL_PRESENCE_PRESENT,
                resource_status.observed_presence);

  frame_size = make_signed_canonical_network_frame(
      &fixture, &config, 62u, MESH_CONTROL_DESIRED_DELETE, 2u, 1u,
      resource_id, delete_resource_id, frame);
  processed = 0u;
  check_int_eq(MESH_CONTROL_OK, mesh_control_iris_receive_frame_v1(
                                       &agent.iris, frame, frame_size));
  check_int_eq(MESH_CONTROL_OK,
               mesh_control_agent_poll_v1(&agent, &processed));
  check_size_eq(1u, processed);
  memset(&fabric_status, 0, sizeof(fabric_status));
  fabric_status.struct_size = sizeof(fabric_status);
  check_int_eq(MESH_OK,
               mesh_fabric_get_status_v2(fixture.fabric, &fabric_status));
  check_size_eq(0u, fabric_status.attached_networks);
  check_int_eq(MESH_CONTROL_OK, mesh_control_state_get_resource_v1(
                                       mesh_control_agent_state_v1(&agent),
                                       MESH_CONTROL_RESOURCE_NETWORK,
                                       resource_id, &resource_status));
  check_uint_eq(MESH_CONTROL_PRESENCE_ABSENT,
                resource_status.observed_presence);
  check_int_eq(MESH_CONTROL_OK, mesh_control_agent_stop_v1(&agent));
  test_agent_network_fixture_destroy(&fixture);
}

static void test_agent_persists_flowmq_network_completion_before_ack(void) {
  mesh_control_agent_v1_t agent = {0};
  mesh_control_agent_config_v1_t config;
  mesh_control_network_provider_v1_t descriptor;
  test_agent_network_provider_v1_t provider;
  test_agent_network_fixture_t fixture;
  turbo_tls_server_config_t tls;
  mesh_control_resource_status_v1_t resource_status;
  uint8_t resource_id[MESH_CONTROL_DIGEST_SIZE];
  uint8_t frame[MESH_MGMT_FRAME_MAX];
  size_t frame_size;
  size_t processed = 0u;
  size_t attempts;
  char *path = tt_make_temp_file("mesh-control-agent-network-provider",
                                 ".bin");

  check_not_null(path);
  if (!path)
    return;
  cleanup_wal_files(path);
  make_agent_config(&config, &tls);
  check_int_eq(0, test_agent_network_fixture_init(&fixture, &config));
  memset(&provider, 0, sizeof(provider));
  memset(&descriptor, 0, sizeof(descriptor));
  provider.agent = &agent;
  descriptor.ops.try_start = test_network_provider_start;
  descriptor.ops.try_peek_completion = test_network_provider_peek;
  descriptor.ops.ack_completion = test_network_provider_ack;
  descriptor.ops.close = test_network_provider_close;
  descriptor.ops.is_drained = test_network_provider_drained;
  descriptor.context = &provider;
  config.network_fabric = NULL;
  config.network_provider = &descriptor;
  config.network_capacity = 2u;
  config.max_provider_completions_per_poll = 4u;
  config.max_provider_starts_per_poll = 4u;
  enable_durability(&config, path);
  frame_size = make_signed_canonical_network_frame(
      &fixture, &config, 64u, MESH_CONTROL_DESIRED_APPLY, 1u, 0u, NULL,
      resource_id, frame);
  check_int_eq(MESH_CONTROL_OK,
               mesh_control_agent_start_v1(&agent, &config));
  check_int_eq(MESH_CONTROL_OK, mesh_control_iris_receive_frame_v1(
                                       &agent.iris, frame, frame_size));
  for (attempts = 0u; attempts < 1000u && provider.acks == 0u;
       ++attempts) {
    check_int_eq(MESH_CONTROL_OK,
                 mesh_control_agent_poll_v1(&agent, &processed));
    turbo_sleep_ms(1u);
  }
  check_true(attempts < 1000u);
  check_size_eq(1u, provider.starts);
  check_size_eq(1u, provider.acks);
  check_uint_eq(2u, provider.ack_log_index);
  check_uint_eq(2u, agent.owner.committed_log_index);
  check_int_eq(MESH_CONTROL_OK, mesh_control_state_get_resource_v1(
                                       mesh_control_agent_state_v1(&agent),
                                       MESH_CONTROL_RESOURCE_NETWORK,
                                       resource_id, &resource_status));
  check_uint_eq(MESH_CONTROL_PRESENCE_PRESENT,
                resource_status.observed_presence);
  check_int_eq(MESH_CONTROL_OK, mesh_control_agent_stop_v1(&agent));
  check_true(provider.closed);

  memset(&provider, 0, sizeof(provider));
  memset(&descriptor, 0, sizeof(descriptor));
  provider.agent = &agent;
  descriptor.ops.try_start = test_network_provider_start;
  descriptor.ops.try_peek_completion = test_network_provider_peek;
  descriptor.ops.ack_completion = test_network_provider_ack;
  descriptor.ops.close = test_network_provider_close;
  descriptor.ops.is_drained = test_network_provider_drained;
  descriptor.context = &provider;
  config.network_provider = &descriptor;
  check_int_eq(MESH_CONTROL_OK,
               mesh_control_agent_start_v1(&agent, &config));
  for (attempts = 0u; attempts < 1000u && provider.acks == 0u;
       ++attempts) {
    processed = SIZE_MAX;
    check_int_eq(MESH_CONTROL_OK,
                 mesh_control_agent_poll_v1(&agent, &processed));
    check_size_eq(0u, processed);
    turbo_sleep_ms(1u);
  }
  check_true(attempts < 1000u);
  check_size_eq(1u, provider.starts);
  check_size_eq(1u, provider.acks);
  check_uint_eq(2u, provider.ack_log_index);
  check_uint_eq(2u, agent.owner.committed_log_index);
  check_int_eq(MESH_CONTROL_OK, mesh_control_agent_stop_v1(&agent));
  test_agent_network_fixture_destroy(&fixture);
  cleanup_wal_files(path);
  free(path);
}

static void test_agent_persists_and_restores_network_runtime(void) {
  mesh_control_agent_v1_t agent = {0};
  mesh_control_agent_config_v1_t config;
  test_agent_network_fixture_t fixture;
  turbo_tls_server_config_t tls;
  mesh_fabric_status_v2_t fabric_status;
  mesh_control_resource_status_v1_t resource_status;
  uint8_t resource_id[MESH_CONTROL_DIGEST_SIZE];
  uint8_t frame[MESH_MGMT_FRAME_MAX];
  size_t frame_size;
  size_t processed = 0u;
  size_t attempts;
  char *path = tt_make_temp_file("mesh-control-agent-network", ".bin");

  check_not_null(path);
  if (!path)
    return;
  cleanup_wal_files(path);
  make_agent_config(&config, &tls);
  check_int_eq(0, test_agent_network_fixture_init(&fixture, &config));
  enable_durability(&config, path);
  frame_size = make_signed_canonical_network_frame(
      &fixture, &config, 70u, MESH_CONTROL_DESIRED_APPLY, 1u, 0u, NULL,
      resource_id, frame);
  check_int_eq(MESH_CONTROL_OK,
               mesh_control_agent_start_v1(&agent, &config));
  check_int_eq(MESH_CONTROL_OK, mesh_control_iris_receive_frame_v1(
                                       &agent.iris, frame, frame_size));
  for (attempts = 0u; attempts < 1000u &&
                      agent.owner.committed_log_index < 2u;
       ++attempts) {
    check_int_eq(MESH_CONTROL_OK,
                 mesh_control_agent_poll_v1(&agent, &processed));
    turbo_sleep_ms(1u);
  }
  check_true(attempts < 1000u);
  check_uint_eq(2u, agent.owner.committed_log_index);
  check_int_eq(MESH_CONTROL_OK, mesh_control_state_get_resource_v1(
                                       mesh_control_agent_state_v1(&agent),
                                       MESH_CONTROL_RESOURCE_NETWORK,
                                       resource_id, &resource_status));
  check_uint_eq(MESH_CONTROL_PRESENCE_PRESENT,
                resource_status.observed_presence);
  check_int_eq(MESH_CONTROL_OK, mesh_control_agent_stop_v1(&agent));
  memset(&fabric_status, 0, sizeof(fabric_status));
  fabric_status.struct_size = sizeof(fabric_status);
  check_int_eq(MESH_OK,
               mesh_fabric_get_status_v2(fixture.fabric, &fabric_status));
  check_size_eq(0u, fabric_status.attached_networks);
  test_agent_network_fixture_destroy(&fixture);

  make_agent_config(&config, &tls);
  check_int_eq(0, test_agent_network_fixture_init(&fixture, &config));
  enable_durability(&config, path);
  check_int_eq(MESH_CONTROL_OK,
               mesh_control_agent_start_v1(&agent, &config));
  check_uint_eq(2u, agent.owner.committed_log_index);
  memset(&fabric_status, 0, sizeof(fabric_status));
  fabric_status.struct_size = sizeof(fabric_status);
  check_int_eq(MESH_OK,
               mesh_fabric_get_status_v2(fixture.fabric, &fabric_status));
  check_size_eq(1u, fabric_status.attached_networks);
  check_int_eq(MESH_CONTROL_OK, mesh_control_agent_stop_v1(&agent));
  test_agent_network_fixture_destroy(&fixture);
  cleanup_wal_files(path);
  free(path);
}

static void test_agent_commits_after_wal_and_recovers_on_restart(void) {
  mesh_control_agent_v1_t agent = {0};
  mesh_control_agent_config_v1_t config;
  turbo_tls_server_config_t tls;
  mesh_control_resource_status_v1_t status;
  uint8_t frame[MESH_MGMT_FRAME_MAX];
  uint8_t resource_id[MESH_CONTROL_DIGEST_SIZE] = {0};
  size_t frame_size;
  size_t processed = 0u;
  size_t attempts;
  char *path = tt_make_temp_file("mesh-control-agent-wal", ".bin");

  check_not_null(path);
  if (!path)
    return;
  cleanup_wal_files(path);
  resource_id[0] = 0x51u;
  make_agent_config(&config, &tls);
  enable_durability(&config, path);
  frame_size = make_signed_service_frame(10u, frame);
  check_int_eq(mesh_control_agent_start_v1(&agent, &config), MESH_CONTROL_OK);
  check_int_eq(mesh_control_iris_receive_frame_v1(&agent.iris, frame, frame_size), MESH_CONTROL_OK);
  check_int_eq(mesh_control_agent_poll_v1(&agent, &processed), MESH_CONTROL_OK);
  check_size_eq(processed, 0u);
  check_int_eq(mesh_control_state_get_resource_v1(mesh_control_agent_state_v1(&agent),
                                                  MESH_CONTROL_RESOURCE_SERVICE, resource_id,
                                                  &status),
               MESH_CONTROL_EMPTY);
  for (attempts = 0u; attempts < 1000u && processed == 0u; ++attempts) {
    check_int_eq(mesh_control_agent_poll_v1(&agent, &processed), MESH_CONTROL_OK);
    turbo_sleep_ms(1u);
  }
  check_size_eq(processed, 1u);
  check_int_eq(mesh_control_state_get_resource_v1(mesh_control_agent_state_v1(&agent),
                                                  MESH_CONTROL_RESOURCE_SERVICE, resource_id,
                                                  &status),
               MESH_CONTROL_OK);
  check_uint_eq(agent.owner.committed_log_index, 1u);
  check_int_eq(mesh_control_agent_stop_v1(&agent), MESH_CONTROL_OK);

  make_agent_config(&config, &tls);
  enable_durability(&config, path);
  check_int_eq(mesh_control_agent_start_v1(&agent, &config), MESH_CONTROL_OK);
  check_int_eq(mesh_control_state_get_resource_v1(mesh_control_agent_state_v1(&agent),
                                                  MESH_CONTROL_RESOURCE_SERVICE, resource_id,
                                                  &status),
               MESH_CONTROL_OK);
  check_uint_eq(agent.owner.committed_log_index, 1u);
  check_int_eq(mesh_control_agent_stop_v1(&agent), MESH_CONTROL_OK);
  cleanup_wal_files(path);
  free(path);
}

static void test_agent_checkpoints_compacts_and_recovers_before_ingress(void) {
  mesh_control_agent_v1_t agent = {0};
  mesh_control_agent_config_v1_t config;
  mesh_control_wal_worker_stats_v1_t stats;
  mesh_control_receipt_v1_t receipt;
  turbo_tls_server_config_t tls;
  mesh_control_resource_status_v1_t status;
  test_http_request_t request;
  const uint8_t *body;
  uint8_t frame[MESH_MGMT_FRAME_MAX];
  uint8_t operation_id[MESH_CONTROL_ID_SIZE] = {0};
  uint8_t resource_id[MESH_CONTROL_DIGEST_SIZE] = {0};
  char receipt_path[96];
  size_t body_size = 0u;
  size_t frame_size;
  size_t processed = 0u;
  size_t attempts;
  char *wal_path = tt_make_temp_file("mesh-control-agent-compact-wal", ".bin");
  char *checkpoint_path = tt_make_temp_file("mesh-control-agent-compact-checkpoint", ".bin");

  check_not_null(wal_path);
  check_not_null(checkpoint_path);
  if (!wal_path || !checkpoint_path)
    goto cleanup;
  cleanup_wal_files(wal_path);
  cleanup_checkpoint_files(checkpoint_path);
  resource_id[0] = 0x51u;
  operation_id[0] = 50u;
  make_agent_config(&config, &tls);
  config.controller_tls_certificate_sha256 = TEST_CERTIFICATE_SHA256;
  config.port = pick_loopback_port();
  check_true(config.port != 0u);
  enable_durability(&config, wal_path);
  config.wal.byte_capacity =
      MESH_CONTROL_WAL_FILE_HEADER_SIZE_V1 + 3u * MESH_CONTROL_WAL_MAX_RECORD_SIZE_V1;
  config.checkpoint_path = checkpoint_path;
  config.checkpoint_interval_records = 1u;
  frame_size = make_signed_service_frame(50u, frame);

  check_int_eq(mesh_control_agent_start_v1(&agent, &config), MESH_CONTROL_OK);
  check_int_eq(mesh_control_iris_receive_frame_v1(&agent.iris, frame, frame_size), MESH_CONTROL_OK);
  for (attempts = 0u; attempts < 1000u; ++attempts) {
    check_int_eq(mesh_control_agent_poll_v1(&agent, &processed), MESH_CONTROL_OK);
    if (agent.last_checkpoint_index == 1u && !agent.checkpoint_persisting)
      break;
    turbo_sleep_ms(1u);
  }
  check_true(attempts < 1000u);
  check_uint_eq(agent.owner.committed_log_index, 1u);
  check_int_eq(mesh_control_wal_worker_get_stats_v1(&agent.wal_worker, &stats),
               MESH_CONTROL_WAL_WORKER_OK);
  check_uint_eq(stats.wal.base_index, 1u);
  check_uint_eq(stats.wal.tail_index, 1u);
  check_size_eq(stats.wal.record_count, 0u);
  (void)snprintf(receipt_path, sizeof(receipt_path),
                 MESH_CONTROL_AGENT_RECEIPTS_PATH_V1
                 "?operation_id=32000000000000000000000000000000");
  check_int_eq(run_http_get(&agent, receipt_path, &request), 0);
  check_not_null(strstr((const char *)request.response, "HTTP/1.1 200 OK"));
  check_not_null(
      strstr((const char *)request.response, "Content-Type: " MESH_CONTROL_RECEIPT_MIME_V1));
  body = http_response_body(&request, &body_size);
  check_not_null(body);
  check_int_eq(mesh_control_receipt_decode_v1(body, body_size, &receipt), MESH_CONTROL_OK);
  check_mem_eq(receipt.operation.operation_id, operation_id, sizeof(operation_id));
  check_uint_eq(receipt.durable_through_index, 1u);
  check_uint_eq(receipt.checkpoint_base_index, 1u);
  check_int_eq(mesh_control_agent_stop_v1(&agent), MESH_CONTROL_OK);

  make_agent_config(&config, &tls);
  config.controller_tls_certificate_sha256 = TEST_CERTIFICATE_SHA256;
  config.port = pick_loopback_port();
  check_true(config.port != 0u);
  enable_durability(&config, wal_path);
  config.wal.byte_capacity =
      MESH_CONTROL_WAL_FILE_HEADER_SIZE_V1 + 3u * MESH_CONTROL_WAL_MAX_RECORD_SIZE_V1;
  config.checkpoint_path = checkpoint_path;
  config.checkpoint_interval_records = 1u;
  check_int_eq(mesh_control_agent_start_v1(&agent, &config), MESH_CONTROL_OK);
  check_uint_eq(agent.owner.committed_log_index, 1u);
  check_uint_eq(agent.last_checkpoint_index, 1u);
  check_int_eq(mesh_control_state_get_resource_v1(mesh_control_agent_state_v1(&agent),
                                                  MESH_CONTROL_RESOURCE_SERVICE, resource_id,
                                                  &status),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_agent_stop_v1(&agent), MESH_CONTROL_OK);

cleanup:
  if (wal_path) {
    cleanup_wal_files(wal_path);
    free(wal_path);
  }
  if (checkpoint_path) {
    cleanup_checkpoint_files(checkpoint_path);
    free(checkpoint_path);
  }
}

static void test_agent_persists_provider_result_before_ack(void) {
  mesh_control_agent_v1_t agent = {0};
  mesh_control_agent_config_v1_t config;
  turbo_tls_server_config_t tls;
  mesh_control_provider_v1_t descriptor;
  test_native_provider_t provider = {0};
  mesh_control_resource_status_v1_t status;
  uint8_t frame[MESH_MGMT_FRAME_MAX];
  uint8_t function_id[MESH_CONTROL_DIGEST_SIZE] = {0};
  size_t frame_size;
  size_t processed = 0u;
  size_t attempts;
  char *path = tt_make_temp_file("mesh-control-agent-result", ".bin");

  check_not_null(path);
  if (!path)
    return;
  cleanup_wal_files(path);
  function_id[0] = 0x31u;
  make_agent_config(&config, &tls);
  config.controller_permissions |= MESH_CONTROL_PERMISSION_RUN_NATIVE;
  config.node_policy.local_permissions |= MESH_CONTROL_PERMISSION_RUN_NATIVE;
  config.node_policy.available_runtimes |= MESH_CONTROL_RUNTIME_AVAILABLE_NATIVE;
  configure_test_native_provider(&config, &descriptor, &provider);
  enable_durability(&config, path);
  frame_size = make_signed_function_frame(MESH_CONTROL_FUNCTION_NATIVE, 40u, frame);

  check_int_eq(mesh_control_agent_start_v1(&agent, &config), MESH_CONTROL_OK);
  check_int_eq(mesh_control_iris_receive_frame_v1(&agent.iris, frame, frame_size), MESH_CONTROL_OK);
  for (attempts = 0u; attempts < 1000u && !provider.active; ++attempts) {
    check_int_eq(mesh_control_agent_poll_v1(&agent, &processed), MESH_CONTROL_OK);
    turbo_sleep_ms(1u);
  }
  check_true(provider.active);
  check_uint_eq(agent.owner.committed_log_index, 1u);

  provider.completion_ready = 1u;
  memset(&status, 0, sizeof(status));
  for (attempts = 0u; attempts < 1000u; ++attempts) {
    check_int_eq(mesh_control_agent_poll_v1(&agent, &processed), MESH_CONTROL_OK);
    if (mesh_control_state_get_resource_v1(mesh_control_agent_state_v1(&agent),
                                           MESH_CONTROL_RESOURCE_FUNCTION, function_id,
                                           &status) == MESH_CONTROL_OK &&
        status.observed_presence == MESH_CONTROL_PRESENCE_PRESENT && !provider.active) {
      break;
    }
    turbo_sleep_ms(1u);
  }
  check_int_eq(status.observed_presence, MESH_CONTROL_PRESENCE_PRESENT);
  check_false(provider.active);
  check_false(provider.completion_ready);
  check_uint_eq(agent.owner.committed_log_index, 2u);
  check_int_eq(mesh_control_agent_stop_v1(&agent), MESH_CONTROL_OK);

  memset(&provider, 0, sizeof(provider));
  make_agent_config(&config, &tls);
  config.controller_permissions |= MESH_CONTROL_PERMISSION_RUN_NATIVE;
  config.node_policy.local_permissions |= MESH_CONTROL_PERMISSION_RUN_NATIVE;
  config.node_policy.available_runtimes |= MESH_CONTROL_RUNTIME_AVAILABLE_NATIVE;
  configure_test_native_provider(&config, &descriptor, &provider);
  enable_durability(&config, path);
  check_int_eq(mesh_control_agent_start_v1(&agent, &config), MESH_CONTROL_OK);
  check_int_eq(mesh_control_state_get_resource_v1(mesh_control_agent_state_v1(&agent),
                                                  MESH_CONTROL_RESOURCE_FUNCTION, function_id,
                                                  &status),
               MESH_CONTROL_OK);
  check_int_eq(status.observed_presence, MESH_CONTROL_PRESENCE_PRESENT);
  check_uint_eq(agent.owner.committed_log_index, 2u);
  check_false(provider.active);
  check_int_eq(mesh_control_agent_stop_v1(&agent), MESH_CONTROL_OK);
  cleanup_wal_files(path);
  free(path);
}

static void test_agent_drains_ready_provider_completion_during_stop(void) {
  mesh_control_agent_v1_t agent = {0};
  mesh_control_agent_config_v1_t config;
  turbo_tls_server_config_t tls;
  mesh_control_provider_v1_t descriptor;
  test_native_provider_t provider = {0};
  mesh_control_resource_status_v1_t status;
  uint8_t frame[MESH_MGMT_FRAME_MAX];
  uint8_t function_id[MESH_CONTROL_DIGEST_SIZE] = {0};
  size_t frame_size;
  size_t processed = 0u;
  size_t attempts;
  char *path = tt_make_temp_file("mesh-control-agent-stop-result", ".bin");

  check_not_null(path);
  if (!path)
    return;
  cleanup_wal_files(path);
  function_id[0] = 0x31u;
  make_agent_config(&config, &tls);
  config.controller_permissions |= MESH_CONTROL_PERMISSION_RUN_NATIVE;
  config.node_policy.local_permissions |= MESH_CONTROL_PERMISSION_RUN_NATIVE;
  config.node_policy.available_runtimes |= MESH_CONTROL_RUNTIME_AVAILABLE_NATIVE;
  configure_test_native_provider(&config, &descriptor, &provider);
  enable_durability(&config, path);
  frame_size = make_signed_function_frame(MESH_CONTROL_FUNCTION_NATIVE, 45u, frame);

  check_int_eq(mesh_control_agent_start_v1(&agent, &config), MESH_CONTROL_OK);
  check_int_eq(mesh_control_iris_receive_frame_v1(&agent.iris, frame, frame_size), MESH_CONTROL_OK);
  for (attempts = 0u; attempts < 1000u && !provider.active; ++attempts) {
    check_int_eq(mesh_control_agent_poll_v1(&agent, &processed), MESH_CONTROL_OK);
    turbo_sleep_ms(1u);
  }
  check_true(provider.active);
  provider.completion_ready = 1u;
  check_int_eq(mesh_control_agent_stop_v1(&agent), MESH_CONTROL_OK);
  check_false(provider.active);
  check_false(provider.completion_ready);

  memset(&provider, 0, sizeof(provider));
  make_agent_config(&config, &tls);
  config.controller_permissions |= MESH_CONTROL_PERMISSION_RUN_NATIVE;
  config.node_policy.local_permissions |= MESH_CONTROL_PERMISSION_RUN_NATIVE;
  config.node_policy.available_runtimes |= MESH_CONTROL_RUNTIME_AVAILABLE_NATIVE;
  configure_test_native_provider(&config, &descriptor, &provider);
  enable_durability(&config, path);
  check_int_eq(mesh_control_agent_start_v1(&agent, &config), MESH_CONTROL_OK);
  check_int_eq(mesh_control_state_get_resource_v1(mesh_control_agent_state_v1(&agent),
                                                  MESH_CONTROL_RESOURCE_FUNCTION, function_id,
                                                  &status),
               MESH_CONTROL_OK);
  check_int_eq(status.observed_presence, MESH_CONTROL_PRESENCE_PRESENT);
  check_uint_eq(agent.owner.committed_log_index, 2u);
  check_false(provider.active);
  check_int_eq(mesh_control_agent_stop_v1(&agent), MESH_CONTROL_OK);
  cleanup_wal_files(path);
  free(path);
}

static void test_agent_status_pages_detect_concurrent_state_change(void) {
  mesh_control_agent_v1_t agent = {0};
  mesh_control_agent_config_v1_t config;
  turbo_tls_server_config_t tls;
  mesh_control_envelope_v1_t first;
  mesh_control_envelope_v1_t second;
  mesh_control_operation_v1_t operation;
  mesh_control_status_page_view_v1_t page;
  mesh_control_event_page_view_v1_t event_page;
  uint8_t status[512];
  size_t status_size = 0u;
  uint64_t first_generation;

  make_agent_config(&config, &tls);
  config.status_page_resource_limit = 1u;
  config.status_page_operation_limit = 1u;
  check_int_eq(mesh_control_agent_start_v1(&agent, &config), MESH_CONTROL_OK);
  make_status_intent(&first, 10u, 1u);
  check_int_eq(mesh_control_state_submit_v1(&agent.owner.state, &first, MESH_CONTROL_DESIRED_APPLY,
                                            1500u, &operation),
               MESH_CONTROL_OK);
  check_int_eq(
      mesh_control_agent_status_page_v1(&agent, 0u, 0u, 0u, status, sizeof(status), &status_size),
      MESH_CONTROL_OK);
  check_int_eq(mesh_control_status_page_decode_v1(status, status_size, &page), MESH_CONTROL_OK);
  check_int_eq(page.resource_total, 1u);
  check_int_eq(page.operation_total, 1u);
  first_generation = page.generation;

  make_status_intent(&second, 20u, 2u);
  check_int_eq(mesh_control_state_submit_v1(&agent.owner.state, &second, MESH_CONTROL_DESIRED_APPLY,
                                            1500u, &operation),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_agent_status_page_v1(&agent, first_generation, 1u, 1u, status,
                                                 sizeof(status), &status_size),
               MESH_CONTROL_CONFLICT);
  check_int_eq(mesh_control_agent_event_page_v1(&agent, 0u, status, sizeof(status), &status_size),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_event_page_decode_v1(status, status_size, &event_page),
               MESH_CONTROL_OK);
  check_int_eq(event_page.event_count, 2u);
  check_int_eq(event_page.next_cursor, 2u);
  check_int_eq(mesh_control_agent_stop_v1(&agent), MESH_CONTROL_OK);
}

static void test_agent_serves_authenticated_status_and_events(void) {
  mesh_control_agent_v1_t agent = {0};
  mesh_control_agent_config_v1_t config;
  turbo_tls_server_config_t tls;
  mesh_control_envelope_v1_t intent;
  mesh_control_operation_v1_t operation;
  mesh_control_status_page_view_v1_t status_page;
  mesh_control_event_page_view_v1_t event_page;
  test_http_request_t request;
  const uint8_t *body;
  size_t body_size = 0u;

  make_agent_config(&config, &tls);
  config.controller_tls_certificate_sha256 = TEST_CERTIFICATE_SHA256;
  config.port = pick_loopback_port();
  check_true(config.port != 0u);
  check_int_eq(mesh_control_agent_start_v1(&agent, &config), MESH_CONTROL_OK);
  make_status_intent(&intent, 10u, 1u);
  check_int_eq(mesh_control_state_submit_v1(&agent.owner.state, &intent, MESH_CONTROL_DESIRED_APPLY,
                                            1500u, &operation),
               MESH_CONTROL_OK);

  check_int_eq(run_http_get(&agent, MESH_CONTROL_AGENT_STATUS_PATH_V1, &request), 0);
  check_not_null(strstr((const char *)request.response, "HTTP/1.1 200 OK"));
  check_not_null(
      strstr((const char *)request.response, "Content-Type: " MESH_CONTROL_STATUS_MIME_V1));
  body = http_response_body(&request, &body_size);
  check_not_null(body);
  check_int_eq(mesh_control_status_page_decode_v1(body, body_size, &status_page), MESH_CONTROL_OK);
  check_int_eq(status_page.resource_total, 1u);
  check_int_eq(status_page.operation_total, 1u);

  check_int_eq(run_http_get(&agent, MESH_CONTROL_AGENT_EVENTS_PATH_V1, &request), 0);
  check_not_null(
      strstr((const char *)request.response, "Content-Type: " MESH_CONTROL_EVENT_MIME_V1));
  body = http_response_body(&request, &body_size);
  check_not_null(body);
  check_int_eq(mesh_control_event_page_decode_v1(body, body_size, &event_page), MESH_CONTROL_OK);
  check_int_eq(event_page.event_count, 1u);
  check_int_eq(event_page.next_cursor, 1u);
  check_int_eq(mesh_control_agent_stop_v1(&agent), MESH_CONTROL_OK);
}

static void test_agent_serves_status_over_real_h2_mtls(void) {
  mesh_control_agent_v1_t agent = {0};
  mesh_control_agent_config_v1_t config;
  turbo_tls_server_config_t server_tls;
  turbo_tls_client_config_t client_tls;
  turbo_http_options_t options;
  turbo_http_stats_t stats;
  turbo_http_t *client = NULL;
  test_h2_request_t request = {0};
  char url[256];
  int url_size;
  size_t processed = 0u;
  uint64_t deadline;

  make_agent_config(&config, &server_tls);
  config.controller_tls_certificate_sha256 = TEST_CERTIFICATE_SHA256;
  config.port = pick_loopback_port();
  check_true(config.port != 0u);
  check_int_eq(mesh_control_agent_start_v1(&agent, &config), MESH_CONTROL_OK);

  check_int_eq(turbo_http_options_init(&options, sizeof(options)), TURBO_OK);
  options.transport = TURBO_HTTP_TRANSPORT_H2;
  options.h2_fallback_to_h1 = 0;
  options.timeout_ms = TEST_HTTP_TIMEOUT_MS;
  check_int_eq(turbo_http_create(agent.context, &options, &client), TURBO_OK);
  check_not_null(client);
  if (!client)
    goto cleanup;
  memset(&client_tls, 0, sizeof(client_tls));
  client_tls.ca_file = MESH_CONTROL_AGENT_TEST_CERT;
  client_tls.cert_file = MESH_CONTROL_AGENT_TEST_CERT;
  client_tls.key_file = MESH_CONTROL_AGENT_TEST_KEY;
  client_tls.verify_peer = 1;
  check_int_eq(turbo_http_set_tls_config(client, &client_tls), TURBO_OK);
  url_size = snprintf(url, sizeof(url), "https://localhost:%u%s", config.port,
                      MESH_CONTROL_AGENT_STATUS_PATH_V1);
  check_true(url_size > 0 && (size_t)url_size < sizeof(url));
  if (url_size <= 0 || (size_t)url_size >= sizeof(url))
    goto cleanup;
  request.client = client;
  request.url = url;
  check_int_eq(coro_context_spawn(agent.context, test_h2_client_task, &request), TURBO_OK);
  deadline = turbo_monotonic_ms() + TEST_RUN_TIMEOUT_MS;
  while (!request.done && turbo_monotonic_ms() < deadline)
    check_int_eq(mesh_control_agent_poll_v1(&agent, &processed), MESH_CONTROL_OK);

  check_true(request.done);
  check_not_null(request.response);
  if (request.response) {
    check_int_eq(request.response->error_code, HTTP_ERROR_NONE);
    check_int_eq(request.response->status_code, 200);
    check_true(request.response->body_len > 0u);
  }
  memset(&stats, 0, sizeof(stats));
  turbo_http_get_stats(client, &stats);
  check_uint_eq(stats.h2_attempts, 1u);
  check_uint_eq(stats.h1_attempts, 0u);
  check_uint_eq(stats.h2_fallbacks, 0u);
  check_uint_eq(stats.h2_sessions, 1u);

cleanup:
  http_response_free(request.response);
  if (client)
    turbo_http_destroy(client);
  if (agent.running)
    check_int_eq(mesh_control_agent_stop_v1(&agent), MESH_CONTROL_OK);
}

static void test_agent_denies_status_without_observe_permission(void) {
  mesh_control_agent_v1_t agent = {0};
  mesh_control_agent_config_v1_t config;
  turbo_tls_server_config_t tls;
  test_http_request_t request;

  make_agent_config(&config, &tls);
  config.controller_tls_certificate_sha256 = TEST_CERTIFICATE_SHA256;
  config.controller_permissions = MESH_CONTROL_PERMISSION_MANAGE;
  config.port = pick_loopback_port();
  check_true(config.port != 0u);
  check_int_eq(mesh_control_agent_start_v1(&agent, &config), MESH_CONTROL_OK);
  check_int_eq(run_http_get(&agent, MESH_CONTROL_AGENT_STATUS_PATH_V1, &request), 0);
  check_not_null(strstr((const char *)request.response, "HTTP/1.1 403 Forbidden"));
  check_int_eq(mesh_control_agent_stop_v1(&agent), MESH_CONTROL_OK);
}

static void test_agent_enforces_runtime_specific_function_permissions(void) {
  mesh_control_agent_v1_t agent = {0};
  mesh_control_agent_config_v1_t config;
  turbo_tls_server_config_t tls;
  mesh_control_resource_status_v1_t status;
  uint8_t frame[MESH_MGMT_FRAME_MAX];
  size_t frame_size;
  size_t processed = 0u;
  uint8_t function_id[MESH_CONTROL_DIGEST_SIZE] = {0};
  uint8_t signing_public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE];
  mesh_control_provider_v1_t provider_descriptor;
  test_native_provider_t provider = {0};

  function_id[0] = 0x31u;
  check_int_eq(mesh_mgmt_ed25519_public_from_private(TEST_SIGNING_PRIVATE_KEY, signing_public_key),
               MESH_MGMT_CRYPTO_OK);
  make_agent_config(&config, &tls);
  memcpy(config.owner.replay_binding.principal_key, signing_public_key,
         sizeof(config.owner.replay_binding.principal_key));
  check_int_eq(mesh_control_agent_start_v1(&agent, &config), MESH_CONTROL_OK);
  frame_size = make_signed_function_frame(MESH_CONTROL_FUNCTION_NATIVE, 10u, frame);
  check_int_eq(mesh_control_iris_receive_frame_v1(&agent.iris, frame, frame_size),
               MESH_CONTROL_CONFLICT);
  check_int_eq(mesh_control_agent_poll_v1(&agent, &processed), MESH_CONTROL_OK);
  check_int_eq(processed, 0u);
  check_int_eq(mesh_control_agent_stop_v1(&agent), MESH_CONTROL_OK);

  make_agent_config(&config, &tls);
  memcpy(config.owner.replay_binding.principal_key, signing_public_key,
         sizeof(config.owner.replay_binding.principal_key));
  config.controller_permissions |= MESH_CONTROL_PERMISSION_RUN_NATIVE;
  config.node_policy.local_permissions |= MESH_CONTROL_PERMISSION_RUN_NATIVE;
  config.node_policy.available_runtimes |= MESH_CONTROL_RUNTIME_AVAILABLE_NATIVE;
  check_int_eq(mesh_control_agent_start_v1(&agent, &config), MESH_CONTROL_OK);
  frame_size = make_signed_function_frame(MESH_CONTROL_FUNCTION_NATIVE, 15u, frame);
  check_int_eq(mesh_control_iris_receive_frame_v1(&agent.iris, frame, frame_size),
               MESH_CONTROL_CONFLICT);
  check_int_eq(mesh_control_agent_stop_v1(&agent), MESH_CONTROL_OK);

  make_agent_config(&config, &tls);
  memcpy(config.owner.replay_binding.principal_key, signing_public_key,
         sizeof(config.owner.replay_binding.principal_key));
  config.controller_permissions |=
      MESH_CONTROL_PERMISSION_RUN_NATIVE | MESH_CONTROL_PERMISSION_RUN_WASM;
  config.node_policy.local_permissions |= MESH_CONTROL_PERMISSION_RUN_NATIVE;
  config.node_policy.available_runtimes |= MESH_CONTROL_RUNTIME_AVAILABLE_NATIVE;
  configure_test_native_provider(&config, &provider_descriptor, &provider);
  check_int_eq(mesh_control_agent_start_v1(&agent, &config), MESH_CONTROL_OK);
  frame_size = make_signed_function_frame(MESH_CONTROL_FUNCTION_NATIVE, 20u, frame);
  check_int_eq(mesh_control_iris_receive_frame_v1(&agent.iris, frame, frame_size), MESH_CONTROL_OK);
  check_int_eq(mesh_control_agent_poll_v1(&agent, &processed), MESH_CONTROL_OK);
  check_int_eq(processed, 1u);
  check_int_eq(mesh_control_state_get_resource_v1(mesh_control_agent_state_v1(&agent),
                                                  MESH_CONTROL_RESOURCE_FUNCTION, function_id,
                                                  &status),
               MESH_CONTROL_OK);
  check_int_eq(status.desired_epoch, 1u);
  check_int_eq(status.observed_presence, MESH_CONTROL_PRESENCE_ABSENT);
  check_true(provider.active);
  provider.completion_ready = 1u;
  check_int_eq(mesh_control_agent_poll_v1(&agent, &processed), MESH_CONTROL_OK);
  check_int_eq(mesh_control_state_get_resource_v1(mesh_control_agent_state_v1(&agent),
                                                  MESH_CONTROL_RESOURCE_FUNCTION, function_id,
                                                  &status),
               MESH_CONTROL_OK);
  check_int_eq(status.observed_presence, MESH_CONTROL_PRESENCE_PRESENT);
  check_int_eq(status.observed_epoch, 1u);
  frame_size = make_signed_function_frame(MESH_CONTROL_FUNCTION_WASM, 30u, frame);
  check_int_eq(mesh_control_iris_receive_frame_v1(&agent.iris, frame, frame_size),
               MESH_CONTROL_CONFLICT);
  check_int_eq(mesh_control_agent_stop_v1(&agent), MESH_CONTROL_OK);
}

spec("standalone mesh control agent lifecycle") {
  describe("mTLS H1 H2 WebSocket endpoint") {
    it("requires mTLS plus h2 and http/1.1 ALPN") {
      test_agent_requires_mtls_and_both_alpn_protocols();
    }
    it("starts polls and drains cleanly") { test_agent_starts_polls_and_stops_cleanly(); }
    it("serves generation-consistent bounded status pages") {
      test_agent_status_pages_detect_concurrent_state_change();
    }
    it("serves authenticated status snapshots and events over TLS") {
      test_agent_serves_authenticated_status_and_events();
    }
    it("serves authenticated status over a real HTTP/2 mTLS client") {
      test_agent_serves_status_over_real_h2_mtls();
    }
    it("denies status collection without observe permission") {
      test_agent_denies_status_without_observe_permission();
    }
    it("enforces separate Native and WASM execution permissions") {
      test_agent_enforces_runtime_specific_function_permissions();
    }
    it("applies and deletes canonical Network resources") {
      test_agent_applies_and_deletes_network_resources();
    }
    it("persists cross-process Network completion before exact ACK") {
      test_agent_persists_flowmq_network_completion_before_ack();
    }
    it("persists Network results and restores runtime state after restart") {
      test_agent_persists_and_restores_network_runtime();
    }
    it("commits only after WAL durability and recovers after restart") {
      test_agent_commits_after_wal_and_recovers_on_restart();
    }
    it("restores a checkpoint before replaying its compacted WAL suffix") {
      test_agent_checkpoints_compacts_and_recovers_before_ingress();
    }
    it("persists provider results before ACK and skips completed work after restart") {
      test_agent_persists_provider_result_before_ack();
    }
    it("persists a ready provider completion while stopping") {
      test_agent_drains_ready_provider_completion_during_stop();
    }
  }
}
