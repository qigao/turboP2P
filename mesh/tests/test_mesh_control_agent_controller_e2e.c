#include "mesh_control_agent_runtime.h"
#include "mesh_control_controller_runtime.h"
#include "mesh_control_document.h"
#include "mesh_control_mmp.h"
#include "platform.h"
#include "tinytest.h"
#include "turbo_thread.h"
#include <turbo_http.h>

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_NOW_MS UINT64_C(1786690000000)

static const uint8_t AGENT_PRIVATE_KEY[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60};

static const uint8_t CONTROLLER_PRIVATE_KEY[32] = {
    0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda,
    0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
    0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24,
    0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb};

typedef struct {
  char ca[TURBO_FS_MAX_PATH];
  char server_cert[TURBO_FS_MAX_PATH];
  char server_key[TURBO_FS_MAX_PATH];
  char client_cert[TURBO_FS_MAX_PATH];
  char client_key[TURBO_FS_MAX_PATH];
  char client_next_cert[TURBO_FS_MAX_PATH];
  char client_next_key[TURBO_FS_MAX_PATH];
} e2e_paths_v1_t;

typedef struct {
  uint8_t operation_id[MESH_CONTROL_ID_SIZE];
  uint64_t starts;
  uint8_t completion_ready;
  uint8_t closed;
} e2e_provider_v1_t;

typedef struct {
  mesh_control_controller_runtime_v1_t *runtime;
  const mesh_control_controller_runtime_identity_config_v1_t *rotation;
  atomic_bool stop;
  atomic_bool rotate_requested;
  atomic_bool rotate_done;
  atomic_bool acked;
  atomic_bool failed;
} controller_thread_v1_t;

static void digest_string(
    const uint8_t digest[MESH_CONTROL_DIGEST_SIZE],
    char output[sizeof("sha256:") - 1u + MESH_CONTROL_DIGEST_SIZE * 2u + 1u]) {
  static const char HEX[] = "0123456789abcdef";
  size_t index;
  memcpy(output, "sha256:", sizeof("sha256:") - 1u);
  for (index = 0u; index < MESH_CONTROL_DIGEST_SIZE; ++index) {
    output[sizeof("sha256:") - 1u + index * 2u] = HEX[digest[index] >> 4u];
    output[sizeof("sha256:") - 1u + index * 2u + 1u] =
        HEX[digest[index] & 0x0fu];
  }
  output[sizeof("sha256:") - 1u + MESH_CONTROL_DIGEST_SIZE * 2u] = '\0';
}

static int submit_command(const char *url, const e2e_paths_v1_t *paths,
                          const uint8_t *command, size_t command_size) {
  const char *headers[] = {
      "Content-Type: " MESH_CONTROL_CONTROLLER_SUBMIT_MEDIA_TYPE_V1,
      "Accept: text/plain"};
  turbo_http_options_t options;
  turbo_tls_client_config_t tls;
  turbo_http_t *client = NULL;
  http_response_t *response = NULL;
  int ok = 0;
  if (turbo_http_options_init(&options, sizeof(options)) != TURBO_OK)
    return 0;
  options.transport = TURBO_HTTP_TRANSPORT_H2;
  options.h2_fallback_to_h1 = 0;
  options.follow_redirects = 0;
  options.retry.max_retries = 0;
  options.timeout_ms = 5000;
  if (turbo_http_create_sync(&options, &client) != TURBO_OK || !client)
    return 0;
  memset(&tls, 0, sizeof(tls));
  tls.ca_file = paths->ca;
  tls.cert_file = paths->client_cert;
  tls.key_file = paths->client_key;
  tls.verify_peer = 1;
  if (turbo_http_set_tls_config(client, &tls) != TURBO_OK) goto cleanup;
  response = turbo_http_request_sync(client, HTTP_POST, url, headers, 2u,
                                     (const char *)command, command_size);
  ok = response && response->error_code == HTTP_ERROR_NONE &&
       response->status_code == 202;
cleanup:
  if (response) http_response_free(response);
  turbo_http_destroy(client);
  return ok;
}

static uint64_t test_now(void *context) {
  (void)context;
  return TEST_NOW_MS;
}

static int test_random(void *context, uint8_t *output, size_t output_size) {
  static atomic_uint_fast32_t sequence = 1u;
  uint32_t value = (uint32_t)atomic_fetch_add_explicit(
      &sequence, 1u, memory_order_relaxed);
  size_t index;
  (void)context;
  for (index = 0u; index < output_size; ++index)
    output[index] = (uint8_t)(0x30u + value + index);
  return 0;
}

static void cert_path(char output[TURBO_FS_MAX_PATH], const char *name) {
  (void)snprintf(output, TURBO_FS_MAX_PATH, "%s/%s",
                 MESH_TEST_CERTIFICATE_DIR, name);
}

static void make_paths(e2e_paths_v1_t *paths) {
  cert_path(paths->ca, "ca.pem");
  cert_path(paths->server_cert, "server-current-cert.pem");
  cert_path(paths->server_key, "server-current-key.pem");
  cert_path(paths->client_cert, "client-current-cert.pem");
  cert_path(paths->client_key, "client-current-key.pem");
  cert_path(paths->client_next_cert, "client-next-cert.pem");
  cert_path(paths->client_next_key, "client-next-key.pem");
}

static void remove_store(const char *path) {
  char lock_path[TURBO_FS_MAX_PATH + 6u];
  char temp_path[TURBO_FS_MAX_PATH + 5u];
  (void)snprintf(lock_path, sizeof(lock_path), "%s.lock", path);
  (void)snprintf(temp_path, sizeof(temp_path), "%s.tmp", path);
  (void)remove(path);
  (void)remove(lock_path);
  (void)remove(temp_path);
}

static uint16_t bound_port(const coro_socket_t *listener) {
  struct sockaddr_storage address;
  if (!listener || coro_socket_get_local_address((coro_socket_t *)listener,
                                                  &address) != 0)
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
  WSADATA data;
  if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return 0u;
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
  if (socket_handle == INVALID_SOCKET) return 0u;
#else
  if (socket_handle < 0) return 0u;
#endif
  if (bind(socket_handle, (struct sockaddr *)&address, sizeof(address)) == 0 &&
      getsockname(socket_handle, (struct sockaddr *)&address,
                  &address_size) == 0)
    port = ntohs(address.sin_port);
#ifdef _WIN32
  closesocket(socket_handle);
#else
  close(socket_handle);
#endif
  return port;
}

static mesh_control_result_t provider_start(
    void *context, const mesh_control_provider_request_v1_t *request) {
  e2e_provider_v1_t *provider = (e2e_provider_v1_t *)context;
  if (!provider || !request || provider->closed || provider->completion_ready)
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  memcpy(provider->operation_id, request->operation.operation_id,
         sizeof(provider->operation_id));
  provider->starts++;
  provider->completion_ready = 1u;
  return MESH_CONTROL_OK;
}

static mesh_control_result_t provider_peek(
    void *context, mesh_control_provider_completion_v1_t *out_completion) {
  e2e_provider_v1_t *provider = (e2e_provider_v1_t *)context;
  if (!provider || !out_completion) return MESH_CONTROL_INVALID_ARG;
  if (!provider->completion_ready) return MESH_CONTROL_EMPTY;
  memset(out_completion, 0, sizeof(*out_completion));
  memcpy(out_completion->operation_id, provider->operation_id,
         sizeof(out_completion->operation_id));
  out_completion->state = MESH_CONTROL_PROVIDER_COMPLETED;
  return MESH_CONTROL_OK;
}

static mesh_control_result_t provider_ack(
    void *context, const uint8_t operation_id[MESH_CONTROL_ID_SIZE]) {
  e2e_provider_v1_t *provider = (e2e_provider_v1_t *)context;
  if (!provider || !provider->completion_ready ||
      memcmp(provider->operation_id, operation_id,
             sizeof(provider->operation_id)) != 0)
    return MESH_CONTROL_CONFLICT;
  memset(provider->operation_id, 0, sizeof(provider->operation_id));
  provider->completion_ready = 0u;
  return MESH_CONTROL_OK;
}

static void provider_close(void *context) {
  e2e_provider_v1_t *provider = (e2e_provider_v1_t *)context;
  if (provider) provider->closed = 1u;
}

static int provider_drained(void *context) {
  const e2e_provider_v1_t *provider =
      (const e2e_provider_v1_t *)context;
  return provider && provider->closed && !provider->completion_ready;
}

static void configure_controller(
    mesh_control_controller_runtime_config_v1_t *config,
    mesh_control_controller_runtime_identity_config_v1_t *identity,
    const e2e_paths_v1_t *paths, const char *outbox_path,
    const uint8_t node_id[MESH_CONTROL_NODE_ID_SIZE]) {
  size_t index;
  memset(config, 0, sizeof(*config));
  memset(identity, 0, sizeof(*identity));
  memcpy(identity->node_id, node_id, sizeof(identity->node_id));
  check_int_eq(mesh_mgmt_ed25519_public_from_private(
                   AGENT_PRIVATE_KEY, identity->management_public_key),
               MESH_MGMT_CRYPTO_OK);
  identity->certificate.ca_file = paths->ca;
  identity->certificate.role = MESH_CERTIFICATE_ROLE_CLIENT_V1;
  identity->certificate.current.certificate_file = paths->client_cert;
  identity->certificate.next.certificate_file = paths->client_next_cert;
  identity->certificate.certificate_only = 1u;
  identity->certificate.policy_generation = 1u;
  identity->certificate.now_ms = TEST_NOW_MS;
  identity->identity_policy_generation = 1u;

  config->host = "127.0.0.1";
  config->port = 0u;
  config->server_certificate.ca_file = paths->ca;
  config->server_certificate.role = MESH_CERTIFICATE_ROLE_SERVER_V1;
  config->server_certificate.current.certificate_file = paths->server_cert;
  config->server_certificate.current.private_key_file = paths->server_key;
  config->server_certificate.policy_generation = 1u;
  config->server_certificate.now_ms = TEST_NOW_MS;
  config->agent_client_ca_file = paths->ca;
  config->identities = identity;
  config->identity_count = 1u;
  config->identity_capacity = 2u;
  config->now_ms = test_now;
  config->session.outbox.path = outbox_path;
  config->session.outbox.entry_capacity = 8u;
  config->session.outbox.session_capacity = 4u;
  config->session.outbox.byte_capacity = 256u * 1024u;
  config->session.outbox.max_payload_size =
      MESH_CONTROL_AGENT_SYNC_MAX_PAYLOAD_V1;
  config->session.outbox.max_claim_lease_ms = 2000u;
  config->session.outbox.ack_retention_ms = 1000u;
  for (index = 0u;
       index < sizeof(config->session.outbox.authentication_key); ++index)
    config->session.outbox.authentication_key[index] =
        (uint8_t)(0x90u + index);
  config->session.session_capacity = 4u;
  config->session.claim_lease_ms = 1000u;
  config->session.maximum_clock_skew_ms = 100u;
  config->session.maximum_hello_lifetime_ms = 2000u;
  config->persistence_timeout_ms = 2000u;
  config->shutdown_drain_timeout_ms = 3000u;
}

static void configure_agent(
    mesh_control_agent_runtime_config_v1_t *config,
    mesh_control_provider_v1_t *descriptor, e2e_provider_v1_t *provider,
    const e2e_paths_v1_t *paths, const char *wal_path,
    const char *controller_url,
    const uint8_t mesh_id[MESH_CONTROL_DIGEST_SIZE],
    const uint8_t node_id[MESH_CONTROL_NODE_ID_SIZE],
    const uint8_t controller_node_id[MESH_CONTROL_NODE_ID_SIZE],
    const uint8_t controller_public_key[MESH_CONTROL_DIGEST_SIZE]) {
  mesh_control_agent_config_v1_t *agent;
  size_t index;
  memset(config, 0, sizeof(*config));
  config->server_certificate.ca_file = paths->ca;
  config->server_certificate.role = MESH_CERTIFICATE_ROLE_SERVER_V1;
  config->server_certificate.current.certificate_file = paths->server_cert;
  config->server_certificate.current.private_key_file = paths->server_key;
  config->server_certificate.policy_generation = 1u;
  config->server_certificate.now_ms = TEST_NOW_MS;
  config->client_certificate.ca_file = paths->ca;
  config->client_certificate.role = MESH_CERTIFICATE_ROLE_CLIENT_V1;
  config->client_certificate.current.certificate_file = paths->client_cert;
  config->client_certificate.current.private_key_file = paths->client_key;
  config->client_certificate.next.certificate_file = paths->client_next_cert;
  config->client_certificate.next.private_key_file = paths->client_next_key;
  config->client_certificate.policy_generation = 1u;
  config->client_certificate.now_ms = TEST_NOW_MS;
  config->controller_client_ca_file = paths->ca;
  config->controller_tls.ca_file = paths->ca;
  config->controller_tls.verify_peer = 1;
  config->controller_sync_url = controller_url;
  config->controller_timeout_ms = 2000u;

  agent = &config->local_agent;
  agent->host = "127.0.0.1";
  agent->port = 0u;
  agent->controller_tls_certificate_sha256 =
      "sha256:36f828b7dfeeeb70c1088ab417e6a473dbe7f8c479513894ef7a620f7c164eac";
  memcpy(agent->controller_node_id, controller_node_id,
         sizeof(agent->controller_node_id));
  agent->controller_certificate_serial = 3001u;
  agent->controller_permissions =
      MESH_CONTROL_PERMISSION_OBSERVE | MESH_CONTROL_PERMISSION_MANAGE |
      MESH_CONTROL_PERMISSION_RUN_BUILTIN;
  mesh_control_node_policy_default_v1(&agent->node_policy);
  memset(descriptor, 0, sizeof(*descriptor));
  memset(descriptor->provider_id, 0x71, sizeof(descriptor->provider_id));
  descriptor->runtime = MESH_CONTROL_FUNCTION_BUILTIN;
  descriptor->ops.try_start = provider_start;
  descriptor->ops.try_peek_completion = provider_peek;
  descriptor->ops.ack_completion = provider_ack;
  descriptor->ops.close = provider_close;
  descriptor->ops.is_drained = provider_drained;
  descriptor->context = provider;
  agent->function_reconciler.providers = descriptor;
  agent->function_reconciler.provider_count = 1u;
  agent->function_reconciler.inflight_capacity = 8u;
  agent->owner.state.resource_capacity = 8u;
  agent->owner.state.operation_capacity = 8u;
  agent->owner.state.event_capacity = 16u;
  agent->owner.state.terminal_retention_ms = 60000u;
  agent->owner.state.desired_document_max_bytes = 4096u;
  agent->owner.state.desired_document_retained_bytes = 32u * 1024u;
  agent->owner.replay.capacity = 16u;
  agent->owner.replay.ttl_ms = 60000u;
  memcpy(agent->owner.mesh_id, mesh_id, sizeof(agent->owner.mesh_id));
  memcpy(agent->owner.node_id, node_id, sizeof(agent->owner.node_id));
  memcpy(agent->owner.replay_binding.principal_key, controller_public_key,
         sizeof(agent->owner.replay_binding.principal_key));
  agent->owner.replay_binding.principal_epoch = 1u;
  agent->owner.replay_binding.incarnation = 1u;
  memset(agent->owner.replay_binding.session_id, 0x61,
         sizeof(agent->owner.replay_binding.session_id));
  agent->channel_capacity = 16u;
  agent->channel_retained_bytes = 256u * 1024u;
  agent->channel_max_payload = 64u * 1024u;
  agent->max_commands_per_poll = 8u;
  agent->max_provider_completions_per_poll = 8u;
  agent->max_provider_starts_per_poll = 8u;
  agent->status_page_resource_limit = 8u;
  agent->status_page_operation_limit = 8u;
  agent->status_event_limit = 16u;
  agent->shutdown_drain_timeout_ms = 3000u;
  agent->now_ms = test_now;
  agent->durability_enabled = 1u;
  agent->wal.path = wal_path;
  agent->wal.record_capacity = 32u;
  agent->wal.byte_capacity = 1024u * 1024u;
  memcpy(agent->wal.mesh_id, mesh_id, sizeof(agent->wal.mesh_id));
  memcpy(agent->wal.node_id, node_id, sizeof(agent->wal.node_id));
  memcpy(agent->wal.controller_principal, controller_public_key,
         sizeof(agent->wal.controller_principal));
  memcpy(agent->wal.controller_node_id, controller_node_id,
         sizeof(agent->wal.controller_node_id));
  agent->wal.principal_epoch = 1u;
  agent->wal.incarnation = 1u;
  agent->wal.certificate_serial = 3001u;
  memcpy(agent->wal.session_id, agent->owner.replay_binding.session_id,
         sizeof(agent->wal.session_id));
  for (index = 0u; index < sizeof(agent->wal.authentication_key); ++index)
    agent->wal.authentication_key[index] = (uint8_t)(0xb0u + index);

  memcpy(config->identity.node_id, node_id, sizeof(config->identity.node_id));
  check_int_eq(mesh_mgmt_ed25519_public_from_private(
                   AGENT_PRIVATE_KEY, config->identity.management_public_key),
               MESH_MGMT_CRYPTO_OK);
  config->identity.management_private_key = AGENT_PRIVATE_KEY;
  config->identity.hello_lifetime_ms = 1000u;
  config->identity.claim_interval_ms = 1u;
  config->identity.now_ms = test_now;
  config->identity.random_bytes = test_random;
}

static size_t make_signed_function_command(
    const uint8_t mesh_id[MESH_CONTROL_DIGEST_SIZE],
    const uint8_t target_node_id[MESH_CONTROL_NODE_ID_SIZE],
    const uint8_t controller_node_id[MESH_CONTROL_NODE_ID_SIZE],
    const uint8_t controller_public_key[MESH_CONTROL_DIGEST_SIZE],
    const uint8_t provider_id[MESH_CONTROL_DIGEST_SIZE],
    uint8_t message_id[MESH_CONTROL_ID_SIZE],
    uint8_t request_id[MESH_CONTROL_ID_SIZE],
    uint8_t output[MESH_CONTROL_MAX_FRAME_SIZE_V1]) {
  mesh_control_function_spec_v1_t spec;
  mesh_control_envelope_v1_t envelope;
  mesh_mgmt_sign_input_v1_t sign_input;
  uint8_t document[MESH_CONTROL_FUNCTION_DOCUMENT_SIZE_V1];
  uint8_t intent[MESH_CONTROL_FUNCTION_DOCUMENT_SIZE_V1 +
                 MESH_CONTROL_INTENT_HEADER_SIZE_V1];
  uint8_t payload[1024];
  size_t document_size = 0u;
  size_t intent_size = 0u;
  size_t payload_size = 0u;
  size_t output_size = 0u;
  memset(&spec, 0, sizeof(spec));
  spec.schema_version = MESH_CONTROL_SCHEMA_V1;
  spec.runtime = MESH_CONTROL_FUNCTION_BUILTIN;
  spec.desired_state = MESH_CONTROL_FUNCTION_RUNNING;
  memset(spec.function_id, 0x81, sizeof(spec.function_id));
  memcpy(spec.provider_id, provider_id, sizeof(spec.provider_id));
  memset(spec.artifact_digest, 0x82, sizeof(spec.artifact_digest));
  memset(spec.config_digest, 0x83, sizeof(spec.config_digest));
  memset(spec.network_policy_digest, 0x84,
         sizeof(spec.network_policy_digest));
  spec.generation = 1u;
  spec.limits.memory_bytes = 1024u * 1024u;
  spec.limits.cpu_time_ms = 1000u;
  spec.limits.input_bytes = 4096u;
  spec.limits.output_bytes = 4096u;
  spec.limits.concurrency = 1u;
  spec.limits.host_calls = 1u;
  check_int_eq(mesh_control_function_document_encode_v1(
                   &spec, document, sizeof(document), &document_size),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_intent_encode_v1(
                   MESH_CONTROL_DESIRED_APPLY, document, document_size,
                   intent, sizeof(intent), &intent_size),
               MESH_CONTROL_OK);
  memset(&envelope, 0, sizeof(envelope));
  envelope.schema_version = MESH_CONTROL_SCHEMA_V1;
  envelope.kind = MESH_CONTROL_MESSAGE_INTENT;
  envelope.resource_kind = MESH_CONTROL_RESOURCE_FUNCTION;
  envelope.epoch = 1u;
  envelope.sequence = 1u;
  envelope.issued_at_ms = TEST_NOW_MS - 10u;
  envelope.expires_at_ms = TEST_NOW_MS + 30000u;
  envelope.principal_epoch = 1u;
  envelope.incarnation = 1u;
  envelope.certificate_serial = 3001u;
  envelope.payload_size = intent_size;
  memset(message_id, 0x91, MESH_CONTROL_ID_SIZE);
  memset(request_id, 0x92, MESH_CONTROL_ID_SIZE);
  memcpy(envelope.message_id, message_id, sizeof(envelope.message_id));
  memcpy(envelope.request_id, request_id, sizeof(envelope.request_id));
  memcpy(envelope.mesh_id, mesh_id, sizeof(envelope.mesh_id));
  memcpy(envelope.origin_principal, controller_public_key,
         sizeof(envelope.origin_principal));
  memcpy(envelope.origin_node_id, controller_node_id,
         sizeof(envelope.origin_node_id));
  memcpy(envelope.target_node_id, target_node_id,
         sizeof(envelope.target_node_id));
  memset(envelope.session_id, 0x61, sizeof(envelope.session_id));
  memcpy(envelope.resource_id, spec.function_id,
         sizeof(envelope.resource_id));
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
  sign_input.private_key = CONTROLLER_PRIVATE_KEY;
  sign_input.payload = payload;
  sign_input.payload_len = payload_size;
  memcpy(sign_input.header.mesh_id_hash, mesh_id,
         sizeof(sign_input.header.mesh_id_hash));
  memcpy(sign_input.header.origin_node_id, controller_node_id,
         sizeof(sign_input.header.origin_node_id));
  memcpy(sign_input.header.target_node_id, target_node_id,
         sizeof(sign_input.header.target_node_id));
  sign_input.header.principal_epoch = 1u;
  sign_input.header.incarnation = 1u;
  memset(sign_input.header.session_id, 0x61,
         sizeof(sign_input.header.session_id));
  sign_input.header.origin_sequence = 1u;
  memcpy(sign_input.header.message_id, message_id,
         sizeof(sign_input.header.message_id));
  sign_input.header.issued_at_ms = envelope.issued_at_ms;
  sign_input.header.expires_at_ms = envelope.expires_at_ms;
  sign_input.header.certificate_serial = 3001u;
  check_int_eq(mesh_mgmt_envelope_sign_v1(
                   &sign_input, output, MESH_CONTROL_MAX_FRAME_SIZE_V1,
                   &output_size),
               MESH_MGMT_ENVELOPE_OK);
  return output_size;
}

static void controller_thread(void *argument) {
  controller_thread_v1_t *state = (controller_thread_v1_t *)argument;
  for (;;) {
    size_t progress = 0u;
    if (atomic_load_explicit(&state->stop, memory_order_acquire)) break;
    if (atomic_load_explicit(&state->rotate_requested,
                             memory_order_acquire) &&
        !atomic_load_explicit(&state->rotate_done, memory_order_relaxed)) {
      if (mesh_control_controller_runtime_rotate_identity_v1(
              state->runtime, state->rotation) != MESH_CONTROL_OK) {
        atomic_store_explicit(&state->failed, true, memory_order_release);
        break;
      }
      atomic_store_explicit(&state->rotate_done, true, memory_order_release);
    }
    if (mesh_control_controller_runtime_poll_v1(state->runtime, &progress) !=
        MESH_CONTROL_OK) {
      atomic_store_explicit(&state->failed, true, memory_order_release);
      break;
    }
    {
      mesh_control_controller_session_stats_v1_t stats;
      if (mesh_control_controller_session_get_stats_v1(
              &state->runtime->session, &stats) == MESH_CONTROL_OK &&
          stats.durable_receipts != 0u)
        atomic_store_explicit(&state->acked, true, memory_order_release);
    }
    if (progress == 0u) turbo_sleep_ms(1u);
  }
}

static int poll_agent_until(mesh_control_agent_runtime_v1_t *agent,
                            atomic_bool *condition, uint64_t timeout_ms) {
  uint64_t started = turbo_monotonic_ms();
  while (!atomic_load_explicit(condition, memory_order_acquire) &&
         turbo_monotonic_ms() - started < timeout_ms) {
    size_t progress = 0u;
    mesh_control_result_t result =
        mesh_control_agent_runtime_poll_v1(agent, &progress);
    if (result != MESH_CONTROL_OK &&
        result != MESH_CONTROL_PROVIDER_UNAVAILABLE &&
        result != MESH_CONTROL_INVALID_STATE)
      return 0;
    if (progress == 0u) turbo_sleep_ms(1u);
  }
  return atomic_load_explicit(condition, memory_order_acquire);
}

static void test_real_h2_rotation_fencing_and_durable_delivery(void) {
  mesh_control_controller_runtime_v1_t controller = {0};
  mesh_control_controller_runtime_config_v1_t controller_config;
  mesh_control_controller_runtime_identity_config_v1_t identity;
  mesh_control_controller_runtime_identity_config_v1_t rotation;
  mesh_control_agent_runtime_v1_t agent = {0};
  mesh_control_agent_runtime_config_v1_t agent_config;
  mesh_certificate_lifecycle_config_v1_t agent_rotation;
  mesh_control_provider_v1_t provider_descriptor;
  e2e_provider_v1_t provider = {0};
  mesh_certificate_lifecycle_v1_t submitter_certificate = {0};
  controller_thread_v1_t thread_state;
  turbo_thread_t thread = NULL;
  e2e_paths_v1_t paths;
  uint8_t command[MESH_CONTROL_MAX_FRAME_SIZE_V1];
  uint8_t message_id[MESH_CONTROL_ID_SIZE];
  uint8_t request_id[MESH_CONTROL_ID_SIZE];
  uint8_t mesh_id[MESH_CONTROL_DIGEST_SIZE];
  uint8_t node_id[MESH_CONTROL_NODE_ID_SIZE];
  uint8_t controller_node_id[MESH_CONTROL_NODE_ID_SIZE];
  uint8_t controller_public_key[MESH_CONTROL_DIGEST_SIZE];
  char controller_url[256];
  char submit_url[256];
  char submitter_certificate_sha256[
      sizeof("sha256:") - 1u + MESH_CONTROL_DIGEST_SIZE * 2u + 1u];
  char *outbox_path = tt_make_temp_file("mesh-control-e2e-outbox", ".bin");
  char *wal_path = tt_make_temp_file("mesh-control-e2e-agent", ".wal");
  size_t recovered_claims = 0u;
  size_t command_size;
  uint16_t port;
  uint64_t started;
  int initialized = 0;

  check_not_null(outbox_path);
  check_not_null(wal_path);
  if (!outbox_path || !wal_path) goto cleanup;
  remove_store(outbox_path);
  remove_store(wal_path);
  make_paths(&paths);
  memset(mesh_id, 0x31, sizeof(mesh_id));
  memset(node_id, 0x41, sizeof(node_id));
  memset(controller_node_id, 0x51, sizeof(controller_node_id));
  check_int_eq(mesh_mgmt_ed25519_public_from_private(
                   CONTROLLER_PRIVATE_KEY, controller_public_key),
               MESH_MGMT_CRYPTO_OK);
  port = pick_loopback_port();
  check_true(port != 0u);
  if (port == 0u) goto cleanup;
  configure_controller(&controller_config, &identity, &paths, outbox_path,
                       node_id);
  check_int_eq(mesh_certificate_lifecycle_init_v1(&submitter_certificate,
                                                   &identity.certificate),
               MESH_CONTROL_OK);
  if (!submitter_certificate.initialized) goto cleanup;
  digest_string(submitter_certificate.current.certificate_sha256,
                submitter_certificate_sha256);
  mesh_certificate_lifecycle_destroy_v1(&submitter_certificate);
  controller_config.submit_policy.submitter_tls_certificate_sha256 =
      submitter_certificate_sha256;
  memcpy(controller_config.submit_policy.mesh_id, mesh_id,
         sizeof(mesh_id));
  memcpy(controller_config.submit_policy.controller_node_id,
         controller_node_id, sizeof(controller_node_id));
  memcpy(controller_config.submit_policy.controller_management_public_key,
         controller_public_key, sizeof(controller_public_key));
  controller_config.submit_policy.principal_epoch = 1u;
  controller_config.submit_policy.incarnation = 1u;
  controller_config.submit_policy.certificate_serial = 3001u;
  controller_config.submit_policy.maximum_clock_skew_ms = 100u;
  controller_config.submit_policy.maximum_command_lifetime_ms = 60000u;
  controller_config.port = port;
  check_int_eq(mesh_control_controller_runtime_init_v1(
                   &controller, &controller_config, &recovered_claims),
               MESH_CONTROL_OK);
  initialized = controller.initialized;
  if (!initialized) goto cleanup;
  /* CoroNet listener address publication is backend-dependent; successful
   * explicit-port bind above is the authoritative startup result. */
  (void)snprintf(controller_url, sizeof(controller_url),
                 "https://localhost:%u%s", (unsigned int)port,
                 MESH_CONTROL_CONTROLLER_SYNC_PATH_V1);
  (void)snprintf(submit_url, sizeof(submit_url),
                 "https://localhost:%u%s", (unsigned int)port,
                 MESH_CONTROL_CONTROLLER_SUBMIT_PATH_V1);
  configure_agent(&agent_config, &provider_descriptor, &provider, &paths,
                  wal_path, controller_url, mesh_id, node_id,
                  controller_node_id, controller_public_key);
  check_int_eq(mesh_control_agent_runtime_init_v1(&agent, &agent_config),
               MESH_CONTROL_OK);
  if (!agent.initialized) goto cleanup;

  rotation = identity;
  rotation.certificate.current.certificate_file = paths.client_next_cert;
  rotation.certificate.next.certificate_file = NULL;
  rotation.certificate.policy_generation = 2u;
  rotation.identity_policy_generation = 2u;
  memset(&thread_state, 0, sizeof(thread_state));
  thread_state.runtime = &controller;
  thread_state.rotation = &rotation;
  atomic_init(&thread_state.stop, false);
  atomic_init(&thread_state.rotate_requested, false);
  atomic_init(&thread_state.rotate_done, false);
  atomic_init(&thread_state.acked, false);
  atomic_init(&thread_state.failed, false);
  check_int_eq(turbo_thread_create(&thread, controller_thread, &thread_state),
               0);
  if (!thread) goto cleanup;

  started = turbo_monotonic_ms();
  while (agent.service.counters.hellos == 0u &&
         turbo_monotonic_ms() - started < 5000u) {
    size_t progress = 0u;
    check_int_eq(mesh_control_agent_runtime_poll_v1(&agent, &progress),
                 MESH_CONTROL_OK);
    if (progress == 0u) turbo_sleep_ms(1u);
  }
  if (agent.service.counters.hellos == 0u) {
    mesh_control_controller_iris_stats_v1_t iris_stats;
    (void)mesh_control_controller_iris_get_stats_v1(&controller.iris,
                                                     &iris_stats);
    fprintf(stderr,
            "e2e hello failed: transport=%llu protocol=%llu http=%llu "
            "controller_received=%llu transport_reject=%llu protocol_reject=%llu\n",
            (unsigned long long)agent.service.counters.transport_failures,
            (unsigned long long)agent.service.counters.protocol_failures,
            (unsigned long long)agent.http_client.transport_failures,
            (unsigned long long)iris_stats.received,
            (unsigned long long)iris_stats.rejected_transport,
            (unsigned long long)iris_stats.rejected_protocol);
  }
  check_uint_eq(agent.service.counters.hellos, 1u);

  atomic_store_explicit(&thread_state.rotate_requested, true,
                        memory_order_release);
  check_true(poll_agent_until(&agent, &thread_state.rotate_done, 5000u));
  started = turbo_monotonic_ms();
  while (agent.service.counters.transport_failures == 0u &&
         turbo_monotonic_ms() - started < 5000u) {
    size_t progress = 0u;
    (void)mesh_control_agent_runtime_poll_v1(&agent, &progress);
    turbo_sleep_ms(1u);
  }
  check_true(agent.service.counters.transport_failures != 0u);

  agent_rotation = agent_config.client_certificate;
  agent_rotation.current.certificate_file = paths.client_next_cert;
  agent_rotation.current.private_key_file = paths.client_next_key;
  agent_rotation.next.certificate_file = NULL;
  agent_rotation.next.private_key_file = NULL;
  agent_rotation.policy_generation = 2u;
  check_int_eq(mesh_control_agent_runtime_rotate_client_v1(
                   &agent, &agent_rotation),
               MESH_CONTROL_OK);
  started = turbo_monotonic_ms();
  while (agent.service.counters.hellos < 2u &&
         turbo_monotonic_ms() - started < 5000u) {
    size_t progress = 0u;
    check_int_eq(mesh_control_agent_runtime_poll_v1(&agent, &progress),
                 MESH_CONTROL_OK);
    if (progress == 0u) turbo_sleep_ms(1u);
  }
  check_uint_eq(agent.service.counters.hellos, 2u);

  command_size = make_signed_function_command(
      mesh_id, node_id, controller_node_id, controller_public_key,
      provider_descriptor.provider_id, message_id, request_id, command);
  check_true(submit_command(submit_url, &paths, command, command_size));
  check_true(poll_agent_until(&agent, &thread_state.acked, 10000u));
  started = turbo_monotonic_ms();
  while (agent.service.counters.receipts == 0u &&
         turbo_monotonic_ms() - started < 2000u) {
    size_t progress = 0u;
    check_int_eq(mesh_control_agent_runtime_poll_v1(&agent, &progress),
                 MESH_CONTROL_OK);
    if (progress == 0u) turbo_sleep_ms(1u);
  }
  {
    mesh_control_controller_iris_stats_v1_t stats;
    check_int_eq(mesh_control_controller_iris_get_stats_v1(
                     &controller.iris, &stats),
                 MESH_CONTROL_OK);
    check_uint_eq(stats.submitted, 1u);
  }
  check_false(atomic_load_explicit(&thread_state.failed,
                                   memory_order_acquire));
  check_uint_eq(provider.starts, 1u);
  check_uint_eq(agent.service.counters.commands, 1u);
  check_uint_eq(agent.service.counters.receipts, 1u);

cleanup:
  mesh_certificate_lifecycle_destroy_v1(&submitter_certificate);
  if (agent.initialized && !agent.stopped)
    check_int_eq(mesh_control_agent_runtime_stop_v1(&agent), MESH_CONTROL_OK);
  if (agent.initialized) mesh_control_agent_runtime_destroy_v1(&agent);
  if (thread) {
    atomic_store_explicit(&thread_state.stop, true, memory_order_release);
    check_int_eq(turbo_thread_join(&thread), 0);
  }
  if (initialized && !controller.stopped)
    check_int_eq(mesh_control_controller_runtime_stop_v1(&controller),
                 MESH_CONTROL_OK);
  if (initialized)
    mesh_control_controller_runtime_destroy_v1(&controller);
  if (outbox_path) {
    remove_store(outbox_path);
    free(outbox_path);
  }
  if (wal_path) {
    remove_store(wal_path);
    free(wal_path);
  }
}

spec("real Controller to mesh-agent delivery") {
  describe("H2 mTLS, online fencing and durable execution receipt") {
    it("fences the old leaf, reconnects next leaf and ACKs after WAL") {
      test_real_h2_rotation_fencing_and_durable_delivery();
    }
  }
}
