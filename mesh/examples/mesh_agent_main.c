#include "mesh_control_agent_runtime.h"
#include "meshd_key_file.h"

#ifdef TURBO_P2P_ENABLE_FLOWMQ_IPC
#include "mesh_node_control_flowmq_network_provider.h"
#endif

#ifdef TURBO_P2P_ENABLE_NODE_EXECUTION
#include "mesh_control_execution_provider.h"
#include "meshd_execution_config.h"
#endif

#include "platform.h"
#include <turbo_parser.h>

#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#endif

enum {
  MESH_AGENT_DEFAULT_PORT = 9444,
  MESH_AGENT_DEFAULT_TIMEOUT_MS = 5000,
  MESH_AGENT_DEFAULT_CLAIM_MS = 100,
  MESH_AGENT_STATE_CAPACITY = 1024,
  MESH_AGENT_EVENT_CAPACITY = 4096,
  MESH_AGENT_CHANNEL_CAPACITY = 128,
  MESH_AGENT_CHANNEL_BYTES = 8 * 1024 * 1024,
  MESH_AGENT_WAL_RECORDS = 4096,
  MESH_AGENT_WAL_BYTES = 64 * 1024 * 1024,
  MESH_AGENT_NETWORK_CAPACITY = 64,
  MESH_AGENT_NETWORK_CHANNEL_CAPACITY = 8,
  MESH_AGENT_NETWORK_CHANNEL_BYTES = 1024 * 1024
};

typedef struct {
  char *host;
  int64_t port;
  char *controller_url;
  char *agent_ca;
  char *controller_ca;
  char *server_cert;
  char *server_key;
  char *client_cert;
  char *client_key;
  char *management_key_file;
  char *wal_key_file;
  char *wal_file;
  char *checkpoint_file;
  char *mesh_id;
  char *node_id;
  char *controller_node_id;
  char *controller_public_key;
  char *controller_certificate_sha256;
  int64_t controller_certificate_serial;
  int64_t principal_epoch;
  int64_t incarnation;
  char *session_id;
  int64_t certificate_policy_generation;
  int64_t controller_timeout_ms;
  int64_t claim_interval_ms;
#ifdef TURBO_P2P_ENABLE_FLOWMQ_IPC
  int64_t network_control_port;
  char *network_control_ca;
  char *network_control_cert;
  char *network_control_key;
  char *network_control_identity;
  char *network_control_peer_identity;
  char *network_control_peer_certificate_sha256;
  char *network_control_peer_certificate_sha256_next;
  char *network_control_provider_id;
  int64_t network_control_policy_generation;
#endif
#ifdef TURBO_P2P_ENABLE_NODE_EXECUTION
  char *execution_config;
  char *wasm_provider_id;
  char *native_provider_id;
#endif
} mesh_agent_options_v1_t;

typedef struct {
  mesh_control_agent_runtime_v1_t *runtime;
#ifdef TURBO_P2P_ENABLE_FLOWMQ_IPC
  mesh_node_control_flowmq_network_provider_v1_t network_provider;
  uint8_t network_provider_initialized;
#endif
#ifdef TURBO_P2P_ENABLE_NODE_EXECUTION
  meshd_execution_config_t execution_config;
  mesh_mgmt_execution_process_v1_t processes[2];
  mesh_control_execution_provider_v1_t execution_providers[2];
  mesh_control_provider_v1_t provider_descriptors[2];
  mesh_control_execution_deployment_v1_t
      deployment_bindings[2][MESHD_EXECUTION_MAX_DEPLOYMENTS];
  size_t provider_count;
#endif
  uint8_t started;
} mesh_agent_app_v1_t;

static volatile sig_atomic_t g_stop_requested = 0;
static volatile sig_atomic_t g_reload_requested = 0;

static uint64_t wall_now(void *context) {
  (void)context;
  return turbo_realtime_ms();
}

static int secure_random(void *context, uint8_t *output,
                         size_t output_size) {
  (void)context;
  return turbo_secure_random(output, output_size);
}

static int hex_value(char value) {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  if (value >= 'A' && value <= 'F') return value - 'A' + 10;
  return -1;
}

static int decode_hex_exact(const char *text, uint8_t *output,
                            size_t output_size) {
  size_t index;
  if (!text || !output || output_size > SIZE_MAX / 2u ||
      strlen(text) != output_size * 2u)
    return 0;
  for (index = 0u; index < output_size; ++index) {
    int high = hex_value(text[index * 2u]);
    int low = hex_value(text[index * 2u + 1u]);
    if (high < 0 || low < 0) {
      memset(output, 0, output_size);
      return 0;
    }
    output[index] = (uint8_t)((high << 4) | low);
  }
  return 1;
}

static int certificate_digest_valid(const char *value) {
  size_t index;
  static const char prefix[] = "sha256:";
  if (!value || strlen(value) != sizeof(prefix) - 1u + 64u ||
      strncmp(value, prefix, sizeof(prefix) - 1u) != 0)
    return 0;
  for (index = sizeof(prefix) - 1u; value[index] != '\0'; ++index)
    if (hex_value(value[index]) < 0) return 0;
  return 1;
}

static void require_last(turbo_cmd_parser_t *parser) {
  turbo_cmd_set_required(parser, turbo_cmd_last_index(parser));
}

static turbo_cmd_parser_t *build_parser(mesh_agent_options_v1_t *options) {
  turbo_cmd_parser_t *parser = turbo_cmd_create("mesh-agent", "1.0");
  if (!parser) return NULL;
  options->host = "127.0.0.1";
  options->port = MESH_AGENT_DEFAULT_PORT;
  options->controller_timeout_ms = MESH_AGENT_DEFAULT_TIMEOUT_MS;
  options->claim_interval_ms = MESH_AGENT_DEFAULT_CLAIM_MS;
  options->checkpoint_file = NULL;
#ifdef TURBO_P2P_ENABLE_FLOWMQ_IPC
  options->network_control_port = 0;
  options->network_control_policy_generation = 1;
#endif
  turbo_cmd_add_string(parser, &options->host, "host", NULL,
                       "Local mTLS status listener host");
  turbo_cmd_add_integer(parser, &options->port, "port", "p",
                        "Local mTLS status listener port");
#define REQUIRED_STRING(field, name, description)                         \
  do {                                                                     \
    turbo_cmd_add_string(parser, &(field), (name), NULL, (description));   \
    require_last(parser);                                                  \
  } while (0)
  REQUIRED_STRING(options->controller_url, "controller-url",
                  "Controller H2 /v1/agent/sync URL");
  REQUIRED_STRING(options->agent_ca, "agent-ca",
                  "CA for this agent's server/client leaves");
  REQUIRED_STRING(options->controller_ca, "controller-ca",
                  "CA for Controller server/client leaves");
  REQUIRED_STRING(options->server_cert, "server-cert",
                  "Agent local-listener certificate PEM");
  REQUIRED_STRING(options->server_key, "server-key",
                  "Agent local-listener private key PEM");
  REQUIRED_STRING(options->client_cert, "client-cert",
                  "Agent outbound client certificate PEM");
  REQUIRED_STRING(options->client_key, "client-key",
                  "Agent outbound client private key PEM");
  REQUIRED_STRING(options->management_key_file, "management-key-file",
                  "ACL-protected Ed25519 seed file");
  REQUIRED_STRING(options->wal_key_file, "wal-key-file",
                  "ACL-protected independent WAL HMAC key file");
  REQUIRED_STRING(options->wal_file, "wal-file", "Durable agent WAL path");
  turbo_cmd_add_string(parser, &options->checkpoint_file, "checkpoint-file",
                       NULL, "Optional durable checkpoint path");
  REQUIRED_STRING(options->mesh_id, "mesh-id", "32-byte mesh ID as hex");
  REQUIRED_STRING(options->node_id, "node-id", "32-byte node ID as hex");
  REQUIRED_STRING(options->controller_node_id, "controller-node-id",
                  "32-byte Controller node ID as hex");
  REQUIRED_STRING(options->controller_public_key, "controller-public-key",
                  "Controller Ed25519 public key as hex");
  REQUIRED_STRING(options->controller_certificate_sha256,
                  "controller-cert-sha256",
                  "Pinned Controller leaf as sha256:<hex>");
  REQUIRED_STRING(options->session_id, "session-id",
                  "Persistent 16-byte replay session ID as hex");
#undef REQUIRED_STRING
#define REQUIRED_INTEGER(field, name, description)                       \
  do {                                                                    \
    turbo_cmd_add_integer(parser, &(field), (name), NULL, (description)); \
    require_last(parser);                                                 \
  } while (0)
  REQUIRED_INTEGER(options->controller_certificate_serial,
                   "controller-cert-serial", "Pinned Controller leaf serial");
  REQUIRED_INTEGER(options->principal_epoch, "principal-epoch",
                   "Controller principal epoch");
  REQUIRED_INTEGER(options->incarnation, "incarnation",
                   "Persistent agent incarnation");
  REQUIRED_INTEGER(options->certificate_policy_generation,
                   "certificate-policy-generation",
                   "Local certificate policy generation");
#undef REQUIRED_INTEGER
  turbo_cmd_add_integer(parser, &options->controller_timeout_ms,
                        "controller-timeout-ms", NULL,
                        "Bounded Controller exchange timeout");
  turbo_cmd_add_integer(parser, &options->claim_interval_ms,
                        "claim-interval-ms", NULL,
                        "Controller durable claim interval");
#ifdef TURBO_P2P_ENABLE_FLOWMQ_IPC
  turbo_cmd_add_integer(parser, &options->network_control_port,
                        "network-control-port", NULL,
                        "Enable local meshd FlowMQ/mTLS bridge on this port");
  turbo_cmd_add_string(parser, &options->network_control_ca,
                       "network-control-ca", NULL,
                       "CA for the local meshd FlowMQ server");
  turbo_cmd_add_string(parser, &options->network_control_cert,
                       "network-control-cert", NULL,
                       "Dedicated local FlowMQ client certificate PEM");
  turbo_cmd_add_string(parser, &options->network_control_key,
                       "network-control-key", NULL,
                       "ACL-protected local FlowMQ client key PEM");
  turbo_cmd_add_string(parser, &options->network_control_identity,
                       "network-control-identity", NULL,
                       "Exact FlowMQ HELLO identity for this agent");
  turbo_cmd_add_string(parser, &options->network_control_peer_identity,
                       "network-control-peer-identity", NULL,
                       "Exact expected meshd FlowMQ HELLO identity");
  turbo_cmd_add_string(
      parser, &options->network_control_peer_certificate_sha256,
      "network-control-peer-cert-sha256", NULL,
      "Pinned current meshd FlowMQ leaf as sha256:<hex>");
  turbo_cmd_add_string(
      parser, &options->network_control_peer_certificate_sha256_next,
      "network-control-peer-cert-sha256-next", NULL,
      "Optional pinned next meshd FlowMQ leaf");
  turbo_cmd_add_string(parser, &options->network_control_provider_id,
                       "network-control-provider-id", NULL,
                       "Stable local meshd provider ID as 32-byte hex");
  turbo_cmd_add_integer(parser,
                        &options->network_control_policy_generation,
                        "network-control-policy-generation", NULL,
                        "Local FlowMQ certificate-map generation");
#endif
#ifdef TURBO_P2P_ENABLE_NODE_EXECUTION
  turbo_cmd_add_string(parser, &options->execution_config,
                       "execution-config", NULL,
                       "Strict prestaged Native/TurboWASM YAML profile");
  turbo_cmd_add_string(parser, &options->wasm_provider_id,
                       "wasm-provider-id", NULL,
                       "WASM provider ID as 32-byte hex");
  turbo_cmd_add_string(parser, &options->native_provider_id,
                       "native-provider-id", NULL,
                       "Native provider ID as 32-byte hex");
#endif
  return parser;
}

#ifdef TURBO_P2P_ENABLE_FLOWMQ_IPC
static void set_flowmq_timeouts(flowmq_coronet_timeout_config_t *timeouts,
                                uint64_t timeout_ms) {
  memset(timeouts, 0, sizeof(*timeouts));
  timeouts->timeout_ms = timeout_ms;
  timeouts->connect_timeout_ms = timeout_ms;
  timeouts->send_timeout_ms = timeout_ms;
  timeouts->recv_timeout_ms = timeout_ms;
  timeouts->handshake_timeout_ms = timeout_ms;
  timeouts->set_flags = FLOWMQ_TIMEOUT_SET_ALL;
  timeouts->explicit_flags = FLOWMQ_TIMEOUT_SET_ALL;
}

static int build_network_provider(
    mesh_agent_app_v1_t *app, const mesh_agent_options_v1_t *options,
    const uint8_t mesh_id[MESH_CONTROL_DIGEST_SIZE],
    const uint8_t sender_incarnation[MESH_CONTROL_ID_SIZE]) {
  static const char path[] = "/mesh-node-control";
  static const char topic[] = "mesh.node.control";
  flowmq_coronet_tls_client_config_t tls;
  flowmq_connect_endpoint_config_t endpoint;
  mesh_certificate_lifecycle_config_v1_t certificate_config;
  mesh_certificate_lifecycle_v1_t certificate;
  mesh_node_control_flowmq_network_provider_config_v1_t provider_config;
  int enabled;

  enabled = options->network_control_port != 0 ||
            options->network_control_ca || options->network_control_cert ||
            options->network_control_key ||
            options->network_control_identity ||
            options->network_control_peer_identity ||
            options->network_control_peer_certificate_sha256 ||
            options->network_control_peer_certificate_sha256_next ||
            options->network_control_provider_id;
  if (!enabled)
    return 1;
  if (options->network_control_port <= 0 ||
      options->network_control_port > UINT16_MAX ||
      options->network_control_policy_generation <= 0 ||
      !options->network_control_ca || !options->network_control_cert ||
      !options->network_control_key ||
      !options->network_control_identity ||
      !options->network_control_peer_identity ||
      !certificate_digest_valid(
          options->network_control_peer_certificate_sha256) ||
      (options->network_control_peer_certificate_sha256_next &&
       !certificate_digest_valid(
           options->network_control_peer_certificate_sha256_next)) ||
      !options->network_control_provider_id ||
      flowmq_coronet_tls_require_tls13() != TURBO_OK ||
      !flowmq_coronet_tls_is_tls13_only())
    return 0;

  memset(&certificate, 0, sizeof(certificate));
  memset(&certificate_config, 0, sizeof(certificate_config));
  certificate_config.ca_file = options->network_control_ca;
  certificate_config.role = MESH_CERTIFICATE_ROLE_CLIENT_V1;
  certificate_config.current.certificate_file =
      options->network_control_cert;
  certificate_config.current.private_key_file = options->network_control_key;
  certificate_config.policy_generation =
      (uint64_t)options->network_control_policy_generation;
  certificate_config.now_ms = turbo_realtime_ms();
  certificate_config.require_private_key_file_security = 1u;
  if (certificate_config.now_ms == 0u ||
      mesh_certificate_lifecycle_init_v1(&certificate,
                                         &certificate_config) !=
          MESH_CONTROL_OK)
    return 0;

  memset(&tls, 0, sizeof(tls));
  tls.ca_file = options->network_control_ca;
  tls.cert_file = options->network_control_cert;
  tls.key_file = options->network_control_key;
  tls.server_name = "localhost";
  tls.verify_peer = 1;
  flowmq_connect_endpoint_config_init(&endpoint);
  endpoint.transport = FLOWMQ_TRANSPORT_TLS;
  endpoint.pattern = FLOWMQ_PROTOCOL_DEALER;
  endpoint.host = "localhost";
  endpoint.path = path;
  endpoint.topic = topic;
  endpoint.identity = options->network_control_identity;
  endpoint.tls = &tls;
  endpoint.port = (int)options->network_control_port;
  endpoint.max_frame_size = MESH_NODE_IPC_FLOWMQ_MAX_FRAME_SIZE_V1;
  endpoint.reconnect_initial_ms = 100u;
  endpoint.reconnect_max_ms = 5000u;
  endpoint.heartbeat_interval_ms = 1000u;
  endpoint.heartbeat_timeout_ms = 5000u;
  set_flowmq_timeouts(&endpoint.timeouts,
                      (uint64_t)options->controller_timeout_ms);

  memset(&provider_config, 0, sizeof(provider_config));
  provider_config.runtime.connect_endpoint = &endpoint;
  provider_config.runtime.expected_peer_identity =
      options->network_control_peer_identity;
  provider_config.runtime.expected_peer_certificate_sha256 =
      options->network_control_peer_certificate_sha256;
  provider_config.runtime.expected_peer_certificate_sha256_next =
      options->network_control_peer_certificate_sha256_next;
  provider_config.runtime.identity_policy_generation =
      (uint64_t)options->network_control_policy_generation;
  memcpy(provider_config.runtime.mesh_id, mesh_id,
         sizeof(provider_config.runtime.mesh_id));
  memcpy(provider_config.runtime.sender_incarnation, sender_incarnation,
         sizeof(provider_config.runtime.sender_incarnation));
  if (!decode_hex_exact(options->network_control_provider_id,
                        provider_config.runtime.provider_id,
                        sizeof(provider_config.runtime.provider_id))) {
    mesh_certificate_lifecycle_destroy_v1(&certificate);
    return 0;
  }
  provider_config.runtime.operation_capacity =
      MESH_NODE_CONTROL_FLOWMQ_NETWORK_OPERATION_CAPACITY_V1;
  provider_config.runtime.channel_capacity =
      MESH_AGENT_NETWORK_CHANNEL_CAPACITY;
  provider_config.runtime.channel_max_retained_bytes =
      MESH_AGENT_NETWORK_CHANNEL_BYTES;
  provider_config.response_budget = MESH_AGENT_NETWORK_CHANNEL_CAPACITY;
  provider_config.send_budget = MESH_AGENT_NETWORK_CHANNEL_CAPACITY;
  if (mesh_node_control_flowmq_network_provider_init_v1(
          &app->network_provider, &provider_config) != MESH_CONTROL_OK ||
      mesh_node_control_flowmq_network_provider_start_v1(
          &app->network_provider) != MESH_CONTROL_OK) {
    mesh_node_control_flowmq_network_provider_destroy_v1(
        &app->network_provider);
    mesh_certificate_lifecycle_destroy_v1(&certificate);
    return 0;
  }
  app->network_provider_initialized = 1u;
  mesh_certificate_lifecycle_destroy_v1(&certificate);
  return 1;
}

static void destroy_network_provider(mesh_agent_app_v1_t *app) {
  if (!app || !app->network_provider_initialized)
    return;
  mesh_node_control_flowmq_network_provider_destroy_v1(
      &app->network_provider);
  app->network_provider_initialized = 0u;
}
#endif

#ifdef TURBO_P2P_ENABLE_NODE_EXECUTION
static int build_execution_provider(
    mesh_agent_app_v1_t *app, const mesh_agent_options_v1_t *options,
    uint16_t runtime, const char *provider_id,
    const uint8_t node_id[MESH_CONTROL_NODE_ID_SIZE],
    const uint8_t result_private_key[MESH_MGMT_EXECUTION_DIGEST_SIZE]) {
  mesh_control_execution_provider_config_v1_t config;
  char journal_path[TURBO_FS_MAX_PATH];
  mesh_mgmt_execution_deployment_runtime_v1_t deployment_runtime =
      runtime == MESH_CONTROL_FUNCTION_WASM
          ? MESH_MGMT_EXECUTION_DEPLOYMENT_WASM_V1
          : MESH_MGMT_EXECUTION_DEPLOYMENT_NATIVE_PROCESS_V1;
  size_t provider_index = app->provider_count;
  size_t binding_count = 0u;
  size_t index;
  int journal_path_length;
  mesh_control_result_t provider_result;
  int process_started = 0;
  if (!provider_id || provider_index >= 2u) return 0;
  for (index = 0u; index < app->execution_config.deployment_count; ++index) {
    mesh_control_execution_deployment_v1_t *binding;
    if (app->execution_config.deployments[index].runtime != deployment_runtime)
      continue;
    if (!app->execution_config.deployment_has_control_binding[index])
      return 0;
    binding = &app->deployment_bindings[provider_index][binding_count++];
    memset(binding, 0, sizeof(*binding));
    binding->deployment = app->execution_config.deployments[index];
    memcpy(binding->config_digest,
           app->execution_config.deployment_config_digests[index],
           sizeof(binding->config_digest));
    memcpy(binding->network_policy_digest,
           app->execution_config.deployment_network_policy_digests[index],
           sizeof(binding->network_policy_digest));
  }
  if (binding_count == 0u) return 1;
  if (meshd_execution_config_build_process(
          &app->execution_config, &app->processes[provider_index]) != 0)
    return 0;
  process_started = 1;
  memset(&config, 0, sizeof(config));
  if (!decode_hex_exact(provider_id, config.provider_id,
                        sizeof(config.provider_id)))
    goto failed;
  config.runtime = runtime;
  memcpy(config.local_node_id, node_id, sizeof(config.local_node_id));
  config.capabilities = app->execution_config.capabilities;
  config.hard_limits = app->execution_config.limits;
  config.deployments = app->deployment_bindings[provider_index];
  config.deployment_count = binding_count;
  config.process = &app->processes[provider_index];
  journal_path_length = snprintf(
      journal_path, sizeof(journal_path), "%s.%s-control",
      app->execution_config.store_file,
      runtime == MESH_CONTROL_FUNCTION_WASM ? "wasm" : "native");
  if (journal_path_length < 0 ||
      (size_t)journal_path_length >= sizeof(journal_path))
    goto failed;
  config.journal_path = journal_path;
  config.journal_capacity = MESH_AGENT_STATE_CAPACITY;
  memcpy(config.result_private_key, result_private_key,
         sizeof(config.result_private_key));
  config.worker_generation = (uint64_t)options->incarnation;
  config.now_ms = wall_now;
  provider_result = mesh_control_execution_provider_init_v1(
      &app->execution_providers[provider_index], &config,
      &app->provider_descriptors[provider_index]);
  mesh_mgmt_crypto_wipe(config.result_private_key,
                        sizeof(config.result_private_key));
  if (provider_result != MESH_CONTROL_OK)
    goto failed;
  app->provider_count++;
  return 1;

failed:
  if (process_started)
    mesh_mgmt_execution_process_destroy_v1(
        &app->processes[provider_index]);
  return 0;
}

static int build_execution(mesh_agent_app_v1_t *app,
                           const mesh_agent_options_v1_t *options,
                           const uint8_t node_id[MESH_CONTROL_NODE_ID_SIZE],
                           const uint8_t result_private_key[
                               MESH_MGMT_EXECUTION_DIGEST_SIZE]) {
  size_t index;
  int has_wasm = 0;
  int has_native = 0;
  if (!options->execution_config) return 1;
  if (meshd_execution_config_load(&app->execution_config,
                                  options->execution_config) != 0 ||
      app->execution_config.mode == MESHD_EXECUTION_MODE_DISABLED)
    return 0;
  for (index = 0u; index < app->execution_config.deployment_count; ++index) {
    if (app->execution_config.deployments[index].runtime ==
        MESH_MGMT_EXECUTION_DEPLOYMENT_WASM_V1)
      has_wasm = 1;
    else if (app->execution_config.deployments[index].runtime ==
             MESH_MGMT_EXECUTION_DEPLOYMENT_NATIVE_PROCESS_V1)
      has_native = 1;
  }
  if ((has_wasm && !options->wasm_provider_id) ||
      (has_native && !options->native_provider_id))
    return 0;
  return build_execution_provider(app, options, MESH_CONTROL_FUNCTION_WASM,
                                  options->wasm_provider_id, node_id,
                                  result_private_key) &&
         build_execution_provider(app, options, MESH_CONTROL_FUNCTION_NATIVE,
                                  options->native_provider_id, node_id,
                                  result_private_key);
}

static void destroy_execution(mesh_agent_app_v1_t *app) {
  size_t index;
  for (index = 0u; index < app->provider_count; ++index) {
    if (app->provider_descriptors[index].ops.close)
      app->provider_descriptors[index].ops.close(
          app->provider_descriptors[index].context);
    mesh_control_execution_provider_destroy_v1(
        &app->execution_providers[index]);
    mesh_mgmt_execution_process_destroy_v1(&app->processes[index]);
  }
  app->provider_count = 0u;
}
#endif

static int configure_and_start(mesh_agent_app_v1_t *app,
                               const mesh_agent_options_v1_t *options) {
  mesh_control_agent_runtime_config_v1_t config;
  mesh_control_agent_config_v1_t *agent = &config.local_agent;
  uint8_t management_key[MESHD_PRIVATE_KEY_SIZE];
  uint8_t wal_key[MESHD_PRIVATE_KEY_SIZE];
  uint8_t controller_public_key[MESH_CONTROL_DIGEST_SIZE];
  uint8_t node_id[MESH_CONTROL_NODE_ID_SIZE];
  uint8_t session_id[MESH_CONTROL_ID_SIZE];
  uint64_t now_ms = turbo_realtime_ms();
  int ok = 0;
  memset(&config, 0, sizeof(config));
  memset(management_key, 0, sizeof(management_key));
  memset(wal_key, 0, sizeof(wal_key));
  memset(controller_public_key, 0, sizeof(controller_public_key));
  memset(node_id, 0, sizeof(node_id));
  memset(session_id, 0, sizeof(session_id));
  if (now_ms == 0u || options->port <= 0 || options->port > UINT16_MAX ||
      options->controller_timeout_ms <= 0 ||
      options->claim_interval_ms <= 0 || options->principal_epoch <= 0 ||
      options->incarnation <= 0 ||
      options->certificate_policy_generation <= 0 ||
      options->controller_certificate_serial <= 0 ||
      !certificate_digest_valid(options->controller_certificate_sha256) ||
      !decode_hex_exact(options->mesh_id, agent->owner.mesh_id,
                        sizeof(agent->owner.mesh_id)) ||
      !decode_hex_exact(options->node_id, node_id, sizeof(node_id)) ||
      !decode_hex_exact(options->controller_node_id,
                        agent->controller_node_id,
                        sizeof(agent->controller_node_id)) ||
      !decode_hex_exact(options->controller_public_key,
                        controller_public_key,
                        sizeof(controller_public_key)) ||
      !decode_hex_exact(options->session_id, session_id,
                        sizeof(session_id)))
    goto cleanup;
  if (meshd_private_key_file_read(options->management_key_file,
                                  management_key) != MESHD_KEY_FILE_OK ||
      meshd_private_key_file_read(options->wal_key_file, wal_key) !=
          MESHD_KEY_FILE_OK)
    goto cleanup;

#ifdef TURBO_P2P_ENABLE_FLOWMQ_IPC
  if (!build_network_provider(app, options, agent->owner.mesh_id,
                              session_id))
    goto cleanup;
  if (app->network_provider_initialized) {
    agent->network_provider =
        mesh_node_control_flowmq_network_provider_descriptor_v1(
            &app->network_provider);
    agent->network_capacity = MESH_AGENT_NETWORK_CAPACITY;
  }
#endif

#ifdef TURBO_P2P_ENABLE_NODE_EXECUTION
  if (!build_execution(app, options, node_id, management_key)) goto cleanup;
  agent->function_reconciler.providers = app->provider_descriptors;
  agent->function_reconciler.provider_count = app->provider_count;
  agent->function_reconciler.inflight_capacity = app->provider_count;
#endif
  agent->host = options->host;
  agent->port = (uint16_t)options->port;
  agent->controller_tls_certificate_sha256 =
      options->controller_certificate_sha256;
  agent->controller_certificate_serial =
      (uint64_t)options->controller_certificate_serial;
  agent->controller_permissions = MESH_CONTROL_PERMISSION_OBSERVE |
                                  MESH_CONTROL_PERMISSION_MANAGE;
  memset(&agent->node_policy, 0, sizeof(agent->node_policy));
  agent->node_policy.local_permissions = MESH_CONTROL_PERMISSION_OBSERVE |
                                         MESH_CONTROL_PERMISSION_MANAGE;
#ifdef TURBO_P2P_ENABLE_NODE_EXECUTION
  {
    size_t index;
    for (index = 0u; index < app->provider_count; ++index) {
      if (app->provider_descriptors[index].runtime ==
          MESH_CONTROL_FUNCTION_WASM) {
        agent->node_policy.local_permissions |=
            MESH_CONTROL_PERMISSION_RUN_WASM;
        agent->node_policy.available_runtimes |=
            MESH_CONTROL_RUNTIME_AVAILABLE_WASM;
        agent->controller_permissions |= MESH_CONTROL_PERMISSION_RUN_WASM;
      } else {
        agent->node_policy.local_permissions |=
            MESH_CONTROL_PERMISSION_RUN_NATIVE;
        agent->node_policy.available_runtimes |=
            MESH_CONTROL_RUNTIME_AVAILABLE_NATIVE;
        agent->controller_permissions |= MESH_CONTROL_PERMISSION_RUN_NATIVE;
      }
    }
  }
#endif
  agent->owner.state.resource_capacity = MESH_AGENT_STATE_CAPACITY;
  agent->owner.state.operation_capacity = MESH_AGENT_STATE_CAPACITY;
  agent->owner.state.event_capacity = MESH_AGENT_EVENT_CAPACITY;
  agent->owner.state.terminal_retention_ms = 24u * 60u * 60u * 1000u;
  agent->owner.state.desired_document_max_bytes =
      MESH_CONTROL_MAX_FRAME_SIZE_V1;
  agent->owner.state.desired_document_retained_bytes =
      MESH_AGENT_CHANNEL_BYTES;
  agent->owner.replay.capacity = MESH_AGENT_STATE_CAPACITY;
  agent->owner.replay.ttl_ms = 10u * 60u * 1000u;
  memcpy(agent->owner.node_id, node_id, sizeof(agent->owner.node_id));
  memcpy(agent->owner.replay_binding.principal_key, controller_public_key,
         sizeof(agent->owner.replay_binding.principal_key));
  agent->owner.replay_binding.principal_epoch =
      (uint64_t)options->principal_epoch;
  agent->owner.replay_binding.incarnation =
      (uint64_t)options->incarnation;
  memcpy(agent->owner.replay_binding.session_id, session_id,
         sizeof(agent->owner.replay_binding.session_id));
  agent->channel_capacity = MESH_AGENT_CHANNEL_CAPACITY;
  agent->channel_retained_bytes = MESH_AGENT_CHANNEL_BYTES;
  agent->channel_max_payload = MESH_CONTROL_MAX_FRAME_SIZE_V1;
  agent->max_commands_per_poll = 16u;
  agent->max_provider_completions_per_poll = 16u;
  agent->max_provider_starts_per_poll = 16u;
  agent->status_page_resource_limit = 128u;
  agent->status_page_operation_limit = 128u;
  agent->status_event_limit = 256u;
  agent->shutdown_drain_timeout_ms = 30000u;
  agent->now_ms = wall_now;
  agent->durability_enabled = 1u;
  agent->wal.path = options->wal_file;
  agent->wal.record_capacity = MESH_AGENT_WAL_RECORDS;
  agent->wal.byte_capacity = MESH_AGENT_WAL_BYTES;
  memcpy(agent->wal.mesh_id, agent->owner.mesh_id,
         sizeof(agent->wal.mesh_id));
  memcpy(agent->wal.node_id, node_id, sizeof(agent->wal.node_id));
  memcpy(agent->wal.controller_principal, controller_public_key,
         sizeof(agent->wal.controller_principal));
  memcpy(agent->wal.controller_node_id, agent->controller_node_id,
         sizeof(agent->wal.controller_node_id));
  agent->wal.principal_epoch = (uint64_t)options->principal_epoch;
  agent->wal.incarnation = (uint64_t)options->incarnation;
  agent->wal.certificate_serial =
      (uint64_t)options->controller_certificate_serial;
  memcpy(agent->wal.session_id, session_id, sizeof(agent->wal.session_id));
  memcpy(agent->wal.authentication_key, wal_key,
         sizeof(agent->wal.authentication_key));
  if (options->checkpoint_file) {
    agent->checkpoint_path = options->checkpoint_file;
    agent->checkpoint_interval_records = 1024u;
  }

  config.server_certificate.ca_file = options->agent_ca;
  config.server_certificate.role = MESH_CERTIFICATE_ROLE_SERVER_V1;
  config.server_certificate.current.certificate_file = options->server_cert;
  config.server_certificate.current.private_key_file = options->server_key;
  config.server_certificate.policy_generation =
      (uint64_t)options->certificate_policy_generation;
  config.server_certificate.now_ms = now_ms;
  config.server_certificate.require_private_key_file_security = 1u;
  config.controller_client_ca_file = options->controller_ca;
  config.client_certificate.ca_file = options->agent_ca;
  config.client_certificate.role = MESH_CERTIFICATE_ROLE_CLIENT_V1;
  config.client_certificate.current.certificate_file = options->client_cert;
  config.client_certificate.current.private_key_file = options->client_key;
  config.client_certificate.policy_generation =
      (uint64_t)options->certificate_policy_generation;
  config.client_certificate.now_ms = now_ms;
  config.client_certificate.require_private_key_file_security = 1u;
  config.controller_tls.ca_file = options->controller_ca;
  config.controller_tls.verify_peer = 1;
  config.controller_sync_url = options->controller_url;
  config.controller_timeout_ms =
      (uint64_t)options->controller_timeout_ms;
  memcpy(config.identity.node_id, node_id, sizeof(config.identity.node_id));
  if (mesh_mgmt_ed25519_public_from_private(
          management_key, config.identity.management_public_key) !=
      MESH_MGMT_CRYPTO_OK)
    goto cleanup;
  config.identity.management_private_key = management_key;
  config.identity.hello_lifetime_ms = 30000u;
  config.identity.claim_interval_ms =
      (uint64_t)options->claim_interval_ms;
  config.identity.now_ms = wall_now;
  config.identity.random_bytes = secure_random;

  app->runtime = (mesh_control_agent_runtime_v1_t *)calloc(
      1u, sizeof(*app->runtime));
  if (!app->runtime ||
      mesh_control_agent_runtime_init_v1(app->runtime, &config) !=
          MESH_CONTROL_OK)
    goto cleanup;
#ifdef TURBO_P2P_ENABLE_NODE_EXECUTION
  {
    size_t index;
    for (index = 0u; index < app->provider_count; ++index) {
      size_t removed = 0u;
      if (mesh_control_execution_provider_reconcile_journal_v1(
              &app->execution_providers[index],
              mesh_control_owner_state_v1(&app->runtime->agent.owner),
              &removed) != MESH_CONTROL_OK)
        goto cleanup;
    }
  }
#endif
  app->started = 1u;
  ok = 1;

cleanup:
  mesh_mgmt_crypto_wipe(management_key, sizeof(management_key));
  mesh_mgmt_crypto_wipe(wal_key, sizeof(wal_key));
  mesh_mgmt_crypto_wipe(controller_public_key,
                        sizeof(controller_public_key));
  mesh_mgmt_crypto_wipe(session_id, sizeof(session_id));
  if (!ok) {
    if (app->runtime && app->runtime->initialized) {
      (void)mesh_control_agent_runtime_stop_v1(app->runtime);
      if (app->runtime->stopped)
        mesh_control_agent_runtime_destroy_v1(app->runtime);
    }
    free(app->runtime);
    app->runtime = NULL;
#ifdef TURBO_P2P_ENABLE_NODE_EXECUTION
    destroy_execution(app);
#endif
#ifdef TURBO_P2P_ENABLE_FLOWMQ_IPC
    destroy_network_provider(app);
#endif
  }
  return ok;
}

static int stop_app(mesh_agent_app_v1_t *app) {
  int ok = 1;
  if (app->runtime) {
    if (app->started && !app->runtime->stopped &&
        mesh_control_agent_runtime_stop_v1(app->runtime) != MESH_CONTROL_OK)
      ok = 0;
    if (app->runtime->stopped)
      mesh_control_agent_runtime_destroy_v1(app->runtime);
    free(app->runtime);
    app->runtime = NULL;
  }
#ifdef TURBO_P2P_ENABLE_NODE_EXECUTION
  destroy_execution(app);
#endif
#ifdef TURBO_P2P_ENABLE_FLOWMQ_IPC
  destroy_network_provider(app);
#endif
  app->started = 0u;
  return ok;
}

#ifdef _WIN32
static BOOL WINAPI console_handler(DWORD signal) {
  if (signal == CTRL_BREAK_EVENT) {
    g_reload_requested = 1;
    return TRUE;
  }
  if (signal == CTRL_C_EVENT || signal == CTRL_CLOSE_EVENT ||
      signal == CTRL_SHUTDOWN_EVENT) {
    g_stop_requested = 1;
    return TRUE;
  }
  return FALSE;
}
#else
static void signal_handler(int signal_number) {
  if (signal_number == SIGHUP)
    g_reload_requested = 1;
  else
    g_stop_requested = 1;
}
#endif

static void install_signals(void) {
#ifdef _WIN32
  (void)SetConsoleCtrlHandler(console_handler, TRUE);
#else
  (void)signal(SIGINT, signal_handler);
  (void)signal(SIGTERM, signal_handler);
  (void)signal(SIGHUP, signal_handler);
#endif
}

static int write_stdout(const char *data, size_t size, void *context) {
  (void)context;
  return size == 0u || fwrite(data, 1u, size, stdout) == size ? 0 : -1;
}

int main(int argc, char **argv) {
  mesh_agent_options_v1_t options;
  turbo_cmd_parser_t *parser;
  turbo_cmd_parse_result_t parse_result;
  int exit_code = 1;
  memset(&options, 0, sizeof(options));
  parser = build_parser(&options);
  if (!parser) {
    fprintf(stderr, "mesh-agent: command parser allocation failed\n");
    return 1;
  }
  memset(&parse_result, 0, sizeof(parse_result));
  parse_result.size = sizeof(parse_result);
  if (turbo_cmd_parse_ex(parser, argc, argv, &parse_result) != 0) {
    fprintf(stderr, "mesh-agent: command parser failed\n");
    goto cleanup;
  }
  if (parse_result.status == TURBO_CMD_PARSE_HELP) {
    if (turbo_cmd_render_help(parser, parse_result.leaf, write_stdout, NULL) !=
        0)
      fprintf(stderr, "mesh-agent: cannot render command help\n");
    else
      exit_code = 0;
    goto cleanup;
  }
  if (parse_result.status == TURBO_CMD_PARSE_VERSION) {
    fprintf(stdout, "%s\n", parse_result.message ? parse_result.message
                                                  : "mesh-agent 1.0");
    exit_code = 0;
    goto cleanup;
  }
  if (parse_result.status != TURBO_CMD_PARSE_OK) {
    fprintf(stderr, "mesh-agent: %s%s%s\n",
            parse_result.error_code ? parse_result.error_code
                                    : "invalid-argument",
            parse_result.message ? ": " : "",
            parse_result.message ? parse_result.message : "");
    goto cleanup;
  }
  install_signals();
  while (!g_stop_requested) {
    mesh_agent_app_v1_t app;
    memset(&app, 0, sizeof(app));
    g_reload_requested = 0;
    if (!configure_and_start(&app, &options)) {
      fprintf(stderr, "mesh-agent: fail-closed startup validation failed\n");
      (void)stop_app(&app);
      goto cleanup;
    }
    fprintf(stdout, "mesh-agent: started on %s:%lld\n", options.host,
            (long long)options.port);
    fflush(stdout);
    while (!g_stop_requested && !g_reload_requested) {
      size_t progress = 0u;
      mesh_control_result_t result =
          mesh_control_agent_runtime_poll_v1(app.runtime, &progress);
      if (result != MESH_CONTROL_OK &&
          result != MESH_CONTROL_PROVIDER_UNAVAILABLE &&
          result != MESH_CONTROL_STALE_EPOCH) {
        fprintf(stderr, "mesh-agent: runtime fault (%d)\n", (int)result);
        g_stop_requested = 1;
        break;
      }
      if (progress == 0u) turbo_sleep_ms(1u);
    }
    if (!stop_app(&app)) {
      fprintf(stderr, "mesh-agent: shutdown drain failed\n");
      goto cleanup;
    }
    if (g_reload_requested && !g_stop_requested) {
      fprintf(stdout, "mesh-agent: reloading certificates and policy\n");
      fflush(stdout);
    }
  }
  exit_code = 0;

cleanup:
  turbo_cmd_destroy(parser);
  return exit_code;
}
