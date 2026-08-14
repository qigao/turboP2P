#include "mesh_control_controller_runtime.h"
#include "meshd_key_file.h"

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
  MESH_CONTROLLER_DEFAULT_PORT = 9443,
  MESH_CONTROLLER_MAX_IDENTITIES = 256,
  MESH_CONTROLLER_IDENTITY_SPEC_MAX = 4096,
  MESH_CONTROLLER_OUTBOX_ENTRIES = 4096,
  MESH_CONTROLLER_OUTBOX_SESSIONS = 1024,
  MESH_CONTROLLER_OUTBOX_BYTES = 64 * 1024 * 1024,
  MESH_CONTROLLER_PERSISTENCE_TIMEOUT_MS = 5000,
  MESH_CONTROLLER_SHUTDOWN_TIMEOUT_MS = 30000,
  MESH_CONTROLLER_CLAIM_LEASE_MS = 30000,
  MESH_CONTROLLER_MAX_CLAIM_LEASE_MS = 60000,
  MESH_CONTROLLER_ACK_RETENTION_MS = 24 * 60 * 60 * 1000,
  MESH_CONTROLLER_MAX_CLOCK_SKEW_MS = 30000,
  MESH_CONTROLLER_MAX_COMMAND_LIFETIME_MS = 5 * 60 * 1000
};

typedef struct {
  char *host;
  int64_t port;
  char *ca_file;
  char *server_cert;
  char *server_key;
  char *outbox_file;
  char *outbox_key_file;
  char *mesh_id;
  char *controller_node_id;
  char *controller_public_key;
  char *submitter_certificate_sha256;
  int64_t controller_certificate_serial;
  int64_t principal_epoch;
  int64_t incarnation;
  int64_t server_certificate_policy_generation;
  char *identity_specs[MESH_CONTROLLER_MAX_IDENTITIES];
  uint32_t identity_count;
} mesh_controller_options_v1_t;

typedef struct {
  mesh_control_controller_runtime_v1_t *runtime;
  uint8_t started;
} mesh_controller_app_v1_t;

typedef struct {
  mesh_control_controller_runtime_identity_config_v1_t identities[
      MESH_CONTROLLER_MAX_IDENTITIES];
  char current_certificates[MESH_CONTROLLER_MAX_IDENTITIES][TURBO_FS_MAX_PATH];
  char next_certificates[MESH_CONTROLLER_MAX_IDENTITIES][TURBO_FS_MAX_PATH];
} mesh_controller_identity_storage_v1_t;

static volatile sig_atomic_t g_stop_requested = 0;
static volatile sig_atomic_t g_reload_requested = 0;

static uint64_t wall_now(void *context) {
  (void)context;
  return turbo_realtime_ms();
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

static int parse_u64(const char *text, uint64_t *out_value) {
  uint64_t value = 0u;
  const unsigned char *cursor = (const unsigned char *)text;
  if (!text || !text[0] || !out_value) return 0;
  while (*cursor) {
    uint64_t digit;
    if (*cursor < '0' || *cursor > '9') return 0;
    digit = (uint64_t)(*cursor - '0');
    if (value > (UINT64_MAX - digit) / 10u) return 0;
    value = value * 10u + digit;
    ++cursor;
  }
  if (value == 0u) return 0;
  *out_value = value;
  return 1;
}

static int certificate_digest_valid(const char *value) {
  size_t index;
  static const char prefix[] = "sha256:";
  if (!value || strlen(value) != sizeof(prefix) - 1u + 64u ||
      strncmp(value, prefix, sizeof(prefix) - 1u) != 0)
    return 0;
  for (index = sizeof(prefix) - 1u; value[index]; ++index)
    if (hex_value(value[index]) < 0) return 0;
  return 1;
}

static void require_last(turbo_cmd_parser_t *parser) {
  turbo_cmd_set_required(parser, turbo_cmd_last_index(parser));
}

static turbo_cmd_parser_t *build_parser(
    mesh_controller_options_v1_t *options) {
  turbo_cmd_parser_t *parser = turbo_cmd_create("mesh-controller", "1.0");
  if (!parser) return NULL;
  options->host = "127.0.0.1";
  options->port = MESH_CONTROLLER_DEFAULT_PORT;
  turbo_cmd_add_string(parser, &options->host, "host", NULL,
                       "H2 mTLS listener host");
  turbo_cmd_add_integer(parser, &options->port, "port", "p",
                        "H2 mTLS listener port");
#define REQUIRED_STRING(field, name, description)                        \
  do {                                                                    \
    turbo_cmd_add_string(parser, &(field), (name), NULL, (description));  \
    require_last(parser);                                                 \
  } while (0)
  REQUIRED_STRING(options->ca_file, "client-ca",
                  "CA bundle for agent and submitter client leaves");
  REQUIRED_STRING(options->server_cert, "server-cert",
                  "Controller server certificate PEM");
  REQUIRED_STRING(options->server_key, "server-key",
                  "ACL-protected Controller server private key PEM");
  REQUIRED_STRING(options->outbox_file, "outbox-file",
                  "Durable outbox path");
  REQUIRED_STRING(options->outbox_key_file, "outbox-key-file",
                  "ACL-protected independent outbox HMAC key file");
  REQUIRED_STRING(options->mesh_id, "mesh-id", "32-byte mesh ID as hex");
  REQUIRED_STRING(options->controller_node_id, "controller-node-id",
                  "32-byte Controller node ID as hex");
  REQUIRED_STRING(options->controller_public_key, "controller-public-key",
                  "Controller Ed25519 public key as hex");
  REQUIRED_STRING(options->submitter_certificate_sha256,
                  "submitter-cert-sha256",
                  "Pinned northbound submitter leaf as sha256:<hex>");
#undef REQUIRED_STRING
#define REQUIRED_INTEGER(field, name, description)                       \
  do {                                                                    \
    turbo_cmd_add_integer(parser, &(field), (name), NULL, (description)); \
    require_last(parser);                                                 \
  } while (0)
  REQUIRED_INTEGER(options->controller_certificate_serial,
                   "controller-cert-serial",
                   "Serial bound into signed MMP commands");
  REQUIRED_INTEGER(options->principal_epoch, "principal-epoch",
                   "Controller signing-principal epoch");
  REQUIRED_INTEGER(options->incarnation, "incarnation",
                   "Persistent Controller incarnation");
  REQUIRED_INTEGER(options->server_certificate_policy_generation,
                   "certificate-policy-generation",
                   "Server certificate policy generation");
#undef REQUIRED_INTEGER
  turbo_cmd_add_string_list(
      parser, options->identity_specs, &options->identity_count,
      MESH_CONTROLLER_MAX_IDENTITIES, "agent", NULL,
      "Repeatable node_hex,public_key_hex,current_cert,next_cert_or_dash,generation");
  return parser;
}

static int parse_identity_spec(
    const char *spec, uint64_t now_ms,
    mesh_control_controller_runtime_identity_config_v1_t *identity,
    char current_certificate[TURBO_FS_MAX_PATH],
    char next_certificate[TURBO_FS_MAX_PATH]) {
  char buffer[MESH_CONTROLLER_IDENTITY_SPEC_MAX];
  char *fields[5];
  char *cursor;
  size_t index;
  uint64_t generation;
  if (!spec || strlen(spec) >= sizeof(buffer)) return 0;
  memcpy(buffer, spec, strlen(spec) + 1u);
  cursor = buffer;
  for (index = 0u; index < 4u; ++index) {
    char *comma = strchr(cursor, ',');
    if (!comma) return 0;
    *comma = '\0';
    fields[index] = cursor;
    cursor = comma + 1;
  }
  fields[4] = cursor;
  if (strchr(fields[4], ',') || !parse_u64(fields[4], &generation) ||
      !decode_hex_exact(fields[0], identity->node_id,
                        sizeof(identity->node_id)) ||
      !decode_hex_exact(fields[1], identity->management_public_key,
                        sizeof(identity->management_public_key)) ||
      !fields[2][0] || strlen(fields[2]) >= TURBO_FS_MAX_PATH ||
      (strcmp(fields[3], "-") != 0 &&
       (!fields[3][0] || strlen(fields[3]) >= TURBO_FS_MAX_PATH)))
    return 0;
  memcpy(current_certificate, fields[2], strlen(fields[2]) + 1u);
  if (strcmp(fields[3], "-") != 0)
    memcpy(next_certificate, fields[3], strlen(fields[3]) + 1u);
  memset(&identity->certificate, 0, sizeof(identity->certificate));
  identity->certificate.role = MESH_CERTIFICATE_ROLE_CLIENT_V1;
  identity->certificate.current.certificate_file = current_certificate;
  if (next_certificate[0])
    identity->certificate.next.certificate_file = next_certificate;
  identity->certificate.policy_generation = generation;
  identity->certificate.now_ms = now_ms;
  identity->certificate.certificate_only = 1u;
  identity->identity_policy_generation = generation;
  return 1;
}

static int configure_and_start(mesh_controller_app_v1_t *app,
                               const mesh_controller_options_v1_t *options) {
  mesh_control_controller_runtime_config_v1_t config;
  mesh_controller_identity_storage_v1_t *storage = NULL;
  uint8_t outbox_key[MESHD_PRIVATE_KEY_SIZE];
  uint64_t now_ms = turbo_realtime_ms();
  size_t recovered_claims = 0u;
  size_t index;
  int ok = 0;
  memset(&config, 0, sizeof(config));
  memset(outbox_key, 0, sizeof(outbox_key));
  if (now_ms == 0u || options->port <= 0 || options->port > UINT16_MAX ||
      options->identity_count == 0u ||
      options->controller_certificate_serial <= 0 ||
      options->principal_epoch <= 0 || options->incarnation <= 0 ||
      options->server_certificate_policy_generation <= 0 ||
      !certificate_digest_valid(options->submitter_certificate_sha256) ||
      meshd_private_key_file_read(options->outbox_key_file, outbox_key) !=
          MESHD_KEY_FILE_OK)
    goto cleanup;
  storage = (mesh_controller_identity_storage_v1_t *)calloc(
      1u, sizeof(*storage));
  if (!storage) goto cleanup;
  for (index = 0u; index < options->identity_count; ++index) {
    mesh_control_controller_runtime_identity_config_v1_t *identity =
        &storage->identities[index];
    if (!parse_identity_spec(options->identity_specs[index], now_ms, identity,
                             storage->current_certificates[index],
                             storage->next_certificates[index]))
      goto cleanup;
    identity->certificate.ca_file = options->ca_file;
  }
  config.host = options->host;
  config.port = (uint16_t)options->port;
  config.server_certificate.ca_file = options->ca_file;
  config.server_certificate.role = MESH_CERTIFICATE_ROLE_SERVER_V1;
  config.server_certificate.current.certificate_file = options->server_cert;
  config.server_certificate.current.private_key_file = options->server_key;
  config.server_certificate.policy_generation =
      (uint64_t)options->server_certificate_policy_generation;
  config.server_certificate.now_ms = now_ms;
  config.server_certificate.require_private_key_file_security = 1u;
  config.agent_client_ca_file = options->ca_file;
  config.identities = storage->identities;
  config.identity_count = options->identity_count;
  config.identity_capacity = options->identity_count;
  config.now_ms = wall_now;
  config.session.outbox.path = options->outbox_file;
  config.session.outbox.entry_capacity = MESH_CONTROLLER_OUTBOX_ENTRIES;
  config.session.outbox.session_capacity = MESH_CONTROLLER_OUTBOX_SESSIONS;
  config.session.outbox.byte_capacity = MESH_CONTROLLER_OUTBOX_BYTES;
  config.session.outbox.max_payload_size = MESH_CONTROL_MAX_FRAME_SIZE_V1;
  config.session.outbox.max_claim_lease_ms =
      MESH_CONTROLLER_MAX_CLAIM_LEASE_MS;
  config.session.outbox.ack_retention_ms =
      MESH_CONTROLLER_ACK_RETENTION_MS;
  memcpy(config.session.outbox.authentication_key, outbox_key,
         sizeof(outbox_key));
  config.session.session_capacity = options->identity_count;
  config.session.claim_lease_ms = MESH_CONTROLLER_CLAIM_LEASE_MS;
  config.session.maximum_clock_skew_ms = MESH_CONTROLLER_MAX_CLOCK_SKEW_MS;
  config.session.maximum_hello_lifetime_ms =
      MESH_CONTROLLER_MAX_COMMAND_LIFETIME_MS;
  config.submit_policy.submitter_tls_certificate_sha256 =
      options->submitter_certificate_sha256;
  if (!decode_hex_exact(options->mesh_id, config.submit_policy.mesh_id,
                        sizeof(config.submit_policy.mesh_id)) ||
      !decode_hex_exact(options->controller_node_id,
                        config.submit_policy.controller_node_id,
                        sizeof(config.submit_policy.controller_node_id)) ||
      !decode_hex_exact(
          options->controller_public_key,
          config.submit_policy.controller_management_public_key,
          sizeof(config.submit_policy.controller_management_public_key)))
    goto cleanup;
  config.submit_policy.principal_epoch =
      (uint64_t)options->principal_epoch;
  config.submit_policy.incarnation = (uint64_t)options->incarnation;
  config.submit_policy.certificate_serial =
      (uint64_t)options->controller_certificate_serial;
  config.submit_policy.maximum_clock_skew_ms =
      MESH_CONTROLLER_MAX_CLOCK_SKEW_MS;
  config.submit_policy.maximum_command_lifetime_ms =
      MESH_CONTROLLER_MAX_COMMAND_LIFETIME_MS;
  config.persistence_timeout_ms = MESH_CONTROLLER_PERSISTENCE_TIMEOUT_MS;
  config.shutdown_drain_timeout_ms = MESH_CONTROLLER_SHUTDOWN_TIMEOUT_MS;
  app->runtime = (mesh_control_controller_runtime_v1_t *)calloc(
      1u, sizeof(*app->runtime));
  if (!app->runtime ||
      mesh_control_controller_runtime_init_v1(
          app->runtime, &config, &recovered_claims) != MESH_CONTROL_OK)
    goto cleanup;
  app->started = 1u;
  fprintf(stdout, "mesh-controller: recovered %zu active claims\n",
          recovered_claims);
  ok = 1;

cleanup:
  mesh_mgmt_crypto_wipe(outbox_key, sizeof(outbox_key));
  free(storage);
  if (!ok) {
    free(app->runtime);
    app->runtime = NULL;
  }
  return ok;
}

static int stop_app(mesh_controller_app_v1_t *app) {
  int ok = 1;
  if (app->runtime) {
    if (app->started && !app->runtime->stopped &&
        mesh_control_controller_runtime_stop_v1(app->runtime) !=
            MESH_CONTROL_OK)
      ok = 0;
    if (app->runtime->stopped)
      mesh_control_controller_runtime_destroy_v1(app->runtime);
    free(app->runtime);
    app->runtime = NULL;
  }
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
  mesh_controller_options_v1_t options;
  turbo_cmd_parser_t *parser;
  turbo_cmd_parse_result_t parse_result;
  int exit_code = 1;
  memset(&options, 0, sizeof(options));
  parser = build_parser(&options);
  if (!parser) return 1;
  memset(&parse_result, 0, sizeof(parse_result));
  parse_result.size = sizeof(parse_result);
  if (turbo_cmd_parse_ex(parser, argc, argv, &parse_result) != 0)
    goto cleanup;
  if (parse_result.status == TURBO_CMD_PARSE_HELP) {
    if (turbo_cmd_render_help(parser, parse_result.leaf, write_stdout, NULL) ==
        0)
      exit_code = 0;
    goto cleanup;
  }
  if (parse_result.status == TURBO_CMD_PARSE_VERSION) {
    fprintf(stdout, "%s\n", parse_result.message ? parse_result.message
                                                  : "mesh-controller 1.0");
    exit_code = 0;
    goto cleanup;
  }
  if (parse_result.status != TURBO_CMD_PARSE_OK) {
    fprintf(stderr, "mesh-controller: %s%s%s\n",
            parse_result.error_code ? parse_result.error_code
                                    : "invalid-argument",
            parse_result.message ? ": " : "",
            parse_result.message ? parse_result.message : "");
    goto cleanup;
  }
  install_signals();
  while (!g_stop_requested) {
    mesh_controller_app_v1_t app;
    memset(&app, 0, sizeof(app));
    g_reload_requested = 0;
    if (!configure_and_start(&app, &options)) {
      fprintf(stderr,
              "mesh-controller: fail-closed startup validation failed\n");
      (void)stop_app(&app);
      goto cleanup;
    }
    fprintf(stdout, "mesh-controller: started on %s:%lld\n", options.host,
            (long long)options.port);
    fflush(stdout);
    while (!g_stop_requested && !g_reload_requested) {
      size_t progress = 0u;
      mesh_control_result_t result =
          mesh_control_controller_runtime_poll_v1(app.runtime, &progress);
      if (result != MESH_CONTROL_OK) {
        fprintf(stderr, "mesh-controller: runtime fault (%d)\n", (int)result);
        g_stop_requested = 1;
        break;
      }
      if (progress == 0u) turbo_sleep_ms(1u);
    }
    if (!stop_app(&app)) {
      fprintf(stderr, "mesh-controller: shutdown drain failed\n");
      goto cleanup;
    }
    if (g_reload_requested && !g_stop_requested) {
      fprintf(stdout, "mesh-controller: reloading certificates and policy\n");
      fflush(stdout);
    }
  }
  exit_code = 0;

cleanup:
  turbo_cmd_destroy(parser);
  return exit_code;
}
