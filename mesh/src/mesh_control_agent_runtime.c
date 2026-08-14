#include "mesh_control_agent_runtime.h"

#include "mesh_mgmt_crypto.h"

#include <string.h>

static const char *const AGENT_ALPN[] = {"h2", "http/1.1"};

static void service_task(coro_t *coroutine, void *argument) {
  mesh_control_agent_runtime_v1_t *runtime =
      (mesh_control_agent_runtime_v1_t *)argument;
  (void)coroutine;
  if (!runtime) return;
  runtime->service_task_running = 1u;
  while (runtime->service_task_accepting) {
    size_t progress = 0u;
    mesh_control_result_t result =
        mesh_control_agent_service_poll_v1(&runtime->service, &progress);
    runtime->service_task_progress += progress;
    if (result != MESH_CONTROL_OK &&
        result != MESH_CONTROL_PROVIDER_UNAVAILABLE &&
        result != MESH_CONTROL_STALE_EPOCH) {
      runtime->service_task_result = result;
      break;
    }
    coro_sleep(runtime->agent.context, 1u);
  }
  runtime->service_task_running = 0u;
}

static int config_valid(const mesh_control_agent_runtime_config_v1_t *config) {
  return config && config->controller_client_ca_file &&
         config->controller_client_ca_file[0] != '\0' &&
         config->controller_sync_url && config->controller_timeout_ms != 0u &&
         config->server_certificate.role == MESH_CERTIFICATE_ROLE_SERVER_V1 &&
         config->client_certificate.role == MESH_CERTIFICATE_ROLE_CLIENT_V1 &&
         config->controller_tls.ca_file &&
         config->controller_tls.ca_file[0] != '\0' &&
         config->controller_tls.verify_peer == 1 &&
         config->local_agent.durability_enabled == 1u &&
         config->identity.management_private_key;
}

static void reset_runtime(mesh_control_agent_runtime_v1_t *runtime) {
  mesh_certificate_lifecycle_destroy_v1(&runtime->client_certificate);
  mesh_certificate_lifecycle_destroy_v1(&runtime->server_certificate);
  mesh_mgmt_crypto_wipe(runtime->management_private_key,
                        sizeof(runtime->management_private_key));
  memset(runtime, 0, sizeof(*runtime));
}

mesh_control_result_t mesh_control_agent_runtime_init_v1(
    mesh_control_agent_runtime_v1_t *runtime,
    const mesh_control_agent_runtime_config_v1_t *config) {
  mesh_control_agent_config_v1_t agent_config;
  mesh_control_agent_http_client_config_v1_t http_config;
  mesh_control_agent_service_config_v1_t identity;
  mesh_control_result_t result = MESH_CONTROL_INVALID_STATE;

  if (!runtime || runtime->initialized || !config_valid(config))
    return MESH_CONTROL_INVALID_ARG;
  memset(runtime, 0, sizeof(*runtime));
  if (mesh_certificate_lifecycle_init_v1(
          &runtime->server_certificate, &config->server_certificate) !=
          MESH_CONTROL_OK ||
      mesh_certificate_lifecycle_init_v1(
          &runtime->client_certificate, &config->client_certificate) !=
          MESH_CONTROL_OK)
    goto failed;

  memcpy(runtime->management_private_key,
         config->identity.management_private_key,
         sizeof(runtime->management_private_key));
  memset(&runtime->server_tls, 0, sizeof(runtime->server_tls));
  runtime->server_tls.size = sizeof(runtime->server_tls);
  runtime->server_tls.cert_file =
      runtime->server_certificate.current.certificate_file;
  runtime->server_tls.key_file =
      runtime->server_certificate.current.private_key_file;
  runtime->server_tls.key_password = config->server_key_password;
  runtime->server_tls.ca_file = config->controller_client_ca_file;
  runtime->server_tls.client_auth = TURBO_TLS_CLIENT_AUTH_REQUIRED;
  runtime->server_tls.alpn_protos = AGENT_ALPN;
  runtime->server_tls.alpn_proto_count =
      sizeof(AGENT_ALPN) / sizeof(AGENT_ALPN[0]);

  agent_config = config->local_agent;
  agent_config.tls = &runtime->server_tls;
  result = mesh_control_agent_start_v1(&runtime->agent, &agent_config);
  if (result != MESH_CONTROL_OK) goto failed;
  runtime->agent_started = 1u;

  runtime->controller_tls_template = config->controller_tls;
  runtime->client_tls = runtime->controller_tls_template;
  runtime->client_tls.cert_file =
      runtime->client_certificate.current.certificate_file;
  runtime->client_tls.key_file =
      runtime->client_certificate.current.private_key_file;
  runtime->client_tls.verify_peer = 1;
  memset(&http_config, 0, sizeof(http_config));
  http_config.sync_url = config->controller_sync_url;
  http_config.tls = &runtime->client_tls;
  http_config.timeout_ms = config->controller_timeout_ms;
  result = mesh_control_agent_http_client_init_v1(
      &runtime->http_client, runtime->agent.context, &http_config);
  if (result != MESH_CONTROL_OK) goto failed;
  runtime->http_started = 1u;

  identity = config->identity;
  identity.management_private_key = runtime->management_private_key;
  memcpy(identity.tls_certificate_sha256,
         runtime->client_certificate.current.certificate_sha256,
         sizeof(identity.tls_certificate_sha256));
  identity.certificate_serial = runtime->client_certificate.current.serial;
  identity.certificate_policy_generation =
      runtime->client_certificate.policy_generation;
  result = mesh_control_agent_service_init_http_v1(
      &runtime->service, &runtime->agent, &runtime->http_client, &identity);
  if (result != MESH_CONTROL_OK) goto failed;
  runtime->service_started = 1u;
  runtime->service_task_accepting = 1u;
  runtime->service_task_result = MESH_CONTROL_OK;
  if (coro_context_spawn(runtime->agent.context, service_task, runtime) != 0)
    goto failed;
  runtime->initialized = 1u;
  return MESH_CONTROL_OK;

failed:
  if (runtime->service_started)
    mesh_control_agent_service_destroy_v1(&runtime->service);
  if (runtime->http_started)
    mesh_control_agent_http_client_destroy_v1(&runtime->http_client);
  if (runtime->agent_started)
    (void)mesh_control_agent_stop_v1(&runtime->agent);
  reset_runtime(runtime);
  return result;
}

mesh_control_result_t mesh_control_agent_runtime_poll_v1(
    mesh_control_agent_runtime_v1_t *runtime, size_t *out_progress) {
  if (!runtime || !runtime->initialized || runtime->stopped || !out_progress)
    return MESH_CONTROL_INVALID_ARG;
  *out_progress = 0u;
  (void)coro_context_run(runtime->agent.context, TURBO_RUN_NOWAIT);
  *out_progress = runtime->service_task_progress;
  runtime->service_task_progress = 0u;
  return runtime->service_task_result;
}

mesh_control_result_t mesh_control_agent_runtime_rotate_client_v1(
    mesh_control_agent_runtime_v1_t *runtime,
    const mesh_certificate_lifecycle_config_v1_t *config) {
  mesh_certificate_lifecycle_v1_t candidate;
  mesh_control_result_t result;
  if (!runtime || !runtime->initialized || runtime->stopped || !config ||
      config->role != MESH_CERTIFICATE_ROLE_CLIENT_V1 ||
      config->policy_generation <=
          runtime->client_certificate.policy_generation)
    return MESH_CONTROL_INVALID_ARG;
  memset(&candidate, 0, sizeof(candidate));
  result = mesh_certificate_lifecycle_init_v1(&candidate, config);
  if (result != MESH_CONTROL_OK) return result;
  result = mesh_control_agent_service_rotate_certificate_v1(
      &runtime->service, &runtime->http_client, &candidate,
      &runtime->controller_tls_template);
  if (result != MESH_CONTROL_OK) {
    mesh_certificate_lifecycle_destroy_v1(&candidate);
    return result;
  }
  runtime->client_certificate = candidate;
  runtime->client_tls = runtime->controller_tls_template;
  runtime->client_tls.cert_file =
      runtime->client_certificate.current.certificate_file;
  runtime->client_tls.key_file =
      runtime->client_certificate.current.private_key_file;
  runtime->client_tls.verify_peer = 1;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_agent_runtime_stop_v1(
    mesh_control_agent_runtime_v1_t *runtime) {
  mesh_control_result_t result;
  if (!runtime || !runtime->initialized)
    return MESH_CONTROL_INVALID_ARG;
  if (runtime->stopped) return MESH_CONTROL_OK;
  runtime->service_task_accepting = 0u;
  while (runtime->service_task_running) {
    (void)coro_context_run(runtime->agent.context, TURBO_RUN_ONCE);
  }
  if (runtime->service_started) {
    result = mesh_control_agent_service_close_v1(&runtime->service);
    if (result != MESH_CONTROL_OK) return result;
    runtime->service_started = 0u;
  }
  if (runtime->http_started) {
    result = mesh_control_agent_http_client_close_v1(&runtime->http_client);
    if (result != MESH_CONTROL_OK) return result;
    mesh_control_agent_http_client_destroy_v1(&runtime->http_client);
    runtime->http_started = 0u;
  }
  if (runtime->agent_started) {
    result = mesh_control_agent_stop_v1(&runtime->agent);
    if (result != MESH_CONTROL_OK) return result;
    runtime->agent_started = 0u;
  }
  runtime->stopped = 1u;
  return MESH_CONTROL_OK;
}

void mesh_control_agent_runtime_destroy_v1(
    mesh_control_agent_runtime_v1_t *runtime) {
  if (!runtime || (runtime->initialized && !runtime->stopped)) return;
  mesh_control_agent_service_destroy_v1(&runtime->service);
  mesh_control_agent_http_client_destroy_v1(&runtime->http_client);
  reset_runtime(runtime);
}
