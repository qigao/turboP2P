#include "mesh_control_controller_runtime.h"

#include "mesh_mgmt_crypto.h"
#include "platform.h"

#include <stdlib.h>
#include <string.h>

static const char *const CONTROLLER_ALPN[] = {"h2", "http/1.1"};

static int bytes_zero(const uint8_t *bytes, size_t size) {
  uint8_t value = 0u;
  size_t index;
  for (index = 0u; index < size; ++index) value |= bytes[index];
  return value == 0u;
}

static int identity_config_valid(
    const mesh_control_controller_runtime_identity_config_v1_t *identity) {
  return identity &&
         !bytes_zero(identity->node_id, sizeof(identity->node_id)) &&
         !bytes_zero(identity->management_public_key,
                     sizeof(identity->management_public_key)) &&
         identity->certificate.role == MESH_CERTIFICATE_ROLE_CLIENT_V1 &&
         identity->certificate.certificate_only == 1u &&
         identity->certificate.current.private_key_file == NULL &&
         identity->certificate.next.private_key_file == NULL &&
         identity->identity_policy_generation != 0u &&
         identity->identity_policy_generation ==
             identity->certificate.policy_generation;
}

static int submit_policy_valid(
    const mesh_control_controller_submit_policy_v1_t *policy) {
  if (!policy->submitter_tls_certificate_sha256)
    return bytes_zero(policy->mesh_id, sizeof(policy->mesh_id)) &&
           bytes_zero(policy->controller_node_id,
                      sizeof(policy->controller_node_id)) &&
           bytes_zero(policy->controller_management_public_key,
                      sizeof(policy->controller_management_public_key)) &&
           policy->principal_epoch == 0u && policy->incarnation == 0u &&
           policy->certificate_serial == 0u &&
           policy->maximum_clock_skew_ms == 0u &&
           policy->maximum_command_lifetime_ms == 0u;
  return policy->submitter_tls_certificate_sha256[0] != '\0' &&
         !bytes_zero(policy->mesh_id, sizeof(policy->mesh_id)) &&
         !bytes_zero(policy->controller_node_id,
                     sizeof(policy->controller_node_id)) &&
         !bytes_zero(policy->controller_management_public_key,
                     sizeof(policy->controller_management_public_key)) &&
         policy->principal_epoch != 0u && policy->incarnation != 0u &&
         policy->certificate_serial != 0u &&
         policy->maximum_command_lifetime_ms != 0u;
}

static int config_valid(
    const mesh_control_controller_runtime_config_v1_t *config) {
  size_t index;
  if (!config || !config->host || config->host[0] == '\0' ||
      strlen(config->host) > MESH_CONTROL_CONTROLLER_HOST_MAX_V1 ||
      config->server_certificate.role != MESH_CERTIFICATE_ROLE_SERVER_V1 ||
      !config->agent_client_ca_file ||
      config->agent_client_ca_file[0] == '\0' || !config->identities ||
      config->identity_count == 0u ||
      config->identity_capacity < config->identity_count ||
      config->identity_capacity > MESH_CONTROL_CONTROLLER_IDENTITY_MAX_V1 ||
      !config->now_ms || config->persistence_timeout_ms == 0u ||
      config->shutdown_drain_timeout_ms == 0u ||
      !submit_policy_valid(&config->submit_policy))
    return 0;
  for (index = 0u; index < config->identity_count; ++index)
    if (!identity_config_valid(&config->identities[index])) return 0;
  return 1;
}

static mesh_control_result_t authorize_submit(
    void *context, const mesh_mgmt_verified_envelope_v1_t *verified,
    const mesh_control_envelope_v1_t *envelope, uint64_t now_ms) {
  mesh_control_controller_runtime_v1_t *runtime =
      (mesh_control_controller_runtime_v1_t *)context;
  const mesh_control_controller_submit_policy_v1_t *policy;
  uint64_t latest_issued_at;
  size_t index;
  if (!runtime || !verified || !envelope || now_ms == 0u)
    return MESH_CONTROL_INVALID_ARG;
  policy = &runtime->submit_policy;
  latest_issued_at = now_ms > UINT64_MAX - policy->maximum_clock_skew_ms
                         ? UINT64_MAX
                         : now_ms + policy->maximum_clock_skew_ms;
  if (envelope->kind != MESH_CONTROL_MESSAGE_INTENT ||
      !mesh_mgmt_crypto_equal_32(envelope->mesh_id, policy->mesh_id) ||
      !mesh_mgmt_crypto_equal_32(envelope->origin_node_id,
                                 policy->controller_node_id) ||
      !mesh_mgmt_crypto_equal_32(
          envelope->origin_principal,
          policy->controller_management_public_key) ||
      envelope->principal_epoch != policy->principal_epoch ||
      envelope->incarnation != policy->incarnation ||
      envelope->certificate_serial != policy->certificate_serial ||
      envelope->issued_at_ms > latest_issued_at ||
      envelope->expires_at_ms <= now_ms ||
      envelope->expires_at_ms <= envelope->issued_at_ms ||
      envelope->expires_at_ms - envelope->issued_at_ms >
          policy->maximum_command_lifetime_ms)
    return MESH_CONTROL_UNAUTHORIZED;
  for (index = 0u; index < runtime->identities.count; ++index)
    if (mesh_mgmt_crypto_equal_32(runtime->identities.entries[index].node_id,
                                  envelope->target_node_id))
      return MESH_CONTROL_OK;
  return MESH_CONTROL_UNAUTHORIZED;
}

static void destroy_members(mesh_control_controller_runtime_v1_t *runtime) {
  size_t index;
  if (!runtime) return;
  if (runtime->listener) {
    coro_socket_destroy(runtime->listener);
    runtime->listener = NULL;
  }
  /* Managed callbacks may still reference iris/session. Destroy their event
   * loop before releasing either owner on failed-start paths. */
  if (runtime->context) {
    coro_context_stop(runtime->context);
    coro_context_destroy(runtime->context);
    runtime->context = NULL;
  }
  if (runtime->iris_started) {
    mesh_control_controller_iris_destroy_v1(&runtime->iris);
    runtime->iris_started = 0u;
  }
  if (runtime->session_started) {
    mesh_control_controller_session_destroy_v1(&runtime->session);
    runtime->session_started = 0u;
  }
  mesh_control_controller_identity_registry_destroy_v1(&runtime->identities);
  if (runtime->client_certificates) {
    for (index = 0u; index < runtime->identity_count; ++index)
      mesh_certificate_lifecycle_destroy_v1(
          &runtime->client_certificates[index]);
    free(runtime->client_certificates);
    runtime->client_certificates = NULL;
  }
  mesh_certificate_lifecycle_destroy_v1(&runtime->server_certificate);
  if (runtime->app) {
    iris_app_destroy(runtime->app);
    runtime->app = NULL;
  }
}

mesh_control_result_t mesh_control_controller_runtime_init_v1(
    mesh_control_controller_runtime_v1_t *runtime,
    const mesh_control_controller_runtime_config_v1_t *config,
    size_t *out_recovered_claims) {
  mesh_control_controller_session_config_v1_t session_config;
  mesh_control_controller_iris_config_v1_t iris_config;
  mesh_control_controller_identity_entry_v1_t entry;
  mesh_control_result_t result = MESH_CONTROL_INVALID_STATE;
  size_t recovered_claims = 0u;
  size_t index;

  if (!runtime || runtime->initialized || !out_recovered_claims ||
      !config_valid(config))
    return MESH_CONTROL_INVALID_ARG;
  *out_recovered_claims = 0u;
  memset(runtime, 0, sizeof(*runtime));
  memcpy(runtime->host, config->host, strlen(config->host) + 1u);
  runtime->shutdown_drain_timeout_ms = config->shutdown_drain_timeout_ms;
  runtime->identity_count = config->identity_count;
  runtime->submit_policy = config->submit_policy;

  result = mesh_certificate_lifecycle_init_v1(
      &runtime->server_certificate, &config->server_certificate);
  if (result != MESH_CONTROL_OK) goto failed;
  runtime->client_certificates =
      (mesh_certificate_lifecycle_v1_t *)calloc(
          config->identity_capacity, sizeof(*runtime->client_certificates));
  if (!runtime->client_certificates) {
    result = MESH_CONTROL_RESOURCE_EXHAUSTED;
    goto failed;
  }
  result = mesh_control_controller_identity_registry_init_v1(
      &runtime->identities, config->identity_capacity, config->now_ms,
      config->now_context);
  if (result != MESH_CONTROL_OK) goto failed;
  for (index = 0u; index < config->identity_count; ++index) {
    result = mesh_certificate_lifecycle_init_v1(
        &runtime->client_certificates[index],
        &config->identities[index].certificate);
    if (result != MESH_CONTROL_OK) goto failed;
    memset(&entry, 0, sizeof(entry));
    memcpy(entry.node_id, config->identities[index].node_id,
           sizeof(entry.node_id));
    memcpy(entry.management_public_key,
           config->identities[index].management_public_key,
           sizeof(entry.management_public_key));
    entry.certificate = &runtime->client_certificates[index];
    entry.identity_policy_generation =
        config->identities[index].identity_policy_generation;
    result = mesh_control_controller_identity_registry_put_v1(
        &runtime->identities, &entry);
    if (result != MESH_CONTROL_OK) goto failed;
  }

  session_config = config->session;
  session_config.authorize_identity =
      mesh_control_controller_identity_authorize_v1;
  session_config.identity_context = &runtime->identities;
  result = mesh_control_controller_session_init_v1(
      &runtime->session, &session_config, &recovered_claims);
  if (result != MESH_CONTROL_OK) goto failed;
  runtime->session_started = 1u;

  runtime->app = iris_app_create();
  runtime->context = coro_context_create(NULL);
  if (!runtime->app || !runtime->context) goto failed;
  memset(&iris_config, 0, sizeof(iris_config));
  iris_config.controller = &runtime->session;
  iris_config.context = runtime->context;
  iris_config.now_ms = config->now_ms;
  iris_config.now_context = config->now_context;
  iris_config.persistence_timeout_ms = config->persistence_timeout_ms;
  iris_config.submit_peer_certificate_sha256 =
      config->submit_policy.submitter_tls_certificate_sha256;
  if (iris_config.submit_peer_certificate_sha256) {
    iris_config.authorize_submit = authorize_submit;
    iris_config.submit_context = runtime;
  }
  result = mesh_control_controller_iris_register_v1(
      &runtime->iris, runtime->app, &iris_config);
  if (result != MESH_CONTROL_OK) goto failed;
  runtime->iris_started = 1u;

  memset(&runtime->server_tls, 0, sizeof(runtime->server_tls));
  runtime->server_tls.size = sizeof(runtime->server_tls);
  runtime->server_tls.cert_file =
      runtime->server_certificate.current.certificate_file;
  runtime->server_tls.key_file =
      runtime->server_certificate.current.private_key_file;
  runtime->server_tls.key_password = config->server_key_password;
  runtime->server_tls.ca_file = config->agent_client_ca_file;
  runtime->server_tls.client_auth = TURBO_TLS_CLIENT_AUTH_REQUIRED;
  runtime->server_tls.alpn_protos = CONTROLLER_ALPN;
  runtime->server_tls.alpn_proto_count =
      sizeof(CONTROLLER_ALPN) / sizeof(CONTROLLER_ALPN[0]);
  runtime->listener = iris_server_start_tls_on(
      runtime->app, runtime->context, runtime->host, config->port,
      &runtime->server_tls);
  if (!runtime->listener) goto failed;
  runtime->initialized = 1u;
  *out_recovered_claims = recovered_claims;
  return MESH_CONTROL_OK;

failed:
  if (runtime->iris_started)
    (void)mesh_control_controller_iris_close_v1(&runtime->iris);
  if (runtime->session_started)
    (void)mesh_control_controller_session_shutdown_v1(&runtime->session);
  destroy_members(runtime);
  memset(runtime, 0, sizeof(*runtime));
  return result;
}

mesh_control_result_t mesh_control_controller_runtime_poll_v1(
    mesh_control_controller_runtime_v1_t *runtime, size_t *out_progress) {
  if (!runtime || !runtime->initialized || runtime->stopped || !out_progress)
    return MESH_CONTROL_INVALID_ARG;
  *out_progress = 0u;
  (void)coro_context_run(runtime->context, TURBO_RUN_NOWAIT);
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_controller_runtime_try_submit_v1(
    mesh_control_controller_runtime_v1_t *runtime,
    const mesh_control_durable_outbox_message_v1_t *message,
    uint64_t *out_request_token) {
  if (!runtime || !runtime->initialized || runtime->stopped)
    return MESH_CONTROL_INVALID_ARG;
  return mesh_control_controller_session_try_submit_v1(
      &runtime->session, message, out_request_token);
}

mesh_control_result_t mesh_control_controller_runtime_try_take_submit_v1(
    mesh_control_controller_runtime_v1_t *runtime,
    mesh_control_controller_submit_completion_v1_t *out_completion) {
  if (!runtime || !runtime->initialized || runtime->stopped)
    return MESH_CONTROL_INVALID_ARG;
  return mesh_control_controller_session_try_take_submit_v1(
      &runtime->session, out_completion);
}

mesh_control_result_t mesh_control_controller_runtime_rotate_identity_v1(
    mesh_control_controller_runtime_v1_t *runtime,
    const mesh_control_controller_runtime_identity_config_v1_t *config) {
  mesh_certificate_lifecycle_v1_t candidate;
  mesh_certificate_lifecycle_v1_t previous;
  mesh_control_controller_identity_entry_v1_t entry;
  size_t index;
  mesh_control_result_t result;
  if (!runtime || !runtime->initialized || runtime->stopped ||
      !identity_config_valid(config))
    return MESH_CONTROL_INVALID_ARG;
  for (index = 0u; index < runtime->identity_count; ++index)
    if (mesh_mgmt_crypto_equal_32(
            runtime->identities.entries[index].node_id, config->node_id))
      break;
  if (index == runtime->identity_count ||
      config->identity_policy_generation <=
          runtime->identities.entries[index].identity_policy_generation)
    return index == runtime->identity_count ? MESH_CONTROL_EMPTY
                                            : MESH_CONTROL_STALE_EPOCH;
  memset(&candidate, 0, sizeof(candidate));
  result = mesh_certificate_lifecycle_init_v1(&candidate,
                                               &config->certificate);
  if (result != MESH_CONTROL_OK) return result;
  previous = runtime->client_certificates[index];
  runtime->client_certificates[index] = candidate;
  memset(&entry, 0, sizeof(entry));
  memcpy(entry.node_id, config->node_id, sizeof(entry.node_id));
  memcpy(entry.management_public_key, config->management_public_key,
         sizeof(entry.management_public_key));
  entry.certificate = &runtime->client_certificates[index];
  entry.identity_policy_generation = config->identity_policy_generation;
  result = mesh_control_controller_identity_registry_put_v1(
      &runtime->identities, &entry);
  if (result != MESH_CONTROL_OK) {
    runtime->client_certificates[index] = previous;
    mesh_certificate_lifecycle_destroy_v1(&candidate);
    return result;
  }
  mesh_certificate_lifecycle_destroy_v1(&previous);
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_controller_runtime_stop_v1(
    mesh_control_controller_runtime_v1_t *runtime) {
  mesh_control_controller_session_stats_v1_t stats;
  uint64_t started_at_ms;
  mesh_control_result_t result;
  if (!runtime || !runtime->initialized) return MESH_CONTROL_INVALID_ARG;
  if (runtime->stopped) return MESH_CONTROL_OK;
  if (runtime->iris_started)
    (void)mesh_control_controller_iris_close_v1(&runtime->iris);
  if (runtime->listener) {
    coro_socket_destroy(runtime->listener);
    runtime->listener = NULL;
  }
  started_at_ms = turbo_monotonic_ms();
  for (;;) {
    (void)coro_context_run(runtime->context, TURBO_RUN_NOWAIT);
    result = mesh_control_controller_session_get_stats_v1(&runtime->session,
                                                           &stats);
    if (result != MESH_CONTROL_OK) return result;
    if (stats.response_ready)
      (void)mesh_control_controller_session_abandon_response_v1(
          &runtime->session);
    if (runtime->session.submit_completion_ready) {
      mesh_control_controller_submit_completion_v1_t completion;
      (void)mesh_control_controller_session_try_take_submit_v1(
          &runtime->session, &completion);
    }
    if (!runtime->iris.maintenance_running &&
        atomic_load_explicit(&runtime->iris.active_callbacks,
                             memory_order_acquire) == 0u &&
        !stats.persistence_busy &&
        !runtime->session.pending_operation && !runtime->session.response_ready &&
        !runtime->session.submit_completion_ready)
      break;
    if (turbo_monotonic_ms() - started_at_ms >=
        runtime->shutdown_drain_timeout_ms)
      return MESH_CONTROL_TIMEOUT;
    turbo_sleep_ms(1u);
  }
  result = mesh_control_controller_session_shutdown_v1(&runtime->session);
  if (result != MESH_CONTROL_OK) return result;
  coro_context_stop(runtime->context);
  while (coro_context_alive(runtime->context) &&
         turbo_monotonic_ms() - started_at_ms <
             runtime->shutdown_drain_timeout_ms)
    (void)coro_context_run(runtime->context, TURBO_RUN_ONCE);
  if (coro_context_alive(runtime->context)) return MESH_CONTROL_TIMEOUT;
  runtime->stopped = 1u;
  return MESH_CONTROL_OK;
}

void mesh_control_controller_runtime_destroy_v1(
    mesh_control_controller_runtime_v1_t *runtime) {
  if (!runtime || (runtime->initialized && !runtime->stopped)) return;
  destroy_members(runtime);
  memset(runtime, 0, sizeof(*runtime));
}
