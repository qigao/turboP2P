#include "mesh_control_agent.h"

#include <turbo_crypto.h>

#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

static mesh_control_result_t
agent_authorize_transport(void *context,
                          const char peer_certificate_sha256[CORO_TLS_PEER_CERT_SHA256_CAPACITY]);

static int bytes_zero(const uint8_t *bytes, size_t size) {
  uint8_t aggregate = 0u;
  size_t index;
  if (!bytes)
    return 1;
  for (index = 0u; index < size; ++index)
    aggregate |= bytes[index];
  return aggregate == 0u;
}

static int durability_config_valid(const mesh_control_agent_config_v1_t *config) {
  const mesh_control_wal_config_v1_t *wal;
  int checkpoint_disabled;
  int checkpoint_enabled;
  if (!config || config->durability_enabled > 1u)
    return 0;
  if (!config->durability_enabled)
    return config->checkpoint_path == NULL && config->checkpoint_interval_records == 0u;
  wal = &config->wal;
  checkpoint_disabled =
      config->checkpoint_path == NULL && config->checkpoint_interval_records == 0u;
  checkpoint_enabled = config->checkpoint_path != NULL && config->checkpoint_path[0] != '\0' &&
                       turbo_fs_path_is_absolute(config->checkpoint_path) &&
                       config->checkpoint_interval_records != 0u &&
                       config->checkpoint_interval_records < wal->record_capacity &&
                       wal->byte_capacity >= MESH_CONTROL_WAL_FILE_HEADER_SIZE_V1 +
                                                 2u * MESH_CONTROL_WAL_MAX_RECORD_SIZE_V1;
  return wal->path && wal->path[0] != '\0' && turbo_fs_path_is_absolute(wal->path) &&
         wal->record_capacity != 0u && wal->record_capacity <= MESH_CONTROL_WAL_MAX_RECORDS_V1 &&
         wal->byte_capacity != 0u && wal->byte_capacity <= MESH_CONTROL_WAL_MAX_FILE_SIZE_V1 &&
         !bytes_zero(wal->authentication_key, sizeof(wal->authentication_key)) &&
         memcmp(wal->mesh_id, config->owner.mesh_id, sizeof(wal->mesh_id)) == 0 &&
         memcmp(wal->node_id, config->owner.node_id, sizeof(wal->node_id)) == 0 &&
         memcmp(wal->controller_principal, config->owner.replay_binding.principal_key,
                sizeof(wal->controller_principal)) == 0 &&
         memcmp(wal->controller_node_id, config->controller_node_id,
                sizeof(wal->controller_node_id)) == 0 &&
         wal->principal_epoch == config->owner.replay_binding.principal_epoch &&
         wal->incarnation == config->owner.replay_binding.incarnation &&
         wal->certificate_serial == config->controller_certificate_serial &&
         memcmp(wal->session_id, config->owner.replay_binding.session_id,
                sizeof(wal->session_id)) == 0 &&
         (checkpoint_disabled || checkpoint_enabled);
}

static int digest_string_valid(const char *value) {
  size_t index;
  if (value == NULL || strlen(value) != 71u || memcmp(value, "sha256:", 7u) != 0)
    return 0;
  for (index = 7u; index < 71u; ++index) {
    if (!isxdigit((unsigned char)value[index]) || (value[index] >= 'A' && value[index] <= 'F'))
      return 0;
  }
  return 1;
}

static int tls_alpn_valid(const turbo_tls_server_config_t *tls) {
  size_t index;
  int has_h2 = 0;
  int has_http1 = 0;
  if (tls == NULL || tls->alpn_protos == NULL || tls->alpn_proto_count == 0u)
    return 0;
  for (index = 0u; index < tls->alpn_proto_count; ++index) {
    if (tls->alpn_protos[index] == NULL)
      return 0;
    if (strcmp(tls->alpn_protos[index], "h2") == 0)
      has_h2 = 1;
    else if (strcmp(tls->alpn_protos[index], "http/1.1") == 0)
      has_http1 = 1;
  }
  return has_h2 && has_http1;
}

static int status_limits_valid(const mesh_control_agent_config_v1_t *config) {
  size_t resource_bytes;
  size_t operation_bytes;
  if (config->status_page_resource_limit == 0u || config->status_page_operation_limit == 0u ||
      config->status_event_limit == 0u || config->status_page_resource_limit > UINT16_MAX ||
      config->status_page_operation_limit > UINT16_MAX || config->status_event_limit > UINT16_MAX ||
      config->status_page_resource_limit > SIZE_MAX / MESH_CONTROL_STATUS_RESOURCE_RECORD_SIZE_V1 ||
      config->status_page_operation_limit >
          SIZE_MAX / MESH_CONTROL_STATUS_OPERATION_RECORD_SIZE_V1 ||
      config->status_event_limit >
          (MESH_CONTROL_MAX_STATUS_SNAPSHOT_SIZE_V1 - MESH_CONTROL_EVENT_HEADER_SIZE_V1) /
              MESH_CONTROL_EVENT_RECORD_SIZE_V1)
    return 0;
  resource_bytes = config->status_page_resource_limit * MESH_CONTROL_STATUS_RESOURCE_RECORD_SIZE_V1;
  operation_bytes =
      config->status_page_operation_limit * MESH_CONTROL_STATUS_OPERATION_RECORD_SIZE_V1;
  return resource_bytes <=
             MESH_CONTROL_MAX_STATUS_SNAPSHOT_SIZE_V1 - MESH_CONTROL_STATUS_HEADER_SIZE_V1 &&
         operation_bytes <= MESH_CONTROL_MAX_STATUS_SNAPSHOT_SIZE_V1 -
                                MESH_CONTROL_STATUS_HEADER_SIZE_V1 - resource_bytes;
}

static int network_config_valid(const mesh_control_agent_config_v1_t *config) {
  mesh_fabric_status_v2_t status;
  const mesh_control_network_provider_v1_t *provider =
      config->network_provider;
  if (config->network_fabric != NULL && provider != NULL)
    return 0;
  if (config->network_fabric == NULL && provider == NULL)
    return config->network_capacity == 0u;
  if (config->network_capacity == 0u ||
      config->network_capacity > MESH_NETWORK_HARD_LIMIT)
    return 0;
  if (provider != NULL)
    return provider->context != NULL && provider->ops.try_start != NULL &&
           provider->ops.try_peek_completion != NULL &&
           provider->ops.ack_completion != NULL &&
           provider->ops.close != NULL && provider->ops.is_drained != NULL;
  memset(&status, 0, sizeof(status));
  status.struct_size = sizeof(status);
  return mesh_fabric_get_status_v2(config->network_fabric, &status) ==
             MESH_OK &&
         status.attached_networks == 0u;
}

static int agent_network_enabled(const mesh_control_agent_v1_t *agent) {
  return agent && (agent->network_reconciler_initialized ||
                   agent->network_provider_initialized);
}

static int config_valid(const mesh_control_agent_config_v1_t *config) {
  int provider_config_valid;
  if (config == NULL)
    return 0;
  provider_config_valid =
      (config->function_reconciler.provider_count == 0u &&
       config->function_reconciler.providers == NULL &&
       config->function_reconciler.inflight_capacity == 0u) ||
      (config->function_reconciler.provider_count != 0u &&
       config->function_reconciler.providers != NULL &&
       config->function_reconciler.inflight_capacity >= config->owner.state.operation_capacity &&
       config->max_provider_completions_per_poll != 0u &&
       config->max_provider_starts_per_poll != 0u);
  if (config->network_provider != NULL &&
      (config->max_provider_completions_per_poll == 0u ||
       config->max_provider_starts_per_poll == 0u))
    provider_config_valid = 0;
  return config->host != NULL && config->host[0] != '\0' &&
         strlen(config->host) <= MESH_CONTROL_AGENT_HOST_MAX_V1 && config->tls != NULL &&
         config->tls->size == sizeof(turbo_tls_server_config_t) && config->tls->cert_file != NULL &&
         config->tls->key_file != NULL && config->tls->ca_file != NULL &&
         config->tls->client_auth == TURBO_TLS_CLIENT_AUTH_REQUIRED &&
         tls_alpn_valid(config->tls) &&
         digest_string_valid(config->controller_tls_certificate_sha256) &&
         config->controller_certificate_serial != 0u && config->channel_capacity != 0u &&
         config->channel_retained_bytes != 0u && config->channel_max_payload != 0u &&
         config->max_commands_per_poll != 0u && provider_config_valid &&
         network_config_valid(config) &&
         durability_config_valid(config) && config->shutdown_drain_timeout_ms != 0u &&
         status_limits_valid(config) && config->now_ms != NULL &&
         (config->controller_permissions & MESH_CONTROL_PERMISSION_MANAGE) != 0u &&
         (config->controller_permissions & ~MESH_CONTROL_PERMISSION_KNOWN_V1) == 0u &&
         mesh_control_node_policy_validate_v1(&config->node_policy) == MESH_CONTROL_OK;
}

static int parse_size_query(const char *value, size_t *out_value) {
  size_t parsed = 0u;
  const unsigned char *cursor = (const unsigned char *)value;
  if (value == NULL || value[0] == '\0' || out_value == NULL)
    return 0;
  while (*cursor != '\0') {
    size_t digit;
    if (*cursor < '0' || *cursor > '9')
      return 0;
    digit = (size_t)(*cursor - '0');
    if (parsed > (SIZE_MAX - digit) / 10u)
      return 0;
    parsed = parsed * 10u + digit;
    ++cursor;
  }
  *out_value = parsed;
  return 1;
}

static int parse_u64_query(const char *value, uint64_t *out_value) {
  uint64_t parsed = 0u;
  const unsigned char *cursor = (const unsigned char *)value;
  if (value == NULL || value[0] == '\0' || out_value == NULL)
    return 0;
  while (*cursor != '\0') {
    uint64_t digit;
    if (*cursor < '0' || *cursor > '9')
      return 0;
    digit = (uint64_t)(*cursor - '0');
    if (parsed > (UINT64_MAX - digit) / 10u)
      return 0;
    parsed = parsed * 10u + digit;
    ++cursor;
  }
  *out_value = parsed;
  return 1;
}

static int parse_hex_id(const char *value, uint8_t output[MESH_CONTROL_ID_SIZE]) {
  size_t index;
  if (!value || !output || strlen(value) != MESH_CONTROL_ID_SIZE * 2u)
    return 0;
  for (index = 0u; index < MESH_CONTROL_ID_SIZE; ++index) {
    unsigned char high = (unsigned char)value[index * 2u];
    unsigned char low = (unsigned char)value[index * 2u + 1u];
    uint8_t high_value;
    uint8_t low_value;
    if (!((high >= '0' && high <= '9') || (high >= 'a' && high <= 'f')) ||
        !((low >= '0' && low <= '9') || (low >= 'a' && low <= 'f'))) {
      return 0;
    }
    high_value = high <= '9' ? (uint8_t)(high - '0') : (uint8_t)(high - 'a' + 10u);
    low_value = low <= '9' ? (uint8_t)(low - '0') : (uint8_t)(low - 'a' + 10u);
    output[index] = (uint8_t)((high_value << 4u) | low_value);
  }
  return 1;
}

static int agent_request_observe_authorized(mesh_control_agent_v1_t *agent, const Req *req) {
  char peer_certificate_sha256[CORO_TLS_PEER_CERT_SHA256_CAPACITY];
  if (agent == NULL || req == NULL)
    return 0;
  memset(peer_certificate_sha256, 0, sizeof(peer_certificate_sha256));
  return req_get_verified_tls_peer_certificate_sha256(req, peer_certificate_sha256) == 0 &&
         agent_authorize_transport(agent, peer_certificate_sha256) == MESH_CONTROL_OK &&
         (agent->config.controller_permissions & MESH_CONTROL_PERMISSION_OBSERVE) != 0u &&
         (agent->config.node_policy.local_permissions & MESH_CONTROL_PERMISSION_OBSERVE) != 0u;
}

static void mesh_control_agent_status_handler(Req *req, Res *res) {
  mesh_control_agent_v1_t *agent;
  const char *generation_text;
  const char *resource_offset_text;
  const char *operation_offset_text;
  uint64_t generation = 0u;
  size_t resource_offset = 0u;
  size_t operation_offset = 0u;
  size_t output_capacity;
  size_t output_size = 0u;
  uint8_t *output;
  mesh_control_result_t result;

  agent = req == NULL || req->app == NULL ? NULL
                                          : (mesh_control_agent_v1_t *)iris_app_lookup_rpc_context(
                                                req->app, MESH_CONTROL_AGENT_STATUS_PATH_V1);
  if (agent == NULL || agent->running == 0u) {
    reply(res, 503, "text/plain", NULL, 0u);
    return;
  }
  if (!agent_request_observe_authorized(agent, req)) {
    reply(res, 403, "text/plain", NULL, 0u);
    return;
  }
  generation_text = get_query(req, "generation");
  resource_offset_text = get_query(req, "resource_offset");
  operation_offset_text = get_query(req, "operation_offset");
  if ((generation_text != NULL && !parse_u64_query(generation_text, &generation)) ||
      (resource_offset_text != NULL && !parse_size_query(resource_offset_text, &resource_offset)) ||
      (operation_offset_text != NULL &&
       !parse_size_query(operation_offset_text, &operation_offset)) ||
      (generation == 0u && (resource_offset != 0u || operation_offset != 0u))) {
    reply(res, 400, "text/plain", NULL, 0u);
    return;
  }
  output_capacity =
      MESH_CONTROL_STATUS_HEADER_SIZE_V1 +
      agent->config.status_page_resource_limit * MESH_CONTROL_STATUS_RESOURCE_RECORD_SIZE_V1 +
      agent->config.status_page_operation_limit * MESH_CONTROL_STATUS_OPERATION_RECORD_SIZE_V1;
  output = (uint8_t *)malloc(output_capacity);
  if (output == NULL) {
    reply(res, 503, "text/plain", NULL, 0u);
    return;
  }
  result = mesh_control_agent_status_page_v1(agent, generation, resource_offset, operation_offset,
                                             output, output_capacity, &output_size);
  if (result == MESH_CONTROL_OK)
    reply(res, 200, MESH_CONTROL_STATUS_MIME_V1, output, output_size);
  else if (result == MESH_CONTROL_CONFLICT)
    reply(res, 409, "text/plain", NULL, 0u);
  else if (result == MESH_CONTROL_INVALID_ARG)
    reply(res, 400, "text/plain", NULL, 0u);
  else
    reply(res, 503, "text/plain", NULL, 0u);
  free(output);
}

static void mesh_control_agent_events_handler(Req *req, Res *res) {
  mesh_control_agent_v1_t *agent;
  const char *cursor_text;
  uint64_t cursor = 0u;
  size_t output_capacity;
  size_t output_size = 0u;
  uint8_t *output;
  mesh_control_result_t result;

  agent = req == NULL || req->app == NULL ? NULL
                                          : (mesh_control_agent_v1_t *)iris_app_lookup_rpc_context(
                                                req->app, MESH_CONTROL_AGENT_EVENTS_PATH_V1);
  if (agent == NULL || agent->running == 0u) {
    reply(res, 503, "text/plain", NULL, 0u);
    return;
  }
  if (!agent_request_observe_authorized(agent, req)) {
    reply(res, 403, "text/plain", NULL, 0u);
    return;
  }
  cursor_text = get_query(req, "cursor");
  if (cursor_text != NULL && !parse_u64_query(cursor_text, &cursor)) {
    reply(res, 400, "text/plain", NULL, 0u);
    return;
  }
  output_capacity = MESH_CONTROL_EVENT_HEADER_SIZE_V1 +
                    agent->config.status_event_limit * MESH_CONTROL_EVENT_RECORD_SIZE_V1;
  output = (uint8_t *)malloc(output_capacity);
  if (output == NULL) {
    reply(res, 503, "text/plain", NULL, 0u);
    return;
  }
  result = mesh_control_agent_event_page_v1(agent, cursor, output, output_capacity, &output_size);
  if (result == MESH_CONTROL_OK)
    reply(res, 200, MESH_CONTROL_EVENT_MIME_V1, output, output_size);
  else if (result == MESH_CONTROL_CONFLICT)
    reply(res, 409, "text/plain", NULL, 0u);
  else if (result == MESH_CONTROL_INVALID_ARG)
    reply(res, 400, "text/plain", NULL, 0u);
  else
    reply(res, 503, "text/plain", NULL, 0u);
  free(output);
}

static void mesh_control_agent_receipts_handler(Req *req, Res *res) {
  mesh_control_agent_v1_t *agent;
  const char *operation_id_text;
  uint8_t operation_id[MESH_CONTROL_ID_SIZE];
  uint8_t output[MESH_CONTROL_RECEIPT_SIZE_V1];
  size_t output_size = 0u;
  mesh_control_result_t result;

  agent = req == NULL || req->app == NULL ? NULL
                                          : (mesh_control_agent_v1_t *)iris_app_lookup_rpc_context(
                                                req->app, MESH_CONTROL_AGENT_RECEIPTS_PATH_V1);
  if (!agent || !agent->running) {
    reply(res, 503, "text/plain", NULL, 0u);
    return;
  }
  if (!agent_request_observe_authorized(agent, req)) {
    reply(res, 403, "text/plain", NULL, 0u);
    return;
  }
  operation_id_text = get_query(req, "operation_id");
  if (!parse_hex_id(operation_id_text, operation_id)) {
    reply(res, 400, "text/plain", NULL, 0u);
    return;
  }
  result = mesh_control_agent_receipt_v1(agent, operation_id, output, &output_size);
  if (result == MESH_CONTROL_OK)
    reply(res, 200, MESH_CONTROL_RECEIPT_MIME_V1, output, output_size);
  else if (result == MESH_CONTROL_EMPTY)
    reply(res, 404, "text/plain", NULL, 0u);
  else if (result == MESH_CONTROL_INVALID_ARG)
    reply(res, 400, "text/plain", NULL, 0u);
  else
    reply(res, 503, "text/plain", NULL, 0u);
}

static mesh_control_result_t
agent_authorize_transport(void *context,
                          const char peer_certificate_sha256[CORO_TLS_PEER_CERT_SHA256_CAPACITY]) {
  mesh_control_agent_v1_t *agent = (mesh_control_agent_v1_t *)context;
  if (agent == NULL || peer_certificate_sha256 == NULL)
    return MESH_CONTROL_INVALID_ARG;
  return strcmp(agent->controller_tls_certificate_sha256, peer_certificate_sha256) == 0
             ? MESH_CONTROL_OK
             : MESH_CONTROL_CONFLICT;
}

static mesh_control_result_t
agent_authorize_message(void *context, const mesh_mgmt_verified_envelope_v1_t *verified,
                        const mesh_control_envelope_v1_t *envelope, const uint8_t *body,
                        size_t body_size) {
  mesh_control_agent_v1_t *agent = (mesh_control_agent_v1_t *)context;
  uint64_t required_permission;
  uint64_t effective_permissions;
  mesh_control_function_spec_v1_t function_spec;
  uint64_t now_ms;

  (void)verified;
  if (agent == NULL || envelope == NULL || (body_size != 0u && body == NULL))
    return MESH_CONTROL_INVALID_ARG;
  now_ms = agent->config.now_ms(agent->config.now_context);
  if (memcmp(envelope->mesh_id, agent->config.owner.mesh_id, sizeof(envelope->mesh_id)) != 0 ||
      memcmp(envelope->target_node_id, agent->config.owner.node_id,
             sizeof(envelope->target_node_id)) != 0 ||
      memcmp(envelope->origin_principal, agent->config.owner.replay_binding.principal_key,
             sizeof(envelope->origin_principal)) != 0 ||
      memcmp(envelope->origin_node_id, agent->config.controller_node_id,
             sizeof(envelope->origin_node_id)) != 0 ||
      envelope->certificate_serial != agent->config.controller_certificate_serial ||
      now_ms < envelope->issued_at_ms || now_ms >= envelope->expires_at_ms) {
    return MESH_CONTROL_CONFLICT;
  }
  required_permission = envelope->kind == MESH_CONTROL_MESSAGE_INTENT
                            ? MESH_CONTROL_PERMISSION_MANAGE
                            : MESH_CONTROL_PERMISSION_OBSERVE;
  if ((agent->config.controller_permissions & required_permission) == 0u ||
      (agent->config.node_policy.local_permissions & required_permission) == 0u) {
    return MESH_CONTROL_CONFLICT;
  }
  if (envelope->kind == MESH_CONTROL_MESSAGE_INTENT &&
      envelope->resource_kind == MESH_CONTROL_RESOURCE_FUNCTION) {
    mesh_control_result_t result = mesh_control_node_policy_authorize_function_intent_v1(
        &agent->config.node_policy, envelope, body, body_size, agent->config.controller_permissions,
        &effective_permissions, &function_spec);
    if (result != MESH_CONTROL_OK || function_spec.schema_version == 0u)
      return result;
    if (!agent->function_reconciler_initialized)
      return MESH_CONTROL_CONFLICT;
    return mesh_control_reconciler_has_provider_v1(
        &agent->function_reconciler, function_spec.provider_id, function_spec.runtime);
  }
  if (envelope->kind == MESH_CONTROL_MESSAGE_INTENT &&
      envelope->resource_kind == MESH_CONTROL_RESOURCE_NETWORK) {
    mesh_control_intent_view_v1_t intent;
    mesh_control_network_document_v1_t document;
    uint8_t resource_id[MESH_CONTROL_DIGEST_SIZE];
    mesh_control_result_t result;
    if (!agent_network_enabled(agent))
      return MESH_CONTROL_CONFLICT;
    result = mesh_control_intent_decode_v1(body, body_size, &intent);
    if (result != MESH_CONTROL_OK)
      return result;
    if (intent.action == MESH_CONTROL_DESIRED_DELETE)
      return intent.document_size == 0u ? MESH_CONTROL_OK
                                        : MESH_CONTROL_INVALID_ARG;
    result = mesh_control_network_document_decode_v1(
        intent.document, intent.document_size, &document);
    if (result != MESH_CONTROL_OK)
      return result;
    result = mesh_network_resource_id_v1(document.mesh_id,
                                         document.network_uid, resource_id);
    if (result != MESH_CONTROL_OK)
      return result;
    return memcmp(document.mesh_id, envelope->mesh_id,
                  sizeof(document.mesh_id)) == 0 &&
                   memcmp(document.managed_node_id, envelope->target_node_id,
                          sizeof(document.managed_node_id)) == 0 &&
                   memcmp(resource_id, envelope->resource_id,
                          sizeof(resource_id)) == 0 &&
                   document.generation == envelope->epoch
               ? MESH_CONTROL_OK
               : MESH_CONTROL_CONFLICT;
  }
  return MESH_CONTROL_OK;
}

static size_t agent_find_network_record(
    const mesh_control_agent_v1_t *agent,
    const uint8_t resource_id[MESH_CONTROL_DIGEST_SIZE]) {
  size_t index;
  for (index = 0u; index < agent->network_reconciler.count; ++index) {
    if (memcmp(agent->network_reconciler.records[index].resource_id,
               resource_id, MESH_CONTROL_DIGEST_SIZE) == 0)
      return index;
  }
  return SIZE_MAX;
}

static void agent_make_operation_result(
    const mesh_control_operation_v1_t *operation, uint16_t outcome,
    mesh_control_wal_operation_result_v1_t *out_result) {
  memset(out_result, 0, sizeof(*out_result));
  memcpy(out_result->operation_id, operation->operation_id,
         sizeof(out_result->operation_id));
  out_result->resource_kind = operation->resource_kind;
  out_result->action = operation->action;
  out_result->outcome = outcome;
  memcpy(out_result->resource_id, operation->resource_id,
         sizeof(out_result->resource_id));
  out_result->desired_epoch = operation->desired_epoch;
}

static mesh_control_result_t agent_apply_operation_result(
    mesh_control_agent_v1_t *agent,
    const mesh_control_wal_operation_result_v1_t *operation_result,
    uint64_t now_ms) {
  mesh_control_operation_v1_t operation;
  uint8_t digest[MESH_CONTROL_DIGEST_SIZE] = {0u};
  mesh_control_result_t result;
  if (!agent || !operation_result)
    return MESH_CONTROL_INVALID_ARG;
  result = mesh_control_state_get_operation_v1(
      mesh_control_owner_state_v1(&agent->owner),
      operation_result->operation_id, &operation);
  if (result != MESH_CONTROL_OK ||
      operation.resource_kind != operation_result->resource_kind ||
      operation.action != operation_result->action ||
      operation.desired_epoch != operation_result->desired_epoch ||
      memcmp(operation.resource_id, operation_result->resource_id,
             sizeof(operation.resource_id)) != 0)
    return MESH_CONTROL_INVALID_STATE;
  if (operation_result->outcome == MESH_CONTROL_WAL_OPERATION_FAILED)
    return mesh_control_state_transition_operation_v1(
        mesh_control_owner_state_v1(&agent->owner), operation.operation_id,
        MESH_CONTROL_OPERATION_FAILED, now_ms);
  if (operation_result->outcome != MESH_CONTROL_WAL_OPERATION_SUCCEEDED)
    return MESH_CONTROL_INVALID_STATE;
  if (operation.action == MESH_CONTROL_DESIRED_APPLY)
    memcpy(digest, operation.desired_digest, sizeof(digest));
  return mesh_control_state_observe_v1(
      mesh_control_owner_state_v1(&agent->owner), operation.resource_kind,
      operation.resource_id, operation.desired_epoch,
      operation.action == MESH_CONTROL_DESIRED_APPLY
          ? MESH_CONTROL_PRESENCE_PRESENT
          : MESH_CONTROL_PRESENCE_ABSENT,
      digest, now_ms);
}

static mesh_control_result_t agent_execute_network_operation(
    mesh_control_agent_v1_t *agent,
    const mesh_control_operation_v1_t *operation, uint16_t *out_outcome) {
  mesh_control_resource_status_v1_t status;
  const uint8_t *document = NULL;
  size_t document_size = 0u;
  size_t record_index;
  uint64_t applied_generation = 0u;
  mesh_control_result_t result;
  if (!agent || !operation || !out_outcome ||
      operation->resource_kind != MESH_CONTROL_RESOURCE_NETWORK ||
      !agent->network_reconciler_initialized)
    return MESH_CONTROL_INVALID_ARG;
  *out_outcome = MESH_CONTROL_WAL_OPERATION_FAILED;
  result = mesh_control_state_get_resource_v1(
      mesh_control_owner_state_v1(&agent->owner), operation->resource_kind,
      operation->resource_id, &status);
  if (result != MESH_CONTROL_OK)
    return MESH_CONTROL_INVALID_STATE;
  if (status.desired_epoch != operation->desired_epoch ||
      (operation->action == MESH_CONTROL_DESIRED_APPLY &&
       status.desired_presence != MESH_CONTROL_PRESENCE_PRESENT) ||
      (operation->action == MESH_CONTROL_DESIRED_DELETE &&
       status.desired_presence != MESH_CONTROL_PRESENCE_ABSENT))
    return MESH_CONTROL_OK;

  record_index = agent_find_network_record(agent, operation->resource_id);
  if (operation->action == MESH_CONTROL_DESIRED_DELETE) {
    if (record_index == SIZE_MAX) {
      *out_outcome = MESH_CONTROL_WAL_OPERATION_SUCCEEDED;
      return MESH_CONTROL_OK;
    }
    result = mesh_network_reconciler_submit_v1(
        &agent->network_reconciler, operation->resource_id,
        MESH_CONTROL_DESIRED_DELETE,
        agent->network_reconciler.records[record_index].generation, NULL, 0u,
        agent->config.shutdown_drain_timeout_ms, &applied_generation);
  } else {
    mesh_control_network_document_v1_t decoded;
    result = mesh_control_state_get_desired_document_v1(
        mesh_control_owner_state_v1(&agent->owner), operation->resource_kind,
        operation->resource_id, &document, &document_size);
    if (result != MESH_CONTROL_OK ||
        mesh_control_network_document_decode_v1(document, document_size,
                                                &decoded) != MESH_CONTROL_OK)
      return MESH_CONTROL_INVALID_STATE;
    if (record_index != SIZE_MAX &&
        agent->network_reconciler.records[record_index].generation ==
            decoded.generation) {
      *out_outcome = MESH_CONTROL_WAL_OPERATION_SUCCEEDED;
      return MESH_CONTROL_OK;
    }
    if (record_index != SIZE_MAX &&
        agent->network_reconciler.records[record_index].generation >
            decoded.generation)
      return MESH_CONTROL_OK;
    result = mesh_network_reconciler_submit_v1(
        &agent->network_reconciler, operation->resource_id,
        MESH_CONTROL_DESIRED_APPLY,
        record_index == SIZE_MAX
            ? 0u
            : agent->network_reconciler.records[record_index].generation,
        document, document_size, 0u, &applied_generation);
  }
  if (result == MESH_CONTROL_OK)
    *out_outcome = MESH_CONTROL_WAL_OPERATION_SUCCEEDED;
  return MESH_CONTROL_OK;
}

static mesh_control_result_t agent_start_network_provider_operation(
    mesh_control_agent_v1_t *agent,
    const mesh_control_operation_v1_t *operation) {
  mesh_control_network_provider_request_v1_t request;
  mesh_control_resource_status_v1_t status;
  const uint8_t *document = NULL;
  size_t document_size = 0u;
  mesh_control_result_t result;
  if (!agent || !operation || !agent->network_provider_initialized ||
      operation->resource_kind != MESH_CONTROL_RESOURCE_NETWORK)
    return MESH_CONTROL_INVALID_ARG;
  if (agent->network_provider_active)
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  result = mesh_control_state_get_resource_v1(
      mesh_control_owner_state_v1(&agent->owner), operation->resource_kind,
      operation->resource_id, &status);
  if (result != MESH_CONTROL_OK ||
      status.desired_epoch != operation->desired_epoch)
    return MESH_CONTROL_INVALID_STATE;
  if (operation->action == MESH_CONTROL_DESIRED_APPLY) {
    result = mesh_control_state_get_desired_document_v1(
        mesh_control_owner_state_v1(&agent->owner), operation->resource_kind,
        operation->resource_id, &document, &document_size);
    if (result != MESH_CONTROL_OK)
      return result;
  }
  memset(&request, 0, sizeof(request));
  request.operation = *operation;
  request.precondition_epoch =
      status.observed_presence == MESH_CONTROL_PRESENCE_PRESENT
          ? status.observed_epoch
          : 0u;
  request.document = document;
  request.document_size = document_size;
  result = agent->network_provider.ops.try_start(
      agent->network_provider.context, &request);
  if (result == MESH_CONTROL_OK) {
    agent->network_active_operation = *operation;
    agent->network_provider_active = 1u;
  }
  return result;
}

static int agent_network_operation_is_pending(
    const mesh_control_operation_v1_t *operation) {
  return operation->resource_kind == MESH_CONTROL_RESOURCE_NETWORK &&
         (operation->state == MESH_CONTROL_OPERATION_ACCEPTED ||
          operation->state == MESH_CONTROL_OPERATION_RUNNING);
}

static mesh_control_result_t agent_snapshot_network_state(
    mesh_control_agent_v1_t *agent,
    mesh_control_snapshot_page_info_v1_t *out_page) {
  return mesh_control_state_snapshot_page_v1(
      mesh_control_owner_state_v1(&agent->owner), 0u, 0u,
      agent->network_resource_scan, agent->config.owner.state.resource_capacity,
      0u, agent->network_operation_scan,
      agent->config.owner.state.operation_capacity, out_page);
}

static mesh_control_result_t agent_restore_network_runtime(
    mesh_control_agent_v1_t *agent) {
  mesh_control_snapshot_page_info_v1_t page;
  size_t resource_index;
  mesh_control_result_t result;
  if (!agent || !agent_network_enabled(agent))
    return agent ? MESH_CONTROL_OK : MESH_CONTROL_INVALID_ARG;
  result = agent_snapshot_network_state(agent, &page);
  if (result != MESH_CONTROL_OK)
    return result;
  for (resource_index = 0u; resource_index < page.operation_count;
       ++resource_index) {
    if (agent_network_operation_is_pending(
            &agent->network_operation_scan[resource_index])) {
      agent->network_recovery_pending = 1u;
      break;
    }
  }
  if (agent->network_provider_initialized) {
    for (resource_index = 0u; resource_index < page.resource_count;
         ++resource_index) {
      const mesh_control_resource_status_v1_t *status =
          &agent->network_resource_scan[resource_index];
      if (status->resource_kind == MESH_CONTROL_RESOURCE_NETWORK &&
          status->desired_presence == MESH_CONTROL_PRESENCE_PRESENT &&
          status->observed_presence == MESH_CONTROL_PRESENCE_PRESENT &&
          status->desired_epoch == status->observed_epoch &&
          memcmp(status->desired_digest, status->observed_digest,
                 sizeof(status->desired_digest)) == 0) {
        agent->network_provider_restore_pending = 1u;
        agent->network_restore_scan_index = 0u;
        break;
      }
    }
    return MESH_CONTROL_OK;
  }
  for (resource_index = 0u; resource_index < page.resource_count;
       ++resource_index) {
    const mesh_control_resource_status_v1_t *status =
        &agent->network_resource_scan[resource_index];
    const uint8_t *document = NULL;
    size_t document_size = 0u;
    uint64_t applied_generation = 0u;
    int restore = 0;
    size_t operation_index;
    if (status->resource_kind != MESH_CONTROL_RESOURCE_NETWORK ||
        status->desired_presence != MESH_CONTROL_PRESENCE_PRESENT)
      continue;
    restore = status->observed_epoch == status->desired_epoch &&
              status->observed_presence == MESH_CONTROL_PRESENCE_PRESENT &&
              memcmp(status->observed_digest, status->desired_digest,
                     sizeof(status->desired_digest)) == 0;
    for (operation_index = 0u; !restore &&
                               operation_index < page.operation_count;
         ++operation_index) {
      const mesh_control_operation_v1_t *operation =
          &agent->network_operation_scan[operation_index];
      restore = agent_network_operation_is_pending(operation) &&
                operation->desired_epoch == status->desired_epoch &&
                memcmp(operation->resource_id, status->resource_id,
                       sizeof(status->resource_id)) == 0;
    }
    if (!restore)
      continue;
    result = mesh_control_state_get_desired_document_v1(
        mesh_control_owner_state_v1(&agent->owner), status->resource_kind,
        status->resource_id, &document, &document_size);
    if (result != MESH_CONTROL_OK ||
        mesh_network_reconciler_submit_v1(
            &agent->network_reconciler, status->resource_id,
            MESH_CONTROL_DESIRED_APPLY, 0u, document, document_size, 0u,
            &applied_generation) != MESH_CONTROL_OK)
      return MESH_CONTROL_INVALID_STATE;
  }
  return MESH_CONTROL_OK;
}

static mesh_control_result_t agent_find_pending_network_operation(
    mesh_control_agent_v1_t *agent,
    mesh_control_operation_v1_t *out_operation) {
  mesh_control_snapshot_page_info_v1_t page;
  size_t index;
  mesh_control_result_t result;
  if (!agent || !out_operation || !agent_network_enabled(agent))
    return MESH_CONTROL_INVALID_ARG;
  result = agent_snapshot_network_state(agent, &page);
  if (result != MESH_CONTROL_OK)
    return result;
  for (index = 0u; index < page.operation_count; ++index) {
    if (agent_network_operation_is_pending(
            &agent->network_operation_scan[index])) {
      *out_operation = agent->network_operation_scan[index];
      return MESH_CONTROL_OK;
    }
  }
  return MESH_CONTROL_EMPTY;
}

static mesh_control_result_t agent_peek_network_provider_result(
    mesh_control_agent_v1_t *agent,
    mesh_control_wal_operation_result_v1_t *out_result) {
  mesh_control_network_provider_completion_v1_t completion;
  mesh_control_result_t result;
  if (!agent || !out_result || !agent->network_provider_initialized)
    return MESH_CONTROL_INVALID_ARG;
  if (!agent->network_provider_active)
    return MESH_CONTROL_EMPTY;
  result = agent->network_provider.ops.try_peek_completion(
      agent->network_provider.context, &completion);
  if (result != MESH_CONTROL_OK)
    return result;
  if (memcmp(completion.operation_id,
             agent->network_active_operation.operation_id,
             sizeof(completion.operation_id)) != 0 ||
      (completion.state != MESH_CONTROL_NETWORK_PROVIDER_COMPLETED &&
       completion.state != MESH_CONTROL_NETWORK_PROVIDER_FAILED))
    return MESH_CONTROL_CONFLICT;
  agent_make_operation_result(
      &agent->network_active_operation,
      completion.state == MESH_CONTROL_NETWORK_PROVIDER_COMPLETED
          ? MESH_CONTROL_WAL_OPERATION_SUCCEEDED
          : MESH_CONTROL_WAL_OPERATION_FAILED,
      out_result);
  return MESH_CONTROL_OK;
}

static mesh_control_result_t agent_make_network_restore_operation(
    const mesh_control_resource_status_v1_t *status,
    mesh_control_operation_v1_t *out_operation) {
  static const uint8_t request_domain[] =
      "mesh-network-restore-request/v1";
  static const uint8_t operation_domain[] =
      "mesh-network-restore-operation/v1";
  uint8_t input[sizeof(operation_domain) - 1u +
                MESH_CONTROL_DIGEST_SIZE + 8u];
  uint8_t digest[MESH_CONTROL_DIGEST_SIZE];
  size_t domain_size;
  size_t index;
  if (!status || !out_operation || status->desired_epoch == 0u)
    return MESH_CONTROL_INVALID_ARG;
  memset(out_operation, 0, sizeof(*out_operation));
  out_operation->resource_kind = MESH_CONTROL_RESOURCE_NETWORK;
  out_operation->action = MESH_CONTROL_DESIRED_APPLY;
  out_operation->desired_epoch = status->desired_epoch;
  memcpy(out_operation->resource_id, status->resource_id,
         sizeof(out_operation->resource_id));
  memcpy(out_operation->desired_digest, status->desired_digest,
         sizeof(out_operation->desired_digest));

  domain_size = sizeof(operation_domain) - 1u;
  memcpy(input, operation_domain, domain_size);
  memcpy(input + domain_size, status->resource_id,
         MESH_CONTROL_DIGEST_SIZE);
  for (index = 0u; index < 8u; ++index)
    input[domain_size + MESH_CONTROL_DIGEST_SIZE + index] =
        (uint8_t)(status->desired_epoch >> (56u - index * 8u));
  if (turbo_crypto_sha256(input,
                          domain_size + MESH_CONTROL_DIGEST_SIZE + 8u,
                          digest) != TURBO_CRYPTO_OK)
    return MESH_CONTROL_INVALID_STATE;
  memcpy(out_operation->operation_id, digest,
         sizeof(out_operation->operation_id));

  domain_size = sizeof(request_domain) - 1u;
  memcpy(input, request_domain, domain_size);
  memcpy(input + domain_size, status->resource_id,
         MESH_CONTROL_DIGEST_SIZE);
  for (index = 0u; index < 8u; ++index)
    input[domain_size + MESH_CONTROL_DIGEST_SIZE + index] =
        (uint8_t)(status->desired_epoch >> (56u - index * 8u));
  if (turbo_crypto_sha256(input,
                          domain_size + MESH_CONTROL_DIGEST_SIZE + 8u,
                          digest) != TURBO_CRYPTO_OK) {
    memset(input, 0, sizeof(input));
    return MESH_CONTROL_INVALID_STATE;
  }
  memcpy(out_operation->request_id, digest,
         sizeof(out_operation->request_id));
  memset(digest, 0, sizeof(digest));
  memset(input, 0, sizeof(input));
  return MESH_CONTROL_OK;
}

static mesh_control_result_t agent_poll_network_provider_restore(
    mesh_control_agent_v1_t *agent, size_t *out_progress) {
  mesh_control_network_provider_completion_v1_t completion;
  mesh_control_network_provider_request_v1_t request;
  mesh_control_resource_status_v1_t *status;
  const uint8_t *document = NULL;
  size_t document_size = 0u;
  mesh_control_result_t result;
  if (!agent || !out_progress || !agent->network_provider_initialized)
    return MESH_CONTROL_INVALID_ARG;
  *out_progress = 0u;
  if (agent->network_provider_restore_active) {
    result = agent->network_provider.ops.try_peek_completion(
        agent->network_provider.context, &completion);
    if (result == MESH_CONTROL_EMPTY)
      return MESH_CONTROL_OK;
    if (result != MESH_CONTROL_OK ||
        memcmp(completion.operation_id,
               agent->network_active_operation.operation_id,
               sizeof(completion.operation_id)) != 0)
      return result == MESH_CONTROL_OK ? MESH_CONTROL_CONFLICT : result;
    result = agent->network_provider.ops.ack_completion(
        agent->network_provider.context,
        agent->network_active_operation.operation_id);
    if (result != MESH_CONTROL_OK)
      return result;
    memset(&agent->network_active_operation, 0,
           sizeof(agent->network_active_operation));
    agent->network_provider_active = 0u;
    agent->network_provider_restore_active = 0u;
    *out_progress = 1u;
    if (completion.state != MESH_CONTROL_NETWORK_PROVIDER_COMPLETED)
      return MESH_CONTROL_INVALID_STATE;
  }
  while (agent->network_restore_scan_index <
         agent->config.owner.state.resource_capacity) {
    status = &agent->network_resource_scan[
        agent->network_restore_scan_index++];
    if (status->resource_kind != MESH_CONTROL_RESOURCE_NETWORK ||
        status->desired_presence != MESH_CONTROL_PRESENCE_PRESENT ||
        status->observed_presence != MESH_CONTROL_PRESENCE_PRESENT ||
        status->desired_epoch != status->observed_epoch ||
        memcmp(status->desired_digest, status->observed_digest,
               sizeof(status->desired_digest)) != 0)
      continue;
    result = mesh_control_state_get_desired_document_v1(
        mesh_control_owner_state_v1(&agent->owner), status->resource_kind,
        status->resource_id, &document, &document_size);
    if (result != MESH_CONTROL_OK)
      return result;
    memset(&request, 0, sizeof(request));
    result = agent_make_network_restore_operation(status,
                                                  &request.operation);
    if (result != MESH_CONTROL_OK)
      return result;
    request.document = document;
    request.document_size = document_size;
    result = agent->network_provider.ops.try_start(
        agent->network_provider.context, &request);
    if (result == MESH_CONTROL_RESOURCE_EXHAUSTED ||
        result == MESH_CONTROL_PROVIDER_UNAVAILABLE ||
        result == MESH_CONTROL_TIMEOUT) {
      --agent->network_restore_scan_index;
      return MESH_CONTROL_OK;
    }
    if (result != MESH_CONTROL_OK)
      return result;
    agent->network_active_operation = request.operation;
    agent->network_provider_active = 1u;
    agent->network_provider_restore_active = 1u;
    *out_progress += 1u;
    return MESH_CONTROL_OK;
  }
  agent->network_provider_restore_pending = 0u;
  return MESH_CONTROL_OK;
}

static mesh_control_result_t agent_poll_volatile_network_provider(
    mesh_control_agent_v1_t *agent, uint64_t now_ms, size_t *out_progress) {
  mesh_control_wal_operation_result_v1_t operation_result;
  mesh_control_operation_v1_t operation;
  mesh_control_result_t result;
  if (!agent || !out_progress || !agent->network_provider_initialized)
    return MESH_CONTROL_INVALID_ARG;
  *out_progress = 0u;
  if (agent->network_provider_active) {
    result = agent_peek_network_provider_result(agent, &operation_result);
    if (result == MESH_CONTROL_EMPTY)
      return MESH_CONTROL_OK;
    if (result != MESH_CONTROL_OK)
      return result;
    result = agent_apply_operation_result(agent, &operation_result, now_ms);
    if (result != MESH_CONTROL_OK)
      return result;
    result = agent->network_provider.ops.ack_completion(
        agent->network_provider.context,
        agent->network_active_operation.operation_id);
    if (result != MESH_CONTROL_OK)
      return result;
    memset(&agent->network_active_operation, 0,
           sizeof(agent->network_active_operation));
    agent->network_provider_active = 0u;
    *out_progress = 1u;
  }
  if (agent->network_recovery_pending &&
      !agent->network_provider_active) {
    result = agent_find_pending_network_operation(agent, &operation);
    if (result == MESH_CONTROL_EMPTY) {
      agent->network_recovery_pending = 0u;
      return MESH_CONTROL_OK;
    }
    if (result != MESH_CONTROL_OK)
      return result;
    result = agent_start_network_provider_operation(agent, &operation);
    if (result == MESH_CONTROL_OK) {
      *out_progress += 1u;
      return MESH_CONTROL_OK;
    }
    if (result == MESH_CONTROL_RESOURCE_EXHAUSTED ||
        result == MESH_CONTROL_PROVIDER_UNAVAILABLE ||
        result == MESH_CONTROL_TIMEOUT)
      return MESH_CONTROL_OK;
    return result;
  }
  return MESH_CONTROL_OK;
}

static void cleanup_started_agent(mesh_control_agent_v1_t *agent) {
  if (agent->listener != NULL) {
    coro_socket_destroy(agent->listener);
    agent->listener = NULL;
  }
  if (agent->app != NULL) {
    (void)iris_app_unbind_rpc_context(agent->app, MESH_CONTROL_AGENT_STATUS_PATH_V1, agent);
    (void)iris_app_unbind_rpc_context(agent->app, MESH_CONTROL_AGENT_EVENTS_PATH_V1, agent);
    (void)iris_app_unbind_rpc_context(agent->app, MESH_CONTROL_AGENT_RECEIPTS_PATH_V1, agent);
  }
  mesh_control_iris_destroy_v1(&agent->iris);
  if (agent->wal_worker_initialized) {
    mesh_control_wal_worker_destroy_v1(&agent->wal_worker);
    agent->wal_worker_initialized = 0u;
  }
  mesh_control_reconciler_destroy_v1(&agent->function_reconciler);
  agent->function_reconciler_initialized = 0u;
  if (agent->network_reconciler_initialized) {
    (void)mesh_network_reconciler_close_v1(
        &agent->network_reconciler,
        agent->config.shutdown_drain_timeout_ms);
    mesh_network_reconciler_destroy_v1(&agent->network_reconciler);
    agent->network_reconciler_initialized = 0u;
  }
  free(agent->network_resource_scan);
  agent->network_resource_scan = NULL;
  free(agent->network_operation_scan);
  agent->network_operation_scan = NULL;
  mesh_control_owner_destroy_v1(&agent->owner);
  mesh_control_channel_destroy_v1(&agent->inbound);
  if (agent->app != NULL) {
    iris_app_destroy(agent->app);
    agent->app = NULL;
  }
  if (agent->context != NULL) {
    coro_context_stop(agent->context);
    coro_context_destroy(agent->context);
    agent->context = NULL;
  }
}

static int agent_recover_wal_record(void *context,
                                    const mesh_control_wal_record_view_v1_t *record) {
  mesh_control_agent_v1_t *agent = (mesh_control_agent_v1_t *)context;
  mesh_mgmt_verified_envelope_v1_t verified;
  mesh_control_envelope_v1_t envelope;
  mesh_control_owner_prepared_v1_t prepared;
  const uint8_t *body = NULL;
  size_t body_size = 0u;

  if (!agent || !record)
    return -1;
  if (record->record_type == MESH_CONTROL_WAL_RECORD_OPERATION_RESULT) {
    mesh_control_result_t result = agent_apply_operation_result(
        agent, &record->operation_result, record->accepted_at_ms);
    return result == MESH_CONTROL_OK && mesh_control_owner_advance_log_index_v1(
                                            &agent->owner, record->log_index) == MESH_CONTROL_OK
               ? 0
               : -1;
  }
  if (record->record_type != MESH_CONTROL_WAL_RECORD_SIGNED_INTENT ||
      mesh_mgmt_envelope_verify_v1(record->signed_frame, record->signed_frame_size, &verified) !=
          MESH_MGMT_ENVELOPE_OK ||
      mesh_control_mmp_payload_decode_v1(&verified, &envelope, &body, &body_size) !=
          MESH_CONTROL_MMP_OK ||
      mesh_control_channel_try_push_signed_v1(&agent->inbound, &envelope, body, body_size,
                                              record->signed_frame,
                                              record->signed_frame_size) != MESH_CONTROL_OK ||
      mesh_control_owner_prepare_next_v1(&agent->owner, record->accepted_at_ms, &prepared) !=
          MESH_CONTROL_OK ||
      prepared.expected_log_index != record->log_index ||
      mesh_control_owner_commit_prepared_v1(&agent->owner, record->log_index, NULL) !=
          MESH_CONTROL_OK) {
    return -1;
  }
  return 0;
}

static mesh_control_result_t agent_recover_function_operations(mesh_control_agent_v1_t *agent) {
  mesh_control_state_usage_v1_t usage;
  mesh_control_snapshot_page_info_v1_t page;
  mesh_control_operation_v1_t *operations = NULL;
  mesh_control_result_t result;
  size_t index;

  if (!agent)
    return MESH_CONTROL_INVALID_ARG;
  if (!agent->function_reconciler_initialized)
    return MESH_CONTROL_OK;
  result = mesh_control_state_get_usage_v1(mesh_control_owner_state_v1(&agent->owner), &usage);
  if (result != MESH_CONTROL_OK)
    return result;
  if (usage.operation_count == 0u)
    return MESH_CONTROL_OK;
  operations = (mesh_control_operation_v1_t *)calloc(usage.operation_count, sizeof(*operations));
  if (!operations)
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  result =
      mesh_control_state_snapshot_page_v1(mesh_control_owner_state_v1(&agent->owner), 0u, 0u, NULL,
                                          0u, 0u, operations, usage.operation_count, &page);
  if (result != MESH_CONTROL_OK || page.operation_count != usage.operation_count) {
    free(operations);
    return result == MESH_CONTROL_OK ? MESH_CONTROL_INVALID_STATE : result;
  }
  for (index = 0u; index < page.operation_count; ++index) {
    const uint8_t *document = NULL;
    size_t document_size = 0u;
    if (operations[index].resource_kind != MESH_CONTROL_RESOURCE_FUNCTION ||
        (operations[index].state != MESH_CONTROL_OPERATION_ACCEPTED &&
         operations[index].state != MESH_CONTROL_OPERATION_RUNNING)) {
      continue;
    }
    result = mesh_control_state_get_desired_document_v1(
        mesh_control_owner_state_v1(&agent->owner), operations[index].resource_kind,
        operations[index].resource_id, &document, &document_size);
    if (result != MESH_CONTROL_OK ||
        mesh_control_reconciler_enqueue_v1(&agent->function_reconciler, &operations[index],
                                           document, document_size) != MESH_CONTROL_OK) {
      free(operations);
      return MESH_CONTROL_INVALID_STATE;
    }
  }
  free(operations);
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_agent_start_v1(mesh_control_agent_v1_t *agent,
                                                  const mesh_control_agent_config_v1_t *config) {
  mesh_control_iris_config_v1_t iris_config;
  mesh_control_wal_worker_config_v1_t wal_worker_config;

  if (agent == NULL || agent->running != 0u || !config_valid(config))
    return MESH_CONTROL_INVALID_ARG;
  memset(agent, 0, sizeof(*agent));
  agent->config = *config;
  memcpy(agent->host, config->host, strlen(config->host) + 1u);
  memcpy(agent->controller_tls_certificate_sha256, config->controller_tls_certificate_sha256,
         CORO_TLS_PEER_CERT_SHA256_CAPACITY);
  agent->config.host = agent->host;
  agent->config.controller_tls_certificate_sha256 = agent->controller_tls_certificate_sha256;

  if (mesh_control_channel_init_v1(&agent->inbound, config->channel_capacity,
                                   config->channel_retained_bytes,
                                   config->channel_max_payload) != MESH_CONTROL_OK)
    goto failed;
  if (mesh_control_owner_init_v1(&agent->owner, &agent->inbound, &config->owner) != MESH_CONTROL_OK)
    goto failed;
  if (config->function_reconciler.provider_count != 0u) {
    if (mesh_control_reconciler_init_v1(&agent->function_reconciler,
                                        &config->function_reconciler) != MESH_CONTROL_OK)
      goto failed;
    agent->function_reconciler_initialized = 1u;
  }
  if (config->network_fabric != NULL || config->network_provider != NULL) {
    agent->network_resource_scan =
        (mesh_control_resource_status_v1_t *)calloc(
            config->owner.state.resource_capacity,
            sizeof(*agent->network_resource_scan));
    agent->network_operation_scan =
        (mesh_control_operation_v1_t *)calloc(
            config->owner.state.operation_capacity,
            sizeof(*agent->network_operation_scan));
    if (!agent->network_resource_scan || !agent->network_operation_scan)
      goto failed;
    if (config->network_fabric != NULL) {
      if (mesh_network_reconciler_init_v1(&agent->network_reconciler,
                                          config->network_fabric,
                                          config->network_capacity) !=
          MESH_CONTROL_OK)
        goto failed;
      agent->network_reconciler_initialized = 1u;
    } else {
      agent->network_provider = *config->network_provider;
      agent->config.network_provider = &agent->network_provider;
      agent->network_provider_initialized = 1u;
    }
  }
  if (config->durability_enabled) {
    mesh_control_snapshot_page_info_v1_t checkpoint_page = {0};
    mesh_control_wal_worker_stats_v1_t wal_stats;
    memset(&wal_worker_config, 0, sizeof(wal_worker_config));
    wal_worker_config.wal = config->wal;
    wal_worker_config.checkpoint_path = config->checkpoint_path;
    wal_worker_config.checkpoint_owner = config->checkpoint_path ? &agent->owner : NULL;
    wal_worker_config.recovery_now_ms = config->now_ms(config->now_context);
    wal_worker_config.recovery_after_index = agent->owner.committed_log_index;
    wal_worker_config.recovery = agent_recover_wal_record;
    wal_worker_config.recovery_context = agent;
    if (mesh_control_wal_worker_init_v1(&agent->wal_worker, &wal_worker_config) !=
        MESH_CONTROL_WAL_WORKER_OK) {
      goto failed;
    }
    agent->wal_worker_initialized = 1u;
    if (mesh_control_wal_worker_get_stats_v1(&agent->wal_worker, &wal_stats) !=
        MESH_CONTROL_WAL_WORKER_OK) {
      goto failed;
    }
    agent->last_checkpoint_index = wal_stats.wal.base_index;
    if (agent->last_checkpoint_index != 0u &&
        mesh_control_state_snapshot_page_v1(mesh_control_owner_state_v1(&agent->owner), 0u, 0u,
                                            NULL, 0u, 0u, NULL, 0u,
                                            &checkpoint_page) != MESH_CONTROL_OK) {
      goto failed;
    }
    if (agent->last_checkpoint_index != 0u)
      agent->last_checkpoint_generation = checkpoint_page.generation;
  }
  if (agent_recover_function_operations(agent) != MESH_CONTROL_OK)
    goto failed;
  if (agent_restore_network_runtime(agent) != MESH_CONTROL_OK)
    goto failed;
  agent->app = iris_app_create();
  agent->context = coro_context_create(NULL);
  if (agent->app == NULL || agent->context == NULL)
    goto failed;
  memset(&iris_config, 0, sizeof(iris_config));
  iris_config.inbound = &agent->inbound;
  iris_config.authorize_transport = agent_authorize_transport;
  iris_config.admit = agent_authorize_message;
  iris_config.auth_context = agent;
  if (mesh_control_iris_register_v1(&agent->iris, agent->app, &iris_config) != MESH_CONTROL_OK)
    goto failed;
  if (iris_app_bind_rpc_context(agent->app, MESH_CONTROL_AGENT_STATUS_PATH_V1, agent) != 0)
    goto failed;
  if (iris_app_bind_rpc_context(agent->app, MESH_CONTROL_AGENT_EVENTS_PATH_V1, agent) != 0)
    goto failed;
  if (iris_app_bind_rpc_context(agent->app, MESH_CONTROL_AGENT_RECEIPTS_PATH_V1, agent) != 0)
    goto failed;
  iris_app_get(agent->app, MESH_CONTROL_AGENT_STATUS_PATH_V1, mesh_control_agent_status_handler);
  iris_app_get(agent->app, MESH_CONTROL_AGENT_EVENTS_PATH_V1, mesh_control_agent_events_handler);
  iris_app_get(agent->app, MESH_CONTROL_AGENT_RECEIPTS_PATH_V1,
               mesh_control_agent_receipts_handler);
  agent->listener =
      iris_server_start_tls_on(agent->app, agent->context, agent->host, config->port, config->tls);
  if (agent->listener == NULL)
    goto failed;
  agent->running = 1u;
  return MESH_CONTROL_OK;

failed:
  cleanup_started_agent(agent);
  memset(agent, 0, sizeof(*agent));
  return MESH_CONTROL_INVALID_STATE;
}

static mesh_control_result_t agent_dispatch_operation(mesh_control_agent_v1_t *agent,
                                                      const mesh_control_operation_v1_t *operation,
                                                      uint64_t now_ms) {
  const uint8_t *document = NULL;
  size_t document_size = 0u;
  mesh_control_result_t result;

  if (!agent || !operation)
    return MESH_CONTROL_INVALID_ARG;
  if (operation->resource_kind == MESH_CONTROL_RESOURCE_NETWORK) {
    mesh_control_wal_operation_result_v1_t operation_result;
    mesh_control_wal_worker_result_t worker_result;
    uint16_t outcome;
    if (agent->network_provider_initialized) {
      result = agent_start_network_provider_operation(agent, operation);
      if (result == MESH_CONTROL_OK)
        return MESH_CONTROL_OK;
      if (result == MESH_CONTROL_RESOURCE_EXHAUSTED ||
          result == MESH_CONTROL_PROVIDER_UNAVAILABLE ||
          result == MESH_CONTROL_TIMEOUT) {
        agent->network_recovery_pending = 1u;
        return MESH_CONTROL_OK;
      }
      return mesh_control_state_transition_operation_v1(
          mesh_control_owner_state_v1(&agent->owner),
          operation->operation_id, MESH_CONTROL_OPERATION_FAILED, now_ms);
    }
    result = agent_execute_network_operation(agent, operation, &outcome);
    if (result != MESH_CONTROL_OK)
      return result;
    agent_make_operation_result(operation, outcome, &operation_result);
    if (!agent->wal_worker_initialized)
      return agent_apply_operation_result(agent, &operation_result, now_ms);
    worker_result = mesh_control_wal_worker_try_submit_operation_result_v1(
        &agent->wal_worker, agent->owner.committed_log_index + 1u, now_ms,
        &operation_result);
    if (worker_result != MESH_CONTROL_WAL_WORKER_OK) {
      agent->persistence_fault = 1u;
      return MESH_CONTROL_INVALID_STATE;
    }
    agent->network_pending_result = operation_result;
    agent->network_result_persisting = 1u;
    return MESH_CONTROL_OK;
  }
  if (operation->resource_kind != MESH_CONTROL_RESOURCE_FUNCTION)
    return MESH_CONTROL_OK;
  result = mesh_control_state_get_desired_document_v1(
      mesh_control_owner_state_v1(&agent->owner), operation->resource_kind,
      operation->resource_id, &document, &document_size);
  if (result == MESH_CONTROL_OK && agent->function_reconciler_initialized)
    result = mesh_control_reconciler_enqueue_v1(
        &agent->function_reconciler, operation, document, document_size);
  if (result == MESH_CONTROL_OK)
    return MESH_CONTROL_OK;
  return mesh_control_state_transition_operation_v1(mesh_control_owner_state_v1(&agent->owner),
                                                    operation->operation_id,
                                                    MESH_CONTROL_OPERATION_FAILED, now_ms);
}

static mesh_control_result_t agent_poll_durable_commands(mesh_control_agent_v1_t *agent,
                                                         uint64_t now_ms, uint8_t allow_commands,
                                                         size_t *out_processed) {
  size_t processed = 0u;
  size_t completion_progress = 0u;

  if (!agent || !out_processed || !agent->wal_worker_initialized)
    return MESH_CONTROL_INVALID_ARG;
  if (agent->persistence_fault)
    return MESH_CONTROL_INVALID_STATE;
  while ((allow_commands && processed < agent->config.max_commands_per_poll) ||
         ((agent->network_result_persisting ||
           agent->network_recovery_pending) &&
          completion_progress < agent->config.max_commands_per_poll) ||
         completion_progress < agent->config.max_provider_completions_per_poll) {
    mesh_control_owner_prepared_v1_t prepared;
    mesh_control_reconciler_prepared_completion_v1_t provider_prepared;
    mesh_control_wal_worker_completion_v1_t completion;
    mesh_control_wal_operation_result_v1_t operation_result;
    mesh_control_operation_v1_t operation;
    mesh_control_wal_worker_result_t worker_result;
    mesh_control_result_t result;

    if (agent->checkpoint_persisting) {
      worker_result = mesh_control_wal_worker_try_take_v1(&agent->wal_worker, &completion);
      if (worker_result == MESH_CONTROL_WAL_WORKER_EMPTY)
        break;
      if (worker_result != MESH_CONTROL_WAL_WORKER_OK ||
          completion.record_type != MESH_CONTROL_WAL_WORKER_CHECKPOINT_RECORD_V1 ||
          completion.checkpoint_result != MESH_CONTROL_CHECKPOINT_STORE_OK ||
          completion.wal_result != MESH_CONTROL_WAL_OK ||
          completion.expected_index != agent->owner.committed_log_index ||
          completion.log_index != completion.expected_index) {
        agent->persistence_fault = 1u;
        return MESH_CONTROL_INVALID_STATE;
      }
      agent->checkpoint_persisting = 0u;
      agent->last_checkpoint_index = completion.log_index;
      agent->last_checkpoint_generation = agent->checkpoint_generation_pending;
      agent->checkpoint_generation_pending = 0u;
      continue;
    }

    if (agent->network_provider_ack_pending) {
      result = agent->network_provider.ops.ack_completion(
          agent->network_provider.context,
          agent->network_active_operation.operation_id);
      if (result == MESH_CONTROL_RESOURCE_EXHAUSTED ||
          result == MESH_CONTROL_TIMEOUT ||
          result == MESH_CONTROL_PROVIDER_UNAVAILABLE)
        break;
      if (result != MESH_CONTROL_OK)
        return result;
      memset(&agent->network_active_operation, 0,
             sizeof(agent->network_active_operation));
      agent->network_provider_active = 0u;
      agent->network_provider_ack_pending = 0u;
      ++completion_progress;
      continue;
    }

    if (agent->network_result_persisting) {
      worker_result = mesh_control_wal_worker_try_take_v1(
          &agent->wal_worker, &completion);
      if (worker_result == MESH_CONTROL_WAL_WORKER_EMPTY)
        break;
      if (worker_result != MESH_CONTROL_WAL_WORKER_OK ||
          completion.wal_result != MESH_CONTROL_WAL_OK ||
          completion.record_type != MESH_CONTROL_WAL_RECORD_OPERATION_RESULT ||
          completion.expected_index != agent->owner.committed_log_index + 1u) {
        agent->persistence_fault = 1u;
        return MESH_CONTROL_INVALID_STATE;
      }
      result = agent_apply_operation_result(
          agent, &agent->network_pending_result, now_ms);
      if (result != MESH_CONTROL_OK ||
          mesh_control_owner_advance_log_index_v1(
              &agent->owner, completion.log_index) != MESH_CONTROL_OK) {
        agent->persistence_fault = 1u;
        return MESH_CONTROL_INVALID_STATE;
      }
      memset(&agent->network_pending_result, 0,
             sizeof(agent->network_pending_result));
      agent->network_result_persisting = 0u;
      if (agent->network_provider_active)
        agent->network_provider_ack_pending = 1u;
      ++completion_progress;
      continue;
    }

    if (agent->provider_result_ack_pending) {
      result = mesh_control_reconciler_ack_completion_v1(&agent->function_reconciler);
      if (result != MESH_CONTROL_OK)
        return result;
      agent->provider_result_ack_pending = 0u;
      agent->provider_result_log_index = 0u;
      ++completion_progress;
      continue;
    }

    if (agent->provider_result_persisting) {
      worker_result = mesh_control_wal_worker_try_take_v1(&agent->wal_worker, &completion);
      if (worker_result == MESH_CONTROL_WAL_WORKER_EMPTY)
        break;
      if (worker_result != MESH_CONTROL_WAL_WORKER_OK ||
          completion.wal_result != MESH_CONTROL_WAL_OK ||
          completion.record_type != MESH_CONTROL_WAL_RECORD_OPERATION_RESULT ||
          completion.expected_index != agent->owner.committed_log_index + 1u) {
        agent->persistence_fault = 1u;
        return MESH_CONTROL_INVALID_STATE;
      }
      result = mesh_control_reconciler_apply_completion_v1(
          &agent->function_reconciler, mesh_control_owner_state_v1(&agent->owner), now_ms);
      if (result != MESH_CONTROL_OK ||
          mesh_control_owner_advance_log_index_v1(&agent->owner, completion.log_index) !=
              MESH_CONTROL_OK) {
        agent->persistence_fault = 1u;
        return MESH_CONTROL_INVALID_STATE;
      }
      agent->provider_result_persisting = 0u;
      agent->provider_result_ack_pending = 1u;
      agent->provider_result_log_index = completion.log_index;
      continue;
    }

    if (agent->network_provider_initialized &&
        agent->network_provider_active &&
        completion_progress < agent->config.max_provider_completions_per_poll) {
      result = agent_peek_network_provider_result(agent,
                                                   &operation_result);
      if (result == MESH_CONTROL_OK) {
        worker_result =
            mesh_control_wal_worker_try_submit_operation_result_v1(
                &agent->wal_worker, agent->owner.committed_log_index + 1u,
                now_ms, &operation_result);
        if (worker_result != MESH_CONTROL_WAL_WORKER_OK) {
          agent->persistence_fault = 1u;
          return MESH_CONTROL_INVALID_STATE;
        }
        agent->network_pending_result = operation_result;
        agent->network_result_persisting = 1u;
        break;
      }
      if (result != MESH_CONTROL_EMPTY)
        return result;
    }

    if (agent->network_recovery_pending &&
        completion_progress < agent->config.max_commands_per_poll) {
      result = agent_find_pending_network_operation(agent, &operation);
      if (result == MESH_CONTROL_OK) {
        if (agent->network_provider_initialized) {
          if (agent->network_provider_active)
            break;
          result = agent_start_network_provider_operation(agent,
                                                           &operation);
          if (result == MESH_CONTROL_OK)
            break;
          if (result == MESH_CONTROL_RESOURCE_EXHAUSTED ||
              result == MESH_CONTROL_PROVIDER_UNAVAILABLE ||
              result == MESH_CONTROL_TIMEOUT)
            break;
          return result;
        } else {
          uint16_t outcome;
          result = agent_execute_network_operation(agent, &operation,
                                                   &outcome);
          if (result != MESH_CONTROL_OK)
            return result;
          agent_make_operation_result(&operation, outcome,
                                      &operation_result);
          worker_result =
              mesh_control_wal_worker_try_submit_operation_result_v1(
                  &agent->wal_worker,
                  agent->owner.committed_log_index + 1u, now_ms,
                  &operation_result);
          if (worker_result != MESH_CONTROL_WAL_WORKER_OK) {
            agent->persistence_fault = 1u;
            return MESH_CONTROL_INVALID_STATE;
          }
          agent->network_pending_result = operation_result;
          agent->network_result_persisting = 1u;
          break;
        }
      }
      if (result != MESH_CONTROL_EMPTY)
        return result;
      agent->network_recovery_pending = 0u;
    }

    if (agent->owner.preparation_active) {
      worker_result = mesh_control_wal_worker_try_take_v1(&agent->wal_worker, &completion);
      if (worker_result == MESH_CONTROL_WAL_WORKER_EMPTY)
        break;
      if (worker_result != MESH_CONTROL_WAL_WORKER_OK ||
          completion.wal_result != MESH_CONTROL_WAL_OK ||
          completion.record_type != MESH_CONTROL_WAL_RECORD_SIGNED_INTENT ||
          completion.expected_index != agent->owner.pending.expected_log_index) {
        agent->persistence_fault = 1u;
        return MESH_CONTROL_INVALID_STATE;
      }
      result =
          mesh_control_owner_commit_prepared_v1(&agent->owner, completion.log_index, &operation);
      if (result != MESH_CONTROL_OK) {
        agent->persistence_fault = 1u;
        return MESH_CONTROL_INVALID_STATE;
      }
      result = agent_dispatch_operation(agent, &operation, now_ms);
      if (result != MESH_CONTROL_OK)
        return result;
      ++processed;
      continue;
    }

    if (agent->function_reconciler_initialized &&
        completion_progress < agent->config.max_provider_completions_per_poll) {
      result = mesh_control_reconciler_prepare_completion_v1(&agent->function_reconciler,
                                                             &provider_prepared);
      if (result == MESH_CONTROL_OK) {
        memset(&operation_result, 0, sizeof(operation_result));
        memcpy(operation_result.operation_id, provider_prepared.operation.operation_id,
               sizeof(operation_result.operation_id));
        operation_result.resource_kind = provider_prepared.operation.resource_kind;
        operation_result.action = provider_prepared.operation.action;
        operation_result.outcome =
            provider_prepared.completion.state == MESH_CONTROL_PROVIDER_COMPLETED
                ? MESH_CONTROL_WAL_OPERATION_SUCCEEDED
                : MESH_CONTROL_WAL_OPERATION_FAILED;
        memcpy(operation_result.resource_id, provider_prepared.operation.resource_id,
               sizeof(operation_result.resource_id));
        operation_result.desired_epoch = provider_prepared.operation.desired_epoch;
        worker_result = mesh_control_wal_worker_try_submit_operation_result_v1(
            &agent->wal_worker, agent->owner.committed_log_index + 1u, now_ms, &operation_result);
        if (worker_result != MESH_CONTROL_WAL_WORKER_OK) {
          agent->persistence_fault = 1u;
          return MESH_CONTROL_INVALID_STATE;
        }
        agent->provider_result_persisting = 1u;
        break;
      }
      if (result != MESH_CONTROL_EMPTY)
        return result;
    }

    if (!allow_commands || processed >= agent->config.max_commands_per_poll)
      break;

    result = mesh_control_owner_prepare_next_v1(&agent->owner, now_ms, &prepared);
    if (result == MESH_CONTROL_EMPTY)
      break;
    if (result != MESH_CONTROL_OK) {
      ++processed;
      continue;
    }
    if (!prepared.signed_frame || prepared.signed_frame_size == 0u) {
      agent->persistence_fault = 1u;
      return MESH_CONTROL_INVALID_STATE;
    }
    worker_result = mesh_control_wal_worker_try_submit_v1(
        &agent->wal_worker, prepared.expected_log_index, prepared.accepted_at_ms,
        prepared.signed_frame, prepared.signed_frame_size);
    if (worker_result != MESH_CONTROL_WAL_WORKER_OK) {
      agent->persistence_fault = 1u;
      return MESH_CONTROL_INVALID_STATE;
    }
    break;
  }
  *out_processed = processed;
  return MESH_CONTROL_OK;
}

static mesh_control_result_t agent_maybe_schedule_checkpoint(mesh_control_agent_v1_t *agent,
                                                             uint8_t force) {
  mesh_control_wal_worker_stats_v1_t stats;
  mesh_control_snapshot_page_info_v1_t page;
  mesh_control_checkpoint_result_t checkpoint_result;
  mesh_control_wal_worker_result_t worker_result;
  uint8_t *bytes = NULL;
  size_t size = 0u;

  if (!agent || !agent->wal_worker_initialized)
    return MESH_CONTROL_INVALID_ARG;
  if (!agent->config.checkpoint_path || agent->owner.committed_log_index == 0u)
    return MESH_CONTROL_OK;
  if (agent->checkpoint_persisting || agent->network_result_persisting ||
      agent->network_provider_ack_pending ||
      agent->network_recovery_pending ||
      agent->provider_result_persisting ||
      agent->provider_result_ack_pending || agent->owner.preparation_active) {
    return MESH_CONTROL_OK;
  }
  if (mesh_control_wal_worker_get_stats_v1(&agent->wal_worker, &stats) !=
      MESH_CONTROL_WAL_WORKER_OK) {
    return MESH_CONTROL_INVALID_STATE;
  }
  if (stats.busy || stats.completion_ready)
    return MESH_CONTROL_OK;
  if (mesh_control_state_snapshot_page_v1(mesh_control_owner_state_v1(&agent->owner), 0u, 0u, NULL,
                                          0u, 0u, NULL, 0u, &page) != MESH_CONTROL_OK) {
    return MESH_CONTROL_INVALID_STATE;
  }
  if (force && agent->last_checkpoint_index == agent->owner.committed_log_index &&
      agent->last_checkpoint_generation == page.generation) {
    return MESH_CONTROL_OK;
  }
  if (!force && stats.wal.record_count < agent->config.checkpoint_interval_records &&
      stats.wal.file_size < stats.wal.byte_capacity / 2u) {
    return MESH_CONTROL_OK;
  }
  checkpoint_result = mesh_control_checkpoint_encode_v1(&agent->owner, &bytes, &size);
  if (checkpoint_result != MESH_CONTROL_CHECKPOINT_OK) {
    agent->persistence_fault = 1u;
    return checkpoint_result == MESH_CONTROL_CHECKPOINT_RESOURCE_EXHAUSTED
               ? MESH_CONTROL_RESOURCE_EXHAUSTED
               : MESH_CONTROL_INVALID_STATE;
  }
  worker_result = mesh_control_wal_worker_try_submit_checkpoint_v1(
      &agent->wal_worker, agent->owner.committed_log_index, bytes, size);
  if (worker_result == MESH_CONTROL_WAL_WORKER_FULL) {
    mesh_control_checkpoint_free_v1(bytes);
    return MESH_CONTROL_OK;
  }
  if (worker_result != MESH_CONTROL_WAL_WORKER_OK) {
    mesh_control_checkpoint_free_v1(bytes);
    agent->persistence_fault = 1u;
    return MESH_CONTROL_INVALID_STATE;
  }
  agent->checkpoint_persisting = 1u;
  agent->checkpoint_generation_pending = page.generation;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_agent_poll_v1(mesh_control_agent_v1_t *agent,
                                                 size_t *out_processed) {
  size_t processed = 0u;
  size_t reconcile_progress = 0u;
  size_t network_progress = 0u;
  uint64_t now_ms;
  mesh_control_result_t result;
  if (agent == NULL || agent->running == 0u || out_processed == NULL)
    return MESH_CONTROL_INVALID_ARG;
  *out_processed = 0u;
  if (coro_context_current() != agent->context)
    (void)coro_context_run(agent->context, TURBO_RUN_NOWAIT);
  now_ms = agent->config.now_ms(agent->config.now_context);
  if (agent->network_provider_initialized &&
      (agent->network_provider_restore_pending ||
       agent->network_provider_restore_active)) {
    result = agent_poll_network_provider_restore(agent, &network_progress);
    if (result != MESH_CONTROL_OK)
      return result;
    if (agent->network_provider_restore_pending ||
        agent->network_provider_restore_active) {
      return MESH_CONTROL_OK;
    }
  }
  if (agent->network_provider_initialized && !agent->wal_worker_initialized) {
    result = agent_poll_volatile_network_provider(agent, now_ms,
                                                  &network_progress);
    if (result != MESH_CONTROL_OK)
      return result;
  }
  if (agent->function_reconciler_initialized && !agent->wal_worker_initialized) {
    result = mesh_control_reconciler_poll_v1(
        &agent->function_reconciler, mesh_control_owner_state_v1(&agent->owner),
        agent->config.max_provider_completions_per_poll, agent->config.max_provider_starts_per_poll,
        now_ms, &reconcile_progress);
    if (result != MESH_CONTROL_OK)
      return result;
  }
  if (agent->wal_worker_initialized) {
    result = agent_poll_durable_commands(agent, now_ms, 1u, &processed);
    if (result != MESH_CONTROL_OK)
      return result;
  } else {
    while (processed < agent->config.max_commands_per_poll) {
      mesh_control_operation_v1_t operation;
      result = mesh_control_owner_process_next_v1(&agent->owner, now_ms, &operation);
      if (result == MESH_CONTROL_EMPTY)
        break;
      if (result == MESH_CONTROL_OK) {
        result = agent_dispatch_operation(agent, &operation, now_ms);
        if (result != MESH_CONTROL_OK)
          return result;
      }
      ++processed;
    }
  }
  if (agent->function_reconciler_initialized) {
    result = agent->wal_worker_initialized
                 ? mesh_control_reconciler_poll_starts_v1(
                       &agent->function_reconciler, mesh_control_owner_state_v1(&agent->owner),
                       agent->config.max_provider_starts_per_poll, now_ms, &reconcile_progress)
                 : mesh_control_reconciler_poll_v1(
                       &agent->function_reconciler, mesh_control_owner_state_v1(&agent->owner),
                       agent->config.max_provider_completions_per_poll,
                       agent->config.max_provider_starts_per_poll, now_ms, &reconcile_progress);
    if (result != MESH_CONTROL_OK)
      return result;
  }
  if (agent->wal_worker_initialized) {
    result = agent_maybe_schedule_checkpoint(agent, 0u);
    if (result != MESH_CONTROL_OK)
      return result;
  }
  (void)reconcile_progress;
  (void)network_progress;
  *out_processed = processed;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_agent_stop_v1(mesh_control_agent_v1_t *agent) {
  uint64_t drain_started_at_ms;
  mesh_control_result_t result;
  if (agent == NULL || agent->running == 0u)
    return MESH_CONTROL_INVALID_ARG;
  (void)mesh_control_iris_close_v1(&agent->iris);
  (void)mesh_control_channel_close_v1(&agent->inbound);
  drain_started_at_ms = turbo_monotonic_ms();

  while (agent->network_provider_initialized &&
         (agent->network_provider_restore_pending ||
          agent->network_provider_restore_active)) {
    size_t restore_progress = 0u;
    result = agent_poll_network_provider_restore(agent, &restore_progress);
    if (result != MESH_CONTROL_OK)
      return result;
    if (turbo_monotonic_ms() - drain_started_at_ms >=
        agent->config.shutdown_drain_timeout_ms)
      return MESH_CONTROL_INVALID_STATE;
    if (restore_progress == 0u)
      turbo_sleep_ms(1u);
  }

  if (agent->wal_worker_initialized) {
    size_t recovered_progress = 0u;
    result = agent_poll_durable_commands(
        agent, agent->config.now_ms(agent->config.now_context), 0u,
        &recovered_progress);
    if (result != MESH_CONTROL_OK)
      return result;
    while (agent->checkpoint_persisting || agent->network_result_persisting ||
           agent->network_provider_active ||
           agent->network_provider_ack_pending ||
           agent->network_recovery_pending ||
           agent->provider_result_persisting ||
           agent->provider_result_ack_pending || agent->owner.preparation_active) {
      size_t processed = 0u;
      result = agent_poll_durable_commands(agent, agent->config.now_ms(agent->config.now_context),
                                           0u, &processed);
      if (result != MESH_CONTROL_OK)
        return result;
      if (turbo_monotonic_ms() - drain_started_at_ms >= agent->config.shutdown_drain_timeout_ms) {
        return MESH_CONTROL_INVALID_STATE;
      }
      turbo_sleep_ms(1u);
    }
  } else if (agent->network_provider_initialized) {
    while (agent->network_provider_active ||
           agent->network_recovery_pending) {
      size_t network_progress = 0u;
      result = agent_poll_volatile_network_provider(
          agent, agent->config.now_ms(agent->config.now_context),
          &network_progress);
      if (result != MESH_CONTROL_OK)
        return result;
      if (turbo_monotonic_ms() - drain_started_at_ms >=
          agent->config.shutdown_drain_timeout_ms)
        return MESH_CONTROL_INVALID_STATE;
      if (network_progress == 0u)
        turbo_sleep_ms(1u);
    }
  }

  if (agent->function_reconciler_initialized) {
    (void)mesh_control_reconciler_close_v1(&agent->function_reconciler);
    while (!mesh_control_reconciler_is_drained_v1(&agent->function_reconciler)) {
      size_t durable_progress = 0u;
      size_t shutdown_progress = 0u;
      uint64_t now_ms = agent->config.now_ms(agent->config.now_context);
      if (agent->wal_worker_initialized) {
        result = agent_poll_durable_commands(agent, now_ms, 0u, &durable_progress);
        if (result != MESH_CONTROL_OK)
          return result;
        result = mesh_control_reconciler_poll_shutdown_v1(
            &agent->function_reconciler, mesh_control_owner_state_v1(&agent->owner),
            agent->config.max_provider_completions_per_poll, now_ms, &shutdown_progress);
      } else {
        result = mesh_control_reconciler_poll_v1(
            &agent->function_reconciler, mesh_control_owner_state_v1(&agent->owner),
            agent->config.max_provider_completions_per_poll,
            agent->config.max_provider_starts_per_poll, now_ms, &shutdown_progress);
      }
      if (result != MESH_CONTROL_OK)
        return MESH_CONTROL_INVALID_STATE;
      if (mesh_control_reconciler_is_drained_v1(&agent->function_reconciler))
        break;
      if (turbo_monotonic_ms() - drain_started_at_ms >= agent->config.shutdown_drain_timeout_ms) {
        return MESH_CONTROL_INVALID_STATE;
      }
      if (durable_progress == 0u && shutdown_progress == 0u)
        turbo_sleep_ms(1u);
    }
  }

  if (agent->network_reconciler_initialized &&
      mesh_network_reconciler_close_v1(
          &agent->network_reconciler,
          agent->config.shutdown_drain_timeout_ms) != MESH_CONTROL_OK)
    return MESH_CONTROL_INVALID_STATE;

  if (agent->network_provider_initialized) {
    agent->network_provider.ops.close(agent->network_provider.context);
    while (!agent->network_provider.ops.is_drained(
        agent->network_provider.context)) {
      if (turbo_monotonic_ms() - drain_started_at_ms >=
          agent->config.shutdown_drain_timeout_ms)
        return MESH_CONTROL_INVALID_STATE;
      turbo_sleep_ms(1u);
    }
    agent->network_provider_initialized = 0u;
  }

  if (agent->wal_worker_initialized && agent->config.checkpoint_path) {
    result = agent_maybe_schedule_checkpoint(agent, 1u);
    if (result != MESH_CONTROL_OK)
      return result;
    while (agent->checkpoint_persisting) {
      size_t processed = 0u;
      result = agent_poll_durable_commands(agent, agent->config.now_ms(agent->config.now_context),
                                           0u, &processed);
      if (result != MESH_CONTROL_OK)
        return result;
      if (turbo_monotonic_ms() - drain_started_at_ms >= agent->config.shutdown_drain_timeout_ms) {
        return MESH_CONTROL_INVALID_STATE;
      }
      turbo_sleep_ms(1u);
    }
  }

  if (agent->wal_worker_initialized &&
      mesh_control_wal_worker_shutdown_v1(&agent->wal_worker) != MESH_CONTROL_WAL_WORKER_OK) {
    return MESH_CONTROL_INVALID_STATE;
  }
  if (agent->listener != NULL) {
    coro_socket_destroy(agent->listener);
    agent->listener = NULL;
  }
  coro_context_stop(agent->context);
  while (coro_context_alive(agent->context) &&
         turbo_monotonic_ms() - drain_started_at_ms < agent->config.shutdown_drain_timeout_ms) {
    (void)coro_context_run(agent->context, TURBO_RUN_ONCE);
  }
  if (coro_context_alive(agent->context))
    return MESH_CONTROL_INVALID_STATE;
  agent->running = 0u;
  cleanup_started_agent(agent);
  memset(agent, 0, sizeof(*agent));
  return MESH_CONTROL_OK;
}

const mesh_control_state_v1_t *mesh_control_agent_state_v1(const mesh_control_agent_v1_t *agent) {
  return agent != NULL && agent->running != 0u ? &agent->owner.state : NULL;
}

mesh_control_result_t mesh_control_agent_status_page_v1(mesh_control_agent_v1_t *agent,
                                                        uint64_t expected_generation,
                                                        size_t resource_offset,
                                                        size_t operation_offset, uint8_t *output,
                                                        size_t output_capacity, size_t *out_size) {
  mesh_control_resource_status_v1_t *resources;
  mesh_control_operation_v1_t *operations;
  mesh_control_snapshot_page_info_v1_t info;
  mesh_control_result_t result;

  if (out_size == NULL)
    return MESH_CONTROL_INVALID_ARG;
  *out_size = 0u;
  if (agent == NULL || agent->running == 0u || output == NULL)
    return MESH_CONTROL_INVALID_ARG;
  resources = (mesh_control_resource_status_v1_t *)malloc(agent->config.status_page_resource_limit *
                                                          sizeof(*resources));
  operations = (mesh_control_operation_v1_t *)malloc(agent->config.status_page_operation_limit *
                                                     sizeof(*operations));
  if (resources == NULL || operations == NULL) {
    free(operations);
    free(resources);
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  }
  result = mesh_control_state_snapshot_page_v1(
      mesh_control_owner_state_v1(&agent->owner), expected_generation, resource_offset, resources,
      agent->config.status_page_resource_limit, operation_offset, operations,
      agent->config.status_page_operation_limit, &info);
  if (result == MESH_CONTROL_OK) {
    result = mesh_control_status_page_encode_v1(&info, resources, operations, output,
                                                output_capacity, out_size);
  }
  free(operations);
  free(resources);
  return result;
}

mesh_control_result_t mesh_control_agent_event_page_v1(mesh_control_agent_v1_t *agent,
                                                       uint64_t cursor, uint8_t *output,
                                                       size_t output_capacity, size_t *out_size) {
  mesh_control_event_v1_t *events;
  size_t event_count = 0u;
  uint64_t next_cursor = cursor;
  mesh_control_result_t result;

  if (out_size == NULL)
    return MESH_CONTROL_INVALID_ARG;
  *out_size = 0u;
  if (agent == NULL || agent->running == 0u || output == NULL)
    return MESH_CONTROL_INVALID_ARG;
  events = (mesh_control_event_v1_t *)malloc(agent->config.status_event_limit * sizeof(*events));
  if (events == NULL)
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  result = mesh_control_state_events_after_v1(mesh_control_owner_state_v1(&agent->owner), cursor,
                                              events, agent->config.status_event_limit,
                                              &event_count, &next_cursor);
  if (result == MESH_CONTROL_OK) {
    result = mesh_control_event_page_encode_v1(cursor, next_cursor, events, event_count, output,
                                               output_capacity, out_size);
  }
  free(events);
  return result;
}

mesh_control_result_t
mesh_control_agent_receipt_v1(mesh_control_agent_v1_t *agent,
                              const uint8_t operation_id[MESH_CONTROL_ID_SIZE],
                              uint8_t output[MESH_CONTROL_RECEIPT_SIZE_V1], size_t *out_size) {
  mesh_control_receipt_v1_t receipt;
  mesh_control_snapshot_page_info_v1_t page;
  mesh_control_result_t result;
  if (!agent || !agent->running || !operation_id || !output || !out_size)
    return MESH_CONTROL_INVALID_ARG;
  *out_size = 0u;
  if (!agent->wal_worker_initialized)
    return MESH_CONTROL_INVALID_STATE;
  memset(&receipt, 0, sizeof(receipt));
  result = mesh_control_state_get_operation_v1(mesh_control_owner_state_v1(&agent->owner),
                                               operation_id, &receipt.operation);
  if (result != MESH_CONTROL_OK)
    return result;
  result = mesh_control_state_snapshot_page_v1(mesh_control_owner_state_v1(&agent->owner), 0u, 0u,
                                               NULL, 0u, 0u, NULL, 0u, &page);
  if (result != MESH_CONTROL_OK)
    return result;
  receipt.flags = MESH_CONTROL_RECEIPT_FLAG_DURABLE_V1;
  receipt.operation.state = MESH_CONTROL_OPERATION_ACCEPTED;
  receipt.durable_through_index = agent->owner.committed_log_index;
  receipt.state_generation = page.generation;
  receipt.checkpoint_base_index = agent->last_checkpoint_index;
  return mesh_control_receipt_encode_v1(&receipt, output, MESH_CONTROL_RECEIPT_SIZE_V1, out_size);
}
