#include "mesh_control_agent_http_client.h"

#include "mesh_control_controller_iris.h"

#include <string.h>

static int https_url_valid(const char *url) {
  size_t size;
  const char *path;
  static const char prefix[] = "https://";
  if (!url || strncmp(url, prefix, sizeof(prefix) - 1u) != 0) return 0;
  size = strlen(url);
  path = strchr(url + sizeof(prefix) - 1u, '/');
  return size > sizeof(prefix) - 1u && size < 2048u && path &&
         path != url + sizeof(prefix) - 1u &&
         strcmp(path, MESH_CONTROL_CONTROLLER_SYNC_PATH_V1) == 0;
}

static mesh_control_result_t create_http(
    coro_context_t *context, uint64_t timeout_ms,
    const turbo_tls_client_config_t *tls, turbo_http_t **out_http) {
  turbo_http_options_t options;
  turbo_http_t *http = NULL;
  if (!context || !tls || !tls->ca_file || !tls->cert_file ||
      !tls->key_file || tls->verify_peer != 1 || timeout_ms == 0u ||
      timeout_ms > INT64_MAX || !out_http)
    return MESH_CONTROL_INVALID_ARG;
  *out_http = NULL;
  if (turbo_http_options_init(&options, sizeof(options)) != TURBO_OK)
    return MESH_CONTROL_INVALID_STATE;
  options.transport = TURBO_HTTP_TRANSPORT_H2;
  options.h2_fallback_to_h1 = 0;
  options.follow_redirects = 0;
  options.retry.max_retries = 0;
  options.timeout_ms = (int64_t)timeout_ms;
  if (turbo_http_create(context, &options, &http) != TURBO_OK || !http)
    return MESH_CONTROL_INVALID_STATE;
  if (turbo_http_set_tls_config(http, tls) != TURBO_OK) {
    turbo_http_destroy(http);
    return MESH_CONTROL_UNAUTHORIZED;
  }
  *out_http = http;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_agent_http_client_init_v1(
    mesh_control_agent_http_client_v1_t *client, coro_context_t *context,
    const mesh_control_agent_http_client_config_v1_t *config) {
  mesh_control_result_t result;
  if (!client || client->initialized || !context || !config ||
      !https_url_valid(config->sync_url) || !config->tls ||
      !config->tls->ca_file || !config->tls->cert_file ||
      !config->tls->key_file || config->tls->verify_peer != 1 ||
      config->timeout_ms == 0u || config->timeout_ms > INT64_MAX)
    return MESH_CONTROL_INVALID_ARG;
  memset(client, 0, sizeof(*client));
  result = create_http(context, config->timeout_ms, config->tls,
                       &client->http);
  if (result != MESH_CONTROL_OK) return result;
  memcpy(client->sync_url, config->sync_url, strlen(config->sync_url) + 1u);
  client->context = context;
  client->timeout_ms = config->timeout_ms;
  client->initialized = 1u;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_agent_http_client_exchange_v1(
    mesh_control_agent_http_client_v1_t *client, const uint8_t *request,
    size_t request_size, uint8_t *response, size_t response_capacity,
    size_t *out_response_size) {
  const char *headers[] = {
      "Content-Type: " MESH_CONTROL_CONTROLLER_SYNC_MEDIA_TYPE_V1,
      "Accept: " MESH_CONTROL_CONTROLLER_SYNC_MEDIA_TYPE_V1};
  http_response_t *http_response;
  mesh_control_agent_sync_message_v1_t decoded;
  if (!out_response_size) return MESH_CONTROL_INVALID_ARG;
  *out_response_size = 0u;
  if (!client || !client->initialized || client->closed || !request ||
      request_size == 0u || request_size > MESH_CONTROL_MAX_FRAME_SIZE_V1 ||
      !response || response_capacity == 0u)
    return MESH_CONTROL_INVALID_ARG;
  http_response = turbo_http_request(
      client->http, HTTP_POST, client->sync_url, headers, 2,
      (const char *)request, request_size);
  if (!http_response || http_response->error ||
      http_response->status_code != 200) {
    client->transport_failures++;
    if (http_response) http_response_free(http_response);
    return MESH_CONTROL_PROVIDER_UNAVAILABLE;
  }
  if (!http_response->body || http_response->body_len == 0u ||
      http_response->body_len > MESH_CONTROL_MAX_FRAME_SIZE_V1 ||
      mesh_control_agent_sync_decode_v1(
          (const uint8_t *)http_response->body, http_response->body_len,
          &decoded) != MESH_CONTROL_AGENT_SYNC_OK) {
    client->protocol_failures++;
    http_response_free(http_response);
    return MESH_CONTROL_INVALID_STATE;
  }
  *out_response_size = http_response->body_len;
  if (response_capacity < http_response->body_len) {
    http_response_free(http_response);
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  }
  memcpy(response, http_response->body, http_response->body_len);
  client->exchanged++;
  http_response_free(http_response);
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_agent_http_client_close_v1(
    mesh_control_agent_http_client_v1_t *client) {
  if (!client || !client->initialized) return MESH_CONTROL_INVALID_ARG;
  client->closed = 1u;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_agent_http_client_reload_tls_v1(
    mesh_control_agent_http_client_v1_t *client,
    const turbo_tls_client_config_t *tls) {
  turbo_http_t *replacement = NULL;
  turbo_http_t *previous;
  mesh_control_result_t result;
  if (!client || !client->initialized || client->closed || !tls)
    return MESH_CONTROL_INVALID_ARG;
  result = create_http(client->context, client->timeout_ms, tls, &replacement);
  if (result != MESH_CONTROL_OK) return result;
  previous = client->http;
  client->http = replacement;
  turbo_http_destroy(previous);
  return MESH_CONTROL_OK;
}

void mesh_control_agent_http_client_destroy_v1(
    mesh_control_agent_http_client_v1_t *client) {
  if (!client) return;
  if (client->http) turbo_http_destroy(client->http);
  memset(client, 0, sizeof(*client));
}
