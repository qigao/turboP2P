#include "meshctl_controller_http.h"
#include "meshctl_controller_validation.h"

#include <http_client/http.h>
#include <json_parser.h>
#include <uri_parser.h>
#include <fmt.h>
#include <tlog.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

int meshctl_controller_endpoint_valid(const char *endpoint) {
  uri_t uri;
  if (!endpoint || strncmp(endpoint, "https://", 8u) != 0 ||
      strlen(endpoint) >= MESHCTL_PRODUCT_ENDPOINT_CAPACITY ||
      !uri_parse(endpoint, &uri)) return 0;
  return uri.valid && !uri.overflow_flags &&
      strcmp(uri.scheme, "https") == 0 && uri.host[0] &&
      !uri.userinfo[0] && !uri.query[0] && !uri.fragment[0] &&
      (!uri.path[0] || strcmp(uri.path, "/") == 0) &&
      (!(uri.component_flags & URI_COMPONENT_PORT) ||
       (uri.port > 0 && uri.port <= UINT16_MAX));
}

int meshctl_controller_credential_file_valid(const char *path, int private_key) {
  if (!path || path[0] == '\0' || strlen(path) >= MESHCTL_PRODUCT_PATH_CAPACITY ||
      strchr(path, '\r') || strchr(path, '\n'))
    return 0;
#ifdef _WIN32
  {
    DWORD attributes = GetFileAttributesA(path);
    if (attributes == INVALID_FILE_ATTRIBUTES ||
        (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0u ||
        (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0u)
      return 0;
  }
#else
  {
    struct stat info;
    if (lstat(path, &info) != 0 || !S_ISREG(info.st_mode) ||
        info.st_uid != geteuid() || (info.st_mode & (S_IWGRP | S_IWOTH)) != 0)
      return 0;
    if (private_key && (info.st_mode & (S_IRGRP | S_IROTH)) != 0) return 0;
  }
#endif
  return 1;
}

static int route_valid(const char *route) {
  static const char prefix[] = "/v1/meshes/";
  if (!route) return 0;
  size_t size = strlen(route);
  return size > sizeof(prefix) - 1u && size < MESHCTL_PRODUCT_ROUTE_CAPACITY &&
      strncmp(route, prefix, sizeof(prefix) - 1u) == 0 &&
      !strchr(route, '\r') && !strchr(route, '\n') && !strchr(route, '#');
}

void meshctl_controller_response_destroy(meshctl_controller_response_t *response) {
  if (!response) return;
  free(response->body);
  memset(response, 0, sizeof(*response));
}

static chttp_client_config controller_config(uint32_t timeout_ms) {
  chttp_client_config config = {0};
#if defined(_WIN32)
  config.network.backend = NATIVE_IO_BACKEND_IOCP;
#elif defined(__linux__)
  config.network.backend = NATIVE_IO_BACKEND_EPOLL;
#else
  config.network.backend = NATIVE_IO_BACKEND_KQUEUE;
#endif
  config.network.connection_capacity = 1u;
  config.network.command_capacity = 8u;
  config.network.request_capacity = 8u;
  config.network.completion_batch_capacity = 8u;
  config.network.event_capacity = 8u;
  config.network.max_send_bytes = MESHCTL_PRODUCT_MAX_REQUEST_SIZE +
                                  MESHCTL_PRODUCT_MAX_RESPONSE_HEADER_SIZE;
  config.network.receive_buffer_bytes = 16384u;
  config.network.connect_timeout_ms = timeout_ms;
  config.network.read_timeout_ms = timeout_ms;
  config.network.write_timeout_ms = timeout_ms;
  config.network.tls_io_buffer_bytes = CNET_TLS_MIN_IO_BUFFER_BYTES;
  config.network.tls_handshake_timeout_ms = timeout_ms;
  config.request_capacity = 1u;
  config.max_start_line_bytes = MESHCTL_PRODUCT_ENDPOINT_CAPACITY +
                                 MESHCTL_PRODUCT_ROUTE_CAPACITY;
  config.max_header_count = MESHCTL_PRODUCT_MAX_RESPONSE_HEADER_SIZE / 4u;
  config.max_header_bytes = MESHCTL_PRODUCT_MAX_RESPONSE_HEADER_SIZE;
  config.max_request_body_bytes = MESHCTL_PRODUCT_MAX_REQUEST_SIZE;
  config.max_response_body_bytes = MESHCTL_PRODUCT_MAX_RESPONSE_SIZE;
  config.max_informational_responses = 8u;
  return config;
}

meshctl_controller_result_t meshctl_controller_request_http2(
    void *context, const meshctl_product_common_options_t *options,
    const meshctl_controller_request_t *request, uint32_t remaining_ms,
    meshctl_controller_response_t *out_response) {
  static const char *const alpn[] = {"h2"};
  const chttp_header headers[] = {
      {"Accept", MESHCTL_PRODUCT_MEDIA_TYPE},
      {"Content-Type", MESHCTL_PRODUCT_MEDIA_TYPE}};
  chttp_client client = {0};
  chttp_response response = {0};
  chttp_error error = {0};
  chttp_tls_profile profile = {0};
  cnet_tls_client_config tls = {0};
  chttp_options http_options = {0};
  chttp_client_config config;
  json_value_t *json = NULL;
  tstr uri = NULL;
  tstr authority = NULL;
  size_t endpoint_size;
  int status;
  meshctl_controller_result_t result = MESHCTL_CONTROLLER_TRANSPORT_ERROR;
  (void)context;
  if (!options || !meshctl_controller_endpoint_valid(options->endpoint) ||
      !meshctl_controller_credential_file_valid(options->ca_file, 0) ||
      !meshctl_controller_credential_file_valid(options->cert_file, 0) ||
      !meshctl_controller_credential_file_valid(options->key_file, 1) ||
      !request || !route_valid(request->route) || !out_response ||
      !remaining_ms || remaining_ms > MESHCTL_PRODUCT_MAX_TIMEOUT_MS)
    return MESHCTL_CONTROLLER_INVALID_ARGUMENT;
  if (request->method == MESHCTL_CONTROLLER_METHOD_GET) {
    if (request->body || request->body_size || request->content_type)
      return MESHCTL_CONTROLLER_INVALID_ARGUMENT;
    http_options.header_count = 1u;
  } else if (request->method == MESHCTL_CONTROLLER_METHOD_POST) {
    if (!request->body || !request->body_size ||
        request->body_size > MESHCTL_PRODUCT_MAX_REQUEST_SIZE ||
        !request->content_type ||
        strcmp(request->content_type, MESHCTL_PRODUCT_MEDIA_TYPE) != 0)
      return MESHCTL_CONTROLLER_INVALID_ARGUMENT;
    http_options.header_count = 2u;
  } else return MESHCTL_CONTROLLER_INVALID_ARGUMENT;
  memset(out_response, 0, sizeof(*out_response));
  endpoint_size = strlen(options->endpoint);
  if (options->endpoint[endpoint_size - 1u] == '/') --endpoint_size;
  /* Keep the original authority, including bracketed IPv6 and explicit port.
   * The validated https scheme is replaced only at the CNet boundary. */
  authority = tstr_new_len(options->endpoint + 8u, endpoint_size - 8u);
  if (!authority) { result = MESHCTL_CONTROLLER_NO_MEMORY; goto cleanup; }
  uri = tstr_format("tls://{}", authority);
  if (!uri) { result = MESHCTL_CONTROLLER_NO_MEMORY; goto cleanup; }
  tls.size = sizeof(tls);
  tls.ca_file = options->ca_file;
  tls.cert_file = options->cert_file;
  tls.key_file = options->key_file;
  tls.alpn_protocols = alpn;
  tls.alpn_protocol_count = 1u;
  status = chttp_tls_profile_init(&profile, &tls);
  if (status != SALTS_OK) {
    result = status == SALTS_ENOMEM ? MESHCTL_CONTROLLER_NO_MEMORY :
                                     MESHCTL_CONTROLLER_INVALID_ARGUMENT;
    goto cleanup;
  }
  config = controller_config(remaining_ms);
  status = chttp_client_init(&client, &config);
  if (status != SALTS_OK) {
    if (status == SALTS_ENOMEM) result = MESHCTL_CONTROLLER_NO_MEMORY;
    goto cleanup;
  }
  http_options.connection_uri = uri;
  http_options.authority = authority;
  http_options.target = request->route;
  http_options.headers = headers;
  http_options.body = request->body;
  http_options.body_size = request->body_size;
  http_options.timeout_ms = remaining_ms;
  http_options.tls = &profile;
  http_options.protocol = CHTTP_HTTP_2;
  /* Exactly one attempt. HTTP status, ALPN failure and terminal timeout never
   * cause a redirect, protocol downgrade or business request resubmission. */
  status = request->method == MESHCTL_CONTROLLER_METHOD_GET ?
      chttp_get(&client, &http_options, &response, &error) :
      chttp_post(&client, &http_options, &response, &error);
  if (status != SALTS_OK) {
    if (status == SALTS_ETIMEDOUT) result = MESHCTL_CONTROLLER_TIMEOUT;
    else if (status == SALTS_ENOMEM) result = MESHCTL_CONTROLLER_NO_MEMORY;
    goto cleanup;
  }
  if (response.http_major != 2u || !response.body || !response.body_size ||
      response.body_size > MESHCTL_PRODUCT_MAX_RESPONSE_SIZE ||
      !(json = json_parse(response.body, response.body_size))) {
    result = MESHCTL_CONTROLLER_PROTOCOL_ERROR;
    goto cleanup;
  }
  out_response->body = malloc(response.body_size + 1u);
  if (!out_response->body) { result = MESHCTL_CONTROLLER_NO_MEMORY; goto cleanup; }
  memcpy(out_response->body, response.body, response.body_size);
  out_response->body[response.body_size] = '\0';
  out_response->body_size = response.body_size;
  out_response->status_code = (int)response.status_code;
  result = MESHCTL_CONTROLLER_OK;
cleanup:
  json_free(json);
  chttp_response_destroy(&response);
  /* A timeout retains this sole progress owner. Finish terminal drain before
   * freeing stack storage or releasing the TLS profile. No HTTP retry here. */
  do { status = chttp_client_destroy(&client, MESHCTL_PRODUCT_DEFAULT_TIMEOUT_MS); }
  while (status == SALTS_ETIMEDOUT);
  if (status != SALTS_OK) {
    TLOG_FATALF("Controller client shutdown failed: status={}", status);
    abort();
  }
  status = chttp_tls_profile_destroy(&profile);
  if (status != SALTS_OK) {
    TLOG_FATALF("Controller TLS profile release failed: status={}", status);
    abort();
  }
  tstr_free(uri);
  tstr_free(authority);
  if (result != MESHCTL_CONTROLLER_OK)
    meshctl_controller_response_destroy(out_response);
  return result;
}

meshctl_controller_result_t meshctl_controller_query_http2(
    void *context, const meshctl_product_common_options_t *options,
    const char *route, uint32_t remaining_ms,
    meshctl_controller_response_t *out_response) {
  meshctl_controller_request_t request = {0};
  request.method = MESHCTL_CONTROLLER_METHOD_GET;
  request.route = route;
  return meshctl_controller_request_http2(context, options, &request,
                                        remaining_ms, out_response);
}
