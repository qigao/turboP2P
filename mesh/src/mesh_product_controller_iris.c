#include "mesh_product_controller_iris.h"

#include <turbo_parser.h>
#include <turbo_selector.h>
#include <platform.h>

#include <openssl/evp.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
  MESH_PRODUCT_CONTROLLER_MAX_RESPONSE_BYTES_V1 = 1024 * 1024,
  MESH_PRODUCT_CONTROLLER_MAX_PAGE_ITEMS_V1 = 1000,
  MESH_PRODUCT_CONTROLLER_MAX_PLAN_REQUEST_BYTES_V1 = 64 * 1024,
  MESH_PRODUCT_CONTROLLER_MAX_PLAN_TIMEOUT_MS_V1 = 120000,
  MESH_PRODUCT_CONTROLLER_SUBJECT_CAPACITY_V1 = 257,
  MESH_PRODUCT_CONTROLLER_ID_CAPACITY_V1 = 129,
  MESH_PRODUCT_CONTROLLER_SHA256_HEX_SIZE = 64
};

static const char MESH_PRODUCT_CONTROLLER_SHA256_PREFIX[] = "sha256:";
static const char *const MESH_PRODUCT_SELECTOR_FIELDS_V1[] = {
    "region", "role", "node.id", "node.name", "platform", "arch"};

static int identifier_valid(const char *value) {
  size_t index;
  size_t size;
  if (!value) return 0;
  size = strlen(value);
  if (size == 0u || size >= MESH_PRODUCT_CONTROLLER_ID_CAPACITY_V1) return 0;
  for (index = 0u; index < size; ++index) {
    unsigned char ch = (unsigned char)value[index];
    if (!isalnum(ch) && ch != '-' && ch != '_' && ch != '.') return 0;
  }
  return 1;
}

static int placement_subject_valid(const char *value) {
  static const char prefix[] = "release:";
  if (!value || strlen(value) >= MESH_PRODUCT_CONTROLLER_SUBJECT_CAPACITY_V1 ||
      strncmp(value, prefix, sizeof(prefix) - 1u) != 0)
    return 0;
  return identifier_valid(value + sizeof(prefix) - 1u);
}

static int certificate_digest_valid(const char *value) {
  size_t index;
  if (!value || strlen(value) != CORO_TLS_PEER_CERT_SHA256_CAPACITY - 1u)
    return 0;
  if (strncmp(value, MESH_PRODUCT_CONTROLLER_SHA256_PREFIX,
              sizeof(MESH_PRODUCT_CONTROLLER_SHA256_PREFIX) - 1u) != 0)
    return 0;
  for (index = sizeof(MESH_PRODUCT_CONTROLLER_SHA256_PREFIX) - 1u;
       index < CORO_TLS_PEER_CERT_SHA256_CAPACITY - 1u; ++index) {
    unsigned char ch = (unsigned char)value[index];
    if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')))
      return 0;
  }
  return index - (sizeof(MESH_PRODUCT_CONTROLLER_SHA256_PREFIX) - 1u) ==
         MESH_PRODUCT_CONTROLLER_SHA256_HEX_SIZE;
}

static int parse_page_limit(const char *value, uint32_t maximum,
                            uint32_t *out_value) {
  uint32_t parsed = 0u;
  const unsigned char *cursor = (const unsigned char *)value;
  if (!value || value[0] == '\0' || !out_value) return 0;
  while (*cursor != '\0') {
    uint32_t digit;
    if (*cursor < '0' || *cursor > '9') return 0;
    digit = (uint32_t)(*cursor - '0');
    if (parsed > (UINT32_MAX - digit) / 10u) return 0;
    parsed = parsed * 10u + digit;
    ++cursor;
  }
  if (parsed == 0u || parsed > maximum) return 0;
  *out_value = parsed;
  return 1;
}

mesh_control_result_t mesh_product_controller_iris_query_v1(
    mesh_product_controller_iris_v1_t *adapter,
    const char *peer_certificate_sha256,
    mesh_product_query_kind_v1_t query_kind, const char *mesh,
    const char *resource_id, uint32_t page_limit, char *output,
    size_t output_capacity, size_t *out_size) {
  mesh_control_result_t result;
  size_t produced = 0u;
  turbo_json_doc_t *json = NULL;
  if (out_size) *out_size = 0u;
  if (!adapter || !adapter->initialized ||
      !certificate_digest_valid(peer_certificate_sha256) ||
      !identifier_valid(mesh) || !out_size || !output ||
      output_capacity == 0u ||
      (query_kind != MESH_PRODUCT_QUERY_NODES_LIST &&
       query_kind != MESH_PRODUCT_QUERY_NODE_GET &&
       query_kind != MESH_PRODUCT_QUERY_OPERATION_GET &&
       query_kind != MESH_PRODUCT_QUERY_NETWORKS_LIST &&
       query_kind != MESH_PRODUCT_QUERY_NETWORK_GET) ||
      ((query_kind == MESH_PRODUCT_QUERY_NODES_LIST ||
        query_kind == MESH_PRODUCT_QUERY_NETWORKS_LIST)
           ? page_limit == 0u || page_limit > adapter->config.max_page_items ||
                 resource_id != NULL
           : page_limit != 0u || !identifier_valid(resource_id))) {
    return MESH_CONTROL_INVALID_ARG;
  }
  if (!atomic_load_explicit(&adapter->accepting, memory_order_acquire))
    return MESH_CONTROL_CLOSED;
  atomic_fetch_add_explicit(&adapter->received, 1u, memory_order_relaxed);
  result = adapter->config.authorize(adapter->config.context,
                                     peer_certificate_sha256, mesh, query_kind);
  if (result != MESH_CONTROL_OK) {
    atomic_fetch_add_explicit(&adapter->rejected_auth, 1u,
                              memory_order_relaxed);
    return result;
  }
  atomic_fetch_add_explicit(&adapter->authorized, 1u, memory_order_relaxed);
  result = adapter->config.query(
      adapter->config.context, query_kind, mesh, resource_id, page_limit,
      output, output_capacity, &produced);
  if (result != MESH_CONTROL_OK || produced == 0u ||
      produced > output_capacity ||
      produced > adapter->config.max_response_bytes) {
    atomic_fetch_add_explicit(&adapter->rejected_source, 1u,
                              memory_order_relaxed);
    memset(output, 0, output_capacity);
    *out_size = produced;
    return result == MESH_CONTROL_OK ? MESH_CONTROL_INVALID_STATE : result;
  }
  if (turbo_parse_json((const uint8_t *)output, produced, &json) != 0 || !json) {
    atomic_fetch_add_explicit(&adapter->rejected_source, 1u,
                              memory_order_relaxed);
    memset(output, 0, produced);
    return MESH_CONTROL_INVALID_STATE;
  }
  turbo_free_json(&json);
  *out_size = produced;
  atomic_fetch_add_explicit(&adapter->succeeded, 1u, memory_order_relaxed);
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_product_controller_iris_plan_v1(
    mesh_product_controller_iris_v1_t *adapter,
    const char *peer_certificate_sha256, const char *mesh,
    const char *subject, uint32_t selector_language_version,
    const char *selector, size_t selector_size, char *output,
    size_t output_capacity, size_t *out_size) {
  turbo_selector_schema_v1_t schema;
  turbo_selector_diagnostic_v1_t selector_diagnostic;
  turbo_selector_program_t *program = NULL;
  mesh_product_placement_plan_v1_t request;
  turbo_json_doc_t *json = NULL;
  char *canonical = NULL;
  size_t canonical_size = 0u;
  size_t produced = 0u;
  mesh_control_result_t result;
  int selector_result;
  if (out_size) *out_size = 0u;
  if (!adapter || !adapter->initialized || !adapter->config.plan ||
      !certificate_digest_valid(peer_certificate_sha256) ||
      !identifier_valid(mesh) || !placement_subject_valid(subject) ||
      selector_language_version != TURBO_SELECTOR_LANGUAGE_VERSION_V1 ||
      !selector || selector_size == 0u ||
      selector_size > TURBO_SELECTOR_MAX_SOURCE_BYTES_V1 ||
      memchr(selector, '\0', selector_size) != NULL || !output ||
      output_capacity == 0u || !out_size)
    return MESH_CONTROL_INVALID_ARG;
  if (!atomic_load_explicit(&adapter->accepting, memory_order_acquire))
    return MESH_CONTROL_CLOSED;
  atomic_fetch_add_explicit(&adapter->received, 1u, memory_order_relaxed);
  result = adapter->config.authorize(
      adapter->config.context, peer_certificate_sha256, mesh,
      MESH_PRODUCT_QUERY_PLACEMENT_PLAN);
  if (result != MESH_CONTROL_OK) {
    atomic_fetch_add_explicit(&adapter->rejected_auth, 1u,
                              memory_order_relaxed);
    return result;
  }
  atomic_fetch_add_explicit(&adapter->authorized, 1u, memory_order_relaxed);
  memset(&schema, 0, sizeof(schema));
  schema.size = TURBO_SELECTOR_SCHEMA_V1_SIZE;
  schema.allowed_fields = MESH_PRODUCT_SELECTOR_FIELDS_V1;
  schema.allowed_field_count = sizeof(MESH_PRODUCT_SELECTOR_FIELDS_V1) /
                               sizeof(MESH_PRODUCT_SELECTOR_FIELDS_V1[0]);
  schema.allow_tag_fields = 1;
  memset(&selector_diagnostic, 0, sizeof(selector_diagnostic));
  selector_diagnostic.size = TURBO_SELECTOR_DIAGNOSTIC_V1_SIZE;
  selector_result = turbo_selector_compile_v1(
      selector, selector_size, &schema, &program, &selector_diagnostic);
  if (selector_result != TURBO_SELECTOR_OK) {
    atomic_fetch_add_explicit(&adapter->rejected_input, 1u,
                              memory_order_relaxed);
    return selector_result == TURBO_SELECTOR_RESOURCE_LIMIT
               ? MESH_CONTROL_RESOURCE_EXHAUSTED
               : MESH_CONTROL_INVALID_ARG;
  }
  selector_result = turbo_selector_program_canonical_v1(
      program, NULL, 0u, &canonical_size, &selector_diagnostic);
  if (selector_result != TURBO_SELECTOR_OK ||
      canonical_size > TURBO_SELECTOR_MAX_CANONICAL_BYTES_V1) {
    result = MESH_CONTROL_RESOURCE_EXHAUSTED;
    goto cleanup;
  }
  canonical = (char *)malloc(canonical_size + 1u);
  if (!canonical) {
    result = MESH_CONTROL_RESOURCE_EXHAUSTED;
    goto cleanup;
  }
  selector_result = turbo_selector_program_canonical_v1(
      program, canonical, canonical_size + 1u, &canonical_size,
      &selector_diagnostic);
  if (selector_result != TURBO_SELECTOR_OK) {
    result = MESH_CONTROL_INVALID_STATE;
    goto cleanup;
  }
  memset(&request, 0, sizeof(request));
  request.selector_language_version = TURBO_SELECTOR_LANGUAGE_VERSION_V1;
  request.subject = subject;
  request.selector = canonical;
  {
    unsigned int digest_size = 0u;
    if (EVP_Digest(canonical, canonical_size, request.selector_digest,
                   &digest_size, EVP_sha256(), NULL) != 1 ||
        digest_size != MESH_PRODUCT_SELECTOR_DIGEST_SIZE_V1) {
      result = MESH_CONTROL_INVALID_STATE;
      goto cleanup;
    }
  }
  request.selector_program = program;
  request.predicate_count =
      turbo_selector_program_predicate_count(program);
  request.deadline_ms = turbo_monotonic_ms();
  if (request.deadline_ms > UINT64_MAX - adapter->config.plan_timeout_ms) {
    result = MESH_CONTROL_INVALID_STATE;
    goto cleanup;
  }
  request.deadline_ms += adapter->config.plan_timeout_ms;
  result = adapter->config.plan(adapter->config.context, mesh, &request,
                                output, output_capacity, &produced);
  if (result != MESH_CONTROL_OK || produced == 0u ||
      produced > output_capacity ||
      produced > adapter->config.max_response_bytes) {
    atomic_fetch_add_explicit(&adapter->rejected_source, 1u,
                              memory_order_relaxed);
    memset(output, 0, output_capacity);
    *out_size = produced;
    result = result == MESH_CONTROL_OK ? MESH_CONTROL_INVALID_STATE : result;
    goto cleanup;
  }
  if (turbo_parse_json((const uint8_t *)output, produced, &json) != 0 || !json) {
    atomic_fetch_add_explicit(&adapter->rejected_source, 1u,
                              memory_order_relaxed);
    memset(output, 0, produced);
    result = MESH_CONTROL_INVALID_STATE;
    goto cleanup;
  }
  *out_size = produced;
  atomic_fetch_add_explicit(&adapter->succeeded, 1u, memory_order_relaxed);
  result = MESH_CONTROL_OK;

cleanup:
  turbo_free_json(&json);
  free(canonical);
  turbo_selector_program_destroy(program);
  return result;
}

static mesh_product_controller_iris_v1_t *adapter_from_request(Req *req,
                                                                const char *path) {
  if (!req || !req->app) return NULL;
  return (mesh_product_controller_iris_v1_t *)iris_app_lookup_rpc_context(
      req->app, path);
}

static void send_error(Res *res, int status, const char *code) {
  char body[192];
  int written = snprintf(body, sizeof(body),
                         "{\"code\":\"%s\",\"message\":\"request rejected\"}",
                         code);
  if (written < 0 || (size_t)written >= sizeof(body)) {
    reply(res, 500, MESH_PRODUCT_CONTROLLER_MEDIA_TYPE_V1, NULL, 0u);
    return;
  }
  reply(res, status, MESH_PRODUCT_CONTROLLER_MEDIA_TYPE_V1, body,
        (size_t)written);
}

static void handle_query(Req *req, Res *res, const char *binding_path,
                         mesh_product_query_kind_v1_t query_kind) {
  mesh_product_controller_iris_v1_t *adapter =
      adapter_from_request(req, binding_path);
  char certificate[CORO_TLS_PEER_CERT_SHA256_CAPACITY];
  const char *mesh;
  const char *resource_id = NULL;
  const char *limit_text;
  uint32_t page_limit = 0u;
  char *output = NULL;
  size_t output_size = 0u;
  mesh_control_result_t result;
  if (!adapter || !adapter->initialized ||
      !atomic_load_explicit(&adapter->accepting, memory_order_acquire)) {
    send_error(res, 503, "UNAVAILABLE");
    return;
  }
  memset(certificate, 0, sizeof(certificate));
  if (req_get_verified_tls_peer_certificate_sha256(req, certificate) != 0) {
    atomic_fetch_add_explicit(&adapter->rejected_auth, 1u,
                              memory_order_relaxed);
    send_error(res, 403, "MTLS_REQUIRED");
    return;
  }
  mesh = get_params(req, "mesh");
  if (query_kind == MESH_PRODUCT_QUERY_NODE_GET)
    resource_id = get_params(req, "node");
  else if (query_kind == MESH_PRODUCT_QUERY_OPERATION_GET)
    resource_id = get_params(req, "operation");
  else if (query_kind == MESH_PRODUCT_QUERY_NETWORK_GET)
    resource_id = get_params(req, "network");
  if (query_kind == MESH_PRODUCT_QUERY_NODES_LIST ||
      query_kind == MESH_PRODUCT_QUERY_NETWORKS_LIST) {
    limit_text = get_query(req, "limit");
    if (!parse_page_limit(limit_text, adapter->config.max_page_items,
                          &page_limit)) {
      atomic_fetch_add_explicit(&adapter->rejected_input, 1u,
                                memory_order_relaxed);
      send_error(res, 400, "INVALID_LIMIT");
      return;
    }
  }
  output = (char *)malloc(adapter->config.max_response_bytes);
  if (!output) {
    send_error(res, 503, "RESOURCE_EXHAUSTED");
    return;
  }
  result = mesh_product_controller_iris_query_v1(
      adapter, certificate, query_kind, mesh, resource_id, page_limit, output,
      adapter->config.max_response_bytes, &output_size);
  if (result == MESH_CONTROL_OK)
    reply(res, 200, MESH_PRODUCT_CONTROLLER_MEDIA_TYPE_V1, output, output_size);
  else if (result == MESH_CONTROL_EMPTY)
    send_error(res, 404, "NOT_FOUND");
  else if (result == MESH_CONTROL_CONFLICT ||
           result == MESH_CONTROL_UNAUTHORIZED)
    send_error(res, 403, "FORBIDDEN");
  else if (result == MESH_CONTROL_INVALID_ARG)
    send_error(res, 400, "INVALID_ARGUMENT");
  else if (result == MESH_CONTROL_RESOURCE_EXHAUSTED)
    send_error(res, 503, "RESOURCE_EXHAUSTED");
  else
    send_error(res, 503, "UNAVAILABLE");
  free(output);
}

static void nodes_list_handler(Req *req, Res *res) {
  handle_query(req, res, MESH_PRODUCT_CONTROLLER_NODES_PATH_V1,
               MESH_PRODUCT_QUERY_NODES_LIST);
}

static void node_get_handler(Req *req, Res *res) {
  handle_query(req, res, MESH_PRODUCT_CONTROLLER_NODE_PATH_V1,
               MESH_PRODUCT_QUERY_NODE_GET);
}

static void operation_get_handler(Req *req, Res *res) {
  handle_query(req, res, MESH_PRODUCT_CONTROLLER_OPERATION_PATH_V1,
               MESH_PRODUCT_QUERY_OPERATION_GET);
}

static void networks_list_handler(Req *req, Res *res) {
  handle_query(req, res, MESH_PRODUCT_CONTROLLER_NETWORKS_PATH_V1,
               MESH_PRODUCT_QUERY_NETWORKS_LIST);
}

static void network_get_handler(Req *req, Res *res) {
  handle_query(req, res, MESH_PRODUCT_CONTROLLER_NETWORK_PATH_V1,
               MESH_PRODUCT_QUERY_NETWORK_GET);
}

static int json_number_is_one(const json_value_t *value) {
  const char *text;
  size_t size = 0u;
  if (!value || turbo_json_type(value) != TURBO_JSON_NUMBER) return 0;
  text = turbo_json_number_text(value, &size);
  return text && size == 1u && text[0] == '1';
}

static int json_number_to_u32(const json_value_t *value, uint32_t minimum,
                              uint32_t maximum, uint32_t *out_value) {
  const char *text;
  size_t size = 0u;
  size_t index;
  uint32_t parsed = 0u;
  if (!value || !out_value || minimum > maximum ||
      turbo_json_type(value) != TURBO_JSON_NUMBER)
    return 0;
  text = turbo_json_number_text(value, &size);
  if (!text || size == 0u) return 0;
  for (index = 0u; index < size; ++index) {
    uint32_t digit;
    if (text[index] < '0' || text[index] > '9') return 0;
    digit = (uint32_t)(text[index] - '0');
    if (parsed > (UINT32_MAX - digit) / 10u) return 0;
    parsed = parsed * 10u + digit;
  }
  if (parsed < minimum || parsed > maximum) return 0;
  *out_value = parsed;
  return 1;
}

static int network_json_shape_valid(const json_value_t *root,
                                    mesh_product_query_kind_v1_t kind,
                                    uint32_t *out_drain_timeout_ms) {
  unsigned int seen = 0u;
  size_t index;
  if (!root || !out_drain_timeout_ms ||
      turbo_json_type(root) != TURBO_JSON_OBJECT)
    return 0;
  *out_drain_timeout_ms = 0u;
  for (index = 0u; index < turbo_json_object_size(root); ++index) {
    const char *key = turbo_json_object_key(root, index);
    unsigned int bit = 0u;
    if (!key) return 0;
    if (strcmp(key, "schema_version") == 0)
      bit = 1u;
    else if (strcmp(key, "drain_timeout_ms") == 0) {
      if (kind != MESH_PRODUCT_QUERY_NETWORK_DELETE) return 0;
      bit = 2u;
    } else if (kind == MESH_PRODUCT_QUERY_NETWORK_DELETE)
      return 0;
    if (bit != 0u && (seen & bit) != 0u) return 0;
    seen |= bit;
  }
  if ((seen & 1u) == 0u) return 0;
  if (kind != MESH_PRODUCT_QUERY_NETWORK_DELETE) return 1;
  return turbo_json_object_size(root) == 2u && seen == 3u &&
         json_number_to_u32(
             turbo_json_object_get(root, "drain_timeout_ms"), 1u,
             MESH_PRODUCT_NETWORK_DRAIN_MAX_MS_V1, out_drain_timeout_ms);
}

static int placement_plan_json_fields_valid(const json_value_t *root) {
  unsigned int seen = 0u;
  size_t index;
  if (!root || turbo_json_type(root) != TURBO_JSON_OBJECT ||
      turbo_json_object_size(root) != 4u)
    return 0;
  for (index = 0u; index < turbo_json_object_size(root); ++index) {
    const char *key = turbo_json_object_key(root, index);
    unsigned int bit;
    if (!key) return 0;
    if (strcmp(key, "schema_version") == 0)
      bit = 1u;
    else if (strcmp(key, "subject") == 0)
      bit = 2u;
    else if (strcmp(key, "selector_language_version") == 0)
      bit = 4u;
    else if (strcmp(key, "selector") == 0)
      bit = 8u;
    else
      return 0;
    if ((seen & bit) != 0u) return 0;
    seen |= bit;
  }
  return seen == 15u;
}

mesh_control_result_t mesh_product_controller_iris_plan_json_v1(
    mesh_product_controller_iris_v1_t *adapter,
    const char *peer_certificate_sha256, const char *mesh,
    const char *body, size_t body_size, char *output,
    size_t output_capacity, size_t *out_size) {
  turbo_json_doc_t *json = NULL;
  json_value_t *schema_version;
  json_value_t *language_version;
  json_value_t *subject_value;
  json_value_t *selector_value;
  const char *subject;
  const char *selector;
  size_t subject_size;
  size_t selector_size;
  mesh_control_result_t result;
  if (out_size) *out_size = 0u;
  if (!adapter || !adapter->initialized || !adapter->config.plan || !body ||
      body_size == 0u || body_size > adapter->config.max_plan_request_bytes ||
      !output || output_capacity == 0u || !out_size ||
      turbo_parse_json((const uint8_t *)body, body_size, &json) != 0 ||
      !placement_plan_json_fields_valid((json_value_t *)json)) {
    if (adapter && adapter->initialized)
      atomic_fetch_add_explicit(&adapter->rejected_input, 1u,
                                memory_order_relaxed);
    turbo_free_json(&json);
    return MESH_CONTROL_INVALID_ARG;
  }
  schema_version = turbo_json_object_get((json_value_t *)json,
                                         "schema_version");
  language_version = turbo_json_object_get(
      (json_value_t *)json, "selector_language_version");
  subject_value = turbo_json_object_get((json_value_t *)json, "subject");
  selector_value = turbo_json_object_get((json_value_t *)json, "selector");
  if (!json_number_is_one(schema_version) ||
      !json_number_is_one(language_version) || !subject_value ||
      turbo_json_type(subject_value) != TURBO_JSON_STRING || !selector_value ||
      turbo_json_type(selector_value) != TURBO_JSON_STRING) {
    atomic_fetch_add_explicit(&adapter->rejected_input, 1u,
                              memory_order_relaxed);
    turbo_free_json(&json);
    return MESH_CONTROL_INVALID_ARG;
  }
  subject = turbo_json_string(subject_value);
  subject_size = turbo_json_string_len(subject_value);
  selector = turbo_json_string(selector_value);
  selector_size = turbo_json_string_len(selector_value);
  if (!subject || subject_size == 0u ||
      memchr(subject, '\0', subject_size) != NULL || !selector ||
      selector_size == 0u || memchr(selector, '\0', selector_size) != NULL) {
    atomic_fetch_add_explicit(&adapter->rejected_input, 1u,
                              memory_order_relaxed);
    turbo_free_json(&json);
    return MESH_CONTROL_INVALID_ARG;
  }
  result = mesh_product_controller_iris_plan_v1(
      adapter, peer_certificate_sha256, mesh, subject,
      TURBO_SELECTOR_LANGUAGE_VERSION_V1, selector, selector_size, output,
      output_capacity, out_size);
  turbo_free_json(&json);
  return result;
}

mesh_control_result_t mesh_product_controller_iris_network_json_v1(
    mesh_product_controller_iris_v1_t *adapter,
    const char *peer_certificate_sha256, const char *mesh,
    mesh_product_query_kind_v1_t kind, const char *network,
    const char *body, size_t body_size, char *output,
    size_t output_capacity, size_t *out_size) {
  turbo_json_doc_t *json = NULL;
  json_value_t *schema_version;
  mesh_product_network_request_v1_t request;
  mesh_control_result_t result;
  size_t produced = 0u;
  uint32_t drain_timeout_ms = 0u;
  if (out_size) *out_size = 0u;
  if (!adapter || !adapter->initialized || !adapter->config.network ||
      !certificate_digest_valid(peer_certificate_sha256) ||
      !identifier_valid(mesh) ||
      (kind != MESH_PRODUCT_QUERY_NETWORK_PLAN &&
       kind != MESH_PRODUCT_QUERY_NETWORK_APPLY &&
       kind != MESH_PRODUCT_QUERY_NETWORK_DELETE) ||
      (kind == MESH_PRODUCT_QUERY_NETWORK_DELETE
           ? !identifier_valid(network)
           : network != NULL) ||
      !body || body_size == 0u ||
      body_size > adapter->config.max_network_request_bytes || !output ||
      output_capacity == 0u || !out_size ||
      turbo_parse_json((const uint8_t *)body, body_size, &json) != 0 ||
      !json || turbo_json_type((json_value_t *)json) != TURBO_JSON_OBJECT) {
    if (adapter && adapter->initialized)
      atomic_fetch_add_explicit(&adapter->rejected_input, 1u,
                                memory_order_relaxed);
    turbo_free_json(&json);
    return MESH_CONTROL_INVALID_ARG;
  }
  schema_version =
      turbo_json_object_get((json_value_t *)json, "schema_version");
  if (!json_number_is_one(schema_version) ||
      !network_json_shape_valid((json_value_t *)json, kind,
                                &drain_timeout_ms)) {
    atomic_fetch_add_explicit(&adapter->rejected_input, 1u,
                              memory_order_relaxed);
    turbo_free_json(&json);
    return MESH_CONTROL_INVALID_ARG;
  }
  if (!atomic_load_explicit(&adapter->accepting, memory_order_acquire)) {
    turbo_free_json(&json);
    return MESH_CONTROL_CLOSED;
  }
  atomic_fetch_add_explicit(&adapter->received, 1u, memory_order_relaxed);
  result = adapter->config.authorize(adapter->config.context,
                                     peer_certificate_sha256, mesh, kind);
  if (result != MESH_CONTROL_OK) {
    atomic_fetch_add_explicit(&adapter->rejected_auth, 1u,
                              memory_order_relaxed);
    turbo_free_json(&json);
    return result;
  }
  atomic_fetch_add_explicit(&adapter->authorized, 1u, memory_order_relaxed);
  memset(&request, 0, sizeof(request));
  request.kind = kind;
  request.network = network;
  request.document = body;
  request.document_size = body_size;
  request.drain_timeout_ms = drain_timeout_ms;
  request.deadline_ms = turbo_monotonic_ms();
  if (request.deadline_ms > UINT64_MAX - adapter->config.network_timeout_ms) {
    atomic_fetch_add_explicit(&adapter->rejected_input, 1u,
                              memory_order_relaxed);
    turbo_free_json(&json);
    return MESH_CONTROL_INVALID_ARG;
  }
  request.deadline_ms += adapter->config.network_timeout_ms;
  result = adapter->config.network(adapter->config.context, mesh, &request,
                                   output, output_capacity, &produced);
  if (result != MESH_CONTROL_OK || produced == 0u ||
      produced > output_capacity ||
      produced > adapter->config.max_response_bytes) {
    atomic_fetch_add_explicit(&adapter->rejected_source, 1u,
                              memory_order_relaxed);
    memset(output, 0, output_capacity);
    *out_size = produced;
    turbo_free_json(&json);
    return result == MESH_CONTROL_OK ? MESH_CONTROL_INVALID_STATE : result;
  }
  turbo_free_json(&json);
  json = NULL;
  if (turbo_parse_json((const uint8_t *)output, produced, &json) != 0 ||
      !json) {
    atomic_fetch_add_explicit(&adapter->rejected_source, 1u,
                              memory_order_relaxed);
    memset(output, 0, produced);
    turbo_free_json(&json);
    return MESH_CONTROL_INVALID_STATE;
  }
  turbo_free_json(&json);
  *out_size = produced;
  atomic_fetch_add_explicit(&adapter->succeeded, 1u, memory_order_relaxed);
  return MESH_CONTROL_OK;
}

static void network_request_handler(Req *req, Res *res, const char *path,
                                    mesh_product_query_kind_v1_t kind) {
  mesh_product_controller_iris_v1_t *adapter = adapter_from_request(req, path);
  char certificate[CORO_TLS_PEER_CERT_SHA256_CAPACITY];
  const char *content_type;
  const char *network = NULL;
  char *output;
  size_t output_size = 0u;
  mesh_control_result_t result;
  if (!adapter || !adapter->initialized || !adapter->config.network ||
      !atomic_load_explicit(&adapter->accepting, memory_order_acquire)) {
    send_error(res, 503, "UNAVAILABLE");
    return;
  }
  content_type = get_headers(req, "Content-Type");
  if (!content_type ||
      strcmp(content_type, MESH_PRODUCT_CONTROLLER_MEDIA_TYPE_V1) != 0 ||
      !req->body || req->body_len == 0u ||
      req->body_len > adapter->config.max_network_request_bytes) {
    atomic_fetch_add_explicit(&adapter->rejected_input, 1u,
                              memory_order_relaxed);
    send_error(res, 400, "INVALID_NETWORK_REQUEST");
    return;
  }
  memset(certificate, 0, sizeof(certificate));
  if (req_get_verified_tls_peer_certificate_sha256(req, certificate) != 0) {
    atomic_fetch_add_explicit(&adapter->rejected_auth, 1u,
                              memory_order_relaxed);
    send_error(res, 403, "MTLS_REQUIRED");
    return;
  }
  if (kind == MESH_PRODUCT_QUERY_NETWORK_DELETE)
    network = get_params(req, "network");
  output = (char *)malloc(adapter->config.max_response_bytes);
  if (!output) {
    send_error(res, 503, "RESOURCE_EXHAUSTED");
    return;
  }
  result = mesh_product_controller_iris_network_json_v1(
      adapter, certificate, get_params(req, "mesh"), kind, network,
      req->body, req->body_len, output, adapter->config.max_response_bytes,
      &output_size);
  if (result == MESH_CONTROL_OK)
    reply(res, kind == MESH_PRODUCT_QUERY_NETWORK_PLAN ? 200 : 202,
          MESH_PRODUCT_CONTROLLER_MEDIA_TYPE_V1, output, output_size);
  else if (result == MESH_CONTROL_CONFLICT ||
           result == MESH_CONTROL_STALE_EPOCH)
    send_error(res, 409, "CONFLICT");
  else if (result == MESH_CONTROL_UNAUTHORIZED)
    send_error(res, 403, "FORBIDDEN");
  else if (result == MESH_CONTROL_RESOURCE_EXHAUSTED)
    send_error(res, 429, "RESOURCE_EXHAUSTED");
  else if (result == MESH_CONTROL_UNSUPPORTED)
    send_error(res, 422, "UNSUPPORTED");
  else if (result == MESH_CONTROL_INVALID_ARG)
    send_error(res, 400, "INVALID_NETWORK_REQUEST");
  else if (result == MESH_CONTROL_CLOSED)
    send_error(res, 503, "CLOSED");
  else if (result == MESH_CONTROL_UNKNOWN_COMMIT)
    send_error(res, 503, "UNKNOWN_COMMIT");
  else
    send_error(res, 503, "UNAVAILABLE");
  free(output);
}

static void network_plan_handler(Req *req, Res *res) {
  network_request_handler(req, res, MESH_PRODUCT_CONTROLLER_NETWORK_PLAN_PATH_V1,
                          MESH_PRODUCT_QUERY_NETWORK_PLAN);
}

static void network_apply_handler(Req *req, Res *res) {
  network_request_handler(req, res, MESH_PRODUCT_CONTROLLER_NETWORK_APPLY_PATH_V1,
                          MESH_PRODUCT_QUERY_NETWORK_APPLY);
}

static void network_delete_handler(Req *req, Res *res) {
  network_request_handler(req, res, MESH_PRODUCT_CONTROLLER_NETWORK_DELETE_PATH_V1,
                          MESH_PRODUCT_QUERY_NETWORK_DELETE);
}

static void placement_plan_handler(Req *req, Res *res) {
  mesh_product_controller_iris_v1_t *adapter = adapter_from_request(
      req, MESH_PRODUCT_CONTROLLER_PLACEMENT_PLAN_PATH_V1);
  const char *content_type;
  char certificate[CORO_TLS_PEER_CERT_SHA256_CAPACITY];
  char *output = NULL;
  size_t output_size = 0u;
  mesh_control_result_t result;
  if (!adapter || !adapter->initialized || !adapter->config.plan ||
      !atomic_load_explicit(&adapter->accepting, memory_order_acquire)) {
    send_error(res, 503, "UNAVAILABLE");
    return;
  }
  content_type = get_headers(req, "Content-Type");
  if (!content_type ||
      strcmp(content_type, MESH_PRODUCT_CONTROLLER_MEDIA_TYPE_V1) != 0 ||
      !req->body || req->body_len == 0u ||
      req->body_len > adapter->config.max_plan_request_bytes) {
    atomic_fetch_add_explicit(&adapter->rejected_input, 1u,
                              memory_order_relaxed);
    send_error(res, 400, "INVALID_PLAN_REQUEST");
    return;
  }
  memset(certificate, 0, sizeof(certificate));
  if (req_get_verified_tls_peer_certificate_sha256(req, certificate) != 0) {
    atomic_fetch_add_explicit(&adapter->rejected_auth, 1u,
                              memory_order_relaxed);
    send_error(res, 403, "MTLS_REQUIRED");
    return;
  }
  output = (char *)malloc(adapter->config.max_response_bytes);
  if (!output) {
    send_error(res, 503, "RESOURCE_EXHAUSTED");
    return;
  }
  result = mesh_product_controller_iris_plan_json_v1(
      adapter, certificate, get_params(req, "mesh"), req->body, req->body_len,
      output, adapter->config.max_response_bytes, &output_size);
  if (result == MESH_CONTROL_OK)
    reply(res, 200, MESH_PRODUCT_CONTROLLER_MEDIA_TYPE_V1, output, output_size);
  else if (result == MESH_CONTROL_CONFLICT)
    send_error(res, 403, "FORBIDDEN");
  else if (result == MESH_CONTROL_INVALID_ARG)
    send_error(res, 400, "INVALID_SELECTOR");
  else if (result == MESH_CONTROL_RESOURCE_EXHAUSTED)
    send_error(res, 429, "SELECTOR_RESOURCE_LIMIT");
  else
    send_error(res, 503, "UNAVAILABLE");
  free(output);
}

mesh_control_result_t mesh_product_controller_iris_register_v1(
    mesh_product_controller_iris_v1_t *adapter, iris_app_t *app,
    const mesh_product_controller_iris_config_v1_t *config) {
  if (!adapter || !app || !config || !config->authorize || !config->query ||
      config->max_response_bytes == 0u ||
      config->max_response_bytes >
          MESH_PRODUCT_CONTROLLER_MAX_RESPONSE_BYTES_V1 ||
      config->max_page_items == 0u ||
      config->max_page_items > MESH_PRODUCT_CONTROLLER_MAX_PAGE_ITEMS_V1 ||
      (config->plan &&
       (config->max_plan_request_bytes == 0u ||
        config->max_plan_request_bytes >
            MESH_PRODUCT_CONTROLLER_MAX_PLAN_REQUEST_BYTES_V1 ||
        config->plan_timeout_ms == 0u ||
        config->plan_timeout_ms >
            MESH_PRODUCT_CONTROLLER_MAX_PLAN_TIMEOUT_MS_V1)) ||
      (!config->plan && (config->max_plan_request_bytes != 0u ||
                         config->plan_timeout_ms != 0u)) ||
      (config->network &&
       (config->max_network_request_bytes == 0u ||
        config->max_network_request_bytes >
            MESH_PRODUCT_CONTROLLER_MAX_PLAN_REQUEST_BYTES_V1 ||
        config->network_timeout_ms == 0u ||
        config->network_timeout_ms >
            MESH_PRODUCT_CONTROLLER_MAX_PLAN_TIMEOUT_MS_V1)) ||
      (!config->network &&
       (config->max_network_request_bytes != 0u ||
        config->network_timeout_ms != 0u)))
    return MESH_CONTROL_INVALID_ARG;
  memset(adapter, 0, sizeof(*adapter));
  adapter->app = app;
  adapter->config = *config;
  atomic_init(&adapter->accepting, true);
  atomic_init(&adapter->received, 0u);
  atomic_init(&adapter->authorized, 0u);
  atomic_init(&adapter->succeeded, 0u);
  atomic_init(&adapter->rejected_auth, 0u);
  atomic_init(&adapter->rejected_input, 0u);
  atomic_init(&adapter->rejected_source, 0u);
  adapter->initialized = 1u;
  if (iris_app_bind_rpc_context(app, MESH_PRODUCT_CONTROLLER_NODES_PATH_V1,
                                adapter) != 0 ||
      iris_app_bind_rpc_context(app, MESH_PRODUCT_CONTROLLER_NODE_PATH_V1,
                                adapter) != 0 ||
      iris_app_bind_rpc_context(
          app, MESH_PRODUCT_CONTROLLER_OPERATION_PATH_V1, adapter) != 0) {
    mesh_product_controller_iris_destroy_v1(adapter);
    return MESH_CONTROL_CONFLICT;
  }
  if (iris_app_bind_rpc_context(
          app, MESH_PRODUCT_CONTROLLER_NETWORKS_PATH_V1, adapter) != 0 ||
      iris_app_bind_rpc_context(
          app, MESH_PRODUCT_CONTROLLER_NETWORK_PATH_V1, adapter) != 0) {
    mesh_product_controller_iris_destroy_v1(adapter);
    return MESH_CONTROL_CONFLICT;
  }
  if (config->plan &&
      iris_app_bind_rpc_context(
          app, MESH_PRODUCT_CONTROLLER_PLACEMENT_PLAN_PATH_V1, adapter) != 0) {
    mesh_product_controller_iris_destroy_v1(adapter);
    return MESH_CONTROL_CONFLICT;
  }
  if (config->network &&
      (iris_app_bind_rpc_context(
           app, MESH_PRODUCT_CONTROLLER_NETWORK_PLAN_PATH_V1, adapter) != 0 ||
       iris_app_bind_rpc_context(
           app, MESH_PRODUCT_CONTROLLER_NETWORK_APPLY_PATH_V1, adapter) != 0 ||
       iris_app_bind_rpc_context(
           app, MESH_PRODUCT_CONTROLLER_NETWORK_DELETE_PATH_V1, adapter) != 0)) {
    mesh_product_controller_iris_destroy_v1(adapter);
    return MESH_CONTROL_CONFLICT;
  }
  iris_app_get(app, MESH_PRODUCT_CONTROLLER_NODES_PATH_V1,
               nodes_list_handler);
  iris_app_get(app, MESH_PRODUCT_CONTROLLER_NODE_PATH_V1, node_get_handler);
  iris_app_get(app, MESH_PRODUCT_CONTROLLER_OPERATION_PATH_V1,
               operation_get_handler);
  iris_app_get(app, MESH_PRODUCT_CONTROLLER_NETWORKS_PATH_V1,
               networks_list_handler);
  iris_app_get(app, MESH_PRODUCT_CONTROLLER_NETWORK_PATH_V1,
               network_get_handler);
  if (config->plan)
    iris_app_post(app, MESH_PRODUCT_CONTROLLER_PLACEMENT_PLAN_PATH_V1,
                  placement_plan_handler);
  if (config->network) {
    iris_app_post(app, MESH_PRODUCT_CONTROLLER_NETWORK_PLAN_PATH_V1,
                  network_plan_handler);
    iris_app_post(app, MESH_PRODUCT_CONTROLLER_NETWORK_APPLY_PATH_V1,
                  network_apply_handler);
    iris_app_post(app, MESH_PRODUCT_CONTROLLER_NETWORK_DELETE_PATH_V1,
                  network_delete_handler);
  }
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_product_controller_iris_close_v1(
    mesh_product_controller_iris_v1_t *adapter) {
  if (!adapter || !adapter->initialized) return MESH_CONTROL_INVALID_ARG;
  atomic_store_explicit(&adapter->accepting, false, memory_order_release);
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_product_controller_iris_get_stats_v1(
    const mesh_product_controller_iris_v1_t *adapter,
    mesh_product_controller_iris_stats_v1_t *out_stats) {
  if (!adapter || !adapter->initialized || !out_stats)
    return MESH_CONTROL_INVALID_ARG;
  memset(out_stats, 0, sizeof(*out_stats));
  out_stats->accepting =
      atomic_load_explicit(&adapter->accepting, memory_order_acquire);
  out_stats->received =
      atomic_load_explicit(&adapter->received, memory_order_relaxed);
  out_stats->authorized =
      atomic_load_explicit(&adapter->authorized, memory_order_relaxed);
  out_stats->succeeded =
      atomic_load_explicit(&adapter->succeeded, memory_order_relaxed);
  out_stats->rejected_auth =
      atomic_load_explicit(&adapter->rejected_auth, memory_order_relaxed);
  out_stats->rejected_input =
      atomic_load_explicit(&adapter->rejected_input, memory_order_relaxed);
  out_stats->rejected_source =
      atomic_load_explicit(&adapter->rejected_source, memory_order_relaxed);
  return MESH_CONTROL_OK;
}

void mesh_product_controller_iris_destroy_v1(
    mesh_product_controller_iris_v1_t *adapter) {
  if (!adapter) return;
  if (adapter->initialized) {
    (void)mesh_product_controller_iris_close_v1(adapter);
    if (adapter->app) {
      (void)iris_app_unbind_rpc_context(
          adapter->app, MESH_PRODUCT_CONTROLLER_NODES_PATH_V1, adapter);
      (void)iris_app_unbind_rpc_context(
          adapter->app, MESH_PRODUCT_CONTROLLER_NODE_PATH_V1, adapter);
      (void)iris_app_unbind_rpc_context(
          adapter->app, MESH_PRODUCT_CONTROLLER_OPERATION_PATH_V1, adapter);
      (void)iris_app_unbind_rpc_context(
          adapter->app, MESH_PRODUCT_CONTROLLER_NETWORKS_PATH_V1, adapter);
      (void)iris_app_unbind_rpc_context(
          adapter->app, MESH_PRODUCT_CONTROLLER_NETWORK_PATH_V1, adapter);
      if (adapter->config.plan)
        (void)iris_app_unbind_rpc_context(
            adapter->app, MESH_PRODUCT_CONTROLLER_PLACEMENT_PLAN_PATH_V1,
            adapter);
      if (adapter->config.network) {
        (void)iris_app_unbind_rpc_context(
            adapter->app, MESH_PRODUCT_CONTROLLER_NETWORK_PLAN_PATH_V1,
            adapter);
        (void)iris_app_unbind_rpc_context(
            adapter->app, MESH_PRODUCT_CONTROLLER_NETWORK_APPLY_PATH_V1,
            adapter);
        (void)iris_app_unbind_rpc_context(
            adapter->app, MESH_PRODUCT_CONTROLLER_NETWORK_DELETE_PATH_V1,
            adapter);
      }
    }
  }
  memset(adapter, 0, sizeof(*adapter));
}
