#include "meshctl_product.h"

#include <turbo_http.h>
#include <turbo_parser.h>
#include <turbo_selector.h>
#include <turbo_fs.h>
#include <platform.h>

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

#define MESHCTL_PRODUCT_MEDIA_TYPE \
  "application/vnd.turbop2p.control+json;version=1"

static const char *const MESHCTL_SELECTOR_FIELDS_V1[] = {
    "region", "role", "node.id", "node.name", "platform", "arch"};

typedef struct {
  char *endpoint;
  char *mesh;
  char *ca_file;
  char *cert_file;
  char *key_file;
  int64_t timeout_ms;
  int64_t page_size;
  char *resource_id;
  char *placement_subject;
  char *selector;
  char *network_file;
  int64_t drain_timeout_ms;
  turbo_cmd_node_t *nodes_list;
  turbo_cmd_node_t *nodes_get;
  turbo_cmd_node_t *operations_get;
  turbo_cmd_node_t *placements_plan;
  turbo_cmd_node_t *networks_list;
  turbo_cmd_node_t *networks_get;
  turbo_cmd_node_t *networks_plan;
  turbo_cmd_node_t *networks_apply;
  turbo_cmd_node_t *networks_delete;
} meshctl_product_parse_storage_t;

typedef struct {
  char *buffer;
  size_t capacity;
  size_t size;
} meshctl_help_sink_t;

static void meshctl_diagnostic_set(
    meshctl_product_parse_diagnostic_t *diagnostic,
    meshctl_product_parse_status_t status, const char *code,
    const char *message);

static int meshctl_copy_string(char *destination, size_t capacity,
                               const char *source) {
  size_t size;
  if (!destination || capacity == 0u || !source) return -1;
  size = strlen(source);
  if (size == 0u || size >= capacity) return -1;
  memcpy(destination, source, size + 1u);
  return 0;
}

static int meshctl_identifier_valid(const char *value) {
  size_t index;
  size_t size;
  if (!value) return 0;
  size = strlen(value);
  if (size == 0u || size >= MESHCTL_PRODUCT_ID_CAPACITY) return 0;
  for (index = 0u; index < size; ++index) {
    unsigned char ch = (unsigned char)value[index];
    if (!isalnum(ch) && ch != '-' && ch != '_' && ch != '.') return 0;
  }
  return 1;
}

static int meshctl_placement_subject_valid(const char *value) {
  static const char prefix[] = "release:";
  const char *identifier;
  if (!value || strlen(value) >= MESHCTL_PRODUCT_SUBJECT_CAPACITY ||
      strncmp(value, prefix, sizeof(prefix) - 1u) != 0)
    return 0;
  identifier = value + sizeof(prefix) - 1u;
  return meshctl_identifier_valid(identifier);
}

static int meshctl_selector_canonicalize(
    const char *source, char *output, size_t output_capacity,
    meshctl_product_parse_diagnostic_t *diagnostic) {
  turbo_selector_schema_v1_t schema;
  turbo_selector_diagnostic_v1_t selector_diagnostic;
  turbo_selector_program_t *program = NULL;
  size_t required = 0u;
  int result;
  if (!source || !output || output_capacity == 0u || !diagnostic) return -1;
  memset(&schema, 0, sizeof(schema));
  schema.size = TURBO_SELECTOR_SCHEMA_V1_SIZE;
  schema.allowed_fields = MESHCTL_SELECTOR_FIELDS_V1;
  schema.allowed_field_count = sizeof(MESHCTL_SELECTOR_FIELDS_V1) /
                               sizeof(MESHCTL_SELECTOR_FIELDS_V1[0]);
  schema.allow_tag_fields = 1;
  memset(&selector_diagnostic, 0, sizeof(selector_diagnostic));
  selector_diagnostic.size = TURBO_SELECTOR_DIAGNOSTIC_V1_SIZE;
  result = turbo_selector_compile_v1(source, strlen(source), &schema, &program,
                                     &selector_diagnostic);
  if (result == TURBO_SELECTOR_OK)
    result = turbo_selector_program_canonical_v1(
        program, output, output_capacity, &required, &selector_diagnostic);
  turbo_selector_program_destroy(program);
  if (result != TURBO_SELECTOR_OK) {
    char message[MESHCTL_PRODUCT_DIAGNOSTIC_CAPACITY];
    (void)snprintf(message, sizeof(message),
                   "selector at byte %zu (line %u, column %u): %s",
                   selector_diagnostic.byte_offset,
                   selector_diagnostic.line, selector_diagnostic.column,
                   selector_diagnostic.message[0]
                       ? selector_diagnostic.message
                       : "selector validation failed");
    meshctl_diagnostic_set(diagnostic, MESHCTL_PRODUCT_PARSE_INVALID,
                           result == TURBO_SELECTOR_RESOURCE_LIMIT
                               ? "selector-resource-limit"
                               : "invalid-selector",
                           message);
    return result == TURBO_SELECTOR_NO_MEMORY ? -1 : 0;
  }
  return 1;
}

static int meshctl_endpoint_valid(const char *endpoint) {
  uri_t *uri = NULL;
  const char *path;
  int valid = 0;
  if (!endpoint || strlen(endpoint) >= MESHCTL_PRODUCT_ENDPOINT_CAPACITY ||
      turbo_parse_uri((const uint8_t *)endpoint, strlen(endpoint), &uri) != 0 ||
      !uri)
    return 0;
  path = turbo_uri_path(uri);
  valid = turbo_uri_is_valid(uri) && turbo_uri_scheme(uri) &&
          strcmp(turbo_uri_scheme(uri), "https") == 0 &&
          turbo_uri_host(uri) && turbo_uri_host(uri)[0] != '\0' &&
          (!turbo_uri_userinfo(uri) || turbo_uri_userinfo(uri)[0] == '\0') &&
          (!turbo_uri_query(uri) || turbo_uri_query(uri)[0] == '\0') &&
          (!turbo_uri_fragment(uri) || turbo_uri_fragment(uri)[0] == '\0') &&
          (!path || path[0] == '\0' || strcmp(path, "/") == 0);
  turbo_free_uri(&uri);
  return valid;
}

static int meshctl_route_valid(const char *route) {
  static const char prefix[] = "/v1/meshes/";
  size_t size;
  if (!route) return 0;
  size = strlen(route);
  return size > sizeof(prefix) - 1u &&
         size < MESHCTL_PRODUCT_ROUTE_CAPACITY &&
         strncmp(route, prefix, sizeof(prefix) - 1u) == 0 &&
         !strchr(route, '\r') && !strchr(route, '\n') &&
         !strchr(route, '#');
}

static int meshctl_credential_file_valid(const char *path, int private_key) {
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

static int meshctl_help_write(const char *data, size_t size, void *context) {
  meshctl_help_sink_t *sink = (meshctl_help_sink_t *)context;
  if (!sink || !data || size > sink->capacity - sink->size - 1u) return -1;
  memcpy(sink->buffer + sink->size, data, size);
  sink->size += size;
  sink->buffer[sink->size] = '\0';
  return 0;
}

static void meshctl_diagnostic_set(meshctl_product_parse_diagnostic_t *diagnostic,
                                   meshctl_product_parse_status_t status,
                                   const char *code, const char *message) {
  if (!diagnostic) return;
  memset(diagnostic, 0, sizeof(*diagnostic));
  diagnostic->status = status;
  if (code)
    (void)snprintf(diagnostic->error_code,
                   sizeof(diagnostic->error_code), "%s", code);
  if (message)
    (void)snprintf(diagnostic->message, sizeof(diagnostic->message), "%s",
                   message);
}

static int meshctl_product_tree_build(turbo_cmd_parser_t *parser,
                                      meshctl_product_parse_storage_t *storage) {
  turbo_cmd_node_t *root;
  turbo_cmd_node_t *nodes;
  turbo_cmd_node_t *operations;
  turbo_cmd_node_t *placements;
  turbo_cmd_node_t *networks;
  if (!parser || !storage) return -1;
  root = turbo_cmd_root(parser);
  if (!root ||
      turbo_cmd_node_add_string(root, &storage->endpoint, "endpoint", NULL,
                                "Allowed HTTPS Controller origin") != 0 ||
      turbo_cmd_node_set_required(root, turbo_cmd_node_last_index(root)) != 0 ||
      turbo_cmd_node_add_string(root, &storage->mesh, "mesh", NULL,
                                "Mesh ID or name") != 0 ||
      turbo_cmd_node_set_required(root, turbo_cmd_node_last_index(root)) != 0 ||
      turbo_cmd_node_add_string(root, &storage->ca_file, "ca-file", NULL,
                                "Controller CA bundle") != 0 ||
      turbo_cmd_node_set_required(root, turbo_cmd_node_last_index(root)) != 0 ||
      turbo_cmd_node_add_string(root, &storage->cert_file, "cert-file", NULL,
                                "Operator mTLS certificate") != 0 ||
      turbo_cmd_node_set_required(root, turbo_cmd_node_last_index(root)) != 0 ||
      turbo_cmd_node_add_string(root, &storage->key_file, "key-file", NULL,
                                "Operator mTLS private-key file") != 0 ||
      turbo_cmd_node_set_required(root, turbo_cmd_node_last_index(root)) != 0 ||
      turbo_cmd_node_add_integer(root, &storage->timeout_ms, "timeout-ms", NULL,
                                 "End-to-end command budget") != 0 ||
      turbo_cmd_node_add_integer(root, &storage->page_size, "page-size", NULL,
                                 "Maximum page items") != 0)
    return -1;
  nodes = turbo_cmd_add_command(root, "nodes", "Query Mesh nodes");
  operations =
      turbo_cmd_add_command(root, "operations", "Query durable operations");
  placements =
      turbo_cmd_add_command(root, "placements", "Plan content placement");
  networks = turbo_cmd_add_command(root, "networks", "Manage logical Networks");
  if (!nodes || !operations || !placements || !networks) return -1;
  storage->nodes_list = turbo_cmd_add_command(nodes, "list", "List nodes");
  storage->nodes_get = turbo_cmd_add_command(nodes, "get", "Get one node");
  storage->operations_get =
      turbo_cmd_add_command(operations, "get", "Get one operation");
  storage->placements_plan =
      turbo_cmd_add_command(placements, "plan", "Plan release placement");
  storage->networks_list = turbo_cmd_add_command(networks, "list", "List Networks");
  storage->networks_get = turbo_cmd_add_command(networks, "get", "Get one Network");
  storage->networks_plan = turbo_cmd_add_command(networks, "plan", "Plan a Network snapshot");
  storage->networks_apply = turbo_cmd_add_command(networks, "apply", "Apply a planned Network snapshot");
  storage->networks_delete = turbo_cmd_add_command(networks, "delete", "Drain and delete a Network");
  if (!storage->nodes_list || !storage->nodes_get ||
      !storage->operations_get || !storage->placements_plan ||
      !storage->networks_list || !storage->networks_get ||
      !storage->networks_plan || !storage->networks_apply ||
      !storage->networks_delete ||
      turbo_cmd_node_add_required_string(storage->nodes_get,
                                         &storage->resource_id, "node-id",
                                         "Node identifier") != 0 ||
      turbo_cmd_node_add_required_string(storage->operations_get,
                                         &storage->resource_id,
                                         "operation-id",
                                         "Operation identifier") != 0 ||
      turbo_cmd_node_add_required_string(
          storage->placements_plan, &storage->placement_subject, "subject",
          "Placement subject (release:<id>)") != 0 ||
      turbo_cmd_node_add_string(storage->placements_plan, &storage->selector,
                                "selector", NULL,
                                "Bounded inventory selector expression") != 0 ||
      turbo_cmd_node_set_required(
          storage->placements_plan,
          turbo_cmd_node_last_index(storage->placements_plan)) != 0 ||
      turbo_cmd_node_add_required_string(storage->networks_get,
                                         &storage->resource_id, "network",
                                         "Network ID or name") != 0 ||
      turbo_cmd_node_add_string(storage->networks_plan,
                                &storage->network_file, "file", "f",
                                "Bounded JSON Network document") != 0 ||
      turbo_cmd_node_set_required(
          storage->networks_plan,
          turbo_cmd_node_last_index(storage->networks_plan)) != 0 ||
      turbo_cmd_node_add_string(storage->networks_apply,
                                &storage->network_file, "file", "f",
                                "Bounded JSON Network document") != 0 ||
      turbo_cmd_node_set_required(
          storage->networks_apply,
          turbo_cmd_node_last_index(storage->networks_apply)) != 0 ||
      turbo_cmd_node_add_required_string(storage->networks_delete,
                                         &storage->resource_id, "network",
                                         "Network ID or name") != 0 ||
      turbo_cmd_node_add_integer(storage->networks_delete,
                                 &storage->drain_timeout_ms,
                                 "drain-timeout-ms", NULL,
                                 "Bounded Network drain deadline") != 0)
    return -1;
  return 0;
}

int meshctl_product_parse(int argc, char **argv,
                          meshctl_product_command_t *out_command,
                          meshctl_product_parse_diagnostic_t *out_diagnostic) {
  turbo_cmd_parser_t *parser = NULL;
  turbo_cmd_parse_result_t result;
  meshctl_product_parse_storage_t storage;
  meshctl_help_sink_t sink;
  int return_value = -1;
  if (!out_command || !out_diagnostic) return -1;
  memset(out_command, 0, sizeof(*out_command));
  memset(&storage, 0, sizeof(storage));
  storage.timeout_ms = MESHCTL_PRODUCT_DEFAULT_TIMEOUT_MS;
  storage.page_size = MESHCTL_PRODUCT_DEFAULT_PAGE_SIZE;
  storage.drain_timeout_ms = 30000;
  meshctl_diagnostic_set(out_diagnostic, MESHCTL_PRODUCT_PARSE_INVALID,
                         "invalid-argument", "invalid command arguments");
  parser = turbo_cmd_create("meshctl", "1.0");
  if (!parser || meshctl_product_tree_build(parser, &storage) != 0) {
    meshctl_diagnostic_set(out_diagnostic, MESHCTL_PRODUCT_PARSE_NO_MEMORY,
                           "command-tree", "cannot build command tree");
    goto cleanup;
  }
  memset(&result, 0, sizeof(result));
  result.size = sizeof(result);
  if (turbo_cmd_parse_ex(parser, argc, argv, &result) != 0) {
    meshctl_diagnostic_set(out_diagnostic, MESHCTL_PRODUCT_PARSE_NO_MEMORY,
                           "parser-failure", "command parser failed");
    goto cleanup;
  }
  if (result.status == TURBO_CMD_PARSE_HELP) {
    meshctl_diagnostic_set(out_diagnostic, MESHCTL_PRODUCT_PARSE_HELP, NULL,
                           NULL);
    sink.buffer = out_diagnostic->message;
    sink.capacity = sizeof(out_diagnostic->message);
    sink.size = 0u;
    if (turbo_cmd_render_help(parser, result.leaf, meshctl_help_write, &sink) !=
        0) {
      meshctl_diagnostic_set(out_diagnostic,
                             MESHCTL_PRODUCT_PARSE_NO_MEMORY,
                             "help-too-large",
                             "generated help exceeds its hard limit");
      goto cleanup;
    }
    return_value = 0;
    goto cleanup;
  }
  if (result.status == TURBO_CMD_PARSE_VERSION) {
    meshctl_diagnostic_set(out_diagnostic, MESHCTL_PRODUCT_PARSE_VERSION,
                           NULL, result.message);
    return_value = 0;
    goto cleanup;
  }
  if (result.status != TURBO_CMD_PARSE_OK) {
    meshctl_diagnostic_set(out_diagnostic, MESHCTL_PRODUCT_PARSE_INVALID,
                           result.error_code, result.message);
    return_value = 0;
    goto cleanup;
  }
  if (!meshctl_endpoint_valid(storage.endpoint) ||
      !meshctl_identifier_valid(storage.mesh) ||
      !meshctl_credential_file_valid(storage.ca_file, 0) ||
      !meshctl_credential_file_valid(storage.cert_file, 0) ||
      !meshctl_credential_file_valid(storage.key_file, 1) ||
      storage.timeout_ms < 1 ||
      storage.timeout_ms > MESHCTL_PRODUCT_MAX_TIMEOUT_MS ||
      storage.page_size < 1 ||
      storage.page_size > MESHCTL_PRODUCT_MAX_PAGE_SIZE) {
    meshctl_diagnostic_set(
        out_diagnostic, MESHCTL_PRODUCT_PARSE_INVALID, "invalid-context",
        "endpoint, mesh, credential files or numeric limits are invalid");
    return_value = 0;
    goto cleanup;
  }
  if (meshctl_copy_string(out_command->common.endpoint,
                          sizeof(out_command->common.endpoint),
                          storage.endpoint) != 0 ||
      meshctl_copy_string(out_command->common.mesh,
                          sizeof(out_command->common.mesh), storage.mesh) != 0 ||
      meshctl_copy_string(out_command->common.ca_file,
                          sizeof(out_command->common.ca_file),
                          storage.ca_file) != 0 ||
      meshctl_copy_string(out_command->common.cert_file,
                          sizeof(out_command->common.cert_file),
                          storage.cert_file) != 0 ||
      meshctl_copy_string(out_command->common.key_file,
                          sizeof(out_command->common.key_file),
                          storage.key_file) != 0) {
    meshctl_diagnostic_set(out_diagnostic, MESHCTL_PRODUCT_PARSE_INVALID,
                           "value-too-large", "command value exceeds limit");
    return_value = 0;
    goto cleanup;
  }
  out_command->common.timeout_ms = (uint32_t)storage.timeout_ms;
  out_command->common.page_size = (uint32_t)storage.page_size;
  if (result.leaf == storage.nodes_list) {
    out_command->kind = MESHCTL_PRODUCT_COMMAND_NODES_LIST;
  } else if (result.leaf == storage.nodes_get &&
             meshctl_identifier_valid(storage.resource_id)) {
    out_command->kind = MESHCTL_PRODUCT_COMMAND_NODES_GET;
    (void)meshctl_copy_string(out_command->args.nodes_get.node_id,
                              sizeof(out_command->args.nodes_get.node_id),
                              storage.resource_id);
  } else if (result.leaf == storage.operations_get &&
             meshctl_identifier_valid(storage.resource_id)) {
    out_command->kind = MESHCTL_PRODUCT_COMMAND_OPERATIONS_GET;
    (void)meshctl_copy_string(
        out_command->args.operations_get.operation_id,
        sizeof(out_command->args.operations_get.operation_id),
        storage.resource_id);
  } else if (result.leaf == storage.placements_plan &&
             meshctl_placement_subject_valid(storage.placement_subject)) {
    int selector_result;
    out_command->kind = MESHCTL_PRODUCT_COMMAND_PLACEMENTS_PLAN;
    if (meshctl_copy_string(
            out_command->args.placements_plan.subject,
            sizeof(out_command->args.placements_plan.subject),
            storage.placement_subject) != 0) {
      meshctl_diagnostic_set(out_diagnostic, MESHCTL_PRODUCT_PARSE_INVALID,
                             "value-too-large",
                             "placement subject exceeds limit");
      return_value = 0;
      goto cleanup;
    }
    selector_result = meshctl_selector_canonicalize(
        storage.selector, out_command->args.placements_plan.selector,
        sizeof(out_command->args.placements_plan.selector), out_diagnostic);
    if (selector_result <= 0) {
      if (selector_result < 0)
        meshctl_diagnostic_set(out_diagnostic,
                               MESHCTL_PRODUCT_PARSE_NO_MEMORY,
                               "selector-failure",
                               "cannot validate placement selector");
      return_value = 0;
      goto cleanup;
    }
    out_command->args.placements_plan.selector_language_version =
        TURBO_SELECTOR_LANGUAGE_VERSION_V1;
  } else if (result.leaf == storage.networks_list) {
    out_command->kind = MESHCTL_PRODUCT_COMMAND_NETWORKS_LIST;
  } else if (result.leaf == storage.networks_get &&
             meshctl_identifier_valid(storage.resource_id)) {
    out_command->kind = MESHCTL_PRODUCT_COMMAND_NETWORKS_GET;
    (void)meshctl_copy_string(out_command->args.networks_get.network,
                              sizeof(out_command->args.networks_get.network),
                              storage.resource_id);
  } else if ((result.leaf == storage.networks_plan ||
              result.leaf == storage.networks_apply) &&
             storage.network_file && storage.network_file[0] != '\0' &&
             strlen(storage.network_file) < MESHCTL_PRODUCT_PATH_CAPACITY) {
    out_command->kind = result.leaf == storage.networks_plan
                            ? MESHCTL_PRODUCT_COMMAND_NETWORKS_PLAN
                            : MESHCTL_PRODUCT_COMMAND_NETWORKS_APPLY;
    (void)meshctl_copy_string(out_command->args.networks_mutation.file,
                              sizeof(out_command->args.networks_mutation.file),
                              storage.network_file);
  } else if (result.leaf == storage.networks_delete &&
             meshctl_identifier_valid(storage.resource_id) &&
             storage.drain_timeout_ms >= 1 &&
             storage.drain_timeout_ms <= 300000) {
    out_command->kind = MESHCTL_PRODUCT_COMMAND_NETWORKS_DELETE;
    (void)meshctl_copy_string(out_command->args.networks_delete.network,
                              sizeof(out_command->args.networks_delete.network),
                              storage.resource_id);
    out_command->args.networks_delete.drain_timeout_ms =
        (uint32_t)storage.drain_timeout_ms;
  } else {
    meshctl_diagnostic_set(out_diagnostic, MESHCTL_PRODUCT_PARSE_INVALID,
                           "invalid-resource-id",
                           "resource identifier is invalid");
    return_value = 0;
    goto cleanup;
  }
  meshctl_diagnostic_set(out_diagnostic, MESHCTL_PRODUCT_PARSE_OK, NULL, NULL);
  return_value = 0;

cleanup:
  turbo_cmd_destroy(parser);
  return return_value;
}

int meshctl_product_is_command(const char *name) {
  return name && (strcmp(name, "nodes") == 0 ||
                  strcmp(name, "operations") == 0 ||
                  strcmp(name, "placements") == 0 ||
                  strcmp(name, "networks") == 0);
}

int meshctl_deadline_init_at(meshctl_deadline_t *deadline, uint64_t now_ms,
                             uint32_t timeout_ms) {
  if (!deadline || timeout_ms == 0u ||
      timeout_ms > MESHCTL_PRODUCT_MAX_TIMEOUT_MS ||
      now_ms > UINT64_MAX - timeout_ms)
    return -1;
  deadline->started_ms = now_ms;
  deadline->deadline_ms = now_ms + timeout_ms;
  return 0;
}

uint32_t meshctl_deadline_remaining_at(const meshctl_deadline_t *deadline,
                                       uint64_t now_ms) {
  uint64_t remaining;
  if (!deadline || now_ms >= deadline->deadline_ms) return 0u;
  remaining = deadline->deadline_ms - now_ms;
  return remaining > UINT32_MAX ? UINT32_MAX : (uint32_t)remaining;
}

void meshctl_controller_response_destroy(
    meshctl_controller_response_t *response) {
  if (!response) return;
  free(response->body);
  memset(response, 0, sizeof(*response));
}

meshctl_controller_result_t meshctl_controller_request_http2(
    void *context, const meshctl_product_common_options_t *options,
    const meshctl_controller_request_t *request, uint32_t remaining_ms,
    meshctl_controller_response_t *out_response) {
  turbo_http_options_t http_options;
  turbo_tls_client_config_t tls;
  turbo_http_t *client = NULL;
  http_response_t *response = NULL;
  turbo_json_doc_t *json = NULL;
  char url[MESHCTL_PRODUCT_ENDPOINT_CAPACITY + MESHCTL_PRODUCT_ROUTE_CAPACITY];
  const char *headers[] = {"Accept: " MESHCTL_PRODUCT_MEDIA_TYPE,
                           "Content-Type: " MESHCTL_PRODUCT_MEDIA_TYPE};
  http_method_t method;
  int header_count;
  size_t endpoint_size;
  int written;
  meshctl_controller_result_t result = MESHCTL_CONTROLLER_TRANSPORT_ERROR;
  (void)context;
  if (!options || !meshctl_endpoint_valid(options->endpoint) ||
      !meshctl_credential_file_valid(options->ca_file, 0) ||
      !meshctl_credential_file_valid(options->cert_file, 0) ||
      !meshctl_credential_file_valid(options->key_file, 1) ||
      !request || !meshctl_route_valid(request->route) || !out_response ||
      remaining_ms == 0u || remaining_ms > MESHCTL_PRODUCT_MAX_TIMEOUT_MS)
    return MESHCTL_CONTROLLER_INVALID_ARGUMENT;
  if (request->method == MESHCTL_CONTROLLER_METHOD_GET) {
    if (request->body || request->body_size != 0u || request->content_type)
      return MESHCTL_CONTROLLER_INVALID_ARGUMENT;
    method = HTTP_GET;
    header_count = 1;
  } else if (request->method == MESHCTL_CONTROLLER_METHOD_POST) {
    if (!request->body || request->body_size == 0u ||
        request->body_size > MESHCTL_PRODUCT_MAX_REQUEST_SIZE ||
        !request->content_type ||
        strcmp(request->content_type, MESHCTL_PRODUCT_MEDIA_TYPE) != 0)
      return MESHCTL_CONTROLLER_INVALID_ARGUMENT;
    method = HTTP_POST;
    header_count = 2;
  } else {
    return MESHCTL_CONTROLLER_INVALID_ARGUMENT;
  }
  memset(out_response, 0, sizeof(*out_response));
  endpoint_size = strlen(options->endpoint);
  if (endpoint_size > 0u && options->endpoint[endpoint_size - 1u] == '/')
    --endpoint_size;
  written = snprintf(url, sizeof(url), "%.*s%s", (int)endpoint_size,
                     options->endpoint, request->route);
  if (written < 0 || (size_t)written >= sizeof(url))
    return MESHCTL_CONTROLLER_INVALID_ARGUMENT;
  if (turbo_http_options_init(&http_options, sizeof(http_options)) != TURBO_OK)
    return MESHCTL_CONTROLLER_TRANSPORT_ERROR;
  http_options.transport = TURBO_HTTP_TRANSPORT_H2;
  http_options.h2_fallback_to_h1 = 0;
  http_options.follow_redirects = 0;
  http_options.max_redirects = 0;
  memset(&http_options.retry, 0, sizeof(http_options.retry));
  http_options.timeout_ms = (int64_t)remaining_ms;
  if (turbo_http_create_sync(&http_options, &client) != TURBO_OK || !client)
    return MESHCTL_CONTROLLER_NO_MEMORY;
  turbo_http_set_max_response_size(client,
                                   MESHCTL_PRODUCT_MAX_RESPONSE_SIZE);
  turbo_http_set_max_response_header_size(
      client, MESHCTL_PRODUCT_MAX_RESPONSE_HEADER_SIZE);
  memset(&tls, 0, sizeof(tls));
  tls.ca_file = options->ca_file;
  tls.cert_file = options->cert_file;
  tls.key_file = options->key_file;
  tls.verify_peer = 1;
  if (turbo_http_set_tls_config(client, &tls) != TURBO_OK) {
    result = MESHCTL_CONTROLLER_INVALID_ARGUMENT;
    goto cleanup;
  }
  response = turbo_http_request_sync(client, method, url, headers, header_count,
                                     request->body, request->body_size);
  if (!response) {
    result = MESHCTL_CONTROLLER_NO_MEMORY;
    goto cleanup;
  }
  if (response->error_code != HTTP_ERROR_NONE) {
    result = response->error_code == HTTP_ERROR_TIMEOUT
                 ? MESHCTL_CONTROLLER_TIMEOUT
                 : MESHCTL_CONTROLLER_TRANSPORT_ERROR;
    goto cleanup;
  }
  if (!response->body || response->body_len == 0u ||
      response->body_len > MESHCTL_PRODUCT_MAX_RESPONSE_SIZE ||
      turbo_parse_json((const uint8_t *)response->body, response->body_len,
                       &json) != 0 ||
      !json) {
    result = MESHCTL_CONTROLLER_PROTOCOL_ERROR;
    goto cleanup;
  }
  out_response->body = (char *)malloc(response->body_len + 1u);
  if (!out_response->body) {
    result = MESHCTL_CONTROLLER_NO_MEMORY;
    goto cleanup;
  }
  memcpy(out_response->body, response->body, response->body_len);
  out_response->body[response->body_len] = '\0';
  out_response->body_size = response->body_len;
  out_response->status_code = response->status_code;
  result = MESHCTL_CONTROLLER_OK;

cleanup:
  turbo_free_json(&json);
  if (response) http_response_free(response);
  turbo_http_destroy(client);
  if (result != MESHCTL_CONTROLLER_OK)
    meshctl_controller_response_destroy(out_response);
  return result;
}

meshctl_controller_result_t meshctl_controller_query_http2(
    void *context, const meshctl_product_common_options_t *options,
    const char *route, uint32_t remaining_ms,
    meshctl_controller_response_t *out_response) {
  meshctl_controller_request_t request;
  memset(&request, 0, sizeof(request));
  request.method = MESHCTL_CONTROLLER_METHOD_GET;
  request.route = route;
  return meshctl_controller_request_http2(context, options, &request,
                                          remaining_ms, out_response);
}

static int meshctl_product_build_route(const meshctl_product_command_t *command,
                                       char *route, size_t route_capacity) {
  int written;
  switch (command->kind) {
  case MESHCTL_PRODUCT_COMMAND_NODES_LIST:
    written = snprintf(route, route_capacity, "/v1/meshes/%s/nodes?limit=%u",
                       command->common.mesh, command->common.page_size);
    break;
  case MESHCTL_PRODUCT_COMMAND_NODES_GET:
    written = snprintf(route, route_capacity, "/v1/meshes/%s/nodes/%s",
                       command->common.mesh,
                       command->args.nodes_get.node_id);
    break;
  case MESHCTL_PRODUCT_COMMAND_OPERATIONS_GET:
    written = snprintf(route, route_capacity,
                       "/v1/meshes/%s/operations/%s", command->common.mesh,
                       command->args.operations_get.operation_id);
    break;
  case MESHCTL_PRODUCT_COMMAND_PLACEMENTS_PLAN:
    written = snprintf(route, route_capacity,
                       "/v1/meshes/%s/placements:plan",
                       command->common.mesh);
    break;
  case MESHCTL_PRODUCT_COMMAND_NETWORKS_LIST:
    written = snprintf(route, route_capacity, "/v1/meshes/%s/networks?limit=%u",
                       command->common.mesh, command->common.page_size);
    break;
  case MESHCTL_PRODUCT_COMMAND_NETWORKS_GET:
    written = snprintf(route, route_capacity, "/v1/meshes/%s/networks/%s",
                       command->common.mesh,
                       command->args.networks_get.network);
    break;
  case MESHCTL_PRODUCT_COMMAND_NETWORKS_PLAN:
    written = snprintf(route, route_capacity, "/v1/meshes/%s/networks:plan",
                       command->common.mesh);
    break;
  case MESHCTL_PRODUCT_COMMAND_NETWORKS_APPLY:
    written = snprintf(route, route_capacity, "/v1/meshes/%s/networks:apply",
                       command->common.mesh);
    break;
  case MESHCTL_PRODUCT_COMMAND_NETWORKS_DELETE:
    written = snprintf(route, route_capacity,
                       "/v1/meshes/%s/networks/%s:delete",
                       command->common.mesh,
                       command->args.networks_delete.network);
    break;
  default:
    return -1;
  }
  return written >= 0 && (size_t)written < route_capacity ? 0 : -1;
}

static int meshctl_json_add(json_value_t *object, const char *key,
                            json_value_t *value) {
  if (!value || !turbo_json_object_add_checked(object, key, value)) {
    turbo_free_json((turbo_json_doc_t **)&value);
    return -1;
  }
  return 0;
}

static int meshctl_product_build_plan_body(
    const meshctl_product_command_t *command, char **out_body,
    size_t *out_body_size) {
  json_value_t *root = NULL;
  meshctl_product_parse_diagnostic_t diagnostic;
  char canonical[MESHCTL_PRODUCT_SELECTOR_CAPACITY];
  char *body = NULL;
  size_t body_size = 0u;
  if (out_body) *out_body = NULL;
  if (out_body_size) *out_body_size = 0u;
  if (!command || command->kind != MESHCTL_PRODUCT_COMMAND_PLACEMENTS_PLAN ||
      !out_body || !out_body_size ||
      !meshctl_placement_subject_valid(
          command->args.placements_plan.subject) ||
      command->args.placements_plan.selector_language_version !=
          TURBO_SELECTOR_LANGUAGE_VERSION_V1 ||
      command->args.placements_plan.selector[0] == '\0')
    return -1;
  memset(&diagnostic, 0, sizeof(diagnostic));
  if (meshctl_selector_canonicalize(
          command->args.placements_plan.selector, canonical,
          sizeof(canonical), &diagnostic) != 1 ||
      strcmp(canonical, command->args.placements_plan.selector) != 0)
    return -1;
  root = turbo_json_create_object();
  if (!root ||
      meshctl_json_add(root, "schema_version",
                       turbo_json_create_uint64(1u)) != 0 ||
      meshctl_json_add(
          root, "subject",
          turbo_json_create_string(command->args.placements_plan.subject)) !=
          0 ||
      meshctl_json_add(
          root, "selector_language_version",
          turbo_json_create_uint64(
              command->args.placements_plan.selector_language_version)) != 0 ||
      meshctl_json_add(
          root, "selector",
          turbo_json_create_string(command->args.placements_plan.selector)) !=
          0)
    goto cleanup;
  body = turbo_json_serialize(root, &body_size);
  if (!body || body_size == 0u ||
      body_size > MESHCTL_PRODUCT_MAX_REQUEST_SIZE)
    goto cleanup;
  *out_body = body;
  *out_body_size = body_size;
  body = NULL;
  turbo_free_json((turbo_json_doc_t **)&root);
  return 0;

cleanup:
  turbo_json_serialize_free(body);
  turbo_free_json((turbo_json_doc_t **)&root);
  return -1;
}

static int meshctl_product_build_network_body(
    const meshctl_product_command_t *command, char **out_body,
    size_t *out_body_size) {
  turbo_fs_buf_t bytes = {0};
  turbo_json_doc_t *json = NULL;
  char *body = NULL;
  int result = -1;
  if (!command || !out_body || !out_body_size) return -1;
  *out_body = NULL;
  *out_body_size = 0u;
  if (command->kind == MESHCTL_PRODUCT_COMMAND_NETWORKS_DELETE) {
    int written;
    body = (char *)malloc(96u);
    if (!body) return -1;
    written = snprintf(body, 96u,
                       "{\"schema_version\":1,\"drain_timeout_ms\":%u}",
                       command->args.networks_delete.drain_timeout_ms);
    if (written <= 0 || written >= 96) goto cleanup;
    *out_body = body;
    *out_body_size = (size_t)written;
    return 0;
  }
  if (command->kind != MESHCTL_PRODUCT_COMMAND_NETWORKS_PLAN &&
      command->kind != MESHCTL_PRODUCT_COMMAND_NETWORKS_APPLY)
    return -1;
  if (turbo_fs_read_file(command->args.networks_mutation.file, &bytes) != 0 ||
      !bytes.base || bytes.len == 0u ||
      bytes.len > MESHCTL_PRODUCT_MAX_REQUEST_SIZE ||
      turbo_parse_json((const uint8_t *)bytes.base, bytes.len, &json) != 0 ||
      !json)
    goto cleanup;
  body = (char *)malloc(bytes.len + 1u);
  if (!body) goto cleanup;
  memcpy(body, bytes.base, bytes.len);
  body[bytes.len] = '\0';
  *out_body = body;
  *out_body_size = bytes.len;
  body = NULL;
  result = 0;
cleanup:
  free(body);
  turbo_free_json(&json);
  turbo_fs_buf_free(&bytes);
  return result;
}

static int meshctl_product_http_exit(int status_code) {
  if (status_code >= 200 && status_code < 300) return 0;
  if (status_code == 401 || status_code == 403) return 3;
  if (status_code == 404) return 4;
  if (status_code == 409 || status_code == 412) return 5;
  if (status_code == 429) return 8;
  if (status_code >= 500) return 7;
  return 9;
}

int meshctl_product_execute(const meshctl_product_command_t *command,
                            const meshctl_controller_client_t *client,
                            FILE *out, FILE *err) {
  meshctl_deadline_t deadline;
  meshctl_controller_response_t response;
  meshctl_controller_request_t request;
  meshctl_controller_result_t result;
  char route[MESHCTL_PRODUCT_ROUTE_CAPACITY];
  char *request_body = NULL;
  size_t request_body_size = 0u;
  uint32_t remaining_ms;
  int exit_code;
  if (!command || !client || (!client->request && !client->query) || !out ||
      !err ||
      meshctl_product_build_route(command, route, sizeof(route)) != 0 ||
      meshctl_deadline_init_at(&deadline, turbo_monotonic_ms(),
                               command->common.timeout_ms) != 0) {
    fprintf(err, "meshctl: invalid product command\n");
    return 2;
  }
  memset(&request, 0, sizeof(request));
  request.route = route;
  if (command->kind == MESHCTL_PRODUCT_COMMAND_PLACEMENTS_PLAN) {
    if (!client->request ||
        meshctl_product_build_plan_body(command, &request_body,
                                        &request_body_size) != 0) {
      fprintf(err, "meshctl: cannot build bounded placement plan request\n");
      return client->request ? 9 : 2;
    }
    request.method = MESHCTL_CONTROLLER_METHOD_POST;
    request.content_type = MESHCTL_PRODUCT_MEDIA_TYPE;
    request.body = request_body;
    request.body_size = request_body_size;
  } else if (command->kind == MESHCTL_PRODUCT_COMMAND_NETWORKS_PLAN ||
             command->kind == MESHCTL_PRODUCT_COMMAND_NETWORKS_APPLY ||
             command->kind == MESHCTL_PRODUCT_COMMAND_NETWORKS_DELETE) {
    if (!client->request ||
        meshctl_product_build_network_body(command, &request_body,
                                           &request_body_size) != 0) {
      fprintf(err, "meshctl: cannot build bounded Network request\n");
      return client->request ? 9 : 2;
    }
    request.method = MESHCTL_CONTROLLER_METHOD_POST;
    request.content_type = MESHCTL_PRODUCT_MEDIA_TYPE;
    request.body = request_body;
    request.body_size = request_body_size;
  } else {
    request.method = MESHCTL_CONTROLLER_METHOD_GET;
  }
  remaining_ms =
      meshctl_deadline_remaining_at(&deadline, turbo_monotonic_ms());
  if (remaining_ms == 0u) {
    turbo_json_serialize_free(request_body);
    fprintf(err, "meshctl: deadline expired before send\n");
    return 7;
  }
  memset(&response, 0, sizeof(response));
  if (client->request)
    result = client->request(client->context, &command->common, &request,
                             remaining_ms, &response);
  else
    result = client->query(client->context, &command->common, route,
                           remaining_ms, &response);
  turbo_json_serialize_free(request_body);
  if (result != MESHCTL_CONTROLLER_OK) {
    meshctl_controller_response_destroy(&response);
    fprintf(err, "meshctl: Controller query failed (%d)\n", (int)result);
    return result == MESHCTL_CONTROLLER_INVALID_ARGUMENT ? 2 :
           result == MESHCTL_CONTROLLER_NO_MEMORY ? 9 : 7;
  }
  if (response.body_size > 0u &&
      fwrite(response.body, 1u, response.body_size, out) !=
          response.body_size) {
    meshctl_controller_response_destroy(&response);
    fprintf(err, "meshctl: cannot write complete response\n");
    return 9;
  }
  fputc('\n', out);
  exit_code = meshctl_product_http_exit(response.status_code);
  meshctl_controller_response_destroy(&response);
  return exit_code;
}

int meshctl_product_run(int argc, char **argv) {
  meshctl_product_command_t command;
  meshctl_product_parse_diagnostic_t diagnostic;
  meshctl_controller_client_t client;
  if (meshctl_product_parse(argc, argv, &command, &diagnostic) != 0) {
    fprintf(stderr, "meshctl: command parser failure\n");
    return 9;
  }
  if (diagnostic.status == MESHCTL_PRODUCT_PARSE_HELP ||
      diagnostic.status == MESHCTL_PRODUCT_PARSE_VERSION) {
    fputs(diagnostic.message, stdout);
    if (diagnostic.message[0] != '\0' &&
        diagnostic.message[strlen(diagnostic.message) - 1u] != '\n')
      fputc('\n', stdout);
    return 0;
  }
  if (diagnostic.status != MESHCTL_PRODUCT_PARSE_OK) {
    fprintf(stderr, "meshctl: %s%s%s\n", diagnostic.error_code,
            diagnostic.message[0] ? ": " : "", diagnostic.message);
    return diagnostic.status == MESHCTL_PRODUCT_PARSE_NO_MEMORY ? 9 : 2;
  }
  memset(&client, 0, sizeof(client));
  client.request = meshctl_controller_request_http2;
  client.context = NULL;
  return meshctl_product_execute(&command, &client, stdout, stderr);
}
