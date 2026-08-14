#include "meshctl_product.h"
#include "tinytest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <sys/stat.h>
#endif

typedef struct {
  char route[MESHCTL_PRODUCT_ROUTE_CAPACITY];
  char body[4096];
  meshctl_controller_method_t method;
  uint32_t remaining_ms;
  int calls;
  meshctl_controller_result_t result;
} fake_controller_t;

static meshctl_controller_result_t fake_request(
    void *context, const meshctl_product_common_options_t *options,
    const meshctl_controller_request_t *request, uint32_t remaining_ms,
    meshctl_controller_response_t *out_response) {
  static const char body[] =
      "{\"inventory_generation\":7,\"target_count\":2}";
  fake_controller_t *fake = (fake_controller_t *)context;
  (void)options;
  if (!request || !request->route ||
      request->body_size >= sizeof(fake->body))
    return MESHCTL_CONTROLLER_INVALID_ARGUMENT;
  fake->calls++;
  fake->remaining_ms = remaining_ms;
  fake->method = request->method;
  (void)snprintf(fake->route, sizeof(fake->route), "%s", request->route);
  if (request->body && request->body_size > 0u) {
    memcpy(fake->body, request->body, request->body_size);
    fake->body[request->body_size] = '\0';
  }
  out_response->body = (char *)malloc(sizeof(body));
  if (!out_response->body) return MESHCTL_CONTROLLER_NO_MEMORY;
  memcpy(out_response->body, body, sizeof(body));
  out_response->body_size = sizeof(body) - 1u;
  out_response->status_code = 200;
  return fake->result;
}

static meshctl_controller_result_t fake_query(
    void *context, const meshctl_product_common_options_t *options,
    const char *route, uint32_t remaining_ms,
    meshctl_controller_response_t *out_response) {
  static const char body[] = "{\"nodes\":[],\"generation\":7}";
  fake_controller_t *fake = (fake_controller_t *)context;
  (void)options;
  fake->calls++;
  fake->remaining_ms = remaining_ms;
  (void)snprintf(fake->route, sizeof(fake->route), "%s", route);
  out_response->body = (char *)malloc(sizeof(body));
  if (!out_response->body) return MESHCTL_CONTROLLER_NO_MEMORY;
  memcpy(out_response->body, body, sizeof(body));
  out_response->body_size = sizeof(body) - 1u;
  out_response->status_code = 200;
  return fake->result;
}

static char *make_credential_file(const char *suffix) {
  char *path = tt_make_temp_file("meshctl-product", suffix);
  if (!path) return NULL;
  if (tt_write_file(path, "test", 4u) != 0) {
    free(path);
    return NULL;
  }
#ifndef _WIN32
  if (chmod(path, S_IRUSR | S_IWUSR) != 0) {
    (void)tt_remove_file(path);
    free(path);
    return NULL;
  }
#endif
  return path;
}

static void remove_credential_file(char *path) {
  if (!path) return;
  (void)tt_remove_file(path);
  free(path);
}

spec("meshctl product command core") {
  describe("typed recursive parsing") {
    it("builds an owned bounded nodes-list command") {
      meshctl_product_command_t command;
      meshctl_product_parse_diagnostic_t diagnostic;
      char *ca = make_credential_file("-ca.pem");
      char *cert = make_credential_file("-cert.pem");
      char *key = make_credential_file("-key.pem");
      char *argv[] = {
          "meshctl", "nodes", "list", "--endpoint",
          "https://controller.example", "--mesh", "demo", "--ca-file",
          ca, "--cert-file", cert, "--key-file", key, "--timeout-ms",
          "5000", "--page-size", "25"};

      check_not_null(ca);
      check_not_null(cert);
      check_not_null(key);
      check_int_eq(meshctl_product_parse(17, argv, &command, &diagnostic), 0);
      check_int_eq(diagnostic.status, MESHCTL_PRODUCT_PARSE_OK);
      check_int_eq(command.kind, MESHCTL_PRODUCT_COMMAND_NODES_LIST);
      check_str_eq(command.common.endpoint, "https://controller.example");
      check_str_eq(command.common.mesh, "demo");
      check_uint_eq(command.common.timeout_ms, 5000u);
      check_uint_eq(command.common.page_size, 25u);

      remove_credential_file(key);
      remove_credential_file(cert);
      remove_credential_file(ca);
    }

    it("returns help without requiring credentials") {
      meshctl_product_command_t command;
      meshctl_product_parse_diagnostic_t diagnostic;
      char *argv[] = {"meshctl", "operations", "get", "--help"};

      check_int_eq(meshctl_product_parse(4, argv, &command, &diagnostic), 0);
      check_int_eq(diagnostic.status, MESHCTL_PRODUCT_PARSE_HELP);
      check_str_contains(diagnostic.message, "meshctl operations get");
      check_str_contains(diagnostic.message, "operation-id");
    }

    it("rejects plaintext Controller endpoints") {
      meshctl_product_command_t command;
      meshctl_product_parse_diagnostic_t diagnostic;
      char *ca = make_credential_file("-ca.pem");
      char *cert = make_credential_file("-cert.pem");
      char *key = make_credential_file("-key.pem");
      char *argv[] = {"meshctl", "nodes", "list", "--endpoint",
                      "http://controller.example", "--mesh", "demo",
                      "--ca-file", ca, "--cert-file", cert, "--key-file",
                      key};

      check_int_eq(meshctl_product_parse(13, argv, &command, &diagnostic), 0);
      check_int_eq(diagnostic.status, MESHCTL_PRODUCT_PARSE_INVALID);
      check_str_eq(diagnostic.error_code, "invalid-context");

      remove_credential_file(key);
      remove_credential_file(cert);
      remove_credential_file(ca);
    }

    it("accepts an HTTPS origin with only a root path") {
      meshctl_product_command_t command;
      meshctl_product_parse_diagnostic_t diagnostic;
      char *ca = make_credential_file("-ca.pem");
      char *cert = make_credential_file("-cert.pem");
      char *key = make_credential_file("-key.pem");
      char *argv[] = {"meshctl", "nodes", "list", "--endpoint",
                      "https://controller.example/", "--mesh", "demo",
                      "--ca-file", ca, "--cert-file", cert, "--key-file",
                      key};

      check_int_eq(meshctl_product_parse(13, argv, &command, &diagnostic), 0);
      check_int_eq(diagnostic.status, MESHCTL_PRODUCT_PARSE_OK);
      check_str_eq(command.common.endpoint, "https://controller.example/");

      remove_credential_file(key);
      remove_credential_file(cert);
      remove_credential_file(ca);
    }

    it("builds a canonical bounded placement-plan selector") {
      meshctl_product_command_t command;
      meshctl_product_parse_diagnostic_t diagnostic;
      char *ca = make_credential_file("-ca.pem");
      char *cert = make_credential_file("-cert.pem");
      char *key = make_credential_file("-key.pem");
      char *argv[] = {
          "meshctl", "placements", "plan", "release:web-v42",
          "--selector", "role in [\"edge\",\"cache\"] && region==\"eu\"",
          "--endpoint", "https://controller.example", "--mesh", "demo",
          "--ca-file", ca, "--cert-file", cert, "--key-file", key};

      check_int_eq(meshctl_product_parse(16, argv, &command, &diagnostic), 0);
      check_int_eq(diagnostic.status, MESHCTL_PRODUCT_PARSE_OK);
      check_int_eq(command.kind,
                   MESHCTL_PRODUCT_COMMAND_PLACEMENTS_PLAN);
      check_str_eq(command.args.placements_plan.subject, "release:web-v42");
      check_uint_eq(command.args.placements_plan.selector_language_version,
                    TURBO_SELECTOR_LANGUAGE_VERSION_V1);
      check_str_eq(command.args.placements_plan.selector,
                   "(role in [\"cache\", \"edge\"] && region == \"eu\")");

      remove_credential_file(key);
      remove_credential_file(cert);
      remove_credential_file(ca);
    }

    it("rejects placement selectors outside the field allowlist") {
      meshctl_product_command_t command;
      meshctl_product_parse_diagnostic_t diagnostic;
      char *ca = make_credential_file("-ca.pem");
      char *cert = make_credential_file("-cert.pem");
      char *key = make_credential_file("-key.pem");
      char *argv[] = {
          "meshctl", "placements", "plan", "release:web-v42",
          "--selector", "secret == \"x\"", "--endpoint",
          "https://controller.example", "--mesh", "demo", "--ca-file", ca,
          "--cert-file", cert, "--key-file", key};

      check_int_eq(meshctl_product_parse(16, argv, &command, &diagnostic), 0);
      check_int_eq(diagnostic.status, MESHCTL_PRODUCT_PARSE_INVALID);
      check_str_eq(diagnostic.error_code, "invalid-selector");
      check_str_contains(diagnostic.message, "not allowed");

      remove_credential_file(key);
      remove_credential_file(cert);
      remove_credential_file(ca);
    }

    it("parses bounded Network apply and drain-delete commands") {
      meshctl_product_command_t command;
      meshctl_product_parse_diagnostic_t diagnostic;
      char *ca = make_credential_file("-ca.pem");
      char *cert = make_credential_file("-cert.pem");
      char *key = make_credential_file("-key.pem");
      char *document = make_credential_file("-network.json");
      char *apply_argv[] = {
          "meshctl", "networks", "apply", "-f", document, "--endpoint",
          "https://controller.example", "--mesh", "demo", "--ca-file", ca,
          "--cert-file", cert, "--key-file", key};
      char *delete_argv[] = {
          "meshctl", "networks", "delete", "production", "--drain-timeout-ms",
          "45000", "--endpoint", "https://controller.example", "--mesh", "demo",
          "--ca-file", ca, "--cert-file", cert, "--key-file", key};

      check_int_eq(meshctl_product_parse(15, apply_argv, &command, &diagnostic), 0);
      check_int_eq(diagnostic.status, MESHCTL_PRODUCT_PARSE_OK);
      check_int_eq(command.kind, MESHCTL_PRODUCT_COMMAND_NETWORKS_APPLY);
      check_str_eq(command.args.networks_mutation.file, document);
      check_int_eq(meshctl_product_parse(16, delete_argv, &command, &diagnostic), 0);
      check_int_eq(diagnostic.status, MESHCTL_PRODUCT_PARSE_OK);
      check_int_eq(command.kind, MESHCTL_PRODUCT_COMMAND_NETWORKS_DELETE);
      check_str_eq(command.args.networks_delete.network, "production");
      check_uint_eq(45000u, command.args.networks_delete.drain_timeout_ms);

      remove_credential_file(document);
      remove_credential_file(key);
      remove_credential_file(cert);
      remove_credential_file(ca);
    }
  }

  describe("deadline and execution") {
    it("uses one monotonic deadline without resetting its budget") {
      meshctl_deadline_t deadline;

      check_int_eq(meshctl_deadline_init_at(&deadline, 1000u, 5000u), 0);
      check_uint_eq(meshctl_deadline_remaining_at(&deadline, 1000u), 5000u);
      check_uint_eq(meshctl_deadline_remaining_at(&deadline, 3250u), 2750u);
      check_uint_eq(meshctl_deadline_remaining_at(&deadline, 6000u), 0u);
      check_int_ne(meshctl_deadline_init_at(
                       &deadline, UINT64_MAX - 2u, 5000u),
                   0);
    }

    it("maps a typed query to the documented Controller route") {
      meshctl_product_command_t command;
      meshctl_controller_client_t client;
      fake_controller_t fake;
      FILE *out = tmpfile();
      FILE *err = tmpfile();
      char output[128];
      size_t output_size;

      check_not_null(out);
      check_not_null(err);
      memset(&command, 0, sizeof(command));
      memset(&fake, 0, sizeof(fake));
      memset(&client, 0, sizeof(client));
      command.kind = MESHCTL_PRODUCT_COMMAND_NODES_LIST;
      command.common.timeout_ms = 5000u;
      command.common.page_size = 25u;
      (void)snprintf(command.common.mesh, sizeof(command.common.mesh), "demo");
      client.query = fake_query;
      client.context = &fake;

      check_int_eq(meshctl_product_execute(&command, &client, out, err), 0);
      check_int_eq(fake.calls, 1);
      check_str_eq(fake.route, "/v1/meshes/demo/nodes?limit=25");
      check_true(fake.remaining_ms > 0u);
      check_true(fake.remaining_ms <= 5000u);
      rewind(out);
      output_size = fread(output, 1u, sizeof(output) - 1u, out);
      output[output_size] = '\0';
      check_str_eq(output, "{\"nodes\":[],\"generation\":7}\n");

      fclose(err);
      fclose(out);
    }

    it("sends a placement plan as a typed bounded POST request") {
      meshctl_product_command_t command;
      meshctl_controller_client_t client;
      fake_controller_t fake;
      FILE *out = tmpfile();
      FILE *err = tmpfile();

      check_not_null(out);
      check_not_null(err);
      memset(&command, 0, sizeof(command));
      memset(&fake, 0, sizeof(fake));
      memset(&client, 0, sizeof(client));
      command.kind = MESHCTL_PRODUCT_COMMAND_PLACEMENTS_PLAN;
      command.common.timeout_ms = 5000u;
      (void)snprintf(command.common.mesh, sizeof(command.common.mesh), "demo");
      (void)snprintf(command.args.placements_plan.subject,
                     sizeof(command.args.placements_plan.subject),
                     "release:web-v42");
      command.args.placements_plan.selector_language_version =
          TURBO_SELECTOR_LANGUAGE_VERSION_V1;
      (void)snprintf(command.args.placements_plan.selector,
                     sizeof(command.args.placements_plan.selector),
                     "region == \"eu\"");
      client.request = fake_request;
      client.context = &fake;

      check_int_eq(meshctl_product_execute(&command, &client, out, err), 0);
      check_int_eq(fake.calls, 1);
      check_int_eq(fake.method, MESHCTL_CONTROLLER_METHOD_POST);
      check_str_eq(fake.route, "/v1/meshes/demo/placements:plan");
      check_str_contains(fake.body, "\"schema_version\":1");
      check_str_contains(fake.body, "\"subject\":\"release:web-v42\"");
      check_str_contains(fake.body, "\"selector\":\"region == \\\"eu\\\"\"");

      fclose(err);
      fclose(out);
    }

    it("sends Network plan documents and bounded drain-delete requests") {
      meshctl_product_command_t command;
      meshctl_controller_client_t client;
      fake_controller_t fake;
      FILE *out = tmpfile();
      FILE *err = tmpfile();
      char *document = tt_make_temp_file("meshctl-product", "-network.json");
      static const char json[] = "{\"schema_version\":1,\"name\":\"production\"}";

      check_not_null(out);
      check_not_null(err);
      check_not_null(document);
      check_int_eq(tt_write_file(document, json, sizeof(json) - 1u), 0);
      memset(&command, 0, sizeof(command));
      memset(&fake, 0, sizeof(fake));
      memset(&client, 0, sizeof(client));
      command.kind = MESHCTL_PRODUCT_COMMAND_NETWORKS_PLAN;
      command.common.timeout_ms = 5000u;
      (void)snprintf(command.common.mesh, sizeof(command.common.mesh), "demo");
      (void)snprintf(command.args.networks_mutation.file,
                     sizeof(command.args.networks_mutation.file), "%s", document);
      client.request = fake_request;
      client.context = &fake;

      check_int_eq(meshctl_product_execute(&command, &client, out, err), 0);
      check_int_eq(fake.method, MESHCTL_CONTROLLER_METHOD_POST);
      check_str_eq(fake.route, "/v1/meshes/demo/networks:plan");
      check_str_eq(fake.body, json);

      memset(&fake, 0, sizeof(fake));
      command.kind = MESHCTL_PRODUCT_COMMAND_NETWORKS_DELETE;
      (void)snprintf(command.args.networks_delete.network,
                     sizeof(command.args.networks_delete.network), "production");
      command.args.networks_delete.drain_timeout_ms = 45000u;
      check_int_eq(meshctl_product_execute(&command, &client, out, err), 0);
      check_str_eq(fake.route,
                   "/v1/meshes/demo/networks/production:delete");
      check_str_contains(fake.body, "\"drain_timeout_ms\":45000");

      (void)tt_remove_file(document);
      free(document);
      fclose(err);
      fclose(out);
    }

    it("releases a failed client response before returning") {
      meshctl_product_command_t command;
      meshctl_controller_client_t client;
      fake_controller_t fake;
      FILE *out = tmpfile();
      FILE *err = tmpfile();

      check_not_null(out);
      check_not_null(err);
      memset(&command, 0, sizeof(command));
      memset(&fake, 0, sizeof(fake));
      memset(&client, 0, sizeof(client));
      command.kind = MESHCTL_PRODUCT_COMMAND_NODES_LIST;
      command.common.timeout_ms = 5000u;
      command.common.page_size = 25u;
      (void)snprintf(command.common.mesh, sizeof(command.common.mesh), "demo");
      fake.result = MESHCTL_CONTROLLER_TIMEOUT;
      client.query = fake_query;
      client.context = &fake;

      check_int_eq(meshctl_product_execute(&command, &client, out, err), 7);
      check_int_eq(fake.calls, 1);

      fclose(err);
      fclose(out);
    }
  }
}
