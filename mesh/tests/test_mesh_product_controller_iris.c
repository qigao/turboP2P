#include "mesh_product_controller_iris.h"
#include "tinytest.h"

#include <stdio.h>
#include <string.h>

static const char TEST_CERTIFICATE_DIGEST[] =
    "sha256:0123456789abcdef0123456789abcdef"
    "0123456789abcdef0123456789abcdef";
static const uint8_t TEST_SELECTOR_DIGEST[MESH_PRODUCT_SELECTOR_DIGEST_SIZE_V1] = {
    0x9b, 0xa5, 0xc7, 0xe5, 0x2b, 0xe7, 0xa5, 0x2c,
    0x53, 0x1a, 0xb3, 0xc2, 0x4e, 0x64, 0xeb, 0xc3,
    0x3a, 0x13, 0xc5, 0x46, 0xde, 0xdf, 0xdc, 0xea,
    0xdb, 0x2c, 0xed, 0xb1, 0xe7, 0x21, 0xa3, 0x56};

typedef struct {
  mesh_control_result_t authorization;
  mesh_control_result_t query_result;
  int invalid_json;
  size_t authorizations;
  size_t queries;
  size_t plans;
  size_t network_requests;
  size_t last_predicate_count;
  uint64_t last_deadline_ms;
  int last_selector_match;
  uint8_t last_selector_digest[MESH_PRODUCT_SELECTOR_DIGEST_SIZE_V1];
  mesh_product_query_kind_v1_t last_kind;
  char last_mesh[32];
  char last_resource[32];
  char last_subject[64];
  char last_selector[256];
  uint32_t last_limit;
  mesh_product_query_kind_v1_t last_network_kind;
  char last_network[32];
  char last_network_document[256];
  uint32_t last_network_drain_timeout_ms;
} controller_fixture_t;

static int resolve_plan_field(void *context, const char *field,
                              size_t field_size, const char **out_value,
                              size_t *out_value_size) {
  (void)context;
  if (field_size == 6u && memcmp(field, "region", 6u) == 0) {
    *out_value = "eu";
    *out_value_size = 2u;
    return 1;
  }
  if (field_size == 4u && memcmp(field, "role", 4u) == 0) {
    *out_value = "edge";
    *out_value_size = 4u;
    return 1;
  }
  return 0;
}

static int resolve_plan_capability(void *context, const char *capability,
                                   size_t capability_size) {
  (void)context;
  (void)capability;
  (void)capability_size;
  return 0;
}

static mesh_control_result_t render_plan(
    void *context, const char *mesh,
    const mesh_product_placement_plan_v1_t *request, char *output,
    size_t output_capacity, size_t *out_size) {
  static const char body[] =
      "{\"inventory_generation\":7,\"target_count\":2}";
  controller_fixture_t *fixture = (controller_fixture_t *)context;
  turbo_selector_eval_ops_v1_t eval_ops = {
      TURBO_SELECTOR_EVAL_OPS_V1_SIZE, resolve_plan_field,
      resolve_plan_capability};
  turbo_selector_diagnostic_v1_t diagnostic = {
      TURBO_SELECTOR_DIAGNOSTIC_V1_SIZE};
  fixture->plans++;
  (void)snprintf(fixture->last_mesh, sizeof(fixture->last_mesh), "%s", mesh);
  (void)snprintf(fixture->last_subject, sizeof(fixture->last_subject), "%s",
                 request->subject);
  (void)snprintf(fixture->last_selector, sizeof(fixture->last_selector), "%s",
                 request->selector);
  check_not_null(request->selector_program);
  fixture->last_predicate_count = request->predicate_count;
  fixture->last_deadline_ms = request->deadline_ms;
  memcpy(fixture->last_selector_digest, request->selector_digest,
         sizeof(fixture->last_selector_digest));
  if (turbo_selector_program_evaluate_v1(
          request->selector_program, &eval_ops, fixture,
          &fixture->last_selector_match, &diagnostic) != TURBO_SELECTOR_OK)
    return MESH_CONTROL_INVALID_STATE;
  *out_size = sizeof(body) - 1u;
  if (*out_size > output_capacity) return MESH_CONTROL_RESOURCE_EXHAUSTED;
  memcpy(output, body, *out_size);
  return fixture->query_result;
}

static mesh_control_result_t handle_network(
    void *context, const char *mesh,
    const mesh_product_network_request_v1_t *request, char *output,
    size_t output_capacity, size_t *out_size) {
  static const char body[] =
      "{\"operation_id\":\"op-network-1\",\"state\":\"accepted\"}";
  controller_fixture_t *fixture = (controller_fixture_t *)context;
  size_t copy_size;
  fixture->network_requests++;
  fixture->last_network_kind = request->kind;
  (void)snprintf(fixture->last_mesh, sizeof(fixture->last_mesh), "%s", mesh);
  if (request->network)
    (void)snprintf(fixture->last_network, sizeof(fixture->last_network),
                   "%s", request->network);
  copy_size = request->document_size < sizeof(fixture->last_network_document) - 1u
                  ? request->document_size
                  : sizeof(fixture->last_network_document) - 1u;
  memcpy(fixture->last_network_document, request->document, copy_size);
  fixture->last_network_document[copy_size] = '\0';
  fixture->last_deadline_ms = request->deadline_ms;
  fixture->last_network_drain_timeout_ms = request->drain_timeout_ms;
  *out_size = sizeof(body) - 1u;
  if (*out_size > output_capacity) return MESH_CONTROL_RESOURCE_EXHAUSTED;
  memcpy(output, body, *out_size);
  return fixture->query_result;
}

static mesh_control_result_t authorize_query(
    void *context, const char *peer_certificate_sha256, const char *mesh,
    mesh_product_query_kind_v1_t query_kind) {
  controller_fixture_t *fixture = (controller_fixture_t *)context;
  check_str_eq(peer_certificate_sha256, TEST_CERTIFICATE_DIGEST);
  check_str_eq(mesh, "demo");
  fixture->authorizations++;
  fixture->last_kind = query_kind;
  return fixture->authorization;
}

static mesh_control_result_t render_query(
    void *context, mesh_product_query_kind_v1_t query_kind,
    const char *mesh, const char *resource_id, uint32_t page_limit,
    char *output, size_t output_capacity, size_t *out_size) {
  controller_fixture_t *fixture = (controller_fixture_t *)context;
  const char *body = fixture->invalid_json ? "not-json" :
      "{\"generation\":7,\"nodes\":[]}";
  size_t body_size = strlen(body);
  fixture->queries++;
  fixture->last_kind = query_kind;
  fixture->last_limit = page_limit;
  (void)snprintf(fixture->last_mesh, sizeof(fixture->last_mesh), "%s", mesh);
  if (resource_id)
    (void)snprintf(fixture->last_resource, sizeof(fixture->last_resource),
                   "%s", resource_id);
  if (fixture->query_result != MESH_CONTROL_OK)
    return fixture->query_result;
  *out_size = body_size;
  if (body_size > output_capacity) return MESH_CONTROL_RESOURCE_EXHAUSTED;
  memcpy(output, body, body_size);
  return MESH_CONTROL_OK;
}

static void configure(mesh_product_controller_iris_config_v1_t *config,
                      controller_fixture_t *fixture) {
  memset(config, 0, sizeof(*config));
  config->authorize = authorize_query;
  config->query = render_query;
  config->context = fixture;
  config->max_response_bytes = 4096u;
  config->max_page_items = 100u;
}

static void configure_plan(mesh_product_controller_iris_config_v1_t *config,
                           controller_fixture_t *fixture) {
  configure(config, fixture);
  config->plan = render_plan;
  config->max_plan_request_bytes = 8192u;
  config->plan_timeout_ms = 30000u;
}

static void configure_network(mesh_product_controller_iris_config_v1_t *config,
                              controller_fixture_t *fixture) {
  configure(config, fixture);
  config->network = handle_network;
  config->max_network_request_bytes = 8192u;
  config->network_timeout_ms = 30000u;
}

spec("Product Controller Iris read-only adapter") {
  describe("authorization and bounded queries") {
    it("authorizes and returns a validated immutable JSON page") {
      mesh_product_controller_iris_v1_t adapter;
      mesh_product_controller_iris_config_v1_t config;
      mesh_product_controller_iris_stats_v1_t stats;
      controller_fixture_t fixture = {MESH_CONTROL_OK, MESH_CONTROL_OK};
      iris_app_t *app = iris_app_create();
      char output[256] = {0};
      size_t output_size = 0u;

      check_not_null(app);
      configure(&config, &fixture);
      check_int_eq(mesh_product_controller_iris_register_v1(
                       &adapter, app, &config),
                   MESH_CONTROL_OK);
      check_int_eq(mesh_product_controller_iris_query_v1(
                       &adapter, TEST_CERTIFICATE_DIGEST,
                       MESH_PRODUCT_QUERY_NODES_LIST, "demo", NULL, 25u,
                       output, sizeof(output), &output_size),
                   MESH_CONTROL_OK);
      check_str_eq(fixture.last_mesh, "demo");
      check_int_eq(fixture.last_kind, MESH_PRODUCT_QUERY_NODES_LIST);
      check_uint_eq(fixture.last_limit, 25u);
      check_size_eq(output_size,
                    strlen("{\"generation\":7,\"nodes\":[]}"));
      check_int_eq(mesh_product_controller_iris_get_stats_v1(&adapter, &stats),
                   MESH_CONTROL_OK);
      check_uint_eq(stats.received, 1u);
      check_uint_eq(stats.authorized, 1u);
      check_uint_eq(stats.succeeded, 1u);

      mesh_product_controller_iris_destroy_v1(&adapter);
      iris_app_destroy(app);
    }

    it("fails closed on authorization and invalid source JSON") {
      mesh_product_controller_iris_v1_t adapter;
      mesh_product_controller_iris_config_v1_t config;
      mesh_product_controller_iris_stats_v1_t stats;
      controller_fixture_t fixture = {MESH_CONTROL_CONFLICT,
                                      MESH_CONTROL_OK};
      iris_app_t *app = iris_app_create();
      char output[256];
      size_t output_size = 0u;

      check_not_null(app);
      memset(output, 0x7f, sizeof(output));
      configure(&config, &fixture);
      check_int_eq(mesh_product_controller_iris_register_v1(
                       &adapter, app, &config),
                   MESH_CONTROL_OK);
      check_int_eq(mesh_product_controller_iris_query_v1(
                       &adapter, TEST_CERTIFICATE_DIGEST,
                       MESH_PRODUCT_QUERY_NODE_GET, "demo", "node-7", 0u,
                       output, sizeof(output), &output_size),
                   MESH_CONTROL_CONFLICT);
      check_uint_eq(fixture.queries, 0u);

      fixture.authorization = MESH_CONTROL_OK;
      fixture.invalid_json = 1;
      check_int_eq(mesh_product_controller_iris_query_v1(
                       &adapter, TEST_CERTIFICATE_DIGEST,
                       MESH_PRODUCT_QUERY_NODE_GET, "demo", "node-7", 0u,
                       output, sizeof(output), &output_size),
                   MESH_CONTROL_INVALID_STATE);
      check_int_eq(output[0], 0);
      check_int_eq(mesh_product_controller_iris_get_stats_v1(&adapter, &stats),
                   MESH_CONTROL_OK);
      check_uint_eq(stats.rejected_auth, 1u);
      check_uint_eq(stats.rejected_source, 1u);

      mesh_product_controller_iris_destroy_v1(&adapter);
      iris_app_destroy(app);
    }

    it("queries Networks and admits bounded authorized mutations") {
      mesh_product_controller_iris_v1_t adapter;
      mesh_product_controller_iris_config_v1_t config;
      controller_fixture_t fixture = {MESH_CONTROL_OK, MESH_CONTROL_OK};
      iris_app_t *app = iris_app_create();
      char output[256] = {0};
      size_t output_size = 0u;
      static const char apply[] =
          "{\"schema_version\":1,\"name\":\"production\"}";
      static const char delete_request[] =
          "{\"schema_version\":1,\"drain_timeout_ms\":30000}";

      check_not_null(app);
      configure_network(&config, &fixture);
      check_int_eq(mesh_product_controller_iris_register_v1(
                       &adapter, app, &config),
                   MESH_CONTROL_OK);
      check_int_eq(mesh_product_controller_iris_query_v1(
                       &adapter, TEST_CERTIFICATE_DIGEST,
                       MESH_PRODUCT_QUERY_NETWORKS_LIST, "demo", NULL, 25u,
                       output, sizeof(output), &output_size),
                   MESH_CONTROL_OK);
      check_int_eq(fixture.last_kind, MESH_PRODUCT_QUERY_NETWORKS_LIST);
      check_int_eq(mesh_product_controller_iris_network_json_v1(
                       &adapter, TEST_CERTIFICATE_DIGEST, "demo",
                       MESH_PRODUCT_QUERY_NETWORK_APPLY, NULL, apply,
                       sizeof(apply) - 1u, output, sizeof(output),
                       &output_size),
                   MESH_CONTROL_OK);
      check_uint_eq(1u, fixture.network_requests);
      check_int_eq(fixture.last_network_kind,
                   MESH_PRODUCT_QUERY_NETWORK_APPLY);
      check_str_eq(fixture.last_network_document, apply);
      check_true(fixture.last_deadline_ms > 0u);

      check_int_eq(mesh_product_controller_iris_network_json_v1(
                       &adapter, TEST_CERTIFICATE_DIGEST, "demo",
                       MESH_PRODUCT_QUERY_NETWORK_DELETE, "production",
                       delete_request, sizeof(delete_request) - 1u, output,
                       sizeof(output), &output_size),
                   MESH_CONTROL_OK);
      check_str_eq(fixture.last_network, "production");
      check_uint_eq(fixture.last_network_drain_timeout_ms, 30000u);

      check_int_eq(mesh_product_controller_iris_network_json_v1(
                       &adapter, TEST_CERTIFICATE_DIGEST, "demo",
                       MESH_PRODUCT_QUERY_NETWORK_DELETE, "production",
                       "{\"schema_version\":1,\"drain_timeout_ms\":300001}",
                       strlen("{\"schema_version\":1,\"drain_timeout_ms\":300001}"),
                       output, sizeof(output), &output_size),
                   MESH_CONTROL_INVALID_ARG);
      check_uint_eq(fixture.network_requests, 2u);

      mesh_product_controller_iris_destroy_v1(&adapter);
      iris_app_destroy(app);
    }

    it("rejects invalid identity, limits and post-close queries") {
      mesh_product_controller_iris_v1_t adapter;
      mesh_product_controller_iris_config_v1_t config;
      controller_fixture_t fixture = {MESH_CONTROL_OK, MESH_CONTROL_OK};
      iris_app_t *app = iris_app_create();
      char output[64];
      size_t output_size = 0u;

      check_not_null(app);
      configure(&config, &fixture);
      check_int_eq(mesh_product_controller_iris_register_v1(
                       &adapter, app, &config),
                   MESH_CONTROL_OK);
      check_int_eq(mesh_product_controller_iris_query_v1(
                       &adapter, "invalid", MESH_PRODUCT_QUERY_NODES_LIST,
                       "demo", NULL, 25u, output, sizeof(output),
                       &output_size),
                   MESH_CONTROL_INVALID_ARG);
      check_int_eq(mesh_product_controller_iris_query_v1(
                       &adapter,
                       "sha256:0123456789ABCDEF0123456789ABCDEF"
                       "0123456789ABCDEF0123456789ABCDEF",
                       MESH_PRODUCT_QUERY_NODES_LIST, "demo", NULL, 25u,
                       output, sizeof(output), &output_size),
                   MESH_CONTROL_INVALID_ARG);
      check_int_eq(mesh_product_controller_iris_query_v1(
                       &adapter, TEST_CERTIFICATE_DIGEST,
                       MESH_PRODUCT_QUERY_NODES_LIST, "demo", NULL, 101u,
                       output, sizeof(output), &output_size),
                   MESH_CONTROL_INVALID_ARG);
      check_int_eq(mesh_product_controller_iris_close_v1(&adapter),
                   MESH_CONTROL_OK);
      check_int_eq(mesh_product_controller_iris_query_v1(
                       &adapter, TEST_CERTIFICATE_DIGEST,
                       MESH_PRODUCT_QUERY_NODES_LIST, "demo", NULL, 25u,
                       output, sizeof(output), &output_size),
                   MESH_CONTROL_CLOSED);

      mesh_product_controller_iris_destroy_v1(&adapter);
      iris_app_destroy(app);
    }
  }


  describe("authoritative placement selector planning") {
    it("recompiles and canonicalizes the selector after authorization") {
      mesh_product_controller_iris_v1_t adapter;
      mesh_product_controller_iris_config_v1_t config;
      mesh_product_controller_iris_stats_v1_t stats;
      controller_fixture_t fixture = {MESH_CONTROL_OK, MESH_CONTROL_OK};
      iris_app_t *app = iris_app_create();
      char output[256] = {0};
      size_t output_size = 0u;
      static const char selector[] =
          "role in [\"edge\",\"cache\"] && region==\"eu\"";

      check_not_null(app);
      configure_plan(&config, &fixture);
      check_int_eq(mesh_product_controller_iris_register_v1(
                       &adapter, app, &config),
                   MESH_CONTROL_OK);
      check_int_eq(mesh_product_controller_iris_plan_v1(
                       &adapter, TEST_CERTIFICATE_DIGEST, "demo",
                       "release:web-v42", 1u, selector,
                       sizeof(selector) - 1u, output, sizeof(output),
                       &output_size),
                   MESH_CONTROL_OK);
      check_uint_eq(fixture.plans, 1u);
      check_int_eq(fixture.last_kind, MESH_PRODUCT_QUERY_PLACEMENT_PLAN);
      check_str_eq(fixture.last_subject, "release:web-v42");
      check_str_eq(fixture.last_selector,
                   "(role in [\"cache\", \"edge\"] && region == \"eu\")");
      check_size_eq(fixture.last_predicate_count, 2u);
      check_true(fixture.last_deadline_ms > 0u);
      check_true(fixture.last_selector_match);
      check_mem_eq(fixture.last_selector_digest, TEST_SELECTOR_DIGEST,
                   sizeof(TEST_SELECTOR_DIGEST));
      check_int_eq(mesh_product_controller_iris_get_stats_v1(&adapter, &stats),
                   MESH_CONTROL_OK);
      check_uint_eq(stats.received, 1u);
      check_uint_eq(stats.authorized, 1u);
      check_uint_eq(stats.succeeded, 1u);

      mesh_product_controller_iris_destroy_v1(&adapter);
      iris_app_destroy(app);
    }

    it("rejects unknown fields without invoking the planner") {
      mesh_product_controller_iris_v1_t adapter;
      mesh_product_controller_iris_config_v1_t config;
      mesh_product_controller_iris_stats_v1_t stats;
      controller_fixture_t fixture = {MESH_CONTROL_OK, MESH_CONTROL_OK};
      iris_app_t *app = iris_app_create();
      char output[64] = {0};
      size_t output_size = 0u;
      static const char selector[] = "secret == \"x\"";

      check_not_null(app);
      configure_plan(&config, &fixture);
      check_int_eq(mesh_product_controller_iris_register_v1(
                       &adapter, app, &config),
                   MESH_CONTROL_OK);
      check_int_eq(mesh_product_controller_iris_plan_v1(
                       &adapter, TEST_CERTIFICATE_DIGEST, "demo",
                       "release:web-v42", 1u, selector,
                       sizeof(selector) - 1u, output, sizeof(output),
                       &output_size),
                   MESH_CONTROL_INVALID_ARG);
      check_uint_eq(fixture.plans, 0u);
      check_int_eq(mesh_product_controller_iris_get_stats_v1(&adapter, &stats),
                   MESH_CONTROL_OK);
      check_uint_eq(stats.rejected_input, 1u);

      mesh_product_controller_iris_destroy_v1(&adapter);
      iris_app_destroy(app);
    }

    it("accepts only the exact versioned JSON request schema") {
      mesh_product_controller_iris_v1_t adapter;
      mesh_product_controller_iris_config_v1_t config;
      controller_fixture_t fixture = {MESH_CONTROL_OK, MESH_CONTROL_OK};
      iris_app_t *app = iris_app_create();
      char output[256] = {0};
      size_t output_size = 0u;
      static const char valid[] =
          "{\"schema_version\":1,\"subject\":\"release:web-v42\","
          "\"selector_language_version\":1,"
          "\"selector\":\"region == \\\"eu\\\"\"}";
      static const char unknown[] =
          "{\"schema_version\":1,\"subject\":\"release:web-v42\","
          "\"selector_language_version\":1,"
          "\"selector\":\"region == \\\"eu\\\"\",\"actor\":\"root\"}";
      static const char duplicate[] =
          "{\"schema_version\":1,\"schema_version\":1,"
          "\"subject\":\"release:web-v42\","
          "\"selector_language_version\":1,"
          "\"selector\":\"region == \\\"eu\\\"\"}";

      check_not_null(app);
      configure_plan(&config, &fixture);
      check_int_eq(mesh_product_controller_iris_register_v1(
                       &adapter, app, &config),
                   MESH_CONTROL_OK);
      check_int_eq(mesh_product_controller_iris_plan_json_v1(
                       &adapter, TEST_CERTIFICATE_DIGEST, "demo", valid,
                       sizeof(valid) - 1u, output, sizeof(output),
                       &output_size),
                   MESH_CONTROL_OK);
      check_uint_eq(fixture.plans, 1u);
      check_int_eq(mesh_product_controller_iris_plan_json_v1(
                       &adapter, TEST_CERTIFICATE_DIGEST, "demo", unknown,
                       sizeof(unknown) - 1u, output, sizeof(output),
                       &output_size),
                   MESH_CONTROL_INVALID_ARG);
      check_int_eq(mesh_product_controller_iris_plan_json_v1(
                       &adapter, TEST_CERTIFICATE_DIGEST, "demo", duplicate,
                       sizeof(duplicate) - 1u, output, sizeof(output),
                       &output_size),
                   MESH_CONTROL_INVALID_ARG);
      check_uint_eq(fixture.plans, 1u);

      mesh_product_controller_iris_destroy_v1(&adapter);
      iris_app_destroy(app);
    }
  }
}
