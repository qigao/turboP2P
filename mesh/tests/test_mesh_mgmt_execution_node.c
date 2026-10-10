#include <tinytest.h>

#include "mesh_mgmt_crypto.h"
#include "mesh_mgmt_execution_node.h"
#include "mesh_mgmt_execution_wire.h"
#include <salts/clock.h>
#include <salts/thread.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Deterministic TEST signing key, not a product or user credential. */
static const uint8_t TEST_NODE_EXECUTION_PRIVATE_KEY[32] = {
    1u, 3u, 5u, 7u, 9u, 11u, 13u, 15u,
    17u, 19u, 21u, 23u, 25u, 27u, 29u, 31u,
    2u, 4u, 6u, 8u, 10u, 12u, 14u, 16u,
    18u, 20u, 22u, 24u, 26u, 28u, 30u, 32u
};

static uint64_t node_test_now(void *context) {
  (void)context;
  return 1000u;
}

static void fill_limits(mesh_mgmt_execution_limits_v1_t *limits) {
  memset(limits, 0, sizeof(*limits));
  limits->module_bytes = 1024u * 1024u;
  limits->stack_bytes = 64u * 1024u;
  limits->linear_memory_bytes = 256u * 1024u;
  limits->timeout_ms = 1000u;
  limits->control_flow_steps = 1000000u;
  limits->host_calls = 128u;
  limits->copied_guest_bytes = 1024u * 1024u;
  limits->input_bytes = 64u * 1024u;
  limits->stdout_bytes = 64u * 1024u;
  limits->stderr_bytes = 64u * 1024u;
}

static void fill_config(
    mesh_mgmt_execution_node_config_v1_t *config,
    mesh_mgmt_execution_deployment_v1_t *deployment,
    const char *store_path) {
  memset(config, 0, sizeof(*config));
  memset(deployment, 0, sizeof(*deployment));
  memset(deployment->deployment_id, 0x21, sizeof(deployment->deployment_id));
  deployment->generation = 1u;
  deployment->module_path = MESH_TEST_EXECUTION_WASM;
  check_equal(mesh_mgmt_execution_runner_module_digest_v1(
                   deployment->module_path, 1024u * 1024u,
                   deployment->module_digest, NULL),
               MESH_MGMT_EXECUTION_RUNNER_OK);
  config->store_path = store_path;
  config->store_capacity = 8u;
  config->deployment_capacity = 1u;
  config->worker_queue_capacity = 4u;
  config->egress_capacity = 4u;
  config->deployments = deployment;
  config->deployment_count = 1u;
  memset(config->local_node_id, 0x31, sizeof(config->local_node_id));
  memcpy(config->result_private_key, TEST_NODE_EXECUTION_PRIVATE_KEY,
         sizeof(config->result_private_key));
  check_equal(mesh_mgmt_ed25519_public_from_private(
                   TEST_NODE_EXECUTION_PRIVATE_KEY, config->grant_issuer_key),
               MESH_MGMT_CRYPTO_OK);
  config->host_capabilities = MESH_MGMT_EXECUTION_NODE_RAW_CAPABILITIES;
  config->hard_capabilities = MESH_MGMT_EXECUTION_NODE_RAW_CAPABILITIES;
  fill_limits(&config->host_limits);
  fill_limits(&config->hard_limits);
  config->worker_generation = 1u;
  config->clock_now_ms = node_test_now;
}

static void test_binds_every_prestaged_module_digest(void) {
  mesh_mgmt_execution_node_config_v1_t config;
  mesh_mgmt_execution_deployment_v1_t deployment;
  mesh_mgmt_execution_node_v1_t node;
  char *store_path = tt_make_temp_file("mesh-execution-node", ".journal");

  check_not_null(store_path);
  if (!store_path)
    return;
  (void)remove(store_path);
  fill_config(&config, &deployment, store_path);
  memset(&node, 0, sizeof(node));
  check_equal(mesh_mgmt_execution_node_init_v1(&node, &config),
               MESH_MGMT_EXECUTION_NODE_OK);
  mesh_mgmt_execution_node_destroy_v1(&node);

  deployment.module_digest[0] ^= 0xffu;
  check_equal(mesh_mgmt_execution_node_init_v1(&node, &config),
               MESH_MGMT_EXECUTION_NODE_DEPLOYMENT_FAILED);
  mesh_mgmt_execution_node_destroy_v1(&node);
  (void)remove(store_path);
  free(store_path);
}


static void fill_execution_command(
    const mesh_mgmt_execution_node_config_v1_t *config,
    const mesh_mgmt_execution_deployment_v1_t *deployment,
    mesh_mgmt_execution_shadow_command_v1_t *command) {
  mesh_mgmt_execution_grant_v1_t *grant = &command->grant;
  mesh_mgmt_execution_request_v1_t *request = &command->request;
  memset(command, 0, sizeof(*command));

  grant->version = MESH_MGMT_EXECUTION_SCHEMA_V1;
  memset(grant->grant_id, 0x11, sizeof(grant->grant_id));
  memset(grant->mesh_id, 0x22, sizeof(grant->mesh_id));
  grant->policy_epoch = 1u;
  memset(grant->subject_principal, 0x33, sizeof(grant->subject_principal));
  memcpy(grant->target_node_id, config->local_node_id,
         sizeof(grant->target_node_id));
  memcpy(grant->deployment_id, deployment->deployment_id,
         sizeof(grant->deployment_id));
  grant->deployment_generation = deployment->generation;
  memcpy(grant->package_digest, deployment->module_digest,
         sizeof(grant->package_digest));
  grant->operation = MESH_MGMT_EXECUTION_OPERATION_RUN_PRESTAGED_WASM;
  grant->capabilities = config->host_capabilities;
  grant->max_limits = config->host_limits;
  grant->not_before_ms = 900u;
  grant->expires_at_ms = 5000u;
  check_equal(mesh_mgmt_execution_grant_sign_v1(
      grant, TEST_NODE_EXECUTION_PRIVATE_KEY), MESH_MGMT_EXECUTION_WIRE_OK);

  request->version = MESH_MGMT_EXECUTION_SCHEMA_V1;
  memset(request->command_id, 0x44, sizeof(request->command_id));
  memcpy(request->grant_id, grant->grant_id, sizeof(request->grant_id));
  memcpy(request->target_node_id, grant->target_node_id,
         sizeof(request->target_node_id));
  memcpy(request->deployment_id, grant->deployment_id,
         sizeof(request->deployment_id));
  request->deployment_generation = grant->deployment_generation;
  memcpy(request->package_digest, grant->package_digest,
         sizeof(request->package_digest));
  request->input_kind = MESH_MGMT_EXECUTION_INPUT_NONE;
  request->output_mode = MESH_MGMT_EXECUTION_OUTPUT_DIGEST;
  request->deadline_ms = 4000u;
  memset(request->request_nonce, 0x55, sizeof(request->request_nonce));
  memset(request->correlation_id, 0x66, sizeof(request->correlation_id));
  memset(command->reply_node_id, 0x77, sizeof(command->reply_node_id));
  check_equal(mesh_mgmt_execution_grant_verify_v1(
      grant, config->grant_issuer_key, node_test_now(NULL)),
      MESH_MGMT_EXECUTION_WIRE_OK);
  check_equal(mesh_mgmt_execution_request_validate_v1(
      request, node_test_now(NULL)), MESH_MGMT_EXECUTION_OK);
  check_equal(mesh_mgmt_execution_request_bind_v1(
      grant, request), MESH_MGMT_EXECUTION_OK);
  check_equal(mesh_mgmt_execution_request_digest_v1(
      request, command->request_digest), MESH_MGMT_EXECUTION_RESULT_OK);
}

static int await_signed_worker_result(
    mesh_mgmt_execution_node_v1_t *node,
    mesh_mgmt_execution_egress_item_v1_t *out_item) {
  const uint64_t deadline = cmeta_monotonic_ms() + 10000u;
  for (;;) {
    mesh_mgmt_execution_egress_result_t result =
        mesh_mgmt_execution_egress_peek_v1(&node->egress, out_item);
    if (result == MESH_MGMT_EXECUTION_EGRESS_OK) return 1;
    if (result != MESH_MGMT_EXECUTION_EGRESS_EMPTY ||
        cmeta_monotonic_ms() >= deadline) return 0;
    cmeta_sleep_ms(1u);
  }
}

/* This really runs an installed/prestaged WebAssembly guest via the
 * production Node → Worker → Service → Orchestrator → TurboRuntime runner,
 * not the old stub/fixture that only signed an invented result. */
static void test_worker_executes_real_prestaged_wasm_once(void) {
  mesh_mgmt_execution_node_config_v1_t config = {0};
  mesh_mgmt_execution_deployment_v1_t deployment = {0};
  mesh_mgmt_execution_node_v1_t node = {0};
  mesh_mgmt_execution_shadow_command_v1_t command = {0};
  mesh_mgmt_execution_egress_item_v1_t item = {0};
  mesh_mgmt_execution_result_v1_t decoded = {0};
  uint8_t original_signature[MESH_MGMT_EXECUTION_SIGNATURE_SIZE] = {0};
  uint64_t generation;
  char *path = tt_make_temp_file("mesh-execution-real-wasm", ".journal");

  check_not_null(path);
  if (!path) return;
  (void)remove(path);
  fill_config(&config, &deployment, path);
  deployment.module_path = MESH_TEST_EXECUTION_SUCCESS_WASM;
  check_equal(mesh_mgmt_execution_runner_module_digest_v1(
      deployment.module_path, config.hard_limits.module_bytes,
      deployment.module_digest, NULL), MESH_MGMT_EXECUTION_RUNNER_OK);
  /* NULL runner adapter means the production TurboWasm Wasm engine
   * executes the actual prestaged guest, not a test callback. */
  check_true(config.execute_runner == NULL);
  check_equal(mesh_mgmt_execution_node_init_v1(&node, &config),
               MESH_MGMT_EXECUTION_NODE_OK);
  check_true(node.orchestrator.execute_runner == NULL);
  fill_execution_command(&config, &deployment, &command);
  check_equal(mesh_mgmt_execution_node_try_submit_v1(&node, &command),
               MESH_MGMT_EXECUTION_NODE_OK);
  check_true(await_signed_worker_result(&node, &item));
  check_equal(item.service_result, MESH_MGMT_EXECUTION_SERVICE_OK);
  check_equal(item.result_payload_size,
                MESH_MGMT_EXECUTION_COMMAND_RESULT_SIZE_V1);
  check_equal(mesh_mgmt_execution_command_result_decode_v1(
      item.result_payload, item.result_payload_size, &decoded),
      MESH_MGMT_EXECUTION_WIRE_OK);
  check_equal(mesh_mgmt_execution_result_verify_v1(
      &decoded, node.orchestrator.result_public_key),
      MESH_MGMT_EXECUTION_RESULT_OK);
  check_equal(decoded.state, MESH_MGMT_EXECUTION_STATE_SUCCEEDED);
  check_equal(decoded.guest_exit_code, 0);
  check_true(decoded.usage.invocations > 0u);
  check_equal(decoded.request_digest, command.request_digest,
               sizeof(command.request_digest));
  check_equal(decoded.command_id, command.request.command_id,
               sizeof(command.request.command_id));
  check_equal(decoded.correlation_id, command.request.correlation_id,
               sizeof(command.request.correlation_id));
  check_equal(decoded.target_node_id, config.local_node_id,
               sizeof(config.local_node_id));
  check_equal(decoded.package_digest, deployment.module_digest,
               sizeof(deployment.module_digest));
  memcpy(original_signature, decoded.signature, sizeof(original_signature));
  generation = node.store.journal.generation;
  check_equal(mesh_mgmt_execution_egress_consume_v1(&node.egress),
               MESH_MGMT_EXECUTION_EGRESS_OK);

  /* Explicit repeat of the identical operation reads the committed signed
   * result; it does NOT execute a second guest or advance the store journal. */
  check_equal(mesh_mgmt_execution_node_try_submit_v1(&node, &command),
               MESH_MGMT_EXECUTION_NODE_OK);
  check_true(await_signed_worker_result(&node, &item));
  check_equal(item.service_result, MESH_MGMT_EXECUTION_SERVICE_OK);
  check_equal(original_signature, item.result.signature,
               sizeof(original_signature));
  check_equal(node.store.journal.generation, generation);
  check_equal(mesh_mgmt_execution_egress_consume_v1(&node.egress),
               MESH_MGMT_EXECUTION_EGRESS_OK);

  check_equal(mesh_mgmt_execution_node_shutdown_v1(&node),
               MESH_MGMT_EXECUTION_NODE_OK);
  check_equal(mesh_mgmt_execution_node_try_submit_v1(&node, &command),
               MESH_MGMT_EXECUTION_NODE_CLOSED);
  mesh_mgmt_execution_node_destroy_v1(&node);
  (void)remove(path);
  free(path);
}

spec("mesh management TurboWasm node composition") {
  describe("prestaged deployment boundary") {
    it("binds configured digests before accepting work") {
      test_binds_every_prestaged_module_digest();
    }
    it("runs a REAL prestaged success Wasm via the Worker and replays only the durable result") {
      test_worker_executes_real_prestaged_wasm_once();
    }
  }
}
