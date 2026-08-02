#include <tinytest.h>

#include "mesh_mgmt_crypto.h"
#include "mesh_mgmt_execution_node.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
  static const uint8_t private_key[32] = {
      1u, 3u, 5u, 7u, 9u, 11u, 13u, 15u,
      17u, 19u, 21u, 23u, 25u, 27u, 29u, 31u,
      2u, 4u, 6u, 8u, 10u, 12u, 14u, 16u,
      18u, 20u, 22u, 24u, 26u, 28u, 30u, 32u};

  memset(config, 0, sizeof(*config));
  memset(deployment, 0, sizeof(*deployment));
  memset(deployment->deployment_id, 0x21, sizeof(deployment->deployment_id));
  deployment->generation = 1u;
  deployment->module_path = MESH_TEST_EXECUTION_WASM;
  check_int_eq(mesh_mgmt_execution_runner_module_digest_v1(
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
  memcpy(config->result_private_key, private_key,
         sizeof(config->result_private_key));
  check_int_eq(mesh_mgmt_ed25519_public_from_private(
                   private_key, config->grant_issuer_key),
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
  check_int_eq(mesh_mgmt_execution_node_init_v1(&node, &config),
               MESH_MGMT_EXECUTION_NODE_OK);
  mesh_mgmt_execution_node_destroy_v1(&node);

  deployment.module_digest[0] ^= 0xffu;
  check_int_eq(mesh_mgmt_execution_node_init_v1(&node, &config),
               MESH_MGMT_EXECUTION_NODE_DEPLOYMENT_FAILED);
  mesh_mgmt_execution_node_destroy_v1(&node);
  (void)remove(store_path);
  free(store_path);
}

spec("mesh management TurboRuntime node composition") {
  describe("prestaged deployment boundary") {
    it("binds configured digests before accepting work") {
      test_binds_every_prestaged_module_digest();
    }
  }
}
