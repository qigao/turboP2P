#include "mesh_mgmt_execution_rpc_registry.h"

#include <tinytest.h>

#include <string.h>

#define TEST_NOW_MS 1000u
#define TEST_DEADLINE_MS 2000u
#define TEST_RETENTION_MS 500u

static void fill_bytes(uint8_t *bytes, size_t size, uint8_t first) {
  size_t index;

  for (index = 0u; index < size; ++index)
    bytes[index] = (uint8_t)(first + index);
}

static void make_binding(mesh_mgmt_execution_rpc_binding_v1_t *binding,
                         uint8_t first) {
  memset(binding, 0, sizeof(*binding));
  fill_bytes(binding->command_id, sizeof(binding->command_id), first);
  fill_bytes(binding->correlation_id, sizeof(binding->correlation_id),
             (uint8_t)(first + 0x10u));
  fill_bytes(binding->request_digest, sizeof(binding->request_digest),
             (uint8_t)(first + 0x20u));
  fill_bytes(binding->target_node_id, sizeof(binding->target_node_id),
             (uint8_t)(first + 0x40u));
  binding->deadline_ms = TEST_DEADLINE_MS;
}

static void make_result_response(
    const mesh_mgmt_execution_rpc_binding_v1_t *binding,
    mesh_mgmt_execution_response_v1_t *response) {
  memset(response, 0, sizeof(*response));
  response->kind = MESH_MGMT_KIND_COMMAND_RESULT;
  memcpy(response->result.command_id, binding->command_id,
         sizeof(response->result.command_id));
  memcpy(response->result.correlation_id, binding->correlation_id,
         sizeof(response->result.correlation_id));
  memcpy(response->result.request_digest, binding->request_digest,
         sizeof(response->result.request_digest));
  memcpy(response->result.target_node_id, binding->target_node_id,
         sizeof(response->result.target_node_id));
}

static void make_status_response(
    const mesh_mgmt_execution_rpc_binding_v1_t *binding,
    mesh_mgmt_execution_response_v1_t *response) {
  memset(response, 0, sizeof(*response));
  response->kind = MESH_MGMT_KIND_COMMAND_STATUS;
  response->status.version = MESH_MGMT_EXECUTION_SCHEMA_V1;
  response->status.code = MESH_MGMT_EXECUTION_STATUS_BUSY;
  memcpy(response->status.command_id, binding->command_id,
         sizeof(response->status.command_id));
  memcpy(response->status.correlation_id, binding->correlation_id,
         sizeof(response->status.correlation_id));
  memcpy(response->status.request_digest, binding->request_digest,
         sizeof(response->status.request_digest));
  memcpy(response->status.responder_node_id, binding->target_node_id,
         sizeof(response->status.responder_node_id));
}

static void test_registry_commits_an_exact_result_once(void) {
  mesh_mgmt_execution_rpc_registry_v1_t registry = {0};
  mesh_mgmt_execution_rpc_binding_v1_t binding;
  mesh_mgmt_execution_rpc_completion_v1_t completion;
  mesh_mgmt_execution_response_v1_t response;

  make_binding(&binding, 0x11u);
  make_result_response(&binding, &response);
  check_int_eq(mesh_mgmt_execution_rpc_registry_init_v1(
                   &registry, 2u, TEST_RETENTION_MS),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  check_int_eq(mesh_mgmt_execution_rpc_registry_register_v1(
                   &registry, &binding, TEST_NOW_MS),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  check_int_eq(mesh_mgmt_execution_rpc_registry_get_v1(
                   &registry, binding.correlation_id, TEST_NOW_MS,
                   &completion),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  check_int_eq(completion.state, MESH_MGMT_EXECUTION_RPC_PENDING);
  check_int_eq(mesh_mgmt_execution_rpc_registry_release_v1(
                   &registry, binding.correlation_id),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_NOT_READY);
  check_int_eq(mesh_mgmt_execution_rpc_registry_complete_v1(
                   &registry, &response, 1200u),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  check_int_eq(mesh_mgmt_execution_rpc_registry_complete_v1(
                   &registry, &response, 1201u),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_ALREADY_COMPLETE);
  check_int_eq(mesh_mgmt_execution_rpc_registry_get_v1(
                   &registry, binding.correlation_id, 1201u, &completion),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  check_int_eq(completion.state, MESH_MGMT_EXECUTION_RPC_RESULT);
  check_mem_eq(completion.response.result.request_digest,
               binding.request_digest, sizeof(binding.request_digest));
  check_int_eq(mesh_mgmt_execution_rpc_registry_release_v1(
                   &registry, binding.correlation_id),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  check_int_eq(mesh_mgmt_execution_rpc_registry_get_v1(
                   &registry, binding.correlation_id, 1202u, &completion),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_NOT_FOUND);
  mesh_mgmt_execution_rpc_registry_destroy_v1(&registry);
}

static void test_registry_preserves_retryable_status(void) {
  mesh_mgmt_execution_rpc_registry_v1_t registry = {0};
  mesh_mgmt_execution_rpc_binding_v1_t binding;
  mesh_mgmt_execution_rpc_completion_v1_t completion;
  mesh_mgmt_execution_response_v1_t response;

  make_binding(&binding, 0x21u);
  make_status_response(&binding, &response);
  check_int_eq(mesh_mgmt_execution_rpc_registry_init_v1(
                   &registry, 1u, TEST_RETENTION_MS),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  check_int_eq(mesh_mgmt_execution_rpc_registry_register_v1(
                   &registry, &binding, TEST_NOW_MS),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  check_int_eq(mesh_mgmt_execution_rpc_registry_complete_v1(
                   &registry, &response, 1100u),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  check_int_eq(mesh_mgmt_execution_rpc_registry_get_v1(
                   &registry, binding.correlation_id, 1100u, &completion),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  check_int_eq(completion.state, MESH_MGMT_EXECUTION_RPC_STATUS);
  check_int_eq(completion.response.status.code,
               MESH_MGMT_EXECUTION_STATUS_BUSY);
  check_true(mesh_mgmt_execution_status_is_retryable_v1(
      completion.response.status.code));
  mesh_mgmt_execution_rpc_registry_destroy_v1(&registry);
}

static void test_registry_rejects_mismatched_response_bindings(void) {
  mesh_mgmt_execution_rpc_registry_v1_t registry = {0};
  mesh_mgmt_execution_rpc_binding_v1_t binding;
  mesh_mgmt_execution_rpc_completion_v1_t completion;
  mesh_mgmt_execution_response_v1_t response;

  make_binding(&binding, 0x31u);
  make_result_response(&binding, &response);
  check_int_eq(mesh_mgmt_execution_rpc_registry_init_v1(
                   &registry, 1u, TEST_RETENTION_MS),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  check_int_eq(mesh_mgmt_execution_rpc_registry_register_v1(
                   &registry, &binding, TEST_NOW_MS),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  response.result.target_node_id[0] ^= 1u;
  check_int_eq(mesh_mgmt_execution_rpc_registry_complete_v1(
                   &registry, &response, 1100u),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_AUTH_FAILED);
  check_int_eq(mesh_mgmt_execution_rpc_registry_get_v1(
                   &registry, binding.correlation_id, 1100u, &completion),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  check_int_eq(completion.state, MESH_MGMT_EXECUTION_RPC_PENDING);
  mesh_mgmt_execution_rpc_registry_destroy_v1(&registry);
}

static void test_registry_bounds_identity_and_retention(void) {
  mesh_mgmt_execution_rpc_registry_v1_t registry = {0};
  mesh_mgmt_execution_rpc_binding_v1_t first;
  mesh_mgmt_execution_rpc_binding_v1_t second;
  mesh_mgmt_execution_rpc_binding_v1_t conflict;
  mesh_mgmt_execution_rpc_completion_v1_t completion;

  make_binding(&first, 0x41u);
  make_binding(&second, 0x71u);
  conflict = first;
  conflict.request_digest[0] ^= 1u;
  check_int_eq(mesh_mgmt_execution_rpc_registry_init_v1(
                   &registry, 1u, TEST_RETENTION_MS),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  check_int_eq(mesh_mgmt_execution_rpc_registry_register_v1(
                   &registry, &first, TEST_NOW_MS),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  check_int_eq(mesh_mgmt_execution_rpc_registry_register_v1(
                   &registry, &first, TEST_NOW_MS),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_ALREADY_EXISTS);
  check_int_eq(mesh_mgmt_execution_rpc_registry_register_v1(
                   &registry, &conflict, TEST_NOW_MS),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_CONFLICT);
  check_int_eq(mesh_mgmt_execution_rpc_registry_register_v1(
                   &registry, &second, TEST_NOW_MS),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_RESOURCE_EXHAUSTED);
  check_int_eq(mesh_mgmt_execution_rpc_registry_get_v1(
                   &registry, first.correlation_id, TEST_DEADLINE_MS,
                   &completion),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  check_int_eq(completion.state, MESH_MGMT_EXECUTION_RPC_TIMED_OUT);
  check_size_eq(mesh_mgmt_execution_rpc_registry_sweep_v1(
                    &registry, TEST_DEADLINE_MS + TEST_RETENTION_MS),
                1u);
  check_int_eq(mesh_mgmt_execution_rpc_registry_get_v1(
                   &registry, first.correlation_id,
                   TEST_DEADLINE_MS + TEST_RETENTION_MS, &completion),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_NOT_FOUND);
  check_int_eq(mesh_mgmt_execution_rpc_registry_register_v1(
                   &registry, &second,
                   TEST_DEADLINE_MS + TEST_RETENTION_MS),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_INVALID_ARG);
  second.deadline_ms = TEST_DEADLINE_MS + TEST_RETENTION_MS + 1000u;
  check_int_eq(mesh_mgmt_execution_rpc_registry_register_v1(
                   &registry, &second,
                   TEST_DEADLINE_MS + TEST_RETENTION_MS),
               MESH_MGMT_EXECUTION_RPC_REGISTRY_OK);
  mesh_mgmt_execution_rpc_registry_destroy_v1(&registry);
}

spec("mesh management execution RPC registry E9") {
  describe("bounded correlation state") {
    it("commits an exactly bound result only once") {
      test_registry_commits_an_exact_result_once();
    }
    it("preserves a retryable status response") {
      test_registry_preserves_retryable_status();
    }
    it("rejects a mismatched responder binding") {
      test_registry_rejects_mismatched_response_bindings();
    }
    it("bounds identity reuse, capacity, timeout, and retention") {
      test_registry_bounds_identity_and_retention();
    }
  }
}
