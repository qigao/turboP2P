#include "mesh_mgmt_execution_result.h"
#include "mesh_mgmt_crypto.h"
#include "tinytest.h"

#include <string.h>

static const uint8_t test_private_key[32] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f};

static void fill_bytes(uint8_t *bytes, size_t size, uint8_t value) {
  memset(bytes, value, size);
}

static void make_result(mesh_mgmt_execution_result_v1_t *result) {
  memset(result, 0, sizeof(*result));
  result->version = MESH_MGMT_EXECUTION_RESULT_VERSION_V1;
  fill_bytes(result->command_id, sizeof(result->command_id), 1u);
  fill_bytes(result->request_digest, sizeof(result->request_digest), 2u);
  fill_bytes(result->target_node_id, sizeof(result->target_node_id), 3u);
  fill_bytes(result->deployment_id, sizeof(result->deployment_id), 4u);
  result->deployment_generation = 5u;
  fill_bytes(result->package_digest, sizeof(result->package_digest), 6u);
  result->policy_epoch = 7u;
  fill_bytes(result->grant_id, sizeof(result->grant_id), 8u);
  result->state = MESH_MGMT_EXECUTION_STATE_SUCCEEDED;
  result->runtime_stage = 7;
  result->usage.invocations = 1u;
  result->usage.host_calls = 2u;
  result->usage.copied_guest_bytes = 3u;
  result->usage.modules_loaded = 1u;
  result->stdout_bytes = 4u;
  fill_bytes(result->stdout_digest, sizeof(result->stdout_digest), 9u);
  fill_bytes(result->stderr_digest, sizeof(result->stderr_digest), 10u);
  result->started_at_ms = 100u;
  result->finished_at_ms = 110u;
  result->worker_generation = 11u;
  fill_bytes(result->correlation_id, sizeof(result->correlation_id), 12u);
}

static void make_request(mesh_mgmt_execution_request_v1_t *request) {
  memset(request, 0, sizeof(*request));
  request->version = MESH_MGMT_EXECUTION_SCHEMA_V1;
  fill_bytes(request->command_id, sizeof(request->command_id), 1u);
  fill_bytes(request->grant_id, sizeof(request->grant_id), 2u);
  fill_bytes(request->target_node_id, sizeof(request->target_node_id), 3u);
  fill_bytes(request->deployment_id, sizeof(request->deployment_id), 4u);
  request->deployment_generation = 5u;
  fill_bytes(request->package_digest, sizeof(request->package_digest), 6u);
  request->input_kind = MESH_MGMT_EXECUTION_INPUT_INLINE;
  request->input_length = 3u;
  request->inline_input_size = 3u;
  memcpy(request->inline_input, "abc", 3u);
  request->output_mode = MESH_MGMT_EXECUTION_OUTPUT_DIGEST;
  request->deadline_ms = 1000u;
  fill_bytes(request->request_nonce, sizeof(request->request_nonce), 7u);
  fill_bytes(request->correlation_id, sizeof(request->correlation_id), 8u);
}

static void test_signed_result_binds_every_field(void) {
  mesh_mgmt_execution_result_v1_t result;
  mesh_mgmt_execution_result_v1_t decoded;
  uint8_t public_key[32];
  uint8_t canonical[MESH_MGMT_EXECUTION_RESULT_CANONICAL_SIZE_V1];
  size_t canonical_size = 0u;

  make_result(&result);
  check_int_eq(mesh_mgmt_execution_result_sign_v1(&result, test_private_key),
               MESH_MGMT_EXECUTION_RESULT_OK);
  check_int_eq(mesh_mgmt_ed25519_public_from_private(test_private_key,
                                                     public_key),
               MESH_MGMT_CRYPTO_OK);
  check_int_eq(mesh_mgmt_execution_result_verify_v1(&result, public_key),
               MESH_MGMT_EXECUTION_RESULT_OK);
  check_int_eq(mesh_mgmt_execution_result_encode_canonical_v1(
                   &result, canonical, sizeof(canonical), &canonical_size),
               MESH_MGMT_EXECUTION_RESULT_OK);
  check_size_eq(canonical_size,
                MESH_MGMT_EXECUTION_RESULT_CANONICAL_SIZE_V1);
  check_int_eq(mesh_mgmt_execution_result_decode_canonical_v1(
                   canonical, canonical_size, &decoded),
               MESH_MGMT_EXECUTION_RESULT_OK);
  memcpy(decoded.signature, result.signature, sizeof(decoded.signature));
  check_int_eq(mesh_mgmt_execution_result_verify_v1(&decoded, public_key),
               MESH_MGMT_EXECUTION_RESULT_OK);

  result.usage.host_calls++;
  check_int_eq(mesh_mgmt_execution_result_verify_v1(&result, public_key),
               MESH_MGMT_EXECUTION_RESULT_AUTH_FAILED);
}

static void test_result_rejects_wrong_signer_and_ambiguous_artifact(void) {
  mesh_mgmt_execution_result_v1_t result;
  uint8_t wrong_public_key[32];

  make_result(&result);
  check_int_eq(mesh_mgmt_execution_result_sign_v1(&result, test_private_key),
               MESH_MGMT_EXECUTION_RESULT_OK);
  fill_bytes(wrong_public_key, sizeof(wrong_public_key), 0xa5u);
  check_int_eq(
      mesh_mgmt_execution_result_verify_v1(&result, wrong_public_key),
      MESH_MGMT_EXECUTION_RESULT_AUTH_FAILED);
  result.output_artifact_digest[0] = 1u;
  check_int_eq(mesh_mgmt_execution_result_validate_v1(&result),
               MESH_MGMT_EXECUTION_RESULT_INVALID_SCHEMA);
}

static void test_request_digest_is_deterministic_and_payload_bound(void) {
  mesh_mgmt_execution_request_v1_t request;
  uint8_t first[32];
  uint8_t second[32];

  make_request(&request);
  check_int_eq(mesh_mgmt_execution_request_digest_v1(&request, first),
               MESH_MGMT_EXECUTION_RESULT_OK);
  check_int_eq(mesh_mgmt_execution_request_digest_v1(&request, second),
               MESH_MGMT_EXECUTION_RESULT_OK);
  check_mem_eq(first, second, sizeof(first));
  request.inline_input[1] ^= 1u;
  check_int_eq(mesh_mgmt_execution_request_digest_v1(&request, second),
               MESH_MGMT_EXECUTION_RESULT_OK);
  check_true(memcmp(first, second, sizeof(first)) != 0);
}

spec("mesh management signed execution result E2") {
  describe("canonical signed result") {
    it("binds all result fields to the node signer") {
      test_signed_result_binds_every_field();
    }
    it("rejects the wrong signer and ambiguous artifact state") {
      test_result_rejects_wrong_signer_and_ambiguous_artifact();
    }
  }
  describe("canonical request identity") {
    it("is deterministic and binds inline payload bytes") {
      test_request_digest_is_deterministic_and_payload_bound();
    }
  }
}
