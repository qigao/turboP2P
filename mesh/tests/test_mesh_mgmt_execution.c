#include "tinytest.h"

#include "mesh_mgmt_execution.h"

#include <string.h>

#define TEST_NOW_MS 1000u

static void fill_bytes(uint8_t *bytes, size_t length, uint8_t value) {
  memset(bytes, value, length);
}

static mesh_mgmt_execution_limits_v1_t test_limits(uint32_t base) {
  mesh_mgmt_execution_limits_v1_t limits;

  memset(&limits, 0, sizeof(limits));
  limits.module_bytes = base;
  limits.stack_bytes = base + 1u;
  limits.linear_memory_bytes = base + 2u;
  limits.timeout_ms = base + 3u;
  limits.control_flow_steps = base + 4u;
  limits.host_calls = base + 5u;
  limits.copied_guest_bytes = base + 6u;
  limits.input_bytes = base + 7u;
  limits.stdout_bytes = base + 8u;
  limits.stderr_bytes = base + 9u;
  return limits;
}

static mesh_mgmt_execution_grant_v1_t test_grant(void) {
  mesh_mgmt_execution_grant_v1_t grant;

  memset(&grant, 0, sizeof(grant));
  grant.version = MESH_MGMT_EXECUTION_SCHEMA_V1;
  fill_bytes(grant.grant_id, sizeof(grant.grant_id), 0x11u);
  fill_bytes(grant.mesh_id, sizeof(grant.mesh_id), 0x22u);
  grant.policy_epoch = 7u;
  fill_bytes(grant.subject_principal, sizeof(grant.subject_principal), 0x33u);
  fill_bytes(grant.target_node_id, sizeof(grant.target_node_id), 0x44u);
  fill_bytes(grant.deployment_id, sizeof(grant.deployment_id), 0x55u);
  grant.deployment_generation = 3u;
  fill_bytes(grant.package_digest, sizeof(grant.package_digest), 0x66u);
  grant.operation = MESH_MGMT_EXECUTION_OPERATION_RUN_PRESTAGED_WASM;
  grant.capabilities =
      MESH_MGMT_EXECUTION_CAP_CORE | MESH_MGMT_EXECUTION_CAP_UTILS;
  fill_bytes(grant.mount_ids[0], sizeof(grant.mount_ids[0]), 0x71u);
  grant.mount_count = 1u;
  fill_bytes(grant.service_ids[0], sizeof(grant.service_ids[0]), 0x72u);
  grant.service_count = 1u;
  fill_bytes(grant.provider_ids[0], sizeof(grant.provider_ids[0]), 0x73u);
  grant.provider_count = 1u;
  grant.max_limits = test_limits(500u);
  grant.not_before_ms = 900u;
  grant.expires_at_ms = 2000u;
  fill_bytes(grant.issuer_key, sizeof(grant.issuer_key), 0x77u);
  fill_bytes(grant.signature, sizeof(grant.signature), 0x88u);
  return grant;
}

static mesh_mgmt_execution_request_v1_t test_request(
    const mesh_mgmt_execution_grant_v1_t *grant) {
  mesh_mgmt_execution_request_v1_t request;

  memset(&request, 0, sizeof(request));
  request.version = MESH_MGMT_EXECUTION_SCHEMA_V1;
  fill_bytes(request.command_id, sizeof(request.command_id), 0x91u);
  memcpy(request.grant_id, grant->grant_id, sizeof(request.grant_id));
  memcpy(request.target_node_id, grant->target_node_id,
         sizeof(request.target_node_id));
  memcpy(request.deployment_id, grant->deployment_id,
         sizeof(request.deployment_id));
  request.deployment_generation = grant->deployment_generation;
  memcpy(request.package_digest, grant->package_digest,
         sizeof(request.package_digest));
  request.input_kind = MESH_MGMT_EXECUTION_INPUT_INLINE;
  fill_bytes(request.input_digest, sizeof(request.input_digest), 0x92u);
  memcpy(request.inline_input, "input", 5u);
  request.inline_input_size = 5u;
  request.input_length = 5u;
  request.output_mode = MESH_MGMT_EXECUTION_OUTPUT_DIGEST;
  request.deadline_ms = 1500u;
  fill_bytes(request.request_nonce, sizeof(request.request_nonce), 0x93u);
  fill_bytes(request.correlation_id, sizeof(request.correlation_id), 0x94u);
  return request;
}

static void test_typed_schema_rejects_ambiguous_authority(void) {
  mesh_mgmt_execution_grant_v1_t grant = test_grant();
  mesh_mgmt_execution_request_v1_t request = test_request(&grant);

  check_int_eq(mesh_mgmt_execution_grant_validate_v1(&grant, TEST_NOW_MS),
               MESH_MGMT_EXECUTION_OK);
  check_int_eq(mesh_mgmt_execution_request_validate_v1(&request, TEST_NOW_MS),
               MESH_MGMT_EXECUTION_OK);
  check_int_eq(mesh_mgmt_execution_request_bind_v1(&grant, &request),
               MESH_MGMT_EXECUTION_OK);

  grant.operation = MESH_MGMT_EXECUTION_OPERATION_RUN_PRESTAGED_NATIVE;
  check_int_eq(mesh_mgmt_execution_grant_validate_v1(&grant, TEST_NOW_MS),
               MESH_MGMT_EXECUTION_OK);

  grant.capabilities |= 1u << 31;
  check_int_eq(mesh_mgmt_execution_grant_validate_v1(&grant, TEST_NOW_MS),
               MESH_MGMT_EXECUTION_INVALID_SCHEMA);
  grant = test_grant();
  memcpy(grant.mount_ids[1], grant.mount_ids[0], sizeof(grant.mount_ids[1]));
  grant.mount_count = 2u;
  check_int_eq(mesh_mgmt_execution_grant_validate_v1(&grant, TEST_NOW_MS),
               MESH_MGMT_EXECUTION_INVALID_SCHEMA);

  grant = test_grant();
  request = test_request(&grant);
  request.deployment_generation++;
  check_int_eq(mesh_mgmt_execution_request_bind_v1(&grant, &request),
               MESH_MGMT_EXECUTION_BINDING_MISMATCH);
}

static void test_effective_policy_is_intersection_not_union(void) {
  mesh_mgmt_execution_grant_v1_t grant = test_grant();
  mesh_mgmt_execution_authorization_input_v1_t input;
  mesh_mgmt_execution_effective_policy_v1_t effective;

  memset(&input, 0, sizeof(input));
  memset(&effective, 0, sizeof(effective));
  input.requested_capabilities =
      MESH_MGMT_EXECUTION_CAP_CORE | MESH_MGMT_EXECUTION_CAP_UTILS;
  input.host_capabilities = MESH_MGMT_EXECUTION_CAP_ALL;
  input.hard_capabilities = MESH_MGMT_EXECUTION_CAP_ALL;
  input.requested_limits = test_limits(800u);
  input.host_limits = test_limits(700u);
  input.hard_limits = test_limits(600u);
  check_int_eq(mesh_mgmt_execution_authorize_v1(&grant, &input, &effective),
               MESH_MGMT_EXECUTION_OK);
  check_uint_eq(effective.capabilities, input.requested_capabilities);
  check_uint_eq(effective.limits.module_bytes, 500u);
  check_hex64_eq(effective.limits.timeout_ms, 503u);

  input.requested_capabilities |= MESH_MGMT_EXECUTION_CAP_HTTP;
  check_int_eq(mesh_mgmt_execution_authorize_v1(&grant, &input, &effective),
               MESH_MGMT_EXECUTION_DENIED);
  check_uint_eq(effective.capabilities, 0u);
}

static void test_journal_deduplicates_and_detects_conflicts(void) {
  mesh_mgmt_execution_journal_v1_t journal;
  mesh_mgmt_execution_journal_entry_v1_t entry;
  uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE];
  uint8_t digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint8_t other_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];

  memset(&journal, 0, sizeof(journal));
  fill_bytes(command_id, sizeof(command_id), 0x10u);
  fill_bytes(digest, sizeof(digest), 0x20u);
  fill_bytes(other_digest, sizeof(other_digest), 0x21u);
  check_int_eq(mesh_mgmt_execution_journal_init_v1(&journal, 1u),
               MESH_MGMT_EXECUTION_OK);
  check_int_eq(mesh_mgmt_execution_journal_submit_v1(
                   &journal, command_id, digest, &entry),
               MESH_MGMT_EXECUTION_OK);
  check_int_eq(entry.state, MESH_MGMT_EXECUTION_STATE_ACCEPTED);
  check_size_eq(journal.count, 1u);
  check_int_eq(mesh_mgmt_execution_journal_submit_v1(
                   &journal, command_id, digest, &entry),
               MESH_MGMT_EXECUTION_OK);
  check_size_eq(journal.count, 1u);
  check_int_eq(mesh_mgmt_execution_journal_submit_v1(
                   &journal, command_id, other_digest, &entry),
               MESH_MGMT_EXECUTION_CONFLICT);
  command_id[0]++;
  check_int_eq(mesh_mgmt_execution_journal_submit_v1(
                   &journal, command_id, digest, &entry),
               MESH_MGMT_EXECUTION_RESOURCE_EXHAUSTED);
  mesh_mgmt_execution_journal_destroy_v1(&journal);
}

static void test_journal_enforces_terminal_state_monotonicity(void) {
  mesh_mgmt_execution_journal_v1_t journal;
  mesh_mgmt_execution_journal_entry_v1_t entry;
  uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE];
  uint8_t digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];

  memset(&journal, 0, sizeof(journal));
  fill_bytes(command_id, sizeof(command_id), 0x30u);
  fill_bytes(digest, sizeof(digest), 0x40u);
  check_int_eq(mesh_mgmt_execution_journal_init_v1(&journal, 2u),
               MESH_MGMT_EXECUTION_OK);
  check_int_eq(mesh_mgmt_execution_journal_submit_v1(
                   &journal, command_id, digest, &entry),
               MESH_MGMT_EXECUTION_OK);
  check_int_eq(mesh_mgmt_execution_journal_transition_v1(
                   &journal, command_id, MESH_MGMT_EXECUTION_STATE_RUNNING,
                   0, &entry),
               MESH_MGMT_EXECUTION_INVALID_STATE);
  check_int_eq(mesh_mgmt_execution_journal_transition_v1(
                   &journal, command_id, MESH_MGMT_EXECUTION_STATE_STAGING,
                   0, &entry),
               MESH_MGMT_EXECUTION_OK);
  check_int_eq(mesh_mgmt_execution_journal_transition_v1(
                   &journal, command_id, MESH_MGMT_EXECUTION_STATE_RUNNING,
                   0, &entry),
               MESH_MGMT_EXECUTION_OK);
  check_int_eq(mesh_mgmt_execution_journal_transition_v1(
                   &journal, command_id, MESH_MGMT_EXECUTION_STATE_SUCCEEDED,
                   0, &entry),
               MESH_MGMT_EXECUTION_OK);
  check_true(mesh_mgmt_execution_state_is_terminal_v1(entry.state));
  check_int_eq(mesh_mgmt_execution_journal_transition_v1(
                   &journal, command_id, MESH_MGMT_EXECUTION_STATE_FAILED,
                   -1, &entry),
               MESH_MGMT_EXECUTION_INVALID_STATE);
  mesh_mgmt_execution_journal_destroy_v1(&journal);
}

static void test_snapshot_recovery_marks_running_indeterminate(void) {
  mesh_mgmt_execution_journal_v1_t source;
  mesh_mgmt_execution_journal_v1_t restored;
  mesh_mgmt_execution_journal_entry_v1_t entry;
  mesh_mgmt_execution_journal_entry_v1_t snapshot[2];
  uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE];
  uint8_t digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  size_t snapshot_count = 0u;
  size_t recovered = 0u;

  memset(&source, 0, sizeof(source));
  memset(&restored, 0, sizeof(restored));
  fill_bytes(command_id, sizeof(command_id), 0x50u);
  fill_bytes(digest, sizeof(digest), 0x60u);
  check_int_eq(mesh_mgmt_execution_journal_init_v1(&source, 2u),
               MESH_MGMT_EXECUTION_OK);
  check_int_eq(mesh_mgmt_execution_journal_submit_v1(
                   &source, command_id, digest, &entry),
               MESH_MGMT_EXECUTION_OK);
  check_int_eq(mesh_mgmt_execution_journal_transition_v1(
                   &source, command_id, MESH_MGMT_EXECUTION_STATE_STAGING,
                   0, &entry),
               MESH_MGMT_EXECUTION_OK);
  check_int_eq(mesh_mgmt_execution_journal_transition_v1(
                   &source, command_id, MESH_MGMT_EXECUTION_STATE_RUNNING,
                   0, &entry),
               MESH_MGMT_EXECUTION_OK);
  check_int_eq(mesh_mgmt_execution_journal_export_v1(
                   &source, snapshot, 2u, &snapshot_count),
               MESH_MGMT_EXECUTION_OK);
  check_size_eq(snapshot_count, 1u);

  check_int_eq(mesh_mgmt_execution_journal_init_v1(&restored, 2u),
               MESH_MGMT_EXECUTION_OK);
  check_int_eq(mesh_mgmt_execution_journal_import_v1(
                   &restored, snapshot, snapshot_count),
               MESH_MGMT_EXECUTION_OK);
  check_int_eq(mesh_mgmt_execution_journal_recover_v1(
                   &restored, &recovered),
               MESH_MGMT_EXECUTION_OK);
  check_size_eq(recovered, 1u);
  check_int_eq(mesh_mgmt_execution_journal_get_v1(
                   &restored, command_id, &entry),
               MESH_MGMT_EXECUTION_OK);
  check_int_eq(entry.state,
               MESH_MGMT_EXECUTION_STATE_FAILED_INDETERMINATE);
  check_true(mesh_mgmt_execution_state_is_terminal_v1(entry.state));

  mesh_mgmt_execution_journal_destroy_v1(&restored);
  mesh_mgmt_execution_journal_destroy_v1(&source);
}

spec("mesh management node execution E0") {
  describe("typed execution authority") {
    it("rejects ambiguous or mismatched authority") {
      test_typed_schema_rejects_ambiguous_authority();
    }
    it("intersects every capability and limit source") {
      test_effective_policy_is_intersection_not_union();
    }
  }

  describe("bounded command journal simulator") {
    it("deduplicates command IDs and detects conflicting payloads") {
      test_journal_deduplicates_and_detects_conflicts();
    }
    it("keeps terminal states monotonic") {
      test_journal_enforces_terminal_state_monotonicity();
    }
    it("marks restored running work indeterminate") {
      test_snapshot_recovery_marks_running_indeterminate();
    }
  }
}
