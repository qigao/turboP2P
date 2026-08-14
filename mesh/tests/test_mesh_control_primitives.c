#include "mesh_control_primitives.h"

#include <tinytest.h>

#include <string.h>

#define TEST_ISSUED_AT_MS 1000u
#define TEST_EXPIRES_AT_MS 2000u

static void fill_bytes(uint8_t *bytes, size_t size, uint8_t first) {
  size_t index;

  for (index = 0u; index < size; ++index)
    bytes[index] = (uint8_t)(first + index);
}

static void make_envelope(mesh_control_envelope_v1_t *envelope,
                          mesh_control_message_kind_v1_t kind) {
  memset(envelope, 0, sizeof(*envelope));
  envelope->schema_version = MESH_CONTROL_SCHEMA_V1;
  envelope->kind = (uint16_t)kind;
  fill_bytes(envelope->message_id, sizeof(envelope->message_id), 0x11u);
  fill_bytes(envelope->request_id, sizeof(envelope->request_id), 0x21u);
  fill_bytes(envelope->mesh_id, sizeof(envelope->mesh_id), 0x31u);
  fill_bytes(envelope->origin_principal, sizeof(envelope->origin_principal),
             0x41u);
  fill_bytes(envelope->target_node_id, sizeof(envelope->target_node_id),
             0x51u);
  envelope->sequence = 1u;
  envelope->issued_at_ms = TEST_ISSUED_AT_MS;
  envelope->expires_at_ms = TEST_EXPIRES_AT_MS;
  if (kind != MESH_CONTROL_MESSAGE_HELLO) {
    envelope->resource_kind = MESH_CONTROL_RESOURCE_NODE;
    fill_bytes(envelope->resource_id, sizeof(envelope->resource_id), 0x61u);
    envelope->epoch = 1u;
  }
}

static void make_function_spec(mesh_control_function_spec_v1_t *spec,
                               mesh_control_function_runtime_v1_t runtime) {
  memset(spec, 0, sizeof(*spec));
  spec->schema_version = MESH_CONTROL_SCHEMA_V1;
  spec->runtime = (uint16_t)runtime;
  spec->desired_state = MESH_CONTROL_FUNCTION_RUNNING;
  spec->flags = MESH_CONTROL_FUNCTION_FLAG_PRESTAGED;
  if (runtime == MESH_CONTROL_FUNCTION_NATIVE)
    spec->flags |= MESH_CONTROL_FUNCTION_FLAG_OUT_OF_PROCESS;
  fill_bytes(spec->function_id, sizeof(spec->function_id), 0x11u);
  fill_bytes(spec->provider_id, sizeof(spec->provider_id), 0x31u);
  if (runtime != MESH_CONTROL_FUNCTION_BUILTIN)
    fill_bytes(spec->artifact_digest, sizeof(spec->artifact_digest), 0x51u);
  fill_bytes(spec->config_digest, sizeof(spec->config_digest), 0x71u);
  fill_bytes(spec->network_policy_digest,
             sizeof(spec->network_policy_digest), 0x91u);
  spec->generation = 1u;
  spec->required_capabilities = 3u;
  spec->limits.memory_bytes = 1024u * 1024u;
  spec->limits.cpu_time_ms = 1000u;
  spec->limits.input_bytes = 4096u;
  spec->limits.output_bytes = 4096u;
  spec->limits.concurrency = 1u;
  spec->limits.host_calls = 16u;
}

static void test_envelope_separates_hello_and_resource_messages(void) {
  mesh_control_envelope_v1_t envelope;

  make_envelope(&envelope, MESH_CONTROL_MESSAGE_HELLO);
  check_int_eq(mesh_control_envelope_validate_v1(&envelope),
               MESH_CONTROL_OK);
  envelope.resource_kind = MESH_CONTROL_RESOURCE_NODE;
  check_int_eq(mesh_control_envelope_validate_v1(&envelope),
               MESH_CONTROL_INVALID_ARG);

  make_envelope(&envelope, MESH_CONTROL_MESSAGE_INTENT);
  check_int_eq(mesh_control_envelope_validate_v1(&envelope),
               MESH_CONTROL_OK);
  memset(envelope.target_node_id, 0, sizeof(envelope.target_node_id));
  check_int_eq(mesh_control_envelope_validate_v1(&envelope),
               MESH_CONTROL_INVALID_ARG);
}

static void test_envelope_binds_payload_shape_and_lifetime(void) {
  mesh_control_envelope_v1_t envelope;

  make_envelope(&envelope, MESH_CONTROL_MESSAGE_OBSERVATION);
  envelope.payload_size = 4u;
  fill_bytes(envelope.payload_digest, sizeof(envelope.payload_digest), 0xa1u);
  check_int_eq(mesh_control_envelope_validate_v1(&envelope),
               MESH_CONTROL_OK);
  memset(envelope.payload_digest, 0, sizeof(envelope.payload_digest));
  check_int_eq(mesh_control_envelope_validate_v1(&envelope),
               MESH_CONTROL_INVALID_ARG);
  envelope.payload_size = MESH_CONTROL_MAX_FRAME_SIZE_V1 + 1u;
  check_int_eq(mesh_control_envelope_validate_v1(&envelope),
               MESH_CONTROL_INVALID_ARG);
  envelope.payload_size = 0u;
  envelope.expires_at_ms = envelope.issued_at_ms;
  check_int_eq(mesh_control_envelope_validate_v1(&envelope),
               MESH_CONTROL_INVALID_ARG);
}

static void test_function_specs_reject_remote_native_loading(void) {
  mesh_control_function_spec_v1_t spec;

  make_function_spec(&spec, MESH_CONTROL_FUNCTION_NATIVE);
  check_int_eq(mesh_control_function_spec_validate_v1(&spec),
               MESH_CONTROL_OK);
  spec.flags &= ~MESH_CONTROL_FUNCTION_FLAG_OUT_OF_PROCESS;
  check_int_eq(mesh_control_function_spec_validate_v1(&spec),
               MESH_CONTROL_INVALID_ARG);
  spec.flags |= MESH_CONTROL_FUNCTION_FLAG_OUT_OF_PROCESS;
  memset(spec.artifact_digest, 0, sizeof(spec.artifact_digest));
  check_int_eq(mesh_control_function_spec_validate_v1(&spec),
               MESH_CONTROL_INVALID_ARG);

  make_function_spec(&spec, MESH_CONTROL_FUNCTION_WASM);
  check_int_eq(mesh_control_function_spec_validate_v1(&spec),
               MESH_CONTROL_OK);
  spec.flags = 0u;
  check_int_eq(mesh_control_function_spec_validate_v1(&spec),
               MESH_CONTROL_INVALID_ARG);

  make_function_spec(&spec, MESH_CONTROL_FUNCTION_BUILTIN);
  check_int_eq(mesh_control_function_spec_validate_v1(&spec),
               MESH_CONTROL_OK);
}

static void test_runtime_permissions_are_intersected_and_wasm_can_stay_disabled(void) {
  mesh_control_function_spec_v1_t spec;
  uint64_t effective = UINT64_MAX;
  uint64_t grant = MESH_CONTROL_PERMISSION_MANAGE |
                   MESH_CONTROL_PERMISSION_RUN_BUILTIN |
                   MESH_CONTROL_PERMISSION_RUN_NATIVE |
                   MESH_CONTROL_PERMISSION_RUN_WASM;
  uint64_t local = MESH_CONTROL_PERMISSION_OBSERVE |
                   MESH_CONTROL_PERMISSION_MANAGE |
                   MESH_CONTROL_PERMISSION_RUN_BUILTIN |
                   MESH_CONTROL_PERMISSION_RUN_NATIVE;

  make_function_spec(&spec, MESH_CONTROL_FUNCTION_WASM);
  check_int_eq(mesh_control_function_authorize_v1(
                   &spec, grant, local, &effective),
               MESH_CONTROL_CONFLICT);
  check_int_eq(effective & MESH_CONTROL_PERMISSION_RUN_WASM, 0u);

  make_function_spec(&spec, MESH_CONTROL_FUNCTION_NATIVE);
  check_int_eq(mesh_control_function_authorize_v1(
                   &spec, grant, local, &effective),
               MESH_CONTROL_OK);
  check_bits(effective, MESH_CONTROL_PERMISSION_RUN_NATIVE);

  make_function_spec(&spec, MESH_CONTROL_FUNCTION_BUILTIN);
  check_int_eq(mesh_control_function_authorize_v1(
                   &spec, grant, local, &effective),
               MESH_CONTROL_OK);

  spec.desired_state = MESH_CONTROL_FUNCTION_STAGED;
  local = MESH_CONTROL_PERMISSION_MANAGE;
  check_int_eq(mesh_control_function_authorize_v1(
                   &spec, grant, local, &effective),
               MESH_CONTROL_OK);
}

static void test_operation_state_machine_preserves_terminal_results(void) {
  check_true(mesh_control_operation_transition_allowed_v1(
      MESH_CONTROL_OPERATION_SUBMITTED, MESH_CONTROL_OPERATION_ACCEPTED));
  check_true(mesh_control_operation_transition_allowed_v1(
      MESH_CONTROL_OPERATION_ACCEPTED, MESH_CONTROL_OPERATION_RUNNING));
  check_true(mesh_control_operation_transition_allowed_v1(
      MESH_CONTROL_OPERATION_RUNNING, MESH_CONTROL_OPERATION_SUCCEEDED));
  check_true(mesh_control_operation_transition_allowed_v1(
      MESH_CONTROL_OPERATION_SUCCEEDED, MESH_CONTROL_OPERATION_SUCCEEDED));
  check_false(mesh_control_operation_transition_allowed_v1(
      MESH_CONTROL_OPERATION_SUCCEEDED, MESH_CONTROL_OPERATION_RUNNING));
  check_false(mesh_control_operation_transition_allowed_v1(
      MESH_CONTROL_OPERATION_SUBMITTED, MESH_CONTROL_OPERATION_RUNNING));
  check_false(mesh_control_operation_transition_allowed_v1(
      (mesh_control_operation_state_v1_t)0,
      MESH_CONTROL_OPERATION_ACCEPTED));
}

spec("mesh H2 WebSocket control primitives") {
  describe("transport-neutral contracts") {
    it("separates connection hello from resource messages") {
      test_envelope_separates_hello_and_resource_messages();
    }
    it("binds payload size, digest, and validity window") {
      test_envelope_binds_payload_shape_and_lifetime();
    }
    it("allows only prestaged isolated native and WASM functions") {
      test_function_specs_reject_remote_native_loading();
    }
    it("intersects runtime permissions and permits disabling WASM execution") {
      test_runtime_permissions_are_intersected_and_wasm_can_stay_disabled();
    }
    it("keeps operation terminal states immutable and replayable") {
      test_operation_state_machine_preserves_terminal_results();
    }
  }
}
