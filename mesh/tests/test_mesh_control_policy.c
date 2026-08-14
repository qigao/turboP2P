#include "mesh_control_policy.h"
#include "tinytest.h"

#include <string.h>

static void make_spec(mesh_control_function_spec_v1_t *spec,
                      mesh_control_function_runtime_v1_t runtime) {
  memset(spec, 0, sizeof(*spec));
  spec->schema_version = MESH_CONTROL_SCHEMA_V1;
  spec->runtime = runtime;
  spec->desired_state = MESH_CONTROL_FUNCTION_RUNNING;
  spec->function_id[0] = 1u;
  spec->provider_id[0] = 2u;
  spec->artifact_digest[0] = 3u;
  spec->config_digest[0] = 4u;
  spec->network_policy_digest[0] = 5u;
  spec->generation = 1u;
  spec->limits.memory_bytes = 1024u;
  spec->limits.cpu_time_ms = 100u;
  spec->limits.input_bytes = 1024u;
  spec->limits.output_bytes = 1024u;
  spec->limits.concurrency = 1u;
  spec->limits.host_calls = 1u;
  if (runtime != MESH_CONTROL_FUNCTION_BUILTIN)
    spec->flags |= MESH_CONTROL_FUNCTION_FLAG_PRESTAGED;
  if (runtime == MESH_CONTROL_FUNCTION_NATIVE)
    spec->flags |= MESH_CONTROL_FUNCTION_FLAG_OUT_OF_PROCESS;
}

static void test_default_policy_runs_only_builtins(void) {
  mesh_control_node_policy_v1_t policy;
  mesh_control_function_spec_v1_t spec;
  uint64_t grant = MESH_CONTROL_PERMISSION_MANAGE |
                   MESH_CONTROL_PERMISSION_RUN_BUILTIN |
                   MESH_CONTROL_PERMISSION_RUN_NATIVE |
                   MESH_CONTROL_PERMISSION_RUN_WASM;
  uint64_t effective = 0u;

  mesh_control_node_policy_default_v1(&policy);
  check_int_eq(mesh_control_node_policy_validate_v1(&policy),
               MESH_CONTROL_OK);
  make_spec(&spec, MESH_CONTROL_FUNCTION_BUILTIN);
  check_int_eq(mesh_control_node_policy_authorize_function_v1(
                   &policy, &spec, grant, &effective),
               MESH_CONTROL_OK);
  make_spec(&spec, MESH_CONTROL_FUNCTION_NATIVE);
  check_int_eq(mesh_control_node_policy_authorize_function_v1(
                   &policy, &spec, grant, &effective),
               MESH_CONTROL_CONFLICT);
  make_spec(&spec, MESH_CONTROL_FUNCTION_WASM);
  check_int_eq(mesh_control_node_policy_authorize_function_v1(
                   &policy, &spec, grant, &effective),
               MESH_CONTROL_CONFLICT);
}

static void test_native_and_wasm_are_independent_opt_ins(void) {
  mesh_control_node_policy_v1_t policy;
  mesh_control_function_spec_v1_t spec;
  uint64_t grant = MESH_CONTROL_PERMISSION_MANAGE |
                   MESH_CONTROL_PERMISSION_RUN_NATIVE |
                   MESH_CONTROL_PERMISSION_RUN_WASM;
  uint64_t effective = 0u;

  mesh_control_node_policy_default_v1(&policy);
  policy.local_permissions |= MESH_CONTROL_PERMISSION_RUN_NATIVE;
  policy.available_runtimes |= MESH_CONTROL_RUNTIME_AVAILABLE_NATIVE;
  check_int_eq(mesh_control_node_policy_validate_v1(&policy),
               MESH_CONTROL_OK);
  make_spec(&spec, MESH_CONTROL_FUNCTION_NATIVE);
  check_int_eq(mesh_control_node_policy_authorize_function_v1(
                   &policy, &spec, grant, &effective),
               MESH_CONTROL_OK);
  check_bits(effective, MESH_CONTROL_PERMISSION_RUN_NATIVE);

  policy.local_permissions |= MESH_CONTROL_PERMISSION_RUN_WASM;
  check_int_eq(mesh_control_node_policy_validate_v1(&policy),
               MESH_CONTROL_INVALID_ARG);
  policy.available_runtimes |= MESH_CONTROL_RUNTIME_AVAILABLE_WASM;
  check_int_eq(mesh_control_node_policy_validate_v1(&policy),
               MESH_CONTROL_OK);
  make_spec(&spec, MESH_CONTROL_FUNCTION_WASM);
  check_int_eq(mesh_control_node_policy_authorize_function_v1(
                   &policy, &spec, grant, &effective),
               MESH_CONTROL_OK);
  check_bits(effective, MESH_CONTROL_PERMISSION_RUN_WASM);
  spec.desired_state = MESH_CONTROL_FUNCTION_STAGED;
  check_int_eq(mesh_control_node_policy_authorize_function_v1(
                   &policy, &spec, grant, &effective),
               MESH_CONTROL_OK);
  spec.desired_state = MESH_CONTROL_FUNCTION_STOPPED;
  check_int_eq(mesh_control_node_policy_authorize_function_v1(
                   &policy, &spec, grant, &effective),
               MESH_CONTROL_OK);
}

static size_t make_function_intent(
    mesh_control_envelope_v1_t *envelope,
    const mesh_control_function_spec_v1_t *spec,
    mesh_control_desired_action_v1_t action, uint8_t *payload,
    size_t payload_capacity) {
  uint8_t document[MESH_CONTROL_FUNCTION_DOCUMENT_SIZE_V1];
  size_t document_size = 0u;
  size_t payload_size = 0u;

  memset(envelope, 0, sizeof(*envelope));
  envelope->schema_version = MESH_CONTROL_SCHEMA_V1;
  envelope->kind = MESH_CONTROL_MESSAGE_INTENT;
  envelope->resource_kind = MESH_CONTROL_RESOURCE_FUNCTION;
  envelope->resource_id[0] = 1u;
  envelope->epoch = 1u;
  if (action == MESH_CONTROL_DESIRED_APPLY) {
    check_int_eq(mesh_control_function_document_encode_v1(
                     spec, document, sizeof(document), &document_size),
                 MESH_CONTROL_OK);
  }
  check_int_eq(mesh_control_intent_encode_v1(
                   action, document_size == 0u ? NULL : document,
                   document_size, payload, payload_capacity, &payload_size),
               MESH_CONTROL_OK);
  return payload_size;
}

static void test_function_intent_binds_schema_identity_and_permission(void) {
  mesh_control_node_policy_v1_t policy;
  mesh_control_function_spec_v1_t spec;
  mesh_control_function_spec_v1_t decoded;
  mesh_control_envelope_v1_t envelope;
  uint8_t payload[MESH_CONTROL_FUNCTION_DOCUMENT_SIZE_V1 +
                  MESH_CONTROL_INTENT_HEADER_SIZE_V1];
  uint64_t effective = 0u;
  size_t payload_size;

  mesh_control_node_policy_default_v1(&policy);
  make_spec(&spec, MESH_CONTROL_FUNCTION_NATIVE);
  spec.generation = 1u;
  payload_size = make_function_intent(
      &envelope, &spec, MESH_CONTROL_DESIRED_APPLY, payload,
      sizeof(payload));
  check_int_eq(mesh_control_node_policy_authorize_function_intent_v1(
                   &policy, &envelope, payload, payload_size,
                   MESH_CONTROL_PERMISSION_MANAGE |
                       MESH_CONTROL_PERMISSION_RUN_NATIVE,
                   &effective, &decoded),
               MESH_CONTROL_CONFLICT);

  policy.local_permissions |= MESH_CONTROL_PERMISSION_RUN_NATIVE;
  policy.available_runtimes |= MESH_CONTROL_RUNTIME_AVAILABLE_NATIVE;
  check_int_eq(mesh_control_node_policy_authorize_function_intent_v1(
                   &policy, &envelope, payload, payload_size,
                   MESH_CONTROL_PERMISSION_MANAGE |
                       MESH_CONTROL_PERMISSION_RUN_NATIVE,
                   &effective, &decoded),
               MESH_CONTROL_OK);
  check_mem_eq(&decoded, &spec, sizeof(spec));
  envelope.epoch = 2u;
  check_int_eq(mesh_control_node_policy_authorize_function_intent_v1(
                   &policy, &envelope, payload, payload_size,
                   MESH_CONTROL_PERMISSION_MANAGE |
                       MESH_CONTROL_PERMISSION_RUN_NATIVE,
                   &effective, &decoded),
               MESH_CONTROL_CONFLICT);
}

static void test_function_delete_requires_manage_and_empty_document(void) {
  mesh_control_node_policy_v1_t policy;
  mesh_control_function_spec_v1_t decoded;
  mesh_control_envelope_v1_t envelope;
  uint8_t payload[MESH_CONTROL_FUNCTION_DOCUMENT_SIZE_V1 +
                  MESH_CONTROL_INTENT_HEADER_SIZE_V1];
  uint64_t effective = 0u;
  size_t payload_size;

  mesh_control_node_policy_default_v1(&policy);
  payload_size = make_function_intent(
      &envelope, NULL, MESH_CONTROL_DESIRED_DELETE, payload,
      sizeof(payload));
  check_int_eq(mesh_control_node_policy_authorize_function_intent_v1(
                   &policy, &envelope, payload, payload_size,
                   MESH_CONTROL_PERMISSION_MANAGE, &effective, &decoded),
               MESH_CONTROL_OK);
  check_bits(effective, MESH_CONTROL_PERMISSION_MANAGE);
  payload[payload_size++] = 1u;
  check_int_eq(mesh_control_node_policy_authorize_function_intent_v1(
                   &policy, &envelope, payload, payload_size,
                   MESH_CONTROL_PERMISSION_MANAGE, &effective, &decoded),
               MESH_CONTROL_INVALID_ARG);
  payload_size = make_function_intent(
      &envelope, NULL, MESH_CONTROL_DESIRED_DELETE, payload,
      sizeof(payload));
  check_int_eq(mesh_control_node_policy_authorize_function_intent_v1(
                   &policy, &envelope, payload, payload_size,
                   MESH_CONTROL_PERMISSION_OBSERVE, &effective, &decoded),
               MESH_CONTROL_CONFLICT);
}

spec("mesh node runtime policy") {
  describe("separate builtin native and WASM permissions") {
    it("uses a safe builtin-only execution baseline") {
      test_default_policy_runs_only_builtins();
    }
    it("allows independent Native and WASM opt-in") {
      test_native_and_wasm_are_independent_opt_ins();
    }
    it("binds function schema identity generation and runtime permission") {
      test_function_intent_binds_schema_identity_and_permission();
    }
    it("allows safe stop/delete without runtime permission") {
      test_function_delete_requires_manage_and_empty_document();
    }
  }
}
