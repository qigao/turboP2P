#include "mesh_control_reconciler.h"
#include "tinytest.h"

#include <string.h>

typedef struct {
  mesh_control_provider_request_v1_t request;
  uint16_t completion_state;
  uint8_t active;
  uint8_t completion_ready;
  uint8_t ack_failure;
  uint8_t backpressure;
  uint8_t closed;
} fake_provider_v1_t;

static mesh_control_result_t fake_try_start(void *context,
                                            const mesh_control_provider_request_v1_t *request) {
  fake_provider_v1_t *provider = (fake_provider_v1_t *)context;
  if (provider == NULL || request == NULL)
    return MESH_CONTROL_INVALID_ARG;
  if (provider->closed)
    return MESH_CONTROL_CLOSED;
  if (provider->backpressure || provider->active)
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  provider->request = *request;
  provider->active = 1u;
  return MESH_CONTROL_OK;
}

static mesh_control_result_t
fake_try_peek_completion(void *context, mesh_control_provider_completion_v1_t *out_completion) {
  fake_provider_v1_t *provider = (fake_provider_v1_t *)context;
  if (provider == NULL || out_completion == NULL)
    return MESH_CONTROL_INVALID_ARG;
  if (!provider->completion_ready)
    return MESH_CONTROL_EMPTY;
  memset(out_completion, 0, sizeof(*out_completion));
  memcpy(out_completion->operation_id, provider->request.operation.operation_id,
         sizeof(out_completion->operation_id));
  out_completion->state = provider->completion_state;
  return MESH_CONTROL_OK;
}

static mesh_control_result_t fake_ack_completion(void *context,
                                                 const uint8_t operation_id[MESH_CONTROL_ID_SIZE]) {
  fake_provider_v1_t *provider = (fake_provider_v1_t *)context;
  if (provider == NULL || operation_id == NULL || !provider->completion_ready ||
      memcmp(operation_id, provider->request.operation.operation_id, MESH_CONTROL_ID_SIZE) != 0) {
    return MESH_CONTROL_INVALID_ARG;
  }
  if (provider->ack_failure)
    return MESH_CONTROL_INVALID_STATE;
  provider->completion_ready = 0u;
  provider->active = 0u;
  return MESH_CONTROL_OK;
}

static void fake_close(void *context) {
  fake_provider_v1_t *provider = (fake_provider_v1_t *)context;
  provider->closed = 1u;
  if (!provider->completion_ready)
    provider->active = 0u;
}

static int fake_is_drained(void *context) {
  const fake_provider_v1_t *provider = (const fake_provider_v1_t *)context;
  return provider->closed && !provider->active && !provider->completion_ready;
}

static void fake_complete(fake_provider_v1_t *provider, uint16_t state) {
  provider->completion_state = state;
  provider->completion_ready = 1u;
}

static void make_provider(mesh_control_provider_v1_t *provider, fake_provider_v1_t *context,
                          uint16_t runtime) {
  memset(provider, 0, sizeof(*provider));
  provider->provider_id[0] = 0x22u;
  provider->runtime = runtime;
  provider->ops.try_start = fake_try_start;
  provider->ops.try_peek_completion = fake_try_peek_completion;
  provider->ops.ack_completion = fake_ack_completion;
  provider->ops.close = fake_close;
  provider->ops.is_drained = fake_is_drained;
  provider->context = context;
}

static void make_function_document(mesh_control_function_spec_v1_t *spec,
                                   uint8_t document[MESH_CONTROL_FUNCTION_DOCUMENT_SIZE_V1],
                                   size_t *out_size) {
  memset(spec, 0, sizeof(*spec));
  spec->schema_version = MESH_CONTROL_SCHEMA_V1;
  spec->runtime = MESH_CONTROL_FUNCTION_NATIVE;
  spec->desired_state = MESH_CONTROL_FUNCTION_RUNNING;
  spec->flags = MESH_CONTROL_FUNCTION_FLAG_PRESTAGED | MESH_CONTROL_FUNCTION_FLAG_OUT_OF_PROCESS;
  spec->function_id[0] = 0x11u;
  spec->provider_id[0] = 0x22u;
  spec->artifact_digest[0] = 0x33u;
  spec->config_digest[0] = 0x44u;
  spec->network_policy_digest[0] = 0x55u;
  spec->generation = 1u;
  spec->required_capabilities = 1u;
  spec->limits.memory_bytes = 1024u;
  spec->limits.cpu_time_ms = 100u;
  spec->limits.input_bytes = 1024u;
  spec->limits.output_bytes = 1024u;
  spec->limits.concurrency = 1u;
  spec->limits.host_calls = 1u;
  check_int_eq(mesh_control_function_document_encode_v1(
                   spec, document, MESH_CONTROL_FUNCTION_DOCUMENT_SIZE_V1, out_size),
               MESH_CONTROL_OK);
}

static void make_intent(mesh_control_envelope_v1_t *envelope,
                        const mesh_control_function_spec_v1_t *spec, uint8_t identity,
                        uint64_t epoch, uint64_t precondition_epoch) {
  memset(envelope, 0, sizeof(*envelope));
  envelope->schema_version = MESH_CONTROL_SCHEMA_V1;
  envelope->kind = MESH_CONTROL_MESSAGE_INTENT;
  envelope->message_id[0] = identity;
  envelope->request_id[0] = (uint8_t)(identity + 1u);
  envelope->mesh_id[0] = 1u;
  envelope->origin_principal[0] = 2u;
  envelope->target_node_id[0] = 3u;
  envelope->resource_kind = MESH_CONTROL_RESOURCE_FUNCTION;
  memcpy(envelope->resource_id, spec->function_id, sizeof(envelope->resource_id));
  envelope->epoch = epoch;
  envelope->sequence = epoch;
  envelope->issued_at_ms = 1000u;
  envelope->expires_at_ms = 2000u;
  envelope->precondition_epoch = precondition_epoch;
  envelope->payload_digest[0] = identity;
  envelope->payload_size = 1u;
}

static void test_native_apply_and_delete_reconcile(void) {
  const mesh_control_state_config_v1_t state_config = {2u, 4u, 8u, 500u, 1024u, 2048u};
  fake_provider_v1_t fake = {0};
  mesh_control_provider_v1_t provider;
  mesh_control_reconciler_config_v1_t reconcile_config;
  mesh_control_reconciler_v1_t reconciler = {0};
  mesh_control_state_v1_t state = {0};
  mesh_control_function_spec_v1_t spec;
  mesh_control_envelope_v1_t apply;
  mesh_control_envelope_v1_t remove;
  mesh_control_operation_v1_t operation;
  mesh_control_reconciler_prepared_completion_v1_t prepared;
  mesh_control_resource_status_v1_t status;
  mesh_control_reconciler_stats_v1_t stats;
  uint8_t document[MESH_CONTROL_FUNCTION_DOCUMENT_SIZE_V1];
  const uint8_t *retained_document = NULL;
  size_t document_size = 0u;
  size_t retained_document_size = 0u;
  size_t progress = 0u;

  make_provider(&provider, &fake, MESH_CONTROL_FUNCTION_NATIVE);
  memset(&reconcile_config, 0, sizeof(reconcile_config));
  reconcile_config.providers = &provider;
  reconcile_config.provider_count = 1u;
  reconcile_config.inflight_capacity = 4u;
  make_function_document(&spec, document, &document_size);
  make_intent(&apply, &spec, 10u, 1u, 0u);
  check_int_eq(mesh_control_state_init_v1(&state, &state_config), MESH_CONTROL_OK);
  check_int_eq(mesh_control_reconciler_init_v1(&reconciler, &reconcile_config), MESH_CONTROL_OK);
  check_int_eq(mesh_control_state_submit_document_v1(&state, &apply, MESH_CONTROL_DESIRED_APPLY,
                                                     document, document_size, 1100u, &operation),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_reconciler_enqueue_v1(&reconciler, &operation, document, document_size),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_reconciler_poll_v1(&reconciler, &state, 2u, 2u, 1110u, &progress),
               MESH_CONTROL_OK);
  check_int_eq(progress, 1u);
  check_int_eq(mesh_control_state_get_operation_v1(&state, operation.operation_id, &operation),
               MESH_CONTROL_OK);
  check_int_eq(operation.state, MESH_CONTROL_OPERATION_RUNNING);
  fake_complete(&fake, MESH_CONTROL_PROVIDER_COMPLETED);
  fake.ack_failure = 1u;
  check_int_eq(mesh_control_reconciler_poll_v1(&reconciler, &state, 2u, 2u, 1120u, &progress),
               MESH_CONTROL_INVALID_STATE);
  check_true(fake.completion_ready);
  fake.ack_failure = 0u;
  check_int_eq(mesh_control_reconciler_poll_v1(&reconciler, &state, 2u, 2u, 1120u, &progress),
               MESH_CONTROL_OK);
  check_false(fake.completion_ready);
  check_int_eq(mesh_control_state_get_resource_v1(&state, MESH_CONTROL_RESOURCE_FUNCTION,
                                                  spec.function_id, &status),
               MESH_CONTROL_OK);
  check_int_eq(status.observed_presence, MESH_CONTROL_PRESENCE_PRESENT);

  make_intent(&remove, &spec, 20u, 2u, 1u);
  check_int_eq(mesh_control_state_submit_document_v1(&state, &remove, MESH_CONTROL_DESIRED_DELETE,
                                                     NULL, 0u, 1200u, &operation),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_state_get_desired_document_v1(&state, MESH_CONTROL_RESOURCE_FUNCTION,
                                                          spec.function_id, &retained_document,
                                                          &retained_document_size),
               MESH_CONTROL_OK);
  check_int_eq(retained_document_size, document_size);
  check_int_eq(mesh_control_reconciler_enqueue_v1(&reconciler, &operation, retained_document,
                                                  retained_document_size),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_reconciler_poll_v1(&reconciler, &state, 2u, 2u, 1210u, &progress),
               MESH_CONTROL_OK);
  fake_complete(&fake, MESH_CONTROL_PROVIDER_COMPLETED);
  check_int_eq(mesh_control_reconciler_prepare_completion_v1(&reconciler, &prepared),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_reconciler_apply_completion_v1(&reconciler, &state, 1220u),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_reconciler_close_v1(&reconciler), MESH_CONTROL_OK);
  check_true(fake.completion_ready);
  check_false(mesh_control_reconciler_is_drained_v1(&reconciler));
  check_int_eq(mesh_control_reconciler_ack_completion_v1(&reconciler), MESH_CONTROL_OK);
  check_int_eq(mesh_control_state_get_resource_v1(&state, MESH_CONTROL_RESOURCE_FUNCTION,
                                                  spec.function_id, &status),
               MESH_CONTROL_OK);
  check_int_eq(status.observed_presence, MESH_CONTROL_PRESENCE_ABSENT);
  check_int_eq(mesh_control_reconciler_get_stats_v1(&reconciler, &stats), MESH_CONTROL_OK);
  check_int_eq(stats.started, 2u);
  check_int_eq(stats.succeeded, 2u);
  check_int_eq(stats.queued, 0u);
  check_int_eq(stats.inflight, 0u);
  check_true(mesh_control_reconciler_is_drained_v1(&reconciler));
  mesh_control_reconciler_destroy_v1(&reconciler);
  mesh_control_state_destroy_v1(&state);
}

static void test_backpressure_and_shutdown_are_bounded(void) {
  const mesh_control_state_config_v1_t state_config = {1u, 1u, 4u, 500u, 1024u, 2048u};
  fake_provider_v1_t fake = {0};
  mesh_control_provider_v1_t provider;
  mesh_control_reconciler_config_v1_t reconcile_config;
  mesh_control_reconciler_v1_t reconciler = {0};
  mesh_control_state_v1_t state = {0};
  mesh_control_function_spec_v1_t spec;
  mesh_control_envelope_v1_t apply;
  mesh_control_operation_v1_t operation;
  mesh_control_reconciler_stats_v1_t stats;
  uint8_t document[MESH_CONTROL_FUNCTION_DOCUMENT_SIZE_V1];
  size_t document_size = 0u;
  size_t progress = 0u;

  make_provider(&provider, &fake, MESH_CONTROL_FUNCTION_NATIVE);
  reconcile_config.providers = &provider;
  reconcile_config.provider_count = 1u;
  reconcile_config.inflight_capacity = 1u;
  make_function_document(&spec, document, &document_size);
  make_intent(&apply, &spec, 30u, 1u, 0u);
  check_int_eq(mesh_control_state_init_v1(&state, &state_config), MESH_CONTROL_OK);
  check_int_eq(mesh_control_reconciler_init_v1(&reconciler, &reconcile_config), MESH_CONTROL_OK);
  check_int_eq(mesh_control_state_submit_document_v1(&state, &apply, MESH_CONTROL_DESIRED_APPLY,
                                                     document, document_size, 1100u, &operation),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_reconciler_enqueue_v1(&reconciler, &operation, document, document_size),
               MESH_CONTROL_OK);
  fake.backpressure = 1u;
  check_int_eq(mesh_control_reconciler_poll_v1(&reconciler, &state, 1u, 1u, 1110u, &progress),
               MESH_CONTROL_OK);
  check_int_eq(progress, 0u);
  check_int_eq(mesh_control_reconciler_get_stats_v1(&reconciler, &stats), MESH_CONTROL_OK);
  check_int_eq(stats.queued, 1u);
  check_int_eq(stats.provider_backpressure, 1u);
  check_int_eq(mesh_control_reconciler_close_v1(&reconciler), MESH_CONTROL_OK);
  check_false(mesh_control_reconciler_is_drained_v1(&reconciler));
  check_int_eq(mesh_control_reconciler_poll_v1(&reconciler, &state, 1u, 1u, 1120u, &progress),
               MESH_CONTROL_OK);
  check_int_eq(progress, 1u);
  check_true(mesh_control_reconciler_is_drained_v1(&reconciler));
  check_int_eq(mesh_control_state_get_operation_v1(&state, operation.operation_id, &operation),
               MESH_CONTROL_OK);
  check_int_eq(operation.state, MESH_CONTROL_OPERATION_INTERRUPTED);
  mesh_control_reconciler_destroy_v1(&reconciler);
  mesh_control_state_destroy_v1(&state);
}

static void test_wasm_provider_registration_is_supported(void) {
  fake_provider_v1_t fake = {0};
  mesh_control_provider_v1_t provider;
  mesh_control_reconciler_config_v1_t config;
  mesh_control_reconciler_v1_t reconciler = {0};

  make_provider(&provider, &fake, MESH_CONTROL_FUNCTION_WASM);
  config.providers = &provider;
  config.provider_count = 1u;
  config.inflight_capacity = 1u;
  check_int_eq(mesh_control_reconciler_init_v1(&reconciler, &config),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_reconciler_has_provider_v1(
                   &reconciler, provider.provider_id,
                   MESH_CONTROL_FUNCTION_WASM),
               MESH_CONTROL_OK);
  check_int_eq(mesh_control_reconciler_close_v1(&reconciler),
               MESH_CONTROL_OK);
  check_true(mesh_control_reconciler_is_drained_v1(&reconciler));
  mesh_control_reconciler_destroy_v1(&reconciler);
}

spec("mesh control function reconciler") {
  describe("bounded prestaged provider strategy") {
    it("reconciles Native apply and delete through one registered provider") {
      test_native_apply_and_delete_reconcile();
    }
    it("preserves provider backpressure and interrupts on bounded shutdown") {
      test_backpressure_and_shutdown_are_bounded();
    }
    it("registers an explicitly enabled WASM provider") {
      test_wasm_provider_registration_is_supported();
    }
  }
}
