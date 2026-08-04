#include "mesh_mgmt_execution_sender.h"
#include "mesh_mgmt_execution_egress.h"
#include "mesh_mgmt_execution_orchestrator.h"
#include "mesh_mgmt_execution_service.h"
#include "mesh_mgmt_execution_worker.h"
#include "tinytest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  uint64_t now_ms;
  unsigned int verifies;
} test_context_t;

static void fill_bytes(uint8_t *bytes, size_t size, uint8_t value) {
  memset(bytes, value, size);
}

static uint64_t test_clock(void *context) {
  test_context_t *test = (test_context_t *)context;
  return test->now_ms++;
}

static int verify_grant(void *context,
                        const mesh_mgmt_execution_grant_v1_t *grant,
                        uint64_t now_ms) {
  test_context_t *test = (test_context_t *)context;
  (void)grant;
  (void)now_ms;
  test->verifies++;
  return 0;
}

typedef struct {
  turbo_mutex_t mutex;
  turbo_cond_t condition;
  unsigned int started;
  unsigned int completed;
  int release_callbacks;
  mesh_mgmt_execution_service_result_t service_result;
  mesh_mgmt_execution_result_v1_t result;
  size_t payload_size;
} worker_test_context_t;

typedef struct {
  uint8_t frame[MESH_MGMT_FRAME_MAX];
  size_t frame_size;
  size_t sends;
} sender_test_io_t;

static int sender_test_send(void *context, const uint8_t *bytes, size_t size) {
  sender_test_io_t *io = (sender_test_io_t *)context;

  if (size > sizeof(io->frame))
    return -1;
  memcpy(io->frame, bytes, size);
  io->frame_size = size;
  io->sends++;
  return 0;
}

static void worker_completion(
    void *context,
    const mesh_mgmt_execution_shadow_command_v1_t *command,
    mesh_mgmt_execution_service_result_t service_result,
    const uint8_t *result_payload,
    size_t result_payload_size,
    const mesh_mgmt_execution_result_v1_t *result) {
  worker_test_context_t *worker_context = (worker_test_context_t *)context;

  (void)command;
  (void)result_payload;
  turbo_mutex_lock(&worker_context->mutex);
  worker_context->started++;
  worker_context->service_result = service_result;
  worker_context->result = *result;
  worker_context->payload_size = result_payload_size;
  turbo_cond_broadcast(&worker_context->condition);
  while (!worker_context->release_callbacks) {
    turbo_cond_wait(&worker_context->condition, &worker_context->mutex);
  }
  worker_context->completed++;
  turbo_cond_broadcast(&worker_context->condition);
  turbo_mutex_unlock(&worker_context->mutex);
}

static int wait_for_worker_start(worker_test_context_t *context) {
  int wait_result = 0;

  turbo_mutex_lock(&context->mutex);
  while (context->started == 0u && wait_result == 0) {
    wait_result = turbo_cond_timedwait(
        &context->condition, &context->mutex, 5u * 1000u * 1000u * 1000u);
  }
  turbo_mutex_unlock(&context->mutex);
  return wait_result == 0;
}

static void fill_limits(mesh_mgmt_execution_limits_v1_t *limits) {
  memset(limits, 0, sizeof(*limits));
  limits->module_bytes = 1024u * 1024u;
  limits->stack_bytes = 64u * 1024u;
  limits->linear_memory_bytes = 256u * 1024u;
  limits->timeout_ms = 1000u;
  limits->control_flow_steps = 1000000u;
  limits->host_calls = 64u;
  limits->copied_guest_bytes = 64u * 1024u;
  limits->input_bytes = MESH_MGMT_EXECUTION_INLINE_INPUT_MAX;
  limits->stdout_bytes = 64u * 1024u;
  limits->stderr_bytes = 64u * 1024u;
}

static void cleanup_store_files(const char *path) {
  char lock_path[TURBO_FS_MAX_PATH + 6u];
  char temp_path[TURBO_FS_MAX_PATH + 5u];

  (void)snprintf(lock_path, sizeof(lock_path), "%s.lock", path);
  (void)snprintf(temp_path, sizeof(temp_path), "%s.tmp", path);
  /* Only remove files that exist; unlink/stat of a missing file logs ERROR. */
  if (turbo_fs_access(path, TURBO_FS_ACCESS_EXISTS) == 0) (void)turbo_fs_unlink(path);
  if (turbo_fs_access(lock_path, TURBO_FS_ACCESS_EXISTS) == 0) (void)turbo_fs_unlink(lock_path);
  if (turbo_fs_access(temp_path, TURBO_FS_ACCESS_EXISTS) == 0) (void)turbo_fs_unlink(temp_path);
}

static void test_executes_once_and_replays_signed_result(void) {
  static const uint8_t result_private_key[32] = {
      1,  3,  5,  7,  9,  11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31,
      2,  4,  6,  8,  10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32};
  mesh_mgmt_execution_store_v1_t store;
  mesh_mgmt_execution_runner_v1_t runner;
  mesh_mgmt_execution_deployment_v1_t deployment;
  mesh_mgmt_execution_grant_v1_t grant;
  mesh_mgmt_execution_request_v1_t request;
  mesh_mgmt_execution_authorization_input_v1_t authorization;
  mesh_mgmt_execution_orchestrator_config_v1_t config;
  mesh_mgmt_execution_orchestrator_v1_t orchestrator;
  mesh_mgmt_execution_result_v1_t first_result;
  mesh_mgmt_execution_result_v1_t repeated_result;
  mesh_mgmt_execution_result_v1_t service_result;
  mesh_mgmt_execution_result_v1_t decoded_result;
  mesh_mgmt_execution_shadow_command_v1_t command;
  mesh_mgmt_execution_service_config_v1_t service_config;
  mesh_mgmt_execution_service_v1_t service;
  mesh_mgmt_execution_worker_config_v1_t worker_config;
  mesh_mgmt_execution_worker_v1_t worker;
  mesh_mgmt_execution_worker_stats_v1_t worker_stats;
  worker_test_context_t worker_context;
  mesh_mgmt_execution_egress_v1_t egress;
  mesh_mgmt_execution_egress_item_v1_t egress_item;
  mesh_mgmt_execution_egress_stats_v1_t egress_stats;
  mesh_mgmt_peer_signer_v1_t result_signer;
  mesh_mgmt_connection_v1_t result_connection;
  mesh_mgmt_verified_envelope_v1_t sent_envelope;
  mesh_mgmt_execution_status_v1_t sent_status;
  mesh_mgmt_execution_result_v1_t empty_result;
  sender_test_io_t sender_io;
  test_context_t context = {1000u, 0u};
  uint8_t module_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint8_t result_payload[MESH_MGMT_EXECUTION_COMMAND_RESULT_SIZE_V1];
  size_t result_payload_size = 0u;
  uint64_t terminal_generation;
  char *path = tt_make_temp_file("mesh-execution-orchestrator", ".bin");

  check_not_null(path);
  if (!path)
    return;
  cleanup_store_files(path);
  check_int_eq(mesh_mgmt_execution_runner_module_digest_v1(
                   MESH_TEST_EXECUTION_WASM, 1024u * 1024u,
                   module_digest, NULL),
               MESH_MGMT_EXECUTION_RUNNER_OK);
  memset(&deployment, 0, sizeof(deployment));
  fill_bytes(deployment.deployment_id, sizeof(deployment.deployment_id), 4u);
  deployment.generation = 1u;
  memcpy(deployment.module_digest, module_digest, sizeof(module_digest));
  deployment.module_path = MESH_TEST_EXECUTION_WASM;
  check_int_eq(mesh_mgmt_execution_runner_init_v1(&runner, 1u),
               MESH_MGMT_EXECUTION_RUNNER_OK);
  check_int_eq(mesh_mgmt_execution_runner_register_v1(&runner, &deployment),
               MESH_MGMT_EXECUTION_RUNNER_OK);
  check_int_eq(mesh_mgmt_execution_store_open_v1(&store, path, 2u, NULL),
               MESH_MGMT_EXECUTION_STORE_OK);

  memset(&grant, 0, sizeof(grant));
  grant.version = MESH_MGMT_EXECUTION_SCHEMA_V1;
  fill_bytes(grant.grant_id, sizeof(grant.grant_id), 1u);
  fill_bytes(grant.mesh_id, sizeof(grant.mesh_id), 2u);
  grant.policy_epoch = 3u;
  fill_bytes(grant.subject_principal, sizeof(grant.subject_principal), 4u);
  fill_bytes(grant.target_node_id, sizeof(grant.target_node_id), 5u);
  memcpy(grant.deployment_id, deployment.deployment_id,
         sizeof(grant.deployment_id));
  grant.deployment_generation = deployment.generation;
  memcpy(grant.package_digest, module_digest, sizeof(module_digest));
  grant.operation = MESH_MGMT_EXECUTION_OPERATION_RUN_PRESTAGED_WASM;
  grant.capabilities = MESH_MGMT_EXECUTION_CAP_CORE |
                       MESH_MGMT_EXECUTION_CAP_UTILS |
                       MESH_MGMT_EXECUTION_CAP_APP;
  fill_limits(&grant.max_limits);
  grant.not_before_ms = 900u;
  grant.expires_at_ms = 5000u;
  fill_bytes(grant.issuer_key, sizeof(grant.issuer_key), 6u);
  fill_bytes(grant.signature, sizeof(grant.signature), 7u);

  memset(&request, 0, sizeof(request));
  request.version = MESH_MGMT_EXECUTION_SCHEMA_V1;
  fill_bytes(request.command_id, sizeof(request.command_id), 8u);
  memcpy(request.grant_id, grant.grant_id, sizeof(request.grant_id));
  memcpy(request.target_node_id, grant.target_node_id,
         sizeof(request.target_node_id));
  memcpy(request.deployment_id, deployment.deployment_id,
         sizeof(request.deployment_id));
  request.deployment_generation = deployment.generation;
  memcpy(request.package_digest, module_digest, sizeof(module_digest));
  request.input_kind = MESH_MGMT_EXECUTION_INPUT_NONE;
  request.output_mode = MESH_MGMT_EXECUTION_OUTPUT_DIGEST;
  request.deadline_ms = 4000u;
  fill_bytes(request.request_nonce, sizeof(request.request_nonce), 9u);
  fill_bytes(request.correlation_id, sizeof(request.correlation_id), 10u);

  memset(&authorization, 0, sizeof(authorization));
  authorization.requested_capabilities = grant.capabilities;
  authorization.host_capabilities = grant.capabilities;
  authorization.hard_capabilities = grant.capabilities;
  fill_limits(&authorization.requested_limits);
  fill_limits(&authorization.host_limits);
  fill_limits(&authorization.hard_limits);

  memset(&config, 0, sizeof(config));
  config.store = &store;
  config.runner = &runner;
  memcpy(config.local_node_id, grant.target_node_id,
         sizeof(config.local_node_id));
  memcpy(config.result_private_key, result_private_key,
         sizeof(config.result_private_key));
  config.worker_generation = 1u;
  config.verify_grant = verify_grant;
  config.verify_grant_context = &context;
  config.clock_now_ms = test_clock;
  config.clock_context = &context;
  check_int_eq(mesh_mgmt_execution_orchestrator_init_v1(
                   &orchestrator, &config),
               MESH_MGMT_EXECUTION_ORCHESTRATOR_OK);

  check_int_eq(mesh_mgmt_execution_orchestrator_execute_v1(
                   &orchestrator, &grant, &request, &authorization, NULL,
                   &first_result),
               MESH_MGMT_EXECUTION_ORCHESTRATOR_OK);
  check_int_eq(first_result.state, MESH_MGMT_EXECUTION_STATE_FAILED);
  check_int_eq(first_result.guest_exit_code, 7);
  check_int_eq(mesh_mgmt_execution_result_verify_v1(
                   &first_result, orchestrator.result_public_key),
               MESH_MGMT_EXECUTION_RESULT_OK);
  terminal_generation = store.journal.generation;

  check_int_eq(mesh_mgmt_execution_orchestrator_execute_v1(
                   &orchestrator, &grant, &request, &authorization, NULL,
                   &repeated_result),
               MESH_MGMT_EXECUTION_ORCHESTRATOR_OK);
  check_mem_eq(repeated_result.signature, first_result.signature,
               sizeof(first_result.signature));
  check_uint_eq(store.journal.generation, terminal_generation);
  check_uint_eq(context.verifies, 2u);

  memset(&command, 0, sizeof(command));
  command.grant = grant;
  command.request = request;
  fill_bytes(command.reply_node_id, sizeof(command.reply_node_id), 11u);
  check_int_eq(mesh_mgmt_execution_request_digest_v1(
                   &command.request, command.request_digest),
               MESH_MGMT_EXECUTION_RESULT_OK);

  memset(&service_config, 0, sizeof(service_config));
  service_config.orchestrator = &orchestrator;
  check_int_eq(mesh_mgmt_execution_service_init_v1(&service, &service_config),
               MESH_MGMT_EXECUTION_SERVICE_OK);
  terminal_generation = store.journal.generation;
  check_int_eq(mesh_mgmt_execution_service_execute_v1(
                   &service, &command, &authorization, NULL, result_payload,
                   sizeof(result_payload), &result_payload_size,
                   &service_result),
               MESH_MGMT_EXECUTION_SERVICE_DISABLED);
  check_uint_eq(store.journal.generation, terminal_generation);
  mesh_mgmt_execution_service_destroy_v1(&service);

  service_config.enabled = 1u;
  check_int_eq(mesh_mgmt_execution_service_init_v1(&service, &service_config),
               MESH_MGMT_EXECUTION_SERVICE_OK);
  check_int_eq(mesh_mgmt_execution_service_execute_v1(
                   &service, &command, &authorization, NULL, result_payload,
                   sizeof(result_payload) - 1u, &result_payload_size,
                   &service_result),
               MESH_MGMT_EXECUTION_SERVICE_RESOURCE_EXHAUSTED);
  check_size_eq(result_payload_size,
                MESH_MGMT_EXECUTION_COMMAND_RESULT_SIZE_V1);
  check_uint_eq(store.journal.generation, terminal_generation);

  command.request_digest[0] ^= 0xffu;
  check_int_eq(mesh_mgmt_execution_service_execute_v1(
                   &service, &command, &authorization, NULL, result_payload,
                   sizeof(result_payload), &result_payload_size,
                   &service_result),
               MESH_MGMT_EXECUTION_SERVICE_INVALID_COMMAND);
  check_uint_eq(store.journal.generation, terminal_generation);
  command.request_digest[0] ^= 0xffu;

  check_int_eq(mesh_mgmt_execution_service_execute_v1(
                   &service, &command, &authorization, NULL, result_payload,
                   sizeof(result_payload), &result_payload_size,
                   &service_result),
               MESH_MGMT_EXECUTION_SERVICE_OK);
  check_size_eq(result_payload_size,
                MESH_MGMT_EXECUTION_COMMAND_RESULT_SIZE_V1);
  check_uint_eq(store.journal.generation, terminal_generation);
  check_mem_eq(service_result.signature, first_result.signature,
               sizeof(first_result.signature));
  check_int_eq(mesh_mgmt_execution_command_result_decode_v1(
                   result_payload, result_payload_size, &decoded_result),
               MESH_MGMT_EXECUTION_WIRE_OK);
  check_mem_eq(decoded_result.signature, first_result.signature,
               sizeof(first_result.signature));
  check_int_eq(mesh_mgmt_execution_result_verify_v1(
                   &decoded_result, decoded_result.signer_public_key),
               MESH_MGMT_EXECUTION_RESULT_OK);

  memset(&worker_context, 0, sizeof(worker_context));
  turbo_mutex_init(&worker_context.mutex);
  turbo_cond_init(&worker_context.condition);
  memset(&worker_config, 0, sizeof(worker_config));
  worker_config.service = &service;
  worker_config.completion = worker_completion;
  worker_config.completion_context = &worker_context;
  check_int_eq(mesh_mgmt_execution_worker_init_v1(&worker, &worker_config),
               MESH_MGMT_EXECUTION_WORKER_INVALID_ARG);
  worker_config.queue_capacity =
      MESH_MGMT_EXECUTION_WORKER_MAX_QUEUE_CAPACITY + 1u;
  check_int_eq(mesh_mgmt_execution_worker_init_v1(&worker, &worker_config),
               MESH_MGMT_EXECUTION_WORKER_INVALID_ARG);
  worker_config.queue_capacity = 2u;
  check_int_eq(mesh_mgmt_execution_worker_init_v1(&worker, &worker_config),
               MESH_MGMT_EXECUTION_WORKER_OK);
  check_int_eq(mesh_mgmt_execution_worker_try_submit_v1(
                   &worker, &command, &authorization),
               MESH_MGMT_EXECUTION_WORKER_OK);
  check_true(wait_for_worker_start(&worker_context));
  check_int_eq(mesh_mgmt_execution_worker_try_submit_v1(
                   &worker, &command, &authorization),
               MESH_MGMT_EXECUTION_WORKER_OK);
  check_int_eq(mesh_mgmt_execution_worker_try_submit_v1(
                   &worker, &command, &authorization),
               MESH_MGMT_EXECUTION_WORKER_OK);
  check_int_eq(mesh_mgmt_execution_worker_try_submit_v1(
                   &worker, &command, &authorization),
               MESH_MGMT_EXECUTION_WORKER_FULL);

  turbo_mutex_lock(&worker_context.mutex);
  worker_context.release_callbacks = 1;
  turbo_cond_broadcast(&worker_context.condition);
  turbo_mutex_unlock(&worker_context.mutex);
  check_int_eq(mesh_mgmt_execution_worker_shutdown_v1(&worker),
               MESH_MGMT_EXECUTION_WORKER_OK);
  check_int_eq(mesh_mgmt_execution_worker_try_submit_v1(
                   &worker, &command, &authorization),
               MESH_MGMT_EXECUTION_WORKER_CLOSED);
  check_int_eq(mesh_mgmt_execution_worker_get_stats_v1(
                   &worker, &worker_stats),
               MESH_MGMT_EXECUTION_WORKER_OK);
  check_size_eq(worker_stats.queue_capacity, 2u);
  check_uint_eq(worker_stats.submitted, 3u);
  check_uint_eq(worker_stats.started, 3u);
  check_uint_eq(worker_stats.completed, 3u);
  check_uint_eq(worker_stats.rejected, 1u);
  check_uint_eq(worker_stats.queued, 0u);
  check_uint_eq(worker_context.started, 3u);
  check_uint_eq(worker_context.completed, 3u);
  check_int_eq(worker_context.service_result,
               MESH_MGMT_EXECUTION_SERVICE_OK);
  check_size_eq(worker_context.payload_size,
                MESH_MGMT_EXECUTION_COMMAND_RESULT_SIZE_V1);
  check_mem_eq(worker_context.result.signature, first_result.signature,
               sizeof(first_result.signature));
  check_uint_eq(store.journal.generation, terminal_generation);
  mesh_mgmt_execution_worker_destroy_v1(&worker);
  turbo_cond_destroy(&worker_context.condition);
  turbo_mutex_destroy(&worker_context.mutex);

  check_int_eq(mesh_mgmt_execution_egress_init_v1(&egress, 0u),
               MESH_MGMT_EXECUTION_EGRESS_INVALID_ARG);
  check_int_eq(mesh_mgmt_execution_egress_init_v1(&egress, 3u),
               MESH_MGMT_EXECUTION_EGRESS_INVALID_ARG);
  check_int_eq(mesh_mgmt_execution_egress_init_v1(&egress, 2u),
               MESH_MGMT_EXECUTION_EGRESS_OK);
  memset(&worker_config, 0, sizeof(worker_config));
  worker_config.service = &service;
  worker_config.queue_capacity = 4u;
  worker_config.completion = mesh_mgmt_execution_egress_completion_v1;
  worker_config.completion_context = &egress;
  check_int_eq(mesh_mgmt_execution_worker_init_v1(&worker, &worker_config),
               MESH_MGMT_EXECUTION_WORKER_OK);
  check_int_eq(mesh_mgmt_execution_worker_try_submit_v1(
                   &worker, &command, &authorization),
               MESH_MGMT_EXECUTION_WORKER_OK);
  check_int_eq(mesh_mgmt_execution_worker_try_submit_v1(
                   &worker, &command, &authorization),
               MESH_MGMT_EXECUTION_WORKER_OK);
  check_int_eq(mesh_mgmt_execution_worker_try_submit_v1(
                   &worker, &command, &authorization),
               MESH_MGMT_EXECUTION_WORKER_OK);
  check_int_eq(mesh_mgmt_execution_worker_shutdown_v1(&worker),
               MESH_MGMT_EXECUTION_WORKER_OK);
  check_int_eq(mesh_mgmt_execution_egress_get_stats_v1(
                   &egress, &egress_stats),
               MESH_MGMT_EXECUTION_EGRESS_OK);
  check_size_eq(egress_stats.capacity, 2u);
  check_size_eq(egress_stats.pending, 2u);
  check_uint_eq(egress_stats.published, 2u);
  check_uint_eq(egress_stats.rejected_full, 1u);
  check_int_eq(mesh_mgmt_execution_egress_try_pop_v1(
                   &egress, &egress_item),
               MESH_MGMT_EXECUTION_EGRESS_OK);
  check_mem_eq(egress_item.target_node_id, command.reply_node_id,
               sizeof(egress_item.target_node_id));
  check_mem_eq(egress_item.command_id, request.command_id,
               sizeof(egress_item.command_id));
  check_mem_eq(egress_item.correlation_id, request.correlation_id,
               sizeof(egress_item.correlation_id));
  check_int_eq(egress_item.service_result,
               MESH_MGMT_EXECUTION_SERVICE_OK);
  check_size_eq(egress_item.result_payload_size,
                MESH_MGMT_EXECUTION_COMMAND_RESULT_SIZE_V1);
  check_int_eq(mesh_mgmt_execution_command_result_decode_v1(
                   egress_item.result_payload,
                   egress_item.result_payload_size, &decoded_result),
               MESH_MGMT_EXECUTION_WIRE_OK);
  check_int_eq(mesh_mgmt_execution_result_verify_v1(
                   &decoded_result, decoded_result.signer_public_key),
               MESH_MGMT_EXECUTION_RESULT_OK);
  check_int_eq(mesh_mgmt_execution_egress_try_pop_v1(
                   &egress, &egress_item),
               MESH_MGMT_EXECUTION_EGRESS_OK);
  check_int_eq(mesh_mgmt_execution_egress_try_pop_v1(
                   &egress, &egress_item),
               MESH_MGMT_EXECUTION_EGRESS_EMPTY);
  check_int_eq(mesh_mgmt_execution_egress_close_v1(&egress),
               MESH_MGMT_EXECUTION_EGRESS_OK);
  check_int_eq(mesh_mgmt_execution_egress_try_push_v1(
                   &egress, &command, MESH_MGMT_EXECUTION_SERVICE_OK,
                   result_payload, result_payload_size, &service_result),
               MESH_MGMT_EXECUTION_EGRESS_CLOSED);
  check_int_eq(mesh_mgmt_execution_egress_get_stats_v1(
                   &egress, &egress_stats),
               MESH_MGMT_EXECUTION_EGRESS_OK);
  check_size_eq(egress_stats.pending, 0u);
  check_uint_eq(egress_stats.consumed, 2u);
  check_uint_eq(egress_stats.rejected_closed, 1u);
  mesh_mgmt_execution_worker_destroy_v1(&worker);
  mesh_mgmt_execution_egress_destroy_v1(&egress);

  check_int_eq(mesh_mgmt_execution_egress_init_v1(&egress, 2u),
               MESH_MGMT_EXECUTION_EGRESS_OK);
  check_int_eq(mesh_mgmt_execution_egress_try_push_v1(
                   &egress, &command, MESH_MGMT_EXECUTION_SERVICE_OK,
                   result_payload, result_payload_size, &service_result),
               MESH_MGMT_EXECUTION_EGRESS_OK);
  memset(&result_signer, 0, sizeof(result_signer));
  memcpy(result_signer.private_key, result_private_key,
         sizeof(result_signer.private_key));
  memcpy(result_signer.mesh_id_hash, grant.mesh_id,
         sizeof(result_signer.mesh_id_hash));
  memcpy(result_signer.origin_node_id, service_result.target_node_id,
         sizeof(result_signer.origin_node_id));
  fill_bytes(result_signer.session_id, sizeof(result_signer.session_id), 12u);
  result_signer.principal_epoch = 1u;
  result_signer.incarnation = 1u;
  result_signer.certificate_serial = 1u;
  result_signer.next_sequence = 1u;
  result_signer.frame_ttl_ms = 1000u;
  result_signer.state = MESH_MGMT_PEER_SIGNER_READY;
  result_signer.hello_built = 1u;
  result_signer.ack_built = 1u;

  memset(&result_connection, 0, sizeof(result_connection));
  memset(&sender_io, 0, sizeof(sender_io));
  result_connection.state = MESH_MGMT_CONNECTION_READY;
  result_connection.transport.initialized = 1u;
  result_connection.transport.io.context = &sender_io;
  result_connection.transport.io.send = sender_test_send;
  result_connection.dispatcher.enable_node_execution_shadow = 1u;
  result_connection.dispatcher.session.state =
      MESH_MGMT_SESSION_ESTABLISHED;
  result_connection.dispatcher.session.negotiated.features =
      MESH_MGMT_FEATURE_TARGETED_RPC |
      MESH_MGMT_FEATURE_NODE_EXECUTION;
  result_connection.dispatcher.session.negotiated.max_frame =
      MESH_MGMT_FRAME_MAX;
  memcpy(result_connection.dispatcher.session.config.expected_mesh_id_hash,
         grant.mesh_id, sizeof(grant.mesh_id));
  memcpy(result_connection.dispatcher.session.remote_certificate.managed_node_id,
         command.reply_node_id, sizeof(command.reply_node_id));
  result_connection.dispatcher.session.remote_certificate.managed_node_id[0] ^=
      1u;
  check_int_eq(mesh_mgmt_execution_sender_send_next_v1(
                   &egress, &result_signer, &result_connection),
               MESH_MGMT_EXECUTION_SENDER_TARGET_MISMATCH);
  check_int_eq(mesh_mgmt_execution_egress_get_stats_v1(
                   &egress, &egress_stats),
               MESH_MGMT_EXECUTION_EGRESS_OK);
  check_size_eq(egress_stats.pending, 1u);
  result_connection.dispatcher.session.remote_certificate.managed_node_id[0] ^=
      1u;
  check_int_eq(mesh_mgmt_execution_sender_send_next_v1(
                   &egress, &result_signer, &result_connection),
               MESH_MGMT_EXECUTION_SENDER_OK);
  check_size_eq(sender_io.sends, 1u);
  check_int_eq(mesh_mgmt_envelope_verify_v1(
                   sender_io.frame, sender_io.frame_size, &sent_envelope),
               MESH_MGMT_ENVELOPE_OK);
  check_int_eq(sent_envelope.frame.kind, MESH_MGMT_KIND_COMMAND_RESULT);
  check_mem_eq(sent_envelope.header.target_node_id, command.reply_node_id,
               sizeof(command.reply_node_id));
  check_int_eq(mesh_mgmt_execution_egress_get_stats_v1(
                   &egress, &egress_stats),
               MESH_MGMT_EXECUTION_EGRESS_OK);
  check_size_eq(egress_stats.pending, 0u);
  mesh_mgmt_execution_egress_destroy_v1(&egress);

  memset(&empty_result, 0, sizeof(empty_result));
  check_int_eq(mesh_mgmt_execution_egress_init_v1(&egress, 2u),
               MESH_MGMT_EXECUTION_EGRESS_OK);
  check_int_eq(mesh_mgmt_execution_egress_try_push_v1(
                   &egress, &command, MESH_MGMT_EXECUTION_SERVICE_BUSY,
                   NULL, 0u, &empty_result),
               MESH_MGMT_EXECUTION_EGRESS_OK);
  check_int_eq(mesh_mgmt_execution_sender_send_next_v1(
                   &egress, &result_signer, &result_connection),
               MESH_MGMT_EXECUTION_SENDER_OK);
  check_int_eq(mesh_mgmt_envelope_verify_v1(
                   sender_io.frame, sender_io.frame_size, &sent_envelope),
               MESH_MGMT_ENVELOPE_OK);
  check_int_eq(sent_envelope.frame.kind, MESH_MGMT_KIND_COMMAND_STATUS);
  check_int_eq(mesh_mgmt_execution_command_status_decode_v1(
                   sent_envelope.frame.payload,
                   sent_envelope.frame.payload_len, &sent_status),
               MESH_MGMT_EXECUTION_WIRE_OK);
  check_int_eq(sent_status.code, MESH_MGMT_EXECUTION_STATUS_BUSY);
  check_true(mesh_mgmt_execution_status_is_retryable_v1(sent_status.code));
  check_mem_eq(sent_status.request_digest, command.request_digest,
               sizeof(command.request_digest));
  mesh_mgmt_execution_egress_destroy_v1(&egress);
  mesh_mgmt_execution_service_destroy_v1(&service);

  mesh_mgmt_execution_orchestrator_destroy_v1(&orchestrator);
  mesh_mgmt_execution_store_close_v1(&store);
  mesh_mgmt_execution_runner_destroy_v1(&runner);
  cleanup_store_files(path);
  free(path);
}

spec("mesh management durable execution orchestrator E2") {
  describe("authorized local execution") {
    it("executes once and replays the persisted signed result") {
      test_executes_once_and_replays_signed_result();
    }
  }
}
