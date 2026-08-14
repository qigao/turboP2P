#include "mesh_control_durable_outbox_worker.h"
#include "tinytest.h"
#include "turbo_thread.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { TEST_WAIT_ATTEMPTS = 2000 };

static void fill_bytes(uint8_t *bytes, size_t size, uint8_t seed) {
  size_t index;
  for (index = 0u; index < size; ++index)
    bytes[index] = (uint8_t)(seed + index);
}

static char *make_path(char **out_directory) {
  char *directory = tt_make_temp_dir("mesh-outbox-worker");
  char *path;
  size_t size;
  if (!directory)
    return NULL;
  size = strlen(directory) + strlen("/outbox.bin") + 1u;
  path = (char *)malloc(size);
  if (!path) {
    (void)tt_remove_tree(directory);
    free(directory);
    return NULL;
  }
  (void)snprintf(path, size, "%s/outbox.bin", directory);
  *out_directory = directory;
  return path;
}

static void configure(mesh_control_durable_outbox_config_v1_t *config,
                      const char *path) {
  memset(config, 0, sizeof(*config));
  config->path = path;
  config->entry_capacity = 8u;
  config->session_capacity = 4u;
  config->byte_capacity = 4096u;
  config->max_payload_size = 1024u;
  config->max_claim_lease_ms = 5000u;
  config->ack_retention_ms = 1000u;
  fill_bytes(config->authentication_key, sizeof(config->authentication_key),
             0x70u);
}

static mesh_control_durable_outbox_worker_result_t wait_take(
    mesh_control_durable_outbox_worker_v1_t *worker,
    mesh_control_durable_outbox_worker_completion_v1_t *completion,
    uint8_t *payload, size_t payload_capacity, size_t *out_payload_size) {
  size_t attempt;
  mesh_control_durable_outbox_worker_result_t result =
      MESH_CONTROL_DURABLE_OUTBOX_WORKER_EMPTY;
  for (attempt = 0u; attempt < TEST_WAIT_ATTEMPTS; ++attempt) {
    result = mesh_control_durable_outbox_worker_try_take_v1(
        worker, completion, payload, payload_capacity, out_payload_size);
    if (result != MESH_CONTROL_DURABLE_OUTBOX_WORKER_EMPTY)
      return result;
    turbo_sleep_ms(1u);
  }
  return result;
}

spec("Controller durable outbox persistence worker") {
  it("keeps file I/O off the caller and preserves bounded fenced delivery") {
    mesh_control_durable_outbox_worker_v1_t worker;
    mesh_control_durable_outbox_worker_completion_v1_t completion;
    mesh_control_durable_outbox_worker_stats_v1_t stats;
    mesh_control_durable_outbox_config_v1_t config;
    mesh_control_durable_outbox_message_v1_t message;
    uint8_t target[MESH_CONTROL_NODE_ID_SIZE];
    uint8_t message_id[MESH_CONTROL_ID_SIZE];
    uint8_t request_id[MESH_CONTROL_ID_SIZE];
    uint8_t session[MESH_CONTROL_ID_SIZE];
    uint8_t output[64];
    const uint8_t payload[] = "signed-controller-intent";
    char *directory = NULL;
    char *path = make_path(&directory);
    size_t output_size = 0u;
    uint64_t session_generation;
    uint64_t lease_generation;

    check_not_null(path);
    configure(&config, path);
    fill_bytes(target, sizeof(target), 0x10u);
    fill_bytes(message_id, sizeof(message_id), 0x30u);
    fill_bytes(request_id, sizeof(request_id), 0x50u);
    fill_bytes(session, sizeof(session), 0x90u);
    memset(&message, 0, sizeof(message));
    memcpy(message.target_node_id, target, sizeof(target));
    memcpy(message.message_id, message_id, sizeof(message_id));
    memcpy(message.request_id, request_id, sizeof(request_id));
    message.sequence = 1u;
    message.payload = payload;
    message.payload_size = sizeof(payload);
    message.created_at_ms = 100u;

    check_int_eq(mesh_control_durable_outbox_worker_init_v1(
                     &worker, &config, NULL),
                 MESH_CONTROL_DURABLE_OUTBOX_WORKER_OK);
    check_int_eq(mesh_control_durable_outbox_worker_try_submit_message_v1(
                     &worker, 1u, &message),
                 MESH_CONTROL_DURABLE_OUTBOX_WORKER_OK);
    check_int_eq(mesh_control_durable_outbox_worker_try_submit_message_v1(
                     &worker, 2u, &message),
                 MESH_CONTROL_DURABLE_OUTBOX_WORKER_FULL);
    check_int_eq(wait_take(&worker, &completion, output, sizeof(output),
                           &output_size),
                 MESH_CONTROL_DURABLE_OUTBOX_WORKER_OK);
    check_uint_eq(completion.request_token, 1u);
    check_int_eq(completion.store_result, MESH_CONTROL_DURABLE_OUTBOX_OK);

    check_int_eq(mesh_control_durable_outbox_worker_try_activate_session_v1(
                     &worker, 3u, target, session, 110u),
                 MESH_CONTROL_DURABLE_OUTBOX_WORKER_OK);
    check_int_eq(wait_take(&worker, &completion, output, sizeof(output),
                           &output_size),
                 MESH_CONTROL_DURABLE_OUTBOX_WORKER_OK);
    check_uint_eq(completion.request_token, 3u);
    check_int_eq(completion.store_result, MESH_CONTROL_DURABLE_OUTBOX_OK);
    session_generation = completion.session_generation;
    check_true(session_generation > 0u);

    check_int_eq(mesh_control_durable_outbox_worker_try_claim_v1(
                     &worker, 4u, target, session, session_generation, 120u,
                     500u),
                 MESH_CONTROL_DURABLE_OUTBOX_WORKER_OK);
    check_int_eq(wait_take(&worker, &completion, output, 1u, &output_size),
                 MESH_CONTROL_DURABLE_OUTBOX_WORKER_RESOURCE_EXHAUSTED);
    check_size_eq(output_size, sizeof(payload));
    check_int_eq(wait_take(&worker, &completion, output, sizeof(output),
                           &output_size),
                 MESH_CONTROL_DURABLE_OUTBOX_WORKER_OK);
    check_uint_eq(completion.request_token, 4u);
    check_mem_eq(output, payload, sizeof(payload));
    lease_generation = completion.view.lease_generation;

    check_int_eq(mesh_control_durable_outbox_worker_try_ack_v1(
                     &worker, 5u, target, message_id, session,
                     session_generation, lease_generation, 130u),
                 MESH_CONTROL_DURABLE_OUTBOX_WORKER_OK);
    check_int_eq(wait_take(&worker, &completion, output, sizeof(output),
                           &output_size),
                 MESH_CONTROL_DURABLE_OUTBOX_WORKER_OK);
    check_int_eq(completion.store_result, MESH_CONTROL_DURABLE_OUTBOX_OK);
    check_int_eq(mesh_control_durable_outbox_worker_get_stats_v1(&worker,
                                                                  &stats),
                 MESH_CONTROL_DURABLE_OUTBOX_WORKER_OK);
    check_uint_eq(stats.submitted, 4u);
    check_uint_eq(stats.completed, 4u);
    check_uint_eq(stats.rejected_full, 1u);
    check_size_eq(stats.outbox.acked, 1u);

    check_int_eq(mesh_control_durable_outbox_worker_shutdown_v1(&worker),
                 MESH_CONTROL_DURABLE_OUTBOX_WORKER_OK);
    check_int_eq(mesh_control_durable_outbox_worker_try_compact_v1(
                     &worker, 6u, 2000u),
                 MESH_CONTROL_DURABLE_OUTBOX_WORKER_INVALID_STATE);
    mesh_control_durable_outbox_worker_destroy_v1(&worker);
    free(path);
    (void)tt_remove_tree(directory);
    free(directory);
  }
}
