#include "mesh_control_durable_outbox.h"
#include "tinytest.h"
#include "turbo_fs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
  TEST_ENTRY_CAPACITY = 4,
  TEST_BYTE_CAPACITY = 1024,
  TEST_MAX_PAYLOAD = 256,
  TEST_MAX_LEASE_MS = 1000,
  TEST_ACK_RETENTION_MS = 100
};

static void fill_bytes(uint8_t *bytes, size_t size, uint8_t seed) {
  size_t index;
  for (index = 0u; index < size; ++index)
    bytes[index] = (uint8_t)(seed + index);
}

static void configure(mesh_control_durable_outbox_config_v1_t *config,
                      const char *path, uint8_t key_seed) {
  memset(config, 0, sizeof(*config));
  config->path = path;
  config->entry_capacity = TEST_ENTRY_CAPACITY;
  config->session_capacity = TEST_ENTRY_CAPACITY;
  config->byte_capacity = TEST_BYTE_CAPACITY;
  config->max_payload_size = TEST_MAX_PAYLOAD;
  config->max_claim_lease_ms = TEST_MAX_LEASE_MS;
  config->ack_retention_ms = TEST_ACK_RETENTION_MS;
  fill_bytes(config->authentication_key, sizeof(config->authentication_key), key_seed);
}

static void make_message(mesh_control_durable_outbox_message_v1_t *message,
                         uint8_t seed, uint64_t sequence,
                         const uint8_t *payload, size_t payload_size) {
  memset(message, 0, sizeof(*message));
  fill_bytes(message->target_node_id, sizeof(message->target_node_id), 0x20u);
  fill_bytes(message->message_id, sizeof(message->message_id), seed);
  fill_bytes(message->request_id, sizeof(message->request_id), (uint8_t)(seed + 0x10u));
  message->sequence = sequence;
  message->payload = payload;
  message->payload_size = payload_size;
  message->created_at_ms = 1000u + sequence;
}

static char *make_store_path(char **out_directory) {
  char *directory = tt_make_temp_dir("mesh-durable-outbox");
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

static void cleanup_store_path(char *directory, char *path) {
  free(path);
  if (directory) {
    (void)tt_remove_tree(directory);
    free(directory);
  }
}

spec("Controller durable outbox") {
  it("durably submits claims ACKs and retains an idempotency tombstone") {
    mesh_control_durable_outbox_v1_t outbox;
    mesh_control_durable_outbox_config_v1_t config;
    mesh_control_durable_outbox_message_v1_t message;
    mesh_control_durable_outbox_view_v1_t view;
    mesh_control_durable_outbox_stats_v1_t stats;
    uint8_t session[MESH_CONTROL_ID_SIZE];
    const uint8_t payload[] = "signed-control-frame";
    char *directory = NULL;
    char *path = make_store_path(&directory);
    size_t recovered = 99u;
    size_t removed = 0u;
    uint64_t session_generation = 0u;

    check_not_null(path);
    configure(&config, path, 0x70u);
    make_message(&message, 0x31u, 7u, payload, sizeof(payload));
    fill_bytes(session, sizeof(session), 0x90u);
    check_int_eq(mesh_control_durable_outbox_open_v1(&outbox, &config, &recovered),
                 MESH_CONTROL_DURABLE_OUTBOX_OK);
    check_size_eq(recovered, 0u);
    check_int_eq(mesh_control_durable_outbox_submit_v1(&outbox, &message, &view),
                 MESH_CONTROL_DURABLE_OUTBOX_OK);
    check_int_eq(view.state, MESH_CONTROL_DURABLE_OUTBOX_PENDING);
    check_mem_eq(view.payload, payload, sizeof(payload));
    check_int_eq(mesh_control_durable_outbox_activate_session_v1(
                     &outbox, message.target_node_id, session, 1900u,
                     &session_generation, NULL),
                 MESH_CONTROL_DURABLE_OUTBOX_OK);
    check_int_eq(mesh_control_durable_outbox_claim_v1(
                     &outbox, message.target_node_id, session,
                     session_generation, 2000u, 250u, &view),
                 MESH_CONTROL_DURABLE_OUTBOX_OK);
    check_int_eq(view.state, MESH_CONTROL_DURABLE_OUTBOX_CLAIMED);
    check_uint_eq(view.lease_generation, 1u);
    check_int_eq(mesh_control_durable_outbox_ack_v1(
                     &outbox, message.target_node_id, message.message_id, session,
                     session_generation, view.lease_generation, 2100u),
                 MESH_CONTROL_DURABLE_OUTBOX_OK);
    check_int_eq(mesh_control_durable_outbox_ack_v1(
                     &outbox, message.target_node_id, message.message_id, session,
                     session_generation, view.lease_generation, 2100u),
                 MESH_CONTROL_DURABLE_OUTBOX_OK);
    mesh_control_durable_outbox_close_v1(&outbox);

    check_int_eq(mesh_control_durable_outbox_open_v1(&outbox, &config, &recovered),
                 MESH_CONTROL_DURABLE_OUTBOX_OK);
    check_int_eq(mesh_control_durable_outbox_get_v1(&outbox, message.message_id, &view),
                 MESH_CONTROL_DURABLE_OUTBOX_OK);
    check_int_eq(view.state, MESH_CONTROL_DURABLE_OUTBOX_ACKED);
    check_null(view.payload);
    check_size_eq(view.payload_size, 0u);
    check_int_eq(mesh_control_durable_outbox_get_stats_v1(&outbox, &stats),
                 MESH_CONTROL_DURABLE_OUTBOX_OK);
    check_size_eq(stats.acked, 1u);
    check_size_eq(stats.active_sessions, 0u);
    check_uint_eq(stats.recovered_sessions, 1u);
    check_size_eq(stats.retained_payload_bytes, 0u);
    check_int_eq(mesh_control_durable_outbox_compact_v1(&outbox, 2199u, &removed),
                 MESH_CONTROL_DURABLE_OUTBOX_OK);
    check_size_eq(removed, 0u);
    check_int_eq(mesh_control_durable_outbox_compact_v1(&outbox, 2200u, &removed),
                 MESH_CONTROL_DURABLE_OUTBOX_OK);
    check_size_eq(removed, 1u);
    check_int_eq(mesh_control_durable_outbox_get_v1(&outbox, message.message_id, &view),
                 MESH_CONTROL_DURABLE_OUTBOX_NOT_FOUND);
    mesh_control_durable_outbox_close_v1(&outbox);
    cleanup_store_path(directory, path);
  }

  it("reclaims expired delivery and fences the stale lease and session") {
    mesh_control_durable_outbox_v1_t outbox;
    mesh_control_durable_outbox_config_v1_t config;
    mesh_control_durable_outbox_message_v1_t message;
    mesh_control_durable_outbox_view_v1_t first;
    mesh_control_durable_outbox_view_v1_t second;
    uint8_t old_session[MESH_CONTROL_ID_SIZE];
    uint64_t session_generation = 0u;
    const uint8_t payload[] = {1u, 2u, 3u};
    char *directory = NULL;
    char *path = make_store_path(&directory);

    check_not_null(path);
    configure(&config, path, 0x21u);
    make_message(&message, 0x32u, 1u, payload, sizeof(payload));
    fill_bytes(old_session, sizeof(old_session), 0x40u);
    check_int_eq(mesh_control_durable_outbox_open_v1(&outbox, &config, NULL),
                 MESH_CONTROL_DURABLE_OUTBOX_OK);
    check_int_eq(mesh_control_durable_outbox_submit_v1(&outbox, &message, NULL),
                 MESH_CONTROL_DURABLE_OUTBOX_OK);
    check_int_eq(mesh_control_durable_outbox_activate_session_v1(
                     &outbox, message.target_node_id, old_session, 90u,
                     &session_generation, NULL),
                 MESH_CONTROL_DURABLE_OUTBOX_OK);
    check_int_eq(mesh_control_durable_outbox_claim_v1(
                     &outbox, message.target_node_id, old_session,
                     session_generation, 100u, 50u, &first),
                 MESH_CONTROL_DURABLE_OUTBOX_OK);
    check_int_eq(mesh_control_durable_outbox_claim_v1(
                     &outbox, message.target_node_id, old_session,
                     session_generation, 149u, 50u, &second),
                 MESH_CONTROL_DURABLE_OUTBOX_NOT_FOUND);
    check_int_eq(mesh_control_durable_outbox_claim_v1(
                     &outbox, message.target_node_id, old_session,
                     session_generation, 150u, 50u, &second),
                 MESH_CONTROL_DURABLE_OUTBOX_OK);
    check_uint_eq(second.lease_generation, first.lease_generation + 1u);
    check_int_eq(mesh_control_durable_outbox_ack_v1(
                     &outbox, message.target_node_id, message.message_id, old_session,
                     session_generation, first.lease_generation, 160u),
                 MESH_CONTROL_DURABLE_OUTBOX_FENCED);
    check_int_eq(mesh_control_durable_outbox_ack_v1(
                     &outbox, message.target_node_id, message.message_id, old_session,
                     session_generation, second.lease_generation, 160u),
                 MESH_CONTROL_DURABLE_OUTBOX_OK);
    mesh_control_durable_outbox_close_v1(&outbox);
    cleanup_store_path(directory, path);
  }

  it("requeues an in-flight claim during restart recovery") {
    mesh_control_durable_outbox_v1_t outbox;
    mesh_control_durable_outbox_config_v1_t config;
    mesh_control_durable_outbox_message_v1_t message;
    mesh_control_durable_outbox_view_v1_t view;
    uint8_t session[MESH_CONTROL_ID_SIZE];
    const uint8_t payload[] = "intent";
    char *directory = NULL;
    char *path = make_store_path(&directory);
    size_t recovered = 0u;
    uint64_t session_generation = 0u;

    check_not_null(path);
    configure(&config, path, 0x22u);
    make_message(&message, 0x33u, 2u, payload, sizeof(payload));
    fill_bytes(session, sizeof(session), 0x44u);
    check_int_eq(mesh_control_durable_outbox_open_v1(&outbox, &config, NULL),
                 MESH_CONTROL_DURABLE_OUTBOX_OK);
    check_int_eq(mesh_control_durable_outbox_submit_v1(&outbox, &message, NULL),
                 MESH_CONTROL_DURABLE_OUTBOX_OK);
    check_int_eq(mesh_control_durable_outbox_activate_session_v1(
                     &outbox, message.target_node_id, session, 90u,
                     &session_generation, NULL),
                 MESH_CONTROL_DURABLE_OUTBOX_OK);
    check_int_eq(mesh_control_durable_outbox_claim_v1(
                     &outbox, message.target_node_id, session,
                     session_generation, 100u, 500u, &view),
                 MESH_CONTROL_DURABLE_OUTBOX_OK);
    mesh_control_durable_outbox_close_v1(&outbox);

    check_int_eq(mesh_control_durable_outbox_open_v1(&outbox, &config, &recovered),
                 MESH_CONTROL_DURABLE_OUTBOX_OK);
    check_size_eq(recovered, 1u);
    check_int_eq(mesh_control_durable_outbox_get_v1(&outbox, message.message_id, &view),
                 MESH_CONTROL_DURABLE_OUTBOX_OK);
    check_int_eq(view.state, MESH_CONTROL_DURABLE_OUTBOX_PENDING);
    check_true(view.lease_generation > 0u);
    check_uint_eq(view.lease_expires_at_ms, 0u);
    mesh_control_durable_outbox_close_v1(&outbox);
    cleanup_store_path(directory, path);
  }

  it("durably requeues claims owned by an older online session") {
    mesh_control_durable_outbox_v1_t outbox;
    mesh_control_durable_outbox_config_v1_t config;
    mesh_control_durable_outbox_message_v1_t message;
    mesh_control_durable_outbox_view_v1_t old_claim;
    mesh_control_durable_outbox_view_v1_t new_claim;
    uint8_t old_session[MESH_CONTROL_ID_SIZE];
    uint8_t new_session[MESH_CONTROL_ID_SIZE];
    const uint8_t payload[] = "network-apply";
    char *directory = NULL;
    char *path = make_store_path(&directory);
    size_t released = 0u;
    uint64_t old_session_generation = 0u;
    uint64_t new_session_generation = 0u;

    check_not_null(path);
    configure(&config, path, 0x26u);
    make_message(&message, 0x35u, 4u, payload, sizeof(payload));
    fill_bytes(old_session, sizeof(old_session), 0x45u);
    fill_bytes(new_session, sizeof(new_session), 0x65u);
    check_int_eq(mesh_control_durable_outbox_open_v1(&outbox, &config, NULL),
                 MESH_CONTROL_DURABLE_OUTBOX_OK);
    check_int_eq(mesh_control_durable_outbox_submit_v1(&outbox, &message, NULL),
                 MESH_CONTROL_DURABLE_OUTBOX_OK);
    check_int_eq(mesh_control_durable_outbox_activate_session_v1(
                     &outbox, message.target_node_id, old_session, 90u,
                     &old_session_generation, NULL),
                 MESH_CONTROL_DURABLE_OUTBOX_OK);
    check_int_eq(mesh_control_durable_outbox_claim_v1(
                     &outbox, message.target_node_id, old_session,
                     old_session_generation, 100u, 500u,
                     &old_claim),
                 MESH_CONTROL_DURABLE_OUTBOX_OK);
    check_int_eq(mesh_control_durable_outbox_activate_session_v1(
                     &outbox, message.target_node_id, new_session, 105u,
                     &new_session_generation, &released),
                 MESH_CONTROL_DURABLE_OUTBOX_OK);
    check_size_eq(released, 1u);
    check_uint_eq(new_session_generation, old_session_generation + 1u);
    check_int_eq(mesh_control_durable_outbox_ack_v1(
                     &outbox, message.target_node_id, message.message_id,
                     old_session, old_session_generation,
                     old_claim.lease_generation, 110u),
                 MESH_CONTROL_DURABLE_OUTBOX_FENCED);
    check_int_eq(mesh_control_durable_outbox_claim_v1(
                     &outbox, message.target_node_id, new_session,
                     new_session_generation, 111u, 500u,
                     &new_claim),
                 MESH_CONTROL_DURABLE_OUTBOX_OK);
    check_uint_eq(new_claim.lease_generation, old_claim.lease_generation + 1u);
    check_int_eq(mesh_control_durable_outbox_deactivate_session_v1(
                     &outbox, message.target_node_id, new_session,
                     new_session_generation),
                 MESH_CONTROL_DURABLE_OUTBOX_OK);
    check_int_eq(mesh_control_durable_outbox_claim_v1(
                     &outbox, message.target_node_id, new_session,
                     new_session_generation, 112u, 500u, &new_claim),
                 MESH_CONTROL_DURABLE_OUTBOX_FENCED);
    check_int_eq(mesh_control_durable_outbox_activate_session_v1(
                     &outbox, message.target_node_id, new_session, 113u,
                     &new_session_generation, &released),
                 MESH_CONTROL_DURABLE_OUTBOX_OK);
    check_uint_eq(new_session_generation, old_session_generation + 2u);
    mesh_control_durable_outbox_close_v1(&outbox);
    cleanup_store_path(directory, path);
  }

  it("rejects conflicting ids capacity overflow and a second writer") {
    mesh_control_durable_outbox_v1_t first;
    mesh_control_durable_outbox_v1_t second;
    mesh_control_durable_outbox_config_v1_t config;
    mesh_control_durable_outbox_message_v1_t message;
    uint8_t payload[TEST_MAX_PAYLOAD];
    char *directory = NULL;
    char *path = make_store_path(&directory);

    check_not_null(path);
    memset(payload, 0x5a, sizeof(payload));
    configure(&config, path, 0x23u);
    config.byte_capacity = sizeof(payload);
    make_message(&message, 0x34u, 3u, payload, sizeof(payload));
    check_int_eq(mesh_control_durable_outbox_open_v1(&first, &config, NULL),
                 MESH_CONTROL_DURABLE_OUTBOX_OK);
    check_int_eq(mesh_control_durable_outbox_open_v1(&second, &config, NULL),
                 MESH_CONTROL_DURABLE_OUTBOX_LOCKED);
    check_int_eq(mesh_control_durable_outbox_submit_v1(&first, &message, NULL),
                 MESH_CONTROL_DURABLE_OUTBOX_OK);
    message.sequence++;
    check_int_eq(mesh_control_durable_outbox_submit_v1(&first, &message, NULL),
                 MESH_CONTROL_DURABLE_OUTBOX_CONFLICT);
    message.sequence++;
    fill_bytes(message.message_id, sizeof(message.message_id), 0x70u);
    check_int_eq(mesh_control_durable_outbox_submit_v1(&first, &message, NULL),
                 MESH_CONTROL_DURABLE_OUTBOX_RESOURCE_EXHAUSTED);
    mesh_control_durable_outbox_close_v1(&first);
    cleanup_store_path(directory, path);
  }

  it("fails closed when the authentication key does not match") {
    mesh_control_durable_outbox_v1_t outbox;
    mesh_control_durable_outbox_config_v1_t config;
    char *directory = NULL;
    char *path = make_store_path(&directory);

    check_not_null(path);
    configure(&config, path, 0x24u);
    check_int_eq(mesh_control_durable_outbox_open_v1(&outbox, &config, NULL),
                 MESH_CONTROL_DURABLE_OUTBOX_OK);
    mesh_control_durable_outbox_close_v1(&outbox);
    configure(&config, path, 0x25u);
    check_int_eq(mesh_control_durable_outbox_open_v1(&outbox, &config, NULL),
                 MESH_CONTROL_DURABLE_OUTBOX_AUTH_FAILED);
    cleanup_store_path(directory, path);
  }
}
