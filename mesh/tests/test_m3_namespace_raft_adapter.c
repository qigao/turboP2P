#include "m3_namespace_raft_adapter.h"

#include <tinytest.h>
#include <turbo_error.h>

#include <string.h>

enum {
  TEST_MAX_OBJECT_BYTES = 1024,
  TEST_MAX_CHUNKS = 4,
  TEST_MAX_MANIFEST_BYTES = 256,
  TEST_MAX_BUCKET_BYTES = 32,
  TEST_MAX_OBJECT_KEY_BYTES = 64,
};

typedef struct {
  size_t transaction_count;
  size_t commit_count;
} raft_test_io_t;

typedef struct {
  size_t calls;
  m3_namespace_lookup_result_t result;
  uint8_t manifest[TEST_MAX_MANIFEST_BYTES];
  size_t manifest_size;
  uint64_t applied_index;
  uint8_t linearizable;
} lookup_capture_t;

static int storage_begin(void *context) {
  ++((raft_test_io_t *)context)->transaction_count;
  return TURBO_OK;
}

static int storage_write_hard_state(void *context, tr_raft_term_t term,
                                    tr_raft_node_id_t voted_for) {
  (void)context;
  (void)term;
  (void)voted_for;
  return TURBO_OK;
}

static int storage_truncate(void *context, tr_raft_index_t from_index) {
  (void)context;
  (void)from_index;
  return TURBO_OK;
}

static int storage_append(void *context, const tr_raft_entry_t *entries,
                          size_t entry_count) {
  (void)context;
  return entries && entry_count != 0u ? TURBO_OK : TURBO_EINVAL;
}

static int storage_write_commit_index(void *context,
                                      tr_raft_index_t commit_index) {
  (void)context;
  (void)commit_index;
  return TURBO_OK;
}

static int storage_commit(void *context) {
  ++((raft_test_io_t *)context)->commit_count;
  return TURBO_OK;
}

static int storage_rollback(void *context) {
  (void)context;
  return TURBO_OK;
}

static int transport_enqueue(void *context,
                             const tr_raft_message_t *message) {
  (void)context;
  return message ? TURBO_OK : TURBO_EINVAL;
}

static void configure_service(
    tr_raft_service_config_t *config, raft_test_io_t *io,
    m3_namespace_raft_adapter_v1_t *adapter,
    const tr_raft_node_id_t *voters) {
  memset(config, 0, sizeof(*config));
  config->core.self_id = 1u;
  config->core.voters = voters;
  config->core.voter_count = 1u;
  config->core.heartbeat_ticks = 1u;
  config->core.election_min_ticks = 3u;
  config->core.election_max_ticks = 5u;
  config->core.initial_election_timeout_ticks = 3u;
  config->core.max_log_entries = 16u;
  config->storage.context = io;
  config->storage.begin = storage_begin;
  config->storage.write_hard_state = storage_write_hard_state;
  config->storage.truncate_log = storage_truncate;
  config->storage.append_log = storage_append;
  config->storage.write_commit_index = storage_write_commit_index;
  config->storage.commit = storage_commit;
  config->storage.rollback = storage_rollback;
  config->transport.context = io;
  config->transport.enqueue = transport_enqueue;
  config->state_machine = m3_namespace_raft_state_machine_v1(adapter);
}

static uint8_t *make_manifest(size_t *out_size) {
  m3_chunk_cid_v1_t chunk;
  m3_object_manifest_v1_t manifest;
  uint8_t *bytes = NULL;

  memset(&chunk, 0, sizeof(chunk));
  chunk.hash_algorithm = M3_CHUNK_STORE_HASH_ALGORITHM_SHA256;
  chunk.size = 4u;
  memset(chunk.digest, 0x31, sizeof(chunk.digest));
  memset(&manifest, 0, sizeof(manifest));
  manifest.version = M3_OBJECT_MANIFEST_VERSION;
  manifest.object_cid.hash_algorithm = M3_CHUNK_STORE_HASH_ALGORITHM_SHA256;
  manifest.object_cid.size = chunk.size;
  memset(manifest.object_cid.digest, 0x32,
         sizeof(manifest.object_cid.digest));
  manifest.chunks = &chunk;
  manifest.chunk_count = 1u;
  check_int_eq(m3_object_manifest_encode_v1(
                   &manifest, TEST_MAX_OBJECT_BYTES, TEST_MAX_CHUNKS, &bytes,
                   out_size),
               M3_OBJECT_MANIFEST_OK);
  check_not_null(bytes);
  return bytes;
}

static void capture_lookup(m3_namespace_lookup_result_t result,
                           const m3_namespace_lookup_response_v1_t *response,
                           void *user_data) {
  lookup_capture_t *capture = (lookup_capture_t *)user_data;

  ++capture->calls;
  capture->result = result;
  if (!response) {
    return;
  }
  check(response->manifest_size <= sizeof(capture->manifest));
  memcpy(capture->manifest, response->manifest_bytes, response->manifest_size);
  capture->manifest_size = response->manifest_size;
  capture->applied_index = response->applied_index;
  capture->linearizable = response->linearizable;
}

static void test_codec_is_canonical_and_bounded(void) {
  m3_namespace_raft_command_v1_t command;
  m3_namespace_raft_command_v1_t decoded;
  uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE];
  uint8_t bytes[TR_RAFT_MAX_ENTRY_BYTES];
  size_t size = 0u;

  memset(&command, 0, sizeof(command));
  memset(tenant_id, 7, sizeof(tenant_id));
  command.type = M3_NAMESPACE_RAFT_COMMAND_TOMBSTONE;
  memcpy(command.tenant_id, tenant_id, sizeof(tenant_id));
  command.bucket = (const uint8_t *)"bucket";
  command.bucket_size = 6u;
  command.object_key = (const uint8_t *)"object";
  command.object_key_size = 6u;
  check_int_eq(m3_namespace_raft_command_encode_v1(
                   &command, bytes, sizeof(bytes), &size),
               TURBO_OK);
  check_int_eq(m3_namespace_raft_command_decode_v1(bytes, size, &decoded),
               TURBO_OK);
  check_int_eq(decoded.type, M3_NAMESPACE_RAFT_COMMAND_TOMBSTONE);
  check_size_eq(decoded.bucket_size, command.bucket_size);
  check_size_eq(decoded.object_key_size, command.object_key_size);
  check_mem_eq(decoded.tenant_id, tenant_id, sizeof(tenant_id));

  bytes[0] ^= 1u;
  check_int_eq(m3_namespace_raft_command_decode_v1(bytes, size, &decoded),
               TURBO_EPROTO);
  bytes[0] ^= 1u;
  check_int_eq(m3_namespace_raft_command_decode_v1(bytes, size - 1u, &decoded),
               TURBO_EPROTO);
  command.type = M3_NAMESPACE_RAFT_COMMAND_PUT;
  check_int_eq(m3_namespace_raft_command_encode_v1(
                   &command, bytes, sizeof(bytes), &size),
               TURBO_EINVAL);
}

static void test_service_applies_and_reads_with_quorum_fence(void) {
  static const tr_raft_node_id_t voters[] = {1u};
  m3_namespace_local_store_v1_t store;
  m3_namespace_raft_adapter_v1_t *adapter = NULL;
  tr_raft_service_config_t config;
  tr_raft_service_t *service = NULL;
  tr_raft_tick_t tick = {3u, 4u};
  tr_raft_service_status_t status;
  tr_raft_operation_status_t receipt;
  m3_namespace_raft_command_v1_t command;
  m3_namespace_lookup_adapter_v1_t lookup;
  m3_namespace_lookup_request_v1_t request;
  lookup_capture_t capture;
  raft_test_io_t io;
  uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE];
  uint8_t *manifest;
  size_t manifest_size = 0u;
  size_t completed = 0u;

  memset(&store, 0, sizeof(store));
  memset(&io, 0, sizeof(io));
  memset(tenant_id, 9, sizeof(tenant_id));
  manifest = make_manifest(&manifest_size);
  check_int_eq(m3_namespace_local_store_init_v1(
                   &store, 4u, TEST_MAX_BUCKET_BYTES,
                   TEST_MAX_OBJECT_KEY_BYTES, TEST_MAX_MANIFEST_BYTES,
                   TEST_MAX_OBJECT_BYTES, TEST_MAX_CHUNKS),
               M3_NAMESPACE_LOCAL_OK);
  check_int_eq(m3_namespace_raft_adapter_create_v1(&store, 2u, &adapter),
               TURBO_OK);
  configure_service(&config, &io, adapter, voters);
  check_int_eq(tr_raft_service_create(&config, &service), TURBO_OK);
  check_int_eq(m3_namespace_raft_adapter_bind_service_v1(adapter, service),
               TURBO_OK);
  check_int_eq(tr_raft_service_tick(service, &tick), TURBO_OK);
  check_int_eq(tr_raft_service_status(service, &status), TURBO_OK);
  check_int_eq(status.core.role, TR_RAFT_LEADER);

  memset(&command, 0, sizeof(command));
  command.type = M3_NAMESPACE_RAFT_COMMAND_PUT;
  memcpy(command.tenant_id, tenant_id, sizeof(tenant_id));
  command.bucket = (const uint8_t *)"bucket";
  command.bucket_size = 6u;
  command.object_key = (const uint8_t *)"object";
  command.object_key_size = 6u;
  command.manifest_bytes = manifest;
  command.manifest_size = manifest_size;
  check_int_eq(m3_namespace_raft_propose_v1(adapter, 1u, &command, &receipt),
               TURBO_OK);
  check_int_eq(receipt.state, TR_RAFT_OPERATION_APPLIED);
  check_long_eq(receipt.index, 1u);

  memset(&request, 0, sizeof(request));
  memcpy(request.tenant_id, tenant_id, sizeof(tenant_id));
  request.bucket = command.bucket;
  request.bucket_size = command.bucket_size;
  request.object_key = command.object_key;
  request.object_key_size = command.object_key_size;
  request.require_linearizable = 1u;
  memset(&capture, 0, sizeof(capture));
  lookup = m3_namespace_raft_lookup_adapter_v1(adapter);
  check_int_eq(lookup.start(lookup.context, &request, capture_lookup, &capture),
               M3_NAMESPACE_LOOKUP_OK);
  check_size_eq(capture.calls, 0u);
  check_int_eq(m3_namespace_raft_adapter_poll_v1(adapter, &completed),
               TURBO_OK);
  check_size_eq(completed, 1u);
  check_size_eq(capture.calls, 1u);
  check_int_eq(capture.result, M3_NAMESPACE_LOOKUP_OK);
  check(capture.linearizable);
  check_long_eq(capture.applied_index, receipt.index);
  check_size_eq(capture.manifest_size, manifest_size);
  check_mem_eq(capture.manifest, manifest, manifest_size);

  command.type = M3_NAMESPACE_RAFT_COMMAND_TOMBSTONE;
  command.manifest_bytes = NULL;
  command.manifest_size = 0u;
  check_int_eq(m3_namespace_raft_propose_v1(adapter, 2u, &command, &receipt),
               TURBO_OK);
  check_int_eq(receipt.state, TR_RAFT_OPERATION_APPLIED);
  check_long_eq(receipt.index, 2u);
  memset(&capture, 0, sizeof(capture));
  check_int_eq(lookup.start(lookup.context, &request, capture_lookup, &capture),
               M3_NAMESPACE_LOOKUP_OK);
  check_int_eq(m3_namespace_raft_adapter_poll_v1(adapter, &completed),
               TURBO_OK);
  check_size_eq(capture.calls, 1u);
  check_int_eq(capture.result, M3_NAMESPACE_LOOKUP_NOT_FOUND);

  {
    tr_raft_entry_t stale_entry;
    tr_raft_state_machine_t state_machine =
        m3_namespace_raft_state_machine_v1(adapter);
    size_t encoded_size = 0u;

    memset(&stale_entry, 0, sizeof(stale_entry));
    stale_entry.index = receipt.index;
    check_int_eq(m3_namespace_raft_command_encode_v1(
                     &command, stale_entry.data, sizeof(stale_entry.data),
                     &encoded_size),
                 TURBO_OK);
    stale_entry.data_length = encoded_size;
    check_int_eq(state_machine.apply_batch(state_machine.context, &stale_entry,
                                           1u),
                 TURBO_EPROTO);
  }

  tr_raft_service_destroy(service);
  m3_namespace_raft_adapter_destroy_v1(adapter);
  m3_namespace_local_store_destroy_v1(&store);
  m3_object_manifest_bytes_free_v1(manifest);
}

spec("M3 TurboRaft namespace adapter") {
  it("uses one exact bounded canonical command codec") {
    test_codec_is_canonical_and_bounded();
  }
  it("applies metadata and completes reads only after quorum ReadIndex") {
    test_service_applies_and_reads_with_quorum_fence();
  }
}
