#include <tinytest.h>

#include "m3_namespace_raft_adapter.h"
#include "m3_object_manifest.h"

#include <turbo_error.h>
#include <turboraft/raft_sqlite_storage.h>
#include <turboraft/raft_wire_codec.h>

#include <stdlib.h>
#include <string.h>

/* Phase 2b-ii (wire): three-voter cluster where every raft message crosses a
 * serialization boundary via tr_raft_wire_codec before delivery, simulating a
 * process/network edge. Verifies quorum commit convergence under codec. */

#define CLUSTER_NODE_COUNT 3u

typedef struct {
  uint8_t *frame;
  size_t frame_size;
} wire_frame_t;

typedef struct {
  m3_namespace_local_store_v1_t store;
  tr_raft_sqlite_storage_t *storage;
  m3_namespace_raft_adapter_v1_t *adapter;
  tr_raft_service_t *service;
  wire_frame_t *inbox;
  size_t inbox_count;
  size_t inbox_capacity;
  uint8_t open;
} cluster_node_t;

typedef struct {
  cluster_node_t nodes[CLUSTER_NODE_COUNT];
  tr_raft_wire_codec_t *codec;
  tr_raft_wire_metadata_t metadata;
} cluster_t;

static const tr_raft_node_id_t VOTERS[] = {1u, 2u, 3u};
static const uint8_t TENANT_ID[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE] = {
    0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
    0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56};

static int inbox_push(cluster_node_t *node, const uint8_t *frame, size_t frame_size) {
  wire_frame_t *grown;

  if (node->inbox_count >= node->inbox_capacity) {
    size_t new_capacity = node->inbox_capacity == 0u ? 16u : node->inbox_capacity * 2u;
    grown = (wire_frame_t *)realloc(node->inbox, new_capacity * sizeof(*node->inbox));
    if (!grown)
      return TURBO_ENOMEM;
    node->inbox = grown;
    node->inbox_capacity = new_capacity;
  }
  node->inbox[node->inbox_count].frame = (uint8_t *)malloc(frame_size);
  if (!node->inbox[node->inbox_count].frame)
    return TURBO_ENOMEM;
  memcpy(node->inbox[node->inbox_count].frame, frame, frame_size);
  node->inbox[node->inbox_count].frame_size = frame_size;
  node->inbox_count++;
  return TURBO_OK;
}

static int cluster_enqueue(void *context, const tr_raft_message_t *message) {
  cluster_t *cluster = (cluster_t *)context;
  uint8_t frame[TR_RAFT_WIRE_MAX_FRAME_SIZE];
  size_t frame_size = 0u;
  size_t index;
  int result;

  if (!cluster || !message)
    return TURBO_EINVAL;
  index = (size_t)(message->to - 1u);
  if (index >= CLUSTER_NODE_COUNT)
    return TURBO_EINVAL;
  cluster->metadata.message_id++;
  result = tr_raft_wire_encode(cluster->codec, &cluster->metadata, message, frame, sizeof(frame),
                               &frame_size);
  if (result != TURBO_OK)
    return result;
  return inbox_push(&cluster->nodes[index], frame, frame_size);
}

static int make_manifest(uint8_t **out_bytes, size_t *out_size) {
  m3_object_manifest_v1_t manifest;

  memset(&manifest, 0, sizeof(manifest));
  manifest.version = M3_OBJECT_MANIFEST_VERSION;
  manifest.object_cid.hash_algorithm = M3_CHUNK_STORE_HASH_ALGORITHM_SHA256;
  manifest.object_cid.size = 0u;
  memset(manifest.object_cid.digest, 1u, sizeof(manifest.object_cid.digest));
  manifest.chunks = NULL;
  manifest.chunk_count = 0u;
  return m3_object_manifest_encode_v1(&manifest, UINT64_C(1) << 30, 4096u, out_bytes, out_size) ==
                 M3_OBJECT_MANIFEST_OK
             ? 0
             : -1;
}

static int node_open(cluster_t *cluster, size_t index, tr_raft_node_id_t self_id) {
  cluster_node_t *node = &cluster->nodes[index];
  tr_raft_sqlite_storage_config_t storage_config;
  tr_raft_sqlite_recovery_t recovery;
  tr_raft_storage_t storage_adapter;
  tr_raft_service_config_t service_config;
  tr_raft_transport_t transport;
  int result;

  memset(&node->store, 0, sizeof(node->store));
  result = m3_namespace_local_store_init_v1(&node->store, 64u, 128u, 1024u, 65536u,
                                            UINT64_C(1) << 30, 4096u);
  if (result != M3_NAMESPACE_LOCAL_OK)
    return TURBO_EINVAL;
  result = m3_namespace_raft_adapter_create_v1(&node->store, 64u, &node->adapter);
  if (result != TURBO_OK)
    return result;

  memset(&storage_config, 0, sizeof(storage_config));
  storage_config.path = ":memory:";
  storage_config.busy_timeout_ms = 1000;
  storage_config.create_if_missing = 1;
  storage_config.max_snapshot_bytes = 4u * 1024 * 1024;
  result = tr_raft_sqlite_storage_open(&storage_config, &node->storage);
  if (result != TURBO_OK)
    return result;
  memset(&storage_adapter, 0, sizeof(storage_adapter));
  result = tr_raft_sqlite_storage_bind(node->storage, &storage_adapter);
  if (result != TURBO_OK)
    return result;
  memset(&recovery, 0, sizeof(recovery));
  result = tr_raft_sqlite_storage_load(node->storage, &recovery);
  if (result != TURBO_OK)
    return result;

  memset(&service_config, 0, sizeof(service_config));
  service_config.core.self_id = self_id;
  service_config.core.voters = VOTERS;
  service_config.core.voter_count = CLUSTER_NODE_COUNT;
  service_config.core.heartbeat_ticks = 1u;
  service_config.core.election_min_ticks = 3u;
  service_config.core.election_max_ticks = 6u;
  service_config.core.initial_election_timeout_ticks = (uint32_t)(self_id + 2u);
  service_config.core.max_log_entries = 64u;
  service_config.core.initial_term = recovery.term;
  service_config.core.initial_vote = recovery.voted_for;
  service_config.core.initial_last_log_index = recovery.snapshot_index;
  service_config.core.initial_last_log_term = recovery.snapshot_term;
  service_config.core.initial_log_entries = recovery.entries;
  service_config.core.initial_log_entry_count = recovery.entry_count;
  service_config.core.initial_commit_index = recovery.commit_index;
  service_config.core.initial_applied_index = recovery.snapshot_index;
  service_config.storage = storage_adapter;
  memset(&transport, 0, sizeof(transport));
  transport.context = cluster;
  transport.enqueue = cluster_enqueue;
  service_config.transport = transport;
  service_config.state_machine = m3_namespace_raft_state_machine_v1(node->adapter);
  result = tr_raft_service_create(&service_config, &node->service);
  tr_raft_sqlite_recovery_destroy(&recovery);
  if (result != TURBO_OK)
    return result;
  result = m3_namespace_raft_adapter_bind_service_v1(node->adapter, node->service);
  if (result != TURBO_OK)
    return result;
  node->open = 1u;
  return TURBO_OK;
}

static void node_close(cluster_node_t *node) {
  if (node->service)
    tr_raft_service_destroy(node->service);
  if (node->storage)
    (void)tr_raft_sqlite_storage_close(node->storage);
  if (node->adapter)
    m3_namespace_raft_adapter_destroy_v1(node->adapter);
  if (node->store.open)
    m3_namespace_local_store_destroy_v1(&node->store);
  for (size_t i = 0u; i < node->inbox_count; i++)
    free(node->inbox[i].frame);
  free(node->inbox);
  memset(node, 0, sizeof(*node));
}

static void cluster_drive(cluster_t *cluster, size_t rounds) {
  tr_raft_tick_t tick;

  memset(&tick, 0, sizeof(tick));
  tick.elapsed_ticks = 1u;
  tick.next_election_timeout_ticks = 4u;
  for (size_t round = 0u; round < rounds; round++) {
    for (size_t i = 0u; i < CLUSTER_NODE_COUNT; i++) {
      (void)tr_raft_service_tick(cluster->nodes[i].service, &tick);
      (void)tr_raft_service_poll(cluster->nodes[i].service);
    }
    for (size_t i = 0u; i < CLUSTER_NODE_COUNT; i++) {
      cluster_node_t *node = &cluster->nodes[i];
      while (node->inbox_count > 0u) {
        tr_raft_wire_metadata_t metadata;
        tr_raft_message_t message;
        wire_frame_t head = node->inbox[0];
        size_t j;

        for (j = 1u; j < node->inbox_count; j++) {
          node->inbox[j - 1u] = node->inbox[j];
        }
        node->inbox_count--;
        memset(&message, 0, sizeof(message));
        if (tr_raft_wire_decode(cluster->codec, head.frame, head.frame_size, &metadata, &message) ==
            TURBO_OK) {
          (void)tr_raft_service_step(node->service, &message);
          (void)tr_raft_service_poll(node->service);
        }
        free(head.frame);
      }
    }
  }
}

typedef struct {
  int completed;
  int found;
} cluster_capture_t;

static void cluster_capture_lookup(m3_namespace_lookup_result_t result,
                                   const m3_namespace_lookup_response_v1_t *response,
                                   void *user_data) {
  cluster_capture_t *capture = (cluster_capture_t *)user_data;

  capture->completed = 1;
  capture->found = result == M3_NAMESPACE_LOOKUP_OK && response != NULL;
}

static int store_has_key(m3_namespace_local_store_v1_t *store, const char *bucket,
                         const char *object) {
  m3_namespace_lookup_request_v1_t request;
  m3_namespace_lookup_adapter_v1_t adapter;
  cluster_capture_t capture;

  memset(&capture, 0, sizeof(capture));
  memset(&request, 0, sizeof(request));
  memcpy(request.tenant_id, TENANT_ID, sizeof(request.tenant_id));
  request.bucket = (const uint8_t *)bucket;
  request.bucket_size = strlen(bucket);
  request.object_key = (const uint8_t *)object;
  request.object_key_size = strlen(object);
  request.require_linearizable = 1u;
  adapter = m3_namespace_local_store_adapter_v1(store);
  if (adapter.start(adapter.context, &request, cluster_capture_lookup, &capture) !=
      M3_NAMESPACE_LOOKUP_OK) {
    return 0;
  }
  return capture.completed != 0 && capture.found != 0;
}

static void test_wire_codec_cluster_commits(void) {
  cluster_t cluster;
  uint8_t *manifest = NULL;
  size_t manifest_size = 0u;
  m3_namespace_raft_command_v1_t command;
  int committed = 0;

  memset(&cluster, 0, sizeof(cluster));
  memset(&cluster.metadata.cluster_id, 0x5a, sizeof(cluster.metadata.cluster_id));
  check_int_eq(TURBO_OK, tr_raft_wire_codec_create(&cluster.codec));
  check_int_eq(TURBO_OK, node_open(&cluster, 0u, 1u));
  check_int_eq(TURBO_OK, node_open(&cluster, 1u, 2u));
  check_int_eq(TURBO_OK, node_open(&cluster, 2u, 3u));
  check_int_eq(0, make_manifest(&manifest, &manifest_size));

  for (size_t attempt = 0u; attempt < 300u && !committed; attempt++) {
    cluster_drive(&cluster, 4u);
    for (size_t i = 0u; i < CLUSTER_NODE_COUNT && !committed; i++) {
      tr_raft_operation_status_t receipt;
      uint64_t before = cluster.nodes[i].store.applied_index;
      uint64_t command_id = (uint64_t)(attempt * 100u + i + 1u);

      memset(&command, 0, sizeof(command));
      command.type = M3_NAMESPACE_RAFT_COMMAND_PUT;
      memcpy(command.tenant_id, TENANT_ID, sizeof(command.tenant_id));
      command.bucket = (const uint8_t *)"bucket";
      command.bucket_size = 6u;
      command.object_key = (const uint8_t *)"key";
      command.object_key_size = 3u;
      command.manifest_bytes = manifest;
      command.manifest_size = manifest_size;
      if (m3_namespace_raft_propose_v1(cluster.nodes[i].adapter, command_id, &command, &receipt) ==
          TURBO_OK) {
        for (size_t wait = 0u; wait < 300u; wait++) {
          cluster_drive(&cluster, 1u);
          if (cluster.nodes[0].store.applied_index > before &&
              cluster.nodes[1].store.applied_index > before &&
              cluster.nodes[2].store.applied_index > before) {
            committed = 1;
            break;
          }
        }
      }
    }
  }
  check_int_eq(1, committed);
  check_int_eq(1, store_has_key(&cluster.nodes[0].store, "bucket", "key"));
  check_int_eq(1, store_has_key(&cluster.nodes[1].store, "bucket", "key"));
  check_int_eq(1, store_has_key(&cluster.nodes[2].store, "bucket", "key"));

  m3_object_manifest_bytes_free_v1(manifest);
  for (size_t i = 0u; i < CLUSTER_NODE_COUNT; i++) {
    node_close(&cluster.nodes[i]);
  }
  tr_raft_wire_codec_destroy(cluster.codec);
}

spec("m3 raft wire codec") {
  describe("three-voter cluster over wire codec transport") {
    it("commits and converges across the serialization boundary") {
      test_wire_codec_cluster_commits();
    }
  }
}
