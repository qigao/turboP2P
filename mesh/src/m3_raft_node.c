#include "m3_raft_node.h"

#include "m3_namespace_local_store.h"

#include <CoroNet/turbo_coro_context.h>
#include <platform.h>
#include <turbo_error.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Phase 2b-ii step 2/3/4: real CoroNet TLS transport node.
 * Assembles the metadata stack (m3_gateway_raft) with a
 * tr_raft_coronet_peer_service so proposals and replication flow between
 * processes over verified mTLS sessions. */

#define M3_RAFT_NODE_STEP_INTERVAL_MS 10u
#define M3_RAFT_NODE_SOCKET_TIMEOUT_MS 5000u
/* Raft ticks must advance in real time, not at event-loop speed; otherwise a
 * peer that is briefly unreachable fills the bounded outbound queue and the
 * raft service faults on ENOSPC (see M3_RAFT_DEPLOYMENT.md risk section). */
#define M3_RAFT_NODE_RAFT_POLL_INTERVAL_MS 10u
#define M3_RAFT_NODE_OUTBOUND_QUEUE_CAPACITY 2048u
#define M3_RAFT_NODE_INITIAL_RETRY_MS 100u
#define M3_RAFT_NODE_MAX_RETRY_MS 2000u

struct m3_raft_node {
  m3_raft_node_config_t config;
  tr_raft_cluster_id_t cluster_id;
  tr_raft_handshake_config_t handshake;
  coro_context_t *ctx;
  tr_raft_coronet_peer_service_t *peer_service;
  tr_raft_coronet_peer_service_step_result_t step_result;
  tr_raft_transport_t transport;
  m3_namespace_local_store_v1_t store;
  m3_gateway_raft_v1_t *raft;
  coro_socket_t *listener;
  uint64_t last_raft_poll_ms;
  uint64_t dropped_messages;
  int stop;
  int failed;
};

static void node_fill_cluster_id(tr_raft_cluster_id_t *out) {
  static const uint8_t k_m3_cluster_id[sizeof(tr_raft_cluster_id_t)] = {
      0x4d, 0x33, 0x2d, 0x72, 0x61, 0x66, 0x74, 0x2d,
      0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x01};
  memcpy(out->bytes, k_m3_cluster_id, sizeof(out->bytes));
}

static int node_on_message(void *context, const tr_raft_message_t *message) {
  m3_raft_node_t *node = (m3_raft_node_t *)context;
  tr_raft_service_t *service;

  if (node == NULL || message == NULL) {
    return TURBO_EINVAL;
  }
  service = m3_gateway_raft_service_v1(node->raft);
  if (service == NULL) {
    return TURBO_EPROTO;
  }
  return tr_raft_service_step(service, message);
}

static void node_on_inbound_result(void *context, int result,
                                   tr_raft_node_id_t peer_node_id) {
  m3_raft_node_t *node = (m3_raft_node_t *)context;
  (void)node;
  if (result != TURBO_OK) {
    fprintf(stderr, "m3 raft node: inbound admission failed peer=%llu rc=%d\n",
            (unsigned long long)peer_node_id, result);
  }
}

static int node_is_retryable(void *context, int error_code) {
  (void)context;
  return error_code == TURBO_EIO || error_code == TURBO_ECONNREFUSED ||
         error_code == TURBO_ENETUNREACH || error_code == TURBO_ETIMEDOUT;
}

static int node_resolve_endpoint(void *context, tr_raft_node_id_t peer_node_id,
                                 tr_raft_coronet_endpoint_t *out_endpoint) {
  m3_raft_node_t *node = (m3_raft_node_t *)context;

  if (node == NULL || out_endpoint == NULL) {
    return TURBO_EINVAL;
  }
  for (size_t i = 0u; i < node->config.peer_count; ++i) {
    const m3_raft_node_peer_config_t *peer = &node->config.peers[i];
    if (peer->node_id == peer_node_id) {
      memcpy(out_endpoint->connect_host, peer->connect_host,
             sizeof(out_endpoint->connect_host));
      memcpy(out_endpoint->request_host, peer->request_host,
             sizeof(out_endpoint->request_host));
      out_endpoint->port = peer->port;
      return TURBO_OK;
    }
  }
  return TURBO_EPROTO;
}

static void node_stepper(coro_t *co, void *arg) {
  m3_raft_node_t *node = (m3_raft_node_t *)arg;
  (void)co;

  while (!node->stop) {
    int rc = tr_raft_coronet_peer_service_step(node->peer_service,
                                               turbo_monotonic_ms(),
                                               &node->step_result);
    if (rc != TURBO_OK && rc != TURBO_EBUSY && node->failed == 0) {
      node->failed = 1;
      fprintf(stderr, "m3 raft node: peer service step failed rc=%d\n", rc);
    }
    coro_sleep(node->ctx, M3_RAFT_NODE_STEP_INTERVAL_MS);
  }
}

static void node_config_release(m3_raft_node_t *node);

static int node_config_copy(m3_raft_node_t *node,
                            const m3_raft_node_config_t *config) {
  node->config = *config;
  node->config.listen_host = config->listen_host ? strdup(config->listen_host) : NULL;
  node->config.sqlite_path = strdup(config->sqlite_path);
  node->config.cert_file = strdup(config->cert_file);
  node->config.key_file = strdup(config->key_file);
  node->config.ca_file = strdup(config->ca_file);
  node->config.voters = NULL;
  node->config.peers = NULL;
  if ((config->listen_host && node->config.listen_host == NULL) ||
      node->config.sqlite_path == NULL || node->config.cert_file == NULL ||
      node->config.key_file == NULL || node->config.ca_file == NULL) {
    node_config_release(node);
    return TURBO_ENOMEM;
  }
  if (config->voters && config->voter_count > 0u) {
    node->config.voters = (tr_raft_node_id_t *)calloc(config->voter_count,
                                                       sizeof(tr_raft_node_id_t));
    if (!node->config.voters) {
      node_config_release(node);
      return TURBO_ENOMEM;
    }
    memcpy((void *)node->config.voters, config->voters,
           config->voter_count * sizeof(tr_raft_node_id_t));
  }
  if (config->peers && config->peer_count > 0u) {
    node->config.peers = (m3_raft_node_peer_config_t *)calloc(
        config->peer_count, sizeof(m3_raft_node_peer_config_t));
    if (!node->config.peers) {
      node_config_release(node);
      return TURBO_ENOMEM;
    }
    memcpy((void *)node->config.peers, config->peers,
           config->peer_count * sizeof(m3_raft_node_peer_config_t));
  }
  return TURBO_OK;
}

static void node_config_release(m3_raft_node_t *node) {
  free((void *)node->config.listen_host);
  free((void *)node->config.sqlite_path);
  free((void *)node->config.cert_file);
  free((void *)node->config.key_file);
  free((void *)node->config.ca_file);
  free((void *)node->config.voters);
  free((void *)node->config.peers);
}

static int node_config_valid(const m3_raft_node_config_t *config) {
  if (!config || config->node_id == 0u || !config->listen_host ||
      config->listen_host[0] == '\0' || config->listen_port <= 0 ||
      config->listen_port > 65535 || !config->sqlite_path ||
      config->sqlite_path[0] == '\0' || !config->cert_file ||
      config->cert_file[0] == '\0' || !config->key_file ||
      config->key_file[0] == '\0' || !config->ca_file ||
      config->ca_file[0] == '\0' || !config->voters ||
      config->voter_count == 0u || config->max_snapshot_bytes == 0u ||
      config->max_pending_reads == 0u) {
    return 0;
  }
  if (config->peer_count > M3_RAFT_NODE_MAX_PEERS ||
      (config->voter_count > 1u && config->peer_count == 0u)) {
    return 0;
  }
  for (size_t i = 0u; i < config->peer_count; ++i) {
    const m3_raft_node_peer_config_t *peer = &config->peers[i];
    if (peer->node_id == 0u || peer->node_id == config->node_id ||
        peer->connect_host[0] == '\0' || peer->request_host[0] == '\0' ||
        peer->port <= 0 || peer->port > 65535 ||
        peer->certificate_sha256[0] == '\0') {
      return 0;
    }
  }
  return 1;
}

static void node_fill_handshake(m3_raft_node_t *node) {
  tr_raft_handshake_config_t *config = &node->handshake;

  memset(config, 0, sizeof(*config));
  node->cluster_id = node->config.cluster_id ? *node->config.cluster_id
                                             : (tr_raft_cluster_id_t){0};
  if (node->config.cluster_id == NULL) {
    node_fill_cluster_id(&node->cluster_id);
  }
  config->cluster_id = node->cluster_id;
  config->local_node_id = node->config.node_id;
  memset(&config->process_incarnation, 0x33, sizeof(config->process_incarnation));
  config->process_incarnation.bytes[0] = (uint8_t)node->config.node_id;
  config->config_epoch = 1u;
  config->feature_bits = TR_RAFT_HANDSHAKE_FEATURE_CURRENT;
  config->wire_major_min = TR_RAFT_HANDSHAKE_WIRE_MAJOR;
  config->wire_major_max = TR_RAFT_HANDSHAKE_WIRE_MAJOR;
  config->wire_minor_min = TR_RAFT_HANDSHAKE_WIRE_MINOR;
  config->wire_minor_max = TR_RAFT_HANDSHAKE_WIRE_MINOR;
  config->max_frame_size = TR_RAFT_HANDSHAKE_MIN_FRAME_SIZE;
  config->max_snapshot_chunk_size = TR_RAFT_HANDSHAKE_MIN_SNAPSHOT_CHUNK_SIZE;
}

static int node_build_peer_ids(m3_raft_node_t *node,
                               tr_raft_node_id_t *out_ids) {
  for (size_t i = 0u; i < node->config.peer_count; ++i) {
    out_ids[i] = node->config.peers[i].node_id;
  }
  return TURBO_OK;
}

static int node_create_peer_service(m3_raft_node_t *node) {
  tr_raft_coronet_peer_service_config_t config;
  tr_raft_coronet_identity_entry_t identities[M3_RAFT_NODE_MAX_PEERS];
  tr_raft_node_id_t peer_ids[M3_RAFT_NODE_MAX_PEERS];

  memset(&config, 0, sizeof(config));
  memset(identities, 0, sizeof(identities));
  memset(peer_ids, 0, sizeof(peer_ids));
  if (node_build_peer_ids(node, peer_ids) != TURBO_OK) {
    return TURBO_EPROTO;
  }
  for (size_t i = 0u; i < node->config.peer_count; ++i) {
    memcpy(identities[i].certificate_sha256,
           node->config.peers[i].certificate_sha256,
           sizeof(identities[i].certificate_sha256));
    identities[i].node_id = node->config.peers[i].node_id;
  }
  config.context = node->ctx;
  config.manager.cluster_id = node->cluster_id;
  config.manager.local_node_id = node->config.node_id;
  config.manager.peer_node_ids = peer_ids;
  config.manager.peer_count = node->config.peer_count;
  config.identity_entries = identities;
  config.identity_entry_count = node->config.peer_count;
  config.outbound_queue_capacity = M3_RAFT_NODE_OUTBOUND_QUEUE_CAPACITY;
  config.admit_owned_socket = tr_raft_coronet_peer_manager_admit_owned_socket;
  config.connect_outbound = tr_raft_coronet_peer_manager_connect_outbound;
  return tr_raft_coronet_peer_service_create(&config, &node->peer_service);
}

static int node_configure_inbound(m3_raft_node_t *node) {
  tr_raft_coronet_inbound_service_config_t config;

  memset(&config, 0, sizeof(config));
  config.admission.handshake.handshake = &node->handshake;
  config.admission.handshake.timeout_ms = M3_RAFT_NODE_SOCKET_TIMEOUT_MS;
  config.admission.direction = TR_RAFT_CORONET_CONNECTION_INBOUND;
  config.admission.first_outbound_message_id = 1u;
  config.admission.peer_idle_timeout_ms = M3_RAFT_NODE_SOCKET_TIMEOUT_MS;
  config.admission.on_message = node_on_message;
  config.admission.message_context = node;
  config.on_result = node_on_inbound_result;
  config.result_context = node;
  return tr_raft_coronet_peer_service_configure_inbound(node->peer_service,
                                                        &config);
}

static int node_start_listener(m3_raft_node_t *node) {
  turbo_tls_server_config_t tls;

  memset(&tls, 0, sizeof(tls));
  tls.size = sizeof(tls);
  tls.cert_file = node->config.cert_file;
  tls.key_file = node->config.key_file;
  tls.ca_file = node->config.ca_file;
  tls.client_auth = TURBO_TLS_CLIENT_AUTH_REQUIRED;

  node->listener = coro_socket_create(node->ctx, CORO_SOCKET_TLS);
  if (!node->listener) {
    return TURBO_ENOMEM;
  }
  if (coro_socket_set_tls_server_config(node->listener, &tls) != 0 ||
      coro_socket_listen_on(node->listener, node->config.listen_host,
                            node->config.listen_port,
                            tr_raft_coronet_peer_service_handle_inbound,
                            node->peer_service) != 0) {
    coro_socket_destroy(node->listener);
    node->listener = NULL;
    return TURBO_EIO;
  }
  return TURBO_OK;
}

static int node_add_outbound(m3_raft_node_t *node) {
  for (size_t i = 0u; i < node->config.peer_count; ++i) {
    const m3_raft_node_peer_config_t *peer = &node->config.peers[i];
    tr_raft_coronet_dial_scheduler_config_t config;

    /* Deterministic direction: the smaller node id dials outbound. */
    if (peer->node_id < node->config.node_id) {
      continue;
    }
    memset(&config, 0, sizeof(config));
    config.outbound.context = node->ctx;
    config.outbound.connect_timeout_ms = M3_RAFT_NODE_SOCKET_TIMEOUT_MS;
    config.outbound.tls.ca_file = node->config.ca_file;
    config.outbound.tls.cert_file = node->config.cert_file;
    config.outbound.tls.key_file = node->config.key_file;
    config.outbound.tls.verify_peer = 1;
    config.outbound.admission.handshake.handshake = &node->handshake;
    config.outbound.admission.handshake.timeout_ms =
        M3_RAFT_NODE_SOCKET_TIMEOUT_MS;
    config.outbound.admission.direction =
        TR_RAFT_CORONET_CONNECTION_OUTBOUND;
    config.outbound.admission.expected_peer_node_id = peer->node_id;
    config.outbound.admission.first_outbound_message_id = 1u;
    config.outbound.admission.peer_idle_timeout_ms =
        M3_RAFT_NODE_SOCKET_TIMEOUT_MS;
    config.outbound.admission.on_message = node_on_message;
    config.outbound.admission.message_context = node;
    config.resolve_endpoint = node_resolve_endpoint;
    config.resolve_context = node;
    config.is_retryable = node_is_retryable;
    config.initial_retry_delay_ms = M3_RAFT_NODE_INITIAL_RETRY_MS;
    config.max_retry_delay_ms = M3_RAFT_NODE_MAX_RETRY_MS;
    config.max_attempts = UINT32_MAX; /* keep reconnecting */
    {
      int result = tr_raft_coronet_peer_service_add_outbound(node->peer_service,
                                                             &config);
      if (result != TURBO_OK) {
        return result;
      }
    }
  }
  return TURBO_OK;
}

/* Raft transport enqueue wrapper. The peer service buffers up to the bounded
 * queue capacity per peer; once full it returns ENOSPC. Faulting the raft
 * service on that (the default turboraft behavior) would kill a healthy node
 * whenever a peer stays unreachable past the buffer window, which is wrong for
 * a deployment that must tolerate peer crashes/restarts. Raft is designed for
 * lossy transports: dropped heartbeats/append/vote messages are retransmitted
 * by the sender, so returning OK after dropping is safe and keeps the service
 * running. The bounded queue still caps memory; the drop counter exposes the
 * behaviour for observability. */
static int node_transport_enqueue(void *context, const tr_raft_message_t *message) {
  m3_raft_node_t *node = (m3_raft_node_t *)context;
  int result;

  if (node == NULL || node->peer_service == NULL || message == NULL) {
    return TURBO_EINVAL;
  }
  result = tr_raft_coronet_peer_service_enqueue(node->peer_service, message);
  if (result == TURBO_ENOSPC) {
    ++node->dropped_messages;
    return TURBO_OK;
  }
  return result;
}

static int node_open_raft(m3_raft_node_t *node) {
  m3_gateway_raft_config_v1_t config;

  memset(&node->transport, 0, sizeof(node->transport));
  node->transport.context = node;
  node->transport.enqueue = node_transport_enqueue;

  memset(&config, 0, sizeof(config));
  config.sqlite_path = node->config.sqlite_path;
  config.self_id = node->config.node_id;
  config.voters = node->config.voters;
  config.voter_count = node->config.voter_count;
  config.max_snapshot_bytes = node->config.max_snapshot_bytes;
  config.max_pending_reads = node->config.max_pending_reads;
  config.transport = &node->transport;
  return m3_gateway_raft_open_v1(&config, &node->store, &node->raft);
}

int m3_raft_node_create(const m3_raft_node_config_t *config,
                        m3_raft_node_t **out_node) {
  m3_raft_node_t *node;
  int result;

  if (out_node == NULL) {
    return TURBO_EINVAL;
  }
  *out_node = NULL;
  if (!node_config_valid(config)) {
    return TURBO_EINVAL;
  }
  node = (m3_raft_node_t *)calloc(1u, sizeof(*node));
  if (!node) {
    return TURBO_ENOMEM;
  }
  result = node_config_copy(node, config);
  if (result != TURBO_OK) {
    node_config_release(node);
    free(node);
    return result;
  }
  node_fill_handshake(node);

  node->ctx = coro_context_create(NULL);
  if (!node->ctx) {
    node_config_release(node);
    free(node);
    return TURBO_ENOMEM;
  }
  memset(&node->store, 0, sizeof(node->store));
  if (m3_namespace_local_store_init_v1(&node->store, 64u, 128u, 1024u, 65536u,
                                       UINT64_C(1) << 30, 4096u) !=
      M3_NAMESPACE_LOCAL_OK) {
    result = TURBO_ENOMEM;
    goto fail;
  }
  result = node_create_peer_service(node);
  if (result != TURBO_OK) {
    goto fail;
  }
  result = node_configure_inbound(node);
  if (result != TURBO_OK) {
    goto fail;
  }
  result = node_start_listener(node);
  if (result != TURBO_OK) {
    goto fail;
  }
  result = node_add_outbound(node);
  if (result != TURBO_OK) {
    goto fail;
  }
  result = node_open_raft(node);
  if (result != TURBO_OK) {
    goto fail;
  }
  result = coro_context_spawn(node->ctx, node_stepper, node);
  if (result != TURBO_OK) {
    goto fail;
  }
  *out_node = node;
  return TURBO_OK;

fail:
  m3_raft_node_destroy(node);
  return result;
}

int m3_raft_node_poll(m3_raft_node_t *node) {
  size_t completed = 0u;
  uint64_t now;

  if (!node || !node->raft) {
    return TURBO_EINVAL;
  }
  for (int i = 0; i < 8; ++i) {
    coro_context_run(node->ctx, TURBO_RUN_NOWAIT);
  }
  now = turbo_monotonic_ms();
  if (now - node->last_raft_poll_ms < M3_RAFT_NODE_RAFT_POLL_INTERVAL_MS) {
    return TURBO_OK;
  }
  node->last_raft_poll_ms = now;
  return m3_gateway_raft_poll_v1(node->raft, &completed);
}

void m3_raft_node_run_until(m3_raft_node_t *node, uint64_t timeout_ms,
                            int (*done)(void *ctx, m3_raft_node_t *node),
                            void *ctx) {
  uint64_t deadline;

  if (!node) {
    return;
  }
  deadline = turbo_monotonic_ms() + timeout_ms;
  while (turbo_monotonic_ms() < deadline) {
    if (done && done(ctx, node)) {
      return;
    }
    if (m3_raft_node_poll(node) != TURBO_OK) {
      return;
    }
  }
}

static uint64_t g_node_command_sequence = 0u;

int m3_raft_node_propose_put(m3_raft_node_t *node,
                             const uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE],
                             const char *bucket, const char *object,
                             const uint8_t *manifest_bytes, size_t manifest_size) {
  m3_namespace_raft_command_v1_t command;
  tr_raft_operation_status_t receipt;

  if (!node || !node->raft || !tenant_id || !bucket || !object ||
      !manifest_bytes || manifest_size == 0u) {
    return TURBO_EINVAL;
  }
  memset(&command, 0, sizeof(command));
  command.type = M3_NAMESPACE_RAFT_COMMAND_PUT;
  memcpy(command.tenant_id, tenant_id, sizeof(command.tenant_id));
  command.bucket = (const uint8_t *)bucket;
  command.bucket_size = strlen(bucket);
  command.object_key = (const uint8_t *)object;
  command.object_key_size = strlen(object);
  command.manifest_bytes = manifest_bytes;
  command.manifest_size = manifest_size;
  return m3_gateway_raft_propose_v1(node->raft, ++g_node_command_sequence,
                                    &command, &receipt);
}

int m3_raft_node_propose_update_placement(
    m3_raft_node_t *node,
    const uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE],
    const char *bucket, const char *object, const uint8_t *manifest_bytes,
    size_t manifest_size) {
  m3_namespace_raft_command_v1_t command;
  tr_raft_operation_status_t receipt;

  if (!node || !node->raft || !tenant_id || !bucket || !object ||
      !manifest_bytes || manifest_size == 0u) {
    return TURBO_EINVAL;
  }
  memset(&command, 0, sizeof(command));
  command.type = M3_NAMESPACE_RAFT_COMMAND_UPDATE_PLACEMENT;
  memcpy(command.tenant_id, tenant_id, sizeof(command.tenant_id));
  command.bucket = (const uint8_t *)bucket;
  command.bucket_size = strlen(bucket);
  command.object_key = (const uint8_t *)object;
  command.object_key_size = strlen(object);
  command.manifest_bytes = manifest_bytes;
  command.manifest_size = manifest_size;
  return m3_gateway_raft_propose_v1(node->raft, ++g_node_command_sequence,
                                    &command, &receipt);
}

int m3_raft_node_propose_tombstone(m3_raft_node_t *node,
                                   const uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE],
                                   const char *bucket, const char *object) {
  m3_namespace_raft_command_v1_t command;
  tr_raft_operation_status_t receipt;

  if (!node || !node->raft || !tenant_id || !bucket || !object) {
    return TURBO_EINVAL;
  }
  memset(&command, 0, sizeof(command));
  command.type = M3_NAMESPACE_RAFT_COMMAND_TOMBSTONE;
  memcpy(command.tenant_id, tenant_id, sizeof(command.tenant_id));
  command.bucket = (const uint8_t *)bucket;
  command.bucket_size = strlen(bucket);
  command.object_key = (const uint8_t *)object;
  command.object_key_size = strlen(object);
  return m3_gateway_raft_propose_v1(node->raft, ++g_node_command_sequence,
                                    &command, &receipt);
}

uint64_t m3_raft_node_applied_index(const m3_raft_node_t *node) {
  return node ? m3_gateway_raft_applied_index_v1(node->raft) : 0u;
}

int m3_raft_node_status(const m3_raft_node_t *node, m3_raft_node_status_t *out) {
  tr_raft_coronet_peer_service_status_t st;
  tr_raft_service_status_t raft_st;

  if (!node || !out) {
    return TURBO_EINVAL;
  }
  memset(out, 0, sizeof(*out));
  (void)m3_raft_node_is_leader((m3_raft_node_t *)node, &out->leader);
  out->applied_index = m3_raft_node_applied_index(node);
  if (node->peer_service) {
    memset(&st, 0, sizeof(st));
    if (tr_raft_coronet_peer_service_get_status(node->peer_service, &st) ==
        TURBO_OK) {
      out->connected_peers = st.active_reader_count;
      out->queued_messages = st.queued_message_count;
      out->last_pump_error = st.last_pump_error;
    }
  }
  out->dropped_messages = node->dropped_messages;
  if (node->raft) {
    memset(&raft_st, 0, sizeof(raft_st));
    if (m3_gateway_raft_service_status_v1(node->raft, &raft_st) == TURBO_OK) {
      out->raft_faulted = raft_st.faulted;
      out->raft_fault_cause = raft_st.cause;
      out->raft_stage = (int)raft_st.runtime.stage;
    }
  }
  return TURBO_OK;
}

int m3_raft_node_is_leader(const m3_raft_node_t *node, int *out_leader) {
  tr_raft_role_t role;

  if (!node || !out_leader) {
    return TURBO_EINVAL;
  }
  {
    int result = m3_gateway_raft_role_v1(node->raft, &role);
    if (result != TURBO_OK) {
      return result;
    }
  }
  *out_leader = role == TR_RAFT_LEADER ? 1 : 0;
  return TURBO_OK;
}

int m3_raft_node_leader(const m3_raft_node_t *node, tr_raft_node_id_t *out_leader_id) {
  if (!node || !out_leader_id) {
    return TURBO_EINVAL;
  }
  return m3_gateway_raft_leader_v1(node->raft, out_leader_id);
}

m3_gateway_raft_v1_t *m3_raft_node_gateway(const m3_raft_node_t *node) {
  return node ? node->raft : NULL;
}

int m3_raft_node_disconnect_peer(m3_raft_node_t *node, tr_raft_node_id_t peer_node_id) {
  if (node == NULL || node->peer_service == NULL || peer_node_id == 0u) {
    return TURBO_EINVAL;
  }
  return tr_raft_coronet_peer_service_disconnect_peer(node->peer_service, peer_node_id,
                                                      turbo_monotonic_ms());
}

typedef struct {
  int completed;
  int found;
} node_lookup_capture_t;

typedef struct m3_raft_node_lookup_s {
  m3_namespace_lookup_adapter_v1_t lookup;
  node_lookup_capture_t capture;
} m3_raft_node_lookup_t;

static void node_lookup_cb(m3_namespace_lookup_result_t result,
                           const m3_namespace_lookup_response_v1_t *response,
                           void *user_data) {
  node_lookup_capture_t *capture = (node_lookup_capture_t *)user_data;
  capture->completed = 1;
  capture->found = result == M3_NAMESPACE_LOOKUP_OK && response != NULL;
}

static int node_lookup_fill(m3_raft_node_t *node, m3_raft_node_lookup_t *handle,
                            const uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE],
                            const char *bucket, const char *object) {
  m3_namespace_lookup_request_v1_t request;
  m3_namespace_lookup_result_t result;

  memset(&request, 0, sizeof(request));
  memcpy(request.tenant_id, tenant_id, sizeof(request.tenant_id));
  request.bucket = (const uint8_t *)bucket;
  request.bucket_size = strlen(bucket);
  request.object_key = (const uint8_t *)object;
  request.object_key_size = strlen(object);
  /* Linearizable read: read-index barrier, leader-only. Followers must
   * route reads to the current leader. */
  request.require_linearizable = 1u;
  handle->lookup = m3_gateway_raft_lookup_v1(node->raft);
  result = handle->lookup.start(handle->lookup.context, &request,
                                node_lookup_cb, &handle->capture);
  return result == M3_NAMESPACE_LOOKUP_OK
             ? TURBO_OK
             : (result == M3_NAMESPACE_LOOKUP_INVALID_ARG ? TURBO_EINVAL
                                                         : TURBO_EPROTO);
}

int m3_raft_node_lookup_start(m3_raft_node_t *node,
                              const uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE],
                              const char *bucket, const char *object,
                              m3_raft_node_lookup_t **out_handle) {
  m3_raft_node_lookup_t *handle;

  if (!node || !node->raft || !tenant_id || !bucket || !object || !out_handle) {
    return TURBO_EINVAL;
  }
  *out_handle = NULL;
  handle = (m3_raft_node_lookup_t *)calloc(1u, sizeof(*handle));
  if (!handle) {
    return TURBO_ENOMEM;
  }
  {
    int result = node_lookup_fill(node, handle, tenant_id, bucket, object);
    if (result != TURBO_OK) {
      free(handle);
      return result;
    }
  }
  *out_handle = handle;
  return TURBO_OK;
}

int m3_raft_node_lookup_try(m3_raft_node_lookup_t *handle, int *out_found,
                            int *out_done) {
  if (!handle || !out_found || !out_done) {
    return TURBO_EINVAL;
  }
  *out_done = handle->capture.completed;
  *out_found = handle->capture.completed ? handle->capture.found : 0;
  return TURBO_OK;
}

void m3_raft_node_lookup_release(m3_raft_node_lookup_t *handle) {
  free(handle);
}

int m3_raft_node_list(m3_raft_node_t *node,
                      const uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE],
                      const uint8_t *bucket, size_t bucket_size, const uint8_t *prefix,
                      size_t prefix_size, m3_raft_node_list_cb callback, void *user_data) {
  if (!node || !node->raft || !tenant_id || callback == NULL ||
      (bucket == NULL && bucket_size != 0u) ||
      (bucket != NULL && bucket_size == 0u)) {
    return TURBO_EINVAL;
  }
  return m3_namespace_local_store_list_v1(&node->store, tenant_id, bucket, bucket_size,
                                          prefix, prefix_size, callback, user_data) ==
                 M3_NAMESPACE_LOCAL_OK
             ? TURBO_OK
             : TURBO_EPROTO;
}

int m3_raft_node_lookup(m3_raft_node_t *node,
                        const uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE],
                        const char *bucket, const char *object, int *out_found) {
  m3_raft_node_lookup_t *handle = NULL;
  uint64_t deadline;
  int found = 0;
  int done = 0;

  if (!out_found) {
    return TURBO_EINVAL;
  }
  *out_found = 0;
  {
    int result = m3_raft_node_lookup_start(node, tenant_id, bucket, object, &handle);
    if (result != TURBO_OK) {
      return result;
    }
  }
  /* The read barrier needs peer event loops to respond; in a real deployment
   * each node process pumps its own loop, so pumping this node is enough. */
  deadline = turbo_monotonic_ms() + M3_RAFT_NODE_SOCKET_TIMEOUT_MS;
  while (!done && turbo_monotonic_ms() < deadline) {
    if (m3_raft_node_poll(node) != TURBO_OK) {
      break;
    }
    (void)m3_raft_node_lookup_try(handle, &found, &done);
  }
  m3_raft_node_lookup_release(handle);
  if (!done) {
    return TURBO_ETIMEDOUT;
  }
  *out_found = found;
  return TURBO_OK;
}

void m3_raft_node_destroy(m3_raft_node_t *node) {
  uint64_t deadline;

  if (!node) {
    return;
  }
  node->stop = 1;
  if (node->listener) {
    coro_socket_destroy(node->listener);
    node->listener = NULL;
  }
  if (node->peer_service) {
    (void)tr_raft_coronet_peer_service_stop(node->peer_service);
  }
  if (node->ctx) {
    /* Drain the stepper, reader and accept-loop coroutines before teardown.
     * The stepper can be blocked inside peer_service_step on a connect whose
     * timeout is M3_RAFT_NODE_SOCKET_TIMEOUT_MS, so the drain window must
     * exceed that timeout or teardown would race a still-alive coroutine. */
    deadline = turbo_monotonic_ms() + M3_RAFT_NODE_SOCKET_TIMEOUT_MS + 2000u;
    while (coro_context_alive(node->ctx) && turbo_monotonic_ms() < deadline) {
      coro_context_run(node->ctx, TURBO_RUN_NOWAIT);
    }
    if (node->peer_service) {
      (void)tr_raft_coronet_peer_service_destroy(node->peer_service);
      node->peer_service = NULL;
    }
  }
  if (node->raft) {
    m3_gateway_raft_close_v1(node->raft);
    node->raft = NULL;
  }
  m3_namespace_local_store_destroy_v1(&node->store);
  if (node->ctx) {
    coro_context_destroy(node->ctx);
    node->ctx = NULL;
  }
  node_config_release(node);
  free(node);
}
