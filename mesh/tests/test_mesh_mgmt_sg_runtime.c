#include <tinytest.h>
#include "mesh_mgmt_agent_runtime.h"
#include "mesh_mgmt_test_identity.h"
#include "mesh_mgmt_execution_wire.h"
#include "core/node_cnet.h"
#include "core/node_state.h"
#include <cnet/sg_host.h>
#include <salts/native_io_sharded.h>
#include <salts/clock.h>
#include <salts/thread.h>
#include <stdio.h>
#include <string.h>

/* One REAL native SG acceptor worker plus one borrowed Final P2P Owner.
 * The final worker performs authenticated Noise/MMP, production Router
 * post-auth Pool READY, explicit Lease, Manager-terminal and checked Stop.
 * A standalone signed client is independent of the 2-shard SG Host. */
enum { SG_MMP_SHARDS = 2, SG_MMP_TIMEOUT = 12000 };
typedef struct signed_sg_case signed_sg_case;

typedef struct {
  mesh_mgmt_agent_runtime_v1_t runtime;
  mesh_mgmt_agent_runtime_config_v1_t config;
  mesh_mgmt_p2p_peer_config_v1_t identity;
  runtime_callbacks_t random;
  p2p_runtime_config_v2_t network;
  p2p_peer_t *peer;
  uint8_t secret[32], public_key[32];
  unsigned established, closed, admitted, failures;
} signed_endpoint;

typedef struct {
  signed_sg_case *scenario;
  size_t shard;
  native_io_sharded_host_lease lease;
  native_io_backend *backend;
  p2p_cnet_owner_t *acceptor, *final_transport;
  cnet_stream_peer listener;
  const void *worker_token;
  size_t turns, stop_retries;
  int stopped, released, error;
  const char *failed_at;
} signed_sg_lane;

struct signed_sg_case {
  native_io_sharded *host;
  p2p_cnet_sg_t *handoff;
  signed_sg_lane lanes[SG_MMP_SHARDS];
  signed_endpoint server, client;
  mesh_mgmt_p2p_security_provider_v2_t server_security;
  p2p_node_t *server_node;
  p2p_node_cnet_t *server_owner;
  cnet_pool_lease lease;
  cnet_pool_snapshot pool;
  uint8_t command_payload[MESH_MGMT_EXECUTION_COMMAND_STATUS_SIZE_V1];
  size_t command_payload_len;
  uint64_t command_ticket;
  unsigned command_terminals;
  int command_terminal_status;
};

static native_io_backend_kind signed_backend(void) {
#if defined(_WIN32)
  return NATIVE_IO_BACKEND_IOCP;
#elif defined(__APPLE__)
  return NATIVE_IO_BACKEND_KQUEUE;
#else
  return NATIVE_IO_BACKEND_EPOLL;
#endif
}

static void lane_error(signed_sg_lane *lane, int code, const char *where) {
  if (!lane->error) { lane->error = code; lane->failed_at = where; }
}
#define SG_CALL(lane, expr) do {                            \
  const int sg_rc_ = (expr);                                \
  if (sg_rc_ != 0) {                                        \
    lane_error((lane), sg_rc_, #expr); return;              \
  }                                                        \
} while (0)

static int admitted(void *ctx, p2p_peer_t *peer, const uint8_t key[32],
                    const mesh_mgmt_dispatch_event_v1_t *event) {
  signed_endpoint *endpoint = (signed_endpoint *)ctx;
  (void)peer; (void)key; (void)event;
  endpoint->admitted++;
  return 0;
}
static int established(void *ctx, p2p_peer_t *peer, const uint8_t key[32],
                       const mesh_mgmt_dispatch_event_v1_t *event) {
  signed_endpoint *endpoint = (signed_endpoint *)ctx;
  (void)key;
  if (event->type == MESH_MGMT_DISPATCH_EVENT_SESSION_ESTABLISHED) {
    endpoint->peer = peer;
    endpoint->established++;
  }
  return 0;
}
static void disconnected(void *ctx, p2p_peer_t *peer, const uint8_t key[32],
                         mesh_mgmt_agent_router_close_reason_t reason) {
  signed_endpoint *endpoint = (signed_endpoint *)ctx;
  (void)key; (void)reason;
  endpoint->closed++;
  if (endpoint->peer == peer) endpoint->peer = NULL;
}
static void failure(void *ctx, p2p_peer_t *peer,
                    mesh_mgmt_agent_router_result_t router,
                    mesh_mgmt_p2p_peer_result_t result) {
  signed_endpoint *endpoint = (signed_endpoint *)ctx;
  (void)peer; (void)router; (void)result;
  endpoint->failures++;
}
static int random_bytes(void *ctx, uint8_t *out, size_t length) {
  signed_endpoint *endpoint = (signed_endpoint *)ctx;
  return runtime_random_bytes(&endpoint->random, out, length);
}
static void prepare_endpoint(signed_endpoint *endpoint, uint8_t seed) {
  uint8_t management_key[32] = {0};
  endpoint->secret[0] = seed;
  management_key[0] = (uint8_t)(seed + 1u);
  endpoint->random.next_message_byte = seed;
  check_equal(P2P_OK, p2p_public_key_from_private_key(
      endpoint->secret, endpoint->public_key));
  check_equal(0, prepare_runtime_config(&endpoint->identity, NULL, NULL,
      endpoint->public_key, management_key, seed, seed, seed, seed,
      &endpoint->random));
  check_equal(P2P_OK, p2p_runtime_config_v2_init(&endpoint->network));
  endpoint->network.receive_buffer_bytes = 97u;
  endpoint->network.stop_timeout_ms = 100u;
  endpoint->config.listen_host = "127.0.0.1";
  endpoint->config.p2p_private_key = endpoint->secret;
  endpoint->config.max_peers = 2u;
  endpoint->config.signer_template = &endpoint->identity.signer;
  endpoint->config.dispatch_template = &endpoint->identity.dispatch;
  endpoint->config.endpoint_capacity = 2u;
  endpoint->config.retry_base_ms = 10u;
  endpoint->config.retry_max_ms = 100u;
  endpoint->config.connect_timeout_ms = 5000u;
  endpoint->config.protocol_failure_limit = 2u;
  endpoint->config.first_endpoint_record_epoch = 1u;
  endpoint->config.first_service_record_epoch = 1u;
  endpoint->config.admit_peer = admitted;
  endpoint->config.on_event = established;
  endpoint->config.on_peer_closed = disconnected;
  endpoint->config.on_failure = failure;
  endpoint->config.callback_context = endpoint;
  endpoint->config.random_bytes = random_bytes;
  endpoint->config.random_context = endpoint;
}

/* Real SG Final worker and dedicated client must negotiate the SAME
 * explicit MMP execution feature and a pinned grant issuer public key.
 * This fixture never silently enables execution for normal production
 * management sessions. */
static void enable_execution_capability(signed_endpoint *endpoint) {
  const uint64_t features = MESH_MGMT_FEATURE_MEMBERSHIP |
                            MESH_MGMT_FEATURE_TARGETED_RPC |
                            MESH_MGMT_FEATURE_NODE_EXECUTION;
  endpoint->identity.signer.hello.features = features;
  endpoint->identity.dispatch.session.features = features;
  endpoint->identity.dispatch.enable_node_execution_shadow = 1u;
  memcpy(endpoint->identity.dispatch.node_execution_grant_issuer_key,
         endpoint->identity.dispatch.session.trusted_issuer_key,
         sizeof(endpoint->identity.dispatch.node_execution_grant_issuer_key));
  endpoint->identity.signer.hello.max_frame = MESH_MGMT_FRAME_MAX;
  endpoint->identity.dispatch.session.max_frame = MESH_MGMT_FRAME_MAX;
}

static void prepare_command_status(signed_sg_case *scenario) {
  mesh_mgmt_execution_status_v1_t status = {0};
  size_t bytes = 0u;
  status.version = MESH_MGMT_EXECUTION_SCHEMA_V1;
  status.code = MESH_MGMT_EXECUTION_STATUS_DISABLED;
  memset(status.command_id, 0x51, sizeof(status.command_id));
  memset(status.correlation_id, 0x52, sizeof(status.correlation_id));
  memset(status.request_digest, 0x53, sizeof(status.request_digest));
  memcpy(status.responder_node_id,
         scenario->server.identity.signer.hello.managed_node_id,
         sizeof(status.responder_node_id));
  check_equal(MESH_MGMT_EXECUTION_WIRE_OK,
      mesh_mgmt_execution_command_status_encode_v1(
          &status, scenario->command_payload,
          sizeof(scenario->command_payload), &bytes));
  scenario->command_payload_len = bytes;
}

static p2p_cnet_config_t final_transport_config(void) {
  p2p_cnet_config_t cfg = {0};
  cfg.client.backend = signed_backend();
  cfg.client.connection_capacity = 8u;
  cfg.client.command_capacity = 32u;
  cfg.client.request_capacity = 32u;
  cfg.client.completion_batch_capacity = 8u;
  cfg.client.event_capacity = 32u;
  cfg.client.max_send_bytes = 128u * 1024u;
  cfg.client.receive_buffer_bytes = 97u;
  cfg.client.connect_timeout_ms = 5000u;
  cfg.client.write_timeout_ms = 5000u;
  cfg.send_hwm_bytes = 128u * 1024u;
  cfg.pending_write_limit = 8u;
  cfg.accept_budget = 2u;
  cfg.stop_timeout_ms = 5000u;
  return cfg;
}
static bool host_quiescent(void *ctx) {
  const signed_sg_lane *lane = (const signed_sg_lane *)ctx;
  return lane->released && !lane->acceptor && !lane->final_transport;
}
static int refuse_local_accept(p2p_cnet_owner_t *owner,
                               p2p_connection_t *conn,
                               const cnet_stream_peer *remote, void *ctx) {
  signed_sg_lane *lane = (signed_sg_lane *)ctx;
  (void)owner; (void)conn; (void)remote;
  lane_error(lane, P2P_ERR_INVALID_STATE, "unexpected acceptor direct admit");
  return P2P_ERR_INVALID_STATE;
}

static void host_init(native_io_sharded_context *context, void *arg) {
  signed_sg_lane *lane = (signed_sg_lane *)arg;
  signed_sg_case *scenario = lane->scenario;
  const p2p_cnet_config_t cfg = final_transport_config();
  if (native_io_sharded_context_shard(context) != lane->shard) {
    lane_error(lane, SALTS_EPERM, "initial SG shard");
    return;
  }
  lane->worker_token = cmeta_thread_current_token();
  SG_CALL(lane, native_io_sharded_context_acquire_host(
      context, host_quiescent, lane, &lane->lease, &lane->backend));
  if (lane->shard == 0u) {
    SG_CALL(lane, p2p_cnet_owner_create_external(
        &cfg, lane->backend, lane->lease, &lane->acceptor));
    SG_CALL(lane, p2p_cnet_owner_listen(
        lane->acceptor, "127.0.0.1", 0u, 8u,
        refuse_local_accept, lane, &lane->listener));
    return;
  }

  signed_endpoint *server = &scenario->server;
  mesh_mgmt_p2p_security_config_v2_t trust = {0};
  p2p_security_config_v2_t p2p_security = {0};
  scenario->server_node = p2p_node_state_create("127.0.0.1", 0);
  if (!scenario->server_node) {
    lane_error(lane, P2P_ERR_NO_MEM, "p2p_node_state_create");
    return;
  }
  SG_CALL(lane, p2p_node_set_private_key(
      scenario->server_node, server->secret));
  trust.local_certificate = server->identity.signer.hello.certificate;
  trust.local_certificate_len =
      sizeof(server->identity.signer.hello.certificate);
  trust.trusted_issuer_key =
      server->identity.dispatch.session.trusted_issuer_key;
  trust.mesh_id_hash =
      server->identity.dispatch.session.expected_mesh_id_hash;
  trust.now_ms = server->identity.signer.now_ms;
  trust.now_context = server->identity.signer.callback_context;
  SG_CALL(lane, mesh_mgmt_p2p_security_provider_init_v2(
      &scenario->server_security, &trust, &p2p_security));
  /* An explicitly constructed SG-native Node does NOT pass through
   * p2p_start_nonblocking_v2's dedicated default policy conversion.
   * Supply the same nonzero mandatory Cookie/Noise/source-admission
   * budgets as the existing P2P SG Node fixtures, without a fallback. */
  p2p_security.handshake_timeout_ms = 5000u;
  p2p_security.ready_timeout_ms = 5000u;
  p2p_security.send_hwm_bytes = cfg.send_hwm_bytes;
  p2p_security.node_send_budget_bytes = cfg.send_hwm_bytes * 4u;
  p2p_security.session_max_age_ms = 60000u;
  p2p_security.session_max_bytes_per_direction = cfg.send_hwm_bytes;
  p2p_security.cookie_gate_limit = 16u;
  p2p_security.cookie_lifetime_ms = 5000u;
  p2p_security.cookie_key_rotation_ms = 10000u;
  p2p_security.source_admission_burst = 16u;
  p2p_security.source_admission_refill_per_second = 1u;
  p2p_security.source_admission_bucket_limit = 16u;
  SG_CALL(lane, p2p_node_configure_security_v2(
      scenario->server_node, &p2p_security));
  SG_CALL(lane, p2p_node_cnet_create_external(
      scenario->server_node, &cfg, lane->backend, lane->lease,
      &scenario->server_owner));
  SG_CALL(lane, p2p_node_cnet_bind_handoff_accept(scenario->server_owner));
  lane->final_transport = p2p_node_cnet_transport_owner(scenario->server_owner);
  if (!lane->final_transport)
    lane_error(lane, P2P_ERR_INVALID_STATE, "final transport");
}

static void host_install_runtime(native_io_sharded_context *context, void *arg) {
  signed_sg_lane *lane = (signed_sg_lane *)arg;
  signed_sg_case *scenario = lane->scenario;
  signed_endpoint *server = &scenario->server;
  if (lane->shard != 1u || lane->error) return;
  /* A stale SG lease fails before any Router or Pool allocation. */
  native_io_sharded_host_lease invalid = lane->lease;
  invalid.generation++;
  if (mesh_mgmt_agent_runtime_init_sg_final_v3(
          &server->runtime, &server->config,
          scenario->server_node, scenario->server_owner,
          context, invalid) != MESH_MGMT_AGENT_RUNTIME_INVALID_STATE ||
      server->runtime.node != NULL) {
    lane_error(lane, P2P_ERR_INVALID_STATE, "stale lease SG init");
    return;
  }
  SG_CALL(lane, mesh_mgmt_agent_runtime_init_sg_final_v3(
      &server->runtime, &server->config,
      scenario->server_node, scenario->server_owner, context, lane->lease));
  SG_CALL(lane, mesh_mgmt_agent_runtime_enable_signed_pool_v3(
      &server->runtime, 7u, 1u, 1u));
  SG_CALL(lane, mesh_mgmt_agent_runtime_start_v1(&server->runtime));
  if (server->runtime.owns_node || !server->runtime.sg_final_mode ||
      server->runtime.node != scenario->server_node ||
      server->runtime.signed_pool.impl ||
      mesh_mgmt_agent_runtime_poll_v1(&server->runtime) !=
          MESH_MGMT_AGENT_RUNTIME_INVALID_STATE)
    lane_error(lane, P2P_ERR_INVALID_STATE, "borrowed SG runtime mode");
}

static void host_progress(native_io_sharded_context *context, void *arg) {
  signed_sg_lane *lane = (signed_sg_lane *)arg;
  signed_sg_case *scenario = lane->scenario;
  size_t observed = 0u, settled = 0u;
  if (lane->error || lane->stopped) return;
  if (native_io_sharded_context_shard(context) != lane->shard ||
      cmeta_thread_current_token() != lane->worker_token) {
    lane_error(lane, SALTS_EPERM, "SG progress wrong owner");
    return;
  }
  if (lane->shard == 0u) {
    SG_CALL(lane, p2p_cnet_owner_poll_sg_host(
        lane->acceptor, context, lane->lease, &observed, &settled));
  } else if (lane->stop_retries) {
    SG_CALL(lane, p2p_cnet_owner_poll_sg_host(
        lane->final_transport, context, lane->lease, &observed, &settled));
  } else {
    SG_CALL(lane, p2p_node_cnet_poll_sg_host(
        scenario->server_owner, context, lane->lease, &observed, &settled));
    const mesh_mgmt_agent_runtime_state_t state = scenario->server.runtime.state;
    if (state == MESH_MGMT_AGENT_RUNTIME_RUNNING ||
        state == MESH_MGMT_AGENT_RUNTIME_STOPPING)
      SG_CALL(lane, mesh_mgmt_agent_runtime_sg_final_advance_v3(
          &scenario->server.runtime, context, lane->lease));
  }
  lane->turns++;
}

/* The command continuation is delivered from the ORIGINAL SG final
 * worker's CNet full-send/physical terminal. It owns the Lease, not the
 * acceptor or the initiating thread, and checked Stop must reject reentry. */
static void command_terminal(void *context, uint64_t ticket, int status) {
  signed_sg_case *scenario = context;
  signed_sg_lane *lane = &scenario->lanes[1];
  if (cmeta_thread_current_token() != lane->worker_token ||
      ticket != scenario->command_ticket || scenario->command_terminals != 0u) {
    lane_error(lane, SALTS_EPERM, "SG signed command callback wrong generation/owner");
    return;
  }
  ++scenario->command_terminals;
  scenario->command_terminal_status = status;
  if (mesh_mgmt_agent_runtime_stop_v1(&scenario->server.runtime) !=
          MESH_MGMT_AGENT_RUNTIME_INVALID_STATE)
    lane_error(lane, SALTS_EPERM, "SG terminal callback reentered runtime stop");
}

static void host_wrong_owner_command(native_io_sharded_context *context, void *arg) {
  signed_sg_lane *lane = arg;
  signed_sg_case *scenario = lane->scenario;
  uint64_t denied = UINT64_C(77);
  if (native_io_sharded_context_shard(context) != 0u || lane->error) return;
  if (mesh_mgmt_agent_runtime_send_execution_leased_v4(
          &scenario->server.runtime, MESH_MGMT_KIND_COMMAND_STATUS,
          scenario->client.identity.signer.hello.managed_node_id,
          scenario->command_payload, scenario->command_payload_len,
          command_terminal, scenario, &denied) !=
          MESH_MGMT_AGENT_RUNTIME_INVALID_STATE ||
      denied != 0u || scenario->command_terminals != 0u)
    lane_error(lane, SALTS_EPERM, "foreign SG owner admitted signed command");
}

static void host_send_command(native_io_sharded_context *context, void *arg) {
  signed_sg_lane *lane = arg;
  signed_sg_case *scenario = lane->scenario;
  if (native_io_sharded_context_shard(context) != 1u || lane->error) return;
  SG_CALL(lane, mesh_mgmt_agent_runtime_send_execution_leased_v4(
      &scenario->server.runtime, MESH_MGMT_KIND_COMMAND_STATUS,
      scenario->client.identity.signer.hello.managed_node_id,
      scenario->command_payload, scenario->command_payload_len,
      command_terminal, scenario, &scenario->command_ticket));
  if (!scenario->command_ticket || scenario->command_terminals != 0u ||
      scenario->server.runtime.command_terminal_inflight != 1u)
    lane_error(lane, P2P_ERR_INVALID_STATE, "SG leased MMP command inline completion");
}

static void host_snapshot(native_io_sharded_context *context, void *arg) {
  signed_sg_lane *lane = (signed_sg_lane *)arg;
  signed_sg_case *scenario = lane->scenario;
  if (native_io_sharded_context_shard(context) != 1u || lane->error) return;
  SG_CALL(lane, mesh_mgmt_agent_runtime_signed_pool_snapshot_v3(
      &scenario->server.runtime, &scenario->pool));
}

static void host_acquire(native_io_sharded_context *context, void *arg) {
  signed_sg_lane *lane = (signed_sg_lane *)arg;
  signed_sg_case *scenario = lane->scenario;
  if (native_io_sharded_context_shard(context) != 1u || lane->error) return;
  SG_CALL(lane, mesh_mgmt_agent_runtime_signed_pool_acquire_v3(
      &scenario->server.runtime, scenario->server.peer, &scenario->lease));
}

static void host_stop_runtime_with_lease(native_io_sharded_context *context,
                                         void *arg) {
  signed_sg_lane *lane = (signed_sg_lane *)arg;
  signed_sg_case *scenario = lane->scenario;
  if (native_io_sharded_context_shard(context) != 1u || lane->error) return;
  if (mesh_mgmt_agent_runtime_stop_v1(&scenario->server.runtime) !=
          MESH_MGMT_AGENT_RUNTIME_INVALID_STATE ||
      mesh_mgmt_agent_runtime_destroy_v2(&scenario->server.runtime) !=
          MESH_MGMT_AGENT_RUNTIME_INVALID_STATE ||
      scenario->server.runtime.state != MESH_MGMT_AGENT_RUNTIME_STOPPING ||
      !scenario->server.runtime.node || !scenario->server.runtime.signed_pool.impl)
    lane_error(lane, P2P_ERR_INVALID_STATE, "borrowed SG Stop retained lease");
}

static void host_finish_runtime(native_io_sharded_context *context, void *arg) {
  signed_sg_lane *lane = (signed_sg_lane *)arg;
  signed_sg_case *scenario = lane->scenario;
  if (native_io_sharded_context_shard(context) != 1u || lane->error) return;
  SG_CALL(lane, mesh_mgmt_agent_runtime_signed_pool_release_v3(
      &scenario->server.runtime, scenario->lease));
  if (mesh_mgmt_agent_runtime_signed_pool_release_v3(
          &scenario->server.runtime, scenario->lease) !=
          MESH_MGMT_AGENT_RUNTIME_INVALID_STATE) {
    lane_error(lane, P2P_ERR_INVALID_STATE, "duplicate SG Lease release");
    return;
  }
  SG_CALL(lane, mesh_mgmt_agent_runtime_stop_v1(&scenario->server.runtime));
  SG_CALL(lane, mesh_mgmt_agent_runtime_destroy_v2(&scenario->server.runtime));
  if (scenario->server.runtime.node != NULL ||
      scenario->server.runtime.sg_final_mode != 0u ||
      !scenario->server_node || !scenario->server_owner)
    lane_error(lane, P2P_ERR_INVALID_STATE, "SG borrowed Owner destroyed by Runtime");
}

static void host_wrong_owner(native_io_sharded_context *context, void *arg) {
  signed_sg_lane *lane = (signed_sg_lane *)arg;
  signed_sg_case *scenario = lane->scenario;
  cnet_pool_snapshot snapshot = {0};
  cnet_pool_lease denied = {0};
  if (native_io_sharded_context_shard(context) != 0u) return;
  if (mesh_mgmt_agent_runtime_sg_final_advance_v3(
          &scenario->server.runtime, context, lane->lease) !=
          MESH_MGMT_AGENT_RUNTIME_INVALID_STATE ||
      mesh_mgmt_agent_runtime_signed_pool_snapshot_v3(
          &scenario->server.runtime, &snapshot) !=
          MESH_MGMT_AGENT_RUNTIME_INVALID_STATE ||
      mesh_mgmt_agent_runtime_signed_pool_acquire_v3(
          &scenario->server.runtime, scenario->server.peer, &denied) !=
          MESH_MGMT_AGENT_RUNTIME_INVALID_STATE ||
      denied.slot != 0u)
    lane_error(lane, SALTS_EPERM, "foreign SG Final Pool access");
}

static void host_stop(native_io_sharded_context *context, void *arg) {
  signed_sg_lane *lane = (signed_sg_lane *)arg;
  signed_sg_case *scenario = lane->scenario;
  if (native_io_sharded_context_shard(context) != lane->shard ||
      lane->error || lane->stopped) return;
  int status = lane->shard == 0u
      ? p2p_cnet_owner_stop(lane->acceptor)
      : p2p_node_cnet_stop(scenario->server_owner);
  if (status == P2P_ERR_INVALID_STATE) {
    lane->stop_retries++;
    return;
  }
  if (status != P2P_OK) {
    lane_error(lane, status, "SG Owner stop");
    return;
  }
  lane->stopped = 1;
}

static void host_destroy(native_io_sharded_context *context, void *arg) {
  signed_sg_lane *lane = (signed_sg_lane *)arg;
  signed_sg_case *scenario = lane->scenario;
  if (native_io_sharded_context_shard(context) != lane->shard ||
      cmeta_thread_current_token() != lane->worker_token || lane->error) return;
  if (lane->shard == 0u) {
    SG_CALL(lane, p2p_cnet_owner_destroy(lane->acceptor));
    lane->acceptor = NULL;
  } else {
    SG_CALL(lane, p2p_node_cnet_destroy(scenario->server_owner));
    scenario->server_owner = NULL;
    lane->final_transport = NULL;
    SG_CALL(lane, p2p_node_state_destroy(scenario->server_node));
    scenario->server_node = NULL;
    mesh_mgmt_p2p_security_provider_destroy_v2(&scenario->server_security);
  }
  lane->released = 1;
  SG_CALL(lane, native_io_sharded_context_release_host(context, lane->lease));
  lane->backend = NULL;
}

static void submit(signed_sg_case *scenario, size_t shard,
                   native_io_sharded_task_fn function) {
  native_io_sharded_task task = {function, NULL, NULL, &scenario->lanes[shard]};
  check_equal(SALTS_OK, native_io_sharded_submit_to(
      scenario->host, shard, &task));
}
static void barrier(signed_sg_case *scenario) {
  check_equal(SALTS_OK, native_io_sharded_wait(scenario->host));
  for (size_t i = 0u; i < SG_MMP_SHARDS; ++i) {
    const signed_sg_lane *lane = &scenario->lanes[i];
    if (lane->error)
      fprintf(stderr, "signed SG Final shard %zu failed %d at %s\n",
              i, lane->error, lane->failed_at ? lane->failed_at : "?");
    check_equal(0, lane->error);
  }
}
static void pump(signed_sg_case *scenario) {
  if (scenario->client.runtime.state == MESH_MGMT_AGENT_RUNTIME_RUNNING)
    check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
        mesh_mgmt_agent_runtime_poll_v1(&scenario->client.runtime));
  for (size_t i = 0u; i < SG_MMP_SHARDS; ++i)
    submit(scenario, i, host_progress);
  barrier(scenario);
  cmeta_sleep_ms(1u);
}

static void test_real_signed_sg_final_runtime(void) {
  signed_sg_case fixture = {0};
  signed_sg_case *scenario = &fixture;
  const native_io_sharded_config settings = {
      SG_MMP_SHARDS, 8u, {signed_backend(), 64u, 128u, 16u}};
  p2p_cnet_sg_config_v1_t policy = {0};
  mesh_mgmt_agent_bootstrap_v1_t bootstrap = {0};
  prepare_endpoint(&scenario->server, 17u);
  prepare_endpoint(&scenario->client, 33u);
  enable_execution_capability(&scenario->server);
  enable_execution_capability(&scenario->client);
  prepare_command_status(scenario);
  scenario->server.config.listen_host = NULL;
  scenario->server.config.listen_port = 0u;
  scenario->server.config.p2p_private_key = NULL;

  check_equal(SALTS_OK, native_io_sharded_create(
      &settings, &scenario->host));
  for (size_t i = 0u; i < SG_MMP_SHARDS; ++i) {
    scenario->lanes[i].scenario = scenario;
    scenario->lanes[i].shard = i;
    submit(scenario, i, host_init);
  }
  barrier(scenario);

  policy.size = sizeof(policy);
  policy.version = P2P_CNET_SG_VERSION;
  policy.acceptor = scenario->lanes[0].acceptor;
  policy.final_owners[0] = scenario->lanes[1].final_transport;
  policy.final_owner_count = 1u;
  policy.placement = CNET_OWNER_PLACE_ROUND_ROBIN;
  policy.queue_capacity = 2u;
  policy.connection_capacity = 4u;
  check_equal(P2P_OK, p2p_cnet_sg_create_v1(
      &policy, &scenario->handoff));
  submit(scenario, 1u, host_install_runtime);
  barrier(scenario);

  memcpy(bootstrap.transport_peer_id, scenario->server.public_key, 32u);
  bootstrap.host = "127.0.0.1";
  bootstrap.port = scenario->lanes[0].listener.port;
  scenario->client.config.bootstraps = &bootstrap;
  scenario->client.config.bootstrap_count = 1u;
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_init_v2(
          &scenario->client.runtime, &scenario->client.config,
          &scenario->client.network));
  scenario->client.config.bootstraps = NULL;
  scenario->client.config.bootstrap_count = 0u;
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_start_v1(&scenario->client.runtime));

  const uint64_t connect_deadline = cmeta_monotonic_ms() + SG_MMP_TIMEOUT;
  while ((!scenario->server.established || !scenario->client.established) &&
         cmeta_monotonic_ms() < connect_deadline)
    pump(scenario);
  check_equal(1u, scenario->server.established);
  check_equal(1u, scenario->client.established);
  check_not_null(scenario->server.peer);
  submit(scenario, 1u, host_snapshot);
  barrier(scenario);
  check_equal((size_t)1u, scenario->pool.ready);
  check_equal((size_t)1u, scenario->pool.physical_in_use);
  check_equal((size_t)0u, scenario->pool.active_leases);

  /* Real SG worker sends authenticated typed MMP STATUS, holds CNet Pool
   * Lease across admission and only returns it on CNet completion. The
   * acceptor, even with the same CNet SG host, cannot send on this Owner. */
  submit(scenario, 0u, host_wrong_owner_command);
  submit(scenario, 1u, host_send_command);
  barrier(scenario);
  check_true(scenario->command_ticket != 0u);
  check_equal(0u, scenario->command_terminals);
  submit(scenario, 1u, host_snapshot);
  barrier(scenario);
  check_equal((size_t)1u, scenario->pool.active_leases);
  const uint64_t command_deadline = cmeta_monotonic_ms() + SG_MMP_TIMEOUT;
  while (!scenario->command_terminals &&
         cmeta_monotonic_ms() < command_deadline)
    pump(scenario);
  check_equal(1u, scenario->command_terminals);
  check_equal(P2P_OK, scenario->command_terminal_status);
  check_equal((size_t)0u, scenario->server.runtime.command_terminal_inflight);
  submit(scenario, 1u, host_snapshot);
  barrier(scenario);
  check_equal((size_t)0u, scenario->pool.active_leases);
  for (unsigned turn = 0u; turn < 4u; ++turn) pump(scenario);
  check_equal(1u, scenario->command_terminals);

  submit(scenario, 0u, host_wrong_owner);
  submit(scenario, 1u, host_acquire);
  barrier(scenario);
  check_true(scenario->lease.slot != 0u);
  submit(scenario, 1u, host_snapshot);
  barrier(scenario);
  check_equal((size_t)1u, scenario->pool.active_leases);

  submit(scenario, 1u, host_stop_runtime_with_lease);
  barrier(scenario);
  const uint64_t retired_deadline = cmeta_monotonic_ms() + SG_MMP_TIMEOUT;
  for (;;) {
    pump(scenario);
    submit(scenario, 1u, host_snapshot);
    barrier(scenario);
    if (scenario->pool.terminal_waiting_for_leases == 1u ||
        cmeta_monotonic_ms() >= retired_deadline) break;
  }
  check_true(scenario->pool.sealed);
  check_equal((size_t)0u, scenario->pool.ready);
  check_equal((size_t)1u, scenario->pool.active_leases);
  check_equal((size_t)1u, scenario->pool.terminal_waiting_for_leases);

  submit(scenario, 1u, host_finish_runtime);
  barrier(scenario);
  check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
      mesh_mgmt_agent_runtime_destroy_v2(&scenario->client.runtime));

  check_equal(P2P_OK, p2p_cnet_sg_seal_v1(scenario->handoff));
  for (size_t i = 0u; i < SG_MMP_SHARDS; ++i)
    submit(scenario, i, host_stop);
  barrier(scenario);
  const uint64_t stop_deadline = cmeta_monotonic_ms() + SG_MMP_TIMEOUT;
  while ((!scenario->lanes[0].stopped || !scenario->lanes[1].stopped) &&
         cmeta_monotonic_ms() < stop_deadline) {
    for (size_t i = 0u; i < SG_MMP_SHARDS; ++i)
      if (!scenario->lanes[i].stopped) submit(scenario, i, host_progress);
    barrier(scenario);
    for (size_t i = 0u; i < SG_MMP_SHARDS; ++i)
      if (!scenario->lanes[i].stopped) submit(scenario, i, host_stop);
    barrier(scenario);
    cmeta_sleep_ms(1u);
  }
  check_true(scenario->lanes[0].stopped && scenario->lanes[1].stopped);
  check_equal(P2P_OK, p2p_cnet_sg_destroy_v1(scenario->handoff));
  scenario->handoff = NULL;
  for (size_t i = 0u; i < SG_MMP_SHARDS; ++i)
    submit(scenario, i, host_destroy);
  barrier(scenario);
  check_equal(SALTS_OK, native_io_sharded_shutdown(scenario->host));
  check_equal(SALTS_OK, native_io_sharded_destroy(scenario->host));
}

spec("Signed MMP Runtime on real SG Final Owner") {
  it("borrows exact final P2P Manager and drains signed Pool leases before checked shutdown") {
    test_real_signed_sg_final_runtime();
  }
}
