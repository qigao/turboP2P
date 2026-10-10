#include <tinytest.h>
#include "mesh_mgmt_agent_runtime.h"
#include "mesh_mgmt_test_identity.h"
#include "core/node_cnet.h"
#include "core/node_state.h"
#include "core/peer_cnet.h"
#include <cnet/sg_host.h>
#include <cnet/client_pool.h>
#include <salts/native_io_sharded.h>
#include <salts/clock.h>
#include <salts/thread.h>
#include <stdio.h>
#include <string.h>

/* Real SG final-owner concurrency: N=2 and N=4 distinct final CNet workers
 * PLUS one acceptor. Every final has a different P2P Node/Manager, signed
 * Router, ClientPool and exclusive application Lease. Exactly ONE SG Host
 * observe/routing pass occurs per shard, never a private per-Pool poll. */
enum { SG_MULTI_MAX_FINALS = 4, SG_MULTI_MAX_SHARDS = 5,
       SG_MULTI_TIMEOUT_MS = 16000 };
typedef struct sg_multi_case sg_multi_case;

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
  signed_endpoint server, client;
  mesh_mgmt_p2p_security_provider_v2_t security;
  p2p_node_t *node;
  p2p_node_cnet_t *owner;
  cnet_pool_lease lease;
  cnet_pool_snapshot pool;
  cnet_manager *manager; /* copied borrowed identity, never accessed off-owner */
  cnet_managed_connection managed;
  uint8_t signed_connection[16];
} signed_final;

typedef struct {
  sg_multi_case *scenario;
  size_t shard;
  native_io_sharded_host_lease lease;
  native_io_backend *backend;
  p2p_cnet_owner_t *acceptor, *final_transport;
  cnet_stream_peer listener;
  const void *worker_token;
  size_t turns, stop_retries;
  int stopped, released, error;
  const char *failed_at;
} sg_multi_lane;

struct sg_multi_case {
  size_t finals, shards;
  native_io_sharded *host;
  p2p_cnet_sg_t *handoff;
  sg_multi_lane lanes[SG_MULTI_MAX_SHARDS];
  signed_final finals_data[SG_MULTI_MAX_FINALS];
};

static native_io_backend_kind sg_backend(void) {
#if defined(_WIN32)
  return NATIVE_IO_BACKEND_IOCP;
#elif defined(__APPLE__)
  return NATIVE_IO_BACKEND_KQUEUE;
#else
  return NATIVE_IO_BACKEND_EPOLL;
#endif
}
static signed_final *lane_final(sg_multi_lane *lane) {
  return &lane->scenario->finals_data[lane->shard - 1u];
}
static void fail_lane(sg_multi_lane *lane, int error, const char *source) {
  if (!lane->error) { lane->error = error; lane->failed_at = source; }
}
#define SG_CHECK(lane, expr) do {                                 \
  const int result_ = (expr);                                    \
  if (result_ != 0) { fail_lane((lane), result_, #expr); return; } \
} while (0)

static int admit(void *ctx, p2p_peer_t *peer, const uint8_t key[32],
                 const mesh_mgmt_dispatch_event_v1_t *event) {
  signed_endpoint *ep = (signed_endpoint *)ctx;
  (void)peer; (void)key; (void)event;
  ++ep->admitted;
  return 0;
}
static int on_event(void *ctx, p2p_peer_t *peer, const uint8_t key[32],
                    const mesh_mgmt_dispatch_event_v1_t *event) {
  signed_endpoint *ep = (signed_endpoint *)ctx;
  (void)key;
  if (event->type == MESH_MGMT_DISPATCH_EVENT_SESSION_ESTABLISHED) {
    ep->peer = peer;
    ++ep->established;
  }
  return 0;
}
static void on_close(void *ctx, p2p_peer_t *peer, const uint8_t key[32],
                     mesh_mgmt_agent_router_close_reason_t reason) {
  signed_endpoint *ep = (signed_endpoint *)ctx;
  (void)key; (void)reason;
  ++ep->closed;
  if (ep->peer == peer) ep->peer = NULL;
}
static void on_failure(void *ctx, p2p_peer_t *peer,
                       mesh_mgmt_agent_router_result_t router,
                       mesh_mgmt_p2p_peer_result_t result) {
  signed_endpoint *ep = (signed_endpoint *)ctx;
  (void)peer; (void)router; (void)result;
  ++ep->failures;
}
static int random_bytes(void *ctx, uint8_t *out, size_t bytes) {
  signed_endpoint *ep = (signed_endpoint *)ctx;
  return runtime_random_bytes(&ep->random, out, bytes);
}
static void prepare(signed_endpoint *ep, uint8_t seed) {
  uint8_t management_key[32] = {0};
  ep->secret[0] = seed;
  management_key[0] = (uint8_t)(seed + 1u);
  ep->random.next_message_byte = seed;
  check_equal(P2P_OK, p2p_public_key_from_private_key(
      ep->secret, ep->public_key));
  check_equal(0, prepare_runtime_config(
      &ep->identity, NULL, NULL, ep->public_key, management_key,
      seed, seed, seed, seed, &ep->random));
  check_equal(P2P_OK, p2p_runtime_config_v2_init(&ep->network));
  ep->network.receive_buffer_bytes = 97u;
  ep->network.stop_timeout_ms = 100u;
  ep->config.listen_host = "127.0.0.1";
  ep->config.p2p_private_key = ep->secret;
  ep->config.max_peers = 2u;
  ep->config.signer_template = &ep->identity.signer;
  ep->config.dispatch_template = &ep->identity.dispatch;
  ep->config.endpoint_capacity = 2u;
  /* Existing EndpointPool remains the sole reconnect/quarantine clock.
   * Lengthen retry interval in the fixture to avoid moving a redial to a
   * DIFFERENT round-robin final while qualifying initial exact peer IDs. */
  ep->config.retry_base_ms = 5000u;
  ep->config.retry_max_ms = 5000u;
  ep->config.connect_timeout_ms = 5000u;
  ep->config.protocol_failure_limit = 2u;
  ep->config.first_endpoint_record_epoch = 1u;
  ep->config.first_service_record_epoch = 1u;
  ep->config.admit_peer = admit;
  ep->config.on_event = on_event;
  ep->config.on_peer_closed = on_close;
  ep->config.on_failure = on_failure;
  ep->config.callback_context = ep;
  ep->config.random_bytes = random_bytes;
  ep->config.random_context = ep;
}
static p2p_cnet_config_t transport_settings(void) {
  p2p_cnet_config_t cfg = {0};
  cfg.client.backend = sg_backend();
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
static bool quiescent(void *ctx) {
  const sg_multi_lane *lane = (const sg_multi_lane *)ctx;
  return lane->released && lane->acceptor == NULL &&
         lane->final_transport == NULL;
}
static int acceptor_reject(p2p_cnet_owner_t *owner, p2p_connection_t *conn,
                           const cnet_stream_peer *remote, void *ctx) {
  sg_multi_lane *lane = (sg_multi_lane *)ctx;
  (void)owner; (void)conn; (void)remote;
  fail_lane(lane, P2P_ERR_INVALID_STATE, "acceptor processed final peer");
  return P2P_ERR_INVALID_STATE;
}

static void host_init(native_io_sharded_context *ctx, void *arg) {
  sg_multi_lane *lane = (sg_multi_lane *)arg;
  const p2p_cnet_config_t cfg = transport_settings();
  if (native_io_sharded_context_shard(ctx) != lane->shard) {
    fail_lane(lane, SALTS_EPERM, "create on wrong shard"); return;
  }
  lane->worker_token = cmeta_thread_current_token();
  SG_CHECK(lane, native_io_sharded_context_acquire_host(
      ctx, quiescent, lane, &lane->lease, &lane->backend));
  if (!lane->shard) {
    SG_CHECK(lane, p2p_cnet_owner_create_external(
        &cfg, lane->backend, lane->lease, &lane->acceptor));
    SG_CHECK(lane, p2p_cnet_owner_listen(
        lane->acceptor, "127.0.0.1", 0u, 16u,
        acceptor_reject, lane, &lane->listener));
    return;
  }
  signed_final *f = lane_final(lane);
  mesh_mgmt_p2p_security_config_v2_t trust = {0};
  p2p_security_config_v2_t sec = {0};
  f->node = p2p_node_state_create("127.0.0.1", 0);
  if (!f->node) { fail_lane(lane, P2P_ERR_NO_MEM, "create final Node"); return; }
  SG_CHECK(lane, p2p_node_set_private_key(f->node, f->server.secret));
  trust.local_certificate = f->server.identity.signer.hello.certificate;
  trust.local_certificate_len =
      sizeof(f->server.identity.signer.hello.certificate);
  trust.trusted_issuer_key =
      f->server.identity.dispatch.session.trusted_issuer_key;
  trust.mesh_id_hash = f->server.identity.dispatch.session.expected_mesh_id_hash;
  trust.now_ms = f->server.identity.signer.now_ms;
  trust.now_context = f->server.identity.signer.callback_context;
  SG_CHECK(lane, mesh_mgmt_p2p_security_provider_init_v2(
      &f->security, &trust, &sec));
  sec.handshake_timeout_ms = 5000u;
  sec.ready_timeout_ms = 5000u;
  sec.send_hwm_bytes = cfg.send_hwm_bytes;
  sec.node_send_budget_bytes = cfg.send_hwm_bytes * 4u;
  sec.session_max_age_ms = 60000u;
  sec.session_max_bytes_per_direction = cfg.send_hwm_bytes;
  sec.cookie_gate_limit = 16u;
  sec.cookie_lifetime_ms = 5000u;
  sec.cookie_key_rotation_ms = 10000u;
  sec.source_admission_burst = 16u;
  sec.source_admission_refill_per_second = 1u;
  sec.source_admission_bucket_limit = 16u;
  SG_CHECK(lane, p2p_node_configure_security_v2(f->node, &sec));
  SG_CHECK(lane, p2p_node_cnet_create_external(
      f->node, &cfg, lane->backend, lane->lease, &f->owner));
  SG_CHECK(lane, p2p_node_cnet_bind_handoff_accept(f->owner));
  lane->final_transport = p2p_node_cnet_transport_owner(f->owner);
  if (!lane->final_transport)
    fail_lane(lane, P2P_ERR_INVALID_STATE, "missing final CNet Owner");
}
static void host_install(native_io_sharded_context *ctx, void *arg) {
  sg_multi_lane *lane = (sg_multi_lane *)arg;
  if (!lane->shard || lane->error) return;
  signed_final *f = lane_final(lane);
  native_io_sharded_host_lease stale = lane->lease;
  stale.generation++;
  if (mesh_mgmt_agent_runtime_init_sg_final_v3(
          &f->server.runtime, &f->server.config,
          f->node, f->owner, ctx, stale) !=
          MESH_MGMT_AGENT_RUNTIME_INVALID_STATE ||
      f->server.runtime.node != NULL) {
    fail_lane(lane, P2P_ERR_INVALID_STATE, "foreign Host lease admitted"); return;
  }
  SG_CHECK(lane, mesh_mgmt_agent_runtime_init_sg_final_v3(
      &f->server.runtime, &f->server.config, f->node, f->owner,
      ctx, lane->lease));
  SG_CHECK(lane, mesh_mgmt_agent_runtime_enable_signed_pool_v3(
      &f->server.runtime, (uint64_t)(70u + lane->shard), 1u, 1u));
  SG_CHECK(lane, mesh_mgmt_agent_runtime_start_v1(&f->server.runtime));
  if (f->server.runtime.owns_node || !f->server.runtime.sg_final_mode ||
      f->server.runtime.signed_pool.impl != NULL ||
      mesh_mgmt_agent_runtime_poll_v1(&f->server.runtime) !=
          MESH_MGMT_AGENT_RUNTIME_INVALID_STATE)
    fail_lane(lane, P2P_ERR_INVALID_STATE, "final Runtime owned backend");
}
static void host_progress(native_io_sharded_context *ctx, void *arg) {
  sg_multi_lane *lane = (sg_multi_lane *)arg;
  if (lane->error || lane->stopped) return;
  if (native_io_sharded_context_shard(ctx) != lane->shard ||
      cmeta_thread_current_token() != lane->worker_token) {
    fail_lane(lane, SALTS_EPERM, "wrong-progress worker"); return;
  }
  size_t observed = 0u, settled = 0u;
  if (!lane->shard) {
    SG_CHECK(lane, p2p_cnet_owner_poll_sg_host(
        lane->acceptor, ctx, lane->lease, &observed, &settled));
  } else {
    signed_final *f = lane_final(lane);
    if (lane->stop_retries) {
      SG_CHECK(lane, p2p_cnet_owner_poll_sg_host(
          lane->final_transport, ctx, lane->lease, &observed, &settled));
    } else {
      SG_CHECK(lane, p2p_node_cnet_poll_sg_host(
          f->owner, ctx, lane->lease, &observed, &settled));
      if (f->server.runtime.state == MESH_MGMT_AGENT_RUNTIME_RUNNING ||
          f->server.runtime.state == MESH_MGMT_AGENT_RUNTIME_STOPPING)
        SG_CHECK(lane, mesh_mgmt_agent_runtime_sg_final_advance_v3(
            &f->server.runtime, ctx, lane->lease));
    }
  }
  ++lane->turns;
}
static void host_snapshot(native_io_sharded_context *ctx, void *arg) {
  sg_multi_lane *lane = (sg_multi_lane *)arg;
  (void)ctx;
  if (!lane->shard || lane->error) return;
  signed_final *f = lane_final(lane);
  SG_CHECK(lane, mesh_mgmt_agent_runtime_signed_pool_snapshot_v3(
      &f->server.runtime, &f->pool));
  if (f->server.runtime.state == MESH_MGMT_AGENT_RUNTIME_RUNNING &&
      f->pool.ready == 1u) {
    const mesh_mgmt_runtime_pool_record_v3_t *record =
        &f->server.runtime.signed_pool_records[0];
    cnet_manager_entry entry = {0};
    if (!record->active || record->draining ||
        cnet_manager_lookup(f->server.runtime.signed_pool_manager,
                            record->managed, &entry) != SALTS_OK ||
        entry.state != CNET_MANAGER_BOUND ||
        entry.connection.slot == 0u ||
        record->managed.manager != (uintptr_t)f->server.runtime.signed_pool_manager) {
      /* Manager ID's pointer field is tested below through entry returned
       * by upstream; this assertion never constructs another Manager. */
      fail_lane(lane, P2P_ERR_INVALID_STATE, "final Manager BOUND"); return;
    }
    f->manager = f->server.runtime.signed_pool_manager;
    f->managed = record->managed;
    memcpy(f->signed_connection, record->connection_id,
           sizeof(f->signed_connection));
  }
}
static void host_acquire(native_io_sharded_context *ctx, void *arg) {
  sg_multi_lane *lane = (sg_multi_lane *)arg;
  (void)ctx;
  if (!lane->shard || lane->error) return;
  signed_final *f = lane_final(lane);
  cnet_pool_lease extra = {0};
  SG_CHECK(lane, mesh_mgmt_agent_runtime_signed_pool_acquire_v3(
      &f->server.runtime, f->server.peer, &f->lease));
  if (!f->lease.slot ||
      mesh_mgmt_agent_runtime_signed_pool_acquire_v3(
          &f->server.runtime, f->server.peer, &extra) !=
          MESH_MGMT_AGENT_RUNTIME_RESOURCE_EXHAUSTED ||
      extra.slot != 0u)
    fail_lane(lane, P2P_ERR_INVALID_STATE, "extra Lease stolen");
}
/* On a FINAL worker, reject all operations against the NEXT final's Pool;
 * verify its real Manager also enforces thread affinity. No other final's
 * capacity/lease is allowed to change. */
static void host_foreign(native_io_sharded_context *ctx, void *arg) {
  sg_multi_lane *lane = (sg_multi_lane *)arg;
  if (!lane->shard || lane->error) return;
  sg_multi_case *sc = lane->scenario;
  const size_t next = (lane->shard % sc->finals);
  signed_final *local = lane_final(lane), *foreign = &sc->finals_data[next];
  cnet_pool_snapshot denied_snapshot = {0}, local_snapshot = {0};
  cnet_pool_lease denied_lease = {0};
  cnet_manager_entry denied_entry = {0};
  if (foreign == local || foreign->manager == local->manager ||
      mesh_mgmt_agent_runtime_signed_pool_snapshot_v3(
          &foreign->server.runtime, &denied_snapshot) !=
          MESH_MGMT_AGENT_RUNTIME_INVALID_STATE ||
      mesh_mgmt_agent_runtime_signed_pool_acquire_v3(
          &foreign->server.runtime, foreign->server.peer, &denied_lease) !=
          MESH_MGMT_AGENT_RUNTIME_INVALID_STATE ||
      denied_lease.slot != 0u ||
      mesh_mgmt_agent_runtime_signed_pool_release_v3(
          &foreign->server.runtime, foreign->lease) !=
          MESH_MGMT_AGENT_RUNTIME_INVALID_STATE ||
      mesh_mgmt_agent_runtime_sg_final_advance_v3(
          &foreign->server.runtime, ctx, lane->lease) !=
          MESH_MGMT_AGENT_RUNTIME_INVALID_STATE ||
      cnet_manager_lookup(foreign->manager, foreign->managed,
                          &denied_entry) != SALTS_EPERM ||
      cnet_pool_get_snapshot(&foreign->server.runtime.signed_pool,
                             &denied_snapshot) != SALTS_EPERM ||
      mesh_mgmt_agent_runtime_signed_pool_snapshot_v3(
          &local->server.runtime, &local_snapshot) !=
          MESH_MGMT_AGENT_RUNTIME_OK ||
      local_snapshot.ready != 1u || local_snapshot.active_leases != 1u)
    fail_lane(lane, SALTS_EPERM, "cross-final Pool/Manager isolation");
}
/* An application's single-slot Lease is NEVER a substitute for a signed
 * MMP authority/key. Underlying CNet Manager must also reject a premature
 * fabricated physical terminal while still BOUND. Exercise after each
 * Final has already acquired a real Lease and before checked shutdown. */
static void host_reject_unsigned_key(native_io_sharded_context *ctx, void *arg) {
  sg_multi_lane *lane = (sg_multi_lane *)arg;
  (void)ctx;
  if (!lane->shard || lane->error) return;
  signed_final *f = lane_final(lane);
  mesh_mgmt_runtime_pool_record_v3_t *record =
      &f->server.runtime.signed_pool_records[0];
  cnet_pool_key wrong_key = {0};
  cnet_pool_lease denied = {0}, reacquired = {0};
  cnet_managed_connection denied_managed = {0};
  const cnet_pool_lease original = f->lease;
  if (!record->active || record->draining ||
      cnet_pool_terminal(&f->server.runtime.signed_pool,
                         record->physical) != SALTS_EBUSY) {
    fail_lane(lane, P2P_ERR_INVALID_STATE, "live Manager early-terminal");
    return;
  }
  SG_CHECK(lane, mesh_mgmt_agent_runtime_signed_pool_release_v3(
      &f->server.runtime, original));
  if (mesh_mgmt_agent_runtime_signed_pool_release_v3(
          &f->server.runtime, original) !=
          MESH_MGMT_AGENT_RUNTIME_INVALID_STATE) {
    fail_lane(lane, P2P_ERR_INVALID_STATE, "duplicate old Lease");
    return;
  }

  wrong_key = record->key;
  wrong_key.authority_id ^= UINT64_C(1);
  if (cnet_pool_try_acquire(&f->server.runtime.signed_pool, &wrong_key,
                            NULL, &denied, &denied_managed) != SALTS_ENOBUFS ||
      denied.slot != 0u || denied_managed.slot != 0u) {
    fail_lane(lane, SALTS_EPROTO, "wrong signed authority granted Lease");
    return;
  }
  wrong_key = record->key;
  wrong_key.session_id ^= UINT64_C(1);
  if (cnet_pool_try_acquire(&f->server.runtime.signed_pool, &wrong_key,
                            NULL, &denied, &denied_managed) != SALTS_ENOBUFS ||
      denied.slot != 0u || denied_managed.slot != 0u) {
    fail_lane(lane, SALTS_EPROTO, "stale signed session granted Lease");
    return;
  }
  wrong_key = record->key;
  wrong_key.owner_id ^= UINT64_C(1);
  if (cnet_pool_try_acquire(&f->server.runtime.signed_pool, &wrong_key,
                            NULL, &denied, &denied_managed) != SALTS_EINVAL ||
      denied.slot != 0u || denied_managed.slot != 0u) {
    fail_lane(lane, SALTS_EPROTO, "foreign Pool owner granted Lease");
    return;
  }

  SG_CHECK(lane, mesh_mgmt_agent_runtime_signed_pool_acquire_v3(
      &f->server.runtime, f->server.peer, &reacquired));
  if (!reacquired.slot ||
      (reacquired.slot == original.slot &&
       reacquired.generation == original.generation)) {
    fail_lane(lane, P2P_ERR_INVALID_STATE, "Lease generation recycled");
    return;
  }
  f->lease = reacquired;
}

static void host_stop_retaining(native_io_sharded_context *ctx, void *arg) {
  sg_multi_lane *lane = (sg_multi_lane *)arg;
  (void)ctx;
  if (!lane->shard || lane->error) return;
  signed_final *f = lane_final(lane);
  if (mesh_mgmt_agent_runtime_stop_v1(&f->server.runtime) !=
          MESH_MGMT_AGENT_RUNTIME_INVALID_STATE ||
      mesh_mgmt_agent_runtime_destroy_v2(&f->server.runtime) !=
          MESH_MGMT_AGENT_RUNTIME_INVALID_STATE ||
      f->server.runtime.state != MESH_MGMT_AGENT_RUNTIME_STOPPING ||
      !f->server.runtime.node || !f->server.runtime.signed_pool.impl ||
      !f->server.runtime.signed_pool_manager)
    fail_lane(lane, P2P_ERR_INVALID_STATE, "Stop stole outstanding Lease");
}
static void host_finish_runtime(native_io_sharded_context *ctx, void *arg) {
  sg_multi_lane *lane = (sg_multi_lane *)arg;
  (void)ctx;
  if (!lane->shard || lane->error) return;
  signed_final *f = lane_final(lane);
  SG_CHECK(lane, mesh_mgmt_agent_runtime_signed_pool_release_v3(
      &f->server.runtime, f->lease));
  if (mesh_mgmt_agent_runtime_signed_pool_release_v3(
          &f->server.runtime, f->lease) !=
          MESH_MGMT_AGENT_RUNTIME_INVALID_STATE) {
    fail_lane(lane, P2P_ERR_INVALID_STATE, "duplicate Lease return"); return;
  }
  SG_CHECK(lane, mesh_mgmt_agent_runtime_stop_v1(&f->server.runtime));
  SG_CHECK(lane, mesh_mgmt_agent_runtime_destroy_v2(&f->server.runtime));
  if (f->server.runtime.node || f->server.runtime.sg_final_mode ||
      !f->node || !f->owner || f->server.runtime.signed_pool.impl)
    fail_lane(lane, P2P_ERR_INVALID_STATE, "borrowed SG Node freed");
}
static void host_stop_owner(native_io_sharded_context *ctx, void *arg) {
  sg_multi_lane *lane = (sg_multi_lane *)arg;
  if (native_io_sharded_context_shard(ctx) != lane->shard ||
      lane->error || lane->stopped) return;
  int status = !lane->shard
      ? p2p_cnet_owner_stop(lane->acceptor)
      : p2p_node_cnet_stop(lane_final(lane)->owner);
  if (status == P2P_ERR_INVALID_STATE) {
    ++lane->stop_retries; return;
  }
  if (status != P2P_OK) {
    fail_lane(lane, status, "SG transport stop"); return;
  }
  lane->stopped = 1;
}
static void host_destroy(native_io_sharded_context *ctx, void *arg) {
  sg_multi_lane *lane = (sg_multi_lane *)arg;
  if (lane->error || native_io_sharded_context_shard(ctx) != lane->shard ||
      cmeta_thread_current_token() != lane->worker_token) {
    fail_lane(lane, SALTS_EPERM, "destroy worker"); return;
  }
  if (!lane->shard) {
    SG_CHECK(lane, p2p_cnet_owner_destroy(lane->acceptor));
    lane->acceptor = NULL;
  } else {
    signed_final *f = lane_final(lane);
    SG_CHECK(lane, p2p_node_cnet_destroy(f->owner));
    f->owner = NULL;
    lane->final_transport = NULL;
    SG_CHECK(lane, p2p_node_state_destroy(f->node));
    f->node = NULL;
    mesh_mgmt_p2p_security_provider_destroy_v2(&f->security);
  }
  lane->released = 1;
  SG_CHECK(lane, native_io_sharded_context_release_host(
      ctx, lane->lease));
  lane->backend = NULL;
}

static void submit(sg_multi_case *sc, size_t shard,
                   native_io_sharded_task_fn fn) {
  native_io_sharded_task task = {fn, NULL, NULL, &sc->lanes[shard]};
  check_equal(SALTS_OK, native_io_sharded_submit_to(sc->host, shard, &task));
}
static void barrier(sg_multi_case *sc) {
  check_equal(SALTS_OK, native_io_sharded_wait(sc->host));
  for (size_t i = 0u; i < sc->shards; ++i) {
    const sg_multi_lane *lane = &sc->lanes[i];
    if (lane->error)
      fprintf(stderr, "signed SG %zu finals: shard %zu error %d in %s\n",
              sc->finals, i, lane->error,
              lane->failed_at ? lane->failed_at : "?");
    check_equal(0, lane->error);
  }
}
static void pump(sg_multi_case *sc) {
  for (size_t i = 0u; i < sc->finals; ++i) {
    signed_endpoint *client = &sc->finals_data[i].client;
    if (client->runtime.state == MESH_MGMT_AGENT_RUNTIME_RUNNING)
      check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
          mesh_mgmt_agent_runtime_poll_v1(&client->runtime));
  }
  for (size_t i = 0u; i < sc->shards; ++i)
    submit(sc, i, host_progress);
  barrier(sc);
  cmeta_sleep_ms(1u);
}
static void refresh(sg_multi_case *sc, size_t first) {
  for (size_t i = first; i < sc->finals; ++i)
    if (sc->finals_data[i].server.runtime.state !=
        MESH_MGMT_AGENT_RUNTIME_STOPPED)
      submit(sc, i+1u, host_snapshot);
  barrier(sc);
}
static void until_terminals(sg_multi_case *sc, size_t first) {
  const uint64_t deadline = cmeta_monotonic_ms() + SG_MULTI_TIMEOUT_MS;
  for (;;) {
    pump(sc);
    refresh(sc, first);
    bool ready = true;
    for (size_t i = first; i < sc->finals; ++i)
      if (sc->finals_data[i].pool.terminal_waiting_for_leases != 1u)
        ready = false;
    if (ready || cmeta_monotonic_ms() >= deadline) break;
  }
  for (size_t i = first; i < sc->finals; ++i) {
    const signed_final *f = &sc->finals_data[i];
    check_true(f->pool.sealed);
    check_equal((size_t)0u, f->pool.ready);
    check_equal((size_t)1u, f->pool.active_leases);
    check_equal((size_t)1u, f->pool.terminal_waiting_for_leases);
  }
}

static void test_multi_final(size_t final_count) {
  sg_multi_case fixture = {0};
  sg_multi_case *sc = &fixture;
  sc->finals = final_count;
  sc->shards = final_count + 1u;
  check_true(final_count == 2u || final_count == 4u);
  const native_io_sharded_config cfg = {
      sc->shards, 8u, {sg_backend(), 64u, 128u, 16u}};
  p2p_cnet_sg_config_v1_t policy = {0};
  mesh_mgmt_agent_bootstrap_v1_t bootstrap = {0};

  for (size_t i = 0u; i < sc->finals; ++i) {
    signed_final *f = &sc->finals_data[i];
    prepare(&f->server, (uint8_t)(17u + 2u*i));
    prepare(&f->client, (uint8_t)(33u + 2u*i));
    f->server.config.listen_host = NULL;
    f->server.config.listen_port = 0u;
    f->server.config.p2p_private_key = NULL;
  }
  check_equal(SALTS_OK, native_io_sharded_create(&cfg, &sc->host));
  for (size_t i = 0u; i < sc->shards; ++i) {
    sc->lanes[i].scenario = sc;
    sc->lanes[i].shard = i;
    submit(sc, i, host_init);
  }
  barrier(sc);
  for (size_t i = 0u; i < sc->shards; ++i) {
    check_not_null(sc->lanes[i].worker_token);
    check_not_null(sc->lanes[i].backend);
    check_equal((uint32_t)i, sc->lanes[i].lease.owner_shard);
    for (size_t j = 0u; j < i; ++j) {
      check_true(sc->lanes[i].worker_token != sc->lanes[j].worker_token);
      check_true(sc->lanes[i].backend != sc->lanes[j].backend);
    }
  }
  check_true(sc->lanes[0].listener.port != 0u);
  policy.size = sizeof(policy);
  policy.version = P2P_CNET_SG_VERSION;
  policy.acceptor = sc->lanes[0].acceptor;
  policy.final_owner_count = sc->finals;
  policy.placement = CNET_OWNER_PLACE_ROUND_ROBIN;
  policy.queue_capacity = 2u;
  policy.connection_capacity = 4u;
  for (size_t i = 0u; i < sc->finals; ++i)
    policy.final_owners[i] = sc->lanes[i+1u].final_transport;
  check_equal(P2P_OK, p2p_cnet_sg_create_v1(&policy, &sc->handoff));
  for (size_t i = 1u; i < sc->shards; ++i)
    submit(sc, i, host_install);
  barrier(sc);

  /* Establish one signed Noise+MMP connection per selected final Owner.
   * Sequential initial connects fix the round-robin final placement; after
   * admission every final and independent client is progressed concurrently. */
  for (size_t i = 0u; i < sc->finals; ++i) {
    signed_final *f = &sc->finals_data[i];
    memcpy(bootstrap.transport_peer_id, f->server.public_key, 32u);
    bootstrap.host = "127.0.0.1";
    bootstrap.port = sc->lanes[0].listener.port;
    f->client.config.bootstraps = &bootstrap;
    f->client.config.bootstrap_count = 1u;
    check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
        mesh_mgmt_agent_runtime_init_v2(
            &f->client.runtime, &f->client.config, &f->client.network));
    f->client.config.bootstraps = NULL;
    f->client.config.bootstrap_count = 0u;
    check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
        mesh_mgmt_agent_runtime_start_v1(&f->client.runtime));
    const uint64_t deadline = cmeta_monotonic_ms() + SG_MULTI_TIMEOUT_MS;
    while ((!f->server.established || !f->client.established) &&
           cmeta_monotonic_ms() < deadline)
      pump(sc);
    check_equal(1u, f->server.established);
    check_equal(1u, f->client.established);
    check_not_null(f->server.peer);
    p2p_cnet_sg_snapshot_v1_t ticket = {0};
    check_equal(P2P_OK, p2p_cnet_sg_snapshot_v1(
        sc->handoff, i, &ticket));
    check_equal((size_t)1u, ticket.handoff.taken);
    check_equal((size_t)0u, ticket.handoff.queued);
  }
  refresh(sc, 0u);
  for (size_t i = 0u; i < sc->finals; ++i) {
    const signed_final *f = &sc->finals_data[i];
    check_not_null(f->manager);
    check_equal((size_t)1u, f->pool.ready);
    check_equal((size_t)1u, f->pool.physical_in_use);
    check_equal((size_t)0u, f->pool.active_leases);
    for (size_t j = 0u; j < i; ++j) {
      const signed_final *other = &sc->finals_data[j];
      check_true(f->manager != other->manager);
      check_true(f->server.runtime.signed_pool.impl !=
                 other->server.runtime.signed_pool.impl);
      check_true(memcmp(f->signed_connection, other->signed_connection,
                        sizeof(f->signed_connection)) != 0);
    }
  }

  /* Every final obtains its own REAL exclusive Pool Lease on its SG worker.
   * Then cross-final operations explicitly reject, leaving every Pool's
   * native single-slot capacity and Manager BOUND identity unchanged. */
  for (size_t i = 1u; i < sc->shards; ++i)
    submit(sc, i, host_acquire);
  barrier(sc);
  for (size_t i = 1u; i < sc->shards; ++i)
    submit(sc, i, host_foreign);
  barrier(sc);
  /* Same-worker false signed authority/session/owner and early terminal
   * must reject with free lease budget; fresh genuine Lease must still work. */
  for (size_t i = 1u; i < sc->shards; ++i)
    submit(sc, i, host_reject_unsigned_key);
  barrier(sc);
  refresh(sc, 0u);
  for (size_t i = 0u; i < sc->finals; ++i)
    check_equal((size_t)1u, sc->finals_data[i].pool.active_leases);

  /* Retire final A while ALL other final Owners remain signed/READY and
   * leased. A's checked Stop and Destroy must retain its native Manager
   * until real physical terminal and application Lease return; B/C/D cannot
   * inherit A's credit or observe a false terminal. */
  submit(sc, 1u, host_stop_retaining);
  barrier(sc);
  /* Only first final was sealed: wait for its physical terminal while
   * verifying all OTHER final Pools stay signed READY and leased. */
  {
    const uint64_t deadline = cmeta_monotonic_ms() + SG_MULTI_TIMEOUT_MS;
    for (;;) {
      pump(sc);
      refresh(sc, 0u);
      bool others_intact = true;
      for (size_t i = 1u; i < sc->finals; ++i) {
        const signed_final *other = &sc->finals_data[i];
        if (other->pool.ready != 1u || other->pool.active_leases != 1u ||
            other->pool.sealed) others_intact = false;
      }
      check_true(others_intact);
      if (sc->finals_data[0].pool.terminal_waiting_for_leases == 1u ||
          cmeta_monotonic_ms() >= deadline) break;
    }
    check_equal((size_t)1u,
                sc->finals_data[0].pool.terminal_waiting_for_leases);
    check_equal((size_t)1u, sc->finals_data[0].pool.active_leases);
  }
  submit(sc, 1u, host_finish_runtime);
  barrier(sc);
  refresh(sc, 1u);
  for (size_t i = 1u; i < sc->finals; ++i) {
    const signed_final *f = &sc->finals_data[i];
    check_equal(1u, f->server.established);
    check_equal((size_t)1u, f->pool.ready);
    check_equal((size_t)1u, f->pool.active_leases);
    check_true(!f->pool.sealed);
  }

  /* Stop the other independently hosted Runtimes concurrently. */
  for (size_t i = 2u; i < sc->shards; ++i)
    submit(sc, i, host_stop_retaining);
  barrier(sc);
  until_terminals(sc, 1u);
  for (size_t i = 2u; i < sc->shards; ++i)
    submit(sc, i, host_finish_runtime);
  barrier(sc);

  for (size_t i = 0u; i < sc->finals; ++i)
    check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
        mesh_mgmt_agent_runtime_destroy_v2(&sc->finals_data[i].client.runtime));

  check_equal(P2P_OK, p2p_cnet_sg_seal_v1(sc->handoff));
  for (size_t i = 0u; i < sc->shards; ++i)
    submit(sc, i, host_stop_owner);
  barrier(sc);
  const uint64_t stop_deadline = cmeta_monotonic_ms() + SG_MULTI_TIMEOUT_MS;
  for (;;) {
    bool finished = true;
    for (size_t i = 0u; i < sc->shards; ++i) {
      if (sc->lanes[i].stopped) continue;
      finished = false;
      submit(sc, i, host_progress);
    }
    if (finished || cmeta_monotonic_ms() >= stop_deadline) break;
    barrier(sc);
    for (size_t i = 0u; i < sc->shards; ++i)
      if (!sc->lanes[i].stopped)
        submit(sc, i, host_stop_owner);
    barrier(sc);
    cmeta_sleep_ms(1u);
  }
  for (size_t i = 0u; i < sc->shards; ++i)
    check_true(sc->lanes[i].stopped);
  check_equal(P2P_OK, p2p_cnet_sg_destroy_v1(sc->handoff));
  sc->handoff = NULL;
  for (size_t i = 0u; i < sc->shards; ++i)
    submit(sc, i, host_destroy);
  barrier(sc);
  for (size_t i = 0u; i < sc->shards; ++i)
    check_true(sc->lanes[i].released);
  check_equal(SALTS_OK, native_io_sharded_shutdown(sc->host));
  check_equal(SALTS_OK, native_io_sharded_destroy(sc->host));
}

spec("Concurrent signed MMP ClientPools on real CNet SG final Owners") {
  it("isolates 2 final Managers, signed READY and leases on 3 actual SG workers") {
    test_multi_final(2u);
  }
  it("isolates 4 final Managers, signed READY and leases on 5 actual SG workers") {
    test_multi_final(4u);
  }
}
