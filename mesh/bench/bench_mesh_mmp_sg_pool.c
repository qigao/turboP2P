/* Opt-in experiment: equal-load REAL signed Noise/MMP ClientPool on
 * 1 / 2 / 4 independent SG Final Owners (PLUS one SG acceptor).
 *
 * Exactly four distinct authenticated clients, same total CNet/Pool
 * capacity budget (4 connections) and same per-client encrypted custom
 * P2P echo traffic across all topologies. Each Final must acquire/release
 * its real signed ClientPool Lease before QUEUEING an echo reply.
 *
 * This is signed-MMP-READY-gated P2P data-plane echo with Lease admission,
 * NOT MMP execution RPC latency, full send-terminal Lease accounting, nor
 * a raw-CNet baseline. Keep these separately labeled in comparisons.
 *
 * The SG Host is the sole NativeIO observer. No Actor, fallback backend,
 * replay, independent retry timer or per-consumer observe is introduced. */
#define _POSIX_C_SOURCE 200809L
#include <tinytest.h>
#include "mesh_mgmt_agent_runtime.h"
#include "mesh_mgmt_test_identity.h"
#include "core/node_cnet.h"
#include "core/node_state.h"
#include <cnet/sg_host.h>
#include <salts/native_io_sharded.h>
#include <salts/clock.h>
#include <salts/thread.h>
#include <inttypes.h>
#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>

#ifndef BENCH_MMP_FINALS
#error BENCH_MMP_FINALS must be 1, 2 or 4
#endif
#if BENCH_MMP_FINALS != 1 && BENCH_MMP_FINALS != 2 && BENCH_MMP_FINALS != 4
#error Unsupported BENCH_MMP_FINALS
#endif
#ifndef BENCH_ASYNC_PROGRESS
#define BENCH_ASYNC_PROGRESS 0
#endif
#if BENCH_ASYNC_PROGRESS != 0 && BENCH_ASYNC_PROGRESS != 1
#error BENCH_ASYNC_PROGRESS must be 0 or 1
#endif
#ifndef BENCH_APP_INDEPENDENT
#define BENCH_APP_INDEPENDENT 0
#endif
#if BENCH_APP_INDEPENDENT != 0 && BENCH_APP_INDEPENDENT != 1
#error BENCH_APP_INDEPENDENT must be 0 or 1
#endif
#define BENCH_DRIVER_LABEL (BENCH_APP_INDEPENDENT ? \
    (BENCH_ASYNC_PROGRESS ? "owner-independent-app-independent" \
                          : "global-barrier-app-independent") \
    : (BENCH_ASYNC_PROGRESS ? "owner-independent" : "global-barrier"))
enum {
  BENCH_SESSIONS = 4,
  BENCH_FINALS = BENCH_MMP_FINALS,
  BENCH_SHARDS = BENCH_FINALS + 1,
  BENCH_PER_FINAL = BENCH_SESSIONS / BENCH_FINALS,
  BENCH_BYTES_MAX = 1024,
  BENCH_TIMEOUT_MS = 15000
};
typedef struct benchmark_case benchmark_case;
typedef struct bench_final bench_final;

typedef struct {
  benchmark_case *scenario;
  mesh_mgmt_agent_runtime_v1_t runtime;
  mesh_mgmt_agent_runtime_config_v1_t cfg;
  mesh_mgmt_p2p_peer_config_v1_t identity;
  runtime_callbacks_t random;
  p2p_runtime_config_v2_t network;
  p2p_peer_t *peer;
  uint8_t private_key[32], public_key[32];
  uint8_t request[BENCH_BYTES_MAX];
  size_t bytes, round, next_to_send, warmup, rounds;
  uint64_t sent_ns, *samples;
  size_t authenticated, received, invalid, unexpected_closes;
} bench_client;

typedef struct {
  benchmark_case *scenario;
  size_t shard;
  native_io_sharded_host_lease lease;
  native_io_backend *backend;
  p2p_cnet_owner_t *acceptor, *final_transport;
  cnet_stream_peer listener;
  const void *token;
  size_t turns, stop_retries;
  int stopped, released, error;
  const char *where;
#if BENCH_ASYNC_PROGRESS
  /* Exactly one SG Host observe/progress per worker at any instant.
   * The finalize callback returns the scheduling token on completion. */
  atomic_bool progress_ready;
  atomic_int cancel_status;
  atomic_int owner_failed;
#endif
} bench_lane;

struct bench_final {
  benchmark_case *scenario;
  bench_lane *lane;
  mesh_mgmt_agent_runtime_v1_t runtime;
  mesh_mgmt_agent_runtime_config_v1_t cfg;
  mesh_mgmt_p2p_peer_config_v1_t identity;
  runtime_callbacks_t random;
  mesh_mgmt_p2p_security_provider_v2_t security;
  p2p_node_t *node;
  p2p_node_cnet_t *owner;
  uint8_t private_key[32], public_key[32];
  p2p_peer_t *peers[BENCH_SESSIONS];
  uint8_t pending_frame[BENCH_SESSIONS][BENCH_BYTES_MAX];
  size_t pending_size[BENCH_SESSIONS];
  size_t signed_ready, echo_enqueued, leases, unexpected_closes;
  cnet_pool_snapshot pool;
};

struct benchmark_case {
  native_io_sharded *host;
  p2p_cnet_sg_t *sg;
  bench_lane lanes[BENCH_SHARDS];
  bench_final finals[BENCH_FINALS];
  bench_client clients[BENCH_SESSIONS];
  size_t warmup, rounds, bytes;
  int stopping;
};

static native_io_backend_kind backend_kind(void) {
#if defined(_WIN32)
  return NATIVE_IO_BACKEND_IOCP;
#elif defined(__APPLE__)
  return NATIVE_IO_BACKEND_KQUEUE;
#else
  return NATIVE_IO_BACKEND_EPOLL;
#endif
}
static uint64_t clock_ns(clockid_t clock_kind) {
  struct timespec t={0};
  check_equal(0, clock_gettime(clock_kind,&t));
  return (uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;
}
static void bench_error(bench_lane *lane,int code,const char *where) {
  if (!lane->error) {lane->error=code;lane->where=where;}
#if BENCH_ASYNC_PROGRESS
  atomic_store_explicit(&lane->owner_failed,code,memory_order_release);
#endif
}
#define BC(lane, expr) do { \
  int status_=(expr); \
  if (status_!=0) {bench_error((lane),status_,#expr);return;} \
} while(0)

static uint64_t env_count(const char *name,uint64_t default_value,uint64_t maximum) {
  const char *v=getenv(name);
  char *end=NULL;
  unsigned long long n;
  if (!v||!*v) return default_value;
  errno=0;
  n=strtoull(v,&end,10);
  if (errno||end==v||*end||n<1u||n>maximum) {
    fprintf(stderr,"Invalid %s=%s (1..%" PRIu64 ")\n",name,v,maximum);
    exit(2);
  }
  return (uint64_t)n;
}
static int cmp_u64(const void *a,const void *b) {
  uint64_t x=*(const uint64_t*)a,y=*(const uint64_t*)b;
  return (x>y)-(x<y);
}
static uint64_t pct(const uint64_t *samples,size_t count,unsigned percentile) {
  size_t rank=(count*percentile+99u)/100u;
  return samples[rank?rank-1u:0u];
}
static void frame_for_client(uint8_t *dst,size_t length,size_t client,size_t round) {
  memset(dst,0,length);
  dst[0]='E';dst[1]='C';dst[2]='H';dst[3]='O';
  dst[4]=(uint8_t)(client+1u);
  dst[5]=(uint8_t)round;
  dst[6]=(uint8_t)(round>>8);
  dst[7]=(uint8_t)(client ^ round ^ 0x5Au);
  for (size_t j=8u;j<length;++j)
    dst[j]=(uint8_t)(j ^ (round*31u) ^ (client*17u));
}
static void init_identity(bench_client *c,uint8_t seed) {
  uint8_t management_key[32]={0};
  c->private_key[0]=seed;
  management_key[0]=(uint8_t)(seed+1u);
  c->random.next_message_byte=seed;
  check_equal(P2P_OK,p2p_public_key_from_private_key(c->private_key,c->public_key));
  check_equal(0,prepare_runtime_config(&c->identity,NULL,NULL,
      c->public_key,management_key,seed,seed,seed,seed,&c->random));
  check_equal(P2P_OK,p2p_runtime_config_v2_init(&c->network));
  c->network.receive_buffer_bytes=97u;
  c->network.stop_timeout_ms=500u;
  c->cfg.listen_host="127.0.0.1";
  c->cfg.p2p_private_key=c->private_key;
  c->cfg.max_peers=2u;
  c->cfg.signer_template=&c->identity.signer;
  c->cfg.dispatch_template=&c->identity.dispatch;
  c->cfg.endpoint_capacity=2u;
  c->cfg.retry_base_ms=60000u; /* failure = failfast, never replay in a run */
  c->cfg.retry_max_ms=60000u;
  c->cfg.connect_timeout_ms=5000u;
  c->cfg.protocol_failure_limit=2u;
  c->cfg.first_endpoint_record_epoch=1u;
  c->cfg.first_service_record_epoch=1u;
}
static int client_admit(void *ctx,p2p_peer_t *peer,const uint8_t key[32],
                        const mesh_mgmt_dispatch_event_v1_t *e) {
  (void)ctx;(void)peer;(void)key;(void)e;
  return 0;
}
static void client_closed(void *ctx,p2p_peer_t *peer,const uint8_t key[32],
                          mesh_mgmt_agent_router_close_reason_t reason) {
  bench_client *c=(bench_client*)ctx;
  if (!c->scenario->stopping && c->authenticated) {
    ++c->unexpected_closes;
    ++c->invalid;
    fprintf(stderr,"Unexpected signed client close: peer=%p reason=%d "
            "auth_count=%zu key_prefix=%02x%02x\n",
            (void *)peer,(int)reason,c->authenticated,
            (unsigned)key[0],(unsigned)key[1]);
  }
}
static int client_session(void *ctx,p2p_peer_t *peer,const uint8_t key[32],
                          const mesh_mgmt_dispatch_event_v1_t *event) {
  bench_client *c=(bench_client*)ctx;
  (void)key;
  if (event->type==MESH_MGMT_DISPATCH_EVENT_SESSION_ESTABLISHED) {
    c->peer=peer;
    c->authenticated++;
  }
  return 0;
}
static void client_echo(void *ctx,p2p_node_t *node,p2p_peer_t *peer,
                        const void *data,size_t length) {
  bench_client *c=(bench_client*)ctx;
  (void)node;
  if (peer!=c->peer||length!=c->bytes||
      memcmp(c->request,data,length)!=0||c->sent_ns==0u ||
      c->received!=c->round) {
    c->invalid++;
    return;
  }
  uint64_t elapsed=clock_ns(CLOCK_MONOTONIC)-c->sent_ns;
  if (c->round>=c->warmup)
    c->samples[c->round-c->warmup]=elapsed;
  c->received++;
}
static int server_admit(void *ctx,p2p_peer_t *peer,const uint8_t key[32],
                        const mesh_mgmt_dispatch_event_v1_t *event) {
  (void)ctx;(void)peer;(void)key;(void)event;
  return 0;
}
static int server_session(void *ctx,p2p_peer_t *peer,const uint8_t key[32],
                          const mesh_mgmt_dispatch_event_v1_t *event) {
  bench_final *f=(bench_final*)ctx;
  if (event->type!=MESH_MGMT_DISPATCH_EVENT_SESSION_ESTABLISHED)
    return 0;
  for (size_t i=0;i<BENCH_SESSIONS;++i) {
    if (memcmp(key,f->scenario->clients[i].public_key,32u)) continue;
    if ((i%BENCH_FINALS)!=f->lane->shard-1u || f->peers[i]) {
      fprintf(stderr,"Signed SG mismatch: final=%zu client=%zu expected_final=%zu "
              "seen_sessions=%zu existing_peer=%p incoming_peer=%p "
              "client_auth=%zu transport_key_prefix=%02x%02x\n",
              f->lane->shard-1u,i,i%BENCH_FINALS,f->signed_ready,
              (void *)f->peers[i],(void *)peer,
              f->scenario->clients[i].authenticated,
              (unsigned)key[0],(unsigned)key[1]);
      bench_error(f->lane,P2P_ERR_INVALID_STATE,"wrong signed Final mapping");
      return -1;
    }
    f->peers[i]=peer;
    f->signed_ready++;
    return 0;
  }
  bench_error(f->lane,P2P_ERR_INVALID_STATE,"unrecognized signed peer");
  return -1;
}
static void server_closed(void *ctx,p2p_peer_t *peer,const uint8_t key[32],
                          mesh_mgmt_agent_router_close_reason_t reason) {
  bench_final *f=(bench_final*)ctx;
  if (!f->scenario->stopping && f->signed_ready) {
    size_t client=BENCH_SESSIONS;
    for (size_t i=0u;i<BENCH_SESSIONS;++i)
      if (f->peers[i]==peer) {client=i;break;}
    ++f->unexpected_closes;
    fprintf(stderr,"Unexpected signed Final close: final=%zu client=%zu "
            "peer=%p reason=%d sessions=%zu key_prefix=%02x%02x\n",
            f->lane->shard-1u,client,(void *)peer,(int)reason,
            f->signed_ready,(unsigned)key[0],(unsigned)key[1]);
    bench_error(f->lane,P2P_ERR_INVALID_STATE,"unexpected signed peer close");
  }
}
static void server_echo(void *ctx,p2p_node_t *node,p2p_peer_t *peer,
                        const void *data,size_t length) {
  bench_final *f=(bench_final*)ctx;
  (void)node;
  for (size_t i=0;i<BENCH_SESSIONS;++i) {
    if (f->peers[i]!=peer || !peer) continue;
    if (f->pending_size[i] || length!=f->scenario->bytes ||
        length>BENCH_BYTES_MAX || length<8u) {
      bench_error(f->lane,P2P_ERR_INVALID_STATE,"duplicate/invalid echo request");
      return;
    }
    memcpy(f->pending_frame[i],data,length);
    f->pending_size[i]=length;
    return;
  }
  bench_error(f->lane,P2P_ERR_INVALID_STATE,"unsigned echo request");
}
static int random_bytes(void *ctx,uint8_t *out,size_t length) {
  runtime_callbacks_t *r=(runtime_callbacks_t*)ctx;
  return runtime_random_bytes(r,out,length);
}
static void init_final(bench_final *f,size_t index) {
  uint8_t management_key[32]={0};
  f->private_key[0]=17u; /* SAME synthetic test server identity all Finals */
  management_key[0]=18u;
  f->random.next_message_byte=(uint8_t)(17u+index*31u);
  check_equal(P2P_OK,p2p_public_key_from_private_key(
      f->private_key,f->public_key));
  /* Template random/callback context MUST reference persistent final Owner
   * storage, never a temporary fixture copied from the stack. */
  check_equal(0,prepare_runtime_config(&f->identity,NULL,NULL,
      f->public_key,management_key,17u,17u,17u,17u,&f->random));
  f->cfg.max_peers=BENCH_PER_FINAL;
  f->cfg.endpoint_capacity=BENCH_PER_FINAL;
  f->cfg.signer_template=&f->identity.signer;
  f->cfg.dispatch_template=&f->identity.dispatch;
  f->cfg.retry_base_ms=60000u;
  f->cfg.retry_max_ms=60000u;
  f->cfg.connect_timeout_ms=5000u;
  f->cfg.protocol_failure_limit=2u;
  f->cfg.first_endpoint_record_epoch=1u;
  f->cfg.first_service_record_epoch=1u;
  f->cfg.admit_peer=server_admit;
  f->cfg.on_event=server_session;
  f->cfg.on_peer_closed=server_closed;
  f->cfg.on_non_mmp=server_echo;
  f->cfg.callback_context=f;
  f->cfg.random_bytes=random_bytes;
  f->cfg.random_context=&f->random;
}
static p2p_cnet_config_t native_config(size_t connection_capacity) {
  p2p_cnet_config_t cfg={0};
  cfg.client.backend=backend_kind();
  cfg.client.connection_capacity=connection_capacity;
  cfg.client.command_capacity=32u;
  cfg.client.request_capacity=32u;
  cfg.client.completion_batch_capacity=8u;
  cfg.client.event_capacity=32u;
  cfg.client.max_send_bytes=128u*1024u;
  cfg.client.receive_buffer_bytes=97u;
  cfg.client.connect_timeout_ms=5000u;
  cfg.client.write_timeout_ms=5000u;
  cfg.send_hwm_bytes=128u*1024u;
  cfg.pending_write_limit=8u;
  cfg.accept_budget=4u;
  cfg.stop_timeout_ms=5000u;
  return cfg;
}
static bool quiescent(void *ctx) {
  const bench_lane *lane=(const bench_lane*)ctx;
  return lane->released && lane->acceptor==NULL &&
         lane->final_transport==NULL;
}
static int not_direct(p2p_cnet_owner_t *owner,p2p_connection_t *conn,
                      const cnet_stream_peer *peer,void *ctx) {
  (void)owner;(void)conn;(void)peer;
  bench_error((bench_lane*)ctx,P2P_ERR_INVALID_STATE,"acceptor local adopt");
  return P2P_ERR_INVALID_STATE;
}
static void init_worker(native_io_sharded_context *ctx,void *arg) {
  bench_lane *lane=(bench_lane*)arg;
  benchmark_case *sc=lane->scenario;
  p2p_cnet_config_t cfg=native_config(
      lane->shard?BENCH_PER_FINAL:8u);
  lane->token=cmeta_thread_current_token();
  BC(lane,native_io_sharded_context_acquire_host(
      ctx,quiescent,lane,&lane->lease,&lane->backend));
  if (!lane->shard) {
    BC(lane,p2p_cnet_owner_create_external(
        &cfg,lane->backend,lane->lease,&lane->acceptor));
    BC(lane,p2p_cnet_owner_listen(
        lane->acceptor,"127.0.0.1",0u,16u,not_direct,lane,&lane->listener));
    return;
  }
  bench_final *f=&sc->finals[lane->shard-1u];
  mesh_mgmt_p2p_security_config_v2_t trust={0};
  p2p_security_config_v2_t security={0};
  f->node=p2p_node_state_create("127.0.0.1",0);
  if (!f->node) {bench_error(lane,P2P_ERR_NO_MEM,"new Final node");return;}
  BC(lane,p2p_node_set_private_key(f->node,f->private_key));
  trust.local_certificate=f->identity.signer.hello.certificate;
  trust.local_certificate_len=sizeof(f->identity.signer.hello.certificate);
  trust.trusted_issuer_key=f->identity.dispatch.session.trusted_issuer_key;
  trust.mesh_id_hash=f->identity.dispatch.session.expected_mesh_id_hash;
  trust.now_ms=f->identity.signer.now_ms;
  trust.now_context=f->identity.signer.callback_context;
  BC(lane,mesh_mgmt_p2p_security_provider_init_v2(
      &f->security,&trust,&security));
  security.handshake_timeout_ms=5000u;
  security.ready_timeout_ms=5000u;
  security.send_hwm_bytes=cfg.send_hwm_bytes;
  security.node_send_budget_bytes=cfg.send_hwm_bytes*4u;
  /* Encrypted session lifetime is distinct from the 128-KiB SEND HWM.
   * An earlier fixture wrongly used send_hwm_bytes as the cumulative
   * Noise wire-byte ceiling, closing sessions halfway through the 1024B
   * x 256-round workload. Zero uses upstream 24h / 1TiB defaults, also
   * used by the dedicated signed clients. All topologies match. */
  security.session_max_age_ms=0u;
  security.session_max_bytes_per_direction=0u;
  security.cookie_gate_limit=16u;
  security.cookie_lifetime_ms=5000u;
  security.cookie_key_rotation_ms=10000u;
  security.source_admission_burst=16u;
  security.source_admission_refill_per_second=1u;
  security.source_admission_bucket_limit=16u;
  BC(lane,p2p_node_configure_security_v2(f->node,&security));
  BC(lane,p2p_node_cnet_create_external(
      f->node,&cfg,lane->backend,lane->lease,&f->owner));
  BC(lane,p2p_node_cnet_bind_handoff_accept(f->owner));
  lane->final_transport=p2p_node_cnet_transport_owner(f->owner);
  if (!lane->final_transport)
    bench_error(lane,P2P_ERR_INVALID_STATE,"missing SG final transport");
}
static void init_runtime(native_io_sharded_context *ctx,void *arg) {
  bench_lane *lane=(bench_lane*)arg;
  if (!lane->shard||lane->error) return;
  bench_final *f=&lane->scenario->finals[lane->shard-1u];
  BC(lane,mesh_mgmt_agent_runtime_init_sg_final_v3(
      &f->runtime,&f->cfg,f->node,f->owner,ctx,lane->lease));
  BC(lane,mesh_mgmt_agent_runtime_enable_signed_pool_v3(
      &f->runtime,(uint64_t)(700u+lane->shard),
      BENCH_PER_FINAL,BENCH_PER_FINAL));
  BC(lane,mesh_mgmt_agent_runtime_start_v1(&f->runtime));
}
static void flush_replies(bench_lane *lane) {
  bench_final *f=&lane->scenario->finals[lane->shard-1u];
  for (size_t i=0;i<BENCH_SESSIONS;++i) {
    if (!f->pending_size[i]) continue;
    cnet_pool_lease lease={0};
    int status=mesh_mgmt_agent_runtime_signed_pool_acquire_v3(
        &f->runtime,f->peers[i],&lease);
    if (status!=MESH_MGMT_AGENT_RUNTIME_OK || !lease.slot) {
      bench_error(lane,status?status:P2P_ERR_INVALID_STATE,
                  "signed ClientPool Lease admission");
      return;
    }
    status=p2p_send_message(f->node,f->peers[i],P2P_MSG_CUSTOM,
                            f->pending_frame[i],f->pending_size[i]);
    if (status!=P2P_OK) {
      bench_error(lane,status,"encrypted echo enqueue");
      /* still return real Lease, but this benchmark run will fail */
    } else {
      f->echo_enqueued++;
    }
    const int released=mesh_mgmt_agent_runtime_signed_pool_release_v3(
        &f->runtime,lease);
    if (released!=MESH_MGMT_AGENT_RUNTIME_OK) {
      bench_error(lane,released,"signed Pool Lease return");
      return;
    }
    f->leases++;
    f->pending_size[i]=0u;
    if (status!=P2P_OK) return;
  }
}
static void progress(native_io_sharded_context *ctx,void *arg) {
  bench_lane *lane=(bench_lane*)arg;
  size_t observed=0u,settled=0u;
  if (lane->error||lane->stopped) return;
  if (native_io_sharded_context_shard(ctx)!=lane->shard ||
      cmeta_thread_current_token()!=lane->token) {
    bench_error(lane,SALTS_EPERM,"foreign SG worker");return;
  }
  if (!lane->shard) {
    BC(lane,p2p_cnet_owner_poll_sg_host(
        lane->acceptor,ctx,lane->lease,&observed,&settled));
  } else if (lane->stop_retries) {
    BC(lane,p2p_cnet_owner_poll_sg_host(
        lane->final_transport,ctx,lane->lease,&observed,&settled));
  } else {
    bench_final *f=&lane->scenario->finals[lane->shard-1u];
    BC(lane,p2p_node_cnet_poll_sg_host(
        f->owner,ctx,lane->lease,&observed,&settled));
    if (f->runtime.state==MESH_MGMT_AGENT_RUNTIME_RUNNING ||
        f->runtime.state==MESH_MGMT_AGENT_RUNTIME_STOPPING)
      BC(lane,mesh_mgmt_agent_runtime_sg_final_advance_v3(
          &f->runtime,ctx,lane->lease));
    if (f->runtime.state==MESH_MGMT_AGENT_RUNTIME_RUNNING)
      flush_replies(lane);
  }
  ++lane->turns;
}
static void snapshot(native_io_sharded_context *ctx,void *arg) {
  bench_lane *lane=(bench_lane*)arg;
  (void)ctx;
  if (!lane->shard||lane->error) return;
  bench_final *f=&lane->scenario->finals[lane->shard-1u];
  BC(lane,mesh_mgmt_agent_runtime_signed_pool_snapshot_v3(
      &f->runtime,&f->pool));
}
static void stop_runtime(native_io_sharded_context *ctx,void *arg) {
  bench_lane *lane=(bench_lane*)arg;
  (void)ctx;
  if (!lane->shard||lane->error) return;
  bench_final *f=&lane->scenario->finals[lane->shard-1u];
  BC(lane,mesh_mgmt_agent_runtime_destroy_v2(&f->runtime));
  if (f->runtime.node || !f->node || !f->owner)
    bench_error(lane,P2P_ERR_INVALID_STATE,"Final Runtime freed P2P Owner");
}
static void stop_worker(native_io_sharded_context *ctx,void *arg) {
  bench_lane *lane=(bench_lane*)arg;
  if (native_io_sharded_context_shard(ctx)!=lane->shard ||
      lane->stopped||lane->error) return;
  const int status=!lane->shard
    ?p2p_cnet_owner_stop(lane->acceptor)
    :p2p_node_cnet_stop(lane->scenario->finals[lane->shard-1u].owner);
  if (status==P2P_ERR_INVALID_STATE) {++lane->stop_retries;return;}
  if (status!=P2P_OK) {bench_error(lane,status,"P2P SG stop");return;}
  lane->stopped=1;
}
static void destroy_worker(native_io_sharded_context *ctx,void *arg) {
  bench_lane *lane=(bench_lane*)arg;
  if (native_io_sharded_context_shard(ctx)!=lane->shard ||
      cmeta_thread_current_token()!=lane->token||lane->error) {
    bench_error(lane,SALTS_EPERM,"destroy wrong worker");return;
  }
  if (!lane->shard) {
    BC(lane,p2p_cnet_owner_destroy(lane->acceptor));
    lane->acceptor=NULL;
  } else {
    bench_final *f=&lane->scenario->finals[lane->shard-1u];
    BC(lane,p2p_node_cnet_destroy(f->owner));
    f->owner=NULL;
    lane->final_transport=NULL;
    BC(lane,p2p_node_state_destroy(f->node));
    f->node=NULL;
    mesh_mgmt_p2p_security_provider_destroy_v2(&f->security);
  }
  lane->released=1;
  BC(lane,native_io_sharded_context_release_host(ctx,lane->lease));
  lane->backend=NULL;
}
static void submit(benchmark_case *sc,size_t shard,native_io_sharded_task_fn fn) {
  native_io_sharded_task task={fn,NULL,NULL,&sc->lanes[shard]};
  check_equal(SALTS_OK,native_io_sharded_submit_to(sc->host,shard,&task));
}
static void barrier(benchmark_case *sc) {
  check_equal(SALTS_OK,native_io_sharded_wait(sc->host));
  for (size_t i=0;i<BENCH_SHARDS;++i) {
    if (sc->lanes[i].error)
      fprintf(stderr,"MMP SG bench Final %u shard %zu error %d at %s\n",
        (unsigned)BENCH_FINALS,i,sc->lanes[i].error,
        sc->lanes[i].where?sc->lanes[i].where:"?");
    check_equal(0,sc->lanes[i].error);
  }
}
static void pump(benchmark_case *sc) {
  for (size_t i=0;i<BENCH_SESSIONS;++i)
    if (sc->clients[i].runtime.state==MESH_MGMT_AGENT_RUNTIME_RUNNING)
      check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
                  mesh_mgmt_agent_runtime_poll_v1(&sc->clients[i].runtime));
  for (size_t j=0;j<BENCH_SHARDS;++j) submit(sc,j,progress);
  barrier(sc);
}
#if BENCH_ASYNC_PROGRESS
/* The coordinator never invokes a NativeIO observe or waits across SG
 * shards in a measured round. Bounded per-lane tasks become eligible for
 * resubmission only AFTER their original worker finalize callback. */
static void progress_cancel(void *ctx,int status) {
  bench_lane *lane=(bench_lane*)ctx;
  atomic_store_explicit(&lane->cancel_status,status,memory_order_relaxed);
}
static void progress_finalize(void *ctx) {
  bench_lane *lane=(bench_lane*)ctx;
  atomic_store_explicit(&lane->progress_ready,true,memory_order_release);
}
static void pump_independent(benchmark_case *sc) {
  for (size_t i=0u;i<BENCH_SESSIONS;++i)
    if (sc->clients[i].runtime.state==MESH_MGMT_AGENT_RUNTIME_RUNNING)
      check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
                  mesh_mgmt_agent_runtime_poll_v1(&sc->clients[i].runtime));
  for (size_t shard=0u;shard<BENCH_SHARDS;++shard) {
    bench_lane *lane=&sc->lanes[shard];
    check_equal(0,atomic_load_explicit(&lane->owner_failed,memory_order_acquire));
    check_equal(0,atomic_load_explicit(&lane->cancel_status,memory_order_relaxed));
    if (!atomic_exchange_explicit(&lane->progress_ready,false,memory_order_acq_rel))
      continue;
    native_io_sharded_task task={
      progress,progress_cancel,progress_finalize,lane
    };
    const int status=native_io_sharded_try_submit_to(sc->host,shard,&task);
    if (status!=SALTS_OK) {
      /* A rejected bounded task owns neither NativeIO completion nor lease.
       * Return the token, but never fallback to independent event polling. */
      atomic_store_explicit(&lane->progress_ready,true,memory_order_release);
      if (status!=SALTS_ENOBUFS) check_equal(SALTS_OK,status);
    }
  }
}
static void finish_independent(benchmark_case *sc) {
  /* Setup and teardown use barriers; the measured hot path has no global
   * NativeIO wait until the final completed application echo batch. */
  barrier(sc);
  for (size_t shard=0u;shard<BENCH_SHARDS;++shard) {
    bench_lane *lane=&sc->lanes[shard];
    check_true(atomic_load_explicit(&lane->progress_ready,memory_order_acquire));
    check_equal(0,atomic_load_explicit(&lane->owner_failed,memory_order_acquire));
    check_equal(0,atomic_load_explicit(&lane->cancel_status,memory_order_relaxed));
  }
}
#define BENCH_MEASURE_PUMP(s) pump_independent(s)
#define BENCH_MEASURE_FINISH(s) finish_independent(s)
#define BENCH_MEASURE_BOUNDARY(s) finish_independent(s)
#else
#define BENCH_MEASURE_PUMP(s) pump(s)
#define BENCH_MEASURE_FINISH(s) ((void)0)
#define BENCH_MEASURE_BOUNDARY(s) ((void)0)
#endif
static void snapshot_all(benchmark_case *sc) {
  for (size_t j=1u;j<BENCH_SHARDS;++j) submit(sc,j,snapshot);
  barrier(sc);
}
static void run_rounds(benchmark_case *sc) {
  const size_t total=sc->warmup+sc->rounds;
  uint64_t wall0=0,cpu0=0;
#if BENCH_APP_INDEPENDENT
  /* This workload removes the GLOBAL APPLICATION per-round barrier. Each
   * of four signed clients maintains exactly ONE in-flight request at a
   * time and independently queues its next payload after its own echo.
   * Same per-session warmup + measured counts, immutable signed Pool
   * connection quota and no replay. No new IO observer or thread. */
  for (size_t phase=0u;phase<2u;++phase) {
    const size_t target=phase?total:sc->warmup;
    if (phase) {
      BENCH_MEASURE_BOUNDARY(sc);
      wall0=clock_ns(CLOCK_MONOTONIC);
      cpu0=clock_ns(CLOCK_PROCESS_CPUTIME_ID);
    }
    const uint64_t deadline=cmeta_monotonic_ms()+BENCH_TIMEOUT_MS;
    for (;;) {
      int all_done=1;
      for (size_t i=0u;i<BENCH_SESSIONS;++i) {
        bench_client *c=&sc->clients[i];
        check_equal((size_t)0u,c->invalid);
        check_true(c->received<=c->next_to_send &&
                   c->next_to_send<=target);
        if (c->received==c->next_to_send && c->next_to_send<target) {
          const size_t round=c->next_to_send;
          c->round=round;
          frame_for_client(c->request,sc->bytes,i,round);
          c->sent_ns=clock_ns(CLOCK_MONOTONIC);
          check_equal(P2P_OK,p2p_send_message(
              c->runtime.node,c->peer,P2P_MSG_CUSTOM,c->request,sc->bytes));
          c->next_to_send++;
        }
        if (c->received!=target) all_done=0;
      }
      if (all_done) break;
      check_true(cmeta_monotonic_ms()<deadline);
      BENCH_MEASURE_PUMP(sc);
    }
    for (size_t i=0u;i<BENCH_SESSIONS;++i) {
      check_equal(target,sc->clients[i].received);
      check_equal(target,sc->clients[i].next_to_send);
      check_equal((size_t)0u,sc->clients[i].invalid);
    }
  }
#else
  for (size_t round=0u;round<total;++round) {
    if (round==sc->warmup) {
      /* Equal measured work starts after the warmup worker tasks settle. */
      BENCH_MEASURE_BOUNDARY(sc);
      wall0=clock_ns(CLOCK_MONOTONIC);
      cpu0=clock_ns(CLOCK_PROCESS_CPUTIME_ID);
    }
    for (size_t i=0;i<BENCH_SESSIONS;++i) {
      bench_client *c=&sc->clients[i];
      c->round=round;
      frame_for_client(c->request,sc->bytes,i,round);
      c->sent_ns=clock_ns(CLOCK_MONOTONIC);
      check_equal(P2P_OK,p2p_send_message(
          c->runtime.node,c->peer,P2P_MSG_CUSTOM,c->request,sc->bytes));
    }
    const uint64_t deadline=cmeta_monotonic_ms()+BENCH_TIMEOUT_MS;
    for (;;) {
      int all_done=1;
      for (size_t i=0;i<BENCH_SESSIONS;++i)
        if (sc->clients[i].received<=round) all_done=0;
      if (all_done||cmeta_monotonic_ms()>=deadline) break;
      BENCH_MEASURE_PUMP(sc);
    }
    for (size_t i=0;i<BENCH_SESSIONS;++i) {
      check_equal(round+1u,sc->clients[i].received);
      check_equal((size_t)0u,sc->clients[i].invalid);
    }
  }
#endif
  BENCH_MEASURE_FINISH(sc);
  const uint64_t wall1=clock_ns(CLOCK_MONOTONIC);
  const uint64_t cpu1=clock_ns(CLOCK_PROCESS_CPUTIME_ID);
  const double wall=(double)(wall1-wall0)/1e9;
  const double cpu=(double)(cpu1-cpu0)/1e9;
  const double messages=(double)sc->rounds*BENCH_SESSIONS*2.0;
  const size_t nsamples=sc->rounds*BENCH_SESSIONS;
  uint64_t *combined=calloc(nsamples,sizeof(*combined));
  check_not_null(combined);
  for (size_t i=0;i<BENCH_SESSIONS;++i) {
    bench_client *c=&sc->clients[i];
    memcpy(combined+i*sc->rounds,c->samples,
           sc->rounds*sizeof(uint64_t));
    /* Preserve chronological raw roundtrips BEFORE percentile sort.
     * Emitted after the measured wall/CPU boundary: no printf in hot path. */
    for (size_t round=0u;round<sc->rounds;++round)
      printf("P2P_MMP_SG_RTT,%s,%u,%u,%u,%zu,%zu,%.3f\n",
          BENCH_DRIVER_LABEL,(unsigned)BENCH_FINALS,(unsigned)BENCH_SHARDS,
          (unsigned)(i+1u),sc->bytes,round+1u,
          (double)c->samples[round]/1000.0);
    qsort(c->samples,sc->rounds,sizeof(uint64_t),cmp_u64);
    printf("P2P_MMP_SG_SESSION,sg-signed-ready-data-echo,%s,"
           "%u,%u,%u,%zu,%zu,%.3f,%.3f,%.3f\n",
           BENCH_DRIVER_LABEL,(unsigned)BENCH_FINALS,(unsigned)BENCH_SHARDS,
           (unsigned)(i+1u),sc->bytes,sc->rounds,
           (double)pct(c->samples,sc->rounds,50u)/1000.0,
           (double)pct(c->samples,sc->rounds,95u)/1000.0,
           (double)pct(c->samples,sc->rounds,99u)/1000.0);
  }
  qsort(combined,nsamples,sizeof(uint64_t),cmp_u64);
  check_true(wall>0.0 && cpu>=0.0);
  printf("P2P_MMP_SG_BENCH,sg-signed-ready-data-echo,%s,"
         "%u,%u,%u,%zu,%zu,%zu,%.3f,%.3f,%.3f,%.3f,%.6f,"
         "%.3f,%.3f,%.3f\n",
         BENCH_DRIVER_LABEL,(unsigned)BENCH_FINALS,(unsigned)BENCH_SHARDS,
         (unsigned)BENCH_SESSIONS,sc->bytes,sc->rounds,sc->warmup,
         wall*1000.0,cpu*1000.0,cpu*100.0/wall,
         messages/wall,messages*(double)sc->bytes/(1048576.0*wall),
         (double)pct(combined,nsamples,50u)/1000.0,
         (double)pct(combined,nsamples,95u)/1000.0,
         (double)pct(combined,nsamples,99u)/1000.0);
  fflush(stdout);
  free(combined);
}
static void run_benchmark(void) {
  benchmark_case fixture={0};
  benchmark_case *sc=&fixture;
  const native_io_sharded_config settings={
    BENCH_SHARDS,8u,{backend_kind(),64u,128u,16u}};
  p2p_cnet_sg_config_v1_t policy={0};
  mesh_mgmt_agent_bootstrap_v1_t bootstrap={0};
  sc->warmup=(size_t)env_count("P2P_MMP_BENCH_WARMUP",16u,512u);
  sc->rounds=(size_t)env_count("P2P_MMP_BENCH_ROUNDS",128u,4096u);
  sc->bytes=(size_t)env_count("P2P_MMP_BENCH_PAYLOAD",8u,BENCH_BYTES_MAX);
  if (sc->bytes!=8u && sc->bytes!=1024u) {
    fprintf(stderr,"Payload must be 8 or 1024 bytes for matched profiles\n");
    exit(2);
  }
  for (size_t i=0;i<BENCH_FINALS;++i) {
    sc->finals[i].scenario=sc;
    sc->finals[i].lane=&sc->lanes[i+1u];
    init_final(&sc->finals[i],i);
  }
  for (size_t i=0;i<BENCH_SESSIONS;++i) {
    bench_client *c=&sc->clients[i];
    /* X25519 clamps the low three scalar bits: adjacent seeds do not
     * produce distinct transport public keys. Keep four true identities. */
    c->scenario=sc;
    init_identity(c,(uint8_t)(33u+16u*i));
    c->cfg.admit_peer=client_admit;
    c->cfg.on_event=client_session;
    c->cfg.on_peer_closed=client_closed;
    c->cfg.on_non_mmp=client_echo;
    c->cfg.callback_context=c;
    c->cfg.random_bytes=random_bytes;
    c->cfg.random_context=&c->random;
    c->rounds=sc->rounds;
    c->warmup=sc->warmup;
    c->bytes=sc->bytes;
    c->samples=calloc(sc->rounds,sizeof(uint64_t));
    check_not_null(c->samples);
    for (size_t earlier=0u;earlier<i;++earlier)
      check_true(memcmp(c->public_key,sc->clients[earlier].public_key,32u)!=0);
  }
  check_equal(SALTS_OK,native_io_sharded_create(&settings,&sc->host));
  for (size_t i=0;i<BENCH_SHARDS;++i) {
    sc->lanes[i].scenario=sc;
    sc->lanes[i].shard=i;
#if BENCH_ASYNC_PROGRESS
    atomic_init(&sc->lanes[i].progress_ready,true);
    atomic_init(&sc->lanes[i].cancel_status,0);
    atomic_init(&sc->lanes[i].owner_failed,0);
#endif
    submit(sc,i,init_worker);
  }
  barrier(sc);
  policy.size=sizeof(policy);
  policy.version=P2P_CNET_SG_VERSION;
  policy.acceptor=sc->lanes[0].acceptor;
  policy.placement=CNET_OWNER_PLACE_ROUND_ROBIN;
  policy.final_owner_count=BENCH_FINALS;
  /* SG Handoff limits are PER FINAL. Exactly four aggregate physical
   * credits and four signed Pool connection slots in every topology. */
  policy.queue_capacity=BENCH_PER_FINAL;
  policy.connection_capacity=BENCH_PER_FINAL;
  for (size_t i=0;i<BENCH_FINALS;++i)
    policy.final_owners[i]=sc->lanes[i+1u].final_transport;
  check_equal(P2P_OK,p2p_cnet_sg_create_v1(&policy,&sc->sg));
  for (size_t i=1u;i<BENCH_SHARDS;++i) submit(sc,i,init_runtime);
  barrier(sc);

  for (size_t i=0;i<BENCH_SESSIONS;++i) {
    bench_client *c=&sc->clients[i];
    memcpy(bootstrap.transport_peer_id,sc->finals[0].public_key,32u);
    bootstrap.host="127.0.0.1";
    bootstrap.port=sc->lanes[0].listener.port;
    c->cfg.bootstraps=&bootstrap;
    c->cfg.bootstrap_count=1u;
    check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
        mesh_mgmt_agent_runtime_init_v2(&c->runtime,&c->cfg,&c->network));
    c->cfg.bootstraps=NULL;
    c->cfg.bootstrap_count=0u;
    check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
        mesh_mgmt_agent_runtime_start_v1(&c->runtime));
    bench_final *f=&sc->finals[i%BENCH_FINALS];
    const uint64_t deadline=cmeta_monotonic_ms()+BENCH_TIMEOUT_MS;
    while ((!c->authenticated || !f->peers[i]) &&
           cmeta_monotonic_ms()<deadline)
      pump(sc);
    check_equal((size_t)1u,c->authenticated);
    check_not_null(f->peers[i]);
    check_equal((size_t)0u,c->invalid);
  }
  snapshot_all(sc);
  for (size_t i=0;i<BENCH_FINALS;++i) {
    bench_final *f=&sc->finals[i];
    check_equal((size_t)BENCH_PER_FINAL,f->signed_ready);
    check_equal((size_t)BENCH_PER_FINAL,f->pool.ready);
    check_equal((size_t)BENCH_PER_FINAL,f->pool.physical_in_use);
    check_equal((size_t)0u,f->pool.active_leases);
    p2p_cnet_sg_snapshot_v1_t handoff={0};
    check_equal(P2P_OK,p2p_cnet_sg_snapshot_v1(sc->sg,i,&handoff));
    check_equal((size_t)BENCH_PER_FINAL,handoff.handoff.taken);
    check_equal((size_t)0u,handoff.handoff.queued);
  }
  for (size_t i=0;i<BENCH_FINALS;++i)
    check_equal((size_t)0u,sc->finals[i].unexpected_closes);
  for (size_t i=0;i<BENCH_SESSIONS;++i)
    check_equal((size_t)0u,sc->clients[i].unexpected_closes);
  run_rounds(sc);
  /* Intentional application shutdown is not a benchmark reconnect. */
  sc->stopping=1;
  for (size_t i=0;i<BENCH_SESSIONS;++i)
    check_equal(MESH_MGMT_AGENT_RUNTIME_OK,
        mesh_mgmt_agent_runtime_destroy_v2(&sc->clients[i].runtime));

  const uint64_t drain_deadline=cmeta_monotonic_ms()+BENCH_TIMEOUT_MS;
  for (;;) {
    for (size_t j=0;j<BENCH_SHARDS;++j) submit(sc,j,progress);
    barrier(sc);
    snapshot_all(sc);
    int all_drained=1;
    for (size_t i=0;i<BENCH_FINALS;++i) {
      p2p_cnet_sg_snapshot_v1_t handoff={0};
      check_equal(P2P_OK,p2p_cnet_sg_snapshot_v1(sc->sg,i,&handoff));
      if (!sc->finals[i].pool.drained || handoff.handoff.taken!=0u)
        all_drained=0;
    }
    if (all_drained||cmeta_monotonic_ms()>=drain_deadline) break;
  }
  for (size_t i=0;i<BENCH_FINALS;++i) {
    check_true(sc->finals[i].pool.drained);
    check_equal((size_t)sc->rounds+sc->warmup,
                sc->finals[i].echo_enqueued/BENCH_PER_FINAL);
    check_equal(sc->finals[i].echo_enqueued,sc->finals[i].leases);
  }
  for (size_t j=1u;j<BENCH_SHARDS;++j) submit(sc,j,stop_runtime);
  barrier(sc);

  check_equal(P2P_OK,p2p_cnet_sg_seal_v1(sc->sg));
  for (size_t j=0;j<BENCH_SHARDS;++j) submit(sc,j,stop_worker);
  barrier(sc);
  const uint64_t stop_deadline=cmeta_monotonic_ms()+BENCH_TIMEOUT_MS;
  for (;;) {
    int all_stopped=1;
    for (size_t j=0;j<BENCH_SHARDS;++j) {
      if (sc->lanes[j].stopped) continue;
      all_stopped=0;
      submit(sc,j,progress);
    }
    if (all_stopped||cmeta_monotonic_ms()>=stop_deadline) break;
    barrier(sc);
    for (size_t j=0;j<BENCH_SHARDS;++j)
      if (!sc->lanes[j].stopped) submit(sc,j,stop_worker);
    barrier(sc);
  }
  for (size_t j=0;j<BENCH_SHARDS;++j) check_true(sc->lanes[j].stopped);
  check_equal(P2P_OK,p2p_cnet_sg_destroy_v1(sc->sg));
  for (size_t j=0;j<BENCH_SHARDS;++j) submit(sc,j,destroy_worker);
  barrier(sc);
  check_equal(SALTS_OK,native_io_sharded_shutdown(sc->host));
  check_equal(SALTS_OK,native_io_sharded_destroy(sc->host));
  for (size_t i=0;i<BENCH_SESSIONS;++i) free(sc->clients[i].samples);
}
spec("Equal-load four-session signed MMP SG ClientPool data echo (opt-in)") {
  it("uses real signed READY, owner-local Pool Leases and authenticated echo") {
    run_benchmark();
  }
}
