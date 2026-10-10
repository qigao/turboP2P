/* Opt-in pure P2P Noise TCP/NativeIO SG data echo benchmark.
 *
 * Exactly FOUR distinct clients authenticate with the production P2P
 * cookie/Noise handshake (pinned public keys; NO MMP Router or Pool).
 * NativeIO SG Host routes an acceptor's real detached socket to 1/2/4
 * final Owner workers using the original CNet SG Handoff credits.
 *
 * Four actual sessions and exactly four physical credits regardless of
 * Final count. Same 8B / 1024B application echo frames, warmups, rounds
 * and output schema as raw-CNet and post-MMP-ready stages. No artificial
 * authentication, direct raw socket fallback, Actor, second observer, or
 * reconnect/replay.
 *
 * Synthetic same-server-key across distinct Final workers is TEST ONLY:
 * it isolates Noise/P2P framing from MMP and must never prescribe shared
 * private key distribution for production deployment. */
#define _POSIX_C_SOURCE 200809L
#include <tinytest.h>
#include "core/node_cnet.h"
#include "core/node_state.h"
#include "core/peer_cnet.h"
#include <cnet/sg_host.h>
#include <salts/native_io_sharded.h>
#include <salts/clock.h>
#include <salts/thread.h>
#include <time.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>

#ifndef NOISE_BENCH_FINALS
#error NOISE_BENCH_FINALS must be 1, 2, or 4
#endif
#if NOISE_BENCH_FINALS != 1 && NOISE_BENCH_FINALS != 2 && NOISE_BENCH_FINALS != 4
#error Unsupported NOISE_BENCH_FINALS
#endif
#ifndef NOISE_ASYNC_PROGRESS
#define NOISE_ASYNC_PROGRESS 0
#endif
#if NOISE_ASYNC_PROGRESS != 0 && NOISE_ASYNC_PROGRESS != 1
#error Invalid NOISE_ASYNC_PROGRESS
#endif
#define NOISE_DRIVER_LABEL (NOISE_ASYNC_PROGRESS ? "owner-independent" : "global-barrier")
enum { NOISE_SESSIONS=4, NOISE_FINALS=NOISE_BENCH_FINALS,
       NOISE_SHARDS=NOISE_FINALS+1, NOISE_PER_FINAL=NOISE_SESSIONS/NOISE_FINALS,
       NOISE_PAYLOAD_MAX=1024, NOISE_BATCH=16, NOISE_WAIT_MS=15000 };
typedef struct noise_case noise_case;
typedef struct noise_final noise_final;
typedef struct noise_lane noise_lane;
/* Kept for the full P2P Node lifetime, as the real Noise handshake
 * synchronously invokes its borrowed identity provider callbacks. */
typedef struct noise_test_identity {
  uint8_t public_key[32];
  uint8_t allowed[NOISE_SESSIONS][32];
  uint8_t remote_principal_seeds[NOISE_SESSIONS];
  size_t count;
  p2p_authenticated_identity_v2_t principal;
} noise_test_identity;

typedef struct noise_client {
  noise_case *scenario;
  p2p_node_t *node;
  p2p_node_cnet_t *owner;
  p2p_peer_t *peer;
  uint8_t private_key[32],public_key[32];
  noise_test_identity identity;
  uint8_t request[NOISE_PAYLOAD_MAX];
  uint64_t *samples,sent_ns;
  size_t index,authenticated,received,invalid,closed;
} noise_client;

struct noise_final {
  noise_case *scenario;
  noise_lane *lane;
  p2p_node_t *node;
  p2p_node_cnet_t *owner;
  uint8_t private_key[32],public_key[32];
  noise_test_identity identity;
  p2p_peer_t *peers[NOISE_SESSIONS];
  uint8_t pending[NOISE_SESSIONS][NOISE_PAYLOAD_MAX];
  size_t pending_size[NOISE_SESSIONS];
  size_t authenticated[NOISE_SESSIONS],received[NOISE_SESSIONS];
  size_t replied[NOISE_SESSIONS],closed[NOISE_SESSIONS];
  size_t invalid;
};

struct noise_lane {
  noise_case *scenario;
  size_t shard;
  native_io_sharded_host_lease lease;
  native_io_backend *backend;
  p2p_cnet_owner_t *acceptor,*final_transport;
  cnet_stream_peer listener;
  const void *worker_token;
  size_t turns,stop_retries;
  int stopped,released,error;
  const char *failed_at;
#if NOISE_ASYNC_PROGRESS
  atomic_bool progress_ready;
  atomic_int cancel_status,owner_failed;
#endif
};
struct noise_case {
  native_io_sharded *sg;
  p2p_cnet_sg_t *handoff;
  noise_lane lanes[NOISE_SHARDS];
  noise_final finals[NOISE_FINALS];
  noise_client clients[NOISE_SESSIONS];
  uint8_t server_key[32];
  /* Pinned security API borrows a CONTIGUOUS 4x32-byte trusted key array,
   * never the strided public_key members of noise_client structs. */
  uint8_t client_allowlist[NOISE_SESSIONS][32];
  size_t bytes,warmup,rounds;
  int stopping;
};

static native_io_backend_kind noise_backend(void) {
#if defined(_WIN32)
  return NATIVE_IO_BACKEND_IOCP;
#elif defined(__APPLE__)
  return NATIVE_IO_BACKEND_KQUEUE;
#else
  return NATIVE_IO_BACKEND_EPOLL;
#endif
}
static uint64_t timestamp_ns(clockid_t kind) {
  struct timespec t={0};
  check_equal(0,clock_gettime(kind,&t));
  return (uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;
}
static size_t env_count(const char *name,size_t fallback,size_t limit) {
  const char *s=getenv(name);char *end=NULL;
  if (!s||!*s) return fallback;
  errno=0;unsigned long v=strtoul(s,&end,10);
  if (errno||end==s||*end||v==0u||v>limit) {
    fprintf(stderr,"Invalid %s=%s (1..%zu)\n",name,s,limit);exit(2);
  }
  return (size_t)v;
}
static void frame(uint8_t *dest,size_t len,size_t client,size_t round) {
  memset(dest,0,len);
  dest[0]='E';dest[1]='C';dest[2]='H';dest[3]='O';
  dest[4]=(uint8_t)(client+1u);
  dest[5]=(uint8_t)round;dest[6]=(uint8_t)(round>>8);
  dest[7]=(uint8_t)(client^round^0x5Au);
  for(size_t i=8u;i<len;++i)dest[i]=(uint8_t)(i^(round*31u)^(client*17u));
}
static int compare_u64(const void *a,const void *b) {
  uint64_t x=*(const uint64_t*)a,y=*(const uint64_t*)b;
  return (x>y)-(x<y);
}
static uint64_t quantile(const uint64_t *samples,size_t n,unsigned pct) {
  size_t rank=(n*pct+99u)/100u;
  if (!rank) rank=1u;
  if (rank>n) rank=n;
  return samples[rank-1u];
}
static p2p_cnet_config_t net_config(size_t capacity) {
  p2p_cnet_config_t c={0};
  c.client.backend=noise_backend();
  c.client.connection_capacity=capacity;
  c.client.command_capacity=32u;
  c.client.request_capacity=32u;
  c.client.completion_batch_capacity=8u;
  c.client.event_capacity=32u;
  c.client.max_send_bytes=128u*1024u;
  c.client.receive_buffer_bytes=97u;
  c.client.connect_timeout_ms=5000u;
  c.client.write_timeout_ms=5000u;
  c.send_hwm_bytes=128u*1024u;
  c.pending_write_limit=8u;
  c.accept_budget=4u;
  c.stop_timeout_ms=5000u;
  return c;
}
static void lane_error(noise_lane *lane,int error,const char *where) {
  if (!lane->error) {lane->error=error;lane->failed_at=where;}
#if NOISE_ASYNC_PROGRESS
  atomic_store_explicit(&lane->owner_failed,error,memory_order_release);
#endif
}
#define NOISE_CALL(lane,expr) do { \
  const int noise_status_=(expr); \
  if (noise_status_!=P2P_OK) {lane_error((lane),noise_status_,#expr);return;} \
} while (0)
static bool quiescent(void *arg) {
  const noise_lane *lane=(const noise_lane*)arg;
  return lane->released&&!lane->acceptor&&!lane->final_transport;
}
static int build_local_credential(void *ctx,const uint8_t local[32],
                                  uint8_t *credential,size_t cap,size_t *size,
                                  p2p_authenticated_identity_v2_t *identity) {
  noise_test_identity *test=(noise_test_identity*)ctx;
  if (!credential||!size||!identity||cap<32u)
    return P2P_ERR_INVALID_ARG;
  memcpy(credential,local,32u);
  *size=32u;
  *identity=test->principal;
  return P2P_OK;
}
static int verify_remote_credential(void *ctx,const uint8_t remote[32],
                                    const uint8_t binding[32],
                                    const uint8_t *credential,size_t length,
                                    uint64_t now_ms,
                                    p2p_authenticated_identity_v2_t *identity) {
  noise_test_identity *test=(noise_test_identity*)ctx;
  uint8_t zero[32]={0};
  if (!test||!remote||!binding||!credential||!identity||
      length!=32u||!now_ms||memcmp(binding,zero,32u)==0||
      memcmp(credential,remote,32u)!=0) return P2P_ERR_UNTRUSTED_IDENTITY;
  for(size_t i=0;i<test->count;++i) {
    if (memcmp(test->allowed[i],remote,32u)!=0)continue;
    /* The remote's authenticated principal is NOT the local principal.
     * The fixture contract is keyed by the X25519 static key. */
    memset(identity,test->remote_principal_seeds[i],sizeof(*identity));
    return P2P_OK;
  }
  return P2P_ERR_UNTRUSTED_IDENTITY;
}
static void configure_identity(p2p_node_t *node,noise_test_identity *test,
                               const uint8_t private_key[32],
                               const uint8_t *allowlist,const uint8_t *remote_seeds,
                               size_t count) {
  p2p_security_config_v2_t security={0};
  check_not_null(node);
  check_true(count>0u&&count<=NOISE_SESSIONS);
  check_equal(P2P_OK,p2p_node_set_private_key(node,private_key));
  check_equal(P2P_OK,p2p_public_key_from_private_key(
      private_key,test->public_key));
  for(size_t i=0;i<count;++i) {
    memcpy(test->allowed[i],allowlist+32u*i,32u);
    test->remote_principal_seeds[i]=remote_seeds[i];
  }
  test->count=count;
  /* Match the established P2P SG identity fixture's deterministic mapping. */
  memset(&test->principal,private_key[0],sizeof(test->principal));
  security.struct_size=sizeof(security);
  security.handshake_timeout_ms=5000u;
  security.ready_timeout_ms=5000u;
  security.send_hwm_bytes=128u*1024u;
  security.node_send_budget_bytes=4u*128u*1024u;
  /* Send HWM is NOT cumulative Noise session byte lifetime.
   * Follow production v2 defaults for a real multi-round benchmark. */
  security.session_max_age_ms=0u;
  security.session_max_bytes_per_direction=0u;
  security.identity_provider.build_local_credential=build_local_credential;
  security.identity_provider.verify_remote_credential=verify_remote_credential;
  security.identity_provider.context=test;
  memset(security.network_id_hash,9u,32u);
  security.cookie_gate_limit=16u;
  security.cookie_lifetime_ms=5000u;
  security.cookie_key_rotation_ms=10000u;
  security.source_admission_burst=16u;
  security.source_admission_refill_per_second=1u;
  security.source_admission_bucket_limit=16u;
  check_equal(P2P_OK,p2p_node_configure_security_v2(node,&security));
}
static void client_connected(p2p_peer_t *peer,void *arg) {
  noise_client *c=(noise_client*)arg;
  uint8_t key[32]={0};
  if (p2p_peer_get_public_key(peer,key)!=P2P_OK ||
      memcmp(key,c->scenario->server_key,32u)!=0 ||
      c->authenticated || c->peer) {c->invalid++;return;}
  c->peer=peer;c->authenticated++;
}
static void client_disconnected(p2p_peer_t *peer,void *arg) {
  noise_client *c=(noise_client*)arg;
  c->closed++;
  if (!c->scenario->stopping) c->invalid++;
  if (c->peer==peer) c->peer=NULL;
}
static void client_echo(p2p_node_t *node,p2p_peer_t *peer,
                        const void *data,size_t len,void *arg) {
  noise_client *c=(noise_client*)arg;
  (void)node;
  if (peer!=c->peer||len!=c->scenario->bytes||!c->sent_ns||
      memcmp(c->request,data,len)!=0) {c->invalid++;return;}
  if (c->received>=c->scenario->warmup)
    c->samples[c->received-c->scenario->warmup]=
        timestamp_ns(CLOCK_MONOTONIC)-c->sent_ns;
  c->received++;
}
static void server_connected(p2p_peer_t *peer,void *arg) {
  noise_final *f=(noise_final*)arg;
  uint8_t key[32]={0};
  if (p2p_peer_get_public_key(peer,key)!=P2P_OK) {
    f->invalid++;return;
  }
  for(size_t i=0u;i<NOISE_SESSIONS;++i) {
    if (memcmp(key,f->scenario->clients[i].public_key,32u)!=0)continue;
    if (i%NOISE_FINALS!=f->lane->shard-1u || f->peers[i]) {
      f->invalid++;return;
    }
    f->peers[i]=peer;f->authenticated[i]++;
    return;
  }
  f->invalid++;
}
static void server_disconnected(p2p_peer_t *peer,void *arg) {
  noise_final *f=(noise_final*)arg;
  for(size_t i=0u;i<NOISE_SESSIONS;++i) {
    if (f->peers[i]!=peer) continue;
    f->closed[i]++;
    if (!f->scenario->stopping) f->invalid++;
    f->peers[i]=NULL;
    return;
  }
  f->invalid++;
}
static void server_echo(p2p_node_t *node,p2p_peer_t *peer,
                        const void *data,size_t len,void *arg) {
  noise_final *f=(noise_final*)arg;
  (void)node;
  for(size_t i=0u;i<NOISE_SESSIONS;++i) {
    if (f->peers[i]!=peer||!peer)continue;
    uint8_t expected[NOISE_PAYLOAD_MAX];
    frame(expected,f->scenario->bytes,i,f->replied[i]);
    if (len!=f->scenario->bytes||f->pending_size[i]||
        memcmp(data,expected,len)!=0) {f->invalid++;return;}
    memcpy(f->pending[i],data,len);
    f->pending_size[i]=len;
    f->received[i]++;
    return;
  }
  f->invalid++;
}
static int deny_accept(p2p_cnet_owner_t *owner,p2p_connection_t *connection,
                       const cnet_stream_peer *remote,void *arg) {
  noise_lane *lane=(noise_lane*)arg;
  (void)owner;(void)connection;(void)remote;
  lane_error(lane,P2P_ERR_INVALID_STATE,"direct accept bypassed SG");
  return P2P_ERR_INVALID_STATE;
}
static void init_owner(native_io_sharded_context *context,void *arg) {
  noise_lane *lane=(noise_lane*)arg;
  noise_case *sc=lane->scenario;
  p2p_cnet_config_t transport=net_config(
      lane->shard?NOISE_PER_FINAL:8u);
  if (native_io_sharded_context_shard(context)!=lane->shard) {
    lane_error(lane,SALTS_EPERM,"initial SG shard");return;
  }
  lane->worker_token=cmeta_thread_current_token();
  NOISE_CALL(lane,native_io_sharded_context_acquire_host(
      context,quiescent,lane,&lane->lease,&lane->backend));
  if (!lane->shard) {
    NOISE_CALL(lane,p2p_cnet_owner_create_external(
        &transport,lane->backend,lane->lease,&lane->acceptor));
    NOISE_CALL(lane,p2p_cnet_owner_listen(
        lane->acceptor,"127.0.0.1",0u,16u,
        deny_accept,lane,&lane->listener));
    return;
  }
  noise_final *f=&sc->finals[lane->shard-1u];
  f->node=p2p_node_state_create("127.0.0.1",0);
  if (!f->node) {lane_error(lane,P2P_ERR_NO_MEM,"server Node allocation");return;}
  const uint8_t remote_seeds[NOISE_SESSIONS]={33u,49u,65u,81u};
  configure_identity(f->node,&f->identity,f->private_key,
                     &sc->client_allowlist[0][0],remote_seeds,
                     NOISE_SESSIONS);
  p2p_set_peer_callbacks(f->node,server_connected,server_disconnected,f);
  p2p_set_message_handler(f->node,server_echo,f);
  NOISE_CALL(lane,p2p_node_cnet_create_external(
      f->node,&transport,lane->backend,lane->lease,&f->owner));
  NOISE_CALL(lane,p2p_node_cnet_bind_handoff_accept(f->owner));
  lane->final_transport=p2p_node_cnet_transport_owner(f->owner);
  if (!lane->final_transport)
    lane_error(lane,P2P_ERR_INVALID_STATE,"final P2P CNet transport");
}
static void flush_replies(noise_lane *lane) {
  noise_final *f=&lane->scenario->finals[lane->shard-1u];
  for (size_t i=0u;i<NOISE_SESSIONS;++i) {
    if (!f->pending_size[i])continue;
    int status=p2p_send_message(
        f->node,f->peers[i],P2P_MSG_CUSTOM,f->pending[i],f->pending_size[i]);
    if (status!=P2P_OK) {
      lane_error(lane,status,"Noise echo enqueue");return;
    }
    f->pending_size[i]=0u;
    f->replied[i]++;
  }
}
static void progress(native_io_sharded_context *context,void *arg) {
  noise_lane *lane=(noise_lane*)arg;
  if (lane->error||lane->stopped) return;
  if (native_io_sharded_context_shard(context)!=lane->shard ||
      cmeta_thread_current_token()!=lane->worker_token) {
    lane_error(lane,SALTS_EPERM,"SG progress wrong owner");return;
  }
  size_t observed=0u,settled=0u;
  if (!lane->shard) {
    NOISE_CALL(lane,p2p_cnet_owner_poll_sg_host(
        lane->acceptor,context,lane->lease,&observed,&settled));
  } else if (lane->stop_retries) {
    NOISE_CALL(lane,p2p_cnet_owner_poll_sg_host(
        lane->final_transport,context,lane->lease,&observed,&settled));
  } else {
    noise_final *f=&lane->scenario->finals[lane->shard-1u];
    NOISE_CALL(lane,p2p_node_cnet_poll_sg_host(
        f->owner,context,lane->lease,&observed,&settled));
    flush_replies(lane);
  }
  lane->turns++;
}
static void stop_owner(native_io_sharded_context *context,void *arg) {
  noise_lane *lane=(noise_lane*)arg;
  if (lane->error||lane->stopped) return;
  if (native_io_sharded_context_shard(context)!=lane->shard) {
    lane_error(lane,SALTS_EPERM,"SG stop wrong shard");return;
  }
  const int rc=lane->shard
      ?p2p_node_cnet_stop(lane->scenario->finals[lane->shard-1u].owner)
      :p2p_cnet_owner_stop(lane->acceptor);
  if (rc==P2P_ERR_INVALID_STATE) {lane->stop_retries++;return;}
  if (rc!=P2P_OK) {lane_error(lane,rc,"SG stop");return;}
  lane->stopped=1;
}
static void destroy_owner(native_io_sharded_context *context,void *arg) {
  noise_lane *lane=(noise_lane*)arg;
  if (lane->error||
      native_io_sharded_context_shard(context)!=lane->shard ||
      cmeta_thread_current_token()!=lane->worker_token) {
    lane_error(lane,SALTS_EPERM,"SG destroy wrong worker");return;
  }
  if (!lane->shard) {
    NOISE_CALL(lane,p2p_cnet_owner_destroy(lane->acceptor));
    lane->acceptor=NULL;
  } else {
    noise_final *f=&lane->scenario->finals[lane->shard-1u];
    NOISE_CALL(lane,p2p_node_cnet_destroy(f->owner));
    f->owner=NULL;
    lane->final_transport=NULL;
    NOISE_CALL(lane,p2p_node_state_destroy(f->node));
    f->node=NULL;
  }
  lane->released=1;
  NOISE_CALL(lane,native_io_sharded_context_release_host(
      context,lane->lease));
  lane->backend=NULL;
}
static void submit(noise_case *sc,size_t shard,native_io_sharded_task_fn fn) {
  native_io_sharded_task task={fn,NULL,NULL,&sc->lanes[shard]};
  check_equal(SALTS_OK,native_io_sharded_submit_to(sc->sg,shard,&task));
}
static void barrier(noise_case *sc) {
  check_equal(SALTS_OK,native_io_sharded_wait(sc->sg));
  for (size_t i=0u;i<NOISE_SHARDS;++i) {
    const noise_lane *lane=&sc->lanes[i];
    if(lane->error)fprintf(stderr,
        "Noise SG %u Finals shard %zu: status %d at %s\n",
        (unsigned)NOISE_FINALS,i,lane->error,
        lane->failed_at?lane->failed_at:"?");
    check_equal(0,lane->error);
  }
}
static void pump(noise_case *sc) {
  /* Clients are admitted sequentially. Never poll not-yet-created nodes;
   * each created dedicated Node still has exactly one progress owner. */
  for (size_t i=0u;i<NOISE_SESSIONS;++i)
    if (sc->clients[i].node && sc->clients[i].owner)
      check_equal(P2P_OK,p2p_poll(sc->clients[i].node));
  for (size_t shard=0u;shard<NOISE_SHARDS;++shard)
    submit(sc,shard,progress);
  barrier(sc);
}
#if NOISE_ASYNC_PROGRESS
/* Real SG Host observer remains the only NativeIO progress authority;
 * at most ONE bounded task may be enqueued per final worker and acceptor.
 * No global wait between measured echo rounds. */
static void progress_cancel(void *arg,int status) {
  noise_lane *lane=(noise_lane*)arg;
  atomic_store_explicit(&lane->cancel_status,status,memory_order_relaxed);
}
static void progress_finalize(void *arg) {
  noise_lane *lane=(noise_lane*)arg;
  atomic_store_explicit(&lane->progress_ready,true,memory_order_release);
}
static void pump_independent(noise_case *sc) {
  for(size_t i=0u;i<NOISE_SESSIONS;++i)
    if (sc->clients[i].node && sc->clients[i].owner)
      check_equal(P2P_OK,p2p_poll(sc->clients[i].node));
  for(size_t shard=0u;shard<NOISE_SHARDS;++shard) {
    noise_lane *lane=&sc->lanes[shard];
    check_equal(0,atomic_load_explicit(
        &lane->owner_failed,memory_order_acquire));
    check_equal(0,atomic_load_explicit(
        &lane->cancel_status,memory_order_relaxed));
    if (!atomic_exchange_explicit(
            &lane->progress_ready,false,memory_order_acq_rel)) continue;
    native_io_sharded_task task={
      progress,progress_cancel,progress_finalize,lane
    };
    const int rc=native_io_sharded_try_submit_to(sc->sg,shard,&task);
    if (rc!=SALTS_OK) {
      atomic_store_explicit(&lane->progress_ready,true,memory_order_release);
      if (rc!=SALTS_ENOBUFS)check_equal(SALTS_OK,rc);
    }
  }
}
static void finish_independent(noise_case *sc) {
  barrier(sc);
  for(size_t shard=0u;shard<NOISE_SHARDS;++shard) {
    noise_lane *lane=&sc->lanes[shard];
    check_true(atomic_load_explicit(
        &lane->progress_ready,memory_order_acquire));
    check_equal(0,atomic_load_explicit(
        &lane->owner_failed,memory_order_acquire));
    check_equal(0,atomic_load_explicit(
        &lane->cancel_status,memory_order_relaxed));
  }
}
#define NOISE_MEASURE_PUMP(s) pump_independent(s)
#define NOISE_MEASURE_BOUNDARY(s) finish_independent(s)
#define NOISE_MEASURE_FINISH(s) finish_independent(s)
#else
#define NOISE_MEASURE_PUMP(s) pump(s)
#define NOISE_MEASURE_BOUNDARY(s) ((void)0)
#define NOISE_MEASURE_FINISH(s) ((void)0)
#endif
static void run_rounds(noise_case *sc) {
  const size_t total=sc->warmup+sc->rounds;
  uint64_t wall0=0u,cpu0=0u;
  for (size_t round=0u;round<total;++round) {
    if (round==sc->warmup) {
      NOISE_MEASURE_BOUNDARY(sc);
      wall0=timestamp_ns(CLOCK_MONOTONIC);
      cpu0=timestamp_ns(CLOCK_PROCESS_CPUTIME_ID);
    }
    for (size_t i=0u;i<NOISE_SESSIONS;++i) {
      noise_client *c=&sc->clients[i];
      frame(c->request,sc->bytes,i,round);
      c->sent_ns=timestamp_ns(CLOCK_MONOTONIC);
      check_equal(P2P_OK,p2p_send_message(
          c->node,c->peer,P2P_MSG_CUSTOM,c->request,sc->bytes));
    }
    const uint64_t deadline=cmeta_monotonic_ms()+NOISE_WAIT_MS;
    for (;;) {
      bool complete=true;
      for (size_t i=0u;i<NOISE_SESSIONS;++i)
        if (sc->clients[i].received<=round)complete=false;
      if (complete||cmeta_monotonic_ms()>=deadline)break;
      NOISE_MEASURE_PUMP(sc);
    }
    for (size_t i=0u;i<NOISE_SESSIONS;++i) {
      check_equal(round+1u,sc->clients[i].received);
      check_equal((size_t)0u,sc->clients[i].invalid);
    }
    /* Validate server-side byte equality and callback counts, not just a
     * client echo generated accidentally by a different source. */
    for(size_t f=0u;f<NOISE_FINALS;++f) {
      const noise_final *final=&sc->finals[f];
      check_equal((size_t)0u,final->invalid);
      for(size_t i=f;i<NOISE_SESSIONS;i+=NOISE_FINALS) {
        check_equal(round+1u,final->received[i]);
        check_equal(round+1u,final->replied[i]);
      }
    }
  }
  NOISE_MEASURE_FINISH(sc);
  const uint64_t wall1=timestamp_ns(CLOCK_MONOTONIC);
  const uint64_t cpu1=timestamp_ns(CLOCK_PROCESS_CPUTIME_ID);
  const double wall=(double)(wall1-wall0)/1e9;
  const double cpu=(double)(cpu1-cpu0)/1e9;
  uint64_t *all=calloc(sc->rounds*NOISE_SESSIONS,sizeof(*all));
  check_not_null(all);
  for (size_t i=0u;i<NOISE_SESSIONS;++i) {
    noise_client *c=&sc->clients[i];
    memcpy(all+i*sc->rounds,c->samples,sc->rounds*sizeof(uint64_t));
    for(size_t j=0u;j<sc->rounds;++j)
      printf("NOISE_SG_RTT,%s,%u,%u,%zu,%zu,%zu,%.3f\n",
          NOISE_DRIVER_LABEL,(unsigned)NOISE_FINALS,(unsigned)NOISE_SHARDS,i+1u,sc->bytes,j+1u,
          (double)c->samples[j]/1000.0);
    qsort(c->samples,sc->rounds,sizeof(uint64_t),compare_u64);
    printf("NOISE_SG_SESSION,noise-only-p2p-echo,%s,"
           "%u,%u,%zu,%zu,%zu,%.3f,%.3f,%.3f\n",
           NOISE_DRIVER_LABEL,(unsigned)NOISE_FINALS,(unsigned)NOISE_SHARDS,
           i+1u,sc->bytes,sc->rounds,
           (double)quantile(c->samples,sc->rounds,50u)/1000.0,
           (double)quantile(c->samples,sc->rounds,95u)/1000.0,
           (double)quantile(c->samples,sc->rounds,99u)/1000.0);
  }
  qsort(all,sc->rounds*NOISE_SESSIONS,sizeof(uint64_t),compare_u64);
  check_true(wall>0.0);
  const double app_messages=(double)sc->rounds*NOISE_SESSIONS*2.0;
  printf("NOISE_SG_BENCH,noise-only-p2p-echo,%s,"
         "%u,%u,%u,%zu,%zu,%zu,%.3f,%.3f,%.3f,%.3f,%.6f,%.3f,%.3f,%.3f\n",
         NOISE_DRIVER_LABEL,(unsigned)NOISE_FINALS,(unsigned)NOISE_SHARDS,
         (unsigned)NOISE_SESSIONS,sc->bytes,sc->rounds,sc->warmup,
         wall*1000.0,cpu*1000.0,cpu*100.0/wall,
         app_messages/wall,app_messages*(double)sc->bytes/(1048576.0*wall),
         (double)quantile(all,sc->rounds*NOISE_SESSIONS,50u)/1000.0,
         (double)quantile(all,sc->rounds*NOISE_SESSIONS,95u)/1000.0,
         (double)quantile(all,sc->rounds*NOISE_SESSIONS,99u)/1000.0);
  fflush(stdout);
  free(all);
}
static void run_noise_baseline(void) {
  noise_case fixture={0},*sc=&fixture;
  const native_io_sharded_config settings={
      NOISE_SHARDS,8u,{noise_backend(),64u,128u,NOISE_BATCH}};
  p2p_cnet_sg_config_v1_t policy={0};
  sc->bytes=env_count("P2P_MMP_BENCH_PAYLOAD",8u,NOISE_PAYLOAD_MAX);
  sc->warmup=env_count("P2P_MMP_BENCH_WARMUP",8u,512u);
  sc->rounds=env_count("P2P_MMP_BENCH_ROUNDS",32u,4096u);
  if (sc->bytes!=8u&&sc->bytes!=1024u) {
    fprintf(stderr,"Noise-only payload must be 8 or 1024\n");exit(2);
  }
  for(size_t i=0u;i<NOISE_SESSIONS;++i) {
    noise_client *c=&sc->clients[i];
    c->scenario=sc;c->index=i;
    c->private_key[0]=(uint8_t)(33u+16u*i);
    check_equal(P2P_OK,p2p_public_key_from_private_key(
        c->private_key,c->public_key));
    memcpy(sc->client_allowlist[i],c->public_key,32u);
    c->samples=calloc(sc->rounds,sizeof(uint64_t));
    check_not_null(c->samples);
    for(size_t k=0u;k<i;++k)
      check_true(memcmp(c->public_key,sc->clients[k].public_key,32u)!=0);
  }
  uint8_t server_private[32]={0};
  server_private[0]=17u;
  check_equal(P2P_OK,p2p_public_key_from_private_key(
      server_private,sc->server_key));
  for(size_t i=0u;i<NOISE_FINALS;++i) {
    noise_final *f=&sc->finals[i];
    f->scenario=sc;f->lane=&sc->lanes[i+1u];
    memcpy(f->private_key,server_private,32u);
    memcpy(f->public_key,sc->server_key,32u);
  }
  check_equal(SALTS_OK,native_io_sharded_create(&settings,&sc->sg));
  for(size_t shard=0u;shard<NOISE_SHARDS;++shard) {
    sc->lanes[shard].scenario=sc;
    sc->lanes[shard].shard=shard;
#if NOISE_ASYNC_PROGRESS
    atomic_init(&sc->lanes[shard].progress_ready,true);
    atomic_init(&sc->lanes[shard].cancel_status,0);
    atomic_init(&sc->lanes[shard].owner_failed,0);
#endif
    submit(sc,shard,init_owner);
  }
  barrier(sc);
  check_true(sc->lanes[0].listener.port!=0u);
  policy.size=sizeof(policy);
  policy.version=P2P_CNET_SG_VERSION;
  policy.acceptor=sc->lanes[0].acceptor;
  policy.placement=CNET_OWNER_PLACE_ROUND_ROBIN;
  policy.final_owner_count=NOISE_FINALS;
  policy.queue_capacity=NOISE_PER_FINAL;
  policy.connection_capacity=NOISE_PER_FINAL;
  for(size_t i=0u;i<NOISE_FINALS;++i)
    policy.final_owners[i]=sc->lanes[i+1u].final_transport;
  check_equal(P2P_OK,p2p_cnet_sg_create_v1(&policy,&sc->handoff));
  for(size_t i=0u;i<NOISE_SESSIONS;++i) {
    noise_client *c=&sc->clients[i];
    c->node=p2p_node_state_create("127.0.0.1",0);
    check_not_null(c->node);
    const uint8_t remote_seed[1]={17u};
    configure_identity(c->node,&c->identity,c->private_key,
                       sc->server_key,remote_seed,1u);
    p2p_set_peer_callbacks(c->node,client_connected,client_disconnected,c);
    p2p_set_message_handler(c->node,client_echo,c);
    p2p_cnet_config_t transport=net_config(2u);
    check_equal(P2P_OK,p2p_node_cnet_create(
        c->node,&transport,&c->owner));
    check_equal(P2P_OK,p2p_node_cnet_listen(c->owner));
    check_equal(P2P_OK,p2p_connect(
        c->node,"127.0.0.1",(int)sc->lanes[0].listener.port));
    const uint64_t deadline=cmeta_monotonic_ms()+NOISE_WAIT_MS;
    while ((!c->authenticated||
            !sc->finals[i%NOISE_FINALS].authenticated[i]) &&
            cmeta_monotonic_ms()<deadline) pump(sc);
    if (!c->authenticated || !sc->finals[i%NOISE_FINALS].authenticated[i]) {
      p2p_cnet_sg_snapshot_v1_t snap={0};
      check_equal(P2P_OK,p2p_cnet_sg_snapshot_v1(
          sc->handoff,i%NOISE_FINALS,&snap));
      fprintf(stderr,"Noise handshake timeout: client=%zu auth=%zu invalid=%zu "
              "server_auth=%zu server_invalid=%zu client_peers=%d "
              "sg_routed=%" PRIu64 " denied=%" PRIu64 " credit_taken=%zu\n",
              i,c->authenticated,c->invalid,
              sc->finals[i%NOISE_FINALS].authenticated[i],
              sc->finals[i%NOISE_FINALS].invalid,
              p2p_get_peer_count(c->node),
              snap.routed,snap.denied,snap.handoff.taken);
    }
    check_equal((size_t)1u,c->authenticated);
    check_equal((size_t)1u,sc->finals[i%NOISE_FINALS].authenticated[i]);
    check_not_null(c->peer);
  }
  for(size_t i=0u;i<NOISE_FINALS;++i) {
    p2p_cnet_sg_snapshot_v1_t snap={0};
    check_equal(P2P_OK,p2p_cnet_sg_snapshot_v1(
        sc->handoff,i,&snap));
    check_equal((size_t)NOISE_PER_FINAL,snap.handoff.taken);
    check_equal((size_t)0u,snap.handoff.queued);
  }
  run_rounds(sc);
  sc->stopping=1;
  for(size_t i=0u;i<NOISE_SESSIONS;++i)
    p2p_peer_disconnect(sc->clients[i].peer);
  const uint64_t drain_deadline=cmeta_monotonic_ms()+NOISE_WAIT_MS;
  for(;;) {
    pump(sc);
    bool done=true;
    for(size_t i=0u;i<NOISE_SESSIONS;++i)
      if (sc->clients[i].closed!=1u||
          sc->finals[i%NOISE_FINALS].closed[i]!=1u) done=false;
    for(size_t i=0u;i<NOISE_FINALS;++i) {
      p2p_cnet_sg_snapshot_v1_t snap={0};
      check_equal(P2P_OK,p2p_cnet_sg_snapshot_v1(sc->handoff,i,&snap));
      if(snap.handoff.taken)done=false;
    }
    if (done||cmeta_monotonic_ms()>=drain_deadline)break;
  }
  for(size_t i=0u;i<NOISE_SESSIONS;++i) {
    check_equal((size_t)1u,sc->clients[i].closed);
    check_equal((size_t)1u,sc->finals[i%NOISE_FINALS].closed[i]);
    check_equal((size_t)0u,sc->clients[i].invalid);
  }
  check_equal(P2P_OK,p2p_cnet_sg_seal_v1(sc->handoff));
  for(size_t shard=0u;shard<NOISE_SHARDS;++shard)
    submit(sc,shard,stop_owner);
  barrier(sc);
  const uint64_t stop_deadline=cmeta_monotonic_ms()+NOISE_WAIT_MS;
  for(;;) {
    bool done=true;
    for(size_t shard=0u;shard<NOISE_SHARDS;++shard) {
      if(sc->lanes[shard].stopped)continue;
      done=false;
      submit(sc,shard,progress);
    }
    if (done||cmeta_monotonic_ms()>=stop_deadline)break;
    barrier(sc);
    for(size_t shard=0u;shard<NOISE_SHARDS;++shard)
      if (!sc->lanes[shard].stopped)
        submit(sc,shard,stop_owner);
    barrier(sc);
  }
  for(size_t shard=0u;shard<NOISE_SHARDS;++shard)
    check_true(sc->lanes[shard].stopped);
  check_equal(P2P_OK,p2p_cnet_sg_destroy_v1(sc->handoff));
  sc->handoff=NULL;
  for(size_t shard=0u;shard<NOISE_SHARDS;++shard)
    submit(sc,shard,destroy_owner);
  barrier(sc);
  check_equal(SALTS_OK,native_io_sharded_shutdown(sc->sg));
  check_equal(SALTS_OK,native_io_sharded_destroy(sc->sg));
  for(size_t i=0u;i<NOISE_SESSIONS;++i) {
    check_equal(P2P_OK,p2p_node_cnet_destroy(sc->clients[i].owner));
    check_equal(P2P_OK,p2p_node_state_destroy(sc->clients[i].node));
    free(sc->clients[i].samples);
  }
}
spec("Four-session pure P2P Noise SG transport stage (no MMP/Pool)") {
  it("uses real pinned Noise identities, CNet SG Handoff and exact echo") {
    run_noise_baseline();
  }
}
