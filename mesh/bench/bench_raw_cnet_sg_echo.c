/* Opt-in PURE CNet TCP/NativeIO SG echo baseline. No Noise, MMP,
 * ClientPool or P2P callbacks: four numeric TCP sessions, the same
 * 1/2/4 final SG workers (+1 acceptor), 8B / 1024B, complete 4-session
 * request/echo batches and the SAME client and SG Handoff credit count.
 *
 * Actual CNet listener accept_detached -> Handoff reserve/publish/take ->
 * owner-affine cnet_client_adopt_accepted. Only the original SG Host
 * observes completions. Handoff credit is returned once AFTER CNet
 * callbacks/physical terminal and completed client stop.
 *
 * This is a raw-CNet TCP echo stage, not an encrypted MMP RPC result. */
#define _POSIX_C_SOURCE 200809L
#include <tinytest.h>
#include <cnet/cnet.h>
#include <cnet/handoff.h>
#include <cnet/sg_host.h>
#include <salts/native_io_sharded.h>
#include <salts/clock.h>
#include <salts/thread.h>
#include <cmeta_buffer.h>
#include <time.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>

#ifndef BENCH_RAW_FINALS
#error BENCH_RAW_FINALS must be 1, 2, or 4
#endif
#if BENCH_RAW_FINALS != 1 && BENCH_RAW_FINALS != 2 && BENCH_RAW_FINALS != 4
#error Invalid BENCH_RAW_FINALS
#endif
#ifndef BENCH_RAW_ASYNC_PROGRESS
#define BENCH_RAW_ASYNC_PROGRESS 0
#endif
#if BENCH_RAW_ASYNC_PROGRESS != 0 && BENCH_RAW_ASYNC_PROGRESS != 1
#error Invalid BENCH_RAW_ASYNC_PROGRESS
#endif
#ifndef BENCH_APP_INDEPENDENT
#define BENCH_APP_INDEPENDENT 0
#endif
#if BENCH_APP_INDEPENDENT != 0 && BENCH_APP_INDEPENDENT != 1
#error BENCH_APP_INDEPENDENT must be 0 or 1
#endif
#define RAW_DRIVER_LABEL (BENCH_APP_INDEPENDENT ? \
    (BENCH_RAW_ASYNC_PROGRESS ? "owner-independent-app-independent" \
                              : "global-barrier-app-independent") \
    : (BENCH_RAW_ASYNC_PROGRESS ? "owner-independent" : "global-barrier"))
enum { RAW_SESSIONS=4, RAW_FINALS=BENCH_RAW_FINALS,
       RAW_SHARDS=RAW_FINALS+1, RAW_PER_FINAL=RAW_SESSIONS/RAW_FINALS,
       RAW_BATCH=16, RAW_BYTES_MAX=1024, RAW_TIMEOUT_MS=15000 };
typedef struct raw_case raw_case;
typedef struct raw_lane raw_lane;

typedef struct {
  raw_case *scenario;
  size_t index;
  cnet_client client;
  cnet_connection connection;
  uint8_t request[RAW_BYTES_MAX],received_frame[RAW_BYTES_MAX];
  size_t received_used, received, next_to_send, rounds, warmup;
  size_t connected,terminal,invalid;
  uint64_t sent_ns,*samples;
} raw_client;

typedef struct {
  raw_lane *lane;
  size_t index;
  cnet_connection connection;
  cnet_handoff_ticket ticket;
  uint8_t request[RAW_BYTES_MAX];
  size_t recv_used;
  uint8_t pending[RAW_BYTES_MAX];
  size_t pending_size,replies,received,bytes_sent;
  int connected,terminal,receive_armed;
} raw_server_peer;

struct raw_lane {
  raw_case *scenario;
  size_t shard;
  native_io_sharded_host_lease lease;
  native_io_backend *backend;
  cnet_client client;
  cnet_listener listener;
  cnet_stream_endpoint local;
  raw_server_peer peers[RAW_PER_FINAL];
  size_t accepted,turned,stops;
  const void *owner_thread;
  int error,stopped,released,closing;
  const char *failed_at;
#if BENCH_RAW_ASYNC_PROGRESS
  atomic_bool progress_ready;
  atomic_int cancel_status,owner_failed;
#endif
};

struct raw_case {
  native_io_sharded *sg;
  cnet_handoff handoffs[RAW_FINALS];
  raw_lane lanes[RAW_SHARDS];
  raw_client clients[RAW_SESSIONS];
  size_t bytes,warmup,rounds;
  size_t published,admitted;
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
static uint64_t mono_ns(clockid_t k) {
  struct timespec t={0};
  check_equal(0,clock_gettime(k,&t));
  return (uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;
}
static size_t env_count(const char *name,size_t def,size_t cap) {
  const char *value=getenv(name); char *end=NULL;
  if (!value||!*value) return def;
  errno=0;
  unsigned long v=strtoul(value,&end,10);
  if (errno||end==value||*end||v==0u||v>cap) {
    fprintf(stderr,"Invalid %s=%s (1..%zu)\n",name,value,cap);exit(2);
  }
  return (size_t)v;
}
static void frame(uint8_t *dst,size_t bytes,size_t client,size_t round) {
  memset(dst,0,bytes);
  dst[0]='E';dst[1]='C';dst[2]='H';dst[3]='O';
  dst[4]=(uint8_t)(client+1u);
  dst[5]=(uint8_t)round; dst[6]=(uint8_t)(round>>8);
  dst[7]=(uint8_t)(client^round^0x5Au);
  for (size_t j=8u;j<bytes;++j)
    dst[j]=(uint8_t)(j^(round*31u)^(client*17u));
}
static int sort_u64(const void *a,const void *b) {
  uint64_t x=*(const uint64_t *)a,y=*(const uint64_t *)b;
  return (x>y)-(x<y);
}
static uint64_t percentile(const uint64_t *values,size_t count,unsigned p) {
  size_t rank=(count*p+99u)/100u;
  if (!rank) rank=1u;
  if (rank>count) rank=count;
  return values[rank-1u];
}
static cnet_client_config client_cfg(size_t connections) {
  cnet_client_config cfg={0};
  cfg.backend=backend_kind();
  cfg.connection_capacity=connections;
  cfg.command_capacity=32u;
  cfg.request_capacity=32u;
  cfg.completion_batch_capacity=RAW_BATCH;
  cfg.event_capacity=32u;
  cfg.max_send_bytes=128u*1024u;
  cfg.receive_buffer_bytes=97u;
  cfg.connect_timeout_ms=5000u;
  cfg.read_timeout_ms=5000u;
  cfg.write_timeout_ms=5000u;
  return cfg;
}
static void lane_error(raw_lane *lane,int rc,const char *where) {
  if (lane->error==SALTS_OK) {lane->error=rc;lane->failed_at=where;}
#if BENCH_RAW_ASYNC_PROGRESS
  atomic_store_explicit(&lane->owner_failed,rc,memory_order_release);
#endif
}
#define RAW_CHECK(lane, expr) do { \
  const int rc_=(expr); \
  if (rc_!=SALTS_OK) {lane_error((lane),rc_,#expr);return;} \
} while(0)
static int send_copy(cnet_client *client,cnet_connection connection,
                     const uint8_t *payload,size_t bytes) {
  mem_buffer_t *buffer=mem_get_buffer(mem_global(),bytes);
  if (!buffer) return SALTS_ENOMEM;
  memcpy(mem_buffer_data(buffer),payload,bytes);
  mem_set_used(buffer,bytes);
  int result=cnet_send_buffer(client,connection,buffer);
  mem_buffer_release(buffer);
  return result;
}
static bool host_quiescent(void *arg) {
  raw_lane *lane=(raw_lane *)arg;
  return lane->released && !lane->client.impl && !lane->listener.impl;
}
static void client_state(void *arg,cnet_connection handle,
                         cnet_connection_state state,const cnet_error *error) {
  raw_client *c=(raw_client *)arg;
  (void)handle;(void)error;
  if (state==CNET_CONNECTION_CONNECTED) c->connected++;
  if (state==CNET_CONNECTION_CLOSED || state==CNET_CONNECTION_FAILED) {
    c->terminal++;
    if (!c->scenario->stopping) c->invalid++;
  }
}
static void client_recv(void *arg,cnet_connection handle,
                        const cnet_receive_view *view) {
  raw_client *c=(raw_client *)arg;
  if (!view||view->kind!=CNET_MESSAGE_BYTES ||
      !view->size||c->received_used+view->size>c->scenario->bytes) {
    c->invalid++;return;
  }
  memcpy(c->received_frame+c->received_used,view->data,view->size);
  c->received_used+=view->size;
  if (c->received_used==c->scenario->bytes) {
    if (memcmp(c->request,c->received_frame,c->scenario->bytes)!=0 ||
        c->sent_ns==0u) {
      c->invalid++;return;
    }
    if (c->received>=c->warmup)
      c->samples[c->received-c->warmup]=mono_ns(CLOCK_MONOTONIC)-c->sent_ns;
    c->received++;
    c->received_used=0u;
  }
  if (!c->scenario->stopping) {
    int rc=cnet_receive(&c->client,handle,1u);
    if (rc!=SALTS_OK) c->invalid++;
  }
}
static cnet_observer client_observer(raw_client *c) {
  cnet_observer obs={0};
  obs.on_state=client_state;
  obs.on_receive=client_recv;
  obs.user=c;
  return obs;
}
static void server_state(void *arg,cnet_connection connection,
                         cnet_connection_state state,const cnet_error *error) {
  raw_server_peer *p=(raw_server_peer *)arg;
  (void)connection;(void)error;
  if (cmeta_thread_current_token()!=p->lane->owner_thread) {
    lane_error(p->lane,SALTS_EPERM,"raw CNet callback owner");return;
  }
  if (state==CNET_CONNECTION_CONNECTED) p->connected=1;
  if (state==CNET_CONNECTION_CLOSED || state==CNET_CONNECTION_FAILED) {
    p->terminal=1;
    if (!p->lane->scenario->stopping)
      lane_error(p->lane,SALTS_ECONNRESET,"raw CNet server unexpected close");
  }
}
static void server_receive(void *arg,cnet_connection connection,
                           const cnet_receive_view *view) {
  raw_server_peer *p=(raw_server_peer *)arg;
  raw_case *sc=p->lane->scenario;
  if (!view||view->kind!=CNET_MESSAGE_BYTES||
      !view->size||p->recv_used+view->size>sc->bytes||p->pending_size) {
    lane_error(p->lane,SALTS_EPROTO,"raw CNet frame or duplicate");return;
  }
  memcpy(p->request+p->recv_used,view->data,view->size);
  p->recv_used+=view->size;
  if (p->recv_used==sc->bytes) {
    uint8_t expected[RAW_BYTES_MAX]={0};
    frame(expected,sc->bytes,p->index,p->replies);
    if (memcmp(expected,p->request,sc->bytes)!=0) {
      lane_error(p->lane,SALTS_EPROTO,"raw CNet request differs");return;
    }
    memcpy(p->pending,p->request,sc->bytes);
    p->pending_size=sc->bytes;
    p->recv_used=0u;
    p->received++;
  }
  if (!sc->stopping) {
    int rc=cnet_receive(&p->lane->client,connection,1u);
    if (rc!=SALTS_OK) lane_error(p->lane,rc,"raw CNet recv rearm");
  }
}
static void server_send(void *arg,cnet_connection connection,size_t bytes) {
  raw_server_peer *p=(raw_server_peer *)arg;
  (void)connection;
  p->bytes_sent+=bytes;
}
static cnet_observer server_observer(raw_server_peer *p) {
  cnet_observer obs={0};
  obs.on_state=server_state;
  obs.on_receive=server_receive;
  obs.on_send=server_send;
  obs.user=p;
  return obs;
}
static void init_host(native_io_sharded_context *ctx,void *arg) {
  raw_lane *lane=(raw_lane *)arg;
  raw_case *sc=lane->scenario;
  cnet_client_config config=client_cfg(lane->shard?RAW_PER_FINAL:1u);
  if (native_io_sharded_context_shard(ctx)!=lane->shard) {
    lane_error(lane,SALTS_EPERM,"raw init shard mismatch");return;
  }
  lane->owner_thread=cmeta_thread_current_token();
  RAW_CHECK(lane,native_io_sharded_context_acquire_host(
      ctx,host_quiescent,lane,&lane->lease,&lane->backend));
  RAW_CHECK(lane,cnet_client_init_external(&lane->client,&config,lane->backend));
  if (!lane->shard) {
    cnet_stream_endpoint bind=CNET_STREAM_ENDPOINT_INIT;
    native_io_request request={0};
    bind.family=CNET_DATAGRAM_ADDRESS_IPV4;
    bind.address[0]=127u;bind.address[3]=1u;
    RAW_CHECK(lane,cnet_listener_open(&lane->listener,backend_kind(),
                                      CNET_DATAGRAM_ADDRESS_IPV4));
    RAW_CHECK(lane,cnet_listener_bind_open_endpoint(&lane->listener,&bind));
    RAW_CHECK(lane,cnet_listener_local_endpoint(&lane->listener,&lane->local));
    RAW_CHECK(lane,cnet_listener_listen(&lane->listener,16u));
    RAW_CHECK(lane,cnet_listener_attach_external(&lane->listener,lane->backend));
    RAW_CHECK(lane,cnet_listener_submit_external_accept(&lane->listener,&request));
    sc->admitted=0u;
  }
}
static void take_final(raw_lane *lane) {
  raw_case *sc=lane->scenario;
  cnet_handoff *inbox=&sc->handoffs[lane->shard-1u];
  for (;;) {
    cnet_accepted_stream accepted=CNET_ACCEPTED_STREAM_INIT;
    cnet_handoff_ticket ticket={0};
    const int take=cnet_handoff_take(inbox,&ticket,&accepted);
    if (take==SALTS_ENOENT) break;
    if (take!=SALTS_OK) {lane_error(lane,take,"Handoff take");return;}
    if (lane->accepted>=RAW_PER_FINAL) {
      (void)cnet_accepted_stream_close(&accepted);
      (void)cnet_handoff_release(inbox,ticket);
      lane_error(lane,SALTS_ENOBUFS,"Final over admission budget");return;
    }
    raw_server_peer *p=&lane->peers[lane->accepted];
    p->lane=lane;
    p->index=(lane->shard-1u)+lane->accepted*RAW_FINALS;
    p->ticket=ticket;
    cnet_observer obs=server_observer(p);
    const int rc=cnet_client_adopt_accepted(
        &lane->client,&accepted,&obs,&p->connection);
    if (rc!=SALTS_OK || accepted.internal_active!=0u ||
        p->connection.slot==0u) {
      lane_error(lane,rc?rc:SALTS_EPROTO,"raw CNet adopt on final");return;
    }
    lane->accepted++;
  }
}
static void publish_accepted(raw_lane *lane) {
  raw_case *sc=lane->scenario;
  for (;;) {
    cnet_accepted_stream stream=CNET_ACCEPTED_STREAM_INIT;
    int rc=cnet_listener_accept_detached(&lane->listener,&stream);
    if (rc==SALTS_ETIMEDOUT) break;
    if (rc!=SALTS_OK) {lane_error(lane,rc,"raw listener accept");return;}
    if (sc->published>=RAW_SESSIONS) {
      (void)cnet_accepted_stream_close(&stream);
      lane_error(lane,SALTS_ENOBUFS,"acceptor admitted fifth connection");return;
    }
    size_t selected=sc->published%RAW_FINALS;
    cnet_handoff_ticket ticket={0};
    rc=cnet_handoff_reserve(&sc->handoffs[selected],&ticket);
    if (rc!=SALTS_OK) {
      (void)cnet_accepted_stream_close(&stream);
      lane_error(lane,rc,"raw Handoff reserve");return;
    }
    rc=cnet_handoff_publish(&sc->handoffs[selected],ticket,&stream);
    if (rc!=SALTS_OK) {
      (void)cnet_accepted_stream_close(&stream);
      (void)cnet_handoff_release(&sc->handoffs[selected],ticket);
      lane_error(lane,rc,"raw Handoff publish");return;
    }
    sc->published++;
  }
  if (sc->published<RAW_SESSIONS&&!sc->stopping) {
    native_io_request request={0};
    int rc=cnet_listener_submit_external_accept(&lane->listener,&request);
    if (rc!=SALTS_OK) lane_error(lane,rc,"raw rearm accept");
  }
}
static void flush_pending(raw_lane *lane) {
  for (size_t slot=0u;slot<lane->accepted;++slot) {
    raw_server_peer *p=&lane->peers[slot];
    if (!p->pending_size) continue;
    int status=send_copy(&lane->client,p->connection,p->pending,p->pending_size);
    if (status!=SALTS_OK) {
      lane_error(lane,status,"raw CNet echo reply");return;
    }
    p->pending_size=0u;
    p->replies++;
  }
}
static void progress(native_io_sharded_context *ctx,void *arg) {
  raw_lane *lane=(raw_lane *)arg;
  raw_case *sc=lane->scenario;
  native_io_sharded_completion events[RAW_BATCH];
  cnet_client *clients[1]={&lane->client};
  cnet_sg_host_routes routes={sizeof(routes),CNET_SG_HOST_ROUTING_VERSION,
                             lane->shard==0u&&lane->listener.impl?&lane->listener:NULL,
                             clients,1u};
  size_t observed=0u,routed=0u,accepts=0u,sg_settled=0u;
  if (lane->error||lane->stopped) return;
  if (native_io_sharded_context_shard(ctx)!=lane->shard ||
      cmeta_thread_current_token()!=lane->owner_thread) {
    lane_error(lane,SALTS_EPERM,"raw progress wrong owner");return;
  }
  if (lane->shard) {
    take_final(lane);
    if (lane->error) return;
  }
  RAW_CHECK(lane,cnet_client_advance_external(&lane->client,&routed));
  int status=native_io_sharded_context_observe_host(
      ctx,lane->lease,events,RAW_BATCH,0u,&observed);
  if (status!=SALTS_OK && status!=SALTS_ETIMEDOUT) {
    lane_error(lane,status,"raw SG observe");return;
  }
  RAW_CHECK(lane,cnet_sg_host_route_batch(
      events,observed,&routes,&accepts,&sg_settled));
  if (!lane->shard && accepts) {
    publish_accepted(lane);
    if (lane->error) return;
  }
  RAW_CHECK(lane,cnet_client_advance_external(&lane->client,&routed));
  if (lane->shard) {
    for (size_t i=0u;i<lane->accepted;++i) {
      raw_server_peer *p=&lane->peers[i];
      if (p->connected && !p->receive_armed) {
        /* Arm the FIRST receive exactly once; callback reparms later reads.
         * Repeated demand without this flag silently changes CNet work. */
        RAW_CHECK(lane,cnet_receive(&lane->client,p->connection,1u));
        p->receive_armed=1;
      }
    }
    flush_pending(lane);
  }
  ++lane->turned;
}
static void submit(raw_case *sc,size_t shard,native_io_sharded_task_fn fn) {
  native_io_sharded_task task={fn,NULL,NULL,&sc->lanes[shard]};
  check_equal(SALTS_OK,native_io_sharded_submit_to(sc->sg,shard,&task));
}
static void barrier(raw_case *sc) {
  check_equal(SALTS_OK,native_io_sharded_wait(sc->sg));
  for (size_t i=0u;i<RAW_SHARDS;++i) {
    const raw_lane *lane=&sc->lanes[i];
    if (lane->error!=SALTS_OK)
      fprintf(stderr,"raw SG %u Finals: shard %zu error %d at %s\n",
         (unsigned)RAW_FINALS,i,lane->error,
         lane->failed_at?lane->failed_at:"?");
    check_equal(SALTS_OK,lane->error);
  }
}
static void pump_clients(raw_case *sc) {
  for (size_t i=0u;i<RAW_SESSIONS;++i) {
    raw_client *c=&sc->clients[i];
    if (!c->client.impl) continue;
    size_t events=0u;
    check_equal(SALTS_OK,cnet_client_poll(&c->client,0u,&events));
    if (c->connected && !c->terminal && c->received==0u &&
        c->received_used==0u && c->sent_ns==0u) {
      /* First receive demand, subsequent rearm from callbacks. */
      check_equal(SALTS_OK,cnet_receive(&c->client,c->connection,1u));
      c->sent_ns=1u; /* set to a real timestamp before measured request */
    }
  }
}
static void pump(raw_case *sc) {
  pump_clients(sc);
  for (size_t shard=0u;shard<RAW_SHARDS;++shard)
    submit(sc,shard,progress);
  barrier(sc);
}
#if BENCH_RAW_ASYNC_PROGRESS
static void progress_cancel(void *ctx,int status) {
  raw_lane *lane=(raw_lane *)ctx;
  atomic_store_explicit(&lane->cancel_status,status,memory_order_relaxed);
}
static void progress_finalized(void *ctx) {
  raw_lane *lane=(raw_lane *)ctx;
  atomic_store_explicit(&lane->progress_ready,true,memory_order_release);
}
static void pump_independent(raw_case *sc) {
  pump_clients(sc);
  for (size_t shard=0u;shard<RAW_SHARDS;++shard) {
    raw_lane *lane=&sc->lanes[shard];
    check_equal(SALTS_OK,atomic_load_explicit(
        &lane->owner_failed,memory_order_acquire));
    check_equal(0,atomic_load_explicit(
        &lane->cancel_status,memory_order_relaxed));
    if (!atomic_exchange_explicit(
            &lane->progress_ready,false,memory_order_acq_rel))
      continue;
    native_io_sharded_task task={
      progress,progress_cancel,progress_finalized,lane
    };
    const int status=native_io_sharded_try_submit_to(sc->sg,shard,&task);
    if (status!=SALTS_OK) {
      /* One in-flight SG Host task, never a second per-shard observer. */
      atomic_store_explicit(&lane->progress_ready,true,memory_order_release);
      if (status!=SALTS_ENOBUFS) check_equal(SALTS_OK,status);
    }
  }
}
static void finish_independent(raw_case *sc) {
  /* One native SG wait AFTER measured operations, not per echo round. */
  barrier(sc);
  for (size_t shard=0u;shard<RAW_SHARDS;++shard) {
    raw_lane *lane=&sc->lanes[shard];
    check_true(atomic_load_explicit(
        &lane->progress_ready,memory_order_acquire));
    check_equal(SALTS_OK,atomic_load_explicit(
        &lane->owner_failed,memory_order_acquire));
    check_equal(0,atomic_load_explicit(
        &lane->cancel_status,memory_order_relaxed));
  }
}
#define RAW_MEASURE_PUMP(s) pump_independent(s)
#define RAW_MEASURE_BOUNDARY(s) finish_independent(s)
#define RAW_MEASURE_FINISH(s) finish_independent(s)
#else
#define RAW_MEASURE_PUMP(s) pump(s)
#define RAW_MEASURE_BOUNDARY(s) ((void)0)
#define RAW_MEASURE_FINISH(s) ((void)0)
#endif
static void run_rounds(raw_case *sc) {
  const size_t total=sc->warmup+sc->rounds;
  uint64_t wall0=0u,cpu0=0u;
#if BENCH_APP_INDEPENDENT
  /* Identical four independent per-session one-inflight request streams
   * to the signed MMP fixture; no global app round barrier and no
   * duplicate receive demand. The native CNet SG Host remains sole
   * external observer, whichever Owner scheduler was selected. */
  for (size_t phase=0u;phase<2u;++phase) {
    const size_t target=phase?total:sc->warmup;
    if (phase) {
      RAW_MEASURE_BOUNDARY(sc);
      wall0=mono_ns(CLOCK_MONOTONIC);
      cpu0=mono_ns(CLOCK_PROCESS_CPUTIME_ID);
    }
    const uint64_t deadline=cmeta_monotonic_ms()+RAW_TIMEOUT_MS;
    for (;;) {
      bool all_done=true;
      for (size_t i=0u;i<RAW_SESSIONS;++i) {
        raw_client *c=&sc->clients[i];
        check_equal((size_t)0u,c->invalid);
        check_true(c->received<=c->next_to_send &&
                   c->next_to_send<=target);
        if (c->received==c->next_to_send && c->next_to_send<target) {
          const size_t round=c->next_to_send;
          frame(c->request,sc->bytes,i,round);
          c->sent_ns=mono_ns(CLOCK_MONOTONIC);
          check_equal(SALTS_OK,send_copy(
              &c->client,c->connection,c->request,sc->bytes));
          c->next_to_send++;
        }
        if (c->received!=target) all_done=false;
      }
      if (all_done) break;
      check_true(cmeta_monotonic_ms()<deadline);
      RAW_MEASURE_PUMP(sc);
    }
    for (size_t i=0u;i<RAW_SESSIONS;++i) {
      check_equal(target,sc->clients[i].received);
      check_equal(target,sc->clients[i].next_to_send);
      check_equal((size_t)0u,sc->clients[i].invalid);
    }
  }
#else
  for (size_t round=0u;round<total;++round) {
    if (round==sc->warmup) {
      RAW_MEASURE_BOUNDARY(sc);
      wall0=mono_ns(CLOCK_MONOTONIC);
      cpu0=mono_ns(CLOCK_PROCESS_CPUTIME_ID);
    }
    for (size_t i=0u;i<RAW_SESSIONS;++i) {
      raw_client *c=&sc->clients[i];
      frame(c->request,sc->bytes,i,round);
      c->sent_ns=mono_ns(CLOCK_MONOTONIC);
      check_equal(SALTS_OK,send_copy(
          &c->client,c->connection,c->request,sc->bytes));
    }
    const uint64_t deadline=cmeta_monotonic_ms()+RAW_TIMEOUT_MS;
    for (;;) {
      bool complete=true;
      for (size_t i=0u;i<RAW_SESSIONS;++i)
        if (sc->clients[i].received<=round) complete=false;
      if (complete||cmeta_monotonic_ms()>=deadline) break;
      RAW_MEASURE_PUMP(sc);
    }
    for (size_t i=0u;i<RAW_SESSIONS;++i) {
      check_equal(round+1u,sc->clients[i].received);
      check_equal((size_t)0u,sc->clients[i].invalid);
    }
  }
#endif
  RAW_MEASURE_FINISH(sc);
  uint64_t wall1=mono_ns(CLOCK_MONOTONIC),cpu1=mono_ns(CLOCK_PROCESS_CPUTIME_ID);
  const double elapsed=(double)(wall1-wall0)/1e9;
  const double cpu=(double)(cpu1-cpu0)/1e9;
  const size_t sample_count=RAW_SESSIONS*sc->rounds;
  uint64_t *combined=calloc(sample_count,sizeof(uint64_t));
  check_not_null(combined);
  for (size_t i=0u;i<RAW_SESSIONS;++i) {
    raw_client *c=&sc->clients[i];
    memcpy(combined+i*sc->rounds,c->samples,sc->rounds*sizeof(uint64_t));
    for (size_t j=0u;j<sc->rounds;++j)
      printf("RAW_CNET_SG_RTT,%s,%u,%u,%zu,%zu,%zu,%.3f\n",
          RAW_DRIVER_LABEL,(unsigned)RAW_FINALS,(unsigned)RAW_SHARDS,i+1u,sc->bytes,j+1u,
          (double)c->samples[j]/1000.0);
    qsort(c->samples,sc->rounds,sizeof(uint64_t),sort_u64);
    printf("RAW_CNET_SG_SESSION,raw-cnet-tcp-echo,%s,"
           "%u,%u,%zu,%zu,%zu,%.3f,%.3f,%.3f\n",
           RAW_DRIVER_LABEL,(unsigned)RAW_FINALS,(unsigned)RAW_SHARDS,
           i+1u,sc->bytes,sc->rounds,
           (double)percentile(c->samples,sc->rounds,50u)/1000.0,
           (double)percentile(c->samples,sc->rounds,95u)/1000.0,
           (double)percentile(c->samples,sc->rounds,99u)/1000.0);
  }
  qsort(combined,sample_count,sizeof(uint64_t),sort_u64);
  check_true(elapsed>0u);
  const double messages=(double)sc->rounds*RAW_SESSIONS*2.0;
  printf("RAW_CNET_SG_BENCH,raw-cnet-tcp-echo,%s,"
         "%u,%u,%u,%zu,%zu,%zu,%.3f,%.3f,%.3f,%.3f,%.6f,%.3f,%.3f,%.3f\n",
         RAW_DRIVER_LABEL,(unsigned)RAW_FINALS,(unsigned)RAW_SHARDS,(unsigned)RAW_SESSIONS,
         sc->bytes,sc->rounds,sc->warmup,
         elapsed*1000.0,cpu*1000.0,cpu*100.0/elapsed,
         messages/elapsed,messages*(double)sc->bytes/(1048576.0*elapsed),
         (double)percentile(combined,sample_count,50u)/1000.0,
         (double)percentile(combined,sample_count,95u)/1000.0,
         (double)percentile(combined,sample_count,99u)/1000.0);
  fflush(stdout);
  free(combined);
}
static void stop_raw_worker(native_io_sharded_context *ctx,void *arg) {
  raw_lane *lane=(raw_lane *)arg;
  raw_case *sc=lane->scenario;
  if (lane->stopped||lane->error) return;
  if (!lane->shard) {
    if (!lane->closing) {
      int rc=cnet_listener_close(&lane->listener);
      if (rc==SALTS_EBUSY) {lane->stops++;return;}
      if (rc!=SALTS_OK) {lane_error(lane,rc,"raw listener close");return;}
      lane->closing=1;
    }
    int rc=cnet_listener_destroy(&lane->listener);
    if (rc==SALTS_EBUSY) {lane->stops++;return;}
    if (rc!=SALTS_OK) {lane_error(lane,rc,"raw listener destroy");return;}
  }
  int rc=cnet_client_stop_external(&lane->client);
  if (rc==SALTS_EBUSY) {lane->stops++;return;}
  if (rc!=SALTS_OK) {lane_error(lane,rc,"raw client stop external");return;}
  RAW_CHECK(lane,cnet_client_destroy(&lane->client));
  if (lane->shard) {
    for (size_t i=0u;i<lane->accepted;++i) {
      raw_server_peer *p=&lane->peers[i];
      if (!p->terminal||!p->ticket.slot) {
        lane_error(lane,SALTS_EBUSY,"raw final terminal/credit");return;
      }
      RAW_CHECK(lane,cnet_handoff_release(&sc->handoffs[lane->shard-1u],
                                           p->ticket));
      p->ticket=(cnet_handoff_ticket){0};
    }
  }
  lane->stopped=1;
}
static void destroy_raw_worker(native_io_sharded_context *ctx,void *arg) {
  raw_lane *lane=(raw_lane *)arg;
  if (native_io_sharded_context_shard(ctx)!=lane->shard ||
      cmeta_thread_current_token()!=lane->owner_thread ||
      lane->error || !lane->stopped)
    {lane_error(lane,SALTS_EPERM,"raw destroy owner");return;}
  lane->released=1;
  RAW_CHECK(lane,native_io_sharded_context_release_host(ctx,lane->lease));
  lane->backend=NULL;
}
static void run_raw_cnet_benchmark(void) {
  raw_case scenario={0},*sc=&scenario;
  const native_io_sharded_config sg_cfg={
    RAW_SHARDS,8u,{backend_kind(),64u,128u,RAW_BATCH}};
  sc->warmup=env_count("P2P_MMP_BENCH_WARMUP",16u,512u);
  sc->rounds=env_count("P2P_MMP_BENCH_ROUNDS",128u,4096u);
  sc->bytes=env_count("P2P_MMP_BENCH_PAYLOAD",8u,RAW_BYTES_MAX);
  if (sc->bytes!=8u && sc->bytes!=1024u) {
    fprintf(stderr,"raw baseline payload must be 8 or 1024\n");exit(2);
  }
  for (size_t i=0u;i<RAW_FINALS;++i) {
    const cnet_handoff_config config={
       sizeof(config),CNET_HANDOFF_VERSION,RAW_PER_FINAL,RAW_PER_FINAL};
    check_equal(SALTS_OK,cnet_handoff_init(&sc->handoffs[i],&config));
  }
  check_equal(SALTS_OK,native_io_sharded_create(&sg_cfg,&sc->sg));
  for (size_t i=0u;i<RAW_SHARDS;++i) {
    sc->lanes[i].scenario=sc;
    sc->lanes[i].shard=i;
#if BENCH_RAW_ASYNC_PROGRESS
    atomic_init(&sc->lanes[i].progress_ready,true);
    atomic_init(&sc->lanes[i].cancel_status,0);
    atomic_init(&sc->lanes[i].owner_failed,SALTS_OK);
#endif
    submit(sc,i,init_host);
  }
  barrier(sc);
  check_true(sc->lanes[0].local.port!=0u);
  for (size_t i=0u;i<RAW_SESSIONS;++i) {
    raw_client *c=&sc->clients[i];
    c->scenario=sc;c->index=i;c->rounds=sc->rounds;c->warmup=sc->warmup;
    c->samples=calloc(sc->rounds,sizeof(uint64_t));
    check_not_null(c->samples);
    cnet_client_config cfg=client_cfg(1u);
    check_equal(SALTS_OK,cnet_client_init(&c->client,&cfg));
    cnet_observer obs=client_observer(c);
    check_equal(SALTS_OK,cnet_connect_endpoint(
      &c->client,&sc->lanes[0].local,NULL,&obs,&c->connection));
    const uint64_t deadline=cmeta_monotonic_ms()+RAW_TIMEOUT_MS;
    for (;;) {
      pump(sc);
      raw_lane *final=&sc->lanes[1u+i%RAW_FINALS];
      if (c->connected && final->accepted>i/RAW_FINALS &&
          final->peers[i/RAW_FINALS].connected) break;
      if (cmeta_monotonic_ms()>=deadline) break;
    }
    check_equal((size_t)1u,c->connected);
    check_true(sc->lanes[1u+i%RAW_FINALS].accepted>i/RAW_FINALS);
  }
  check_equal((size_t)RAW_SESSIONS,sc->published);
  for (size_t i=0u;i<RAW_FINALS;++i) {
    cnet_handoff_snapshot snap={0};
    check_equal(SALTS_OK,cnet_handoff_get_snapshot(&sc->handoffs[i],&snap));
    check_equal((size_t)RAW_PER_FINAL,snap.taken);
    check_equal((size_t)0u,snap.queued);
  }
  run_rounds(sc);
  sc->stopping=1;
  for (size_t i=0u;i<RAW_SESSIONS;++i)
    check_equal(SALTS_OK,cnet_close(&sc->clients[i].client,
                                   sc->clients[i].connection));
  const uint64_t deadline=cmeta_monotonic_ms()+RAW_TIMEOUT_MS;
  for (;;) {
    pump(sc);
    int drained=1;
    for (size_t i=0u;i<RAW_SESSIONS;++i)
      if (!sc->clients[i].terminal) drained=0;
    for (size_t shard=1u;shard<RAW_SHARDS;++shard)
      for (size_t i=0u;i<sc->lanes[shard].accepted;++i)
        if (!sc->lanes[shard].peers[i].terminal) drained=0;
    if (drained||cmeta_monotonic_ms()>=deadline) break;
  }
  for (size_t i=0u;i<RAW_SESSIONS;++i) {
    raw_client *c=&sc->clients[i];
    check_equal((size_t)1u,c->terminal);
    check_equal((size_t)0u,c->invalid);
    check_equal(SALTS_OK,cnet_client_stop(&c->client,5000u));
    check_equal(SALTS_OK,cnet_client_destroy(&c->client));
  }
  for (size_t shard=0u;shard<RAW_SHARDS;++shard)
    submit(sc,shard,stop_raw_worker);
  barrier(sc);
  const uint64_t stop_deadline=cmeta_monotonic_ms()+RAW_TIMEOUT_MS;
  for (;;) {
    bool complete=true;
    for (size_t shard=0u;shard<RAW_SHARDS;++shard)
      if (!sc->lanes[shard].stopped) {
        complete=false;
        submit(sc,shard,progress);
      }
    if (complete || cmeta_monotonic_ms()>=stop_deadline) break;
    barrier(sc);
    for (size_t shard=0u;shard<RAW_SHARDS;++shard)
      if (!sc->lanes[shard].stopped)
        submit(sc,shard,stop_raw_worker);
    barrier(sc);
  }
  for (size_t shard=0u;shard<RAW_SHARDS;++shard)
    check_true(sc->lanes[shard].stopped);
  for (size_t i=0u;i<RAW_FINALS;++i) {
    cnet_handoff_snapshot snap={0};
    check_equal(SALTS_OK,cnet_handoff_get_snapshot(&sc->handoffs[i],&snap));
    check_true(snap.drained);
    check_equal((size_t)0u,snap.taken);
    check_equal(SALTS_OK,cnet_handoff_seal(&sc->handoffs[i]));
    check_equal(SALTS_OK,cnet_handoff_destroy(&sc->handoffs[i]));
  }
  for (size_t shard=0u;shard<RAW_SHARDS;++shard)
    submit(sc,shard,destroy_raw_worker);
  barrier(sc);
  check_equal(SALTS_OK,native_io_sharded_shutdown(sc->sg));
  check_equal(SALTS_OK,native_io_sharded_destroy(sc->sg));
  for (size_t i=0u;i<RAW_SESSIONS;++i) free(sc->clients[i].samples);
}
spec("Raw CNet four-connection equal-work NativeIO SG Handoff") {
  it("echoes 8B/1024B on 1/2/4 final workers without Noise or MMP") {
    run_raw_cnet_benchmark();
  }
}
