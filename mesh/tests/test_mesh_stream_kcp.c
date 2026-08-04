#include <tinytest.h>

#include "mesh_stream_kcp_adapter.h"

#include <CoroNet.h>

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <sys/socket.h>
#endif

/* P7: bind mesh_stream_live to a real CoroNet KCP transport. The live FEC
 * group maps to turbo_kcp's Reed-Solomon FEC config and the session io is
 * bridged to coro_socket_send/recv. A loopback KCP server + client carry a
 * live session (app FEC 2+1) end to end; the FEC mapping itself is asserted
 * both at the config level and on a real KCP socket. */

#define TEST_PSK_SIZE 32u
#define TEST_BLOCK 64u
#define TEST_BLOCKS 6u
#define TEST_RECV_TIMEOUT_MS 10u
#define TEST_RUN_TIMEOUT 10000u

static const uint8_t TEST_PSK[TEST_PSK_SIZE] = {
    0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
    0x1f, 0x2e, 0x3d, 0x4c, 0x5b, 0x6a, 0x79, 0x88, 0x97, 0xa6, 0xb5, 0xc4, 0xd3, 0xe2, 0xf1, 0x01};

typedef struct {
  coro_context_t *ctx;
  unsigned short port;
  uint8_t got[TEST_BLOCKS][TEST_BLOCK];
  uint64_t seqs[TEST_BLOCKS];
  size_t lens[TEST_BLOCKS];
  size_t delivered;
  int client_done;
  int server_done;
  int ok;
} kcp_live_state_t;

static void fill_block(uint8_t *out, size_t len, uint64_t id) {
  for (size_t i = 0u; i < len; i++)
    out[i] = (uint8_t)(id * 29u + i * 11u + (i >> 3u));
}

static unsigned short pick_loopback_port(void) {
  unsigned short port = 0u;
  struct sockaddr_in address;
#ifdef _WIN32
  int address_len = (int)sizeof(address);
  SOCKET socket_handle = INVALID_SOCKET;
#else
  socklen_t address_len = (socklen_t)sizeof(address);
  int socket_handle = -1;
#endif

  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = htons(0u);
  socket_handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#ifdef _WIN32
  if (socket_handle == INVALID_SOCKET)
    return 0u;
#else
  if (socket_handle < 0)
    return 0u;
#endif
  if (bind(socket_handle, (struct sockaddr *)&address, sizeof(address)) == 0 &&
      getsockname(socket_handle, (struct sockaddr *)&address, &address_len) == 0) {
    port = ntohs(address.sin_port);
  }
#ifdef _WIN32
  closesocket(socket_handle);
#else
  close(socket_handle);
#endif
  return port;
}

static turbo_kcp_config_t kcp_config(void) {
  turbo_kcp_config_t config;

  turbo_kcp_config_default(&config);
  memcpy(config.pre_shared_key, TEST_PSK, sizeof(config.pre_shared_key));
  return config;
}

static void make_live_config(mesh_stream_live_config_v1_t *config) {
  memset(config, 0, sizeof(*config));
  for (size_t i = 0u; i < MESH_STREAM_LIVE_STREAM_ID_SIZE; i++)
    config->stream_id[i] = (uint8_t)(0x30u + i);
  config->window_groups = 8u;
  config->skip_gap_groups = 2u;
  config->max_block_bytes = TEST_BLOCK;
  config->fec_data_shards = 2u;
  config->fec_parity_shards = 1u;
  config->join_seq = 0u;
}

static void kcp_live_handler(coro_socket_t *client, void *arg) {
  kcp_live_state_t *state = (kcp_live_state_t *)arg;
  mesh_stream_live_config_v1_t config;
  mesh_stream_live_io_v1_t io;
  mesh_stream_kcp_io_t *kcp_io = NULL;
  mesh_stream_live_t *rx;

  if (mesh_stream_kcp_adapter_io_create_v1(
          client, TEST_RECV_TIMEOUT_MS,
          TEST_BLOCK + MESH_STREAM_LIVE_FRAME_HEADER_SIZE, &kcp_io) !=
      MESH_STREAM_KCP_ADAPTER_OK) {
    state->ok = 0;
    return;
  }
  if (mesh_stream_kcp_adapter_io_live_io_v1(kcp_io, &io) !=
      MESH_STREAM_KCP_ADAPTER_OK) {
    mesh_stream_kcp_adapter_io_destroy_v1(kcp_io);
    state->ok = 0;
    return;
  }
  make_live_config(&config);
  rx = mesh_stream_live_create(MESH_STREAM_LIVE_ROLE_RECEIVER, &config, &io);
  if (!rx) {
    mesh_stream_kcp_adapter_io_destroy_v1(kcp_io);
    state->ok = 0;
    return;
  }
  for (;;) {
    size_t len = 0u;
    uint64_t seq = 0u;
    mesh_stream_live_result_t rc = mesh_stream_live_receiver_pump(
        rx, state->got[state->delivered], TEST_BLOCK, &len, &seq);

    if (rc == MESH_STREAM_LIVE_END)
      break;
    if (rc != MESH_STREAM_LIVE_OK || state->delivered >= TEST_BLOCKS) {
      state->ok = 0;
      break;
    }
    state->seqs[state->delivered] = seq;
    state->lens[state->delivered] = len;
    state->delivered++;
  }
  mesh_stream_live_destroy(rx);
  mesh_stream_kcp_adapter_io_destroy_v1(kcp_io);
  state->server_done = 1;
}

static void kcp_live_client(coro_t *co, void *arg) {
  kcp_live_state_t *state = (kcp_live_state_t *)arg;
  coro_socket_t *client = NULL;
  turbo_kcp_config_t config = kcp_config();
  mesh_stream_live_config_v1_t live_config;
  mesh_stream_live_io_v1_t io;
  mesh_stream_kcp_io_t *kcp_io = NULL;
  mesh_stream_live_t *tx = NULL;
  uint8_t block[TEST_BLOCK];
  uint64_t seq = 0u;
  int wait;

  (void)co;
  client = coro_socket_create_kcp(state->ctx);
  if (!client)
    goto fail;
  if (coro_socket_set_kcp_config(client, &config) != 0)
    goto fail;
  coro_socket_set_timeout(client, 2000u);
  if (coro_socket_connect(client, "127.0.0.1", state->port) != 0) {
    goto fail;
  }
  if (mesh_stream_kcp_adapter_io_create_v1(
          client, TEST_RECV_TIMEOUT_MS,
          TEST_BLOCK + MESH_STREAM_LIVE_FRAME_HEADER_SIZE, &kcp_io) !=
      MESH_STREAM_KCP_ADAPTER_OK) {
    goto fail;
  }
  if (mesh_stream_kcp_adapter_io_live_io_v1(kcp_io, &io) !=
      MESH_STREAM_KCP_ADAPTER_OK) {
    goto fail;
  }
  make_live_config(&live_config);
  tx = mesh_stream_live_create(MESH_STREAM_LIVE_ROLE_SENDER, &live_config, &io);
  if (!tx) {
    goto fail;
  }
  for (size_t i = 0u; i < TEST_BLOCKS; i++) {
    fill_block(block, TEST_BLOCK, i);
    if (mesh_stream_live_sender_produce(tx, block, TEST_BLOCK, &seq) !=
        MESH_STREAM_LIVE_OK) {
      goto fail;
    }
  }
  if (mesh_stream_live_sender_finish(tx) != MESH_STREAM_LIVE_OK)
    goto fail;
  mesh_stream_live_destroy(tx);
  tx = NULL;

  wait = TEST_RUN_TIMEOUT;
  while (!state->server_done && wait > 0) {
    coro_sleep(state->ctx, 5u); /* let the server's recv timeouts fire */
    wait -= 5;
  }
  state->client_done = 1;
  if (kcp_io)
    mesh_stream_kcp_adapter_io_destroy_v1(kcp_io);
  if (client)
    coro_socket_destroy(client);
  coro_context_stop(state->ctx);
  return;

fail:
  if (tx)
    mesh_stream_live_destroy(tx);
  if (kcp_io)
    mesh_stream_kcp_adapter_io_destroy_v1(kcp_io);
  if (client)
    coro_socket_destroy(client);
  state->ok = 0;
  state->client_done = 1;
  coro_context_stop(state->ctx);
}

static void destroy_context_robust(coro_context_t *ctx) {
  int drain = 500;

  if (!ctx)
    return;
  coro_context_stop(ctx);
  while (drain-- > 0) {
    if (!coro_context_alive(ctx))
      break;
    coro_context_run(ctx, TURBO_RUN_NOWAIT);
  }
  coro_context_destroy(ctx);
}

/* ---- fec config mapping ---- */

static void test_fec_config_mapping(void) {
  mesh_stream_live_config_v1_t live;
  turbo_kcp_fec_config_t fec;

  /* No live FEC -> disabled transport FEC. */
  make_live_config(&live);
  live.fec_data_shards = 0u;
  live.fec_parity_shards = 0u;
  check_int_eq(MESH_STREAM_KCP_ADAPTER_OK,
               mesh_stream_kcp_adapter_fec_config_v1(&live, &fec));
  check_int_eq(fec.backend, TURBO_KCP_FEC_BACKEND_NONE);

  /* Live FEC 2+1 -> Reed-Solomon with the same shards and block payload. */
  make_live_config(&live);
  check_int_eq(MESH_STREAM_KCP_ADAPTER_OK,
               mesh_stream_kcp_adapter_fec_config_v1(&live, &fec));
  check_int_eq(fec.backend, TURBO_KCP_FEC_BACKEND_REED_SOLOMON);
  check_int_eq(fec.data_shards, 2u);
  check_int_eq(fec.parity_shards, 1u);
  check_int_eq(fec.max_payload_size, TEST_BLOCK);
  check_uint_eq(fec.receive_group_count, 16u);

  check_int_eq(MESH_STREAM_KCP_ADAPTER_INVALID_ARG,
               mesh_stream_kcp_adapter_fec_config_v1(NULL, &fec));
  check_int_eq(MESH_STREAM_KCP_ADAPTER_INVALID_ARG,
               mesh_stream_kcp_adapter_fec_config_v1(&live, NULL));

  /* Parity without data is invalid. */
  make_live_config(&live);
  live.fec_data_shards = 0u;
  live.fec_parity_shards = 1u;
  check_int_eq(MESH_STREAM_KCP_ADAPTER_INVALID_ARG,
               mesh_stream_kcp_adapter_fec_config_v1(&live, &fec));
}

/* ---- KCP FEC binding on a real socket ---- */

static void test_kcp_fec_socket_binding(void) {
  coro_context_t *ctx = coro_context_create(NULL);
  coro_socket_t *socket;
  turbo_kcp_config_t config;
  turbo_kcp_fec_config_t got;
  mesh_stream_live_config_v1_t live;
  turbo_kcp_fec_config_t fec;

  check_not_null(ctx);
  socket = coro_socket_create_kcp(ctx);
  check_not_null(socket);
  make_live_config(&live);
  live.max_block_bytes = 2048u; /* >= mtu(1200) + record overhead(48) */
  check_int_eq(MESH_STREAM_KCP_ADAPTER_OK,
               mesh_stream_kcp_adapter_fec_config_v1(&live, &fec));
  config = kcp_config();
  config.fec = fec;
  check_int_eq(coro_socket_set_kcp_config(socket, &config), 0);
  memset(&got, 0, sizeof(got));
  check_int_eq(coro_socket_get_kcp_config(socket, &config), 0);
  check_int_eq(config.fec.data_shards, 2u);
  check_int_eq(config.fec.parity_shards, 1u);
  check_int_eq(config.fec.backend, TURBO_KCP_FEC_BACKEND_REED_SOLOMON);
  coro_socket_destroy(socket);
  destroy_context_robust(ctx);
}

/* ---- live session over a real KCP loopback ---- */

static void test_kcp_live_loopback(void) {
  coro_context_t *ctx = coro_context_create(NULL);
  coro_socket_t *server;
  turbo_kcp_config_t config = kcp_config();
  kcp_live_state_t state;

  check_not_null(ctx);
  memset(&state, 0, sizeof(state));
  state.ctx = ctx;
  state.ok = 1;

  state.port = pick_loopback_port();
  check_true(state.port != 0u);
  server = coro_socket_create_kcp(ctx);
  check_not_null(server);
  check_int_eq(coro_socket_set_kcp_config(server, &config), 0);
  check_int_eq(coro_socket_listen_on(server, "127.0.0.1", state.port, kcp_live_handler, &state), 0);

  check_int_eq(coro_context_spawn(ctx, kcp_live_client, &state), 0);
  coro_context_run(ctx, TURBO_RUN_DEFAULT);

  check_int_eq(state.ok, 1);
  check_int_eq(state.client_done, 1);
  check_int_eq(state.server_done, 1);
  check_size_eq(state.delivered, TEST_BLOCKS);
  {
    /* 2 data + 1 parity groups: delivered data seqs are 0,1,3,4,6,7. */
    static const uint64_t exp_seqs[TEST_BLOCKS] = {0u, 1u, 3u, 4u, 6u, 7u};
    uint8_t block[TEST_BLOCK];

    for (size_t i = 0u; i < state.delivered; i++) {
      check_uint_eq(state.seqs[i], exp_seqs[i]);
      check_size_eq(state.lens[i], TEST_BLOCK);
      fill_block(block, TEST_BLOCK, (state.seqs[i] / 3u) * 2u + (state.seqs[i] % 3u));
      check_mem_eq(state.got[i], block, TEST_BLOCK);
    }
  }

  coro_socket_destroy(server);
  destroy_context_robust(ctx);
}

/* ---- invalid args ---- */

static void test_invalid_args(void) {
  mesh_stream_live_io_v1_t io;
  mesh_stream_kcp_io_t *kcp_io = (mesh_stream_kcp_io_t *)&io;

  check_int_eq(MESH_STREAM_KCP_ADAPTER_INVALID_ARG,
               mesh_stream_kcp_adapter_io_create_v1(NULL, 30u, 128u, &kcp_io));
  check_int_eq(MESH_STREAM_KCP_ADAPTER_INVALID_ARG,
               mesh_stream_kcp_adapter_io_create_v1((coro_socket_t *)&io, 0u, 128u, &kcp_io));
  check_int_eq(MESH_STREAM_KCP_ADAPTER_INVALID_ARG,
               mesh_stream_kcp_adapter_io_create_v1((coro_socket_t *)&io, 30u, 0u, &kcp_io));
  check_int_eq(MESH_STREAM_KCP_ADAPTER_INVALID_ARG,
               mesh_stream_kcp_adapter_io_create_v1((coro_socket_t *)&io, 30u, 128u, NULL));
  check_int_eq(MESH_STREAM_KCP_ADAPTER_INVALID_ARG,
               mesh_stream_kcp_adapter_io_live_io_v1(NULL, &io));
  check_int_eq(MESH_STREAM_KCP_ADAPTER_INVALID_ARG,
               mesh_stream_kcp_adapter_io_live_io_v1(kcp_io, NULL));
  mesh_stream_kcp_adapter_io_destroy_v1(NULL);
}

spec("mesh stream kcp adapter") {
    describe("KCP transport binding") {
        it("maps live FEC groups to the KCP Reed-Solomon config") {
            test_fec_config_mapping();
        }
        it("applies the mapped FEC config to a real KCP socket") {
            test_kcp_fec_socket_binding();
        }
        it("carries a live session over a KCP loopback") {
            test_kcp_live_loopback();
        }
        it("rejects invalid arguments") {
            test_invalid_args();
        }
    }
}