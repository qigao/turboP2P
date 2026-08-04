/* mesh_stream_live_source_main.c - live source: produce blocks, send over KCP.
 *
 * A coroutine connects a KCP socket to a relay, runs a mesh_stream_live sender
 * over the KCP io (no FEC: ordered delivery) and produces N deterministic
 * segments, then finishes. The relay receives them and serves HLS.
 *
 * Usage:
 *   mesh_stream_live_source_main --host <h> --port <p> --segments <N> [--block <b>]
 */

#include "mesh_stream_kcp_adapter.h"
#include "mesh_stream_live.h"

#include <CoroNet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#define DEFAULT_BLOCK 256u

static const uint8_t LIVE_PSK[32] = {
    0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
    0x1f, 0x2e, 0x3d, 0x4c, 0x5b, 0x6a, 0x79, 0x88, 0x97, 0xa6, 0xb5, 0xc4, 0xd3, 0xe2, 0xf1, 0x01};

typedef struct {
  coro_context_t *ctx;
  const char *host;
  unsigned short port;
  uint64_t segments;
  uint64_t block_size;
  int ok;
  int done;
} source_state_t;

static void fill_block(uint8_t *out, size_t len, uint64_t id) {
  for (size_t i = 0u; i < len; i++)
    out[i] = (uint8_t)(id * 31u + i * 7u + (i >> 3u));
}

static void source_client(coro_t *co, void *arg) {
  source_state_t *state = (source_state_t *)arg;
  coro_socket_t *client = NULL;
  turbo_kcp_config_t kcp_config;
  mesh_stream_live_config_v1_t live_config;
  mesh_stream_live_io_v1_t io;
  mesh_stream_kcp_io_t *kcp_io = NULL;
  mesh_stream_live_t *tx = NULL;
  uint8_t *block = NULL;
  uint64_t seq = 0u;

  (void)co;
  block = (uint8_t *)malloc((size_t)state->block_size);
  client = coro_socket_create_kcp(state->ctx);
  if (!block || !client)
    goto fail;
  turbo_kcp_config_default(&kcp_config);
  memcpy(kcp_config.pre_shared_key, LIVE_PSK, sizeof(LIVE_PSK));
  if (coro_socket_set_kcp_config(client, &kcp_config) != 0)
    goto fail;
  coro_socket_set_timeout(client, 3000u);
  if (coro_socket_connect(client, state->host, state->port) != 0)
    goto fail;
  if (mesh_stream_kcp_adapter_io_create_v1(
          client, 30u, (size_t)state->block_size + MESH_STREAM_LIVE_FRAME_HEADER_SIZE,
          &kcp_io) != MESH_STREAM_KCP_ADAPTER_OK) {
    goto fail;
  }
  if (mesh_stream_kcp_adapter_io_live_io_v1(kcp_io, &io) !=
      MESH_STREAM_KCP_ADAPTER_OK) {
    goto fail;
  }
  memset(&live_config, 0, sizeof(live_config));
  live_config.window_groups = 16u;
  live_config.skip_gap_groups = 4u;
  live_config.max_block_bytes = state->block_size;
  live_config.fec_data_shards = 0u;
  tx = mesh_stream_live_create(MESH_STREAM_LIVE_ROLE_SENDER, &live_config, &io);
  if (!tx)
    goto fail;
  for (uint64_t i = 0u; i < state->segments; i++) {
    fill_block(block, (size_t)state->block_size, i);
    if (mesh_stream_live_sender_produce(tx, block, (size_t)state->block_size,
                                        &seq) != MESH_STREAM_LIVE_OK) {
      goto fail;
    }
  }
  if (mesh_stream_live_sender_finish(tx) != MESH_STREAM_LIVE_OK)
    goto fail;
  mesh_stream_live_destroy(tx);
  tx = NULL;
  /* Give the relay a moment to drain, then stop the context. */
  {
    int wait = 1000;

    while (wait-- > 0)
      coro_yield();
  }
  state->ok = 1;
  state->done = 1;
  if (kcp_io)
    mesh_stream_kcp_adapter_io_destroy_v1(kcp_io);
  coro_socket_destroy(client);
  free(block);
  coro_context_stop(state->ctx);
  return;

fail:
  if (tx)
    mesh_stream_live_destroy(tx);
  if (kcp_io)
    mesh_stream_kcp_adapter_io_destroy_v1(kcp_io);
  if (client)
    coro_socket_destroy(client);
  free(block);
  state->done = 1;
  coro_context_stop(state->ctx);
}

int main(int argc, char **argv) {
  source_state_t state;
  const char *host = "127.0.0.1";
  unsigned short port = 0u;
  uint64_t segments = 0u;
  uint64_t block_size = DEFAULT_BLOCK;
  int drain = 500;

  memset(&state, 0, sizeof(state));
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--host") == 0 && i + 1 < argc)
      host = argv[++i];
    else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc)
      port = (unsigned short)strtoul(argv[++i], NULL, 10);
    else if (strcmp(argv[i], "--segments") == 0 && i + 1 < argc)
      segments = strtoull(argv[++i], NULL, 10);
    else if (strcmp(argv[i], "--block") == 0 && i + 1 < argc)
      block_size = strtoull(argv[++i], NULL, 10);
    else {
      fprintf(stderr, "unknown arg: %s\n", argv[i]);
      return 1;
    }
  }
  if (port == 0u || segments == 0u || block_size == 0u)
    return 1;
  state.host = host;
  state.port = port;
  state.segments = segments;
  state.block_size = block_size;
  state.ctx = coro_context_create(NULL);
  if (!state.ctx)
    return 1;
  if (coro_context_spawn(state.ctx, source_client, &state) != 0)
    return 1;
  coro_context_run(state.ctx, TURBO_RUN_DEFAULT);
  while (drain-- > 0 && coro_context_alive(state.ctx))
    coro_context_run(state.ctx, TURBO_RUN_NOWAIT);
  coro_context_destroy(state.ctx);
  if (!state.ok) {
    fprintf(stderr, "source failed\n");
    return 1;
  }
  printf("SOURCE OK segments=%llu\n", (unsigned long long)segments);
  return 0;
}