/* mesh_stream_live_hls_main.c - live-over-HTTP demo server.
 *
 * A producer thread generates deterministic segments into the sliding-window
 * HLS live playlist (mesh_stream_live_hls); a minimal HTTP server serves the
 * live playlist (/live.m3u8) and segments (/live/seg-N). A client polls the
 * playlist to watch EXT-X-MEDIA-SEQUENCE advance and fetches segments before
 * they leave the window (evicted segments 404, like LIVE_SKIP).
 *
 * Usage:
 *   mesh_stream_live_hls_main --port <p> --segments <N> --interval-ms <ms>
 *       [--window <W>] [--block <bytes>]
 */

#include "mesh_stream_kcp_adapter.h"
#include "mesh_stream_live.h"
#include "mesh_stream_live_hls.h"

#include <CoroNet.h>

#include <turbo_thread.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#define DEFAULT_BLOCK 256u

static const uint8_t LIVE_PSK[32] = {
    0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
    0x1f, 0x2e, 0x3d, 0x4c, 0x5b, 0x6a, 0x79, 0x88, 0x97, 0xa6, 0xb5, 0xc4, 0xd3, 0xe2, 0xf1, 0x01};

typedef struct {
  mesh_stream_live_hls_v1_t hls;
  uint64_t segments;
  uint64_t interval_ms;
  uint64_t block_size;
  unsigned short kcp_port; /* >0: relay mode (receive live over KCP) */
  volatile int stop;
} live_server_t;

#ifdef _WIN32
typedef SOCKET sock_t;
#define INVALID_SOCK INVALID_SOCKET
#define CLOSE_SOCK closesocket
#else
typedef int sock_t;
#define INVALID_SOCK (-1)
#define CLOSE_SOCK close
#endif

static void producer_thread(void *arg) {
  live_server_t *srv = (live_server_t *)arg;
  uint8_t *block = (uint8_t *)malloc((size_t)srv->block_size);

  if (!block)
    return;
  for (uint64_t i = 0u; i < srv->segments && !srv->stop; i++) {
    uint64_t index = 0u;

    for (size_t j = 0u; j < (size_t)srv->block_size; j++)
      block[j] = (uint8_t)(i * 31u + j * 7u + (j >> 3u));
    if (mesh_stream_live_hls_push_v1(&srv->hls, block, (size_t)srv->block_size,
                                     &index) != MESH_STREAM_LIVE_HLS_OK) {
      break;
    }
    if (i + 1u < srv->segments)
      turbo_sleep_ms((uint32_t)srv->interval_ms);
  }
  free(block);
}

/* Relay mode: a KCP server receives live blocks and pushes them into the HLS
 * window (thread-safe via the HLS mutex) so the HTTP loop can serve them. */
static void relay_handler(coro_socket_t *client, void *arg) {
  live_server_t *srv = (live_server_t *)arg;
  mesh_stream_live_io_v1_t io;
  mesh_stream_kcp_io_t *kcp_io = NULL;
  mesh_stream_live_config_v1_t live_config;
  mesh_stream_live_t *rx = NULL;
  uint8_t *block;

  if (mesh_stream_kcp_adapter_io_create_v1(
          client, 30u,
          (size_t)srv->block_size + MESH_STREAM_LIVE_FRAME_HEADER_SIZE,
          &kcp_io) != MESH_STREAM_KCP_ADAPTER_OK) {
    return;
  }
  if (mesh_stream_kcp_adapter_io_live_io_v1(kcp_io, &io) !=
      MESH_STREAM_KCP_ADAPTER_OK) {
    mesh_stream_kcp_adapter_io_destroy_v1(kcp_io);
    return;
  }
  memset(&live_config, 0, sizeof(live_config));
  live_config.window_groups = 16u;
  live_config.skip_gap_groups = 4u;
  live_config.max_block_bytes = srv->block_size;
  live_config.fec_data_shards = 0u; /* the source sends ordered blocks */
  rx = mesh_stream_live_create(MESH_STREAM_LIVE_ROLE_RECEIVER, &live_config, &io);
  block = (uint8_t *)malloc((size_t)srv->block_size);
  if (!rx || !block) {
    if (rx)
      mesh_stream_live_destroy(rx);
    free(block);
    mesh_stream_kcp_adapter_io_destroy_v1(kcp_io);
    return;
  }
  for (;;) {
    size_t len = 0u;
    uint64_t seq = 0u;
    uint64_t index = 0u;
    mesh_stream_live_result_t rc = mesh_stream_live_receiver_pump(
        rx, block, (size_t)srv->block_size, &len, &seq);

    if (rc == MESH_STREAM_LIVE_END)
      break;
    if (rc != MESH_STREAM_LIVE_OK)
      break;
    if (mesh_stream_live_hls_push_v1(&srv->hls, block, len, &index) !=
        MESH_STREAM_LIVE_HLS_OK) {
      break;
    }
  }
  mesh_stream_live_destroy(rx);
  free(block);
  mesh_stream_kcp_adapter_io_destroy_v1(kcp_io);
}

static void relay_thread(void *arg) {
  live_server_t *srv = (live_server_t *)arg;
  coro_context_t *ctx = coro_context_create(NULL);
  coro_socket_t *server;
  turbo_kcp_config_t kcp_config;

  if (!ctx)
    return;
  server = coro_socket_create_kcp(ctx);
  if (!server) {
    coro_context_destroy(ctx);
    return;
  }
  turbo_kcp_config_default(&kcp_config);
  memcpy(kcp_config.pre_shared_key, LIVE_PSK, sizeof(LIVE_PSK));
  if (coro_socket_set_kcp_config(server, &kcp_config) != 0 ||
      coro_socket_listen_on(server, "127.0.0.1", srv->kcp_port, relay_handler,
                            srv) != 0) {
    coro_socket_destroy(server);
    coro_context_destroy(ctx);
    return;
  }
  coro_context_run(ctx, TURBO_RUN_DEFAULT);
  coro_socket_destroy(server);
  {
    int drain = 200;

    coro_context_stop(ctx);
    while (drain-- > 0 && coro_context_alive(ctx))
      coro_context_run(ctx, TURBO_RUN_NOWAIT);
  }
  coro_context_destroy(ctx);
}

static void send_all(sock_t client, const char *bytes, size_t len) {
  size_t sent = 0u;

  while (sent < len) {
    int n = (int)send(client, bytes + sent, (int)(len - sent), 0);

    if (n <= 0)
      return;
    sent += (size_t)n;
  }
}

static void respond(sock_t client, int status, const char *content_type,
                    const char *body, size_t body_len) {
  char header[256];

  snprintf(header, sizeof(header),
           "HTTP/1.1 %d %s\r\n"
           "Content-Type: %s\r\n"
           "Content-Length: %zu\r\n"
           "Connection: close\r\n"
           "\r\n",
           status, status == 200 ? "OK" : "Not Found", content_type, body_len);
  send_all(client, header, strlen(header));
  send_all(client, body, body_len);
}

static void serve_connection(live_server_t *srv, sock_t client) {
  char request[2048];
  int got = recv(client, request, (int)sizeof(request) - 1, 0);
  char path[512] = {0};
  char body[8192];
  size_t body_len = 0u;
  uint64_t index;

  if (got <= 0) {
    CLOSE_SOCK(client);
    return;
  }
  request[got] = '\0';
  /* Parse "GET <path> HTTP/1.1". */
  if (sscanf(request, "GET %511s", path) != 1) {
    respond(client, 404, "text/plain", "bad request", 11u);
    CLOSE_SOCK(client);
    return;
  }
  if (strcmp(path, "/live.m3u8") == 0) {
    mesh_stream_live_hls_result_t rc = mesh_stream_live_hls_playlist_v1(
        &srv->hls, body, sizeof(body), &body_len);

    if (rc != MESH_STREAM_LIVE_HLS_OK) {
      respond(client, 500, "text/plain", "playlist error", 14u);
    } else {
      respond(client, 200, "application/vnd.apple.mpegurl", body, body_len);
    }
    CLOSE_SOCK(client);
    return;
  }
  if (strncmp(path, "/live/seg-", 10u) == 0) {
    char *end = NULL;

    index = strtoull(path + 10u, &end, 10);
    if (end && *end == '\0') {
      mesh_stream_live_hls_result_t rc = mesh_stream_live_hls_segment_v1(
          &srv->hls, index, (uint8_t *)body, sizeof(body), &body_len);

      if (rc == MESH_STREAM_LIVE_HLS_OK) {
        respond(client, 200, "application/octet-stream", body, body_len);
      } else {
        respond(client, 404, "text/plain", "segment evicted", 15u);
      }
      CLOSE_SOCK(client);
      return;
    }
  }
  respond(client, 404, "text/plain", "not found", 9u);
  CLOSE_SOCK(client);
}

int main(int argc, char **argv) {
  live_server_t srv;
  mesh_stream_live_hls_config_v1_t config;
  turbo_thread_t producer = NULL;
  uint16_t port = 0u;
  sock_t listener = INVALID_SOCK;
  struct sockaddr_in addr;

  memset(&srv, 0, sizeof(srv));
  memset(&config, 0, sizeof(config));
  config.window = 3u;
  config.segment_duration_ms = 1000u;
  config.max_segment_bytes = DEFAULT_BLOCK;
  srv.segments = 6u;
  srv.interval_ms = 300u;
  srv.block_size = DEFAULT_BLOCK;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--port") == 0 && i + 1 < argc)
      port = (uint16_t)strtoul(argv[++i], NULL, 10);
    else if (strcmp(argv[i], "--segments") == 0 && i + 1 < argc)
      srv.segments = strtoull(argv[++i], NULL, 10);
    else if (strcmp(argv[i], "--interval-ms") == 0 && i + 1 < argc)
      srv.interval_ms = strtoull(argv[++i], NULL, 10);
    else if (strcmp(argv[i], "--window") == 0 && i + 1 < argc)
      config.window = strtoull(argv[++i], NULL, 10);
    else if (strcmp(argv[i], "--block") == 0 && i + 1 < argc)
      srv.block_size = strtoull(argv[++i], NULL, 10);
    else if (strcmp(argv[i], "--kcp-port") == 0 && i + 1 < argc)
      srv.kcp_port = (unsigned short)strtoul(argv[++i], NULL, 10);
    else {
      fprintf(stderr, "unknown arg: %s\n", argv[i]);
      return 1;
    }
  }
  config.max_segment_bytes = srv.block_size;
  if (port == 0u || srv.segments == 0u || srv.interval_ms == 0u)
    return 1;
  if (mesh_stream_live_hls_init_v1(&srv.hls, &config) !=
      MESH_STREAM_LIVE_HLS_OK) {
    return 1;
  }
  if (srv.kcp_port != 0u) {
    if (turbo_thread_create(&producer, relay_thread, &srv) != 0)
      return 1;
  } else if (turbo_thread_create(&producer, producer_thread, &srv) != 0) {
    return 1;
  }

#ifdef _WIN32
  {
    WSADATA wsa;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
      return 1;
  }
#endif
  listener = (sock_t)socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (listener == INVALID_SOCK)
    return 1;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(port);
  if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
      listen(listener, 4) != 0) {
    return 1;
  }
  printf("LIVE READY port=%u window=%llu segments=%llu\n", (unsigned)port,
         (unsigned long long)config.window,
         (unsigned long long)srv.segments);
  fflush(stdout);
  while (!srv.stop) {
    sock_t client = (sock_t)accept(listener, NULL, NULL);

    if (client == INVALID_SOCK)
      break;
    serve_connection(&srv, client);
  }
  CLOSE_SOCK(listener);
#ifdef _WIN32
  WSACleanup();
#endif
  mesh_stream_live_hls_destroy_v1(&srv.hls);
  return 0;
}