/* mesh_stream_live_client_main.c - live HLS cross-gateway failover client.
 *
 * A live HLS gateway (mesh_stream_live_hls_main) serves a deterministic live
 * session: every segment index carries identical bytes on any gateway built
 * from the same source. This client watches a primary gateway, and when it
 * becomes unreachable, switches to a backup gateway serving the same session.
 * It verifies that the segment bytes served by both gateways are identical,
 * proving a client can switch live sources without content divergence.
 *
 * Usage:
 *   mesh_stream_live_client_main --primary <host:port> --backup <host:port>
 *       --segment <K>
 *
 * Output:
 *   PRIMARY seg-<K> OK (<n> bytes)          (primary reachable)
 *   PRIMARY seg-<K> unreachable             (primary dead; failover)
 *   LIVE FAILOVER VERIFY OK seg=<K> bytes=<n>   (both served identical bytes)
 *   LIVE FAILOVER OK seg=<K> served-by=backup bytes=<n>
 *   LIVE BACKUP PLAYLIST OK                 (backup is a live source)
 */

#include <CoroNet.h>
#include <http/http_client.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  http_client_t *primary_client;
  http_client_t *backup_client;
  uint64_t segment;
  uint8_t primary_body[4096];
  size_t primary_len;
  int primary_ok;
  int ok;
  int done;
  coro_context_t *ctx;
} live_client_state_t;

static void live_client_coroutine(coro_t *co, void *arg) {
  live_client_state_t *state = (live_client_state_t *)arg;
  char seg_path[64];
  http_response_t *response;

  (void)co;
  snprintf(seg_path, sizeof(seg_path), "/live/seg-%llu",
           (unsigned long long)state->segment);

  /* Primary. */
  response = http_request(state->primary_client, HTTP_GET, seg_path, NULL, 0,
                          NULL, 0);
  if (response && response->status_code == 200 && response->body_len > 0u &&
      response->body_len <= sizeof(state->primary_body)) {
    memcpy(state->primary_body, response->body, response->body_len);
    state->primary_len = response->body_len;
    state->primary_ok = 1;
    printf("PRIMARY seg-%llu OK (%zu bytes)\n",
           (unsigned long long)state->segment, state->primary_len);
  } else {
    printf("PRIMARY seg-%llu unreachable\n",
           (unsigned long long)state->segment);
    state->primary_ok = 0;
  }
  if (response)
    http_response_free(response);

  /* Backup: serve the same segment index. */
  response = http_request(state->backup_client, HTTP_GET, seg_path, NULL, 0,
                          NULL, 0);
  if (!response || response->status_code != 200 || response->body_len == 0u) {
    if (response)
      http_response_free(response);
    state->ok = 0;
    state->done = 1;
    coro_context_stop(state->ctx);
    return;
  }
  if (state->primary_ok) {
    if (response->body_len != state->primary_len ||
        memcmp(response->body, state->primary_body, state->primary_len) != 0) {
      fprintf(stderr, "backup segment content differs from primary\n");
      http_response_free(response);
      state->ok = 0;
      state->done = 1;
      coro_context_stop(state->ctx);
      return;
    }
    printf("LIVE FAILOVER VERIFY OK seg=%llu bytes=%zu\n",
           (unsigned long long)state->segment, response->body_len);
  } else {
    printf("LIVE FAILOVER OK seg=%llu served-by=backup bytes=%zu\n",
           (unsigned long long)state->segment, response->body_len);
  }
  http_response_free(response);

  /* The backup must be a live source. */
  response = http_request(state->backup_client, HTTP_GET, "/live.m3u8", NULL, 0,
                          NULL, 0);
  if (!response || response->status_code != 200 || !response->body ||
      strstr(response->body, "#EXTM3U") == NULL ||
      strstr(response->body, "#EXT-X-MEDIA-SEQUENCE:") == NULL) {
    if (response)
      http_response_free(response);
    state->ok = 0;
    state->done = 1;
    coro_context_stop(state->ctx);
    return;
  }
  printf("LIVE BACKUP PLAYLIST OK\n");
  http_response_free(response);
  state->ok = 1;
  state->done = 1;
  coro_context_stop(state->ctx);
}

int main(int argc, char **argv) {
  const char *primary = NULL;
  const char *backup = NULL;
  uint64_t segment = 0u;
  live_client_state_t state;
  coro_context_t *ctx = NULL;
  char primary_url[128];
  char backup_url[128];
  int drain = 200;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--primary") == 0 && i + 1 < argc)
      primary = argv[++i];
    else if (strcmp(argv[i], "--backup") == 0 && i + 1 < argc)
      backup = argv[++i];
    else if (strcmp(argv[i], "--segment") == 0 && i + 1 < argc)
      segment = strtoull(argv[++i], NULL, 10);
    else {
      fprintf(stderr, "unknown arg: %s\n", argv[i]);
      return 1;
    }
  }
  if (!primary || !backup) {
    fprintf(stderr, "usage: mesh_stream_live_client_main --primary <host:port> "
                    "--backup <host:port> --segment <K>\n");
    return 1;
  }
  memset(&state, 0, sizeof(state));
  state.segment = segment;
  snprintf(primary_url, sizeof(primary_url), "http://%s", primary);
  snprintf(backup_url, sizeof(backup_url), "http://%s", backup);
  ctx = coro_context_create(NULL);
  if (!ctx)
    return 1;
  state.ctx = ctx;
  state.primary_client = http_client_create(primary_url);
  if (!state.primary_client) {
    coro_context_destroy(ctx);
    return 1;
  }
  state.backup_client = http_client_create(backup_url);
  if (!state.backup_client) {
    http_client_destroy(state.primary_client);
    coro_context_destroy(ctx);
    return 1;
  }
  http_client_set_timeout(state.primary_client, 3000);
  http_client_set_timeout(state.backup_client, 3000);
  if (coro_context_spawn(ctx, live_client_coroutine, &state) != 0) {
    http_client_destroy(state.backup_client);
    http_client_destroy(state.primary_client);
    coro_context_destroy(ctx);
    return 1;
  }
  coro_context_run(ctx, TURBO_RUN_DEFAULT);
  while (drain-- > 0 && coro_context_alive(ctx))
    coro_context_run(ctx, TURBO_RUN_NOWAIT);
  coro_context_destroy(ctx);
  http_client_destroy(state.backup_client);
  http_client_destroy(state.primary_client);
  if (!state.ok) {
    fprintf(stderr, "live failover client failed\n");
    return 1;
  }
  return 0;
}
